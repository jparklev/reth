//! Phase 26.x — full-mainnet hash-keyed state checkpointer (v2).
//!
//! Walks reth's `HashedAccounts` / `HashedStorages` / `Bytecodes`
//! tables in shard-aligned chunks and emits Vortex bundles keyed by
//! `keccak(addr)` / `(keccak(addr), keccak(slot))`. A reth-fork
//! follower hydrates those bundles lazily via
//! `reth-bucket-state-client`, hashing query inputs on the fly.
//!
//! ## Why hash-keyed
//!
//! Production reth runs storage_v2: `PlainAccountState` and
//! `PlainStorageState` are empty; all state lives in the hashed
//! tables. Plain-keyed enumeration would require a reverse hash
//! dictionary that gets pruned along with `AccountChangeSets`. The
//! follower receives plain `(Address, slot)` at query time and can
//! hash on the fly, so the bucket can stay hash-keyed end-to-end.
//!
//! ## Operational stance
//!
//! - Checkpoint binds to the local node's current state — callers pause reth or run on a paused
//!   replica.
//! - No trie recomputation; we trust the local node's canonical header for `state_root`.
//! - Streaming per-shard: HashedAccounts/HashedStorages are sorted by hashed key, so we accumulate
//!   one shard's worth of rows in memory, flush, and move on. Peak memory ≈ one shard.
//! - Code is sharded by top-bits of `code_hash` (independent of the account shard) because the
//!   client looks up code by hash only.

use std::{collections::HashSet, path::PathBuf, sync::Arc, time::Instant};

use alloy_consensus::constants::KECCAK_EMPTY;
use alloy_primitives::{Address, B256, U256, keccak256};
use chrono::SecondsFormat;
use clap::Parser;
use ed25519_dalek::Signer;
use eyre::{eyre, Context};
use object_store::{
    aws::AmazonS3Builder, path::Path as ObjectPath, ObjectStore, ObjectStoreExt, PutPayload,
};
use reth_cli_commands::common::{AccessRights, CliNodeTypes, Environment, EnvironmentArgs};
use reth_db_api::{
    cursor::DbCursorRO,
    tables::{Bytecodes, HashedAccounts, HashedStorages},
    transaction::DbTx,
};
use reth_ethereum_cli::chainspec::EthereumChainSpecParser;
use reth_provider::{
    BlockNumReader, DatabaseProviderFactory, HeaderProvider, ProviderFactory,
    providers::ProviderNodeTypes,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tracing::{info, warn};

mod vortex_writer;

#[derive(Parser, Debug)]
#[command(name = "relay-state-checkpointer", version, about, long_about = None)]
struct Cli {
    /// Reth datadir / chain config (uses the same flags as
    /// `reth db`). The binary always opens read-only.
    #[command(flatten)]
    env: EnvironmentArgs<EthereumChainSpecParser>,

    /// Output directory for the local artifact bundle (written
    /// before any upload). Created if it doesn't exist.
    #[arg(long)]
    out_dir: PathBuf,

    /// Number of high-order bits of `keccak(addr)` used to assign a
    /// shard. 0 = single shard (testing only — won't scale). 8 = 256
    /// shards (default; ~1.5M accounts / shard at full mainnet).
    /// 12 = 4096 shards (~95k each). Must be ≤ 16.
    #[arg(long, default_value_t = 8u8)]
    shard_bits: u8,

    /// Cap on total accounts emitted. `0` disables. Aborts the
    /// HashedAccounts walk early once the cap is hit. Useful for
    /// smoke runs against full mainnet without the ~30-min walk.
    /// Note: storage rows for accounts beyond the cap are skipped.
    #[arg(long, default_value_t = 0usize)]
    max_accounts: usize,

    // ---- Upload (optional) ----
    /// When set, after writing local artifacts the binary uploads
    /// them and the signed manifest to s3://<bucket>/<prefix><block>/.
    #[arg(long)]
    upload_bucket: Option<String>,

    #[arg(long)]
    upload_endpoint: Option<String>,

    #[arg(long, default_value = "auto")]
    upload_region: String,

    #[arg(long, env = "BUCKET_ACCESS_KEY_ENV", default_value = "BUCKET_ACCESS_KEY")]
    upload_access_key_env: String,

    #[arg(long, env = "BUCKET_SECRET_KEY_ENV", default_value = "BUCKET_SECRET_KEY")]
    upload_secret_key_env: String,

    /// Path to the ed25519 signing key (32 raw bytes). Same shape
    /// as the indexer's `relay-indexer/writer.key`.
    #[arg(long)]
    writer_key: Option<PathBuf>,

    /// Writer ID; matches `writer-keys/<id>.pub` in the bucket.
    #[arg(long, default_value = "primary")]
    writer_id: String,

    /// Bucket prefix for checkpoints. Default: `checkpoints/`.
    #[arg(long, default_value = "checkpoints/")]
    checkpoint_prefix: String,

    /// After upload, refresh `<prefix>index.json[.sig]` with the
    /// new entry.
    #[arg(long)]
    update_index: bool,
}

fn main() -> eyre::Result<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    runtime.block_on(async_main())
}

async fn async_main() -> eyre::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(
            |_| tracing_subscriber::EnvFilter::new("info,relay_state_checkpointer=debug,reth=warn"),
        ))
        .init();
    let cli = Cli::parse();
    if cli.shard_bits > 16 {
        return Err(eyre!("--shard-bits must be ≤ 16; got {}", cli.shard_bits));
    }
    tokio::fs::create_dir_all(&cli.out_dir).await?;

    let runtime = reth_tasks::Runtime::new()?;
    let env: Environment<_> = cli
        .env
        .init::<reth_node_ethereum::node::EthereumNode>(AccessRights::RO, runtime)?;
    let factory = env.provider_factory.clone();

    let provider = factory.database_provider_ro()?;
    let info = provider.chain_info()?;
    let block_number = info.best_number;
    let block_hash = format!("0x{}", hex::encode(info.best_hash.as_slice()));
    let header = provider
        .header_by_number(block_number)?
        .ok_or_else(|| eyre!("header for best block {block_number} not in db"))?;
    let state_root = Some(format!("0x{}", hex::encode(header.state_root.as_slice())));
    info!(
        block_number,
        %block_hash,
        state_root = state_root.as_deref().unwrap_or("<missing>"),
        shard_bits = cli.shard_bits,
        "anchored to local reth canonical head"
    );
    drop(provider);

    let start = Instant::now();
    let dump = dump_state(&factory, &cli).await?;
    info!(
        accounts = dump.total_accounts,
        storage_rows = dump.total_storage,
        code_blobs = dump.total_code,
        shards = dump.account_shards.len(),
        code_shards = dump.code_shards.len(),
        elapsed_secs = start.elapsed().as_secs(),
        "hash-keyed state dump complete"
    );

    let manifest = build_manifest(&cli, block_number, &block_hash, &state_root, &dump);
    let manifest_bytes = serde_json::to_vec_pretty(&manifest)?;
    tokio::fs::write(cli.out_dir.join("manifest.json"), &manifest_bytes).await?;

    if let Some(bucket) = &cli.upload_bucket {
        let writer_key = cli
            .writer_key
            .clone()
            .ok_or_else(|| eyre!("--writer-key required with --upload-bucket"))?;
        let endpoint = cli
            .upload_endpoint
            .clone()
            .ok_or_else(|| eyre!("--upload-endpoint required with --upload-bucket"))?;
        upload(
            &cli,
            &manifest,
            UploadParams {
                bucket: bucket.clone(),
                endpoint,
                region: cli.upload_region.clone(),
                access_key_env: cli.upload_access_key_env.clone(),
                secret_key_env: cli.upload_secret_key_env.clone(),
                writer_key,
                writer_id: cli.writer_id.clone(),
                prefix: cli.checkpoint_prefix.clone(),
                update_index: cli.update_index,
            },
        )
        .await?;
    }

    println!("{}", serde_json::to_string_pretty(&manifest)?);
    Ok(())
}

// ============== shard math ==============

fn shard_count(bits: u8) -> usize {
    if bits == 0 {
        1
    } else {
        1usize << bits
    }
}

/// Top `bits` of a 32-byte hash, big-endian.
fn shard_for_hash(hash: B256, bits: u8) -> usize {
    if bits == 0 {
        return 0;
    }
    let bytes = hash.as_slice();
    // We support up to 16 bits, so reading the first 2 bytes is enough.
    let v = ((bytes[0] as u32) << 8) | (bytes[1] as u32);
    (v as usize) >> (16 - bits as usize)
}

/// Inclusive [min, max] hash range covered by `shard_id` under `bits`.
fn shard_range(shard_id: u32, bits: u8) -> (B256, B256) {
    let mut min = [0u8; 32];
    let mut max = [0xffu8; 32];
    if bits == 0 {
        return (B256::from(min), B256::from(max));
    }
    // Distribute the shard_id across the first 2 bytes of the hash;
    // the remaining bits of byte 1 (and all lower bytes) are wildcards.
    let shifted = (shard_id as u32) << (16 - bits as u32);
    min[0] = (shifted >> 8) as u8;
    min[1] = (shifted & 0xff) as u8;
    let upper = shifted | ((1u32 << (16 - bits as u32)) - 1);
    max[0] = (upper >> 8) as u8;
    max[1] = (upper & 0xff) as u8;
    (B256::from(min), B256::from(max))
}

// ============== dump (streaming, shard-by-shard) ==============

#[derive(Default)]
struct ShardEmit {
    shard: u32,
    object_key: String,
    bytes_written: u64,
    sha256_hex: String,
    key_min: Option<B256>,
    key_max: Option<B256>,
    rows: u64,
}

#[derive(Default)]
struct StateDump {
    account_shards: Vec<ShardEmit>,
    storage_shards: Vec<ShardEmit>,
    code_shards: Vec<ShardEmit>,
    total_accounts: u64,
    total_storage: u64,
    total_code: u64,
}

async fn dump_state<N>(factory: &ProviderFactory<N>, cli: &Cli) -> eyre::Result<StateDump>
where
    N: ProviderNodeTypes,
{
    let mut dump = StateDump::default();

    let provider = factory.database_provider_ro()?;
    let tx = provider.tx_ref();

    // ---- accounts (and code-hash collection) ----
    let acct_start = Instant::now();
    let mut accounts_cursor = tx.cursor_read::<HashedAccounts>()?;
    let mut current_shard: Option<u32> = None;
    let mut buf: Vec<(B256, u64, U256, B256)> = Vec::new();
    let mut code_hashes_seen: HashSet<B256> = HashSet::new();
    let max_accounts = if cli.max_accounts == 0 { u64::MAX } else { cli.max_accounts as u64 };

    let mut walk = accounts_cursor.walk(None)?;
    while let Some(row) = walk.next() {
        if dump.total_accounts >= max_accounts {
            break;
        }
        let (h_addr, account) = row?;
        let shard = shard_for_hash(h_addr, cli.shard_bits) as u32;

        if Some(shard) != current_shard {
            if let Some(prev) = current_shard.take() {
                let emit = flush_accounts(cli, prev, std::mem::take(&mut buf)).await?;
                dump.account_shards.push(emit);
            }
            current_shard = Some(shard);
        }

        let code_hash = account.bytecode_hash.unwrap_or(KECCAK_EMPTY);
        if code_hash != KECCAK_EMPTY {
            code_hashes_seen.insert(code_hash);
        }
        buf.push((h_addr, account.nonce, account.balance, code_hash));
        dump.total_accounts += 1;

        if dump.total_accounts.is_multiple_of(500_000) {
            info!(
                accounts = dump.total_accounts,
                shard,
                elapsed_secs = acct_start.elapsed().as_secs(),
                "accounts walk progress"
            );
        }
    }
    if let Some(prev) = current_shard.take() {
        let emit = flush_accounts(cli, prev, std::mem::take(&mut buf)).await?;
        dump.account_shards.push(emit);
    }
    info!(
        accounts = dump.total_accounts,
        shards = dump.account_shards.len(),
        code_hashes_referenced = code_hashes_seen.len(),
        elapsed_secs = acct_start.elapsed().as_secs(),
        "accounts dump complete"
    );

    // ---- storage ----
    let storage_start = Instant::now();
    let mut storage_cursor = tx.cursor_dup_read::<HashedStorages>()?;
    let mut current_shard: Option<u32> = None;
    let mut buf: Vec<(B256, B256, U256)> = Vec::new();

    // walk over a dup table yields (key, value) per duplicate row; for
    // HashedStorages: key = keccak(addr), value = StorageEntry { key:
    // keccak(slot), value: U256 }.
    let mut walk = storage_cursor.walk(None)?;
    while let Some(row) = walk.next() {
        let (h_addr, entry) = row?;
        let shard = shard_for_hash(h_addr, cli.shard_bits) as u32;

        // Skip storage for accounts past the --max-accounts cap. We
        // identify those by shard ID > last account shard (since
        // sorted), OR by comparing within the current shard against
        // the highest account hash emitted. For simplicity: if
        // max_accounts capped us mid-walk, the last account shard
        // emit captures the cutoff; storage shards beyond it are
        // skipped entirely.
        if cli.max_accounts > 0 {
            let last_acct_shard = dump.account_shards.last().map(|s| s.shard).unwrap_or(0);
            if shard > last_acct_shard {
                break;
            }
        }

        if Some(shard) != current_shard {
            if let Some(prev) = current_shard.take() {
                let emit = flush_storage(cli, prev, std::mem::take(&mut buf)).await?;
                dump.storage_shards.push(emit);
            }
            current_shard = Some(shard);
        }

        buf.push((h_addr, entry.key, entry.value));
        dump.total_storage += 1;

        if dump.total_storage.is_multiple_of(2_000_000) {
            info!(
                storage = dump.total_storage,
                shard,
                elapsed_secs = storage_start.elapsed().as_secs(),
                "storage walk progress"
            );
        }
    }
    if let Some(prev) = current_shard.take() {
        let emit = flush_storage(cli, prev, std::mem::take(&mut buf)).await?;
        dump.storage_shards.push(emit);
    }
    info!(
        storage = dump.total_storage,
        shards = dump.storage_shards.len(),
        elapsed_secs = storage_start.elapsed().as_secs(),
        "storage dump complete"
    );

    // ---- code (independent shard layout: top-bits of code_hash) ----
    let code_start = Instant::now();
    let mut bytecode_cursor = tx.cursor_read::<Bytecodes>()?;
    let mut sorted: Vec<B256> = code_hashes_seen.into_iter().collect();
    sorted.sort();

    let mut current_shard: Option<u32> = None;
    let mut buf: Vec<(B256, Vec<u8>)> = Vec::new();
    for code_hash in sorted {
        let shard = shard_for_hash(code_hash, cli.shard_bits) as u32;

        if Some(shard) != current_shard {
            if let Some(prev) = current_shard.take() {
                let emit = flush_code(cli, prev, std::mem::take(&mut buf)).await?;
                dump.code_shards.push(emit);
            }
            current_shard = Some(shard);
        }

        match bytecode_cursor.seek_exact(code_hash)? {
            Some((_, bytecode)) => {
                buf.push((code_hash, bytecode.original_byte_slice().to_vec()));
                dump.total_code += 1;
            }
            None => {
                warn!(?code_hash, "referenced code_hash missing from Bytecodes");
            }
        }
    }
    if let Some(prev) = current_shard.take() {
        let emit = flush_code(cli, prev, std::mem::take(&mut buf)).await?;
        dump.code_shards.push(emit);
    }
    info!(
        code_blobs = dump.total_code,
        shards = dump.code_shards.len(),
        elapsed_secs = code_start.elapsed().as_secs(),
        "code dump complete"
    );

    Ok(dump)
}

fn shard_dir(out_dir: &std::path::Path, shard: u32) -> PathBuf {
    out_dir.join(format!("shard-{shard:04}"))
}

async fn flush_accounts(
    cli: &Cli,
    shard: u32,
    rows: Vec<(B256, u64, U256, B256)>,
) -> eyre::Result<ShardEmit> {
    let dir = shard_dir(&cli.out_dir, shard);
    tokio::fs::create_dir_all(&dir).await?;
    let bytes = vortex_writer::accounts_chunk(&rows).await?;
    let key_min = rows.first().map(|r| r.0);
    let key_max = rows.last().map(|r| r.0);
    let path = dir.join("accounts.vortex");
    let object_key = format!("shard-{shard:04}/accounts.vortex");
    tokio::fs::write(&path, &bytes).await?;
    Ok(ShardEmit {
        shard,
        object_key,
        bytes_written: bytes.len() as u64,
        sha256_hex: format!("{:x}", Sha256::digest(&bytes)),
        key_min,
        key_max,
        rows: rows.len() as u64,
    })
}

async fn flush_storage(
    cli: &Cli,
    shard: u32,
    rows: Vec<(B256, B256, U256)>,
) -> eyre::Result<ShardEmit> {
    let dir = shard_dir(&cli.out_dir, shard);
    tokio::fs::create_dir_all(&dir).await?;
    let bytes = vortex_writer::storage_chunk(&rows).await?;
    let key_min = rows.first().map(|r| r.0);
    let key_max = rows.last().map(|r| r.0);
    let path = dir.join("storage.vortex");
    let object_key = format!("shard-{shard:04}/storage.vortex");
    tokio::fs::write(&path, &bytes).await?;
    Ok(ShardEmit {
        shard,
        object_key,
        bytes_written: bytes.len() as u64,
        sha256_hex: format!("{:x}", Sha256::digest(&bytes)),
        key_min,
        key_max,
        rows: rows.len() as u64,
    })
}

async fn flush_code(cli: &Cli, shard: u32, rows: Vec<(B256, Vec<u8>)>) -> eyre::Result<ShardEmit> {
    let dir = shard_dir(&cli.out_dir, shard);
    tokio::fs::create_dir_all(&dir).await?;
    let bytes = vortex_writer::code_chunk(&rows).await?;
    let key_min = rows.first().map(|r| r.0);
    let key_max = rows.last().map(|r| r.0);
    let path = dir.join("code.vortex");
    let object_key = format!("shard-{shard:04}/code.vortex");
    tokio::fs::write(&path, &bytes).await?;
    Ok(ShardEmit {
        shard,
        object_key,
        bytes_written: bytes.len() as u64,
        sha256_hex: format!("{:x}", Sha256::digest(&bytes)),
        key_min,
        key_max,
        rows: rows.len() as u64,
    })
}

// ============== manifest emission (v2 / hash-keyed) ==============

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StateArtifactRef {
    chain_id: u64,
    kind: String,
    from_block: u64,
    to_block: u64,
    state_root: Option<String>,
    object_key: String,
    content_sha256: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    shard: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    key_min: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    key_max: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ShardManifest {
    shard: u32,
    accounts: StateArtifactRef,
    storage: StateArtifactRef,
    code: StateArtifactRef,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct FinalizedStateArtifactManifest {
    version: u8,
    chain_id: u64,
    block_number: u64,
    block_hash: String,
    state_root: Option<String>,
    /// Always present in v2; only the per-shard refs are populated.
    shards: Vec<ShardManifest>,
    /// Number of high-order bits of `keccak(addr)` that route to a shard.
    shard_bits: Option<u8>,
    /// Always `"hashed"` in v2 — kept as a string so v3 can extend.
    key_layout: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct SignedCheckpointManifest {
    version: u8,
    writer_id: String,
    signed_at: String,
    manifest: FinalizedStateArtifactManifest,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CheckpointIndexEntry {
    block_number: u64,
    block_hash: String,
    state_root: Option<String>,
    manifest_url: String,
    manifest_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CheckpointIndex {
    version: u8,
    chain_id: u64,
    writer_id: String,
    updated_at: String,
    entries: Vec<CheckpointIndexEntry>,
}

const MAX_INDEX_ENTRIES: usize = 64;

fn build_manifest(
    cli: &Cli,
    block_number: u64,
    block_hash: &str,
    state_root: &Option<String>,
    dump: &StateDump,
) -> FinalizedStateArtifactManifest {
    // Join the three shard families on shard_id. Each family may have
    // gaps (e.g. a shard with no storage rows), but for every shard
    // that contains accounts we emit a ShardManifest. The bucket
    // client tolerates empty storage/code refs (returns 0 rows).
    let mut by_shard: std::collections::BTreeMap<
        u32,
        (Option<&ShardEmit>, Option<&ShardEmit>, Option<&ShardEmit>),
    > = std::collections::BTreeMap::new();
    for e in &dump.account_shards {
        by_shard.entry(e.shard).or_insert((None, None, None)).0 = Some(e);
    }
    for e in &dump.storage_shards {
        by_shard.entry(e.shard).or_insert((None, None, None)).1 = Some(e);
    }
    for e in &dump.code_shards {
        by_shard.entry(e.shard).or_insert((None, None, None)).2 = Some(e);
    }
    let shards = by_shard
        .into_iter()
        .map(|(shard_id, (a, s, c))| {
            let (rmin, rmax) = shard_range(shard_id, cli.shard_bits);
            let range_min = format!("0x{}", hex::encode(rmin.as_slice()));
            let range_max = format!("0x{}", hex::encode(rmax.as_slice()));
            ShardManifest {
                shard: shard_id,
                accounts: emit_to_ref(
                    1,
                    "accounts",
                    block_number,
                    state_root,
                    shard_id,
                    a,
                    &range_min,
                    &range_max,
                ),
                storage: emit_to_ref(
                    1,
                    "storage",
                    block_number,
                    state_root,
                    shard_id,
                    s,
                    &range_min,
                    &range_max,
                ),
                code: emit_to_ref(
                    1,
                    "code",
                    block_number,
                    state_root,
                    shard_id,
                    c,
                    &range_min,
                    &range_max,
                ),
            }
        })
        .collect();

    FinalizedStateArtifactManifest {
        version: 2,
        chain_id: 1,
        block_number,
        block_hash: block_hash.to_string(),
        state_root: state_root.clone(),
        shards,
        shard_bits: Some(cli.shard_bits),
        key_layout: Some("hashed".to_string()),
    }
}

fn emit_to_ref(
    chain_id: u64,
    kind: &str,
    block: u64,
    state_root: &Option<String>,
    shard_id: u32,
    emit: Option<&ShardEmit>,
    range_min: &str,
    range_max: &str,
) -> StateArtifactRef {
    match emit {
        Some(e) => StateArtifactRef {
            chain_id,
            kind: kind.to_string(),
            from_block: block,
            to_block: block,
            state_root: state_root.clone(),
            object_key: e.object_key.clone(),
            content_sha256: e.sha256_hex.clone(),
            shard: Some(shard_id),
            key_min: e.key_min.map(|h| format!("0x{}", hex::encode(h.as_slice()))),
            key_max: e.key_max.map(|h| format!("0x{}", hex::encode(h.as_slice()))),
        },
        None => StateArtifactRef {
            chain_id,
            kind: kind.to_string(),
            from_block: block,
            to_block: block,
            state_root: state_root.clone(),
            object_key: format!("shard-{shard_id:04}/{kind}.vortex"),
            content_sha256: format!("{:x}", Sha256::digest([])),
            shard: Some(shard_id),
            key_min: Some(range_min.to_string()),
            key_max: Some(range_max.to_string()),
        },
    }
}

// ======================== upload ========================

struct UploadParams {
    bucket: String,
    endpoint: String,
    region: String,
    access_key_env: String,
    secret_key_env: String,
    writer_key: PathBuf,
    writer_id: String,
    prefix: String,
    update_index: bool,
}

async fn upload(
    cli: &Cli,
    manifest: &FinalizedStateArtifactManifest,
    params: UploadParams,
) -> eyre::Result<()> {
    let key_bytes = tokio::fs::read(&params.writer_key)
        .await
        .with_context(|| format!("read writer key {}", params.writer_key.display()))?;
    if key_bytes.len() != 32 {
        return Err(eyre!("writer key must be 32 raw bytes, got {}", key_bytes.len()));
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&key_bytes);
    let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed);

    let access_key = std::env::var(&params.access_key_env)
        .with_context(|| format!("env {} not set", params.access_key_env))?;
    let secret_key = std::env::var(&params.secret_key_env)
        .with_context(|| format!("env {} not set", params.secret_key_env))?;
    let allow_http = params.endpoint.starts_with("http://");
    let store = AmazonS3Builder::new()
        .with_bucket_name(&params.bucket)
        .with_region(&params.region)
        .with_endpoint(&params.endpoint)
        .with_access_key_id(access_key)
        .with_secret_access_key(secret_key)
        .with_virtual_hosted_style_request(false)
        .with_allow_http(allow_http)
        .build()?;
    let store: Arc<dyn ObjectStore> = Arc::new(store);

    let base = params.prefix.trim_end_matches('/').to_string();
    let dir_prefix = if base.is_empty() {
        format!("{}", manifest.block_number)
    } else {
        format!("{base}/{}", manifest.block_number)
    };

    let upload_one = |local: PathBuf, key: String, expected: String| {
        let store = Arc::clone(&store);
        async move {
            // Tolerate "shard exists in manifest but no file on disk"
            // for the empty-shard placeholder case. The expected sha
            // is the sha of empty bytes; if we can't read the file,
            // upload empty.
            let bytes = match tokio::fs::read(&local).await {
                Ok(b) => b,
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => Vec::new(),
                Err(err) => return Err(eyre!("read {}: {err}", local.display())),
            };
            let actual = format!("{:x}", Sha256::digest(&bytes));
            if actual != expected {
                return Err(eyre!(
                    "sha mismatch on {}: local {actual} ≠ manifest {expected}",
                    local.display()
                ));
            }
            store.put(&ObjectPath::from(key.as_str()), PutPayload::from(bytes)).await?;
            info!(key, "uploaded");
            eyre::Ok(())
        }
    };

    for shard in &manifest.shards {
        let dir = shard_dir(&cli.out_dir, shard.shard);
        upload_one(
            dir.join("accounts.vortex"),
            format!("{dir_prefix}/{}", shard.accounts.object_key),
            shard.accounts.content_sha256.clone(),
        )
        .await?;
        upload_one(
            dir.join("storage.vortex"),
            format!("{dir_prefix}/{}", shard.storage.object_key),
            shard.storage.content_sha256.clone(),
        )
        .await?;
        upload_one(
            dir.join("code.vortex"),
            format!("{dir_prefix}/{}", shard.code.object_key),
            shard.code.content_sha256.clone(),
        )
        .await?;
    }

    let signed = SignedCheckpointManifest {
        version: 1,
        writer_id: params.writer_id.clone(),
        signed_at: chrono::Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
        manifest: manifest.clone(),
    };
    let signed_bytes = serde_json::to_vec_pretty(&signed)?;
    let signed_sha = format!("{:x}", Sha256::digest(&signed_bytes));
    let signature = signing_key.sign(&signed_bytes).to_bytes().to_vec();
    let manifest_key = format!("{dir_prefix}/manifest.json");
    let sig_key = format!("{manifest_key}.sig");
    store.put(&ObjectPath::from(manifest_key.as_str()), PutPayload::from(signed_bytes)).await?;
    store.put(&ObjectPath::from(sig_key.as_str()), PutPayload::from(signature)).await?;
    info!(manifest_key, "uploaded signed checkpoint manifest");

    if params.update_index {
        let index_key =
            if base.is_empty() { "index.json".to_string() } else { format!("{base}/index.json") };
        let mut entries: Vec<CheckpointIndexEntry> =
            match store.get(&ObjectPath::from(index_key.as_str())).await {
                Ok(g) => {
                    let bytes = g.bytes().await?.to_vec();
                    serde_json::from_slice::<CheckpointIndex>(&bytes)
                        .map(|i| i.entries)
                        .unwrap_or_default()
                }
                Err(e) => {
                    let msg = e.to_string();
                    if msg.contains("NoSuchKey") ||
                        msg.contains("NotFound") ||
                        msg.contains("status code: 404") ||
                        msg.contains("status code: 403") ||
                        msg.contains("AccessDenied")
                    {
                        Vec::new()
                    } else {
                        return Err(eyre!("read index {index_key}: {e}"));
                    }
                }
            };
        entries.retain(|e| e.block_number != manifest.block_number);
        entries.push(CheckpointIndexEntry {
            block_number: manifest.block_number,
            block_hash: manifest.block_hash.clone(),
            state_root: manifest.state_root.clone(),
            manifest_url: manifest_key.clone(),
            manifest_sha256: signed_sha,
        });
        entries.sort_by(|a, b| b.block_number.cmp(&a.block_number));
        entries.truncate(MAX_INDEX_ENTRIES);
        let new_index = CheckpointIndex {
            version: 1,
            chain_id: manifest.chain_id,
            writer_id: params.writer_id.clone(),
            updated_at: chrono::Utc::now().to_rfc3339_opts(SecondsFormat::Millis, true),
            entries,
        };
        let new_bytes = serde_json::to_vec_pretty(&new_index)?;
        let new_sig = signing_key.sign(&new_bytes).to_bytes().to_vec();
        store.put(&ObjectPath::from(index_key.as_str()), PutPayload::from(new_bytes)).await?;
        store
            .put(&ObjectPath::from(format!("{index_key}.sig").as_str()), PutPayload::from(new_sig))
            .await?;
        info!(index_key, "uploaded checkpoint index");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shard_for_hash_uses_top_bits() {
        let mut bytes = [0u8; 32];
        bytes[0] = 0xab;
        bytes[1] = 0xcd;
        let h = B256::from(bytes);
        // 8-bit shard: 0xab
        assert_eq!(shard_for_hash(h, 8), 0xab);
        // 12-bit shard: 0xabc
        assert_eq!(shard_for_hash(h, 12), 0xabc);
        // 16-bit shard: 0xabcd
        assert_eq!(shard_for_hash(h, 16), 0xabcd);
    }

    #[test]
    fn shard_for_hash_zero_bits_single_shard() {
        let h = B256::from([0xffu8; 32]);
        assert_eq!(shard_for_hash(h, 0), 0);
    }

    #[test]
    fn shard_count_powers_of_two() {
        assert_eq!(shard_count(0), 1);
        assert_eq!(shard_count(1), 2);
        assert_eq!(shard_count(8), 256);
        assert_eq!(shard_count(12), 4096);
        assert_eq!(shard_count(16), 65_536);
    }

    #[test]
    fn shard_range_covers_full_space() {
        // 8 bits, shard 0: 0x0000... to 0x00ff...
        let (lo, hi) = shard_range(0, 8);
        assert_eq!(lo.as_slice()[0..2], [0x00, 0x00]);
        assert_eq!(hi.as_slice()[0..2], [0x00, 0xff]);
        // 8 bits, shard 0xff: 0xff00... to 0xffff...
        let (lo, hi) = shard_range(0xff, 8);
        assert_eq!(lo.as_slice()[0..2], [0xff, 0x00]);
        assert_eq!(hi.as_slice()[0..2], [0xff, 0xff]);
        // 12 bits, shard 0xabc: 0xabc0 to 0xabcf in top 16 bits
        let (lo, hi) = shard_range(0xabc, 12);
        assert_eq!(lo.as_slice()[0..2], [0xab, 0xc0]);
        assert_eq!(hi.as_slice()[0..2], [0xab, 0xcf]);
    }

    #[test]
    fn shard_assignment_round_trips_with_range() {
        for bits in [0u8, 1, 4, 8, 12, 16] {
            for shard in 0..shard_count(bits) as u32 {
                let (lo, hi) = shard_range(shard, bits);
                assert_eq!(shard_for_hash(lo, bits), shard as usize);
                assert_eq!(shard_for_hash(hi, bits), shard as usize);
            }
        }
    }

    #[test]
    fn keccak_addr_is_deterministic() {
        let a = Address::from([1u8; 20]);
        let h1 = keccak256(a);
        let h2 = keccak256(a);
        assert_eq!(h1, h2);
    }
}

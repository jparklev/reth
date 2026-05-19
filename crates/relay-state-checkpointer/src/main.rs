//! Phase 26.3 — full-mainnet plain-state checkpointer.
//!
//! Reads PlainAccountState, PlainStorageState, and Bytecodes from a
//! local reth datadir (opened read-only via the existing reth-cli
//! Environment bootstrap), streams the rows into three Vortex
//! chunks whose schema is byte-equivalent to the relay-rpc reader,
//! signs the resulting checkpoint manifest with the same ed25519
//! writer key the indexer uses for head.json, and uploads the
//! bundle to an S3-compatible bucket. Optionally refreshes
//! `<prefix>index.json` so thin-reth followers can hydrate from
//! the latest checkpoint ≤ a target block.
//!
//! ## Why this is a reth-fork binary, not a relay-side CLI
//!
//! Reading PlainAccountState at mainnet scale (~300M accounts) is
//! infeasible over JSON-RPC and impractical via the `reth db` TUI.
//! Direct MDBX access via reth's provider crates is the only
//! workable shape. Doing it inside the reth fork lets us use path
//! deps to reth-cli-commands, reth-db-api, reth-provider — no git
//! wrangling.
//!
//! ## Operational stance (codex review pivot, 2026-05-18)
//!
//! - The checkpoint binds to the local node's **current** plain
//!   state (not an arbitrary historical block). Caller is expected
//!   to pause reth or run on a paused replica.
//! - No trie recomputation; we trust the state_root from the local
//!   node's canonical header.
//! - Sharding by address prefix is supported via `--shard-bits`
//!   (0 = single shard, 8 = 256 shards, 12 = 4096 shards). At
//!   mainnet today 8 shards keeps each `accounts.vortex` ~40MB.
//! - Streaming: rows are accumulated per shard, written once per
//!   shard. A future iteration can fully stream the Vortex writer
//!   (today's vortex-file writer wants the full ArrayRef).

use std::collections::HashSet;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use alloy_primitives::{Address, B256, U256, keccak256};
use chrono::SecondsFormat;
use clap::Parser;
use ed25519_dalek::Signer;
use eyre::{Context, eyre};
use object_store::aws::AmazonS3Builder;
use object_store::path::Path as ObjectPath;
use object_store::{ObjectStore, PutPayload};
use alloy_consensus::constants::KECCAK_EMPTY;
use object_store::ObjectStoreExt;
use reth_cli_commands::common::{AccessRights, CliNodeTypes, Environment, EnvironmentArgs};
use reth_db_api::cursor::{DbCursorRO, DbDupCursorRO};
use reth_db_api::tables::{Bytecodes, HashedAccounts, HashedStorages, PlainAccountState, PlainStorageState};
use reth_db_api::transaction::DbTx;
use reth_ethereum_cli::chainspec::EthereumChainSpecParser;
use reth_provider::providers::ProviderNodeTypes;
use reth_provider::{
    BlockNumReader, DatabaseProviderFactory, HeaderProvider, ProviderFactory,
    StaticFileProviderFactory,
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

    /// Number of high-order address bits to shard on. 0 = single
    /// chunk per artifact family (good for spike runs). 8 = 256
    /// shards (good for mainnet — ~1.2M accounts/shard, ~40MB
    /// post-vortex). 12 = 4096 shards (~75k each).
    #[arg(long, default_value_t = 0u8)]
    shard_bits: u8,

    /// Cap on total accounts emitted across the run. `0` disables
    /// (full table dump). Useful for spike runs against mainnet
    /// before paying the full ~30 min walk cost.
    #[arg(long, default_value_t = 0usize)]
    max_accounts: usize,

    /// Cap on storage rows per account. `0` disables. Some heavy
    /// contracts (Uniswap pools, USDC) have millions of slots;
    /// per-account capping keeps the artifact bounded at the cost
    /// of incompleteness.
    #[arg(long, default_value_t = 0usize)]
    max_storage_per_account: usize,

    /// Additional account address to force-include in the
    /// checkpoint (repeatable). Useful for targeted spike runs
    /// where you want a known contract / EOA (e.g. USDC, vitalik)
    /// in the bucket even when `--max-accounts` would skip past
    /// them. The account row plus its bytecode are emitted; storage
    /// for these addresses follows `--max-storage-per-account`.
    #[arg(long = "account", value_name = "ADDR")]
    extra_accounts: Vec<String>,

    /// Additional storage slot to force-include, of the form
    /// `0xADDR:0xSLOT` (repeatable). Useful for seeding known
    /// state mappings like `balances[user]` without dumping the
    /// whole contract's storage table.
    #[arg(long = "slot", value_name = "ADDR:SLOT")]
    extra_slots: Vec<String>,

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
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async_main())
}

async fn async_main() -> eyre::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| {
                tracing_subscriber::EnvFilter::new(
                    "info,relay_state_checkpointer=debug,reth=warn",
                )
            }),
        )
        .init();
    let cli = Cli::parse();
    tokio::fs::create_dir_all(&cli.out_dir).await?;

    let env: Environment<_> = cli
        .env
        .init::<reth_node_ethereum::node::EthereumNode>(AccessRights::RO)?;
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

    let start = Instant::now();
    let dump = read_state(&factory, &cli)?;
    info!(
        accounts = dump.total_accounts,
        storage_rows = dump.total_storage,
        code_blobs = dump.total_code,
        shards = dump.shards.len(),
        elapsed_secs = start.elapsed().as_secs(),
        "plain-state dump complete"
    );

    let manifest = write_artifacts(&cli, block_number, &block_hash, &state_root, &dump).await?;

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

#[derive(Default)]
struct StateDump {
    /// Indexed by shard ID (0..=2^shard_bits-1).
    shards: Vec<ShardData>,
    total_accounts: usize,
    total_storage: usize,
    total_code: usize,
}

#[derive(Default)]
struct ShardData {
    accounts: Vec<(Address, u64, U256, B256)>,
    storage: Vec<(Address, U256, U256)>,
    code: Vec<(B256, Vec<u8>)>,
}

fn shard_count(bits: u8) -> usize {
    if bits == 0 {
        1
    } else {
        1usize << bits
    }
}

fn shard_for(address: Address, bits: u8) -> usize {
    if bits == 0 {
        return 0;
    }
    let bytes = address.as_slice();
    let v = ((bytes[0] as u16) << 8) | bytes[1] as u16;
    (v as usize) >> (16 - bits as usize)
}

fn read_state<N>(factory: &ProviderFactory<N>, cli: &Cli) -> eyre::Result<StateDump>
where
    N: ProviderNodeTypes,
{
    let shards = shard_count(cli.shard_bits);
    let mut out = StateDump {
        shards: (0..shards).map(|_| ShardData::default()).collect(),
        ..Default::default()
    };
    let provider = factory.database_provider_ro()?;
    let tx = provider.tx_ref();

    let mut account_cursor = tx.cursor_read::<PlainAccountState>()?;
    let mut storage_cursor = tx.cursor_dup_read::<PlainStorageState>()?;
    let mut bytecode_cursor = tx.cursor_read::<Bytecodes>()?;
    // Phase 26.x — reth's "optimized" / storage_v2 mode wipes
    // PlainAccountState / PlainStorageState in favor of HashedAccounts
    // / HashedStorages keyed by `keccak256(addr)` / `keccak256(slot)`.
    // For targeted (`--account` / `--slot`) lookups we transparently
    // fall back to the hashed tables.
    let mut hashed_account_cursor = tx.cursor_read::<HashedAccounts>()?;
    let mut hashed_storage_cursor = tx.cursor_dup_read::<HashedStorages>()?;

    let row_cap = if cli.max_accounts == 0 {
        usize::MAX
    } else {
        cli.max_accounts
    };
    let per_acct_cap = if cli.max_storage_per_account == 0 {
        usize::MAX
    } else {
        cli.max_storage_per_account
    };

    let mut seen_code: HashSet<B256> = HashSet::new();
    let mut acct_iter = account_cursor.walk(None)?;
    while let Some(row) = acct_iter.next() {
        if out.total_accounts >= row_cap {
            break;
        }
        let (address, account) = row?;
        let code_hash = account
            .bytecode_hash
            .unwrap_or(KECCAK_EMPTY);
        let shard = shard_for(address, cli.shard_bits);
        out.shards[shard]
            .accounts
            .push((address, account.nonce, account.balance, code_hash));
        out.total_accounts += 1;

        if account.bytecode_hash.is_some()
            && code_hash != KECCAK_EMPTY
            && seen_code.insert(code_hash)
        {
            if let Some((_, bytecode)) = bytecode_cursor.seek_exact(code_hash)? {
                out.shards[shard]
                    .code
                    .push((code_hash, bytecode.original_byte_slice().to_vec()));
                out.total_code += 1;
            }
        }

        let mut entry = storage_cursor.seek_exact(address)?;
        let mut per_acct = 0usize;
        while let Some((addr, sub)) = entry {
            if addr != address || per_acct >= per_acct_cap {
                break;
            }
            let slot = U256::from_be_slice(sub.key.as_slice());
            out.shards[shard].storage.push((address, slot, sub.value));
            out.total_storage += 1;
            per_acct += 1;
            entry = storage_cursor.next_dup()?;
        }

        if out.total_accounts % 100_000 == 0 {
            info!(
                accounts = out.total_accounts,
                storage = out.total_storage,
                code = out.total_code,
                "checkpoint walk progress"
            );
        }
    }

    // ---- Pass 2: force-include extra accounts/slots ----
    // Phase 26.x — lets a spike-run target specific contracts/EOAs
    // (e.g. USDC + vitalik) without dumping the surrounding 300M
    // accounts.
    let already_seeded: HashSet<Address> = out
        .shards
        .iter()
        .flat_map(|s| s.accounts.iter().map(|(a, ..)| *a))
        .collect();

    for raw in &cli.extra_accounts {
        let addr: Address = raw.parse().with_context(|| {
            format!("--account: invalid address {raw:?}")
        })?;
        if already_seeded.contains(&addr) {
            continue;
        }
        // Plain first, then hashed (storage_v2 path).
        let account = match account_cursor.seek_exact(addr)? {
            Some((_, a)) => Some(a),
            None => {
                let h = keccak256(addr);
                hashed_account_cursor.seek_exact(h)?.map(|(_, a)| a)
            }
        };
        let Some(account) = account else {
            warn!(address = %addr, "extra account not found in PlainAccountState or HashedAccounts");
            continue;
        };
        let code_hash = account.bytecode_hash.unwrap_or(KECCAK_EMPTY);
        let shard = shard_for(addr, cli.shard_bits);
        out.shards[shard]
            .accounts
            .push((addr, account.nonce, account.balance, code_hash));
        out.total_accounts += 1;
        if account.bytecode_hash.is_some()
            && code_hash != KECCAK_EMPTY
            && seen_code.insert(code_hash)
        {
            if let Some((_, bytecode)) = bytecode_cursor.seek_exact(code_hash)? {
                out.shards[shard]
                    .code
                    .push((code_hash, bytecode.original_byte_slice().to_vec()));
                out.total_code += 1;
            }
        }
        // Walk storage rows for the targeted account up to the cap.
        // PlainStorageState first, fall back to HashedStorages.
        let mut entry = storage_cursor.seek_exact(addr)?;
        let mut per_acct = 0usize;
        let mut found_plain = false;
        while let Some((haddr, sub)) = entry {
            if haddr != addr || per_acct >= per_acct_cap {
                break;
            }
            let slot = U256::from_be_slice(sub.key.as_slice());
            out.shards[shard].storage.push((addr, slot, sub.value));
            out.total_storage += 1;
            per_acct += 1;
            found_plain = true;
            entry = storage_cursor.next_dup()?;
        }
        if !found_plain {
            // HashedStorages is keyed by keccak256(addr); the slot
            // inner key is keccak256(slot). We don't have a reverse
            // map from hashed slot back to plain slot, so we can
            // only emit storage rows that were explicitly named via
            // `--slot ADDR:SLOT`. That's handled in the next loop.
        }
        info!(address = %addr, "extra account seeded");
    }

    for raw in &cli.extra_slots {
        let Some((a_raw, s_raw)) = raw.split_once(':') else {
            return Err(eyre!("--slot expects ADDR:SLOT, got {raw:?}"));
        };
        let addr: Address = a_raw
            .parse()
            .with_context(|| format!("--slot: invalid address {a_raw:?}"))?;
        let slot: U256 = U256::from_str_radix(
            s_raw.trim_start_matches("0x"),
            16,
        )
        .with_context(|| format!("--slot: invalid slot {s_raw:?}"))?;
        let target_key_be: [u8; 32] = slot.to_be_bytes();
        let target_key = B256::from(target_key_be);
        let shard = shard_for(addr, cli.shard_bits);
        let mut found = false;
        // PlainStorageState first.
        let mut entry = storage_cursor.seek_exact(addr)?;
        while let Some((haddr, sub)) = entry {
            if haddr != addr {
                break;
            }
            if sub.key == target_key {
                out.shards[shard].storage.push((addr, slot, sub.value));
                out.total_storage += 1;
                found = true;
                info!(address = %addr, slot = %slot, value = %sub.value, "extra slot seeded (plain)");
                break;
            }
            entry = storage_cursor.next_dup()?;
        }
        if !found {
            // HashedStorages fallback: dup table keyed by
            // keccak256(addr), inner key keccak256(slot).
            let h_addr = keccak256(addr);
            let h_slot = keccak256(target_key);
            let mut h_entry = hashed_storage_cursor.seek_by_key_subkey(h_addr, h_slot)?;
            // seek_by_key_subkey may land on a higher subkey if the
            // exact slot isn't present.
            while let Some(sub) = h_entry {
                if sub.key != h_slot {
                    break;
                }
                out.shards[shard].storage.push((addr, slot, sub.value));
                out.total_storage += 1;
                found = true;
                info!(address = %addr, slot = %slot, value = %sub.value, "extra slot seeded (hashed)");
                break;
            }
        }
        if !found {
            warn!(address = %addr, slot = %slot, "extra slot not found in PlainStorageState or HashedStorages");
        }
    }

    Ok(out)
}

// ======================== artifact emit ========================

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StateArtifactRef {
    chain_id: u64,
    kind: String,
    from_block: u64,
    to_block: u64,
    state_root: Option<String>,
    object_key: String,
    index_key: Option<String>,
    content_sha256: String,
    /// Phase 26.3 — shard-aware: which shard this ref points at.
    /// `None` for single-shard (`shard_bits=0`) checkpoints.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    shard: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct FinalizedStateArtifactManifest {
    version: u8,
    chain_id: u64,
    block_number: u64,
    block_hash: String,
    state_root: Option<String>,
    /// Single-shard mode: identical to Phase 26.2's schema.
    /// Multi-shard mode: top-level `accounts/storage/code` are
    /// `None`; consult `shards[*]` instead.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    accounts: Option<StateArtifactRef>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    storage: Option<StateArtifactRef>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    code: Option<StateArtifactRef>,
    /// Phase 26.3 — one entry per shard, ordered by shard id
    /// ascending. Each entry has its own (accounts, storage, code)
    /// refs. Empty when `shard_bits == 0`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    shards: Vec<ShardManifest>,
    /// `shard_bits` used to lay out the shards. Readers shard the
    /// same way when looking up by address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    shard_bits: Option<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ShardManifest {
    shard: u32,
    accounts: StateArtifactRef,
    storage: StateArtifactRef,
    code: StateArtifactRef,
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

async fn write_artifacts(
    cli: &Cli,
    block_number: u64,
    block_hash: &str,
    state_root: &Option<String>,
    dump: &StateDump,
) -> eyre::Result<FinalizedStateArtifactManifest> {
    let mut manifest = FinalizedStateArtifactManifest {
        version: 1,
        chain_id: 1, // Mainnet — relay-side bucket is mainnet-only today
        block_number,
        block_hash: block_hash.to_string(),
        state_root: state_root.clone(),
        accounts: None,
        storage: None,
        code: None,
        shards: Vec::new(),
        shard_bits: if cli.shard_bits == 0 {
            None
        } else {
            Some(cli.shard_bits)
        },
    };

    if cli.shard_bits == 0 {
        // Single-shard: matches Phase 26.2 schema exactly.
        let shard = &dump.shards[0];
        let (a_bytes, s_bytes, c_bytes) = write_shard(cli, "0", shard).await?;
        manifest.accounts = Some(make_ref(1, "accounts", block_number, state_root, "accounts.vortex", &a_bytes, None));
        manifest.storage = Some(make_ref(1, "storage", block_number, state_root, "storage.vortex", &s_bytes, None));
        manifest.code = Some(make_ref(1, "code", block_number, state_root, "code.vortex", &c_bytes, None));
    } else {
        for (idx, shard) in dump.shards.iter().enumerate() {
            let dirname = format!("shard-{idx:04}");
            let (a_bytes, s_bytes, c_bytes) = write_shard(cli, &dirname, shard).await?;
            let s = ShardManifest {
                shard: idx as u32,
                accounts: make_ref(
                    1,
                    "accounts",
                    block_number,
                    state_root,
                    &format!("{dirname}/accounts.vortex"),
                    &a_bytes,
                    Some(idx as u32),
                ),
                storage: make_ref(
                    1,
                    "storage",
                    block_number,
                    state_root,
                    &format!("{dirname}/storage.vortex"),
                    &s_bytes,
                    Some(idx as u32),
                ),
                code: make_ref(
                    1,
                    "code",
                    block_number,
                    state_root,
                    &format!("{dirname}/code.vortex"),
                    &c_bytes,
                    Some(idx as u32),
                ),
            };
            manifest.shards.push(s);
        }
    }
    let bytes = serde_json::to_vec_pretty(&manifest)?;
    tokio::fs::write(cli.out_dir.join("manifest.json"), bytes).await?;
    Ok(manifest)
}

async fn write_shard(
    cli: &Cli,
    dirname: &str,
    shard: &ShardData,
) -> eyre::Result<(Vec<u8>, Vec<u8>, Vec<u8>)> {
    let dir = if dirname == "0" {
        cli.out_dir.clone()
    } else {
        let d = cli.out_dir.join(dirname);
        tokio::fs::create_dir_all(&d).await?;
        d
    };
    let a = vortex_writer::accounts_chunk(&shard.accounts).await?;
    let s = vortex_writer::storage_chunk(&shard.storage).await?;
    let c = vortex_writer::code_chunk(&shard.code).await?;
    tokio::fs::write(dir.join("accounts.vortex"), &a).await?;
    tokio::fs::write(dir.join("storage.vortex"), &s).await?;
    tokio::fs::write(dir.join("code.vortex"), &c).await?;
    Ok((a, s, c))
}

fn make_ref(
    chain_id: u64,
    kind: &str,
    block: u64,
    state_root: &Option<String>,
    object_key: &str,
    bytes: &[u8],
    shard: Option<u32>,
) -> StateArtifactRef {
    StateArtifactRef {
        chain_id,
        kind: kind.to_string(),
        from_block: block,
        to_block: block,
        state_root: state_root.clone(),
        object_key: object_key.to_string(),
        index_key: None,
        content_sha256: format!("{:x}", Sha256::digest(bytes)),
        shard,
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

    let upload_one = |local: PathBuf, key: String, ar: &StateArtifactRef| {
        let store = Arc::clone(&store);
        let expected = ar.content_sha256.clone();
        async move {
            let bytes = tokio::fs::read(&local).await?;
            let actual = format!("{:x}", Sha256::digest(&bytes));
            if actual != expected {
                return Err(eyre!(
                    "sha mismatch on {}: local {actual} ≠ manifest {expected}",
                    local.display()
                ));
            }
            store
                .put(&ObjectPath::from(key.as_str()), PutPayload::from(bytes))
                .await?;
            info!(key, "uploaded");
            eyre::Ok(())
        }
    };

    if let (Some(a), Some(s), Some(c)) = (&manifest.accounts, &manifest.storage, &manifest.code) {
        upload_one(
            cli.out_dir.join("accounts.vortex"),
            format!("{dir_prefix}/accounts.vortex"),
            a,
        )
        .await?;
        upload_one(
            cli.out_dir.join("storage.vortex"),
            format!("{dir_prefix}/storage.vortex"),
            s,
        )
        .await?;
        upload_one(
            cli.out_dir.join("code.vortex"),
            format!("{dir_prefix}/code.vortex"),
            c,
        )
        .await?;
    } else {
        for shard in &manifest.shards {
            let local = cli.out_dir.join(format!("shard-{:04}", shard.shard));
            upload_one(
                local.join("accounts.vortex"),
                format!("{dir_prefix}/{}", shard.accounts.object_key),
                &shard.accounts,
            )
            .await?;
            upload_one(
                local.join("storage.vortex"),
                format!("{dir_prefix}/{}", shard.storage.object_key),
                &shard.storage,
            )
            .await?;
            upload_one(
                local.join("code.vortex"),
                format!("{dir_prefix}/{}", shard.code.object_key),
                &shard.code,
            )
            .await?;
        }
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
    store
        .put(&ObjectPath::from(manifest_key.as_str()), PutPayload::from(signed_bytes))
        .await?;
    store
        .put(&ObjectPath::from(sig_key.as_str()), PutPayload::from(signature))
        .await?;
    info!(manifest_key, "uploaded signed checkpoint manifest");

    if params.update_index {
        let index_key = if base.is_empty() {
            "index.json".to_string()
        } else {
            format!("{base}/index.json")
        };
        let mut entries: Vec<CheckpointIndexEntry> = match store
            .get(&ObjectPath::from(index_key.as_str()))
            .await
        {
            Ok(g) => {
                let bytes = g.bytes().await?.to_vec();
                serde_json::from_slice::<CheckpointIndex>(&bytes)
                    .map(|i| i.entries)
                    .unwrap_or_default()
            }
            Err(e) => {
                let msg = e.to_string();
                if msg.contains("NoSuchKey")
                    || msg.contains("NotFound")
                    || msg.contains("status code: 404")
                    || msg.contains("status code: 403")
                    || msg.contains("AccessDenied")
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
        store
            .put(
                &ObjectPath::from(index_key.as_str()),
                PutPayload::from(new_bytes),
            )
            .await?;
        store
            .put(
                &ObjectPath::from(format!("{index_key}.sig").as_str()),
                PutPayload::from(new_sig),
            )
            .await?;
        info!(index_key, "uploaded checkpoint index");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::Address;

    #[test]
    fn shard_for_distributes_addresses() {
        let mut counts = [0usize; 256];
        for i in 0u32..=10_000 {
            let mut bytes = [0u8; 20];
            bytes[0..4].copy_from_slice(&i.to_be_bytes());
            let addr = Address::from(bytes);
            let s = shard_for(addr, 8);
            counts[s] += 1;
        }
        // Bits 0..8 are i.to_be_bytes()[0] which is i >> 24 — all
        // 0 for our small range. The whole 10,000 addresses land
        // in shard 0. This isn't a uniformity test (sequential
        // inputs aren't randomized), but it does prove the
        // function maps every address to a valid shard id.
        assert_eq!(counts[0], 10_001);
        for c in &counts[1..] {
            assert_eq!(*c, 0);
        }
    }

    #[test]
    fn shard_for_high_bits_route_to_high_shards() {
        let mut bytes = [0u8; 20];
        bytes[0] = 0xff;
        let addr = Address::from(bytes);
        assert_eq!(shard_for(addr, 8), 255);

        bytes[0] = 0x80;
        let addr = Address::from(bytes);
        assert_eq!(shard_for(addr, 8), 128);

        bytes[0] = 0xab;
        bytes[1] = 0xcd;
        let addr = Address::from(bytes);
        // 12-bit shard: top 12 bits = 0xabc
        assert_eq!(shard_for(addr, 12), 0xabc);
    }

    #[test]
    fn shard_count_powers_of_two() {
        assert_eq!(shard_count(0), 1);
        assert_eq!(shard_count(1), 2);
        assert_eq!(shard_count(8), 256);
        assert_eq!(shard_count(12), 4096);
    }
}

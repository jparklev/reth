//! Per-shard sha256 diff tool: compares what was emitted for a shard
//! in the bucket Vortex chunks vs what landed in an imported reth
//! MDBX (`HashedAccounts`/`HashedStorages`). The two should be byte-equal
//! for a faithful import.
//!
//! Usage:
//!   shard_probe \
//!     --cache-dir /var/lib/reth/reth-bucket-state-cache-v2/checkpoint-25138564 \
//!     --datadir   /var/lib/reth/reth-bucket-import-test-v2 \
//!     --shard-bits 12 \
//!     --shards 0,1,512,1024,2048,4095
//!
//! For each shard:
//!   * decode `shard-XXXX/accounts-part-*.vortex` from disk cache, sort by hashed_address, sha256
//!     over `(h_addr, nonce_be8, balance_be32, code_hash)`.
//!   * walk MDBX `HashedAccounts` in `[shard_min, shard_max]` and hash with the same canonical
//!     encoding.
//!   * same for storage: `(h_addr, h_slot, value_be32)` sorted by `(h_addr, h_slot)`.
//!   * print the two shas + a short `OK/MISMATCH` summary.
//!
//! Reads only. Safe to run with prod reth + reth-bucket services live, as long
//! as you pass `--datadir` for the IMPORTED (not the prod) datadir.

use std::{collections::BTreeSet, path::PathBuf};

use alloy_consensus::constants::KECCAK_EMPTY;
use alloy_primitives::{B256, U256};
use clap::Parser;
use eyre::Context;
use reth_bucket_state_client::vortex_state::{decode_accounts_chunk, decode_storage_chunk};
use reth_cli_commands::common::{AccessRights, CliNodeTypes, Environment, EnvironmentArgs};
use reth_db_api::{
    cursor::{DbCursorRO, DbDupCursorRO},
    tables::{HashedAccounts, HashedStorages},
    transaction::DbTx,
};
use reth_ethereum_cli::chainspec::EthereumChainSpecParser;
use reth_provider::{providers::ProviderNodeTypes, DatabaseProviderFactory, ProviderFactory};
use sha2::{Digest, Sha256};

#[derive(Parser, Debug)]
#[command(name = "shard_probe", version, about, long_about = None)]
struct Cli {
    /// Bucket state cache root for the pinned checkpoint, e.g.
    /// `/var/lib/reth/reth-bucket-state-cache-v2/checkpoint-25138564/`.
    /// Must contain `shard-XXXX/{accounts,storage}-part-NNNN.vortex` files.
    #[arg(long)]
    cache_dir: PathBuf,

    /// Reth datadir + chain config (same shape `reth db` uses). Opens
    /// MDBX read-only.
    #[command(flatten)]
    env: EnvironmentArgs<EthereumChainSpecParser>,

    /// Shard width in bits (matches `relay-state-checkpointer`'s
    /// `--shard-bits`, default 12). Used to compute each shard's
    /// inclusive `[h_addr_min, h_addr_max]` range.
    #[arg(long, default_value_t = 12u8)]
    shard_bits: u8,

    /// Comma-separated shard IDs to probe. e.g. `0,1,512,1024,4095`.
    #[arg(long)]
    shards: String,

    /// Skip the storage comparison (accounts only). Useful for a fast
    /// sanity check before paying the storage walk's cost.
    #[arg(long)]
    accounts_only: bool,
}

fn main() -> eyre::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info,reth=warn")),
        )
        .init();
    let cli = Cli::parse();
    if cli.shard_bits == 0 || cli.shard_bits > 16 {
        return Err(eyre::eyre!("--shard-bits must be in 1..=16"));
    }

    let task_runtime =
        reth_tasks::RuntimeBuilder::new(reth_tasks::RuntimeConfig::default()).build()?;
    let handle = task_runtime.handle().clone();
    let result = handle.block_on(run(cli, task_runtime.clone()));
    drop(task_runtime);
    result
}

async fn run(cli: Cli, task_runtime: reth_tasks::Runtime) -> eyre::Result<()> {
    let env: Environment<_> =
        cli.env.init::<reth_node_ethereum::node::EthereumNode>(AccessRights::RO, task_runtime)?;
    let factory = env.provider_factory.clone();

    let shards: Vec<u32> = cli
        .shards
        .split(',')
        .filter(|s| !s.is_empty())
        .map(|s| s.parse::<u32>().context(format!("parse shard id {s}")))
        .collect::<eyre::Result<_>>()?;

    for shard in shards {
        probe_shard(&cli, &factory, shard).await?;
    }
    Ok(())
}

async fn probe_shard<N>(cli: &Cli, factory: &ProviderFactory<N>, shard: u32) -> eyre::Result<()>
where
    N: ProviderNodeTypes,
{
    let (lo, hi) = shard_range(shard, cli.shard_bits);
    println!(
        "\n=== shard {shard:04} range=[0x{}..=0x{}] ===",
        hex::encode(&lo.as_slice()[..4]),
        hex::encode(&hi.as_slice()[..4]),
    );

    // ---- accounts ----
    let mut bucket_accts: Vec<(B256, u64, U256, B256)> = Vec::new();
    let shard_dir = cli.cache_dir.join(format!("shard-{shard:04}"));
    if !shard_dir.exists() {
        eyre::bail!("shard cache dir {} does not exist", shard_dir.display());
    }
    let mut part: u32 = 0;
    loop {
        let path = shard_dir.join(format!("accounts-part-{part:04}.vortex"));
        if !path.exists() {
            break;
        }
        let bytes = std::fs::read(&path).context(format!("read {}", path.display()))?;
        let parts_before = bucket_accts.len();
        decode_accounts_chunk(bytes, |row| {
            bucket_accts.push((row.hashed_address, row.nonce, row.balance, row.code_hash));
        })
        .await
        .map_err(|err| eyre::eyre!("decode accounts shard {shard} part {part}: {err}"))?;
        println!(
            "  bucket accounts part {part:04}: +{} rows (total {})",
            bucket_accts.len() - parts_before,
            bucket_accts.len()
        );
        part += 1;
    }
    bucket_accts.sort_unstable_by_key(|r| r.0);
    let bucket_accts_sha = sha_accounts(&bucket_accts);
    println!("  bucket accounts: {} rows  sha=0x{bucket_accts_sha}", bucket_accts.len());

    // MDBX accounts in [lo, hi].
    let provider = factory.database_provider_ro()?;
    let tx = provider.tx_ref();
    let mut acct_cursor = tx.cursor_read::<HashedAccounts>()?;
    let mut mdbx_accts: Vec<(B256, u64, U256, B256)> = Vec::new();
    let mut entry = acct_cursor.seek(lo)?;
    while let Some((k, account)) = entry {
        if k > hi {
            break;
        }
        let ch = account.bytecode_hash.unwrap_or(KECCAK_EMPTY);
        mdbx_accts.push((k, account.nonce, account.balance, ch));
        entry = acct_cursor.next()?;
    }
    let mdbx_accts_sha = sha_accounts(&mdbx_accts);
    println!("  mdbx   accounts: {} rows  sha=0x{mdbx_accts_sha}", mdbx_accts.len());

    if bucket_accts.len() != mdbx_accts.len() {
        println!(
            "  ACCOUNT-COUNT MISMATCH: bucket {} vs mdbx {} (Δ={})",
            bucket_accts.len(),
            mdbx_accts.len(),
            mdbx_accts.len() as i64 - bucket_accts.len() as i64
        );
    }
    if bucket_accts_sha != mdbx_accts_sha {
        println!("  ACCOUNT-SHA MISMATCH");
        // Identify first divergence by sorted hashed_address.
        let mut bi = bucket_accts.iter();
        let mut mi = mdbx_accts.iter();
        let mut b = bi.next();
        let mut m = mi.next();
        let mut diffs = 0;
        while diffs < 16 && (b.is_some() || m.is_some()) {
            match (b, m) {
                (Some(br), Some(mr)) => {
                    if br.0 == mr.0 {
                        if br != mr {
                            println!(
                                "    DIFF h_addr={} bucket=({},{},{}) mdbx=({},{},{})",
                                br.0, br.1, br.2, br.3, mr.1, mr.2, mr.3,
                            );
                            diffs += 1;
                        }
                        b = bi.next();
                        m = mi.next();
                    } else if br.0 < mr.0 {
                        println!("    ONLY-IN-BUCKET h_addr={}", br.0);
                        diffs += 1;
                        b = bi.next();
                    } else {
                        println!("    ONLY-IN-MDBX h_addr={}", mr.0);
                        diffs += 1;
                        m = mi.next();
                    }
                }
                (Some(br), None) => {
                    println!("    ONLY-IN-BUCKET h_addr={} (mdbx tail empty)", br.0);
                    diffs += 1;
                    b = bi.next();
                }
                (None, Some(mr)) => {
                    println!("    ONLY-IN-MDBX h_addr={} (bucket tail empty)", mr.0);
                    diffs += 1;
                    m = mi.next();
                }
                (None, None) => break,
            }
        }
    } else {
        println!("  accounts: OK (sha matches)");
    }

    if cli.accounts_only {
        return Ok(());
    }

    // ---- storage ----
    let mut bucket_storage: Vec<(B256, B256, U256)> = Vec::new();
    let mut part: u32 = 0;
    loop {
        let path = shard_dir.join(format!("storage-part-{part:04}.vortex"));
        if !path.exists() {
            break;
        }
        let bytes = std::fs::read(&path).context(format!("read {}", path.display()))?;
        let before = bucket_storage.len();
        decode_storage_chunk(bytes, |row| {
            bucket_storage.push((row.hashed_address, row.hashed_slot, row.value));
        })
        .await
        .map_err(|err| eyre::eyre!("decode storage shard {shard} part {part}: {err}"))?;
        println!(
            "  bucket storage part  {part:04}: +{} rows (total {})",
            bucket_storage.len() - before,
            bucket_storage.len()
        );
        part += 1;
    }
    // Track in-bucket dup keys before sort (writer side should never emit dups).
    let mut bucket_dups: BTreeSet<(B256, B256)> = BTreeSet::new();
    {
        let mut seen: BTreeSet<(B256, B256)> = BTreeSet::new();
        for row in &bucket_storage {
            let k = (row.0, row.1);
            if !seen.insert(k) {
                bucket_dups.insert(k);
            }
        }
    }
    // Bucket convention: value=0 rows are NOT stored in HashedStorages (importer drops them).
    // Drop them here too so the comparison is apples-to-apples.
    bucket_storage.retain(|r| !r.2.is_zero());
    bucket_storage.sort_unstable_by_key(|r| (r.0, r.1));
    let bucket_storage_sha = sha_storage(&bucket_storage);
    println!(
        "  bucket storage: {} non-zero rows  in-bucket dup-keys={}  sha=0x{bucket_storage_sha}",
        bucket_storage.len(),
        bucket_dups.len(),
    );
    if !bucket_dups.is_empty() {
        let preview: Vec<_> = bucket_dups.iter().take(4).collect();
        println!("    first bucket dup keys: {preview:?}");
    }

    // MDBX storage in [lo, hi].
    let mut store_cursor = tx.cursor_dup_read::<HashedStorages>()?;
    let mut mdbx_storage: Vec<(B256, B256, U256)> = Vec::new();
    let mut mdbx_dups: BTreeSet<(B256, B256)> = BTreeSet::new();
    {
        let mut walk = store_cursor.walk(Some(lo))?;
        while let Some(row) = walk.next() {
            let (h_addr, entry) = row?;
            if h_addr > hi {
                break;
            }
            mdbx_storage.push((h_addr, entry.key, entry.value));
        }
    }
    {
        let mut seen: BTreeSet<(B256, B256)> = BTreeSet::new();
        for row in &mdbx_storage {
            let k = (row.0, row.1);
            if !seen.insert(k) {
                mdbx_dups.insert(k);
            }
        }
    }
    mdbx_storage.sort_unstable_by_key(|r| (r.0, r.1));
    let mdbx_storage_sha = sha_storage(&mdbx_storage);
    println!(
        "  mdbx   storage: {} rows  in-mdbx dup-keys={}  sha=0x{mdbx_storage_sha}",
        mdbx_storage.len(),
        mdbx_dups.len(),
    );
    if !mdbx_dups.is_empty() {
        let preview: Vec<_> = mdbx_dups.iter().take(4).collect();
        println!("    first mdbx dup keys: {preview:?}");
    }

    if bucket_storage.len() != mdbx_storage.len() {
        println!(
            "  STORAGE-COUNT MISMATCH: bucket {} vs mdbx {} (Δ={})",
            bucket_storage.len(),
            mdbx_storage.len(),
            mdbx_storage.len() as i64 - bucket_storage.len() as i64
        );
    }
    if bucket_storage_sha != mdbx_storage_sha {
        println!("  STORAGE-SHA MISMATCH");
        // First 16 row-by-row diffs.
        let mut bi = bucket_storage.iter();
        let mut mi = mdbx_storage.iter();
        let mut b = bi.next();
        let mut m = mi.next();
        let mut diffs = 0;
        while diffs < 16 && (b.is_some() || m.is_some()) {
            match (b, m) {
                (Some(br), Some(mr)) => {
                    let bk = (br.0, br.1);
                    let mk = (mr.0, mr.1);
                    if bk == mk {
                        if br.2 != mr.2 {
                            println!(
                                "    DIFF h_addr={} h_slot={} bucket={} mdbx={}",
                                br.0, br.1, br.2, mr.2
                            );
                            diffs += 1;
                        }
                        b = bi.next();
                        m = mi.next();
                    } else if bk < mk {
                        println!(
                            "    ONLY-IN-BUCKET h_addr={} h_slot={} value={}",
                            br.0, br.1, br.2
                        );
                        diffs += 1;
                        b = bi.next();
                    } else {
                        println!("    ONLY-IN-MDBX h_addr={} h_slot={} value={}", mr.0, mr.1, mr.2);
                        diffs += 1;
                        m = mi.next();
                    }
                }
                (Some(br), None) => {
                    println!("    ONLY-IN-BUCKET h_addr={} h_slot={}", br.0, br.1);
                    diffs += 1;
                    b = bi.next();
                }
                (None, Some(mr)) => {
                    println!("    ONLY-IN-MDBX h_addr={} h_slot={}", mr.0, mr.1);
                    diffs += 1;
                    m = mi.next();
                }
                (None, None) => break,
            }
        }
    } else {
        println!("  storage: OK (sha matches)");
    }
    Ok(())
}

fn sha_accounts(rows: &[(B256, u64, U256, B256)]) -> String {
    let mut h = Sha256::new();
    let mut tmp = [0u8; 32];
    for (addr, nonce, balance, code_hash) in rows {
        h.update(addr.as_slice());
        h.update(nonce.to_be_bytes());
        h.update(balance.to_be_bytes::<32>());
        h.update(code_hash.as_slice());
        tmp[0] ^= 0; // suppress unused
    }
    let _ = tmp;
    format!("{:x}", h.finalize())
}

fn sha_storage(rows: &[(B256, B256, U256)]) -> String {
    let mut h = Sha256::new();
    for (addr, slot, value) in rows {
        h.update(addr.as_slice());
        h.update(slot.as_slice());
        h.update(value.to_be_bytes::<32>());
    }
    format!("{:x}", h.finalize())
}

fn shard_range(shard_id: u32, bits: u8) -> (B256, B256) {
    let mut min = [0u8; 32];
    let mut max = [0xffu8; 32];
    let shifted = (shard_id as u32) << (16 - bits as u32);
    min[0] = (shifted >> 8) as u8;
    min[1] = (shifted & 0xff) as u8;
    let upper = shifted | ((1u32 << (16 - bits as u32)) - 1);
    max[0] = (upper >> 8) as u8;
    max[1] = (upper & 0xff) as u8;
    (B256::from(min), B256::from(max))
}

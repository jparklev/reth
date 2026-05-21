//! Per-shard MDBX diff: prod reth datadir vs imported reth datadir.
//!
//! Opens both MDBX environments read-only, walks `HashedAccounts` and
//! `HashedStorages` in each shard's hash range, and reports:
//!
//!   - rows-only-in-prod  (account or storage missing from import)
//!   - rows-only-in-import (only if writer leaked stale rows; expected 0)
//!   - rows-with-different-values
//!
//! For each missing/different row, also reports its position WITHIN the shard
//! range: the first byte (and the bottom 4 bits of the second byte for 12-bit
//! shards). This lets us spot writer bugs that drop rows at specific
//! shard-boundary offsets vs natural per-block drift (which is uniform).
//!
//! Usage:
//!   prod_probe \
//!     --prod-db    /var/lib/reth/db \
//!     --import-db  /var/lib/reth/reth-bucket-import-test-v2/db \
//!     --shard-bits 12 \
//!     --shards 0,1,512,1024,2048,4095 \
//!     [--accounts-only] [--max-diffs 32]
//!
//! Prod reth's MDBX is opened in `MDBX_RDONLY` mode and tolerates a live
//! writer in the same datadir (MDBX is MVCC). We never write to either DB.

use std::path::PathBuf;

use alloy_consensus::constants::KECCAK_EMPTY;
use alloy_primitives::{B256, U256};
use clap::Parser;
use eyre::Context;
use reth_db::{mdbx::DatabaseArguments, open_db_read_only, ClientVersion};
use reth_db_api::{
    cursor::DbCursorRO,
    database::Database,
    tables::{HashedAccounts, HashedStorages},
    transaction::DbTx,
};
use sha2::{Digest, Sha256};

#[derive(Parser, Debug)]
#[command(name = "prod_probe", version, about, long_about = None)]
struct Cli {
    /// Path to prod reth's MDBX directory (the one containing `mdbx.dat`).
    #[arg(long)]
    prod_db: PathBuf,

    /// Path to the import reth's MDBX directory (the one containing `mdbx.dat`).
    #[arg(long)]
    import_db: PathBuf,

    /// Shard width in bits (matches the checkpointer's `--shard-bits`,
    /// typically 12 for 4096 shards).
    #[arg(long, default_value_t = 12u8)]
    shard_bits: u8,

    /// Comma-separated shard IDs to probe. Empty = none.
    #[arg(long, default_value = "")]
    shards: String,

    /// If set, probe ALL `2^shard_bits` shards. Overrides `--shards`.
    #[arg(long)]
    all: bool,

    /// Skip the storage comparison (accounts only). Useful for an O(N)
    /// fast pass before paying the storage walk's cost.
    #[arg(long)]
    accounts_only: bool,

    /// Cap the number of per-shard row-diff lines printed. Counts are always
    /// reported in full.
    #[arg(long, default_value_t = 16usize)]
    max_diffs: usize,

    /// Only print SHARDS that have a mismatch. Otherwise print every shard.
    #[arg(long)]
    only_mismatches: bool,
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

    // Open both MDBX envs read-only. Reth runs `MDBX_RDONLY` here, which
    // is MVCC-safe to run alongside a live writer in the same datadir.
    let prod = open_db_read_only(&cli.prod_db, DatabaseArguments::new(ClientVersion::default()))
        .with_context(|| format!("open prod MDBX at {}", cli.prod_db.display()))?;
    let import =
        open_db_read_only(&cli.import_db, DatabaseArguments::new(ClientVersion::default()))
            .with_context(|| format!("open import MDBX at {}", cli.import_db.display()))?;

    let shard_ids: Vec<u32> = if cli.all {
        (0..(1u32 << cli.shard_bits)).collect()
    } else {
        cli.shards
            .split(',')
            .filter(|s| !s.is_empty())
            .map(|s| s.parse::<u32>().context(format!("parse shard id {s}")))
            .collect::<eyre::Result<_>>()?
    };

    let mut grand = GrandTotals::default();
    for shard in shard_ids {
        let summary = probe_shard(&cli, &prod, &import, shard)?;
        if !cli.only_mismatches || summary.has_mismatch() {
            summary.print(shard);
        }
        grand.merge(&summary);
    }
    println!();
    grand.print();
    Ok(())
}

#[derive(Default, Clone)]
struct ShardSummary {
    acct_only_prod: u64,
    acct_only_import: u64,
    acct_diff: u64,
    acct_prod_total: u64,
    acct_import_total: u64,
    acct_prod_sha: String,
    acct_import_sha: String,
    storage_only_prod: u64,
    storage_only_import: u64,
    storage_diff: u64,
    storage_prod_total: u64,
    storage_import_total: u64,
    storage_prod_sha: String,
    storage_import_sha: String,
    /// Lowest byte-offset (within the shard's hash range, treated as a u16 of
    /// `(byte1, byte2)`) at which we saw a mismatched account. Helps spot
    /// shard-boundary off-by-one bugs.
    acct_min_off: Option<u16>,
    acct_max_off: Option<u16>,
    storage_min_off: Option<u16>,
    storage_max_off: Option<u16>,
}

impl ShardSummary {
    fn has_mismatch(&self) -> bool {
        self.acct_only_prod > 0 ||
            self.acct_only_import > 0 ||
            self.acct_diff > 0 ||
            self.storage_only_prod > 0 ||
            self.storage_only_import > 0 ||
            self.storage_diff > 0
    }

    fn print(&self, shard: u32) {
        println!(
            "shard {shard:04} accts prod={:>7} imp={:>7} only_prod={:>5} only_imp={:>5} diff={:>5} off=[{},{}] sha_prod=0x{}.. sha_imp=0x{}..",
            self.acct_prod_total,
            self.acct_import_total,
            self.acct_only_prod,
            self.acct_only_import,
            self.acct_diff,
            off_to_str(self.acct_min_off),
            off_to_str(self.acct_max_off),
            short(&self.acct_prod_sha),
            short(&self.acct_import_sha),
        );
        println!(
            "          stor  prod={:>7} imp={:>7} only_prod={:>5} only_imp={:>5} diff={:>5} off=[{},{}] sha_prod=0x{}.. sha_imp=0x{}..",
            self.storage_prod_total,
            self.storage_import_total,
            self.storage_only_prod,
            self.storage_only_import,
            self.storage_diff,
            off_to_str(self.storage_min_off),
            off_to_str(self.storage_max_off),
            short(&self.storage_prod_sha),
            short(&self.storage_import_sha),
        );
    }
}

#[derive(Default)]
struct GrandTotals {
    shards: u64,
    mismatched_shards: u64,
    acct_only_prod: u64,
    acct_only_import: u64,
    acct_diff: u64,
    acct_prod_total: u64,
    acct_import_total: u64,
    storage_only_prod: u64,
    storage_only_import: u64,
    storage_diff: u64,
    storage_prod_total: u64,
    storage_import_total: u64,
}

impl GrandTotals {
    fn merge(&mut self, s: &ShardSummary) {
        self.shards += 1;
        if s.has_mismatch() {
            self.mismatched_shards += 1;
        }
        self.acct_only_prod += s.acct_only_prod;
        self.acct_only_import += s.acct_only_import;
        self.acct_diff += s.acct_diff;
        self.acct_prod_total += s.acct_prod_total;
        self.acct_import_total += s.acct_import_total;
        self.storage_only_prod += s.storage_only_prod;
        self.storage_only_import += s.storage_only_import;
        self.storage_diff += s.storage_diff;
        self.storage_prod_total += s.storage_prod_total;
        self.storage_import_total += s.storage_import_total;
    }

    fn print(&self) {
        println!(
            "=== TOTALS over {} shards ({} mismatched) ===",
            self.shards, self.mismatched_shards
        );
        println!(
            "accts prod={:>9} imp={:>9} only_prod={:>6} only_imp={:>6} diff={:>6}",
            self.acct_prod_total,
            self.acct_import_total,
            self.acct_only_prod,
            self.acct_only_import,
            self.acct_diff,
        );
        println!(
            "stor  prod={:>9} imp={:>9} only_prod={:>6} only_imp={:>6} diff={:>6}",
            self.storage_prod_total,
            self.storage_import_total,
            self.storage_only_prod,
            self.storage_only_import,
            self.storage_diff,
        );
    }
}

fn probe_shard<P, I>(cli: &Cli, prod: &P, import: &I, shard: u32) -> eyre::Result<ShardSummary>
where
    P: Database,
    I: Database,
{
    let (lo, hi) = shard_range(shard, cli.shard_bits);

    // ---- accounts ----
    let prod_tx = prod.tx()?;
    let import_tx = import.tx()?;
    let prod_accts = read_accounts(&prod_tx, lo, hi)?;
    let import_accts = read_accounts(&import_tx, lo, hi)?;

    let prod_accts_sha = sha_accounts(&prod_accts);
    let import_accts_sha = sha_accounts(&import_accts);

    let mut summary = ShardSummary {
        acct_prod_total: prod_accts.len() as u64,
        acct_import_total: import_accts.len() as u64,
        acct_prod_sha: prod_accts_sha,
        acct_import_sha: import_accts_sha,
        ..Default::default()
    };

    let mut printed = 0usize;
    diff_accounts(&prod_accts, &import_accts, |kind, h_addr, prod_row, import_row| {
        let off = ((h_addr.as_slice()[0] as u16) << 8) | h_addr.as_slice()[1] as u16;
        match kind {
            DiffKind::OnlyA => {
                summary.acct_only_prod += 1;
                bump_off(&mut summary.acct_min_off, &mut summary.acct_max_off, off);
                if printed < cli.max_diffs {
                    let r = prod_row.unwrap();
                    println!("    ACCT only-in-prod  shard {shard:04}  h_addr={h_addr:?}  nonce={} bal={} code={:?}", r.1, r.2, r.3);
                    printed += 1;
                }
            }
            DiffKind::OnlyB => {
                summary.acct_only_import += 1;
                bump_off(&mut summary.acct_min_off, &mut summary.acct_max_off, off);
                if printed < cli.max_diffs {
                    let r = import_row.unwrap();
                    println!("    ACCT only-in-IMPORT shard {shard:04}  h_addr={h_addr:?}  nonce={} bal={} code={:?}", r.1, r.2, r.3);
                    printed += 1;
                }
            }
            DiffKind::Diff => {
                summary.acct_diff += 1;
                bump_off(&mut summary.acct_min_off, &mut summary.acct_max_off, off);
                if printed < cli.max_diffs {
                    let p = prod_row.unwrap();
                    let i = import_row.unwrap();
                    println!(
                        "    ACCT diff shard {shard:04}  h_addr={h_addr:?}  prod=(n={},b={},c={:?}) imp=(n={},b={},c={:?})",
                        p.1, p.2, p.3, i.1, i.2, i.3
                    );
                    printed += 1;
                }
            }
        }
    });

    if cli.accounts_only {
        return Ok(summary);
    }

    // ---- storage ----
    let prod_storage = read_storage(&prod_tx, lo, hi)?;
    let import_storage = read_storage(&import_tx, lo, hi)?;

    summary.storage_prod_total = prod_storage.len() as u64;
    summary.storage_import_total = import_storage.len() as u64;
    summary.storage_prod_sha = sha_storage(&prod_storage);
    summary.storage_import_sha = sha_storage(&import_storage);

    let mut printed = 0usize;
    diff_storage(&prod_storage, &import_storage, |kind, key, prod_v, import_v| {
        let off = ((key.0.as_slice()[0] as u16) << 8) | key.0.as_slice()[1] as u16;
        match kind {
            DiffKind::OnlyA => {
                summary.storage_only_prod += 1;
                bump_off(&mut summary.storage_min_off, &mut summary.storage_max_off, off);
                if printed < cli.max_diffs {
                    println!(
                        "    STOR only-in-prod  shard {shard:04}  h_addr={:?} slot={:?} v={}",
                        key.0,
                        key.1,
                        prod_v.unwrap()
                    );
                    printed += 1;
                }
            }
            DiffKind::OnlyB => {
                summary.storage_only_import += 1;
                bump_off(&mut summary.storage_min_off, &mut summary.storage_max_off, off);
                if printed < cli.max_diffs {
                    println!(
                        "    STOR only-in-IMPORT shard {shard:04}  h_addr={:?} slot={:?} v={}",
                        key.0,
                        key.1,
                        import_v.unwrap()
                    );
                    printed += 1;
                }
            }
            DiffKind::Diff => {
                summary.storage_diff += 1;
                bump_off(&mut summary.storage_min_off, &mut summary.storage_max_off, off);
                if printed < cli.max_diffs {
                    println!(
                        "    STOR diff shard {shard:04}  h_addr={:?} slot={:?} prod={} imp={}",
                        key.0,
                        key.1,
                        prod_v.unwrap(),
                        import_v.unwrap()
                    );
                    printed += 1;
                }
            }
        }
    });

    Ok(summary)
}

fn read_accounts<TX: DbTx>(
    tx: &TX,
    lo: B256,
    hi: B256,
) -> eyre::Result<Vec<(B256, u64, U256, B256)>> {
    let mut cursor = tx.cursor_read::<HashedAccounts>()?;
    let mut out = Vec::new();
    let mut entry = cursor.seek(lo)?;
    while let Some((k, account)) = entry {
        if k > hi {
            break;
        }
        // Flatten bytecode_hash: None -> KECCAK_EMPTY so that we compare
        // semantically equal accounts even if one side wrote a None and the
        // other wrote a Some(KECCAK_EMPTY). (Reth itself stores None for
        // EOAs; the bucket writer flattens to KECCAK_EMPTY and the importer
        // flattens back to None, so both sides should already match — but
        // canonicalize defensively.)
        let ch = account.bytecode_hash.unwrap_or(KECCAK_EMPTY);
        out.push((k, account.nonce, account.balance, ch));
        entry = cursor.next()?;
    }
    Ok(out)
}

fn read_storage<TX: DbTx>(tx: &TX, lo: B256, hi: B256) -> eyre::Result<Vec<(B256, B256, U256)>> {
    let mut cursor = tx.cursor_dup_read::<HashedStorages>()?;
    let mut out = Vec::new();
    let mut walk = cursor.walk(Some(lo))?;
    while let Some(row) = walk.next() {
        let (h_addr, entry) = row?;
        if h_addr > hi {
            break;
        }
        out.push((h_addr, entry.key, entry.value));
    }
    out.sort_unstable_by_key(|r| (r.0, r.1));
    Ok(out)
}

#[derive(Copy, Clone)]
enum DiffKind {
    OnlyA,
    OnlyB,
    Diff,
}

fn diff_accounts<F>(a: &[(B256, u64, U256, B256)], b: &[(B256, u64, U256, B256)], mut emit: F)
where
    F: FnMut(DiffKind, B256, Option<&(B256, u64, U256, B256)>, Option<&(B256, u64, U256, B256)>),
{
    // Both inputs are sorted by hashed_address (`read_accounts` cursor walks
    // in key order; sort is implicit on the prod side from MDBX layout).
    let mut i = 0usize;
    let mut j = 0usize;
    while i < a.len() && j < b.len() {
        let ka = a[i].0;
        let kb = b[j].0;
        if ka == kb {
            if a[i] != b[j] {
                emit(DiffKind::Diff, ka, Some(&a[i]), Some(&b[j]));
            }
            i += 1;
            j += 1;
        } else if ka < kb {
            emit(DiffKind::OnlyA, ka, Some(&a[i]), None);
            i += 1;
        } else {
            emit(DiffKind::OnlyB, kb, None, Some(&b[j]));
            j += 1;
        }
    }
    while i < a.len() {
        let ka = a[i].0;
        emit(DiffKind::OnlyA, ka, Some(&a[i]), None);
        i += 1;
    }
    while j < b.len() {
        let kb = b[j].0;
        emit(DiffKind::OnlyB, kb, None, Some(&b[j]));
        j += 1;
    }
}

fn diff_storage<F>(a: &[(B256, B256, U256)], b: &[(B256, B256, U256)], mut emit: F)
where
    F: FnMut(DiffKind, (B256, B256), Option<U256>, Option<U256>),
{
    let mut i = 0usize;
    let mut j = 0usize;
    while i < a.len() && j < b.len() {
        let ka = (a[i].0, a[i].1);
        let kb = (b[j].0, b[j].1);
        if ka == kb {
            if a[i].2 != b[j].2 {
                emit(DiffKind::Diff, ka, Some(a[i].2), Some(b[j].2));
            }
            i += 1;
            j += 1;
        } else if ka < kb {
            emit(DiffKind::OnlyA, ka, Some(a[i].2), None);
            i += 1;
        } else {
            emit(DiffKind::OnlyB, kb, None, Some(b[j].2));
            j += 1;
        }
    }
    while i < a.len() {
        let ka = (a[i].0, a[i].1);
        emit(DiffKind::OnlyA, ka, Some(a[i].2), None);
        i += 1;
    }
    while j < b.len() {
        let kb = (b[j].0, b[j].1);
        emit(DiffKind::OnlyB, kb, None, Some(b[j].2));
        j += 1;
    }
}

fn bump_off(min: &mut Option<u16>, max: &mut Option<u16>, off: u16) {
    *min = Some(min.map(|m| m.min(off)).unwrap_or(off));
    *max = Some(max.map(|m| m.max(off)).unwrap_or(off));
}

fn off_to_str(o: Option<u16>) -> String {
    o.map(|v| format!("0x{v:04x}")).unwrap_or_else(|| "----".into())
}

fn short(s: &str) -> &str {
    if s.len() < 12 {
        s
    } else {
        &s[..12]
    }
}

fn sha_accounts(rows: &[(B256, u64, U256, B256)]) -> String {
    let mut h = Sha256::new();
    for (addr, nonce, balance, code_hash) in rows {
        h.update(addr.as_slice());
        h.update(nonce.to_be_bytes());
        h.update(balance.to_be_bytes::<32>());
        h.update(code_hash.as_slice());
    }
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

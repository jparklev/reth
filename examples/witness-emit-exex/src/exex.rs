//! Witness-emit ExEx.
//!
//! For every canonically committed block, re-execute against the parent state
//! provider (guaranteed consistent inside the node process — see
//! `BlockchainProvider::consistent_provider`), record the touched state via
//! `ExecutionWitnessRecord`, and write a bincode+zstd `WitnessBundle` atomically
//! to `--witness-emit-dir/<num>-<hash>.witness.zst`.
//!
//! Why re-execute: `Chain::execution_outcome()` carries the post-state bundle
//! (changed accounts/slots) but NOT the access list of reads that returned the
//! original value. Without those, the resulting witness is missing nodes a
//! stateless validator needs to recompute the state root.
//!
//! Re-orgs: on `ChainReverted` / `ChainReorged.old`, rename the now-orphaned
//! witness files to `<...>.witness.zst.stale` so the uploader can skip them.

use alloy_consensus::BlockHeader;
use alloy_eips::{eip2935, eip4788, eip7002, eip7251};
use alloy_primitives::B256;
use alloy_rlp::Encodable;
use eyre::WrapErr;
use futures_util::StreamExt;
use reth_ethereum::{
    exex::{ExExContext, ExExEvent},
    node::api::{FullNodeComponents, NodePrimitives, NodeTypes},
    EthPrimitives,
};
use reth_evm::{execute::Executor, ConfigureEvm};
use reth_revm::{database::StateProviderDatabase, db::State, witness::ExecutionWitnessRecord};
use reth_storage_api::StateProviderFactory;
use reth_trie_common::ExecutionWitnessMode;
use std::{
    path::{Path, PathBuf},
    time::Instant,
};
use tracing::{debug, error, info, warn};

use crate::bundle::{encode_bundle, Encoding, WitnessBundle};

// ---------------------------------------------------------------------------
// Prometheus metrics
//
// We piggyback on reth's process-wide Prometheus recorder (installed by
// `reth_node_metrics::recorder::install_prometheus_recorder`) so all metric
// names land on the same `--metrics` scrape endpoint.
// ---------------------------------------------------------------------------

/// Counter: total per-block emit attempts, labelled `result=ok|err|stale_reorg`.
const EMIT_TOTAL: &str = "witness_emit_total";
/// Histogram: end-to-end notification -> file-durable latency, seconds.
const EMIT_E2E_SECONDS: &str = "witness_emit_e2e_seconds";
/// Histogram: re-execution time, seconds.
const EMIT_EXECUTE_SECONDS: &str = "witness_emit_execute_seconds";
/// Histogram: witness build (proof generation) time, seconds.
const EMIT_BUILD_SECONDS: &str = "witness_emit_build_seconds";
/// Histogram: bincode+zstd encode time, seconds.
const EMIT_ENCODE_SECONDS: &str = "witness_emit_encode_seconds";
/// Histogram: encoded witness size, bytes.
const EMIT_SIZE_BYTES: &str = "witness_emit_size_bytes";
/// Gauge: latest block number for which a witness file was durably written.
const EMIT_HIGHEST_BLOCK: &str = "witness_emit_highest_block";
/// Counter: re-org events handled.
const EMIT_REORG_TOTAL: &str = "witness_emit_reorg_total";
/// Counter: blocks marked `.stale` due to a re-org.
const EMIT_STALE_MARKED_TOTAL: &str = "witness_emit_stale_marked_total";

/// Per-block stats line appended to the `--stats` JSONL file (or stdout if no
/// stats file is configured).
#[derive(serde::Serialize)]
struct BlockStats {
    ts: String,
    block_number: u64,
    block_hash: String,
    parent_hash: String,
    tx_count: usize,
    size_bytes: u64,
    state_nodes: usize,
    codes: usize,
    keys: usize,
    /// `state_by_block_hash(parent)` latency.
    state_open_ms: u128,
    /// `executor.execute_with_state_closure` latency (full re-execution).
    execute_ms: u128,
    /// `into_execution_witness` latency (proof generation + ancestor headers).
    witness_build_ms: u128,
    /// Bincode + zstd-3 encode latency.
    encode_ms: u128,
    /// Temp-write + fsync + rename latency.
    write_ms: u128,
    /// Total `ChainCommitted` -> file-durable wall clock (per block).
    e2e_ms: u128,
}

/// Configurable ExEx.
pub(crate) struct WitnessEmitExEx<Node: FullNodeComponents> {
    ctx: ExExContext<Node>,
    out_dir: PathBuf,
    stats_path: Option<PathBuf>,
}

impl<Node> WitnessEmitExEx<Node>
where
    Node: FullNodeComponents<Types: NodeTypes<Primitives = EthPrimitives>>,
{
    pub(crate) const fn new(
        ctx: ExExContext<Node>,
        out_dir: PathBuf,
        stats_path: Option<PathBuf>,
    ) -> Self {
        Self { ctx, out_dir, stats_path }
    }

    /// Main loop. Exits when the notification stream is closed.
    pub(crate) async fn run(mut self) -> eyre::Result<()> {
        std::fs::create_dir_all(&self.out_dir)
            .wrap_err_with(|| format!("create out_dir {}", self.out_dir.display()))?;
        if let Some(stats) = &self.stats_path &&
            let Some(parent) = stats.parent()
        {
            std::fs::create_dir_all(parent).ok();
        }
        info!(out_dir = %self.out_dir.display(), "witness-emit ExEx ready");

        describe_metrics();

        while let Some(result) = self.ctx.notifications.next().await {
            let notification = result.wrap_err("recv ExEx notification")?;

            // Mark reverted blocks stale BEFORE we emit new ones — so a reader
            // listing the dir during a reorg sees a consistent state.
            if let Some(old) = notification.reverted_chain() {
                metrics::counter!(EMIT_REORG_TOTAL).increment(1);
                for block in old.blocks_iter() {
                    let path = witness_path(&self.out_dir, block.number(), block.hash());
                    if let Err(err) = mark_stale(&path) {
                        warn!(?err, block = block.number(), "mark stale failed");
                    } else {
                        info!(block = block.number(), hash = %block.hash(), "marked stale (reorg)");
                        metrics::counter!(EMIT_STALE_MARKED_TOTAL).increment(1);
                    }
                }
            }

            if let Some(committed) = notification.committed_chain() {
                let range = committed.range();
                debug!(?range, "ChainCommitted");

                let mut highest_durable: Option<alloy_eips::BlockNumHash> = None;
                let mut had_failure = false;
                for block in committed.blocks_iter() {
                    let block_started = Instant::now();
                    match emit_block(&self.ctx, &self.out_dir, block, block_started) {
                        Ok(stats) => {
                            self.write_stats(&stats);
                            // Histograms accept f64 seconds; the recorder maps
                            // them onto its bucket layout. We feed seconds so a
                            // single dashboard expression works regardless of
                            // whether we ever switch to summary types.
                            metrics::counter!(EMIT_TOTAL, "result" => "ok").increment(1);
                            metrics::histogram!(EMIT_E2E_SECONDS)
                                .record(stats.e2e_ms as f64 / 1000.0);
                            metrics::histogram!(EMIT_EXECUTE_SECONDS)
                                .record(stats.execute_ms as f64 / 1000.0);
                            metrics::histogram!(EMIT_BUILD_SECONDS)
                                .record(stats.witness_build_ms as f64 / 1000.0);
                            metrics::histogram!(EMIT_ENCODE_SECONDS)
                                .record(stats.encode_ms as f64 / 1000.0);
                            metrics::histogram!(EMIT_SIZE_BYTES).record(stats.size_bytes as f64);
                            metrics::gauge!(EMIT_HIGHEST_BLOCK).set(stats.block_number as f64);
                            info!(
                                block = stats.block_number,
                                e2e_ms = stats.e2e_ms,
                                execute_ms = stats.execute_ms,
                                witness_build_ms = stats.witness_build_ms,
                                size_kb = stats.size_bytes / 1024,
                                "emitted"
                            );
                            highest_durable = Some(block.num_hash());
                        }
                        Err(err) => {
                            // A per-block emit failure is most likely a stale
                            // notification (e.g. parent state pruned because a
                            // newer fork won) — that case will be cleaned up
                            // by the ChainReverted notification that's already
                            // queued behind us. Don't kill the ExEx; record
                            // the failure as a stats line and keep going. The
                            // uploader scans for `.stale` files so a missing
                            // `.witness.zst` simply doesn't get advertised.
                            had_failure = true;
                            metrics::counter!(EMIT_TOTAL, "result" => "err").increment(1);
                            error!(block = block.number(), ?err, "emit failed; continuing");
                            let line = serde_json::json!({
                                "ts": chrono_rfc3339(),
                                "block_number": block.number(),
                                "block_hash": format!("{:?}", block.hash()),
                                "skipped": true,
                                "err": format!("{err:?}"),
                            });
                            if let Some(path) = &self.stats_path {
                                use std::io::Write;
                                if let Ok(mut f) =
                                    std::fs::OpenOptions::new().create(true).append(true).open(path)
                                {
                                    let _ = writeln!(f, "{line}");
                                }
                            }
                        }
                    }
                }

                // Ack only up to the last block we durably wrote. If we had a
                // mid-chain failure, downstream restart will re-deliver the
                // failed block (and everything after).
                if let Some(durable) = highest_durable &&
                    let Err(err) = self.ctx.events.send(ExExEvent::FinishedHeight(durable))
                {
                    warn!(?err, "send FinishedHeight failed (ExEx manager gone?)");
                    break;
                }
                if had_failure {
                    warn!(
                        ?range,
                        "ChainCommitted notification had failed blocks; will re-deliver on restart"
                    );
                }
            }
        }

        info!("witness-emit ExEx exiting (notification stream closed)");
        Ok(())
    }

    fn write_stats(&self, stats: &BlockStats) {
        let line = match serde_json::to_string(stats) {
            Ok(s) => s,
            Err(err) => {
                warn!(?err, "stats serialize failed");
                return;
            }
        };
        if let Some(path) = &self.stats_path {
            use std::io::Write;
            match std::fs::OpenOptions::new().create(true).append(true).open(path) {
                Ok(mut f) => {
                    let _ = writeln!(f, "{line}");
                }
                Err(err) => warn!(?err, "stats open failed"),
            }
        }
    }
}

/// Emit one block's witness bundle. Returns per-stage timings on success.
fn emit_block<Node>(
    ctx: &ExExContext<Node>,
    out_dir: &Path,
    block: &reth_ethereum::primitives::RecoveredBlock<
        <<Node::Types as NodeTypes>::Primitives as NodePrimitives>::Block,
    >,
    started: Instant,
) -> eyre::Result<BlockStats>
where
    Node: FullNodeComponents<Types: NodeTypes<Primitives = EthPrimitives>>,
{
    let block_number = block.number();
    let block_hash = block.hash();
    let parent_hash = block.parent_hash();

    // 1) Snapshot parent state via the in-process consistent provider.
    let t_state = Instant::now();
    let state_provider = ctx
        .provider()
        .state_by_block_hash(parent_hash)
        .wrap_err_with(|| format!("state_by_block_hash({parent_hash})"))?;
    let state_open_ms = t_state.elapsed().as_millis();

    // 2) Re-execute. This populates the `State<DB>` cache with EVERY touched account/slot —
    //    including reads that returned the original value, which are what we need a witness for.
    let t_exec = Instant::now();
    let evm_config = ctx.evm_config().clone();
    let mut db = State::builder()
        .with_database(StateProviderDatabase::new(&state_provider))
        .with_bundle_update()
        .build();

    let mut witness_record = ExecutionWitnessRecord::default();
    let executor = evm_config.executor(&mut db);
    executor
        .execute_with_state_closure(block, |statedb: &State<_>| {
            witness_record.record_executed_state(statedb, ExecutionWitnessMode::Canonical);
        })
        .wrap_err("execute_with_state_closure")?;
    let execute_ms = t_exec.elapsed().as_millis();

    // 3) Build the witness (proofs + ancestor headers).
    //
    // Defense in depth: `ExecutionWitnessMode::Canonical` collects bytecode
    // from `statedb.cache.contracts.values()`, which is whatever revm
    // happened to load via `code_by_hash` during execution. That cache is
    // populated as a side effect of evaluation and varies depending on the
    // path that drove the block (live engine vs staged-sync replay vs
    // post-`stage unwind`). Predeployed system contracts called by the
    // block prologue (EIP-2935 BLOCKHASH, EIP-4788 BeaconRoots, EIP-7002
    // WithdrawalRequest, EIP-7251 ConsolidationRequest) sometimes execute
    // without ever triggering a `code_by_hash` miss — which means the
    // emitted witness omits their bytecode, and the stateless validator
    // fails with `missing code for hash 0x6e49...`.
    //
    // We inject the known system-contract bytecodes unconditionally. The
    // network's post-Prague invariant is that these accounts are
    // pre-deployed with these exact bytecodes; including them is correct
    // for every Prague-active block (the validator just needs them to
    // exist in `bundle.witness.codes`, not to be the most recent value).
    inject_system_contracts(&mut witness_record);

    let t_proof = Instant::now();
    let codes_count = witness_record.codes.len();
    let keys_count = witness_record.keys.len();
    let witness = witness_record
        .into_execution_witness(
            &state_provider,
            ctx.provider(),
            block_number,
            ExecutionWitnessMode::Canonical,
        )
        .wrap_err("into_execution_witness")?;
    let witness_build_ms = t_proof.elapsed().as_millis();
    let state_nodes = witness.state.len();

    // 4) Encode bundle.
    let parent_header = reth_storage_api::HeaderProvider::header(ctx.provider(), parent_hash)?
        .ok_or_else(|| eyre::eyre!("parent header {parent_hash} not found"))?;
    let parent_state_root = parent_header.state_root();

    let mut header_buf = Vec::new();
    block.header().encode(&mut header_buf);
    let mut body_buf = Vec::new();
    block.body().encode(&mut body_buf);

    let bundle = WitnessBundle {
        header: header_buf.into(),
        block_body: body_buf.into(),
        witness,
        parent_state_root,
        expected_state_root: block.state_root(),
        block_number,
    };

    let t_encode = Instant::now();
    let encoded = encode_bundle(&bundle, Encoding::BincodeZstd).wrap_err("encode bundle")?;
    let encode_ms = t_encode.elapsed().as_millis();
    let size_bytes = encoded.len() as u64;

    // 5) Write atomically: temp -> sync -> rename.
    let t_write = Instant::now();
    let final_path = witness_path(out_dir, block_number, block_hash);
    write_atomic(&final_path, &encoded)?;
    let write_ms = t_write.elapsed().as_millis();

    Ok(BlockStats {
        ts: chrono_rfc3339(),
        block_number,
        block_hash: format!("{block_hash:?}"),
        parent_hash: format!("{parent_hash:?}"),
        tx_count: block.body().transactions.len(),
        size_bytes,
        state_nodes,
        codes: codes_count,
        keys: keys_count,
        state_open_ms,
        execute_ms,
        witness_build_ms,
        encode_ms,
        write_ms,
        e2e_ms: started.elapsed().as_millis(),
    })
}

// We avoid pulling chrono into the producer binary just for a timestamp.
// `SystemTime` -> RFC3339 millis is good enough for stats lines.
fn chrono_rfc3339() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    let secs = now.as_secs() as i64;
    let millis = now.subsec_millis();
    // We're OK with a UTC-only naive formatter. The uploader uses chrono for
    // its own log lines.
    let (year, month, day, hour, min, sec) = unix_to_civil(secs);
    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{min:02}:{sec:02}.{millis:03}Z")
}

/// Howard Hinnant's `days_from_civil` inverse (public domain).
const fn unix_to_civil(secs: i64) -> (i32, u32, u32, u32, u32, u32) {
    let day = secs.div_euclid(86400);
    let tod = secs.rem_euclid(86400) as u32;
    let hour = tod / 3600;
    let min = (tod / 60) % 60;
    let sec = tod % 60;
    let z = day + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u32; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = doy - (153 * mp + 2) / 5 + 1; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 }; // [1, 12]
    let year = (y + if m <= 2 { 1 } else { 0 }) as i32;
    (year, m, d, hour, min, sec)
}

fn witness_path(dir: &Path, block_number: u64, block_hash: B256) -> PathBuf {
    dir.join(format!("{block_number}-{block_hash:x}.witness.zst"))
}

/// Inject the post-Prague system-contract bytecodes into the witness record.
///
/// `ExecutionWitnessRecord` collects bytecode by walking
/// `statedb.cache.contracts`, which is populated only as a side effect of
/// `code_by_hash` misses inside revm. The block prologue executes these
/// system contracts via `transact_system_call`, which can succeed against
/// preloaded account state without ever triggering a code miss — leaving
/// the emitted witness missing the contract bytecode and unvalidatable.
///
/// These are constants per the EIPs (the producer cannot get them wrong)
/// so we always inject them. Duplicate entries are deduped by
/// `into_execution_witness` later, so there's no over-counting harm.
fn inject_system_contracts(record: &mut ExecutionWitnessRecord) {
    for code in [
        eip2935::HISTORY_STORAGE_CODE.clone(),
        eip4788::BEACON_ROOTS_CODE.clone(),
        eip7002::WITHDRAWAL_REQUEST_PREDEPLOY_CODE.clone(),
        eip7251::CONSOLIDATION_REQUEST_PREDEPLOY_CODE.clone(),
    ] {
        // record.codes is a Vec<Bytes>. Skip if the producer already has it
        // — `into_execution_witness` dedupes too but skipping here keeps
        // the linear scan O(1) per dedup hit instead of O(n) per dedup
        // miss inside the witness builder.
        if record.codes.iter().any(|c| c == &code) {
            continue;
        }
        record.codes.push(code);
    }
}

fn describe_metrics() {
    use metrics::{describe_counter, describe_gauge, describe_histogram, Unit};
    describe_counter!(EMIT_TOTAL, "ExEx per-block emit attempts");
    describe_counter!(EMIT_REORG_TOTAL, "ChainReverted notifications observed");
    describe_counter!(EMIT_STALE_MARKED_TOTAL, "Witness files renamed to .stale due to a reorg");
    describe_histogram!(
        EMIT_E2E_SECONDS,
        Unit::Seconds,
        "ChainCommitted -> file-durable wall clock per block"
    );
    describe_histogram!(EMIT_EXECUTE_SECONDS, Unit::Seconds, "Re-execution time per block");
    describe_histogram!(EMIT_BUILD_SECONDS, Unit::Seconds, "Witness proof-build time per block");
    describe_histogram!(EMIT_ENCODE_SECONDS, Unit::Seconds, "bincode+zstd encode time per block");
    describe_histogram!(EMIT_SIZE_BYTES, Unit::Bytes, "Encoded witness size per block");
    describe_gauge!(EMIT_HIGHEST_BLOCK, "Highest block number durably written by the ExEx");
}

fn mark_stale(path: &Path) -> std::io::Result<()> {
    if !path.exists() {
        return Ok(());
    }
    let stale = path.with_extension("zst.stale");
    std::fs::rename(path, stale)
}

fn write_atomic(final_path: &Path, bytes: &[u8]) -> eyre::Result<()> {
    use std::io::Write;
    let tmp = final_path.with_extension("zst.tmp");
    {
        let mut f =
            std::fs::File::create(&tmp).wrap_err_with(|| format!("create {}", tmp.display()))?;
        f.write_all(bytes).wrap_err_with(|| format!("write {}", tmp.display()))?;
        f.sync_all().wrap_err_with(|| format!("fsync {}", tmp.display()))?;
    }
    std::fs::rename(&tmp, final_path)
        .wrap_err_with(|| format!("rename {} -> {}", tmp.display(), final_path.display()))?;
    // fsync the containing dir so the rename is durable across power loss.
    if let Some(dir) = final_path.parent() &&
        let Ok(d) = std::fs::File::open(dir)
    {
        let _ = d.sync_all();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn witness_path_format_matches_uploader_parser() {
        // The uploader parses filenames back as `<num>-<hex_no_prefix>.witness.zst`.
        let hash = B256::repeat_byte(0xab);
        let p = witness_path(Path::new("/tmp"), 25145987, hash);
        let name = p.file_name().unwrap().to_str().unwrap();
        assert!(name.starts_with("25145987-"));
        assert!(name.ends_with(".witness.zst"));
        // Hash should be lowercase hex with NO 0x prefix.
        let stem = name.trim_end_matches(".witness.zst");
        let (num_s, hash_s) = stem.split_once('-').unwrap();
        assert_eq!(num_s.parse::<u64>().unwrap(), 25145987);
        assert_eq!(hash_s.len(), 64);
        assert!(!hash_s.starts_with("0x"));
    }

    #[test]
    fn unix_to_civil_known_dates() {
        // 2024-01-01T00:00:00Z = 1704067200
        assert_eq!(unix_to_civil(1704067200), (2024, 1, 1, 0, 0, 0));
        // 2026-05-21T17:35:00Z = 1779384900
        assert_eq!(unix_to_civil(1779384900), (2026, 5, 21, 17, 35, 0));
        // 2026-02-29 doesn't exist (not a leap year). Check 2024-02-29 does.
        // 2024-02-29T00:00:00Z = 1709164800
        assert_eq!(unix_to_civil(1709164800), (2024, 2, 29, 0, 0, 0));
    }

    #[test]
    fn write_atomic_durable_no_tmp_left() {
        let dir = std::env::temp_dir().join(format!("witness-emit-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let final_path = dir.join("99-abc.witness.zst");
        write_atomic(&final_path, b"hello").unwrap();
        assert_eq!(std::fs::read(&final_path).unwrap(), b"hello");
        // .tmp must not be left behind.
        assert!(!final_path.with_extension("zst.tmp").exists());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn mark_stale_renames_when_present_and_noops_when_absent() {
        let dir = std::env::temp_dir().join(format!("witness-emit-stale-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("100-x.witness.zst");
        // No-op when absent.
        mark_stale(&p).unwrap();
        // Rename when present.
        std::fs::write(&p, b"x").unwrap();
        mark_stale(&p).unwrap();
        assert!(!p.exists());
        assert!(p.with_extension("zst.stale").exists());
        std::fs::remove_dir_all(&dir).ok();
    }
}

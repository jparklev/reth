//! Optional `eth_getLogs` short-circuit through a vortex-backed bucket.
//!
//! Phase 26.x ships bucket-mode header reads on `BlockchainProvider`.
//! For `eth_getLogs`, the natural extension is to let bucket-backed
//! providers serve the entire request from the signed log chunks +
//! per-chunk Bloom side-tables instead of walking the local
//! receipts table. This trait is the seam the EthFilter pipeline
//! uses to detect that capability without taking a hard bound on
//! `BucketHeaderClient` (which lives in `reth-provider`, a higher
//! crate).
//!
//! Implementations that don't have a bucket client return `Ok(None)`
//! (the default), and the EthFilter falls through to the normal
//! receipts-based path.
//!
//! Companion to item 4 of the FULL-VORTEX-RETH-READ-NODE roadmap.

use alloc::vec::Vec;
use alloy_rpc_types_eth::{Filter, Log};
use reth_storage_errors::provider::ProviderResult;

/// Lookup logs from a vortex-backed signed bucket for the inclusive
/// block range `from_block..=to_block` applying the alloy `filter`'s
/// address allowlist + topic constraints.
///
/// Returns:
/// - `Ok(Some(logs))` — the bucket fully served the range (sorted by
///   `(block_num, log_idx)`). Caller should NOT also walk receipts.
/// - `Ok(None)` — no bucket configured, or the range spans blocks
///   not covered by the bucket. Caller should fall through to the
///   regular log scan.
/// - `Err(_)` — bucket fetch / decode / signature verification
///   failed. Caller should bubble up.
///
/// Why `Option<Vec<Log>>` instead of `Vec<Log>` with a `covered()`
/// probe: the bucket coverage check is per-range, not per-provider,
/// so the natural shape is "ask, and if it served the request, use
/// it; else fall through." Same shape as `header_by_number` in
/// `BucketHeaderClient`.
#[auto_impl::auto_impl(&, Arc)]
pub trait BucketLogsLookup {
    /// Default impl returns `Ok(None)` — most providers don't have a
    /// bucket attached.
    fn bucket_logs_in_range(
        &self,
        _filter: &Filter,
        _from_block: u64,
        _to_block: u64,
    ) -> ProviderResult<Option<Vec<Log>>> {
        Ok(None)
    }
}

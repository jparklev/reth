//! Optional side-channel for capturing per-block [`ExecutionWitnessRecord`]s as a side effect of
//! canonical block execution.
//!
//! # Motivation
//!
//! The default flow for an ExEx that needs to produce stateless-execution witnesses is to
//! re-execute every canonically committed block in `ExExNotification::ChainCommitted` against the
//! parent state, attaching `ExecutionWitnessRecord` to capture every read. That re-execution costs
//! 150-650ms per block on mainnet — pure waste, because the canonical executor inside reth already
//! touched the exact same accounts/slots/codes a few hundred milliseconds earlier and threw the
//! read cache away.
//!
//! This module exposes a process-global registry that an ExEx can install at startup. When a
//! sender is installed, [`crate::tree::BasicEngineValidator::execute_block`] will, on the serial
//! execution path, build an [`ExecutionWitnessRecord`] from the live `revm` state cache between
//! `merge_transitions` and `take_bundle`, then ship it through the channel keyed by block hash.
//! The ExEx then joins on its incoming `ChainCommitted` notification and skips re-execution.
//!
//! # Properties
//!
//! - **Zero overhead when nothing is installed.** A single `OnceLock<...>` load; if `None`, the
//!   validator never allocates a record.
//! - **Best-effort.** If the channel is full or the receiver was dropped, the send fails silently.
//!   Consensus is never affected.
//! - **Not for the BAL fast path.** `execute_block_bal` builds the canonical `State` from a decoded
//!   BAL and short-lived worker `State`s; its `cache.accounts` does NOT contain every read-only
//!   tx-level access. Mainnet does not have BAL today (pre-Amsterdam), so this is fine in practice.
//!   A consumer that needs BAL coverage must keep a re-execution fallback.
//! - **Not for pipeline backfill.** Pipeline-stage execution uses a separate batch executor and is
//!   not hooked here. Use the V1 re-execution path for `ExExNotificationSource::Pipeline`.
//! - **Fork blocks included.** Fork blocks that ultimately lose to a competing chain will also emit
//!   records. The consumer should join by block hash and treat unmatched records as eligible for
//!   eviction (e.g., bounded LRU or TTL).
//!
//! # Usage
//!
//! ```ignore
//! use reth_engine_tree::tree::witness_sink::{install_sender, WitnessRecordEvent};
//! use tokio::sync::mpsc;
//!
//! let (tx, mut rx) = mpsc::unbounded_channel::<WitnessRecordEvent>();
//! install_sender(tx).expect("only call once");
//! // ... start the ExEx, which drains `rx` and matches each event to ChainCommitted blocks ...
//! ```

use alloy_primitives::B256;
use reth_revm::witness::ExecutionWitnessRecord;
use std::sync::OnceLock;
use tokio::sync::mpsc::UnboundedSender;

/// A witness record harvested from canonical execution.
///
/// Sent as a side effect of `BasicEngineValidator::execute_block` whenever a sender has been
/// installed via [`install_sender`].
#[derive(Debug)]
pub struct WitnessRecordEvent {
    /// Hash of the executed block.
    pub block_hash: B256,
    /// Number of the executed block (denormalized for cheap log/eviction decisions in consumers).
    pub block_number: u64,
    /// The captured access list + codes + hashed-post-state. Built via
    /// `ExecutionWitnessRecord::from_executed_state(&db, ExecutionWitnessMode::Canonical)`.
    pub record: ExecutionWitnessRecord,
}

/// Returns the installed sender, if any.
///
/// Cheap (single atomic load). Designed to be called from the hot canonical execution path.
pub fn sender() -> Option<&'static UnboundedSender<WitnessRecordEvent>> {
    REGISTRY.get()
}

/// Installs the global witness-record sender. Returns `Err(sender)` if one was already installed.
///
/// Must be called once during process startup, before the engine begins executing payloads.
pub fn install_sender(
    sender: UnboundedSender<WitnessRecordEvent>,
) -> Result<(), UnboundedSender<WitnessRecordEvent>> {
    REGISTRY.set(sender)
}

/// Returns true when a sender has been installed. Cheap; safe to call from the hot path.
pub fn is_installed() -> bool {
    REGISTRY.get().is_some()
}

static REGISTRY: OnceLock<UnboundedSender<WitnessRecordEvent>> = OnceLock::new();

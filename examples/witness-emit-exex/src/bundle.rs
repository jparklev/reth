//! `WitnessBundle` envelope and (de)serialization.
//!
//! **IMPORTANT**: this MUST stay byte-identical to
//! `examples/witness-exec-spike/src/bundle.rs` — both producers feed the same
//! validator and stream readers. Keep them in lock-step.

use alloy_primitives::{Bytes, B256};
use serde::{Deserialize, Serialize};

/// Envelope written by `reth-witness-emit-node` (ExEx producer) and consumed by
/// `witness-validator` / `witness-stream`. Layout is identical for both
/// encodings.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub(crate) struct WitnessBundle {
    /// RLP-encoded block header.
    pub(crate) header: Bytes,
    /// RLP-encoded block body.
    pub(crate) block_body: Bytes,
    /// The execution witness (state nodes, codes, keys, ancestor headers).
    pub(crate) witness: alloy_rpc_types_debug::ExecutionWitness,
    /// Parent state root (== `header.state_root` of the parent block).
    pub(crate) parent_state_root: B256,
    /// Expected post-state root (== this block's `header.state_root`).
    pub(crate) expected_state_root: B256,
    /// Block number.
    pub(crate) block_number: u64,
}

/// Encoding selected by output file extension.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) enum Encoding {
    /// Pretty-printed JSON.
    Json,
    /// `bincode` v1 + zstd level 3.
    BincodeZstd,
}

impl Encoding {
    /// Pick encoding from a file name / S3 key suffix.
    #[allow(dead_code)]
    pub(crate) fn from_path(path: &str) -> Self {
        if path.ends_with(".zst") || path.ends_with(".bin.zst") {
            Self::BincodeZstd
        } else {
            Self::Json
        }
    }
}

/// Serialize a bundle. Bincode + zstd(3) for `.zst`, pretty JSON otherwise.
#[allow(dead_code)] // used by ExEx producer + uploader (when peeking parent_hash)
pub(crate) fn encode_bundle(bundle: &WitnessBundle, encoding: Encoding) -> eyre::Result<Vec<u8>> {
    match encoding {
        Encoding::Json => Ok(serde_json::to_vec_pretty(bundle)?),
        Encoding::BincodeZstd => {
            let raw = bincode::serialize(bundle)?;
            let compressed = zstd::stream::encode_all(raw.as_slice(), 3)?;
            Ok(compressed)
        }
    }
}

//! Shared `WitnessBundle` envelope and (de)serialization helpers.
//!
//! Two on-disk encodings:
//!   - JSON  (`*.json`)     — v0, human-inspectable with `jq`.
//!   - bincode+zstd (`*.zst`) — v1, ~4x smaller, ~10x faster decode.
//!
//! The validator dispatches on file extension / object key suffix.

use alloy_primitives::{Bytes, B256};
use serde::{Deserialize, Serialize};

/// Envelope written by `witness-producer` and read by `witness-validator` /
/// `witness-stream`. Identical layout for JSON and bincode encodings.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub(crate) struct WitnessBundle {
    /// RLP-encoded block header.
    pub(crate) header: Bytes,
    /// RLP-encoded block body.
    pub(crate) block_body: Bytes,
    /// The execution witness (state nodes, codes, keys, ancestor headers).
    pub(crate) witness: alloy_rpc_types_debug::ExecutionWitness,
    /// Parent state root (== header.state_root of the parent block). Convenience.
    pub(crate) parent_state_root: B256,
    /// Expected post-state root (== this block's header.state_root). Convenience.
    pub(crate) expected_state_root: B256,
    /// Block number. Convenience.
    pub(crate) block_number: u64,
}

/// Encoding selected by output file extension.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum Encoding {
    /// Pretty-printed JSON.
    Json,
    /// `bincode` v1 + zstd level 3.
    BincodeZstd,
}

impl Encoding {
    /// Pick encoding from a file name / S3 key suffix.
    pub(crate) fn from_path(path: &str) -> Self {
        if path.ends_with(".zst") || path.ends_with(".bin.zst") {
            Self::BincodeZstd
        } else {
            Self::Json
        }
    }
}

/// Serialize a bundle to bytes. Uses bincode + zstd(level=3) for `.zst`,
/// pretty JSON otherwise.
#[allow(dead_code)] // used by producer binary only
pub(crate) fn encode_bundle(bundle: &WitnessBundle, encoding: Encoding) -> eyre::Result<Vec<u8>> {
    match encoding {
        Encoding::Json => Ok(serde_json::to_vec_pretty(bundle)?),
        Encoding::BincodeZstd => {
            // Default bincode config: little-endian, variable-int sizes. Fine for our shape.
            let raw = bincode::serialize(bundle)?;
            // Level 3 keeps decode <50ms on the witness sizes we see (~3–4 MiB compressed).
            let compressed = zstd::stream::encode_all(raw.as_slice(), 3)?;
            Ok(compressed)
        }
    }
}

/// Deserialize a bundle from bytes given the encoding.
#[allow(dead_code)] // used by validator/stream binaries only
pub(crate) fn decode_bundle(bytes: &[u8], encoding: Encoding) -> eyre::Result<WitnessBundle> {
    match encoding {
        Encoding::Json => Ok(serde_json::from_slice(bytes)?),
        Encoding::BincodeZstd => {
            let raw = zstd::stream::decode_all(bytes)?;
            Ok(bincode::deserialize(&raw)?)
        }
    }
}

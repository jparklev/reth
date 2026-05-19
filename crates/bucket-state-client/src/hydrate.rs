//! Hydrate-side helpers: materialize checkpoint shards + replay epoch
//! deltas into hash-keyed caches.
//!
//! Schema mirrors the writer side:
//! - **checkpoint** (Phase 26.2 / 26.3) chunks are written by `relay-state-checkpointer` and
//!   `relay-rpc state-artifacts write`. Account schema `hashed_address, nonce, balance, code_hash`;
//!   storage `hashed_address, hashed_slot, value`; code `code_hash, code`.
//! - **delta** (Phase 26.1) chunks are written by `relay-indexer`'s `state_epoch` emitter. Schemas
//!   as above but with a leading `block_num` column (sorted by `block_num` asc within the epoch).
//!
//! Tombstones (writer-side convention):
//! - Account `nonce=0, balance=0, code_hash=KECCAK_EMPTY` → "no account"
//! - Storage `value=0` → "slot cleared in this epoch" (we still *insert* the (addr, slot) → 0
//!   mapping so subsequent reads see 0 rather than fall through to MDBX).

use std::sync::Arc;

use alloy_consensus::constants::KECCAK_EMPTY;
use alloy_primitives::{keccak256, BlockNumber, Bytes, B256, U256};
use moka::sync::Cache;
use object_store::ObjectStore;
use reth_primitives_traits::Account;

use crate::EpochManifest;
use sha2::{Digest, Sha256};
use tracing::{debug, warn};

use crate::{fetch_object, vortex_state, BucketStateClientError};

/// Stats for the index.json + manifest.json fetch step.
#[derive(Debug, Clone, Default)]
pub struct ManifestFetchStats {
    pub bytes_fetched: u64,
    pub fetch_elapsed_ms: u64,
}

/// Stats from the checkpoint chunk load.
#[derive(Debug, Clone, Default)]
pub struct CheckpointHydrateStats {
    pub block_number: BlockNumber,
    pub shards: u32,
    pub accounts: u64,
    pub storage: u64,
    pub code: u64,
    pub bytes_fetched: u64,
    pub elapsed_ms: u64,
}

/// Stats from the epoch-delta replay.
#[derive(Debug, Clone, Default)]
pub struct DeltaHydrateStats {
    pub epochs_replayed: u32,
    pub epochs_skipped: u32,
    pub account_rows: u64,
    pub storage_rows: u64,
    pub code_rows: u64,
    pub bytes_fetched: u64,
    pub elapsed_ms: u64,
}

/// Overall hydrate timing + counts. Useful for log lines + the
/// `relay_bucket_state_*` metrics callers may add on top.
#[derive(Debug, Clone, Default)]
pub struct HydrateStats {
    pub index_and_manifest: ManifestFetchStats,
    pub checkpoint: CheckpointHydrateStats,
    pub deltas: DeltaHydrateStats,
    pub total_elapsed_ms: u64,
}

#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct MaterializedShardCounts {
    pub accounts: u64,
    pub storage: u64,
    pub code: u64,
}

/// Decode the three checkpoint chunks for one shard and merge them into
/// the hash-keyed caches.
pub(crate) async fn materialize_shard(
    accounts_bytes: Vec<u8>,
    storage_bytes: Vec<u8>,
    code_bytes: Vec<u8>,
    account_cache: &Cache<B256, Option<Account>>,
    storage_cache: &Cache<(B256, B256), Option<U256>>,
    code_cache: &Cache<B256, Option<Bytes>>,
) -> Result<MaterializedShardCounts, BucketStateClientError> {
    let mut counts = MaterializedShardCounts::default();

    let rows_a = vortex_state::decode_accounts_chunk(accounts_bytes).await?;
    for row in rows_a {
        let account =
            Account { nonce: row.nonce, balance: row.balance, bytecode_hash: Some(row.code_hash) };
        if account_cache.get(&row.hashed_address).is_none() {
            if is_account_tombstone(&account) {
                account_cache.insert(row.hashed_address, None);
            } else {
                account_cache.insert(row.hashed_address, Some(account));
            }
        }
        counts.accounts += 1;
    }

    let rows_s = vortex_state::decode_storage_chunk(storage_bytes).await?;
    for row in rows_s {
        let key = (row.hashed_address, row.hashed_slot);
        if storage_cache.get(&key).is_none() {
            storage_cache.insert(key, Some(row.value));
        }
        counts.storage += 1;
    }

    let rows_c = vortex_state::decode_code_chunk(code_bytes).await?;
    for row in rows_c {
        if code_cache.get(&row.code_hash).is_none() {
            code_cache.insert(row.code_hash, Some(row.code));
        }
        counts.code += 1;
    }

    Ok(counts)
}

/// Apply a single epoch's delta artifacts to the in-memory caches.
///
/// "Latest-wins" semantics: within the epoch, rows are sorted by
/// `block_num asc, address asc, slot asc` (the writer's invariant);
/// we iterate in that order and overwrite the map each time. The
/// final state of the map equals the post-state at the highest
/// `block_num <= head_block` in the epoch.
///
/// Returns the highest block_num actually applied (the caller uses
/// it to bump `pinned_block`).
pub(crate) async fn apply_epoch_deltas(
    store: Arc<dyn ObjectStore>,
    epoch: &EpochManifest,
    pinned_block: BlockNumber,
    head_block: BlockNumber,
    account_cache: &Cache<B256, Option<Account>>,
    storage_cache: &Cache<(B256, B256), Option<U256>>,
    code_cache: &Cache<B256, Option<Bytes>>,
    stats: &mut DeltaHydrateStats,
) -> Result<BlockNumber, BucketStateClientError> {
    // Phase 26.1 advertises the three artifact families as entries in
    // `epoch_artifacts` (parsed inside the EpochManifest from the
    // chain walk). Sig verification already happened in walk_epoch_chain.
    let epoch_artifacts = parse_epoch_artifacts_value(&epoch.epoch_artifacts);
    let mut applied = pinned_block;
    if let Some(a) = epoch_artifacts.state_account_deltas {
        let key = chunks_key(&a.path);
        let bytes = fetch_object(&store, &key).await?;
        verify_chunk_sha(&bytes, &a.content_sha256, &key)?;
        stats.bytes_fetched += bytes.len() as u64;
        let rows = vortex_state::decode_account_deltas_chunk(bytes).await?;
        for row in rows {
            if row.block_num <= pinned_block {
                continue; // already covered by the checkpoint
            }
            if row.block_num > head_block {
                break; // sorted asc by block_num
            }
            let hashed_address = keccak256(row.address);
            if row.nonce == 0 && row.balance.is_zero() && row.code_hash == KECCAK_EMPTY {
                account_cache.insert(hashed_address, None);
            } else {
                account_cache.insert(
                    hashed_address,
                    Some(Account {
                        nonce: row.nonce,
                        balance: row.balance,
                        bytecode_hash: Some(row.code_hash),
                    }),
                );
            }
            stats.account_rows += 1;
            if row.block_num > applied {
                applied = row.block_num;
            }
        }
    }
    if let Some(s) = epoch_artifacts.state_storage_deltas {
        let key = chunks_key(&s.path);
        let bytes = fetch_object(&store, &key).await?;
        verify_chunk_sha(&bytes, &s.content_sha256, &key)?;
        stats.bytes_fetched += bytes.len() as u64;
        let rows = vortex_state::decode_storage_deltas_chunk(bytes).await?;
        for row in rows {
            if row.block_num <= pinned_block {
                continue;
            }
            if row.block_num > head_block {
                break;
            }
            // `value=0` here means "the slot was cleared in this epoch"
            // — we still insert so callers see Some(0) rather than fall
            // through (avoids returning the MDBX/static-file's older
            // pre-clear value).
            storage_cache.insert((keccak256(row.address), keccak256(row.slot.to_be_bytes::<32>())), Some(row.value));
            stats.storage_rows += 1;
            if row.block_num > applied {
                applied = row.block_num;
            }
        }
    }
    if let Some(c) = epoch_artifacts.state_code_deltas {
        let key = chunks_key(&c.path);
        let bytes = fetch_object(&store, &key).await?;
        verify_chunk_sha(&bytes, &c.content_sha256, &key)?;
        stats.bytes_fetched += bytes.len() as u64;
        let rows = vortex_state::decode_code_deltas_chunk(bytes).await?;
        for row in rows {
            if row.block_num <= pinned_block {
                continue;
            }
            if row.block_num > head_block {
                break;
            }
            if code_cache.get(&row.code_hash).is_none() {
                code_cache.insert(row.code_hash, Some(row.code));
            }
            stats.code_rows += 1;
            if row.block_num > applied {
                applied = row.block_num;
            }
        }
    }
    stats.epochs_replayed += 1;
    debug!(
        target: "bucket-state-client",
        epoch = epoch.epoch,
        first_block = epoch.first_block_num,
        last_block = epoch.last_block_num,
        applied,
        "applied epoch deltas"
    );
    Ok(applied)
}

/// Subset of the per-epoch `epoch_artifacts` map we care about.
#[derive(Debug, Clone, Default)]
pub(crate) struct EpochStateArtifacts {
    pub state_account_deltas: Option<ManifestChunkDescriptorLite>,
    pub state_storage_deltas: Option<ManifestChunkDescriptorLite>,
    pub state_code_deltas: Option<ManifestChunkDescriptorLite>,
}

#[derive(Debug, Clone, serde::Deserialize)]
pub(crate) struct ManifestChunkDescriptorLite {
    pub path: String,
    #[serde(default)]
    pub content_sha256: String,
    /// Advisory size hint from the manifest; not currently consumed.
    /// Kept on the struct so future code that wants to preallocate
    /// can read it without a schema change.
    #[allow(dead_code)]
    #[serde(default)]
    pub size_bytes: Option<u64>,
}

/// Parse an `EpochManifest::epoch_artifacts` JSON value into the
/// three state delta refs we care about.
pub(crate) fn parse_epoch_artifacts_value(value: &serde_json::Value) -> EpochStateArtifacts {
    let Some(map) = value.as_object() else {
        return EpochStateArtifacts::default();
    };
    let pick = |name: &str| -> Option<ManifestChunkDescriptorLite> {
        let entry = map.get(name)?;
        let desc: ManifestChunkDescriptorLite = serde_json::from_value(entry.clone()).ok()?;
        if !desc.path.is_empty() {
            Some(desc)
        } else {
            None
        }
    };
    EpochStateArtifacts {
        state_account_deltas: pick("state_account_deltas"),
        state_storage_deltas: pick("state_storage_deltas"),
        state_code_deltas: pick("state_code_deltas"),
    }
}

/// Normalize a chunk path. Manifest entries sometimes carry the path
/// as `chunks/<sha[0:2]>/<sha>` (the writer's canonical form);
/// sometimes as a bare path relative to bucket root. Either way we
/// want the key as stored in the bucket.
fn chunks_key(path: &str) -> String {
    let trimmed = path.trim_start_matches('/');
    if trimmed.starts_with("chunks/") {
        trimmed.to_string()
    } else {
        format!("chunks/{trimmed}")
    }
}

pub(crate) fn verify_chunk_sha(
    bytes: &[u8],
    expected: &str,
    label: &str,
) -> Result<(), BucketStateClientError> {
    if expected.is_empty() {
        return Ok(()); // Some manifest variants omit this; trust the signed manifest.
    }
    let actual = format!("{:x}", Sha256::digest(bytes));
    if actual != expected {
        return Err(BucketStateClientError::Trust(format!(
            "chunk {label} sha mismatch: expected {expected}, got {actual}"
        )));
    }
    Ok(())
}

pub(crate) fn is_account_tombstone(account: &Account) -> bool {
    account.nonce == 0 && account.balance.is_zero() && account.bytecode_hash == Some(KECCAK_EMPTY)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_epoch_artifacts_extracts_state_refs() {
        let v: serde_json::Value = serde_json::from_str(
            r#"{
            "logs": {"path": "chunks/aa/aa..."},
            "state_account_deltas": {
              "path": "chunks/01/0123",
              "content_sha256": "0123",
              "size_bytes": 100
            },
            "state_storage_deltas": {
              "path": "chunks/02/0234",
              "content_sha256": "0234"
            },
            "state_code_deltas": {
              "path": "chunks/03/0345",
              "content_sha256": "0345"
            }
          }"#,
        )
        .unwrap();
        let out = parse_epoch_artifacts_value(&v);
        assert_eq!(out.state_account_deltas.as_ref().unwrap().path, "chunks/01/0123");
        assert_eq!(out.state_storage_deltas.as_ref().unwrap().path, "chunks/02/0234");
        assert_eq!(out.state_code_deltas.as_ref().unwrap().path, "chunks/03/0345");
    }

    #[test]
    fn parse_epoch_artifacts_handles_missing_state() {
        let v: serde_json::Value = serde_json::from_str(r#"{"logs": {"path": "x"}}"#).unwrap();
        let out = parse_epoch_artifacts_value(&v);
        assert!(out.state_account_deltas.is_none());
        assert!(out.state_storage_deltas.is_none());
        assert!(out.state_code_deltas.is_none());
    }

    #[test]
    fn parse_epoch_artifacts_handles_empty_map() {
        let v: serde_json::Value = serde_json::from_str("{}").unwrap();
        let out = parse_epoch_artifacts_value(&v);
        assert!(out.state_account_deltas.is_none());
    }

    #[test]
    fn chunks_key_normalizes_paths() {
        assert_eq!(chunks_key("chunks/ab/abcd"), "chunks/ab/abcd");
        assert_eq!(chunks_key("ab/abcd"), "chunks/ab/abcd");
        assert_eq!(chunks_key("/chunks/ab/abcd"), "chunks/ab/abcd");
    }

    #[test]
    fn verify_chunk_sha_accepts_empty_expected() {
        verify_chunk_sha(b"hi", "", "x").unwrap();
    }

    #[test]
    fn verify_chunk_sha_catches_mismatch() {
        let actual = format!("{:x}", Sha256::digest(b"hello"));
        assert!(verify_chunk_sha(b"hello", &actual, "x").is_ok());
        assert!(verify_chunk_sha(b"hello", "deadbeef", "x").is_err());
    }
}

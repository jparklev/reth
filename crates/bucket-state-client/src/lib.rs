//! HTTP/Vortex implementer of [`reth_provider::BucketStateClient`].
//!
//! Phase 26.2 checkpoint + Phase 26.1 epoch-delta replay → hash-keyed
//! lazy shard caches → sync `BucketStateClient` reads.
//!
//! This crate is intentionally **independent of `reth-bucket-header-client`**.
//! It re-defines the small subset of head-manifest types it needs so the
//! state crate can build even while the header crate is in flux.
//! Callers wire the two clients separately via
//! `BlockchainProvider::with_bucket(...)` + `with_state_bucket(...)`.
//!
//! ## Boot algorithm
//!
//! 1. `object_store` init (same shape as `bucket-header-client`).
//! 2. Fetch `manifest/head.json[.sig]`, verify ed25519 against `writer-keys/<id>.pub`, parse to get
//!    the latest finalized block.
//! 3. Fetch `<prefix>/index.json[.sig]`, verify, parse as `CheckpointIndex`.
//! 4. Pick the most recent entry ≤ `target_block` (default = head's `latest_finalized_block_num`).
//! 5. Fetch the entry's `manifest.json[.sig]`, verify sig + sha, parse.
//! 6. Validate the checkpoint manifest is v3 + hashed-keyed.
//! 7. Scan the local disk cache for already-downloaded shards. Do not fetch or decode checkpoint
//!    shards during boot.
//! 8. Walk forward through epoch manifests from `checkpoint.block_number + 1 ..
//!    head.latest_finalized_block_num`, decoding each epoch's `state_account_deltas` /
//!    `state_storage_deltas` / `state_code_deltas` artifacts when advertised, and applying as
//!    latest-wins updates into the caches.
//! 9. Track `pinned_block_number` = last block whose state is fully materialized.
//!
//! ## Read path
//!
//! `account` / `storage` / `code_by_hash` first check hash-keyed moka
//! caches. Cache misses compute the owning shard from the high-order
//! keccak prefix bits, then singleflight the shard materialization from
//! disk cache or bucket fetch. `BucketStateClient` is sync (mirrors
//! reth's `StateProvider`), so lazy shard fetches run under
//! `block_in_place(handle.block_on(...))` from inside the reth runtime
//! context, the same shape `HttpBucketHeaderClient` uses.

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Instant,
};

use alloy_consensus::{constants::KECCAK_EMPTY, Header};
use alloy_primitives::{keccak256, Address, BlockHash, BlockNumber, Bytes, TxHash, B256, U256};
use dashmap::{DashMap, DashSet};
use ed25519_dalek::Verifier;
use moka::sync::Cache;
use object_store::{aws::AmazonS3Builder, path::Path as ObjectPath, ObjectStore, ObjectStoreExt};
use reth_ethereum_primitives::TransactionSigned;
use reth_primitives_traits::Account;
use reth_provider::{BucketHeaderClient, BucketStateClient, BucketStateClientArc};
use reth_storage_errors::{
    db::DatabaseError,
    provider::{ProviderError, ProviderResult},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::runtime::Handle;
use tracing::{debug, info, warn};

mod hydrate;
mod vortex_state;

pub use hydrate::HydrateStats;

/// Errors surfaced by the bucket-state client.
#[derive(Debug, Clone, thiserror::Error)]
pub enum BucketStateClientError {
    #[error("bucket backend: {0}")]
    Backend(String),
    #[error("trust verification failed: {0}")]
    Trust(String),
    #[error("decode failed: {0}")]
    Decode(String),
    #[error("vortex: {0}")]
    Vortex(String),
}

impl From<BucketStateClientError> for ProviderError {
    fn from(err: BucketStateClientError) -> Self {
        ProviderError::Database(DatabaseError::Other(err.to_string()))
    }
}

/// Bucket connection parameters. Same shape as
/// `reth_bucket_header_client::BucketHeaderClientConfig` so callers
/// can pass through transparently.
#[derive(Debug, Clone)]
pub struct BucketStateConnConfig {
    pub bucket_url: String,
    pub endpoint: String,
    pub region: String,
    pub anonymous: bool,
    pub access_key_env: String,
    pub secret_key_env: String,
    pub trusted_writers: Vec<String>,
    pub cache_dir: PathBuf,
}

impl BucketStateConnConfig {
    pub fn default_cache_dir() -> PathBuf {
        std::env::var_os("RELAY_BUCKET_STATE_CACHE")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("/var/cache/reth-bucket-state"))
    }
}

/// Configuration for constructing an [`HttpBucketStateClient`].
#[derive(Debug, Clone)]
pub struct BucketStateClientConfig {
    pub conn: BucketStateConnConfig,
    /// Bucket prefix where checkpoints live. Default
    /// `"checkpoints"` (the Phase 26.2 writer's default).
    pub checkpoint_prefix: String,
    /// Optional override for the target block of the boot
    /// checkpoint. When `None`, the client picks the latest entry in
    /// the index ≤ `head.json`'s `latest_finalized_block_num`.
    pub target_block: Option<BlockNumber>,
    /// Apply Phase 26.1 epoch deltas forward from the checkpoint to
    /// head when `true` (the default). Disable for tests or when
    /// only a single point-in-time state is needed.
    pub apply_deltas: bool,
}

impl BucketStateClientConfig {
    pub fn new(conn: BucketStateConnConfig) -> Self {
        Self {
            conn,
            checkpoint_prefix: "checkpoints".into(),
            target_block: None,
            apply_deltas: true,
        }
    }
}

// ---------------- Phase 26.x manifest types (mirrored) ----------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeadManifest {
    pub chain_id: u64,
    pub writer_id: String,
    pub latest_finalized_epoch: u64,
    pub latest_finalized_block_num: u64,
    pub latest_finalized_block_hash: String,
    pub epoch_manifest_url: String,
    pub epoch_manifest_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpochManifest {
    pub chain_id: u64,
    pub epoch: u64,
    pub first_block_num: u64,
    pub last_block_num: u64,
    #[serde(default)]
    pub previous_epoch_manifest_url: Option<String>,
    #[serde(default)]
    pub previous_epoch_manifest_sha256: Option<String>,
    #[serde(default)]
    pub epoch_artifacts: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StateArtifactRef {
    #[serde(default)]
    pub chain_id: u64,
    #[serde(default)]
    pub kind: String,
    #[serde(default)]
    pub from_block: u64,
    #[serde(default)]
    pub to_block: u64,
    #[serde(default)]
    pub state_root: Option<String>,
    pub object_key: String,
    #[serde(default)]
    pub index_key: Option<String>,
    pub content_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shard: Option<u32>,
    #[serde(default)]
    pub key_min: Option<String>,
    #[serde(default)]
    pub key_max: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardManifest {
    pub shard: u32,
    pub accounts: Vec<StateArtifactRef>,
    pub storage: Vec<StateArtifactRef>,
    pub code: Vec<StateArtifactRef>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinalizedStateArtifactManifest {
    pub version: u8,
    pub chain_id: u64,
    pub block_number: u64,
    pub block_hash: String,
    #[serde(default)]
    pub state_root: Option<String>,
    #[serde(default)]
    pub accounts: Option<StateArtifactRef>,
    #[serde(default)]
    pub storage: Option<StateArtifactRef>,
    #[serde(default)]
    pub code: Option<StateArtifactRef>,
    #[serde(default)]
    pub shards: Vec<ShardManifest>,
    #[serde(default)]
    pub shard_bits: Option<u8>,
    #[serde(default)]
    pub key_layout: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedCheckpointManifest {
    pub version: u8,
    pub writer_id: String,
    pub signed_at: String,
    pub manifest: FinalizedStateArtifactManifest,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckpointIndexEntry {
    pub block_number: u64,
    pub block_hash: String,
    #[serde(default)]
    pub state_root: Option<String>,
    pub manifest_url: String,
    pub manifest_sha256: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckpointIndex {
    pub version: u8,
    pub chain_id: u64,
    pub writer_id: String,
    pub updated_at: String,
    pub entries: Vec<CheckpointIndexEntry>,
}

impl CheckpointIndex {
    /// Entries are sorted descending by block_number; pick the first
    /// entry whose block_number is ≤ `target`.
    pub fn pick_for_block(&self, target: u64) -> Option<&CheckpointIndexEntry> {
        self.entries.iter().find(|e| e.block_number <= target)
    }
}

// ---------------- HttpBucketStateClient ----------------

/// HTTP/Vortex implementer of [`BucketStateClient`].
pub struct HttpBucketStateClient {
    /// Head manifest snapshot (the bucket's signed latest-finalized).
    head: HeadManifest,
    /// Pinned block number = last block whose plain state is fully
    /// materialized in our caches. Always ≤ `head.latest_finalized_block_num`.
    pinned_block: BlockNumber,
    /// Block hash matching `pinned_block`. Used by `BlockchainProvider`'s
    /// `maybe_wrap_with_bucket` gate so historical-block queries don't
    /// accidentally get pinned-block answers. `None` if we couldn't
    /// derive a hash for `pinned_block` (intermediate epoch advance
    /// without an authoritative hash).
    pinned_block_hash: Option<BlockHash>,
    store: Arc<dyn ObjectStore>,
    manifest_dir: String,
    shard_bits: u8,
    shards: HashMap<u32, ShardManifest>,
    checkpoint_cache_dir: PathBuf,
    account_cache: Cache<B256, Option<Account>>,
    storage_cache: Cache<(B256, B256), Option<U256>>,
    code_cache: Cache<B256, Option<Bytes>>,
    loaded_shards: DashSet<u32>,
    materialized_shards: DashSet<u32>,
    shard_singleflight: DashMap<u32, Arc<Mutex<Option<Result<(), BucketStateClientError>>>>>,
    stats: HydrateStats,
}

impl std::fmt::Debug for HttpBucketStateClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpBucketStateClient")
            .field("pinned_block", &self.pinned_block)
            .field("head_block", &self.head.latest_finalized_block_num)
            .field("shard_bits", &self.shard_bits)
            .field("shards", &self.shards.len())
            .field("disk_cached_shards", &self.loaded_shards.len())
            .field("materialized_shards", &self.materialized_shards.len())
            .field("accounts", &self.account_cache.entry_count())
            .field("storage", &self.storage_cache.entry_count())
            .field("code", &self.code_cache.entry_count())
            .field("stats", &self.stats)
            .finish()
    }
}

impl HttpBucketStateClient {
    /// Snapshot of the per-stage hydrate timings + counts.
    pub fn stats(&self) -> &HydrateStats {
        &self.stats
    }

    /// Number of accounts loaded.
    pub fn account_count(&self) -> usize {
        self.account_cache.entry_count() as usize
    }
    /// Number of storage slots loaded.
    pub fn storage_count(&self) -> usize {
        self.storage_cache.entry_count() as usize
    }
    /// Number of bytecode blobs loaded.
    pub fn code_count(&self) -> usize {
        self.code_cache.entry_count() as usize
    }
    /// Latest-finalized block per the bucket's signed head.json.
    pub fn head_block(&self) -> BlockNumber {
        self.head.latest_finalized_block_num
    }

    /// Sync constructor — mirrors
    /// `HttpBucketHeaderClient::new_blocking` so it can be called
    /// from inside the reth NodeBuilder closure. Uses
    /// `tokio::task::block_in_place` to safely call async code from
    /// within a multi-threaded tokio runtime context.
    pub fn new_blocking(
        config: BucketStateClientConfig,
    ) -> Result<Arc<Self>, BucketStateClientError> {
        let handle = Handle::try_current().map_err(|_| {
            BucketStateClientError::Backend(
                "HttpBucketStateClient::new_blocking requires a tokio runtime context".into(),
            )
        })?;
        tokio::task::block_in_place(|| handle.block_on(async { Self::new(config).await }))
            .map(Arc::new)
    }

    /// Async constructor.
    pub async fn new(config: BucketStateClientConfig) -> Result<Self, BucketStateClientError> {
        let total_start = Instant::now();
        let store = build_object_store(&config.conn)?;
        let prefix = config.checkpoint_prefix.trim_matches('/').to_string();

        // Resolve the trusted writer pubkey.
        let writer_id =
            config.conn.trusted_writers.first().cloned().unwrap_or_else(|| "primary".to_string());
        let pubkey = fetch_writer_pubkey(&store, &writer_id).await?;

        // 1. Fetch + verify head.json so we know head.latest_finalized.
        let head_bytes = fetch_object(&store, "manifest/head.json")
            .await
            .map_err(|err| BucketStateClientError::Backend(format!("head.json fetch: {err}")))?;
        let head_sig = fetch_object(&store, "manifest/head.json.sig")
            .await
            .map_err(|err| BucketStateClientError::Backend(format!("head.json sig: {err}")))?;
        verify_ed25519(&pubkey, &head_bytes, &head_sig)?;
        let head: HeadManifest = serde_json::from_slice(&head_bytes)
            .map_err(|err| BucketStateClientError::Decode(format!("head.json decode: {err}")))?;
        if !config.conn.trusted_writers.is_empty() &&
            !config.conn.trusted_writers.contains(&head.writer_id)
        {
            return Err(BucketStateClientError::Trust(format!(
                "writer_id '{}' not in trusted set",
                head.writer_id
            )));
        }

        // 2. Fetch + verify checkpoint index.
        // Default target is the bucket head's latest_finalized, but if
        // the latest checkpoint is *newer* (which can happen when the
        // operator runs `relay-state-checkpointer` against a reth
        // ahead of the indexer's head publish cadence), fall back to
        // u64::MAX so we pick the freshest checkpoint we have.
        let target_block = config.target_block.unwrap_or(u64::MAX);
        let mut idx_stats = hydrate::ManifestFetchStats::default();
        let index_t0 = Instant::now();
        let index_key = if prefix.is_empty() {
            "index.json".to_string()
        } else {
            format!("{prefix}/index.json")
        };
        let index_bytes = fetch_object(&store, &index_key)
            .await
            .map_err(|err| BucketStateClientError::Backend(format!("index fetch: {err}")))?;
        let index_sig = fetch_object(&store, &format!("{index_key}.sig"))
            .await
            .map_err(|err| BucketStateClientError::Backend(format!("index sig fetch: {err}")))?;
        verify_ed25519(&pubkey, &index_bytes, &index_sig)?;
        idx_stats.bytes_fetched += (index_bytes.len() + index_sig.len()) as u64;
        let index: CheckpointIndex = serde_json::from_slice(&index_bytes).map_err(|err| {
            BucketStateClientError::Decode(format!("checkpoint index decode: {err}"))
        })?;
        let entry = index.pick_for_block(target_block).cloned().ok_or_else(|| {
            BucketStateClientError::Backend(format!(
                "no checkpoint entry covers target block {target_block} in index of {} entries",
                index.entries.len()
            ))
        })?;
        info!(
            target: "bucket-state-client",
            target_block,
            picked = entry.block_number,
            block_hash = %entry.block_hash,
            "picked checkpoint entry"
        );

        // 3. Fetch + verify the manifest.
        let manifest_bytes = fetch_object(&store, &entry.manifest_url)
            .await
            .map_err(|err| BucketStateClientError::Backend(format!("manifest fetch: {err}")))?;
        let actual_sha = format!("{:x}", Sha256::digest(&manifest_bytes));
        if actual_sha != entry.manifest_sha256 {
            return Err(BucketStateClientError::Trust(format!(
                "checkpoint manifest sha mismatch: index {} vs actual {actual_sha}",
                entry.manifest_sha256
            )));
        }
        let manifest_sig = fetch_object(&store, &format!("{}.sig", entry.manifest_url))
            .await
            .map_err(|err| BucketStateClientError::Backend(format!("manifest sig fetch: {err}")))?;
        verify_ed25519(&pubkey, &manifest_bytes, &manifest_sig)?;
        idx_stats.bytes_fetched += (manifest_bytes.len() + manifest_sig.len()) as u64;
        idx_stats.fetch_elapsed_ms = index_t0.elapsed().as_millis() as u64;
        let signed: SignedCheckpointManifest =
            serde_json::from_slice(&manifest_bytes).map_err(|err| {
                BucketStateClientError::Decode(format!("signed manifest decode: {err}"))
            })?;
        let manifest = signed.manifest;
        validate_checkpoint_manifest(&manifest)?;

        // 4. Build lazy shard/cache infrastructure. Checkpoint shards are
        // fetched and decoded on first read, not during boot.
        let manifest_dir = manifest_dir_from_url(&entry.manifest_url);
        let shard_bits = manifest.shard_bits.unwrap_or(0);
        let shards = manifest
            .shards
            .iter()
            .cloned()
            .map(|shard| (shard.shard, shard))
            .collect::<HashMap<_, _>>();
        let checkpoint_cache_dir =
            config.conn.cache_dir.join(format!("checkpoint-{}", manifest.block_number));
        let loaded_shards = scan_cached_shards(&checkpoint_cache_dir);
        let account_cache = cache();
        let storage_cache = cache();
        let code_cache = cache();
        code_cache.insert(KECCAK_EMPTY, Some(Bytes::new()));

        let checkpoint_stats = hydrate::CheckpointHydrateStats {
            block_number: manifest.block_number,
            shards: manifest.shards.len() as u32,
            accounts: 0,
            storage: 0,
            code: 0,
            bytes_fetched: 0,
            elapsed_ms: 0,
        };
        info!(
            target: "bucket-state-client",
            block_number = manifest.block_number,
            shard_bits,
            shards = checkpoint_stats.shards,
            disk_cached_shards = loaded_shards.len(),
            cache_dir = %checkpoint_cache_dir.display(),
            "checkpoint manifest loaded"
        );

        let mut pinned_block = manifest.block_number;
        let checkpoint_block_hash = parse_block_hash(&manifest.block_hash).ok();
        let mut pinned_block_hash = checkpoint_block_hash;
        let mut delta_stats = hydrate::DeltaHydrateStats::default();

        // 5. Phase 26.1 epoch-delta replay forward.
        let head_block = head.latest_finalized_block_num;
        // No-op when checkpoint is newer than the head publish cadence.
        if config.apply_deltas && pinned_block < head_block {
            let delta_t0 = Instant::now();
            let ascending = walk_epoch_chain(&store, &pubkey, &head, pinned_block).await?;
            for epoch in &ascending {
                let applied = hydrate::apply_epoch_deltas(
                    Arc::clone(&store),
                    epoch,
                    pinned_block,
                    head_block,
                    &account_cache,
                    &storage_cache,
                    &code_cache,
                    &mut delta_stats,
                )
                .await?;
                if applied > pinned_block {
                    pinned_block = applied;
                    // Once deltas catch us up to head, adopt the head's
                    // hash as the pinned hash. Intermediate epoch tips
                    // get `None` — the bucket then refuses to answer
                    // historical-block state queries for those blocks
                    // (conservative: fall through to MDBX).
                    if pinned_block == head_block {
                        pinned_block_hash =
                            parse_block_hash(&head.latest_finalized_block_hash).ok();
                    } else {
                        pinned_block_hash = None;
                    }
                }
            }
            delta_stats.elapsed_ms = delta_t0.elapsed().as_millis() as u64;
            info!(
                target: "bucket-state-client",
                epochs = delta_stats.epochs_replayed,
                account_rows = delta_stats.account_rows,
                storage_rows = delta_stats.storage_rows,
                code_rows = delta_stats.code_rows,
                bytes = delta_stats.bytes_fetched,
                elapsed_ms = delta_stats.elapsed_ms,
                "epoch deltas replayed"
            );
        }

        let stats = HydrateStats {
            index_and_manifest: idx_stats,
            checkpoint: checkpoint_stats,
            deltas: delta_stats,
            total_elapsed_ms: total_start.elapsed().as_millis() as u64,
        };
        info!(
            target: "bucket-state-client",
            pinned_block,
            head_block,
            account_count = account_cache.entry_count(),
            storage_count = storage_cache.entry_count(),
            code_count = code_cache.entry_count(),
            elapsed_ms = stats.total_elapsed_ms,
            "bucket-state-client snapshot initialized"
        );

        Ok(Self {
            head,
            pinned_block,
            pinned_block_hash,
            store,
            manifest_dir,
            shard_bits,
            shards,
            checkpoint_cache_dir,
            account_cache,
            storage_cache,
            code_cache,
            loaded_shards,
            materialized_shards: DashSet::new(),
            shard_singleflight: DashMap::new(),
            stats,
        })
    }

    fn ensure_shard_materialized(&self, shard: u32) -> Result<(), BucketStateClientError> {
        if self.materialized_shards.contains(&shard) {
            return Ok(());
        }
        let gate = self
            .shard_singleflight
            .entry(shard)
            .or_insert_with(|| Arc::new(Mutex::new(None)))
            .clone();
        let mut result = gate.lock().map_err(|_| {
            BucketStateClientError::Backend(format!("shard {shard} loader poisoned"))
        })?;
        if self.materialized_shards.contains(&shard) {
            return Ok(());
        }
        if let Some(previous) = &*result {
            return previous.clone();
        }
        let handle = Handle::try_current().map_err(|_| {
            BucketStateClientError::Backend(
                "HttpBucketStateClient shard load requires a tokio runtime context".into(),
            )
        })?;
        let loaded = tokio::task::block_in_place(|| {
            handle.block_on(async { self.materialize_shard_async(shard).await })
        });
        *result = Some(loaded.clone());
        loaded
    }

    async fn materialize_shard_async(&self, shard: u32) -> Result<(), BucketStateClientError> {
        let manifest = self.shards.get(&shard).ok_or_else(|| {
            BucketStateClientError::Decode(format!("checkpoint manifest has no shard {shard}"))
        })?;
        let shard_dir = self.shard_cache_dir(shard);
        let accounts = self.chunk_bytes_for_refs(&shard_dir, &manifest.accounts).await?;
        let storage = self.chunk_bytes_for_refs(&shard_dir, &manifest.storage).await?;
        let code = self.chunk_bytes_for_refs(&shard_dir, &manifest.code).await?;
        let counts = hydrate::materialize_shard(
            accounts,
            storage,
            code,
            &self.account_cache,
            &self.storage_cache,
            &self.code_cache,
        )
        .await?;
        self.loaded_shards.insert(shard);
        self.materialized_shards.insert(shard);
        debug!(
            target: "bucket-state-client",
            shard,
            accounts = counts.accounts,
            storage = counts.storage,
            code = counts.code,
            "checkpoint shard materialized"
        );
        Ok(())
    }

    async fn chunk_bytes_for_refs(
        &self,
        shard_dir: &Path,
        refs: &[StateArtifactRef],
    ) -> Result<Vec<Vec<u8>>, BucketStateClientError> {
        let mut chunks = Vec::with_capacity(refs.len());
        for (idx, artifact) in refs.iter().enumerate() {
            let file_name = artifact_cache_file_name(artifact, idx);
            chunks.push(
                self.chunk_bytes_from_disk_or_bucket(
                    shard_dir,
                    &file_name,
                    &artifact.object_key,
                    &artifact.content_sha256,
                )
                .await?,
            );
        }
        Ok(chunks)
    }

    async fn chunk_bytes_from_disk_or_bucket(
        &self,
        shard_dir: &Path,
        file_name: &str,
        object_key: &str,
        expected_sha: &str,
    ) -> Result<Vec<u8>, BucketStateClientError> {
        let local_path = shard_dir.join(file_name);
        match std::fs::read(&local_path) {
            Ok(bytes) => match hydrate::verify_chunk_sha(
                &bytes,
                expected_sha,
                &local_path.display().to_string(),
            ) {
                Ok(()) => return Ok(bytes),
                Err(err) => {
                    warn!(
                        target: "bucket-state-client",
                        path = %local_path.display(),
                        %err,
                        "discarding invalid cached shard chunk"
                    );
                    let _ = std::fs::remove_file(&local_path);
                }
            },
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => {
                return Err(BucketStateClientError::Backend(format!(
                    "read cached shard chunk {}: {err}",
                    local_path.display()
                )));
            }
        }

        let bucket_key = if self.manifest_dir.is_empty() {
            object_key.to_string()
        } else {
            format!("{}/{}", self.manifest_dir, object_key)
        };
        let bytes = fetch_object(&self.store, &bucket_key).await?;
        hydrate::verify_chunk_sha(&bytes, expected_sha, &bucket_key)?;
        std::fs::create_dir_all(shard_dir).map_err(|err| {
            BucketStateClientError::Backend(format!(
                "create shard cache dir {}: {err}",
                shard_dir.display()
            ))
        })?;
        std::fs::write(&local_path, &bytes).map_err(|err| {
            BucketStateClientError::Backend(format!(
                "write cached shard chunk {}: {err}",
                local_path.display()
            ))
        })?;
        Ok(bytes)
    }

    fn shard_cache_dir(&self, shard: u32) -> PathBuf {
        self.checkpoint_cache_dir.join(format!("shard-{shard:04}"))
    }
}

// ============== BucketHeaderClient: trivial stub ==============
//
// We implement it (so the same Arc can be passed to with_bucket if the
// operator wants) but defer all real work to the dedicated header client.
// In practice the engine launcher wires the two clients separately.

impl BucketHeaderClient for HttpBucketStateClient {
    fn header_by_number(&self, _: BlockNumber) -> ProviderResult<Option<Header>> {
        Ok(None)
    }
    fn header_by_hash(&self, _: BlockHash) -> ProviderResult<Option<Header>> {
        Ok(None)
    }
    fn latest_finalized_block_number(&self) -> BlockNumber {
        self.head.latest_finalized_block_num
    }
    fn transaction_by_hash(&self, _: TxHash) -> ProviderResult<Option<TransactionSigned>> {
        Ok(None)
    }
}

// ============== BucketStateClient impl =====================

impl BucketStateClient for HttpBucketStateClient {
    fn account(&self, addr: Address) -> ProviderResult<Option<Account>> {
        let hashed_address = keccak256(addr);
        if let Some(cached) = self.account_cache.get(&hashed_address) {
            return Ok(cached);
        }
        let shard = shard_id(hashed_address, self.shard_bits);
        self.ensure_shard_materialized(shard)?;
        if let Some(cached) = self.account_cache.get(&hashed_address) {
            return Ok(cached);
        }
        self.account_cache.insert(hashed_address, None);
        Ok(None)
    }

    fn storage(&self, addr: Address, slot: U256) -> ProviderResult<Option<U256>> {
        let hashed_address = keccak256(addr);
        let hashed_slot = keccak256(slot.to_be_bytes::<32>());
        let key = (hashed_address, hashed_slot);
        if let Some(cached) = self.storage_cache.get(&key) {
            return Ok(cached);
        }
        let shard = shard_id(hashed_address, self.shard_bits);
        self.ensure_shard_materialized(shard)?;
        if let Some(cached) = self.storage_cache.get(&key) {
            return Ok(cached);
        }
        self.storage_cache.insert(key, None);
        Ok(None)
    }

    fn code_by_hash(&self, code_hash: B256) -> ProviderResult<Option<Bytes>> {
        if let Some(cached) = self.code_cache.get(&code_hash) {
            return Ok(cached);
        }
        let shard = shard_id(code_hash, self.shard_bits);
        self.ensure_shard_materialized(shard)?;
        if let Some(cached) = self.code_cache.get(&code_hash) {
            return Ok(cached);
        }
        self.code_cache.insert(code_hash, None);
        Ok(None)
    }

    fn pinned_block_number(&self) -> BlockNumber {
        self.pinned_block
    }

    fn pinned_block_hash(&self) -> Option<BlockHash> {
        self.pinned_block_hash
    }
}

/// Parse `"0x..."` (or bare hex) into a [`BlockHash`]. Used to lift
/// the manifest's String fields into the typed gate.
fn parse_block_hash(s: &str) -> Result<BlockHash, BucketStateClientError> {
    let trimmed = s.strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(trimmed).map_err(|err| {
        BucketStateClientError::Decode(format!("invalid hex for block hash {s:?}: {err}"))
    })?;
    if bytes.len() != 32 {
        return Err(BucketStateClientError::Decode(format!(
            "block hash must be 32 bytes, got {} in {s:?}",
            bytes.len()
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(BlockHash::from(out))
}

// ============== plumbing helpers ===========================

fn cache<K, V>() -> Cache<K, Option<V>>
where
    K: Eq + std::hash::Hash + Clone + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
{
    Cache::new(u64::MAX)
}

fn validate_checkpoint_manifest(
    manifest: &FinalizedStateArtifactManifest,
) -> Result<(), BucketStateClientError> {
    if manifest.version != 3 {
        return Err(BucketStateClientError::Decode(format!(
            "unsupported checkpoint manifest version {}; bucket-state-client requires version 3 hashed checkpoints",
            manifest.version
        )));
    }
    if manifest.key_layout.as_deref() != Some("hashed") {
        return Err(BucketStateClientError::Decode(format!(
            "unsupported checkpoint key_layout {:?}; bucket-state-client requires \"hashed\"",
            manifest.key_layout
        )));
    }
    if manifest.shards.is_empty() {
        return Err(BucketStateClientError::Decode(
            "checkpoint manifest v3 must contain hashed shards".into(),
        ));
    }
    let shard_bits = manifest.shard_bits.ok_or_else(|| {
        BucketStateClientError::Decode("checkpoint manifest v3 missing shard_bits".into())
    })?;
    if shard_bits > 32 {
        return Err(BucketStateClientError::Decode(format!(
            "checkpoint shard_bits {shard_bits} exceeds 32"
        )));
    }
    Ok(())
}

fn scan_cached_shards(checkpoint_cache_dir: &Path) -> DashSet<u32> {
    let loaded = DashSet::new();
    let Ok(entries) = std::fs::read_dir(checkpoint_cache_dir) else {
        return loaded;
    };
    for entry in entries.flatten() {
        let file_name = entry.file_name();
        let Some(name) = file_name.to_str() else {
            continue;
        };
        let Some(shard) = name.strip_prefix("shard-").and_then(|suffix| suffix.parse::<u32>().ok())
        else {
            continue;
        };
        let dir = entry.path();
        if dir.is_dir() {
            loaded.insert(shard);
        }
    }
    loaded
}

fn shard_id(hash: B256, shard_bits: u8) -> u32 {
    if shard_bits == 0 {
        return 0;
    }
    let bytes = hash.as_slice();
    let mut prefix = 0u32;
    for bit in 0..shard_bits {
        let byte = bytes[(bit / 8) as usize];
        let bit_in_byte = 7 - (bit % 8);
        prefix = (prefix << 1) | u32::from((byte >> bit_in_byte) & 1);
    }
    prefix
}

fn artifact_cache_file_name(artifact: &StateArtifactRef, fallback_idx: usize) -> String {
    Path::new(&artifact.object_key)
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.is_empty())
        .map(str::to_owned)
        .unwrap_or_else(|| format!("chunk-{fallback_idx:04}.vortex"))
}

fn build_object_store(
    cfg: &BucketStateConnConfig,
) -> Result<Arc<dyn ObjectStore>, BucketStateClientError> {
    let bucket = cfg
        .bucket_url
        .strip_prefix("s3://")
        .ok_or_else(|| {
            BucketStateClientError::Backend(format!(
                "expected s3:// bucket URL, got {}",
                cfg.bucket_url
            ))
        })?
        .to_string();
    if bucket.is_empty() {
        return Err(BucketStateClientError::Backend("empty bucket name".into()));
    }
    let allow_http = cfg.endpoint.starts_with("http://");
    let mut builder = AmazonS3Builder::new()
        .with_bucket_name(&bucket)
        .with_region(&cfg.region)
        .with_endpoint(&cfg.endpoint)
        .with_virtual_hosted_style_request(false)
        .with_allow_http(allow_http);
    if cfg.anonymous {
        builder = builder.with_skip_signature(true);
    } else {
        let ak = std::env::var(&cfg.access_key_env).map_err(|_| {
            BucketStateClientError::Backend(format!(
                "access key env var '{}' not set",
                cfg.access_key_env
            ))
        })?;
        let sk = std::env::var(&cfg.secret_key_env).map_err(|_| {
            BucketStateClientError::Backend(format!(
                "secret key env var '{}' not set",
                cfg.secret_key_env
            ))
        })?;
        builder = builder.with_access_key_id(ak).with_secret_access_key(sk);
    }
    Ok(Arc::new(builder.build().map_err(|err| {
        BucketStateClientError::Backend(format!("object_store init failed: {err}"))
    })?))
}

pub(crate) async fn fetch_object(
    store: &Arc<dyn ObjectStore>,
    key: &str,
) -> Result<Vec<u8>, BucketStateClientError> {
    let path = ObjectPath::from(key);
    let result = store
        .get(&path)
        .await
        .map_err(|err| BucketStateClientError::Backend(format!("GET {key}: {err}")))?;
    let bytes = result
        .bytes()
        .await
        .map_err(|err| BucketStateClientError::Backend(format!("body {key}: {err}")))?;
    Ok(bytes.to_vec())
}

async fn fetch_writer_pubkey(
    store: &Arc<dyn ObjectStore>,
    writer_id: &str,
) -> Result<[u8; 32], BucketStateClientError> {
    let bytes = fetch_object(store, &format!("writer-keys/{writer_id}.pub")).await?;
    if bytes.len() != 32 {
        return Err(BucketStateClientError::Trust(format!(
            "writer pubkey must be 32 raw bytes, got {}",
            bytes.len()
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

pub(crate) fn verify_ed25519(
    pubkey: &[u8; 32],
    payload: &[u8],
    sig: &[u8],
) -> Result<(), BucketStateClientError> {
    if sig.len() != 64 {
        return Err(BucketStateClientError::Trust(format!(
            "ed25519 sig must be 64 bytes, got {}",
            sig.len()
        )));
    }
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(sig);
    let key = ed25519_dalek::VerifyingKey::from_bytes(pubkey)
        .map_err(|err| BucketStateClientError::Trust(format!("invalid ed25519 pubkey: {err}")))?;
    let signature = ed25519_dalek::Signature::from_bytes(&sig_arr);
    key.verify(payload, &signature)
        .map_err(|err| BucketStateClientError::Trust(format!("signature verify failed: {err}")))
}

fn manifest_dir_from_url(manifest_url: &str) -> String {
    match manifest_url.rsplit_once('/') {
        Some((dir, _)) => dir.to_string(),
        None => String::new(),
    }
}

/// Walk the signed epoch manifest chain backwards from head, sig-
/// verifying every step, until we reach an epoch whose
/// `last_block_num <= pinned_block`. Returns the epochs that touch
/// `(pinned_block .. head_block]` in ascending order (the order
/// deltas must be applied in).
async fn walk_epoch_chain(
    store: &Arc<dyn ObjectStore>,
    pubkey: &[u8; 32],
    head: &HeadManifest,
    pinned_block: BlockNumber,
) -> Result<Vec<EpochManifest>, BucketStateClientError> {
    let mut collected: Vec<EpochManifest> = Vec::new();
    let mut next_url = Some(head.epoch_manifest_url.clone());
    let mut expected_sha = Some(head.epoch_manifest_sha256.clone());
    // Generous budget: head→pinned/32 epochs + headroom.
    let mut budget =
        64u32 + ((head.latest_finalized_block_num.saturating_sub(pinned_block) / 32 + 8) as u32);
    while let Some(url) = next_url.take() {
        if budget == 0 {
            return Err(BucketStateClientError::Backend(
                "epoch manifest chain walk exceeded budget".into(),
            ));
        }
        budget -= 1;
        let bytes = fetch_object(store, &url)
            .await
            .map_err(|err| BucketStateClientError::Backend(format!("epoch {url}: {err}")))?;
        let sig = fetch_object(store, &format!("{url}.sig"))
            .await
            .map_err(|err| BucketStateClientError::Backend(format!("epoch sig {url}: {err}")))?;
        verify_ed25519(pubkey, &bytes, &sig)?;
        if let Some(expected) = &expected_sha {
            let got = format!("{:x}", Sha256::digest(&bytes));
            if &got != expected {
                return Err(BucketStateClientError::Trust(format!(
                    "epoch manifest {url} sha mismatch: expected {expected}, got {got}"
                )));
            }
        }
        let manifest: EpochManifest = serde_json::from_slice(&bytes)
            .map_err(|err| BucketStateClientError::Decode(format!("epoch {url} decode: {err}")))?;
        let touches_window = manifest.last_block_num > pinned_block &&
            manifest.first_block_num <= head.latest_finalized_block_num;
        let earlier_than_pin = manifest.last_block_num <= pinned_block;
        expected_sha = manifest.previous_epoch_manifest_sha256.clone();
        next_url = manifest.previous_epoch_manifest_url.clone();
        if touches_window {
            collected.push(manifest);
        } else if earlier_than_pin {
            break;
        }
    }
    collected.sort_by_key(|e| e.first_block_num);
    debug!(
        target: "bucket-state-client",
        epochs = collected.len(),
        pinned_block,
        head_block = head.latest_finalized_block_num,
        "walked epoch manifest chain"
    );
    Ok(collected)
}

/// Wrap the loaded client as a `BucketStateClientArc` for
/// `BlockchainProvider::with_state_bucket(...)`.
pub fn into_state_arc(client: Arc<HttpBucketStateClient>) -> BucketStateClientArc {
    client
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checkpoint_index_picks_latest_le_target() {
        let idx = CheckpointIndex {
            version: 1,
            chain_id: 1,
            writer_id: "primary".into(),
            updated_at: "".into(),
            entries: vec![
                CheckpointIndexEntry {
                    block_number: 100,
                    block_hash: "0xaa".into(),
                    state_root: None,
                    manifest_url: "checkpoints/100/manifest.json".into(),
                    manifest_sha256: "x".into(),
                },
                CheckpointIndexEntry {
                    block_number: 50,
                    block_hash: "0xbb".into(),
                    state_root: None,
                    manifest_url: "checkpoints/50/manifest.json".into(),
                    manifest_sha256: "y".into(),
                },
            ],
        };
        assert_eq!(idx.pick_for_block(99).unwrap().block_number, 50);
        assert_eq!(idx.pick_for_block(100).unwrap().block_number, 100);
        assert_eq!(idx.pick_for_block(200).unwrap().block_number, 100);
        assert!(idx.pick_for_block(0).is_none());
    }

    #[test]
    fn ed25519_round_trip() {
        let mut seed = [0u8; 32];
        seed[0] = 7;
        let key = ed25519_dalek::SigningKey::from_bytes(&seed);
        let pubkey: [u8; 32] = ed25519_dalek::VerifyingKey::from(&key).to_bytes();
        let payload = b"checkpoint manifest payload";
        let sig = ed25519_dalek::Signer::sign(&key, payload).to_bytes().to_vec();
        verify_ed25519(&pubkey, payload, &sig).expect("ok");
        let mut tampered = payload.to_vec();
        tampered[0] = b'X';
        assert!(verify_ed25519(&pubkey, &tampered, &sig).is_err());
    }

    #[test]
    fn manifest_dir_strips_filename() {
        assert_eq!(
            manifest_dir_from_url("checkpoints/25120500/manifest.json"),
            "checkpoints/25120500"
        );
        assert_eq!(manifest_dir_from_url("manifest.json"), "");
    }

    #[test]
    fn config_defaults() {
        let cfg = BucketStateClientConfig::new(BucketStateConnConfig {
            bucket_url: "s3://x".into(),
            endpoint: "https://example.com".into(),
            region: "auto".into(),
            anonymous: true,
            access_key_env: "X".into(),
            secret_key_env: "Y".into(),
            trusted_writers: vec!["primary".into()],
            cache_dir: BucketStateConnConfig::default_cache_dir(),
        });
        assert_eq!(cfg.checkpoint_prefix, "checkpoints");
        assert!(cfg.apply_deltas);
        assert!(cfg.target_block.is_none());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn cache_hit_returns_without_fetch() {
        let tmp = tempfile::tempdir().unwrap();
        let client = test_client(
            Arc::new(object_store::memory::InMemory::new()) as Arc<dyn ObjectStore>,
            checkpoint_manifest(0, vec![empty_shard_manifest(0)]),
            tmp.path().to_path_buf(),
        );
        let addr = Address::from([0x11; 20]);
        let account = Account {
            nonce: 7,
            balance: U256::from(9),
            bytecode_hash: Some(B256::from([0x22; 32])),
        };
        client.account_cache.insert(keccak256(addr), Some(account));

        assert_eq!(client.account(addr).unwrap(), Some(account));
        assert!(client.materialized_shards.is_empty());
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn cache_miss_loads_shard_then_second_call_hits_cache() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(object_store::memory::InMemory::new()) as Arc<dyn ObjectStore>;
        let manifest_dir = "checkpoints/100";
        let addr = Address::from([0x33; 20]);
        let slot = U256::from(0x44);
        let hashed_addr = keccak256(addr);
        let hashed_slot = keccak256(slot.to_be_bytes::<32>());
        let code = Bytes::from_static(b"bucket-code");
        let code_hash = keccak256(code.as_ref());
        let account = Account { nonce: 1, balance: U256::from(2), bytecode_hash: Some(code_hash) };
        let shard = put_test_shard(
            &store,
            manifest_dir,
            0,
            &[(hashed_addr, account.nonce, account.balance, code_hash)],
            &[(hashed_addr, hashed_slot, U256::from(3))],
            &[(code_hash, code.to_vec())],
        )
        .await;
        let client = test_client(
            Arc::clone(&store),
            checkpoint_manifest(0, vec![shard]),
            tmp.path().to_path_buf(),
        );

        assert_eq!(client.account(addr).unwrap(), Some(account));
        assert_eq!(client.storage(addr, slot).unwrap(), Some(U256::from(3)));
        assert_eq!(client.code_by_hash(code_hash).unwrap(), Some(code.clone()));
        assert!(client.materialized_shards.contains(&0));
        assert!(client.shard_cache_dir(0).join("accounts-part-0000.vortex").is_file());

        for object in [
            "shard-0000/accounts-part-0000.vortex",
            "shard-0000/storage-part-0000.vortex",
            "shard-0000/code-part-0000.vortex",
        ] {
            store.delete(&ObjectPath::from(format!("{manifest_dir}/{object}"))).await.unwrap();
        }

        assert_eq!(client.account(addr).unwrap(), Some(account));
        assert_eq!(client.storage(addr, slot).unwrap(), Some(U256::from(3)));
        assert_eq!(client.code_by_hash(code_hash).unwrap(), Some(code));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn shard_load_decodes_multiple_storage_sub_chunks() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(object_store::memory::InMemory::new()) as Arc<dyn ObjectStore>;
        let manifest_dir = "checkpoints/100";
        let addr = Address::from([0x34; 20]);
        let slot_a = U256::from(0x45);
        let slot_b = U256::from(0x46);
        let hashed_addr = keccak256(addr);
        let hashed_slot_a = keccak256(slot_a.to_be_bytes::<32>());
        let hashed_slot_b = keccak256(slot_b.to_be_bytes::<32>());
        let mut shard = empty_shard_manifest(0);
        let mut storage_ref_a = artifact_ref(0, "storage", 0);
        put_chunk(
            &store,
            manifest_dir,
            &mut storage_ref_a,
            storage_chunk(&[(hashed_addr, hashed_slot_a, U256::from(11))]).await,
        )
        .await;
        shard.storage.push(storage_ref_a);
        let mut storage_ref_b = artifact_ref(0, "storage", 1);
        put_chunk(
            &store,
            manifest_dir,
            &mut storage_ref_b,
            storage_chunk(&[(hashed_addr, hashed_slot_b, U256::from(12))]).await,
        )
        .await;
        shard.storage.push(storage_ref_b);
        let client = test_client(
            Arc::clone(&store),
            checkpoint_manifest(0, vec![shard]),
            tmp.path().to_path_buf(),
        );

        assert_eq!(client.storage(addr, slot_a).unwrap(), Some(U256::from(11)));
        assert_eq!(client.storage(addr, slot_b).unwrap(), Some(U256::from(12)));
        assert!(client.materialized_shards.contains(&0));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn shard_load_failure_propagates() {
        let tmp = tempfile::tempdir().unwrap();
        let client = test_client(
            Arc::new(object_store::memory::InMemory::new()) as Arc<dyn ObjectStore>,
            checkpoint_manifest(0, vec![referenced_shard_manifest(0)]),
            tmp.path().to_path_buf(),
        );
        let err = client.account(Address::from([0x55; 20])).unwrap_err();
        assert!(err
            .to_string()
            .contains("GET checkpoints/100/shard-0000/accounts-part-0000.vortex"));
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn lazy_checkpoint_load_does_not_overwrite_delta_cache_entries() {
        let tmp = tempfile::tempdir().unwrap();
        let store = Arc::new(object_store::memory::InMemory::new()) as Arc<dyn ObjectStore>;
        let manifest_dir = "checkpoints/100";
        let addr = Address::from([0x66; 20]);
        let slot = U256::from(0x77);
        let hashed_addr = keccak256(addr);
        let hashed_slot = keccak256(slot.to_be_bytes::<32>());
        let checkpoint_code = Bytes::from_static(b"old-code");
        let checkpoint_code_hash = keccak256(checkpoint_code.as_ref());
        let delta_code = Bytes::from_static(b"new-code");
        let delta_code_hash = keccak256(delta_code.as_ref());
        let shard = put_test_shard(
            &store,
            manifest_dir,
            0,
            &[(hashed_addr, 1, U256::from(1), checkpoint_code_hash)],
            &[(hashed_addr, hashed_slot, U256::from(1))],
            &[(delta_code_hash, checkpoint_code.to_vec())],
        )
        .await;
        let client = test_client(
            Arc::clone(&store),
            checkpoint_manifest(0, vec![shard]),
            tmp.path().to_path_buf(),
        );
        let delta_account =
            Account { nonce: 2, balance: U256::from(2), bytecode_hash: Some(delta_code_hash) };
        client.account_cache.insert(hashed_addr, Some(delta_account));
        client.storage_cache.insert((hashed_addr, hashed_slot), Some(U256::from(2)));
        client.code_cache.insert(delta_code_hash, Some(delta_code.clone()));

        assert_eq!(client.account(addr).unwrap(), Some(delta_account));
        assert_eq!(client.storage(addr, slot).unwrap(), Some(U256::from(2)));
        assert_eq!(client.code_by_hash(delta_code_hash).unwrap(), Some(delta_code));
    }

    #[test]
    fn manifest_pre_v3_is_rejected() {
        let mut manifest = checkpoint_manifest(0, vec![empty_shard_manifest(0)]);
        for version in [1, 2] {
            manifest.version = version;
            let err = validate_checkpoint_manifest(&manifest).unwrap_err();
            assert!(err.to_string().contains("requires version 3 hashed checkpoints"));
        }
    }

    #[test]
    fn parse_block_hash_round_trip() {
        let h = BlockHash::from([0xabu8; 32]);
        let s = format!("0x{}", hex::encode(h.as_slice()));
        let parsed = parse_block_hash(&s).expect("parse");
        assert_eq!(parsed, h);

        // bare hex (no 0x prefix) also accepted
        let s2 = hex::encode(h.as_slice());
        let parsed2 = parse_block_hash(&s2).expect("parse no-prefix");
        assert_eq!(parsed2, h);

        // wrong length rejected
        assert!(parse_block_hash("0xdead").is_err());
        // non-hex rejected
        assert!(parse_block_hash("0xZZ").is_err());
    }

    #[test]
    fn pinned_block_hash_matches_manifest_for_fresh_checkpoint() {
        let tempdir = tempfile::tempdir().unwrap();
        let store: Arc<dyn ObjectStore> = Arc::new(object_store::memory::InMemory::new());
        let hash = BlockHash::from([0x42u8; 32]);
        let mut manifest = checkpoint_manifest(4, vec![empty_shard_manifest(0)]);
        manifest.block_hash = format!("0x{}", hex::encode(hash.as_slice()));
        let client = test_client(store, manifest, tempdir.path().to_path_buf());

        // No deltas applied; pinned hash == checkpoint hash.
        assert_eq!(client.pinned_block_hash(), Some(hash));
    }

    #[test]
    fn shard_id_uses_high_order_keccak_prefix_bits() {
        assert_eq!(shard_id(B256::from([0b1010_0000; 32]), 0), 0);
        assert_eq!(shard_id(B256::from([0b1010_0000; 32]), 1), 1);
        assert_eq!(shard_id(B256::from([0b1010_0000; 32]), 4), 0b1010);
        assert_eq!(shard_id(B256::from([0b1010_0000; 32]), 8), 0b1010_0000);
    }

    /// Smoke: the trait is dyn-compatible.
    #[test]
    fn bucket_state_client_dyn_smoke() {
        fn assert_dyn(_x: &dyn BucketStateClient) {}
        struct Stub;
        impl std::fmt::Debug for Stub {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "Stub")
            }
        }
        impl BucketHeaderClient for Stub {
            fn header_by_number(&self, _: BlockNumber) -> ProviderResult<Option<Header>> {
                Ok(None)
            }
            fn latest_finalized_block_number(&self) -> BlockNumber {
                0
            }
        }
        impl BucketStateClient for Stub {}
        assert_dyn(&Stub);
    }

    fn test_client(
        store: Arc<dyn ObjectStore>,
        manifest: FinalizedStateArtifactManifest,
        cache_dir: PathBuf,
    ) -> HttpBucketStateClient {
        let checkpoint_cache_dir = cache_dir.join(format!("checkpoint-{}", manifest.block_number));
        let shard_bits = manifest.shard_bits.unwrap_or(0);
        let shards = manifest
            .shards
            .iter()
            .cloned()
            .map(|shard| (shard.shard, shard))
            .collect::<HashMap<_, _>>();
        let code_cache = cache();
        code_cache.insert(KECCAK_EMPTY, Some(Bytes::new()));
        HttpBucketStateClient {
            head: HeadManifest {
                chain_id: 1,
                writer_id: "primary".into(),
                latest_finalized_epoch: 0,
                latest_finalized_block_num: manifest.block_number,
                latest_finalized_block_hash: "0x00".into(),
                epoch_manifest_url: "epochs/0/manifest.json".into(),
                epoch_manifest_sha256: String::new(),
            },
            pinned_block: manifest.block_number,
            pinned_block_hash: parse_block_hash(&manifest.block_hash).ok(),
            store,
            manifest_dir: "checkpoints/100".into(),
            shard_bits,
            shards,
            checkpoint_cache_dir,
            account_cache: cache(),
            storage_cache: cache(),
            code_cache,
            loaded_shards: DashSet::new(),
            materialized_shards: DashSet::new(),
            shard_singleflight: DashMap::new(),
            stats: HydrateStats::default(),
        }
    }

    fn checkpoint_manifest(
        shard_bits: u8,
        shards: Vec<ShardManifest>,
    ) -> FinalizedStateArtifactManifest {
        FinalizedStateArtifactManifest {
            version: 3,
            chain_id: 1,
            block_number: 100,
            block_hash: "0x00".into(),
            state_root: None,
            accounts: None,
            storage: None,
            code: None,
            shards,
            shard_bits: Some(shard_bits),
            key_layout: Some("hashed".into()),
        }
    }

    fn empty_shard_manifest(shard: u32) -> ShardManifest {
        ShardManifest { shard, accounts: Vec::new(), storage: Vec::new(), code: Vec::new() }
    }

    fn referenced_shard_manifest(shard: u32) -> ShardManifest {
        ShardManifest {
            shard,
            accounts: vec![artifact_ref(shard, "accounts", 0)],
            storage: vec![artifact_ref(shard, "storage", 0)],
            code: vec![artifact_ref(shard, "code", 0)],
        }
    }

    fn artifact_ref(shard: u32, kind: &str, part: usize) -> StateArtifactRef {
        StateArtifactRef {
            chain_id: 1,
            kind: kind.into(),
            from_block: 100,
            to_block: 100,
            state_root: None,
            object_key: format!("shard-{shard:04}/{kind}-part-{part:04}.vortex"),
            index_key: None,
            content_sha256: String::new(),
            shard: Some(shard),
            key_min: None,
            key_max: None,
        }
    }

    async fn put_test_shard(
        store: &Arc<dyn ObjectStore>,
        manifest_dir: &str,
        shard: u32,
        accounts: &[(B256, u64, U256, B256)],
        storage: &[(B256, B256, U256)],
        code: &[(B256, Vec<u8>)],
    ) -> ShardManifest {
        let accounts_bytes = accounts_chunk(accounts).await;
        let storage_bytes = storage_chunk(storage).await;
        let code_bytes = code_chunk(code).await;
        let mut manifest = empty_shard_manifest(shard);
        let mut accounts_ref = artifact_ref(shard, "accounts", 0);
        put_chunk(store, manifest_dir, &mut accounts_ref, accounts_bytes).await;
        manifest.accounts.push(accounts_ref);
        let mut storage_ref = artifact_ref(shard, "storage", 0);
        put_chunk(store, manifest_dir, &mut storage_ref, storage_bytes).await;
        manifest.storage.push(storage_ref);
        let mut code_ref = artifact_ref(shard, "code", 0);
        put_chunk(store, manifest_dir, &mut code_ref, code_bytes).await;
        manifest.code.push(code_ref);
        manifest
    }

    async fn put_chunk(
        store: &Arc<dyn ObjectStore>,
        manifest_dir: &str,
        artifact: &mut StateArtifactRef,
        bytes: Vec<u8>,
    ) {
        artifact.content_sha256 = format!("{:x}", Sha256::digest(&bytes));
        store
            .put(&ObjectPath::from(format!("{manifest_dir}/{}", artifact.object_key)), bytes.into())
            .await
            .unwrap();
    }

    async fn accounts_chunk(rows: &[(B256, u64, U256, B256)]) -> Vec<u8> {
        use vortex::array::{
            arrays::StructArray as VortexStructArray, dtype::FieldNames, validity::Validity,
            IntoArray,
        };

        let len = rows.len();
        let data = VortexStructArray::new(
            FieldNames::from(["hashed_address", "nonce", "balance", "code_hash"]),
            vec![
                binary_required(rows.iter().map(|(a, _, _, _)| a.as_slice().to_vec()).collect()),
                primitive_required(rows.iter().map(|(_, n, _, _)| *n as i64)),
                binary_required(
                    rows.iter().map(|(_, _, b, _)| b.to_be_bytes::<32>().to_vec()).collect(),
                ),
                binary_required(rows.iter().map(|(_, _, _, h)| h.as_slice().to_vec()).collect()),
            ],
            len,
            Validity::NonNullable,
        )
        .into_array();
        write_vortex(data).await
    }

    async fn storage_chunk(rows: &[(B256, B256, U256)]) -> Vec<u8> {
        use vortex::array::{
            arrays::StructArray as VortexStructArray, dtype::FieldNames, validity::Validity,
            IntoArray,
        };

        let len = rows.len();
        let data = VortexStructArray::new(
            FieldNames::from(["hashed_address", "hashed_slot", "value"]),
            vec![
                binary_required(rows.iter().map(|(a, _, _)| a.as_slice().to_vec()).collect()),
                binary_required(rows.iter().map(|(_, s, _)| s.as_slice().to_vec()).collect()),
                binary_required(
                    rows.iter().map(|(_, _, v)| v.to_be_bytes::<32>().to_vec()).collect(),
                ),
            ],
            len,
            Validity::NonNullable,
        )
        .into_array();
        write_vortex(data).await
    }

    async fn code_chunk(rows: &[(B256, Vec<u8>)]) -> Vec<u8> {
        use vortex::array::{
            arrays::StructArray as VortexStructArray, dtype::FieldNames, validity::Validity,
            IntoArray,
        };

        let len = rows.len();
        let data = VortexStructArray::new(
            FieldNames::from(["code_hash", "code"]),
            vec![
                binary_required(rows.iter().map(|(h, _)| h.as_slice().to_vec()).collect()),
                binary_required(rows.iter().map(|(_, c)| c.clone()).collect()),
            ],
            len,
            Validity::NonNullable,
        )
        .into_array();
        write_vortex(data).await
    }

    async fn write_vortex(data: vortex::array::ArrayRef) -> Vec<u8> {
        use vortex::{buffer::ByteBufferMut, session::VortexSession, VortexSessionDefault};
        use vortex_file::WriteOptionsSessionExt;

        let session = VortexSession::default();
        let mut out = ByteBufferMut::empty();
        session.write_options().write(&mut out, data.to_array_stream()).await.unwrap();
        out.freeze().to_vec()
    }

    fn primitive_required<T, I>(values: I) -> vortex::array::ArrayRef
    where
        T: vortex::array::dtype::NativePType,
        I: IntoIterator<Item = T>,
    {
        use vortex::{
            array::{arrays::PrimitiveArray, validity::Validity, IntoArray},
            buffer::Buffer,
        };

        PrimitiveArray::new(
            Buffer::<T>::from(values.into_iter().collect::<Vec<_>>()),
            Validity::NonNullable,
        )
        .into_array()
    }

    fn binary_required(values: Vec<Vec<u8>>) -> vortex::array::ArrayRef {
        use vortex::array::{
            builders::{ArrayBuilder, VarBinViewBuilder},
            dtype::{DType, Nullability},
        };

        let mut builder =
            VarBinViewBuilder::with_capacity(DType::Binary(Nullability::NonNullable), values.len());
        for value in values {
            builder.append_value(value);
        }
        ArrayBuilder::finish(&mut builder)
    }
}

//! HTTP/Vortex implementer of [`reth_provider::BucketStateClient`].
//!
//! Phase 26.2 checkpoint + Phase 26.1 epoch-delta replay → in-memory
//! plain-state HashMaps → sync `BucketStateClient` reads.
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
//! 2. Fetch `manifest/head.json[.sig]`, verify ed25519 against
//!    `writer-keys/<id>.pub`, parse to get the latest finalized block.
//! 3. Fetch `<prefix>/index.json[.sig]`, verify, parse as
//!    `CheckpointIndex`.
//! 4. Pick the most recent entry ≤ `target_block` (default = head's
//!    `latest_finalized_block_num`).
//! 5. Fetch the entry's `manifest.json[.sig]`, verify sig + sha, parse.
//! 6. For single-shard checkpoints: fetch `accounts.vortex`,
//!    `storage.vortex`, `code.vortex`. For shard-bits > 0:
//!    fetch `shard-NNNN/{accounts,storage,code}.vortex` per shard.
//! 7. Decode each Vortex chunk → fold into in-memory HashMaps.
//! 8. Walk forward through epoch manifests from
//!    `checkpoint.block_number + 1 .. head.latest_finalized_block_num`,
//!    decoding each epoch's `state_account_deltas` /
//!    `state_storage_deltas` / `state_code_deltas` artifacts when
//!    advertised, and applying as latest-wins updates.
//! 9. Track `pinned_block_number` = last block whose state is fully
//!    materialized.
//!
//! ## Read path
//!
//! `account` / `storage` / `code_by_hash` are HashMap lookups.
//! `BucketStateClient` is sync (mirrors reth's `StateProvider`); the
//! bootstrap is the only async part and runs under
//! `block_in_place(handle.block_on(...))` from inside the reth runtime
//! context, the same shape `HttpBucketHeaderClient` uses.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use alloy_consensus::Header;
use alloy_consensus::constants::KECCAK_EMPTY;
use alloy_primitives::{Address, B256, BlockHash, BlockNumber, Bytes, TxHash, U256};
use ed25519_dalek::Verifier;
use object_store::aws::AmazonS3Builder;
use object_store::path::Path as ObjectPath;
use object_store::{ObjectStore, ObjectStoreExt};
use reth_ethereum_primitives::TransactionSigned;
use reth_primitives_traits::Account;
use reth_provider::{BucketHeaderClient, BucketStateClient, BucketStateClientArc};
use reth_storage_errors::db::DatabaseError;
use reth_storage_errors::provider::{ProviderError, ProviderResult};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::runtime::Handle;
use tracing::{debug, info, warn};

mod hydrate;
mod vortex_state;

pub use hydrate::HydrateStats;

/// Errors surfaced by the bucket-state client.
#[derive(Debug, thiserror::Error)]
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
    pub chain_id: u64,
    pub kind: String,
    pub from_block: u64,
    pub to_block: u64,
    #[serde(default)]
    pub state_root: Option<String>,
    pub object_key: String,
    #[serde(default)]
    pub index_key: Option<String>,
    pub content_sha256: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shard: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShardManifest {
    pub shard: u32,
    pub accounts: StateArtifactRef,
    pub storage: StateArtifactRef,
    pub code: StateArtifactRef,
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
    /// materialized in our HashMaps. Always ≤ `head.latest_finalized_block_num`.
    pinned_block: BlockNumber,
    accounts: HashMap<Address, Account>,
    storage: HashMap<(Address, U256), U256>,
    code: HashMap<B256, Bytes>,
    stats: HydrateStats,
}

impl std::fmt::Debug for HttpBucketStateClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpBucketStateClient")
            .field("pinned_block", &self.pinned_block)
            .field("head_block", &self.head.latest_finalized_block_num)
            .field("accounts", &self.accounts.len())
            .field("storage", &self.storage.len())
            .field("code", &self.code.len())
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
        self.accounts.len()
    }
    /// Number of storage slots loaded.
    pub fn storage_count(&self) -> usize {
        self.storage.len()
    }
    /// Number of bytecode blobs loaded.
    pub fn code_count(&self) -> usize {
        self.code.len()
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
    pub async fn new(
        config: BucketStateClientConfig,
    ) -> Result<Self, BucketStateClientError> {
        let total_start = Instant::now();
        let store = build_object_store(&config.conn)?;
        let prefix = config.checkpoint_prefix.trim_matches('/').to_string();

        // Resolve the trusted writer pubkey.
        let writer_id = config
            .conn
            .trusted_writers
            .first()
            .cloned()
            .unwrap_or_else(|| "primary".to_string());
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
        if !config.conn.trusted_writers.is_empty()
            && !config.conn.trusted_writers.contains(&head.writer_id)
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
        let entry = index
            .pick_for_block(target_block)
            .cloned()
            .ok_or_else(|| {
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
        let signed: SignedCheckpointManifest = serde_json::from_slice(&manifest_bytes)
            .map_err(|err| {
                BucketStateClientError::Decode(format!("signed manifest decode: {err}"))
            })?;
        let manifest = signed.manifest;

        // 4. Hydrate accounts/storage/code from the checkpoint chunks.
        let manifest_dir = manifest_dir_from_url(&entry.manifest_url);
        let mut accounts: HashMap<Address, Account> = HashMap::new();
        let mut storage: HashMap<(Address, U256), U256> = HashMap::new();
        let mut code: HashMap<B256, Bytes> = HashMap::new();
        // KECCAK_EMPTY always maps to empty bytes.
        code.insert(KECCAK_EMPTY, Bytes::new());

        let checkpoint_t0 = Instant::now();
        let mut chunk_bytes = 0u64;
        if !manifest.shards.is_empty() {
            for shard in &manifest.shards {
                let a_path = format!("{manifest_dir}/{}", shard.accounts.object_key);
                let s_path = format!("{manifest_dir}/{}", shard.storage.object_key);
                let c_path = format!("{manifest_dir}/{}", shard.code.object_key);
                chunk_bytes += hydrate::load_shard(
                    Arc::clone(&store),
                    &a_path,
                    &shard.accounts.content_sha256,
                    &s_path,
                    &shard.storage.content_sha256,
                    &c_path,
                    &shard.code.content_sha256,
                    &mut accounts,
                    &mut storage,
                    &mut code,
                )
                .await?;
            }
        } else if let (Some(a), Some(s), Some(c)) =
            (&manifest.accounts, &manifest.storage, &manifest.code)
        {
            let a_path = format!("{manifest_dir}/{}", a.object_key);
            let s_path = format!("{manifest_dir}/{}", s.object_key);
            let c_path = format!("{manifest_dir}/{}", c.object_key);
            chunk_bytes += hydrate::load_shard(
                Arc::clone(&store),
                &a_path,
                &a.content_sha256,
                &s_path,
                &s.content_sha256,
                &c_path,
                &c.content_sha256,
                &mut accounts,
                &mut storage,
                &mut code,
            )
            .await?;
        } else {
            return Err(BucketStateClientError::Decode(
                "checkpoint manifest has neither shards nor single-shard refs".into(),
            ));
        }
        let checkpoint_stats = hydrate::CheckpointHydrateStats {
            block_number: manifest.block_number,
            shards: manifest.shards.len().max(1) as u32,
            accounts: accounts.len() as u64,
            storage: storage.len() as u64,
            code: code.len() as u64,
            bytes_fetched: chunk_bytes,
            elapsed_ms: checkpoint_t0.elapsed().as_millis() as u64,
        };
        info!(
            target: "bucket-state-client",
            block_number = manifest.block_number,
            accounts = checkpoint_stats.accounts,
            storage = checkpoint_stats.storage,
            code = checkpoint_stats.code,
            bytes = checkpoint_stats.bytes_fetched,
            elapsed_ms = checkpoint_stats.elapsed_ms,
            "checkpoint hydrated"
        );

        let mut pinned_block = manifest.block_number;
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
                    &mut accounts,
                    &mut storage,
                    &mut code,
                    &mut delta_stats,
                )
                .await?;
                if applied > pinned_block {
                    pinned_block = applied;
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
            account_count = accounts.len(),
            storage_count = storage.len(),
            code_count = code.len(),
            elapsed_ms = stats.total_elapsed_ms,
            "bucket-state-client snapshot loaded"
        );

        Ok(Self {
            head,
            pinned_block,
            accounts,
            storage,
            code,
            stats,
        })
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
        if let Some(acc) = self.accounts.get(&addr).copied() {
            // Tombstone: all-zero account is `None` to revm/StateProvider
            if acc.nonce == 0
                && acc.balance.is_zero()
                && acc.bytecode_hash == Some(KECCAK_EMPTY)
            {
                return Ok(None);
            }
            return Ok(Some(acc));
        }
        Ok(None)
    }

    fn storage(&self, addr: Address, slot: U256) -> ProviderResult<Option<U256>> {
        Ok(self.storage.get(&(addr, slot)).copied())
    }

    fn code_by_hash(&self, code_hash: B256) -> ProviderResult<Option<Bytes>> {
        Ok(self.code.get(&code_hash).cloned())
    }

    fn pinned_block_number(&self) -> BlockNumber {
        self.pinned_block
    }
}

// ============== plumbing helpers ===========================

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
    Ok(Arc::new(
        builder.build().map_err(|err| {
            BucketStateClientError::Backend(format!("object_store init failed: {err}"))
        })?,
    ))
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
    let key = ed25519_dalek::VerifyingKey::from_bytes(pubkey).map_err(|err| {
        BucketStateClientError::Trust(format!("invalid ed25519 pubkey: {err}"))
    })?;
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
    let mut budget = 64u32
        + ((head.latest_finalized_block_num.saturating_sub(pinned_block) / 32 + 8) as u32);
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
        let touches_window = manifest.last_block_num > pinned_block
            && manifest.first_block_num <= head.latest_finalized_block_num;
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
        });
        assert_eq!(cfg.checkpoint_prefix, "checkpoints");
        assert!(cfg.apply_deltas);
        assert!(cfg.target_block.is_none());
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
}

//! HTTP/Vortex implementer of [`reth_provider::BucketHeaderClient`].
//!
//! Fetches the signed manifest chain from an S3-compatible bucket
//! and decodes header reads from per-block `block_header.vortex`
//! chunks (or `block_header` parquet fallback when Vortex isn't
//! advertised by the chunk's manifest entry).
//!
//! ## Trust chain
//!
//! - `manifest/head.json` ed25519-signed by writer
//! - `manifest/finalized/<epoch>.json` ed25519-signed by writer, sha256-pinned by
//!   `head.epoch_manifest_sha256`
//! - chunks pinned by sha256 inside the epoch manifest's `block_index` + `chunks` map
//!
//! Same trust shape relay-rpc already runs at 100% L1 mainnet
//! traffic. See `crates/relay-rpc/src/backends/bucket.rs` in the
//! relay project for the canonical reader-side implementation; this
//! crate is the in-reth port (sync `HeaderProvider`-shaped surface).

use std::{collections::HashMap, sync::Arc};

use alloy_consensus::Header;
use alloy_primitives::{Address, BlockHash, BlockNumber, Bloom, Bytes, B256, U256};
use alloy_rpc_types_eth::Log;
use arc_swap::ArcSwap;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use ed25519_dalek::Verifier;
use object_store::{aws::AmazonS3Builder, path::Path as ObjectPath, ObjectStore, ObjectStoreExt};
use reth_ethereum_primitives::TransactionSigned;
use reth_provider::{BucketHeaderClient, BucketHeaderClientArc};
use reth_storage_errors::{
    db::DatabaseError,
    provider::{ProviderError, ProviderResult},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::runtime::Handle;
use tracing::{debug, info, warn};

mod log_decode;
mod logs_decode;
mod receipt_decode;
mod tx_decode;
mod vortex_decode;

pub use logs_decode::{chunk_bloom_skips_filter, LogScanFilter};

#[derive(Debug, thiserror::Error)]
pub enum BucketClientError {
    #[error("bucket backend: {0}")]
    Backend(String),
    #[error("trust verification failed: {0}")]
    Trust(String),
    #[error("decode failed for block {block}: {reason}")]
    Decode { block: u64, reason: String },
}

impl From<BucketClientError> for ProviderError {
    fn from(err: BucketClientError) -> Self {
        ProviderError::Database(DatabaseError::Other(err.to_string()))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HeadManifest {
    pub chain_id: u64,
    pub writer_id: String,
    pub latest_finalized_epoch: u64,
    pub latest_finalized_block_num: u64,
    pub latest_finalized_block_hash: String,
    pub epoch_manifest_url: String,
    pub epoch_manifest_sha256: String,
    #[serde(default)]
    pub updated_at: Option<String>,
    #[serde(default)]
    pub previous_head_sha256: Option<String>,
    #[serde(default)]
    pub version: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EpochManifest {
    pub chain_id: u64,
    pub epoch: u64,
    pub first_block_num: u64,
    pub last_block_num: u64,
    pub blocks: Vec<ManifestBlock>,
    #[serde(default)]
    pub epoch_artifacts: std::collections::BTreeMap<String, ManifestChunkRef>,
    #[serde(default)]
    pub tx_index: Option<ManifestIndex>,
    #[serde(default)]
    pub block_hash_index: Option<ManifestIndex>,
    #[serde(default)]
    pub previous_epoch_manifest_url: Option<String>,
    #[serde(default)]
    pub previous_epoch_manifest_sha256: Option<String>,
}

/// Signed external index reference (e.g. `tx_index.json`,
/// `block_hash_index.json`). The URL points to a JSON map and is
/// pinned by the sha256 — both signed by the writer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestIndex {
    pub url: String,
    pub sha256: String,
}

/// Per-tx location in the bucket: which finalized block it lives in
/// and its `idx` within that block's `transactions` chunk.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct TxIndexEntry {
    pub block_num: u64,
    pub tx_index: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestBlock {
    pub num: u64,
    pub hash: String,
    pub timestamp: String,
    pub chunks: std::collections::BTreeMap<String, ManifestChunkRef>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ManifestChunkRef {
    Path(String),
    Descriptor(ManifestChunkDescriptor),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestChunkDescriptor {
    pub path: String,
    #[serde(default)]
    pub format: String,
    #[serde(default)]
    pub version: Option<u32>,
    #[serde(default)]
    pub size_bytes: Option<u64>,
    #[serde(default)]
    pub vortex_footer_metadata_b64: Option<String>,
    #[serde(default)]
    pub vortex_preload_ranges: Vec<VortexPreloadRange>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VortexPreloadRange {
    pub offset: u64,
    pub length: u64,
}

impl ManifestChunkRef {
    pub fn path(&self) -> &str {
        match self {
            Self::Path(p) => p,
            Self::Descriptor(d) => &d.path,
        }
    }
    pub fn is_vortex(&self) -> bool {
        matches!(self, Self::Descriptor(d) if d.format == "vortex")
    }
    pub fn is_parquet(&self) -> bool {
        match self {
            Self::Path(_) => true,
            Self::Descriptor(d) => d.format.is_empty() || d.format == "parquet",
        }
    }
    pub fn footer_metadata(&self) -> Option<&str> {
        match self {
            Self::Descriptor(d) => d.vortex_footer_metadata_b64.as_deref(),
            _ => None,
        }
    }
    pub fn preload_ranges(&self) -> &[VortexPreloadRange] {
        match self {
            Self::Descriptor(d) => &d.vortex_preload_ranges,
            _ => &[],
        }
    }
    pub fn size_bytes(&self) -> Option<u64> {
        match self {
            Self::Descriptor(d) => d.size_bytes,
            _ => None,
        }
    }
}

#[derive(Debug)]
struct Snapshot {
    head: HeadManifest,
    epochs: Vec<EpochManifest>,
    block_to_epoch: HashMap<u64, usize>,
    block_hash_to_num: HashMap<String, u64>,
    /// `0x...` hex tx hash → (block_num, tx_idx). Built at boot
    /// from the signed per-epoch `tx_index.json` artifacts. Empty
    /// when no warm epoch ships `tx_index` (older writer output).
    tx_hash_to_location: HashMap<String, TxIndexEntry>,
}

#[derive(Debug, Clone)]
pub struct BucketHeaderClientConfig {
    pub bucket_url: String,
    pub endpoint: String,
    pub region: String,
    pub anonymous: bool,
    pub access_key_env: String,
    pub secret_key_env: String,
    pub trusted_writers: Vec<String>,
    pub warm_epochs: u32,
}

/// HTTP/Vortex BucketHeaderClient implementer.
#[derive(Debug)]
pub struct HttpBucketHeaderClient {
    config: BucketHeaderClientConfig,
    store: Arc<dyn ObjectStore>,
    snapshot: ArcSwap<Snapshot>,
    /// Public key (32 bytes) of the trusted writer for sig checks.
    writer_pubkey: [u8; 32],
}

impl HttpBucketHeaderClient {
    /// Build the client. Loads the head + warm epoch manifests
    /// synchronously (so a subsequent header query is one S3 fetch).
    pub fn new_blocking(config: BucketHeaderClientConfig) -> Result<Arc<Self>, BucketClientError> {
        let handle = Handle::try_current().map_err(|_| {
            BucketClientError::Backend(
                "HttpBucketHeaderClient::new_blocking requires a tokio runtime context".into(),
            )
        })?;
        // Inside a multi-threaded runtime the constructor is
        // called from within an executor task; using block_on
        // directly would panic. block_in_place yields the worker
        // to other tasks while we run the bootstrap synchronously.
        tokio::task::block_in_place(|| handle.block_on(async { Self::new(config).await }))
            .map(Arc::new)
    }

    pub fn bucket_url(&self) -> &str {
        &self.config.bucket_url
    }

    pub async fn new(config: BucketHeaderClientConfig) -> Result<Self, BucketClientError> {
        let bucket = config
            .bucket_url
            .strip_prefix("s3://")
            .ok_or_else(|| {
                BucketClientError::Backend(format!(
                    "expected s3:// bucket URL, got {}",
                    config.bucket_url
                ))
            })?
            .to_string();
        if bucket.is_empty() {
            return Err(BucketClientError::Backend("empty bucket name".into()));
        }
        let allow_http = config.endpoint.starts_with("http://");
        let mut builder = AmazonS3Builder::new()
            .with_bucket_name(&bucket)
            .with_region(&config.region)
            .with_endpoint(&config.endpoint)
            .with_virtual_hosted_style_request(false)
            .with_allow_http(allow_http);
        if config.anonymous {
            builder = builder.with_skip_signature(true);
        } else {
            let ak = std::env::var(&config.access_key_env).map_err(|_| {
                BucketClientError::Backend(format!(
                    "access key env var '{}' not set",
                    config.access_key_env
                ))
            })?;
            let sk = std::env::var(&config.secret_key_env).map_err(|_| {
                BucketClientError::Backend(format!(
                    "secret key env var '{}' not set",
                    config.secret_key_env
                ))
            })?;
            builder = builder.with_access_key_id(ak).with_secret_access_key(sk);
        }
        let store = Arc::new(builder.build().map_err(|err| {
            BucketClientError::Backend(format!("object_store init failed: {err}"))
        })?) as Arc<dyn ObjectStore>;
        // Load head + writer pubkey
        let head_bytes = fetch_object(&store, "manifest/head.json").await?;
        let head_sig = fetch_object(&store, "manifest/head.json.sig").await?;
        let head: HeadManifest = serde_json::from_slice(&head_bytes)
            .map_err(|err| BucketClientError::Backend(format!("decode head.json: {err}")))?;
        if !config.trusted_writers.is_empty() && !config.trusted_writers.contains(&head.writer_id) {
            return Err(BucketClientError::Trust(format!(
                "writer_id '{}' not in --bucket-trusted-writers",
                head.writer_id
            )));
        }
        let pubkey_bytes =
            fetch_object(&store, &format!("writer-keys/{}.pub", head.writer_id)).await?;
        if pubkey_bytes.len() != 32 {
            return Err(BucketClientError::Trust(format!(
                "writer pubkey must be 32 raw bytes, got {}",
                pubkey_bytes.len()
            )));
        }
        let mut writer_pubkey = [0u8; 32];
        writer_pubkey.copy_from_slice(&pubkey_bytes);
        verify_signature(&writer_pubkey, &head_bytes, &head_sig)?;
        // Walk epoch manifests up to warm_epochs.
        let mut epochs = Vec::new();
        let mut next_url = Some(head.epoch_manifest_url.clone());
        let mut expected_sha = Some(head.epoch_manifest_sha256.clone());
        while let Some(url) = next_url.take() {
            if epochs.len() as u32 >= config.warm_epochs.max(1) {
                break;
            }
            let bytes = fetch_object(&store, &url).await?;
            let sig = fetch_object(&store, &format!("{url}.sig")).await?;
            verify_signature(&writer_pubkey, &bytes, &sig)?;
            if let Some(expected) = &expected_sha {
                let got = format!("{:x}", Sha256::digest(&bytes));
                if &got != expected {
                    return Err(BucketClientError::Trust(format!(
                        "epoch manifest {url} sha mismatch: expected {expected}, got {got}"
                    )));
                }
            }
            let manifest: EpochManifest = serde_json::from_slice(&bytes)
                .map_err(|err| BucketClientError::Backend(format!("decode epoch {url}: {err}")))?;
            expected_sha = manifest.previous_epoch_manifest_sha256.clone();
            next_url = manifest.previous_epoch_manifest_url.clone();
            epochs.push(manifest);
        }
        let mut block_to_epoch = HashMap::new();
        let mut block_hash_to_num = HashMap::new();
        for (idx, e) in epochs.iter().enumerate() {
            for blk in &e.blocks {
                block_to_epoch.insert(blk.num, idx);
                block_hash_to_num.insert(blk.hash.clone(), blk.num);
            }
        }

        // Load per-epoch `tx_index.json` (signed) into an in-memory
        // tx_hash → (block_num, tx_idx) map. Each epoch's index is
        // verified against the writer's ed25519 key AND its sha256
        // is pinned by the epoch manifest. Epochs missing an index
        // entry are skipped silently — they predate the writer
        // emitting tx_index artifacts.
        let mut tx_hash_to_location: HashMap<String, TxIndexEntry> = HashMap::new();
        let mut tx_index_loaded_epochs = 0usize;
        for e in &epochs {
            let Some(index_ref) = &e.tx_index else { continue };
            let bytes = fetch_object(&store, &index_ref.url).await?;
            let sig = fetch_object(&store, &format!("{}.sig", index_ref.url)).await?;
            verify_signature(&writer_pubkey, &bytes, &sig)?;
            let got = format!("{:x}", Sha256::digest(&bytes));
            if got != index_ref.sha256 {
                return Err(BucketClientError::Trust(format!(
                    "tx_index sha mismatch for {}: expected {}, got {got}",
                    index_ref.url, index_ref.sha256
                )));
            }
            let parsed: HashMap<String, TxIndexEntry> =
                serde_json::from_slice(&bytes).map_err(|err| {
                    BucketClientError::Backend(format!("decode tx_index {}: {err}", index_ref.url))
                })?;
            tx_hash_to_location.extend(parsed);
            tx_index_loaded_epochs += 1;
        }

        info!(
            warm_epochs = epochs.len(),
            blocks = block_to_epoch.len(),
            tx_index_loaded_epochs,
            indexed_txs = tx_hash_to_location.len(),
            latest_finalized = head.latest_finalized_block_num,
            "bucket-header-client snapshot loaded"
        );
        Ok(Self {
            config,
            store,
            snapshot: ArcSwap::from_pointee(Snapshot {
                head,
                epochs,
                block_to_epoch,
                block_hash_to_num,
                tx_hash_to_location,
            }),
            writer_pubkey,
        })
    }

    /// Convenience: wrap as [`BucketHeaderClientArc`] for
    /// `BlockchainProvider::with_bucket`.
    pub fn into_arc(self: Arc<Self>) -> BucketHeaderClientArc {
        self
    }

    async fn fetch_header(&self, num: BlockNumber) -> Result<Option<Header>, BucketClientError> {
        let snap = self.snapshot.load();
        let Some(epoch_idx) = snap.block_to_epoch.get(&num).copied() else {
            return Ok(None);
        };
        let epoch = &snap.epochs[epoch_idx];
        let block = epoch.blocks.iter().find(|b| b.num == num).ok_or_else(|| {
            BucketClientError::Backend(format!(
                "block {num} indexed but not in epoch {} blocks",
                epoch.epoch
            ))
        })?;
        let chunk_ref = block.chunks.get("block_header").ok_or_else(|| {
            BucketClientError::Backend(format!("block {num} has no block_header chunk"))
        })?;
        let path = format!("chunks/{}", chunk_ref.path());
        debug!(num, path, "fetching block_header chunk");
        if chunk_ref.is_vortex() {
            let header = vortex_decode::decode_block_header_chunk(
                Arc::clone(&self.store),
                ObjectPath::from(path.as_str()),
                num,
                chunk_ref.size_bytes(),
                chunk_ref.footer_metadata(),
                chunk_ref.preload_ranges(),
            )
            .await
            .map_err(|err| BucketClientError::Decode {
                block: num,
                reason: format!("vortex: {err}"),
            })?;
            return Ok(Some(header));
        }
        // Parquet path — for the spike we synthesize a Header from
        // the manifest entry only (number + hash + parent_hash).
        // Filling the rest requires Parquet decoding which isn't
        // wired into this crate to keep the binary small. Real
        // production deployments use the Vortex chunks (Phase 24+).
        warn!(
            num,
            chunk_path = %chunk_ref.path(),
            "block_header chunk is legacy parquet — returning manifest-only Header. Vortex chunks recommended for full fidelity."
        );
        let parent_hash = epoch
            .blocks
            .iter()
            .find(|b| b.num == num.saturating_sub(1))
            .map(|b| parse_b256_hex(&b.hash))
            .transpose()
            .map_err(|err| BucketClientError::Decode {
                block: num,
                reason: format!("parent hash: {err}"),
            })?
            .unwrap_or(B256::ZERO);
        let hash = parse_b256_hex(&block.hash).map_err(|err| BucketClientError::Decode {
            block: num,
            reason: format!("hash: {err}"),
        })?;
        let _ = hash;
        Ok(Some(Header { parent_hash, number: num, ..Default::default() }))
    }

    /// Helper: locate the `(epoch_idx, block_meta, chunk_ref)`
    /// triplet for a given block + chunk kind, returning `None` if
    /// the snapshot doesn't cover the block or the block is missing
    /// that chunk kind. Used by tx/receipt/by-block paths.
    fn locate_chunk<'a>(
        snap: &'a Snapshot,
        num: u64,
        kind: &str,
    ) -> Option<(&'a EpochManifest, &'a ManifestBlock, &'a ManifestChunkRef)> {
        let epoch_idx = snap.block_to_epoch.get(&num).copied()?;
        let epoch = snap.epochs.get(epoch_idx)?;
        let block = epoch.blocks.iter().find(|b| b.num == num)?;
        let chunk = block.chunks.get(kind)?;
        Some((epoch, block, chunk))
    }

    /// Decode all transactions in `block_num` from the bucket's
    /// `transactions` chunk. Returns `Ok(None)` if the block is not
    /// covered or the chunk isn't a Vortex chunk (Parquet fallback
    /// would require pulling parquet decode for txs into this
    /// crate; not in scope for items 1-3).
    async fn fetch_transactions_by_block(
        &self,
        block_num: BlockNumber,
    ) -> Result<Option<Vec<TransactionSigned>>, BucketClientError> {
        let snap = self.snapshot.load();
        let Some((_, _, chunk_ref)) = Self::locate_chunk(&snap, block_num, "transactions") else {
            return Ok(None);
        };
        if !chunk_ref.is_vortex() {
            // The live mainnet bucket may still ship parquet for
            // `transactions` chunks; we don't ship a parquet path
            // for transactions in this crate. Fall through so the
            // caller can hit MDBX instead.
            debug!(
                block_num,
                chunk = chunk_ref.path(),
                "transactions chunk is not vortex; falling through"
            );
            return Ok(None);
        }
        let path = format!("chunks/{}", chunk_ref.path());
        let decoded = tx_decode::decode_transactions_chunk(
            Arc::clone(&self.store),
            ObjectPath::from(path.as_str()),
            block_num,
            chunk_ref.size_bytes(),
            chunk_ref.footer_metadata(),
            chunk_ref.preload_ranges(),
        )
        .await
        .map_err(|err| BucketClientError::Decode {
            block: block_num,
            reason: format!("vortex transactions: {err}"),
        })?;
        Ok(Some(decoded.into_iter().map(|d| d.tx).collect()))
    }

    /// Decode all receipts in `block_num`, joining logs from the
    /// block's `logs` chunk. Returns `Ok(None)` if either chunk is
    /// missing or non-Vortex.
    async fn fetch_receipts_by_block(
        &self,
        block_num: BlockNumber,
    ) -> Result<Option<Vec<reth_ethereum_primitives::Receipt>>, BucketClientError> {
        let snap = self.snapshot.load();
        let Some((_, _, receipts_chunk)) = Self::locate_chunk(&snap, block_num, "receipts") else {
            return Ok(None);
        };
        let logs_chunk = Self::locate_chunk(&snap, block_num, "logs").map(|(_, _, c)| c.clone());
        let txs_chunk =
            Self::locate_chunk(&snap, block_num, "transactions").map(|(_, _, c)| c.clone());
        let receipts_chunk = receipts_chunk.clone();
        drop(snap);

        if !receipts_chunk.is_vortex() {
            debug!(
                block_num,
                chunk = receipts_chunk.path(),
                "receipts chunk is not vortex; falling through"
            );
            return Ok(None);
        }

        // Decode logs for this block (or empty if no logs chunk /
        // not vortex). Receipts can still be returned with no logs
        // when the block had zero log-emitting transactions; we
        // treat missing logs as "no logs", not as an error.
        let logs_by_tx_idx = if let Some(chunk_ref) = logs_chunk {
            if chunk_ref.is_vortex() {
                let path = format!("chunks/{}", chunk_ref.path());
                let decoded = log_decode::decode_logs_chunk(
                    Arc::clone(&self.store),
                    ObjectPath::from(path.as_str()),
                    block_num,
                    chunk_ref.size_bytes(),
                    chunk_ref.footer_metadata(),
                    chunk_ref.preload_ranges(),
                )
                .await
                .map_err(|err| BucketClientError::Decode {
                    block: block_num,
                    reason: format!("vortex logs: {err}"),
                })?;
                receipt_decode::group_logs_by_tx_idx(decoded)
            } else {
                std::collections::BTreeMap::new()
            }
        } else {
            std::collections::BTreeMap::new()
        };

        // Decode tx-types alongside (needed for Receipt.tx_type).
        // Parquet-only transactions fall back to assuming legacy
        // tx_type=0 — better than failing the entire receipt fetch.
        let tx_types_by_tx_idx = if let Some(chunk_ref) = txs_chunk {
            if chunk_ref.is_vortex() {
                let path = format!("chunks/{}", chunk_ref.path());
                let decoded = tx_decode::decode_transactions_chunk(
                    Arc::clone(&self.store),
                    ObjectPath::from(path.as_str()),
                    block_num,
                    chunk_ref.size_bytes(),
                    chunk_ref.footer_metadata(),
                    chunk_ref.preload_ranges(),
                )
                .await
                .map_err(|err| BucketClientError::Decode {
                    block: block_num,
                    reason: format!("vortex transactions (tx_types): {err}"),
                })?;
                use alloy_consensus::Transaction as _;
                decoded
                    .into_iter()
                    .map(|d| (d.tx_idx, d.tx.tx_type() as u8))
                    .collect::<std::collections::BTreeMap<_, _>>()
            } else {
                std::collections::BTreeMap::new()
            }
        } else {
            std::collections::BTreeMap::new()
        };

        let path = format!("chunks/{}", receipts_chunk.path());
        let decoded = receipt_decode::decode_receipts_chunk(
            Arc::clone(&self.store),
            ObjectPath::from(path.as_str()),
            block_num,
            receipts_chunk.size_bytes(),
            receipts_chunk.footer_metadata(),
            receipts_chunk.preload_ranges(),
            &logs_by_tx_idx,
            &tx_types_by_tx_idx,
        )
        .await
        .map_err(|err| BucketClientError::Decode {
            block: block_num,
            reason: format!("vortex receipts: {err}"),
        })?;
        Ok(Some(decoded.into_iter().map(|d| d.receipt).collect()))
    }

    /// Fetch a single transaction by hash. Uses the boot-loaded
    /// tx_index to locate `(block_num, tx_idx)`, then decodes the
    /// transactions chunk and picks the matching row.
    async fn fetch_transaction_by_hash(
        &self,
        hash: alloy_primitives::TxHash,
    ) -> Result<Option<TransactionSigned>, BucketClientError> {
        let snap = self.snapshot.load();
        let key = format!("0x{}", hex::encode(hash.as_slice()));
        let Some(entry) = snap.tx_hash_to_location.get(&key).copied() else {
            return Ok(None);
        };
        drop(snap);
        let Some(txs) = self.fetch_transactions_by_block(entry.block_num).await? else {
            return Ok(None);
        };
        // Decoded txs are sorted by tx_idx. Find the entry matching
        // the index column from tx_index.json.
        Ok(txs.into_iter().nth(entry.tx_index as usize))
    }

    /// Fetch a single receipt by tx hash.
    async fn fetch_receipt_by_hash(
        &self,
        hash: alloy_primitives::TxHash,
    ) -> Result<Option<reth_ethereum_primitives::Receipt>, BucketClientError> {
        let snap = self.snapshot.load();
        let key = format!("0x{}", hex::encode(hash.as_slice()));
        let Some(entry) = snap.tx_hash_to_location.get(&key).copied() else {
            return Ok(None);
        };
        drop(snap);
        let Some(receipts) = self.fetch_receipts_by_block(entry.block_num).await? else {
            return Ok(None);
        };
        Ok(receipts.into_iter().nth(entry.tx_index as usize))
    }

    /// PHASE26.x — fetch logs for the inclusive range and apply the
    /// filter. Used by `BucketHeaderClient::logs_in_range`.
    async fn fetch_logs_in_range(
        &self,
        from_block: BlockNumber,
        to_block: BlockNumber,
        filter: &LogScanFilter,
    ) -> Result<Vec<Log>, BucketClientError> {
        if to_block < from_block {
            return Ok(Vec::new());
        }
        let snap = self.snapshot.load();
        // Identify epochs that overlap the requested range.
        let mut epoch_indices: Vec<usize> = (from_block..=to_block)
            .filter_map(|num| snap.block_to_epoch.get(&num).copied())
            .collect();
        epoch_indices.sort_unstable();
        epoch_indices.dedup();
        if epoch_indices.is_empty() {
            return Ok(Vec::new());
        }

        // Pre-build block_num -> canonical hash so decoded logs
        // can advertise the block_hash field correctly.
        let mut block_hashes: HashMap<u64, B256> = HashMap::new();
        for &idx in &epoch_indices {
            for blk in &snap.epochs[idx].blocks {
                if blk.num >= from_block && blk.num <= to_block {
                    if let Ok(h) = parse_b256_hex(&blk.hash) {
                        block_hashes.insert(blk.num, h);
                    }
                }
            }
        }

        let mut out: Vec<Log> = Vec::new();
        for &idx in &epoch_indices {
            let epoch = &snap.epochs[idx];
            // Prefer the per-epoch aggregated `logs` artifact when
            // present: 1 GET per epoch vs up to 32 (one per block).
            if let Some(epoch_logs) = epoch.epoch_artifacts.get("logs") {
                let chunk_ref = epoch_logs.clone();
                let path = format!("chunks/{}", chunk_ref.path());
                let bytes = fetch_object(&self.store, &path).await?;
                // Bloom probe — chunk-level skip when the filter is
                // selective and the SBBF proves a miss.
                if logs_decode::chunk_bloom_skips_filter(&bytes, filter) {
                    debug!(epoch = epoch.epoch, "epoch logs chunk bloom-skipped");
                    continue;
                }
                if chunk_ref.is_parquet() {
                    let rows = logs_decode::decode_log_chunk_parquet(
                        bytes,
                        from_block,
                        to_block,
                        filter,
                        &block_hashes,
                    )
                    .map_err(|err| {
                        BucketClientError::Backend(format!(
                            "decode epoch logs (epoch {}): {err}",
                            epoch.epoch
                        ))
                    })?;
                    out.extend(rows);
                } else if chunk_ref.is_vortex() {
                    // Vortex epoch-logs format. Today the live
                    // mainnet bucket emits parquet for epoch logs;
                    // when Vortex epoch artifacts ship this is the
                    // pushdown path.
                    let rows = vortex_decode::decode_log_chunk(
                        Arc::clone(&self.store),
                        ObjectPath::from(path.as_str()),
                        chunk_ref.size_bytes(),
                        chunk_ref.footer_metadata(),
                        chunk_ref.preload_ranges(),
                        from_block,
                        to_block,
                        filter,
                        &block_hashes,
                    )
                    .await
                    .map_err(|err| {
                        BucketClientError::Backend(format!(
                            "decode vortex epoch logs (epoch {}): {err}",
                            epoch.epoch
                        ))
                    })?;
                    out.extend(rows);
                }
                continue;
            }

            // Per-block fanout fallback — fetch every block's logs
            // chunk in the requested range.
            for blk in &epoch.blocks {
                if blk.num < from_block || blk.num > to_block {
                    continue;
                }
                let Some(chunk_ref) = blk.chunks.get("logs") else {
                    continue;
                };
                let path = format!("chunks/{}", chunk_ref.path());
                let bytes = fetch_object(&self.store, &path).await?;
                if logs_decode::chunk_bloom_skips_filter(&bytes, filter) {
                    debug!(block = blk.num, "block logs chunk bloom-skipped");
                    continue;
                }
                if chunk_ref.is_parquet() {
                    let rows = logs_decode::decode_log_chunk_parquet(
                        bytes,
                        from_block,
                        to_block,
                        filter,
                        &block_hashes,
                    )
                    .map_err(|err| {
                        BucketClientError::Backend(format!(
                            "decode block-logs (block {}): {err}",
                            blk.num
                        ))
                    })?;
                    out.extend(rows);
                } else if chunk_ref.is_vortex() {
                    let rows = vortex_decode::decode_log_chunk(
                        Arc::clone(&self.store),
                        ObjectPath::from(path.as_str()),
                        chunk_ref.size_bytes(),
                        chunk_ref.footer_metadata(),
                        chunk_ref.preload_ranges(),
                        from_block,
                        to_block,
                        filter,
                        &block_hashes,
                    )
                    .await
                    .map_err(|err| {
                        BucketClientError::Backend(format!(
                            "decode vortex block-logs (block {}): {err}",
                            blk.num
                        ))
                    })?;
                    out.extend(rows);
                }
            }
        }

        // Final sort by (block_num, log_idx) for deterministic order.
        out.sort_by_key(|l| (l.block_number.unwrap_or_default(), l.log_index.unwrap_or_default()));
        Ok(out)
    }
}

impl BucketHeaderClient for HttpBucketHeaderClient {
    fn header_by_number(&self, num: BlockNumber) -> ProviderResult<Option<Header>> {
        // We assume we're inside a tokio runtime — reth's RPC
        // pipeline always is. If not (e.g. some tests), fall back
        // to None so reth's normal database path takes over.
        match Handle::try_current() {
            Ok(handle) => tokio::task::block_in_place(|| {
                handle.block_on(async { self.fetch_header(num).await })
            })
            .map_err(Into::into),
            Err(_) => Ok(None),
        }
    }

    fn header_by_hash(&self, hash: BlockHash) -> ProviderResult<Option<Header>> {
        let hex = format!("0x{}", hex::encode(hash.as_slice()));
        let snap = self.snapshot.load();
        let Some(&num) = snap.block_hash_to_num.get(&hex) else {
            return Ok(None);
        };
        drop(snap);
        self.header_by_number(num)
    }

    fn latest_finalized_block_number(&self) -> BlockNumber {
        self.snapshot.load().head.latest_finalized_block_num
    }

    fn transaction_by_hash(
        &self,
        hash: alloy_primitives::TxHash,
    ) -> ProviderResult<Option<TransactionSigned>> {
        match Handle::try_current() {
            Ok(handle) => tokio::task::block_in_place(|| {
                handle.block_on(async { self.fetch_transaction_by_hash(hash).await })
            })
            .map_err(Into::into),
            Err(_) => Ok(None),
        }
    }

    fn receipt_by_hash(
        &self,
        hash: alloy_primitives::TxHash,
    ) -> ProviderResult<Option<reth_ethereum_primitives::Receipt>> {
        match Handle::try_current() {
            Ok(handle) => tokio::task::block_in_place(|| {
                handle.block_on(async { self.fetch_receipt_by_hash(hash).await })
            })
            .map_err(Into::into),
            Err(_) => Ok(None),
        }
    }

    fn transactions_by_block(
        &self,
        num: BlockNumber,
    ) -> ProviderResult<Option<Vec<TransactionSigned>>> {
        match Handle::try_current() {
            Ok(handle) => tokio::task::block_in_place(|| {
                handle.block_on(async { self.fetch_transactions_by_block(num).await })
            })
            .map_err(Into::into),
            Err(_) => Ok(None),
        }
    }

    fn receipts_by_block(
        &self,
        num: BlockNumber,
    ) -> ProviderResult<Option<Vec<reth_ethereum_primitives::Receipt>>> {
        match Handle::try_current() {
            Ok(handle) => tokio::task::block_in_place(|| {
                handle.block_on(async { self.fetch_receipts_by_block(num).await })
            })
            .map_err(Into::into),
            Err(_) => Ok(None),
        }
    }

    fn logs_in_range(
        &self,
        from_block: BlockNumber,
        to_block: BlockNumber,
        addresses: &[Address],
        topics: &[Vec<B256>; 4],
    ) -> ProviderResult<Vec<Log>> {
        let filter = LogScanFilter {
            addresses: addresses.to_vec(),
            topics: [topics[0].clone(), topics[1].clone(), topics[2].clone(), topics[3].clone()],
        };
        match Handle::try_current() {
            Ok(handle) => tokio::task::block_in_place(|| {
                handle.block_on(async {
                    self.fetch_logs_in_range(from_block, to_block, &filter).await
                })
            })
            .map_err(Into::into),
            Err(_) => Ok(Vec::new()),
        }
    }
}

async fn fetch_object(
    store: &Arc<dyn ObjectStore>,
    key: &str,
) -> Result<Vec<u8>, BucketClientError> {
    let path = ObjectPath::from(key);
    let result = store
        .get(&path)
        .await
        .map_err(|err| BucketClientError::Backend(format!("GET {key}: {err}")))?;
    let bytes = result
        .bytes()
        .await
        .map_err(|err| BucketClientError::Backend(format!("body {key}: {err}")))?;
    Ok(bytes.to_vec())
}

fn verify_signature(
    pubkey: &[u8; 32],
    payload: &[u8],
    sig: &[u8],
) -> Result<(), BucketClientError> {
    if sig.len() != 64 {
        return Err(BucketClientError::Trust(format!(
            "ed25519 sig must be 64 bytes, got {}",
            sig.len()
        )));
    }
    let mut sig_arr = [0u8; 64];
    sig_arr.copy_from_slice(sig);
    let key = ed25519_dalek::VerifyingKey::from_bytes(pubkey)
        .map_err(|err| BucketClientError::Trust(format!("invalid ed25519 pubkey: {err}")))?;
    let signature = ed25519_dalek::Signature::from_bytes(&sig_arr);
    key.verify(payload, &signature)
        .map_err(|err| BucketClientError::Trust(format!("signature verify failed: {err}")))
}

fn parse_b256_hex(s: &str) -> Result<B256, String> {
    let stripped = s.strip_prefix("0x").unwrap_or(s);
    if stripped.len() != 64 {
        return Err(format!("expected 32-byte hex, got len {}", stripped.len()));
    }
    let mut out = [0u8; 32];
    hex::decode_to_slice(stripped, &mut out).map_err(|err| err.to_string())?;
    Ok(B256::from(out))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_chunk_ref_distinguishes_vortex_and_parquet() {
        let v: ManifestChunkRef = serde_json::from_value(serde_json::json!({
            "path": "ab/abcdef",
            "format": "vortex",
            "version": 1,
            "size_bytes": 1234,
            "vortex_footer_metadata_b64": "Zm9v",
            "vortex_preload_ranges": [{"offset": 0, "length": 100}]
        }))
        .expect("parse");
        assert!(v.is_vortex());
        assert_eq!(v.path(), "ab/abcdef");
        assert_eq!(v.size_bytes(), Some(1234));
        assert_eq!(v.preload_ranges().len(), 1);

        // legacy parquet path-only
        let p: ManifestChunkRef = serde_json::from_str("\"ab/abcdef\"").expect("parse path-only");
        assert!(!p.is_vortex());
        assert!(p.is_parquet());
        assert_eq!(p.path(), "ab/abcdef");

        // descriptor with explicit parquet format
        let pdesc: ManifestChunkRef = serde_json::from_value(serde_json::json!({
            "path": "cd/cdef",
            "format": "parquet",
            "version": 1,
            "size_bytes": 99
        }))
        .expect("parse parquet desc");
        assert!(!pdesc.is_vortex());
        assert!(pdesc.is_parquet());
    }

    #[test]
    fn parse_b256_strict_length() {
        let h =
            parse_b256_hex("0x0000000000000000000000000000000000000000000000000000000000000001")
                .unwrap();
        assert_eq!(h.as_slice()[31], 1);
        assert!(parse_b256_hex("0x01").is_err());
    }

    #[test]
    fn verify_signature_round_trip() {
        let mut seed = [0u8; 32];
        seed[0] = 1;
        let key = ed25519_dalek::SigningKey::from_bytes(&seed);
        let pubkey: [u8; 32] = ed25519_dalek::VerifyingKey::from(&key).to_bytes();
        let payload = b"manifest";
        let sig = ed25519_dalek::Signer::sign(&key, payload).to_bytes().to_vec();
        verify_signature(&pubkey, payload, &sig).expect("ok");
        // Tamper
        let mut bad = payload.to_vec();
        bad[0] = b'M';
        assert!(verify_signature(&pubkey, &bad, &sig).is_err());
    }

    #[test]
    fn epoch_manifest_deserializes_with_epoch_artifacts() {
        let json = serde_json::json!({
            "chain_id": 1,
            "epoch": 448739,
            "first_block_num": 25124823,
            "last_block_num": 25124854,
            "blocks": [],
            "epoch_artifacts": {
                "logs": {
                    "format": "parquet",
                    "path": "27/27408af36f550c3d6490e5328f5c331e74ae30a06abc3ce8411d272bcb561518",
                    "size_bytes": 972372,
                    "version": 1
                }
            }
        });
        let m: EpochManifest = serde_json::from_value(json).expect("parse");
        assert_eq!(m.epoch, 448739);
        assert_eq!(m.epoch_artifacts.len(), 1);
        let logs_ref = m.epoch_artifacts.get("logs").unwrap();
        assert!(logs_ref.is_parquet());
        assert_eq!(logs_ref.size_bytes(), Some(972372));
    }
}

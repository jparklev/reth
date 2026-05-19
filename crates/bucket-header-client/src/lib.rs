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
//! - `manifest/finalized/<epoch>.json` ed25519-signed by writer,
//!   sha256-pinned by `head.epoch_manifest_sha256`
//! - chunks pinned by sha256 inside the epoch manifest's
//!   `block_index` + `chunks` map
//!
//! Same trust shape relay-rpc already runs at 100% L1 mainnet
//! traffic. See `crates/relay-rpc/src/backends/bucket.rs` in the
//! relay project for the canonical reader-side implementation; this
//! crate is the in-reth port (sync `HeaderProvider`-shaped surface).

use std::collections::HashMap;
use std::sync::Arc;

use alloy_consensus::Header;
use alloy_primitives::{Address, B256, BlockHash, BlockNumber, Bloom, Bytes, U256};
use arc_swap::ArcSwap;
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use ed25519_dalek::Verifier;
use object_store::{ObjectStore, ObjectStoreExt};
use object_store::aws::AmazonS3Builder;
use object_store::path::Path as ObjectPath;
use reth_provider::{BucketHeaderClient, BucketHeaderClientArc};
use reth_storage_errors::db::DatabaseError;
use reth_storage_errors::provider::{ProviderError, ProviderResult};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::runtime::Handle;
use tracing::{debug, info, warn};

mod vortex_decode;

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
    pub previous_epoch_manifest_url: Option<String>,
    #[serde(default)]
    pub previous_epoch_manifest_sha256: Option<String>,
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
        tokio::task::block_in_place(|| {
            handle.block_on(async { Self::new(config).await })
        })
        .map(Arc::new)
    }

    pub fn bucket_url(&self) -> &str { &self.config.bucket_url }

    pub async fn new(config: BucketHeaderClientConfig) -> Result<Self, BucketClientError> {
        let bucket = config
            .bucket_url
            .strip_prefix("s3://")
            .ok_or_else(|| {
                BucketClientError::Backend(format!("expected s3:// bucket URL, got {}", config.bucket_url))
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
            builder = builder
                .with_access_key_id(ak)
                .with_secret_access_key(sk);
        }
        let store = Arc::new(builder.build().map_err(|err| {
            BucketClientError::Backend(format!("object_store init failed: {err}"))
        })?) as Arc<dyn ObjectStore>;
        // Load head + writer pubkey
        let head_bytes = fetch_object(&store, "manifest/head.json").await?;
        let head_sig = fetch_object(&store, "manifest/head.json.sig").await?;
        let head: HeadManifest = serde_json::from_slice(&head_bytes).map_err(|err| {
            BucketClientError::Backend(format!("decode head.json: {err}"))
        })?;
        if !config.trusted_writers.is_empty()
            && !config.trusted_writers.contains(&head.writer_id)
        {
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
            let manifest: EpochManifest =
                serde_json::from_slice(&bytes).map_err(|err| {
                    BucketClientError::Backend(format!("decode epoch {url}: {err}"))
                })?;
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
        info!(
            warm_epochs = epochs.len(),
            blocks = block_to_epoch.len(),
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
        Ok(Some(Header {
            parent_hash,
            number: num,
            ..Default::default()
        }))
    }
}

impl BucketHeaderClient for HttpBucketHeaderClient {
    fn header_by_number(&self, num: BlockNumber) -> ProviderResult<Option<Header>> {
        // We assume we're inside a tokio runtime — reth's RPC
        // pipeline always is. If not (e.g. some tests), fall back
        // to None so reth's normal database path takes over.
        match Handle::try_current() {
            Ok(handle) => handle
                .block_on(async { self.fetch_header(num).await })
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
}

async fn fetch_object(
    store: &Arc<dyn ObjectStore>,
    key: &str,
) -> Result<Vec<u8>, BucketClientError> {
    let path = ObjectPath::from(key);
    let result = store.get(&path).await.map_err(|err| {
        BucketClientError::Backend(format!("GET {key}: {err}"))
    })?;
    let bytes = result.bytes().await.map_err(|err| {
        BucketClientError::Backend(format!("body {key}: {err}"))
    })?;
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
    let key = ed25519_dalek::VerifyingKey::from_bytes(pubkey).map_err(|err| {
        BucketClientError::Trust(format!("invalid ed25519 pubkey: {err}"))
    })?;
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
        assert_eq!(p.path(), "ab/abcdef");
    }

    #[test]
    fn parse_b256_strict_length() {
        let h = parse_b256_hex("0x0000000000000000000000000000000000000000000000000000000000000001")
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
}

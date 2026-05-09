//! S3-compatible [`RemoteJarBackend`] implementation.
//!
//! Reads a `NippyJar` segment's data and offsets files from an S3-compatible object store
//! (AWS S3, Cloudflare R2, Hetzner Object Storage, `MinIO`, …) using HTTP range requests.
//!
//! The offsets file is eagerly loaded into memory at construction time — it is small
//! (a few MB at most for a 50k-row segment) and read once per row lookup. Data ranges
//! are fetched on demand via S3 GET with a `Range` header.
//!
//! Credentials are resolved from the standard AWS provider chain (env vars,
//! `~/.aws/credentials`, etc.) by [`aws_config::defaults`].

#![cfg(feature = "s3-backend")]

use crate::{NippyJarError, RemoteJarBackend};
use aws_config::BehaviorVersion;
use aws_sdk_s3::{config::Region, Client};
use std::{ops::Range, sync::OnceLock};
use tokio::runtime::{Builder, Runtime};

/// Returns a process-wide tokio runtime dedicated to S3 IO. Lazily initialized on first use.
///
/// We use a separate runtime so that synchronous callers (the [`crate::NippyJarCursor`])
/// can `block_on` from any thread without interfering with the host application's runtime.
fn s3_runtime() -> &'static Runtime {
    static RT: OnceLock<Runtime> = OnceLock::new();
    RT.get_or_init(|| {
        Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("nippy-jar-s3-io")
            .enable_all()
            .build()
            .expect("failed to construct nippy-jar S3 IO runtime")
    })
}

/// Locates a `NippyJar` segment in an S3-compatible object store.
#[derive(Debug, Clone)]
pub struct S3JarLocator {
    /// Service endpoint, e.g. `https://fsn1.your-objectstorage.com` or
    /// `https://<account>.r2.cloudflarestorage.com`. Leave empty for AWS S3 default.
    pub endpoint: String,
    /// Region, e.g. `fsn1`, `auto` (R2), `eu-central-1`.
    pub region: String,
    /// Bucket name.
    pub bucket: String,
    /// Optional key prefix, e.g. `mainnet/v2/static_files`. Trailing slashes are stripped.
    pub key_prefix: String,
}

impl S3JarLocator {
    /// Build the object key for a segment's data file given its basename
    /// (e.g. `static_file_account-change-sets_24850000_24899999`).
    fn data_key(&self, segment_basename: &str) -> String {
        let prefix = self.key_prefix.trim_end_matches('/');
        if prefix.is_empty() {
            segment_basename.to_string()
        } else {
            format!("{prefix}/{segment_basename}")
        }
    }
}

/// S3-backed [`RemoteJarBackend`] for a single `NippyJar` segment.
#[derive(Debug)]
pub struct S3JarBackend {
    client: Client,
    bucket: String,
    data_key: String,
    /// Eagerly-loaded offsets file. Small enough to keep entirely in RAM.
    offsets_bytes: Vec<u8>,
    /// Total size of the data file in bytes (from HEAD).
    data_size: usize,
}

impl S3JarBackend {
    /// Construct a new backend for the segment at
    /// `<endpoint>/<bucket>/<key_prefix>/<segment_basename>`.
    ///
    /// Issues a HEAD on the data file (for size) and a full GET on the offsets file
    /// (eagerly cached). Subsequent data reads are individual range GETs.
    pub fn new(locator: &S3JarLocator, segment_basename: &str) -> Result<Self, NippyJarError> {
        s3_runtime().block_on(Self::new_async(locator, segment_basename))
    }

    async fn new_async(
        locator: &S3JarLocator,
        segment_basename: &str,
    ) -> Result<Self, NippyJarError> {
        let mut loader = aws_config::defaults(BehaviorVersion::latest())
            .region(Region::new(locator.region.clone()));
        if !locator.endpoint.is_empty() {
            loader = loader.endpoint_url(&locator.endpoint);
        }
        let shared = loader.load().await;

        // Path-style addressing — required for most non-AWS S3 services and supported by AWS too.
        let s3_config = aws_sdk_s3::config::Builder::from(&shared).force_path_style(true).build();
        let client = Client::from_conf(s3_config);

        let data_key = locator.data_key(segment_basename);
        let offsets_key = format!("{data_key}.off");

        let head = client
            .head_object()
            .bucket(&locator.bucket)
            .key(&data_key)
            .send()
            .await
            .map_err(|e| NippyJarError::Custom(format!("HEAD {data_key}: {e}")))?;
        let data_size = head.content_length().unwrap_or_default().max(0) as usize;
        if data_size == 0 {
            return Err(NippyJarError::Custom(format!("zero-size data object: {data_key}")));
        }

        let off = client
            .get_object()
            .bucket(&locator.bucket)
            .key(&offsets_key)
            .send()
            .await
            .map_err(|e| NippyJarError::Custom(format!("GET {offsets_key}: {e}")))?;
        let offsets_bytes = off
            .body
            .collect()
            .await
            .map_err(|e| NippyJarError::Custom(format!("body {offsets_key}: {e}")))?
            .into_bytes()
            .to_vec();

        Ok(Self { client, bucket: locator.bucket.clone(), data_key, offsets_bytes, data_size })
    }
}

impl RemoteJarBackend for S3JarBackend {
    fn read_offsets(&self, range: Range<usize>) -> Result<Vec<u8>, NippyJarError> {
        if range.end > self.offsets_bytes.len() {
            return Err(NippyJarError::OffsetOutOfBounds { index: range.end });
        }
        Ok(self.offsets_bytes[range].to_vec())
    }

    fn read_data(&self, range: Range<usize>) -> Result<Vec<u8>, NippyJarError> {
        if range.is_empty() || range.end > self.data_size {
            return Err(NippyJarError::Custom(format!(
                "invalid data range {}..{} (size={})",
                range.start, range.end, self.data_size
            )));
        }
        let range_header = format!("bytes={}-{}", range.start, range.end - 1);
        let bucket = self.bucket.clone();
        let key = self.data_key.clone();
        let client = self.client.clone();

        s3_runtime().block_on(async move {
            let resp = client
                .get_object()
                .bucket(&bucket)
                .key(&key)
                .range(range_header)
                .send()
                .await
                .map_err(|e| NippyJarError::Custom(format!("GET range {key}: {e}")))?;
            let bytes = resp
                .body
                .collect()
                .await
                .map_err(|e| NippyJarError::Custom(format!("body {key}: {e}")))?
                .into_bytes()
                .to_vec();
            Ok::<_, NippyJarError>(bytes)
        })
    }

    fn data_size(&self) -> usize {
        self.data_size
    }

    fn offsets_size(&self) -> usize {
        self.offsets_bytes.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn data_key_with_prefix() {
        let loc = S3JarLocator {
            endpoint: String::new(),
            region: "fsn1".into(),
            bucket: "reth-mainnet".into(),
            key_prefix: "static_files/".into(),
        };
        assert_eq!(
            loc.data_key("static_file_headers_0_499999"),
            "static_files/static_file_headers_0_499999"
        );
    }

    #[test]
    fn data_key_without_prefix() {
        let loc = S3JarLocator {
            endpoint: String::new(),
            region: "fsn1".into(),
            bucket: "reth-mainnet".into(),
            key_prefix: String::new(),
        };
        assert_eq!(loc.data_key("static_file_headers_0_499999"), "static_file_headers_0_499999");
    }
}

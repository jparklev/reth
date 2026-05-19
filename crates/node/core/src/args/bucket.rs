//! Phase 26.x — CLI args for bucket-mode header reads.
//!
//! Adds `--bucket-url`, `--bucket-endpoint`, `--bucket-region`,
//! `--bucket-anonymous`, `--bucket-trusted-writers` to the node
//! command. When `--bucket-url` is set, the engine launch path
//! constructs a `BucketHeaderClient` and attaches it to the
//! `BlockchainProvider` via `.with_bucket(...)`. Header reads then
//! consult the bucket first; everything else continues to hit
//! MDBX / static_files normally.

use clap::Args;

#[derive(Debug, Clone, Default, Args, serde::Serialize, serde::Deserialize)]
pub struct BucketArgs {
    /// S3-style bucket URL (e.g. `s3://reth-spike-fsn1`). When set,
    /// the node enables bucket-mode header reads: a signed-manifest
    /// chain is loaded from the bucket and consulted before
    /// MDBX/static_files for `HeaderProvider` queries.
    #[arg(long, value_name = "S3_URL", help_heading = "Bucket")]
    pub bucket_url: Option<String>,

    /// HTTPS endpoint for the S3 API.
    /// E.g. `https://fsn1.your-objectstorage.com` for Hetzner,
    /// `https://s3.us-east-1.amazonaws.com` for AWS.
    /// Required when `--bucket-url` is set.
    #[arg(long, value_name = "URL", help_heading = "Bucket")]
    pub bucket_endpoint: Option<String>,

    /// S3 region. Many object stores ignore this; pass `auto` if
    /// unsure. Required when `--bucket-url` is set.
    #[arg(long, value_name = "REGION", default_value = "auto", help_heading = "Bucket")]
    pub bucket_region: String,

    /// Read the bucket anonymously (no signing). The relay project's
    /// production bucket allows this; AWS S3 typically does not
    /// unless the bucket has a public-read policy.
    #[arg(long, help_heading = "Bucket")]
    pub bucket_anonymous: bool,

    /// Comma-separated list of trusted writer IDs (`primary`,
    /// `primary,secondary`, ...). Defaults to `primary`.
    /// Empty disables the trust check (insecure — accepts any
    /// signature-valid writer).
    #[arg(long, value_name = "IDS", default_value = "primary", help_heading = "Bucket")]
    pub bucket_trusted_writers: String,

    /// Number of epoch manifests to keep warm in the in-process
    /// snapshot. More = more recent history visible without a
    /// refresh, but slower startup. Default 8 (~50 minutes of
    /// mainnet at 32-block CL epoch cadence).
    #[arg(long, value_name = "N", default_value_t = 8u32, help_heading = "Bucket")]
    pub bucket_warm_epochs: u32,

    /// Phase 26.x - enable bucket-mode plain-state reads.
    /// When set (along with --bucket-url), the node fetches the
    /// latest Phase 26.2 checkpoint from `<bucket>/<state-prefix>/index.json`,
    /// hydrates it into an in-memory plain-state map, applies Phase 26.1
    /// epoch deltas forward, and serves account/storage/bytecode reads
    /// from the in-memory state before falling back to MDBX.
    #[arg(long, help_heading = "Bucket")]
    pub bucket_state_enabled: bool,

    /// Bucket prefix where Phase 26.2 checkpoints live. Default
    /// `checkpoints` (the Phase 26.2 writer default).
    #[arg(long, value_name = "PREFIX", default_value = "checkpoints", help_heading = "Bucket")]
    pub bucket_state_prefix: String,
}

impl BucketArgs {
    /// True when `--bucket-url` was passed; the rest of the args
    /// are only meaningful in that case.
    pub fn is_enabled(&self) -> bool {
        self.bucket_url.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[derive(Parser, Debug)]
    struct Wrapper {
        #[command(flatten)]
        bucket: BucketArgs,
    }

    #[test]
    fn parses_minimum_flags() {
        let w = Wrapper::try_parse_from([
            "reth",
            "--bucket-url",
            "s3://reth-spike-fsn1",
            "--bucket-endpoint",
            "https://fsn1.your-objectstorage.com",
        ])
        .expect("parse");
        assert!(w.bucket.is_enabled());
        assert_eq!(w.bucket.bucket_url.as_deref(), Some("s3://reth-spike-fsn1"));
        assert_eq!(w.bucket.bucket_region, "auto");
        assert!(!w.bucket.bucket_anonymous);
        assert_eq!(w.bucket.bucket_trusted_writers, "primary");
        assert_eq!(w.bucket.bucket_warm_epochs, 8);
    }

    #[test]
    fn defaults_when_no_bucket_url() {
        let w = Wrapper::try_parse_from(["reth"]).expect("parse no flags");
        assert!(!w.bucket.is_enabled());
        assert!(w.bucket.bucket_url.is_none());
    }

    #[test]
    fn parses_anonymous_flag() {
        let w = Wrapper::try_parse_from([
            "reth",
            "--bucket-url",
            "s3://x",
            "--bucket-endpoint",
            "https://example.com",
            "--bucket-anonymous",
            "--bucket-trusted-writers",
            "primary,backup",
            "--bucket-warm-epochs",
            "32",
        ])
        .expect("parse anonymous");
        assert!(w.bucket.bucket_anonymous);
        assert_eq!(w.bucket.bucket_trusted_writers, "primary,backup");
        assert_eq!(w.bucket.bucket_warm_epochs, 32);
    }
}

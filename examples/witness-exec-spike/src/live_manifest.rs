//! `head.json` manifest schema published by `witness-publisher` and consumed by
//! `witness-stream` / `witness-validator`.
//!
//! Layout in the bucket:
//! ```text
//! witnesses/live/head.json              # JSON: most recent N entries (default 256)
//! witnesses/live/head.json.sig          # raw 64-byte ed25519 signature over head.json
//! witnesses/live/<num>-<hash>.witness.zst
//! witnesses/live/<num>-<hash>.witness.zst.sig
//! ```
//!
//! The manifest is replaced atomically (PUT) on each successful upload, ordered
//! newest-first. Stale readers fall back to fetching by `block_number-block_hash`
//! prefix listing if `head.json` is too far behind.

use alloy_primitives::B256;
use serde::{Deserialize, Serialize};

/// Keep this many recent entries in `head.json`. ~256 covers ~50 min at 12s blocks.
#[allow(dead_code)] // publisher only
pub(crate) const MAX_ENTRIES: usize = 256;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub(crate) struct LiveManifest {
    /// Schema version.
    pub(crate) version: u32,
    /// Writer ID; matches `writer-keys/<id>.pub` in the bucket. Convenience
    /// for readers picking the right pubkey.
    pub(crate) writer_id: String,
    /// ISO-8601 timestamp of the most recent update.
    pub(crate) updated_at: String,
    /// Latest canonical entry (= entries.first(), copied for cheap reads).
    pub(crate) head: Option<ManifestEntry>,
    /// Newest-first list of canonical witnesses still considered live.
    /// Orphaned entries (reorg-evicted) are omitted on the next update.
    pub(crate) entries: Vec<ManifestEntry>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub(crate) struct ManifestEntry {
    pub(crate) block_number: u64,
    pub(crate) block_hash: B256,
    pub(crate) parent_hash: B256,
    /// S3 object key, e.g. `witnesses/live/25145800-0xabc...witness.zst`.
    pub(crate) object_key: String,
    /// Hex sha256 of the *compressed* witness blob bytes (the bytes that were
    /// signed and uploaded). Reader can integrity-check before signature verify.
    pub(crate) content_sha256: String,
    /// ISO-8601 timestamp of signing/upload.
    pub(crate) signed_at: String,
    /// Size of the witness object in bytes.
    pub(crate) size_bytes: u64,
}

#[allow(dead_code)] // publisher only
impl LiveManifest {
    /// Empty manifest under a writer id.
    pub(crate) fn empty(writer_id: impl Into<String>) -> Self {
        Self {
            version: 1,
            writer_id: writer_id.into(),
            updated_at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            head: None,
            entries: Vec::new(),
        }
    }

    /// Push a new entry to the front and truncate to [`MAX_ENTRIES`].
    /// Any existing entries with the same `block_number` are removed (reorg
    /// replacement) — this also implicitly orphans witnesses on the abandoned
    /// fork: they remain in S3 but stop being advertised.
    pub(crate) fn push_front(&mut self, entry: ManifestEntry) {
        self.entries.retain(|e| e.block_number != entry.block_number);
        self.entries.insert(0, entry.clone());
        self.entries.truncate(MAX_ENTRIES);
        self.head = Some(entry);
        self.updated_at = chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    }

    /// On a deeper reorg, drop every entry strictly above `block_number`. Used
    /// when the publisher sees a new head whose number is `<=` last published
    /// number and parent_hash doesn't match (i.e. they're on a different fork).
    pub(crate) fn rewind_above(&mut self, block_number: u64) {
        self.entries.retain(|e| e.block_number <= block_number);
        self.head = self.entries.first().cloned();
    }
}

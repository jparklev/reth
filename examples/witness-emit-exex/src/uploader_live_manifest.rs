//! `head.json` manifest schema published by `witness-uploader`. Same shape as
//! the sidecar `witness-publisher` so existing readers don't need to change.

use alloy_primitives::B256;
use serde::{Deserialize, Serialize};

pub(crate) const MAX_ENTRIES: usize = 256;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub(crate) struct LiveManifest {
    pub(crate) version: u32,
    pub(crate) writer_id: String,
    pub(crate) updated_at: String,
    pub(crate) head: Option<ManifestEntry>,
    pub(crate) entries: Vec<ManifestEntry>,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub(crate) struct ManifestEntry {
    pub(crate) block_number: u64,
    pub(crate) block_hash: B256,
    pub(crate) parent_hash: B256,
    pub(crate) object_key: String,
    pub(crate) content_sha256: String,
    pub(crate) signed_at: String,
    pub(crate) size_bytes: u64,
}

impl LiveManifest {
    pub(crate) fn empty(writer_id: impl Into<String>) -> Self {
        Self {
            version: 1,
            writer_id: writer_id.into(),
            updated_at: chrono::Utc::now()
                .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            head: None,
            entries: Vec::new(),
        }
    }

    pub(crate) fn push_front(&mut self, entry: ManifestEntry) {
        self.entries.retain(|e| e.block_number != entry.block_number);
        self.entries.insert(0, entry.clone());
        self.entries.truncate(MAX_ENTRIES);
        self.head = Some(entry);
        self.updated_at =
            chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    }

    pub(crate) fn rewind_above(&mut self, block_number: u64) {
        self.entries.retain(|e| e.block_number <= block_number);
        self.head = self.entries.first().cloned();
        self.updated_at =
            chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    }
}

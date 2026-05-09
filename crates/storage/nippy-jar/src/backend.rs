//! Backend abstraction for [`crate::DataReader`].
//!
//! A jar's data and offsets bytes can be served either from local memory-mapped files
//! ([`Backend::Mmap`]) or from a remote source such as an S3-compatible object store
//! ([`Backend::Remote`]). The remote variant uses HTTP range reads via [`RemoteJarBackend`].

use crate::NippyJarError;
use memmap2::Mmap;
use std::{borrow::Cow, fmt::Debug, fs::File, ops::Range, sync::Arc};

/// Storage backend for a [`crate::DataReader`].
#[derive(Debug)]
pub(crate) enum Backend {
    /// Local memory-mapped data and offsets files.
    Mmap(MmapBackend),
    /// Remote backend (e.g. S3 range reads).
    Remote(Arc<dyn RemoteJarBackend>),
}

impl Backend {
    /// Read raw offsets-file bytes in the given range.
    pub(crate) fn offset_bytes(&self, range: Range<usize>) -> Result<Cow<'_, [u8]>, NippyJarError> {
        match self {
            Self::Mmap(b) => Ok(Cow::Borrowed(&b.offset_mmap[range])),
            Self::Remote(r) => Ok(Cow::Owned(r.read_offsets(range)?)),
        }
    }

    /// Read raw data-file bytes in the given range.
    pub(crate) fn data_bytes(&self, range: Range<usize>) -> Result<Cow<'_, [u8]>, NippyJarError> {
        match self {
            Self::Mmap(b) => Ok(Cow::Borrowed(&b.data_mmap[range])),
            Self::Remote(r) => Ok(Cow::Owned(r.read_data(range)?)),
        }
    }

    /// Length of the data file in bytes.
    pub(crate) fn data_len(&self) -> usize {
        match self {
            Self::Mmap(b) => b.data_mmap.len(),
            Self::Remote(r) => r.data_size(),
        }
    }

    /// Length of the offsets file in bytes.
    pub(crate) fn offsets_len(&self) -> usize {
        match self {
            Self::Mmap(b) => b.offset_mmap.len(),
            Self::Remote(r) => r.offsets_size(),
        }
    }
}

/// Local memory-mapped backend.
#[derive(Debug)]
pub(crate) struct MmapBackend {
    /// Data file descriptor. Kept alive as long as `data_mmap` is held.
    #[expect(dead_code)]
    pub(crate) data_file: File,
    pub(crate) data_mmap: Mmap,
    /// Offset file descriptor. Kept alive as long as `offset_mmap` is held.
    #[expect(dead_code)]
    pub(crate) offset_file: File,
    pub(crate) offset_mmap: Mmap,
}

/// Trait for backends that fetch jar data and offsets from a remote source
/// (e.g. an S3-compatible object store) using HTTP range reads.
///
/// Implementations are expected to:
/// - Eagerly load (or aggressively cache) the offsets file at construction time — it is small (a
///   few MB at most) and accessed once per row read.
/// - Issue HTTP range reads against the data file on demand, optionally backed by a local LRU cache
///   for hot ranges.
pub trait RemoteJarBackend: Debug + Send + Sync {
    /// Read bytes from the offsets file at the given byte range.
    fn read_offsets(&self, range: Range<usize>) -> Result<Vec<u8>, NippyJarError>;
    /// Read bytes from the data file at the given byte range.
    fn read_data(&self, range: Range<usize>) -> Result<Vec<u8>, NippyJarError>;
    /// Total size of the data file in bytes.
    fn data_size(&self) -> usize;
    /// Total size of the offsets file in bytes.
    fn offsets_size(&self) -> usize;
}

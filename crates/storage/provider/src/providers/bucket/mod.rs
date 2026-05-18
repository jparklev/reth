//! Phase 26.x — bucket-mode header reads.
//!
//! Provides a trait `BucketHeaderClient` that the relay project's
//! `thin-reth` crate (or any external implementer) satisfies, and a
//! `WithBucket<P>` provider wrapper that consults the bucket before
//! falling back to a wrapped reth provider for header queries.
//!
//! Why this is in reth-provider instead of as a wholly external
//! integration: reth's HeaderProvider trait shape (sync, takes
//! `&self`, generic `NodePrimitives`) is the cleanest seam for a
//! drop-in. Putting the trait declaration in reth makes the
//! reth-side plumbing — `BlockchainProvider`'s `Option<bucket>`
//! field, the `header_by_number` dispatch arm — buildable inside
//! the fork without a circular relay→reth dep.
//!
//! Why the **impl** is NOT here: a real bucket client pulls in
//! reqwest/object_store + an archive format reader (Parquet or
//! Vortex). Those are heavy deps to drag into `reth-provider`.
//! Instead, an impl lives outside reth (e.g. in relay's
//! `crates/thin-reth/`) and is constructed at startup, then handed
//! to `BlockchainProvider` as `Arc<dyn BucketHeaderClient>`.
//!
//! Spike scope: only `HeaderProvider`. `BlockReader`,
//! `TransactionsProvider`, and friends are the obvious follow-ups
//! and live in the same module when they ship.

use alloy_consensus::Header;
use alloy_primitives::{BlockHash, BlockNumber};
use reth_storage_errors::provider::ProviderResult;
use std::fmt::Debug;
use std::sync::Arc;

/// Sync, trait-object-friendly bucket client.
///
/// Implementers are responsible for:
/// - fetching `head.json` + epoch manifests over HTTP(S);
/// - verifying ed25519 signatures against trusted writer keys;
/// - fetching the chunk that contains a given block's header;
/// - decoding to `alloy_consensus::Header`.
///
/// The sync surface is deliberate: reth's `HeaderProvider` is sync
/// (`crates/storage/storage-api/src/header.rs:13`), so an
/// async impl must `block_on` internally. Async-trait-style
/// callers (the RPC pipeline) are already running inside a tokio
/// runtime when they enter the sync provider boundary, so
/// `tokio::runtime::Handle::current().block_on(...)` from within
/// the impl is safe.
pub trait BucketHeaderClient: Send + Sync + Debug {
    /// Return the header for `num`, or `Ok(None)` if the bucket
    /// snapshot doesn't cover that block.
    fn header_by_number(&self, num: BlockNumber) -> ProviderResult<Option<Header>>;

    /// Return the header for `hash`, or `Ok(None)`. Optional:
    /// implementers without a global hash index can return `None`
    /// and force fallback to the wrapped database provider.
    fn header_by_hash(&self, _hash: BlockHash) -> ProviderResult<Option<Header>> {
        Ok(None)
    }

    /// Best-known finalized block number per the bucket trust
    /// anchor. The dispatch wrapper uses this to short-circuit
    /// fallback when a query target is outside the bucket's
    /// coverage (no point asking the bucket first if it's
    /// guaranteed to miss).
    fn latest_finalized_block_number(&self) -> BlockNumber;
}

/// Convenience type alias used by `BlockchainProvider` when carrying
/// an optional bucket client.
pub type BucketHeaderClientArc = Arc<dyn BucketHeaderClient>;

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::Header;

    /// Sanity check: a trait object can be cloned via Arc, and the
    /// dispatch surface is usable from a sync context.
    #[derive(Debug)]
    struct MockClient {
        latest: BlockNumber,
        header: Header,
    }

    impl BucketHeaderClient for MockClient {
        fn header_by_number(&self, num: BlockNumber) -> ProviderResult<Option<Header>> {
            if num == self.header.number { Ok(Some(self.header.clone())) } else { Ok(None) }
        }
        fn latest_finalized_block_number(&self) -> BlockNumber {
            self.latest
        }
    }

    #[test]
    fn bucket_header_client_dispatches_to_known_number() {
        let mut header = Header::default();
        header.number = 25_120_500;
        let client: BucketHeaderClientArc =
            Arc::new(MockClient { latest: 25_120_500, header: header.clone() });

        // Hit
        let returned = client.header_by_number(25_120_500).unwrap().expect("header");
        assert_eq!(returned.number, 25_120_500);
        // Miss within coverage
        assert!(client.header_by_number(25_120_499).unwrap().is_none());
        // Default header_by_hash returns None
        assert!(client.header_by_hash(alloy_primitives::B256::ZERO).unwrap().is_none());
        // Coverage probe
        assert_eq!(client.latest_finalized_block_number(), 25_120_500);
    }

    /// Probe that the trait is dyn-compatible (object-safe). If
    /// someone refactors the trait into a generic-method shape the
    /// `Arc<dyn BucketHeaderClient>` line below would fail to
    /// compile and tell us immediately.
    #[test]
    fn bucket_header_client_is_dyn_compatible() {
        fn assert_dyn(_x: &dyn BucketHeaderClient) {}
        let mut header = Header::default();
        header.number = 1;
        let client = MockClient { latest: 1, header };
        assert_dyn(&client);
    }
}

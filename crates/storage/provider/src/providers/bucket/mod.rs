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
use alloy_primitives::{Address, BlockHash, BlockNumber, Bytes, TxHash, B256, U256};
use alloy_rpc_types_eth::Log;
use reth_ethereum_primitives::{Receipt, TransactionSigned};
use reth_primitives_traits::Account;
use reth_storage_errors::provider::ProviderResult;
use std::{fmt::Debug, sync::Arc};

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

    /// Get the transaction for `hash` from the bucket. Returns
    /// `Ok(None)` if the bucket doesn't cover the tx (e.g. the tx
    /// lives outside the warm-epochs window) — the dispatch site
    /// falls through to the database path on `None`.
    ///
    /// Default impl returns `Ok(None)` so older trait implementers
    /// don't have to support it; the production
    /// `HttpBucketHeaderClient` will override.
    ///
    /// Stage: spike (transaction_by_hash is the next item on the
    /// FULL-VORTEX-RETH-READ-NODE roadmap in
    /// `jparklev/relay@docs/FULL-VORTEX-RETH-READ-NODE.md`).
    fn transaction_by_hash(&self, _hash: TxHash) -> ProviderResult<Option<TransactionSigned>> {
        Ok(None)
    }

    /// Get the receipt for `tx_hash` from the bucket. `Ok(None)`
    /// when the bucket doesn't cover the tx — falls through to the
    /// database path.
    ///
    /// Default impl returns `Ok(None)`; the production
    /// `HttpBucketHeaderClient` overrides with a vortex_receipts +
    /// vortex_logs decode.
    fn receipt_by_hash(&self, _tx_hash: TxHash) -> ProviderResult<Option<Receipt>> {
        Ok(None)
    }

    /// Get all transactions in a finalized block. `Ok(None)` when
    /// the block isn't covered — falls through to the database
    /// path. Returns transactions sorted by `tx_idx`.
    ///
    /// Default impl returns `Ok(None)` so partial implementers
    /// remain valid.
    fn transactions_by_block(
        &self,
        _num: BlockNumber,
    ) -> ProviderResult<Option<Vec<TransactionSigned>>> {
        Ok(None)
    }

    /// Get all receipts in a finalized block. `Ok(None)` when not
    /// covered — falls through to the database path. Returns
    /// receipts sorted by `tx_idx`, each populated with its logs
    /// from the same block's `vortex_logs` chunk.
    fn receipts_by_block(&self, _num: BlockNumber) -> ProviderResult<Option<Vec<Receipt>>> {
        Ok(None)
    }

    /// Return all logs in the inclusive block range `from..=to`
    /// matching the given `addresses` allowlist (empty = any) and
    /// `topics` slot constraints (`topics[i]` empty = any). The
    /// bucket implementation is responsible for:
    /// - identifying the epochs the range spans;
    /// - probing per-chunk Bloom side-tables (Phase 22 sprint 3) to skip chunks that can't possibly
    ///   match;
    /// - pushing the filter down into the chunk decoder where the format supports it (Vortex
    ///   `with_filter`/`select`);
    /// - filtering remaining rows by block_num + filter predicate;
    /// - sorting by `(block_num, log_idx)` for deterministic output.
    ///
    /// Default impl returns `Ok(Vec::new())` so older implementers
    /// don't have to support it — the dispatch site falls back to
    /// the regular DB path.
    ///
    /// Stage: item 4 of the FULL-VORTEX-RETH-READ-NODE roadmap in
    /// `jparklev/relay@docs/FULL-VORTEX-RETH-READ-NODE.md`.
    fn logs_in_range(
        &self,
        _from_block: BlockNumber,
        _to_block: BlockNumber,
        _addresses: &[Address],
        _topics: &[Vec<B256>; 4],
    ) -> ProviderResult<Vec<Log>> {
        Ok(Vec::new())
    }
}

/// Convenience type alias used by `BlockchainProvider` when carrying
/// an optional bucket client.
pub type BucketHeaderClientArc = Arc<dyn BucketHeaderClient>;

/// Phase 26.x — bucket-backed plain-state reader.
///
/// Sibling to [`BucketHeaderClient`]: implementers hydrate the
/// canonical plain-state at a chosen finalized checkpoint, optionally
/// fast-forward by replaying signed epoch deltas, and serve point
/// reads from in-memory HashMaps.
///
/// The trait is `BucketHeaderClient`-extending so a single
/// implementation can advertise both surfaces and `BlockchainProvider`
/// can fall through cleanly when only the state side is wired.
///
/// Methods are sync to fit reth's [`StateProvider`] shape (also sync).
/// The async hydration happens up front at boot; the lookups are
/// HashMap reads.
///
/// `account_info` returns reth's [`Account`] (no bytecode body) — the
/// bytecode is fetched separately via `code_by_hash`. The dispatch
/// wrapper in `BlockchainProvider` glues these into a
/// [`reth_storage_api::StateProvider`].
pub trait BucketStateClient: BucketHeaderClient {
    /// Plain-state account read. Returns `Ok(None)` if the bucket
    /// doesn't cover the account at the pinned block (callers should
    /// fall back to MDBX). All-zero / `KECCAK_EMPTY` rows are treated
    /// as tombstones and surface as `Ok(None)`.
    fn account(&self, _addr: Address) -> ProviderResult<Option<Account>> {
        Ok(None)
    }

    /// Plain-state storage slot read. Returns `Ok(None)` when the
    /// slot was untouched at the pinned block (callers fall back).
    /// Zero values for slots that *were* touched are returned as
    /// `Ok(Some(U256::ZERO))` (the writer-side delta encoder treats
    /// `value=0` as "cleared", and the reader preserves that).
    fn storage(&self, _addr: Address, _slot: U256) -> ProviderResult<Option<U256>> {
        Ok(None)
    }

    /// Plain-state code read, content-addressed by `code_hash`.
    /// Returns `Ok(None)` when the bucket doesn't know the blob.
    fn code_by_hash(&self, _code_hash: B256) -> ProviderResult<Option<Bytes>> {
        Ok(None)
    }

    /// The block number this state client is pinned to (= the
    /// checkpoint's block_number plus all deltas applied forward).
    /// `BlockchainProvider` uses this as a coverage gate (no point
    /// asking the bucket for a future block's state).
    fn pinned_block_number(&self) -> BlockNumber {
        0
    }

    /// The block hash this state client is pinned to.
    /// `BlockchainProvider::maybe_wrap_with_bucket` gates the bucket
    /// overlay on `hint_block_hash == pinned_block_hash`, so historical
    /// state queries (block != pinned) fall through to MDBX directly
    /// instead of being answered with the pinned block's state.
    ///
    /// Defaults to `None` for trait impls that don't expose their
    /// pinned hash; in that case the wrap proceeds unconditionally
    /// (matching pre-gate behavior — useful for tests + the
    /// `latest()` path that doesn't have a hint yet).
    fn pinned_block_hash(&self) -> Option<BlockHash> {
        None
    }

    /// The full header for the pinned block. Used by `BlockchainProvider`'s
    /// header_by_hash / header_by_number dispatch + by the eth_call env
    /// builder so post-merge prevrandao (mix_hash), gas_limit, timestamp,
    /// etc. are populated for bucket-served blocks.
    fn pinned_header(&self) -> Option<Header> {
        None
    }
}

/// Convenience type alias for the optional bucket state client field
/// on `BlockchainProvider`.
pub type BucketStateClientArc = Arc<dyn BucketStateClient>;

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
            if num == self.header.number {
                Ok(Some(self.header.clone()))
            } else {
                Ok(None)
            }
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

    /// `BucketStateClient` must be dyn-compatible too; this catches
    /// regressions if someone adds a generic method later.
    #[test]
    fn bucket_state_client_is_dyn_compatible() {
        #[derive(Debug)]
        struct S;
        impl BucketHeaderClient for S {
            fn header_by_number(&self, _: BlockNumber) -> ProviderResult<Option<Header>> {
                Ok(None)
            }
            fn latest_finalized_block_number(&self) -> BlockNumber {
                0
            }
        }
        impl BucketStateClient for S {}
        fn assert_dyn(_x: &dyn BucketStateClient) {}
        assert_dyn(&S);
    }

    /// Default impls on the block-data surface (receipt_by_hash,
    /// transactions_by_block, receipts_by_block) must surface as
    /// `Ok(None)` so the dispatch site falls through cleanly when
    /// the implementer doesn't override them.
    #[test]
    fn bucket_header_client_block_defaults_return_none() {
        #[derive(Debug)]
        struct S;
        impl BucketHeaderClient for S {
            fn header_by_number(&self, _: BlockNumber) -> ProviderResult<Option<Header>> {
                Ok(None)
            }
            fn latest_finalized_block_number(&self) -> BlockNumber {
                0
            }
        }
        let s = S;
        assert!(s.transaction_by_hash(B256::ZERO).unwrap().is_none());
        assert!(s.receipt_by_hash(B256::ZERO).unwrap().is_none());
        assert!(s.transactions_by_block(0).unwrap().is_none());
        assert!(s.receipts_by_block(0).unwrap().is_none());
        // Default logs_in_range returns empty (back compat).
        let logs =
            s.logs_in_range(0, 1, &[], &[Vec::new(), Vec::new(), Vec::new(), Vec::new()]).unwrap();
        assert!(logs.is_empty());
    }

    /// Default impls on `BucketStateClient` should surface as `None`
    /// so a partial implementer is safe.
    #[test]
    fn bucket_state_client_defaults_return_none() {
        #[derive(Debug)]
        struct S;
        impl BucketHeaderClient for S {
            fn header_by_number(&self, _: BlockNumber) -> ProviderResult<Option<Header>> {
                Ok(None)
            }
            fn latest_finalized_block_number(&self) -> BlockNumber {
                0
            }
        }
        impl BucketStateClient for S {}
        let s = S;
        assert!(s.account(Address::ZERO).unwrap().is_none());
        assert!(s.storage(Address::ZERO, U256::ZERO).unwrap().is_none());
        assert!(s.code_by_hash(B256::ZERO).unwrap().is_none());
        assert_eq!(s.pinned_block_number(), 0);
    }
}

mod state_provider;
pub use state_provider::BucketStateProvider;

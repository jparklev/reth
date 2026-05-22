use alloy_consensus::BlockHeader;
use alloy_primitives::{BlockNumber, Sealable, B256};
use alloy_rlp::Decodable;
use reth_codecs::Compact;
use reth_db_api::{tables, transaction::DbTxMut};
use reth_node_builder::NodePrimitives;
use reth_primitives_traits::{SealedBlock, SealedHeader, SealedHeaderFor};
use reth_provider::{
    providers::StaticFileProvider, BlockWriter, DBProvider, ProviderError, ProviderResult,
    StageCheckpointWriter, StaticFileProviderFactory, StaticFileWriter,
};
use reth_stages::{StageCheckpoint, StageId};
use reth_static_file_types::StaticFileSegment;
use std::path::Path;
use tracing::info;

/// Reads the header RLP from a file and returns the Header.
///
/// This supports both raw rlp bytes and rlp hex string.
pub(crate) fn read_header_from_file<H>(path: &Path) -> Result<H, eyre::Error>
where
    H: Decodable,
{
    let buf = if let Ok(content) = reth_fs_util::read_to_string(path) {
        alloy_primitives::hex::decode(content.trim())?
    } else {
        // If UTF-8 decoding fails, read as raw bytes
        reth_fs_util::read(path)?
    };

    let header = H::decode(&mut &buf[..])?;
    Ok(header)
}

/// Creates a dummy chain (with no transactions) up to the last EVM block and appends the
/// first valid block.
///
/// When `pre_anchor_headers` is non-empty, the suffix of the dummy chain is replaced with
/// the supplied real headers. Each entry is `(header, hash)` where `hash == header.hash_slow()`,
/// numbers must be strictly increasing and contiguous, and the last header's number must equal
/// `anchor - 1` so that `anchor.parent_hash() == headers.last().1`. Validation is performed
/// before any static-file writes; on error the writers are not touched.
///
/// The real-header backfill exists so that post-anchor blocks executing `BLOCKHASH(N)` for
/// `anchor - 256 <= N < anchor` resolve to the actual mainnet hash. Without it the dummy
/// segment returns `B256::ZERO`, which `StateProviderDatabase::block_hash_ref` silently
/// coerces to a valid (but wrong) zero, causing the EVM to take the "block invalid" branch
/// and diverging from prod (see `docs/PATH-B-DIAGNOSIS-25143845.md`).
pub fn setup_without_evm<Provider, F>(
    provider_rw: &Provider,
    header: SealedHeader<<Provider::Primitives as NodePrimitives>::BlockHeader>,
    header_factory: F,
    pre_anchor_headers: Vec<(<Provider::Primitives as NodePrimitives>::BlockHeader, B256)>,
) -> ProviderResult<()>
where
    Provider: StaticFileProviderFactory
        + StageCheckpointWriter
        + DBProvider<Tx: DbTxMut>
        + BlockWriter<Block = <Provider::Primitives as NodePrimitives>::Block>,
    F: Fn(BlockNumber) -> <Provider::Primitives as NodePrimitives>::BlockHeader
        + Send
        + Sync
        + 'static,
{
    info!(
        target: "reth::cli",
        new_tip = ?header.num_hash(),
        pre_anchor_real_headers = pre_anchor_headers.len(),
        "Setting up dummy EVM chain before importing state."
    );

    validate_pre_anchor_headers(&header, &pre_anchor_headers)?;

    let static_file_provider = provider_rw.static_file_provider();
    // Write EVM dummy data up to `header - 1` block. Skip when the supplied
    // header is at block 0: `header.number() - 1` would underflow in u64 to
    // `u64::MAX`, sending `append_dummy_chain` into a 1..=u64::MAX loop that
    // exhausts memory before failing.
    if header.number() > 0 {
        // Clone the (number, hash) pairs so we can write HeaderNumbers entries
        // from the main thread after `append_dummy_chain` consumes the vec.
        let pre_anchor_index_rows: Vec<(BlockNumber, B256)> =
            pre_anchor_headers.iter().map(|(h, hash)| (h.number(), *hash)).collect();

        append_dummy_chain(
            &static_file_provider,
            header.number() - 1,
            header_factory,
            pre_anchor_headers,
        )?;

        // Backfill MDBX `HeaderNumbers` for the real pre-anchor blocks so that
        // `BlockNumberReader::block_number(hash)` resolves them. `insert_block`
        // (called by `append_first_block` below) is responsible for the anchor's
        // own `HeaderNumbers` row. `CanonicalHeaders` is not written: the active
        // `DatabaseProvider::block_hash` / `canonical_hashes_range` paths read
        // from static files (where the hashes now live correctly).
        let tx = provider_rw.tx_ref();
        for (number, hash) in &pre_anchor_index_rows {
            tx.put::<tables::HeaderNumbers>(*hash, *number)?;
        }
    }

    info!(target: "reth::cli", "Appending first valid block.");

    append_first_block(provider_rw, &header)?;

    for stage in StageId::ALL {
        provider_rw.save_stage_checkpoint(stage, StageCheckpoint::new(header.number()))?;
    }

    info!(target: "reth::cli", "Set up finished.");

    Ok(())
}

/// Strict validation for the optional pre-anchor header backfill. Fails before any
/// static-file or MDBX write so a malformed input cannot corrupt the datadir.
fn validate_pre_anchor_headers<H>(
    anchor: &SealedHeader<H>,
    headers: &[(H, B256)],
) -> ProviderResult<()>
where
    H: BlockHeader + Sealable + Compact,
{
    if headers.is_empty() {
        return Ok(());
    }

    let anchor_number = anchor.number();
    if anchor_number == 0 {
        return Err(ProviderError::other(std::io::Error::other(
            "pre_anchor_headers supplied for a genesis-block anchor",
        )));
    }
    let max_window = anchor_number.min(256) as usize;
    if headers.len() > max_window {
        return Err(ProviderError::other(std::io::Error::other(format!(
            "pre_anchor_headers len {} exceeds max window {} (anchor={})",
            headers.len(),
            max_window,
            anchor_number,
        ))));
    }

    let expected_start = anchor_number - headers.len() as u64;
    let mut prev_hash: Option<B256> = None;
    for (idx, (h, hash)) in headers.iter().enumerate() {
        let expected_number = expected_start + idx as u64;
        if h.number() != expected_number {
            return Err(ProviderError::other(std::io::Error::other(format!(
                "pre_anchor_headers[{idx}].number = {} but expected {expected_number}",
                h.number(),
            ))));
        }
        // Hash claim must be self-consistent.
        // Using `hash_slow` here is intentional: catches RPC-side corruption.
        if h.hash_slow() != *hash {
            return Err(ProviderError::other(std::io::Error::other(format!(
                "pre_anchor_headers[{idx}] hash mismatch: claimed {hash:?}, computed {:?}",
                h.hash_slow(),
            ))));
        }
        if let Some(prev) = prev_hash {
            if h.parent_hash() != prev {
                return Err(ProviderError::other(std::io::Error::other(format!(
                    "pre_anchor_headers[{idx}].parent_hash does not chain from previous entry",
                ))));
            }
        }
        prev_hash = Some(*hash);
    }

    let last_hash = prev_hash.expect("non-empty checked above");
    if anchor.parent_hash() != last_hash {
        return Err(ProviderError::other(std::io::Error::other(format!(
            "anchor.parent_hash {:?} does not match last pre_anchor hash {last_hash:?}",
            anchor.parent_hash(),
        ))));
    }

    Ok(())
}

/// Appends the first block.
///
/// By appending it, static file writer also verifies that all segments are at the same
/// height.
fn append_first_block<Provider>(
    provider_rw: &Provider,
    header: &SealedHeaderFor<Provider::Primitives>,
) -> ProviderResult<()>
where
    Provider: BlockWriter<Block = <Provider::Primitives as NodePrimitives>::Block>
        + StaticFileProviderFactory<Primitives: NodePrimitives<BlockHeader: Compact>>,
{
    provider_rw.insert_block(
        &SealedBlock::<<Provider::Primitives as NodePrimitives>::Block>::from_sealed_parts(
            header.clone(),
            Default::default(),
        )
        .try_recover()
        .expect("no senders or txes"),
    )?;

    let sf_provider = provider_rw.static_file_provider();

    sf_provider.latest_writer(StaticFileSegment::Receipts)?.increment_block(header.number())?;

    Ok(())
}

/// Creates a dummy chain with no transactions/receipts up to `target_height` block inclusive.
///
/// * Headers: It will push an empty block. When `pre_anchor_headers` is non-empty, the suffix
///   `[target_height - pre_anchor_headers.len() + 1 ..= target_height]` is written with the
///   supplied real headers (and their real hashes) instead of zero-hash dummies.
/// * Transactions: It will not push any tx, only increments the end block range.
/// * Receipts: It will not push any receipt, only increments the end block range.
/// * TransactionSenders: If the segment exists, increments the end block range.
fn append_dummy_chain<N, F>(
    sf_provider: &StaticFileProvider<N>,
    target_height: BlockNumber,
    header_factory: F,
    pre_anchor_headers: Vec<(N::BlockHeader, B256)>,
) -> ProviderResult<()>
where
    N: NodePrimitives,
    F: Fn(BlockNumber) -> N::BlockHeader + Send + Sync + 'static,
{
    let (tx, rx) = std::sync::mpsc::channel();

    // Spawn jobs for incrementing the block end range of transactions, receipts, and senders.
    for segment in [
        StaticFileSegment::Transactions,
        StaticFileSegment::Receipts,
        StaticFileSegment::TransactionSenders,
    ] {
        if sf_provider.get_highest_static_file_block(segment).is_none() {
            continue
        }
        let tx_clone = tx.clone();
        let provider = sf_provider.clone();
        let thread_name = match segment {
            StaticFileSegment::Transactions => "init-state-txs",
            StaticFileSegment::Receipts => "init-state-receipts",
            StaticFileSegment::TransactionSenders => "init-state-senders",
            _ => "init-state-segment",
        };
        reth_tasks::spawn_os_thread(thread_name, move || {
            let result = provider.latest_writer(segment).and_then(|mut writer| {
                for block_num in 1..=target_height {
                    writer.increment_block(block_num)?;
                }
                Ok(())
            });

            tx_clone.send(result).unwrap();
        });
    }

    // Spawn job for appending empty headers (and any real backfill suffix).
    let provider = sf_provider.clone();
    let real_count = pre_anchor_headers.len() as u64;
    // Real range is `real_start..=target_height`; for empty backfill `real_start = target_height +
    // 1` so the second loop is a no-op and the first loop covers everything.
    let real_start = target_height + 1 - real_count;
    reth_tasks::spawn_os_thread("init-state-headers", move || {
        let result = provider.latest_writer(StaticFileSegment::Headers).and_then(|mut writer| {
            for block_num in 1..real_start {
                // TODO: should we fill with real parent_hash?
                let header = header_factory(block_num);
                writer.append_header(&header, &B256::ZERO)?;
            }
            for (header, hash) in pre_anchor_headers {
                writer.append_header(&header, &hash)?;
            }
            Ok(())
        });

        tx.send(result).unwrap();
    });

    // Catches any StaticFileWriter error.
    while let Ok(append_result) = rx.recv() {
        if let Err(err) = append_result {
            tracing::error!(target: "reth::cli", "Error appending dummy chain: {err}");
            return Err(err)
        }
    }

    // If, for any reason, rayon crashes this verifies if all segments are at the same
    // target_height.
    for segment in [
        StaticFileSegment::Headers,
        StaticFileSegment::Receipts,
        StaticFileSegment::Transactions,
        StaticFileSegment::TransactionSenders,
    ] {
        if sf_provider.get_highest_static_file_block(segment).is_none() {
            continue
        }
        assert_eq!(
            sf_provider.latest_writer(segment)?.user_header().block_end(),
            Some(target_height),
            "Static file segment {segment} was unsuccessful advancing its block height."
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_consensus::Header;
    use alloy_primitives::{address, b256};
    use reth_db_common::init::init_genesis;
    use reth_provider::{test_utils::create_test_provider_factory, DatabaseProviderFactory};
    use std::{
        io::Write,
        sync::{
            atomic::{AtomicU64, Ordering},
            Arc,
        },
    };
    use tempfile::NamedTempFile;

    #[test]
    fn test_read_header_from_file_hex_string() {
        let header_rlp = "0xf90212a00d84d79f59fc384a1f6402609a5b7253b4bfe7a4ae12608ed107273e5422b6dda01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d493479471562b71999873db5b286df957af199ec94617f7a0f496f3d199c51a1aaee67dac95f24d92ac13c60d25181e1eecd6eca5ddf32ac0a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000808206a4840365908a808468e975f09ad983011003846765746888676f312e32352e308664617277696ea06f485a167165ec12e0ab3e6ab59a7b88560b90306ac98a26eb294abf95a8c59b88000000000000000007";

        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(header_rlp.as_bytes()).unwrap();
        temp_file.flush().unwrap();

        let header: Header = read_header_from_file(temp_file.path()).unwrap();

        assert_eq!(header.number, 1700);
        assert_eq!(
            header.parent_hash,
            b256!("0d84d79f59fc384a1f6402609a5b7253b4bfe7a4ae12608ed107273e5422b6dd")
        );
        assert_eq!(header.beneficiary, address!("71562b71999873db5b286df957af199ec94617f7"));
    }

    #[test]
    fn test_read_header_from_file_raw_bytes() {
        let header_rlp = "0xf90212a00d84d79f59fc384a1f6402609a5b7253b4bfe7a4ae12608ed107273e5422b6dda01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d493479471562b71999873db5b286df957af199ec94617f7a0f496f3d199c51a1aaee67dac95f24d92ac13c60d25181e1eecd6eca5ddf32ac0a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000808206a4840365908a808468e975f09ad983011003846765746888676f312e32352e308664617277696ea06f485a167165ec12e0ab3e6ab59a7b88560b90306ac98a26eb294abf95a8c59b88000000000000000007";
        let header_bytes =
            alloy_primitives::hex::decode(header_rlp.trim_start_matches("0x")).unwrap();

        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(&header_bytes).unwrap();
        temp_file.flush().unwrap();

        let header: Header = read_header_from_file(temp_file.path()).unwrap();

        assert_eq!(header.number, 1700);
        assert_eq!(
            header.parent_hash,
            b256!("0d84d79f59fc384a1f6402609a5b7253b4bfe7a4ae12608ed107273e5422b6dd")
        );
        assert_eq!(header.beneficiary, address!("71562b71999873db5b286df957af199ec94617f7"));
    }

    #[test]
    fn test_setup_without_evm_succeeds() {
        let header_rlp = "0xf90212a00d84d79f59fc384a1f6402609a5b7253b4bfe7a4ae12608ed107273e5422b6dda01dcc4de8dec75d7aab85b567b6ccd41ad312451b948a7413f0a142fd40d493479471562b71999873db5b286df957af199ec94617f7a0f496f3d199c51a1aaee67dac95f24d92ac13c60d25181e1eecd6eca5ddf32ac0a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421a056e81f171bcc55a6ff8345e692c0f86e5b48e01b996cadc001622fb5e363b421b9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000808206a4840365908a808468e975f09ad983011003846765746888676f312e32352e308664617277696ea06f485a167165ec12e0ab3e6ab59a7b88560b90306ac98a26eb294abf95a8c59b88000000000000000007";
        let header_bytes =
            alloy_primitives::hex::decode(header_rlp.trim_start_matches("0x")).unwrap();

        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(&header_bytes).unwrap();
        temp_file.flush().unwrap();

        let header: Header = read_header_from_file(temp_file.path()).unwrap();
        let header_hash = b256!("4f05e4392969fc82e41f6d6a8cea379323b0b2d3ddf7def1a33eec03883e3a33");

        let provider_factory = create_test_provider_factory();

        init_genesis(&provider_factory).unwrap();

        let provider_rw = provider_factory.database_provider_rw().unwrap();

        setup_without_evm(
            &provider_rw,
            SealedHeader::new(header, header_hash),
            |number| Header { number, ..Default::default() },
            Vec::new(),
        )
        .unwrap();

        let static_files = provider_factory.static_file_provider();
        let writer = static_files.latest_writer(StaticFileSegment::Headers).unwrap();
        let actual_next_height = writer.next_block_number();
        let expected_next_height = 1701;

        assert_eq!(actual_next_height, expected_next_height);
    }

    /// Regression: a header at block 0 used to send `append_dummy_chain` into
    /// a `1..=u64::MAX` loop because `header.number() - 1` underflowed in
    /// u64. The guard `if header.number() > 0` skips the dummy-chain step
    /// when there is no pre-genesis range to backfill, so `header_factory`
    /// is never invoked.
    #[test]
    fn test_setup_without_evm_skips_dummy_chain_for_genesis_header() {
        let header = Header { number: 0, ..Default::default() };
        let header_hash = header.hash_slow();

        let provider_factory = create_test_provider_factory();
        init_genesis(&provider_factory).unwrap();
        let provider_rw = provider_factory.database_provider_rw().unwrap();

        let factory_calls = Arc::new(AtomicU64::new(0));
        let factory_calls_inner = Arc::clone(&factory_calls);

        // The Result of `setup_without_evm` itself is not asserted: with
        // `number == 0` plus a genesis already written by `init_genesis`,
        // the subsequent `append_first_block` may legitimately fail. The
        // bug under test is the OOM in the dummy-chain loop, observable
        // through the factory-call counter below.
        let _ = setup_without_evm(
            &provider_rw,
            SealedHeader::new(header, header_hash),
            move |number| {
                // Bound calls so a regression cannot exhaust the test
                // runner's memory; the only correct value here is 0.
                let n = factory_calls_inner.fetch_add(1, Ordering::Relaxed);
                assert!(n < 8, "header_factory must not be invoked for a genesis-block header");
                Header { number, ..Default::default() }
            },
            Vec::new(),
        );

        assert_eq!(
            factory_calls.load(Ordering::Relaxed),
            0,
            "append_dummy_chain must be skipped when header.number() == 0"
        );
    }

    /// Build a linked chain of `count` headers starting at `start_number`. Returns
    /// (headers_with_hashes, last_hash) where consecutive entries are chained via
    /// `parent_hash`. Difficulty is set to `number` so each header hashes uniquely.
    fn build_linked_chain(
        start_number: u64,
        count: u64,
        first_parent: B256,
    ) -> (Vec<(Header, B256)>, B256) {
        use alloy_primitives::U256;
        let mut out = Vec::with_capacity(count as usize);
        let mut parent = first_parent;
        for i in 0..count {
            let h = Header {
                number: start_number + i,
                parent_hash: parent,
                difficulty: U256::from(start_number + i),
                ..Default::default()
            };
            let hash = h.hash_slow();
            out.push((h, hash));
            parent = hash;
        }
        (out, parent)
    }

    /// Real headers backfilled into the dummy-chain suffix must end up in both
    /// the Headers static-file segment (correct hash column) and the MDBX
    /// `HeaderNumbers` table. Dummies before the real suffix retain `B256::ZERO`.
    #[test]
    fn pre_anchor_headers_overwrite_dummy_suffix() {
        use reth_db_api::transaction::DbTx;
        use reth_provider::BlockHashReader;

        // Anchor at block 20; backfill last 5 (blocks 15..=19).
        let anchor_number: u64 = 20;
        let backfill_count: u64 = 5;

        let provider_factory = create_test_provider_factory();
        init_genesis(&provider_factory).unwrap();

        // Build a chain whose first entry's parent is `B256::ZERO` — the dummy
        // hash that `append_dummy_chain` writes for blocks before the backfill
        // suffix. The validator only requires hash self-consistency and that
        // the chain's tail equals `anchor.parent_hash`; it does not require
        // continuity with the dummy prefix (those dummies are zero anyway).
        let backfill_start = anchor_number - backfill_count;
        let (backfill, last_hash) = build_linked_chain(backfill_start, backfill_count, B256::ZERO);
        let anchor = Header { number: anchor_number, parent_hash: last_hash, ..Default::default() };
        let anchor_hash = anchor.hash_slow();

        let provider_rw = provider_factory.database_provider_rw().unwrap();
        setup_without_evm(
            &provider_rw,
            SealedHeader::new(anchor, anchor_hash),
            |number| Header { number, ..Default::default() },
            backfill.clone(),
        )
        .unwrap();
        provider_rw.static_file_provider().commit().unwrap();
        provider_rw.commit().unwrap();

        // Static-file hash column matches for each backfilled block.
        let provider_ro = provider_factory.database_provider_ro().unwrap();
        for (h, expected_hash) in &backfill {
            let got = provider_ro
                .static_file_provider()
                .block_hash(h.number)
                .unwrap()
                .expect("backfilled hash must be present");
            assert_eq!(got, *expected_hash, "block {} hash mismatch", h.number);
        }

        // A dummy block before the backfill suffix still has the zero hash.
        let dummy_block = backfill_start - 1; // = 14
        let dummy_hash = provider_ro
            .static_file_provider()
            .block_hash(dummy_block)
            .unwrap()
            .expect("dummy slot must be present");
        assert_eq!(dummy_hash, B256::ZERO, "dummy below backfill must remain zero");

        // MDBX HeaderNumbers has the real (hash -> number) row for backfilled blocks.
        let tx = provider_ro.tx_ref();
        for (h, expected_hash) in &backfill {
            let got: Option<u64> = tx.get::<tables::HeaderNumbers>(*expected_hash).unwrap();
            assert_eq!(got, Some(h.number), "HeaderNumbers missing for block {}", h.number);
        }

        // Anchor is written by `append_first_block` -> `insert_block`, which also
        // populates HeaderNumbers for the anchor itself.
        let anchor_via_numbers: Option<u64> = tx.get::<tables::HeaderNumbers>(anchor_hash).unwrap();
        assert_eq!(anchor_via_numbers, Some(anchor_number), "anchor HeaderNumbers row missing");
    }

    /// Validation must reject a chain whose `parent_hash` links don't connect.
    #[test]
    fn validate_pre_anchor_headers_rejects_broken_chain() {
        let anchor = Header { number: 10, parent_hash: B256::ZERO, ..Default::default() };
        let anchor_hash = anchor.hash_slow();
        // Two headers whose parent_hashes don't chain.
        let h1 = Header { number: 8, parent_hash: B256::ZERO, ..Default::default() };
        let h2 = Header {
            number: 9,
            parent_hash: B256::from([0x11; 32]), // wrong: should be h1.hash_slow()
            ..Default::default()
        };
        let bad: Vec<(Header, B256)> =
            vec![(h1.clone(), h1.hash_slow()), (h2.clone(), h2.hash_slow())];

        let err = validate_pre_anchor_headers(&SealedHeader::new(anchor, anchor_hash), &bad)
            .expect_err("broken parent_hash chain must fail validation");
        let msg = format!("{err:?}");
        assert!(msg.contains("parent_hash"), "error should reference parent_hash: {msg}");
    }

    /// Validation must reject a self-inconsistent hash claim.
    #[test]
    fn validate_pre_anchor_headers_rejects_hash_mismatch() {
        let anchor = Header { number: 5, parent_hash: B256::ZERO, ..Default::default() };
        let anchor_hash = anchor.hash_slow();
        let h = Header { number: 4, ..Default::default() };
        // Claim the wrong hash.
        let bad = vec![(h, B256::from([0xaa; 32]))];
        let err = validate_pre_anchor_headers(&SealedHeader::new(anchor, anchor_hash), &bad)
            .expect_err("hash mismatch must fail validation");
        let msg = format!("{err:?}");
        assert!(msg.contains("hash mismatch"), "error should reference hash mismatch: {msg}");
    }
}

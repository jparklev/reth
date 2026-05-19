//! Decode `logs` chunks (Parquet or Vortex) into
//! `alloy_rpc_types_eth::Log` rows.
//!
//! Schema (port of `relay_indexer::types::LogRow`):
//! - `block_num: i64`
//! - `block_hash: fixed_len_byte_array(32)`
//! - `log_idx: i32`
//! - `tx_idx: i32`
//! - `tx_hash: fixed_len_byte_array(32)`
//! - `address: fixed_len_byte_array(20)`
//! - `topic0: fixed_len_byte_array(32)`  (anonymous events: 32 zero bytes)
//! - `topic1..3: optional fixed_len_byte_array(32)`
//! - `data: binary`
//!
//! The live mainnet bucket (`s3://reth-spike-fsn1`) currently emits
//! Parquet for the `logs` chunk type — Vortex is the future format.
//! Both paths are supported here to match relay-rpc's reader.

use alloy_primitives::{Address, B256, Bytes, LogData, Log as PrimitiveLog};
use alloy_rpc_types_eth::Log;
use eyre::{Result, eyre};
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
use parquet::arrow::ProjectionMask;
use parquet::file::properties::ReaderProperties;
use parquet::file::reader::FileReader;
use parquet::file::serialized_reader::{ReadOptionsBuilder, SerializedFileReader};
use std::sync::Arc;

use arrow::array::{Array, BinaryArray, FixedSizeBinaryArray, Int32Array, Int64Array};
use arrow::record_batch::RecordBatch;

/// Flat representation of an `eth_getLogs` filter, in the shape the
/// bucket reader needs. `addresses.is_empty()` ⇒ match any address;
/// `topics[i].is_empty()` ⇒ match any topic at slot i.
#[derive(Debug, Clone, Default)]
pub struct LogScanFilter {
    pub addresses: Vec<Address>,
    pub topics: [Vec<B256>; 4],
}

impl LogScanFilter {
    pub fn is_selective(&self) -> bool {
        !self.addresses.is_empty() || !self.topics[0].is_empty()
    }

    pub fn matches(&self, address: &Address, topics: &[B256]) -> bool {
        if !self.addresses.is_empty() && !self.addresses.contains(address) {
            return false;
        }
        for (slot, slot_filter) in self.topics.iter().enumerate() {
            if slot_filter.is_empty() {
                continue;
            }
            let log_topic = topics.get(slot);
            let Some(topic) = log_topic else {
                return false;
            };
            if !slot_filter.contains(topic) {
                return false;
            }
        }
        true
    }
}

/// Match the writer-side persisted-bytes normalization: anonymous
/// events use 32 zero bytes in the column (and thus in the SBBF).
/// Right-pads short inputs with zeros so the probe bytes always have
/// length 32 — same as `topic0_or_zero_bytes` on the writer.
///
/// Port of relay-rpc `normalize_topic0_key`.
fn normalize_topic0_key(topic: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; 32];
    let copy_len = topic.len().min(32);
    out[32 - copy_len..].copy_from_slice(&topic[..copy_len]);
    out
}

/// PHASE22 Sprint 3 — chunk-level Bloom probe over a Parquet logs
/// chunk's SBBF side-table.
///
/// Returns `true` only when the per-chunk SBBF *proves* there cannot
/// be a matching log in this chunk for the given predicate. Returns
/// `false` on **any** ambiguity — missing Bloom (pre-Sprint-3 chunk),
/// parquet parse failure, or definite/possible match — because a
/// false negative here would silently corrupt `eth_getLogs` results.
///
/// Port of `chunk_bloom_skips_filter` from relay-rpc.
pub fn chunk_bloom_skips_filter(chunk_bytes: &[u8], filter: &LogScanFilter) -> bool {
    if !filter.is_selective() {
        return false;
    }

    let options = ReadOptionsBuilder::new()
        .with_reader_properties(
            ReaderProperties::builder()
                .set_read_bloom_filter(true)
                .build(),
        )
        .build();
    let Ok(reader) = SerializedFileReader::new_with_options(
        bytes::Bytes::copy_from_slice(chunk_bytes),
        options,
    ) else {
        return false;
    };
    let Ok(row_group) = reader.get_row_group(0) else {
        return false;
    };
    let columns = row_group.metadata().columns();
    let column_idx = |name: &str| {
        columns
            .iter()
            .position(|c| c.column_path().string() == name)
    };

    // Address allowlist — if every address misses the SBBF the
    // chunk is provably empty for the filter.
    if !filter.addresses.is_empty()
        && let Some(idx) = column_idx("address")
        && let Some(bloom) = row_group.get_column_bloom_filter(idx)
        && filter.addresses.iter().all(|address| {
            let v: &[u8] = address.as_slice();
            !bloom.check(&v.to_vec())
        })
    {
        return true;
    }

    // Topic0 — anonymous-event normalization on the writer side
    // means the probed key is always 32 bytes.
    if !filter.topics[0].is_empty()
        && let Some(idx) = column_idx("topic0")
        && let Some(bloom) = row_group.get_column_bloom_filter(idx)
        && filter.topics[0].iter().all(|topic| {
            let key = normalize_topic0_key(topic.as_slice());
            !bloom.check(&key)
        })
    {
        return true;
    }

    false
}

/// Decode a Parquet `logs.parquet` chunk into a flat `Vec<Log>` with
/// the row-level filter applied **and** the block_num restricted to
/// `[from_block, to_block]`. `block_hashes` supplies the
/// canonical block hash for the per-block_num so we can fill the
/// `Log::block_hash` field without an extra header fetch.
pub fn decode_log_chunk_parquet(
    bytes: Vec<u8>,
    from_block: u64,
    to_block: u64,
    filter: &LogScanFilter,
    block_hashes: &std::collections::HashMap<u64, B256>,
) -> Result<Vec<Log>> {
    let reader = ParquetRecordBatchReaderBuilder::try_new(bytes::Bytes::from(bytes))
        .map_err(|err| eyre!("open parquet: {err}"))?;
    let schema = reader.schema().clone();
    let parquet_schema = reader.parquet_schema();
    let want: &[&str] = &[
        "block_num", "block_hash", "log_idx", "tx_idx", "tx_hash", "address",
        "topic0", "topic1", "topic2", "topic3", "data",
    ];
    let projection_indices: Vec<usize> = want
        .iter()
        .map(|name| {
            schema
                .index_of(name)
                .map_err(|err| eyre!("parquet missing {name}: {err}"))
        })
        .collect::<Result<_>>()?;
    let mask = ProjectionMask::leaves(parquet_schema, projection_indices.clone());
    let reader = reader
        .with_projection(mask)
        .build()
        .map_err(|err| eyre!("build parquet reader: {err}"))?;
    let _ = schema; // keep schema alive for life of reader

    let mut out = Vec::new();
    for batch in reader {
        let batch = batch.map_err(|err| eyre!("read parquet batch: {err}"))?;
        decode_batch_into(&batch, from_block, to_block, filter, block_hashes, &mut out)?;
    }
    Ok(out)
}

fn decode_batch_into(
    batch: &RecordBatch,
    from_block: u64,
    to_block: u64,
    filter: &LogScanFilter,
    block_hashes: &std::collections::HashMap<u64, B256>,
    out: &mut Vec<Log>,
) -> Result<()> {
    let block_num = downcast::<Int64Array>(batch, "block_num")?;
    let log_idx = downcast::<Int32Array>(batch, "log_idx")?;
    let tx_idx = downcast::<Int32Array>(batch, "tx_idx")?;
    let tx_hash = bytes_column(batch, "tx_hash", 32)?;
    let address = bytes_column(batch, "address", 20)?;
    let topic0 = bytes_column(batch, "topic0", 32)?;
    let topic1 = bytes_column(batch, "topic1", 32)?;
    let topic2 = bytes_column(batch, "topic2", 32)?;
    let topic3 = bytes_column(batch, "topic3", 32)?;
    let data = downcast::<BinaryArray>(batch, "data")?;
    let block_hash = bytes_column(batch, "block_hash", 32)?;

    for row in 0..batch.num_rows() {
        let bn = block_num.value(row) as u64;
        if bn < from_block || bn > to_block {
            continue;
        }
        let addr_bytes = address.value(row);
        if addr_bytes.len() != 20 {
            return Err(eyre!("address column row {row} not 20 bytes"));
        }
        let addr = Address::from_slice(addr_bytes);

        let mut topics: Vec<B256> = Vec::with_capacity(4);
        // topic0 may be 32 zeros for anonymous events; treat that
        // as "no topic0 present" so we don't break filter semantics
        // for filters with an empty topic[0] slot.
        let t0 = topic0.value(row);
        let t0_is_zero = t0.iter().all(|b| *b == 0);
        if !t0_is_zero {
            topics.push(B256::from_slice(t0));
        }
        if let Some(t1) = topic1.opt(row) {
            topics.push(B256::from_slice(&t1));
        }
        if let Some(t2) = topic2.opt(row) {
            topics.push(B256::from_slice(&t2));
        }
        if let Some(t3) = topic3.opt(row) {
            topics.push(B256::from_slice(&t3));
        }

        if !filter.matches(&addr, &topics) {
            continue;
        }

        let data_bytes = data.value(row).to_vec();
        let bh = block_hash.opt(row).map(|b| B256::from_slice(&b));
        let canonical_bh = block_hashes.get(&bn).copied().or(bh);

        let primitive = PrimitiveLog {
            address: addr,
            data: LogData::new(topics, Bytes::from(data_bytes)).ok_or_else(|| {
                eyre!("log topics > 4 at row {row}")
            })?,
        };
        out.push(Log {
            inner: primitive,
            block_hash: canonical_bh,
            block_number: Some(bn),
            block_timestamp: None,
            transaction_hash: Some(B256::from_slice(&tx_hash.value(row))),
            transaction_index: Some(tx_idx.value(row) as u64),
            log_index: Some(log_idx.value(row) as u64),
            removed: false,
        });
    }
    Ok(())
}

fn downcast<'a, T: Array + 'static>(batch: &'a RecordBatch, name: &str) -> Result<&'a T> {
    let idx = batch
        .schema()
        .index_of(name)
        .map_err(|err| eyre!("parquet missing column {name}: {err}"))?;
    batch
        .column(idx)
        .as_any()
        .downcast_ref::<T>()
        .ok_or_else(|| eyre!("parquet column {name} has unexpected type"))
}

enum BytesColumn<'a> {
    Fixed(&'a FixedSizeBinaryArray, usize),
    Binary(&'a BinaryArray, usize),
}

impl BytesColumn<'_> {
    fn value(&self, row: usize) -> &[u8] {
        match self {
            Self::Fixed(arr, _) => arr.value(row),
            Self::Binary(arr, _) => arr.value(row),
        }
    }
    fn opt(&self, row: usize) -> Option<Vec<u8>> {
        let is_null = match self {
            Self::Fixed(arr, _) => arr.is_null(row),
            Self::Binary(arr, _) => arr.is_null(row),
        };
        if is_null { None } else { Some(self.value(row).to_vec()) }
    }
}

fn bytes_column<'a>(batch: &'a RecordBatch, name: &str, width: usize) -> Result<BytesColumn<'a>> {
    let idx = batch
        .schema()
        .index_of(name)
        .map_err(|err| eyre!("parquet missing column {name}: {err}"))?;
    let array = batch.column(idx);
    if let Some(fixed) = array.as_any().downcast_ref::<FixedSizeBinaryArray>() {
        return Ok(BytesColumn::Fixed(fixed, width));
    }
    if let Some(binary) = array.as_any().downcast_ref::<BinaryArray>() {
        return Ok(BytesColumn::Binary(binary, width));
    }
    Err(eyre!("parquet column {name} not a binary type"))
}

// Suppress unused warning when the rest of the crate doesn't reference
// `Arc` directly (kept for potential future shared chunk caches).
#[allow(dead_code)]
fn _force_arc_dep(_: Arc<()>) {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn addr(b: u8) -> Address {
        let mut out = [0u8; 20];
        out.fill(b);
        Address::from(out)
    }

    fn topic(b: u8) -> B256 {
        let mut out = [0u8; 32];
        out.fill(b);
        B256::from(out)
    }

    #[test]
    fn matches_address_allowlist_and_topic_slots() {
        let filter = LogScanFilter {
            addresses: vec![addr(0x31)],
            topics: [
                vec![topic(0x41)],
                Vec::new(),
                vec![topic(0x52)],
                Vec::new(),
            ],
        };
        // Hit: address matches, topic0 matches, topic2 matches.
        assert!(filter.matches(
            &addr(0x31),
            &[topic(0x41), topic(0x51), topic(0x52)],
        ));
        // Miss: address mismatch.
        assert!(!filter.matches(
            &addr(0x32),
            &[topic(0x41), topic(0x51), topic(0x52)],
        ));
        // Miss: topic0 mismatch.
        assert!(!filter.matches(
            &addr(0x31),
            &[topic(0xff), topic(0x51), topic(0x52)],
        ));
        // Miss: topic2 absent (log has only 1 topic).
        assert!(!filter.matches(&addr(0x31), &[topic(0x41)]));
    }

    #[test]
    fn empty_filter_matches_everything() {
        let filter = LogScanFilter::default();
        assert!(!filter.is_selective());
        assert!(filter.matches(&addr(0x55), &[]));
        assert!(filter.matches(&addr(0xff), &[topic(0xaa), topic(0xbb)]));
    }

    #[test]
    fn normalize_topic0_right_pads() {
        let v = normalize_topic0_key(&[0xab, 0xcd]);
        assert_eq!(v.len(), 32);
        assert_eq!(&v[30..], &[0xab, 0xcd]);
        let v2 = normalize_topic0_key(&[0u8; 32]);
        assert_eq!(v2, vec![0u8; 32]);
    }

    /// `chunk_bloom_skips_filter` must NEVER return true on garbage
    /// bytes — a false positive would silently drop real logs from
    /// the user's `eth_getLogs` response. This is the critical
    /// correctness gate for the Bloom path (PHASE22 §2 risk
    /// register row 1).
    #[test]
    fn bloom_probe_returns_false_on_unparseable_bytes() {
        let filter = LogScanFilter {
            addresses: vec![addr(0x31)],
            topics: Default::default(),
        };
        assert!(filter.is_selective());
        // Garbage bytes — not a parquet file. Probe must NOT claim
        // the chunk is "definitely empty"; it must fall through to
        // the full decode-and-filter path (`false`).
        let garbage = b"not a parquet file".to_vec();
        assert!(!chunk_bloom_skips_filter(&garbage, &filter));
    }

    /// A non-selective filter must never trigger the probe (we
    /// short-circuit before doing any parquet parse work).
    #[test]
    fn bloom_probe_does_nothing_when_filter_not_selective() {
        let filter = LogScanFilter::default();
        assert!(!filter.is_selective());
        // Even valid parquet bytes would return false here; the
        // probe should short-circuit on `!is_selective()`.
        assert!(!chunk_bloom_skips_filter(b"any-bytes", &filter));
    }
}

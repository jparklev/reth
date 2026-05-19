//! Vortex chunk decode → `alloy_consensus::Header`.
//!
//! Schema matches `crates/relay-rpc/src/backends/vortex_headers.rs`
//! in the relay project (24 fields). This module is a minimal port:
//! we only need to materialize an `alloy_consensus::Header`, not
//! the relay `BlockRow` shape.

use std::sync::Arc;

use alloy_consensus::Header;
use alloy_primitives::{Address, B256, Bloom, Bytes, U256};
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use eyre::{Result, eyre};
use object_store::{ObjectStore, ObjectStoreExt};
use object_store::path::Path as ObjectPath;
use vortex::array::accessor::ArrayAccessor;
use vortex::array::arrays::decimal::DecimalArrayExt;
use vortex::array::arrays::struct_::StructArrayExt;
use vortex::array::arrays::{
    DecimalArray, PrimitiveArray, StructArray as VortexStructArray,
    VarBinViewArray as VortexVarBinViewArray,
};
use vortex::array::dtype::DecimalType;
use vortex::array::expr::{col, eq, lit, root, select};
use vortex::array::stream::ArrayStreamExt;
use vortex::array::{ExecutionCtx, VortexSessionExecute, scalar::Scalar};
use vortex::session::VortexSession;
use vortex::VortexSessionDefault;
use vortex_buffer::ByteBuffer;
use vortex_file::{Footer, OpenOptionsSessionExt};
use vortex_io::object_store::ObjectStoreReadAt;

use super::VortexPreloadRange;

const HEADER_COLUMNS: &[&str] = &[
    "num",
    "hash",
    "parent_hash",
    "timestamp",
    "gas_limit",
    "gas_used",
    "base_fee_per_gas",
    "miner",
    "difficulty",
    "extra_data",
    "mix_hash",
    "nonce",
    "state_root",
    "transactions_root",
    "receipts_root",
    "logs_bloom",
    "withdrawals_root",
    "blob_gas_used",
    "excess_blob_gas",
    "parent_beacon_block_root",
    "requests_hash",
];

pub(crate) async fn decode_block_header_chunk(
    store: Arc<dyn ObjectStore>,
    path: ObjectPath,
    block_num: u64,
    file_size: Option<u64>,
    footer_metadata_b64: Option<&str>,
    preload_ranges: &[VortexPreloadRange],
) -> Result<Header> {
    let session = VortexSession::default();
    let handle = vortex_io::runtime::Handle::find()
        .ok_or_else(|| eyre!("no vortex runtime handle available"))?;
    let read_at = ObjectStoreReadAt::new(Arc::clone(&store), path.clone(), handle);

    let mut options = session.open_options();
    options = options.with_some_file_size(file_size);

    if let Some(b64) = footer_metadata_b64 {
        let bytes = BASE64
            .decode(b64)
            .map_err(|err| eyre!("decode footer b64: {err}"))?;
        let footer = Footer::from_metadata_bytes(ByteBuffer::copy_from(&bytes), session.clone())
            .map_err(|err| eyre!("footer parse: {err}"))?;
        options = options.with_footer(footer);
    }

    // Preload hot byte ranges (footer + segments) via direct
    // get_range so vortex can fill from cache instead of fetching
    // again over object_store.
    for range in preload_ranges {
        if range.length == 0 {
            continue;
        }
        let end = range
            .offset
            .checked_add(range.length)
            .ok_or_else(|| eyre!("preload range overflow"))?;
        let bytes = store
            .get_range(&path, range.offset..end)
            .await
            .map_err(|err| eyre!("preload {}..{}: {err}", range.offset, end))?;
        options =
            options.with_preloaded_file_range(range.offset, ByteBuffer::copy_from(bytes.as_ref()));
    }

    let file = options
        .open(Arc::new(read_at))
        .await
        .map_err(|err| eyre!("open vortex file: {err}"))?;

    let array = file
        .scan()
        .map_err(|err| eyre!("scan vortex: {err}"))?
        .with_filter(eq(col("num"), lit(Scalar::from(block_num as i64))))
        .with_projection(select(HEADER_COLUMNS, root()))
        .into_array_stream()
        .map_err(|err| eyre!("stream vortex: {err}"))?
        .read_all()
        .await
        .map_err(|err| eyre!("read vortex: {err}"))?;
    let mut ctx = session.create_execution_ctx();
    let struct_arr: VortexStructArray = array
        .execute(&mut ctx)
        .map_err(|err| eyre!("decode vortex: {err}"))?;
    rows_to_header(&mut ctx, struct_arr, block_num)
}

fn rows_to_header(
    ctx: &mut ExecutionCtx,
    struct_arr: VortexStructArray,
    block_num: u64,
) -> Result<Header> {
    let num = primitive_required::<i64>(ctx, &struct_arr, "num")?;
    let hash = varbin_required(ctx, &struct_arr, "hash")?;
    let _ = hash;
    let parent_hash = varbin_required(ctx, &struct_arr, "parent_hash")?;
    let timestamp = primitive_required::<i64>(ctx, &struct_arr, "timestamp")?;
    let gas_limit = primitive_required::<i64>(ctx, &struct_arr, "gas_limit")?;
    let gas_used = primitive_required::<i64>(ctx, &struct_arr, "gas_used")?;
    let base_fee = decimal_optional(ctx, &struct_arr, "base_fee_per_gas")?;
    let miner = varbin_required(ctx, &struct_arr, "miner")?;
    let difficulty_str = decimal_optional(ctx, &struct_arr, "difficulty")?;
    let extra_data = varbin_required(ctx, &struct_arr, "extra_data")?;
    let mix_hash = varbin_optional(ctx, &struct_arr, "mix_hash")?;
    let nonce_bytes = varbin_optional(ctx, &struct_arr, "nonce")?;
    let state_root = varbin_required(ctx, &struct_arr, "state_root")?;
    let transactions_root = varbin_required(ctx, &struct_arr, "transactions_root")?;
    let receipts_root = varbin_required(ctx, &struct_arr, "receipts_root")?;
    let logs_bloom = varbin_required(ctx, &struct_arr, "logs_bloom")?;
    let withdrawals_root = varbin_optional(ctx, &struct_arr, "withdrawals_root")?;
    let blob_gas_used = primitive_optional::<i64>(ctx, &struct_arr, "blob_gas_used")?;
    let excess_blob_gas = primitive_optional::<i64>(ctx, &struct_arr, "excess_blob_gas")?;
    let parent_beacon = varbin_optional(ctx, &struct_arr, "parent_beacon_block_root")?;
    let requests_hash = varbin_optional(ctx, &struct_arr, "requests_hash")?;

    let row = num
        .iter()
        .position(|v| *v == block_num as i64)
        .ok_or_else(|| eyre!("decoded chunk contained no row with num={block_num}"))?;

    let parent_hash_b = bytes_to_b256(&parent_hash[row])?;
    let miner_addr = bytes_to_address(&miner[row])?;
    let state_root_b = bytes_to_b256(&state_root[row])?;
    let tx_root = bytes_to_b256(&transactions_root[row])?;
    let receipts_root_b = bytes_to_b256(&receipts_root[row])?;
    let bloom = bytes_to_bloom(&logs_bloom[row])?;
    let difficulty = difficulty_str[row]
        .as_deref()
        .map(parse_u256_dec)
        .transpose()?
        .unwrap_or(U256::ZERO);
    let extra = Bytes::from(extra_data[row].clone());
    let mix = mix_hash[row]
        .as_ref()
        .map(|b| bytes_to_b256(b))
        .transpose()?
        .unwrap_or(B256::ZERO);
    let nonce = nonce_bytes[row]
        .as_ref()
        .map(|b| {
            if b.len() == 8 {
                let mut out = [0u8; 8];
                out.copy_from_slice(b);
                Ok::<_, eyre::Report>(alloy_primitives::B64::from(out))
            } else {
                Err(eyre!("nonce must be 8 bytes, got {}", b.len()))
            }
        })
        .transpose()?
        .unwrap_or_default();
    let base_fee_n = base_fee[row]
        .as_deref()
        .map(parse_u256_dec)
        .transpose()?
        .map(|u| u.to::<u64>());
    let withdrawals_root_b = withdrawals_root[row]
        .as_ref()
        .map(|b| bytes_to_b256(b))
        .transpose()?;
    let parent_beacon_b = parent_beacon[row]
        .as_ref()
        .map(|b| bytes_to_b256(b))
        .transpose()?;
    let requests_hash_b = requests_hash[row]
        .as_ref()
        .map(|b| bytes_to_b256(b))
        .transpose()?;

    Ok(Header {
        parent_hash: parent_hash_b,
        ommers_hash: alloy_consensus::EMPTY_OMMER_ROOT_HASH,
        beneficiary: miner_addr,
        state_root: state_root_b,
        transactions_root: tx_root,
        receipts_root: receipts_root_b,
        logs_bloom: bloom,
        difficulty,
        number: num[row] as u64,
        gas_limit: gas_limit[row] as u64,
        gas_used: gas_used[row] as u64,
        timestamp: timestamp[row] as u64,
        extra_data: extra,
        mix_hash: mix,
        nonce,
        base_fee_per_gas: base_fee_n,
        withdrawals_root: withdrawals_root_b,
        blob_gas_used: blob_gas_used[row].map(|v| v as u64),
        excess_blob_gas: excess_blob_gas[row].map(|v| v as u64),
        parent_beacon_block_root: parent_beacon_b,
        requests_hash: requests_hash_b,
        block_access_list_hash: None,
        slot_number: None,
    })
}

fn primitive_required<T>(
    ctx: &mut ExecutionCtx,
    array: &VortexStructArray,
    name: &str,
) -> Result<Vec<T>>
where
    T: vortex::array::dtype::NativePType + Copy + Default,
{
    Ok(primitive_optional(ctx, array, name)?
        .into_iter()
        .map(|v| v.unwrap_or_default())
        .collect())
}

fn primitive_optional<T>(
    ctx: &mut ExecutionCtx,
    array: &VortexStructArray,
    name: &str,
) -> Result<Vec<Option<T>>>
where
    T: vortex::array::dtype::NativePType + Copy,
{
    let field = array
        .unmasked_field_by_name(name)
        .map_err(|err| eyre!("vortex missing {name}: {err}"))?;
    let values: PrimitiveArray =
        field.clone().execute(ctx).map_err(|err| eyre!("decode {name}: {err}"))?;
    Ok(values.with_iterator(|iter| iter.map(|v| v.copied()).collect::<Vec<_>>()))
}

fn decimal_optional(
    ctx: &mut ExecutionCtx,
    array: &VortexStructArray,
    name: &str,
) -> Result<Vec<Option<String>>> {
    let field = array
        .unmasked_field_by_name(name)
        .map_err(|err| eyre!("vortex missing {name}: {err}"))?;
    let values: DecimalArray =
        field.clone().execute(ctx).map_err(|err| eyre!("decode {name}: {err}"))?;
    if values.scale() != 0 {
        return Err(eyre!("expected integer decimal scale for {name}"));
    }
    let validity = values
        .validity()
        .map_err(|err| eyre!("validity {name}: {err}"))?;
    let mut out = match values.values_type() {
        DecimalType::I8 => buf_to_strs(values.buffer::<i8>()),
        DecimalType::I16 => buf_to_strs(values.buffer::<i16>()),
        DecimalType::I32 => buf_to_strs(values.buffer::<i32>()),
        DecimalType::I64 => buf_to_strs(values.buffer::<i64>()),
        DecimalType::I128 => buf_to_strs(values.buffer::<i128>()),
        DecimalType::I256 => return Err(eyre!("i256 decimal not supported for {name}")),
    };
    for (idx, value) in out.iter_mut().enumerate() {
        if !validity
            .is_valid(idx)
            .map_err(|err| eyre!("validity is_valid {name}: {err}"))?
        {
            *value = None;
        }
    }
    Ok(out)
}

fn buf_to_strs<T: ToString>(values: vortex::buffer::Buffer<T>) -> Vec<Option<String>> {
    values.iter().map(|v| Some(v.to_string())).collect()
}

fn varbin_required(
    ctx: &mut ExecutionCtx,
    array: &VortexStructArray,
    name: &str,
) -> Result<Vec<Vec<u8>>> {
    Ok(varbin_optional(ctx, array, name)?
        .into_iter()
        .map(|v| v.unwrap_or_default())
        .collect())
}

fn varbin_optional(
    ctx: &mut ExecutionCtx,
    array: &VortexStructArray,
    name: &str,
) -> Result<Vec<Option<Vec<u8>>>> {
    let field = array
        .unmasked_field_by_name(name)
        .map_err(|err| eyre!("vortex missing {name}: {err}"))?;
    let values: VortexVarBinViewArray =
        field.clone().execute(ctx).map_err(|err| eyre!("decode {name}: {err}"))?;
    Ok(values.with_iterator(|iter| iter.map(|v| v.map(|b| b.to_vec())).collect::<Vec<_>>()))
}

fn bytes_to_b256(b: &[u8]) -> Result<B256> {
    if b.len() != 32 {
        return Err(eyre!("expected 32-byte hash, got {}", b.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(b);
    Ok(B256::from(out))
}

fn bytes_to_address(b: &[u8]) -> Result<Address> {
    if b.len() != 20 {
        return Err(eyre!("expected 20-byte address, got {}", b.len()));
    }
    let mut out = [0u8; 20];
    out.copy_from_slice(b);
    Ok(Address::from(out))
}

fn bytes_to_bloom(b: &[u8]) -> Result<Bloom> {
    if b.len() != 256 {
        return Err(eyre!("expected 256-byte bloom, got {}", b.len()));
    }
    let mut out = [0u8; 256];
    out.copy_from_slice(b);
    Ok(Bloom::from(out))
}

fn parse_u256_dec(s: &str) -> Result<U256> {
    U256::from_str_radix(s, 10).map_err(|err| eyre!("parse U256 from '{s}': {err}"))
}
// ===== Vortex log chunk decoder (epoch- or block-level) =====
//
// Port of `relay-rpc/src/backends/vortex_logs.rs`'s scan path, with
// filter pushdown via `with_filter(eq(col("address"), …))`. The
// current live bucket emits Parquet for `logs` chunks (so this code
// path is exercised only by Vortex unit tests + future Phase 24
// deploys that promote `logs` to Vortex).
//
// Schema, port of `relay_indexer::types::LogRow`:
//   block_num: i64
//   block_hash: binary
//   log_idx: i32
//   tx_idx: i32
//   tx_hash: binary
//   address: binary
//   topic0..3: binary (topic0 is NonNull and contains 32 zero bytes
//              for anonymous events; topic1..3 are nullable)
//   data: binary
//
// Filter pushdown:
//   block_num predicate is always pushed (range or eq)
//   address allowlist becomes an OR-of-eq pushdown
//   topic0 (selective only) becomes an OR-of-eq pushdown
//   topic1..3 are filtered in-process for now (the relay reader
//   does push them down, but the lit() shape requires the
//   anonymous-event normalization which only applies to topic0)

use std::collections::HashMap;

use alloy_primitives::{Bytes as PrimBytes, LogData, Log as PrimitiveLog};
use alloy_rpc_types_eth::Log;
use vortex::array::dtype::Nullability;
use vortex::array::expr::{and, gt_eq, lt_eq, or_collect};

use super::logs_decode::LogScanFilter;

const LOG_COLUMNS: &[&str] = &[
    "block_num",
    "block_hash",
    "log_idx",
    "tx_idx",
    "tx_hash",
    "address",
    "topic0",
    "topic1",
    "topic2",
    "topic3",
    "data",
];

pub(crate) async fn decode_log_chunk(
    store: Arc<dyn ObjectStore>,
    path: ObjectPath,
    file_size: Option<u64>,
    footer_metadata_b64: Option<&str>,
    preload_ranges: &[VortexPreloadRange],
    from_block: u64,
    to_block: u64,
    filter: &LogScanFilter,
    block_hashes: &HashMap<u64, B256>,
) -> Result<Vec<Log>> {
    let session = VortexSession::default();
    let handle = vortex_io::runtime::Handle::find()
        .ok_or_else(|| eyre!("no vortex runtime handle available"))?;
    let read_at = ObjectStoreReadAt::new(Arc::clone(&store), path.clone(), handle);

    let mut options = session.open_options();
    options = options.with_some_file_size(file_size);
    if let Some(b64) = footer_metadata_b64 {
        let bytes = BASE64
            .decode(b64)
            .map_err(|err| eyre!("decode footer b64: {err}"))?;
        let footer = Footer::from_metadata_bytes(ByteBuffer::copy_from(&bytes), session.clone())
            .map_err(|err| eyre!("footer parse: {err}"))?;
        options = options.with_footer(footer);
    }
    for range in preload_ranges {
        if range.length == 0 {
            continue;
        }
        let end = range
            .offset
            .checked_add(range.length)
            .ok_or_else(|| eyre!("preload range overflow"))?;
        let bytes = store
            .get_range(&path, range.offset..end)
            .await
            .map_err(|err| eyre!("preload {}..{}: {err}", range.offset, end))?;
        options =
            options.with_preloaded_file_range(range.offset, ByteBuffer::copy_from(bytes.as_ref()));
    }

    let file = options
        .open(Arc::new(read_at))
        .await
        .map_err(|err| eyre!("open vortex file: {err}"))?;

    // Build the filter expression. Block-num range is always pushed.
    let block_filter = if from_block == to_block {
        eq(col("block_num"), lit(Scalar::from(from_block as i64)))
    } else {
        and(
            gt_eq(col("block_num"), lit(Scalar::from(from_block as i64))),
            lt_eq(col("block_num"), lit(Scalar::from(to_block as i64))),
        )
    };
    let mut filter_expr = block_filter;
    if !filter.addresses.is_empty() {
        if let Some(address_pred) = or_collect(filter.addresses.iter().map(|addr| {
            eq(
                col("address"),
                lit(Scalar::binary(ByteBuffer::copy_from(addr.as_slice()), Nullability::NonNullable)),
            )
        })) {
            filter_expr = and(filter_expr, address_pred);
        }
    }
    if !filter.topics[0].is_empty() {
        if let Some(topic0_pred) = or_collect(filter.topics[0].iter().map(|topic_b| {
            let key = {
                let bytes = topic_b.as_slice();
                let mut out = vec![0u8; 32];
                let copy_len = bytes.len().min(32);
                out[32 - copy_len..].copy_from_slice(&bytes[..copy_len]);
                out
            };
            eq(
                col("topic0"),
                lit(Scalar::binary(ByteBuffer::copy_from(&key), Nullability::NonNullable)),
            )
        })) {
            filter_expr = and(filter_expr, topic0_pred);
        }
    }

    let array = file
        .scan()
        .map_err(|err| eyre!("scan vortex logs: {err}"))?
        .with_filter(filter_expr)
        .with_projection(select(LOG_COLUMNS, root()))
        .into_array_stream()
        .map_err(|err| eyre!("stream vortex logs: {err}"))?
        .read_all()
        .await
        .map_err(|err| eyre!("read vortex logs: {err}"))?;

    let mut ctx = session.create_execution_ctx();
    let struct_arr: VortexStructArray = array
        .execute(&mut ctx)
        .map_err(|err| eyre!("decode vortex logs: {err}"))?;

    let block_num = primitive_required::<i64>(&mut ctx, &struct_arr, "block_num")?;
    let log_idx = primitive_required::<i32>(&mut ctx, &struct_arr, "log_idx")?;
    let tx_idx = primitive_required::<i32>(&mut ctx, &struct_arr, "tx_idx")?;
    let tx_hash = varbin_required(&mut ctx, &struct_arr, "tx_hash")?;
    let address = varbin_required(&mut ctx, &struct_arr, "address")?;
    let topic0 = varbin_required(&mut ctx, &struct_arr, "topic0")?;
    let topic1 = varbin_optional(&mut ctx, &struct_arr, "topic1")?;
    let topic2 = varbin_optional(&mut ctx, &struct_arr, "topic2")?;
    let topic3 = varbin_optional(&mut ctx, &struct_arr, "topic3")?;
    let data = varbin_required(&mut ctx, &struct_arr, "data")?;
    let block_hash = varbin_required(&mut ctx, &struct_arr, "block_hash")?;

    let len = block_num.len();
    let mut out: Vec<Log> = Vec::with_capacity(len);
    for row in 0..len {
        let bn = block_num[row] as u64;
        if bn < from_block || bn > to_block {
            continue;
        }
        if address[row].len() != 20 {
            return Err(eyre!("address row {row} not 20 bytes"));
        }
        let addr = Address::from_slice(&address[row]);

        let mut topics: Vec<B256> = Vec::with_capacity(4);
        let t0_is_zero = topic0[row].iter().all(|b| *b == 0);
        if !t0_is_zero && topic0[row].len() == 32 {
            topics.push(B256::from_slice(&topic0[row]));
        }
        if let Some(t1) = topic1[row].as_ref().filter(|t| t.len() == 32) {
            topics.push(B256::from_slice(t1));
        }
        if let Some(t2) = topic2[row].as_ref().filter(|t| t.len() == 32) {
            topics.push(B256::from_slice(t2));
        }
        if let Some(t3) = topic3[row].as_ref().filter(|t| t.len() == 32) {
            topics.push(B256::from_slice(t3));
        }

        if !filter.matches(&addr, &topics) {
            continue;
        }

        let primitive = PrimitiveLog {
            address: addr,
            data: LogData::new(topics, PrimBytes::from(data[row].clone()))
                .ok_or_else(|| eyre!("log topics > 4 at row {row}"))?,
        };
        let canonical_bh = block_hashes
            .get(&bn)
            .copied()
            .or_else(|| (block_hash[row].len() == 32).then(|| B256::from_slice(&block_hash[row])));

        out.push(Log {
            inner: primitive,
            block_hash: canonical_bh,
            block_number: Some(bn),
            block_timestamp: None,
            transaction_hash: (tx_hash[row].len() == 32).then(|| B256::from_slice(&tx_hash[row])),
            transaction_index: Some(tx_idx[row] as u64),
            log_index: Some(log_idx[row] as u64),
            removed: false,
        });
    }
    Ok(out)
}

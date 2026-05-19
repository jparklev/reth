//! Vortex transactions chunk decode → [`reth_ethereum_primitives::TransactionSigned`].
//!
//! Schema parity with `crates/relay-rpc/src/backends/vortex_txs.rs`
//! in the relay project (23 fields). The relay-side decoder
//! materializes a `TxRow` (Clickhouse-shaped). This module skips
//! that intermediate and goes straight to reth's signed-tx type, so
//! the read RPC pipeline can serve `eth_getTransactionByHash`
//! directly from bucket-decoded data.
//!
//! Tx type byte (from the relay's TxRow.tx_type column) maps:
//! - 0 → Legacy
//! - 1 → EIP-2930
//! - 2 → EIP-1559
//! - 3 → EIP-4844
//! - 4 → EIP-7702
//!
//! Drift between this decoder and the relay-side writer (
//! `src/bucket/archive.rs::write_transactions_chunk`) silently
//! corrupts reads, so the test in `tests::decodes_synthetic_tx_chunk`
//! pins the schema column-by-column.

use std::sync::Arc;

use alloy_consensus::{
    EthereumTypedTransaction, TxEip1559, TxEip2930, TxEip4844, TxEip7702, TxLegacy,
};
use alloy_eips::{eip2930::AccessList, eip7702::SignedAuthorization};
use alloy_primitives::{Address, Bytes, Signature, TxKind, B256, U256};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use eyre::{eyre, Result};
use object_store::{path::Path as ObjectPath, ObjectStore, ObjectStoreExt};
use reth_ethereum_primitives::TransactionSigned;
use vortex::{
    array::{
        accessor::ArrayAccessor,
        arrays::{
            decimal::DecimalArrayExt, struct_::StructArrayExt, DecimalArray, PrimitiveArray,
            StructArray as VortexStructArray, VarBinViewArray as VortexVarBinViewArray,
        },
        dtype::DecimalType,
        expr::{col, eq, lit, root, select},
        scalar::Scalar,
        stream::ArrayStreamExt,
        ExecutionCtx, VortexSessionExecute,
    },
    session::VortexSession,
    VortexSessionDefault,
};
use vortex_buffer::ByteBuffer;
use vortex_file::{Footer, OpenOptionsSessionExt};
use vortex_io::object_store::ObjectStoreReadAt;

use super::VortexPreloadRange;

const TX_COLUMNS: &[&str] = &[
    "block_num",
    "block_hash",
    "idx",
    "hash",
    "type",
    "from",
    "to",
    "value",
    "input",
    "nonce",
    "gas_limit",
    "gas_price",
    "max_fee_per_gas",
    "max_priority_fee_per_gas",
    "max_fee_per_blob_gas",
    "chain_id",
    "access_list",
    "authorization_list",
    "blob_versioned_hashes",
    "v",
    "r",
    "s",
    "y_parity",
];

/// Decoded transaction with its block coordinates from the bucket.
#[derive(Debug, Clone)]
pub(crate) struct DecodedTx {
    pub block_num: u64,
    pub tx_idx: u32,
    pub tx: TransactionSigned,
}

/// Decode all transaction rows for the given block from a Vortex
/// `transactions` chunk.
pub(crate) async fn decode_transactions_chunk(
    store: Arc<dyn ObjectStore>,
    path: ObjectPath,
    block_num: u64,
    file_size: Option<u64>,
    footer_metadata_b64: Option<&str>,
    preload_ranges: &[VortexPreloadRange],
) -> Result<Vec<DecodedTx>> {
    let struct_arr =
        open_and_scan(store, path, file_size, footer_metadata_b64, preload_ranges, block_num)
            .await?;
    let session = VortexSession::default();
    let mut ctx = session.create_execution_ctx();
    rows_to_transactions(&mut ctx, struct_arr, Some(block_num))
}

/// Internal helper used by both production callers and tests.
async fn open_and_scan(
    store: Arc<dyn ObjectStore>,
    path: ObjectPath,
    file_size: Option<u64>,
    footer_metadata_b64: Option<&str>,
    preload_ranges: &[VortexPreloadRange],
    block_num: u64,
) -> Result<VortexStructArray> {
    let session = VortexSession::default();
    let handle = vortex_io::runtime::Handle::find()
        .ok_or_else(|| eyre!("no vortex runtime handle available"))?;
    let read_at = ObjectStoreReadAt::new(Arc::clone(&store), path.clone(), handle);

    let mut options = session.open_options();
    options = options.with_some_file_size(file_size);

    if let Some(b64) = footer_metadata_b64 {
        let bytes = BASE64.decode(b64).map_err(|err| eyre!("decode footer b64: {err}"))?;
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
        .map_err(|err| eyre!("open vortex transactions file: {err}"))?;

    let array = file
        .scan()
        .map_err(|err| eyre!("scan vortex transactions: {err}"))?
        .with_filter(eq(col("block_num"), lit(Scalar::from(block_num as i64))))
        .with_projection(select(TX_COLUMNS, root()))
        .into_array_stream()
        .map_err(|err| eyre!("stream vortex transactions: {err}"))?
        .read_all()
        .await
        .map_err(|err| eyre!("read vortex transactions: {err}"))?;
    let mut ctx = session.create_execution_ctx();
    array.execute(&mut ctx).map_err(|err| eyre!("decode vortex transactions: {err}"))
}

/// Convert a decoded struct array into [`DecodedTx`] rows. If
/// `block_filter` is `Some`, skips rows for other blocks (the
/// Vortex scan filter already prefilters, but a chunk that holds
/// many blocks needs the row-level cut too).
pub(crate) fn rows_to_transactions(
    ctx: &mut ExecutionCtx,
    struct_arr: VortexStructArray,
    block_filter: Option<u64>,
) -> Result<Vec<DecodedTx>> {
    let block_num = primitive_required::<i64>(ctx, &struct_arr, "block_num")?;
    let idx = primitive_required::<i32>(ctx, &struct_arr, "idx")?;
    let tx_type = primitive_required::<i8>(ctx, &struct_arr, "type")?;
    let nonce = primitive_required::<i64>(ctx, &struct_arr, "nonce")?;
    let gas_limit = primitive_required::<i64>(ctx, &struct_arr, "gas_limit")?;
    let chain_id = primitive_optional::<i64>(ctx, &struct_arr, "chain_id")?;
    let value = decimal_required(ctx, &struct_arr, "value")?;
    let gas_price = decimal_optional(ctx, &struct_arr, "gas_price")?;
    let max_fee_per_gas = decimal_optional(ctx, &struct_arr, "max_fee_per_gas")?;
    let max_priority_fee_per_gas = decimal_optional(ctx, &struct_arr, "max_priority_fee_per_gas")?;
    let max_fee_per_blob_gas = decimal_optional(ctx, &struct_arr, "max_fee_per_blob_gas")?;
    let v_str = decimal_required(ctx, &struct_arr, "v")?;
    let y_parity = primitive_optional::<i8>(ctx, &struct_arr, "y_parity")?;
    let hash = varbin_required(ctx, &struct_arr, "hash")?;
    let to = varbin_optional(ctx, &struct_arr, "to")?;
    let input = varbin_required(ctx, &struct_arr, "input")?;
    let access_list = json_optional(ctx, &struct_arr, "access_list")?;
    let authorization_list = json_optional(ctx, &struct_arr, "authorization_list")?;
    let blob_versioned_hashes = blob_hashes(ctx, &struct_arr, "blob_versioned_hashes")?;
    let r = varbin_required(ctx, &struct_arr, "r")?;
    let s = varbin_required(ctx, &struct_arr, "s")?;

    let len = struct_arr.len();
    let mut out = Vec::with_capacity(len);
    for row in 0..len {
        let row_block = block_num[row] as u64;
        if let Some(filter) = block_filter &&
            row_block != filter
        {
            continue;
        }
        let row_idx = idx[row] as u32;
        let tx_hash = bytes_to_b256(&hash[row])
            .map_err(|err| eyre!("row {row} (block {row_block} idx {row_idx}) hash: {err}"))?;
        let to_kind = match &to[row] {
            Some(bytes) if !bytes.is_empty() => {
                TxKind::Call(bytes_to_address(bytes).map_err(|err| eyre!("row {row} to: {err}"))?)
            }
            _ => TxKind::Create,
        };
        let to_addr_required = match &to[row] {
            Some(bytes) if !bytes.is_empty() => {
                bytes_to_address(bytes).map_err(|err| eyre!("row {row} to: {err}"))?
            }
            _ => Address::ZERO,
        };
        let value_u256 =
            parse_u256_dec(&value[row]).map_err(|err| eyre!("row {row} value: {err}"))?;
        let chain_id_u64 = chain_id[row].map(|v| v as u64);
        let nonce_u64 = nonce[row] as u64;
        let gas_limit_u64 = gas_limit[row] as u64;
        let input_bytes = Bytes::from(input[row].clone());
        let access_list = if let Some(value) = access_list[row].clone() {
            serde_json::from_value::<AccessList>(value)
                .map_err(|err| eyre!("row {row} access_list: {err}"))?
        } else {
            AccessList::default()
        };
        let authorization_list_typed: Vec<SignedAuthorization> =
            if let Some(value) = authorization_list[row].clone() {
                serde_json::from_value(value)
                    .map_err(|err| eyre!("row {row} authorization_list: {err}"))?
            } else {
                Vec::new()
            };

        // Signature scalars.
        let r_u256 = U256::try_from_be_slice(&r[row])
            .ok_or_else(|| eyre!("row {row} signature r: not 32 bytes"))?;
        let s_u256 = U256::try_from_be_slice(&s[row])
            .ok_or_else(|| eyre!("row {row} signature s: not 32 bytes"))?;
        let parity = match (tx_type[row] as u8, y_parity[row]) {
            (0, _) => {
                // Legacy: derive parity from v.
                let v = parse_u256_dec(&v_str[row])
                    .map_err(|err| eyre!("row {row} legacy v: {err}"))?;
                legacy_parity(v, chain_id_u64)
            }
            (_, Some(p)) => p != 0,
            (_, None) => {
                return Err(eyre!(
                    "row {row} (block {row_block} idx {row_idx}) typed tx \
                     missing y_parity"
                ));
            }
        };
        let signature = Signature::new(r_u256, s_u256, parity);

        let transaction: EthereumTypedTransaction<TxEip4844> = match tx_type[row] as u8 {
            0 => EthereumTypedTransaction::Legacy(TxLegacy {
                chain_id: chain_id_u64,
                nonce: nonce_u64,
                gas_price: parse_u128_opt(&gas_price[row])
                    .map_err(|err| eyre!("row {row} legacy gas_price: {err}"))?
                    .unwrap_or_default(),
                gas_limit: gas_limit_u64,
                to: to_kind,
                value: value_u256,
                input: input_bytes,
            }),
            1 => EthereumTypedTransaction::Eip2930(TxEip2930 {
                chain_id: chain_id_u64
                    .ok_or_else(|| eyre!("row {row} eip2930 missing chain_id"))?,
                nonce: nonce_u64,
                gas_price: parse_u128_opt(&gas_price[row])
                    .map_err(|err| eyre!("row {row} eip2930 gas_price: {err}"))?
                    .unwrap_or_default(),
                gas_limit: gas_limit_u64,
                to: to_kind,
                value: value_u256,
                access_list,
                input: input_bytes,
            }),
            2 => EthereumTypedTransaction::Eip1559(TxEip1559 {
                chain_id: chain_id_u64
                    .ok_or_else(|| eyre!("row {row} eip1559 missing chain_id"))?,
                nonce: nonce_u64,
                gas_limit: gas_limit_u64,
                max_fee_per_gas: parse_u128_opt(&max_fee_per_gas[row])
                    .map_err(|err| eyre!("row {row} eip1559 max_fee_per_gas: {err}"))?
                    .unwrap_or_default(),
                max_priority_fee_per_gas: parse_u128_opt(&max_priority_fee_per_gas[row])
                    .map_err(|err| eyre!("row {row} eip1559 max_priority_fee_per_gas: {err}"))?
                    .unwrap_or_default(),
                to: to_kind,
                value: value_u256,
                access_list,
                input: input_bytes,
            }),
            3 => EthereumTypedTransaction::Eip4844(TxEip4844 {
                chain_id: chain_id_u64
                    .ok_or_else(|| eyre!("row {row} eip4844 missing chain_id"))?,
                nonce: nonce_u64,
                gas_limit: gas_limit_u64,
                max_fee_per_gas: parse_u128_opt(&max_fee_per_gas[row])
                    .map_err(|err| eyre!("row {row} eip4844 max_fee_per_gas: {err}"))?
                    .unwrap_or_default(),
                max_priority_fee_per_gas: parse_u128_opt(&max_priority_fee_per_gas[row])
                    .map_err(|err| eyre!("row {row} eip4844 max_priority_fee_per_gas: {err}"))?
                    .unwrap_or_default(),
                to: to_addr_required,
                value: value_u256,
                access_list,
                blob_versioned_hashes: blob_versioned_hashes[row]
                    .iter()
                    .map(|bytes| bytes_to_b256(bytes))
                    .collect::<Result<Vec<_>>>()?,
                max_fee_per_blob_gas: parse_u128_opt(&max_fee_per_blob_gas[row])
                    .map_err(|err| eyre!("row {row} eip4844 max_fee_per_blob_gas: {err}"))?
                    .unwrap_or_default(),
                input: input_bytes,
            }),
            4 => EthereumTypedTransaction::Eip7702(TxEip7702 {
                chain_id: chain_id_u64
                    .ok_or_else(|| eyre!("row {row} eip7702 missing chain_id"))?,
                nonce: nonce_u64,
                gas_limit: gas_limit_u64,
                max_fee_per_gas: parse_u128_opt(&max_fee_per_gas[row])
                    .map_err(|err| eyre!("row {row} eip7702 max_fee_per_gas: {err}"))?
                    .unwrap_or_default(),
                max_priority_fee_per_gas: parse_u128_opt(&max_priority_fee_per_gas[row])
                    .map_err(|err| eyre!("row {row} eip7702 max_priority_fee_per_gas: {err}"))?
                    .unwrap_or_default(),
                to: to_addr_required,
                value: value_u256,
                access_list,
                authorization_list: authorization_list_typed,
                input: input_bytes,
            }),
            other => return Err(eyre!("row {row} unknown tx_type {other}")),
        };

        let signed = TransactionSigned::new_unchecked(transaction, signature, tx_hash);
        out.push(DecodedTx { block_num: row_block, tx_idx: row_idx, tx: signed });
    }
    out.sort_by_key(|d| (d.block_num, d.tx_idx));
    Ok(out)
}

fn legacy_parity(v: U256, chain_id: Option<u64>) -> bool {
    // Pre-EIP-155: v ∈ {27,28}. Post-EIP-155: v = chain_id*2 + 35 + parity.
    let v64 = v.to::<u128>();
    if v64 == 27 || v64 == 28 {
        v64 == 28
    } else if let Some(cid) = chain_id {
        let base = (cid as u128).saturating_mul(2).saturating_add(35);
        (v64.saturating_sub(base)) & 1 == 1
    } else {
        (v64 & 1) == 1
    }
}

fn primitive_required<T>(
    ctx: &mut ExecutionCtx,
    array: &VortexStructArray,
    name: &str,
) -> Result<Vec<T>>
where
    T: vortex::array::dtype::NativePType + Copy + Default,
{
    Ok(primitive_optional(ctx, array, name)?.into_iter().map(|v| v.unwrap_or_default()).collect())
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
        .map_err(|err| eyre!("vortex transactions missing {name}: {err}"))?;
    let values: PrimitiveArray =
        field.clone().execute(ctx).map_err(|err| eyre!("decode {name}: {err}"))?;
    Ok(values.with_iterator(|iter| iter.map(|v| v.copied()).collect::<Vec<_>>()))
}

fn decimal_required(
    ctx: &mut ExecutionCtx,
    array: &VortexStructArray,
    name: &str,
) -> Result<Vec<String>> {
    Ok(decimal_optional(ctx, array, name)?
        .into_iter()
        .map(|v| v.unwrap_or_else(|| "0".to_string()))
        .collect())
}

fn decimal_optional(
    ctx: &mut ExecutionCtx,
    array: &VortexStructArray,
    name: &str,
) -> Result<Vec<Option<String>>> {
    let field = array
        .unmasked_field_by_name(name)
        .map_err(|err| eyre!("vortex transactions missing {name}: {err}"))?;
    let values: DecimalArray =
        field.clone().execute(ctx).map_err(|err| eyre!("decode {name}: {err}"))?;
    if values.scale() != 0 {
        return Err(eyre!("expected integer decimal scale for {name}"));
    }
    let validity = values.validity().map_err(|err| eyre!("validity {name}: {err}"))?;
    let mut out = match values.values_type() {
        DecimalType::I8 => buf_to_strs(values.buffer::<i8>()),
        DecimalType::I16 => buf_to_strs(values.buffer::<i16>()),
        DecimalType::I32 => buf_to_strs(values.buffer::<i32>()),
        DecimalType::I64 => buf_to_strs(values.buffer::<i64>()),
        DecimalType::I128 => buf_to_strs(values.buffer::<i128>()),
        DecimalType::I256 => return Err(eyre!("i256 decimal not supported for {name}")),
    };
    for (idx, value) in out.iter_mut().enumerate() {
        if !validity.is_valid(idx).map_err(|err| eyre!("validity is_valid {name}: {err}"))? {
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
    Ok(varbin_optional(ctx, array, name)?.into_iter().map(|v| v.unwrap_or_default()).collect())
}

fn varbin_optional(
    ctx: &mut ExecutionCtx,
    array: &VortexStructArray,
    name: &str,
) -> Result<Vec<Option<Vec<u8>>>> {
    let field = array
        .unmasked_field_by_name(name)
        .map_err(|err| eyre!("vortex transactions missing {name}: {err}"))?;
    let values: VortexVarBinViewArray =
        field.clone().execute(ctx).map_err(|err| eyre!("decode {name}: {err}"))?;
    Ok(values.with_iterator(|iter| iter.map(|v| v.map(|b| b.to_vec())).collect::<Vec<_>>()))
}

fn json_optional(
    ctx: &mut ExecutionCtx,
    array: &VortexStructArray,
    name: &str,
) -> Result<Vec<Option<serde_json::Value>>> {
    varbin_optional(ctx, array, name)?
        .into_iter()
        .map(|value| match value {
            Some(bytes) if !bytes.is_empty() => serde_json::from_slice::<serde_json::Value>(&bytes)
                .map(Some)
                .map_err(|err| eyre!("decode {name} JSON: {err}")),
            _ => Ok(None),
        })
        .collect()
}

fn blob_hashes(
    ctx: &mut ExecutionCtx,
    array: &VortexStructArray,
    name: &str,
) -> Result<Vec<Vec<Vec<u8>>>> {
    varbin_required(ctx, array, name)?
        .into_iter()
        .map(|bytes| {
            if bytes.is_empty() {
                Ok(Vec::new())
            } else {
                serde_json::from_slice(&bytes).map_err(|err| eyre!("decode {name} JSON: {err}"))
            }
        })
        .collect()
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

fn parse_u256_dec(s: &str) -> Result<U256> {
    U256::from_str_radix(s, 10).map_err(|err| eyre!("parse U256 from '{s}': {err}"))
}

fn parse_u128_opt(s: &Option<String>) -> Result<Option<u128>> {
    Ok(match s {
        Some(s) => {
            Some(u128::from_str_radix(s, 10).map_err(|err| eyre!("parse u128 '{s}': {err}"))?)
        }
        None => None,
    })
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use object_store::{memory::InMemory, ObjectStoreExt};
    use vortex::{
        array::{
            arrays::StructArray,
            builders::{ArrayBuilder, VarBinViewBuilder},
            dtype::{DType, DecimalDType, FieldNames, Nullability},
            validity::Validity,
            IntoArray,
        },
        buffer::{Buffer, ByteBufferMut},
    };
    use vortex_file::WriteOptionsSessionExt;

    /// Round-trip: write a synthetic in-memory `transactions` chunk
    /// matching the relay-side writer schema, then decode it via
    /// `decode_transactions_chunk`. Verifies the schema column
    /// mapping is in lockstep with the writer (`vortex_txs.rs`
    /// tests in relay-rpc use the identical column layout).
    #[tokio::test]
    async fn decodes_synthetic_tx_chunk() {
        let store = Arc::new(InMemory::new()) as Arc<dyn ObjectStore>;
        let chunk_path = "epoch-7/transactions/test-tx-sha.vortex";
        let object_path = ObjectPath::from(format!("chunks/{chunk_path}"));
        let bytes = build_synthetic_tx_chunk().await;
        let file_size = bytes.len() as u64;
        store
            .put(&object_path, bytes.freeze().to_vec().into())
            .await
            .expect("put vortex test object");

        let decoded =
            decode_transactions_chunk(store, object_path, 101, Some(file_size), None, &[])
                .await
                .expect("decode tx chunk");
        // Two rows in block 101 (the synthetic also includes a
        // block 100 row, which the block_num filter prunes).
        assert_eq!(decoded.len(), 2, "decoded {decoded:?}");
        assert_eq!(decoded[0].block_num, 101);
        assert_eq!(decoded[0].tx_idx, 0);
        // EIP-1559 row.
        let signed = &decoded[0].tx;
        use alloy_consensus::Transaction as _;
        assert_eq!(signed.tx_type() as u8, 2);
        assert_eq!(signed.nonce(), 9);
        assert_eq!(signed.gas_limit(), 21_000);
        // Second row in block 101: contract creation (`to=None`)
        // legacy-style decoded as type 0 with chain_id=Some(1).
        assert_eq!(decoded[1].tx_idx, 1);
        match &decoded[1].tx {
            TransactionSigned::Legacy(signed_legacy) => {
                let tx = signed_legacy.tx();
                assert_eq!(tx.chain_id, Some(1));
                assert_eq!(tx.to, TxKind::Create);
            }
            other => panic!("expected legacy tx, got {other:?}"),
        }
    }

    /// Build a 3-row vortex transactions chunk: block 100 (filtered
    /// out at decode time), and two rows for block 101 (1559 + legacy).
    pub(crate) async fn build_synthetic_tx_chunk() -> ByteBufferMut {
        let session = VortexSession::default();
        let data = StructArray::new(
            FieldNames::from(TX_COLUMNS),
            vec![
                // block_num
                primitive_array([100_i64, 101, 101]),
                // block_hash
                binary_array([Some(vec![0x10; 32]), Some(vec![0x11; 32]), Some(vec![0x12; 32])]),
                // idx
                primitive_array([0_i32, 0, 1]),
                // hash (use deterministic distinct hashes; the
                // verify-on-decode debug_assert is conservative —
                // we leave actual keccak verification to caller).
                binary_array([
                    Some(vec![0x20; 32]),
                    Some(test_keccak_hash_marker(0)),
                    Some(test_keccak_hash_marker(1)),
                ]),
                // type: 2 (1559), 2 (1559), 0 (legacy)
                primitive_array([2_i8, 2, 0]),
                // from
                binary_array([Some(vec![0x30; 20]), Some(vec![0x31; 20]), Some(vec![0x32; 20])]),
                // to: None for the legacy row (contract creation)
                binary_array([Some(vec![0x40; 20]), Some(vec![0x41; 20]), None]),
                // value
                decimal_array([500_i128, 1000, 0]),
                // input
                binary_array([
                    Some(b"ignored".to_vec()),
                    Some(b"calldata-a".to_vec()),
                    Some(Vec::new()),
                ]),
                // nonce
                primitive_array([1_i64, 9, 10]),
                // gas_limit
                primitive_array([30_000_i64, 21_000, 50_000]),
                // gas_price (legacy needs this; nullable for typed)
                decimal_nullable_array([Some(6_i128), None, Some(20)]),
                // max_fee_per_gas
                decimal_nullable_array([None, Some(8_i128), None]),
                // max_priority_fee_per_gas
                decimal_nullable_array([None, Some(2_i128), None]),
                // max_fee_per_blob_gas
                decimal_nullable_array([None::<i128>, None, None]),
                // chain_id
                primitive_nullable_array([Some(1_i64), Some(1), Some(1)]),
                // access_list
                binary_array([Some(b"[]".to_vec()), Some(b"[]".to_vec()), Some(b"[]".to_vec())]),
                // authorization_list
                binary_array([None, None, None]),
                // blob_versioned_hashes
                binary_array([Some(b"[]".to_vec()), Some(b"[]".to_vec()), Some(b"[]".to_vec())]),
                // v: legacy uses 27 / chain_id*2+35+parity; typed uses
                // 0/1 (we put y_parity column for typed below). We
                // store v=1 for typed (will be ignored), and 27 for
                // legacy → parity=false.
                decimal_array([1_i128, 1, 27]),
                // r
                binary_array([Some(vec![0x50; 32]), Some(vec![0x51; 32]), Some(vec![0x52; 32])]),
                // s
                binary_array([Some(vec![0x60; 32]), Some(vec![0x61; 32]), Some(vec![0x62; 32])]),
                // y_parity (typed only)
                primitive_nullable_array([Some(0_i8), Some(1), None]),
            ],
            3,
            Validity::NonNullable,
        )
        .into_array();

        let mut out = ByteBufferMut::empty();
        session
            .write_options()
            .write(&mut out, data.to_array_stream())
            .await
            .expect("write test vortex file");
        out
    }

    fn test_keccak_hash_marker(idx: u8) -> Vec<u8> {
        // The keccak of the encoded tx is deterministic but
        // expensive to compute here; placeholder hashes work because
        // `TransactionSigned::new` only seeds the OnceLock — it
        // doesn't re-keccak unless `hash()` is called. The
        // round-trip test doesn't call `hash()`.
        let mut v = vec![0xa0; 32];
        v[31] = idx;
        v
    }

    fn primitive_array<T>(values: impl IntoIterator<Item = T>) -> vortex::array::ArrayRef
    where
        T: vortex::array::dtype::NativePType,
    {
        PrimitiveArray::new(
            Buffer::<T>::from(values.into_iter().collect::<Vec<_>>()),
            Validity::NonNullable,
        )
        .into_array()
    }

    fn primitive_nullable_array<T, const N: usize>(
        values: [Option<T>; N],
    ) -> vortex::array::ArrayRef
    where
        T: vortex::array::dtype::NativePType,
    {
        PrimitiveArray::new(
            Buffer::<T>::from(values.iter().map(|v| v.unwrap_or_default()).collect::<Vec<_>>()),
            Validity::from_iter(values.iter().map(Option::is_some)),
        )
        .into_array()
    }

    fn decimal_array(values: impl IntoIterator<Item = i128>) -> vortex::array::ArrayRef {
        DecimalArray::from_iter(values, DecimalDType::new(38, 0)).into_array()
    }

    fn decimal_nullable_array<const N: usize>(
        values: [Option<i128>; N],
    ) -> vortex::array::ArrayRef {
        DecimalArray::from_option_iter(values, DecimalDType::new(38, 0)).into_array()
    }

    fn binary_array<const N: usize>(values: [Option<Vec<u8>>; N]) -> vortex::array::ArrayRef {
        let mut builder =
            VarBinViewBuilder::with_capacity(DType::Binary(Nullability::Nullable), values.len());
        for value in values {
            match value {
                Some(v) => builder.append_value(v),
                None => builder.append_null(),
            }
        }
        ArrayBuilder::finish(&mut builder)
    }
}

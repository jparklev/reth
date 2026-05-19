//! Vortex receipts chunk decode → [`reth_ethereum_primitives::Receipt`].
//!
//! Schema parity with `crates/relay-rpc/src/backends/vortex_receipts.rs`
//! (14 columns). The relay-side decoder materializes a
//! `ReceiptRow`; we skip that and emit reth's `Receipt` directly,
//! joining the per-block `vortex_logs` chunk by `tx_idx` for the
//! `logs` field.

use std::collections::BTreeMap;
use std::sync::Arc;

use alloy_consensus::TxType;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use eyre::{Result, eyre};
use object_store::{ObjectStore, ObjectStoreExt};
use object_store::path::Path as ObjectPath;
use reth_ethereum_primitives::Receipt;
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
use super::log_decode::DecodedLog;

const RECEIPT_COLUMNS: &[&str] = &[
    "block_num",
    "block_hash",
    "tx_idx",
    "tx_hash",
    "from",
    "to",
    "contract_address",
    "status",
    "gas_used",
    "cumulative_gas_used",
    "effective_gas_price",
    "blob_gas_used",
    "blob_gas_price",
    "logs_bloom",
];

/// One decoded receipt row with its block coordinates, ready to be
/// matched against the per-block logs chunk.
#[derive(Debug, Clone)]
pub(crate) struct DecodedReceipt {
    pub block_num: u64,
    pub tx_idx: u32,
    pub tx_hash: alloy_primitives::B256,
    pub tx_type: u8,
    pub receipt: Receipt,
}

/// Decode all receipt rows for the given block, joining logs by
/// `tx_idx`. `logs_by_tx_idx` is the output of
/// [`crate::log_decode::decode_logs_chunk`] grouped by `tx_idx`.
pub(crate) async fn decode_receipts_chunk(
    store: Arc<dyn ObjectStore>,
    path: ObjectPath,
    block_num: u64,
    file_size: Option<u64>,
    footer_metadata_b64: Option<&str>,
    preload_ranges: &[VortexPreloadRange],
    logs_by_tx_idx: &BTreeMap<u32, Vec<alloy_primitives::Log>>,
    tx_types_by_tx_idx: &BTreeMap<u32, u8>,
) -> Result<Vec<DecodedReceipt>> {
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
        .map_err(|err| eyre!("open vortex receipts file: {err}"))?;

    let array = file
        .scan()
        .map_err(|err| eyre!("scan vortex receipts: {err}"))?
        .with_filter(eq(col("block_num"), lit(Scalar::from(block_num as i64))))
        .with_projection(select(RECEIPT_COLUMNS, root()))
        .into_array_stream()
        .map_err(|err| eyre!("stream vortex receipts: {err}"))?
        .read_all()
        .await
        .map_err(|err| eyre!("read vortex receipts: {err}"))?;
    let mut ctx = session.create_execution_ctx();
    let struct_arr: VortexStructArray =
        array.execute(&mut ctx).map_err(|err| eyre!("decode vortex receipts: {err}"))?;
    rows_to_receipts(&mut ctx, struct_arr, Some(block_num), logs_by_tx_idx, tx_types_by_tx_idx)
}

pub(crate) fn rows_to_receipts(
    ctx: &mut ExecutionCtx,
    struct_arr: VortexStructArray,
    block_filter: Option<u64>,
    logs_by_tx_idx: &BTreeMap<u32, Vec<alloy_primitives::Log>>,
    tx_types_by_tx_idx: &BTreeMap<u32, u8>,
) -> Result<Vec<DecodedReceipt>> {
    let block_num = primitive_required::<i64>(ctx, &struct_arr, "block_num")?;
    let tx_idx = primitive_required::<i32>(ctx, &struct_arr, "tx_idx")?;
    let status = primitive_required::<i8>(ctx, &struct_arr, "status")?;
    let cumulative_gas_used = primitive_required::<i64>(ctx, &struct_arr, "cumulative_gas_used")?;
    let tx_hash = varbin_required(ctx, &struct_arr, "tx_hash")?;

    let len = struct_arr.len();
    let mut out = Vec::with_capacity(len);
    for row in 0..len {
        let row_block = block_num[row] as u64;
        if let Some(filter) = block_filter
            && row_block != filter
        {
            continue;
        }
        let idx = tx_idx[row] as u32;
        let logs = logs_by_tx_idx.get(&idx).cloned().unwrap_or_default();
        let tx_type_byte = tx_types_by_tx_idx.get(&idx).copied().unwrap_or(0);
        let tx_type = TxType::try_from(tx_type_byte)
            .map_err(|err| eyre!("row {row} tx_type {tx_type_byte}: {err}"))?;
        let tx_hash_b = bytes_to_b256(&tx_hash[row])
            .map_err(|err| eyre!("row {row} tx_hash: {err}"))?;
        let receipt = Receipt {
            tx_type,
            success: status[row] != 0,
            cumulative_gas_used: cumulative_gas_used[row] as u64,
            logs,
        };
        out.push(DecodedReceipt {
            block_num: row_block,
            tx_idx: idx,
            tx_hash: tx_hash_b,
            tx_type: tx_type_byte,
            receipt,
        });
    }
    out.sort_by_key(|d| (d.block_num, d.tx_idx));
    Ok(out)
}

/// Group logs by `tx_idx`. Logs within each group keep their
/// (tx_idx, log_idx) ordering from the decode.
pub(crate) fn group_logs_by_tx_idx(
    logs: Vec<DecodedLog>,
) -> BTreeMap<u32, Vec<alloy_primitives::Log>> {
    let mut map: BTreeMap<u32, Vec<alloy_primitives::Log>> = BTreeMap::new();
    for d in logs {
        map.entry(d.tx_idx).or_default().push(d.log);
    }
    map
}

fn primitive_required<T>(
    ctx: &mut ExecutionCtx,
    array: &VortexStructArray,
    name: &str,
) -> Result<Vec<T>>
where
    T: vortex::array::dtype::NativePType + Copy + Default,
{
    let field = array
        .unmasked_field_by_name(name)
        .map_err(|err| eyre!("vortex receipts missing {name}: {err}"))?;
    let values: PrimitiveArray =
        field.clone().execute(ctx).map_err(|err| eyre!("decode {name}: {err}"))?;
    Ok(values.with_iterator(|iter| {
        iter.map(|v| v.copied().unwrap_or_default()).collect::<Vec<_>>()
    }))
}

fn varbin_required(
    ctx: &mut ExecutionCtx,
    array: &VortexStructArray,
    name: &str,
) -> Result<Vec<Vec<u8>>> {
    let field = array
        .unmasked_field_by_name(name)
        .map_err(|err| eyre!("vortex receipts missing {name}: {err}"))?;
    let values: VortexVarBinViewArray =
        field.clone().execute(ctx).map_err(|err| eyre!("decode {name}: {err}"))?;
    Ok(values.with_iterator(|iter| {
        iter.map(|v| v.map(|b| b.to_vec()).unwrap_or_default()).collect::<Vec<_>>()
    }))
}

fn bytes_to_b256(b: &[u8]) -> Result<alloy_primitives::B256> {
    if b.len() != 32 {
        return Err(eyre!("expected 32-byte hash, got {}", b.len()));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(b);
    Ok(alloy_primitives::B256::from(out))
}

// `DecimalArray` is referenced here to keep the imports honest —
// the receipts schema does carry decimal columns (effective_gas_price,
// blob_gas_price), but we don't pull them into [`Receipt`] (reth's
// Receipt struct doesn't carry effective_gas_price; that's a
// pseudo-field surfaced by the RPC layer on top of meta).
#[allow(dead_code)]
fn _decimal_unused(_a: DecimalArray, _t: DecimalType) {}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use object_store::ObjectStoreExt;
    use object_store::memory::InMemory;
    use vortex::array::IntoArray;
    use vortex::array::arrays::StructArray;
    use vortex::array::builders::{ArrayBuilder, VarBinViewBuilder};
    use vortex::array::dtype::{DType, DecimalDType, FieldNames, Nullability};
    use vortex::array::validity::Validity;
    use vortex::buffer::{Buffer, ByteBufferMut};
    use vortex_file::WriteOptionsSessionExt;

    #[tokio::test]
    async fn decodes_synthetic_receipts_chunk() {
        let store = Arc::new(InMemory::new()) as Arc<dyn ObjectStore>;
        let chunk_path = "epoch-7/receipts/test-receipt-sha.vortex";
        let object_path = ObjectPath::from(format!("chunks/{chunk_path}"));
        let bytes = build_synthetic_receipt_chunk().await;
        let file_size = bytes.len() as u64;
        store
            .put(&object_path, bytes.freeze().to_vec().into())
            .await
            .expect("put receipt object");

        // Synthetic logs/tx-types: tx 0 has one log; tx 1 none.
        let mut logs = BTreeMap::new();
        logs.insert(
            0_u32,
            vec![alloy_primitives::Log {
                address: alloy_primitives::Address::from([0x11; 20]),
                data: alloy_primitives::LogData::new(
                    vec![alloy_primitives::B256::from([0xa1; 32])],
                    alloy_primitives::Bytes::from(b"data-0".to_vec()),
                )
                .unwrap(),
            }],
        );
        let mut tx_types = BTreeMap::new();
        tx_types.insert(0_u32, 2_u8); // EIP-1559
        tx_types.insert(1_u32, 0_u8); // Legacy

        let decoded = decode_receipts_chunk(
            store,
            object_path,
            101,
            Some(file_size),
            None,
            &[],
            &logs,
            &tx_types,
        )
        .await
        .expect("decode receipts");
        assert_eq!(decoded.len(), 2);
        assert_eq!(decoded[0].block_num, 101);
        assert_eq!(decoded[0].tx_idx, 0);
        assert_eq!(decoded[0].receipt.tx_type as u8, 2);
        assert!(decoded[0].receipt.success);
        assert_eq!(decoded[0].receipt.cumulative_gas_used, 22_000);
        assert_eq!(decoded[0].receipt.logs.len(), 1);
        assert_eq!(decoded[1].tx_idx, 1);
        assert_eq!(decoded[1].receipt.tx_type as u8, 0);
        assert!(!decoded[1].receipt.success);
        assert!(decoded[1].receipt.logs.is_empty());
    }

    pub(crate) async fn build_synthetic_receipt_chunk() -> ByteBufferMut {
        let session = VortexSession::default();
        let data = StructArray::new(
            FieldNames::from(RECEIPT_COLUMNS),
            vec![
                primitive_array([100_i64, 101, 101]),
                binary_array([
                    Some(vec![0x10; 32]),
                    Some(vec![0x11; 32]),
                    Some(vec![0x12; 32]),
                ]),
                primitive_array([0_i32, 0, 1]),
                binary_array([
                    Some(vec![0x20; 32]),
                    Some(vec![0x21; 32]),
                    Some(vec![0x22; 32]),
                ]),
                binary_array([
                    Some(vec![0x30; 20]),
                    Some(vec![0x31; 20]),
                    Some(vec![0x32; 20]),
                ]),
                binary_array([None, Some(vec![0x41; 20]), None]),
                binary_array([None, None, Some(vec![0x52; 20])]),
                primitive_array([1_i8, 1, 0]),
                primitive_array([10_000_i64, 21_000, 30_000]),
                primitive_array([10_000_i64, 22_000, 52_000]),
                decimal_array([6_i128, 7, 8]),
                primitive_nullable_array([None, Some(3_i64), None]),
                decimal_nullable_array([None, Some(9_i128), None]),
                binary_array([
                    Some(vec![0x70; 256]),
                    Some(vec![0x71; 256]),
                    Some(vec![0x72; 256]),
                ]),
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
            .expect("write receipt test chunk");
        out
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

    fn primitive_nullable_array<T, const N: usize>(values: [Option<T>; N]) -> vortex::array::ArrayRef
    where
        T: vortex::array::dtype::NativePType,
    {
        PrimitiveArray::new(
            Buffer::<T>::from(
                values
                    .iter()
                    .map(|v| v.unwrap_or_default())
                    .collect::<Vec<_>>(),
            ),
            Validity::from_iter(values.iter().map(Option::is_some)),
        )
        .into_array()
    }

    fn decimal_array(values: impl IntoIterator<Item = i128>) -> vortex::array::ArrayRef {
        DecimalArray::from_iter(values, DecimalDType::new(38, 0)).into_array()
    }

    fn decimal_nullable_array<const N: usize>(values: [Option<i128>; N]) -> vortex::array::ArrayRef {
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

#!/usr/bin/env bash
# Smoke test the witness-emit pipeline after starting the systemd units.
#
# Confirms:
#   1. The ExEx is emitting witness files to /var/lib/witness-emit/inbox/.
#   2. The uploader is uploading + clearing the inbox.
#   3. The new head.json under witnesses/exex/ is being updated.
#   4. A representative file is byte-compatible with the existing witness-stream
#      validator.

set -euo pipefail

EMIT_DIR="${EMIT_DIR:-/var/lib/witness-emit/inbox}"
BUCKET="${BUCKET:-reth-spike-fsn1}"
ENDPOINT="${ENDPOINT:-https://fsn1.your-objectstorage.com}"
PREFIX="${PREFIX:-witnesses/exex}"
PUBKEY="${PUBKEY:-/var/lib/reth/relay-indexer/writer.pub}"

echo "==> ExEx output dir: $EMIT_DIR"
ls -la "$EMIT_DIR" | head -5
local_n=$(ls "$EMIT_DIR"/*.witness.zst 2>/dev/null | wc -l || echo 0)
echo "$local_n witness files currently buffered"

echo "==> Live manifest from S3:"
curl -sf "$ENDPOINT/$BUCKET/$PREFIX/head.json" | jq '{
  version, writer_id, updated_at,
  head: .head | {block_number, block_hash, parent_hash, size_bytes},
  entries: (.entries | length)
}'

echo "==> Tail of ExEx stats:"
tail -3 /var/lib/witness-emit/exex-stats.jsonl | jq -c

echo "==> Tail of uploader stats:"
tail -3 /var/lib/witness-emit/uploader-stats.jsonl | jq -c

echo "==> Re-validating the latest witness via the existing witness-stream binary..."
witness-stream \
    --endpoint "$ENDPOINT" \
    --bucket   "$BUCKET" \
    --region   fsn1 \
    --manifest "$PREFIX/head.json" \
    --pubkey   "$PUBKEY" 2>&1 | tail -8

echo "==> Done"

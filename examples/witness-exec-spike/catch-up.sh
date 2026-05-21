#!/usr/bin/env bash
# Catch-up benchmark: fetch the current head.json from S3, validate every
# witness in it (or up to --limit), and report time to drain the backlog.
#
# Run from a fresh client (cold caches). Uses the HTTPS path (--base-url)
# to avoid AWS SDK overhead.
#
# Usage:
#   ./catch-up.sh                       # default: validate all entries
#   ./catch-up.sh 50                    # validate 50 entries
set -euo pipefail
LIMIT="${1:-0}"
BIN="${WITNESS_STREAM:-$(dirname "$0")/../../target/release/witness-stream}"
PUBKEY="${WITNESS_PUBKEY:-/tmp/witness-keys/primary.pub}"
BUCKET="${S3_BUCKET:-reth-spike-fsn1}"
BASE_URL="${WITNESS_BASE_URL:-https://fsn1.your-objectstorage.com/${BUCKET}}"
MANIFEST="${S3_MANIFEST:-witnesses/live/head.json}"
ENDPOINT="${S3_ENDPOINT:-https://fsn1.your-objectstorage.com}"
REGION="${S3_REGION:-fsn1}"

if [[ ! -x "$BIN" ]]; then
    echo "missing witness-stream binary at $BIN (set WITNESS_STREAM=)" >&2
    exit 1
fi
if [[ ! -f "$PUBKEY" ]]; then
    echo "missing pubkey at $PUBKEY (set WITNESS_PUBKEY=)" >&2
    exit 1
fi

extra=()
[[ "$LIMIT" -gt 0 ]] && extra+=(--limit "$LIMIT")

start=$(date +%s)
echo "[catch-up] starting at $(date -u +%FT%TZ) using base_url=$BASE_URL"
"$BIN" \
    --bucket   "$BUCKET" \
    --base-url "$BASE_URL" \
    --endpoint "$ENDPOINT" \
    --region   "$REGION" \
    --manifest "$MANIFEST" \
    --pubkey   "$PUBKEY" \
    "${extra[@]}"
end=$(date +%s)
echo "[catch-up] finished in $((end - start))s"

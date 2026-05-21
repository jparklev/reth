#!/usr/bin/env bash
# Dev-mode end-to-end smoke test for the witness-emit pipeline.
#
# Runs reth-witness-emit-node in --dev mode with auto-mining, submits dev
# transactions to force block production, then verifies witness files appear
# in the emit-dir with sensible stats.
#
# Usage: ./dev-smoke.sh [BINARY] [HTTP_PORT]
#   BINARY     defaults to ./target/release/reth-witness-emit-node
#   HTTP_PORT  defaults to 18555

set -euo pipefail

BIN=${1:-/root/witness-spike/target/release/reth-witness-emit-node}
HTTP_PORT=${2:-18555}

WORK=$(mktemp -d -t wemit-smoke-XXXXXX)
trap 'rm -rf "$WORK"; pkill -f "$WORK" 2>/dev/null || true' EXIT
mkdir -p "$WORK/datadir" "$WORK/witnesses"

echo "==> spawning $BIN (dev mode, $WORK)"
"$BIN" node \
    --datadir "$WORK/datadir" \
    --chain dev \
    --dev --dev.block-time 2s \
    --http --http.addr 127.0.0.1 --http.port "$HTTP_PORT" --http.api eth,net,web3,debug,admin \
    --authrpc.port $((HTTP_PORT+6)) \
    --metrics 127.0.0.1:$((HTTP_PORT+10)) \
    --port $((HTTP_PORT+100)) --discovery.port $((HTTP_PORT+100)) \
    --witness-emit-dir "$WORK/witnesses" \
    --witness-stats "$WORK/exex-stats.jsonl" >"$WORK/node.log" 2>&1 &
NODE_PID=$!
trap 'kill $NODE_PID 2>/dev/null; sleep 1; kill -9 $NODE_PID 2>/dev/null; rm -rf "$WORK"' EXIT

# Wait for HTTP RPC
for i in $(seq 1 30); do
    if curl -sf -X POST -H "Content-Type: application/json" \
        --data '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' \
        "http://127.0.0.1:$HTTP_PORT" >/dev/null 2>&1; then
        break
    fi
    sleep 1
done

CHAIN_ID=$(curl -sS -X POST -H "Content-Type: application/json" \
    --data '{"jsonrpc":"2.0","method":"eth_chainId","params":[],"id":1}' \
    "http://127.0.0.1:$HTTP_PORT" | jq -r .result)
echo "==> dev chain ready, chainId=$CHAIN_ID"

# Submit transfers from dev signer
FROM=0x14dc79964da2c08b23698b3d3cc7ca32193d9955
TO=0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266

echo "==> submitting 25 transfers ($FROM -> $TO)"
for i in $(seq 1 25); do
    curl -sS -X POST -H "Content-Type: application/json" \
        --data "{\"jsonrpc\":\"2.0\",\"method\":\"eth_sendTransaction\",\"params\":[{\"from\":\"$FROM\",\"to\":\"$TO\",\"value\":\"0x1\",\"gas\":\"0x5208\",\"maxFeePerGas\":\"0x77359400\",\"maxPriorityFeePerGas\":\"0x59682f00\"}],\"id\":1}" \
        "http://127.0.0.1:$HTTP_PORT" > "$WORK/tx-$i.json"
    result=$(jq -r '.result // .error.message' "$WORK/tx-$i.json")
    if [ "$i" -le 2 ] || [ $((i % 10)) -eq 0 ]; then echo "    tx$i -> $result"; fi
    sleep 1
done

echo "==> let mining catch up"
sleep 10

HEAD=$(curl -sS -X POST -H "Content-Type: application/json" \
    --data '{"jsonrpc":"2.0","method":"eth_blockNumber","params":[],"id":1}' \
    "http://127.0.0.1:$HTTP_PORT" | jq -r .result)
HEAD_DEC=$((HEAD))
echo "==> final block head: $HEAD ($HEAD_DEC)"

# Wait for any in-flight ExEx writes
sleep 2

echo ""
echo "==> witnesses produced:"
ls -la "$WORK/witnesses" | tail -n +2 | head

echo ""
echo "==> first witness file inspection:"
FIRST_WITNESS=$(ls "$WORK/witnesses"/*.witness.zst 2>/dev/null | head -1 || true)
if [ -n "$FIRST_WITNESS" ]; then
    SIZE=$(stat -c %s "$FIRST_WITNESS")
    echo "    file: $FIRST_WITNESS"
    echo "    size: $SIZE bytes"
fi

echo ""
echo "==> ExEx stats JSONL ($WORK/exex-stats.jsonl):"
if [ -f "$WORK/exex-stats.jsonl" ]; then
    wc -l "$WORK/exex-stats.jsonl"
    cat "$WORK/exex-stats.jsonl" | head -5 | jq -c '{block_number, tx_count, size_bytes, e2e_ms, execute_ms, witness_build_ms, encode_ms, write_ms}'
    echo ""
    echo "==> stats summary:"
    jq -s '
      map(select(.skipped != true)) as $ok |
      {
        emitted: length,
        e2e_p50_ms: ($ok | map(.e2e_ms) | sort | .[length/2|floor]),
        e2e_max_ms: ($ok | map(.e2e_ms) | max),
        execute_p50_ms: ($ok | map(.execute_ms) | sort | .[length/2|floor]),
        witness_build_p50_ms: ($ok | map(.witness_build_ms) | sort | .[length/2|floor]),
        encode_p50_ms: ($ok | map(.encode_ms) | sort | .[length/2|floor]),
        write_p50_ms: ($ok | map(.write_ms) | sort | .[length/2|floor]),
        size_kb_p50: ($ok | map(.size_bytes/1024|floor) | sort | .[length/2|floor]),
        total_tx_count: ($ok | map(.tx_count) | add)
      }
    ' "$WORK/exex-stats.jsonl"
else
    echo "    NO STATS FILE WRITTEN"
fi

echo ""
echo "==> node memory/cpu:"
ps -o pid,rss,pcpu,etime= -p $NODE_PID 2>&1 || true

echo ""
echo "==> ExEx events from node log:"
grep -E "emitted|ExEx started|witness-emit ExEx ready" "$WORK/node.log" | tail -10

echo ""
echo "==> done — keeping log at $WORK/node.log for inspection (will be deleted on exit)"

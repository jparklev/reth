# witness-exec-spike

Stateless mainnet block validation end-to-end:

```
S3 bucket (witnesses/<hash>.zst)
        │
        ▼  fetch bytes
   witness-validator (single block)            ─── no MDBX needed
   witness-stream    (many blocks, prefetch)   ─── no MDBX needed
        │
        ├─ zstd-decompress + bincode-decode  (envelope)
        ├─ RLP-decode header + body, recover senders
        ├─ reveal SparseStateTrie from witness.state
        ├─ execute revm against WitnessDb
        ├─ recompute post-state root from sparse trie + bundle changes
        └─ assert == header.state_root
```

## Layout

- `src/bundle.rs` — `WitnessBundle` envelope + JSON / bincode-zstd helpers (shared).
- `src/validate_core.rs` — per-block pipeline (decode, reveal, execute, root) shared
  by validator and streaming binaries.
- `src/signing.rs` — ed25519 sign/verify (publisher signs, validators verify).
- `src/live_manifest.rs` — `head.json` schema (newest-first list of live witnesses).
- `src/producer.rs` — one-shot: opens a reth datadir read-only, writes a `.json` or `.zst`
  bundle for a single block. Needs MDBX. Behind `--features producer`.
- `src/publisher.rs` — **daemon**: subscribes to reth's WS `newHeads`, produces +
  signs + uploads every canonical block, maintains a signed `head.json`. Needs MDBX.
  Behind `--features producer`.
- `src/validator.rs` — fetches one bundle (S3 or HTTP), optionally verifies ed25519
  signature, validates. No MDBX.
- `src/stream.rs` — fetches a manifest of N blocks (legacy or live `head.json`), verifies
  signatures + state roots, reports per-block + aggregate stats. Supports `--base-url`
  for CDN paths. No MDBX.

Encoding is selected by file/key suffix:
- `*.json`             → pretty JSON envelope (v0; ~13 MiB / block)
- `*.zst` / `*.bin.zst` → bincode + zstd level 3 (v1; ~3.5 MiB / block)

## Compile

```bash
# Validator + streaming binary (no MDBX)
cargo build --release -p example-witness-exec-spike --bin witness-validator --bin witness-stream

# Producer / publisher (need MDBX-linkable host)
SDKROOT=$(xcrun --show-sdk-path) cargo build --release \
    -p example-witness-exec-spike --features producer
```

## Continuous publisher (production path)

Subscribes to reth's WS, signs + uploads every canonical block, maintains a signed
`head.json`. Run on the same box as reth.

```bash
source /etc/default/relay-l2
AWS_ACCESS_KEY_ID=$HETZNER_ACCESS_KEY \
AWS_SECRET_ACCESS_KEY=$HETZNER_SECRET_KEY \
RUST_LOG=info \
witness-publisher \
    --datadir       /var/lib/reth \
    --ws            ws://127.0.0.1:8547 \
    --http          http://127.0.0.1:8545 \
    --signing-key   /var/lib/reth/relay-indexer/writer.key \
    --writer-id     primary \
    --endpoint      https://fsn1.your-objectstorage.com \
    --bucket        reth-spike-fsn1 \
    --region        fsn1 \
    --prefix        witnesses/live \
    --cursor        /var/lib/witness-publisher/cursor.json \
    --stats         /var/lib/witness-publisher/stats.jsonl \
    --target-lag    3
```

Or via systemd (unit at `examples/witness-exec-spike/witness-publisher.service`):

```bash
sudo cp witness-publisher.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl start witness-publisher
sudo systemctl status witness-publisher
journalctl -u witness-publisher -f
```

Each successful publish emits a JSONL line to `--stats` like:

```json
{"ts":"2026-05-21T...","block_number":25145987,"size_bytes":3712418,"e2e_ms":487,
 "produce_ms":312,"upload_ms":174,"tx_count":214,"gas_used":18234567,...}
```

## Step 1 — Produce a witness from a reth datadir

```bash
# Binary + zstd (recommended)
./witness-producer --datadir /var/lib/reth \
    --block 0xabc...def \
    --out /tmp/witness.zst

# Or JSON (debuggable with jq)
./witness-producer --datadir /var/lib/reth \
    --block 0xabc...def \
    --out /tmp/witness.json
```

Opening a live datadir read-only works via MDBX `MDBX_RDONLY` while a writer runs.

## Step 2 — Upload to S3 (Hetzner Object Storage)

```bash
source /etc/default/relay-l2
AWS_ACCESS_KEY_ID=$HETZNER_ACCESS_KEY \
AWS_SECRET_ACCESS_KEY=$HETZNER_SECRET_KEY \
  aws --endpoint-url https://fsn1.your-objectstorage.com s3 cp \
    /tmp/witness.zst s3://reth-spike-fsn1/witnesses/<block_hash>.witness.zst
```

## Step 3a — Validate ONE block from S3

```bash
export AWS_ACCESS_KEY_ID=$HETZNER_ACCESS_KEY
export AWS_SECRET_ACCESS_KEY=$HETZNER_SECRET_KEY
./witness-validator \
    --endpoint https://fsn1.your-objectstorage.com \
    --bucket  reth-spike-fsn1 \
    --region  fsn1 \
    --key     witnesses/<block_hash>.witness.zst
```

## Step 3b — Stream-validate N blocks with prefetch

The streaming binary reads a manifest JSON from S3, prefetches one witness ahead
while validating the current one, and reports per-block + aggregate stats.

Manifest format (uploaded once by the producer driver script):

```json
{
  "blocks": [
    { "number": 25145626, "hash": "0x74b1...", "key": "witnesses/streaming/25145626-0x74b1...witness.zst" },
    { "number": 25145627, "hash": "0xbf60...", "key": "witnesses/streaming/25145627-0xbf60...witness.zst" }
  ]
}
```

Run against the legacy streaming manifest (no signatures):

```bash
./witness-stream \
    --endpoint https://fsn1.your-objectstorage.com \
    --bucket   reth-spike-fsn1 \
    --region   fsn1 \
    --manifest witnesses/streaming/manifest.json \
    --rpc      http://localhost:8545   # optional: cross-check header.stateRoot
```

Or against the live signed publisher manifest (recommended):

```bash
./witness-stream \
    --endpoint https://fsn1.your-objectstorage.com \
    --bucket   reth-spike-fsn1 \
    --region   fsn1 \
    --manifest witnesses/live/head.json \
    --pubkey   ./writer-keys/primary.pub
```

To fetch through an HTTP CDN URL instead of the S3 API (faster cold connections
since reqwest pools + parallelizes the `.zst` + `.zst.sig` fetches):

```bash
./witness-stream \
    --base-url https://fsn1.your-objectstorage.com/reth-spike-fsn1 \
    --bucket   reth-spike-fsn1 \
    --region   fsn1 \
    --manifest witnesses/live/head.json \
    --pubkey   ./writer-keys/primary.pub
```

Per-block "wall" is measured from when fetched bytes land in the channel until
validation finishes — so it is roughly `max(prefetched_fetch_time, compute_time)`
once the pipeline fills. Steady-state throughput converges to
`1 / max(fetch, compute)`.

Measured on 2026-05-21 (10 mainnet blocks at head-1, average 5.75 MiB/block zst):

| run                                | mean compute | p50 compute | p99 compute | notes                              |
|------------------------------------|-------------:|------------:|------------:|------------------------------------|
| cross-DC (mac → fsn1), no RPC      |   172 ms     |   136 ms    |   337 ms    | wall ≈ compute (prefetch absorbed) |
| cross-DC (mac → fsn1), with RPC    |   172 ms     |   146 ms    |   325 ms    | all 10 roots matched prod header   |
| intra-DC (box → fsn1), with RPC    | varied       |   149 ms    | 3325 ms     | one block had per-tx hot path that |
|                                    |              |             |             | took 3.3s under writer/RPC load    |

## Quick local-file path (single block)

```bash
./witness-validator --local /tmp/witness.zst
```

## Notes / sharp edges

- `debug_executionWitness` RPC on this reth build returns `BlindedNode` — the producer
  bypasses it by reading MDBX directly.
- `ChainSpecBuilder::mainnet().build()` drops the BPO blob schedule; producer + validator
  must use `MAINNET` static instead.
- `reth-codecs-0.3.1` panics on blocks > ~30 behind head — only validate fresh blocks.
- After `executor.execute(input)`, must use `output.state`, NOT `db.take_bundle()`
  (the latter returns an empty bundle and gives a deterministic wrong root).

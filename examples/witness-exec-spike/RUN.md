# witness-exec-spike

Stateless mainnet block validation end-to-end:

```
S3 bucket (witnesses/<hash>.json)
        │
        ▼  fetch bytes
   witness-validator                ─── compiles on any host (no MDBX needed)
        │
        ├─ decode JSON + RLP header/body
        ├─ reveal SparseStateTrie from witness.state
        ├─ execute revm against WitnessDatabase
        ├─ recompute post-state root from sparse trie + bundle changes
        └─ assert == header.state_root
```

## Layout

- `src/producer.rs` — opens a reth datadir read-only, generates an
  `ExecutionWitness` for one block, writes a JSON bundle. Needs MDBX (only
  builds on a host where libmdbx can link — Linux fine, macOS needs
  `SDKROOT=$(xcrun --show-sdk-path)`). Behind `--features producer`.
- `src/validator.rs` — fetches from S3 (or local file), executes, verifies.
  No MDBX needed.

## Compile

```bash
# Validator only (no MDBX)
cargo build --release -p example-witness-exec-spike --bin witness-validator

# Producer too (needs MDBX-linkable host)
SDKROOT=$(xcrun --show-sdk-path) cargo build --release \
    -p example-witness-exec-spike --features producer
```

## Step 1 — Produce a witness from a reth datadir

Run on a host where the datadir lives (Hetzner box for us):

```bash
./witness-producer \
    --datadir /var/lib/reth \
    --block 0xa8cfd050a211a1b6286ce9c636bf325e238be5ea1e67f25525b86c11854e4439 \
    --out /tmp/witness.json
```

Note: opening a datadir read-only while a live writer is running works via
MDBX `MDBX_RDONLY`. The validator-side path is not affected by writer load.

## Step 2 — Upload to S3 (Hetzner Object Storage)

```bash
source /etc/default/relay-l2
AWS_ACCESS_KEY_ID=$HETZNER_ACCESS_KEY \
AWS_SECRET_ACCESS_KEY=$HETZNER_SECRET_KEY \
  aws --endpoint-url https://fsn1.your-objectstorage.com s3 cp \
  /tmp/witness.json \
  s3://reth-spike-fsn1/witnesses/<block_hash>.json
```

## Step 3 — Validate from S3

```bash
export AWS_ACCESS_KEY_ID=$HETZNER_ACCESS_KEY
export AWS_SECRET_ACCESS_KEY=$HETZNER_SECRET_KEY
./witness-validator \
    --endpoint https://fsn1.your-objectstorage.com \
    --bucket  reth-spike-fsn1 \
    --region  fsn1 \
    --key     witnesses/<block_hash>.json
```

Expected output:

```
[1/6] fetch:      0.xxs  (NN.NN MiB)
[2/6] decode:     0.xxs  (block #NNNNN, state nodes=NNNN, codes=NN, ancestors=N)
[3/6] reveal:     0.xxs
[5/6] execute:    0.xxs  (txs=NNN, gas_used=NNNNNNNN)
[6/6] root:       0.xxs
OK: state root 0x... matches header
OK: header hash 0x...

==================================================
TOTAL fetch→verify:           N.NNNs
  fetch (S3 GET):             N.NNNs
  decode (JSON+RLP):          N.NNNs
  reveal sparse trie:         N.NNNs
  execute (revm):             N.NNNs
  state root recompute:       N.NNNs
==================================================
```

## Quick local-file path (no S3 round-trip)

```bash
./witness-validator --local /tmp/witness.json
```

## Why a JSON envelope instead of bincode/RLP?

It's the v0 dump. Easy to inspect with `jq`. The validator's decode cost
is dominated by the (large) hex-decoded `Bytes` lists — `serde_json` is
not bottleneck-grade but works. v1 would use length-prefixed binary
encoding to skip ~50ms on a typical block.

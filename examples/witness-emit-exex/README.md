# witness-emit-exex

An in-process replacement for the `witness-publisher` sidecar at
`examples/witness-exec-spike/src/publisher.rs`.

Same wire format (`WitnessBundle` bincode+zstd), same manifest shape
(`head.json` ed25519-signed, newest-first list of live entries), same on-disk
ed25519 key format. Drop-in for `witness-stream` / `witness-validator`
consumers — they need no changes.

## Why

The sidecar opens reth's MDBX read-only and re-executes blocks by walking
changesets back from `best_block`. The blockchain-tree's in-memory state
isn't visible from outside the process, and reth's BalStore changeset cache
only covers a small window. The combination causes inconsistent
`StateProvider` results within ~20 blocks of `best_block`, which the executor
sometimes accepts but the resulting witness is internally broken. The sidecar
self-validates every produced witness and **skips ~24% of blocks** as a
result.

The fix: produce the witness from inside the reth process via an Execution
Extension. ExEx notifications fire after a chain commits; `ctx.provider()` is
the live `BlockchainProvider` whose `consistent_provider()` snapshots both
the in-memory head and the DB at the same moment. The result: state at
parent_hash is always available and self-consistent. **Skip rate → 0**.

## Layout

```
src/main.rs                      reth node binary with --witness-emit-dir flag
src/exex.rs                      the ExEx: re-execute -> record -> bundle -> write
src/bundle.rs                    WitnessBundle envelope (must match the spike's)
src/uploader.rs                  watches the emit dir, signs, uploads, manifest
src/uploader_live_manifest.rs    head.json schema (same as the spike's)
src/uploader_signing.rs          ed25519 sign helpers (same as the spike's)
reth-witness-emit-node.service   systemd unit for the node binary
witness-uploader.service         systemd unit for the uploader
```

## How it works

For each committed block in an `ExExNotification::ChainCommitted`:

1. `state = ctx.provider().state_by_block_hash(block.parent_hash())` —
   guaranteed consistent (consistent_provider snapshots in-memory + DB
   together).
2. Re-execute the block against `state` using `ctx.evm_config().executor()`.
   The closure form `execute_with_state_closure` lets us inspect the
   post-execution `revm::database::State<DB>` to record every touched
   account/slot/code, including reads that returned the original value (which
   `ExecutionOutcome` does NOT carry).
3. `into_execution_witness(&state, ctx.provider(), block.number(), ...)` —
   builds the state proofs and ancestor headers.
4. Bincode + zstd-3 encode the `WitnessBundle`.
5. Write to `<emit-dir>/<num>-<hash>.witness.zst.tmp`, fsync, rename to
   `.witness.zst`, fsync the dir.
6. Emit `ExExEvent::FinishedHeight(tip)` AFTER every block in the chain is
   durable. This drives reth's ExEx WAL prune cursor.

For each `ExExNotification::ChainReverted` (or `ChainReorged.old`):

- Rename `<num>-<hash>.witness.zst` -> `.witness.zst.stale` so the uploader
  knows to rewind the manifest and not re-advertise the orphaned block.

## Build

```bash
# Node binary (needs MDBX-linkable host)
cargo build --release -p example-witness-emit-exex --bin reth-witness-emit-node

# Uploader
cargo build --release -p example-witness-emit-exex --bin witness-uploader
```

## Deploy (separate from prod reth)

The node binary is a **full reth node** with one ExEx added — it needs its
own datadir + ports + p2p discovery slot. Do NOT point it at the prod reth
datadir.

```bash
# On the box:
sudo install -m 755 target/release/reth-witness-emit-node /usr/local/bin/
sudo install -m 755 target/release/witness-uploader        /usr/local/bin/
sudo install -m 644 reth-witness-emit-node.service /etc/systemd/system/
sudo install -m 644 witness-uploader.service       /etc/systemd/system/
sudo systemctl daemon-reload

# Bootstrap datadir (one option):
#   reth-witness-emit-node init --datadir /var/lib/reth-witness-emit --chain mainnet
#   then point at a snapshot or sync from p2p
# For the spike we use the existing verify-v5 datadir at
# /var/lib/reth/reth-bucket-import-test-v5/ (which is at the anchor block)
# and apply the Path B header injection so block 25143845 executes cleanly.

sudo systemctl start reth-witness-emit-node
sudo systemctl start witness-uploader
journalctl -u reth-witness-emit-node -u witness-uploader -f
```

## CLI flags added to `reth node`

| flag | env | default | description |
|------|-----|---------|-------------|
| `--witness-emit-dir <PATH>` | `WITNESS_EMIT_DIR` | (required) | where the ExEx writes `<num>-<hash>.witness.zst` |
| `--witness-stats <PATH>` | `WITNESS_STATS` | none | optional JSONL stats file (one line per emitted block) |

All other reth flags work as normal.

## Stats line shape

```json
{"ts":"2026-05-21T16:52:00.123Z","block_number":25145987,
 "block_hash":"0xabc...","parent_hash":"0xdef...",
 "tx_count":214,"size_bytes":3712418,
 "state_nodes":2417,"codes":48,"keys":5102,
 "state_open_ms":2,"execute_ms":78,"witness_build_ms":35,
 "encode_ms":11,"write_ms":3,"e2e_ms":129}
```

`e2e_ms` is the per-block wall clock from when this block came out of the
ExEx notification stream to when its `.witness.zst` is durable on disk.

## Re-org handling

- `ChainReverted{old}` and `ChainReorged{old, new}` are both handled.
  Files for blocks in `old` are renamed to `.witness.zst.stale` BEFORE any
  new files are written.
- The uploader scans for `.stale` files on every tick, rewinds the published
  `head.json` manifest above the lowest stale block, and deletes the stale
  files locally.
- The orphaned objects remain in S3 (uploaded but not advertised) — same
  policy as the sidecar publisher.

# Bucket-mode reth node + Phase 26.3 checkpointer

> Status (2026-05-19): both shipped on
> `jparklev/reth@claude/bucket-mode-spike`. Build + unit tests pass
> on the box.

This fork ships two new pieces on top of paradigmxyz/reth v1.11.3:

1. **`reth node --bucket-url s3://...`** — header reads served from
   a signed S3 bucket via the
   `crates/storage/provider/src/providers/bucket/` trait + the new
   `crates/bucket-header-client/` HTTP/Vortex implementer.

2. **`relay-state-checkpointer`** — a standalone binary at
   `crates/relay-state-checkpointer/` that reads PlainAccountState
   / PlainStorageState / Bytecodes from a local reth datadir and
   emits a signed Vortex checkpoint to an S3 bucket (Phase 26.3).

## `reth node --bucket-url`

```bash
cargo build --release --bin reth

# Boot with bucket-mode (against the relay project's public bucket):
./target/release/reth node \
    --bucket-url s3://reth-spike-fsn1 \
    --bucket-endpoint https://fsn1.your-objectstorage.com \
    --bucket-region auto \
    --bucket-anonymous \
    --bucket-trusted-writers primary \
    --bucket-warm-epochs 8 \
    [normal reth node flags ...]
```

At boot:
1. `HttpBucketHeaderClient::new_blocking` fetches `manifest/head.json` +
   the writer pubkey, verifies the ed25519 signature, walks back N
   warm epoch manifests (default 8) and verifies the SHA chain.
2. `BlockchainProvider::with_bucket(...)` attaches the client to
   the provider stack.
3. From this point, every `HeaderProvider::header_by_number(n)` or
   `header(hash)` query consults the bucket first. Misses fall
   through to the normal MDBX/static-files path.

Failure modes (intentional):
- Bucket unreachable at boot → reth refuses to start with a clear
  error. We don't want to silently fall back to a local-only mode
  the operator didn't ask for.
- Signature verification fails → same; refuses to start, surfaces
  the offending writer ID.
- A specific block isn't covered by the warm snapshot → header
  query falls through to MDBX/static-files (no error). Run with
  `--bucket-warm-epochs N` higher if you need more recent history
  visible without a refresh.

## `relay-state-checkpointer`

```bash
cargo build --release --bin relay-state-checkpointer

# Operator-demand checkpoint of current plain state:
sudo ./target/release/relay-state-checkpointer \
    --datadir /var/lib/reth \
    --out-dir /tmp/checkpoint-25120500 \
    --shard-bits 8 \
    [--max-accounts 1000000]   # optional cap for spike runs

# With upload:
sudo BUCKET_ACCESS_KEY=... BUCKET_SECRET_KEY=... \
    ./target/release/relay-state-checkpointer \
        --datadir /var/lib/reth \
        --out-dir /tmp/checkpoint-25120500 \
        --shard-bits 8 \
        --upload-bucket reth-spike-fsn1 \
        --upload-endpoint https://fsn1.your-objectstorage.com \
        --upload-region auto \
        --writer-key /var/lib/reth/relay-indexer/writer.key \
        --writer-id primary \
        --update-index
```

What it does:
1. Opens the reth datadir read-only via reth's `EnvironmentArgs::init`
   bootstrap (handles all the 5-arg `ProviderFactory::new` wiring,
   storage settings, rocksdb provider, etc).
2. Cursors `PlainAccountState`, `PlainStorageState` (dup-sort
   per-address), `Bytecodes`.
3. Shards by high-order address bits (`--shard-bits 8` → 256 shards;
   each shard is one Vortex chunk per artifact family).
4. Writes:
   ```
   <out_dir>/manifest.json
   <out_dir>/shard-NNNN/accounts.vortex
   <out_dir>/shard-NNNN/storage.vortex
   <out_dir>/shard-NNNN/code.vortex
   ```
   (Or single-shard mode at `<out_dir>/accounts.vortex` etc. when
   `--shard-bits 0`.)
5. With `--upload-bucket`: uploads each artifact to
   `s3://<bucket>/checkpoints/<block_num>/...` plus a signed
   `SignedCheckpointManifest`. With `--update-index`: appends to
   `<prefix>index.json[.sig]`.

The checkpoint binds to the **current local-node canonical state**
(`chain_info().best_number`). It does not pretend to represent an
arbitrary historical block — codex's review caught that wrinkle and
this shape is the documented one.

Operationally: codex flagged that a long MDBX read transaction on a
disk-pressure-sensitive production node is risky. Run on a paused
replica or during a maintenance window. For dry-runs against the
production node, use `--max-accounts 10000` first to see the
throughput.

## Building

The reth fork pulls vortex (git fork on `jparklev/vortex@develop`)
via the `bucket-header-client` and `relay-state-checkpointer` deps.
The fork is on branch `claude/bucket-mode-spike` of `jparklev/reth`.

```bash
git clone -b claude/bucket-mode-spike git@github.com:jparklev/reth.git
cd reth
cargo build --release --bin reth --bin relay-state-checkpointer
```

Build needs GitHub network access (vortex git deps). The relay-archive
box (where the fork was developed) has that. CI / sandbox
environments may need `--offline` workarounds.

## Test coverage on the fork

```
cargo test -p reth-provider --lib providers::bucket
    → 2 tests pass

cargo test -p reth-bucket-header-client --lib
    → 3 tests pass (manifest chunk ref, b256 parse, signature)

cargo test -p relay-state-checkpointer --bin relay-state-checkpointer
    → 3 tests pass (shard distribution, shard_count, high-bit routing)
```

## Limitations (this PR)

- **Header-only**. `BlockReader`, `TransactionsProvider`,
  `ReceiptProvider`, state providers still hit MDBX. Extending to
  the full set is the obvious follow-up — same trait-extension
  pattern, more decoders in `bucket-header-client`.
- **Vortex chunks only**. Legacy parquet `block_header` chunks fall
  through to a manifest-only Header (parent_hash + number only); the
  full Header decode requires Vortex. The relay bucket has been
  dual-writing Vortex since Phase 24, so all recent epochs work.
- **Checkpointer is reth-version-pinned**. Uses internal reth
  crates (`reth-db-api`, `reth-provider`, etc.) via path deps.
  Upstream reth API breakage will require updating the checkpointer.
- **No on-disk caching of the bucket snapshot**. Boot re-fetches
  head + N warm manifests. Acceptable for relay-scale (small JSON
  documents); a future iteration could persist them.

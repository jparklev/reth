# Checkpoint-import sync for reth-bucket

Status: design + spike. Authored 2026-05-20.

## Problem

Bucket-mode reth, when started fresh against mainnet with a CL attached, has
nothing in MDBX. The CL sends `forkchoiceUpdated(head=tip~25.2M,
finalized=tip-64, safe=tip-32)`. The engine tree reads
`provider.best_block_number() = 0` (only genesis is in MDBX), so it computes a
backfill target gap of ~25M blocks and routes the work into the staged-sync
pipeline. Headers → bodies → execution → trie. Hours-to-days, defeating the
whole point of having a signed bucket checkpoint that already contains the
plain state at block 25,124,931.

We want: on boot, trust the bucket checkpoint as the canonical starting head,
so the engine tree thinks its local tip is 25,124,931 and backfill is only the
~75K blocks since checkpoint capture.

## How reth decides its starting head

`BlockchainProvider::new()` calls `provider.chain_info()` which reads
`provider.best_block_number() → get_stage_checkpoint(StageId::Finish)`. The
hash for that number is read from MDBX `BlockHashes` / static_files
`Headers`. That tuple seeds `CanonicalInMemoryState::with_head(latest, finalized,
safe)`.

When `EngineApiTreeHandler::spawn_new` runs (`crates/engine/tree/src/tree/mod.rs`
line 438), it does:

```rust
let best_block_number = provider.best_block_number().unwrap_or(0);
let header = provider.sealed_header(best_block_number).ok().flatten().unwrap_or_default();
let persistence_state = PersistenceState {
    last_persisted_block: BlockNumHash::new(best_block_number, header.hash()),
    ...
};
let state = EngineApiTreeState::new(..., header.num_hash(), ...);
```

So the engine's `canonical_block` anchor is whatever `best_block_number` +
`sealed_header(N)` return. Backfill decisions use that as `local_tip` (line
2512: `block > local_tip && block - local_tip > MIN_BLOCKS_FOR_PIPELINE_RUN`).

If we can make `best_block_number = 25_124_931` and `sealed_header(25_124_931)
= <pinned header>` on a fresh datadir, the engine thinks it's at the tip and
asks for a small backfill (~75K blocks) on the CL's first FCU.

## The existing import primitive: `reth init-state --without-evm`

`crates/cli/commands/src/init_state/without_evm.rs` already does the
header/static-file/checkpoint half. `setup_without_evm`:

1. `append_dummy_chain(sf, target=N-1, ...)` writes empty Header rows in
   `static_files/headers` from block 1 to N-1 and increments the end-block on
   Transactions/Receipts/TransactionSenders segments (no rows, just bookkeeping
   so the segments are at the same height).
2. `append_first_block(provider, &header_at_N)` inserts the **real** pinned
   header at block N via `BlockWriter::insert_block`.
3. For every `StageId::ALL` (Headers, Bodies, SenderRecovery, Execution,
   AccountHashing, StorageHashing, MerkleExecute, IndexAccountHistory,
   IndexStorageHistory, TransactionLookup, Prune, Finish), saves a
   `StageCheckpoint::new(N)`.

After step 3, `best_block_number()` = N, `sealed_header(N)` = pinned header.
This is exactly the engine-tree anchor we need.

`init_state` then calls `init_from_state_dump` (step 4): parse a JSONL state
dump, write into `PlainAccountState`/`PlainStorageState`/`Bytecodes`, clear
trie tables, recompute state root from scratch, verify against the header's
state_root.

## The fatal constraint on "skip step 4"

A naive plan: skip step 4. Trust the bucket-state-client to serve any read for
block ≤ pinned. After import, MDBX has headers up to N but zero plain state.
The CL sends FCU, engine triggers small backfill from N to tip-64. Backfill
runs `HeaderStage` (download 75K headers — fine), `BodyStage` (download 75K
bodies — fine), then `ExecutionStage`.

`ExecutionStage::execute` (crates/stages/stages/src/stages/execution/mod.rs:305):

```rust
let db = StateProviderDatabase(LatestStateProviderRef::new(provider));
let mut executor = self.evm_config.batch_executor(db);
```

`LatestStateProviderRef<'_, Provider>` (`crates/storage/provider/src/providers/state/latest.rs:44`)
holds `&Provider: DBProvider` and reads `PlainAccountState`/`PlainStorageState`/
`Bytecodes` via raw MDBX cursors. **It does NOT go through `BlockchainProvider`,
so the bucket-state overlay is bypassed.** The first block executed after N
reads parent-state from empty MDBX tables → all account loads return None →
execution diverges from canonical.

This is the load-bearing finding for the whole design. The bucket-state
overlay is plumbed through `BlockchainProvider::maybe_wrap_with_bucket`, which
sits in `latest()` / `history_by_block_hash` / `state_by_block_hash`. The
stage pipeline's `Provider` is the raw `DatabaseProvider`, not
`BlockchainProvider`, and it directly constructs `LatestStateProviderRef` from
itself. The overlay cannot intercept stage-time reads without an
`ExecutionStage` refactor.

## Two viable paths

### Path A: Materialize at import time (chosen for spike)

Drain the bucket-state-client's hydrated HashMaps into MDBX
`PlainAccountState`/`PlainStorageState`/`Bytecodes` during the import command.
After the import:

- MDBX has plain state at block N.
- Trie tables are empty.
- `MerkleStage` will see `to_block - from_block <= 100_000` (rebuild
  threshold) and try incremental updates from changesets — but there are no
  changesets going back from N, and there's no existing trie. So we either
  need to (a) pre-populate the trie and HashedAccounts/HashedStorages
  eagerly at import time (slow — full state-root computation, on the order
  of an hour for mainnet state), or (b) set the MerkleStage checkpoint to
  one block past N at import time so the very first incremental update is
  N+1 → N+1 trivially, and rebuild only when the backfill exceeds threshold
  (which it doesn't with 75K blocks). Option (b) is wrong because the
  initial state root is unknown without the trie.

The pragmatic compromise: materialize plain state, then run the standard
`HashedAccounts`/`HashedStorages` + trie-from-scratch computation **once** at
import time (call into `compute_state_root_chunked` like `init_from_state_dump`
does, but verify against the bucket-trusted `pinned_header.state_root`). This
is expensive but happens once and is verifiable.

Cost estimate: ~250M accounts × 100B ≈ 25GB cursor writes (~15-30 minutes on
NVMe) + full trie computation (~30-60 minutes). Total import: 1-2 hours.
Compare to staged sync from genesis: 24-72 hours. Net win.

### Path B: Refactor `ExecutionStage` to take a `StateProviderFactory`

Change `ExecutionStage::execute` to fetch state via
`provider.latest_with_overlay()` (or similar), so the bucket overlay can
intercept reads. First block N+1's reads go to bucket; writes go to MDBX
`PlainAccountState`. Block N+2 reads from MDBX for touched accounts, bucket
for untouched. Copy-on-write semantics.

Pros: zero up-front import cost. Boot is instant.

Cons: invasive refactor of a stage that's shared with non-bucket reth.
Trie/HashedAccounts still need a full rebuild before MerkleStage can run, so
we still pay that cost eventually. Plus: every read in ExecutionStage now
goes through the BlockchainProvider hop, adding latency to the hot path.
Plus: `StateWriter::write_to_storage` writes to MDBX, but the **changesets**
that IndexHistory + Merkle depend on are computed from the bundle delta — fine
— but Merkle still needs a root, which still needs the trie.

Verdict: Path B is more architecturally complex and saves less time than it
looks, because the trie build is the long tail.

## Spike scope

Pick the smallest demonstration that's directionally useful:

**`reth import-bucket-checkpoint`** — a new CLI subcommand that:

1. Takes the same `--bucket-url` / `--bucket-endpoint` / etc. flags as `reth
   node`.
2. Boots a `HttpBucketStateClient` (the existing one — reads manifest, fetches
   shards, populates in-memory HashMaps). Reads `pinned_header`,
   `pinned_block_number`, `pinned_block_hash` off the client.
3. Calls a `setup_without_evm`-equivalent: dummy headers 1..N-1 +
   real pinned header at N + `save_stage_checkpoint` for every `StageId::ALL`.
4. **Spike-cut here.** Stops short of draining plain state into MDBX. Just
   verifies that after this, `reth node --bucket-url ...` boots with
   `best_block_number = N` and `sealed_header(N) = pinned header`.
5. Document what the next step would be: drain plain state +
   compute-state-root pass.

This gets us **half the puzzle** in one or two commits — the engine-tree
anchor — and proves the seam is correct. The CL's first FCU won't actually
produce a working chain (ExecutionStage will fail on the first block past N
with `AccountNotFound` because plain state is empty), but `eth_blockNumber`
will return N immediately and the bucket-state RPC for blocks ≤ N continues
to work.

The "follow-up commit" lands the plain-state drain + state-root compute. That
gets us the full end-to-end working spike.

## Edge cases (for future hardening)

- **Reorg through pinned**. If the CL ever finalizes a block whose canonical
  chain doesn't include the bucket's pinned hash, reth must unwind past
  pinned. Today the import bakes pinned in as a stage checkpoint; unwind
  semantics would unwind into the dummy headers (block N-1 with state_root =
  empty), which is wrong. Mitigation: pinned must be deep-enough-finalized
  that reorgs through it are catastrophic (out-of-scope) — practically, a
  bucket-state checkpoint pinned at N-2048 or deeper makes this a non-issue.
- **CL says finalized = pre-pinned**. The CL believes its finality view; if
  it's started fresh, its first FCU's finalized hash might be far behind
  pinned. The engine code in `backfill_target_hash` uses `finalized_block_hash`
  (non-OP). If finalized < pinned, `backfill_sync_target` calls
  `provider.header_by_hash_or_number(target_hash)` and gets `Ok(Some(_))`
  (dummy header in static_files) → returns None → no backfill. The engine
  then waits for newPayload(N+1,...) and just goes from there. Practical
  behavior: works fine, the dummy headers are never actually read for
  consensus.
- **Trie stages**. As discussed: cannot incrementally update without a
  starting trie. Spike defers this; productionizing requires the eager
  state-root pass.
- **Static-file consistency**. `append_first_block` calls
  `latest_writer(Receipts).increment_block(header.number())`, mirroring
  `init_state --without-evm` behavior. We should do the same for the spike.

## Code cut points

- **New file**: `crates/cli/commands/src/import_bucket_checkpoint.rs` —
  CLI subcommand that fetches the bucket client and calls the
  setup-without-evm equivalent + (eventually) the plain-state drain.
- **Modified**: `crates/cli/commands/src/lib.rs` — register the new subcommand
  in the Commands enum.
- **Modified**: `bin/reth/src/main.rs` (or wherever the subcommand dispatch
  happens) — route to the new command.
- **Reused**: `crates/cli/commands/src/init_state/without_evm.rs::setup_without_evm`
  is already pub. We can call it directly with `SealedHeader::new(pinned_header,
  pinned_hash)`.
- **Reused**: `crates/bucket-state-client::HttpBucketStateClient::new_blocking`.

## Productionization roadmap (post-spike)

1. **Spike commit 1** (this PR): `reth import-bucket-checkpoint` writes
   headers + checkpoints. Engine anchor works; execution past N is broken.
   ~150 LOC.
2. **Spike commit 2**: drain `account_count`/`storage_count`/`code_count`
   HashMaps into MDBX cursor-puts. ~300 LOC.
3. **Spike commit 3**: run `compute_state_root_chunked` and verify against
   `pinned_header.state_root`. Populate `HashedAccounts`, `HashedStorages`,
   `AccountsTrie`, `StoragesTrie`. ~200 LOC (mostly call into existing
   `init_from_state_dump` helpers).
4. **Hardening**: handle the "datadir already has data" case (refuse + tell
   user to wipe). Handle the "bucket pinned block doesn't match the chainspec
   genesis hash" check. Add a verification mode that re-reads pinned_header
   from MDBX after import and confirms hash + state_root match.
5. **Inline mode**: a `--bucket-checkpoint-import` flag on `reth node` that
   detects a fresh datadir + bucket URL and runs the import inline before
   starting the pipeline. Removes the operational step of running a separate
   subcommand.
6. **Reorg defense**: refuse to unwind past pinned without an explicit flag.

Estimated effort to "works for shadow + eventual cutover": 1–2 weeks of
focused engineering. The biggest unknown is the cost + correctness of the
state-root computation on a ~25M-block mainnet state — that may want to be
pipelined / streamed rather than one big batch.

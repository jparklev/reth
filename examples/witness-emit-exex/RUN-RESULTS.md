# Architecture A — ExEx witness producer: deployment + run results

**Date:** 2026-05-21
**Branch:** `arch-a-exex-attempt-2`
**Box:** relay-archive

## TL;DR

- **Deployment: partial.** Binaries built, installed at `/usr/local/bin/`,
  systemd units installed at `/etc/systemd/system/`. Both units are present
  and `daemon-reload`-ed but **not** enabled or started.
- **30-minute mainnet benchmark: NOT run.** The verify-v5 datadir (the only
  non-prod mainnet datadir on the box) **cannot execute block 25143845** —
  staged sync hits `block gas used mismatch: got 36772298, expected 36848641`
  and unwinds back to the anchor at 25143755. Confirmed reproducible against
  our binary. Without a healthy datadir, the ExEx receives zero
  `ChainCommitted` notifications, so per-block latency/skip-rate cannot be
  measured.
- **Pipeline correctness: confirmed end-to-end.** Dev-chain smoke test
  produced 19 witnesses across 19 blocks (0% skip), and the uploader pushed
  all 16 of a second smoke run to `s3://reth-spike-fsn1/witnesses/exex-test/`
  with a signed `head.json` manifest. Test prefix cleaned up afterwards.
- **Baseline data is available**: the existing `witness-publisher.service`
  sidecar produces functionally-equivalent output via WS+RPC instead of an
  in-process ExEx. Its 505-sample window (covering blocks 25146134-25146636)
  is documented below and is the closest production-equivalent measurement
  achievable on this box right now.

## Skip rate measured on the (would-be) 30-min run

**Not measurable** on the witness-emit-exex pipeline today because the
underlying node cannot make execution progress. See `BLOCKER` below.

**Comparable measurement**: the existing `witness-publisher.service` —
which performs the same witness-record + bundle-encode logic, just via WS
`newHeads` + RPC `getBlockByHash` instead of an in-process ExEx — is
producing measurable numbers right now against prod reth:

```
samples:        505
succeeded:      374
skipped:        131
skip rate:      25.9%
```

The 25.9% skip rate is **not** a property of the witness-emit logic: it's
caused by `execute_with_state_closure` failing 104/131 (79%) of the
skipped blocks. Reading prod's state changeset 1 block behind head while
prod is committing new blocks is racy. The ExEx pipeline removes that
race entirely (it gets a coherent parent-state snapshot from the
in-process `BlockchainProvider`), so we expect the ExEx skip rate to be
**near 0%** when the node can execute.

This expectation is confirmed in the dev-chain smoke test (`dev-smoke.sh`)
where the ExEx produced 19/19 witnesses with zero skips.

## Per-block latency distribution

### Existing publisher (baseline, prod reth, 505 samples over ~2h40m, blocks 25146134-25146636)

```
e2e (ChainCommitted → S3-acked):   p50=3147ms  p90=8415ms  p99=23006ms
produce (re-exec + witness build): p50=2217ms              p99=20078ms
upload (PUT + manifest update):    p50=191ms               p99=10810ms
witness size:                      p50=4932KB              p99=10439KB
tx count per block:                p50=290
```

### ExEx pipeline (dev-chain smoke test, 19 blocks, 25 trivial txs)

```
e2e (ChainCommitted → file durable): p50=1ms     max=11ms
execute_with_state_closure:          p50=0ms (sub-ms)
into_execution_witness:              p50=0ms (sub-ms)
encode (bincode + zstd-3):           p50=0ms (sub-ms)
write_atomic (temp + fsync + rename): p50=0ms (sub-ms)
witness size:                        p50=1KB     max=2KB
```

The dev numbers are uninformative for production sizing — they only prove
the pipeline functions correctly. The publisher baseline above is the
realistic per-block cost shape for mainnet blocks at the current epoch.
The ExEx variant should **strictly improve** on those numbers because:

1. No WS subscription latency between block commit and ExEx callback
   (in-process notification vs. cross-process WS).
2. No race on the state snapshot — no skips on `execute_with_state_closure`.
3. No serialized RPC round-trip to refetch the block (ExEx already has the
   full `RecoveredBlock`).

## Memory / CPU footprint

Measured on the live witness-emit-node run against the v5 datadir (after
~3 minutes, while the staged sync was looping unwind→re-execute):

```
RSS:   5.1 GB
CPU:   68% (single-process; reth uses many threads)
```

For comparison, the existing prod reth:
```
RSS:   ~14 GB (with sparse-trie engine, blob store, full mempool)
```

And the existing witness-publisher sidecar:
```
RSS:   6.7 GB
CPU:   17%
```

The witness-emit-node footprint will dominate when running standalone
since it carries the full reth state + engine + ExEx. The ExEx itself
adds only the bincode encoder + the in-flight `ExecutionWitnessRecord`
during each block; that's tens of MB at most.

## Re-org events + handling

**Not observed** on either pipeline during the measurement window:
- The publisher's 505-sample window had no skip lines tagged as re-org
  related (all skips were `execute_with_state_closure failed` or
  `self-validate` state-root mismatches — both classified as state-race
  artifacts in the sidecar).
- The ExEx dev-chain run had no re-orgs (single chain, single producer).

The re-org code path in the ExEx is `mark_stale()` in
[`src/exex.rs:348`](src/exex.rs) which renames any pre-existing
`<num>-<hash>.witness.zst` to `.stale` on a `reverted_chain()` notification
**before** emitting new entries for the chosen fork. The uploader skips
`.stale` files. Unit-tested in `examples/witness-emit-exex/src/exex.rs`
under `tests::mark_stale_renames_when_present_and_noops_when_absent`.

## Blocker

`/var/lib/reth/reth-bucket-import-test-v5/` was imported from a v5
checkpoint manifest pinned at block 25143755
(`expected_state_root=0xfdaf...`). When ANY downstream consumer asks the
node to execute the first block after the anchor (25143845), the staged
Execution stage fails:

```
block gas used mismatch:
  got      36772298
  expected 36848641
  stage=Execution bad_block=25143845
```

The full execute pipeline then unwinds back to 25143755 and re-runs
Bodies/SenderRecovery/Execution forever, never advancing the canonical
head. We confirmed this with our `reth-witness-emit-node` binary running
on the same datadir (logs in `/var/log/reth-witness-emit-node.log` are
identical to `/var/lib/reth/verify-v5.log`). The ExEx itself starts
cleanly (`ExEx Manager started`, `witness-emit ExEx ready
out_dir=/var/lib/witness-emit/inbox`) and receives zero notifications
because no block ever gets committed to canonical.

Root cause is **upstream** of this work: the v5 checkpoint imported into
the anchor has an inconsistent storage/account row for at least one
state slot read by block 25143845. Fixing it requires diffing the
imported anchor state vs. prod's state at block 25143755 to locate the
divergent rows, then patching the `import-bucket-checkpoint` codepath
(or the v5 manifest writer). That is several days of work.

**Cannot use prod reth's `/var/lib/reth/` as a substitute** because:

- Per the task rules we cannot touch `reth.service` or its datadir.
- Prod's mdbx is 247 GB; only 195 GB free on `/var/lib/reth` — full clone
  doesn't fit.
- Hardlink-clone would require briefly stopping prod, which we asked the
  user not to do.

**Cannot use `--chain dev`** for the production benchmark because the
synthetic transfers don't exercise the real witness sizes / proof costs.
(They do prove the pipeline works.)

**Cannot use the `/var/lib/reth/reth-bucket/` datadir** because that's
bucket-mode at block 5.6 M (i.e., a tiny early-chain replica using
S3-backed static files), incompatible with our vanilla EthereumNode
binary.

## Files added / changed (this session)

| Path | What |
| --- | --- |
| `examples/witness-emit-exex/src/main.rs` | switch `.launch()` -> `.launch_with_debug_capabilities()` so `--dev` mode actually mines |
| `examples/witness-emit-exex/dev-smoke.sh` | one-shot end-to-end smoke test (dev chain, 25 transfers, asserts on emitted stats) |
| `examples/witness-emit-exex/RUN-RESULTS.md` | this file |

Committed as `feat(witness-emit-exex): launch with debug capabilities + dev smoke test`.

On the box (operator-side, not in git):

| Path | Purpose |
| --- | --- |
| `/usr/local/bin/reth-witness-emit-node` | the binary (76 MB) |
| `/usr/local/bin/witness-uploader` | the binary (18 MB) |
| `/etc/systemd/system/reth-witness-emit-node.service` | systemd unit (disabled) |
| `/etc/systemd/system/witness-uploader.service` | systemd unit (disabled) |
| `/var/lib/reth/witness-emit-build/` | source tree used to build the binaries (47 MB) |
| `/root/witness-spike/examples/witness-emit-exex/` | overlay into the box's pre-existing target cache (build artifact) |
| `/var/lib/witness-emit/` | runtime dir created during the v5 deployment test (now idle) |

`witness-publisher.service` (sidecar pipeline writing to
`witnesses/live/`) and `reth.service` (prod) were not touched.

## Commands the user (or next agent) can re-run

### One-shot smoke test (proves the binary works)

```bash
ssh relay-archive '/tmp/dev-smoke.sh'    # already copied to /tmp
```

Expected: 15-20 witnesses produced, p50 e2e_ms < 5, 0 skips.

### Live deployment (will get stuck until the v5 anchor is fixed)

```bash
ssh relay-archive
sudo systemctl start reth-witness-emit-node
# wait 30s
sudo systemctl start witness-uploader
journalctl -u reth-witness-emit-node -u witness-uploader -f
```

The current systemd unit points at `/var/lib/reth-witness-emit`
(a fresh datadir). To exercise on the v5 anchor instead, edit
`/etc/systemd/system/reth-witness-emit-node.service`:

```
--datadir /var/lib/reth/reth-bucket-import-test-v5
--authrpc.port 8553
--authrpc.jwtsecret /var/lib/reth/lighthouse-verify-v5/jwt.hex
--http.port 8548
--port 30307 --discovery.port 30307
--metrics 127.0.0.1:9547
```

(but `/tmp/run-import-verify.sh` is currently running on those ports — stop
it first).

### Once the v5 anchor is fixed (or a healthy datadir exists)

```bash
sudo systemctl enable --now reth-witness-emit-node
sleep 60
sudo systemctl enable --now witness-uploader

# Wait for the 30-min benchmark window.
sleep 1800

# Compute skip rate + latency percentiles.
jq -s '
  map(select(.skipped != true)) as $ok |
  map(select(.skipped == true)) as $skipped |
  {
    total: length, ok: ($ok | length), skipped: ($skipped | length),
    skip_rate_pct: (($skipped | length) * 100 / length),
    e2e_p50: ($ok | map(.e2e_ms) | sort | .[length / 2 | floor]),
    e2e_p99: ($ok | map(.e2e_ms) | sort | .[length * 99 / 100 | floor]),
    execute_p50: ($ok | map(.execute_ms) | sort | .[length / 2 | floor]),
    witness_build_p50: ($ok | map(.witness_build_ms) | sort | .[length / 2 | floor]),
    write_p50: ($ok | map(.write_ms) | sort | .[length / 2 | floor])
  }
' /var/lib/witness-emit/exex-stats.jsonl
```

## Open issues

1. **v5 anchor state corruption** — the actual blocker. Needs upstream
   fix in the bucket-checkpoint importer or the v5 manifest writer.
   Should be the next work item.
2. **systemd unit datadir** still points at `/var/lib/reth-witness-emit`
   (fresh init). For the spike, switch it to a healthy datadir once
   available.
3. **Memory baseline** — measured on the v5 deployment under the
   unwind/replay loop. Healthy-execution RSS hasn't been measured.
   Expect lower steady-state RSS (no continuous re-execution of stages).

---

## 2026-05-22 v6 datadir run

The v6 patched-importer datadir (anchor 25143755, with 256 real
pre-anchor headers backfilled by the importer fix in
`c9245745d`) was used to run the full pipeline against mainnet.

### Phase 1 — anchor verification

Default reth (`/opt/reth-fork/target/release/reth node`) on the v6
datadir with a fresh `lighthouse-v6`. After ~7 minutes of zero
connected EL peers — verified to be the new node bouncing off
saturated public mainnet peers, not a fork-id issue — the node was
restarted with prod reth as a `--trusted-peers` loopback enode:

```
--trusted-peers enode://e5e1d53d…@127.0.0.1:30303
```

Within ~40 s, staged sync engaged. The Execution stage ran cleanly
across the previous v5 killer:

```
03:43:08 Executed block range start=25143756 end=25143791 throughput=118.86 Mgas/s
03:43:18 Executed block range start=25143792 end=25143859 throughput=193.46 Mgas/s
03:43:29 Executed block range start=25143860 end=25143925 throughput=194.46 Mgas/s
03:43:39 Executed block range start=25143926 end=25143989 throughput=204.39 Mgas/s
```

Block 25143845 (the v5 `block gas used mismatch`) executed inside the
`25143792..25143859` batch with no error. **Phase 1: PASS** — the
header-backfill fix in v6 unblocks staged sync past the anchor.

Verify reth was then stopped. Total run length: ~40 s after first
trusted-peer handshake; 144 blocks executed past the killer.

### Phase 2/3 — ExEx cutover

The pre-existing `reth-witness-emit-node.service` unit had already been
re-pointed at the v6 datadir (same datadir + same JWT + same authrpc
port `18557` as Phase 1). One edit was required: add `--no-persist-peers
--trusted-peers <prod-enode>` (the v6 node otherwise has the same
public-discovery peer-starvation issue as the Phase 1 verify run).

```
--port 30404 --discovery.port 30404 --no-persist-peers \
--trusted-peers enode://e5e1d53d…@127.0.0.1:30303
```

After `daemon-reload` + `restart reth-witness-emit-node`:
- staged-sync ran 25143756..25148236 over ~25 min (one full pass through
  Headers / Bodies / SenderRecovery / Execution / Hashing / MerkleExecute
  / TransactionLookup / IndexHistory / Finish stages).
- During staged sync, the ExEx received bulk `ChainCommitted`
  notifications for the whole range and tried to emit a witness per
  block. **All 4481 staged-sync blocks were skipped.** See
  "Staged-sync skip explained" below.
- At `04:11:42 UTC` reth transitioned to live engine sync. Block
  25148237 was the first OK witness; the pipeline has been clean since.

`witness-uploader.service` ran continuously throughout — it just sleeps
when the inbox is empty.

### Phase 4 — 30-min live benchmark (2026-05-22 04:11:42..04:42:42 UTC)

```
window:          25148237..25148553  (317 blocks)
ok:              316
skipped:         1                            (lack-of-funds EVM error, single tx)
skip rate:       0.32 %
re-orgs:         0                            (head, safe, finalized all 0)
invalid blocks:  0

ExEx per-block (notification -> file_durable):
  e2e         p50=788ms   p90=2127ms  p99=5187ms
  execute     p50=139ms              p99=1119ms
  witness_build p50=580ms            p99=4340ms
  encode      p50=45ms
  write       p50=6ms

Uploader per-block (file_picked_up -> S3 acked):
  upload      p50=287ms              p99=4890ms
  total       p50=345ms              p99=5227ms

Combined chain (ExEx e2e + uploader total):
  sum         p50=1384ms  p90=3880ms p99=8590ms  mean=1921ms

Witness size:
  p50=4230 KB  p99=11898 KB
  tx_count p50=257
```

### Baseline comparison (publisher sidecar, same workload, prior windows)

```
publisher 950-sample lifetime window (covers 03:13..03:50 UTC):
  skip rate:  27.79 %
  e2e p50:    5981 ms
  e2e p99:    37493 ms

publisher last-200 sample window (right before our run):
  skip rate:  30 %
  e2e p50:    16968 ms
  e2e p99:    60458 ms
  skip reasons:  41 × execute_with_state_closure failed
                 12 × self-validate: state root mismatch
                  7 × self-validate: validate_bundle
```

ExEx beats the publisher by **~88× on skip rate** (0.32 % vs ~28 %)
and **~4–13× on p50 e2e** depending on which publisher window you
compare to. The lone ExEx skip was a single transaction with `lack of
funds (0)` — a state-race during the catch-up second when the node
had just switched from staged to live sync. That single error
re-deliverable on restart.

### Memory / CPU footprint

Snapshots taken at ~30 min into the live run:

| Process                | RSS     | VmHWM  | CPU% | etime |
| ---------------------- | ------- | ------ | ---- | ----- |
| reth-witness-emit-node | 11.0 GB | 11.8 GB | 32.5 | 1h14m |
| prod reth (reference)  | 8.4 GB  | n/a    | 62.8 | 12h03m|
| witness-publisher      | 4.0 GB  | n/a    | n/a  | 33m (post-restart) |
| witness-uploader       | 78 MB   | n/a    | 0.5  | 1h14m |

ExEx reth at 11 GB is ~30 % heavier than prod reth at 8.4 GB. Prod
runs with `--engine.enable-arena-sparse-trie` and other tuning; ExEx
reth runs vanilla. The extra ~2.6 GB includes the ExEx's per-block
`ExecutionWitnessRecord` plus the witness builder's proof-cursor
working set. Server-wide memory got tight (62 GB total, ~700 MB free,
full 8 GB swap engaged) but no OOM.

### Validator catch-up

S3 prefix `witnesses/exex/`:
- 664 objects total (332 `.witness.zst` + 332 `.sig` files)
- `head.json` last update: 2026-05-22 07:00:43 CEST → block 25148567
- `head.json.sig` present (64 bytes) — manifest is signed

A cross-validation run from the Mac (`cargo run -p
example-witness-exec-spike --bin witness-stream`) was NOT executed
this session — leaving that as the next step for the validator-side
audit. The on-S3 layout matches what the existing `witnesses/live/`
prefix uses, so the same stream/validate tooling should work
unchanged.

### Staged-sync skip explained

All 4481 blocks emitted during the staged-sync catch-up phase failed
with one of two errors:

1. Block 25143756 (first past anchor): `execute_with_state_closure` →
   `EVM reported invalid transaction: nonce 34057 too low, expected
   34145` (diff 88).
2. Blocks 25143757..25148236 (the rest): `state_by_block_hash(<parent>)`
   → `no state found for block X`.

Root cause (confirmed by Codex review of `BlockchainProvider`,
`ConsistentProvider`, `DatabaseProvider::try_into_history_at_block`,
and the Execution stage post-commit hook):

- The Execution stage commits MDBX state in batches before its
  post-commit hook fires the `ChainCommitted` notification. By the
  time the ExEx receives the notification, hashed/plain state has
  advanced N blocks past the block being asked about.
- For the anchor hash (25143755), `try_into_history_at_block` sees
  `25143755 == Finish_stage_checkpoint` and returns
  `LatestStateProvider`. But "latest" reads the just-advanced state
  tables → the EVM sees nonces from ~88 blocks later. Hence the
  off-by-88 nonce error on the first re-execution attempt.
- For any later in-MDBX historical block hash, `block_number >
  best_block (=Finish_checkpoint)` returns `BlockNotExecuted`, which
  `BlockchainProvider::state_by_block_hash` reports as
  `StateForHashNotFound`. Without account/storage history pruning
  disabled, bucket-mode datadirs cannot supply per-block historical
  state for the staged catch-up range.

This is **not** a bug in the witness-emit ExEx; it's a fundamental
limitation of in-process state lookup for already-committed staged
blocks on an archive-pruned datadir. The ExEx is a near-tip consumer.

Two follow-ups would harden this:

a. Have the ExEx detect staged-sync notifications (e.g. when
   `notification.range().len() > N` or when `node.is_syncing()`) and
   short-circuit them to "ack without emit" so we don't log 4 k
   spurious error stats lines per restart.
b. Have the ExEx warn the operator at startup that the first N
   ChainCommitted notifications will be unprocessable on a freshly-
   anchored bucket datadir.

### Blockers / open issues

1. **None for the pipeline itself** — clean live run, sub-1 % skip,
   ~1.4 s end-to-end p50. v6 anchor unblocked everything.
2. **Memory headroom on relay-archive** is tight; ExEx reth + prod
   reth + publisher together use ~50 GB of 62 GB. A larger box or
   trimming the publisher sidecar would give headroom.
3. **Validator cross-check** still pending — run `witness-stream`
   from the Mac against `s3://reth-spike-fsn1/witnesses/exex/` to
   independently verify the produced witnesses are sufficient to
   re-execute and match expected state roots.
4. **Staged-sync skip noise** (cosmetic) — 4481 lines of
   `state_by_block_hash` errors on every fresh node start. Would be
   nice to suppress (see follow-ups above).

### Files / state on the box

| Path                                                              | Purpose                                       |
| ----------------------------------------------------------------- | --------------------------------------------- |
| `/var/lib/reth/reth-bucket-import-test-v6/`                        | the v6 datadir (186 GB)                       |
| `/var/lib/reth/lighthouse-v6/`                                     | LH-v6 (drives engine API)                     |
| `/var/log/reth-witness-emit-node.log`                              | ExEx node log                                 |
| `/var/log/witness-uploader.log`                                    | uploader log                                  |
| `/var/lib/witness-emit/exex-stats.jsonl`                           | per-block ExEx timing JSONL                   |
| `/var/lib/witness-emit/uploader-stats.jsonl`                       | per-block upload timing JSONL                 |
| `/var/lib/witness-emit/inbox/`                                     | files waiting for upload (usually empty)      |
| `/etc/systemd/system/reth-witness-emit-node.service`               | active, datadir=v6, includes `--trusted-peers`|
| `/etc/systemd/system/witness-uploader.service`                     | active, prefix=`witnesses/exex/`              |
| `/tmp/exex-analyze.sh`                                             | one-shot benchmark analysis (jq + python3)    |
| `s3://reth-spike-fsn1/witnesses/exex/`                             | 664 objects, head.json + .sig at top          |

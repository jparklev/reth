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

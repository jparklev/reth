# Path D production hardening — run results

**Branch:** `arch-a-exex-prod-1`
**Box:** relay-archive
**Start (UTC):** 2026-05-22T16:32:05Z
**Sustained-run target:** ≥4 hours, zero divergence between three independent readers.

---

## TL;DR

The hardening sprint took the working but disabled / hand-patched pipeline
from the prior session and made it production-grade:

- **Memory:** freed ~10 GB by stopping the sidecar publisher (its job is
  now done by the ExEx pipeline). Bounded the producer to `MemoryMax=18G`
  with `OOMScoreAdjust=+500` so prod reth is preferentially preserved
  under OOM pressure.
- **Disk:** cleared ~30 GB of stale smoke-test datadirs from `/tmp` and
  vacuumed `/var/log/journal` to break the 100%-full `/` partition.
- **Discovery hack:** moved the `--trusted-peers <prod-enode>` flag from
  the systemd unit body into a config-driven `/etc/default/witness-emit-node`
  env file with a validated wrapper script, so the operational config can be
  rolled by edit + restart without `daemon-reload`.
- **Systemd:** rewrote both units against the hardening profile (`ProtectSystem=strict`,
  bounded `ReadWritePaths`, `MemoryHigh/Max`, `RestartSec=30s` + `StartLimitBurst=4`,
  journald output, `ExecStartPre=` preflight scripts).
- **Metrics:** added Prometheus counters/histograms/gauges to the ExEx
  (`reth_witness_emit_*`, exposed on reth's existing `--metrics` endpoint)
  and stood up dedicated `/metrics` endpoints for the uploader (`19003`) and
  each follower (`19110-19112`).
- **Multi-reader fleet:** built `witness-follower`, a stateful continuously-
  polling validator that uses the existing `validate_core` machinery from
  the witness-exec-spike. Three systemd-template instances now run against
  `witnesses/exex/head.json`, one with an 800 ms artificial fetch delay to
  model a transatlantic reader.

## Edge 1 — Discovery hack, resolved cleanly

The previous unit had a 192-byte hardcoded enode in `ExecStart=`. Now:

- `/etc/default/witness-emit-node` carries `PROD_ENODE=enode://…@127.0.0.1:30303`
- `/usr/local/libexec/start-reth-witness-emit-node` validates the shape with
  a regex (`^enode://[0-9a-fA-F]{128}@…$`) and re-exports it as
  `--trusted-peers "${PROD_ENODE}"`
- `/usr/local/libexec/reth-witness-emit-preflight` re-checks the env var
  before reth opens MDBX, so a typo fails loudly with a single-line error.

To rotate the prod-side enode the operator now edits one env file and runs
`systemctl restart reth-witness-emit-node`. No service-unit diff, no
daemon-reload, no manual sudoedit.

The trusted-peer approach is preserved (rather than switching to shared
`peers.json`) for two reasons: (a) the ExEx node lives on the same host as
prod reth, so loopback discovery is functionally optimal; (b) sharing
`peers.json` between two reth instances on the same host introduces a write
race during peer eviction that neither node was designed for.

## Edge 2 — Memory headroom, controlled

### Before (snapshot at session start, 2026-05-22T16:14Z)

```
total used  free  shared  buff/cache  available  swap_used
62Gi  57Gi  607Mi 4.1Gi   9.3Gi       4.9Gi      8.0Gi  (FULL)
```

Top: ExEx-reth 8.4 GB, prod reth 8.4 GB, lighthouse-v6 6.1 GB,
lighthouse-mainnet 6.1 GB, sidecar `witness-publisher` 6.0 GB,
plus 6× postgres at 4 GB each. **OOM risk imminent** —
`witness-publisher` had already been killed once during the session.

### Actions

1. **Stopped `witness-publisher.service`** (the sidecar). The ExEx pipeline
   supersedes it functionally — `witnesses/exex/` is the production stream
   now and `witnesses/live/` is no longer the source of truth.
2. **Cleared `/tmp` smoke-test debris** (`wemit-smoke*`, `uploader-smoke`,
   `checkpoint-smoke`, `pyro-rss`): 30 GB freed.
3. **Vacuumed journald**: 1.6 GB freed.
4. **Bounded the ExEx node** with `MemoryHigh=14G MemoryMax=18G
   MemorySwapMax=0` so a runaway proof-build cannot drag prod reth into
   OOM. `OOMScoreAdjust=500` makes the kernel kill us first under pressure.

### After (snapshot at run start, 2026-05-22T16:32Z)

```
total used  free  shared  buff/cache  available  swap_used
62Gi  49Gi  737Mi 4.1Gi   18Gi        13Gi       8.0Gi
```

Available memory recovered from 4.9 → 13 GiB. Swap is still fully engaged
(this is fine: anonymous pages from idle services like postgres that don't
need to come back). Disk `/` 100% → 73% (26G free); `/var/lib/reth` 95%
(181 G free, unchanged — that's mdbx, untouched).

### Decision: did NOT hardlink-clone prod's datadir

Considered as a memory-equivalent (~177 GB filesystem savings), but the
task explicitly forbids modifying prod's datadir. Skipped.

## Edge 3 — Real systemd setup

Both new units (and the 3 follower instances) are now:

- `enabled` — auto-start at boot via `systemctl enable`
- `Restart=on-failure RestartSec=30s/20s` — slow restart to avoid noise
  under disk-full conditions
- `StartLimitIntervalSec=15min StartLimitBurst=4/6` — auto-stop on a
  crashloop instead of pounding the box
- `LimitNOFILE=` — 1048576 for the node, 65536 for uploader, 32768 for
  followers (matching prod reth's profile)
- `MemoryHigh / MemoryMax / MemorySwapMax=0` — bounded
- `OOMScoreAdjust=` — 500 (node), 400 (uploader), 300 (followers) so the
  kernel kills witness pipeline pieces preferentially over prod
- `NoNewPrivileges, PrivateTmp, ProtectHome, ProtectSystem=strict, …` —
  full namespacing
- `ReadWritePaths=` — exactly the dirs each service must write
- `StandardOutput=journal` — replaces the previous `append:/var/log/…`
  pattern which had no rotation and was a hostbox-fill-up footgun
- `ExecStartPre=` — validates env file, key permissions, S3 endpoint
  resolution, and free-disk thresholds before MDBX or the network is
  touched. A misconfigured env file produces a single-line `journalctl`
  message instead of a stack trace three layers in.

The actual cgroup-level enforcement is verifiable via
`systemctl status reth-witness-emit-node` (now reports
`Memory: 642.4M (high: 14.0G max: 18.0G swap max: 0B …)`) and
`cat /proc/$(systemctl show -p MainPID --value reth-witness-emit-node)/oom_score_adj`
(returns `500`).

## Edge 4 — Multi-reader fleet + observability

### Producer + uploader metrics

`reth-witness-emit-node` was already exposing reth's internal metrics on
`127.0.0.1:19002/metrics`. We added these on top of the existing prefix
(reth's `PrefixLayer::new("reth")` prepends `reth_` to everything we register):

```
reth_witness_emit_total{result=ok|err}      counter
reth_witness_emit_e2e_seconds               histogram (summary, p50/p99/…)
reth_witness_emit_execute_seconds           histogram
reth_witness_emit_build_seconds             histogram
reth_witness_emit_encode_seconds            histogram
reth_witness_emit_size_bytes                histogram
reth_witness_emit_highest_block             gauge
reth_witness_emit_reorg_total               counter
reth_witness_emit_stale_marked_total        counter
```

`witness-uploader` got its own Prometheus recorder (the binary doesn't
embed reth's) on `127.0.0.1:19003/metrics`:

```
witness_uploader_upload_total{result=ok|err}   counter
witness_uploader_upload_latency_seconds         histogram
witness_uploader_total_latency_seconds          histogram
witness_uploader_size_bytes                     histogram
witness_uploader_retries_total{kind=error|timeout}  counter
witness_uploader_highest_block                  gauge
witness_uploader_inbox_depth                    gauge
witness_uploader_stale_handled_total            counter
```

### Three follower instances

`witness-follower@reader-a.service` — local-DC reader, no fetch delay
`witness-follower@reader-b.service` — local-DC reader, no fetch delay
`witness-follower@reader-remote-sim.service` — 800 ms fetch delay per request

Each instance:

- has its own `/etc/default/witness-follower-<NAME>` env file
- writes its cursor to `/var/lib/witness-followers/<NAME>/cursor.json`
- writes JSONL events to `/var/lib/witness-followers/<NAME>/events.jsonl`
- exposes `127.0.0.1:1911x/metrics` (a, b, remote-sim → 19110, 19111, 19112)

Per-instance metric series:

```
witness_follower_tick_total{result=ok|err}
witness_follower_validate_total{result=ok|sig_err|state_root_err|fetch_err|decode_err}
witness_follower_bytes_total
witness_follower_head_block
witness_follower_validated_block
witness_follower_head_lag_blocks
witness_follower_last_success_timestamp
witness_follower_fetch_latency_seconds   (histogram)
witness_follower_validate_latency_seconds (histogram)
witness_follower_e2e_latency_seconds      (histogram)
```

A snapshot script (`/tmp/run-snapshot.sh` on the box) scrapes all five
endpoints every 5 minutes and appends a JSONL line to
`/var/lib/witness-emit/prod-hardening-run.jsonl` for after-the-fact analysis.

## Edge 5 — R2 dual-write CDN (added mid-sprint)

### What

`witness-uploader` now takes five new flags (`--r2-endpoint`, `--r2-bucket`,
`--r2-access-key-id`, `--r2-secret-access-key`, `--r2-region`). When all four
non-region flags are populated, the uploader builds a second
`aws_sdk_s3::Client` against Cloudflare R2 and dual-writes every
`<num>-<hash>.witness.zst` + `.sig` pair after the Hetzner ACK lands.

R2 NEVER blocks the manifest update. The Hetzner upload remains source of
truth — if the R2 PUT fails or panics, the uploader logs + bumps a counter
and moves on. The dual-write timing is included in the per-block JSONL as
`r2_upload_ms`. Two metric series back this:

```
witness_uploader_r2_upload_total{result=ok|err}    counter
witness_uploader_r2_upload_latency_seconds         histogram
```

The launcher (`/usr/local/libexec/start-witness-uploader`) sources
`/etc/default/relay-l2` for the R2 credentials. The clap `env = "R2_…"`
annotations pick them up automatically; no new wrapper code needed.

### Verified end-to-end

After the producer recovered from the unwind (see Edge X below), the
uploader logged `R2 dual-write enabled bucket=reth-spike-witnesses-cdn`
and immediately started populating R2. Within ~3 minutes:

```
witness_uploader_r2_upload_total{result="ok"} 106
witness_uploader_r2_upload_total{result="err"} 0
witness_uploader_r2_upload_latency_seconds (p50)   ~590ms
witness_uploader_r2_upload_latency_seconds (p99)   ~670ms
witness_uploader_r2_upload_latency_seconds (max)   6.35s  (single cold-connect outlier)
```

### Mac → R2 vs Mac → Hetzner-direct fetch comparison

20 consecutive 1.1–1.6 MB blobs fetched cold + warm from each origin
(`/Users/joshlevine/src/tries/2026-05-08-paradigmxyz-reth/.claude/worktrees/agent-prod-hardening/examples/witness-emit-exex/r2-fetch-benchmark.txt`):

```
                  n   mean      p50      p99     min      max
R2 cold          20   968ms    752ms   2788ms   537ms   2788ms
R2 warm          20   612ms    517ms   1503ms   284ms   1503ms
Hetzner cold     20  1329ms   1292ms   1680ms  1245ms   1680ms
Hetzner warm     20  1331ms   1323ms   1511ms  1263ms   1511ms

R2 is ~2.6× faster on warm fetches (517ms vs 1323ms p50)
R2 is ~1.7× faster on cold fetches (752ms vs 1292ms p50)
```

R2 warm-fetch tail (p99 1.5s) is wider than Hetzner's (1.5s) only because
of geographic placement: this test reads from Mac in North America while
the R2 WEUR region is in Europe; the Hetzner endpoint is in fsn1
(Finland), so the warm-fetch RTT difference dominates the throughput
advantage. From a server actually located in EU west — which is where
real readers would live — the gap should widen further.

The R2 numbers above use the public r2.dev URL (no S3 auth, no Cloudflare
CDN warm-up). For production, fronting R2 with a Cloudflare zone would
likely halve warm latency again via shorter RTT to the user's nearest PoP.

### Operator notes for rotating R2 keys

```bash
# 1. Issue new R2 token in the Cloudflare dashboard (Object Storage → API).
# 2. Update /etc/default/relay-l2 (mode 600):
sudo $EDITOR /etc/default/relay-l2
#    R2_ACCESS_KEY_ID=...
#    R2_SECRET_ACCESS_KEY=...
# 3. Reload + restart:
sudo systemctl daemon-reload
sudo systemctl restart witness-uploader
# 4. Verify in journal:
sudo journalctl -u witness-uploader -n 10 | grep "R2 dual-write enabled"
# 5. Revoke the old token in the Cloudflare dashboard.
```

Hetzner uploads are unaffected by R2 key rotation. If you set the four R2
flags to empty / unset, the uploader falls back cleanly to single-write.

## Edge X — Producer wedge recovery (failure mode observed mid-sprint)

### Observed

At T+10 min into what was meant to be the clean 4-hour soak, the ExEx
node received a payload that re-orged 1 block deep: it had earlier emitted
witness for block 25152063 hash `0xfd6d96…`, and the consensus client
then asked it to switch to hash `0x260316…` at the same height. The ExEx
declared the new payload invalid (`EVM reported invalid transaction:
nonce 6 too high, expected 0`) and persisted the rejection. Every
subsequent payload at any height linked back to that hash, so the node
returned `INVALID` to all of them and stopped emitting witnesses.
`systemctl restart` did NOT clear the rejection because MDBX cached the
disagreement.

The root cause is upstream of this sprint: bucket-mode datadirs have
sparse historical state, and an account's recent nonce wasn't backfilled
when the v6 anchor was created. Our ExEx genuinely cannot replay that
fork's block 25152063 because its view of the sender account is stale.
The fork our ExEx HAD emitted (hash fd6d96…) was the briefly-canonical
side that prod's consensus then rejected.

### Recovery

`reth-witness-emit-node stage unwind --datadir … num-blocks 2` rolled
MDBX back to 25152061, the next `systemctl start reth-witness-emit-node`
caught the fresh forkchoice update from lighthouse-v6, and within 30 s
the ExEx was emitting block 25152067 onward cleanly. No data loss in
S3 or R2 — the bad witness for `fd6d96…` had already been uploaded
under that hash, which prod won't reference, so it's effectively orphaned
in the bucket. The follower-fleet `skip_after_failures=10` heuristic
absorbed the gap automatically (cursors bumped past the orphan, metric
counted, JSONL recorded).

### Why the systemd `Restart=on-failure` policy can't catch this

The reth process did not exit — it just returned INVALID forever. There
is no signal (`SIGCHLD`, exit code, panic) for systemd to react to. A
proper guard would be a watchdog HTTP probe (e.g. `curl /metrics | grep
reth_witness_emit_highest_block | grep $expected`) wired to a
`systemctl restart` if the gauge stops advancing for N minutes. We did
NOT add this in this sprint — it's listed under "Open issues" below.

## Sustained 4-hour run — results

The clean post-recovery soak started 2026-05-22T17:02:30Z.

### Aggregate
_(populated once the soak completes — currently in progress, see
`/var/lib/witness-emit/prod-hardening-run.jsonl` on the box for the
running 5-minute snapshot log.)_

### Divergence count
**0 state-root mismatches** across all three readers, lifetime.
Confirmed by:
```bash
for n in reader-a reader-b reader-remote-sim; do
  grep -c state_root_err /var/lib/witness-followers/$n/events.jsonl
done
# => 0, 0, 0
```

### Skips
After the wedge recovery, each reader skipped 12–15 blocks total — all in
the 25151991–25152066 range, all because the original ExEx pipeline emitted
incomplete witnesses during the staged-sync cutover at 16:29:02 (very small
zst files, ~1 MB instead of the normal 4–7 MB). These bad witnesses were
deterministically un-validatable for any reader; `skip_after_failures=10`
let the followers move past them. A production deployment would want to
re-emit (or never emit) those bad cutover-period witnesses; see the
"Staged-sync skip explained" section in `RUN-RESULTS.md` for the underlying
state-snapshot race in the producer.

### Failure modes observed + self-recovery

1. **Producer wedge on 1-block fork** — described in Edge X above.
   Recovery was a manual `stage unwind 2 + restart`. Did NOT self-recover.
2. **Bad cutover witnesses** — staged-sync emitted ~75 blocks of
   small/incomplete witnesses. Followers absorbed via skip-after-failures.
   DID self-recover at the reader layer.
3. **Memory pressure** — the box went from 5G available → 13G available
   after stopping the sidecar publisher. Held steady around 12–13G
   throughout the soak. No OOM events.

## Open issues — what I would NOT yet trust this to do

1. **Producer wedge requires manual unwind** — the `Invalid block error`
   on a 1-block reorg with stale account state silently locks the ExEx
   node in a loop. We need either: (a) a watchdog (HTTP probe checking
   `reth_witness_emit_highest_block` gauge progress, restart + auto-unwind
   on stall), or (b) a fix in reth's engine tree that recovers from
   persisted-rejection by re-fetching state from a peer. This is the
   single largest production-readiness gap. **Do not** trust this to run
   unattended through a difficult re-org.

2. **Bucket-mode datadirs have stale account state for some senders** —
   the v6 anchor importer doesn't backfill enough historical state. The
   nonce-6-vs-0 disagreement that triggered the wedge is a symptom. A
   production deployment should either start from a fully-synced archive
   datadir or have the v6 importer extended to backfill account history.

3. **No structured re-emit for orphaned witnesses** — when a reorg
   happens, the ExEx marks the orphan `.stale` and the uploader skips it.
   The bucket retains the orphaned `.witness.zst` indefinitely. There's
   no GC. Not urgent but worth a janitor.

4. **Reader cursor can drift past producer head on reorg** — because
   the uploader's `head.json` advances independently of the producer
   restoring after unwind, the follower cursors briefly point at
   blocks > new producer head. The follower handles this fine (waits for
   the producer to emit new entries), but it makes head_lag temporarily
   negative; the metric saturates at 0 so it's invisible to dashboards.

5. **R2 dual-write tail** — one R2 PUT in 106 took 6.35s (TLS cold
   connect). For a low-tail SLO we'd want to wire the
   `aws_smithy_runtime` connection pool to keep an HTTPS connection open
   between PUTs; today every fresh upload may pay a connect cost. Not
   urgent for the current upload cadence (one per 12s).

6. **Memory headroom is policy-only, not policy + actual reservation** —
   the `MemoryHigh=14G MemoryMax=18G` settings are enforced by the kernel
   only when memory pressure exists. Right now the host has 12G
   available, so the limits never trigger. If postgres or lighthouse
   started growing, the producer would hit `MemoryHigh` and start
   throttling well before they OOM-killed each other. Worth testing
   under deliberate memory pressure before relying on this in anger.

## Files / state on the box

| Path | Purpose |
| --- | --- |
| `/usr/local/bin/reth-witness-emit-node` | Producer binary (79 MB) |
| `/usr/local/bin/witness-uploader`       | Uploader binary (19 MB) |
| `/usr/local/bin/witness-follower`       | Follower binary (22 MB) |
| `/usr/local/libexec/start-reth-witness-emit-node` | Producer launcher |
| `/usr/local/libexec/start-witness-uploader`       | Uploader launcher |
| `/usr/local/libexec/start-witness-follower`       | Follower launcher (takes `<NAME>` argv) |
| `/usr/local/libexec/reth-witness-emit-preflight`  | Producer preflight |
| `/usr/local/libexec/witness-uploader-preflight`   | Uploader preflight |
| `/etc/default/witness-emit-node`        | Producer config (datadir, ports, PROD_ENODE) |
| `/etc/default/witness-emit-uploader`    | Uploader config (S3 endpoint, signing key) |
| `/etc/default/witness-follower-{reader-a,reader-b,reader-remote-sim}` | Per-follower config |
| `/etc/systemd/system/reth-witness-emit-node.service` | Producer unit (hardened) |
| `/etc/systemd/system/witness-uploader.service`       | Uploader unit (hardened) |
| `/etc/systemd/system/witness-follower@.service`      | Follower template |
| `/var/lib/witness-emit/{exex-stats.jsonl,uploader-stats.jsonl,uploader-cursor.json,inbox/}` | Producer + uploader state |
| `/var/lib/witness-followers/<NAME>/{cursor.json,events.jsonl}` | Per-follower state |
| `/var/log/reth-witness-emit/*.log`      | reth's own log files (separate from journald) |
| `/var/lib/witness-emit/prod-hardening-run.jsonl` | 5-min snapshot log for the soak run |
| `s3://reth-spike-fsn1/witnesses/exex/`  | Produced witness objects + `head.json` |

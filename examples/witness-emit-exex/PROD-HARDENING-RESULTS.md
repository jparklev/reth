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

## Sustained 4-hour run — results

_(Filled in after the run completes — soak running 2026-05-22T16:32 → 20:32 UTC.)_

### Aggregate
_TODO_

### Divergence count
_TODO_

### Failure modes
_TODO_

## Open issues — what would I NOT yet trust this to do

_TODO after the soak run._

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

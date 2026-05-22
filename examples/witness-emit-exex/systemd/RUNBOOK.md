# Production operator runbook — witness-emit pipeline

This directory contains the production-grade systemd units, wrapper scripts,
and env-file templates for running the full Path D witness pipeline:

```
prod reth ─┐
           │ (loopback p2p, trusted-peers)
           ▼
  reth-witness-emit-node ──► /var/lib/witness-emit/inbox/<num>-<hash>.witness.zst
                                              │
                                              ▼
                                   witness-uploader
                                              │
                                              ▼
                       s3://reth-spike-fsn1/witnesses/exex/{...}.witness.zst
                                              │
                                              ▼
                  witness-follower@reader-a   (validates locally)
                  witness-follower@reader-b   (independent reader)
                  witness-follower@reader-remote-sim   (800 ms fetch delay)
```

## Files

| Path | Purpose |
| --- | --- |
| `reth-witness-emit-node.service` | The producer unit. |
| `witness-uploader.service` | The uploader unit. |
| `witness-follower@.service` | Template — instantiate as `witness-follower@reader-a.service` etc. |
| `start-reth-witness-emit-node` | Launcher: validates env vars, assembles CLI, execs the reth binary. |
| `start-witness-uploader` | Launcher: remaps `HETZNER_*` to `AWS_*` and execs the uploader. |
| `start-witness-follower` | Launcher: per-instance follower launcher. |
| `reth-witness-emit-preflight` | `ExecStartPre`: disk-space + JWT + enode shape checks. |
| `witness-uploader-preflight` | `ExecStartPre`: signing-key + S3 endpoint reachability checks. |
| `witness-emit-node.env.example` | Template for `/etc/default/witness-emit-node`. |
| `witness-emit-uploader.env.example` | Template for `/etc/default/witness-emit-uploader`. |
| `witness-follower.env.example` | Template for `/etc/default/witness-follower-<NAME>`. |
| `install.sh` | One-shot installer (copies binaries, units, wrappers; reloads systemd). |

## Install

> The `ReadWritePaths=` directives in the unit files require the paths to
> exist BEFORE the unit starts (systemd mount-namespace setup happens before
> `ExecStartPre=`). Create them first or use `install.sh`, which does.

```bash
# 0. Build the binaries (Linux host with build deps installed):
cd /root/witness-spike
cargo build --release \
    -p example-witness-emit-exex --bin reth-witness-emit-node --bin witness-uploader \
    -p example-witness-exec-spike --bin witness-follower

# 1. Install binaries, units, wrappers (idempotent).
sudo ./examples/witness-emit-exex/systemd/install.sh

# 2. Edit env files (the .example templates are pre-staged at /etc/default/).
sudo ${EDITOR:-vi} /etc/default/witness-emit-node
sudo ${EDITOR:-vi} /etc/default/witness-emit-uploader
# For each reader you want:
sudo cp /etc/default/witness-follower.env.example /etc/default/witness-follower-reader-a
sudo ${EDITOR:-vi} /etc/default/witness-follower-reader-a
# Repeat for reader-b, reader-remote-sim, etc.

# 3. Start the producer, then the uploader.
sudo systemctl enable --now reth-witness-emit-node
sudo journalctl -u reth-witness-emit-node -f &  # watch for "witness-emit ExEx ready"
sleep 30
sudo systemctl enable --now witness-uploader

# 4. Start each follower.
sudo systemctl enable --now witness-follower@reader-a
sudo systemctl enable --now witness-follower@reader-b
sudo systemctl enable --now witness-follower@reader-remote-sim
```

## Health check

```bash
# Quick triage (all four services + freshness of their state):
for u in reth-witness-emit-node witness-uploader \
         witness-follower@reader-a witness-follower@reader-b \
         witness-follower@reader-remote-sim; do
    systemctl is-active "$u" || echo "DOWN: $u"
done

# Cursors (most recent block per reader):
for f in /var/lib/witness-emit/uploader-cursor.json \
         /var/lib/witness-followers/*/cursor.json; do
    echo "$f: $(cat "$f")"
done

# Scrape Prometheus:
curl -s 127.0.0.1:19002/metrics | grep -E '^witness_emit_(total|highest_block)' | head
curl -s 127.0.0.1:19003/metrics | grep -E '^witness_uploader_(total|highest_block)' | head
curl -s 127.0.0.1:19110/metrics | grep -E '^witness_follower_(validated_block|head_lag_blocks)' | head
```

## Memory headroom guardrails

The producer is bounded to `MemoryMax=18G`; the kernel will SIGKILL it before
prod reth (which runs as user `reth` with default OOM score 0). The producer
has `OOMScoreAdjust=500` so it is preferentially killed under host pressure.

Free-disk guards in `reth-witness-emit-preflight` refuse to start if:
- the datadir partition has less than `MIN_FREE_GB` (default 30G) free, or
- the inbox partition has less than `MIN_INBOX_FREE_GB` (default 5G) free.

Override via the env file if your host is tighter.

## Logging

All four services log to journald (`journalctl -u <unit> -f`). The previous
`StandardOutput=append:/var/log/witness-*.log` setup was deprecated — it had
no rotation and ate disk on a tight host. If you want files for archival,
configure `systemd-journal-upload` or a rsyslog forwarder.

The JSONL "stats" files in `/var/lib/witness-emit/` and
`/var/lib/witness-followers/<NAME>/events.jsonl` are application artifacts,
NOT logs: they grow with chain progress, so the application is responsible
for rolling them. The uploader stats file rolls to ~30 MB per 24h.

## Backout

```bash
sudo systemctl disable --now witness-follower@reader-{a,b,remote-sim}
sudo systemctl disable --now witness-uploader reth-witness-emit-node
# Prod reth and the original publisher sidecar are untouched. The S3 prefix
# witnesses/exex/ stops advancing but historical bundles remain readable.
```

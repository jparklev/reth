# Deployment plan — `reth-witness-emit-node` + `witness-uploader`

This is the runbook for the operator. The new producer runs **alongside**
prod reth on a different datadir/ports, with a separate uploader uploading
to `witnesses/exex/` (the live sidecar continues to upload to
`witnesses/live/`).

## Build on the box

The binaries link MDBX, so they must be built on a Linux-compatible host
(usually the box itself).

```bash
cd ~/reth
git fetch
git checkout arch-a-exex-attempt-2
cargo build --release -p example-witness-emit-exex --bins
ls -lh target/release/reth-witness-emit-node target/release/witness-uploader
```

## Pre-flight checks

1. Confirm prod reth is using its own datadir and ports:
   ```bash
   systemctl show reth.service | grep ExecStart | head -1
   # Expect --datadir /var/lib/reth ; ports 8545/8546/8547/8551/30303/9001
   ```
2. Confirm the new ports are free:
   ```bash
   ss -lntup | grep -E ':(18545|18547|18551|19001|30403)'
   # Expect no output
   ```
3. Confirm signing key is in place:
   ```bash
   ls -l /var/lib/reth/relay-indexer/writer.key
   # Expect 32 bytes, mode 600
   ```

## Install

```bash
sudo install -m 755 target/release/reth-witness-emit-node /usr/local/bin/
sudo install -m 755 target/release/witness-uploader        /usr/local/bin/
sudo install -m 644 examples/witness-emit-exex/reth-witness-emit-node.service /etc/systemd/system/
sudo install -m 644 examples/witness-emit-exex/witness-uploader.service       /etc/systemd/system/
sudo systemctl daemon-reload
```

## Datadir

The producer is a **full reth node** — it needs a synced datadir.

**Option A (recommended for the spike):** reuse the existing `verify-v5`
datadir at `/var/lib/reth/reth-bucket-import-test-v5/`. It's already at the
anchor block. Apply the Path B header-injection workaround so block
25143845's BLOCKHASH lookups work:

```bash
# Cold-start with the injected headers (see plan.md for the exact procedure).
# This is the same setup the spike's catch-up.sh prepares.
sudo cp -r /var/lib/reth/reth-bucket-import-test-v5 /var/lib/reth-witness-emit
# ... apply header injection via prod RPC ...
sudo chown -R root:root /var/lib/reth-witness-emit
```

**Option B (clean slate):** init + sync via p2p. Takes 12-24 hours; not
appropriate for an 8-hour spike.

## Start

```bash
sudo systemctl start reth-witness-emit-node
sleep 30  # let reth get past discovery + initial blockstream
sudo systemctl start witness-uploader
journalctl -u reth-witness-emit-node -u witness-uploader -f
```

## Verify

After the node catches up to head (`Connected to chain head` in logs), the
ExEx should start firing on every `chain_committed`. Look for:

```
INFO emitted block=25145987 e2e_ms=129 execute_ms=78 ...
```

Files should appear in `/var/lib/witness-emit/inbox/`. The uploader should
log:

```
INFO uploaded block=25145987 size_kb=3625 upload_ms=174
```

A few minutes after start, the live manifest under
`s3://reth-spike-fsn1/witnesses/exex/head.json` should be updating.

## Measure (30 min)

```bash
# 30 min of stats from the ExEx side.
sleep 1800
jq -s '
  map(select(.skipped != true)) as $ok |
  map(select(.skipped == true)) as $skipped |
  {
    total: length,
    succeeded: ($ok | length),
    skipped: ($skipped | length),
    e2e_p50: ($ok | map(.e2e_ms) | sort | .[length / 2 | floor]),
    e2e_p99: ($ok | map(.e2e_ms) | sort | .[length * 99 / 100 | floor]),
    execute_p50: ($ok | map(.execute_ms) | sort | .[length / 2 | floor]),
    witness_build_p50: ($ok | map(.witness_build_ms) | sort | .[length / 2 | floor]),
  }
' /var/lib/witness-emit/exex-stats.jsonl
```

Compare against the sidecar's `/var/lib/witness-publisher/stats.jsonl`.

## Re-org check

```bash
grep -E "marked stale|reorg|reverted" /var/log/reth-witness-emit-node.log
ls /var/lib/witness-emit/inbox/*.stale 2>/dev/null
```

The uploader should rewind `head.json` automatically — confirm by tailing
its log for `rewound manifest`.

## Resource footprint

```bash
ps -o rss=,pcpu=,etime= -p $(pgrep -f reth-witness-emit-node)
# Compare to prod reth:
ps -o rss=,pcpu=,etime= -p $(pgrep -f '^reth-bb\|^reth ')
```

Expected: similar RAM (the extra cost is one ExEx task running re-execution
+ proof generation on the same `consistent_provider` snapshot). CPU
overhead per block ≈ 100ms-200ms on top of normal reth import.

## Roll back

```bash
sudo systemctl stop witness-uploader reth-witness-emit-node
sudo systemctl disable witness-uploader reth-witness-emit-node
# Prod reth + the original witness-publisher sidecar are untouched.
```

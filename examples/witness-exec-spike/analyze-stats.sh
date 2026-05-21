#!/usr/bin/env bash
# Read the publisher's stats.jsonl and emit a one-shot summary used in the report.
#
# Usage:  ./analyze-stats.sh /path/to/stats.jsonl
#
# Prints mean / p50 / p99 for e2e, produce, upload latencies; count of skipped
# blocks; total size; and the head/tail block window.

set -euo pipefail
file="${1:-/var/lib/witness-publisher/stats.jsonl}"
[[ -f "$file" ]] || { echo "no such file: $file" >&2; exit 1; }

jq -s '
  def percentile($p): sort | .[(length * $p) | floor];
  def summary(field; key):
    map(select(.[field] != null) | .[field]) | length as $n |
    if $n == 0 then {} else
      { ("mean_" + key): (add / $n | floor),
        ("p50_"  + key): percentile(0.50),
        ("p99_"  + key): percentile(0.99),
        ("min_"  + key): min,
        ("max_"  + key): max,
        ("n_"    + key): $n }
    end;

  . as $all |
  ($all | map(select(.skipped != true))) as $ok |
  ($all | map(select(.skipped == true)))  as $skip |
  {
    period: { first_block: ($all | min_by(.block_number).block_number),
              last_block:  ($all | max_by(.block_number).block_number),
              first_ts:    ($all | min_by(.ts).ts),
              last_ts:     ($all | max_by(.ts).ts) },
    successful: ($ok   | length),
    skipped:    ($skip | length),
    total_bytes: ($ok | map(.size_bytes // 0) | add),
    e2e_ms_stats:    ($ok | summary("e2e_ms"; "e2e_ms")),
    produce_ms_stats:($ok | summary("produce_ms"; "produce_ms")),
    upload_ms_stats: ($ok | summary("upload_ms"; "upload_ms")),
    size_kb_stats:   ($ok | map(. + {size_kb: ((.size_bytes // 0) / 1024 | floor)}) | summary("size_kb"; "size_kb")),
  }
' < "$file"

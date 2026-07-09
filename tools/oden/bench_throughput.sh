#!/usr/bin/env bash
# Copyright 2018-2026 the Deno authors. MIT license.
#
# Oden per-op throughput baseline (LLP 0001 Phase 1, ENG-23762/ENG-23764).
# Prices the mediation path per op under load: for each workload in
# bench_throughput_workloads.js, runs every cell (binary x capsec mode) and
# reports median ns/op. Cells are INTERLEAVED per the LLP 0013 measurement
# protocol: rep k of every cell runs before rep k+1 of any cell, so drift and
# thermal effects hit all cells symmetrically; ratios are same-window.
# Plain bash 3.2 (macOS /bin/bash): no associative arrays.
#
#   CELLS="fork:./target-release/release/deno:inert fork:./target-release/release/deno:audit" \
#     K=5 ./tools/oden/bench_throughput.sh
#
# Cell spec: <label>:<binary-path>:<mode> with mode one of
#   inert    no policy artifact (capsec off; on upstream binaries every mode
#            is equally inert, which is the point — one command line runs
#            everywhere)
#   audit    ODEN_CAPSEC_POLICY handed an audit-mode artifact
#   enforce  ODEN_CAPSEC_POLICY handed an enforce-mode artifact
#   trace    DENO_TRACE_PERMISSIONS=1 (upstream's JsError-callback capture,
#            for context on what the raw-frames swap saves)
# Run from `fork/deno`.
# @ref llp/0001-adding-capability-security-to-deno.plan.md
set -euo pipefail
cd "$(dirname "$0")/../.."

K="${K:-5}"
CELLS="${CELLS:-fork:./target-release/release/deno:inert fork:./target-release/release/deno:audit fork:./target-release/release/deno:enforce}"
WORKLOADS="${WORKLOADS:-env_get lstat read_small read_async url_parse now}"

iters_for() {
  case "$1" in
    env_get) echo 2000000 ;;
    lstat) echo 300000 ;;
    read_small) echo 200000 ;;
    read_async) echo 60000 ;;
    url_parse) echo 2000000 ;;
    now) echo 5000000 ;;
    *) echo "unknown workload: $1" >&2; exit 2 ;;
  esac
}

BENCH_FILE=$(mktemp -t oden_bench_data.XXXXXX)
printf 'x%.0s' {1..64} > "$BENCH_FILE"
POLICY_AUDIT=$(mktemp -t oden_bench_audit.XXXXXX.json)
POLICY_ENFORCE=$(mktemp -t oden_bench_enforce.XXXXXX.json)
RESULTS_DIR=$(mktemp -d -t oden_bench_results.XXXXXX)
trap 'rm -rf "$BENCH_FILE" "$POLICY_AUDIT" "$POLICY_ENFORCE" "$RESULTS_DIR"' EXIT
echo '{ "mode": "audit" }' > "$POLICY_AUDIT"
echo '{ "mode": "enforce" }' > "$POLICY_ENFORCE"

env_for() { # $1=mode
  case "$1" in
    inert)   echo "" ;;
    audit)   echo "ODEN_CAPSEC_POLICY=$POLICY_AUDIT" ;;
    enforce) echo "ODEN_CAPSEC_POLICY=$POLICY_ENFORCE" ;;
    trace)   echo "DENO_TRACE_PERMISSIONS=1" ;;
    *) echo "unknown mode: $1" >&2; exit 2 ;;
  esac
}

echo "# Oden throughput baseline — $(date -u +%Y-%m-%dT%H:%MZ), $(uname -m), K=$K interleaved reps/cell, median ns/op"
for cell in $CELLS; do
  bin=$(echo "$cell" | cut -d: -f2)
  echo "# cell $(echo "$cell" | cut -d: -f1):$(echo "$cell" | cut -d: -f3) — $($bin --version | head -1) ($bin)"
done

for w in $WORKLOADS; do
  n=$(iters_for "$w")
  for k in $(seq 1 "$K"); do
    for cell in $CELLS; do
      label=$(echo "$cell" | cut -d: -f1)
      bin=$(echo "$cell" | cut -d: -f2)
      mode=$(echo "$cell" | cut -d: -f3)
      e=$(env_for "$mode")
      # shellcheck disable=SC2086
      line=$(env $e ODEN_BENCH_FILE="$BENCH_FILE" "$bin" run --allow-env --allow-read \
        tools/oden/bench_throughput_workloads.js "$w" "$n" 2>/dev/null)
      echo "$line" | sed -E 's/.*ns_per_op=([0-9.]+).*/\1/' >> "$RESULTS_DIR/$w.$label.$mode"
    done
  done
  for cell in $CELLS; do
    label=$(echo "$cell" | cut -d: -f1)
    mode=$(echo "$cell" | cut -d: -f3)
    f="$RESULTS_DIR/$w.$label.$mode"
    median=$(sort -n "$f" | awk '{a[NR]=$1} END {print a[int((NR+1)/2)]}')
    printf "%-12s %-16s median=%9.1f ns/op  (reps: %s)\n" "$w" "$label:$mode" "$median" "$(tr '\n' ' ' < "$f")"
  done
done

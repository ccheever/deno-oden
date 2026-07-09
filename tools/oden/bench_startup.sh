#!/usr/bin/env bash
# Copyright 2018-2026 the Deno authors. MIT license.
#
# Oden startup baseline (LLP 0001 Phase 0). Times `deno eval` cold-ish startup
# for the fork with capsec inert vs armed, so later phases can price the cost of
# the mediation path (op-dispatch capture, per-op CPED writes) against a real
# reference. Prints mean/min over N runs. Run from `fork/deno`.
#
#   DENO=./target/debug/deno N=30 ./tools/oden/bench_startup.sh
#
# @ref llp/0001-adding-capability-security-to-deno.plan.md
set -euo pipefail
cd "$(dirname "$0")/../.."
DENO="${DENO:-./target/debug/deno}"
N="${N:-30}"
SCRIPT='Deno.env.get("PATH"); Deno.exit(0)'

bench() { # $1=label ; rest=env assignments
  local label="$1"; shift
  local total=0 min=99999999 t
  for _ in $(seq 1 "$N"); do
    local start end
    start=$(perl -MTime::HiRes=time -e 'print time()')
    env "$@" "$DENO" eval "$SCRIPT" >/dev/null 2>&1 || true
    end=$(perl -MTime::HiRes=time -e 'print time()')
    t=$(perl -e "print int(($end-$start)*1000)")
    total=$((total + t))
    [ "$t" -lt "$min" ] && min="$t"
  done
  printf "%-28s mean=%4dms min=%4dms  (N=%d)\n" "$label" "$((total / N))" "$min" "$N"
}

echo "# Oden startup baseline — $($DENO --version | head -1)"
echo "# script: $SCRIPT"
bench "inert (capsec off)"          --allow-env
bench "armed audit (no enforce)"    --allow-env DENO_TRACE_PERMISSIONS=1 ODEN_CAPSEC_SPIKE=1 ODEN_CAPSEC_MODE=audit
bench "armed enforce"               --allow-env DENO_TRACE_PERMISSIONS=1 ODEN_CAPSEC_SPIKE=1 ODEN_CAPSEC_ENFORCE=1

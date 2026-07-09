#!/usr/bin/env bash
# Copyright 2018-2026 the Deno authors. MIT license.
#
# Oden rebase canary — the invariant check the weekly rebase runs after bumping
# the fork to a new upstream tag and rebasing the PATCHES.md set (LLP 0001
# Phase 0). It does NOT do the bump/rebase itself (that is the human/CI step
# below); it asserts that, on whatever fork state it is handed, the Oden
# invariants still hold:
#
#   1. the op-coverage manifest is current (no new mediated op / op-body skip
#      slipped in unrecorded);
#   2. the script-creation inventory markers are all present (no registration or
#      seal key was dropped);
#   3. PATCHES.md exists and records a pin.
#
# The heavy checks (full `deno` build + Deno's own test suite + the oden_capsec
# spec tests) are run by the CI job that calls this after a successful build;
# this script is the fast, build-free gate. Run from `fork/deno`.
#
# Weekly rebase procedure (performed by CI or a maintainer before calling this):
#   git fetch upstream && git rebase <new-tag>   # rebase the PATCHES set
#   cargo build --bin deno                        # ≤ half a day budget
#   ./tools/oden/canary.sh                        # invariants
#   ./x test-spec oden_capsec                     # capsec regression
#
# @ref llp/0001-adding-capability-security-to-deno.plan.md ; ../PATCHES.md
set -euo pipefail
cd "$(dirname "$0")/../.."   # fork/deno

fail=0
DENO="${DENO:-./target/debug/deno}"
if [ ! -x "$DENO" ]; then
  # Fall back to a deno on PATH for the build-free checks.
  DENO="$(command -v deno || true)"
fi
if [ -z "$DENO" ]; then
  echo "canary: no deno binary (set DENO=... or build target/debug/deno)" >&2
  exit 2
fi

echo "== op-coverage manifest =="
if ! "$DENO" run --allow-read tools/oden/coverage_manifest.ts --check; then
  fail=1
fi

echo "== script-creation inventory =="
if ! "$DENO" run --allow-read tools/oden/script_creation_manifest.ts --check; then
  fail=1
fi

echo "== exhaustive ambient-global inventory =="
if ! "$DENO" run --allow-read tools/oden/global_inventory.ts --check; then
  fail=1
fi

echo "== resource-family classification =="
if ! "$DENO" run --allow-read tools/oden/resource_families.ts --check; then
  fail=1
fi

echo "== red-team soundness gate (Phase-2 exit gate) =="
if ! "$DENO" run --allow-read tools/oden/redteam.ts --check; then
  fail=1
fi

echo "== stack-trace annotation audit (capture-point completeness) =="
if ! "$DENO" run --allow-read tools/oden/stack_trace_audit.ts --check; then
  fail=1
fi

echo "== PATCHES.md pin =="
if [ -f ../PATCHES.md ] && grep -q "Pin:" ../PATCHES.md; then
  grep "Pin:" ../PATCHES.md | head -1
else
  echo "PATCHES.md missing or has no Pin: line" >&2
  fail=1
fi

if [ "$fail" -ne 0 ]; then
  echo "canary: FAILED — invariants drifted; review before landing the rebase" >&2
  exit 1
fi
echo "canary: OK"

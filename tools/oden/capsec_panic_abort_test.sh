#!/bin/sh
# Copyright 2018-2026 the Deno authors. MIT license.
#
# Run an exact filtered `deno` library-test harness with the reviewed release
# panic strategy. Stable Cargo needs its bootstrap escape hatch to accept
# `-Z panic-abort-tests`, but that global value would alter the compiler cfg
# captured by the Rev2 build identity. Cargo therefore invokes this same file
# as RUSTC; the child mode narrows the compiler bootstrap to the `deno` crate.
#
# @ref LLP 0019#pre-promotion-conformance-candidate-execution [tests] --
# This is a development verifier for candidate-only code. It does not connect
# a candidate to dispatch, admission, activation, evidence, or release authority.

set -eu

toolchain=1.95.0
child_marker=ODEN_CAPSEC_PANIC_ABORT_RUSTC_CHILD

if [ "${ODEN_CAPSEC_PANIC_ABORT_RUSTC_CHILD:-}" = "1" ]; then
  export RUSTC_BOOTSTRAP=deno
  exec rustup run "$toolchain" rustc "$@"
fi

if [ "$#" -eq 0 ] || [ -z "$1" ]; then
  echo "usage: $0 FILTER [LIBTEST_ARGUMENT ...]" >&2
  exit 2
fi

filter=$1
case "$filter" in
  -*)
    echo "usage: $0 FILTER [LIBTEST_ARGUMENT ...]" >&2
    exit 2
    ;;
esac
shift
script_dir=$(CDPATH= cd "$(dirname "$0")" && pwd -P)
script_path="$script_dir/$(basename "$0")"
repo_root=$(CDPATH= cd "$script_dir/../.." && pwd -P)

cd "$repo_root"
export "$child_marker=1"
export RUSTC_BOOTSTRAP=1
export RUSTC="$script_path"
export CARGO_PROFILE_RELEASE_PANIC=abort
export CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS=false

exec rustup run "$toolchain" cargo -Z panic-abort-tests test \
  --release -p deno --lib "$filter" -- "$@"

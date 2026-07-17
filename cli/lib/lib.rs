// Copyright 2018-2026 the Deno authors. MIT license.

pub mod args;
pub mod loader;
pub mod npm;
pub mod shared;
pub mod standalone;
pub mod sys;
pub mod util;
pub mod version;
pub mod worker;

// @ref LLP 0019#frozen-parent-standalone-allowlist-and-byte-graph [tests] --
// Cargo does not build `build.rs` as a test target. Include it only in this
// library test harness so its authenticated-commit grammar and selection
// vectors run under the ordinary `deno_lib` test command.
#[cfg(test)]
#[allow(dead_code, reason = "test-only build-script module")]
#[path = "build.rs"]
mod build_script_test_target;

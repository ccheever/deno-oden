// Copyright 2018-2026 the Deno authors. MIT license.

pub fn main() {
  // We have a lib.rs and main.rs in order to be able
  // to run tests without building a binary on the CI.
  //
  // Prefer to keep this file simple and mostly empty.
  let args = std::env::args_os().collect::<Vec<_>>();
  // @ref LLP 0019#frozen-parent-standalone-allowlist-and-byte-graph [implements] —
  // Standalone images expose only the shared scan-only refusal surface.
  if !matches!(
    deno_lib::standalone::oden_parent_allowlist::classify_oden_parent_allowlist_raw_argv(&args),
    deno_lib::standalone::oden_parent_allowlist::OdenParentAllowlistRawDispatch::Absent
  ) {
    std::process::exit(
      deno_lib::standalone::oden_parent_allowlist::ODEN_PARENT_ALLOWLIST_REFUSAL_EXIT_CODE,
    );
  }
  denort::main()
}

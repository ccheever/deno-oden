// Copyright 2018-2026 the Deno authors. MIT license.

pub fn main() {
  // We have a lib.rs and main.rs in order to be able
  // to run tests without building a binary on the CI.
  //
  // Prefer to keep this file simple and mostly empty.
  let args = std::env::args_os().collect::<Vec<_>>();
  // @ref LLP 0019#frozen-parent-standalone-allowlist-and-byte-graph [implements] —
  // This is the first Oden/Deno application branch. The exact modes remain
  // output-free refusals until the compile-time role decoder and dedicated
  // handler are implemented.
  match deno_lib::standalone::oden_parent_allowlist::classify_oden_parent_allowlist_raw_argv(&args) {
    deno_lib::standalone::oden_parent_allowlist::OdenParentAllowlistRawDispatch::Absent => {}
    deno_lib::standalone::oden_parent_allowlist::OdenParentAllowlistRawDispatch::Generate
    | deno_lib::standalone::oden_parent_allowlist::OdenParentAllowlistRawDispatch::Check
    | deno_lib::standalone::oden_parent_allowlist::OdenParentAllowlistRawDispatch::Refuse => {
      std::process::exit(
        deno_lib::standalone::oden_parent_allowlist::ODEN_PARENT_ALLOWLIST_REFUSAL_EXIT_CODE,
      );
    }
  }
  if let Some(exit_code) =
    deno::maybe_run_oden_capsec_filesystem_supervisor(args.iter().cloned())
  {
    std::process::exit(exit_code);
  }
  if let Some(exit_code) =
    deno::maybe_run_oden_capsec_filesystem_candidate(args)
  {
    std::process::exit(exit_code);
  }
  deno::main()
}

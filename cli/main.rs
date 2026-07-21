// Copyright 2018-2026 the Deno authors. MIT license.

pub fn main() {
  // We have a lib.rs and main.rs in order to be able
  // to run tests without building a binary on the CI.
  //
  // Prefer to keep this file simple and mostly empty.
  let args = std::env::args_os().collect::<Vec<_>>();
  // @ref LLP 0019#frozen-parent-standalone-allowlist-and-byte-graph [implements] —
  // This is the first Oden/Deno application branch. Exact Generate and Check
  // enter their separately role-gated candidate handlers; every malformed
  // reserved-family vector remains a silent exit-76 refusal. Neither branch
  // reaches ordinary standalone output or downstream authority.
  let oden_parent_allowlist_dispatch =
    deno_lib::standalone::oden_parent_allowlist::classify_oden_parent_allowlist_raw_argv(&args);
  match oden_parent_allowlist_dispatch {
    deno_lib::standalone::oden_parent_allowlist::OdenParentAllowlistRawDispatch::Absent => {}
    deno_lib::standalone::oden_parent_allowlist::OdenParentAllowlistRawDispatch::Generate => {
      std::process::exit(deno::run_oden_parent_allowlist_generate());
    }
    deno_lib::standalone::oden_parent_allowlist::OdenParentAllowlistRawDispatch::Check => {
      std::process::exit(deno::run_oden_parent_allowlist_check());
    }
    deno_lib::standalone::oden_parent_allowlist::OdenParentAllowlistRawDispatch::Refuse => {
      std::process::exit(
        deno_lib::standalone::oden_parent_allowlist::ODEN_PARENT_ALLOWLIST_REFUSAL_EXIT_CODE,
      );
    }
  }
  if let Some(exit_code) =
    deno::maybe_run_oden_capsec_filesystem_drive(args.iter().cloned())
  {
    std::process::exit(exit_code);
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

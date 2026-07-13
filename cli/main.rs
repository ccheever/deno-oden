// Copyright 2018-2026 the Deno authors. MIT license.

pub fn main() {
  // We have a lib.rs and main.rs in order to be able
  // to run tests without building a binary on the CI.
  //
  // Prefer to keep this file simple and mostly empty.
  let args = std::env::args_os().collect::<Vec<_>>();
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

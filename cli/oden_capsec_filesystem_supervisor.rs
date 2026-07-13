// Copyright 2018-2026 the Deno authors. MIT license.

use std::ffi::OsString;

use crate::oden_capsec_filesystem_protocol::REFUSAL_EXIT_CODE;
use crate::oden_capsec_filesystem_protocol::parse_reserved_request;

const RESERVED_FLAG: &str = "--_oden-capsec-filesystem-supervise-v2";
const RESERVED_PREFIX: &str = "--_oden-capsec-filesystem-supervise";

// The supervisor table stays empty until it can create roots, own the private
// socketpair/arena, spawn the exact candidate child, capture response+EOF, and
// reap the child without exposing those facts to the external runner.
const SUPERVISED_CASES: &[(&str, &str)] = &[];

// @ref LLP 0019#pre-promotion-conformance-candidate-execution [implements] —
// Reserve the trusted native supervisor before deno::main or V8 while keeping
// every case mechanically refused until parent capture is implemented.
pub fn maybe_run_oden_capsec_filesystem_supervisor(
  args: impl IntoIterator<Item = OsString>,
) -> Option<i32> {
  let args = args.into_iter().collect::<Vec<_>>();
  let request =
    match parse_reserved_request(&args, RESERVED_FLAG, RESERVED_PREFIX)? {
      Ok(request) => request,
      Err(()) => return Some(REFUSAL_EXIT_CODE),
    };
  if !SUPERVISED_CASES.iter().any(|(digest, case_id)| {
    *digest == request.manifest_digest && *case_id == request.case_id
  }) {
    return Some(REFUSAL_EXIT_CODE);
  }
  Some(REFUSAL_EXIT_CODE)
}

#[cfg(test)]
mod tests {
  use super::*;

  const DIGEST: &str = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
  const CASE_ID: &str = "filesystem:lstat-sync:existing";

  fn run(args: &[&str]) -> Option<i32> {
    maybe_run_oden_capsec_filesystem_supervisor(args.iter().map(OsString::from))
  }

  #[test]
  fn ordinary_argv_is_not_intercepted() {
    assert_eq!(run(&["deno", "run", "mod.ts"]), None);
  }

  #[test]
  fn exact_but_unregistered_supervision_refuses() {
    assert_eq!(
      run(&[
        "deno",
        "--_oden-capsec-filesystem-supervise-v2",
        DIGEST,
        CASE_ID,
      ]),
      Some(REFUSAL_EXIT_CODE),
    );
  }

  #[test]
  fn malformed_supervisor_prefix_refuses() {
    assert_eq!(
      run(&[
        "deno",
        "--_oden-capsec-filesystem-supervise-v3",
        DIGEST,
        CASE_ID,
      ]),
      Some(REFUSAL_EXIT_CODE),
    );
  }
}

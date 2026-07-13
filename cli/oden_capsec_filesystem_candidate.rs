// Copyright 2018-2026 the Deno authors. MIT license.

use std::ffi::OsString;

use crate::oden_capsec_filesystem_protocol::REFUSAL_EXIT_CODE;
use crate::oden_capsec_filesystem_protocol::parse_reserved_request;

const RESERVED_FLAG: &str = "--_oden-capsec-filesystem-candidate-v2";
const RESERVED_PREFIX: &str = "--_oden-capsec-filesystem-candidate";

// The generator will replace this empty table with exact
// (manifest-artifact-digest, case-id) rows. Keeping it empty is deliberate:
// the argv seam can be compiled and reviewed without admitting a case before
// parent-owned process capture and the executable oracle exist.
const CANDIDATE_CASES: &[(&str, &str)] = &[];

// @ref LLP 0019#pre-promotion-conformance-candidate-execution [implements] —
// The exact reserved candidate argv is intercepted before deno::main, V8, the
// ordinary control plane, or any inherited control descriptor is touched.
pub fn maybe_run_oden_capsec_filesystem_candidate(
  args: impl IntoIterator<Item = OsString>,
) -> Option<i32> {
  let args = args.into_iter().collect::<Vec<_>>();
  let request =
    match parse_reserved_request(&args, RESERVED_FLAG, RESERVED_PREFIX)? {
      Ok(request) => request,
      Err(()) => return Some(REFUSAL_EXIT_CODE),
    };
  if !CANDIDATE_CASES.iter().any(|(digest, case_id)| {
    *digest == request.manifest_digest && *case_id == request.case_id
  }) {
    return Some(REFUSAL_EXIT_CODE);
  }

  // No row can currently reach this point. The first generated row must add
  // the parent-owned FD3 transcript contract before it adds execution.
  Some(REFUSAL_EXIT_CODE)
}

#[cfg(test)]
mod tests {
  use super::*;

  const DIGEST: &str = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
  const CASE_ID: &str = "filesystem:lstat-sync:existing";

  fn run(args: &[&str]) -> Option<i32> {
    maybe_run_oden_capsec_filesystem_candidate(args.iter().map(OsString::from))
  }

  #[test]
  fn ordinary_argv_is_not_intercepted() {
    assert_eq!(run(&["deno", "run", "mod.ts"]), None);
  }

  #[test]
  fn exact_but_unregistered_candidate_refuses() {
    assert_eq!(
      run(&[
        "deno",
        "--_oden-capsec-filesystem-candidate-v2",
        DIGEST,
        CASE_ID,
      ]),
      Some(REFUSAL_EXIT_CODE),
    );
  }

  #[test]
  fn malformed_reserved_argv_refuses() {
    for args in [
      vec!["deno", "--_oden-capsec-filesystem-candidate-v2"],
      vec![
        "deno",
        "run",
        "--_oden-capsec-filesystem-candidate-v2",
        DIGEST,
        CASE_ID,
      ],
      vec![
        "deno",
        "--_oden-capsec-filesystem-candidate-v3",
        DIGEST,
        CASE_ID,
      ],
      vec![
        "deno",
        "--_oden-capsec-filesystem-candidate-v2",
        "sha256-not-canonical",
        CASE_ID,
      ],
      vec![
        "deno",
        "--_oden-capsec-filesystem-candidate-v2",
        DIGEST,
        "case id",
      ],
    ] {
      assert_eq!(run(&args), Some(REFUSAL_EXIT_CODE));
    }
  }
}

// Copyright 2018-2026 the Deno authors. MIT license.

use std::ffi::OsString;

use crate::oden_capsec_filesystem_protocol::REFUSAL_EXIT_CODE;
use crate::oden_capsec_filesystem_protocol::parse_reserved_request;

const RESERVED_FLAG: &str = "--_oden-capsec-filesystem-drive-v2";
const RESERVED_PREFIX: &str = "--_oden-capsec-filesystem-drive";

// The drive table stays empty until the trusted compiled parent can mint the
// one-shot keys, spawn the supervisor and candidate children into an owned
// process group, run the pinned oracle, gate the receipt-key release, and emit
// the handoff — none of which exist yet. Keeping it empty is deliberate: the
// entrypoint argv seam can be compiled and reviewed before any orchestration.
const DRIVE_CASES: &[(&str, &str)] = &[];

// @ref LLP 0019#pre-promotion-conformance-candidate-execution [implements] —
// Reserve the trusted native drive entrypoint before deno::main or V8 while
// keeping every case mechanically refused until parent orchestration is
// implemented.
pub fn maybe_run_oden_capsec_filesystem_drive(
  args: impl IntoIterator<Item = OsString>,
) -> Option<i32> {
  let args = args.into_iter().collect::<Vec<_>>();
  let request =
    match parse_reserved_request(&args, RESERVED_FLAG, RESERVED_PREFIX)? {
      Ok(request) => request,
      Err(()) => return Some(REFUSAL_EXIT_CODE),
    };
  if !DRIVE_CASES.iter().any(|(digest, case_id)| {
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
  const CASE_ID: &str =
    "case:op_fs_lstat_sync:aarch64-apple-darwin:lstat-existing:v1";

  fn run(args: &[&str]) -> Option<i32> {
    maybe_run_oden_capsec_filesystem_drive(args.iter().map(OsString::from))
  }

  #[test]
  fn ordinary_argv_is_not_intercepted() {
    assert_eq!(run(&["deno", "run", "mod.ts"]), None);
  }

  #[test]
  fn exact_but_unregistered_drive_refuses() {
    assert_eq!(
      run(&[
        "deno",
        "--_oden-capsec-filesystem-drive-v2",
        DIGEST,
        CASE_ID,
      ]),
      Some(REFUSAL_EXIT_CODE),
    );
  }

  #[test]
  fn malformed_drive_prefix_refuses() {
    assert_eq!(
      run(&[
        "deno",
        "--_oden-capsec-filesystem-drive-v3",
        DIGEST,
        CASE_ID,
      ]),
      Some(REFUSAL_EXIT_CODE),
    );
  }
}

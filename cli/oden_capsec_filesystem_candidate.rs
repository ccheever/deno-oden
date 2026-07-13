// Copyright 2018-2026 the Deno authors. MIT license.

use std::ffi::OsStr;
use std::ffi::OsString;

const RESERVED_FLAG: &[u8] = b"--_oden-capsec-filesystem-candidate-v2";
const RESERVED_PREFIX: &[u8] = b"--_oden-capsec-filesystem-candidate";
const REFUSAL_EXIT_CODE: i32 = 76;

// The generator will replace this empty table with exact
// (manifest-artifact-digest, case-id) rows. Keeping it empty is deliberate:
// the argv seam can be compiled and reviewed without admitting a case before
// parent-owned process capture and the executable oracle exist.
const CANDIDATE_CASES: &[(&str, &str)] = &[];

struct CandidateRequest {
  manifest_digest: String,
  case_id: String,
}

// @ref LLP 0019#pre-promotion-conformance-candidate-execution [implements] —
// The exact reserved candidate argv is intercepted before deno::main, V8, the
// ordinary control plane, or any inherited control descriptor is touched.
pub fn maybe_run_oden_capsec_filesystem_candidate(
  args: impl IntoIterator<Item = OsString>,
) -> Option<i32> {
  let args = args.into_iter().collect::<Vec<_>>();
  if !args
    .iter()
    .skip(1)
    .any(|arg| os_bytes(arg).starts_with(RESERVED_PREFIX))
  {
    return None;
  }
  let request = match parse_candidate_request(&args) {
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

fn parse_candidate_request(args: &[OsString]) -> Result<CandidateRequest, ()> {
  if args.len() != 4 || os_bytes(&args[1]) != RESERVED_FLAG {
    return Err(());
  }
  let manifest_digest = canonical_ascii(&args[2]).ok_or(())?;
  if !is_canonical_sha256_digest(manifest_digest) {
    return Err(());
  }
  let case_id = canonical_ascii(&args[3]).ok_or(())?;
  if !is_canonical_identifier(case_id) {
    return Err(());
  }
  Ok(CandidateRequest {
    manifest_digest: manifest_digest.to_string(),
    case_id: case_id.to_string(),
  })
}

fn canonical_ascii(value: &OsStr) -> Option<&str> {
  let value = value.to_str()?;
  value.is_ascii().then_some(value)
}

fn is_canonical_sha256_digest(value: &str) -> bool {
  let Some(payload) = value.strip_prefix("sha256-") else {
    return false;
  };
  payload.len() == 43
    && payload
      .bytes()
      .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
    && payload
      .as_bytes()
      .last()
      .is_some_and(|last| b"AEIMQUYcgkosw048".contains(last))
}

fn is_canonical_identifier(value: &str) -> bool {
  !value.is_empty()
    && value.len() <= 4096
    && value.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
}

#[cfg(unix)]
fn os_bytes(value: &OsStr) -> &[u8] {
  use std::os::unix::ffi::OsStrExt;
  value.as_bytes()
}

#[cfg(not(unix))]
fn os_bytes(value: &OsStr) -> &[u8] {
  value.to_str().map(str::as_bytes).unwrap_or_default()
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

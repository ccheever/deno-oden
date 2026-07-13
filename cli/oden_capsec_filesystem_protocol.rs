// Copyright 2018-2026 the Deno authors. MIT license.

use std::ffi::OsStr;
use std::ffi::OsString;

pub(crate) const REFUSAL_EXIT_CODE: i32 = 76;

pub(crate) struct ReservedRequest {
  pub(crate) manifest_digest: String,
  pub(crate) case_id: String,
}

pub(crate) fn parse_reserved_request(
  args: &[OsString],
  exact_flag: &str,
  reserved_prefix: &str,
) -> Option<Result<ReservedRequest, ()>> {
  if !args
    .iter()
    .skip(1)
    .any(|arg| os_bytes(arg).starts_with(reserved_prefix.as_bytes()))
  {
    return None;
  }
  Some(parse_exact_request(args, exact_flag))
}

fn parse_exact_request(
  args: &[OsString],
  exact_flag: &str,
) -> Result<ReservedRequest, ()> {
  if args.len() != 4 || os_bytes(&args[1]) != exact_flag.as_bytes() {
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
  Ok(ReservedRequest {
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

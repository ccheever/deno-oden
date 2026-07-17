// Copyright 2018-2026 the Deno authors. MIT license.

const ODEN_AUTHENTICATED_FORK_COMMIT: &str = "ODEN_AUTHENTICATED_FORK_COMMIT";

fn main() {
  // todo(dsherret): remove this after Deno 242.0 is published and then
  // align the version of this crate with Deno then. We need to wait because
  // there was previously a deno_lib 2.4.0 published (https://crates.io/crates/deno_lib/versions)
  let version_path = std::path::Path::new(".").join("version.txt");
  println!("cargo:rerun-if-changed={}", version_path.display());
  #[allow(clippy::disallowed_methods, reason = "build code")]
  let text = std::fs::read_to_string(version_path).unwrap();
  println!("cargo:rustc-env=DENO_VERSION={}", text);

  println!("cargo:rerun-if-env-changed={ODEN_AUTHENTICATED_FORK_COMMIT}");
  let commit_hash = select_oden_fork_commit(
    std::env::var(ODEN_AUTHENTICATED_FORK_COMMIT),
    git_commit_hash,
  )
  .unwrap_or_else(|reason| panic!("{ODEN_AUTHENTICATED_FORK_COMMIT} {reason}"));
  println!("cargo:rustc-env=GIT_COMMIT_HASH={}", commit_hash);
  println!(
    "cargo:rustc-env=GIT_COMMIT_HASH_SHORT={}",
    &commit_hash[..7]
  );
}

// @ref LLP 0019#frozen-parent-standalone-allowlist-and-byte-graph [implements] --
// Parse only the authenticated v1 fork-revision spelling.
fn parse_oden_authenticated_fork_commit(value: &str) -> Option<&str> {
  let commit_hash = value.strip_prefix("git-sha1:")?;
  (commit_hash.len() == 40
    && commit_hash
      .bytes()
      .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f')))
  .then_some(commit_hash)
}

// @ref LLP 0019#frozen-parent-standalone-allowlist-and-byte-graph [implements] --
// Derive markers from any supplied authenticated value without fallback.
fn select_oden_fork_commit<F>(
  authenticated_fork_commit: Result<String, std::env::VarError>,
  legacy_non_authoritative_fallback: F,
) -> Result<String, &'static str>
where
  F: FnOnce() -> String,
{
  match authenticated_fork_commit {
    Ok(value) => parse_oden_authenticated_fork_commit(&value)
      .map(str::to_owned)
      .ok_or("must be exactly git-sha1: plus 40 lowercase hexadecimal digits"),
    Err(std::env::VarError::NotUnicode(_)) => {
      Err("must be valid Unicode in its exact ASCII grammar")
    }
    Err(std::env::VarError::NotPresent) => {
      Ok(legacy_non_authoritative_fallback())
    }
  }
}

// Current non-authoritative builds retain the upstream checkout probe when the
// authenticated input is absent. The root-private authoring bit is intentionally
// invisible here, and all-feature builds must remain compilable, so final/
// authoring missing-input refusal remains a later admission gate.
// Any supplied authenticated input, valid or invalid, never reaches fallback.
fn git_commit_hash() -> String {
  if let Ok(output) = std::process::Command::new("git")
    .arg("rev-list")
    .arg("-1")
    .arg("HEAD")
    .output()
  {
    if output.status.success() {
      std::str::from_utf8(&output.stdout[..40])
        .unwrap()
        .to_string()
    } else {
      // When not in git repository
      // (e.g. when the user install by `cargo install deno`)
      "UNKNOWN".to_string()
    }
  } else {
    // When there is no git command for some reason
    "UNKNOWN".to_string()
  }
}

#[cfg(test)]
mod tests {
  use std::cell::Cell;

  use super::parse_oden_authenticated_fork_commit;
  use super::select_oden_fork_commit;

  #[test]
  fn parses_exact_authenticated_sha1_revision() {
    let commit_hash = parse_oden_authenticated_fork_commit(
      "git-sha1:0123456789abcdef0123456789abcdef01234567",
    )
    .unwrap();

    assert_eq!(commit_hash, "0123456789abcdef0123456789abcdef01234567");
    assert_eq!(&commit_hash[..7], "0123456");
  }

  #[test]
  fn rejects_every_noncanonical_revision_shape() {
    for value in [
      "",
      "UNKNOWN",
      "0123456789abcdef0123456789abcdef01234567",
      "git-sha1:",
      "git-sha1:0123456789abcdef0123456789abcdef0123456",
      "git-sha1:0123456789abcdef0123456789abcdef012345678",
      "GIT-SHA1:0123456789abcdef0123456789abcdef01234567",
      "git-sha1:0123456789abcdef0123456789abcdef0123456F",
      "git-sha1:0123456789abcdef0123456789abcdef0123456g",
      " git-sha1:0123456789abcdef0123456789abcdef01234567",
      "git-sha1:0123456789abcdef0123456789abcdef01234567 ",
      "git-sha1:0123456789abcdef0123456789abcdef01234567\n",
      "git-sha1:0123456789abcdef0123456789abcdef01234567\r",
      "git-sha1:0123456789abcdef0123456789abcdef0123456\0",
      "git-sha1:0123456789abcdef0123456789abcdef012345é",
      "git-sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    ] {
      assert_eq!(
        parse_oden_authenticated_fork_commit(value),
        None,
        "unexpectedly accepted {value:?}"
      );
    }
  }

  #[test]
  fn authenticated_revision_derives_full_and_short_markers_without_fallback() {
    let fallback_calls = Cell::new(0);
    let commit_hash = select_oden_fork_commit(
      Ok("git-sha1:0123456789abcdef0123456789abcdef01234567".to_string()),
      || {
        fallback_calls.set(fallback_calls.get() + 1);
        "fallback".to_string()
      },
    )
    .unwrap();

    assert_eq!(commit_hash, "0123456789abcdef0123456789abcdef01234567");
    assert_eq!(&commit_hash[..7], "0123456");
    assert_eq!(fallback_calls.get(), 0);
  }

  #[test]
  fn malformed_authenticated_revision_never_reaches_fallback() {
    for value in [
      "",
      "UNKNOWN",
      "git-sha1:0123456789abcdef0123456789abcdef0123456F",
      "git-sha1:0123456789abcdef0123456789abcdef01234567\n",
    ] {
      let fallback_calls = Cell::new(0);
      let error = select_oden_fork_commit(Ok(value.to_string()), || {
        fallback_calls.set(fallback_calls.get() + 1);
        "fallback".to_string()
      })
      .unwrap_err();

      assert_eq!(
        error,
        "must be exactly git-sha1: plus 40 lowercase hexadecimal digits"
      );
      assert_eq!(fallback_calls.get(), 0);
    }
  }

  #[test]
  fn non_unicode_authenticated_revision_never_reaches_fallback() {
    let fallback_calls = Cell::new(0);
    let error = select_oden_fork_commit(
      Err(std::env::VarError::NotUnicode(std::ffi::OsString::from(
        "non-unicode environment value",
      ))),
      || {
        fallback_calls.set(fallback_calls.get() + 1);
        "fallback".to_string()
      },
    )
    .unwrap_err();

    assert_eq!(error, "must be valid Unicode in its exact ASCII grammar");
    assert_eq!(fallback_calls.get(), 0);
  }

  #[test]
  fn missing_authenticated_revision_uses_legacy_fallback_once() {
    let fallback_calls = Cell::new(0);
    let commit_hash =
      select_oden_fork_commit(Err(std::env::VarError::NotPresent), || {
        fallback_calls.set(fallback_calls.get() + 1);
        "legacy-development-identity".to_string()
      })
      .unwrap();

    assert_eq!(commit_hash, "legacy-development-identity");
    assert_eq!(fallback_calls.get(), 1);
  }
}

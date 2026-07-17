// Copyright 2018-2026 the Deno authors. MIT license.

fn main() {
  // todo(dsherret): remove this after Deno 242.0 is published and then
  // align the version of this crate with Deno then. We need to wait because
  // there was previously a deno_lib 2.4.0 published (https://crates.io/crates/deno_lib/versions)
  let version_path = std::path::Path::new(".").join("version.txt");
  println!("cargo:rerun-if-changed={}", version_path.display());
  #[allow(clippy::disallowed_methods, reason = "build code")]
  let text = std::fs::read_to_string(version_path).unwrap();
  println!("cargo:rustc-env=DENO_VERSION={}", text);

  let commit_hash = git_commit_hash();
  println!("cargo:rustc-env=GIT_COMMIT_HASH={}", commit_hash);
  println!("cargo:rerun-if-env-changed=GIT_COMMIT_HASH");
  println!(
    "cargo:rustc-env=GIT_COMMIT_HASH_SHORT={}",
    &commit_hash[..7]
  );
}

// This pure grammar helper is deliberately uncalled by the production path.
// `main` still uses `git_commit_hash()` and its checkout probe/`UNKNOWN`
// fallback, so adding the parser alone does not activate authenticated build
// identity.
#[allow(dead_code, reason = "dormant Oden build-identity parser")]
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
  use super::parse_oden_authenticated_fork_commit;

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
}

// Copyright 2018-2026 the Deno authors. MIT license.

//! Oden loader principal index (LLP 0001 Phase 1, ENG-23763).
//!
//! The production module -> owning-principal map, *integrity-bound from the
//! start*: a package-shaped principal (npm, JSR, remote URL) is admitted only
//! when the identity the module claims on disk is pinned by the project's
//! content-addressed lockfile (`deno.lock`), and the lockfile hash is recorded
//! on the index entry. A version/content swap that does not match the lockfile
//! fails attribution CLOSED — the module resolves to the quarantine principal
//! (never granted) instead of falling back to a path-string principal —
//! closing Ibex's forged-version residual (0016 W7b/R8) instead of
//! inheriting it.
//!
//! Modules with no lockfile entry, by design:
//!   - first-party files under the project root -> Root (the trusted root is
//!     the human review boundary; the lockfile does not hash local code);
//!   - `ext:`/`node:`/`deno:` internals -> Runtime;
//!   - dynamically evaluated / out-of-graph code -> Quarantine (the existing
//!     eval-quarantine fail-closed semantics, untouched here).
//!
//! Lockfile states:
//!   - **Loaded**: binding is enforced for every package-shaped principal.
//!   - **Absent** (no `deno.lock`): the graph is not lockfile-managed, so
//!     binding is impossible; locators stay path-derived and the readiness
//!     report names the degraded state under enforce.
//!   - **Unreadable/corrupt**: fails closed — every package-shaped principal
//!     resolves to quarantine — same doctrine as the policy-unreadable latch.
//!
//! Content-swap bounds, stated honestly: for remote/JSR code the lockfile is
//! content-addressed per file/version-manifest and Deno's own loader already
//! refuses a byte swap before the module ever executes (this index re-asserts
//! the URL/version is *pinned* and records the hash). For npm code the lockfile
//! integrity is the install-time tarball hash; the runtime-detectable forgery
//! is the identity claim (name@version vs the pin) — a post-install byte tamper
//! of an npm dir that keeps its pinned version string is bounded by
//! install-time tarball verification, not by any runtime lockfile mechanism.
//!
//! Lookup is shaped for the enforcement hot path (ENG-23772): principals are
//! memoized per (isolate, script_id) and per locator, so op dispatch pays one
//! hash-map probe, not a classify parse; binding I/O (the lockfile read,
//! package.json claims) happens once per process / per package directory.
//
// @ref llp/0001-adding-capability-security-to-deno.plan.md (Principals and the package index)

use std::collections::HashMap;
use std::sync::LazyLock;
use std::sync::Mutex;

use super::oden_policy;
use super::oden_policy::Principal;

// --- Lockfile snapshot -------------------------------------------------------

#[derive(Debug, Default, Clone)]
pub(crate) struct LockData {
  /// npm: package name -> [(pinned version, integrity)]
  npm: HashMap<String, Vec<(String, String)>>,
  /// jsr: package name -> [(pinned version, integrity)] — the integrity is the
  /// version-manifest hash, i.e. JSR provenance for the whole version.
  jsr: HashMap<String, Vec<(String, String)>>,
  /// remote: exact URL -> content hash.
  remote: HashMap<String, String>,
}

#[derive(Debug, Clone)]
pub(crate) enum LockState {
  /// No deno.lock: binding unavailable, locators stay path-derived (degraded,
  /// named in the readiness report).
  Absent,
  /// deno.lock exists but cannot be read/parsed: fail closed — every
  /// package-shaped principal quarantines.
  Unreadable,
  Loaded(LockData),
}

impl LockState {
  pub(crate) fn readiness_label(&self) -> &'static str {
    match self {
      LockState::Absent => "unbound (no lockfile)",
      LockState::Unreadable => "FAIL-CLOSED (deno.lock unreadable)",
      LockState::Loaded(_) => "bound (deno.lock)",
    }
  }

  pub(crate) fn is_absent(&self) -> bool {
    matches!(self, LockState::Absent)
  }

  pub(crate) fn is_unreadable(&self) -> bool {
    matches!(self, LockState::Unreadable)
  }
}

/// Split a lockfile package key (`name@version`, possibly with a `_peer@ver`
/// resolution suffix) into (name, version). Package names may contain `_` and
/// scoped names start with `@`, so parse from the left: skip a leading `@`,
/// split at the next `@` (names cannot contain one), then cut the version at
/// the first `_` (semver forbids `_`; Deno uses it for the peer-dep suffix).
fn split_lock_key(key: &str) -> Option<(String, String)> {
  let search_from = usize::from(key.starts_with('@'));
  let at = key[search_from..].find('@')? + search_from;
  let name = &key[..at];
  let rest = &key[at + 1..];
  let version = rest.split('_').next().unwrap_or(rest);
  if name.is_empty() || version.is_empty() {
    return None;
  }
  Some((name.to_string(), version.to_string()))
}

/// Parse a deno.lock (v4/v5 shape: `npm`/`jsr` keyed maps with `integrity`,
/// `remote` url->hash). Unknown sections are ignored; a JSON parse failure is
/// the caller's fail-closed signal.
fn parse_lockfile(text: &str) -> Option<LockData> {
  let value: serde_json::Value = serde_json::from_str(text).ok()?;
  let obj = value.as_object()?;
  let mut data = LockData::default();
  for (section, out) in [("npm", &mut data.npm), ("jsr", &mut data.jsr)] {
    if let Some(map) = obj.get(section).and_then(|v| v.as_object()) {
      for (key, entry) in map {
        let Some((name, version)) = split_lock_key(key) else {
          continue;
        };
        let integrity = entry
          .get("integrity")
          .and_then(|v| v.as_str())
          .unwrap_or("")
          .to_string();
        out.entry(name).or_default().push((version, integrity));
      }
    }
  }
  if let Some(map) = obj.get("remote").and_then(|v| v.as_object()) {
    for (url, hash) in map {
      if let Some(hash) = hash.as_str() {
        data.remote.insert(url.clone(), hash.to_string());
      }
    }
  }
  Some(data)
}

/// Process-lifetime snapshot of `<root>/deno.lock`, same arm-time doctrine as
/// the policy artifact: principals were bound against the lockfile that armed
/// this process, and a lockfile that changes or vanishes mid-run must not
/// re-shape a running process's attribution.
#[allow(
  clippy::disallowed_methods,
  reason = "the integrity index reads the committed deno.lock from the project root once at arm time"
)]
pub(crate) fn lock_state() -> &'static LockState {
  static STATE: LazyLock<LockState> = LazyLock::new(|| {
    let root = super::oden_capsec_project_root();
    if root.is_empty() {
      return LockState::Absent;
    }
    let path = std::path::Path::new(root).join("deno.lock");
    if !path.exists() {
      return LockState::Absent;
    }
    match std::fs::read_to_string(&path) {
      Ok(text) => match parse_lockfile(&text) {
        Some(data) => LockState::Loaded(data),
        None => LockState::Unreadable,
      },
      Err(_) => LockState::Unreadable,
    }
  });
  &STATE
}

// --- Binding -----------------------------------------------------------------

/// An index entry: the resolved principal plus the lockfile hash the locator is
/// bound to (None when the graph is not lockfile-managed or the principal has
/// no lockfile identity by design — root/runtime/quarantine).
#[derive(Debug, Clone)]
pub(crate) struct BoundEntry {
  pub principal: Principal,
  pub integrity: Option<String>,
}

impl BoundEntry {
  fn unbound(principal: Principal) -> BoundEntry {
    BoundEntry {
      principal,
      integrity: None,
    }
  }
}

/// The claimed npm identity read from a locator path, without trusting the
/// bare `node_modules/<name>` string alone:
///   1. Deno's managed layout `node_modules/.deno/<name>@<version>/...` carries
///      the resolver-chosen version in the folder itself (scoped names fold
///      `/` to `+`); it is used only when the folder name matches the package.
///   2. Otherwise the package directory's own `package.json` `version` field is
///      the claim (read once per package dir, memoized).
fn npm_claimed_version(
  locator: &str,
  name: &str,
  pkg_json_version: &dyn Fn(&str) -> Option<String>,
) -> Option<String> {
  // Layout 1: /node_modules/.deno/<folder>/node_modules/<name>/...
  if let Some(idx) = locator.find("/node_modules/.deno/") {
    let folder_start = idx + "/node_modules/.deno/".len();
    if let Some(folder) = locator[folder_start..].split('/').next()
      && let Some(at) = folder.rfind('@')
      && at > 0
    {
      let folder_name = folder[..at].replace('+', "/");
      let version = &folder[at + 1..];
      if folder_name == name && !version.is_empty() {
        return Some(version.to_string());
      }
    }
  }
  // Layout 2: the package dir's package.json.
  let path = locator.strip_prefix("file://").unwrap_or(locator);
  let idx = path.rfind("/node_modules/")?;
  let pkg_dir = format!("{}/node_modules/{}", &path[..idx], name);
  pkg_json_version(&pkg_dir)
}

/// Memoized `package.json` `version` read for a package directory. The claim
/// is read once per directory; binding I/O never lands on the per-op hot path.
#[allow(
  clippy::disallowed_methods,
  reason = "the integrity index reads a package's own package.json once to learn the version it claims"
)]
fn pkg_json_version_cached(pkg_dir: &str) -> Option<String> {
  static CACHE: LazyLock<Mutex<HashMap<String, Option<String>>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
  if let Some(v) = CACHE.lock().unwrap().get(pkg_dir) {
    return v.clone();
  }
  let version =
    std::fs::read_to_string(std::path::Path::new(pkg_dir).join("package.json"))
      .ok()
      .and_then(|text| serde_json::from_str::<serde_json::Value>(&text).ok())
      .and_then(|v| {
        v.get("version")
          .and_then(|s| s.as_str())
          .map(|s| s.to_string())
      });
  CACHE
    .lock()
    .unwrap()
    .insert(pkg_dir.to_string(), version.clone());
  version
}

/// Recognize a module in Deno's global npm cache
/// (`.../npm/registry.npmjs.org/<name>/<version>/...`), which carries no
/// `node_modules` path segment and would otherwise quarantine. The identity is
/// resolver-derived (the cache layout is written from lockfile-pinned,
/// tarball-verified extractions), and it is admitted here ONLY through a
/// lockfile binding — with no lockfile, global-cache modules stay quarantined
/// rather than gaining an unverified path-string principal.
fn global_npm_cache_identity(locator: &str) -> Option<(String, String)> {
  let idx = locator.find("/npm/registry.npmjs.org/")?;
  let rest = &locator[idx + "/npm/registry.npmjs.org/".len()..];
  let segs: Vec<&str> = rest.split('/').collect();
  let (name, version_seg, min_len) = if segs.first()?.starts_with('@') {
    (
      format!("{}/{}", segs.first()?, segs.get(1)?),
      *segs.get(2)?,
      4,
    )
  } else {
    ((*segs.first()?).to_string(), *segs.get(1)?, 3)
  };
  if segs.len() < min_len {
    return None;
  }
  // Copy-package dirs suffix the version with `_<n>`; the pinned version is
  // the part before it.
  let version = version_seg.split('_').next().unwrap_or(version_seg);
  if version.is_empty() {
    return None;
  }
  Some((name, version.to_string()))
}

fn find_pin<'a>(
  section: &'a HashMap<String, Vec<(String, String)>>,
  name: &str,
  version: &str,
) -> Option<&'a str> {
  section
    .get(name)?
    .iter()
    .find(|(v, _)| v == version)
    .map(|(_, integrity)| integrity.as_str())
}

fn pins_of(
  section: &HashMap<String, Vec<(String, String)>>,
  name: &str,
) -> String {
  match section.get(name) {
    Some(list) if !list.is_empty() => list
      .iter()
      .map(|(v, _)| format!("{name}@{v}"))
      .collect::<Vec<_>>()
      .join(", "),
    _ => format!("no {name} entry"),
  }
}

/// Fail attribution closed with an audit signal: the locator resolves to
/// quarantine (never granted; denied under enforce, recorded under audit) —
/// NOT to a path-string package principal. Emitted once per locator (resolution
/// is memoized).
fn quarantine_signal(locator: &str, why: &str) -> BoundEntry {
  eprintln!("[oden-capsec] integrity: {locator} {why} -> quarantine");
  super::oden_capsec_audit_record(
    "quarantine",
    "integrity",
    "bind",
    locator,
    "DENY(integrity)",
    None,
  );
  BoundEntry::unbound(Principal::Quarantine)
}

/// Bind a classified principal to the lockfile. Pure over its inputs so the
/// binding rules are unit-testable without a filesystem; `pkg_json_version`
/// injects the package.json claim reader.
fn bind(
  locator: &str,
  principal: Principal,
  lock: &LockState,
  pkg_json_version: &dyn Fn(&str) -> Option<String>,
) -> BoundEntry {
  match principal {
    Principal::Package { name, version } => match lock {
      LockState::Absent => {
        BoundEntry::unbound(Principal::Package { name, version })
      }
      LockState::Unreadable => quarantine_signal(
        locator,
        "claims an npm package but deno.lock is unreadable",
      ),
      LockState::Loaded(data) => {
        let claimed = version
          .clone()
          .or_else(|| npm_claimed_version(locator, &name, pkg_json_version));
        match claimed {
          Some(v) => match find_pin(&data.npm, &name, &v) {
            Some(integrity) => BoundEntry {
              principal: Principal::Package {
                name,
                version: Some(v),
              },
              integrity: Some(integrity.to_string()),
            },
            None => quarantine_signal(
              locator,
              &format!(
                "claims {name}@{v} but deno.lock pins {}",
                pins_of(&data.npm, &name)
              ),
            ),
          },
          None => quarantine_signal(
            locator,
            &format!("claims npm package {name} with no verifiable version"),
          ),
        }
      }
    },
    Principal::Jsr { name, version } => match lock {
      LockState::Absent => {
        BoundEntry::unbound(Principal::Jsr { name, version })
      }
      LockState::Unreadable => quarantine_signal(
        locator,
        "claims a jsr package but deno.lock is unreadable",
      ),
      LockState::Loaded(data) => match version {
        Some(v) => match find_pin(&data.jsr, &name, &v) {
          Some(integrity) => BoundEntry {
            principal: Principal::Jsr {
              name,
              version: Some(v),
            },
            integrity: Some(integrity.to_string()),
          },
          None => quarantine_signal(
            locator,
            &format!(
              "claims {name}@{v} but deno.lock pins {}",
              pins_of(&data.jsr, &name)
            ),
          ),
        },
        None => quarantine_signal(
          locator,
          &format!("claims jsr package {name} with no verifiable version"),
        ),
      },
    },
    Principal::Url { canonical } => match lock {
      LockState::Absent => BoundEntry::unbound(Principal::Url { canonical }),
      LockState::Unreadable => quarantine_signal(
        locator,
        "is a remote module but deno.lock is unreadable",
      ),
      LockState::Loaded(data) => match data.remote.get(&canonical) {
        Some(hash) => BoundEntry {
          principal: Principal::Url { canonical },
          integrity: Some(hash.clone()),
        },
        None => quarantine_signal(
          locator,
          "is a remote module not pinned by deno.lock",
        ),
      },
    },
    // Quarantined locators may still be attributable global-npm-cache modules;
    // admit them ONLY through a lockfile binding (never a path-string widen).
    Principal::Quarantine => {
      if let LockState::Loaded(data) = lock
        && let Some((name, version)) = global_npm_cache_identity(locator)
        && let Some(integrity) = find_pin(&data.npm, &name, &version)
      {
        return BoundEntry {
          principal: Principal::Package {
            name,
            version: Some(version),
          },
          integrity: Some(integrity.to_string()),
        };
      }
      BoundEntry::unbound(Principal::Quarantine)
    }
    // Root / Runtime / NoUser have no lockfile identity by design.
    other => BoundEntry::unbound(other),
  }
}

// --- Memoized resolution (the hot-path surface) -------------------------------

fn bound_for_locator(locator: &str) -> BoundEntry {
  static CACHE: LazyLock<Mutex<HashMap<String, BoundEntry>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
  if let Some(entry) = CACHE.lock().unwrap().get(locator) {
    return entry.clone();
  }
  let root = super::oden_capsec_project_root();
  let principal = oden_policy::classify(locator, root);
  let entry = bind(locator, principal, lock_state(), &pkg_json_version_cached);
  CACHE
    .lock()
    .unwrap()
    .insert(locator.to_string(), entry.clone());
  entry
}

/// Resolve a locator to its integrity-bound principal (memoized).
pub(crate) fn resolve_locator(locator: &str) -> Principal {
  bound_for_locator(locator).principal
}

/// The lockfile hash a locator is bound to, if any — the recorded binding.
/// Shaped for the ENG-23772 per-package enforcement surface (a decision or its
/// audit record can name the exact content hash the acting principal was
/// admitted under); exercised by the unit tests until that wiring lands.
#[allow(dead_code, reason = "ENG-23772 consumes the recorded binding")]
pub(crate) fn integrity_of(locator: &str) -> Option<String> {
  bound_for_locator(locator).integrity
}

/// Resolve a captured stack frame to its principal. Keyed by
/// (isolate, script_id) — one hash probe on the op-dispatch hot path; script
/// IDs are registered at compile time (before any frame can execute), so a
/// resolved binding never changes for the life of the isolate.
pub(crate) fn resolve_frame(
  isolate_id: Option<usize>,
  script_id: Option<usize>,
  locator: &str,
) -> Principal {
  static CACHE: LazyLock<Mutex<HashMap<(usize, usize), Principal>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));
  let key = match (isolate_id, script_id) {
    (Some(i), Some(s)) => Some((i, s)),
    _ => None,
  };
  if let Some(k) = key
    && let Some(p) = CACHE.lock().unwrap().get(&k)
  {
    return p.clone();
  }
  let principal = resolve_locator(locator);
  if let Some(k) = key {
    CACHE.lock().unwrap().insert(k, principal.clone());
  }
  principal
}

#[cfg(test)]
mod tests {
  use super::*;

  fn lock(json: &str) -> LockState {
    LockState::Loaded(parse_lockfile(json).unwrap())
  }

  fn no_pkg_json(_: &str) -> Option<String> {
    None
  }

  const LOCK: &str = r#"{
    "version": "5",
    "npm": {
      "dep-a@1.0.0": { "integrity": "sha512-AAA" },
      "@scope/dep@2.1.0_peer@3.0.0": { "integrity": "sha512-SCOPED" }
    },
    "jsr": {
      "@std/fs@1.0.2": { "integrity": "sha256-JSR" }
    },
    "remote": {
      "https://example.com/mod.ts": "cafebabe"
    }
  }"#;

  #[test]
  fn lock_key_split_handles_scopes_underscores_and_peers() {
    assert_eq!(
      split_lock_key("dep-a@1.0.0"),
      Some(("dep-a".into(), "1.0.0".into()))
    );
    assert_eq!(
      split_lock_key("@scope/dep@2.1.0_peer@3.0.0"),
      Some(("@scope/dep".into(), "2.1.0".into()))
    );
    assert_eq!(
      split_lock_key("@jsr/denotest__add@1.0.0"),
      Some(("@jsr/denotest__add".into(), "1.0.0".into()))
    );
    assert_eq!(split_lock_key("no-version"), None);
  }

  #[test]
  fn matching_claim_binds_with_integrity() {
    let entry = bind(
      "file:///p/node_modules/dep-a/index.js",
      Principal::Package {
        name: "dep-a".into(),
        version: None,
      },
      &lock(LOCK),
      &|_| Some("1.0.0".into()),
    );
    assert_eq!(
      entry.principal,
      Principal::Package {
        name: "dep-a".into(),
        version: Some("1.0.0".into())
      }
    );
    assert_eq!(entry.integrity.as_deref(), Some("sha512-AAA"));
  }

  #[test]
  fn version_swap_fails_attribution_closed() {
    // The forged-version residual (Ibex 0016 W7b/R8): the on-disk package
    // claims a version the lockfile does not pin. Attribution must fail
    // CLOSED to quarantine — not fall back to the path-string principal.
    let entry = bind(
      "file:///p/node_modules/dep-a/index.js",
      Principal::Package {
        name: "dep-a".into(),
        version: None,
      },
      &lock(LOCK),
      &|_| Some("2.0.0".into()),
    );
    assert_eq!(entry.principal, Principal::Quarantine);
    assert_eq!(entry.integrity, None);
  }

  #[test]
  fn package_missing_from_lockfile_fails_closed() {
    let entry = bind(
      "file:///p/node_modules/not-pinned/index.js",
      Principal::Package {
        name: "not-pinned".into(),
        version: None,
      },
      &lock(LOCK),
      &|_| Some("1.0.0".into()),
    );
    assert_eq!(entry.principal, Principal::Quarantine);
  }

  #[test]
  fn unverifiable_version_claim_fails_closed() {
    // No package.json version and no managed-layout folder: with a lockfile
    // present the claim cannot be verified — quarantine, never a bare name.
    let entry = bind(
      "file:///p/node_modules/dep-a/index.js",
      Principal::Package {
        name: "dep-a".into(),
        version: None,
      },
      &lock(LOCK),
      &no_pkg_json,
    );
    assert_eq!(entry.principal, Principal::Quarantine);
  }

  #[test]
  fn no_lockfile_passes_through_unbound() {
    let entry = bind(
      "file:///p/node_modules/dep-a/index.js",
      Principal::Package {
        name: "dep-a".into(),
        version: None,
      },
      &LockState::Absent,
      &no_pkg_json,
    );
    assert_eq!(
      entry.principal,
      Principal::Package {
        name: "dep-a".into(),
        version: None
      }
    );
    assert_eq!(entry.integrity, None);
  }

  #[test]
  fn unreadable_lockfile_fails_closed() {
    let entry = bind(
      "file:///p/node_modules/dep-a/index.js",
      Principal::Package {
        name: "dep-a".into(),
        version: None,
      },
      &LockState::Unreadable,
      &|_| Some("1.0.0".into()),
    );
    assert_eq!(entry.principal, Principal::Quarantine);
  }

  #[test]
  fn managed_layout_folder_version_is_the_claim() {
    let v = npm_claimed_version(
      "file:///p/node_modules/.deno/dep-a@1.0.0/node_modules/dep-a/index.js",
      "dep-a",
      &no_pkg_json,
    );
    assert_eq!(v.as_deref(), Some("1.0.0"));
    // Scoped names fold `/` to `+` in the managed layout.
    let v = npm_claimed_version(
      "file:///p/node_modules/.deno/@scope+dep@2.1.0/node_modules/@scope/dep/i.js",
      "@scope/dep",
      &no_pkg_json,
    );
    assert_eq!(v.as_deref(), Some("2.1.0"));
    // A folder that names a DIFFERENT package is not a claim for this one.
    let v = npm_claimed_version(
      "file:///p/node_modules/.deno/other@9.9.9/node_modules/dep-a/index.js",
      "dep-a",
      &no_pkg_json,
    );
    assert_eq!(v, None);
  }

  #[test]
  fn scoped_peer_suffixed_pin_binds() {
    let entry = bind(
      "file:///p/node_modules/@scope/dep/index.js",
      Principal::Package {
        name: "@scope/dep".into(),
        version: None,
      },
      &lock(LOCK),
      &|_| Some("2.1.0".into()),
    );
    assert_eq!(entry.integrity.as_deref(), Some("sha512-SCOPED"));
  }

  #[test]
  fn jsr_binding_and_swap() {
    let bound = bind(
      "https://jsr.io/@std/fs/1.0.2/mod.ts",
      Principal::Jsr {
        name: "@std/fs".into(),
        version: Some("1.0.2".into()),
      },
      &lock(LOCK),
      &no_pkg_json,
    );
    assert_eq!(bound.integrity.as_deref(), Some("sha256-JSR"));
    let swapped = bind(
      "https://jsr.io/@std/fs/9.9.9/mod.ts",
      Principal::Jsr {
        name: "@std/fs".into(),
        version: Some("9.9.9".into()),
      },
      &lock(LOCK),
      &no_pkg_json,
    );
    assert_eq!(swapped.principal, Principal::Quarantine);
  }

  #[test]
  fn url_binding_and_unpinned_url_fails_closed() {
    let bound = bind(
      "https://example.com/mod.ts",
      Principal::Url {
        canonical: "https://example.com/mod.ts".into(),
      },
      &lock(LOCK),
      &no_pkg_json,
    );
    assert_eq!(bound.integrity.as_deref(), Some("cafebabe"));
    let unpinned = bind(
      "https://example.com/other.ts",
      Principal::Url {
        canonical: "https://example.com/other.ts".into(),
      },
      &lock(LOCK),
      &no_pkg_json,
    );
    assert_eq!(unpinned.principal, Principal::Quarantine);
  }

  #[test]
  fn global_npm_cache_admits_only_via_lockfile() {
    let locator =
      "file:///home/u/.cache/deno/npm/registry.npmjs.org/dep-a/1.0.0/index.js";
    // Pinned: attributed to the package, integrity-bound.
    let entry = bind(locator, Principal::Quarantine, &lock(LOCK), &no_pkg_json);
    assert_eq!(
      entry.principal,
      Principal::Package {
        name: "dep-a".into(),
        version: Some("1.0.0".into())
      }
    );
    assert_eq!(entry.integrity.as_deref(), Some("sha512-AAA"));
    // Unpinned version: stays quarantined.
    let swapped = bind(
      "file:///home/u/.cache/deno/npm/registry.npmjs.org/dep-a/9.9.9/index.js",
      Principal::Quarantine,
      &lock(LOCK),
      &no_pkg_json,
    );
    assert_eq!(swapped.principal, Principal::Quarantine);
    // No lockfile: never a path-string widen.
    let absent = bind(
      locator,
      Principal::Quarantine,
      &LockState::Absent,
      &no_pkg_json,
    );
    assert_eq!(absent.principal, Principal::Quarantine);
  }

  #[test]
  fn root_runtime_and_sentinels_are_never_lockfile_bound() {
    for p in [Principal::Root, Principal::Runtime, Principal::NoUser] {
      let entry =
        bind("file:///p/app.js", p.clone(), &lock(LOCK), &no_pkg_json);
      assert_eq!(entry.principal, p);
      assert_eq!(entry.integrity, None);
    }
  }
}

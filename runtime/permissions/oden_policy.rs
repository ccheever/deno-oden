// Copyright 2018-2026 the Deno authors. MIT license.

use std::collections::BTreeSet;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;

use super::oden_dynamic::EscalationCeiling;
use super::oden_dynamic::SessionOverlay;

// Fork-local mirror of the parent workspace's crates/oden_policy model. The
// fork must remain buildable without a path dependency back to the parent repo.
// @ref llp/0001-adding-capability-security-to-deno.plan.md
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Family {
  Fs,
  Network,
  Env,
  Run,
  Ffi,
  Sys,
}

impl Family {
  fn parse(s: &str) -> Option<Family> {
    match s.to_lowercase().as_str() {
      "fs" | "file" | "read" | "write" => Some(Family::Fs),
      "network" | "net" | "fetch" => Some(Family::Network),
      "env" => Some(Family::Env),
      "run" | "spawn" => Some(Family::Run),
      "ffi" | "napi" => Some(Family::Ffi),
      "sys" | "os" => Some(Family::Sys),
      _ => None,
    }
  }

  pub fn name(self) -> &'static str {
    match self {
      Family::Fs => "fs",
      Family::Network => "network",
      Family::Env => "env",
      Family::Run => "run",
      Family::Ffi => "ffi",
      Family::Sys => "sys",
    }
  }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Grant {
  pub family: Family,
  pub action: String,
  pub scope: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
  pub family: Family,
  pub action: String,
  pub target: String,
}

// Keep in parity with the parent workspace's `oden_policy` and userland
// `policy.ts`. The fork remains standalone, so this is intentionally mirrored
// rather than imported through an outward path dependency.
// @ref LLP 0014#the-endowment-derivation-table [implements]
pub const ALWAYS_ENDOWED_GLOBALS: &[&str] = &[
  "AggregateError",
  "Array",
  "ArrayBuffer",
  "Atomics",
  "BigInt",
  "BigInt64Array",
  "BigUint64Array",
  "Blob",
  "Boolean",
  "DataView",
  "Date",
  "Error",
  "EvalError",
  "FinalizationRegistry",
  "Float16Array",
  "Float32Array",
  "Float64Array",
  "Function",
  "Headers",
  "Infinity",
  "Int16Array",
  "Int32Array",
  "Int8Array",
  "Intl",
  "Iterator",
  "JSON",
  "Map",
  "Math",
  "NaN",
  "Number",
  "Object",
  "Promise",
  "Proxy",
  "RangeError",
  "ReferenceError",
  "Reflect",
  "RegExp",
  "Request",
  "Response",
  "Set",
  "SharedArrayBuffer",
  "String",
  "SubtleCrypto",
  "SuppressedError",
  "Symbol",
  "SyntaxError",
  "Temporal",
  "TextDecoder",
  "TextEncoder",
  "TypeError",
  "URIError",
  "URL",
  "URLPattern",
  "URLSearchParams",
  "Uint16Array",
  "Uint32Array",
  "Uint8Array",
  "Uint8ClampedArray",
  "WeakMap",
  "WeakRef",
  "WeakSet",
  "WebAssembly",
  "atob",
  "btoa",
  "crypto",
  "decodeURI",
  "decodeURIComponent",
  "encodeURI",
  "encodeURIComponent",
  "escape",
  "isFinite",
  "isNaN",
  "parseFloat",
  "parseInt",
  "performance",
  "queueMicrotask",
  "structuredClone",
  "undefined",
  "unescape",
];

pub const GRANT_DERIVED_GLOBALS: &[&str] =
  &["EventSource", "WebSocket", "fetch"];

pub fn endow(grants: &[Grant]) -> BTreeSet<String> {
  let mut names = ALWAYS_ENDOWED_GLOBALS
    .iter()
    .map(|name| (*name).to_string())
    .collect::<BTreeSet<_>>();
  for grant in grants {
    if grant.family != Family::Network {
      continue;
    }
    match grant.action.as_str() {
      "fetch" => {
        names.insert("EventSource".into());
        names.insert("fetch".into());
      }
      "connect" => {
        names.insert("WebSocket".into());
      }
      "*" => names
        .extend(GRANT_DERIVED_GLOBALS.iter().map(|name| (*name).to_string())),
      _ => {}
    }
  }
  names
}

impl Grant {
  pub fn parse(s: &str) -> Option<Grant> {
    let s = s.trim();
    let parts: Vec<&str> = s.split(':').collect();
    let family = Family::parse(parts.first()?.trim())?;
    match family {
      Family::Ffi => Some(Grant {
        family,
        action: "load".into(),
        scope: String::new(),
      }),
      Family::Run => {
        let scope = if parts.len() >= 3 {
          parts[2..].join(":")
        } else {
          parts.get(1).copied().unwrap_or("").to_string()
        };
        Some(Grant {
          family,
          action: "run".into(),
          scope,
        })
      }
      Family::Env => {
        let mid = parts.get(1).copied().unwrap_or("").to_lowercase();
        let action = if parts.len() >= 3 && (mid == "write" || mid == "*") {
          mid
        } else {
          "read".to_string()
        };
        let scope = if parts.len() >= 3 {
          parts[2..].join(":")
        } else {
          parts.get(1).copied().unwrap_or("").to_string()
        };
        Some(Grant {
          family,
          action,
          scope,
        })
      }
      Family::Sys => {
        let scope = if parts.len() >= 3 {
          parts[2..].join(":")
        } else {
          parts.get(1).copied().unwrap_or("").to_string()
        };
        Some(Grant {
          family,
          action: "read".into(),
          scope,
        })
      }
      Family::Fs | Family::Network => {
        let action = parts.get(1).copied().unwrap_or("*").trim().to_lowercase();
        let scope = if parts.len() >= 3 {
          parts[2..].join(":")
        } else {
          String::new()
        };
        Some(Grant {
          family,
          action,
          scope,
        })
      }
    }
  }

  pub fn parse_many(s: &str) -> Vec<Grant> {
    s.split(',').filter_map(Grant::parse).collect()
  }

  pub fn valid_dynamic_authority(s: &str) -> bool {
    s.split(',')
      .map(str::trim)
      .filter(|token| !token.is_empty())
      .all(valid_dynamic_authority_token)
  }

  pub fn to_string_canonical(&self) -> String {
    match self.family {
      Family::Ffi => "ffi".into(),
      Family::Run => {
        if self.scope.is_empty() {
          "run".into()
        } else {
          format!("run:{}", self.scope)
        }
      }
      Family::Env => format!("env:{}:{}", self.action, self.scope),
      Family::Sys => format!("sys:read:{}", self.scope),
      Family::Fs => format!("fs:{}:{}", self.action, self.scope),
      Family::Network => {
        format!("network:{}:{}", self.action, self.scope)
      }
    }
  }

  /// Exact session-grant width for dynamic permissions.
  /// @ref llp/0015-dynamic-permissions-with-ceiling.plan.md (Request state machine)
  pub fn from_request(req: &Request) -> Grant {
    Grant {
      family: req.family,
      action: req.action.clone(),
      scope: req.target.clone(),
    }
  }
}

fn valid_dynamic_authority_token(token: &str) -> bool {
  let parts = token.split(':').collect::<Vec<_>>();
  let Some(family) = parts.first().and_then(|value| Family::parse(value))
  else {
    return false;
  };
  match family {
    Family::Ffi => parts.len() == 1,
    Family::Run => match parts.as_slice() {
      [_] => true,
      [_, scope] => !scope.is_empty(),
      [_, action, scope @ ..] => {
        action.eq_ignore_ascii_case("run")
          && !scope.is_empty()
          && scope.iter().any(|part| !part.is_empty())
      }
      [] => false,
    },
    Family::Env => match parts.as_slice() {
      [_, scope] => !scope.is_empty(),
      [_, action, scope @ ..] => {
        matches!(action.to_lowercase().as_str(), "read" | "write" | "*")
          && !scope.is_empty()
          && scope.iter().any(|part| !part.is_empty())
      }
      _ => false,
    },
    Family::Sys => match parts.as_slice() {
      [_, scope] => !scope.is_empty(),
      [_, action, scope @ ..] => {
        action.eq_ignore_ascii_case("read")
          && !scope.is_empty()
          && scope.iter().any(|part| !part.is_empty())
      }
      _ => false,
    },
    Family::Fs => {
      parts.len() >= 3
        && matches!(parts[1].to_lowercase().as_str(), "read" | "write" | "*")
        && parts[2..].iter().any(|part| !part.is_empty())
    }
    Family::Network => {
      parts.len() >= 3
        && matches!(
          parts[1].to_lowercase().as_str(),
          "fetch" | "connect" | "listen" | "*"
        )
        && parts[2..].iter().any(|part| !part.is_empty())
    }
  }
}

pub fn covers(grants: &[Grant], req: &Request) -> bool {
  grants.iter().any(|g| covers_one(g, req))
}

fn covers_one(g: &Grant, req: &Request) -> bool {
  if g.family != req.family {
    return false;
  }
  match g.family {
    Family::Fs => {
      if g.scope.is_empty() {
        return false;
      }
      (g.action == req.action || g.action == "*")
        && (g.scope == "*" || path_under(&req.target, &g.scope))
    }
    Family::Network => {
      (g.action == req.action || g.action == "*")
        && host_covered(&g.scope, &host_of(&req.target))
    }
    Family::Env => {
      (g.action == req.action || g.action == "*")
        && (g.scope == "*" || g.scope == req.target)
    }
    Family::Run => {
      g.scope == "*"
        || g.scope == req.target
        || g.scope == basename(&req.target)
    }
    Family::Ffi => true,
    Family::Sys => g.scope == "*" || g.scope == req.target,
  }
}

pub fn grants_intersect(a: &Grant, b: &Grant) -> bool {
  if a.family != b.family {
    return false;
  }
  let actions_overlap =
    a.action == "*" || b.action == "*" || a.action == b.action;
  match a.family {
    Family::Ffi => true,
    Family::Fs => {
      actions_overlap
        && !a.scope.is_empty()
        && !b.scope.is_empty()
        && (a.scope == "*"
          || b.scope == "*"
          || path_under(&a.scope, &b.scope)
          || path_under(&b.scope, &a.scope))
    }
    Family::Network => {
      actions_overlap
        && (host_covered(&a.scope, &b.scope)
          || host_covered(&b.scope, &a.scope))
    }
    Family::Env => {
      actions_overlap
        && (a.scope == "*" || b.scope == "*" || a.scope == b.scope)
    }
    Family::Sys => a.scope == "*" || b.scope == "*" || a.scope == b.scope,
    Family::Run => {
      covers_one(
        a,
        &Request {
          family: b.family,
          action: b.action.clone(),
          target: b.scope.clone(),
        },
      ) || covers_one(
        b,
        &Request {
          family: a.family,
          action: a.action.clone(),
          target: a.scope.clone(),
        },
      )
    }
  }
}

pub fn path_under(child: &str, parent: &str) -> bool {
  if parent.is_empty() {
    return false;
  }
  if parent == "/" {
    return child.starts_with('/');
  }
  if child == parent {
    return true;
  }
  let boundary = if parent.ends_with('/') {
    parent.to_string()
  } else {
    format!("{parent}/")
  };
  child.starts_with(&boundary)
}

fn host_covered(grant_host: &str, host: &str) -> bool {
  let grant_host = grant_host.to_lowercase();
  let host = host.to_lowercase();
  grant_host == "*"
    || host == grant_host
    || host.ends_with(&format!(".{grant_host}"))
}

fn host_of(target: &str) -> String {
  if target.starts_with("unix:") || target.starts_with("vsock:") {
    return target.to_string();
  }
  let t = target
    .strip_prefix("https://")
    .or_else(|| target.strip_prefix("http://"))
    .unwrap_or(target);
  let t = t.split('/').next().unwrap_or(t);
  if let Some(bracketed) = t.strip_prefix('[')
    && let Some(end) = bracketed.find(']')
  {
    return format!("[{}]", &bracketed[..end]);
  }
  if t.matches(':').count() == 1 {
    return t.split(':').next().unwrap_or(t).to_string();
  }
  t.to_string()
}

fn basename(p: &str) -> String {
  p.rsplit('/').next().unwrap_or(p).to_string()
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Principal {
  Root,
  Package {
    name: String,
    version: Option<String>,
  },
  Jsr {
    name: String,
    version: Option<String>,
  },
  Url {
    canonical: String,
  },
  Runtime,
  Quarantine,
  NoUser,
}

impl Principal {
  pub fn selector(&self) -> Option<String> {
    match self {
      Principal::Package { name, .. } => Some(name.clone()),
      Principal::Jsr { name, .. } => Some(name.clone()),
      Principal::Url { canonical } => Some(canonical.clone()),
      _ => None,
    }
  }

  pub fn is_ambient(&self) -> bool {
    matches!(self, Principal::Root | Principal::Runtime)
  }

  pub fn label(&self) -> String {
    match self {
      Principal::Root => "root".to_string(),
      Principal::Package { name, .. } => name.clone(),
      Principal::Jsr { name, .. } => name.clone(),
      Principal::Url { canonical } => canonical.clone(),
      Principal::Runtime => "runtime".to_string(),
      Principal::Quarantine => "quarantine".to_string(),
      Principal::NoUser => "no-user".to_string(),
    }
  }
}

pub fn classify(locator: &str, project_root: &str) -> Principal {
  if locator.starts_with("ext:")
    || locator.starts_with("node:")
    || locator.starts_with("deno:")
  {
    return Principal::Runtime;
  }
  if locator.starts_with("data:") || locator.starts_with("blob:") {
    return Principal::Quarantine;
  }
  if let Some(idx) = locator.rfind("/node_modules/") {
    let rest = &locator[idx + "/node_modules/".len()..];
    if let Some((name, version)) = package_from_node_modules(rest) {
      return Principal::Package { name, version };
    }
  }
  if let Some(spec) = locator.strip_prefix("npm:") {
    let (name, version) = npm_name_version(spec);
    return Principal::Package { name, version };
  }
  if let Some(spec) = locator.strip_prefix("jsr:") {
    let (name, version) = jsr_name_version(spec);
    return Principal::Jsr { name, version };
  }
  if let Some(spec) = locator.strip_prefix("https://jsr.io/") {
    let (name, version) = jsr_name_version(spec);
    return Principal::Jsr { name, version };
  }
  if locator.starts_with("http://") || locator.starts_with("https://") {
    return Principal::Url {
      canonical: locator.to_string(),
    };
  }

  let path = locator.strip_prefix("file://").unwrap_or(locator);
  let root_boundary = if project_root.ends_with('/') {
    project_root.to_string()
  } else {
    format!("{project_root}/")
  };
  if path == project_root || path.starts_with(&root_boundary) {
    return Principal::Root;
  }

  Principal::Quarantine
}

fn package_from_node_modules(rest: &str) -> Option<(String, Option<String>)> {
  let segs: Vec<&str> = rest.split('/').collect();
  let first = *segs.first()?;
  if first.starts_with('@') {
    let scope_pkg = format!("{}/{}", first, segs.get(1)?);
    Some((scope_pkg, None))
  } else if first.is_empty() {
    None
  } else {
    Some((first.to_string(), None))
  }
}

fn npm_name_version(spec: &str) -> (String, Option<String>) {
  if let Some(rest) = spec.strip_prefix('@') {
    if let Some(slash) = rest.find('/') {
      let scope = &rest[..slash];
      let after = &rest[slash + 1..];
      let (name, ver) = split_name_version(after);
      return (format!("@{scope}/{name}"), ver);
    }
    return (format!("@{rest}"), None);
  }
  let (name, ver) = split_name_version(spec);
  (name, ver)
}

fn jsr_name_version(spec: &str) -> (String, Option<String>) {
  let segs: Vec<&str> = spec.split('/').collect();
  if let Some(first) = segs.first()
    && first.starts_with('@')
  {
    if let Some(second) = segs.get(1) {
      let (pkg, ver) = split_name_version(second);
      let version = ver.or_else(|| segs.get(2).map(|v| v.to_string()));
      return (format!("{first}/{pkg}"), version);
    }
    return ((*first).to_string(), None);
  }
  (spec.split('/').next().unwrap_or(spec).to_string(), None)
}

fn split_name_version(s: &str) -> (String, Option<String>) {
  let name_part = s.split('/').next().unwrap_or(s);
  if let Some(at) = name_part.find('@') {
    (
      name_part[..at].to_string(),
      Some(name_part[at + 1..].to_string()),
    )
  } else {
    (name_part.to_string(), None)
  }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
  Permissive,
  Audit,
  Enforce,
}

#[derive(Debug, Clone)]
pub struct Policy {
  pub mode: Mode,
  pub packages: HashMap<String, Vec<Grant>>,
  pub ceilings: HashMap<String, EscalationCeiling>,
  pub deny_ceiling: Vec<Grant>,
  pub(super) session: Arc<Mutex<SessionOverlay>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
  Allow,
  AllowRecord,
  Deny,
}

impl Policy {
  pub fn new(mode: Mode) -> Policy {
    Policy {
      mode,
      packages: HashMap::new(),
      ceilings: HashMap::new(),
      deny_ceiling: Vec::new(),
      session: Arc::new(Mutex::new(SessionOverlay::default())),
    }
  }

  pub fn grant(&mut self, selector: &str, grant_str: &str) {
    self
      .packages
      .entry(selector.to_string())
      .or_default()
      .extend(Grant::parse_many(grant_str));
  }

  /// Mode-independent grant check: does this principal, on its own, hold a
  /// capability covering `req`? Ambient principals (root/runtime) always do;
  /// the fail-closed sentinels (no-user/quarantine) never do. This is the raw
  /// predicate `decide` and `decide_set` layer mode semantics on top of.
  pub fn grants(&self, principal: &Principal, req: &Request) -> bool {
    if principal.is_ambient() {
      return true;
    }
    let Some(selector) = principal.selector() else {
      return false;
    };
    let floor = self
      .packages
      .get(&selector)
      .map(|g| covers(g, req))
      .unwrap_or(false);
    self
      .session
      .lock()
      .unwrap()
      .effective(&selector, req, floor)
  }

  /// Pure `endow(principal, policy)` derivation used by the bootstrap-captured
  /// compartment record. Ambient root/runtime receive every mapped name;
  /// quarantine/no-user receive the authority-free set only.
  // @ref LLP 0014#the-endowment-derivation-table [implements]
  pub fn endowments(&self, principal: &Principal) -> BTreeSet<String> {
    let mut names = if principal.is_ambient() {
      endow(&[])
    } else {
      let grants = principal
        .selector()
        .and_then(|selector| self.packages.get(&selector))
        .map(Vec::as_slice)
        .unwrap_or_default();
      endow(grants)
    };
    if principal.is_ambient() {
      names
        .extend(GRANT_DERIVED_GLOBALS.iter().map(|name| (*name).to_string()));
    }
    names
  }

  pub fn decide(&self, principal: &Principal, req: &Request) -> Decision {
    if self.mode == Mode::Permissive {
      return Decision::Allow;
    }
    if principal.is_ambient() {
      return Decision::Allow;
    }
    let granted = self.grants(principal, req);

    match (granted, self.mode) {
      (true, Mode::Enforce) => Decision::Allow,
      (true, Mode::Audit) => Decision::AllowRecord,
      (false, Mode::Enforce) => Decision::Deny,
      (false, Mode::Audit) => Decision::AllowRecord,
      (_, Mode::Permissive) => Decision::Allow,
    }
  }

  /// Stack-intersection decision (LLP 0001 async-attribution precedence row 3).
  /// Given every principal implicated in an op — the distinct non-ambient
  /// package principals live on the stack, plus any appended CPED scheduling
  /// principal(s) — the op is allowed under enforce only if *every* one of them
  /// independently satisfies the request (least privilege across the call
  /// chain). A single ungranted principal (`[deputy, evil]` with `evil`
  /// ungranted) denies, closing deputy laundering. Ambient principals impose no
  /// constraint and duplicates collapse, so a package scheduling its own
  /// callback (`[evil, evil]` -> `[evil]`) is decided exactly as the
  /// single-principal path — no false denials. An all-ambient (or empty) set is
  /// unconstrained; the caller supplies the row-4 sentinel when nothing is
  /// implicated.
  pub fn decide_set(
    &self,
    principals: &[Principal],
    req: &Request,
  ) -> Decision {
    if self.mode == Mode::Permissive {
      return Decision::Allow;
    }
    let constrained = Self::constrained_principals(principals);
    if constrained.is_empty() {
      return Decision::Allow;
    }
    let all_granted = constrained.iter().all(|p| self.grants(p, req));
    match self.mode {
      Mode::Enforce if all_granted => Decision::Allow,
      Mode::Enforce => Decision::Deny,
      Mode::Audit => Decision::AllowRecord,
      Mode::Permissive => Decision::Allow,
    }
  }

  /// The distinct, constraint-bearing principals of a set: ambient principals
  /// (root/runtime) dropped, order preserved, duplicates collapsed. The
  /// fail-closed sentinels (no-user/quarantine) are kept — they are never
  /// granted, so their presence denies, which is the intended fail-closed
  /// behavior for an unattributable frame in the intersection.
  pub fn constrained_principals(principals: &[Principal]) -> Vec<Principal> {
    let mut out: Vec<Principal> = Vec::new();
    for p in principals {
      if p.is_ambient() {
        continue;
      }
      if !out.contains(p) {
        out.push(p.clone());
      }
    }
    out
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn classifies_node_modules_and_root() {
    assert_eq!(
      classify("file:///proj/node_modules/evil-dep/mod.js", "/proj"),
      Principal::Package {
        name: "evil-dep".into(),
        version: None
      }
    );
    assert_eq!(classify("file:///proj/app.js", "/proj"), Principal::Root);
    assert_eq!(
      classify("file:///elsewhere/app.js", "/proj"),
      Principal::Quarantine
    );
  }

  #[test]
  fn policy_denies_ungranted_package_under_enforce() {
    let mut policy = Policy::new(Mode::Enforce);
    policy.grant("evil-dep", "env:read:ALLOWED");
    let principal = Principal::Package {
      name: "evil-dep".into(),
      version: None,
    };
    assert_eq!(
      policy.decide(
        &principal,
        &Request {
          family: Family::Env,
          action: "read".into(),
          target: "ALLOWED".into(),
        },
      ),
      Decision::Allow,
    );
    assert_eq!(
      policy.decide(
        &principal,
        &Request {
          family: Family::Env,
          action: "read".into(),
          target: "SECRET".into(),
        },
      ),
      Decision::Deny,
    );
  }

  #[test]
  fn endowment_derivation_is_action_sensitive_and_fs_empty() {
    let mut policy = Policy::new(Mode::Enforce);
    policy.grant("fetcher", "network:fetch:api.example");
    policy.grant("socket", "network:connect:socket.example");
    policy.grant("reader", "fs:read:/tmp");

    let fetcher = policy.endowments(&pkg("fetcher"));
    assert!(fetcher.contains("fetch"));
    assert!(fetcher.contains("EventSource"));
    assert!(!fetcher.contains("WebSocket"));

    let socket = policy.endowments(&pkg("socket"));
    assert!(socket.contains("WebSocket"));
    assert!(!socket.contains("fetch"));

    assert_eq!(
      policy.endowments(&pkg("reader")).len(),
      ALWAYS_ENDOWED_GLOBALS.len()
    );
    assert!(policy.endowments(&Principal::Root).contains("fetch"));
  }

  #[test]
  fn network_coverage_preserves_unix_vsock_and_ipv6_endpoint_shapes() {
    let cases = [
      (
        "network:fetch:unix:/tmp/oden.sock",
        "fetch",
        "unix:/tmp/oden.sock",
      ),
      ("network:connect:vsock:2:8000", "connect", "vsock:2:8000"),
      ("network:connect:[::1]", "connect", "[::1]:443"),
    ];
    for (grant, action, target) in cases {
      let grant = Grant::parse(grant).unwrap();
      assert!(covers(
        &[grant],
        &Request {
          family: Family::Network,
          action: action.into(),
          target: target.into(),
        }
      ));
    }

    assert!(!covers(
      &[Grant::parse("network:fetch:unix:/tmp/oden.sock").unwrap()],
      &Request {
        family: Family::Network,
        action: "connect".into(),
        target: "unix:/tmp/oden.sock".into(),
      }
    ));
  }

  #[test]
  fn dynamic_authority_vocabulary_is_strict() {
    assert!(Grant::valid_dynamic_authority(
      "fs:read:./cache,network:connect:example.com,env:*:TOKEN,run:git,sys:read:hostname,ffi"
    ));
    assert!(!Grant::valid_dynamic_authority("telepathy:read:thoughts"));
    assert!(!Grant::valid_dynamic_authority("env:execute:PATH"));
    assert!(!Grant::valid_dynamic_authority("network:connect:"));
  }

  #[test]
  fn intersection_compares_action_and_scope_breadth_independently() {
    let narrow_all = Grant::parse("fs:*:/proj/.oden/cache").unwrap();
    let broad_read = Grant::parse("fs:read:/proj/.oden").unwrap();
    assert!(grants_intersect(&narrow_all, &broad_read));

    let all_env = Grant::parse("env:*:*").unwrap();
    let one_env_read = Grant::parse("env:read:NPM_TOKEN").unwrap();
    assert!(grants_intersect(&all_env, &one_env_read));
    assert!(!grants_intersect(
      &Grant::parse("env:write:SAFE").unwrap(),
      &one_env_read
    ));
  }

  // --- Stack-intersection / deputyClasses (precedence row 3) ----------------

  fn pkg(name: &str) -> Principal {
    Principal::Package {
      name: name.into(),
      version: None,
    }
  }

  fn req_secret() -> Request {
    Request {
      family: Family::Env,
      action: "read".into(),
      target: "SECRET".into(),
    }
  }

  #[test]
  fn stack_intersection_denies_when_scheduler_ungranted() {
    // A trusted deputy is granted SECRET; the evil scheduler is not. Row 1
    // alone (nearest frame = deputy) would allow. The stack-intersection set
    // [deputy, evil] must deny because evil is ungranted -- deputy laundering
    // is closed.
    let mut policy = Policy::new(Mode::Enforce);
    policy.grant("deputy-dep", "env:read:SECRET");
    assert_eq!(
      policy.decide_set(&[pkg("deputy-dep"), pkg("evil-dep")], &req_secret()),
      Decision::Deny,
    );
  }

  #[test]
  fn stack_intersection_allows_when_all_granted() {
    let mut policy = Policy::new(Mode::Enforce);
    policy.grant("deputy-dep", "env:read:SECRET");
    policy.grant("evil-dep", "env:read:SECRET");
    assert_eq!(
      policy.decide_set(&[pkg("deputy-dep"), pkg("evil-dep")], &req_secret()),
      Decision::Allow,
    );
  }

  #[test]
  fn self_scheduling_collapses_without_false_denial() {
    // A package scheduling its own callback yields [evil, evil], which collapses
    // to [evil]; a grant to evil allows, exactly as the single-principal path.
    let mut policy = Policy::new(Mode::Enforce);
    policy.grant("evil-dep", "env:read:SECRET");
    assert_eq!(
      policy.decide_set(&[pkg("evil-dep"), pkg("evil-dep")], &req_secret()),
      Decision::Allow,
    );
  }

  #[test]
  fn ambient_principals_impose_no_constraint() {
    // root on the stack beneath a granted package does not deny; an all-ambient
    // set is unconstrained.
    let mut policy = Policy::new(Mode::Enforce);
    policy.grant("evil-dep", "env:read:SECRET");
    assert_eq!(
      policy.decide_set(&[Principal::Root, pkg("evil-dep")], &req_secret()),
      Decision::Allow,
    );
    assert_eq!(
      policy.decide_set(&[Principal::Root, Principal::Runtime], &req_secret()),
      Decision::Allow,
    );
  }

  #[test]
  fn no_user_sentinel_in_set_fails_closed() {
    // An unattributable frame (no-user) in the intersection denies under
    // enforce even alongside a granted package -- fail closed, never launder.
    let mut policy = Policy::new(Mode::Enforce);
    policy.grant("deputy-dep", "env:read:SECRET");
    assert_eq!(
      policy.decide_set(&[pkg("deputy-dep"), Principal::NoUser], &req_secret()),
      Decision::Deny,
    );
  }

  #[test]
  fn constrained_principals_drops_ambient_and_dedupes() {
    let set = Policy::constrained_principals(&[
      Principal::Root,
      pkg("evil-dep"),
      Principal::Runtime,
      pkg("evil-dep"),
      pkg("deputy-dep"),
    ]);
    assert_eq!(set, vec![pkg("evil-dep"), pkg("deputy-dep")]);
  }
}

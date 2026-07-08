// Copyright 2018-2026 the Deno authors. MIT license.

use std::collections::HashMap;

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
}

impl Family {
  fn parse(s: &str) -> Option<Family> {
    match s {
      "fs" | "read" | "write" => Some(Family::Fs),
      "network" | "net" | "fetch" => Some(Family::Network),
      "env" => Some(Family::Env),
      "run" | "spawn" => Some(Family::Run),
      "ffi" | "napi" => Some(Family::Ffi),
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
    }
  }
}

#[derive(Debug, Clone, PartialEq, Eq)]
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
      (g.action == req.action || g.action == "*")
        && (g.scope == "*" || path_under(&req.target, &g.scope))
    }
    Family::Network => host_covered(&g.scope, &host_of(&req.target)),
    Family::Env => g.scope == "*" || g.scope == req.target,
    Family::Run => g.scope == req.target || g.scope == basename(&req.target),
    Family::Ffi => true,
  }
}

pub fn path_under(child: &str, parent: &str) -> bool {
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
  grant_host == "*"
    || host == grant_host
    || host.ends_with(&format!(".{grant_host}"))
}

fn host_of(target: &str) -> String {
  let t = target
    .strip_prefix("https://")
    .or_else(|| target.strip_prefix("http://"))
    .unwrap_or(target);
  let t = t.split('/').next().unwrap_or(t);
  t.split(':').next().unwrap_or(t).to_string()
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
    }
  }

  pub fn grant(&mut self, selector: &str, grant_str: &str) {
    self
      .packages
      .entry(selector.to_string())
      .or_default()
      .extend(Grant::parse_many(grant_str));
  }

  pub fn decide(&self, principal: &Principal, req: &Request) -> Decision {
    if self.mode == Mode::Permissive {
      return Decision::Allow;
    }
    if principal.is_ambient() {
      return Decision::Allow;
    }
    let granted = principal
      .selector()
      .and_then(|s| self.packages.get(&s))
      .map(|g| covers(g, req))
      .unwrap_or(false);

    match (granted, self.mode) {
      (true, Mode::Enforce) => Decision::Allow,
      (true, Mode::Audit) => Decision::AllowRecord,
      (false, Mode::Enforce) => Decision::Deny,
      (false, Mode::Audit) => Decision::AllowRecord,
      (_, Mode::Permissive) => Decision::Allow,
    }
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
}

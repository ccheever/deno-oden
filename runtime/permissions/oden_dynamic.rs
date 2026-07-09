// Copyright 2018-2026 the Deno authors. MIT license.

//! Ceiling-bounded dynamic permission state for Oden package principals.
//!
//! @ref llp/0015-dynamic-permissions-with-ceiling.plan.md (Authority envelope; Request state machine)

use std::collections::HashMap;

use super::oden_policy::Grant;
use super::oden_policy::Mode;
use super::oden_policy::Policy;
use super::oden_policy::Principal;
use super::oden_policy::Request;
use super::oden_policy::covers;
use super::oden_policy::grants_intersect;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OnRequest {
  Prompt,
  Auto,
  Deny,
}

impl OnRequest {
  pub fn parse(value: &str) -> Option<Self> {
    match value {
      "prompt" => Some(Self::Prompt),
      "auto" => Some(Self::Auto),
      "deny" => Some(Self::Deny),
      _ => None,
    }
  }
}

#[derive(Debug, Clone)]
pub struct EscalationCeiling {
  pub authority: Vec<Grant>,
  pub on_request: OnRequest,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyValidationIssue {
  FloorAboveCeiling {
    selector: String,
    grant: String,
  },
  CeilingConflicted {
    selector: String,
    ceiling: String,
    deny: String,
  },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DynamicPermissionState {
  Granted,
  Denied,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DynamicQueryState {
  Ambient,
  Granted,
  Prompt,
  Denied,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum DynamicRequestCode {
  Granted,
  Refused,
  AboveCeiling,
  DenyCeiling,
  Unanswered,
  Unattributed,
  Ambiguous,
}

impl DynamicRequestCode {
  pub fn as_str(self) -> &'static str {
    match self {
      Self::Granted => "OD-CAP-REQ-GRANTED",
      Self::Refused => "OD-CAP-REQ-REFUSED",
      Self::AboveCeiling => "OD-CAP-REQ-ABOVE-CEILING",
      Self::DenyCeiling => "OD-CAP-REQ-DENY-CEILING",
      Self::Unanswered => "OD-CAP-REQ-UNANSWERED",
      Self::Unattributed => "OD-CAP-REQ-UNATTRIBUTED",
      Self::Ambiguous => "OD-CAP-REQ-AMBIGUOUS",
    }
  }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DynamicDecider {
  Existing,
  Policy,
  Interactive,
  Broker,
}

impl DynamicDecider {
  pub fn as_str(self) -> &'static str {
    match self {
      Self::Existing => "existing",
      Self::Policy => "policy",
      Self::Interactive => "interactive",
      Self::Broker => "broker",
    }
  }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DynamicRequestResult {
  pub state: DynamicPermissionState,
  pub code: DynamicRequestCode,
  pub decider: Option<DynamicDecider>,
  pub session_grant: Option<Grant>,
  pub ceiling: Option<Grant>,
  pub memoized: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DynamicRequestEvaluation {
  Ambient,
  Terminal(DynamicRequestResult),
  NeedsDecision { ceiling: Grant },
}

#[derive(Debug, Clone)]
struct OverlayEntry {
  grant: Grant,
  allow: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct RequestKey {
  selector: String,
  family: super::oden_policy::Family,
  action: String,
  target: String,
}

impl RequestKey {
  fn new(selector: &str, req: &Request) -> Self {
    Self {
      selector: selector.to_string(),
      family: req.family,
      action: req.action.clone(),
      target: req.target.clone(),
    }
  }
}

#[derive(Debug, Default)]
pub(super) struct SessionOverlay {
  entries: HashMap<String, Vec<OverlayEntry>>,
  memo: HashMap<RequestKey, DynamicRequestCode>,
}

impl SessionOverlay {
  pub(super) fn effective(
    &self,
    selector: &str,
    req: &Request,
    floor: bool,
  ) -> bool {
    let mut effective = floor;
    if let Some(entries) = self.entries.get(selector) {
      for entry in entries {
        if covers(std::slice::from_ref(&entry.grant), req) {
          effective = entry.allow;
        }
      }
    }
    effective
  }

  fn append(&mut self, selector: &str, req: &Request, allow: bool) -> Grant {
    let grant = Grant::from_request(req);
    self
      .entries
      .entry(selector.to_string())
      .or_default()
      .push(OverlayEntry {
        grant: grant.clone(),
        allow,
      });
    if allow {
      self.memo.remove(&RequestKey::new(selector, req));
    }
    grant
  }
}

impl Policy {
  pub fn ceiling(
    &mut self,
    selector: &str,
    authority: &str,
    on_request: OnRequest,
  ) {
    let parsed = Grant::parse_many(authority);
    self
      .ceilings
      .entry(selector.to_string())
      .and_modify(|c| {
        c.authority.extend(parsed.clone());
        c.on_request = on_request;
      })
      .or_insert(EscalationCeiling {
        authority: parsed,
        on_request,
      });
  }

  pub fn deny_ceiling(&mut self, authority: &str) {
    self.deny_ceiling.extend(Grant::parse_many(authority));
  }

  pub fn validate_envelopes(&self) -> Vec<PolicyValidationIssue> {
    let mut issues = Vec::new();
    for (selector, ceiling) in &self.ceilings {
      for entry in &ceiling.authority {
        if let Some(deny) = self
          .deny_ceiling
          .iter()
          .find(|deny| grants_intersect(entry, deny))
        {
          issues.push(PolicyValidationIssue::CeilingConflicted {
            selector: selector.clone(),
            ceiling: entry.to_string_canonical(),
            deny: deny.to_string_canonical(),
          });
        }
      }
      for floor in self.packages.get(selector).into_iter().flatten() {
        let covered = self.active_ceiling(selector).iter().any(|entry| {
          covers(
            std::slice::from_ref(entry),
            &Request {
              family: floor.family,
              action: floor.action.clone(),
              target: floor.scope.clone(),
            },
          )
        });
        if !covered {
          issues.push(PolicyValidationIssue::FloorAboveCeiling {
            selector: selector.clone(),
            grant: floor.to_string_canonical(),
          });
        }
      }
    }
    issues
  }

  fn active_ceiling(&self, selector: &str) -> Vec<Grant> {
    self
      .ceilings
      .get(selector)
      .map(|ceiling| {
        ceiling
          .authority
          .iter()
          .filter(|entry| {
            !self
              .deny_ceiling
              .iter()
              .any(|deny| grants_intersect(entry, deny))
          })
          .cloned()
          .collect()
      })
      .unwrap_or_default()
  }

  fn covering_ceiling(&self, selector: &str, req: &Request) -> Option<Grant> {
    self
      .active_ceiling(selector)
      .into_iter()
      .find(|entry| covers(std::slice::from_ref(entry), req))
  }

  pub fn query_dynamic(
    &self,
    principal: &Principal,
    req: Option<&Request>,
  ) -> DynamicQueryState {
    if self.mode == Mode::Permissive {
      return DynamicQueryState::Granted;
    }
    if principal.is_ambient() {
      return DynamicQueryState::Ambient;
    }
    let Some(req) = req else {
      return DynamicQueryState::Denied;
    };
    let Some(selector) = principal.selector() else {
      return DynamicQueryState::Denied;
    };
    if self.grants(principal, req) {
      return DynamicQueryState::Granted;
    }
    if covers(&self.deny_ceiling, req) {
      return DynamicQueryState::Denied;
    }
    let Some(ceiling) = self.ceilings.get(&selector) else {
      return DynamicQueryState::Denied;
    };
    if ceiling.on_request == OnRequest::Deny {
      return DynamicQueryState::Denied;
    }
    if self.covering_ceiling(&selector, req).is_some() {
      DynamicQueryState::Prompt
    } else {
      DynamicQueryState::Denied
    }
  }

  pub fn evaluate_dynamic_request(
    &self,
    principal: &Principal,
    req: Option<&Request>,
  ) -> DynamicRequestEvaluation {
    if self.mode == Mode::Permissive {
      return DynamicRequestEvaluation::Terminal(granted(
        DynamicDecider::Existing,
        None,
        None,
      ));
    }
    if principal.is_ambient() {
      return DynamicRequestEvaluation::Ambient;
    }
    let Some(req) = req else {
      return DynamicRequestEvaluation::Terminal(denied(
        DynamicRequestCode::Ambiguous,
        None,
        false,
      ));
    };
    let Some(selector) = principal.selector() else {
      return DynamicRequestEvaluation::Terminal(denied(
        DynamicRequestCode::Unattributed,
        None,
        false,
      ));
    };
    if self.grants(principal, req) {
      return DynamicRequestEvaluation::Terminal(granted(
        DynamicDecider::Existing,
        None,
        None,
      ));
    }
    if covers(&self.deny_ceiling, req) {
      return DynamicRequestEvaluation::Terminal(self.memoized_denial(
        &selector,
        req,
        DynamicRequestCode::DenyCeiling,
        None,
      ));
    }
    let Some(config) = self.ceilings.get(&selector) else {
      return DynamicRequestEvaluation::Terminal(self.memoized_denial(
        &selector,
        req,
        DynamicRequestCode::AboveCeiling,
        None,
      ));
    };
    let Some(covering) = self.covering_ceiling(&selector, req) else {
      return DynamicRequestEvaluation::Terminal(self.memoized_denial(
        &selector,
        req,
        DynamicRequestCode::AboveCeiling,
        None,
      ));
    };
    if config.on_request == OnRequest::Deny {
      return DynamicRequestEvaluation::Terminal(self.memoized_denial(
        &selector,
        req,
        DynamicRequestCode::AboveCeiling,
        Some(covering),
      ));
    }
    let key = RequestKey::new(&selector, req);
    if let Some(code) = self.session.lock().unwrap().memo.get(&key).copied() {
      return DynamicRequestEvaluation::Terminal(denied(
        code,
        Some(covering),
        true,
      ));
    }
    if config.on_request == OnRequest::Auto {
      let grant = self.session.lock().unwrap().append(&selector, req, true);
      return DynamicRequestEvaluation::Terminal(granted(
        DynamicDecider::Policy,
        Some(grant),
        Some(covering),
      ));
    }
    DynamicRequestEvaluation::NeedsDecision { ceiling: covering }
  }

  pub fn complete_dynamic_request(
    &self,
    principal: &Principal,
    req: &Request,
    ceiling: Grant,
    decider: DynamicDecider,
    allowed: bool,
  ) -> DynamicRequestResult {
    let Some(selector) = principal.selector() else {
      return denied(DynamicRequestCode::Unattributed, Some(ceiling), false);
    };
    if allowed {
      let grant = self.session.lock().unwrap().append(&selector, req, true);
      granted(decider, Some(grant), Some(ceiling))
    } else {
      self.memoized_denial(
        &selector,
        req,
        DynamicRequestCode::Refused,
        Some(ceiling),
      )
    }
  }

  pub fn unanswered_dynamic_request(
    &self,
    principal: &Principal,
    req: &Request,
    ceiling: Grant,
  ) -> DynamicRequestResult {
    let Some(selector) = principal.selector() else {
      return denied(DynamicRequestCode::Unattributed, Some(ceiling), false);
    };
    self.memoized_denial(
      &selector,
      req,
      DynamicRequestCode::Unanswered,
      Some(ceiling),
    )
  }

  pub fn revoke_dynamic(
    &self,
    principal: &Principal,
    req: &Request,
  ) -> DynamicQueryState {
    if self.mode == Mode::Permissive {
      return DynamicQueryState::Granted;
    }
    if principal.is_ambient() {
      return DynamicQueryState::Ambient;
    }
    let Some(selector) = principal.selector() else {
      return DynamicQueryState::Denied;
    };
    self.session.lock().unwrap().append(&selector, req, false);
    DynamicQueryState::Denied
  }

  fn memoized_denial(
    &self,
    selector: &str,
    req: &Request,
    code: DynamicRequestCode,
    ceiling: Option<Grant>,
  ) -> DynamicRequestResult {
    let key = RequestKey::new(selector, req);
    let mut session = self.session.lock().unwrap();
    let memoized = session.memo.contains_key(&key);
    session.memo.entry(key).or_insert(code);
    denied(code, ceiling, memoized)
  }
}

fn granted(
  decider: DynamicDecider,
  session_grant: Option<Grant>,
  ceiling: Option<Grant>,
) -> DynamicRequestResult {
  DynamicRequestResult {
    state: DynamicPermissionState::Granted,
    code: DynamicRequestCode::Granted,
    decider: Some(decider),
    session_grant,
    ceiling,
    memoized: false,
  }
}

fn denied(
  code: DynamicRequestCode,
  ceiling: Option<Grant>,
  memoized: bool,
) -> DynamicRequestResult {
  DynamicRequestResult {
    state: DynamicPermissionState::Denied,
    code,
    decider: None,
    session_grant: None,
    ceiling,
    memoized,
  }
}

#[cfg(test)]
mod tests {
  use super::super::oden_policy::Family;
  use super::*;

  fn dep(name: &str) -> Principal {
    Principal::Package {
      name: name.into(),
      version: None,
    }
  }

  fn env(name: &str) -> Request {
    Request {
      family: Family::Env,
      action: "read".into(),
      target: name.into(),
    }
  }

  #[test]
  fn every_state_machine_row_is_bounded_and_memoized() {
    let mut p = Policy::new(Mode::Enforce);
    p.grant("dep", "env:read:FLOOR");
    p.ceiling(
      "dep",
      "env:read:FLOOR,env:read:OK,env:read:NEVER",
      OnRequest::Prompt,
    );
    p.deny_ceiling("env:read:NEVER");
    assert!(p.validate_envelopes().iter().any(|issue| matches!(
      issue,
      PolicyValidationIssue::CeilingConflicted { .. }
    )));
    assert_eq!(
      p.query_dynamic(&dep("dep"), Some(&env("FLOOR"))),
      DynamicQueryState::Granted
    );
    assert_eq!(
      p.query_dynamic(&dep("dep"), Some(&env("OK"))),
      DynamicQueryState::Prompt
    );
    assert_eq!(
      p.query_dynamic(&dep("dep"), Some(&env("OTHER"))),
      DynamicQueryState::Denied
    );
    assert!(matches!(
      p.evaluate_dynamic_request(&dep("dep"), Some(&env("NEVER"))),
      DynamicRequestEvaluation::Terminal(DynamicRequestResult {
        code: DynamicRequestCode::DenyCeiling,
        ..
      })
    ));
    assert!(matches!(
      p.evaluate_dynamic_request(&dep("dep"), Some(&env("OTHER"))),
      DynamicRequestEvaluation::Terminal(DynamicRequestResult {
        code: DynamicRequestCode::AboveCeiling,
        ..
      })
    ));
    assert!(matches!(
      p.evaluate_dynamic_request(&Principal::Quarantine, Some(&env("OK"))),
      DynamicRequestEvaluation::Terminal(DynamicRequestResult {
        code: DynamicRequestCode::Unattributed,
        ..
      })
    ));
    assert!(matches!(
      p.evaluate_dynamic_request(&dep("dep"), None),
      DynamicRequestEvaluation::Terminal(DynamicRequestResult {
        code: DynamicRequestCode::Ambiguous,
        ..
      })
    ));
    let DynamicRequestEvaluation::NeedsDecision { ceiling } =
      p.evaluate_dynamic_request(&dep("dep"), Some(&env("OK")))
    else {
      panic!("needs decider")
    };
    let first = p.unanswered_dynamic_request(&dep("dep"), &env("OK"), ceiling);
    assert_eq!(first.code, DynamicRequestCode::Unanswered);
    assert!(matches!(
      p.evaluate_dynamic_request(&dep("dep"), Some(&env("OK"))),
      DynamicRequestEvaluation::Terminal(DynamicRequestResult {
        code: DynamicRequestCode::Unanswered,
        memoized: true,
        ..
      })
    ));
  }

  #[test]
  fn auto_is_exact_and_does_not_transfer() {
    let mut p = Policy::new(Mode::Enforce);
    p.ceiling("dep", "env:read:*", OnRequest::Auto);
    assert!(matches!(
      p.evaluate_dynamic_request(&dep("dep"), Some(&env("ONE"))),
      DynamicRequestEvaluation::Terminal(DynamicRequestResult {
        state: DynamicPermissionState::Granted,
        decider: Some(DynamicDecider::Policy),
        ..
      })
    ));
    assert!(p.grants(&dep("dep"), &env("ONE")));
    assert!(!p.grants(&dep("dep"), &env("TWO")));
    assert!(!p.grants(&dep("other"), &env("ONE")));
    assert_eq!(
      p.decide_set(&[dep("dep"), dep("other")], &env("ONE")),
      super::super::oden_policy::Decision::Deny,
      "a session grant cannot be laundered through a second principal"
    );
    assert_eq!(
      p.revoke_dynamic(&dep("dep"), &env("ONE")),
      DynamicQueryState::Denied
    );
    assert!(!p.grants(&dep("dep"), &env("ONE")));
  }

  #[test]
  fn ambient_existing_deny_disposition_and_refusal_rows_are_terminal() {
    let mut p = Policy::new(Mode::Enforce);
    p.grant("dep", "env:read:FLOOR");
    p.ceiling("dep", "env:read:FLOOR,env:read:PROMPT", OnRequest::Prompt);
    assert_eq!(
      p.evaluate_dynamic_request(&Principal::Root, Some(&env("PROMPT"))),
      DynamicRequestEvaluation::Ambient
    );
    assert!(matches!(
      p.evaluate_dynamic_request(&dep("dep"), Some(&env("FLOOR"))),
      DynamicRequestEvaluation::Terminal(DynamicRequestResult {
        state: DynamicPermissionState::Granted,
        decider: Some(DynamicDecider::Existing),
        session_grant: None,
        ..
      })
    ));
    let DynamicRequestEvaluation::NeedsDecision { ceiling } =
      p.evaluate_dynamic_request(&dep("dep"), Some(&env("PROMPT")))
    else {
      panic!("within-ceiling prompt request should need a decider")
    };
    let refused = p.complete_dynamic_request(
      &dep("dep"),
      &env("PROMPT"),
      ceiling,
      DynamicDecider::Interactive,
      false,
    );
    assert_eq!(refused.code, DynamicRequestCode::Refused);
    assert!(matches!(
      p.evaluate_dynamic_request(&dep("dep"), Some(&env("PROMPT"))),
      DynamicRequestEvaluation::Terminal(DynamicRequestResult {
        code: DynamicRequestCode::Refused,
        memoized: true,
        ..
      })
    ));

    let mut deny = Policy::new(Mode::Enforce);
    deny.ceiling("dep", "env:read:DOCUMENTED", OnRequest::Deny);
    assert!(matches!(
      deny.evaluate_dynamic_request(&dep("dep"), Some(&env("DOCUMENTED"))),
      DynamicRequestEvaluation::Terminal(DynamicRequestResult {
        code: DynamicRequestCode::AboveCeiling,
        ..
      })
    ));
  }
}

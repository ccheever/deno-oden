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
  Capacity,
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
      Self::Capacity => "OD-CAP-REQ-CAPACITY",
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
  sequence: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct DescriptorKey {
  family: super::oden_policy::Family,
  action: String,
  target: String,
}

impl DescriptorKey {
  fn new(req: &Request) -> Option<Self> {
    if req.action.len().saturating_add(req.target.len())
      > MAX_DYNAMIC_DESCRIPTOR_BYTES
    {
      return None;
    }
    Some(Self {
      family: req.family,
      action: req.action.clone(),
      target: req.target.clone(),
    })
  }
}

const MAX_DYNAMIC_DESCRIPTOR_BYTES: usize = 4096;
const MAX_SESSION_PRINCIPALS: usize = 256;
const MAX_OVERLAY_ENTRIES_PER_PRINCIPAL: usize = 128;
const MAX_MEMO_ENTRIES_PER_PRINCIPAL: usize = 128;
const MAX_OVERLAY_ENTRIES_PER_PROCESS: usize = 4096;
const MAX_MEMO_ENTRIES_PER_PROCESS: usize = 4096;

#[derive(Debug, Default)]
struct PrincipalOverlay {
  entries: HashMap<DescriptorKey, OverlayEntry>,
  memo: HashMap<DescriptorKey, DynamicRequestCode>,
  requests_blocked: bool,
  deny_all_effective: bool,
}

#[derive(Debug, Default)]
pub(super) struct SessionOverlay {
  principals: HashMap<String, PrincipalOverlay>,
  entry_count: usize,
  memo_count: usize,
  next_sequence: u64,
  process_requests_blocked: bool,
  deny_all_effective: bool,
}

impl SessionOverlay {
  pub(super) fn effective(
    &self,
    selector: &str,
    req: &Request,
    floor: bool,
  ) -> bool {
    self.effective_with_scan_count(selector, req, floor).0
  }

  fn effective_with_scan_count(
    &self,
    selector: &str,
    req: &Request,
    floor: bool,
  ) -> (bool, usize) {
    if self.deny_all_effective {
      return (false, 0);
    }
    let Some(principal) = self.principals.get(selector) else {
      return (floor, 0);
    };
    if principal.deny_all_effective {
      return (false, 0);
    }
    let Some(exact) = DescriptorKey::new(req) else {
      return (floor, 0);
    };

    // @ref llp/0015-dynamic-permissions-with-ceiling.plan.md (Bounded live overlay)
    let mut newest = principal.entries.get(&exact);
    let mut scanned = 0;
    for (key, entry) in &principal.entries {
      if key == &exact {
        continue;
      }
      scanned += 1;
      if covers(std::slice::from_ref(&entry.grant), req)
        && newest.is_none_or(|current| entry.sequence > current.sequence)
      {
        newest = Some(entry);
      }
    }
    (newest.map_or(floor, |entry| entry.allow), scanned)
  }

  fn prior_denial_or_blocked(
    &self,
    selector: &str,
    req: &Request,
  ) -> Result<Option<DynamicRequestCode>, ()> {
    let key = DescriptorKey::new(req).ok_or(())?;
    if let Some(principal) = self.principals.get(selector) {
      if let Some(code) = principal.memo.get(&key) {
        return Ok(Some(*code));
      }
      if principal.requests_blocked {
        return Err(());
      }
    }
    if self.process_requests_blocked {
      return Err(());
    }
    Ok(None)
  }

  fn append_allow(&mut self, selector: &str, req: &Request) -> Option<Grant> {
    if self.process_requests_blocked {
      return None;
    }
    let key = DescriptorKey::new(req)?;
    if self
      .principals
      .get(selector)
      .is_some_and(|principal| principal.requests_blocked)
    {
      return None;
    }
    if !self.ensure_principal(selector) {
      return None;
    }
    let replacing = self
      .principals
      .get(selector)
      .expect("principal exists")
      .entries
      .contains_key(&key);
    if !replacing {
      self.make_entry_room(selector, true)?;
    }
    let sequence = self.take_sequence()?;
    let grant = Grant::from_request(req);
    let principal =
      self.principals.get_mut(selector).expect("principal exists");
    let is_new = principal
      .entries
      .insert(
        key.clone(),
        OverlayEntry {
          grant: grant.clone(),
          allow: true,
          sequence,
        },
      )
      .is_none();
    if is_new {
      self.entry_count += 1;
    }
    if principal.memo.remove(&key).is_some() {
      self.memo_count -= 1;
    }
    Some(grant)
  }

  fn revoke(&mut self, selector: &str, req: &Request) {
    let Some(key) = DescriptorKey::new(req) else {
      self.deny_all_effective = true;
      self.process_requests_blocked = true;
      return;
    };
    if !self.ensure_principal(selector) {
      self.deny_all_effective = true;
      return;
    }
    if self.deny_all_effective
      || self
        .principals
        .get(selector)
        .is_some_and(|principal| principal.deny_all_effective)
    {
      return;
    }
    let replacing = self
      .principals
      .get(selector)
      .expect("principal exists")
      .entries
      .contains_key(&key);
    if !replacing && self.make_entry_room(selector, false).is_none() {
      return;
    }
    let Some(sequence) = self.take_sequence() else {
      self.deny_all_effective = true;
      return;
    };
    let grant = Grant::from_request(req);
    let principal =
      self.principals.get_mut(selector).expect("principal exists");
    let is_new = principal
      .entries
      .insert(
        key,
        OverlayEntry {
          grant,
          allow: false,
          sequence,
        },
      )
      .is_none();
    if is_new {
      self.entry_count += 1;
    }
  }

  fn record_denial(
    &mut self,
    selector: &str,
    req: &Request,
    code: DynamicRequestCode,
  ) -> bool {
    let Some(key) = DescriptorKey::new(req) else {
      return false;
    };
    if let Some(principal) = self.principals.get(selector) {
      if principal.memo.contains_key(&key) {
        return true;
      }
      if principal.requests_blocked {
        return false;
      }
    }
    if self.process_requests_blocked || !self.ensure_principal(selector) {
      return false;
    }

    let principal_memo_full =
      self.principals.get(selector).is_some_and(|principal| {
        principal.memo.len() >= MAX_MEMO_ENTRIES_PER_PRINCIPAL
      });
    if principal_memo_full {
      let principal =
        self.principals.get_mut(selector).expect("principal exists");
      self.memo_count -= principal.memo.len();
      principal.memo.clear();
      principal.requests_blocked = true;
      return false;
    }
    if self.memo_count >= MAX_MEMO_ENTRIES_PER_PROCESS {
      for principal in self.principals.values_mut() {
        principal.memo.clear();
      }
      self.memo_count = 0;
      self.process_requests_blocked = true;
      return false;
    }
    self
      .principals
      .get_mut(selector)
      .expect("principal exists")
      .memo
      .insert(key, code);
    self.memo_count += 1;
    false
  }

  fn ensure_principal(&mut self, selector: &str) -> bool {
    if self.principals.contains_key(selector) {
      return true;
    }
    if selector.len() > MAX_DYNAMIC_DESCRIPTOR_BYTES
      || self.principals.len() >= MAX_SESSION_PRINCIPALS
    {
      self.process_requests_blocked = true;
      return false;
    }
    self
      .principals
      .insert(selector.to_string(), PrincipalOverlay::default());
    true
  }

  fn make_entry_room(&mut self, selector: &str, allow: bool) -> Option<()> {
    let existing = self.principals.get(selector).expect("principal exists");
    if existing.deny_all_effective {
      return if allow { None } else { Some(()) };
    }
    if existing.entries.len() >= MAX_OVERLAY_ENTRIES_PER_PRINCIPAL
      && !self.evict_oldest_allow(Some(selector))
    {
      let principal =
        self.principals.get_mut(selector).expect("principal exists");
      if allow {
        principal.requests_blocked = true;
      } else {
        self.entry_count -= principal.entries.len();
        principal.entries.clear();
        principal.deny_all_effective = true;
        principal.requests_blocked = true;
      }
      return None;
    }
    if self.entry_count >= MAX_OVERLAY_ENTRIES_PER_PROCESS
      && !self.evict_oldest_allow(None)
    {
      self.process_requests_blocked = true;
      if !allow {
        self.deny_all_effective = true;
        self.entry_count = 0;
        for principal in self.principals.values_mut() {
          principal.entries.clear();
        }
      }
      return None;
    }
    Some(())
  }

  fn evict_oldest_allow(&mut self, selector: Option<&str>) -> bool {
    let mut candidate: Option<(String, DescriptorKey, u64)> = None;
    for (candidate_selector, principal) in &self.principals {
      if selector.is_some_and(|wanted| wanted != candidate_selector) {
        continue;
      }
      for (key, entry) in &principal.entries {
        if entry.allow
          && candidate
            .as_ref()
            .is_none_or(|(_, _, oldest)| entry.sequence < *oldest)
        {
          candidate =
            Some((candidate_selector.clone(), key.clone(), entry.sequence));
        }
      }
    }
    let Some((selector, key, _)) = candidate else {
      return false;
    };
    self
      .principals
      .get_mut(&selector)
      .expect("candidate principal exists")
      .entries
      .remove(&key);
    self.entry_count -= 1;
    true
  }

  fn take_sequence(&mut self) -> Option<u64> {
    let sequence = self.next_sequence;
    let Some(next) = self.next_sequence.checked_add(1) else {
      self.process_requests_blocked = true;
      return None;
    };
    self.next_sequence = next;
    Some(sequence)
  }
}

impl Policy {
  pub fn ceiling(
    &mut self,
    selector: &str,
    authority: &str,
    on_request: OnRequest,
  ) {
    let parsed = Grant::parse_many(authority)
      .expect("dynamic authority is validated before policy construction");
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
    self
      .deny_ceiling
      .extend(Grant::parse_many(authority).expect(
        "dynamic deny ceiling is validated before policy construction",
      ));
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

  fn deny_ceiling_intersects(&self, req: &Request) -> bool {
    let requested = Grant::from_request(req);
    self
      .deny_ceiling
      .iter()
      .any(|deny| grants_intersect(&requested, deny))
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
    if self.deny_ceiling_intersects(req) {
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
    if self.deny_ceiling_intersects(req) {
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
    match self
      .session
      .read()
      .unwrap()
      .prior_denial_or_blocked(&selector, req)
    {
      Ok(Some(code)) => {
        return DynamicRequestEvaluation::Terminal(denied(
          code,
          Some(covering),
          true,
        ));
      }
      Err(()) => {
        return DynamicRequestEvaluation::Terminal(denied(
          DynamicRequestCode::Capacity,
          Some(covering),
          false,
        ));
      }
      Ok(None) => {}
    }
    if config.on_request == OnRequest::Auto {
      let Some(grant) =
        self.session.write().unwrap().append_allow(&selector, req)
      else {
        return DynamicRequestEvaluation::Terminal(denied(
          DynamicRequestCode::Capacity,
          Some(covering),
          false,
        ));
      };
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
      let Some(grant) =
        self.session.write().unwrap().append_allow(&selector, req)
      else {
        return denied(DynamicRequestCode::Capacity, Some(ceiling), false);
      };
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
    self.session.write().unwrap().revoke(&selector, req);
    DynamicQueryState::Denied
  }

  fn memoized_denial(
    &self,
    selector: &str,
    req: &Request,
    code: DynamicRequestCode,
    ceiling: Option<Grant>,
  ) -> DynamicRequestResult {
    let memoized = self
      .session
      .write()
      .unwrap()
      .record_denial(selector, req, code);
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
    p.grant("dep", "env:read:FLOOR").unwrap();
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

    let mut broad = Policy::new(Mode::Enforce);
    broad.ceiling("dep", "env:*:*", OnRequest::Auto);
    broad.deny_ceiling("env:read:NEVER");
    let all_env = Request {
      family: Family::Env,
      action: "*".into(),
      target: "*".into(),
    };
    assert_eq!(
      broad.query_dynamic(&dep("dep"), Some(&all_env)),
      DynamicQueryState::Denied,
      "a broad descriptor intersects a narrow deny-ceiling entry"
    );
    assert!(matches!(
      broad.evaluate_dynamic_request(&dep("dep"), Some(&all_env)),
      DynamicRequestEvaluation::Terminal(DynamicRequestResult {
        code: DynamicRequestCode::DenyCeiling,
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
    p.grant("dep", "env:read:FLOOR").unwrap();
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

  #[test]
  fn exact_outcomes_compact_and_covering_scans_have_a_constant_ceiling() {
    let mut p = Policy::new(Mode::Enforce);
    p.ceiling("dep", "env:read:*", OnRequest::Auto);

    for _ in 0..10_000 {
      assert!(matches!(
        p.evaluate_dynamic_request(&dep("dep"), Some(&env("SAME"))),
        DynamicRequestEvaluation::Terminal(DynamicRequestResult {
          state: DynamicPermissionState::Granted,
          ..
        })
      ));
      p.revoke_dynamic(&dep("dep"), &env("SAME"));
    }
    let session = p.session.read().unwrap();
    assert_eq!(
      session.entry_count, 1,
      "last writer replaces one descriptor"
    );
    drop(session);

    for index in 0..10_000 {
      let request = env(&format!("UNIQUE_{index}"));
      assert!(matches!(
        p.evaluate_dynamic_request(&dep("dep"), Some(&request)),
        DynamicRequestEvaluation::Terminal(DynamicRequestResult {
          state: DynamicPermissionState::Granted,
          ..
        })
      ));
    }
    let session = p.session.read().unwrap();
    let principal = session.principals.get("dep").unwrap();
    assert_eq!(principal.entries.len(), MAX_OVERLAY_ENTRIES_PER_PRINCIPAL);
    assert!(session.entry_count <= MAX_OVERLAY_ENTRIES_PER_PROCESS);
    let (_, scanned) =
      session.effective_with_scan_count("dep", &env("MISSING"), false);
    assert!(
      scanned <= MAX_OVERLAY_ENTRIES_PER_PRINCIPAL,
      "hot-path work is independent of the 10,000 adversarial mutations"
    );
    drop(session);
    assert_eq!(
      p.query_dynamic(&dep("dep"), Some(&env("UNIQUE_0"))),
      DynamicQueryState::Prompt,
      "evicting an allow narrows authority and returns to requestable state"
    );
  }

  #[test]
  fn denial_overflow_collapses_to_a_fail_closed_request_circuit_breaker() {
    let mut p = Policy::new(Mode::Enforce);
    p.ceiling("dep", "env:read:*", OnRequest::Prompt);
    for index in 0..=MAX_MEMO_ENTRIES_PER_PRINCIPAL {
      let request = env(&format!("DENIED_{index}"));
      let DynamicRequestEvaluation::NeedsDecision { ceiling } =
        p.evaluate_dynamic_request(&dep("dep"), Some(&request))
      else {
        panic!(
          "request should remain promptable until the memo quota is crossed"
        )
      };
      assert_eq!(
        p.unanswered_dynamic_request(&dep("dep"), &request, ceiling)
          .state,
        DynamicPermissionState::Denied
      );
    }
    let session = p.session.read().unwrap();
    let principal = session.principals.get("dep").unwrap();
    assert!(principal.requests_blocked);
    assert!(principal.memo.len() <= MAX_MEMO_ENTRIES_PER_PRINCIPAL);
    assert!(session.memo_count <= MAX_MEMO_ENTRIES_PER_PROCESS);
    drop(session);
    assert!(matches!(
      p.evaluate_dynamic_request(&dep("dep"), Some(&env("AFTER_OVERFLOW"))),
      DynamicRequestEvaluation::Terminal(DynamicRequestResult {
        code: DynamicRequestCode::Capacity,
        ..
      })
    ));
  }

  #[test]
  fn revoke_overflow_never_restores_static_floor_authority() {
    let mut p = Policy::new(Mode::Enforce);
    p.grant("dep", "env:read:*").unwrap();
    for index in 0..=MAX_OVERLAY_ENTRIES_PER_PRINCIPAL {
      p.revoke_dynamic(&dep("dep"), &env(&format!("REVOKED_{index}")));
    }
    let session = p.session.read().unwrap();
    assert!(session.principals.get("dep").unwrap().deny_all_effective);
    assert!(session.entry_count <= MAX_OVERLAY_ENTRIES_PER_PROCESS);
    drop(session);
    assert!(
      !p.grants(&dep("dep"), &env("FLOOR_TARGET")),
      "negative-state compaction must narrow, never restore the static floor"
    );
  }

  #[test]
  fn bounded_overlay_supports_concurrent_workers_and_principals() {
    const WORKERS: usize = 8;
    let mut p = Policy::new(Mode::Enforce);
    for worker in 0..WORKERS {
      p.ceiling(&format!("worker-{worker}"), "env:read:*", OnRequest::Auto);
    }
    let p = std::sync::Arc::new(p);
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(WORKERS));
    let handles = (0..WORKERS)
      .map(|worker| {
        let p = p.clone();
        let barrier = barrier.clone();
        std::thread::spawn(move || {
          let principal = dep(&format!("worker-{worker}"));
          barrier.wait();
          for index in 0..1_000 {
            let request = env(&format!("W{worker}_{index}"));
            assert!(matches!(
              p.evaluate_dynamic_request(&principal, Some(&request)),
              DynamicRequestEvaluation::Terminal(DynamicRequestResult {
                state: DynamicPermissionState::Granted,
                ..
              })
            ));
            assert!(p.grants(&principal, &request));
          }
        })
      })
      .collect::<Vec<_>>();
    for handle in handles {
      handle.join().unwrap();
    }
    let session = p.session.read().unwrap();
    assert_eq!(session.principals.len(), WORKERS);
    assert!(session.entry_count <= WORKERS * MAX_OVERLAY_ENTRIES_PER_PRINCIPAL);
    assert!(session.entry_count <= MAX_OVERLAY_ENTRIES_PER_PROCESS);
  }

  #[test]
  fn process_principal_quota_blocks_new_dynamic_authority() {
    let mut p = Policy::new(Mode::Enforce);
    for index in 0..=MAX_SESSION_PRINCIPALS {
      let selector = format!("principal-{index}");
      p.ceiling(&selector, "env:read:*", OnRequest::Auto);
      let result =
        p.evaluate_dynamic_request(&dep(&selector), Some(&env("FIRST")));
      if index < MAX_SESSION_PRINCIPALS {
        assert!(matches!(
          result,
          DynamicRequestEvaluation::Terminal(DynamicRequestResult {
            state: DynamicPermissionState::Granted,
            ..
          })
        ));
      } else {
        assert!(matches!(
          result,
          DynamicRequestEvaluation::Terminal(DynamicRequestResult {
            code: DynamicRequestCode::Capacity,
            ..
          })
        ));
      }
    }
    let session = p.session.read().unwrap();
    assert_eq!(session.principals.len(), MAX_SESSION_PRINCIPALS);
    assert!(session.process_requests_blocked);
    drop(session);
    assert!(p.grants(&dep("principal-0"), &env("FIRST")));
    assert!(matches!(
      p.evaluate_dynamic_request(&dep("principal-0"), Some(&env("SECOND"))),
      DynamicRequestEvaluation::Terminal(DynamicRequestResult {
        code: DynamicRequestCode::Capacity,
        ..
      })
    ));
  }
}

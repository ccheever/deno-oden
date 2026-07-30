// Copyright 2018-2026 the Deno authors. MIT license.

//! Sealed debug-only fixture harness for the protected inspector-stream op.
//!
//! The harness constructs and MAC-verifies a generated-target Candidate
//! snapshot with a fixture-local key, then requires `VerifiedUnarmed` before
//! projecting policy into a local authority context. That local MAC is not
//! externally authenticated evidence. The harness has no JavaScript
//! constructor, never publishes process-wide C04, and is absent from ordinary
//! production builds.
//!
//! @ref LLP 0019#pre-promotion-conformance-candidate-execution
//! [constrained-by] -- Fixture execution consumes only unauthoritative
//! Candidate state and cannot advertise, arm, admit, or release a target.
//! @ref LLP 0019#operation-scoped-positive-authority-provenance [implements]
//! -- The fixture captures principals and the effect owner in Rust, then binds
//! the exact native stage before the public op reaches a delivery boundary.

use std::cell::RefCell;
use std::sync::Arc;

use serde_json::Value;
use serde_json::json;

use crate::OdenRev2ArmedContext;
use crate::OdenRev2HostActor;
use crate::OdenRev2HostError;
use crate::OdenRev2HostInteraction;
use crate::OdenRev2RuntimeAuthorityContext;
use crate::oden_rev2_authority::AuthorityRowKind;
use crate::oden_rev2_context::OdenRev2ExecutionRole;
use crate::oden_rev2_context::OdenRev2OperationAuthorityFacts;
use crate::oden_rev2_policy::OdenRev2LoadState;
use crate::oden_rev2_policy::fixture_support;
use crate::rev2::AuthoritySelectorInput;
use crate::rev2::CanonicalAuthoritySelector;
use crate::rev2::EngineIdentity;
use crate::rev2::PrincipalKind;
use crate::rev2::PrincipalRef;
use crate::rev2::Rev2Core;
use crate::rev2::SelectorPolarity;
use crate::rev2::canonical_json;
use crate::rev2::domain_digest;
use crate::rev2_registry_generated::REV2_ADVERTISED_TARGETS;
use crate::rev2_registry_generated::REV2_VOCAB_DIGEST;

const ACTOR_KEY: &str =
  "pkg:sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const OTHER_KEY: &str =
  "pkg:sha256-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA";
const TRANSPARENT_RUNTIME_KEY: &str =
  "runtime:protected-inspector-stream-fixture";
const TARGET: &str = "127.0.0.1:9229";
const EFFECT_OWNER_ID: &str = "owner:protected-inspector-stream-fixture";
const OPERATION_ID: &str = "operation:protected-inspector-stream-fixture";
const ACTOR_ID: &str = "actor:protected-inspector-stream-fixture";
const INSPECTOR_CAPABILITY: &str = "inspector:activate";
const TERMINAL_EVIDENCE_ID: &str =
  "terminal:protected-inspector-stream-fixture";

const API_NAMES: [&str; 3] = [
  "Deno.Conn readable stream",
  "fetch response body reader",
  "node:net.Socket native read delivery",
];

const CASE_KINDS: [&str; 16] = [
  "authorable-cross-action-denial",
  "authorable-missing-principal-denial",
  "authorable-negative",
  "authorable-no-user-denial",
  "authorable-positive",
  "authorable-quarantine-denial",
  "authorable-wrong-principal-denial",
  "malformed-resource-refusal",
  "predicate-vector:rev2.predicate.exact-static-missing",
  "predicate-vector:rev2.predicate.exact-static-present",
  "staged-barrier:authorization",
  "staged-barrier:cancellation",
  "staged-barrier:cleanup",
  "staged-barrier:commit",
  "staged-barrier:discovery",
  "staged-barrier:revocation",
];

thread_local! {
  static TRACE: RefCell<Vec<String>> = const { RefCell::new(Vec::new()) };
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AuthorityPlan {
  CrossAction,
  ExactFloor,
  ExactFloorAndDenial,
  MissingPrincipal,
  NoUser,
  Quarantine,
  WrongPrincipal,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OdenRev2ProtectedStreamObservation {
  pub negative_overlay_rows: usize,
  pub revocation_rows: usize,
  pub session_positive_rows: usize,
  pub session_revocation_rows: usize,
}

pub struct OdenRev2ProtectedStreamFixture {
  authority: Arc<OdenRev2RuntimeAuthorityContext>,
  case_kind: &'static str,
  api_name: &'static str,
  principals: Vec<PrincipalRef>,
  effect_owner: PrincipalRef,
  quota_owner: PrincipalRef,
  verified_unarmed: bool,
  candidate_blockers: Vec<String>,
}

fn principal(kind: PrincipalKind, key: &str) -> PrincipalRef {
  PrincipalRef {
    kind,
    key: key.to_string(),
  }
}

fn actor() -> PrincipalRef {
  principal(PrincipalKind::Package, ACTOR_KEY)
}

fn other() -> PrincipalRef {
  principal(PrincipalKind::Package, OTHER_KEY)
}

fn plan(case_kind: &str) -> AuthorityPlan {
  match case_kind {
    "authorable-cross-action-denial"
    | "predicate-vector:rev2.predicate.exact-static-missing" => {
      AuthorityPlan::CrossAction
    }
    "authorable-missing-principal-denial" => AuthorityPlan::MissingPrincipal,
    "authorable-no-user-denial" => AuthorityPlan::NoUser,
    "authorable-quarantine-denial" => AuthorityPlan::Quarantine,
    "authorable-wrong-principal-denial" => AuthorityPlan::WrongPrincipal,
    "authorable-negative" | "staged-barrier:authorization" => {
      AuthorityPlan::ExactFloorAndDenial
    }
    _ => AuthorityPlan::ExactFloor,
  }
}

fn normalized_selector(
  principal: Option<PrincipalRef>,
  capability: &str,
  resource: Value,
  polarity: SelectorPolarity,
) -> CanonicalAuthoritySelector {
  Rev2Core::embedded()
    .expect("fixture uses the embedded generated core")
    .normalize_selector(
      &AuthoritySelectorInput {
        identity: EngineIdentity::embedded(),
        principal,
        capability: capability.to_string(),
        resource,
      },
      polarity,
    )
    .expect("sealed fixture selector is generated-vocabulary valid")
}

fn inspector_resource() -> Value {
  json!({
    "route": {
      "attestation": null,
      "endpoint": null,
      "kind": "direct",
    },
    "session": {
      "kind": "inspector",
      "value": TARGET,
    },
  })
}

fn row(source_id: &str, selector: CanonicalAuthoritySelector) -> Value {
  json!({
    "sourceId": source_id,
    "selector": selector,
  })
}

fn policy_principal(
  principal: &PrincipalRef,
  mut floor: Vec<Value>,
  mut denials: Vec<Value>,
) -> Value {
  floor.sort_by_key(|value| canonical_json(value).unwrap());
  denials.sort_by_key(|value| canonical_json(value).unwrap());
  json!({
    "principal": principal,
    "binding": {
      "resolverId": "fixture-lock-resolver/2",
      "bindingDigest": REV2_VOCAB_DIGEST,
    },
    "floor": floor,
    "escalationCeiling": [],
    "denials": denials,
  })
}

fn static_policy(case_kind: &str) -> Vec<Value> {
  let authority_plan = plan(case_kind);
  let (row_principal, include_principal) = match authority_plan {
    AuthorityPlan::NoUser
    | AuthorityPlan::Quarantine
    | AuthorityPlan::MissingPrincipal => (actor(), false),
    AuthorityPlan::WrongPrincipal => (other(), true),
    _ => (actor(), true),
  };
  if !include_principal {
    return Vec::new();
  }
  let floor = match authority_plan {
    AuthorityPlan::CrossAction => vec![row(
      "floor:protected-stream-fixture:cross-action",
      normalized_selector(
        Some(row_principal.clone()),
        "env:read",
        json!({ "name": "ODEN_PROTECTED_STREAM_CROSS_ACTION" }),
        SelectorPolarity::Positive,
      ),
    )],
    _ => vec![row(
      "floor:protected-stream-fixture:exact",
      normalized_selector(
        Some(row_principal.clone()),
        INSPECTOR_CAPABILITY,
        inspector_resource(),
        SelectorPolarity::Positive,
      ),
    )],
  };
  let denials = if authority_plan == AuthorityPlan::ExactFloorAndDenial {
    vec![row(
      "denial:protected-stream-fixture:exact",
      normalized_selector(
        Some(row_principal.clone()),
        INSPECTOR_CAPABILITY,
        inspector_resource(),
        SelectorPolarity::Negative,
      ),
    )]
  } else {
    Vec::new()
  };
  vec![policy_principal(&row_principal, floor, denials)]
}

fn route_bindings(principals: &[Value]) -> Vec<Value> {
  let mut bindings = Vec::new();
  for principal in principals {
    for field in ["floor", "denials"] {
      for row in principal[field]
        .as_array()
        .expect("sealed fixture policy row array")
      {
        let resource = &row["selector"]["resource"];
        let Some(route) = resource.get("route") else {
          continue;
        };
        let source_id =
          row["sourceId"].as_str().expect("sealed fixture source id");
        bindings.push(json!({
          "sourceId": source_id,
          "resourceDigest": domain_digest(
            "oden:capsec:route-resource:2",
            resource,
          ).expect("sealed fixture resource is canonical"),
          "routeDigest": domain_digest(
            "oden:capsec:route-selector:2",
            route,
          ).expect("sealed fixture route is canonical"),
          "routeId": format!("route:protected-stream-fixture:{source_id}"),
          "routeKind": "direct",
        }));
      }
    }
  }
  bindings.sort_by_key(|value| canonical_json(value).unwrap());
  bindings
}

fn captured_principals(case_kind: &str) -> Vec<PrincipalRef> {
  match plan(case_kind) {
    // The shared core normalizes an empty constrained set to explicit NoUser.
    // A transparent runtime owner can be retained without smuggling a
    // constrained principal into this case.
    AuthorityPlan::MissingPrincipal => Vec::new(),
    AuthorityPlan::NoUser => vec![principal(PrincipalKind::NoUser, "no-user")],
    AuthorityPlan::Quarantine => {
      vec![principal(PrincipalKind::Quarantine, "quarantine")]
    }
    _ => vec![actor()],
  }
}

fn project_policy(
  authority: &OdenRev2RuntimeAuthorityContext,
  quota_owner: PrincipalRef,
) -> Result<crate::rev2::DecisionPolicyInput, OdenRev2HostError> {
  let view = authority
    .authority_state()
    .read_view()
    .map_err(|_| OdenRev2HostError::InvalidNativeStage)?;
  authority
    .decision_policy_for_operation(
      &view,
      OdenRev2OperationAuthorityFacts::new(
        quota_owner,
        TERMINAL_EVIDENCE_ID.to_string(),
      ),
    )
    .map_err(|_| OdenRev2HostError::InvalidNativeStage)
}

impl OdenRev2ProtectedStreamFixture {
  pub fn new(case_kind: &str, mode: &str) -> Result<Self, String> {
    let case_index = CASE_KINDS
      .iter()
      .position(|candidate| *candidate == case_kind)
      .ok_or_else(|| "OD-CAP-REV2-PROTECTED-STREAM-FIXTURE-CASE".to_string())?;
    if !matches!(mode, "permissive" | "audit" | "enforce") {
      return Err("OD-CAP-REV2-PROTECTED-STREAM-FIXTURE-MODE".to_string());
    }
    if !REV2_ADVERTISED_TARGETS.is_empty() {
      return Err(
        "OD-CAP-REV2-PROTECTED-STREAM-FIXTURE-ADVERTISED".to_string(),
      );
    }
    let mut snapshot = fixture_support::unarmed_candidate_snapshot(mode);
    let principals = static_policy(case_kind);
    snapshot["routeBindings"] = Value::Array(route_bindings(&principals));
    snapshot["canonicalPolicy"]["principals"] = Value::Array(principals);
    fixture_support::refresh_digests(&mut snapshot);
    let loaded = fixture_support::load_unarmed_candidate_snapshot(
      snapshot,
      &[183_u8; 32],
    )?;
    let evidence = loaded.evidence();
    let verified_unarmed = loaded.state() == OdenRev2LoadState::VerifiedUnarmed
      && evidence["armable"] == false
      && evidence["armed"] == false
      && evidence["conformant"] == false
      && evidence["advertised"] == false
      && evidence["executionRole"] == "candidate"
      && evidence["conformanceReportDigest"].is_null();
    if !verified_unarmed {
      return Err("OD-CAP-REV2-PROTECTED-STREAM-FIXTURE-CANDIDATE".to_string());
    }
    let candidate_blockers = loaded.blockers().to_vec();
    let authority = Arc::new(
      OdenRev2RuntimeAuthorityContext::
        install_protected_stream_fixture_candidate(loaded)?,
    );
    if authority.execution_role() != OdenRev2ExecutionRole::Candidate {
      return Err("OD-CAP-REV2-PROTECTED-STREAM-FIXTURE-ROLE".to_string());
    }
    let principals = captured_principals(case_kind);
    let effect_owner = principals.first().cloned().unwrap_or_else(|| {
      principal(PrincipalKind::Runtime, TRANSPARENT_RUNTIME_KEY)
    });
    let quota_owner = principals.first().cloned().unwrap_or_else(|| {
      principal(PrincipalKind::NoUser, "no-user:missing-principal-quota")
    });
    crate::oden_rev2_set_permission_actors_for_test(Some((
      principals.clone(),
      effect_owner.clone(),
    )));
    Ok(Self {
      authority,
      case_kind: CASE_KINDS[case_index],
      api_name: API_NAMES[case_index % API_NAMES.len()],
      principals,
      effect_owner,
      quota_owner,
      verified_unarmed,
      candidate_blockers,
    })
  }

  pub fn case_kind(&self) -> &'static str {
    self.case_kind
  }

  pub fn target(&self) -> &'static str {
    TARGET
  }

  pub fn api_name(&self) -> &'static str {
    self.api_name
  }

  pub fn verified_unarmed(&self) -> bool {
    self.verified_unarmed
  }

  pub fn candidate_blockers(&self) -> &[String] {
    &self.candidate_blockers
  }

  pub fn fresh_context(
    &self,
  ) -> Result<OdenRev2ArmedContext, OdenRev2HostError> {
    let initial_policy =
      project_policy(&self.authority, self.quota_owner.clone())?;
    let actor = OdenRev2HostActor::capture_host(
      OPERATION_ID,
      ACTOR_ID,
      self.principals.clone(),
      EFFECT_OWNER_ID,
      self.effect_owner.clone(),
      "0",
      None,
      &initial_policy,
    )?;
    Ok(OdenRev2ArmedContext::capture_host(actor))
  }

  pub fn arm(
    &self,
    context: &mut OdenRev2ArmedContext,
    discovery: bool,
    sequence: u8,
  ) -> Result<(), OdenRev2HostError> {
    if sequence == 0 || sequence > 2 {
      return Err(OdenRev2HostError::InvalidNativeStage);
    }
    let authority = self.authority.clone();
    let quota_owner = self.quota_owner.clone();
    context.arm_protected_inspector_stream_stage(
      TARGET,
      self.api_name,
      format!("protected-stream-fixture:{}:{sequence}", self.case_kind),
      move || project_policy(&authority, quota_owner.clone()),
      discovery,
      OdenRev2HostInteraction::NonInteractive,
    )
  }

  pub fn arm_malformed(
    &self,
    context: &mut OdenRev2ArmedContext,
  ) -> Result<(), OdenRev2HostError> {
    let authority = self.authority.clone();
    let quota_owner = self.quota_owner.clone();
    let result = context.arm_protected_inspector_stream_stage(
      "not-a-socket-address",
      self.api_name,
      "protected-stream-fixture:malformed",
      move || project_policy(&authority, quota_owner.clone()),
      false,
      OdenRev2HostInteraction::NonInteractive,
    );
    if matches!(&result, Err(OdenRev2HostError::InvalidNativeStage)) {
      oden_capsec_rev2_protected_stream_fixture_record_event(
        "malformed-native-stage-refused",
      );
    }
    result
  }

  pub fn seed_exact_revocation(&self) -> Result<(), String> {
    let selector = normalized_selector(
      Some(self.principals[0].clone()),
      INSPECTOR_CAPABILITY,
      inspector_resource(),
      SelectorPolarity::Negative,
    );
    let mut transaction = self
      .authority
      .authority_state()
      .begin_transaction()
      .map_err(|_| {
        "OD-CAP-REV2-PROTECTED-STREAM-FIXTURE-TRANSACTION".to_string()
      })?;
    transaction
      .upsert_session_revocation(
        &self.effect_owner,
        &self.principals[0],
        &selector,
        None,
      )
      .map_err(|_| {
        "OD-CAP-REV2-PROTECTED-STREAM-FIXTURE-REVOCATION".to_string()
      })?;
    self
      .authority
      .authority_state()
      .commit_if(transaction, |_| Ok(()))
      .map(|_| ())
      .map_err(|_| "OD-CAP-REV2-PROTECTED-STREAM-FIXTURE-COMMIT".to_string())
  }

  pub fn observe(&self) -> Result<OdenRev2ProtectedStreamObservation, String> {
    let view = self.authority.authority_state().read_view().map_err(|_| {
      "OD-CAP-REV2-PROTECTED-STREAM-FIXTURE-OBSERVE".to_string()
    })?;
    let count = |kind| view.rows(kind).count();
    Ok(OdenRev2ProtectedStreamObservation {
      negative_overlay_rows: count(AuthorityRowKind::NegativeOverlay),
      revocation_rows: count(AuthorityRowKind::Revocation),
      session_positive_rows: count(AuthorityRowKind::SessionPositive),
      session_revocation_rows: count(AuthorityRowKind::SessionRevocation),
    })
  }
}

impl Drop for OdenRev2ProtectedStreamFixture {
  fn drop(&mut self) {
    crate::oden_rev2_set_permission_actors_for_test(None);
  }
}

pub fn oden_capsec_rev2_protected_stream_fixture_case_kinds()
-> &'static [&'static str] {
  &CASE_KINDS
}

pub fn oden_capsec_rev2_protected_stream_fixture_compiled_target()
-> &'static str {
  fixture_support::target()
}

pub fn oden_capsec_rev2_protected_stream_fixture_compiled_feature_set()
-> &'static str {
  fixture_support::feature_set()
}

pub fn oden_capsec_rev2_protected_stream_fixture_compiled_vocab_digest()
-> &'static str {
  REV2_VOCAB_DIGEST
}

pub fn oden_capsec_rev2_protected_stream_fixture_record_event(event: &str) {
  TRACE.with(|trace| trace.borrow_mut().push(event.to_string()));
}

pub fn oden_capsec_rev2_protected_stream_fixture_reset_trace() {
  TRACE.with(|trace| trace.borrow_mut().clear());
}

pub fn oden_capsec_rev2_protected_stream_fixture_take_trace() -> Vec<String> {
  TRACE.with(|trace| std::mem::take(&mut *trace.borrow_mut()))
}

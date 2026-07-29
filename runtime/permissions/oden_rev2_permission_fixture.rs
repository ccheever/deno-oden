// Copyright 2018-2026 the Deno authors. MIT license.

//! Debug-only construction and observation for the registered native
//! `Deno.permissions` fixture.
//!
//! This module is compiled only by the `deno_runtime` dev-dependency feature.
//! It never publishes its context to the process-global C04 slot and has no
//! production or JavaScript constructor.

use std::path::Path;
use std::sync::Arc;

use serde_json::Value;
use serde_json::json;

use crate::OdenRev2RuntimeAuthorityContext;
use crate::oden_rev2_authority::AuthorityPathFact;
use crate::oden_rev2_authority::AuthorityRowKind;
use crate::oden_rev2_permission::OdenRev2PermissionFixtureCall;
use crate::oden_rev2_permission::OdenRev2PermissionOperation;
use crate::oden_rev2_permission::permission_fixture_capture_path_fact;
use crate::oden_rev2_permission::permission_fixture_reset_trace;
use crate::oden_rev2_permission::permission_fixture_take_trace;
use crate::oden_rev2_permission::permission_fixture_trace;
use crate::oden_rev2_policy::fixture_support;
use crate::oden_rev2_session::session_row_ids;
use crate::rev2::AuthoritySelectorInput;
use crate::rev2::CanonicalAuthoritySelector;
use crate::rev2::EngineIdentity;
use crate::rev2::PrincipalKind;
use crate::rev2::PrincipalRef;
use crate::rev2::Rev2Core;
use crate::rev2::SelectorPolarity;
use crate::rev2::canonical_json;
use crate::rev2_registry_generated::REV2_REGISTRY_DIGEST;
use crate::rev2_registry_generated::REV2_RUNTIME_PERMISSION_BRANCHES;
use crate::rev2_registry_generated::REV2_RUNTIME_SEMANTIC_PAYLOAD_JSON;
use crate::rev2_registry_generated::REV2_VOCAB_DIGEST;

const ACTOR_KEY: &str =
  "pkg:sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const OTHER_KEY: &str =
  "pkg:sha256-BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBA";
const QUARANTINE_KEY: &str =
  "quarantine:sha256-CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCA";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FixtureBranch {
  Ffi,
  Read,
  Run,
  Sys,
  Write,
}

impl FixtureBranch {
  fn from_case_kind(case_kind: &str) -> Self {
    if matches!(
      case_kind,
      "staged-barrier:cancellation" | "staged-barrier:cleanup"
    ) {
      Self::Read
    } else if case_kind.starts_with("alternative-branch:effect-10-run:") {
      Self::Run
    } else if case_kind.starts_with("alternative-branch:effect-3-ffi:") {
      Self::Ffi
    } else if case_kind.starts_with("alternative-branch:effect-4-fs:read:") {
      Self::Read
    } else if case_kind.starts_with("alternative-branch:effect-5-fs:write:") {
      Self::Write
    } else {
      Self::Sys
    }
  }

  fn capability(self) -> &'static str {
    match self {
      Self::Ffi => "ffi:load",
      Self::Read => "fs:read",
      Self::Run => "process:spawn",
      Self::Sys => "sys:read",
      Self::Write => "fs:write",
    }
  }

  fn branch_id(self) -> &'static str {
    match self {
      Self::Ffi => "permission.ffi.scoped/2",
      Self::Read => "permission.read.scoped/2",
      Self::Run => "permission.run.scoped/2",
      Self::Sys => "permission.sys.scoped/2",
      Self::Write => "permission.write.scoped/2",
    }
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum FixtureAuthorityPlan {
  CrossAction,
  Floor,
  FloorAndPrincipalDenial,
  FloorAndProcessDenial,
  MissingPrincipal,
  NoUser,
  Quarantine,
  WrongPrincipal,
}

fn authority_plan(case_kind: &str) -> FixtureAuthorityPlan {
  if case_kind.ends_with(":denied") || case_kind == "authorable-negative" {
    FixtureAuthorityPlan::FloorAndPrincipalDenial
  } else if matches!(
    case_kind,
    "alternative-cross-action-denial" | "authorable-cross-action-denial"
  ) {
    FixtureAuthorityPlan::CrossAction
  } else if case_kind == "authorable-missing-principal-denial" {
    FixtureAuthorityPlan::MissingPrincipal
  } else if case_kind == "authorable-no-user-denial" {
    FixtureAuthorityPlan::NoUser
  } else if case_kind == "authorable-quarantine-denial" {
    FixtureAuthorityPlan::Quarantine
  } else if case_kind == "authorable-wrong-principal-denial" {
    FixtureAuthorityPlan::WrongPrincipal
  } else if case_kind == "staged-barrier:authorization" {
    FixtureAuthorityPlan::FloorAndProcessDenial
  } else {
    FixtureAuthorityPlan::Floor
  }
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

fn normalized_selector(
  principal: Option<PrincipalRef>,
  capability: &str,
  resource: Value,
  polarity: SelectorPolarity,
) -> CanonicalAuthoritySelector {
  Rev2Core::embedded()
    .unwrap()
    .normalize_selector(
      &AuthoritySelectorInput {
        identity: EngineIdentity::embedded(),
        principal,
        capability: capability.to_string(),
        resource,
      },
      polarity,
    )
    .unwrap()
}

fn canonical_selector(
  principal: Option<PrincipalRef>,
  capability: &str,
  resource: Value,
  polarity: SelectorPolarity,
) -> Value {
  serde_json::to_value(normalized_selector(
    principal, capability, resource, polarity,
  ))
  .unwrap()
}

fn sort_values(values: &mut [Value]) {
  values.sort_by_key(|value| canonical_json(value).unwrap());
}

fn policy_principal(
  principal: &PrincipalRef,
  mut floor: Vec<Value>,
  mut escalation_ceiling: Vec<Value>,
  mut denials: Vec<Value>,
) -> Value {
  sort_values(&mut floor);
  sort_values(&mut escalation_ceiling);
  sort_values(&mut denials);
  json!({
    "principal": principal,
    "binding": {
      "resolverId": "fixture-lock-resolver/2",
      "bindingDigest": REV2_VOCAB_DIGEST,
    },
    "floor": floor,
    "escalationCeiling": escalation_ceiling,
    "denials": denials,
  })
}

fn descriptor(branch: FixtureBranch, root: &Path, malformed: bool) -> Value {
  if malformed {
    return json!({ "name": "sys", "kind": null });
  }
  match branch {
    FixtureBranch::Ffi => json!({
      "name": "ffi",
      "path": root.join("libfixture.bin").to_str().unwrap(),
    }),
    FixtureBranch::Read => json!({
      "name": "read",
      "path": root.join("data").to_str().unwrap(),
    }),
    FixtureBranch::Run => json!({
      "name": "run",
      "command": root.join("fixture-native").to_str().unwrap(),
    }),
    FixtureBranch::Sys => json!({ "name": "sys", "kind": "osRelease" }),
    FixtureBranch::Write => json!({
      "name": "write",
      "path": root.join("data").to_str().unwrap(),
    }),
  }
}

fn selected_resource(
  branch: FixtureBranch,
  root: &Path,
) -> (Value, Vec<Value>) {
  match branch {
    FixtureBranch::Sys => (json!({ "kind": "os-release" }), Vec::new()),
    FixtureBranch::Read | FixtureBranch::Write => (
      json!({
        "kind": "path-tree",
        "path": { "encoding": "unicode", "value": "data" },
        "root": "$PROJECT",
      }),
      Vec::new(),
    ),
    FixtureBranch::Run => {
      let native = root.join("fixture-native");
      let digest = fixture_support::file_digest(&native);
      (
        json!({
          "interpreterIdentity": {
            "kind": "verified-content",
            "value": digest,
          },
          "objectIdentity": {
            "kind": "verified-content",
            "value": digest,
          },
          "path": {
            "encoding": "unicode",
            "value": "$PACKAGE/bin/fixture-native",
          },
        }),
        vec![
          json!({
            "sourceId": "floor:fixture:selected",
            "role": "interpreter",
            "canonicalContentIdentity": digest,
            "bindingId": "executable:fixture:interpreter",
            "principal": actor(),
            "canonicalPath": {
              "encoding": "unicode",
              "value": native.to_str().unwrap(),
            },
            "objectIdentity": fixture_support::object_identity(&native),
            "provenanceDigest": REV2_REGISTRY_DIGEST,
          }),
          json!({
            "sourceId": "floor:fixture:selected",
            "role": "object",
            "canonicalContentIdentity": digest,
            "bindingId": "executable:fixture:object",
            "principal": actor(),
            "canonicalPath": {
              "encoding": "unicode",
              "value": native.to_str().unwrap(),
            },
            "objectIdentity": fixture_support::object_identity(&native),
            "provenanceDigest": REV2_REGISTRY_DIGEST,
          }),
        ],
      )
    }
    FixtureBranch::Ffi => {
      let library = root.join("libfixture.bin");
      let digest = fixture_support::file_digest(&library);
      (
        json!({
          "objectIdentity": {
            "kind": "verified-content",
            "value": digest,
          },
          "path": {
            "encoding": "unicode",
            "value": "$PACKAGE/lib/libfixture.bin",
          },
        }),
        vec![json!({
          "sourceId": "floor:fixture:selected",
          "role": "object",
          "canonicalContentIdentity": digest,
          "bindingId": "executable:fixture:object",
          "principal": actor(),
          "canonicalPath": {
            "encoding": "unicode",
            "value": library.to_str().unwrap(),
          },
          "objectIdentity": fixture_support::object_identity(&library),
          "provenanceDigest": REV2_REGISTRY_DIGEST,
        })],
      )
    }
  }
}

fn runtime_session_resource(
  branch: FixtureBranch,
  static_resource: &Value,
) -> Value {
  match branch {
    FixtureBranch::Read | FixtureBranch::Write => json!({
      "kind": "path-exact",
      "root": static_resource["root"].clone(),
      "path": static_resource["path"].clone(),
    }),
    FixtureBranch::Ffi | FixtureBranch::Run | FixtureBranch::Sys => {
      static_resource.clone()
    }
  }
}

fn selected_negative_projection(branch: FixtureBranch) -> &'static str {
  let generated = REV2_RUNTIME_PERMISSION_BRANCHES
    .iter()
    .find(|candidate| candidate.id == branch.branch_id())
    .expect("fixture branch is generated");
  let [slot] = generated.slot_order else {
    panic!("fixture branch is not a generated singleton");
  };
  assert_eq!(slot.capability, branch.capability());
  slot.negative_projection_id
}

fn generated_negative_projection(capability: &str) -> String {
  let payload: Value =
    serde_json::from_str(REV2_RUNTIME_SEMANTIC_PAYLOAD_JSON).unwrap();
  payload["definitions"]
    .as_array()
    .unwrap()
    .iter()
    .find(|definition| definition["id"] == capability)
    .and_then(|definition| definition["negativeProjectionId"].as_str())
    .expect("fixture capability has a generated negative projection")
    .to_string()
}

fn root_bindings_for_selected(
  branch: FixtureBranch,
  root: &Path,
  source_ids: &[&str],
  row_principal: &PrincipalRef,
) -> Vec<Value> {
  if !matches!(branch, FixtureBranch::Read | FixtureBranch::Write) {
    return Vec::new();
  }
  source_ids
    .iter()
    .enumerate()
    .map(|(index, source_id)| {
      json!({
        "sourceId": source_id,
        "logicalRoot": "$PROJECT",
        "principal": row_principal,
        "rootBindingId": format!("root-binding:fixture:{index}"),
        "canonicalPath": {
          "encoding": "unicode",
          "value": root.to_str().unwrap(),
        },
        "objectIdentity": fixture_support::object_identity(root),
        "bindingProvenanceDigest": REV2_REGISTRY_DIGEST,
      })
    })
    .collect()
}

/// One debug-only local context and its closed native descriptor.
pub struct OdenRev2PermissionFixtureContext {
  pub authority: Arc<OdenRev2RuntimeAuthorityContext>,
  pub descriptor: Value,
  pub selected_branch: &'static str,
  pub selected_capability: &'static str,
  fixture_call: OdenRev2PermissionFixtureCall,
  actors: Vec<PrincipalRef>,
  overlay_owner: PrincipalRef,
  selected_policy_positive: CanonicalAuthoritySelector,
  selected_positive: CanonicalAuthoritySelector,
  selected_session_revocation: CanonicalAuthoritySelector,
  selected_path_fact: Option<AuthorityPathFact>,
  unselected_session_revocation: CanonicalAuthoritySelector,
}

impl OdenRev2PermissionFixtureContext {
  pub fn fixture_call(&self) -> OdenRev2PermissionFixtureCall {
    self.fixture_call.clone()
  }

  pub fn lifecycle_hook_consumed(&self) -> bool {
    self.fixture_call.is_claimed()
  }

  pub fn exact_selected_ceiling_and_root_binding_counts(
    &self,
  ) -> (usize, usize) {
    let ceiling_count = self
      .authority
      .static_policy()
      .principals()
      .iter()
      .filter(|principal| principal.principal() == &self.overlay_owner)
      .flat_map(|principal| principal.escalation_ceiling())
      .filter(|row| {
        row.source_id() == "ceiling:fixture:selected"
          && row.selector() == &self.selected_policy_positive
      })
      .count();
    let root_binding_count = self
      .authority
      .bindings()
      .roots()
      .iter()
      .filter(|binding| binding.source_id() == "ceiling:fixture:selected")
      .count();
    (ceiling_count, root_binding_count)
  }
}

/// One exact authority-state observation used before and after registered-op
/// dispatch.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OdenRev2PermissionFixtureObservation {
  pub negative_overlay_generation: u64,
  pub policy_snapshot_generation: u64,
  pub revocation_generation: u64,
  pub session_overlay_generation: u64,
  pub session_positive_row_ids: Vec<String>,
  pub session_revocation_row_ids: Vec<String>,
  pub selected_session_positive_row_ids: Vec<String>,
  pub selected_session_revocation_row_ids: Vec<String>,
  pub expected_selected_session_positive_row_ids: Vec<String>,
  pub expected_selected_session_revocation_row_ids: Vec<String>,
  pub unrelated_session_revocation_row_ids: Vec<String>,
  pub expected_unrelated_session_revocation_row_id: String,
  pub unexpected_session_positive_row_ids: Vec<String>,
  pub unexpected_session_revocation_row_ids: Vec<String>,
  pub unexpected_session_revocation_rows: Vec<String>,
  pub expected_selected_session_revocation_selectors: Vec<String>,
  pub negative_overlay_row_ids: Vec<String>,
  pub revocation_row_ids: Vec<String>,
  pub unselected_session_revocation_row_id: Option<String>,
}

impl OdenRev2PermissionFixtureObservation {
  pub fn total_row_count(&self) -> usize {
    self.session_positive_row_ids.len()
      + self.session_revocation_row_ids.len()
      + self.negative_overlay_row_ids.len()
      + self.revocation_row_ids.len()
  }
}

/// Build a fresh authenticated-but-local fixture context. The caller must put
/// the returned Arc only in a cfg(test) OpState wrapper; this helper has no
/// process-global publication path.
///
/// @ref LLP 0019#typed-permission-batches [tests] -- The registered-op fixture
/// selects one generated descriptor branch and observes the exact atomic
/// session rows without granting the fixture any release authority.
pub fn oden_capsec_rev2_permission_fixture_context(
  operation: &str,
  case_kind: &str,
  mode: &str,
  root: &Path,
) -> Result<OdenRev2PermissionFixtureContext, String> {
  if !matches!(operation, "query" | "request" | "revoke")
    || !matches!(mode, "permissive" | "audit" | "enforce")
  {
    return Err("fixture operation or mode is not closed".to_string());
  }
  let branch = FixtureBranch::from_case_kind(case_kind);
  if operation == "request"
    && matches!(branch, FixtureBranch::Run | FixtureBranch::Ffi)
  {
    return Err(
      "static-only request branch is not a supported case".to_string(),
    );
  }
  if matches!(
    (operation, case_kind),
    ("query" | "request", "staged-barrier:revocation")
  ) {
    return Err("unsupported staged permission fixture case".to_string());
  }

  std::fs::create_dir_all(root).map_err(|error| error.to_string())?;
  use std::os::unix::fs::PermissionsExt;
  std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700))
    .map_err(|error| error.to_string())?;
  std::fs::write(root.join("data"), b"dynamic permission fixture")
    .map_err(|error| error.to_string())?;
  std::fs::write(root.join("fixture-native"), b"fixture native image")
    .map_err(|error| error.to_string())?;
  std::fs::write(root.join("libfixture.bin"), b"fixture library image")
    .map_err(|error| error.to_string())?;
  let root = std::fs::canonicalize(root).map_err(|error| error.to_string())?;
  let plan = authority_plan(case_kind);
  let overlay_owner = match plan {
    FixtureAuthorityPlan::NoUser => {
      principal(PrincipalKind::NoUser, "no-user:dynamic-permission-fixture")
    }
    FixtureAuthorityPlan::Quarantine => {
      principal(PrincipalKind::Quarantine, QUARANTINE_KEY)
    }
    _ => actor(),
  };
  let actors = match plan {
    FixtureAuthorityPlan::MissingPrincipal => Vec::new(),
    FixtureAuthorityPlan::WrongPrincipal => vec![actor(), other()],
    _ => vec![overlay_owner.clone()],
  };
  let row_owner = match plan {
    FixtureAuthorityPlan::WrongPrincipal
    | FixtureAuthorityPlan::MissingPrincipal => other(),
    FixtureAuthorityPlan::NoUser => actor(),
    _ => overlay_owner.clone(),
  };
  let (policy_resource, mut executable_bindings) =
    selected_resource(branch, &root);
  for binding in &mut executable_bindings {
    binding["principal"] = serde_json::to_value(&row_owner).unwrap();
  }
  if plan == FixtureAuthorityPlan::FloorAndPrincipalDenial {
    let denial_bindings = executable_bindings
      .iter()
      .cloned()
      .map(|mut binding| {
        binding["sourceId"] = json!("deny:fixture:selected");
        binding["bindingId"] =
          json!(format!("{}:denial", binding["bindingId"].as_str().unwrap()));
        binding
      })
      .collect::<Vec<_>>();
    executable_bindings.extend(denial_bindings);
  }
  sort_values(&mut executable_bindings);
  let policy_positive = normalized_selector(
    Some(row_owner.clone()),
    branch.capability(),
    policy_resource.clone(),
    SelectorPolarity::Positive,
  );
  let policy_negative = normalized_selector(
    Some(row_owner.clone()),
    branch.capability(),
    policy_resource.clone(),
    SelectorPolarity::Negative,
  );
  let runtime_resource = runtime_session_resource(branch, &policy_resource);
  let selected_positive = normalized_selector(
    Some(overlay_owner.clone()),
    branch.capability(),
    runtime_resource.clone(),
    SelectorPolarity::Positive,
  );
  let mut selected_session_revocation = normalized_selector(
    Some(overlay_owner.clone()),
    branch.capability(),
    runtime_resource,
    SelectorPolarity::Negative,
  );
  selected_session_revocation.projection_id =
    selected_negative_projection(branch).to_string();
  let mut unselected_session_revocation = normalized_selector(
    Some(overlay_owner.clone()),
    "env:read",
    json!({ "name": "UNSELECTED_FIXTURE_TOKEN" }),
    SelectorPolarity::Negative,
  );
  unselected_session_revocation.projection_id =
    generated_negative_projection("env:read");
  let floor_row = json!({ "sourceId": "floor:fixture:selected", "selector": policy_positive.clone() });
  let principal_denial_row = json!({ "sourceId": "deny:fixture:selected", "selector": policy_negative.clone() });
  let ceiling_row = json!({
    "sourceId": "ceiling:fixture:selected",
    "selector": policy_positive.clone(),
  });
  let env_floor = json!({
    "sourceId": "floor:fixture:cross-action",
    "selector": canonical_selector(
      Some(row_owner.clone()),
      "env:read",
      json!({ "name": "TOKEN" }),
      SelectorPolarity::Positive,
    ),
  });

  let (floor, denials) = match plan {
    FixtureAuthorityPlan::CrossAction => (vec![env_floor], Vec::new()),
    FixtureAuthorityPlan::Quarantine => (Vec::new(), Vec::new()),
    FixtureAuthorityPlan::FloorAndPrincipalDenial => {
      (vec![floor_row], vec![principal_denial_row])
    }
    _ => {
      let mut floor = vec![floor_row];
      if case_kind == "alternative-no-unselected-branch-commit" {
        floor.push(env_floor);
      }
      (floor, Vec::new())
    }
  };
  let mut snapshot = fixture_support::candidate_snapshot(mode);
  let revoke_cancellation =
    operation == "revoke" && case_kind == "staged-barrier:cancellation";
  let escalation_ceiling = if matches!(
    case_kind,
    "alternative-no-unselected-branch-commit" | "staged-barrier:revocation"
  ) || revoke_cancellation
  {
    vec![ceiling_row]
  } else {
    Vec::new()
  };
  snapshot["canonicalPolicy"]["principals"] =
    Value::Array(vec![policy_principal(
      &row_owner,
      floor,
      escalation_ceiling,
      denials,
    )]);
  if plan == FixtureAuthorityPlan::FloorAndProcessDenial {
    snapshot["canonicalPolicy"]["processDenials"] = json!([{
      "sourceId": "process-deny:fixture:selected",
      "selector": canonical_selector(
        None,
        branch.capability(),
        selected_resource(branch, &root).0,
        SelectorPolarity::Negative,
      ),
    }]);
  }

  let mut root_source_ids = Vec::new();
  if !matches!(
    plan,
    FixtureAuthorityPlan::CrossAction | FixtureAuthorityPlan::Quarantine
  ) {
    root_source_ids.push("floor:fixture:selected");
  }
  if plan == FixtureAuthorityPlan::FloorAndPrincipalDenial {
    root_source_ids.push("deny:fixture:selected");
  }
  if plan == FixtureAuthorityPlan::FloorAndProcessDenial {
    root_source_ids.push("process-deny:fixture:selected");
  }
  if revoke_cancellation {
    root_source_ids.push("ceiling:fixture:selected");
  }
  let mut root_bindings =
    root_bindings_for_selected(branch, &root, &root_source_ids, &row_owner);
  sort_values(&mut root_bindings);
  snapshot["rootBindings"] = Value::Array(root_bindings);
  snapshot["executableBindings"] = Value::Array(executable_bindings);
  fixture_support::refresh_digests(&mut snapshot);
  let mut loaded = fixture_support::load_snapshot(snapshot, &[117_u8; 32]);
  loaded
    .install_immutable_executables(&root)
    .map_err(|error| error.to_string())?;
  let authority = Arc::new(
    OdenRev2RuntimeAuthorityContext::install_for_test(loaded)
      .map_err(|error| error.to_string())?,
  );
  let selected_path_fact = if matches!(branch, FixtureBranch::Read) {
    Some(
      permission_fixture_capture_path_fact(
        &authority,
        &actors,
        &overlay_owner,
        &selected_positive,
        &root.join("data"),
      )
      .map_err(|error| error.to_string())?,
    )
  } else {
    None
  };
  let operation = match operation {
    "query" => OdenRev2PermissionOperation::Query,
    "request" => OdenRev2PermissionOperation::Request,
    "revoke" => OdenRev2PermissionOperation::Revoke,
    _ => unreachable!("validated above"),
  };
  let fixture_call = OdenRev2PermissionFixtureCall::capture(
    authority.clone(),
    operation,
    case_kind,
  );
  Ok(OdenRev2PermissionFixtureContext {
    authority,
    descriptor: descriptor(
      branch,
      &root,
      case_kind == "malformed-resource-refusal",
    ),
    selected_branch: branch.branch_id(),
    selected_capability: branch.capability(),
    fixture_call,
    actors,
    overlay_owner,
    selected_policy_positive: policy_positive,
    selected_positive,
    selected_session_revocation,
    selected_path_fact,
    unselected_session_revocation,
  })
}

/// Seed one exact positive session row as a visible synthetic baseline. The
/// staged-revocation and revoke-lifecycle fixtures use this; the evidence
/// operation remains the registered revoke op. Path cases attach an
/// independently host-verified fact for the exact retained object.
pub fn oden_capsec_rev2_permission_fixture_seed_positive(
  fixture: &OdenRev2PermissionFixtureContext,
) {
  let mut transaction = fixture
    .authority
    .authority_state()
    .begin_transaction()
    .unwrap();
  transaction
    .reconcile_session_grant(
      &fixture.overlay_owner,
      &fixture.overlay_owner,
      &fixture.selected_positive,
      &fixture.selected_session_revocation,
      fixture.selected_path_fact.as_ref(),
    )
    .unwrap();
  fixture
    .authority
    .authority_state()
    .commit_if(transaction, |_| Ok(()))
    .unwrap();
}

/// Seed one exact selected-branch revocation and one unrelated env revocation
/// as a synthetic baseline. The corresponding isolation case observes both
/// before dispatch and requires the registered op to leave the unrelated row
/// byte-for-byte unchanged.
pub fn oden_capsec_rev2_permission_fixture_seed_revocation(
  fixture: &OdenRev2PermissionFixtureContext,
) {
  let mut transaction = fixture
    .authority
    .authority_state()
    .begin_transaction()
    .unwrap();
  transaction
    .upsert_session_revocation(
      &fixture.overlay_owner,
      &fixture.overlay_owner,
      &fixture.selected_session_revocation,
      None,
    )
    .unwrap();
  transaction
    .upsert_session_revocation(
      &fixture.overlay_owner,
      &fixture.overlay_owner,
      &fixture.unselected_session_revocation,
      None,
    )
    .unwrap();
  fixture
    .authority
    .authority_state()
    .commit_if(transaction, |_| Ok(()))
    .unwrap();
}

pub fn oden_capsec_rev2_permission_fixture_set_actors(
  fixture: Option<&OdenRev2PermissionFixtureContext>,
) {
  crate::oden_rev2_set_permission_actors_for_test(
    fixture
      .map(|fixture| (fixture.actors.clone(), fixture.overlay_owner.clone())),
  );
  crate::oden_rev2_reset_permission_actor_capture_count_for_test();
  permission_fixture_reset_trace();
}

pub fn oden_capsec_rev2_permission_fixture_observe(
  fixture: &OdenRev2PermissionFixtureContext,
) -> OdenRev2PermissionFixtureObservation {
  let view = fixture.authority.authority_state().read_view().unwrap();
  let ids = |kind| {
    view
      .rows(kind)
      .map(|row| row.row_id().to_string())
      .collect::<Vec<_>>()
  };
  let is_selected =
    |row: &crate::oden_rev2_authority::AuthorityRow,
     template: &CanonicalAuthoritySelector| {
      fixture.actors.iter().any(|principal| {
        let mut expected = template.clone();
        expected.principal = Some(principal.clone());
        row.selector() == &expected
      })
    };
  let mut expected_selected_session_positive_row_ids = Vec::new();
  let mut expected_selected_session_revocation_row_ids = Vec::new();
  let mut expected_selected_session_revocation_selectors = Vec::new();
  for principal in &fixture.actors {
    let mut positive = fixture.selected_positive.clone();
    positive.principal = Some(principal.clone());
    let positive_ids = session_row_ids(
      view.identity(),
      &fixture.overlay_owner,
      principal,
      &positive,
    )
    .unwrap();
    let mut revocation = fixture.selected_session_revocation.clone();
    revocation.principal = Some(principal.clone());
    let revocation_ids = session_row_ids(
      view.identity(),
      &fixture.overlay_owner,
      principal,
      &revocation,
    )
    .unwrap();
    assert_eq!(
      positive_ids, revocation_ids,
      "runtime positive/revocation selectors must share one exact row identity"
    );
    expected_selected_session_positive_row_ids
      .push(positive_ids.positive().to_string());
    expected_selected_session_revocation_row_ids
      .push(revocation_ids.revocation().to_string());
    expected_selected_session_revocation_selectors.push(
      canonical_json(&serde_json::to_value(&revocation).unwrap()).unwrap(),
    );
  }
  expected_selected_session_positive_row_ids.sort();
  expected_selected_session_revocation_row_ids.sort();
  expected_selected_session_revocation_selectors.sort();
  let expected_unrelated_session_revocation_row_id = session_row_ids(
    view.identity(),
    &fixture.overlay_owner,
    &fixture.overlay_owner,
    &fixture.unselected_session_revocation,
  )
  .unwrap()
  .revocation()
  .to_string();
  let selected_session_positive_row_ids = view
    .rows(AuthorityRowKind::SessionPositive)
    .filter(|row| is_selected(row, &fixture.selected_positive))
    .map(|row| row.row_id().to_string())
    .collect::<Vec<_>>();
  let selected_session_revocation_row_ids = view
    .rows(AuthorityRowKind::SessionRevocation)
    .filter(|row| is_selected(row, &fixture.selected_session_revocation))
    .map(|row| row.row_id().to_string())
    .collect::<Vec<_>>();
  let unrelated_session_revocation_row_ids = view
    .rows(AuthorityRowKind::SessionRevocation)
    .filter(|row| row.selector() == &fixture.unselected_session_revocation)
    .map(|row| row.row_id().to_string())
    .collect::<Vec<_>>();
  let unexpected_session_positive_row_ids = view
    .rows(AuthorityRowKind::SessionPositive)
    .filter(|row| !is_selected(row, &fixture.selected_positive))
    .map(|row| row.row_id().to_string())
    .collect::<Vec<_>>();
  let unexpected_session_revocation_row_ids = view
    .rows(AuthorityRowKind::SessionRevocation)
    .filter(|row| {
      !is_selected(row, &fixture.selected_session_revocation)
        && row.selector() != &fixture.unselected_session_revocation
    })
    .map(|row| row.row_id().to_string())
    .collect::<Vec<_>>();
  let unexpected_session_revocation_rows = view
    .rows(AuthorityRowKind::SessionRevocation)
    .filter(|row| {
      !is_selected(row, &fixture.selected_session_revocation)
        && row.selector() != &fixture.unselected_session_revocation
    })
    .map(|row| row.canonical_value().to_string())
    .collect::<Vec<_>>();
  let generations = view.generations();
  let unselected_session_revocation_row_id = view
    .rows(AuthorityRowKind::SessionRevocation)
    .find(|row| row.selector() == &fixture.unselected_session_revocation)
    .map(|row| row.row_id().to_string());
  OdenRev2PermissionFixtureObservation {
    negative_overlay_generation: generations.negative_overlay(),
    policy_snapshot_generation: generations.policy_snapshot(),
    revocation_generation: generations.revocation(),
    session_overlay_generation: generations.session_overlay(),
    session_positive_row_ids: ids(AuthorityRowKind::SessionPositive),
    session_revocation_row_ids: ids(AuthorityRowKind::SessionRevocation),
    selected_session_positive_row_ids,
    selected_session_revocation_row_ids,
    expected_selected_session_positive_row_ids,
    expected_selected_session_revocation_row_ids,
    unrelated_session_revocation_row_ids,
    expected_unrelated_session_revocation_row_id,
    unexpected_session_positive_row_ids,
    unexpected_session_revocation_row_ids,
    unexpected_session_revocation_rows,
    expected_selected_session_revocation_selectors,
    negative_overlay_row_ids: ids(AuthorityRowKind::NegativeOverlay),
    revocation_row_ids: ids(AuthorityRowKind::Revocation),
    unselected_session_revocation_row_id,
  }
}

pub fn oden_capsec_rev2_permission_fixture_record_event(event: &str) {
  permission_fixture_trace(event);
}

pub fn oden_capsec_rev2_permission_fixture_take_trace()
-> (Vec<String>, usize, u64, usize, usize, usize, u64) {
  let actor_captures =
    crate::oden_rev2_permission_actor_capture_count_for_test();
  let (
    trace,
    active_host_effects,
    mode_fallback_count,
    retained_descriptor_count,
    released_descriptor_count,
    active_retained_descriptors,
  ) = permission_fixture_take_trace();
  (
    trace,
    active_host_effects,
    mode_fallback_count,
    retained_descriptor_count,
    released_descriptor_count,
    active_retained_descriptors,
    actor_captures,
  )
}

pub fn oden_capsec_rev2_permission_fixture_compiled_target() -> &'static str {
  fixture_support::target()
}

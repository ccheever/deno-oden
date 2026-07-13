// Copyright 2018-2026 the Deno authors. MIT license.

//! Live, closed `Deno.permissions` adapter for the installed C04 context.
//!
//! @ref LLP 0019#stage-c-runtime-authority-and-typed-permission-checkpoint-c04--eng-24017 [implements] -- An installed Rev2 context selects exactly one generated descriptor branch and never falls through to the Revision-1 wildcard or prompt path.

use std::collections::BTreeSet;
use std::fs::File;
use std::path::Component;
use std::path::Path;
use std::path::PathBuf;
use std::sync::OnceLock;

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::Value;
use serde_json::json;

use crate::OdenDynamicPermissionDescriptor;
use crate::OdenRev2RuntimeAuthorityContext;
use crate::PermissionState as PublicPermissionState;
use crate::PermissionsContainer;
#[cfg(test)]
use crate::oden_rev2_authority::AuthorityPathFact;
use crate::oden_rev2_authority::AuthorityStateError;
use crate::oden_rev2_authority::RuntimeAuthorityReadView;
use crate::oden_rev2_context::OdenRev2OperationAuthorityFacts;
use crate::oden_rev2_protocol::NormalizedPermissionBatch;
use crate::oden_rev2_protocol::NormalizedPermissionEffect;
use crate::oden_rev2_protocol::PermissionBatchResult;
use crate::oden_rev2_protocol::PermissionDimensionResult;
use crate::oden_rev2_protocol::PermissionEffectResult;
use crate::oden_rev2_protocol::PermissionEvaluationView;
use crate::oden_rev2_protocol::PermissionNegativeReentryPhase;
use crate::oden_rev2_protocol::PermissionOperation;
use crate::oden_rev2_protocol::PermissionProtocolError;
use crate::oden_rev2_protocol::PermissionState;
use crate::oden_rev2_protocol::SealedPermissionNegativeReentry;
use crate::oden_rev2_protocol::VerifiedPermissionActorSet;
use crate::oden_rev2_protocol::select_generated_permission_branch;
use crate::rev2::AuthoritySelectorInput;
use crate::rev2::DecisionPolicyInput;
use crate::rev2::EffectInput;
use crate::rev2::EngineIdentity;
use crate::rev2::Outcome;
use crate::rev2::PathBindingInput;
use crate::rev2::Rev2Core;
use crate::rev2::SelectorPolarity;
use crate::rev2::StageDecision;
use crate::rev2_registry_generated::REV2_RUNTIME_PERMISSION_BRANCHES;
use crate::rev2_registry_generated::REV2_RUNTIME_SEMANTIC_PAYLOAD_JSON;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OdenRev2PermissionOperation {
  Query,
  Request,
  Revoke,
}

impl From<OdenRev2PermissionOperation> for PermissionOperation {
  fn from(value: OdenRev2PermissionOperation) -> Self {
    match value {
      OdenRev2PermissionOperation::Query => Self::Query,
      OdenRev2PermissionOperation::Request => Self::Request,
      OdenRev2PermissionOperation::Revoke => Self::Revoke,
    }
  }
}

#[derive(Debug, thiserror::Error)]
pub enum OdenRev2PermissionError {
  #[error("Rev2 permission descriptor refused: {0}")]
  DescriptorRefused(String),
  #[error("Rev2 permission descriptor is invalid: {0}")]
  DescriptorInvalid(String),
  #[error("Rev2 permission host verifier is not installed for {0}")]
  HostVerifierUnavailable(String),
  #[error("Rev2 permission protocol refused: {0}")]
  Protocol(String),
  #[error("Rev2 permission core refused: {0}")]
  Core(String),
  #[error("Rev2 permission authority context refused: {0}")]
  Context(String),
}

impl From<PermissionProtocolError> for OdenRev2PermissionError {
  fn from(error: PermissionProtocolError) -> Self {
    Self::Protocol(error.to_string())
  }
}

fn present_fields(
  descriptor: &OdenDynamicPermissionDescriptor<'_>,
) -> BTreeSet<&'static str> {
  let mut present = BTreeSet::from(["name"]);
  for (name, is_present) in [
    ("path", descriptor.presence.path),
    ("host", descriptor.presence.host),
    ("variable", descriptor.presence.variable),
    ("kind", descriptor.presence.kind),
    ("command", descriptor.presence.command),
  ] {
    if is_present {
      present.insert(name);
    }
  }
  present
}

fn select_branch(
  descriptor: &OdenDynamicPermissionDescriptor<'_>,
) -> Result<
  &'static crate::rev2_registry_generated::Rev2RuntimePermissionBranch,
  OdenRev2PermissionError,
> {
  let present = present_fields(descriptor);
  let matches = REV2_RUNTIME_PERMISSION_BRANCHES
    .iter()
    .filter(|branch| branch.descriptor_name == descriptor.name)
    .filter(|branch| {
      let accepted = branch
        .descriptor_required_fields
        .iter()
        .chain(branch.descriptor_optional_fields)
        .copied()
        .collect::<BTreeSet<_>>();
      let required = branch
        .descriptor_required_fields
        .iter()
        .copied()
        .collect::<BTreeSet<_>>();
      required.is_subset(&present) && present.is_subset(&accepted)
    })
    .collect::<Vec<_>>();
  let [branch] = matches.as_slice() else {
    return Err(OdenRev2PermissionError::DescriptorInvalid(
      "no unique generated branch matches the exact field set".to_string(),
    ));
  };
  if branch.descriptor_scope_requirement == "required-nonempty" {
    let Some(field) = branch.descriptor_scope_field else {
      return Err(OdenRev2PermissionError::DescriptorInvalid(
        "generated scoped branch omits its scope field".to_string(),
      ));
    };
    let value = match field {
      "path" => descriptor.path,
      "host" => descriptor.host,
      "variable" => descriptor.variable,
      "kind" => descriptor.kind,
      "command" => descriptor.command,
      _ => None,
    };
    if value.is_none_or(|value| value.is_empty()) {
      return Err(OdenRev2PermissionError::DescriptorInvalid(format!(
        "{field} must be nonempty"
      )));
    }
  }
  if branch.disposition != "normalize" {
    return Err(OdenRev2PermissionError::DescriptorRefused(
      branch
        .refusal_reason_code
        .unwrap_or("OD-CAP-PERMISSION-REFUSED")
        .to_string(),
    ));
  }
  Ok(branch)
}

fn protocol_state_to_public(state: PermissionState) -> PublicPermissionState {
  match state {
    PermissionState::Granted => PublicPermissionState::Granted,
    PermissionState::Prompt => PublicPermissionState::Prompt,
    PermissionState::Denied => PublicPermissionState::Denied,
  }
}

fn require_current_authority_view(
  context: &OdenRev2RuntimeAuthorityContext,
  view: &RuntimeAuthorityReadView,
) -> Result<(), OdenRev2PermissionError> {
  if context
    .authority_state()
    .is_current(view)
    .map_err(|error| OdenRev2PermissionError::Context(error.to_string()))?
  {
    Ok(())
  } else {
    Err(OdenRev2PermissionError::Protocol(
      PermissionProtocolError::StaleAuthorityView.to_string(),
    ))
  }
}

fn evaluate_phase<'batch>(
  context: &OdenRev2RuntimeAuthorityContext,
  batch: &'batch NormalizedPermissionBatch,
  view: &RuntimeAuthorityReadView,
  overlay_owner: &crate::rev2::PrincipalRef,
  path_bindings: &[PathBindingInput],
  phase: PermissionNegativeReentryPhase,
  evaluation_view: PermissionEvaluationView,
) -> Result<SealedPermissionNegativeReentry<'batch>, OdenRev2PermissionError> {
  let mut facts = OdenRev2OperationAuthorityFacts::new(
    overlay_owner.clone(),
    format!("permission:{}", phase.id()),
  );
  facts = facts.with_path_bindings(path_bindings.iter().cloned());
  context
    .evaluate_permission_negative_reentry(
      batch,
      view,
      facts,
      phase,
      evaluation_view,
      0,
      None,
    )
    .map_err(OdenRev2PermissionError::from)
}

fn permission_effect_result(
  core: &Rev2Core,
  policy: &DecisionPolicyInput,
  effect_input: &EffectInput,
  decision: &StageDecision,
  logical_slot_id: &str,
  dynamically_authorable: bool,
) -> Result<PermissionEffectResult, OdenRev2PermissionError> {
  let effect_decision = decision.effects.first().ok_or_else(|| {
    OdenRev2PermissionError::Protocol(
      PermissionProtocolError::IncompleteResult.to_string(),
    )
  })?;
  if decision.effects.len() != 1 {
    return Err(OdenRev2PermissionError::Protocol(
      PermissionProtocolError::IncompleteResult.to_string(),
    ));
  }
  let dimensions = effect_decision
    .dimensions
    .iter()
    .map(|dimension| {
      let mut inside_escalation_ceiling = false;
      if dynamically_authorable
        && dimension.outcome == Outcome::Deny
        && matches!(dimension.stratum, 7 | 17)
      {
        for row in &policy.escalation_ceiling {
          if row.selector.principal.as_ref() == Some(&dimension.principal)
            && core
              .selector_matches_effect(
                &row.selector,
                effect_input,
                SelectorPolarity::Positive,
                &row.source_id,
                &policy.path_bindings,
              )
              .map_err(|error| {
                OdenRev2PermissionError::Core(error.to_string())
              })?
          {
            inside_escalation_ceiling = true;
            break;
          }
        }
      }
      let state = match dimension.outcome {
        Outcome::Allow => PermissionState::Granted,
        Outcome::Masked | Outcome::Deny if inside_escalation_ceiling => {
          PermissionState::Prompt
        }
        Outcome::Masked | Outcome::Deny => PermissionState::Denied,
      };
      PermissionDimensionResult::capture_host(
        dimension.principal.clone(),
        state,
        dimension.positive_source.clone(),
      )
      .map_err(OdenRev2PermissionError::from)
    })
    .collect::<Result<Vec<_>, _>>()?;
  PermissionEffectResult::capture_host(logical_slot_id.to_string(), &dimensions)
    .map_err(OdenRev2PermissionError::from)
}

struct VerifiedHostEffect {
  resource: Value,
  occurrence: Value,
  path_bindings: Vec<PathBindingInput>,
  session_path_binding: Option<PathBindingInput>,
  // Keep every descriptor used to establish the occurrence alive through the
  // complete typed evaluation. A later operational adapter must likewise
  // consume these handles instead of reopening the checked spelling.
  _retained_handles: Vec<File>,
  _installed_bindings:
    Vec<crate::oden_rev2_executable::OdenRev2InstalledExecutable>,
}

fn evaluate_singleton_permission(
  context: &OdenRev2RuntimeAuthorityContext,
  branch: &crate::rev2_registry_generated::Rev2RuntimePermissionBranch,
  operation: PermissionOperation,
  dynamically_authorable: bool,
  build_host_effect: impl FnOnce(
    &[crate::rev2::PrincipalRef],
    &crate::rev2::PrincipalRef,
  ) -> Result<
    VerifiedHostEffect,
    OdenRev2PermissionError,
  >,
) -> Result<PublicPermissionState, OdenRev2PermissionError> {
  let generated = select_generated_permission_branch(branch.id, operation)?;
  let slot = branch.slot_order.first().ok_or_else(|| {
    OdenRev2PermissionError::DescriptorInvalid(
      "generated normalized branch has no slot".to_string(),
    )
  })?;
  if branch.slot_order.len() != 1 {
    return Err(OdenRev2PermissionError::DescriptorInvalid(
      "permission branch is not the exact generated singleton".to_string(),
    ));
  }
  let operation_effect_slot_id = match operation {
    PermissionOperation::Query => slot.operation_effect_slot_ids.query,
    PermissionOperation::Request => slot.operation_effect_slot_ids.request,
    PermissionOperation::Revoke => slot.operation_effect_slot_ids.revoke,
  }
  .ok_or(PermissionProtocolError::TransitionRefused)?;

  let (principals, overlay_owner) =
    crate::oden_rev2_capture_live_permission_actors();
  let actors = VerifiedPermissionActorSet::capture_host(
    &principals,
    overlay_owner.clone(),
  )?;
  let host_effect = build_host_effect(&principals, &overlay_owner)?;
  let core = Rev2Core::embedded()
    .map_err(|error| OdenRev2PermissionError::Core(error.to_string()))?;
  let effect_input = EffectInput {
    identity: EngineIdentity::embedded(),
    edge_id: match operation {
      PermissionOperation::Query => branch.operation_edge_ids.query,
      PermissionOperation::Request => branch.operation_edge_ids.request,
      PermissionOperation::Revoke => branch.operation_edge_ids.revoke,
    }
    .to_string(),
    effect_slot_id: operation_effect_slot_id.to_string(),
    capability: slot.capability.to_string(),
    effect_owner: overlay_owner.key.clone(),
    occurrence: host_effect.occurrence.clone(),
  };
  let canonical_effect = core
    .normalize_effect(&effect_input)
    .map_err(|error| OdenRev2PermissionError::Core(error.to_string()))?;
  let selector = core
    .normalize_selector(
      &AuthoritySelectorInput {
        identity: EngineIdentity::embedded(),
        principal: Some(overlay_owner.clone()),
        capability: slot.capability.to_string(),
        resource: host_effect.resource.clone(),
      },
      SelectorPolarity::Positive,
    )
    .map_err(|error| OdenRev2PermissionError::Core(error.to_string()))?;
  let effect = NormalizedPermissionEffect::capture_generated_slot(
    slot.slot_id.to_string(),
    overlay_owner.clone(),
    selector,
    canonical_effect,
  )?;
  let view = context
    .authority_state()
    .read_view()
    .map_err(|error| OdenRev2PermissionError::Context(error.to_string()))?;
  let sequence = context
    .next_permission_batch_sequence()
    .map_err(OdenRev2PermissionError::Context)?;
  let batch = NormalizedPermissionBatch::capture_host_with_path_bindings(
    context.authority_state(),
    &view,
    sequence,
    operation,
    &generated,
    &actors,
    std::slice::from_ref(&effect),
    &[host_effect.session_path_binding.as_ref()],
  )?;

  let phases: &[PermissionNegativeReentryPhase] = match operation {
    PermissionOperation::Query => &[
      PermissionNegativeReentryPhase::InitialQueryOrRequest,
      PermissionNegativeReentryPhase::ResultProduction,
    ],
    PermissionOperation::Request => &[
      PermissionNegativeReentryPhase::InitialQueryOrRequest,
      PermissionNegativeReentryPhase::AlreadyGrantedCheck,
      PermissionNegativeReentryPhase::ResultProduction,
    ],
    PermissionOperation::Revoke => {
      &[PermissionNegativeReentryPhase::InitialQueryOrRequest]
    }
  };
  let mut final_evaluation = None;
  for &phase in phases {
    final_evaluation = Some(evaluate_phase(
      context,
      &batch,
      &view,
      &overlay_owner,
      &host_effect.path_bindings,
      phase,
      PermissionEvaluationView::Current,
    )?);
  }
  let seal =
    final_evaluation.expect("each operation evaluates at least one phase");
  let effect_result = permission_effect_result(
    &core,
    seal.policy(),
    &effect_input,
    seal.decision(),
    slot.slot_id,
    dynamically_authorable,
  )?;
  let current_result = if operation == PermissionOperation::Query {
    PermissionBatchResult::capture_query_current(
      context.authority_state(),
      &batch,
      &view,
      std::slice::from_ref(&effect_result),
    )?
  } else {
    PermissionBatchResult::capture_complete(
      &batch,
      &view,
      std::slice::from_ref(&effect_result),
    )?
  };
  if operation != PermissionOperation::Query {
    require_current_authority_view(context, &view)?;
  }

  match operation {
    PermissionOperation::Query => {
      Ok(protocol_state_to_public(current_result.state()))
    }
    PermissionOperation::Request => {
      // Already-granted requests complete after exact negative re-entry. A
      // promptable miss has no installed authenticated broker, so it is an
      // unanswered decision and publishes no positive row.
      Ok(if current_result.state() == PermissionState::Granted {
        PublicPermissionState::Granted
      } else {
        PublicPermissionState::Denied
      })
    }
    PermissionOperation::Revoke => {
      let transaction = batch.session_revoke_transaction(
        context.authority_state(),
        &current_result,
      )?;
      let mut validation_error = None;
      let committed = context
        .authority_state()
        .compare_propose_validate_commit(transaction, |proposed_view| {
          let validate = || {
            let mut final_evaluation = None;
            for phase in [
              PermissionNegativeReentryPhase::BeforeOverlayPublication,
              PermissionNegativeReentryPhase::ResultProduction,
            ] {
              final_evaluation = Some(evaluate_phase(
                context,
                &batch,
                proposed_view,
                &overlay_owner,
                &host_effect.path_bindings,
                phase,
                PermissionEvaluationView::Proposed,
              )?);
            }
            let seal = final_evaluation
              .expect("both generated proposed-state phases are evaluated");
            let effect_result = permission_effect_result(
              &core,
              seal.policy(),
              &effect_input,
              seal.decision(),
              slot.slot_id,
              dynamically_authorable,
            )?;
            PermissionBatchResult::capture_proposed_mutation(
              &batch,
              proposed_view,
              &[effect_result],
            )
            .map_err(OdenRev2PermissionError::from)
          };
          match validate() {
            Ok(result) => Ok(result),
            Err(error) => {
              validation_error = Some(error);
              Err(AuthorityStateError::InvalidField("permissionResult"))
            }
          }
        });
      match committed {
        Ok(committed) => {
          Ok(protocol_state_to_public(committed.output().state()))
        }
        Err(_) if validation_error.is_some() => {
          Err(validation_error.expect("checked above"))
        }
        Err(error) => Err(OdenRev2PermissionError::Context(error.to_string())),
      }
    }
  }
}

fn canonical_system_information_kind(
  deno_spelling: &str,
) -> Result<String, OdenRev2PermissionError> {
  static KINDS: OnceLock<Result<Vec<(String, String)>, String>> =
    OnceLock::new();
  let kinds = KINDS
    .get_or_init(|| {
      let payload: Value =
        serde_json::from_str(REV2_RUNTIME_SEMANTIC_PAYLOAD_JSON)
          .map_err(|_| "generated payload is invalid".to_string())?;
      let rows = payload
        .pointer("/policyRulesAndClassifiers/systemInformationKinds")
        .and_then(Value::as_array)
        .ok_or_else(|| "generated sys-kind inventory is absent".to_string())?;
      let mut kinds = Vec::new();
      for row in rows {
        let row = row
          .as_object()
          .ok_or_else(|| "generated sys-kind row is invalid".to_string())?;
        if row.get("disposition").and_then(Value::as_str) != Some("sys-read") {
          continue;
        }
        let canonical = row
          .get("canonical")
          .and_then(Value::as_str)
          .ok_or_else(|| {
            "generated sys-kind canonical name is absent".to_string()
          })?;
        let spellings = row
          .get("denoSpellings")
          .and_then(Value::as_array)
          .ok_or_else(|| {
            "generated sys-kind spellings are absent".to_string()
          })?;
        for spelling in spellings {
          let spelling = spelling.as_str().ok_or_else(|| {
            "generated sys-kind spelling is invalid".to_string()
          })?;
          kinds.push((spelling.to_string(), canonical.to_string()));
        }
      }
      kinds.sort();
      if kinds.windows(2).any(|rows| rows[0].0 == rows[1].0) {
        return Err("generated sys-kind spelling is ambiguous".to_string());
      }
      Ok(kinds)
    })
    .as_ref()
    .map_err(|reason| OdenRev2PermissionError::Protocol(reason.clone()))?;
  let canonical = kinds
    .iter()
    .find(|(spelling, _)| spelling == deno_spelling)
    .map(|(_, canonical)| canonical.clone())
    .ok_or_else(|| {
      OdenRev2PermissionError::DescriptorRefused(
        "OD-CAP-PERMISSION-SYS-KIND-REFUSED".to_string(),
      )
    })?;
  Ok(canonical)
}

fn system_information_effect(
  owner: &crate::rev2::PrincipalRef,
  canonical_kind: &str,
) -> VerifiedHostEffect {
  VerifiedHostEffect {
    resource: json!({ "kind": canonical_kind }),
    occurrence: json!({
      "effectOwner": owner.key,
      "kind": canonical_kind,
    }),
    path_bindings: Vec::new(),
    session_path_binding: None,
    _retained_handles: Vec::new(),
    _installed_bindings: Vec::new(),
  }
}

#[cfg(unix)]
pub(crate) fn bound_platform_path(
  path: &crate::oden_rev2_context::OdenRev2PlatformPath,
) -> PathBuf {
  match path {
    crate::oden_rev2_context::OdenRev2PlatformPath::Unicode(path) => {
      PathBuf::from(path)
    }
    crate::oden_rev2_context::OdenRev2PlatformPath::Bytes(path) => {
      use std::ffi::OsString;
      use std::os::unix::ffi::OsStringExt;
      PathBuf::from(OsString::from_vec(path.clone()))
    }
  }
}

#[cfg(unix)]
pub(crate) fn platform_path_value(path: &Path) -> Value {
  use std::os::unix::ffi::OsStrExt;
  match path.to_str() {
    Some(path) => json!({ "encoding": "unicode", "value": path }),
    None => json!({
      "encoding": "opaque-base64url",
      "value": URL_SAFE_NO_PAD.encode(path.as_os_str().as_bytes()),
    }),
  }
}

#[cfg(unix)]
fn platform_identity(metadata: &std::fs::Metadata) -> Value {
  use std::os::unix::fs::MetadataExt;
  json!({
    "kind": "platform-object",
    "value": format!(
      "unix-dev-ino:{:016x}{:016x}",
      metadata.dev(),
      metadata.ino(),
    ),
  })
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum StaticPathSourceClass {
  Negative,
  Floor,
  Ceiling,
}

#[cfg(unix)]
pub(crate) struct StaticPathRoot<'a> {
  pub(crate) binding: &'a crate::oden_rev2_context::OdenRev2RootBinding,
  pub(crate) retained: &'a crate::oden_rev2_policy::OdenRev2RetainedObject,
  pub(crate) row: &'a crate::oden_rev2_context::OdenRev2StaticAuthorityRow,
  pub(crate) class: StaticPathSourceClass,
}

#[cfg(unix)]
pub(crate) fn collect_static_path_roots<'a>(
  context: &'a OdenRev2RuntimeAuthorityContext,
  constrained_principals: &[crate::rev2::PrincipalRef],
  capability: &str,
) -> Result<Vec<StaticPathRoot<'a>>, OdenRev2PermissionError> {
  let constrained = constrained_principals.iter().collect::<BTreeSet<_>>();
  let mut rows = Vec::new();
  for row in context
    .static_policy()
    .process_denials()
    .iter()
    .chain(context.static_policy().deny_ceiling())
  {
    if row.selector().capability == capability
      && row
        .selector()
        .principal
        .as_ref()
        .is_none_or(|principal| constrained.contains(principal))
    {
      rows.push((row, StaticPathSourceClass::Negative));
    }
  }
  for principal in context.static_policy().principals() {
    if !constrained.contains(principal.principal()) {
      continue;
    }
    rows.extend(
      principal
        .denials()
        .iter()
        .filter(|row| row.selector().capability == capability)
        .map(|row| (row, StaticPathSourceClass::Negative)),
    );
    rows.extend(
      principal
        .floor()
        .iter()
        .filter(|row| row.selector().capability == capability)
        .map(|row| (row, StaticPathSourceClass::Floor)),
    );
    rows.extend(
      principal
        .escalation_ceiling()
        .iter()
        .filter(|row| row.selector().capability == capability)
        .map(|row| (row, StaticPathSourceClass::Ceiling)),
    );
  }
  rows.retain(|(row, _)| {
    row.selector().resource.get("root").is_some()
      && row.selector().resource.get("path").is_some()
  });
  rows.sort_by(|left, right| left.0.source_id().cmp(right.0.source_id()));
  if rows
    .windows(2)
    .any(|rows| rows[0].0.source_id() == rows[1].0.source_id())
  {
    return Err(OdenRev2PermissionError::HostVerifierUnavailable(
      "ambiguous-path-source".to_string(),
    ));
  }
  rows
    .into_iter()
    .map(|(row, class)| {
      let bindings = context
        .bindings()
        .roots()
        .iter()
        .filter(|binding| binding.source_id() == row.source_id())
        .collect::<Vec<_>>();
      let [binding] = bindings.as_slice() else {
        return Err(OdenRev2PermissionError::HostVerifierUnavailable(
          "ambiguous-path-source-binding".to_string(),
        ));
      };
      let retained = context
        .retained_objects()
        .iter()
        .find(|object| {
          object.binding_id() == binding.binding_id() && object.role().is_none()
        })
        .ok_or_else(|| {
          OdenRev2PermissionError::HostVerifierUnavailable(
            "retained-path-root".to_string(),
          )
        })?;
      Ok(StaticPathRoot {
        binding,
        retained,
        row,
        class,
      })
    })
    .collect()
}

#[cfg(unix)]
pub(crate) fn select_primary_path_root<'a>(
  roots: &'a [StaticPathRoot<'a>],
  owner: &crate::rev2::PrincipalRef,
  requested: &Path,
) -> Result<(&'a StaticPathRoot<'a>, PathBuf), OdenRev2PermissionError> {
  let mut candidates = roots
    .iter()
    .filter_map(|root| {
      let canonical_root = bound_platform_path(root.binding.canonical_path());
      let relative =
        requested.strip_prefix(&canonical_root).ok()?.to_path_buf();
      let owner_source = root.row.selector().principal.as_ref() == Some(owner);
      let rank = match (owner_source, root.class) {
        (true, StaticPathSourceClass::Floor) => 0,
        (true, StaticPathSourceClass::Ceiling) => 1,
        (true, StaticPathSourceClass::Negative) => 2,
        (false, StaticPathSourceClass::Negative) => 3,
        (false, StaticPathSourceClass::Floor) => 4,
        (false, StaticPathSourceClass::Ceiling) => 5,
      };
      Some((root, relative, rank, canonical_root.components().count()))
    })
    .collect::<Vec<_>>();
  candidates.sort_by(|left, right| {
    (
      left.2,
      std::cmp::Reverse(left.3),
      left.0.binding.source_id(),
    )
      .cmp(&(
        right.2,
        std::cmp::Reverse(right.3),
        right.0.binding.source_id(),
      ))
  });
  let Some((selected, relative, selected_rank, selected_depth)) =
    candidates.first()
  else {
    return Err(OdenRev2PermissionError::HostVerifierUnavailable(
      "unbound-path-root".to_string(),
    ));
  };
  let selected_lexical =
    platform_path_value(if relative.as_os_str().is_empty() {
      Path::new(".")
    } else {
      relative
    });
  if candidates
    .iter()
    .take_while(|candidate| {
      candidate.2 == *selected_rank && candidate.3 == *selected_depth
    })
    .any(|(candidate, candidate_relative, _, _)| {
      candidate.binding.logical_root() != selected.binding.logical_root()
        || platform_path_value(if candidate_relative.as_os_str().is_empty() {
          Path::new(".")
        } else {
          candidate_relative
        }) != selected_lexical
    })
  {
    return Err(OdenRev2PermissionError::HostVerifierUnavailable(
      "ambiguous-path-root".to_string(),
    ));
  }
  Ok((selected, relative.clone()))
}

#[cfg(unix)]
fn open_relative_component(
  directory: &File,
  component: &std::ffi::OsStr,
  require_directory: bool,
) -> std::io::Result<File> {
  use std::os::fd::AsRawFd;
  use std::os::fd::FromRawFd;
  use std::os::unix::ffi::OsStrExt;
  let component = std::ffi::CString::new(component.as_bytes())
    .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
  #[cfg(target_os = "linux")]
  let mut flags = libc::O_PATH | libc::O_CLOEXEC | libc::O_NOFOLLOW;
  #[cfg(target_os = "macos")]
  let mut flags =
    libc::O_RDONLY | libc::O_NONBLOCK | libc::O_CLOEXEC | libc::O_NOFOLLOW;
  #[cfg(not(any(target_os = "linux", target_os = "macos")))]
  return Err(std::io::Error::new(
    std::io::ErrorKind::Unsupported,
    "Rev2 path identity has no platform adapter",
  ));
  if require_directory {
    flags |= libc::O_DIRECTORY;
  }
  // SAFETY: the retained directory descriptor and NUL-terminated single path
  // component remain live for the call; successful openat returns ownership.
  let fd =
    unsafe { libc::openat(directory.as_raw_fd(), component.as_ptr(), flags) };
  if fd < 0 {
    Err(std::io::Error::last_os_error())
  } else {
    // SAFETY: successful openat returned a new uniquely owned descriptor.
    Ok(unsafe { File::from_raw_fd(fd) })
  }
}

#[cfg(unix)]
fn reopen_bound_root(path: &Path) -> std::io::Result<File> {
  use std::os::unix::fs::OpenOptionsExt;
  std::fs::OpenOptions::new()
    .read(true)
    .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_DIRECTORY)
    .open(path)
}

#[cfg(unix)]
pub(crate) fn relative_platform_path(
  value: &Value,
) -> Result<PathBuf, OdenRev2PermissionError> {
  use std::ffi::OsString;
  use std::os::unix::ffi::OsStringExt;
  let record = value.as_object().ok_or_else(|| {
    OdenRev2PermissionError::HostVerifierUnavailable(
      "path-selector-platform-path".to_string(),
    )
  })?;
  let path = match (
    record.get("encoding").and_then(Value::as_str),
    record.get("value").and_then(Value::as_str),
  ) {
    (Some("unicode"), Some(value)) => PathBuf::from(value),
    (Some("opaque-base64url"), Some(value)) => PathBuf::from(
      OsString::from_vec(URL_SAFE_NO_PAD.decode(value).map_err(|_| {
        OdenRev2PermissionError::HostVerifierUnavailable(
          "path-selector-platform-path".to_string(),
        )
      })?),
    ),
    _ => {
      return Err(OdenRev2PermissionError::HostVerifierUnavailable(
        "path-selector-platform-path".to_string(),
      ));
    }
  };
  if path.is_absolute()
    || path
      .components()
      .any(|component| !matches!(component, Component::Normal(_)))
  {
    return Err(OdenRev2PermissionError::HostVerifierUnavailable(
      "path-selector-platform-path".to_string(),
    ));
  }
  Ok(path)
}

#[cfg(unix)]
struct ObservedRelativePath {
  final_state: Value,
  parent_identity: Value,
  handles: Vec<File>,
}

#[cfg(unix)]
fn observe_relative_path(
  root: &File,
  root_identity: &Value,
  relative: &Path,
) -> Result<ObservedRelativePath, OdenRev2PermissionError> {
  let components = relative.components().collect::<Vec<_>>();
  if components
    .iter()
    .any(|component| !matches!(component, Component::Normal(_)))
  {
    return Err(OdenRev2PermissionError::DescriptorInvalid(
      "normalized path escaped its retained root".to_string(),
    ));
  }
  let mut handles = Vec::new();
  let mut current = root.try_clone().map_err(|_| {
    OdenRev2PermissionError::HostVerifierUnavailable(
      "retained-path-root-clone".to_string(),
    )
  })?;
  let mut parent_identity = root_identity.clone();
  let mut final_state = json!({ "kind": "missing" });
  if components.is_empty() {
    let parent =
      open_relative_component(&current, std::ffi::OsStr::new(".."), true)
        .map_err(|_| {
          OdenRev2PermissionError::HostVerifierUnavailable(
            "retained-root-parent".to_string(),
          )
        })?;
    parent_identity = platform_identity(&parent.metadata().map_err(|_| {
      OdenRev2PermissionError::HostVerifierUnavailable(
        "retained-root-parent-metadata".to_string(),
      )
    })?);
    final_state = json!({
      "kind": "existing",
      "identity": root_identity,
    });
    handles.push(parent);
  } else {
    for (index, component) in components.iter().enumerate() {
      let Component::Normal(component) = component else {
        unreachable!("validated above")
      };
      let final_component = index + 1 == components.len();
      parent_identity =
        platform_identity(&current.metadata().map_err(|_| {
          OdenRev2PermissionError::HostVerifierUnavailable(
            "path-parent-metadata".to_string(),
          )
        })?);
      match open_relative_component(&current, component, !final_component) {
        Ok(opened) => {
          let metadata = opened.metadata().map_err(|_| {
            OdenRev2PermissionError::HostVerifierUnavailable(
              "path-object-metadata".to_string(),
            )
          })?;
          if metadata.file_type().is_symlink()
            || (!final_component && !metadata.is_dir())
          {
            return Err(OdenRev2PermissionError::HostVerifierUnavailable(
              "path-alias-or-type".to_string(),
            ));
          }
          if final_component {
            final_state = json!({
              "kind": "existing",
              "identity": platform_identity(&metadata),
            });
          }
          current = opened.try_clone().map_err(|_| {
            OdenRev2PermissionError::HostVerifierUnavailable(
              "path-object-clone".to_string(),
            )
          })?;
          handles.push(opened);
        }
        Err(error)
          if error.kind() == std::io::ErrorKind::NotFound
            && final_component =>
        {
          break;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
          return Err(OdenRev2PermissionError::HostVerifierUnavailable(
            "path-missing-parent".to_string(),
          ));
        }
        Err(_) => {
          return Err(OdenRev2PermissionError::HostVerifierUnavailable(
            "path-open-no-follow".to_string(),
          ));
        }
      }
    }
  }
  Ok(ObservedRelativePath {
    final_state,
    parent_identity,
    handles,
  })
}

#[cfg(unix)]
struct AuthenticatedRetainedRoot {
  walker: File,
  identity: Value,
  handles: Vec<File>,
}

#[cfg(unix)]
fn authenticate_retained_root(
  root: &StaticPathRoot<'_>,
) -> Result<AuthenticatedRetainedRoot, OdenRev2PermissionError> {
  let expected_identity = root.binding.object_identity().value();
  let retained_metadata = root.retained.file().metadata().map_err(|_| {
    OdenRev2PermissionError::HostVerifierUnavailable(
      "retained-path-root-metadata".to_string(),
    )
  })?;
  let identity = platform_identity(&retained_metadata);
  if identity["value"] != expected_identity {
    return Err(OdenRev2PermissionError::HostVerifierUnavailable(
      "retained-path-root-identity".to_string(),
    ));
  }
  let named_root =
    reopen_bound_root(&bound_platform_path(root.binding.canonical_path()))
      .map_err(|_| {
        OdenRev2PermissionError::HostVerifierUnavailable(
          "retained-path-root-name".to_string(),
        )
      })?;
  if platform_identity(&named_root.metadata().map_err(|_| {
    OdenRev2PermissionError::HostVerifierUnavailable(
      "retained-path-root-name-metadata".to_string(),
    )
  })?)["value"]
    != expected_identity
  {
    return Err(OdenRev2PermissionError::HostVerifierUnavailable(
      "retained-path-root-name-identity".to_string(),
    ));
  }
  let walker = named_root.try_clone().map_err(|_| {
    OdenRev2PermissionError::HostVerifierUnavailable(
      "retained-path-root-clone".to_string(),
    )
  })?;
  Ok(AuthenticatedRetainedRoot {
    walker,
    identity,
    handles: vec![
      root.retained.file().try_clone().map_err(|_| {
        OdenRev2PermissionError::HostVerifierUnavailable(
          "retained-path-root-clone".to_string(),
        )
      })?,
      named_root,
    ],
  })
}

#[cfg(unix)]
fn recheck_retained_root(
  root: &StaticPathRoot<'_>,
) -> Result<File, OdenRev2PermissionError> {
  let expected_identity = root.binding.object_identity().value();
  let after = root.retained.file().metadata().map_err(|_| {
    OdenRev2PermissionError::HostVerifierUnavailable(
      "retained-path-root-metadata".to_string(),
    )
  })?;
  if platform_identity(&after)["value"] != expected_identity {
    return Err(OdenRev2PermissionError::HostVerifierUnavailable(
      "retained-path-root-race".to_string(),
    ));
  }
  let named_root =
    reopen_bound_root(&bound_platform_path(root.binding.canonical_path()))
      .map_err(|_| {
        OdenRev2PermissionError::HostVerifierUnavailable(
          "retained-path-root-name-race".to_string(),
        )
      })?;
  if platform_identity(&named_root.metadata().map_err(|_| {
    OdenRev2PermissionError::HostVerifierUnavailable(
      "retained-path-root-name-metadata".to_string(),
    )
  })?)["value"]
    != expected_identity
  {
    return Err(OdenRev2PermissionError::HostVerifierUnavailable(
      "retained-path-root-name-race".to_string(),
    ));
  }
  Ok(named_root)
}

#[cfg(unix)]
fn verified_path_effect(
  context: &OdenRev2RuntimeAuthorityContext,
  constrained_principals: &[crate::rev2::PrincipalRef],
  owner: &crate::rev2::PrincipalRef,
  capability: &str,
  requested: &Path,
) -> Result<VerifiedHostEffect, OdenRev2PermissionError> {
  let roots =
    collect_static_path_roots(context, constrained_principals, capability)?;
  let (primary, relative) = select_primary_path_root(&roots, owner, requested)?;
  let primary_root = authenticate_retained_root(primary)?;
  let mut handles = Vec::new();
  let observed = observe_relative_path(
    &primary_root.walker,
    &primary_root.identity,
    &relative,
  )?;
  let final_state = observed.final_state;
  let parent_identity = observed.parent_identity;
  handles.extend(primary_root.handles);
  handles.extend(observed.handles);
  let final_object_identities = final_state
    .get("identity")
    .cloned()
    .into_iter()
    .collect::<Vec<_>>();
  let parent_identities = if final_state["kind"] == "missing" {
    vec![parent_identity.clone()]
  } else {
    Vec::new()
  };
  let mut path_bindings = Vec::with_capacity(roots.len());
  for source in &roots {
    let source_root = authenticate_retained_root(source)?;
    let source_relative = if source.class == StaticPathSourceClass::Negative {
      if source
        .row
        .selector()
        .resource
        .get("root")
        .and_then(Value::as_str)
        != Some(source.binding.logical_root())
      {
        return Err(OdenRev2PermissionError::HostVerifierUnavailable(
          "path-source-logical-root".to_string(),
        ));
      }
      Some(relative_platform_path(
        source.row.selector().resource.get("path").ok_or_else(|| {
          OdenRev2PermissionError::HostVerifierUnavailable(
            "path-selector-platform-path".to_string(),
          )
        })?,
      )?)
    } else {
      let source_host_root =
        bound_platform_path(source.binding.canonical_path());
      requested
        .strip_prefix(&source_host_root)
        .ok()
        .map(Path::to_path_buf)
    };
    let Some(source_relative) = source_relative else {
      handles.extend(source_root.handles);
      continue;
    };
    let source_observed = observe_relative_path(
      &source_root.walker,
      &source_root.identity,
      &source_relative,
    )?;
    let source_final_identities = source_observed
      .final_state
      .get("identity")
      .cloned()
      .into_iter()
      .collect::<Vec<_>>();
    let source_parent_identities =
      if source_observed.final_state["kind"] == "missing" {
        vec![source_observed.parent_identity]
      } else {
        Vec::new()
      };
    handles.extend(source_root.handles);
    handles.extend(source_observed.handles);
    path_bindings.push(PathBindingInput {
      source_id: source.binding.source_id().to_string(),
      // The fact was independently resolved through `source`'s authenticated
      // retained descriptor. Shared-core matching keys facts by the one root
      // id carried in the occurrence, so the host-private projection binds it
      // to that separately authenticated occurrence root id.
      root_binding_id: primary.binding.binding_id().to_string(),
      final_object_identities: source_final_identities,
      parent_identities: source_parent_identities,
    });
  }
  for source in &roots {
    handles.push(recheck_retained_root(source)?);
  }

  let lexical = if relative.as_os_str().is_empty() {
    Path::new(".")
  } else {
    relative.as_path()
  };
  let session_path_binding = PathBindingInput {
    source_id: primary.binding.source_id().to_string(),
    root_binding_id: primary.binding.binding_id().to_string(),
    final_object_identities,
    parent_identities,
  };
  Ok(VerifiedHostEffect {
    resource: json!({
      "kind": "path-exact",
      "root": primary.binding.logical_root(),
      "path": platform_path_value(lexical),
    }),
    occurrence: json!({
      "effectOwner": owner.key,
      "root": primary.binding.logical_root(),
      "followMode": "follow-final",
      "finalObjectState": final_state,
      "parentIdentity": parent_identity,
      "rootBindingId": primary.binding.binding_id(),
      "lexicalPath": platform_path_value(lexical),
    }),
    path_bindings,
    session_path_binding: Some(session_path_binding),
    _retained_handles: handles,
    _installed_bindings: Vec::new(),
  })
}

#[cfg(not(unix))]
fn verified_path_effect(
  _context: &OdenRev2RuntimeAuthorityContext,
  _constrained_principals: &[crate::rev2::PrincipalRef],
  _owner: &crate::rev2::PrincipalRef,
  _capability: &str,
  _requested: &Path,
) -> Result<VerifiedHostEffect, OdenRev2PermissionError> {
  Err(OdenRev2PermissionError::HostVerifierUnavailable(
    "path-platform-unsupported".to_string(),
  ))
}

fn exact_static_resource(
  context: &OdenRev2RuntimeAuthorityContext,
  source_id: &str,
  capability: &str,
) -> Result<Value, OdenRev2PermissionError> {
  let mut resources = context
    .static_policy()
    .principals()
    .iter()
    .flat_map(|principal| principal.floor())
    .filter(|row| {
      row.source_id() == source_id && row.selector().capability == capability
    })
    .map(|row| row.selector().resource.clone())
    .collect::<Vec<_>>();
  resources.sort_by_key(|resource| {
    crate::rev2::canonical_json(resource).unwrap_or_default()
  });
  resources.dedup();
  let [resource] = resources.as_slice() else {
    return Err(OdenRev2PermissionError::HostVerifierUnavailable(format!(
      "{capability}-static-binding"
    )));
  };
  Ok(resource.clone())
}

fn verified_installed_effect(
  context: &OdenRev2RuntimeAuthorityContext,
  owner: &crate::rev2::PrincipalRef,
  capability: &str,
  requested: &Path,
) -> Result<VerifiedHostEffect, OdenRev2PermissionError> {
  let mut matches = context
    .installed_executables()
    .as_slice()
    .iter()
    .filter(|binding| binding.role() == "object")
    .filter(|binding| binding.canonical_path() == requested)
    .filter(|binding| binding.principal().is_none_or(|value| value == owner))
    .filter_map(|binding| {
      exact_static_resource(context, binding.source_id(), capability)
        .ok()
        .map(|resource| (binding, resource))
    })
    .filter(|(binding, resource)| {
      resource
        .get("objectIdentity")
        .and_then(|identity| identity.get("kind"))
        .and_then(Value::as_str)
        == Some("verified-content")
        && resource
          .get("objectIdentity")
          .and_then(|identity| identity.get("value"))
          .and_then(Value::as_str)
          == Some(binding.canonical_content_identity())
    })
    .collect::<Vec<_>>();
  let [(object, resource)] = matches.as_mut_slice() else {
    return Err(OdenRev2PermissionError::HostVerifierUnavailable(format!(
      "{capability}-installed-binding"
    )));
  };
  let requested_path = resource.get("path").cloned().ok_or_else(|| {
    OdenRev2PermissionError::HostVerifierUnavailable(format!(
      "{capability}-logical-path"
    ))
  })?;
  let object_identity = resource["objectIdentity"].clone();
  let occurrence = if capability == "ffi:load" {
    json!({
      "effectOwner": owner.key,
      "objectIdentity": object_identity,
      "requestedPath": requested_path,
    })
  } else {
    let interpreter_identity = resource
      .get("interpreterIdentity")
      .cloned()
      .ok_or_else(|| {
        OdenRev2PermissionError::HostVerifierUnavailable(
          "process:spawn-interpreter-identity".to_string(),
        )
      })?;
    let interpreter_digest = interpreter_identity
      .get("value")
      .and_then(Value::as_str)
      .ok_or_else(|| {
        OdenRev2PermissionError::HostVerifierUnavailable(
          "process:spawn-interpreter-identity".to_string(),
        )
      })?;
    let interpreters = context
      .installed_executables()
      .as_slice()
      .iter()
      .filter(|binding| {
        binding.role() == "interpreter"
          && binding.source_id() == object.source_id()
          && binding.canonical_content_identity() == interpreter_digest
          && binding.principal() == object.principal()
      })
      .collect::<Vec<_>>();
    let [_interpreter] = interpreters.as_slice() else {
      return Err(OdenRev2PermissionError::HostVerifierUnavailable(
        "process:spawn-installed-interpreter".to_string(),
      ));
    };
    let launch_value = requested_path
      .get("value")
      .and_then(Value::as_str)
      .ok_or_else(|| {
        OdenRev2PermissionError::HostVerifierUnavailable(
          "process:spawn-logical-entry-path".to_string(),
        )
      })?;
    if interpreter_identity != object_identity {
      // C03 currently retains the interpreter's authenticated host path but
      // not its canonical logical launch path. The generated launchSet cannot
      // be populated honestly, and checking/reopening a shebang path here
      // would discard the immutable binding. Keep scripts closed until that
      // trusted logical fact is part of the armed binding.
      return Err(OdenRev2PermissionError::HostVerifierUnavailable(
        "process:spawn-script-logical-interpreter-path".to_string(),
      ));
    }
    let launch_set = vec![json!({ "kind": "entry", "value": launch_value })];
    json!({
      "effectOwner": owner.key,
      "objectIdentity": object_identity,
      "interpreterIdentity": interpreter_identity,
      "requestedPath": requested_path,
      "launchSet": launch_set,
    })
  };
  let mut installed_bindings = vec![(*object).clone()];
  if capability == "process:spawn" {
    let interpreter_identity = resource["interpreterIdentity"]["value"]
      .as_str()
      .expect("validated above");
    let interpreter = context
      .installed_executables()
      .as_slice()
      .iter()
      .find(|binding| {
        binding.role() == "interpreter"
          && binding.source_id() == object.source_id()
          && binding.canonical_content_identity() == interpreter_identity
          && binding.principal() == object.principal()
      })
      .expect("unique interpreter validated above");
    installed_bindings.push(interpreter.clone());
  }
  Ok(VerifiedHostEffect {
    resource: resource.clone(),
    occurrence,
    path_bindings: Vec::new(),
    session_path_binding: None,
    _retained_handles: Vec::new(),
    _installed_bindings: installed_bindings,
  })
}

pub fn oden_capsec_rev2_permission_operation(
  context: &OdenRev2RuntimeAuthorityContext,
  permissions: &PermissionsContainer,
  operation: OdenRev2PermissionOperation,
  descriptor: &OdenDynamicPermissionDescriptor<'_>,
) -> Result<PublicPermissionState, OdenRev2PermissionError> {
  let branch = select_branch(descriptor)?;
  let operation = PermissionOperation::from(operation);
  // This enforces generated request/revoke dispositions even for branches
  // whose object verifier is not installed yet (notably request run/ffi).
  let _ = select_generated_permission_branch(branch.id, operation)?;
  match descriptor.name {
    "sys" => {
      let spelling = descriptor.kind.expect("generated scoped branch");
      permissions
        .descriptor_parser
        .parse_sys_descriptor(spelling)
        .map_err(|error| {
          OdenRev2PermissionError::DescriptorInvalid(error.to_string())
        })?;
      let canonical = canonical_system_information_kind(spelling)?;
      evaluate_singleton_permission(
        context,
        branch,
        operation,
        true,
        |_, owner| Ok(system_information_effect(owner, &canonical)),
      )
    }
    "read" => {
      let parsed = permissions
        .descriptor_parser
        .parse_read_descriptor(
          descriptor.path.expect("generated scoped branch"),
        )
        .map_err(|error| {
          OdenRev2PermissionError::DescriptorInvalid(error.to_string())
        })?;
      let path = parsed.0.resolved_path().to_path_buf();
      evaluate_singleton_permission(
        context,
        branch,
        operation,
        true,
        |principals, owner| {
          verified_path_effect(context, principals, owner, "fs:read", &path)
        },
      )
    }
    "write" => {
      let parsed = permissions
        .descriptor_parser
        .parse_write_descriptor(
          descriptor.path.expect("generated scoped branch"),
        )
        .map_err(|error| {
          OdenRev2PermissionError::DescriptorInvalid(error.to_string())
        })?;
      let path = parsed.0.resolved_path().to_path_buf();
      evaluate_singleton_permission(
        context,
        branch,
        operation,
        true,
        |principals, owner| {
          verified_path_effect(context, principals, owner, "fs:write", &path)
        },
      )
    }
    "run" => {
      let command = descriptor.command.expect("generated scoped branch");
      if !crate::AllowRunDescriptor::is_path(command)
        || !Path::new(command).is_absolute()
      {
        return Err(OdenRev2PermissionError::DescriptorRefused(
          "OD-CAP-PERMISSION-RUN-UNRESOLVED".to_string(),
        ));
      }
      let parsed = permissions
        .descriptor_parser
        .parse_allow_run_descriptor(command)
        .map_err(|error| {
          OdenRev2PermissionError::DescriptorInvalid(error.to_string())
        })?;
      let crate::AllowRunDescriptorParseResult::Descriptor(parsed) = parsed
      else {
        return Err(OdenRev2PermissionError::HostVerifierUnavailable(
          "process:spawn-unresolved-command".to_string(),
        ));
      };
      let path = parsed.0.resolved_path().to_path_buf();
      evaluate_singleton_permission(
        context,
        branch,
        operation,
        false,
        |_, owner| {
          verified_installed_effect(context, owner, "process:spawn", &path)
        },
      )
    }
    "ffi" => {
      let parsed = permissions
        .descriptor_parser
        .parse_ffi_descriptor(descriptor.path.expect("generated scoped branch"))
        .map_err(|error| {
          OdenRev2PermissionError::DescriptorInvalid(error.to_string())
        })?;
      let path = parsed.0.resolved_path().to_path_buf();
      evaluate_singleton_permission(
        context,
        branch,
        operation,
        false,
        |_, owner| verified_installed_effect(context, owner, "ffi:load", &path),
      )
    }
    _ => Err(OdenRev2PermissionError::DescriptorRefused(
      "OD-CAP-PERMISSION-NO-REV2-CAPABILITY".to_string(),
    )),
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::oden_rev2_policy::tests as policy_fixtures;
  use crate::rev2::PrincipalRef;
  use std::sync::Arc;

  struct ActorGuard;

  impl Drop for ActorGuard {
    fn drop(&mut self) {
      crate::oden_rev2_set_permission_actors_for_test(None);
    }
  }

  fn install_test_actor() -> (ActorGuard, PrincipalRef) {
    let owner = PrincipalRef {
      kind: crate::rev2::PrincipalKind::Package,
      key: "pkg:sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
    };
    crate::oden_rev2_set_permission_actors_for_test(Some((
      vec![owner.clone()],
      owner.clone(),
    )));
    (ActorGuard, owner)
  }

  fn install_test_actor_set(
    principals: Vec<PrincipalRef>,
    owner: PrincipalRef,
  ) -> ActorGuard {
    crate::oden_rev2_set_permission_actors_for_test(Some((principals, owner)));
    ActorGuard
  }

  fn test_permissions() -> PermissionsContainer {
    let parser =
      crate::runtime_descriptor_parser::RuntimePermissionDescriptorParser::new(
        sys_traits::impls::RealSys,
      );
    PermissionsContainer::new(
      Arc::new(parser),
      crate::Permissions::none_without_prompt(),
    )
  }

  fn temp_root(label: &str) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let unique = std::time::SystemTime::now()
      .duration_since(std::time::UNIX_EPOCH)
      .unwrap()
      .as_nanos();
    let root = std::env::temp_dir().join(format!(
      "oden-rev2-permission-{label}-{}-{unique}",
      std::process::id()
    ));
    std::fs::create_dir(&root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
      .unwrap();
    std::fs::canonicalize(root).unwrap()
  }

  #[cfg(unix)]
  fn path_context(
    root: &Path,
    owner: &PrincipalRef,
    ceiling_only: bool,
  ) -> OdenRev2RuntimeAuthorityContext {
    path_context_with_deny(root, owner, ceiling_only, false, None)
  }

  #[cfg(unix)]
  fn path_context_with_deny(
    root: &Path,
    owner: &PrincipalRef,
    ceiling_only: bool,
    floor_and_ceiling: bool,
    denied_path: Option<&Path>,
  ) -> OdenRev2RuntimeAuthorityContext {
    let core = Rev2Core::embedded().unwrap();
    let row = |source_id: &str, capability: &str| {
      let selector = core
        .normalize_selector(
          &AuthoritySelectorInput {
            identity: EngineIdentity::embedded(),
            principal: Some(owner.clone()),
            capability: capability.to_string(),
            resource: json!({
              "kind": "path-tree",
              "path": { "encoding": "unicode", "value": "data" },
              "root": "$PROJECT",
            }),
          },
          SelectorPolarity::Positive,
        )
        .unwrap();
      json!({ "sourceId": source_id, "selector": selector })
    };
    let mut snapshot = policy_fixtures::candidate_with_env_policy(
      policy_fixtures::hermetic_target(),
    );
    let rows = vec![
      row("floor:path-read", "fs:read"),
      row("floor:path-write", "fs:write"),
    ];
    let ceiling_rows = if floor_and_ceiling {
      vec![
        row("ceiling:path-read", "fs:read"),
        row("ceiling:path-write", "fs:write"),
      ]
    } else {
      rows.clone()
    };
    let denials = denied_path
      .map(|denied_path| {
        let relative = denied_path.strip_prefix(root).unwrap();
        let selector = core
          .normalize_selector(
            &AuthoritySelectorInput {
              identity: EngineIdentity::embedded(),
              principal: Some(owner.clone()),
              capability: "fs:read".to_string(),
              resource: json!({
                "kind": "path-exact",
                "path": platform_path_value(relative),
                "root": "$PROJECT",
              }),
            },
            SelectorPolarity::Negative,
          )
          .unwrap();
        vec![json!({ "sourceId": "deny:path-read", "selector": selector })]
      })
      .unwrap_or_default();
    snapshot["canonicalPolicy"]["principals"] = json!([{
      "principal": owner,
      "binding": {
        "resolverId": "fixture-lock-resolver/2",
        "bindingDigest": crate::rev2_registry_generated::REV2_VOCAB_DIGEST,
      },
      "floor": if ceiling_only { Vec::<Value>::new() } else { rows },
      "escalationCeiling": if ceiling_only || floor_and_ceiling { ceiling_rows } else { Vec::<Value>::new() },
      "denials": denials,
    }]);
    let mut root_bindings = vec![
      {
        let mut binding = serde_json::Map::new();
        binding.insert("sourceId".to_string(), json!("floor:path-read"));
        binding.insert("logicalRoot".to_string(), json!("$PROJECT"));
        binding.insert("principal".to_string(), json!(owner));
        binding.insert("rootBindingId".to_string(), json!("root-binding:read"));
        binding.insert(
          "canonicalPath".to_string(),
          json!({ "encoding": "unicode", "value": root.to_str().unwrap() }),
        );
        binding.insert(
          "objectIdentity".to_string(),
          policy_fixtures::platform_identity(root),
        );
        binding.insert(
          "bindingProvenanceDigest".to_string(),
          json!(crate::rev2_registry_generated::REV2_REGISTRY_DIGEST),
        );
        Value::Object(binding)
      },
      {
        let mut binding = serde_json::Map::new();
        binding.insert("sourceId".to_string(), json!("floor:path-write"));
        binding.insert("logicalRoot".to_string(), json!("$PROJECT"));
        binding.insert("principal".to_string(), json!(owner));
        binding
          .insert("rootBindingId".to_string(), json!("root-binding:write"));
        binding.insert(
          "canonicalPath".to_string(),
          json!({ "encoding": "unicode", "value": root.to_str().unwrap() }),
        );
        binding.insert(
          "objectIdentity".to_string(),
          policy_fixtures::platform_identity(root),
        );
        binding.insert(
          "bindingProvenanceDigest".to_string(),
          json!(crate::rev2_registry_generated::REV2_REGISTRY_DIGEST),
        );
        Value::Object(binding)
      },
    ];
    if denied_path.is_some() {
      let mut binding = root_bindings[0].clone();
      binding["sourceId"] = json!("deny:path-read");
      binding["rootBindingId"] = json!("root-binding:deny-read");
      root_bindings.push(binding);
    }
    if floor_and_ceiling {
      for (source_id, binding_id) in [
        ("ceiling:path-read", "root-binding:ceiling-read"),
        ("ceiling:path-write", "root-binding:ceiling-write"),
      ] {
        let mut binding = root_bindings
          .iter()
          .find(|binding| {
            binding["sourceId"]
              == json!(source_id.replace("ceiling:", "floor:"))
          })
          .unwrap()
          .clone();
        binding["sourceId"] = json!(source_id);
        binding["rootBindingId"] = json!(binding_id);
        root_bindings.push(binding);
      }
    }
    root_bindings
      .sort_by_key(|binding| crate::rev2::canonical_json(binding).unwrap());
    snapshot["rootBindings"] = Value::Array(root_bindings);
    policy_fixtures::refresh_digests(&mut snapshot);
    let mut loaded =
      policy_fixtures::verify_armable_snapshot(snapshot, &[91_u8; 32]).unwrap();
    loaded.install_immutable_executables(root).unwrap();
    OdenRev2RuntimeAuthorityContext::install_for_test(loaded).unwrap()
  }

  #[cfg(unix)]
  fn overlapping_deputy_path_context(
    shallow_root: &Path,
    deep_root: &Path,
    denied: &Path,
    unrelated: &Path,
    owner: &PrincipalRef,
    deputy: &PrincipalRef,
  ) -> OdenRev2RuntimeAuthorityContext {
    let core = Rev2Core::embedded().unwrap();
    let selector = |principal: &PrincipalRef,
                    capability: &str,
                    kind: &str,
                    root: &str,
                    path: &Path,
                    polarity: SelectorPolarity| {
      core
        .normalize_selector(
          &AuthoritySelectorInput {
            identity: EngineIdentity::embedded(),
            principal: Some(principal.clone()),
            capability: capability.to_string(),
            resource: json!({
              "kind": kind,
              "path": platform_path_value(path),
              "root": root,
            }),
          },
          polarity,
        )
        .unwrap()
    };
    let owner_floor = json!({
      "sourceId": "floor:owner-deep",
      "selector": selector(
        owner,
        "fs:read",
        "path-tree",
        "$PACKAGE",
        Path::new("data"),
        SelectorPolarity::Positive,
      ),
    });
    let deputy_floor = json!({
      "sourceId": "floor:deputy-exact",
      "selector": selector(
        deputy,
        "fs:read",
        "path-exact",
        "$PACKAGE",
        unrelated.strip_prefix(deep_root).unwrap(),
        SelectorPolarity::Positive,
      ),
    });
    let deputy_deny = json!({
      "sourceId": "deny:deputy-shallow",
      "selector": selector(
        deputy,
        "fs:read",
        "path-exact",
        "$PROJECT",
        denied.strip_prefix(shallow_root).unwrap(),
        SelectorPolarity::Negative,
      ),
    });
    let principal_row =
      |principal: &PrincipalRef, floor: Vec<Value>, denials: Vec<Value>| {
        json!({
          "principal": principal,
          "binding": {
            "resolverId": "fixture-lock-resolver/2",
            "bindingDigest": crate::rev2_registry_generated::REV2_VOCAB_DIGEST,
          },
          "floor": floor,
          "escalationCeiling": [],
          "denials": denials,
        })
      };
    let mut principals = vec![
      principal_row(owner, vec![owner_floor], Vec::new()),
      principal_row(deputy, vec![deputy_floor], vec![deputy_deny]),
    ];
    principals
      .sort_by_key(|principal| crate::rev2::canonical_json(principal).unwrap());
    let root_binding = |source_id: &str,
                        logical_root: &str,
                        principal: &PrincipalRef,
                        binding_id: &str,
                        canonical_root: &Path| {
      json!({
        "sourceId": source_id,
        "logicalRoot": logical_root,
        "principal": principal,
        "rootBindingId": binding_id,
        "canonicalPath": platform_path_value(canonical_root),
        "objectIdentity": policy_fixtures::platform_identity(canonical_root),
        "bindingProvenanceDigest": crate::rev2_registry_generated::REV2_REGISTRY_DIGEST,
      })
    };
    let mut root_bindings = vec![
      root_binding(
        "floor:owner-deep",
        "$PACKAGE",
        owner,
        "root-binding:owner-deep",
        deep_root,
      ),
      root_binding(
        "floor:deputy-exact",
        "$PACKAGE",
        deputy,
        "root-binding:deputy-deep",
        deep_root,
      ),
      root_binding(
        "deny:deputy-shallow",
        "$PROJECT",
        deputy,
        "root-binding:deputy-shallow",
        shallow_root,
      ),
    ];
    root_bindings
      .sort_by_key(|binding| crate::rev2::canonical_json(binding).unwrap());
    let mut snapshot = policy_fixtures::candidate_with_env_policy(
      policy_fixtures::hermetic_target(),
    );
    snapshot["canonicalPolicy"]["principals"] = Value::Array(principals);
    snapshot["rootBindings"] = Value::Array(root_bindings);
    policy_fixtures::refresh_digests(&mut snapshot);
    let mut loaded =
      policy_fixtures::verify_armable_snapshot(snapshot, &[95_u8; 32]).unwrap();
    loaded.install_immutable_executables(shallow_root).unwrap();
    OdenRev2RuntimeAuthorityContext::install_for_test(loaded).unwrap()
  }

  #[cfg(unix)]
  fn executable_context(
    object: &Path,
    interpreter: &Path,
    owner: &PrincipalRef,
  ) -> OdenRev2RuntimeAuthorityContext {
    let mut snapshot = policy_fixtures::candidate_with_executable_policy(
      policy_fixtures::hermetic_target(),
      object,
      interpreter,
    );
    snapshot["canonicalPolicy"]["principals"][0]["principal"] =
      serde_json::to_value(owner).unwrap();
    snapshot["canonicalPolicy"]["principals"][0]["floor"][0]["selector"]["principal"] =
      serde_json::to_value(owner).unwrap();
    for binding in snapshot["executableBindings"].as_array_mut().unwrap() {
      binding["principal"] = serde_json::to_value(owner).unwrap();
    }
    policy_fixtures::refresh_digests(&mut snapshot);
    let mut loaded =
      policy_fixtures::verify_armable_snapshot(snapshot, &[92_u8; 32]).unwrap();
    loaded
      .install_immutable_executables(object.parent().unwrap())
      .unwrap();
    OdenRev2RuntimeAuthorityContext::install_for_test(loaded).unwrap()
  }

  #[cfg(unix)]
  fn ffi_context(
    library: &Path,
    owner: &PrincipalRef,
  ) -> OdenRev2RuntimeAuthorityContext {
    let mut snapshot = policy_fixtures::candidate_with_executable_policy(
      policy_fixtures::hermetic_target(),
      library,
      library,
    );
    let content = policy_fixtures::file_sha256_digest(library);
    let selector = Rev2Core::embedded()
      .unwrap()
      .normalize_selector(
        &AuthoritySelectorInput {
          identity: EngineIdentity::embedded(),
          principal: Some(owner.clone()),
          capability: "ffi:load".to_string(),
          resource: json!({
            "objectIdentity": { "kind": "verified-content", "value": content },
            "path": { "encoding": "unicode", "value": "$PACKAGE/lib/example.dylib" },
          }),
        },
        SelectorPolarity::Positive,
      )
      .unwrap();
    snapshot["canonicalPolicy"]["principals"][0] = json!({
      "principal": owner,
      "binding": {
        "resolverId": "fixture-lock-resolver/2",
        "bindingDigest": crate::rev2_registry_generated::REV2_VOCAB_DIGEST,
      },
      "floor": [{ "sourceId": "floor:spawn", "selector": selector }],
      "escalationCeiling": [],
      "denials": [],
    });
    let object = snapshot["executableBindings"][1].clone();
    snapshot["executableBindings"] = json!([object]);
    snapshot["executableBindings"][0]["principal"] =
      serde_json::to_value(owner).unwrap();
    policy_fixtures::refresh_digests(&mut snapshot);
    let mut loaded =
      policy_fixtures::verify_armable_snapshot(snapshot, &[93_u8; 32]).unwrap();
    loaded
      .install_immutable_executables(library.parent().unwrap())
      .unwrap();
    OdenRev2RuntimeAuthorityContext::install_for_test(loaded).unwrap()
  }

  fn sys_context(owner: &PrincipalRef) -> OdenRev2RuntimeAuthorityContext {
    let core = Rev2Core::embedded().unwrap();
    let kinds = [
      "network-interfaces",
      "os-release",
      "os-uptime",
      "system-memory-info",
    ];
    let floor = kinds
      .iter()
      .map(|kind| {
        let selector = core
          .normalize_selector(
            &AuthoritySelectorInput {
              identity: EngineIdentity::embedded(),
              principal: Some(owner.clone()),
              capability: "sys:read".to_string(),
              resource: json!({ "kind": kind }),
            },
            SelectorPolarity::Positive,
          )
          .unwrap();
        json!({ "sourceId": format!("floor:sys:{kind}"), "selector": selector })
      })
      .collect::<Vec<_>>();
    let mut snapshot = policy_fixtures::candidate_with_env_policy(
      policy_fixtures::hermetic_target(),
    );
    snapshot["canonicalPolicy"]["principals"][0] = json!({
      "principal": owner,
      "binding": {
        "resolverId": "fixture-lock-resolver/2",
        "bindingDigest": crate::rev2_registry_generated::REV2_VOCAB_DIGEST,
      },
      "floor": floor,
      "escalationCeiling": [],
      "denials": [],
    });
    policy_fixtures::refresh_digests(&mut snapshot);
    let mut loaded =
      policy_fixtures::verify_armable_snapshot(snapshot, &[94_u8; 32]).unwrap();
    loaded
      .install_immutable_executables(Path::new("."))
      .unwrap();
    OdenRev2RuntimeAuthorityContext::install_for_test(loaded).unwrap()
  }

  fn descriptor<'a>(
    name: &'a str,
    path: Option<&'a str>,
    kind: Option<&'a str>,
  ) -> OdenDynamicPermissionDescriptor<'a> {
    OdenDynamicPermissionDescriptor {
      name,
      path,
      host: None,
      variable: None,
      kind,
      command: None,
      presence: crate::OdenDynamicPermissionFieldPresence::from_values(
        path, None, None, kind, None,
      ),
    }
  }

  #[cfg(unix)]
  fn install_exact_session_path_grant(
    context: &OdenRev2RuntimeAuthorityContext,
    owner: &PrincipalRef,
    path: &Path,
  ) {
    let verified = verified_path_effect(
      context,
      std::slice::from_ref(owner),
      owner,
      "fs:read",
      path,
    )
    .unwrap();
    let core = Rev2Core::embedded().unwrap();
    let positive = core
      .normalize_selector(
        &AuthoritySelectorInput {
          identity: EngineIdentity::embedded(),
          principal: Some(owner.clone()),
          capability: "fs:read".to_string(),
          resource: verified.resource.clone(),
        },
        SelectorPolarity::Positive,
      )
      .unwrap();
    let revocation = core
      .normalize_selector(
        &AuthoritySelectorInput {
          identity: EngineIdentity::embedded(),
          principal: Some(owner.clone()),
          capability: "fs:read".to_string(),
          resource: verified.resource,
        },
        SelectorPolarity::Negative,
      )
      .unwrap();
    let path_fact = AuthorityPathFact::capture_verified(
      verified.session_path_binding.as_ref().unwrap(),
      &positive,
      &verified.occurrence,
    )
    .unwrap();
    let mut transaction =
      context.authority_state().begin_transaction().unwrap();
    transaction
      .reconcile_session_grant(
        owner,
        owner,
        &positive,
        &revocation,
        Some(&path_fact),
      )
      .unwrap();
    context.authority_state().commit(transaction).unwrap();
  }

  #[cfg(unix)]
  #[test]
  fn retained_path_verifier_grants_exact_objects_and_refuses_alias_or_root_replacement()
   {
    use std::os::unix::fs::symlink;

    let (_actor, owner) = install_test_actor();
    let root = temp_root("paths");
    std::fs::create_dir(root.join("data")).unwrap();
    let file = root.join("data/file.txt");
    std::fs::write(&file, b"trusted").unwrap();
    let alias = root.join("data/alias.txt");
    symlink(&file, &alias).unwrap();
    let context = path_context(&root, &owner, false);
    let permissions = test_permissions();

    for name in ["read", "write"] {
      assert_eq!(
        oden_capsec_rev2_permission_operation(
          &context,
          &permissions,
          OdenRev2PermissionOperation::Query,
          &descriptor(name, Some(file.to_str().unwrap()), None),
        )
        .unwrap(),
        PublicPermissionState::Granted,
      );
    }
    assert!(matches!(
      oden_capsec_rev2_permission_operation(
        &context,
        &permissions,
        OdenRev2PermissionOperation::Query,
        &descriptor("read", Some(alias.to_str().unwrap()), None),
      ),
      Err(OdenRev2PermissionError::HostVerifierUnavailable(reason))
        if reason == "path-alias-or-type" || reason == "path-open-no-follow"
    ));

    let old_root = root.with_extension("retained-old");
    std::fs::rename(&root, &old_root).unwrap();
    std::fs::create_dir(&root).unwrap();
    std::fs::create_dir(root.join("data")).unwrap();
    std::fs::write(&file, b"replacement").unwrap();
    assert!(matches!(
      oden_capsec_rev2_permission_operation(
        &context,
        &permissions,
        OdenRev2PermissionOperation::Query,
        &descriptor("read", Some(file.to_str().unwrap()), None),
      ),
      Err(OdenRev2PermissionError::HostVerifierUnavailable(reason))
        if reason == "retained-path-root-name-identity"
    ));
    drop(context);
    std::fs::remove_dir_all(root).unwrap();
    std::fs::remove_dir_all(old_root).unwrap();
  }

  #[cfg(unix)]
  #[test]
  fn static_path_denial_uses_its_own_resolved_object_fact_not_the_current_operation()
   {
    let (_actor, owner) = install_test_actor();
    let root = temp_root("static-path-denial");
    std::fs::create_dir(root.join("data")).unwrap();
    let denied = root.join("data/denied.txt");
    let alias = root.join("data/denied-hardlink.txt");
    let unrelated = root.join("data/unrelated.txt");
    std::fs::write(&denied, b"denied").unwrap();
    std::fs::hard_link(&denied, &alias).unwrap();
    std::fs::write(&unrelated, b"unrelated").unwrap();
    let context =
      path_context_with_deny(&root, &owner, false, false, Some(&denied));
    let permissions = test_permissions();

    assert_eq!(
      oden_capsec_rev2_permission_operation(
        &context,
        &permissions,
        OdenRev2PermissionOperation::Query,
        &descriptor("read", Some(alias.to_str().unwrap()), None),
      )
      .unwrap(),
      PublicPermissionState::Denied,
    );
    assert_eq!(
      oden_capsec_rev2_permission_operation(
        &context,
        &permissions,
        OdenRev2PermissionOperation::Query,
        &descriptor("read", Some(unrelated.to_str().unwrap()), None),
      )
      .unwrap(),
      PublicPermissionState::Granted,
    );

    let alias_facts = verified_path_effect(
      &context,
      std::slice::from_ref(&owner),
      &owner,
      "fs:read",
      &alias,
    )
    .unwrap();
    let unrelated_facts = verified_path_effect(
      &context,
      std::slice::from_ref(&owner),
      &owner,
      "fs:read",
      &unrelated,
    )
    .unwrap();
    fn denial_fact(effect: &VerifiedHostEffect) -> &PathBindingInput {
      effect
        .path_bindings
        .iter()
        .find(|binding| binding.source_id == "deny:path-read")
        .unwrap()
    }
    assert_eq!(
      denial_fact(&alias_facts).final_object_identities,
      denial_fact(&unrelated_facts).final_object_identities,
    );
    let unrelated_floor = unrelated_facts
      .path_bindings
      .iter()
      .find(|binding| binding.source_id == "floor:path-read")
      .unwrap();
    assert_ne!(
      denial_fact(&unrelated_facts).final_object_identities,
      unrelated_floor.final_object_identities,
    );

    drop(context);
    std::fs::remove_dir_all(root).unwrap();
  }

  #[cfg(unix)]
  #[test]
  fn deputy_denial_follows_a_hardlink_across_a_shallower_overlapping_root_without_widening_positives()
   {
    let (_initial_guard, owner) = install_test_actor();
    let deputy = PrincipalRef {
      kind: crate::rev2::PrincipalKind::Package,
      key: "pkg:sha256-BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
    };
    let shallow = temp_root("deputy-overlap");
    let deep = shallow.join("deep");
    std::fs::create_dir_all(deep.join("data")).unwrap();
    let denied = shallow.join("denied.txt");
    let alias = deep.join("data/denied-hardlink.txt");
    let unrelated = deep.join("data/unrelated.txt");
    let outside_deputy_floor = deep.join("data/owner-only.txt");
    std::fs::write(&denied, b"deputy denied object").unwrap();
    std::fs::hard_link(&denied, &alias).unwrap();
    std::fs::write(&unrelated, b"both principals allow exactly this").unwrap();
    std::fs::write(&outside_deputy_floor, b"owner floor only").unwrap();
    let context = overlapping_deputy_path_context(
      &shallow, &deep, &denied, &unrelated, &owner, &deputy,
    );
    let _actor = install_test_actor_set(
      vec![owner.clone(), deputy.clone()],
      owner.clone(),
    );
    let permissions = test_permissions();

    assert_eq!(
      oden_capsec_rev2_permission_operation(
        &context,
        &permissions,
        OdenRev2PermissionOperation::Query,
        &descriptor("read", Some(alias.to_str().unwrap()), None),
      )
      .unwrap(),
      PublicPermissionState::Denied,
    );
    assert_eq!(
      oden_capsec_rev2_permission_operation(
        &context,
        &permissions,
        OdenRev2PermissionOperation::Query,
        &descriptor("read", Some(unrelated.to_str().unwrap()), None),
      )
      .unwrap(),
      PublicPermissionState::Granted,
    );
    assert_eq!(
      oden_capsec_rev2_permission_operation(
        &context,
        &permissions,
        OdenRev2PermissionOperation::Query,
        &descriptor(
          "read",
          Some(outside_deputy_floor.to_str().unwrap()),
          None,
        ),
      )
      .unwrap(),
      PublicPermissionState::Denied,
    );

    let facts = verified_path_effect(
      &context,
      &[owner.clone(), deputy.clone()],
      &owner,
      "fs:read",
      &alias,
    )
    .unwrap();
    let occurrence_root = facts
      .session_path_binding
      .as_ref()
      .unwrap()
      .root_binding_id
      .as_str();
    let deputy_denial = facts
      .path_bindings
      .iter()
      .find(|binding| binding.source_id == "deny:deputy-shallow")
      .unwrap();
    assert_eq!(deputy_denial.root_binding_id, occurrence_root);
    assert_eq!(deputy_denial.final_object_identities.len(), 1);

    drop(context);
    std::fs::remove_dir_all(shallow).unwrap();
  }

  #[cfg(unix)]
  #[test]
  fn equivalent_floor_and_ceiling_roots_produce_distinct_source_facts_without_ambiguity()
   {
    let (_actor, owner) = install_test_actor();
    let root = temp_root("path-floor-ceiling");
    std::fs::create_dir(root.join("data")).unwrap();
    let file = root.join("data/file.txt");
    std::fs::write(&file, b"same object").unwrap();
    let context = path_context_with_deny(&root, &owner, false, true, None);
    let verified = verified_path_effect(
      &context,
      std::slice::from_ref(&owner),
      &owner,
      "fs:read",
      &file,
    )
    .unwrap();
    let sources = verified
      .path_bindings
      .iter()
      .map(|binding| binding.source_id.as_str())
      .collect::<BTreeSet<_>>();
    assert_eq!(
      sources,
      BTreeSet::from(["ceiling:path-read", "floor:path-read"]),
    );
    assert!(verified.path_bindings.iter().all(|binding| {
      binding.root_binding_id
        == verified
          .session_path_binding
          .as_ref()
          .unwrap()
          .root_binding_id
    }));
    assert_eq!(
      oden_capsec_rev2_permission_operation(
        &context,
        &test_permissions(),
        OdenRev2PermissionOperation::Query,
        &descriptor("read", Some(file.to_str().unwrap()), None),
      )
      .unwrap(),
      PublicPermissionState::Granted,
    );
    drop(context);
    std::fs::remove_dir_all(root).unwrap();
  }

  #[cfg(unix)]
  #[test]
  fn exact_path_session_grant_and_revoke_reuse_the_verified_binding_under_stable_row_ids()
   {
    let (_actor, owner) = install_test_actor();
    let root = temp_root("path-session");
    std::fs::create_dir(root.join("data")).unwrap();
    let file = root.join("data/session.txt");
    std::fs::write(&file, b"trusted").unwrap();
    let hardlink = root.join("data/session-hardlink.txt");
    std::fs::hard_link(&file, &hardlink).unwrap();
    let unrelated = root.join("data/unrelated.txt");
    std::fs::write(&unrelated, b"unrelated").unwrap();
    let context = path_context(&root, &owner, true);
    let permissions = test_permissions();
    let file_descriptor =
      descriptor("read", Some(file.to_str().unwrap()), None);

    assert_eq!(
      oden_capsec_rev2_permission_operation(
        &context,
        &permissions,
        OdenRev2PermissionOperation::Query,
        &file_descriptor,
      )
      .unwrap(),
      PublicPermissionState::Prompt,
    );

    let verified = verified_path_effect(
      &context,
      std::slice::from_ref(&owner),
      &owner,
      "fs:read",
      &file,
    )
    .unwrap();
    let core = Rev2Core::embedded().unwrap();
    let positive = core
      .normalize_selector(
        &AuthoritySelectorInput {
          identity: EngineIdentity::embedded(),
          principal: Some(owner.clone()),
          capability: "fs:read".to_string(),
          resource: verified.resource.clone(),
        },
        SelectorPolarity::Positive,
      )
      .unwrap();
    let revocation = core
      .normalize_selector(
        &AuthoritySelectorInput {
          identity: EngineIdentity::embedded(),
          principal: Some(owner.clone()),
          capability: "fs:read".to_string(),
          resource: verified.resource,
        },
        SelectorPolarity::Negative,
      )
      .unwrap();
    let path_fact = AuthorityPathFact::capture_verified(
      verified.session_path_binding.as_ref().unwrap(),
      &positive,
      &verified.occurrence,
    )
    .unwrap();
    let mut missing_fact =
      context.authority_state().begin_transaction().unwrap();
    assert_eq!(
      missing_fact.reconcile_session_grant(
        &owner,
        &owner,
        &positive,
        &revocation,
        None,
      ),
      Err(AuthorityStateError::InvalidField("sessionPathFact")),
    );
    assert!(context.authority_state().commit(missing_fact).is_err());
    assert_eq!(
      context.authority_state().read_view().unwrap().row_count(),
      0
    );
    let mut transaction =
      context.authority_state().begin_transaction().unwrap();
    transaction
      .reconcile_session_grant(
        &owner,
        &owner,
        &positive,
        &revocation,
        Some(&path_fact),
      )
      .unwrap();
    let granted_view = context.authority_state().commit(transaction).unwrap();
    let stored = granted_view
      .rows(crate::oden_rev2_authority::AuthorityRowKind::SessionPositive)
      .next()
      .unwrap();
    let wire = serde_json::to_value(stored).unwrap();
    assert!(wire.get("pathFact").is_none());
    assert!(stored.path_binding().is_some());
    assert!(
      stored.encoded_weight_bytes() > serde_json::to_vec(stored).unwrap().len()
    );

    assert_eq!(
      oden_capsec_rev2_permission_operation(
        &context,
        &permissions,
        OdenRev2PermissionOperation::Query,
        &file_descriptor,
      )
      .unwrap(),
      PublicPermissionState::Granted,
    );
    assert_eq!(
      oden_capsec_rev2_permission_operation(
        &context,
        &permissions,
        OdenRev2PermissionOperation::Revoke,
        &file_descriptor,
      )
      .unwrap(),
      PublicPermissionState::Prompt,
    );
    assert_eq!(
      oden_capsec_rev2_permission_operation(
        &context,
        &permissions,
        OdenRev2PermissionOperation::Query,
        &file_descriptor,
      )
      .unwrap(),
      PublicPermissionState::Prompt,
    );

    for path in [&hardlink, &unrelated] {
      assert_eq!(
        oden_capsec_rev2_permission_operation(
          &context,
          &permissions,
          OdenRev2PermissionOperation::Query,
          &descriptor("read", Some(path.to_str().unwrap()), None),
        )
        .unwrap(),
        PublicPermissionState::Prompt,
      );
    }

    let view = context.authority_state().read_view().unwrap();
    let revocation_row = view
      .rows(crate::oden_rev2_authority::AuthorityRowKind::SessionRevocation)
      .next()
      .unwrap();
    let branch = select_branch(&file_descriptor).unwrap();
    let slot = &branch.slot_order[0];
    let matches_session_revocation = |path: &Path| {
      let verified = verified_path_effect(
        &context,
        std::slice::from_ref(&owner),
        &owner,
        "fs:read",
        path,
      )
      .unwrap();
      let policy = context
        .decision_policy_for_operation(
          &view,
          OdenRev2OperationAuthorityFacts::new(
            owner.clone(),
            "terminal:path-session-source-isolation".to_string(),
          )
          .with_path_bindings(verified.path_bindings.clone()),
        )
        .unwrap();
      core
        .selector_matches_effect(
          &AuthoritySelectorInput {
            identity: EngineIdentity::embedded(),
            principal: revocation_row.selector().principal.clone(),
            capability: revocation_row.selector().capability.clone(),
            resource: revocation_row.selector().resource.clone(),
          },
          &EffectInput {
            identity: EngineIdentity::embedded(),
            edge_id: branch.operation_edge_ids.query.to_string(),
            effect_slot_id: slot
              .operation_effect_slot_ids
              .query
              .unwrap()
              .to_string(),
            capability: "fs:read".to_string(),
            effect_owner: owner.key.clone(),
            occurrence: verified.occurrence,
          },
          SelectorPolarity::Negative,
          revocation_row.row_id(),
          &policy.path_bindings,
        )
        .unwrap()
    };
    assert!(matches_session_revocation(&hardlink));
    assert!(!matches_session_revocation(&unrelated));

    drop(context);
    std::fs::remove_dir_all(root).unwrap();
  }

  #[cfg(unix)]
  #[test]
  fn session_path_facts_do_not_authorize_created_or_replaced_objects() {
    let (_actor, owner) = install_test_actor();
    let root = temp_root("path-session-replacement");
    std::fs::create_dir(root.join("data")).unwrap();
    let missing = root.join("data/missing.txt");
    let existing = root.join("data/existing.txt");
    std::fs::write(&existing, b"first inode").unwrap();
    let context = path_context(&root, &owner, true);
    let permissions = test_permissions();

    install_exact_session_path_grant(&context, &owner, &missing);
    assert_eq!(
      oden_capsec_rev2_permission_operation(
        &context,
        &permissions,
        OdenRev2PermissionOperation::Query,
        &descriptor("read", Some(missing.to_str().unwrap()), None),
      )
      .unwrap(),
      PublicPermissionState::Granted,
    );
    std::fs::write(&missing, b"new object").unwrap();
    assert_eq!(
      oden_capsec_rev2_permission_operation(
        &context,
        &permissions,
        OdenRev2PermissionOperation::Query,
        &descriptor("read", Some(missing.to_str().unwrap()), None),
      )
      .unwrap(),
      PublicPermissionState::Prompt,
    );

    install_exact_session_path_grant(&context, &owner, &existing);
    assert_eq!(
      oden_capsec_rev2_permission_operation(
        &context,
        &permissions,
        OdenRev2PermissionOperation::Query,
        &descriptor("read", Some(existing.to_str().unwrap()), None),
      )
      .unwrap(),
      PublicPermissionState::Granted,
    );
    let old = root.join("data/old-existing.txt");
    std::fs::rename(&existing, &old).unwrap();
    std::fs::write(&existing, b"replacement inode").unwrap();
    assert_eq!(
      oden_capsec_rev2_permission_operation(
        &context,
        &permissions,
        OdenRev2PermissionOperation::Query,
        &descriptor("read", Some(existing.to_str().unwrap()), None),
      )
      .unwrap(),
      PublicPermissionState::Prompt,
    );

    drop(context);
    std::fs::remove_dir_all(root).unwrap();
  }

  #[cfg(unix)]
  #[test]
  fn installed_native_binding_drives_run_and_script_binding_fails_closed() {
    let (_actor, owner) = install_test_actor();
    let root = temp_root("run");
    let native = root.join("native");
    std::fs::write(&native, b"native image").unwrap();
    let permissions = test_permissions();

    let native_context = executable_context(&native, &native, &owner);
    let native_descriptor = OdenDynamicPermissionDescriptor {
      name: "run",
      path: None,
      host: None,
      variable: None,
      kind: None,
      command: Some(native.to_str().unwrap()),
      presence: crate::OdenDynamicPermissionFieldPresence {
        command: true,
        ..Default::default()
      },
    };
    assert_eq!(
      oden_capsec_rev2_permission_operation(
        &native_context,
        &permissions,
        OdenRev2PermissionOperation::Query,
        &native_descriptor,
      )
      .unwrap(),
      PublicPermissionState::Granted,
    );
    assert!(matches!(
      oden_capsec_rev2_permission_operation(
        &native_context,
        &permissions,
        OdenRev2PermissionOperation::Request,
        &native_descriptor,
      ),
      Err(OdenRev2PermissionError::Protocol(_))
    ));
    let missing = root.join("missing");
    let missing_descriptor = OdenDynamicPermissionDescriptor {
      command: Some(missing.to_str().unwrap()),
      ..native_descriptor
    };
    assert!(matches!(
      oden_capsec_rev2_permission_operation(
        &native_context,
        &permissions,
        OdenRev2PermissionOperation::Query,
        &missing_descriptor,
      ),
      Err(OdenRev2PermissionError::HostVerifierUnavailable(_))
    ));
    let bare_descriptor = OdenDynamicPermissionDescriptor {
      command: Some("git"),
      ..native_descriptor
    };
    assert!(matches!(
      oden_capsec_rev2_permission_operation(
        &native_context,
        &permissions,
        OdenRev2PermissionOperation::Query,
        &bare_descriptor,
      ),
      Err(OdenRev2PermissionError::DescriptorRefused(reason))
        if reason == "OD-CAP-PERMISSION-RUN-UNRESOLVED"
    ));

    let script = root.join("script.js");
    let interpreter = root.join("interpreter");
    std::fs::write(&script, b"#!interpreter\nscript").unwrap();
    std::fs::write(&interpreter, b"interpreter image").unwrap();
    let script_context = executable_context(&script, &interpreter, &owner);
    let script_descriptor = OdenDynamicPermissionDescriptor {
      command: Some(script.to_str().unwrap()),
      ..native_descriptor
    };
    assert!(matches!(
      oden_capsec_rev2_permission_operation(
        &script_context,
        &permissions,
        OdenRev2PermissionOperation::Query,
        &script_descriptor,
      ),
      Err(OdenRev2PermissionError::HostVerifierUnavailable(reason))
        if reason == "process:spawn-script-logical-interpreter-path"
    ));
    drop(native_context);
    drop(script_context);
    std::fs::remove_dir_all(root).unwrap();
  }

  #[cfg(unix)]
  #[test]
  fn installed_library_binding_drives_ffi_query_and_typed_revoke_only() {
    let (_actor, owner) = install_test_actor();
    let root = temp_root("ffi");
    let library = root.join("example.dylib");
    std::fs::write(&library, b"library image").unwrap();
    let context = ffi_context(&library, &owner);
    let permissions = test_permissions();
    let descriptor = OdenDynamicPermissionDescriptor {
      name: "ffi",
      path: Some(library.to_str().unwrap()),
      host: None,
      variable: None,
      kind: None,
      command: None,
      presence: crate::OdenDynamicPermissionFieldPresence {
        path: true,
        ..Default::default()
      },
    };
    assert_eq!(
      oden_capsec_rev2_permission_operation(
        &context,
        &permissions,
        OdenRev2PermissionOperation::Query,
        &descriptor,
      )
      .unwrap(),
      PublicPermissionState::Granted,
    );
    assert!(matches!(
      oden_capsec_rev2_permission_operation(
        &context,
        &permissions,
        OdenRev2PermissionOperation::Request,
        &descriptor,
      ),
      Err(OdenRev2PermissionError::Protocol(_))
    ));
    assert_eq!(
      oden_capsec_rev2_permission_operation(
        &context,
        &permissions,
        OdenRev2PermissionOperation::Revoke,
        &descriptor,
      )
      .unwrap(),
      PublicPermissionState::Denied,
    );
    assert_eq!(
      oden_capsec_rev2_permission_operation(
        &context,
        &permissions,
        OdenRev2PermissionOperation::Query,
        &descriptor,
      )
      .unwrap(),
      PublicPermissionState::Denied,
    );
    let missing = root.join("missing.dylib");
    let missing_descriptor = OdenDynamicPermissionDescriptor {
      path: Some(missing.to_str().unwrap()),
      ..descriptor
    };
    assert!(matches!(
      oden_capsec_rev2_permission_operation(
        &context,
        &permissions,
        OdenRev2PermissionOperation::Query,
        &missing_descriptor,
      ),
      Err(OdenRev2PermissionError::HostVerifierUnavailable(_))
    ));
    drop(context);
    std::fs::remove_dir_all(root).unwrap();
  }

  #[test]
  fn live_sys_aliases_query_request_and_revoke_only_canonical_rows() {
    let (_actor, owner) = install_test_actor();
    let context = sys_context(&owner);
    let permissions = test_permissions();
    let aliases = [
      ("networkInterfaces", "network-interfaces"),
      ("osRelease", "os-release"),
      ("osUptime", "os-uptime"),
      ("systemMemoryInfo", "system-memory-info"),
    ];
    for (alias, _) in aliases {
      let descriptor = descriptor("sys", None, Some(alias));
      assert_eq!(
        oden_capsec_rev2_permission_operation(
          &context,
          &permissions,
          OdenRev2PermissionOperation::Query,
          &descriptor,
        )
        .unwrap(),
        PublicPermissionState::Granted,
      );
      assert_eq!(
        oden_capsec_rev2_permission_operation(
          &context,
          &permissions,
          OdenRev2PermissionOperation::Request,
          &descriptor,
        )
        .unwrap(),
        PublicPermissionState::Granted,
      );
      assert_eq!(
        oden_capsec_rev2_permission_operation(
          &context,
          &permissions,
          OdenRev2PermissionOperation::Revoke,
          &descriptor,
        )
        .unwrap(),
        PublicPermissionState::Denied,
      );
    }
    let view = context.authority_state().read_view().unwrap();
    let actual = view
      .rows(crate::oden_rev2_authority::AuthorityRowKind::SessionRevocation)
      .map(|row| {
        row.selector().resource["kind"]
          .as_str()
          .unwrap()
          .to_string()
      })
      .collect::<BTreeSet<_>>();
    let expected = aliases
      .into_iter()
      .map(|(_, canonical)| canonical.to_string())
      .collect::<BTreeSet<_>>();
    assert_eq!(actual, expected);
  }

  #[test]
  fn unattributed_no_user_is_a_closed_denied_dimension_not_a_protocol_error() {
    let authored_owner = PrincipalRef {
      kind: crate::rev2::PrincipalKind::Package,
      key: "pkg:sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
    };
    let no_user = PrincipalRef {
      kind: crate::rev2::PrincipalKind::NoUser,
      key: "no-user:unattributed".to_string(),
    };
    crate::oden_rev2_set_permission_actors_for_test(Some((
      vec![no_user.clone()],
      no_user,
    )));
    let _guard = ActorGuard;
    let context = sys_context(&authored_owner);
    let permissions = test_permissions();
    assert_eq!(
      oden_capsec_rev2_permission_operation(
        &context,
        &permissions,
        OdenRev2PermissionOperation::Query,
        &descriptor("sys", None, Some("networkInterfaces")),
      )
      .unwrap(),
      PublicPermissionState::Denied,
    );
  }

  #[test]
  fn generated_descriptor_selection_is_closed_and_never_wildcards() {
    let read =
      select_branch(&descriptor("read", Some("src/main.ts"), None)).unwrap();
    assert_eq!(read.id, "permission.read.scoped/2");
    assert!(matches!(
      select_branch(&descriptor("read", None, None)),
      Err(OdenRev2PermissionError::DescriptorRefused(reason))
        if reason == "OD-CAP-PERMISSION-UNSCOPED"
    ));
    assert!(matches!(
      select_branch(&OdenDynamicPermissionDescriptor {
        name: "read",
        path: Some("src/main.ts"),
        host: Some("attacker.example"),
        variable: None,
        kind: None,
        command: None,
        presence: crate::OdenDynamicPermissionFieldPresence {
          path: true,
          host: true,
          ..Default::default()
        },
      }),
      Err(OdenRev2PermissionError::DescriptorInvalid(_))
    ));
    assert!(matches!(
      select_branch(&descriptor("net", None, None)),
      Err(OdenRev2PermissionError::DescriptorRefused(reason))
        if reason == "OD-CAP-PERMISSION-AMBIGUOUS-AGGREGATE"
    ));
  }

  #[test]
  fn present_null_or_wrong_branch_field_never_collapses_to_absent() {
    let descriptor = OdenDynamicPermissionDescriptor {
      name: "sys",
      path: None,
      host: None,
      variable: None,
      kind: Some("cpus"),
      command: None,
      presence: crate::OdenDynamicPermissionFieldPresence {
        path: true,
        kind: true,
        ..Default::default()
      },
    };
    assert!(matches!(
      select_branch(&descriptor),
      Err(OdenRev2PermissionError::DescriptorInvalid(_))
    ));
  }

  #[test]
  fn generated_sys_inventory_canonicalizes_deno_aliases_only() {
    assert_eq!(
      canonical_system_information_kind("networkInterfaces").unwrap(),
      "network-interfaces"
    );
    assert_eq!(
      canonical_system_information_kind("osRelease").unwrap(),
      "os-release"
    );
    assert_eq!(
      canonical_system_information_kind("osUptime").unwrap(),
      "os-uptime"
    );
    assert_eq!(
      canonical_system_information_kind("systemMemoryInfo").unwrap(),
      "system-memory-info"
    );
    assert!(matches!(
      canonical_system_information_kind("setPriority"),
      Err(OdenRev2PermissionError::DescriptorRefused(_))
    ));
    assert!(matches!(
      canonical_system_information_kind("network-interfaces"),
      Err(OdenRev2PermissionError::DescriptorRefused(_))
    ));
  }

  #[test]
  fn generated_static_only_request_refuses_before_any_host_verifier() {
    let branch = select_branch(&OdenDynamicPermissionDescriptor {
      name: "run",
      path: None,
      host: None,
      variable: None,
      kind: None,
      command: Some("/bin/example"),
      presence: crate::OdenDynamicPermissionFieldPresence {
        command: true,
        ..Default::default()
      },
    })
    .unwrap();
    assert_eq!(branch.id, "permission.run.scoped/2");
    assert_eq!(
      select_generated_permission_branch(
        branch.id,
        PermissionOperation::Request,
      )
      .unwrap_err(),
      PermissionProtocolError::TransitionRefused
    );

    let ffi = select_branch(&OdenDynamicPermissionDescriptor {
      name: "ffi",
      path: Some("/tmp/example.so"),
      host: None,
      variable: None,
      kind: None,
      command: None,
      presence: crate::OdenDynamicPermissionFieldPresence {
        path: true,
        ..Default::default()
      },
    })
    .unwrap();
    assert_eq!(
      select_generated_permission_branch(ffi.id, PermissionOperation::Request,)
        .unwrap_err(),
      PermissionProtocolError::TransitionRefused
    );
  }

  #[test]
  fn missing_dynamic_authority_is_prompt_only_inside_exact_ceiling() {
    let owner = crate::rev2::PrincipalRef {
      kind: crate::rev2::PrincipalKind::Package,
      key: "pkg:prompt".to_string(),
    };
    let core = Rev2Core::embedded().unwrap();
    let effect_input = EffectInput {
      identity: EngineIdentity::embedded(),
      edge_id: "native-op:runtime/ops/permissions.rs#op_query_permission"
        .to_string(),
      effect_slot_id:
        "native-op:runtime/ops/permissions.rs#op_query_permission:effect-slot:2"
          .to_string(),
      capability: "sys:read".to_string(),
      effect_owner: owner.key.clone(),
      occurrence: json!({
        "effectOwner": owner.key,
        "kind": "cpus",
      }),
    };
    let canonical_effect = core.normalize_effect(&effect_input).unwrap();
    let ceiling = AuthoritySelectorInput {
      identity: EngineIdentity::embedded(),
      principal: Some(owner.clone()),
      capability: "sys:read".to_string(),
      resource: json!({ "kind": "cpus" }),
    };
    let policy = DecisionPolicyInput {
      identity: EngineIdentity::embedded(),
      mode: crate::rev2::Mode::Enforce,
      run_nonce: "run:test".to_string(),
      channel_epoch: "channel:test".to_string(),
      provenance: crate::rev2::OperationProvenanceContext {
        policy_digest: "sha256-policy".to_string(),
        armed_snapshot_digest: "sha256-snapshot".to_string(),
        quota_owner: owner.clone(),
        terminal_evidence_id: "terminal:test".to_string(),
      },
      generations: crate::rev2::Generations::default(),
      process_denials: vec![],
      principal_denials: vec![],
      session_revocations: vec![],
      escalation_ceiling: vec![crate::rev2::NamedSelectorInput {
        source_id: "ceiling:sys".to_string(),
        selector: ceiling,
      }],
      static_floor: vec![],
      handles: vec![],
      session_grants: vec![],
      implicit_self: vec![],
      protected_exceptions: vec![],
      compatibility_dispositions: vec![],
      validated_receipt_row_digests: vec![],
      path_bindings: vec![],
    };
    let decision = StageDecision {
      stage_id: "result-production".to_string(),
      outcome: Outcome::Deny,
      effects: vec![crate::rev2::EffectDecision {
        effect: canonical_effect,
        outcome: Outcome::Deny,
        dimensions: vec![crate::rev2::DimensionDecision {
          principal: owner,
          outcome: Outcome::Deny,
          stratum: 17,
          reason_code: "OD-CAP-MISSING-AUTHORITY".to_string(),
          positive_source: None,
        }],
      }],
      committed_effects: vec![],
      omitted_effects: vec![],
      canonical_effects_json: "[]".to_string(),
    };
    assert_eq!(
      permission_effect_result(
        &core,
        &policy,
        &effect_input,
        &decision,
        "permission.sys:slot:0",
        true,
      )
      .unwrap()
      .state(),
      PermissionState::Prompt
    );
    assert_eq!(
      permission_effect_result(
        &core,
        &policy,
        &effect_input,
        &decision,
        "permission.sys:slot:0",
        false,
      )
      .unwrap()
      .state(),
      PermissionState::Denied
    );

    let mut revoked = decision.clone();
    revoked.effects[0].dimensions[0].stratum = 7;
    assert_eq!(
      permission_effect_result(
        &core,
        &policy,
        &effect_input,
        &revoked,
        "permission.sys:slot:0",
        true,
      )
      .unwrap()
      .state(),
      PermissionState::Prompt
    );
    revoked.effects[0].dimensions[0].stratum = 6;
    assert_eq!(
      permission_effect_result(
        &core,
        &policy,
        &effect_input,
        &revoked,
        "permission.sys:slot:0",
        true,
      )
      .unwrap()
      .state(),
      PermissionState::Denied
    );
  }
}

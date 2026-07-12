// Copyright 2018-2026 the Deno authors. MIT license.

//! Live, closed `Deno.permissions` adapter for the installed C04 context.
//!
//! @ref LLP 0019#stage-c-runtime-authority-and-typed-permission-checkpoint-c04--eng-24017 [implements] -- An installed Rev2 context selects exactly one generated descriptor branch and never falls through to the Revision-1 wildcard or prompt path.

use std::collections::BTreeSet;

use serde_json::json;

use crate::OdenDynamicPermissionDescriptor;
use crate::OdenRev2RuntimeAuthorityContext;
use crate::PermissionState as PublicPermissionState;
use crate::PermissionsContainer;
use crate::oden_rev2_authority::AuthorityStateError;
use crate::oden_rev2_authority::RuntimeAuthorityReadView;
use crate::oden_rev2_context::OdenRev2OperationAuthorityFacts;
use crate::oden_rev2_protocol::NormalizedPermissionBatch;
use crate::oden_rev2_protocol::NormalizedPermissionEffect;
use crate::oden_rev2_protocol::PermissionBatchResult;
use crate::oden_rev2_protocol::PermissionDimensionResult;
use crate::oden_rev2_protocol::PermissionEffectResult;
use crate::oden_rev2_protocol::PermissionOperation;
use crate::oden_rev2_protocol::PermissionProtocolError;
use crate::oden_rev2_protocol::PermissionState;
use crate::oden_rev2_protocol::VerifiedPermissionActorSet;
use crate::oden_rev2_protocol::select_generated_permission_branch;
use crate::rev2::AuthoritySelectorInput;
use crate::rev2::DecisionPolicyInput;
use crate::rev2::EffectInput;
use crate::rev2::EngineIdentity;
use crate::rev2::Outcome;
use crate::rev2::Rev2Core;
use crate::rev2::SelectorPolarity;
use crate::rev2::StageDecision;
use crate::rev2::StageRequest;
use crate::rev2_registry_generated::REV2_RUNTIME_NEGATIVE_REENTRY_PHASES;
use crate::rev2_registry_generated::REV2_RUNTIME_PERMISSION_BRANCHES;

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
  for (name, value) in [
    ("path", descriptor.path),
    ("host", descriptor.host),
    ("variable", descriptor.variable),
    ("kind", descriptor.kind),
    ("command", descriptor.command),
  ] {
    if value.is_some() {
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

fn validate_stock_spelling_without_deciding(
  permissions: &PermissionsContainer,
  descriptor: &OdenDynamicPermissionDescriptor<'_>,
) -> Result<(), OdenRev2PermissionError> {
  let parser = &permissions.descriptor_parser;
  let result = match descriptor.name {
    "read" => parser
      .parse_read_descriptor(descriptor.path.expect("generated scoped branch"))
      .map(|_| ())
      .map_err(|error| error.to_string()),
    "write" => parser
      .parse_write_descriptor(descriptor.path.expect("generated scoped branch"))
      .map(|_| ())
      .map_err(|error| error.to_string()),
    "sys" => parser
      .parse_sys_descriptor(descriptor.kind.expect("generated scoped branch"))
      .map(|_| ())
      .map_err(|error| error.to_string()),
    "run" => parser
      .parse_allow_run_descriptor(
        descriptor.command.expect("generated scoped branch"),
      )
      .map(|_| ())
      .map_err(|error| error.to_string()),
    "ffi" => parser
      .parse_ffi_descriptor(descriptor.path.expect("generated scoped branch"))
      .map(|_| ())
      .map_err(|error| error.to_string()),
    _ => Err("generated normalized branch has no native parser".to_string()),
  };
  result.map_err(OdenRev2PermissionError::DescriptorInvalid)
}

fn generated_phase(id: &str) -> Result<&'static str, OdenRev2PermissionError> {
  REV2_RUNTIME_NEGATIVE_REENTRY_PHASES
    .iter()
    .find(|phase| phase.id == id && phase.strata == [1, 2, 3, 4, 5, 6, 7])
    .map(|phase| phase.id)
    .ok_or_else(|| {
      OdenRev2PermissionError::Protocol(
        PermissionProtocolError::InvalidField("negativeReentryPhase")
          .to_string(),
      )
    })
}

fn protocol_state_to_public(state: PermissionState) -> PublicPermissionState {
  match state {
    PermissionState::Granted => PublicPermissionState::Granted,
    PermissionState::Prompt => PublicPermissionState::Prompt,
    PermissionState::Denied => PublicPermissionState::Denied,
  }
}

#[derive(Clone, Copy)]
enum PermissionEvaluationView {
  Current,
  Proposed,
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

fn evaluate_phase(
  context: &OdenRev2RuntimeAuthorityContext,
  core: &Rev2Core,
  view: &RuntimeAuthorityReadView,
  overlay_owner: &crate::rev2::PrincipalRef,
  principals: &[crate::rev2::PrincipalRef],
  effect_input: &EffectInput,
  phase: &str,
  evaluation_view: PermissionEvaluationView,
) -> Result<(DecisionPolicyInput, StageDecision), OdenRev2PermissionError> {
  let phase = generated_phase(phase)?;
  let facts = OdenRev2OperationAuthorityFacts::new(
    overlay_owner.clone(),
    format!("permission:{phase}"),
  );
  let policy = match evaluation_view {
    PermissionEvaluationView::Current => {
      context.decision_policy_for_operation(view, facts)
    }
    PermissionEvaluationView::Proposed => {
      context.decision_policy_for_proposed_operation(view, facts)
    }
  }
  .map_err(OdenRev2PermissionError::Context)?;
  let decision = core
    .decide_stage(
      &StageRequest {
        identity: EngineIdentity::embedded(),
        stage_id: phase.to_string(),
        principals: principals.to_vec(),
        effects: vec![effect_input.clone()],
      },
      &policy,
    )
    .map_err(|error| OdenRev2PermissionError::Core(error.to_string()))?;
  Ok((policy, decision))
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

/// Evaluate the one fully host-constructible initial branch (`sys`). Other
/// generated normalized branches are selected and parser-validated above but
/// remain closed until their object-identity verifier can build the complete
/// occurrence from retained native state.
fn evaluate_system_information(
  context: &OdenRev2RuntimeAuthorityContext,
  branch: &crate::rev2_registry_generated::Rev2RuntimePermissionBranch,
  operation: PermissionOperation,
  kind: &str,
) -> Result<PublicPermissionState, OdenRev2PermissionError> {
  let generated = select_generated_permission_branch(branch.id, operation)?;
  let slot = branch.slot_order.first().ok_or_else(|| {
    OdenRev2PermissionError::DescriptorInvalid(
      "generated normalized branch has no slot".to_string(),
    )
  })?;
  if branch.slot_order.len() != 1 || slot.capability != "sys:read" {
    return Err(OdenRev2PermissionError::DescriptorInvalid(
      "system-information branch is not the exact generated singleton"
        .to_string(),
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
    occurrence: json!({
      "effectOwner": overlay_owner.key,
      "kind": kind,
    }),
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
        resource: json!({ "kind": kind }),
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
  let batch = NormalizedPermissionBatch::capture_host(
    context.authority_state(),
    &view,
    sequence,
    operation,
    &generated,
    &actors,
    std::slice::from_ref(&effect),
  )?;

  let phases: &[&str] = match operation {
    PermissionOperation::Query => {
      &["initial-query-or-request", "result-production"]
    }
    PermissionOperation::Request => &[
      "initial-query-or-request",
      "already-granted-check",
      "result-production",
    ],
    PermissionOperation::Revoke => &["initial-query-or-request"],
  };
  let mut final_evaluation = None;
  for phase in phases {
    final_evaluation = Some(evaluate_phase(
      context,
      &core,
      &view,
      &overlay_owner,
      &principals,
      &effect_input,
      phase,
      PermissionEvaluationView::Current,
    )?);
  }
  let (policy, decision) =
    final_evaluation.expect("each operation evaluates at least one phase");
  let effect_result = permission_effect_result(
    &core,
    &policy,
    &effect_input,
    &decision,
    slot.slot_id,
    true,
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
            for phase in ["before-overlay-publication", "result-production"] {
              final_evaluation = Some(evaluate_phase(
                context,
                &core,
                proposed_view,
                &overlay_owner,
                &principals,
                &effect_input,
                phase,
                PermissionEvaluationView::Proposed,
              )?);
            }
            let (policy, decision) = final_evaluation
              .expect("both generated proposed-state phases are evaluated");
            let effect_result = permission_effect_result(
              &core,
              &policy,
              &effect_input,
              &decision,
              slot.slot_id,
              true,
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
      validate_stock_spelling_without_deciding(permissions, descriptor)?;
      evaluate_system_information(
        context,
        branch,
        operation,
        descriptor.kind.expect("generated scoped branch"),
      )
    }
    "read" | "write" | "run" | "ffi" => {
      Err(OdenRev2PermissionError::HostVerifierUnavailable(
        descriptor.name.to_string(),
      ))
    }
    _ => Err(OdenRev2PermissionError::DescriptorRefused(
      "OD-CAP-PERMISSION-NO-REV2-CAPABILITY".to_string(),
    )),
  }
}

#[cfg(test)]
mod tests {
  use super::*;

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
    }
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
  fn generated_static_only_request_refuses_before_any_host_verifier() {
    let branch = select_branch(&OdenDynamicPermissionDescriptor {
      name: "run",
      path: None,
      host: None,
      variable: None,
      kind: None,
      command: Some("/bin/example"),
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

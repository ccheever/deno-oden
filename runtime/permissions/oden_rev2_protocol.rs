// Copyright 2018-2026 the Deno authors. MIT license.

//! Closed, host-only Rev2 typed-permission protocol records.
//!
//! JavaScript descriptor parsing and legacy descriptor adaptation deliberately
//! live outside this module. Trusted native normalization supplies one
//! generated edge specification and already-canonical effects; this module
//! checks the closed batch protocol, computes its digest, constructs complete
//! results, and authenticates one-shot external responses.
//!
//! @ref LLP 0019#stage-c-runtime-authority-and-typed-permission-checkpoint-c04--eng-24017 [implements] -- Permission batches bind generated effect order, the exact runtime identity and generation read view, and one conjunctive result.

#![allow(
  dead_code,
  reason = "C04 defines the typed host protocol before the generated descriptor boundary and broker adapter register their consumers"
)]

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hmac::Hmac;
use hmac::Mac;
use serde::Serialize;
use serde::Serializer;
use serde::ser::SerializeStruct;
use serde_json::Value;
use sha2::Digest;
use sha2::Sha256;
use std::collections::BTreeSet;
use std::collections::HashSet;
use std::fmt;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::sync::atomic::compiler_fence;

use crate::oden_rev2_authority::AuthorityStateError;
use crate::oden_rev2_authority::AuthorityTransaction;
#[cfg(test)]
use crate::oden_rev2_authority::CommittedAuthorityTransaction;
use crate::oden_rev2_authority::RuntimeAuthorityReadView;
use crate::oden_rev2_authority::RuntimeAuthorityState;
use crate::oden_rev2_authority::RuntimeGenerationVector;
use crate::oden_rev2_authority::RuntimeIdentityBinding;
use crate::oden_rev2_context::OdenRev2PermissionBatchSequence;
use crate::rev2::CanonicalAuthoritySelector;
use crate::rev2::CanonicalEffect;
use crate::rev2::PositiveSource;
use crate::rev2::PrincipalRef;
use crate::rev2_registry_generated::{
  REV2_RUNTIME_EXTERNAL_RESPONSE_MAC_DOMAIN,
  REV2_RUNTIME_EXTERNAL_RESPONSE_SCHEMA, REV2_RUNTIME_MAX_BATCH_EFFECTS,
  REV2_RUNTIME_MAX_CANONICAL_BATCH_BYTES,
  REV2_RUNTIME_MAX_CANONICAL_COMPONENT_BYTES,
  REV2_RUNTIME_MAX_CANONICAL_EFFECT_BYTES,
  REV2_RUNTIME_MAX_CANONICAL_RESULT_BYTES,
  REV2_RUNTIME_MAX_CONSTRAINED_PRINCIPALS,
  REV2_RUNTIME_MAX_PRINCIPAL_EFFECT_DIMENSIONS,
  REV2_RUNTIME_PERMISSION_BATCH_DIGEST_DOMAIN,
  REV2_RUNTIME_PERMISSION_BATCH_SCHEMA, REV2_RUNTIME_PERMISSION_BRANCHES,
  REV2_RUNTIME_PERMISSION_RESULT_SCHEMA,
};

const PERMISSION_BATCH_SCHEMA: &str = REV2_RUNTIME_PERMISSION_BATCH_SCHEMA;
const PERMISSION_RESULT_SCHEMA: &str = REV2_RUNTIME_PERMISSION_RESULT_SCHEMA;
const EXTERNAL_RESPONSE_SCHEMA: &str = REV2_RUNTIME_EXTERNAL_RESPONSE_SCHEMA;
const PERMISSION_BATCH_DIGEST_DOMAIN: &[u8] =
  REV2_RUNTIME_PERMISSION_BATCH_DIGEST_DOMAIN.as_bytes();
const EXTERNAL_RESPONSE_MAC_DOMAIN: &[u8] =
  REV2_RUNTIME_EXTERNAL_RESPONSE_MAC_DOMAIN.as_bytes();

const MAX_COMPONENT_BYTES: usize = REV2_RUNTIME_MAX_CANONICAL_COMPONENT_BYTES;
const MAX_CANONICAL_EFFECT_BYTES: usize =
  REV2_RUNTIME_MAX_CANONICAL_EFFECT_BYTES;
const MAX_CANONICAL_BATCH_BYTES: usize = REV2_RUNTIME_MAX_CANONICAL_BATCH_BYTES;
const MAX_CANONICAL_RESULT_BYTES: usize =
  REV2_RUNTIME_MAX_CANONICAL_RESULT_BYTES;
const MAX_GENERATED_EFFECTS: usize = REV2_RUNTIME_MAX_BATCH_EFFECTS;
const MAX_CONSTRAINED_PRINCIPALS: usize =
  REV2_RUNTIME_MAX_CONSTRAINED_PRINCIPALS;
const MAX_PRINCIPAL_EFFECT_PRODUCT: usize =
  REV2_RUNTIME_MAX_PRINCIPAL_EFFECT_DIMENSIONS;
const MAX_CANONICAL_U64_BYTES: usize = 20;
const EXTERNAL_RESPONSE_KEY_BYTES: usize = 32;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum PermissionProtocolError {
  InvalidField(&'static str),
  Empty(&'static str),
  BoundExceeded(&'static str),
  DuplicateGeneratedSlot,
  DuplicatePrincipal,
  DuplicateSlot,
  DuplicateEffect,
  SlotNotGenerated,
  SlotOrder,
  IncompleteGeneratedSlotSet,
  TransitionRefused,
  OverlayOwnerNotConstrained,
  EffectOwnerNotConstrained,
  EffectOwnerSelectorMismatch,
  EffectOwnerCanonicalMismatch,
  EffectOwnerOccurrenceMismatch,
  EffectCapabilityMismatch,
  EffectProjectionMismatch,
  EffectEdgeMismatch,
  IncompleteResult,
  InvalidPositiveSource,
  AuthenticationFailed,
  ExternalMutationRefused,
  StaleAuthorityView,
  AuthorityState(AuthorityStateError),
  IdentityMismatch,
  GenerationMismatch,
  BatchSequenceMismatch,
  OperationMismatch,
  BatchDigestMismatch,
  ResponseReplay,
  Serialization(String),
}

impl fmt::Display for PermissionProtocolError {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::InvalidField(field) => write!(formatter, "invalid {field}"),
      Self::Empty(field) => write!(formatter, "empty {field}"),
      Self::BoundExceeded(field) => write!(formatter, "{field} exceeds bound"),
      Self::DuplicateGeneratedSlot => {
        formatter.write_str("generated slot order contains a duplicate")
      }
      Self::DuplicatePrincipal => {
        formatter.write_str("constrained principal set contains a duplicate")
      }
      Self::DuplicateSlot => {
        formatter.write_str("permission batch contains a duplicate slot")
      }
      Self::DuplicateEffect => formatter
        .write_str("permission batch contains a duplicate canonical effect"),
      Self::SlotNotGenerated => {
        formatter.write_str("permission batch contains an unknown slot")
      }
      Self::SlotOrder => {
        formatter.write_str("permission effects are not in generated order")
      }
      Self::IncompleteGeneratedSlotSet => formatter.write_str(
        "permission effects do not exactly cover the generated branch slots",
      ),
      Self::TransitionRefused => formatter
        .write_str("generated permission branch refuses this transition"),
      Self::OverlayOwnerNotConstrained => {
        formatter.write_str("overlay owner is not constrained")
      }
      Self::EffectOwnerNotConstrained => {
        formatter.write_str("effect owner is not constrained")
      }
      Self::EffectOwnerSelectorMismatch => {
        formatter.write_str("effect owner and selector principal differ")
      }
      Self::EffectOwnerCanonicalMismatch => formatter
        .write_str("typed effect owner and canonical effect owner differ"),
      Self::EffectOwnerOccurrenceMismatch => formatter
        .write_str("canonical effect owner and occurrence owner differ"),
      Self::EffectCapabilityMismatch => {
        formatter.write_str("selector and canonical effect capabilities differ")
      }
      Self::EffectProjectionMismatch => {
        formatter.write_str("effect projection differs from the generated slot")
      }
      Self::EffectEdgeMismatch => formatter
        .write_str("canonical effect belongs to another generated edge"),
      Self::IncompleteResult => {
        formatter.write_str("permission result does not cover the whole batch")
      }
      Self::InvalidPositiveSource => formatter
        .write_str("permission effect state and positive source disagree"),
      Self::AuthenticationFailed => {
        formatter.write_str("external permission response is unauthenticated")
      }
      Self::ExternalMutationRefused => formatter.write_str(
        "external decision cannot authorize a runtime authority mutation",
      ),
      Self::StaleAuthorityView => {
        formatter.write_str("runtime authority view is not current")
      }
      Self::AuthorityState(error) => {
        write!(formatter, "runtime authority state failed: {error}")
      }
      Self::IdentityMismatch => {
        formatter.write_str("external response runtime identity differs")
      }
      Self::GenerationMismatch => {
        formatter.write_str("external response generation vector differs")
      }
      Self::BatchSequenceMismatch => {
        formatter.write_str("external response batch sequence differs")
      }
      Self::OperationMismatch => {
        formatter.write_str("external response operation differs")
      }
      Self::BatchDigestMismatch => {
        formatter.write_str("external response batch digest differs")
      }
      Self::ResponseReplay => {
        formatter.write_str("external response has already been consumed")
      }
      Self::Serialization(error) => {
        write!(
          formatter,
          "permission protocol serialization failed: {error}"
        )
      }
    }
  }
}

impl std::error::Error for PermissionProtocolError {}

impl From<AuthorityStateError> for PermissionProtocolError {
  fn from(error: AuthorityStateError) -> Self {
    Self::AuthorityState(error)
  }
}

fn require_current_view(
  state: &RuntimeAuthorityState,
  view: &RuntimeAuthorityReadView,
) -> Result<(), PermissionProtocolError> {
  if state.is_current(view)? {
    Ok(())
  } else {
    Err(PermissionProtocolError::StaleAuthorityView)
  }
}

fn validate_component(
  field: &'static str,
  value: &str,
) -> Result<(), PermissionProtocolError> {
  if value.is_empty() || value.len() > MAX_COMPONENT_BYTES {
    return Err(PermissionProtocolError::InvalidField(field));
  }
  Ok(())
}

fn canonical_serialization<T: Serialize>(
  value: &T,
  maximum_bytes: usize,
  bound_field: &'static str,
) -> Result<String, PermissionProtocolError> {
  let value = serde_json::to_value(value).map_err(|error| {
    PermissionProtocolError::Serialization(error.to_string())
  })?;
  let canonical = crate::rev2::canonical_json(&value).map_err(|error| {
    PermissionProtocolError::Serialization(error.to_string())
  })?;
  if canonical.len() > maximum_bytes {
    return Err(PermissionProtocolError::BoundExceeded(bound_field));
  }
  Ok(canonical)
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct CanonicalU64(u64);

impl Serialize for CanonicalU64 {
  fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
  where
    S: Serializer,
  {
    serializer.serialize_str(&self.0.to_string())
  }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum PermissionOperation {
  Query,
  Request,
  Revoke,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PermissionQueryDisposition {
  Evaluate,
  Refuse,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PermissionRequestDisposition {
  AddSessionPositive,
  Refuse,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PermissionRevokeDisposition {
  AddSessionNegative,
  Refuse,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PermissionTransitionDispositions {
  query: PermissionQueryDisposition,
  request: PermissionRequestDisposition,
  revoke: PermissionRevokeDisposition,
}

impl PermissionTransitionDispositions {
  fn dynamic() -> Self {
    Self {
      query: PermissionQueryDisposition::Evaluate,
      request: PermissionRequestDisposition::AddSessionPositive,
      revoke: PermissionRevokeDisposition::AddSessionNegative,
    }
  }

  fn static_only() -> Self {
    Self {
      query: PermissionQueryDisposition::Evaluate,
      request: PermissionRequestDisposition::Refuse,
      revoke: PermissionRevokeDisposition::AddSessionNegative,
    }
  }

  fn permits(self, operation: PermissionOperation) -> bool {
    match operation {
      PermissionOperation::Query => {
        self.query == PermissionQueryDisposition::Evaluate
      }
      PermissionOperation::Request => {
        self.request == PermissionRequestDisposition::AddSessionPositive
      }
      PermissionOperation::Revoke => {
        self.revoke == PermissionRevokeDisposition::AddSessionNegative
      }
    }
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
enum PermissionAtomicity {
  Conjunctive,
}

/// Generated, trusted metadata for the one permission edge selected by the
/// descriptor boundary. It has no wire deserializer and cannot carry effects.
#[derive(Clone, Debug)]
pub(crate) struct GeneratedPermissionSlotSpec {
  slot_id: String,
  operation_effect_slot_id: String,
  capability: String,
  positive_projection_id: String,
  negative_projection_id: String,
  transitions: PermissionTransitionDispositions,
}

impl GeneratedPermissionSlotSpec {
  fn capture_generated(
    slot_id: String,
    operation_effect_slot_id: String,
    capability: String,
    positive_projection_id: String,
    negative_projection_id: String,
    transitions: PermissionTransitionDispositions,
  ) -> Result<Self, PermissionProtocolError> {
    validate_component("generatedSlotId", &slot_id)?;
    validate_component(
      "generatedOperationEffectSlotId",
      &operation_effect_slot_id,
    )?;
    validate_component("generatedSlotCapability", &capability)?;
    validate_component(
      "generatedSlotPositiveProjection",
      &positive_projection_id,
    )?;
    validate_component(
      "generatedSlotNegativeProjection",
      &negative_projection_id,
    )?;
    Ok(Self {
      slot_id,
      operation_effect_slot_id,
      capability,
      positive_projection_id,
      negative_projection_id,
      transitions,
    })
  }
}

#[derive(Clone, Debug)]
pub(crate) struct SelectedGeneratedPermissionBranch {
  branch_id: String,
  coverage_edge_id: String,
  slot_order: Box<[GeneratedPermissionSlotSpec]>,
  principal_effect_bound: usize,
}

impl SelectedGeneratedPermissionBranch {
  fn capture_generated(
    branch_id: String,
    coverage_edge_id: String,
    slot_order: Vec<GeneratedPermissionSlotSpec>,
    principal_effect_bound: usize,
  ) -> Result<Self, PermissionProtocolError> {
    validate_component("generatedBranchId", &branch_id)?;
    validate_component("coverageEdgeId", &coverage_edge_id)?;
    if slot_order.is_empty() {
      return Err(PermissionProtocolError::Empty("generatedSlotOrder"));
    }
    if slot_order.len() > MAX_GENERATED_EFFECTS {
      return Err(PermissionProtocolError::BoundExceeded(
        "generatedEffectBound",
      ));
    }
    if principal_effect_bound == 0
      || principal_effect_bound > MAX_PRINCIPAL_EFFECT_PRODUCT
    {
      return Err(PermissionProtocolError::BoundExceeded(
        "generatedPrincipalEffectBound",
      ));
    }
    let mut slots = BTreeSet::new();
    for slot in &slot_order {
      if !slots.insert(slot.slot_id.as_str()) {
        return Err(PermissionProtocolError::DuplicateGeneratedSlot);
      }
    }
    Ok(Self {
      branch_id,
      coverage_edge_id,
      slot_order: slot_order.into(),
      principal_effect_bound,
    })
  }

  pub(crate) fn coverage_edge_id(&self) -> &str {
    &self.coverage_edge_id
  }

  fn ensure_transition(
    &self,
    operation: PermissionOperation,
  ) -> Result<(), PermissionProtocolError> {
    if self
      .slot_order
      .iter()
      .all(|slot| slot.transitions.permits(operation))
    {
      Ok(())
    } else {
      Err(PermissionProtocolError::TransitionRefused)
    }
  }
}

fn transition_dispositions_from_generated(
  query: &str,
  request: &str,
  revoke: &str,
) -> Result<PermissionTransitionDispositions, PermissionProtocolError> {
  let query = match query {
    "evaluate" | "evaluate-static-only" => PermissionQueryDisposition::Evaluate,
    "refuse-static-only" | "refuse-unsupported-descriptor" => {
      PermissionQueryDisposition::Refuse
    }
    _ => return Err(PermissionProtocolError::InvalidField("queryTransition")),
  };
  let request = match request {
    "compare-and-commit-session-positive" => {
      PermissionRequestDisposition::AddSessionPositive
    }
    "refuse-static-only" | "refuse-unsupported-descriptor" => {
      PermissionRequestDisposition::Refuse
    }
    _ => {
      return Err(PermissionProtocolError::InvalidField("requestTransition"));
    }
  };
  let revoke = match revoke {
    "compare-and-commit-session-revocation" => {
      PermissionRevokeDisposition::AddSessionNegative
    }
    "refuse-static-only" | "refuse-unsupported-descriptor" => {
      PermissionRevokeDisposition::Refuse
    }
    _ => return Err(PermissionProtocolError::InvalidField("revokeTransition")),
  };
  Ok(PermissionTransitionDispositions {
    query,
    request,
    revoke,
  })
}

/// Select one closed descriptor branch from the generated C04 protocol.
/// Unknown, refused, and operation-inapplicable rows fail closed before a
/// batch can retain caller-controlled effects.
fn select_generated_permission_branch(
  branch_id: &str,
  operation: PermissionOperation,
) -> Result<SelectedGeneratedPermissionBranch, PermissionProtocolError> {
  let branch = REV2_RUNTIME_PERMISSION_BRANCHES
    .iter()
    .find(|candidate| candidate.id == branch_id)
    .ok_or(PermissionProtocolError::SlotNotGenerated)?;
  if branch.disposition != "normalize" {
    return Err(PermissionProtocolError::TransitionRefused);
  }
  let coverage_edge_id = match operation {
    PermissionOperation::Query => branch.operation_edge_ids.query,
    PermissionOperation::Request => branch.operation_edge_ids.request,
    PermissionOperation::Revoke => branch.operation_edge_ids.revoke,
  };
  let mut slots = Vec::with_capacity(branch.slot_order.len());
  for slot in branch.slot_order {
    let operation_effect_slot_id = match operation {
      PermissionOperation::Query => slot.operation_effect_slot_ids.query,
      PermissionOperation::Request => slot.operation_effect_slot_ids.request,
      PermissionOperation::Revoke => slot.operation_effect_slot_ids.revoke,
    };
    let transitions = transition_dispositions_from_generated(
      slot.transitions.query,
      slot.transitions.request,
      slot.transitions.revoke,
    )?;
    let Some(operation_effect_slot_id) = operation_effect_slot_id else {
      return Err(PermissionProtocolError::TransitionRefused);
    };
    slots.push(GeneratedPermissionSlotSpec::capture_generated(
      slot.slot_id.to_string(),
      operation_effect_slot_id.to_string(),
      slot.capability.to_string(),
      slot.positive_projection_id.to_string(),
      slot.negative_projection_id.to_string(),
      transitions,
    )?);
  }
  SelectedGeneratedPermissionBranch::capture_generated(
    branch.id.to_string(),
    coverage_edge_id.to_string(),
    slots,
    MAX_PRINCIPAL_EFFECT_PRODUCT,
  )
}

/// One host-verified live attribution capture.
///
/// Construction stays private to this dormant protocol module until the
/// reviewed generated descriptor/attribution adapter exists. A batch receives
/// this opaque proof instead of independently supplied principal and owner
/// slices that could describe different captures.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct VerifiedPermissionActorSet {
  constrained_principals: Box<[PrincipalRef]>,
  overlay_owner: PrincipalRef,
}

impl VerifiedPermissionActorSet {
  fn capture_host(
    constrained_principals: &[PrincipalRef],
    overlay_owner: PrincipalRef,
  ) -> Result<Self, PermissionProtocolError> {
    if constrained_principals.is_empty() {
      return Err(PermissionProtocolError::Empty("constrainedPrincipals"));
    }
    if constrained_principals.len() > MAX_CONSTRAINED_PRINCIPALS {
      return Err(PermissionProtocolError::BoundExceeded(
        "constrainedPrincipals",
      ));
    }
    validate_component("overlayOwner.key", &overlay_owner.key)?;
    let mut canonical_principals =
      Vec::with_capacity(constrained_principals.len());
    let mut seen_principals =
      HashSet::with_capacity(constrained_principals.len());
    for principal in constrained_principals {
      validate_component("constrainedPrincipal.key", &principal.key)?;
      let canonical = canonical_serialization(
        principal,
        MAX_CANONICAL_EFFECT_BYTES,
        "constrainedPrincipal",
      )?
      .into_bytes();
      if !seen_principals.insert(canonical.clone()) {
        return Err(PermissionProtocolError::DuplicatePrincipal);
      }
      canonical_principals.push((canonical, principal.clone()));
    }
    canonical_principals.sort_by(|left, right| left.0.cmp(&right.0));
    let constrained_principals = canonical_principals
      .into_iter()
      .map(|(_, principal)| principal)
      .collect::<Vec<_>>();
    if constrained_principals
      .iter()
      .all(|principal| principal != &overlay_owner)
    {
      return Err(PermissionProtocolError::OverlayOwnerNotConstrained);
    }
    Ok(Self {
      constrained_principals: constrained_principals.into(),
      overlay_owner,
    })
  }

  fn constrained_principals(&self) -> &[PrincipalRef] {
    &self.constrained_principals
  }

  fn overlay_owner(&self) -> &PrincipalRef {
    &self.overlay_owner
  }
}

/// One permission effect captured from the shared core's typed canonical
/// effect. The compact wire shape omits only fields that are exactly implied
/// and revalidated against the selected generated edge and slot; the complete
/// `CanonicalEffect` remains retained for native evaluation and duplicate
/// identity.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct NormalizedPermissionEffect {
  slot_id: String,
  effect_owner: PrincipalRef,
  selector: CanonicalAuthoritySelector,
  canonical_effect: CanonicalEffect,
}

impl NormalizedPermissionEffect {
  fn capture_host(
    effect_owner: PrincipalRef,
    selector: CanonicalAuthoritySelector,
    canonical_effect: CanonicalEffect,
  ) -> Result<Self, PermissionProtocolError> {
    let slot_id = canonical_effect.effect_slot_id.clone();
    Self::capture_generated_slot(
      slot_id,
      effect_owner,
      selector,
      canonical_effect,
    )
  }

  fn capture_generated_slot(
    slot_id: String,
    effect_owner: PrincipalRef,
    selector: CanonicalAuthoritySelector,
    canonical_effect: CanonicalEffect,
  ) -> Result<Self, PermissionProtocolError> {
    validate_component("effect.logicalSlotId", &slot_id)?;
    validate_component("effect.slotId", &canonical_effect.effect_slot_id)?;
    validate_component("effect.effectOwner.key", &effect_owner.key)?;
    validate_component(
      "effect.canonicalOwner",
      &canonical_effect.effect_owner,
    )?;
    if selector.principal.as_ref() != Some(&effect_owner) {
      return Err(PermissionProtocolError::EffectOwnerSelectorMismatch);
    }
    if canonical_effect.effect_owner != effect_owner.key {
      return Err(PermissionProtocolError::EffectOwnerCanonicalMismatch);
    }
    if selector.capability != canonical_effect.capability {
      return Err(PermissionProtocolError::EffectCapabilityMismatch);
    }
    if canonical_effect
      .occurrence
      .get("effectOwner")
      .and_then(Value::as_str)
      != Some(effect_owner.key.as_str())
    {
      return Err(PermissionProtocolError::EffectOwnerOccurrenceMismatch);
    }
    canonical_serialization(
      &selector,
      MAX_CANONICAL_EFFECT_BYTES,
      "effectSelector",
    )?;
    canonical_serialization(
      &canonical_effect,
      MAX_CANONICAL_EFFECT_BYTES,
      "canonicalEffect",
    )?;
    Ok(Self {
      slot_id,
      effect_owner,
      selector,
      canonical_effect,
    })
  }

  pub(crate) fn slot_id(&self) -> &str {
    &self.slot_id
  }

  pub(crate) fn effect_owner(&self) -> &PrincipalRef {
    &self.effect_owner
  }

  pub(crate) fn selector(&self) -> &CanonicalAuthoritySelector {
    &self.selector
  }

  pub(crate) fn canonical_effect(&self) -> &CanonicalEffect {
    &self.canonical_effect
  }
}

impl Serialize for NormalizedPermissionEffect {
  fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
  where
    S: Serializer,
  {
    let mut effect = serializer.serialize_struct("PermissionEffect", 4)?;
    effect.serialize_field("slotId", self.slot_id())?;
    effect.serialize_field("effectOwner", &self.effect_owner)?;
    effect.serialize_field("selector", &self.selector)?;
    effect.serialize_field("occurrence", &self.canonical_effect.occurrence)?;
    effect.end()
  }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PermissionEffectIdentity<'a> {
  effect_owner: &'a PrincipalRef,
  selector: &'a CanonicalAuthoritySelector,
  occurrence: &'a Value,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct PermissionBatchDigestPayload<'a> {
  schema: &'static str,
  batch_sequence: CanonicalU64,
  operation: PermissionOperation,
  coverage_edge_id: &'a str,
  atomicity: PermissionAtomicity,
  identity: &'a RuntimeIdentityBinding,
  expected_generations: RuntimeGenerationVector,
  constrained_principals: &'a [PrincipalRef],
  overlay_owner: &'a PrincipalRef,
  effects: &'a [NormalizedPermissionEffect],
}

/// The complete normalized permission batch. Construction captures identity
/// and generations from one immutable authority read view and has no serde
/// input path.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct NormalizedPermissionBatch {
  schema: &'static str,
  batch_sequence: CanonicalU64,
  operation: PermissionOperation,
  coverage_edge_id: String,
  atomicity: PermissionAtomicity,
  identity: RuntimeIdentityBinding,
  expected_generations: RuntimeGenerationVector,
  constrained_principals: Box<[PrincipalRef]>,
  overlay_owner: PrincipalRef,
  effects: Box<[NormalizedPermissionEffect]>,
  batch_digest: String,
  #[serde(skip)]
  authority_view: RuntimeAuthorityReadView,
  #[serde(skip)]
  external_response_consumed: AtomicBool,
}

impl NormalizedPermissionBatch {
  fn capture_host(
    state: &RuntimeAuthorityState,
    read_view: &RuntimeAuthorityReadView,
    batch_sequence: OdenRev2PermissionBatchSequence,
    operation: PermissionOperation,
    generated: &SelectedGeneratedPermissionBranch,
    actors: &VerifiedPermissionActorSet,
    effects: &[NormalizedPermissionEffect],
  ) -> Result<Self, PermissionProtocolError> {
    require_current_view(state, read_view)?;
    generated.ensure_transition(operation)?;
    if effects.len() != generated.slot_order.len() {
      return Err(PermissionProtocolError::IncompleteGeneratedSlotSet);
    }
    let constrained_principals = actors.constrained_principals();
    let overlay_owner = actors.overlay_owner();
    let work = constrained_principals
      .len()
      .checked_mul(effects.len())
      .ok_or(PermissionProtocolError::BoundExceeded(
        "principalEffectProduct",
      ))?;
    if work > generated.principal_effect_bound
      || work > MAX_PRINCIPAL_EFFECT_PRODUCT
    {
      return Err(PermissionProtocolError::BoundExceeded(
        "principalEffectProduct",
      ));
    }

    let mut slots = BTreeSet::new();
    let mut canonical_effects = BTreeSet::new();
    for (effect, generated_slot) in effects.iter().zip(&generated.slot_order) {
      if constrained_principals
        .iter()
        .all(|principal| principal != effect.effect_owner())
      {
        return Err(PermissionProtocolError::EffectOwnerNotConstrained);
      }
      if !slots.insert(effect.slot_id()) {
        return Err(PermissionProtocolError::DuplicateSlot);
      }
      if effect.slot_id() != generated_slot.slot_id {
        if generated
          .slot_order
          .iter()
          .any(|slot| slot.slot_id == effect.slot_id())
        {
          return Err(PermissionProtocolError::SlotOrder);
        }
        return Err(PermissionProtocolError::SlotNotGenerated);
      }
      let canonical_effect = effect.canonical_effect();
      if canonical_effect.effect_slot_id
        != generated_slot.operation_effect_slot_id
      {
        return Err(PermissionProtocolError::EffectEdgeMismatch);
      }
      if canonical_effect.edge_id != generated.coverage_edge_id {
        return Err(PermissionProtocolError::EffectEdgeMismatch);
      }
      if canonical_effect.capability != generated_slot.capability
        || effect.selector().capability != generated_slot.capability
      {
        return Err(PermissionProtocolError::EffectCapabilityMismatch);
      }
      if effect.selector().projection_id
        != generated_slot.positive_projection_id
        || canonical_effect.projection_id
          != generated_slot.negative_projection_id
      {
        return Err(PermissionProtocolError::EffectProjectionMismatch);
      }
      let identity = PermissionEffectIdentity {
        effect_owner: effect.effect_owner(),
        selector: effect.selector(),
        occurrence: &canonical_effect.occurrence,
      };
      let canonical = canonical_serialization(
        &identity,
        MAX_CANONICAL_EFFECT_BYTES,
        "canonicalEffectIdentity",
      )?;
      if !canonical_effects.insert(canonical) {
        return Err(PermissionProtocolError::DuplicateEffect);
      }
    }

    let identity = read_view.identity().clone();
    let expected_generations = read_view.generations();
    let constrained_principals: Box<[PrincipalRef]> =
      constrained_principals.to_vec().into();
    let effects: Box<[NormalizedPermissionEffect]> = effects.to_vec().into();
    let batch_sequence = batch_sequence.into_value();
    let digest_payload = PermissionBatchDigestPayload {
      schema: PERMISSION_BATCH_SCHEMA,
      batch_sequence: CanonicalU64(batch_sequence),
      operation,
      coverage_edge_id: generated.coverage_edge_id(),
      atomicity: PermissionAtomicity::Conjunctive,
      identity: &identity,
      expected_generations,
      constrained_principals: &constrained_principals,
      overlay_owner,
      effects: &effects,
    };
    let canonical = canonical_serialization(
      &digest_payload,
      MAX_CANONICAL_BATCH_BYTES,
      "permissionBatch",
    )?;
    let mut digest = Sha256::new();
    digest.update(PERMISSION_BATCH_DIGEST_DOMAIN);
    digest.update(canonical.as_bytes());
    let batch_digest =
      format!("sha256-{}", URL_SAFE_NO_PAD.encode(digest.finalize()));

    require_current_view(state, read_view)?;
    Ok(Self {
      schema: PERMISSION_BATCH_SCHEMA,
      batch_sequence: CanonicalU64(batch_sequence),
      operation,
      coverage_edge_id: generated.coverage_edge_id.clone(),
      atomicity: PermissionAtomicity::Conjunctive,
      identity,
      expected_generations,
      constrained_principals,
      overlay_owner: overlay_owner.clone(),
      effects,
      batch_digest,
      authority_view: read_view.clone(),
      external_response_consumed: AtomicBool::new(false),
    })
  }

  pub(crate) fn batch_sequence(&self) -> u64 {
    self.batch_sequence.0
  }

  pub(crate) fn operation(&self) -> PermissionOperation {
    self.operation
  }

  pub(crate) fn coverage_edge_id(&self) -> &str {
    &self.coverage_edge_id
  }

  pub(crate) fn identity(&self) -> &RuntimeIdentityBinding {
    &self.identity
  }

  pub(crate) fn expected_generations(&self) -> RuntimeGenerationVector {
    self.expected_generations
  }

  pub(crate) fn constrained_principals(&self) -> &[PrincipalRef] {
    &self.constrained_principals
  }

  pub(crate) fn overlay_owner(&self) -> &PrincipalRef {
    &self.overlay_owner
  }

  pub(crate) fn effects(&self) -> &[NormalizedPermissionEffect] {
    &self.effects
  }

  pub(crate) fn batch_digest(&self) -> &str {
    &self.batch_digest
  }

  pub(crate) fn canonical_json(
    &self,
  ) -> Result<String, PermissionProtocolError> {
    canonical_serialization(self, MAX_CANONICAL_BATCH_BYTES, "permissionBatch")
  }

  fn session_revoke_transaction(
    &self,
    state: &RuntimeAuthorityState,
    current_result: &PermissionBatchResult,
  ) -> Result<AuthorityTransaction, PermissionProtocolError> {
    require_current_view(state, &self.authority_view)?;
    if self.operation != PermissionOperation::Revoke
      || current_result.batch_sequence != self.batch_sequence
      || current_result.operation != PermissionOperation::Revoke
      || current_result.batch_digest != self.batch_digest
      || current_result.identity != self.identity
      || current_result.observed_generations
        != self.authority_view.generations()
      || current_result.effects.len() != self.effects.len()
    {
      return Err(PermissionProtocolError::ExternalMutationRefused);
    }
    let mut transaction = state.begin_transaction_from(&self.authority_view)?;
    for (effect, result) in self.effects.iter().zip(current_result.effects()) {
      if effect.slot_id() != result.slot_id() {
        return Err(PermissionProtocolError::IncompleteResult);
      }
      for dimension in result.dimensions() {
        let mut revocation_selector = effect.selector().clone();
        revocation_selector.principal = Some(dimension.principal().clone());
        revocation_selector.projection_id =
          effect.canonical_effect().projection_id.clone();
        transaction.upsert_session_revocation(
          self.overlay_owner(),
          dimension.principal(),
          &revocation_selector,
        )?;
      }
    }
    require_current_view(state, &self.authority_view)?;
    Ok(transaction)
  }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum PermissionState {
  Granted,
  Prompt,
  Denied,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PermissionDimensionResult {
  principal: PrincipalRef,
  state: PermissionState,
  positive_source: Option<PositiveSource>,
}

fn validate_positive_source(
  source: &PositiveSource,
) -> Result<(), PermissionProtocolError> {
  if validate_component("positiveSource.kind", &source.kind).is_err()
    || validate_component("positiveSource.sourceId", &source.source_id).is_err()
  {
    return Err(PermissionProtocolError::InvalidPositiveSource);
  }
  if let Some(generation) = &source.generation {
    if generation.is_empty() || generation.len() > MAX_CANONICAL_U64_BYTES {
      return Err(PermissionProtocolError::InvalidPositiveSource);
    }
    let parsed = generation
      .parse::<u64>()
      .map_err(|_| PermissionProtocolError::InvalidPositiveSource)?;
    if parsed.to_string() != *generation {
      return Err(PermissionProtocolError::InvalidPositiveSource);
    }
  }
  Ok(())
}

impl PermissionDimensionResult {
  fn capture_host(
    principal: PrincipalRef,
    state: PermissionState,
    positive_source: Option<PositiveSource>,
  ) -> Result<Self, PermissionProtocolError> {
    validate_component("resultDimension.principal.key", &principal.key)?;
    if (state == PermissionState::Granted) != positive_source.is_some() {
      return Err(PermissionProtocolError::InvalidPositiveSource);
    }
    if let Some(source) = &positive_source {
      validate_positive_source(source)?;
    }
    Ok(Self {
      principal,
      state,
      positive_source,
    })
  }

  pub(crate) fn principal(&self) -> &PrincipalRef {
    &self.principal
  }

  pub(crate) fn state(&self) -> PermissionState {
    self.state
  }

  pub(crate) fn positive_source(&self) -> Option<&PositiveSource> {
    self.positive_source.as_ref()
  }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PermissionEffectResult {
  slot_id: String,
  state: PermissionState,
  dimensions: Box<[PermissionDimensionResult]>,
}

impl PermissionEffectResult {
  fn capture_host(
    slot_id: String,
    dimensions: &[PermissionDimensionResult],
  ) -> Result<Self, PermissionProtocolError> {
    validate_component("resultEffect.slotId", &slot_id)?;
    if dimensions.is_empty() {
      return Err(PermissionProtocolError::IncompleteResult);
    }
    if dimensions.len() > MAX_CONSTRAINED_PRINCIPALS {
      return Err(PermissionProtocolError::BoundExceeded("resultDimensions"));
    }
    let mut canonical_dimensions = Vec::with_capacity(dimensions.len());
    let mut seen_principals = HashSet::with_capacity(dimensions.len());
    for dimension in dimensions {
      let principal = canonical_serialization(
        &dimension.principal,
        MAX_CANONICAL_EFFECT_BYTES,
        "resultDimension.principal",
      )?
      .into_bytes();
      if !seen_principals.insert(principal) {
        return Err(PermissionProtocolError::DuplicatePrincipal);
      }
      let canonical = canonical_serialization(
        dimension,
        MAX_CANONICAL_EFFECT_BYTES,
        "resultDimension",
      )?
      .into_bytes();
      canonical_dimensions.push((canonical, dimension.clone()));
    }
    canonical_dimensions.sort_by(|left, right| left.0.cmp(&right.0));
    let dimensions = canonical_dimensions
      .into_iter()
      .map(|(_, dimension)| dimension)
      .collect::<Vec<_>>();
    let state = dimensions
      .iter()
      .map(PermissionDimensionResult::state)
      .max()
      .ok_or(PermissionProtocolError::IncompleteResult)?;
    Ok(Self {
      slot_id,
      state,
      dimensions: dimensions.into(),
    })
  }

  pub(crate) fn slot_id(&self) -> &str {
    &self.slot_id
  }

  pub(crate) fn state(&self) -> PermissionState {
    self.state
  }

  pub(crate) fn dimensions(&self) -> &[PermissionDimensionResult] {
    &self.dimensions
  }
}

/// A complete internal permission result. Aggregate state is always derived
/// from the complete ordered effect vector; callers cannot supply it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PermissionBatchResult {
  schema: &'static str,
  batch_sequence: CanonicalU64,
  operation: PermissionOperation,
  batch_digest: String,
  identity: RuntimeIdentityBinding,
  observed_generations: RuntimeGenerationVector,
  state: PermissionState,
  effects: Box<[PermissionEffectResult]>,
}

impl PermissionBatchResult {
  fn capture_complete(
    batch: &NormalizedPermissionBatch,
    observed_view: &RuntimeAuthorityReadView,
    effects: &[PermissionEffectResult],
  ) -> Result<Self, PermissionProtocolError> {
    if observed_view.identity() != batch.identity() {
      return Err(PermissionProtocolError::IdentityMismatch);
    }
    if effects.len() != batch.effects().len()
      || effects
        .iter()
        .zip(batch.effects())
        .any(|(result, effect)| result.slot_id() != effect.slot_id())
    {
      return Err(PermissionProtocolError::IncompleteResult);
    }
    let expected_principals = batch
      .constrained_principals()
      .iter()
      .map(|principal| {
        canonical_serialization(
          principal,
          MAX_CANONICAL_EFFECT_BYTES,
          "resultExpectedPrincipal",
        )
        .map(String::into_bytes)
      })
      .collect::<Result<HashSet<_>, _>>()?;
    for effect in effects {
      if effect.dimensions().len() != expected_principals.len() {
        return Err(PermissionProtocolError::IncompleteResult);
      }
      let actual_principals = effect
        .dimensions()
        .iter()
        .map(|dimension| {
          canonical_serialization(
            dimension.principal(),
            MAX_CANONICAL_EFFECT_BYTES,
            "resultObservedPrincipal",
          )
          .map(String::into_bytes)
        })
        .collect::<Result<HashSet<_>, _>>()?;
      if actual_principals != expected_principals {
        return Err(PermissionProtocolError::IncompleteResult);
      }
    }
    let aggregate_state = effects
      .iter()
      .map(PermissionEffectResult::state)
      .max()
      .ok_or(PermissionProtocolError::IncompleteResult)?;
    let result = Self {
      schema: PERMISSION_RESULT_SCHEMA,
      batch_sequence: batch.batch_sequence,
      operation: batch.operation,
      batch_digest: batch.batch_digest.clone(),
      identity: batch.identity.clone(),
      observed_generations: observed_view.generations(),
      state: aggregate_state,
      effects: effects.to_vec().into(),
    };
    canonical_serialization(
      &result,
      MAX_CANONICAL_RESULT_BYTES,
      "permissionResult",
    )?;
    Ok(result)
  }

  fn capture_query_current(
    state: &RuntimeAuthorityState,
    batch: &NormalizedPermissionBatch,
    observed_view: &RuntimeAuthorityReadView,
    effects: &[PermissionEffectResult],
  ) -> Result<Self, PermissionProtocolError> {
    if batch.operation() != PermissionOperation::Query {
      return Err(PermissionProtocolError::TransitionRefused);
    }
    require_current_view(state, &batch.authority_view)?;
    require_current_view(state, observed_view)?;
    let result = Self::capture_complete(batch, observed_view, effects)?;
    require_current_view(state, &batch.authority_view)?;
    require_current_view(state, observed_view)?;
    Ok(result)
  }

  fn capture_proposed_mutation(
    batch: &NormalizedPermissionBatch,
    proposed_view: &RuntimeAuthorityReadView,
    effects: &[PermissionEffectResult],
  ) -> Result<Self, PermissionProtocolError> {
    if batch.operation() == PermissionOperation::Query {
      return Err(PermissionProtocolError::TransitionRefused);
    }
    proposed_view
      .generations()
      .ensure_monotonic_from(&batch.expected_generations())?;
    Self::capture_complete(batch, proposed_view, effects)
  }

  pub(crate) fn state(&self) -> PermissionState {
    self.state
  }

  pub(crate) fn effects(&self) -> &[PermissionEffectResult] {
    &self.effects
  }

  pub(crate) fn observed_generations(&self) -> RuntimeGenerationVector {
    self.observed_generations
  }
}

/// Test-only exercise of the future typed mutation-result seam.
///
/// Production intentionally has no request/revoke row builder yet: stable row
/// identity and the exact missing-row projection belong to the generated
/// semantic registry batch. This helper proves that a result is evaluated
/// against the complete proposed view inside compare/propose/validate/commit,
/// and is returned only with the publication that passed validation.
#[cfg(test)]
fn commit_mutation_result_for_test(
  state: &RuntimeAuthorityState,
  batch: &NormalizedPermissionBatch,
  transaction: AuthorityTransaction,
  effects: &[PermissionEffectResult],
) -> Result<
  CommittedAuthorityTransaction<PermissionBatchResult>,
  PermissionProtocolError,
> {
  let mut validation_error = None;
  let committed =
    state.compare_propose_validate_commit(transaction, |proposed_view| {
      match PermissionBatchResult::capture_proposed_mutation(
        batch,
        proposed_view,
        effects,
      ) {
        Ok(result) => Ok(result),
        Err(error) => {
          validation_error = Some(error);
          Err(AuthorityStateError::InvalidField("permissionResult"))
        }
      }
    });
  match committed {
    Ok(committed) => Ok(committed),
    Err(_) if validation_error.is_some() => Err(validation_error.unwrap()),
    Err(error) => Err(error.into()),
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub(crate) enum ExternalPermissionDecision {
  Granted,
  Denied,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ExternalResponseMacPayload<'a> {
  schema: &'static str,
  batch_sequence: CanonicalU64,
  operation: PermissionOperation,
  batch_digest: &'a str,
  identity: &'a RuntimeIdentityBinding,
  expected_generations: RuntimeGenerationVector,
  decision: ExternalPermissionDecision,
}

/// Transport-decoded external response. This record intentionally has no
/// `Deserialize`; a later authenticated broker adapter must construct it from
/// its closed parser and provide the exact 32-byte tag.
#[derive(Clone, Debug)]
pub(crate) struct AuthenticatedExternalPermissionResponse {
  batch_sequence: CanonicalU64,
  operation: PermissionOperation,
  batch_digest: String,
  identity: RuntimeIdentityBinding,
  expected_generations: RuntimeGenerationVector,
  decision: ExternalPermissionDecision,
  authentication_tag: [u8; 32],
}

impl Serialize for AuthenticatedExternalPermissionResponse {
  fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
  where
    S: Serializer,
  {
    let mut response = serializer
      .serialize_struct("AuthenticatedExternalPermissionResponse", 8)?;
    response.serialize_field("schema", EXTERNAL_RESPONSE_SCHEMA)?;
    response.serialize_field("batchSequence", &self.batch_sequence)?;
    response.serialize_field("operation", &self.operation)?;
    response.serialize_field("batchDigest", &self.batch_digest)?;
    response.serialize_field("identity", &self.identity)?;
    response
      .serialize_field("expectedGenerations", &self.expected_generations)?;
    response.serialize_field("decision", &self.decision)?;
    response.serialize_field(
      "authenticationTag",
      &URL_SAFE_NO_PAD.encode(self.authentication_tag),
    )?;
    response.end()
  }
}

impl AuthenticatedExternalPermissionResponse {
  #[allow(clippy::too_many_arguments)]
  fn capture_host(
    batch_sequence: u64,
    operation: PermissionOperation,
    batch_digest: String,
    identity: RuntimeIdentityBinding,
    expected_generations: RuntimeGenerationVector,
    decision: ExternalPermissionDecision,
    authentication_tag: [u8; 32],
  ) -> Result<Self, PermissionProtocolError> {
    validate_component("externalResponse.batchDigest", &batch_digest)?;
    Ok(Self {
      batch_sequence: CanonicalU64(batch_sequence),
      operation,
      batch_digest,
      identity,
      expected_generations,
      decision,
      authentication_tag,
    })
  }

  fn mac_payload(&self) -> ExternalResponseMacPayload<'_> {
    ExternalResponseMacPayload {
      schema: EXTERNAL_RESPONSE_SCHEMA,
      batch_sequence: self.batch_sequence,
      operation: self.operation,
      batch_digest: &self.batch_digest,
      identity: &self.identity,
      expected_generations: self.expected_generations,
      decision: self.decision,
    }
  }
}

/// Host-private response authenticator. Successful verification consumes the
/// target batch's response latch atomically; the same response cannot be used
/// twice even when verification races across native tasks.
pub(crate) struct PermissionResponseAuthenticator {
  key: Box<[u8]>,
}

/// One authenticated external decision bound to the exact still-current
/// authority publication captured after verification. It is deliberately not
/// cloneable. A mutation consumer must consume it to seed a transaction from
/// that exact view; the authority compare/propose path then refuses if another
/// publication won the race.
#[derive(Debug)]
pub(crate) struct AuthenticatedExternalPermissionDecision<'batch> {
  decision: ExternalPermissionDecision,
  batch: &'batch NormalizedPermissionBatch,
  authority_view: RuntimeAuthorityReadView,
}

/// An inert, exact-scope proof that an external broker granted one Request.
///
/// The whole closed batch remains borrowed, preserving its digest, ordered
/// effects, typed owners, actor set, and base publication. No transaction
/// builder exists yet: stable session-row identity and the exact missing-row
/// projection must come from the future generated semantic registry batch.
#[derive(Debug)]
pub(crate) struct AuthenticatedExternalRequestGrant<'batch> {
  batch: &'batch NormalizedPermissionBatch,
  authority_view: RuntimeAuthorityReadView,
}

impl<'batch> AuthenticatedExternalRequestGrant<'batch> {
  fn into_session_transaction(
    self,
    state: &RuntimeAuthorityState,
    pre_result: &PermissionBatchResult,
  ) -> Result<AuthorityTransaction, PermissionProtocolError> {
    require_current_view(state, &self.authority_view)?;
    if pre_result.batch_sequence != self.batch.batch_sequence
      || pre_result.operation != PermissionOperation::Request
      || pre_result.batch_digest != self.batch.batch_digest
      || pre_result.identity != self.batch.identity
      || pre_result.observed_generations != self.authority_view.generations()
      || pre_result.effects.len() != self.batch.effects.len()
      || pre_result.state == PermissionState::Denied
    {
      return Err(PermissionProtocolError::ExternalMutationRefused);
    }
    let mut transaction = state.begin_transaction_from(&self.authority_view)?;
    for (effect, result) in self.batch.effects.iter().zip(pre_result.effects())
    {
      if effect.slot_id() != result.slot_id() {
        return Err(PermissionProtocolError::IncompleteResult);
      }
      for dimension in result.dimensions() {
        match dimension.state() {
          PermissionState::Granted => continue,
          PermissionState::Denied => {
            return Err(PermissionProtocolError::ExternalMutationRefused);
          }
          PermissionState::Prompt => {}
        }
        let mut positive_selector = effect.selector().clone();
        positive_selector.principal = Some(dimension.principal().clone());
        let mut revocation_selector = positive_selector.clone();
        revocation_selector.projection_id =
          effect.canonical_effect().projection_id.clone();
        transaction.reconcile_session_grant(
          self.batch.overlay_owner(),
          dimension.principal(),
          &positive_selector,
          &revocation_selector,
        )?;
      }
    }
    require_current_view(state, &self.authority_view)?;
    Ok(transaction)
  }
}

/// Authentication is necessary but insufficient: all seven generated
/// negative strata must be re-evaluated against the exact current view before
/// an external answer can become a result or mutation permit.
#[derive(Debug)]
pub(crate) struct NegativeReentryProof<'batch> {
  decision: ExternalPermissionDecision,
  batch: &'batch NormalizedPermissionBatch,
  authority_view: RuntimeAuthorityReadView,
}

impl<'batch> AuthenticatedExternalPermissionDecision<'batch> {
  fn revalidate_current_negatives<F>(
    self,
    state: &RuntimeAuthorityState,
    evaluate: F,
  ) -> Result<NegativeReentryProof<'batch>, PermissionProtocolError>
  where
    F: FnOnce(
      &RuntimeAuthorityReadView,
      &NormalizedPermissionBatch,
      &[crate::rev2_registry_generated::Rev2RuntimeNegativeReentryPhase],
    ) -> Result<(), PermissionProtocolError>,
  {
    if !state.is_current(&self.authority_view)? {
      return Err(PermissionProtocolError::StaleAuthorityView);
    }
    evaluate(
      &self.authority_view,
      self.batch,
      crate::rev2_registry_generated::REV2_RUNTIME_NEGATIVE_REENTRY_PHASES,
    )?;
    if !state.is_current(&self.authority_view)? {
      return Err(PermissionProtocolError::StaleAuthorityView);
    }
    Ok(NegativeReentryProof {
      decision: self.decision,
      batch: self.batch,
      authority_view: self.authority_view,
    })
  }
}

impl<'batch> NegativeReentryProof<'batch> {
  fn into_request_grant(
    self,
  ) -> Result<AuthenticatedExternalRequestGrant<'batch>, PermissionProtocolError>
  {
    if self.decision != ExternalPermissionDecision::Granted
      || self.batch.operation() != PermissionOperation::Request
    {
      return Err(PermissionProtocolError::ExternalMutationRefused);
    }
    Ok(AuthenticatedExternalRequestGrant {
      batch: self.batch,
      authority_view: self.authority_view,
    })
  }
}

impl PermissionResponseAuthenticator {
  fn capture_host(key: &[u8]) -> Result<Self, PermissionProtocolError> {
    if key.len() != EXTERNAL_RESPONSE_KEY_BYTES {
      return Err(PermissionProtocolError::InvalidField("externalResponseKey"));
    }
    Ok(Self { key: key.into() })
  }

  pub(crate) fn authenticate<'batch>(
    &self,
    state: &RuntimeAuthorityState,
    batch: &'batch NormalizedPermissionBatch,
    response: &AuthenticatedExternalPermissionResponse,
  ) -> Result<
    AuthenticatedExternalPermissionDecision<'batch>,
    PermissionProtocolError,
  > {
    let canonical = canonical_serialization(
      &response.mac_payload(),
      MAX_CANONICAL_BATCH_BYTES,
      "externalResponse",
    )?;
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&self.key)
      .map_err(|_| PermissionProtocolError::AuthenticationFailed)?;
    mac.update(EXTERNAL_RESPONSE_MAC_DOMAIN);
    mac.update(canonical.as_bytes());
    mac
      .verify_slice(&response.authentication_tag)
      .map_err(|_| PermissionProtocolError::AuthenticationFailed)?;

    // Authentication makes this an answer for some real batch on this
    // channel. Consume before freshness checks so a stale authenticated answer
    // invalidates the old attempt instead of allowing answer substitution.
    batch
      .external_response_consumed
      .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
      .map_err(|_| PermissionProtocolError::ResponseReplay)?;
    if &response.identity != batch.identity() {
      return Err(PermissionProtocolError::IdentityMismatch);
    }
    if response.expected_generations != batch.expected_generations() {
      return Err(PermissionProtocolError::GenerationMismatch);
    }
    if response.batch_sequence.0 != batch.batch_sequence() {
      return Err(PermissionProtocolError::BatchSequenceMismatch);
    }
    if response.operation != batch.operation() {
      return Err(PermissionProtocolError::OperationMismatch);
    }
    if response.batch_digest != batch.batch_digest() {
      return Err(PermissionProtocolError::BatchDigestMismatch);
    }
    let current_view = state.read_view()?;
    require_current_view(state, &current_view)?;
    if current_view.identity() != batch.identity()
      || current_view.generations() != batch.expected_generations()
      || !state.is_current(&batch.authority_view)?
    {
      return Err(PermissionProtocolError::StaleAuthorityView);
    }
    Ok(AuthenticatedExternalPermissionDecision {
      decision: response.decision,
      batch,
      authority_view: current_view,
    })
  }

  #[cfg(test)]
  fn sign_for_test(
    &self,
    response: &AuthenticatedExternalPermissionResponse,
  ) -> [u8; 32] {
    let canonical = canonical_serialization(
      &response.mac_payload(),
      MAX_CANONICAL_BATCH_BYTES,
      "externalResponse",
    )
    .unwrap();
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&self.key).unwrap();
    mac.update(EXTERNAL_RESPONSE_MAC_DOMAIN);
    mac.update(canonical.as_bytes());
    mac.finalize().into_bytes().into()
  }
}

impl Drop for PermissionResponseAuthenticator {
  fn drop(&mut self) {
    for byte in self.key.iter_mut() {
      // SAFETY: `byte` is a valid uniquely borrowed location in the owned key
      // allocation. Volatile writes plus the fence prevent dead-store removal.
      unsafe { std::ptr::write_volatile(byte, 0) };
    }
    compiler_fence(Ordering::SeqCst);
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::oden_rev2_authority::AuthorityRowKind;
  use crate::oden_rev2_authority::RuntimeAuthorityState;
  use crate::rev2::PrincipalKind;

  fn digest(character: char) -> String {
    format!(
      "sha256-{}",
      URL_SAFE_NO_PAD.encode(Sha256::digest([character as u8]))
    )
  }

  fn identity(run_nonce: &str) -> RuntimeIdentityBinding {
    RuntimeIdentityBinding::new(
      digest('A'),
      digest('B'),
      digest('C'),
      digest('D'),
      digest('E'),
      run_nonce.to_string(),
      "channel-epoch".to_string(),
    )
    .unwrap()
  }

  fn principal(key: &str) -> PrincipalRef {
    principal_of_kind(PrincipalKind::Package, key)
  }

  fn principal_of_kind(kind: PrincipalKind, key: &str) -> PrincipalRef {
    PrincipalRef {
      kind,
      key: key.to_string(),
    }
  }

  fn selector(owner: &PrincipalRef, name: &str) -> CanonicalAuthoritySelector {
    CanonicalAuthoritySelector {
      principal: Some(owner.clone()),
      capability: "env:read".to_string(),
      projection_id: "projection.env:read.positive/2".to_string(),
      resource: serde_json::json!({ "name": name }),
    }
  }

  fn effect(
    slot: &str,
    owner: &PrincipalRef,
    name: &str,
  ) -> NormalizedPermissionEffect {
    let canonical_effect = CanonicalEffect {
      edge_id: "generated:permission-edge".to_string(),
      effect_slot_id: slot.to_string(),
      capability: "env:read".to_string(),
      effect_owner: owner.key.clone(),
      projection_id: "projection.env:read.negative/2".to_string(),
      occurrence: serde_json::json!({
        "effectOwner": owner.key,
        "kind": "read",
        "name": name,
      }),
    };
    NormalizedPermissionEffect::capture_host(
      owner.clone(),
      selector(owner, name),
      canonical_effect,
    )
    .unwrap()
  }

  fn generated_slot(slot: &str) -> GeneratedPermissionSlotSpec {
    generated_slot_with_transitions(
      slot,
      PermissionTransitionDispositions::dynamic(),
    )
  }

  fn generated_slot_with_transitions(
    slot: &str,
    transitions: PermissionTransitionDispositions,
  ) -> GeneratedPermissionSlotSpec {
    GeneratedPermissionSlotSpec::capture_generated(
      slot.to_string(),
      slot.to_string(),
      "env:read".to_string(),
      "projection.env:read.positive/2".to_string(),
      "projection.env:read.negative/2".to_string(),
      transitions,
    )
    .unwrap()
  }

  fn generated_branch(
    slots: &[&str],
    work_bound: usize,
  ) -> SelectedGeneratedPermissionBranch {
    SelectedGeneratedPermissionBranch::capture_generated(
      "generated:test-branch".to_string(),
      "generated:permission-edge".to_string(),
      slots.iter().map(|slot| generated_slot(slot)).collect(),
      work_bound,
    )
    .unwrap()
  }

  fn actors(
    constrained_principals: &[PrincipalRef],
    overlay_owner: &PrincipalRef,
  ) -> VerifiedPermissionActorSet {
    VerifiedPermissionActorSet::capture_host(
      constrained_principals,
      overlay_owner.clone(),
    )
    .unwrap()
  }

  fn sequence(value: u64) -> OdenRev2PermissionBatchSequence {
    OdenRev2PermissionBatchSequence::for_test(value)
  }

  fn batch(
    state: &RuntimeAuthorityState,
    view: &RuntimeAuthorityReadView,
    sequence: u64,
    operation: PermissionOperation,
    effects: &[NormalizedPermissionEffect],
  ) -> NormalizedPermissionBatch {
    let owner = principal("pkg:owner");
    let slots = effects
      .iter()
      .map(NormalizedPermissionEffect::slot_id)
      .collect::<Vec<_>>();
    let generated = generated_branch(&slots, MAX_PRINCIPAL_EFFECT_PRODUCT);
    let actors = actors(std::slice::from_ref(&owner), &owner);
    NormalizedPermissionBatch::capture_host(
      state,
      view,
      self::sequence(sequence),
      operation,
      &generated,
      &actors,
      effects,
    )
    .unwrap()
  }

  fn positive_source(slot: &str) -> PositiveSource {
    PositiveSource {
      kind: "static-floor".to_string(),
      source_id: format!("floor:{slot}"),
      generation: None,
    }
  }

  fn dimension(
    principal: &PrincipalRef,
    state: PermissionState,
    suffix: &str,
  ) -> PermissionDimensionResult {
    PermissionDimensionResult::capture_host(
      principal.clone(),
      state,
      (state == PermissionState::Granted).then(|| positive_source(suffix)),
    )
    .unwrap()
  }

  fn result(
    slot: &str,
    principal: &PrincipalRef,
    state: PermissionState,
  ) -> PermissionEffectResult {
    PermissionEffectResult::capture_host(
      slot.to_string(),
      &[dimension(principal, state, slot)],
    )
    .unwrap()
  }

  fn authenticator() -> PermissionResponseAuthenticator {
    PermissionResponseAuthenticator::capture_host(&[0x5a; 32]).unwrap()
  }

  fn signed_response(
    authenticator: &PermissionResponseAuthenticator,
    batch: &NormalizedPermissionBatch,
  ) -> AuthenticatedExternalPermissionResponse {
    signed_response_with_decision(
      authenticator,
      batch,
      ExternalPermissionDecision::Granted,
    )
  }

  fn signed_response_with_decision(
    authenticator: &PermissionResponseAuthenticator,
    batch: &NormalizedPermissionBatch,
    decision: ExternalPermissionDecision,
  ) -> AuthenticatedExternalPermissionResponse {
    let mut response = AuthenticatedExternalPermissionResponse::capture_host(
      batch.batch_sequence(),
      batch.operation(),
      batch.batch_digest().to_string(),
      batch.identity().clone(),
      batch.expected_generations(),
      decision,
      [0; 32],
    )
    .unwrap();
    response.authentication_tag = authenticator.sign_for_test(&response);
    response
  }

  fn resign(
    authenticator: &PermissionResponseAuthenticator,
    response: &mut AuthenticatedExternalPermissionResponse,
  ) {
    response.authentication_tag = authenticator.sign_for_test(response);
  }

  #[test]
  fn canonical_batch_digest_uses_the_closed_jcs_preimage() {
    let state = RuntimeAuthorityState::new(identity("run-a"));
    let view = state.read_view().unwrap();
    let owner = principal("pkg:owner");
    let effects = [effect("slot:0", &owner, "HOME")];
    let batch = batch(&state, &view, 7, PermissionOperation::Request, &effects);
    let canonical = batch.canonical_json().unwrap();
    let encoded: Value = serde_json::from_str(&canonical).unwrap();
    assert_eq!(encoded["schema"], PERMISSION_BATCH_SCHEMA);
    assert_eq!(encoded["batchSequence"], "7");
    assert_eq!(encoded["atomicity"], "conjunctive");
    assert_eq!(encoded["batchDigest"], batch.batch_digest());
    assert_eq!(
      batch.batch_digest(),
      "sha256-210pltsUw3p05PMinLp3ZV8Zh6b4600hrEVSnh4-3bE"
    );
  }

  #[test]
  fn generated_protocol_drives_branch_slots_bounds_and_response_schema() {
    let owner = principal("pkg:owner");
    let generated = select_generated_permission_branch(
      "permission.read.scoped/2",
      PermissionOperation::Query,
    )
    .unwrap();
    assert_eq!(
      generated.coverage_edge_id(),
      "native-op:runtime/ops/permissions.rs#op_query_permission"
    );
    assert_eq!(generated.slot_order[0].slot_id, "permission.read:slot:0");
    assert_eq!(
      generated.slot_order[0].operation_effect_slot_id,
      "native-op:runtime/ops/permissions.rs#op_query_permission:effect-slot:5"
    );
    assert_eq!(
      generated.principal_effect_bound,
      MAX_PRINCIPAL_EFFECT_PRODUCT
    );
    assert_eq!(MAX_GENERATED_EFFECTS, REV2_RUNTIME_MAX_BATCH_EFFECTS);

    let canonical_effect = CanonicalEffect {
      edge_id: generated.coverage_edge_id().to_string(),
      effect_slot_id: generated.slot_order[0].operation_effect_slot_id.clone(),
      capability: "fs:read".to_string(),
      effect_owner: owner.key.clone(),
      projection_id: "projection.fs:read.negative/2".to_string(),
      occurrence: serde_json::json!({
        "effectOwner": owner.key,
        "finalObjectState": {
          "identity": { "kind": "opaque-token", "value": "file:example" },
          "kind": "existing",
        },
        "followMode": "follow-final",
        "lexicalPath": { "encoding": "unicode", "value": "example.txt" },
        "parentIdentity": { "kind": "opaque-token", "value": "dir:example" },
        "root": "$PROJECT",
        "rootBindingId": "root-binding:project",
      }),
    };
    let effect = NormalizedPermissionEffect::capture_generated_slot(
      generated.slot_order[0].slot_id.clone(),
      owner.clone(),
      CanonicalAuthoritySelector {
        principal: Some(owner.clone()),
        capability: "fs:read".to_string(),
        projection_id: "projection.fs:read.positive/2".to_string(),
        resource: serde_json::json!({
          "kind": "path-exact",
          "path": { "encoding": "unicode", "value": "example.txt" },
          "root": "$PROJECT",
        }),
      },
      canonical_effect,
    )
    .unwrap();
    let state = RuntimeAuthorityState::new(identity("run-generated"));
    let view = state.read_view().unwrap();
    let batch = NormalizedPermissionBatch::capture_host(
      &state,
      &view,
      sequence(1),
      PermissionOperation::Query,
      &generated,
      &actors(std::slice::from_ref(&owner), &owner),
      &[effect],
    )
    .unwrap();
    assert_eq!(batch.effects()[0].slot_id(), "permission.read:slot:0");
    assert_eq!(
      batch.canonical_json().unwrap().len() <= MAX_CANONICAL_BATCH_BYTES,
      true
    );

    let response = signed_response(&authenticator(), &batch);
    let encoded = serde_json::to_value(response).unwrap();
    assert_eq!(encoded["schema"], REV2_RUNTIME_EXTERNAL_RESPONSE_SCHEMA);
    assert_ne!(
      REV2_RUNTIME_EXTERNAL_RESPONSE_SCHEMA,
      REV2_RUNTIME_EXTERNAL_RESPONSE_MAC_DOMAIN
    );

    assert_eq!(
      select_generated_permission_branch(
        "permission.env.scoped-refusal/2",
        PermissionOperation::Query,
      )
      .unwrap_err(),
      PermissionProtocolError::TransitionRefused
    );
    assert_eq!(
      select_generated_permission_branch(
        "permission.run.scoped/2",
        PermissionOperation::Request,
      )
      .unwrap_err(),
      PermissionProtocolError::TransitionRefused
    );
  }

  #[test]
  fn protocol_sets_use_complete_jcs_element_order() {
    let state = RuntimeAuthorityState::new(identity("run-canonical-sets"));
    let view = state.read_view().unwrap();
    let package_a = principal_of_kind(PrincipalKind::Package, "a");
    let root_z = principal_of_kind(PrincipalKind::Root, "z");
    let actors = actors(&[root_z.clone(), package_a.clone()], &package_a);
    let generated = generated_branch(&["slot:0"], 2);
    let effects = [effect("slot:0", &package_a, "HOME")];
    let batch = NormalizedPermissionBatch::capture_host(
      &state,
      &view,
      sequence(8),
      PermissionOperation::Query,
      &generated,
      &actors,
      &effects,
    )
    .unwrap();
    let encoded: Value =
      serde_json::from_str(&batch.canonical_json().unwrap()).unwrap();
    assert_eq!(
      encoded["constrainedPrincipals"],
      serde_json::json!([
        { "key": "a", "kind": "package" },
        { "key": "z", "kind": "root" },
      ])
    );

    let dimension = |principal: PrincipalRef, source_id: &str| {
      PermissionDimensionResult::capture_host(
        principal,
        PermissionState::Granted,
        Some(PositiveSource {
          kind: "static-floor".to_string(),
          source_id: source_id.to_string(),
          generation: None,
        }),
      )
      .unwrap()
    };
    let result = PermissionEffectResult::capture_host(
      "slot:0".to_string(),
      &[
        dimension(package_a, "source-z"),
        dimension(root_z, "source-a"),
      ],
    )
    .unwrap();
    assert_eq!(result.dimensions[0].principal.kind, PrincipalKind::Root);
    assert_eq!(result.dimensions[1].principal.kind, PrincipalKind::Package);
    let complete = PermissionBatchResult::capture_query_current(
      &state,
      &batch,
      &view,
      std::slice::from_ref(&result),
    )
    .unwrap();
    assert_eq!(complete.state(), PermissionState::Granted);
    let canonical = result
      .dimensions
      .iter()
      .map(|dimension| {
        canonical_serialization(
          dimension,
          MAX_CANONICAL_EFFECT_BYTES,
          "testDimension",
        )
        .unwrap()
      })
      .collect::<Vec<_>>();
    let mut sorted = canonical.clone();
    sorted.sort();
    assert_eq!(canonical, sorted);
  }

  #[test]
  fn generated_order_duplicates_empty_sets_and_work_bounds_refuse() {
    assert_eq!(
      SelectedGeneratedPermissionBranch::capture_generated(
        "branch".to_string(),
        "edge".to_string(),
        vec![generated_slot("slot:0"), generated_slot("slot:0")],
        4,
      )
      .unwrap_err(),
      PermissionProtocolError::DuplicateGeneratedSlot
    );

    let state = RuntimeAuthorityState::new(identity("run-a"));
    let view = state.read_view().unwrap();
    let owner = principal("pkg:owner");
    let first = effect("slot:0", &owner, "HOME");
    let second = effect("slot:1", &owner, "PATH");
    let third = effect("slot:2", &owner, "SHELL");
    let generated = generated_branch(&["slot:0", "slot:1"], 4);
    let owner_actor = actors(std::slice::from_ref(&owner), &owner);
    assert_eq!(
      NormalizedPermissionBatch::capture_host(
        &state,
        &view,
        sequence(1),
        PermissionOperation::Query,
        &generated,
        &owner_actor,
        &[],
      )
      .unwrap_err(),
      PermissionProtocolError::IncompleteGeneratedSlotSet
    );
    assert_eq!(
      NormalizedPermissionBatch::capture_host(
        &state,
        &view,
        sequence(2),
        PermissionOperation::Query,
        &generated,
        &owner_actor,
        std::slice::from_ref(&first),
      )
      .unwrap_err(),
      PermissionProtocolError::IncompleteGeneratedSlotSet
    );
    assert_eq!(
      NormalizedPermissionBatch::capture_host(
        &state,
        &view,
        sequence(3),
        PermissionOperation::Query,
        &generated,
        &owner_actor,
        &[first.clone(), second.clone(), third],
      )
      .unwrap_err(),
      PermissionProtocolError::IncompleteGeneratedSlotSet
    );
    assert_eq!(
      NormalizedPermissionBatch::capture_host(
        &state,
        &view,
        sequence(4),
        PermissionOperation::Query,
        &generated,
        &owner_actor,
        &[second.clone(), first.clone()],
      )
      .unwrap_err(),
      PermissionProtocolError::SlotOrder
    );
    assert_eq!(
      NormalizedPermissionBatch::capture_host(
        &state,
        &view,
        sequence(5),
        PermissionOperation::Query,
        &generated,
        &owner_actor,
        &[first.clone(), first],
      )
      .unwrap_err(),
      PermissionProtocolError::DuplicateSlot
    );

    let other = principal("pkg:other");
    let two_actors = actors(&[owner.clone(), other], &owner);
    let one_slot = generated_branch(&["slot:1"], 1);
    assert_eq!(
      NormalizedPermissionBatch::capture_host(
        &state,
        &view,
        sequence(6),
        PermissionOperation::Query,
        &one_slot,
        &two_actors,
        std::slice::from_ref(&second),
      )
      .unwrap_err(),
      PermissionProtocolError::BoundExceeded("principalEffectProduct")
    );

    let original = effect("slot:0", &owner, "HOME");
    let mut duplicate_canonical = original.canonical_effect().clone();
    duplicate_canonical.effect_slot_id = "slot:1".to_string();
    let duplicate_identity = NormalizedPermissionEffect::capture_host(
      owner.clone(),
      original.selector().clone(),
      duplicate_canonical,
    )
    .unwrap();
    assert_eq!(
      NormalizedPermissionBatch::capture_host(
        &state,
        &view,
        sequence(7),
        PermissionOperation::Query,
        &generated,
        &owner_actor,
        &[original, duplicate_identity],
      )
      .unwrap_err(),
      PermissionProtocolError::DuplicateEffect
    );
  }

  #[test]
  fn actor_capture_transition_dispositions_and_exact_aggregate_are_sealed() {
    let owner = principal("pkg:owner");
    let deputy = principal("pkg:deputy");
    assert_eq!(
      VerifiedPermissionActorSet::capture_host(&[], owner.clone()).unwrap_err(),
      PermissionProtocolError::Empty("constrainedPrincipals")
    );
    assert_eq!(
      VerifiedPermissionActorSet::capture_host(
        std::slice::from_ref(&deputy),
        owner.clone(),
      )
      .unwrap_err(),
      PermissionProtocolError::OverlayOwnerNotConstrained
    );

    let state = RuntimeAuthorityState::new(identity("run-sealed"));
    let view = state.read_view().unwrap();
    let owner_actor = actors(std::slice::from_ref(&owner), &owner);
    let deputy_effect = effect("slot:0", &deputy, "HOME");
    let one_slot = generated_branch(&["slot:0"], 1);
    assert_eq!(
      NormalizedPermissionBatch::capture_host(
        &state,
        &view,
        sequence(20),
        PermissionOperation::Query,
        &one_slot,
        &owner_actor,
        &[deputy_effect],
      )
      .unwrap_err(),
      PermissionProtocolError::EffectOwnerNotConstrained
    );

    let static_only = SelectedGeneratedPermissionBranch::capture_generated(
      "generated:static-only".to_string(),
      "generated:permission-edge".to_string(),
      vec![generated_slot_with_transitions(
        "slot:0",
        PermissionTransitionDispositions::static_only(),
      )],
      1,
    )
    .unwrap();
    let one_effect = [effect("slot:0", &owner, "HOME")];
    assert_eq!(
      NormalizedPermissionBatch::capture_host(
        &state,
        &view,
        sequence(21),
        PermissionOperation::Request,
        &static_only,
        &owner_actor,
        &one_effect,
      )
      .unwrap_err(),
      PermissionProtocolError::TransitionRefused
    );
    assert!(
      NormalizedPermissionBatch::capture_host(
        &state,
        &view,
        sequence(22),
        PermissionOperation::Query,
        &static_only,
        &owner_actor,
        &one_effect,
      )
      .is_ok()
    );
    assert!(
      NormalizedPermissionBatch::capture_host(
        &state,
        &view,
        sequence(23),
        PermissionOperation::Revoke,
        &static_only,
        &owner_actor,
        &one_effect,
      )
      .is_ok()
    );

    let mixed = SelectedGeneratedPermissionBranch::capture_generated(
      "generated:mixed".to_string(),
      "generated:permission-edge".to_string(),
      vec![
        generated_slot("slot:0"),
        generated_slot_with_transitions(
          "slot:1",
          PermissionTransitionDispositions::static_only(),
        ),
      ],
      2,
    )
    .unwrap();
    let mixed_effects = [
      effect("slot:0", &owner, "HOME"),
      effect("slot:1", &owner, "PATH"),
    ];
    assert_eq!(
      NormalizedPermissionBatch::capture_host(
        &state,
        &view,
        sequence(24),
        PermissionOperation::Request,
        &mixed,
        &owner_actor,
        &mixed_effects,
      )
      .unwrap_err(),
      PermissionProtocolError::TransitionRefused
    );

    let aggregate_actors = actors(&[owner.clone(), deputy], &owner);
    let aggregate = generated_branch(&["slot:0", "slot:1"], 4);
    let aggregate_effects = [
      effect("slot:0", &owner, "HOME"),
      effect("slot:1", &owner, "PATH"),
    ];
    // Production has no raw-integer constructor for this argument: only the
    // context returns the opaque, single-use token. Tests use its cfg(test)
    // issuer so the dormant protocol can be exercised before installation.
    let aggregate_batch = NormalizedPermissionBatch::capture_host(
      &state,
      &view,
      sequence(25),
      PermissionOperation::Request,
      &aggregate,
      &aggregate_actors,
      &aggregate_effects,
    )
    .unwrap();
    assert_eq!(aggregate_batch.batch_sequence(), 25);
    assert_eq!(aggregate_batch.effects().len(), 2);
    assert_eq!(aggregate_batch.effects()[0].slot_id(), "slot:0");
    assert_eq!(aggregate_batch.effects()[1].slot_id(), "slot:1");
    assert_eq!(aggregate_batch.constrained_principals().len(), 2);
    assert_eq!(aggregate_batch.overlay_owner(), &owner);
  }

  #[test]
  fn owner_selector_and_shared_effect_substitution_refuse() {
    let owner = principal("pkg:owner");
    let other = principal("pkg:other");
    let canonical = effect("slot:0", &owner, "HOME");
    assert_eq!(
      NormalizedPermissionEffect::capture_host(
        other,
        canonical.selector().clone(),
        canonical.canonical_effect().clone(),
      )
      .unwrap_err(),
      PermissionProtocolError::EffectOwnerSelectorMismatch
    );

    let mut canonical_owner_substitution = canonical.canonical_effect().clone();
    canonical_owner_substitution.effect_owner = "pkg:attacker".to_string();
    canonical_owner_substitution.occurrence["effectOwner"] =
      Value::String("pkg:attacker".to_string());
    assert_eq!(
      NormalizedPermissionEffect::capture_host(
        owner.clone(),
        canonical.selector().clone(),
        canonical_owner_substitution,
      )
      .unwrap_err(),
      PermissionProtocolError::EffectOwnerCanonicalMismatch
    );

    let mut occurrence_substitution = canonical.canonical_effect().clone();
    occurrence_substitution.occurrence["effectOwner"] =
      Value::String("pkg:attacker".to_string());
    assert_eq!(
      NormalizedPermissionEffect::capture_host(
        owner.clone(),
        canonical.selector().clone(),
        occurrence_substitution,
      )
      .unwrap_err(),
      PermissionProtocolError::EffectOwnerOccurrenceMismatch
    );

    let mut capability_substitution = canonical.canonical_effect().clone();
    capability_substitution.capability = "env:write".to_string();
    assert_eq!(
      NormalizedPermissionEffect::capture_host(
        owner.clone(),
        canonical.selector().clone(),
        capability_substitution,
      )
      .unwrap_err(),
      PermissionProtocolError::EffectCapabilityMismatch
    );

    let state = RuntimeAuthorityState::new(identity("run-substitution"));
    let view = state.read_view().unwrap();
    let generated = generated_branch(&["slot:0"], 1);
    let actors = actors(std::slice::from_ref(&owner), &owner);
    let mut wrong_edge = canonical.canonical_effect().clone();
    wrong_edge.edge_id = "generated:other-edge".to_string();
    let wrong_edge = NormalizedPermissionEffect::capture_host(
      owner.clone(),
      canonical.selector().clone(),
      wrong_edge,
    )
    .unwrap();
    assert_eq!(
      NormalizedPermissionBatch::capture_host(
        &state,
        &view,
        sequence(1),
        PermissionOperation::Request,
        &generated,
        &actors,
        &[wrong_edge],
      )
      .unwrap_err(),
      PermissionProtocolError::EffectEdgeMismatch
    );

    let mut wrong_projection = canonical.canonical_effect().clone();
    wrong_projection.projection_id =
      "projection.env:write.negative/2".to_string();
    let wrong_projection = NormalizedPermissionEffect::capture_host(
      owner.clone(),
      canonical.selector().clone(),
      wrong_projection,
    )
    .unwrap();
    assert_eq!(
      NormalizedPermissionBatch::capture_host(
        &state,
        &view,
        sequence(2),
        PermissionOperation::Request,
        &generated,
        &actors,
        &[wrong_projection],
      )
      .unwrap_err(),
      PermissionProtocolError::EffectProjectionMismatch
    );
  }

  #[test]
  fn positive_sources_and_complete_result_encoding_are_closed_and_bounded() {
    let owner = principal("pkg:owner");
    let invalid_sources = [
      PositiveSource {
        kind: String::new(),
        source_id: "source".to_string(),
        generation: None,
      },
      PositiveSource {
        kind: "static-floor".to_string(),
        source_id: String::new(),
        generation: None,
      },
      PositiveSource {
        kind: "x".repeat(MAX_COMPONENT_BYTES + 1),
        source_id: "source".to_string(),
        generation: None,
      },
      PositiveSource {
        kind: "static-floor".to_string(),
        source_id: "x".repeat(MAX_COMPONENT_BYTES + 1),
        generation: None,
      },
      PositiveSource {
        kind: "session-positive".to_string(),
        source_id: "source".to_string(),
        generation: Some("01".to_string()),
      },
      PositiveSource {
        kind: "session-positive".to_string(),
        source_id: "source".to_string(),
        generation: Some("18446744073709551616".to_string()),
      },
      PositiveSource {
        kind: "session-positive".to_string(),
        source_id: "source".to_string(),
        generation: Some("1".repeat(21)),
      },
    ];
    for source in invalid_sources {
      assert_eq!(
        PermissionDimensionResult::capture_host(
          owner.clone(),
          PermissionState::Granted,
          Some(source),
        )
        .unwrap_err(),
        PermissionProtocolError::InvalidPositiveSource
      );
    }
    assert!(
      PermissionDimensionResult::capture_host(
        owner.clone(),
        PermissionState::Granted,
        Some(PositiveSource {
          kind: "session-positive".to_string(),
          source_id: "source".to_string(),
          generation: Some(u64::MAX.to_string()),
        }),
      )
      .is_ok()
    );

    let state = RuntimeAuthorityState::new(identity("run-result-bound"));
    let view = state.read_view().unwrap();
    let mut principals = (0..1023)
      .map(|index| principal(&format!("pkg:bounded-{index:04}")))
      .collect::<Vec<_>>();
    principals.push(owner.clone());
    let actor_set = actors(&principals, &owner);
    let generated = generated_branch(&["slot:0"], principals.len());
    let batch = NormalizedPermissionBatch::capture_host(
      &state,
      &view,
      sequence(30),
      PermissionOperation::Query,
      &generated,
      &actor_set,
      &[effect("slot:0", &owner, "HOME")],
    )
    .unwrap();
    let dimensions = principals
      .iter()
      .map(|principal| {
        PermissionDimensionResult::capture_host(
          principal.clone(),
          PermissionState::Granted,
          Some(PositiveSource {
            kind: "static-floor".to_string(),
            source_id: "x".repeat(MAX_COMPONENT_BYTES),
            generation: None,
          }),
        )
        .unwrap()
      })
      .collect::<Vec<_>>();
    let oversized_effect =
      PermissionEffectResult::capture_host("slot:0".to_string(), &dimensions)
        .unwrap();
    assert_eq!(
      PermissionBatchResult::capture_query_current(
        &state,
        &batch,
        &view,
        &[oversized_effect],
      )
      .unwrap_err(),
      PermissionProtocolError::BoundExceeded("permissionResult")
    );
  }

  #[test]
  fn result_collapse_is_conjunctive_and_partial_aggregates_refuse() {
    let state = RuntimeAuthorityState::new(identity("run-a"));
    let view = state.read_view().unwrap();
    let owner = principal("pkg:owner");
    let deputy = principal("pkg:deputy");
    let effects = [
      effect("slot:0", &owner, "HOME"),
      effect("slot:1", &owner, "PATH"),
    ];
    let actors = actors(&[owner.clone(), deputy.clone()], &owner);
    let generated = generated_branch(&["slot:0", "slot:1"], 4);
    let batch = NormalizedPermissionBatch::capture_host(
      &state,
      &view,
      sequence(3),
      PermissionOperation::Query,
      &generated,
      &actors,
      &effects,
    )
    .unwrap();

    let complete_granted = |slot: &str| {
      PermissionEffectResult::capture_host(
        slot.to_string(),
        &[
          dimension(&owner, PermissionState::Granted, slot),
          dimension(&deputy, PermissionState::Granted, slot),
        ],
      )
      .unwrap()
    };

    assert_eq!(
      PermissionBatchResult::capture_query_current(
        &state,
        &batch,
        &view,
        &[complete_granted("slot:0")],
      )
      .unwrap_err(),
      PermissionProtocolError::IncompleteResult
    );
    let missing_deputy = PermissionEffectResult::capture_host(
      "slot:0".to_string(),
      &[dimension(&owner, PermissionState::Granted, "slot:0")],
    )
    .unwrap();
    assert_eq!(
      PermissionBatchResult::capture_query_current(
        &state,
        &batch,
        &view,
        &[missing_deputy, complete_granted("slot:1")],
      )
      .unwrap_err(),
      PermissionProtocolError::IncompleteResult
    );

    let mixed_prompt = PermissionEffectResult::capture_host(
      "slot:0".to_string(),
      &[
        dimension(&owner, PermissionState::Granted, "slot:0"),
        dimension(&deputy, PermissionState::Prompt, "slot:0"),
      ],
    )
    .unwrap();
    let prompt = PermissionBatchResult::capture_query_current(
      &state,
      &batch,
      &view,
      &[mixed_prompt, complete_granted("slot:1")],
    )
    .unwrap();
    assert_eq!(prompt.state(), PermissionState::Prompt);
    assert_eq!(prompt.effects()[0].dimensions().len(), 2);
    assert!(
      prompt.effects()[0].dimensions()[0]
        .positive_source()
        .is_none()
        || prompt.effects()[0].dimensions()[1]
          .positive_source()
          .is_none()
    );

    let mixed_denied = PermissionEffectResult::capture_host(
      "slot:0".to_string(),
      &[
        dimension(&owner, PermissionState::Granted, "slot:0"),
        dimension(&deputy, PermissionState::Denied, "slot:0"),
      ],
    )
    .unwrap();
    let denied = PermissionBatchResult::capture_query_current(
      &state,
      &batch,
      &view,
      &[mixed_denied, complete_granted("slot:1")],
    )
    .unwrap();
    assert_eq!(denied.state(), PermissionState::Denied);
  }

  #[test]
  fn stale_views_and_responses_after_publication_refuse() {
    let authenticator = authenticator();
    let state = RuntimeAuthorityState::new(identity("run-stale"));
    let stale_view = state.read_view().unwrap();
    let owner = principal("pkg:owner");
    let actor_set = actors(std::slice::from_ref(&owner), &owner);
    let generated = generated_branch(&["slot:0"], 1);
    let effects = [effect("slot:0", &owner, "HOME")];
    let query_batch = NormalizedPermissionBatch::capture_host(
      &state,
      &stale_view,
      sequence(40),
      PermissionOperation::Query,
      &generated,
      &actor_set,
      &effects,
    )
    .unwrap();
    let request_batch = NormalizedPermissionBatch::capture_host(
      &state,
      &stale_view,
      sequence(41),
      PermissionOperation::Request,
      &generated,
      &actor_set,
      &effects,
    )
    .unwrap();
    let response = signed_response(&authenticator, &request_batch);
    let complete_result = PermissionEffectResult::capture_host(
      "slot:0".to_string(),
      &[dimension(&owner, PermissionState::Granted, "slot:0")],
    )
    .unwrap();

    let mut intervening = state.begin_transaction().unwrap();
    intervening
      .upsert(
        AuthorityRowKind::SessionPositive,
        "session:intervening".to_string(),
        &selector(&owner, "HOME"),
      )
      .unwrap();
    let current_view = state.commit(intervening).unwrap();

    assert_eq!(
      NormalizedPermissionBatch::capture_host(
        &state,
        &stale_view,
        sequence(42),
        PermissionOperation::Query,
        &generated,
        &actor_set,
        &effects,
      )
      .unwrap_err(),
      PermissionProtocolError::StaleAuthorityView
    );
    assert_eq!(
      PermissionBatchResult::capture_query_current(
        &state,
        &query_batch,
        &stale_view,
        std::slice::from_ref(&complete_result),
      )
      .unwrap_err(),
      PermissionProtocolError::StaleAuthorityView
    );
    assert_eq!(
      PermissionBatchResult::capture_query_current(
        &state,
        &query_batch,
        &current_view,
        std::slice::from_ref(&complete_result),
      )
      .unwrap_err(),
      PermissionProtocolError::StaleAuthorityView
    );
    assert_eq!(
      authenticator
        .authenticate(&state, &request_batch, &response)
        .unwrap_err(),
      PermissionProtocolError::StaleAuthorityView
    );
    assert_eq!(
      authenticator
        .authenticate(&state, &request_batch, &response)
        .unwrap_err(),
      PermissionProtocolError::ResponseReplay
    );
  }

  #[test]
  fn external_grant_proof_is_request_only_exact_scope_and_inert() {
    let authenticator = authenticator();
    let state = RuntimeAuthorityState::new(identity("run-proof"));
    let view = state.read_view().unwrap();
    let owner = principal("pkg:owner");
    let effects = [effect("slot:0", &owner, "HOME")];
    let request_batch =
      batch(&state, &view, 50, PermissionOperation::Request, &effects);
    let response = signed_response(&authenticator, &request_batch);
    let authenticated = authenticator
      .authenticate(&state, &request_batch, &response)
      .unwrap();
    let proof = authenticated
      .revalidate_current_negatives(
        &state,
        |proof_view, proof_batch, phases| {
          assert_eq!(proof_view.generations(), view.generations());
          assert_eq!(proof_batch.batch_digest(), request_batch.batch_digest());
          assert_eq!(phases.len(), 7);
          assert!(
            phases
              .iter()
              .all(|phase| phase.strata == [1, 2, 3, 4, 5, 6, 7])
          );
          Ok(())
        },
      )
      .unwrap();
    let grant = proof.into_request_grant().unwrap();
    assert_eq!(grant.batch.batch_digest(), request_batch.batch_digest());
    assert_eq!(grant.batch.effects(), request_batch.effects());
    assert_eq!(grant.batch.overlay_owner(), &owner);
    assert!(state.is_current(&grant.authority_view).unwrap());
    let prompt = PermissionEffectResult::capture_host(
      "slot:0".to_string(),
      &[dimension(&owner, PermissionState::Prompt, "slot:0")],
    )
    .unwrap();
    let pre_result =
      PermissionBatchResult::capture_complete(&request_batch, &view, &[prompt])
        .unwrap();
    let transaction =
      grant.into_session_transaction(&state, &pre_result).unwrap();
    let proposed = state.propose_transaction(transaction).unwrap();
    assert_eq!(proposed.read_view().row_count(), 1);
    drop(proposed);
    assert_eq!(state.read_view().unwrap().row_count(), 0);

    let denied_batch =
      batch(&state, &view, 51, PermissionOperation::Request, &effects);
    let denied_response = signed_response_with_decision(
      &authenticator,
      &denied_batch,
      ExternalPermissionDecision::Denied,
    );
    assert_eq!(
      authenticator
        .authenticate(&state, &denied_batch, &denied_response)
        .unwrap()
        .revalidate_current_negatives(&state, |_, _, _| Ok(()))
        .unwrap()
        .into_request_grant()
        .unwrap_err(),
      PermissionProtocolError::ExternalMutationRefused
    );

    for (sequence, operation) in [
      (52, PermissionOperation::Query),
      (53, PermissionOperation::Revoke),
    ] {
      let non_request = batch(&state, &view, sequence, operation, &effects);
      let response = signed_response(&authenticator, &non_request);
      assert_eq!(
        authenticator
          .authenticate(&state, &non_request, &response)
          .unwrap()
          .revalidate_current_negatives(&state, |_, _, _| Ok(()))
          .unwrap()
          .into_request_grant()
          .unwrap_err(),
        PermissionProtocolError::ExternalMutationRefused
      );
    }

    // A grant proof exposes neither an authority transaction nor caller-chosen
    // row IDs. The separate generated session adapter owns stable identity and
    // transaction reconciliation.
    assert_eq!(state.read_view().unwrap().row_count(), 0);

    let race_batch = batch(
      &state,
      &state.read_view().unwrap(),
      54,
      PermissionOperation::Request,
      &effects,
    );
    let race_response = signed_response(&authenticator, &race_batch);
    let race = authenticator
      .authenticate(&state, &race_batch, &race_response)
      .unwrap();
    assert_eq!(
      race
        .revalidate_current_negatives(&state, |_, _, _| {
          let mut negative = state.begin_transaction().unwrap();
          negative
            .upsert(
              AuthorityRowKind::NegativeOverlay,
              "negative:race".to_string(),
              &selector(&owner, "HOME"),
            )
            .unwrap();
          state.commit(negative).unwrap();
          Ok(())
        })
        .unwrap_err(),
      PermissionProtocolError::StaleAuthorityView
    );
  }

  #[test]
  fn proposed_request_and_revoke_results_publish_atomically_for_test() {
    let owner = principal("pkg:owner");
    for (operation, kind, row_id, result_state) in [
      (
        PermissionOperation::Request,
        AuthorityRowKind::SessionPositive,
        "test:request",
        PermissionState::Granted,
      ),
      (
        PermissionOperation::Revoke,
        AuthorityRowKind::SessionRevocation,
        "test:revoke",
        PermissionState::Denied,
      ),
    ] {
      let state = RuntimeAuthorityState::new(identity(row_id));
      let view = state.read_view().unwrap();
      let effects = [effect("slot:0", &owner, "HOME")];
      let batch = batch(&state, &view, 60, operation, &effects);
      let mut transaction = state.begin_transaction_from(&view).unwrap();
      let mut row_selector = effects[0].selector().clone();
      if operation == PermissionOperation::Revoke {
        row_selector.projection_id =
          effects[0].canonical_effect().projection_id.clone();
      }
      transaction
        .upsert(kind, row_id.to_string(), &row_selector)
        .unwrap();
      let dimensions = if result_state == PermissionState::Granted {
        vec![dimension(&owner, PermissionState::Granted, "slot:0")]
      } else {
        vec![dimension(&owner, PermissionState::Denied, "slot:0")]
      };
      let effect_result =
        PermissionEffectResult::capture_host("slot:0".to_string(), &dimensions)
          .unwrap();
      let committed = commit_mutation_result_for_test(
        &state,
        &batch,
        transaction,
        &[effect_result],
      )
      .unwrap();
      assert_eq!(committed.output().state(), result_state);
      assert_eq!(
        committed.output().observed_generations(),
        committed.read_view().generations()
      );
      assert!(committed.read_view().row(kind, row_id).is_some());
      assert!(state.is_current(committed.read_view()).unwrap());
    }
  }

  #[test]
  fn generated_revoke_builder_uses_stable_session_transaction() {
    let owner = principal("pkg:owner");
    let state = RuntimeAuthorityState::new(identity("run-revoke-builder"));
    let view = state.read_view().unwrap();
    let effects = [effect("slot:0", &owner, "HOME")];
    let batch = batch(&state, &view, 61, PermissionOperation::Revoke, &effects);
    let current = PermissionEffectResult::capture_host(
      "slot:0".to_string(),
      &[dimension(&owner, PermissionState::Granted, "slot:0")],
    )
    .unwrap();
    let current_result =
      PermissionBatchResult::capture_complete(&batch, &view, &[current])
        .unwrap();
    let transaction = batch
      .session_revoke_transaction(&state, &current_result)
      .unwrap();
    let proposed = state.propose_transaction(transaction).unwrap();
    let rows = proposed
      .read_view()
      .rows(AuthorityRowKind::SessionRevocation)
      .collect::<Vec<_>>();
    assert_eq!(rows.len(), 1);
    assert_eq!(
      rows[0].selector().projection_id,
      effects[0].canonical_effect().projection_id
    );
    assert_eq!(state.read_view().unwrap().row_count(), 0);
  }

  #[test]
  fn proposed_result_validation_failure_publishes_no_test_row() {
    let state = RuntimeAuthorityState::new(identity("run-rollback"));
    let view = state.read_view().unwrap();
    let owner = principal("pkg:owner");
    let effects = [effect("slot:0", &owner, "HOME")];
    let batch =
      batch(&state, &view, 61, PermissionOperation::Request, &effects);
    let mut transaction = state.begin_transaction_from(&view).unwrap();
    transaction
      .upsert(
        AuthorityRowKind::SessionPositive,
        "test:must-rollback".to_string(),
        effects[0].selector(),
      )
      .unwrap();
    assert_eq!(
      commit_mutation_result_for_test(&state, &batch, transaction, &[])
        .unwrap_err(),
      PermissionProtocolError::IncompleteResult
    );
    let after = state.read_view().unwrap();
    assert_eq!(after.generations(), view.generations());
    assert!(
      after
        .row(AuthorityRowKind::SessionPositive, "test:must-rollback")
        .is_none()
    );
  }

  #[test]
  fn authenticated_response_rejects_every_substitution_and_replay() {
    let authenticator = authenticator();
    let state = RuntimeAuthorityState::new(identity("run-a"));
    let view = state.read_view().unwrap();
    let owner = principal("pkg:owner");
    let effects = [effect("slot:0", &owner, "HOME")];

    let cross_run_target =
      batch(&state, &view, 11, PermissionOperation::Request, &effects);
    let other_state = RuntimeAuthorityState::new(identity("run-b"));
    let other_view = other_state.read_view().unwrap();
    let other_batch = batch(
      &other_state,
      &other_view,
      11,
      PermissionOperation::Request,
      &effects,
    );
    let cross_run = signed_response(&authenticator, &other_batch);
    assert_eq!(
      authenticator
        .authenticate(&state, &cross_run_target, &cross_run)
        .unwrap_err(),
      PermissionProtocolError::IdentityMismatch
    );
    let exact_after_stale = signed_response(&authenticator, &cross_run_target);
    assert_eq!(
      authenticator
        .authenticate(&state, &cross_run_target, &exact_after_stale)
        .unwrap_err(),
      PermissionProtocolError::ResponseReplay
    );

    let generation_target =
      batch(&state, &view, 12, PermissionOperation::Request, &effects);
    let mut generation_transaction = state.begin_transaction().unwrap();
    generation_transaction
      .upsert(
        AuthorityRowKind::SessionPositive,
        "session:generation-test".to_string(),
        &selector(&owner, "HOME"),
      )
      .unwrap();
    let changed_view = state.commit(generation_transaction).unwrap();
    let mut changed_generation =
      signed_response(&authenticator, &generation_target);
    changed_generation.expected_generations = changed_view.generations();
    resign(&authenticator, &mut changed_generation);
    assert_eq!(
      authenticator
        .authenticate(&state, &generation_target, &changed_generation)
        .unwrap_err(),
      PermissionProtocolError::GenerationMismatch
    );

    let sequence_target = batch(
      &state,
      &changed_view,
      13,
      PermissionOperation::Request,
      &effects,
    );
    let mut changed_sequence =
      signed_response(&authenticator, &sequence_target);
    changed_sequence.batch_sequence = CanonicalU64(14);
    resign(&authenticator, &mut changed_sequence);
    assert_eq!(
      authenticator
        .authenticate(&state, &sequence_target, &changed_sequence)
        .unwrap_err(),
      PermissionProtocolError::BatchSequenceMismatch
    );

    let operation_target = batch(
      &state,
      &changed_view,
      14,
      PermissionOperation::Request,
      &effects,
    );
    let mut changed_operation =
      signed_response(&authenticator, &operation_target);
    changed_operation.operation = PermissionOperation::Revoke;
    resign(&authenticator, &mut changed_operation);
    assert_eq!(
      authenticator
        .authenticate(&state, &operation_target, &changed_operation)
        .unwrap_err(),
      PermissionProtocolError::OperationMismatch
    );

    let digest_target = batch(
      &state,
      &changed_view,
      15,
      PermissionOperation::Request,
      &effects,
    );
    let substituted_effects = [effect("slot:0", &owner, "PATH")];
    let substituted_batch = batch(
      &state,
      &changed_view,
      15,
      PermissionOperation::Request,
      &substituted_effects,
    );
    let changed_digest = signed_response(&authenticator, &substituted_batch);
    assert_eq!(
      authenticator
        .authenticate(&state, &digest_target, &changed_digest)
        .unwrap_err(),
      PermissionProtocolError::BatchDigestMismatch
    );

    let replay_target = batch(
      &state,
      &changed_view,
      16,
      PermissionOperation::Request,
      &effects,
    );
    let exact = signed_response(&authenticator, &replay_target);
    let authenticated = authenticator
      .authenticate(&state, &replay_target, &exact)
      .unwrap();
    assert_eq!(authenticated.decision, ExternalPermissionDecision::Granted);
    assert_eq!(
      authenticator
        .authenticate(&state, &replay_target, &exact)
        .unwrap_err(),
      PermissionProtocolError::ResponseReplay
    );
  }

  #[test]
  fn concurrent_external_response_replay_has_one_winner() {
    let authenticator = authenticator();
    let state = RuntimeAuthorityState::new(identity("run-concurrent"));
    let view = state.read_view().unwrap();
    let owner = principal("pkg:owner");
    let effects = [effect("slot:0", &owner, "HOME")];
    let batch =
      batch(&state, &view, 21, PermissionOperation::Request, &effects);
    let response = signed_response(&authenticator, &batch);
    let outcomes = std::thread::scope(|scope| {
      let first =
        scope.spawn(|| authenticator.authenticate(&state, &batch, &response));
      let second =
        scope.spawn(|| authenticator.authenticate(&state, &batch, &response));
      [first.join().unwrap(), second.join().unwrap()]
    });
    assert_eq!(outcomes.iter().filter(|outcome| outcome.is_ok()).count(), 1);
    assert_eq!(
      outcomes
        .iter()
        .filter(|outcome| {
          matches!(outcome, Err(PermissionProtocolError::ResponseReplay))
        })
        .count(),
      1
    );
  }

  #[test]
  fn unauthenticated_response_never_consumes_the_batch() {
    let authenticator = authenticator();
    let state = RuntimeAuthorityState::new(identity("run-a"));
    let view = state.read_view().unwrap();
    let owner = principal("pkg:owner");
    let effects = [effect("slot:0", &owner, "HOME")];
    let batch =
      batch(&state, &view, 13, PermissionOperation::Request, &effects);
    let mut response = signed_response(&authenticator, &batch);
    response.authentication_tag[0] ^= 0xff;
    assert_eq!(
      authenticator
        .authenticate(&state, &batch, &response)
        .unwrap_err(),
      PermissionProtocolError::AuthenticationFailed
    );
    let exact = signed_response(&authenticator, &batch);
    let authenticated =
      authenticator.authenticate(&state, &batch, &exact).unwrap();
    assert_eq!(authenticated.decision, ExternalPermissionDecision::Granted);
  }
}

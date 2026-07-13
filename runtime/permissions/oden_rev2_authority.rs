// Copyright 2018-2026 the Deno authors. MIT license.

//! Bounded, process-local Rev2 authority state.
//!
//! This module deliberately does not parse the C03 snapshot or translate
//! JavaScript permission descriptors. It accepts only host-constructed,
//! already-canonical identities, rows, cache keys, and cache values. A later
//! integration slice installs it from the sealed C03 context and projects its
//! immutable read views into the shared decision core.
//! @ref LLP 0019#stage-c-runtime-authority-and-typed-permission-checkpoint-c04--eng-24017 [implements]

#![allow(
  dead_code,
  reason = "the C04 authority kernel precedes its reviewed generated descriptor, broker, and operation-actor consumers"
)]

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Serialize;
use serde::Serializer;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::collections::HashMap;
use std::collections::HashSet;
use std::fmt;
use std::hash::Hash;
use std::hash::Hasher;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::MutexGuard;

use crate::oden_rev2_session::{
  OdenRev2SessionRowIds, SessionRowAdmission, classify_same_id_row,
  session_row_ids,
};
use crate::rev2::CanonicalAuthoritySelector;
use crate::rev2::CanonicalEffect;
use crate::rev2::PathBindingInput;
use crate::rev2::PositiveSource;
use crate::rev2::PrincipalRef;
use crate::rev2::canonical_json;
use crate::rev2_registry_generated::{
  REV2_RUNTIME_AUTHORITY_MAX_ROW_BYTES, REV2_RUNTIME_AUTHORITY_MAX_ROWS,
  REV2_RUNTIME_AUTHORITY_MAX_TOTAL_BYTES, REV2_RUNTIME_CACHE_MAX_DIMENSIONS,
  REV2_RUNTIME_CACHE_MAX_EFFECTS, REV2_RUNTIME_CACHE_MAX_ENTRIES,
  REV2_RUNTIME_CACHE_MAX_ENTRY_BYTES, REV2_RUNTIME_CACHE_MAX_PRINCIPALS,
  REV2_RUNTIME_CACHE_MAX_RECEIPT_DEPENDENCIES,
  REV2_RUNTIME_CACHE_MAX_TOTAL_BYTES, REV2_RUNTIME_DECISION_CACHE_KEY_SCHEMA,
  REV2_RUNTIME_GENERATION_TRANSITIONS,
  REV2_RUNTIME_MAX_CANONICAL_COMPONENT_BYTES,
  REV2_RUNTIME_MAX_CANONICAL_EFFECT_BYTES,
  REV2_RUNTIME_MAX_TRANSACTION_MUTATIONS,
};

pub const DECISION_CACHE_MAX_ENTRIES: usize = REV2_RUNTIME_CACHE_MAX_ENTRIES;
pub const DECISION_CACHE_MAX_WEIGHT_BYTES: usize =
  REV2_RUNTIME_CACHE_MAX_TOTAL_BYTES;
pub const DECISION_CACHE_MAX_ENTRY_WEIGHT_BYTES: usize =
  REV2_RUNTIME_CACHE_MAX_ENTRY_BYTES;
pub const AUTHORITY_STATE_MAX_ROWS: usize = REV2_RUNTIME_AUTHORITY_MAX_ROWS;
pub const AUTHORITY_STATE_MAX_WEIGHT_BYTES: usize =
  REV2_RUNTIME_AUTHORITY_MAX_TOTAL_BYTES;
pub const AUTHORITY_STATE_MAX_ROW_WEIGHT_BYTES: usize =
  REV2_RUNTIME_AUTHORITY_MAX_ROW_BYTES;

const MAX_IDENTITY_COMPONENT_BYTES: usize =
  REV2_RUNTIME_MAX_CANONICAL_COMPONENT_BYTES;
const MAX_AUTHORITY_ROW_ID_BYTES: usize =
  REV2_RUNTIME_MAX_CANONICAL_COMPONENT_BYTES;
const MAX_TRANSACTION_MUTATIONS: usize = REV2_RUNTIME_MAX_TRANSACTION_MUTATIONS;
const MAX_CACHE_COMPONENT_BYTES: usize =
  REV2_RUNTIME_MAX_CANONICAL_EFFECT_BYTES;
const MAX_CACHE_CONSTRAINED_PRINCIPALS: usize =
  REV2_RUNTIME_CACHE_MAX_PRINCIPALS;
const MAX_CACHE_EFFECTS: usize = REV2_RUNTIME_CACHE_MAX_EFFECTS;
const MAX_CACHE_DECISION_DIMENSIONS: usize = REV2_RUNTIME_CACHE_MAX_DIMENSIONS;
const MAX_CACHE_RECEIPT_DEPENDENCIES: usize =
  REV2_RUNTIME_CACHE_MAX_RECEIPT_DEPENDENCIES;
const DECISION_CACHE_KEY_SCHEMA: &str = REV2_RUNTIME_DECISION_CACHE_KEY_SCHEMA;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum AuthorityStateError {
  InvalidDigest(&'static str),
  InvalidField(&'static str),
  DuplicateMutation,
  DuplicateRowSourceId,
  TooManyMutations,
  IdentityMismatch,
  GenerationChanged,
  GenerationRollback(&'static str),
  GenerationOverflow(&'static str),
  AuthorityCapacityExceeded(&'static str),
  StateFailClosed,
  CacheKeyStale,
  Serialization(String),
  SessionRowIdentity(String),
  UntypedSessionMutation,
  NamespaceGateReentry,
  LockPoisoned,
}

impl fmt::Display for AuthorityStateError {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::InvalidDigest(field) => {
        write!(formatter, "{field} is not a canonical sha256 digest")
      }
      Self::InvalidField(field) => {
        write!(formatter, "{field} is not a valid closed protocol field")
      }
      Self::DuplicateMutation => {
        formatter.write_str("authority transaction mutates one row twice")
      }
      Self::DuplicateRowSourceId => formatter.write_str(
        "authority row source id occurs in more than one mutable row kind",
      ),
      Self::TooManyMutations => {
        formatter.write_str("authority transaction exceeds its work bound")
      }
      Self::IdentityMismatch => {
        formatter.write_str("runtime authority identity does not match")
      }
      Self::GenerationChanged => {
        formatter.write_str("runtime authority generation changed")
      }
      Self::GenerationRollback(field) => {
        write!(
          formatter,
          "runtime authority generation rolled back: {field}"
        )
      }
      Self::GenerationOverflow(field) => {
        write!(
          formatter,
          "runtime authority generation overflowed: {field}"
        )
      }
      Self::AuthorityCapacityExceeded(limit) => {
        write!(formatter, "runtime authority state exceeded {limit}")
      }
      Self::StateFailClosed => {
        formatter.write_str("runtime authority state is fail-closed")
      }
      Self::CacheKeyStale => formatter.write_str("decision-cache key is stale"),
      Self::Serialization(error) => {
        write!(
          formatter,
          "canonical protocol serialization failed: {error}"
        )
      }
      Self::SessionRowIdentity(error) => {
        write!(formatter, "session-row identity refused: {error}")
      }
      Self::UntypedSessionMutation => formatter.write_str(
        "session rows require a stable-ID typed authority transaction",
      ),
      Self::NamespaceGateReentry => formatter.write_str(
        "runtime authority state cannot be re-locked by its namespace operation thread",
      ),
      Self::LockPoisoned => {
        formatter.write_str("runtime authority state lock is poisoned")
      }
    }
  }
}

impl std::error::Error for AuthorityStateError {}

fn validate_digest(
  field: &'static str,
  value: &str,
) -> Result<(), AuthorityStateError> {
  let Some(encoded) = value.strip_prefix("sha256-") else {
    return Err(AuthorityStateError::InvalidDigest(field));
  };
  let Ok(decoded) = URL_SAFE_NO_PAD.decode(encoded) else {
    return Err(AuthorityStateError::InvalidDigest(field));
  };
  if decoded.len() != 32 || URL_SAFE_NO_PAD.encode(&decoded) != encoded {
    return Err(AuthorityStateError::InvalidDigest(field));
  }
  Ok(())
}

fn canonicalize_typed<T: Serialize>(
  field: &'static str,
  value: &T,
) -> Result<String, AuthorityStateError> {
  let value = serde_json::to_value(value)
    .map_err(|error| AuthorityStateError::Serialization(error.to_string()))?;
  canonical_json(&value).map_err(|error| {
    AuthorityStateError::Serialization(format!("{field}: {error}"))
  })
}

fn validate_component(
  field: &'static str,
  value: &str,
  maximum_bytes: usize,
) -> Result<(), AuthorityStateError> {
  if value.is_empty() || value.len() > maximum_bytes {
    return Err(AuthorityStateError::InvalidField(field));
  }
  Ok(())
}

/// The complete immutable identity of one installed authority context.
///
/// Fields are private so no caller can partially initialize or later mutate
/// the four-digest, project, run, and authenticated-channel binding.
#[derive(Clone, Debug, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeIdentityBinding {
  vocab_digest: String,
  registry_digest: String,
  policy_digest: String,
  armed_snapshot_digest: String,
  project_digest: String,
  run_nonce: String,
  channel_epoch: String,
}

impl RuntimeIdentityBinding {
  pub(crate) fn new(
    vocab_digest: String,
    registry_digest: String,
    policy_digest: String,
    armed_snapshot_digest: String,
    project_digest: String,
    run_nonce: String,
    channel_epoch: String,
  ) -> Result<Self, AuthorityStateError> {
    validate_digest("vocabDigest", &vocab_digest)?;
    validate_digest("registryDigest", &registry_digest)?;
    validate_digest("policyDigest", &policy_digest)?;
    validate_digest("armedSnapshotDigest", &armed_snapshot_digest)?;
    validate_digest("projectDigest", &project_digest)?;
    validate_component("runNonce", &run_nonce, MAX_IDENTITY_COMPONENT_BYTES)?;
    validate_component(
      "channelEpoch",
      &channel_epoch,
      MAX_IDENTITY_COMPONENT_BYTES,
    )?;
    Ok(Self {
      vocab_digest,
      registry_digest,
      policy_digest,
      armed_snapshot_digest,
      project_digest,
      run_nonce,
      channel_epoch,
    })
  }

  pub fn vocab_digest(&self) -> &str {
    &self.vocab_digest
  }

  pub fn registry_digest(&self) -> &str {
    &self.registry_digest
  }

  pub fn policy_digest(&self) -> &str {
    &self.policy_digest
  }

  pub fn armed_snapshot_digest(&self) -> &str {
    &self.armed_snapshot_digest
  }

  pub fn project_digest(&self) -> &str {
    &self.project_digest
  }

  pub fn run_nonce(&self) -> &str {
    &self.run_nonce
  }

  pub fn channel_epoch(&self) -> &str {
    &self.channel_epoch
  }
}

/// A generation is stored as a `u64` but serializes as the LLP's canonical
/// unsigned decimal string.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
struct CanonicalGeneration(u64);

impl Serialize for CanonicalGeneration {
  fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
  where
    S: Serializer,
  {
    serializer.serialize_str(&self.0.to_string())
  }
}

/// One atomic snapshot of all runtime authority generations.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RuntimeGenerationVector {
  negative_overlay: CanonicalGeneration,
  policy_snapshot: CanonicalGeneration,
  revocation: CanonicalGeneration,
  session_overlay: CanonicalGeneration,
}

impl RuntimeGenerationVector {
  fn initial() -> Self {
    Self {
      negative_overlay: CanonicalGeneration(0),
      policy_snapshot: CanonicalGeneration(1),
      revocation: CanonicalGeneration(0),
      session_overlay: CanonicalGeneration(0),
    }
  }

  pub fn negative_overlay(&self) -> u64 {
    self.negative_overlay.0
  }

  pub fn policy_snapshot(&self) -> u64 {
    self.policy_snapshot.0
  }

  pub fn revocation(&self) -> u64 {
    self.revocation.0
  }

  pub fn session_overlay(&self) -> u64 {
    self.session_overlay.0
  }

  /// Reject a vector that would move any generation backwards.
  pub fn ensure_monotonic_from(
    &self,
    previous: &Self,
  ) -> Result<(), AuthorityStateError> {
    for (field, current, old) in [
      (
        "negativeOverlay",
        self.negative_overlay.0,
        previous.negative_overlay.0,
      ),
      (
        "policySnapshot",
        self.policy_snapshot.0,
        previous.policy_snapshot.0,
      ),
      ("revocation", self.revocation.0, previous.revocation.0),
      (
        "sessionOverlay",
        self.session_overlay.0,
        previous.session_overlay.0,
      ),
    ] {
      if current < old {
        return Err(AuthorityStateError::GenerationRollback(field));
      }
    }
    Ok(())
  }

  fn advance(
    self,
    impact: GenerationImpact,
  ) -> Result<Self, AuthorityStateError> {
    let mut next = self;
    if impact.negative_overlay {
      next.negative_overlay =
        CanonicalGeneration(
          next.negative_overlay.0.checked_add(1).ok_or(
            AuthorityStateError::GenerationOverflow("negativeOverlay"),
          )?,
        );
    }
    if impact.revocation {
      next.revocation = CanonicalGeneration(
        next
          .revocation
          .0
          .checked_add(1)
          .ok_or(AuthorityStateError::GenerationOverflow("revocation"))?,
      );
    }
    if impact.session_overlay {
      next.session_overlay = CanonicalGeneration(
        next
          .session_overlay
          .0
          .checked_add(1)
          .ok_or(AuthorityStateError::GenerationOverflow("sessionOverlay"))?,
      );
    }
    Ok(next)
  }

  #[cfg(test)]
  fn for_test(
    negative_overlay: u64,
    policy_snapshot: u64,
    revocation: u64,
    session_overlay: u64,
  ) -> Self {
    Self {
      negative_overlay: CanonicalGeneration(negative_overlay),
      policy_snapshot: CanonicalGeneration(policy_snapshot),
      revocation: CanonicalGeneration(revocation),
      session_overlay: CanonicalGeneration(session_overlay),
    }
  }
}

#[derive(
  Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "kebab-case")]
pub enum AuthorityRowKind {
  SessionPositive,
  SessionRevocation,
  NegativeOverlay,
  Revocation,
}

/// One host-authenticated path identity captured for an exact permission
/// occurrence. This value has no `Deserialize` implementation and is never
/// included in an authority row's wire representation. Session mutation APIs
/// can only attach it while deriving the row's stable id from the matching
/// canonical selector.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct AuthorityPathFact {
  root_binding_id: String,
  #[serde(skip_serializing_if = "Vec::is_empty")]
  final_object_identities: Vec<serde_json::Value>,
  #[serde(skip_serializing_if = "Vec::is_empty")]
  parent_identities: Vec<serde_json::Value>,
}

impl AuthorityPathFact {
  pub(crate) fn capture_verified(
    binding: &PathBindingInput,
    selector: &CanonicalAuthoritySelector,
    occurrence: &serde_json::Value,
  ) -> Result<Self, AuthorityStateError> {
    let resource = selector.resource.as_object().ok_or(
      AuthorityStateError::InvalidField("sessionPathFact.selector"),
    )?;
    if !selector.capability.starts_with("fs:")
      || resource.get("root").is_none()
      || resource.get("path").is_none()
      || binding.source_id.trim().is_empty()
      || binding.root_binding_id.trim().is_empty()
      || binding.final_object_identities.len() > 1
      || binding.parent_identities.len() > 1
    {
      return Err(AuthorityStateError::InvalidField("sessionPathFact"));
    }
    let occurrence =
      occurrence
        .as_object()
        .ok_or(AuthorityStateError::InvalidField(
          "sessionPathFact.occurrence",
        ))?;
    if occurrence.get("root") != resource.get("root")
      || occurrence.get("lexicalPath") != resource.get("path")
      || occurrence
        .get("rootBindingId")
        .and_then(serde_json::Value::as_str)
        != Some(binding.root_binding_id.as_str())
    {
      return Err(AuthorityStateError::InvalidField(
        "sessionPathFact.occurrence",
      ));
    }
    let state = occurrence
      .get("finalObjectState")
      .and_then(serde_json::Value::as_object)
      .ok_or(AuthorityStateError::InvalidField(
        "sessionPathFact.finalObjectState",
      ))?;
    match state.get("kind").and_then(serde_json::Value::as_str) {
      Some("existing" | "link-entry") => {
        let identity =
          state
            .get("identity")
            .ok_or(AuthorityStateError::InvalidField(
              "sessionPathFact.identity",
            ))?;
        if binding.final_object_identities.as_slice()
          != std::slice::from_ref(identity)
          || !binding.parent_identities.is_empty()
        {
          return Err(AuthorityStateError::InvalidField(
            "sessionPathFact.identity",
          ));
        }
      }
      Some("missing" | "proposed") => {
        let parent = occurrence.get("parentIdentity").ok_or(
          AuthorityStateError::InvalidField("sessionPathFact.parentIdentity"),
        )?;
        if binding.parent_identities.as_slice() != std::slice::from_ref(parent)
          || !binding.final_object_identities.is_empty()
        {
          return Err(AuthorityStateError::InvalidField(
            "sessionPathFact.parentIdentity",
          ));
        }
      }
      _ => {
        return Err(AuthorityStateError::InvalidField(
          "sessionPathFact.finalObjectState",
        ));
      }
    }
    let fact = Self {
      root_binding_id: binding.root_binding_id.clone(),
      final_object_identities: binding.final_object_identities.clone(),
      parent_identities: binding.parent_identities.clone(),
    };
    let canonical = canonicalize_typed("sessionPathFact", &fact)?;
    validate_component(
      "sessionPathFact",
      &canonical,
      MAX_CACHE_COMPONENT_BYTES,
    )?;
    Ok(fact)
  }

  fn binding_for_source(&self, source_id: &str) -> PathBindingInput {
    PathBindingInput {
      source_id: source_id.to_string(),
      root_binding_id: self.root_binding_id.clone(),
      final_object_identities: self.final_object_identities.clone(),
      parent_identities: self.parent_identities.clone(),
    }
  }

  fn encoded_weight_bytes(&self) -> Result<usize, AuthorityStateError> {
    serde_json::to_vec(self)
      .map(|encoded| encoded.len())
      .map_err(|error| AuthorityStateError::Serialization(error.to_string()))
  }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthorityRow {
  row_id: String,
  selector: CanonicalAuthoritySelector,
  #[serde(skip)]
  path_fact: Option<AuthorityPathFact>,
  #[serde(skip)]
  canonical_value: String,
  #[serde(skip)]
  encoded_weight_bytes: usize,
}

impl AuthorityRow {
  fn from_selector(
    row_id: String,
    selector: &CanonicalAuthoritySelector,
  ) -> Result<Self, AuthorityStateError> {
    Self::from_selector_with_path_fact(row_id, selector, None)
  }

  fn from_selector_with_path_fact(
    row_id: String,
    selector: &CanonicalAuthoritySelector,
    path_fact: Option<&AuthorityPathFact>,
  ) -> Result<Self, AuthorityStateError> {
    validate_component(
      "authorityRow.rowId",
      &row_id,
      MAX_AUTHORITY_ROW_ID_BYTES,
    )?;
    let canonical_value =
      canonicalize_typed("authorityRow.selector", selector)?;
    validate_component(
      "authorityRow.canonicalValue",
      &canonical_value,
      MAX_CACHE_COMPONENT_BYTES,
    )?;
    let mut row = Self {
      row_id,
      selector: selector.clone(),
      path_fact: path_fact.cloned(),
      canonical_value,
      encoded_weight_bytes: 0,
    };
    row.encoded_weight_bytes = serde_json::to_vec(&row)
      .map_err(|error| AuthorityStateError::Serialization(error.to_string()))?
      .len()
      .checked_add(
        row
          .path_fact
          .as_ref()
          .map(AuthorityPathFact::encoded_weight_bytes)
          .transpose()?
          .unwrap_or(0),
      )
      .ok_or(AuthorityStateError::AuthorityCapacityExceeded(
        "per-row byte bound",
      ))?;
    if row.encoded_weight_bytes > AUTHORITY_STATE_MAX_ROW_WEIGHT_BYTES {
      return Err(AuthorityStateError::AuthorityCapacityExceeded(
        "per-row byte bound",
      ));
    }
    Ok(row)
  }

  pub fn row_id(&self) -> &str {
    &self.row_id
  }

  pub fn canonical_value(&self) -> &str {
    &self.canonical_value
  }

  pub fn selector(&self) -> &CanonicalAuthoritySelector {
    &self.selector
  }

  pub(crate) fn path_binding(&self) -> Option<PathBindingInput> {
    self
      .path_fact
      .as_ref()
      .map(|fact| fact.binding_for_source(&self.row_id))
  }

  pub fn encoded_weight_bytes(&self) -> usize {
    self.encoded_weight_bytes
  }
}

#[derive(Clone, Copy, Debug)]
struct AuthorityStateLimits {
  max_rows: usize,
  max_weight_bytes: usize,
  max_row_weight_bytes: usize,
}

impl AuthorityStateLimits {
  const fn production() -> Self {
    Self {
      max_rows: AUTHORITY_STATE_MAX_ROWS,
      max_weight_bytes: AUTHORITY_STATE_MAX_WEIGHT_BYTES,
      max_row_weight_bytes: AUTHORITY_STATE_MAX_ROW_WEIGHT_BYTES,
    }
  }

  #[cfg(test)]
  fn for_test(
    max_rows: usize,
    max_weight_bytes: usize,
    max_row_weight_bytes: usize,
  ) -> Self {
    assert!(max_rows > 0);
    assert!(max_weight_bytes > 0);
    assert!(max_row_weight_bytes > 0);
    Self {
      max_rows,
      max_weight_bytes,
      max_row_weight_bytes,
    }
  }
}

#[derive(Clone, Debug, Default, Eq, PartialEq)]
struct RuntimeAuthorityRows {
  session_positive: BTreeMap<String, AuthorityRow>,
  session_revocations: BTreeMap<String, AuthorityRow>,
  negative_overlays: BTreeMap<String, AuthorityRow>,
  revocations: BTreeMap<String, AuthorityRow>,
  row_count: usize,
  weight_bytes: usize,
}

impl RuntimeAuthorityRows {
  fn map(&self, kind: AuthorityRowKind) -> &BTreeMap<String, AuthorityRow> {
    match kind {
      AuthorityRowKind::SessionPositive => &self.session_positive,
      AuthorityRowKind::SessionRevocation => &self.session_revocations,
      AuthorityRowKind::NegativeOverlay => &self.negative_overlays,
      AuthorityRowKind::Revocation => &self.revocations,
    }
  }

  fn map_mut(
    &mut self,
    kind: AuthorityRowKind,
  ) -> &mut BTreeMap<String, AuthorityRow> {
    match kind {
      AuthorityRowKind::SessionPositive => &mut self.session_positive,
      AuthorityRowKind::SessionRevocation => &mut self.session_revocations,
      AuthorityRowKind::NegativeOverlay => &mut self.negative_overlays,
      AuthorityRowKind::Revocation => &mut self.revocations,
    }
  }

  fn apply(&mut self, change: RowChange) -> Result<bool, AuthorityStateError> {
    match change {
      RowChange::Upsert { kind, row } => {
        let existing = self.map(kind).get(row.row_id());
        if existing == Some(&row) {
          return Ok(false);
        }
        let existing_weight = existing
          .map(AuthorityRow::encoded_weight_bytes)
          .unwrap_or(0);
        let next_count = self
          .row_count
          .checked_add(usize::from(existing.is_none()))
          .ok_or(AuthorityStateError::AuthorityCapacityExceeded(
            "row-count bound",
          ))?;
        let next_weight = self
          .weight_bytes
          .checked_sub(existing_weight)
          .and_then(|weight| weight.checked_add(row.encoded_weight_bytes))
          .ok_or(AuthorityStateError::AuthorityCapacityExceeded(
            "aggregate byte bound",
          ))?;
        self.map_mut(kind).insert(row.row_id.clone(), row);
        self.row_count = next_count;
        self.weight_bytes = next_weight;
        Ok(true)
      }
      RowChange::Remove { kind, row_id } => {
        let Some(removed) = self.map_mut(kind).remove(&row_id) else {
          return Ok(false);
        };
        self.row_count = self
          .row_count
          .checked_sub(1)
          .expect("authority row-count accounting underflow");
        self.weight_bytes = self
          .weight_bytes
          .checked_sub(removed.encoded_weight_bytes)
          .expect("authority row-weight accounting underflow");
        Ok(true)
      }
    }
  }

  fn validate_complete(
    &self,
    limits: AuthorityStateLimits,
  ) -> Result<(), AuthorityStateError> {
    let mut source_ids = BTreeSet::new();
    let mut row_count = 0usize;
    let mut weight_bytes = 0usize;
    for rows in [
      &self.session_positive,
      &self.session_revocations,
      &self.negative_overlays,
      &self.revocations,
    ] {
      for (source_id, row) in rows {
        if source_id != row.row_id() {
          return Err(AuthorityStateError::InvalidField("authorityRows.rowId"));
        }
        if !source_ids.insert(source_id.as_str()) {
          return Err(AuthorityStateError::DuplicateRowSourceId);
        }
        if row.encoded_weight_bytes > limits.max_row_weight_bytes {
          return Err(AuthorityStateError::AuthorityCapacityExceeded(
            "per-row byte bound",
          ));
        }
        row_count = row_count.checked_add(1).ok_or(
          AuthorityStateError::AuthorityCapacityExceeded("row-count bound"),
        )?;
        weight_bytes = weight_bytes
          .checked_add(row.encoded_weight_bytes)
          .ok_or(AuthorityStateError::AuthorityCapacityExceeded(
            "aggregate byte bound",
          ))?;
      }
    }
    if row_count > limits.max_rows {
      return Err(AuthorityStateError::AuthorityCapacityExceeded(
        "row-count bound",
      ));
    }
    if weight_bytes > limits.max_weight_bytes {
      return Err(AuthorityStateError::AuthorityCapacityExceeded(
        "aggregate byte bound",
      ));
    }
    if row_count != self.row_count || weight_bytes != self.weight_bytes {
      return Err(AuthorityStateError::InvalidField(
        "authorityRows.accounting",
      ));
    }
    Ok(())
  }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct GenerationImpact {
  negative_overlay: bool,
  revocation: bool,
  session_overlay: bool,
}

impl GenerationImpact {
  fn record(
    &mut self,
    kind: AuthorityRowKind,
  ) -> Result<(), AuthorityStateError> {
    let transition_id = match kind {
      AuthorityRowKind::SessionPositive => {
        "generation.session-positive-change/2"
      }
      AuthorityRowKind::SessionRevocation => {
        "generation.session-revocation-change/2"
      }
      AuthorityRowKind::NegativeOverlay => "generation.other-negative-change/2",
      AuthorityRowKind::Revocation => {
        "generation.revocation-inventory-change/2"
      }
    };
    let transition = REV2_RUNTIME_GENERATION_TRANSITIONS
      .iter()
      .find(|transition| transition.id == transition_id)
      .ok_or(AuthorityStateError::InvalidField("generationTransition"))?;
    match kind {
      AuthorityRowKind::SessionPositive => {
        self.session_overlay = true;
      }
      AuthorityRowKind::SessionRevocation => {
        self.session_overlay = true;
        self.negative_overlay = true;
        self.revocation = true;
      }
      AuthorityRowKind::NegativeOverlay => {
        self.negative_overlay = true;
      }
      AuthorityRowKind::Revocation => {
        self.negative_overlay = true;
        self.revocation = true;
      }
    }
    let expected = match kind {
      AuthorityRowKind::SessionPositive => {
        ["sessionOverlay"].into_iter().collect::<BTreeSet<_>>()
      }
      AuthorityRowKind::SessionRevocation => {
        ["negativeOverlay", "revocation", "sessionOverlay"]
          .into_iter()
          .collect::<BTreeSet<_>>()
      }
      AuthorityRowKind::NegativeOverlay => {
        ["negativeOverlay"].into_iter().collect::<BTreeSet<_>>()
      }
      AuthorityRowKind::Revocation => ["negativeOverlay", "revocation"]
        .into_iter()
        .collect::<BTreeSet<_>>(),
    };
    let generated = transition
      .increments
      .iter()
      .copied()
      .collect::<BTreeSet<_>>();
    if generated != expected
      || transition.cache_disposition != "clear-before-publication"
      || transition.publication != "atomic-rows-vector-and-cache"
    {
      return Err(AuthorityStateError::InvalidField("generationTransition"));
    }
    Ok(())
  }

  fn is_empty(self) -> bool {
    !self.negative_overlay && !self.revocation && !self.session_overlay
  }
}

#[derive(Debug)]
enum RowChange {
  Upsert {
    kind: AuthorityRowKind,
    row: AuthorityRow,
  },
  Remove {
    kind: AuthorityRowKind,
    row_id: String,
  },
}

/// A compare-and-commit authority transaction.
///
/// Once any builder call fails, the transaction is permanently invalid. This
/// prevents a caller from ignoring an error on its second mutation and
/// accidentally committing the valid first mutation.
#[derive(Debug)]
pub struct AuthorityTransaction {
  identity: Arc<RuntimeIdentityBinding>,
  base_publication: Arc<RuntimeAuthorityPublication>,
  changes: Vec<RowChange>,
  touched: BTreeSet<(AuthorityRowKind, String)>,
  construction_error: Option<AuthorityStateError>,
}

impl AuthorityTransaction {
  fn new(
    identity: Arc<RuntimeIdentityBinding>,
    base_publication: Arc<RuntimeAuthorityPublication>,
  ) -> Self {
    Self {
      identity,
      base_publication,
      changes: Vec::new(),
      touched: BTreeSet::new(),
      construction_error: None,
    }
  }

  fn reject<T>(
    &mut self,
    error: AuthorityStateError,
  ) -> Result<T, AuthorityStateError> {
    if self.construction_error.is_none() {
      self.construction_error = Some(error.clone());
    }
    Err(error)
  }

  fn reserve_change(
    &mut self,
    kind: AuthorityRowKind,
    row_id: &str,
  ) -> Result<(), AuthorityStateError> {
    if self.changes.len() >= MAX_TRANSACTION_MUTATIONS {
      return self.reject(AuthorityStateError::TooManyMutations);
    }
    if !self.touched.insert((kind, row_id.to_string())) {
      return self.reject(AuthorityStateError::DuplicateMutation);
    }
    Ok(())
  }

  fn session_admission(
    &mut self,
    kind: AuthorityRowKind,
    row_id: &str,
    selector: &CanonicalAuthoritySelector,
    path_fact: Option<&AuthorityPathFact>,
  ) -> Result<SessionRowAdmission, AuthorityStateError> {
    let existing = self.base_publication.rows.map(kind).get(row_id);
    let admission =
      classify_same_id_row(existing.map(AuthorityRow::selector), selector)
        .map_err(|error| {
          let error =
            AuthorityStateError::SessionRowIdentity(error.to_string());
          if self.construction_error.is_none() {
            self.construction_error = Some(error.clone());
          }
          error
        })?;
    if existing.is_some_and(|row| row.path_fact.as_ref() != path_fact) {
      return self.reject(AuthorityStateError::SessionRowIdentity(
        "same session row id carried a different host path fact".to_string(),
      ));
    }
    Ok(admission)
  }

  fn validate_session_path_fact(
    &mut self,
    selector: &CanonicalAuthoritySelector,
    path_fact: Option<&AuthorityPathFact>,
  ) -> Result<(), AuthorityStateError> {
    let resource_is_path = selector.capability.starts_with("fs:")
      && selector.resource.get("root").is_some()
      && selector.resource.get("path").is_some();
    if resource_is_path != path_fact.is_some() {
      return self.reject(AuthorityStateError::InvalidField("sessionPathFact"));
    }
    Ok(())
  }

  fn derive_session_row_ids(
    &mut self,
    overlay_owner: &PrincipalRef,
    principal: &PrincipalRef,
    selector: &CanonicalAuthoritySelector,
  ) -> Result<OdenRev2SessionRowIds, AuthorityStateError> {
    match session_row_ids(&self.identity, overlay_owner, principal, selector) {
      Ok(ids) => Ok(ids),
      Err(error) => {
        self.reject(AuthorityStateError::SessionRowIdentity(error.to_string()))
      }
    }
  }

  /// Publish one stable session revocation. The row ID is always derived from
  /// the generated polarity-neutral tuple; callers cannot choose it.
  pub(crate) fn upsert_session_revocation(
    &mut self,
    overlay_owner: &PrincipalRef,
    principal: &PrincipalRef,
    selector: &CanonicalAuthoritySelector,
    path_fact: Option<&AuthorityPathFact>,
  ) -> Result<SessionRowAdmission, AuthorityStateError> {
    self.validate_session_path_fact(selector, path_fact)?;
    let ids =
      self.derive_session_row_ids(overlay_owner, principal, selector)?;
    let admission = self.session_admission(
      AuthorityRowKind::SessionRevocation,
      ids.revocation(),
      selector,
      path_fact,
    )?;
    if let Some((positive_selector, positive_path_fact)) = self
      .base_publication
      .rows
      .map(AuthorityRowKind::SessionPositive)
      .get(ids.positive())
      .map(|row| (row.selector.clone(), row.path_fact.clone()))
    {
      let positive_ids = self.derive_session_row_ids(
        overlay_owner,
        principal,
        &positive_selector,
      )?;
      if positive_ids != ids {
        return self.reject(AuthorityStateError::SessionRowIdentity(
          "paired positive row derived a different logical identity"
            .to_string(),
        ));
      }
      if positive_path_fact.as_ref() != path_fact {
        return self.reject(AuthorityStateError::SessionRowIdentity(
          "session revocation did not preserve the positive row path fact"
            .to_string(),
        ));
      }
      self.remove_row(
        AuthorityRowKind::SessionPositive,
        ids.positive().to_string(),
      )?;
    }
    if admission == SessionRowAdmission::Insert {
      self.upsert_row_with_path_fact(
        AuthorityRowKind::SessionRevocation,
        ids.revocation().to_string(),
        selector,
        path_fact,
      )?;
    }
    Ok(admission)
  }

  /// Atomically remove the exact paired revocation and install the positive
  /// session row. Both selectors must describe the same polarity-neutral
  /// principal/capability/resource tuple; same-ID substitutions refuse.
  pub(crate) fn reconcile_session_grant(
    &mut self,
    overlay_owner: &PrincipalRef,
    principal: &PrincipalRef,
    positive_selector: &CanonicalAuthoritySelector,
    revocation_selector: &CanonicalAuthoritySelector,
    path_fact: Option<&AuthorityPathFact>,
  ) -> Result<SessionRowAdmission, AuthorityStateError> {
    self.validate_session_path_fact(positive_selector, path_fact)?;
    self.validate_session_path_fact(revocation_selector, path_fact)?;
    let positive_ids = self.derive_session_row_ids(
      overlay_owner,
      principal,
      positive_selector,
    )?;
    let revocation_ids = self.derive_session_row_ids(
      overlay_owner,
      principal,
      revocation_selector,
    )?;
    if positive_ids != revocation_ids {
      return self.reject(AuthorityStateError::SessionRowIdentity(
        "positive and revocation selectors describe different logical rows"
          .to_string(),
      ));
    }
    let positive_admission = self.session_admission(
      AuthorityRowKind::SessionPositive,
      positive_ids.positive(),
      positive_selector,
      path_fact,
    )?;
    self.session_admission(
      AuthorityRowKind::SessionRevocation,
      positive_ids.revocation(),
      revocation_selector,
      path_fact,
    )?;
    if self
      .base_publication
      .rows
      .map(AuthorityRowKind::SessionRevocation)
      .contains_key(positive_ids.revocation())
    {
      self.remove_row(
        AuthorityRowKind::SessionRevocation,
        positive_ids.revocation().to_string(),
      )?;
    }
    if positive_admission == SessionRowAdmission::Insert {
      self.upsert_row_with_path_fact(
        AuthorityRowKind::SessionPositive,
        positive_ids.positive().to_string(),
        positive_selector,
        path_fact,
      )?;
    }
    Ok(positive_admission)
  }

  pub(crate) fn upsert(
    &mut self,
    kind: AuthorityRowKind,
    row_id: String,
    selector: &CanonicalAuthoritySelector,
  ) -> Result<(), AuthorityStateError> {
    if matches!(
      kind,
      AuthorityRowKind::SessionPositive | AuthorityRowKind::SessionRevocation
    ) {
      return self.reject(AuthorityStateError::UntypedSessionMutation);
    }
    self.upsert_row(kind, row_id, selector)
  }

  fn upsert_row(
    &mut self,
    kind: AuthorityRowKind,
    row_id: String,
    selector: &CanonicalAuthoritySelector,
  ) -> Result<(), AuthorityStateError> {
    self.upsert_row_with_path_fact(kind, row_id, selector, None)
  }

  fn upsert_row_with_path_fact(
    &mut self,
    kind: AuthorityRowKind,
    row_id: String,
    selector: &CanonicalAuthoritySelector,
    path_fact: Option<&AuthorityPathFact>,
  ) -> Result<(), AuthorityStateError> {
    let row = match AuthorityRow::from_selector_with_path_fact(
      row_id, selector, path_fact,
    ) {
      Ok(row) => row,
      Err(error) => return self.reject(error),
    };
    self.reserve_change(kind, row.row_id())?;
    self.changes.push(RowChange::Upsert { kind, row });
    Ok(())
  }

  pub(crate) fn remove(
    &mut self,
    kind: AuthorityRowKind,
    row_id: String,
  ) -> Result<(), AuthorityStateError> {
    if matches!(
      kind,
      AuthorityRowKind::SessionPositive | AuthorityRowKind::SessionRevocation
    ) {
      return self.reject(AuthorityStateError::UntypedSessionMutation);
    }
    self.remove_row(kind, row_id)
  }

  fn remove_row(
    &mut self,
    kind: AuthorityRowKind,
    row_id: String,
  ) -> Result<(), AuthorityStateError> {
    if let Err(error) = validate_component(
      "authorityRow.rowId",
      &row_id,
      MAX_AUTHORITY_ROW_ID_BYTES,
    ) {
      return self.reject(error);
    }
    self.reserve_change(kind, &row_id)?;
    self.changes.push(RowChange::Remove { kind, row_id });
    Ok(())
  }

  #[cfg(test)]
  pub(crate) fn upsert_session_row_for_test(
    &mut self,
    kind: AuthorityRowKind,
    row_id: String,
    selector: &CanonicalAuthoritySelector,
  ) -> Result<(), AuthorityStateError> {
    if !matches!(
      kind,
      AuthorityRowKind::SessionPositive | AuthorityRowKind::SessionRevocation
    ) {
      return self
        .reject(AuthorityStateError::InvalidField("test.sessionRowKind"));
    }
    self.upsert_row(kind, row_id, selector)
  }

  #[cfg(test)]
  pub(crate) fn remove_session_row_for_test(
    &mut self,
    kind: AuthorityRowKind,
    row_id: String,
  ) -> Result<(), AuthorityStateError> {
    if !matches!(
      kind,
      AuthorityRowKind::SessionPositive | AuthorityRowKind::SessionRevocation
    ) {
      return self
        .reject(AuthorityStateError::InvalidField("test.sessionRowKind"));
    }
    self.remove_row(kind, row_id)
  }
}

#[derive(Clone, Debug)]
struct RuntimeAuthorityPublication {
  rows: Arc<RuntimeAuthorityRows>,
  generations: RuntimeGenerationVector,
  fail_closed: bool,
}

/// An immutable, internally consistent authority-state snapshot.
#[derive(Clone, Debug)]
pub struct RuntimeAuthorityReadView {
  identity: Arc<RuntimeIdentityBinding>,
  publication: Arc<RuntimeAuthorityPublication>,
}

impl RuntimeAuthorityReadView {
  pub fn identity(&self) -> &RuntimeIdentityBinding {
    &self.identity
  }

  pub fn generations(&self) -> RuntimeGenerationVector {
    self.publication.generations
  }

  pub fn is_fail_closed(&self) -> bool {
    self.publication.fail_closed
  }

  pub fn row(
    &self,
    kind: AuthorityRowKind,
    row_id: &str,
  ) -> Option<&AuthorityRow> {
    self.publication.rows.map(kind).get(row_id)
  }

  pub fn rows(
    &self,
    kind: AuthorityRowKind,
  ) -> impl Iterator<Item = &AuthorityRow> {
    self.publication.rows.map(kind).values()
  }

  pub fn row_count(&self) -> usize {
    self.publication.rows.row_count
  }

  pub fn row_weight_bytes(&self) -> usize {
    self.publication.rows.weight_bytes
  }
}

/// A bounded complete-state proposal that has not yet been accepted by the
/// operation actor. Its read view is immutable and is not globally visible.
#[derive(Debug)]
pub struct ProposedAuthorityTransaction {
  base_publication: Arc<RuntimeAuthorityPublication>,
  proposed_view: RuntimeAuthorityReadView,
  changed: bool,
}

impl ProposedAuthorityTransaction {
  pub fn read_view(&self) -> &RuntimeAuthorityReadView {
    &self.proposed_view
  }

  /// Evaluate the complete proposed state without holding the authority-state
  /// lock. Consuming `self` prevents a failed validation from later being
  /// committed through the typed path.
  pub fn validate<T, E, F>(
    self,
    validator: F,
  ) -> Result<ValidatedAuthorityTransaction<T>, E>
  where
    F: FnOnce(&RuntimeAuthorityReadView) -> Result<T, E>,
  {
    let output = validator(&self.proposed_view)?;
    Ok(ValidatedAuthorityTransaction {
      proposal: self,
      output,
    })
  }
}

/// A proposal whose complete immutable read view passed operation validation.
/// Fields are private so callers cannot manufacture the validated state.
#[derive(Debug)]
pub struct ValidatedAuthorityTransaction<T> {
  proposal: ProposedAuthorityTransaction,
  output: T,
}

/// The result and exact read view published at one linearization point.
#[derive(Debug)]
pub struct CommittedAuthorityTransaction<T> {
  read_view: RuntimeAuthorityReadView,
  output: T,
}

impl<T> CommittedAuthorityTransaction<T> {
  pub fn read_view(&self) -> &RuntimeAuthorityReadView {
    &self.read_view
  }

  pub fn output(&self) -> &T {
    &self.output
  }

  pub fn into_parts(self) -> (RuntimeAuthorityReadView, T) {
    (self.read_view, self.output)
  }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum RuntimeAuthorityMode {
  Permissive,
  Audit,
  Enforce,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DecisionCacheEffect {
  slot_id: String,
  effect_owner: PrincipalRef,
  selector: CanonicalAuthoritySelector,
  occurrence: serde_json::Value,
  #[serde(skip)]
  canonical_identity_bytes: Vec<u8>,
}

impl DecisionCacheEffect {
  pub(crate) fn from_normalized_permission(
    logical_slot_id: String,
    selector: &CanonicalAuthoritySelector,
    effect: &CanonicalEffect,
  ) -> Result<Self, AuthorityStateError> {
    if selector.capability != effect.capability {
      return Err(AuthorityStateError::InvalidField("cacheEffect.capability"));
    }
    let slot_id = logical_slot_id;
    let effect_owner = selector
      .principal
      .clone()
      .ok_or(AuthorityStateError::InvalidField("cacheEffect.effectOwner"))?;
    if effect.effect_owner != effect_owner.key {
      return Err(AuthorityStateError::InvalidField("cacheEffect.effectOwner"));
    }
    if effect
      .occurrence
      .get("effectOwner")
      .and_then(serde_json::Value::as_str)
      != Some(effect_owner.key.as_str())
    {
      return Err(AuthorityStateError::InvalidField(
        "cacheEffect.occurrence.effectOwner",
      ));
    }
    let canonical_owner =
      canonicalize_typed("cacheEffect.effectOwner", &effect_owner)?;
    let canonical_selector =
      canonicalize_typed("cacheEffect.selector", selector)?;
    let canonical_occurrence =
      canonicalize_typed("cacheEffect.occurrence", &effect.occurrence)?;
    validate_component(
      "cacheEffect.slotId",
      &slot_id,
      MAX_CACHE_COMPONENT_BYTES,
    )?;
    validate_component(
      "cacheEffect.effectOwner",
      &canonical_owner,
      MAX_CACHE_COMPONENT_BYTES,
    )?;
    validate_component(
      "cacheEffect.selector",
      &canonical_selector,
      MAX_CACHE_COMPONENT_BYTES,
    )?;
    validate_component(
      "cacheEffect.occurrence",
      &canonical_occurrence,
      MAX_CACHE_COMPONENT_BYTES,
    )?;
    validate_component(
      "cacheEffect.canonicalOwner",
      &effect.effect_owner,
      MAX_CACHE_COMPONENT_BYTES,
    )?;
    let canonical_identity_bytes = canonicalize_typed(
      "cacheEffect.identity",
      &(&effect_owner, selector, &effect.occurrence),
    )?
    .into_bytes();
    Ok(Self {
      slot_id,
      effect_owner,
      selector: selector.clone(),
      occurrence: effect.occurrence.clone(),
      canonical_identity_bytes,
    })
  }

  #[cfg(test)]
  fn from_canonical(
    selector: &CanonicalAuthoritySelector,
    effect: &CanonicalEffect,
  ) -> Result<Self, AuthorityStateError> {
    Self::from_normalized_permission(
      effect.effect_slot_id.clone(),
      selector,
      effect,
    )
  }

  pub fn slot_id(&self) -> &str {
    &self.slot_id
  }

  pub(crate) fn effect_owner(&self) -> &PrincipalRef {
    &self.effect_owner
  }

  pub(crate) fn selector(&self) -> &CanonicalAuthoritySelector {
    &self.selector
  }

  pub(crate) fn occurrence(&self) -> &serde_json::Value {
    &self.occurrence
  }
}

#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ReceiptDependency {
  receipt_id: String,
  issuer_generation: CanonicalGeneration,
  receipt_negative_generation: CanonicalGeneration,
  monotonic_deadline: CanonicalGeneration,
}

impl ReceiptDependency {
  #[allow(
    dead_code,
    reason = "constructed by the later protected-receipt context adapter"
  )]
  pub(crate) fn new(
    receipt_id: String,
    issuer_generation: u64,
    receipt_negative_generation: u64,
    monotonic_deadline: u64,
  ) -> Result<Self, AuthorityStateError> {
    validate_component(
      "receiptDependency.receiptId",
      &receipt_id,
      MAX_CACHE_COMPONENT_BYTES,
    )?;
    Ok(Self {
      receipt_id,
      issuer_generation: CanonicalGeneration(issuer_generation),
      receipt_negative_generation: CanonicalGeneration(
        receipt_negative_generation,
      ),
      monotonic_deadline: CanonicalGeneration(monotonic_deadline),
    })
  }
}

fn cache_dimension_bound(
  principal_count: usize,
  effect_count: usize,
  receipt_count: usize,
) -> Result<usize, AuthorityStateError> {
  if principal_count == 0
    || principal_count > MAX_CACHE_CONSTRAINED_PRINCIPALS
    || effect_count == 0
    || effect_count > MAX_CACHE_EFFECTS
    || receipt_count > MAX_CACHE_RECEIPT_DEPENDENCIES
  {
    return Err(AuthorityStateError::InvalidField("cacheKey"));
  }
  let dimensions = principal_count.checked_mul(effect_count).ok_or(
    AuthorityStateError::InvalidField("cacheKey.principalEffectProduct"),
  )?;
  if dimensions > MAX_CACHE_DECISION_DIMENSIONS {
    return Err(AuthorityStateError::InvalidField(
      "cacheKey.principalEffectProduct",
    ));
  }
  Ok(dimensions)
}

/// The complete decision-cache key. Hashing is only an index optimization;
/// `HashMap` still compares every field through `Eq` after a hash match.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DecisionCacheKey {
  schema: &'static str,
  operation_class: String,
  coverage_edge_id: String,
  stage_id: String,
  mode: RuntimeAuthorityMode,
  identity: RuntimeIdentityBinding,
  generations: RuntimeGenerationVector,
  constrained_principals: Vec<PrincipalRef>,
  overlay_owner: PrincipalRef,
  effects: Vec<DecisionCacheEffect>,
  receipt_dependencies: Vec<ReceiptDependency>,
  #[serde(skip)]
  canonical_key_bytes: Vec<u8>,
}

impl Hash for DecisionCacheKey {
  fn hash<H: Hasher>(&self, state: &mut H) {
    self.canonical_key_bytes.hash(state);
  }
}

impl DecisionCacheKey {
  #[allow(clippy::too_many_arguments)]
  pub(crate) fn new(
    operation_class: String,
    coverage_edge_id: String,
    stage_id: String,
    mode: RuntimeAuthorityMode,
    identity: RuntimeIdentityBinding,
    generations: RuntimeGenerationVector,
    constrained_principals: Vec<PrincipalRef>,
    overlay_owner: PrincipalRef,
    effects: Vec<DecisionCacheEffect>,
    receipt_dependencies: Vec<ReceiptDependency>,
  ) -> Result<Self, AuthorityStateError> {
    cache_dimension_bound(
      constrained_principals.len(),
      effects.len(),
      receipt_dependencies.len(),
    )?;
    validate_component(
      "cacheKey.operationClass",
      &operation_class,
      MAX_CACHE_COMPONENT_BYTES,
    )?;
    validate_component(
      "cacheKey.coverageEdgeId",
      &coverage_edge_id,
      MAX_CACHE_COMPONENT_BYTES,
    )?;
    validate_component(
      "cacheKey.stageId",
      &stage_id,
      MAX_CACHE_COMPONENT_BYTES,
    )?;
    let mut canonical_principals =
      Vec::with_capacity(constrained_principals.len());
    let mut seen_principals =
      HashSet::with_capacity(constrained_principals.len());
    for principal in constrained_principals {
      let canonical =
        canonicalize_typed("cacheKey.constrainedPrincipal", &principal)?;
      validate_component(
        "cacheKey.constrainedPrincipal",
        &canonical,
        MAX_CACHE_COMPONENT_BYTES,
      )?;
      if !seen_principals.insert(canonical.clone()) {
        return Err(AuthorityStateError::InvalidField(
          "cacheKey.constrainedPrincipals",
        ));
      }
      canonical_principals.push((canonical.into_bytes(), principal));
    }
    let canonical_overlay_owner =
      canonicalize_typed("cacheKey.overlayOwner", &overlay_owner)?;
    validate_component(
      "cacheKey.overlayOwner",
      &canonical_overlay_owner,
      MAX_CACHE_COMPONENT_BYTES,
    )?;
    canonical_principals.sort_by(|left, right| left.0.cmp(&right.0));
    let constrained_principals = canonical_principals
      .into_iter()
      .map(|(_, principal)| principal)
      .collect::<Vec<_>>();
    if constrained_principals
      .iter()
      .all(|principal| principal != &overlay_owner)
    {
      return Err(AuthorityStateError::InvalidField("cacheKey.overlayOwner"));
    }

    let mut slots = BTreeSet::new();
    let mut occurrences = BTreeSet::new();
    for effect in &effects {
      if !slots.insert(effect.slot_id.clone())
        || !occurrences.insert(effect.canonical_identity_bytes.clone())
      {
        return Err(AuthorityStateError::InvalidField("cacheKey.effects"));
      }
    }

    let mut canonical_receipts = Vec::with_capacity(receipt_dependencies.len());
    let mut seen_receipts = HashSet::with_capacity(receipt_dependencies.len());
    for dependency in receipt_dependencies {
      let canonical =
        canonicalize_typed("cacheKey.receiptDependency", &dependency)?
          .into_bytes();
      if !seen_receipts.insert(canonical.clone()) {
        return Err(AuthorityStateError::InvalidField(
          "cacheKey.receiptDependencies",
        ));
      }
      canonical_receipts.push((canonical, dependency));
    }
    canonical_receipts.sort_by(|left, right| left.0.cmp(&right.0));
    let receipt_dependencies = canonical_receipts
      .into_iter()
      .map(|(_, dependency)| dependency)
      .collect::<Vec<_>>();

    let mut key = Self {
      schema: DECISION_CACHE_KEY_SCHEMA,
      operation_class,
      coverage_edge_id,
      stage_id,
      mode,
      identity,
      generations,
      constrained_principals,
      overlay_owner,
      effects,
      receipt_dependencies,
      canonical_key_bytes: Vec::new(),
    };
    key.canonical_key_bytes =
      canonicalize_typed("cacheKey", &key)?.into_bytes();
    Ok(key)
  }

  pub fn identity(&self) -> &RuntimeIdentityBinding {
    &self.identity
  }

  pub fn generations(&self) -> RuntimeGenerationVector {
    self.generations
  }

  pub(crate) fn operation_class(&self) -> &str {
    &self.operation_class
  }

  pub(crate) fn coverage_edge_id(&self) -> &str {
    &self.coverage_edge_id
  }

  pub(crate) fn stage_id(&self) -> &str {
    &self.stage_id
  }

  pub(crate) fn mode(&self) -> RuntimeAuthorityMode {
    self.mode
  }

  pub(crate) fn constrained_principals(&self) -> &[PrincipalRef] {
    &self.constrained_principals
  }

  pub(crate) fn overlay_owner(&self) -> &PrincipalRef {
    &self.overlay_owner
  }

  pub(crate) fn effects(&self) -> &[DecisionCacheEffect] {
    &self.effects
  }

  fn minimum_receipt_deadline(&self) -> Option<u64> {
    self
      .receipt_dependencies
      .iter()
      .map(|dependency| dependency.monotonic_deadline.0)
      .min()
  }

  fn has_expired_receipt(&self, now_monotonic: u64) -> bool {
    self
      .minimum_receipt_deadline()
      .is_some_and(|deadline| now_monotonic >= deadline)
  }
}

#[derive(
  Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize,
)]
#[serde(rename_all = "kebab-case")]
pub enum CachedDecision {
  Allow,
  Deny,
  Masked,
  Prompt,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DecisionDimension {
  slot_id: String,
  principal: PrincipalRef,
  decision: CachedDecision,
  positive_source: Option<PositiveSource>,
}

impl DecisionDimension {
  pub(crate) fn new(
    slot_id: String,
    principal: PrincipalRef,
    decision: CachedDecision,
    positive_source: Option<PositiveSource>,
  ) -> Result<Self, AuthorityStateError> {
    validate_component(
      "cacheDimension.slotId",
      &slot_id,
      MAX_CACHE_COMPONENT_BYTES,
    )?;
    let canonical_principal =
      canonicalize_typed("cacheDimension.principal", &principal)?;
    validate_component(
      "cacheDimension.principal",
      &canonical_principal,
      MAX_CACHE_COMPONENT_BYTES,
    )?;
    if (decision == CachedDecision::Allow) != positive_source.is_some() {
      return Err(AuthorityStateError::InvalidField(
        "cacheDimension.positiveSource",
      ));
    }
    if let Some(source) = &positive_source {
      let canonical_source =
        canonicalize_typed("cacheDimension.positiveSource", source)?;
      validate_component(
        "cacheDimension.positiveSource",
        &canonical_source,
        MAX_CACHE_COMPONENT_BYTES,
      )?;
    }
    Ok(Self {
      slot_id,
      principal,
      decision,
      positive_source,
    })
  }

  pub(crate) fn slot_id(&self) -> &str {
    &self.slot_id
  }

  pub(crate) fn principal(&self) -> &PrincipalRef {
    &self.principal
  }

  pub(crate) fn decision(&self) -> CachedDecision {
    self.decision
  }

  pub(crate) fn positive_source(&self) -> Option<&PositiveSource> {
    self.positive_source.as_ref()
  }
}

/// A complete cached decision candidate. It cannot independently authorize an
/// operation; a cache hit returns this value together with the exact current
/// read view so the caller can re-enter negative strata before reuse.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DecisionCacheValue {
  decision: CachedDecision,
  dimensions: Vec<DecisionDimension>,
  negative_inventory_digest: String,
  valid_until_monotonic: Option<CanonicalGeneration>,
  weight_bytes: CanonicalGeneration,
}

impl DecisionCacheValue {
  pub(crate) fn new(
    decision: CachedDecision,
    dimensions: Vec<DecisionDimension>,
    negative_inventory_digest: String,
    valid_until_monotonic: Option<u64>,
  ) -> Result<Self, AuthorityStateError> {
    if dimensions.is_empty() || dimensions.len() > MAX_CACHE_DECISION_DIMENSIONS
    {
      return Err(AuthorityStateError::InvalidField("cacheValue.dimensions"));
    }
    validate_digest(
      "cacheValue.negativeInventoryDigest",
      &negative_inventory_digest,
    )?;
    let mut canonical_dimensions = Vec::with_capacity(dimensions.len());
    let mut seen_dimensions = HashSet::with_capacity(dimensions.len());
    for dimension in dimensions {
      let principal = canonicalize_typed(
        "cacheDimension.principalIdentity",
        &dimension.principal,
      )?;
      if !seen_dimensions.insert((dimension.slot_id.clone(), principal)) {
        return Err(AuthorityStateError::InvalidField("cacheValue.dimensions"));
      }
      let canonical =
        canonicalize_typed("cacheDimension", &dimension)?.into_bytes();
      canonical_dimensions.push((canonical, dimension));
    }
    canonical_dimensions.sort_by(|left, right| left.0.cmp(&right.0));
    let dimensions = canonical_dimensions
      .into_iter()
      .map(|(_, dimension)| dimension)
      .collect::<Vec<_>>();
    // Preserve the shared core's `deny > masked > allow` ordering; a prompt is
    // an interaction candidate below a terminal masked result and above allow.
    let collapsed = if dimensions
      .iter()
      .any(|dimension| dimension.decision == CachedDecision::Deny)
    {
      CachedDecision::Deny
    } else if dimensions
      .iter()
      .any(|dimension| dimension.decision == CachedDecision::Masked)
    {
      CachedDecision::Masked
    } else if dimensions
      .iter()
      .any(|dimension| dimension.decision == CachedDecision::Prompt)
    {
      CachedDecision::Prompt
    } else {
      CachedDecision::Allow
    };
    if decision != collapsed {
      return Err(AuthorityStateError::InvalidField("cacheValue.decision"));
    }
    Ok(Self {
      decision,
      dimensions,
      negative_inventory_digest,
      valid_until_monotonic: valid_until_monotonic.map(CanonicalGeneration),
      weight_bytes: CanonicalGeneration(0),
    })
  }

  pub fn decision(&self) -> CachedDecision {
    self.decision
  }

  pub fn dimensions(&self) -> &[DecisionDimension] {
    &self.dimensions
  }

  pub fn weight_bytes(&self) -> u64 {
    self.weight_bytes.0
  }

  pub(crate) fn negative_inventory_digest(&self) -> &str {
    &self.negative_inventory_digest
  }

  pub(crate) fn valid_until_monotonic(&self) -> Option<u64> {
    self.valid_until_monotonic.map(|deadline| deadline.0)
  }

  fn is_expired(&self, now_monotonic: u64) -> bool {
    self
      .valid_until_monotonic
      .is_some_and(|deadline| now_monotonic >= deadline.0)
  }

  fn constrain_to_receipt_deadline(&mut self, deadline: Option<u64>) {
    let Some(deadline) = deadline else {
      return;
    };
    self.valid_until_monotonic = Some(CanonicalGeneration(
      self
        .valid_until_monotonic
        .map_or(deadline, |current| current.0.min(deadline)),
    ));
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CacheAdmission {
  Inserted,
  Replaced,
  NotAdmittedOversize,
}

#[derive(Clone, Copy, Debug)]
struct DecisionCacheLimits {
  max_entries: usize,
  max_weight_bytes: usize,
  max_entry_weight_bytes: usize,
}

impl DecisionCacheLimits {
  const fn production() -> Self {
    Self {
      max_entries: DECISION_CACHE_MAX_ENTRIES,
      max_weight_bytes: DECISION_CACHE_MAX_WEIGHT_BYTES,
      max_entry_weight_bytes: DECISION_CACHE_MAX_ENTRY_WEIGHT_BYTES,
    }
  }

  #[cfg(test)]
  fn for_test(
    max_entries: usize,
    max_weight_bytes: usize,
    max_entry_weight_bytes: usize,
  ) -> Self {
    assert!(max_entries > 0);
    assert!(max_weight_bytes > 0);
    assert!(max_entry_weight_bytes > 0);
    Self {
      max_entries,
      max_weight_bytes,
      max_entry_weight_bytes,
    }
  }
}

#[derive(Debug)]
struct DecisionCacheEntry {
  value: DecisionCacheValue,
  canonical_key_bytes: Vec<u8>,
  last_used: u64,
  weight_bytes: usize,
}

#[derive(Debug)]
struct DecisionCache {
  entries: HashMap<DecisionCacheKey, DecisionCacheEntry>,
  limits: DecisionCacheLimits,
  total_weight_bytes: usize,
  access_sequence: u64,
}

impl DecisionCache {
  fn new() -> Self {
    Self::with_limits(DecisionCacheLimits::production())
  }

  fn with_limits(limits: DecisionCacheLimits) -> Self {
    Self {
      entries: HashMap::new(),
      limits,
      total_weight_bytes: 0,
      access_sequence: 0,
    }
  }

  fn len(&self) -> usize {
    self.entries.len()
  }

  fn total_weight_bytes(&self) -> usize {
    self.total_weight_bytes
  }

  fn clear(&mut self) {
    self.entries.clear();
    self.total_weight_bytes = 0;
    self.access_sequence = 0;
  }

  fn next_access_sequence(&mut self) -> u64 {
    if self.access_sequence == u64::MAX {
      // LRU sequence is not authority. Clearing converts overflow to misses
      // and avoids ever reusing an ambiguous order.
      self.clear();
    }
    self.access_sequence += 1;
    self.access_sequence
  }

  fn canonical_serialized<T: Serialize>(
    field: &'static str,
    value: &T,
  ) -> Result<Vec<u8>, AuthorityStateError> {
    Ok(canonicalize_typed(field, value)?.into_bytes())
  }

  fn prepare_entry(
    key: &DecisionCacheKey,
    mut value: DecisionCacheValue,
  ) -> Result<(DecisionCacheValue, Vec<u8>, usize), AuthorityStateError> {
    let canonical_key_bytes = key.canonical_key_bytes.clone();
    let mut proposed_weight = 0u64;
    for _ in 0..8 {
      value.weight_bytes = CanonicalGeneration(proposed_weight);
      let value_bytes = Self::canonical_serialized("cacheValue", &value)?;
      let weight = canonical_key_bytes
        .len()
        .checked_add(value_bytes.len())
        .ok_or_else(|| {
          AuthorityStateError::Serialization(
            "decision-cache entry weight overflow".to_string(),
          )
        })?;
      let weight_u64 = u64::try_from(weight).map_err(|_| {
        AuthorityStateError::Serialization(
          "decision-cache entry weight exceeds u64".to_string(),
        )
      })?;
      if weight_u64 == proposed_weight {
        return Ok((value, canonical_key_bytes, weight));
      }
      proposed_weight = weight_u64;
    }
    Err(AuthorityStateError::Serialization(
      "decision-cache weight did not converge".to_string(),
    ))
  }

  fn remove(&mut self, key: &DecisionCacheKey) -> Option<DecisionCacheEntry> {
    let entry = self.entries.remove(key)?;
    self.total_weight_bytes = self
      .total_weight_bytes
      .checked_sub(entry.weight_bytes)
      .expect("decision-cache weight accounting underflow");
    Some(entry)
  }

  fn evict_lru(&mut self) -> bool {
    let evicted = self
      .entries
      .iter()
      .min_by(|(_, left), (_, right)| {
        (left.last_used, &left.canonical_key_bytes)
          .cmp(&(right.last_used, &right.canonical_key_bytes))
      })
      .map(|(key, _)| key.clone());
    evicted.is_some_and(|key| self.remove(&key).is_some())
  }

  fn insert(
    &mut self,
    key: DecisionCacheKey,
    mut value: DecisionCacheValue,
  ) -> Result<CacheAdmission, AuthorityStateError> {
    let expected_count = cache_dimension_bound(
      key.constrained_principals.len(),
      key.effects.len(),
      key.receipt_dependencies.len(),
    )?;
    if value.dimensions.len() != expected_count {
      return Err(AuthorityStateError::InvalidField("cacheValue.dimensions"));
    }
    let expected_dimensions = key
      .effects
      .iter()
      .flat_map(|effect| {
        key
          .constrained_principals
          .iter()
          .map(move |principal| (&effect.slot_id, principal))
      })
      .collect::<BTreeSet<_>>();
    let actual_dimensions = value
      .dimensions
      .iter()
      .map(|dimension| (&dimension.slot_id, &dimension.principal))
      .collect::<BTreeSet<_>>();
    if actual_dimensions != expected_dimensions {
      return Err(AuthorityStateError::InvalidField("cacheValue.dimensions"));
    }
    value.constrain_to_receipt_deadline(key.minimum_receipt_deadline());
    let (value, canonical_key_bytes, weight_bytes) =
      Self::prepare_entry(&key, value)?;
    if weight_bytes > self.limits.max_entry_weight_bytes
      || weight_bytes > self.limits.max_weight_bytes
    {
      return Ok(CacheAdmission::NotAdmittedOversize);
    }

    let replaced = self.remove(&key).is_some();
    while self.entries.len() >= self.limits.max_entries
      || self
        .total_weight_bytes
        .checked_add(weight_bytes)
        .is_none_or(|weight| weight > self.limits.max_weight_bytes)
    {
      if !self.evict_lru() {
        return Ok(CacheAdmission::NotAdmittedOversize);
      }
    }

    let last_used = self.next_access_sequence();
    self.total_weight_bytes += weight_bytes;
    self.entries.insert(
      key,
      DecisionCacheEntry {
        value,
        canonical_key_bytes,
        last_used,
        weight_bytes,
      },
    );
    Ok(if replaced {
      CacheAdmission::Replaced
    } else {
      CacheAdmission::Inserted
    })
  }

  fn get_cloned(
    &mut self,
    key: &DecisionCacheKey,
    now_monotonic: u64,
  ) -> Option<DecisionCacheValue> {
    if key.has_expired_receipt(now_monotonic)
      || self
        .entries
        .get(key)
        .is_some_and(|entry| entry.value.is_expired(now_monotonic))
    {
      self.remove(key);
      return None;
    }
    if !self.entries.contains_key(key) {
      return None;
    }
    let last_used = self.next_access_sequence();
    let entry = self.entries.get_mut(key)?;
    entry.last_used = last_used;
    Some(entry.value.clone())
  }
}

struct RuntimeAuthorityStateInner {
  publication: Arc<RuntimeAuthorityPublication>,
  cache: DecisionCache,
}

/// The synchronized authority-state owner. Cache and row publication share
/// one lock so a generation-changing transaction clears the old cache before
/// the new rows can become observable.
pub struct RuntimeAuthorityState {
  identity: Arc<RuntimeIdentityBinding>,
  authority_limits: AuthorityStateLimits,
  inner: Mutex<RuntimeAuthorityStateInner>,
}

/// One pinned authority publication for a synchronous native operation.
///
/// The private mutex guard prevents row/generation publication and cache
/// mutation until the operation drops this value. Callers receive only an
/// immutable read view; exposing the guarded state would let an operation
/// manufacture a mixed publication or mutate authority while its filesystem
/// commit gate is held.
///
/// @ref LLP 0019#generations-and-atomic-invalidation [implements] -- Native
/// operation validation, commit, and delivery can retain one exact rows/vector
/// publication rather than repeatedly sampling independently current views.
pub(crate) struct RuntimeAuthorityPublicationGuard<'a> {
  state: &'a RuntimeAuthorityState,
  inner: MutexGuard<'a, RuntimeAuthorityStateInner>,
}

impl RuntimeAuthorityPublicationGuard<'_> {
  pub(crate) fn read_view(&self) -> RuntimeAuthorityReadView {
    self.state.view_for(self.inner.publication.clone())
  }

  pub(crate) fn belongs_to(&self, state: &RuntimeAuthorityState) -> bool {
    std::ptr::eq(self.state, state)
  }
}

impl RuntimeAuthorityState {
  pub fn new(identity: RuntimeIdentityBinding) -> Self {
    Self::with_configuration(
      identity,
      RuntimeGenerationVector::initial(),
      AuthorityStateLimits::production(),
    )
  }

  fn with_configuration(
    identity: RuntimeIdentityBinding,
    generations: RuntimeGenerationVector,
    authority_limits: AuthorityStateLimits,
  ) -> Self {
    Self {
      identity: Arc::new(identity),
      authority_limits,
      inner: Mutex::new(RuntimeAuthorityStateInner {
        publication: Arc::new(RuntimeAuthorityPublication {
          rows: Arc::new(RuntimeAuthorityRows::default()),
          generations,
          fail_closed: false,
        }),
        cache: DecisionCache::new(),
      }),
    }
  }

  #[cfg(test)]
  fn with_generations_for_test(
    identity: RuntimeIdentityBinding,
    generations: RuntimeGenerationVector,
  ) -> Self {
    Self::with_configuration(
      identity,
      generations,
      AuthorityStateLimits::production(),
    )
  }

  #[cfg(test)]
  fn with_limits_for_test(
    identity: RuntimeIdentityBinding,
    authority_limits: AuthorityStateLimits,
  ) -> Self {
    Self::with_configuration(
      identity,
      RuntimeGenerationVector::initial(),
      authority_limits,
    )
  }

  fn lock(
    &self,
  ) -> Result<MutexGuard<'_, RuntimeAuthorityStateInner>, AuthorityStateError>
  {
    if crate::oden_rev2_context::namespace_gate_held_on_current_thread() {
      return Err(AuthorityStateError::NamespaceGateReentry);
    }
    self
      .inner
      .lock()
      .map_err(|_| AuthorityStateError::LockPoisoned)
  }

  fn view_for(
    &self,
    publication: Arc<RuntimeAuthorityPublication>,
  ) -> RuntimeAuthorityReadView {
    RuntimeAuthorityReadView {
      identity: self.identity.clone(),
      publication,
    }
  }

  pub fn read_view(
    &self,
  ) -> Result<RuntimeAuthorityReadView, AuthorityStateError> {
    let inner = self.lock()?;
    Ok(self.view_for(inner.publication.clone()))
  }

  /// Pin the exact current publication for a callback-free synchronous native
  /// operation. Methods that acquire `inner` again must not be called until
  /// this guard is dropped.
  pub(crate) fn pin_publication(
    &self,
    _namespace_witness: &crate::oden_rev2_context::OdenRev2NamespacePinWitness,
  ) -> Result<RuntimeAuthorityPublicationGuard<'_>, AuthorityStateError> {
    let inner = self.lock()?;
    if inner.publication.fail_closed {
      return Err(AuthorityStateError::StateFailClosed);
    }
    Ok(RuntimeAuthorityPublicationGuard { state: self, inner })
  }

  pub fn is_current(
    &self,
    view: &RuntimeAuthorityReadView,
  ) -> Result<bool, AuthorityStateError> {
    if !Arc::ptr_eq(&view.identity, &self.identity) {
      return Ok(false);
    }
    let inner = self.lock()?;
    Ok(
      Arc::ptr_eq(&view.publication, &inner.publication)
        && !inner.publication.fail_closed,
    )
  }

  pub fn begin_transaction(
    &self,
  ) -> Result<AuthorityTransaction, AuthorityStateError> {
    let view = self.read_view()?;
    if view.is_fail_closed() {
      return Err(AuthorityStateError::StateFailClosed);
    }
    Ok(AuthorityTransaction::new(
      view.identity.clone(),
      view.publication,
    ))
  }

  pub fn begin_transaction_from(
    &self,
    view: &RuntimeAuthorityReadView,
  ) -> Result<AuthorityTransaction, AuthorityStateError> {
    if !Arc::ptr_eq(&view.identity, &self.identity) {
      return Err(AuthorityStateError::IdentityMismatch);
    }
    if view.is_fail_closed() {
      return Err(AuthorityStateError::StateFailClosed);
    }
    Ok(AuthorityTransaction::new(
      view.identity.clone(),
      view.publication.clone(),
    ))
  }

  fn fail_closed_on_generation_overflow<T>(
    &self,
    base_publication: &Arc<RuntimeAuthorityPublication>,
    overflow: AuthorityStateError,
  ) -> Result<T, AuthorityStateError> {
    let mut inner = self.lock()?;
    if inner.publication.fail_closed {
      return Err(AuthorityStateError::StateFailClosed);
    }
    if !Arc::ptr_eq(base_publication, &inner.publication) {
      return Err(AuthorityStateError::GenerationChanged);
    }
    inner.cache.clear();
    inner.publication = Arc::new(RuntimeAuthorityPublication {
      rows: inner.publication.rows.clone(),
      generations: inner.publication.generations,
      fail_closed: true,
    });
    Err(overflow)
  }

  /// Compare the transaction's exact base publication, then build and bound a
  /// complete immutable proposed publication without holding the state lock.
  pub(crate) fn propose_transaction(
    &self,
    transaction: AuthorityTransaction,
  ) -> Result<ProposedAuthorityTransaction, AuthorityStateError> {
    if let Some(error) = transaction.construction_error {
      return Err(error);
    }
    if !Arc::ptr_eq(&transaction.identity, &self.identity) {
      return Err(AuthorityStateError::IdentityMismatch);
    }

    {
      let inner = self.lock()?;
      if inner.publication.fail_closed {
        return Err(AuthorityStateError::StateFailClosed);
      }
      if !Arc::ptr_eq(&transaction.base_publication, &inner.publication) {
        return Err(AuthorityStateError::GenerationChanged);
      }
    }

    let base_publication = transaction.base_publication;
    let mut rows = (*base_publication.rows).clone();
    let mut impact = GenerationImpact::default();
    for change in transaction.changes {
      let kind = match &change {
        RowChange::Upsert { kind, .. } | RowChange::Remove { kind, .. } => {
          *kind
        }
      };
      if rows.apply(change)? {
        impact.record(kind)?;
      }
    }
    rows.validate_complete(self.authority_limits)?;

    if impact.is_empty() {
      return Ok(ProposedAuthorityTransaction {
        proposed_view: self.view_for(base_publication.clone()),
        base_publication,
        changed: false,
      });
    }

    let generations = match base_publication.generations.advance(impact) {
      Ok(generations) => generations,
      Err(error @ AuthorityStateError::GenerationOverflow(_)) => {
        return self
          .fail_closed_on_generation_overflow(&base_publication, error);
      }
      Err(error) => return Err(error),
    };

    let publication = Arc::new(RuntimeAuthorityPublication {
      rows: Arc::new(rows),
      generations,
      fail_closed: false,
    });
    Ok(ProposedAuthorityTransaction {
      base_publication,
      proposed_view: self.view_for(publication),
      changed: true,
    })
  }

  /// Publish a previously validated proposal only if its exact base
  /// publication is still current. Cache invalidation and publication remain
  /// one lock-held linearization point.
  pub(crate) fn commit_validated<T>(
    &self,
    validated: ValidatedAuthorityTransaction<T>,
  ) -> Result<CommittedAuthorityTransaction<T>, AuthorityStateError> {
    let ValidatedAuthorityTransaction { proposal, output } = validated;
    if !Arc::ptr_eq(&proposal.proposed_view.identity, &self.identity) {
      return Err(AuthorityStateError::IdentityMismatch);
    }
    let mut inner = self.lock()?;
    if inner.publication.fail_closed {
      return Err(AuthorityStateError::StateFailClosed);
    }
    if !Arc::ptr_eq(&proposal.base_publication, &inner.publication) {
      return Err(AuthorityStateError::GenerationChanged);
    }
    if proposal.changed {
      inner.cache.clear();
      inner.publication = proposal.proposed_view.publication.clone();
    }
    let read_view = self.view_for(inner.publication.clone());
    Ok(CommittedAuthorityTransaction { read_view, output })
  }

  pub(crate) fn compare_propose_validate_commit<T, F>(
    &self,
    transaction: AuthorityTransaction,
    validate_proposed: F,
  ) -> Result<CommittedAuthorityTransaction<T>, AuthorityStateError>
  where
    F: FnOnce(&RuntimeAuthorityReadView) -> Result<T, AuthorityStateError>,
  {
    let proposed = self.propose_transaction(transaction)?;
    let validated = proposed.validate(validate_proposed)?;
    self.commit_validated(validated)
  }

  pub(crate) fn commit_if<F>(
    &self,
    transaction: AuthorityTransaction,
    validate_proposed: F,
  ) -> Result<RuntimeAuthorityReadView, AuthorityStateError>
  where
    F: FnOnce(&RuntimeAuthorityReadView) -> Result<(), AuthorityStateError>,
  {
    self
      .compare_propose_validate_commit(transaction, validate_proposed)
      .map(|committed| committed.into_parts().0)
  }

  #[cfg(test)]
  pub(crate) fn commit(
    &self,
    transaction: AuthorityTransaction,
  ) -> Result<RuntimeAuthorityReadView, AuthorityStateError> {
    self.commit_if(transaction, |_| Ok(()))
  }

  pub fn cache_insert(
    &self,
    key: DecisionCacheKey,
    value: DecisionCacheValue,
  ) -> Result<CacheAdmission, AuthorityStateError> {
    let mut inner = self.lock()?;
    if inner.publication.fail_closed {
      return Err(AuthorityStateError::StateFailClosed);
    }
    if key.identity() != self.identity.as_ref() {
      return Err(AuthorityStateError::IdentityMismatch);
    }
    if key.generations() != inner.publication.generations {
      return Err(AuthorityStateError::CacheKeyStale);
    }
    inner.cache.insert(key, value)
  }

  pub(crate) fn cache_candidate(
    &self,
    key: &DecisionCacheKey,
    now_monotonic: u64,
  ) -> Result<Option<DecisionCacheCandidate>, AuthorityStateError> {
    let mut inner = self.lock()?;
    if inner.publication.fail_closed {
      return Err(AuthorityStateError::StateFailClosed);
    }
    if key.identity() != self.identity.as_ref() {
      return Err(AuthorityStateError::IdentityMismatch);
    }
    if key.generations() != inner.publication.generations {
      return Ok(None);
    }
    let Some(value) = inner.cache.get_cloned(key, now_monotonic) else {
      return Ok(None);
    };
    Ok(Some(DecisionCacheCandidate {
      value,
      read_view: self.view_for(inner.publication.clone()),
    }))
  }

  pub fn cache_len(&self) -> Result<usize, AuthorityStateError> {
    Ok(self.lock()?.cache.len())
  }

  pub fn cache_weight_bytes(&self) -> Result<usize, AuthorityStateError> {
    Ok(self.lock()?.cache.total_weight_bytes())
  }
}

/// A cache hit is deliberately an internal candidate paired with the exact
/// read view. It can leave this module only for the context-owned shared-core
/// re-entry evaluator; there is no callback-shaped validation surface.
#[derive(Clone, Debug)]
pub(crate) struct DecisionCacheCandidate {
  value: DecisionCacheValue,
  read_view: RuntimeAuthorityReadView,
}

impl DecisionCacheCandidate {
  pub(crate) fn into_parts(
    self,
  ) -> (DecisionCacheValue, RuntimeAuthorityReadView) {
    (self.value, self.read_view)
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::rev2::PrincipalKind;

  fn digest(byte: u8) -> String {
    format!("sha256-{}", URL_SAFE_NO_PAD.encode([byte; 32]))
  }

  fn principal() -> PrincipalRef {
    PrincipalRef {
      kind: PrincipalKind::Package,
      key: "pkg:owner".to_string(),
    }
  }

  fn named_principal(key: &str) -> PrincipalRef {
    principal_of_kind(PrincipalKind::Package, key)
  }

  fn principal_of_kind(kind: PrincipalKind, key: &str) -> PrincipalRef {
    PrincipalRef {
      kind,
      key: key.to_string(),
    }
  }

  fn selector(
    suffix: &str,
    payload_bytes: usize,
  ) -> CanonicalAuthoritySelector {
    CanonicalAuthoritySelector {
      principal: Some(principal()),
      capability: "env:read".to_string(),
      projection_id: "projection:env-read".to_string(),
      resource: serde_json::json!({
        "kind": "env-name",
        "name": format!("{suffix}{}", "x".repeat(payload_bytes)),
      }),
    }
  }

  fn positive_source(suffix: &str, payload_bytes: usize) -> PositiveSource {
    PositiveSource {
      kind: "static-floor".to_string(),
      source_id: format!("source-{suffix}-{}", "x".repeat(payload_bytes)),
      generation: None,
    }
  }

  fn identity() -> RuntimeIdentityBinding {
    RuntimeIdentityBinding::new(
      digest(b'A'),
      digest(b'B'),
      digest(b'C'),
      digest(b'D'),
      digest(b'E'),
      "run-nonce".to_string(),
      "channel-epoch".to_string(),
    )
    .unwrap()
  }

  fn effect(suffix: &str) -> DecisionCacheEffect {
    let selector = selector(suffix, 0);
    let effect = CanonicalEffect {
      edge_id: format!("edge-{suffix}"),
      effect_slot_id: format!("slot-{suffix}"),
      capability: "env:read".to_string(),
      effect_owner: principal().key,
      projection_id: "projection:env-read".to_string(),
      occurrence: serde_json::json!({
        "effectOwner": principal().key,
        "name": suffix,
      }),
    };
    DecisionCacheEffect::from_canonical(&selector, &effect).unwrap()
  }

  fn cache_key(
    identity: &RuntimeIdentityBinding,
    generations: RuntimeGenerationVector,
    suffix: &str,
  ) -> DecisionCacheKey {
    DecisionCacheKey::new(
      "permission-query".to_string(),
      format!("edge-{suffix}"),
      "initial".to_string(),
      RuntimeAuthorityMode::Enforce,
      identity.clone(),
      generations,
      vec![principal()],
      principal(),
      vec![effect(suffix)],
      Vec::new(),
    )
    .unwrap()
  }

  fn cache_value(suffix: &str, payload_bytes: usize) -> DecisionCacheValue {
    DecisionCacheValue::new(
      CachedDecision::Allow,
      vec![
        DecisionDimension::new(
          format!("slot-{suffix}"),
          principal(),
          CachedDecision::Allow,
          Some(positive_source(suffix, payload_bytes)),
        )
        .unwrap(),
      ],
      digest(b'N'),
      None,
    )
    .unwrap()
  }

  fn upsert_once(
    state: &RuntimeAuthorityState,
    kind: AuthorityRowKind,
    row_id: &str,
    value: &str,
  ) -> RuntimeAuthorityReadView {
    let mut transaction = state.begin_transaction().unwrap();
    let selector = selector(value, 0);
    upsert_row_for_test(&mut transaction, kind, row_id, &selector).unwrap();
    state.commit(transaction).unwrap()
  }

  fn upsert_row_for_test(
    transaction: &mut AuthorityTransaction,
    kind: AuthorityRowKind,
    row_id: &str,
    selector: &CanonicalAuthoritySelector,
  ) -> Result<(), AuthorityStateError> {
    match kind {
      AuthorityRowKind::SessionPositive
      | AuthorityRowKind::SessionRevocation => transaction
        .upsert_session_row_for_test(kind, row_id.to_string(), selector),
      AuthorityRowKind::NegativeOverlay | AuthorityRowKind::Revocation => {
        transaction.upsert(kind, row_id.to_string(), selector)
      }
    }
  }

  fn remove_row_for_test(
    transaction: &mut AuthorityTransaction,
    kind: AuthorityRowKind,
    row_id: &str,
  ) -> Result<(), AuthorityStateError> {
    match kind {
      AuthorityRowKind::SessionPositive
      | AuthorityRowKind::SessionRevocation => {
        transaction.remove_session_row_for_test(kind, row_id.to_string())
      }
      AuthorityRowKind::NegativeOverlay | AuthorityRowKind::Revocation => {
        transaction.remove(kind, row_id.to_string())
      }
    }
  }

  #[test]
  fn identity_is_closed_and_validates_all_digest_bindings() {
    let identity = identity();
    assert_eq!(identity.vocab_digest(), digest(b'A'));
    assert_eq!(identity.registry_digest(), digest(b'B'));
    assert_eq!(identity.policy_digest(), digest(b'C'));
    assert_eq!(identity.armed_snapshot_digest(), digest(b'D'));
    assert_eq!(identity.project_digest(), digest(b'E'));
    assert_eq!(identity.run_nonce(), "run-nonce");
    assert_eq!(identity.channel_epoch(), "channel-epoch");

    let invalid = RuntimeIdentityBinding::new(
      "sha256-too-short".to_string(),
      digest(b'B'),
      digest(b'C'),
      digest(b'D'),
      digest(b'E'),
      "run".to_string(),
      "channel".to_string(),
    );
    assert!(matches!(
      invalid,
      Err(AuthorityStateError::InvalidDigest("vocabDigest"))
    ));

    let mut noncanonical_low_bits = digest(0);
    assert_eq!(noncanonical_low_bits.pop(), Some('A'));
    noncanonical_low_bits.push('B');
    let invalid = RuntimeIdentityBinding::new(
      noncanonical_low_bits,
      digest(b'B'),
      digest(b'C'),
      digest(b'D'),
      digest(b'E'),
      "run".to_string(),
      "channel".to_string(),
    );
    assert!(matches!(
      invalid,
      Err(AuthorityStateError::InvalidDigest("vocabDigest"))
    ));

    let invalid = RuntimeIdentityBinding::new(
      format!("{}=", digest(0)),
      digest(b'B'),
      digest(b'C'),
      digest(b'D'),
      digest(b'E'),
      "run".to_string(),
      "channel".to_string(),
    );
    assert!(matches!(
      invalid,
      Err(AuthorityStateError::InvalidDigest("vocabDigest"))
    ));
  }

  #[test]
  fn publication_guard_blocks_generation_publish_until_drop() {
    let state = Arc::new(RuntimeAuthorityState::new(identity()));
    let witness =
      crate::oden_rev2_context::OdenRev2NamespacePinWitness::for_test();
    let mut transaction = state.begin_transaction().unwrap();
    transaction
      .upsert(
        AuthorityRowKind::NegativeOverlay,
        "guarded-row".to_string(),
        &selector("guarded", 0),
      )
      .unwrap();

    let pinned = state.pin_publication(&witness).unwrap();
    assert_eq!(pinned.read_view().generations().negative_overlay(), 0);
    assert!(pinned.belongs_to(&state));
    assert!(matches!(
      state.inner.try_lock(),
      Err(std::sync::TryLockError::WouldBlock)
    ));

    let (started_tx, started_rx) = std::sync::mpsc::channel();
    let (published_tx, published_rx) = std::sync::mpsc::channel();
    let writer_state = Arc::clone(&state);
    let writer = std::thread::spawn(move || {
      started_tx.send(()).unwrap();
      let view = writer_state.commit(transaction).unwrap();
      published_tx
        .send(view.generations().negative_overlay())
        .unwrap();
    });
    started_rx.recv().unwrap();
    assert!(matches!(
      published_rx.recv_timeout(std::time::Duration::from_millis(50)),
      Err(std::sync::mpsc::RecvTimeoutError::Timeout)
    ));

    drop(pinned);
    assert_eq!(
      published_rx
        .recv_timeout(std::time::Duration::from_secs(2))
        .unwrap(),
      1
    );
    writer.join().unwrap();
  }

  #[test]
  fn publication_guard_poison_refuses_without_recovery() {
    let state = Arc::new(RuntimeAuthorityState::new(identity()));
    let poisoning_state = Arc::clone(&state);
    assert!(
      std::thread::spawn(move || {
        let witness =
          crate::oden_rev2_context::OdenRev2NamespacePinWitness::for_test();
        let _pinned = poisoning_state.pin_publication(&witness).unwrap();
        panic!("poison pinned publication");
      })
      .join()
      .is_err()
    );
    assert!(matches!(
      state.pin_publication(
        &crate::oden_rev2_context::OdenRev2NamespacePinWitness::for_test()
      ),
      Err(AuthorityStateError::LockPoisoned)
    ));
    assert!(matches!(
      state.read_view(),
      Err(AuthorityStateError::LockPoisoned)
    ));
  }

  #[test]
  fn every_row_kind_advances_exact_generations_for_add_replace_and_remove() {
    let cases = [
      (AuthorityRowKind::SessionPositive, (0, 0, 1)),
      (AuthorityRowKind::SessionRevocation, (1, 1, 1)),
      (AuthorityRowKind::NegativeOverlay, (1, 0, 0)),
      (AuthorityRowKind::Revocation, (1, 1, 0)),
    ];

    for (kind, (negative_step, revocation_step, session_step)) in cases {
      let state = RuntimeAuthorityState::new(identity());
      let initial = state.read_view().unwrap().generations();
      assert_eq!(
        (initial.negative_overlay(), initial.policy_snapshot()),
        (0, 1)
      );
      assert_eq!((initial.revocation(), initial.session_overlay()), (0, 0));

      for phase in 1..=2u64 {
        let view =
          upsert_once(&state, kind, "row", &format!("canonical-value-{phase}"));
        assert_eq!(
          view.generations().negative_overlay(),
          negative_step * phase
        );
        assert_eq!(view.generations().revocation(), revocation_step * phase);
        assert_eq!(view.generations().session_overlay(), session_step * phase);
        assert_eq!(view.generations().policy_snapshot(), 1);
      }

      let mut remove = state.begin_transaction().unwrap();
      remove_row_for_test(&mut remove, kind, "row").unwrap();
      let view = state.commit(remove).unwrap();
      assert_eq!(view.generations().negative_overlay(), negative_step * 3);
      assert_eq!(view.generations().revocation(), revocation_step * 3);
      assert_eq!(view.generations().session_overlay(), session_step * 3);
      assert_eq!(view.generations().policy_snapshot(), 1);
      assert!(view.row(kind, "row").is_none());
    }
  }

  #[test]
  fn mixed_generation_sequence_is_monotonic_and_batch_count_independent() {
    let state = RuntimeAuthorityState::new(identity());
    let mut expected = RuntimeGenerationVector::initial();

    for index in 0..256 {
      let kind = match index % 4 {
        0 => AuthorityRowKind::SessionPositive,
        1 => AuthorityRowKind::SessionRevocation,
        2 => AuthorityRowKind::NegativeOverlay,
        _ => AuthorityRowKind::Revocation,
      };
      let mut transaction = state.begin_transaction().unwrap();
      for item in 0..=index % 3 {
        let selector = selector(&format!("value-{index}-{item}"), 0);
        upsert_row_for_test(
          &mut transaction,
          kind,
          &format!("row-{index}-{item}"),
          &selector,
        )
        .unwrap();
      }
      let previous = state.read_view().unwrap().generations();
      let current = state.commit(transaction).unwrap().generations();
      current.ensure_monotonic_from(&previous).unwrap();
      let mut impact = GenerationImpact::default();
      impact.record(kind).unwrap();
      expected = expected.advance(impact).unwrap();
      assert_eq!(current, expected);
    }
  }

  #[test]
  fn no_op_transaction_preserves_generation_and_cache() {
    let state = RuntimeAuthorityState::new(identity());
    let first =
      upsert_once(&state, AuthorityRowKind::SessionPositive, "row", "same");
    let key = cache_key(first.identity(), first.generations(), "same");
    state.cache_insert(key, cache_value("same", 0)).unwrap();

    let second =
      upsert_once(&state, AuthorityRowKind::SessionPositive, "row", "same");
    assert_eq!(first.generations(), second.generations());
    assert_eq!(state.cache_len().unwrap(), 1);
  }

  #[test]
  fn conditional_commit_validates_proposed_rows_before_publication() {
    let state = RuntimeAuthorityState::new(identity());
    let initial = state.read_view().unwrap();
    let key =
      cache_key(initial.identity(), initial.generations(), "conditional");
    state
      .cache_insert(key, cache_value("conditional", 0))
      .unwrap();

    let mut rejected = state.begin_transaction().unwrap();
    rejected
      .upsert_session_row_for_test(
        AuthorityRowKind::SessionPositive,
        "candidate".to_string(),
        &selector("candidate", 0),
      )
      .unwrap();
    assert!(matches!(
      state.commit_if(rejected, |proposed| {
        assert!(
          proposed
            .row(AuthorityRowKind::SessionPositive, "candidate")
            .is_some()
        );
        Err(AuthorityStateError::InvalidField("test.validator"))
      }),
      Err(AuthorityStateError::InvalidField("test.validator"))
    ));
    let unchanged = state.read_view().unwrap();
    assert_eq!(unchanged.generations(), initial.generations());
    assert!(
      unchanged
        .row(AuthorityRowKind::SessionPositive, "candidate")
        .is_none()
    );
    assert_eq!(state.cache_len().unwrap(), 1);

    let mut accepted = state.begin_transaction().unwrap();
    accepted
      .upsert_session_row_for_test(
        AuthorityRowKind::SessionPositive,
        "candidate".to_string(),
        &selector("candidate", 0),
      )
      .unwrap();
    let published = state
      .compare_propose_validate_commit(accepted, |proposed| {
        if proposed
          .row(AuthorityRowKind::SessionPositive, "candidate")
          .is_some()
        {
          Ok("validated-batch-result")
        } else {
          Err(AuthorityStateError::InvalidField("test.validator"))
        }
      })
      .unwrap();
    assert_eq!(published.output(), &"validated-batch-result");
    assert_eq!(published.read_view().generations().session_overlay(), 1);
    assert_eq!(state.cache_len().unwrap(), 0);
    assert!(state.is_current(published.read_view()).unwrap());
  }

  #[test]
  fn intervening_publication_makes_validated_proposal_stale_without_partial_commit()
   {
    let state = RuntimeAuthorityState::new(identity());
    let initial = state.read_view().unwrap();
    let mut transaction = state.begin_transaction_from(&initial).unwrap();
    transaction
      .upsert_session_row_for_test(
        AuthorityRowKind::SessionPositive,
        "prepared-row".to_string(),
        &selector("prepared", 0),
      )
      .unwrap();

    let proposed = state.propose_transaction(transaction).unwrap();
    assert!(
      proposed
        .read_view()
        .row(AuthorityRowKind::SessionPositive, "prepared-row")
        .is_some()
    );
    assert!(
      state
        .read_view()
        .unwrap()
        .row(AuthorityRowKind::SessionPositive, "prepared-row")
        .is_none()
    );
    let validated = proposed
      .validate(|_| Ok::<_, AuthorityStateError>("validated"))
      .unwrap();

    let intervening = upsert_once(
      &state,
      AuthorityRowKind::NegativeOverlay,
      "intervening-row",
      "intervening",
    );
    assert!(matches!(
      state.commit_validated(validated),
      Err(AuthorityStateError::GenerationChanged)
    ));
    let current = state.read_view().unwrap();
    assert_eq!(current.generations(), intervening.generations());
    assert!(
      current
        .row(AuthorityRowKind::SessionPositive, "prepared-row")
        .is_none()
    );
    assert!(
      current
        .row(AuthorityRowKind::NegativeOverlay, "intervening-row")
        .is_some()
    );
  }

  #[test]
  fn immutable_read_views_never_mix_old_rows_with_new_generations() {
    let state = RuntimeAuthorityState::new(identity());
    let old = state.read_view().unwrap();
    let new = upsert_once(
      &state,
      AuthorityRowKind::NegativeOverlay,
      "deny-row",
      "deny-value",
    );

    assert!(
      old
        .row(AuthorityRowKind::NegativeOverlay, "deny-row")
        .is_none()
    );
    assert_eq!(old.generations().negative_overlay(), 0);
    let expected =
      canonicalize_typed("test.selector", &selector("deny-value", 0)).unwrap();
    assert_eq!(
      new
        .row(AuthorityRowKind::NegativeOverlay, "deny-row")
        .unwrap()
        .canonical_value(),
      expected
    );
    assert_eq!(
      new
        .row(AuthorityRowKind::NegativeOverlay, "deny-row")
        .unwrap()
        .selector(),
      &selector("deny-value", 0)
    );
    assert_eq!(new.generations().negative_overlay(), 1);
    assert!(!state.is_current(&old).unwrap());
    assert!(state.is_current(&new).unwrap());
  }

  #[test]
  fn stale_copied_cache_key_cannot_survive_generation_publication() {
    let state = RuntimeAuthorityState::new(identity());
    let initial = state.read_view().unwrap();
    let stale_key =
      cache_key(initial.identity(), initial.generations(), "stale");
    let value = cache_value("stale", 0);
    state
      .cache_insert(stale_key.clone(), value.clone())
      .unwrap();
    assert!(state.cache_candidate(&stale_key, 0).unwrap().is_some());

    let current =
      upsert_once(&state, AuthorityRowKind::SessionPositive, "grant", "value");
    assert_eq!(state.cache_len().unwrap(), 0);
    assert!(state.cache_candidate(&stale_key, 0).unwrap().is_none());
    assert_eq!(
      state.cache_insert(stale_key, value),
      Err(AuthorityStateError::CacheKeyStale)
    );

    let current_key =
      cache_key(current.identity(), current.generations(), "current");
    state
      .cache_insert(current_key.clone(), cache_value("current", 0))
      .unwrap();
    let candidate = state.cache_candidate(&current_key, 0).unwrap().unwrap();
    let (candidate_value, candidate_view) = candidate.into_parts();
    assert_eq!(candidate_value.decision(), CachedDecision::Allow);
    assert_eq!(candidate_view.generations(), current.generations());
    assert!(state.is_current(&candidate_view).unwrap());

    let race_key =
      cache_key(current.identity(), current.generations(), "negative-race");
    state
      .cache_insert(race_key.clone(), cache_value("negative-race", 0))
      .unwrap();
    let candidate = state.cache_candidate(&race_key, 0).unwrap().unwrap();
    let (_, candidate_view) = candidate.into_parts();
    upsert_once(
      &state,
      AuthorityRowKind::NegativeOverlay,
      "negative-race",
      "negative-race",
    );
    assert!(!state.is_current(&candidate_view).unwrap());
  }

  #[test]
  fn stale_transaction_and_generation_rollback_apply_nothing() {
    let state = RuntimeAuthorityState::new(identity());
    let old_view = state.read_view().unwrap();
    let mut stale = state.begin_transaction_from(&old_view).unwrap();
    let stale_selector = selector("stale-value", 0);
    stale
      .upsert_session_row_for_test(
        AuthorityRowKind::SessionPositive,
        "stale-row".to_string(),
        &stale_selector,
      )
      .unwrap();

    let current = upsert_once(
      &state,
      AuthorityRowKind::NegativeOverlay,
      "current-row",
      "current-value",
    );
    assert!(matches!(
      state.commit(stale),
      Err(AuthorityStateError::GenerationChanged)
    ));
    let after = state.read_view().unwrap();
    assert_eq!(after.generations(), current.generations());
    assert!(
      after
        .row(AuthorityRowKind::SessionPositive, "stale-row")
        .is_none()
    );

    let rolled_back = RuntimeGenerationVector::for_test(0, 1, 0, 0);
    let previous = RuntimeGenerationVector::for_test(1, 1, 1, 1);
    assert_eq!(
      rolled_back.ensure_monotonic_from(&previous),
      Err(AuthorityStateError::GenerationRollback("negativeOverlay"))
    );
  }

  #[test]
  fn session_specific_transactions_are_polarity_separated_and_collision_safe() {
    let state = RuntimeAuthorityState::new(identity());
    let owner = principal();
    let mut positive = selector("session", 0);
    positive.projection_id = "projection.env:read.positive/2".to_string();
    let mut revocation = positive.clone();
    revocation.projection_id = "projection.env:read.negative/2".to_string();
    let initial = state.read_view().unwrap();
    let ids =
      session_row_ids(initial.identity(), &owner, &owner, &positive).unwrap();

    let mut revoke = state.begin_transaction().unwrap();
    assert_eq!(
      revoke
        .upsert_session_revocation(&owner, &owner, &revocation, None)
        .unwrap(),
      SessionRowAdmission::Insert
    );
    state.commit(revoke).unwrap();
    let revoked = state.read_view().unwrap();
    assert!(
      revoked
        .row(AuthorityRowKind::SessionRevocation, ids.revocation())
        .is_some()
    );
    assert!(
      revoked
        .row(AuthorityRowKind::SessionPositive, ids.positive())
        .is_none()
    );

    let mut grant = state.begin_transaction().unwrap();
    assert_eq!(
      grant
        .reconcile_session_grant(&owner, &owner, &positive, &revocation, None,)
        .unwrap(),
      SessionRowAdmission::Insert
    );
    state.commit(grant).unwrap();
    let granted = state.read_view().unwrap();
    assert!(
      granted
        .row(AuthorityRowKind::SessionRevocation, ids.revocation())
        .is_none()
    );
    assert_eq!(
      granted
        .row(AuthorityRowKind::SessionPositive, ids.positive())
        .unwrap()
        .selector(),
      &positive
    );

    let mut idempotent = state.begin_transaction().unwrap();
    assert_eq!(
      idempotent
        .reconcile_session_grant(&owner, &owner, &positive, &revocation, None,)
        .unwrap(),
      SessionRowAdmission::Idempotent
    );

    let conflicting_state = RuntimeAuthorityState::new(identity());
    let mut conflict = positive.clone();
    conflict.resource =
      serde_json::json!({ "kind": "env-name", "name": "other" });
    let mut inject = conflicting_state.begin_transaction().unwrap();
    inject
      .upsert_session_row_for_test(
        AuthorityRowKind::SessionPositive,
        ids.positive().to_string(),
        &conflict,
      )
      .unwrap();
    conflicting_state.commit(inject).unwrap();
    let mut refused = conflicting_state.begin_transaction().unwrap();
    assert!(matches!(
      refused.reconcile_session_grant(
        &owner,
        &owner,
        &positive,
        &revocation,
        None,
      ),
      Err(AuthorityStateError::SessionRowIdentity(_))
    ));
    assert!(conflicting_state.commit(refused).is_err());
    assert_eq!(
      conflicting_state
        .read_view()
        .unwrap()
        .row(AuthorityRowKind::SessionPositive, ids.positive())
        .unwrap()
        .selector(),
      &conflict
    );
  }

  #[test]
  fn generic_mutation_cannot_insert_remove_or_replace_session_rows() {
    let owner = principal();
    let mut positive = selector("session", 0);
    positive.projection_id = "projection.env:read.positive/2".to_string();
    let mut revocation = positive.clone();
    revocation.projection_id = "projection.env:read.negative/2".to_string();

    for (kind, selector) in [
      (AuthorityRowKind::SessionPositive, &positive),
      (AuthorityRowKind::SessionRevocation, &revocation),
    ] {
      let empty = RuntimeAuthorityState::new(identity());
      let mut insert = empty.begin_transaction().unwrap();
      assert_eq!(
        insert.upsert(kind, "caller-chosen".to_string(), selector),
        Err(AuthorityStateError::UntypedSessionMutation)
      );
      assert!(matches!(
        empty.commit(insert),
        Err(AuthorityStateError::UntypedSessionMutation)
      ));
      assert_eq!(empty.read_view().unwrap().row_count(), 0);

      let state = RuntimeAuthorityState::new(identity());
      let ids =
        session_row_ids(&identity(), &owner, &owner, &positive).unwrap();
      let row_id = match kind {
        AuthorityRowKind::SessionPositive => ids.positive(),
        AuthorityRowKind::SessionRevocation => ids.revocation(),
        AuthorityRowKind::NegativeOverlay | AuthorityRowKind::Revocation => {
          unreachable!()
        }
      };
      let mut setup = state.begin_transaction().unwrap();
      match kind {
        AuthorityRowKind::SessionPositive => {
          setup
            .reconcile_session_grant(
              &owner,
              &owner,
              &positive,
              &revocation,
              None,
            )
            .unwrap();
        }
        AuthorityRowKind::SessionRevocation => {
          setup
            .upsert_session_revocation(&owner, &owner, &revocation, None)
            .unwrap();
        }
        AuthorityRowKind::NegativeOverlay | AuthorityRowKind::Revocation => {
          unreachable!()
        }
      }
      state.commit(setup).unwrap();

      let mut remove = state.begin_transaction().unwrap();
      assert_eq!(
        remove.remove(kind, row_id.to_string()),
        Err(AuthorityStateError::UntypedSessionMutation)
      );
      assert!(matches!(
        state.commit(remove),
        Err(AuthorityStateError::UntypedSessionMutation)
      ));

      let mut replacement = selector.clone();
      replacement.projection_id =
        format!("{}.substitution", selector.projection_id);
      let mut replace = state.begin_transaction().unwrap();
      assert_eq!(
        replace.upsert(kind, row_id.to_string(), &replacement),
        Err(AuthorityStateError::UntypedSessionMutation)
      );
      assert!(matches!(
        state.commit(replace),
        Err(AuthorityStateError::UntypedSessionMutation)
      ));
      assert_eq!(
        state
          .read_view()
          .unwrap()
          .row(kind, row_id)
          .unwrap()
          .selector(),
        selector
      );
    }
  }

  #[test]
  fn every_mutable_generation_overflow_is_terminal_and_partial_free() {
    let cases = [
      (
        AuthorityRowKind::NegativeOverlay,
        RuntimeGenerationVector::for_test(u64::MAX, 1, 0, 0),
        "negativeOverlay",
      ),
      (
        AuthorityRowKind::Revocation,
        RuntimeGenerationVector::for_test(0, 1, u64::MAX, 0),
        "revocation",
      ),
      (
        AuthorityRowKind::SessionPositive,
        RuntimeGenerationVector::for_test(0, 1, 0, u64::MAX),
        "sessionOverlay",
      ),
    ];

    for (kind, generations, overflowed) in cases {
      let state = RuntimeAuthorityState::with_generations_for_test(
        identity(),
        generations,
      );
      let key = cache_key(&identity(), generations, overflowed);
      state.cache_insert(key, cache_value(overflowed, 0)).unwrap();
      let mut transaction = state.begin_transaction().unwrap();
      let selector = selector("value", 0);
      upsert_row_for_test(&mut transaction, kind, "row", &selector).unwrap();
      assert!(matches!(
        state.commit(transaction),
        Err(AuthorityStateError::GenerationOverflow(field)) if field == overflowed
      ));
      let view = state.read_view().unwrap();
      assert!(view.is_fail_closed());
      assert!(view.row(kind, "row").is_none());
      assert_eq!(view.generations(), generations);
      assert_eq!(state.cache_len().unwrap(), 0);
      assert!(matches!(
        state.begin_transaction(),
        Err(AuthorityStateError::StateFailClosed)
      ));
    }
  }

  #[test]
  fn invalid_multirow_transaction_never_publishes_a_valid_prefix() {
    let state = RuntimeAuthorityState::new(identity());
    let initial = state.read_view().unwrap();
    let key = cache_key(initial.identity(), initial.generations(), "preserved");
    state
      .cache_insert(key, cache_value("preserved", 0))
      .unwrap();

    let mut transaction = state.begin_transaction().unwrap();
    let valid_selector = selector("value", 0);
    transaction
      .upsert_session_row_for_test(
        AuthorityRowKind::SessionPositive,
        "valid".to_string(),
        &valid_selector,
      )
      .unwrap();
    let invalid_selector = selector("invalid", 0);
    assert!(matches!(
      transaction.upsert(
        AuthorityRowKind::NegativeOverlay,
        String::new(),
        &invalid_selector
      ),
      Err(AuthorityStateError::InvalidField("authorityRow.rowId"))
    ));
    assert!(matches!(
      state.commit(transaction),
      Err(AuthorityStateError::InvalidField("authorityRow.rowId"))
    ));

    let after = state.read_view().unwrap();
    assert_eq!(after.generations(), initial.generations());
    assert!(
      after
        .row(AuthorityRowKind::SessionPositive, "valid")
        .is_none()
    );
    assert_eq!(state.cache_len().unwrap(), 1);
  }

  #[test]
  fn duplicate_row_mutation_aborts_the_complete_transaction() {
    let state = RuntimeAuthorityState::new(identity());
    let mut transaction = state.begin_transaction().unwrap();
    let first = selector("first", 0);
    transaction
      .upsert_session_row_for_test(
        AuthorityRowKind::SessionPositive,
        "row".to_string(),
        &first,
      )
      .unwrap();
    let second = selector("second", 0);
    assert_eq!(
      transaction.upsert_session_row_for_test(
        AuthorityRowKind::SessionPositive,
        "row".to_string(),
        &second,
      ),
      Err(AuthorityStateError::DuplicateMutation)
    );
    assert!(matches!(
      state.commit(transaction),
      Err(AuthorityStateError::DuplicateMutation)
    ));
    assert_eq!(
      state
        .read_view()
        .unwrap()
        .rows(AuthorityRowKind::SessionPositive)
        .count(),
      0
    );
  }

  #[test]
  fn duplicate_row_source_id_across_kinds_aborts_complete_state() {
    let state = RuntimeAuthorityState::new(identity());
    let before = upsert_once(
      &state,
      AuthorityRowKind::SessionPositive,
      "shared-source",
      "positive",
    );
    let key = cache_key(
      before.identity(),
      before.generations(),
      "cross-kind-duplicate",
    );
    state
      .cache_insert(key, cache_value("cross-kind-duplicate", 0))
      .unwrap();

    let mut transaction = state.begin_transaction().unwrap();
    transaction
      .upsert(
        AuthorityRowKind::NegativeOverlay,
        "shared-source".to_string(),
        &selector("negative", 0),
      )
      .unwrap();
    assert!(matches!(
      state.commit(transaction),
      Err(AuthorityStateError::DuplicateRowSourceId)
    ));

    let after = state.read_view().unwrap();
    assert_eq!(after.generations(), before.generations());
    assert!(
      after
        .row(AuthorityRowKind::SessionPositive, "shared-source")
        .is_some()
    );
    assert!(
      after
        .row(AuthorityRowKind::NegativeOverlay, "shared-source")
        .is_none()
    );
    assert_eq!(state.cache_len().unwrap(), 1);
  }

  #[test]
  fn atomic_cross_kind_move_is_validated_only_in_complete_final_state() {
    let moved_selector = selector("moved", 0);
    let moved_row =
      AuthorityRow::from_selector("shared-source".to_string(), &moved_selector)
        .unwrap();
    let state = RuntimeAuthorityState::with_limits_for_test(
      identity(),
      AuthorityStateLimits::for_test(
        1,
        moved_row.encoded_weight_bytes(),
        moved_row.encoded_weight_bytes(),
      ),
    );
    let before = upsert_once(
      &state,
      AuthorityRowKind::SessionPositive,
      "shared-source",
      "moved",
    );

    let mut transaction = state.begin_transaction().unwrap();
    // Upsert first deliberately exceeds the one-row bound in the intermediate
    // builder state. Only the complete proposed state is authoritative.
    transaction
      .upsert(
        AuthorityRowKind::NegativeOverlay,
        "shared-source".to_string(),
        &moved_selector,
      )
      .unwrap();
    transaction
      .remove_session_row_for_test(
        AuthorityRowKind::SessionPositive,
        "shared-source".to_string(),
      )
      .unwrap();
    let moved = state.commit(transaction).unwrap();

    assert_eq!(moved.row_count(), 1);
    assert!(
      moved
        .row(AuthorityRowKind::SessionPositive, "shared-source")
        .is_none()
    );
    assert!(
      moved
        .row(AuthorityRowKind::NegativeOverlay, "shared-source")
        .is_some()
    );
    assert_eq!(
      moved.generations().negative_overlay(),
      before.generations().negative_overlay() + 1
    );
    assert_eq!(
      moved.generations().session_overlay(),
      before.generations().session_overlay() + 1
    );
  }

  #[test]
  fn accumulated_authority_limits_abort_without_rows_generations_or_cache_loss()
  {
    assert_eq!(AUTHORITY_STATE_MAX_ROWS, 4_096);
    assert_eq!(AUTHORITY_STATE_MAX_WEIGHT_BYTES, 16 * 1024 * 1024);
    assert_eq!(AUTHORITY_STATE_MAX_ROW_WEIGHT_BYTES, 64 * 1024);

    let first_selector = selector("first-capacity", 64);
    let second_selector = selector("second-capacity", 64);
    let first_row =
      AuthorityRow::from_selector("first".to_string(), &first_selector)
        .unwrap();
    let second_row =
      AuthorityRow::from_selector("second".to_string(), &second_selector)
        .unwrap();
    let aggregate_limit =
      first_row.encoded_weight_bytes() + second_row.encoded_weight_bytes() - 1;
    let row_limit = first_row
      .encoded_weight_bytes()
      .max(second_row.encoded_weight_bytes());
    let state = RuntimeAuthorityState::with_limits_for_test(
      identity(),
      AuthorityStateLimits::for_test(4, aggregate_limit, row_limit),
    );
    let mut first_transaction = state.begin_transaction().unwrap();
    first_transaction
      .upsert_session_row_for_test(
        AuthorityRowKind::SessionPositive,
        "first".to_string(),
        &first_selector,
      )
      .unwrap();
    let first = state.commit(first_transaction).unwrap();
    let key = cache_key(first.identity(), first.generations(), "capacity");
    state.cache_insert(key, cache_value("capacity", 0)).unwrap();

    let mut over_total = state.begin_transaction().unwrap();
    over_total
      .upsert_session_row_for_test(
        AuthorityRowKind::SessionPositive,
        "second".to_string(),
        &second_selector,
      )
      .unwrap();
    assert!(matches!(
      state.commit(over_total),
      Err(AuthorityStateError::AuthorityCapacityExceeded(
        "aggregate byte bound"
      ))
    ));
    let after = state.read_view().unwrap();
    assert_eq!(after.generations(), first.generations());
    assert_eq!(after.row_count(), 1);
    assert_eq!(after.row_weight_bytes(), first_row.encoded_weight_bytes());
    assert!(
      after
        .row(AuthorityRowKind::SessionPositive, "first")
        .is_some()
    );
    assert!(
      after
        .row(AuthorityRowKind::SessionPositive, "second")
        .is_none()
    );
    assert_eq!(state.cache_len().unwrap(), 1);

    let count_state = RuntimeAuthorityState::with_limits_for_test(
      identity(),
      AuthorityStateLimits::for_test(
        1,
        AUTHORITY_STATE_MAX_WEIGHT_BYTES,
        AUTHORITY_STATE_MAX_ROW_WEIGHT_BYTES,
      ),
    );
    upsert_once(
      &count_state,
      AuthorityRowKind::NegativeOverlay,
      "one",
      "one",
    );
    let before = count_state.read_view().unwrap();
    let mut over_count = count_state.begin_transaction().unwrap();
    let two = selector("two", 0);
    over_count
      .upsert(AuthorityRowKind::NegativeOverlay, "two".to_string(), &two)
      .unwrap();
    assert!(matches!(
      count_state.commit(over_count),
      Err(AuthorityStateError::AuthorityCapacityExceeded(
        "row-count bound"
      ))
    ));
    assert_eq!(
      count_state.read_view().unwrap().generations(),
      before.generations()
    );

    let oversize_selector = selector("oversize-row", 256);
    let oversize_row =
      AuthorityRow::from_selector("oversize".to_string(), &oversize_selector)
        .unwrap();
    let per_row_state = RuntimeAuthorityState::with_limits_for_test(
      identity(),
      AuthorityStateLimits::for_test(
        4,
        AUTHORITY_STATE_MAX_WEIGHT_BYTES,
        oversize_row.encoded_weight_bytes() - 1,
      ),
    );
    let mut over_row = per_row_state.begin_transaction().unwrap();
    over_row
      .upsert(
        AuthorityRowKind::Revocation,
        "oversize".to_string(),
        &oversize_selector,
      )
      .unwrap();
    assert!(matches!(
      per_row_state.commit(over_row),
      Err(AuthorityStateError::AuthorityCapacityExceeded(
        "per-row byte bound"
      ))
    ));
    let after = per_row_state.read_view().unwrap();
    assert_eq!(after.row_count(), 0);
    assert_eq!(after.generations(), RuntimeGenerationVector::initial());

    let production = RuntimeAuthorityState::new(identity());
    let production_oversize =
      selector("production-oversize", AUTHORITY_STATE_MAX_ROW_WEIGHT_BYTES);
    let mut transaction = production.begin_transaction().unwrap();
    assert!(matches!(
      transaction.upsert(
        AuthorityRowKind::NegativeOverlay,
        "production-oversize".to_string(),
        &production_oversize,
      ),
      Err(AuthorityStateError::AuthorityCapacityExceeded(
        "per-row byte bound"
      ))
    ));
    assert!(production.commit(transaction).is_err());
    assert_eq!(production.read_view().unwrap().row_count(), 0);
  }

  #[test]
  fn cached_overall_decision_must_equal_deterministic_dimension_collapse() {
    let allow = DecisionDimension::new(
      "slot-allow".to_string(),
      principal(),
      CachedDecision::Allow,
      Some(positive_source("allow", 0)),
    )
    .unwrap();
    let deny = DecisionDimension::new(
      "slot-deny".to_string(),
      principal(),
      CachedDecision::Deny,
      None,
    )
    .unwrap();
    assert!(matches!(
      DecisionCacheValue::new(
        CachedDecision::Allow,
        vec![allow.clone(), deny.clone()],
        digest(b'N'),
        None,
      ),
      Err(AuthorityStateError::InvalidField("cacheValue.decision"))
    ));
    assert!(
      DecisionCacheValue::new(
        CachedDecision::Deny,
        vec![allow, deny],
        digest(b'N'),
        None,
      )
      .is_ok()
    );

    let masked = DecisionDimension::new(
      "slot-masked".to_string(),
      principal(),
      CachedDecision::Masked,
      None,
    )
    .unwrap();
    let prompt = DecisionDimension::new(
      "slot-prompt".to_string(),
      principal(),
      CachedDecision::Prompt,
      None,
    )
    .unwrap();
    assert!(
      DecisionCacheValue::new(
        CachedDecision::Masked,
        vec![masked, prompt],
        digest(b'N'),
        None,
      )
      .is_ok()
    );
  }

  #[test]
  fn cache_sets_use_complete_jcs_element_order() {
    let package_a = named_principal("pkg:owner");
    let root_z = principal_of_kind(PrincipalKind::Root, "z");
    let key = DecisionCacheKey::new(
      "permission-query".to_string(),
      "edge-canonical-sets".to_string(),
      "initial".to_string(),
      RuntimeAuthorityMode::Enforce,
      identity(),
      RuntimeGenerationVector::initial(),
      vec![root_z.clone(), package_a.clone()],
      package_a.clone(),
      vec![effect("canonical-sets")],
      vec![
        ReceiptDependency::new("receipt-a".to_string(), 9, 8, 7).unwrap(),
        ReceiptDependency::new("receipt-z".to_string(), 1, 2, 3).unwrap(),
      ],
    )
    .unwrap();
    assert_eq!(key.constrained_principals[0], package_a);
    assert_eq!(key.constrained_principals[1], root_z);
    assert_eq!(key.receipt_dependencies[0].receipt_id, "receipt-z");
    assert_eq!(key.receipt_dependencies[0].issuer_generation.0, 1);
    assert_eq!(key.receipt_dependencies[0].receipt_negative_generation.0, 2);
    assert_eq!(key.receipt_dependencies[0].monotonic_deadline.0, 3);
    let canonical_receipts = key
      .receipt_dependencies
      .iter()
      .map(|dependency| {
        canonicalize_typed("test.receiptDependency", dependency).unwrap()
      })
      .collect::<Vec<_>>();
    let mut sorted_receipts = canonical_receipts.clone();
    sorted_receipts.sort();
    assert_eq!(canonical_receipts, sorted_receipts);

    let allow = |slot: &str, principal: PrincipalRef, source_id: &str| {
      DecisionDimension::new(
        slot.to_string(),
        principal,
        CachedDecision::Allow,
        Some(PositiveSource {
          kind: "static-floor".to_string(),
          source_id: source_id.to_string(),
          generation: Some("7".to_string()),
        }),
      )
      .unwrap()
    };
    let dimensions = vec![
      DecisionDimension::new(
        "slot-0".to_string(),
        principal_of_kind(PrincipalKind::Root, "deny"),
        CachedDecision::Deny,
        None,
      )
      .unwrap(),
      allow("slot-a", named_principal("package"), "source-z"),
      allow(
        "slot-z",
        principal_of_kind(PrincipalKind::Root, "root"),
        "source-a",
      ),
    ];
    let value = DecisionCacheValue::new(
      CachedDecision::Deny,
      dimensions,
      digest(b'N'),
      None,
    )
    .unwrap();
    assert_eq!(value.dimensions[0].decision, CachedDecision::Allow);
    assert_eq!(
      value.dimensions[0]
        .positive_source
        .as_ref()
        .unwrap()
        .source_id,
      "source-a"
    );
    assert_eq!(value.dimensions[1].decision, CachedDecision::Allow);
    assert_eq!(value.dimensions[2].decision, CachedDecision::Deny);
    let canonical_dimensions = value
      .dimensions
      .iter()
      .map(|dimension| {
        canonicalize_typed("test.cacheDimension", dimension).unwrap()
      })
      .collect::<Vec<_>>();
    let mut sorted_dimensions = canonical_dimensions.clone();
    sorted_dimensions.sort();
    assert_eq!(canonical_dimensions, sorted_dimensions);
  }

  #[test]
  fn cache_value_must_cover_the_exact_key_dimension_product() {
    let identity = identity();
    let generations = RuntimeGenerationVector::initial();
    let key = cache_key(&identity, generations, "expected");
    let mismatched = cache_value("different", 0);
    let mut cache = DecisionCache::new();
    assert_eq!(
      cache.insert(key, mismatched),
      Err(AuthorityStateError::InvalidField("cacheValue.dimensions"))
    );
    assert_eq!(cache.len(), 0);
    assert_eq!(cache.total_weight_bytes(), 0);

    let principals = (0..=MAX_CACHE_CONSTRAINED_PRINCIPALS)
      .map(|index| PrincipalRef {
        kind: PrincipalKind::Package,
        key: format!("pkg:{index}"),
      })
      .collect::<Vec<_>>();
    assert!(matches!(
      DecisionCacheKey::new(
        "permission-query".to_string(),
        "edge-bounded".to_string(),
        "initial".to_string(),
        RuntimeAuthorityMode::Enforce,
        identity,
        generations,
        principals.clone(),
        principals[0].clone(),
        vec![effect("bounded")],
        Vec::new(),
      ),
      Err(AuthorityStateError::InvalidField("cacheKey"))
    ));

    let dimension = DecisionDimension::new(
      "slot-bounded".to_string(),
      principal(),
      CachedDecision::Deny,
      None,
    )
    .unwrap();
    assert!(matches!(
      DecisionCacheValue::new(
        CachedDecision::Deny,
        vec![dimension; MAX_CACHE_DECISION_DIMENSIONS + 1],
        digest(b'N'),
        None,
      ),
      Err(AuthorityStateError::InvalidField("cacheValue.dimensions"))
    ));
  }

  #[test]
  fn cache_admission_refuses_incomplete_extra_and_substituted_dimensions() {
    let owner = principal();
    let deputy = named_principal("pkg:deputy");
    let key = DecisionCacheKey::new(
      "permission-query".to_string(),
      "edge-product".to_string(),
      "initial".to_string(),
      RuntimeAuthorityMode::Enforce,
      identity(),
      RuntimeGenerationVector::initial(),
      vec![owner.clone(), deputy.clone()],
      owner.clone(),
      vec![effect("one"), effect("two")],
      Vec::new(),
    )
    .unwrap();
    let dimension = |slot: &str, principal: PrincipalRef| {
      DecisionDimension::new(
        format!("slot-{slot}"),
        principal,
        CachedDecision::Deny,
        None,
      )
      .unwrap()
    };
    let complete = vec![
      dimension("one", owner.clone()),
      dimension("one", deputy.clone()),
      dimension("two", owner.clone()),
      dimension("two", deputy.clone()),
    ];

    let candidates = [
      complete[..3].to_vec(),
      {
        let mut extra = complete.clone();
        extra.push(dimension("extra", owner.clone()));
        extra
      },
      vec![
        dimension("one", owner.clone()),
        dimension("one", deputy.clone()),
        dimension("two", owner.clone()),
        dimension("extra", deputy.clone()),
      ],
    ];
    for dimensions in candidates {
      let value = DecisionCacheValue::new(
        CachedDecision::Deny,
        dimensions,
        digest(b'N'),
        None,
      )
      .unwrap();
      let mut cache = DecisionCache::new();
      assert_eq!(
        cache.insert(key.clone(), value),
        Err(AuthorityStateError::InvalidField("cacheValue.dimensions"))
      );
      assert_eq!(cache.len(), 0);
    }

    let complete = DecisionCacheValue::new(
      CachedDecision::Deny,
      complete,
      digest(b'N'),
      None,
    )
    .unwrap();
    let mut cache = DecisionCache::new();
    assert_eq!(
      cache.insert(key, complete).unwrap(),
      CacheAdmission::Inserted
    );
  }

  #[test]
  fn cache_key_rejects_effect_product_and_receipt_bound_overflow_prework() {
    let generations = RuntimeGenerationVector::initial();
    let too_many_effects = vec![effect("repeated"); MAX_CACHE_EFFECTS + 1];
    assert!(matches!(
      DecisionCacheKey::new(
        "permission-query".to_string(),
        "edge-effects".to_string(),
        "initial".to_string(),
        RuntimeAuthorityMode::Enforce,
        identity(),
        generations,
        vec![principal()],
        principal(),
        too_many_effects,
        Vec::new(),
      ),
      Err(AuthorityStateError::InvalidField("cacheKey"))
    ));

    let principals = (0..65)
      .map(|index| named_principal(&format!("pkg:product-{index}")))
      .collect::<Vec<_>>();
    assert!(matches!(
      DecisionCacheKey::new(
        "permission-query".to_string(),
        "edge-product".to_string(),
        "initial".to_string(),
        RuntimeAuthorityMode::Enforce,
        identity(),
        generations,
        principals.clone(),
        principals[0].clone(),
        vec![effect("repeated"); MAX_CACHE_EFFECTS],
        Vec::new(),
      ),
      Err(AuthorityStateError::InvalidField(
        "cacheKey.principalEffectProduct"
      ))
    ));

    let receipts = (0..=MAX_CACHE_RECEIPT_DEPENDENCIES)
      .map(|index| {
        ReceiptDependency::new(format!("receipt-{index}"), 0, 0, 100).unwrap()
      })
      .collect::<Vec<_>>();
    assert!(matches!(
      DecisionCacheKey::new(
        "permission-query".to_string(),
        "edge-receipts".to_string(),
        "initial".to_string(),
        RuntimeAuthorityMode::Enforce,
        identity(),
        generations,
        vec![principal()],
        principal(),
        vec![effect("receipts")],
        receipts,
      ),
      Err(AuthorityStateError::InvalidField("cacheKey"))
    ));
  }

  #[test]
  fn typed_authority_payloads_are_canonicalized_and_mismatch_refuses() {
    let selector = selector("typed", 0);
    let effect = CanonicalEffect {
      edge_id: "edge-typed".to_string(),
      effect_slot_id: "slot-typed".to_string(),
      capability: "env:read".to_string(),
      effect_owner: principal().key,
      projection_id: "projection:env-read".to_string(),
      occurrence: serde_json::json!({
        "effectOwner": principal().key,
        "z": 1,
        "a": 2,
      }),
    };
    let cached = DecisionCacheEffect::from_canonical(&selector, &effect)
      .expect("typed normalized values should cache");
    assert_eq!(cached.slot_id(), "slot-typed");
    assert_eq!(cached.effect_owner, principal());
    assert_eq!(cached.selector, selector);
    assert_eq!(
      cached.occurrence,
      serde_json::json!({
        "effectOwner": principal().key,
        "z": 1,
        "a": 2,
      })
    );

    let mut owner_mismatch = effect.clone();
    owner_mismatch.effect_owner = "pkg:substituted".to_string();
    assert!(matches!(
      DecisionCacheEffect::from_canonical(&selector, &owner_mismatch),
      Err(AuthorityStateError::InvalidField("cacheEffect.effectOwner"))
    ));

    let mut occurrence_mismatch = effect.clone();
    occurrence_mismatch.occurrence["effectOwner"] =
      serde_json::Value::String("pkg:substituted".to_string());
    assert!(matches!(
      DecisionCacheEffect::from_canonical(&selector, &occurrence_mismatch),
      Err(AuthorityStateError::InvalidField(
        "cacheEffect.occurrence.effectOwner"
      ))
    ));

    let mut missing_occurrence_owner = effect.clone();
    missing_occurrence_owner
      .occurrence
      .as_object_mut()
      .unwrap()
      .remove("effectOwner");
    assert!(matches!(
      DecisionCacheEffect::from_canonical(&selector, &missing_occurrence_owner),
      Err(AuthorityStateError::InvalidField(
        "cacheEffect.occurrence.effectOwner"
      ))
    ));

    let mut capability_mismatch = effect;
    capability_mismatch.capability = "env:write".to_string();
    assert!(matches!(
      DecisionCacheEffect::from_canonical(&selector, &capability_mismatch),
      Err(AuthorityStateError::InvalidField("cacheEffect.capability"))
    ));
  }

  #[test]
  fn cache_serialization_is_schema_exact_typed_and_jcs_weighted() {
    let key = cache_key(
      &identity(),
      RuntimeGenerationVector::initial(),
      "serialization",
    );
    let key_json: serde_json::Value =
      serde_json::from_slice(&key.canonical_key_bytes).unwrap();
    assert_eq!(
      key_json.get("schema").and_then(serde_json::Value::as_str),
      Some(DECISION_CACHE_KEY_SCHEMA)
    );
    assert!(key_json["constrainedPrincipals"][0].is_object());
    assert!(key_json["overlayOwner"].is_object());
    assert!(key_json["effects"][0]["effectOwner"].is_object());
    assert!(key_json["effects"][0]["selector"].is_object());
    assert!(key_json["effects"][0]["occurrence"].is_object());
    assert_eq!(
      key.canonical_key_bytes,
      canonicalize_typed("test.cacheKey", &key)
        .unwrap()
        .into_bytes()
    );
    assert_ne!(
      key.canonical_key_bytes,
      serde_json::to_vec(&key).unwrap(),
      "the canonical LRU/index bytes must not depend on serde field order"
    );

    let value = cache_value("serialization", 0);
    let (prepared, canonical_key_bytes, weight) =
      DecisionCache::prepare_entry(&key, value).unwrap();
    let canonical_value_bytes =
      canonicalize_typed("test.cacheValue", &prepared)
        .unwrap()
        .into_bytes();
    assert_eq!(canonical_key_bytes, key.canonical_key_bytes);
    assert_eq!(
      weight,
      canonical_key_bytes.len() + canonical_value_bytes.len()
    );
    assert_eq!(prepared.weight_bytes(), weight as u64);
    let value_json: serde_json::Value =
      serde_json::from_slice(&canonical_value_bytes).unwrap();
    assert!(value_json["dimensions"][0]["principal"].is_object());
    assert!(value_json["dimensions"][0]["positiveSource"].is_object());
  }

  #[test]
  fn production_cache_count_bound_evicts_the_oldest_full_key() {
    assert_eq!(DECISION_CACHE_MAX_ENTRIES, 4_096);
    assert_eq!(DECISION_CACHE_MAX_WEIGHT_BYTES, 16 * 1024 * 1024);
    assert_eq!(DECISION_CACHE_MAX_ENTRY_WEIGHT_BYTES, 64 * 1024);

    let identity = identity();
    let generations = RuntimeGenerationVector::initial();
    let mut cache = DecisionCache::new();
    let first_key = cache_key(&identity, generations, "0");
    for index in 0..=DECISION_CACHE_MAX_ENTRIES {
      let suffix = index.to_string();
      assert_ne!(
        cache
          .insert(
            cache_key(&identity, generations, &suffix),
            cache_value(&suffix, 0),
          )
          .unwrap(),
        CacheAdmission::NotAdmittedOversize
      );
    }
    assert_eq!(cache.len(), DECISION_CACHE_MAX_ENTRIES);
    assert!(cache.get_cloned(&first_key, 0).is_none());
    let newest = cache_key(
      &identity,
      generations,
      &DECISION_CACHE_MAX_ENTRIES.to_string(),
    );
    assert!(cache.get_cloned(&newest, 0).is_some());
    assert!(cache.total_weight_bytes() <= DECISION_CACHE_MAX_WEIGHT_BYTES);
  }

  #[test]
  fn lru_touch_and_full_value_survive_while_the_middle_entry_evicts() {
    let identity = identity();
    let generations = RuntimeGenerationVector::initial();
    let mut cache = DecisionCache::with_limits(DecisionCacheLimits::for_test(
      2,
      1024 * 1024,
      512 * 1024,
    ));
    let one = cache_key(&identity, generations, "one");
    let two = cache_key(&identity, generations, "two");
    let three = cache_key(&identity, generations, "three");
    let (one_value, _, _) =
      DecisionCache::prepare_entry(&one, cache_value("one", 17)).unwrap();
    let (three_value, _, _) =
      DecisionCache::prepare_entry(&three, cache_value("three", 31)).unwrap();

    cache.insert(one.clone(), one_value.clone()).unwrap();
    cache.insert(two.clone(), cache_value("two", 23)).unwrap();
    assert_eq!(
      cache.get_cloned(&one, 0).unwrap().dimensions(),
      one_value.dimensions()
    );
    cache.insert(three.clone(), three_value.clone()).unwrap();

    assert!(cache.get_cloned(&two, 0).is_none());
    assert_eq!(cache.get_cloned(&one, 0).unwrap(), one_value);
    assert_eq!(cache.get_cloned(&three, 0).unwrap(), three_value);
  }

  #[test]
  fn entry_and_total_weight_bounds_never_admit_partial_values() {
    let identity = identity();
    let generations = RuntimeGenerationVector::initial();
    let key = cache_key(&identity, generations, "oversize");
    let value = cache_value("oversize", DECISION_CACHE_MAX_ENTRY_WEIGHT_BYTES);
    let mut production = DecisionCache::new();
    assert_eq!(
      production.insert(key, value).unwrap(),
      CacheAdmission::NotAdmittedOversize
    );
    assert_eq!(production.len(), 0);
    assert_eq!(production.total_weight_bytes(), 0);

    let first_key = cache_key(&identity, generations, "first-weight");
    let second_key = cache_key(&identity, generations, "second-weight");
    let first_value = cache_value("first-weight", 64);
    let second_value = cache_value("second-weight", 64);
    let (_, _, first_weight) =
      DecisionCache::prepare_entry(&first_key, first_value.clone()).unwrap();
    let (_, _, second_weight) =
      DecisionCache::prepare_entry(&second_key, second_value.clone()).unwrap();
    let total_limit = first_weight + second_weight - 1;
    let mut bounded = DecisionCache::with_limits(
      DecisionCacheLimits::for_test(8, total_limit, total_limit),
    );
    bounded.insert(first_key.clone(), first_value).unwrap();
    bounded.insert(second_key.clone(), second_value).unwrap();
    assert_eq!(bounded.len(), 1);
    assert!(bounded.get_cloned(&first_key, 0).is_none());
    assert!(bounded.get_cloned(&second_key, 0).is_some());
    assert!(bounded.total_weight_bytes() <= total_limit);
  }

  #[test]
  fn deadline_expiry_removes_the_complete_cached_value() {
    let identity = identity();
    let generations = RuntimeGenerationVector::initial();
    let key = cache_key(&identity, generations, "deadline");
    let value = DecisionCacheValue::new(
      CachedDecision::Allow,
      vec![
        DecisionDimension::new(
          "slot-deadline".to_string(),
          principal(),
          CachedDecision::Allow,
          Some(positive_source("deadline", 0)),
        )
        .unwrap(),
      ],
      digest(b'N'),
      Some(10),
    )
    .unwrap();
    let mut cache = DecisionCache::new();
    cache.insert(key.clone(), value).unwrap();
    assert!(cache.get_cloned(&key, 9).is_some());
    assert!(cache.get_cloned(&key, 10).is_none());
    assert_eq!(cache.len(), 0);
    assert_eq!(cache.total_weight_bytes(), 0);
  }

  #[test]
  fn receipt_deadline_bounds_admission_and_independently_expires_lookup() {
    let key = DecisionCacheKey::new(
      "permission-query".to_string(),
      "edge-receipt-deadline".to_string(),
      "initial".to_string(),
      RuntimeAuthorityMode::Enforce,
      identity(),
      RuntimeGenerationVector::initial(),
      vec![principal()],
      principal(),
      vec![effect("receipt-deadline")],
      vec![
        ReceiptDependency::new("later".to_string(), 1, 2, 20).unwrap(),
        ReceiptDependency::new("earlier".to_string(), 1, 2, 10).unwrap(),
      ],
    )
    .unwrap();
    let value = DecisionCacheValue::new(
      CachedDecision::Allow,
      vec![
        DecisionDimension::new(
          "slot-receipt-deadline".to_string(),
          principal(),
          CachedDecision::Allow,
          Some(positive_source("receipt-deadline", 0)),
        )
        .unwrap(),
      ],
      digest(b'N'),
      Some(50),
    )
    .unwrap();
    let mut cache = DecisionCache::new();
    cache.insert(key.clone(), value).unwrap();
    assert_eq!(
      cache.entries.get(&key).unwrap().value.valid_until_monotonic,
      Some(CanonicalGeneration(10))
    );
    assert!(cache.get_cloned(&key, 9).is_some());

    // Even a retained value with its derived deadline accidentally removed is
    // not reusable after a key receipt dependency expires.
    cache
      .entries
      .get_mut(&key)
      .unwrap()
      .value
      .valid_until_monotonic = None;
    assert!(cache.get_cloned(&key, 10).is_none());
    assert_eq!(cache.len(), 0);
    assert_eq!(cache.total_weight_bytes(), 0);
  }
}

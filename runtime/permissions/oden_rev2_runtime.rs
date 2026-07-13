// Copyright 2018-2026 the Deno authors. MIT license.

//! Native-only Rev2 operation actors and the dormant Deno op binding.
//!
//! Nothing in this module is deserializable. JavaScript selects only an exact
//! host-bound native guard; the operation request, policy, actor, child-export
//! requiredness, provisional release hooks, and commit permit remain in Rust.
//! @ref LLP 0019#operation-scoped-positive-authority-provenance [implements]
//! @ref LLP 0019#stage-c-shared-core-implementation-checkpoint-eng-24015 [implements]

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::sync::atomic::Ordering;
use std::sync::atomic::compiler_fence;

use serde_json::Value;

use crate::PermissionCheckError;
use crate::PermissionDeniedError;
use crate::PermissionState;
use crate::oden_rev2_context::OdenRev2FilesystemDeliveryWitness;
use crate::oden_rev2_context::OdenRev2FilesystemNativeCommitWitness;
use crate::oden_rev2_fs::OdenRev2FsActorInventory;
use crate::oden_rev2_fs::OdenRev2FsActorOperation;
use crate::oden_rev2_fs::OdenRev2FsCheckedTargetKind;
use crate::oden_rev2_fs::OdenRev2FsMetadataObservation;
use crate::oden_rev2_fs::OdenRev2FsMkdirCommitOutcome;
use crate::oden_rev2_fs::OdenRev2FsOperationSession;
use crate::rev2::CapturedOperationContext;
use crate::rev2::CommitPermit;
use crate::rev2::CommitResult;
use crate::rev2::CoreError;
use crate::rev2::DecisionPolicyInput;
use crate::rev2::EffectInput;
use crate::rev2::Interaction;
use crate::rev2::OperationBarrier;
use crate::rev2::OperationReleaseEvidence;
use crate::rev2::Outcome;
use crate::rev2::PrincipalRef;
use crate::rev2::ProvisionalResources;
use crate::rev2::Rev2Core;
use crate::rev2::SealedChildExportFact;
use crate::rev2::StageAuthorization;
use crate::rev2::StageDecision;
use crate::rev2::StageRequest;
use crate::rev2::StagedOperation;
use crate::rev2::StructuredDenial;

const PROTECTED_INSPECTOR_EDGE: &str =
  "native-op:runtime/ops/oden.rs#op_oden_check_protected_inspector_stream_use";
const PROTECTED_INSPECTOR_SLOT: &str = "native-op:runtime/ops/oden.rs#op_oden_check_protected_inspector_stream_use:effect-slot:0";
const PROTECTED_INSPECTOR_CAPABILITY: &str = "inspector:activate";
const MAX_HOST_CHILD_EXPORTS: usize = 256;
const MAX_HOST_CHILD_EXPORT_NAME_BYTES: usize = 1_024;
const MAX_HOST_CHILD_EXPORT_VALUE_BYTES: usize = 256 * 1024;
const MAX_HOST_LAUNCH_PAYLOAD_BYTES: usize = 1024 * 1024;

/// Requiredness is captured by trusted launch construction, never copied from
/// a child-export occurrence supplied by caller bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OdenRev2RequiredForCommit {
  Optional,
  Required,
}

impl OdenRev2RequiredForCommit {
  fn as_bool(self) -> bool {
    self == Self::Required
  }
}

/// Closed set of generated edges that already declare the trusted masked
/// child-export contract. `op_spawn_sync` intentionally has no variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OdenRev2HostSpawnEdge {
  DenoSpawnChild,
  NodeSpawnChild,
  DeprecatedRun,
}

impl OdenRev2HostSpawnEdge {
  fn edge_id(self) -> &'static str {
    match self {
      Self::DenoSpawnChild => "native-op:ext/process/lib.rs#op_spawn_child",
      Self::NodeSpawnChild => {
        "native-op:ext/process/lib.rs#op_node_spawn_child"
      }
      Self::DeprecatedRun => "native-op:ext/process/lib.rs#op_run",
    }
  }

  fn env_read_slot(self) -> String {
    format!("{}:effect-slot:1", self.edge_id())
  }

  fn env_write_slot(self) -> String {
    format!("{}:effect-slot:2", self.edge_id())
  }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OdenRev2HostChildExportKind {
  BrokerRead,
  PrincipalOverlayRead,
  LiteralWrite,
}

/// Scoped owner used while a plaintext value is still being validated. Every
/// fallible constructor path drops this guard; successful construction moves
/// the allocation into the longer-lived secret-bearing wrapper.
struct OdenRev2SecretString(String);

impl OdenRev2SecretString {
  fn new(value: String) -> Self {
    Self(value)
  }

  fn get(&self) -> &str {
    &self.0
  }

  fn take(&mut self) -> String {
    std::mem::take(&mut self.0)
  }
}

impl Drop for OdenRev2SecretString {
  fn drop(&mut self) {
    best_effort_zeroize_string(&mut self.0);
    #[cfg(test)]
    ODEN_REV2_SECRET_GUARD_DROPS.with(|drops| drops.set(drops.get() + 1));
  }
}

#[cfg(test)]
std::thread_local! {
  static ODEN_REV2_SECRET_GUARD_DROPS: std::cell::Cell<usize> = const {
    std::cell::Cell::new(0)
  };
}

#[cfg(test)]
fn secret_guard_drop_count() -> usize {
  ODEN_REV2_SECRET_GUARD_DROPS.with(std::cell::Cell::get)
}

/// One host-sealed child export. Private fields and the absence of serde
/// implementations keep this outside every JS/oracle wire shape.
pub struct OdenRev2HostChildExport {
  edge: OdenRev2HostSpawnEdge,
  kind: OdenRev2HostChildExportKind,
  effect: EffectInput,
  value: String,
}

impl Drop for OdenRev2HostChildExport {
  fn drop(&mut self) {
    best_effort_zeroize_string(&mut self.value);
  }
}

impl std::fmt::Debug for OdenRev2HostChildExport {
  fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    formatter
      .debug_struct("OdenRev2HostChildExport")
      .field("edge", &self.edge)
      .field("kind", &self.kind)
      .field("effect", &self.effect)
      .field("value", &"<redacted>")
      .finish()
  }
}

impl OdenRev2HostChildExport {
  pub fn capture_broker_env_read_host(
    edge: OdenRev2HostSpawnEdge,
    effect_owner: impl Into<String>,
    owner_generation: impl Into<String>,
    name: impl Into<String>,
    value: impl Into<String>,
    requiredness: OdenRev2RequiredForCommit,
  ) -> Result<Self, OdenRev2HostError> {
    Self::capture_env_read_host(
      edge,
      OdenRev2HostChildExportKind::BrokerRead,
      effect_owner,
      owner_generation,
      name,
      value,
      requiredness,
    )
  }

  pub fn capture_principal_overlay_env_read_host(
    edge: OdenRev2HostSpawnEdge,
    effect_owner: impl Into<String>,
    owner_generation: impl Into<String>,
    name: impl Into<String>,
    value: impl Into<String>,
    requiredness: OdenRev2RequiredForCommit,
  ) -> Result<Self, OdenRev2HostError> {
    Self::capture_env_read_host(
      edge,
      OdenRev2HostChildExportKind::PrincipalOverlayRead,
      effect_owner,
      owner_generation,
      name,
      value,
      requiredness,
    )
  }

  #[allow(clippy::too_many_arguments)]
  fn capture_env_read_host(
    edge: OdenRev2HostSpawnEdge,
    kind: OdenRev2HostChildExportKind,
    effect_owner: impl Into<String>,
    owner_generation: impl Into<String>,
    name: impl Into<String>,
    value: impl Into<String>,
    requiredness: OdenRev2RequiredForCommit,
  ) -> Result<Self, OdenRev2HostError> {
    let value = OdenRev2SecretString::new(value.into());
    let effect_owner = effect_owner.into();
    let owner_generation = owner_generation.into();
    let name = name.into();
    let target_kind = match kind {
      OdenRev2HostChildExportKind::BrokerRead => "broker",
      OdenRev2HostChildExportKind::PrincipalOverlayRead => "principal-overlay",
      OdenRev2HostChildExportKind::LiteralWrite => unreachable!(),
    };
    Self::capture_prepared_host(
      edge,
      kind,
      EffectInput {
        identity: crate::rev2::EngineIdentity::embedded(),
        edge_id: edge.edge_id().to_string(),
        effect_slot_id: edge.env_read_slot(),
        capability: "env:read".to_string(),
        effect_owner: effect_owner.clone(),
        occurrence: serde_json::json!({
          "effectOwner": effect_owner,
          "name": name,
          "ownerGeneration": owner_generation,
          "targetKind": target_kind,
        }),
      },
      value,
      requiredness,
    )
  }

  pub fn capture_literal_env_write_host(
    edge: OdenRev2HostSpawnEdge,
    effect_owner: impl Into<String>,
    owner_generation: impl Into<String>,
    name: impl Into<String>,
    value: impl Into<String>,
  ) -> Result<Self, OdenRev2HostError> {
    let value = OdenRev2SecretString::new(value.into());
    let effect_owner = effect_owner.into();
    let owner_generation = owner_generation.into();
    let name = name.into();
    Self::capture_prepared_host(
      edge,
      OdenRev2HostChildExportKind::LiteralWrite,
      EffectInput {
        identity: crate::rev2::EngineIdentity::embedded(),
        edge_id: edge.edge_id().to_string(),
        effect_slot_id: edge.env_write_slot(),
        capability: "env:write".to_string(),
        effect_owner: effect_owner.clone(),
        occurrence: serde_json::json!({
          "effectOwner": effect_owner,
          "name": name,
          "ownerGeneration": owner_generation,
          "targetId": "child:launch",
          "targetKind": "child-launch",
        }),
      },
      value,
      OdenRev2RequiredForCommit::Optional,
    )
  }

  fn capture_prepared_host(
    edge: OdenRev2HostSpawnEdge,
    kind: OdenRev2HostChildExportKind,
    mut effect: EffectInput,
    mut value: OdenRev2SecretString,
    requiredness: OdenRev2RequiredForCommit,
  ) -> Result<Self, OdenRev2HostError> {
    let occurrence = effect
      .occurrence
      .as_object_mut()
      .ok_or(OdenRev2HostError::InvalidChildExport)?;
    if occurrence.contains_key("requiredForCommit") {
      return Err(OdenRev2HostError::UntrustedRequiredForCommit);
    }
    let expected_keys: &[&str] = match kind {
      OdenRev2HostChildExportKind::BrokerRead
      | OdenRev2HostChildExportKind::PrincipalOverlayRead => {
        &["effectOwner", "name", "ownerGeneration", "targetKind"]
      }
      OdenRev2HostChildExportKind::LiteralWrite => &[
        "effectOwner",
        "name",
        "ownerGeneration",
        "targetId",
        "targetKind",
      ],
    };
    let owner_generation = occurrence
      .get("ownerGeneration")
      .and_then(Value::as_str)
      .ok_or(OdenRev2HostError::InvalidChildExport)?;
    let valid_generation = owner_generation
      .parse::<u64>()
      .is_ok_and(|value| value.to_string() == owner_generation);
    let (expected_slot, expected_capability, expected_target_kind) = match kind
    {
      OdenRev2HostChildExportKind::BrokerRead => {
        (edge.env_read_slot(), "env:read", "broker")
      }
      OdenRev2HostChildExportKind::PrincipalOverlayRead => {
        (edge.env_read_slot(), "env:read", "principal-overlay")
      }
      OdenRev2HostChildExportKind::LiteralWrite => {
        (edge.env_write_slot(), "env:write", "child-launch")
      }
    };
    let name = occurrence
      .get("name")
      .and_then(Value::as_str)
      .ok_or(OdenRev2HostError::InvalidChildExport)?;
    if effect.identity != crate::rev2::EngineIdentity::embedded()
      || effect.edge_id != edge.edge_id()
      || effect.effect_slot_id != expected_slot
      || effect.capability != expected_capability
      || effect.effect_owner.trim().is_empty()
      || effect.effect_owner.len() > 1024
      || !valid_env_name(name)
      || !valid_env_value(value.get())
      || occurrence.len() != expected_keys.len()
      || expected_keys
        .iter()
        .any(|key| !occurrence.contains_key(*key))
      || occurrence.get("effectOwner").and_then(Value::as_str)
        != Some(effect.effect_owner.as_str())
      || occurrence.get("targetKind").and_then(Value::as_str)
        != Some(expected_target_kind)
      || (kind == OdenRev2HostChildExportKind::LiteralWrite
        && occurrence.get("targetId").and_then(Value::as_str)
          != Some("child:launch"))
      || !valid_generation
    {
      return Err(OdenRev2HostError::InvalidChildExport);
    }
    if kind != OdenRev2HostChildExportKind::LiteralWrite {
      occurrence.insert(
        "requiredForCommit".to_string(),
        Value::Bool(requiredness.as_bool()),
      );
    }
    Ok(Self {
      edge,
      kind,
      effect,
      value: value.take(),
    })
  }
}

fn valid_env_name(name: &str) -> bool {
  !name.is_empty()
    && name.len() <= MAX_HOST_CHILD_EXPORT_NAME_BYTES
    && !name.as_bytes().contains(&0)
    && !name.as_bytes().contains(&b'=')
}

fn valid_env_value(value: &str) -> bool {
  value.len() <= MAX_HOST_CHILD_EXPORT_VALUE_BYTES
    && !value.as_bytes().contains(&0)
}

/// Best-effort in-place scrubbing for the one owned String allocation visible
/// here. Volatile byte stores plus a compiler fence prevent this overwrite
/// from being optimized away. Zero bytes are valid UTF-8, so the String stays
/// valid until its ordinary destructor releases the allocation. This cannot
/// erase allocator copies, earlier clones, registers, or kernel buffers.
fn best_effort_zeroize_string(value: &mut String) {
  // SAFETY: `String::as_mut_vec` is safe to use only while preserving UTF-8.
  // Replacing every initialized byte with zero preserves both length/capacity
  // and UTF-8 validity. No reference into `value` survives this function.
  let bytes = unsafe { value.as_mut_vec() };
  for byte in bytes {
    // SAFETY: `byte` is a live, uniquely borrowed initialized byte in the
    // String allocation above.
    unsafe { std::ptr::write_volatile(byte, 0) };
  }
  compiler_fence(Ordering::SeqCst);
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OdenRev2EnvNamePlatform {
  Posix,
  Windows,
}

impl OdenRev2EnvNamePlatform {
  fn current() -> Self {
    if cfg!(windows) {
      Self::Windows
    } else {
      Self::Posix
    }
  }
}

fn env_name_collision_key(
  name: &str,
  platform: OdenRev2EnvNamePlatform,
) -> String {
  match platform {
    OdenRev2EnvNamePlatform::Posix => name.to_string(),
    OdenRev2EnvNamePlatform::Windows => name.to_ascii_uppercase(),
  }
}

/// Exact encoded bytes contributed by one target environment entry. POSIX
/// uses UTF-8 `name=value\0`; Windows uses UTF-16LE `name=value\0`, so its
/// trusted launch budget is also expressed in encoded bytes. The separate
/// target budget is responsible for the Windows whole-block or POSIX ARG_MAX
/// reserve that applies at the actual launch site.
fn encoded_env_entry_bytes(
  name: &str,
  value: &str,
  platform: OdenRev2EnvNamePlatform,
) -> Option<usize> {
  match platform {
    OdenRev2EnvNamePlatform::Posix => {
      name.len().checked_add(value.len())?.checked_add(2)
    }
    OdenRev2EnvNamePlatform::Windows => name
      .encode_utf16()
      .count()
      .checked_add(value.encode_utf16().count())?
      .checked_add(2)?
      .checked_mul(2),
  }
}

/// Closed host-only launch seal. This remains dormant until the complete
/// process-spawn launch set is integrated under ENG-24022.
#[derive(Debug)]
pub struct OdenRev2HostLaunchSeal {
  edge_id: String,
  exports: Vec<OdenRev2HostChildExport>,
  payload_bytes: usize,
}

impl OdenRev2HostLaunchSeal {
  pub fn capture_spawn_host(
    edge: OdenRev2HostSpawnEdge,
    exports: Vec<OdenRev2HostChildExport>,
    trusted_target_launch_budget_bytes: usize,
  ) -> Result<Self, OdenRev2HostError> {
    let mut names = BTreeSet::new();
    if exports.len() > MAX_HOST_CHILD_EXPORTS
      || exports.iter().any(|export| export.edge != edge)
    {
      return Err(OdenRev2HostError::InvalidLaunchSeal);
    }
    let mut payload_bytes = 0usize;
    for export in &exports {
      let Some(name) =
        export.effect.occurrence.get("name").and_then(Value::as_str)
      else {
        return Err(OdenRev2HostError::InvalidLaunchSeal);
      };
      let name_key =
        env_name_collision_key(name, OdenRev2EnvNamePlatform::current());
      if !names.insert(name_key) {
        return Err(OdenRev2HostError::InvalidLaunchSeal);
      }
      let sealed_shape_matches = match export.kind {
        OdenRev2HostChildExportKind::BrokerRead
        | OdenRev2HostChildExportKind::PrincipalOverlayRead => export
          .effect
          .occurrence
          .get("requiredForCommit")
          .is_some_and(Value::is_boolean),
        OdenRev2HostChildExportKind::LiteralWrite => {
          export.effect.occurrence.get("requiredForCommit").is_none()
        }
      };
      let encoded_entry_bytes = encoded_env_entry_bytes(
        name,
        &export.value,
        OdenRev2EnvNamePlatform::current(),
      )
      .ok_or(OdenRev2HostError::InvalidLaunchSeal)?;
      payload_bytes = payload_bytes
        .checked_add(encoded_entry_bytes)
        .ok_or(OdenRev2HostError::InvalidLaunchSeal)?;
      if !valid_env_name(name)
        || !valid_env_value(&export.value)
        || !sealed_shape_matches
        || payload_bytes > MAX_HOST_LAUNCH_PAYLOAD_BYTES
        || payload_bytes > trusted_target_launch_budget_bytes
      {
        return Err(OdenRev2HostError::InvalidLaunchSeal);
      }
    }
    Ok(Self {
      edge_id: edge.edge_id().to_string(),
      exports,
      payload_bytes,
    })
  }

  fn commit_plan(
    &self,
    core: &Rev2Core,
    decision: &StageDecision,
  ) -> Result<Vec<bool>, OdenRev2HostError> {
    if decision.outcome != Outcome::Allow {
      return Err(OdenRev2HostError::InvalidLaunchDecision);
    }
    let repeatable_decisions = decision
      .effects
      .iter()
      .filter(|effect| {
        effect.effect.edge_id == self.edge_id
          && (effect.effect.effect_slot_id.ends_with(":effect-slot:1")
            || effect.effect.effect_slot_id.ends_with(":effect-slot:2"))
      })
      .collect::<Vec<_>>();
    if repeatable_decisions.len() != self.exports.len() {
      return Err(OdenRev2HostError::InvalidLaunchDecision);
    }

    let mut plan = Vec::with_capacity(self.exports.len());
    for export in &self.exports {
      let canonical = core.normalize_effect(&export.effect)?;
      if !repeatable_decisions
        .iter()
        .any(|effect| effect.effect == canonical)
      {
        return Err(OdenRev2HostError::InvalidLaunchDecision);
      }
      let committed = decision
        .committed_effects
        .iter()
        .filter(|effect| **effect == canonical)
        .count();
      let omitted = decision
        .omitted_effects
        .iter()
        .filter(|omission| omission.effect == canonical)
        .count();
      match (committed, omitted) {
        (1, 0) => plan.push(true),
        (0, 1)
          if matches!(
            export.kind,
            OdenRev2HostChildExportKind::BrokerRead
              | OdenRev2HostChildExportKind::PrincipalOverlayRead
          ) && export
            .effect
            .occurrence
            .get("requiredForCommit")
            .and_then(Value::as_bool)
            == Some(false) =>
        {
          plan.push(false);
        }
        _ => return Err(OdenRev2HostError::InvalidLaunchDecision),
      }
    }
    Ok(plan)
  }

  fn into_committed_payload(
    self,
    included: Vec<bool>,
  ) -> Result<OdenRev2CommittedLaunchPayload, OdenRev2HostError> {
    if included.len() != self.exports.len() {
      return Err(OdenRev2HostError::InvalidLaunchDecision);
    }
    let mut entries = Vec::with_capacity(self.exports.len());
    let mut payload_bytes = 0usize;
    for (mut export, include) in self.exports.into_iter().zip(included) {
      if !include {
        continue;
      }
      let name = export
        .effect
        .occurrence
        .get("name")
        .and_then(Value::as_str)
        .ok_or(OdenRev2HostError::InvalidLaunchDecision)?
        .to_string();
      let encoded_entry_bytes = encoded_env_entry_bytes(
        &name,
        &export.value,
        OdenRev2EnvNamePlatform::current(),
      )
      .ok_or(OdenRev2HostError::InvalidLaunchDecision)?;
      payload_bytes = payload_bytes
        .checked_add(encoded_entry_bytes)
        .ok_or(OdenRev2HostError::InvalidLaunchDecision)?;
      entries.push(OdenRev2CommittedLaunchEntry {
        name,
        value: std::mem::take(&mut export.value),
      });
    }
    if payload_bytes > self.payload_bytes {
      return Err(OdenRev2HostError::InvalidLaunchDecision);
    }
    Ok(OdenRev2CommittedLaunchPayload {
      edge_id: self.edge_id,
      entries,
      payload_bytes,
    })
  }
}

/// A host-only environment entry released by exactly one successful launch
/// commit. It intentionally has no serde, Clone, Display, or value-bearing
/// Debug implementation.
pub struct OdenRev2CommittedLaunchEntry {
  name: String,
  value: String,
}

impl Drop for OdenRev2CommittedLaunchEntry {
  fn drop(&mut self) {
    best_effort_zeroize_string(&mut self.value);
  }
}

impl std::fmt::Debug for OdenRev2CommittedLaunchEntry {
  fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    formatter
      .debug_struct("OdenRev2CommittedLaunchEntry")
      .field("name", &self.name)
      .field("value", &"<redacted>")
      .finish()
  }
}

impl OdenRev2CommittedLaunchEntry {
  pub fn name(&self) -> &str {
    &self.name
  }

  pub fn value(&self) -> &str {
    &self.value
  }

  pub fn into_name_value(mut self) -> (String, String) {
    (
      std::mem::take(&mut self.name),
      std::mem::take(&mut self.value),
    )
  }
}

/// The filtered launch environment produced from the exact committed Rev2
/// decision. Optional masked entries are absent; values never enter an oracle
/// or serializable type.
pub struct OdenRev2CommittedLaunchPayload {
  edge_id: String,
  entries: Vec<OdenRev2CommittedLaunchEntry>,
  payload_bytes: usize,
}

impl std::fmt::Debug for OdenRev2CommittedLaunchPayload {
  fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    formatter
      .debug_struct("OdenRev2CommittedLaunchPayload")
      .field("edge_id", &self.edge_id)
      .field("entries", &self.entries)
      .field("payload_bytes", &self.payload_bytes)
      .finish()
  }
}

impl OdenRev2CommittedLaunchPayload {
  pub fn edge_id(&self) -> &str {
    &self.edge_id
  }

  pub fn entries(&self) -> &[OdenRev2CommittedLaunchEntry] {
    &self.entries
  }

  pub fn into_entries(self) -> Vec<OdenRev2CommittedLaunchEntry> {
    self.entries
  }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OdenRev2HostInteraction {
  NonInteractive,
  MayPrompt,
}

impl From<OdenRev2HostInteraction> for Interaction {
  fn from(value: OdenRev2HostInteraction) -> Self {
    match value {
      OdenRev2HostInteraction::NonInteractive => Self::NonInteractive,
      OdenRev2HostInteraction::MayPrompt => Self::MayPrompt,
    }
  }
}

#[derive(Debug, thiserror::Error)]
pub enum OdenRev2HostError {
  #[error(transparent)]
  Core(#[from] CoreError),
  #[error(
    "child-export requiredForCommit must originate in trusted host state"
  )]
  UntrustedRequiredForCommit,
  #[error("child-export occurrence is not a host-sealable object")]
  InvalidChildExport,
  #[error(
    "host launch seal is invalid, oversized, over budget, or edge-inconsistent"
  )]
  InvalidLaunchSeal,
  #[error("committed decision does not exactly classify the host launch seal")]
  InvalidLaunchDecision,
  #[error("provisional resource identity is empty, oversized, or duplicated")]
  InvalidProvisionalResource,
  #[error(
    "filesystem provisional inventory is missing, invalid, or used by the wrong actor kind"
  )]
  InvalidFilesystemInventory,
  #[error("the operation has no host-retained commit permit")]
  NoPendingPermit,
  #[error("operation stages were invoked out of order")]
  InvalidStageOrder,
  #[error(
    "operation completion is not covered by the immediately preceding commit"
  )]
  IncompleteOperation,
  #[error("a native stage is already bound")]
  NativeStageAlreadyBound,
  #[error("native stage does not implement the exact protected-inspector edge")]
  InvalidNativeStage,
  #[error("the armed Rev2 context has no operation actor")]
  MissingNativeActor,
  #[error("no native stage is bound for this exact target and API")]
  NativeStageMismatch,
  #[error("live op/CPED principals do not match the captured operation actor")]
  LivePrincipalMismatch,
  #[error("Rev2 authorization did not commit: {0}")]
  AuthorizationRejected(String),
}

type ReleaseHook = Box<dyn FnOnce() + 'static>;

#[derive(Default)]
struct OdenRev2CallbackResources {
  held: BTreeMap<String, ReleaseHook>,
  released: Vec<String>,
}

impl OdenRev2CallbackResources {
  fn hold(
    &mut self,
    id: impl Into<String>,
    release: impl FnOnce() + 'static,
  ) -> Result<(), OdenRev2HostError> {
    let id = id.into();
    if id.trim().is_empty() || id.len() > 1024 || self.held.contains_key(&id) {
      return Err(OdenRev2HostError::InvalidProvisionalResource);
    }
    self.held.insert(id, Box::new(release));
    Ok(())
  }

  fn disarm_all(&mut self) -> Vec<String> {
    std::mem::take(&mut self.held).into_keys().collect()
  }
}

impl ProvisionalResources for OdenRev2CallbackResources {
  fn held_ids(&self) -> Vec<String> {
    self.held.keys().cloned().collect()
  }

  fn release_all(&mut self) -> Vec<String> {
    let held = std::mem::take(&mut self.held);
    let mut released = Vec::with_capacity(held.len());
    for (id, release) in held {
      release();
      released.push(id);
    }
    self.released.extend(released.iter().cloned());
    released
  }
}

impl Drop for OdenRev2CallbackResources {
  fn drop(&mut self) {
    let _ = self.release_all();
  }
}

enum OdenRev2HostResources {
  Callbacks(OdenRev2CallbackResources),
  Filesystem(Box<OdenRev2FsActorInventory>),
}

impl Default for OdenRev2HostResources {
  fn default() -> Self {
    Self::Callbacks(OdenRev2CallbackResources::default())
  }
}

impl OdenRev2HostResources {
  fn hold(
    &mut self,
    id: impl Into<String>,
    release: impl FnOnce() + 'static,
  ) -> Result<(), OdenRev2HostError> {
    match self {
      Self::Callbacks(resources) => resources.hold(id, release),
      Self::Filesystem(_) => Err(OdenRev2HostError::InvalidFilesystemInventory),
    }
  }

  fn disarm_callbacks(&mut self) -> Result<Vec<String>, OdenRev2HostError> {
    match self {
      Self::Callbacks(resources) => Ok(resources.disarm_all()),
      Self::Filesystem(_) => Err(OdenRev2HostError::InvalidFilesystemInventory),
    }
  }

  fn filesystem(&self) -> Result<&OdenRev2FsActorInventory, OdenRev2HostError> {
    match self {
      Self::Filesystem(resources) if resources.is_intact() => Ok(resources),
      Self::Callbacks(_) | Self::Filesystem(_) => {
        Err(OdenRev2HostError::InvalidFilesystemInventory)
      }
    }
  }

  fn filesystem_mut(
    &mut self,
  ) -> Result<&mut OdenRev2FsActorInventory, OdenRev2HostError> {
    match self {
      Self::Filesystem(resources) if resources.is_intact() => Ok(resources),
      Self::Callbacks(_) | Self::Filesystem(_) => {
        Err(OdenRev2HostError::InvalidFilesystemInventory)
      }
    }
  }

  fn take_filesystem(
    &mut self,
  ) -> Result<OdenRev2FsActorInventory, OdenRev2HostError> {
    let resources = std::mem::take(self);
    match resources {
      Self::Filesystem(resources) if resources.is_intact() => Ok(*resources),
      Self::Callbacks(_) | Self::Filesystem(_) => {
        Err(OdenRev2HostError::InvalidFilesystemInventory)
      }
    }
  }
}

impl ProvisionalResources for OdenRev2HostResources {
  fn held_ids(&self) -> Vec<String> {
    match self {
      Self::Callbacks(resources) => resources.held_ids(),
      Self::Filesystem(resources) => resources.held_ids(),
    }
  }

  fn release_all(&mut self) -> Vec<String> {
    match self {
      Self::Callbacks(resources) => resources.release_all(),
      Self::Filesystem(resources) => resources.release_all(),
    }
  }
}

/// Opaque owner transferred out of a successfully completed filesystem actor.
/// Dropping this value closes every operation-local checked/source handle.
///
/// @ref LLP 0019#filesystem-actor-resource-ownership-checkpoint-eng-24019
/// [implements]
pub(crate) struct OdenRev2HostFilesystemCompletion {
  _resources: OdenRev2FsActorInventory,
  _not_send_sync: std::marker::PhantomData<std::rc::Rc<()>>,
}

pub(crate) struct OdenRev2FilesystemPendingWitness {
  _private: (),
}

pub(crate) struct OdenRev2FilesystemCommittedWitness {
  _private: (),
}

#[cfg(test)]
impl OdenRev2FilesystemPendingWitness {
  pub(crate) fn for_test() -> Self {
    Self { _private: () }
  }
}

/// Filesystem-only HostActor facade. Its closed method set deliberately omits
/// callback registration and nonterminal cleanup, so neither can run while a
/// namespace operation owns checked filesystem resources.
///
/// @ref LLP 0019#filesystem-actor-resource-ownership-checkpoint-eng-24019
/// [implements]
pub(crate) struct OdenRev2FilesystemHostActor {
  inner: OdenRev2HostActor,
  operation: OdenRev2FsActorOperation,
  initial_target: OdenRev2FsCheckedTargetKind,
  bound_request: StageRequest,
  phase: OdenRev2FilesystemActorPhase,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OdenRev2FilesystemActorPhase {
  AwaitingAuthorization,
  Pending {
    sources_validated: bool,
    target_validated: bool,
    prepared: bool,
    observed: bool,
  },
  CoreCommitted,
  NativeCommitted,
  Terminal,
}

#[cfg(all(test, unix))]
impl OdenRev2HostFilesystemCompletion {
  pub(crate) fn provisional_weak_handles(
    &self,
  ) -> Vec<std::sync::Weak<std::fs::File>> {
    self._resources.provisional_weak_handles()
  }
}

struct OdenRev2PendingCommit {
  request: StageRequest,
  permit: CommitPermit,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OdenRev2ActorPhase {
  AwaitingInitial,
  Discovery,
  Terminal,
}

/// Sanitized authorization outcome. The commit permit is deliberately absent:
/// it is retained inside `OdenRev2HostActor` and has no deserializer in the
/// shared core.
#[derive(Debug, PartialEq, Eq)]
pub enum OdenRev2HostAuthorization {
  Authorized {
    actor_digest: String,
    decision: StageDecision,
  },
  Masked {
    decision: StageDecision,
    released_provisional_resources: Vec<String>,
  },
  Denied(StructuredDenial),
  RestartRequired(StructuredDenial),
  AlreadyDenied {
    terminal_evidence_id: String,
  },
}

#[derive(Debug)]
pub enum OdenRev2HostCommit {
  Committed {
    stage_id: String,
    actor_digest: String,
    launch_payload: Option<OdenRev2CommittedLaunchPayload>,
  },
  Denied(StructuredDenial),
  AlreadyDenied {
    terminal_evidence_id: String,
  },
}

/// A generic native operation actor. It owns the shared core state machine,
/// provisional release hooks, and the one-shot permit between authorization
/// and the host's commit boundary.
pub struct OdenRev2HostActor {
  core: Rev2Core,
  operation: StagedOperation,
  resources: OdenRev2HostResources,
  pending: Option<OdenRev2PendingCommit>,
  captured_principals: Vec<PrincipalRef>,
  effect_owner_id: String,
  phase: OdenRev2ActorPhase,
  completion_inventory: Option<Vec<String>>,
  sealed_launch: Option<OdenRev2HostLaunchSeal>,
}

impl OdenRev2HostActor {
  #[allow(clippy::too_many_arguments)]
  pub fn capture_host(
    operation_id: impl Into<String>,
    actor_id: impl Into<String>,
    principals: Vec<PrincipalRef>,
    effect_owner_id: impl Into<String>,
    effect_owner_principal: PrincipalRef,
    effect_owner_generation: impl Into<String>,
    launch_seal: Option<OdenRev2HostLaunchSeal>,
    policy: &DecisionPolicyInput,
  ) -> Result<Self, OdenRev2HostError> {
    let core = Rev2Core::embedded()?;
    let mut captured_principals = principals.clone();
    captured_principals.sort();
    captured_principals.dedup();
    let effect_owner_id = effect_owner_id.into();
    let (sealed_child_exports, sealed_repeatable_edge_id, sealed_launch) =
      if let Some(seal) = launch_seal {
        (
          seal
            .exports
            .iter()
            .map(|export| {
              SealedChildExportFact::capture_host(export.effect.clone())
            })
            .collect(),
          Some(seal.edge_id.clone()),
          Some(seal),
        )
      } else {
        (Vec::new(), None, None)
      };
    let captured = CapturedOperationContext::capture_host(
      actor_id,
      core.identity(),
      principals,
      effect_owner_id.clone(),
      effect_owner_principal,
      effect_owner_generation,
      sealed_child_exports,
      sealed_repeatable_edge_id,
    )?;
    let operation =
      StagedOperation::new(&core, operation_id, captured, policy)?;
    Ok(Self {
      core,
      operation,
      resources: OdenRev2HostResources::default(),
      pending: None,
      captured_principals,
      effect_owner_id,
      phase: OdenRev2ActorPhase::AwaitingInitial,
      completion_inventory: None,
      sealed_launch,
    })
  }

  #[allow(clippy::too_many_arguments)]
  fn capture_filesystem_host(
    operation_id: impl Into<String>,
    actor_id: impl Into<String>,
    principals: Vec<PrincipalRef>,
    effect_owner_id: impl Into<String>,
    effect_owner_principal: PrincipalRef,
    effect_owner_generation: impl Into<String>,
    policy: &DecisionPolicyInput,
    filesystem_inventory: OdenRev2FsActorInventory,
  ) -> Result<Self, OdenRev2HostError> {
    let operation_id = operation_id.into();
    let actor_id = actor_id.into();
    if !filesystem_inventory.is_intact()
      || !filesystem_inventory.binds(&operation_id, &actor_id)
      || !filesystem_inventory.binds_policy(policy)
    {
      return Err(OdenRev2HostError::InvalidFilesystemInventory);
    }
    let mut actor = Self::capture_host(
      operation_id,
      actor_id,
      principals,
      effect_owner_id,
      effect_owner_principal,
      effect_owner_generation,
      None,
      policy,
    )?;
    actor.resources =
      OdenRev2HostResources::Filesystem(Box::new(filesystem_inventory));
    Ok(actor)
  }

  pub fn hold_provisional(
    &mut self,
    id: impl Into<String>,
    release: impl FnOnce() + 'static,
  ) -> Result<(), OdenRev2HostError> {
    self.completion_inventory = None;
    self.resources.hold(id, release)
  }

  fn require_pending_filesystem_stage(
    &mut self,
  ) -> Result<(), OdenRev2HostError> {
    if self.pending.is_some()
      && self.phase != OdenRev2ActorPhase::Terminal
      && self.completion_inventory.is_none()
      && self.sealed_launch.is_none()
      && self.resources.filesystem().is_ok()
    {
      Ok(())
    } else {
      self.terminalize();
      Err(OdenRev2HostError::InvalidStageOrder)
    }
  }

  fn require_committed_filesystem_stage(
    &mut self,
  ) -> Result<Vec<String>, OdenRev2HostError> {
    let current_inventory = self.resources.held_ids();
    if self.pending.is_none()
      && self.phase == OdenRev2ActorPhase::Discovery
      && self.completion_inventory.as_ref() == Some(&current_inventory)
      && self.sealed_launch.is_none()
      && self.resources.filesystem().is_ok()
    {
      Ok(current_inventory)
    } else {
      self.terminalize();
      Err(OdenRev2HostError::InvalidStageOrder)
    }
  }

  fn revalidate_filesystem_sources(
    &mut self,
    operation_session: &OdenRev2FsOperationSession,
  ) -> Result<(), OdenRev2HostError> {
    self.require_pending_filesystem_stage()?;
    let result = self.resources.filesystem().and_then(|inventory| {
      inventory
        .revalidate_sources(operation_session)
        .map_err(|_| OdenRev2HostError::InvalidFilesystemInventory)
    });
    if result.is_err() {
      self.terminalize();
    }
    result
  }

  fn revalidate_filesystem_target(
    &mut self,
    operation_session: &OdenRev2FsOperationSession,
  ) -> Result<(), OdenRev2HostError> {
    self.require_pending_filesystem_stage()?;
    let result = self.resources.filesystem().and_then(|inventory| {
      inventory
        .revalidate_target(operation_session)
        .map_err(|_| OdenRev2HostError::InvalidFilesystemInventory)
    });
    if result.is_err() {
      self.terminalize();
    }
    result
  }

  fn observe_filesystem_metadata(
    &mut self,
    operation_session: &OdenRev2FsOperationSession,
  ) -> Result<OdenRev2FsMetadataObservation, OdenRev2HostError> {
    self.require_pending_filesystem_stage()?;
    let witness = OdenRev2FilesystemPendingWitness { _private: () };
    let result = self.resources.filesystem().and_then(|inventory| {
      inventory
        .observe_metadata(operation_session, &witness)
        .map_err(|_| OdenRev2HostError::InvalidFilesystemInventory)
    });
    if result.is_err() {
      self.terminalize();
    }
    result
  }

  fn observe_filesystem_missing(
    &mut self,
    operation_session: &OdenRev2FsOperationSession,
  ) -> Result<(), OdenRev2HostError> {
    self.require_pending_filesystem_stage()?;
    let witness = OdenRev2FilesystemPendingWitness { _private: () };
    let result = self.resources.filesystem().and_then(|inventory| {
      inventory
        .observe_missing(operation_session, &witness)
        .map_err(|_| OdenRev2HostError::InvalidFilesystemInventory)
    });
    if result.is_err() {
      self.terminalize();
    }
    result
  }

  fn prepare_filesystem_mkdir(
    &mut self,
    operation_session: &OdenRev2FsOperationSession,
  ) -> Result<(), OdenRev2HostError> {
    self.require_pending_filesystem_stage()?;
    let before = self.resources.held_ids();
    let witness = OdenRev2FilesystemPendingWitness { _private: () };
    let result = self.resources.filesystem_mut().and_then(|inventory| {
      inventory
        .prepare_mkdir(operation_session, &witness)
        .map_err(|_| OdenRev2HostError::InvalidFilesystemInventory)
    });
    if result.is_err() || self.resources.held_ids() != before {
      self.terminalize();
      return Err(OdenRev2HostError::InvalidFilesystemInventory);
    }
    Ok(())
  }

  fn commit_filesystem_mkdir(
    &mut self,
    operation_session: &OdenRev2FsOperationSession,
    mode: u32,
    native_commit_witness: &OdenRev2FilesystemNativeCommitWitness<'_>,
  ) -> Result<OdenRev2FsMkdirCommitOutcome, OdenRev2HostError> {
    let before = self.require_committed_filesystem_stage()?;
    let witness = OdenRev2FilesystemCommittedWitness { _private: () };
    let outcome = self.resources.filesystem_mut()?.commit_mkdir(
      operation_session,
      mode,
      &witness,
      native_commit_witness,
    );
    if self.resources.held_ids() != before {
      self.terminalize();
      return Err(OdenRev2HostError::InvalidFilesystemInventory);
    }
    Ok(outcome)
  }

  pub fn authorize_initial(
    &mut self,
    request: &StageRequest,
    policy: &DecisionPolicyInput,
    interaction: OdenRev2HostInteraction,
  ) -> Result<OdenRev2HostAuthorization, OdenRev2HostError> {
    if self.phase != OdenRev2ActorPhase::AwaitingInitial {
      self.terminalize();
      return Err(OdenRev2HostError::InvalidStageOrder);
    }
    self.authorize_at(
      OperationBarrier::AuthorizationBeforeCommit,
      request,
      policy,
      interaction,
    )
  }

  /// Newly discovered effects re-enter the full evaluator at the
  /// revocation-before-next-effect/delivery barrier.
  pub fn authorize_discovery(
    &mut self,
    request: &StageRequest,
    policy: &DecisionPolicyInput,
    interaction: OdenRev2HostInteraction,
  ) -> Result<OdenRev2HostAuthorization, OdenRev2HostError> {
    if self.phase != OdenRev2ActorPhase::Discovery {
      self.terminalize();
      return Err(OdenRev2HostError::InvalidStageOrder);
    }
    self.authorize_at(
      OperationBarrier::RevocationBeforeNextEffectOrDelivery,
      request,
      policy,
      interaction,
    )
  }

  fn authorize_at(
    &mut self,
    barrier: OperationBarrier,
    request: &StageRequest,
    policy: &DecisionPolicyInput,
    interaction: OdenRev2HostInteraction,
  ) -> Result<OdenRev2HostAuthorization, OdenRev2HostError> {
    self.completion_inventory = None;
    let authorization = self.operation.authorize_at_barrier(
      &self.core,
      barrier,
      request,
      policy,
      &mut self.resources,
      interaction.into(),
    );
    let authorization = match authorization {
      Ok(authorization) => authorization,
      Err(error) => {
        self.terminalize();
        return Err(error.into());
      }
    };
    self.pending = None;
    let authorization = match authorization {
      StageAuthorization::Permit { permit } => {
        let actor_digest = permit.actor_digest().to_string();
        let decision = permit.decision().clone();
        self.pending = Some(OdenRev2PendingCommit {
          request: request.clone(),
          permit,
        });
        OdenRev2HostAuthorization::Authorized {
          actor_digest,
          decision,
        }
      }
      StageAuthorization::Masked {
        decision,
        released_provisional_resources,
      } => OdenRev2HostAuthorization::Masked {
        decision,
        released_provisional_resources,
      },
      StageAuthorization::Denied { denial } => {
        self.phase = OdenRev2ActorPhase::Terminal;
        self.sealed_launch = None;
        OdenRev2HostAuthorization::Denied(denial)
      }
      StageAuthorization::RestartRequired { denial } => {
        self.phase = OdenRev2ActorPhase::Terminal;
        self.sealed_launch = None;
        OdenRev2HostAuthorization::RestartRequired(denial)
      }
      StageAuthorization::AlreadyDenied {
        terminal_evidence_id,
      } => {
        self.phase = OdenRev2ActorPhase::Terminal;
        self.sealed_launch = None;
        OdenRev2HostAuthorization::AlreadyDenied {
          terminal_evidence_id,
        }
      }
    };
    Ok(authorization)
  }

  /// Consume the retained permit immediately before the irreversible native
  /// action. No caller-supplied request or permit is accepted here.
  pub fn commit_authorized(
    &mut self,
    policy: &DecisionPolicyInput,
  ) -> Result<OdenRev2HostCommit, OdenRev2HostError> {
    let Some(pending) = self.pending.take() else {
      self.terminalize();
      return Err(OdenRev2HostError::NoPendingPermit);
    };
    let launch_plan = self
      .prepare_launch_commit(&pending.request, pending.permit.decision())?;
    let commit_result = self.operation.commit(
      &self.core,
      pending.permit,
      &pending.request,
      policy,
      &mut self.resources,
    );
    let commit_result = match commit_result {
      Ok(result) => result,
      Err(error) => {
        self.terminalize();
        return Err(error.into());
      }
    };
    let result = match commit_result {
      CommitResult::Committed {
        stage_id,
        actor_digest,
      } => {
        let launch_payload = match launch_plan {
          Some(included) => {
            let Some(seal) = self.sealed_launch.take() else {
              self.terminalize();
              return Err(OdenRev2HostError::InvalidLaunchSeal);
            };
            match seal.into_committed_payload(included) {
              Ok(payload) => Some(payload),
              Err(error) => {
                self.terminalize();
                return Err(error);
              }
            }
          }
          None => None,
        };
        self.phase = OdenRev2ActorPhase::Discovery;
        self.completion_inventory = Some(self.resources.held_ids());
        OdenRev2HostCommit::Committed {
          stage_id,
          actor_digest,
          launch_payload,
        }
      }
      CommitResult::Denied { denial } => {
        self.phase = OdenRev2ActorPhase::Terminal;
        self.completion_inventory = None;
        self.sealed_launch = None;
        OdenRev2HostCommit::Denied(denial)
      }
      CommitResult::AlreadyDenied {
        terminal_evidence_id,
      } => {
        self.phase = OdenRev2ActorPhase::Terminal;
        self.completion_inventory = None;
        self.sealed_launch = None;
        OdenRev2HostCommit::AlreadyDenied {
          terminal_evidence_id,
        }
      }
    };
    Ok(result)
  }

  fn prepare_launch_commit(
    &mut self,
    request: &StageRequest,
    decision: &StageDecision,
  ) -> Result<Option<Vec<bool>>, OdenRev2HostError> {
    let Some(seal) = self.sealed_launch.as_ref() else {
      return Ok(None);
    };
    if !request
      .effects
      .iter()
      .all(|effect| effect.edge_id == seal.edge_id)
    {
      return Ok(None);
    }
    match seal.commit_plan(&self.core, decision) {
      Ok(plan) => Ok(Some(plan)),
      Err(error) => {
        self.terminalize();
        Err(error)
      }
    }
  }

  pub fn completed_stages(&self) -> &[String] {
    self.operation.completed_stages()
  }

  fn protected_inspector_stream_request(
    &self,
    stage_id: impl Into<String>,
    target: &str,
  ) -> Result<StageRequest, OdenRev2HostError> {
    let stage_id = stage_id.into();
    if stage_id.trim().is_empty()
      || stage_id.len() > 1024
      || target.parse::<std::net::SocketAddr>().is_err()
    {
      return Err(OdenRev2HostError::InvalidNativeStage);
    }
    let request = StageRequest {
      identity: self.core.identity(),
      stage_id,
      principals: self.captured_principals.clone(),
      effects: vec![EffectInput {
        identity: self.core.identity(),
        edge_id: PROTECTED_INSPECTOR_EDGE.to_string(),
        effect_slot_id: PROTECTED_INSPECTOR_SLOT.to_string(),
        capability: PROTECTED_INSPECTOR_CAPABILITY.to_string(),
        effect_owner: self.effect_owner_id.clone(),
        occurrence: serde_json::json!({
          "effectOwner": self.effect_owner_id,
          "listener": { "kind": "network-listener", "value": target },
          "route": { "attestation": null, "endpoint": null, "kind": "direct" },
          "session": { "kind": "inspector", "value": target },
        }),
      }],
    };
    self.validate_protected_inspector_stream_request(&request, target)?;
    Ok(request)
  }

  fn validate_protected_inspector_stream_request(
    &self,
    request: &StageRequest,
    target: &str,
  ) -> Result<(), OdenRev2HostError> {
    let expected_occurrence = serde_json::json!({
      "effectOwner": self.effect_owner_id,
      "listener": { "kind": "network-listener", "value": target },
      "route": { "attestation": null, "endpoint": null, "kind": "direct" },
      "session": { "kind": "inspector", "value": target },
    });
    let valid = request.identity == self.core.identity()
      && request.principals == self.captured_principals
      && request.effects.len() == 1
      && request.effects.first().is_some_and(|effect| {
        effect.identity == self.core.identity()
          && effect.edge_id == PROTECTED_INSPECTOR_EDGE
          && effect.effect_slot_id == PROTECTED_INSPECTOR_SLOT
          && effect.capability == PROTECTED_INSPECTOR_CAPABILITY
          && effect.effect_owner == self.effect_owner_id
          && effect.occurrence == expected_occurrence
      });
    if valid {
      Ok(())
    } else {
      Err(OdenRev2HostError::InvalidNativeStage)
    }
  }

  fn live_principals_match(&self) -> bool {
    crate::oden_rev2_capture_live_principals() == self.captured_principals
  }

  pub fn cancel(&mut self) -> OperationReleaseEvidence {
    self.pending = None;
    self.phase = OdenRev2ActorPhase::Terminal;
    self.completion_inventory = None;
    self.sealed_launch = None;
    self.operation.cancel(&mut self.resources)
  }

  pub fn cleanup_non_authorizing(&mut self) -> OperationReleaseEvidence {
    self.completion_inventory = None;
    self.operation.cleanup_non_authorizing(&mut self.resources)
  }

  /// Transfer every still-provisional resource to the completed host action.
  /// Dropping an incomplete actor instead invokes every remaining release hook.
  pub fn complete(mut self) -> Result<Vec<String>, OdenRev2HostError> {
    let current_inventory = self.resources.held_ids();
    if self.pending.is_some()
      || self.phase != OdenRev2ActorPhase::Discovery
      || self.completion_inventory.as_ref() != Some(&current_inventory)
      || self.sealed_launch.is_some()
    {
      self.terminalize();
      return Err(OdenRev2HostError::IncompleteOperation);
    }
    self.completion_inventory = None;
    self.resources.disarm_callbacks()
  }

  /// Transfer the exact callback-free filesystem inventory to the delivery
  /// lease. The inventory IDs must still byte-match the immediately preceding
  /// commit; no callback-backed resource may coexist with this actor kind.
  fn complete_filesystem(
    mut self,
  ) -> Result<OdenRev2HostFilesystemCompletion, OdenRev2HostError> {
    let current_inventory = self.resources.held_ids();
    let native_completion_ready = self
      .resources
      .filesystem()
      .is_ok_and(OdenRev2FsActorInventory::completion_ready);
    if self.pending.is_some()
      || self.phase != OdenRev2ActorPhase::Discovery
      || self.completion_inventory.as_ref() != Some(&current_inventory)
      || self.sealed_launch.is_some()
      || !native_completion_ready
    {
      self.terminalize();
      return Err(OdenRev2HostError::IncompleteOperation);
    }
    self.completion_inventory = None;
    Ok(OdenRev2HostFilesystemCompletion {
      _resources: self.resources.take_filesystem()?,
      _not_send_sync: std::marker::PhantomData,
    })
  }

  fn terminalize(&mut self) {
    self.pending = None;
    self.phase = OdenRev2ActorPhase::Terminal;
    self.completion_inventory = None;
    self.sealed_launch = None;
    let _ = self.operation.cancel(&mut self.resources);
  }
}

impl OdenRev2FilesystemHostActor {
  #[allow(clippy::too_many_arguments)]
  pub(crate) fn capture_host(
    operation_id: impl Into<String>,
    actor_id: impl Into<String>,
    principals: Vec<PrincipalRef>,
    effect_owner_id: impl Into<String>,
    effect_owner_principal: PrincipalRef,
    effect_owner_generation: impl Into<String>,
    policy: &DecisionPolicyInput,
    filesystem_inventory: OdenRev2FsActorInventory,
  ) -> Result<Self, OdenRev2HostError> {
    let operation = filesystem_inventory.operation();
    let initial_target = filesystem_inventory
      .target_kind()
      .map_err(|_| OdenRev2HostError::InvalidFilesystemInventory)?;
    let bound_request = filesystem_inventory.bound_request().clone();
    Ok(Self {
      inner: OdenRev2HostActor::capture_filesystem_host(
        operation_id,
        actor_id,
        principals,
        effect_owner_id,
        effect_owner_principal,
        effect_owner_generation,
        policy,
        filesystem_inventory,
      )?,
      operation,
      initial_target,
      bound_request,
      phase: OdenRev2FilesystemActorPhase::AwaitingAuthorization,
    })
  }

  fn terminal_error<T>(&mut self) -> Result<T, OdenRev2HostError> {
    self.inner.terminalize();
    self.phase = OdenRev2FilesystemActorPhase::Terminal;
    Err(OdenRev2HostError::InvalidStageOrder)
  }

  pub(crate) fn authorize_initial(
    &mut self,
    request: &StageRequest,
    policy: &DecisionPolicyInput,
    interaction: OdenRev2HostInteraction,
  ) -> Result<OdenRev2HostAuthorization, OdenRev2HostError> {
    if self.phase != OdenRev2FilesystemActorPhase::AwaitingAuthorization
      || self.bound_request != *request
    {
      return self.terminal_error();
    }
    let result = self.inner.authorize_initial(request, policy, interaction);
    self.phase = match &result {
      Ok(OdenRev2HostAuthorization::Authorized { .. }) => {
        OdenRev2FilesystemActorPhase::Pending {
          sources_validated: false,
          target_validated: false,
          prepared: false,
          observed: false,
        }
      }
      _ => OdenRev2FilesystemActorPhase::Terminal,
    };
    result
  }

  pub(crate) fn revalidate_sources(
    &mut self,
    operation_session: &OdenRev2FsOperationSession,
  ) -> Result<(), OdenRev2HostError> {
    if !matches!(
      self.phase,
      OdenRev2FilesystemActorPhase::Pending {
        sources_validated: false,
        target_validated: false,
        prepared: false,
        observed: false,
      }
    ) {
      return self.terminal_error();
    }
    if let Err(error) =
      self.inner.revalidate_filesystem_sources(operation_session)
    {
      self.phase = OdenRev2FilesystemActorPhase::Terminal;
      return Err(error);
    }
    let OdenRev2FilesystemActorPhase::Pending {
      sources_validated, ..
    } = &mut self.phase
    else {
      unreachable!();
    };
    *sources_validated = true;
    Ok(())
  }

  pub(crate) fn revalidate_target(
    &mut self,
    operation_session: &OdenRev2FsOperationSession,
  ) -> Result<(), OdenRev2HostError> {
    if !matches!(
      self.phase,
      OdenRev2FilesystemActorPhase::Pending {
        sources_validated: true,
        target_validated: false,
        observed: false,
        ..
      }
    ) {
      return self.terminal_error();
    }
    if let Err(error) =
      self.inner.revalidate_filesystem_target(operation_session)
    {
      self.phase = OdenRev2FilesystemActorPhase::Terminal;
      return Err(error);
    }
    let OdenRev2FilesystemActorPhase::Pending {
      target_validated, ..
    } = &mut self.phase
    else {
      unreachable!();
    };
    *target_validated = true;
    Ok(())
  }

  pub(crate) fn observe_metadata(
    &mut self,
    operation_session: &OdenRev2FsOperationSession,
  ) -> Result<OdenRev2FsMetadataObservation, OdenRev2HostError> {
    if self.operation != OdenRev2FsActorOperation::ObserveMetadata
      || !matches!(
        self.phase,
        OdenRev2FilesystemActorPhase::Pending {
          sources_validated: true,
          target_validated: true,
          prepared: false,
          observed: false,
        }
      )
    {
      return self.terminal_error();
    }
    let observation =
      match self.inner.observe_filesystem_metadata(operation_session) {
        Ok(observation) => observation,
        Err(error) => {
          self.phase = OdenRev2FilesystemActorPhase::Terminal;
          return Err(error);
        }
      };
    let OdenRev2FilesystemActorPhase::Pending { observed, .. } =
      &mut self.phase
    else {
      unreachable!();
    };
    *observed = true;
    Ok(observation)
  }

  pub(crate) fn observe_missing(
    &mut self,
    operation_session: &OdenRev2FsOperationSession,
  ) -> Result<(), OdenRev2HostError> {
    if self.operation != OdenRev2FsActorOperation::ObserveMetadata
      || !matches!(
        self.phase,
        OdenRev2FilesystemActorPhase::Pending {
          sources_validated: true,
          target_validated: true,
          prepared: false,
          observed: false,
        }
      )
    {
      return self.terminal_error();
    }
    if let Err(error) = self.inner.observe_filesystem_missing(operation_session)
    {
      self.phase = OdenRev2FilesystemActorPhase::Terminal;
      return Err(error);
    }
    let OdenRev2FilesystemActorPhase::Pending { observed, .. } =
      &mut self.phase
    else {
      unreachable!();
    };
    *observed = true;
    Ok(())
  }

  pub(crate) fn prepare_mkdir(
    &mut self,
    operation_session: &OdenRev2FsOperationSession,
  ) -> Result<(), OdenRev2HostError> {
    if self.operation != OdenRev2FsActorOperation::Mkdir
      || self.initial_target != OdenRev2FsCheckedTargetKind::Missing
      || !matches!(
        self.phase,
        OdenRev2FilesystemActorPhase::Pending {
          sources_validated: true,
          target_validated: true,
          prepared: false,
          observed: false,
        }
      )
    {
      return self.terminal_error();
    }
    if let Err(error) = self.inner.prepare_filesystem_mkdir(operation_session) {
      self.phase = OdenRev2FilesystemActorPhase::Terminal;
      return Err(error);
    }
    self.phase = OdenRev2FilesystemActorPhase::Pending {
      sources_validated: true,
      target_validated: false,
      prepared: true,
      observed: false,
    };
    Ok(())
  }

  pub(crate) fn commit_authorized(
    &mut self,
    policy: &DecisionPolicyInput,
  ) -> Result<OdenRev2HostCommit, OdenRev2HostError> {
    let ready = matches!(
      (self.operation, self.initial_target, self.phase),
      (
        OdenRev2FsActorOperation::ObserveMetadata,
        _,
        OdenRev2FilesystemActorPhase::Pending {
          sources_validated: true,
          target_validated: true,
          prepared: false,
          observed: true,
        },
      ) | (
        OdenRev2FsActorOperation::Mkdir,
        OdenRev2FsCheckedTargetKind::Existing
          | OdenRev2FsCheckedTargetKind::NoFollowLink,
        OdenRev2FilesystemActorPhase::Pending {
          sources_validated: true,
          target_validated: true,
          prepared: false,
          observed: false,
        },
      ) | (
        OdenRev2FsActorOperation::Mkdir,
        OdenRev2FsCheckedTargetKind::Missing,
        OdenRev2FilesystemActorPhase::Pending {
          sources_validated: true,
          target_validated: true,
          prepared: true,
          observed: false,
        },
      )
    );
    if !ready {
      return self.terminal_error();
    }
    let result = self.inner.commit_authorized(policy);
    self.phase = match &result {
      Ok(OdenRev2HostCommit::Committed { .. }) => {
        OdenRev2FilesystemActorPhase::CoreCommitted
      }
      _ => OdenRev2FilesystemActorPhase::Terminal,
    };
    result
  }

  pub(crate) fn commit_mkdir(
    &mut self,
    operation_session: &OdenRev2FsOperationSession,
    mode: u32,
    native_commit_witness: &OdenRev2FilesystemNativeCommitWitness<'_>,
  ) -> Result<OdenRev2FsMkdirCommitOutcome, OdenRev2HostError> {
    if self.operation != OdenRev2FsActorOperation::Mkdir
      || self.initial_target != OdenRev2FsCheckedTargetKind::Missing
      || self.phase != OdenRev2FilesystemActorPhase::CoreCommitted
    {
      return self.terminal_error();
    }
    let outcome = match self.inner.commit_filesystem_mkdir(
      operation_session,
      mode,
      native_commit_witness,
    ) {
      Ok(outcome) => outcome,
      Err(error) => {
        self.phase = OdenRev2FilesystemActorPhase::Terminal;
        return Err(error);
      }
    };
    if matches!(outcome, OdenRev2FsMkdirCommitOutcome::Committed) {
      self.phase = OdenRev2FilesystemActorPhase::NativeCommitted;
    } else {
      let _ = self.inner.cancel();
      self.phase = OdenRev2FilesystemActorPhase::Terminal;
    }
    Ok(outcome)
  }

  pub(crate) fn cancel(&mut self) -> OperationReleaseEvidence {
    self.phase = OdenRev2FilesystemActorPhase::Terminal;
    self.inner.cancel()
  }

  pub(crate) fn complete(
    mut self,
    _witness: &OdenRev2FilesystemDeliveryWitness,
  ) -> Result<OdenRev2HostFilesystemCompletion, OdenRev2HostError> {
    let ready = matches!(
      (self.operation, self.initial_target, self.phase),
      (
        OdenRev2FsActorOperation::ObserveMetadata,
        _,
        OdenRev2FilesystemActorPhase::CoreCommitted,
      ) | (
        OdenRev2FsActorOperation::Mkdir,
        OdenRev2FsCheckedTargetKind::Existing
          | OdenRev2FsCheckedTargetKind::NoFollowLink,
        OdenRev2FilesystemActorPhase::CoreCommitted,
      ) | (
        OdenRev2FsActorOperation::Mkdir,
        OdenRev2FsCheckedTargetKind::Missing,
        OdenRev2FilesystemActorPhase::NativeCommitted,
      )
    );
    if !ready {
      return self.terminal_error();
    }
    self.inner.complete_filesystem()
  }
}

type OdenRev2PolicyProvider =
  Box<dyn FnMut() -> Result<DecisionPolicyInput, OdenRev2HostError> + 'static>;

struct OdenRev2BoundNativeStage {
  target: String,
  api_name: String,
  request: StageRequest,
  policy_provider: OdenRev2PolicyProvider,
  discovery: bool,
  interaction: OdenRev2HostInteraction,
}

/// Host-only state installed in Deno's `OpState`. Its absence preserves the
/// exact Rev1 op path. Its presence fails closed unless the caller's two
/// strings match a stage whose semantic inputs were already captured by Rust.
pub struct OdenRev2ArmedContext {
  actor: Option<OdenRev2HostActor>,
  protected_inspector_stream_stage: Option<OdenRev2BoundNativeStage>,
  committed_launch_payload: Option<OdenRev2CommittedLaunchPayload>,
}

impl OdenRev2ArmedContext {
  pub fn capture_host(actor: OdenRev2HostActor) -> Self {
    Self {
      actor: Some(actor),
      protected_inspector_stream_stage: None,
      committed_launch_payload: None,
    }
  }

  /// A fail-closed context for initialization ordering and native seam tests.
  pub fn unbound_host() -> Self {
    Self {
      actor: None,
      protected_inspector_stream_stage: None,
      committed_launch_payload: None,
    }
  }

  #[allow(clippy::too_many_arguments)]
  pub fn arm_protected_inspector_stream_stage<F>(
    &mut self,
    target: impl Into<String>,
    api_name: impl Into<String>,
    stage_id: impl Into<String>,
    policy_provider: F,
    discovery: bool,
    interaction: OdenRev2HostInteraction,
  ) -> Result<(), OdenRev2HostError>
  where
    F: FnMut() -> Result<DecisionPolicyInput, OdenRev2HostError> + 'static,
  {
    let target = target.into();
    let api_name = api_name.into();
    let actor = self
      .actor
      .as_ref()
      .ok_or(OdenRev2HostError::MissingNativeActor)?;
    let request =
      actor.protected_inspector_stream_request(stage_id, &target)?;
    self.arm_prepared_protected_inspector_stream_stage(
      target,
      api_name,
      request,
      Box::new(policy_provider),
      discovery,
      interaction,
    )
  }

  #[allow(clippy::too_many_arguments)]
  fn arm_prepared_protected_inspector_stream_stage(
    &mut self,
    target: String,
    api_name: String,
    request: StageRequest,
    policy_provider: OdenRev2PolicyProvider,
    discovery: bool,
    interaction: OdenRev2HostInteraction,
  ) -> Result<(), OdenRev2HostError> {
    if self.protected_inspector_stream_stage.is_some() {
      return Err(OdenRev2HostError::NativeStageAlreadyBound);
    }
    if api_name.trim().is_empty() || api_name.len() > 1024 {
      return Err(OdenRev2HostError::InvalidNativeStage);
    }
    self
      .actor
      .as_ref()
      .ok_or(OdenRev2HostError::MissingNativeActor)?
      .validate_protected_inspector_stream_request(&request, &target)?;
    self.protected_inspector_stream_stage = Some(OdenRev2BoundNativeStage {
      target,
      api_name,
      request,
      policy_provider,
      discovery,
      interaction,
    });
    Ok(())
  }

  pub fn consume_protected_inspector_stream_stage(
    &mut self,
    target: &str,
    api_name: &str,
  ) -> Result<(), PermissionCheckError> {
    let Some(bound) = self.protected_inspector_stream_stage.as_ref() else {
      return Err(self.fail_closed_permission(
        OdenRev2HostError::NativeStageMismatch,
        target,
        api_name,
      ));
    };
    if bound.target != target || bound.api_name != api_name {
      return Err(self.fail_closed_permission(
        OdenRev2HostError::NativeStageMismatch,
        target,
        api_name,
      ));
    }
    if !self
      .actor
      .as_ref()
      .is_some_and(OdenRev2HostActor::live_principals_match)
    {
      return Err(self.fail_closed_permission(
        OdenRev2HostError::LivePrincipalMismatch,
        target,
        api_name,
      ));
    }
    let mut bound = self
      .protected_inspector_stream_stage
      .take()
      .expect("exact native stage checked above");
    let authorization_policy = match (bound.policy_provider)() {
      Ok(policy) => policy,
      Err(error) => {
        return Err(self.fail_closed_permission(error, target, api_name));
      }
    };
    let Some(actor) = self.actor.as_mut() else {
      return Err(self.fail_closed_permission(
        OdenRev2HostError::MissingNativeActor,
        target,
        api_name,
      ));
    };
    let authorization = if bound.discovery {
      actor.authorize_discovery(
        &bound.request,
        &authorization_policy,
        bound.interaction,
      )
    } else {
      actor.authorize_initial(
        &bound.request,
        &authorization_policy,
        bound.interaction,
      )
    }
    .map_err(|error| rev2_permission_error(error, target, api_name));
    let authorization = match authorization {
      Ok(authorization) => authorization,
      Err(error) => {
        self.cancel_actor();
        return Err(error);
      }
    };
    if let OdenRev2HostAuthorization::Authorized { .. } = authorization {
      let commit_policy = match (bound.policy_provider)() {
        Ok(policy) => policy,
        Err(error) => {
          return Err(self.fail_closed_permission(error, target, api_name));
        }
      };
      let commit = match self
        .actor
        .as_mut()
        .ok_or(OdenRev2HostError::MissingNativeActor)
        .and_then(|actor| actor.commit_authorized(&commit_policy))
      {
        Ok(commit) => commit,
        Err(error) => {
          return Err(self.fail_closed_permission(error, target, api_name));
        }
      };
      match commit {
        OdenRev2HostCommit::Committed { launch_payload, .. } => {
          if let Some(payload) = launch_payload {
            if self.committed_launch_payload.is_some() {
              return Err(self.fail_closed_permission(
                OdenRev2HostError::InvalidLaunchDecision,
                target,
                api_name,
              ));
            }
            self.committed_launch_payload = Some(payload);
          }
          Ok(())
        }
        OdenRev2HostCommit::Denied(denial) => Err(self.fail_closed_permission(
          OdenRev2HostError::AuthorizationRejected(denial.reason_code),
          target,
          api_name,
        )),
        OdenRev2HostCommit::AlreadyDenied { .. } => {
          Err(self.fail_closed_permission(
            OdenRev2HostError::AuthorizationRejected(
              "OD-CAP-OPERATION-CONTEXT".to_string(),
            ),
            target,
            api_name,
          ))
        }
      }
    } else {
      let reason = match authorization {
        OdenRev2HostAuthorization::Masked { .. } => {
          "OD-CAP-ENV-MASKED".to_string()
        }
        OdenRev2HostAuthorization::Denied(denial)
        | OdenRev2HostAuthorization::RestartRequired(denial) => {
          denial.reason_code
        }
        OdenRev2HostAuthorization::AlreadyDenied { .. } => {
          "OD-CAP-OPERATION-CONTEXT".to_string()
        }
        OdenRev2HostAuthorization::Authorized { .. } => unreachable!(),
      };
      Err(self.fail_closed_permission(
        OdenRev2HostError::AuthorizationRejected(reason),
        target,
        api_name,
      ))
    }
  }

  pub fn hold_provisional(
    &mut self,
    id: impl Into<String>,
    release: impl FnOnce() + 'static,
  ) -> Result<(), OdenRev2HostError> {
    self
      .actor
      .as_mut()
      .ok_or(OdenRev2HostError::MissingNativeActor)?
      .hold_provisional(id, release)
  }

  pub fn take_committed_launch_payload(
    &mut self,
  ) -> Option<OdenRev2CommittedLaunchPayload> {
    self.committed_launch_payload.take()
  }

  pub fn cancel(
    &mut self,
  ) -> Result<OperationReleaseEvidence, OdenRev2HostError> {
    self.protected_inspector_stream_stage = None;
    self.committed_launch_payload = None;
    self
      .actor
      .as_mut()
      .ok_or(OdenRev2HostError::MissingNativeActor)
      .map(OdenRev2HostActor::cancel)
  }

  /// Release provisional resources without authorizing or terminalizing the
  /// single-operation actor. Any merely bound native stage is abandoned; use
  /// `cancel` when the complete actor and its sealed launch should be retired.
  pub fn cleanup_non_authorizing(
    &mut self,
  ) -> Result<OperationReleaseEvidence, OdenRev2HostError> {
    self.protected_inspector_stream_stage = None;
    self
      .actor
      .as_mut()
      .ok_or(OdenRev2HostError::MissingNativeActor)
      .map(OdenRev2HostActor::cleanup_non_authorizing)
  }

  pub fn complete(mut self) -> Result<Vec<String>, OdenRev2HostError> {
    self.protected_inspector_stream_stage = None;
    self
      .actor
      .take()
      .ok_or(OdenRev2HostError::MissingNativeActor)?
      .complete()
  }

  fn cancel_actor(&mut self) {
    self.protected_inspector_stream_stage = None;
    self.committed_launch_payload = None;
    if let Some(actor) = self.actor.as_mut() {
      let _ = actor.cancel();
    }
  }

  fn fail_closed_permission(
    &mut self,
    error: OdenRev2HostError,
    target: &str,
    api_name: &str,
  ) -> PermissionCheckError {
    self.cancel_actor();
    rev2_permission_error(error, target, api_name)
  }
}

fn rev2_permission_error(
  error: OdenRev2HostError,
  target: &str,
  api_name: &str,
) -> PermissionCheckError {
  PermissionCheckError::PermissionDenied(PermissionDeniedError {
    access: format!("{api_name} Rev2 access to {target:?}"),
    name: "capsec",
    custom_message: Some(format!("oden capsec Rev2 native guard: {error}")),
    state: PermissionState::Denied,
  })
}

#[cfg(test)]
mod tests {
  use std::cell::Cell;
  use std::rc::Rc;

  use serde_json::json;

  use super::*;
  use crate::rev2::AuthoritySelectorInput;
  use crate::rev2::CompatibilityDispositionInput;
  use crate::rev2::EngineIdentity;
  use crate::rev2::Generations;
  use crate::rev2::Mode;
  use crate::rev2::NamedSelectorInput;
  use crate::rev2::OperationProvenanceContext;
  use crate::rev2::PrincipalKind;

  const ENV_EDGE: &str = "native-op:ext/os/lib.rs#op_get_env";
  const ENV_SLOT: &str = "native-op:ext/os/lib.rs#op_get_env:effect-slot:0";

  fn package() -> PrincipalRef {
    PrincipalRef {
      kind: PrincipalKind::Package,
      key: "pkg:sha256-runtime-integration".to_string(),
    }
  }

  fn root() -> PrincipalRef {
    PrincipalRef {
      kind: PrincipalKind::Root,
      key: "root".to_string(),
    }
  }

  fn spawn_edges() -> [OdenRev2HostSpawnEdge; 3] {
    [
      OdenRev2HostSpawnEdge::DenoSpawnChild,
      OdenRev2HostSpawnEdge::NodeSpawnChild,
      OdenRev2HostSpawnEdge::DeprecatedRun,
    ]
  }

  fn env_effect(name: &str) -> EffectInput {
    EffectInput {
      identity: EngineIdentity::embedded(),
      edge_id: ENV_EDGE.to_string(),
      effect_slot_id: ENV_SLOT.to_string(),
      capability: "env:read".to_string(),
      effect_owner: "owner:pkg".to_string(),
      occurrence: json!({
        "effectOwner": "owner:pkg",
        "name": name,
        "ownerGeneration": "0",
        "requiredForCommit": false,
        "targetKind": "broker",
      }),
    }
  }

  fn env_selector(name: &str) -> AuthoritySelectorInput {
    AuthoritySelectorInput {
      identity: EngineIdentity::embedded(),
      principal: Some(package()),
      capability: "env:read".to_string(),
      resource: json!({ "name": name }),
    }
  }

  fn spawn_effect(edge: OdenRev2HostSpawnEdge) -> EffectInput {
    EffectInput {
      identity: EngineIdentity::embedded(),
      edge_id: edge.edge_id().to_string(),
      effect_slot_id: format!("{}:effect-slot:0", edge.edge_id()),
      capability: "process:spawn".to_string(),
      effect_owner: "owner:pkg".to_string(),
      occurrence: json!({
        "effectOwner": "owner:pkg",
        "interpreterIdentity": { "kind": "platform-object", "value": "none" },
        "launchSet": [{ "kind": "entry", "value": "/bin/echo" }],
        "objectIdentity": { "kind": "platform-object", "value": "exe:echo" },
        "requestedPath": { "encoding": "unicode", "value": "/bin/echo" },
      }),
    }
  }

  fn spawn_selector() -> AuthoritySelectorInput {
    AuthoritySelectorInput {
      identity: EngineIdentity::embedded(),
      principal: Some(package()),
      capability: "process:spawn".to_string(),
      resource: json!({
        "interpreterIdentity": { "kind": "platform-object", "value": "none" },
        "objectIdentity": { "kind": "platform-object", "value": "exe:echo" },
        "path": { "encoding": "unicode", "value": "/bin/echo" },
      }),
    }
  }

  fn child_env_write_selector(name: &str) -> AuthoritySelectorInput {
    AuthoritySelectorInput {
      identity: EngineIdentity::embedded(),
      principal: Some(package()),
      capability: "env:write".to_string(),
      resource: json!({
        "name": name,
        "targetId": "child:launch",
        "targetKind": "child-launch",
      }),
    }
  }

  fn spawn_policy(
    allowed_reads: &[&str],
    allowed_writes: &[&str],
    masked_reads: &[&str],
  ) -> DecisionPolicyInput {
    let mut policy = policy(&[]);
    policy
      .static_floor
      .push(named("floor:spawn", spawn_selector()));
    policy.static_floor.extend(
      allowed_reads
        .iter()
        .map(|name| named(&format!("floor:read:{name}"), env_selector(name))),
    );
    policy
      .static_floor
      .extend(allowed_writes.iter().map(|name| {
        named(
          &format!("floor:write:{name}"),
          child_env_write_selector(name),
        )
      }));
    policy
      .compatibility_dispositions
      .extend(
        masked_reads
          .iter()
          .map(|name| CompatibilityDispositionInput {
            disposition_id: "env:ignore".to_string(),
            source_id: format!("mask:{name}"),
            selector: env_selector(name),
          }),
      );
    policy
  }

  fn spawn_actor(
    policy: &DecisionPolicyInput,
    seal: OdenRev2HostLaunchSeal,
  ) -> OdenRev2HostActor {
    OdenRev2HostActor::capture_host(
      "operation:native-spawn",
      "actor:native-spawn",
      vec![package()],
      "owner:pkg",
      package(),
      "0",
      Some(seal),
      policy,
    )
    .unwrap()
  }

  fn named(
    source_id: &str,
    selector: AuthoritySelectorInput,
  ) -> NamedSelectorInput {
    NamedSelectorInput {
      source_id: source_id.to_string(),
      selector,
    }
  }

  fn policy(names: &[&str]) -> DecisionPolicyInput {
    DecisionPolicyInput {
      identity: EngineIdentity::embedded(),
      mode: Mode::Enforce,
      run_nonce: "run:native-integration".to_string(),
      channel_epoch: "channel:native-integration".to_string(),
      provenance: OperationProvenanceContext {
        policy_digest: crate::rev2_registry_generated::REV2_VOCAB_DIGEST
          .to_string(),
        armed_snapshot_digest:
          crate::rev2_registry_generated::REV2_REGISTRY_DIGEST.to_string(),
        quota_owner: PrincipalRef {
          kind: PrincipalKind::Runtime,
          key: "runtime:quota-owner".to_string(),
        },
        terminal_evidence_id: "terminal:native-integration".to_string(),
      },
      generations: Generations {
        policy_snapshot: "1".to_string(),
        ..Generations::default()
      },
      process_denials: Vec::new(),
      principal_denials: Vec::new(),
      session_revocations: Vec::new(),
      escalation_ceiling: Vec::new(),
      static_floor: names
        .iter()
        .map(|name| named(&format!("floor:{name}"), env_selector(name)))
        .collect(),
      handles: Vec::new(),
      session_grants: Vec::new(),
      implicit_self: Vec::new(),
      protected_exceptions: Vec::new(),
      compatibility_dispositions: Vec::new(),
      validated_receipt_row_digests: Vec::new(),
      path_bindings: Vec::new(),
    }
  }

  fn inspector_policy(
    target: &str,
    principal: PrincipalRef,
  ) -> DecisionPolicyInput {
    let mut policy = policy(&[]);
    policy.static_floor = vec![named(
      "floor:protected-inspector-stream",
      AuthoritySelectorInput {
        identity: EngineIdentity::embedded(),
        principal: Some(principal),
        capability: PROTECTED_INSPECTOR_CAPABILITY.to_string(),
        resource: json!({
          "route": { "attestation": null, "endpoint": null, "kind": "direct" },
          "session": { "kind": "inspector", "value": target },
        }),
      },
    )];
    policy
  }

  fn request(stage_id: &str, name: &str) -> StageRequest {
    StageRequest {
      identity: EngineIdentity::embedded(),
      stage_id: stage_id.to_string(),
      principals: vec![package()],
      effects: vec![env_effect(name)],
    }
  }

  fn actor(policy: &DecisionPolicyInput) -> OdenRev2HostActor {
    actor_for(policy, package())
  }

  fn actor_for(
    policy: &DecisionPolicyInput,
    principal: PrincipalRef,
  ) -> OdenRev2HostActor {
    OdenRev2HostActor::capture_host(
      "operation:native-integration",
      "actor:native-integration",
      vec![principal.clone()],
      "owner:pkg",
      principal,
      "0",
      None,
      policy,
    )
    .unwrap()
  }

  #[test]
  fn host_actor_consumes_initial_discovery_and_commit_barriers() {
    let policy = policy(&["TOKEN"]);
    let mut actor = actor(&policy);
    assert!(matches!(
      actor
        .authorize_initial(
          &request("initial", "TOKEN"),
          &policy,
          OdenRev2HostInteraction::NonInteractive,
        )
        .unwrap(),
      OdenRev2HostAuthorization::Authorized { .. }
    ));
    assert!(matches!(
      actor.commit_authorized(&policy).unwrap(),
      OdenRev2HostCommit::Committed { .. }
    ));
    assert!(matches!(
      actor
        .authorize_discovery(
          &request("discovery", "TOKEN"),
          &policy,
          OdenRev2HostInteraction::NonInteractive,
        )
        .unwrap(),
      OdenRev2HostAuthorization::Authorized { .. }
    ));
    assert!(matches!(
      actor.commit_authorized(&policy).unwrap(),
      OdenRev2HostCommit::Committed { .. }
    ));
    assert_eq!(actor.completed_stages(), ["initial", "discovery"]);
  }

  #[test]
  fn denial_and_restart_release_real_provisional_resources() {
    let released_on_deny = Rc::new(Cell::new(false));
    let mut denied = actor(&policy(&[]));
    let released = released_on_deny.clone();
    denied
      .hold_provisional("rid:deny", move || released.set(true))
      .unwrap();
    let OdenRev2HostAuthorization::Denied(denial) = denied
      .authorize_initial(
        &request("deny", "TOKEN"),
        &policy(&[]),
        OdenRev2HostInteraction::NonInteractive,
      )
      .unwrap()
    else {
      panic!("missing floor must deny");
    };
    assert!(released_on_deny.get());
    assert_eq!(denial.released_provisional_resources, ["rid:deny"]);

    let allow = policy(&["TOKEN"]);
    let released_on_restart = Rc::new(Cell::new(false));
    let mut restart = actor(&allow);
    let released = released_on_restart.clone();
    restart
      .hold_provisional("rid:restart", move || released.set(true))
      .unwrap();
    let OdenRev2HostAuthorization::RestartRequired(denial) = restart
      .authorize_initial(
        &request("restart", "TOKEN"),
        &allow,
        OdenRev2HostInteraction::MayPrompt,
      )
      .unwrap()
    else {
      panic!("interactive transition must restart");
    };
    assert!(released_on_restart.get());
    assert_eq!(denial.released_provisional_resources, ["rid:restart"]);
  }

  #[test]
  fn permit_replay_resource_tamper_and_revocation_fail_closed() {
    let allow = policy(&["TOKEN"]);
    let mut replay = actor(&allow);
    replay
      .authorize_initial(
        &request("replay", "TOKEN"),
        &allow,
        OdenRev2HostInteraction::NonInteractive,
      )
      .unwrap();
    assert!(matches!(
      replay.commit_authorized(&allow).unwrap(),
      OdenRev2HostCommit::Committed { .. }
    ));
    assert!(matches!(
      replay.commit_authorized(&allow),
      Err(OdenRev2HostError::NoPendingPermit)
    ));

    let release_count = Rc::new(Cell::new(0));
    let mut tamper = actor(&allow);
    let released = release_count.clone();
    tamper
      .hold_provisional("rid:before", move || released.set(released.get() + 1))
      .unwrap();
    tamper
      .authorize_initial(
        &request("tamper", "TOKEN"),
        &allow,
        OdenRev2HostInteraction::NonInteractive,
      )
      .unwrap();
    let released = release_count.clone();
    tamper
      .hold_provisional("rid:after", move || released.set(released.get() + 1))
      .unwrap();
    assert!(matches!(
      tamper.commit_authorized(&allow).unwrap(),
      OdenRev2HostCommit::Denied(_)
    ));
    assert_eq!(release_count.get(), 2);

    let mut revoked_actor = actor(&allow);
    revoked_actor
      .authorize_initial(
        &request("revoked", "TOKEN"),
        &allow,
        OdenRev2HostInteraction::NonInteractive,
      )
      .unwrap();
    let mut revoked = allow.clone();
    revoked.generations.revocation = "1".to_string();
    revoked.session_revocations =
      vec![named("revocation:TOKEN", env_selector("TOKEN"))];
    assert!(matches!(
      revoked_actor.commit_authorized(&revoked).unwrap(),
      OdenRev2HostCommit::Denied(_)
    ));
  }

  #[test]
  fn phase_order_and_completion_cannot_bypass_a_clean_commit() {
    let allow = policy(&["TOKEN"]);
    let wrong_order_release = Rc::new(Cell::new(false));
    let mut wrong_order = actor(&allow);
    let released = wrong_order_release.clone();
    wrong_order
      .hold_provisional("rid:wrong-order", move || released.set(true))
      .unwrap();
    assert!(matches!(
      wrong_order.authorize_discovery(
        &request("discovery-first", "TOKEN"),
        &allow,
        OdenRev2HostInteraction::NonInteractive,
      ),
      Err(OdenRev2HostError::InvalidStageOrder)
    ));
    assert!(wrong_order_release.get());

    let uncommitted_release = Rc::new(Cell::new(false));
    let mut uncommitted = actor(&allow);
    let released = uncommitted_release.clone();
    uncommitted
      .hold_provisional("rid:uncommitted", move || released.set(true))
      .unwrap();
    uncommitted
      .authorize_initial(
        &request("uncommitted", "TOKEN"),
        &allow,
        OdenRev2HostInteraction::NonInteractive,
      )
      .unwrap();
    assert!(matches!(
      uncommitted.complete(),
      Err(OdenRev2HostError::IncompleteOperation)
    ));
    assert!(uncommitted_release.get());

    let release_count = Rc::new(Cell::new(0));
    let mut dirty_after_commit = actor(&allow);
    let released = release_count.clone();
    dirty_after_commit
      .hold_provisional("rid:covered", move || released.set(released.get() + 1))
      .unwrap();
    dirty_after_commit
      .authorize_initial(
        &request("covered", "TOKEN"),
        &allow,
        OdenRev2HostInteraction::NonInteractive,
      )
      .unwrap();
    dirty_after_commit.commit_authorized(&allow).unwrap();
    let released = release_count.clone();
    dirty_after_commit
      .hold_provisional("rid:uncovered", move || {
        released.set(released.get() + 1)
      })
      .unwrap();
    assert!(matches!(
      dirty_after_commit.complete(),
      Err(OdenRev2HostError::IncompleteOperation)
    ));
    assert_eq!(release_count.get(), 2);

    let transferred_release = Rc::new(Cell::new(false));
    let mut clean = actor(&allow);
    let released = transferred_release.clone();
    clean
      .hold_provisional("rid:clean", move || released.set(true))
      .unwrap();
    clean
      .authorize_initial(
        &request("clean", "TOKEN"),
        &allow,
        OdenRev2HostInteraction::NonInteractive,
      )
      .unwrap();
    clean.commit_authorized(&allow).unwrap();
    assert_eq!(clean.complete().unwrap(), ["rid:clean"]);
    assert!(!transferred_release.get());
  }

  #[test]
  fn required_for_commit_is_host_sealed_and_caller_fields_are_rejected() {
    let edges = [
      OdenRev2HostSpawnEdge::DenoSpawnChild,
      OdenRev2HostSpawnEdge::NodeSpawnChild,
      OdenRev2HostSpawnEdge::DeprecatedRun,
    ];
    assert!(
      edges
        .iter()
        .all(|edge| !edge.edge_id().contains("spawn_sync"))
    );
    for edge in edges {
      let required = OdenRev2HostChildExport::capture_broker_env_read_host(
        edge,
        "owner:pkg",
        "0",
        "BROKER_TOKEN",
        "broker-value",
        OdenRev2RequiredForCommit::Required,
      )
      .unwrap();
      assert!(!format!("{required:?}").contains("broker-value"));
      assert_eq!(required.effect.edge_id, edge.edge_id());
      assert_eq!(required.effect.effect_slot_id, edge.env_read_slot());
      assert_eq!(required.effect.capability, "env:read");
      assert_eq!(required.effect.occurrence["targetKind"], "broker");
      assert_eq!(required.effect.occurrence["requiredForCommit"], true);
      assert_eq!(required.value, "broker-value");

      let optional =
        OdenRev2HostChildExport::capture_principal_overlay_env_read_host(
          edge,
          "owner:pkg",
          "0",
          "OVERLAY_TOKEN",
          "overlay-value",
          OdenRev2RequiredForCommit::Optional,
        )
        .unwrap();
      assert_eq!(optional.effect.effect_slot_id, edge.env_read_slot());
      assert_eq!(
        optional.effect.occurrence["targetKind"],
        "principal-overlay"
      );
      assert_eq!(optional.effect.occurrence["requiredForCommit"], false);

      let literal = OdenRev2HostChildExport::capture_literal_env_write_host(
        edge,
        "owner:pkg",
        "0",
        "LITERAL_TOKEN",
        "literal-value",
      )
      .unwrap();
      assert_eq!(literal.effect.effect_slot_id, edge.env_write_slot());
      assert_eq!(literal.effect.capability, "env:write");
      assert_eq!(literal.effect.occurrence["targetKind"], "child-launch");
      assert_eq!(literal.effect.occurrence["targetId"], "child:launch");
      assert!(
        !literal
          .effect
          .occurrence
          .as_object()
          .unwrap()
          .contains_key("requiredForCommit")
      );

      let launch = OdenRev2HostLaunchSeal::capture_spawn_host(
        edge,
        vec![required, optional, literal],
        1024,
      )
      .unwrap();
      assert_eq!(launch.edge_id, edge.edge_id());
    }

    OdenRev2HostLaunchSeal::capture_spawn_host(
      OdenRev2HostSpawnEdge::DenoSpawnChild,
      Vec::new(),
      0,
    )
    .expect("the generated zero-or-more launch contract permits no exports");
    let oversized = (0..=MAX_HOST_CHILD_EXPORTS)
      .map(|index| {
        OdenRev2HostChildExport::capture_broker_env_read_host(
          OdenRev2HostSpawnEdge::DenoSpawnChild,
          "owner:pkg",
          "0",
          format!("TOKEN_{index}"),
          "value",
          OdenRev2RequiredForCommit::Required,
        )
      })
      .collect::<Result<Vec<_>, _>>()
      .unwrap();
    assert!(matches!(
      OdenRev2HostLaunchSeal::capture_spawn_host(
        OdenRev2HostSpawnEdge::DenoSpawnChild,
        oversized,
        MAX_HOST_LAUNCH_PAYLOAD_BYTES,
      ),
      Err(OdenRev2HostError::InvalidLaunchSeal)
    ));
    let deno = OdenRev2HostChildExport::capture_broker_env_read_host(
      OdenRev2HostSpawnEdge::DenoSpawnChild,
      "owner:pkg",
      "0",
      "TOKEN",
      "value",
      OdenRev2RequiredForCommit::Required,
    )
    .unwrap();
    assert!(matches!(
      OdenRev2HostLaunchSeal::capture_spawn_host(
        OdenRev2HostSpawnEdge::NodeSpawnChild,
        vec![deno],
        1024,
      ),
      Err(OdenRev2HostError::InvalidLaunchSeal)
    ));
    let first = OdenRev2HostChildExport::capture_broker_env_read_host(
      OdenRev2HostSpawnEdge::DenoSpawnChild,
      "owner:pkg",
      "0",
      "DUPLICATE",
      "one",
      OdenRev2RequiredForCommit::Required,
    )
    .unwrap();
    let second = OdenRev2HostChildExport::capture_literal_env_write_host(
      OdenRev2HostSpawnEdge::DenoSpawnChild,
      "owner:pkg",
      "0",
      "DUPLICATE",
      "two",
    )
    .unwrap();
    assert!(matches!(
      OdenRev2HostLaunchSeal::capture_spawn_host(
        OdenRev2HostSpawnEdge::DenoSpawnChild,
        vec![first, second],
        1024,
      ),
      Err(OdenRev2HostError::InvalidLaunchSeal)
    ));

    let prepared = || {
      let sealed = OdenRev2HostChildExport::capture_broker_env_read_host(
        OdenRev2HostSpawnEdge::DenoSpawnChild,
        "owner:pkg",
        "0",
        "TOKEN",
        "value",
        OdenRev2RequiredForCommit::Required,
      )
      .unwrap();
      let mut effect = sealed.effect.clone();
      effect
        .occurrence
        .as_object_mut()
        .unwrap()
        .remove("requiredForCommit");
      effect
    };
    let mut caller_requiredness = prepared();
    caller_requiredness.occurrence["requiredForCommit"] = Value::Bool(false);
    assert!(matches!(
      OdenRev2HostChildExport::capture_prepared_host(
        OdenRev2HostSpawnEdge::DenoSpawnChild,
        OdenRev2HostChildExportKind::BrokerRead,
        caller_requiredness,
        OdenRev2SecretString::new("value".to_string()),
        OdenRev2RequiredForCommit::Required,
      ),
      Err(OdenRev2HostError::UntrustedRequiredForCommit)
    ));
    let mut wrong_edge = prepared();
    wrong_edge.edge_id = ENV_EDGE.to_string();
    let mut wrong_slot = prepared();
    wrong_slot.effect_slot_id = ENV_SLOT.to_string();
    let mut wrong_capability = prepared();
    wrong_capability.capability = "env:write".to_string();
    let mut wrong_target_kind = prepared();
    wrong_target_kind.occurrence["targetKind"] =
      Value::String("process".to_string());
    let mut wrong_owner = prepared();
    wrong_owner.occurrence["effectOwner"] =
      Value::String("owner:other".to_string());
    let mut wrong_generation = prepared();
    wrong_generation.occurrence["ownerGeneration"] =
      Value::String("01".to_string());
    let mut empty_name = prepared();
    empty_name.occurrence["name"] = Value::String(String::new());
    for forged in [
      wrong_edge,
      wrong_slot,
      wrong_capability,
      wrong_target_kind,
      wrong_owner,
      wrong_generation,
      empty_name,
    ] {
      assert!(matches!(
        OdenRev2HostChildExport::capture_prepared_host(
          OdenRev2HostSpawnEdge::DenoSpawnChild,
          OdenRev2HostChildExportKind::BrokerRead,
          forged,
          OdenRev2SecretString::new("value".to_string()),
          OdenRev2RequiredForCommit::Required,
        ),
        Err(OdenRev2HostError::InvalidChildExport)
      ));
    }
    let empty_value = OdenRev2HostChildExport::capture_broker_env_read_host(
      OdenRev2HostSpawnEdge::DenoSpawnChild,
      "owner:pkg",
      "0",
      "EMPTY_VALUE",
      "",
      OdenRev2RequiredForCommit::Required,
    )
    .expect("empty environment values are valid launch data");
    assert!(empty_value.value.is_empty());
  }

  #[test]
  fn launch_validation_enforces_platform_names_and_both_payload_budgets() {
    assert_eq!(
      env_name_collision_key("PATH", OdenRev2EnvNamePlatform::Windows),
      env_name_collision_key("Path", OdenRev2EnvNamePlatform::Windows)
    );
    assert_ne!(
      env_name_collision_key("PATH", OdenRev2EnvNamePlatform::Posix),
      env_name_collision_key("Path", OdenRev2EnvNamePlatform::Posix)
    );
    assert_eq!(
      encoded_env_entry_bytes("é", "", OdenRev2EnvNamePlatform::Posix),
      Some(4)
    );
    assert_eq!(
      encoded_env_entry_bytes("é", "", OdenRev2EnvNamePlatform::Windows),
      Some(6)
    );

    for invalid_name in ["", "A=B", "A\0B"] {
      assert!(matches!(
        OdenRev2HostChildExport::capture_broker_env_read_host(
          OdenRev2HostSpawnEdge::DenoSpawnChild,
          "owner:pkg",
          "0",
          invalid_name,
          "value",
          OdenRev2RequiredForCommit::Required,
        ),
        Err(OdenRev2HostError::InvalidChildExport)
      ));
    }
    assert!(matches!(
      OdenRev2HostChildExport::capture_broker_env_read_host(
        OdenRev2HostSpawnEdge::DenoSpawnChild,
        "owner:pkg",
        "0",
        "N".repeat(MAX_HOST_CHILD_EXPORT_NAME_BYTES + 1),
        "value",
        OdenRev2RequiredForCommit::Required,
      ),
      Err(OdenRev2HostError::InvalidChildExport)
    ));
    OdenRev2HostChildExport::capture_broker_env_read_host(
      OdenRev2HostSpawnEdge::DenoSpawnChild,
      "owner:pkg",
      "0",
      "MAX_VALUE",
      "v".repeat(MAX_HOST_CHILD_EXPORT_VALUE_BYTES),
      OdenRev2RequiredForCommit::Required,
    )
    .expect("the governing 256 KiB decoded-value boundary is inclusive");
    for invalid_value in [
      "A\0B".to_string(),
      "v".repeat(MAX_HOST_CHILD_EXPORT_VALUE_BYTES + 1),
    ] {
      assert!(matches!(
        OdenRev2HostChildExport::capture_broker_env_read_host(
          OdenRev2HostSpawnEdge::DenoSpawnChild,
          "owner:pkg",
          "0",
          "TOKEN",
          invalid_value,
          OdenRev2RequiredForCommit::Required,
        ),
        Err(OdenRev2HostError::InvalidChildExport)
      ));
    }

    let make_target_entry = || {
      OdenRev2HostChildExport::capture_broker_env_read_host(
        OdenRev2HostSpawnEdge::DenoSpawnChild,
        "owner:pkg",
        "0",
        "TOKEN",
        "value",
        OdenRev2RequiredForCommit::Required,
      )
      .unwrap()
    };
    let exact_target_budget = encoded_env_entry_bytes(
      "TOKEN",
      "value",
      OdenRev2EnvNamePlatform::current(),
    )
    .unwrap();
    OdenRev2HostLaunchSeal::capture_spawn_host(
      OdenRev2HostSpawnEdge::DenoSpawnChild,
      vec![make_target_entry()],
      exact_target_budget,
    )
    .expect("the exact encoded target budget is inclusive");
    assert!(matches!(
      OdenRev2HostLaunchSeal::capture_spawn_host(
        OdenRev2HostSpawnEdge::DenoSpawnChild,
        vec![make_target_entry()],
        exact_target_budget - 1,
      ),
      Err(OdenRev2HostError::InvalidLaunchSeal)
    ));

    let over_global_budget = (0..4)
      .map(|index| {
        OdenRev2HostChildExport::capture_broker_env_read_host(
          OdenRev2HostSpawnEdge::DenoSpawnChild,
          "owner:pkg",
          "0",
          format!("TOKEN_{index}"),
          "v".repeat(MAX_HOST_CHILD_EXPORT_VALUE_BYTES),
          OdenRev2RequiredForCommit::Required,
        )
      })
      .collect::<Result<Vec<_>, _>>()
      .unwrap();
    assert!(matches!(
      OdenRev2HostLaunchSeal::capture_spawn_host(
        OdenRev2HostSpawnEdge::DenoSpawnChild,
        over_global_budget,
        usize::MAX,
      ),
      Err(OdenRev2HostError::InvalidLaunchSeal)
    ));
  }

  #[test]
  fn secret_owner_drop_primitive_overwrites_in_place_and_preserves_utf8() {
    let mut secret = String::from("sëcret-value");
    let initialized_len = secret.len();
    best_effort_zeroize_string(&mut secret);
    assert_eq!(secret.len(), initialized_len);
    assert!(secret.as_bytes().iter().all(|byte| *byte == 0));
    assert!(std::str::from_utf8(secret.as_bytes()).is_ok());

    let entry = OdenRev2CommittedLaunchEntry {
      name: "TOKEN".to_string(),
      value: "transferred-secret".to_string(),
    };
    assert!(!format!("{entry:?}").contains("transferred-secret"));
    let (name, mut value) = entry.into_name_value();
    assert_eq!(name, "TOKEN");
    assert_eq!(value, "transferred-secret");
    best_effort_zeroize_string(&mut value);
  }

  #[test]
  fn invalid_child_export_construction_drops_zeroizing_value_guards() {
    let before = secret_guard_drop_count();
    let broker_secret = "broker-invalid-secret";
    let principal_secret = "principal-invalid-secret";
    let literal_secret = "literal-invalid-secret";

    let broker = OdenRev2HostChildExport::capture_broker_env_read_host(
      OdenRev2HostSpawnEdge::DenoSpawnChild,
      "owner:pkg",
      "0",
      "",
      broker_secret,
      OdenRev2RequiredForCommit::Required,
    )
    .unwrap_err();
    let principal =
      OdenRev2HostChildExport::capture_principal_overlay_env_read_host(
        OdenRev2HostSpawnEdge::NodeSpawnChild,
        "owner:pkg",
        "01",
        "TOKEN",
        principal_secret,
        OdenRev2RequiredForCommit::Optional,
      )
      .unwrap_err();
    let literal = OdenRev2HostChildExport::capture_literal_env_write_host(
      OdenRev2HostSpawnEdge::DeprecatedRun,
      "owner:pkg",
      "0",
      "A=B",
      literal_secret,
    )
    .unwrap_err();

    assert_eq!(secret_guard_drop_count(), before + 3);
    let diagnostics = format!("{broker}; {principal}; {literal}");
    for secret in [broker_secret, principal_secret, literal_secret] {
      assert!(!diagnostics.contains(secret));
    }
  }

  #[test]
  fn launch_commit_returns_only_authorized_one_shot_values() {
    for edge in spawn_edges() {
      let required = OdenRev2HostChildExport::capture_broker_env_read_host(
        edge,
        "owner:pkg",
        "0",
        "REQUIRED",
        "required-secret",
        OdenRev2RequiredForCommit::Required,
      )
      .unwrap();
      let optional =
        OdenRev2HostChildExport::capture_principal_overlay_env_read_host(
          edge,
          "owner:pkg",
          "0",
          "OPTIONAL",
          "optional-secret",
          OdenRev2RequiredForCommit::Optional,
        )
        .unwrap();
      let literal = OdenRev2HostChildExport::capture_literal_env_write_host(
        edge,
        "owner:pkg",
        "0",
        "LITERAL",
        "literal-secret",
      )
      .unwrap();
      let empty = OdenRev2HostChildExport::capture_broker_env_read_host(
        edge,
        "owner:pkg",
        "0",
        "EMPTY",
        "",
        OdenRev2RequiredForCommit::Required,
      )
      .unwrap();
      let request = StageRequest {
        identity: EngineIdentity::embedded(),
        stage_id: "spawn-filtered".to_string(),
        principals: vec![package()],
        effects: vec![
          spawn_effect(edge),
          required.effect.clone(),
          optional.effect.clone(),
          literal.effect.clone(),
          empty.effect.clone(),
        ],
      };
      let seal = OdenRev2HostLaunchSeal::capture_spawn_host(
        edge,
        vec![required, optional, literal, empty],
        1024,
      )
      .unwrap();
      let policy =
        spawn_policy(&["REQUIRED", "EMPTY"], &["LITERAL"], &["OPTIONAL"]);
      let mut actor = spawn_actor(&policy, seal);
      assert!(matches!(
        actor
          .authorize_initial(
            &request,
            &policy,
            OdenRev2HostInteraction::NonInteractive,
          )
          .unwrap(),
        OdenRev2HostAuthorization::Authorized { .. }
      ));
      let OdenRev2HostCommit::Committed {
        launch_payload: Some(payload),
        ..
      } = actor.commit_authorized(&policy).unwrap()
      else {
        panic!("a sealed spawn commit must return its host-only payload");
      };
      let debug = format!("{payload:?}");
      assert!(!debug.contains("required-secret"));
      assert!(!debug.contains("optional-secret"));
      assert!(!debug.contains("literal-secret"));
      assert_eq!(payload.edge_id(), edge.edge_id());
      assert_eq!(
        payload.payload_bytes,
        [
          ("REQUIRED", "required-secret"),
          ("LITERAL", "literal-secret"),
          ("EMPTY", ""),
        ]
        .into_iter()
        .map(|(name, value)| {
          encoded_env_entry_bytes(
            name,
            value,
            OdenRev2EnvNamePlatform::current(),
          )
          .unwrap()
        })
        .sum::<usize>()
      );
      assert_eq!(
        payload
          .entries()
          .iter()
          .map(|entry| (entry.name(), entry.value()))
          .collect::<Vec<_>>(),
        [
          ("REQUIRED", "required-secret"),
          ("LITERAL", "literal-secret"),
          ("EMPTY", ""),
        ]
      );
      assert!(matches!(
        actor.commit_authorized(&policy),
        Err(OdenRev2HostError::NoPendingPermit)
      ));
    }
  }

  #[test]
  fn required_mask_revocation_and_empty_launch_never_expose_extra_values() {
    for edge in spawn_edges() {
      let canceled_export =
        OdenRev2HostChildExport::capture_broker_env_read_host(
          edge,
          "owner:pkg",
          "0",
          "CANCELED",
          "cancel-secret",
          OdenRev2RequiredForCommit::Required,
        )
        .unwrap();
      let canceled_seal = OdenRev2HostLaunchSeal::capture_spawn_host(
        edge,
        vec![canceled_export],
        1024,
      )
      .unwrap();
      let canceled_policy = spawn_policy(&["CANCELED"], &[], &[]);
      let mut canceled_actor = spawn_actor(&canceled_policy, canceled_seal);
      assert!(canceled_actor.sealed_launch.is_some());
      canceled_actor.cancel();
      assert!(canceled_actor.sealed_launch.is_none());

      let restart_export =
        OdenRev2HostChildExport::capture_broker_env_read_host(
          edge,
          "owner:pkg",
          "0",
          "RESTART",
          "restart-secret",
          OdenRev2RequiredForCommit::Required,
        )
        .unwrap();
      let restart_request = StageRequest {
        identity: EngineIdentity::embedded(),
        stage_id: "spawn-restart".to_string(),
        principals: vec![package()],
        effects: vec![spawn_effect(edge), restart_export.effect.clone()],
      };
      let restart_seal = OdenRev2HostLaunchSeal::capture_spawn_host(
        edge,
        vec![restart_export],
        1024,
      )
      .unwrap();
      let restart_policy = spawn_policy(&["RESTART"], &[], &[]);
      let mut restart_actor = spawn_actor(&restart_policy, restart_seal);
      assert!(matches!(
        restart_actor
          .authorize_initial(
            &restart_request,
            &restart_policy,
            OdenRev2HostInteraction::MayPrompt,
          )
          .unwrap(),
        OdenRev2HostAuthorization::RestartRequired(_)
      ));
      assert!(restart_actor.sealed_launch.is_none());

      let required = OdenRev2HostChildExport::capture_broker_env_read_host(
        edge,
        "owner:pkg",
        "0",
        "REQUIRED",
        "must-not-escape",
        OdenRev2RequiredForCommit::Required,
      )
      .unwrap();
      let required_request = StageRequest {
        identity: EngineIdentity::embedded(),
        stage_id: "spawn-required-mask".to_string(),
        principals: vec![package()],
        effects: vec![spawn_effect(edge), required.effect.clone()],
      };
      let required_seal =
        OdenRev2HostLaunchSeal::capture_spawn_host(edge, vec![required], 1024)
          .unwrap();
      let masked_policy = spawn_policy(&[], &[], &["REQUIRED"]);
      let mut required_actor = spawn_actor(&masked_policy, required_seal);
      let required_released = Rc::new(Cell::new(false));
      let release = required_released.clone();
      required_actor
        .hold_provisional("rid:required-mask", move || release.set(true))
        .unwrap();
      assert!(matches!(
        required_actor
          .authorize_initial(
            &required_request,
            &masked_policy,
            OdenRev2HostInteraction::NonInteractive,
          )
          .unwrap(),
        OdenRev2HostAuthorization::Denied(_)
      ));
      assert!(required_released.get());
      assert!(required_actor.sealed_launch.is_none());
      assert!(matches!(
        required_actor.commit_authorized(&masked_policy),
        Err(OdenRev2HostError::NoPendingPermit)
      ));

      let allowed = OdenRev2HostChildExport::capture_broker_env_read_host(
        edge,
        "owner:pkg",
        "0",
        "ALLOWED",
        "revoked-before-commit",
        OdenRev2RequiredForCommit::Required,
      )
      .unwrap();
      let revocation_request = StageRequest {
        identity: EngineIdentity::embedded(),
        stage_id: "spawn-revoked".to_string(),
        principals: vec![package()],
        effects: vec![spawn_effect(edge), allowed.effect.clone()],
      };
      let allowed_seal =
        OdenRev2HostLaunchSeal::capture_spawn_host(edge, vec![allowed], 1024)
          .unwrap();
      let allow_policy = spawn_policy(&["ALLOWED"], &[], &[]);
      let released = Rc::new(Cell::new(false));
      let mut revoked_actor = spawn_actor(&allow_policy, allowed_seal);
      let release = released.clone();
      revoked_actor
        .hold_provisional("rid:revoked-launch", move || release.set(true))
        .unwrap();
      revoked_actor
        .authorize_initial(
          &revocation_request,
          &allow_policy,
          OdenRev2HostInteraction::NonInteractive,
        )
        .unwrap();
      let mut revoked_policy = allow_policy.clone();
      revoked_policy.generations.revocation = "1".to_string();
      revoked_policy.session_revocations =
        vec![named("revocation:ALLOWED", env_selector("ALLOWED"))];
      assert!(matches!(
        revoked_actor.commit_authorized(&revoked_policy).unwrap(),
        OdenRev2HostCommit::Denied(_)
      ));
      assert!(released.get());
      assert!(revoked_actor.sealed_launch.is_none());

      let empty_seal =
        OdenRev2HostLaunchSeal::capture_spawn_host(edge, Vec::new(), 0)
          .unwrap();
      let empty_policy = spawn_policy(&[], &[], &[]);
      let empty_request = StageRequest {
        identity: EngineIdentity::embedded(),
        stage_id: "spawn-empty".to_string(),
        principals: vec![package()],
        effects: vec![spawn_effect(edge)],
      };
      let mut empty_actor = spawn_actor(&empty_policy, empty_seal);
      empty_actor
        .authorize_initial(
          &empty_request,
          &empty_policy,
          OdenRev2HostInteraction::NonInteractive,
        )
        .unwrap();
      let OdenRev2HostCommit::Committed {
        launch_payload: Some(empty),
        ..
      } = empty_actor.commit_authorized(&empty_policy).unwrap()
      else {
        panic!("an empty sealed launch still returns a typed empty payload");
      };
      assert!(empty.entries().is_empty());
      assert!(empty_actor.sealed_launch.is_none());
    }
  }

  #[test]
  fn native_binding_uses_only_the_exact_host_bound_stage_and_is_one_shot() {
    let target = "127.0.0.1:9229";
    struct ResetAttribution;
    impl Drop for ResetAttribution {
      fn drop(&mut self) {
        crate::prompter::clear_current_oden_stacktrace();
        crate::prompter::set_current_oden_cped_locator(None);
        crate::prompter::set_current_oden_cped_stack(None);
        crate::prompter::set_current_oden_trusted_host_actor(false);
      }
    }
    let _reset = ResetAttribution;
    let locator =
      format!("file://{}/rev2-native-test.ts", env!("CARGO_MANIFEST_DIR"));
    crate::prompter::set_current_oden_stacktrace(Box::new(move || {
      vec![crate::prompter::OdenStackFrame {
        isolate_id: Some(24015),
        script_id: Some(24016),
        locator: Some(locator.clone()),
        display_name: None,
      }]
    }));
    crate::prompter::set_current_oden_cped_locator(None);
    crate::prompter::set_current_oden_cped_stack(None);
    crate::prompter::set_current_oden_trusted_host_actor(false);

    let allow = inspector_policy(target, root());
    let mut mismatch_context =
      OdenRev2ArmedContext::capture_host(actor_for(&allow, root()));
    let supplied = allow.clone();
    mismatch_context
      .arm_protected_inspector_stream_stage(
        target,
        "native-test",
        "native",
        move || Ok(supplied.clone()),
        false,
        OdenRev2HostInteraction::NonInteractive,
      )
      .unwrap();
    assert!(
      mismatch_context
        .consume_protected_inspector_stream_stage(
          "127.0.0.1:9228",
          "native-test"
        )
        .is_err()
    );
    assert!(mismatch_context.protected_inspector_stream_stage.is_none());

    let mut context =
      OdenRev2ArmedContext::capture_host(actor_for(&allow, root()));
    let supplied = allow.clone();
    let provider_calls = Rc::new(Cell::new(0));
    let calls = provider_calls.clone();
    context
      .arm_protected_inspector_stream_stage(
        target,
        "native-test",
        "native-success",
        move || {
          calls.set(calls.get() + 1);
          Ok(supplied.clone())
        },
        false,
        OdenRev2HostInteraction::NonInteractive,
      )
      .unwrap();
    let result =
      context.consume_protected_inspector_stream_stage(target, "native-test");
    assert!(result.is_ok(), "{result:?}");
    assert_eq!(provider_calls.get(), 2);
    assert!(
      context
        .consume_protected_inspector_stream_stage(target, "native-test")
        .is_err()
    );
  }

  #[test]
  fn native_policy_provider_is_live_at_both_barriers_and_failure_releases() {
    struct ResetAttribution;
    impl Drop for ResetAttribution {
      fn drop(&mut self) {
        crate::prompter::clear_current_oden_stacktrace();
        crate::prompter::set_current_oden_cped_locator(None);
        crate::prompter::set_current_oden_cped_stack(None);
        crate::prompter::set_current_oden_trusted_host_actor(false);
      }
    }
    let _reset = ResetAttribution;
    let locator = format!(
      "file://{}/rev2-live-policy-test.ts",
      env!("CARGO_MANIFEST_DIR")
    );
    crate::prompter::set_current_oden_stacktrace(Box::new(move || {
      vec![crate::prompter::OdenStackFrame {
        isolate_id: Some(24017),
        script_id: Some(24018),
        locator: Some(locator.clone()),
        display_name: None,
      }]
    }));
    crate::prompter::set_current_oden_cped_locator(None);
    crate::prompter::set_current_oden_cped_stack(None);
    crate::prompter::set_current_oden_trusted_host_actor(false);

    let target = "127.0.0.1:9229";
    let allow = inspector_policy(target, root());
    let mut revoked = allow.clone();
    revoked.generations.revocation = "1".to_string();
    revoked.session_revocations = vec![named(
      "revocation:inspector",
      allow.static_floor[0].selector.clone(),
    )];
    let released = Rc::new(Cell::new(false));
    let calls = Rc::new(Cell::new(0));
    let mut context =
      OdenRev2ArmedContext::capture_host(actor_for(&allow, root()));
    let release = released.clone();
    context
      .hold_provisional("rid:live-policy", move || release.set(true))
      .unwrap();
    let provider_calls = calls.clone();
    context
      .arm_protected_inspector_stream_stage(
        target,
        "native-live-policy",
        "native-live-policy",
        move || {
          let call = provider_calls.get();
          provider_calls.set(call + 1);
          if call == 0 {
            Ok(allow.clone())
          } else {
            Ok(revoked.clone())
          }
        },
        false,
        OdenRev2HostInteraction::NonInteractive,
      )
      .unwrap();
    let error = context
      .consume_protected_inspector_stream_stage(target, "native-live-policy")
      .unwrap_err();
    assert!(error.to_string().contains("authorization did not commit"));
    assert_eq!(calls.get(), 2);
    assert!(released.get());

    let provider_failure_released = Rc::new(Cell::new(false));
    let mut failure = OdenRev2ArmedContext::capture_host(actor_for(
      &inspector_policy(target, root()),
      root(),
    ));
    let release = provider_failure_released.clone();
    failure
      .hold_provisional("rid:provider-failure", move || release.set(true))
      .unwrap();
    failure
      .arm_protected_inspector_stream_stage(
        target,
        "native-provider-failure",
        "native-provider-failure",
        || Err(OdenRev2HostError::InvalidNativeStage),
        false,
        OdenRev2HostInteraction::NonInteractive,
      )
      .unwrap();
    assert!(
      failure
        .consume_protected_inspector_stream_stage(
          target,
          "native-provider-failure"
        )
        .is_err()
    );
    assert!(provider_failure_released.get());
  }

  #[test]
  fn armed_context_cleanup_and_discovery_reentry_preserve_stage_order() {
    struct ResetAttribution;
    impl Drop for ResetAttribution {
      fn drop(&mut self) {
        crate::prompter::clear_current_oden_stacktrace();
        crate::prompter::set_current_oden_cped_locator(None);
        crate::prompter::set_current_oden_cped_stack(None);
        crate::prompter::set_current_oden_trusted_host_actor(false);
      }
    }
    let _reset = ResetAttribution;
    let locator = format!(
      "file://{}/rev2-context-discovery-test.ts",
      env!("CARGO_MANIFEST_DIR")
    );
    crate::prompter::set_current_oden_stacktrace(Box::new(move || {
      vec![crate::prompter::OdenStackFrame {
        isolate_id: Some(24023),
        script_id: Some(24024),
        locator: Some(locator.clone()),
        display_name: None,
      }]
    }));
    crate::prompter::set_current_oden_cped_locator(None);
    crate::prompter::set_current_oden_cped_stack(None);
    crate::prompter::set_current_oden_trusted_host_actor(false);

    let target = "127.0.0.1:9229";
    let allow = inspector_policy(target, root());
    let mut context =
      OdenRev2ArmedContext::capture_host(actor_for(&allow, root()));
    let released = Rc::new(Cell::new(false));
    let release = released.clone();
    context
      .hold_provisional("rid:cleanup-forward", move || release.set(true))
      .unwrap();
    let abandoned_provider_calls = Rc::new(Cell::new(0));
    let calls = abandoned_provider_calls.clone();
    let supplied = allow.clone();
    context
      .arm_protected_inspector_stream_stage(
        target,
        "native-cleanup-discovery",
        "abandoned-before-authorization",
        move || {
          calls.set(calls.get() + 1);
          Ok(supplied.clone())
        },
        false,
        OdenRev2HostInteraction::NonInteractive,
      )
      .unwrap();
    let cleanup = context.cleanup_non_authorizing().unwrap();
    assert_eq!(
      cleanup.released_provisional_resources,
      ["rid:cleanup-forward"]
    );
    assert!(released.get());
    assert_eq!(abandoned_provider_calls.get(), 0);

    let supplied = allow.clone();
    context
      .arm_protected_inspector_stream_stage(
        target,
        "native-cleanup-discovery",
        "initial-after-cleanup",
        move || Ok(supplied.clone()),
        false,
        OdenRev2HostInteraction::NonInteractive,
      )
      .unwrap();
    context
      .consume_protected_inspector_stream_stage(
        target,
        "native-cleanup-discovery",
      )
      .unwrap();

    let supplied = allow.clone();
    context
      .arm_protected_inspector_stream_stage(
        target,
        "native-cleanup-discovery",
        "discovery-reentry",
        move || Ok(supplied.clone()),
        true,
        OdenRev2HostInteraction::NonInteractive,
      )
      .unwrap();
    context
      .consume_protected_inspector_stream_stage(
        target,
        "native-cleanup-discovery",
      )
      .unwrap();
    assert_eq!(
      context.actor.as_ref().unwrap().completed_stages(),
      ["initial-after-cleanup", "discovery-reentry"]
    );
    assert!(context.complete().unwrap().is_empty());
  }

  #[test]
  fn exact_arm_and_live_match_preserve_frame_and_cped_locator_bindings() {
    struct ResetAttribution;
    impl Drop for ResetAttribution {
      fn drop(&mut self) {
        crate::prompter::clear_current_oden_stacktrace();
        crate::prompter::set_current_oden_cped_locator(None);
        crate::prompter::set_current_oden_cped_stack(None);
        crate::prompter::set_current_oden_trusted_host_actor(false);
      }
    }
    let _reset = ResetAttribution;
    let frame_locator =
      "file:///oden-rev2/node_modules/frame-package/index.js".to_string();
    let cped_locator =
      "file:///oden-rev2/node_modules/cped-package/callback.js".to_string();
    crate::prompter::set_current_oden_stacktrace(Box::new(move || {
      vec![crate::prompter::OdenStackFrame {
        isolate_id: Some(24019),
        script_id: Some(24020),
        locator: Some(frame_locator.clone()),
        display_name: None,
      }]
    }));
    crate::prompter::set_current_oden_cped_locator(Some(cped_locator));
    crate::prompter::set_current_oden_cped_stack(None);
    crate::prompter::set_current_oden_trusted_host_actor(false);

    let principals = crate::oden_rev2_capture_live_principals();
    assert_eq!(principals.len(), 2);
    assert!(principals.iter().all(|principal| {
      principal.kind == PrincipalKind::Package
        && principal.key.contains("#locator:")
    }));

    let target = "127.0.0.1:9229";
    let mut allow = policy(&[]);
    allow.static_floor = principals
      .iter()
      .enumerate()
      .map(|(index, principal)| {
        named(
          &format!("floor:inspector:{index}"),
          AuthoritySelectorInput {
            identity: EngineIdentity::embedded(),
            principal: Some(principal.clone()),
            capability: PROTECTED_INSPECTOR_CAPABILITY.to_string(),
            resource: json!({
              "route": { "attestation": null, "endpoint": null, "kind": "direct" },
              "session": { "kind": "inspector", "value": target },
            }),
          },
        )
      })
      .collect();
    let actor = OdenRev2HostActor::capture_host(
      "operation:exact-live-attribution",
      "actor:exact-live-attribution",
      principals.clone(),
      "owner:pkg",
      principals[0].clone(),
      "0",
      None,
      &allow,
    )
    .unwrap();
    let supplied = allow.clone();
    let mut context = OdenRev2ArmedContext::capture_host(actor);
    context
      .arm_protected_inspector_stream_stage(
        target,
        "native-exact-live-attribution",
        "native-exact-live-attribution",
        move || Ok(supplied.clone()),
        false,
        OdenRev2HostInteraction::NonInteractive,
      )
      .unwrap();
    assert!(
      context
        .consume_protected_inspector_stream_stage(
          target,
          "native-exact-live-attribution"
        )
        .is_ok()
    );
  }

  #[test]
  fn native_binding_rejects_edge_slot_capability_principal_owner_and_target_substitution()
   {
    let target = "127.0.0.1:9229";
    let allow = inspector_policy(target, package());
    let mut context = OdenRev2ArmedContext::capture_host(actor(&allow));
    let request = context
      .actor
      .as_ref()
      .unwrap()
      .protected_inspector_stream_request("native", target)
      .unwrap();
    let mut variants = Vec::new();
    let mut wrong_edge = request.clone();
    wrong_edge.effects[0].edge_id = ENV_EDGE.to_string();
    variants.push(wrong_edge);
    let mut wrong_slot = request.clone();
    wrong_slot.effects[0].effect_slot_id = ENV_SLOT.to_string();
    variants.push(wrong_slot);
    let mut wrong_capability = request.clone();
    wrong_capability.effects[0].capability = "env:read".to_string();
    variants.push(wrong_capability);
    let mut wrong_principal = request.clone();
    wrong_principal.principals.clear();
    variants.push(wrong_principal);
    let mut wrong_owner = request.clone();
    wrong_owner.effects[0].effect_owner = "owner:other".to_string();
    variants.push(wrong_owner);
    let mut wrong_target = request;
    wrong_target.effects[0].occurrence["listener"]["value"] =
      Value::String("127.0.0.1:9230".to_string());
    variants.push(wrong_target);

    for variant in variants {
      assert!(matches!(
        context.arm_prepared_protected_inspector_stream_stage(
          target.to_string(),
          "native-test".to_string(),
          variant,
          Box::new({
            let allow = allow.clone();
            move || Ok(allow.clone())
          }),
          false,
          OdenRev2HostInteraction::NonInteractive,
        ),
        Err(OdenRev2HostError::InvalidNativeStage)
      ));
      assert!(context.protected_inspector_stream_stage.is_none());
    }
  }

  #[test]
  fn live_attribution_preserves_package_intersection_and_rejects_nouser_or_quarantine()
   {
    let package_principal = crate::OdenPrincipal::Package {
      name: "a".to_string(),
      version: Some("1.0.0".to_string()),
    };
    let frame_locator = "file:///app/node_modules/a/frame.ts";
    let cped_locator = "file:///app/node_modules/a/callback.ts";
    let frame = crate::oden_rev2_map_attributed_principal(
      package_principal.clone(),
      Some(frame_locator),
    );
    let cped = crate::oden_rev2_map_attributed_principal(
      package_principal.clone(),
      Some(cped_locator),
    );
    assert_eq!(frame.kind, PrincipalKind::Package);
    assert_eq!(
      frame.key,
      crate::oden_capsec_compartment_key(
        &package_principal,
        Some(frame_locator)
      )
    );
    assert_eq!(cped.kind, PrincipalKind::Package);
    assert_eq!(
      cped.key,
      crate::oden_capsec_compartment_key(
        &package_principal,
        Some(cped_locator)
      )
    );
    assert_ne!(frame.key, cped.key);
    for (principal, kind, key) in [
      (
        crate::OdenPrincipal::NoUser,
        PrincipalKind::NoUser,
        "no-user",
      ),
      (
        crate::OdenPrincipal::Quarantine,
        PrincipalKind::Quarantine,
        "quarantine",
      ),
    ] {
      assert_eq!(
        crate::oden_rev2_map_attributed_principal(
          principal,
          Some("file:///must-not-bind-sentinel.ts")
        ),
        PrincipalRef {
          kind,
          key: key.to_string(),
        }
      );
    }

    struct ResetAttribution;
    impl Drop for ResetAttribution {
      fn drop(&mut self) {
        crate::prompter::clear_current_oden_stacktrace();
        crate::prompter::set_current_oden_cped_locator(None);
        crate::prompter::set_current_oden_cped_stack(None);
        crate::prompter::set_current_oden_trusted_host_actor(false);
      }
    }
    let _reset = ResetAttribution;
    crate::prompter::set_current_oden_cped_locator(None);
    crate::prompter::set_current_oden_cped_stack(None);
    crate::prompter::set_current_oden_trusted_host_actor(false);
    crate::prompter::set_current_oden_stacktrace(Box::new(Vec::new));

    let target = "127.0.0.1:9229";
    let allow = inspector_policy(target, package());
    let mut context = OdenRev2ArmedContext::capture_host(actor(&allow));
    let supplied = allow.clone();
    context
      .arm_protected_inspector_stream_stage(
        target,
        "native-attribution-test",
        "native-attribution",
        move || Ok(supplied.clone()),
        false,
        OdenRev2HostInteraction::NonInteractive,
      )
      .unwrap();
    let no_user = context
      .consume_protected_inspector_stream_stage(
        target,
        "native-attribution-test",
      )
      .unwrap_err();
    assert!(no_user.to_string().contains("live op/CPED principals"));
    assert!(context.protected_inspector_stream_stage.is_none());

    let mut quarantine_context =
      OdenRev2ArmedContext::capture_host(actor(&allow));
    let supplied = allow.clone();
    quarantine_context
      .arm_protected_inspector_stream_stage(
        target,
        "native-attribution-test",
        "native-attribution-quarantine",
        move || Ok(supplied.clone()),
        false,
        OdenRev2HostInteraction::NonInteractive,
      )
      .unwrap();

    crate::prompter::set_current_oden_stacktrace(Box::new(|| {
      vec![crate::prompter::OdenStackFrame {
        isolate_id: Some(24015),
        script_id: Some(24015),
        locator: None,
        display_name: Some("file:///untrusted-package.js".to_string()),
      }]
    }));
    let quarantine = quarantine_context
      .consume_protected_inspector_stream_stage(
        target,
        "native-attribution-test",
      )
      .unwrap_err();
    assert!(quarantine.to_string().contains("live op/CPED principals"));
    assert!(
      quarantine_context
        .protected_inspector_stream_stage
        .is_none()
    );
  }

  #[test]
  fn runtime_integration_does_not_advertise_rev2() {
    assert!(crate::rev2_registry_generated::REV2_ADVERTISED_TARGETS.is_empty());
  }
}

// Copyright 2018-2026 the Deno authors. MIT license.

//! Sealed synchronous filesystem adapters for the installed Rev2 context.
//!
//! Actor attribution is captured before the namespace gate because stack
//! capture may invoke a host-installed callback. Everything after gate entry is
//! callback-free and retains the exact root, ancestor, parent, and target
//! handles through authorization, actor commit, and result delivery.
//!
//! @ref LLP 0019#paths [implements]
//! @ref LLP 0019#operation-scoped-positive-authority-provenance [implements]

use std::io;
use std::path::Path;

use super::OdenRev2NamespaceOperationGuard;
use super::OdenRev2RuntimeAuthorityContext;
use crate::oden_rev2_runtime::OdenRev2HostFilesystemCompletion;

#[derive(Debug, thiserror::Error)]
pub enum OdenRev2FilesystemError {
  #[error(transparent)]
  Io(#[from] io::Error),
  #[error("{0}")]
  Refused(String),
}

enum LstatDeliveryValue {
  Metadata(std::fs::Metadata),
  NotFound,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OdenRev2FilesystemActorSequenceFaultForTest {
  SubstituteRequest,
  SkipObservation,
  SkipPostPrepareRevalidation,
  SkipNativeCommit,
  MismatchedNativeCommitWitness,
  PanicAfterMutationBegin,
  CompleteAfterNotCommitted,
  RepeatNativeCommit,
}

#[cfg(test)]
thread_local! {
  static ODEN_REV2_FILESYSTEM_ACTOR_SEQUENCE_FAULT_FOR_TEST: std::cell::Cell<Option<OdenRev2FilesystemActorSequenceFaultForTest>> = const { std::cell::Cell::new(None) };
}

#[cfg(test)]
fn set_actor_sequence_fault_for_test(
  fault: Option<OdenRev2FilesystemActorSequenceFaultForTest>,
) {
  ODEN_REV2_FILESYSTEM_ACTOR_SEQUENCE_FAULT_FOR_TEST
    .with(|current| current.set(fault));
}

#[cfg(test)]
fn take_actor_sequence_fault_for_test()
-> Option<OdenRev2FilesystemActorSequenceFaultForTest> {
  ODEN_REV2_FILESYSTEM_ACTOR_SEQUENCE_FAULT_FOR_TEST
    .with(|current| current.take())
}

pub(crate) struct OdenRev2FilesystemDeliveryWitness {
  _private: (),
}

impl OdenRev2FilesystemDeliveryWitness {
  fn new() -> Self {
    Self { _private: () }
  }
}

pub(crate) struct OdenRev2FilesystemNativeCommitWitness<'guard> {
  gate_token: &'guard super::OdenRev2NamespaceGateToken,
  _not_send_sync: std::marker::PhantomData<std::rc::Rc<()>>,
}

impl<'guard> OdenRev2FilesystemNativeCommitWitness<'guard> {
  fn new(gate_token: &'guard super::OdenRev2NamespaceGateToken) -> Self {
    Self {
      gate_token,
      _not_send_sync: std::marker::PhantomData,
    }
  }

  pub(crate) fn gate_token(&self) -> &super::OdenRev2NamespaceGateToken {
    self.gate_token
  }
}

/// @ref LLP 0019#filesystem-actor-resource-ownership-checkpoint-eng-24019
/// [implements] -- Filesystem resources close before authority publication and
/// the namespace gate are released.
struct OdenRev2FilesystemDeliveryLease<'context> {
  resources: Option<OdenRev2HostFilesystemCompletion>,
  guard: Option<OdenRev2NamespaceOperationGuard<'context>>,
}

impl<'context> OdenRev2FilesystemDeliveryLease<'context> {
  fn new(
    resources: OdenRev2HostFilesystemCompletion,
    guard: OdenRev2NamespaceOperationGuard<'context>,
  ) -> Self {
    Self {
      resources: Some(resources),
      guard: Some(guard),
    }
  }
}

impl Drop for OdenRev2FilesystemDeliveryLease<'_> {
  fn drop(&mut self) {
    // Close every operation-local descriptor while authority publication and
    // the process-global namespace gate are still pinned.
    debug_assert!(super::namespace_gate_held_on_current_thread());
    drop(self.resources.take());
    debug_assert!(super::namespace_gate_held_on_current_thread());
    drop(self.guard.take());
  }
}

/// Opaque result whose lifetime keeps the namespace gate and authority
/// publication pinned through the extension's stat serialization or ENOENT
/// construction. Call `finish` only at the synchronous op return boundary.
#[must_use = "the Rev2 delivery token must be finished at the op return boundary"]
pub struct OdenRev2LstatDelivery<'context> {
  value: LstatDeliveryValue,
  _lease: OdenRev2FilesystemDeliveryLease<'context>,
}

impl OdenRev2LstatDelivery<'_> {
  pub fn metadata(&self) -> Option<&std::fs::Metadata> {
    match &self.value {
      LstatDeliveryValue::Metadata(metadata) => Some(metadata),
      LstatDeliveryValue::NotFound => None,
    }
  }

  pub fn is_not_found(&self) -> bool {
    matches!(self.value, LstatDeliveryValue::NotFound)
  }

  pub fn finish(self) {}
}

/// Opaque mkdir result retaining the same pinned delivery boundary for either
/// success or an authorized existing-entry conflict.
#[must_use = "the Rev2 delivery token must be finished at the op return boundary"]
pub struct OdenRev2MkdirDelivery<'context> {
  already_exists: bool,
  _lease: OdenRev2FilesystemDeliveryLease<'context>,
}

impl OdenRev2MkdirDelivery<'_> {
  pub fn already_exists(&self) -> bool {
    self.already_exists
  }

  pub fn finish(self) {}
}

const LSTAT_EDGE: &str = "native-op:ext/fs/ops.rs#op_fs_lstat_sync";
const LSTAT_LIST_SLOT: &str =
  "native-op:ext/fs/ops.rs#op_fs_lstat_sync:effect-slot:0";
const MKDIR_EDGE: &str = "native-op:ext/fs/ops.rs#op_fs_mkdir_sync";
const MKDIR_WRITE_SLOT: &str =
  "native-op:ext/fs/ops.rs#op_fs_mkdir_sync:effect-slot:0";
const MKDIR_LIST_SLOT: &str =
  "native-op:ext/fs/ops.rs#op_fs_mkdir_sync:effect-slot:1";

fn refused(reason: &'static str) -> OdenRev2FilesystemError {
  OdenRev2FilesystemError::Refused(format!("OD-CAP-REV2-FILESYSTEM-{reason}"))
}

/// Resolve and authorize one no-follow metadata observation, returning only
/// retained metadata or an authorized final-entry `ENOENT`.
pub fn oden_capsec_rev2_lstat_sync<'context>(
  context: &'context OdenRev2RuntimeAuthorityContext,
  path: &Path,
) -> Result<OdenRev2LstatDelivery<'context>, OdenRev2FilesystemError> {
  #[cfg(any(target_os = "linux", target_os = "macos"))]
  {
    lstat_sync_supported(context, path)
  }
  #[cfg(not(any(target_os = "linux", target_os = "macos")))]
  {
    let _ = (context, path);
    Err(refused("PLATFORM-UNSUPPORTED"))
  }
}

/// Authorize and atomically create one missing directory through its retained
/// parent. Recursive discovery is outside this dormant first adapter slice.
pub fn oden_capsec_rev2_mkdir_sync<'context>(
  context: &'context OdenRev2RuntimeAuthorityContext,
  path: &Path,
  recursive: bool,
  mode: u32,
) -> Result<OdenRev2MkdirDelivery<'context>, OdenRev2FilesystemError> {
  if recursive {
    // This check intentionally precedes path validation, actor capture, gate
    // acquisition, and every filesystem observation.
    return Err(refused("RECURSIVE-UNSUPPORTED"));
  }
  #[cfg(any(target_os = "linux", target_os = "macos"))]
  {
    mkdir_sync_supported(context, path, mode)
  }
  #[cfg(not(any(target_os = "linux", target_os = "macos")))]
  {
    let _ = (context, path, mode);
    Err(refused("PLATFORM-UNSUPPORTED"))
  }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod supported {
  use std::collections::BTreeSet;
  use std::path::Component;
  use std::path::Path;
  use std::path::PathBuf;

  use serde_json::Value;
  use serde_json::json;

  use super::LSTAT_EDGE;
  use super::LSTAT_LIST_SLOT;
  use super::LstatDeliveryValue;
  use super::MKDIR_EDGE;
  use super::MKDIR_LIST_SLOT;
  use super::MKDIR_WRITE_SLOT;
  use super::OdenRev2FilesystemError;
  use super::OdenRev2LstatDelivery;
  use super::OdenRev2MkdirDelivery;
  use super::OdenRev2RuntimeAuthorityContext;
  use super::refused;
  use crate::oden_rev2_authority::AuthorityRowKind;
  use crate::oden_rev2_context::OdenRev2NamespaceOperationGuard;
  use crate::oden_rev2_context::OdenRev2OperationAuthorityFacts;
  use crate::oden_rev2_fs::OdenRev2FsActorInventory;
  use crate::oden_rev2_fs::OdenRev2FsActorSourceClass;
  use crate::oden_rev2_fs::OdenRev2FsActorSourceEvidence;
  use crate::oden_rev2_fs::OdenRev2FsAuthenticatedRoot;
  use crate::oden_rev2_fs::OdenRev2FsCheckedPath;
  use crate::oden_rev2_fs::OdenRev2FsCheckedTargetKind;
  use crate::oden_rev2_fs::OdenRev2FsError;
  use crate::oden_rev2_fs::OdenRev2FsFollowMode;
  use crate::oden_rev2_fs::OdenRev2FsIdentityState;
  use crate::oden_rev2_fs::OdenRev2FsMkdirCommitOutcome;
  use crate::oden_rev2_fs::OdenRev2FsOperationSession;
  use crate::oden_rev2_fs::OdenRev2FsPlatformIdentity;
  use crate::oden_rev2_fs::OdenRev2FsResolutionStep;
  use crate::oden_rev2_permission::StaticPathRoot;
  use crate::oden_rev2_permission::StaticPathSourceClass;
  use crate::oden_rev2_permission::bound_platform_path;
  use crate::oden_rev2_permission::collect_static_path_roots;
  use crate::oden_rev2_permission::platform_path_value;
  use crate::oden_rev2_permission::relative_platform_path;
  use crate::oden_rev2_permission::select_primary_path_root;
  use crate::oden_rev2_protocol::VerifiedPermissionActorSet;
  use crate::oden_rev2_runtime::OdenRev2FilesystemHostActor;
  use crate::oden_rev2_runtime::OdenRev2HostAuthorization;
  use crate::oden_rev2_runtime::OdenRev2HostCommit;
  use crate::oden_rev2_runtime::OdenRev2HostFilesystemCompletion;
  use crate::oden_rev2_runtime::OdenRev2HostInteraction;
  use crate::rev2::EffectInput;
  use crate::rev2::EngineIdentity;
  use crate::rev2::Outcome;
  use crate::rev2::PathBindingInput;
  use crate::rev2::Rev2Core;
  use crate::rev2::StageDecision;
  use crate::rev2::StageRequest;
  use crate::rev2::canonical_json;
  use crate::rev2::domain_digest;

  struct SourceEvidence {
    entries: Vec<OdenRev2FsActorSourceEvidence>,
  }

  struct OperationIds {
    operation_id: String,
    actor_id: String,
    stage_id: String,
    terminal_evidence_id: String,
  }

  struct AuthorizedOperation {
    actor: OdenRev2FilesystemHostActor,
    actor_digest: String,
  }

  struct NamespaceMutation<'guard, 'context> {
    guard: &'guard mut OdenRev2NamespaceOperationGuard<'context>,
  }

  impl<'guard, 'context> NamespaceMutation<'guard, 'context> {
    fn begin(
      guard: &'guard mut OdenRev2NamespaceOperationGuard<'context>,
    ) -> Result<Self, OdenRev2FilesystemError> {
      let namespace = guard
        .namespace
        .as_mut()
        .ok_or_else(|| refused("NAMESPACE-GATE"))?;
      if namespace.fail_closed {
        return Err(refused("NAMESPACE-FAIL-CLOSED"));
      }
      // Default to uncertain before the first irreversible instruction. Drop
      // deliberately leaves this bit set on panic or an unclassified result.
      namespace.fail_closed = true;
      Ok(Self { guard })
    }

    fn resolve(self) {
      if let Some(namespace) = self.guard.namespace.as_mut() {
        namespace.fail_closed = false;
      }
    }

    fn native_commit_witness(
      &self,
    ) -> super::OdenRev2FilesystemNativeCommitWitness<'_> {
      super::OdenRev2FilesystemNativeCommitWitness::new(&self.guard.gate_token)
    }
  }

  impl Drop for NamespaceMutation<'_, '_> {
    fn drop(&mut self) {
      // An unresolved token deliberately leaves `fail_closed` set. The
      // explicit Drop type makes that lifetime boundary part of the API.
    }
  }

  fn validate_absolute_path(
    path: &Path,
  ) -> Result<(), OdenRev2FilesystemError> {
    use std::os::unix::ffi::OsStrExt;

    if !path.is_absolute() {
      return Err(refused("ABSOLUTE-PATH-REQUIRED"));
    }
    let mut normalized = PathBuf::from("/");
    let mut saw_root = false;
    let mut normal_count = 0usize;
    for component in path.components() {
      match component {
        Component::RootDir if !saw_root => saw_root = true,
        Component::Normal(component) if saw_root => {
          normalized.push(component);
          normal_count += 1;
        }
        _ => return Err(refused("LEXICAL-PATH")),
      }
    }
    if !saw_root
      || normal_count == 0
      || normalized.as_os_str().as_bytes() != path.as_os_str().as_bytes()
    {
      return Err(refused("LEXICAL-PATH"));
    }
    Ok(())
  }

  fn capture_actors()
  -> Result<VerifiedPermissionActorSet, OdenRev2FilesystemError> {
    let (principals, owner) = crate::oden_rev2_capture_live_permission_actors();
    VerifiedPermissionActorSet::capture_host(&principals, owner)
      .map_err(|_| refused("ACTOR-CAPTURE"))
  }

  fn captured_actor_digest(
    actors: &VerifiedPermissionActorSet,
  ) -> Result<String, OdenRev2FilesystemError> {
    domain_digest(
      "oden:capsec:filesystem-captured-actors:2",
      &json!({
        "effectOwner": actors.overlay_owner(),
        "principals": actors.constrained_principals(),
      }),
    )
    .map_err(|_| refused("ACTOR-CAPTURE"))
  }

  fn operation_ids(
    edge_id: &str,
    actor_capture_digest: &str,
    guard: &OdenRev2NamespaceOperationGuard<'_>,
  ) -> Result<OperationIds, OdenRev2FilesystemError> {
    let basis = json!({
      "actorCaptureDigest": actor_capture_digest,
      "edgeId": edge_id,
      "generations": guard.gate_token.generations(),
      "identity": guard.gate_token.identity(),
      "namespaceSequence": guard.gate_token.sequence().to_string(),
    });
    let digest = |domain| {
      domain_digest(domain, &basis).map_err(|_| refused("OPERATION-IDENTITY"))
    };
    Ok(OperationIds {
      operation_id: digest("oden:capsec:filesystem-operation:2")?,
      actor_id: digest("oden:capsec:filesystem-operation-actor:2")?,
      stage_id: digest("oden:capsec:filesystem-stage:2")?,
      terminal_evidence_id: digest(
        "oden:capsec:filesystem-terminal-evidence:2",
      )?,
    })
  }

  fn ensure_no_dynamic_path_sources(
    guard: &OdenRev2NamespaceOperationGuard<'_>,
    capabilities: &[&str],
  ) -> Result<(), OdenRev2FilesystemError> {
    for kind in [
      AuthorityRowKind::SessionPositive,
      AuthorityRowKind::SessionRevocation,
      AuthorityRowKind::NegativeOverlay,
      AuthorityRowKind::Revocation,
    ] {
      if guard.stable_view.rows(kind).any(|row| {
        capabilities.contains(&row.selector().capability.as_str())
          && row.selector().resource.get("root").is_some()
          && row.selector().resource.get("path").is_some()
      }) {
        return Err(refused("DYNAMIC-PATH-SOURCE-UNSUPPORTED"));
      }
    }
    Ok(())
  }

  fn resolve_checked(
    root: &StaticPathRoot<'_>,
    session: &OdenRev2FsOperationSession,
    relative: &Path,
  ) -> Result<OdenRev2FsCheckedPath, OdenRev2FilesystemError> {
    let authenticated =
      OdenRev2FsAuthenticatedRoot::authenticate(root.binding, root.retained)
        .map_err(|_| refused("HOST-FACTS"))?;
    let resolution = authenticated
      .begin_resolution(session, relative, OdenRev2FsFollowMode::NoFollowFinal)
      .map_err(|_| refused("HOST-FACTS"))?;
    match resolution.advance().map_err(|_| refused("HOST-FACTS"))? {
      OdenRev2FsResolutionStep::Complete(checked) => Ok(checked),
      OdenRev2FsResolutionStep::AuthorizationRequired(_) => {
        Err(refused("SYMLINK-ANCESTOR-UNSUPPORTED"))
      }
    }
  }

  fn platform_identity(identity: &OdenRev2FsPlatformIdentity) -> Value {
    json!({
      "kind": "platform-object",
      "value": identity.canonical_value(),
    })
  }

  fn path_binding(
    source_id: &str,
    occurrence_root_binding_id: &str,
    checked: &OdenRev2FsCheckedPath,
  ) -> PathBindingInput {
    let state = checked.identity_fact();
    match state.state() {
      OdenRev2FsIdentityState::Existing { identity, .. }
      | OdenRev2FsIdentityState::NoFollowLink { identity } => {
        PathBindingInput {
          source_id: source_id.to_string(),
          root_binding_id: occurrence_root_binding_id.to_string(),
          final_object_identities: vec![platform_identity(identity)],
          parent_identities: Vec::new(),
        }
      }
      OdenRev2FsIdentityState::MissingParent { parent_identity }
      | OdenRev2FsIdentityState::ProposedParent {
        parent_identity, ..
      } => PathBindingInput {
        source_id: source_id.to_string(),
        root_binding_id: occurrence_root_binding_id.to_string(),
        final_object_identities: Vec::new(),
        parent_identities: vec![platform_identity(parent_identity)],
      },
    }
  }

  fn source_evidence(
    roots: &[StaticPathRoot<'_>],
    requested: &Path,
    occurrence_root_binding_id: &str,
    session: &OdenRev2FsOperationSession,
  ) -> Result<SourceEvidence, OdenRev2FilesystemError> {
    let mut entries = Vec::with_capacity(roots.len());
    for source in roots {
      if source
        .row
        .selector()
        .resource
        .get("root")
        .and_then(Value::as_str)
        != Some(source.binding.logical_root())
      {
        return Err(refused("ROOT-BINDING"));
      }
      let relative = if source.class == StaticPathSourceClass::Negative {
        Some(
          relative_platform_path(
            source
              .row
              .selector()
              .resource
              .get("path")
              .ok_or_else(|| refused("PATH-SOURCE"))?,
          )
          .map_err(|_| refused("PATH-SOURCE"))?,
        )
      } else {
        requested
          .strip_prefix(bound_platform_path(source.binding.canonical_path()))
          .ok()
          .map(Path::to_path_buf)
      };
      let Some(relative) = relative else {
        continue;
      };
      let source_checked = resolve_checked(source, session, &relative)?;
      let class = match source.class {
        StaticPathSourceClass::Negative => OdenRev2FsActorSourceClass::Negative,
        StaticPathSourceClass::Floor => OdenRev2FsActorSourceClass::Floor,
        StaticPathSourceClass::Ceiling => OdenRev2FsActorSourceClass::Ceiling,
      };
      entries.push(OdenRev2FsActorSourceEvidence::new(
        path_binding(
          source.binding.source_id(),
          occurrence_root_binding_id,
          &source_checked,
        ),
        source_checked,
        class,
        crate::rev2::AuthoritySelectorInput {
          identity: EngineIdentity::embedded(),
          principal: source.row.selector().principal.clone(),
          capability: source.row.selector().capability.clone(),
          resource: source.row.selector().resource.clone(),
        },
      ));
    }
    Ok(SourceEvidence { entries })
  }

  fn final_state(
    checked: &OdenRev2FsCheckedPath,
    proposed: bool,
  ) -> Result<Value, OdenRev2FilesystemError> {
    match checked.target_kind() {
      OdenRev2FsCheckedTargetKind::Existing => Ok(json!({
        "kind": "existing",
        "identity": platform_identity(
          checked
            .existing()
            .ok_or_else(|| refused("HOST-FACTS"))?
            .identity(),
        ),
      })),
      OdenRev2FsCheckedTargetKind::NoFollowLink => Ok(json!({
        "kind": "link-entry",
        "identity": platform_identity(
          checked
            .no_follow_link()
            .ok_or_else(|| refused("HOST-FACTS"))?
            .identity(),
        ),
      })),
      OdenRev2FsCheckedTargetKind::Missing => Ok(json!({
        "kind": if proposed { "proposed" } else { "missing" },
      })),
      OdenRev2FsCheckedTargetKind::Proposed => {
        Ok(json!({ "kind": "proposed" }))
      }
    }
  }

  fn occurrence(
    checked: &OdenRev2FsCheckedPath,
    occurrence_root_binding_id: &str,
    owner: &str,
    proposed: bool,
  ) -> Result<Value, OdenRev2FilesystemError> {
    let parent = checked
      .parent_identity()
      .ok_or_else(|| refused("VERIFIED-PARENT-REQUIRED"))?;
    let lexical = checked.lexical_fact().relative_path();
    if lexical.as_os_str().is_empty() {
      return Err(refused("VERIFIED-PARENT-REQUIRED"));
    }
    Ok(json!({
      "effectOwner": owner,
      "finalObjectState": final_state(checked, proposed)?,
      "followMode": "no-follow-final",
      "lexicalPath": platform_path_value(lexical),
      "parentIdentity": platform_identity(parent),
      "root": checked.lexical_fact().source_root().logical_root(),
      "rootBindingId": occurrence_root_binding_id,
    }))
  }

  fn effect(
    edge_id: &str,
    effect_slot_id: &str,
    capability: &str,
    owner: &str,
    occurrence: Value,
  ) -> EffectInput {
    EffectInput {
      identity: EngineIdentity::embedded(),
      edge_id: edge_id.to_string(),
      effect_slot_id: effect_slot_id.to_string(),
      capability: capability.to_string(),
      effect_owner: owner.to_string(),
      occurrence,
    }
  }

  fn canonical_effect_set(
    effects: impl IntoIterator<Item = crate::rev2::CanonicalEffect>,
  ) -> Result<BTreeSet<String>, OdenRev2FilesystemError> {
    effects
      .into_iter()
      .map(|effect| {
        serde_json::to_value(effect)
          .map_err(|_| refused("DECISION-SHAPE"))
          .and_then(|value| {
            canonical_json(&value).map_err(|_| refused("DECISION-SHAPE"))
          })
      })
      .collect()
  }

  fn validate_allow_decision(
    core: &Rev2Core,
    request: &StageRequest,
    decision: &StageDecision,
    principal_count: usize,
  ) -> Result<(), OdenRev2FilesystemError> {
    let expected = canonical_effect_set(
      request
        .effects
        .iter()
        .map(|effect| core.normalize_effect(effect))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| refused("DECISION-SHAPE"))?,
    )?;
    let decided = canonical_effect_set(
      decision.effects.iter().map(|effect| effect.effect.clone()),
    )?;
    let committed =
      canonical_effect_set(decision.committed_effects.iter().cloned())?;
    if decision.stage_id != request.stage_id
      || decision.outcome != Outcome::Allow
      || decision.effects.len() != request.effects.len()
      || decision.committed_effects.len() != request.effects.len()
      || !decision.omitted_effects.is_empty()
      || decided != expected
      || committed != expected
      || decision.effects.iter().any(|effect| {
        effect.outcome != Outcome::Allow
          || effect.dimensions.len() != principal_count
          || effect
            .dimensions
            .iter()
            .any(|dimension| dimension.outcome != Outcome::Allow)
      })
    {
      return Err(refused("AUTHORIZATION-INCOMPLETE"));
    }
    Ok(())
  }

  fn authorize(
    context: &OdenRev2RuntimeAuthorityContext,
    guard: &OdenRev2NamespaceOperationGuard<'_>,
    actors: &VerifiedPermissionActorSet,
    ids: &OperationIds,
    request: &StageRequest,
    path_bindings: Vec<PathBindingInput>,
    filesystem_inventory: OdenRev2FsActorInventory,
  ) -> Result<
    (AuthorizedOperation, crate::rev2::DecisionPolicyInput),
    OdenRev2FilesystemError,
  > {
    let policy = context
      .decision_policy_for_namespace_operation(
        guard,
        OdenRev2OperationAuthorityFacts::new(
          actors.overlay_owner().clone(),
          ids.terminal_evidence_id.clone(),
        )
        .with_path_bindings(path_bindings),
      )
      .map_err(|_| refused("POLICY-PROJECTION"))?;
    let mut actor = OdenRev2FilesystemHostActor::capture_host(
      ids.operation_id.clone(),
      ids.actor_id.clone(),
      actors.constrained_principals().to_vec(),
      actors.overlay_owner().key.clone(),
      actors.overlay_owner().clone(),
      // Synchronous host attribution has no mutable owner epoch. `0` is the
      // existing native-actor sentinel; authority generations remain bound in
      // the pinned policy and filesystem operation session.
      "0",
      &policy,
      filesystem_inventory,
    )
    .map_err(|_| refused("OPERATION-ACTOR"))?;
    let authorization = actor
      .authorize_initial(
        request,
        &policy,
        OdenRev2HostInteraction::NonInteractive,
      )
      .map_err(|_| refused("AUTHORIZATION"))?;
    let OdenRev2HostAuthorization::Authorized {
      actor_digest,
      decision,
    } = authorization
    else {
      return Err(refused("AUTHORIZATION"));
    };
    let core =
      Rev2Core::embedded().map_err(|_| refused("CORE-INITIALIZATION"))?;
    validate_allow_decision(
      &core,
      request,
      &decision,
      actors.constrained_principals().len(),
    )?;
    Ok((
      AuthorizedOperation {
        actor,
        actor_digest,
      },
      policy,
    ))
  }

  fn commit_actor(
    operation: &mut AuthorizedOperation,
    policy: &crate::rev2::DecisionPolicyInput,
    stage_id: &str,
  ) -> Result<(), OdenRev2FilesystemError> {
    match operation
      .actor
      .commit_authorized(policy)
      .map_err(|_| refused("ACTOR-COMMIT"))?
    {
      OdenRev2HostCommit::Committed {
        stage_id: committed_stage,
        actor_digest,
        launch_payload: None,
      } if committed_stage == stage_id
        && actor_digest == operation.actor_digest =>
      {
        Ok(())
      }
      _ => Err(refused("ACTOR-COMMIT")),
    }
  }

  fn complete_actor(
    operation: AuthorizedOperation,
  ) -> Result<OdenRev2HostFilesystemCompletion, OdenRev2FilesystemError> {
    operation
      .actor
      .complete(&super::OdenRev2FilesystemDeliveryWitness::new())
      .map_err(|_| refused("ACTOR-COMPLETE"))
  }

  pub(super) fn lstat_sync_supported<'context>(
    context: &'context OdenRev2RuntimeAuthorityContext,
    path: &Path,
  ) -> Result<OdenRev2LstatDelivery<'context>, OdenRev2FilesystemError> {
    validate_absolute_path(path)?;
    let actors = capture_actors()?;
    let actor_capture_digest = captured_actor_digest(&actors)?;
    let guard = context
      .begin_namespace_operation()
      .map_err(|_| refused("NAMESPACE-GATE"))?;
    ensure_no_dynamic_path_sources(&guard, &["fs:list"])?;
    let ids = operation_ids(LSTAT_EDGE, &actor_capture_digest, &guard)?;
    let session = OdenRev2FsOperationSession::capture_host(
      &guard.gate_token,
      ids.actor_id.clone(),
    )
    .map_err(|_| refused("OPERATION-SESSION"))?;
    let roots = collect_static_path_roots(
      context,
      actors.constrained_principals(),
      "fs:list",
    )
    .map_err(|_| refused("PATH-SOURCES"))?;
    let (primary, relative) =
      select_primary_path_root(&roots, actors.overlay_owner(), path)
        .map_err(|_| refused("PATH-SOURCES"))?;
    if relative.as_os_str().is_empty() {
      return Err(refused("VERIFIED-PARENT-REQUIRED"));
    }
    let occurrence_root_binding_id = primary.binding.binding_id();
    let checked = resolve_checked(primary, &session, &relative)?;
    let evidence =
      source_evidence(&roots, path, occurrence_root_binding_id, &session)?;
    let target_kind = checked.target_kind();
    let occurrence = occurrence(
      &checked,
      occurrence_root_binding_id,
      &actors.overlay_owner().key,
      false,
    )?;
    let request = StageRequest {
      identity: EngineIdentity::embedded(),
      stage_id: ids.stage_id.clone(),
      principals: actors.constrained_principals().to_vec(),
      effects: vec![effect(
        LSTAT_EDGE,
        LSTAT_LIST_SLOT,
        "fs:list",
        &actors.overlay_owner().key,
        occurrence,
      )],
    };
    #[cfg(test)]
    let actor_sequence_fault = super::take_actor_sequence_fault_for_test();
    let filesystem_inventory = OdenRev2FsActorInventory::seal(
      ids.operation_id.clone(),
      &request,
      &session,
      checked,
      evidence.entries,
    )
    .map_err(|_| refused("PROVISIONAL-INVENTORY"))?;
    let bindings = filesystem_inventory.path_bindings().to_vec();
    #[cfg(test)]
    let request_for_authorization = {
      let mut candidate = request.clone();
      if actor_sequence_fault
        == Some(
          super::OdenRev2FilesystemActorSequenceFaultForTest::SubstituteRequest,
        )
      {
        candidate.stage_id.push_str(":substituted");
      }
      candidate
    };
    #[cfg(test)]
    let request_for_authorization = &request_for_authorization;
    #[cfg(not(test))]
    let request_for_authorization = &request;
    let (mut operation, policy) = authorize(
      context,
      &guard,
      &actors,
      &ids,
      request_for_authorization,
      bindings,
      filesystem_inventory,
    )?;
    operation
      .actor
      .revalidate_sources(&session)
      .map_err(|_| refused("SOURCE-RACE"))?;
    operation
      .actor
      .revalidate_target(&session)
      .map_err(|_| refused("TARGET-RACE"))?;
    #[cfg(test)]
    if actor_sequence_fault
      == Some(
        super::OdenRev2FilesystemActorSequenceFaultForTest::SkipObservation,
      )
    {
      commit_actor(&mut operation, &policy, &ids.stage_id)?;
      return Err(refused("TEST-SEQUENCE-FAULT-SURVIVED"));
    }
    let value = match target_kind {
      OdenRev2FsCheckedTargetKind::Existing
      | OdenRev2FsCheckedTargetKind::NoFollowLink => {
        LstatDeliveryValue::Metadata(
          operation
            .actor
            .observe_metadata(&session)
            .map_err(|_| refused("TARGET-RACE"))?
            .into_metadata(),
        )
      }
      OdenRev2FsCheckedTargetKind::Missing => {
        operation
          .actor
          .observe_missing(&session)
          .map_err(|_| refused("TARGET-RACE"))?;
        LstatDeliveryValue::NotFound
      }
      OdenRev2FsCheckedTargetKind::Proposed => {
        return Err(refused("TARGET-STATE"));
      }
    };
    commit_actor(&mut operation, &policy, &ids.stage_id)?;
    let filesystem_completion = complete_actor(operation)?;
    Ok(OdenRev2LstatDelivery {
      value,
      _lease: super::OdenRev2FilesystemDeliveryLease::new(
        filesystem_completion,
        guard,
      ),
    })
  }

  fn same_mkdir_root(
    list: &StaticPathRoot<'_>,
    list_relative: &Path,
    write: &StaticPathRoot<'_>,
    write_relative: &Path,
  ) -> bool {
    list.binding.logical_root() == write.binding.logical_root()
      && list.binding.canonical_path() == write.binding.canonical_path()
      && list.binding.object_identity().value()
        == write.binding.object_identity().value()
      && list_relative == write_relative
  }

  fn uncertain_error(_error: OdenRev2FsError) -> OdenRev2FilesystemError {
    // The kernel result or postcheck is not trustworthy enough to distinguish
    // success from failure. Never turn that uncertainty into an ordinary,
    // path-bearing errno disclosure.
    refused("COMMIT-UNCERTAIN")
  }

  pub(super) fn mkdir_sync_supported<'context>(
    context: &'context OdenRev2RuntimeAuthorityContext,
    path: &Path,
    mode: u32,
  ) -> Result<OdenRev2MkdirDelivery<'context>, OdenRev2FilesystemError> {
    validate_absolute_path(path)?;
    let actors = capture_actors()?;
    let actor_capture_digest = captured_actor_digest(&actors)?;
    let mut guard = context
      .begin_namespace_operation()
      .map_err(|_| refused("NAMESPACE-GATE"))?;
    ensure_no_dynamic_path_sources(&guard, &["fs:list", "fs:write"])?;
    let ids = operation_ids(MKDIR_EDGE, &actor_capture_digest, &guard)?;
    let session = OdenRev2FsOperationSession::capture_host(
      &guard.gate_token,
      ids.actor_id.clone(),
    )
    .map_err(|_| refused("OPERATION-SESSION"))?;
    let list_roots = collect_static_path_roots(
      context,
      actors.constrained_principals(),
      "fs:list",
    )
    .map_err(|_| refused("PATH-SOURCES"))?;
    let write_roots = collect_static_path_roots(
      context,
      actors.constrained_principals(),
      "fs:write",
    )
    .map_err(|_| refused("PATH-SOURCES"))?;
    let (list_primary, list_relative) =
      select_primary_path_root(&list_roots, actors.overlay_owner(), path)
        .map_err(|_| refused("PATH-SOURCES"))?;
    let (write_primary, write_relative) =
      select_primary_path_root(&write_roots, actors.overlay_owner(), path)
        .map_err(|_| refused("PATH-SOURCES"))?;
    if write_relative.as_os_str().is_empty()
      || !same_mkdir_root(
        list_primary,
        &list_relative,
        write_primary,
        &write_relative,
      )
    {
      return Err(refused("CONJUNCTIVE-ROOT-MISMATCH"));
    }
    let occurrence_root_binding_id = write_primary.binding.binding_id();
    let checked = resolve_checked(write_primary, &session, &write_relative)?;
    let target_kind = checked.target_kind();
    let list_evidence =
      source_evidence(&list_roots, path, occurrence_root_binding_id, &session)?;
    let write_evidence = source_evidence(
      &write_roots,
      path,
      occurrence_root_binding_id,
      &session,
    )?;
    let list_occurrence = occurrence(
      &checked,
      occurrence_root_binding_id,
      &actors.overlay_owner().key,
      false,
    )?;
    let write_occurrence = occurrence(
      &checked,
      occurrence_root_binding_id,
      &actors.overlay_owner().key,
      checked.target_kind() == OdenRev2FsCheckedTargetKind::Missing,
    )?;
    let request = StageRequest {
      identity: EngineIdentity::embedded(),
      stage_id: ids.stage_id.clone(),
      principals: actors.constrained_principals().to_vec(),
      effects: vec![
        effect(
          MKDIR_EDGE,
          MKDIR_WRITE_SLOT,
          "fs:write",
          &actors.overlay_owner().key,
          write_occurrence,
        ),
        effect(
          MKDIR_EDGE,
          MKDIR_LIST_SLOT,
          "fs:list",
          &actors.overlay_owner().key,
          list_occurrence,
        ),
      ],
    };
    #[cfg(test)]
    let actor_sequence_fault = super::take_actor_sequence_fault_for_test();
    let mut source_evidence = list_evidence.entries;
    source_evidence.extend(write_evidence.entries);
    let filesystem_inventory = OdenRev2FsActorInventory::seal(
      ids.operation_id.clone(),
      &request,
      &session,
      checked,
      source_evidence,
    )
    .map_err(|_| refused("PROVISIONAL-INVENTORY"))?;
    let bindings = filesystem_inventory.path_bindings().to_vec();
    let (mut operation, policy) = authorize(
      context,
      &guard,
      &actors,
      &ids,
      &request,
      bindings,
      filesystem_inventory,
    )?;
    operation
      .actor
      .revalidate_sources(&session)
      .map_err(|_| refused("SOURCE-RACE"))?;
    operation
      .actor
      .revalidate_target(&session)
      .map_err(|_| refused("TARGET-RACE"))?;
    match target_kind {
      OdenRev2FsCheckedTargetKind::Existing
      | OdenRev2FsCheckedTargetKind::NoFollowLink => {
        commit_actor(&mut operation, &policy, &ids.stage_id)?;
        let filesystem_completion = complete_actor(operation)?;
        Ok(OdenRev2MkdirDelivery {
          already_exists: true,
          _lease: super::OdenRev2FilesystemDeliveryLease::new(
            filesystem_completion,
            guard,
          ),
        })
      }
      OdenRev2FsCheckedTargetKind::Missing => {
        operation
          .actor
          .prepare_mkdir(&session)
          .map_err(|_| refused("TARGET-RACE"))?;
        #[cfg(test)]
        let skip_post_prepare_revalidation = actor_sequence_fault
          == Some(
            super::OdenRev2FilesystemActorSequenceFaultForTest::SkipPostPrepareRevalidation,
          );
        #[cfg(not(test))]
        let skip_post_prepare_revalidation = false;
        if !skip_post_prepare_revalidation {
          operation
            .actor
            .revalidate_target(&session)
            .map_err(|_| refused("TARGET-RACE"))?;
        }
        commit_actor(&mut operation, &policy, &ids.stage_id)?;
        #[cfg(test)]
        if actor_sequence_fault
          == Some(
            super::OdenRev2FilesystemActorSequenceFaultForTest::SkipNativeCommit,
          )
        {
          complete_actor(operation)?;
          return Err(refused("TEST-SEQUENCE-FAULT-SURVIVED"));
        }
        let mutation = NamespaceMutation::begin(&mut guard)?;
        #[cfg(test)]
        if actor_sequence_fault
          == Some(
            super::OdenRev2FilesystemActorSequenceFaultForTest::PanicAfterMutationBegin,
          )
        {
          panic!("injected panic after namespace mutation begin");
        }
        #[cfg(test)]
        let mismatched_gate_token = (actor_sequence_fault
          == Some(
            super::OdenRev2FilesystemActorSequenceFaultForTest::MismatchedNativeCommitWitness,
          ))
        .then(|| mutation.guard.gate_token.mismatched_for_test());
        #[cfg(test)]
        let native_commit_witness = mismatched_gate_token
          .as_ref()
          .map(super::OdenRev2FilesystemNativeCommitWitness::new)
          .unwrap_or_else(|| mutation.native_commit_witness());
        #[cfg(not(test))]
        let native_commit_witness = mutation.native_commit_witness();
        let outcome = operation
          .actor
          .commit_mkdir(&session, mode, &native_commit_witness)
          .map_err(|_| refused("PROVISIONAL-INVENTORY"))?;
        match outcome {
          OdenRev2FsMkdirCommitOutcome::Committed => {
            #[cfg(test)]
            if actor_sequence_fault
              == Some(
                super::OdenRev2FilesystemActorSequenceFaultForTest::RepeatNativeCommit,
              )
            {
              let repeated = operation.actor.commit_mkdir(
                &session,
                mode,
                &native_commit_witness,
              );
              mutation.resolve();
              if repeated.is_err() {
                return Err(refused("PROVISIONAL-INVENTORY"));
              }
              return Err(refused("TEST-SEQUENCE-FAULT-SURVIVED"));
            }
            let filesystem_completion = complete_actor(operation)?;
            mutation.resolve();
            Ok(OdenRev2MkdirDelivery {
              already_exists: false,
              _lease: super::OdenRev2FilesystemDeliveryLease::new(
                filesystem_completion,
                guard,
              ),
            })
          }
          OdenRev2FsMkdirCommitOutcome::NotCommitted(_) => {
            #[cfg(test)]
            if actor_sequence_fault
              == Some(
                super::OdenRev2FilesystemActorSequenceFaultForTest::CompleteAfterNotCommitted,
              )
            {
              let completion = complete_actor(operation);
              mutation.resolve();
              completion?;
              return Err(refused("TEST-SEQUENCE-FAULT-SURVIVED"));
            }
            let _ = operation.actor.cancel();
            mutation.resolve();
            Err(refused("TARGET-RACE"))
          }
          OdenRev2FsMkdirCommitOutcome::Uncertain(error) => {
            let _ = operation.actor.cancel();
            // Dropping the unresolved token permanently leaves this context's
            // namespace gate fail-closed.
            drop(mutation);
            Err(uncertain_error(error))
          }
        }
      }
      OdenRev2FsCheckedTargetKind::Proposed => Err(refused("TARGET-STATE")),
    }
  }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
use supported::lstat_sync_supported;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use supported::mkdir_sync_supported;

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
mod tests {
  use std::path::Path;
  use std::path::PathBuf;
  use std::sync::atomic::AtomicU64;
  use std::sync::atomic::Ordering;

  use serde_json::Value;
  use serde_json::json;

  use super::*;
  use crate::oden_rev2_fs::OdenRev2FsMkdirCommitFaultForTest;
  use crate::oden_rev2_fs::oden_rev2_fs_set_mkdir_commit_fault_for_test;
  use crate::oden_rev2_fs::oden_rev2_fs_take_last_released_handles_for_test;
  use crate::oden_rev2_policy::tests as policy_fixtures;
  use crate::rev2::AuthoritySelectorInput;
  use crate::rev2::EngineIdentity;
  use crate::rev2::PrincipalKind;
  use crate::rev2::PrincipalRef;
  use crate::rev2::Rev2Core;
  use crate::rev2::SelectorPolarity;
  use crate::rev2_registry_generated::REV2_REGISTRY_DIGEST;
  use crate::rev2_registry_generated::REV2_VOCAB_DIGEST;

  static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);

  struct TempRoot(PathBuf);

  impl TempRoot {
    fn new(label: &str) -> Self {
      let sequence = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
      let raw = std::env::temp_dir().join(format!(
        "oden-rev2-fs-runtime-{label}-{}-{sequence}",
        std::process::id()
      ));
      std::fs::create_dir(&raw).unwrap();
      std::fs::create_dir(raw.join("data")).unwrap();
      Self(std::fs::canonicalize(raw).unwrap())
    }
  }

  impl Drop for TempRoot {
    fn drop(&mut self) {
      let _ = std::fs::remove_dir_all(&self.0);
    }
  }

  struct ActorCapture;

  impl ActorCapture {
    fn install(principal: PrincipalRef) -> Self {
      crate::oden_rev2_set_permission_actors_for_test(Some((
        vec![principal.clone()],
        principal,
      )));
      crate::oden_rev2_reset_permission_actor_capture_count_for_test();
      Self
    }
  }

  impl Drop for ActorCapture {
    fn drop(&mut self) {
      crate::oden_rev2_set_permission_actors_for_test(None);
      oden_rev2_fs_set_mkdir_commit_fault_for_test(None);
      set_actor_sequence_fault_for_test(None);
    }
  }

  fn principal() -> PrincipalRef {
    PrincipalRef {
      kind: PrincipalKind::Package,
      key: "pkg:sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
    }
  }

  fn path_selector(
    capability: &str,
  ) -> crate::rev2::CanonicalAuthoritySelector {
    selector(capability, "path-tree", "data", SelectorPolarity::Positive)
  }

  fn selector(
    capability: &str,
    kind: &str,
    path: &str,
    polarity: SelectorPolarity,
  ) -> crate::rev2::CanonicalAuthoritySelector {
    Rev2Core::embedded()
      .unwrap()
      .normalize_selector(
        &AuthoritySelectorInput {
          identity: EngineIdentity::embedded(),
          principal: Some(principal()),
          capability: capability.to_string(),
          resource: json!({
            "kind": kind,
            "path": { "encoding": "unicode", "value": path },
            "root": "$PROJECT",
          }),
        },
        polarity,
      )
      .unwrap()
  }

  fn context(
    root: &Path,
    allow_list: bool,
    allow_write: bool,
  ) -> OdenRev2RuntimeAuthorityContext {
    let mut floor = Vec::new();
    let mut bindings = Vec::new();
    for (allowed, source_id, binding_id, capability) in [
      (allow_list, "floor:list", "root-binding:list", "fs:list"),
      (allow_write, "floor:write", "root-binding:write", "fs:write"),
    ] {
      if !allowed {
        continue;
      }
      floor.push(json!({
        "sourceId": source_id,
        "selector": path_selector(capability),
      }));
      bindings.push(json!({
        "sourceId": source_id,
        "logicalRoot": "$PROJECT",
        "principal": principal(),
        "rootBindingId": binding_id,
        "canonicalPath": {
          "encoding": "unicode",
          "value": root.to_str().unwrap(),
        },
        "objectIdentity": policy_fixtures::platform_identity(root),
        "bindingProvenanceDigest": REV2_REGISTRY_DIGEST,
      }));
    }
    let mut snapshot = policy_fixtures::candidate_snapshot(
      policy_fixtures::hermetic_target(),
      None,
    );
    snapshot["canonicalPolicy"]["principals"] = json!([{
      "principal": principal(),
      "binding": {
        "resolverId": "fixture-lock-resolver/2",
        "bindingDigest": REV2_VOCAB_DIGEST,
      },
      "floor": floor,
      "escalationCeiling": [],
      "denials": [],
    }]);
    snapshot["rootBindings"] = Value::Array(bindings);
    policy_fixtures::refresh_digests(&mut snapshot);
    let mut loaded =
      policy_fixtures::verify_armable_snapshot(snapshot, &[91_u8; 32]).unwrap();
    loaded
      .install_immutable_executables(Path::new("."))
      .unwrap();
    OdenRev2RuntimeAuthorityContext::install_for_test(loaded).unwrap()
  }

  fn context_with_exact_list_deny(
    root: &Path,
  ) -> OdenRev2RuntimeAuthorityContext {
    let mut snapshot = policy_fixtures::candidate_snapshot(
      policy_fixtures::hermetic_target(),
      None,
    );
    snapshot["canonicalPolicy"]["principals"] = json!([{
      "principal": principal(),
      "binding": {
        "resolverId": "fixture-lock-resolver/2",
        "bindingDigest": REV2_VOCAB_DIGEST,
      },
      "floor": [{
        "sourceId": "floor:list",
        "selector": path_selector("fs:list"),
      }],
      "escalationCeiling": [],
      "denials": [{
        "sourceId": "deny:list-secret",
        "selector": selector(
          "fs:list",
          "path-exact",
          "deny/secret",
          SelectorPolarity::Negative,
        ),
      }],
    }]);
    snapshot["rootBindings"] = json!([
      {
        "sourceId": "deny:list-secret",
        "logicalRoot": "$PROJECT",
        "principal": principal(),
        "rootBindingId": "root-binding:deny-list-secret",
        "canonicalPath": {
          "encoding": "unicode",
          "value": root.to_str().unwrap(),
        },
        "objectIdentity": policy_fixtures::platform_identity(root),
        "bindingProvenanceDigest": REV2_REGISTRY_DIGEST,
      },
      {
        "sourceId": "floor:list",
        "logicalRoot": "$PROJECT",
        "principal": principal(),
        "rootBindingId": "root-binding:list",
        "canonicalPath": {
          "encoding": "unicode",
          "value": root.to_str().unwrap(),
        },
        "objectIdentity": policy_fixtures::platform_identity(root),
        "bindingProvenanceDigest": REV2_REGISTRY_DIGEST,
      },
    ]);
    policy_fixtures::refresh_digests(&mut snapshot);
    let mut loaded =
      policy_fixtures::verify_armable_snapshot(snapshot, &[92_u8; 32]).unwrap();
    loaded
      .install_immutable_executables(Path::new("."))
      .unwrap();
    OdenRev2RuntimeAuthorityContext::install_for_test(loaded).unwrap()
  }

  fn refusal(error: OdenRev2FilesystemError) -> String {
    match error {
      OdenRev2FilesystemError::Refused(reason) => reason,
      OdenRev2FilesystemError::Io(error) => {
        panic!("expected refusal, got {error}")
      }
    }
  }

  fn oden_capsec_rev2_lstat_sync(
    context: &OdenRev2RuntimeAuthorityContext,
    path: &Path,
  ) -> Result<std::fs::Metadata, OdenRev2FilesystemError> {
    let delivery = super::oden_capsec_rev2_lstat_sync(context, path)?;
    let result = delivery.metadata().cloned().ok_or_else(|| {
      OdenRev2FilesystemError::Io(std::io::Error::from_raw_os_error(
        libc::ENOENT,
      ))
    });
    delivery.finish();
    result
  }

  fn oden_capsec_rev2_mkdir_sync(
    context: &OdenRev2RuntimeAuthorityContext,
    path: &Path,
    recursive: bool,
    mode: u32,
  ) -> Result<(), OdenRev2FilesystemError> {
    let delivery =
      super::oden_capsec_rev2_mkdir_sync(context, path, recursive, mode)?;
    let result = if delivery.already_exists() {
      Err(OdenRev2FilesystemError::Io(
        std::io::Error::from_raw_os_error(libc::EEXIST),
      ))
    } else {
      Ok(())
    };
    delivery.finish();
    result
  }

  #[test]
  fn lstat_delivers_only_authorized_existing_link_or_final_missing() {
    use std::os::unix::fs::FileTypeExt as _;
    use std::os::unix::fs::symlink;

    let root = TempRoot::new("lstat");
    std::fs::write(root.0.join("data/file"), b"data").unwrap();
    symlink("file", root.0.join("data/link")).unwrap();
    let context = context(&root.0, true, false);
    let _actors = ActorCapture::install(principal());

    crate::oden_rev2_reset_permission_actor_capture_count_for_test();
    let file =
      oden_capsec_rev2_lstat_sync(&context, &root.0.join("data/file")).unwrap();
    assert!(file.is_file());
    assert_eq!(
      crate::oden_rev2_permission_actor_capture_count_for_test(),
      1
    );

    let link =
      oden_capsec_rev2_lstat_sync(&context, &root.0.join("data/link")).unwrap();
    assert!(link.file_type().is_symlink());
    assert!(!link.file_type().is_socket());

    let missing =
      oden_capsec_rev2_lstat_sync(&context, &root.0.join("data/missing"))
        .unwrap_err();
    assert!(matches!(
      missing,
      OdenRev2FilesystemError::Io(error)
        if error.raw_os_error() == Some(libc::ENOENT)
    ));

    let ancestor =
      oden_capsec_rev2_lstat_sync(&context, &root.0.join("data/absent/child"))
        .unwrap_err();
    assert!(refusal(ancestor).contains("HOST-FACTS"));
  }

  #[test]
  fn lstat_refuses_relative_root_and_symlink_ancestor_paths() {
    use std::os::unix::fs::symlink;

    let root = TempRoot::new("lstat-refusals");
    std::fs::create_dir(root.0.join("other")).unwrap();
    symlink("../other", root.0.join("data/alias")).unwrap();
    let context = context(&root.0, true, false);
    let _actors = ActorCapture::install(principal());

    assert!(
      refusal(
        oden_capsec_rev2_lstat_sync(&context, Path::new("data/file"))
          .unwrap_err()
      )
      .contains("ABSOLUTE-PATH-REQUIRED")
    );
    assert!(
      refusal(oden_capsec_rev2_lstat_sync(&context, &root.0).unwrap_err())
        .contains("VERIFIED-PARENT-REQUIRED")
    );
    assert!(refusal(
      oden_capsec_rev2_lstat_sync(
        &context,
        &root.0.join("data/alias/child"),
      )
      .unwrap_err()
    )
    .contains("SYMLINK-ANCESTOR-UNSUPPORTED"));
  }

  #[test]
  fn exact_list_deny_follows_a_hardlink_alias_without_disclosing_metadata() {
    let root = TempRoot::new("lstat-hardlink-deny");
    std::fs::create_dir(root.0.join("deny")).unwrap();
    std::fs::write(root.0.join("deny/secret"), b"secret").unwrap();
    std::fs::hard_link(root.0.join("deny/secret"), root.0.join("data/alias"))
      .unwrap();
    std::fs::write(root.0.join("data/public"), b"public").unwrap();
    let context = context_with_exact_list_deny(&root.0);
    let _actors = ActorCapture::install(principal());
    let _ = oden_rev2_fs_take_last_released_handles_for_test();

    assert!(
      refusal(
        oden_capsec_rev2_lstat_sync(&context, &root.0.join("data/alias"))
          .unwrap_err()
      )
      .contains("AUTHORIZATION")
    );
    let released = oden_rev2_fs_take_last_released_handles_for_test();
    assert!(!released.is_empty());
    assert!(released.iter().all(|handle| handle.upgrade().is_none()));
    assert!(
      oden_capsec_rev2_lstat_sync(&context, &root.0.join("data/public"))
        .unwrap()
        .is_file()
    );
  }

  #[test]
  fn actor_request_and_observation_steps_cannot_be_substituted_or_skipped() {
    let root = TempRoot::new("actor-sequence-lstat");
    std::fs::write(root.0.join("data/file"), b"data").unwrap();
    let context = context(&root.0, true, false);
    let _actors = ActorCapture::install(principal());

    for (fault, expected) in [
      (
        OdenRev2FilesystemActorSequenceFaultForTest::SubstituteRequest,
        "AUTHORIZATION",
      ),
      (
        OdenRev2FilesystemActorSequenceFaultForTest::SkipObservation,
        "ACTOR-COMMIT",
      ),
    ] {
      let _ = oden_rev2_fs_take_last_released_handles_for_test();
      set_actor_sequence_fault_for_test(Some(fault));
      let error =
        oden_capsec_rev2_lstat_sync(&context, &root.0.join("data/file"))
          .unwrap_err();
      assert!(refusal(error).contains(expected));
      let released = oden_rev2_fs_take_last_released_handles_for_test();
      assert!(!released.is_empty());
      assert!(released.iter().all(|handle| handle.upgrade().is_none()));
    }

    assert!(
      oden_capsec_rev2_lstat_sync(&context, &root.0.join("data/file"))
        .unwrap()
        .is_file()
    );
  }

  #[test]
  fn delivery_token_retains_the_namespace_gate_until_explicit_finish() {
    let root = TempRoot::new("lstat-delivery-pin");
    std::fs::write(root.0.join("data/file"), b"data").unwrap();
    let context = context(&root.0, true, false);
    let _actors = ActorCapture::install(principal());

    let delivery =
      super::oden_capsec_rev2_lstat_sync(&context, &root.0.join("data/file"))
        .unwrap();
    assert!(delivery.metadata().unwrap().is_file());
    let provisional_handles = delivery
      ._lease
      .resources
      .as_ref()
      .unwrap()
      .provisional_weak_handles();
    assert!(!provisional_handles.is_empty());
    assert!(
      provisional_handles
        .iter()
        .all(|handle| handle.upgrade().is_some())
    );
    assert!(context.begin_namespace_operation().is_err());
    delivery.finish();
    assert!(
      provisional_handles
        .iter()
        .all(|handle| handle.upgrade().is_none())
    );
    assert!(
      oden_capsec_rev2_lstat_sync(&context, &root.0.join("data/file"))
        .unwrap()
        .is_file()
    );
  }

  #[test]
  fn mkdir_delivery_retains_prepared_inventory_until_finish() {
    let root = TempRoot::new("mkdir-delivery-pin");
    let context = context(&root.0, true, true);
    let _actors = ActorCapture::install(principal());
    let destination = root.0.join("data/created");

    let delivery =
      super::oden_capsec_rev2_mkdir_sync(&context, &destination, false, 0o700)
        .unwrap();
    assert!(!delivery.already_exists());
    assert!(destination.is_dir());
    let provisional_handles = delivery
      ._lease
      .resources
      .as_ref()
      .unwrap()
      .provisional_weak_handles();
    assert!(!provisional_handles.is_empty());
    assert!(
      provisional_handles
        .iter()
        .all(|handle| handle.upgrade().is_some())
    );
    assert!(context.begin_namespace_operation().is_err());

    delivery.finish();
    assert!(
      provisional_handles
        .iter()
        .all(|handle| handle.upgrade().is_none())
    );
    assert!(context.begin_namespace_operation().is_ok());
  }

  #[test]
  fn mkdir_requires_one_conjunctive_list_and_write_stage() {
    use std::os::unix::fs::symlink;

    let root = TempRoot::new("mkdir-conjunction");
    std::fs::write(root.0.join("data/target"), b"data").unwrap();
    symlink("target", root.0.join("data/conflict-link")).unwrap();
    let full_context = context(&root.0, true, true);
    let _actors = ActorCapture::install(principal());
    let created = root.0.join("data/created");

    oden_capsec_rev2_mkdir_sync(&full_context, &created, false, 0o750).unwrap();
    assert!(created.is_dir());
    assert!(matches!(
      oden_capsec_rev2_mkdir_sync(
        &full_context,
        &created,
        false,
        0o750,
      ),
      Err(OdenRev2FilesystemError::Io(error))
        if error.raw_os_error() == Some(libc::EEXIST)
    ));
    assert!(matches!(
      oden_capsec_rev2_mkdir_sync(
        &full_context,
        &root.0.join("data/conflict-link"),
        false,
        0o750,
      ),
      Err(OdenRev2FilesystemError::Io(error))
        if error.raw_os_error() == Some(libc::EEXIST)
    ));

    for (label, list, write) in
      [("list-only", true, false), ("write-only", false, true)]
    {
      let root = TempRoot::new(label);
      let context = context(&root.0, list, write);
      let denied = root.0.join("data/denied");
      assert!(matches!(
        oden_capsec_rev2_mkdir_sync(&context, &denied, false, 0o700,),
        Err(OdenRev2FilesystemError::Refused(_))
      ));
      assert!(!denied.exists());
    }
  }

  #[test]
  fn recursive_mkdir_refuses_before_actor_capture_or_discovery() {
    let root = TempRoot::new("mkdir-recursive");
    let context = context(&root.0, true, true);
    let _actors = ActorCapture::install(principal());
    crate::oden_rev2_reset_permission_actor_capture_count_for_test();
    let destination = root.0.join("data/a/b");
    assert!(
      refusal(
        oden_capsec_rev2_mkdir_sync(&context, &destination, true, 0o700,)
          .unwrap_err()
      )
      .contains("RECURSIVE-UNSUPPORTED")
    );
    assert_eq!(
      crate::oden_rev2_permission_actor_capture_count_for_test(),
      0
    );
    assert!(!destination.exists());
  }

  #[test]
  fn raced_eexist_is_not_disclosed_and_does_not_latch_the_gate() {
    let root = TempRoot::new("mkdir-race");
    let context = context(&root.0, true, true);
    let _actors = ActorCapture::install(principal());
    let destination = root.0.join("data/raced");
    let _ = oden_rev2_fs_take_last_released_handles_for_test();
    oden_rev2_fs_set_mkdir_commit_fault_for_test(Some(
      OdenRev2FsMkdirCommitFaultForTest::RaceExisting,
    ));
    let error =
      oden_capsec_rev2_mkdir_sync(&context, &destination, false, 0o700)
        .unwrap_err();
    assert!(refusal(error).contains("TARGET-RACE"));
    let released = oden_rev2_fs_take_last_released_handles_for_test();
    assert!(!released.is_empty());
    assert!(released.iter().all(|handle| handle.upgrade().is_none()));
    assert!(destination.is_dir());
    assert!(
      oden_capsec_rev2_lstat_sync(&context, &destination)
        .unwrap()
        .is_dir()
    );
  }

  #[test]
  fn mkdir_cannot_complete_before_or_after_a_failed_native_commit() {
    let root = TempRoot::new("actor-sequence-mkdir");
    let context = context(&root.0, true, true);
    let _actors = ActorCapture::install(principal());

    let postcheck_skipped = root.0.join("data/postcheck-skipped");
    let _ = oden_rev2_fs_take_last_released_handles_for_test();
    set_actor_sequence_fault_for_test(Some(
      OdenRev2FilesystemActorSequenceFaultForTest::SkipPostPrepareRevalidation,
    ));
    let error =
      oden_capsec_rev2_mkdir_sync(&context, &postcheck_skipped, false, 0o700)
        .unwrap_err();
    assert!(refusal(error).contains("ACTOR-COMMIT"));
    assert!(!postcheck_skipped.exists());
    let released = oden_rev2_fs_take_last_released_handles_for_test();
    assert!(!released.is_empty());
    assert!(released.iter().all(|handle| handle.upgrade().is_none()));

    let mismatched_witness = root.0.join("data/mismatched-witness");
    let _ = oden_rev2_fs_take_last_released_handles_for_test();
    set_actor_sequence_fault_for_test(Some(
      OdenRev2FilesystemActorSequenceFaultForTest::MismatchedNativeCommitWitness,
    ));
    let error =
      oden_capsec_rev2_mkdir_sync(&context, &mismatched_witness, false, 0o700)
        .unwrap_err();
    assert!(refusal(error).contains("TARGET-RACE"));
    assert!(!mismatched_witness.exists());
    let released = oden_rev2_fs_take_last_released_handles_for_test();
    assert!(!released.is_empty());
    assert!(released.iter().all(|handle| handle.upgrade().is_none()));

    let skipped = root.0.join("data/skipped");
    let _ = oden_rev2_fs_take_last_released_handles_for_test();
    set_actor_sequence_fault_for_test(Some(
      OdenRev2FilesystemActorSequenceFaultForTest::SkipNativeCommit,
    ));
    let error = oden_capsec_rev2_mkdir_sync(&context, &skipped, false, 0o700)
      .unwrap_err();
    assert!(refusal(error).contains("ACTOR-COMPLETE"));
    assert!(!skipped.exists());
    let released = oden_rev2_fs_take_last_released_handles_for_test();
    assert!(!released.is_empty());
    assert!(released.iter().all(|handle| handle.upgrade().is_none()));

    let raced = root.0.join("data/raced-completion");
    let _ = oden_rev2_fs_take_last_released_handles_for_test();
    oden_rev2_fs_set_mkdir_commit_fault_for_test(Some(
      OdenRev2FsMkdirCommitFaultForTest::RaceExisting,
    ));
    set_actor_sequence_fault_for_test(Some(
      OdenRev2FilesystemActorSequenceFaultForTest::CompleteAfterNotCommitted,
    ));
    let error =
      oden_capsec_rev2_mkdir_sync(&context, &raced, false, 0o700).unwrap_err();
    assert!(refusal(error).contains("ACTOR-COMPLETE"));
    assert!(raced.is_dir());
    let released = oden_rev2_fs_take_last_released_handles_for_test();
    assert!(!released.is_empty());
    assert!(released.iter().all(|handle| handle.upgrade().is_none()));
    assert!(
      oden_capsec_rev2_lstat_sync(&context, &raced)
        .unwrap()
        .is_dir()
    );

    let repeated = root.0.join("data/repeated");
    let _ = oden_rev2_fs_take_last_released_handles_for_test();
    set_actor_sequence_fault_for_test(Some(
      OdenRev2FilesystemActorSequenceFaultForTest::RepeatNativeCommit,
    ));
    let error = oden_capsec_rev2_mkdir_sync(&context, &repeated, false, 0o700)
      .unwrap_err();
    assert!(refusal(error).contains("PROVISIONAL-INVENTORY"));
    assert!(repeated.is_dir());
    let released = oden_rev2_fs_take_last_released_handles_for_test();
    assert!(!released.is_empty());
    assert!(released.iter().all(|handle| handle.upgrade().is_none()));
    assert!(
      oden_capsec_rev2_lstat_sync(&context, &repeated)
        .unwrap()
        .is_dir()
    );
  }

  #[test]
  fn ambiguous_postcommit_state_permanently_latches_namespace_fail_closed() {
    let root = TempRoot::new("mkdir-uncertain");
    let context = context(&root.0, true, true);
    let _actors = ActorCapture::install(principal());
    let destination = root.0.join("data/uncertain");
    oden_rev2_fs_set_mkdir_commit_fault_for_test(Some(
      OdenRev2FsMkdirCommitFaultForTest::UncertainAfterSyscall,
    ));
    let error =
      oden_capsec_rev2_mkdir_sync(&context, &destination, false, 0o700)
        .unwrap_err();
    assert!(refusal(error).contains("COMMIT-UNCERTAIN"));
    assert!(destination.is_dir());
    assert!(matches!(
      oden_capsec_rev2_lstat_sync(&context, &destination),
      Err(OdenRev2FilesystemError::Refused(_))
    ));
  }

  #[test]
  fn panic_after_namespace_mutation_begin_releases_inventory_and_latches_closed()
   {
    let root = TempRoot::new("mkdir-mutation-panic");
    let context = context(&root.0, true, true);
    let _actors = ActorCapture::install(principal());
    let destination = root.0.join("data/panic");
    let _ = oden_rev2_fs_take_last_released_handles_for_test();
    set_actor_sequence_fault_for_test(Some(
      OdenRev2FilesystemActorSequenceFaultForTest::PanicAfterMutationBegin,
    ));

    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
      let _ = oden_capsec_rev2_mkdir_sync(&context, &destination, false, 0o700);
    }));
    assert!(panic.is_err());
    assert!(!destination.exists());
    let released = oden_rev2_fs_take_last_released_handles_for_test();
    assert!(!released.is_empty());
    assert!(released.iter().all(|handle| handle.upgrade().is_none()));
    assert!(matches!(
      oden_capsec_rev2_lstat_sync(&context, &destination),
      Err(OdenRev2FilesystemError::Refused(_))
    ));
  }
}

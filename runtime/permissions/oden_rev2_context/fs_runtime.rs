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

use std::fs::File;
use std::io;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;

use super::OdenRev2NamespaceOperationGuard;
use super::OdenRev2RuntimeAuthorityContext;
use crate::oden_rev2_policy::OdenRev2CompiledBuildIdentity;
use crate::oden_rev2_policy::validate_current_binary_candidate_build_identity;
use crate::oden_rev2_policy::verify_unarmed_candidate_snapshot;
use crate::oden_rev2_protocol::VerifiedPermissionActorSet;
use crate::oden_rev2_runtime::OdenRev2HostFilesystemCompletion;
use crate::rev2::AuthoritySelectorInput;
use crate::rev2::EngineIdentity;
use crate::rev2::FilesystemCandidateOracleInput;
use crate::rev2::FilesystemExecutionMode;
use crate::rev2::FilesystemExecutionProjection;
use crate::rev2::FilesystemFinalObjectState;
use crate::rev2::FilesystemInitialSandboxInventory;
use crate::rev2::FilesystemInitialSandboxObject;
use crate::rev2::FilesystemInputMutation;
use crate::rev2::FilesystemLogicalRoot;
use crate::rev2::FilesystemMetadataProjection;
use crate::rev2::FilesystemObjectIdentity;
use crate::rev2::FilesystemObjectIdentityKind;
use crate::rev2::FilesystemObjectKind;
use crate::rev2::FilesystemParentCaptureFacts;
use crate::rev2::FilesystemPlatformPathEncoding;
use crate::rev2::FilesystemRealizedLogicalRoot;
use crate::rev2::FilesystemRealizedObjectState;
use crate::rev2::FilesystemSandboxPhase;
use crate::rev2::FilesystemTracePhase;
use crate::rev2::Mode;
use crate::rev2::Rev2Core;
use crate::rev2::SelectorPolarity;
use crate::rev2::ValidatedFilesystemCandidateExecution;
use crate::rev2::canonical_json;
use crate::rev2::domain_digest;
use crate::rev2::hjcs_digest;
use crate::rev2::validate_filesystem_candidate_execution;
use crate::rev2_registry_generated::REV2_FILESYSTEM_LSTAT_EXISTING_EXECUTION_ADMISSIONS;
use crate::rev2_registry_generated::REV2_FILESYSTEM_LSTAT_FINAL_MISSING_EXECUTION_ADMISSIONS;
use crate::rev2_registry_generated::REV2_PROFILE;
use crate::rev2_registry_generated::REV2_REGISTRY_DIGEST;
use crate::rev2_registry_generated::REV2_TARGET_STATUS;
use crate::rev2_registry_generated::REV2_VOCAB_DIGEST;
use crate::rev2_registry_generated::Rev2FilesystemLstatExecutionAdmission;

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
    let context = self.guard.as_ref().map(|guard| guard.context);
    drop(self.resources.take());
    if let Some(context) = context {
      let _ = context.record_candidate_lstat_phase(
        FilesystemTracePhase::ProvisionalResourcesReleased,
      );
    }
    debug_assert!(super::namespace_gate_held_on_current_thread());
    drop(self.guard.take());
    if let Some(context) = context {
      let _ = context.record_candidate_lstat_phase(
        FilesystemTracePhase::NamespaceGateReleased,
      );
    }
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
const CANDIDATE_SNAPSHOT_SCHEMA: &str = "oden/capsec-armed-snapshot/2";
const CANDIDATE_POLICY_SCHEMA: &str = "oden/capsec-policy/2";
const CANDIDATE_RECEIPT_SET_DOMAIN: &str =
  "oden:capsec:protected-receipt-set:2";

fn refused(reason: &'static str) -> OdenRev2FilesystemError {
  OdenRev2FilesystemError::Refused(format!("OD-CAP-REV2-FILESYSTEM-{reason}"))
}

fn exact_candidate_path(left: &Path, right: &Path) -> bool {
  #[cfg(unix)]
  {
    use std::os::unix::ffi::OsStrExt;
    left.as_os_str().as_bytes() == right.as_os_str().as_bytes()
  }
  #[cfg(not(unix))]
  {
    left == right
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OdenRev2LstatCandidateCase {
  Existing,
  FinalMissing,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OdenRev2LstatCandidateObserved {
  Existing,
  FinalMissing,
}

struct OdenRev2LstatCandidateTraceState {
  next_phase: usize,
  failed: bool,
  observed: Option<OdenRev2LstatCandidateObserved>,
}

/// Sealed, candidate-local state for one exact generated lstat traversal.
/// This value is never installed in the process-global C04 slot.
pub(super) struct OdenRev2LstatCandidateHarness {
  admission: &'static Rev2FilesystemLstatExecutionAdmission,
  case: OdenRev2LstatCandidateCase,
  root_path: PathBuf,
  target_path: PathBuf,
  root_binding_id: String,
  actors: VerifiedPermissionActorSet,
  expected_trace: Box<[FilesystemTracePhase]>,
  validated: Arc<ValidatedFilesystemCandidateExecution>,
  trace: Mutex<OdenRev2LstatCandidateTraceState>,
}

impl OdenRev2LstatCandidateHarness {
  fn new(
    admission: &'static Rev2FilesystemLstatExecutionAdmission,
    validated: ValidatedFilesystemCandidateExecution,
    root_path: PathBuf,
  ) -> Result<Self, OdenRev2FilesystemError> {
    let projection = validated.execution_projection();
    let case = match projection.case_kind.as_str() {
      "lstat-existing" => OdenRev2LstatCandidateCase::Existing,
      "lstat-final-missing" => OdenRev2LstatCandidateCase::FinalMissing,
      _ => return Err(refused("CANDIDATE-EXECUTION-CASE")),
    };
    let expected_trace: Box<[FilesystemTracePhase]> = [
      FilesystemTracePhase::HarnessAdmitted,
      FilesystemTracePhase::PublicOpEntered,
      FilesystemTracePhase::ActorsCaptured,
      FilesystemTracePhase::NamespaceGateAcquired,
      FilesystemTracePhase::DiscoveryComplete,
      FilesystemTracePhase::AuthorizationComplete,
      FilesystemTracePhase::SourcesRevalidated,
      FilesystemTracePhase::TargetRevalidated,
      FilesystemTracePhase::CoreCommitRecorded,
      FilesystemTracePhase::OperationCompleted,
      FilesystemTracePhase::DeliverySerialized,
      FilesystemTracePhase::ProvisionalResourcesReleased,
      FilesystemTracePhase::NamespaceGateReleased,
      FilesystemTracePhase::HarnessExited,
    ]
    .into();
    if projection.execution.trace_phases.as_slice() != expected_trace.as_ref()
      || projection.execution.actors.len() != 1
      || projection.principals.len() != 1
      || projection.constrained_principal_keys.len() != 1
    {
      return Err(refused("CANDIDATE-GENERATED-TRACE"));
    }
    let actor = &projection.execution.actors[0];
    let principal = &projection.principals[0];
    if actor.actor_id != "actor:list"
      || actor.slot_id != LSTAT_LIST_SLOT
      || actor.principal_key.as_deref() != Some(principal.key.as_str())
      || actor.effect_owner != principal.key
      || projection.effect_owner_key != principal.key
      || projection.constrained_principal_keys[0] != principal.key
    {
      return Err(refused("CANDIDATE-GENERATED-ACTORS"));
    }
    let actors = VerifiedPermissionActorSet::capture_host(
      std::slice::from_ref(principal),
      principal.clone(),
    )
    .map_err(|_| refused("CANDIDATE-GENERATED-ACTORS"))?;
    let target_setup = validated.target_setup();
    let root_binding_id = validated
      .initial_sandbox()
      .logical_roots
      .iter()
      .find(|root| root.root == FilesystemLogicalRoot::Project)
      .map(|root| root.binding_id.clone())
      .ok_or_else(|| refused("CANDIDATE-PARENT-ROOT-IDENTITY"))?;
    let target_path = root_path.join(&target_setup.path.value);
    Ok(Self {
      admission,
      case,
      root_path,
      target_path,
      root_binding_id,
      actors,
      expected_trace,
      validated: Arc::new(validated),
      trace: Mutex::new(OdenRev2LstatCandidateTraceState {
        next_phase: 0,
        failed: false,
        observed: None,
      }),
    })
  }

  fn record(
    &self,
    phase: FilesystemTracePhase,
  ) -> Result<(), OdenRev2FilesystemError> {
    let mut trace =
      self.trace.lock().map_err(|_| refused("CANDIDATE-TRACE"))?;
    if trace.failed
      || self.expected_trace.get(trace.next_phase).copied() != Some(phase)
    {
      trace.failed = true;
      return Err(refused("CANDIDATE-TRACE"));
    }
    trace.next_phase += 1;
    Ok(())
  }

  fn actors(&self) -> VerifiedPermissionActorSet {
    self.actors.clone()
  }

  fn observe_delivery(
    &self,
    delivery: &OdenRev2LstatDelivery<'_>,
  ) -> Result<(), OdenRev2FilesystemError> {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
      let observed = match self.case {
        OdenRev2LstatCandidateCase::Existing => {
          let delivered = delivery
            .metadata()
            .ok_or_else(|| refused("CANDIDATE-TARGET-MISSING"))?;
          let after = reconcile_lstat_existing_host_inventory(
            &self.root_path,
            &self.validated,
          )?;
          if candidate_platform_identity(&after)
            != candidate_platform_identity(delivered)
            || candidate_metadata_projection(&after)
              != candidate_metadata_projection(delivered)
          {
            return Err(refused("CANDIDATE-TARGET-RACE"));
          }
          OdenRev2LstatCandidateObserved::Existing
        }
        OdenRev2LstatCandidateCase::FinalMissing => {
          if !delivery.is_not_found() {
            return Err(refused("CANDIDATE-TARGET-PRESENT"));
          }
          reconcile_lstat_final_missing_host_inventory(
            &self.root_path,
            &self.validated,
          )?;
          OdenRev2LstatCandidateObserved::FinalMissing
        }
      };
      {
        let mut trace =
          self.trace.lock().map_err(|_| refused("CANDIDATE-TRACE"))?;
        if trace.observed.replace(observed).is_some() {
          trace.failed = true;
          return Err(refused("CANDIDATE-ONE-SHOT"));
        }
      }
      self.record(FilesystemTracePhase::DeliverySerialized)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
      let _ = delivery;
      Err(refused("PLATFORM-UNSUPPORTED"))
    }
  }

  fn finish(
    &self,
    public_op_succeeded: bool,
  ) -> Result<OdenRev2LstatCandidateObservation, OdenRev2FilesystemError> {
    self.record(FilesystemTracePhase::HarnessExited)?;
    let trace = self.trace.lock().map_err(|_| refused("CANDIDATE-TRACE"))?;
    let expected_observed = match self.case {
      OdenRev2LstatCandidateCase::Existing => {
        OdenRev2LstatCandidateObserved::Existing
      }
      OdenRev2LstatCandidateCase::FinalMissing => {
        OdenRev2LstatCandidateObserved::FinalMissing
      }
    };
    let expected_success = self.case == OdenRev2LstatCandidateCase::Existing;
    if trace.failed
      || trace.next_phase != self.expected_trace.len()
      || trace.observed != Some(expected_observed)
      || public_op_succeeded != expected_success
    {
      return Err(refused("CANDIDATE-PUBLIC-OP-OUTCOME"));
    }
    Ok(OdenRev2LstatCandidateObservation { _private: () })
  }
}

impl OdenRev2RuntimeAuthorityContext {
  fn candidate_lstat_actors(
    &self,
    edge_id: &str,
  ) -> Result<Option<VerifiedPermissionActorSet>, OdenRev2FilesystemError> {
    let Some(harness) = &self.lstat_candidate else {
      return Ok(None);
    };
    if edge_id != LSTAT_EDGE {
      return Err(refused("CANDIDATE-EDGE"));
    }
    Ok(Some(harness.actors()))
  }

  fn record_candidate_lstat_phase(
    &self,
    phase: FilesystemTracePhase,
  ) -> Result<(), OdenRev2FilesystemError> {
    if let Some(harness) = &self.lstat_candidate {
      harness.record(phase)?;
    }
    Ok(())
  }
}

/// One shared one-shot binding placed only in the capsule's private `OpState`.
/// Clones share the same claim bit and sealed context.
#[doc(hidden)]
pub struct OdenRev2LstatCandidateOpStateBinding {
  context: Arc<OdenRev2RuntimeAuthorityContext>,
  harness: Arc<OdenRev2LstatCandidateHarness>,
  claimed: AtomicBool,
}

impl OdenRev2LstatCandidateOpStateBinding {
  fn claim_context(
    &self,
    path: &Path,
  ) -> Result<&OdenRev2RuntimeAuthorityContext, OdenRev2FilesystemError> {
    if crate::oden_capsec_rev2_process_mode()
      != crate::OdenRev2ProcessMode::Rev1
      || crate::oden_capsec_rev2_runtime_authority_context().is_some()
      || !exact_candidate_path(path, &self.harness.target_path)
    {
      return Err(refused("CANDIDATE-OPSTATE-BOUNDARY"));
    }
    self
      .claimed
      .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
      .map_err(|_| refused("CANDIDATE-ONE-SHOT"))?;
    reconcile_lstat_candidate_root(&self.context, &self.harness)?;
    self.harness.record(FilesystemTracePhase::PublicOpEntered)?;
    Ok(&self.context)
  }

  #[cfg(test)]
  fn claim_for_test(
    &self,
    path: &Path,
  ) -> Result<&OdenRev2RuntimeAuthorityContext, OdenRev2FilesystemError> {
    self.claim_context(path)
  }

  #[doc(hidden)]
  pub fn observe_delivery(
    &self,
    path: &Path,
    delivery: &OdenRev2LstatDelivery<'_>,
  ) -> Result<(), OdenRev2FilesystemError> {
    if !exact_candidate_path(path, &self.harness.target_path)
      || !self.claimed.load(Ordering::Acquire)
    {
      return Err(refused("CANDIDATE-OPSTATE-BOUNDARY"));
    }
    self.harness.observe_delivery(delivery)
  }

  #[doc(hidden)]
  pub fn finish(
    &self,
    public_op_succeeded: bool,
  ) -> Result<OdenRev2LstatCandidateObservation, OdenRev2FilesystemError> {
    if !self.claimed.load(Ordering::Acquire) {
      return Err(refused("CANDIDATE-PUBLIC-OP-NOT-ENTERED"));
    }
    self.harness.finish(public_op_succeeded)
  }
}

/// Production-uncalled capsule for exactly one generated lstat Candidate.
/// Its only consumable output is a one-shot `OpState` binding plus the exact
/// generated target path; no authority, expectation, target, feature set,
/// projection, oracle, or verdict is caller-selectable.
#[doc(hidden)]
pub struct OdenRev2LstatCandidateCapsule {
  binding: Arc<OdenRev2LstatCandidateOpStateBinding>,
  target_path: PathBuf,
}

impl OdenRev2LstatCandidateCapsule {
  #[doc(hidden)]
  pub fn into_execution_parts(
    self,
  ) -> (Arc<OdenRev2LstatCandidateOpStateBinding>, PathBuf) {
    (self.binding, self.target_path)
  }
}

/// Opaque expected-free completion. It deliberately exposes no metadata,
/// expected value, oracle result, verdict, receipt, report, or promotion bit.
#[doc(hidden)]
pub struct OdenRev2LstatCandidateObservation {
  _private: (),
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

/// Enter the sealed Candidate context and run the same checked adapter used by
/// the registered public op. The context itself never crosses this boundary,
/// so it cannot be reused for another native adapter.
#[doc(hidden)]
pub fn oden_capsec_rev2_lstat_candidate_sync<'binding>(
  binding: &'binding OdenRev2LstatCandidateOpStateBinding,
  path: &Path,
) -> Result<OdenRev2LstatDelivery<'binding>, OdenRev2FilesystemError> {
  let context = binding.claim_context(path)?;
  oden_capsec_rev2_lstat_sync(context, path)
}

/// One unauthenticated native observation of the dormant `lstat-existing`
/// fixture candidate. This type intentionally has no serialization, oracle,
/// verdict, receipt, report, promotion, or publication API.
///
/// @ref LLP 0019#generated-outputs-and-ci-invariants [constrained-by] --
/// Generated fixture identity is candidate provenance, not observed
/// conformance or promotion authority.
#[allow(dead_code)]
struct OdenRev2LstatExistingCandidateObservation {
  fixture_artifact_digest: &'static str,
  case_id: String,
  target: &'static str,
  metadata: std::fs::Metadata,
}

#[allow(dead_code)]
impl OdenRev2LstatExistingCandidateObservation {
  fn fixture_artifact_digest(&self) -> &'static str {
    self.fixture_artifact_digest
  }

  fn case_id(&self) -> &str {
    &self.case_id
  }

  fn target(&self) -> &'static str {
    self.target
  }

  fn metadata(&self) -> &std::fs::Metadata {
    &self.metadata
  }
}

/// One unauthenticated native not-found observation of the dormant
/// `lstat-final-missing` fixture candidate. This opaque type intentionally has
/// no metadata, serialization, oracle, verdict, receipt, report, promotion,
/// or publication API.
///
/// @ref LLP 0019#generated-outputs-and-ci-invariants [constrained-by] --
/// Generated fixture identity is candidate provenance, not observed
/// conformance or promotion authority.
#[allow(dead_code)]
struct OdenRev2LstatFinalMissingCandidateObservation {
  fixture_artifact_digest: &'static str,
  case_id: String,
  target: &'static str,
}

#[allow(dead_code)]
impl OdenRev2LstatFinalMissingCandidateObservation {
  fn fixture_artifact_digest(&self) -> &'static str {
    self.fixture_artifact_digest
  }

  fn case_id(&self) -> &str {
    &self.case_id
  }

  fn target(&self) -> &'static str {
    self.target
  }

  fn is_not_found(&self) -> bool {
    true
  }
}

fn validate_lstat_candidate_context(
  target: &str,
  feature_set: &str,
  admission: &Rev2FilesystemLstatExecutionAdmission,
) -> Result<(), OdenRev2FilesystemError> {
  if target != admission.target {
    return Err(refused("CANDIDATE-TARGET"));
  }
  if feature_set != admission.feature_set {
    return Err(refused("CANDIDATE-FEATURE-SET"));
  }
  Ok(())
}

fn validate_lstat_existing_candidate_context(
  target: &str,
  feature_set: &str,
  admission: &Rev2FilesystemLstatExecutionAdmission,
) -> Result<(), OdenRev2FilesystemError> {
  validate_lstat_candidate_context(target, feature_set, admission)
}

fn validate_lstat_final_missing_candidate_context(
  target: &str,
  feature_set: &str,
  admission: &Rev2FilesystemLstatExecutionAdmission,
) -> Result<(), OdenRev2FilesystemError> {
  validate_lstat_candidate_context(target, feature_set, admission)
}

const FILESYSTEM_EXECUTION_PROJECTION_DIGEST_DOMAIN: &str =
  "oden:capsec:filesystem-execution-projection:2";
const LSTAT_EXISTING_CASE_ID: &str = "filesystem:lstat-sync:lstat-existing";
const LSTAT_FINAL_MISSING_CASE_ID: &str =
  "filesystem:lstat-sync:lstat-final-missing";
const LSTAT_EXISTING_REQUIREMENT_ID: &str =
  "fixture-requirement:native-op:ext/fs/ops.rs#op_fs_lstat_sync:complete";
const LSTAT_EXISTING_CONTENT_DIGEST: &str =
  "sha256-47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU";

// "Admission" here means only that one candidate-local expected-free execution
// projection equals one compiled generated row. Pointer identity does not
// authenticate the repository, content tree, fixture definition, runner,
// process, caller-assembled inventory, or any execution fact and grants no
// runtime or release authority.
fn validate_lstat_execution_admission(
  target: &str,
  feature_set: &str,
  registered_admissions: &'static [Rev2FilesystemLstatExecutionAdmission],
  admission: &'static Rev2FilesystemLstatExecutionAdmission,
  input: FilesystemCandidateOracleInput,
) -> Result<ValidatedFilesystemCandidateExecution, OdenRev2FilesystemError> {
  if !registered_admissions
    .iter()
    .any(|registered| std::ptr::eq(registered, admission))
  {
    return Err(refused("CANDIDATE-EXECUTION-ADMISSION"));
  }
  validate_lstat_candidate_context(target, feature_set, admission)?;
  let generated_projection =
    validate_lstat_generated_admission_projection(admission)?;
  if input.case_projection != generated_projection
    || input.case_projection_digest != admission.case_projection_digest
  {
    return Err(refused("CANDIDATE-GENERATED-PROJECTION"));
  }

  validate_filesystem_candidate_execution(input)
    .map_err(|_| refused("CANDIDATE-EXECUTION-INPUT"))
}

fn validate_lstat_generated_admission_projection(
  admission: &Rev2FilesystemLstatExecutionAdmission,
) -> Result<FilesystemExecutionProjection, OdenRev2FilesystemError> {
  let generated_projection: FilesystemExecutionProjection =
    serde_json::from_str(admission.case_projection_json)
      .map_err(|_| refused("CANDIDATE-GENERATED-PROJECTION"))?;
  let generated_projection_value = serde_json::to_value(&generated_projection)
    .map_err(|_| refused("CANDIDATE-GENERATED-PROJECTION"))?;
  if canonical_json(&generated_projection_value)
    .map_err(|_| refused("CANDIDATE-GENERATED-PROJECTION"))?
    != admission.case_projection_json
    || hjcs_digest(
      FILESYSTEM_EXECUTION_PROJECTION_DIGEST_DOMAIN,
      &generated_projection_value,
    )
    .map_err(|_| refused("CANDIDATE-GENERATED-PROJECTION"))?
      != admission.case_projection_digest
  {
    return Err(refused("CANDIDATE-GENERATED-PROJECTION"));
  }
  Ok(generated_projection)
}

fn validate_lstat_existing_execution_admission(
  target: &str,
  feature_set: &str,
  admission: &'static Rev2FilesystemLstatExecutionAdmission,
  input: FilesystemCandidateOracleInput,
) -> Result<ValidatedFilesystemCandidateExecution, OdenRev2FilesystemError> {
  let validated = validate_lstat_execution_admission(
    target,
    feature_set,
    REV2_FILESYSTEM_LSTAT_EXISTING_EXECUTION_ADMISSIONS,
    admission,
    input,
  )?;
  let projection = validated.execution_projection();
  let target_setup = validated.target_setup();
  let target_initial = validated.target_initial();
  let target_content = target_setup.content.as_ref();
  if admission.case_id != LSTAT_EXISTING_CASE_ID
    || projection.case_id != LSTAT_EXISTING_CASE_ID
    || projection.edge_id != LSTAT_EDGE
    || projection.requirement_id != LSTAT_EXISTING_REQUIREMENT_ID
    || projection.case_kind != "lstat-existing"
    || projection.mode != FilesystemExecutionMode::Enforce
    || projection.input_mutation != FilesystemInputMutation::None
    || target_setup.object_id != "source"
    || target_setup.root != FilesystemLogicalRoot::Project
    || target_setup.path.encoding != FilesystemPlatformPathEncoding::Unicode
    || target_setup.path.value != "input.txt"
    || target_setup
      .object_identity
      .as_ref()
      .is_none_or(|identity| {
        identity.kind != FilesystemObjectIdentityKind::VerifiedContent
          || identity.value != LSTAT_EXISTING_CONTENT_DIGEST
      })
    || target_setup.kind != FilesystemObjectKind::RegularFile
    || target_setup.content_digest.as_deref()
      != Some(LSTAT_EXISTING_CONTENT_DIGEST)
    || target_content.is_none_or(|content| !content.bytes.is_empty())
    || target_setup.alias_target_object_id.is_some()
    || target_setup.link_target_object_id.is_some()
    || target_initial.state.kind != FilesystemObjectKind::RegularFile
    || target_initial.state.content_digest.as_deref()
      != Some(LSTAT_EXISTING_CONTENT_DIGEST)
    || validated.runtime_slots().len() != 1
    || validated.runtime_slots()[0].slot_id != LSTAT_LIST_SLOT
    || validated.runtime_slots()[0].capability != "fs:list"
  {
    return Err(refused("CANDIDATE-EXECUTION-CASE"));
  }
  Ok(validated)
}

fn validate_lstat_final_missing_execution_admission(
  target: &str,
  feature_set: &str,
  admission: &'static Rev2FilesystemLstatExecutionAdmission,
  input: FilesystemCandidateOracleInput,
) -> Result<ValidatedFilesystemCandidateExecution, OdenRev2FilesystemError> {
  let validated = validate_lstat_execution_admission(
    target,
    feature_set,
    REV2_FILESYSTEM_LSTAT_FINAL_MISSING_EXECUTION_ADMISSIONS,
    admission,
    input,
  )?;
  let projection = validated.execution_projection();
  let target_setup = validated.target_setup();
  let target_initial = validated.target_initial();
  let initial_sandbox = validated.initial_sandbox();
  if admission.case_id != LSTAT_FINAL_MISSING_CASE_ID
    || projection.case_id != LSTAT_FINAL_MISSING_CASE_ID
    || projection.edge_id != LSTAT_EDGE
    || projection.requirement_id != LSTAT_EXISTING_REQUIREMENT_ID
    || projection.case_kind != "lstat-final-missing"
    || projection.mode != FilesystemExecutionMode::Enforce
    || projection.input_mutation != FilesystemInputMutation::None
    || target_setup.object_id != "source"
    || target_setup.root != FilesystemLogicalRoot::Project
    || target_setup.path.encoding != FilesystemPlatformPathEncoding::Unicode
    || target_setup.path.value != "input.txt"
    || target_setup.object_identity.is_some()
    || target_setup.kind != FilesystemObjectKind::Missing
    || target_setup.content.is_some()
    || target_setup.content_digest.is_some()
    || target_setup.alias_target_object_id.is_some()
    || target_setup.link_target_object_id.is_some()
    || target_initial.state.kind != FilesystemObjectKind::Missing
    || target_initial.state.identity.is_some()
    || target_initial.state.metadata.is_some()
    || target_initial.state.content_digest.is_some()
    || target_initial.state.alias_target_object_id.is_some()
    || target_initial.state.link_target_object_id.is_some()
    || initial_sandbox.objects.len() != 2
    || !initial_sandbox.unexpected_entries.is_empty()
    || initial_sandbox.objects.iter().any(|object| {
      object.state.kind != FilesystemObjectKind::Missing
        || object.state.identity.is_some()
        || object.state.metadata.is_some()
        || object.state.content_digest.is_some()
        || object.state.alias_target_object_id.is_some()
        || object.state.link_target_object_id.is_some()
    })
    || validated.runtime_slots().len() != 1
    || validated.runtime_slots()[0].slot_id != LSTAT_LIST_SLOT
    || validated.runtime_slots()[0].capability != "fs:list"
    || !matches!(
      validated.runtime_slots()[0].occurrence.final_object_state,
      FilesystemFinalObjectState::Missing
    )
  {
    return Err(refused("CANDIDATE-EXECUTION-CASE"));
  }
  Ok(validated)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn candidate_platform_identity(
  metadata: &std::fs::Metadata,
) -> FilesystemObjectIdentity {
  use std::os::unix::fs::MetadataExt;

  FilesystemObjectIdentity {
    kind: FilesystemObjectIdentityKind::PlatformObject,
    value: format!(
      "unix-dev-ino:{:016x}{:016x}",
      metadata.dev(),
      metadata.ino()
    ),
  }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn candidate_unix_time_ns(seconds: i64, nanoseconds: i64) -> String {
  (i128::from(seconds) * 1_000_000_000_i128 + i128::from(nanoseconds))
    .to_string()
}

#[cfg(target_os = "macos")]
fn candidate_birth_time_ns(metadata: &std::fs::Metadata) -> Option<String> {
  use std::os::macos::fs::MetadataExt;

  Some(candidate_unix_time_ns(
    metadata.st_birthtime(),
    metadata.st_birthtime_nsec(),
  ))
}

#[cfg(not(target_os = "macos"))]
fn candidate_birth_time_ns(_: &std::fs::Metadata) -> Option<String> {
  None
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn candidate_metadata_projection(
  metadata: &std::fs::Metadata,
) -> FilesystemMetadataProjection {
  use std::os::unix::fs::MetadataExt;

  FilesystemMetadataProjection {
    mode: metadata.mode(),
    size: metadata.size().to_string(),
    link_count: metadata.nlink().to_string(),
    device: metadata.dev().to_string(),
    inode: metadata.ino().to_string(),
    uid: Some(metadata.uid().to_string()),
    gid: Some(metadata.gid().to_string()),
    rdev: Some(metadata.rdev().to_string()),
    block_size: Some(metadata.blksize().to_string()),
    blocks: Some(metadata.blocks().to_string()),
    accessed_time_ns: Some(candidate_unix_time_ns(
      metadata.atime(),
      metadata.atime_nsec(),
    )),
    modified_time_ns: Some(candidate_unix_time_ns(
      metadata.mtime(),
      metadata.mtime_nsec(),
    )),
    changed_time_ns: Some(candidate_unix_time_ns(
      metadata.ctime(),
      metadata.ctime_nsec(),
    )),
    birth_time_ns: candidate_birth_time_ns(metadata),
  }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
// This preparatory reconciliation deliberately uses path-based metadata and
// directory APIs. It catches the closed mutations exercised below, but does
// not retain one parent descriptor across the whole sequence and is not a
// race-free or authenticated fixture-setup proof.
fn reconcile_lstat_existing_host_inventory(
  parent_root: &Path,
  validated: &ValidatedFilesystemCandidateExecution,
) -> Result<std::fs::Metadata, OdenRev2FilesystemError> {
  use std::os::unix::fs::MetadataExt;

  let canonical_parent = std::fs::canonicalize(parent_root)
    .map_err(|_| refused("CANDIDATE-PARENT-ROOT-CANONICAL"))?;
  if !exact_candidate_path(&canonical_parent, parent_root) {
    return Err(refused("CANDIDATE-PARENT-ROOT-CANONICAL"));
  }
  let parent_metadata = std::fs::symlink_metadata(parent_root)
    .map_err(|_| refused("CANDIDATE-PARENT-ROOT-IDENTITY"))?;
  if !parent_metadata.is_dir() {
    return Err(refused("CANDIDATE-PARENT-ROOT-IDENTITY"));
  }
  let realized_root = validated
    .initial_sandbox()
    .logical_roots
    .iter()
    .find(|root| root.root == FilesystemLogicalRoot::Project)
    .ok_or_else(|| refused("CANDIDATE-PARENT-ROOT-IDENTITY"))?;
  if realized_root.platform_identity
    != candidate_platform_identity(&parent_metadata)
  {
    return Err(refused("CANDIDATE-PARENT-ROOT-IDENTITY"));
  }

  let mut entry_names = std::fs::read_dir(parent_root)
    .map_err(|_| refused("CANDIDATE-INITIAL-INVENTORY"))?
    .map(|entry| {
      entry
        .map(|entry| entry.file_name())
        .map_err(|_| refused("CANDIDATE-INITIAL-INVENTORY"))
    })
    .collect::<Result<Vec<_>, _>>()?;
  entry_names.sort();
  if entry_names != [std::ffi::OsString::from("input.txt")] {
    return Err(refused("CANDIDATE-INITIAL-INVENTORY"));
  }

  let target_path = parent_root.join("input.txt");
  let target_metadata = std::fs::symlink_metadata(&target_path)
    .map_err(|_| refused("CANDIDATE-TARGET-IDENTITY"))?;
  let target_initial = validated.target_initial();
  if !target_metadata.is_file()
    || target_metadata.nlink() != 1
    || target_metadata.len() != 0
    || target_initial.state.identity.as_ref()
      != Some(&candidate_platform_identity(&target_metadata))
    || target_initial.state.metadata.as_ref()
      != Some(&candidate_metadata_projection(&target_metadata))
  {
    return Err(refused("CANDIDATE-TARGET-IDENTITY"));
  }
  Ok(target_metadata)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
// This preparatory missing-entry reconciliation has the same candidate-only
// path-observation limit as the existing-entry variant above. It exact-closes
// every observed directory entry and repeats the check while delivery remains
// pinned, but cannot prove continuous absence between kernel observations.
fn reconcile_lstat_final_missing_host_inventory(
  parent_root: &Path,
  validated: &ValidatedFilesystemCandidateExecution,
) -> Result<(), OdenRev2FilesystemError> {
  let canonical_parent = std::fs::canonicalize(parent_root)
    .map_err(|_| refused("CANDIDATE-PARENT-ROOT-CANONICAL"))?;
  if !exact_candidate_path(&canonical_parent, parent_root) {
    return Err(refused("CANDIDATE-PARENT-ROOT-CANONICAL"));
  }
  let parent_metadata = std::fs::symlink_metadata(parent_root)
    .map_err(|_| refused("CANDIDATE-PARENT-ROOT-IDENTITY"))?;
  if !parent_metadata.is_dir() {
    return Err(refused("CANDIDATE-PARENT-ROOT-IDENTITY"));
  }
  let realized_root = validated
    .initial_sandbox()
    .logical_roots
    .iter()
    .find(|root| root.root == FilesystemLogicalRoot::Project)
    .ok_or_else(|| refused("CANDIDATE-PARENT-ROOT-IDENTITY"))?;
  if realized_root.platform_identity
    != candidate_platform_identity(&parent_metadata)
  {
    return Err(refused("CANDIDATE-PARENT-ROOT-IDENTITY"));
  }

  let mut entry_names = std::fs::read_dir(parent_root)
    .map_err(|_| refused("CANDIDATE-INITIAL-INVENTORY"))?
    .map(|entry| {
      entry
        .map(|entry| entry.file_name())
        .map_err(|_| refused("CANDIDATE-INITIAL-INVENTORY"))
    })
    .collect::<Result<Vec<_>, _>>()?;
  entry_names.sort();
  if !entry_names.is_empty() {
    return Err(refused("CANDIDATE-INITIAL-INVENTORY"));
  }
  match std::fs::symlink_metadata(parent_root.join("input.txt")) {
    Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
    _ => Err(refused("CANDIDATE-TARGET-IDENTITY")),
  }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn compiled_lstat_target_status() -> Result<
  &'static crate::rev2_registry_generated::Rev2TargetStatus,
  OdenRev2FilesystemError,
> {
  #[cfg(all(
    target_arch = "x86_64",
    target_vendor = "unknown",
    target_os = "linux",
    target_env = "gnu"
  ))]
  let target = "x86_64-unknown-linux-gnu";
  #[cfg(all(
    target_arch = "aarch64",
    target_vendor = "apple",
    target_os = "macos"
  ))]
  let target = "aarch64-apple-darwin";
  #[cfg(not(any(
    all(
      target_arch = "x86_64",
      target_vendor = "unknown",
      target_os = "linux",
      target_env = "gnu"
    ),
    all(target_arch = "aarch64", target_vendor = "apple", target_os = "macos")
  )))]
  let target: &str = {
    return Err(refused("CANDIDATE-TARGET"));
  };
  REV2_TARGET_STATUS
    .iter()
    .find(|status| status.target == target)
    .ok_or_else(|| refused("CANDIDATE-TARGET"))
}

/// Opaque, authority-free equality projection of one generated lstat
/// admission and the generated target row selected by this binary's native
/// cfg and complete compiled build identity.
///
/// It intentionally exposes no generated table, projection bytes, public-op
/// capsule, descriptor, runtime context, execution method, or serialization
/// surface. Its typed expected-free projection is retained only so the
/// candidate can reconstruct transferred descriptor facts without reselecting
/// an admission from caller-provided strings.
#[doc(hidden)]
pub struct OdenRev2LstatCandidateBinaryIdentity {
  fixture_artifact_digest: &'static str,
  case_id: &'static str,
  target: &'static str,
  feature_set: &'static str,
  rust_toolchain: &'static str,
  cargo_features: &'static str,
  rust_cfg_digest: &'static str,
  cargo_feature_graph_digest: &'static str,
  build_profile: &'static str,
  execution_projection_digest: &'static str,
  execution_projection: FilesystemExecutionProjection,
}

impl OdenRev2LstatCandidateBinaryIdentity {
  pub fn fixture_artifact_digest(&self) -> &'static str {
    self.fixture_artifact_digest
  }

  pub fn case_id(&self) -> &'static str {
    self.case_id
  }

  pub fn target(&self) -> &'static str {
    self.target
  }

  pub fn feature_set(&self) -> &'static str {
    self.feature_set
  }

  pub fn rust_toolchain(&self) -> &'static str {
    self.rust_toolchain
  }

  pub fn cargo_features(&self) -> &'static str {
    self.cargo_features
  }

  pub fn rust_cfg_digest(&self) -> &'static str {
    self.rust_cfg_digest
  }

  pub fn cargo_feature_graph_digest(&self) -> &'static str {
    self.cargo_feature_graph_digest
  }

  pub fn build_profile(&self) -> &'static str {
    self.build_profile
  }

  pub fn execution_projection_digest(&self) -> &'static str {
    self.execution_projection_digest
  }

  pub fn execution_projection(&self) -> &FilesystemExecutionProjection {
    &self.execution_projection
  }
}

/// Select one exact generated lstat admission only after joining the current
/// binary's native cfg and complete embedded build-marker facts to the same
/// generated target row.
///
/// @ref LLP 0019#pre-promotion-conformance-candidate-execution
/// [constrained-by] -- This is a dormant equality join before FD3 descriptor
/// reconstruction. It authenticates no image or execution fact, constructs no
/// runtime/public-op capsule, and grants no conformance or release authority.
#[doc(hidden)]
pub fn oden_capsec_rev2_join_lstat_candidate_binary_identity(
  build_identity: &OdenRev2CompiledBuildIdentity,
  fixture_artifact_digest: &str,
  case_id: &str,
) -> Result<OdenRev2LstatCandidateBinaryIdentity, OdenRev2FilesystemError> {
  #[cfg(any(target_os = "linux", target_os = "macos"))]
  {
    join_lstat_candidate_binary_identity_with_validator(
      build_identity,
      fixture_artifact_digest,
      case_id,
      validate_current_binary_candidate_build_identity,
    )
  }
  #[cfg(not(any(target_os = "linux", target_os = "macos")))]
  {
    let _ = (build_identity, fixture_artifact_digest, case_id);
    Err(refused("PLATFORM-UNSUPPORTED"))
  }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn join_lstat_candidate_binary_identity_with_validator(
  build_identity: &OdenRev2CompiledBuildIdentity,
  fixture_artifact_digest: &str,
  case_id: &str,
  validate_build: impl FnOnce(
    &crate::rev2_registry_generated::Rev2TargetStatus,
    &OdenRev2CompiledBuildIdentity,
  ) -> Result<(), String>,
) -> Result<OdenRev2LstatCandidateBinaryIdentity, OdenRev2FilesystemError> {
  let target = compiled_lstat_target_status()?;
  validate_build(target, build_identity)
    .map_err(|_| refused("CANDIDATE-BINARY-IDENTITY"))?;
  let admission = select_lstat_candidate_admission(
    fixture_artifact_digest,
    case_id,
    target.target,
    target.feature_set,
  )?;
  let projection = validate_lstat_generated_admission_projection(admission)?;
  if projection.case_id != admission.case_id {
    return Err(refused("CANDIDATE-GENERATED-PROJECTION"));
  }
  Ok(OdenRev2LstatCandidateBinaryIdentity {
    fixture_artifact_digest: admission.fixture_artifact_digest,
    case_id: admission.case_id,
    target: target.target,
    feature_set: target.feature_set,
    rust_toolchain: target.rust_toolchain,
    cargo_features: target.cargo_features,
    rust_cfg_digest: target.rust_cfg_digest,
    cargo_feature_graph_digest: target.cargo_feature_graph_digest,
    build_profile: target.build_profile,
    execution_projection_digest: admission.case_projection_digest,
    execution_projection: projection,
  })
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn select_lstat_candidate_admission(
  fixture_artifact_digest: &str,
  case_id: &str,
  target: &str,
  feature_set: &str,
) -> Result<
  &'static Rev2FilesystemLstatExecutionAdmission,
  OdenRev2FilesystemError,
> {
  let admissions = match case_id {
    LSTAT_EXISTING_CASE_ID => {
      REV2_FILESYSTEM_LSTAT_EXISTING_EXECUTION_ADMISSIONS
    }
    LSTAT_FINAL_MISSING_CASE_ID => {
      REV2_FILESYSTEM_LSTAT_FINAL_MISSING_EXECUTION_ADMISSIONS
    }
    _ => return Err(refused("CANDIDATE-EXECUTION-ADMISSION")),
  };
  let mut matches = admissions.iter().filter(|admission| {
    admission.fixture_artifact_digest == fixture_artifact_digest
      && admission.case_id == case_id
      && admission.target == target
      && admission.feature_set == feature_set
  });
  let admission = matches
    .next()
    .ok_or_else(|| refused("CANDIDATE-EXECUTION-ADMISSION"))?;
  if matches.next().is_some() {
    return Err(refused("CANDIDATE-EXECUTION-ADMISSION"));
  }
  Ok(admission)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn lstat_candidate_input(
  root: &Path,
  admission: &Rev2FilesystemLstatExecutionAdmission,
) -> Result<FilesystemCandidateOracleInput, OdenRev2FilesystemError> {
  let projection: FilesystemExecutionProjection =
    serde_json::from_str(admission.case_projection_json)
      .map_err(|_| refused("CANDIDATE-GENERATED-PROJECTION"))?;
  let root_setup = projection
    .setup
    .logical_roots
    .iter()
    .find(|candidate| candidate.root == FilesystemLogicalRoot::Project)
    .ok_or_else(|| refused("CANDIDATE-PARENT-ROOT-IDENTITY"))?;
  let root_metadata = std::fs::symlink_metadata(root)
    .map_err(|_| refused("CANDIDATE-PARENT-ROOT-IDENTITY"))?;
  let mut objects = Vec::with_capacity(projection.setup.objects.len());
  for object in &projection.setup.objects {
    let state = match object.kind {
      FilesystemObjectKind::RegularFile => {
        let metadata = std::fs::symlink_metadata(root.join(&object.path.value))
          .map_err(|_| refused("CANDIDATE-TARGET-IDENTITY"))?;
        FilesystemRealizedObjectState {
          kind: FilesystemObjectKind::RegularFile,
          identity: Some(candidate_platform_identity(&metadata)),
          metadata: Some(candidate_metadata_projection(&metadata)),
          content_digest: object.content_digest.clone(),
          alias_target_object_id: object.alias_target_object_id.clone(),
          link_target_object_id: object.link_target_object_id.clone(),
        }
      }
      FilesystemObjectKind::Missing => {
        if !std::fs::symlink_metadata(root.join(&object.path.value))
          .is_err_and(|error| error.kind() == io::ErrorKind::NotFound)
        {
          return Err(refused("CANDIDATE-TARGET-IDENTITY"));
        }
        FilesystemRealizedObjectState {
          kind: FilesystemObjectKind::Missing,
          identity: None,
          metadata: None,
          content_digest: None,
          alias_target_object_id: None,
          link_target_object_id: None,
        }
      }
      _ => return Err(refused("CANDIDATE-EXECUTION-CASE")),
    };
    objects.push(FilesystemInitialSandboxObject {
      object_id: object.object_id.clone(),
      root: object.root,
      path: object.path.clone(),
      fixture_identity: object.object_identity.clone(),
      state,
    });
  }
  let initial_sandbox = FilesystemInitialSandboxInventory {
    schema: "oden/capsec-filesystem-sandbox-inventory/2".to_string(),
    phase: FilesystemSandboxPhase::Initial,
    logical_roots: vec![FilesystemRealizedLogicalRoot {
      root: FilesystemLogicalRoot::Project,
      binding_id: root_setup.binding_id.clone(),
      fixture_identity: root_setup.object_identity.clone(),
      platform_identity: candidate_platform_identity(&root_metadata),
    }],
    objects,
    unexpected_entries: Vec::new(),
  };
  let inventory_value = serde_json::to_value(&initial_sandbox)
    .map_err(|_| refused("CANDIDATE-INITIAL-INVENTORY"))?;
  let initial_inventory_digest = hjcs_digest(
    "oden:capsec:filesystem-sandbox-inventory:2",
    &inventory_value,
  )
  .map_err(|_| refused("CANDIDATE-INITIAL-INVENTORY"))?;
  Ok(FilesystemCandidateOracleInput {
    case_projection: projection,
    case_projection_digest: admission.case_projection_digest.to_string(),
    initial_sandbox,
    initial_inventory_digest,
    // This dormant capsule does not authenticate the future parent-captured
    // umask. Lstat does not consume it, and the opaque result is not evidence.
    parent_capture_facts: FilesystemParentCaptureFacts {
      captured_umask: 0o077,
    },
  })
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn lstat_candidate_snapshot(
  root: &Path,
  admission: &Rev2FilesystemLstatExecutionAdmission,
  validated: &ValidatedFilesystemCandidateExecution,
) -> Result<serde_json::Value, OdenRev2FilesystemError> {
  let projection = validated.execution_projection();
  let authority = projection
    .authority_rows
    .first()
    .ok_or_else(|| refused("CANDIDATE-EXECUTION-CASE"))?;
  let principal = projection
    .principals
    .first()
    .cloned()
    .ok_or_else(|| refused("CANDIDATE-GENERATED-ACTORS"))?;
  let root_binding = projection
    .setup
    .logical_roots
    .iter()
    .find(|binding| binding.root == FilesystemLogicalRoot::Project)
    .ok_or_else(|| refused("CANDIDATE-PARENT-ROOT-IDENTITY"))?;
  let realized_root = validated
    .initial_sandbox()
    .logical_roots
    .iter()
    .find(|binding| binding.root == FilesystemLogicalRoot::Project)
    .ok_or_else(|| refused("CANDIDATE-PARENT-ROOT-IDENTITY"))?;
  let resource = serde_json::to_value(&authority.resource)
    .map_err(|_| refused("CANDIDATE-GENERATED-PROJECTION"))?;
  let selector = Rev2Core::embedded()
    .map_err(|_| refused("CANDIDATE-GENERATED-PROJECTION"))?
    .normalize_selector(
      &AuthoritySelectorInput {
        identity: EngineIdentity::embedded(),
        principal: Some(principal.clone()),
        capability: authority.capability.clone(),
        resource,
      },
      SelectorPolarity::Positive,
    )
    .map_err(|_| refused("CANDIDATE-GENERATED-PROJECTION"))?;
  let mut policy = serde_json::json!({
    "policySchema": CANDIDATE_POLICY_SCHEMA,
    "capsVocab": REV2_PROFILE,
    "vocabDigest": REV2_VOCAB_DIGEST,
    "policyDigest": "",
    "mode": "enforce",
    "principals": [{
      "principal": principal.clone(),
      "binding": {
        "resolverId": "fixture-lock-resolver/2",
        "bindingDigest": REV2_VOCAB_DIGEST,
      },
      "floor": [{
        "sourceId": authority.source_id,
        "selector": selector,
      }],
      "escalationCeiling": [],
      "denials": [],
    }],
    "processDenials": [],
  });
  let mut policy_basis = policy.clone();
  policy_basis
    .as_object_mut()
    .ok_or_else(|| refused("CANDIDATE-GENERATED-PROJECTION"))?
    .remove("policyDigest");
  let policy_digest = domain_digest("oden:capsec:policy:2", &policy_basis)
    .map_err(|_| refused("CANDIDATE-GENERATED-PROJECTION"))?;
  policy["policyDigest"] = serde_json::Value::String(policy_digest.clone());
  let receipts = serde_json::Value::Array(Vec::new());
  let receipt_digest =
    domain_digest(CANDIDATE_RECEIPT_SET_DOMAIN, &receipts)
      .map_err(|_| refused("CANDIDATE-GENERATED-PROJECTION"))?;
  let root_path = root
    .to_str()
    .ok_or_else(|| refused("CANDIDATE-PARENT-ROOT-UNICODE"))?;
  let project_digest = domain_digest(
    "oden:capsec:lstat-candidate-project:1",
    &serde_json::json!({
      "caseProjectionDigest": admission.case_projection_digest,
      "rootIdentity": realized_root.platform_identity,
      "rootPath": root_path,
    }),
  )
  .map_err(|_| refused("CANDIDATE-GENERATED-PROJECTION"))?;
  let mut snapshot = serde_json::json!({
    "snapshotSchema": CANDIDATE_SNAPSHOT_SCHEMA,
    "capsVocab": REV2_PROFILE,
    "vocabDigest": REV2_VOCAB_DIGEST,
    "registryDigest": REV2_REGISTRY_DIGEST,
    "policyDigest": policy_digest,
    "projectDigest": project_digest,
    "armedSnapshotDigest": "",
    "engineTarget": admission.target,
    "engineFeatureSet": admission.feature_set,
    "executionRole": "candidate",
    "conformanceReportDigest": null,
    "effectiveMode": "enforce",
    "runNonce": format!("candidate:{}", admission.case_projection_digest),
    "channelEpoch": "candidate:unauthenticated",
    "canonicalPolicy": policy,
    "rootBindings": [{
      "sourceId": authority.source_id,
      "logicalRoot": "$PROJECT",
      "principal": principal,
      "rootBindingId": root_binding.binding_id,
      "canonicalPath": {
        "encoding": "unicode",
        "value": root_path,
      },
      "objectIdentity": realized_root.platform_identity,
      "bindingProvenanceDigest": REV2_REGISTRY_DIGEST,
    }],
    "denyCeiling": [],
    "executableBindings": [],
    "routeBindings": [],
    "classifierBindings": [],
    "protectedPredicateVersions": [],
    "protectedReceiptBindings": receipts,
    "protectedReceiptSetDigest": receipt_digest,
  });
  let mut armed_basis = snapshot.clone();
  armed_basis
    .as_object_mut()
    .ok_or_else(|| refused("CANDIDATE-GENERATED-PROJECTION"))?
    .remove("armedSnapshotDigest");
  snapshot["armedSnapshotDigest"] = serde_json::Value::String(
    domain_digest("oden:capsec:armed:2", &armed_basis)
      .map_err(|_| refused("CANDIDATE-GENERATED-PROJECTION"))?,
  );
  Ok(snapshot)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn reconcile_lstat_candidate_root(
  context: &OdenRev2RuntimeAuthorityContext,
  harness: &OdenRev2LstatCandidateHarness,
) -> Result<(), OdenRev2FilesystemError> {
  if context.execution_role() != super::OdenRev2ExecutionRole::Candidate
    || context.mode() != Mode::Enforce
    || context.target() != harness.admission.target
    || context.feature_set() != harness.admission.feature_set
  {
    return Err(refused("CANDIDATE-CONTEXT"));
  }
  let retained = context.retained_objects();
  let retained = match retained {
    [retained]
      if retained.binding_id() == harness.root_binding_id
        && exact_candidate_path(
          retained.canonical_path(),
          &harness.root_path,
        )
        && retained.role().is_none() =>
    {
      retained
    }
    _ => return Err(refused("CANDIDATE-PARENT-ROOT-IDENTITY")),
  };
  let canonical = std::fs::canonicalize(&harness.root_path)
    .map_err(|_| refused("CANDIDATE-PARENT-ROOT-CANONICAL"))?;
  let named = std::fs::symlink_metadata(&harness.root_path)
    .map_err(|_| refused("CANDIDATE-PARENT-ROOT-IDENTITY"))?;
  let held = retained
    .file()
    .metadata()
    .map_err(|_| refused("CANDIDATE-PARENT-ROOT-IDENTITY"))?;
  let initial = harness
    .validated
    .initial_sandbox()
    .logical_roots
    .iter()
    .find(|root| root.root == FilesystemLogicalRoot::Project)
    .ok_or_else(|| refused("CANDIDATE-PARENT-ROOT-IDENTITY"))?;
  if !exact_candidate_path(&canonical, &harness.root_path)
    || !named.is_dir()
    || !held.is_dir()
    || candidate_platform_identity(&named) != candidate_platform_identity(&held)
    || candidate_platform_identity(&held) != initial.platform_identity
    || retained.object_identity() != initial.platform_identity.value
  {
    return Err(refused("CANDIDATE-PARENT-ROOT-IDENTITY"));
  }
  Ok(())
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn reconcile_lstat_candidate_root(
  context: &OdenRev2RuntimeAuthorityContext,
  harness: &OdenRev2LstatCandidateHarness,
) -> Result<(), OdenRev2FilesystemError> {
  let _ = (context, harness);
  Err(refused("PLATFORM-UNSUPPORTED"))
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn reconcile_supplied_lstat_candidate_root(
  root: &Path,
  root_file: &File,
) -> Result<(), OdenRev2FilesystemError> {
  use std::os::fd::AsRawFd;
  use std::os::unix::fs::MetadataExt;

  let named = std::fs::symlink_metadata(root)
    .map_err(|_| refused("CANDIDATE-PARENT-ROOT-DESCRIPTOR"))?;
  let held = root_file
    .metadata()
    .map_err(|_| refused("CANDIDATE-PARENT-ROOT-DESCRIPTOR"))?;
  // SAFETY: `root_file` owns a live descriptor for this call; `F_GETFD` only
  // reads its descriptor flags.
  let descriptor_flags =
    unsafe { libc::fcntl(root_file.as_raw_fd(), libc::F_GETFD) };
  if !named.is_dir()
    || !held.is_dir()
    || descriptor_flags < 0
    || descriptor_flags & libc::FD_CLOEXEC == 0
    || named.dev() != held.dev()
    || named.ino() != held.ino()
  {
    return Err(refused("CANDIDATE-PARENT-ROOT-DESCRIPTOR"));
  }
  Ok(())
}

/// Prepare one dormant, one-shot exact-public-op lstat Candidate capsule.
///
/// @ref LLP 0019#pre-promotion-conformance-candidate-execution
/// [constrained-by] -- The caller selects only a generated artifact/case
/// identity and a fixture root. Target, feature set, execution projection,
/// actors, policy rows, trace, and outcome class come from the compiled
/// generated admission. The retained-root snapshot is `VerifiedUnarmed` and
/// never reaches process-global C04 publication.
#[doc(hidden)]
pub fn oden_capsec_rev2_prepare_lstat_candidate(
  fixture_artifact_digest: &str,
  case_id: &str,
  root: &Path,
  root_file: File,
) -> Result<OdenRev2LstatCandidateCapsule, OdenRev2FilesystemError> {
  #[cfg(any(target_os = "linux", target_os = "macos"))]
  {
    let canonical_root = std::fs::canonicalize(root)
      .map_err(|_| refused("CANDIDATE-PARENT-ROOT-CANONICAL"))?;
    if crate::oden_capsec_rev2_process_mode()
      != crate::OdenRev2ProcessMode::Rev1
      || crate::oden_capsec_rev2_runtime_authority_context().is_some()
      || !root.is_absolute()
      || !exact_candidate_path(&canonical_root, root)
    {
      return Err(refused("CANDIDATE-PARENT-ROOT-CANONICAL"));
    }
    reconcile_supplied_lstat_candidate_root(root, &root_file)?;
    let target = compiled_lstat_target_status()?;
    let admission = select_lstat_candidate_admission(
      fixture_artifact_digest,
      case_id,
      target.target,
      target.feature_set,
    )?;
    let input = lstat_candidate_input(root, admission)?;
    reconcile_supplied_lstat_candidate_root(root, &root_file)?;
    let validated = match case_id {
      LSTAT_EXISTING_CASE_ID => validate_lstat_existing_execution_admission(
        target.target,
        target.feature_set,
        admission,
        input,
      )?,
      LSTAT_FINAL_MISSING_CASE_ID => {
        validate_lstat_final_missing_execution_admission(
          target.target,
          target.feature_set,
          admission,
          input,
        )?
      }
      _ => return Err(refused("CANDIDATE-EXECUTION-ADMISSION")),
    };
    let snapshot = lstat_candidate_snapshot(root, admission, &validated)?;
    let mut loaded = verify_unarmed_candidate_snapshot(&snapshot)
      .map_err(|_| refused("CANDIDATE-CONTEXT"))?;
    loaded
      .replace_candidate_root_descriptor(root, root_file)
      .map_err(|_| refused("CANDIDATE-PARENT-ROOT-DESCRIPTOR"))?;
    let harness = Arc::new(OdenRev2LstatCandidateHarness::new(
      admission,
      validated,
      root.to_path_buf(),
    )?);
    let context = Arc::new(
      OdenRev2RuntimeAuthorityContext::install_lstat_candidate(
        loaded,
        harness.clone(),
      )
      .map_err(|_| refused("CANDIDATE-CONTEXT"))?,
    );
    reconcile_lstat_candidate_root(&context, &harness)?;
    match harness.case {
      OdenRev2LstatCandidateCase::Existing => {
        reconcile_lstat_existing_host_inventory(root, &harness.validated)?;
      }
      OdenRev2LstatCandidateCase::FinalMissing => {
        reconcile_lstat_final_missing_host_inventory(root, &harness.validated)?;
      }
    }
    reconcile_lstat_candidate_root(&context, &harness)?;
    harness.record(FilesystemTracePhase::HarnessAdmitted)?;
    let target_path = harness.target_path.clone();
    Ok(OdenRev2LstatCandidateCapsule {
      binding: Arc::new(OdenRev2LstatCandidateOpStateBinding {
        context,
        harness,
        claimed: AtomicBool::new(false),
      }),
      target_path,
    })
  }
  #[cfg(not(any(target_os = "linux", target_os = "macos")))]
  {
    let _ = (fixture_artifact_digest, case_id, root, root_file);
    Err(refused("PLATFORM-UNSUPPORTED"))
  }
}

/// Execute only the real checked-lstat seam for one exact generated candidate.
/// The caller owns fixture setup, supplies the already-canonical absolute
/// project root, and passes the complete expected-free core input. This
/// function neither creates inputs nor emits evidence.
///
/// @ref LLP 0019#paths [implements] -- The parent root and the exact
/// `input.txt` lexical child remain coupled to the checked native operation.
/// @ref LLP 0019#pre-promotion-conformance-candidate-execution
/// [constrained-by] -- This hidden candidate consumes the digest-bound full
/// execution projection and initial sandbox through the shared core's opaque
/// validation token. Fixture-definition identity, manifest schema/path/HBYTES,
/// runner identity/path/HBYTES, expectation, oracle output, verdict, receipt,
/// report, and authentication keys are absent.
///
/// This preparatory seam does not authenticate that the live C04 context,
/// actor capture, parent umask, root/inventory carrier, actual phase trace, or
/// executable/process identity was produced from the generated plan.
/// `FilesystemCandidateOracleInput` is a legacy type name here: it contains no
/// oracle output, and its inventory plus parent-capture fields are
/// caller-assembled. The path-based pre/post reconciliation is not a retained-
/// descriptor setup proof. The output remains an unauthenticated candidate
/// observation until those later joins exist.
#[allow(dead_code)]
fn oden_capsec_rev2_observe_lstat_existing_candidate(
  context: &OdenRev2RuntimeAuthorityContext,
  parent_root: &Path,
  admission: &'static Rev2FilesystemLstatExecutionAdmission,
  input: FilesystemCandidateOracleInput,
) -> Result<OdenRev2LstatExistingCandidateObservation, OdenRev2FilesystemError>
{
  if !parent_root.is_absolute() {
    return Err(refused("CANDIDATE-PARENT-ROOT-ABSOLUTE"));
  }
  if context.mode() != Mode::Enforce {
    return Err(refused("CANDIDATE-EXECUTION-MODE"));
  }
  let validated = validate_lstat_existing_execution_admission(
    context.target(),
    context.feature_set(),
    admission,
    input,
  )?;
  #[cfg(any(target_os = "linux", target_os = "macos"))]
  {
    let initial_metadata =
      reconcile_lstat_existing_host_inventory(parent_root, &validated)?;

    let delivery =
      oden_capsec_rev2_lstat_sync(context, &parent_root.join("input.txt"))?;
    let metadata = delivery.metadata().cloned();
    delivery.finish();
    let metadata =
      metadata.ok_or_else(|| refused("CANDIDATE-TARGET-MISSING"))?;
    if candidate_platform_identity(&metadata)
      != candidate_platform_identity(&initial_metadata)
      || candidate_metadata_projection(&metadata)
        != candidate_metadata_projection(&initial_metadata)
    {
      return Err(refused("CANDIDATE-TARGET-RACE"));
    }
    let after_metadata =
      reconcile_lstat_existing_host_inventory(parent_root, &validated)?;
    if candidate_platform_identity(&after_metadata)
      != candidate_platform_identity(&metadata)
      || candidate_metadata_projection(&after_metadata)
        != candidate_metadata_projection(&metadata)
    {
      return Err(refused("CANDIDATE-TARGET-RACE"));
    }
    return Ok(OdenRev2LstatExistingCandidateObservation {
      fixture_artifact_digest: admission.fixture_artifact_digest,
      case_id: validated.execution_projection().case_id.clone(),
      target: admission.target,
      metadata,
    });
  }
  #[cfg(not(any(target_os = "linux", target_os = "macos")))]
  {
    let _ = (parent_root, validated);
    Err(refused("PLATFORM-UNSUPPORTED"))
  }
}

/// Execute only the real checked-lstat seam for one exact generated
/// final-entry-missing candidate. The caller owns fixture setup, supplies the
/// already-canonical absolute project root, and passes the complete
/// expected-free core input. This function neither creates inputs nor emits
/// evidence.
///
/// @ref LLP 0019#paths [implements] -- The retained project root and exact
/// missing `input.txt` lexical child stay coupled to the checked operation.
/// @ref LLP 0019#pre-promotion-conformance-candidate-execution
/// [constrained-by] -- This hidden candidate consumes only its separate
/// digest-bound generated admission and shared-core validation token.
/// Definition, runner, expected result, oracle, verdict, receipt, report, and
/// authentication identities remain absent.
///
/// The pre/post scans are unauthenticated point observations and cannot prove
/// continuous absence between syscalls. This module-private, production-
/// uncalled result remains a development candidate rather than conformance
/// evidence or release authority.
#[allow(dead_code)]
fn oden_capsec_rev2_observe_lstat_final_missing_candidate(
  context: &OdenRev2RuntimeAuthorityContext,
  parent_root: &Path,
  admission: &'static Rev2FilesystemLstatExecutionAdmission,
  input: FilesystemCandidateOracleInput,
) -> Result<
  OdenRev2LstatFinalMissingCandidateObservation,
  OdenRev2FilesystemError,
> {
  if !parent_root.is_absolute() {
    return Err(refused("CANDIDATE-PARENT-ROOT-ABSOLUTE"));
  }
  if context.mode() != Mode::Enforce {
    return Err(refused("CANDIDATE-EXECUTION-MODE"));
  }
  let validated = validate_lstat_final_missing_execution_admission(
    context.target(),
    context.feature_set(),
    admission,
    input,
  )?;
  #[cfg(any(target_os = "linux", target_os = "macos"))]
  {
    reconcile_lstat_final_missing_host_inventory(parent_root, &validated)?;
    let delivery =
      oden_capsec_rev2_lstat_sync(context, &parent_root.join("input.txt"))?;
    if !delivery.is_not_found() {
      return Err(refused("CANDIDATE-TARGET-PRESENT"));
    }
    // Keep the delivery lease and namespace gate pinned through the repeated
    // root/inventory/ENOENT observation.
    reconcile_lstat_final_missing_host_inventory(parent_root, &validated)?;
    delivery.finish();
    return Ok(OdenRev2LstatFinalMissingCandidateObservation {
      fixture_artifact_digest: admission.fixture_artifact_digest,
      case_id: validated.execution_projection().case_id.clone(),
      target: admission.target,
    });
  }
  #[cfg(not(any(target_os = "linux", target_os = "macos")))]
  {
    let _ = (parent_root, validated);
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
  use crate::rev2::FilesystemTracePhase;
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

  pub(super) fn capture_actors(
    context: &OdenRev2RuntimeAuthorityContext,
    edge_id: &str,
  ) -> Result<VerifiedPermissionActorSet, OdenRev2FilesystemError> {
    if let Some(actors) = context.candidate_lstat_actors(edge_id)? {
      context
        .record_candidate_lstat_phase(FilesystemTracePhase::ActorsCaptured)?;
      return Ok(actors);
    }
    let (principals, owner) = crate::oden_rev2_capture_live_permission_actors();
    let actors = VerifiedPermissionActorSet::capture_host(&principals, owner)
      .map_err(|_| refused("ACTOR-CAPTURE"))?;
    context
      .record_candidate_lstat_phase(FilesystemTracePhase::ActorsCaptured)?;
    Ok(actors)
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
    let actors = capture_actors(context, LSTAT_EDGE)?;
    let actor_capture_digest = captured_actor_digest(&actors)?;
    let guard = context
      .begin_namespace_operation()
      .map_err(|_| refused("NAMESPACE-GATE"))?;
    context.record_candidate_lstat_phase(
      FilesystemTracePhase::NamespaceGateAcquired,
    )?;
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
    context
      .record_candidate_lstat_phase(FilesystemTracePhase::DiscoveryComplete)?;
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
    context.record_candidate_lstat_phase(
      FilesystemTracePhase::AuthorizationComplete,
    )?;
    operation
      .actor
      .revalidate_sources(&session)
      .map_err(|_| refused("SOURCE-RACE"))?;
    context
      .record_candidate_lstat_phase(FilesystemTracePhase::SourcesRevalidated)?;
    operation
      .actor
      .revalidate_target(&session)
      .map_err(|_| refused("TARGET-RACE"))?;
    context
      .record_candidate_lstat_phase(FilesystemTracePhase::TargetRevalidated)?;
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
    context
      .record_candidate_lstat_phase(FilesystemTracePhase::CoreCommitRecorded)?;
    let filesystem_completion = complete_actor(operation)?;
    context
      .record_candidate_lstat_phase(FilesystemTracePhase::OperationCompleted)?;
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
    let actors = capture_actors(context, MKDIR_EDGE)?;
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
  use crate::rev2::FilesystemInitialSandboxInventory;
  use crate::rev2::FilesystemInitialSandboxObject;
  use crate::rev2::FilesystemParentCaptureFacts;
  use crate::rev2::FilesystemRealizedLogicalRoot;
  use crate::rev2::FilesystemRealizedObjectState;
  use crate::rev2::FilesystemSandboxPhase;
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

  fn retained_candidate_root(path: &Path) -> std::fs::File {
    use std::os::unix::fs::OpenOptionsExt;

    std::fs::OpenOptions::new()
      .read(true)
      .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
      .open(path)
      .unwrap()
  }

  #[cfg(any(
    all(target_arch = "aarch64", target_vendor = "apple", target_os = "macos"),
    all(
      target_arch = "x86_64",
      target_vendor = "unknown",
      target_os = "linux",
      target_env = "gnu"
    )
  ))]
  #[test]
  fn lstat_candidate_public_op_uses_exact_generated_target_and_case() {
    let admission = native_lstat_existing_execution_admission();
    let root = TempRoot::new("public-op-generated");
    let project = root.0.join("data");
    std::fs::write(project.join("input.txt"), b"").unwrap();
    let capsule = super::oden_capsec_rev2_prepare_lstat_candidate(
      admission.fixture_artifact_digest,
      admission.case_id,
      &project,
      retained_candidate_root(&project),
    )
    .unwrap();

    assert_eq!(capsule.binding.context.target(), admission.target);
    assert_eq!(capsule.binding.context.feature_set(), admission.feature_set);
    assert_eq!(
      capsule.binding.context.execution_role(),
      super::super::OdenRev2ExecutionRole::Candidate
    );
    assert_eq!(capsule.binding.context.mode(), Mode::Enforce);
    assert_eq!(capsule.binding.harness.admission.case_id, admission.case_id);
    assert_eq!(
      crate::oden_capsec_rev2_process_mode(),
      crate::OdenRev2ProcessMode::Rev1
    );
    assert!(crate::oden_capsec_rev2_runtime_authority_context().is_none());
  }

  #[cfg(any(
    all(target_arch = "aarch64", target_vendor = "apple", target_os = "macos"),
    all(
      target_arch = "x86_64",
      target_vendor = "unknown",
      target_os = "linux",
      target_env = "gnu"
    )
  ))]
  #[test]
  fn lstat_candidate_public_op_cannot_substitute_live_actors() {
    let admission = native_lstat_existing_execution_admission();
    let root = TempRoot::new("public-op-actors");
    let project = root.0.join("data");
    std::fs::write(project.join("input.txt"), b"").unwrap();
    let capsule = super::oden_capsec_rev2_prepare_lstat_candidate(
      admission.fixture_artifact_digest,
      admission.case_id,
      &project,
      retained_candidate_root(&project),
    )
    .unwrap();
    let wrong = PrincipalRef {
      kind: PrincipalKind::Package,
      key: format!("pkg:sha256-B{}", "A".repeat(42)),
    };
    let _actors = ActorCapture::install(wrong);
    let context = capsule
      .binding
      .claim_for_test(&capsule.target_path)
      .unwrap();

    let captured =
      super::supported::capture_actors(&context, LSTAT_EDGE).unwrap();

    assert_eq!(captured.constrained_principals(), &[principal()]);
    assert_eq!(captured.overlay_owner(), &principal());
    assert_eq!(
      crate::oden_rev2_permission_actor_capture_count_for_test(),
      0
    );
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

  fn lstat_existing_candidate_context(
    root: &Path,
    projection: &FilesystemExecutionProjection,
  ) -> OdenRev2RuntimeAuthorityContext {
    lstat_existing_candidate_context_with_mode(root, projection, "enforce")
  }

  fn lstat_existing_candidate_context_with_mode(
    root: &Path,
    projection: &FilesystemExecutionProjection,
    mode: &str,
  ) -> OdenRev2RuntimeAuthorityContext {
    let authority = &projection.authority_rows[0];
    let target = projection
      .setup
      .objects
      .iter()
      .find(|object| object.object_id == "source")
      .unwrap();
    let root_binding = &projection.setup.logical_roots[0];
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
        "sourceId": authority.source_id,
        "selector": selector(
          &authority.capability,
          "path-exact",
          &target.path.value,
          SelectorPolarity::Positive,
        ),
      }],
      "escalationCeiling": [],
      "denials": [],
    }]);
    snapshot["rootBindings"] = json!([{
      "sourceId": authority.source_id,
      "logicalRoot": "$PROJECT",
      "principal": principal(),
      "rootBindingId": root_binding.binding_id,
      "canonicalPath": {
        "encoding": "unicode",
        "value": root.to_str().unwrap(),
      },
      "objectIdentity": policy_fixtures::platform_identity(root),
      "bindingProvenanceDigest": REV2_REGISTRY_DIGEST,
    }]);
    snapshot["effectiveMode"] = json!(mode);
    snapshot["canonicalPolicy"]["mode"] = json!(mode);
    policy_fixtures::refresh_digests(&mut snapshot);
    let mut loaded =
      policy_fixtures::verify_armable_snapshot(snapshot, &[93_u8; 32]).unwrap();
    loaded
      .install_immutable_executables(Path::new("."))
      .unwrap();
    OdenRev2RuntimeAuthorityContext::install_for_test(loaded).unwrap()
  }

  fn lstat_final_missing_candidate_context(
    root: &Path,
    projection: &FilesystemExecutionProjection,
  ) -> OdenRev2RuntimeAuthorityContext {
    lstat_existing_candidate_context_with_mode(root, projection, "enforce")
  }

  fn lstat_final_missing_candidate_context_with_mode(
    root: &Path,
    projection: &FilesystemExecutionProjection,
    mode: &str,
  ) -> OdenRev2RuntimeAuthorityContext {
    lstat_existing_candidate_context_with_mode(root, projection, mode)
  }

  #[cfg(any(
    all(target_arch = "aarch64", target_vendor = "apple", target_os = "macos"),
    all(
      target_arch = "x86_64",
      target_vendor = "unknown",
      target_os = "linux",
      target_env = "gnu"
    )
  ))]
  fn native_lstat_existing_execution_admission()
  -> &'static Rev2FilesystemLstatExecutionAdmission {
    let compiled = policy_fixtures::embedded_compiled_target();
    REV2_FILESYSTEM_LSTAT_EXISTING_EXECUTION_ADMISSIONS
      .iter()
      .find(|admission| {
        admission.case_id == LSTAT_EXISTING_CASE_ID
          && admission.target == compiled.target
          && admission.feature_set == compiled.feature_set
      })
      .unwrap()
  }

  #[cfg(any(
    all(target_arch = "aarch64", target_vendor = "apple", target_os = "macos"),
    all(
      target_arch = "x86_64",
      target_vendor = "unknown",
      target_os = "linux",
      target_env = "gnu"
    )
  ))]
  fn native_lstat_final_missing_execution_admission()
  -> &'static Rev2FilesystemLstatExecutionAdmission {
    let compiled = policy_fixtures::embedded_compiled_target();
    REV2_FILESYSTEM_LSTAT_FINAL_MISSING_EXECUTION_ADMISSIONS
      .iter()
      .find(|admission| {
        admission.case_id == LSTAT_FINAL_MISSING_CASE_ID
          && admission.target == compiled.target
          && admission.feature_set == compiled.feature_set
      })
      .unwrap()
  }

  #[cfg(any(
    all(target_arch = "aarch64", target_vendor = "apple", target_os = "macos"),
    all(
      target_arch = "x86_64",
      target_vendor = "unknown",
      target_os = "linux",
      target_env = "gnu"
    )
  ))]
  fn exact_release_build_identity() -> OdenRev2CompiledBuildIdentity {
    let target = policy_fixtures::embedded_compiled_target();
    OdenRev2CompiledBuildIdentity {
      target: target.target,
      rust_toolchain: target.rust_toolchain,
      cargo_features: target.cargo_features,
      rust_cfg_digest: target.rust_cfg_digest,
      cargo_feature_graph_digest: target.cargo_feature_graph_digest,
      build_profile: target.build_profile,
      marker_panic_strategy: "abort",
      marker_debug_assertions: "false",
      actual_panic_strategy: "abort",
      actual_debug_assertions: false,
    }
  }

  #[cfg(any(
    all(target_arch = "aarch64", target_vendor = "apple", target_os = "macos"),
    all(
      target_arch = "x86_64",
      target_vendor = "unknown",
      target_os = "linux",
      target_env = "gnu"
    )
  ))]
  fn join_test_candidate_binary_identity(
    build_identity: &OdenRev2CompiledBuildIdentity,
    fixture_artifact_digest: &str,
    case_id: &str,
  ) -> Result<OdenRev2LstatCandidateBinaryIdentity, OdenRev2FilesystemError> {
    join_lstat_candidate_binary_identity_with_validator(
      build_identity,
      fixture_artifact_digest,
      case_id,
      crate::oden_rev2_policy::validate_compiled_build_identity,
    )
  }

  #[cfg(any(
    all(target_arch = "aarch64", target_vendor = "apple", target_os = "macos"),
    all(
      target_arch = "x86_64",
      target_vendor = "unknown",
      target_os = "linux",
      target_env = "gnu"
    )
  ))]
  #[test]
  fn candidate_binary_identity_join_selects_exact_generated_rows() {
    let build_identity = exact_release_build_identity();
    for admission in [
      native_lstat_existing_execution_admission(),
      native_lstat_final_missing_execution_admission(),
    ] {
      let identity = join_test_candidate_binary_identity(
        &build_identity,
        admission.fixture_artifact_digest,
        admission.case_id,
      )
      .unwrap();
      let target = policy_fixtures::embedded_compiled_target();
      assert_eq!(
        identity.fixture_artifact_digest(),
        admission.fixture_artifact_digest
      );
      assert_eq!(identity.case_id(), admission.case_id);
      assert_eq!(identity.target(), target.target);
      assert_eq!(identity.feature_set(), target.feature_set);
      assert_eq!(identity.rust_toolchain(), target.rust_toolchain);
      assert_eq!(identity.cargo_features(), target.cargo_features);
      assert_eq!(identity.rust_cfg_digest(), target.rust_cfg_digest);
      assert_eq!(
        identity.cargo_feature_graph_digest(),
        target.cargo_feature_graph_digest
      );
      assert_eq!(identity.build_profile(), "release");
      assert_eq!(
        identity.execution_projection_digest(),
        admission.case_projection_digest
      );
      assert_eq!(identity.execution_projection().case_id, admission.case_id);
      assert_eq!(identity.execution_projection().edge_id, LSTAT_EDGE);
    }
  }

  #[cfg(any(
    all(target_arch = "aarch64", target_vendor = "apple", target_os = "macos"),
    all(
      target_arch = "x86_64",
      target_vendor = "unknown",
      target_os = "linux",
      target_env = "gnu"
    )
  ))]
  #[test]
  fn candidate_binary_identity_join_refuses_stale_alias_and_missing_facts() {
    let exact = exact_release_build_identity();
    let admission = native_lstat_existing_execution_admission();
    for build_identity in [
      OdenRev2CompiledBuildIdentity {
        target: "arm64-apple-darwin",
        ..exact
      },
      OdenRev2CompiledBuildIdentity {
        cargo_features: "__vendored_zlib_ng,default",
        ..exact
      },
      OdenRev2CompiledBuildIdentity {
        rust_cfg_digest: "",
        ..exact
      },
      OdenRev2CompiledBuildIdentity {
        cargo_feature_graph_digest: "sha256:stale",
        ..exact
      },
    ] {
      assert_eq!(
        refusal(
          join_test_candidate_binary_identity(
            &build_identity,
            admission.fixture_artifact_digest,
            admission.case_id,
          )
          .err()
          .expect("stale build identity must refuse")
        ),
        "OD-CAP-REV2-FILESYSTEM-CANDIDATE-BINARY-IDENTITY"
      );
    }

    for (fixture_artifact_digest, case_id) in [
      ("", admission.case_id),
      (
        "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        admission.case_id,
      ),
      (admission.fixture_artifact_digest, ""),
      (
        admission.fixture_artifact_digest,
        "filesystem:lstat-sync:existing",
      ),
    ] {
      assert_eq!(
        refusal(
          join_test_candidate_binary_identity(
            &exact,
            fixture_artifact_digest,
            case_id,
          )
          .err()
          .expect("alias or missing admission identity must refuse")
        ),
        "OD-CAP-REV2-FILESYSTEM-CANDIDATE-EXECUTION-ADMISSION"
      );
    }
  }

  #[cfg(any(
    all(target_arch = "aarch64", target_vendor = "apple", target_os = "macos"),
    all(
      target_arch = "x86_64",
      target_vendor = "unknown",
      target_os = "linux",
      target_env = "gnu"
    )
  ))]
  fn lstat_candidate_input(
    root: &Path,
    admission: &Rev2FilesystemLstatExecutionAdmission,
  ) -> FilesystemCandidateOracleInput {
    let projection: FilesystemExecutionProjection =
      serde_json::from_str(admission.case_projection_json).unwrap();
    let root_setup = projection
      .setup
      .logical_roots
      .iter()
      .find(|candidate| candidate.root == FilesystemLogicalRoot::Project)
      .unwrap();
    let root_metadata = std::fs::symlink_metadata(root).unwrap();
    let objects = projection
      .setup
      .objects
      .iter()
      .map(|object| {
        let state = match object.kind {
          FilesystemObjectKind::RegularFile => {
            let metadata =
              std::fs::symlink_metadata(root.join(&object.path.value)).unwrap();
            FilesystemRealizedObjectState {
              kind: FilesystemObjectKind::RegularFile,
              identity: Some(candidate_platform_identity(&metadata)),
              metadata: Some(candidate_metadata_projection(&metadata)),
              content_digest: object.content_digest.clone(),
              alias_target_object_id: object.alias_target_object_id.clone(),
              link_target_object_id: object.link_target_object_id.clone(),
            }
          }
          FilesystemObjectKind::Missing => {
            assert!(
              std::fs::symlink_metadata(root.join(&object.path.value))
                .is_err_and(|error| error.kind() == io::ErrorKind::NotFound)
            );
            FilesystemRealizedObjectState {
              kind: FilesystemObjectKind::Missing,
              identity: None,
              metadata: None,
              content_digest: None,
              alias_target_object_id: None,
              link_target_object_id: None,
            }
          }
          other => panic!("unexpected lstat candidate setup kind {other:?}"),
        };
        FilesystemInitialSandboxObject {
          object_id: object.object_id.clone(),
          root: object.root,
          path: object.path.clone(),
          fixture_identity: object.object_identity.clone(),
          state,
        }
      })
      .collect();
    let initial_sandbox = FilesystemInitialSandboxInventory {
      schema: "oden/capsec-filesystem-sandbox-inventory/2".to_string(),
      phase: FilesystemSandboxPhase::Initial,
      logical_roots: vec![FilesystemRealizedLogicalRoot {
        root: FilesystemLogicalRoot::Project,
        binding_id: root_setup.binding_id.clone(),
        fixture_identity: root_setup.object_identity.clone(),
        platform_identity: candidate_platform_identity(&root_metadata),
      }],
      objects,
      unexpected_entries: Vec::new(),
    };
    let inventory_value = serde_json::to_value(&initial_sandbox).unwrap();
    let initial_inventory_digest = hjcs_digest(
      "oden:capsec:filesystem-sandbox-inventory:2",
      &inventory_value,
    )
    .unwrap();
    FilesystemCandidateOracleInput {
      case_projection: projection,
      case_projection_digest: admission.case_projection_digest.to_string(),
      initial_sandbox,
      initial_inventory_digest,
      parent_capture_facts: FilesystemParentCaptureFacts {
        captured_umask: 0o077,
      },
    }
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

  #[cfg(any(
    all(target_arch = "aarch64", target_vendor = "apple", target_os = "macos"),
    all(
      target_arch = "x86_64",
      target_vendor = "unknown",
      target_os = "linux",
      target_env = "gnu"
    )
  ))]
  #[test]
  fn lstat_existing_candidate_context_requires_exact_target_and_feature_set() {
    let admission = native_lstat_existing_execution_admission();
    super::validate_lstat_existing_candidate_context(
      admission.target,
      admission.feature_set,
      admission,
    )
    .unwrap();
    for near_miss in [
      "arm64e-apple-darwin",
      "x86_64-unknown-linux-gnuasan",
      "x86_64-unknown-linux-gnux32",
    ] {
      assert_eq!(
        refusal(
          super::validate_lstat_existing_candidate_context(
            near_miss,
            admission.feature_set,
            admission,
          )
          .unwrap_err()
        ),
        "OD-CAP-REV2-FILESYSTEM-CANDIDATE-TARGET"
      );
    }
    assert_eq!(
      refusal(
        super::validate_lstat_existing_candidate_context(
          admission.target,
          "rust:wrong-feature-set",
          admission,
        )
        .unwrap_err()
      ),
      "OD-CAP-REV2-FILESYSTEM-CANDIDATE-FEATURE-SET"
    );
  }

  #[cfg(any(
    all(target_arch = "aarch64", target_vendor = "apple", target_os = "macos"),
    all(
      target_arch = "x86_64",
      target_vendor = "unknown",
      target_os = "linux",
      target_env = "gnu"
    )
  ))]
  #[test]
  fn lstat_existing_candidate_observes_real_zero_file_without_mutation() {
    let admission = native_lstat_existing_execution_admission();
    let root = TempRoot::new("lstat-existing-candidate");
    let project = root.0.join("data");
    let target = project.join("input.txt");
    std::fs::write(&target, b"").unwrap();
    let before = std::fs::read(&target).unwrap();
    let input = lstat_candidate_input(&project, admission);
    let context =
      lstat_existing_candidate_context(&project, &input.case_projection);
    let _actors = ActorCapture::install(principal());

    let observation = super::oden_capsec_rev2_observe_lstat_existing_candidate(
      &context, &project, admission, input,
    )
    .unwrap();

    assert_eq!(
      observation.fixture_artifact_digest(),
      admission.fixture_artifact_digest
    );
    assert_eq!(observation.case_id(), LSTAT_EXISTING_CASE_ID);
    assert_eq!(observation.target(), admission.target);
    assert!(observation.metadata().is_file());
    assert_eq!(observation.metadata().len(), 0);
    assert_eq!(
      crate::oden_rev2_permission_actor_capture_count_for_test(),
      1
    );
    assert!(project.is_dir());
    assert_eq!(std::fs::read(&target).unwrap(), before);
  }

  #[cfg(any(
    all(target_arch = "aarch64", target_vendor = "apple", target_os = "macos"),
    all(
      target_arch = "x86_64",
      target_vendor = "unknown",
      target_os = "linux",
      target_env = "gnu"
    )
  ))]
  #[test]
  fn lstat_existing_candidate_refuses_wrong_parent_without_entering_checked_op()
  {
    let admission = native_lstat_existing_execution_admission();
    let root = TempRoot::new("lstat-existing-candidate-root");
    let wrong = TempRoot::new("lstat-existing-candidate-wrong");
    let project = root.0.join("data");
    let wrong_project = wrong.0.join("data");
    let root_target = project.join("input.txt");
    let wrong_target = wrong_project.join("input.txt");
    std::fs::write(&root_target, b"").unwrap();
    std::fs::write(&wrong_target, b"wrong-root").unwrap();
    let root_before = std::fs::read(&root_target).unwrap();
    let wrong_before = std::fs::read(&wrong_target).unwrap();
    let input = lstat_candidate_input(&project, admission);
    let context =
      lstat_existing_candidate_context(&project, &input.case_projection);
    let _actors = ActorCapture::install(principal());
    crate::oden_rev2_reset_permission_actor_capture_count_for_test();

    let error = super::oden_capsec_rev2_observe_lstat_existing_candidate(
      &context,
      &wrong_project,
      admission,
      input,
    );
    assert_eq!(
      refusal(error.err().expect("wrong root must refuse")),
      "OD-CAP-REV2-FILESYSTEM-CANDIDATE-PARENT-ROOT-IDENTITY"
    );
    assert_eq!(
      crate::oden_rev2_permission_actor_capture_count_for_test(),
      0
    );

    assert!(root.0.is_dir());
    assert!(wrong.0.is_dir());
    assert_eq!(std::fs::read(&root_target).unwrap(), root_before);
    assert_eq!(std::fs::read(&wrong_target).unwrap(), wrong_before);
  }

  #[cfg(any(
    all(target_arch = "aarch64", target_vendor = "apple", target_os = "macos"),
    all(
      target_arch = "x86_64",
      target_vendor = "unknown",
      target_os = "linux",
      target_env = "gnu"
    )
  ))]
  #[test]
  fn lstat_existing_candidate_refuses_projection_and_core_tampering_before_io()
  {
    let admission = native_lstat_existing_execution_admission();
    let root = TempRoot::new("lstat-existing-candidate-preflight");
    let project = root.0.join("data");
    std::fs::write(project.join("input.txt"), b"").unwrap();
    let base = lstat_candidate_input(&project, admission);
    let context =
      lstat_existing_candidate_context(&project, &base.case_projection);
    let audit_context = lstat_existing_candidate_context_with_mode(
      &project,
      &base.case_projection,
      "audit",
    );
    let nonexistent = root.0.join("nonexistent-project");
    let _actors = ActorCapture::install(principal());
    crate::oden_rev2_reset_permission_actor_capture_count_for_test();

    assert_eq!(
      refusal(
        super::oden_capsec_rev2_observe_lstat_existing_candidate(
          &audit_context,
          &nonexistent,
          admission,
          base.clone(),
        )
        .err()
        .expect("audit mode must refuse")
      ),
      "OD-CAP-REV2-FILESYSTEM-CANDIDATE-EXECUTION-MODE"
    );
    assert_eq!(
      crate::oden_rev2_permission_actor_capture_count_for_test(),
      0
    );

    let mut projection_tamper = base.clone();
    projection_tamper.case_projection.case_id =
      "filesystem:lstat-sync:lstat-existing-tampered".to_string();
    assert_eq!(
      refusal(
        super::oden_capsec_rev2_observe_lstat_existing_candidate(
          &context,
          &nonexistent,
          admission,
          projection_tamper,
        )
        .err()
        .expect("projection tamper must refuse")
      ),
      "OD-CAP-REV2-FILESYSTEM-CANDIDATE-GENERATED-PROJECTION"
    );
    assert_eq!(
      crate::oden_rev2_permission_actor_capture_count_for_test(),
      0
    );

    let mut inventory_tamper = base;
    inventory_tamper
      .initial_sandbox
      .unexpected_entries
      .push("extra".to_string());
    inventory_tamper.initial_inventory_digest = hjcs_digest(
      "oden:capsec:filesystem-sandbox-inventory:2",
      &serde_json::to_value(&inventory_tamper.initial_sandbox).unwrap(),
    )
    .unwrap();
    assert_eq!(
      refusal(
        super::oden_capsec_rev2_observe_lstat_existing_candidate(
          &context,
          &nonexistent,
          admission,
          inventory_tamper,
        )
        .err()
        .expect("inventory tamper must refuse")
      ),
      "OD-CAP-REV2-FILESYSTEM-CANDIDATE-EXECUTION-INPUT"
    );
    assert_eq!(
      crate::oden_rev2_permission_actor_capture_count_for_test(),
      0
    );
  }

  #[cfg(any(
    all(target_arch = "aarch64", target_vendor = "apple", target_os = "macos"),
    all(
      target_arch = "x86_64",
      target_vendor = "unknown",
      target_os = "linux",
      target_env = "gnu"
    )
  ))]
  #[test]
  fn lstat_existing_candidate_requires_registered_admission_identity() {
    let admission = native_lstat_existing_execution_admission();
    let forged: &'static Rev2FilesystemLstatExecutionAdmission =
      Box::leak(Box::new(*admission));
    let root = TempRoot::new("lstat-existing-candidate-forged-admission");
    let project = root.0.join("data");
    std::fs::write(project.join("input.txt"), b"").unwrap();
    let input = lstat_candidate_input(&project, admission);
    let context =
      lstat_existing_candidate_context(&project, &input.case_projection);
    assert_eq!(
      refusal(
        super::oden_capsec_rev2_observe_lstat_existing_candidate(
          &context, &project, forged, input,
        )
        .err()
        .expect("forged admission must refuse")
      ),
      "OD-CAP-REV2-FILESYSTEM-CANDIDATE-EXECUTION-ADMISSION"
    );
  }

  #[cfg(any(
    all(target_arch = "aarch64", target_vendor = "apple", target_os = "macos"),
    all(
      target_arch = "x86_64",
      target_vendor = "unknown",
      target_os = "linux",
      target_env = "gnu"
    )
  ))]
  #[test]
  fn lstat_existing_candidate_refuses_links_specials_bytes_and_inventory_aliases()
   {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::PermissionsExt;
    use std::os::unix::fs::symlink;

    let admission = native_lstat_existing_execution_admission();
    let _actors = ActorCapture::install(principal());
    for (mutation, expected_reason) in [
      (
        "symlink",
        "OD-CAP-REV2-FILESYSTEM-CANDIDATE-TARGET-IDENTITY",
      ),
      (
        "hardlink",
        "OD-CAP-REV2-FILESYSTEM-CANDIDATE-TARGET-IDENTITY",
      ),
      (
        "nonempty",
        "OD-CAP-REV2-FILESYSTEM-CANDIDATE-TARGET-IDENTITY",
      ),
      (
        "replacement",
        "OD-CAP-REV2-FILESYSTEM-CANDIDATE-TARGET-IDENTITY",
      ),
      (
        "metadata",
        "OD-CAP-REV2-FILESYSTEM-CANDIDATE-TARGET-IDENTITY",
      ),
      ("fifo", "OD-CAP-REV2-FILESYSTEM-CANDIDATE-TARGET-IDENTITY"),
      (
        "extra-entry",
        "OD-CAP-REV2-FILESYSTEM-CANDIDATE-INITIAL-INVENTORY",
      ),
      (
        "case-alias",
        "OD-CAP-REV2-FILESYSTEM-CANDIDATE-INITIAL-INVENTORY",
      ),
    ] {
      let root =
        TempRoot::new(&format!("lstat-existing-candidate-host-{mutation}"));
      let project = root.0.join("data");
      let target = project.join("input.txt");
      std::fs::write(&target, b"").unwrap();
      std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o600))
        .unwrap();
      let input = lstat_candidate_input(&project, admission);
      let context =
        lstat_existing_candidate_context(&project, &input.case_projection);
      match mutation {
        "symlink" => {
          std::fs::remove_file(&target).unwrap();
          std::fs::write(root.0.join("outside.txt"), b"").unwrap();
          symlink("../outside.txt", &target).unwrap();
        }
        "hardlink" => {
          std::fs::hard_link(&target, root.0.join("outside-link")).unwrap();
        }
        "nonempty" => std::fs::write(&target, b"x").unwrap(),
        "replacement" => {
          let replacement = root.0.join("replacement.txt");
          std::fs::write(&replacement, b"").unwrap();
          std::fs::remove_file(&target).unwrap();
          std::fs::rename(replacement, &target).unwrap();
        }
        "metadata" => {
          std::fs::set_permissions(
            &target,
            std::fs::Permissions::from_mode(0o640),
          )
          .unwrap();
        }
        "fifo" => {
          std::fs::remove_file(&target).unwrap();
          let target_c =
            std::ffi::CString::new(target.as_os_str().as_bytes()).unwrap();
          // SAFETY: target_c is NUL-terminated and mkfifo does not retain it.
          assert_eq!(unsafe { libc::mkfifo(target_c.as_ptr(), 0o600) }, 0);
        }
        "extra-entry" => {
          std::fs::write(project.join("unexpected.txt"), b"").unwrap()
        }
        "case-alias" => {
          std::fs::rename(&target, project.join("INPUT.txt")).unwrap()
        }
        _ => unreachable!(),
      }
      crate::oden_rev2_reset_permission_actor_capture_count_for_test();
      assert_eq!(
        refusal(
          super::oden_capsec_rev2_observe_lstat_existing_candidate(
            &context, &project, admission, input,
          )
          .err()
          .expect("host mutation must refuse")
        ),
        expected_reason,
        "{mutation}"
      );
      assert_eq!(
        crate::oden_rev2_permission_actor_capture_count_for_test(),
        0,
        "{mutation} must refuse before checked-op actor capture"
      );
    }
  }

  #[cfg(any(
    all(target_arch = "aarch64", target_vendor = "apple", target_os = "macos"),
    all(
      target_arch = "x86_64",
      target_vendor = "unknown",
      target_os = "linux",
      target_env = "gnu"
    )
  ))]
  #[test]
  fn lstat_final_missing_candidate_context_requires_exact_target_and_feature_set()
   {
    let admission = native_lstat_final_missing_execution_admission();
    super::validate_lstat_final_missing_candidate_context(
      admission.target,
      admission.feature_set,
      admission,
    )
    .unwrap();
    for near_miss in [
      "arm64e-apple-darwin",
      "x86_64-unknown-linux-gnuasan",
      "x86_64-unknown-linux-gnux32",
    ] {
      assert_eq!(
        refusal(
          super::validate_lstat_final_missing_candidate_context(
            near_miss,
            admission.feature_set,
            admission,
          )
          .unwrap_err()
        ),
        "OD-CAP-REV2-FILESYSTEM-CANDIDATE-TARGET"
      );
    }
    assert_eq!(
      refusal(
        super::validate_lstat_final_missing_candidate_context(
          admission.target,
          "rust:wrong-feature-set",
          admission,
        )
        .unwrap_err()
      ),
      "OD-CAP-REV2-FILESYSTEM-CANDIDATE-FEATURE-SET"
    );
  }

  #[cfg(any(
    all(target_arch = "aarch64", target_vendor = "apple", target_os = "macos"),
    all(
      target_arch = "x86_64",
      target_vendor = "unknown",
      target_os = "linux",
      target_env = "gnu"
    )
  ))]
  #[test]
  fn lstat_final_missing_candidate_observes_real_absence_without_mutation() {
    let admission = native_lstat_final_missing_execution_admission();
    let root = TempRoot::new("lstat-final-missing-candidate");
    let project = root.0.join("data");
    let input = lstat_candidate_input(&project, admission);
    let context =
      lstat_final_missing_candidate_context(&project, &input.case_projection);
    let _actors = ActorCapture::install(principal());
    crate::oden_rev2_reset_permission_actor_capture_count_for_test();

    let observation =
      super::oden_capsec_rev2_observe_lstat_final_missing_candidate(
        &context, &project, admission, input,
      )
      .unwrap();

    assert_eq!(
      observation.fixture_artifact_digest(),
      admission.fixture_artifact_digest
    );
    assert_eq!(observation.case_id(), LSTAT_FINAL_MISSING_CASE_ID);
    assert_eq!(observation.target(), admission.target);
    assert!(observation.is_not_found());
    assert_eq!(
      crate::oden_rev2_permission_actor_capture_count_for_test(),
      1
    );
    assert!(project.is_dir());
    assert_eq!(std::fs::read_dir(&project).unwrap().count(), 0);
  }

  #[cfg(any(
    all(target_arch = "aarch64", target_vendor = "apple", target_os = "macos"),
    all(
      target_arch = "x86_64",
      target_vendor = "unknown",
      target_os = "linux",
      target_env = "gnu"
    )
  ))]
  #[test]
  fn lstat_final_missing_candidate_refuses_wrong_parent_without_entering_checked_op()
   {
    let admission = native_lstat_final_missing_execution_admission();
    let root = TempRoot::new("lstat-final-missing-candidate-root");
    let wrong = TempRoot::new("lstat-final-missing-candidate-wrong");
    let project = root.0.join("data");
    let wrong_project = wrong.0.join("data");
    let input = lstat_candidate_input(&project, admission);
    let context =
      lstat_final_missing_candidate_context(&project, &input.case_projection);
    let _actors = ActorCapture::install(principal());
    crate::oden_rev2_reset_permission_actor_capture_count_for_test();

    assert_eq!(
      refusal(
        super::oden_capsec_rev2_observe_lstat_final_missing_candidate(
          &context,
          &wrong_project,
          admission,
          input,
        )
        .err()
        .expect("wrong root must refuse")
      ),
      "OD-CAP-REV2-FILESYSTEM-CANDIDATE-PARENT-ROOT-IDENTITY"
    );
    assert_eq!(
      crate::oden_rev2_permission_actor_capture_count_for_test(),
      0
    );
    assert_eq!(std::fs::read_dir(&project).unwrap().count(), 0);
    assert_eq!(std::fs::read_dir(&wrong_project).unwrap().count(), 0);
  }

  #[cfg(any(
    all(target_arch = "aarch64", target_vendor = "apple", target_os = "macos"),
    all(
      target_arch = "x86_64",
      target_vendor = "unknown",
      target_os = "linux",
      target_env = "gnu"
    )
  ))]
  #[test]
  fn lstat_final_missing_candidate_refuses_projection_and_core_tampering_before_io()
   {
    let admission = native_lstat_final_missing_execution_admission();
    let root = TempRoot::new("lstat-final-missing-candidate-preflight");
    let project = root.0.join("data");
    let base = lstat_candidate_input(&project, admission);
    let context =
      lstat_final_missing_candidate_context(&project, &base.case_projection);
    let audit_context = lstat_final_missing_candidate_context_with_mode(
      &project,
      &base.case_projection,
      "audit",
    );
    let nonexistent = root.0.join("nonexistent-project");
    let _actors = ActorCapture::install(principal());
    crate::oden_rev2_reset_permission_actor_capture_count_for_test();

    assert_eq!(
      refusal(
        super::oden_capsec_rev2_observe_lstat_final_missing_candidate(
          &audit_context,
          &nonexistent,
          admission,
          base.clone(),
        )
        .err()
        .expect("audit mode must refuse")
      ),
      "OD-CAP-REV2-FILESYSTEM-CANDIDATE-EXECUTION-MODE"
    );
    assert_eq!(
      crate::oden_rev2_permission_actor_capture_count_for_test(),
      0
    );

    let mut projection_tamper = base.clone();
    projection_tamper.case_projection.case_id =
      "filesystem:lstat-sync:lstat-final-missing-tampered".to_string();
    assert_eq!(
      refusal(
        super::oden_capsec_rev2_observe_lstat_final_missing_candidate(
          &context,
          &nonexistent,
          admission,
          projection_tamper,
        )
        .err()
        .expect("projection tamper must refuse")
      ),
      "OD-CAP-REV2-FILESYSTEM-CANDIDATE-GENERATED-PROJECTION"
    );
    assert_eq!(
      crate::oden_rev2_permission_actor_capture_count_for_test(),
      0
    );

    let mut inventory_tamper = base;
    inventory_tamper
      .initial_sandbox
      .unexpected_entries
      .push("extra".to_string());
    inventory_tamper.initial_inventory_digest = hjcs_digest(
      "oden:capsec:filesystem-sandbox-inventory:2",
      &serde_json::to_value(&inventory_tamper.initial_sandbox).unwrap(),
    )
    .unwrap();
    assert_eq!(
      refusal(
        super::oden_capsec_rev2_observe_lstat_final_missing_candidate(
          &context,
          &nonexistent,
          admission,
          inventory_tamper,
        )
        .err()
        .expect("inventory tamper must refuse")
      ),
      "OD-CAP-REV2-FILESYSTEM-CANDIDATE-EXECUTION-INPUT"
    );
    assert_eq!(
      crate::oden_rev2_permission_actor_capture_count_for_test(),
      0
    );
  }

  #[cfg(any(
    all(target_arch = "aarch64", target_vendor = "apple", target_os = "macos"),
    all(
      target_arch = "x86_64",
      target_vendor = "unknown",
      target_os = "linux",
      target_env = "gnu"
    )
  ))]
  #[test]
  fn lstat_final_missing_candidate_requires_registered_admission_identity() {
    let admission = native_lstat_final_missing_execution_admission();
    let forged: &'static Rev2FilesystemLstatExecutionAdmission =
      Box::leak(Box::new(*admission));
    let existing = native_lstat_existing_execution_admission();
    let root = TempRoot::new("lstat-final-missing-candidate-admission");
    let project = root.0.join("data");
    let input = lstat_candidate_input(&project, admission);
    let context =
      lstat_final_missing_candidate_context(&project, &input.case_projection);
    for candidate in [forged, existing] {
      assert_eq!(
        refusal(
          super::oden_capsec_rev2_observe_lstat_final_missing_candidate(
            &context,
            &project,
            candidate,
            input.clone(),
          )
          .err()
          .expect("copied or wrong-table admission must refuse")
        ),
        "OD-CAP-REV2-FILESYSTEM-CANDIDATE-EXECUTION-ADMISSION"
      );
    }
    assert_eq!(std::fs::read_dir(&project).unwrap().count(), 0);
  }

  #[cfg(any(
    all(target_arch = "aarch64", target_vendor = "apple", target_os = "macos"),
    all(
      target_arch = "x86_64",
      target_vendor = "unknown",
      target_os = "linux",
      target_env = "gnu"
    )
  ))]
  #[test]
  fn lstat_final_missing_candidate_refuses_present_entries_and_inventory_aliases()
   {
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::symlink;

    let admission = native_lstat_final_missing_execution_admission();
    let _actors = ActorCapture::install(principal());
    for mutation in [
      "empty-file",
      "nonempty-file",
      "symlink",
      "hardlink",
      "directory",
      "fifo",
      "case-alias",
      "destination",
      "extra-entry",
    ] {
      let root = TempRoot::new(&format!("lstat-final-missing-host-{mutation}"));
      let project = root.0.join("data");
      let target = project.join("input.txt");
      let input = lstat_candidate_input(&project, admission);
      let context =
        lstat_final_missing_candidate_context(&project, &input.case_projection);
      match mutation {
        "empty-file" => std::fs::write(&target, b"").unwrap(),
        "nonempty-file" => std::fs::write(&target, b"x").unwrap(),
        "symlink" => {
          std::fs::write(root.0.join("outside.txt"), b"").unwrap();
          symlink("../outside.txt", &target).unwrap();
        }
        "hardlink" => {
          std::fs::write(&target, b"").unwrap();
          std::fs::hard_link(&target, root.0.join("outside-link")).unwrap();
        }
        "directory" => std::fs::create_dir(&target).unwrap(),
        "fifo" => {
          let target_c =
            std::ffi::CString::new(target.as_os_str().as_bytes()).unwrap();
          // SAFETY: target_c is NUL-terminated and mkfifo does not retain it.
          assert_eq!(unsafe { libc::mkfifo(target_c.as_ptr(), 0o600) }, 0);
        }
        "case-alias" => std::fs::write(project.join("INPUT.txt"), b"").unwrap(),
        "destination" => {
          std::fs::write(project.join("output.txt"), b"").unwrap()
        }
        "extra-entry" => {
          std::fs::write(project.join("unexpected.txt"), b"").unwrap()
        }
        _ => unreachable!(),
      }
      crate::oden_rev2_reset_permission_actor_capture_count_for_test();
      assert_eq!(
        refusal(
          super::oden_capsec_rev2_observe_lstat_final_missing_candidate(
            &context, &project, admission, input,
          )
          .err()
          .expect("present entry must refuse")
        ),
        "OD-CAP-REV2-FILESYSTEM-CANDIDATE-INITIAL-INVENTORY",
        "{mutation}"
      );
      assert_eq!(
        crate::oden_rev2_permission_actor_capture_count_for_test(),
        0,
        "{mutation} must refuse before checked-op actor capture"
      );
      assert!(std::fs::read_dir(&project).unwrap().next().is_some());
    }
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

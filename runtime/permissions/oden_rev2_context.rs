// Copyright 2018-2026 the Deno authors. MIT license.

//! Sealed C03-to-C04 runtime authority context.
//!
//! The constructor consumes one Armable C03 context only after immutable
//! executable installation. The authenticated raw snapshot is deserialized
//! once into closed typed policy and binding records and then dropped. No API
//! in this module crosses V8 or advertises an armed runtime.
//! @ref LLP 0019#stage-c-runtime-authority-and-typed-permission-checkpoint-c04--eng-24017 [implements]

#![allow(
  dead_code,
  reason = "the sealed C04 context precedes its later bootstrap and operation-adapter consumers"
)]

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Deserialize;
#[cfg(test)]
use serde_json::Value;
use std::collections::BTreeSet;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

use crate::oden_rev2_authority::AuthorityRowKind;
use crate::oden_rev2_authority::RuntimeAuthorityReadView;
use crate::oden_rev2_authority::RuntimeAuthorityState;
use crate::oden_rev2_authority::RuntimeIdentityBinding;
use crate::oden_rev2_executable::OdenRev2InstalledExecutableContext;
use crate::oden_rev2_policy::OdenRev2LoadedPolicyContext;
use crate::oden_rev2_policy::OdenRev2RetainedObject;
use crate::rev2::AuthoritySelectorInput;
use crate::rev2::CanonicalAuthoritySelector;
use crate::rev2::CompatibilityDispositionInput;
use crate::rev2::DecisionPolicyInput;
use crate::rev2::EngineIdentity;
use crate::rev2::Generations;
use crate::rev2::HandleSelectorInput;
use crate::rev2::Mode;
use crate::rev2::NamedSelectorInput;
use crate::rev2::OperationProvenanceContext;
use crate::rev2::PathBindingInput;
use crate::rev2::PrincipalKind;
use crate::rev2::PrincipalRef;
use crate::rev2::ProtectedExceptionInput;
use crate::rev2::Rev2Core;
use crate::rev2::SelectorPolarity;
use crate::rev2::domain_digest;
use crate::rev2_registry_generated::REV2_PROFILE;
use crate::rev2_registry_generated::REV2_REGISTRY_DIGEST;
use crate::rev2_registry_generated::REV2_VOCAB_DIGEST;

const CONTEXT_ERROR: &str = "OD-CAP-REV2-RUNTIME-CONTEXT";
const SNAPSHOT_SCHEMA: &str = "oden/capsec-armed-snapshot/2";
const POLICY_SCHEMA: &str = "oden/capsec-policy/2";

static RUNTIME_AUTHORITY_INSTALLER: RuntimeAuthorityInstaller =
  RuntimeAuthorityInstaller::new();

struct RuntimeAuthorityInstaller {
  claimed: AtomicBool,
}

/// One context-minted permission-batch sequence.
///
/// The value is intentionally opaque outside this module: sibling runtime
/// modules can consume a token, but cannot construct one from a caller-owned
/// integer. The token is not `Clone` or `Copy`, so one issuance can seed only
/// one normalized batch.
#[derive(Debug, Eq, PartialEq)]
pub(crate) struct OdenRev2PermissionBatchSequence {
  value: u64,
}

impl OdenRev2PermissionBatchSequence {
  pub(crate) fn into_value(self) -> u64 {
    self.value
  }

  #[cfg(test)]
  pub(crate) fn for_test(value: u64) -> Self {
    Self { value }
  }
}

impl RuntimeAuthorityInstaller {
  const fn new() -> Self {
    Self {
      claimed: AtomicBool::new(false),
    }
  }

  fn claim(&self) -> Result<(), String> {
    self
      .claimed
      .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
      .map(|_| ())
      .map_err(|_| format!("{CONTEXT_ERROR}-ALREADY-INSTALLED"))
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OdenRev2ExecutionRole {
  Run,
  Probe,
  Candidate,
  Baseline,
}

impl OdenRev2ExecutionRole {
  fn parse(value: &str) -> Result<Self, String> {
    match value {
      "run" => Ok(Self::Run),
      "probe" => Ok(Self::Probe),
      "candidate" => Ok(Self::Candidate),
      "baseline" => Ok(Self::Baseline),
      _ => Err(format!("{CONTEXT_ERROR}-EXECUTION-ROLE")),
    }
  }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OdenRev2ProtectedException {
  predicate_id: String,
  reason_digest: String,
  canonical_row_digest: String,
}

impl OdenRev2ProtectedException {
  pub fn predicate_id(&self) -> &str {
    &self.predicate_id
  }

  pub fn reason_digest(&self) -> &str {
    &self.reason_digest
  }

  pub fn canonical_row_digest(&self) -> &str {
    &self.canonical_row_digest
  }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OdenRev2StaticAuthorityRow {
  source_id: String,
  selector: CanonicalAuthoritySelector,
  protected: Option<OdenRev2ProtectedException>,
}

impl OdenRev2StaticAuthorityRow {
  pub fn source_id(&self) -> &str {
    &self.source_id
  }

  pub fn selector(&self) -> &CanonicalAuthoritySelector {
    &self.selector
  }

  pub fn protected(&self) -> Option<&OdenRev2ProtectedException> {
    self.protected.as_ref()
  }
}

#[derive(Clone, Debug)]
pub struct OdenRev2PrincipalPolicy {
  principal: PrincipalRef,
  resolver_id: String,
  binding_digest: String,
  floor: Arc<[OdenRev2StaticAuthorityRow]>,
  escalation_ceiling: Arc<[OdenRev2StaticAuthorityRow]>,
  denials: Arc<[OdenRev2StaticAuthorityRow]>,
}

impl OdenRev2PrincipalPolicy {
  pub fn principal(&self) -> &PrincipalRef {
    &self.principal
  }

  pub fn resolver_id(&self) -> &str {
    &self.resolver_id
  }

  pub fn binding_digest(&self) -> &str {
    &self.binding_digest
  }

  pub fn floor(&self) -> &[OdenRev2StaticAuthorityRow] {
    &self.floor
  }

  pub fn escalation_ceiling(&self) -> &[OdenRev2StaticAuthorityRow] {
    &self.escalation_ceiling
  }

  pub fn denials(&self) -> &[OdenRev2StaticAuthorityRow] {
    &self.denials
  }
}

#[derive(Clone, Debug)]
pub struct OdenRev2StaticPolicy {
  principals: Arc<[OdenRev2PrincipalPolicy]>,
  process_denials: Arc<[OdenRev2StaticAuthorityRow]>,
  deny_ceiling: Arc<[OdenRev2StaticAuthorityRow]>,
  validated_protected_receipts: Arc<[OdenRev2ValidatedProtectedReceipt]>,
  validated_receipt_row_digests: Arc<[String]>,
}

impl OdenRev2StaticPolicy {
  pub fn principals(&self) -> &[OdenRev2PrincipalPolicy] {
    &self.principals
  }

  pub fn process_denials(&self) -> &[OdenRev2StaticAuthorityRow] {
    &self.process_denials
  }

  pub fn deny_ceiling(&self) -> &[OdenRev2StaticAuthorityRow] {
    &self.deny_ceiling
  }

  pub fn validated_receipt_row_digests(&self) -> &[String] {
    &self.validated_receipt_row_digests
  }

  pub fn validated_protected_receipts(
    &self,
  ) -> &[OdenRev2ValidatedProtectedReceipt] {
    &self.validated_protected_receipts
  }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OdenRev2ValidatedProtectedReceipt {
  receipt_id: String,
  binding_digest: String,
  canonical_row_digest: String,
  predicate_id: String,
  principal: PrincipalRef,
  resource_digest: String,
  project_digest: String,
  issuer_id: String,
  issuer_generation: String,
  revocation_feed_id: String,
  receipt_negative_generation: String,
  expires_at: String,
  monotonic_deadline: String,
}

impl OdenRev2ValidatedProtectedReceipt {
  pub fn receipt_id(&self) -> &str {
    &self.receipt_id
  }

  pub fn binding_digest(&self) -> &str {
    &self.binding_digest
  }

  pub fn canonical_row_digest(&self) -> &str {
    &self.canonical_row_digest
  }

  pub fn predicate_id(&self) -> &str {
    &self.predicate_id
  }

  pub fn principal(&self) -> &PrincipalRef {
    &self.principal
  }

  pub fn resource_digest(&self) -> &str {
    &self.resource_digest
  }

  pub fn project_digest(&self) -> &str {
    &self.project_digest
  }

  pub fn issuer_id(&self) -> &str {
    &self.issuer_id
  }

  pub fn issuer_generation(&self) -> &str {
    &self.issuer_generation
  }

  pub fn revocation_feed_id(&self) -> &str {
    &self.revocation_feed_id
  }

  pub fn receipt_negative_generation(&self) -> &str {
    &self.receipt_negative_generation
  }

  pub fn expires_at(&self) -> &str {
    &self.expires_at
  }

  pub fn monotonic_deadline(&self) -> &str {
    &self.monotonic_deadline
  }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OdenRev2PlatformPath {
  Unicode(String),
  Bytes(Vec<u8>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OdenRev2PlatformObjectIdentity {
  value: String,
}

impl OdenRev2PlatformObjectIdentity {
  pub fn value(&self) -> &str {
    &self.value
  }
}

#[derive(Clone, Debug)]
pub struct OdenRev2RootBinding {
  source_id: String,
  logical_root: String,
  principal: Option<PrincipalRef>,
  binding_id: String,
  canonical_path: OdenRev2PlatformPath,
  object_identity: OdenRev2PlatformObjectIdentity,
  binding_provenance_digest: String,
}

impl OdenRev2RootBinding {
  pub fn source_id(&self) -> &str {
    &self.source_id
  }

  pub fn logical_root(&self) -> &str {
    &self.logical_root
  }

  pub fn principal(&self) -> Option<&PrincipalRef> {
    self.principal.as_ref()
  }

  pub fn binding_id(&self) -> &str {
    &self.binding_id
  }

  pub fn canonical_path(&self) -> &OdenRev2PlatformPath {
    &self.canonical_path
  }

  pub fn object_identity(&self) -> &OdenRev2PlatformObjectIdentity {
    &self.object_identity
  }

  pub fn binding_provenance_digest(&self) -> &str {
    &self.binding_provenance_digest
  }
}

#[derive(Clone, Debug)]
pub struct OdenRev2ExecutableBinding {
  source_id: String,
  role: String,
  canonical_content_identity: String,
  binding_id: String,
  principal: Option<PrincipalRef>,
  canonical_path: OdenRev2PlatformPath,
  object_identity: OdenRev2PlatformObjectIdentity,
  provenance_digest: String,
}

impl OdenRev2ExecutableBinding {
  pub fn source_id(&self) -> &str {
    &self.source_id
  }

  pub fn binding_id(&self) -> &str {
    &self.binding_id
  }

  pub fn role(&self) -> &str {
    &self.role
  }

  pub fn canonical_content_identity(&self) -> &str {
    &self.canonical_content_identity
  }

  pub fn principal(&self) -> Option<&PrincipalRef> {
    self.principal.as_ref()
  }

  pub fn canonical_path(&self) -> &OdenRev2PlatformPath {
    &self.canonical_path
  }

  pub fn object_identity(&self) -> &OdenRev2PlatformObjectIdentity {
    &self.object_identity
  }

  pub fn provenance_digest(&self) -> &str {
    &self.provenance_digest
  }
}

#[derive(Clone, Debug)]
pub struct OdenRev2RouteBinding {
  source_id: String,
  resource_digest: String,
  route_digest: String,
  route_id: String,
  route_kind: String,
}

impl OdenRev2RouteBinding {
  pub fn source_id(&self) -> &str {
    &self.source_id
  }

  pub fn resource_digest(&self) -> &str {
    &self.resource_digest
  }

  pub fn route_digest(&self) -> &str {
    &self.route_digest
  }

  pub fn route_id(&self) -> &str {
    &self.route_id
  }

  pub fn route_kind(&self) -> &str {
    &self.route_kind
  }
}

#[derive(Clone, Debug)]
pub struct OdenRev2ClassifierBinding {
  source_id: String,
  classifier_id: String,
  classifier_version: String,
  input_digest: String,
}

impl OdenRev2ClassifierBinding {
  pub fn source_id(&self) -> &str {
    &self.source_id
  }

  pub fn classifier_id(&self) -> &str {
    &self.classifier_id
  }

  pub fn classifier_version(&self) -> &str {
    &self.classifier_version
  }

  pub fn input_digest(&self) -> &str {
    &self.input_digest
  }
}

#[derive(Clone, Debug)]
pub struct OdenRev2StaticBindings {
  roots: Arc<[OdenRev2RootBinding]>,
  executables: Arc<[OdenRev2ExecutableBinding]>,
  routes: Arc<[OdenRev2RouteBinding]>,
  classifiers: Arc<[OdenRev2ClassifierBinding]>,
}

impl OdenRev2StaticBindings {
  pub fn roots(&self) -> &[OdenRev2RootBinding] {
    &self.roots
  }

  pub fn executables(&self) -> &[OdenRev2ExecutableBinding] {
    &self.executables
  }

  pub fn routes(&self) -> &[OdenRev2RouteBinding] {
    &self.routes
  }

  pub fn classifiers(&self) -> &[OdenRev2ClassifierBinding] {
    &self.classifiers
  }
}

pub struct OdenRev2RuntimeAuthorityContext {
  identity: RuntimeIdentityBinding,
  engine_identity: EngineIdentity,
  target: String,
  feature_set: String,
  execution_role: OdenRev2ExecutionRole,
  mode: Mode,
  static_policy: OdenRev2StaticPolicy,
  bindings: OdenRev2StaticBindings,
  retained_objects: Arc<[OdenRev2RetainedObject]>,
  installed_executables: OdenRev2InstalledExecutableContext,
  authority_state: RuntimeAuthorityState,
  permission_batch_sequence: AtomicU64,
}

impl OdenRev2RuntimeAuthorityContext {
  pub(crate) fn install(
    loaded: OdenRev2LoadedPolicyContext,
  ) -> Result<Self, String> {
    Self::install_with(&RUNTIME_AUTHORITY_INSTALLER, loaded)
  }

  fn install_with(
    installer: &RuntimeAuthorityInstaller,
    loaded: OdenRev2LoadedPolicyContext,
  ) -> Result<Self, String> {
    installer.claim()?;
    let parts = loaded.into_runtime_parts()?;
    let snapshot: SnapshotWire = serde_json::from_value(parts.snapshot)
      .map_err(|_| format!("{CONTEXT_ERROR}-SNAPSHOT-SHAPE"))?;
    if snapshot.snapshot_schema != SNAPSHOT_SCHEMA
      || snapshot.caps_vocab != REV2_PROFILE
      || snapshot.vocab_digest != REV2_VOCAB_DIGEST
      || snapshot.registry_digest != REV2_REGISTRY_DIGEST
      || snapshot.policy_digest != parts.policy_digest
      || snapshot.project_digest != parts.project_digest
      || snapshot.armed_snapshot_digest != parts.armed_snapshot_digest
      || snapshot.engine_target != parts.target
      || snapshot.engine_feature_set != parts.feature_set
      || snapshot.execution_role != parts.execution_role
      || snapshot.run_nonce != parts.run_nonce
      || snapshot.channel_epoch != parts.channel_epoch
      || snapshot.canonical_policy.policy_schema != POLICY_SCHEMA
      || snapshot.canonical_policy.caps_vocab != REV2_PROFILE
      || snapshot.canonical_policy.vocab_digest != REV2_VOCAB_DIGEST
      || snapshot.canonical_policy.policy_digest != parts.policy_digest
      || snapshot.canonical_policy.mode != snapshot.effective_mode
    {
      return Err(format!("{CONTEXT_ERROR}-IDENTITY-MISMATCH"));
    }

    let identity = RuntimeIdentityBinding::new(
      snapshot.vocab_digest,
      snapshot.registry_digest,
      snapshot.policy_digest,
      snapshot.armed_snapshot_digest,
      snapshot.project_digest,
      snapshot.run_nonce,
      snapshot.channel_epoch,
    )
    .map_err(|_| format!("{CONTEXT_ERROR}-IDENTITY-MALFORMED"))?;
    let engine_identity = EngineIdentity::embedded();
    let core =
      Rev2Core::embedded().map_err(|_| format!("{CONTEXT_ERROR}-CORE-INIT"))?;
    let (mut static_policy, source_ids) = compile_static_policy(
      snapshot.canonical_policy,
      snapshot.deny_ceiling,
      &core,
    )?;
    let bindings = compile_bindings(
      snapshot.root_bindings,
      snapshot.executable_bindings,
      snapshot.route_bindings,
      snapshot.classifier_bindings,
      &source_ids,
      &parts.retained_objects,
      &parts.installed_executables,
    )?;
    let validated_receipts = compile_validated_receipts(
      snapshot.protected_receipt_bindings,
      identity.project_digest(),
      &static_policy,
    )?;
    static_policy.validated_receipt_row_digests = validated_receipts
      .iter()
      .map(|receipt| receipt.canonical_row_digest.clone())
      .collect::<Vec<_>>()
      .into();
    static_policy.validated_protected_receipts = validated_receipts.into();

    // All other authenticated fields were consumed into closed wire records;
    // explicitly drop non-decision metadata rather than retaining raw JSON.
    drop(snapshot.conformance_report_digest);
    drop(snapshot.protected_predicate_versions);
    drop(snapshot.protected_receipt_set_digest);
    let execution_role = OdenRev2ExecutionRole::parse(&parts.execution_role)?;
    let authority_state = RuntimeAuthorityState::new(identity.clone());
    Ok(Self {
      identity,
      engine_identity,
      target: parts.target,
      feature_set: parts.feature_set,
      execution_role,
      mode: snapshot.effective_mode,
      static_policy,
      bindings,
      retained_objects: parts.retained_objects,
      installed_executables: parts.installed_executables,
      authority_state,
      permission_batch_sequence: AtomicU64::new(1),
    })
  }

  pub fn identity(&self) -> &RuntimeIdentityBinding {
    &self.identity
  }

  pub fn target(&self) -> &str {
    &self.target
  }

  pub fn feature_set(&self) -> &str {
    &self.feature_set
  }

  pub fn execution_role(&self) -> OdenRev2ExecutionRole {
    self.execution_role
  }

  pub fn mode(&self) -> Mode {
    self.mode
  }

  pub fn static_policy(&self) -> &OdenRev2StaticPolicy {
    &self.static_policy
  }

  pub fn bindings(&self) -> &OdenRev2StaticBindings {
    &self.bindings
  }

  pub fn authority_state(&self) -> &RuntimeAuthorityState {
    &self.authority_state
  }

  pub(crate) fn next_permission_batch_sequence(
    &self,
  ) -> Result<OdenRev2PermissionBatchSequence, String> {
    let mut current = self.permission_batch_sequence.load(Ordering::Acquire);
    loop {
      if current == u64::MAX {
        return Err(format!("{CONTEXT_ERROR}-BATCH-SEQUENCE-EXHAUSTED"));
      }
      match self.permission_batch_sequence.compare_exchange_weak(
        current,
        current + 1,
        Ordering::AcqRel,
        Ordering::Acquire,
      ) {
        Ok(_) => {
          return Ok(OdenRev2PermissionBatchSequence { value: current });
        }
        Err(observed) => current = observed,
      }
    }
  }

  pub(crate) fn installed_executables(
    &self,
  ) -> &OdenRev2InstalledExecutableContext {
    &self.installed_executables
  }

  pub(crate) fn retained_objects(&self) -> &[OdenRev2RetainedObject] {
    &self.retained_objects
  }

  pub(crate) fn decision_policy_for_operation(
    &self,
    view: &RuntimeAuthorityReadView,
    facts: OdenRev2OperationAuthorityFacts,
  ) -> Result<DecisionPolicyInput, String> {
    if view.identity() != &self.identity
      || !self
        .authority_state
        .is_current(view)
        .map_err(|_| format!("{CONTEXT_ERROR}-READ-VIEW"))?
      || view.is_fail_closed()
    {
      return Err(format!("{CONTEXT_ERROR}-READ-VIEW"));
    }
    // C03 authenticates and retains the complete receipts, but C04 does not
    // yet own a trusted current monotonic clock or issuer/revocation-feed
    // generation adapter. Never project receipt row digests until those live
    // dependencies can be checked atomically for this operation.
    if !self.static_policy.validated_protected_receipts.is_empty() {
      return Err(format!("{CONTEXT_ERROR}-RECEIPT-RUNTIME-UNINSTALLED"));
    }
    validate_operation_facts(self, &facts)?;

    let mut process_denials = self
      .static_policy
      .process_denials
      .iter()
      .chain(self.static_policy.deny_ceiling.iter())
      .map(|row| named_input(&self.engine_identity, row))
      .collect::<Vec<_>>();
    let mut principal_denials = Vec::new();
    let mut escalation_ceiling = Vec::new();
    let mut static_floor = Vec::new();
    let mut protected_exceptions = Vec::new();
    for principal in self.static_policy.principals.iter() {
      principal_denials.extend(
        principal
          .denials
          .iter()
          .map(|row| named_input(&self.engine_identity, row)),
      );
      escalation_ceiling.extend(
        principal
          .escalation_ceiling
          .iter()
          .map(|row| named_input(&self.engine_identity, row)),
      );
      for row in principal.floor.iter() {
        static_floor.push(named_input(&self.engine_identity, row));
        if let Some(protected) = &row.protected {
          protected_exceptions.push(ProtectedExceptionInput {
            source_id: row.source_id.clone(),
            predicate_id: protected.predicate_id.clone(),
            reason_digest: protected.reason_digest.clone(),
            canonical_row_digest: protected.canonical_row_digest.clone(),
            selector: selector_input(&self.engine_identity, &row.selector),
          });
        }
      }
    }

    let session_revocations = view
      .rows(AuthorityRowKind::SessionRevocation)
      .map(|row| NamedSelectorInput {
        source_id: row.row_id().to_string(),
        selector: selector_input(&self.engine_identity, row.selector()),
      })
      .collect();
    for kind in [
      AuthorityRowKind::NegativeOverlay,
      AuthorityRowKind::Revocation,
    ] {
      for row in view.rows(kind) {
        let input = NamedSelectorInput {
          source_id: row.row_id().to_string(),
          selector: selector_input(&self.engine_identity, row.selector()),
        };
        if row.selector().principal.is_some() {
          principal_denials.push(input);
        } else {
          process_denials.push(input);
        }
      }
    }
    let session_grants = view
      .rows(AuthorityRowKind::SessionPositive)
      .map(|row| NamedSelectorInput {
        source_id: row.row_id().to_string(),
        selector: selector_input(&self.engine_identity, row.selector()),
      })
      .collect();
    let generations = view.generations();
    Ok(DecisionPolicyInput {
      identity: self.engine_identity.clone(),
      mode: self.mode,
      run_nonce: self.identity.run_nonce().to_string(),
      channel_epoch: self.identity.channel_epoch().to_string(),
      provenance: OperationProvenanceContext {
        policy_digest: self.identity.policy_digest().to_string(),
        armed_snapshot_digest: self
          .identity
          .armed_snapshot_digest()
          .to_string(),
        quota_owner: facts.quota_owner,
        terminal_evidence_id: facts.terminal_evidence_id,
      },
      generations: Generations {
        negative_overlay: generations.negative_overlay().to_string(),
        policy_snapshot: generations.policy_snapshot().to_string(),
        revocation: generations.revocation().to_string(),
        session_overlay: generations.session_overlay().to_string(),
      },
      process_denials: {
        process_denials
          .sort_by(|left, right| left.source_id.cmp(&right.source_id));
        process_denials
      },
      principal_denials,
      session_revocations,
      escalation_ceiling,
      static_floor,
      handles: facts.handles,
      session_grants,
      implicit_self: facts.implicit_self,
      protected_exceptions,
      compatibility_dispositions: Vec::<CompatibilityDispositionInput>::new(),
      validated_receipt_row_digests: self
        .static_policy
        .validated_receipt_row_digests
        .to_vec(),
      path_bindings: facts.path_bindings,
    })
  }
}

pub(crate) struct OdenRev2OperationAuthorityFacts {
  quota_owner: PrincipalRef,
  terminal_evidence_id: String,
  implicit_self: Vec<NamedSelectorInput>,
  path_bindings: Vec<PathBindingInput>,
  handles: Vec<HandleSelectorInput>,
}

impl OdenRev2OperationAuthorityFacts {
  /// Capture only facts whose authentication is complete in C04 today.
  /// Implicit-self inventories, live path identities, and handles remain
  /// closed until their owning host verifiers can construct unforgeable facts.
  fn new(quota_owner: PrincipalRef, terminal_evidence_id: String) -> Self {
    Self {
      quota_owner,
      terminal_evidence_id,
      implicit_self: Vec::new(),
      path_bindings: Vec::new(),
      handles: Vec::new(),
    }
  }
}

fn selector_input(
  identity: &EngineIdentity,
  selector: &CanonicalAuthoritySelector,
) -> AuthoritySelectorInput {
  AuthoritySelectorInput {
    identity: identity.clone(),
    principal: selector.principal.clone(),
    capability: selector.capability.clone(),
    resource: selector.resource.clone(),
  }
}

fn named_input(
  identity: &EngineIdentity,
  row: &OdenRev2StaticAuthorityRow,
) -> NamedSelectorInput {
  NamedSelectorInput {
    source_id: row.source_id.clone(),
    selector: selector_input(identity, &row.selector),
  }
}

fn validate_operation_facts(
  context: &OdenRev2RuntimeAuthorityContext,
  facts: &OdenRev2OperationAuthorityFacts,
) -> Result<(), String> {
  if facts.terminal_evidence_id.trim().is_empty()
    || facts.quota_owner.key.trim().is_empty()
    || matches!(
      facts.quota_owner.kind,
      PrincipalKind::Runtime | PrincipalKind::NoUser
    )
  {
    return Err(format!("{CONTEXT_ERROR}-OPERATION-FACTS"));
  }
  let core =
    Rev2Core::embedded().map_err(|_| format!("{CONTEXT_ERROR}-CORE-INIT"))?;
  let mut source_ids = BTreeSet::new();
  for row in &facts.implicit_self {
    if row.source_id.trim().is_empty()
      || !source_ids.insert(row.source_id.clone())
      || row.selector.identity != context.engine_identity
      || core
        .normalize_selector(&row.selector, SelectorPolarity::Positive)
        .is_err()
    {
      return Err(format!("{CONTEXT_ERROR}-IMPLICIT-SELF"));
    }
  }
  let root_keys = context
    .bindings
    .roots
    .iter()
    .map(|binding| (binding.source_id.as_str(), binding.binding_id.as_str()))
    .collect::<BTreeSet<_>>();
  let mut path_keys = BTreeSet::new();
  for binding in &facts.path_bindings {
    if !root_keys
      .contains(&(binding.source_id.as_str(), binding.root_binding_id.as_str()))
      || !path_keys
        .insert((binding.source_id.clone(), binding.root_binding_id.clone()))
    {
      return Err(format!("{CONTEXT_ERROR}-PATH-BINDING"));
    }
  }
  let mut handle_ids = BTreeSet::new();
  for handle in &facts.handles {
    if handle.handle_id.trim().is_empty()
      || !handle_ids.insert(handle.handle_id.clone())
      || handle.armed_snapshot_digest
        != context.identity.armed_snapshot_digest()
      || handle.carrier_epoch != context.identity.channel_epoch()
      || handle.selector.identity != context.engine_identity
      || core
        .normalize_selector(&handle.selector, SelectorPolarity::Positive)
        .is_err()
    {
      return Err(format!("{CONTEXT_ERROR}-HANDLE"));
    }
  }
  Ok(())
}

fn compile_static_policy(
  policy: CanonicalPolicyWire,
  deny_ceiling: Vec<AuthorityRowWire>,
  core: &Rev2Core,
) -> Result<(OdenRev2StaticPolicy, BTreeSet<String>), String> {
  let mut source_ids = BTreeSet::new();
  let mut protected_digests = BTreeSet::new();
  let mut principals = Vec::with_capacity(policy.principals.len());
  for principal in policy.principals {
    validate_principal(&principal.principal)?;
    validate_digest(&principal.binding.binding_digest)?;
    require_nonempty(&principal.binding.resolver_id)?;
    let floor = compile_rows(
      principal.floor,
      Some(&principal.principal),
      SelectorPolarity::Positive,
      true,
      core,
      &mut source_ids,
      &mut protected_digests,
    )?;
    let escalation_ceiling = compile_rows(
      principal.escalation_ceiling,
      Some(&principal.principal),
      SelectorPolarity::Positive,
      false,
      core,
      &mut source_ids,
      &mut protected_digests,
    )?;
    let denials = compile_rows(
      principal.denials,
      Some(&principal.principal),
      SelectorPolarity::Negative,
      false,
      core,
      &mut source_ids,
      &mut protected_digests,
    )?;
    principals.push(OdenRev2PrincipalPolicy {
      principal: principal.principal,
      resolver_id: principal.binding.resolver_id,
      binding_digest: principal.binding.binding_digest,
      floor: floor.into(),
      escalation_ceiling: escalation_ceiling.into(),
      denials: denials.into(),
    });
  }
  let process_denials = compile_rows(
    policy.process_denials,
    None,
    SelectorPolarity::Negative,
    false,
    core,
    &mut source_ids,
    &mut protected_digests,
  )?;
  let deny_ceiling = compile_rows(
    deny_ceiling,
    None,
    SelectorPolarity::Negative,
    false,
    core,
    &mut source_ids,
    &mut protected_digests,
  )?;
  Ok((
    OdenRev2StaticPolicy {
      principals: principals.into(),
      process_denials: process_denials.into(),
      deny_ceiling: deny_ceiling.into(),
      validated_protected_receipts: Arc::from([]),
      validated_receipt_row_digests: Arc::from([]),
    },
    source_ids,
  ))
}

#[allow(clippy::too_many_arguments)]
fn compile_rows(
  rows: Vec<AuthorityRowWire>,
  expected_principal: Option<&PrincipalRef>,
  polarity: SelectorPolarity,
  protected_allowed: bool,
  core: &Rev2Core,
  source_ids: &mut BTreeSet<String>,
  protected_digests: &mut BTreeSet<String>,
) -> Result<Vec<OdenRev2StaticAuthorityRow>, String> {
  let mut compiled = Vec::with_capacity(rows.len());
  for row in rows {
    if !source_ids.insert(row.source_id.clone())
      || row.selector.principal.as_ref() != expected_principal
    {
      return Err(format!("{CONTEXT_ERROR}-STATIC-ROW"));
    }
    let normalized = core
      .normalize_selector(
        &selector_input(&EngineIdentity::embedded(), &row.selector),
        polarity,
      )
      .map_err(|_| format!("{CONTEXT_ERROR}-STATIC-SELECTOR"))?;
    if normalized != row.selector {
      return Err(format!("{CONTEXT_ERROR}-STATIC-SELECTOR"));
    }
    let protected = match row.protected {
      Some(protected) if protected_allowed => {
        for value in [
          &protected.predicate_id,
          &protected.reason_digest,
          &protected.canonical_row_digest,
        ] {
          require_nonempty(value)?;
        }
        validate_digest(&protected.reason_digest)?;
        validate_digest(&protected.canonical_row_digest)?;
        if !protected_digests.insert(protected.canonical_row_digest.clone()) {
          return Err(format!("{CONTEXT_ERROR}-PROTECTED-DUPLICATE"));
        }
        Some(OdenRev2ProtectedException {
          predicate_id: protected.predicate_id,
          reason_digest: protected.reason_digest,
          canonical_row_digest: protected.canonical_row_digest,
        })
      }
      Some(_) => return Err(format!("{CONTEXT_ERROR}-PROTECTED-POSITION")),
      None => None,
    };
    compiled.push(OdenRev2StaticAuthorityRow {
      source_id: row.source_id,
      selector: row.selector,
      protected,
    });
  }
  Ok(compiled)
}

fn compile_validated_receipts(
  receipts: Vec<ProtectedReceiptWire>,
  project_digest: &str,
  policy: &OdenRev2StaticPolicy,
) -> Result<Vec<OdenRev2ValidatedProtectedReceipt>, String> {
  let expected = policy
    .principals
    .iter()
    .flat_map(|principal| principal.floor.iter())
    .filter_map(|row| row.protected.as_ref().map(|protected| (row, protected)))
    .map(|(row, protected)| {
      (protected.canonical_row_digest.as_str(), (row, protected))
    })
    .collect::<std::collections::BTreeMap<_, _>>();
  let mut receipt_ids = BTreeSet::new();
  let mut binding_digests = BTreeSet::new();
  let mut row_digests = BTreeSet::new();
  let mut compiled = Vec::with_capacity(receipts.len());
  for receipt in receipts {
    let Some((row, protected)) =
      expected.get(receipt.canonical_row_digest.as_str())
    else {
      return Err(format!("{CONTEXT_ERROR}-RECEIPT-ROW"));
    };
    for value in [
      &receipt.receipt_id,
      &receipt.predicate_id,
      &receipt.issuer_id,
      &receipt.revocation_feed_id,
      &receipt.expires_at,
    ] {
      require_nonempty(value)?;
    }
    for digest in [
      &receipt.binding_digest,
      &receipt.canonical_row_digest,
      &receipt.resource_digest,
      &receipt.project_digest,
    ] {
      validate_digest(digest)?;
    }
    for generation in [
      &receipt.issuer_generation,
      &receipt.receipt_negative_generation,
      &receipt.monotonic_deadline,
    ] {
      validate_canonical_u64(generation)?;
    }
    let resource_digest =
      domain_digest("oden:capsec:protected-resource:2", &row.selector.resource)
        .map_err(|_| format!("{CONTEXT_ERROR}-RECEIPT-RESOURCE"))?;
    if receipt.project_digest != project_digest
      || receipt.predicate_id != protected.predicate_id
      || receipt.principal
        != row
          .selector
          .principal
          .clone()
          .ok_or_else(|| format!("{CONTEXT_ERROR}-RECEIPT-PRINCIPAL"))?
      || receipt.resource_digest != resource_digest
      || !receipt_ids.insert(receipt.receipt_id.clone())
      || !binding_digests.insert(receipt.binding_digest.clone())
      || !row_digests.insert(receipt.canonical_row_digest.clone())
    {
      return Err(format!("{CONTEXT_ERROR}-RECEIPT-BINDING"));
    }
    compiled.push(OdenRev2ValidatedProtectedReceipt {
      receipt_id: receipt.receipt_id,
      binding_digest: receipt.binding_digest,
      canonical_row_digest: receipt.canonical_row_digest,
      predicate_id: receipt.predicate_id,
      principal: receipt.principal,
      resource_digest: receipt.resource_digest,
      project_digest: receipt.project_digest,
      issuer_id: receipt.issuer_id,
      issuer_generation: receipt.issuer_generation,
      revocation_feed_id: receipt.revocation_feed_id,
      receipt_negative_generation: receipt.receipt_negative_generation,
      expires_at: receipt.expires_at,
      monotonic_deadline: receipt.monotonic_deadline,
    });
  }
  if row_digests
    != expected
      .keys()
      .map(|digest| (*digest).to_string())
      .collect::<BTreeSet<_>>()
  {
    return Err(format!("{CONTEXT_ERROR}-RECEIPT-COVERAGE"));
  }
  compiled.sort_by(|left, right| {
    (&left.canonical_row_digest, &left.receipt_id)
      .cmp(&(&right.canonical_row_digest, &right.receipt_id))
  });
  Ok(compiled)
}

fn validate_canonical_u64(value: &str) -> Result<(), String> {
  let parsed = value
    .parse::<u64>()
    .map_err(|_| format!("{CONTEXT_ERROR}-GENERATION"))?;
  if parsed.to_string() != value {
    return Err(format!("{CONTEXT_ERROR}-GENERATION"));
  }
  Ok(())
}

fn compile_bindings(
  roots: Vec<RootBindingWire>,
  executables: Vec<ExecutableBindingWire>,
  routes: Vec<RouteBindingWire>,
  classifiers: Vec<ClassifierBindingWire>,
  source_ids: &BTreeSet<String>,
  retained: &[OdenRev2RetainedObject],
  installed: &OdenRev2InstalledExecutableContext,
) -> Result<OdenRev2StaticBindings, String> {
  let mut binding_ids = BTreeSet::new();
  let mut compiled_roots = Vec::with_capacity(roots.len());
  for root in roots {
    validate_binding_source(source_ids, &root.source_id)?;
    if !binding_ids.insert(root.root_binding_id.clone()) {
      return Err(format!("{CONTEXT_ERROR}-BINDING-ID"));
    }
    validate_digest(&root.binding_provenance_digest)?;
    let canonical_path = compile_platform_path(root.canonical_path)?;
    let object_identity = compile_object_identity(root.object_identity)?;
    let retained = retained
      .iter()
      .find(|object| object.binding_id() == root.root_binding_id)
      .ok_or_else(|| format!("{CONTEXT_ERROR}-ROOT-RETAINED"))?;
    if retained.source_id() != root.source_id
      || retained.role().is_some()
      || retained.principal() != root.principal.as_ref()
      || retained.canonical_path() != platform_path(&canonical_path)?.as_path()
      || retained.object_identity() != object_identity.value
      || retained.provenance_digest()
        != Some(root.binding_provenance_digest.as_str())
    {
      return Err(format!("{CONTEXT_ERROR}-ROOT-RETAINED"));
    }
    compiled_roots.push(OdenRev2RootBinding {
      source_id: root.source_id,
      logical_root: root.logical_root,
      principal: root.principal,
      binding_id: root.root_binding_id,
      canonical_path,
      object_identity,
      binding_provenance_digest: root.binding_provenance_digest,
    });
  }

  let mut compiled_executables = Vec::with_capacity(executables.len());
  for executable in executables {
    validate_binding_source(source_ids, &executable.source_id)?;
    if !binding_ids.insert(executable.binding_id.clone()) {
      return Err(format!("{CONTEXT_ERROR}-BINDING-ID"));
    }
    validate_digest(&executable.canonical_content_identity)?;
    validate_digest(&executable.provenance_digest)?;
    let canonical_path = compile_platform_path(executable.canonical_path)?;
    let object_identity = compile_object_identity(executable.object_identity)?;
    let installed = installed
      .by_binding_id(&executable.binding_id)
      .ok_or_else(|| format!("{CONTEXT_ERROR}-EXECUTABLE-INSTALLED"))?;
    if installed.source_id() != executable.source_id
      || installed.role() != executable.role
      || installed.principal() != executable.principal.as_ref()
      || installed.canonical_path() != platform_path(&canonical_path)?.as_path()
      || installed.object_identity() != object_identity.value
      || installed.canonical_content_identity()
        != executable.canonical_content_identity
      || installed.provenance_digest() != executable.provenance_digest
    {
      return Err(format!("{CONTEXT_ERROR}-EXECUTABLE-INSTALLED"));
    }
    compiled_executables.push(OdenRev2ExecutableBinding {
      source_id: executable.source_id,
      role: executable.role,
      canonical_content_identity: executable.canonical_content_identity,
      binding_id: executable.binding_id,
      principal: executable.principal,
      canonical_path,
      object_identity,
      provenance_digest: executable.provenance_digest,
    });
  }
  if installed.as_slice().len() != compiled_executables.len()
    || retained.len() != compiled_roots.len() + compiled_executables.len()
  {
    return Err(format!("{CONTEXT_ERROR}-BINDING-COVERAGE"));
  }

  let mut compiled_routes = Vec::with_capacity(routes.len());
  for route in routes {
    validate_binding_source(source_ids, &route.source_id)?;
    validate_digest(&route.resource_digest)?;
    validate_digest(&route.route_digest)?;
    compiled_routes.push(OdenRev2RouteBinding {
      source_id: route.source_id,
      resource_digest: route.resource_digest,
      route_digest: route.route_digest,
      route_id: route.route_id,
      route_kind: route.route_kind,
    });
  }
  let mut compiled_classifiers = Vec::with_capacity(classifiers.len());
  for classifier in classifiers {
    validate_binding_source(source_ids, &classifier.source_id)?;
    validate_digest(&classifier.input_digest)?;
    compiled_classifiers.push(OdenRev2ClassifierBinding {
      source_id: classifier.source_id,
      classifier_id: classifier.classifier_id,
      classifier_version: classifier.classifier_version,
      input_digest: classifier.input_digest,
    });
  }
  Ok(OdenRev2StaticBindings {
    roots: compiled_roots.into(),
    executables: compiled_executables.into(),
    routes: compiled_routes.into(),
    classifiers: compiled_classifiers.into(),
  })
}

fn validate_binding_source(
  source_ids: &BTreeSet<String>,
  source_id: &str,
) -> Result<(), String> {
  if !source_ids.contains(source_id) {
    return Err(format!("{CONTEXT_ERROR}-BINDING-SOURCE"));
  }
  Ok(())
}

fn compile_platform_path(
  path: PlatformPathWire,
) -> Result<OdenRev2PlatformPath, String> {
  match path.encoding.as_str() {
    "unicode" => Ok(OdenRev2PlatformPath::Unicode(path.value)),
    "bytes" => URL_SAFE_NO_PAD
      .decode(path.value)
      .map(OdenRev2PlatformPath::Bytes)
      .map_err(|_| format!("{CONTEXT_ERROR}-PLATFORM-PATH")),
    _ => Err(format!("{CONTEXT_ERROR}-PLATFORM-PATH")),
  }
}

fn platform_path(path: &OdenRev2PlatformPath) -> Result<PathBuf, String> {
  match path {
    OdenRev2PlatformPath::Unicode(path) => Ok(PathBuf::from(path)),
    OdenRev2PlatformPath::Bytes(bytes) => {
      #[cfg(unix)]
      {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;
        Ok(PathBuf::from(OsString::from_vec(bytes.clone())))
      }
      #[cfg(not(unix))]
      {
        let _ = bytes;
        Err(format!("{CONTEXT_ERROR}-PLATFORM-PATH"))
      }
    }
  }
}

fn compile_object_identity(
  identity: ObjectIdentityWire,
) -> Result<OdenRev2PlatformObjectIdentity, String> {
  if identity.kind != "platform-object" || identity.value.trim().is_empty() {
    return Err(format!("{CONTEXT_ERROR}-OBJECT-IDENTITY"));
  }
  Ok(OdenRev2PlatformObjectIdentity {
    value: identity.value,
  })
}

fn validate_principal(principal: &PrincipalRef) -> Result<(), String> {
  if principal.key.trim().is_empty()
    || matches!(
      principal.kind,
      PrincipalKind::Runtime | PrincipalKind::NoUser
    )
  {
    return Err(format!("{CONTEXT_ERROR}-PRINCIPAL"));
  }
  Ok(())
}

fn require_nonempty(value: &str) -> Result<(), String> {
  if value.trim().is_empty() {
    Err(format!("{CONTEXT_ERROR}-EMPTY"))
  } else {
    Ok(())
  }
}

fn validate_digest(value: &str) -> Result<(), String> {
  let encoded = value
    .strip_prefix("sha256-")
    .ok_or_else(|| format!("{CONTEXT_ERROR}-DIGEST"))?;
  let decoded = URL_SAFE_NO_PAD
    .decode(encoded)
    .map_err(|_| format!("{CONTEXT_ERROR}-DIGEST"))?;
  if decoded.len() != 32 || URL_SAFE_NO_PAD.encode(decoded) != encoded {
    return Err(format!("{CONTEXT_ERROR}-DIGEST"));
  }
  Ok(())
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SnapshotWire {
  snapshot_schema: String,
  caps_vocab: String,
  vocab_digest: String,
  registry_digest: String,
  policy_digest: String,
  project_digest: String,
  armed_snapshot_digest: String,
  engine_target: String,
  engine_feature_set: String,
  execution_role: String,
  conformance_report_digest: Option<String>,
  effective_mode: Mode,
  run_nonce: String,
  channel_epoch: String,
  canonical_policy: CanonicalPolicyWire,
  root_bindings: Vec<RootBindingWire>,
  deny_ceiling: Vec<AuthorityRowWire>,
  executable_bindings: Vec<ExecutableBindingWire>,
  route_bindings: Vec<RouteBindingWire>,
  classifier_bindings: Vec<ClassifierBindingWire>,
  protected_predicate_versions: Vec<ProtectedPredicateVersionWire>,
  protected_receipt_bindings: Vec<ProtectedReceiptWire>,
  protected_receipt_set_digest: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CanonicalPolicyWire {
  policy_schema: String,
  caps_vocab: String,
  vocab_digest: String,
  policy_digest: String,
  mode: Mode,
  principals: Vec<PrincipalPolicyWire>,
  process_denials: Vec<AuthorityRowWire>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PrincipalPolicyWire {
  principal: PrincipalRef,
  binding: PrincipalBindingWire,
  floor: Vec<AuthorityRowWire>,
  escalation_ceiling: Vec<AuthorityRowWire>,
  denials: Vec<AuthorityRowWire>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PrincipalBindingWire {
  resolver_id: String,
  binding_digest: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AuthorityRowWire {
  source_id: String,
  selector: CanonicalAuthoritySelector,
  #[serde(default)]
  protected: Option<ProtectedWire>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProtectedWire {
  predicate_id: String,
  reason_digest: String,
  canonical_row_digest: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PlatformPathWire {
  encoding: String,
  value: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ObjectIdentityWire {
  kind: String,
  value: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RootBindingWire {
  source_id: String,
  logical_root: String,
  principal: Option<PrincipalRef>,
  root_binding_id: String,
  canonical_path: PlatformPathWire,
  object_identity: ObjectIdentityWire,
  binding_provenance_digest: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ExecutableBindingWire {
  source_id: String,
  role: String,
  canonical_content_identity: String,
  binding_id: String,
  principal: Option<PrincipalRef>,
  canonical_path: PlatformPathWire,
  object_identity: ObjectIdentityWire,
  provenance_digest: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RouteBindingWire {
  source_id: String,
  resource_digest: String,
  route_digest: String,
  route_id: String,
  route_kind: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ClassifierBindingWire {
  source_id: String,
  classifier_id: String,
  classifier_version: String,
  input_digest: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProtectedPredicateVersionWire {
  predicate_id: String,
  version: String,
}

#[allow(dead_code)]
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ProtectedReceiptWire {
  receipt_id: String,
  binding_digest: String,
  canonical_row_digest: String,
  predicate_id: String,
  principal: PrincipalRef,
  resource_digest: String,
  project_digest: String,
  issuer_id: String,
  issuer_generation: String,
  revocation_feed_id: String,
  receipt_negative_generation: String,
  expires_at: String,
  monotonic_deadline: String,
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::oden_rev2_policy::tests as policy_fixtures;
  use crate::rev2::EffectInput;
  use crate::rev2::Outcome;
  use crate::rev2::StageRequest;
  use std::collections::BTreeSet;
  #[cfg(unix)]
  use std::os::unix::fs::PermissionsExt;
  use std::path::Path;
  use std::sync::Mutex;
  use std::thread;

  fn digest(byte: u8) -> String {
    format!("sha256-{}", URL_SAFE_NO_PAD.encode([byte; 32]))
  }

  fn principal() -> PrincipalRef {
    PrincipalRef {
      kind: PrincipalKind::Package,
      key: "pkg:sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
    }
  }

  fn canonical_selector(
    principal: Option<PrincipalRef>,
    name: &str,
    polarity: SelectorPolarity,
  ) -> CanonicalAuthoritySelector {
    Rev2Core::embedded()
      .unwrap()
      .normalize_selector(
        &AuthoritySelectorInput {
          identity: EngineIdentity::embedded(),
          principal,
          capability: "env:read".to_string(),
          resource: serde_json::json!({ "name": name }),
        },
        polarity,
      )
      .unwrap()
  }

  fn env_snapshot_with_all_static_strata() -> Value {
    let mut snapshot = policy_fixtures::candidate_with_env_policy(
      policy_fixtures::hermetic_target(),
    );
    let principal = principal();
    snapshot["canonicalPolicy"]["principals"][0]["escalationCeiling"] = serde_json::json!([{
      "sourceId": "ceiling:env",
      "selector": canonical_selector(
        Some(principal.clone()),
        "TOKEN",
        SelectorPolarity::Positive,
      ),
    }]);
    snapshot["canonicalPolicy"]["principals"][0]["denials"] = serde_json::json!([{
      "sourceId": "denial:secret",
      "selector": canonical_selector(
        Some(principal),
        "SECRET",
        SelectorPolarity::Negative,
      ),
    }]);
    snapshot["canonicalPolicy"]["processDenials"] = serde_json::json!([{
      "sourceId": "process:other",
      "selector": canonical_selector(None, "OTHER", SelectorPolarity::Negative),
    }]);
    snapshot["denyCeiling"] = serde_json::json!([{
      "sourceId": "deny-ceiling:token",
      "selector": canonical_selector(None, "TOKEN", SelectorPolarity::Negative),
    }]);
    snapshot
  }

  fn armable_loaded(
    snapshot: Value,
    key: &[u8; 32],
  ) -> OdenRev2LoadedPolicyContext {
    let mut loaded =
      policy_fixtures::verify_armable_snapshot(snapshot, key).unwrap();
    loaded
      .install_immutable_executables(Path::new("."))
      .unwrap();
    loaded
  }

  fn install_for_test(
    loaded: OdenRev2LoadedPolicyContext,
  ) -> OdenRev2RuntimeAuthorityContext {
    OdenRev2RuntimeAuthorityContext::install_with(
      &RuntimeAuthorityInstaller::new(),
      loaded,
    )
    .unwrap()
  }

  fn empty_operation_facts() -> OdenRev2OperationAuthorityFacts {
    OdenRev2OperationAuthorityFacts::new(
      principal(),
      "terminal:test".to_string(),
    )
  }

  fn env_effect(name: &str) -> EffectInput {
    EffectInput {
      identity: EngineIdentity::embedded(),
      edge_id: "native-op:ext/os/lib.rs#op_get_env".to_string(),
      effect_slot_id: "native-op:ext/os/lib.rs#op_get_env:effect-slot:0"
        .to_string(),
      capability: "env:read".to_string(),
      effect_owner: "owner:pkg".to_string(),
      occurrence: serde_json::json!({
        "effectOwner": "owner:pkg",
        "name": name,
        "ownerGeneration": "0",
        "requiredForCommit": false,
        "targetKind": "broker",
      }),
    }
  }

  #[test]
  fn real_envelope_consumes_raw_snapshot_and_preserves_identity_sources_and_precedence()
   {
    let key = [41_u8; 32];
    let loaded = policy_fixtures::verify_armable_snapshot(
      env_snapshot_with_all_static_strata(),
      &key,
    )
    .unwrap();
    let weak_snapshot = loaded.snapshot_weak_for_test();
    let mut loaded = loaded;
    loaded
      .install_immutable_executables(Path::new("."))
      .unwrap();
    let context = install_for_test(loaded);
    assert!(weak_snapshot.upgrade().is_none());
    assert_eq!(context.identity().vocab_digest(), REV2_VOCAB_DIGEST);
    assert_eq!(context.identity().registry_digest(), REV2_REGISTRY_DIGEST);
    assert_eq!(context.identity().run_nonce(), "run:test");
    assert_eq!(context.identity().channel_epoch(), "channel:test");
    assert_eq!(context.mode(), Mode::Enforce);
    assert_eq!(context.execution_role(), OdenRev2ExecutionRole::Probe);

    let sources = context
      .static_policy()
      .principals()
      .iter()
      .flat_map(|principal| {
        principal
          .floor()
          .iter()
          .chain(principal.escalation_ceiling())
          .chain(principal.denials())
      })
      .chain(context.static_policy().process_denials())
      .chain(context.static_policy().deny_ceiling())
      .map(|row| row.source_id().to_string())
      .collect::<BTreeSet<_>>();
    assert_eq!(
      sources,
      BTreeSet::from([
        "ceiling:env".to_string(),
        "denial:secret".to_string(),
        "deny-ceiling:token".to_string(),
        "floor:env".to_string(),
        "process:other".to_string(),
      ])
    );

    let view = context.authority_state().read_view().unwrap();
    let policy = context
      .decision_policy_for_operation(&view, empty_operation_facts())
      .unwrap();
    assert_eq!(
      policy.provenance.policy_digest,
      context.identity().policy_digest()
    );
    assert_eq!(
      policy.provenance.armed_snapshot_digest,
      context.identity().armed_snapshot_digest()
    );
    assert_eq!(policy.generations.policy_snapshot, "1");
    assert_eq!(policy.generations.negative_overlay, "0");
    assert_eq!(policy.static_floor[0].source_id, "floor:env");
    assert_eq!(policy.process_denials.len(), 2);

    let decision = Rev2Core::embedded()
      .unwrap()
      .decide_stage(
        &StageRequest {
          identity: EngineIdentity::embedded(),
          stage_id: "stage:negative-before-positive".to_string(),
          principals: vec![principal()],
          effects: vec![env_effect("TOKEN")],
        },
        &policy,
      )
      .unwrap();
    assert_eq!(decision.outcome, Outcome::Deny);
  }

  #[test]
  fn generation_and_typed_mutable_selector_project_from_one_read_view() {
    let key = [43_u8; 32];
    let context = install_for_test(armable_loaded(
      policy_fixtures::candidate_snapshot(
        policy_fixtures::hermetic_target(),
        None,
      ),
      &key,
    ));
    let selector = canonical_selector(
      Some(principal()),
      "SESSION",
      SelectorPolarity::Positive,
    );
    let mut transaction =
      context.authority_state().begin_transaction().unwrap();
    transaction
      .upsert(
        AuthorityRowKind::SessionPositive,
        "session:exact".to_string(),
        &selector,
      )
      .unwrap();
    let view = context.authority_state().commit(transaction).unwrap();
    let projected = context
      .decision_policy_for_operation(&view, empty_operation_facts())
      .unwrap();
    assert_eq!(projected.generations.session_overlay, "1");
    assert_eq!(projected.session_grants[0].source_id, "session:exact");
    assert_eq!(
      projected.session_grants[0].selector.resource,
      selector.resource
    );

    let stale = context.authority_state().read_view().unwrap();
    let mut transaction =
      context.authority_state().begin_transaction().unwrap();
    let negative = canonical_selector(
      Some(principal()),
      "SESSION",
      SelectorPolarity::Negative,
    );
    transaction
      .upsert(
        AuthorityRowKind::SessionRevocation,
        "revoke:exact".to_string(),
        &negative,
      )
      .unwrap();
    context.authority_state().commit(transaction).unwrap();
    assert!(
      context
        .decision_policy_for_operation(&stale, empty_operation_facts())
        .is_err()
    );
  }

  #[test]
  fn unarmed_uninstalled_second_install_and_malformed_projection_refuse() {
    let key = [47_u8; 32];
    let unarmed = policy_fixtures::verified_unarmed_empty_context(&key);
    assert!(matches!(
      OdenRev2RuntimeAuthorityContext::install_with(
        &RuntimeAuthorityInstaller::new(),
        unarmed,
      ),
      Err(reason) if reason == "OD-CAP-REV2-RUNTIME-CONTEXT-NOT-ARMABLE"
    ));

    let armable = policy_fixtures::verify_armable_snapshot(
      policy_fixtures::candidate_snapshot(
        policy_fixtures::hermetic_target(),
        None,
      ),
      &key,
    )
    .unwrap();
    assert!(matches!(
      OdenRev2RuntimeAuthorityContext::install_with(
        &RuntimeAuthorityInstaller::new(),
        armable,
      ),
      Err(reason) if reason == "OD-CAP-REV2-RUNTIME-CONTEXT-EXECUTABLES-UNINSTALLED"
    ));

    let installer = RuntimeAuthorityInstaller::new();
    let first = armable_loaded(
      policy_fixtures::candidate_snapshot(
        policy_fixtures::hermetic_target(),
        None,
      ),
      &[49_u8; 32],
    );
    OdenRev2RuntimeAuthorityContext::install_with(&installer, first).unwrap();
    let second = armable_loaded(
      policy_fixtures::candidate_snapshot(
        policy_fixtures::hermetic_target(),
        None,
      ),
      &[51_u8; 32],
    );
    assert!(matches!(
      OdenRev2RuntimeAuthorityContext::install_with(&installer, second),
      Err(reason) if reason == "OD-CAP-REV2-RUNTIME-CONTEXT-ALREADY-INSTALLED"
    ));

    let context = install_for_test(armable_loaded(
      policy_fixtures::candidate_snapshot(
        policy_fixtures::hermetic_target(),
        None,
      ),
      &[53_u8; 32],
    ));
    let view = context.authority_state().read_view().unwrap();
    let malformed =
      OdenRev2OperationAuthorityFacts::new(principal(), String::new());
    assert!(
      context
        .decision_policy_for_operation(&view, malformed)
        .is_err()
    );
  }

  #[test]
  fn permission_batch_sequence_is_monotonic_concurrent_and_terminal_at_exhaustion()
   {
    let context = Arc::new(install_for_test(armable_loaded(
      policy_fixtures::candidate_snapshot(
        policy_fixtures::hermetic_target(),
        None,
      ),
      &[59_u8; 32],
    )));
    assert_eq!(
      context
        .next_permission_batch_sequence()
        .unwrap()
        .into_value(),
      1
    );
    assert_eq!(
      context
        .next_permission_batch_sequence()
        .unwrap()
        .into_value(),
      2
    );

    let observed = Arc::new(Mutex::new(Vec::new()));
    let workers = (0..8)
      .map(|_| {
        let context = context.clone();
        let observed = observed.clone();
        thread::spawn(move || {
          let values = (0..128)
            .map(|_| {
              context
                .next_permission_batch_sequence()
                .unwrap()
                .into_value()
            })
            .collect::<Vec<_>>();
          observed.lock().unwrap().extend(values);
        })
      })
      .collect::<Vec<_>>();
    for worker in workers {
      worker.join().unwrap();
    }
    let mut observed = observed.lock().unwrap().clone();
    observed.sort_unstable();
    assert_eq!(observed, (3..(3 + 8 * 128)).collect::<Vec<_>>());

    context
      .permission_batch_sequence
      .store(u64::MAX - 1, Ordering::Release);
    assert_eq!(
      context
        .next_permission_batch_sequence()
        .unwrap()
        .into_value(),
      u64::MAX - 1
    );
    assert!(context.next_permission_batch_sequence().is_err());
    assert!(context.next_permission_batch_sequence().is_err());
  }

  #[test]
  fn complete_validated_receipt_survives_typed_conversion_but_projection_refuses_without_runtime_freshness()
   {
    let selector = canonical_selector(
      Some(principal()),
      "TOKEN",
      SelectorPolarity::Positive,
    );
    let row_digest = digest(61);
    let reason_digest = digest(62);
    let project_digest = digest(63);
    let resource_digest =
      domain_digest("oden:capsec:protected-resource:2", &selector.resource)
        .unwrap();
    let policy = OdenRev2StaticPolicy {
      principals: vec![OdenRev2PrincipalPolicy {
        principal: principal(),
        resolver_id: "resolver:test".to_string(),
        binding_digest: digest(64),
        floor: vec![OdenRev2StaticAuthorityRow {
          source_id: "floor:protected".to_string(),
          selector,
          protected: Some(OdenRev2ProtectedException {
            predicate_id: "predicate.protected-receipt/2".to_string(),
            reason_digest,
            canonical_row_digest: row_digest.clone(),
          }),
        }]
        .into(),
        escalation_ceiling: Arc::from([]),
        denials: Arc::from([]),
      }]
      .into(),
      process_denials: Arc::from([]),
      deny_ceiling: Arc::from([]),
      validated_protected_receipts: Arc::from([]),
      validated_receipt_row_digests: Arc::from([]),
    };
    let receipt = ProtectedReceiptWire {
      receipt_id: "receipt:test".to_string(),
      binding_digest: digest(65),
      canonical_row_digest: row_digest,
      predicate_id: "predicate.protected-receipt/2".to_string(),
      principal: principal(),
      resource_digest,
      project_digest: project_digest.clone(),
      issuer_id: "issuer:test".to_string(),
      issuer_generation: "7".to_string(),
      revocation_feed_id: "feed:test".to_string(),
      receipt_negative_generation: "11".to_string(),
      expires_at: "2099-01-01T00:00:00.000Z".to_string(),
      monotonic_deadline: "13".to_string(),
    };
    let receipts =
      compile_validated_receipts(vec![receipt], &project_digest, &policy)
        .unwrap();
    let receipt = &receipts[0];
    assert_eq!(receipt.receipt_id(), "receipt:test");
    assert_eq!(receipt.issuer_generation(), "7");
    assert_eq!(receipt.revocation_feed_id(), "feed:test");
    assert_eq!(receipt.receipt_negative_generation(), "11");
    assert_eq!(receipt.monotonic_deadline(), "13");
    assert_eq!(receipt.project_digest(), project_digest);

    let retained_row_digest = receipt.canonical_row_digest().to_string();
    let mut context = install_for_test(armable_loaded(
      policy_fixtures::candidate_snapshot(
        policy_fixtures::hermetic_target(),
        None,
      ),
      &[69_u8; 32],
    ));
    context.static_policy.validated_protected_receipts = receipts.into();
    context.static_policy.validated_receipt_row_digests =
      vec![retained_row_digest].into();
    let view = context.authority_state().read_view().unwrap();
    assert!(matches!(
      context.decision_policy_for_operation(&view, empty_operation_facts()),
      Err(reason)
        if reason
          == "OD-CAP-REV2-RUNTIME-CONTEXT-RECEIPT-RUNTIME-UNINSTALLED"
    ));
  }

  #[cfg(unix)]
  #[test]
  fn real_root_envelope_preserves_complete_typed_binding_and_retained_object() {
    let unique = std::time::SystemTime::now()
      .duration_since(std::time::UNIX_EPOCH)
      .unwrap()
      .as_nanos();
    let raw = std::env::temp_dir().join(format!(
      "oden-rev2-context-root-{}-{unique}",
      std::process::id()
    ));
    std::fs::create_dir(&raw).unwrap();
    let root = std::fs::canonicalize(&raw).unwrap();
    let selector = Rev2Core::embedded()
      .unwrap()
      .normalize_selector(
        &AuthoritySelectorInput {
          identity: EngineIdentity::embedded(),
          principal: Some(principal()),
          capability: "fs:read".to_string(),
          resource: serde_json::json!({
            "kind": "path-tree",
            "path": { "encoding": "unicode", "value": "data" },
            "root": "$PROJECT",
          }),
        },
        SelectorPolarity::Positive,
      )
      .unwrap();
    let mut snapshot = policy_fixtures::candidate_snapshot(
      policy_fixtures::hermetic_target(),
      None,
    );
    snapshot["canonicalPolicy"]["principals"] = serde_json::json!([{
      "principal": principal(),
      "binding": {
        "resolverId": "fixture-lock-resolver/2",
        "bindingDigest": REV2_VOCAB_DIGEST,
      },
      "floor": [{ "sourceId": "floor:path", "selector": selector }],
      "escalationCeiling": [],
      "denials": [],
    }]);
    snapshot["rootBindings"] = serde_json::json!([{
      "sourceId": "floor:path",
      "logicalRoot": "$PROJECT",
      "principal": principal(),
      "rootBindingId": "root-binding:project",
      "canonicalPath": {
        "encoding": "unicode",
        "value": root.to_str().unwrap(),
      },
      "objectIdentity": policy_fixtures::platform_identity(&root),
      "bindingProvenanceDigest": REV2_REGISTRY_DIGEST,
    }]);
    policy_fixtures::refresh_digests(&mut snapshot);
    let context = install_for_test(armable_loaded(snapshot, &[66_u8; 32]));
    let binding = &context.bindings().roots()[0];
    assert_eq!(binding.source_id(), "floor:path");
    assert_eq!(binding.logical_root(), "$PROJECT");
    assert_eq!(binding.principal(), Some(&principal()));
    assert_eq!(binding.binding_id(), "root-binding:project");
    assert_eq!(
      binding.canonical_path(),
      &OdenRev2PlatformPath::Unicode(root.to_str().unwrap().to_string())
    );
    assert_eq!(
      binding.object_identity().value(),
      context.retained_objects()[0].object_identity()
    );
    assert_eq!(binding.binding_provenance_digest(), REV2_REGISTRY_DIGEST);
    assert_eq!(context.retained_objects().len(), 1);
    drop(context);
    std::fs::remove_dir_all(raw).unwrap();
  }

  #[cfg(unix)]
  #[test]
  fn real_executable_envelope_retains_immutable_installed_images() {
    let unique = std::time::SystemTime::now()
      .duration_since(std::time::UNIX_EPOCH)
      .unwrap()
      .as_nanos();
    let raw = std::env::temp_dir().join(format!(
      "oden-rev2-context-exec-{}-{unique}",
      std::process::id()
    ));
    std::fs::create_dir(&raw).unwrap();
    std::fs::set_permissions(&raw, std::fs::Permissions::from_mode(0o700))
      .unwrap();
    // Production canonicalizes the authenticated control root before C04
    // installation. Mirror that here so macOS's `/var` compatibility symlink
    // does not intentionally trip the all-components no-follow open.
    let raw = std::fs::canonicalize(raw).unwrap();
    let object = raw.join("worker.js");
    let interpreter = raw.join("interpreter");
    std::fs::write(&object, b"console.log('context');\n").unwrap();
    std::fs::write(&interpreter, b"context interpreter\n").unwrap();
    let object = std::fs::canonicalize(object).unwrap();
    let interpreter = std::fs::canonicalize(interpreter).unwrap();
    let snapshot = policy_fixtures::candidate_with_executable_policy(
      policy_fixtures::hermetic_target(),
      &object,
      &interpreter,
    );
    let mut loaded =
      policy_fixtures::verify_armable_snapshot(snapshot, &[67_u8; 32]).unwrap();
    loaded.install_immutable_executables(&raw).unwrap();
    let context = install_for_test(loaded);
    assert_eq!(context.bindings().executables().len(), 2);
    let installed = context
      .installed_executables()
      .by_binding_id("executable:object")
      .unwrap();
    assert_eq!(installed.source_id(), "floor:spawn");
    assert!(installed.byte_len() > 0);
    assert!(!installed.image().platform_kind().is_empty());
    assert_eq!(context.retained_objects().len(), 2);
    drop(context);
    std::fs::remove_dir_all(raw).unwrap();
  }

  #[cfg(unix)]
  #[test]
  fn failed_executable_install_cannot_satisfy_runtime_context() {
    let unique = std::time::SystemTime::now()
      .duration_since(std::time::UNIX_EPOCH)
      .unwrap()
      .as_nanos();
    let raw = std::env::temp_dir().join(format!(
      "oden-rev2-context-failed-exec-{}-{unique}",
      std::process::id()
    ));
    std::fs::create_dir(&raw).unwrap();
    std::fs::set_permissions(&raw, std::fs::Permissions::from_mode(0o700))
      .unwrap();
    let object = raw.join("worker.js");
    let interpreter = raw.join("interpreter");
    std::fs::write(&object, b"console.log('verified');\n").unwrap();
    std::fs::write(&interpreter, b"verified interpreter\n").unwrap();
    let object = std::fs::canonicalize(object).unwrap();
    let interpreter = std::fs::canonicalize(interpreter).unwrap();
    let snapshot = policy_fixtures::candidate_with_executable_policy(
      policy_fixtures::hermetic_target(),
      &object,
      &interpreter,
    );
    let mut loaded =
      policy_fixtures::verify_armable_snapshot(snapshot, &[71_u8; 32]).unwrap();
    std::fs::write(&object, b"console.log('changed after verify');\n").unwrap();
    assert!(loaded.install_immutable_executables(&raw).is_err());
    assert!(matches!(
      OdenRev2RuntimeAuthorityContext::install_with(
        &RuntimeAuthorityInstaller::new(),
        loaded,
      ),
      Err(reason)
        if reason
          == "OD-CAP-REV2-RUNTIME-CONTEXT-EXECUTABLES-UNINSTALLED"
    ));
    std::fs::remove_dir_all(raw).unwrap();
  }
}

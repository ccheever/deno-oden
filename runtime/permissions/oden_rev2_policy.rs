//! Authenticated, immutable Rev2 policy-snapshot verification.
//!
//! This module verifies the parent-produced armed-snapshot candidate before V8.
//! It does not translate runtime permission descriptors or install operation
//! actors; those protocol bindings belong to LLP 0019/C04.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hmac::Hmac;
use hmac::Mac;
use serde_json::Map;
use serde_json::Value;
use sha2::Digest;
use sha2::Sha256;
use std::collections::HashMap;
use std::collections::HashSet;
use std::fs::File;
use std::path::PathBuf;
use std::sync::Arc;

use crate::oden_rev2_executable::OdenRev2InstalledExecutableContext;
use crate::rev2::AuthoritySelectorInput;
use crate::rev2::CanonicalAuthoritySelector;
use crate::rev2::EngineIdentity;
use crate::rev2::PrincipalKind;
use crate::rev2::PrincipalRef;
use crate::rev2::Rev2Core;
use crate::rev2::SelectorPolarity;
use crate::rev2::canonical_json;
use crate::rev2::domain_digest;
use crate::rev2::parse_strict_json;
use crate::rev2_registry_generated::REV2_ADVERTISED_TARGETS;
use crate::rev2_registry_generated::REV2_PROFILE;
use crate::rev2_registry_generated::REV2_REGISTRY_DIGEST;
use crate::rev2_registry_generated::REV2_RUNTIME_SEMANTIC_PAYLOAD_JSON;
use crate::rev2_registry_generated::REV2_TARGET_STATUS;
use crate::rev2_registry_generated::REV2_VOCAB_DIGEST;

const ENVELOPE_SCHEMA: &str = "oden/capsec-armed-envelope/2";
const SNAPSHOT_SCHEMA: &str = "oden/capsec-armed-snapshot/2";
const POLICY_SCHEMA: &str = "oden/capsec-policy/2";
const ENVELOPE_AUTH_DOMAIN: &str = "oden:capsec:armed-envelope:2";
const RECEIPT_SET_DOMAIN: &str = "oden:capsec:protected-receipt-set:2";
const PROTECTED_RESOURCE_DOMAIN: &str = "oden:capsec:protected-resource:2";
const ROUTE_RESOURCE_DOMAIN: &str = "oden:capsec:route-resource:2";
const ROUTE_SELECTOR_DOMAIN: &str = "oden:capsec:route-selector:2";
const CLASSIFIER_INPUT_DOMAIN: &str = "oden:capsec:classifier-input:2";
const MAX_ENVELOPE_BYTES: usize = 8 * 1024 * 1024;
const MAX_BINDING_ROWS: usize = 16_384;

pub(crate) const C04_SCRIPT_LAUNCH_UNSUPPORTED: &str =
  "OD-CAP-REV2-RUNTIME-CONTEXT-SCRIPT-LAUNCH-UNSUPPORTED";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OdenRev2CompiledBuildIdentity {
  pub target: &'static str,
  pub rust_toolchain: &'static str,
  pub cargo_features: &'static str,
  pub rust_cfg_digest: &'static str,
  pub cargo_feature_graph_digest: &'static str,
  pub build_profile: &'static str,
  pub marker_panic_strategy: &'static str,
  pub marker_debug_assertions: &'static str,
  pub actual_panic_strategy: &'static str,
  pub actual_debug_assertions: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum OdenRev2LoadState {
  Armable,
  VerifiedUnarmed,
}

#[derive(Clone, Debug)]
pub struct OdenRev2RetainedObject {
  binding_id: String,
  source_id: String,
  role: Option<String>,
  principal: Option<PrincipalRef>,
  canonical_path: PathBuf,
  object_identity: String,
  canonical_content_identity: Option<String>,
  provenance_digest: Option<String>,
  file: Arc<File>,
}

impl OdenRev2RetainedObject {
  pub fn binding_id(&self) -> &str {
    &self.binding_id
  }

  pub fn source_id(&self) -> &str {
    &self.source_id
  }

  pub fn role(&self) -> Option<&str> {
    self.role.as_deref()
  }

  pub fn file(&self) -> &File {
    &self.file
  }

  pub(crate) fn principal(&self) -> Option<&PrincipalRef> {
    self.principal.as_ref()
  }

  pub(crate) fn canonical_path(&self) -> &std::path::Path {
    &self.canonical_path
  }

  pub(crate) fn object_identity(&self) -> &str {
    &self.object_identity
  }

  pub(crate) fn canonical_content_identity(&self) -> Option<&str> {
    self.canonical_content_identity.as_deref()
  }

  pub(crate) fn provenance_digest(&self) -> Option<&str> {
    self.provenance_digest.as_deref()
  }

  pub(crate) fn candidate_file_strong_count(&self) -> usize {
    Arc::strong_count(&self.file)
  }

  pub(crate) fn candidate_file_weak(&self) -> std::sync::Weak<File> {
    Arc::downgrade(&self.file)
  }

  #[cfg(test)]
  pub(crate) fn executable_for_test(
    binding_id: impl Into<String>,
    source_id: impl Into<String>,
    role: impl Into<String>,
    canonical_content_identity: impl Into<String>,
    provenance_digest: impl Into<String>,
    canonical_path: PathBuf,
    file: File,
  ) -> Self {
    Self {
      binding_id: binding_id.into(),
      source_id: source_id.into(),
      role: Some(role.into()),
      principal: None,
      canonical_path,
      object_identity: "unix-dev-ino:00000000000000000000000000000000"
        .to_string(),
      canonical_content_identity: Some(canonical_content_identity.into()),
      provenance_digest: Some(provenance_digest.into()),
      file: Arc::new(file),
    }
  }
}

#[derive(Debug)]
pub struct OdenRev2LoadedPolicyContext {
  state: OdenRev2LoadState,
  target: String,
  feature_set: String,
  policy_digest: String,
  project_digest: String,
  armed_snapshot_digest: String,
  conformance_report_digest: Option<String>,
  execution_role: String,
  run_nonce: String,
  channel_epoch: String,
  conformant: bool,
  advertised: bool,
  blockers: Arc<[String]>,
  retained_objects: Arc<[OdenRev2RetainedObject]>,
  installed_executables: OdenRev2InstalledExecutableContext,
  snapshot: Arc<Value>,
}

pub(crate) struct OdenRev2LoadedPolicyParts {
  pub(crate) target: String,
  pub(crate) feature_set: String,
  pub(crate) policy_digest: String,
  pub(crate) project_digest: String,
  pub(crate) armed_snapshot_digest: String,
  pub(crate) execution_role: String,
  pub(crate) run_nonce: String,
  pub(crate) channel_epoch: String,
  pub(crate) retained_objects: Arc<[OdenRev2RetainedObject]>,
  pub(crate) installed_executables: OdenRev2InstalledExecutableContext,
  pub(crate) snapshot: Value,
}

fn candidate_runtime_snapshot_closed(snapshot: &Value) -> bool {
  let empty = |field| {
    snapshot
      .get(field)
      .and_then(Value::as_array)
      .is_some_and(Vec::is_empty)
  };
  let Some([_root]) = snapshot
    .get("rootBindings")
    .and_then(Value::as_array)
    .map(Vec::as_slice)
  else {
    return false;
  };
  let Some(policy) = snapshot.get("canonicalPolicy") else {
    return false;
  };
  let Some([principal]) = policy
    .get("principals")
    .and_then(Value::as_array)
    .map(Vec::as_slice)
  else {
    return false;
  };
  let one_floor = principal
    .get("floor")
    .and_then(Value::as_array)
    .is_some_and(|rows| rows.len() == 1);
  let empty_principal = |field| {
    principal
      .get(field)
      .and_then(Value::as_array)
      .is_some_and(Vec::is_empty)
  };
  snapshot.get("effectiveMode").and_then(Value::as_str) == Some("enforce")
    && policy.get("mode").and_then(Value::as_str) == Some("enforce")
    && policy
      .get("processDenials")
      .and_then(Value::as_array)
      .is_some_and(Vec::is_empty)
    && one_floor
    && empty_principal("escalationCeiling")
    && empty_principal("denials")
    && empty("denyCeiling")
    && empty("executableBindings")
    && empty("routeBindings")
    && empty("classifierBindings")
    && empty("protectedPredicateVersions")
    && empty("protectedReceiptBindings")
}

impl OdenRev2LoadedPolicyContext {
  pub fn state(&self) -> OdenRev2LoadState {
    self.state.clone()
  }

  pub fn target(&self) -> &str {
    &self.target
  }

  pub fn feature_set(&self) -> &str {
    &self.feature_set
  }

  pub fn policy_digest(&self) -> &str {
    &self.policy_digest
  }

  pub fn project_digest(&self) -> &str {
    &self.project_digest
  }

  pub fn armed_snapshot_digest(&self) -> &str {
    &self.armed_snapshot_digest
  }

  pub fn run_nonce(&self) -> &str {
    &self.run_nonce
  }

  pub fn execution_role(&self) -> &str {
    &self.execution_role
  }

  pub fn channel_epoch(&self) -> &str {
    &self.channel_epoch
  }

  pub fn blockers(&self) -> &[String] {
    &self.blockers
  }

  pub fn retained_objects(&self) -> &[OdenRev2RetainedObject] {
    &self.retained_objects
  }

  #[allow(
    dead_code,
    reason = "the first C04 slice installs images before the subsequent runtime protocol consumes them"
  )]
  pub(crate) fn installed_executables(
    &self,
  ) -> &OdenRev2InstalledExecutableContext {
    &self.installed_executables
  }

  pub(crate) fn install_immutable_executables(
    &mut self,
    control_root: &std::path::Path,
  ) -> Result<(), String> {
    self
      .installed_executables
      .install_once(&self.retained_objects, control_root)
  }

  /// Refuse a C03-authenticated execution shape that the initial C04 run
  /// adapter cannot represent without inventing a logical interpreter path.
  ///
  /// C03 deliberately authenticates and retains both images for a script.
  /// The initial C04 permission projection, however, has only the logical
  /// entry path needed by the generated `launchSet`; it has no authenticated
  /// logical interpreter path. Distinct object/interpreter identities are
  /// therefore refused before the process-wide runtime context is published.
  pub(crate) fn validate_c04_execution_support(&self) -> Result<(), String> {
    if self.state != OdenRev2LoadState::Armable {
      return Ok(());
    }
    let principals = self
      .snapshot
      .get("canonicalPolicy")
      .and_then(Value::as_object)
      .and_then(|policy| policy.get("principals"))
      .and_then(Value::as_array)
      .ok_or_else(|| {
        "OD-CAP-REV2-RUNTIME-CONTEXT-EXECUTION-POLICY-SHAPE".to_string()
      })?;
    for principal in principals {
      let floor = principal
        .get("floor")
        .and_then(Value::as_array)
        .ok_or_else(|| {
          "OD-CAP-REV2-RUNTIME-CONTEXT-EXECUTION-POLICY-SHAPE".to_string()
        })?;
      for row in floor {
        let Some(selector) = row.get("selector") else {
          return Err(
            "OD-CAP-REV2-RUNTIME-CONTEXT-EXECUTION-POLICY-SHAPE".to_string(),
          );
        };
        if selector.get("capability").and_then(Value::as_str)
          != Some("process:spawn")
        {
          continue;
        }
        let resource = selector
          .get("resource")
          .and_then(Value::as_object)
          .ok_or_else(|| {
            "OD-CAP-REV2-RUNTIME-CONTEXT-EXECUTION-POLICY-SHAPE".to_string()
          })?;
        let object_identity =
          resource.get("objectIdentity").ok_or_else(|| {
            "OD-CAP-REV2-RUNTIME-CONTEXT-EXECUTION-POLICY-SHAPE".to_string()
          })?;
        let interpreter_identity =
          resource.get("interpreterIdentity").ok_or_else(|| {
            "OD-CAP-REV2-RUNTIME-CONTEXT-EXECUTION-POLICY-SHAPE".to_string()
          })?;
        if object_identity != interpreter_identity {
          return Err(C04_SCRIPT_LAUNCH_UNSUPPORTED.to_string());
        }
      }
    }
    Ok(())
  }

  pub(crate) fn into_runtime_parts(
    self,
  ) -> Result<OdenRev2LoadedPolicyParts, String> {
    if self.state != OdenRev2LoadState::Armable {
      return Err("OD-CAP-REV2-RUNTIME-CONTEXT-NOT-ARMABLE".to_string());
    }
    if !self.installed_executables.is_installed() {
      return Err(
        "OD-CAP-REV2-RUNTIME-CONTEXT-EXECUTABLES-UNINSTALLED".to_string(),
      );
    }
    self.into_parts()
  }

  pub(crate) fn into_candidate_runtime_parts(
    self,
  ) -> Result<OdenRev2LoadedPolicyParts, String> {
    if self.state != OdenRev2LoadState::VerifiedUnarmed
      || self.execution_role != "candidate"
      || self.conformant
      || self.advertised
      || self.conformance_report_digest.is_some()
      || self.installed_executables.is_installed()
      || self.retained_objects.len() != 1
      || self.retained_objects[0].role().is_some()
      || !candidate_runtime_snapshot_closed(&self.snapshot)
    {
      return Err("OD-CAP-REV2-RUNTIME-CONTEXT-CANDIDATE-BOUNDARY".to_string());
    }
    self.into_parts()
  }

  fn into_parts(self) -> Result<OdenRev2LoadedPolicyParts, String> {
    let snapshot = Arc::try_unwrap(self.snapshot)
      .map_err(|_| "OD-CAP-REV2-RUNTIME-CONTEXT-SNAPSHOT-SHARED".to_string())?;
    Ok(OdenRev2LoadedPolicyParts {
      target: self.target,
      feature_set: self.feature_set,
      policy_digest: self.policy_digest,
      project_digest: self.project_digest,
      armed_snapshot_digest: self.armed_snapshot_digest,
      execution_role: self.execution_role,
      run_nonce: self.run_nonce,
      channel_epoch: self.channel_epoch,
      retained_objects: self.retained_objects,
      installed_executables: self.installed_executables,
      snapshot,
    })
  }

  #[cfg(test)]
  pub(crate) fn snapshot_weak_for_test(&self) -> std::sync::Weak<Value> {
    Arc::downgrade(&self.snapshot)
  }

  pub fn evidence(&self) -> Value {
    let mut evidence_blockers = self.blockers.to_vec();
    if self.state == OdenRev2LoadState::Armable {
      evidence_blockers.push("runtime-protocol-not-installed".to_string());
    }
    evidence_blockers.sort_unstable();
    evidence_blockers.dedup();
    serde_json::json!({
      "v": 1,
      "event": "rev2_loaded_context",
      "profile": REV2_PROFILE,
      "vocabDigest": REV2_VOCAB_DIGEST,
      "registryDigest": REV2_REGISTRY_DIGEST,
      "policyDigest": self.policy_digest,
      "projectDigest": self.project_digest,
      "armedSnapshotDigest": self.armed_snapshot_digest,
      "loadedArmedSnapshotDigest": self.armed_snapshot_digest,
      "conformanceReportDigest": self.conformance_report_digest,
      "executionRole": self.execution_role,
      "engineTarget": self.target,
      "engineFeatureSet": self.feature_set,
      "runNonce": self.run_nonce,
      "channelEpoch": self.channel_epoch,
      "configured": true,
      "decisionStage": "bootstrap",
      "verified": true,
      "armable": self.state == OdenRev2LoadState::Armable,
      // C04 installs the typed runtime protocol. Artifact verification alone
      // must never be presented as an actually armed execution context.
      "armed": false,
      "conformant": self.conformant,
      "advertised": self.advertised,
      "blockers": evidence_blockers,
    })
  }
}

#[derive(Clone, Copy)]
pub(crate) struct TargetStatus<'a> {
  target: &'a str,
  feature_set: &'a str,
  profile_claim: &'a str,
  conformance_report_digest: Option<&'a str>,
  enforced: usize,
  closed: usize,
  absent: usize,
  unsupported: usize,
  advertised: bool,
  hermetic: bool,
}

#[derive(Clone)]
struct CanonicalRowFact {
  source_id: String,
  principal: Option<PrincipalRef>,
  projection_id: String,
  resource: Value,
  protected: Option<ProtectedRowFact>,
}

#[derive(Clone)]
struct ProtectedRowFact {
  predicate_id: String,
  predicate_version: String,
  canonical_row_digest: String,
}

struct PolicyFacts {
  rows: Vec<CanonicalRowFact>,
  protected_by_digest: HashMap<String, CanonicalRowFact>,
  source_ids: HashSet<String>,
}

pub fn verify_authenticated_envelope(
  bytes: &[u8],
  one_shot_key: &[u8],
  build_identity: &OdenRev2CompiledBuildIdentity,
) -> Result<OdenRev2LoadedPolicyContext, String> {
  let snapshot = parse_authenticated_snapshot(bytes, one_shot_key)?;
  let target = snapshot
    .get("engineTarget")
    .and_then(Value::as_str)
    .ok_or_else(|| "OD-CAP-REV2-TARGET-MISSING".to_string())?;
  if Some(target) != compiled_target() {
    return Err("OD-CAP-REV2-TARGET-BINARY-MISMATCH".to_string());
  }
  if Some(build_identity.target) != compiled_target() {
    return Err("OD-CAP-REV2-FEATURE-BINARY-MISMATCH".to_string());
  }
  let embedded = REV2_TARGET_STATUS
    .iter()
    .find(|status| status.target == target)
    .ok_or_else(|| "OD-CAP-REV2-TARGET-UNKNOWN".to_string())?;
  validate_compiled_build_identity(embedded, build_identity)?;
  verify_snapshot(
    &snapshot,
    TargetStatus {
      target: embedded.target,
      feature_set: embedded.feature_set,
      profile_claim: embedded.profile_claim,
      // A production report is a separately generated, release-bound input;
      // none is embedded while every candidate target remains unsupported.
      conformance_report_digest: None,
      enforced: embedded.enforced,
      closed: embedded.closed,
      absent: embedded.absent,
      unsupported: embedded.unsupported,
      advertised: REV2_ADVERTISED_TARGETS.contains(&embedded.target),
      hermetic: false,
    },
  )
}

struct CandidateDescriptorSnapshotRoot {
  synthetic_path: PathBuf,
  file: File,
}

/// Verify the same closed Candidate snapshot while sourcing its sole root
/// binding from an already-retained descriptor. The synthetic path is used
/// only by the internal lexical selector; this verifier never opens it.
///
/// @ref LLP 0019#pre-promotion-conformance-candidate-execution
/// [constrained-by] -- Descriptor authentication is confined to the sealed,
/// production-uncalled lstat Candidate. It does not authenticate a repository
/// path, image, fixture execution, or release fact.
pub(crate) fn verify_unarmed_descriptor_candidate_snapshot(
  snapshot: &Value,
  synthetic_path: PathBuf,
  file: File,
) -> Result<OdenRev2LoadedPolicyContext, String> {
  let compiled = compiled_target()
    .ok_or_else(|| "OD-CAP-REV2-TARGET-UNKNOWN".to_string())?;
  let embedded = REV2_TARGET_STATUS
    .iter()
    .find(|status| status.target == compiled)
    .ok_or_else(|| "OD-CAP-REV2-TARGET-UNKNOWN".to_string())?;
  let loaded = verify_snapshot_with_candidate_root(
    snapshot,
    TargetStatus {
      target: embedded.target,
      feature_set: embedded.feature_set,
      profile_claim: embedded.profile_claim,
      conformance_report_digest: None,
      enforced: embedded.enforced,
      closed: embedded.closed,
      absent: embedded.absent,
      unsupported: embedded.unsupported,
      advertised: REV2_ADVERTISED_TARGETS.contains(&embedded.target),
      hermetic: false,
    },
    Some(CandidateDescriptorSnapshotRoot {
      synthetic_path,
      file,
    }),
  )?;
  if loaded.state != OdenRev2LoadState::VerifiedUnarmed
    || loaded.execution_role != "candidate"
    || loaded.conformant
    || loaded.advertised
    || loaded.conformance_report_digest.is_some()
  {
    return Err("OD-CAP-REV2-CANDIDATE-SNAPSHOT-ARMABLE".to_string());
  }
  Ok(loaded)
}

fn parse_authenticated_snapshot(
  bytes: &[u8],
  one_shot_key: &[u8],
) -> Result<Value, String> {
  if bytes.is_empty() || bytes.len() > MAX_ENVELOPE_BYTES {
    return Err("OD-CAP-REV2-ENVELOPE-BOUNDS".to_string());
  }
  if one_shot_key.len() != 32 {
    return Err("OD-CAP-REV2-AUTH-KEY".to_string());
  }
  let text = std::str::from_utf8(bytes)
    .map_err(|_| "OD-CAP-REV2-ENVELOPE-UTF8".to_string())?;
  let envelope = parse_strict_json(text)
    .map_err(|_| "OD-CAP-REV2-ENVELOPE-JSON".to_string())?;
  let envelope = exact_object(
    &envelope,
    &["mac", "schema", "snapshot"],
    "OD-CAP-REV2-ENVELOPE-SHAPE",
  )?;
  require_string(envelope, "schema", ENVELOPE_SCHEMA)?;
  let snapshot = envelope
    .get("snapshot")
    .ok_or_else(|| "OD-CAP-REV2-SNAPSHOT-MISSING".to_string())?;
  let mac = exact_object(
    envelope
      .get("mac")
      .ok_or_else(|| "OD-CAP-REV2-AUTH-MISSING".to_string())?,
    &["algorithm", "keyId", "tag"],
    "OD-CAP-REV2-AUTH-SHAPE",
  )?;
  require_string(mac, "algorithm", "hmac-sha256")?;
  verify_mac(snapshot, mac, one_shot_key)?;
  Ok(snapshot.clone())
}

pub(crate) fn validate_compiled_build_identity(
  expected: &crate::rev2_registry_generated::Rev2TargetStatus,
  actual: &OdenRev2CompiledBuildIdentity,
) -> Result<(), String> {
  if actual.target != expected.target
    || actual.rust_toolchain != expected.rust_toolchain
    || actual.cargo_features != expected.cargo_features
    || actual.rust_cfg_digest != expected.rust_cfg_digest
    || actual.cargo_feature_graph_digest != expected.cargo_feature_graph_digest
    || actual.build_profile != expected.build_profile
    || actual.actual_panic_strategy != actual.marker_panic_strategy
    || match actual.marker_debug_assertions {
      "true" => !actual.actual_debug_assertions,
      "false" => actual.actual_debug_assertions,
      _ => true,
    }
  {
    return Err("OD-CAP-REV2-FEATURE-BINARY-MISMATCH".to_string());
  }
  Ok(())
}

fn validate_compiled_build_identity_against_native_facts(
  expected: &crate::rev2_registry_generated::Rev2TargetStatus,
  actual: &OdenRev2CompiledBuildIdentity,
  native_target: &str,
  native_panic_strategy: &str,
  native_debug_assertions: bool,
) -> Result<(), String> {
  validate_compiled_build_identity(expected, actual)?;
  if actual.target != native_target
    || actual.actual_panic_strategy != native_panic_strategy
    || actual.actual_debug_assertions != native_debug_assertions
    || actual.marker_panic_strategy != "abort"
    || actual.marker_debug_assertions != "false"
    || actual.build_profile != "release"
  {
    return Err("OD-CAP-REV2-FEATURE-BINARY-MISMATCH".to_string());
  }
  Ok(())
}

/// Candidate-only equality join between the CLI's embedded build-marker
/// projection, this crate's native cfg facts, and one generated target row.
///
/// The caller-supplied structure is evidence, not authority: this function
/// independently selects the native target and reads panic/debug cfg in this
/// compiled crate. Its only consumer is a dormant pre-FD3 candidate identity
/// projection; it does not authenticate an image, advertise a target, or arm
/// a runtime context.
///
/// @ref LLP 0019#pre-promotion-conformance-candidate-execution
/// [constrained-by] -- Compiled marker equality is candidate preparation only;
/// it grants no execution, conformance, admission, or release authority.
pub(crate) fn validate_current_binary_candidate_build_identity(
  expected: &crate::rev2_registry_generated::Rev2TargetStatus,
  actual: &OdenRev2CompiledBuildIdentity,
) -> Result<(), String> {
  let native_target = compiled_target()
    .ok_or_else(|| "OD-CAP-REV2-FEATURE-BINARY-MISMATCH".to_string())?;
  let native_panic_strategy = if cfg!(panic = "abort") {
    "abort"
  } else {
    "unwind"
  };
  validate_compiled_build_identity_against_native_facts(
    expected,
    actual,
    native_target,
    native_panic_strategy,
    cfg!(debug_assertions),
  )
}

fn compiled_target() -> Option<&'static str> {
  #[cfg(all(
    target_arch = "x86_64",
    target_os = "linux",
    target_env = "gnu"
  ))]
  return Some("x86_64-unknown-linux-gnu");
  #[cfg(all(
    target_arch = "aarch64",
    target_os = "linux",
    target_env = "gnu"
  ))]
  return Some("aarch64-unknown-linux-gnu");
  #[cfg(all(target_arch = "x86_64", target_os = "macos"))]
  return Some("x86_64-apple-darwin");
  #[cfg(all(target_arch = "aarch64", target_os = "macos"))]
  return Some("aarch64-apple-darwin");
  #[allow(unreachable_code)]
  None
}

fn verify_mac(
  snapshot: &Value,
  mac: &Map<String, Value>,
  key: &[u8],
) -> Result<(), String> {
  let key_id = mac
    .get("keyId")
    .and_then(Value::as_str)
    .ok_or_else(|| "OD-CAP-REV2-AUTH-KEY-ID".to_string())?;
  let expected_key_id =
    format!("sha256-{}", URL_SAFE_NO_PAD.encode(Sha256::digest(key)));
  if key_id != expected_key_id {
    return Err("OD-CAP-REV2-AUTH-KEY-ID".to_string());
  }
  let tag = mac
    .get("tag")
    .and_then(Value::as_str)
    .and_then(|tag| URL_SAFE_NO_PAD.decode(tag).ok())
    .filter(|tag| tag.len() == 32)
    .ok_or_else(|| "OD-CAP-REV2-AUTH-TAG".to_string())?;
  let canonical = canonical_json(snapshot)
    .map_err(|_| "OD-CAP-REV2-AUTH-CANONICAL".to_string())?;
  let mut verifier = <Hmac<Sha256> as Mac>::new_from_slice(key)
    .map_err(|_| "OD-CAP-REV2-AUTH-KEY".to_string())?;
  verifier.update(ENVELOPE_AUTH_DOMAIN.as_bytes());
  verifier.update(key_id.as_bytes());
  verifier.update(canonical.as_bytes());
  verifier
    .verify_slice(&tag)
    .map_err(|_| "OD-CAP-REV2-AUTH-FAILED".to_string())
}

fn verify_snapshot(
  snapshot: &Value,
  target_status: TargetStatus<'_>,
) -> Result<OdenRev2LoadedPolicyContext, String> {
  verify_snapshot_with_candidate_root(snapshot, target_status, None)
}

fn verify_snapshot_with_candidate_root(
  snapshot: &Value,
  target_status: TargetStatus<'_>,
  candidate_root: Option<CandidateDescriptorSnapshotRoot>,
) -> Result<OdenRev2LoadedPolicyContext, String> {
  let snapshot_object = exact_object(
    snapshot,
    &[
      "armedSnapshotDigest",
      "canonicalPolicy",
      "capsVocab",
      "channelEpoch",
      "classifierBindings",
      "conformanceReportDigest",
      "denyCeiling",
      "effectiveMode",
      "engineFeatureSet",
      "engineTarget",
      "executionRole",
      "executableBindings",
      "policyDigest",
      "projectDigest",
      "protectedPredicateVersions",
      "protectedReceiptBindings",
      "protectedReceiptSetDigest",
      "registryDigest",
      "rootBindings",
      "routeBindings",
      "runNonce",
      "snapshotSchema",
      "vocabDigest",
    ],
    "OD-CAP-REV2-SNAPSHOT-SHAPE",
  )?;
  require_string(snapshot_object, "snapshotSchema", SNAPSHOT_SCHEMA)?;
  require_string(snapshot_object, "capsVocab", REV2_PROFILE)?;
  require_string(snapshot_object, "vocabDigest", REV2_VOCAB_DIGEST)?;
  require_string(snapshot_object, "registryDigest", REV2_REGISTRY_DIGEST)?;
  require_string(snapshot_object, "engineTarget", target_status.target)?;
  require_string(
    snapshot_object,
    "engineFeatureSet",
    target_status.feature_set,
  )?;
  let mode = required_mode(snapshot_object, "effectiveMode")?;
  let execution_role = snapshot_object
    .get("executionRole")
    .and_then(Value::as_str)
    .filter(|role| matches!(*role, "run" | "probe" | "candidate" | "baseline"))
    .ok_or_else(|| "OD-CAP-REV2-EXECUTION-ROLE".to_string())?;
  let run_nonce = bounded_nonempty(snapshot_object, "runNonce", 1024)?;
  let channel_epoch = bounded_nonempty(snapshot_object, "channelEpoch", 1024)?;
  let project_digest = required_digest(snapshot_object, "projectDigest")?;
  for field in [
    "rootBindings",
    "denyCeiling",
    "executableBindings",
    "routeBindings",
    "classifierBindings",
    "protectedPredicateVersions",
    "protectedReceiptBindings",
  ] {
    let rows = snapshot_object
      .get(field)
      .and_then(Value::as_array)
      .ok_or_else(|| format!("OD-CAP-REV2-{field}-SHAPE"))?;
    if rows.len() > MAX_BINDING_ROWS {
      return Err(format!("OD-CAP-REV2-{field}-BOUNDS"));
    }
    require_canonical_set(rows, field)?;
  }

  let canonical_policy = snapshot_object
    .get("canonicalPolicy")
    .ok_or_else(|| "OD-CAP-REV2-POLICY-MISSING".to_string())?;
  let policy = exact_object(
    canonical_policy,
    &[
      "capsVocab",
      "mode",
      "policyDigest",
      "policySchema",
      "principals",
      "processDenials",
      "vocabDigest",
    ],
    "OD-CAP-REV2-POLICY-SHAPE",
  )?;
  require_string(policy, "policySchema", POLICY_SCHEMA)?;
  require_string(policy, "capsVocab", REV2_PROFILE)?;
  require_string(policy, "vocabDigest", REV2_VOCAB_DIGEST)?;
  if required_mode(policy, "mode")? != mode {
    return Err("OD-CAP-REV2-MODE-MISMATCH".to_string());
  }
  let core =
    Rev2Core::embedded().map_err(|_| "OD-CAP-REV2-CORE-INIT".to_string())?;
  let mut policy_facts = validate_canonical_policy_contents(policy, &core)?;
  let deny_ceiling = snapshot_object
    .get("denyCeiling")
    .and_then(Value::as_array)
    .ok_or_else(|| "OD-CAP-REV2-denyCeiling-SHAPE".to_string())?;
  validate_authority_rows(
    deny_ceiling,
    None,
    SelectorPolarity::Negative,
    false,
    &core,
    &mut policy_facts,
    "denyCeiling",
  )?;
  let policy_digest = required_digest(snapshot_object, "policyDigest")?;
  if required_digest(policy, "policyDigest")? != policy_digest {
    return Err("OD-CAP-REV2-POLICY-DIGEST-MISMATCH".to_string());
  }
  let mut policy_basis = canonical_policy.clone();
  policy_basis
    .as_object_mut()
    .expect("validated policy object")
    .remove("policyDigest");
  let computed_policy_digest =
    domain_digest("oden:capsec:policy:2", &policy_basis)
      .map_err(|_| "OD-CAP-REV2-POLICY-CANONICAL".to_string())?;
  if computed_policy_digest != policy_digest {
    return Err("OD-CAP-REV2-POLICY-DIGEST-MISMATCH".to_string());
  }

  let receipt_bindings = snapshot_object
    .get("protectedReceiptBindings")
    .expect("validated receipt array");
  let receipt_set_digest =
    required_digest(snapshot_object, "protectedReceiptSetDigest")?;
  let computed_receipt_set =
    domain_digest(RECEIPT_SET_DOMAIN, receipt_bindings)
      .map_err(|_| "OD-CAP-REV2-RECEIPT-CANONICAL".to_string())?;
  if receipt_set_digest != computed_receipt_set {
    return Err("OD-CAP-REV2-RECEIPT-DIGEST-MISMATCH".to_string());
  }
  let retained_objects = validate_snapshot_bindings(
    snapshot_object,
    &policy_facts,
    project_digest,
    candidate_root,
  )?;

  reject_display_or_source_fields(snapshot)?;
  let armed_snapshot_digest =
    required_digest(snapshot_object, "armedSnapshotDigest")?;
  let mut armed_basis = snapshot.clone();
  armed_basis
    .as_object_mut()
    .expect("validated snapshot object")
    .remove("armedSnapshotDigest");
  let computed_armed_digest =
    domain_digest("oden:capsec:armed:2", &armed_basis)
      .map_err(|_| "OD-CAP-REV2-ARMED-CANONICAL".to_string())?;
  if computed_armed_digest != armed_snapshot_digest {
    return Err("OD-CAP-REV2-ARMED-DIGEST-MISMATCH".to_string());
  }

  let cell_total = target_status
    .enforced
    .checked_add(target_status.closed)
    .and_then(|value| value.checked_add(target_status.absent))
    .and_then(|value| value.checked_add(target_status.unsupported))
    .ok_or_else(|| "OD-CAP-REV2-TARGET-COUNT".to_string())?;
  if cell_total == 0 {
    return Err("OD-CAP-REV2-TARGET-COUNT".to_string());
  }
  let expected_claim = if target_status.hermetic {
    "test-conformant"
  } else if target_status.advertised {
    "advertised"
  } else {
    "not-advertised"
  };
  if target_status.profile_claim != expected_claim {
    return Err("OD-CAP-REV2-TARGET-CLAIM".to_string());
  }
  let mut blockers = Vec::new();
  if target_status.unsupported != 0 {
    blockers.push(format!(
      "target-unsupported-cells:{}",
      target_status.unsupported
    ));
  }
  if !target_status.hermetic && !target_status.advertised {
    blockers.push("target-not-advertised".to_string());
  }
  let report = snapshot_object.get("conformanceReportDigest");
  let conformance_report_digest = match target_status.conformance_report_digest
  {
    Some(expected) => {
      let actual = required_digest(snapshot_object, "conformanceReportDigest")?;
      if actual != expected {
        return Err("OD-CAP-REV2-CONFORMANCE-REPORT-MISMATCH".to_string());
      }
      Some(actual.to_string())
    }
    None if matches!(report, Some(Value::Null)) => None,
    None => {
      return Err("OD-CAP-REV2-CONFORMANCE-REPORT-UNTRUSTED".to_string());
    }
  };
  let conformant =
    target_status.unsupported == 0 && conformance_report_digest.is_some();
  if target_status.unsupported == 0 && !conformant {
    blockers.push("conformance-report-not-embedded".to_string());
  }
  blockers.sort_unstable();
  blockers.dedup();
  let state =
    if conformant && (target_status.hermetic || target_status.advertised) {
      OdenRev2LoadState::Armable
    } else {
      OdenRev2LoadState::VerifiedUnarmed
    };
  Ok(OdenRev2LoadedPolicyContext {
    state,
    target: target_status.target.to_string(),
    feature_set: target_status.feature_set.to_string(),
    policy_digest: policy_digest.to_string(),
    project_digest: project_digest.to_string(),
    armed_snapshot_digest: armed_snapshot_digest.to_string(),
    conformance_report_digest,
    execution_role: execution_role.to_string(),
    run_nonce: run_nonce.to_string(),
    channel_epoch: channel_epoch.to_string(),
    conformant,
    advertised: target_status.advertised,
    blockers: blockers.into(),
    retained_objects: retained_objects.into(),
    installed_executables: OdenRev2InstalledExecutableContext::empty(),
    snapshot: Arc::new(snapshot.clone()),
  })
}

fn validate_canonical_policy_contents(
  policy: &Map<String, Value>,
  core: &Rev2Core,
) -> Result<PolicyFacts, String> {
  let principals = policy
    .get("principals")
    .and_then(Value::as_array)
    .ok_or_else(|| "OD-CAP-REV2-PRINCIPALS-SHAPE".to_string())?;
  if principals.len() > MAX_BINDING_ROWS {
    return Err("OD-CAP-REV2-PRINCIPALS-BOUNDS".to_string());
  }
  require_canonical_set(principals, "principals")?;
  let mut facts = PolicyFacts {
    rows: Vec::new(),
    protected_by_digest: HashMap::new(),
    source_ids: HashSet::new(),
  };
  let mut principal_keys = HashSet::new();
  for principal_policy in principals {
    let entry = exact_object(
      principal_policy,
      &[
        "binding",
        "denials",
        "escalationCeiling",
        "floor",
        "principal",
      ],
      "OD-CAP-REV2-PRINCIPAL-POLICY-SHAPE",
    )?;
    let principal_value = entry
      .get("principal")
      .ok_or_else(|| "OD-CAP-REV2-PRINCIPAL-MISSING".to_string())?;
    let principal = validate_policy_principal(principal_value)?;
    if !principal_keys.insert(principal.key.clone()) {
      return Err("OD-CAP-REV2-PRINCIPAL-DUPLICATE".to_string());
    }
    validate_integrity_binding(
      entry
        .get("binding")
        .ok_or_else(|| "OD-CAP-REV2-BINDING-MISSING".to_string())?,
    )?;
    for (field, polarity, protected_allowed) in [
      ("floor", SelectorPolarity::Positive, true),
      ("escalationCeiling", SelectorPolarity::Positive, false),
      ("denials", SelectorPolarity::Negative, false),
    ] {
      let rows = entry
        .get(field)
        .and_then(Value::as_array)
        .ok_or_else(|| format!("OD-CAP-REV2-{field}-SHAPE"))?;
      validate_authority_rows(
        rows,
        Some(&principal),
        polarity,
        protected_allowed,
        core,
        &mut facts,
        field,
      )?;
    }
  }
  let process_denials = policy
    .get("processDenials")
    .and_then(Value::as_array)
    .ok_or_else(|| "OD-CAP-REV2-PROCESS-DENIALS-SHAPE".to_string())?;
  validate_authority_rows(
    process_denials,
    None,
    SelectorPolarity::Negative,
    false,
    core,
    &mut facts,
    "processDenials",
  )?;
  Ok(facts)
}

#[allow(clippy::too_many_arguments)]
fn validate_authority_rows(
  rows: &[Value],
  expected_principal: Option<&PrincipalRef>,
  polarity: SelectorPolarity,
  protected_allowed: bool,
  core: &Rev2Core,
  facts: &mut PolicyFacts,
  field: &str,
) -> Result<(), String> {
  if rows.len() > MAX_BINDING_ROWS {
    return Err(format!("OD-CAP-REV2-{field}-BOUNDS"));
  }
  require_canonical_set(rows, field)?;
  for row in rows {
    let has_protected = row
      .as_object()
      .is_some_and(|object| object.contains_key("protected"));
    let expected_fields: &[&str] = if has_protected {
      &["protected", "selector", "sourceId"]
    } else {
      &["selector", "sourceId"]
    };
    let row_object =
      exact_object(row, expected_fields, "OD-CAP-REV2-AUTHORITY-ROW-SHAPE")?;
    let source_id = bounded_nonempty(row_object, "sourceId", 1024)?;
    if !facts.source_ids.insert(source_id.to_string()) {
      return Err("OD-CAP-REV2-SOURCE-ID-DUPLICATE".to_string());
    }
    let selector_value = row_object
      .get("selector")
      .ok_or_else(|| "OD-CAP-REV2-SELECTOR-MISSING".to_string())?;
    let selector = validate_canonical_selector(selector_value, polarity, core)?;
    if selector.principal.as_ref() != expected_principal {
      return Err("OD-CAP-REV2-SELECTOR-PRINCIPAL".to_string());
    }
    let protected = if let Some(protected_value) = row_object.get("protected") {
      if !protected_allowed || expected_principal.is_none() {
        return Err("OD-CAP-REV2-PROTECTED-POSITION".to_string());
      }
      let protected_object = exact_object(
        protected_value,
        &["canonicalRowDigest", "predicateId", "reasonDigest"],
        "OD-CAP-REV2-PROTECTED-SHAPE",
      )?;
      let predicate_id =
        bounded_nonempty(protected_object, "predicateId", 256)?;
      let predicate_version = generated_protected_predicate_version(
        &selector.capability,
        predicate_id,
      )?;
      let reason_digest = required_digest(protected_object, "reasonDigest")?;
      let row_digest = required_digest(protected_object, "canonicalRowDigest")?;
      let basis = serde_json::json!({
        "sourceId": source_id,
        "selector": selector_value,
        "predicateId": predicate_id,
        "reasonDigest": reason_digest,
      });
      let expected = domain_digest("oden:capsec:protected-row:2", &basis)
        .map_err(|_| "OD-CAP-REV2-PROTECTED-CANONICAL".to_string())?;
      if row_digest != expected {
        return Err("OD-CAP-REV2-PROTECTED-DIGEST".to_string());
      }
      Some(ProtectedRowFact {
        predicate_id: predicate_id.to_string(),
        predicate_version,
        canonical_row_digest: row_digest.to_string(),
      })
    } else {
      None
    };
    let fact = CanonicalRowFact {
      source_id: source_id.to_string(),
      principal: selector.principal.clone(),
      projection_id: selector.projection_id.clone(),
      resource: selector.resource.clone(),
      protected: protected.clone(),
    };
    if let Some(protected) = protected {
      if facts
        .protected_by_digest
        .insert(protected.canonical_row_digest, fact.clone())
        .is_some()
      {
        return Err("OD-CAP-REV2-PROTECTED-DUPLICATE".to_string());
      }
    }
    facts.rows.push(fact);
  }
  Ok(())
}

fn validate_canonical_selector(
  value: &Value,
  polarity: SelectorPolarity,
  core: &Rev2Core,
) -> Result<CanonicalAuthoritySelector, String> {
  let selector = exact_object(
    value,
    &["capability", "principal", "projectionId", "resource"],
    "OD-CAP-REV2-SELECTOR-SHAPE",
  )?;
  let principal = match selector.get("principal") {
    Some(Value::Null) => None,
    Some(value) => Some(validate_policy_principal(value)?),
    None => return Err("OD-CAP-REV2-SELECTOR-PRINCIPAL".to_string()),
  };
  let capability = bounded_nonempty(selector, "capability", 256)?;
  let projection_id = bounded_nonempty(selector, "projectionId", 1024)?;
  let resource = selector
    .get("resource")
    .ok_or_else(|| "OD-CAP-REV2-SELECTOR-RESOURCE".to_string())?
    .clone();
  let canonical = CanonicalAuthoritySelector {
    principal: principal.clone(),
    capability: capability.to_string(),
    projection_id: projection_id.to_string(),
    resource: resource.clone(),
  };
  let normalized = core
    .normalize_selector(
      &AuthoritySelectorInput {
        identity: EngineIdentity::embedded(),
        principal,
        capability: capability.to_string(),
        resource,
      },
      polarity,
    )
    .map_err(|_| "OD-CAP-REV2-SELECTOR-CORE".to_string())?;
  if normalized != canonical {
    return Err("OD-CAP-REV2-SELECTOR-NONCANONICAL".to_string());
  }
  Ok(canonical)
}

fn validate_policy_principal(value: &Value) -> Result<PrincipalRef, String> {
  let principal =
    exact_object(value, &["key", "kind"], "OD-CAP-REV2-PRINCIPAL-SHAPE")?;
  let kind = principal
    .get("kind")
    .and_then(Value::as_str)
    .ok_or_else(|| "OD-CAP-REV2-PRINCIPAL-KIND".to_string())?;
  let (kind, prefix) = match kind {
    "root" => (PrincipalKind::Root, "root:"),
    "package" => (PrincipalKind::Package, "pkg:"),
    "jsr" => (PrincipalKind::Jsr, "jsr:"),
    "url" => (PrincipalKind::Url, "url:"),
    "quarantine" => (PrincipalKind::Quarantine, "quarantine:"),
    "runtime" | "no-user" => {
      return Err("OD-CAP-REV2-PRINCIPAL-RECIPIENT".to_string());
    }
    _ => return Err("OD-CAP-REV2-PRINCIPAL-KIND".to_string()),
  };
  let key = bounded_nonempty(principal, "key", 1024)?;
  let Some(digest) = key.strip_prefix(prefix) else {
    return Err("OD-CAP-REV2-PRINCIPAL-KEY".to_string());
  };
  if !valid_digest(digest) {
    return Err("OD-CAP-REV2-PRINCIPAL-KEY".to_string());
  }
  Ok(PrincipalRef {
    kind,
    key: key.to_string(),
  })
}

fn validate_integrity_binding(value: &Value) -> Result<(), String> {
  let binding = exact_object(
    value,
    &["bindingDigest", "resolverId"],
    "OD-CAP-REV2-PRINCIPAL-BINDING-SHAPE",
  )?;
  bounded_nonempty(binding, "resolverId", 1024)?;
  required_digest(binding, "bindingDigest")?;
  Ok(())
}

fn validate_snapshot_bindings(
  snapshot: &Map<String, Value>,
  facts: &PolicyFacts,
  project_digest: &str,
  candidate_root: Option<CandidateDescriptorSnapshotRoot>,
) -> Result<Vec<OdenRev2RetainedObject>, String> {
  let mut retained = validate_root_bindings(
    snapshot
      .get("rootBindings")
      .and_then(Value::as_array)
      .ok_or_else(|| "OD-CAP-REV2-rootBindings-SHAPE".to_string())?,
    facts,
    candidate_root,
  )?;
  retained.extend(validate_executable_bindings(
    snapshot
      .get("executableBindings")
      .and_then(Value::as_array)
      .ok_or_else(|| "OD-CAP-REV2-executableBindings-SHAPE".to_string())?,
    facts,
  )?);
  validate_route_bindings(
    snapshot
      .get("routeBindings")
      .and_then(Value::as_array)
      .ok_or_else(|| "OD-CAP-REV2-routeBindings-SHAPE".to_string())?,
    facts,
  )?;
  validate_classifier_bindings(
    snapshot
      .get("classifierBindings")
      .and_then(Value::as_array)
      .ok_or_else(|| "OD-CAP-REV2-classifierBindings-SHAPE".to_string())?,
    facts,
  )?;
  validate_protected_bindings(
    snapshot
      .get("protectedPredicateVersions")
      .and_then(Value::as_array)
      .ok_or_else(|| {
        "OD-CAP-REV2-protectedPredicateVersions-SHAPE".to_string()
      })?,
    snapshot
      .get("protectedReceiptBindings")
      .and_then(Value::as_array)
      .ok_or_else(|| {
        "OD-CAP-REV2-protectedReceiptBindings-SHAPE".to_string()
      })?,
    facts,
    project_digest,
  )?;
  Ok(retained)
}

fn validate_root_bindings(
  bindings: &[Value],
  facts: &PolicyFacts,
  mut candidate_root: Option<CandidateDescriptorSnapshotRoot>,
) -> Result<Vec<OdenRev2RetainedObject>, String> {
  if candidate_root.is_some() && bindings.len() != 1 {
    return Err("OD-CAP-REV2-CANDIDATE-ROOT-COVERAGE".to_string());
  }
  let mut required = HashSet::new();
  for fact in &facts.rows {
    let mut roots = HashSet::new();
    collect_logical_roots(&fact.resource, &mut roots)?;
    for root in roots {
      required.insert(root_requirement_key(
        &fact.source_id,
        &root,
        fact.principal.as_ref(),
      )?);
    }
  }
  let mut supplied = HashSet::new();
  let mut binding_ids = HashSet::new();
  let mut retained = Vec::new();
  for binding in bindings {
    let object = exact_object(
      binding,
      &[
        "bindingProvenanceDigest",
        "canonicalPath",
        "logicalRoot",
        "objectIdentity",
        "principal",
        "rootBindingId",
        "sourceId",
      ],
      "OD-CAP-REV2-ROOT-BINDING-SHAPE",
    )?;
    let source_id = bounded_nonempty(object, "sourceId", 1024)?;
    let logical_root = bounded_nonempty(object, "logicalRoot", 16)?;
    if !matches!(
      logical_root,
      "$PROJECT" | "$PACKAGE" | "$HOME" | "$TMP" | "$ABS"
    ) {
      return Err("OD-CAP-REV2-ROOT-BINDING-LOGICAL".to_string());
    }
    let principal = validate_optional_policy_principal(
      object
        .get("principal")
        .ok_or_else(|| "OD-CAP-REV2-ROOT-BINDING-PRINCIPAL".to_string())?,
    )?;
    let binding_id = bounded_nonempty(object, "rootBindingId", 1024)?;
    if !binding_ids.insert(binding_id.to_string()) {
      return Err("OD-CAP-REV2-ROOT-BINDING-ID".to_string());
    }
    let binding_provenance_digest =
      required_digest(object, "bindingProvenanceDigest")?;
    let key =
      root_requirement_key(source_id, logical_root, principal.as_ref())?;
    if !supplied.insert(key) {
      return Err("OD-CAP-REV2-ROOT-BINDING-DUPLICATE".to_string());
    }
    let canonical_path_value = object
      .get("canonicalPath")
      .ok_or_else(|| "OD-CAP-REV2-ROOT-BINDING-PATH".to_string())?;
    let object_identity_value = object
      .get("objectIdentity")
      .ok_or_else(|| "OD-CAP-REV2-ROOT-BINDING-OBJECT".to_string())?;
    let canonical_path = parse_tagged_path(canonical_path_value)?;
    let object_identity = platform_object_identity(object_identity_value)?;
    let file = if let Some(candidate) = candidate_root.take() {
      if canonical_path != candidate.synthetic_path {
        return Err("OD-CAP-REV2-CANDIDATE-ROOT-PATH".to_string());
      }
      validate_candidate_descriptor_root(&candidate.file, &object_identity)?;
      candidate.file
    } else {
      validate_and_open_bound_object(
        canonical_path_value,
        object_identity_value,
        true,
      )?
    };
    retained.push(OdenRev2RetainedObject {
      binding_id: binding_id.to_string(),
      source_id: source_id.to_string(),
      role: None,
      principal,
      canonical_path,
      object_identity,
      canonical_content_identity: None,
      provenance_digest: Some(binding_provenance_digest.to_string()),
      file: Arc::new(file),
    });
  }
  if required != supplied {
    return Err("OD-CAP-REV2-ROOT-BINDING-COVERAGE".to_string());
  }
  if candidate_root.is_some() {
    return Err("OD-CAP-REV2-CANDIDATE-ROOT-COVERAGE".to_string());
  }
  Ok(retained)
}

fn validate_candidate_descriptor_root(
  file: &File,
  expected_identity: &str,
) -> Result<(), String> {
  #[cfg(not(any(target_os = "linux", target_os = "macos")))]
  {
    let _ = (file, expected_identity);
    return Err("OD-CAP-REV2-CANDIDATE-ROOT-PLATFORM".to_string());
  }
  #[cfg(any(target_os = "linux", target_os = "macos"))]
  {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::MetadataExt;

    let metadata = file
      .metadata()
      .map_err(|_| "OD-CAP-REV2-CANDIDATE-ROOT-DESCRIPTOR".to_string())?;
    let identity = format!(
      "unix-dev-ino:{:016x}{:016x}",
      metadata.dev(),
      metadata.ino()
    );
    // SAFETY: both fcntl commands only inspect the live retained descriptor.
    let descriptor_flags =
      unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFD) };
    // SAFETY: F_GETFL only inspects the live retained descriptor.
    let status_flags = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETFL) };
    #[cfg(target_os = "linux")]
    let alternate_access =
      status_flags >= 0 && status_flags & libc::O_PATH != 0;
    #[cfg(target_os = "macos")]
    let alternate_access =
      status_flags >= 0 && status_flags & (libc::O_EVTONLY | libc::O_EXEC) != 0;
    if !metadata.is_dir()
      || identity != expected_identity
      || descriptor_flags < 0
      || descriptor_flags & libc::FD_CLOEXEC == 0
      || status_flags < 0
      || status_flags & libc::O_ACCMODE != libc::O_RDONLY
      || status_flags & libc::O_APPEND != 0
      || alternate_access
    {
      return Err("OD-CAP-REV2-CANDIDATE-ROOT-DESCRIPTOR".to_string());
    }
    Ok(())
  }
}

fn validate_executable_bindings(
  bindings: &[Value],
  facts: &PolicyFacts,
) -> Result<Vec<OdenRev2RetainedObject>, String> {
  let mut required = HashMap::new();
  for fact in &facts.rows {
    let mut identities = Vec::new();
    collect_content_identities(&fact.resource, &mut identities)?;
    for (role, digest) in identities {
      let key = executable_requirement_key(&fact.source_id, role, &digest)?;
      required.insert(key, fact.principal.clone());
    }
  }
  let mut supplied = HashSet::new();
  let mut binding_ids = HashSet::new();
  let mut retained = Vec::new();
  for binding in bindings {
    let object = exact_object(
      binding,
      &[
        "bindingId",
        "canonicalContentIdentity",
        "canonicalPath",
        "objectIdentity",
        "principal",
        "provenanceDigest",
        "role",
        "sourceId",
      ],
      "OD-CAP-REV2-EXECUTABLE-BINDING-SHAPE",
    )?;
    let source_id = bounded_nonempty(object, "sourceId", 1024)?;
    let role = bounded_nonempty(object, "role", 16)?;
    if !matches!(role, "object" | "interpreter") {
      return Err("OD-CAP-REV2-EXECUTABLE-ROLE".to_string());
    }
    let content = required_digest(object, "canonicalContentIdentity")?;
    let principal = validate_optional_policy_principal(
      object
        .get("principal")
        .ok_or_else(|| "OD-CAP-REV2-EXECUTABLE-PRINCIPAL".to_string())?,
    )?;
    let key = executable_requirement_key(source_id, role, content)?;
    if !supplied.insert(key.clone()) {
      return Err("OD-CAP-REV2-EXECUTABLE-DUPLICATE".to_string());
    }
    if required.get(&key) != Some(&principal) {
      return Err("OD-CAP-REV2-EXECUTABLE-COVERAGE".to_string());
    }
    let binding_id = bounded_nonempty(object, "bindingId", 1024)?;
    if !binding_ids.insert(binding_id.to_string()) {
      return Err("OD-CAP-REV2-EXECUTABLE-ID".to_string());
    }
    let provenance_digest = required_digest(object, "provenanceDigest")?;
    let canonical_path_value = object
      .get("canonicalPath")
      .ok_or_else(|| "OD-CAP-REV2-EXECUTABLE-PATH".to_string())?;
    let object_identity_value = object
      .get("objectIdentity")
      .ok_or_else(|| "OD-CAP-REV2-EXECUTABLE-OBJECT".to_string())?;
    let canonical_path = parse_tagged_path(canonical_path_value)?;
    let object_identity = platform_object_identity(object_identity_value)?;
    let file = validate_and_open_bound_object(
      canonical_path_value,
      object_identity_value,
      false,
    )?;
    verify_opened_executable_content(&file, content)?;
    retained.push(OdenRev2RetainedObject {
      binding_id: binding_id.to_string(),
      source_id: source_id.to_string(),
      role: Some(role.to_string()),
      principal,
      canonical_path,
      object_identity,
      canonical_content_identity: Some(content.to_string()),
      provenance_digest: Some(provenance_digest.to_string()),
      file: Arc::new(file),
    });
  }
  if required.keys().cloned().collect::<HashSet<_>>() != supplied {
    return Err("OD-CAP-REV2-EXECUTABLE-COVERAGE".to_string());
  }
  Ok(retained)
}

fn validate_route_bindings(
  bindings: &[Value],
  facts: &PolicyFacts,
) -> Result<(), String> {
  let mut required = HashMap::new();
  for fact in &facts.rows {
    let mut routes = Vec::new();
    collect_named_objects(&fact.resource, "route", &mut routes)?;
    if routes.is_empty() {
      continue;
    }
    let resource_digest = domain_digest(ROUTE_RESOURCE_DOMAIN, &fact.resource)
      .map_err(|_| "OD-CAP-REV2-ROUTE-RESOURCE".to_string())?;
    for route in routes {
      let route_object = route
        .as_object()
        .ok_or_else(|| "OD-CAP-REV2-ROUTE-SELECTOR".to_string())?;
      let kind = route_object
        .get("kind")
        .and_then(Value::as_str)
        .filter(|kind| !kind.trim().is_empty())
        .ok_or_else(|| "OD-CAP-REV2-ROUTE-KIND".to_string())?;
      let route_digest = domain_digest(ROUTE_SELECTOR_DOMAIN, route)
        .map_err(|_| "OD-CAP-REV2-ROUTE-SELECTOR".to_string())?;
      required.insert(
        route_requirement_key(
          &fact.source_id,
          &resource_digest,
          &route_digest,
        )?,
        kind.to_string(),
      );
    }
  }
  let mut supplied = HashSet::new();
  let mut route_ids = HashSet::new();
  for binding in bindings {
    let object = exact_object(
      binding,
      &[
        "resourceDigest",
        "routeDigest",
        "routeId",
        "routeKind",
        "sourceId",
      ],
      "OD-CAP-REV2-ROUTE-BINDING-SHAPE",
    )?;
    let source_id = bounded_nonempty(object, "sourceId", 1024)?;
    let resource_digest = required_digest(object, "resourceDigest")?;
    let route_digest = required_digest(object, "routeDigest")?;
    let route_kind = bounded_nonempty(object, "routeKind", 256)?;
    let route_id = bounded_nonempty(object, "routeId", 1024)?;
    if !route_ids.insert(route_id.to_string()) {
      return Err("OD-CAP-REV2-ROUTE-ID".to_string());
    }
    let key = route_requirement_key(source_id, resource_digest, route_digest)?;
    if !supplied.insert(key.clone())
      || required.get(&key) != Some(&route_kind.to_string())
    {
      return Err("OD-CAP-REV2-ROUTE-COVERAGE".to_string());
    }
  }
  if required.keys().cloned().collect::<HashSet<_>>() != supplied {
    return Err("OD-CAP-REV2-ROUTE-COVERAGE".to_string());
  }
  Ok(())
}

fn validate_classifier_bindings(
  bindings: &[Value],
  facts: &PolicyFacts,
) -> Result<(), String> {
  let payload = parse_strict_json(REV2_RUNTIME_SEMANTIC_PAYLOAD_JSON)
    .map_err(|_| "OD-CAP-REV2-CLASSIFIER-PAYLOAD".to_string())?;
  let rules = payload
    .get("policyRulesAndClassifiers")
    .and_then(Value::as_object)
    .ok_or_else(|| "OD-CAP-REV2-CLASSIFIER-PAYLOAD".to_string())?;
  let projections = rules
    .get("projections")
    .and_then(Value::as_array)
    .ok_or_else(|| "OD-CAP-REV2-CLASSIFIER-PROJECTIONS".to_string())?;
  let match_spec = rules
    .get("matchEvaluationSpec")
    .and_then(Value::as_object)
    .ok_or_else(|| "OD-CAP-REV2-CLASSIFIER-MATCH-SPEC".to_string())?;
  let operations = match_spec
    .get("operations")
    .and_then(Value::as_array)
    .ok_or_else(|| "OD-CAP-REV2-CLASSIFIER-OPERATIONS".to_string())?;
  let data_tables = match_spec
    .get("dataTables")
    .and_then(Value::as_array)
    .ok_or_else(|| "OD-CAP-REV2-CLASSIFIER-TABLES".to_string())?;
  let mut required = HashMap::new();
  let mut table_digests: HashMap<String, String> = HashMap::new();
  for fact in &facts.rows {
    let projection = find_generated_row(projections, &fact.projection_id)
      .ok_or_else(|| "OD-CAP-REV2-CLASSIFIER-PROJECTION".to_string())?;
    let Some(spec) = projection.get("matchSpec") else {
      return Err("OD-CAP-REV2-CLASSIFIER-PROJECTION".to_string());
    };
    let clauses: &[Value] = if spec.is_null() {
      &[]
    } else {
      spec
        .get("clauses")
        .and_then(Value::as_array)
        .ok_or_else(|| "OD-CAP-REV2-CLASSIFIER-CLAUSES".to_string())?
    };
    for clause in clauses {
      let operation_id = clause
        .get("operation")
        .and_then(Value::as_str)
        .ok_or_else(|| "OD-CAP-REV2-CLASSIFIER-OPERATION".to_string())?;
      let operation = find_generated_row(operations, operation_id)
        .ok_or_else(|| "OD-CAP-REV2-CLASSIFIER-OPERATION".to_string())?;
      let refs = operation
        .get("tableRefs")
        .and_then(Value::as_array)
        .ok_or_else(|| "OD-CAP-REV2-CLASSIFIER-TABLE-REFS".to_string())?;
      for table_id in refs {
        let table_id = table_id
          .as_str()
          .ok_or_else(|| "OD-CAP-REV2-CLASSIFIER-TABLE-ID".to_string())?;
        let table = find_generated_row(data_tables, table_id)
          .ok_or_else(|| "OD-CAP-REV2-CLASSIFIER-TABLE".to_string())?;
        let version = table
          .get("version")
          .and_then(Value::as_str)
          .ok_or_else(|| "OD-CAP-REV2-CLASSIFIER-VERSION".to_string())?;
        let digest = if let Some(digest) = table_digests.get(table_id) {
          digest.clone()
        } else {
          let digest = domain_digest(CLASSIFIER_INPUT_DOMAIN, table)
            .map_err(|_| "OD-CAP-REV2-CLASSIFIER-DIGEST".to_string())?;
          table_digests.insert(table_id.to_string(), digest.clone());
          digest
        };
        required.insert(
          classifier_requirement_key(&fact.source_id, table_id)?,
          (version.to_string(), digest),
        );
      }
    }
  }
  let mut supplied = HashSet::new();
  for binding in bindings {
    let object = exact_object(
      binding,
      &[
        "classifierId",
        "classifierVersion",
        "inputDigest",
        "sourceId",
      ],
      "OD-CAP-REV2-CLASSIFIER-BINDING-SHAPE",
    )?;
    let source_id = bounded_nonempty(object, "sourceId", 1024)?;
    let classifier_id = bounded_nonempty(object, "classifierId", 1024)?;
    let version = bounded_nonempty(object, "classifierVersion", 256)?;
    let input_digest = required_digest(object, "inputDigest")?;
    let key = classifier_requirement_key(source_id, classifier_id)?;
    if !supplied.insert(key.clone())
      || required.get(&key)
        != Some(&(version.to_string(), input_digest.to_string()))
    {
      return Err("OD-CAP-REV2-CLASSIFIER-COVERAGE".to_string());
    }
  }
  if required.keys().cloned().collect::<HashSet<_>>() != supplied {
    return Err("OD-CAP-REV2-CLASSIFIER-COVERAGE".to_string());
  }
  Ok(())
}

fn generated_protected_predicate_version(
  capability: &str,
  predicate_id: &str,
) -> Result<String, String> {
  let payload = parse_strict_json(REV2_RUNTIME_SEMANTIC_PAYLOAD_JSON)
    .map_err(|_| "OD-CAP-REV2-PROTECTED-PAYLOAD".to_string())?;
  let definition = payload
    .get("definitions")
    .and_then(Value::as_array)
    .and_then(|definitions| find_generated_row(definitions, capability))
    .ok_or_else(|| "OD-CAP-REV2-PROTECTED-UNREGISTERED".to_string())?;
  if definition
    .get("protectedReceiptPredicateId")
    .and_then(Value::as_str)
    != Some(predicate_id)
  {
    return Err("OD-CAP-REV2-PROTECTED-UNREGISTERED".to_string());
  }

  let rules = payload
    .get("policyRulesAndClassifiers")
    .and_then(Value::as_object)
    .ok_or_else(|| "OD-CAP-REV2-PROTECTED-PAYLOAD".to_string())?;
  let predicate = rules
    .get("predicates")
    .and_then(Value::as_array)
    .and_then(|predicates| find_generated_row(predicates, predicate_id))
    .ok_or_else(|| "OD-CAP-REV2-PROTECTED-UNREGISTERED".to_string())?;
  if predicate.get("kind").and_then(Value::as_str)
    != Some("definition-positive")
    || predicate
      .get("evaluator")
      .and_then(Value::as_object)
      .and_then(|evaluator| evaluator.get("algorithm"))
      .and_then(Value::as_str)
      != Some("authenticated-protected-receipt")
  {
    return Err("OD-CAP-REV2-PROTECTED-UNREGISTERED".to_string());
  }
  let receipt_schema_id = rules
    .get("protectedReceiptSchema")
    .and_then(Value::as_object)
    .and_then(|schema| schema.get("id"))
    .and_then(Value::as_str)
    .ok_or_else(|| "OD-CAP-REV2-PROTECTED-UNREGISTERED".to_string())?;
  let predicate_version = generated_id_version(predicate_id)?;
  if generated_id_version(receipt_schema_id)? != predicate_version {
    return Err("OD-CAP-REV2-PROTECTED-VERSION".to_string());
  }
  Ok(predicate_version.to_string())
}

fn generated_id_version(id: &str) -> Result<&str, String> {
  let (_, version) = id
    .rsplit_once('/')
    .ok_or_else(|| "OD-CAP-REV2-PROTECTED-VERSION".to_string())?;
  if version.is_empty()
    || version.starts_with('0')
    || !version.bytes().all(|byte| byte.is_ascii_digit())
  {
    return Err("OD-CAP-REV2-PROTECTED-VERSION".to_string());
  }
  Ok(version)
}

fn validate_protected_bindings(
  predicate_versions: &[Value],
  receipts: &[Value],
  facts: &PolicyFacts,
  project_digest: &str,
) -> Result<(), String> {
  let required_predicates = facts
    .protected_by_digest
    .values()
    .filter_map(|fact| fact.protected.as_ref())
    .map(|protected| {
      (
        protected.predicate_id.clone(),
        protected.predicate_version.clone(),
      )
    })
    .collect::<HashMap<_, _>>();
  let mut supplied_predicates = HashSet::new();
  for version in predicate_versions {
    let object = exact_object(
      version,
      &["predicateId", "version"],
      "OD-CAP-REV2-PREDICATE-VERSION-SHAPE",
    )?;
    let predicate_id = bounded_nonempty(object, "predicateId", 256)?;
    let version = bounded_nonempty(object, "version", 256)?;
    if !supplied_predicates.insert(predicate_id.to_string()) {
      return Err("OD-CAP-REV2-PREDICATE-DUPLICATE".to_string());
    }
    if required_predicates.get(predicate_id).map(String::as_str)
      != Some(version)
    {
      return Err("OD-CAP-REV2-PREDICATE-VERSION".to_string());
    }
  }
  if required_predicates.keys().cloned().collect::<HashSet<_>>()
    != supplied_predicates
  {
    return Err("OD-CAP-REV2-PREDICATE-COVERAGE".to_string());
  }

  let required_receipts = facts
    .protected_by_digest
    .keys()
    .cloned()
    .collect::<HashSet<_>>();
  let mut supplied_receipts = HashSet::new();
  let mut receipt_ids = HashSet::new();
  let mut binding_digests = HashSet::new();
  for receipt in receipts {
    let object = exact_object(
      receipt,
      &[
        "bindingDigest",
        "canonicalRowDigest",
        "expiresAt",
        "issuerGeneration",
        "issuerId",
        "monotonicDeadline",
        "predicateId",
        "principal",
        "projectDigest",
        "receiptId",
        "receiptNegativeGeneration",
        "resourceDigest",
        "revocationFeedId",
      ],
      "OD-CAP-REV2-RECEIPT-SHAPE",
    )?;
    let receipt_id = bounded_nonempty(object, "receiptId", 1024)?;
    if !receipt_ids.insert(receipt_id.to_string()) {
      return Err("OD-CAP-REV2-RECEIPT-ID".to_string());
    }
    let binding_digest = required_digest(object, "bindingDigest")?;
    if !binding_digests.insert(binding_digest.to_string()) {
      return Err("OD-CAP-REV2-RECEIPT-BINDING".to_string());
    }
    let row_digest = required_digest(object, "canonicalRowDigest")?;
    if !supplied_receipts.insert(row_digest.to_string()) {
      return Err("OD-CAP-REV2-RECEIPT-DUPLICATE".to_string());
    }
    let fact = facts
      .protected_by_digest
      .get(row_digest)
      .ok_or_else(|| "OD-CAP-REV2-RECEIPT-ROW".to_string())?;
    let protected = fact
      .protected
      .as_ref()
      .ok_or_else(|| "OD-CAP-REV2-RECEIPT-ROW".to_string())?;
    if bounded_nonempty(object, "predicateId", 256)? != protected.predicate_id {
      return Err("OD-CAP-REV2-RECEIPT-PREDICATE".to_string());
    }
    let principal = validate_policy_principal(
      object
        .get("principal")
        .ok_or_else(|| "OD-CAP-REV2-RECEIPT-PRINCIPAL".to_string())?,
    )?;
    if fact.principal.as_ref() != Some(&principal) {
      return Err("OD-CAP-REV2-RECEIPT-PRINCIPAL".to_string());
    }
    let expected_resource =
      domain_digest(PROTECTED_RESOURCE_DOMAIN, &fact.resource)
        .map_err(|_| "OD-CAP-REV2-RECEIPT-RESOURCE".to_string())?;
    if required_digest(object, "resourceDigest")? != expected_resource {
      return Err("OD-CAP-REV2-RECEIPT-RESOURCE".to_string());
    }
    if required_digest(object, "projectDigest")? != project_digest {
      return Err("OD-CAP-REV2-RECEIPT-PROJECT".to_string());
    }
    for field in ["issuerId", "revocationFeedId"] {
      bounded_nonempty(object, field, 1024)?;
    }
    for field in [
      "issuerGeneration",
      "receiptNegativeGeneration",
      "monotonicDeadline",
    ] {
      let value = object
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("OD-CAP-REV2-RECEIPT-{field}"))?;
      if !canonical_unsigned(value) {
        return Err(format!("OD-CAP-REV2-RECEIPT-{field}"));
      }
    }
    let expires = object
      .get("expiresAt")
      .and_then(Value::as_str)
      .ok_or_else(|| "OD-CAP-REV2-RECEIPT-EXPIRY".to_string())?;
    let expires = chrono::DateTime::parse_from_rfc3339(expires)
      .map_err(|_| "OD-CAP-REV2-RECEIPT-EXPIRY".to_string())?;
    let canonical = expires
      .with_timezone(&chrono::Utc)
      .to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
    if object.get("expiresAt").and_then(Value::as_str) != Some(&canonical)
      || expires <= chrono::Utc::now()
    {
      return Err("OD-CAP-REV2-RECEIPT-EXPIRY".to_string());
    }
  }
  if required_receipts != supplied_receipts {
    return Err("OD-CAP-REV2-RECEIPT-COVERAGE".to_string());
  }
  Ok(())
}

fn validate_optional_policy_principal(
  value: &Value,
) -> Result<Option<PrincipalRef>, String> {
  if value.is_null() {
    Ok(None)
  } else {
    validate_policy_principal(value).map(Some)
  }
}

fn collect_logical_roots(
  value: &Value,
  roots: &mut HashSet<String>,
) -> Result<(), String> {
  match value {
    Value::Array(values) => {
      for value in values {
        collect_logical_roots(value, roots)?;
      }
    }
    Value::Object(object) => {
      for (key, value) in object {
        if key == "root" {
          let root = value
            .as_str()
            .ok_or_else(|| "OD-CAP-REV2-ROOT-BINDING-LOGICAL".to_string())?;
          if !matches!(
            root,
            "$PROJECT" | "$PACKAGE" | "$HOME" | "$TMP" | "$ABS"
          ) {
            return Err("OD-CAP-REV2-ROOT-BINDING-LOGICAL".to_string());
          }
          roots.insert(root.to_string());
        }
        collect_logical_roots(value, roots)?;
      }
    }
    Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
  }
  Ok(())
}

fn collect_content_identities<'a>(
  value: &'a Value,
  identities: &mut Vec<(&'static str, String)>,
) -> Result<(), String> {
  match value {
    Value::Array(values) => {
      for value in values {
        collect_content_identities(value, identities)?;
      }
    }
    Value::Object(object) => {
      for (key, value) in object {
        if matches!(key.as_str(), "objectIdentity" | "interpreterIdentity") {
          let identity = exact_object(
            value,
            &["kind", "value"],
            "OD-CAP-REV2-CONTENT-IDENTITY-SHAPE",
          )?;
          require_string(identity, "kind", "verified-content")?;
          let digest = required_digest(identity, "value")?;
          identities.push((
            if key == "objectIdentity" {
              "object"
            } else {
              "interpreter"
            },
            digest.to_string(),
          ));
        } else {
          collect_content_identities(value, identities)?;
        }
      }
    }
    Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
  }
  Ok(())
}

fn collect_named_objects<'a>(
  value: &'a Value,
  field: &str,
  matches: &mut Vec<&'a Value>,
) -> Result<(), String> {
  match value {
    Value::Array(values) => {
      for value in values {
        collect_named_objects(value, field, matches)?;
      }
    }
    Value::Object(object) => {
      for (key, value) in object {
        if key == field {
          if !value.is_object() {
            return Err("OD-CAP-REV2-NAMED-OBJECT".to_string());
          }
          matches.push(value);
        } else {
          collect_named_objects(value, field, matches)?;
        }
      }
    }
    Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
  }
  Ok(())
}

fn root_requirement_key(
  source_id: &str,
  logical_root: &str,
  principal: Option<&PrincipalRef>,
) -> Result<String, String> {
  canonical_json(&serde_json::json!({
    "sourceId": source_id,
    "logicalRoot": logical_root,
    "principal": principal,
  }))
  .map_err(|_| "OD-CAP-REV2-ROOT-BINDING-CANONICAL".to_string())
}

fn executable_requirement_key(
  source_id: &str,
  role: &str,
  content: &str,
) -> Result<String, String> {
  canonical_json(&serde_json::json!({
    "sourceId": source_id,
    "role": role,
    "canonicalContentIdentity": content,
  }))
  .map_err(|_| "OD-CAP-REV2-EXECUTABLE-CANONICAL".to_string())
}

fn route_requirement_key(
  source_id: &str,
  resource_digest: &str,
  route_digest: &str,
) -> Result<String, String> {
  canonical_json(&serde_json::json!({
    "sourceId": source_id,
    "resourceDigest": resource_digest,
    "routeDigest": route_digest,
  }))
  .map_err(|_| "OD-CAP-REV2-ROUTE-CANONICAL".to_string())
}

fn classifier_requirement_key(
  source_id: &str,
  classifier_id: &str,
) -> Result<String, String> {
  canonical_json(&serde_json::json!({
    "sourceId": source_id,
    "classifierId": classifier_id,
  }))
  .map_err(|_| "OD-CAP-REV2-CLASSIFIER-CANONICAL".to_string())
}

fn find_generated_row<'a>(rows: &'a [Value], id: &str) -> Option<&'a Value> {
  rows
    .iter()
    .find(|row| row.get("id").and_then(Value::as_str) == Some(id))
}

fn canonical_unsigned(value: &str) -> bool {
  value == "0"
    || (!value.starts_with('0')
      && value.bytes().all(|byte| byte.is_ascii_digit()))
}

fn validate_and_open_bound_object(
  path_value: &Value,
  identity_value: &Value,
  expect_directory: bool,
) -> Result<File, String> {
  let path = parse_tagged_path(path_value)?;
  if !path.is_absolute() {
    return Err("OD-CAP-REV2-BOUND-PATH-ABSOLUTE".to_string());
  }
  let canonical = std::fs::canonicalize(&path)
    .map_err(|_| "OD-CAP-REV2-BOUND-PATH-CANONICAL".to_string())?;
  if canonical != path {
    return Err("OD-CAP-REV2-BOUND-PATH-CANONICAL".to_string());
  }
  let before = std::fs::symlink_metadata(&path)
    .map_err(|_| "OD-CAP-REV2-BOUND-PATH-METADATA".to_string())?;
  if before.file_type().is_symlink() {
    return Err("OD-CAP-REV2-BOUND-PATH-SYMLINK".to_string());
  }
  if (expect_directory && !before.is_dir())
    || (!expect_directory && !before.is_file())
  {
    return Err("OD-CAP-REV2-BOUND-PATH-TYPE".to_string());
  }
  let mut options = std::fs::OpenOptions::new();
  options.read(true);
  #[cfg(unix)]
  {
    use std::os::unix::fs::OpenOptionsExt;
    options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
  }
  #[cfg(not(unix))]
  return Err("OD-CAP-REV2-BOUND-PATH-PLATFORM".to_string());
  let file = options
    .open(&path)
    .map_err(|_| "OD-CAP-REV2-BOUND-PATH-OPEN".to_string())?;
  let metadata = file
    .metadata()
    .map_err(|_| "OD-CAP-REV2-BOUND-PATH-METADATA".to_string())?;
  if (expect_directory && !metadata.is_dir())
    || (!expect_directory && !metadata.is_file())
  {
    return Err("OD-CAP-REV2-BOUND-PATH-TYPE".to_string());
  }
  #[cfg(unix)]
  {
    use std::os::unix::fs::MetadataExt;
    if before.dev() != metadata.dev() || before.ino() != metadata.ino() {
      return Err("OD-CAP-REV2-BOUND-PATH-IDENTITY".to_string());
    }
    let identity = exact_object(
      identity_value,
      &["kind", "value"],
      "OD-CAP-REV2-BOUND-OBJECT-SHAPE",
    )?;
    require_string(identity, "kind", "platform-object")?;
    let expected = format!(
      "unix-dev-ino:{:016x}{:016x}",
      metadata.dev(),
      metadata.ino()
    );
    if identity.get("value").and_then(Value::as_str) != Some(&expected) {
      return Err("OD-CAP-REV2-BOUND-OBJECT-IDENTITY".to_string());
    }
  }
  Ok(file)
}

fn platform_object_identity(value: &Value) -> Result<String, String> {
  let identity =
    exact_object(value, &["kind", "value"], "OD-CAP-REV2-BOUND-OBJECT-SHAPE")?;
  require_string(identity, "kind", "platform-object")?;
  identity
    .get("value")
    .and_then(Value::as_str)
    .map(ToString::to_string)
    .ok_or_else(|| "OD-CAP-REV2-BOUND-OBJECT-IDENTITY".to_string())
}

#[cfg(unix)]
fn verify_opened_executable_content(
  file: &File,
  expected: &str,
) -> Result<(), String> {
  use std::os::unix::fs::FileExt;
  use std::os::unix::fs::MetadataExt;

  let before = file
    .metadata()
    .map_err(|_| "OD-CAP-REV2-EXECUTABLE-CONTENT-METADATA".to_string())?;
  if !before.is_file() {
    return Err("OD-CAP-REV2-EXECUTABLE-CONTENT-TYPE".to_string());
  }
  let mut digest = Sha256::new();
  let mut buffer = [0_u8; 64 * 1024];
  let mut offset = 0_u64;
  loop {
    let read = match file.read_at(&mut buffer, offset) {
      Ok(read) => read,
      Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
      Err(_) => return Err("OD-CAP-REV2-EXECUTABLE-CONTENT-READ".to_string()),
    };
    if read == 0 {
      break;
    }
    digest.update(&buffer[..read]);
    offset = offset
      .checked_add(read as u64)
      .ok_or_else(|| "OD-CAP-REV2-EXECUTABLE-CONTENT-BOUNDS".to_string())?;
  }
  let after = file
    .metadata()
    .map_err(|_| "OD-CAP-REV2-EXECUTABLE-CONTENT-METADATA".to_string())?;
  if before.dev() != after.dev()
    || before.ino() != after.ino()
    || before.len() != after.len()
    || before.mtime() != after.mtime()
    || before.mtime_nsec() != after.mtime_nsec()
    || before.ctime() != after.ctime()
    || before.ctime_nsec() != after.ctime_nsec()
    || offset != after.len()
  {
    return Err("OD-CAP-REV2-EXECUTABLE-CONTENT-RACED".to_string());
  }
  let actual = format!("sha256-{}", URL_SAFE_NO_PAD.encode(digest.finalize()));
  if actual != expected {
    return Err("OD-CAP-REV2-EXECUTABLE-CONTENT-DIGEST".to_string());
  }
  Ok(())
}

#[cfg(not(unix))]
fn verify_opened_executable_content(
  _file: &File,
  _expected: &str,
) -> Result<(), String> {
  Err("OD-CAP-REV2-EXECUTABLE-CONTENT-PLATFORM".to_string())
}

fn parse_tagged_path(value: &Value) -> Result<PathBuf, String> {
  let tagged = exact_object(
    value,
    &["encoding", "value"],
    "OD-CAP-REV2-BOUND-PATH-SHAPE",
  )?;
  let encoding = tagged
    .get("encoding")
    .and_then(Value::as_str)
    .ok_or_else(|| "OD-CAP-REV2-BOUND-PATH-ENCODING".to_string())?;
  let value = bounded_nonempty(tagged, "value", 32_768)?;
  match encoding {
    "unicode" => Ok(PathBuf::from(value)),
    "bytes" => {
      let bytes = URL_SAFE_NO_PAD
        .decode(value)
        .ok()
        .filter(|bytes| {
          !bytes.is_empty() && URL_SAFE_NO_PAD.encode(bytes) == value
        })
        .ok_or_else(|| "OD-CAP-REV2-BOUND-PATH-BYTES".to_string())?;
      #[cfg(unix)]
      {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;
        Ok(PathBuf::from(OsString::from_vec(bytes)))
      }
      #[cfg(not(unix))]
      {
        let _ = bytes;
        Err("OD-CAP-REV2-BOUND-PATH-PLATFORM".to_string())
      }
    }
    _ => Err("OD-CAP-REV2-BOUND-PATH-ENCODING".to_string()),
  }
}

fn exact_object<'a>(
  value: &'a Value,
  expected: &[&str],
  reason: &str,
) -> Result<&'a Map<String, Value>, String> {
  let object = value.as_object().ok_or_else(|| reason.to_string())?;
  let mut actual: Vec<&str> = object.keys().map(String::as_str).collect();
  actual.sort_unstable();
  let mut expected = expected.to_vec();
  expected.sort_unstable();
  if actual != expected {
    return Err(reason.to_string());
  }
  Ok(object)
}

fn require_string(
  object: &Map<String, Value>,
  field: &str,
  expected: &str,
) -> Result<(), String> {
  if object.get(field).and_then(Value::as_str) != Some(expected) {
    return Err(format!("OD-CAP-REV2-{field}-MISMATCH"));
  }
  Ok(())
}

fn required_mode<'a>(
  object: &'a Map<String, Value>,
  field: &str,
) -> Result<&'a str, String> {
  object
    .get(field)
    .and_then(Value::as_str)
    .filter(|mode| matches!(*mode, "permissive" | "audit" | "enforce"))
    .ok_or_else(|| format!("OD-CAP-REV2-{field}-INVALID"))
}

fn bounded_nonempty<'a>(
  object: &'a Map<String, Value>,
  field: &str,
  maximum: usize,
) -> Result<&'a str, String> {
  object
    .get(field)
    .and_then(Value::as_str)
    .filter(|value| !value.trim().is_empty() && value.len() <= maximum)
    .ok_or_else(|| format!("OD-CAP-REV2-{field}-INVALID"))
}

fn required_digest<'a>(
  object: &'a Map<String, Value>,
  field: &str,
) -> Result<&'a str, String> {
  object
    .get(field)
    .and_then(Value::as_str)
    .filter(|digest| valid_digest(digest))
    .ok_or_else(|| format!("OD-CAP-REV2-{field}-INVALID"))
}

fn valid_digest(digest: &str) -> bool {
  digest
    .strip_prefix("sha256-")
    .filter(|encoded| encoded.len() == 43)
    .and_then(|encoded| {
      URL_SAFE_NO_PAD
        .decode(encoded)
        .ok()
        .map(|bytes| (encoded, bytes))
    })
    .is_some_and(|(encoded, bytes)| {
      bytes.len() == 32 && URL_SAFE_NO_PAD.encode(bytes) == encoded
    })
}

fn require_canonical_set(rows: &[Value], field: &str) -> Result<(), String> {
  let mut prior: Option<String> = None;
  for row in rows {
    let canonical = canonical_json(row)
      .map_err(|_| format!("OD-CAP-REV2-{field}-CANONICAL"))?;
    if prior.as_ref().is_some_and(|prior| prior >= &canonical) {
      return Err(format!("OD-CAP-REV2-{field}-SET"));
    }
    prior = Some(canonical);
  }
  Ok(())
}

fn reject_display_or_source_fields(value: &Value) -> Result<(), String> {
  match value {
    Value::Array(values) => {
      for value in values {
        reject_display_or_source_fields(value)?;
      }
    }
    Value::Object(object) => {
      for (key, value) in object {
        if matches!(
          key.as_str(),
          "alias"
            | "aliases"
            | "comment"
            | "comments"
            | "display"
            | "macro"
            | "macros"
            | "reason"
        ) {
          return Err("OD-CAP-REV2-DISPLAY-OR-SOURCE-DATA".to_string());
        }
        reject_display_or_source_fields(value)?;
      }
    }
    Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => {}
  }
  Ok(())
}

#[cfg(all(feature = "capsec_fixture_test", debug_assertions, unix))]
pub(crate) mod fixture_support {
  use super::*;

  fn embedded_target()
  -> &'static crate::rev2_registry_generated::Rev2TargetStatus {
    let target =
      compiled_target().expect("fixture host has a generated Rev2 target");
    REV2_TARGET_STATUS
      .iter()
      .find(|status| status.target == target)
      .expect("compiled fixture target is present in the generated registry")
  }

  fn hermetic_target() -> TargetStatus<'static> {
    let embedded = embedded_target();
    TargetStatus {
      target: embedded.target,
      feature_set: embedded.feature_set,
      profile_claim: "test-conformant",
      conformance_report_digest: Some(REV2_REGISTRY_DIGEST),
      enforced: 996,
      closed: 0,
      absent: 0,
      unsupported: 0,
      advertised: false,
      hermetic: true,
    }
  }

  pub(crate) fn candidate_snapshot(mode: &str) -> Value {
    assert!(matches!(mode, "permissive" | "audit" | "enforce"));
    let target = hermetic_target();
    let mut policy = serde_json::json!({
      "policySchema": POLICY_SCHEMA,
      "capsVocab": REV2_PROFILE,
      "vocabDigest": REV2_VOCAB_DIGEST,
      "policyDigest": "",
      "mode": mode,
      "principals": [],
      "processDenials": [],
    });
    let mut policy_basis = policy.clone();
    policy_basis.as_object_mut().unwrap().remove("policyDigest");
    let policy_digest =
      domain_digest("oden:capsec:policy:2", &policy_basis).unwrap();
    policy["policyDigest"] = Value::String(policy_digest.clone());
    let receipts = Value::Array(Vec::new());
    let receipt_digest = domain_digest(RECEIPT_SET_DOMAIN, &receipts).unwrap();
    let mut snapshot = serde_json::json!({
      "snapshotSchema": SNAPSHOT_SCHEMA,
      "capsVocab": REV2_PROFILE,
      "vocabDigest": REV2_VOCAB_DIGEST,
      "registryDigest": REV2_REGISTRY_DIGEST,
      "policyDigest": policy_digest,
      "projectDigest": REV2_REGISTRY_DIGEST,
      "armedSnapshotDigest": "",
      "engineTarget": target.target,
      "engineFeatureSet": target.feature_set,
      "executionRole": "probe",
      "conformanceReportDigest": REV2_REGISTRY_DIGEST,
      "effectiveMode": mode,
      "runNonce": "run:dynamic-permission-fixture",
      "channelEpoch": "channel:dynamic-permission-fixture",
      "canonicalPolicy": policy,
      "rootBindings": [],
      "denyCeiling": [],
      "executableBindings": [],
      "routeBindings": [],
      "classifierBindings": [],
      "protectedPredicateVersions": [],
      "protectedReceiptBindings": receipts,
      "protectedReceiptSetDigest": receipt_digest,
    });
    refresh_digests(&mut snapshot);
    snapshot
  }

  pub(crate) fn refresh_digests(snapshot: &mut Value) {
    let policy = snapshot["canonicalPolicy"].as_object_mut().unwrap();
    policy.remove("policyDigest");
    let policy_digest =
      domain_digest("oden:capsec:policy:2", &Value::Object(policy.clone()))
        .unwrap();
    policy.insert(
      "policyDigest".to_string(),
      Value::String(policy_digest.clone()),
    );
    snapshot["policyDigest"] = Value::String(policy_digest);
    snapshot
      .as_object_mut()
      .unwrap()
      .remove("armedSnapshotDigest");
    snapshot["armedSnapshotDigest"] =
      Value::String(domain_digest("oden:capsec:armed:2", snapshot).unwrap());
  }

  fn envelope(snapshot: Value, key: &[u8; 32]) -> Vec<u8> {
    let key_id =
      format!("sha256-{}", URL_SAFE_NO_PAD.encode(Sha256::digest(key)));
    let mut signer = <Hmac<Sha256> as Mac>::new_from_slice(key).unwrap();
    signer.update(ENVELOPE_AUTH_DOMAIN.as_bytes());
    signer.update(key_id.as_bytes());
    signer.update(canonical_json(&snapshot).unwrap().as_bytes());
    let tag = URL_SAFE_NO_PAD.encode(signer.finalize().into_bytes());
    serde_json::to_vec(&serde_json::json!({
      "schema": ENVELOPE_SCHEMA,
      "snapshot": snapshot,
      "mac": {
        "algorithm": "hmac-sha256",
        "keyId": key_id,
        "tag": tag,
      },
    }))
    .unwrap()
  }

  pub(crate) fn load_snapshot(
    mut snapshot: Value,
    key: &[u8; 32],
  ) -> OdenRev2LoadedPolicyContext {
    snapshot["conformanceReportDigest"] =
      Value::String(REV2_REGISTRY_DIGEST.to_string());
    refresh_digests(&mut snapshot);
    let authenticated =
      parse_authenticated_snapshot(&envelope(snapshot, key), key).unwrap();
    verify_snapshot(&authenticated, hermetic_target()).unwrap()
  }

  #[cfg(unix)]
  pub(crate) fn file_digest(path: &std::path::Path) -> String {
    format!(
      "sha256-{}",
      URL_SAFE_NO_PAD.encode(Sha256::digest(std::fs::read(path).unwrap()))
    )
  }

  #[cfg(unix)]
  pub(crate) fn object_identity(path: &std::path::Path) -> Value {
    use std::os::unix::fs::MetadataExt;
    let metadata = std::fs::metadata(path).unwrap();
    serde_json::json!({
      "kind": "platform-object",
      "value": format!(
        "unix-dev-ino:{:016x}{:016x}",
        metadata.dev(),
        metadata.ino(),
      ),
    })
  }

  pub(crate) fn target() -> &'static str {
    embedded_target().target
  }
}

#[cfg(test)]
pub(crate) mod tests {
  use super::*;

  pub(crate) fn embedded_compiled_target()
  -> &'static crate::rev2_registry_generated::Rev2TargetStatus {
    let target =
      compiled_target().expect("test host has a generated Rev2 target");
    REV2_TARGET_STATUS
      .iter()
      .find(|status| status.target == target)
      .expect("compiled target is present in the generated registry")
  }

  fn test_build_identity() -> OdenRev2CompiledBuildIdentity {
    let target = embedded_compiled_target();
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

  fn verify_authenticated_envelope(
    bytes: &[u8],
    key: &[u8],
  ) -> Result<OdenRev2LoadedPolicyContext, String> {
    super::verify_authenticated_envelope(bytes, key, &test_build_identity())
  }

  pub(crate) fn candidate_snapshot(
    target: TargetStatus<'_>,
    report: Option<&str>,
  ) -> Value {
    let mut policy = serde_json::json!({
      "policySchema": POLICY_SCHEMA,
      "capsVocab": REV2_PROFILE,
      "vocabDigest": REV2_VOCAB_DIGEST,
      "policyDigest": "",
      "mode": "enforce",
      "principals": [],
      "processDenials": [],
    });
    let mut policy_basis = policy.clone();
    policy_basis.as_object_mut().unwrap().remove("policyDigest");
    let policy_digest =
      domain_digest("oden:capsec:policy:2", &policy_basis).unwrap();
    policy["policyDigest"] = Value::String(policy_digest.clone());
    let receipts = Value::Array(Vec::new());
    let receipt_digest = domain_digest(RECEIPT_SET_DOMAIN, &receipts).unwrap();
    let mut snapshot = serde_json::json!({
      "snapshotSchema": SNAPSHOT_SCHEMA,
      "capsVocab": REV2_PROFILE,
      "vocabDigest": REV2_VOCAB_DIGEST,
      "registryDigest": REV2_REGISTRY_DIGEST,
      "policyDigest": policy_digest,
      "projectDigest": REV2_REGISTRY_DIGEST,
      "armedSnapshotDigest": "",
      "engineTarget": target.target,
      "engineFeatureSet": target.feature_set,
      "executionRole": "probe",
      "conformanceReportDigest": report,
      "effectiveMode": "enforce",
      "runNonce": "run:test",
      "channelEpoch": "channel:test",
      "canonicalPolicy": policy,
      "rootBindings": [],
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
      .unwrap()
      .remove("armedSnapshotDigest");
    snapshot["armedSnapshotDigest"] = Value::String(
      domain_digest("oden:capsec:armed:2", &armed_basis).unwrap(),
    );
    snapshot
  }

  pub(crate) fn envelope(snapshot: Value, key: &[u8; 32]) -> Vec<u8> {
    let key_id =
      format!("sha256-{}", URL_SAFE_NO_PAD.encode(Sha256::digest(key)));
    let mut signer = <Hmac<Sha256> as Mac>::new_from_slice(key).unwrap();
    signer.update(ENVELOPE_AUTH_DOMAIN.as_bytes());
    signer.update(key_id.as_bytes());
    signer.update(canonical_json(&snapshot).unwrap().as_bytes());
    let tag = URL_SAFE_NO_PAD.encode(signer.finalize().into_bytes());
    serde_json::to_vec(&serde_json::json!({
      "schema": ENVELOPE_SCHEMA,
      "snapshot": snapshot,
      "mac": {
        "algorithm": "hmac-sha256",
        "keyId": key_id,
        "tag": tag,
      },
    }))
    .unwrap()
  }

  pub(crate) fn refresh_digests(snapshot: &mut Value) {
    let policy = snapshot["canonicalPolicy"].as_object_mut().unwrap();
    policy.remove("policyDigest");
    let policy_digest =
      domain_digest("oden:capsec:policy:2", &Value::Object(policy.clone()))
        .unwrap();
    policy.insert(
      "policyDigest".to_string(),
      Value::String(policy_digest.clone()),
    );
    snapshot["policyDigest"] = Value::String(policy_digest);
    snapshot
      .as_object_mut()
      .unwrap()
      .remove("armedSnapshotDigest");
    let digest = domain_digest("oden:capsec:armed:2", snapshot).unwrap();
    snapshot["armedSnapshotDigest"] = Value::String(digest);
  }

  pub(crate) fn hermetic_target() -> TargetStatus<'static> {
    let embedded = embedded_compiled_target();
    TargetStatus {
      target: embedded.target,
      feature_set: embedded.feature_set,
      profile_claim: "test-conformant",
      conformance_report_digest: Some(REV2_REGISTRY_DIGEST),
      enforced: 996,
      closed: 0,
      absent: 0,
      unsupported: 0,
      advertised: false,
      hermetic: true,
    }
  }

  pub(crate) fn verify_armable_snapshot(
    mut snapshot: Value,
    key: &[u8; 32],
  ) -> Result<OdenRev2LoadedPolicyContext, String> {
    snapshot["conformanceReportDigest"] =
      Value::String(REV2_REGISTRY_DIGEST.to_string());
    refresh_digests(&mut snapshot);
    let authenticated =
      parse_authenticated_snapshot(&envelope(snapshot, key), key)?;
    verify_snapshot(&authenticated, hermetic_target())
  }

  pub(crate) fn verified_unarmed_empty_context(
    key: &[u8; 32],
  ) -> OdenRev2LoadedPolicyContext {
    let embedded = embedded_compiled_target();
    let target = TargetStatus {
      target: embedded.target,
      feature_set: embedded.feature_set,
      profile_claim: embedded.profile_claim,
      conformance_report_digest: None,
      enforced: embedded.enforced,
      closed: embedded.closed,
      absent: embedded.absent,
      unsupported: embedded.unsupported,
      advertised: false,
      hermetic: false,
    };
    let snapshot = candidate_snapshot(target, None);
    verify_authenticated_envelope(&envelope(snapshot, key), key).unwrap()
  }

  pub(crate) fn candidate_with_env_policy(target: TargetStatus<'_>) -> Value {
    let mut snapshot = candidate_snapshot(target, None);
    let principal = PrincipalRef {
      kind: PrincipalKind::Package,
      key: "pkg:sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
    };
    let selector = Rev2Core::embedded()
      .unwrap()
      .normalize_selector(
        &AuthoritySelectorInput {
          identity: EngineIdentity::embedded(),
          principal: Some(principal.clone()),
          capability: "env:read".to_string(),
          resource: serde_json::json!({ "name": "TOKEN" }),
        },
        SelectorPolarity::Positive,
      )
      .unwrap();
    snapshot["canonicalPolicy"]["principals"] = serde_json::json!([{
      "principal": principal,
      "binding": {
        "resolverId": "fixture-lock-resolver/2",
        "bindingDigest": REV2_VOCAB_DIGEST,
      },
      "floor": [{ "sourceId": "floor:env", "selector": selector }],
      "escalationCeiling": [],
      "denials": [],
    }]);
    refresh_digests(&mut snapshot);
    snapshot
  }

  #[cfg(unix)]
  pub(crate) fn candidate_with_executable_policy(
    target: TargetStatus<'_>,
    object_path: &std::path::Path,
    interpreter_path: &std::path::Path,
  ) -> Value {
    let principal = PrincipalRef {
      kind: PrincipalKind::Package,
      key: "pkg:sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
    };
    let object_digest = file_sha256_digest(object_path);
    let interpreter_digest = file_sha256_digest(interpreter_path);
    let selector = Rev2Core::embedded()
      .unwrap()
      .normalize_selector(
        &AuthoritySelectorInput {
          identity: EngineIdentity::embedded(),
          principal: Some(principal.clone()),
          capability: "process:spawn".to_string(),
          resource: serde_json::json!({
            "interpreterIdentity": {
              "kind": "verified-content",
              "value": interpreter_digest,
            },
            "objectIdentity": {
              "kind": "verified-content",
              "value": object_digest,
            },
            "path": { "encoding": "unicode", "value": "$PACKAGE/bin/worker" },
          }),
        },
        SelectorPolarity::Positive,
      )
      .unwrap();
    let mut snapshot = candidate_snapshot(target, None);
    snapshot["canonicalPolicy"]["principals"] = serde_json::json!([{
      "principal": principal.clone(),
      "binding": {
        "resolverId": "fixture-lock-resolver/2",
        "bindingDigest": REV2_VOCAB_DIGEST,
      },
      "floor": [{ "sourceId": "floor:spawn", "selector": selector }],
      "escalationCeiling": [],
      "denials": [],
    }]);
    snapshot["executableBindings"] = serde_json::json!([
      {
        "sourceId": "floor:spawn",
        "role": "interpreter",
        "canonicalContentIdentity": interpreter_digest,
        "bindingId": "executable:interpreter",
        "principal": principal.clone(),
        "canonicalPath": {
          "encoding": "unicode",
          "value": interpreter_path.to_str().unwrap(),
        },
        "objectIdentity": platform_identity(interpreter_path),
        "provenanceDigest": REV2_REGISTRY_DIGEST,
      },
      {
        "sourceId": "floor:spawn",
        "role": "object",
        "canonicalContentIdentity": object_digest,
        "bindingId": "executable:object",
        "principal": principal,
        "canonicalPath": {
          "encoding": "unicode",
          "value": object_path.to_str().unwrap(),
        },
        "objectIdentity": platform_identity(object_path),
        "provenanceDigest": REV2_REGISTRY_DIGEST,
      },
    ]);
    refresh_digests(&mut snapshot);
    snapshot
  }

  #[cfg(unix)]
  pub(crate) fn file_sha256_digest(path: &std::path::Path) -> String {
    format!(
      "sha256-{}",
      URL_SAFE_NO_PAD.encode(Sha256::digest(std::fs::read(path).unwrap()))
    )
  }

  #[cfg(unix)]
  pub(crate) fn platform_identity(path: &std::path::Path) -> Value {
    use std::os::unix::fs::MetadataExt;
    let metadata = std::fs::metadata(path).unwrap();
    serde_json::json!({
      "kind": "platform-object",
      "value": format!(
        "unix-dev-ino:{:016x}{:016x}",
        metadata.dev(),
        metadata.ino(),
      ),
    })
  }

  #[test]
  fn unknown_envelope_fields_and_bad_auth_fail_closed() {
    let key = [7_u8; 32];
    let bad = br#"{"schema":"oden/capsec-armed-envelope/2","snapshot":{},"mac":{"algorithm":"hmac-sha256","keyId":"bad","tag":"bad"},"extra":true}"#;
    assert!(matches!(
      verify_authenticated_envelope(bad, &key),
      Err(reason) if reason == "OD-CAP-REV2-ENVELOPE-SHAPE"
    ));
  }

  #[test]
  fn compiled_build_identity_must_match_every_generated_feature_field() {
    let expected = embedded_compiled_target();
    let exact = test_build_identity();
    assert!(validate_compiled_build_identity(expected, &exact).is_ok());
    for actual in [
      OdenRev2CompiledBuildIdentity {
        build_profile: "debug",
        ..exact
      },
      OdenRev2CompiledBuildIdentity {
        cargo_features: "__vendored_zlib_ng,default,hmr,upgrade",
        ..exact
      },
      OdenRev2CompiledBuildIdentity {
        cargo_features: "__vendored_zlib_ng,upgrade",
        ..exact
      },
      OdenRev2CompiledBuildIdentity {
        rust_cfg_digest: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        ..exact
      },
      OdenRev2CompiledBuildIdentity {
        cargo_feature_graph_digest: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
        ..exact
      },
      OdenRev2CompiledBuildIdentity {
        rust_toolchain: "0.0.0",
        ..exact
      },
      OdenRev2CompiledBuildIdentity {
        target: "unknown-target",
        ..exact
      },
      OdenRev2CompiledBuildIdentity {
        actual_panic_strategy: "unwind",
        ..exact
      },
      OdenRev2CompiledBuildIdentity {
        actual_debug_assertions: true,
        ..exact
      },
      OdenRev2CompiledBuildIdentity {
        marker_panic_strategy: "unwind",
        ..exact
      },
      OdenRev2CompiledBuildIdentity {
        marker_debug_assertions: "not-a-boolean",
        ..exact
      },
    ] {
      assert_eq!(
        validate_compiled_build_identity(expected, &actual),
        Err("OD-CAP-REV2-FEATURE-BINARY-MISMATCH".to_string())
      );
    }
  }

  #[test]
  fn candidate_current_binary_join_requires_native_and_release_cfg_facts() {
    let expected = embedded_compiled_target();
    let exact = test_build_identity();
    assert!(
      validate_compiled_build_identity_against_native_facts(
        expected,
        &exact,
        expected.target,
        "abort",
        false,
      )
      .is_ok()
    );

    for (native_target, panic_strategy, debug_assertions) in [
      ("alias-target", "abort", false),
      (expected.target, "unwind", false),
      (expected.target, "abort", true),
    ] {
      assert_eq!(
        validate_compiled_build_identity_against_native_facts(
          expected,
          &exact,
          native_target,
          panic_strategy,
          debug_assertions,
        ),
        Err("OD-CAP-REV2-FEATURE-BINARY-MISMATCH".to_string())
      );
    }
  }

  #[test]
  fn candidate_current_binary_join_refuses_stale_or_missing_marker_facts() {
    let expected = embedded_compiled_target();
    let exact = test_build_identity();
    for actual in [
      OdenRev2CompiledBuildIdentity {
        rust_toolchain: "",
        ..exact
      },
      OdenRev2CompiledBuildIdentity {
        cargo_features: "__vendored_zlib_ng,default",
        ..exact
      },
      OdenRev2CompiledBuildIdentity {
        rust_cfg_digest: "sha256:stale",
        ..exact
      },
      OdenRev2CompiledBuildIdentity {
        cargo_feature_graph_digest: "sha256:stale",
        ..exact
      },
      OdenRev2CompiledBuildIdentity {
        build_profile: "",
        ..exact
      },
      OdenRev2CompiledBuildIdentity {
        marker_panic_strategy: "",
        ..exact
      },
      OdenRev2CompiledBuildIdentity {
        marker_debug_assertions: "",
        ..exact
      },
    ] {
      assert_eq!(
        validate_compiled_build_identity_against_native_facts(
          expected,
          &actual,
          expected.target,
          "abort",
          false,
        ),
        Err("OD-CAP-REV2-FEATURE-BINARY-MISMATCH".to_string())
      );
    }
  }

  #[test]
  fn production_candidate_is_verified_but_never_armed_or_advertised() {
    let key = [9_u8; 32];
    let embedded = embedded_compiled_target();
    let target = TargetStatus {
      target: embedded.target,
      feature_set: embedded.feature_set,
      profile_claim: embedded.profile_claim,
      conformance_report_digest: None,
      enforced: embedded.enforced,
      closed: embedded.closed,
      absent: embedded.absent,
      unsupported: embedded.unsupported,
      advertised: false,
      hermetic: false,
    };
    let snapshot = candidate_snapshot(target, None);
    let context =
      verify_authenticated_envelope(&envelope(snapshot, &key), &key).unwrap();
    assert_eq!(context.state(), OdenRev2LoadState::VerifiedUnarmed);
    assert!(
      context
        .blockers()
        .iter()
        .any(|blocker| blocker.starts_with("target-unsupported-cells:"))
    );
    assert!(
      context
        .blockers()
        .contains(&"target-not-advertised".to_string())
    );
    let evidence = context.evidence();
    assert_eq!(evidence["armed"], false);
    assert_eq!(evidence["executionRole"], "probe");
    assert_eq!(
      evidence["loadedArmedSnapshotDigest"],
      evidence["armedSnapshotDigest"]
    );
    assert_eq!(evidence["projectDigest"], REV2_REGISTRY_DIGEST);
  }

  #[test]
  fn authenticated_tamper_and_digest_mutation_refuse() {
    let key = [11_u8; 32];
    let embedded = embedded_compiled_target();
    let target = TargetStatus {
      target: embedded.target,
      feature_set: embedded.feature_set,
      profile_claim: embedded.profile_claim,
      conformance_report_digest: None,
      enforced: embedded.enforced,
      closed: embedded.closed,
      absent: embedded.absent,
      unsupported: embedded.unsupported,
      advertised: false,
      hermetic: false,
    };
    let mut encoded = envelope(candidate_snapshot(target, None), &key);
    let index = encoded
      .windows(b"run:test".len())
      .position(|window| window == b"run:test")
      .unwrap();
    encoded[index] = b'R';
    assert!(matches!(
      verify_authenticated_envelope(&encoded, &key),
      Err(reason) if reason == "OD-CAP-REV2-AUTH-FAILED"
    ));

    let mut snapshot = candidate_snapshot(target, None);
    snapshot["policyDigest"] = Value::String(
      "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
    );
    assert!(matches!(
      verify_authenticated_envelope(&envelope(snapshot, &key), &key),
      Err(reason) if reason == "OD-CAP-REV2-POLICY-DIGEST-MISMATCH"
    ));
  }

  #[test]
  fn nested_policy_shapes_principals_and_core_normalization_fail_closed() {
    let key = [13_u8; 32];
    let embedded = embedded_compiled_target();
    let target = TargetStatus {
      target: embedded.target,
      feature_set: embedded.feature_set,
      profile_claim: embedded.profile_claim,
      conformance_report_digest: None,
      enforced: embedded.enforced,
      closed: embedded.closed,
      absent: embedded.absent,
      unsupported: embedded.unsupported,
      advertised: false,
      hermetic: false,
    };
    let snapshot = candidate_with_env_policy(target);
    verify_authenticated_envelope(&envelope(snapshot.clone(), &key), &key)
      .unwrap();

    let mut projection = snapshot.clone();
    projection["canonicalPolicy"]["principals"][0]["floor"][0]["selector"]["projectionId"] =
      Value::String("projection:forged".to_string());
    refresh_digests(&mut projection);
    assert!(matches!(
      verify_authenticated_envelope(&envelope(projection, &key), &key),
      Err(reason) if reason == "OD-CAP-REV2-SELECTOR-NONCANONICAL"
    ));

    let mut unknown = snapshot.clone();
    unknown["canonicalPolicy"]["principals"][0]["binding"]["extra"] =
      Value::Bool(true);
    refresh_digests(&mut unknown);
    assert!(matches!(
      verify_authenticated_envelope(&envelope(unknown, &key), &key),
      Err(reason) if reason == "OD-CAP-REV2-PRINCIPAL-BINDING-SHAPE"
    ));

    let mut protected = snapshot.clone();
    let source_id =
      protected["canonicalPolicy"]["principals"][0]["floor"][0]["sourceId"]
        .clone();
    let selector =
      protected["canonicalPolicy"]["principals"][0]["floor"][0]["selector"]
        .clone();
    let predicate_id = "predicate.protected-receipt/2";
    let reason_digest = REV2_REGISTRY_DIGEST;
    let protected_digest = domain_digest(
      "oden:capsec:protected-row:2",
      &serde_json::json!({
        "sourceId": source_id,
        "selector": selector,
        "predicateId": predicate_id,
        "reasonDigest": reason_digest,
      }),
    )
    .unwrap();
    protected["canonicalPolicy"]["principals"][0]["floor"][0]["protected"] = serde_json::json!({
      "predicateId": predicate_id,
      "reasonDigest": reason_digest,
      "canonicalRowDigest": protected_digest,
    });
    refresh_digests(&mut protected);
    assert!(matches!(
      verify_authenticated_envelope(&envelope(protected, &key), &key),
      Err(reason) if reason == "OD-CAP-REV2-PROTECTED-UNREGISTERED"
    ));

    let mut runtime = snapshot;
    runtime["canonicalPolicy"]["principals"][0]["principal"] =
      serde_json::json!({ "kind": "runtime", "key": "runtime:internal" });
    refresh_digests(&mut runtime);
    assert!(matches!(
      verify_authenticated_envelope(&envelope(runtime, &key), &key),
      Err(reason) if reason == "OD-CAP-REV2-PRINCIPAL-RECIPIENT"
    ));
  }

  #[cfg(unix)]
  #[test]
  fn root_bindings_are_exact_revalidated_and_retained() {
    let key = [15_u8; 32];
    let embedded = embedded_compiled_target();
    let target = TargetStatus {
      target: embedded.target,
      feature_set: embedded.feature_set,
      profile_claim: embedded.profile_claim,
      conformance_report_digest: None,
      enforced: embedded.enforced,
      closed: embedded.closed,
      absent: embedded.absent,
      unsupported: embedded.unsupported,
      advertised: false,
      hermetic: false,
    };
    let principal = PrincipalRef {
      kind: PrincipalKind::Package,
      key: "pkg:sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string(),
    };
    let selector = Rev2Core::embedded()
      .unwrap()
      .normalize_selector(
        &AuthoritySelectorInput {
          identity: EngineIdentity::embedded(),
          principal: Some(principal.clone()),
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
    let unique = std::time::SystemTime::now()
      .duration_since(std::time::UNIX_EPOCH)
      .unwrap()
      .as_nanos();
    let raw = std::env::temp_dir()
      .join(format!("oden-rev2-root-{}-{unique}", std::process::id()));
    std::fs::create_dir(&raw).unwrap();
    let root = std::fs::canonicalize(&raw).unwrap();
    let mut snapshot = candidate_snapshot(target, None);
    snapshot["canonicalPolicy"]["principals"] = serde_json::json!([{
      "principal": principal.clone(),
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
      "principal": principal,
      "rootBindingId": "root-binding:project",
      "canonicalPath": {
        "encoding": "unicode",
        "value": root.to_str().unwrap(),
      },
      "objectIdentity": platform_identity(&root),
      "bindingProvenanceDigest": REV2_REGISTRY_DIGEST,
    }]);
    refresh_digests(&mut snapshot);
    let context =
      verify_authenticated_envelope(&envelope(snapshot.clone(), &key), &key)
        .unwrap();
    assert_eq!(context.retained_objects().len(), 1);
    assert_eq!(
      context.retained_objects()[0].binding_id(),
      "root-binding:project"
    );

    let mut missing = snapshot.clone();
    missing["rootBindings"] = Value::Array(Vec::new());
    refresh_digests(&mut missing);
    assert!(matches!(
      verify_authenticated_envelope(&envelope(missing, &key), &key),
      Err(reason) if reason == "OD-CAP-REV2-ROOT-BINDING-COVERAGE"
    ));

    let mut wrong_identity = snapshot;
    wrong_identity["rootBindings"][0]["objectIdentity"]["value"] =
      Value::String(
        "unix-dev-ino:00000000000000000000000000000000".to_string(),
      );
    refresh_digests(&mut wrong_identity);
    assert!(matches!(
      verify_authenticated_envelope(&envelope(wrong_identity, &key), &key),
      Err(reason) if reason == "OD-CAP-REV2-BOUND-OBJECT-IDENTITY"
    ));
    drop(context);
    std::fs::remove_dir(root).unwrap();
  }

  #[cfg(unix)]
  #[test]
  fn executable_bindings_hash_opened_bytes_and_retain_exact_objects() {
    use std::os::unix::fs::MetadataExt;

    let key = [17_u8; 32];
    let embedded = embedded_compiled_target();
    let target = TargetStatus {
      target: embedded.target,
      feature_set: embedded.feature_set,
      profile_claim: embedded.profile_claim,
      conformance_report_digest: None,
      enforced: embedded.enforced,
      closed: embedded.closed,
      absent: embedded.absent,
      unsupported: embedded.unsupported,
      advertised: false,
      hermetic: false,
    };
    let unique = std::time::SystemTime::now()
      .duration_since(std::time::UNIX_EPOCH)
      .unwrap()
      .as_nanos();
    let raw = std::env::temp_dir().join(format!(
      "oden-rev2-executable-{}-{unique}",
      std::process::id()
    ));
    std::fs::create_dir(&raw).unwrap();
    let object = raw.join("worker.js");
    let interpreter = raw.join("interpreter");
    std::fs::write(&object, b"console.log('verified');\n").unwrap();
    std::fs::write(&interpreter, b"verified interpreter bytes\n").unwrap();
    let object = std::fs::canonicalize(object).unwrap();
    let interpreter = std::fs::canonicalize(interpreter).unwrap();
    let snapshot =
      candidate_with_executable_policy(target, &object, &interpreter);
    let context =
      verify_authenticated_envelope(&envelope(snapshot.clone(), &key), &key)
        .unwrap();
    assert_eq!(context.retained_objects().len(), 2);
    assert!(
      context
        .retained_objects()
        .iter()
        .any(|object| object.role() == Some("object"))
    );
    let retained_object = context
      .retained_objects()
      .iter()
      .find(|retained| retained.role() == Some("object"))
      .unwrap();
    assert_eq!(
      retained_object.provenance_digest(),
      Some(REV2_REGISTRY_DIGEST)
    );
    assert_eq!(retained_object.canonical_path(), object);
    let inode = std::fs::metadata(&object).unwrap().ino();
    std::fs::write(&object, b"console.log('mutated');\n").unwrap();
    assert_eq!(std::fs::metadata(&object).unwrap().ino(), inode);
    assert!(matches!(
      verify_authenticated_envelope(&envelope(snapshot, &key), &key),
      Err(reason) if reason == "OD-CAP-REV2-EXECUTABLE-CONTENT-DIGEST"
    ));
    drop(context);
    std::fs::remove_dir_all(raw).unwrap();
  }

  #[test]
  fn hermetic_conformant_registry_can_arm_without_a_production_override() {
    let embedded = &REV2_TARGET_STATUS[0];
    let report = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let target = TargetStatus {
      target: embedded.target,
      feature_set: embedded.feature_set,
      profile_claim: "test-conformant",
      conformance_report_digest: Some(report),
      enforced: 996,
      closed: 0,
      absent: 0,
      unsupported: 0,
      advertised: false,
      hermetic: true,
    };
    let snapshot = candidate_snapshot(target, Some(report));
    let key = [23_u8; 32];
    let authenticated =
      parse_authenticated_snapshot(&envelope(snapshot, &key), &key).unwrap();
    let context = verify_snapshot(&authenticated, target).unwrap();
    assert_eq!(context.state(), OdenRev2LoadState::Armable);
    assert!(context.blockers().is_empty());
    let evidence = context.evidence();
    assert_eq!(evidence["verified"], true);
    assert_eq!(evidence["armable"], true);
    assert_eq!(evidence["armed"], false);
    assert_eq!(evidence["conformant"], true);
    assert_eq!(evidence["advertised"], false);
    assert_eq!(evidence["conformanceReportDigest"], report);
    assert_eq!(
      evidence["blockers"],
      serde_json::json!(["runtime-protocol-not-installed"])
    );
  }
}

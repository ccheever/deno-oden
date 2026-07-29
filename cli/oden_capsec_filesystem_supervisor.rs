// Copyright 2018-2026 the Deno authors. MIT license.

use std::ffi::OsString;

use crate::oden_capsec_filesystem_protocol::REFUSAL_EXIT_CODE;
use crate::oden_capsec_filesystem_protocol::parse_reserved_request;

const RESERVED_FLAG: &str = "--_oden-capsec-filesystem-supervise-v2";
const RESERVED_PREFIX: &str = "--_oden-capsec-filesystem-supervise";

// The supervisor table stays empty until later checkpoints can reconcile the
// candidate arena, validate final cleanup, and emit the parent-bound report
// without exposing candidate or parent claims as authority.
const SUPERVISED_CASES: &[(&str, &str)] = &[];

// @ref LLP 0019#pre-promotion-conformance-candidate-execution [implements] —
// Reserve the trusted native supervisor before deno::main or V8 while keeping
// every case mechanically refused until parent capture is implemented.
pub fn maybe_run_oden_capsec_filesystem_supervisor(
  args: impl IntoIterator<Item = OsString>,
) -> Option<i32> {
  let args = args.into_iter().collect::<Vec<_>>();
  let request =
    match parse_reserved_request(&args, RESERVED_FLAG, RESERVED_PREFIX)? {
      Ok(request) => request,
      Err(()) => return Some(REFUSAL_EXIT_CODE),
    };
  if !SUPERVISED_CASES.iter().any(|(digest, case_id)| {
    *digest == request.manifest_digest && *case_id == request.case_id
  }) {
    return Some(REFUSAL_EXIT_CODE);
  }
  Some(REFUSAL_EXIT_CODE)
}

#[cfg(unix)]
#[allow(
  dead_code,
  reason = "the topology remains production-uncalled while SUPERVISED_CASES is empty"
)]
mod topology {
  use std::ffi::CString;
  use std::io;
  use std::os::fd::AsFd;
  use std::os::fd::AsRawFd;
  use std::os::fd::BorrowedFd;
  use std::os::fd::FromRawFd;
  use std::os::fd::IntoRawFd;
  use std::os::fd::OwnedFd;
  use std::sync::Arc;
  use std::time::Duration;
  use std::time::Instant;

  use base64::Engine;
  use base64::engine::general_purpose::URL_SAFE_NO_PAD;
  use deno_core::serde_json::Map;
  use deno_core::serde_json::Value;
  use deno_core::serde_json::json;
  use deno_runtime::deno_permissions;
  use deno_runtime::deno_permissions::OdenRev2CompiledBuildIdentity;
  use deno_runtime::deno_permissions::OdenRev2LstatCandidateBinaryIdentity;
  use deno_runtime::deno_permissions::oden_capsec_rev2_join_lstat_candidate_binary_identity;
  use deno_runtime::deno_permissions::rev2::FilesystemCleanup;
  use deno_runtime::deno_permissions::rev2::FilesystemDecision;
  use deno_runtime::deno_permissions::rev2::FilesystemDelivery;
  use deno_runtime::deno_permissions::rev2::FilesystemExpectedObservation;
  use deno_runtime::deno_permissions::rev2::FilesystemFinalObjectState;
  use deno_runtime::deno_permissions::rev2::FilesystemFollowMode;
  use deno_runtime::deno_permissions::rev2::FilesystemInlineContentKind;
  use deno_runtime::deno_permissions::rev2::FilesystemLogicalRoot;
  use deno_runtime::deno_permissions::rev2::FilesystemObjectIdentityKind;
  use deno_runtime::deno_permissions::rev2::FilesystemObjectKind;
  use deno_runtime::deno_permissions::rev2::FilesystemOperationRequest;
  use deno_runtime::deno_permissions::rev2::FilesystemPlatformPathEncoding;
  use deno_runtime::deno_permissions::rev2::FilesystemTargetParentRef;
  use sha2::Digest;
  use sha2::Sha256;

  use crate::oden_capsec_filesystem_parent::CLEANUP_RESERVE_MS;
  use crate::oden_capsec_filesystem_parent::MAX_TIMEOUT_BUDGET_MS;
  use crate::oden_capsec_filesystem_parent::MIN_TIMEOUT_BUDGET_MS;
  use crate::oden_capsec_filesystem_parent::MonotonicNs;
  use crate::oden_capsec_filesystem_parent::PINNED_CHILD_UMASK;
  use crate::oden_capsec_filesystem_parent::PositiveDecimal;
  use crate::oden_capsec_filesystem_parent::ProcessCredentials;
  use crate::oden_capsec_filesystem_parent::RlimitNprocReadback;
  use crate::oden_capsec_filesystem_parent::is_canonical_positive_decimal20;
  use crate::oden_capsec_filesystem_parent::platform_identity_of_fd;
  use crate::oden_capsec_filesystem_protocol::is_canonical_identifier;
  use crate::oden_capsec_filesystem_protocol::is_canonical_sha256_digest;
  use crate::oden_capsec_filesystem_protocol::unix_transport::FrameByteLimit;
  use crate::oden_capsec_filesystem_protocol::unix_transport::FramedStreamEndpoint;
  use crate::oden_capsec_filesystem_protocol::unix_transport::MAX_CANDIDATE_READY_PACKET_BYTES;
  use crate::oden_capsec_filesystem_protocol::unix_transport::parse_canonical_jcs;

  const CAPSEC_PROFILE: &str = "oden/capsec/2";
  const SUPERVISOR_REQUEST_SCHEMA: &str =
    "oden/capsec-filesystem-supervisor-request/2";
  const CANDIDATE_SPAWN_REQUEST_SCHEMA: &str =
    "oden/capsec-filesystem-candidate-spawn-request/2";
  const CANDIDATE_READY_SCHEMA: &str =
    "oden/capsec-filesystem-candidate-ready-frame/2";
  const CANDIDATE_SPAWN_RESULT_SCHEMA: &str =
    "oden/capsec-filesystem-candidate-spawn-result/2";
  const CANDIDATE_REQUEST_SCHEMA: &str =
    "oden/capsec-filesystem-candidate-request-frame/2";
  const CANDIDATE_RESPONSE_SCHEMA: &str =
    "oden/capsec-filesystem-candidate-response-frame/2";
  const CANDIDATE_ARENA_SCHEMA: &str =
    "oden/capsec-filesystem-candidate-arena/2";
  const CANDIDATE_TERMINAL_SCHEMA: &str =
    "oden/capsec-filesystem-candidate-terminal/2";
  const DESCRIPTOR_SLOTS_SCHEMA: &str =
    "oden/capsec-filesystem-descriptor-slots/2";
  const SUPERVISOR_REQUEST_DIGEST_DOMAIN: &str =
    "oden:capsec:filesystem-supervisor-request-frame:2";
  const CANDIDATE_SPAWN_REQUEST_DIGEST_DOMAIN: &str =
    "oden:capsec:filesystem-candidate-spawn-request-frame:2";
  const CANDIDATE_READY_DIGEST_DOMAIN: &str =
    "oden:capsec:filesystem-candidate-ready-frame:2";
  const CANDIDATE_SPAWN_RESULT_DIGEST_DOMAIN: &str =
    "oden:capsec:filesystem-candidate-spawn-result-frame:2";
  const CANDIDATE_REQUEST_DIGEST_DOMAIN: &str =
    "oden:capsec:filesystem-candidate-request-frame:2";
  const CANDIDATE_RESPONSE_DIGEST_DOMAIN: &str =
    "oden:capsec:filesystem-candidate-response-frame:2";
  const CANDIDATE_ARENA_DIGEST_DOMAIN: &str =
    "oden:capsec:filesystem-candidate-arena:2";
  const CANDIDATE_TERMINAL_DIGEST_DOMAIN: &str =
    "oden:capsec:filesystem-candidate-terminal-frame:2";
  const ENGINE_TRACE_DIGEST_DOMAIN: &str =
    "oden:capsec:filesystem-engine-trace:2";
  const OBSERVED_RESULT_DIGEST_DOMAIN: &str =
    "oden:capsec:filesystem-observed-result:2";
  const DELIVERY_FRAME_DIGEST_DOMAIN: &str =
    "oden:capsec:filesystem-delivery-frame:2";
  const RESOURCE_INVENTORY_DIGEST_DOMAIN: &str =
    "oden:capsec:filesystem-resource-inventory:2";
  const DESCRIPTOR_SLOTS_DIGEST_DOMAIN: &str =
    "oden:capsec:filesystem-descriptor-slots:2";
  const LSTAT_EDGE_ID: &str = "native-op:ext/fs/ops.rs#op_fs_lstat_sync";
  const LSTAT_REQUIREMENT_ID: &str =
    "fixture-requirement:native-op:ext/fs/ops.rs#op_fs_lstat_sync:complete";
  const LSTAT_SLOT_ID: &str =
    "native-op:ext/fs/ops.rs#op_fs_lstat_sync:effect-slot:0";
  const LSTAT_EFFECT_OWNER: &str =
    "pkg:sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
  const LSTAT_ROOT_BINDING_ID: &str = "root:project";
  const LSTAT_ROOT_FIXTURE_IDENTITY: &str = "fixture:project-root";
  const LSTAT_SOURCE_OBJECT_ID: &str = "source";
  const LSTAT_SOURCE_NAME: &str = "input.txt";
  const LSTAT_DESTINATION_OBJECT_ID: &str = "destination";
  const LSTAT_DESTINATION_NAME: &str = "output.txt";
  const LSTAT_ARENA_TRANSFER_INDEX: usize = 1;
  const EMPTY_CONTENT_DIGEST: &str =
    "sha256-47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU";
  const CANDIDATE_RESERVED_FLAG: &str =
    "--_oden-capsec-filesystem-candidate-v2";
  const ARENA_CAPACITY_BYTES: i64 = 8 * 1024 * 1024;
  const ROOT_NAME: &str = "root";
  const ARENA_NAME: &str = "arena";
  const NANOSECONDS_PER_MILLISECOND: u64 = 1_000_000;

  const COMMON_BINDING_FIELDS: &[&str] = &[
    "profile",
    "runNonce",
    "target",
    "featureSet",
    "parentStandaloneDigest",
    "engineDigest",
    "forkCommit",
    "fixtureArtifactDigest",
    "executionIdentityDigest",
    "sourceClosureDigest",
    "caseId",
    "edgeId",
    "requirementId",
    "caseKind",
  ];

  const SUPERVISOR_REQUEST_FIELDS: &[&str] = &[
    "schema",
    "profile",
    "runNonce",
    "target",
    "featureSet",
    "parentStandaloneDigest",
    "engineDigest",
    "forkCommit",
    "fixtureArtifactDigest",
    "executionIdentityDigest",
    "sourceClosureDigest",
    "caseId",
    "edgeId",
    "requirementId",
    "caseKind",
    "executionProjectionDigest",
    "timeoutBudgetMs",
    "cleanupReserveMs",
    "deadlineMonotonicNs",
    "workspaceRootPlatformIdentity",
  ];

  const CANDIDATE_SPAWN_RESULT_FIELDS: &[&str] = &[
    "schema",
    "profile",
    "runNonce",
    "target",
    "featureSet",
    "parentStandaloneDigest",
    "engineDigest",
    "forkCommit",
    "fixtureArtifactDigest",
    "executionIdentityDigest",
    "sourceClosureDigest",
    "caseId",
    "edgeId",
    "requirementId",
    "caseKind",
    "supervisorRequestFrameByteLength",
    "supervisorRequestFrameDigest",
    "candidateSpawnRequestFrameByteLength",
    "candidateSpawnRequestFrameDigest",
    "candidateReadyFrame",
    "candidateArgv",
    "candidatePid",
    "candidatePgid",
    "candidateStartIdentity",
    "immutableImageIdentity",
    "candidateEndpointParentIdentity",
    "candidateEndpointSupervisorIdentity",
    "transferredDescriptorCount",
    "preExec",
    "parentPreRequestPlatformObservationDigest",
    "effectiveWorkDeadlineMonotonicNs",
    "effectiveFinalDeadlineMonotonicNs",
    "admitted",
  ];

  const CANDIDATE_RESPONSE_FIELDS: &[&str] = &[
    "schema",
    "profile",
    "runNonce",
    "target",
    "featureSet",
    "parentStandaloneDigest",
    "engineDigest",
    "forkCommit",
    "fixtureArtifactDigest",
    "executionIdentityDigest",
    "sourceClosureDigest",
    "caseId",
    "edgeId",
    "requirementId",
    "caseKind",
    "candidateRequestFrameDigest",
    "acceptedDescriptorSlotsDigest",
    "capturedUmask",
    "normalizedObservedResult",
    "observedResultDigest",
    "candidateArenaDigest",
    "engineTraceDigest",
    "deliveryFrame",
    "deliveryFrameDigest",
    "resourceInventory",
    "resourceInventoryDigest",
    "faultObservation",
    "faultObservationDigest",
    "noDescendantClaims",
    "rootDescriptorsDroppedClaim",
  ];

  const CANDIDATE_TERMINAL_FIELDS: &[&str] = &[
    "schema",
    "profile",
    "runNonce",
    "target",
    "featureSet",
    "parentStandaloneDigest",
    "engineDigest",
    "forkCommit",
    "fixtureArtifactDigest",
    "executionIdentityDigest",
    "sourceClosureDigest",
    "caseId",
    "edgeId",
    "requirementId",
    "caseKind",
    "candidateSpawnResultFrameDigest",
    "candidatePid",
    "candidatePgid",
    "candidateStartIdentity",
    "terminalObservationMonotonicNs",
    "exitStatus",
    "reaped",
    "supervisorGroupLeaderStillOwned",
  ];

  const CANDIDATE_ARENA_FIELDS: &[&str] = &[
    "schema",
    "profile",
    "runNonce",
    "target",
    "featureSet",
    "parentStandaloneDigest",
    "engineDigest",
    "forkCommit",
    "fixtureArtifactDigest",
    "executionIdentityDigest",
    "sourceClosureDigest",
    "caseId",
    "edgeId",
    "requirementId",
    "caseKind",
    "descriptorSlotsDigest",
    "arenaTransferIndex",
    "arenaPlatformIdentity",
    "capacityBytes",
    "payload",
    "unusedTail",
  ];

  const NO_DESCENDANT_CLAIM_FIELDS: &[&str] = &[
    "noDescendantProfile",
    "sourceClosureDigest",
    "candidatePid",
    "candidatePgid",
    "candidateStartIdentity",
    "expectedPgid",
    "pgidCheckpoints",
    "processLimitReadback",
    "identities",
    "preRequestFdInventory",
    "platformState",
  ];

  #[derive(Clone, Copy, Debug, Eq, PartialEq)]
  pub(crate) enum SupervisorLstatCase {
    Existing,
    FinalMissing,
  }

  impl SupervisorLstatCase {
    fn from_id(case_id: &str) -> Option<Self> {
      match case_id {
        "filesystem:lstat-sync:lstat-existing" => Some(Self::Existing),
        "filesystem:lstat-sync:lstat-final-missing" => Some(Self::FinalMissing),
        _ => None,
      }
    }

    fn case_id(self) -> &'static str {
      match self {
        Self::Existing => "filesystem:lstat-sync:lstat-existing",
        Self::FinalMissing => "filesystem:lstat-sync:lstat-final-missing",
      }
    }

    fn case_kind(self) -> &'static str {
      match self {
        Self::Existing => "lstat-existing",
        Self::FinalMissing => "lstat-final-missing",
      }
    }

    fn native_result_class(self) -> &'static str {
      match self {
        Self::Existing => "lstat-complete",
        Self::FinalMissing => "lstat-not-found",
      }
    }

    fn root_is_empty(self) -> bool {
      matches!(self, Self::FinalMissing)
    }
  }

  enum SupervisorGeneratedSeal {
    Exact(OdenRev2LstatCandidateBinaryIdentity),
    #[cfg(test)]
    Fixture,
  }

  /// Exact generated lstat identity selected by the current binary. This is an
  /// equality seal only; it has no execution or admission method.
  pub(crate) struct SupervisorGeneratedLstatIdentity {
    _seal: SupervisorGeneratedSeal,
    target: String,
    feature_set: String,
    fork_commit: String,
    fixture_artifact_digest: String,
    execution_projection_digest: String,
    case: SupervisorLstatCase,
  }

  impl SupervisorGeneratedLstatIdentity {
    fn from_current_binary(
      fixture_artifact_digest: &str,
      case_id: &str,
    ) -> io::Result<Self> {
      let build_identity = current_binary_build_identity();
      let generated = oden_capsec_rev2_join_lstat_candidate_binary_identity(
        &build_identity,
        fixture_artifact_digest,
        case_id,
      )
      .map_err(|_| {
        invalid_data(
          "supervisor binary does not join its exact generated lstat row",
        )
      })?;
      let fork_commit = deno_lib::version::DENO_VERSION_INFO.git_hash;
      Self::from_generated(generated, fork_commit)
    }

    fn from_generated(
      generated: OdenRev2LstatCandidateBinaryIdentity,
      fork_commit: &str,
    ) -> io::Result<Self> {
      let case =
        SupervisorLstatCase::from_id(generated.case_id()).ok_or_else(|| {
          invalid_data("supervisor generated case is not lstat")
        })?;
      if !matches!(
        generated.target(),
        "aarch64-apple-darwin" | "x86_64-unknown-linux-gnu"
      ) || !is_canonical_identifier(generated.feature_set())
        || !is_canonical_fork_commit(fork_commit)
        || !is_canonical_sha256_digest(generated.fixture_artifact_digest())
        || !is_canonical_sha256_digest(generated.execution_projection_digest())
      {
        return Err(invalid_data(
          "supervisor generated lstat identity is not canonical",
        ));
      }
      validate_generated_lstat_projection(&generated, case)?;
      Ok(Self {
        target: generated.target().to_string(),
        feature_set: generated.feature_set().to_string(),
        fork_commit: fork_commit.to_string(),
        fixture_artifact_digest: generated
          .fixture_artifact_digest()
          .to_string(),
        execution_projection_digest: generated
          .execution_projection_digest()
          .to_string(),
        case,
        _seal: SupervisorGeneratedSeal::Exact(generated),
      })
    }

    #[cfg(test)]
    fn new_test_fixture(
      target: &str,
      feature_set: &str,
      fork_commit: &str,
      fixture_artifact_digest: &str,
      execution_projection_digest: &str,
      case_id: &str,
    ) -> io::Result<Self> {
      let case = SupervisorLstatCase::from_id(case_id)
        .ok_or_else(|| invalid_input("supervisor case is not admitted"))?;
      if !matches!(target, "aarch64-apple-darwin" | "x86_64-unknown-linux-gnu")
        || !is_canonical_identifier(feature_set)
        || !is_canonical_fork_commit(fork_commit)
        || !is_canonical_sha256_digest(fixture_artifact_digest)
        || !is_canonical_sha256_digest(execution_projection_digest)
      {
        return Err(invalid_input("supervisor test identity is not canonical"));
      }
      Ok(Self {
        _seal: SupervisorGeneratedSeal::Fixture,
        target: target.to_string(),
        feature_set: feature_set.to_string(),
        fork_commit: fork_commit.to_string(),
        fixture_artifact_digest: fixture_artifact_digest.to_string(),
        execution_projection_digest: execution_projection_digest.to_string(),
        case,
      })
    }
  }

  fn current_binary_build_identity() -> OdenRev2CompiledBuildIdentity {
    OdenRev2CompiledBuildIdentity {
      target: env!("ODEN_REV2_BUILD_TARGET"),
      rust_toolchain: env!("ODEN_REV2_BUILD_RUST"),
      cargo_features: env!("ODEN_REV2_BUILD_CARGO_FEATURES"),
      rust_cfg_digest: env!("ODEN_REV2_BUILD_RUST_CFG_DIGEST"),
      cargo_feature_graph_digest: env!("ODEN_REV2_BUILD_CARGO_GRAPH_DIGEST"),
      build_profile: env!("ODEN_REV2_BUILD_PROFILE"),
      marker_panic_strategy: env!("ODEN_REV2_BUILD_PANIC"),
      marker_debug_assertions: env!("ODEN_REV2_BUILD_DEBUG_ASSERTIONS"),
      actual_panic_strategy: if cfg!(panic = "abort") {
        "abort"
      } else {
        "unwind"
      },
      actual_debug_assertions: cfg!(debug_assertions),
    }
  }

  fn validate_generated_lstat_projection(
    generated: &OdenRev2LstatCandidateBinaryIdentity,
    case: SupervisorLstatCase,
  ) -> io::Result<()> {
    let projection = generated.execution_projection();
    if projection.case_id != case.case_id()
      || projection.edge_id != LSTAT_EDGE_ID
      || projection.requirement_id != LSTAT_REQUIREMENT_ID
      || projection.case_kind != case.case_kind()
      || projection.setup.logical_roots.len() != 1
      || projection.setup.objects.len() != 2
    {
      return Err(invalid_data(
        "supervisor generated lstat projection is not exact",
      ));
    }
    let root = &projection.setup.logical_roots[0];
    if root.root != FilesystemLogicalRoot::Project
      || root.binding_id != LSTAT_ROOT_BINDING_ID
      || root.descriptor_slot != 0
      || root.object_identity.kind != FilesystemObjectIdentityKind::OpaqueToken
      || root.object_identity.value != LSTAT_ROOT_FIXTURE_IDENTITY
    {
      return Err(invalid_data(
        "supervisor generated logical root is not exact",
      ));
    }
    let target_ref = match &projection.operation_request {
      FilesystemOperationRequest::LstatSync { target_ref } => target_ref,
      _ => {
        return Err(invalid_data(
          "supervisor generated operation is not lstat",
        ));
      }
    };
    if target_ref.object_id != LSTAT_SOURCE_OBJECT_ID
      || !matches!(
        &target_ref.parent,
        FilesystemTargetParentRef::LogicalRoot { root, binding_id }
          if *root == FilesystemLogicalRoot::Project
            && binding_id == LSTAT_ROOT_BINDING_ID
      )
    {
      return Err(invalid_data(
        "supervisor generated lstat target is not exact",
      ));
    }
    let source = &projection.setup.objects[0];
    let source_is_exact = source.object_id == LSTAT_SOURCE_OBJECT_ID
      && source.root == FilesystemLogicalRoot::Project
      && source.path.encoding == FilesystemPlatformPathEncoding::Unicode
      && source.path.value == LSTAT_SOURCE_NAME
      && source.alias_target_object_id.is_none()
      && source.link_target_object_id.is_none()
      && match case {
        SupervisorLstatCase::Existing => {
          source.kind == FilesystemObjectKind::RegularFile
            && source.object_identity.as_ref().is_some_and(|identity| {
              identity.kind == FilesystemObjectIdentityKind::VerifiedContent
                && identity.value == EMPTY_CONTENT_DIGEST
            })
            && source.content.as_ref().is_some_and(|content| {
              content.kind == FilesystemInlineContentKind::InlineBase64url
                && content.bytes.is_empty()
            })
            && source.content_digest.as_deref() == Some(EMPTY_CONTENT_DIGEST)
        }
        SupervisorLstatCase::FinalMissing => {
          source.kind == FilesystemObjectKind::Missing
            && source.object_identity.is_none()
            && source.content.is_none()
            && source.content_digest.is_none()
        }
      };
    let destination = &projection.setup.objects[1];
    if !source_is_exact
      || destination.object_id != LSTAT_DESTINATION_OBJECT_ID
      || destination.root != FilesystemLogicalRoot::Project
      || destination.path.encoding != FilesystemPlatformPathEncoding::Unicode
      || destination.path.value != LSTAT_DESTINATION_NAME
      || destination.kind != FilesystemObjectKind::Missing
      || destination.object_identity.is_some()
      || destination.content.is_some()
      || destination.content_digest.is_some()
      || destination.alias_target_object_id.is_some()
      || destination.link_target_object_id.is_some()
    {
      return Err(invalid_data(
        "supervisor generated lstat objects are not exact",
      ));
    }
    Ok(())
  }

  #[derive(Clone, Debug, Eq, PartialEq)]
  struct SupervisorCaseBinding {
    run_nonce: String,
    parent_standalone_digest: String,
    engine_digest: String,
    execution_identity_digest: String,
    source_closure_digest: String,
  }

  impl SupervisorCaseBinding {
    fn from_supervisor_request(
      object: &Map<String, Value>,
      identity: &SupervisorGeneratedLstatIdentity,
    ) -> io::Result<Self> {
      require_text_eq(object, "profile", CAPSEC_PROFILE)?;
      let run_nonce = require_identifier(object, "runNonce")?;
      require_text_eq(object, "target", &identity.target)?;
      require_text_eq(object, "featureSet", &identity.feature_set)?;
      let parent_standalone_digest =
        require_digest(object, "parentStandaloneDigest")?;
      let engine_digest = require_digest(object, "engineDigest")?;
      require_text_eq(object, "forkCommit", &identity.fork_commit)?;
      require_text_eq(
        object,
        "fixtureArtifactDigest",
        &identity.fixture_artifact_digest,
      )?;
      let execution_identity_digest =
        require_digest(object, "executionIdentityDigest")?;
      let source_closure_digest =
        require_digest(object, "sourceClosureDigest")?;
      require_text_eq(object, "caseId", identity.case.case_id())?;
      require_text_eq(object, "edgeId", LSTAT_EDGE_ID)?;
      require_text_eq(object, "requirementId", LSTAT_REQUIREMENT_ID)?;
      require_text_eq(object, "caseKind", identity.case.case_kind())?;
      Ok(Self {
        run_nonce,
        parent_standalone_digest,
        engine_digest,
        execution_identity_digest,
        source_closure_digest,
      })
    }

    fn insert_common(
      &self,
      object: &mut Map<String, Value>,
      identity: &SupervisorGeneratedLstatIdentity,
    ) {
      object.insert("profile".into(), json!(CAPSEC_PROFILE));
      object.insert("runNonce".into(), json!(self.run_nonce));
      object.insert("target".into(), json!(identity.target));
      object.insert("featureSet".into(), json!(identity.feature_set));
      object.insert(
        "parentStandaloneDigest".into(),
        json!(self.parent_standalone_digest),
      );
      object.insert("engineDigest".into(), json!(self.engine_digest));
      object.insert("forkCommit".into(), json!(identity.fork_commit));
      object.insert(
        "fixtureArtifactDigest".into(),
        json!(identity.fixture_artifact_digest),
      );
      object.insert(
        "executionIdentityDigest".into(),
        json!(self.execution_identity_digest),
      );
      object.insert(
        "sourceClosureDigest".into(),
        json!(self.source_closure_digest),
      );
      object.insert("caseId".into(), json!(identity.case.case_id()));
      object.insert("edgeId".into(), json!(LSTAT_EDGE_ID));
      object.insert("requirementId".into(), json!(LSTAT_REQUIREMENT_ID));
      object.insert("caseKind".into(), json!(identity.case.case_kind()));
    }

    fn validate_common(
      &self,
      object: &Map<String, Value>,
      identity: &SupervisorGeneratedLstatIdentity,
    ) -> io::Result<()> {
      require_text_eq(object, "profile", CAPSEC_PROFILE)?;
      require_text_eq(object, "runNonce", &self.run_nonce)?;
      require_text_eq(object, "target", &identity.target)?;
      require_text_eq(object, "featureSet", &identity.feature_set)?;
      require_text_eq(
        object,
        "parentStandaloneDigest",
        &self.parent_standalone_digest,
      )?;
      require_text_eq(object, "engineDigest", &self.engine_digest)?;
      require_text_eq(object, "forkCommit", &identity.fork_commit)?;
      require_text_eq(
        object,
        "fixtureArtifactDigest",
        &identity.fixture_artifact_digest,
      )?;
      require_text_eq(
        object,
        "executionIdentityDigest",
        &self.execution_identity_digest,
      )?;
      require_text_eq(
        object,
        "sourceClosureDigest",
        &self.source_closure_digest,
      )?;
      require_text_eq(object, "caseId", identity.case.case_id())?;
      require_text_eq(object, "edgeId", LSTAT_EDGE_ID)?;
      require_text_eq(object, "requirementId", LSTAT_REQUIREMENT_ID)?;
      require_text_eq(object, "caseKind", identity.case.case_kind())
    }
  }

  #[derive(Clone, Copy, Debug, Eq, PartialEq)]
  enum SupervisorDeadlineCheckpoint {
    TransitionStart,
    TransportComplete,
    ValidationComplete,
    ArenaRead,
    ArenaReadAttempt,
    ArenaReadComplete,
    ArenaFirstPassComplete,
    ArenaSecondPassComplete,
  }

  trait SupervisorClock: Send + Sync {
    fn now(&self, checkpoint: SupervisorDeadlineCheckpoint) -> Instant;
  }

  struct SystemSupervisorClock;

  impl SupervisorClock for SystemSupervisorClock {
    fn now(&self, _checkpoint: SupervisorDeadlineCheckpoint) -> Instant {
      Instant::now()
    }
  }

  /// Immutable effective supervisor deadline: never later than either the
  /// received parent deadline or receipt-time plus the admitted budget.
  struct SupervisorDeadline {
    timeout_budget_ms: u32,
    requested_final_ns: u64,
    receipt_ns: u64,
    effective_work_ns: u64,
    effective_final_ns: u64,
    work_instant: Instant,
    final_instant: Instant,
    clock: Arc<dyn SupervisorClock>,
  }

  impl SupervisorDeadline {
    fn from_request(object: &Map<String, Value>) -> io::Result<Self> {
      let timeout_budget_ms = require_u32(object, "timeoutBudgetMs")?;
      if !(MIN_TIMEOUT_BUDGET_MS..=MAX_TIMEOUT_BUDGET_MS)
        .contains(&timeout_budget_ms)
        || require_u32(object, "cleanupReserveMs")? != CLEANUP_RESERVE_MS
      {
        return Err(invalid_data(
          "supervisor request budget is outside the frozen bounds",
        ));
      }
      let requested_text = require_text(object, "deadlineMonotonicNs")?;
      if !is_canonical_positive_decimal20(requested_text) {
        return Err(invalid_data(
          "supervisor request deadline is not canonical",
        ));
      }
      let requested_final_ns = requested_text
        .parse::<u64>()
        .map_err(|_| invalid_data("supervisor request deadline overflowed"))?;
      let receipt_instant = Instant::now();
      let receipt_ns = MonotonicNs::now()
        .map_err(|_| invalid_data("supervisor monotonic clock refused"))?
        .0;
      let own_final_ns = receipt_ns
        .checked_add(
          u64::from(timeout_budget_ms)
            .checked_mul(NANOSECONDS_PER_MILLISECOND)
            .ok_or_else(|| invalid_data("supervisor deadline overflowed"))?,
        )
        .ok_or_else(|| invalid_data("supervisor deadline overflowed"))?;
      let effective_final_ns = requested_final_ns.min(own_final_ns);
      let reserve_ns = u64::from(CLEANUP_RESERVE_MS)
        .checked_mul(NANOSECONDS_PER_MILLISECOND)
        .ok_or_else(|| invalid_data("supervisor reserve overflowed"))?;
      let effective_work_ns = effective_final_ns
        .checked_sub(reserve_ns)
        .ok_or_else(|| invalid_data("supervisor deadline lacks reserve"))?;
      if effective_work_ns <= receipt_ns {
        return Err(deadline_expired());
      }
      let work_instant = receipt_instant
        .checked_add(Duration::from_nanos(effective_work_ns - receipt_ns))
        .ok_or_else(|| invalid_data("supervisor work deadline overflowed"))?;
      let final_instant = receipt_instant
        .checked_add(Duration::from_nanos(effective_final_ns - receipt_ns))
        .ok_or_else(|| invalid_data("supervisor final deadline overflowed"))?;
      Ok(Self {
        timeout_budget_ms,
        requested_final_ns,
        receipt_ns,
        effective_work_ns,
        effective_final_ns,
        work_instant,
        final_instant,
        clock: Arc::new(SystemSupervisorClock),
      })
    }

    fn check(
      &self,
      checkpoint: SupervisorDeadlineCheckpoint,
    ) -> io::Result<()> {
      if self.clock.now(checkpoint) >= self.work_instant {
        Err(deadline_expired())
      } else {
        Ok(())
      }
    }

    fn effective_work_text(&self) -> String {
      self.effective_work_ns.to_string()
    }

    fn effective_final_text(&self) -> String {
      self.effective_final_ns.to_string()
    }

    #[cfg(test)]
    fn replace_clock(&mut self, clock: Arc<dyn SupervisorClock>) {
      self.clock = clock;
    }
  }

  pub(crate) struct SupervisorEntryFacts {
    supervisor_pid: PositiveDecimal,
    supervisor_pgid: PositiveDecimal,
    observed_parent_pid: PositiveDecimal,
    observed_parent_pgid: PositiveDecimal,
    captured_umask: u32,
  }

  impl SupervisorEntryFacts {
    fn new(
      supervisor_pid: libc::pid_t,
      supervisor_pgid: libc::pid_t,
      observed_parent_pid: libc::pid_t,
      observed_parent_pgid: libc::pid_t,
      captured_umask: u32,
    ) -> io::Result<Self> {
      if captured_umask != PINNED_CHILD_UMASK {
        return Err(invalid_data(
          "supervisor entry did not retain the pinned umask",
        ));
      }
      Ok(Self {
        supervisor_pid: PositiveDecimal::from_pid(supervisor_pid)
          .ok_or_else(|| invalid_data("supervisor PID is not positive"))?,
        supervisor_pgid: PositiveDecimal::from_pid(supervisor_pgid)
          .ok_or_else(|| invalid_data("supervisor PGID is not positive"))?,
        observed_parent_pid: PositiveDecimal::from_pid(observed_parent_pid)
          .ok_or_else(|| invalid_data("observed parent PID is not positive"))?,
        observed_parent_pgid: PositiveDecimal::from_pid(observed_parent_pgid)
          .ok_or_else(|| {
          invalid_data("observed parent PGID is not positive")
        })?,
        captured_umask,
      })
    }
  }

  #[derive(Clone, Copy, Debug, Eq, PartialEq)]
  enum SupervisorFd4State {
    SpawnRequestPending,
    SpawnResultPending,
    CandidateRequestPending,
    AwaitingCandidateOutcome,
    Refused,
  }

  struct SupervisorSpawnResultFacts {
    raw_bytes: Vec<u8>,
    frame_digest: String,
    ready_raw_bytes: Vec<u8>,
    ready_frame_digest: String,
    candidate_pid: String,
    candidate_pgid: String,
    candidate_start_identity: String,
    candidate_endpoint_identity: String,
  }

  /// Opaque, non-cloneable cutoff after the candidate request has been sent.
  /// Its only transition captures one exact candidate response and immediate
  /// EOF; it cannot interpret candidate claims as observations or evidence.
  ///
  /// @ref LLP 0019#pre-promotion-conformance-candidate-execution
  /// [constrained-by] — Topology preparation is neither execution evidence nor
  /// authority; the production case table stays empty and the sole response
  /// transition stops at retained, unauthenticated candidate claims.
  pub(crate) struct SupervisorAwaitingCandidateOutcome {
    _fd4: FramedStreamEndpoint,
    _candidate_peer: FramedStreamEndpoint,
    _resources: SupervisorLstatResources,
    _identity: SupervisorGeneratedLstatIdentity,
    _binding: SupervisorCaseBinding,
    _entry: SupervisorEntryFacts,
    _deadline: SupervisorDeadline,
    _supervisor_request_raw_bytes: Vec<u8>,
    _supervisor_request_frame_digest: String,
    _spawn_request_raw_bytes: Vec<u8>,
    _spawn_request_frame_digest: String,
    _spawn_result: SupervisorSpawnResultFacts,
    _candidate_request_raw_bytes: Vec<u8>,
    _candidate_request_frame_digest: String,
    _descriptor_slots_raw_bytes: Vec<u8>,
    _descriptor_slots_digest: String,
  }

  struct SupervisorCandidateResponseFacts {
    raw_bytes: Vec<u8>,
    value: Value,
    frame_digest: String,
    observed_result_digest: String,
    candidate_arena_digest: String,
    engine_trace_digest: String,
  }

  /// Opaque, non-cloneable cutoff after the supervisor has captured exactly
  /// one candidate response and immediate FD3 EOF. Its only transition
  /// captures the exact parent terminal and immediate FD4 EOF; every retained
  /// response field remains an unauthenticated candidate claim.
  ///
  /// @ref LLP 0019#parentsupervisor-transport-and-single-process-lifetime-cell
  /// [constrained-by] — Candidate response framing and internal consistency do
  /// not establish parent reconciliation, an oracle result, evidence, or
  /// release authority.
  pub(crate) struct SupervisorAwaitingParentTerminal {
    _fd4: FramedStreamEndpoint,
    _resources: SupervisorLstatResources,
    _identity: SupervisorGeneratedLstatIdentity,
    _binding: SupervisorCaseBinding,
    _entry: SupervisorEntryFacts,
    _deadline: SupervisorDeadline,
    _supervisor_request_raw_bytes: Vec<u8>,
    _supervisor_request_frame_digest: String,
    _spawn_request_raw_bytes: Vec<u8>,
    _spawn_request_frame_digest: String,
    _spawn_result: SupervisorSpawnResultFacts,
    _candidate_request_raw_bytes: Vec<u8>,
    _candidate_request_frame_digest: String,
    _descriptor_slots_raw_bytes: Vec<u8>,
    _descriptor_slots_digest: String,
    _candidate_response: SupervisorCandidateResponseFacts,
    _candidate_response_eof_observed: bool,
    _candidate_peer_closed: bool,
  }

  struct SupervisorCandidateTerminalFacts {
    raw_bytes: Vec<u8>,
    value: Value,
    frame_digest: String,
    terminal_observation_monotonic_ns: String,
  }

  /// Opaque, non-cloneable cutoff after the supervisor has captured the exact
  /// parent terminal, immediate FD4 EOF, and closed FD4. Its sole consuming
  /// method performs candidate-arena byte reconciliation; root scanning,
  /// cleanup, report generation, oracle comparison, and evidence remain
  /// separate transitions.
  ///
  /// @ref LLP 0019#parentsupervisor-transport-and-single-process-lifetime-cell
  /// [constrained-by] — A syntactically and relationally closed parent terminal
  /// is still not arena reconciliation, cleanup proof, evidence, or authority.
  pub(crate) struct SupervisorAwaitingArenaReconciliation {
    _resources: SupervisorLstatResources,
    _identity: SupervisorGeneratedLstatIdentity,
    _binding: SupervisorCaseBinding,
    _entry: SupervisorEntryFacts,
    _deadline: SupervisorDeadline,
    _supervisor_request_raw_bytes: Vec<u8>,
    _supervisor_request_frame_digest: String,
    _spawn_request_raw_bytes: Vec<u8>,
    _spawn_request_frame_digest: String,
    _spawn_result: SupervisorSpawnResultFacts,
    _candidate_request_raw_bytes: Vec<u8>,
    _candidate_request_frame_digest: String,
    _descriptor_slots_raw_bytes: Vec<u8>,
    _descriptor_slots_digest: String,
    _candidate_response: SupervisorCandidateResponseFacts,
    _candidate_response_eof_observed: bool,
    _candidate_peer_closed: bool,
    _candidate_terminal: SupervisorCandidateTerminalFacts,
    _parent_terminal_eof_observed: bool,
    _fd4_closed: bool,
  }

  struct SupervisorCandidateArenaFacts {
    value: Value,
    digest: String,
    payload_bytes: Vec<u8>,
    payload_value: Value,
    payload_byte_digest: String,
    engine_trace_digest: String,
    unused_tail_byte_digest: String,
  }

  /// Opaque, non-cloneable cutoff after two exact bounded reads of the retained
  /// arena agree with each other and with the response-bound arena and trace
  /// digests. It intentionally exposes no method: engine-trace semantics,
  /// final root scanning, cleanup, reporting, oracle comparison, and evidence
  /// remain separate transitions.
  ///
  /// @ref LLP 0019#parentsupervisor-transport-and-single-process-lifetime-cell
  /// [constrained-by] — Reconstructing candidate-authored arena bytes is a
  /// candidate-only consistency observation. It is not immutable-state proof,
  /// execution evidence, admission, or release authority.
  pub(crate) struct SupervisorAwaitingEngineTraceValidation {
    _resources: SupervisorLstatResources,
    _identity: SupervisorGeneratedLstatIdentity,
    _binding: SupervisorCaseBinding,
    _entry: SupervisorEntryFacts,
    _deadline: SupervisorDeadline,
    _supervisor_request_raw_bytes: Vec<u8>,
    _supervisor_request_frame_digest: String,
    _spawn_request_raw_bytes: Vec<u8>,
    _spawn_request_frame_digest: String,
    _spawn_result: SupervisorSpawnResultFacts,
    _candidate_request_raw_bytes: Vec<u8>,
    _candidate_request_frame_digest: String,
    _descriptor_slots_raw_bytes: Vec<u8>,
    _descriptor_slots_digest: String,
    _candidate_response: SupervisorCandidateResponseFacts,
    _candidate_response_eof_observed: bool,
    _candidate_peer_closed: bool,
    _candidate_terminal: SupervisorCandidateTerminalFacts,
    _parent_terminal_eof_observed: bool,
    _fd4_closed: bool,
    _candidate_arena: SupervisorCandidateArenaFacts,
  }

  impl SupervisorAwaitingCandidateOutcome {
    pub(crate) fn capture_candidate_response(
      self,
    ) -> io::Result<SupervisorAwaitingParentTerminal> {
      self
        ._deadline
        .check(SupervisorDeadlineCheckpoint::TransitionStart)?;
      let packet = self._candidate_peer.receive_one_canonical_jcs_frame(
        FrameByteLimit::CONTROL,
        0,
        self._deadline.work_instant,
      )?;
      self
        ._candidate_peer
        .require_eof(self._deadline.work_instant)?;
      self
        ._deadline
        .check(SupervisorDeadlineCheckpoint::TransportComplete)?;
      let SupervisorAwaitingCandidateOutcome {
        _fd4,
        _candidate_peer,
        _resources,
        _identity,
        _binding,
        _entry,
        _deadline,
        _supervisor_request_raw_bytes,
        _supervisor_request_frame_digest,
        _spawn_request_raw_bytes,
        _spawn_request_frame_digest,
        _spawn_result,
        _candidate_request_raw_bytes,
        _candidate_request_frame_digest,
        _descriptor_slots_raw_bytes,
        _descriptor_slots_digest,
      } = self;
      // Both directions are now closed; do not retain FD3 while validating
      // candidate-controlled claims.
      drop(_candidate_peer);
      let candidate_response = validate_candidate_response(
        &packet.raw_bytes,
        &packet.value,
        &_identity,
        &_binding,
        &_spawn_result,
        &_candidate_request_frame_digest,
        &_descriptor_slots_digest,
      )?;
      _deadline.check(SupervisorDeadlineCheckpoint::ValidationComplete)?;
      Ok(SupervisorAwaitingParentTerminal {
        _fd4,
        _resources,
        _identity,
        _binding,
        _entry,
        _deadline,
        _supervisor_request_raw_bytes,
        _supervisor_request_frame_digest,
        _spawn_request_raw_bytes,
        _spawn_request_frame_digest,
        _spawn_result,
        _candidate_request_raw_bytes,
        _candidate_request_frame_digest,
        _descriptor_slots_raw_bytes,
        _descriptor_slots_digest,
        _candidate_response: candidate_response,
        _candidate_response_eof_observed: true,
        _candidate_peer_closed: true,
      })
    }
  }

  impl SupervisorAwaitingParentTerminal {
    pub(crate) fn capture_parent_terminal(
      self,
    ) -> io::Result<SupervisorAwaitingArenaReconciliation> {
      self
        ._deadline
        .check(SupervisorDeadlineCheckpoint::TransitionStart)?;
      let packet = self._fd4.receive_one_canonical_jcs_frame(
        FrameByteLimit::CONTROL,
        0,
        self._deadline.work_instant,
      )?;
      self._fd4.require_eof(self._deadline.work_instant)?;
      self
        ._deadline
        .check(SupervisorDeadlineCheckpoint::TransportComplete)?;
      let SupervisorAwaitingParentTerminal {
        _fd4,
        _resources,
        _identity,
        _binding,
        _entry,
        _deadline,
        _supervisor_request_raw_bytes,
        _supervisor_request_frame_digest,
        _spawn_request_raw_bytes,
        _spawn_request_frame_digest,
        _spawn_result,
        _candidate_request_raw_bytes,
        _candidate_request_frame_digest,
        _descriptor_slots_raw_bytes,
        _descriptor_slots_digest,
        _candidate_response,
        _candidate_response_eof_observed,
        _candidate_peer_closed,
      } = self;
      // The parent has shut down its sole write direction and EOF proved that
      // no second terminal frame or late right exists. Close FD4 before
      // interpreting any parent-controlled terminal field.
      drop(_fd4);
      let candidate_terminal = validate_candidate_terminal(
        &packet.raw_bytes,
        &packet.value,
        &_identity,
        &_binding,
        &_spawn_result,
        &_deadline,
      )?;
      _deadline.check(SupervisorDeadlineCheckpoint::ValidationComplete)?;
      Ok(SupervisorAwaitingArenaReconciliation {
        _resources,
        _identity,
        _binding,
        _entry,
        _deadline,
        _supervisor_request_raw_bytes,
        _supervisor_request_frame_digest,
        _spawn_request_raw_bytes,
        _spawn_request_frame_digest,
        _spawn_result,
        _candidate_request_raw_bytes,
        _candidate_request_frame_digest,
        _descriptor_slots_raw_bytes,
        _descriptor_slots_digest,
        _candidate_response,
        _candidate_response_eof_observed,
        _candidate_peer_closed,
        _candidate_terminal: candidate_terminal,
        _parent_terminal_eof_observed: true,
        _fd4_closed: true,
      })
    }
  }

  impl SupervisorAwaitingArenaReconciliation {
    pub(crate) fn reconcile_candidate_arena(
      self,
    ) -> io::Result<SupervisorAwaitingEngineTraceValidation> {
      self
        ._deadline
        .check(SupervisorDeadlineCheckpoint::TransitionStart)?;
      let candidate_arena = reconcile_supervisor_candidate_arena(
        &self._resources,
        &self._identity,
        &self._binding,
        &self._descriptor_slots_digest,
        &self._candidate_response,
        &self._deadline,
      )?;
      self
        ._deadline
        .check(SupervisorDeadlineCheckpoint::ValidationComplete)?;
      let SupervisorAwaitingArenaReconciliation {
        _resources,
        _identity,
        _binding,
        _entry,
        _deadline,
        _supervisor_request_raw_bytes,
        _supervisor_request_frame_digest,
        _spawn_request_raw_bytes,
        _spawn_request_frame_digest,
        _spawn_result,
        _candidate_request_raw_bytes,
        _candidate_request_frame_digest,
        _descriptor_slots_raw_bytes,
        _descriptor_slots_digest,
        _candidate_response,
        _candidate_response_eof_observed,
        _candidate_peer_closed,
        _candidate_terminal,
        _parent_terminal_eof_observed,
        _fd4_closed,
      } = self;
      Ok(SupervisorAwaitingEngineTraceValidation {
        _resources,
        _identity,
        _binding,
        _entry,
        _deadline,
        _supervisor_request_raw_bytes,
        _supervisor_request_frame_digest,
        _spawn_request_raw_bytes,
        _spawn_request_frame_digest,
        _spawn_result,
        _candidate_request_raw_bytes,
        _candidate_request_frame_digest,
        _descriptor_slots_raw_bytes,
        _descriptor_slots_digest,
        _candidate_response,
        _candidate_response_eof_observed,
        _candidate_peer_closed,
        _candidate_terminal,
        _parent_terminal_eof_observed,
        _fd4_closed,
        _candidate_arena: candidate_arena,
      })
    }
  }

  #[derive(Clone, Debug, Eq, PartialEq)]
  struct SupervisorDescriptorSnapshot {
    device: u64,
    inode: u64,
    mode: u32,
    links: u64,
    uid: u64,
    gid: u64,
    size: i64,
  }

  impl SupervisorDescriptorSnapshot {
    fn capture(descriptor: BorrowedFd<'_>) -> io::Result<Self> {
      // SAFETY: zero is a valid initial state for stat.
      let mut stat: libc::stat = unsafe { std::mem::zeroed() };
      // SAFETY: stat is writable storage and descriptor remains live.
      if unsafe { libc::fstat(descriptor.as_raw_fd(), &mut stat) } != 0 {
        return Err(io::Error::last_os_error());
      }
      Ok(Self {
        device: stat.st_dev as u64,
        inode: stat.st_ino as u64,
        mode: stat.st_mode as u32,
        links: stat.st_nlink as u64,
        uid: stat.st_uid as u64,
        gid: stat.st_gid as u64,
        size: stat.st_size as i64,
      })
    }

    fn platform_identity(&self) -> Value {
      json!({
        "kind": "platform-object",
        "value": format!(
          "unix-dev-ino:{:016x}{:016x}",
          self.device, self.inode
        ),
      })
    }
  }

  struct SupervisorLstatResources {
    workspace: OwnedFd,
    root: Option<OwnedFd>,
    arena: Option<OwnedFd>,
    root_created: bool,
    arena_created: bool,
    source_created: bool,
    before_root: SupervisorDescriptorSnapshot,
    before_arena: SupervisorDescriptorSnapshot,
    before_arena_descriptor_flags: libc::c_int,
    before_arena_status_flags: libc::c_int,
  }

  impl SupervisorLstatResources {
    fn materialize(
      workspace: OwnedFd,
      case: SupervisorLstatCase,
      deadline: &SupervisorDeadline,
    ) -> io::Result<Self> {
      deadline.check(SupervisorDeadlineCheckpoint::TransitionStart)?;
      require_workspace_root(workspace.as_fd(), deadline)?;

      let mut resources = Self {
        workspace,
        root: None,
        arena: None,
        root_created: false,
        arena_created: false,
        source_created: false,
        before_root: zero_snapshot(),
        before_arena: zero_snapshot(),
        before_arena_descriptor_flags: 0,
        before_arena_status_flags: 0,
      };
      mkdirat_exact(resources.workspace.as_fd(), ROOT_NAME, 0o700)?;
      resources.root_created = true;
      let root = openat(
        resources.workspace.as_fd(),
        ROOT_NAME,
        libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        None,
      )?;
      fchmod_exact(root.as_fd(), 0o700)?;
      resources.root = Some(root);

      if case == SupervisorLstatCase::Existing {
        let source = openat(
          resources.root_fd(),
          LSTAT_SOURCE_NAME,
          libc::O_WRONLY
            | libc::O_CREAT
            | libc::O_EXCL
            | libc::O_NOFOLLOW
            | libc::O_CLOEXEC,
          Some(0o600),
        )?;
        resources.source_created = true;
        fchmod_exact(source.as_fd(), 0o600)?;
      }

      let arena = openat(
        resources.workspace.as_fd(),
        ARENA_NAME,
        libc::O_RDWR
          | libc::O_CREAT
          | libc::O_EXCL
          | libc::O_NOFOLLOW
          | libc::O_CLOEXEC,
        Some(0o600),
      )?;
      resources.arena_created = true;
      fchmod_exact(arena.as_fd(), 0o600)?;
      ftruncate_exact(arena.as_fd(), ARENA_CAPACITY_BYTES)?;
      resources.arena = Some(arena);

      let before_root =
        SupervisorDescriptorSnapshot::capture(resources.root_fd())?;
      let before_arena =
        SupervisorDescriptorSnapshot::capture(resources.arena_fd())?;
      require_exact_resource_shapes(
        &before_root,
        &before_arena,
        resources.root_fd(),
        resources.arena_fd(),
      )?;
      require_exact_lstat_root(
        resources.root_fd(),
        case,
        &before_root,
        deadline,
      )?;
      require_zero_arena(resources.arena_fd(), deadline)?;
      deadline.check(SupervisorDeadlineCheckpoint::ValidationComplete)?;
      resources.before_root = before_root;
      resources.before_arena = before_arena;
      resources.before_arena_descriptor_flags =
        descriptor_flags(resources.arena_fd())?;
      resources.before_arena_status_flags =
        descriptor_status_flags(resources.arena_fd())?;
      Ok(resources)
    }

    fn root_fd(&self) -> BorrowedFd<'_> {
      self
        .root
        .as_ref()
        .expect("materialized resources retain root")
        .as_fd()
    }

    fn arena_fd(&self) -> BorrowedFd<'_> {
      self
        .arena
        .as_ref()
        .expect("materialized resources retain arena")
        .as_fd()
    }

    fn revalidate(
      &self,
      case: SupervisorLstatCase,
      deadline: &SupervisorDeadline,
    ) -> io::Result<()> {
      deadline.check(SupervisorDeadlineCheckpoint::ValidationComplete)?;
      let root = SupervisorDescriptorSnapshot::capture(self.root_fd())?;
      let arena = SupervisorDescriptorSnapshot::capture(self.arena_fd())?;
      if root != self.before_root
        || arena != self.before_arena
        || descriptor_flags(self.arena_fd())?
          != self.before_arena_descriptor_flags
        || descriptor_status_flags(self.arena_fd())?
          != self.before_arena_status_flags
      {
        return Err(invalid_data(
          "supervisor lstat resources changed during transfer",
        ));
      }
      require_exact_resource_shapes(
        &root,
        &arena,
        self.root_fd(),
        self.arena_fd(),
      )?;
      require_exact_lstat_root(self.root_fd(), case, &root, deadline)?;
      require_zero_arena(self.arena_fd(), deadline)?;
      deadline.check(SupervisorDeadlineCheckpoint::ValidationComplete)
    }

    fn descriptor_slots(
      &self,
      identity: &SupervisorGeneratedLstatIdentity,
      binding: &SupervisorCaseBinding,
    ) -> io::Result<(Vec<u8>, String)> {
      let root_empty = identity.case.root_is_empty();
      let value = json!({
        "schema": DESCRIPTOR_SLOTS_SCHEMA,
        "profile": CAPSEC_PROFILE,
        "runNonce": binding.run_nonce,
        "target": identity.target,
        "featureSet": identity.feature_set,
        "parentStandaloneDigest": binding.parent_standalone_digest,
        "engineDigest": binding.engine_digest,
        "forkCommit": identity.fork_commit,
        "fixtureArtifactDigest": identity.fixture_artifact_digest,
        "executionIdentityDigest": binding.execution_identity_digest,
        "sourceClosureDigest": binding.source_closure_digest,
        "caseId": identity.case.case_id(),
        "edgeId": LSTAT_EDGE_ID,
        "requirementId": LSTAT_REQUIREMENT_ID,
        "caseKind": identity.case.case_kind(),
        "slots": [
          {
            "transferIndex": 0,
            "role": "logical-root",
            "descriptorSlot": 0,
            "root": "$PROJECT",
            "bindingId": LSTAT_ROOT_BINDING_ID,
            "fixtureIdentity": {
              "kind": "opaque-token",
              "value": LSTAT_ROOT_FIXTURE_IDENTITY,
            },
            "platformIdentity": self.before_root.platform_identity(),
            "objectKind": "directory",
            "mode": self.before_root.mode,
            "uid": self.before_root.uid.to_string(),
            "gid": self.before_root.gid.to_string(),
            "emptyAtTransfer": root_empty,
          },
          {
            "transferIndex": 1,
            "role": "arena",
            "platformIdentity": self.before_arena.platform_identity(),
            "objectKind": "regular-file",
            "mode": self.before_arena.mode,
            "uid": self.before_arena.uid.to_string(),
            "gid": self.before_arena.gid.to_string(),
            "capacityBytes": ARENA_CAPACITY_BYTES,
            "zeroFilledAtTransfer": true,
          },
        ],
      });
      Ok((
        canonical_json_bytes(&value)?,
        hjcs_digest(DESCRIPTOR_SLOTS_DIGEST_DOMAIN, &value)?,
      ))
    }
  }

  impl Drop for SupervisorLstatResources {
    fn drop(&mut self) {
      if self.source_created {
        if let Some(root) = &self.root {
          let _ = unlinkat(root.as_fd(), LSTAT_SOURCE_NAME, 0);
        }
        self.source_created = false;
      }
      if self.root_created {
        let _ = unlinkat(self.workspace.as_fd(), ROOT_NAME, libc::AT_REMOVEDIR);
        self.root_created = false;
      }
      if self.arena_created {
        let _ = unlinkat(self.workspace.as_fd(), ARENA_NAME, 0);
        self.arena_created = false;
      }
    }
  }

  fn zero_snapshot() -> SupervisorDescriptorSnapshot {
    SupervisorDescriptorSnapshot {
      device: 0,
      inode: 0,
      mode: 0,
      links: 0,
      uid: 0,
      gid: 0,
      size: 0,
    }
  }

  fn require_workspace_root(
    workspace: BorrowedFd<'_>,
    deadline: &SupervisorDeadline,
  ) -> io::Result<()> {
    let before = SupervisorDescriptorSnapshot::capture(workspace)?;
    if before.mode & libc::S_IFMT as u32 != libc::S_IFDIR as u32
      || descriptor_flags(workspace)? & libc::FD_CLOEXEC == 0
      || descriptor_status_flags(workspace)? & libc::O_ACCMODE != libc::O_RDONLY
    {
      return Err(invalid_data("supervisor workspace descriptor is not exact"));
    }
    let entries = scan_directory(workspace, deadline)?;
    if !entries.is_empty() {
      return Err(invalid_data("supervisor workspace is not initially empty"));
    }
    if SupervisorDescriptorSnapshot::capture(workspace)? != before {
      return Err(invalid_data("supervisor workspace changed while inspected"));
    }
    Ok(())
  }

  fn require_exact_resource_shapes(
    root: &SupervisorDescriptorSnapshot,
    arena: &SupervisorDescriptorSnapshot,
    root_fd: BorrowedFd<'_>,
    arena_fd: BorrowedFd<'_>,
  ) -> io::Result<()> {
    let root_flags = descriptor_status_flags(root_fd)?;
    let arena_flags = descriptor_status_flags(arena_fd)?;
    if root.mode != (libc::S_IFDIR as u32 | 0o700)
      || arena.mode != (libc::S_IFREG as u32 | 0o600)
      || arena.links != 1
      || arena.size != ARENA_CAPACITY_BYTES
      || (root.device == arena.device && root.inode == arena.inode)
      || root_flags & libc::O_ACCMODE != libc::O_RDONLY
      || root_flags & libc::O_APPEND != 0
      || arena_flags & libc::O_ACCMODE != libc::O_RDWR
      || arena_flags & libc::O_APPEND != 0
      || descriptor_flags(root_fd)? & libc::FD_CLOEXEC == 0
      || descriptor_flags(arena_fd)? & libc::FD_CLOEXEC == 0
    {
      return Err(invalid_data("supervisor lstat resource shape is not exact"));
    }
    Ok(())
  }

  fn require_exact_lstat_root(
    root: BorrowedFd<'_>,
    case: SupervisorLstatCase,
    expected_root: &SupervisorDescriptorSnapshot,
    deadline: &SupervisorDeadline,
  ) -> io::Result<()> {
    let entries = scan_directory(root, deadline)?;
    let expected = if case == SupervisorLstatCase::Existing {
      vec![LSTAT_SOURCE_NAME.as_bytes().to_vec()]
    } else {
      Vec::new()
    };
    if entries != expected {
      return Err(invalid_data("supervisor lstat root topology is not exact"));
    }
    if case == SupervisorLstatCase::Existing {
      let source = openat(
        root,
        LSTAT_SOURCE_NAME,
        libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        None,
      )?;
      let before = SupervisorDescriptorSnapshot::capture(source.as_fd())?;
      let mut byte = 0_u8;
      let read = loop {
        deadline.check(SupervisorDeadlineCheckpoint::ValidationComplete)?;
        // SAFETY: source and byte are live; pread does not alter shared offset.
        let read = unsafe {
          libc::pread(
            source.as_raw_fd(),
            std::ptr::from_mut(&mut byte).cast(),
            1,
            0,
          )
        };
        if read < 0
          && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted
        {
          continue;
        }
        break read;
      };
      if read != 0
        || before.mode != (libc::S_IFREG as u32 | 0o600)
        || before.links != 1
        || before.size != 0
        || (before.device == expected_root.device
          && before.inode == expected_root.inode)
        || SupervisorDescriptorSnapshot::capture(source.as_fd())? != before
      {
        return Err(invalid_data(
          "supervisor existing source is not one exact empty file",
        ));
      }
    } else {
      require_absent_at(root, LSTAT_SOURCE_NAME)?;
    }
    require_absent_at(root, LSTAT_DESTINATION_NAME)
  }

  trait DirectoryScanDeadline {
    fn check_scan(&self) -> io::Result<()>;
  }

  impl DirectoryScanDeadline for SupervisorDeadline {
    fn check_scan(&self) -> io::Result<()> {
      self.check(SupervisorDeadlineCheckpoint::ValidationComplete)
    }
  }

  fn scan_directory(
    directory: BorrowedFd<'_>,
    deadline: &SupervisorDeadline,
  ) -> io::Result<Vec<Vec<u8>>> {
    scan_directory_without_session(directory, deadline)
  }

  fn scan_directory_without_session(
    directory: BorrowedFd<'_>,
    deadline: &impl DirectoryScanDeadline,
  ) -> io::Result<Vec<Vec<u8>>> {
    let scan = openat_scan_directory(
      directory,
      libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
    )?;
    let expected = SupervisorDescriptorSnapshot::capture(directory)?;
    if SupervisorDescriptorSnapshot::capture(scan.as_fd())? != expected {
      return Err(invalid_data(
        "supervisor independent directory scan changed identity",
      ));
    }
    let stream = SupervisorDirectoryStream::from_owned(scan)?;
    let result = (|| {
      let mut entries = Vec::new();
      let mut saw_dot = false;
      let mut saw_dot_dot = false;
      loop {
        deadline.check_scan()?;
        clear_readdir_errno();
        // SAFETY: stream owns the live DIR and each returned name is copied
        // within its record before the next call.
        let entry = unsafe { libc::readdir(stream.raw) };
        if entry.is_null() {
          let errno = readdir_errno();
          if errno != 0 {
            return Err(io::Error::from_raw_os_error(errno));
          }
          break;
        }
        // SAFETY: readdir returned a record with its fixed header accessible.
        let name = unsafe { dirent_name(entry) }?;
        match name.as_slice() {
          b"." if !saw_dot => saw_dot = true,
          b".." if !saw_dot_dot => saw_dot_dot = true,
          b"." | b".." => {
            return Err(invalid_data(
              "supervisor directory repeated a dot entry",
            ));
          }
          _ => entries.push(name),
        }
        if entries.len() > 4 {
          return Err(invalid_data(
            "supervisor directory contains unexpected entries",
          ));
        }
      }
      if !saw_dot || !saw_dot_dot {
        return Err(invalid_data("supervisor directory omitted dot entries"));
      }
      entries.sort();
      Ok(entries)
    })();
    let close_result = stream.close();
    match (result, close_result) {
      (Ok(entries), Ok(())) => Ok(entries),
      (Err(error), _) | (Ok(_), Err(error)) => Err(error),
    }
  }

  struct SupervisorDirectoryStream {
    raw: *mut libc::DIR,
  }

  impl SupervisorDirectoryStream {
    fn from_owned(descriptor: OwnedFd) -> io::Result<Self> {
      let raw_descriptor = descriptor.into_raw_fd();
      // SAFETY: fdopendir takes unique ownership on success.
      let raw = unsafe { libc::fdopendir(raw_descriptor) };
      if raw.is_null() {
        let error = io::Error::last_os_error();
        // SAFETY: fdopendir failed and did not take ownership.
        unsafe { libc::close(raw_descriptor) };
        return Err(error);
      }
      Ok(Self { raw })
    }

    fn close(mut self) -> io::Result<()> {
      let raw = std::mem::replace(&mut self.raw, std::ptr::null_mut());
      // SAFETY: raw is the uniquely owned live stream.
      if unsafe { libc::closedir(raw) } != 0 {
        return Err(io::Error::last_os_error());
      }
      Ok(())
    }
  }

  impl Drop for SupervisorDirectoryStream {
    fn drop(&mut self) {
      if !self.raw.is_null() {
        // SAFETY: error-path close of the uniquely owned stream.
        unsafe { libc::closedir(self.raw) };
        self.raw = std::ptr::null_mut();
      }
    }
  }

  #[cfg(target_os = "linux")]
  fn clear_readdir_errno() {
    // SAFETY: libc exposes the current thread's errno cell.
    unsafe { *libc::__errno_location() = 0 };
  }

  #[cfg(target_os = "macos")]
  fn clear_readdir_errno() {
    // SAFETY: libc exposes the current thread's errno cell.
    unsafe { *libc::__error() = 0 };
  }

  #[cfg(target_os = "linux")]
  fn readdir_errno() -> libc::c_int {
    // SAFETY: libc exposes the current thread's errno cell.
    unsafe { *libc::__errno_location() }
  }

  #[cfg(target_os = "macos")]
  fn readdir_errno() -> libc::c_int {
    // SAFETY: libc exposes the current thread's errno cell.
    unsafe { *libc::__error() }
  }

  fn fixed_array_length<T, const N: usize>(_: *const [T; N]) -> usize {
    N
  }

  #[cfg(target_os = "linux")]
  unsafe fn dirent_name(entry: *const libc::dirent) -> io::Result<Vec<u8>> {
    // SAFETY: caller guarantees the fixed d_reclen header is accessible.
    let record_length = unsafe {
      std::ptr::read_unaligned(std::ptr::addr_of!((*entry).d_reclen))
    } as usize;
    let name_offset = std::mem::offset_of!(libc::dirent, d_name);
    let record_name_bytes = record_length
      .checked_sub(name_offset)
      .ok_or_else(|| invalid_data("supervisor dirent is malformed"))?;
    // SAFETY: only the field address is formed; the slice is bounded below.
    let name_pointer = unsafe { std::ptr::addr_of!((*entry).d_name) };
    let bound = record_name_bytes.min(fixed_array_length(name_pointer));
    // SAFETY: bound is capped by d_reclen and the declared field length.
    let name =
      unsafe { std::slice::from_raw_parts(name_pointer.cast::<u8>(), bound) };
    let end = name
      .iter()
      .position(|byte| *byte == 0)
      .ok_or_else(|| invalid_data("supervisor dirent is malformed"))?;
    Ok(name[..end].to_vec())
  }

  #[cfg(target_os = "macos")]
  unsafe fn dirent_name(entry: *const libc::dirent) -> io::Result<Vec<u8>> {
    // SAFETY: caller guarantees fixed header fields are accessible.
    let record_length = unsafe {
      std::ptr::read_unaligned(std::ptr::addr_of!((*entry).d_reclen))
    } as usize;
    // SAFETY: same fixed-header guarantee as d_reclen.
    let name_length = unsafe {
      std::ptr::read_unaligned(std::ptr::addr_of!((*entry).d_namlen))
    } as usize;
    // SAFETY: only the field address is formed; the slice is bounded below.
    let name_pointer = unsafe { std::ptr::addr_of!((*entry).d_name) };
    let capacity = fixed_array_length(name_pointer);
    let available = record_length
      .checked_sub(std::mem::offset_of!(libc::dirent, d_name))
      .ok_or_else(|| invalid_data("supervisor dirent is malformed"))?;
    let terminated = name_length
      .checked_add(1)
      .ok_or_else(|| invalid_data("supervisor dirent is malformed"))?;
    if name_length >= capacity || terminated > available {
      return Err(invalid_data("supervisor dirent is malformed"));
    }
    // SAFETY: terminated is within both record and fixed field bounds.
    let name = unsafe {
      std::slice::from_raw_parts(name_pointer.cast::<u8>(), terminated)
    };
    if name[name_length] != 0 || name[..name_length].contains(&0) {
      return Err(invalid_data("supervisor dirent is malformed"));
    }
    Ok(name[..name_length].to_vec())
  }

  fn require_zero_arena(
    arena: BorrowedFd<'_>,
    deadline: &SupervisorDeadline,
  ) -> io::Result<()> {
    let mut buffer = [0_u8; 64 * 1024];
    let mut offset = 0_i64;
    while offset < ARENA_CAPACITY_BYTES {
      deadline.check(SupervisorDeadlineCheckpoint::ArenaRead)?;
      let remaining =
        usize::try_from(ARENA_CAPACITY_BYTES - offset).unwrap_or(usize::MAX);
      let requested = remaining.min(buffer.len());
      // SAFETY: buffer is writable and pread leaves shared offset unchanged.
      let read = unsafe {
        libc::pread(
          arena.as_raw_fd(),
          buffer.as_mut_ptr().cast(),
          requested,
          offset,
        )
      };
      if read < 0 {
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::Interrupted {
          continue;
        }
        return Err(error);
      }
      if read == 0 {
        return Err(invalid_data("supervisor arena ended before capacity"));
      }
      let read = read as usize;
      if buffer[..read].iter().any(|byte| *byte != 0) {
        return Err(invalid_data(
          "supervisor arena is not exactly zero-filled",
        ));
      }
      offset += read as i64;
    }
    let mut extra = 0_u8;
    let tail = loop {
      deadline.check(SupervisorDeadlineCheckpoint::ArenaRead)?;
      // SAFETY: extra is writable and the offset is exactly the fixed capacity.
      let tail = unsafe {
        libc::pread(
          arena.as_raw_fd(),
          std::ptr::from_mut(&mut extra).cast(),
          1,
          ARENA_CAPACITY_BYTES,
        )
      };
      if tail < 0
        && io::Error::last_os_error().kind() == io::ErrorKind::Interrupted
      {
        continue;
      }
      break tail;
    };
    if tail != 0 {
      return Err(invalid_data(
        "supervisor arena contains bytes beyond capacity",
      ));
    }
    Ok(())
  }

  fn require_exact_retained_arena(
    resources: &SupervisorLstatResources,
  ) -> io::Result<()> {
    let arena = SupervisorDescriptorSnapshot::capture(resources.arena_fd())?;
    if arena != resources.before_arena
      || arena.mode != (libc::S_IFREG as u32 | 0o600)
      || arena.links != 1
      || arena.size != ARENA_CAPACITY_BYTES
      || (arena.device == resources.before_root.device
        && arena.inode == resources.before_root.inode)
      || descriptor_flags(resources.arena_fd())?
        != resources.before_arena_descriptor_flags
      || descriptor_status_flags(resources.arena_fd())?
        != resources.before_arena_status_flags
      || resources.before_arena_descriptor_flags & libc::FD_CLOEXEC == 0
      || resources.before_arena_status_flags & libc::O_ACCMODE != libc::O_RDWR
      || resources.before_arena_status_flags & libc::O_APPEND != 0
    {
      return Err(invalid_data(
        "supervisor retained arena descriptor is not exact",
      ));
    }
    Ok(())
  }

  fn pread_supervisor_arena(
    arena: BorrowedFd<'_>,
    destination: &mut [u8],
    offset: usize,
    deadline: &SupervisorDeadline,
  ) -> io::Result<usize> {
    let offset = libc::off_t::try_from(offset)
      .map_err(|_| invalid_data("supervisor arena offset overflowed"))?;
    loop {
      deadline.check(SupervisorDeadlineCheckpoint::ArenaReadAttempt)?;
      // SAFETY: destination is writable for its exact length, arena is live,
      // and pread leaves the shared open-file-description offset unchanged.
      let read = unsafe {
        libc::pread(
          arena.as_raw_fd(),
          destination.as_mut_ptr().cast(),
          destination.len(),
          offset,
        )
      };
      let read_error = (read < 0).then(io::Error::last_os_error);
      deadline.check(SupervisorDeadlineCheckpoint::ArenaReadComplete)?;
      if let Some(error) = read_error {
        if error.kind() == io::ErrorKind::Interrupted {
          continue;
        }
        return Err(error);
      }
      let read = usize::try_from(read)
        .map_err(|_| invalid_data("supervisor arena read overflowed"))?;
      if read > destination.len() {
        return Err(invalid_data(
          "supervisor arena read exceeded its requested bound",
        ));
      }
      return Ok(read);
    }
  }

  fn require_supervisor_arena_eof(
    arena: BorrowedFd<'_>,
    deadline: &SupervisorDeadline,
  ) -> io::Result<()> {
    let mut extra = [0_u8; 1];
    let capacity = usize::try_from(ARENA_CAPACITY_BYTES)
      .map_err(|_| invalid_data("supervisor arena capacity overflowed"))?;
    if pread_supervisor_arena(arena, &mut extra, capacity, deadline)? != 0 {
      return Err(invalid_data(
        "supervisor arena contains bytes beyond capacity",
      ));
    }
    Ok(())
  }

  fn read_supervisor_arena_first_pass(
    resources: &SupervisorLstatResources,
    deadline: &SupervisorDeadline,
  ) -> io::Result<Vec<u8>> {
    require_exact_retained_arena(resources)?;
    let capacity = usize::try_from(ARENA_CAPACITY_BYTES)
      .map_err(|_| invalid_data("supervisor arena capacity overflowed"))?;
    let mut buffer = [0_u8; 64 * 1024];
    let mut payload = Vec::new();
    let mut tail_started = false;
    let mut offset = 0_usize;
    while offset < capacity {
      let requested = (capacity - offset).min(buffer.len());
      let read = pread_supervisor_arena(
        resources.arena_fd(),
        &mut buffer[..requested],
        offset,
        deadline,
      )?;
      if read == 0 {
        return Err(invalid_data("supervisor arena ended before capacity"));
      }
      let bytes = &buffer[..read];
      if tail_started {
        if bytes.iter().any(|byte| *byte != 0) {
          return Err(invalid_data(
            "supervisor arena unused tail is not exactly zero",
          ));
        }
      } else if let Some(tail_offset) = bytes.iter().position(|byte| *byte == 0)
      {
        payload.extend_from_slice(&bytes[..tail_offset]);
        if bytes[tail_offset..].iter().any(|byte| *byte != 0) {
          return Err(invalid_data(
            "supervisor arena payload is not one exact prefix",
          ));
        }
        tail_started = true;
      } else {
        payload.extend_from_slice(bytes);
      }
      offset = offset
        .checked_add(read)
        .ok_or_else(|| invalid_data("supervisor arena offset overflowed"))?;
    }
    require_supervisor_arena_eof(resources.arena_fd(), deadline)?;
    require_exact_retained_arena(resources)?;
    if payload.is_empty() {
      return Err(invalid_data("supervisor arena payload is empty"));
    }
    Ok(payload)
  }

  fn read_supervisor_arena_second_pass(
    resources: &SupervisorLstatResources,
    expected_payload: &[u8],
    deadline: &SupervisorDeadline,
  ) -> io::Result<()> {
    require_exact_retained_arena(resources)?;
    let capacity = usize::try_from(ARENA_CAPACITY_BYTES)
      .map_err(|_| invalid_data("supervisor arena capacity overflowed"))?;
    if expected_payload.is_empty() || expected_payload.len() > capacity {
      return Err(invalid_data(
        "supervisor arena payload length is outside capacity",
      ));
    }
    let mut buffer = [0_u8; 64 * 1024];
    let mut offset = 0_usize;
    while offset < capacity {
      let requested = (capacity - offset).min(buffer.len());
      let read = pread_supervisor_arena(
        resources.arena_fd(),
        &mut buffer[..requested],
        offset,
        deadline,
      )?;
      if read == 0 {
        return Err(invalid_data("supervisor arena ended before capacity"));
      }
      for (index, byte) in buffer[..read].iter().copied().enumerate() {
        let absolute = offset
          .checked_add(index)
          .ok_or_else(|| invalid_data("supervisor arena offset overflowed"))?;
        let expected = expected_payload.get(absolute).copied().unwrap_or(0);
        if byte != expected {
          return Err(invalid_data(
            "supervisor arena changed between bounded reads",
          ));
        }
      }
      offset = offset
        .checked_add(read)
        .ok_or_else(|| invalid_data("supervisor arena offset overflowed"))?;
    }
    require_supervisor_arena_eof(resources.arena_fd(), deadline)?;
    require_exact_retained_arena(resources)
  }

  fn reconcile_supervisor_candidate_arena(
    resources: &SupervisorLstatResources,
    identity: &SupervisorGeneratedLstatIdentity,
    binding: &SupervisorCaseBinding,
    descriptor_slots_digest: &str,
    candidate_response: &SupervisorCandidateResponseFacts,
    deadline: &SupervisorDeadline,
  ) -> io::Result<SupervisorCandidateArenaFacts> {
    let payload_bytes = read_supervisor_arena_first_pass(resources, deadline)?;
    deadline.check(SupervisorDeadlineCheckpoint::ArenaFirstPassComplete)?;
    read_supervisor_arena_second_pass(resources, &payload_bytes, deadline)?;
    deadline.check(SupervisorDeadlineCheckpoint::ArenaSecondPassComplete)?;

    // This establishes only syntactic byte identity. Trace phases, operation
    // semantics, and oracle meaning belong to the unreachable next transition.
    let payload_value = parse_canonical_jcs(&payload_bytes)?;
    let payload_byte_digest = sha256_digest(&payload_bytes);
    let engine_trace_digest =
      raw_frame_digest(ENGINE_TRACE_DIGEST_DOMAIN, &payload_bytes);
    if engine_trace_digest != candidate_response.engine_trace_digest {
      return Err(invalid_data(
        "supervisor arena trace digest does not join the response",
      ));
    }
    let capacity = usize::try_from(ARENA_CAPACITY_BYTES)
      .map_err(|_| invalid_data("supervisor arena capacity overflowed"))?;
    let unused_tail_length =
      capacity.checked_sub(payload_bytes.len()).ok_or_else(|| {
        invalid_data("supervisor arena payload exceeds capacity")
      })?;
    let unused_tail_byte_digest = zero_sha256_digest(unused_tail_length);
    let mut object = Map::new();
    object.insert("schema".into(), json!(CANDIDATE_ARENA_SCHEMA));
    binding.insert_common(&mut object, identity);
    object.insert(
      "descriptorSlotsDigest".into(),
      json!(descriptor_slots_digest),
    );
    object.insert(
      "arenaTransferIndex".into(),
      json!(LSTAT_ARENA_TRANSFER_INDEX),
    );
    object.insert(
      "arenaPlatformIdentity".into(),
      resources.before_arena.platform_identity(),
    );
    object.insert("capacityBytes".into(), json!(capacity));
    object.insert(
      "payload".into(),
      json!({
        "offset": 0,
        "length": payload_bytes.len(),
        "byteDigest": payload_byte_digest,
        "engineTraceDigest": engine_trace_digest,
      }),
    );
    object.insert(
      "unusedTail".into(),
      json!({
        "offset": payload_bytes.len(),
        "length": unused_tail_length,
        "byteDigest": unused_tail_byte_digest,
        "allZero": true,
      }),
    );
    let value = Value::Object(object);
    let exact =
      exact_object(&value, CANDIDATE_ARENA_FIELDS, "candidate arena")?;
    binding.validate_common(exact, identity)?;
    require_text_eq(exact, "schema", CANDIDATE_ARENA_SCHEMA)?;
    require_text_eq(exact, "descriptorSlotsDigest", descriptor_slots_digest)?;
    require_usize_eq(exact, "arenaTransferIndex", LSTAT_ARENA_TRANSFER_INDEX)?;
    require_usize_eq(exact, "capacityBytes", capacity)?;
    if required_value(exact, "arenaPlatformIdentity")?
      != &resources.before_arena.platform_identity()
    {
      return Err(invalid_data(
        "supervisor candidate arena identity is not exact",
      ));
    }
    let digest = hjcs_digest(CANDIDATE_ARENA_DIGEST_DOMAIN, &value)?;
    if digest != candidate_response.candidate_arena_digest {
      return Err(invalid_data(
        "supervisor candidate arena digest does not join the response",
      ));
    }
    Ok(SupervisorCandidateArenaFacts {
      value,
      digest,
      payload_bytes,
      payload_value,
      payload_byte_digest,
      engine_trace_digest,
      unused_tail_byte_digest,
    })
  }

  /// One production-uncalled FD4 topology session. Every transition is
  /// one-way and any error destroys both live endpoints and makes the state
  /// permanently refused.
  ///
  /// @ref LLP 0019#parentsupervisor-transport-and-single-process-lifetime-cell
  /// [implements] — The supervisor sends exactly one right-free spawn request,
  /// adopts exactly one parent-transferred candidate peer, and transfers the
  /// root then arena before stopping at the response boundary.
  struct SupervisorFd4Session {
    fd4: Option<FramedStreamEndpoint>,
    candidate_peer: Option<FramedStreamEndpoint>,
    workspace: Option<OwnedFd>,
    identity: Option<SupervisorGeneratedLstatIdentity>,
    binding: SupervisorCaseBinding,
    entry: Option<SupervisorEntryFacts>,
    deadline: Option<SupervisorDeadline>,
    state: SupervisorFd4State,
    supervisor_request_raw_bytes: Vec<u8>,
    supervisor_request_frame_digest: String,
    spawn_request_raw_bytes: Option<Vec<u8>>,
    spawn_request_frame_digest: Option<String>,
    spawn_result: Option<SupervisorSpawnResultFacts>,
  }

  impl SupervisorFd4Session {
    fn begin(
      fd4: FramedStreamEndpoint,
      workspace: OwnedFd,
      identity: SupervisorGeneratedLstatIdentity,
      entry: SupervisorEntryFacts,
      supervisor_request_raw_bytes: &[u8],
    ) -> io::Result<Self> {
      let value = parse_canonical_jcs(supervisor_request_raw_bytes)?;
      let object =
        exact_object(&value, SUPERVISOR_REQUEST_FIELDS, "supervisor request")?;
      require_text_eq(object, "schema", SUPERVISOR_REQUEST_SCHEMA)?;
      let binding =
        SupervisorCaseBinding::from_supervisor_request(object, &identity)?;
      require_text_eq(
        object,
        "executionProjectionDigest",
        &identity.execution_projection_digest,
      )?;
      let workspace_identity =
        platform_identity_text(object, "workspaceRootPlatformIdentity")?;
      if workspace_identity != platform_identity_of_fd(workspace.as_fd())? {
        return Err(invalid_data(
          "supervisor request workspace identity does not match FD5",
        ));
      }
      let deadline = SupervisorDeadline::from_request(object)?;
      deadline.check(SupervisorDeadlineCheckpoint::ValidationComplete)?;
      let frame_digest = raw_frame_digest(
        SUPERVISOR_REQUEST_DIGEST_DOMAIN,
        supervisor_request_raw_bytes,
      );
      Ok(Self {
        fd4: Some(fd4),
        candidate_peer: None,
        workspace: Some(workspace),
        identity: Some(identity),
        binding,
        entry: Some(entry),
        deadline: Some(deadline),
        state: SupervisorFd4State::SpawnRequestPending,
        supervisor_request_raw_bytes: supervisor_request_raw_bytes.to_vec(),
        supervisor_request_frame_digest: frame_digest,
        spawn_request_raw_bytes: None,
        spawn_request_frame_digest: None,
        spawn_result: None,
      })
    }

    fn send_candidate_spawn_request(&mut self) -> io::Result<()> {
      if self.state != SupervisorFd4State::SpawnRequestPending {
        return self.refuse(invalid_input(
          "supervisor spawn-request transition is out of order",
        ));
      }
      if let Err(error) = self
        .deadline()
        .check(SupervisorDeadlineCheckpoint::TransitionStart)
      {
        return self.refuse(error);
      }
      let identity = self.identity();
      let entry = self
        .entry
        .as_ref()
        .expect("pending session retains entry facts");
      let mut object = Map::new();
      self.binding.insert_common(&mut object, identity);
      object.insert("schema".into(), json!(CANDIDATE_SPAWN_REQUEST_SCHEMA));
      object.insert(
        "supervisorRequestFrameDigest".into(),
        json!(self.supervisor_request_frame_digest),
      );
      object
        .insert("supervisorPid".into(), json!(entry.supervisor_pid.as_str()));
      object.insert(
        "supervisorPgid".into(),
        json!(entry.supervisor_pgid.as_str()),
      );
      object.insert(
        "observedParentPid".into(),
        json!(entry.observed_parent_pid.as_str()),
      );
      object.insert(
        "observedParentPgid".into(),
        json!(entry.observed_parent_pgid.as_str()),
      );
      object.insert(
        "candidateArgv".into(),
        json!([
          CANDIDATE_RESERVED_FLAG,
          identity.fixture_artifact_digest,
          identity.case.case_id(),
        ]),
      );
      object.insert(
        "candidateReadyFrameMaxBytes".into(),
        json!(MAX_CANDIDATE_READY_PACKET_BYTES),
      );
      let raw_bytes = match canonical_json_bytes(&Value::Object(object)) {
        Ok(bytes) => bytes,
        Err(error) => return self.refuse(error),
      };
      let digest =
        raw_frame_digest(CANDIDATE_SPAWN_REQUEST_DIGEST_DOMAIN, &raw_bytes);
      let send_result = self.fd4().send_packet_with_descriptors(
        &raw_bytes,
        &[],
        self.deadline().work_instant,
      );
      if let Err(error) = send_result {
        return self.refuse(error);
      }
      if let Err(error) =
        self.fd4().shutdown_write(self.deadline().work_instant)
      {
        return self.refuse(error);
      }
      if let Err(error) = self
        .deadline()
        .check(SupervisorDeadlineCheckpoint::TransportComplete)
      {
        return self.refuse(error);
      }
      self.spawn_request_raw_bytes = Some(raw_bytes);
      self.spawn_request_frame_digest = Some(digest);
      self.state = SupervisorFd4State::SpawnResultPending;
      Ok(())
    }

    fn receive_candidate_spawn_result(&mut self) -> io::Result<()> {
      if self.state != SupervisorFd4State::SpawnResultPending {
        return self.refuse(invalid_input(
          "supervisor spawn-result transition is out of order",
        ));
      }
      let packet = match self.fd4().receive_one_canonical_jcs_frame(
        FrameByteLimit::CONTROL,
        1,
        self.deadline().work_instant,
      ) {
        Ok(packet) => packet,
        Err(error) => return self.refuse(error),
      };
      if let Err(error) = self
        .deadline()
        .check(SupervisorDeadlineCheckpoint::TransportComplete)
      {
        return self.refuse(error);
      }
      let facts = match validate_spawn_result(
        &packet.raw_bytes,
        &packet.value,
        self.identity(),
        &self.binding,
        self.deadline(),
        &self.supervisor_request_raw_bytes,
        &self.supervisor_request_frame_digest,
        self
          .spawn_request_raw_bytes
          .as_deref()
          .expect("spawn-result state retains spawn request"),
        self
          .spawn_request_frame_digest
          .as_deref()
          .expect("spawn-result state retains spawn digest"),
      ) {
        Ok(facts) => facts,
        Err(error) => return self.refuse(error),
      };
      let [descriptor]: [OwnedFd; 1] = match packet.descriptors.try_into() {
        Ok(descriptors) => descriptors,
        Err(_) => {
          return self.refuse(invalid_data(
            "supervisor spawn result changed descriptor count",
          ));
        }
      };
      let candidate_peer =
        match FramedStreamEndpoint::from_received_connected_unix_stream(
          descriptor,
        ) {
          Ok(endpoint) => endpoint,
          Err(error) => return self.refuse(error),
        };
      let received_identity =
        match platform_identity_of_fd(candidate_peer.as_fd()) {
          Ok(identity) => identity,
          Err(error) => return self.refuse(error),
        };
      if received_identity != facts.candidate_endpoint_identity {
        return self.refuse(invalid_data(
          "supervisor received candidate peer identity is inexact",
        ));
      }
      self.candidate_peer = Some(candidate_peer);
      self.spawn_result = Some(facts);
      self.state = SupervisorFd4State::CandidateRequestPending;
      Ok(())
    }

    fn materialize_and_send_lstat_request(
      mut self,
    ) -> io::Result<SupervisorAwaitingCandidateOutcome> {
      if self.state != SupervisorFd4State::CandidateRequestPending {
        return self.refuse(invalid_input(
          "supervisor candidate-request transition is out of order",
        ));
      }
      let identity = self
        .identity
        .take()
        .expect("candidate-request state retains identity");
      let workspace = self
        .workspace
        .take()
        .expect("candidate-request state retains workspace");
      let deadline = self
        .deadline
        .take()
        .expect("candidate-request state retains deadline");
      let resources = SupervisorLstatResources::materialize(
        workspace,
        identity.case,
        &deadline,
      )?;
      let (descriptor_slots_raw_bytes, descriptor_slots_digest) =
        resources.descriptor_slots(&identity, &self.binding)?;
      let spawn_result = self
        .spawn_result
        .take()
        .expect("candidate-request state retains spawn result");
      let mut object = Map::new();
      self.binding.insert_common(&mut object, &identity);
      object.insert("schema".into(), json!(CANDIDATE_REQUEST_SCHEMA));
      object.insert(
        "executionProjectionDigest".into(),
        json!(identity.execution_projection_digest),
      );
      object.insert(
        "candidateSpawnResultFrameDigest".into(),
        json!(spawn_result.frame_digest),
      );
      object.insert(
        "descriptorSlotsDigest".into(),
        json!(descriptor_slots_digest),
      );
      object.insert("requiredCapturedUmask".into(), json!(PINNED_CHILD_UMASK));
      let candidate_request_raw_bytes =
        canonical_json_bytes(&Value::Object(object))?;
      let candidate_request_frame_digest = raw_frame_digest(
        CANDIDATE_REQUEST_DIGEST_DOMAIN,
        &candidate_request_raw_bytes,
      );
      let candidate_peer = self
        .candidate_peer
        .take()
        .expect("candidate-request state retains candidate peer");
      candidate_peer.send_packet_with_descriptors(
        &candidate_request_raw_bytes,
        &[resources.root_fd(), resources.arena_fd()],
        deadline.work_instant,
      )?;
      candidate_peer.shutdown_write(deadline.work_instant)?;
      resources.revalidate(identity.case, &deadline)?;
      deadline.check(SupervisorDeadlineCheckpoint::TransportComplete)?;

      self.state = SupervisorFd4State::AwaitingCandidateOutcome;
      Ok(SupervisorAwaitingCandidateOutcome {
        _fd4: self.fd4.take().expect("awaiting state retains FD4"),
        _candidate_peer: candidate_peer,
        _resources: resources,
        _identity: identity,
        _binding: self.binding,
        _entry: self
          .entry
          .take()
          .expect("awaiting state retains entry facts"),
        _deadline: deadline,
        _supervisor_request_raw_bytes: self.supervisor_request_raw_bytes,
        _supervisor_request_frame_digest: self.supervisor_request_frame_digest,
        _spawn_request_raw_bytes: self
          .spawn_request_raw_bytes
          .take()
          .expect("awaiting state retains spawn request"),
        _spawn_request_frame_digest: self
          .spawn_request_frame_digest
          .take()
          .expect("awaiting state retains spawn digest"),
        _spawn_result: spawn_result,
        _candidate_request_raw_bytes: candidate_request_raw_bytes,
        _candidate_request_frame_digest: candidate_request_frame_digest,
        _descriptor_slots_raw_bytes: descriptor_slots_raw_bytes,
        _descriptor_slots_digest: descriptor_slots_digest,
      })
    }

    fn fd4(&self) -> &FramedStreamEndpoint {
      self.fd4.as_ref().expect("live session retains FD4")
    }

    fn identity(&self) -> &SupervisorGeneratedLstatIdentity {
      self
        .identity
        .as_ref()
        .expect("live session retains identity")
    }

    fn deadline(&self) -> &SupervisorDeadline {
      self
        .deadline
        .as_ref()
        .expect("live session retains deadline")
    }

    fn refuse<T>(&mut self, error: io::Error) -> io::Result<T> {
      self.state = SupervisorFd4State::Refused;
      self.fd4.take();
      self.candidate_peer.take();
      self.workspace.take();
      Err(error)
    }
  }

  pub(crate) fn prepare_supervisor_lstat_topology(
    fd4: FramedStreamEndpoint,
    workspace: OwnedFd,
    identity: SupervisorGeneratedLstatIdentity,
    entry: SupervisorEntryFacts,
    supervisor_request_raw_bytes: &[u8],
  ) -> io::Result<SupervisorAwaitingCandidateOutcome> {
    let mut session = SupervisorFd4Session::begin(
      fd4,
      workspace,
      identity,
      entry,
      supervisor_request_raw_bytes,
    )?;
    session.send_candidate_spawn_request()?;
    session.receive_candidate_spawn_result()?;
    session.materialize_and_send_lstat_request()
  }

  fn validate_candidate_terminal(
    raw_bytes: &[u8],
    value: &Value,
    identity: &SupervisorGeneratedLstatIdentity,
    binding: &SupervisorCaseBinding,
    spawn_result: &SupervisorSpawnResultFacts,
    deadline: &SupervisorDeadline,
  ) -> io::Result<SupervisorCandidateTerminalFacts> {
    let object =
      exact_object(value, CANDIDATE_TERMINAL_FIELDS, "candidate terminal")?;
    require_text_eq(object, "schema", CANDIDATE_TERMINAL_SCHEMA)?;
    binding.validate_common(object, identity)?;
    require_text_eq(
      object,
      "candidateSpawnResultFrameDigest",
      &spawn_result.frame_digest,
    )?;
    require_text_eq(object, "candidatePid", &spawn_result.candidate_pid)?;
    require_text_eq(object, "candidatePgid", &spawn_result.candidate_pgid)?;
    require_text_eq(
      object,
      "candidateStartIdentity",
      &spawn_result.candidate_start_identity,
    )?;
    let terminal_observation_monotonic_ns =
      require_positive_decimal(object, "terminalObservationMonotonicNs")?;
    let terminal_ns = terminal_observation_monotonic_ns
      .parse::<u64>()
      .map_err(|_| {
        invalid_data("candidate terminal monotonic observation overflowed")
      })?;
    if terminal_ns < deadline.receipt_ns
      || terminal_ns > deadline.effective_work_ns
    {
      return Err(invalid_data(
        "candidate terminal observation is outside the frozen work interval",
      ));
    }
    require_u64_eq(object, "exitStatus", 0)?;
    if object.get("reaped") != Some(&Value::Bool(true)) {
      return Err(invalid_data("candidate terminal is not exactly reaped"));
    }
    if object.get("supervisorGroupLeaderStillOwned") != Some(&Value::Bool(true))
    {
      return Err(invalid_data(
        "candidate terminal does not retain supervisor group ownership",
      ));
    }
    Ok(SupervisorCandidateTerminalFacts {
      raw_bytes: raw_bytes.to_vec(),
      value: value.clone(),
      frame_digest: raw_frame_digest(
        CANDIDATE_TERMINAL_DIGEST_DOMAIN,
        raw_bytes,
      ),
      terminal_observation_monotonic_ns,
    })
  }

  #[allow(clippy::too_many_arguments)]
  fn validate_candidate_response(
    raw_bytes: &[u8],
    value: &Value,
    identity: &SupervisorGeneratedLstatIdentity,
    binding: &SupervisorCaseBinding,
    spawn_result: &SupervisorSpawnResultFacts,
    candidate_request_frame_digest: &str,
    descriptor_slots_digest: &str,
  ) -> io::Result<SupervisorCandidateResponseFacts> {
    let object =
      exact_object(value, CANDIDATE_RESPONSE_FIELDS, "candidate response")?;
    require_text_eq(object, "schema", CANDIDATE_RESPONSE_SCHEMA)?;
    binding.validate_common(object, identity)?;
    require_text_eq(
      object,
      "candidateRequestFrameDigest",
      candidate_request_frame_digest,
    )?;
    require_text_eq(
      object,
      "acceptedDescriptorSlotsDigest",
      descriptor_slots_digest,
    )?;
    if required_value(object, "capturedUmask")?.as_u64()
      != Some(u64::from(PINNED_CHILD_UMASK))
    {
      return Err(invalid_data(
        "candidate response capturedUmask is not exact",
      ));
    }
    let candidate_arena_digest =
      require_digest(object, "candidateArenaDigest")?;
    let engine_trace_digest = require_digest(object, "engineTraceDigest")?;
    let normalized_observation =
      required_value(object, "normalizedObservedResult")?;
    validate_normalized_observation(normalized_observation, identity)?;
    let observed_result_digest = deno_permissions::rev2::hjcs_digest(
      OBSERVED_RESULT_DIGEST_DOMAIN,
      normalized_observation,
    )
    .map_err(|_| invalid_data("candidate observed result is not canonical"))?;
    require_text_eq(object, "observedResultDigest", &observed_result_digest)?;
    validate_delivery(
      required_value(object, "deliveryFrame")?,
      required_value(object, "deliveryFrameDigest")?,
      normalized_observation,
    )?;
    let resource_inventory = required_value(object, "resourceInventory")?;
    validate_resource_inventory(resource_inventory)?;
    let resource_inventory_digest = deno_permissions::rev2::hjcs_digest(
      RESOURCE_INVENTORY_DIGEST_DOMAIN,
      resource_inventory,
    )
    .map_err(|_| {
      invalid_data("candidate resource inventory is not canonical")
    })?;
    require_text_eq(
      object,
      "resourceInventoryDigest",
      &resource_inventory_digest,
    )?;
    if !required_value(object, "faultObservation")?.is_null()
      || !required_value(object, "faultObservationDigest")?.is_null()
    {
      return Err(invalid_data(
        "candidate lstat response contains a fault observation",
      ));
    }
    validate_no_descendant_claims(
      required_value(object, "noDescendantClaims")?,
      spawn_result,
      binding,
      identity,
    )?;
    if required_value(object, "rootDescriptorsDroppedClaim")?.as_bool()
      != Some(true)
    {
      return Err(invalid_data(
        "candidate response root-descriptor drop claim is not exact",
      ));
    }
    Ok(SupervisorCandidateResponseFacts {
      raw_bytes: raw_bytes.to_vec(),
      value: value.clone(),
      frame_digest: raw_frame_digest(
        CANDIDATE_RESPONSE_DIGEST_DOMAIN,
        raw_bytes,
      ),
      observed_result_digest,
      candidate_arena_digest,
      engine_trace_digest,
    })
  }

  fn validate_normalized_observation(
    value: &Value,
    identity: &SupervisorGeneratedLstatIdentity,
  ) -> io::Result<()> {
    let observation: FilesystemExpectedObservation =
      deno_core::serde_json::from_value(value.clone()).map_err(|_| {
        invalid_data("candidate normalized observation schema is invalid")
      })?;
    let exact_value =
      deno_core::serde_json::to_value(&observation).map_err(|_| {
        invalid_data("candidate normalized observation is not serializable")
      })?;
    if exact_value != *value {
      return Err(invalid_data(
        "candidate normalized observation omitted required null fields",
      ));
    }
    if observation.case_id != identity.case.case_id()
      || observation.edge_id != LSTAT_EDGE_ID
      || observation.requirement_id != LSTAT_REQUIREMENT_ID
      || observation.case_kind != identity.case.case_kind()
      || observation.decision != FilesystemDecision::Allow
      || observation.result.class != identity.case.native_result_class()
      || !observation.side_effects.is_empty()
      || observation.delivery != FilesystemDelivery::Delivered
      || observation.cleanup != FilesystemCleanup::Complete
      || observation.slots.len() != 1
    {
      return Err(invalid_data(
        "candidate normalized observation is not the exact lstat result",
      ));
    }
    match (identity.case, observation.result.digest.as_deref()) {
      (SupervisorLstatCase::Existing, Some(digest))
        if is_canonical_sha256_digest(digest) => {}
      (SupervisorLstatCase::FinalMissing, None) => {}
      _ => {
        return Err(invalid_data(
          "candidate normalized lstat result digest is not exact",
        ));
      }
    }
    let slot = &observation.slots[0];
    if slot.slot_id != LSTAT_SLOT_ID
      || slot.capability != "fs:list"
      || slot.effect_owner != LSTAT_EFFECT_OWNER
      || slot.occurrence.root != FilesystemLogicalRoot::Project
      || slot.occurrence.root_binding_id != LSTAT_ROOT_BINDING_ID
      || slot.occurrence.lexical_path.encoding
        != FilesystemPlatformPathEncoding::Unicode
      || slot.occurrence.lexical_path.value != LSTAT_SOURCE_NAME
      || slot.occurrence.follow_mode != FilesystemFollowMode::NoFollowFinal
      || slot.occurrence.effect_owner != LSTAT_EFFECT_OWNER
      || slot.occurrence.parent_identity.kind
        != FilesystemObjectIdentityKind::PlatformObject
      || !is_platform_identity_text(&slot.occurrence.parent_identity.value)
    {
      return Err(invalid_data("candidate normalized lstat slot is not exact"));
    }
    match (identity.case, &slot.occurrence.final_object_state) {
      (
        SupervisorLstatCase::Existing,
        FilesystemFinalObjectState::Existing {
          identity: final_identity,
        },
      ) if final_identity.kind
        == FilesystemObjectIdentityKind::PlatformObject
        && is_platform_identity_text(&final_identity.value)
        && final_identity.value != slot.occurrence.parent_identity.value => {}
      (
        SupervisorLstatCase::FinalMissing,
        FilesystemFinalObjectState::Missing,
      ) => {}
      _ => {
        return Err(invalid_data(
          "candidate normalized lstat final-object state is not exact",
        ));
      }
    }
    Ok(())
  }

  fn validate_delivery(
    delivery: &Value,
    delivery_digest: &Value,
    observation: &Value,
  ) -> io::Result<()> {
    let delivery = exact_object(
      delivery,
      &["encoding", "bytes"],
      "candidate delivery frame",
    )?;
    require_text_eq(delivery, "encoding", "base64url")?;
    let encoded = require_identifier(delivery, "bytes")?;
    let decoded = URL_SAFE_NO_PAD
      .decode(encoded.as_bytes())
      .map_err(|_| invalid_data("candidate delivery frame is not base64url"))?;
    if URL_SAFE_NO_PAD.encode(&decoded) != encoded {
      return Err(invalid_data(
        "candidate delivery frame is not canonical base64url",
      ));
    }
    let canonical = deno_permissions::rev2::canonical_json(observation)
      .map_err(|_| {
        invalid_data("candidate normalized observation is not canonical")
      })?;
    if decoded != canonical.as_bytes() {
      return Err(invalid_data(
        "candidate delivery bytes do not equal the normalized observation",
      ));
    }
    let expected = raw_frame_digest(DELIVERY_FRAME_DIGEST_DOMAIN, &decoded);
    if delivery_digest.as_str() != Some(expected.as_str()) {
      return Err(invalid_data(
        "candidate delivery frame digest does not match its bytes",
      ));
    }
    Ok(())
  }

  fn validate_resource_inventory(value: &Value) -> io::Result<()> {
    let object = exact_object(
      value,
      &[
        "provisionalResources",
        "actorTokens",
        "deliveryLeases",
        "inheritedRootDescriptorsOpen",
        "namespaceGateHeld",
      ],
      "candidate resource inventory",
    )?;
    for field in [
      "provisionalResources",
      "actorTokens",
      "deliveryLeases",
      "inheritedRootDescriptorsOpen",
    ] {
      if required_value(object, field)?.as_u64() != Some(0) {
        return Err(invalid_data(
          "candidate resource inventory is not terminal zero-state",
        ));
      }
    }
    if required_value(object, "namespaceGateHeld")?.as_bool() != Some(false) {
      return Err(invalid_data(
        "candidate resource inventory retains the namespace gate",
      ));
    }
    Ok(())
  }

  fn validate_no_descendant_claims(
    value: &Value,
    spawn_result: &SupervisorSpawnResultFacts,
    binding: &SupervisorCaseBinding,
    identity: &SupervisorGeneratedLstatIdentity,
  ) -> io::Result<()> {
    let object = exact_object(
      value,
      NO_DESCENDANT_CLAIM_FIELDS,
      "candidate no-descendant claims",
    )?;
    let ready = parse_canonical_jcs(&spawn_result.ready_raw_bytes)?;
    validate_candidate_ready(
      &ready,
      identity,
      &spawn_result.candidate_pid,
      &spawn_result.candidate_pgid,
      &spawn_result.candidate_start_identity,
    )?;
    let ready = ready
      .as_object()
      .ok_or_else(|| invalid_data("candidate ready frame is not an object"))?;
    for field in [
      "noDescendantProfile",
      "candidatePid",
      "candidatePgid",
      "candidateStartIdentity",
      "processLimitReadback",
      "identities",
      "preRequestFdInventory",
      "platformState",
    ] {
      if required_value(object, field)? != required_value(ready, field)? {
        return Err(invalid_data(
          "candidate no-descendant claim diverges from its ready frame",
        ));
      }
    }
    require_text_eq(
      object,
      "sourceClosureDigest",
      &binding.source_closure_digest,
    )?;
    require_text_eq(object, "expectedPgid", &spawn_result.candidate_pgid)?;
    let checkpoints = exact_object(
      required_value(object, "pgidCheckpoints")?,
      &["entry", "preOperation", "postOperation", "preExit"],
      "candidate PGID checkpoints",
    )?;
    for field in ["entry", "preOperation", "postOperation", "preExit"] {
      require_text_eq(checkpoints, field, &spawn_result.candidate_pgid)?;
    }
    Ok(())
  }

  #[allow(clippy::too_many_arguments)]
  fn validate_spawn_result(
    raw_bytes: &[u8],
    value: &Value,
    identity: &SupervisorGeneratedLstatIdentity,
    binding: &SupervisorCaseBinding,
    deadline: &SupervisorDeadline,
    supervisor_request_raw_bytes: &[u8],
    supervisor_request_frame_digest: &str,
    spawn_request_raw_bytes: &[u8],
    spawn_request_frame_digest: &str,
  ) -> io::Result<SupervisorSpawnResultFacts> {
    let object = exact_object(
      value,
      CANDIDATE_SPAWN_RESULT_FIELDS,
      "candidate spawn result",
    )?;
    require_text_eq(object, "schema", CANDIDATE_SPAWN_RESULT_SCHEMA)?;
    binding.validate_common(object, identity)?;
    require_usize_eq(
      object,
      "supervisorRequestFrameByteLength",
      supervisor_request_raw_bytes.len(),
    )?;
    require_text_eq(
      object,
      "supervisorRequestFrameDigest",
      supervisor_request_frame_digest,
    )?;
    require_usize_eq(
      object,
      "candidateSpawnRequestFrameByteLength",
      spawn_request_raw_bytes.len(),
    )?;
    require_text_eq(
      object,
      "candidateSpawnRequestFrameDigest",
      spawn_request_frame_digest,
    )?;
    validate_candidate_argv(
      object.get("candidateArgv"),
      &identity.fixture_artifact_digest,
      identity.case.case_id(),
    )?;
    let candidate_pid = require_positive_decimal(object, "candidatePid")?;
    let candidate_pgid = require_positive_decimal(object, "candidatePgid")?;
    let candidate_start_identity =
      require_identifier(object, "candidateStartIdentity")?;
    validate_opaque_identity(
      object.get("immutableImageIdentity"),
      "candidate immutable image identity",
    )?;
    let parent_endpoint_identity =
      platform_identity_text(object, "candidateEndpointParentIdentity")?;
    let supervisor_endpoint_identity =
      platform_identity_text(object, "candidateEndpointSupervisorIdentity")?;
    if parent_endpoint_identity != supervisor_endpoint_identity {
      return Err(invalid_data(
        "candidate endpoint identity changed across transfer",
      ));
    }
    require_u64_eq(object, "transferredDescriptorCount", 1)?;
    if object.get("admitted") != Some(&Value::Bool(true)) {
      return Err(invalid_data("candidate spawn result is not admitted"));
    }
    validate_candidate_pre_exec(
      object.get("preExec"),
      identity,
      &candidate_pgid,
      &candidate_start_identity,
    )?;
    require_digest(object, "parentPreRequestPlatformObservationDigest")?;
    require_text_eq(
      object,
      "effectiveWorkDeadlineMonotonicNs",
      &deadline.effective_work_text(),
    )?;
    require_text_eq(
      object,
      "effectiveFinalDeadlineMonotonicNs",
      &deadline.effective_final_text(),
    )?;

    let (ready_raw_bytes, ready_frame_digest) = validate_ready_attachment(
      object.get("candidateReadyFrame"),
      identity,
      &candidate_pid,
      &candidate_pgid,
      &candidate_start_identity,
    )?;
    Ok(SupervisorSpawnResultFacts {
      raw_bytes: raw_bytes.to_vec(),
      frame_digest: raw_frame_digest(
        CANDIDATE_SPAWN_RESULT_DIGEST_DOMAIN,
        raw_bytes,
      ),
      ready_raw_bytes,
      ready_frame_digest,
      candidate_pid,
      candidate_pgid,
      candidate_start_identity,
      candidate_endpoint_identity: supervisor_endpoint_identity,
    })
  }

  fn validate_ready_attachment(
    value: Option<&Value>,
    identity: &SupervisorGeneratedLstatIdentity,
    candidate_pid: &str,
    candidate_pgid: &str,
    candidate_start_identity: &str,
  ) -> io::Result<(Vec<u8>, String)> {
    let attachment = exact_object(
      value
        .ok_or_else(|| invalid_data("candidate ready attachment missing"))?,
      &["encoding", "byteLength", "bytes", "digest"],
      "candidate ready attachment",
    )?;
    require_text_eq(attachment, "encoding", "base64url")?;
    let encoded = require_text(attachment, "bytes")?;
    if encoded.is_empty()
      || encoded.contains('=')
      || !encoded.bytes().all(|byte| {
        byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-'
      })
    {
      return Err(invalid_data(
        "candidate ready attachment encoding is not canonical",
      ));
    }
    let raw_bytes =
      URL_SAFE_NO_PAD.decode(encoded.as_bytes()).map_err(|_| {
        invalid_data("candidate ready attachment is not base64url")
      })?;
    if raw_bytes.is_empty()
      || raw_bytes.len() > MAX_CANDIDATE_READY_PACKET_BYTES
    {
      return Err(invalid_data(
        "candidate ready attachment exceeds its exact bound",
      ));
    }
    require_usize_eq(attachment, "byteLength", raw_bytes.len())?;
    let digest = raw_frame_digest(CANDIDATE_READY_DIGEST_DOMAIN, &raw_bytes);
    require_text_eq(attachment, "digest", &digest)?;
    let ready = parse_canonical_jcs(&raw_bytes)?;
    validate_candidate_ready(
      &ready,
      identity,
      candidate_pid,
      candidate_pgid,
      candidate_start_identity,
    )?;
    Ok((raw_bytes, digest))
  }

  fn validate_candidate_ready(
    value: &Value,
    identity: &SupervisorGeneratedLstatIdentity,
    candidate_pid: &str,
    candidate_pgid: &str,
    candidate_start_identity: &str,
  ) -> io::Result<()> {
    let fields = [
      "schema",
      "profile",
      "target",
      "featureSet",
      "embeddedBuildMarker",
      "forkCommit",
      "fixtureArtifactDigest",
      "caseId",
      "noDescendantProfile",
      "candidatePid",
      "candidatePgid",
      "candidateStartIdentity",
      "identities",
      "processLimitReadback",
      "preRequestFdInventory",
      "platformState",
    ];
    let object = exact_object(value, &fields, "candidate ready frame")?;
    require_text_eq(object, "schema", CANDIDATE_READY_SCHEMA)?;
    require_text_eq(object, "profile", CAPSEC_PROFILE)?;
    require_text_eq(object, "target", &identity.target)?;
    require_text_eq(object, "featureSet", &identity.feature_set)?;
    require_identifier(object, "embeddedBuildMarker")?;
    require_text_eq(object, "forkCommit", &identity.fork_commit)?;
    require_text_eq(
      object,
      "fixtureArtifactDigest",
      &identity.fixture_artifact_digest,
    )?;
    require_text_eq(object, "caseId", identity.case.case_id())?;
    let expected_profile = if identity.target == "aarch64-apple-darwin" {
      "macos-rlimit-nproc-zero-reviewed-callgraph-v1"
    } else {
      "linux-rlimit-nproc-zero-seccomp-v1"
    };
    require_text_eq(object, "noDescendantProfile", expected_profile)?;
    require_text_eq(object, "candidatePid", candidate_pid)?;
    require_text_eq(object, "candidatePgid", candidate_pgid)?;
    require_text_eq(
      object,
      "candidateStartIdentity",
      candidate_start_identity,
    )?;
    validate_identities(object.get("identities"))?;
    validate_process_limit(object.get("processLimitReadback"))?;
    validate_candidate_fd_inventory(object.get("preRequestFdInventory"))?;
    validate_platform_state(object.get("platformState"), &identity.target)
  }

  fn validate_candidate_pre_exec(
    value: Option<&Value>,
    identity: &SupervisorGeneratedLstatIdentity,
    candidate_pgid: &str,
    candidate_start_identity: &str,
  ) -> io::Result<()> {
    let object = exact_object(
      value.ok_or_else(|| invalid_data("candidate pre-exec facts missing"))?,
      &[
        "identities",
        "processLimit",
        "descriptorInventory",
        "expectedPgid",
        "observedPgid",
        "startIdentity",
        "platformState",
      ],
      "candidate pre-exec facts",
    )?;
    validate_identities(object.get("identities"))?;
    validate_process_limit(object.get("processLimit"))?;
    validate_candidate_fd_inventory(object.get("descriptorInventory"))?;
    require_text_eq(object, "expectedPgid", candidate_pgid)?;
    require_text_eq(object, "observedPgid", candidate_pgid)?;
    require_text_eq(object, "startIdentity", candidate_start_identity)?;
    validate_platform_state(object.get("platformState"), &identity.target)
  }

  fn validate_identities(value: Option<&Value>) -> io::Result<()> {
    let object = exact_object(
      value.ok_or_else(|| invalid_data("process identities missing"))?,
      &[
        "realUid",
        "effectiveUid",
        "savedUid",
        "realGid",
        "effectiveGid",
        "savedGid",
      ],
      "process identities",
    )?;
    let credentials = ProcessCredentials {
      real_uid: parse_decimal_field(object, "realUid", true)?,
      effective_uid: parse_decimal_field(object, "effectiveUid", true)?,
      saved_uid: parse_decimal_field(object, "savedUid", true)?,
      real_gid: parse_decimal_field(object, "realGid", false)?,
      effective_gid: parse_decimal_field(object, "effectiveGid", false)?,
      saved_gid: parse_decimal_field(object, "savedGid", false)?,
    };
    if credentials.to_identities_value().as_ref() != Some(value.unwrap()) {
      return Err(invalid_data("process identities are not canonical"));
    }
    Ok(())
  }

  fn validate_process_limit(value: Option<&Value>) -> io::Result<()> {
    let object = exact_object(
      value.ok_or_else(|| invalid_data("process limit missing"))?,
      &["soft", "hard"],
      "process limit",
    )?;
    require_text_eq(object, "soft", "0")?;
    require_text_eq(object, "hard", "0")?;
    let readback = RlimitNprocReadback { soft: 0, hard: 0 };
    if readback.to_process_limit_value().as_ref() != value {
      return Err(invalid_data("process limit is not exact"));
    }
    Ok(())
  }

  fn validate_candidate_fd_inventory(value: Option<&Value>) -> io::Result<()> {
    let entries = value
      .and_then(Value::as_array)
      .ok_or_else(|| invalid_data("candidate fd inventory is not an array"))?;
    if entries.len() != 4 {
      return Err(invalid_data(
        "candidate fd inventory does not have four entries",
      ));
    }
    for (index, entry) in entries.iter().enumerate() {
      let object = exact_object(
        entry,
        &[
          "fd",
          "role",
          "closeOnExec",
          "objectKind",
          "platformIdentity",
        ],
        "candidate fd inventory entry",
      )?;
      require_u64_eq(object, "fd", index as u64)?;
      let (role, close_on_exec, kind) = match index {
        0 => ("null-stdin", false, "character-device"),
        1 => ("null-stdout", false, "character-device"),
        2 => ("null-stderr", false, "character-device"),
        3 => ("candidate-control", true, "socket"),
        _ => unreachable!("inventory length is exact"),
      };
      require_text_eq(object, "role", role)?;
      if object.get("closeOnExec") != Some(&Value::Bool(close_on_exec)) {
        return Err(invalid_data(
          "candidate fd inventory close-on-exec fact is inexact",
        ));
      }
      require_text_eq(object, "objectKind", kind)?;
      platform_identity_value(object.get("platformIdentity"))?;
    }
    Ok(())
  }

  fn validate_platform_state(
    value: Option<&Value>,
    target: &str,
  ) -> io::Result<()> {
    let value =
      value.ok_or_else(|| invalid_data("candidate platform state missing"))?;
    if target == "aarch64-apple-darwin" {
      let object = exact_object(
        value,
        &["platform", "seatbeltDisposition", "seatbeltProfileDigest"],
        "candidate macOS state",
      )?;
      require_text_eq(object, "platform", "macos")?;
      let disposition = require_text(object, "seatbeltDisposition")?;
      if !matches!(
        disposition,
        "applied" | "not-applied-nested" | "unavailable"
      ) {
        return Err(invalid_data("candidate Seatbelt disposition is invalid"));
      }
      match (disposition, object.get("seatbeltProfileDigest")) {
        ("applied", Some(Value::String(digest)))
          if is_canonical_sha256_digest(digest) => {}
        ("not-applied-nested" | "unavailable", Some(Value::Null)) => {}
        _ => {
          return Err(invalid_data(
            "candidate Seatbelt digest relation is invalid",
          ));
        }
      }
      return Ok(());
    }
    if target != "x86_64-unknown-linux-gnu" {
      return Err(invalid_data("candidate target is unsupported"));
    }
    let object = exact_object(
      value,
      &[
        "platform",
        "capabilityInheritableMask",
        "capabilityPermittedMask",
        "capabilityEffectiveMask",
        "capabilityBoundingMask",
        "capabilityAmbientMask",
        "noNewPrivs",
        "seccompMode",
        "seccompProfileDigest",
      ],
      "candidate Linux state",
    )?;
    require_text_eq(object, "platform", "linux")?;
    for field in [
      "capabilityInheritableMask",
      "capabilityPermittedMask",
      "capabilityEffectiveMask",
      "capabilityBoundingMask",
      "capabilityAmbientMask",
    ] {
      let mask = require_text(object, field)?;
      if mask.len() != 16
        || !mask.bytes().all(|byte| byte.is_ascii_hexdigit())
        || mask.bytes().any(|byte| byte.is_ascii_uppercase())
      {
        return Err(invalid_data("candidate capability mask is invalid"));
      }
    }
    require_text_eq(object, "capabilityPermittedMask", "0000000000000000")?;
    require_text_eq(object, "capabilityEffectiveMask", "0000000000000000")?;
    if object.get("noNewPrivs") != Some(&Value::Bool(true)) {
      return Err(invalid_data("candidate no-new-privileges is not set"));
    }
    require_u64_eq(object, "seccompMode", 2)?;
    require_digest(object, "seccompProfileDigest")?;
    Ok(())
  }

  fn validate_candidate_argv(
    value: Option<&Value>,
    fixture_artifact_digest: &str,
    case_id: &str,
  ) -> io::Result<()> {
    let argv = value
      .and_then(Value::as_array)
      .ok_or_else(|| invalid_data("candidate argv is not an array"))?;
    if argv
      != &[
        json!(CANDIDATE_RESERVED_FLAG),
        json!(fixture_artifact_digest),
        json!(case_id),
      ]
    {
      return Err(invalid_data("candidate argv is not exact"));
    }
    Ok(())
  }

  fn validate_opaque_identity(
    value: Option<&Value>,
    context: &'static str,
  ) -> io::Result<()> {
    let object = exact_object(
      value.ok_or_else(|| invalid_data(context))?,
      &["kind", "value"],
      context,
    )?;
    let kind = require_text(object, "kind")?;
    let identity = require_text(object, "value")?;
    match kind {
      "opaque-token" if is_canonical_identifier(identity) => Ok(()),
      "platform-object" if is_platform_identity_text(identity) => Ok(()),
      "verified-content" if is_canonical_sha256_digest(identity) => Ok(()),
      _ => Err(invalid_data(context)),
    }
  }

  fn exact_object<'a>(
    value: &'a Value,
    fields: &[&str],
    context: &'static str,
  ) -> io::Result<&'a Map<String, Value>> {
    let object = value.as_object().ok_or_else(|| invalid_data(context))?;
    if object.len() != fields.len()
      || fields.iter().any(|field| !object.contains_key(*field))
      || object.keys().any(|key| !fields.contains(&key.as_str()))
    {
      return Err(invalid_data(context));
    }
    Ok(object)
  }

  fn required_value<'a>(
    object: &'a Map<String, Value>,
    field: &str,
  ) -> io::Result<&'a Value> {
    object
      .get(field)
      .ok_or_else(|| invalid_data("required value is missing"))
  }

  fn require_text<'a>(
    object: &'a Map<String, Value>,
    field: &str,
  ) -> io::Result<&'a str> {
    object
      .get(field)
      .and_then(Value::as_str)
      .ok_or_else(|| invalid_data("required text field is invalid"))
  }

  fn require_text_eq(
    object: &Map<String, Value>,
    field: &str,
    expected: &str,
  ) -> io::Result<()> {
    if require_text(object, field)? != expected {
      return Err(invalid_data("required text field does not match"));
    }
    Ok(())
  }

  fn require_identifier(
    object: &Map<String, Value>,
    field: &str,
  ) -> io::Result<String> {
    let text = require_text(object, field)?;
    if !is_canonical_identifier(text) {
      return Err(invalid_data("required identifier is not canonical"));
    }
    Ok(text.to_string())
  }

  fn require_digest(
    object: &Map<String, Value>,
    field: &str,
  ) -> io::Result<String> {
    let digest = require_text(object, field)?;
    if !is_canonical_sha256_digest(digest) {
      return Err(invalid_data("required digest is not canonical"));
    }
    Ok(digest.to_string())
  }

  fn require_positive_decimal(
    object: &Map<String, Value>,
    field: &str,
  ) -> io::Result<String> {
    let text = require_text(object, field)?;
    if !is_canonical_positive_decimal20(text) {
      return Err(invalid_data("required positive decimal is not canonical"));
    }
    Ok(text.to_string())
  }

  fn require_u32(object: &Map<String, Value>, field: &str) -> io::Result<u32> {
    let value = object
      .get(field)
      .and_then(Value::as_u64)
      .ok_or_else(|| invalid_data("required integer field is invalid"))?;
    u32::try_from(value)
      .map_err(|_| invalid_data("required integer field exceeds u32"))
  }

  fn require_u64_eq(
    object: &Map<String, Value>,
    field: &str,
    expected: u64,
  ) -> io::Result<()> {
    if object.get(field).and_then(Value::as_u64) != Some(expected) {
      return Err(invalid_data("required integer field does not match"));
    }
    Ok(())
  }

  fn require_usize_eq(
    object: &Map<String, Value>,
    field: &str,
    expected: usize,
  ) -> io::Result<()> {
    let expected = u64::try_from(expected)
      .map_err(|_| invalid_data("frame length exceeds u64"))?;
    require_u64_eq(object, field, expected)
  }

  fn parse_decimal_field(
    object: &Map<String, Value>,
    field: &str,
    positive: bool,
  ) -> io::Result<u64> {
    let text = require_text(object, field)?;
    let canonical = if positive {
      is_canonical_positive_decimal20(text)
    } else {
      text == "0" || is_canonical_positive_decimal20(text)
    };
    if !canonical {
      return Err(invalid_data("process identity decimal is not canonical"));
    }
    text
      .parse()
      .map_err(|_| invalid_data("process identity decimal overflowed"))
  }

  fn platform_identity_text(
    object: &Map<String, Value>,
    field: &str,
  ) -> io::Result<String> {
    platform_identity_value(object.get(field))
  }

  fn platform_identity_value(value: Option<&Value>) -> io::Result<String> {
    let object = exact_object(
      value.ok_or_else(|| invalid_data("platform identity missing"))?,
      &["kind", "value"],
      "platform identity",
    )?;
    require_text_eq(object, "kind", "platform-object")?;
    let text = require_text(object, "value")?;
    if !is_platform_identity_text(text) {
      return Err(invalid_data("platform identity is not canonical"));
    }
    Ok(text.to_string())
  }

  fn is_platform_identity_text(value: &str) -> bool {
    value.strip_prefix("unix-dev-ino:").is_some_and(|payload| {
      payload.len() == 32
        && payload.bytes().all(|byte| byte.is_ascii_hexdigit())
        && payload.bytes().all(|byte| !byte.is_ascii_uppercase())
    })
  }

  fn is_canonical_fork_commit(value: &str) -> bool {
    value.len() == 40
      && value.bytes().all(|byte| byte.is_ascii_hexdigit())
      && value.bytes().all(|byte| !byte.is_ascii_uppercase())
  }

  fn canonical_json_bytes(value: &Value) -> io::Result<Vec<u8>> {
    deno_permissions::rev2::canonical_json(value)
      .map(String::into_bytes)
      .map_err(|_| invalid_data("supervisor value is not canonical JCS"))
  }

  fn hjcs_digest(domain: &str, value: &Value) -> io::Result<String> {
    deno_permissions::rev2::hjcs_digest(domain, value)
      .map_err(|_| invalid_data("supervisor HJCS digest failed"))
  }

  fn raw_frame_digest(domain: &str, raw_bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(domain.as_bytes());
    hasher.update([0]);
    hasher.update(raw_bytes);
    format!("sha256-{}", URL_SAFE_NO_PAD.encode(hasher.finalize()))
  }

  fn sha256_digest(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("sha256-{}", URL_SAFE_NO_PAD.encode(hasher.finalize()))
  }

  fn zero_sha256_digest(length: usize) -> String {
    let mut hasher = Sha256::new();
    let zeros = [0_u8; 64 * 1024];
    let mut remaining = length;
    while remaining != 0 {
      let take = remaining.min(zeros.len());
      hasher.update(&zeros[..take]);
      remaining -= take;
    }
    format!("sha256-{}", URL_SAFE_NO_PAD.encode(hasher.finalize()))
  }

  fn descriptor_status_flags(
    descriptor: BorrowedFd<'_>,
  ) -> io::Result<libc::c_int> {
    fcntl_get(descriptor, libc::F_GETFL)
  }

  fn descriptor_flags(descriptor: BorrowedFd<'_>) -> io::Result<libc::c_int> {
    fcntl_get(descriptor, libc::F_GETFD)
  }

  fn fcntl_get(
    descriptor: BorrowedFd<'_>,
    command: libc::c_int,
  ) -> io::Result<libc::c_int> {
    loop {
      // SAFETY: command is a read-only fcntl query on a live descriptor.
      let result = unsafe { libc::fcntl(descriptor.as_raw_fd(), command) };
      if result >= 0 {
        return Ok(result);
      }
      let error = io::Error::last_os_error();
      if error.kind() != io::ErrorKind::Interrupted {
        return Err(error);
      }
    }
  }

  fn mkdirat_exact(
    directory: BorrowedFd<'_>,
    name: &str,
    mode: libc::mode_t,
  ) -> io::Result<()> {
    let name = c_name(name)?;
    loop {
      // SAFETY: directory is live and name is one NUL-terminated component.
      let result =
        unsafe { libc::mkdirat(directory.as_raw_fd(), name.as_ptr(), mode) };
      if result == 0 {
        return Ok(());
      }
      let error = io::Error::last_os_error();
      if error.kind() != io::ErrorKind::Interrupted {
        return Err(error);
      }
    }
  }

  fn openat(
    directory: BorrowedFd<'_>,
    name: &str,
    flags: libc::c_int,
    mode: Option<libc::mode_t>,
  ) -> io::Result<OwnedFd> {
    let name = c_name(name)?;
    loop {
      // SAFETY: directory and name are live; successful openat returns one
      // uniquely owned descriptor. A mode is supplied exactly with O_CREAT.
      let raw = unsafe {
        match mode {
          Some(mode) => libc::openat(
            directory.as_raw_fd(),
            name.as_ptr(),
            flags,
            mode as libc::c_uint,
          ),
          None => libc::openat(directory.as_raw_fd(), name.as_ptr(), flags),
        }
      };
      if raw >= 0 {
        // SAFETY: successful openat returned a unique descriptor.
        return Ok(unsafe { OwnedFd::from_raw_fd(raw) });
      }
      let error = io::Error::last_os_error();
      if error.kind() != io::ErrorKind::Interrupted {
        return Err(error);
      }
    }
  }

  fn openat_scan_directory(
    directory: BorrowedFd<'_>,
    flags: libc::c_int,
  ) -> io::Result<OwnedFd> {
    let dot = CString::new(".").expect("literal dot has no NUL");
    loop {
      // SAFETY: directory is live, dot is the fixed self component, and a
      // successful call returns one independently owned directory description.
      let raw =
        unsafe { libc::openat(directory.as_raw_fd(), dot.as_ptr(), flags) };
      if raw >= 0 {
        // SAFETY: successful openat returned a unique descriptor.
        return Ok(unsafe { OwnedFd::from_raw_fd(raw) });
      }
      let error = io::Error::last_os_error();
      if error.kind() != io::ErrorKind::Interrupted {
        return Err(error);
      }
    }
  }

  fn fchmod_exact(
    descriptor: BorrowedFd<'_>,
    mode: libc::mode_t,
  ) -> io::Result<()> {
    loop {
      // SAFETY: fchmod changes only mode bits of the live descriptor.
      if unsafe { libc::fchmod(descriptor.as_raw_fd(), mode) } == 0 {
        return Ok(());
      }
      let error = io::Error::last_os_error();
      if error.kind() != io::ErrorKind::Interrupted {
        return Err(error);
      }
    }
  }

  fn ftruncate_exact(
    descriptor: BorrowedFd<'_>,
    length: i64,
  ) -> io::Result<()> {
    loop {
      // SAFETY: ftruncate changes the length of the live writable file.
      if unsafe { libc::ftruncate(descriptor.as_raw_fd(), length) } == 0 {
        return Ok(());
      }
      let error = io::Error::last_os_error();
      if error.kind() != io::ErrorKind::Interrupted {
        return Err(error);
      }
    }
  }

  fn require_absent_at(
    directory: BorrowedFd<'_>,
    name: &str,
  ) -> io::Result<()> {
    match openat(
      directory,
      name,
      libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC,
      None,
    ) {
      Err(error) if error.raw_os_error() == Some(libc::ENOENT) => Ok(()),
      Ok(descriptor) => {
        drop(descriptor);
        Err(invalid_data(
          "supervisor required-missing entry unexpectedly exists",
        ))
      }
      Err(_) => Err(invalid_data(
        "supervisor could not prove required-missing entry",
      )),
    }
  }

  fn unlinkat(
    directory: BorrowedFd<'_>,
    name: &str,
    flags: libc::c_int,
  ) -> io::Result<()> {
    let name = c_name(name)?;
    loop {
      // SAFETY: directory is live and name is one NUL-terminated component.
      if unsafe { libc::unlinkat(directory.as_raw_fd(), name.as_ptr(), flags) }
        == 0
      {
        return Ok(());
      }
      let error = io::Error::last_os_error();
      if error.kind() != io::ErrorKind::Interrupted {
        return Err(error);
      }
    }
  }

  fn c_name(name: &str) -> io::Result<CString> {
    if name.is_empty()
      || name == "."
      || name == ".."
      || name.as_bytes().contains(&b'/')
      || name.as_bytes().contains(&b'\\')
    {
      return Err(invalid_input(
        "supervisor private name is not one canonical component",
      ));
    }
    CString::new(name)
      .map_err(|_| invalid_input("supervisor private name contains NUL"))
  }

  fn invalid_input(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
  }

  fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
  }

  fn deadline_expired() -> io::Error {
    io::Error::new(
      io::ErrorKind::TimedOut,
      "supervisor topology deadline expired",
    )
  }

  #[cfg(test)]
  mod tests {
    use std::fs::File;
    use std::os::fd::RawFd;
    use std::path::Path;
    use std::sync::atomic::AtomicBool;
    use std::sync::atomic::Ordering;
    use std::thread;

    use super::*;
    use crate::oden_capsec_filesystem_protocol::unix_transport::framed_stream_socketpair;

    const DIGEST: &str = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const FORK_COMMIT: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const FEATURE_SET: &str = "release";
    const SUPERVISOR_PID: libc::pid_t = 101;
    const SUPERVISOR_PGID: libc::pid_t = 100;
    const PARENT_PID: libc::pid_t = 99;
    const PARENT_PGID: libc::pid_t = 99;
    const CANDIDATE_PID: &str = "102";
    const CANDIDATE_PGID: &str = "100";
    const CANDIDATE_START_IDENTITY: &str = "candidate-start:test";

    struct PeerObservation {
      candidate_request: Value,
      descriptors: Vec<OwnedFd>,
      candidate_endpoint: FramedStreamEndpoint,
      parent_control: FramedStreamEndpoint,
    }

    fn identity(case: SupervisorLstatCase) -> SupervisorGeneratedLstatIdentity {
      identity_for_target("aarch64-apple-darwin", case)
    }

    fn identity_for_target(
      target: &str,
      case: SupervisorLstatCase,
    ) -> SupervisorGeneratedLstatIdentity {
      SupervisorGeneratedLstatIdentity::new_test_fixture(
        target,
        FEATURE_SET,
        FORK_COMMIT,
        DIGEST,
        DIGEST,
        case.case_id(),
      )
      .unwrap()
    }

    fn entry() -> SupervisorEntryFacts {
      SupervisorEntryFacts::new(
        SUPERVISOR_PID,
        SUPERVISOR_PGID,
        PARENT_PID,
        PARENT_PGID,
        PINNED_CHILD_UMASK,
      )
      .unwrap()
    }

    fn workspace_fd(path: &Path) -> OwnedFd {
      let file = File::open(path).unwrap();
      file.into()
    }

    fn supervisor_request(
      identity: &SupervisorGeneratedLstatIdentity,
      workspace: BorrowedFd<'_>,
    ) -> Vec<u8> {
      let deadline_ns = MonotonicNs::now()
        .unwrap()
        .0
        .checked_add(8_000_000_000)
        .unwrap();
      canonical_json_bytes(&json!({
        "schema": SUPERVISOR_REQUEST_SCHEMA,
        "profile": CAPSEC_PROFILE,
        "runNonce": "run:test",
        "target": identity.target,
        "featureSet": identity.feature_set,
        "parentStandaloneDigest": DIGEST,
        "engineDigest": DIGEST,
        "forkCommit": identity.fork_commit,
        "fixtureArtifactDigest": identity.fixture_artifact_digest,
        "executionIdentityDigest": DIGEST,
        "sourceClosureDigest": DIGEST,
        "caseId": identity.case.case_id(),
        "edgeId": LSTAT_EDGE_ID,
        "requirementId": LSTAT_REQUIREMENT_ID,
        "caseKind": identity.case.case_kind(),
        "executionProjectionDigest": identity.execution_projection_digest,
        "timeoutBudgetMs": 10_000,
        "cleanupReserveMs": CLEANUP_RESERVE_MS,
        "deadlineMonotonicNs": deadline_ns.to_string(),
        "workspaceRootPlatformIdentity": {
          "kind": "platform-object",
          "value": platform_identity_of_fd(workspace).unwrap(),
        },
      }))
      .unwrap()
    }

    fn platform_state(target: &str) -> Value {
      if target == "aarch64-apple-darwin" {
        json!({
          "platform": "macos",
          "seatbeltDisposition": "unavailable",
          "seatbeltProfileDigest": Value::Null,
        })
      } else {
        json!({
          "platform": "linux",
          "capabilityInheritableMask": "0000000000000000",
          "capabilityPermittedMask": "0000000000000000",
          "capabilityEffectiveMask": "0000000000000000",
          "capabilityBoundingMask": "0000000000000000",
          "capabilityAmbientMask": "0000000000000000",
          "noNewPrivs": true,
          "seccompMode": 2,
          "seccompProfileDigest": DIGEST,
        })
      }
    }

    fn identities() -> Value {
      json!({
        "realUid": "501",
        "effectiveUid": "501",
        "savedUid": "501",
        "realGid": "20",
        "effectiveGid": "20",
        "savedGid": "20",
      })
    }

    fn fd_inventory(candidate_control_identity: &str) -> Value {
      let null_identity = "unix-dev-ino:00000000000000010000000000000002";
      json!([
        {
          "fd": 0,
          "role": "null-stdin",
          "closeOnExec": false,
          "objectKind": "character-device",
          "platformIdentity": {
            "kind": "platform-object",
            "value": null_identity,
          },
        },
        {
          "fd": 1,
          "role": "null-stdout",
          "closeOnExec": false,
          "objectKind": "character-device",
          "platformIdentity": {
            "kind": "platform-object",
            "value": null_identity,
          },
        },
        {
          "fd": 2,
          "role": "null-stderr",
          "closeOnExec": false,
          "objectKind": "character-device",
          "platformIdentity": {
            "kind": "platform-object",
            "value": null_identity,
          },
        },
        {
          "fd": 3,
          "role": "candidate-control",
          "closeOnExec": true,
          "objectKind": "socket",
          "platformIdentity": {
            "kind": "platform-object",
            "value": candidate_control_identity,
          },
        },
      ])
    }

    fn ready_frame(
      spawn_request: &Map<String, Value>,
      candidate_endpoint: BorrowedFd<'_>,
    ) -> Vec<u8> {
      let target = spawn_request["target"].as_str().unwrap();
      let no_descendant_profile = if target == "aarch64-apple-darwin" {
        "macos-rlimit-nproc-zero-reviewed-callgraph-v1"
      } else {
        "linux-rlimit-nproc-zero-seccomp-v1"
      };
      canonical_json_bytes(&json!({
        "schema": CANDIDATE_READY_SCHEMA,
        "profile": CAPSEC_PROFILE,
        "target": spawn_request["target"],
        "featureSet": spawn_request["featureSet"],
        "embeddedBuildMarker": "oden-engine-v2-test",
        "forkCommit": spawn_request["forkCommit"],
        "fixtureArtifactDigest": spawn_request["fixtureArtifactDigest"],
        "caseId": spawn_request["caseId"],
        "noDescendantProfile": no_descendant_profile,
        "candidatePid": CANDIDATE_PID,
        "candidatePgid": CANDIDATE_PGID,
        "candidateStartIdentity": CANDIDATE_START_IDENTITY,
        "identities": identities(),
        "processLimitReadback": {
          "soft": "0",
          "hard": "0",
        },
        "preRequestFdInventory": fd_inventory(
          &platform_identity_of_fd(candidate_endpoint).unwrap(),
        ),
        "platformState": platform_state(target),
      }))
      .unwrap()
    }

    fn spawn_result(
      spawn_request_raw: &[u8],
      supervisor_request_raw: &[u8],
      candidate_supervisor_endpoint: BorrowedFd<'_>,
      candidate_child_endpoint: BorrowedFd<'_>,
      mutate: impl FnOnce(&mut Value, &mut Value),
    ) -> Vec<u8> {
      let spawn_request_value = parse_canonical_jcs(spawn_request_raw).unwrap();
      let spawn_request = spawn_request_value.as_object().unwrap();
      let supervisor_request =
        parse_canonical_jcs(supervisor_request_raw).unwrap();
      let supervisor_request = supervisor_request.as_object().unwrap();
      let target = spawn_request["target"].as_str().unwrap();
      let ready_raw = ready_frame(spawn_request, candidate_child_endpoint);
      let ready_digest =
        raw_frame_digest(CANDIDATE_READY_DIGEST_DOMAIN, &ready_raw);
      let candidate_endpoint_identity =
        platform_identity_of_fd(candidate_supervisor_endpoint).unwrap();
      let requested_final = supervisor_request["deadlineMonotonicNs"]
        .as_str()
        .unwrap()
        .parse::<u64>()
        .unwrap();
      let effective_work = requested_final
        - u64::from(CLEANUP_RESERVE_MS) * NANOSECONDS_PER_MILLISECOND;
      let mut ready_value = parse_canonical_jcs(&ready_raw).unwrap();
      let mut result = json!({
        "schema": CANDIDATE_SPAWN_RESULT_SCHEMA,
        "profile": spawn_request["profile"],
        "runNonce": spawn_request["runNonce"],
        "target": spawn_request["target"],
        "featureSet": spawn_request["featureSet"],
        "parentStandaloneDigest": spawn_request["parentStandaloneDigest"],
        "engineDigest": spawn_request["engineDigest"],
        "forkCommit": spawn_request["forkCommit"],
        "fixtureArtifactDigest": spawn_request["fixtureArtifactDigest"],
        "executionIdentityDigest": spawn_request["executionIdentityDigest"],
        "sourceClosureDigest": spawn_request["sourceClosureDigest"],
        "caseId": spawn_request["caseId"],
        "edgeId": spawn_request["edgeId"],
        "requirementId": spawn_request["requirementId"],
        "caseKind": spawn_request["caseKind"],
        "supervisorRequestFrameByteLength": supervisor_request_raw.len(),
        "supervisorRequestFrameDigest": raw_frame_digest(
          SUPERVISOR_REQUEST_DIGEST_DOMAIN,
          supervisor_request_raw,
        ),
        "candidateSpawnRequestFrameByteLength": spawn_request_raw.len(),
        "candidateSpawnRequestFrameDigest": raw_frame_digest(
          CANDIDATE_SPAWN_REQUEST_DIGEST_DOMAIN,
          spawn_request_raw,
        ),
        "candidateReadyFrame": {
          "encoding": "base64url",
          "byteLength": ready_raw.len(),
          "bytes": URL_SAFE_NO_PAD.encode(&ready_raw),
          "digest": ready_digest,
        },
        "candidateArgv": spawn_request["candidateArgv"],
        "candidatePid": CANDIDATE_PID,
        "candidatePgid": CANDIDATE_PGID,
        "candidateStartIdentity": CANDIDATE_START_IDENTITY,
        "immutableImageIdentity": {
          "kind": "opaque-token",
          "value": "retained-image:test",
        },
        "candidateEndpointParentIdentity": {
          "kind": "platform-object",
          "value": candidate_endpoint_identity,
        },
        "candidateEndpointSupervisorIdentity": {
          "kind": "platform-object",
          "value": candidate_endpoint_identity,
        },
        "transferredDescriptorCount": 1,
        "preExec": {
          "identities": identities(),
          "processLimit": {
            "soft": "0",
            "hard": "0",
          },
          "descriptorInventory": fd_inventory(
            &platform_identity_of_fd(candidate_child_endpoint).unwrap(),
          ),
          "expectedPgid": CANDIDATE_PGID,
          "observedPgid": CANDIDATE_PGID,
          "startIdentity": CANDIDATE_START_IDENTITY,
          "platformState": platform_state(target),
        },
        "parentPreRequestPlatformObservationDigest": DIGEST,
        "effectiveWorkDeadlineMonotonicNs": effective_work.to_string(),
        "effectiveFinalDeadlineMonotonicNs": requested_final.to_string(),
        "admitted": true,
      });
      mutate(&mut result, &mut ready_value);
      if ready_value != parse_canonical_jcs(&ready_raw).unwrap() {
        let mutated_ready_raw = canonical_json_bytes(&ready_value).unwrap();
        result["candidateReadyFrame"] = json!({
          "encoding": "base64url",
          "byteLength": mutated_ready_raw.len(),
          "bytes": URL_SAFE_NO_PAD.encode(&mutated_ready_raw),
          "digest": raw_frame_digest(
            CANDIDATE_READY_DIGEST_DOMAIN,
            &mutated_ready_raw,
          ),
        });
      }
      canonical_json_bytes(&result).unwrap()
    }

    fn positive_peer(
      fd4_parent: FramedStreamEndpoint,
      supervisor_request_raw: Vec<u8>,
    ) -> thread::JoinHandle<PeerObservation> {
      thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(7);
        let spawn_request = fd4_parent
          .receive_one_canonical_jcs_frame(FrameByteLimit::CONTROL, 0, deadline)
          .unwrap();
        fd4_parent.require_eof(deadline).unwrap();
        let (candidate_child, candidate_supervisor) =
          framed_stream_socketpair().unwrap();
        let result = spawn_result(
          &spawn_request.raw_bytes,
          &supervisor_request_raw,
          candidate_supervisor.as_fd(),
          candidate_child.as_fd(),
          |_, _| {},
        );
        let candidate_supervisor =
          candidate_supervisor.into_owned_fd_for_test();
        fd4_parent
          .send_packet_transferring_descriptor(
            &result,
            candidate_supervisor,
            deadline,
          )
          .unwrap();
        let request = candidate_child
          .receive_one_canonical_jcs_frame(FrameByteLimit::CONTROL, 2, deadline)
          .unwrap();
        candidate_child.require_eof(deadline).unwrap();
        PeerObservation {
          candidate_request: request.value,
          descriptors: request.descriptors,
          candidate_endpoint: candidate_child,
          parent_control: fd4_parent,
        }
      })
    }

    fn run_positive(
      case: SupervisorLstatCase,
    ) -> (
      SupervisorAwaitingCandidateOutcome,
      tempfile::TempDir,
      PeerObservation,
    ) {
      run_positive_for_target("aarch64-apple-darwin", case)
    }

    fn run_positive_for_target(
      target: &str,
      case: SupervisorLstatCase,
    ) -> (
      SupervisorAwaitingCandidateOutcome,
      tempfile::TempDir,
      PeerObservation,
    ) {
      let temp = tempfile::tempdir().unwrap();
      let workspace = workspace_fd(temp.path());
      let identity = identity_for_target(target, case);
      let request = supervisor_request(&identity, workspace.as_fd());
      let (fd4_supervisor, fd4_parent) = framed_stream_socketpair().unwrap();
      let peer = positive_peer(fd4_parent, request.clone());
      let outcome = prepare_supervisor_lstat_topology(
        fd4_supervisor,
        workspace,
        identity,
        entry(),
        &request,
      )
      .unwrap();
      (outcome, temp, peer.join().unwrap())
    }

    fn response_value(
      outcome: &SupervisorAwaitingCandidateOutcome,
      observation: &PeerObservation,
    ) -> Value {
      let request = &observation.candidate_request;
      let ready =
        parse_canonical_jcs(&outcome._spawn_result.ready_raw_bytes).unwrap();
      let parent_identity = SupervisorDescriptorSnapshot::capture(
        observation.descriptors[0].as_fd(),
      )
      .unwrap()
      .platform_identity();
      let (final_state, result_digest) = match outcome._identity.case {
        SupervisorLstatCase::Existing => {
          let source = openat(
            observation.descriptors[0].as_fd(),
            LSTAT_SOURCE_NAME,
            libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
            None,
          )
          .unwrap();
          let final_identity =
            SupervisorDescriptorSnapshot::capture(source.as_fd())
              .unwrap()
              .platform_identity();
          (
            json!({
              "kind": "existing",
              "identity": final_identity,
            }),
            Value::String(DIGEST.to_string()),
          )
        }
        SupervisorLstatCase::FinalMissing => {
          (json!({ "kind": "missing" }), Value::Null)
        }
      };
      let normalized_observation = json!({
        "caseId": outcome._identity.case.case_id(),
        "edgeId": LSTAT_EDGE_ID,
        "requirementId": LSTAT_REQUIREMENT_ID,
        "caseKind": outcome._identity.case.case_kind(),
        "slots": [{
          "slotId": LSTAT_SLOT_ID,
          "capability": "fs:list",
          "effectOwner": LSTAT_EFFECT_OWNER,
          "occurrence": {
            "root": "$PROJECT",
            "rootBindingId": LSTAT_ROOT_BINDING_ID,
            "lexicalPath": {
              "encoding": "unicode",
              "value": LSTAT_SOURCE_NAME,
            },
            "followMode": "no-follow-final",
            "parentIdentity": parent_identity,
            "finalObjectState": final_state,
            "effectOwner": LSTAT_EFFECT_OWNER,
          },
        }],
        "decision": "allow",
        "result": {
          "class": outcome._identity.case.native_result_class(),
          "digest": result_digest,
        },
        "sideEffects": [],
        "delivery": "delivered",
        "cleanup": "complete",
      });
      let observed_result_digest = deno_permissions::rev2::hjcs_digest(
        OBSERVED_RESULT_DIGEST_DOMAIN,
        &normalized_observation,
      )
      .unwrap();
      let normalized_bytes =
        canonical_json_bytes(&normalized_observation).unwrap();
      let resource_inventory = json!({
        "provisionalResources": 0,
        "actorTokens": 0,
        "deliveryLeases": 0,
        "inheritedRootDescriptorsOpen": 0,
        "namespaceGateHeld": false,
      });
      let resource_inventory_digest = deno_permissions::rev2::hjcs_digest(
        RESOURCE_INVENTORY_DIGEST_DOMAIN,
        &resource_inventory,
      )
      .unwrap();
      json!({
        "schema": CANDIDATE_RESPONSE_SCHEMA,
        "profile": request["profile"],
        "runNonce": request["runNonce"],
        "target": request["target"],
        "featureSet": request["featureSet"],
        "parentStandaloneDigest": request["parentStandaloneDigest"],
        "engineDigest": request["engineDigest"],
        "forkCommit": request["forkCommit"],
        "fixtureArtifactDigest": request["fixtureArtifactDigest"],
        "executionIdentityDigest": request["executionIdentityDigest"],
        "sourceClosureDigest": request["sourceClosureDigest"],
        "caseId": request["caseId"],
        "edgeId": request["edgeId"],
        "requirementId": request["requirementId"],
        "caseKind": request["caseKind"],
        "candidateRequestFrameDigest":
          outcome._candidate_request_frame_digest,
        "acceptedDescriptorSlotsDigest": outcome._descriptor_slots_digest,
        "capturedUmask": PINNED_CHILD_UMASK,
        "normalizedObservedResult": normalized_observation,
        "observedResultDigest": observed_result_digest,
        "candidateArenaDigest": DIGEST,
        "engineTraceDigest": DIGEST,
        "deliveryFrame": {
          "encoding": "base64url",
          "bytes": URL_SAFE_NO_PAD.encode(&normalized_bytes),
        },
        "deliveryFrameDigest":
          raw_frame_digest(DELIVERY_FRAME_DIGEST_DOMAIN, &normalized_bytes),
        "resourceInventory": resource_inventory,
        "resourceInventoryDigest": resource_inventory_digest,
        "faultObservation": null,
        "faultObservationDigest": null,
        "noDescendantClaims": {
          "noDescendantProfile": ready["noDescendantProfile"],
          "sourceClosureDigest": request["sourceClosureDigest"],
          "candidatePid": ready["candidatePid"],
          "candidatePgid": ready["candidatePgid"],
          "candidateStartIdentity": ready["candidateStartIdentity"],
          "expectedPgid": ready["candidatePgid"],
          "pgidCheckpoints": {
            "entry": ready["candidatePgid"],
            "preOperation": ready["candidatePgid"],
            "postOperation": ready["candidatePgid"],
            "preExit": ready["candidatePgid"],
          },
          "processLimitReadback": ready["processLimitReadback"],
          "identities": ready["identities"],
          "preRequestFdInventory": ready["preRequestFdInventory"],
          "platformState": ready["platformState"],
        },
        "rootDescriptorsDroppedClaim": true,
      })
    }

    fn pwrite_all_at(
      descriptor: BorrowedFd<'_>,
      bytes: &[u8],
      offset: usize,
    ) -> io::Result<()> {
      let mut written = 0_usize;
      while written < bytes.len() {
        let absolute = offset
          .checked_add(written)
          .ok_or_else(|| invalid_data("test arena offset overflowed"))?;
        let absolute = libc::off_t::try_from(absolute)
          .map_err(|_| invalid_data("test arena offset overflowed"))?;
        // SAFETY: the unwritten suffix is readable, the descriptor is live and
        // writable, and pwrite leaves the shared file offset unchanged.
        let result = unsafe {
          libc::pwrite(
            descriptor.as_raw_fd(),
            bytes[written..].as_ptr().cast(),
            bytes.len() - written,
            absolute,
          )
        };
        if result < 0 {
          let error = io::Error::last_os_error();
          if error.kind() == io::ErrorKind::Interrupted {
            continue;
          }
          return Err(error);
        }
        if result == 0 {
          return Err(io::Error::from(io::ErrorKind::WriteZero));
        }
        written = written
          .checked_add(result as usize)
          .ok_or_else(|| invalid_data("test arena write overflowed"))?;
      }
      Ok(())
    }

    fn write_test_arena_payload(observation: &PeerObservation, payload: &[u8]) {
      assert!(!payload.is_empty());
      assert!(payload.len() <= ARENA_CAPACITY_BYTES as usize);
      pwrite_all_at(observation.descriptors[1].as_fd(), payload, 0).unwrap();
    }

    fn test_sha256_digest(bytes: &[u8]) -> String {
      let digest = Sha256::digest(bytes);
      format!("sha256-{}", URL_SAFE_NO_PAD.encode(digest))
    }

    fn test_hbytes_digest(domain: &str, bytes: &[u8]) -> String {
      let mut hasher = Sha256::new();
      hasher.update(domain.as_bytes());
      hasher.update([0]);
      hasher.update(bytes);
      format!("sha256-{}", URL_SAFE_NO_PAD.encode(hasher.finalize()))
    }

    fn test_zero_sha256_digest(length: usize) -> String {
      let mut hasher = Sha256::new();
      let zeros = [0_u8; 4096];
      let mut remaining = length;
      while remaining != 0 {
        let take = remaining.min(zeros.len());
        hasher.update(&zeros[..take]);
        remaining -= take;
      }
      format!("sha256-{}", URL_SAFE_NO_PAD.encode(hasher.finalize()))
    }

    fn candidate_arena_value(
      outcome: &SupervisorAwaitingCandidateOutcome,
      payload: &[u8],
    ) -> Value {
      let capacity = ARENA_CAPACITY_BYTES as usize;
      let mut object = Map::new();
      object.insert("schema".into(), json!(CANDIDATE_ARENA_SCHEMA));
      outcome
        ._binding
        .insert_common(&mut object, &outcome._identity);
      object.insert(
        "descriptorSlotsDigest".into(),
        json!(outcome._descriptor_slots_digest),
      );
      object.insert(
        "arenaTransferIndex".into(),
        json!(LSTAT_ARENA_TRANSFER_INDEX),
      );
      object.insert(
        "arenaPlatformIdentity".into(),
        outcome._resources.before_arena.platform_identity(),
      );
      object.insert("capacityBytes".into(), json!(capacity));
      object.insert(
        "payload".into(),
        json!({
          "offset": 0,
          "length": payload.len(),
          "byteDigest": test_sha256_digest(payload),
          "engineTraceDigest":
            test_hbytes_digest(ENGINE_TRACE_DIGEST_DOMAIN, payload),
        }),
      );
      object.insert(
        "unusedTail".into(),
        json!({
          "offset": payload.len(),
          "length": capacity - payload.len(),
          "byteDigest": test_zero_sha256_digest(capacity - payload.len()),
          "allZero": true,
        }),
      );
      Value::Object(object)
    }

    fn response_bound_to_arena(
      outcome: &SupervisorAwaitingCandidateOutcome,
      observation: &PeerObservation,
      payload: &[u8],
    ) -> (Value, Value) {
      write_test_arena_payload(observation, payload);
      let arena = candidate_arena_value(outcome, payload);
      let mut response = response_value(outcome, observation);
      response["candidateArenaDigest"] =
        json!(hjcs_digest(CANDIDATE_ARENA_DIGEST_DOMAIN, &arena).unwrap());
      response["engineTraceDigest"] =
        json!(test_hbytes_digest(ENGINE_TRACE_DIGEST_DOMAIN, payload));
      (response, arena)
    }

    fn send_response(
      endpoint: &FramedStreamEndpoint,
      response: &Value,
      descriptors: &[BorrowedFd<'_>],
    ) -> Vec<u8> {
      let raw_bytes = canonical_json_bytes(response).unwrap();
      let deadline = Instant::now() + Duration::from_secs(3);
      endpoint
        .send_packet_with_descriptors(&raw_bytes, descriptors, deadline)
        .unwrap();
      raw_bytes
    }

    fn send_response_and_eof(
      endpoint: &FramedStreamEndpoint,
      response: &Value,
    ) -> Vec<u8> {
      let raw_bytes = send_response(endpoint, response, &[]);
      endpoint
        .shutdown_write(Instant::now() + Duration::from_secs(3))
        .unwrap();
      raw_bytes
    }

    fn run_awaiting_parent_terminal_for_target(
      target: &str,
      case: SupervisorLstatCase,
    ) -> (
      SupervisorAwaitingParentTerminal,
      tempfile::TempDir,
      PeerObservation,
    ) {
      let (outcome, temp, observation) = run_positive_for_target(target, case);
      let response = response_value(&outcome, &observation);
      send_response_and_eof(&observation.candidate_endpoint, &response);
      let awaiting = outcome.capture_candidate_response().unwrap();
      (awaiting, temp, observation)
    }

    fn run_awaiting_parent_terminal(
      case: SupervisorLstatCase,
    ) -> (
      SupervisorAwaitingParentTerminal,
      tempfile::TempDir,
      PeerObservation,
    ) {
      run_awaiting_parent_terminal_for_target("aarch64-apple-darwin", case)
    }

    fn finish_parent_terminal(
      outcome: SupervisorAwaitingCandidateOutcome,
      observation: &PeerObservation,
      response: &Value,
    ) -> SupervisorAwaitingArenaReconciliation {
      send_response_and_eof(&observation.candidate_endpoint, response);
      let awaiting = outcome.capture_candidate_response().unwrap();
      let terminal = terminal_value(&awaiting);
      send_terminal_and_eof(&observation.parent_control, &terminal);
      awaiting.capture_parent_terminal().unwrap()
    }

    fn run_awaiting_arena_for_target(
      target: &str,
      case: SupervisorLstatCase,
      payload: &[u8],
    ) -> (
      SupervisorAwaitingArenaReconciliation,
      tempfile::TempDir,
      PeerObservation,
      Value,
    ) {
      let (outcome, temp, observation) = run_positive_for_target(target, case);
      let (response, arena) =
        response_bound_to_arena(&outcome, &observation, payload);
      let awaiting = finish_parent_terminal(outcome, &observation, &response);
      (awaiting, temp, observation, arena)
    }

    fn run_awaiting_arena(
      case: SupervisorLstatCase,
      payload: &[u8],
    ) -> (
      SupervisorAwaitingArenaReconciliation,
      tempfile::TempDir,
      PeerObservation,
      Value,
    ) {
      run_awaiting_arena_for_target("aarch64-apple-darwin", case, payload)
    }

    fn arena_reconciliation_error_kind(
      awaiting: SupervisorAwaitingArenaReconciliation,
    ) -> io::ErrorKind {
      match awaiting.reconcile_candidate_arena() {
        Ok(_) => panic!("inexact candidate arena was accepted"),
        Err(error) => error.kind(),
      }
    }

    fn terminal_value(awaiting: &SupervisorAwaitingParentTerminal) -> Value {
      let terminal_ns = MonotonicNs::now().unwrap().0;
      assert!(terminal_ns >= awaiting._deadline.receipt_ns);
      assert!(terminal_ns <= awaiting._deadline.effective_work_ns);
      let mut object = Map::new();
      object.insert("schema".into(), json!(CANDIDATE_TERMINAL_SCHEMA));
      awaiting
        ._binding
        .insert_common(&mut object, &awaiting._identity);
      object.insert(
        "candidateSpawnResultFrameDigest".into(),
        json!(awaiting._spawn_result.frame_digest),
      );
      object.insert(
        "candidatePid".into(),
        json!(awaiting._spawn_result.candidate_pid),
      );
      object.insert(
        "candidatePgid".into(),
        json!(awaiting._spawn_result.candidate_pgid),
      );
      object.insert(
        "candidateStartIdentity".into(),
        json!(awaiting._spawn_result.candidate_start_identity),
      );
      object.insert(
        "terminalObservationMonotonicNs".into(),
        json!(terminal_ns.to_string()),
      );
      object.insert("exitStatus".into(), json!(0));
      object.insert("reaped".into(), json!(true));
      object.insert("supervisorGroupLeaderStillOwned".into(), json!(true));
      Value::Object(object)
    }

    fn send_terminal_and_eof(
      endpoint: &FramedStreamEndpoint,
      terminal: &Value,
    ) -> Vec<u8> {
      send_response_and_eof(endpoint, terminal)
    }

    fn assert_raw_fd_closed(raw_fd: RawFd) {
      // SAFETY: F_GETFD only probes whether the captured descriptor number is
      // still installed; it cannot mutate or adopt it.
      assert_eq!(unsafe { libc::fcntl(raw_fd, libc::F_GETFD) }, -1);
      assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::EBADF),);
    }

    #[derive(Clone, Copy)]
    enum ResponseMutation {
      Schema,
      ExtraField,
      Binding,
      RequestDigest,
      DescriptorDigest,
      ObservedDigest,
      MissingResultDigest,
      ArenaDigestSyntax,
      EngineTraceDigestSyntax,
      DeliveryEncoding,
      DeliveryBytes,
      DeliveryDigest,
      Inventory,
      InventoryDigest,
      FaultObservation,
      NoDescendant,
      NoDescendantSource,
      PgidCheckpoint,
      RootDrop,
    }

    fn aliased_digest(value: &Value) -> Value {
      let mut bytes = value.as_str().unwrap().as_bytes().to_vec();
      bytes[7] = if bytes[7] == b'A' { b'B' } else { b'A' };
      Value::String(String::from_utf8(bytes).unwrap())
    }

    fn mutate_response(response: &mut Value, mutation: ResponseMutation) {
      match mutation {
        ResponseMutation::Schema => {
          response["schema"] = json!("oden/capsec-filesystem-response/2");
        }
        ResponseMutation::ExtraField => {
          response["extra"] = json!(true);
        }
        ResponseMutation::Binding => {
          response["runNonce"] = json!("run:alias");
        }
        ResponseMutation::RequestDigest => {
          response["candidateRequestFrameDigest"] =
            aliased_digest(&response["candidateRequestFrameDigest"]);
        }
        ResponseMutation::DescriptorDigest => {
          response["acceptedDescriptorSlotsDigest"] =
            aliased_digest(&response["acceptedDescriptorSlotsDigest"]);
        }
        ResponseMutation::ObservedDigest => {
          response["observedResultDigest"] =
            aliased_digest(&response["observedResultDigest"]);
        }
        ResponseMutation::MissingResultDigest => {
          response["normalizedObservedResult"]["result"]
            .as_object_mut()
            .unwrap()
            .remove("digest");
          let normalized = response["normalizedObservedResult"].clone();
          let normalized_bytes = canonical_json_bytes(&normalized).unwrap();
          response["observedResultDigest"] = json!(
            deno_permissions::rev2::hjcs_digest(
              OBSERVED_RESULT_DIGEST_DOMAIN,
              &normalized,
            )
            .unwrap()
          );
          response["deliveryFrame"]["bytes"] =
            json!(URL_SAFE_NO_PAD.encode(&normalized_bytes));
          response["deliveryFrameDigest"] = json!(raw_frame_digest(
            DELIVERY_FRAME_DIGEST_DOMAIN,
            &normalized_bytes,
          ));
        }
        ResponseMutation::ArenaDigestSyntax => {
          response["candidateArenaDigest"] = json!("sha256-not-canonical");
        }
        ResponseMutation::EngineTraceDigestSyntax => {
          response["engineTraceDigest"] = json!("sha256-not-canonical");
        }
        ResponseMutation::DeliveryEncoding => {
          response["deliveryFrame"]["encoding"] = json!("base64");
        }
        ResponseMutation::DeliveryBytes => {
          response["deliveryFrame"]["bytes"] = json!("e30");
        }
        ResponseMutation::DeliveryDigest => {
          response["deliveryFrameDigest"] =
            aliased_digest(&response["deliveryFrameDigest"]);
        }
        ResponseMutation::Inventory => {
          response["resourceInventory"]["actorTokens"] = json!(1);
        }
        ResponseMutation::InventoryDigest => {
          response["resourceInventoryDigest"] =
            aliased_digest(&response["resourceInventoryDigest"]);
        }
        ResponseMutation::FaultObservation => {
          response["faultObservation"] = json!({"kind": "alias"});
        }
        ResponseMutation::NoDescendant => {
          response["noDescendantClaims"]["candidatePid"] = json!("103");
        }
        ResponseMutation::NoDescendantSource => {
          response["noDescendantClaims"]["sourceClosureDigest"] =
            aliased_digest(
              &response["noDescendantClaims"]["sourceClosureDigest"],
            );
        }
        ResponseMutation::PgidCheckpoint => {
          response["noDescendantClaims"]["pgidCheckpoints"]["preExit"] =
            json!("101");
        }
        ResponseMutation::RootDrop => {
          response["rootDescriptorsDroppedClaim"] = json!(false);
        }
      }
    }

    fn refusal_for_response_mutation(
      mutation: ResponseMutation,
    ) -> io::ErrorKind {
      let (outcome, _temp, observation) =
        run_positive(SupervisorLstatCase::Existing);
      let mut response = response_value(&outcome, &observation);
      mutate_response(&mut response, mutation);
      send_response_and_eof(&observation.candidate_endpoint, &response);
      match outcome.capture_candidate_response() {
        Ok(_) => panic!("mutated candidate response was accepted"),
        Err(error) => error.kind(),
      }
    }

    #[derive(Clone, Copy)]
    enum TerminalMutation {
      Schema,
      ExtraField,
      Binding,
      SpawnDigest,
      CandidatePid,
      CandidatePgid,
      CandidateStartIdentity,
      MissingExitStatus,
      TimestampSyntax,
      TimestampBeforeReceipt,
      TimestampAfterWork,
      ExitStatus,
      Reaped,
      SupervisorOwned,
    }

    fn mutate_terminal(
      terminal: &mut Value,
      awaiting: &SupervisorAwaitingParentTerminal,
      mutation: TerminalMutation,
    ) {
      match mutation {
        TerminalMutation::Schema => {
          terminal["schema"] =
            json!("oden/capsec-filesystem-candidate-terminal/1");
        }
        TerminalMutation::ExtraField => {
          terminal["extra"] = json!(true);
        }
        TerminalMutation::Binding => {
          terminal["runNonce"] = json!("run:alias");
        }
        TerminalMutation::SpawnDigest => {
          terminal["candidateSpawnResultFrameDigest"] =
            aliased_digest(&terminal["candidateSpawnResultFrameDigest"]);
        }
        TerminalMutation::CandidatePid => {
          terminal["candidatePid"] = json!("103");
        }
        TerminalMutation::CandidatePgid => {
          terminal["candidatePgid"] = json!("101");
        }
        TerminalMutation::CandidateStartIdentity => {
          terminal["candidateStartIdentity"] = json!("candidate-start:alias");
        }
        TerminalMutation::MissingExitStatus => {
          terminal.as_object_mut().unwrap().remove("exitStatus");
        }
        TerminalMutation::TimestampSyntax => {
          terminal["terminalObservationMonotonicNs"] = json!("01");
        }
        TerminalMutation::TimestampBeforeReceipt => {
          terminal["terminalObservationMonotonicNs"] =
            json!(awaiting._deadline.receipt_ns.saturating_sub(1).to_string());
        }
        TerminalMutation::TimestampAfterWork => {
          terminal["terminalObservationMonotonicNs"] = json!(
            awaiting
              ._deadline
              .effective_work_ns
              .checked_add(1)
              .unwrap()
              .to_string()
          );
        }
        TerminalMutation::ExitStatus => {
          terminal["exitStatus"] = json!(1);
        }
        TerminalMutation::Reaped => {
          terminal["reaped"] = json!(false);
        }
        TerminalMutation::SupervisorOwned => {
          terminal["supervisorGroupLeaderStillOwned"] = json!(false);
        }
      }
    }

    fn refusal_for_terminal_mutation(
      mutation: TerminalMutation,
    ) -> io::ErrorKind {
      let (awaiting, _temp, observation) =
        run_awaiting_parent_terminal(SupervisorLstatCase::Existing);
      let mut terminal = terminal_value(&awaiting);
      mutate_terminal(&mut terminal, &awaiting, mutation);
      send_terminal_and_eof(&observation.parent_control, &terminal);
      match awaiting.capture_parent_terminal() {
        Ok(_) => panic!("mutated candidate terminal was accepted"),
        Err(error) => error.kind(),
      }
    }

    fn assert_ordered_lstat_rights(
      observation: &PeerObservation,
      case: SupervisorLstatCase,
    ) {
      assert_eq!(observation.descriptors.len(), 2);
      let root = SupervisorDescriptorSnapshot::capture(
        observation.descriptors[0].as_fd(),
      )
      .unwrap();
      let arena = SupervisorDescriptorSnapshot::capture(
        observation.descriptors[1].as_fd(),
      )
      .unwrap();
      assert_eq!(root.mode, libc::S_IFDIR as u32 | 0o700);
      assert_eq!(arena.mode, libc::S_IFREG as u32 | 0o600);
      assert_eq!(arena.size, ARENA_CAPACITY_BYTES);
      assert_ne!((root.device, root.inode), (arena.device, arena.inode));
      assert_eq!(
        observation.candidate_request["requiredCapturedUmask"],
        PINNED_CHILD_UMASK,
      );
      if case == SupervisorLstatCase::Existing {
        let source = openat(
          observation.descriptors[0].as_fd(),
          LSTAT_SOURCE_NAME,
          libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
          None,
        )
        .unwrap();
        assert_eq!(
          SupervisorDescriptorSnapshot::capture(source.as_fd())
            .unwrap()
            .size,
          0,
        );
      } else {
        require_absent_at(
          observation.descriptors[0].as_fd(),
          LSTAT_SOURCE_NAME,
        )
        .unwrap();
      }
    }

    fn duplicate_cloexec(descriptor: BorrowedFd<'_>) -> OwnedFd {
      let raw = loop {
        // SAFETY: F_DUPFD_CLOEXEC duplicates one live descriptor.
        let raw = unsafe {
          libc::fcntl(descriptor.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0)
        };
        if raw >= 0 {
          break raw;
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
          panic!("failed to duplicate arena descriptor: {error}");
        }
      };
      // SAFETY: successful F_DUPFD_CLOEXEC returned a new owned descriptor.
      unsafe { OwnedFd::from_raw_fd(raw) }
    }

    struct FirstPassArenaMutationClock {
      before: Instant,
      arena: OwnedFd,
      offset: usize,
      replacement: u8,
      fired: AtomicBool,
    }

    impl SupervisorClock for FirstPassArenaMutationClock {
      fn now(&self, checkpoint: SupervisorDeadlineCheckpoint) -> Instant {
        if checkpoint == SupervisorDeadlineCheckpoint::ArenaFirstPassComplete
          && !self.fired.swap(true, Ordering::SeqCst)
        {
          pwrite_all_at(self.arena.as_fd(), &[self.replacement], self.offset)
            .unwrap();
        }
        self.before
      }
    }

    #[test]
    fn supervisor_candidate_arena_reconciles_both_targets_and_cases() {
      assert_eq!(CANDIDATE_ARENA_FIELDS.len(), 21);
      assert!(super::super::SUPERVISED_CASES.is_empty());
      for target in ["aarch64-apple-darwin", "x86_64-unknown-linux-gnu"] {
        for case in [
          SupervisorLstatCase::Existing,
          SupervisorLstatCase::FinalMissing,
        ] {
          let payload = canonical_json_bytes(&json!({
            "case": case.case_kind(),
            "target": target,
          }))
          .unwrap();
          let (awaiting, _temp, _observation, expected_arena) =
            run_awaiting_arena_for_target(target, case, &payload);
          let pre_trace = awaiting.reconcile_candidate_arena().unwrap();
          assert_eq!(pre_trace._identity.target, target);
          assert_eq!(pre_trace._identity.case, case);
          assert_eq!(pre_trace._candidate_arena.value, expected_arena);
          assert_eq!(
            pre_trace._candidate_arena.digest,
            hjcs_digest(
              CANDIDATE_ARENA_DIGEST_DOMAIN,
              &pre_trace._candidate_arena.value,
            )
            .unwrap(),
          );
          assert_eq!(pre_trace._candidate_arena.payload_bytes, payload);
        }
      }
    }

    #[test]
    fn supervisor_candidate_arena_retains_exact_artifact_payload_and_pre_trace_state()
     {
      // Deliberately not a valid engine-trace object: this transition proves
      // canonical byte retention but must stop before trace semantics.
      let payload = br#"{}"#;
      let (awaiting, temp, _observation, expected_arena) =
        run_awaiting_arena(SupervisorLstatCase::Existing, payload);
      let response_arena_digest =
        awaiting._candidate_response.candidate_arena_digest.clone();
      let response_trace_digest =
        awaiting._candidate_response.engine_trace_digest.clone();
      let pre_trace = awaiting.reconcile_candidate_arena().unwrap();
      assert!(pre_trace._candidate_response_eof_observed);
      assert!(pre_trace._candidate_peer_closed);
      assert!(pre_trace._parent_terminal_eof_observed);
      assert!(pre_trace._fd4_closed);
      assert_eq!(pre_trace._candidate_arena.value, expected_arena);
      assert_eq!(pre_trace._candidate_arena.payload_bytes, payload);
      assert_eq!(pre_trace._candidate_arena.payload_value, json!({}));
      assert_eq!(
        pre_trace._candidate_arena.payload_byte_digest,
        test_sha256_digest(payload),
      );
      assert_eq!(
        pre_trace._candidate_arena.engine_trace_digest,
        response_trace_digest,
      );
      assert_eq!(
        pre_trace._candidate_arena.unused_tail_byte_digest,
        test_zero_sha256_digest(ARENA_CAPACITY_BYTES as usize - payload.len()),
      );
      assert_eq!(pre_trace._candidate_arena.digest, response_arena_digest);
      assert!(temp.path().join(ROOT_NAME).exists());
      assert!(temp.path().join(ARENA_NAME).exists());
      drop(pre_trace);
      assert!(!temp.path().join(ROOT_NAME).exists());
      assert!(!temp.path().join(ARENA_NAME).exists());
    }

    #[test]
    fn supervisor_candidate_arena_refuses_response_digest_aliases_and_inexact_layout()
     {
      for field in ["candidateArenaDigest", "engineTraceDigest"] {
        let (outcome, temp, observation) =
          run_positive(SupervisorLstatCase::Existing);
        let (mut response, _arena) =
          response_bound_to_arena(&outcome, &observation, br#"{}"#);
        response[field] = aliased_digest(&response[field]);
        let awaiting = finish_parent_terminal(outcome, &observation, &response);
        assert_eq!(
          arena_reconciliation_error_kind(awaiting),
          io::ErrorKind::InvalidData,
        );
        assert!(!temp.path().join(ROOT_NAME).exists());
        assert!(!temp.path().join(ARENA_NAME).exists());
      }

      let (outcome, temp, observation) =
        run_positive(SupervisorLstatCase::FinalMissing);
      let (response, _arena) =
        response_bound_to_arena(&outcome, &observation, br#"{}"#);
      let awaiting = finish_parent_terminal(outcome, &observation, &response);
      ftruncate_exact(observation.descriptors[1].as_fd(), 0).unwrap();
      ftruncate_exact(observation.descriptors[1].as_fd(), ARENA_CAPACITY_BYTES)
        .unwrap();
      assert_eq!(
        arena_reconciliation_error_kind(awaiting),
        io::ErrorKind::InvalidData,
      );
      assert!(!temp.path().join(ROOT_NAME).exists());
      assert!(!temp.path().join(ARENA_NAME).exists());

      let payload = br#"{}"#;
      let (awaiting, temp, observation, _arena) =
        run_awaiting_arena(SupervisorLstatCase::Existing, payload);
      pwrite_all_at(
        observation.descriptors[1].as_fd(),
        &[1],
        payload.len() + 1,
      )
      .unwrap();
      assert_eq!(
        arena_reconciliation_error_kind(awaiting),
        io::ErrorKind::InvalidData,
      );
      assert!(!temp.path().join(ROOT_NAME).exists());
      assert!(!temp.path().join(ARENA_NAME).exists());
    }

    #[test]
    fn supervisor_candidate_arena_refuses_descriptor_and_content_mutation_before_read()
     {
      let (awaiting, temp, observation, _arena) =
        run_awaiting_arena(SupervisorLstatCase::Existing, br#"{}"#);
      let flags =
        descriptor_status_flags(observation.descriptors[1].as_fd()).unwrap();
      // SAFETY: F_SETFL changes only mutable status flags on this live arena
      // open-file description, shared with the retained supervisor descriptor.
      assert_eq!(
        unsafe {
          libc::fcntl(
            observation.descriptors[1].as_raw_fd(),
            libc::F_SETFL,
            flags | libc::O_APPEND,
          )
        },
        0,
      );
      assert_eq!(
        arena_reconciliation_error_kind(awaiting),
        io::ErrorKind::InvalidData,
      );
      assert!(!temp.path().join(ROOT_NAME).exists());
      assert!(!temp.path().join(ARENA_NAME).exists());

      let (awaiting, temp, observation, _arena) =
        run_awaiting_arena(SupervisorLstatCase::Existing, br#"{}"#);
      ftruncate_exact(
        observation.descriptors[1].as_fd(),
        ARENA_CAPACITY_BYTES - 1,
      )
      .unwrap();
      assert_eq!(
        arena_reconciliation_error_kind(awaiting),
        io::ErrorKind::InvalidData,
      );
      assert!(!temp.path().join(ROOT_NAME).exists());
      assert!(!temp.path().join(ARENA_NAME).exists());

      let (awaiting, temp, observation, _arena) =
        run_awaiting_arena(SupervisorLstatCase::FinalMissing, br#"{}"#);
      pwrite_all_at(observation.descriptors[1].as_fd(), b"[", 0).unwrap();
      assert_eq!(
        arena_reconciliation_error_kind(awaiting),
        io::ErrorKind::InvalidData,
      );
      assert!(!temp.path().join(ROOT_NAME).exists());
      assert!(!temp.path().join(ARENA_NAME).exists());
    }

    #[test]
    fn supervisor_candidate_arena_refuses_mutation_between_bounded_reads() {
      let payload = br#"{"x":1}"#;
      let (mut awaiting, temp, observation, _arena) =
        run_awaiting_arena(SupervisorLstatCase::Existing, payload);
      let clock = Arc::new(FirstPassArenaMutationClock {
        before: awaiting
          ._deadline
          .work_instant
          .checked_sub(Duration::from_millis(1))
          .unwrap(),
        arena: duplicate_cloexec(observation.descriptors[1].as_fd()),
        offset: 5,
        replacement: b'2',
        fired: AtomicBool::new(false),
      });
      awaiting._deadline.replace_clock(clock.clone());
      assert_eq!(
        arena_reconciliation_error_kind(awaiting),
        io::ErrorKind::InvalidData,
      );
      assert!(clock.fired.load(Ordering::SeqCst));
      assert!(!temp.path().join(ROOT_NAME).exists());
      assert!(!temp.path().join(ARENA_NAME).exists());
    }

    #[test]
    fn supervisor_candidate_arena_deadline_and_drop_are_terminal_without_trace_or_cleanup_claim()
     {
      for checkpoint in [
        SupervisorDeadlineCheckpoint::ArenaReadAttempt,
        SupervisorDeadlineCheckpoint::ArenaReadComplete,
        SupervisorDeadlineCheckpoint::ArenaFirstPassComplete,
        SupervisorDeadlineCheckpoint::ArenaSecondPassComplete,
        SupervisorDeadlineCheckpoint::ValidationComplete,
      ] {
        let (mut awaiting, temp, _observation, _arena) =
          run_awaiting_arena(SupervisorLstatCase::FinalMissing, br#"{}"#);
        let expiry = awaiting._deadline.work_instant;
        let before = expiry.checked_sub(Duration::from_millis(1)).unwrap();
        awaiting
          ._deadline
          .replace_clock(Arc::new(CheckpointExpiredClock {
            before,
            expiry,
            checkpoint,
          }));
        assert_eq!(
          arena_reconciliation_error_kind(awaiting),
          io::ErrorKind::TimedOut,
        );
        assert!(!temp.path().join(ROOT_NAME).exists());
        assert!(!temp.path().join(ARENA_NAME).exists());
      }

      let (awaiting, temp, _observation, _arena) =
        run_awaiting_arena(SupervisorLstatCase::Existing, br#"{}"#);
      let pre_trace = awaiting.reconcile_candidate_arena().unwrap();
      assert!(super::super::SUPERVISED_CASES.is_empty());
      assert_eq!(pre_trace._candidate_arena.payload_value, json!({}));
      assert!(temp.path().join(ROOT_NAME).exists());
      assert!(temp.path().join(ARENA_NAME).exists());
      drop(pre_trace);
      assert!(!temp.path().join(ROOT_NAME).exists());
      assert!(!temp.path().join(ARENA_NAME).exists());
    }

    #[test]
    fn supervisor_candidate_terminal_accepts_both_targets_after_response_eof_and_closes_fd4()
     {
      assert_eq!(CANDIDATE_TERMINAL_FIELDS.len(), 23);
      for target in ["aarch64-apple-darwin", "x86_64-unknown-linux-gnu"] {
        for case in [
          SupervisorLstatCase::Existing,
          SupervisorLstatCase::FinalMissing,
        ] {
          let (awaiting, _temp, observation) =
            run_awaiting_parent_terminal_for_target(target, case);
          let terminal = terminal_value(&awaiting);
          let fd4_raw = awaiting._fd4.as_fd().as_raw_fd();
          send_terminal_and_eof(&observation.parent_control, &terminal);
          let reconciliation = awaiting.capture_parent_terminal().unwrap();
          assert!(reconciliation._candidate_response_eof_observed);
          assert!(reconciliation._candidate_peer_closed);
          assert!(reconciliation._parent_terminal_eof_observed);
          assert!(reconciliation._fd4_closed);
          assert_eq!(reconciliation._identity.target, target);
          assert_eq!(reconciliation._identity.case, case);
          assert_raw_fd_closed(fd4_raw);
        }
      }
    }

    #[test]
    fn supervisor_candidate_terminal_retains_exact_raw_digest_and_pre_cleanup_state()
     {
      let (awaiting, temp, observation) =
        run_awaiting_parent_terminal(SupervisorLstatCase::Existing);
      let response_raw = awaiting._candidate_response.raw_bytes.clone();
      let terminal = terminal_value(&awaiting);
      let terminal_ns = terminal["terminalObservationMonotonicNs"]
        .as_str()
        .unwrap()
        .to_string();
      let raw = send_terminal_and_eof(&observation.parent_control, &terminal);
      let reconciliation = awaiting.capture_parent_terminal().unwrap();
      assert_eq!(reconciliation._candidate_terminal.raw_bytes, raw);
      assert_eq!(reconciliation._candidate_terminal.value, terminal);
      assert_eq!(
        reconciliation._candidate_terminal.frame_digest,
        raw_frame_digest(CANDIDATE_TERMINAL_DIGEST_DOMAIN, &raw),
      );
      assert_eq!(
        reconciliation
          ._candidate_terminal
          .terminal_observation_monotonic_ns,
        terminal_ns,
      );
      assert_eq!(reconciliation._candidate_response.raw_bytes, response_raw,);
      assert!(temp.path().join(ROOT_NAME).exists());
      assert!(temp.path().join(ARENA_NAME).exists());
      drop(reconciliation);
      assert!(!temp.path().join(ROOT_NAME).exists());
      assert!(!temp.path().join(ARENA_NAME).exists());
    }

    #[test]
    fn supervisor_candidate_terminal_refuses_binding_spawn_digest_and_candidate_identity_aliases()
     {
      for mutation in [
        TerminalMutation::Schema,
        TerminalMutation::ExtraField,
        TerminalMutation::Binding,
        TerminalMutation::SpawnDigest,
        TerminalMutation::CandidatePid,
        TerminalMutation::CandidatePgid,
        TerminalMutation::CandidateStartIdentity,
        TerminalMutation::MissingExitStatus,
      ] {
        assert_eq!(
          refusal_for_terminal_mutation(mutation),
          io::ErrorKind::InvalidData,
        );
      }
    }

    #[test]
    fn supervisor_candidate_terminal_refuses_terminal_fact_and_monotonic_aliases()
     {
      for mutation in [
        TerminalMutation::TimestampSyntax,
        TerminalMutation::TimestampBeforeReceipt,
        TerminalMutation::TimestampAfterWork,
        TerminalMutation::ExitStatus,
        TerminalMutation::Reaped,
        TerminalMutation::SupervisorOwned,
      ] {
        assert_eq!(
          refusal_for_terminal_mutation(mutation),
          io::ErrorKind::InvalidData,
        );
      }

      let (awaiting, _temp, observation) =
        run_awaiting_parent_terminal(SupervisorLstatCase::FinalMissing);
      let mut terminal = terminal_value(&awaiting);
      terminal["terminalObservationMonotonicNs"] =
        json!(awaiting._deadline.effective_work_ns.to_string());
      send_terminal_and_eof(&observation.parent_control, &terminal);
      let reconciliation = awaiting.capture_parent_terminal().unwrap();
      assert_eq!(
        reconciliation
          ._candidate_terminal
          .terminal_observation_monotonic_ns,
        reconciliation._deadline.effective_work_text(),
      );
    }

    #[test]
    fn supervisor_candidate_terminal_refuses_rights_trailing_bytes_and_missing_eof()
     {
      let (awaiting, _temp, observation) =
        run_awaiting_parent_terminal(SupervisorLstatCase::Existing);
      let terminal = terminal_value(&awaiting);
      let (read_end, _write_end) = pipe_pair().unwrap();
      send_response(
        &observation.parent_control,
        &terminal,
        &[read_end.as_fd()],
      );
      observation
        .parent_control
        .shutdown_write(Instant::now() + Duration::from_secs(3))
        .unwrap();
      assert_eq!(
        match awaiting.capture_parent_terminal() {
          Ok(_) => panic!("candidate terminal with a right was accepted"),
          Err(error) => error.kind(),
        },
        io::ErrorKind::InvalidData,
      );

      let (awaiting, _temp, observation) =
        run_awaiting_parent_terminal(SupervisorLstatCase::FinalMissing);
      let terminal = terminal_value(&awaiting);
      send_response(&observation.parent_control, &terminal, &[]);
      send_response(
        &observation.parent_control,
        &json!({"trailing": true}),
        &[],
      );
      observation
        .parent_control
        .shutdown_write(Instant::now() + Duration::from_secs(3))
        .unwrap();
      assert_eq!(
        match awaiting.capture_parent_terminal() {
          Ok(_) => {
            panic!("candidate terminal with trailing frame bytes was accepted")
          }
          Err(error) => error.kind(),
        },
        io::ErrorKind::InvalidData,
      );

      let (mut awaiting, _temp, observation) =
        run_awaiting_parent_terminal(SupervisorLstatCase::Existing);
      let terminal = terminal_value(&awaiting);
      send_response(&observation.parent_control, &terminal, &[]);
      let missing_eof_deadline = Instant::now() + Duration::from_millis(50);
      awaiting._deadline.work_instant = missing_eof_deadline;
      awaiting._deadline.replace_clock(Arc::new(ExpiredClock {
        now: missing_eof_deadline
          .checked_sub(Duration::from_millis(1))
          .unwrap(),
      }));
      assert_eq!(
        match awaiting.capture_parent_terminal() {
          Ok(_) => panic!("candidate terminal without FD4 EOF was accepted"),
          Err(error) => error.kind(),
        },
        io::ErrorKind::TimedOut,
      );
    }

    #[test]
    fn supervisor_candidate_terminal_deadline_and_drop_are_terminal_without_cleanup_claim()
     {
      let (mut awaiting, temp, observation) =
        run_awaiting_parent_terminal(SupervisorLstatCase::FinalMissing);
      let terminal = terminal_value(&awaiting);
      let fd4_raw = awaiting._fd4.as_fd().as_raw_fd();
      let expiry = awaiting._deadline.work_instant;
      let before = expiry.checked_sub(Duration::from_millis(1)).unwrap();
      awaiting
        ._deadline
        .replace_clock(Arc::new(CheckpointExpiredClock {
          before,
          expiry,
          checkpoint: SupervisorDeadlineCheckpoint::ValidationComplete,
        }));
      send_terminal_and_eof(&observation.parent_control, &terminal);
      assert_eq!(
        match awaiting.capture_parent_terminal() {
          Ok(_) => panic!("post-validation deadline expiry was accepted"),
          Err(error) => error.kind(),
        },
        io::ErrorKind::TimedOut,
      );
      assert_raw_fd_closed(fd4_raw);
      assert!(!temp.path().join(ROOT_NAME).exists());
      assert!(!temp.path().join(ARENA_NAME).exists());
    }

    #[test]
    fn supervisor_candidate_response_accepts_both_exact_lstat_results_and_eof()
    {
      for target in ["aarch64-apple-darwin", "x86_64-unknown-linux-gnu"] {
        for case in [
          SupervisorLstatCase::Existing,
          SupervisorLstatCase::FinalMissing,
        ] {
          let (outcome, _temp, observation) =
            run_positive_for_target(target, case);
          let response = response_value(&outcome, &observation);
          send_response_and_eof(&observation.candidate_endpoint, &response);
          let terminal = outcome.capture_candidate_response().unwrap();
          assert!(terminal._candidate_response_eof_observed);
          assert!(terminal._candidate_peer_closed);
          assert_eq!(terminal._identity.target, target);
          assert_eq!(terminal._identity.case, case);
        }
      }
    }

    #[test]
    fn supervisor_candidate_response_retains_raw_digest_and_parent_terminal_state()
     {
      let (outcome, temp, observation) =
        run_positive(SupervisorLstatCase::Existing);
      let request_digest = outcome._candidate_request_frame_digest.clone();
      let descriptor_digest = outcome._descriptor_slots_digest.clone();
      let response = response_value(&outcome, &observation);
      let raw =
        send_response_and_eof(&observation.candidate_endpoint, &response);
      let terminal = outcome.capture_candidate_response().unwrap();
      assert_eq!(terminal._candidate_response.raw_bytes, raw);
      assert_eq!(terminal._candidate_response.value, response);
      assert_eq!(
        terminal._candidate_response.frame_digest,
        raw_frame_digest(CANDIDATE_RESPONSE_DIGEST_DOMAIN, &raw),
      );
      assert_eq!(
        terminal._candidate_response.observed_result_digest,
        response["observedResultDigest"],
      );
      assert_eq!(terminal._candidate_response.candidate_arena_digest, DIGEST);
      assert_eq!(terminal._candidate_response.engine_trace_digest, DIGEST);
      assert_eq!(terminal._candidate_request_frame_digest, request_digest);
      assert_eq!(terminal._descriptor_slots_digest, descriptor_digest);
      assert!(temp.path().join(ROOT_NAME).exists());
      assert!(temp.path().join(ARENA_NAME).exists());
      drop(terminal);
      assert!(!temp.path().join(ROOT_NAME).exists());
      assert!(!temp.path().join(ARENA_NAME).exists());
    }

    #[test]
    fn supervisor_candidate_response_refuses_schema_binding_and_digest_mutations()
     {
      for mutation in [
        ResponseMutation::Schema,
        ResponseMutation::ExtraField,
        ResponseMutation::Binding,
        ResponseMutation::RequestDigest,
        ResponseMutation::DescriptorDigest,
        ResponseMutation::ObservedDigest,
        ResponseMutation::MissingResultDigest,
        ResponseMutation::ArenaDigestSyntax,
        ResponseMutation::EngineTraceDigestSyntax,
      ] {
        assert_eq!(
          refusal_for_response_mutation(mutation),
          io::ErrorKind::InvalidData,
        );
      }
    }

    #[test]
    fn supervisor_candidate_response_refuses_delivery_inventory_and_claim_aliases()
     {
      for mutation in [
        ResponseMutation::DeliveryEncoding,
        ResponseMutation::DeliveryBytes,
        ResponseMutation::DeliveryDigest,
        ResponseMutation::Inventory,
        ResponseMutation::InventoryDigest,
        ResponseMutation::FaultObservation,
        ResponseMutation::NoDescendant,
        ResponseMutation::NoDescendantSource,
        ResponseMutation::PgidCheckpoint,
        ResponseMutation::RootDrop,
      ] {
        assert_eq!(
          refusal_for_response_mutation(mutation),
          io::ErrorKind::InvalidData,
        );
      }
    }

    #[test]
    fn supervisor_candidate_response_refuses_rights_and_bytes_after_frame() {
      let (outcome, _temp, observation) =
        run_positive(SupervisorLstatCase::Existing);
      let response = response_value(&outcome, &observation);
      let (read_end, _write_end) = pipe_pair().unwrap();
      send_response(
        &observation.candidate_endpoint,
        &response,
        &[read_end.as_fd()],
      );
      observation
        .candidate_endpoint
        .shutdown_write(Instant::now() + Duration::from_secs(3))
        .unwrap();
      assert_eq!(
        match outcome.capture_candidate_response() {
          Ok(_) => panic!("candidate response with a right was accepted"),
          Err(error) => error.kind(),
        },
        io::ErrorKind::InvalidData,
      );

      let (outcome, _temp, observation) =
        run_positive(SupervisorLstatCase::FinalMissing);
      let response = response_value(&outcome, &observation);
      send_response(&observation.candidate_endpoint, &response, &[]);
      send_response(
        &observation.candidate_endpoint,
        &json!({"trailing": true}),
        &[],
      );
      observation
        .candidate_endpoint
        .shutdown_write(Instant::now() + Duration::from_secs(3))
        .unwrap();
      assert_eq!(
        match outcome.capture_candidate_response() {
          Ok(_) => {
            panic!("candidate response with trailing frame bytes was accepted")
          }
          Err(error) => error.kind(),
        },
        io::ErrorKind::InvalidData,
      );
    }

    #[test]
    fn supervisor_candidate_response_deadline_refusal_and_drop_are_terminal() {
      let (mut outcome, temp, observation) =
        run_positive(SupervisorLstatCase::Existing);
      let response = response_value(&outcome, &observation);
      send_response_and_eof(&observation.candidate_endpoint, &response);
      let expiry = outcome._deadline.work_instant;
      outcome
        ._deadline
        .replace_clock(Arc::new(ExpiredClock { now: expiry }));
      assert_eq!(
        match outcome.capture_candidate_response() {
          Ok(_) => panic!("expired candidate response was accepted"),
          Err(error) => error.kind(),
        },
        io::ErrorKind::TimedOut,
      );
      assert!(!temp.path().join(ROOT_NAME).exists());
      assert!(!temp.path().join(ARENA_NAME).exists());

      let (outcome, temp, observation) =
        run_positive(SupervisorLstatCase::FinalMissing);
      let response = response_value(&outcome, &observation);
      send_response_and_eof(&observation.candidate_endpoint, &response);
      let terminal = outcome.capture_candidate_response().unwrap();
      assert!(temp.path().join(ROOT_NAME).exists());
      assert!(temp.path().join(ARENA_NAME).exists());
      drop(terminal);
      assert!(!temp.path().join(ROOT_NAME).exists());
      assert!(!temp.path().join(ARENA_NAME).exists());
    }

    #[test]
    fn supervisor_topology_prepares_exact_two_requests() {
      for target in ["aarch64-apple-darwin", "x86_64-unknown-linux-gnu"] {
        for case in [
          SupervisorLstatCase::Existing,
          SupervisorLstatCase::FinalMissing,
        ] {
          let (outcome, _temp, observation) =
            run_positive_for_target(target, case);
          assert_ordered_lstat_rights(&observation, case);
          assert_eq!(observation.candidate_request["target"], target);
          assert_eq!(observation.candidate_request["caseId"], case.case_id());
          drop(outcome);
        }
      }
    }

    #[test]
    fn supervisor_topology_sends_only_ordered_rights_and_half_closes() {
      let (outcome, _temp, observation) =
        run_positive(SupervisorLstatCase::Existing);
      assert_ordered_lstat_rights(&observation, SupervisorLstatCase::Existing);
      assert_eq!(
        observation.candidate_request["schema"],
        CANDIDATE_REQUEST_SCHEMA,
      );
      drop(outcome);
    }

    #[test]
    fn supervisor_topology_retains_outcome_pending_rights_and_frames() {
      let (outcome, temp, observation) =
        run_positive(SupervisorLstatCase::Existing);
      assert!(temp.path().join(ROOT_NAME).is_dir());
      assert!(temp.path().join(ARENA_NAME).is_file());
      assert!(!outcome._spawn_request_raw_bytes.is_empty());
      assert!(!outcome._spawn_result.raw_bytes.is_empty());
      assert!(!outcome._spawn_result.ready_raw_bytes.is_empty());
      assert!(is_canonical_sha256_digest(
        &outcome._spawn_result.ready_frame_digest,
      ));
      assert_eq!(outcome._spawn_result.candidate_pid, CANDIDATE_PID);
      assert_eq!(outcome._spawn_result.candidate_pgid, CANDIDATE_PGID);
      assert_eq!(
        outcome._spawn_result.candidate_start_identity,
        CANDIDATE_START_IDENTITY,
      );
      observation
        .candidate_endpoint
        .send_packet_with_descriptors(
          br#"{"schema":"not-consumed"}"#,
          &[],
          Instant::now() + Duration::from_secs(1),
        )
        .unwrap();
      drop(outcome);
      assert!(!temp.path().join(ROOT_NAME).exists());
      assert!(!temp.path().join(ARENA_NAME).exists());
    }

    #[derive(Clone, Copy)]
    enum FrameMutation {
      None,
      SpawnTarget,
      ReadyCase,
      EndpointAlias,
    }

    #[derive(Clone, Copy)]
    enum RightMode {
      One,
      Missing,
      Extra,
      Late,
      Pipe,
      SwappedEndpoint,
    }

    fn run_refusal(
      frame_mutation: FrameMutation,
      right_mode: RightMode,
    ) -> io::ErrorKind {
      let temp = tempfile::tempdir().unwrap();
      let workspace = workspace_fd(temp.path());
      let existing_identity = identity(SupervisorLstatCase::Existing);
      let request = supervisor_request(&existing_identity, workspace.as_fd());
      let (fd4_supervisor, fd4_parent) = framed_stream_socketpair().unwrap();
      let request_for_peer = request.clone();
      let peer = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(7);
        let spawn_request = fd4_parent
          .receive_one_canonical_jcs_frame(FrameByteLimit::CONTROL, 0, deadline)
          .unwrap();
        fd4_parent.require_eof(deadline).unwrap();
        let (candidate_child, candidate_supervisor) =
          framed_stream_socketpair().unwrap();
        let result = spawn_result(
          &spawn_request.raw_bytes,
          &request_for_peer,
          candidate_supervisor.as_fd(),
          candidate_child.as_fd(),
          |result, ready| match frame_mutation {
            FrameMutation::None => {}
            FrameMutation::SpawnTarget => {
              result["target"] = json!("x86_64-unknown-linux-gnu");
            }
            FrameMutation::ReadyCase => {
              ready["caseId"] =
                json!("filesystem:lstat-sync:lstat-final-missing");
            }
            FrameMutation::EndpointAlias => {
              result["candidateEndpointSupervisorIdentity"]["value"] =
                json!("unix-dev-ino:00000000000000010000000000000003");
            }
          },
        );
        match right_mode {
          RightMode::One => {
            fd4_parent
              .send_packet_transferring_descriptor(
                &result,
                candidate_supervisor.into_owned_fd_for_test(),
                deadline,
              )
              .unwrap();
          }
          RightMode::Missing => {
            fd4_parent
              .send_packet_with_descriptors(&result, &[], deadline)
              .unwrap();
          }
          RightMode::Extra => {
            fd4_parent
              .send_packet_with_descriptors(
                &result,
                &[candidate_supervisor.as_fd(), candidate_child.as_fd()],
                deadline,
              )
              .unwrap();
          }
          RightMode::Late => {
            send_late_right(
              fd4_parent.as_fd(),
              &result,
              candidate_supervisor.as_fd(),
            )
            .unwrap();
          }
          RightMode::Pipe => {
            let (read_end, _write_end) = pipe_pair().unwrap();
            fd4_parent
              .send_packet_with_descriptors(
                &result,
                &[read_end.as_fd()],
                deadline,
              )
              .unwrap();
          }
          RightMode::SwappedEndpoint => {
            fd4_parent
              .send_packet_transferring_descriptor(
                &result,
                candidate_child.into_owned_fd_for_test(),
                deadline,
              )
              .unwrap();
          }
        }
      });
      let result = prepare_supervisor_lstat_topology(
        fd4_supervisor,
        workspace,
        existing_identity,
        entry(),
        &request,
      );
      let kind = match result {
        Ok(_) => panic!("refusal scenario unexpectedly prepared a topology"),
        Err(error) => error.kind(),
      };
      peer.join().unwrap();
      kind
    }

    #[test]
    fn supervisor_topology_refuses_spawn_identity_and_ready_aliases() {
      for mutation in [
        FrameMutation::SpawnTarget,
        FrameMutation::ReadyCase,
        FrameMutation::EndpointAlias,
      ] {
        assert_eq!(
          run_refusal(mutation, RightMode::One),
          io::ErrorKind::InvalidData,
        );
      }
    }

    #[test]
    fn supervisor_topology_refuses_missing_extra_late_and_swapped_rights() {
      for mode in [
        RightMode::Missing,
        RightMode::Extra,
        RightMode::Late,
        RightMode::Pipe,
        RightMode::SwappedEndpoint,
      ] {
        assert_eq!(
          run_refusal(FrameMutation::None, mode),
          io::ErrorKind::InvalidData,
        );
      }

      let mut descriptors = [-1; 2];
      // SAFETY: descriptors has storage for both socketpair results.
      assert_eq!(
        unsafe {
          libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_STREAM,
            0,
            descriptors.as_mut_ptr(),
          )
        },
        0,
      );
      // SAFETY: successful socketpair returned two uniquely owned descriptors.
      let blocking = unsafe { OwnedFd::from_raw_fd(descriptors[0]) };
      // SAFETY: same ownership transfer for the peer.
      let peer = unsafe { OwnedFd::from_raw_fd(descriptors[1]) };
      assert_eq!(
        FramedStreamEndpoint::from_received_connected_unix_stream(blocking)
          .unwrap_err()
          .kind(),
        io::ErrorKind::InvalidData,
      );
      drop(peer);
    }

    #[test]
    fn supervisor_topology_refuses_inexact_roots_and_arena() {
      let temp = tempfile::tempdir().unwrap();
      let workspace = workspace_fd(temp.path());
      let existing_identity = identity(SupervisorLstatCase::Existing);
      let request = supervisor_request(&existing_identity, workspace.as_fd());
      let request_value = parse_canonical_jcs(&request).unwrap();
      let deadline =
        SupervisorDeadline::from_request(request_value.as_object().unwrap())
          .unwrap();
      let resources = SupervisorLstatResources::materialize(
        workspace,
        SupervisorLstatCase::Existing,
        &deadline,
      )
      .unwrap();
      let extra = openat(
        resources.root_fd(),
        "extra",
        libc::O_WRONLY
          | libc::O_CREAT
          | libc::O_EXCL
          | libc::O_NOFOLLOW
          | libc::O_CLOEXEC,
        Some(0o600),
      )
      .unwrap();
      drop(extra);
      assert_eq!(
        resources
          .revalidate(SupervisorLstatCase::Existing, &deadline)
          .unwrap_err()
          .kind(),
        io::ErrorKind::InvalidData,
      );
      unlinkat(resources.root_fd(), "extra", 0).unwrap();
      drop(resources);

      let workspace = workspace_fd(temp.path());
      let missing_identity = identity(SupervisorLstatCase::FinalMissing);
      let request = supervisor_request(&missing_identity, workspace.as_fd());
      let request_value = parse_canonical_jcs(&request).unwrap();
      let deadline =
        SupervisorDeadline::from_request(request_value.as_object().unwrap())
          .unwrap();
      let resources = SupervisorLstatResources::materialize(
        workspace,
        SupervisorLstatCase::FinalMissing,
        &deadline,
      )
      .unwrap();
      let byte = 1_u8;
      // SAFETY: byte is readable and arena is a live writable file.
      assert_eq!(
        unsafe {
          libc::pwrite(
            resources.arena_fd().as_raw_fd(),
            std::ptr::from_ref(&byte).cast(),
            1,
            0,
          )
        },
        1,
      );
      assert_eq!(
        resources
          .revalidate(SupervisorLstatCase::FinalMissing, &deadline)
          .unwrap_err()
          .kind(),
        io::ErrorKind::InvalidData,
      );
    }

    struct ExpiredClock {
      now: Instant,
    }

    impl SupervisorClock for ExpiredClock {
      fn now(&self, _checkpoint: SupervisorDeadlineCheckpoint) -> Instant {
        self.now
      }
    }

    struct CheckpointExpiredClock {
      before: Instant,
      expiry: Instant,
      checkpoint: SupervisorDeadlineCheckpoint,
    }

    impl SupervisorClock for CheckpointExpiredClock {
      fn now(&self, checkpoint: SupervisorDeadlineCheckpoint) -> Instant {
        if checkpoint == self.checkpoint {
          self.expiry
        } else {
          self.before
        }
      }
    }

    #[test]
    fn supervisor_topology_deadline_is_immutable_and_refusal_sticky() {
      let temp = tempfile::tempdir().unwrap();
      let workspace = workspace_fd(temp.path());
      let identity = identity(SupervisorLstatCase::Existing);
      let request = supervisor_request(&identity, workspace.as_fd());
      let (fd4_supervisor, _fd4_parent) = framed_stream_socketpair().unwrap();
      let mut session = SupervisorFd4Session::begin(
        fd4_supervisor,
        workspace,
        identity,
        entry(),
        &request,
      )
      .unwrap();
      let requested = session.deadline().requested_final_ns;
      let effective = session.deadline().effective_final_ns;
      assert!(effective <= requested);
      let expiry = session.deadline().work_instant;
      session
        .deadline
        .as_mut()
        .unwrap()
        .replace_clock(Arc::new(ExpiredClock { now: expiry }));
      assert_eq!(
        session.send_candidate_spawn_request().unwrap_err().kind(),
        io::ErrorKind::TimedOut,
      );
      assert_eq!(session.state, SupervisorFd4State::Refused);
      assert_eq!(
        session.send_candidate_spawn_request().unwrap_err().kind(),
        io::ErrorKind::InvalidInput,
      );
      assert_eq!(session.state, SupervisorFd4State::Refused);
    }

    #[test]
    fn supervisor_topology_drop_closes_and_removes_resources() {
      let (outcome, temp, observation) =
        run_positive(SupervisorLstatCase::FinalMissing);
      assert!(temp.path().join(ROOT_NAME).exists());
      assert!(temp.path().join(ARENA_NAME).exists());
      drop(outcome);
      assert!(!temp.path().join(ROOT_NAME).exists());
      assert!(!temp.path().join(ARENA_NAME).exists());
      observation
        .candidate_endpoint
        .require_eof(Instant::now() + Duration::from_secs(1))
        .unwrap();
    }

    fn pipe_pair() -> io::Result<(OwnedFd, OwnedFd)> {
      let mut descriptors = [-1; 2];
      // SAFETY: descriptors has storage for both pipe results.
      if unsafe { libc::pipe(descriptors.as_mut_ptr()) } != 0 {
        return Err(io::Error::last_os_error());
      }
      // SAFETY: successful pipe returned two uniquely owned descriptors.
      let read_end = unsafe { OwnedFd::from_raw_fd(descriptors[0]) };
      // SAFETY: same ownership transfer for the write end.
      let write_end = unsafe { OwnedFd::from_raw_fd(descriptors[1]) };
      Ok((read_end, write_end))
    }

    fn send_late_right(
      socket: BorrowedFd<'_>,
      packet: &[u8],
      descriptor: BorrowedFd<'_>,
    ) -> io::Result<()> {
      let mut frame = Vec::with_capacity(4 + packet.len());
      frame.extend_from_slice(&(packet.len() as u32).to_be_bytes());
      frame.extend_from_slice(packet);
      send_raw(socket, &frame[..1])?;
      send_raw_with_right(socket, &frame[1..], descriptor)
    }

    fn send_raw(socket: BorrowedFd<'_>, bytes: &[u8]) -> io::Result<()> {
      let mut offset = 0;
      while offset < bytes.len() {
        // SAFETY: remaining bytes are readable for this send call.
        let result = unsafe {
          libc::send(
            socket.as_raw_fd(),
            bytes.as_ptr().add(offset).cast(),
            bytes.len() - offset,
            0,
          )
        };
        if result > 0 {
          offset += result as usize;
          continue;
        }
        if result == 0 {
          return Err(io::Error::from(io::ErrorKind::WriteZero));
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
          return Err(error);
        }
      }
      Ok(())
    }

    fn send_raw_with_right(
      socket: BorrowedFd<'_>,
      bytes: &[u8],
      descriptor: BorrowedFd<'_>,
    ) -> io::Result<()> {
      let mut iov = libc::iovec {
        iov_base: bytes.as_ptr().cast_mut().cast(),
        iov_len: bytes.len(),
      };
      let control_len =
        unsafe { libc::CMSG_SPACE(size_of::<RawFd>() as _) } as usize;
      let mut control = vec![0_usize; control_len.div_ceil(size_of::<usize>())];
      // SAFETY: zero is a valid initial state for msghdr.
      let mut message: libc::msghdr = unsafe { std::mem::zeroed() };
      message.msg_iov = &mut iov;
      message.msg_iovlen = 1;
      message.msg_control = control.as_mut_ptr().cast();
      message.msg_controllen = control_len as _;
      // SAFETY: control has aligned CMSG_SPACE for one descriptor.
      unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&message);
        (*cmsg).cmsg_level = libc::SOL_SOCKET;
        (*cmsg).cmsg_type = libc::SCM_RIGHTS;
        (*cmsg).cmsg_len = libc::CMSG_LEN(size_of::<RawFd>() as _) as _;
        *libc::CMSG_DATA(cmsg).cast::<RawFd>() = descriptor.as_raw_fd();
      }
      loop {
        // SAFETY: message references live payload and control storage.
        let result = unsafe { libc::sendmsg(socket.as_raw_fd(), &message, 0) };
        if result == bytes.len() as isize {
          return Ok(());
        }
        if result >= 0 {
          return Err(io::Error::from(io::ErrorKind::WriteZero));
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
          return Err(error);
        }
      }
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  const DIGEST: &str = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
  const CASE_ID: &str = "filesystem:lstat-sync:existing";

  fn run(args: &[&str]) -> Option<i32> {
    maybe_run_oden_capsec_filesystem_supervisor(args.iter().map(OsString::from))
  }

  #[test]
  fn ordinary_argv_is_not_intercepted() {
    assert_eq!(run(&["deno", "run", "mod.ts"]), None);
  }

  #[test]
  fn exact_but_unregistered_supervision_refuses() {
    assert_eq!(
      run(&[
        "deno",
        "--_oden-capsec-filesystem-supervise-v2",
        DIGEST,
        CASE_ID,
      ]),
      Some(REFUSAL_EXIT_CODE),
    );
  }

  #[test]
  fn malformed_supervisor_prefix_refuses() {
    assert_eq!(
      run(&[
        "deno",
        "--_oden-capsec-filesystem-supervise-v3",
        DIGEST,
        CASE_ID,
      ]),
      Some(REFUSAL_EXIT_CODE),
    );
  }
}

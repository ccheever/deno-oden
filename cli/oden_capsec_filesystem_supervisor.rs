// Copyright 2018-2026 the Deno authors. MIT license.

use std::ffi::OsString;

use crate::oden_capsec_filesystem_protocol::REFUSAL_EXIT_CODE;
use crate::oden_capsec_filesystem_protocol::parse_reserved_request;

const RESERVED_FLAG: &str = "--_oden-capsec-filesystem-supervise-v2";
const RESERVED_PREFIX: &str = "--_oden-capsec-filesystem-supervise";

// The supervisor table stays empty until it can create roots, own the private
// peer/arena, validate the parent's exact candidate spawn result, and capture
// response+EOF without exposing those facts to the external runner.
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
  const DESCRIPTOR_SLOTS_DIGEST_DOMAIN: &str =
    "oden:capsec:filesystem-descriptor-slots:2";
  const LSTAT_EDGE_ID: &str = "native-op:ext/fs/ops.rs#op_fs_lstat_sync";
  const LSTAT_REQUIREMENT_ID: &str =
    "fixture-requirement:native-op:ext/fs/ops.rs#op_fs_lstat_sync:complete";
  const LSTAT_ROOT_BINDING_ID: &str = "root:project";
  const LSTAT_ROOT_FIXTURE_IDENTITY: &str = "fixture:project-root";
  const LSTAT_SOURCE_OBJECT_ID: &str = "source";
  const LSTAT_SOURCE_NAME: &str = "input.txt";
  const LSTAT_DESTINATION_OBJECT_ID: &str = "destination";
  const LSTAT_DESTINATION_NAME: &str = "output.txt";
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
  /// It intentionally exposes no method: the retained descriptors, immutable
  /// identity, deadlines, and raw frames can only feed a later separately
  /// reviewed response/terminal transition.
  ///
  /// @ref LLP 0019#pre-promotion-conformance-candidate-execution
  /// [constrained-by] — Topology preparation is neither execution evidence nor
  /// authority; the production case table and all response paths stay closed.
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
      if root != self.before_root || arena != self.before_arena {
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

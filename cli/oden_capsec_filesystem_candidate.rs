// Copyright 2018-2026 the Deno authors. MIT license.

use std::ffi::OsString;

use crate::oden_capsec_filesystem_protocol::REFUSAL_EXIT_CODE;
use crate::oden_capsec_filesystem_protocol::parse_reserved_request;

const RESERVED_FLAG: &str = "--_oden-capsec-filesystem-candidate-v2";
const RESERVED_PREFIX: &str = "--_oden-capsec-filesystem-candidate";

// The generator will replace this empty table with exact
// (manifest-artifact-digest, case-id) rows. Keeping it empty is deliberate:
// the argv seam can be compiled and reviewed without admitting a case before
// parent-owned process capture and the executable oracle exist.
const CANDIDATE_CASES: &[(&str, &str)] = &[];

// @ref LLP 0019#pre-promotion-conformance-candidate-execution [implements] —
// The exact reserved candidate argv is intercepted before deno::main, V8, the
// ordinary control plane, or any inherited control descriptor is touched.
pub fn maybe_run_oden_capsec_filesystem_candidate(
  args: impl IntoIterator<Item = OsString>,
) -> Option<i32> {
  let args = args.into_iter().collect::<Vec<_>>();
  let request =
    match parse_reserved_request(&args, RESERVED_FLAG, RESERVED_PREFIX)? {
      Ok(request) => request,
      Err(()) => return Some(REFUSAL_EXIT_CODE),
    };
  if !CANDIDATE_CASES.iter().any(|(digest, case_id)| {
    *digest == request.manifest_digest && *case_id == request.case_id
  }) {
    return Some(REFUSAL_EXIT_CODE);
  }

  // No row can currently reach this point. The dormant FD3 role protocol
  // below still has no production constructor, process-fact collector,
  // response-artifact assembler, or public-op executor. All three generated
  // process admission tables therefore remain empty until the complete
  // parent/supervisor/candidate capture and oracle barriers exist.
  Some(REFUSAL_EXIT_CODE)
}

#[cfg(unix)]
#[allow(
  dead_code,
  reason = "the exact candidate FD3 role stays dormant while all case tables are empty"
)]
mod fd3 {
  use std::io;
  use std::os::fd::AsFd;
  use std::os::fd::AsRawFd;
  use std::os::fd::BorrowedFd;
  use std::os::fd::OwnedFd;
  use std::sync::Arc;
  use std::time::Instant;

  use base64::Engine;
  use base64::engine::general_purpose::URL_SAFE_NO_PAD;
  use deno_core::serde_json::Map;
  use deno_core::serde_json::Value;
  use deno_runtime::deno_permissions;
  use deno_runtime::deno_permissions::rev2::FilesystemCleanup;
  use deno_runtime::deno_permissions::rev2::FilesystemDecision;
  use deno_runtime::deno_permissions::rev2::FilesystemDelivery;
  use deno_runtime::deno_permissions::rev2::FilesystemExpectedObservation;
  use deno_runtime::deno_permissions::rev2::FilesystemFinalObjectState;
  use deno_runtime::deno_permissions::rev2::FilesystemFollowMode;
  use deno_runtime::deno_permissions::rev2::FilesystemLogicalRoot;
  use deno_runtime::deno_permissions::rev2::FilesystemObjectIdentityKind;
  use deno_runtime::deno_permissions::rev2::FilesystemPlatformPathEncoding;
  use sha2::Digest;
  use sha2::Sha256;

  use crate::oden_capsec_filesystem_protocol::is_canonical_identifier;
  use crate::oden_capsec_filesystem_protocol::is_canonical_sha256_digest;
  use crate::oden_capsec_filesystem_protocol::unix_transport::FrameByteLimit;
  use crate::oden_capsec_filesystem_protocol::unix_transport::FramedStreamEndpoint;
  use crate::oden_capsec_filesystem_protocol::unix_transport::MAX_CANDIDATE_READY_PACKET_BYTES;
  use crate::oden_capsec_filesystem_protocol::unix_transport::MAX_CONTROL_PACKET_BYTES;
  use crate::oden_capsec_filesystem_protocol::unix_transport::parse_canonical_jcs;

  const CAPSEC_PROFILE: &str = "oden/capsec/2";
  const LSTAT_EDGE_ID: &str = "native-op:ext/fs/ops.rs#op_fs_lstat_sync";
  const LSTAT_REQUIREMENT_ID: &str =
    "fixture-requirement:native-op:ext/fs/ops.rs#op_fs_lstat_sync:complete";
  const LSTAT_SLOT_ID: &str =
    "native-op:ext/fs/ops.rs#op_fs_lstat_sync:effect-slot:0";
  const LSTAT_EFFECT_OWNER: &str =
    "pkg:sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
  const CANDIDATE_READY_SCHEMA: &str =
    "oden/capsec-filesystem-candidate-ready-frame/2";
  const CANDIDATE_REQUEST_SCHEMA: &str =
    "oden/capsec-filesystem-candidate-request-frame/2";
  const CANDIDATE_RESPONSE_SCHEMA: &str =
    "oden/capsec-filesystem-candidate-response-frame/2";
  const CANDIDATE_REQUEST_DIGEST_DOMAIN: &str =
    "oden:capsec:filesystem-candidate-request-frame:2";
  const OBSERVED_RESULT_DIGEST_DOMAIN: &str =
    "oden:capsec:filesystem-observed-result:2";
  const DELIVERY_FRAME_DIGEST_DOMAIN: &str =
    "oden:capsec:filesystem-delivery-frame:2";
  const RESOURCE_INVENTORY_DIGEST_DOMAIN: &str =
    "oden:capsec:filesystem-resource-inventory:2";
  const ARENA_CAPACITY_BYTES: i64 = 8 * 1024 * 1024;
  const REQUIRED_CAPTURED_UMASK: u64 = 0o077;
  const EXPECTED_DESCRIPTOR_COUNT: usize = 2;

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

  const READY_FIELDS: &[&str] = &[
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

  const REQUEST_FIELDS: &[&str] = &[
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
    "candidateSpawnResultFrameDigest",
    "descriptorSlotsDigest",
    "requiredCapturedUmask",
  ];

  const RESPONSE_FIELDS: &[&str] = &[
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

  const IDENTITIES_FIELDS: &[&str] = &[
    "realUid",
    "effectiveUid",
    "savedUid",
    "realGid",
    "effectiveGid",
    "savedGid",
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

  // @ref LLP 0019#pre-promotion-conformance-candidate-execution
  // [implements] — Only the two exact public-edge lstat case identities and
  // the two supported target names can parameterize the dormant candidate-side
  // packet state machine. A later generated-row join must supply the remaining
  // identity fields before any production caller may exist.
  #[derive(Clone, Copy, Debug, Eq, PartialEq)]
  pub(crate) enum CandidateLstatCase {
    Existing,
    FinalMissing,
  }

  impl CandidateLstatCase {
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
  }

  #[derive(Clone, Debug)]
  pub(crate) struct CandidateLstatProtocolIdentity {
    target: String,
    feature_set: String,
    embedded_build_marker: String,
    fork_commit: String,
    fixture_artifact_digest: String,
    case: CandidateLstatCase,
    execution_projection_digest: String,
  }

  impl CandidateLstatProtocolIdentity {
    pub(crate) fn new(
      target: &str,
      feature_set: &str,
      embedded_build_marker: &str,
      fork_commit: &str,
      fixture_artifact_digest: &str,
      case_id: &str,
      execution_projection_digest: &str,
    ) -> io::Result<Self> {
      let case = CandidateLstatCase::from_id(case_id)
        .ok_or_else(|| invalid_input("candidate FD3 case is not admitted"))?;
      if !matches!(target, "aarch64-apple-darwin" | "x86_64-unknown-linux-gnu")
        || !is_canonical_identifier(feature_set)
        || !is_canonical_identifier(embedded_build_marker)
        || !is_canonical_fork_commit(fork_commit)
        || !is_canonical_sha256_digest(fixture_artifact_digest)
        || !is_canonical_sha256_digest(execution_projection_digest)
      {
        return Err(invalid_input("candidate FD3 identity is not canonical"));
      }
      Ok(Self {
        target: target.to_string(),
        feature_set: feature_set.to_string(),
        embedded_build_marker: embedded_build_marker.to_string(),
        fork_commit: fork_commit.to_string(),
        fixture_artifact_digest: fixture_artifact_digest.to_string(),
        case,
        execution_projection_digest: execution_projection_digest.to_string(),
      })
    }

    fn no_descendant_profile(&self) -> &'static str {
      match self.target.as_str() {
        "aarch64-apple-darwin" => {
          "macos-rlimit-nproc-zero-reviewed-callgraph-v1"
        }
        "x86_64-unknown-linux-gnu" => "linux-rlimit-nproc-zero-seccomp-v1",
        _ => unreachable!("constructor closes the target tuple"),
      }
    }
  }

  #[derive(Clone, Copy, Debug, Eq, PartialEq)]
  enum CandidateFd3State {
    ReadyPending,
    RequestPending,
    ResponsePending,
    Complete,
    Refused,
  }

  #[derive(Clone, Copy, Debug, Eq, PartialEq)]
  enum CandidateDeadlineCheckpoint {
    TransitionStart,
    TransportComplete,
    CpuValidationStart,
    CpuValidationComplete,
    ArenaReadAttempt,
    ArenaReadComplete,
  }

  trait CandidateClock: Send + Sync {
    fn now(&self, checkpoint: CandidateDeadlineCheckpoint) -> Instant;
  }

  struct SystemCandidateClock;

  impl CandidateClock for SystemCandidateClock {
    fn now(&self, _checkpoint: CandidateDeadlineCheckpoint) -> Instant {
      Instant::now()
    }
  }

  struct CandidateSessionDeadline {
    absolute: Instant,
    clock: Arc<dyn CandidateClock>,
  }

  impl CandidateSessionDeadline {
    fn system(absolute: Instant) -> Self {
      Self {
        absolute,
        clock: Arc::new(SystemCandidateClock),
      }
    }

    #[cfg(test)]
    fn with_clock(absolute: Instant, clock: Arc<dyn CandidateClock>) -> Self {
      Self { absolute, clock }
    }

    fn effective(
      &self,
      requested: Instant,
      checkpoint: CandidateDeadlineCheckpoint,
    ) -> io::Result<Instant> {
      let effective = requested.min(self.absolute);
      self.check(effective, checkpoint)?;
      Ok(effective)
    }

    fn check(
      &self,
      effective: Instant,
      checkpoint: CandidateDeadlineCheckpoint,
    ) -> io::Result<()> {
      if self.clock.now(checkpoint) >= effective {
        return Err(deadline_expired());
      }
      Ok(())
    }
  }

  #[derive(Clone, Debug)]
  struct CandidateReadyFacts {
    candidate_pid: String,
    candidate_pgid: String,
    candidate_start_identity: String,
    no_descendant_profile: String,
    identities: Value,
    process_limit_readback: Value,
    pre_request_fd_inventory: Value,
    platform_state: Value,
  }

  #[derive(Clone, Debug)]
  struct CandidateCaseBinding {
    run_nonce: String,
    parent_standalone_digest: String,
    engine_digest: String,
    execution_identity_digest: String,
    source_closure_digest: String,
    descriptor_slots_digest: String,
    request_frame_digest: String,
  }

  #[derive(Debug)]
  struct CandidateLstatRequestMetadata {
    raw_bytes: Vec<u8>,
    request_frame_digest: String,
    descriptor_slots_digest: String,
  }

  /// A non-cloneable identity token for the session-owned transferred rights
  /// retained after one request has passed schema, identity, ordering, type,
  /// size, point-in-time zero-fill, CLOEXEC, EOF, and deadline checks. The
  /// token owns no descriptor and has no execution, oracle, response,
  /// evidence, or authority method.
  #[derive(Debug)]
  pub(crate) struct CandidateLstatRequest {
    metadata: Arc<CandidateLstatRequestMetadata>,
  }

  #[derive(Debug)]
  struct CandidateRetainedLstatRequest {
    metadata: Arc<CandidateLstatRequestMetadata>,
    project_root: OwnedFd,
    arena: OwnedFd,
  }

  impl CandidateLstatRequest {
    pub(crate) fn raw_bytes(&self) -> &[u8] {
      &self.metadata.raw_bytes
    }

    pub(crate) fn request_frame_digest(&self) -> &str {
      &self.metadata.request_frame_digest
    }

    pub(crate) fn descriptor_slots_digest(&self) -> &str {
      &self.metadata.descriptor_slots_digest
    }
  }

  /// Candidate-owned FD3 packet ordering for one exact lstat request.
  ///
  /// This is deliberately only a protocol dependency. There is no production
  /// constructor or caller, it never creates an `OpState`, and it cannot call
  /// the dormant public-op capsule. Its absolute deadline is frozen at
  /// construction; per-transition deadlines can only shorten it. Any error is
  /// sticky: the endpoint and all session-owned received rights are closed and
  /// no later transition is possible.
  ///
  /// @ref LLP 0019#parentsupervisor-transport-and-single-process-lifetime-cell
  /// [implements] — Candidate FD3 emits one ready frame, accepts one request
  /// plus exactly two rights and immediate peer write EOF, emits one response,
  /// then shuts down its own write direction.
  /// @ref LLP 0019#pre-promotion-conformance-candidate-execution
  /// [constrained-by] — Packet validity and an opaque request identity for
  /// session-retained descriptors are candidate preparation, not execution or
  /// evidence.
  pub(crate) struct CandidateFd3Session {
    endpoint: Option<FramedStreamEndpoint>,
    identity: CandidateLstatProtocolIdentity,
    deadline: CandidateSessionDeadline,
    state: CandidateFd3State,
    ready_facts: Option<CandidateReadyFacts>,
    case_binding: Option<CandidateCaseBinding>,
    retained_request: Option<CandidateRetainedLstatRequest>,
  }

  impl CandidateFd3Session {
    pub(crate) fn new(
      endpoint: FramedStreamEndpoint,
      identity: CandidateLstatProtocolIdentity,
      absolute_deadline: Instant,
    ) -> Self {
      Self::with_deadline(
        endpoint,
        identity,
        CandidateSessionDeadline::system(absolute_deadline),
      )
    }

    fn with_deadline(
      endpoint: FramedStreamEndpoint,
      identity: CandidateLstatProtocolIdentity,
      deadline: CandidateSessionDeadline,
    ) -> Self {
      Self {
        endpoint: Some(endpoint),
        identity,
        deadline,
        state: CandidateFd3State::ReadyPending,
        ready_facts: None,
        case_binding: None,
        retained_request: None,
      }
    }

    pub(crate) fn send_ready(
      &mut self,
      raw_bytes: &[u8],
      requested_deadline: Instant,
    ) -> io::Result<()> {
      let deadline = match self.deadline.effective(
        requested_deadline,
        CandidateDeadlineCheckpoint::TransitionStart,
      ) {
        Ok(deadline) => deadline,
        Err(error) => return self.refuse(error),
      };
      if self.state != CandidateFd3State::ReadyPending {
        return self.refuse(invalid_input(
          "candidate FD3 ready transition is out of order",
        ));
      }
      if raw_bytes.is_empty()
        || raw_bytes.len() > MAX_CANDIDATE_READY_PACKET_BYTES
      {
        return self.refuse(invalid_input(
          "candidate FD3 ready frame exceeds its exact bound",
        ));
      }
      if let Err(error) = self
        .deadline
        .check(deadline, CandidateDeadlineCheckpoint::CpuValidationStart)
      {
        return self.refuse(error);
      }
      let validation_result = (|| {
        let value = parse_canonical_jcs(raw_bytes)?;
        validate_ready(&value, &self.identity)
      })();
      if let Err(error) = self
        .deadline
        .check(deadline, CandidateDeadlineCheckpoint::CpuValidationComplete)
      {
        return self.refuse(error);
      };
      let ready_facts = match validation_result {
        Ok(facts) => facts,
        Err(error) => return self.refuse(error),
      };
      let send_result = self.endpoint().and_then(|endpoint| {
        endpoint.send_packet_with_descriptors_bounded(
          raw_bytes,
          &[],
          FrameByteLimit::CANDIDATE_READY,
          deadline,
        )
      });
      if let Err(error) = self
        .deadline
        .check(deadline, CandidateDeadlineCheckpoint::TransportComplete)
      {
        return self.refuse(error);
      }
      if let Err(error) = send_result {
        return self.refuse(error);
      }
      self.ready_facts = Some(ready_facts);
      self.state = CandidateFd3State::RequestPending;
      Ok(())
    }

    pub(crate) fn receive_request(
      &mut self,
      requested_deadline: Instant,
    ) -> io::Result<CandidateLstatRequest> {
      let deadline = match self.deadline.effective(
        requested_deadline,
        CandidateDeadlineCheckpoint::TransitionStart,
      ) {
        Ok(deadline) => deadline,
        Err(error) => return self.refuse(error),
      };
      if self.state != CandidateFd3State::RequestPending {
        return self.refuse(invalid_input(
          "candidate FD3 request transition is out of order",
        ));
      }
      let packet_result = self.endpoint().and_then(|endpoint| {
        endpoint.receive_one_canonical_jcs_frame(
          FrameByteLimit::CONTROL,
          EXPECTED_DESCRIPTOR_COUNT,
          deadline,
        )
      });
      if let Err(error) = self
        .deadline
        .check(deadline, CandidateDeadlineCheckpoint::TransportComplete)
      {
        return self.refuse(error);
      }
      let packet = match packet_result {
        Ok(packet) => packet,
        Err(error) => return self.refuse(error),
      };
      let eof_result = self
        .endpoint()
        .and_then(|endpoint| endpoint.require_eof(deadline));
      if let Err(error) = self
        .deadline
        .check(deadline, CandidateDeadlineCheckpoint::TransportComplete)
      {
        return self.refuse(error);
      }
      if let Err(error) = eof_result {
        return self.refuse(error);
      }
      if let Err(error) = self
        .deadline
        .check(deadline, CandidateDeadlineCheckpoint::CpuValidationStart)
      {
        return self.refuse(error);
      }
      let validation_result = (|| {
        let request_frame_digest =
          raw_frame_digest(CANDIDATE_REQUEST_DIGEST_DOMAIN, &packet.raw_bytes);
        let binding = validate_request(
          &packet.value,
          &self.identity,
          request_frame_digest.clone(),
        )?;
        Ok::<_, io::Error>((request_frame_digest, binding))
      })();
      if let Err(error) = self
        .deadline
        .check(deadline, CandidateDeadlineCheckpoint::CpuValidationComplete)
      {
        return self.refuse(error);
      }
      let (request_frame_digest, binding) = match validation_result {
        Ok(binding) => binding,
        Err(error) => return self.refuse(error),
      };
      let descriptors: [OwnedFd; EXPECTED_DESCRIPTOR_COUNT] =
        match packet.descriptors.try_into() {
          Ok(descriptors) => descriptors,
          Err(_) => {
            return self.refuse(invalid_data(
              "candidate FD3 request descriptor count changed",
            ));
          }
        };
      if let Err(error) =
        validate_request_descriptors(&descriptors, &self.deadline, deadline)
      {
        return self.refuse(error);
      }
      if let Err(error) = self
        .deadline
        .check(deadline, CandidateDeadlineCheckpoint::CpuValidationComplete)
      {
        return self.refuse(error);
      }
      let [project_root, arena] = descriptors;
      let metadata = Arc::new(CandidateLstatRequestMetadata {
        raw_bytes: packet.raw_bytes,
        request_frame_digest,
        descriptor_slots_digest: binding.descriptor_slots_digest.clone(),
      });
      let request = CandidateLstatRequest {
        metadata: Arc::clone(&metadata),
      };
      let retained_request = CandidateRetainedLstatRequest {
        metadata,
        project_root,
        arena,
      };
      self.case_binding = Some(binding);
      self.retained_request = Some(retained_request);
      self.state = CandidateFd3State::ResponsePending;
      Ok(request)
    }

    pub(crate) fn send_response(
      &mut self,
      request: CandidateLstatRequest,
      raw_bytes: &[u8],
      requested_deadline: Instant,
    ) -> io::Result<()> {
      let deadline = match self.deadline.effective(
        requested_deadline,
        CandidateDeadlineCheckpoint::TransitionStart,
      ) {
        Ok(deadline) => deadline,
        Err(error) => return self.refuse(error),
      };
      if self.state != CandidateFd3State::ResponsePending {
        return self.refuse(invalid_input(
          "candidate FD3 response transition is out of order",
        ));
      }
      if raw_bytes.is_empty() || raw_bytes.len() > MAX_CONTROL_PACKET_BYTES {
        return self.refuse(invalid_input(
          "candidate FD3 response frame exceeds its exact bound",
        ));
      }
      let case_binding = self
        .case_binding
        .as_ref()
        .expect("response state retains request binding")
        .clone();
      let retained_metadata = &self
        .retained_request
        .as_ref()
        .expect("response state retains request rights")
        .metadata;
      if request.request_frame_digest() != case_binding.request_frame_digest
        || request.descriptor_slots_digest()
          != case_binding.descriptor_slots_digest
        || !Arc::ptr_eq(&request.metadata, retained_metadata)
      {
        return self.refuse(invalid_input(
          "candidate FD3 response consumed the wrong retained request",
        ));
      }
      let ready_facts = self
        .ready_facts
        .as_ref()
        .expect("response state retains ready facts")
        .clone();
      if let Err(error) = self
        .deadline
        .check(deadline, CandidateDeadlineCheckpoint::CpuValidationStart)
      {
        return self.refuse(error);
      }
      let validation_result = (|| {
        let value = parse_canonical_jcs(raw_bytes)?;
        validate_response(&value, &self.identity, &ready_facts, &case_binding)
      })();
      if let Err(error) = self
        .deadline
        .check(deadline, CandidateDeadlineCheckpoint::CpuValidationComplete)
      {
        return self.refuse(error);
      };
      if let Err(error) = validation_result {
        return self.refuse(error);
      }
      // The terminal-zero inventory and root-drop field remain untrusted
      // candidate claims, but this state machine cannot send them while it
      // retains either transferred right.
      let retained_request = self
        .retained_request
        .take()
        .expect("validated response state retains request rights");
      drop(retained_request);
      drop(request);
      if let Err(error) = self
        .deadline
        .check(deadline, CandidateDeadlineCheckpoint::CpuValidationComplete)
      {
        return self.refuse(error);
      }
      let send_result = self.endpoint().and_then(|endpoint| {
        endpoint.send_packet_with_descriptors_bounded(
          raw_bytes,
          &[],
          FrameByteLimit::CONTROL,
          deadline,
        )
      });
      if let Err(error) = self
        .deadline
        .check(deadline, CandidateDeadlineCheckpoint::TransportComplete)
      {
        return self.refuse(error);
      }
      if let Err(error) = send_result {
        return self.refuse(error);
      }
      let shutdown_result = self
        .endpoint()
        .and_then(|endpoint| endpoint.shutdown_write(deadline));
      if let Err(error) = self
        .deadline
        .check(deadline, CandidateDeadlineCheckpoint::TransportComplete)
      {
        return self.refuse(error);
      }
      if let Err(error) = shutdown_result {
        return self.refuse(error);
      }
      self.endpoint.take();
      self.state = CandidateFd3State::Complete;
      Ok(())
    }

    fn endpoint(&self) -> io::Result<&FramedStreamEndpoint> {
      self.endpoint.as_ref().ok_or_else(|| {
        invalid_input("candidate FD3 endpoint is no longer available")
      })
    }

    fn refuse<T>(&mut self, error: io::Error) -> io::Result<T> {
      self.endpoint.take();
      self.ready_facts.take();
      self.case_binding.take();
      self.retained_request.take();
      self.state = CandidateFd3State::Refused;
      Err(error)
    }

    #[cfg(test)]
    fn state(&self) -> CandidateFd3State {
      self.state
    }

    #[cfg(test)]
    fn retained_descriptor_raw_fds(&self) -> [libc::c_int; 2] {
      let retained = self
        .retained_request
        .as_ref()
        .expect("test session retains request rights");
      [
        retained.project_root.as_raw_fd(),
        retained.arena.as_raw_fd(),
      ]
    }
  }

  fn validate_ready(
    value: &Value,
    identity: &CandidateLstatProtocolIdentity,
  ) -> io::Result<CandidateReadyFacts> {
    let object = exact_object(value, READY_FIELDS, "candidate ready")?;
    require_text_eq(object, "schema", CANDIDATE_READY_SCHEMA)?;
    require_text_eq(object, "profile", CAPSEC_PROFILE)?;
    require_text_eq(object, "target", &identity.target)?;
    require_text_eq(object, "featureSet", &identity.feature_set)?;
    require_text_eq(
      object,
      "embeddedBuildMarker",
      &identity.embedded_build_marker,
    )?;
    require_text_eq(object, "forkCommit", &identity.fork_commit)?;
    require_text_eq(
      object,
      "fixtureArtifactDigest",
      &identity.fixture_artifact_digest,
    )?;
    require_text_eq(object, "caseId", identity.case.case_id())?;
    require_text_eq(
      object,
      "noDescendantProfile",
      identity.no_descendant_profile(),
    )?;
    let candidate_pid = require_positive_decimal(object, "candidatePid")?;
    let candidate_pgid = require_positive_decimal(object, "candidatePgid")?;
    let candidate_start_identity =
      require_identifier(object, "candidateStartIdentity")?;
    validate_identities(required_value(object, "identities")?)?;
    validate_process_limit(required_value(object, "processLimitReadback")?)?;
    validate_fd_inventory(required_value(object, "preRequestFdInventory")?)?;
    validate_platform_state(
      required_value(object, "platformState")?,
      &identity.target,
    )?;
    Ok(CandidateReadyFacts {
      candidate_pid,
      candidate_pgid,
      candidate_start_identity,
      no_descendant_profile: identity.no_descendant_profile().to_string(),
      identities: required_value(object, "identities")?.clone(),
      process_limit_readback: required_value(object, "processLimitReadback")?
        .clone(),
      pre_request_fd_inventory: required_value(
        object,
        "preRequestFdInventory",
      )?
      .clone(),
      platform_state: required_value(object, "platformState")?.clone(),
    })
  }

  fn validate_request(
    value: &Value,
    identity: &CandidateLstatProtocolIdentity,
    request_frame_digest: String,
  ) -> io::Result<CandidateCaseBinding> {
    let object = exact_object(value, REQUEST_FIELDS, "candidate request")?;
    require_text_eq(object, "schema", CANDIDATE_REQUEST_SCHEMA)?;
    validate_common_static_binding(object, identity)?;
    require_text_eq(
      object,
      "executionProjectionDigest",
      &identity.execution_projection_digest,
    )?;
    require_digest(object, "candidateSpawnResultFrameDigest")?;
    require_digest(object, "descriptorSlotsDigest")?;
    if required_value(object, "requiredCapturedUmask")?.as_u64()
      != Some(REQUIRED_CAPTURED_UMASK)
    {
      return Err(invalid_data(
        "candidate request requiredCapturedUmask is not exact",
      ));
    }
    Ok(CandidateCaseBinding {
      run_nonce: require_identifier(object, "runNonce")?,
      parent_standalone_digest: require_digest(
        object,
        "parentStandaloneDigest",
      )?,
      engine_digest: require_digest(object, "engineDigest")?,
      execution_identity_digest: require_digest(
        object,
        "executionIdentityDigest",
      )?,
      source_closure_digest: require_digest(object, "sourceClosureDigest")?,
      descriptor_slots_digest: require_digest(object, "descriptorSlotsDigest")?,
      request_frame_digest,
    })
  }

  fn validate_response(
    value: &Value,
    identity: &CandidateLstatProtocolIdentity,
    ready: &CandidateReadyFacts,
    binding: &CandidateCaseBinding,
  ) -> io::Result<()> {
    let object = exact_object(value, RESPONSE_FIELDS, "candidate response")?;
    require_text_eq(object, "schema", CANDIDATE_RESPONSE_SCHEMA)?;
    validate_common_static_binding(object, identity)?;
    require_text_eq(object, "runNonce", &binding.run_nonce)?;
    require_text_eq(
      object,
      "parentStandaloneDigest",
      &binding.parent_standalone_digest,
    )?;
    require_text_eq(object, "engineDigest", &binding.engine_digest)?;
    require_text_eq(
      object,
      "executionIdentityDigest",
      &binding.execution_identity_digest,
    )?;
    require_text_eq(
      object,
      "sourceClosureDigest",
      &binding.source_closure_digest,
    )?;
    require_text_eq(
      object,
      "candidateRequestFrameDigest",
      &binding.request_frame_digest,
    )?;
    require_text_eq(
      object,
      "acceptedDescriptorSlotsDigest",
      &binding.descriptor_slots_digest,
    )?;
    if required_value(object, "capturedUmask")?.as_u64()
      != Some(REQUIRED_CAPTURED_UMASK)
    {
      return Err(invalid_data(
        "candidate response capturedUmask is not exact",
      ));
    }
    require_digest(object, "candidateArenaDigest")?;
    require_digest(object, "engineTraceDigest")?;
    validate_normalized_observation(
      required_value(object, "normalizedObservedResult")?,
      identity,
    )?;
    let observed_result_digest = deno_permissions::rev2::hjcs_digest(
      OBSERVED_RESULT_DIGEST_DOMAIN,
      required_value(object, "normalizedObservedResult")?,
    )
    .map_err(|_| invalid_data("candidate observed result is not canonical"))?;
    require_text_eq(object, "observedResultDigest", &observed_result_digest)?;
    validate_delivery(
      required_value(object, "deliveryFrame")?,
      required_value(object, "deliveryFrameDigest")?,
      required_value(object, "normalizedObservedResult")?,
    )?;
    validate_resource_inventory(required_value(object, "resourceInventory")?)?;
    let resource_inventory_digest = deno_permissions::rev2::hjcs_digest(
      RESOURCE_INVENTORY_DIGEST_DOMAIN,
      required_value(object, "resourceInventory")?,
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
      ready,
      binding,
    )?;
    if required_value(object, "rootDescriptorsDroppedClaim")?.as_bool()
      != Some(true)
    {
      return Err(invalid_data(
        "candidate response root-descriptor drop claim is not exact",
      ));
    }
    Ok(())
  }

  fn validate_common_static_binding(
    object: &Map<String, Value>,
    identity: &CandidateLstatProtocolIdentity,
  ) -> io::Result<()> {
    for field in COMMON_BINDING_FIELDS {
      required_value(object, field)?;
    }
    require_text_eq(object, "profile", CAPSEC_PROFILE)?;
    require_text_eq(object, "target", &identity.target)?;
    require_text_eq(object, "featureSet", &identity.feature_set)?;
    require_text_eq(object, "forkCommit", &identity.fork_commit)?;
    require_text_eq(
      object,
      "fixtureArtifactDigest",
      &identity.fixture_artifact_digest,
    )?;
    require_text_eq(object, "caseId", identity.case.case_id())?;
    require_text_eq(object, "edgeId", LSTAT_EDGE_ID)?;
    require_text_eq(object, "requirementId", LSTAT_REQUIREMENT_ID)?;
    require_text_eq(object, "caseKind", identity.case.case_kind())?;
    require_identifier(object, "runNonce")?;
    for field in [
      "parentStandaloneDigest",
      "engineDigest",
      "executionIdentityDigest",
      "sourceClosureDigest",
    ] {
      require_digest(object, field)?;
    }
    Ok(())
  }

  fn validate_normalized_observation(
    value: &Value,
    identity: &CandidateLstatProtocolIdentity,
  ) -> io::Result<()> {
    let observation: FilesystemExpectedObservation =
      deno_core::serde_json::from_value(value.clone()).map_err(|_| {
        invalid_data("candidate normalized observation schema is invalid")
      })?;
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
      (CandidateLstatCase::Existing, Some(digest))
        if is_canonical_sha256_digest(digest) => {}
      (CandidateLstatCase::FinalMissing, None) => {}
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
      || slot.occurrence.root_binding_id != "root:project"
      || slot.occurrence.lexical_path.encoding
        != FilesystemPlatformPathEncoding::Unicode
      || slot.occurrence.lexical_path.value != "input.txt"
      || slot.occurrence.follow_mode != FilesystemFollowMode::NoFollowFinal
      || slot.occurrence.effect_owner != LSTAT_EFFECT_OWNER
      || slot.occurrence.parent_identity.kind
        != FilesystemObjectIdentityKind::PlatformObject
      || !is_platform_identity(&slot.occurrence.parent_identity.value)
    {
      return Err(invalid_data("candidate normalized lstat slot is not exact"));
    }
    match (&identity.case, &slot.occurrence.final_object_state) {
      (
        CandidateLstatCase::Existing,
        FilesystemFinalObjectState::Existing { identity },
      ) if identity.kind == FilesystemObjectIdentityKind::PlatformObject
        && is_platform_identity(&identity.value)
        && identity.value != slot.occurrence.parent_identity.value => {}
      (
        CandidateLstatCase::FinalMissing,
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
    ready: &CandidateReadyFacts,
    binding: &CandidateCaseBinding,
  ) -> io::Result<()> {
    let object = exact_object(
      value,
      NO_DESCENDANT_CLAIM_FIELDS,
      "candidate no-descendant claims",
    )?;
    require_text_eq(
      object,
      "noDescendantProfile",
      &ready.no_descendant_profile,
    )?;
    require_text_eq(
      object,
      "sourceClosureDigest",
      &binding.source_closure_digest,
    )?;
    require_text_eq(object, "candidatePid", &ready.candidate_pid)?;
    require_text_eq(object, "candidatePgid", &ready.candidate_pgid)?;
    require_text_eq(
      object,
      "candidateStartIdentity",
      &ready.candidate_start_identity,
    )?;
    require_text_eq(object, "expectedPgid", &ready.candidate_pgid)?;
    for (field, expected) in [
      ("processLimitReadback", &ready.process_limit_readback),
      ("identities", &ready.identities),
      ("preRequestFdInventory", &ready.pre_request_fd_inventory),
      ("platformState", &ready.platform_state),
    ] {
      if required_value(object, field)? != expected {
        return Err(invalid_data(
          "candidate no-descendant claim diverges from its ready frame",
        ));
      }
    }
    let checkpoints = exact_object(
      required_value(object, "pgidCheckpoints")?,
      &["entry", "preOperation", "postOperation", "preExit"],
      "candidate PGID checkpoints",
    )?;
    for field in ["entry", "preOperation", "postOperation", "preExit"] {
      require_text_eq(checkpoints, field, &ready.candidate_pgid)?;
    }
    Ok(())
  }

  fn validate_request_descriptors(
    descriptors: &[OwnedFd; EXPECTED_DESCRIPTOR_COUNT],
    session_deadline: &CandidateSessionDeadline,
    deadline: Instant,
  ) -> io::Result<()> {
    session_deadline
      .check(deadline, CandidateDeadlineCheckpoint::CpuValidationStart)?;
    let shape_result = (|| {
      for descriptor in descriptors {
        require_cloexec(descriptor.as_fd())?;
      }
      let root = fstat(descriptors[0].as_fd())?;
      let arena = fstat(descriptors[1].as_fd())?;
      // This read-only protocol dependency does not yet write the arena. The
      // later actual writer must independently require exact O_RDWR access
      // before it can execute or assemble an arena artifact.
      if root.st_mode & libc::S_IFMT != libc::S_IFDIR
        || arena.st_mode & libc::S_IFMT != libc::S_IFREG
        || arena.st_nlink != 1
        || arena.st_size != ARENA_CAPACITY_BYTES
        || (root.st_dev == arena.st_dev && root.st_ino == arena.st_ino)
      {
        return Err(invalid_data(
          "candidate FD3 request descriptors have the wrong order or shape",
        ));
      }
      Ok(())
    })();
    session_deadline
      .check(deadline, CandidateDeadlineCheckpoint::CpuValidationComplete)?;
    shape_result?;
    require_zero_filled_arena(
      descriptors[1].as_fd(),
      session_deadline,
      deadline,
    )
  }

  fn require_zero_filled_arena(
    descriptor: BorrowedFd<'_>,
    session_deadline: &CandidateSessionDeadline,
    deadline: Instant,
  ) -> io::Result<()> {
    let mut buffer = [0_u8; 64 * 1024];
    let mut offset = 0_i64;
    while offset < ARENA_CAPACITY_BYTES {
      let remaining =
        usize::try_from(ARENA_CAPACITY_BYTES - offset).unwrap_or(usize::MAX);
      let requested = remaining.min(buffer.len());
      let read = loop {
        session_deadline
          .check(deadline, CandidateDeadlineCheckpoint::ArenaReadAttempt)?;
        // SAFETY: buffer is writable for requested bytes and descriptor is a
        // retained regular-file right. pread does not alter its shared offset.
        let result = unsafe {
          libc::pread(
            descriptor.as_raw_fd(),
            buffer.as_mut_ptr().cast(),
            requested,
            offset,
          )
        };
        session_deadline
          .check(deadline, CandidateDeadlineCheckpoint::ArenaReadComplete)?;
        if result >= 0 {
          break result as usize;
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
          return Err(error);
        }
      };
      if read == 0 {
        return Err(invalid_data(
          "candidate arena ended before its fixed capacity",
        ));
      }
      session_deadline
        .check(deadline, CandidateDeadlineCheckpoint::CpuValidationStart)?;
      let contains_nonzero = buffer[..read].iter().any(|byte| *byte != 0);
      session_deadline
        .check(deadline, CandidateDeadlineCheckpoint::CpuValidationComplete)?;
      if contains_nonzero {
        return Err(invalid_data(
          "candidate arena was not zero-filled at transfer",
        ));
      }
      offset += read as i64;
    }
    let mut tail = 0_u8;
    let tail_read = loop {
      session_deadline
        .check(deadline, CandidateDeadlineCheckpoint::ArenaReadAttempt)?;
      // SAFETY: tail is writable for one byte; the offset is the exact fixed
      // capacity. A successful read would contradict the size/EOF contract.
      let result = unsafe {
        libc::pread(
          descriptor.as_raw_fd(),
          std::ptr::from_mut(&mut tail).cast(),
          1,
          ARENA_CAPACITY_BYTES,
        )
      };
      session_deadline
        .check(deadline, CandidateDeadlineCheckpoint::ArenaReadComplete)?;
      if result >= 0 {
        break result;
      }
      let error = io::Error::last_os_error();
      if error.kind() != io::ErrorKind::Interrupted {
        return Err(error);
      }
    };
    session_deadline
      .check(deadline, CandidateDeadlineCheckpoint::CpuValidationStart)?;
    let tail_result = if tail_read == 0 {
      Ok(())
    } else if tail_read > 0 {
      Err(invalid_data(
        "candidate arena contained bytes beyond its fixed capacity",
      ))
    } else {
      Err(io::Error::last_os_error())
    };
    session_deadline
      .check(deadline, CandidateDeadlineCheckpoint::CpuValidationComplete)?;
    tail_result
  }

  fn validate_identities(value: &Value) -> io::Result<()> {
    let object =
      exact_object(value, IDENTITIES_FIELDS, "candidate identities")?;
    for field in ["realUid", "effectiveUid", "savedUid"] {
      let value = required_text(object, field)?;
      if !is_unsigned_decimal(value, false, 40) {
        return Err(invalid_data("candidate UID is not canonical"));
      }
    }
    for field in ["realGid", "effectiveGid", "savedGid"] {
      let value = required_text(object, field)?;
      if !is_unsigned_decimal(value, true, 40) {
        return Err(invalid_data("candidate GID is not canonical"));
      }
    }
    Ok(())
  }

  fn validate_process_limit(value: &Value) -> io::Result<()> {
    let object =
      exact_object(value, &["soft", "hard"], "candidate process limit")?;
    require_text_eq(object, "soft", "0")?;
    require_text_eq(object, "hard", "0")
  }

  fn validate_fd_inventory(value: &Value) -> io::Result<()> {
    let entries = value.as_array().ok_or_else(|| {
      invalid_data("candidate descriptor inventory is not an array")
    })?;
    if entries.len() != 4 {
      return Err(invalid_data(
        "candidate descriptor inventory does not have four entries",
      ));
    }
    for (index, (role, close_on_exec, object_kind)) in [
      ("null-stdin", false, "character-device"),
      ("null-stdout", false, "character-device"),
      ("null-stderr", false, "character-device"),
      ("candidate-control", true, "socket"),
    ]
    .into_iter()
    .enumerate()
    {
      let entry = exact_object(
        &entries[index],
        &[
          "fd",
          "role",
          "closeOnExec",
          "objectKind",
          "platformIdentity",
        ],
        "candidate descriptor entry",
      )?;
      if required_value(entry, "fd")?.as_u64() != Some(index as u64)
        || required_value(entry, "closeOnExec")?.as_bool()
          != Some(close_on_exec)
      {
        return Err(invalid_data(
          "candidate descriptor inventory slot is not exact",
        ));
      }
      require_text_eq(entry, "role", role)?;
      require_text_eq(entry, "objectKind", object_kind)?;
      validate_platform_identity(required_value(entry, "platformIdentity")?)?;
    }
    if entries[3]["platformIdentity"] == entries[0]["platformIdentity"] {
      return Err(invalid_data(
        "candidate control descriptor aliases a null stream",
      ));
    }
    Ok(())
  }

  fn validate_platform_state(value: &Value, target: &str) -> io::Result<()> {
    match target {
      "aarch64-apple-darwin" => {
        let object = exact_object(
          value,
          &["platform", "seatbeltDisposition", "seatbeltProfileDigest"],
          "candidate macOS platform state",
        )?;
        require_text_eq(object, "platform", "macos")?;
        let disposition = required_text(object, "seatbeltDisposition")?;
        if !matches!(
          disposition,
          "applied" | "not-applied-nested" | "unavailable"
        ) {
          return Err(invalid_data(
            "candidate Seatbelt disposition is not closed",
          ));
        }
        let digest = required_value(object, "seatbeltProfileDigest")?;
        if disposition == "applied" {
          if digest
            .as_str()
            .is_none_or(|digest| !is_canonical_sha256_digest(digest))
          {
            return Err(invalid_data(
              "candidate applied Seatbelt state lacks its digest",
            ));
          }
        } else if !digest.is_null() {
          return Err(invalid_data(
            "candidate unapplied Seatbelt state carries a digest",
          ));
        }
        Ok(())
      }
      "x86_64-unknown-linux-gnu" => {
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
          "candidate Linux platform state",
        )?;
        require_text_eq(object, "platform", "linux")?;
        for field in [
          "capabilityInheritableMask",
          "capabilityBoundingMask",
          "capabilityAmbientMask",
        ] {
          if !is_lower_hex(required_text(object, field)?, 16) {
            return Err(invalid_data(
              "candidate Linux capability mask is not canonical",
            ));
          }
        }
        require_text_eq(object, "capabilityPermittedMask", "0000000000000000")?;
        require_text_eq(object, "capabilityEffectiveMask", "0000000000000000")?;
        if required_value(object, "noNewPrivs")?.as_bool() != Some(true)
          || required_value(object, "seccompMode")?.as_u64() != Some(2)
        {
          return Err(invalid_data(
            "candidate Linux filter state is not exact",
          ));
        }
        require_digest(object, "seccompProfileDigest")?;
        Ok(())
      }
      _ => Err(invalid_data(
        "candidate platform state target is unsupported",
      )),
    }
  }

  fn validate_platform_identity(value: &Value) -> io::Result<()> {
    let object =
      exact_object(value, &["kind", "value"], "candidate platform identity")?;
    require_text_eq(object, "kind", "platform-object")?;
    if !is_platform_identity(required_text(object, "value")?) {
      return Err(invalid_data("candidate platform identity is not canonical"));
    }
    Ok(())
  }

  fn exact_object<'a>(
    value: &'a Value,
    fields: &[&str],
    label: &'static str,
  ) -> io::Result<&'a Map<String, Value>> {
    let object = value
      .as_object()
      .ok_or_else(|| invalid_data(format!("{label} is not an object")))?;
    if object.len() != fields.len()
      || fields.iter().any(|field| !object.contains_key(*field))
    {
      return Err(invalid_data(format!("{label} fields are not exact")));
    }
    Ok(object)
  }

  fn required_value<'a>(
    object: &'a Map<String, Value>,
    field: &str,
  ) -> io::Result<&'a Value> {
    object
      .get(field)
      .ok_or_else(|| invalid_data("candidate packet omitted a required field"))
  }

  fn required_text<'a>(
    object: &'a Map<String, Value>,
    field: &str,
  ) -> io::Result<&'a str> {
    required_value(object, field)?
      .as_str()
      .ok_or_else(|| invalid_data("candidate packet field is not a string"))
  }

  fn require_text_eq(
    object: &Map<String, Value>,
    field: &str,
    expected: &str,
  ) -> io::Result<()> {
    if required_text(object, field)? != expected {
      return Err(invalid_data(
        "candidate packet field does not match its exact binding",
      ));
    }
    Ok(())
  }

  fn require_identifier(
    object: &Map<String, Value>,
    field: &str,
  ) -> io::Result<String> {
    let value = required_text(object, field)?;
    if !is_canonical_identifier(value) {
      return Err(invalid_data("candidate packet identifier is not canonical"));
    }
    Ok(value.to_string())
  }

  fn require_digest(
    object: &Map<String, Value>,
    field: &str,
  ) -> io::Result<String> {
    let value = required_text(object, field)?;
    if !is_canonical_sha256_digest(value) {
      return Err(invalid_data("candidate packet digest is not canonical"));
    }
    Ok(value.to_string())
  }

  fn require_positive_decimal(
    object: &Map<String, Value>,
    field: &str,
  ) -> io::Result<String> {
    let value = required_text(object, field)?;
    if !is_unsigned_decimal(value, false, 20) {
      return Err(invalid_data(
        "candidate packet positive decimal is not canonical",
      ));
    }
    Ok(value.to_string())
  }

  fn is_unsigned_decimal(
    value: &str,
    allow_zero: bool,
    max_digits: usize,
  ) -> bool {
    !value.is_empty()
      && value.len() <= max_digits
      && value.bytes().all(|byte| byte.is_ascii_digit())
      && (value == "0" && allow_zero || value != "0" && !value.starts_with('0'))
  }

  fn is_canonical_fork_commit(value: &str) -> bool {
    is_lower_hex(value, 40)
  }

  fn is_platform_identity(value: &str) -> bool {
    value
      .strip_prefix("unix-dev-ino:")
      .is_some_and(|suffix| is_lower_hex(suffix, 32))
  }

  fn is_lower_hex(value: &str, length: usize) -> bool {
    value.len() == length
      && value
        .bytes()
        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
  }

  fn fstat(descriptor: BorrowedFd<'_>) -> io::Result<libc::stat> {
    // SAFETY: zero is a valid initial representation for stat.
    let mut stat: libc::stat = unsafe { std::mem::zeroed() };
    // SAFETY: stat is writable and descriptor is live for this call.
    if unsafe { libc::fstat(descriptor.as_raw_fd(), &mut stat) } != 0 {
      return Err(io::Error::last_os_error());
    }
    Ok(stat)
  }

  fn require_cloexec(descriptor: BorrowedFd<'_>) -> io::Result<()> {
    // SAFETY: F_GETFD only reads flags from the live descriptor.
    let flags = unsafe { libc::fcntl(descriptor.as_raw_fd(), libc::F_GETFD) };
    if flags < 0 {
      return Err(io::Error::last_os_error());
    }
    if flags & libc::FD_CLOEXEC == 0 {
      return Err(invalid_data(
        "candidate received descriptor is not close-on-exec",
      ));
    }
    Ok(())
  }

  fn raw_frame_digest(domain: &str, bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(domain.as_bytes());
    hasher.update([0]);
    hasher.update(bytes);
    format!("sha256-{}", URL_SAFE_NO_PAD.encode(hasher.finalize()))
  }

  fn invalid_input(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
  }

  fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
  }

  fn deadline_expired() -> io::Error {
    io::Error::new(
      io::ErrorKind::TimedOut,
      "candidate FD3 immutable session deadline expired",
    )
  }

  #[cfg(test)]
  mod tests {
    use std::fs::File;
    use std::fs::OpenOptions;
    use std::io::Seek;
    use std::io::SeekFrom;
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    use std::path::PathBuf;
    use std::sync::atomic::AtomicBool;
    use std::sync::atomic::AtomicUsize;
    use std::sync::atomic::Ordering;
    use std::time::Duration;

    use deno_core::serde_json::json;

    use super::*;
    use crate::oden_capsec_filesystem_protocol::unix_transport::framed_stream_socketpair;

    const DIGEST: &str = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    const FIXTURE_DIGEST: &str =
      "sha256-_z_uHneEtf-CblX6irBb_2qsDzhDhxLAaDZTCP2aWAM";
    const FORK_COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";
    const FEATURE_SET: &str = "rust:1.95.0;test:fd3";
    const BUILD_MARKER: &str = "oden-test-build-marker";
    const ROOT_IDENTITY: &str = "unix-dev-ino:00000000000000010000000000000002";
    const CONTROL_IDENTITY: &str =
      "unix-dev-ino:00000000000000030000000000000004";
    const FILE_IDENTITY: &str = "unix-dev-ino:00000000000000050000000000000006";

    struct RequestFiles {
      _temp: tempfile::TempDir,
      root: File,
      arena: File,
    }

    struct TestClock {
      before_deadline: Instant,
      after_deadline: Instant,
      expired: AtomicBool,
      expire_on_arena_attempt: AtomicUsize,
      arena_attempts: AtomicUsize,
    }

    impl TestClock {
      fn new(absolute_deadline: Instant) -> Self {
        Self {
          before_deadline: absolute_deadline
            .checked_sub(Duration::from_secs(1))
            .unwrap(),
          after_deadline: absolute_deadline + Duration::from_secs(1),
          expired: AtomicBool::new(false),
          expire_on_arena_attempt: AtomicUsize::new(usize::MAX),
          arena_attempts: AtomicUsize::new(0),
        }
      }

      fn expire_now(&self) {
        self.expired.store(true, Ordering::SeqCst);
      }

      fn expire_on_arena_attempt(&self, attempt: usize) {
        assert!(attempt > 0);
        self
          .expire_on_arena_attempt
          .store(attempt, Ordering::SeqCst);
      }

      fn arena_attempts(&self) -> usize {
        self.arena_attempts.load(Ordering::SeqCst)
      }
    }

    impl CandidateClock for TestClock {
      fn now(&self, checkpoint: CandidateDeadlineCheckpoint) -> Instant {
        if checkpoint == CandidateDeadlineCheckpoint::ArenaReadAttempt {
          let attempt = self.arena_attempts.fetch_add(1, Ordering::SeqCst) + 1;
          if attempt >= self.expire_on_arena_attempt.load(Ordering::SeqCst) {
            self.expired.store(true, Ordering::SeqCst);
          }
        }
        if self.expired.load(Ordering::SeqCst) {
          self.after_deadline
        } else {
          self.before_deadline
        }
      }
    }

    fn deadline() -> Instant {
      Instant::now() + Duration::from_secs(2)
    }

    fn assert_descriptors_open(descriptors: [libc::c_int; 2]) {
      for descriptor in descriptors {
        // SAFETY: F_GETFD only probes the supplied integer descriptor.
        let result = unsafe { libc::fcntl(descriptor, libc::F_GETFD) };
        assert!(result >= 0, "descriptor {descriptor} unexpectedly closed");
      }
    }

    fn assert_descriptors_closed(descriptors: [libc::c_int; 2]) {
      for descriptor in descriptors {
        // SAFETY: F_GETFD safely reports EBADF for a closed integer
        // descriptor; it does not dereference caller memory.
        let result = unsafe { libc::fcntl(descriptor, libc::F_GETFD) };
        let error = io::Error::last_os_error();
        assert_eq!(result, -1, "descriptor {descriptor} remained open");
        assert_eq!(error.raw_os_error(), Some(libc::EBADF));
      }
    }

    fn identity_for(
      target: &str,
      case: CandidateLstatCase,
    ) -> CandidateLstatProtocolIdentity {
      CandidateLstatProtocolIdentity::new(
        target,
        FEATURE_SET,
        BUILD_MARKER,
        FORK_COMMIT,
        FIXTURE_DIGEST,
        case.case_id(),
        DIGEST,
      )
      .unwrap()
    }

    fn identity(case: CandidateLstatCase) -> CandidateLstatProtocolIdentity {
      identity_for("aarch64-apple-darwin", case)
    }

    fn canonical_bytes(value: &Value) -> Vec<u8> {
      deno_permissions::rev2::canonical_json(value)
        .unwrap()
        .into_bytes()
    }

    fn platform_identity(value: &str) -> Value {
      json!({
        "kind": "platform-object",
        "value": value,
      })
    }

    fn ready(identity: &CandidateLstatProtocolIdentity) -> Value {
      let platform_state = match identity.target.as_str() {
        "aarch64-apple-darwin" => json!({
          "platform": "macos",
          "seatbeltDisposition": "unavailable",
          "seatbeltProfileDigest": null,
        }),
        "x86_64-unknown-linux-gnu" => json!({
          "platform": "linux",
          "capabilityInheritableMask": "0000000000000000",
          "capabilityPermittedMask": "0000000000000000",
          "capabilityEffectiveMask": "0000000000000000",
          "capabilityBoundingMask": "0000000000000000",
          "capabilityAmbientMask": "0000000000000000",
          "noNewPrivs": true,
          "seccompMode": 2,
          "seccompProfileDigest": DIGEST,
        }),
        _ => unreachable!("test identity constructor closes the target"),
      };
      json!({
        "schema": CANDIDATE_READY_SCHEMA,
        "profile": CAPSEC_PROFILE,
        "target": identity.target,
        "featureSet": identity.feature_set,
        "embeddedBuildMarker": identity.embedded_build_marker,
        "forkCommit": identity.fork_commit,
        "fixtureArtifactDigest": identity.fixture_artifact_digest,
        "caseId": identity.case.case_id(),
        "noDescendantProfile": identity.no_descendant_profile(),
        "candidatePid": "77",
        "candidatePgid": "88",
        "candidateStartIdentity": "start:test",
        "identities": {
          "realUid": "501",
          "effectiveUid": "501",
          "savedUid": "501",
          "realGid": "20",
          "effectiveGid": "20",
          "savedGid": "20",
        },
        "processLimitReadback": {
          "soft": "0",
          "hard": "0",
        },
        "preRequestFdInventory": [
          {
            "fd": 0,
            "role": "null-stdin",
            "closeOnExec": false,
            "objectKind": "character-device",
            "platformIdentity": platform_identity(ROOT_IDENTITY),
          },
          {
            "fd": 1,
            "role": "null-stdout",
            "closeOnExec": false,
            "objectKind": "character-device",
            "platformIdentity": platform_identity(ROOT_IDENTITY),
          },
          {
            "fd": 2,
            "role": "null-stderr",
            "closeOnExec": false,
            "objectKind": "character-device",
            "platformIdentity": platform_identity(ROOT_IDENTITY),
          },
          {
            "fd": 3,
            "role": "candidate-control",
            "closeOnExec": true,
            "objectKind": "socket",
            "platformIdentity": platform_identity(CONTROL_IDENTITY),
          },
        ],
        "platformState": platform_state,
      })
    }

    fn request(identity: &CandidateLstatProtocolIdentity) -> Value {
      json!({
        "schema": CANDIDATE_REQUEST_SCHEMA,
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
        "candidateSpawnResultFrameDigest": DIGEST,
        "descriptorSlotsDigest": DIGEST,
        "requiredCapturedUmask": 63,
      })
    }

    fn response(
      identity: &CandidateLstatProtocolIdentity,
      ready: &Value,
      request: &Value,
      request_bytes: &[u8],
    ) -> Value {
      let final_state = match identity.case {
        CandidateLstatCase::Existing => json!({
          "kind": "existing",
          "identity": platform_identity(FILE_IDENTITY),
        }),
        CandidateLstatCase::FinalMissing => json!({ "kind": "missing" }),
      };
      let result_digest = match identity.case {
        CandidateLstatCase::Existing => Value::String(DIGEST.to_string()),
        CandidateLstatCase::FinalMissing => Value::Null,
      };
      let observation = json!({
        "caseId": identity.case.case_id(),
        "edgeId": LSTAT_EDGE_ID,
        "requirementId": LSTAT_REQUIREMENT_ID,
        "caseKind": identity.case.case_kind(),
        "slots": [{
          "slotId": LSTAT_SLOT_ID,
          "capability": "fs:list",
          "effectOwner": LSTAT_EFFECT_OWNER,
          "occurrence": {
            "root": "$PROJECT",
            "rootBindingId": "root:project",
            "lexicalPath": {
              "encoding": "unicode",
              "value": "input.txt",
            },
            "followMode": "no-follow-final",
            "parentIdentity": platform_identity(ROOT_IDENTITY),
            "finalObjectState": final_state,
            "effectOwner": LSTAT_EFFECT_OWNER,
          },
        }],
        "decision": "allow",
        "result": {
          "class": identity.case.native_result_class(),
          "digest": result_digest,
        },
        "sideEffects": [],
        "delivery": "delivered",
        "cleanup": "complete",
      });
      let observed_result_digest = deno_permissions::rev2::hjcs_digest(
        OBSERVED_RESULT_DIGEST_DOMAIN,
        &observation,
      )
      .unwrap();
      let observation_bytes = canonical_bytes(&observation);
      let delivery_frame = json!({
        "encoding": "base64url",
        "bytes": URL_SAFE_NO_PAD.encode(&observation_bytes),
      });
      let delivery_frame_digest =
        raw_frame_digest(DELIVERY_FRAME_DIGEST_DOMAIN, &observation_bytes);
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
        "profile": CAPSEC_PROFILE,
        "runNonce": request["runNonce"],
        "target": identity.target,
        "featureSet": identity.feature_set,
        "parentStandaloneDigest": request["parentStandaloneDigest"],
        "engineDigest": request["engineDigest"],
        "forkCommit": identity.fork_commit,
        "fixtureArtifactDigest": identity.fixture_artifact_digest,
        "executionIdentityDigest": request["executionIdentityDigest"],
        "sourceClosureDigest": request["sourceClosureDigest"],
        "caseId": identity.case.case_id(),
        "edgeId": LSTAT_EDGE_ID,
        "requirementId": LSTAT_REQUIREMENT_ID,
        "caseKind": identity.case.case_kind(),
        "candidateRequestFrameDigest":
          raw_frame_digest(CANDIDATE_REQUEST_DIGEST_DOMAIN, request_bytes),
        "acceptedDescriptorSlotsDigest": request["descriptorSlotsDigest"],
        "capturedUmask": 63,
        "normalizedObservedResult": observation,
        "observedResultDigest": observed_result_digest,
        "candidateArenaDigest": DIGEST,
        "engineTraceDigest": DIGEST,
        "deliveryFrame": delivery_frame,
        "deliveryFrameDigest": delivery_frame_digest,
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

    fn request_files() -> RequestFiles {
      let temp = tempfile::tempdir().unwrap();
      let root_path = temp.path().join("project");
      std::fs::create_dir(&root_path).unwrap();
      let root = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(root_path)
        .unwrap();
      let arena_path: PathBuf = temp.path().join("arena");
      let arena = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(arena_path)
        .unwrap();
      arena.set_len(ARENA_CAPACITY_BYTES as u64).unwrap();
      RequestFiles {
        _temp: temp,
        root,
        arena,
      }
    }

    fn enter_request_pending(
      identity: &CandidateLstatProtocolIdentity,
    ) -> (CandidateFd3Session, FramedStreamEndpoint, Value, Vec<u8>) {
      let (candidate_endpoint, supervisor_endpoint) =
        framed_stream_socketpair().unwrap();
      let mut session = CandidateFd3Session::new(
        candidate_endpoint,
        identity.clone(),
        deadline(),
      );
      let ready = ready(identity);
      let ready_bytes = canonical_bytes(&ready);
      session.send_ready(&ready_bytes, deadline()).unwrap();
      let captured = supervisor_endpoint
        .receive_one_canonical_jcs_frame(
          FrameByteLimit::CANDIDATE_READY,
          0,
          deadline(),
        )
        .unwrap();
      assert_eq!(captured.raw_bytes, ready_bytes);
      (session, supervisor_endpoint, ready, captured.raw_bytes)
    }

    fn enter_request_pending_with_clock(
      identity: &CandidateLstatProtocolIdentity,
      absolute_deadline: Instant,
      clock: Arc<TestClock>,
    ) -> (CandidateFd3Session, FramedStreamEndpoint, Value, Vec<u8>) {
      let (candidate_endpoint, supervisor_endpoint) =
        framed_stream_socketpair().unwrap();
      let mut session = CandidateFd3Session::with_deadline(
        candidate_endpoint,
        identity.clone(),
        CandidateSessionDeadline::with_clock(absolute_deadline, clock),
      );
      let ready = ready(identity);
      let ready_bytes = canonical_bytes(&ready);
      session
        .send_ready(&ready_bytes, absolute_deadline + Duration::from_secs(30))
        .unwrap();
      let captured = supervisor_endpoint
        .receive_one_canonical_jcs_frame(
          FrameByteLimit::CANDIDATE_READY,
          0,
          deadline(),
        )
        .unwrap();
      assert_eq!(captured.raw_bytes, ready_bytes);
      (session, supervisor_endpoint, ready, captured.raw_bytes)
    }

    fn send_request(
      supervisor: &FramedStreamEndpoint,
      request: &Value,
      files: &RequestFiles,
      shutdown: bool,
    ) -> Vec<u8> {
      let request_bytes = canonical_bytes(request);
      supervisor
        .send_packet_with_descriptors(
          &request_bytes,
          &[files.root.as_fd(), files.arena.as_fd()],
          deadline(),
        )
        .unwrap();
      if shutdown {
        supervisor.shutdown_write(deadline()).unwrap();
      }
      request_bytes
    }

    fn accepted_session(
      case: CandidateLstatCase,
    ) -> (
      CandidateFd3Session,
      FramedStreamEndpoint,
      CandidateLstatProtocolIdentity,
      Value,
      Value,
      Vec<u8>,
      CandidateLstatRequest,
      RequestFiles,
    ) {
      let identity = identity(case);
      let (mut session, supervisor, ready, _) =
        enter_request_pending(&identity);
      let request = request(&identity);
      let files = request_files();
      let request_bytes = send_request(&supervisor, &request, &files, true);
      let received = session.receive_request(deadline()).unwrap();
      (
        session,
        supervisor,
        identity,
        ready,
        request,
        request_bytes,
        received,
        files,
      )
    }

    fn accepted_session_with_clock(
      case: CandidateLstatCase,
      absolute_deadline: Instant,
      clock: Arc<TestClock>,
    ) -> (
      CandidateFd3Session,
      FramedStreamEndpoint,
      CandidateLstatProtocolIdentity,
      Value,
      Value,
      Vec<u8>,
      CandidateLstatRequest,
      RequestFiles,
    ) {
      let identity = identity(case);
      let (mut session, supervisor, ready, _) =
        enter_request_pending_with_clock(&identity, absolute_deadline, clock);
      let request = request(&identity);
      let files = request_files();
      let request_bytes = send_request(&supervisor, &request, &files, true);
      let received = session
        .receive_request(absolute_deadline + Duration::from_secs(30))
        .unwrap();
      (
        session,
        supervisor,
        identity,
        ready,
        request,
        request_bytes,
        received,
        files,
      )
    }

    #[test]
    fn candidate_fd3_accepts_both_exact_lstat_packet_sequences() {
      for target in ["aarch64-apple-darwin", "x86_64-unknown-linux-gnu"] {
        for case in [
          CandidateLstatCase::Existing,
          CandidateLstatCase::FinalMissing,
        ] {
          let identity = identity_for(target, case);
          let (mut session, supervisor, ready, _) =
            enter_request_pending(&identity);
          let request = request(&identity);
          let files = request_files();
          let request_bytes = send_request(&supervisor, &request, &files, true);
          let received = session.receive_request(deadline()).unwrap();
          let retained_descriptors = session.retained_descriptor_raw_fds();
          assert_descriptors_open(retained_descriptors);
          assert_eq!(received.raw_bytes(), request_bytes);
          assert_eq!(
            received.request_frame_digest(),
            raw_frame_digest(CANDIDATE_REQUEST_DIGEST_DOMAIN, &request_bytes)
          );
          assert_eq!(received.descriptor_slots_digest(), DIGEST);
          let response = response(&identity, &ready, &request, &request_bytes);
          let response_bytes = canonical_bytes(&response);
          session
            .send_response(received, &response_bytes, deadline())
            .unwrap();
          assert_descriptors_closed(retained_descriptors);
          assert_eq!(session.state(), CandidateFd3State::Complete);
          let captured = supervisor
            .receive_one_canonical_jcs_frame(
              FrameByteLimit::CONTROL,
              0,
              deadline(),
            )
            .unwrap();
          assert_eq!(captured.raw_bytes, response_bytes);
          supervisor.require_eof(deadline()).unwrap();
        }
      }
    }

    #[test]
    fn candidate_fd3_refusal_is_sticky_across_out_of_order_transitions() {
      let identity = identity(CandidateLstatCase::Existing);
      let (candidate_endpoint, supervisor) =
        framed_stream_socketpair().unwrap();
      let mut session = CandidateFd3Session::new(
        candidate_endpoint,
        identity.clone(),
        deadline(),
      );
      let error = session.receive_request(deadline()).unwrap_err();
      assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
      assert_eq!(session.state(), CandidateFd3State::Refused);
      let error = session
        .send_ready(&canonical_bytes(&ready(&identity)), deadline())
        .unwrap_err();
      assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
      supervisor.require_eof(deadline()).unwrap();
    }

    #[test]
    fn candidate_fd3_ready_refuses_noncanonical_or_open_schema_bytes() {
      assert!(
        CandidateLstatProtocolIdentity::new(
          "x86_64-apple-darwin",
          FEATURE_SET,
          BUILD_MARKER,
          FORK_COMMIT,
          FIXTURE_DIGEST,
          CandidateLstatCase::Existing.case_id(),
          DIGEST,
        )
        .is_err()
      );
      assert!(
        CandidateLstatProtocolIdentity::new(
          "aarch64-apple-darwin",
          FEATURE_SET,
          BUILD_MARKER,
          FORK_COMMIT,
          FIXTURE_DIGEST,
          "filesystem:lstat-sync:lstat-symlink",
          DIGEST,
        )
        .is_err()
      );
      for bytes in [br#"{ "schema":"x"}"#.to_vec(), {
        let identity = identity(CandidateLstatCase::Existing);
        let mut value = ready(&identity);
        value["extra"] = json!(true);
        canonical_bytes(&value)
      }] {
        let identity = identity(CandidateLstatCase::Existing);
        let (candidate_endpoint, supervisor) =
          framed_stream_socketpair().unwrap();
        let mut session =
          CandidateFd3Session::new(candidate_endpoint, identity, deadline());
        let error = session.send_ready(&bytes, deadline()).unwrap_err();
        assert!(
          matches!(
            error.kind(),
            io::ErrorKind::InvalidData | io::ErrorKind::InvalidInput
          ),
          "{error:?}"
        );
        assert_eq!(session.state(), CandidateFd3State::Refused);
        supervisor.require_eof(deadline()).unwrap();
      }
    }

    #[test]
    fn candidate_fd3_request_requires_exact_binding_rights_and_peer_eof() {
      enum Mutation {
        Binding,
        ReorderedRights,
        HardlinkedArena,
        WrongSizedArena,
        SpecialArena,
        NonzeroArena,
        MissingEof,
        SecondFrame,
      }
      for mutation in [
        Mutation::Binding,
        Mutation::ReorderedRights,
        Mutation::HardlinkedArena,
        Mutation::WrongSizedArena,
        Mutation::SpecialArena,
        Mutation::NonzeroArena,
        Mutation::MissingEof,
        Mutation::SecondFrame,
      ] {
        let identity = identity(CandidateLstatCase::Existing);
        let (mut session, supervisor, _, _) = enter_request_pending(&identity);
        let mut request = request(&identity);
        let mut files = request_files();
        match mutation {
          Mutation::Binding => {
            request["caseKind"] = json!("lstat-final-missing");
            send_request(&supervisor, &request, &files, true);
          }
          Mutation::ReorderedRights => {
            let request_bytes = canonical_bytes(&request);
            supervisor
              .send_packet_with_descriptors(
                &request_bytes,
                &[files.arena.as_fd(), files.root.as_fd()],
                deadline(),
              )
              .unwrap();
            supervisor.shutdown_write(deadline()).unwrap();
          }
          Mutation::HardlinkedArena => {
            std::fs::hard_link(
              files._temp.path().join("arena"),
              files._temp.path().join("arena-alias"),
            )
            .unwrap();
            send_request(&supervisor, &request, &files, true);
          }
          Mutation::WrongSizedArena => {
            files
              .arena
              .set_len((ARENA_CAPACITY_BYTES - 1) as u64)
              .unwrap();
            send_request(&supervisor, &request, &files, true);
          }
          Mutation::SpecialArena => {
            files.arena = File::open("/dev/null").unwrap();
            send_request(&supervisor, &request, &files, true);
          }
          Mutation::NonzeroArena => {
            files.arena.seek(SeekFrom::Start(4096)).unwrap();
            files.arena.write_all(&[1]).unwrap();
            send_request(&supervisor, &request, &files, true);
          }
          Mutation::MissingEof => {
            send_request(&supervisor, &request, &files, false);
          }
          Mutation::SecondFrame => {
            send_request(&supervisor, &request, &files, false);
            supervisor
              .send_packet_with_descriptors(
                &canonical_bytes(&json!({ "schema": "second" })),
                &[],
                deadline(),
              )
              .unwrap();
            supervisor.shutdown_write(deadline()).unwrap();
          }
        }
        let request_deadline = if matches!(mutation, Mutation::MissingEof) {
          Instant::now() + Duration::from_millis(50)
        } else {
          deadline()
        };
        let error = session.receive_request(request_deadline).unwrap_err();
        assert!(
          matches!(
            error.kind(),
            io::ErrorKind::InvalidData | io::ErrorKind::TimedOut
          ),
          "{error:?}"
        );
        assert_eq!(session.state(), CandidateFd3State::Refused);
      }
    }

    #[test]
    fn candidate_fd3_session_deadline_cannot_be_extended_by_later_transition() {
      let identity = identity(CandidateLstatCase::Existing);
      let absolute_deadline = Instant::now() + Duration::from_secs(30);
      let clock = Arc::new(TestClock::new(absolute_deadline));
      let (mut session, supervisor, _, _) = enter_request_pending_with_clock(
        &identity,
        absolute_deadline,
        Arc::clone(&clock),
      );
      let request = request(&identity);
      let files = request_files();
      send_request(&supervisor, &request, &files, true);
      clock.expire_now();
      let error = session
        .receive_request(absolute_deadline + Duration::from_secs(300))
        .unwrap_err();
      assert_eq!(error.kind(), io::ErrorKind::TimedOut);
      assert_eq!(session.state(), CandidateFd3State::Refused);
      supervisor.require_eof(deadline()).unwrap();
    }

    #[test]
    fn candidate_fd3_arena_scan_expiry_is_sticky_without_sleep() {
      let identity = identity(CandidateLstatCase::Existing);
      let absolute_deadline = Instant::now() + Duration::from_secs(30);
      let clock = Arc::new(TestClock::new(absolute_deadline));
      let (mut session, supervisor, _, _) = enter_request_pending_with_clock(
        &identity,
        absolute_deadline,
        Arc::clone(&clock),
      );
      let request = request(&identity);
      let files = request_files();
      send_request(&supervisor, &request, &files, true);
      clock.expire_on_arena_attempt(2);
      let error = session
        .receive_request(absolute_deadline + Duration::from_secs(300))
        .unwrap_err();
      assert_eq!(error.kind(), io::ErrorKind::TimedOut);
      assert_eq!(clock.arena_attempts(), 2);
      assert_eq!(session.state(), CandidateFd3State::Refused);
      supervisor.require_eof(deadline()).unwrap();
    }

    #[test]
    fn candidate_fd3_pre_response_expiry_closes_session_rights() {
      let absolute_deadline = Instant::now() + Duration::from_secs(30);
      let clock = Arc::new(TestClock::new(absolute_deadline));
      let (
        mut session,
        supervisor,
        identity,
        ready,
        request,
        request_bytes,
        received,
        _files,
      ) = accepted_session_with_clock(
        CandidateLstatCase::Existing,
        absolute_deadline,
        Arc::clone(&clock),
      );
      let retained_descriptors = session.retained_descriptor_raw_fds();
      assert_descriptors_open(retained_descriptors);
      let response = response(&identity, &ready, &request, &request_bytes);
      clock.expire_now();
      let error = session
        .send_response(
          received,
          &canonical_bytes(&response),
          absolute_deadline + Duration::from_secs(300),
        )
        .unwrap_err();
      assert_eq!(error.kind(), io::ErrorKind::TimedOut);
      assert_eq!(session.state(), CandidateFd3State::Refused);
      assert_descriptors_closed(retained_descriptors);
      supervisor.require_eof(deadline()).unwrap();
    }

    #[test]
    fn candidate_fd3_response_refuses_relation_and_schema_mutations() {
      for mutation in
        ["request-digest", "delivery", "extra", "normalized-extra"]
      {
        let (
          mut session,
          supervisor,
          identity,
          ready,
          request,
          request_bytes,
          received,
          _files,
        ) = accepted_session(CandidateLstatCase::FinalMissing);
        let retained_descriptors = session.retained_descriptor_raw_fds();
        assert_descriptors_open(retained_descriptors);
        let mut response =
          response(&identity, &ready, &request, &request_bytes);
        match mutation {
          "request-digest" => {
            response["candidateRequestFrameDigest"] = json!(FIXTURE_DIGEST);
          }
          "delivery" => {
            response["deliveryFrame"]["bytes"] = json!("AA");
          }
          "extra" => {
            response["extra"] = json!(true);
          }
          "normalized-extra" => {
            response["normalizedObservedResult"]["extra"] = json!(true);
          }
          _ => unreachable!(),
        }
        let error = session
          .send_response(received, &canonical_bytes(&response), deadline())
          .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(session.state(), CandidateFd3State::Refused);
        assert_descriptors_closed(retained_descriptors);
        supervisor.require_eof(deadline()).unwrap();
      }
    }

    #[test]
    fn candidate_fd3_response_pending_reentry_closes_session_rights() {
      enum Reentry {
        Receive,
        Ready,
      }
      for reentry in [Reentry::Receive, Reentry::Ready] {
        let (mut session, supervisor, identity, ready, _, _, received, _files) =
          accepted_session(CandidateLstatCase::Existing);
        let retained_descriptors = session.retained_descriptor_raw_fds();
        assert_descriptors_open(retained_descriptors);
        let error = match reentry {
          Reentry::Receive => {
            session.receive_request(deadline()).map(|_| ()).unwrap_err()
          }
          Reentry::Ready => session
            .send_ready(&canonical_bytes(&ready), deadline())
            .unwrap_err(),
        };
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(session.state(), CandidateFd3State::Refused);
        assert_descriptors_closed(retained_descriptors);
        assert_eq!(received.descriptor_slots_digest(), DIGEST);
        assert_eq!(identity.case, CandidateLstatCase::Existing);
        supervisor.require_eof(deadline()).unwrap();
      }
    }

    #[test]
    fn candidate_fd3_incomplete_session_drop_closes_rights_not_token() {
      let (
        session,
        supervisor,
        _identity,
        _ready,
        _request,
        request_bytes,
        received,
        _files,
      ) = accepted_session(CandidateLstatCase::Existing);
      let retained_descriptors = session.retained_descriptor_raw_fds();
      assert_descriptors_open(retained_descriptors);
      drop(session);
      assert_descriptors_closed(retained_descriptors);
      assert_eq!(received.raw_bytes(), request_bytes);
      assert_eq!(received.descriptor_slots_digest(), DIGEST);
      supervisor.require_eof(deadline()).unwrap();
    }

    #[test]
    fn candidate_fd3_response_consumes_request_and_shutdown_is_terminal() {
      let (mut first_session, first_supervisor, _, _, _, _, first_request, _) =
        accepted_session(CandidateLstatCase::Existing);
      let (
        mut second_session,
        second_supervisor,
        _,
        _,
        _,
        _,
        second_request,
        _,
      ) = accepted_session(CandidateLstatCase::Existing);
      let first_descriptors = first_session.retained_descriptor_raw_fds();
      let second_descriptors = second_session.retained_descriptor_raw_fds();
      assert_descriptors_open(first_descriptors);
      assert_descriptors_open(second_descriptors);
      let error = first_session
        .send_response(second_request, b"{}", deadline())
        .unwrap_err();
      assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
      assert_eq!(first_session.state(), CandidateFd3State::Refused);
      assert_descriptors_closed(first_descriptors);
      assert_descriptors_open(second_descriptors);
      first_supervisor.require_eof(deadline()).unwrap();
      let error = second_session
        .send_response(first_request, b"{}", deadline())
        .unwrap_err();
      assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
      assert_eq!(second_session.state(), CandidateFd3State::Refused);
      assert_descriptors_closed(second_descriptors);
      second_supervisor.require_eof(deadline()).unwrap();

      let (
        mut session,
        supervisor,
        identity,
        ready,
        request,
        request_bytes,
        received,
        _files,
      ) = accepted_session(CandidateLstatCase::Existing);
      let retained_descriptors = session.retained_descriptor_raw_fds();
      assert_descriptors_open(retained_descriptors);
      let response = response(&identity, &ready, &request, &request_bytes);
      let response_bytes = canonical_bytes(&response);
      session
        .send_response(received, &response_bytes, deadline())
        .unwrap();
      assert_descriptors_closed(retained_descriptors);
      let captured = supervisor
        .receive_one_canonical_jcs_frame(FrameByteLimit::CONTROL, 0, deadline())
        .unwrap();
      assert_eq!(captured.raw_bytes, response_bytes);
      supervisor.require_eof(deadline()).unwrap();
      assert_eq!(session.state(), CandidateFd3State::Complete);
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  const DIGEST: &str = "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
  const CASE_ID: &str = "filesystem:lstat-sync:existing";

  fn run(args: &[&str]) -> Option<i32> {
    maybe_run_oden_capsec_filesystem_candidate(args.iter().map(OsString::from))
  }

  #[test]
  fn ordinary_argv_is_not_intercepted() {
    assert_eq!(run(&["deno", "run", "mod.ts"]), None);
  }

  #[test]
  fn exact_but_unregistered_candidate_refuses() {
    assert_eq!(
      run(&[
        "deno",
        "--_oden-capsec-filesystem-candidate-v2",
        DIGEST,
        CASE_ID,
      ]),
      Some(REFUSAL_EXIT_CODE),
    );
  }

  #[test]
  fn malformed_reserved_argv_refuses() {
    for args in [
      vec!["deno", "--_oden-capsec-filesystem-candidate-v2"],
      vec![
        "deno",
        "run",
        "--_oden-capsec-filesystem-candidate-v2",
        DIGEST,
        CASE_ID,
      ],
      vec![
        "deno",
        "--_oden-capsec-filesystem-candidate-v3",
        DIGEST,
        CASE_ID,
      ],
      vec![
        "deno",
        "--_oden-capsec-filesystem-candidate-v2",
        "sha256-not-canonical",
        CASE_ID,
      ],
      vec![
        "deno",
        "--_oden-capsec-filesystem-candidate-v2",
        DIGEST,
        "case id",
      ],
    ] {
      assert_eq!(run(&args), Some(REFUSAL_EXIT_CODE));
    }
  }
}

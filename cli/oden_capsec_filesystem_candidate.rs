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
  // below has production-uncalled preflight, construction, descriptor-slot
  // preparation, and exact D1-to-D2 execution-join boundaries, but no
  // response-artifact assembler or production caller. All three generated
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
  use std::ffi::CString;
  use std::fs::File;
  use std::io;
  use std::os::fd::AsFd;
  use std::os::fd::AsRawFd;
  use std::os::fd::BorrowedFd;
  use std::os::fd::FromRawFd;
  use std::os::fd::IntoRawFd;
  use std::os::fd::OwnedFd;
  #[cfg(target_os = "macos")]
  use std::os::fd::RawFd;
  use std::sync::Arc;
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
  use deno_runtime::deno_permissions::rev2::FilesystemExecutionProjection;
  use deno_runtime::deno_permissions::rev2::FilesystemExpectedObservation;
  use deno_runtime::deno_permissions::rev2::FilesystemFinalObjectState;
  use deno_runtime::deno_permissions::rev2::FilesystemFollowMode;
  use deno_runtime::deno_permissions::rev2::FilesystemInlineContentKind;
  use deno_runtime::deno_permissions::rev2::FilesystemLogicalRoot;
  use deno_runtime::deno_permissions::rev2::FilesystemObjectIdentity;
  use deno_runtime::deno_permissions::rev2::FilesystemObjectIdentityKind;
  use deno_runtime::deno_permissions::rev2::FilesystemObjectKind;
  use deno_runtime::deno_permissions::rev2::FilesystemOperationRequest;
  use deno_runtime::deno_permissions::rev2::FilesystemPlatformPathEncoding;
  use deno_runtime::deno_permissions::rev2::FilesystemTargetParentRef;
  use sha2::Digest;
  use sha2::Sha256;

  #[cfg(target_os = "macos")]
  use crate::oden_capsec_filesystem_parent::ProcessCredentials;
  #[cfg(target_os = "macos")]
  use crate::oden_capsec_filesystem_parent::candidate_fd_inventory;
  #[cfg(target_os = "macos")]
  use crate::oden_capsec_filesystem_parent::macos_platform_state_value;
  #[cfg(target_os = "macos")]
  use crate::oden_capsec_filesystem_parent::observe_blocked_child;
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
  const DESCRIPTOR_SLOTS_SCHEMA: &str =
    "oden/capsec-filesystem-descriptor-slots/2";
  const DESCRIPTOR_SLOTS_DIGEST_DOMAIN: &str =
    "oden:capsec:filesystem-descriptor-slots:2";
  const ENGINE_BUILD_MARKER_SCHEMA: &str =
    "oden/capsec-rev2-engine-build-marker/2";
  const ENGINE_BUILD_MARKER_DIGEST_DOMAIN: &str =
    "oden:capsec:rev2-engine-build-marker:2";
  const ENGINE_BUILD_MARKER_PREFIX: &str = "oden-engine-v2-";
  #[cfg(target_os = "macos")]
  const CANDIDATE_MACOS_SEATBELT_DISPOSITION: &str = "unavailable";
  const ARENA_CAPACITY_BYTES: i64 = 8 * 1024 * 1024;
  const REQUIRED_CAPTURED_UMASK: u64 = 0o077;
  const EXPECTED_DESCRIPTOR_COUNT: usize = 2;
  const LSTAT_ROOT_BINDING_ID: &str = "root:project";
  const LSTAT_ROOT_FIXTURE_IDENTITY: &str = "fixture:project-root";
  const LSTAT_SOURCE_OBJECT_ID: &str = "source";
  const LSTAT_SOURCE_NAME: &str = "input.txt";
  const LSTAT_DESTINATION_OBJECT_ID: &str = "destination";
  const LSTAT_DESTINATION_NAME: &str = "output.txt";
  const EMPTY_CONTENT_DIGEST: &str =
    "sha256-47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU";
  #[cfg(target_os = "macos")]
  const CANDIDATE_CONTROL_FD: RawFd = 3;

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
  // the exact generated current-binary row can parameterize the dormant
  // candidate-side packet state machine. This remains an equality projection,
  // not image authentication or execution authority.
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

  pub(crate) struct CandidateLstatProtocolIdentity {
    generated_seal: CandidateGeneratedSeal,
    generated_topology: CandidateGeneratedLstatTopology,
    target: String,
    feature_set: String,
    embedded_build_marker: String,
    fork_commit: String,
    fixture_artifact_digest: String,
    case: CandidateLstatCase,
    execution_projection_digest: String,
  }

  enum CandidateGeneratedSeal {
    Exact(OdenRev2LstatCandidateBinaryIdentity),
    #[cfg(test)]
    Fixture,
  }

  #[derive(Clone, Debug, Eq, PartialEq)]
  struct CandidateGeneratedLstatTopology {
    root_fixture_identity: FilesystemObjectIdentity,
    expected_source: CandidateGeneratedSourceTopology,
  }

  #[derive(Clone, Copy, Debug, Eq, PartialEq)]
  enum CandidateGeneratedSourceTopology {
    ExistingEmptyFile,
    FinalMissing,
  }

  struct CandidateEngineBuildMarkerFacts<'a> {
    target: &'a str,
    rust_toolchain: &'a str,
    cargo_features: &'a str,
    rust_cfg_digest: &'a str,
    cargo_feature_graph_digest: &'a str,
    build_profile: &'a str,
    panic_strategy: &'a str,
    debug_assertions: bool,
    fork_commit: &'a str,
  }

  impl CandidateLstatProtocolIdentity {
    /// Production-compiled, production-uncalled constructor with no target,
    /// feature-set, build-marker, fork, or projection choice at the callsite.
    /// The fixture/case lookup only selects one exact pointer-backed generated
    /// admission after the permissions crate has joined all current binary
    /// build markers and native cfg facts to the same generated target row.
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
          "candidate binary does not join its exact generated lstat row",
        )
      })?;
      let fork_commit = deno_lib::version::DENO_VERSION_INFO.git_hash;
      Self::from_generated(generated, &build_identity, fork_commit)
    }

    fn from_generated(
      generated: OdenRev2LstatCandidateBinaryIdentity,
      build_identity: &OdenRev2CompiledBuildIdentity,
      fork_commit: &str,
    ) -> io::Result<Self> {
      if !is_canonical_fork_commit(fork_commit) {
        return Err(invalid_data(
          "candidate binary fork identity is not exact lowercase Git SHA-1",
        ));
      }
      let embedded_build_marker =
        derive_engine_build_marker(&CandidateEngineBuildMarkerFacts {
          target: generated.target(),
          rust_toolchain: generated.rust_toolchain(),
          cargo_features: generated.cargo_features(),
          rust_cfg_digest: generated.rust_cfg_digest(),
          cargo_feature_graph_digest: generated.cargo_feature_graph_digest(),
          build_profile: generated.build_profile(),
          panic_strategy: build_identity.actual_panic_strategy,
          debug_assertions: build_identity.actual_debug_assertions,
          fork_commit,
        })?;
      let generated_topology = validate_generated_lstat_topology(
        generated.execution_projection(),
        generated.case_id(),
      )?;
      let case = CandidateLstatCase::from_id(generated.case_id())
        .ok_or_else(|| invalid_data("candidate generated case is not lstat"))?;
      Ok(Self {
        generated_topology,
        target: generated.target().to_string(),
        feature_set: generated.feature_set().to_string(),
        embedded_build_marker,
        fork_commit: fork_commit.to_string(),
        fixture_artifact_digest: generated
          .fixture_artifact_digest()
          .to_string(),
        case,
        execution_projection_digest: generated
          .execution_projection_digest()
          .to_string(),
        generated_seal: CandidateGeneratedSeal::Exact(generated),
      })
    }

    #[cfg(test)]
    fn new_test_fixture(
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
        || !is_canonical_engine_build_marker(embedded_build_marker)
        || !is_canonical_fork_commit(fork_commit)
        || !is_canonical_sha256_digest(fixture_artifact_digest)
        || !is_canonical_sha256_digest(execution_projection_digest)
      {
        return Err(invalid_input("candidate FD3 identity is not canonical"));
      }
      let expected_source = match case {
        CandidateLstatCase::Existing => {
          CandidateGeneratedSourceTopology::ExistingEmptyFile
        }
        CandidateLstatCase::FinalMissing => {
          CandidateGeneratedSourceTopology::FinalMissing
        }
      };
      Ok(Self {
        generated_seal: CandidateGeneratedSeal::Fixture,
        generated_topology: CandidateGeneratedLstatTopology {
          root_fixture_identity: FilesystemObjectIdentity {
            kind: FilesystemObjectIdentityKind::OpaqueToken,
            value: LSTAT_ROOT_FIXTURE_IDENTITY.to_string(),
          },
          expected_source,
        },
        target: target.to_string(),
        feature_set: feature_set.to_string(),
        embedded_build_marker: embedded_build_marker.to_string(),
        fork_commit: fork_commit.to_string(),
        fixture_artifact_digest: fixture_artifact_digest.to_string(),
        case,
        execution_projection_digest: execution_projection_digest.to_string(),
      })
    }

    #[cfg(test)]
    fn duplicate_test_fixture(&self) -> Self {
      assert!(matches!(
        self.generated_seal,
        CandidateGeneratedSeal::Fixture
      ));
      Self {
        generated_seal: CandidateGeneratedSeal::Fixture,
        generated_topology: self.generated_topology.clone(),
        target: self.target.clone(),
        feature_set: self.feature_set.clone(),
        embedded_build_marker: self.embedded_build_marker.clone(),
        fork_commit: self.fork_commit.clone(),
        fixture_artifact_digest: self.fixture_artifact_digest.clone(),
        case: self.case,
        execution_projection_digest: self.execution_projection_digest.clone(),
      }
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

    fn require_exact_execution_join(&self) -> io::Result<()> {
      match &self.generated_seal {
        CandidateGeneratedSeal::Exact(generated) => {
          let generated_topology = validate_generated_lstat_topology(
            generated.execution_projection(),
            generated.case_id(),
          )?;
          if generated.fixture_artifact_digest() != self.fixture_artifact_digest
            || generated.case_id() != self.case.case_id()
            || generated.target() != self.target
            || generated.feature_set() != self.feature_set
            || generated.execution_projection_digest()
              != self.execution_projection_digest
            || generated_topology != self.generated_topology
          {
            return Err(invalid_data(
              "candidate prepared identity diverges from generated admission",
            ));
          }
          Ok(())
        }
        #[cfg(test)]
        CandidateGeneratedSeal::Fixture => Err(invalid_data(
          "candidate execution requires an exact generated admission",
        )),
      }
    }
  }

  fn validate_generated_lstat_topology(
    projection: &FilesystemExecutionProjection,
    case_id: &str,
  ) -> io::Result<CandidateGeneratedLstatTopology> {
    let case = CandidateLstatCase::from_id(case_id)
      .ok_or_else(|| invalid_data("candidate generated case is not lstat"))?;
    if projection.case_id != case_id
      || projection.edge_id != LSTAT_EDGE_ID
      || projection.requirement_id != LSTAT_REQUIREMENT_ID
      || projection.case_kind != case.case_kind()
      || projection.setup.logical_roots.len() != 1
      || projection.setup.objects.len() != 2
    {
      return Err(invalid_data(
        "candidate generated lstat topology is not exact",
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
        "candidate generated logical root is not exact",
      ));
    }
    let target_ref = match &projection.operation_request {
      FilesystemOperationRequest::LstatSync { target_ref } => target_ref,
      _ => {
        return Err(invalid_data("candidate generated operation is not lstat"));
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
        "candidate generated lstat target is not exact",
      ));
    }

    let source = &projection.setup.objects[0];
    if source.object_id != LSTAT_SOURCE_OBJECT_ID
      || source.root != FilesystemLogicalRoot::Project
      || source.path.encoding != FilesystemPlatformPathEncoding::Unicode
      || source.path.value != LSTAT_SOURCE_NAME
      || source.alias_target_object_id.is_some()
      || source.link_target_object_id.is_some()
    {
      return Err(invalid_data(
        "candidate generated source object is not exact",
      ));
    }
    let expected_source = match case {
      CandidateLstatCase::Existing
        if source.kind == FilesystemObjectKind::RegularFile
          && source.object_identity.as_ref().is_some_and(|identity| {
            identity.kind == FilesystemObjectIdentityKind::VerifiedContent
              && identity.value == EMPTY_CONTENT_DIGEST
          })
          && source.content.as_ref().is_some_and(|content| {
            content.kind == FilesystemInlineContentKind::InlineBase64url
              && content.bytes.is_empty()
          })
          && source.content_digest.as_deref() == Some(EMPTY_CONTENT_DIGEST) =>
      {
        CandidateGeneratedSourceTopology::ExistingEmptyFile
      }
      CandidateLstatCase::FinalMissing
        if source.kind == FilesystemObjectKind::Missing
          && source.object_identity.is_none()
          && source.content.is_none()
          && source.content_digest.is_none() =>
      {
        CandidateGeneratedSourceTopology::FinalMissing
      }
      _ => {
        return Err(invalid_data(
          "candidate generated source state is not exact",
        ));
      }
    };

    let destination = &projection.setup.objects[1];
    if destination.object_id != LSTAT_DESTINATION_OBJECT_ID
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
        "candidate generated destination state is not exact",
      ));
    }
    Ok(CandidateGeneratedLstatTopology {
      root_fixture_identity: root.object_identity.clone(),
      expected_source,
    })
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

  fn derive_engine_build_marker(
    facts: &CandidateEngineBuildMarkerFacts<'_>,
  ) -> io::Result<String> {
    let cargo_features = facts.cargo_features.split(',').collect::<Vec<_>>();
    if !matches!(
      facts.target,
      "aarch64-apple-darwin" | "x86_64-unknown-linux-gnu"
    ) || !is_canonical_identifier(facts.rust_toolchain)
      || !is_canonical_lower_hex_sha256(facts.rust_cfg_digest)
      || !is_canonical_lower_hex_sha256(facts.cargo_feature_graph_digest)
      || facts.build_profile != "release"
      || facts.panic_strategy != "abort"
      || facts.debug_assertions
      || !is_canonical_fork_commit(facts.fork_commit)
      || cargo_features.is_empty()
      || cargo_features
        .iter()
        .any(|feature| feature.is_empty() || !is_canonical_identifier(feature))
      || cargo_features
        .windows(2)
        .any(|pair| pair[0].as_bytes() >= pair[1].as_bytes())
    {
      return Err(invalid_data(
        "candidate engine build marker facts are not exact",
      ));
    }
    let value = json!({
      "schema": ENGINE_BUILD_MARKER_SCHEMA,
      "target": facts.target,
      "rustToolchain": facts.rust_toolchain,
      "cargoFeatures": cargo_features,
      "rustCfgDigest": facts.rust_cfg_digest,
      "cargoFeatureGraphDigest": facts.cargo_feature_graph_digest,
      "profile": facts.build_profile,
      "panicStrategy": facts.panic_strategy,
      "debugAssertions": facts.debug_assertions,
      "forkCommit": facts.fork_commit,
    });
    let digest = deno_permissions::rev2::hjcs_digest(
      ENGINE_BUILD_MARKER_DIGEST_DOMAIN,
      &value,
    )
    .map_err(|_| invalid_data("candidate engine build marker failed"))?;
    let marker = format!("{ENGINE_BUILD_MARKER_PREFIX}{digest}");
    if !is_canonical_engine_build_marker(&marker) {
      return Err(invalid_data(
        "candidate engine build marker result is not canonical",
      ));
    }
    Ok(marker)
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
    ExecutionStart,
    ExecutionComplete,
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

  #[derive(Clone, Debug, Eq, PartialEq)]
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

  struct CandidateReadyObservedFacts {
    candidate_pid: String,
    candidate_pgid: String,
    candidate_start_identity: String,
    identities: Value,
    process_limit_readback: Value,
    pre_request_fd_inventory: Value,
    platform_state: Value,
  }

  #[derive(Clone, Copy, Debug, Eq, PartialEq)]
  enum CandidateReadyPreflightRefusal {
    ProcessIdentity,
    ProcessCredentials,
    ProcessLimit,
    DescriptorInventory,
    PlatformState,
    LinuxContainmentUnavailable,
    UnsupportedTarget,
    CanonicalFrame,
  }

  /// A non-owning, non-cloneable preflight produced before FD 3 is
  /// reconstructed as an owned endpoint. It retains only canonical ready
  /// bytes and their already-validated fact projection. There is no session,
  /// descriptor, public-op, response, evidence, admission, or authority
  /// method on this value.
  ///
  /// @ref LLP 0019#pre-promotion-conformance-candidate-execution
  /// [constrained-by] — Ready facts are candidate claims until the trusted
  /// parent joins them to independent child and retained-image observations.
  pub(crate) struct CandidateReadyPreflight {
    raw_bytes: Vec<u8>,
    validated_facts: CandidateReadyFacts,
  }

  impl CandidateReadyPreflight {
    fn collect(
      identity: &CandidateLstatProtocolIdentity,
    ) -> Result<Self, CandidateReadyPreflightRefusal> {
      let observed = collect_current_ready_observed_facts()?;
      Self::from_observed(identity, observed)
    }

    fn from_observed(
      identity: &CandidateLstatProtocolIdentity,
      observed: CandidateReadyObservedFacts,
    ) -> Result<Self, CandidateReadyPreflightRefusal> {
      let value = candidate_ready_value(identity, &observed);
      let raw_bytes = deno_permissions::rev2::canonical_json(&value)
        .map(String::into_bytes)
        .map_err(|_| CandidateReadyPreflightRefusal::CanonicalFrame)?;
      let reparsed = parse_canonical_jcs(&raw_bytes)
        .map_err(|_| CandidateReadyPreflightRefusal::CanonicalFrame)?;
      let validated_facts = validate_ready(&reparsed, identity)
        .map_err(|_| CandidateReadyPreflightRefusal::CanonicalFrame)?;
      Ok(Self {
        raw_bytes,
        validated_facts,
      })
    }

    fn raw_bytes(&self) -> &[u8] {
      &self.raw_bytes
    }
  }

  #[derive(Clone, Debug, Eq, PartialEq)]
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

  /// A non-cloneable, opaque prepared request. It owns the exact generated
  /// identity seal, the consumed ready preflight, both transferred rights,
  /// and the reconstructed descriptor-slot artifact. It can only be consumed
  /// by the dormant D3 equality join; it has no arena-write, response, send,
  /// oracle, evidence, policy, admission, or authority method.
  ///
  /// @ref LLP 0019#pre-promotion-conformance-candidate-execution
  /// [constrained-by] — Descriptor reconstruction and exact generated
  /// topology checks prepare one request; they do not authorize or perform
  /// the native operation.
  pub(crate) struct CandidatePreparedLstatRequest {
    _endpoint: FramedStreamEndpoint,
    _identity: CandidateLstatProtocolIdentity,
    _ready_raw_bytes: Vec<u8>,
    _ready_facts: CandidateReadyFacts,
    _binding: CandidateCaseBinding,
    _request_metadata: Arc<CandidateLstatRequestMetadata>,
    _project_root: OwnedFd,
    _arena: OwnedFd,
    _descriptor_slots_raw_bytes: Vec<u8>,
    _descriptor_slots_digest: String,
    _captured_umask: u64,
    _session_deadline: CandidateSessionDeadline,
  }

  /// A consumed D1 request joined to exactly one completed D2 public-op
  /// execution. The original FD 3 endpoint and original arena remain owned
  /// here for a later output checkpoint; the project-root descriptor has
  /// already been consumed and dropped by D2. This type exposes no arena
  /// write, artifact serialization, response, send, oracle, evidence, policy,
  /// admission, or authority method.
  ///
  /// @ref LLP 0019#pre-promotion-conformance-candidate-execution
  /// [constrained-by] — This is only a production-uncalled equality and
  /// ownership join between two dormant candidate checkpoints.
  /// @ref LLP 0019#parentsupervisor-transport-and-single-process-lifetime-cell
  /// [constrained-by] — The endpoint and arena remain unconsumed; D3 emits no
  /// packet and writes no arena byte.
  pub(crate) struct CandidateExecutedLstatRequest {
    _endpoint: FramedStreamEndpoint,
    _identity: CandidateLstatProtocolIdentity,
    _ready_raw_bytes: Vec<u8>,
    _ready_facts: CandidateReadyFacts,
    _binding: CandidateCaseBinding,
    _request_metadata: Arc<CandidateLstatRequestMetadata>,
    _arena: File,
    _descriptor_slots_raw_bytes: Vec<u8>,
    _descriptor_slots_digest: String,
    _captured_umask: u64,
    _session_deadline: CandidateSessionDeadline,
    _artifacts: deno_permissions::OdenRev2LstatCandidateArtifacts,
  }

  impl CandidatePreparedLstatRequest {
    /// Consume one prepared request through the exact D2 public-op capsule.
    /// There is deliberately no production caller while `CANDIDATE_CASES`
    /// remains empty.
    ///
    /// @ref LLP 0019#pre-promotion-conformance-candidate-execution
    /// [constrained-by]
    #[allow(dead_code)]
    pub(crate) fn execute_lstat_candidate(
      self,
      requested_deadline: Instant,
    ) -> io::Result<CandidateExecutedLstatRequest> {
      self.execute_lstat_candidate_with_hook(requested_deadline, |_| Ok(()))
    }

    fn execute_lstat_candidate_with_hook<F>(
      self,
      requested_deadline: Instant,
      after_execution: F,
    ) -> io::Result<CandidateExecutedLstatRequest>
    where
      F: FnOnce(&File) -> io::Result<()>,
    {
      let effective_deadline = self._session_deadline.effective(
        requested_deadline,
        CandidateDeadlineCheckpoint::ExecutionStart,
      )?;
      validate_prepared_execution_relation(
        &self._identity,
        &self._binding,
        &self._request_metadata,
        &self._descriptor_slots_raw_bytes,
        &self._descriptor_slots_digest,
      )?;
      let (reconstructed_bytes, reconstructed_digest) =
        reconstruct_descriptor_slots(
          &self._identity,
          &self._binding,
          self._project_root.as_fd(),
          self._arena.as_fd(),
          &self._session_deadline,
          effective_deadline,
          || Ok(()),
        )?;
      if reconstructed_bytes != self._descriptor_slots_raw_bytes
        || reconstructed_digest != self._descriptor_slots_digest
      {
        return Err(invalid_data(
          "candidate prepared descriptors changed before execution",
        ));
      }

      let CandidatePreparedLstatRequest {
        _endpoint: endpoint,
        _identity: identity,
        _ready_raw_bytes: ready_raw_bytes,
        _ready_facts: ready_facts,
        _binding: binding,
        _request_metadata: request_metadata,
        _project_root: project_root,
        _arena: arena,
        _descriptor_slots_raw_bytes: descriptor_slots_raw_bytes,
        _descriptor_slots_digest: descriptor_slots_digest,
        _captured_umask: captured_umask,
        _session_deadline: session_deadline,
      } = self;
      let project_root = File::from(project_root);
      let arena = File::from(arena);
      require_cloexec(project_root.as_fd())?;
      require_cloexec(arena.as_fd())?;
      let arena_raw_fd = arena.as_raw_fd();
      let arena_snapshot = CandidateDescriptorSnapshot::capture(arena.as_fd())?;
      let arena_status_flags = descriptor_status_flags(arena.as_fd())?;
      let execution_arena = arena.try_clone()?;
      require_cloexec(execution_arena.as_fd())?;
      if execution_arena.as_raw_fd() == arena_raw_fd
        || CandidateDescriptorSnapshot::capture(execution_arena.as_fd())?
          != arena_snapshot
        || descriptor_status_flags(execution_arena.as_fd())?
          != arena_status_flags
      {
        return Err(invalid_data(
          "candidate execution arena duplicate is not exact",
        ));
      }

      let capsule = deno_permissions::oden_capsec_rev2_prepare_lstat_candidate(
        &identity.fixture_artifact_digest,
        identity.case.case_id(),
        project_root,
        execution_arena,
      )
      .map_err(|_| {
        invalid_data("candidate prepared request was refused by D2")
      })?;
      let artifacts =
        deno_runtime::deno_fs::oden_capsec_rev2_execute_lstat_candidate(
          capsule,
        )
        .map_err(|_| {
          invalid_data("candidate D2 public-op execution refused")
        })?;
      after_execution(&arena)?;
      session_deadline.check(
        effective_deadline,
        CandidateDeadlineCheckpoint::ExecutionComplete,
      )?;
      validate_prepared_execution_relation(
        &identity,
        &binding,
        &request_metadata,
        &descriptor_slots_raw_bytes,
        &descriptor_slots_digest,
      )?;
      require_cloexec(arena.as_fd())?;
      if arena.as_raw_fd() != arena_raw_fd
        || CandidateDescriptorSnapshot::capture(arena.as_fd())?
          != arena_snapshot
        || descriptor_status_flags(arena.as_fd())? != arena_status_flags
      {
        return Err(invalid_data(
          "candidate retained arena changed during execution",
        ));
      }
      require_zero_filled_arena(
        arena.as_fd(),
        &session_deadline,
        effective_deadline,
      )?;

      Ok(CandidateExecutedLstatRequest {
        _endpoint: endpoint,
        _identity: identity,
        _ready_raw_bytes: ready_raw_bytes,
        _ready_facts: ready_facts,
        _binding: binding,
        _request_metadata: request_metadata,
        _arena: arena,
        _descriptor_slots_raw_bytes: descriptor_slots_raw_bytes,
        _descriptor_slots_digest: descriptor_slots_digest,
        _captured_umask: captured_umask,
        _session_deadline: session_deadline,
        _artifacts: artifacts,
      })
    }
  }

  fn validate_prepared_execution_relation(
    identity: &CandidateLstatProtocolIdentity,
    binding: &CandidateCaseBinding,
    request_metadata: &Arc<CandidateLstatRequestMetadata>,
    descriptor_slots_raw_bytes: &[u8],
    descriptor_slots_digest: &str,
  ) -> io::Result<()> {
    identity.require_exact_execution_join()?;
    if Arc::strong_count(request_metadata) != 1 {
      return Err(invalid_data(
        "candidate prepared request metadata is not uniquely owned",
      ));
    }
    let request_value = parse_canonical_jcs(&request_metadata.raw_bytes)?;
    let request_frame_digest = raw_frame_digest(
      CANDIDATE_REQUEST_DIGEST_DOMAIN,
      &request_metadata.raw_bytes,
    );
    let revalidated_binding =
      validate_request(&request_value, identity, request_frame_digest.clone())?;
    if request_frame_digest != request_metadata.request_frame_digest
      || request_metadata.descriptor_slots_digest != descriptor_slots_digest
      || revalidated_binding != *binding
      || binding.request_frame_digest != request_frame_digest
      || binding.descriptor_slots_digest != descriptor_slots_digest
    {
      return Err(invalid_data(
        "candidate prepared request relation is not exact",
      ));
    }
    let descriptor_slots = parse_canonical_jcs(descriptor_slots_raw_bytes)?;
    let recomputed_descriptor_slots_digest =
      deno_permissions::rev2::hjcs_digest(
        DESCRIPTOR_SLOTS_DIGEST_DOMAIN,
        &descriptor_slots,
      )
      .map_err(|_| invalid_data("candidate descriptor slots are not exact"))?;
    if recomputed_descriptor_slots_digest != descriptor_slots_digest
      || descriptor_slots.get("schema")
        != Some(&Value::String(DESCRIPTOR_SLOTS_SCHEMA.to_string()))
    {
      return Err(invalid_data(
        "candidate descriptor-slot digest is not exact",
      ));
    }
    Ok(())
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
  /// This is deliberately only a protocol dependency. Its constructors and
  /// prepared-request transition have no production caller, it never creates
  /// an `OpState`, and it cannot call the dormant public-op capsule. Its
  /// absolute deadline is frozen at construction; per-transition deadlines
  /// can only shorten it. Any error is sticky: the endpoint and all
  /// session-owned received rights are closed and no later transition is
  /// possible.
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
    ready_raw_bytes: Option<Vec<u8>>,
    ready_from_preflight: bool,
    case_binding: Option<CandidateCaseBinding>,
    retained_request: Option<CandidateRetainedLstatRequest>,
  }

  impl CandidateFd3Session {
    pub(crate) fn begin_from_preflight(
      endpoint: FramedStreamEndpoint,
      identity: CandidateLstatProtocolIdentity,
      preflight: CandidateReadyPreflight,
      absolute_deadline: Instant,
    ) -> io::Result<Self> {
      let mut session = Self::new(endpoint, identity, absolute_deadline);
      session.send_ready_preflight(preflight, absolute_deadline)?;
      Ok(session)
    }

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
        ready_raw_bytes: None,
        ready_from_preflight: false,
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
      self.ready_raw_bytes = Some(raw_bytes.to_vec());
      self.state = CandidateFd3State::RequestPending;
      Ok(())
    }

    fn send_ready_preflight(
      &mut self,
      preflight: CandidateReadyPreflight,
      requested_deadline: Instant,
    ) -> io::Result<()> {
      let reparsed = match parse_canonical_jcs(&preflight.raw_bytes) {
        Ok(value) => value,
        Err(error) => return self.refuse(error),
      };
      let revalidated = match validate_ready(&reparsed, &self.identity) {
        Ok(facts) => facts,
        Err(error) => return self.refuse(error),
      };
      if revalidated != preflight.validated_facts {
        return self.refuse(invalid_data(
          "candidate ready preflight facts changed before FD3 send",
        ));
      }
      let expected_control_identity =
        revalidated.pre_request_fd_inventory[3]["platformIdentity"]["value"]
          .as_str()
          .ok_or_else(|| {
            invalid_data(
              "candidate ready preflight omitted its control identity",
            )
          });
      let expected_control_identity = match expected_control_identity {
        Ok(identity) => identity,
        Err(error) => return self.refuse(error),
      };
      let before_control_identity = match self
        .endpoint()
        .and_then(|endpoint| inspect_candidate_control_fd(endpoint.as_fd()))
      {
        Ok(identity) => identity,
        Err(error) => return self.refuse(error),
      };
      if before_control_identity != expected_control_identity {
        return self.refuse(invalid_data(
          "candidate ready preflight does not bind the consumed FD3 endpoint",
        ));
      }
      self.send_ready(&preflight.raw_bytes, requested_deadline)?;
      let after_control_identity = match self
        .endpoint()
        .and_then(|endpoint| inspect_candidate_control_fd(endpoint.as_fd()))
      {
        Ok(identity) => identity,
        Err(error) => return self.refuse(error),
      };
      if after_control_identity != before_control_identity {
        return self.refuse(invalid_data(
          "candidate FD3 endpoint changed while sending ready preflight",
        ));
      }
      self.ready_from_preflight = true;
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

    pub(crate) fn receive_prepared_request(
      self,
      requested_deadline: Instant,
    ) -> io::Result<CandidatePreparedLstatRequest> {
      self.receive_prepared_request_with_umask_observer_and_hook(
        requested_deadline,
        capture_inherited_umask,
        || Ok(()),
      )
    }

    #[cfg(test)]
    fn receive_prepared_request_with_observed_umask_and_hook<F>(
      self,
      requested_deadline: Instant,
      captured_umask: u64,
      between_observations: F,
    ) -> io::Result<CandidatePreparedLstatRequest>
    where
      F: FnOnce() -> io::Result<()>,
    {
      self.receive_prepared_request_with_umask_observer_and_hook(
        requested_deadline,
        move || CandidateCapturedUmask::from_observed_for_test(captured_umask),
        between_observations,
      )
    }

    fn receive_prepared_request_with_umask_observer_and_hook<U, F>(
      mut self,
      requested_deadline: Instant,
      observe_umask: U,
      between_observations: F,
    ) -> io::Result<CandidatePreparedLstatRequest>
    where
      U: FnOnce() -> CandidateCapturedUmask,
      F: FnOnce() -> io::Result<()>,
    {
      if !self.ready_from_preflight
        || self.ready_facts.is_none()
        || self.ready_raw_bytes.is_none()
      {
        return self.refuse(invalid_input(
          "candidate prepared request requires a consumed ready preflight",
        ));
      }
      let request = match self.receive_request(requested_deadline) {
        Ok(request) => request,
        Err(error) => return Err(error),
      };
      let captured_umask = observe_umask();
      if captured_umask.value() != REQUIRED_CAPTURED_UMASK {
        return self.refuse(invalid_data(
          "candidate inherited umask is not exactly 0077",
        ));
      }
      let reconstruction_deadline = match self.deadline.effective(
        requested_deadline,
        CandidateDeadlineCheckpoint::CpuValidationStart,
      ) {
        Ok(deadline) => deadline,
        Err(error) => return self.refuse(error),
      };
      let retained_metadata = &self
        .retained_request
        .as_ref()
        .expect("accepted request retains transferred rights")
        .metadata;
      if !Arc::ptr_eq(&request.metadata, retained_metadata) {
        return self.refuse(invalid_input(
          "candidate prepared request identity does not own retained rights",
        ));
      }
      let reconstruction = {
        let retained = self
          .retained_request
          .as_ref()
          .expect("accepted request retains transferred rights");
        let binding = self
          .case_binding
          .as_ref()
          .expect("accepted request retains its exact binding");
        reconstruct_descriptor_slots(
          &self.identity,
          binding,
          retained.project_root.as_fd(),
          retained.arena.as_fd(),
          &self.deadline,
          reconstruction_deadline,
          between_observations,
        )
      };
      let (descriptor_slots_raw_bytes, descriptor_slots_digest) =
        match reconstruction {
          Ok(reconstruction) => reconstruction,
          Err(error) => return self.refuse(error),
        };
      if request.descriptor_slots_digest() != descriptor_slots_digest {
        return self.refuse(invalid_data(
          "candidate reconstructed descriptor slots do not match request",
        ));
      }
      drop(request);

      let endpoint = self
        .endpoint
        .take()
        .expect("prepared request retains its FD3 endpoint");
      let ready_raw_bytes = self
        .ready_raw_bytes
        .take()
        .expect("prepared request retains exact ready bytes");
      let ready_facts = self
        .ready_facts
        .take()
        .expect("prepared request retains exact ready facts");
      let binding = self
        .case_binding
        .take()
        .expect("prepared request retains exact case binding");
      let retained = self
        .retained_request
        .take()
        .expect("prepared request retains transferred rights");
      self.state = CandidateFd3State::Complete;
      Ok(CandidatePreparedLstatRequest {
        _endpoint: endpoint,
        _identity: self.identity,
        _ready_raw_bytes: ready_raw_bytes,
        _ready_facts: ready_facts,
        _binding: binding,
        _request_metadata: retained.metadata,
        _project_root: retained.project_root,
        _arena: retained.arena,
        _descriptor_slots_raw_bytes: descriptor_slots_raw_bytes,
        _descriptor_slots_digest: descriptor_slots_digest,
        _captured_umask: captured_umask.value(),
        _session_deadline: self.deadline,
      })
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
      self.ready_raw_bytes.take();
      self.ready_from_preflight = false;
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

  fn candidate_ready_value(
    identity: &CandidateLstatProtocolIdentity,
    observed: &CandidateReadyObservedFacts,
  ) -> Value {
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
      "candidatePid": observed.candidate_pid,
      "candidatePgid": observed.candidate_pgid,
      "candidateStartIdentity": observed.candidate_start_identity,
      "identities": observed.identities,
      "processLimitReadback": observed.process_limit_readback,
      "preRequestFdInventory": observed.pre_request_fd_inventory,
      "platformState": observed.platform_state,
    })
  }

  #[cfg(target_os = "macos")]
  fn collect_current_ready_observed_facts()
  -> Result<CandidateReadyObservedFacts, CandidateReadyPreflightRefusal> {
    // SAFETY: these identity syscalls take no pointers and cannot fail.
    let candidate_pid = unsafe { libc::getpid() };
    // SAFETY: same as getpid.
    let parent_pid = unsafe { libc::getppid() };
    // SAFETY: getpgrp takes no arguments and cannot fail.
    let candidate_pgid = unsafe { libc::getpgrp() };
    if candidate_pid <= 0 || parent_pid <= 0 || candidate_pgid <= 0 {
      return Err(CandidateReadyPreflightRefusal::ProcessIdentity);
    }
    let process = observe_blocked_child(candidate_pid, parent_pid)
      .map_err(|_| CandidateReadyPreflightRefusal::ProcessIdentity)?;
    if process.pid != candidate_pid
      || process.parent_pid != parent_pid
      || process.pgid != candidate_pgid
      || !is_canonical_identifier(&process.start_identity)
    {
      return Err(CandidateReadyPreflightRefusal::ProcessIdentity);
    }

    let credentials = ProcessCredentials::read_own()
      .map_err(|_| CandidateReadyPreflightRefusal::ProcessCredentials)?;
    if process.real_uid != credentials.real_uid
      || process.saved_uid != credentials.saved_uid
    {
      return Err(CandidateReadyPreflightRefusal::ProcessCredentials);
    }
    let identities = credentials
      .to_identities_value()
      .ok_or(CandidateReadyPreflightRefusal::ProcessCredentials)?;
    let process_limit_readback = read_zero_process_limit()
      .map_err(|_| CandidateReadyPreflightRefusal::ProcessLimit)?;
    let pre_request_fd_inventory = collect_exact_candidate_fd_inventory()
      .map_err(|_| CandidateReadyPreflightRefusal::DescriptorInventory)?;
    let platform_state =
      macos_platform_state_value(CANDIDATE_MACOS_SEATBELT_DISPOSITION)
        .ok_or(CandidateReadyPreflightRefusal::PlatformState)?;

    Ok(CandidateReadyObservedFacts {
      candidate_pid: candidate_pid.to_string(),
      candidate_pgid: candidate_pgid.to_string(),
      candidate_start_identity: process.start_identity,
      identities,
      process_limit_readback,
      pre_request_fd_inventory,
      platform_state,
    })
  }

  #[cfg(target_os = "linux")]
  fn collect_current_ready_observed_facts()
  -> Result<CandidateReadyObservedFacts, CandidateReadyPreflightRefusal> {
    // The current fork has no candidate-role seccomp installer or retained
    // profile digest and therefore cannot honestly produce the required Linux
    // ready state. Do not substitute caller data or a syntactically valid
    // digest for that missing native fact.
    Err(CandidateReadyPreflightRefusal::LinuxContainmentUnavailable)
  }

  #[cfg(not(any(target_os = "macos", target_os = "linux")))]
  fn collect_current_ready_observed_facts()
  -> Result<CandidateReadyObservedFacts, CandidateReadyPreflightRefusal> {
    Err(CandidateReadyPreflightRefusal::UnsupportedTarget)
  }

  #[cfg(target_os = "macos")]
  fn read_zero_process_limit() -> io::Result<Value> {
    // SAFETY: zero is a valid initial representation for rlimit.
    let mut limit: libc::rlimit = unsafe { std::mem::zeroed() };
    // SAFETY: limit is writable storage for the requested resource.
    if unsafe { libc::getrlimit(libc::RLIMIT_NPROC, &mut limit) } != 0 {
      return Err(io::Error::last_os_error());
    }
    if limit.rlim_cur != 0 || limit.rlim_max != 0 {
      return Err(invalid_data(
        "candidate process limit is not irreversibly zero",
      ));
    }
    Ok(json!({ "soft": "0", "hard": "0" }))
  }

  #[cfg(target_os = "macos")]
  fn collect_exact_candidate_fd_inventory() -> io::Result<Value> {
    require_exact_macos_fd_numbers()?;
    let prepared_control_identity =
      prepare_candidate_control_fd(CANDIDATE_CONTROL_FD)?;
    require_exact_macos_fd_numbers()?;
    let before = snapshot_candidate_fd_inventory()?;
    if before[3]["platformIdentity"]["value"]
      != Value::String(prepared_control_identity)
    {
      return Err(invalid_data(
        "candidate control descriptor identity changed after preparation",
      ));
    }
    require_exact_macos_fd_numbers()?;
    let after = snapshot_candidate_fd_inventory()?;
    require_exact_macos_fd_numbers()?;
    if before != after {
      return Err(invalid_data(
        "candidate descriptor inventory changed during ready preflight",
      ));
    }
    Ok(before)
  }

  #[cfg(target_os = "macos")]
  fn require_exact_macos_fd_numbers() -> io::Result<()> {
    const MAX_OBSERVED_FDS: usize = 8;
    // SAFETY: zero is a valid initial representation for this plain C array.
    let mut entries: [libc::proc_fdinfo; MAX_OBSERVED_FDS] =
      unsafe { std::mem::zeroed() };
    let byte_capacity = std::mem::size_of_val(&entries);
    let byte_capacity = libc::c_int::try_from(byte_capacity)
      .map_err(|_| invalid_data("candidate descriptor scan bound overflow"))?;
    // SAFETY: entries is writable for byte_capacity bytes and the flavor
    // returns a dense array of proc_fdinfo records.
    let written = unsafe {
      libc::proc_pidinfo(
        libc::getpid(),
        libc::PROC_PIDLISTFDS,
        0,
        entries.as_mut_ptr().cast(),
        byte_capacity,
      )
    };
    let record_size = std::mem::size_of::<libc::proc_fdinfo>() as libc::c_int;
    if written < 0
      || written % record_size != 0
      || written as usize >= byte_capacity as usize
    {
      return Err(invalid_data(
        "candidate descriptor scan was refused or truncated",
      ));
    }
    let count = usize::try_from(written / record_size)
      .map_err(|_| invalid_data("candidate descriptor count is invalid"))?;
    let mut fds = entries[..count]
      .iter()
      .map(|entry| entry.proc_fd)
      .collect::<Vec<_>>();
    fds.sort_unstable();
    if fds.as_slice() != [0, 1, 2, CANDIDATE_CONTROL_FD] {
      return Err(invalid_data(
        "candidate inherited descriptors are not exactly 0,1,2,3",
      ));
    }
    Ok(())
  }

  #[cfg(target_os = "macos")]
  fn prepare_candidate_control_fd(fd: RawFd) -> io::Result<String> {
    // SAFETY: the caller's exact descriptor scan proved this raw descriptor
    // live, and this function neither closes nor transfers it.
    let before_identity =
      inspect_candidate_control_fd(unsafe { BorrowedFd::borrow_raw(fd) })?;
    let descriptor_flags = get_fcntl_flags(fd, libc::F_GETFD)?;
    if descriptor_flags & libc::FD_CLOEXEC == 0 {
      set_fcntl_flags(fd, libc::F_SETFD, descriptor_flags | libc::FD_CLOEXEC)?;
    }
    let status_flags = get_fcntl_flags(fd, libc::F_GETFL)?;
    if status_flags & libc::O_NONBLOCK == 0 {
      set_fcntl_flags(fd, libc::F_SETFL, status_flags | libc::O_NONBLOCK)?;
    }
    let descriptor_flags = get_fcntl_flags(fd, libc::F_GETFD)?;
    let status_flags = get_fcntl_flags(fd, libc::F_GETFL)?;
    if descriptor_flags & libc::FD_CLOEXEC == 0
      || status_flags & libc::O_NONBLOCK == 0
    {
      return Err(invalid_data(
        "candidate control descriptor flags did not become exact",
      ));
    }
    // SAFETY: the descriptor remains live; the surrounding exact scans and
    // this identity comparison refuse replacement across flag preparation.
    let after_identity =
      inspect_candidate_control_fd(unsafe { BorrowedFd::borrow_raw(fd) })?;
    if before_identity != after_identity {
      return Err(invalid_data(
        "candidate control descriptor changed during preparation",
      ));
    }
    Ok(after_identity)
  }

  #[cfg(target_os = "macos")]
  fn get_fcntl_flags(
    fd: RawFd,
    command: libc::c_int,
  ) -> io::Result<libc::c_int> {
    loop {
      // SAFETY: command is a no-argument fcntl getter for the supplied raw fd.
      let result = unsafe { libc::fcntl(fd, command) };
      if result >= 0 {
        return Ok(result);
      }
      let error = io::Error::last_os_error();
      if error.kind() != io::ErrorKind::Interrupted {
        return Err(error);
      }
    }
  }

  #[cfg(target_os = "macos")]
  fn set_fcntl_flags(
    fd: RawFd,
    command: libc::c_int,
    flags: libc::c_int,
  ) -> io::Result<()> {
    loop {
      // SAFETY: command is the matching integer fcntl setter for the supplied
      // raw fd; flags came from the corresponding getter plus one known bit.
      let result = unsafe { libc::fcntl(fd, command, flags) };
      if result == 0 {
        return Ok(());
      }
      let error = io::Error::last_os_error();
      if error.kind() != io::ErrorKind::Interrupted {
        return Err(error);
      }
    }
  }

  #[cfg(target_os = "macos")]
  fn snapshot_candidate_fd_inventory() -> io::Result<Value> {
    let mut borrowed = Vec::with_capacity(4);
    for fd in [0, 1, 2, CANDIDATE_CONTROL_FD] {
      // SAFETY: the exact descriptor scan immediately before this call proved
      // these four raw numbers are live. The borrow does not take ownership.
      borrowed.push(unsafe { BorrowedFd::borrow_raw(fd) });
    }
    for (index, descriptor) in borrowed.iter().enumerate() {
      let stat = fstat(*descriptor)?;
      let descriptor_flags = get_fcntl_flags(index as RawFd, libc::F_GETFD)?;
      let expected_kind = if index == CANDIDATE_CONTROL_FD as usize {
        libc::S_IFSOCK
      } else {
        libc::S_IFCHR
      };
      let expected_cloexec = index == CANDIDATE_CONTROL_FD as usize;
      if stat.st_mode & libc::S_IFMT != expected_kind
        || (descriptor_flags & libc::FD_CLOEXEC != 0) != expected_cloexec
      {
        return Err(invalid_data(
          "candidate descriptor kind or close-on-exec state is not exact",
        ));
      }
    }
    let inspected_control_identity = inspect_candidate_control_fd(borrowed[3])?;
    let entries = candidate_fd_inventory(
      borrowed[0],
      borrowed[1],
      borrowed[2],
      borrowed[3],
    )?;
    let value = Value::Array(
      entries
        .iter()
        .map(crate::oden_capsec_filesystem_parent::FdInventoryEntry::to_value)
        .collect(),
    );
    if value[3]["platformIdentity"]["value"]
      != Value::String(inspected_control_identity)
    {
      return Err(invalid_data(
        "candidate control descriptor inventory identity is inexact",
      ));
    }
    let control_identity = &value[3]["platformIdentity"];
    if (0..3).any(|index| &value[index]["platformIdentity"] == control_identity)
    {
      return Err(invalid_data(
        "candidate control descriptor aliases a standard stream",
      ));
    }
    Ok(value)
  }

  #[cfg(any(target_os = "linux", target_os = "macos"))]
  fn inspect_candidate_control_fd(
    descriptor: BorrowedFd<'_>,
  ) -> io::Result<String> {
    let stat = fstat(descriptor)?;
    if stat.st_mode & libc::S_IFMT != libc::S_IFSOCK {
      return Err(invalid_data("candidate control descriptor is not a socket"));
    }
    require_unix_stream_socket(descriptor)?;
    Ok(format!(
      "unix-dev-ino:{:016x}{:016x}",
      stat.st_dev as u64, stat.st_ino as u64
    ))
  }

  #[cfg(not(any(target_os = "linux", target_os = "macos")))]
  fn inspect_candidate_control_fd(
    _descriptor: BorrowedFd<'_>,
  ) -> io::Result<String> {
    Err(invalid_data(
      "candidate control descriptor target is unsupported",
    ))
  }

  #[cfg(any(target_os = "linux", target_os = "macos"))]
  fn require_unix_stream_socket(descriptor: BorrowedFd<'_>) -> io::Result<()> {
    let mut socket_type: libc::c_int = 0;
    let mut socket_type_len =
      std::mem::size_of_val(&socket_type) as libc::socklen_t;
    // SAFETY: socket_type and its length are valid output storage.
    if unsafe {
      libc::getsockopt(
        descriptor.as_raw_fd(),
        libc::SOL_SOCKET,
        libc::SO_TYPE,
        std::ptr::from_mut(&mut socket_type).cast(),
        &mut socket_type_len,
      )
    } != 0
      || socket_type_len as usize != std::mem::size_of_val(&socket_type)
      || socket_type != libc::SOCK_STREAM
    {
      return Err(invalid_data(
        "candidate control descriptor is not a stream socket",
      ));
    }
    // SAFETY: zero is a valid initial representation for sockaddr_storage.
    let mut address: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut address_len = std::mem::size_of_val(&address) as libc::socklen_t;
    // SAFETY: address and its length are valid output storage.
    if unsafe {
      libc::getsockname(
        descriptor.as_raw_fd(),
        std::ptr::from_mut(&mut address).cast(),
        &mut address_len,
      )
    } != 0
      || address_len < std::mem::size_of::<libc::sa_family_t>() as _
      || address.ss_family as libc::c_int != libc::AF_UNIX
    {
      return Err(invalid_data(
        "candidate control descriptor is not an AF_UNIX socket",
      ));
    }
    // A listener or otherwise unconnected stream is not the inherited
    // socketpair endpoint required by the candidate protocol.
    // SAFETY: zero is a valid initial representation for sockaddr_storage.
    let mut peer_address: libc::sockaddr_storage =
      unsafe { std::mem::zeroed() };
    let mut peer_address_len =
      std::mem::size_of_val(&peer_address) as libc::socklen_t;
    // SAFETY: peer_address and its length are valid output storage.
    if unsafe {
      libc::getpeername(
        descriptor.as_raw_fd(),
        std::ptr::from_mut(&mut peer_address).cast(),
        &mut peer_address_len,
      )
    } != 0
      || peer_address_len < std::mem::size_of::<libc::sa_family_t>() as _
      || peer_address.ss_family as libc::c_int != libc::AF_UNIX
    {
      return Err(invalid_data(
        "candidate control descriptor has no connected AF_UNIX peer",
      ));
    }
    Ok(())
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
      require_exact_root_status_flags(descriptors[0].as_fd())?;
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

  fn descriptor_status_flags(
    descriptor: BorrowedFd<'_>,
  ) -> io::Result<libc::c_int> {
    loop {
      // SAFETY: F_GETFL only reads status flags from the live descriptor.
      let flags = unsafe { libc::fcntl(descriptor.as_raw_fd(), libc::F_GETFL) };
      if flags >= 0 {
        return Ok(flags);
      }
      let error = io::Error::last_os_error();
      if error.kind() != io::ErrorKind::Interrupted {
        return Err(error);
      }
    }
  }

  fn require_exact_root_status_flags(
    descriptor: BorrowedFd<'_>,
  ) -> io::Result<libc::c_int> {
    let flags = descriptor_status_flags(descriptor)?;
    #[cfg(target_os = "linux")]
    let path_only = flags & libc::O_PATH != 0;
    #[cfg(not(target_os = "linux"))]
    let path_only = false;
    #[cfg(target_os = "macos")]
    let alternate_only = flags & (libc::O_EVTONLY | libc::O_EXEC) != 0;
    #[cfg(not(target_os = "macos"))]
    let alternate_only = false;
    if flags & libc::O_ACCMODE != libc::O_RDONLY
      || flags & libc::O_APPEND != 0
      || path_only
      || alternate_only
    {
      return Err(invalid_data(
        "candidate project-root right is not exact read-only directory access",
      ));
    }
    Ok(flags)
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

  struct CandidateCapturedUmask {
    value: u64,
  }

  impl CandidateCapturedUmask {
    fn value(&self) -> u64 {
      self.value
    }

    #[cfg(test)]
    fn from_observed_for_test(value: u64) -> Self {
      Self { value }
    }
  }

  fn capture_inherited_umask() -> CandidateCapturedUmask {
    // SAFETY: umask takes and returns a value, touches no caller memory, and
    // setting the already-required 0077 value leaves a conforming process
    // unchanged while making a nonconforming process fail closed.
    let value =
      unsafe { libc::umask(REQUIRED_CAPTURED_UMASK as libc::mode_t) as u64 };
    CandidateCapturedUmask { value }
  }

  #[cfg(any(target_os = "linux", target_os = "macos"))]
  #[derive(Clone, Debug, Eq, PartialEq)]
  struct CandidateDescriptorSnapshot {
    device: u64,
    inode: u64,
    mode: u32,
    links: u64,
    uid: u64,
    gid: u64,
    size: i64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
    #[cfg(target_os = "macos")]
    generation: u32,
  }

  #[cfg(any(target_os = "linux", target_os = "macos"))]
  impl CandidateDescriptorSnapshot {
    fn capture(descriptor: BorrowedFd<'_>) -> io::Result<Self> {
      let stat = fstat(descriptor)?;
      Ok(Self {
        device: stat.st_dev as u64,
        inode: stat.st_ino as u64,
        mode: stat.st_mode as u32,
        links: stat.st_nlink as u64,
        uid: stat.st_uid as u64,
        gid: stat.st_gid as u64,
        size: stat.st_size as i64,
        modified_seconds: stat.st_mtime as i64,
        modified_nanoseconds: stat.st_mtime_nsec as i64,
        changed_seconds: stat.st_ctime as i64,
        changed_nanoseconds: stat.st_ctime_nsec as i64,
        #[cfg(target_os = "macos")]
        generation: stat.st_gen,
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

  #[cfg(any(target_os = "linux", target_os = "macos"))]
  #[derive(Debug, Eq, PartialEq)]
  struct CandidateLstatTopologyObservation {
    root_empty: bool,
    source: Option<CandidateDescriptorSnapshot>,
  }

  #[cfg(any(target_os = "linux", target_os = "macos"))]
  struct CandidateDirectoryStream {
    raw: *mut libc::DIR,
  }

  #[cfg(any(target_os = "linux", target_os = "macos"))]
  impl CandidateDirectoryStream {
    fn from_owned(descriptor: OwnedFd) -> io::Result<Self> {
      let raw_descriptor = descriptor.into_raw_fd();
      // SAFETY: raw_descriptor is a uniquely owned independent directory
      // description. fdopendir takes ownership only on success.
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
      // SAFETY: raw is the live stream uniquely owned by this value.
      if unsafe { libc::closedir(raw) } != 0 {
        return Err(io::Error::last_os_error());
      }
      Ok(())
    }
  }

  #[cfg(any(target_os = "linux", target_os = "macos"))]
  impl Drop for CandidateDirectoryStream {
    fn drop(&mut self) {
      if !self.raw.is_null() {
        // SAFETY: this is the error-path close of the uniquely owned stream.
        unsafe { libc::closedir(self.raw) };
        self.raw = std::ptr::null_mut();
      }
    }
  }

  #[cfg(target_os = "linux")]
  fn clear_candidate_readdir_errno() {
    // SAFETY: libc exposes the calling thread's writable errno cell.
    unsafe { *libc::__errno_location() = 0 };
  }

  #[cfg(target_os = "macos")]
  fn clear_candidate_readdir_errno() {
    // SAFETY: libc exposes the calling thread's writable errno cell.
    unsafe { *libc::__error() = 0 };
  }

  #[cfg(target_os = "linux")]
  fn candidate_readdir_errno() -> libc::c_int {
    // SAFETY: libc exposes the calling thread's readable errno cell.
    unsafe { *libc::__errno_location() }
  }

  #[cfg(target_os = "macos")]
  fn candidate_readdir_errno() -> libc::c_int {
    // SAFETY: libc exposes the calling thread's readable errno cell.
    unsafe { *libc::__error() }
  }

  #[cfg(any(target_os = "linux", target_os = "macos"))]
  fn candidate_fixed_array_length<T, const N: usize>(
    _: *const [T; N],
  ) -> usize {
    N
  }

  #[cfg(target_os = "linux")]
  unsafe fn candidate_dirent_name(
    entry: *const libc::dirent,
  ) -> io::Result<Vec<u8>> {
    // SAFETY: the caller guarantees the fixed d_reclen header is accessible.
    let record_length_pointer =
      unsafe { std::ptr::addr_of!((*entry).d_reclen) };
    // SAFETY: readdir supplied the record; an unaligned read avoids forming a
    // full-size dirent reference for a short record.
    let record_length =
      unsafe { std::ptr::read_unaligned(record_length_pointer) } as usize;
    let name_offset = std::mem::offset_of!(libc::dirent, d_name);
    let record_name_bytes = record_length
      .checked_sub(name_offset)
      .ok_or_else(|| invalid_data("candidate directory entry is malformed"))?;
    // SAFETY: only the field address is formed; the slice is capped below.
    let name_array_pointer = unsafe { std::ptr::addr_of!((*entry).d_name) };
    let bound =
      record_name_bytes.min(candidate_fixed_array_length(name_array_pointer));
    // SAFETY: bound is capped by both d_reclen and the declared array.
    let name = unsafe {
      std::slice::from_raw_parts(name_array_pointer.cast::<u8>(), bound)
    };
    let name_end = name
      .iter()
      .position(|unit| *unit == 0)
      .ok_or_else(|| invalid_data("candidate directory entry is malformed"))?;
    Ok(name[..name_end].to_vec())
  }

  #[cfg(target_os = "macos")]
  unsafe fn candidate_dirent_name(
    entry: *const libc::dirent,
  ) -> io::Result<Vec<u8>> {
    // SAFETY: the caller guarantees the fixed header fields are accessible.
    let record_length_pointer =
      unsafe { std::ptr::addr_of!((*entry).d_reclen) };
    // SAFETY: same fixed-header guarantee as d_reclen.
    let name_length_pointer = unsafe { std::ptr::addr_of!((*entry).d_namlen) };
    // SAFETY: readdir supplied both values; unaligned reads avoid forming a
    // full-size dirent reference.
    let record_length =
      unsafe { std::ptr::read_unaligned(record_length_pointer) } as usize;
    // SAFETY: same fixed-header guarantee as above.
    let name_length =
      unsafe { std::ptr::read_unaligned(name_length_pointer) } as usize;
    // SAFETY: only the field address is formed; the slice is capped below.
    let name_array_pointer = unsafe { std::ptr::addr_of!((*entry).d_name) };
    let capacity = candidate_fixed_array_length(name_array_pointer);
    let name_offset = std::mem::offset_of!(libc::dirent, d_name);
    let record_name_bytes = record_length
      .checked_sub(name_offset)
      .ok_or_else(|| invalid_data("candidate directory entry is malformed"))?;
    let terminated_length = name_length
      .checked_add(1)
      .ok_or_else(|| invalid_data("candidate directory entry is malformed"))?;
    if name_length >= capacity || terminated_length > record_name_bytes {
      return Err(invalid_data("candidate directory entry is malformed"));
    }
    // SAFETY: terminated_length is within d_reclen and the fixed array.
    let name = unsafe {
      std::slice::from_raw_parts(
        name_array_pointer.cast::<u8>(),
        terminated_length,
      )
    };
    if name[name_length] != 0 || name[..name_length].contains(&0) {
      return Err(invalid_data("candidate directory entry is malformed"));
    }
    Ok(name[..name_length].to_vec())
  }

  #[cfg(any(target_os = "linux", target_os = "macos"))]
  fn open_candidate_at(
    directory: BorrowedFd<'_>,
    name: &str,
    flags: libc::c_int,
  ) -> io::Result<OwnedFd> {
    let name = CString::new(name.as_bytes())
      .map_err(|_| invalid_data("candidate generated name contains NUL"))?;
    loop {
      // SAFETY: directory is live, name is one NUL-terminated component, and
      // successful openat returns a new uniquely owned descriptor.
      let raw =
        unsafe { libc::openat(directory.as_raw_fd(), name.as_ptr(), flags) };
      if raw >= 0 {
        // SAFETY: successful openat returned a new uniquely owned descriptor.
        return Ok(unsafe { OwnedFd::from_raw_fd(raw) });
      }
      let error = io::Error::last_os_error();
      if error.kind() != io::ErrorKind::Interrupted {
        return Err(error);
      }
    }
  }

  #[cfg(any(target_os = "linux", target_os = "macos"))]
  fn scan_exact_lstat_root(
    root: BorrowedFd<'_>,
    expected_root: &CandidateDescriptorSnapshot,
    expected_source: CandidateGeneratedSourceTopology,
    session_deadline: &CandidateSessionDeadline,
    deadline: Instant,
  ) -> io::Result<CandidateLstatTopologyObservation> {
    session_deadline
      .check(deadline, CandidateDeadlineCheckpoint::CpuValidationStart)?;
    let scan_descriptor = open_candidate_at(
      root,
      ".",
      libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
    )?;
    let scan_snapshot =
      CandidateDescriptorSnapshot::capture(scan_descriptor.as_fd())?;
    if &scan_snapshot != expected_root {
      return Err(invalid_data(
        "candidate independent root scan descriptor changed identity",
      ));
    }
    let stream = CandidateDirectoryStream::from_owned(scan_descriptor)?;
    let expected_non_dot = usize::from(matches!(
      expected_source,
      CandidateGeneratedSourceTopology::ExistingEmptyFile
    ));
    let scan_result = (|| {
      let mut saw_dot = false;
      let mut saw_dot_dot = false;
      let mut non_dot = 0_usize;
      let mut records = 0_usize;
      loop {
        session_deadline
          .check(deadline, CandidateDeadlineCheckpoint::CpuValidationStart)?;
        clear_candidate_readdir_errno();
        // SAFETY: stream.raw is live and uniquely owned. The returned record
        // is copied with record bounds before the next call.
        let entry = unsafe { libc::readdir(stream.raw) };
        if entry.is_null() {
          let errno = candidate_readdir_errno();
          if errno != 0 {
            return Err(io::Error::from_raw_os_error(errno));
          }
          break;
        }
        records = records.saturating_add(1);
        if records > expected_non_dot + 2 {
          return Err(invalid_data(
            "candidate project root contains unexpected directory entries",
          ));
        }
        // SAFETY: readdir returned a record with its fixed header accessible;
        // the helper copies only record-bounded name bytes.
        let name = unsafe { candidate_dirent_name(entry) }?;
        match name.as_slice() {
          b"." if !saw_dot => saw_dot = true,
          b".." if !saw_dot_dot => saw_dot_dot = true,
          name
            if name == LSTAT_SOURCE_NAME.as_bytes()
              && matches!(
                expected_source,
                CandidateGeneratedSourceTopology::ExistingEmptyFile
              ) =>
          {
            non_dot = non_dot.saturating_add(1);
          }
          _ => {
            return Err(invalid_data(
              "candidate project root topology is not exact",
            ));
          }
        }
      }
      if !saw_dot || !saw_dot_dot || non_dot != expected_non_dot {
        return Err(invalid_data(
          "candidate project root topology is not exact",
        ));
      }
      Ok(())
    })();
    let close_result = stream.close();
    if let Err(error) = scan_result {
      let _ = close_result;
      return Err(error);
    }
    close_result?;

    let source = match expected_source {
      CandidateGeneratedSourceTopology::ExistingEmptyFile => {
        let source = open_candidate_at(
          root,
          LSTAT_SOURCE_NAME,
          libc::O_RDONLY
            | libc::O_NONBLOCK
            | libc::O_NOFOLLOW
            | libc::O_CLOEXEC,
        )
        .map_err(|_| {
          invalid_data("candidate existing lstat source could not be opened")
        })?;
        let before = CandidateDescriptorSnapshot::capture(source.as_fd())?;
        if before.mode & libc::S_IFMT as u32 != libc::S_IFREG as u32
          || before.links != 1
          || before.size != 0
          || (before.device == expected_root.device
            && before.inode == expected_root.inode)
        {
          return Err(invalid_data(
            "candidate existing lstat source is not one exact empty file",
          ));
        }
        let mut byte = 0_u8;
        let read = loop {
          session_deadline
            .check(deadline, CandidateDeadlineCheckpoint::CpuValidationStart)?;
          // SAFETY: byte is writable, source is live, and pread does not
          // change its shared file offset.
          let result = unsafe {
            libc::pread(
              source.as_raw_fd(),
              std::ptr::from_mut(&mut byte).cast(),
              1,
              0,
            )
          };
          if result >= 0 {
            break result;
          }
          let error = io::Error::last_os_error();
          if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
          }
        };
        if read != 0 {
          return Err(invalid_data(
            "candidate existing lstat source is not exactly empty",
          ));
        }
        let after = CandidateDescriptorSnapshot::capture(source.as_fd())?;
        if after != before {
          return Err(invalid_data(
            "candidate existing lstat source changed while inspected",
          ));
        }
        Some(before)
      }
      CandidateGeneratedSourceTopology::FinalMissing => {
        let result = open_candidate_at(
          root,
          LSTAT_SOURCE_NAME,
          libc::O_RDONLY
            | libc::O_NONBLOCK
            | libc::O_NOFOLLOW
            | libc::O_CLOEXEC,
        );
        match result {
          Err(error) if error.raw_os_error() == Some(libc::ENOENT) => None,
          Ok(descriptor) => {
            drop(descriptor);
            return Err(invalid_data(
              "candidate final-missing lstat source unexpectedly exists",
            ));
          }
          Err(_) => {
            return Err(invalid_data(
              "candidate final-missing lstat source is not exactly absent",
            ));
          }
        }
      }
    };
    session_deadline
      .check(deadline, CandidateDeadlineCheckpoint::CpuValidationComplete)?;
    Ok(CandidateLstatTopologyObservation {
      root_empty: expected_non_dot == 0,
      source,
    })
  }

  #[cfg(any(target_os = "linux", target_os = "macos"))]
  fn candidate_descriptor_slots_value(
    identity: &CandidateLstatProtocolIdentity,
    binding: &CandidateCaseBinding,
    root: &CandidateDescriptorSnapshot,
    arena: &CandidateDescriptorSnapshot,
    root_empty: bool,
  ) -> Value {
    json!({
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
            "value": identity.generated_topology.root_fixture_identity.value,
          },
          "platformIdentity": root.platform_identity(),
          "objectKind": "directory",
          "mode": root.mode,
          "uid": root.uid.to_string(),
          "gid": root.gid.to_string(),
          "emptyAtTransfer": root_empty,
        },
        {
          "transferIndex": 1,
          "role": "arena",
          "platformIdentity": arena.platform_identity(),
          "objectKind": "regular-file",
          "mode": arena.mode,
          "uid": arena.uid.to_string(),
          "gid": arena.gid.to_string(),
          "capacityBytes": ARENA_CAPACITY_BYTES,
          "zeroFilledAtTransfer": true,
        },
      ],
    })
  }

  #[cfg(any(target_os = "linux", target_os = "macos"))]
  fn reconstruct_descriptor_slots<F>(
    identity: &CandidateLstatProtocolIdentity,
    binding: &CandidateCaseBinding,
    root: BorrowedFd<'_>,
    arena: BorrowedFd<'_>,
    session_deadline: &CandidateSessionDeadline,
    deadline: Instant,
    between_observations: F,
  ) -> io::Result<(Vec<u8>, String)>
  where
    F: FnOnce() -> io::Result<()>,
  {
    session_deadline
      .check(deadline, CandidateDeadlineCheckpoint::CpuValidationStart)?;
    let root_before = CandidateDescriptorSnapshot::capture(root)?;
    let arena_before = CandidateDescriptorSnapshot::capture(arena)?;
    let root_flags_before = require_exact_root_status_flags(root)?;
    if root_before.mode & libc::S_IFMT as u32 != libc::S_IFDIR as u32
      || arena_before.mode & libc::S_IFMT as u32 != libc::S_IFREG as u32
      || arena_before.links != 1
      || arena_before.size != ARENA_CAPACITY_BYTES
      || (root_before.device == arena_before.device
        && root_before.inode == arena_before.inode)
    {
      return Err(invalid_data(
        "candidate descriptor-slot reconstruction has inexact rights",
      ));
    }
    // This D1 value still performs no arena write, but preparation must retain
    // only the exact read/write right required by the later, separate writer.
    let arena_flags_before = descriptor_status_flags(arena)?;
    if arena_flags_before & libc::O_ACCMODE != libc::O_RDWR
      || arena_flags_before & libc::O_APPEND != 0
    {
      return Err(invalid_data(
        "candidate arena right is not exact seekable read/write access",
      ));
    }
    require_zero_filled_arena(arena, session_deadline, deadline)?;
    let topology_before = scan_exact_lstat_root(
      root,
      &root_before,
      identity.generated_topology.expected_source,
      session_deadline,
      deadline,
    )?;
    between_observations()?;
    let topology_after = scan_exact_lstat_root(
      root,
      &root_before,
      identity.generated_topology.expected_source,
      session_deadline,
      deadline,
    )?;
    require_zero_filled_arena(arena, session_deadline, deadline)?;
    let root_after = CandidateDescriptorSnapshot::capture(root)?;
    let arena_after = CandidateDescriptorSnapshot::capture(arena)?;
    let root_flags_after = require_exact_root_status_flags(root)?;
    let arena_flags_after = descriptor_status_flags(arena)?;
    if topology_after != topology_before
      || root_after != root_before
      || arena_after != arena_before
      || root_flags_after != root_flags_before
      || arena_flags_after != arena_flags_before
    {
      return Err(invalid_data(
        "candidate descriptor topology or identity changed during preparation",
      ));
    }
    if identity.generated_topology.root_fixture_identity.kind
      != FilesystemObjectIdentityKind::OpaqueToken
      || identity.generated_topology.root_fixture_identity.value
        != LSTAT_ROOT_FIXTURE_IDENTITY
    {
      return Err(invalid_data(
        "candidate generated root fixture identity is not exact",
      ));
    }
    let value = candidate_descriptor_slots_value(
      identity,
      binding,
      &root_before,
      &arena_before,
      topology_before.root_empty,
    );
    let raw_bytes = deno_permissions::rev2::canonical_json(&value)
      .map(String::into_bytes)
      .map_err(|_| {
        invalid_data("candidate descriptor-slot artifact is not canonical")
      })?;
    let digest = deno_permissions::rev2::hjcs_digest(
      DESCRIPTOR_SLOTS_DIGEST_DOMAIN,
      &value,
    )
    .map_err(|_| {
      invalid_data("candidate descriptor-slot digest could not be derived")
    })?;
    if digest != binding.descriptor_slots_digest {
      return Err(invalid_data(
        "candidate reconstructed descriptor-slot digest is inexact",
      ));
    }
    session_deadline
      .check(deadline, CandidateDeadlineCheckpoint::CpuValidationComplete)?;
    Ok((raw_bytes, digest))
  }

  #[cfg(not(any(target_os = "linux", target_os = "macos")))]
  fn reconstruct_descriptor_slots<F>(
    _identity: &CandidateLstatProtocolIdentity,
    _binding: &CandidateCaseBinding,
    _root: BorrowedFd<'_>,
    _arena: BorrowedFd<'_>,
    _session_deadline: &CandidateSessionDeadline,
    _deadline: Instant,
    _between_observations: F,
  ) -> io::Result<(Vec<u8>, String)>
  where
    F: FnOnce() -> io::Result<()>,
  {
    Err(invalid_data(
      "candidate descriptor-slot reconstruction target is unsupported",
    ))
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

  fn is_canonical_lower_hex_sha256(value: &str) -> bool {
    value
      .strip_prefix("sha256:")
      .is_some_and(|payload| is_lower_hex(payload, 64))
  }

  fn is_canonical_engine_build_marker(value: &str) -> bool {
    value
      .strip_prefix(ENGINE_BUILD_MARKER_PREFIX)
      .is_some_and(is_canonical_sha256_digest)
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
    const BUILD_MARKER: &str =
      "oden-engine-v2-sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
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

    fn execution_session_deadline() -> Instant {
      Instant::now() + Duration::from_secs(30)
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

    fn assert_descriptor_closed(descriptor: libc::c_int) {
      // SAFETY: F_GETFD safely reports EBADF for a closed integer
      // descriptor; it does not dereference caller memory.
      let result = unsafe { libc::fcntl(descriptor, libc::F_GETFD) };
      let error = io::Error::last_os_error();
      assert_eq!(result, -1, "descriptor {descriptor} remained open");
      assert_eq!(error.raw_os_error(), Some(libc::EBADF));
    }

    fn clear_cloexec_for_test(descriptor: BorrowedFd<'_>) -> io::Result<()> {
      // SAFETY: F_GETFD and F_SETFD operate only on the supplied live
      // descriptor.
      let flags = unsafe { libc::fcntl(descriptor.as_raw_fd(), libc::F_GETFD) };
      if flags < 0
        || unsafe {
          libc::fcntl(
            descriptor.as_raw_fd(),
            libc::F_SETFD,
            flags & !libc::FD_CLOEXEC,
          )
        } < 0
      {
        return Err(io::Error::last_os_error());
      }
      Ok(())
    }

    fn identity_for(
      target: &str,
      case: CandidateLstatCase,
    ) -> CandidateLstatProtocolIdentity {
      CandidateLstatProtocolIdentity::new_test_fixture(
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

    fn native_execution_identity(
      case: CandidateLstatCase,
    ) -> CandidateLstatProtocolIdentity {
      let build_identity = current_binary_build_identity();
      let fork_commit = deno_lib::version::DENO_VERSION_INFO.git_hash;
      assert!(is_canonical_fork_commit(fork_commit));
      let generated = oden_capsec_rev2_join_lstat_candidate_binary_identity(
        &build_identity,
        FIXTURE_DIGEST,
        case.case_id(),
      )
      .unwrap();
      CandidateLstatProtocolIdentity::from_generated(
        generated,
        &build_identity,
        fork_commit,
      )
      .unwrap()
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

    fn ready_observed_facts(
      identity: &CandidateLstatProtocolIdentity,
    ) -> CandidateReadyObservedFacts {
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
      CandidateReadyObservedFacts {
        candidate_pid: "77".to_string(),
        candidate_pgid: "88".to_string(),
        candidate_start_identity: "start:test".to_string(),
        identities: json!({
          "realUid": "501",
          "effectiveUid": "501",
          "savedUid": "501",
          "realGid": "20",
          "effectiveGid": "20",
          "savedGid": "20",
        }),
        process_limit_readback: json!({
          "soft": "0",
          "hard": "0",
        }),
        pre_request_fd_inventory: json!([
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
        ]),
        platform_state,
      }
    }

    fn ready(identity: &CandidateLstatProtocolIdentity) -> Value {
      candidate_ready_value(identity, &ready_observed_facts(identity))
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

    fn prepared_request_files(case: CandidateLstatCase) -> RequestFiles {
      let files = request_files();
      if case == CandidateLstatCase::Existing {
        File::create(files._temp.path().join("project/input.txt")).unwrap();
      }
      files
    }

    fn request_bound_to_descriptors(
      identity: &CandidateLstatProtocolIdentity,
      files: &RequestFiles,
    ) -> Value {
      let mut request = request(identity);
      let request_bytes = canonical_bytes(&request);
      let binding = validate_request(
        &request,
        identity,
        raw_frame_digest(CANDIDATE_REQUEST_DIGEST_DOMAIN, &request_bytes),
      )
      .unwrap();
      let root =
        CandidateDescriptorSnapshot::capture(files.root.as_fd()).unwrap();
      let arena =
        CandidateDescriptorSnapshot::capture(files.arena.as_fd()).unwrap();
      let value = candidate_descriptor_slots_value(
        identity,
        &binding,
        &root,
        &arena,
        identity.case == CandidateLstatCase::FinalMissing,
      );
      request["descriptorSlotsDigest"] = Value::String(
        deno_permissions::rev2::hjcs_digest(
          DESCRIPTOR_SLOTS_DIGEST_DOMAIN,
          &value,
        )
        .unwrap(),
      );
      request
    }

    fn enter_preflight_request_pending(
      identity: &CandidateLstatProtocolIdentity,
    ) -> (CandidateFd3Session, FramedStreamEndpoint, Vec<u8>) {
      let (candidate_endpoint, supervisor_endpoint) =
        framed_stream_socketpair().unwrap();
      let mut observed = ready_observed_facts(identity);
      observed.pre_request_fd_inventory[3]["platformIdentity"] =
        platform_identity(
          &inspect_candidate_control_fd(candidate_endpoint.as_fd()).unwrap(),
        );
      let preflight =
        CandidateReadyPreflight::from_observed(identity, observed).unwrap();
      let expected_ready = preflight.raw_bytes().to_vec();
      let session = CandidateFd3Session::begin_from_preflight(
        candidate_endpoint,
        identity.duplicate_test_fixture(),
        preflight,
        deadline(),
      )
      .unwrap();
      let captured = supervisor_endpoint
        .receive_one_canonical_jcs_frame(
          FrameByteLimit::CANDIDATE_READY,
          0,
          deadline(),
        )
        .unwrap();
      assert_eq!(captured.raw_bytes, expected_ready);
      (session, supervisor_endpoint, captured.raw_bytes)
    }

    fn receive_prepared_with_hook<F>(
      identity: &CandidateLstatProtocolIdentity,
      files: &RequestFiles,
      captured_umask: u64,
      between_observations: F,
    ) -> io::Result<CandidatePreparedLstatRequest>
    where
      F: FnOnce() -> io::Result<()>,
    {
      let (session, supervisor, _) = enter_preflight_request_pending(identity);
      let request = request_bound_to_descriptors(identity, files);
      send_request(&supervisor, &request, files, true);
      session.receive_prepared_request_with_observed_umask_and_hook(
        deadline(),
        captured_umask,
        between_observations,
      )
    }

    fn prepared_execution_request(
      case: CandidateLstatCase,
    ) -> (
      CandidatePreparedLstatRequest,
      FramedStreamEndpoint,
      RequestFiles,
    ) {
      let identity = native_execution_identity(case);
      let files = prepared_request_files(case);
      let request = request_bound_to_descriptors(&identity, &files);
      let (candidate_endpoint, supervisor) =
        framed_stream_socketpair().unwrap();
      let absolute_deadline = execution_session_deadline();
      let mut observed = ready_observed_facts(&identity);
      observed.pre_request_fd_inventory[3]["platformIdentity"] =
        platform_identity(
          &inspect_candidate_control_fd(candidate_endpoint.as_fd()).unwrap(),
        );
      let preflight =
        CandidateReadyPreflight::from_observed(&identity, observed).unwrap();
      let expected_ready = preflight.raw_bytes().to_vec();
      let session = CandidateFd3Session::begin_from_preflight(
        candidate_endpoint,
        identity,
        preflight,
        absolute_deadline,
      )
      .unwrap();
      let captured = supervisor
        .receive_one_canonical_jcs_frame(
          FrameByteLimit::CANDIDATE_READY,
          0,
          deadline(),
        )
        .unwrap();
      assert_eq!(captured.raw_bytes, expected_ready);
      send_request(&supervisor, &request, &files, true);
      let prepared = session
        .receive_prepared_request_with_observed_umask_and_hook(
          absolute_deadline,
          REQUIRED_CAPTURED_UMASK,
          || Ok(()),
        )
        .unwrap();
      (prepared, supervisor, files)
    }

    fn assert_no_candidate_response(endpoint: &FramedStreamEndpoint) {
      let mut byte = 0_u8;
      // SAFETY: byte is a writable one-byte buffer and the endpoint remains
      // live for the duration of this non-consuming peek.
      let result = unsafe {
        libc::recv(
          endpoint.as_fd().as_raw_fd(),
          (&mut byte as *mut u8).cast(),
          1,
          libc::MSG_PEEK | libc::MSG_DONTWAIT,
        )
      };
      let error = io::Error::last_os_error();
      assert_eq!(result, -1);
      assert_eq!(
        error.kind(),
        io::ErrorKind::WouldBlock,
        "unexpected candidate response state: {error}"
      );
    }

    fn enter_request_pending(
      identity: &CandidateLstatProtocolIdentity,
    ) -> (CandidateFd3Session, FramedStreamEndpoint, Value, Vec<u8>) {
      let (candidate_endpoint, supervisor_endpoint) =
        framed_stream_socketpair().unwrap();
      let mut session = CandidateFd3Session::new(
        candidate_endpoint,
        identity.duplicate_test_fixture(),
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
        identity.duplicate_test_fixture(),
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

    fn exact_engine_marker_facts() -> CandidateEngineBuildMarkerFacts<'static> {
      CandidateEngineBuildMarkerFacts {
        target: "aarch64-apple-darwin",
        rust_toolchain: "1.95.0",
        cargo_features: "__vendored_zlib_ng,default,upgrade",
        rust_cfg_digest: "sha256:716ae641104f6203efbaba01fa7181272951dd6125dc1eab8ae3179f2468973a",
        cargo_feature_graph_digest: "sha256:62fc7ce277e35b03015efcb6c89461269dcc32c088e5e6c82419f31598473667",
        build_profile: "release",
        panic_strategy: "abort",
        debug_assertions: false,
        fork_commit: FORK_COMMIT,
      }
    }

    #[test]
    fn candidate_binary_engine_marker_has_the_exact_stable_preimage() {
      let marker =
        derive_engine_build_marker(&exact_engine_marker_facts()).unwrap();
      assert_eq!(
        marker,
        "oden-engine-v2-sha256-_nB05NwgnJp4ELZv890rYh9vHwWIYm1K-JLzitgDCzY"
      );
      assert!(is_canonical_engine_build_marker(&marker));
    }

    #[test]
    fn candidate_binary_engine_marker_refuses_alias_and_missing_facts() {
      let mut target_alias = exact_engine_marker_facts();
      target_alias.target = "arm64-apple-darwin";
      let mut missing_feature = exact_engine_marker_facts();
      missing_feature.cargo_features = "__vendored_zlib_ng,,upgrade";
      let mut reordered_features = exact_engine_marker_facts();
      reordered_features.cargo_features = "default,__vendored_zlib_ng,upgrade";
      let mut missing_cfg = exact_engine_marker_facts();
      missing_cfg.rust_cfg_digest = "";
      let mut debug = exact_engine_marker_facts();
      debug.debug_assertions = true;
      let mut unwind = exact_engine_marker_facts();
      unwind.panic_strategy = "unwind";
      let mut missing_fork = exact_engine_marker_facts();
      missing_fork.fork_commit = "";
      for facts in [
        target_alias,
        missing_feature,
        reordered_features,
        missing_cfg,
        debug,
        unwind,
        missing_fork,
      ] {
        assert!(derive_engine_build_marker(&facts).is_err());
      }
    }

    #[test]
    fn candidate_ready_preflight_closes_and_revalidates_exact_fact_bytes() {
      for target in ["aarch64-apple-darwin", "x86_64-unknown-linux-gnu"] {
        let identity = identity_for(target, CandidateLstatCase::FinalMissing);
        let expected = canonical_bytes(&ready(&identity));
        let preflight = CandidateReadyPreflight::from_observed(
          &identity,
          ready_observed_facts(&identity),
        )
        .unwrap();
        assert_eq!(preflight.raw_bytes(), expected);
        let reparsed = parse_canonical_jcs(preflight.raw_bytes()).unwrap();
        validate_ready(&reparsed, &identity).unwrap();
      }
    }

    #[test]
    fn candidate_ready_preflight_refuses_missing_and_aliased_facts() {
      let identity = identity(CandidateLstatCase::Existing);

      let mut missing_limit = ready_observed_facts(&identity);
      missing_limit.process_limit_readback = json!({ "soft": "0" });
      let mut fd_alias = ready_observed_facts(&identity);
      fd_alias.pre_request_fd_inventory[3]["platformIdentity"] =
        platform_identity(ROOT_IDENTITY);
      let mut missing_fd = ready_observed_facts(&identity);
      missing_fd
        .pre_request_fd_inventory
        .as_array_mut()
        .unwrap()
        .pop();
      let mut zero_saved_uid = ready_observed_facts(&identity);
      zero_saved_uid.identities["savedUid"] = json!("0");

      for observed in [missing_limit, fd_alias, missing_fd, zero_saved_uid] {
        assert_eq!(
          CandidateReadyPreflight::from_observed(&identity, observed).err(),
          Some(CandidateReadyPreflightRefusal::CanonicalFrame)
        );
      }
    }

    #[test]
    fn candidate_ready_preflight_refuses_fd3_endpoint_substitution() {
      let identity = identity(CandidateLstatCase::FinalMissing);
      let (observed_endpoint, _observed_peer) =
        framed_stream_socketpair().unwrap();
      let mut observed = ready_observed_facts(&identity);
      observed.pre_request_fd_inventory[3]["platformIdentity"] =
        platform_identity(
          &inspect_candidate_control_fd(observed_endpoint.as_fd()).unwrap(),
        );
      let preflight =
        CandidateReadyPreflight::from_observed(&identity, observed).unwrap();

      let (substituted_endpoint, substituted_peer) =
        framed_stream_socketpair().unwrap();
      let error = CandidateFd3Session::begin_from_preflight(
        substituted_endpoint,
        identity,
        preflight,
        deadline(),
      )
      .err()
      .unwrap();
      assert_eq!(error.kind(), io::ErrorKind::InvalidData);
      substituted_peer.require_eof(deadline()).unwrap();
    }

    #[test]
    fn candidate_prepared_request_accepts_exact_two_target_lstat_topologies() {
      for target in ["aarch64-apple-darwin", "x86_64-unknown-linux-gnu"] {
        for case in [
          CandidateLstatCase::Existing,
          CandidateLstatCase::FinalMissing,
        ] {
          let identity = identity_for(target, case);
          let files = prepared_request_files(case);
          let (session, supervisor, ready_raw_bytes) =
            enter_preflight_request_pending(&identity);
          let request = request_bound_to_descriptors(&identity, &files);
          let expected_digest = request["descriptorSlotsDigest"]
            .as_str()
            .unwrap()
            .to_string();
          let request_raw_bytes =
            send_request(&supervisor, &request, &files, true);
          let prepared = session
            .receive_prepared_request_with_observed_umask_and_hook(
              deadline(),
              REQUIRED_CAPTURED_UMASK,
              || Ok(()),
            )
            .unwrap();
          assert_eq!(prepared._ready_raw_bytes, ready_raw_bytes);
          assert_eq!(prepared._captured_umask, REQUIRED_CAPTURED_UMASK);
          assert_eq!(prepared._descriptor_slots_digest, expected_digest);
          assert_eq!(prepared._request_metadata.raw_bytes, request_raw_bytes);
          assert_eq!(
            raw_frame_digest(
              CANDIDATE_REQUEST_DIGEST_DOMAIN,
              &request_raw_bytes
            ),
            prepared._request_metadata.request_frame_digest
          );
          let artifact =
            parse_canonical_jcs(&prepared._descriptor_slots_raw_bytes).unwrap();
          assert_eq!(artifact["schema"], DESCRIPTOR_SLOTS_SCHEMA);
          assert_eq!(
            artifact["slots"][0]["emptyAtTransfer"],
            case == CandidateLstatCase::FinalMissing
          );
          assert_eq!(
            deno_permissions::rev2::hjcs_digest(
              DESCRIPTOR_SLOTS_DIGEST_DOMAIN,
              &artifact
            )
            .unwrap(),
            expected_digest
          );
          assert_descriptors_open([
            prepared._project_root.as_raw_fd(),
            prepared._arena.as_raw_fd(),
          ]);
          drop(prepared);
          supervisor.require_eof(deadline()).unwrap();
        }
      }
    }

    #[test]
    fn candidate_prepared_request_requires_consumed_preflight_and_exact_umask()
    {
      let identity = identity(CandidateLstatCase::FinalMissing);
      let files = prepared_request_files(identity.case);
      assert!(
        receive_prepared_with_hook(&identity, &files, 0o022, || Ok(()))
          .is_err()
      );

      let (legacy_session, supervisor, _, _) = enter_request_pending(&identity);
      let request = request_bound_to_descriptors(&identity, &files);
      send_request(&supervisor, &request, &files, true);
      let observed_umask = AtomicBool::new(false);
      assert!(
        legacy_session
          .receive_prepared_request_with_umask_observer_and_hook(
            deadline(),
            || {
              observed_umask.store(true, Ordering::SeqCst);
              CandidateCapturedUmask::from_observed_for_test(
                REQUIRED_CAPTURED_UMASK,
              )
            },
            || Ok(())
          )
          .is_err()
      );
      assert!(!observed_umask.load(Ordering::SeqCst));
    }

    #[test]
    fn candidate_prepared_request_refuses_wrong_descriptor_digest_and_access() {
      let identity = identity(CandidateLstatCase::FinalMissing);
      let files = prepared_request_files(identity.case);
      let (session, supervisor, _) = enter_preflight_request_pending(&identity);
      let request = request(&identity);
      send_request(&supervisor, &request, &files, true);
      assert!(
        session
          .receive_prepared_request_with_observed_umask_and_hook(
            deadline(),
            REQUIRED_CAPTURED_UMASK,
            || Ok(())
          )
          .is_err()
      );

      let read_only_files = {
        let mut files = prepared_request_files(identity.case);
        let arena_path = files._temp.path().join("arena");
        files.arena = OpenOptions::new()
          .read(true)
          .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
          .open(arena_path)
          .unwrap();
        files
      };
      assert!(
        receive_prepared_with_hook(
          &identity,
          &read_only_files,
          REQUIRED_CAPTURED_UMASK,
          || Ok(())
        )
        .is_err()
      );

      let append_files = {
        let mut files = prepared_request_files(identity.case);
        let arena_path = files._temp.path().join("arena");
        files.arena = OpenOptions::new()
          .read(true)
          .append(true)
          .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
          .open(arena_path)
          .unwrap();
        files
      };
      assert!(
        receive_prepared_with_hook(
          &identity,
          &append_files,
          REQUIRED_CAPTURED_UMASK,
          || Ok(())
        )
        .is_err()
      );

      let append_root_files = {
        let files = prepared_request_files(identity.case);
        let flags = descriptor_status_flags(files.root.as_fd()).unwrap();
        // SAFETY: F_SETFL updates only mutable status flags on the live
        // retained test descriptor.
        assert!(
          unsafe {
            libc::fcntl(
              files.root.as_raw_fd(),
              libc::F_SETFL,
              flags | libc::O_APPEND,
            )
          } >= 0
        );
        assert_ne!(
          descriptor_status_flags(files.root.as_fd()).unwrap() & libc::O_APPEND,
          0
        );
        files
      };
      assert!(
        receive_prepared_with_hook(
          &identity,
          &append_root_files,
          REQUIRED_CAPTURED_UMASK,
          || Ok(())
        )
        .is_err()
      );

      #[cfg(target_os = "linux")]
      {
        let path_root_files = {
          let mut files = prepared_request_files(identity.case);
          let path_only = open_candidate_at(
            files.root.as_fd(),
            ".",
            libc::O_PATH
              | libc::O_DIRECTORY
              | libc::O_NOFOLLOW
              | libc::O_CLOEXEC,
          )
          .unwrap();
          files.root = File::from(path_only);
          files
        };
        assert!(
          receive_prepared_with_hook(
            &identity,
            &path_root_files,
            REQUIRED_CAPTURED_UMASK,
            || Ok(())
          )
          .is_err()
        );
      }

      #[cfg(target_os = "macos")]
      for alternate_access in [libc::O_EVTONLY, libc::O_SEARCH] {
        let alternate_root_files = {
          let mut files = prepared_request_files(identity.case);
          let alternate = open_candidate_at(
            files.root.as_fd(),
            ".",
            alternate_access
              | libc::O_DIRECTORY
              | libc::O_NOFOLLOW
              | libc::O_CLOEXEC,
          )
          .unwrap();
          files.root = File::from(alternate);
          files
        };
        assert_ne!(
          descriptor_status_flags(alternate_root_files.root.as_fd()).unwrap()
            & alternate_access,
          0
        );
        assert!(
          receive_prepared_with_hook(
            &identity,
            &alternate_root_files,
            REQUIRED_CAPTURED_UMASK,
            || Ok(())
          )
          .is_err()
        );
      }
    }

    #[test]
    fn candidate_prepared_request_refuses_inexact_existing_source_shapes() {
      let identity = identity(CandidateLstatCase::Existing);

      let nonempty = prepared_request_files(identity.case);
      std::fs::write(nonempty._temp.path().join("project/input.txt"), b"x")
        .unwrap();
      assert!(
        receive_prepared_with_hook(
          &identity,
          &nonempty,
          REQUIRED_CAPTURED_UMASK,
          || Ok(())
        )
        .is_err()
      );

      let hard_linked = prepared_request_files(identity.case);
      std::fs::hard_link(
        hard_linked._temp.path().join("project/input.txt"),
        hard_linked._temp.path().join("outside-link"),
      )
      .unwrap();
      assert!(
        receive_prepared_with_hook(
          &identity,
          &hard_linked,
          REQUIRED_CAPTURED_UMASK,
          || Ok(())
        )
        .is_err()
      );

      let directory = prepared_request_files(identity.case);
      let source = directory._temp.path().join("project/input.txt");
      std::fs::remove_file(&source).unwrap();
      std::fs::create_dir(&source).unwrap();
      assert!(
        receive_prepared_with_hook(
          &identity,
          &directory,
          REQUIRED_CAPTURED_UMASK,
          || Ok(())
        )
        .is_err()
      );

      let symlinked = prepared_request_files(identity.case);
      let source = symlinked._temp.path().join("project/input.txt");
      std::fs::remove_file(&source).unwrap();
      File::create(symlinked._temp.path().join("outside")).unwrap();
      std::os::unix::fs::symlink(
        symlinked._temp.path().join("outside"),
        source,
      )
      .unwrap();
      assert!(
        receive_prepared_with_hook(
          &identity,
          &symlinked,
          REQUIRED_CAPTURED_UMASK,
          || Ok(())
        )
        .is_err()
      );
    }

    #[test]
    fn candidate_prepared_request_refuses_extras_aliases_and_mutation() {
      let existing = identity(CandidateLstatCase::Existing);
      let extra = prepared_request_files(existing.case);
      File::create(extra._temp.path().join("project/output.txt")).unwrap();
      assert!(
        receive_prepared_with_hook(
          &existing,
          &extra,
          REQUIRED_CAPTURED_UMASK,
          || Ok(())
        )
        .is_err()
      );

      let final_missing = identity(CandidateLstatCase::FinalMissing);
      let alias = prepared_request_files(final_missing.case);
      File::create(alias._temp.path().join("project/Input.txt")).unwrap();
      assert!(
        receive_prepared_with_hook(
          &final_missing,
          &alias,
          REQUIRED_CAPTURED_UMASK,
          || Ok(())
        )
        .is_err()
      );

      let replaced = prepared_request_files(existing.case);
      let source = replaced._temp.path().join("project/input.txt");
      assert!(
        receive_prepared_with_hook(
          &existing,
          &replaced,
          REQUIRED_CAPTURED_UMASK,
          || {
            std::fs::remove_file(&source)?;
            File::create(&source)?;
            Ok(())
          }
        )
        .is_err()
      );

      let arena_mutated = prepared_request_files(final_missing.case);
      let arena = arena_mutated.arena.try_clone().unwrap();
      assert!(
        receive_prepared_with_hook(
          &final_missing,
          &arena_mutated,
          REQUIRED_CAPTURED_UMASK,
          move || {
            let byte = [1_u8];
            // SAFETY: byte is readable and arena is a live regular file.
            let written = unsafe {
              libc::pwrite(
                arena.as_raw_fd(),
                byte.as_ptr().cast(),
                byte.len(),
                0,
              )
            };
            if written == 1 {
              Ok(())
            } else if written < 0 {
              Err(io::Error::last_os_error())
            } else {
              Err(invalid_data("test arena mutation was short"))
            }
          }
        )
        .is_err()
      );

      let root_flags_mutated = prepared_request_files(final_missing.case);
      let root = root_flags_mutated.root.try_clone().unwrap();
      assert!(
        receive_prepared_with_hook(
          &final_missing,
          &root_flags_mutated,
          REQUIRED_CAPTURED_UMASK,
          move || {
            let flags = descriptor_status_flags(root.as_fd())?;
            // SAFETY: F_SETFL updates only mutable status flags on this live
            // duplicate of the transferred root open-file description.
            if unsafe {
              libc::fcntl(
                root.as_raw_fd(),
                libc::F_SETFL,
                flags | libc::O_APPEND,
              )
            } < 0
            {
              return Err(io::Error::last_os_error());
            }
            Ok(())
          }
        )
        .is_err()
      );
    }

    #[test]
    fn candidate_prepared_dirent_name_is_record_bounded() {
      // SAFETY: zero is a valid representation for this C record.
      let mut entry: libc::dirent = unsafe { std::mem::zeroed() };
      let name_offset = std::mem::offset_of!(libc::dirent, d_name);
      entry.d_name[0] = b'x' as _;
      entry.d_name[1] = 0;
      #[cfg(target_os = "macos")]
      {
        entry.d_namlen = 1;
      }
      entry.d_reclen = (name_offset + 2).try_into().unwrap();
      // SAFETY: the local record contains the fixed header and the bounded
      // name plus NUL described above.
      assert_eq!(unsafe { candidate_dirent_name(&entry) }.unwrap(), b"x");

      entry.d_reclen = (name_offset + 1).try_into().unwrap();
      // SAFETY: the fixed header remains accessible; the helper must refuse
      // because the NUL now lies outside the declared record.
      assert!(unsafe { candidate_dirent_name(&entry) }.is_err());
    }

    #[cfg(all(
      any(
        all(target_arch = "aarch64", target_os = "macos"),
        all(target_arch = "x86_64", target_os = "linux", target_env = "gnu")
      ),
      any(debug_assertions, not(panic = "abort"))
    ))]
    #[test]
    fn candidate_executed_request_exact_join_refuses_nonrelease_test_binary() {
      let build_identity = current_binary_build_identity();
      for case in [
        CandidateLstatCase::Existing,
        CandidateLstatCase::FinalMissing,
      ] {
        assert!(
          oden_capsec_rev2_join_lstat_candidate_binary_identity(
            &build_identity,
            FIXTURE_DIGEST,
            case.case_id(),
          )
          .is_err(),
          "a non-release test binary must not obtain an exact generated seal"
        );
      }
    }

    #[cfg(all(
      any(
        all(target_arch = "aarch64", target_os = "macos"),
        all(target_arch = "x86_64", target_os = "linux", target_env = "gnu")
      ),
      not(debug_assertions),
      panic = "abort"
    ))]
    #[test]
    fn candidate_executed_request_consumes_exact_cases_without_output() {
      for case in [
        CandidateLstatCase::Existing,
        CandidateLstatCase::FinalMissing,
      ] {
        let (prepared, supervisor, files) = prepared_execution_request(case);
        let root_fd = prepared._project_root.as_raw_fd();
        let arena_fd = prepared._arena.as_raw_fd();
        let arena_snapshot =
          CandidateDescriptorSnapshot::capture(prepared._arena.as_fd())
            .unwrap();
        let request_metadata = Arc::as_ptr(&prepared._request_metadata);

        let executed = prepared.execute_lstat_candidate(deadline()).unwrap();

        assert_descriptor_closed(root_fd);
        assert_eq!(executed._arena.as_raw_fd(), arena_fd);
        assert_eq!(
          CandidateDescriptorSnapshot::capture(executed._arena.as_fd())
            .unwrap(),
          arena_snapshot
        );
        assert_eq!(Arc::as_ptr(&executed._request_metadata), request_metadata);
        assert_eq!(Arc::strong_count(&executed._request_metadata), 1);
        assert_eq!(executed._identity.case, case);
        assert_no_candidate_response(&supervisor);
        match case {
          CandidateLstatCase::Existing => {
            assert_eq!(
              std::fs::read(files._temp.path().join("project/input.txt"))
                .unwrap(),
              b""
            );
          }
          CandidateLstatCase::FinalMissing => {
            assert_eq!(
              std::fs::read_dir(files._temp.path().join("project"))
                .unwrap()
                .count(),
              0
            );
          }
        }

        drop(executed);
        supervisor.require_eof(deadline()).unwrap();
      }
    }

    #[cfg(all(
      any(
        all(target_arch = "aarch64", target_os = "macos"),
        all(target_arch = "x86_64", target_os = "linux", target_env = "gnu")
      ),
      not(debug_assertions),
      panic = "abort"
    ))]
    #[test]
    fn candidate_executed_request_refuses_metadata_clone_and_substitution() {
      let (prepared, supervisor, _files) =
        prepared_execution_request(CandidateLstatCase::Existing);
      let metadata_alias = Arc::clone(&prepared._request_metadata);
      let error = prepared.execute_lstat_candidate(deadline()).err().unwrap();
      assert_eq!(
        error.kind(),
        io::ErrorKind::InvalidData,
        "a surviving prepared-request metadata clone must refuse exactly"
      );
      drop(metadata_alias);
      supervisor.require_eof(deadline()).unwrap();

      let (prepared, supervisor, _files) =
        prepared_execution_request(CandidateLstatCase::Existing);
      clear_cloexec_for_test(prepared._project_root.as_fd()).unwrap();
      let error = prepared.execute_lstat_candidate(deadline()).err().unwrap();
      assert_eq!(
        error.kind(),
        io::ErrorKind::InvalidData,
        "a mutated retained-root descriptor must refuse exactly"
      );
      supervisor.require_eof(deadline()).unwrap();

      let (mut existing, existing_supervisor, _existing_files) =
        prepared_execution_request(CandidateLstatCase::Existing);
      let (mut missing, missing_supervisor, _missing_files) =
        prepared_execution_request(CandidateLstatCase::FinalMissing);
      std::mem::swap(&mut existing._identity, &mut missing._identity);
      let error = existing.execute_lstat_candidate(deadline()).err().unwrap();
      assert_eq!(
        error.kind(),
        io::ErrorKind::InvalidData,
        "a substituted prepared identity must refuse exactly"
      );
      drop(missing);
      existing_supervisor.require_eof(deadline()).unwrap();
      missing_supervisor.require_eof(deadline()).unwrap();

      let (mut first, first_supervisor, _first_files) =
        prepared_execution_request(CandidateLstatCase::FinalMissing);
      let (mut second, second_supervisor, _second_files) =
        prepared_execution_request(CandidateLstatCase::FinalMissing);
      std::mem::swap(&mut first._arena, &mut second._arena);
      let error = first.execute_lstat_candidate(deadline()).err().unwrap();
      assert_eq!(
        error.kind(),
        io::ErrorKind::InvalidData,
        "a substituted retained arena must refuse exactly"
      );
      drop(second);
      first_supervisor.require_eof(deadline()).unwrap();
      second_supervisor.require_eof(deadline()).unwrap();
    }

    #[cfg(all(
      any(
        all(target_arch = "aarch64", target_os = "macos"),
        all(target_arch = "x86_64", target_os = "linux", target_env = "gnu")
      ),
      not(debug_assertions),
      panic = "abort"
    ))]
    #[test]
    fn candidate_executed_request_refuses_post_execution_arena_mutation() {
      let (prepared, supervisor, _files) =
        prepared_execution_request(CandidateLstatCase::FinalMissing);
      let error = prepared
        .execute_lstat_candidate_with_hook(deadline(), |arena| {
          let byte = [1_u8];
          // SAFETY: byte is readable and arena is the live retained regular
          // file supplied by this test.
          let written = unsafe {
            libc::pwrite(arena.as_raw_fd(), byte.as_ptr().cast(), byte.len(), 0)
          };
          if written == 1 {
            Ok(())
          } else if written < 0 {
            Err(io::Error::last_os_error())
          } else {
            Err(invalid_data("test arena mutation was short"))
          }
        })
        .err()
        .unwrap();
      assert_eq!(error.kind(), io::ErrorKind::InvalidData);
      supervisor.require_eof(deadline()).unwrap();

      let (prepared, supervisor, _files) =
        prepared_execution_request(CandidateLstatCase::FinalMissing);
      let error = prepared
        .execute_lstat_candidate_with_hook(deadline(), |arena| {
          clear_cloexec_for_test(arena.as_fd())
        })
        .err()
        .unwrap();
      assert_eq!(error.kind(), io::ErrorKind::InvalidData);
      supervisor.require_eof(deadline()).unwrap();
    }

    #[cfg(all(
      any(
        all(target_arch = "aarch64", target_os = "macos"),
        all(target_arch = "x86_64", target_os = "linux", target_env = "gnu")
      ),
      not(debug_assertions),
      panic = "abort"
    ))]
    #[test]
    fn candidate_executed_request_refuses_post_execution_deadline_expiry() {
      let (mut prepared, supervisor, _files) =
        prepared_execution_request(CandidateLstatCase::FinalMissing);
      let absolute_deadline = Instant::now() + Duration::from_secs(30);
      let clock = Arc::new(TestClock::new(absolute_deadline));
      prepared._session_deadline =
        CandidateSessionDeadline::with_clock(absolute_deadline, clock.clone());
      let error = prepared
        .execute_lstat_candidate_with_hook(
          absolute_deadline + Duration::from_secs(30),
          |_| {
            clock.expire_now();
            Ok(())
          },
        )
        .err()
        .unwrap();
      assert_eq!(error.kind(), io::ErrorKind::TimedOut);
      supervisor.require_eof(deadline()).unwrap();
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn candidate_ready_actual_preflight_refuses_the_unprepared_test_process() {
      let identity = identity(CandidateLstatCase::Existing);
      assert_eq!(
        CandidateReadyPreflight::collect(&identity).err(),
        Some(CandidateReadyPreflightRefusal::ProcessLimit)
      );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn candidate_ready_control_fd_is_verified_before_flag_mutation() {
      let regular_file = tempfile::tempfile().unwrap();
      let regular_fd = regular_file.as_raw_fd();
      let regular_descriptor_flags =
        get_fcntl_flags(regular_fd, libc::F_GETFD).unwrap();
      let regular_status_flags =
        get_fcntl_flags(regular_fd, libc::F_GETFL).unwrap();
      assert!(prepare_candidate_control_fd(regular_fd).is_err());
      assert_eq!(
        get_fcntl_flags(regular_fd, libc::F_GETFD).unwrap(),
        regular_descriptor_flags
      );
      assert_eq!(
        get_fcntl_flags(regular_fd, libc::F_GETFL).unwrap(),
        regular_status_flags
      );

      let listener_root = tempfile::tempdir().unwrap();
      let listener =
        std::os::unix::net::UnixListener::bind(listener_root.path().join("s"))
          .unwrap();
      let listener_fd = listener.as_raw_fd();
      let listener_descriptor_flags =
        get_fcntl_flags(listener_fd, libc::F_GETFD).unwrap();
      let listener_status_flags =
        get_fcntl_flags(listener_fd, libc::F_GETFL).unwrap();
      assert!(prepare_candidate_control_fd(listener_fd).is_err());
      assert_eq!(
        get_fcntl_flags(listener_fd, libc::F_GETFD).unwrap(),
        listener_descriptor_flags
      );
      assert_eq!(
        get_fcntl_flags(listener_fd, libc::F_GETFL).unwrap(),
        listener_status_flags
      );

      let (candidate_endpoint, _peer_endpoint) =
        framed_stream_socketpair().unwrap();
      let candidate_fd = candidate_endpoint.as_fd().as_raw_fd();
      let descriptor_flags =
        get_fcntl_flags(candidate_fd, libc::F_GETFD).unwrap();
      set_fcntl_flags(
        candidate_fd,
        libc::F_SETFD,
        descriptor_flags & !libc::FD_CLOEXEC,
      )
      .unwrap();
      let status_flags = get_fcntl_flags(candidate_fd, libc::F_GETFL).unwrap();
      set_fcntl_flags(
        candidate_fd,
        libc::F_SETFL,
        status_flags & !libc::O_NONBLOCK,
      )
      .unwrap();
      let identity = prepare_candidate_control_fd(candidate_fd).unwrap();
      assert!(is_platform_identity(&identity));
      assert_ne!(
        get_fcntl_flags(candidate_fd, libc::F_GETFD).unwrap()
          & libc::FD_CLOEXEC,
        0
      );
      assert_ne!(
        get_fcntl_flags(candidate_fd, libc::F_GETFL).unwrap()
          & libc::O_NONBLOCK,
        0
      );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn candidate_ready_actual_preflight_refuses_absent_linux_containment() {
      let identity =
        identity_for("x86_64-unknown-linux-gnu", CandidateLstatCase::Existing);
      assert_eq!(
        CandidateReadyPreflight::collect(&identity).err(),
        Some(CandidateReadyPreflightRefusal::LinuxContainmentUnavailable)
      );
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
        identity.duplicate_test_fixture(),
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
        CandidateLstatProtocolIdentity::new_test_fixture(
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
        CandidateLstatProtocolIdentity::new_test_fixture(
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

// Copyright 2018-2026 the Deno authors. MIT license.

// @ref LLP 0019#checked-final-lto-target-policy [implements] —
// Session-scoped verifier family for the checked final-LTO target-policy
// selection: bootstrap TCB, verifier session, current-approval guard and
// single-use witness, complete atomic four-row registry validation, and the
// checked one-row selection. The production TCB and compiled-identity
// constructors REFUSE because the durable external current-state authority
// and the externally provisioned compiled-identity catalog do not exist yet;
// only explicitly named test fixtures (which grant no production authority,
// per the spec's test-constructor precedents) can construct the family. No
// authority-bearing type here is Clone, Copy, Default, Serialize, or
// Deserialize, and every authority value is !Send + !Sync.
//
// The approval grammar this family verifies is the CURRENT coherent `/2`
// contract (spec 0019 "Checked final-LTO target policy"): approval schema
// `oden/capsec-filesystem-final-lto-target-policy-registry-approval/2`,
// statement `policyRevision: 1`, and all `:2` domains — matching the `/2`
// revision-1 registry and the landed carrier's revision-1 acceptance.
// Complete registry validation REQUIRES statement/registry coherence and
// REFUSES any schema/revision/domain incoherence (in particular the
// `/3`-over-`/2` hybrid) with a typed error, so no incoherent pair is ever
// constructible into a Validated/Checked authority value.
//
// SCOPE OF THE SINGLE-USE / NON-TRANSFER GUARANTEE. Within one process, in
// safe Rust, the witness is affine (consumed by value, not Clone/Copy) and
// the guard/witness/session brands cannot be transferred across threads
// (!Send + !Sync) or serialized (no serde). These properties hold ONLY
// within a single process. This family does NOT enforce cross-process (e.g.
// `fork()`) confinement, cross-phase liveness, external revocation, or
// protected-clock freshness: `fork()` duplicates the whole address space
// without crossing any serialization boundary, so a forked child would hold
// byte-identical guards and witnesses, and the in-memory generation counter
// re-checked here is a stand-in for — not an implementation of — the
// authenticated linearizable current-state/lease check. Those guarantees
// await the durable external current-state authority, which is a separate,
// still-absent checkpoint (a tracked blocker) and is exactly why the
// production constructors refuse. Nothing here fabricates that authority or
// claims fork/phase/run/process confinement it does not have.

use std::cell::Cell;
use std::marker::PhantomData;

use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::edwards::EdwardsPoint;
use curve25519_dalek::scalar::Scalar;
use sha2::Digest as _;
use sha2::Sha512;
use thiserror::Error;

use super::oden_parent_allowlist::CanonicalSha256Digest;
use super::oden_parent_allowlist::MAX_IJSON_SAFE_INTEGER;
use super::oden_parent_allowlist::ODEN_PARENT_PROFILE;
use super::oden_parent_allowlist::ODEN_PARENT_TARGET_POLICY_DIGEST_DOMAIN;
use super::oden_parent_allowlist::ODEN_PARENT_TARGET_POLICY_REGISTRY_BYTES_DIGEST_DOMAIN;
use super::oden_parent_allowlist::ODEN_PARENT_TARGET_POLICY_REGISTRY_SCHEMA;
use super::oden_parent_allowlist::ODEN_PARENT_TARGET_POLICY_REVISION;
use super::oden_parent_allowlist::ODEN_PARENT_TARGET_POLICY_TARGET_ORDER;
use super::oden_parent_allowlist::OdenParentAllowlistError;
use super::oden_parent_allowlist::OdenParentStrictJsonValue;
use super::oden_parent_allowlist::canonical_value_jcs;
use super::oden_parent_allowlist::framed_sha256_digest;
use super::oden_parent_allowlist::hjcs_digest;
#[cfg(test)]
use super::oden_parent_allowlist::oden_parent_target_policy_feature_set;
use super::oden_parent_allowlist::take_oden_parent_target_policy_registry_rows;

// The approval family is the CURRENT coherent `/2` approval grammar (spec
// 0019 "Checked final-LTO target policy"): approval schema
// `oden/capsec-filesystem-final-lto-target-policy-registry-approval/2`, HJCS
// domain `...approval:2`, keyId/signature-byte/registry-byte digests and the
// signature framing all under the matching `:2` domains, and the statement's
// `policyRevision` literal exactly `1`. This matches the `/2` revision-1
// registry, the landed carrier's revision-1 acceptance, and the checked-in
// JSON schema
// `schemas/capsec/rev2/filesystem-final-lto-target-policy-registry-approval.schema.json`.
// The incompatible `/3` successor grammar (revision `2`, `:3` domains) is
// defined at the successor target-row boundary and is NOT accepted here; a
// reader must never reinterpret a `/2` approval as the successor, and a `/3`
// approval over this `/2` registry is exactly the forbidden hybrid this
// family refuses.
pub const ODEN_TARGET_POLICY_APPROVAL_SCHEMA: &str =
  "oden/capsec-filesystem-final-lto-target-policy-registry-approval/2";
pub const ODEN_TARGET_POLICY_APPROVAL_DIGEST_DOMAIN: &str =
  "oden:capsec:filesystem-final-lto-target-policy-registry-approval:2";
pub const ODEN_TARGET_POLICY_APPROVAL_PUBLIC_KEY_BYTES_DIGEST_DOMAIN: &str = "oden:capsec:filesystem-final-lto-target-policy-registry-approval-public-key-bytes:2";
pub const ODEN_TARGET_POLICY_APPROVAL_SIGNATURE_BYTES_DIGEST_DOMAIN: &str = "oden:capsec:filesystem-final-lto-target-policy-registry-approval-signature-bytes:2";
pub const ODEN_TARGET_POLICY_APPROVAL_SIGNATURE_FRAMING_DOMAIN: &str = "oden:capsec:filesystem-final-lto-target-policy-registry-approval-signature:2";
/// The `/2` approval statement's `registryByteDigest` is HBYTES under the
/// `:2` registry-byte domain — the SAME domain the `/2` registry and landed
/// carrier relation use. Under the coherent `/2` contract this is one
/// domain-separated identity over the exact canonical registry bytes, equal
/// to `ODEN_PARENT_TARGET_POLICY_REGISTRY_BYTES_DIGEST_DOMAIN`.
pub const ODEN_TARGET_POLICY_APPROVAL_REGISTRY_BYTES_DIGEST_DOMAIN: &str =
  ODEN_PARENT_TARGET_POLICY_REGISTRY_BYTES_DIGEST_DOMAIN;
/// The `/2` approval statement's `policyRevision` literal (const per the
/// checked-in `/2` approval schema), exactly `1`. Complete registry
/// validation additionally REQUIRES this to equal the parsed registry's
/// `policyRevision` (also `1`) and REFUSES any mismatch with a typed error,
/// so no incoherent statement/registry pair is constructible into a
/// Validated/Checked authority value.
pub const ODEN_TARGET_POLICY_APPROVAL_STATEMENT_POLICY_REVISION: u64 = 1;
const ODEN_TARGET_POLICY_APPROVAL_JCS_MAX_BYTES: usize = 65_536;

/// Explicitly test-scoped current-state receipt schema, shared verbatim with
/// the parent-side fixture
/// (`capsec/rev2/fixtures/test-authority/test-current-state.json` and
/// `scripts/capsec/rev2_target_policy.ts`). The durable external
/// current-state authority does not exist; this test-namespace schema can
/// never collide with a production receipt and grants no production
/// authority.
#[cfg(test)]
const ODEN_TARGET_POLICY_TEST_FIXTURE_RECEIPT_SCHEMA: &str =
  "oden/capsec-filesystem-final-lto-target-policy-test-current-state/1";
#[cfg(test)]
const ODEN_TARGET_POLICY_TEST_FIXTURE_RECEIPT_JCS_MAX_BYTES: usize = 4_096;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum OdenTargetPolicySessionError {
  #[error(
    "the durable external current-state approval authority does not exist; \
     production bootstrap-TCB construction refuses"
  )]
  ExternalCurrentStateAuthorityAbsent,
  #[error(
    "the externally provisioned compiled-identity catalog authority does not \
     exist; production compiled-identity construction refuses"
  )]
  ExternalCompiledIdentityAuthorityAbsent,
  #[error("invalid test authority fixture: {0}")]
  InvalidTestAuthorityFixture(&'static str),
  #[error("invalid target-policy approval candidate: {0}")]
  InvalidApprovalCandidate(&'static str),
  #[error("invalid target-policy approval JSON: {0}")]
  InvalidApprovalJson(String),
  #[error("invalid target-policy approval field {field}: {reason}")]
  InvalidApprovalField {
    field: &'static str,
    reason: &'static str,
  },
  #[error("approval public key does not derive the approval keyId")]
  ApprovalKeyMismatch,
  #[error(
    "approval signatureByteDigest does not match the detached signature bytes"
  )]
  ApprovalSignatureDigestMismatch,
  #[error("approval signature failed strict Ed25519 verification: {0}")]
  ApprovalSignatureInvalid(&'static str),
  #[error("approval does not match protected current state: {0}")]
  CurrentStateMismatch(&'static str),
  #[error("approval guard is invalidated: {0}")]
  GuardInvalidated(&'static str),
  #[error(
    "approval statement policyRevision {statement} does not equal the parsed \
     registry policyRevision {registry}; production complete validation \
     requires full statement/registry coherence"
  )]
  StatementRegistryPolicyRevisionMismatch { statement: u64, registry: u64 },
  #[error("approval use does not belong to this session family: {0}")]
  ApprovalUseMismatch(&'static str),
  #[error("registry candidate failed complete validation: {0}")]
  RegistryValidation(#[from] OdenParentAllowlistError),
  #[error("registry row is not semantically closed: {0}")]
  RegistryRowNotClosed(&'static str),
  #[error(
    "registry rows do not have independent, non-overlapping identities: {0}"
  )]
  RegistryRowIdentityOverlap(&'static str),
  #[error("registry bytes are not the externally approved bytes")]
  RegistryNotApproved,
  #[error("invalid compiled identity: {0}")]
  InvalidCompiledIdentity(&'static str),
  #[error(
    "selection refuses: no validated registry row matches the authenticated \
     compiled target"
  )]
  SelectionTargetMismatch,
  #[error(
    "selection refuses: the generated Rev2 featureSet does not match \
     byte-for-byte"
  )]
  SelectionFeatureSetMismatch,
  #[error(
    "selection refuses: selected-row targetPolicyDigest recomputation \
     does not match"
  )]
  SelectionDigestMismatch,
}

/// Externally rooted release-control-plane bootstrap TCB (spec 0019, checked
/// final-LTO target policy, bootstrap paragraphs).
///
/// The production constructor refuses: the organization-provisioned bootstrap
/// root, content-tree inventory, runtime closure, compiled-identity catalog,
/// and the durable linearizable current-state authority are all absent, so no
/// production path can create this value. Only the explicitly named
/// `new_test_authority_fixture` constructor (test builds only) can, and per
/// the spec's test-constructor precedents it grants no production authority.
// @ref LLP 0019#checked-final-lto-target-policy [implements] — TCB creation is
// gated on external authority that does not exist yet; fail closed.
#[allow(clippy::upper_case_acronyms)]
pub struct VerifiedFilesystemFinalLtoBootstrapTCB {
  approval_public_key: [u8; 32],
  receipt_approval_digest: String,
  receipt_approval_sequence: u64,
  receipt_registry_byte_digest: String,
  current_state_generation: Cell<u64>,
  _not_send_sync: PhantomData<*const ()>,
}

impl VerifiedFilesystemFinalLtoBootstrapTCB {
  /// Production constructor. Always refuses: the durable external
  /// current-state authority (approval key configuration, protected issuance
  /// clock, rollback-resistant latest-approval transition) is a separate
  /// unimplemented checkpoint, so no present code can supply this authority.
  pub fn from_external_release_authority()
  -> Result<Self, OdenTargetPolicySessionError> {
    Err(OdenTargetPolicySessionError::ExternalCurrentStateAuthorityAbsent)
  }

  /// Test-only fixture constructor. Accepts an explicit test-only Ed25519
  /// public key and a test-fixture current-state receipt. The receipt schema
  /// is fixture-named so this value can never satisfy a production consumer.
  #[cfg(test)]
  pub(crate) fn new_test_authority_fixture(
    approval_public_key: [u8; 32],
    current_state_receipt_jcs: &[u8],
  ) -> Result<Self, OdenTargetPolicySessionError> {
    decompress_strict_point(&approval_public_key).map_err(|_| {
      OdenTargetPolicySessionError::InvalidTestAuthorityFixture(
        "public key is not a canonical prime-order Ed25519 point",
      )
    })?;
    let receipt = parse_test_fixture_receipt(current_state_receipt_jcs)?;
    // The receipt's keyId must derive from exactly the supplied test key: a
    // receipt cannot smuggle in a different signing authority.
    let derived_key_id = framed_sha256_digest(
      ODEN_TARGET_POLICY_APPROVAL_PUBLIC_KEY_BYTES_DIGEST_DOMAIN,
      &approval_public_key,
    );
    if receipt.key_id != derived_key_id.as_str() {
      return Err(OdenTargetPolicySessionError::InvalidTestAuthorityFixture(
        "receipt keyId does not derive from the supplied test public key",
      ));
    }
    Ok(Self {
      approval_public_key,
      receipt_approval_digest: receipt.latest_approval_digest,
      receipt_approval_sequence: receipt.approval_sequence,
      receipt_registry_byte_digest: receipt.registry_byte_digest,
      current_state_generation: Cell::new(receipt.state_generation),
      _not_send_sync: PhantomData,
    })
  }

  /// Simulate a protected current-state transition (revocation, supersession,
  /// generation change). Invalidates existing guards and unconsumed witnesses.
  #[cfg(test)]
  pub(crate) fn advance_test_current_state_generation(&self) {
    self
      .current_state_generation
      .set(self.current_state_generation.get().wrapping_add(1));
  }

  /// Begin one fresh generative verifier session scoped to this TCB.
  pub fn begin_policy_verifier_session(
    &self,
  ) -> FilesystemFinalLtoPolicyVerifierSession<'_> {
    FilesystemFinalLtoPolicyVerifierSession {
      tcb: self,
      _not_send_sync: PhantomData,
    }
  }
}

#[cfg(test)]
struct ParsedTestFixtureReceipt {
  latest_approval_digest: String,
  approval_sequence: u64,
  state_generation: u64,
  key_id: String,
  registry_byte_digest: String,
}

/// Parse the unified test-namespace current-state receipt. The exact closed
/// shape is shared byte-for-byte with the parent-side fixture writer
/// (`scripts/capsec/rev2_target_policy.ts`): `{approvalSequence, authority,
/// grantsProductionAuthority, keyId, latestApprovalDigest, notice,
/// recordedAtEpochSeconds, registryByteDigest, schema, stateGeneration}`,
/// with `authority` exactly `test-authority`, `grantsProductionAuthority`
/// exactly `false`, and a `notice` that declares the receipt TEST-ONLY.
#[cfg(test)]
fn parse_test_fixture_receipt(
  receipt_jcs: &[u8],
) -> Result<ParsedTestFixtureReceipt, OdenTargetPolicySessionError> {
  use OdenTargetPolicySessionError::InvalidTestAuthorityFixture;

  if receipt_jcs.is_empty()
    || receipt_jcs.len() > ODEN_TARGET_POLICY_TEST_FIXTURE_RECEIPT_JCS_MAX_BYTES
  {
    return Err(InvalidTestAuthorityFixture(
      "receipt JCS byte length is outside the fixture bound",
    ));
  }
  let OdenParentStrictJsonValue(value) = serde_json::from_slice::<
    OdenParentStrictJsonValue,
  >(receipt_jcs)
  .map_err(|_| InvalidTestAuthorityFixture("receipt is not strict I-JSON"))?;
  if canonical_value_jcs(&value)? != receipt_jcs {
    return Err(InvalidTestAuthorityFixture(
      "receipt bytes are not the exact canonical JSON rendering",
    ));
  }
  let root = value
    .as_object()
    .ok_or(InvalidTestAuthorityFixture("receipt is not an object"))?;
  let keys = [
    "approvalSequence",
    "authority",
    "grantsProductionAuthority",
    "keyId",
    "latestApprovalDigest",
    "notice",
    "recordedAtEpochSeconds",
    "registryByteDigest",
    "schema",
    "stateGeneration",
  ];
  if root.len() != keys.len() || keys.iter().any(|key| !root.contains_key(*key))
  {
    return Err(InvalidTestAuthorityFixture(
      "receipt does not have the exact closed key set",
    ));
  }
  if root.get("schema").and_then(serde_json::Value::as_str)
    != Some(ODEN_TARGET_POLICY_TEST_FIXTURE_RECEIPT_SCHEMA)
  {
    return Err(InvalidTestAuthorityFixture(
      "receipt schema is not the test-fixture literal",
    ));
  }
  if root.get("authority").and_then(serde_json::Value::as_str)
    != Some("test-authority")
  {
    return Err(InvalidTestAuthorityFixture(
      "receipt authority is not exactly test-authority",
    ));
  }
  if root
    .get("grantsProductionAuthority")
    .and_then(serde_json::Value::as_bool)
    != Some(false)
  {
    return Err(InvalidTestAuthorityFixture(
      "receipt grantsProductionAuthority must be exactly false",
    ));
  }
  let notice = root
    .get("notice")
    .and_then(serde_json::Value::as_str)
    .ok_or(InvalidTestAuthorityFixture(
      "receipt notice is not a string",
    ))?;
  if !notice.contains("TEST-ONLY") {
    return Err(InvalidTestAuthorityFixture(
      "receipt notice does not declare the receipt TEST-ONLY",
    ));
  }
  let parse_digest =
    |key: &'static str| -> Result<String, OdenTargetPolicySessionError> {
      let digest = root.get(key).and_then(serde_json::Value::as_str).ok_or(
        InvalidTestAuthorityFixture("receipt digest is not a string"),
      )?;
      CanonicalSha256Digest::parse(key, digest).map_err(|_| {
        InvalidTestAuthorityFixture(
          "receipt digest is not a canonical sha256 digest",
        )
      })?;
      Ok(digest.to_string())
    };
  let latest_approval_digest = parse_digest("latestApprovalDigest")?;
  let key_id = parse_digest("keyId")?;
  let registry_byte_digest = parse_digest("registryByteDigest")?;
  let approval_sequence = root
    .get("approvalSequence")
    .and_then(serde_json::Value::as_u64)
    .filter(|sequence| *sequence >= 1 && *sequence <= MAX_IJSON_SAFE_INTEGER)
    .ok_or(InvalidTestAuthorityFixture(
      "receipt approvalSequence is not a positive safe integer",
    ))?;
  let state_generation = root
    .get("stateGeneration")
    .and_then(serde_json::Value::as_u64)
    .filter(|generation| *generation <= MAX_IJSON_SAFE_INTEGER)
    .ok_or(InvalidTestAuthorityFixture(
      "receipt stateGeneration is not a nonnegative safe integer",
    ))?;
  if root
    .get("recordedAtEpochSeconds")
    .and_then(serde_json::Value::as_u64)
    .filter(|seconds| *seconds <= MAX_IJSON_SAFE_INTEGER)
    .is_none()
  {
    return Err(InvalidTestAuthorityFixture(
      "receipt recordedAtEpochSeconds is not a nonnegative safe integer",
    ));
  }
  Ok(ParsedTestFixtureReceipt {
    latest_approval_digest,
    approval_sequence,
    state_generation,
    key_id,
    registry_byte_digest,
  })
}

/// One fresh generative verifier session begun by the verified bootstrap TCB.
/// Guards, validated registries, and checked selections are all scoped to a
/// borrow of one session and cannot outlive it.
///
/// Production construction of the whole family remains refusing until the
/// authenticated linearizable durable current-state/lease authority exists
/// (spec: the approval key, protected issuance clock, and rollback-resistant
/// latest-approval transition are a separate unimplemented checkpoint). When
/// that authority lands, witness ISSUANCE and witness CONSUMPTION must each
/// perform the authenticated linearizable current-state/lease check — the
/// in-process generation counter re-checked today is a stand-in for, not an
/// implementation of, that check. This is a tracked blocker, not implemented
/// here.
pub struct FilesystemFinalLtoPolicyVerifierSession<'tcb> {
  tcb: &'tcb VerifiedFilesystemFinalLtoBootstrapTCB,
  _not_send_sync: PhantomData<*const ()>,
}

impl<'tcb> FilesystemFinalLtoPolicyVerifierSession<'tcb> {
  /// Cryptographically check the retained approval preimages against this
  /// TCB's configured key and protected current state, and mint the private
  /// session-scoped approval guard.
  pub fn verify_current_approval<'session>(
    &'session self,
    approval_jcs: &[u8],
    detached_signature: &[u8; 64],
  ) -> Result<
    CurrentFilesystemFinalLtoApprovalGuard<'session>,
    OdenTargetPolicySessionError,
  >
  where
    'tcb: 'session,
  {
    let facts = parse_and_verify_approval(
      &self.tcb.approval_public_key,
      approval_jcs,
      detached_signature,
    )?;
    if facts.approval_sequence != self.tcb.receipt_approval_sequence {
      return Err(OdenTargetPolicySessionError::CurrentStateMismatch(
        "approval sequence is not the protected current sequence",
      ));
    }
    if facts.approval_digest.as_str() != self.tcb.receipt_approval_digest {
      return Err(OdenTargetPolicySessionError::CurrentStateMismatch(
        "approval digest is not the protected current approval (stale, \
         superseded, or forked)",
      ));
    }
    if facts.registry_byte_digest.as_str()
      != self.tcb.receipt_registry_byte_digest
    {
      return Err(OdenTargetPolicySessionError::CurrentStateMismatch(
        "approval statement registryByteDigest is not the protected current \
         registry-byte identity",
      ));
    }
    Ok(CurrentFilesystemFinalLtoApprovalGuard {
      session: self,
      approval: VerifiedFilesystemFinalLtoPolicyApproval {
        target_policy_approval_digest: facts.approval_digest,
        registry_byte_digest: facts.registry_byte_digest,
        policy_revision: facts.policy_revision,
        approval_sequence: facts.approval_sequence,
        issued_at_epoch_seconds: facts.issued_at_epoch_seconds,
        _session: PhantomData,
        _not_send_sync: PhantomData,
      },
      generation_at_creation: self.tcb.current_state_generation.get(),
      _not_send_sync: PhantomData,
    })
  }
}

/// Verified approval whose public projection is exactly the five frozen
/// fields. The private session brand cannot be constructed by callers.
pub struct VerifiedFilesystemFinalLtoPolicyApproval<'session> {
  target_policy_approval_digest: CanonicalSha256Digest,
  registry_byte_digest: CanonicalSha256Digest,
  policy_revision: u64,
  approval_sequence: u64,
  issued_at_epoch_seconds: u64,
  _session: PhantomData<&'session ()>,
  _not_send_sync: PhantomData<*const ()>,
}

impl VerifiedFilesystemFinalLtoPolicyApproval<'_> {
  pub fn target_policy_approval_digest(&self) -> &str {
    self.target_policy_approval_digest.as_str()
  }

  pub fn registry_byte_digest(&self) -> &str {
    self.registry_byte_digest.as_str()
  }

  pub fn policy_revision(&self) -> u64 {
    self.policy_revision
  }

  pub fn approval_sequence(&self) -> u64 {
    self.approval_sequence
  }

  pub fn issued_at_epoch_seconds(&self) -> u64 {
    self.issued_at_epoch_seconds
  }
}

/// Private current-approval guard held by the session. An in-process
/// generation change (the test-only stand-in for a protected current-state
/// transition) invalidates the guard and every unconsumed witness. It is
/// never serialized (no serde) and cannot be transferred across threads
/// (!Send + !Sync). Those properties are WITHIN one process only: !Send +
/// !Sync does NOT prevent `fork()` from duplicating the guard into a child,
/// and there is no cross-process, cross-phase, external-revocation, or
/// protected-clock guarantee here — those await the durable current-state
/// authority.
pub struct CurrentFilesystemFinalLtoApprovalGuard<'session> {
  session: &'session FilesystemFinalLtoPolicyVerifierSession<'session>,
  approval: VerifiedFilesystemFinalLtoPolicyApproval<'session>,
  generation_at_creation: u64,
  _not_send_sync: PhantomData<*const ()>,
}

impl<'session> CurrentFilesystemFinalLtoApprovalGuard<'session> {
  pub fn approval(
    &self,
  ) -> &VerifiedFilesystemFinalLtoPolicyApproval<'session> {
    &self.approval
  }

  fn require_live(&self) -> Result<(), OdenTargetPolicySessionError> {
    if self.session.tcb.current_state_generation.get()
      != self.generation_at_creation
    {
      return Err(OdenTargetPolicySessionError::GuardInvalidated(
        "protected current-state generation changed after guard creation",
      ));
    }
    if self.approval.target_policy_approval_digest.as_str()
      != self.session.tcb.receipt_approval_digest
      || self.approval.approval_sequence
        != self.session.tcb.receipt_approval_sequence
    {
      return Err(OdenTargetPolicySessionError::GuardInvalidated(
        "guard approval no longer matches the protected current state",
      ));
    }
    Ok(())
  }

  /// Re-check the same approval digest, sequence, and protected current-state
  /// generation, then yield one private single-use witness, consuming this
  /// guard by value: one `verify_current_approval` yields at most one witness,
  /// matching the spec's single-use witness and a fresh guard / in-session
  /// re-verification per witness issuance — NOT cross-phase or fresh-session
  /// revalidation (that awaits the still-absent durable current-state
  /// authority). A separate witness — and therefore a separate freshly
  /// re-verified guard — is required immediately before each guarded
  /// operation. NOTE: the liveness re-check is an in-process generation
  /// counter only; it is NOT the authenticated linearizable current-state /
  /// lease check (that awaits the still-absent durable current-state
  /// authority) and provides no cross-process (fork), cross-phase, or
  /// external-revocation guarantee.
  pub fn issue_approval_use(
    self,
  ) -> Result<
    CurrentFilesystemFinalLtoApprovalUse<'session>,
    OdenTargetPolicySessionError,
  > {
    self.require_live()?;
    Ok(CurrentFilesystemFinalLtoApprovalUse {
      session: self.session,
      approval_digest: CanonicalSha256Digest::parse(
        "targetPolicyApprovalDigest",
        self.approval.target_policy_approval_digest.as_str(),
      )?,
      approval_sequence: self.approval.approval_sequence,
      generation_at_issue: self.generation_at_creation,
      _not_send_sync: PhantomData,
    })
  }
}

/// Private single-use approval witness. Consumed by value by exactly one
/// guarded operation; not Clone, not Copy, never serialized.
pub struct CurrentFilesystemFinalLtoApprovalUse<'session> {
  session: &'session FilesystemFinalLtoPolicyVerifierSession<'session>,
  approval_digest: CanonicalSha256Digest,
  approval_sequence: u64,
  generation_at_issue: u64,
  _not_send_sync: PhantomData<*const ()>,
}

struct ValidatedTargetPolicyRow {
  target: &'static str,
  feature_set: String,
  wrapper_jcs: Vec<u8>,
  target_policy_digest: CanonicalSha256Digest,
}

/// Private opaque result of the complete atomic four-row validation. Only the
/// full validator below can create it; partial leaf assertions, a selected
/// row alone, carrier closure, a digest comparison, or a candidate manifest
/// cannot.
///
/// The single constructor (`validate_complete`) REQUIRES full statement/
/// registry coherence — the `/2` approval schema, `policyRevision` equality
/// with the parsed `/2` registry (both `1`), and the shared `:2` registry-
/// byte domain — and REFUSES any incoherence (in particular the
/// `/3`-over-`/2` hybrid) with a typed error, so no incoherent pair is ever
/// constructible into this type. There is no staged-migration escape hatch
/// and no advisory mismatch marker.
pub struct ValidatedFilesystemFinalLtoTargetPolicyRegistry<'session> {
  session: &'session FilesystemFinalLtoPolicyVerifierSession<'session>,
  registry_byte_digest: CanonicalSha256Digest,
  approval_digest: CanonicalSha256Digest,
  rows: Vec<ValidatedTargetPolicyRow>,
  _not_send_sync: PhantomData<*const ()>,
}

impl<'session> ValidatedFilesystemFinalLtoTargetPolicyRegistry<'session> {
  /// Complete atomic four-row validation. The exact retained canonical
  /// registry bytes and the live verified approval are the only variable
  /// inputs. All of canonical shape, schema/profile/revision literals, the
  /// frozen row order, per-row semantic closure, independent content
  /// identities, non-overlapping match domains, approved-byte equality under
  /// the shared `:2` registry-byte domain, AND statement-vs-parsed-registry
  /// `policyRevision` equality must pass atomically; any failure — including
  /// a statement whose revision does not equal the parsed `/2` registry's
  /// `policyRevision: 1` (the `/3`-over-`/2` hybrid) — returns a typed error
  /// without constructing the type.
  pub fn validate_complete(
    guard: &CurrentFilesystemFinalLtoApprovalGuard<'session>,
    registry_jcs: &[u8],
  ) -> Result<Self, OdenTargetPolicySessionError> {
    guard.require_live()?;

    // Canonical shape, exact JCS bytes, closed registry envelope, frozen
    // four-row order, and per-ordinal target/featureSet generated identity.
    let target_policies =
      take_oden_parent_target_policy_registry_rows(registry_jcs)?;

    // Approved-byte equality: the registry bytes must be exactly the bytes
    // named by the verified `/2` approval statement, whose `registryByteDigest`
    // is HBYTES under the `:2` registry-byte domain — the SAME domain the `/2`
    // registry and landed carrier relation use (coherent single identity).
    let registry_byte_digest = framed_sha256_digest(
      ODEN_TARGET_POLICY_APPROVAL_REGISTRY_BYTES_DIGEST_DOMAIN,
      registry_jcs,
    );
    if registry_byte_digest.as_str() != guard.approval.registry_byte_digest() {
      return Err(OdenTargetPolicySessionError::RegistryNotApproved);
    }
    // Statement-vs-parsed-registry policyRevision COHERENCE (required): the
    // registry's own literal (`policyRevision: 1`) was already enforced by
    // the canonical envelope closure above; the `/2` approval statement's
    // literal is pinned to `1` by intrinsic validation. They MUST be equal
    // here — any mismatch (a `/3` revision-2 statement over the `/2`
    // revision-1 registry) is a hard typed REFUSAL, making Validated/Checked
    // UNconstructible over an incoherent pair. There is no advisory marker.
    if guard.approval.policy_revision() != ODEN_PARENT_TARGET_POLICY_REVISION {
      return Err(
        OdenTargetPolicySessionError::StatementRegistryPolicyRevisionMismatch {
          statement: guard.approval.policy_revision(),
          registry: ODEN_PARENT_TARGET_POLICY_REVISION,
        },
      );
    }

    let mut rows = Vec::with_capacity(target_policies.len());
    for (index, target_policy) in target_policies.iter().enumerate() {
      // Per-row semantic closure. Until the reviewed registry file defines
      // additional row members, an unrecognized member cannot be semantically
      // or referentially closed and therefore refuses (fail closed).
      let row_object = target_policy.as_object().ok_or(
        OdenTargetPolicySessionError::RegistryRowNotClosed(
          "row is not an object",
        ),
      )?;
      let closed_keys = ["featureSet", "target"];
      if row_object.len() != closed_keys.len()
        || closed_keys.iter().any(|key| !row_object.contains_key(*key))
      {
        return Err(OdenTargetPolicySessionError::RegistryRowNotClosed(
          "row carries a member outside the reviewed closed member set",
        ));
      }
      let feature_set = row_object
        .get("featureSet")
        .and_then(serde_json::Value::as_str)
        .ok_or(OdenTargetPolicySessionError::RegistryRowNotClosed(
          "row featureSet is not a string",
        ))?
        .to_string();
      let wrapper = serde_json::json!({
        "schema": ODEN_PARENT_TARGET_POLICY_REGISTRY_SCHEMA,
        "profile": ODEN_PARENT_PROFILE,
        "policyRevision": ODEN_PARENT_TARGET_POLICY_REVISION,
        "targetPolicy": target_policy,
      });
      let wrapper_jcs = canonical_value_jcs(&wrapper)?;
      let target_policy_digest =
        hjcs_digest(ODEN_PARENT_TARGET_POLICY_DIGEST_DOMAIN, &wrapper_jcs)?;
      rows.push(ValidatedTargetPolicyRow {
        target: ODEN_PARENT_TARGET_POLICY_TARGET_ORDER[index],
        feature_set,
        wrapper_jcs,
        target_policy_digest,
      });
    }

    // Independent content identities and non-overlapping match domains.
    for left in 0..rows.len() {
      for right in (left + 1)..rows.len() {
        if rows[left].target == rows[right].target {
          return Err(
            OdenTargetPolicySessionError::RegistryRowIdentityOverlap(
              "two rows share one match-domain target",
            ),
          );
        }
        if rows[left].feature_set == rows[right].feature_set {
          return Err(
            OdenTargetPolicySessionError::RegistryRowIdentityOverlap(
              "two rows share one generated featureSet identity",
            ),
          );
        }
        if rows[left].target_policy_digest == rows[right].target_policy_digest {
          return Err(
            OdenTargetPolicySessionError::RegistryRowIdentityOverlap(
              "two rows share one selected-wrapper content identity",
            ),
          );
        }
      }
    }

    Ok(Self {
      session: guard.session,
      registry_byte_digest,
      approval_digest: CanonicalSha256Digest::parse(
        "targetPolicyApprovalDigest",
        guard.approval.target_policy_approval_digest(),
      )?,
      rows,
      _not_send_sync: PhantomData,
    })
  }

  /// HBYTES under the `/2` approval statement's `:2` registry-byte domain over
  /// the exact validated canonical registry bytes (equal to the statement's
  /// `registryByteDigest`).
  pub fn registry_byte_digest(&self) -> &str {
    self.registry_byte_digest.as_str()
  }

  pub fn target_policy_approval_digest(&self) -> &str {
    self.approval_digest.as_str()
  }
}

/// Private validated compiled identity consumed by the checked selection.
///
/// The spec's production constructor reads the eight compile-time build
/// markers plus native cfg results and requires equality with both the
/// externally retained catalog row and the embedded generated
/// `REV2_TARGET_STATUS` row. Neither the external catalog nor this crate's
/// access to those embedded markers exists yet (the generated registry module
/// is private to the `deno_permissions` crate), so the production constructor
/// refuses and the test constructor requires the caller-supplied featureSet
/// to equal this crate's frozen copy of the same generated identity
/// byte-for-byte. Caller-populated raw fields cannot create the type.
pub struct ValidatedFilesystemFinalLtoCompiledIdentity {
  target: &'static str,
  feature_set: String,
  _not_send_sync: PhantomData<*const ()>,
}

impl ValidatedFilesystemFinalLtoCompiledIdentity {
  /// Production constructor. Always refuses: the organization-provisioned
  /// compiled-identity catalog and this crate's build markers are absent.
  pub fn from_external_catalog_and_build_markers()
  -> Result<Self, OdenTargetPolicySessionError> {
    Err(OdenTargetPolicySessionError::ExternalCompiledIdentityAuthorityAbsent)
  }

  /// Test-only fixture constructor. The target must be one of the four
  /// frozen release targets and the featureSet must equal the generated Rev2
  /// identity for that target byte-for-byte; host detection, caller choice
  /// of a fifth target, or a reconstructed feature identity refuses.
  #[cfg(test)]
  pub(crate) fn new_test_fixture(
    target: &str,
    feature_set: &str,
  ) -> Result<Self, OdenTargetPolicySessionError> {
    let ordinal = ODEN_PARENT_TARGET_POLICY_TARGET_ORDER
      .iter()
      .position(|candidate| *candidate == target)
      .ok_or(OdenTargetPolicySessionError::InvalidCompiledIdentity(
        "target is not one of the four frozen release targets",
      ))?;
    let expected_feature_set = oden_parent_target_policy_feature_set(ordinal);
    if feature_set != expected_feature_set {
      return Err(OdenTargetPolicySessionError::InvalidCompiledIdentity(
        "featureSet differs byte-for-byte from the generated Rev2 identity",
      ));
    }
    Ok(Self {
      target: ODEN_PARENT_TARGET_POLICY_TARGET_ORDER[ordinal],
      feature_set: expected_feature_set,
      _not_send_sync: PhantomData,
    })
  }

  pub fn target(&self) -> &str {
    self.target
  }

  pub fn feature_set(&self) -> &str {
    &self.feature_set
  }
}

/// Private checked one-row selection. Requires the verified bootstrap TCB, a
/// live single-use approval witness, the complete validated registry, and the
/// private validated compiled identity; selects exactly one row by the
/// authenticated compiled target and its generated featureSet byte-for-byte
/// and recomputes the selected-row `targetPolicyDigest`. Host detection,
/// caller choice, fallback rows, and reconstructed feature identity refuse.
pub struct CheckedFilesystemFinalLtoTargetPolicySelection<'session> {
  target: &'static str,
  feature_set: String,
  target_policy_digest: CanonicalSha256Digest,
  target_policy_approval_digest: CanonicalSha256Digest,
  _session: PhantomData<&'session ()>,
  _not_send_sync: PhantomData<*const ()>,
}

impl<'session> CheckedFilesystemFinalLtoTargetPolicySelection<'session> {
  pub fn select(
    tcb: &VerifiedFilesystemFinalLtoBootstrapTCB,
    approval_use: CurrentFilesystemFinalLtoApprovalUse<'session>,
    registry: &ValidatedFilesystemFinalLtoTargetPolicyRegistry<'session>,
    compiled_identity: &ValidatedFilesystemFinalLtoCompiledIdentity,
  ) -> Result<Self, OdenTargetPolicySessionError> {
    // Witness/registry/TCB binding is by session-pointer identity and the
    // in-process generation counter only. This is NOT cross-process (fork)
    // confinement: a forked child would hold byte-identical pointers and
    // generation, so both copies would pass here. Real cross-process /
    // cross-phase / revocation confinement awaits the still-absent durable
    // current-state authority (which is why production construction refuses).
    if !std::ptr::eq(approval_use.session, registry.session) {
      return Err(OdenTargetPolicySessionError::ApprovalUseMismatch(
        "witness and validated registry come from different verifier sessions",
      ));
    }
    if !std::ptr::eq(approval_use.session.tcb, tcb) {
      return Err(OdenTargetPolicySessionError::ApprovalUseMismatch(
        "witness session was not begun by this verified bootstrap TCB",
      ));
    }
    if tcb.current_state_generation.get() != approval_use.generation_at_issue {
      return Err(OdenTargetPolicySessionError::GuardInvalidated(
        "protected current-state transition invalidated the unconsumed \
         witness",
      ));
    }
    if approval_use.approval_digest != registry.approval_digest
      || approval_use.approval_sequence != tcb.receipt_approval_sequence
    {
      return Err(OdenTargetPolicySessionError::ApprovalUseMismatch(
        "witness approval differs from the registry's verified approval",
      ));
    }
    let row = registry
      .rows
      .iter()
      .find(|row| row.target == compiled_identity.target())
      .ok_or(OdenTargetPolicySessionError::SelectionTargetMismatch)?;
    if row.feature_set.as_bytes() != compiled_identity.feature_set().as_bytes()
    {
      return Err(OdenTargetPolicySessionError::SelectionFeatureSetMismatch);
    }
    // Recompute the selected wrapper HJCS from the retained wrapper bytes.
    let recomputed =
      hjcs_digest(ODEN_PARENT_TARGET_POLICY_DIGEST_DOMAIN, &row.wrapper_jcs)?;
    if recomputed != row.target_policy_digest {
      return Err(OdenTargetPolicySessionError::SelectionDigestMismatch);
    }
    // The single-use witness is consumed here by value.
    let CurrentFilesystemFinalLtoApprovalUse { .. } = approval_use;
    Ok(Self {
      target: row.target,
      feature_set: row.feature_set.clone(),
      target_policy_digest: recomputed,
      target_policy_approval_digest: CanonicalSha256Digest::parse(
        "targetPolicyApprovalDigest",
        registry.approval_digest.as_str(),
      )?,
      _session: PhantomData,
      _not_send_sync: PhantomData,
    })
  }

  pub fn target(&self) -> &str {
    self.target
  }

  pub fn feature_set(&self) -> &str {
    &self.feature_set
  }

  /// HJCS under `oden:capsec:filesystem-final-lto-target-policy:2` over the
  /// exact selected `{schema, profile, policyRevision, targetPolicy}`
  /// wrapper. The whole-registry digest cannot substitute for this value.
  pub fn target_policy_digest(&self) -> &str {
    self.target_policy_digest.as_str()
  }

  pub fn target_policy_approval_digest(&self) -> &str {
    self.target_policy_approval_digest.as_str()
  }
}

struct VerifiedApprovalFacts {
  approval_digest: CanonicalSha256Digest,
  registry_byte_digest: CanonicalSha256Digest,
  policy_revision: u64,
  approval_sequence: u64,
  issued_at_epoch_seconds: u64,
}

fn parse_and_verify_approval(
  approval_public_key: &[u8; 32],
  approval_jcs: &[u8],
  detached_signature: &[u8; 64],
) -> Result<VerifiedApprovalFacts, OdenTargetPolicySessionError> {
  use OdenTargetPolicySessionError::InvalidApprovalCandidate;
  use OdenTargetPolicySessionError::InvalidApprovalField;

  if approval_jcs.is_empty()
    || approval_jcs.len() > ODEN_TARGET_POLICY_APPROVAL_JCS_MAX_BYTES
  {
    return Err(InvalidApprovalCandidate(
      "approval JCS byte length is outside the frozen bound",
    ));
  }
  let OdenParentStrictJsonValue(value) = serde_json::from_slice::<
    OdenParentStrictJsonValue,
  >(approval_jcs)
  .map_err(|error| {
    OdenTargetPolicySessionError::InvalidApprovalJson(error.to_string())
  })?;
  if canonical_value_jcs(&value)? != approval_jcs {
    return Err(InvalidApprovalCandidate(
      "bytes are not the exact canonical JSON rendering",
    ));
  }
  let root = value
    .as_object()
    .ok_or(InvalidApprovalCandidate("approval is not an object"))?;
  let outer_keys = [
    "keyId",
    "signatureAlgorithm",
    "signatureByteDigest",
    "statement",
  ];
  if root.len() != outer_keys.len()
    || outer_keys.iter().any(|key| !root.contains_key(*key))
  {
    return Err(InvalidApprovalCandidate(
      "approval does not have the exact closed key set",
    ));
  }
  if root
    .get("signatureAlgorithm")
    .and_then(serde_json::Value::as_str)
    != Some("ed25519")
  {
    return Err(InvalidApprovalField {
      field: "signatureAlgorithm",
      reason: "value must be exactly ed25519",
    });
  }

  // The candidate keyId cannot select, fetch, or replace a key: the
  // externally configured key is resolved first and the derived ID compared.
  let derived_key_id = framed_sha256_digest(
    ODEN_TARGET_POLICY_APPROVAL_PUBLIC_KEY_BYTES_DIGEST_DOMAIN,
    approval_public_key,
  );
  if root.get("keyId").and_then(serde_json::Value::as_str)
    != Some(derived_key_id.as_str())
  {
    return Err(OdenTargetPolicySessionError::ApprovalKeyMismatch);
  }
  let derived_signature_digest = framed_sha256_digest(
    ODEN_TARGET_POLICY_APPROVAL_SIGNATURE_BYTES_DIGEST_DOMAIN,
    detached_signature,
  );
  if root
    .get("signatureByteDigest")
    .and_then(serde_json::Value::as_str)
    != Some(derived_signature_digest.as_str())
  {
    return Err(OdenTargetPolicySessionError::ApprovalSignatureDigestMismatch);
  }

  let statement_value = root
    .get("statement")
    .ok_or(InvalidApprovalCandidate("statement is missing"))?;
  let statement = statement_value
    .as_object()
    .ok_or(InvalidApprovalCandidate("statement is not an object"))?;
  let statement_keys = [
    "approvalSequence",
    "issuedAtEpochSeconds",
    "policyRevision",
    "previousApprovalDigest",
    "registryByteDigest",
    "schema",
  ];
  if statement.len() != statement_keys.len()
    || statement_keys
      .iter()
      .any(|key| !statement.contains_key(*key))
  {
    return Err(InvalidApprovalCandidate(
      "statement does not have the exact closed key set",
    ));
  }
  if statement.get("schema").and_then(serde_json::Value::as_str)
    != Some(ODEN_TARGET_POLICY_APPROVAL_SCHEMA)
  {
    return Err(InvalidApprovalField {
      field: "schema",
      reason: "value differs from the approval schema literal",
    });
  }
  let registry_byte_digest = statement
    .get("registryByteDigest")
    .and_then(serde_json::Value::as_str)
    .ok_or(InvalidApprovalField {
      field: "registryByteDigest",
      reason: "value is not a string",
    })?;
  let registry_byte_digest =
    CanonicalSha256Digest::parse("registryByteDigest", registry_byte_digest)
      .map_err(|_| InvalidApprovalField {
        field: "registryByteDigest",
        reason: "value is not a canonical sha256 digest",
      })?;
  // Intrinsic `/2` statement validation pins the schema-const revision `1`.
  // Equality with the parsed registry's `policyRevision` is enforced later,
  // in complete registry validation, which REFUSES any mismatch with a typed
  // error (no registry is in scope here yet).
  let policy_revision = statement
    .get("policyRevision")
    .and_then(serde_json::Value::as_u64)
    .filter(|revision| {
      *revision == ODEN_TARGET_POLICY_APPROVAL_STATEMENT_POLICY_REVISION
    })
    .ok_or(InvalidApprovalField {
      field: "policyRevision",
      reason: "value differs from the /2 approval statement's const revision",
    })?;
  let approval_sequence = statement
    .get("approvalSequence")
    .and_then(serde_json::Value::as_u64)
    .filter(|sequence| *sequence >= 1 && *sequence <= MAX_IJSON_SAFE_INTEGER)
    .ok_or(InvalidApprovalField {
      field: "approvalSequence",
      reason: "value is not a positive safe integer",
    })?;
  match statement.get("previousApprovalDigest") {
    Some(serde_json::Value::Null) => {
      if approval_sequence != 1 {
        return Err(InvalidApprovalField {
          field: "previousApprovalDigest",
          reason: "null is admissible exactly for the genesis sequence",
        });
      }
    }
    Some(serde_json::Value::String(previous)) => {
      if approval_sequence == 1 {
        return Err(InvalidApprovalField {
          field: "previousApprovalDigest",
          reason: "the genesis sequence requires exactly null",
        });
      }
      CanonicalSha256Digest::parse("previousApprovalDigest", previous.clone())
        .map_err(|_| InvalidApprovalField {
          field: "previousApprovalDigest",
          reason: "value is not a canonical sha256 digest",
        })?;
    }
    _ => {
      return Err(InvalidApprovalField {
        field: "previousApprovalDigest",
        reason: "value must be null or one canonical predecessor digest",
      });
    }
  }
  let issued_at_epoch_seconds = statement
    .get("issuedAtEpochSeconds")
    .and_then(serde_json::Value::as_u64)
    .filter(|seconds| *seconds <= MAX_IJSON_SAFE_INTEGER)
    .ok_or(InvalidApprovalField {
      field: "issuedAtEpochSeconds",
      reason: "value is not a nonnegative safe integer",
    })?;

  // The exact signed message is the framing domain, one NUL, and the
  // statement JCS. Verification uses the strict pure-Ed25519 profile.
  let statement_jcs = canonical_value_jcs(statement_value)?;
  let mut message = Vec::with_capacity(
    ODEN_TARGET_POLICY_APPROVAL_SIGNATURE_FRAMING_DOMAIN.len()
      + 1
      + statement_jcs.len(),
  );
  message.extend_from_slice(
    ODEN_TARGET_POLICY_APPROVAL_SIGNATURE_FRAMING_DOMAIN.as_bytes(),
  );
  message.push(0);
  message.extend_from_slice(&statement_jcs);
  verify_ed25519_strict(approval_public_key, &message, detached_signature)?;

  let approval_digest =
    hjcs_digest(ODEN_TARGET_POLICY_APPROVAL_DIGEST_DOMAIN, approval_jcs)?;
  Ok(VerifiedApprovalFacts {
    approval_digest,
    registry_byte_digest,
    policy_revision,
    approval_sequence,
    issued_at_epoch_seconds,
  })
}

/// Strict pure-Ed25519 point/scalar/subgroup profile: canonical compressed
/// public-key and R points, nonidentity/non-small-order prime-subgroup
/// membership, canonical `0 <= S < L`, and the ordinary non-cofactored
/// verification equation. Alternate encodings, torsion or non-subgroup
/// points, reduced noncanonical scalars, prehash, and context variants all
/// refuse structurally (this function accepts only 32/64 raw-byte inputs and
/// the plain message).
fn verify_ed25519_strict(
  public_key: &[u8; 32],
  message: &[u8],
  signature: &[u8; 64],
) -> Result<(), OdenTargetPolicySessionError> {
  let public_point = decompress_strict_point(public_key)?;
  let mut r_bytes = [0_u8; 32];
  r_bytes.copy_from_slice(&signature[..32]);
  let r_point = decompress_strict_point(&r_bytes)?;
  let mut s_bytes = [0_u8; 32];
  s_bytes.copy_from_slice(&signature[32..]);
  let s_scalar: Option<Scalar> = Scalar::from_canonical_bytes(s_bytes).into();
  let s_scalar =
    s_scalar.ok_or(OdenTargetPolicySessionError::ApprovalSignatureInvalid(
      "scalar S is not canonical (0 <= S < L)",
    ))?;
  let mut hasher = Sha512::new();
  hasher.update(r_bytes);
  hasher.update(public_key);
  hasher.update(message);
  let challenge_wide: [u8; 64] = hasher.finalize().into();
  let challenge = Scalar::from_bytes_mod_order_wide(&challenge_wide);
  // Ordinary non-cofactored equation: [S]B = R + [k]A, checked as
  // [k](-A) + [S]B == R with full point equality.
  let recomputed = EdwardsPoint::vartime_double_scalar_mul_basepoint(
    &challenge,
    &(-public_point),
    &s_scalar,
  );
  if recomputed != r_point {
    return Err(OdenTargetPolicySessionError::ApprovalSignatureInvalid(
      "non-cofactored verification equation failed",
    ));
  }
  Ok(())
}

fn decompress_strict_point(
  bytes: &[u8; 32],
) -> Result<EdwardsPoint, OdenTargetPolicySessionError> {
  let point = CompressedEdwardsY(*bytes).decompress().ok_or(
    OdenTargetPolicySessionError::ApprovalSignatureInvalid(
      "point encoding does not decompress",
    ),
  )?;
  if point.compress().as_bytes() != bytes {
    return Err(OdenTargetPolicySessionError::ApprovalSignatureInvalid(
      "point encoding is not canonical",
    ));
  }
  if point.is_small_order() {
    return Err(OdenTargetPolicySessionError::ApprovalSignatureInvalid(
      "point is the identity or has small order",
    ));
  }
  if !point.is_torsion_free() {
    return Err(OdenTargetPolicySessionError::ApprovalSignatureInvalid(
      "point is not in the prime-order subgroup",
    ));
  }
  Ok(point)
}

#[cfg(test)]
mod tests {
  use sha2::Sha256;

  use super::*;

  const TEST_SEED: [u8; 32] = [7_u8; 32];
  const OTHER_SEED: [u8; 32] = [11_u8; 32];
  const TEST_ISSUED_AT: u64 = 1_752_000_000;
  /// Little-endian bytes of the Ed25519 prime subgroup order L.
  const L_BYTES: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2,
    0xde, 0xf9, 0xde, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
  ];
  /// Little-endian bytes of 2^252 (the power-of-two part of L), for
  /// upper-range noncanonical-scalar vectors adjacent to L's structure.
  const TWO_POW_252_BYTES: [u8; 32] = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
  ];
  /// Canonical encoding of the Ed25519 identity point (y = 1).
  const IDENTITY_POINT_ENCODING: [u8; 32] = [
    1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0,
  ];
  /// Canonical encoding of an order-4 (8-torsion) point: y = 0 with x-sign
  /// bit 0 selects x = +sqrt(-1), a canonical small-order encoding.
  const SMALL_ORDER_POINT_ENCODING: [u8; 32] = [0_u8; 32];
  /// Noncanonical point encodings: y = p (reduces to y = 0) with both x-sign
  /// bits. Strict decompression must refuse both before any group check.
  const NONCANONICAL_Y_EQ_P_ENCODING: [u8; 32] = [
    0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
  ];
  const NONCANONICAL_Y_EQ_P_SIGN_BIT_ENCODING: [u8; 32] = [
    0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  ];
  /// Little-endian S+L malleability vector for the CURRENT coherent `/2`
  /// golden detached signature (S is canonical `S < L`; S+L is a distinct
  /// 32-byte little-endian scalar that a lax verifier reducing mod L would
  /// wrongly accept). The S+L test below recomputes it from the actual golden
  /// S and requires equality before exercising the refusal.
  const GOLDEN_S_PLUS_L_LE_HEX: &str =
    "cc5550279b379e520145979bd147eda314a768d68312839f9ad1b09d51e05d1d";
  // The synthetic test registry's rows are exactly {target, featureSet} with
  // the generated identities, so its canonical bytes equal the reviewed
  // parent registry file byte-for-byte and these vectors equal the golden
  // cross-integration vectors below.
  const REGISTRY_BYTE_DIGEST_VECTOR: &str = GOLDEN_REGISTRY_BYTE_DIGEST;
  const ROW0_TARGET_POLICY_DIGEST_VECTOR: &str =
    "sha256-VDeCBZnJr3WNmIguy3EJxekIhMcX0eUKgtWJiT_Nblg";

  // ===== Golden cross-integration fixtures (CP1 parent artifacts) =====
  //
  // Provenance: the four artifact byte files under
  // `testdata/oden_target_policy/` are EXACT byte copies of the parent-repo
  // artifacts produced by the deterministic parent-side generator
  // `scripts/capsec/rev2_target_policy.ts`:
  //
  //   filesystem-final-lto-target-policy.json
  //     <- capsec/rev2/registry/filesystem-final-lto-target-policy.json
  //   approval.json          <- capsec/rev2/fixtures/test-authority/approval.json
  //   approval-signature.bin <- capsec/rev2/fixtures/test-authority/approval-signature.bin
  //   ed25519-public-key.bin <- capsec/rev2/fixtures/test-authority/ed25519-public-key.bin
  //   test-current-state.json<- capsec/rev2/fixtures/test-authority/test-current-state.json
  //
  // Regenerate in the parent repo with
  //   deno run -A scripts/capsec/rev2_target_policy.ts \
  //     --write-registry --write-test-authority \
  //     --test-authority capsec/rev2/fixtures/test-authority
  // then re-copy the bytes here and update the golden digest constants in
  // BOTH pinning sites (that script and this module) in the same change.
  // The test authority is a well-known, publicly derivable TEST-ONLY key
  // (seed = SHA-256("oden:capsec:test-authority:ed25519:v1")); it grants no
  // production authority anywhere.
  const GOLDEN_REGISTRY_JCS: &[u8] = include_bytes!(
    "testdata/oden_target_policy/filesystem-final-lto-target-policy.json"
  );
  const GOLDEN_APPROVAL_JCS: &[u8] =
    include_bytes!("testdata/oden_target_policy/approval.json");
  const GOLDEN_APPROVAL_SIGNATURE: &[u8] =
    include_bytes!("testdata/oden_target_policy/approval-signature.bin");
  const GOLDEN_PUBLIC_KEY: &[u8] =
    include_bytes!("testdata/oden_target_policy/ed25519-public-key.bin");
  const GOLDEN_CURRENT_STATE_RECEIPT_JCS: &[u8] =
    include_bytes!("testdata/oden_target_policy/test-current-state.json");
  const GOLDEN_REGISTRY_BYTE_DIGEST: &str =
    "sha256-w9co3swyrmVlOi7pC-AY7_5EIFXh24Pp8rTWiuyCaw0";
  const GOLDEN_TARGET_POLICY_DIGESTS: [&str; 4] = [
    "sha256-VDeCBZnJr3WNmIguy3EJxekIhMcX0eUKgtWJiT_Nblg",
    "sha256-WDoLpqB0-rEMeVnPLsqMB8lXG02HoVxhEW1bPGPkaU0",
    "sha256-cY0Wub-Xu_zLaAm-ogepRNwCXSRQd_6N9ewZ9STgVPs",
    "sha256--ZrECsKvcbdR-8CYYZ6Wwav-jvhgWNOkff8_o5SgZ1w",
  ];
  const GOLDEN_APPROVAL_DIGEST: &str =
    "sha256-MHKpiWx2bvCr1OySZNxccf8s5VJ4i_ikCEVOOhL5f7E";
  const GOLDEN_APPROVAL_SIGNATURE_BYTE_DIGEST: &str =
    "sha256-h0lq5zxCu3-Z6GUAbcyrXXFWHqw-fch-4bKaF0IzB9k";
  const GOLDEN_KEY_ID: &str =
    "sha256-klO1cvvohAH-s3QgHuFalxHR4zv2KW1fnMURElsM58c";
  const GOLDEN_ISSUED_AT_EPOCH_SECONDS: u64 = 1_784_505_600;

  fn ed25519_test_public_key(seed: &[u8; 32]) -> [u8; 32] {
    let (scalar, _prefix) = ed25519_test_expanded_seed(seed);
    EdwardsPoint::mul_base(&scalar).compress().to_bytes()
  }

  fn ed25519_test_expanded_seed(seed: &[u8; 32]) -> (Scalar, [u8; 32]) {
    let expanded: [u8; 64] = Sha512::digest(seed).into();
    let mut scalar_bytes = [0_u8; 32];
    scalar_bytes.copy_from_slice(&expanded[..32]);
    scalar_bytes[0] &= 248;
    scalar_bytes[31] &= 127;
    scalar_bytes[31] |= 64;
    let mut prefix = [0_u8; 32];
    prefix.copy_from_slice(&expanded[32..]);
    (Scalar::from_bytes_mod_order(scalar_bytes), prefix)
  }

  fn ed25519_test_sign(seed: &[u8; 32], message: &[u8]) -> [u8; 64] {
    let (secret_scalar, prefix) = ed25519_test_expanded_seed(seed);
    let public_bytes =
      EdwardsPoint::mul_base(&secret_scalar).compress().to_bytes();
    let mut hasher = Sha512::new();
    hasher.update(prefix);
    hasher.update(message);
    let nonce_wide: [u8; 64] = hasher.finalize().into();
    let nonce = Scalar::from_bytes_mod_order_wide(&nonce_wide);
    let r_bytes = EdwardsPoint::mul_base(&nonce).compress().to_bytes();
    let mut hasher = Sha512::new();
    hasher.update(r_bytes);
    hasher.update(public_bytes);
    hasher.update(message);
    let challenge_wide: [u8; 64] = hasher.finalize().into();
    let challenge = Scalar::from_bytes_mod_order_wide(&challenge_wide);
    let s_scalar = nonce + challenge * secret_scalar;
    let mut signature = [0_u8; 64];
    signature[..32].copy_from_slice(&r_bytes);
    signature[32..].copy_from_slice(s_scalar.as_bytes());
    signature
  }

  fn test_registry_value() -> serde_json::Value {
    let targets: Vec<serde_json::Value> =
      ODEN_PARENT_TARGET_POLICY_TARGET_ORDER
        .iter()
        .enumerate()
        .map(|(index, target)| {
          serde_json::json!({
            "target": target,
            "featureSet": oden_parent_target_policy_feature_set(index),
          })
        })
        .collect();
    serde_json::json!({
      "schema": ODEN_PARENT_TARGET_POLICY_REGISTRY_SCHEMA,
      "profile": ODEN_PARENT_PROFILE,
      "policyRevision": ODEN_PARENT_TARGET_POLICY_REVISION,
      "targets": targets,
    })
  }

  fn test_registry_jcs() -> Vec<u8> {
    canonical_value_jcs(&test_registry_value()).unwrap()
  }

  fn test_statement_value(
    registry_jcs: &[u8],
    approval_sequence: u64,
    previous_approval_digest: serde_json::Value,
    issued_at_epoch_seconds: u64,
  ) -> serde_json::Value {
    serde_json::json!({
      "schema": ODEN_TARGET_POLICY_APPROVAL_SCHEMA,
      "registryByteDigest": framed_sha256_digest(
        ODEN_TARGET_POLICY_APPROVAL_REGISTRY_BYTES_DIGEST_DOMAIN,
        registry_jcs,
      ).as_str(),
      "policyRevision": ODEN_TARGET_POLICY_APPROVAL_STATEMENT_POLICY_REVISION,
      "approvalSequence": approval_sequence,
      "previousApprovalDigest": previous_approval_digest,
      "issuedAtEpochSeconds": issued_at_epoch_seconds,
    })
  }

  fn signed_approval_for_statement(
    seed: &[u8; 32],
    statement: &serde_json::Value,
  ) -> (Vec<u8>, [u8; 64]) {
    let statement_jcs = canonical_value_jcs(statement).unwrap();
    let mut message = Vec::new();
    message.extend_from_slice(
      ODEN_TARGET_POLICY_APPROVAL_SIGNATURE_FRAMING_DOMAIN.as_bytes(),
    );
    message.push(0);
    message.extend_from_slice(&statement_jcs);
    let signature = ed25519_test_sign(seed, &message);
    let public_key = ed25519_test_public_key(seed);
    let approval = serde_json::json!({
      "statement": statement,
      "signatureAlgorithm": "ed25519",
      "keyId": framed_sha256_digest(
        ODEN_TARGET_POLICY_APPROVAL_PUBLIC_KEY_BYTES_DIGEST_DOMAIN,
        &public_key,
      ).as_str(),
      "signatureByteDigest": framed_sha256_digest(
        ODEN_TARGET_POLICY_APPROVAL_SIGNATURE_BYTES_DIGEST_DOMAIN,
        &signature,
      ).as_str(),
    });
    (canonical_value_jcs(&approval).unwrap(), signature)
  }

  fn genesis_approval(
    seed: &[u8; 32],
    registry_jcs: &[u8],
  ) -> (Vec<u8>, [u8; 64]) {
    let statement = test_statement_value(
      registry_jcs,
      1,
      serde_json::Value::Null,
      TEST_ISSUED_AT,
    );
    signed_approval_for_statement(seed, &statement)
  }

  /// Build the unified test-namespace current-state receipt (exact shape
  /// shared with the parent-side fixture writer). `configured_seed` is the
  /// seed of the key the TCB will be configured with; the receipt's `keyId`
  /// must derive from that key. `registryByteDigest` is copied from the
  /// approval statement so the receipt names the same registry-byte
  /// identity the statement binds.
  fn test_receipt_for_approval(
    configured_seed: &[u8; 32],
    approval_jcs: &[u8],
    approval_sequence: u64,
    generation: u64,
  ) -> Vec<u8> {
    let approval_digest =
      hjcs_digest(ODEN_TARGET_POLICY_APPROVAL_DIGEST_DOMAIN, approval_jcs)
        .unwrap();
    let approval: serde_json::Value =
      serde_json::from_slice(approval_jcs).unwrap();
    let registry_byte_digest = approval
      .get("statement")
      .and_then(|statement| statement.get("registryByteDigest"))
      .and_then(serde_json::Value::as_str)
      .unwrap()
      .to_string();
    let key_id = framed_sha256_digest(
      ODEN_TARGET_POLICY_APPROVAL_PUBLIC_KEY_BYTES_DIGEST_DOMAIN,
      &ed25519_test_public_key(configured_seed),
    );
    canonical_value_jcs(&serde_json::json!({
      "schema": ODEN_TARGET_POLICY_TEST_FIXTURE_RECEIPT_SCHEMA,
      "authority": "test-authority",
      "grantsProductionAuthority": false,
      "approvalSequence": approval_sequence,
      "stateGeneration": generation,
      "keyId": key_id.as_str(),
      "latestApprovalDigest": approval_digest.as_str(),
      "registryByteDigest": registry_byte_digest,
      "recordedAtEpochSeconds": TEST_ISSUED_AT,
      "notice": "TEST-ONLY current-state receipt for fork-side session tests.",
    }))
    .unwrap()
  }

  fn test_tcb_for_approval(
    seed: &[u8; 32],
    approval_jcs: &[u8],
    approval_sequence: u64,
  ) -> VerifiedFilesystemFinalLtoBootstrapTCB {
    let receipt =
      test_receipt_for_approval(seed, approval_jcs, approval_sequence, 1);
    VerifiedFilesystemFinalLtoBootstrapTCB::new_test_authority_fixture(
      ed25519_test_public_key(seed),
      &receipt,
    )
    .unwrap()
  }

  fn test_compiled_identity(
    ordinal: usize,
  ) -> ValidatedFilesystemFinalLtoCompiledIdentity {
    ValidatedFilesystemFinalLtoCompiledIdentity::new_test_fixture(
      ODEN_PARENT_TARGET_POLICY_TARGET_ORDER[ordinal],
      &oden_parent_target_policy_feature_set(ordinal),
    )
    .unwrap()
  }

  #[test]
  fn production_tcb_constructor_refuses() {
    assert_eq!(
      VerifiedFilesystemFinalLtoBootstrapTCB::from_external_release_authority()
        .err(),
      Some(OdenTargetPolicySessionError::ExternalCurrentStateAuthorityAbsent),
    );
  }

  #[test]
  fn production_compiled_identity_constructor_refuses() {
    assert_eq!(
      ValidatedFilesystemFinalLtoCompiledIdentity::from_external_catalog_and_build_markers()
        .err(),
      Some(
        OdenTargetPolicySessionError::ExternalCompiledIdentityAuthorityAbsent
      ),
    );
  }

  #[test]
  fn end_to_end_selection_and_stable_digest_vectors() {
    let registry_jcs = test_registry_jcs();
    let (approval_jcs, signature) = genesis_approval(&TEST_SEED, &registry_jcs);
    let tcb = test_tcb_for_approval(&TEST_SEED, &approval_jcs, 1);
    let session = tcb.begin_policy_verifier_session();
    let guard = session
      .verify_current_approval(&approval_jcs, &signature)
      .unwrap();
    assert_eq!(
      guard.approval().policy_revision(),
      ODEN_TARGET_POLICY_APPROVAL_STATEMENT_POLICY_REVISION,
    );
    assert_eq!(guard.approval().approval_sequence(), 1);
    assert_eq!(guard.approval().issued_at_epoch_seconds(), TEST_ISSUED_AT);
    assert_eq!(
      guard.approval().registry_byte_digest(),
      REGISTRY_BYTE_DIGEST_VECTOR,
    );

    let registry =
      ValidatedFilesystemFinalLtoTargetPolicyRegistry::validate_complete(
        &guard,
        &registry_jcs,
      )
      .unwrap();
    assert_eq!(registry.registry_byte_digest(), REGISTRY_BYTE_DIGEST_VECTOR);
    // Coherent /2 pair: the approval statement's policyRevision (1) equals the
    // /2 registry's policyRevision (1), so validate_complete constructs the
    // registry with no advisory marker (there is no promotion-blocker concept
    // in this family at all).

    let identity = test_compiled_identity(0);
    let guard_approval_digest =
      guard.approval().target_policy_approval_digest().to_string();
    let approval_use = guard.issue_approval_use().unwrap();
    let selection = CheckedFilesystemFinalLtoTargetPolicySelection::select(
      &tcb,
      approval_use,
      &registry,
      &identity,
    )
    .unwrap();
    assert_eq!(selection.target(), "aarch64-apple-darwin");
    assert_eq!(
      selection.feature_set(),
      oden_parent_target_policy_feature_set(0),
    );
    assert_eq!(
      selection.target_policy_digest(),
      ROW0_TARGET_POLICY_DIGEST_VECTOR,
    );
    assert_eq!(
      selection.target_policy_approval_digest(),
      guard_approval_digest,
    );
    // The whole-registry digest must not substitute for the selected row.
    assert_ne!(
      selection.target_policy_digest(),
      registry.registry_byte_digest(),
    );
  }

  #[test]
  fn each_frozen_target_selects_its_own_distinct_row() {
    let registry_jcs = test_registry_jcs();
    let (approval_jcs, signature) = genesis_approval(&TEST_SEED, &registry_jcs);
    let tcb = test_tcb_for_approval(&TEST_SEED, &approval_jcs, 1);
    let session = tcb.begin_policy_verifier_session();
    let guard = session
      .verify_current_approval(&approval_jcs, &signature)
      .unwrap();
    let registry =
      ValidatedFilesystemFinalLtoTargetPolicyRegistry::validate_complete(
        &guard,
        &registry_jcs,
      )
      .unwrap();
    let mut digests = Vec::new();
    for ordinal in 0..4 {
      let identity = test_compiled_identity(ordinal);
      // Witness issuance consumes a guard by value, so each selection
      // re-verifies a fresh guard: in-session per-issuance re-verification,
      // NOT cross-phase or fresh-session revalidation.
      let guard = session
        .verify_current_approval(&approval_jcs, &signature)
        .unwrap();
      let approval_use = guard.issue_approval_use().unwrap();
      let selection = CheckedFilesystemFinalLtoTargetPolicySelection::select(
        &tcb,
        approval_use,
        &registry,
        &identity,
      )
      .unwrap();
      assert_eq!(
        selection.target(),
        ODEN_PARENT_TARGET_POLICY_TARGET_ORDER[ordinal],
      );
      digests.push(selection.target_policy_digest().to_string());
    }
    for left in 0..digests.len() {
      for right in (left + 1)..digests.len() {
        assert_ne!(digests[left], digests[right]);
      }
    }
  }

  fn guard_fixture<'session, 'tcb: 'session>(
    session: &'session FilesystemFinalLtoPolicyVerifierSession<'tcb>,
    approval_jcs: &[u8],
    signature: &[u8; 64],
  ) -> CurrentFilesystemFinalLtoApprovalGuard<'session> {
    session
      .verify_current_approval(approval_jcs, signature)
      .unwrap()
  }

  fn registry_validation_error(
    registry_jcs: &[u8],
  ) -> OdenTargetPolicySessionError {
    // Approve exactly the candidate bytes so structural validation, not
    // approved-byte equality, is the deciding check.
    let (approval_jcs, signature) = genesis_approval(&TEST_SEED, registry_jcs);
    let tcb = test_tcb_for_approval(&TEST_SEED, &approval_jcs, 1);
    let session = tcb.begin_policy_verifier_session();
    let guard = guard_fixture(&session, &approval_jcs, &signature);
    ValidatedFilesystemFinalLtoTargetPolicyRegistry::validate_complete(
      &guard,
      registry_jcs,
    )
    .err()
    .expect("registry candidate must refuse")
  }

  #[test]
  fn registry_rejects_wrong_row_order() {
    let mut registry = test_registry_value();
    let targets = registry
      .get_mut("targets")
      .and_then(serde_json::Value::as_array_mut)
      .unwrap();
    targets.swap(0, 1);
    let registry_jcs = canonical_value_jcs(&registry).unwrap();
    assert!(matches!(
      registry_validation_error(&registry_jcs),
      OdenTargetPolicySessionError::RegistryValidation(_),
    ));
  }

  #[test]
  fn registry_rejects_extra_row() {
    let mut registry = test_registry_value();
    let targets = registry
      .get_mut("targets")
      .and_then(serde_json::Value::as_array_mut)
      .unwrap();
    let duplicate = targets[3].clone();
    targets.push(duplicate);
    let registry_jcs = canonical_value_jcs(&registry).unwrap();
    assert!(matches!(
      registry_validation_error(&registry_jcs),
      OdenTargetPolicySessionError::RegistryValidation(_),
    ));
  }

  #[test]
  fn registry_rejects_missing_row() {
    let mut registry = test_registry_value();
    let targets = registry
      .get_mut("targets")
      .and_then(serde_json::Value::as_array_mut)
      .unwrap();
    targets.pop();
    let registry_jcs = canonical_value_jcs(&registry).unwrap();
    assert!(matches!(
      registry_validation_error(&registry_jcs),
      OdenTargetPolicySessionError::RegistryValidation(_),
    ));
  }

  #[test]
  fn registry_rejects_duplicated_match_domain_target() {
    let mut registry = test_registry_value();
    let targets = registry
      .get_mut("targets")
      .and_then(serde_json::Value::as_array_mut)
      .unwrap();
    targets[1] = targets[0].clone();
    let registry_jcs = canonical_value_jcs(&registry).unwrap();
    // The frozen per-ordinal identity check refuses the overlapping domain
    // before the pairwise overlap check can be reached.
    assert!(matches!(
      registry_validation_error(&registry_jcs),
      OdenTargetPolicySessionError::RegistryValidation(_),
    ));
  }

  #[test]
  fn registry_rejects_mutated_feature_set_bytes() {
    let registry_jcs = test_registry_jcs();
    let needle = b"rust:1.95.0";
    let position = registry_jcs
      .windows(needle.len())
      .position(|window| window == needle)
      .unwrap();
    let mut mutated = registry_jcs.clone();
    mutated[position] = b'q';
    assert!(matches!(
      registry_validation_error(&mutated),
      OdenTargetPolicySessionError::RegistryValidation(_),
    ));
  }

  #[test]
  fn registry_rejects_reencoded_json() {
    let registry_jcs = test_registry_jcs();
    let mut reencoded = Vec::with_capacity(registry_jcs.len() + 1);
    reencoded.push(b'{');
    reencoded.push(b' ');
    reencoded.extend_from_slice(&registry_jcs[1..]);
    assert!(matches!(
      registry_validation_error(&reencoded),
      OdenTargetPolicySessionError::RegistryValidation(_),
    ));
  }

  #[test]
  fn registry_rejects_row_member_outside_closed_set() {
    let mut registry = test_registry_value();
    let targets = registry
      .get_mut("targets")
      .and_then(serde_json::Value::as_array_mut)
      .unwrap();
    targets[2]
      .as_object_mut()
      .unwrap()
      .insert("extra".to_string(), serde_json::json!(1));
    let registry_jcs = canonical_value_jcs(&registry).unwrap();
    assert_eq!(
      registry_validation_error(&registry_jcs),
      OdenTargetPolicySessionError::RegistryRowNotClosed(
        "row carries a member outside the reviewed closed member set",
      ),
    );
  }

  #[test]
  fn registry_rejects_unapproved_bytes() {
    // The approval covers different registry bytes than the candidate.
    let registry_jcs = test_registry_jcs();
    let mut other_registry = test_registry_value();
    other_registry
      .get_mut("targets")
      .and_then(serde_json::Value::as_array_mut)
      .unwrap()
      .swap(0, 1);
    let other_registry_jcs = canonical_value_jcs(&other_registry).unwrap();
    let (approval_jcs, signature) =
      genesis_approval(&TEST_SEED, &other_registry_jcs);
    let tcb = test_tcb_for_approval(&TEST_SEED, &approval_jcs, 1);
    let session = tcb.begin_policy_verifier_session();
    let guard = guard_fixture(&session, &approval_jcs, &signature);
    assert_eq!(
      ValidatedFilesystemFinalLtoTargetPolicyRegistry::validate_complete(
        &guard,
        &registry_jcs,
      )
      .err(),
      Some(OdenTargetPolicySessionError::RegistryNotApproved),
    );
  }

  #[test]
  fn approval_rejects_key_id_of_unconfigured_key() {
    let registry_jcs = test_registry_jcs();
    // Signed and keyId-labeled by OTHER_SEED, but the TCB configures
    // TEST_SEED's key: the derived ID comparison refuses first.
    let (approval_jcs, signature) =
      genesis_approval(&OTHER_SEED, &registry_jcs);
    let receipt = test_receipt_for_approval(&TEST_SEED, &approval_jcs, 1, 1);
    let tcb =
      VerifiedFilesystemFinalLtoBootstrapTCB::new_test_authority_fixture(
        ed25519_test_public_key(&TEST_SEED),
        &receipt,
      )
      .unwrap();
    let session = tcb.begin_policy_verifier_session();
    assert_eq!(
      session
        .verify_current_approval(&approval_jcs, &signature)
        .err(),
      Some(OdenTargetPolicySessionError::ApprovalKeyMismatch),
    );
  }

  #[test]
  fn approval_rejects_signature_by_wrong_key() {
    let registry_jcs = test_registry_jcs();
    let statement = test_statement_value(
      &registry_jcs,
      1,
      serde_json::Value::Null,
      TEST_ISSUED_AT,
    );
    // keyId claims the configured key, but the detached signature was
    // produced by a different key.
    let statement_jcs = canonical_value_jcs(&statement).unwrap();
    let mut message = Vec::new();
    message.extend_from_slice(
      ODEN_TARGET_POLICY_APPROVAL_SIGNATURE_FRAMING_DOMAIN.as_bytes(),
    );
    message.push(0);
    message.extend_from_slice(&statement_jcs);
    let forged_signature = ed25519_test_sign(&OTHER_SEED, &message);
    let configured_key = ed25519_test_public_key(&TEST_SEED);
    let approval = serde_json::json!({
      "statement": statement,
      "signatureAlgorithm": "ed25519",
      "keyId": framed_sha256_digest(
        ODEN_TARGET_POLICY_APPROVAL_PUBLIC_KEY_BYTES_DIGEST_DOMAIN,
        &configured_key,
      ).as_str(),
      "signatureByteDigest": framed_sha256_digest(
        ODEN_TARGET_POLICY_APPROVAL_SIGNATURE_BYTES_DIGEST_DOMAIN,
        &forged_signature,
      ).as_str(),
    });
    let approval_jcs = canonical_value_jcs(&approval).unwrap();
    let receipt = test_receipt_for_approval(&TEST_SEED, &approval_jcs, 1, 1);
    let tcb =
      VerifiedFilesystemFinalLtoBootstrapTCB::new_test_authority_fixture(
        configured_key,
        &receipt,
      )
      .unwrap();
    let session = tcb.begin_policy_verifier_session();
    assert_eq!(
      session
        .verify_current_approval(&approval_jcs, &forged_signature)
        .err(),
      Some(OdenTargetPolicySessionError::ApprovalSignatureInvalid(
        "non-cofactored verification equation failed",
      )),
    );
  }

  #[test]
  fn approval_rejects_mutated_statement_after_signing() {
    let registry_jcs = test_registry_jcs();
    let statement = test_statement_value(
      &registry_jcs,
      1,
      serde_json::Value::Null,
      TEST_ISSUED_AT,
    );
    let (_original_jcs, signature) =
      signed_approval_for_statement(&TEST_SEED, &statement);
    let mutated_statement = test_statement_value(
      &registry_jcs,
      1,
      serde_json::Value::Null,
      TEST_ISSUED_AT + 1,
    );
    let public_key = ed25519_test_public_key(&TEST_SEED);
    let mutated_approval = serde_json::json!({
      "statement": mutated_statement,
      "signatureAlgorithm": "ed25519",
      "keyId": framed_sha256_digest(
        ODEN_TARGET_POLICY_APPROVAL_PUBLIC_KEY_BYTES_DIGEST_DOMAIN,
        &public_key,
      ).as_str(),
      "signatureByteDigest": framed_sha256_digest(
        ODEN_TARGET_POLICY_APPROVAL_SIGNATURE_BYTES_DIGEST_DOMAIN,
        &signature,
      ).as_str(),
    });
    let approval_jcs = canonical_value_jcs(&mutated_approval).unwrap();
    let receipt = test_receipt_for_approval(&TEST_SEED, &approval_jcs, 1, 1);
    let tcb =
      VerifiedFilesystemFinalLtoBootstrapTCB::new_test_authority_fixture(
        public_key, &receipt,
      )
      .unwrap();
    let session = tcb.begin_policy_verifier_session();
    assert_eq!(
      session
        .verify_current_approval(&approval_jcs, &signature)
        .err(),
      Some(OdenTargetPolicySessionError::ApprovalSignatureInvalid(
        "non-cofactored verification equation failed",
      )),
    );
  }

  #[test]
  fn approval_rejects_wrong_signature_byte_digest() {
    let registry_jcs = test_registry_jcs();
    let (approval_jcs, signature) = genesis_approval(&TEST_SEED, &registry_jcs);
    let mut tampered_signature = signature;
    tampered_signature[0] ^= 1;
    let tcb = test_tcb_for_approval(&TEST_SEED, &approval_jcs, 1);
    let session = tcb.begin_policy_verifier_session();
    assert_eq!(
      session
        .verify_current_approval(&approval_jcs, &tampered_signature)
        .err(),
      Some(OdenTargetPolicySessionError::ApprovalSignatureDigestMismatch),
    );
  }

  #[test]
  fn approval_rejects_noncanonical_scalar() {
    // Replace S with the group order L: canonical-range refusal must fire.
    let registry_jcs = test_registry_jcs();
    let statement = test_statement_value(
      &registry_jcs,
      1,
      serde_json::Value::Null,
      TEST_ISSUED_AT,
    );
    let (_jcs, signature) =
      signed_approval_for_statement(&TEST_SEED, &statement);
    let mut noncanonical_signature = signature;
    noncanonical_signature[32..].copy_from_slice(&L_BYTES);
    // Rebuild the approval so signatureByteDigest matches the altered bytes,
    // isolating the scalar canonicality refusal.
    let public_key = ed25519_test_public_key(&TEST_SEED);
    let approval = serde_json::json!({
      "statement": statement,
      "signatureAlgorithm": "ed25519",
      "keyId": framed_sha256_digest(
        ODEN_TARGET_POLICY_APPROVAL_PUBLIC_KEY_BYTES_DIGEST_DOMAIN,
        &public_key,
      ).as_str(),
      "signatureByteDigest": framed_sha256_digest(
        ODEN_TARGET_POLICY_APPROVAL_SIGNATURE_BYTES_DIGEST_DOMAIN,
        &noncanonical_signature,
      ).as_str(),
    });
    let approval_jcs = canonical_value_jcs(&approval).unwrap();
    let receipt = test_receipt_for_approval(&TEST_SEED, &approval_jcs, 1, 1);
    let tcb =
      VerifiedFilesystemFinalLtoBootstrapTCB::new_test_authority_fixture(
        public_key, &receipt,
      )
      .unwrap();
    let session = tcb.begin_policy_verifier_session();
    assert_eq!(
      session
        .verify_current_approval(&approval_jcs, &noncanonical_signature)
        .err(),
      Some(OdenTargetPolicySessionError::ApprovalSignatureInvalid(
        "scalar S is not canonical (0 <= S < L)",
      )),
    );
  }

  #[test]
  fn approval_rejects_sequence_shape_violations() {
    let registry_jcs = test_registry_jcs();
    let public_key = ed25519_test_public_key(&TEST_SEED);

    // Later sequence with null predecessor.
    let statement = test_statement_value(
      &registry_jcs,
      2,
      serde_json::Value::Null,
      TEST_ISSUED_AT,
    );
    let (approval_jcs, signature) =
      signed_approval_for_statement(&TEST_SEED, &statement);
    let receipt = test_receipt_for_approval(&TEST_SEED, &approval_jcs, 2, 1);
    let tcb =
      VerifiedFilesystemFinalLtoBootstrapTCB::new_test_authority_fixture(
        public_key, &receipt,
      )
      .unwrap();
    let session = tcb.begin_policy_verifier_session();
    assert_eq!(
      session
        .verify_current_approval(&approval_jcs, &signature)
        .err(),
      Some(OdenTargetPolicySessionError::InvalidApprovalField {
        field: "previousApprovalDigest",
        reason: "null is admissible exactly for the genesis sequence",
      }),
    );

    // Genesis sequence with a predecessor digest.
    let bogus_predecessor = framed_sha256_digest(
      ODEN_TARGET_POLICY_APPROVAL_DIGEST_DOMAIN,
      b"predecessor",
    );
    let statement = test_statement_value(
      &registry_jcs,
      1,
      serde_json::json!(bogus_predecessor.as_str()),
      TEST_ISSUED_AT,
    );
    let (approval_jcs, signature) =
      signed_approval_for_statement(&TEST_SEED, &statement);
    let receipt = test_receipt_for_approval(&TEST_SEED, &approval_jcs, 1, 1);
    let tcb =
      VerifiedFilesystemFinalLtoBootstrapTCB::new_test_authority_fixture(
        public_key, &receipt,
      )
      .unwrap();
    let session = tcb.begin_policy_verifier_session();
    assert_eq!(
      session
        .verify_current_approval(&approval_jcs, &signature)
        .err(),
      Some(OdenTargetPolicySessionError::InvalidApprovalField {
        field: "previousApprovalDigest",
        reason: "the genesis sequence requires exactly null",
      }),
    );

    // Zero sequence.
    let statement = test_statement_value(
      &registry_jcs,
      0,
      serde_json::Value::Null,
      TEST_ISSUED_AT,
    );
    let (approval_jcs, signature) =
      signed_approval_for_statement(&TEST_SEED, &statement);
    let receipt = test_receipt_for_approval(&TEST_SEED, &approval_jcs, 1, 1);
    let tcb =
      VerifiedFilesystemFinalLtoBootstrapTCB::new_test_authority_fixture(
        public_key, &receipt,
      )
      .unwrap();
    let session = tcb.begin_policy_verifier_session();
    assert_eq!(
      session
        .verify_current_approval(&approval_jcs, &signature)
        .err(),
      Some(OdenTargetPolicySessionError::InvalidApprovalField {
        field: "approvalSequence",
        reason: "value is not a positive safe integer",
      }),
    );
  }

  #[test]
  fn approval_rejects_forked_or_stale_candidate() {
    let registry_jcs = test_registry_jcs();
    let bogus_predecessor = framed_sha256_digest(
      ODEN_TARGET_POLICY_APPROVAL_DIGEST_DOMAIN,
      b"retained-predecessor",
    );
    // The protected current state names candidate A at sequence 3.
    let statement_a = test_statement_value(
      &registry_jcs,
      3,
      serde_json::json!(bogus_predecessor.as_str()),
      TEST_ISSUED_AT,
    );
    let (approval_a_jcs, _signature_a) =
      signed_approval_for_statement(&TEST_SEED, &statement_a);
    let receipt = test_receipt_for_approval(&TEST_SEED, &approval_a_jcs, 3, 1);
    let tcb =
      VerifiedFilesystemFinalLtoBootstrapTCB::new_test_authority_fixture(
        ed25519_test_public_key(&TEST_SEED),
        &receipt,
      )
      .unwrap();
    // Candidate B: same sequence, validly signed, different digest — a fork.
    let statement_b = test_statement_value(
      &registry_jcs,
      3,
      serde_json::json!(bogus_predecessor.as_str()),
      TEST_ISSUED_AT + 60,
    );
    let (approval_b_jcs, signature_b) =
      signed_approval_for_statement(&TEST_SEED, &statement_b);
    let session = tcb.begin_policy_verifier_session();
    assert_eq!(
      session
        .verify_current_approval(&approval_b_jcs, &signature_b)
        .err(),
      Some(OdenTargetPolicySessionError::CurrentStateMismatch(
        "approval digest is not the protected current approval (stale, \
         superseded, or forked)",
      )),
    );
  }

  #[test]
  fn approval_rejects_wrong_sequence_against_current_state() {
    let registry_jcs = test_registry_jcs();
    let (approval_jcs, signature) = genesis_approval(&TEST_SEED, &registry_jcs);
    // Receipt claims the current sequence is 2 while the approval is the
    // genesis approval at sequence 1.
    let receipt = test_receipt_for_approval(&TEST_SEED, &approval_jcs, 2, 1);
    let tcb =
      VerifiedFilesystemFinalLtoBootstrapTCB::new_test_authority_fixture(
        ed25519_test_public_key(&TEST_SEED),
        &receipt,
      )
      .unwrap();
    let session = tcb.begin_policy_verifier_session();
    assert_eq!(
      session
        .verify_current_approval(&approval_jcs, &signature)
        .err(),
      Some(OdenTargetPolicySessionError::CurrentStateMismatch(
        "approval sequence is not the protected current sequence",
      )),
    );
  }

  #[test]
  fn approval_rejects_reencoded_bytes_and_oversize_candidate() {
    let registry_jcs = test_registry_jcs();
    let (approval_jcs, signature) = genesis_approval(&TEST_SEED, &registry_jcs);
    let tcb = test_tcb_for_approval(&TEST_SEED, &approval_jcs, 1);
    let session = tcb.begin_policy_verifier_session();

    let mut reencoded = Vec::with_capacity(approval_jcs.len() + 1);
    reencoded.push(b'{');
    reencoded.push(b' ');
    reencoded.extend_from_slice(&approval_jcs[1..]);
    assert_eq!(
      session
        .verify_current_approval(&reencoded, &signature)
        .err(),
      Some(OdenTargetPolicySessionError::InvalidApprovalCandidate(
        "bytes are not the exact canonical JSON rendering",
      )),
    );

    let oversize = vec![b'a'; ODEN_TARGET_POLICY_APPROVAL_JCS_MAX_BYTES + 1];
    assert_eq!(
      session.verify_current_approval(&oversize, &signature).err(),
      Some(OdenTargetPolicySessionError::InvalidApprovalCandidate(
        "approval JCS byte length is outside the frozen bound",
      )),
    );
  }

  #[test]
  fn state_transition_invalidates_guard_and_unconsumed_witness() {
    let registry_jcs = test_registry_jcs();
    let (approval_jcs, signature) = genesis_approval(&TEST_SEED, &registry_jcs);
    let tcb = test_tcb_for_approval(&TEST_SEED, &approval_jcs, 1);
    let session = tcb.begin_policy_verifier_session();
    let guard = session
      .verify_current_approval(&approval_jcs, &signature)
      .unwrap();
    let registry =
      ValidatedFilesystemFinalLtoTargetPolicyRegistry::validate_complete(
        &guard,
        &registry_jcs,
      )
      .unwrap();
    let unconsumed_use = guard.issue_approval_use().unwrap();
    // Guards created before the protected transition (issuance consumes a
    // guard by value, so post-transition behavior needs its own guards).
    let stale_guard = session
      .verify_current_approval(&approval_jcs, &signature)
      .unwrap();
    let stale_validation_guard = session
      .verify_current_approval(&approval_jcs, &signature)
      .unwrap();

    tcb.advance_test_current_state_generation();

    // A pre-transition guard can no longer mint witnesses.
    assert_eq!(
      stale_guard.issue_approval_use().err(),
      Some(OdenTargetPolicySessionError::GuardInvalidated(
        "protected current-state generation changed after guard creation",
      )),
    );
    // A pre-transition guard can no longer admit registry validation.
    assert_eq!(
      ValidatedFilesystemFinalLtoTargetPolicyRegistry::validate_complete(
        &stale_validation_guard,
        &registry_jcs,
      )
      .err(),
      Some(OdenTargetPolicySessionError::GuardInvalidated(
        "protected current-state generation changed after guard creation",
      )),
    );
    // An already-issued, unconsumed witness cannot be accepted.
    let identity = test_compiled_identity(0);
    assert_eq!(
      CheckedFilesystemFinalLtoTargetPolicySelection::select(
        &tcb,
        unconsumed_use,
        &registry,
        &identity,
      )
      .err(),
      Some(OdenTargetPolicySessionError::GuardInvalidated(
        "protected current-state transition invalidated the unconsumed \
         witness",
      )),
    );
  }

  #[test]
  fn selection_refuses_cross_session_witness() {
    let registry_jcs = test_registry_jcs();
    let (approval_jcs, signature) = genesis_approval(&TEST_SEED, &registry_jcs);
    let tcb = test_tcb_for_approval(&TEST_SEED, &approval_jcs, 1);
    let session_one = tcb.begin_policy_verifier_session();
    let session_two = tcb.begin_policy_verifier_session();
    let guard_one = session_one
      .verify_current_approval(&approval_jcs, &signature)
      .unwrap();
    let guard_two = session_two
      .verify_current_approval(&approval_jcs, &signature)
      .unwrap();
    let registry_two =
      ValidatedFilesystemFinalLtoTargetPolicyRegistry::validate_complete(
        &guard_two,
        &registry_jcs,
      )
      .unwrap();
    let use_one = guard_one.issue_approval_use().unwrap();
    let identity = test_compiled_identity(0);
    assert_eq!(
      CheckedFilesystemFinalLtoTargetPolicySelection::select(
        &tcb,
        use_one,
        &registry_two,
        &identity,
      )
      .err(),
      Some(OdenTargetPolicySessionError::ApprovalUseMismatch(
        "witness and validated registry come from different verifier \
         sessions",
      )),
    );
  }

  #[test]
  fn selection_refuses_foreign_tcb() {
    let registry_jcs = test_registry_jcs();
    let (approval_jcs, signature) = genesis_approval(&TEST_SEED, &registry_jcs);
    let tcb = test_tcb_for_approval(&TEST_SEED, &approval_jcs, 1);
    let other_tcb = test_tcb_for_approval(&TEST_SEED, &approval_jcs, 1);
    let session = tcb.begin_policy_verifier_session();
    let guard = session
      .verify_current_approval(&approval_jcs, &signature)
      .unwrap();
    let registry =
      ValidatedFilesystemFinalLtoTargetPolicyRegistry::validate_complete(
        &guard,
        &registry_jcs,
      )
      .unwrap();
    let approval_use = guard.issue_approval_use().unwrap();
    let identity = test_compiled_identity(0);
    assert_eq!(
      CheckedFilesystemFinalLtoTargetPolicySelection::select(
        &other_tcb,
        approval_use,
        &registry,
        &identity,
      )
      .err(),
      Some(OdenTargetPolicySessionError::ApprovalUseMismatch(
        "witness session was not begun by this verified bootstrap TCB",
      )),
    );
  }

  #[test]
  fn selection_refuses_nonmatching_target_and_feature_set() {
    let registry_jcs = test_registry_jcs();
    let (approval_jcs, signature) = genesis_approval(&TEST_SEED, &registry_jcs);
    let tcb = test_tcb_for_approval(&TEST_SEED, &approval_jcs, 1);
    let session = tcb.begin_policy_verifier_session();
    let guard = session
      .verify_current_approval(&approval_jcs, &signature)
      .unwrap();
    let registry =
      ValidatedFilesystemFinalLtoTargetPolicyRegistry::validate_complete(
        &guard,
        &registry_jcs,
      )
      .unwrap();

    // A compiled identity naming a fifth target cannot select a row. The
    // private type is constructed literally here (same module) because the
    // fixture constructor itself already refuses this identity.
    let foreign_identity = ValidatedFilesystemFinalLtoCompiledIdentity {
      target: "riscv64gc-unknown-linux-gnu",
      feature_set: oden_parent_target_policy_feature_set(0),
      _not_send_sync: PhantomData,
    };
    let approval_use = guard.issue_approval_use().unwrap();
    assert_eq!(
      CheckedFilesystemFinalLtoTargetPolicySelection::select(
        &tcb,
        approval_use,
        &registry,
        &foreign_identity,
      )
      .err(),
      Some(OdenTargetPolicySessionError::SelectionTargetMismatch),
    );

    // A reconstructed feature identity for a real target refuses. Witness
    // issuance consumed the first guard, so re-verify a fresh one.
    let mismatched_identity = ValidatedFilesystemFinalLtoCompiledIdentity {
      target: ODEN_PARENT_TARGET_POLICY_TARGET_ORDER[0],
      feature_set: format!(
        "{};tampered",
        oden_parent_target_policy_feature_set(0),
      ),
      _not_send_sync: PhantomData,
    };
    let guard = session
      .verify_current_approval(&approval_jcs, &signature)
      .unwrap();
    let approval_use = guard.issue_approval_use().unwrap();
    assert_eq!(
      CheckedFilesystemFinalLtoTargetPolicySelection::select(
        &tcb,
        approval_use,
        &registry,
        &mismatched_identity,
      )
      .err(),
      Some(OdenTargetPolicySessionError::SelectionFeatureSetMismatch),
    );
  }

  #[test]
  fn compiled_identity_fixture_refuses_fallback_and_reconstruction() {
    // A fifth target is caller choice / host detection and refuses.
    assert_eq!(
      ValidatedFilesystemFinalLtoCompiledIdentity::new_test_fixture(
        "wasm32-unknown-unknown",
        &oden_parent_target_policy_feature_set(0),
      )
      .err(),
      Some(OdenTargetPolicySessionError::InvalidCompiledIdentity(
        "target is not one of the four frozen release targets",
      )),
    );
    // A separately reconstructed feature identity refuses.
    assert_eq!(
      ValidatedFilesystemFinalLtoCompiledIdentity::new_test_fixture(
        ODEN_PARENT_TARGET_POLICY_TARGET_ORDER[0],
        &oden_parent_target_policy_feature_set(1),
      )
      .err(),
      Some(OdenTargetPolicySessionError::InvalidCompiledIdentity(
        "featureSet differs byte-for-byte from the generated Rev2 identity",
      )),
    );
  }

  #[test]
  fn tcb_fixture_refuses_weak_key_and_malformed_receipt() {
    let registry_jcs = test_registry_jcs();
    let (approval_jcs, _signature) =
      genesis_approval(&TEST_SEED, &registry_jcs);
    let receipt = test_receipt_for_approval(&TEST_SEED, &approval_jcs, 1, 1);

    // The identity point's encoding is small order and must refuse.
    let mut identity_encoding = [0_u8; 32];
    identity_encoding[0] = 1;
    assert_eq!(
      VerifiedFilesystemFinalLtoBootstrapTCB::new_test_authority_fixture(
        identity_encoding,
        &receipt,
      )
      .err(),
      Some(OdenTargetPolicySessionError::InvalidTestAuthorityFixture(
        "public key is not a canonical prime-order Ed25519 point",
      )),
    );

    // A receipt with a non-test-namespace schema must refuse, even when
    // every other field is well formed.
    let receipt_value: serde_json::Value =
      serde_json::from_slice(&receipt).unwrap();
    let mut bad_receipt_value = receipt_value.clone();
    bad_receipt_value.as_object_mut().unwrap().insert(
      "schema".to_string(),
      serde_json::json!(
        "oden/capsec-filesystem-final-lto-current-state-receipt/1"
      ),
    );
    let bad_receipt = canonical_value_jcs(&bad_receipt_value).unwrap();
    assert_eq!(
      VerifiedFilesystemFinalLtoBootstrapTCB::new_test_authority_fixture(
        ed25519_test_public_key(&TEST_SEED),
        &bad_receipt,
      )
      .err(),
      Some(OdenTargetPolicySessionError::InvalidTestAuthorityFixture(
        "receipt schema is not the test-fixture literal",
      )),
    );
  }

  fn golden_public_key() -> [u8; 32] {
    GOLDEN_PUBLIC_KEY.try_into().unwrap()
  }

  fn golden_signature() -> [u8; 64] {
    GOLDEN_APPROVAL_SIGNATURE.try_into().unwrap()
  }

  /// Golden cross-integration: the fork-side session family must accept the
  /// parent repo's ACTUAL reviewed registry bytes, approval, detached
  /// signature, test public key, and current-state receipt end to end, and
  /// must derive exactly the digest vectors the parent-side validator pins
  /// over the same bytes.
  #[test]
  fn golden_parent_artifacts_validate_end_to_end() {
    // The synthetic test registry converges byte-for-byte with the reviewed
    // parent registry file: rows are exactly {target, featureSet} with the
    // generated identities under the frozen /2 envelope.
    assert_eq!(test_registry_jcs(), GOLDEN_REGISTRY_JCS);

    // Byte-digest vectors over the exact artifact bytes. Under the coherent
    // /2 contract the registry-byte domain and the approval's registry-byte
    // domain are the SAME `:2` domain, so both derive the one golden digest.
    assert_eq!(
      framed_sha256_digest(
        ODEN_PARENT_TARGET_POLICY_REGISTRY_BYTES_DIGEST_DOMAIN,
        GOLDEN_REGISTRY_JCS,
      )
      .as_str(),
      GOLDEN_REGISTRY_BYTE_DIGEST,
    );
    assert_eq!(
      ODEN_TARGET_POLICY_APPROVAL_REGISTRY_BYTES_DIGEST_DOMAIN,
      ODEN_PARENT_TARGET_POLICY_REGISTRY_BYTES_DIGEST_DOMAIN,
    );
    assert_eq!(
      framed_sha256_digest(
        ODEN_TARGET_POLICY_APPROVAL_REGISTRY_BYTES_DIGEST_DOMAIN,
        GOLDEN_REGISTRY_JCS,
      )
      .as_str(),
      GOLDEN_REGISTRY_BYTE_DIGEST,
    );
    assert_eq!(
      framed_sha256_digest(
        ODEN_TARGET_POLICY_APPROVAL_PUBLIC_KEY_BYTES_DIGEST_DOMAIN,
        &golden_public_key(),
      )
      .as_str(),
      GOLDEN_KEY_ID,
    );
    assert_eq!(
      framed_sha256_digest(
        ODEN_TARGET_POLICY_APPROVAL_SIGNATURE_BYTES_DIGEST_DOMAIN,
        &golden_signature(),
      )
      .as_str(),
      GOLDEN_APPROVAL_SIGNATURE_BYTE_DIGEST,
    );

    // TCB from the actual public key and actual current-state receipt.
    let tcb =
      VerifiedFilesystemFinalLtoBootstrapTCB::new_test_authority_fixture(
        golden_public_key(),
        GOLDEN_CURRENT_STATE_RECEIPT_JCS,
      )
      .unwrap();

    // The actual approval bytes and detached signature verify.
    let session = tcb.begin_policy_verifier_session();
    let guard = session
      .verify_current_approval(GOLDEN_APPROVAL_JCS, &golden_signature())
      .unwrap();
    assert_eq!(
      guard.approval().target_policy_approval_digest(),
      GOLDEN_APPROVAL_DIGEST,
    );
    assert_eq!(
      guard.approval().registry_byte_digest(),
      GOLDEN_REGISTRY_BYTE_DIGEST,
    );
    assert_eq!(
      guard.approval().policy_revision(),
      ODEN_TARGET_POLICY_APPROVAL_STATEMENT_POLICY_REVISION,
    );
    assert_eq!(guard.approval().approval_sequence(), 1);
    assert_eq!(
      guard.approval().issued_at_epoch_seconds(),
      GOLDEN_ISSUED_AT_EPOCH_SECONDS,
    );

    // The actual registry bytes pass complete atomic validation: the coherent
    // /2 approval (policyRevision 1) matches the /2 registry (policyRevision
    // 1), so validate_complete constructs the registry with no advisory
    // marker.
    let registry =
      ValidatedFilesystemFinalLtoTargetPolicyRegistry::validate_complete(
        &guard,
        GOLDEN_REGISTRY_JCS,
      )
      .unwrap();
    assert_eq!(registry.registry_byte_digest(), GOLDEN_REGISTRY_BYTE_DIGEST,);

    // The aarch64-apple-darwin selection succeeds with the generated
    // featureSet and derives exactly the parent-pinned selected-row digest.
    // Witness issuance consumes the guard by value (one witness per
    // verified guard).
    let identity = test_compiled_identity(0);
    let approval_use = guard.issue_approval_use().unwrap();
    let selection = CheckedFilesystemFinalLtoTargetPolicySelection::select(
      &tcb,
      approval_use,
      &registry,
      &identity,
    )
    .unwrap();
    assert_eq!(selection.target(), "aarch64-apple-darwin");
    assert_eq!(
      selection.feature_set(),
      oden_parent_target_policy_feature_set(0),
    );
    assert_eq!(
      selection.target_policy_digest(),
      GOLDEN_TARGET_POLICY_DIGESTS[0],
    );
    assert_eq!(
      selection.target_policy_approval_digest(),
      GOLDEN_APPROVAL_DIGEST,
    );

    // All four selected-row digests equal the parent-pinned vectors; each
    // selection re-verifies a fresh guard for its single-use witness.
    for ordinal in 0..4 {
      let identity = test_compiled_identity(ordinal);
      let guard = session
        .verify_current_approval(GOLDEN_APPROVAL_JCS, &golden_signature())
        .unwrap();
      let approval_use = guard.issue_approval_use().unwrap();
      let selection = CheckedFilesystemFinalLtoTargetPolicySelection::select(
        &tcb,
        approval_use,
        &registry,
        &identity,
      )
      .unwrap();
      assert_eq!(
        selection.target(),
        ODEN_PARENT_TARGET_POLICY_TARGET_ORDER[ordinal],
      );
      assert_eq!(
        selection.target_policy_digest(),
        GOLDEN_TARGET_POLICY_DIGESTS[ordinal],
      );
    }
  }

  /// Golden cross-integration: a wrong featureSet for a real target refuses
  /// against the actual parent artifacts.
  #[test]
  fn golden_parent_artifacts_refuse_wrong_feature_set() {
    let tcb =
      VerifiedFilesystemFinalLtoBootstrapTCB::new_test_authority_fixture(
        golden_public_key(),
        GOLDEN_CURRENT_STATE_RECEIPT_JCS,
      )
      .unwrap();
    let session = tcb.begin_policy_verifier_session();
    let guard = session
      .verify_current_approval(GOLDEN_APPROVAL_JCS, &golden_signature())
      .unwrap();
    let registry =
      ValidatedFilesystemFinalLtoTargetPolicyRegistry::validate_complete(
        &guard,
        GOLDEN_REGISTRY_JCS,
      )
      .unwrap();
    // A compiled identity claiming aarch64-apple-darwin with a different
    // (real, but wrong-row) generated featureSet must refuse. Constructed
    // literally (same module) because the fixture constructor itself
    // already refuses this identity.
    let mismatched_identity = ValidatedFilesystemFinalLtoCompiledIdentity {
      target: ODEN_PARENT_TARGET_POLICY_TARGET_ORDER[0],
      feature_set: oden_parent_target_policy_feature_set(1),
      _not_send_sync: PhantomData,
    };
    let approval_use = guard.issue_approval_use().unwrap();
    assert_eq!(
      CheckedFilesystemFinalLtoTargetPolicySelection::select(
        &tcb,
        approval_use,
        &registry,
        &mismatched_identity,
      )
      .err(),
      Some(OdenTargetPolicySessionError::SelectionFeatureSetMismatch),
    );
  }

  // ===== Cross-version coherence refusal =====

  /// The coherent `/2` family REFUSES a successor-revision (`/3`) statement at
  /// the approval parser: an approval whose statement carries `policyRevision:
  /// 2` (the `/3` successor revision) cannot even produce a guard, so a
  /// `/3`-over-`/2` hybrid can never reach registry validation or become a
  /// Validated/Checked authority value. (The `validate_complete` coherence
  /// check that compares the guard's approval revision with the parsed
  /// registry revision is additional defense in depth; the parser already
  /// guarantees the guard's approval revision is exactly `1`.)
  #[test]
  fn approval_family_refuses_successor_revision_statement() {
    let registry_jcs = test_registry_jcs();
    // Build a statement identical to the coherent genesis approval except the
    // successor revision literal `2`, and sign it under the test key so only
    // the revision check can decide.
    let statement = serde_json::json!({
      "schema": ODEN_TARGET_POLICY_APPROVAL_SCHEMA,
      "registryByteDigest": framed_sha256_digest(
        ODEN_TARGET_POLICY_APPROVAL_REGISTRY_BYTES_DIGEST_DOMAIN,
        &registry_jcs,
      ).as_str(),
      "policyRevision": 2,
      "approvalSequence": 1,
      "previousApprovalDigest": serde_json::Value::Null,
      "issuedAtEpochSeconds": TEST_ISSUED_AT,
    });
    let (approval_jcs, signature) =
      signed_approval_for_statement(&TEST_SEED, &statement);
    let tcb = test_tcb_for_approval(&TEST_SEED, &approval_jcs, 1);
    let session = tcb.begin_policy_verifier_session();
    assert_eq!(
      session
        .verify_current_approval(&approval_jcs, &signature)
        .err(),
      Some(OdenTargetPolicySessionError::InvalidApprovalField {
        field: "policyRevision",
        reason: "value differs from the /2 approval statement's const revision",
      }),
    );
  }

  // ===== Strict-profile negative vectors over the REAL golden artifacts ====

  /// Seed of the well-known TEST-ONLY golden authority key
  /// (SHA-256 of the published preimage), letting the test signer produce
  /// fresh signatures under exactly the golden public key.
  fn golden_seed() -> [u8; 32] {
    Sha256::digest(b"oden:capsec:test-authority:ed25519:v1").into()
  }

  fn le_add_32(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut sum = [0_u8; 32];
    let mut carry = 0_u16;
    for index in 0..32 {
      let value = u16::from(left[index]) + u16::from(right[index]) + carry;
      sum[index] = value as u8;
      carry = value >> 8;
    }
    assert_eq!(carry, 0, "little-endian sum overflowed 32 bytes");
    sum
  }

  fn lower_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
  }

  /// Rebuild the golden approval bytes with a substituted public key and/or
  /// detached signature: `keyId` and `signatureByteDigest` are re-derived so
  /// the preimage-binding checks pass and the strict Ed25519 profile itself
  /// is the deciding check on the full parse-and-verify path.
  fn golden_approval_rebuilt(
    public_key: &[u8; 32],
    signature: &[u8; 64],
  ) -> Vec<u8> {
    let mut approval: serde_json::Value =
      serde_json::from_slice(GOLDEN_APPROVAL_JCS).unwrap();
    let root = approval.as_object_mut().unwrap();
    root.insert(
      "keyId".to_string(),
      serde_json::json!(
        framed_sha256_digest(
          ODEN_TARGET_POLICY_APPROVAL_PUBLIC_KEY_BYTES_DIGEST_DOMAIN,
          public_key,
        )
        .as_str()
      ),
    );
    root.insert(
      "signatureByteDigest".to_string(),
      serde_json::json!(
        framed_sha256_digest(
          ODEN_TARGET_POLICY_APPROVAL_SIGNATURE_BYTES_DIGEST_DOMAIN,
          signature,
        )
        .as_str()
      ),
    );
    canonical_value_jcs(&approval).unwrap()
  }

  /// The exact framed plaintext the production strict verifier reconstructs and
  /// checks for the golden approval: `framing-domain || NUL || JCS(statement)`.
  /// Used as the base message `M` for the genuine RFC 8032 ph/ctx and
  /// cofactored-torsion attack-class vectors below.
  fn golden_framed_message() -> Vec<u8> {
    let approval: serde_json::Value =
      serde_json::from_slice(GOLDEN_APPROVAL_JCS).unwrap();
    let statement_jcs =
      canonical_value_jcs(approval.get("statement").unwrap()).unwrap();
    let mut message = ODEN_TARGET_POLICY_APPROVAL_SIGNATURE_FRAMING_DOMAIN
      .as_bytes()
      .to_vec();
    message.push(0);
    message.extend_from_slice(&statement_jcs);
    message
  }

  /// A genuine RFC 8032 §5.1.6 signer for the Ed25519ctx / Ed25519ph variants.
  /// Unlike `ed25519_test_sign` (pure Ed25519, empty dom2), this prepends the
  /// SigEd25519 `dom2` octet string to BOTH the nonce hash
  /// `r = SHA-512(dom2 || prefix || signed_message)` and the challenge hash
  /// `k = SHA-512(dom2 || R || A || signed_message)`, exactly as §5.1.6
  /// requires — dom2 FIRST, before `R || A`. For Ed25519ctx `signed_message`
  /// is `M`; for Ed25519ph it is `PH(M) = SHA-512(M)`. The result is a real
  /// variant signature under the SAME test seed as the golden pure key.
  fn ed25519_variant_sign(
    seed: &[u8; 32],
    dom2: &[u8],
    signed_message: &[u8],
  ) -> [u8; 64] {
    let (secret_scalar, prefix) = ed25519_test_expanded_seed(seed);
    let public_bytes =
      EdwardsPoint::mul_base(&secret_scalar).compress().to_bytes();
    let mut hasher = Sha512::new();
    hasher.update(dom2);
    hasher.update(prefix);
    hasher.update(signed_message);
    let nonce_wide: [u8; 64] = hasher.finalize().into();
    let nonce = Scalar::from_bytes_mod_order_wide(&nonce_wide);
    let r_bytes = EdwardsPoint::mul_base(&nonce).compress().to_bytes();
    let mut hasher = Sha512::new();
    hasher.update(dom2);
    hasher.update(r_bytes);
    hasher.update(public_bytes);
    hasher.update(signed_message);
    let challenge_wide: [u8; 64] = hasher.finalize().into();
    let challenge = Scalar::from_bytes_mod_order_wide(&challenge_wide);
    let s_scalar = nonce + challenge * secret_scalar;
    let mut signature = [0_u8; 64];
    signature[..32].copy_from_slice(&r_bytes);
    signature[32..].copy_from_slice(s_scalar.as_bytes());
    signature
  }

  /// Test-only genuine verifier for the Ed25519ctx / Ed25519ph variants, used
  /// to PROVE the variant signatures are real (a variant verifier ACCEPTS
  /// them) before showing the production pure-Ed25519 path REFUSES them. It
  /// recomputes the challenge with the same dom2 prefix and checks the
  /// verification equation `[S]B == R + [k]A` (A and R are prime-order here,
  /// so cofactored and non-cofactored agree).
  fn ed25519_variant_verify(
    public_key: &[u8; 32],
    dom2: &[u8],
    signed_message: &[u8],
    signature: &[u8; 64],
  ) -> bool {
    let public_point = match CompressedEdwardsY(*public_key).decompress() {
      Some(point) => point,
      None => return false,
    };
    let mut r_bytes = [0_u8; 32];
    r_bytes.copy_from_slice(&signature[..32]);
    let r_point = match CompressedEdwardsY(r_bytes).decompress() {
      Some(point) => point,
      None => return false,
    };
    let mut s_bytes = [0_u8; 32];
    s_bytes.copy_from_slice(&signature[32..]);
    let s_scalar: Option<Scalar> = Scalar::from_canonical_bytes(s_bytes).into();
    let s_scalar = match s_scalar {
      Some(scalar) => scalar,
      None => return false,
    };
    let mut hasher = Sha512::new();
    hasher.update(dom2);
    hasher.update(r_bytes);
    hasher.update(public_key);
    hasher.update(signed_message);
    let challenge_wide: [u8; 64] = hasher.finalize().into();
    let challenge = Scalar::from_bytes_mod_order_wide(&challenge_wide);
    EdwardsPoint::mul_base(&s_scalar) == r_point + challenge * public_point
  }

  /// Build an attack-class signature that a COFACTORED Ed25519 verifier
  /// ACCEPTS but the strict prime-order profile REFUSES. An order-4 torsion
  /// point `T` is added to `A` and/or `R`; `S = r + k*a` is then RECOMPUTED
  /// over the torsioned encodings (`k = SHA-512(R' || A' || M)`). Because
  /// `[8]T = identity`, the torsion cancels under the cofactor-8 equation, so
  /// `[8]([S]B) == [8](R' + [k]A')` holds. Returns the mutated public key `A'`
  /// and the recomputed signature `(R', S')`.
  fn cofactored_torsion_signature(
    seed: &[u8; 32],
    message: &[u8],
    torsion: &EdwardsPoint,
    add_to_a: bool,
    add_to_r: bool,
  ) -> ([u8; 32], [u8; 64]) {
    let (secret_scalar, prefix) = ed25519_test_expanded_seed(seed);
    let base_a = EdwardsPoint::mul_base(&secret_scalar);
    let a_point = if add_to_a { base_a + torsion } else { base_a };
    let a_bytes = a_point.compress().to_bytes();
    let mut hasher = Sha512::new();
    hasher.update(prefix);
    hasher.update(message);
    let nonce_wide: [u8; 64] = hasher.finalize().into();
    let nonce = Scalar::from_bytes_mod_order_wide(&nonce_wide);
    let base_r = EdwardsPoint::mul_base(&nonce);
    let r_point = if add_to_r { base_r + torsion } else { base_r };
    let r_bytes = r_point.compress().to_bytes();
    let mut hasher = Sha512::new();
    hasher.update(r_bytes);
    hasher.update(a_bytes);
    hasher.update(message);
    let challenge_wide: [u8; 64] = hasher.finalize().into();
    let challenge = Scalar::from_bytes_mod_order_wide(&challenge_wide);
    let s_scalar = nonce + challenge * secret_scalar;
    let mut signature = [0_u8; 64];
    signature[..32].copy_from_slice(&r_bytes);
    signature[32..].copy_from_slice(s_scalar.as_bytes());
    (a_bytes, signature)
  }

  /// Test-only COFACTORED verifier: `[8]([S]B) == [8](R + [k]A)`. It
  /// decompresses `A`/`R` canonically but does NOT enforce prime-order
  /// membership, so it accepts the mixed-torsion vectors the strict profile
  /// refuses — the distinguisher that proves the strict subgroup check is
  /// load-bearing.
  fn ed25519_cofactored_verify(
    public_key: &[u8; 32],
    message: &[u8],
    signature: &[u8; 64],
  ) -> bool {
    let public_point = match CompressedEdwardsY(*public_key).decompress() {
      Some(point) => point,
      None => return false,
    };
    let mut r_bytes = [0_u8; 32];
    r_bytes.copy_from_slice(&signature[..32]);
    let r_point = match CompressedEdwardsY(r_bytes).decompress() {
      Some(point) => point,
      None => return false,
    };
    let mut s_bytes = [0_u8; 32];
    s_bytes.copy_from_slice(&signature[32..]);
    let s_scalar: Option<Scalar> = Scalar::from_canonical_bytes(s_bytes).into();
    let s_scalar = match s_scalar {
      Some(scalar) => scalar,
      None => return false,
    };
    let mut hasher = Sha512::new();
    hasher.update(r_bytes);
    hasher.update(public_key);
    hasher.update(message);
    let challenge_wide: [u8; 64] = hasher.finalize().into();
    let challenge = Scalar::from_bytes_mod_order_wide(&challenge_wide);
    let lhs = EdwardsPoint::mul_base(&s_scalar).mul_by_cofactor();
    let rhs = (r_point + challenge * public_point).mul_by_cofactor();
    lhs == rhs
  }

  /// S' = S + L malleability over the CURRENT golden signature: S' is a
  /// congruent scalar (S' = S mod L) that a lax verifier accepts, so the
  /// strict profile must refuse it at the canonical-range check.
  #[test]
  fn strict_profile_refuses_s_plus_l_malleated_golden_signature() {
    let signature = golden_signature();
    let mut s_bytes = [0_u8; 32];
    s_bytes.copy_from_slice(&signature[32..]);
    let s_plus_l = le_add_32(&s_bytes, &L_BYTES);
    // Recomputed from the actual golden S; must equal the security review's
    // independently computed malleability vector.
    assert_eq!(lower_hex(&s_plus_l), GOLDEN_S_PLUS_L_LE_HEX);
    let mut malleated = signature;
    malleated[32..].copy_from_slice(&s_plus_l);
    let approval_jcs =
      golden_approval_rebuilt(&golden_public_key(), &malleated);
    assert_eq!(
      parse_and_verify_approval(
        &golden_public_key(),
        &approval_jcs,
        &malleated,
      )
      .err(),
      Some(OdenTargetPolicySessionError::ApprovalSignatureInvalid(
        "scalar S is not canonical (0 <= S < L)",
      )),
    );
  }

  /// S = L, S = L + 1, and an upper-range noncanonical scalar adjacent to
  /// the 2^252 structure of L all refuse at the canonical-range check.
  #[test]
  fn strict_profile_refuses_upper_range_noncanonical_scalars() {
    let l_plus_one = {
      let mut bytes = L_BYTES;
      bytes[0] += 1; // L's low byte is 0xed, so no carry.
      bytes
    };
    let l_plus_two_pow_252 = le_add_32(&L_BYTES, &TWO_POW_252_BYTES);
    for noncanonical_s in [L_BYTES, l_plus_one, l_plus_two_pow_252] {
      let mut mutated = golden_signature();
      mutated[32..].copy_from_slice(&noncanonical_s);
      let approval_jcs =
        golden_approval_rebuilt(&golden_public_key(), &mutated);
      assert_eq!(
        parse_and_verify_approval(
          &golden_public_key(),
          &approval_jcs,
          &mutated,
        )
        .err(),
        Some(OdenTargetPolicySessionError::ApprovalSignatureInvalid(
          "scalar S is not canonical (0 <= S < L)",
        )),
      );
    }
  }

  /// A = identity, A = canonical small-order (8-torsion) encoding,
  /// R = identity, and R = small-order all refuse at strict decompression.
  #[test]
  fn strict_profile_refuses_identity_and_small_order_points() {
    let signature = golden_signature();
    for weak_key in [IDENTITY_POINT_ENCODING, SMALL_ORDER_POINT_ENCODING] {
      let approval_jcs = golden_approval_rebuilt(&weak_key, &signature);
      assert_eq!(
        parse_and_verify_approval(&weak_key, &approval_jcs, &signature).err(),
        Some(OdenTargetPolicySessionError::ApprovalSignatureInvalid(
          "point is the identity or has small order",
        )),
      );
    }
    for weak_r in [IDENTITY_POINT_ENCODING, SMALL_ORDER_POINT_ENCODING] {
      let mut mutated = signature;
      mutated[..32].copy_from_slice(&weak_r);
      let approval_jcs =
        golden_approval_rebuilt(&golden_public_key(), &mutated);
      assert_eq!(
        parse_and_verify_approval(
          &golden_public_key(),
          &approval_jcs,
          &mutated,
        )
        .err(),
        Some(OdenTargetPolicySessionError::ApprovalSignatureInvalid(
          "point is the identity or has small order",
        )),
      );
    }
  }

  /// Noncanonical A/R encodings (y >= p forms, with and without the x-sign
  /// bit set) refuse at strict decompression before any group check.
  #[test]
  fn strict_profile_refuses_noncanonical_point_encodings() {
    let signature = golden_signature();
    for noncanonical in [
      NONCANONICAL_Y_EQ_P_ENCODING,
      NONCANONICAL_Y_EQ_P_SIGN_BIT_ENCODING,
    ] {
      // As the public key A.
      let approval_jcs = golden_approval_rebuilt(&noncanonical, &signature);
      assert_eq!(
        parse_and_verify_approval(&noncanonical, &approval_jcs, &signature)
          .err(),
        Some(OdenTargetPolicySessionError::ApprovalSignatureInvalid(
          "point encoding is not canonical",
        )),
      );
      // As the signature point R.
      let mut mutated = signature;
      mutated[..32].copy_from_slice(&noncanonical);
      let approval_jcs =
        golden_approval_rebuilt(&golden_public_key(), &mutated);
      assert_eq!(
        parse_and_verify_approval(
          &golden_public_key(),
          &approval_jcs,
          &mutated,
        )
        .err(),
        Some(OdenTargetPolicySessionError::ApprovalSignatureInvalid(
          "point encoding is not canonical",
        )),
      );
    }
  }

  /// Genuine strict-vs-cofactored distinguisher. Mixed-torsion `A'`/`R'` (a
  /// prime-order point plus a nonidentity order-4 torsion point) decompress
  /// canonically and are NOT small order. Crucially, `S` is RECOMPUTED as
  /// `r + k*a` over the torsioned encodings, so the signatures are VALID under
  /// the COFACTORED equation `[8]([S]B) == [8](R' + [k]A')` (the torsion
  /// cancels under multiplication by the cofactor 8). A test-only cofactored
  /// verifier ACCEPTS them FIRST — proving these are attack-class acceptance
  /// vectors, not malformed blobs — and only THEN does the production strict
  /// non-cofactored profile REFUSE them at the prime-subgroup membership check,
  /// showing that check is load-bearing (a cofactored-only verifier is fooled).
  #[test]
  fn strict_profile_refuses_mixed_torsion_points() {
    let seed = golden_seed();
    let message = golden_framed_message();
    // A nonidentity small-order (order-4) torsion point; SMALL_ORDER_POINT
    // _ENCODING is the canonical y = 0 encoding. [8]T = identity.
    let torsion = CompressedEdwardsY(SMALL_ORDER_POINT_ENCODING)
      .decompress()
      .expect("small-order point decompresses");

    // Mixed-torsion A' with S recomputed for the cofactored equation.
    let (mixed_a, sig_a) =
      cofactored_torsion_signature(&seed, &message, &torsion, true, false);
    // The mutated public key really carries torsion and really is NOT small
    // order (so it survives every check up to the prime-subgroup test).
    let mixed_a_point = CompressedEdwardsY(mixed_a)
      .decompress()
      .expect("A' decompresses");
    assert!(!mixed_a_point.is_torsion_free(), "A' must carry torsion");
    assert!(
      !mixed_a_point.is_small_order(),
      "A' must not be small order"
    );
    // FIRST prove genuineness: a cofactored verifier ACCEPTS (A', R', S').
    assert!(
      ed25519_cofactored_verify(&mixed_a, &message, &sig_a),
      "cofactored verifier must accept the recomputed mixed-torsion A vector",
    );
    // THEN the production strict profile REFUSES at prime-subgroup membership.
    let approval_jcs = golden_approval_rebuilt(&mixed_a, &sig_a);
    assert_eq!(
      parse_and_verify_approval(&mixed_a, &approval_jcs, &sig_a).err(),
      Some(OdenTargetPolicySessionError::ApprovalSignatureInvalid(
        "point is not in the prime-order subgroup",
      )),
    );

    // Mixed-torsion R' with S recomputed for the cofactored equation; A stays
    // the prime-order golden key.
    let golden_a = golden_public_key();
    let (recomputed_a, sig_r) =
      cofactored_torsion_signature(&seed, &message, &torsion, false, true);
    assert_eq!(
      recomputed_a, golden_a,
      "A must be unchanged for the R vector"
    );
    let mut r_only = [0_u8; 32];
    r_only.copy_from_slice(&sig_r[..32]);
    let mixed_r_point = CompressedEdwardsY(r_only)
      .decompress()
      .expect("R' decompresses");
    assert!(!mixed_r_point.is_torsion_free(), "R' must carry torsion");
    assert!(
      !mixed_r_point.is_small_order(),
      "R' must not be small order"
    );
    // FIRST prove genuineness: a cofactored verifier ACCEPTS (A, R', S').
    assert!(
      ed25519_cofactored_verify(&golden_a, &message, &sig_r),
      "cofactored verifier must accept the recomputed mixed-torsion R vector",
    );
    // THEN the production strict profile REFUSES at prime-subgroup membership.
    let approval_jcs = golden_approval_rebuilt(&golden_a, &sig_r);
    assert_eq!(
      parse_and_verify_approval(&golden_a, &approval_jcs, &sig_r).err(),
      Some(OdenTargetPolicySessionError::ApprovalSignatureInvalid(
        "point is not in the prime-order subgroup",
      )),
    );
  }

  /// Framing exclusivity over the golden statement: signatures by the golden
  /// key over raw JCS (no domain), the domain without the NUL separator, and
  /// the wrong domain version (`:3` instead of the correct `:2`) all refuse;
  /// only the exact `domain || NUL || JCS(statement)` framing verifies.
  #[test]
  fn strict_profile_refuses_wrong_signature_framing() {
    let seed = golden_seed();
    // The published TEST-ONLY seed derives exactly the golden public key.
    assert_eq!(ed25519_test_public_key(&seed), golden_public_key());
    let approval: serde_json::Value =
      serde_json::from_slice(GOLDEN_APPROVAL_JCS).unwrap();
    let statement_jcs =
      canonical_value_jcs(approval.get("statement").unwrap()).unwrap();

    // Raw statement JCS with no framing domain.
    let raw_jcs_message = statement_jcs.clone();
    // Framing domain but no NUL separator.
    let mut missing_nul_message =
      ODEN_TARGET_POLICY_APPROVAL_SIGNATURE_FRAMING_DOMAIN
        .as_bytes()
        .to_vec();
    missing_nul_message.extend_from_slice(&statement_jcs);
    // Wrong framing-domain version: `:3` instead of the correct `:2`.
    let mut wrong_version_message =
      b"oden:capsec:filesystem-final-lto-target-policy-registry-approval-signature:3"
        .to_vec();
    wrong_version_message.push(0);
    wrong_version_message.extend_from_slice(&statement_jcs);

    for message in [raw_jcs_message, missing_nul_message, wrong_version_message]
    {
      let signature = ed25519_test_sign(&seed, &message);
      let approval_jcs =
        golden_approval_rebuilt(&golden_public_key(), &signature);
      assert_eq!(
        parse_and_verify_approval(
          &golden_public_key(),
          &approval_jcs,
          &signature,
        )
        .err(),
        Some(OdenTargetPolicySessionError::ApprovalSignatureInvalid(
          "non-cofactored verification equation failed",
        )),
      );
    }
  }

  /// GENUINE RFC 8032 §5.1.6-5.1.7 prehash (Ed25519ph) and context
  /// (Ed25519ctx) vectors under the golden key. Each is a real variant
  /// signature — dom2 prepended to BOTH the nonce and the challenge hash — so a
  /// matching variant verifier ACCEPTS it FIRST (proving it is an attack-class
  /// signature the strict path must refuse, not a malformed blob any verifier
  /// rejects). The production pure-Ed25519 strict path (which uses empty dom2)
  /// then REFUSES both at the verification equation. This is the accept-then-
  /// reject structure the review requires; the earlier synthetic vectors passed
  /// `dom2 || PH(M)` to a pure signer, producing `H(prefix || dom2 || ...)`
  /// rather than RFC 8032's `H(dom2 || prefix || ...)`, so they were not real
  /// variant signatures.
  #[test]
  fn strict_profile_refuses_genuine_ph_and_ctx_variant_signatures() {
    let seed = golden_seed();
    let public_key = golden_public_key();
    // The published TEST-ONLY seed derives exactly the golden public key.
    assert_eq!(ed25519_test_public_key(&seed), public_key);
    let message = golden_framed_message();

    // Ed25519ctx: dom2(x=0x00, ctx="oden") =
    //   "SigEd25519 no Ed25519 collisions" || 0x00 || 0x04 || "oden".
    // The signed message is M itself.
    let dom2_ctx = b"SigEd25519 no Ed25519 collisions\x00\x04oden";
    let ctx_signature = ed25519_variant_sign(&seed, dom2_ctx, &message);
    // FIRST: a genuine Ed25519ctx verifier ACCEPTS the vector.
    assert!(
      ed25519_variant_verify(&public_key, dom2_ctx, &message, &ctx_signature),
      "genuine Ed25519ctx signature must verify under a ctx verifier",
    );
    // THEN: the production strict pure-Ed25519 path REFUSES it.
    let approval_jcs = golden_approval_rebuilt(&public_key, &ctx_signature);
    assert_eq!(
      parse_and_verify_approval(&public_key, &approval_jcs, &ctx_signature)
        .err(),
      Some(OdenTargetPolicySessionError::ApprovalSignatureInvalid(
        "non-cofactored verification equation failed",
      )),
    );

    // Ed25519ph: dom2(x=0x01, ctx="") =
    //   "SigEd25519 no Ed25519 collisions" || 0x01 || 0x00.
    // The signed message is PH(M) = SHA-512(M).
    let dom2_ph = b"SigEd25519 no Ed25519 collisions\x01\x00";
    let prehash: [u8; 64] = Sha512::digest(&message).into();
    let ph_signature = ed25519_variant_sign(&seed, dom2_ph, &prehash);
    // FIRST: a genuine Ed25519ph verifier ACCEPTS the vector.
    assert!(
      ed25519_variant_verify(&public_key, dom2_ph, &prehash, &ph_signature),
      "genuine Ed25519ph signature must verify under a ph verifier",
    );
    // THEN: the production strict pure-Ed25519 path REFUSES it.
    let approval_jcs = golden_approval_rebuilt(&public_key, &ph_signature);
    assert_eq!(
      parse_and_verify_approval(&public_key, &approval_jcs, &ph_signature)
        .err(),
      Some(OdenTargetPolicySessionError::ApprovalSignatureInvalid(
        "non-cofactored verification equation failed",
      )),
    );

    // Sanity: the genuine variant verifier is actually discriminating — the
    // pure-Ed25519 golden signature does NOT verify under either dom2.
    assert!(
      !ed25519_variant_verify(
        &public_key,
        dom2_ctx,
        &message,
        &golden_signature()
      ),
      "pure golden signature must not verify under the ctx dom2",
    );
    assert!(
      !ed25519_variant_verify(
        &public_key,
        dom2_ph,
        &prehash,
        &golden_signature()
      ),
      "pure golden signature must not verify under the ph dom2",
    );
  }

  /// keyId and signatureByteDigest binding over the REAL golden bytes: a
  /// mutated keyId refuses before any curve operation, and a tampered
  /// detached signature refuses at the digest comparison on the full
  /// session verify path.
  #[test]
  fn strict_profile_refuses_mutated_golden_key_id_and_signature_digest() {
    // Mutated keyId inside the golden approval bytes.
    let mut approval: serde_json::Value =
      serde_json::from_slice(GOLDEN_APPROVAL_JCS).unwrap();
    let key_id = approval
      .get("keyId")
      .and_then(serde_json::Value::as_str)
      .unwrap()
      .to_string();
    let mut characters: Vec<char> = key_id.chars().collect();
    let last = characters.last_mut().unwrap();
    *last = if *last == 'A' { 'B' } else { 'A' };
    let mutated_key_id: String = characters.into_iter().collect();
    approval
      .as_object_mut()
      .unwrap()
      .insert("keyId".to_string(), serde_json::json!(mutated_key_id));
    let approval_jcs = canonical_value_jcs(&approval).unwrap();
    assert_eq!(
      parse_and_verify_approval(
        &golden_public_key(),
        &approval_jcs,
        &golden_signature(),
      )
      .err(),
      Some(OdenTargetPolicySessionError::ApprovalKeyMismatch),
    );

    // Tampered detached signature bytes against the untouched golden
    // approval, on the full session verify path.
    let tcb =
      VerifiedFilesystemFinalLtoBootstrapTCB::new_test_authority_fixture(
        golden_public_key(),
        GOLDEN_CURRENT_STATE_RECEIPT_JCS,
      )
      .unwrap();
    let session = tcb.begin_policy_verifier_session();
    let mut tampered = golden_signature();
    tampered[0] ^= 1;
    assert_eq!(
      session
        .verify_current_approval(GOLDEN_APPROVAL_JCS, &tampered)
        .err(),
      Some(OdenTargetPolicySessionError::ApprovalSignatureDigestMismatch),
    );
  }

  /// Hash-chain shape extras: a sequence-3 approval against a protected
  /// current sequence of 1 (wrong current), and a malformed predecessor
  /// digest string, both refuse.
  #[test]
  fn approval_rejects_wrong_current_sequence_and_malformed_predecessor() {
    let registry_jcs = test_registry_jcs();
    let public_key = ed25519_test_public_key(&TEST_SEED);

    // Sequence-3 approval, receipt claims current sequence 1.
    let predecessor = framed_sha256_digest(
      ODEN_TARGET_POLICY_APPROVAL_DIGEST_DOMAIN,
      b"chain-predecessor",
    );
    let statement = test_statement_value(
      &registry_jcs,
      3,
      serde_json::json!(predecessor.as_str()),
      TEST_ISSUED_AT,
    );
    let (approval_jcs, signature) =
      signed_approval_for_statement(&TEST_SEED, &statement);
    let receipt = test_receipt_for_approval(&TEST_SEED, &approval_jcs, 1, 1);
    let tcb =
      VerifiedFilesystemFinalLtoBootstrapTCB::new_test_authority_fixture(
        public_key, &receipt,
      )
      .unwrap();
    let session = tcb.begin_policy_verifier_session();
    assert_eq!(
      session
        .verify_current_approval(&approval_jcs, &signature)
        .err(),
      Some(OdenTargetPolicySessionError::CurrentStateMismatch(
        "approval sequence is not the protected current sequence",
      )),
    );

    // Malformed predecessor digest string at sequence 2.
    let statement = test_statement_value(
      &registry_jcs,
      2,
      serde_json::json!("sha256-this-is-not-a-canonical-digest"),
      TEST_ISSUED_AT,
    );
    let (approval_jcs, signature) =
      signed_approval_for_statement(&TEST_SEED, &statement);
    let receipt = test_receipt_for_approval(&TEST_SEED, &approval_jcs, 2, 1);
    let tcb =
      VerifiedFilesystemFinalLtoBootstrapTCB::new_test_authority_fixture(
        public_key, &receipt,
      )
      .unwrap();
    let session = tcb.begin_policy_verifier_session();
    assert_eq!(
      session
        .verify_current_approval(&approval_jcs, &signature)
        .err(),
      Some(OdenTargetPolicySessionError::InvalidApprovalField {
        field: "previousApprovalDigest",
        reason: "value is not a canonical sha256 digest",
      }),
    );
  }
}

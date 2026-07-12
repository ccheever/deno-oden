//! The executable Capability Security Revision-2 semantic core.
//!
//! This file is the only implementation of Rev2 schema normalization,
//! authority matching, effect-set decisions, and staged authorization. The
//! registry generator copies these exact bytes into the Deno fork. TypeScript
//! consumers use the JSON oracle exposed at the bottom of this module; they do
//! not reconstruct any decision.
//!
//! @ref LLP 0019#the-effect-model [implements] — Authority selectors and effect
//! occurrences are distinct normalized domains; a stage is conjunctive.
//! @ref LLP 0019#registry-architecture [implements] — Schemas, projections,
//! match operations, definitions, and edge contracts come from generated data.
//! @ref LLP 0019#decision-precedence [implements] — One ordered evaluator owns
//! all negative, predicate, positive, masked, and mode-fallback strata.
//! @ref LLP 0019#operation-scoped-positive-authority-provenance [implements] —
//! every allowing dimension records the exact positive source identity.

// Parent and fork workspaces intentionally use different rustfmt widths. The
// generator installs this module byte-for-byte, so style-only rewrites are
// suppressed in both consumers.
#[rustfmt::skip]
mod shared {
use base64::Engine as _;
use ipnet::{IpNet, Ipv4Net};
use serde::de::{self, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Value};

// Operation-lifetime bounds complement the per-stage Cartesian/work bounds.
// They keep redirect/retry discovery from turning the actor digest history into
// an unbounded, eventually quadratic allocation and serialization surface.
const MAX_OPERATION_COMMITTED_STAGES: usize = 256;
const MAX_OPERATION_CAPTURED_SOURCE_ENTRIES: usize = 16_384;
const MAX_OPERATION_NEGATIVE_INVENTORY_ENTRIES: usize = 4_096;
const MAX_PROVISIONAL_RESOURCE_ENTRIES: usize = 1_024;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv6Addr};
use std::ops::Deref;
use std::str::FromStr;
use std::sync::{Arc, OnceLock};

use crate::rev2_registry_generated::{
    REV2_PROFILE, REV2_REGISTRY_DIGEST, REV2_RUNTIME_SEMANTIC_PAYLOAD_JSON,
    REV2_VOCAB_DIGEST,
};

pub const REASON_SCHEMA_INVALID: &str = "OD-CAP-SCHEMA-INVALID";
pub const REASON_VOCAB_MISMATCH: &str = "OD-CAP-VOCAB-MISMATCH";
pub const REASON_REGISTRY_MISMATCH: &str = "OD-CAP-REGISTRY-MISMATCH";
pub const REASON_DUPLICATE_EFFECT: &str = "OD-CAP-DUPLICATE-EFFECT";
pub const REASON_EDGE_SET_INVALID: &str = "OD-CAP-EDGE-SET-INVALID";
pub const REASON_UNATTRIBUTED: &str = "OD-CAP-UNATTRIBUTED";
pub const REASON_LIFECYCLE: &str = "OD-CAP-LIFECYCLE-DENY";
pub const REASON_PROTECTED: &str = "OD-CAP-PROTECTED-GUARD";
pub const REASON_PROCESS_CEILING: &str = "OD-CAP-DENY-CEILING";
pub const REASON_PRINCIPAL_DENIAL: &str = "OD-CAP-PRINCIPAL-DENIAL";
pub const REASON_REVOKED: &str = "OD-CAP-SESSION-REVOKED";
pub const REASON_POSITIVE_PREDICATE: &str = "OD-CAP-POSITIVE-PREDICATE";
pub const REASON_QUARANTINE: &str = "OD-CAP-QUARANTINE";
pub const REASON_ENV_MASKED: &str = "OD-CAP-ENV-MASKED";
pub const REASON_MISSING_AUTHORITY: &str = "OD-CAP-MISSING-AUTHORITY";
pub const REASON_INTERACTION_RELEASE: &str = "OD-CAP-INTERACTION-RESTART";
pub const REASON_OPERATION_CONTEXT: &str = "OD-CAP-OPERATION-CONTEXT";
pub const REASON_ALLOW: &str = "OD-CAP-ALLOW";
pub const REASON_AUDIT_ALLOW: &str = "OD-CAP-AUDIT-ALLOW";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EngineIdentity {
    pub profile: String,
    pub vocab_digest: String,
    pub registry_digest: String,
}

impl EngineIdentity {
    pub fn embedded() -> Self {
        Self {
            profile: REV2_PROFILE.to_string(),
            vocab_digest: REV2_VOCAB_DIGEST.to_string(),
            registry_digest: REV2_REGISTRY_DIGEST.to_string(),
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
pub enum PrincipalKind {
    Root,
    Runtime,
    Package,
    Jsr,
    Url,
    Quarantine,
    NoUser,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PrincipalRef {
    pub kind: PrincipalKind,
    pub key: String,
}

impl PrincipalRef {
    fn is_transparent(&self) -> bool {
        self.kind == PrincipalKind::Runtime
    }

    fn is_root(&self) -> bool {
        self.kind == PrincipalKind::Root
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum SelectorPolarity {
    Positive,
    Negative,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthoritySelectorInput {
    pub identity: EngineIdentity,
    pub principal: Option<PrincipalRef>,
    pub capability: String,
    pub resource: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EffectInput {
    pub identity: EngineIdentity,
    pub edge_id: String,
    pub effect_slot_id: String,
    pub capability: String,
    pub effect_owner: String,
    pub occurrence: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CanonicalAuthoritySelector {
    pub principal: Option<PrincipalRef>,
    pub capability: String,
    pub projection_id: String,
    pub resource: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CanonicalEffect {
    pub edge_id: String,
    pub effect_slot_id: String,
    pub capability: String,
    pub effect_owner: String,
    pub projection_id: String,
    pub occurrence: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NamedSelectorInput {
    pub source_id: String,
    pub selector: AuthoritySelectorInput,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HandleSelectorInput {
    pub handle_id: String,
    pub handle_generation: String,
    pub armed_snapshot_digest: String,
    pub carrier_epoch: String,
    pub selector: AuthoritySelectorInput,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ProtectedExceptionInput {
    pub source_id: String,
    pub reason: String,
    pub selector: AuthoritySelectorInput,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CompatibilityDispositionInput {
    pub disposition_id: String,
    pub source_id: String,
    pub selector: AuthoritySelectorInput,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PathBindingInput {
    pub source_id: String,
    pub root_binding_id: String,
    #[serde(default)]
    pub final_object_identities: Vec<Value>,
    #[serde(default)]
    pub parent_identities: Vec<Value>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Mode {
    Permissive,
    Audit,
    Enforce,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Generations {
    #[serde(default = "zero_generation")]
    pub negative_overlay: String,
    #[serde(default = "zero_generation")]
    pub policy_snapshot: String,
    #[serde(default = "zero_generation")]
    pub revocation: String,
    #[serde(default = "zero_generation")]
    pub session_overlay: String,
}

impl Default for Generations {
    fn default() -> Self {
        Self {
            negative_overlay: zero_generation(),
            policy_snapshot: zero_generation(),
            revocation: zero_generation(),
            session_overlay: zero_generation(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OperationProvenanceContext {
    pub policy_digest: String,
    pub armed_snapshot_digest: String,
    pub quota_owner: PrincipalRef,
    pub terminal_evidence_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DecisionPolicyInput {
    pub identity: EngineIdentity,
    pub mode: Mode,
    pub run_nonce: String,
    pub channel_epoch: String,
    pub provenance: OperationProvenanceContext,
    #[serde(default)]
    pub generations: Generations,
    #[serde(default)]
    pub process_denials: Vec<NamedSelectorInput>,
    #[serde(default)]
    pub principal_denials: Vec<NamedSelectorInput>,
    #[serde(default)]
    pub session_revocations: Vec<NamedSelectorInput>,
    #[serde(default)]
    pub escalation_ceiling: Vec<NamedSelectorInput>,
    #[serde(default)]
    pub static_floor: Vec<NamedSelectorInput>,
    #[serde(default)]
    pub handles: Vec<HandleSelectorInput>,
    #[serde(default)]
    pub session_grants: Vec<NamedSelectorInput>,
    #[serde(default)]
    pub implicit_self: Vec<NamedSelectorInput>,
    #[serde(default)]
    pub protected_exceptions: Vec<ProtectedExceptionInput>,
    #[serde(default)]
    pub compatibility_dispositions: Vec<CompatibilityDispositionInput>,
    #[serde(default)]
    pub validated_receipt_row_digests: Vec<String>,
    #[serde(default)]
    pub path_bindings: Vec<PathBindingInput>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StageRequest {
    pub identity: EngineIdentity,
    pub stage_id: String,
    pub principals: Vec<PrincipalRef>,
    pub effects: Vec<EffectInput>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "kebab-case")]
pub enum Outcome {
    Allow,
    Masked,
    Deny,
}

impl Outcome {
    fn combine(self, other: Self) -> Self {
        std::cmp::max(self, other)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PositiveSource {
    pub kind: String,
    pub source_id: String,
    pub generation: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DimensionDecision {
    pub principal: PrincipalRef,
    pub outcome: Outcome,
    pub stratum: u8,
    pub reason_code: String,
    pub positive_source: Option<PositiveSource>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EffectDecision {
    pub effect: CanonicalEffect,
    pub outcome: Outcome,
    pub dimensions: Vec<DimensionDecision>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StageDecision {
    pub stage_id: String,
    pub outcome: Outcome,
    pub effects: Vec<EffectDecision>,
    pub committed_effects: Vec<CanonicalEffect>,
    pub omitted_effects: Vec<MaskedEffectOmission>,
    pub canonical_effects_json: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MaskedEffectOmission {
    pub effect: CanonicalEffect,
    pub reason_codes: Vec<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Interaction {
    NonInteractive,
    MayPrompt,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OperationBarrier {
    AuthorizationBeforeCommit,
    RevocationBeforeNextEffectOrDelivery,
}

/// Native-only host capture used by the enforcing staged API. This type has
/// no wire deserializer; JavaScript/oracle request bytes cannot manufacture an
/// operation actor, constrained set, or effect owner.
#[derive(Debug, PartialEq, Eq)]
pub struct CapturedOperationContext {
    actor_id: String,
    identity: EngineIdentity,
    principals: Vec<PrincipalRef>,
    effect_owner_id: String,
    effect_owner_principal: PrincipalRef,
    effect_owner_generation: String,
    sealed_child_exports: Vec<SealedChildExportFact>,
    sealed_repeatable_edge_id: Option<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct SealedChildExportFact {
    effect: EffectInput,
}

impl SealedChildExportFact {
    pub fn capture_host(effect: EffectInput) -> Self {
        Self { effect }
    }
}

impl CapturedOperationContext {
    #[allow(clippy::too_many_arguments)]
    pub fn capture_host(
        actor_id: impl Into<String>,
        identity: EngineIdentity,
        principals: Vec<PrincipalRef>,
        effect_owner_id: impl Into<String>,
        effect_owner_principal: PrincipalRef,
        effect_owner_generation: impl Into<String>,
        sealed_child_exports: Vec<SealedChildExportFact>,
        sealed_repeatable_edge_id: Option<String>,
    ) -> Result<Self, CoreError> {
        let actor_id = actor_id.into();
        let effect_owner_id = effect_owner_id.into();
        let effect_owner_generation = effect_owner_generation.into();
        validate_u64_decimal(&effect_owner_generation)?;
        let principals = normalize_principal_set(&principals);
        if actor_id.trim().is_empty()
            || actor_id.len() > 1024
            || effect_owner_id.trim().is_empty()
            || effect_owner_id.len() > 1024
            || effect_owner_principal.key.trim().is_empty()
            || effect_owner_principal.key.len() > 1024
            || (!effect_owner_principal.is_transparent()
                && !principals.contains(&effect_owner_principal))
        {
            return Err(CoreError::new(
                REASON_OPERATION_CONTEXT,
                "captured operation actor or effect owner is empty",
            ));
        }
        for fact in &sealed_child_exports {
            if fact.effect.effect_owner != effect_owner_id
                || fact
                    .effect
                    .occurrence
                    .get("ownerGeneration")
                    .and_then(Value::as_str)
                    .is_some_and(|generation| generation != effect_owner_generation)
            {
                return Err(CoreError::new(
                    REASON_OPERATION_CONTEXT,
                    "sealed child export facts conflict with the captured owner generation",
                ));
            }
        }
        Ok(Self {
            actor_id,
            identity,
            principals,
            effect_owner_id,
            effect_owner_principal,
            effect_owner_generation,
            sealed_child_exports,
            sealed_repeatable_edge_id,
        })
    }
}

pub trait ProvisionalResources {
    /// Stable, non-secret resource identities used only in structured cleanup
    /// evidence. Implementations release the actual handles in `release_all`.
    fn held_ids(&self) -> Vec<String>;
    fn release_all(&mut self) -> Vec<String>;
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TrackedProvisionalResources {
    held: BTreeSet<String>,
    released: Vec<String>,
}

impl TrackedProvisionalResources {
    pub fn hold(&mut self, id: impl Into<String>) -> Result<(), CoreError> {
        let id = id.into();
        if id.trim().is_empty() || !self.held.insert(id.clone()) {
            return Err(CoreError::new(
                REASON_OPERATION_CONTEXT,
                "provisional resource identity is empty or duplicated",
            ));
        }
        Ok(())
    }

    pub fn released(&self) -> &[String] {
        &self.released
    }
}

impl ProvisionalResources for TrackedProvisionalResources {
    fn held_ids(&self) -> Vec<String> {
        self.held.iter().cloned().collect()
    }

    fn release_all(&mut self) -> Vec<String> {
        let released: Vec<String> = self.held.iter().cloned().collect();
        self.held.clear();
        self.released.extend(released.iter().cloned());
        released
    }
}

fn canonical_provisional_resource_ids<R: ProvisionalResources>(
    resources: &R,
) -> Result<Vec<String>, CoreError> {
    let mut ids = resources.held_ids();
    if ids.len() > MAX_PROVISIONAL_RESOURCE_ENTRIES
        || ids
            .iter()
            .any(|id| id.trim().is_empty() || id.len() > 1024)
    {
        return Err(CoreError::new(
            REASON_OPERATION_CONTEXT,
            "provisional resource inventory exceeds its bound",
        ));
    }
    ids.sort();
    if ids.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(CoreError::new(
            REASON_OPERATION_CONTEXT,
            "provisional resource inventory contains a duplicate",
        ));
    }
    Ok(ids)
}

#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CommitPermit {
    operation_id: String,
    stage_id: String,
    actor_digest: String,
    completed_discovery_stages: Vec<String>,
    provisional_resource_ids: Vec<String>,
    decision: StageDecision,
    permit_token: String,
}

impl CommitPermit {
    pub fn actor_digest(&self) -> &str {
        &self.actor_digest
    }

    pub fn decision(&self) -> &StageDecision {
        &self.decision
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StructuredDenial {
    pub operation_id: String,
    pub stage_id: String,
    pub reason_code: String,
    pub completed_discovery_stages: Vec<String>,
    pub released_provisional_resources: Vec<String>,
    pub decision: Option<StageDecision>,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum StageAuthorization {
    Permit { permit: CommitPermit },
    Masked {
        decision: StageDecision,
        released_provisional_resources: Vec<String>,
    },
    Denied { denial: StructuredDenial },
    RestartRequired { denial: StructuredDenial },
    AlreadyDenied { terminal_evidence_id: String },
}

#[derive(Debug, Serialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum CommitResult {
    Committed {
        stage_id: String,
        actor_digest: String,
    },
    Denied { denial: StructuredDenial },
    AlreadyDenied { terminal_evidence_id: String },
}

#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct OperationReleaseEvidence {
    pub operation_id: String,
    pub terminal_evidence_id: String,
    pub completed_stages: Vec<String>,
    pub released_provisional_resources: Vec<String>,
}

#[derive(Debug, Clone)]
struct PendingCommit {
    permit_token: String,
    actor_digest: String,
    decision: StageDecision,
    generations: Generations,
    positive_inventory_digest: String,
    negative_inventory_digest: String,
    provisional_resource_ids: Vec<String>,
    sealed_launch_consumed_after_commit: bool,
}

#[derive(Debug)]
pub struct StagedOperation {
    operation_id: String,
    identity: EngineIdentity,
    captured_context: CapturedOperationContext,
    policy_snapshot_generation: String,
    run_nonce: String,
    channel_epoch: String,
    mode: Mode,
    provenance: OperationProvenanceContext,
    initial_positive_inventory: BTreeSet<String>,
    initial_positive_inventory_digest: String,
    required_negative_inventory: BTreeSet<String>,
    captured_positive_sources: BTreeMap<String, PositiveSource>,
    captured_positive_source_bases: BTreeMap<String, String>,
    sealed_repeatable_effects: BTreeSet<String>,
    sealed_launch_consumed: bool,
    last_generations: Generations,
    completed_stages: Vec<String>,
    pending_commit: Option<PendingCommit>,
    terminal_denial: Option<StructuredDenial>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(
    tag = "operation",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
#[allow(clippy::large_enum_variant)]
enum OracleRequest {
    Identity,
    NormalizeSelector {
        selector: AuthoritySelectorInput,
        polarity: SelectorPolarity,
    },
    NormalizeEffect {
        effect: EffectInput,
    },
    Match {
        selector: AuthoritySelectorInput,
        effect: EffectInput,
        polarity: SelectorPolarity,
        source_id: String,
        #[serde(default)]
        path_bindings: Vec<PathBindingInput>,
    },
    EvaluateAlgorithm {
        operation_id: String,
        selector: Value,
        occurrence: Value,
        polarity: SelectorPolarity,
        source_id: String,
        #[serde(default)]
        path_bindings: Vec<PathBindingInput>,
    },
    DecideStage {
        stage: StageRequest,
        policy: Box<DecisionPolicyInput>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CoreError {
    pub reason_code: String,
    pub message: String,
}

impl CoreError {
    fn new(reason_code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            reason_code: reason_code.into(),
            message: message.into(),
        }
    }
}

impl fmt::Display for CoreError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "{}: {}", self.reason_code, self.message)
    }
}

impl std::error::Error for CoreError {}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RuntimePayload {
    schema: String,
    profile: String,
    definitions: Vec<Definition>,
    coverage_edges: Vec<Edge>,
    policy_rules_and_classifiers: Rules,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Definition {
    id: String,
    lifecycle: String,
    resource_schema_id: String,
    occurrence_schema_id: String,
    positive_projection_id: String,
    negative_projection_id: String,
    #[serde(default)]
    channels: Vec<String>,
    #[serde(default)]
    constraints: Vec<String>,
    positive_required: bool,
    protected_receipt_predicate_id: Option<String>,
    root_edge_predicate_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Edge {
    id: String,
    kind: String,
    #[serde(default)]
    semantics: Option<Value>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct EdgeSemantics {
    effects: Vec<EdgeEffect>,
    effect_mode: String,
    atomicity_group: Option<String>,
    complete_effect_slot_ids: Option<Vec<String>>,
    #[serde(default)]
    positive_channels: Vec<String>,
    edge_predicate_id: Option<String>,
    lifetime_contract_id: String,
    gate: EdgeGate,
    principal_sources: Vec<String>,
    effect_owner_source: String,
    actor_keys: Vec<String>,
    generation_keys: Vec<String>,
    effect_start_boundary: String,
    barriers: EdgeBarriers,
    target_effect_disposition: String,
    masked_commit: Option<MaskedCommitContract>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct EdgeGate {
    branch_id: String,
    branch_kind: String,
    condition: Option<String>,
    enforcement_disposition: String,
    mechanism: String,
    negative_closure_spec_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct EdgeBarriers {
    authorization: String,
    cancellation: String,
    cleanup: String,
    commit: String,
    delivery: String,
    discovery: String,
    revocation: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct EdgeEffect {
    effect_slot_id: String,
    capability: String,
    branch_id: Option<String>,
    authority_selector_normalizer_id: String,
    effect_occurrence_normalizer_id: String,
    condition: Option<String>,
    source_resource_description: String,
    cardinality: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct MaskedCommitContract {
    masked_effect_slot_id: String,
    optional_disposition: String,
    required_disposition: String,
    required_for_commit_occurrence_path: String,
    required_for_commit_source: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Rules {
    resource_schemas: Vec<TypedSchema>,
    occurrence_schemas: Vec<TypedSchema>,
    value_schemas: Vec<TypedSchema>,
    #[serde(default)]
    #[allow(dead_code)]
    schema_fixture_vectors: Vec<Value>,
    projections: Vec<Projection>,
    match_evaluation_spec: MatchEvaluationSpec,
    #[serde(default)]
    predicates: Vec<Value>,
    ip_address_classes: Option<IpAddressClasses>,
    #[serde(default)]
    derivation_rules: Vec<Value>,
    #[serde(default)]
    dispositions: Vec<Value>,
    #[serde(default)]
    lifetime_contracts: Vec<Value>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TypedSchema {
    id: String,
    kind: String,
    additional_properties: bool,
    tag: Option<SchemaTag>,
    fields: Vec<TypedField>,
    #[serde(default)]
    constraints: Vec<SchemaConstraint>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SchemaTag {
    field: String,
    allowed_values: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct TypedField {
    name: String,
    #[serde(rename = "type")]
    value_type: String,
    format: String,
    canonicalization: String,
    required: bool,
    schema_ref: Option<String>,
    allowed_values: Option<Vec<String>>,
}

#[derive(Debug, Clone, Deserialize)]
struct SchemaConstraint {
    operation: String,
    operands: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Projection {
    id: String,
    capability_id: String,
    polarity: String,
    input_schema_id: String,
    output_kind: String,
    match_spec: Option<ProjectionMatchSpec>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProjectionMatchSpec {
    combine: String,
    occurrence_schema_id: String,
    clauses: Vec<MatchClause>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct MatchClause {
    operation: String,
    selector_path: String,
    occurrence_path: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct MatchEvaluationSpec {
    operations: Vec<MatchOperation>,
    #[serde(default)]
    data_tables: Vec<Value>,
}

#[derive(Debug, Clone, Deserialize)]
struct MatchOperation {
    id: String,
    algorithm: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct IpAddressClasses {
    classes: Vec<IpClass>,
    metadata_exact: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
struct IpClass {
    id: String,
    cidrs: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct NormalizedNamedSelector {
    source_id: String,
    source_generation: Option<String>,
    selector: CanonicalAuthoritySelector,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct NormalizedProtectedException {
    source_id: String,
    reason: String,
    selector: CanonicalAuthoritySelector,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct NormalizedCompatibilityDisposition {
    disposition_id: String,
    source_id: String,
    selector: CanonicalAuthoritySelector,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
struct NormalizedPolicy {
    mode: Mode,
    run_nonce: String,
    channel_epoch: String,
    generations: Generations,
    process_denials: Vec<NormalizedNamedSelector>,
    principal_denials: Vec<NormalizedNamedSelector>,
    session_revocations: Vec<NormalizedNamedSelector>,
    escalation_ceiling: Vec<NormalizedNamedSelector>,
    static_floor: Vec<NormalizedNamedSelector>,
    handles: Vec<NormalizedNamedSelector>,
    session_grants: Vec<NormalizedNamedSelector>,
    implicit_self: Vec<NormalizedNamedSelector>,
    protected_exceptions: Vec<NormalizedProtectedException>,
    compatibility_dispositions: Vec<NormalizedCompatibilityDisposition>,
    validated_receipt_row_digests: BTreeSet<String>,
    path_bindings: Vec<PathBindingInput>,
}

#[derive(Debug, Clone, Copy)]
enum PrincipalRequirement {
    AnyOnly,
    Exact,
}

#[derive(Debug, Clone)]
pub struct Rev2Core {
    state: Arc<Rev2State>,
}

#[derive(Debug)]
#[doc(hidden)]
pub struct Rev2State {
    payload: RuntimePayload,
    definitions: BTreeMap<String, Definition>,
    edges: BTreeMap<String, EdgeSemantics>,
    schemas: BTreeMap<String, TypedSchema>,
    projections: BTreeMap<String, Projection>,
    match_operations: BTreeMap<String, String>,
}

impl Deref for Rev2Core {
    type Target = Rev2State;

    fn deref(&self) -> &Self::Target {
        &self.state
    }
}

static EMBEDDED_CORE: OnceLock<Result<Rev2Core, CoreError>> = OnceLock::new();

impl Rev2Core {
    pub fn embedded() -> Result<Self, CoreError> {
        EMBEDDED_CORE.get_or_init(Self::build_embedded).clone()
    }

    fn build_embedded() -> Result<Self, CoreError> {
        let payload_value = parse_strict_json(REV2_RUNTIME_SEMANTIC_PAYLOAD_JSON)?;
        let computed = domain_digest("oden:capsec:vocab:2", &payload_value)?;
        if computed != REV2_VOCAB_DIGEST {
            return Err(CoreError::new(
                REASON_VOCAB_MISMATCH,
                format!("embedded payload digest {computed} does not equal {REV2_VOCAB_DIGEST}"),
            ));
        }
        let payload: RuntimePayload = serde_json::from_value(payload_value)
            .map_err(|error| CoreError::new(REASON_SCHEMA_INVALID, error.to_string()))?;
        if payload.schema != "oden/capsec-runtime-vocabulary/2" || payload.profile != REV2_PROFILE {
            return Err(CoreError::new(
                REASON_VOCAB_MISMATCH,
                "embedded runtime vocabulary identity is invalid",
            ));
        }
        let definitions = unique_by_id(payload.definitions.iter().cloned(), |row| &row.id)?;
        let mut edges = BTreeMap::new();
        for edge in &payload.coverage_edges {
            if edge.kind == "coverage-edge" {
                let semantics_value = edge.semantics.clone().ok_or_else(|| {
                    CoreError::new(REASON_SCHEMA_INVALID, format!("{} has no semantics", edge.id))
                })?;
                let semantics: EdgeSemantics = serde_json::from_value(semantics_value)
                    .map_err(schema_error)?;
                validate_edge_semantics(&edge.id, &semantics)?;
                if !payload
                    .policy_rules_and_classifiers
                    .lifetime_contracts
                    .iter()
                    .any(|contract| {
                        contract.get("id").and_then(Value::as_str)
                            == Some(semantics.lifetime_contract_id.as_str())
                    })
                {
                    return Err(CoreError::new(
                        REASON_SCHEMA_INVALID,
                        format!(
                            "{} names unknown lifetime contract {}",
                            edge.id, semantics.lifetime_contract_id
                        ),
                    ));
                }
                if edges.insert(edge.id.clone(), semantics).is_some() {
                    return Err(CoreError::new(
                        REASON_SCHEMA_INVALID,
                        format!("duplicate edge {}", edge.id),
                    ));
                }
            }
        }
        let schemas = unique_by_id(
            payload
                .policy_rules_and_classifiers
                .resource_schemas
                .iter()
                .chain(&payload.policy_rules_and_classifiers.occurrence_schemas)
                .chain(&payload.policy_rules_and_classifiers.value_schemas)
                .cloned(),
            |row| &row.id,
        )?;
        for schema in schemas.values() {
            for field in &schema.fields {
                if !supported_canonicalization(&field.canonicalization)
                    || !supported_field_format(&field.format)
                {
                    return Err(CoreError::new(
                        REASON_SCHEMA_INVALID,
                        format!(
                            "{} uses unsupported canonicalization/format {}/{}",
                            schema.id, field.canonicalization, field.format
                        ),
                    ));
                }
            }
        }
        let projections = unique_by_id(
            payload.policy_rules_and_classifiers.projections.iter().cloned(),
            |row| &row.id,
        )?;
        let mut match_operations = BTreeMap::new();
        for operation in &payload
            .policy_rules_and_classifiers
            .match_evaluation_spec
            .operations
        {
            if !supported_match_algorithm(&operation.algorithm) {
                return Err(CoreError::new(
                    REASON_SCHEMA_INVALID,
                    format!("unsupported generated match algorithm {}", operation.algorithm),
                ));
            }
            if match_operations
                .insert(operation.id.clone(), operation.algorithm.clone())
                .is_some()
            {
                return Err(CoreError::new(
                    REASON_SCHEMA_INVALID,
                    format!("duplicate match operation {}", operation.id),
                ));
            }
        }
        Ok(Self {
            state: Arc::new(Rev2State {
                payload,
                definitions,
                edges,
                schemas,
                projections,
                match_operations,
            }),
        })
    }

    pub fn identity(&self) -> EngineIdentity {
        EngineIdentity::embedded()
    }

    pub fn validate_identity(&self, identity: &EngineIdentity) -> Result<(), CoreError> {
        if identity.profile != REV2_PROFILE || identity.vocab_digest != REV2_VOCAB_DIGEST {
            return Err(CoreError::new(
                REASON_VOCAB_MISMATCH,
                format!(
                    "expected {REV2_PROFILE}/{REV2_VOCAB_DIGEST}, received {}/{}",
                    identity.profile, identity.vocab_digest
                ),
            ));
        }
        if identity.registry_digest != REV2_REGISTRY_DIGEST {
            return Err(CoreError::new(
                REASON_REGISTRY_MISMATCH,
                format!(
                    "expected {REV2_REGISTRY_DIGEST}, received {}",
                    identity.registry_digest
                ),
            ));
        }
        Ok(())
    }

    pub fn normalize_selector(
        &self,
        input: &AuthoritySelectorInput,
        polarity: SelectorPolarity,
    ) -> Result<CanonicalAuthoritySelector, CoreError> {
        self.validate_identity(&input.identity)?;
        if input.capability.len() > 256
            || input
                .principal
                .as_ref()
                .is_some_and(|principal| principal.key.is_empty() || principal.key.len() > 1024)
        {
            return Err(CoreError::new(
                REASON_SCHEMA_INVALID,
                "selector capability or principal identity exceeds its bound",
            ));
        }
        let definition = self.definition(&input.capability)?;
        if polarity == SelectorPolarity::Positive
            && (definition.lifecycle != "authorable"
                || self
                    .projection(&definition.positive_projection_id)?
                    .output_kind
                    == "reject-positive")
        {
            return Err(CoreError::new(
                REASON_LIFECYCLE,
                format!("{} cannot appear in positive authority", input.capability),
            ));
        }
        let resource = self.normalize_schema(&definition.resource_schema_id, &input.resource)?;
        Ok(CanonicalAuthoritySelector {
            principal: input.principal.clone(),
            capability: input.capability.clone(),
            projection_id: definition.positive_projection_id.clone(),
            resource,
        })
    }

    pub fn normalize_effect(&self, input: &EffectInput) -> Result<CanonicalEffect, CoreError> {
        self.validate_identity(&input.identity)?;
        if input.effect_owner.trim().is_empty() || input.effect_owner.len() > 1024 {
            return Err(CoreError::new(REASON_SCHEMA_INVALID, "effect owner is empty"));
        }
        let edge = self.edges.get(&input.edge_id).ok_or_else(|| {
            CoreError::new(
                REASON_EDGE_SET_INVALID,
                format!("unknown or non-capability edge {}", input.edge_id),
            )
        })?;
        let slot = edge
            .effects
            .iter()
            .find(|slot| slot.effect_slot_id == input.effect_slot_id)
            .ok_or_else(|| {
                CoreError::new(
                    REASON_EDGE_SET_INVALID,
                    format!("{} has no slot {}", input.edge_id, input.effect_slot_id),
                )
            })?;
        if slot.capability != input.capability {
            return Err(CoreError::new(
                REASON_EDGE_SET_INVALID,
                format!(
                    "slot {} emits {}, not {}",
                    input.effect_slot_id, slot.capability, input.capability
                ),
            ));
        }
        let definition = self.definition(&input.capability)?;
        let occurrence = self.normalize_schema(&definition.occurrence_schema_id, &input.occurrence)?;
        if definition.occurrence_schema_id == "occurrence.dns-query/2"
            && occurrence
                .get("absoluteName")
                .and_then(Value::as_str)
                .is_some_and(|name| name.starts_with("*."))
        {
            return Err(CoreError::new(
                REASON_SCHEMA_INVALID,
                "a DNS occurrence must name one exact absolute name",
            ));
        }
        let occurrence_owner = occurrence
            .as_object()
            .and_then(|object| object.get("effectOwner"))
            .and_then(Value::as_str)
            .ok_or_else(|| CoreError::new(REASON_SCHEMA_INVALID, "occurrence has no effectOwner"))?;
        if occurrence_owner != input.effect_owner {
            return Err(CoreError::new(
                REASON_SCHEMA_INVALID,
                "effectOwner differs from the normalized occurrence",
            ));
        }
        Ok(CanonicalEffect {
            edge_id: input.edge_id.clone(),
            effect_slot_id: input.effect_slot_id.clone(),
            capability: input.capability.clone(),
            effect_owner: input.effect_owner.clone(),
            projection_id: definition.negative_projection_id.clone(),
            occurrence,
        })
    }

    pub fn canonical_effects_json(&self, effects: &[CanonicalEffect]) -> Result<String, CoreError> {
        canonical_json(&serde_json::to_value(effects).map_err(schema_error)?)
    }

    pub fn selector_matches_effect(
        &self,
        selector: &AuthoritySelectorInput,
        effect: &EffectInput,
        polarity: SelectorPolarity,
        source_id: &str,
        path_bindings: &[PathBindingInput],
    ) -> Result<bool, CoreError> {
        let selector = self.normalize_selector(selector, polarity)?;
        let effect = self.normalize_effect(effect)?;
        self.matches_canonical(&selector, &effect, polarity, source_id, path_bindings)
    }

    pub fn decide_stage(
        &self,
        request: &StageRequest,
        policy: &DecisionPolicyInput,
    ) -> Result<StageDecision, CoreError> {
        self.validate_identity(&request.identity)?;
        self.validate_identity(&policy.identity)?;
        if request.stage_id.trim().is_empty() || request.stage_id.len() > 1024 {
            return Err(CoreError::new(REASON_SCHEMA_INVALID, "stage id is empty"));
        }
        let principal_cells = request.principals.len().max(1);
        let decision_cells = principal_cells
            .checked_mul(request.effects.len())
            .ok_or_else(|| CoreError::new(REASON_SCHEMA_INVALID, "stage cell count overflow"))?;
        let estimated_work = decision_cells
            .checked_mul(decision_policy_row_count(policy).max(1))
            .ok_or_else(|| CoreError::new(REASON_SCHEMA_INVALID, "decision work count overflow"))?;
        if request.principals.len() > 64
            || request.effects.len() > 1024
            || decision_cells > 16_384
            || estimated_work > 1_000_000
            || request
                .principals
                .iter()
                .any(|principal| principal.key.is_empty() || principal.key.len() > 1024)
        {
            return Err(CoreError::new(
                REASON_SCHEMA_INVALID,
                "stage exceeds principal, effect, identity, or Cartesian decision bounds",
            ));
        }
        let principals = normalize_principal_set(&request.principals);
        let mut keyed_effects = Vec::with_capacity(request.effects.len());
        let mut effect_keys = BTreeSet::new();
        for input in &request.effects {
            let effect = self.normalize_effect(input)?;
            let key = canonical_json(&serde_json::to_value(&effect).map_err(schema_error)?)?;
            if !effect_keys.insert(key.clone()) {
                return Err(CoreError::new(
                    REASON_DUPLICATE_EFFECT,
                    format!("duplicate effect {} / {}", effect.edge_id, effect.effect_slot_id),
                ));
            }
            keyed_effects.push((key, effect));
        }
        if keyed_effects.is_empty() {
            return Err(CoreError::new(
                REASON_EDGE_SET_INVALID,
                "a decision stage must contain at least one effect",
            ));
        }
        let owners: BTreeSet<&str> = keyed_effects
            .iter()
            .map(|(_, effect)| effect.effect_owner.as_str())
            .collect();
        if owners.len() != 1 {
            return Err(CoreError::new(
                REASON_OPERATION_CONTEXT,
                "one edge invocation must have exactly one captured effect owner",
            ));
        }
        keyed_effects.sort_by(|left, right| left.0.cmp(&right.0));
        let effects: Vec<CanonicalEffect> =
            keyed_effects.into_iter().map(|(_, effect)| effect).collect();
        self.validate_edge_selection(&effects)?;
        let policy = self.normalize_policy(policy)?;
        let canonical_effects_json = self.canonical_effects_json(&effects)?;
        let mut outcome = Outcome::Allow;
        let mut decisions = Vec::with_capacity(effects.len());
        let mut committed_effects = Vec::with_capacity(effects.len());
        let mut omitted_effects = Vec::new();
        for effect in effects {
            let decision = self.decide_effect(&effect, &principals, &policy, &request.stage_id)?;
            let masked_contract = self
                .edges
                .get(&effect.edge_id)
                .and_then(|edge| edge.masked_commit.as_ref())
                .filter(|contract| contract.masked_effect_slot_id == effect.effect_slot_id);
            match (decision.outcome, masked_contract) {
                (Outcome::Allow, _) => committed_effects.push(effect.clone()),
                (Outcome::Masked, Some(contract)) => {
                    let required = value_at_path(
                        &effect.occurrence,
                        &contract.required_for_commit_occurrence_path,
                    )
                    .and_then(Value::as_bool)
                    .ok_or_else(|| {
                        CoreError::new(
                            REASON_SCHEMA_INVALID,
                            "masked-commit requiredness is not a trusted boolean fact",
                        )
                    })?;
                    if required {
                        outcome = Outcome::Deny;
                    } else {
                        let mut reason_codes: Vec<String> = decision
                            .dimensions
                            .iter()
                            .filter(|dimension| dimension.outcome == Outcome::Masked)
                            .map(|dimension| dimension.reason_code.clone())
                            .collect();
                        reason_codes.sort();
                        reason_codes.dedup();
                        omitted_effects.push(MaskedEffectOmission {
                            effect: effect.clone(),
                            reason_codes,
                        });
                    }
                }
                (effect_outcome, _) => outcome = outcome.combine(effect_outcome),
            }
            decisions.push(decision);
        }
        if outcome != Outcome::Allow {
            committed_effects.clear();
        }
        Ok(StageDecision {
            stage_id: request.stage_id.clone(),
            outcome,
            effects: decisions,
            committed_effects,
            omitted_effects,
            canonical_effects_json,
        })
    }

    pub fn normalize_schema(&self, schema_id: &str, input: &Value) -> Result<Value, CoreError> {
        let mut stack = Vec::new();
        self.normalize_schema_inner(schema_id, input, &mut stack)
    }

    fn definition(&self, capability: &str) -> Result<&Definition, CoreError> {
        self.definitions.get(capability).ok_or_else(|| {
            CoreError::new(
                REASON_LIFECYCLE,
                format!("unknown or planned definition {capability}"),
            )
        })
    }

    fn validate_edge_selection(&self, effects: &[CanonicalEffect]) -> Result<(), CoreError> {
        let mut grouped: BTreeMap<&str, Vec<&CanonicalEffect>> = BTreeMap::new();
        for effect in effects {
            grouped.entry(&effect.edge_id).or_default().push(effect);
        }
        if grouped.len() != 1 {
            return Err(CoreError::new(
                REASON_EDGE_SET_INVALID,
                "one decision stage must represent exactly one coverage-edge invocation",
            ));
        }
        for (edge_id, selected) in grouped {
            let edge = self.edges.get(edge_id).ok_or_else(|| {
                CoreError::new(REASON_EDGE_SET_INVALID, format!("unknown edge {edge_id}"))
            })?;
            if edge.effect_mode == "alternative" && selected.len() != 1 {
                return Err(CoreError::new(
                    REASON_EDGE_SET_INVALID,
                    format!("alternative edge {edge_id} selected {} branches", selected.len()),
                ));
            }
            if edge.effect_mode != "alternative" && edge.effect_mode != "conjunctive" {
                return Err(CoreError::new(
                    REASON_EDGE_SET_INVALID,
                    format!("edge {edge_id} has unknown effect mode {}", edge.effect_mode),
                ));
            }
            if (edge.effects.len() > 1 && edge.effect_mode == "conjunctive")
                != edge.atomicity_group.is_some()
            {
                return Err(CoreError::new(
                    REASON_EDGE_SET_INVALID,
                    format!("edge {edge_id} violates generated atomicity"),
                ));
            }
            if edge.effect_mode == "conjunctive" {
                let invalid: Vec<(&str, &str, usize)> = edge
                    .effects
                    .iter()
                    .filter_map(|template| {
                        let count = selected
                            .iter()
                            .filter(|effect| effect.effect_slot_id == template.effect_slot_id)
                            .count();
                        match template.cardinality.as_str() {
                            "exactly-one" if count != 1 => Some((
                                template.effect_slot_id.as_str(),
                                template.cardinality.as_str(),
                                count,
                            )),
                            "zero-or-more" => None,
                            "exactly-one" => None,
                            _ => Some((
                                template.effect_slot_id.as_str(),
                                template.cardinality.as_str(),
                                count,
                            )),
                        }
                    })
                    .collect();
                if !invalid.is_empty() {
                    return Err(CoreError::new(
                        REASON_EDGE_SET_INVALID,
                        format!("conjunctive edge {edge_id} violates cardinality {invalid:?}"),
                    ));
                }
            }
            if edge.effect_mode == "alternative" {
                let mut branch_keys = BTreeSet::new();
                for candidate in &edge.effects {
                    let key = candidate
                        .branch_id
                        .as_deref()
                        .unwrap_or(candidate.effect_slot_id.as_str());
                    if !branch_keys.insert(key) {
                        return Err(CoreError::new(
                            REASON_EDGE_SET_INVALID,
                            format!("alternative edge {edge_id} has duplicate branch key {key}"),
                        ));
                    }
                }
                let selected_slot = &selected[0].effect_slot_id;
                let branch = edge
                    .effects
                    .iter()
                    .find(|candidate| candidate.effect_slot_id == *selected_slot)
                    .and_then(|candidate| {
                        candidate
                            .branch_id
                            .as_deref()
                            .or(Some(candidate.effect_slot_id.as_str()))
                    });
                if branch.is_none() {
                    return Err(CoreError::new(
                        REASON_EDGE_SET_INVALID,
                        format!("alternative edge {edge_id} has no stable branch key"),
                    ));
                }
            }
        }
        Ok(())
    }

    fn normalize_policy(&self, input: &DecisionPolicyInput) -> Result<NormalizedPolicy, CoreError> {
        if input.run_nonce.trim().is_empty()
            || input.channel_epoch.trim().is_empty()
            || input.run_nonce.len() > 1024
            || input.channel_epoch.len() > 1024
        {
            return Err(CoreError::new(
                REASON_SCHEMA_INVALID,
                "run nonce and channel epoch must be nonempty",
            ));
        }
        let policy_rows = decision_policy_row_count(input);
        if policy_rows > 4096 {
            return Err(CoreError::new(
                REASON_SCHEMA_INVALID,
                "policy exceeds normalized row bound",
            ));
        }
        validate_digest_string(&input.provenance.policy_digest)?;
        validate_digest_string(&input.provenance.armed_snapshot_digest)?;
        if input.provenance.quota_owner.key.trim().is_empty()
            || input.provenance.quota_owner.key.len() > 1024
            || input.provenance.terminal_evidence_id.trim().is_empty()
            || input.provenance.terminal_evidence_id.len() > 1024
        {
            return Err(CoreError::new(
                REASON_SCHEMA_INVALID,
                "operation provenance has an empty quota owner or terminal evidence identity",
            ));
        }
        for generation in [
            &input.generations.negative_overlay,
            &input.generations.policy_snapshot,
            &input.generations.revocation,
            &input.generations.session_overlay,
        ] {
            validate_u64_decimal(generation)?;
        }
        let process_denials = self.normalize_named_selectors(
            &input.process_denials,
            SelectorPolarity::Negative,
            PrincipalRequirement::AnyOnly,
            "process denial",
        )?;
        let principal_denials = self.normalize_named_selectors(
            &input.principal_denials,
            SelectorPolarity::Negative,
            PrincipalRequirement::Exact,
            "principal denial",
        )?;
        let session_revocations = self.normalize_named_selectors(
            &input.session_revocations,
            SelectorPolarity::Negative,
            PrincipalRequirement::Exact,
            "session revocation",
        )?;
        let escalation_ceiling = self.normalize_named_selectors(
            &input.escalation_ceiling,
            SelectorPolarity::Positive,
            PrincipalRequirement::Exact,
            "escalation ceiling",
        )?;
        let mut static_floor = self.normalize_named_selectors(
            &input.static_floor,
            SelectorPolarity::Positive,
            PrincipalRequirement::Exact,
            "static floor",
        )?;
        for row in &mut static_floor {
            row.source_id = canonical_row_digest(&row.selector)?;
        }
        static_floor.sort_by(|left, right| left.source_id.cmp(&right.source_id));
        let handles = self.normalize_handle_selectors(input)?;
        let session_grants = self.normalize_named_selectors(
            &input.session_grants,
            SelectorPolarity::Positive,
            PrincipalRequirement::Exact,
            "session grant",
        )?;
        let implicit_self = self.normalize_named_selectors(
            &input.implicit_self,
            SelectorPolarity::Positive,
            PrincipalRequirement::Exact,
            "implicit self",
        )?;
        let mut protected_exceptions = Vec::new();
        let mut protected_ids = BTreeSet::new();
        for row in &input.protected_exceptions {
            if row.source_id.trim().is_empty()
                || row.source_id.len() > 1024
                || row.reason.trim().is_empty()
                || row.reason.len() > 4096
            {
                return Err(CoreError::new(
                    REASON_SCHEMA_INVALID,
                    "protected exceptions require source identity and reason",
                ));
            }
            if !protected_ids.insert(row.source_id.clone()) {
                return Err(CoreError::new(
                    REASON_SCHEMA_INVALID,
                    format!("duplicate protected exception {}", row.source_id),
                ));
            }
            let selector = self.normalize_selector(&row.selector, SelectorPolarity::Positive)?;
            if selector.principal.is_none() {
                return Err(CoreError::new(
                    REASON_SCHEMA_INVALID,
                    "protected exception requires an exact principal",
                ));
            }
            protected_exceptions.push(NormalizedProtectedException {
                source_id: row.source_id.clone(),
                reason: row.reason.clone(),
                selector,
            });
        }
        protected_exceptions.sort_by(|left, right| left.source_id.cmp(&right.source_id));
        let mut compatibility_dispositions = Vec::new();
        let mut disposition_ids = BTreeSet::new();
        for row in &input.compatibility_dispositions {
            if row.disposition_id != "env:ignore"
                || !self.generated_disposition_exists(&row.disposition_id)
                || row.source_id.trim().is_empty()
                || row.source_id.len() > 1024
            {
                return Err(CoreError::new(
                    REASON_SCHEMA_INVALID,
                    "unknown compatibility disposition",
                ));
            }
            if !disposition_ids.insert(row.source_id.clone()) {
                return Err(CoreError::new(
                    REASON_SCHEMA_INVALID,
                    format!("duplicate disposition {}", row.source_id),
                ));
            }
            let selector = self.normalize_selector(&row.selector, SelectorPolarity::Positive)?;
            if selector.principal.is_none() || selector.capability != "env:read" {
                return Err(CoreError::new(
                    REASON_SCHEMA_INVALID,
                    "env:ignore requires an exact env:read selector",
                ));
            }
            compatibility_dispositions.push(NormalizedCompatibilityDisposition {
                disposition_id: row.disposition_id.clone(),
                source_id: row.source_id.clone(),
                selector,
            });
        }
        compatibility_dispositions.sort_by(|left, right| left.source_id.cmp(&right.source_id));
        let mut positive_ids = BTreeSet::new();
        for row in static_floor
            .iter()
            .chain(&handles)
            .chain(&session_grants)
            .chain(&implicit_self)
        {
            if !positive_ids.insert(row.source_id.clone()) {
                return Err(CoreError::new(
                    REASON_SCHEMA_INVALID,
                    format!("duplicate positive source identity {}", row.source_id),
                ));
            }
        }
        let mut binding_source_ids = positive_ids.clone();
        for row in process_denials
            .iter()
            .chain(&principal_denials)
            .chain(&session_revocations)
            .chain(&escalation_ceiling)
        {
            if !binding_source_ids.insert(row.source_id.clone()) {
                return Err(CoreError::new(
                    REASON_SCHEMA_INVALID,
                    format!("ambiguous policy source identity {}", row.source_id),
                ));
            }
        }
        for row in &protected_exceptions {
            if !binding_source_ids.insert(row.source_id.clone()) {
                return Err(CoreError::new(
                    REASON_SCHEMA_INVALID,
                    format!("ambiguous policy source identity {}", row.source_id),
                ));
            }
        }
        let mut receipt_digests = BTreeSet::new();
        for digest in &input.validated_receipt_row_digests {
            validate_digest_string(digest)?;
            if !receipt_digests.insert(digest.clone()) {
                return Err(CoreError::new(
                    REASON_SCHEMA_INVALID,
                    format!("duplicate validated receipt row digest {digest}"),
                ));
            }
        }
        let mut path_bindings = Vec::new();
        let mut binding_keys = BTreeSet::new();
        for binding in &input.path_bindings {
            if binding.source_id.trim().is_empty()
                || binding.root_binding_id.trim().is_empty()
                || !binding_source_ids.contains(&binding.source_id)
                || !binding_keys.insert((binding.source_id.clone(), binding.root_binding_id.clone()))
            {
                return Err(CoreError::new(
                    REASON_SCHEMA_INVALID,
                    "path binding is empty, duplicated, or names no policy source",
                ));
            }
            let final_object_identities = canonical_value_set(
                binding
                    .final_object_identities
                    .iter()
                    .map(|identity| self.normalize_schema("value.object-identity/2", identity))
                    .collect::<Result<Vec<_>, _>>()?,
            )?;
            let parent_identities = canonical_value_set(
                binding
                    .parent_identities
                    .iter()
                    .map(|identity| self.normalize_schema("value.object-identity/2", identity))
                    .collect::<Result<Vec<_>, _>>()?,
            )?;
            path_bindings.push(PathBindingInput {
                source_id: binding.source_id.clone(),
                root_binding_id: binding.root_binding_id.clone(),
                final_object_identities,
                parent_identities,
            });
        }
        path_bindings.sort_by(|left, right| {
            (&left.source_id, &left.root_binding_id)
                .cmp(&(&right.source_id, &right.root_binding_id))
        });
        Ok(NormalizedPolicy {
            mode: input.mode,
            run_nonce: input.run_nonce.clone(),
            channel_epoch: input.channel_epoch.clone(),
            generations: input.generations.clone(),
            process_denials,
            principal_denials,
            session_revocations,
            escalation_ceiling,
            static_floor,
            handles,
            session_grants,
            implicit_self,
            protected_exceptions,
            compatibility_dispositions,
            validated_receipt_row_digests: receipt_digests,
            path_bindings,
        })
    }

    fn normalize_named_selectors(
        &self,
        input: &[NamedSelectorInput],
        polarity: SelectorPolarity,
        principal_requirement: PrincipalRequirement,
        label: &str,
    ) -> Result<Vec<NormalizedNamedSelector>, CoreError> {
        let mut out = Vec::with_capacity(input.len());
        let mut source_ids = BTreeSet::new();
        for row in input {
            if row.source_id.trim().is_empty()
                || row.source_id.len() > 1024
                || !source_ids.insert(row.source_id.clone())
            {
                return Err(CoreError::new(
                    REASON_SCHEMA_INVALID,
                    format!("{label} source identity is empty or duplicated"),
                ));
            }
            let selector = self.normalize_selector(&row.selector, polarity)?;
            let principal_ok = match principal_requirement {
                PrincipalRequirement::AnyOnly => selector.principal.is_none(),
                PrincipalRequirement::Exact => selector.principal.is_some(),
            };
            if !principal_ok {
                return Err(CoreError::new(
                    REASON_SCHEMA_INVALID,
                    format!("{label} has the wrong principal shape"),
                ));
            }
            out.push(NormalizedNamedSelector {
                source_id: row.source_id.clone(),
                source_generation: None,
                selector,
            });
        }
        out.sort_by(|left, right| left.source_id.cmp(&right.source_id));
        Ok(out)
    }

    fn normalize_handle_selectors(
        &self,
        input: &DecisionPolicyInput,
    ) -> Result<Vec<NormalizedNamedSelector>, CoreError> {
        let mut out = Vec::with_capacity(input.handles.len());
        let mut ids = BTreeSet::new();
        for handle in &input.handles {
            validate_u64_decimal(&handle.handle_generation)?;
            validate_digest_string(&handle.armed_snapshot_digest)?;
            if handle.handle_id.trim().is_empty()
                || handle.handle_id.len() > 1024
                || !ids.insert(handle.handle_id.clone())
                || handle.armed_snapshot_digest != input.provenance.armed_snapshot_digest
                || handle.carrier_epoch != input.channel_epoch
            {
                return Err(CoreError::new(
                    REASON_SCHEMA_INVALID,
                    "handle fact is empty, duplicated, or outside the armed snapshot/carrier",
                ));
            }
            let selector =
                self.normalize_selector(&handle.selector, SelectorPolarity::Positive)?;
            if selector.principal.is_none() {
                return Err(CoreError::new(
                    REASON_SCHEMA_INVALID,
                    "handle fact requires an exact delegatee principal",
                ));
            }
            out.push(NormalizedNamedSelector {
                source_id: handle.handle_id.clone(),
                source_generation: Some(handle.handle_generation.clone()),
                selector,
            });
        }
        out.sort_by(|left, right| left.source_id.cmp(&right.source_id));
        Ok(out)
    }

    fn decide_effect(
        &self,
        effect: &CanonicalEffect,
        principals: &[PrincipalRef],
        policy: &NormalizedPolicy,
        stage_id: &str,
    ) -> Result<EffectDecision, CoreError> {
        let mut outcome = Outcome::Allow;
        let mut dimensions = Vec::with_capacity(principals.len());
        for principal in principals {
            let dimension = self.decide_dimension(effect, principal, principals, policy, stage_id)?;
            outcome = outcome.combine(dimension.outcome);
            dimensions.push(dimension);
        }
        Ok(EffectDecision {
            effect: effect.clone(),
            outcome,
            dimensions,
        })
    }

    fn decide_dimension(
        &self,
        effect: &CanonicalEffect,
        principal: &PrincipalRef,
        _principal_set: &[PrincipalRef],
        policy: &NormalizedPolicy,
        stage_id: &str,
    ) -> Result<DimensionDecision, CoreError> {
        let deny = |stratum: u8, reason_code: &str| DimensionDecision {
            principal: principal.clone(),
            outcome: Outcome::Deny,
            stratum,
            reason_code: reason_code.to_string(),
            positive_source: None,
        };
        let allow = |stratum: u8, source: PositiveSource| DimensionDecision {
            principal: principal.clone(),
            outcome: Outcome::Allow,
            stratum,
            reason_code: REASON_ALLOW.to_string(),
            positive_source: Some(source),
        };

        // Stratum 1 is handled before this method: strict JSON, identity,
        // registry, schema, edge, and duplicate validation either succeeds or
        // refuses the complete stage.
        if principal.kind == PrincipalKind::NoUser || principal.key.trim().is_empty() {
            return Ok(deny(2, REASON_UNATTRIBUTED));
        }
        let definition = self.definition(&effect.capability)?;
        if definition.lifecycle != "authorable" && !principal.is_root() {
            return Ok(deny(3, REASON_LIFECYCLE));
        }
        let edge = self.edges.get(&effect.edge_id).ok_or_else(|| {
            CoreError::new(REASON_EDGE_SET_INVALID, format!("unknown edge {}", effect.edge_id))
        })?;
        if edge.gate.mechanism == "deny-only" && !principal.is_root() {
            return Ok(deny(3, REASON_LIFECYCLE));
        }

        let mut protected_static = None;
        if self.is_metadata_effect(effect)? {
            let mut exception = None;
            for row in &policy.protected_exceptions {
                if row.reason.trim().is_empty()
                    || !selector_principal_matches(&row.selector, principal, false)
                {
                    continue;
                }
                if self.metadata_exception_exactly_matches(
                    &row.selector,
                    effect,
                    &row.source_id,
                    &policy.path_bindings,
                )? {
                    exception = Some(row);
                    break;
                }
            }
            let Some(exception) = exception else {
                return Ok(deny(4, REASON_PROTECTED));
            };
            protected_static = policy.static_floor.iter().find(|row| {
                row.selector == exception.selector
                    && selector_principal_matches(&row.selector, principal, false)
            });
            if protected_static.is_none() {
                return Ok(deny(4, REASON_PROTECTED));
            }
            // The exact exception and exact static row only clear the
            // protected-resource guard. Strata 5--7 still run below.
        }

        if self.find_matching_named(
            &policy.process_denials,
            principal,
            effect,
            SelectorPolarity::Negative,
            true,
            &policy.path_bindings,
        )?.is_some() {
            return Ok(deny(5, REASON_PROCESS_CEILING));
        }
        if self.find_matching_named(
            &policy.principal_denials,
            principal,
            effect,
            SelectorPolarity::Negative,
            false,
            &policy.path_bindings,
        )?.is_some() {
            return Ok(deny(6, REASON_PRINCIPAL_DENIAL));
        }
        if self.find_matching_named(
            &policy.session_revocations,
            principal,
            effect,
            SelectorPolarity::Negative,
            false,
            &policy.path_bindings,
        )?.is_some() {
            return Ok(deny(7, REASON_REVOKED));
        }

        let has_positive_predicate = edge.edge_predicate_id.is_some()
            || definition.positive_required
            || definition.protected_receipt_predicate_id.is_some()
            || definition.root_edge_predicate_id.is_some();
        if has_positive_predicate {
            let exact_static = self.find_exact_static(policy, principal, effect)?;
            let edge_ok = match edge.edge_predicate_id.as_deref() {
                None => true,
                Some("predicate.exact-static-row-required/2")
                    if self.generated_predicate_exists("predicate.exact-static-row-required/2") =>
                {
                    exact_static.is_some()
                }
                Some(_) => false,
            };
            let positive_required_ok = !definition.positive_required || exact_static.is_some();
            let receipt_ok = match &definition.protected_receipt_predicate_id {
                None => true,
                Some(_) => exact_static.is_some_and(|row| {
                    policy.validated_receipt_row_digests.contains(&row.source_id)
                }),
            };
            // No root-edge predicate is advertised by the current generated
            // vocabulary. An unknown future predicate fails closed until its
            // generated evaluator lands.
            let root_edge_ok = definition.root_edge_predicate_id.is_none();
            let predicate_channel_ok = edge
                .positive_channels
                .iter()
                .any(|channel| channel == "floor");
            if !(edge_ok
                && positive_required_ok
                && receipt_ok
                && root_edge_ok
                && predicate_channel_ok)
            {
                return Ok(deny(8, REASON_POSITIVE_PREDICATE));
            }
            let row = exact_static.expect("every current positive predicate requires static row");
            let mut source_id = row.source_id.clone();
            if definition.protected_receipt_predicate_id.is_some() {
                source_id.push_str("+validated-receipt");
            }
            return Ok(allow(
                8,
                PositiveSource {
                    kind: "predicate-static-row".to_string(),
                    source_id,
                    generation: None,
                },
            ));
        }

        if definition.channels.iter().any(|channel| channel == "floor")
            && edge.positive_channels.iter().any(|channel| channel == "floor")
        {
            let row = if let Some(row) = protected_static {
                Some(row)
            } else {
                self.find_matching_named(
                    &policy.static_floor,
                    principal,
                    effect,
                    SelectorPolarity::Positive,
                    false,
                    &policy.path_bindings,
                )?
            };
            if let Some(row) = row {
                return Ok(allow(
                    9,
                    PositiveSource {
                        kind: "static-row".to_string(),
                        source_id: row.source_id.clone(),
                        generation: None,
                    },
                ));
            }
        }
        let within_escalation_ceiling = if definition
            .channels
            .iter()
            .any(|channel| channel == "escalation-ceiling")
        {
            self.find_matching_named(
                &policy.escalation_ceiling,
                principal,
                effect,
                SelectorPolarity::Positive,
                false,
                &policy.path_bindings,
            )?
            .is_some()
        } else {
            true
        };
        let lease_eligible = definition.channels.iter().any(|channel| channel == "handle")
            && edge.positive_channels.iter().any(|channel| channel == "handle")
            && !definition.constraints.iter().any(|constraint| {
                constraint == "static-only" || constraint == "nondelegable"
            });
        if lease_eligible {
            if let Some(row) = self.find_matching_named(
                &policy.handles,
                principal,
                effect,
                SelectorPolarity::Positive,
                false,
                &policy.path_bindings,
            )? {
                return Ok(allow(
                    10,
                    PositiveSource {
                        kind: "handle".to_string(),
                        source_id: row.source_id.clone(),
                        generation: row.source_generation.clone(),
                    },
                ));
            }
        }
        if definition.channels.iter().any(|channel| channel == "session")
            && edge.positive_channels.iter().any(|channel| channel == "session")
            && within_escalation_ceiling
        {
            if let Some(row) = self.find_matching_named(
                &policy.session_grants,
                principal,
                effect,
                SelectorPolarity::Positive,
                false,
                &policy.path_bindings,
            )? {
                return Ok(allow(
                    11,
                    PositiveSource {
                        kind: "session-row".to_string(),
                        source_id: row.source_id.clone(),
                        generation: Some(policy.generations.session_overlay.clone()),
                    },
                ));
            }
        }
        if self.implicit_self_registered(&effect.capability)
            && edge
                .positive_channels
                .iter()
                .any(|channel| channel == "implicit-self")
        {
            let mut implicit_row = None;
            for row in &policy.implicit_self {
                if self.implicit_self_row_is_exact(
                    row,
                    principal,
                    effect,
                    edge,
                    &policy.path_bindings,
                )? {
                    implicit_row = Some(row);
                    break;
                }
            }
            if let Some(row) = implicit_row {
                return Ok(allow(
                    12,
                    PositiveSource {
                        kind: "implicit-package-self".to_string(),
                        source_id: row.source_id.clone(),
                        generation: Some(policy.generations.policy_snapshot.clone()),
                    },
                ));
            }
        }
        if principal.is_root()
            && edge
                .positive_channels
                .iter()
                .any(|channel| channel == "ambient-root")
        {
            return Ok(allow(
                13,
                PositiveSource {
                    kind: "ambient-root".to_string(),
                    source_id: format!("ambient-root:{}", principal.key),
                    generation: Some(policy.generations.policy_snapshot.clone()),
                },
            ));
        }
        if principal.kind == PrincipalKind::Quarantine {
            return Ok(deny(14, REASON_QUARANTINE));
        }
        for row in &policy.compatibility_dispositions {
            if row.disposition_id == "env:ignore"
                && selector_principal_matches(&row.selector, principal, false)
                && self.matches_canonical(
                    &row.selector,
                    effect,
                    SelectorPolarity::Positive,
                    &row.source_id,
                    &policy.path_bindings,
                )?
            {
                return Ok(DimensionDecision {
                    principal: principal.clone(),
                    outcome: Outcome::Masked,
                    stratum: 15,
                    reason_code: REASON_ENV_MASKED.to_string(),
                    positive_source: None,
                });
            }
        }
        if effect.capability == "env:read"
            && effect
                .occurrence
                .get("targetKind")
                .and_then(Value::as_str)
                .is_some_and(|kind| matches!(kind, "broker" | "broker-base"))
        {
            return Ok(match policy.mode {
                Mode::Enforce => deny(16, REASON_MISSING_AUTHORITY),
                Mode::Permissive | Mode::Audit => DimensionDecision {
                    principal: principal.clone(),
                    outcome: Outcome::Masked,
                    stratum: 16,
                    reason_code: REASON_ENV_MASKED.to_string(),
                    positive_source: None,
                },
            });
        }
        if matches!(policy.mode, Mode::Permissive | Mode::Audit)
            && edge.positive_channels.iter().any(|channel| channel == "mode-fallback")
            && !definition.constraints.iter().any(|constraint| constraint == "static-only")
        {
            let source = serde_json::json!({
                "channelEpoch": policy.channel_epoch,
                "mode": policy.mode,
                "runNonce": policy.run_nonce,
                "stageId": stage_id,
            });
            return Ok(DimensionDecision {
                principal: principal.clone(),
                outcome: Outcome::Allow,
                stratum: 17,
                reason_code: if policy.mode == Mode::Audit {
                    REASON_AUDIT_ALLOW.to_string()
                } else {
                    REASON_ALLOW.to_string()
                },
                positive_source: Some(PositiveSource {
                    kind: "mode-fallback".to_string(),
                    source_id: domain_digest("oden:capsec:mode-fallback:2", &source)?,
                    generation: Some(policy.generations.policy_snapshot.clone()),
                }),
            });
        }
        Ok(deny(17, REASON_MISSING_AUTHORITY))
    }

    fn find_matching_named<'a>(
        &self,
        rows: &'a [NormalizedNamedSelector],
        principal: &PrincipalRef,
        effect: &CanonicalEffect,
        polarity: SelectorPolarity,
        allow_any_principal: bool,
        path_bindings: &[PathBindingInput],
    ) -> Result<Option<&'a NormalizedNamedSelector>, CoreError> {
        for row in rows {
            if !selector_principal_matches(&row.selector, principal, allow_any_principal) {
                continue;
            }
            if self.matches_canonical(
                &row.selector,
                effect,
                polarity,
                &row.source_id,
                path_bindings,
            )? {
                return Ok(Some(row));
            }
        }
        Ok(None)
    }

    fn find_exact_static<'a>(
        &self,
        policy: &'a NormalizedPolicy,
        principal: &PrincipalRef,
        effect: &CanonicalEffect,
    ) -> Result<Option<&'a NormalizedNamedSelector>, CoreError> {
        for row in &policy.static_floor {
            if !selector_principal_matches(&row.selector, principal, false) {
                continue;
            }
            if self.selector_exactly_matches(
                &row.selector,
                effect,
                SelectorPolarity::Positive,
                &row.source_id,
                &policy.path_bindings,
            )? {
                return Ok(Some(row));
            }
        }
        Ok(None)
    }

    fn selector_exactly_matches(
        &self,
        selector: &CanonicalAuthoritySelector,
        effect: &CanonicalEffect,
        polarity: SelectorPolarity,
        source_id: &str,
        path_bindings: &[PathBindingInput],
    ) -> Result<bool, CoreError> {
        if !self.matches_canonical(selector, effect, polarity, source_id, path_bindings)? {
            return Ok(false);
        }
        let definition = self.definition(&effect.capability)?;
        let projection = self.projection(&definition.positive_projection_id)?;
        let Some(spec) = &projection.match_spec else {
            return Ok(false);
        };
        for clause in &spec.clauses {
            let selector_value = value_at_path(&selector.resource, &clause.selector_path)
                .ok_or_else(match_type_error)?;
            let occurrence_value = value_at_path(&effect.occurrence, &clause.occurrence_path)
                .ok_or_else(match_type_error)?;
            let algorithm = self.match_operations.get(&clause.operation).ok_or_else(|| {
                CoreError::new(REASON_SCHEMA_INVALID, "unknown exact-match operation")
            })?;
            if !self.exact_match_clause(algorithm, selector_value, occurrence_value)? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn metadata_exception_exactly_matches(
        &self,
        selector: &CanonicalAuthoritySelector,
        effect: &CanonicalEffect,
        source_id: &str,
        path_bindings: &[PathBindingInput],
    ) -> Result<bool, CoreError> {
        let selector_host = selector.resource.get("host").and_then(Value::as_object);
        let requested = effect
            .occurrence
            .get("requestedHost")
            .and_then(Value::as_object);
        let verified = effect
            .occurrence
            .get("verifiedPeer")
            .and_then(Value::as_object);
        let exact_literal = matches!(
            (selector_host, requested, verified),
            (Some(selector_host), Some(requested), Some(verified))
                if selector_host.get("kind").and_then(Value::as_str) == Some("ip-exact")
                    && requested.get("kind").and_then(Value::as_str) == Some("ip-exact")
                    && verified.get("kind").and_then(Value::as_str) == Some("ip")
                    && selector_host.get("value") == requested.get("value")
                    && requested.get("value") == verified.get("value")
        );
        if !exact_literal
            || selector.resource.get("peerClasses") != Some(&serde_json::json!(["metadata"]))
        {
            return Ok(false);
        }
        self.selector_exactly_matches(
            selector,
            effect,
            SelectorPolarity::Positive,
            source_id,
            path_bindings,
        )
    }

    fn exact_match_clause(
        &self,
        algorithm: &str,
        selector: &Value,
        occurrence: &Value,
    ) -> Result<bool, CoreError> {
        match algorithm {
            "json-equal" => Ok(selector == occurrence),
            "set-contains-all" => Ok(selector == occurrence),
            "dns-exact-or-subtree" => Ok(
                selector.as_str().is_some_and(|value| !value.starts_with("*."))
                    && selector == occurrence,
            ),
            "port-exact-range-any" => Ok(
                selector.get("kind").and_then(Value::as_str) == Some("exact")
                    && selector.get("exact") == Some(occurrence),
            ),
            "scheme-transport-conjunction" => {
                let Some(array) = selector.as_array() else {
                    return Ok(false);
                };
                let scheme = occurrence.get("scheme");
                Ok(array.len() == 1 && scheme == array.first())
            }
            "peer-class-conjunction" => {
                let Some(peer) = occurrence.get("verifiedPeer").or(Some(occurrence)) else {
                    return Ok(false);
                };
                let Some(address) = peer.get("value").and_then(Value::as_str) else {
                    return Ok(false);
                };
                let classes = self.ip_classes(address)?;
                Ok(selector
                    == &Value::Array(classes.into_iter().map(Value::String).collect::<Vec<_>>()))
            }
            "network-host-peer-conjunction" => {
                let selector_kind = selector.get("kind").and_then(Value::as_str);
                let requested = occurrence.get("requestedHost").unwrap_or(occurrence);
                Ok(matches!(selector_kind, Some("dns-exact" | "ip-exact" | "unix-path" | "unix-abstract" | "vsock"))
                    && selector == requested)
            }
            "path-exact-or-tree" => {
                Ok(selector.get("kind").and_then(Value::as_str) == Some("path-exact")
                    && selector.get("root") == occurrence.get("root")
                    && selector.get("path") == occurrence.get("lexicalPath"))
            }
            _ => Ok(false),
        }
    }

    fn implicit_self_registered(&self, capability: &str) -> bool {
        capability == "fs:read"
            && self
                .payload
                .policy_rules_and_classifiers
                .derivation_rules
                .iter()
                .any(|row| row.get("id").and_then(Value::as_str) == Some("implicit.package-self"))
    }

    fn implicit_self_row_is_exact(
        &self,
        row: &NormalizedNamedSelector,
        principal: &PrincipalRef,
        effect: &CanonicalEffect,
        edge: &EdgeSemantics,
        path_bindings: &[PathBindingInput],
    ) -> Result<bool, CoreError> {
        if principal.kind != PrincipalKind::Package
            || edge.gate.mechanism != "loader-admission"
            || row.selector.principal.as_ref() != Some(principal)
            || row.selector.capability != "fs:read"
            || row.selector.resource.get("kind").and_then(Value::as_str) != Some("path-exact")
            || row.selector.resource.get("root").and_then(Value::as_str) != Some("$PACKAGE")
            || effect.occurrence.get("root").and_then(Value::as_str) != Some("$PACKAGE")
            || effect
                .occurrence
                .pointer("/finalObjectState/kind")
                .and_then(Value::as_str)
                != Some("existing")
        {
            return Ok(false);
        }
        self.matches_canonical(
            &row.selector,
            effect,
            SelectorPolarity::Positive,
            &row.source_id,
            path_bindings,
        )
    }

    fn generated_predicate_exists(&self, predicate_id: &str) -> bool {
        self.payload
            .policy_rules_and_classifiers
            .predicates
            .iter()
            .any(|row| row.get("id").and_then(Value::as_str) == Some(predicate_id))
    }

    fn generated_disposition_exists(&self, disposition_id: &str) -> bool {
        self.payload
            .policy_rules_and_classifiers
            .dispositions
            .iter()
            .any(|row| row.get("id").and_then(Value::as_str) == Some(disposition_id))
    }

    fn data_table(&self, table_id: &str) -> Option<&Value> {
        self.payload
            .policy_rules_and_classifiers
            .match_evaluation_spec
            .data_tables
            .iter()
            .find(|row| row.get("id").and_then(Value::as_str) == Some(table_id))
            .and_then(|row| row.get("data"))
    }

    fn scheme_transport_allowed(&self, scheme: &str, transport: &str) -> bool {
        self.data_table("table.scheme-transport/2")
            .and_then(Value::as_object)
            .and_then(|table| table.get(scheme))
            .and_then(Value::as_array)
            .is_some_and(|transports| {
                transports
                    .iter()
                    .any(|candidate| candidate.as_str() == Some(transport))
            })
    }

    fn scheme_transport_matches(
        &self,
        selector: &Value,
        occurrence: &Value,
    ) -> Result<bool, CoreError> {
        let schemes = selector.as_array().ok_or_else(match_type_error)?;
        let object = occurrence.as_object().ok_or_else(match_type_error)?;
        let scheme = object
            .get("scheme")
            .and_then(Value::as_str)
            .ok_or_else(match_type_error)?;
        let transport = object
            .get("transport")
            .and_then(Value::as_str)
            .ok_or_else(match_type_error)?;
        Ok(self.scheme_transport_allowed(scheme, transport)
            && schemes.iter().any(|candidate| candidate.as_str() == Some(scheme)))
    }

    fn projection(&self, projection_id: &str) -> Result<&Projection, CoreError> {
        self.projections.get(projection_id).ok_or_else(|| {
            CoreError::new(
                REASON_SCHEMA_INVALID,
                format!("unknown projection {projection_id}"),
            )
        })
    }

    fn matches_canonical(
        &self,
        selector: &CanonicalAuthoritySelector,
        effect: &CanonicalEffect,
        polarity: SelectorPolarity,
        source_id: &str,
        path_bindings: &[PathBindingInput],
    ) -> Result<bool, CoreError> {
        if selector.capability != effect.capability {
            return Ok(false);
        }
        let definition = self.definition(&effect.capability)?;
        let projection = self.projection(&definition.positive_projection_id)?;
        if projection.capability_id != effect.capability
            || projection.polarity != "positive"
            || projection.input_schema_id != definition.resource_schema_id
        {
            return Err(CoreError::new(
                REASON_SCHEMA_INVALID,
                format!("invalid positive projection for {}", effect.capability),
            ));
        }
        let Some(spec) = &projection.match_spec else {
            return Ok(false);
        };
        if spec.combine != "all" || spec.occurrence_schema_id != definition.occurrence_schema_id {
            return Err(CoreError::new(
                REASON_SCHEMA_INVALID,
                format!("invalid match composition for {}", effect.capability),
            ));
        }
        for clause in &spec.clauses {
            let selector_value = value_at_path(&selector.resource, &clause.selector_path)
                .ok_or_else(|| {
                    CoreError::new(
                        REASON_SCHEMA_INVALID,
                        format!("selector projection misses {}", clause.selector_path),
                    )
                })?;
            let occurrence_value = value_at_path(&effect.occurrence, &clause.occurrence_path)
                .ok_or_else(|| {
                    CoreError::new(
                        REASON_SCHEMA_INVALID,
                        format!("occurrence projection misses {}", clause.occurrence_path),
                    )
                })?;
            let algorithm = self.match_operations.get(&clause.operation).ok_or_else(|| {
                CoreError::new(
                    REASON_SCHEMA_INVALID,
                    format!("unknown match operation {}", clause.operation),
                )
            })?;
            if !self.evaluate_match(
                algorithm,
                selector_value,
                occurrence_value,
                polarity,
                source_id,
                path_bindings,
            )? {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn evaluate_match(
        &self,
        algorithm: &str,
        selector: &Value,
        occurrence: &Value,
        polarity: SelectorPolarity,
        source_id: &str,
        path_bindings: &[PathBindingInput],
    ) -> Result<bool, CoreError> {
        match algorithm {
            "json-equal" => Ok(selector == occurrence),
            "set-contains-all" => set_contains_all(selector, occurrence, polarity),
            "dns-exact-or-subtree" => {
                let selector = selector.as_str().ok_or_else(match_type_error)?;
                let occurrence = occurrence.as_str().ok_or_else(match_type_error)?;
                Ok(dns_selector_matches(selector, occurrence))
            }
            "port-exact-range-any" => port_matches(selector, occurrence),
            "scheme-transport-conjunction" => self.scheme_transport_matches(selector, occurrence),
            "peer-class-conjunction" => self.peer_class_matches(selector, occurrence),
            "network-host-peer-conjunction" => {
                self.network_host_matches(selector, occurrence, polarity)
            }
            "path-exact-or-tree" => path_matches(
                selector,
                occurrence,
                polarity,
                source_id,
                path_bindings,
            ),
            other => Err(CoreError::new(
                REASON_SCHEMA_INVALID,
                format!("unsupported match algorithm {other}"),
            )),
        }
    }

    fn peer_class_matches(&self, selector: &Value, occurrence: &Value) -> Result<bool, CoreError> {
        let allowed = selector.as_array().ok_or_else(match_type_error)?;
        let peer = occurrence
            .get("verifiedPeer")
            .unwrap_or(occurrence)
            .as_object()
            .ok_or_else(match_type_error)?;
        if peer.get("kind").and_then(Value::as_str) != Some("ip") {
            return Ok(allowed.iter().any(|value| value.as_str() == Some("non-ip")));
        }
        let address = peer
            .get("value")
            .and_then(Value::as_str)
            .ok_or_else(match_type_error)?;
        let classes = self.ip_classes(address)?;
        Ok(classes
            .iter()
            .all(|class| allowed.iter().any(|value| value.as_str() == Some(class))))
    }

    fn network_host_matches(
        &self,
        selector: &Value,
        occurrence: &Value,
        polarity: SelectorPolarity,
    ) -> Result<bool, CoreError> {
        let selector = selector.as_object().ok_or_else(match_type_error)?;
        let occurrence = occurrence.as_object().ok_or_else(match_type_error)?;
        let requested = occurrence
            .get("requestedHost")
            .and_then(Value::as_object)
            .ok_or_else(match_type_error)?;
        let candidate = occurrence
            .get("candidate")
            .and_then(Value::as_object)
            .ok_or_else(match_type_error)?;
        let verified = occurrence
            .get("verifiedPeer")
            .and_then(Value::as_object)
            .ok_or_else(match_type_error)?;
        if candidate.get("kind") != verified.get("kind")
            || candidate.get("value") != verified.get("value")
        {
            return Ok(false);
        }
        let selector_kind = selector
            .get("kind")
            .and_then(Value::as_str)
            .ok_or_else(match_type_error)?;
        let selector_value = selector
            .get("value")
            .and_then(Value::as_str)
            .ok_or_else(match_type_error)?;
        let requested_kind = requested
            .get("kind")
            .and_then(Value::as_str)
            .ok_or_else(match_type_error)?;
        let requested_value = requested
            .get("value")
            .and_then(Value::as_str)
            .ok_or_else(match_type_error)?;
        let peer_kind = verified
            .get("kind")
            .and_then(Value::as_str)
            .ok_or_else(match_type_error)?;
        let peer_value = verified
            .get("value")
            .and_then(Value::as_str)
            .ok_or_else(match_type_error)?;
        match selector_kind {
            "dns-exact" => Ok(
                requested_kind == "dns-exact"
                    && selector_value == requested_value
                    && matches!(peer_kind, "ip" | "dns"),
            ),
            "dns-subtree" => {
                let suffix = selector_value.strip_prefix("*.").ok_or_else(match_type_error)?;
                Ok(requested_kind == "dns-exact"
                    && requested_value.len() > suffix.len()
                    && requested_value.ends_with(suffix)
                    && requested_value.as_bytes()[requested_value.len() - suffix.len() - 1]
                        == b'.'
                    && matches!(peer_kind, "ip" | "dns"))
            }
            "ip-exact" => Ok(peer_kind == "ip"
                && selector_value == peer_value
                && (polarity == SelectorPolarity::Negative
                    || (requested_kind == "ip-exact" && selector_value == requested_value))),
            "cidr" => {
                if peer_kind != "ip" {
                    return Ok(false);
                }
                let network = IpNet::from_str(selector_value)
                    .map_err(|_| CoreError::new(REASON_SCHEMA_INVALID, "invalid selector CIDR"))?;
                let peer_ip = IpAddr::from_str(peer_value)
                    .map(effective_ip)
                    .map_err(|_| CoreError::new(REASON_SCHEMA_INVALID, "invalid peer IP"))?;
                if polarity == SelectorPolarity::Negative {
                    return Ok(network.contains(&peer_ip));
                }
                if requested_kind != "ip-exact" {
                    return Ok(false);
                }
                let requested_ip = IpAddr::from_str(requested_value)
                    .map(effective_ip)
                    .map_err(|_| CoreError::new(REASON_SCHEMA_INVALID, "invalid requested IP"))?;
                Ok(network.contains(&requested_ip) && network.contains(&peer_ip))
            }
            "unix-path" | "unix-abstract" | "vsock" => Ok(
                requested_kind == selector_kind
                    && selector_value == requested_value
                    && selector_value == peer_value,
            ),
            _ => Ok(false),
        }
    }

    fn ip_classes(&self, address: &str) -> Result<Vec<String>, CoreError> {
        let rules = self
            .payload
            .policy_rules_and_classifiers
            .ip_address_classes
            .as_ref()
            .ok_or_else(|| CoreError::new(REASON_SCHEMA_INVALID, "IP class table is absent"))?;
        let ip = IpAddr::from_str(address)
            .map(effective_ip)
            .map_err(|_| CoreError::new(REASON_SCHEMA_INVALID, "invalid peer IP"))?;
        if rules.metadata_exact.iter().any(|candidate| {
            IpAddr::from_str(candidate).map(effective_ip).ok() == Some(ip)
        }) {
            return Ok(vec!["metadata".to_string()]);
        }
        for class in &rules.classes {
            for cidr in &class.cidrs {
                let network = IpNet::from_str(cidr).map_err(|_| {
                    CoreError::new(REASON_SCHEMA_INVALID, format!("invalid classifier CIDR {cidr}"))
                })?;
                if network.contains(&ip) {
                    return Ok(vec![class.id.clone()]);
                }
            }
        }
        Ok(vec!["public".to_string()])
    }

    fn is_metadata_effect(&self, effect: &CanonicalEffect) -> Result<bool, CoreError> {
        if effect.capability != "network:fetch" && effect.capability != "network:connect" {
            return Ok(false);
        }
        let Some(peer) = effect.occurrence.get("verifiedPeer") else {
            return Ok(false);
        };
        let Some(object) = peer.as_object() else {
            return Ok(false);
        };
        if object.get("kind").and_then(Value::as_str) != Some("ip") {
            return Ok(false);
        }
        let Some(address) = object.get("value").and_then(Value::as_str) else {
            return Ok(false);
        };
        Ok(self.ip_classes(address)?.iter().any(|class| class == "metadata"))
    }

    fn normalize_schema_inner(
        &self,
        schema_id: &str,
        input: &Value,
        stack: &mut Vec<String>,
    ) -> Result<Value, CoreError> {
        if stack.iter().any(|active| active == schema_id) {
            return Err(CoreError::new(
                REASON_SCHEMA_INVALID,
                format!("recursive schema cycle at {schema_id}"),
            ));
        }
        let schema = self.schemas.get(schema_id).ok_or_else(|| {
            CoreError::new(REASON_SCHEMA_INVALID, format!("unknown schema {schema_id}"))
        })?;
        if schema.kind != "typed-object" && schema.kind != "tagged-union" {
            return Err(CoreError::new(
                REASON_SCHEMA_INVALID,
                format!("unsupported schema kind {}", schema.kind),
            ));
        }
        let object = input.as_object().ok_or_else(|| {
            CoreError::new(REASON_SCHEMA_INVALID, format!("{schema_id} requires an object"))
        })?;
        let known: BTreeSet<&str> = schema.fields.iter().map(|field| field.name.as_str()).collect();
        if !schema.additional_properties {
            if let Some(name) = object.keys().find(|name| !known.contains(name.as_str())) {
                return Err(CoreError::new(
                    REASON_SCHEMA_INVALID,
                    format!("{schema_id} contains unknown field {name}"),
                ));
            }
        }
        stack.push(schema_id.to_string());
        let mut normalized = Map::new();
        for field in &schema.fields {
            let Some(value) = object.get(&field.name) else {
                if field.required {
                    stack.pop();
                    return Err(CoreError::new(
                        REASON_SCHEMA_INVALID,
                        format!("{schema_id} is missing required field {}", field.name),
                    ));
                }
                continue;
            };
            let value = self.normalize_field(schema_id, field, value, stack)?;
            normalized.insert(field.name.clone(), value);
        }
        stack.pop();
        if let Some(tag) = &schema.tag {
            let value = normalized
                .get(&tag.field)
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    CoreError::new(
                        REASON_SCHEMA_INVALID,
                        format!("{schema_id} tag {} is not a string", tag.field),
                    )
                })?;
            if !tag.allowed_values.iter().any(|allowed| allowed == value) {
                return Err(CoreError::new(
                    REASON_SCHEMA_INVALID,
                    format!("{schema_id} tag {value} is not allowed"),
                ));
            }
        }
        let mut value = Value::Object(normalized);
        self.canonicalize_special_schema(schema_id, &mut value)?;
        for constraint in &schema.constraints {
            self.evaluate_schema_constraint(schema_id, constraint, &value)?;
        }
        Ok(value)
    }

    fn normalize_field(
        &self,
        schema_id: &str,
        field: &TypedField,
        input: &Value,
        stack: &mut Vec<String>,
    ) -> Result<Value, CoreError> {
        let mut value = match field.value_type.as_str() {
            "boolean" if input.is_boolean() => input.clone(),
            "integer" if input.as_i64().is_some() || input.as_u64().is_some() => input.clone(),
            "string" if input.is_string() => input.clone(),
            "string-or-null" if input.is_string() || input.is_null() => input.clone(),
            "object" if input.is_object() => {
                if let Some(reference) = &field.schema_ref {
                    self.normalize_schema_inner(reference, input, stack)?
                } else {
                    canonicalize_value(input)?
                }
            }
            "string-array" if input.is_array() => {
                let mut values = Vec::new();
                for item in input.as_array().expect("checked above") {
                    let text = item.as_str().ok_or_else(|| {
                        CoreError::new(
                            REASON_SCHEMA_INVALID,
                            format!("{schema_id}.{} requires strings", field.name),
                        )
                    })?;
                    values.push(Value::String(text.to_string()));
                }
                Value::Array(values)
            }
            "object-array" if input.is_array() => {
                let mut values = Vec::new();
                for item in input.as_array().expect("checked above") {
                    if !item.is_object() {
                        return Err(CoreError::new(
                            REASON_SCHEMA_INVALID,
                            format!("{schema_id}.{} requires objects", field.name),
                        ));
                    }
                    values.push(if let Some(reference) = &field.schema_ref {
                        self.normalize_schema_inner(reference, item, stack)?
                    } else {
                        canonicalize_value(item)?
                    });
                }
                Value::Array(values)
            }
            _ => {
                return Err(CoreError::new(
                    REASON_SCHEMA_INVALID,
                    format!(
                        "{schema_id}.{} has wrong type for {}",
                        field.name, field.value_type
                    ),
                ));
            }
        };
        if let Some(allowed) = &field.allowed_values {
            let text = value.as_str().ok_or_else(|| {
                CoreError::new(
                    REASON_SCHEMA_INVALID,
                    format!("{schema_id}.{} allowedValues requires a string", field.name),
                )
            })?;
            if !allowed.iter().any(|candidate| candidate == text) {
                return Err(CoreError::new(
                    REASON_SCHEMA_INVALID,
                    format!("{schema_id}.{} value {text} is not allowed", field.name),
                ));
            }
        }
        self.validate_format(schema_id, field, &value)?;
        match field.canonicalization.as_str() {
            "deduplicate-sort-canonical" => {
                value = canonical_set(value, schema_id, &field.name)?;
            }
            "lowercase-idna-a-label-no-trailing-dot" => {
                let text = value.as_str().expect("format requires string");
                value = Value::String(canonical_dns_name(text)?);
            }
            "I-JSON/RFC8785" => value = canonicalize_value(&value)?,
            "host-kind-specific-canonicalization"
            | "identity"
            | "preserve-tagged-path-payload"
            | "tagged-path-preserve-opaque-bytes" => {}
            other => {
                return Err(CoreError::new(
                    REASON_SCHEMA_INVALID,
                    format!("unsupported canonicalization {other}"),
                ));
            }
        }
        Ok(value)
    }

    fn validate_format(
        &self,
        schema_id: &str,
        field: &TypedField,
        value: &Value,
    ) -> Result<(), CoreError> {
        let invalid = |detail: &str| {
            CoreError::new(
                REASON_SCHEMA_INVALID,
                format!("{schema_id}.{} {detail}", field.name),
            )
        };
        match field.format.as_str() {
            "boolean"
            | "canonical-positive-row/2"
            | "network-route/2"
            | "reason-code-or-null/2"
            | "route-attestation-or-null/2"
            | "route-endpoint-or-null/2"
            | "typed-network-host/2"
            | "typed-object-set/2"
            | "typed-object/2"
            | "unicode-or-opaque-platform-path/2" => {}
            "i-json-safe-integer" => {
                let number = value
                    .as_i64()
                    .map(i128::from)
                    .or_else(|| value.as_u64().map(i128::from))
                    .ok_or_else(|| invalid("is not an integer"))?;
                if !(-9_007_199_254_740_991..=9_007_199_254_740_991).contains(&number) {
                    return Err(invalid("is outside the I-JSON safe range"));
                }
            }
            "u16" => {
                let number = value.as_u64().ok_or_else(|| invalid("is not a u16"))?;
                if number > u16::MAX.into() {
                    return Err(invalid("is outside the u16 range"));
                }
            }
            "canonical-u64-decimal" => {
                let text = value.as_str().ok_or_else(|| invalid("is not a string"))?;
                let parsed = text.parse::<u64>().map_err(|_| invalid("is not a u64"))?;
                if parsed.to_string() != text {
                    return Err(invalid("is not canonical unsigned decimal"));
                }
            }
            "dns-a-label-absolute-name/2" => {
                canonical_dns_name(value.as_str().ok_or_else(|| invalid("is not a string"))?)?;
            }
            "canonical-row-digest-set/2"
            | "canonical-string-set/2"
            | "risk-input:authority.effects/2"
            | "risk-input:resource.peerClasses/2" => {
                if !value.is_array() {
                    return Err(invalid("is not a string set"));
                }
            }
            format if format.starts_with("risk-input:") => {}
            "canonical-string/2"
            | "cron-expression/2"
            | "integrity-bound-target-id/2"
            | "logical-path-root/2"
            | "module-entry/2"
            | "network-host-kind/2"
            | "network-host-value/2"
            | "network-route-kind/2"
            | "opaque-id"
            | "path-encoding/2"
            | "path-payload/2"
            | "platform-normalized-name/2"
            | "principal-key/2" => {
                if value.as_str().is_none_or(str::is_empty) {
                    return Err(invalid("must be a nonempty string"));
                }
            }
            other => {
                return Err(CoreError::new(
                    REASON_SCHEMA_INVALID,
                    format!("unsupported field format {other}"),
                ));
            }
        }
        Ok(())
    }

    fn canonicalize_special_schema(
        &self,
        schema_id: &str,
        value: &mut Value,
    ) -> Result<(), CoreError> {
        let object = value.as_object_mut().expect("schema values are objects");
        match schema_id {
            "value.network-host/2" => {
                let kind = object.get("kind").and_then(Value::as_str).ok_or_else(|| {
                    CoreError::new(REASON_SCHEMA_INVALID, "network host has no kind")
                })?;
                let raw = object.get("value").and_then(Value::as_str).ok_or_else(|| {
                    CoreError::new(REASON_SCHEMA_INVALID, "network host has no value")
                })?;
                let canonical = match kind {
                    "dns-exact" => {
                        let name = canonical_dns_name(raw)?;
                        if name.starts_with("*.") {
                            return Err(CoreError::new(
                                REASON_SCHEMA_INVALID,
                                "dns-exact cannot contain a wildcard",
                            ));
                        }
                        name
                    }
                    "dns-subtree" => {
                        let name = canonical_dns_name(raw)?;
                        if !name.starts_with("*.") {
                            return Err(CoreError::new(
                                REASON_SCHEMA_INVALID,
                                "dns-subtree requires an explicit leading wildcard label",
                            ));
                        }
                        name
                    }
                    "ip-exact" => canonical_ip(raw)?,
                    "cidr" => canonical_cidr(raw)?,
                    "unix-path" | "unix-abstract" => {
                        return Err(CoreError::new(
                            REASON_SCHEMA_INVALID,
                            "Unix network endpoints are structurally closed pending object-bound identity",
                        ));
                    }
                    "vsock" => canonical_vsock(raw)?,
                    _ => {
                        return Err(CoreError::new(
                            REASON_SCHEMA_INVALID,
                            format!("unsupported network host kind {kind}"),
                        ));
                    }
                };
                object.insert("value".to_string(), Value::String(canonical));
            }
            "value.network-candidate/2" | "value.verified-peer/2" => {
                let kind = object.get("kind").and_then(Value::as_str).ok_or_else(|| {
                    CoreError::new(REASON_SCHEMA_INVALID, "network peer has no kind")
                })?;
                let raw = object.get("value").and_then(Value::as_str).ok_or_else(|| {
                    CoreError::new(REASON_SCHEMA_INVALID, "network peer has no value")
                })?;
                let canonical = match kind {
                    "ip" => canonical_ip(raw)?,
                    "dns" => {
                        let name = canonical_dns_name(raw)?;
                        if name.starts_with("*.") {
                            return Err(CoreError::new(
                                REASON_SCHEMA_INVALID,
                                "verified DNS peer must be exact",
                            ));
                        }
                        name
                    }
                    "unix" => {
                        return Err(CoreError::new(
                            REASON_SCHEMA_INVALID,
                            "Unix network peers are structurally closed pending object-bound identity",
                        ));
                    }
                    "vsock" => canonical_vsock(raw)?,
                    _ => {
                        return Err(CoreError::new(
                            REASON_SCHEMA_INVALID,
                            "unknown or empty network peer kind",
                        ));
                    }
                };
                object.insert("value".to_string(), Value::String(canonical));
            }
            "value.network-route/2" => {
                let kind = object.get("kind").and_then(Value::as_str).ok_or_else(|| {
                    CoreError::new(REASON_SCHEMA_INVALID, "network route has no kind")
                })?;
                let endpoint = object.get("endpoint").ok_or_else(match_type_error)?;
                let attestation = object.get("attestation").ok_or_else(match_type_error)?;
                let valid = match kind {
                    "direct" => endpoint.is_null() && attestation.is_null(),
                    // The initial profile has no authenticated forward-proxy
                    // assurance profile, so every proxy route is structurally
                    // refused before authority matching.
                    "forward-proxy" => false,
                    _ => false,
                };
                if !valid {
                    return Err(CoreError::new(
                        REASON_SCHEMA_INVALID,
                        "network route violates the initial-profile tagged shape",
                    ));
                }
            }
            "value.platform-path/2" => {
                let encoding = object.get("encoding").and_then(Value::as_str).ok_or_else(|| {
                    CoreError::new(REASON_SCHEMA_INVALID, "platform path has no encoding")
                })?;
                let _payload = object.get("value").and_then(Value::as_str).ok_or_else(|| {
                    CoreError::new(REASON_SCHEMA_INVALID, "platform path has no value")
                })?;
                if !matches!(encoding, "opaque-base64url" | "unicode") {
                    return Err(CoreError::new(
                        REASON_SCHEMA_INVALID,
                        "unknown platform path encoding",
                    ));
                }
            }
            "occurrence.dns-query/2"
                if object
                    .get("absoluteName")
                    .and_then(Value::as_str)
                    .is_some_and(|name| name.starts_with("*.")) =>
            {
                return Err(CoreError::new(
                    REASON_SCHEMA_INVALID,
                    "a DNS occurrence must name one exact absolute name",
                ));
            }
            _ => {}
        }
        Ok(())
    }

    fn evaluate_schema_constraint(
        &self,
        schema_id: &str,
        constraint: &SchemaConstraint,
        value: &Value,
    ) -> Result<(), CoreError> {
        let fail = || {
            CoreError::new(
                REASON_SCHEMA_INVALID,
                format!("{schema_id} failed {}", constraint.operation),
            )
        };
        let operand = |index: usize| -> Option<&Value> {
            constraint
                .operands
                .get(index)
                .and_then(|path| value_at_path(value, path))
        };
        let valid = match constraint.operation.as_str() {
            "integer-range" => {
                let number = operand(0).and_then(value_i128);
                let minimum = constraint.operands.get(1).and_then(|text| text.parse::<i128>().ok());
                let maximum = constraint.operands.get(2).and_then(|text| text.parse::<i128>().ok());
                matches!((number, minimum, maximum), (Some(n), Some(min), Some(max)) if min <= n && n <= max)
            }
            "scheme-transport-consistent" => {
                let scheme = operand(0).and_then(Value::as_str);
                let transport = operand(1).and_then(Value::as_str);
                matches!((scheme, transport), (Some(scheme), Some(transport)) if self.scheme_transport_allowed(scheme, transport))
            }
            "candidate-verified-peer-consistent" => {
                let candidate = operand(0).and_then(Value::as_object);
                let verified = operand(1).and_then(Value::as_object);
                matches!((candidate, verified), (Some(left), Some(right)) if left.get("kind") == right.get("kind") && left.get("value") == right.get("value"))
            }
            "follow-mode-selects-final-state" => {
                let follow_mode = operand(0).and_then(Value::as_str);
                let state = operand(1)
                    .and_then(Value::as_object)
                    .and_then(|state| state.get("kind"))
                    .and_then(Value::as_str);
                match follow_mode {
                    Some("follow-final") => {
                        matches!(state, Some("existing" | "missing" | "proposed"))
                    }
                    Some("no-follow-final") => matches!(
                        state,
                        Some("existing" | "link-entry" | "missing" | "proposed")
                    ),
                    _ => false,
                }
            }
            "tag-selects-network-route-shape" => {
                let kind = operand(0).and_then(Value::as_str);
                let endpoint = operand(1);
                let attestation = operand(2);
                match kind {
                    Some("direct") => {
                        endpoint.is_some_and(Value::is_null)
                            && attestation.is_some_and(Value::is_null)
                    }
                    Some("forward-proxy") => {
                        endpoint.and_then(Value::as_str).is_some_and(|value| !value.is_empty())
                            && attestation
                                .and_then(Value::as_str)
                                .is_some_and(|value| !value.is_empty())
                    }
                    _ => false,
                }
            }
            "initial-profile-allows-network-route" => {
                operand(0).and_then(Value::as_str) == Some("direct")
            }
            "tag-selects-network-peer-shape" => {
                let kind = operand(0).and_then(Value::as_str);
                let value = operand(1).and_then(Value::as_str);
                match (kind, value) {
                    (Some("dns"), Some(value)) => canonical_dns_name(value)
                        .is_ok_and(|canonical| canonical == value && !value.starts_with("*.")),
                    (Some("ip"), Some(value)) => {
                        canonical_ip(value).is_ok_and(|canonical| canonical == value)
                    }
                    (Some("unix"), Some(value)) => !value.is_empty(),
                    (Some("vsock"), Some(value)) => {
                        canonical_vsock(value).is_ok_and(|canonical| canonical == value)
                    }
                    _ => false,
                }
            }
            "tag-selects-final-object-state" => {
                let kind = operand(0).and_then(Value::as_str);
                let identity = operand(1);
                match kind {
                    Some("existing" | "link-entry") => identity.is_some_and(|row| row.is_object()),
                    Some("missing" | "proposed") => identity.is_none() || identity == Some(&Value::Null),
                    _ => false,
                }
            }
            "tag-selects-port-shape" => {
                let kind = operand(0).and_then(Value::as_str);
                let exact = operand(1).and_then(value_i128);
                let minimum = operand(2).and_then(value_i128);
                let maximum = operand(3).and_then(value_i128);
                match kind {
                    Some("any") => exact.is_none() && minimum.is_none() && maximum.is_none(),
                    Some("exact") => exact.is_some() && minimum.is_none() && maximum.is_none(),
                    Some("range") => {
                        exact.is_none()
                            && matches!((minimum, maximum), (Some(min), Some(max)) if min <= max)
                    }
                    _ => false,
                }
            }
            "tag-selects-resource-shape" => {
                matches!(operand(0).and_then(Value::as_str), Some("path-exact" | "path-tree"))
                    && operand(1).and_then(Value::as_str).is_some()
                    && operand(2).is_some_and(Value::is_object)
            }
            other => {
                return Err(CoreError::new(
                    REASON_SCHEMA_INVALID,
                    format!("unsupported schema constraint {other}"),
                ));
            }
        };
        if valid {
            Ok(())
        } else {
            Err(fail())
        }
    }
}

impl StagedOperation {
    pub fn new(
        core: &Rev2Core,
        operation_id: impl Into<String>,
        captured_context: CapturedOperationContext,
        policy: &DecisionPolicyInput,
    ) -> Result<Self, CoreError> {
        let operation_id = operation_id.into();
        if operation_id.trim().is_empty() || operation_id.len() > 1024 {
            return Err(CoreError::new(
                REASON_OPERATION_CONTEXT,
                "operation id is empty or exceeds its bound",
            ));
        }
        core.validate_identity(&captured_context.identity)?;
        core.validate_identity(&policy.identity)?;
        if policy.identity != captured_context.identity {
            return Err(CoreError::new(
                REASON_OPERATION_CONTEXT,
                "captured operation identity differs from the armed policy",
            ));
        }
        let normalized_policy = core.normalize_policy(policy)?;
        let mut sealed_repeatable_effects = BTreeSet::new();
        if let Some(expected_edge_id) = &captured_context.sealed_repeatable_edge_id {
            if !core.edges.get(expected_edge_id).is_some_and(|edge| {
                edge.effects
                    .iter()
                    .any(|template| template.cardinality == "zero-or-more")
            }) {
                return Err(CoreError::new(
                    REASON_OPERATION_CONTEXT,
                    "sealed launch contract names no repeatable generated edge",
                ));
            }
        } else if !captured_context.sealed_child_exports.is_empty() {
            return Err(CoreError::new(
                REASON_OPERATION_CONTEXT,
                "sealed repeatable effects have no captured launch edge",
            ));
        }
        for fact in &captured_context.sealed_child_exports {
            let effect = core.normalize_effect(&fact.effect)?;
            let repeatable = core
                .edges
                .get(&effect.edge_id)
                .and_then(|edge| {
                    edge.effects
                        .iter()
                        .find(|template| template.effect_slot_id == effect.effect_slot_id)
                })
                .is_some_and(|template| template.cardinality == "zero-or-more");
            let canonical = canonical_json(&serde_json::to_value(&effect).map_err(schema_error)?)?;
            if !repeatable
                || captured_context.sealed_repeatable_edge_id.as_deref()
                    != Some(effect.edge_id.as_str())
                || !sealed_repeatable_effects.insert(canonical)
            {
                return Err(CoreError::new(
                    REASON_OPERATION_CONTEXT,
                    "sealed launch facts are not unique repeatable generated effects",
                ));
            }
        }
        let initial_positive_inventory = positive_inventory(&normalized_policy)?;
        let initial_positive_inventory_digest = inventory_digest(
            "oden:capsec:initial-positive-inventory:2",
            &initial_positive_inventory,
        )?;
        let required_negative_inventory = negative_inventory(&normalized_policy)?;
        if required_negative_inventory.len() > MAX_OPERATION_NEGATIVE_INVENTORY_ENTRIES {
            return Err(CoreError::new(
                REASON_OPERATION_CONTEXT,
                "operation negative inventory exceeds its lifetime bound",
            ));
        }
        Ok(Self {
            operation_id,
            identity: captured_context.identity.clone(),
            captured_context,
            policy_snapshot_generation: policy.generations.policy_snapshot.clone(),
            run_nonce: policy.run_nonce.clone(),
            channel_epoch: policy.channel_epoch.clone(),
            mode: policy.mode,
            provenance: policy.provenance.clone(),
            initial_positive_inventory,
            initial_positive_inventory_digest,
            required_negative_inventory,
            captured_positive_sources: BTreeMap::new(),
            captured_positive_source_bases: BTreeMap::new(),
            sealed_repeatable_effects,
            sealed_launch_consumed: false,
            last_generations: policy.generations.clone(),
            completed_stages: Vec::new(),
            pending_commit: None,
            terminal_denial: None,
        })
    }

    pub fn completed_stages(&self) -> &[String] {
        &self.completed_stages
    }

    pub fn cancel<R: ProvisionalResources>(
        &mut self,
        resources: &mut R,
    ) -> OperationReleaseEvidence {
        let released = resources.release_all();
        if self.terminal_denial.is_none() {
            self.pending_commit = None;
            self.terminal_denial = Some(StructuredDenial {
                operation_id: self.operation_id.clone(),
                stage_id: "operation-cancel".to_string(),
                reason_code: REASON_OPERATION_CONTEXT.to_string(),
                completed_discovery_stages: self.completed_stages.clone(),
                released_provisional_resources: released.clone(),
                decision: None,
            });
        }
        OperationReleaseEvidence {
            operation_id: self.operation_id.clone(),
            terminal_evidence_id: self.provenance.terminal_evidence_id.clone(),
            completed_stages: self.completed_stages.clone(),
            released_provisional_resources: released,
        }
    }

    pub fn cleanup_non_authorizing<R: ProvisionalResources>(
        &mut self,
        resources: &mut R,
    ) -> OperationReleaseEvidence {
        OperationReleaseEvidence {
            operation_id: self.operation_id.clone(),
            terminal_evidence_id: self.provenance.terminal_evidence_id.clone(),
            completed_stages: self.completed_stages.clone(),
            released_provisional_resources: resources.release_all(),
        }
    }

    pub fn authorize_next<R: ProvisionalResources>(
        &mut self,
        core: &Rev2Core,
        request: &StageRequest,
        policy: &DecisionPolicyInput,
        resources: &mut R,
        interaction: Interaction,
    ) -> Result<StageAuthorization, CoreError> {
        match self.authorize_next_inner(core, request, policy, resources, interaction) {
            Ok(authorization) => Ok(authorization),
            Err(error) => Ok(self.terminal_core_error_denial(request, resources, error)),
        }
    }

    pub fn authorize_at_barrier<R: ProvisionalResources>(
        &mut self,
        core: &Rev2Core,
        barrier: OperationBarrier,
        request: &StageRequest,
        policy: &DecisionPolicyInput,
        resources: &mut R,
        interaction: Interaction,
    ) -> Result<StageAuthorization, CoreError> {
        if !barrier_contract_matches(core, request, barrier) {
            return self.terminal_context_denial(request, resources);
        }
        self.authorize_next(core, request, policy, resources, interaction)
    }

    fn authorize_next_inner<R: ProvisionalResources>(
        &mut self,
        core: &Rev2Core,
        request: &StageRequest,
        policy: &DecisionPolicyInput,
        resources: &mut R,
        interaction: Interaction,
    ) -> Result<StageAuthorization, CoreError> {
        if self.terminal_denial.is_some() {
            return Ok(StageAuthorization::AlreadyDenied {
                terminal_evidence_id: self.provenance.terminal_evidence_id.clone(),
            });
        }
        if self.completed_stages.len() >= MAX_OPERATION_COMMITTED_STAGES {
            return self.terminal_context_denial(request, resources);
        }
        if request.identity != self.identity
            || !barrier_contract_matches(
                core,
                request,
                OperationBarrier::AuthorizationBeforeCommit,
            )
            || normalize_principal_set(&request.principals) != self.captured_context.principals
            || policy.identity != self.identity
            || policy.generations.policy_snapshot != self.policy_snapshot_generation
            || policy.run_nonce != self.run_nonce
            || policy.channel_epoch != self.channel_epoch
            || policy.mode != self.mode
            || policy.provenance != self.provenance
            || !self.sealed_child_exports_match(core, request)?
            || !generations_are_monotonic(&self.last_generations, &policy.generations)?
            || self.pending_commit.is_some()
            || self.completed_stages.contains(&request.stage_id)
        {
            return self.terminal_context_denial(request, resources);
        }
        let owner_context_matches = request
            .effects
            .iter()
            .all(|effect| {
                effect.effect_owner == self.captured_context.effect_owner_id
                    && effect
                        .occurrence
                        .get("ownerGeneration")
                        .and_then(Value::as_str)
                        .is_none_or(|generation| {
                            generation == self.captured_context.effect_owner_generation
                        })
            });
        if !owner_context_matches {
            return self.terminal_context_denial(request, resources);
        }

        if interaction == Interaction::MayPrompt {
            let denial = StructuredDenial {
                operation_id: self.operation_id.clone(),
                stage_id: request.stage_id.clone(),
                reason_code: REASON_INTERACTION_RELEASE.to_string(),
                completed_discovery_stages: self.completed_stages.clone(),
                released_provisional_resources: resources.release_all(),
                decision: None,
            };
            self.terminal_denial = Some(denial.clone());
            return Ok(StageAuthorization::RestartRequired { denial });
        }

        let normalized_policy = core.normalize_policy(policy)?;
        let current_inventory = positive_inventory(&normalized_policy)?;
        if current_inventory
            .difference(&self.initial_positive_inventory)
            .next()
            .is_some()
        {
            return self.terminal_context_denial(request, resources);
        }
        let current_negative_inventory = negative_inventory(&normalized_policy)?;
        if self
            .required_negative_inventory
            .difference(&current_negative_inventory)
            .next()
            .is_some()
        {
            return self.terminal_context_denial(request, resources);
        }
        let added_negative_entries = current_negative_inventory
            .difference(&self.required_negative_inventory)
            .count();
        if added_negative_entries > 0
            && !negative_generation_strictly_advanced(
                &self.last_generations,
                &policy.generations,
            )?
        {
            return self.terminal_context_denial(request, resources);
        }
        if set_union_exceeds_bound(
            &self.required_negative_inventory,
            &current_negative_inventory,
            MAX_OPERATION_NEGATIVE_INVENTORY_ENTRIES,
        ) {
            return self.terminal_context_denial(request, resources);
        }
        self.required_negative_inventory
            .extend(current_negative_inventory);
        let positive_inventory_digest = inventory_digest(
            "oden:capsec:current-positive-inventory:2",
            &current_inventory,
        )?;
        let negative_inventory_digest = inventory_digest(
            "oden:capsec:required-negative-inventory:2",
            &self.required_negative_inventory,
        )?;
        let decision = core.decide_stage(request, policy)?;
        match decision.outcome {
            Outcome::Allow => {
                let mut source_updates = BTreeMap::new();
                let mut source_base_updates = BTreeMap::new();
                for effect in &decision.effects {
                    if !decision.committed_effects.contains(&effect.effect) {
                        continue;
                    }
                    for dimension in &effect.dimensions {
                        let Some(source) = &dimension.positive_source else {
                            return self.terminal_context_denial(request, resources);
                        };
                        let base_key = positive_source_base_key(
                            &dimension.principal,
                            &effect.effect,
                        )?;
                        let base_value = positive_source_base_value(source)?;
                        if self
                            .captured_positive_source_bases
                            .get(&base_key)
                            .is_some_and(|captured| captured != &base_value)
                            || source_base_updates
                                .get(&base_key)
                                .is_some_and(|captured| captured != &base_value)
                        {
                            return self.terminal_context_denial(request, resources);
                        }
                        if !self.captured_positive_source_bases.contains_key(&base_key) {
                            source_base_updates.entry(base_key).or_insert(base_value);
                        }
                        let binding_key = positive_source_binding_key(
                            &request.stage_id,
                            &dimension.principal,
                            &effect.effect,
                            &source.kind,
                        )?;
                        if self
                            .captured_positive_sources
                            .get(&binding_key)
                            .is_some_and(|captured| captured != source)
                            || source_updates
                                .get(&binding_key)
                                .is_some_and(|captured| captured != source)
                        {
                            return self.terminal_context_denial(request, resources);
                        }
                        if !self.captured_positive_sources.contains_key(&binding_key) {
                            source_updates
                                .entry(binding_key)
                                .or_insert_with(|| source.clone());
                        }
                    }
                }
                if prospective_len_exceeds_bound(
                    self.captured_positive_sources.len(),
                    source_updates.len(),
                    MAX_OPERATION_CAPTURED_SOURCE_ENTRIES,
                ) || prospective_len_exceeds_bound(
                    self.captured_positive_source_bases.len(),
                    source_base_updates.len(),
                    MAX_OPERATION_CAPTURED_SOURCE_ENTRIES,
                )
                {
                    return self.terminal_context_denial(request, resources);
                }
                self.captured_positive_sources.extend(source_updates);
                self.captured_positive_source_bases.extend(source_base_updates);
                let provisional_resource_ids =
                    canonical_provisional_resource_ids(resources)?;
                let consumes_sealed_launch = self
                    .captured_context
                    .sealed_repeatable_edge_id
                    .as_ref()
                    .is_some_and(|edge_id| {
                        request.effects.iter().all(|effect| &effect.edge_id == edge_id)
                    });
                let sealed_launch_consumed_after_commit =
                    self.sealed_launch_consumed || consumes_sealed_launch;
                let mut prospective_stages = self.completed_stages.clone();
                prospective_stages.push(request.stage_id.clone());
                let actor = serde_json::json!({
                    "armedSnapshotDigest": self.provenance.armed_snapshot_digest,
                    "capturedPositiveSources": self.captured_positive_sources,
                    "capturedPositiveSourceBases": self.captured_positive_source_bases,
                    "channelEpoch": self.channel_epoch,
                    "completedStages": prospective_stages,
                    "decision": decision,
                    "effectOwner": {
                        "generation": self.captured_context.effect_owner_generation,
                        "id": self.captured_context.effect_owner_id,
                        "principal": self.captured_context.effect_owner_principal,
                    },
                    "generations": policy.generations,
                    "identity": self.identity,
                    "initialPositiveInventoryDigest": self.initial_positive_inventory_digest,
                    "mode": self.mode,
                    "operationId": self.operation_id,
                    "policyDigest": self.provenance.policy_digest,
                    "operationActorId": self.captured_context.actor_id,
                    "principals": self.captured_context.principals,
                    "provisionalResourceIds": provisional_resource_ids,
                    "quotaOwner": self.provenance.quota_owner,
                    "requiredNegativeInventoryDigest": negative_inventory_digest,
                    "runNonce": self.run_nonce,
                    "sealedLaunch": {
                        "consumedAfterCommit": sealed_launch_consumed_after_commit,
                        "consumedBefore": self.sealed_launch_consumed,
                        "edgeId": self.captured_context.sealed_repeatable_edge_id,
                        "repeatableEffects": self.sealed_repeatable_effects,
                    },
                    "stageId": request.stage_id,
                    "terminalEvidenceId": self.provenance.terminal_evidence_id,
                    "currentPositiveInventoryDigest": positive_inventory_digest,
                });
                let actor_digest = domain_digest("oden:capsec:operation-actor:2", &actor)?;
                let permit_token = domain_digest(
                    "oden:capsec:commit-permit:2",
                    &serde_json::json!({
                        "actorDigest": actor_digest,
                        "decision": decision,
                        "operationId": self.operation_id,
                        "stageId": request.stage_id,
                        "terminalEvidenceId": self.provenance.terminal_evidence_id,
                    }),
                )?;
                self.pending_commit = Some(PendingCommit {
                    permit_token: permit_token.clone(),
                    actor_digest: actor_digest.clone(),
                    decision: decision.clone(),
                    generations: policy.generations.clone(),
                    positive_inventory_digest,
                    negative_inventory_digest,
                    provisional_resource_ids: provisional_resource_ids.clone(),
                    sealed_launch_consumed_after_commit,
                });
                Ok(StageAuthorization::Permit {
                    permit: CommitPermit {
                        operation_id: self.operation_id.clone(),
                        stage_id: request.stage_id.clone(),
                        actor_digest,
                        completed_discovery_stages: prospective_stages,
                        provisional_resource_ids,
                        decision,
                        permit_token,
                    },
                })
            }
            Outcome::Masked => {
                // A nonterminal masked observation still consumes the exact
                // policy generation watermark. Otherwise successive masked
                // stages could grow negative state repeatedly at one
                // generation or roll an observed generation backward.
                self.last_generations = policy.generations.clone();
                Ok(StageAuthorization::Masked {
                    decision,
                    released_provisional_resources: resources.release_all(),
                })
            }
            Outcome::Deny => {
                let reason_code = decision
                    .effects
                    .iter()
                    .flat_map(|effect| &effect.dimensions)
                    .find(|dimension| dimension.outcome == Outcome::Deny)
                    .map(|dimension| dimension.reason_code.clone())
                    .unwrap_or_else(|| REASON_MISSING_AUTHORITY.to_string());
                let denial = StructuredDenial {
                    operation_id: self.operation_id.clone(),
                    stage_id: request.stage_id.clone(),
                    reason_code,
                    completed_discovery_stages: self.completed_stages.clone(),
                    released_provisional_resources: resources.release_all(),
                    decision: Some(decision),
                };
                self.terminal_denial = Some(denial.clone());
                Ok(StageAuthorization::Denied { denial })
            }
        }
    }

    /// Consumes a permit immediately before the host's irreversible commit.
    /// The current policy is re-normalized and the complete decision is
    /// repeated; any generation change, revoke, source change, or replay
    /// terminally denies the operation.
    pub fn commit<R: ProvisionalResources>(
        &mut self,
        core: &Rev2Core,
        permit: CommitPermit,
        request: &StageRequest,
        policy: &DecisionPolicyInput,
        resources: &mut R,
    ) -> Result<CommitResult, CoreError> {
        match self.commit_inner(core, permit, request, policy, resources) {
            Ok(result) => Ok(result),
            Err(error) => Ok(match self.terminal_core_error_denial(request, resources, error) {
                StageAuthorization::Denied { denial } => CommitResult::Denied { denial },
                StageAuthorization::AlreadyDenied {
                    terminal_evidence_id,
                } => CommitResult::AlreadyDenied {
                    terminal_evidence_id,
                },
                _ => unreachable!("core error terminalization cannot authorize or restart"),
            }),
        }
    }

    fn commit_inner<R: ProvisionalResources>(
        &mut self,
        core: &Rev2Core,
        permit: CommitPermit,
        request: &StageRequest,
        policy: &DecisionPolicyInput,
        resources: &mut R,
    ) -> Result<CommitResult, CoreError> {
        if self.terminal_denial.is_some() {
            return Ok(CommitResult::AlreadyDenied {
                terminal_evidence_id: self.provenance.terminal_evidence_id.clone(),
            });
        }
        let Some(pending) = self.pending_commit.clone() else {
            return self.commit_context_denial(request, resources);
        };
        let provisional_resource_ids = canonical_provisional_resource_ids(resources)?;
        let consumes_sealed_launch = self
            .captured_context
            .sealed_repeatable_edge_id
            .as_ref()
            .is_some_and(|edge_id| {
                request.effects.iter().all(|effect| &effect.edge_id == edge_id)
            });
        let sealed_launch_consumed_after_commit =
            self.sealed_launch_consumed || consumes_sealed_launch;
        let expected_stages = self
            .completed_stages
            .iter()
            .cloned()
            .chain(std::iter::once(request.stage_id.clone()))
            .collect::<Vec<_>>();
        if permit.operation_id != self.operation_id
            || permit.stage_id != request.stage_id
            || permit.permit_token != pending.permit_token
            || permit.actor_digest != pending.actor_digest
            || permit.decision != pending.decision
            || permit.completed_discovery_stages != expected_stages
            || permit.provisional_resource_ids != pending.provisional_resource_ids
            || provisional_resource_ids != pending.provisional_resource_ids
            || sealed_launch_consumed_after_commit
                != pending.sealed_launch_consumed_after_commit
            || request.identity != self.identity
            || normalize_principal_set(&request.principals) != self.captured_context.principals
            || request.effects.iter().any(|effect| {
                effect.effect_owner != self.captured_context.effect_owner_id
                    || effect
                        .occurrence
                        .get("ownerGeneration")
                        .and_then(Value::as_str)
                        .is_some_and(|generation| {
                            generation != self.captured_context.effect_owner_generation
                        })
            })
            || policy.identity != self.identity
            || policy.run_nonce != self.run_nonce
            || policy.channel_epoch != self.channel_epoch
            || policy.mode != self.mode
            || policy.provenance != self.provenance
            || !self.sealed_child_exports_match(core, request)?
        {
            return self.commit_context_denial(request, resources);
        }
        let normalized_policy = core.normalize_policy(policy)?;
        let current_inventory = positive_inventory(&normalized_policy)?;
        let current_negative_inventory = negative_inventory(&normalized_policy)?;
        let positive_inventory_digest = inventory_digest(
            "oden:capsec:current-positive-inventory:2",
            &current_inventory,
        )?;
        let negative_inventory_digest = inventory_digest(
            "oden:capsec:required-negative-inventory:2",
            &current_negative_inventory,
        )?;
        let decision = core.decide_stage(request, policy)?;
        let snapshots_match = policy.generations == pending.generations
            && policy.generations.policy_snapshot == self.policy_snapshot_generation
            && positive_inventory_digest == pending.positive_inventory_digest
            && negative_inventory_digest == pending.negative_inventory_digest;
        if !snapshots_match
            || decision.outcome != Outcome::Allow
            || decision != pending.decision
        {
            let reason_code = decision
                .effects
                .iter()
                .flat_map(|effect| &effect.dimensions)
                .find(|dimension| dimension.outcome == Outcome::Deny)
                .map(|dimension| dimension.reason_code.clone())
                .unwrap_or_else(|| REASON_OPERATION_CONTEXT.to_string());
            let denial = StructuredDenial {
                operation_id: self.operation_id.clone(),
                stage_id: request.stage_id.clone(),
                reason_code,
                completed_discovery_stages: self.completed_stages.clone(),
                released_provisional_resources: resources.release_all(),
                decision: Some(decision),
            };
            self.pending_commit = None;
            self.terminal_denial = Some(denial.clone());
            return Ok(CommitResult::Denied { denial });
        }
        let pending = self.pending_commit.take().expect("pending permit checked above");
        self.sealed_launch_consumed = pending.sealed_launch_consumed_after_commit;
        self.completed_stages.push(request.stage_id.clone());
        self.last_generations = policy.generations.clone();
        Ok(CommitResult::Committed {
            stage_id: request.stage_id.clone(),
            actor_digest: pending.actor_digest,
        })
    }

    fn commit_context_denial<R: ProvisionalResources>(
        &mut self,
        request: &StageRequest,
        resources: &mut R,
    ) -> Result<CommitResult, CoreError> {
        let authorization = self.terminal_context_denial(request, resources)?;
        let StageAuthorization::Denied { denial } = authorization else {
            unreachable!("fresh context denial always emits its evidence once")
        };
        self.pending_commit = None;
        Ok(CommitResult::Denied { denial })
    }

    fn sealed_child_exports_match(
        &self,
        core: &Rev2Core,
        request: &StageRequest,
    ) -> Result<bool, CoreError> {
        let mut has_contract = false;
        let mut actual = BTreeSet::new();
        for input in &request.effects {
            let Some(edge) = core.edges.get(&input.edge_id) else {
                return Ok(false);
            };
            has_contract |= edge
                .effects
                .iter()
                .any(|template| template.cardinality == "zero-or-more");
            let repeatable = edge
                .effects
                .iter()
                .find(|template| template.effect_slot_id == input.effect_slot_id)
                .is_some_and(|template| template.cardinality == "zero-or-more");
            if !repeatable {
                continue;
            }
            let effect = core.normalize_effect(input)?;
            let canonical = canonical_json(&serde_json::to_value(effect).map_err(schema_error)?)?;
            if !actual.insert(canonical) {
                return Ok(false);
            }
        }
        match &self.captured_context.sealed_repeatable_edge_id {
            Some(expected_edge_id) if has_contract => Ok(
                !self.sealed_launch_consumed
                    && request
                        .effects
                        .iter()
                        .all(|effect| &effect.edge_id == expected_edge_id)
                    && actual == self.sealed_repeatable_effects,
            ),
            Some(_) => Ok(self.sealed_launch_consumed),
            None => Ok(!has_contract && self.sealed_repeatable_effects.is_empty()),
        }
    }

    fn terminal_core_error_denial<R: ProvisionalResources>(
        &mut self,
        request: &StageRequest,
        resources: &mut R,
        error: CoreError,
    ) -> StageAuthorization {
        if self.terminal_denial.is_some() {
            return StageAuthorization::AlreadyDenied {
                terminal_evidence_id: self.provenance.terminal_evidence_id.clone(),
            };
        }
        let denial = StructuredDenial {
            operation_id: self.operation_id.clone(),
            stage_id: request.stage_id.clone(),
            reason_code: error.reason_code,
            completed_discovery_stages: self.completed_stages.clone(),
            released_provisional_resources: resources.release_all(),
            decision: None,
        };
        self.pending_commit = None;
        self.terminal_denial = Some(denial.clone());
        StageAuthorization::Denied { denial }
    }

    fn terminal_context_denial<R: ProvisionalResources>(
        &mut self,
        request: &StageRequest,
        resources: &mut R,
    ) -> Result<StageAuthorization, CoreError> {
        if self.terminal_denial.is_some() {
            return Ok(StageAuthorization::AlreadyDenied {
                terminal_evidence_id: self.provenance.terminal_evidence_id.clone(),
            });
        }
        let denial = StructuredDenial {
            operation_id: self.operation_id.clone(),
            stage_id: request.stage_id.clone(),
            reason_code: REASON_OPERATION_CONTEXT.to_string(),
            completed_discovery_stages: self.completed_stages.clone(),
            released_provisional_resources: resources.release_all(),
            decision: None,
        };
        self.terminal_denial = Some(denial.clone());
        Ok(StageAuthorization::Denied { denial })
    }
}

pub fn run_oracle_json(input: &str) -> String {
    let result = (|| -> Result<Value, CoreError> {
        let value = parse_strict_json(input)?;
        validate_oracle_request_envelope(&value)?;
        let request: OracleRequest = serde_json::from_value(value).map_err(schema_error)?;
        let core = Rev2Core::embedded()?;
        match request {
            OracleRequest::Identity => serde_json::to_value(core.identity()).map_err(schema_error),
            OracleRequest::NormalizeSelector { selector, polarity } => {
                serde_json::to_value(core.normalize_selector(&selector, polarity)?)
                    .map_err(schema_error)
            }
            OracleRequest::NormalizeEffect { effect } => {
                serde_json::to_value(core.normalize_effect(&effect)?).map_err(schema_error)
            }
            OracleRequest::Match {
                selector,
                effect,
                polarity,
                source_id,
                path_bindings,
            } => Ok(Value::Bool(core.selector_matches_effect(
                &selector,
                &effect,
                polarity,
                &source_id,
                &path_bindings,
            )?)),
            OracleRequest::EvaluateAlgorithm {
                operation_id,
                selector,
                occurrence,
                polarity,
                source_id,
                path_bindings,
            } => {
                let algorithm = core.match_operations.get(&operation_id).ok_or_else(|| {
                    CoreError::new(
                        REASON_SCHEMA_INVALID,
                        format!("unknown match operation {operation_id}"),
                    )
                })?;
                Ok(Value::Bool(core.evaluate_match(
                    algorithm,
                    &selector,
                    &occurrence,
                    polarity,
                    &source_id,
                    &path_bindings,
                )?))
            }
            OracleRequest::DecideStage { stage, policy } => {
                serde_json::to_value(core.decide_stage(&stage, &policy)?).map_err(schema_error)
            }
        }
    })();
    let response = match result {
        Ok(value) => serde_json::json!({ "status": "ok", "value": value }),
        Err(error) => serde_json::json!({ "error": error, "status": "error" }),
    };
    canonical_json(&response).unwrap_or_else(|error| {
        format!(
            "{{\"error\":{{\"message\":{:?},\"reasonCode\":\"{}\"}},\"status\":\"error\"}}",
            error.message, error.reason_code
        )
    })
}

fn validate_oracle_request_envelope(value: &Value) -> Result<(), CoreError> {
    let object = value.as_object().ok_or_else(|| {
        CoreError::new(REASON_SCHEMA_INVALID, "oracle request must be an object")
    })?;
    let operation = object
        .get("operation")
        .and_then(Value::as_str)
        .ok_or_else(|| CoreError::new(REASON_SCHEMA_INVALID, "oracle operation is missing"))?;
    let allowed: &[&str] = match operation {
        "identity" => &["operation"],
        "normalizeSelector" => &["operation", "selector", "polarity"],
        "normalizeEffect" => &["operation", "effect"],
        "match" => &[
            "operation",
            "selector",
            "effect",
            "polarity",
            "sourceId",
            "pathBindings",
        ],
        "evaluateAlgorithm" => &[
            "operation",
            "operationId",
            "selector",
            "occurrence",
            "polarity",
            "sourceId",
            "pathBindings",
        ],
        "decideStage" => &["operation", "stage", "policy"],
        _ => {
            return Err(CoreError::new(
                REASON_SCHEMA_INVALID,
                format!("unknown oracle operation {operation}"),
            ));
        }
    };
    if let Some(key) = object.keys().find(|key| !allowed.contains(&key.as_str())) {
        return Err(CoreError::new(
            REASON_SCHEMA_INVALID,
            format!("unknown oracle request field {key}"),
        ));
    }
    Ok(())
}

pub fn run_oracle_stdio() -> Result<(), CoreError> {
    const MAX_ORACLE_INPUT_BYTES: u64 = 8 * 1024 * 1024;
    const MAX_ORACLE_OUTPUT_BYTES: usize = 16 * 1024 * 1024;
    let mut input = String::new();
    std::io::stdin()
        .take(MAX_ORACLE_INPUT_BYTES + 1)
        .read_to_string(&mut input)
        .map_err(|error| CoreError::new(REASON_SCHEMA_INVALID, error.to_string()))?;
    if input.len() as u64 > MAX_ORACLE_INPUT_BYTES {
        return Err(CoreError::new(
            REASON_SCHEMA_INVALID,
            "oracle request exceeds 8 MiB",
        ));
    }
    let output = run_oracle_json(&input);
    if output.len() > MAX_ORACLE_OUTPUT_BYTES {
        return Err(CoreError::new(
            REASON_SCHEMA_INVALID,
            "oracle response exceeds 16 MiB",
        ));
    }
    std::io::stdout()
        .write_all(output.as_bytes())
        .and_then(|_| std::io::stdout().write_all(b"\n"))
        .map_err(|error| CoreError::new(REASON_SCHEMA_INVALID, error.to_string()))
}

fn positive_inventory(policy: &NormalizedPolicy) -> Result<BTreeSet<String>, CoreError> {
    let mut inventory = BTreeSet::new();
    for (kind, generation, rows) in [
        ("static-row", None, &policy.static_floor),
        (
            "escalation-ceiling",
            Some(policy.generations.policy_snapshot.as_str()),
            &policy.escalation_ceiling,
        ),
        (
            "handle",
            None,
            &policy.handles,
        ),
        (
            "session-row",
            Some(policy.generations.session_overlay.as_str()),
            &policy.session_grants,
        ),
        (
            "implicit-package-self",
            Some(policy.generations.policy_snapshot.as_str()),
            &policy.implicit_self,
        ),
    ] {
        for row in rows {
            let generation = row.source_generation.as_deref().or(generation);
            let path_bindings: Vec<&PathBindingInput> = policy
                .path_bindings
                .iter()
                .filter(|binding| binding.source_id == row.source_id)
                .collect();
            let value = serde_json::json!({
                "channelEpoch": policy.channel_epoch,
                "generation": generation,
                "kind": kind,
                "pathBindings": path_bindings,
                "policySnapshotGeneration": policy.generations.policy_snapshot,
                "runNonce": policy.run_nonce,
                "selector": row.selector,
                "sourceId": row.source_id,
            });
            inventory.insert(domain_digest("oden:capsec:positive-source:2", &value)?);
        }
    }
    for receipt in &policy.validated_receipt_row_digests {
        let value = serde_json::json!({
            "kind": "validated-receipt-row",
            "policySnapshotGeneration": policy.generations.policy_snapshot,
            "receiptRowDigest": receipt,
            "runNonce": policy.run_nonce,
        });
        inventory.insert(domain_digest("oden:capsec:positive-source:2", &value)?);
    }
    for exception in &policy.protected_exceptions {
        let value = serde_json::json!({
            "kind": "protected-exception",
            "reason": exception.reason,
            "selector": exception.selector,
            "sourceId": exception.source_id,
            "runNonce": policy.run_nonce,
        });
        inventory.insert(domain_digest("oden:capsec:positive-source:2", &value)?);
    }
    for disposition in &policy.compatibility_dispositions {
        let value = serde_json::json!({
            "dispositionId": disposition.disposition_id,
            "kind": "compatibility-disposition",
            "selector": disposition.selector,
            "sourceId": disposition.source_id,
        });
        inventory.insert(domain_digest("oden:capsec:positive-source:2", &value)?);
    }
    Ok(inventory)
}

fn decision_policy_row_count(input: &DecisionPolicyInput) -> usize {
    input.process_denials.len()
        + input.principal_denials.len()
        + input.session_revocations.len()
        + input.escalation_ceiling.len()
        + input.static_floor.len()
        + input.handles.len()
        + input.session_grants.len()
        + input.implicit_self.len()
        + input.protected_exceptions.len()
        + input.compatibility_dispositions.len()
        + input.validated_receipt_row_digests.len()
        + input.path_bindings.len()
}

fn prospective_len_exceeds_bound(current: usize, added: usize, maximum: usize) -> bool {
    current.checked_add(added).is_none_or(|total| total > maximum)
}

fn inventory_digest(domain: &str, inventory: &BTreeSet<String>) -> Result<String, CoreError> {
    domain_digest(domain, &serde_json::to_value(inventory).map_err(schema_error)?)
}

fn set_union_exceeds_bound(
    current: &BTreeSet<String>,
    candidate: &BTreeSet<String>,
    maximum: usize,
) -> bool {
    prospective_len_exceeds_bound(
        current.len(),
        candidate.difference(current).count(),
        maximum,
    )
}

fn negative_inventory(policy: &NormalizedPolicy) -> Result<BTreeSet<String>, CoreError> {
    let mut inventory = BTreeSet::new();
    for (kind, rows) in [
        ("process-denial", &policy.process_denials),
        ("principal-denial", &policy.principal_denials),
        ("session-revocation", &policy.session_revocations),
    ] {
        for row in rows {
            let path_bindings: Vec<&PathBindingInput> = policy
                .path_bindings
                .iter()
                .filter(|binding| binding.source_id == row.source_id)
                .collect();
            let value = serde_json::json!({
                "kind": kind,
                "pathBindings": path_bindings,
                "selector": row.selector,
                "sourceId": row.source_id,
            });
            inventory.insert(domain_digest("oden:capsec:negative-source:2", &value)?);
        }
    }
    Ok(inventory)
}

fn positive_source_binding_key(
    stage_id: &str,
    principal: &PrincipalRef,
    effect: &CanonicalEffect,
    source_kind: &str,
) -> Result<String, CoreError> {
    let stage = (source_kind == "mode-fallback").then_some(stage_id);
    domain_digest(
        "oden:capsec:operation-positive-binding:2",
        &serde_json::json!({ "effect": effect, "principal": principal, "stageId": stage }),
    )
}

fn positive_source_base_key(
    principal: &PrincipalRef,
    effect: &CanonicalEffect,
) -> Result<String, CoreError> {
    domain_digest(
        "oden:capsec:operation-positive-base:2",
        &serde_json::json!({ "effect": effect, "principal": principal }),
    )
}

fn positive_source_base_value(source: &PositiveSource) -> Result<String, CoreError> {
    let value = if source.kind == "mode-fallback" {
        serde_json::json!({ "generation": source.generation, "kind": source.kind })
    } else {
        serde_json::to_value(source).map_err(schema_error)?
    };
    canonical_json(&value)
}

fn generations_are_monotonic(
    previous: &Generations,
    current: &Generations,
) -> Result<bool, CoreError> {
    Ok(parse_generation(&current.negative_overlay)?
        >= parse_generation(&previous.negative_overlay)?
        && parse_generation(&current.policy_snapshot)?
            >= parse_generation(&previous.policy_snapshot)?
        && parse_generation(&current.revocation)? >= parse_generation(&previous.revocation)?
        && parse_generation(&current.session_overlay)?
            >= parse_generation(&previous.session_overlay)?)
}

fn negative_generation_strictly_advanced(
    previous: &Generations,
    current: &Generations,
) -> Result<bool, CoreError> {
    Ok(parse_generation(&current.negative_overlay)?
        > parse_generation(&previous.negative_overlay)?
        || parse_generation(&current.revocation)? > parse_generation(&previous.revocation)?
        || parse_generation(&current.session_overlay)?
            > parse_generation(&previous.session_overlay)?)
}

fn parse_generation(value: &str) -> Result<u64, CoreError> {
    validate_u64_decimal(value)?;
    value
        .parse::<u64>()
        .map_err(|_| CoreError::new(REASON_SCHEMA_INVALID, "generation is not a u64"))
}

fn barrier_contract_matches(
    core: &Rev2Core,
    request: &StageRequest,
    barrier: OperationBarrier,
) -> bool {
    !request.effects.is_empty()
        && request.effects.iter().all(|effect| {
            core.edges.get(&effect.edge_id).is_some_and(|edge| match barrier {
                OperationBarrier::AuthorizationBeforeCommit => {
                    edge.barriers.authorization == "before-commit"
                }
                OperationBarrier::RevocationBeforeNextEffectOrDelivery => {
                    edge.barriers.revocation == "before-next-effect-or-delivery"
                }
            })
        })
}

fn match_type_error() -> CoreError {
    CoreError::new(REASON_SCHEMA_INVALID, "match operands have invalid types")
}

fn set_contains_all(
    selector: &Value,
    occurrence: &Value,
    polarity: SelectorPolarity,
) -> Result<bool, CoreError> {
    let selector = selector.as_array().ok_or_else(match_type_error)?;
    let occurrence = occurrence.as_array().ok_or_else(match_type_error)?;
    Ok(if polarity == SelectorPolarity::Negative {
        occurrence.iter().any(|item| selector.contains(item))
    } else {
        occurrence.iter().all(|item| selector.contains(item))
    })
}

fn dns_selector_matches(selector: &str, occurrence: &str) -> bool {
    if let Some(suffix) = selector.strip_prefix("*.") {
        occurrence.len() > suffix.len()
            && occurrence.ends_with(suffix)
            && occurrence.as_bytes()[occurrence.len() - suffix.len() - 1] == b'.'
    } else {
        selector == occurrence
    }
}

fn port_matches(selector: &Value, occurrence: &Value) -> Result<bool, CoreError> {
    let selector = selector.as_object().ok_or_else(match_type_error)?;
    let port = occurrence.as_u64().ok_or_else(match_type_error)?;
    Ok(match selector.get("kind").and_then(Value::as_str) {
        Some("any") => true,
        Some("exact") => selector.get("exact").and_then(Value::as_u64) == Some(port),
        Some("range") => {
            matches!(
                (
                    selector.get("minimum").and_then(Value::as_u64),
                    selector.get("maximum").and_then(Value::as_u64)
                ),
                (Some(minimum), Some(maximum)) if minimum <= port && port <= maximum
            )
        }
        _ => false,
    })
}

fn path_matches(
    selector: &Value,
    occurrence: &Value,
    polarity: SelectorPolarity,
    source_id: &str,
    path_bindings: &[PathBindingInput],
) -> Result<bool, CoreError> {
    let selector = selector.as_object().ok_or_else(match_type_error)?;
    let occurrence = occurrence.as_object().ok_or_else(match_type_error)?;
    let selector_path = selector.get("path").ok_or_else(match_type_error)?;
    let lexical_path = occurrence.get("lexicalPath").ok_or_else(match_type_error)?;
    let path_match = selector.get("root") == occurrence.get("root")
        && match selector.get("kind").and_then(Value::as_str) {
            Some("path-exact") => selector_path == lexical_path,
            Some("path-tree") => platform_path_contains(selector_path, lexical_path)?,
            _ => false,
        };
    let binding_id = occurrence
        .get("rootBindingId")
        .and_then(Value::as_str)
        .ok_or_else(match_type_error)?;
    let binding = path_bindings
        .iter()
        .find(|binding| binding.source_id == source_id && binding.root_binding_id == binding_id);
    let state = occurrence
        .get("finalObjectState")
        .and_then(Value::as_object)
        .ok_or_else(match_type_error)?;
    let identity_match = if let Some(binding) = binding {
        match state.get("kind").and_then(Value::as_str) {
            Some("existing" | "link-entry") => {
                let identity = state.get("identity").ok_or_else(match_type_error)?;
                binding.final_object_identities.contains(identity)
            }
            Some("missing" | "proposed") => {
                let parent = occurrence.get("parentIdentity").ok_or_else(match_type_error)?;
                binding.parent_identities.contains(parent)
            }
            _ => false,
        }
    } else {
        false
    };
    if polarity == SelectorPolarity::Negative {
        // Denials follow either their lexical spelling or an armed object
        // identity through aliases and overlapping logical roots.
        return Ok(path_match || identity_match);
    }
    if !path_match || !identity_match {
        return Ok(false);
    }
    Ok(true)
}

fn platform_path_contains(parent: &Value, child: &Value) -> Result<bool, CoreError> {
    let parent = parent.as_object().ok_or_else(match_type_error)?;
    let child = child.as_object().ok_or_else(match_type_error)?;
    if parent.get("encoding") != child.get("encoding") {
        return Ok(false);
    }
    let encoding = parent
        .get("encoding")
        .and_then(Value::as_str)
        .ok_or_else(match_type_error)?;
    let parent_payload = parent
        .get("value")
        .and_then(Value::as_str)
        .ok_or_else(match_type_error)?;
    let child_payload = child
        .get("value")
        .and_then(Value::as_str)
        .ok_or_else(match_type_error)?;
    let (parent_bytes, child_bytes) = if encoding == "opaque-base64url" {
        let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        (
            engine.decode(parent_payload).map_err(|_| match_type_error())?,
            engine.decode(child_payload).map_err(|_| match_type_error())?,
        )
    } else {
        (parent_payload.as_bytes().to_vec(), child_payload.as_bytes().to_vec())
    };
    if parent_bytes == child_bytes {
        return Ok(true);
    }
    if parent_bytes.is_empty() || child_bytes.len() <= parent_bytes.len() {
        return Ok(false);
    }
    Ok(child_bytes.starts_with(&parent_bytes)
        && (parent_bytes.ends_with(b"/") || child_bytes[parent_bytes.len()] == b'/'))
}

fn normalize_principal_set(input: &[PrincipalRef]) -> Vec<PrincipalRef> {
    let mut principals: Vec<PrincipalRef> = input
        .iter()
        .filter(|principal| !principal.is_transparent())
        .cloned()
        .collect();
    principals.sort();
    principals.dedup();
    if principals.is_empty() {
        principals.push(PrincipalRef {
            kind: PrincipalKind::NoUser,
            key: "no-user".to_string(),
        });
    }
    principals
}

fn selector_principal_matches(
    selector: &CanonicalAuthoritySelector,
    principal: &PrincipalRef,
    allow_any: bool,
) -> bool {
    match &selector.principal {
        Some(expected) => expected == principal,
        None => allow_any,
    }
}

fn canonical_row_digest(selector: &CanonicalAuthoritySelector) -> Result<String, CoreError> {
    let principal = selector.principal.as_ref().ok_or_else(|| {
        CoreError::new(REASON_SCHEMA_INVALID, "canonical positive row has no principal")
    })?;
    let row = serde_json::json!({
        "capability": selector.capability,
        "lifecycle": "authorable",
        "principal": principal,
        "resource": selector.resource,
        "vocabDigest": REV2_VOCAB_DIGEST,
    });
    domain_digest("oden:capsec:canonical-row:2", &row)
}

fn canonicalize_value(value: &Value) -> Result<Value, CoreError> {
    Ok(match value {
        Value::Null | Value::Bool(_) | Value::String(_) => value.clone(),
        Value::Number(number) => {
            if number.as_f64().is_some_and(|value| !value.is_finite()) {
                return Err(CoreError::new(REASON_SCHEMA_INVALID, "non-finite JSON number"));
            }
            Value::Number(number.clone())
        }
        Value::Array(values) => Value::Array(
            values
                .iter()
                .map(canonicalize_value)
                .collect::<Result<Vec<_>, _>>()?,
        ),
        Value::Object(object) => {
            let mut sorted = Map::new();
            let mut keys: Vec<&String> = object.keys().collect();
            keys.sort();
            for key in keys {
                sorted.insert(key.clone(), canonicalize_value(&object[key])?);
            }
            Value::Object(sorted)
        }
    })
}

pub fn canonical_json(value: &Value) -> Result<String, CoreError> {
    serde_json::to_string(&canonicalize_value(value)?).map_err(schema_error)
}

pub fn domain_digest(domain: &str, value: &Value) -> Result<String, CoreError> {
    let canonical = canonical_json(value)?;
    let mut hasher = Sha256::new();
    hasher.update(domain.as_bytes());
    hasher.update(canonical.as_bytes());
    let digest = hasher.finalize();
    Ok(format!(
        "sha256-{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
    ))
}

struct StrictJson(Value);

impl<'de> Deserialize<'de> for StrictJson {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_any(StrictJsonVisitor)
    }
}

struct StrictJsonVisitor;

impl<'de> Visitor<'de> for StrictJsonVisitor {
    type Value = StrictJson;

    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("strict I-JSON")
    }

    fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
        Ok(StrictJson(Value::Bool(value)))
    }

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
        Ok(StrictJson(Value::Number(value.into())))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
        Ok(StrictJson(Value::Number(value.into())))
    }

    fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        if !value.is_finite() {
            return Err(E::custom("non-finite I-JSON number"));
        }
        serde_json::Number::from_f64(value)
            .map(Value::Number)
            .map(StrictJson)
            .ok_or_else(|| E::custom("invalid I-JSON number"))
    }

    fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
        Ok(StrictJson(Value::String(value.to_string())))
    }

    fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
        Ok(StrictJson(Value::String(value)))
    }

    fn visit_none<E>(self) -> Result<Self::Value, E> {
        Ok(StrictJson(Value::Null))
    }

    fn visit_unit<E>(self) -> Result<Self::Value, E> {
        Ok(StrictJson(Value::Null))
    }

    fn visit_some<D>(self, deserializer: D) -> Result<Self::Value, D::Error>
    where
        D: Deserializer<'de>,
    {
        StrictJson::deserialize(deserializer)
    }

    fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
    where
        A: SeqAccess<'de>,
    {
        let mut values = Vec::new();
        while let Some(StrictJson(value)) = sequence.next_element::<StrictJson>()? {
            values.push(value);
        }
        Ok(StrictJson(Value::Array(values)))
    }

    fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
    where
        A: MapAccess<'de>,
    {
        let mut object = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if object.contains_key(&key) {
                return Err(de::Error::custom(format!("duplicate object key {key}")));
            }
            let StrictJson(value) = map.next_value::<StrictJson>()?;
            object.insert(key, value);
        }
        Ok(StrictJson(Value::Object(object)))
    }
}

pub fn parse_strict_json(input: &str) -> Result<Value, CoreError> {
    serde_json::from_str::<StrictJson>(input)
        .map(|value| value.0)
        .map_err(|error| CoreError::new(REASON_SCHEMA_INVALID, error.to_string()))
}

fn zero_generation() -> String {
    "0".to_string()
}

fn validate_u64_decimal(value: &str) -> Result<(), CoreError> {
    let parsed = value.parse::<u64>().map_err(|_| {
        CoreError::new(REASON_SCHEMA_INVALID, "generation is not an unsigned decimal string")
    })?;
    if parsed.to_string() != value {
        return Err(CoreError::new(
            REASON_SCHEMA_INVALID,
            "generation is not canonical unsigned decimal",
        ));
    }
    Ok(())
}

fn validate_digest_string(value: &str) -> Result<(), CoreError> {
    let encoded = value.strip_prefix("sha256-").ok_or_else(|| {
        CoreError::new(REASON_SCHEMA_INVALID, "digest has no sha256- algorithm tag")
    })?;
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| CoreError::new(REASON_SCHEMA_INVALID, "digest is not unpadded base64url"))?;
    if decoded.len() != 32 {
        return Err(CoreError::new(
            REASON_SCHEMA_INVALID,
            "SHA-256 digest does not contain 32 bytes",
        ));
    }
    if base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&decoded) != encoded {
        return Err(CoreError::new(
            REASON_SCHEMA_INVALID,
            "digest is not canonical unpadded base64url",
        ));
    }
    Ok(())
}

fn canonical_value_set(values: Vec<Value>) -> Result<Vec<Value>, CoreError> {
    let mut rows = BTreeMap::new();
    for value in values {
        rows.entry(canonical_json(&value)?).or_insert(value);
    }
    Ok(rows.into_values().collect())
}

fn canonical_dns_name(input: &str) -> Result<String, CoreError> {
    let trimmed = input.strip_suffix('.').unwrap_or(input);
    let (wildcard, trimmed) = if let Some(suffix) = trimmed.strip_prefix("*.") {
        (true, suffix)
    } else {
        (false, trimmed)
    };
    if trimmed.is_empty() || trimmed.split('.').any(str::is_empty) {
        return Err(CoreError::new(REASON_SCHEMA_INVALID, "invalid absolute DNS name"));
    }
    let ascii = idna::domain_to_ascii_strict(trimmed)
        .map_err(|_| CoreError::new(REASON_SCHEMA_INVALID, "invalid IDNA name"))?
        .to_ascii_lowercase();
    if ascii.len() > 253
        || ascii.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        return Err(CoreError::new(REASON_SCHEMA_INVALID, "invalid DNS A-label"));
    }
    Ok(if wildcard {
        format!("*.{ascii}")
    } else {
        ascii
    })
}

fn canonical_ip(input: &str) -> Result<String, CoreError> {
    let parsed = IpAddr::from_str(input)
        .map_err(|_| CoreError::new(REASON_SCHEMA_INVALID, "invalid IP address"))?;
    Ok(effective_ip(parsed).to_string())
}

fn canonical_cidr(input: &str) -> Result<String, CoreError> {
    let network = IpNet::from_str(input)
        .map_err(|_| CoreError::new(REASON_SCHEMA_INVALID, "invalid CIDR"))?
        .trunc();
    match network {
        IpNet::V6(network) => {
            let mapped_base = "::ffff:0:0"
                .parse::<Ipv6Addr>()
                .map_err(|_| CoreError::new(REASON_SCHEMA_INVALID, "invalid mapped base"))?;
            if network.prefix_len() < 96 && network.contains(&mapped_base) {
                return Err(CoreError::new(
                    REASON_SCHEMA_INVALID,
                    "IPv6 CIDR partially overlaps the IPv4-mapped range",
                ));
            }
            if let Some(address) = network.network().to_ipv4_mapped() {
                let prefix = network.prefix_len().checked_sub(96).ok_or_else(|| {
                    CoreError::new(REASON_SCHEMA_INVALID, "invalid mapped CIDR prefix")
                })?;
                return Ipv4Net::new(address, prefix)
                    .map(|network| network.trunc().to_string())
                    .map_err(|_| CoreError::new(REASON_SCHEMA_INVALID, "invalid mapped CIDR"));
            }
            Ok(network.to_string())
        }
        IpNet::V4(network) => Ok(network.to_string()),
    }
}

fn canonical_vsock(input: &str) -> Result<String, CoreError> {
    let Some((cid, port)) = input.split_once(':') else {
        return Err(CoreError::new(REASON_SCHEMA_INVALID, "invalid vsock cid:port"));
    };
    let cid = cid
        .parse::<u32>()
        .map_err(|_| CoreError::new(REASON_SCHEMA_INVALID, "invalid vsock cid"))?;
    let port = port
        .parse::<u32>()
        .map_err(|_| CoreError::new(REASON_SCHEMA_INVALID, "invalid vsock port"))?;
    if format!("{cid}:{port}") != input {
        return Err(CoreError::new(
            REASON_SCHEMA_INVALID,
            "vsock cid:port is not canonical unsigned decimal",
        ));
    }
    Ok(input.to_string())
}

fn effective_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(value) => value
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(value)),
        other => other,
    }
}

fn canonical_set(value: Value, schema_id: &str, field: &str) -> Result<Value, CoreError> {
    let items = value.as_array().ok_or_else(|| {
        CoreError::new(
            REASON_SCHEMA_INVALID,
            format!("{schema_id}.{field} is not an array"),
        )
    })?;
    let mut keyed = BTreeMap::new();
    for item in items {
        let canonical = canonical_json(item)?;
        keyed.entry(canonical).or_insert_with(|| item.clone());
    }
    Ok(Value::Array(keyed.into_values().collect()))
}

fn value_i128(value: &Value) -> Option<i128> {
    value
        .as_i64()
        .map(i128::from)
        .or_else(|| value.as_u64().map(i128::from))
}

fn value_at_path<'a>(value: &'a Value, path: &str) -> Option<&'a Value> {
    if path == "$" || path.is_empty() {
        return Some(value);
    }
    let mut current = value;
    for component in path.trim_start_matches("$.").split('.') {
        current = current.as_object()?.get(component)?;
    }
    Some(current)
}

fn unique_by_id<T, I, F>(rows: I, id: F) -> Result<BTreeMap<String, T>, CoreError>
where
    I: IntoIterator<Item = T>,
    F: Fn(&T) -> &String,
{
    let mut out = BTreeMap::new();
    for row in rows {
        let key = id(&row).clone();
        if out.insert(key.clone(), row).is_some() {
            return Err(CoreError::new(
                REASON_SCHEMA_INVALID,
                format!("duplicate generated id {key}"),
            ));
        }
    }
    Ok(out)
}

fn validate_edge_semantics(edge_id: &str, semantics: &EdgeSemantics) -> Result<(), CoreError> {
    let expected_actor_keys = ["decision-stage", "effect-owner", "operation-actor", "principal-set"];
    let expected_generation_keys = [
        "negative-overlay",
        "policy-snapshot",
        "revocation",
        "session-overlay",
    ];
    let invalid = semantics.effects.is_empty()
        || semantics.principal_sources != ["captured-constrained-set"]
        || semantics.effect_owner_source != "captured-effect-owner"
        || semantics.actor_keys.iter().map(String::as_str).collect::<Vec<_>>()
            != expected_actor_keys
        || semantics
            .generation_keys
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
            != expected_generation_keys
        || semantics.effect_start_boundary != "before-first-authority-bearing-effect"
        || semantics.barriers.authorization != "before-commit"
        || semantics.barriers.cancellation != "release-provisional-state"
        || semantics.barriers.cleanup != "always-permitted-only-when-non-authorizing"
        || !matches!(
            semantics.barriers.commit.as_str(),
            "before-commit" | "unimplemented"
        )
        || semantics.barriers.delivery != "unimplemented"
        || !matches!(
            semantics.barriers.discovery.as_str(),
            "before-next-effect-or-delivery" | "unimplemented"
        )
        || semantics.barriers.revocation != "before-next-effect-or-delivery"
        || semantics.lifetime_contract_id != "lifetime.staged-effect/2"
        || semantics.gate.branch_id.trim().is_empty()
        || !matches!(semantics.gate.branch_kind.as_str(), "single" | "alternative")
        || semantics
            .gate
            .condition
            .as_ref()
            .is_some_and(|condition| condition.trim().is_empty())
        || !matches!(
            semantics.gate.enforcement_disposition.as_str(),
            "bidirectional" | "negative-closure"
        )
        || !matches!(
            semantics.gate.mechanism.as_str(),
            "adds-op-gate"
                | "deny-only"
                | "loader-admission"
                | "reachability-close"
                | "reclassifies"
        )
        || semantics.gate.enforcement_disposition == "negative-closure"
            && semantics.gate.negative_closure_spec_id.is_none()
        || !matches!(
            semantics.target_effect_disposition.as_str(),
            "explicit-complete" | "none" | "replace-current" | "retain-migrated-current"
        )
        || semantics.positive_channels.iter().any(|channel| {
            !matches!(
                channel.as_str(),
                "ambient-root"
                    | "floor"
                    | "handle"
                    | "implicit-self"
                    | "mode-fallback"
                    | "session"
            )
        })
        || semantics.effects.iter().any(|effect| {
            effect.effect_slot_id.trim().is_empty()
                || effect.capability.trim().is_empty()
                || effect.authority_selector_normalizer_id
                    != "normalizer.schema-authority-selector/2"
                || effect.effect_occurrence_normalizer_id
                    != "normalizer.schema-effect-occurrence/2"
                || effect.source_resource_description.trim().is_empty()
                || !matches!(effect.cardinality.as_str(), "exactly-one" | "zero-or-more")
                || semantics.effect_mode == "alternative"
                    && effect.cardinality != "exactly-one"
                || effect
                    .condition
                    .as_ref()
                    .is_some_and(|condition| condition.trim().is_empty())
        });
    if invalid {
        return Err(CoreError::new(
            REASON_SCHEMA_INVALID,
            format!("edge {edge_id} has an unsupported authority-bearing contract"),
        ));
    }
    let slots: BTreeSet<&str> = semantics
        .effects
        .iter()
        .map(|effect| effect.effect_slot_id.as_str())
        .collect();
    if slots.len() != semantics.effects.len() {
        return Err(CoreError::new(
            REASON_SCHEMA_INVALID,
            format!("edge {edge_id} repeats a generated effect slot"),
        ));
    }
    if let Some(complete) = &semantics.complete_effect_slot_ids {
        let complete: BTreeSet<&str> = complete.iter().map(String::as_str).collect();
        let required: BTreeSet<&str> = semantics
            .effects
            .iter()
            .filter(|effect| effect.cardinality == "exactly-one")
            .map(|effect| effect.effect_slot_id.as_str())
            .collect();
        if complete != required {
            return Err(CoreError::new(
                REASON_SCHEMA_INVALID,
                format!("edge {edge_id} complete slot contract disagrees with its effects"),
            ));
        }
    }
    if let Some(contract) = &semantics.masked_commit {
        let masked_effect = semantics.effects.iter().find(|effect| {
            effect.effect_slot_id == contract.masked_effect_slot_id
                && effect.capability == "env:read"
                && effect.cardinality == "zero-or-more"
        });
        if masked_effect.is_none()
            || contract.optional_disposition != "omit-masked-effect-and-continue"
            || contract.required_disposition != "deny-complete-stage"
            || contract.required_for_commit_occurrence_path != "requiredForCommit"
            || contract.required_for_commit_source != "trusted-sealed-child-export-entry"
        {
            return Err(CoreError::new(
                REASON_SCHEMA_INVALID,
                format!("edge {edge_id} has an invalid masked-commit contract"),
            ));
        }
    }
    Ok(())
}

fn supported_match_algorithm(algorithm: &str) -> bool {
    matches!(
        algorithm,
        "dns-exact-or-subtree"
            | "json-equal"
            | "network-host-peer-conjunction"
            | "path-exact-or-tree"
            | "peer-class-conjunction"
            | "port-exact-range-any"
            | "scheme-transport-conjunction"
            | "set-contains-all"
    )
}

fn supported_canonicalization(canonicalization: &str) -> bool {
    matches!(
        canonicalization,
        "I-JSON/RFC8785"
            | "deduplicate-sort-canonical"
            | "host-kind-specific-canonicalization"
            | "identity"
            | "lowercase-idna-a-label-no-trailing-dot"
            | "preserve-tagged-path-payload"
            | "tagged-path-preserve-opaque-bytes"
    )
}

fn supported_field_format(format: &str) -> bool {
    format.starts_with("risk-input:")
        || matches!(
            format,
            "boolean"
                | "canonical-positive-row/2"
                | "canonical-row-digest-set/2"
                | "canonical-string-set/2"
                | "canonical-string/2"
                | "canonical-u64-decimal"
                | "cron-expression/2"
                | "dns-a-label-absolute-name/2"
                | "i-json-safe-integer"
                | "integrity-bound-target-id/2"
                | "logical-path-root/2"
                | "module-entry/2"
                | "network-host-kind/2"
                | "network-host-value/2"
                | "network-route-kind/2"
                | "network-route/2"
                | "opaque-id"
                | "path-encoding/2"
                | "path-payload/2"
                | "platform-normalized-name/2"
                | "principal-key/2"
                | "reason-code-or-null/2"
                | "route-attestation-or-null/2"
                | "route-endpoint-or-null/2"
                | "typed-network-host/2"
                | "typed-object-set/2"
                | "typed-object/2"
                | "u16"
                | "unicode-or-opaque-platform-path/2"
        )
}

fn schema_error(error: serde_json::Error) -> CoreError {
    CoreError::new(REASON_SCHEMA_INVALID, error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use serde_json::json;

    const ENV_EDGE: &str = "native-op:ext/os/lib.rs#op_get_env";
    const ENV_SLOT: &str = "native-op:ext/os/lib.rs#op_get_env:effect-slot:0";
    const CWD_EDGE: &str = "native-op:ext/fs/ops.rs#op_fs_chdir";
    const CWD_SLOT: &str = "native-op:ext/fs/ops.rs#op_fs_chdir:effect-slot:0";
    const INSPECT_EDGE: &str = "startup-hook:cli/args/flags.rs#--inspect-publish-uid";
    const INSPECT_SLOT: &str =
        "startup-hook:cli/args/flags.rs#--inspect-publish-uid:effect-slot:0";
    const INSPECT_MULTI_EDGE: &str = "startup-hook:cli/args/flags.rs#--inspect";
    const INSPECT_MULTI_SLOT: &str = "startup-hook:cli/args/flags.rs#--inspect:effect-slot:0";
    const INSPECT_LISTEN_SLOT: &str = "startup-hook:cli/args/flags.rs#--inspect:effect-slot:1";
    const FETCH_EDGE: &str = "socket-path:ext/net/ops.rs#op_dns_resolve";
    const FETCH_SLOT: &str = "socket-path:ext/net/ops.rs#op_dns_resolve:effect-slot:0";
    const DENY_ONLY_FETCH_EDGE: &str = "socket-path:ext/fetch/lib.rs#op_fetch_custom_client";
    const DENY_ONLY_FETCH_SLOT: &str =
        "socket-path:ext/fetch/lib.rs#op_fetch_custom_client:effect-slot:0";
    const PATH_EDGE: &str = "native-op:ext/node_sqlite/sql_tag_store.rs#SQLTagStore::all";
    const PATH_SLOT: &str =
        "native-op:ext/node_sqlite/sql_tag_store.rs#SQLTagStore::all:effect-slot:0";
    const LOADER_PATH_EDGE: &str = "loader-branch:cli/module_loader.rs#npm-package-load";
    const LOADER_PATH_SLOT: &str =
        "loader-branch:cli/module_loader.rs#npm-package-load:effect-slot:0";
    const SYS_EDGE: &str = "native-op:ext/node/ops/os/mod.rs#op_cpus";
    const SYS_SLOT: &str = "native-op:ext/node/ops/os/mod.rs#op_cpus:effect-slot:0";
    const ALTERNATIVE_EDGE: &str =
        "native-op:ext/node/ops/http2/session.rs#Http2Session::active_stream_count";
    const ALTERNATIVE_CONNECT_SLOT: &str =
        "native-op:ext/node/ops/http2/session.rs#Http2Session::active_stream_count:effect-slot:0";
    const ALTERNATIVE_LISTEN_SLOT: &str =
        "native-op:ext/node/ops/http2/session.rs#Http2Session::active_stream_count:effect-slot:1";
    const SPAWN_EDGE: &str = "native-op:ext/process/lib.rs#op_spawn_child";
    const SPAWN_SLOT: &str = "native-op:ext/process/lib.rs#op_spawn_child:effect-slot:0";
    const SPAWN_ENV_READ_SLOT: &str =
        "native-op:ext/process/lib.rs#op_spawn_child:effect-slot:1";
    const SPAWN_ENV_WRITE_SLOT: &str =
        "native-op:ext/process/lib.rs#op_spawn_child:effect-slot:2";

    fn package(name: &str) -> PrincipalRef {
        PrincipalRef {
            kind: PrincipalKind::Package,
            key: format!("pkg:sha256-{name}"),
        }
    }

    fn root() -> PrincipalRef {
        PrincipalRef {
            kind: PrincipalKind::Root,
            key: "root:sha256-project".to_string(),
        }
    }

    fn selector(principal: Option<PrincipalRef>, capability: &str, resource: Value) -> AuthoritySelectorInput {
        AuthoritySelectorInput {
            identity: EngineIdentity::embedded(),
            principal,
            capability: capability.to_string(),
            resource,
        }
    }

    fn named(source_id: &str, selector: AuthoritySelectorInput) -> NamedSelectorInput {
        NamedSelectorInput {
            source_id: source_id.to_string(),
            selector,
        }
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

    fn env_selector(principal: PrincipalRef, name: &str) -> AuthoritySelectorInput {
        selector(Some(principal), "env:read", json!({ "name": name }))
    }

    fn fetch_effect(address: &str) -> EffectInput {
        EffectInput {
            identity: EngineIdentity::embedded(),
            edge_id: FETCH_EDGE.to_string(),
            effect_slot_id: FETCH_SLOT.to_string(),
            capability: "network:fetch".to_string(),
            effect_owner: "owner:pkg".to_string(),
            occurrence: json!({
                "candidate": { "kind": "ip", "value": address },
                "effectOwner": "owner:pkg",
                "port": 80,
                "requestedHost": { "kind": "ip-exact", "value": address },
                "route": { "attestation": null, "endpoint": null, "kind": "direct" },
                "scheme": "http",
                "transport": "tcp",
                "verifiedPeer": { "kind": "ip", "value": address },
            }),
        }
    }

    fn fetch_dns_effect(host: &str, address: &str) -> EffectInput {
        EffectInput {
            identity: EngineIdentity::embedded(),
            edge_id: FETCH_EDGE.to_string(),
            effect_slot_id: FETCH_SLOT.to_string(),
            capability: "network:fetch".to_string(),
            effect_owner: "owner:pkg".to_string(),
            occurrence: json!({
                "candidate": { "kind": "ip", "value": address },
                "effectOwner": "owner:pkg",
                "port": 80,
                "requestedHost": { "kind": "dns-exact", "value": host },
                "route": { "attestation": null, "endpoint": null, "kind": "direct" },
                "scheme": "http",
                "transport": "tcp",
                "verifiedPeer": { "kind": "ip", "value": address },
            }),
        }
    }

    fn fetch_host_selector(
        principal: Option<PrincipalRef>,
        kind: &str,
        value: &str,
        peer_class: &str,
    ) -> AuthoritySelectorInput {
        selector(
            principal,
            "network:fetch",
            json!({
                "host": { "kind": kind, "value": value },
                "peerClasses": [peer_class],
                "port": { "exact": 80, "kind": "exact" },
                "route": { "attestation": null, "endpoint": null, "kind": "direct" },
                "schemes": ["http"],
            }),
        )
    }

    fn inspector_effect(edge_id: &str, effect_slot_id: &str) -> EffectInput {
        EffectInput {
            identity: EngineIdentity::embedded(),
            edge_id: edge_id.to_string(),
            effect_slot_id: effect_slot_id.to_string(),
            capability: "inspector:activate".to_string(),
            effect_owner: "owner:root".to_string(),
            occurrence: json!({
                "effectOwner": "owner:root",
                "listener": { "kind": "network-listener", "value": "127.0.0.1:9229" },
                "route": { "attestation": null, "endpoint": null, "kind": "direct" },
                "session": { "kind": "inspector", "value": "startup" },
            }),
        }
    }

    fn inspector_selector(principal: PrincipalRef) -> AuthoritySelectorInput {
        selector(
            Some(principal),
            "inspector:activate",
            json!({
                "route": { "attestation": null, "endpoint": null, "kind": "direct" },
                "session": { "kind": "inspector", "value": "startup" },
            }),
        )
    }

    fn inspector_listener_effect() -> EffectInput {
        EffectInput {
            identity: EngineIdentity::embedded(),
            edge_id: INSPECT_MULTI_EDGE.to_string(),
            effect_slot_id: INSPECT_LISTEN_SLOT.to_string(),
            capability: "network:listen".to_string(),
            effect_owner: "owner:root".to_string(),
            occurrence: json!({
                "bind": { "kind": "address", "value": "127.0.0.1" },
                "effectOwner": "owner:root",
                "port": 9229,
                "transport": "tcp",
            }),
        }
    }

    fn inspector_listener_selector(principal: PrincipalRef) -> AuthoritySelectorInput {
        selector(
            Some(principal),
            "network:listen",
            json!({
                "bind": { "kind": "address", "value": "127.0.0.1" },
                "port": { "exact": 9229, "kind": "exact" },
                "transport": "tcp",
            }),
        )
    }

    fn fetch_selector(
        principal: PrincipalRef,
        address: &str,
        peer_class: &str,
    ) -> AuthoritySelectorInput {
        selector(
            Some(principal),
            "network:fetch",
            json!({
                "host": { "kind": "ip-exact", "value": address },
                "peerClasses": [peer_class],
                "port": { "exact": 80, "kind": "exact" },
                "route": { "attestation": null, "endpoint": null, "kind": "direct" },
                "schemes": ["http"],
            }),
        )
    }

    fn path_effect(path: &str, identity: &str) -> EffectInput {
        EffectInput {
            identity: EngineIdentity::embedded(),
            edge_id: PATH_EDGE.to_string(),
            effect_slot_id: PATH_SLOT.to_string(),
            capability: "fs:read".to_string(),
            effect_owner: "owner:pkg".to_string(),
            occurrence: json!({
                "effectOwner": "owner:pkg",
                "finalObjectState": {
                    "identity": { "kind": "platform-object", "value": identity },
                    "kind": "existing",
                },
                "followMode": "follow-final",
                "lexicalPath": { "encoding": "unicode", "value": path },
                "parentIdentity": { "kind": "platform-object", "value": "dir:parent" },
                "root": "$PROJECT",
                "rootBindingId": "root-binding:1",
            }),
        }
    }

    fn path_selector(principal: PrincipalRef, path: &str) -> AuthoritySelectorInput {
        selector(
            Some(principal),
            "fs:read",
            json!({
                "kind": "path-tree",
                "path": { "encoding": "unicode", "value": path },
                "root": "$PROJECT",
            }),
        )
    }

    fn loader_path_effect(path: &str, identity: &str, state_kind: &str) -> EffectInput {
        EffectInput {
            identity: EngineIdentity::embedded(),
            edge_id: LOADER_PATH_EDGE.to_string(),
            effect_slot_id: LOADER_PATH_SLOT.to_string(),
            capability: "fs:read".to_string(),
            effect_owner: "owner:pkg".to_string(),
            occurrence: json!({
                "effectOwner": "owner:pkg",
                "finalObjectState": {
                    "identity": { "kind": "platform-object", "value": identity },
                    "kind": state_kind,
                },
                "followMode": "follow-final",
                "lexicalPath": { "encoding": "unicode", "value": path },
                "parentIdentity": { "kind": "platform-object", "value": "dir:package" },
                "root": "$PACKAGE",
                "rootBindingId": "root-binding:package",
            }),
        }
    }

    fn implicit_package_selector(
        principal: PrincipalRef,
        root: &str,
        path: &str,
    ) -> AuthoritySelectorInput {
        selector(
            Some(principal),
            "fs:read",
            json!({
                "kind": "path-exact",
                "path": { "encoding": "unicode", "value": path },
                "root": root,
            }),
        )
    }

    fn sys_effect(kind: &str) -> EffectInput {
        EffectInput {
            identity: EngineIdentity::embedded(),
            edge_id: SYS_EDGE.to_string(),
            effect_slot_id: SYS_SLOT.to_string(),
            capability: "sys:read".to_string(),
            effect_owner: "owner:pkg".to_string(),
            occurrence: json!({ "effectOwner": "owner:pkg", "kind": kind }),
        }
    }

    fn alternative_connect_effect() -> EffectInput {
        EffectInput {
            identity: EngineIdentity::embedded(),
            edge_id: ALTERNATIVE_EDGE.to_string(),
            effect_slot_id: ALTERNATIVE_CONNECT_SLOT.to_string(),
            capability: "network:connect".to_string(),
            effect_owner: "owner:root".to_string(),
            occurrence: json!({
                "candidate": { "kind": "ip", "value": "8.8.8.8" },
                "effectOwner": "owner:root",
                "port": 443,
                "requestedHost": { "kind": "ip-exact", "value": "8.8.8.8" },
                "route": { "attestation": null, "endpoint": null, "kind": "direct" },
                "scheme": "raw-tcp",
                "transport": "tcp",
                "verifiedPeer": { "kind": "ip", "value": "8.8.8.8" },
            }),
        }
    }

    fn alternative_listen_effect() -> EffectInput {
        EffectInput {
            identity: EngineIdentity::embedded(),
            edge_id: ALTERNATIVE_EDGE.to_string(),
            effect_slot_id: ALTERNATIVE_LISTEN_SLOT.to_string(),
            capability: "network:listen".to_string(),
            effect_owner: "owner:root".to_string(),
            occurrence: json!({
                "bind": { "kind": "address", "value": "127.0.0.1" },
                "effectOwner": "owner:root",
                "port": 443,
                "transport": "tcp",
            }),
        }
    }

    fn spawn_effect() -> EffectInput {
        EffectInput {
            identity: EngineIdentity::embedded(),
            edge_id: SPAWN_EDGE.to_string(),
            effect_slot_id: SPAWN_SLOT.to_string(),
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

    fn spawn_selector(principal: PrincipalRef) -> AuthoritySelectorInput {
        selector(
            Some(principal),
            "process:spawn",
            json!({
                "interpreterIdentity": { "kind": "platform-object", "value": "none" },
                "objectIdentity": { "kind": "platform-object", "value": "exe:echo" },
                "path": { "encoding": "unicode", "value": "/bin/echo" },
            }),
        )
    }

    fn child_env_read_effect(name: &str, required_for_commit: bool) -> EffectInput {
        let mut effect = env_effect(name);
        effect.edge_id = SPAWN_EDGE.to_string();
        effect.effect_slot_id = SPAWN_ENV_READ_SLOT.to_string();
        effect.occurrence["requiredForCommit"] = Value::Bool(required_for_commit);
        effect
    }

    fn child_env_write_effect(name: &str) -> EffectInput {
        EffectInput {
            identity: EngineIdentity::embedded(),
            edge_id: SPAWN_EDGE.to_string(),
            effect_slot_id: SPAWN_ENV_WRITE_SLOT.to_string(),
            capability: "env:write".to_string(),
            effect_owner: "owner:pkg".to_string(),
            occurrence: json!({
                "effectOwner": "owner:pkg",
                "name": name,
                "ownerGeneration": "0",
                "targetId": "child:launch",
                "targetKind": "child-launch",
            }),
        }
    }

    fn child_env_write_selector(
        principal: PrincipalRef,
        name: &str,
    ) -> AuthoritySelectorInput {
        selector(
            Some(principal),
            "env:write",
            json!({
                "name": name,
                "targetId": "child:launch",
                "targetKind": "child-launch",
            }),
        )
    }

    fn stage(id: &str, principals: Vec<PrincipalRef>, effects: Vec<EffectInput>) -> StageRequest {
        StageRequest {
            identity: EngineIdentity::embedded(),
            stage_id: id.to_string(),
            principals,
            effects,
        }
    }

    fn policy(mode: Mode) -> DecisionPolicyInput {
        DecisionPolicyInput {
            identity: EngineIdentity::embedded(),
            mode,
            run_nonce: "run:1".to_string(),
            channel_epoch: "channel:1".to_string(),
            provenance: OperationProvenanceContext {
                policy_digest: REV2_VOCAB_DIGEST.to_string(),
                armed_snapshot_digest: REV2_REGISTRY_DIGEST.to_string(),
                quota_owner: PrincipalRef {
                    kind: PrincipalKind::Runtime,
                    key: "runtime:quota-owner".to_string(),
                },
                terminal_evidence_id: "terminal-evidence:fixture".to_string(),
            },
            generations: Generations {
                policy_snapshot: "1".to_string(),
                ..Generations::default()
            },
            process_denials: Vec::new(),
            principal_denials: Vec::new(),
            session_revocations: Vec::new(),
            escalation_ceiling: Vec::new(),
            static_floor: Vec::new(),
            handles: Vec::new(),
            session_grants: Vec::new(),
            implicit_self: Vec::new(),
            protected_exceptions: Vec::new(),
            compatibility_dispositions: Vec::new(),
            validated_receipt_row_digests: Vec::new(),
            path_bindings: Vec::new(),
        }
    }

    fn captured_context(
        actor_id: &str,
        principals: Vec<PrincipalRef>,
        effect_owner_id: &str,
    ) -> CapturedOperationContext {
        let owner = principals
            .iter()
            .find(|principal| !principal.is_transparent())
            .cloned()
            .unwrap_or(PrincipalRef {
                kind: PrincipalKind::Runtime,
                key: "runtime:effect-owner".to_string(),
            });
        CapturedOperationContext::capture_host(
            actor_id,
            EngineIdentity::embedded(),
            principals,
            effect_owner_id,
            owner,
            "0",
            Vec::new(),
            None,
        )
        .unwrap()
    }

    #[test]
    fn embedded_payload_is_self_authenticating_and_n_is_exact() {
        let core = Rev2Core::embedded().unwrap();
        assert_eq!(core.identity(), EngineIdentity::embedded());
        let mut previous = EngineIdentity::embedded();
        previous.vocab_digest = "sha256-previous-vocabulary".to_string();
        assert_eq!(
            core.validate_identity(&previous).unwrap_err().reason_code,
            REASON_VOCAB_MISMATCH
        );
        let mut wrong_registry = EngineIdentity::embedded();
        wrong_registry.registry_digest = "sha256-wrong-registry".to_string();
        assert_eq!(
            core.validate_identity(&wrong_registry).unwrap_err().reason_code,
            REASON_REGISTRY_MISMATCH
        );
        let duplicate = parse_strict_json(r#"{"a":1,"a":2}"#).unwrap_err();
        assert_eq!(duplicate.reason_code, REASON_SCHEMA_INVALID);
    }

    #[test]
    fn implemented_barrier_contract_is_closed_and_accepted() {
        let core = Rev2Core::embedded().unwrap();
        let edge_id =
            "native-op:runtime/ops/oden.rs#op_oden_check_protected_inspector_stream_use";
        let edge = core.edges.get(edge_id).unwrap();
        assert_eq!(edge.barriers.commit, "before-commit");
        assert_eq!(
            edge.barriers.discovery,
            "before-next-effect-or-delivery"
        );

        let mut invalid = edge.clone();
        invalid.barriers.commit = "release-provisional-state".to_string();
        assert_eq!(
            validate_edge_semantics(edge_id, &invalid)
                .unwrap_err()
                .reason_code,
            REASON_SCHEMA_INVALID
        );

        invalid = edge.clone();
        invalid.barriers.discovery = "before-commit".to_string();
        assert_eq!(
            validate_edge_semantics(edge_id, &invalid)
                .unwrap_err()
                .reason_code,
            REASON_SCHEMA_INVALID
        );
    }

    #[test]
    fn oracle_request_envelope_rejects_duplicate_and_unknown_fields() {
        let duplicate: Value =
            serde_json::from_str(&run_oracle_json(
                r#"{"operation":"identity","operation":"identity"}"#,
            ))
            .unwrap();
        assert_eq!(duplicate.get("status").and_then(Value::as_str), Some("error"));

        for request in [
            json!({ "operation": "identity", "unknown": true }),
            json!({ "operation": "normalizeSelector", "selector": null, "polarity": "positive", "unknown": true }),
            json!({ "operation": "normalizeEffect", "effect": null, "unknown": true }),
            json!({ "operation": "match", "selector": null, "effect": null, "polarity": "positive", "sourceId": "test", "unknown": true }),
            json!({ "operation": "evaluateAlgorithm", "operationId": "match.equal/2", "selector": null, "occurrence": null, "polarity": "positive", "sourceId": "test", "unknown": true }),
            json!({ "operation": "decideStage", "stage": null, "policy": null, "unknown": true }),
        ] {
            let error = validate_oracle_request_envelope(&request).unwrap_err();
            assert!(error.message.contains("unknown oracle request field"));
        }
        assert!(validate_oracle_request_envelope(&json!({ "operation": "unknown" })).is_err());
    }

    #[test]
    fn every_generated_negative_schema_fixture_rejects() {
        let core = Rev2Core::embedded().unwrap();
        for fixture in &core
            .payload
            .policy_rules_and_classifiers
            .schema_fixture_vectors
        {
            let id = fixture.get("id").and_then(Value::as_str).unwrap();
            let schema_id = fixture.get("schemaId").and_then(Value::as_str).unwrap();
            let input = fixture.get("input").unwrap();
            let expected = fixture
                .pointer("/expected/valid")
                .and_then(Value::as_bool)
                .unwrap();
            if expected {
                // Stage C-01's positive schema examples are structural
                // placeholders (for example the literal string "example" in
                // a CIDR field). C-02 must not weaken the registered
                // canonicalizer to accept those placeholders as live values.
                continue;
            }
            let result = core.normalize_schema(schema_id, input);
            assert!(
                result.is_err(),
                "{id}: {}",
                result.as_ref().err().map(ToString::to_string).unwrap_or_default()
            );
        }
    }

    #[test]
    fn authority_selector_and_occurrence_are_separate_closed_domains() {
        let core = Rev2Core::embedded().unwrap();
        let principal = package("a");
        let selector = core
            .normalize_selector(&env_selector(principal, "TOKEN"), SelectorPolarity::Positive)
            .unwrap();
        let effect = core.normalize_effect(&env_effect("TOKEN")).unwrap();
        assert_eq!(selector.resource, json!({ "name": "TOKEN" }));
        assert_eq!(effect.occurrence["targetKind"], "broker");
        let mut malformed = env_effect("TOKEN");
        malformed.occurrence["selectorOnly"] = Value::Bool(true);
        assert_eq!(
            core.normalize_effect(&malformed).unwrap_err().reason_code,
            REASON_SCHEMA_INVALID
        );
    }

    #[test]
    fn principal_dimensions_intersect_and_record_exact_sources() {
        let core = Rev2Core::embedded().unwrap();
        let a = package("a");
        let b = package("b");
        let mut policy = policy(Mode::Enforce);
        policy.static_floor.push(named("a-row", env_selector(a.clone(), "TOKEN")));
        let denied = core
            .decide_stage(
                &stage("read", vec![a.clone(), b.clone()], vec![env_effect("TOKEN")]),
                &policy,
            )
            .unwrap();
        assert_eq!(denied.outcome, Outcome::Deny);
        policy.static_floor.push(named("b-row", env_selector(b.clone(), "TOKEN")));
        let allowed = core
            .decide_stage(&stage("read", vec![b, a], vec![env_effect("TOKEN")]), &policy)
            .unwrap();
        assert_eq!(allowed.outcome, Outcome::Allow);
        assert!(allowed.effects[0].dimensions.iter().all(|dimension| {
            dimension.stratum == 9
                && dimension
                    .positive_source
                    .as_ref()
                    .is_some_and(|source| source.source_id.starts_with("sha256-"))
        }));
    }

    #[test]
    fn canonical_static_source_digest_binds_full_principal_kind_and_key() {
        let core = Rev2Core::embedded().unwrap();
        let key = "shared-principal-key";
        let package_selector = core
            .normalize_selector(
                &env_selector(
                    PrincipalRef {
                        kind: PrincipalKind::Package,
                        key: key.to_string(),
                    },
                    "TOKEN",
                ),
                SelectorPolarity::Positive,
            )
            .unwrap();
        let root_selector = core
            .normalize_selector(
                &env_selector(
                    PrincipalRef {
                        kind: PrincipalKind::Root,
                        key: key.to_string(),
                    },
                    "TOKEN",
                ),
                SelectorPolarity::Positive,
            )
            .unwrap();
        assert_ne!(
            canonical_row_digest(&package_selector).unwrap(),
            canonical_row_digest(&root_selector).unwrap()
        );
    }

    #[test]
    fn missing_nouser_quarantine_and_deny_only_are_fail_closed() {
        let core = Rev2Core::embedded().unwrap();
        for principals in [
            vec![],
            vec![PrincipalRef {
                kind: PrincipalKind::NoUser,
                key: "no-user".to_string(),
            }],
        ] {
            let decision = core
                .decide_stage(&stage("missing", principals, vec![env_effect("TOKEN")]), &policy(Mode::Permissive))
                .unwrap();
            assert_eq!(decision.outcome, Outcome::Deny);
            assert_eq!(decision.effects[0].dimensions[0].stratum, 2);
        }
        let quarantine = PrincipalRef {
            kind: PrincipalKind::Quarantine,
            key: "quarantine:1".to_string(),
        };
        let denied = core
            .decide_stage(
                &stage("q", vec![quarantine.clone()], vec![env_effect("TOKEN")]),
                &policy(Mode::Permissive),
            )
            .unwrap();
        assert_eq!(denied.effects[0].dimensions[0].stratum, 14);
        let mut exact = policy(Mode::Enforce);
        exact
            .static_floor
            .push(named("q-row", env_selector(quarantine.clone(), "TOKEN")));
        assert_eq!(
            core.decide_stage(&stage("q", vec![quarantine], vec![env_effect("TOKEN")]), &exact)
                .unwrap()
                .outcome,
            Outcome::Allow
        );

        let cwd = EffectInput {
            identity: EngineIdentity::embedded(),
            edge_id: CWD_EDGE.to_string(),
            effect_slot_id: CWD_SLOT.to_string(),
            capability: "process:cwd".to_string(),
            effect_owner: "owner:pkg".to_string(),
            occurrence: json!({
                "effectOwner": "owner:pkg",
                "path": { "encoding": "unicode", "value": "/tmp" },
            }),
        };
        let closed = core
            .decide_stage(&stage("cwd", vec![package("a")], vec![cwd]), &policy(Mode::Permissive))
            .unwrap();
        assert_eq!(closed.effects[0].dimensions[0].stratum, 3);
    }

    #[test]
    fn negatives_precede_positives_and_masking_never_authorizes() {
        let core = Rev2Core::embedded().unwrap();
        let principal = package("a");
        let mut rules = policy(Mode::Enforce);
        rules.static_floor.push(named("allow", env_selector(principal.clone(), "TOKEN")));
        rules.process_denials.push(named(
            "ceiling",
            selector(None, "env:read", json!({ "name": "TOKEN" })),
        ));
        let denied = core
            .decide_stage(&stage("read", vec![principal.clone()], vec![env_effect("TOKEN")]), &rules)
            .unwrap();
        assert_eq!(denied.effects[0].dimensions[0].stratum, 5);

        rules.process_denials.clear();
        rules.session_revocations.push(named(
            "revoke",
            env_selector(principal.clone(), "TOKEN"),
        ));
        let revoked = core
            .decide_stage(&stage("read", vec![principal.clone()], vec![env_effect("TOKEN")]), &rules)
            .unwrap();
        assert_eq!(revoked.effects[0].dimensions[0].stratum, 7);

        let mut masked = policy(Mode::Enforce);
        masked.compatibility_dispositions.push(CompatibilityDispositionInput {
            disposition_id: "env:ignore".to_string(),
            source_id: "ignore-token".to_string(),
            selector: env_selector(principal.clone(), "TOKEN"),
        });
        let decision = core
            .decide_stage(&stage("read", vec![principal], vec![env_effect("TOKEN")]), &masked)
            .unwrap();
        assert_eq!(decision.outcome, Outcome::Masked);
        let dimension = &decision.effects[0].dimensions[0];
        assert_eq!(dimension.stratum, 15);
        assert_eq!(dimension.reason_code, REASON_ENV_MASKED);
        assert!(dimension.positive_source.is_none());
        assert!(decision.committed_effects.is_empty());

        let broker_enforce = core
            .decide_stage(
                &stage(
                    "broker-enforce",
                    vec![package("broker-enforce")],
                    vec![env_effect("TOKEN")],
                ),
                &policy(Mode::Enforce),
            )
            .unwrap();
        let dimension = &broker_enforce.effects[0].dimensions[0];
        assert_eq!(dimension.outcome, Outcome::Deny);
        assert_eq!(dimension.stratum, 16);
        assert_eq!(dimension.reason_code, REASON_MISSING_AUTHORITY);
        assert!(broker_enforce.committed_effects.is_empty());

        let broker_audit = core
            .decide_stage(
                &stage(
                    "broker-audit",
                    vec![package("broker-audit")],
                    vec![env_effect("TOKEN")],
                ),
                &policy(Mode::Audit),
            )
            .unwrap();
        let dimension = &broker_audit.effects[0].dimensions[0];
        assert_eq!(dimension.outcome, Outcome::Masked);
        assert_eq!(dimension.stratum, 16);
        assert_eq!(dimension.reason_code, REASON_ENV_MASKED);
        assert!(broker_audit.committed_effects.is_empty());
    }

    #[test]
    fn session_positive_must_remain_inside_the_armed_escalation_ceiling() {
        let core = Rev2Core::embedded().unwrap();
        let principal = package("session-ceiling");
        let request = stage("session", vec![principal.clone()], vec![env_effect("TOKEN")]);
        let mut rules = policy(Mode::Enforce);
        rules.session_grants.push(named(
            "session",
            env_selector(principal.clone(), "TOKEN"),
        ));
        assert_eq!(core.decide_stage(&request, &rules).unwrap().outcome, Outcome::Deny);
        rules.escalation_ceiling.push(named(
            "wrong-ceiling",
            env_selector(principal.clone(), "OTHER"),
        ));
        assert_eq!(core.decide_stage(&request, &rules).unwrap().outcome, Outcome::Deny);
        rules.escalation_ceiling[0].selector = env_selector(principal, "TOKEN");
        let allowed = core.decide_stage(&request, &rules).unwrap();
        assert_eq!(allowed.outcome, Outcome::Allow);
        assert_eq!(allowed.effects[0].dimensions[0].stratum, 11);
    }

    #[test]
    fn handle_and_ambient_root_sources_bind_their_exact_strata_and_context() {
        let core = Rev2Core::embedded().unwrap();
        let principal = package("handle-delegatee");
        let mut rules = policy(Mode::Enforce);
        rules.handles.push(HandleSelectorInput {
            handle_id: "handle:cpus".to_string(),
            handle_generation: "7".to_string(),
            armed_snapshot_digest: rules.provenance.armed_snapshot_digest.clone(),
            carrier_epoch: rules.channel_epoch.clone(),
            selector: selector(
                Some(principal.clone()),
                "sys:read",
                json!({ "kind": "cpus" }),
            ),
        });
        let request = stage(
            "handle",
            vec![principal.clone()],
            vec![sys_effect("cpus")],
        );
        let handled = core.decide_stage(&request, &rules).unwrap();
        let dimension = &handled.effects[0].dimensions[0];
        assert_eq!(dimension.stratum, 10);
        assert_eq!(dimension.reason_code, REASON_ALLOW);
        assert_eq!(
            dimension.positive_source,
            Some(PositiveSource {
                kind: "handle".to_string(),
                source_id: "handle:cpus".to_string(),
                generation: Some("7".to_string()),
            })
        );

        let mut wrong_delegatee = rules.clone();
        wrong_delegatee.handles[0].selector.principal = Some(package("other"));
        let denied = core.decide_stage(&request, &wrong_delegatee).unwrap();
        assert_eq!(denied.outcome, Outcome::Deny);
        assert!(denied.committed_effects.is_empty());

        let mut stale_carrier = rules.clone();
        stale_carrier.handles[0].carrier_epoch = "channel:stale".to_string();
        assert!(core.decide_stage(&request, &stale_carrier).is_err());

        let no_handle = policy(Mode::Enforce);
        let mut resources = TrackedProvisionalResources::default();
        let mut late_join = StagedOperation::new(
            &core,
            "operation:handle-late-join",
            captured_context(
                "actor:handle-late-join",
                vec![principal.clone()],
                "owner:pkg",
            ),
            &no_handle,
        )
        .unwrap();
        assert!(matches!(
            late_join
                .authorize_next(
                    &core,
                    &stage(
                        "handle-late-join",
                        vec![principal.clone()],
                        vec![sys_effect("cpus")],
                    ),
                    &rules,
                    &mut resources,
                    Interaction::NonInteractive,
                )
                .unwrap(),
            StageAuthorization::Denied { .. }
        ));

        let commit_request = stage(
            "handle-remove-before-commit",
            vec![principal.clone()],
            vec![sys_effect("cpus")],
        );
        let mut remove_before_commit = StagedOperation::new(
            &core,
            "operation:handle-remove-before-commit",
            captured_context(
                "actor:handle-remove-before-commit",
                vec![principal.clone()],
                "owner:pkg",
            ),
            &rules,
        )
        .unwrap();
        let StageAuthorization::Permit { permit } = remove_before_commit
            .authorize_next(
                &core,
                &commit_request,
                &rules,
                &mut resources,
                Interaction::NonInteractive,
            )
            .unwrap()
        else {
            panic!("captured handle must authorize before removal");
        };
        assert!(matches!(
            remove_before_commit
                .commit(&core, permit, &commit_request, &no_handle, &mut resources)
                .unwrap(),
            CommitResult::Denied { .. }
        ));

        let mut remove_before_next = StagedOperation::new(
            &core,
            "operation:handle-remove-before-next",
            captured_context(
                "actor:handle-remove-before-next",
                vec![principal.clone()],
                "owner:pkg",
            ),
            &rules,
        )
        .unwrap();
        let first = stage(
            "handle-first",
            vec![principal.clone()],
            vec![sys_effect("cpus")],
        );
        let StageAuthorization::Permit { permit } = remove_before_next
            .authorize_next(
                &core,
                &first,
                &rules,
                &mut resources,
                Interaction::NonInteractive,
            )
            .unwrap()
        else {
            panic!("captured handle must authorize its first stage");
        };
        assert!(matches!(
            remove_before_next
                .commit(&core, permit, &first, &rules, &mut resources)
                .unwrap(),
            CommitResult::Committed { .. }
        ));
        assert!(matches!(
            remove_before_next
                .authorize_next(
                    &core,
                    &stage(
                        "handle-after-removal",
                        vec![principal.clone()],
                        vec![sys_effect("cpus")],
                    ),
                    &no_handle,
                    &mut resources,
                    Interaction::NonInteractive,
                )
                .unwrap(),
            StageAuthorization::Denied { .. }
        ));

        let ambient = core
            .decide_stage(
                &stage("ambient-root", vec![root()], vec![sys_effect("cpus")]),
                &policy(Mode::Enforce),
            )
            .unwrap();
        let dimension = &ambient.effects[0].dimensions[0];
        assert_eq!(dimension.stratum, 13);
        assert_eq!(dimension.reason_code, REASON_ALLOW);
        assert_eq!(
            dimension.positive_source,
            Some(PositiveSource {
                kind: "ambient-root".to_string(),
                source_id: "ambient-root:root:sha256-project".to_string(),
                generation: Some("1".to_string()),
            })
        );
    }

    #[test]
    fn positive_predicate_precedes_root_ambient_authority() {
        let core = Rev2Core::embedded().unwrap();
        let root = root();
        let effect = inspector_effect(INSPECT_EDGE, INSPECT_SLOT);
        let selector = inspector_selector(root.clone());
        let request = stage("inspect", vec![root.clone()], vec![effect.clone()]);
        let missing = core.decide_stage(&request, &policy(Mode::Permissive)).unwrap();
        assert_eq!(missing.effects[0].dimensions[0].stratum, 8);
        let mut exact = policy(Mode::Enforce);
        exact.static_floor.push(named("root-inspector", selector));
        let allowed = core.decide_stage(&request, &exact).unwrap();
        assert_eq!(allowed.outcome, Outcome::Allow);
        assert_eq!(allowed.effects[0].dimensions[0].stratum, 8);
    }

    #[test]
    fn conjunctive_edge_requires_every_generated_slot_before_authorization() {
        let core = Rev2Core::embedded().unwrap();
        let root = root();
        let inspector = inspector_effect(INSPECT_MULTI_EDGE, INSPECT_MULTI_SLOT);
        let listener = inspector_listener_effect();
        let mut exact = policy(Mode::Enforce);
        exact.static_floor.push(named(
            "root-inspector",
            inspector_selector(root.clone()),
        ));
        exact.static_floor.push(named(
            "root-listener",
            inspector_listener_selector(root.clone()),
        ));

        let complete = core
            .decide_stage(
                &stage(
                    "inspect-complete",
                    vec![root.clone()],
                    vec![inspector.clone(), listener],
                ),
                &exact,
            )
            .unwrap();
        assert_eq!(complete.outcome, Outcome::Allow);
        assert_eq!(complete.effects.len(), 2);

        let incomplete = core.decide_stage(
            &stage("inspect-incomplete", vec![root], vec![inspector]),
            &exact,
        );
        assert_eq!(
            incomplete.unwrap_err().reason_code,
            REASON_EDGE_SET_INVALID
        );
    }

    #[test]
    fn alternative_edge_selects_exactly_one_stable_branch() {
        let core = Rev2Core::embedded().unwrap();
        let root = root();
        for (stage_id, effect) in [
            ("alternative-connect", alternative_connect_effect()),
            ("alternative-listen", alternative_listen_effect()),
        ] {
            let decision = core
                .decide_stage(
                    &stage(stage_id, vec![root.clone()], vec![effect]),
                    &policy(Mode::Enforce),
                )
                .unwrap();
            assert_eq!(decision.outcome, Outcome::Allow);
            assert_eq!(decision.committed_effects.len(), 1);
        }

        let two_branches = core.decide_stage(
            &stage(
                "alternative-two-branches",
                vec![root],
                vec![alternative_connect_effect(), alternative_listen_effect()],
            ),
            &policy(Mode::Enforce),
        );
        assert_eq!(
            two_branches.unwrap_err().reason_code,
            REASON_EDGE_SET_INVALID
        );
    }

    #[test]
    fn protected_exception_is_a_negative_only_continuation() {
        let core = Rev2Core::embedded().unwrap();
        let principal = package("metadata-client");
        let authority = fetch_selector(principal.clone(), "169.254.169.254", "metadata");
        let request = stage(
            "metadata",
            vec![principal.clone()],
            vec![fetch_effect("169.254.169.254")],
        );

        let mut static_only = policy(Mode::Enforce);
        static_only.static_floor.push(named("metadata-row", authority.clone()));
        let guarded = core.decide_stage(&request, &static_only).unwrap();
        assert_eq!(guarded.effects[0].dimensions[0].stratum, 4);

        let mut exception_only = policy(Mode::Enforce);
        exception_only.protected_exceptions.push(ProtectedExceptionInput {
            source_id: "metadata-exception".to_string(),
            reason: "instance role".to_string(),
            selector: authority.clone(),
        });
        let still_ungranted = core.decide_stage(&request, &exception_only).unwrap();
        assert_eq!(still_ungranted.effects[0].dimensions[0].stratum, 4);

        let mut broad_floor = exception_only.clone();
        broad_floor.static_floor.push(named(
            "metadata-broad",
            selector(
                Some(principal.clone()),
                "network:fetch",
                json!({
                    "host": { "kind": "cidr", "value": "169.254.0.0/16" },
                    "peerClasses": ["metadata"],
                    "port": { "kind": "any" },
                    "route": { "attestation": null, "endpoint": null, "kind": "direct" },
                    "schemes": ["http", "https"],
                }),
            ),
        ));
        let broad_refused = core.decide_stage(&request, &broad_floor).unwrap();
        assert_eq!(broad_refused.outcome, Outcome::Deny);
        assert_eq!(broad_refused.effects[0].dimensions[0].stratum, 4);

        let dns_authority = fetch_host_selector(
            Some(principal.clone()),
            "dns-exact",
            "evil.example",
            "metadata",
        );
        let mut dns_exception = policy(Mode::Enforce);
        dns_exception.static_floor.push(named("dns-static", dns_authority.clone()));
        dns_exception.protected_exceptions.push(ProtectedExceptionInput {
            source_id: "dns-exception".to_string(),
            reason: "must never clear metadata by DNS".to_string(),
            selector: dns_authority,
        });
        let dns_refused = core
            .decide_stage(
                &stage(
                    "metadata-dns",
                    vec![principal.clone()],
                    vec![fetch_dns_effect("evil.example", "169.254.169.254")],
                ),
                &dns_exception,
            )
            .unwrap();
        assert_eq!(dns_refused.outcome, Outcome::Deny);
        assert_eq!(dns_refused.effects[0].dimensions[0].stratum, 4);

        exception_only
            .static_floor
            .push(named("metadata-row", authority.clone()));
        exception_only.principal_denials.push(named(
            "specific-denial",
            authority,
        ));
        let denied_after_exception = core.decide_stage(&request, &exception_only).unwrap();
        assert_eq!(denied_after_exception.effects[0].dimensions[0].stratum, 6);
    }

    #[test]
    fn path_authority_requires_host_bound_object_identity() {
        let core = Rev2Core::embedded().unwrap();
        let principal = package("reader");
        let authority = path_selector(principal.clone(), "/project/data");
        let canonical = core
            .normalize_selector(&authority, SelectorPolarity::Positive)
            .unwrap();
        let source_id = canonical_row_digest(&canonical).unwrap();
        let request = stage(
            "path",
            vec![principal.clone()],
            vec![path_effect("/project/data/file.txt", "file:1")],
        );
        let mut unbound = policy(Mode::Enforce);
        unbound.static_floor.push(named("path-row", authority.clone()));
        assert_eq!(core.decide_stage(&request, &unbound).unwrap().outcome, Outcome::Deny);

        let mut bound = unbound.clone();
        bound.path_bindings.push(PathBindingInput {
            source_id,
            root_binding_id: "root-binding:1".to_string(),
            final_object_identities: vec![json!({
                "kind": "platform-object",
                "value": "file:1",
            })],
            parent_identities: vec![],
        });
        assert_eq!(core.decide_stage(&request, &bound).unwrap().outcome, Outcome::Allow);
        let alias = stage(
            "alias",
            vec![principal],
            vec![path_effect("/project/data/file.txt", "protected:file")],
        );
        assert_eq!(core.decide_stage(&alias, &bound).unwrap().outcome, Outcome::Deny);
    }

    #[test]
    fn negative_path_binding_follows_the_same_object_through_an_alias() {
        let core = Rev2Core::embedded().unwrap();
        let principal = package("alias-reader");
        let positive = path_selector(principal.clone(), "/project");
        let positive_id = canonical_row_digest(
            &core
                .normalize_selector(&positive, SelectorPolarity::Positive)
                .unwrap(),
        )
        .unwrap();
        let mut rules = policy(Mode::Enforce);
        rules.static_floor.push(named("positive", positive));
        rules.process_denials.push(named(
            "deny-object",
            selector(
                None,
                "fs:read",
                json!({
                    "kind": "path-exact",
                    "path": { "encoding": "unicode", "value": "/project/secret" },
                    "root": "$PROJECT",
                }),
            ),
        ));
        for source_id in [positive_id, "deny-object".to_string()] {
            rules.path_bindings.push(PathBindingInput {
                source_id,
                root_binding_id: "root-binding:1".to_string(),
                final_object_identities: vec![json!({
                    "kind": "platform-object",
                    "value": "file:secret",
                })],
                parent_identities: vec![],
            });
        }
        let decision = core
            .decide_stage(
                &stage(
                    "alias",
                    vec![principal],
                    vec![path_effect("/project/allowed", "file:secret")],
                ),
                &rules,
            )
            .unwrap();
        assert_eq!(decision.outcome, Outcome::Deny);
        assert_eq!(decision.effects[0].dimensions[0].stratum, 5);
    }

    #[test]
    fn implicit_package_self_is_exact_verified_loader_payload_only() {
        let core = Rev2Core::embedded().unwrap();
        let principal = package("implicit");
        let path = "/package/mod.ts";
        let mut rules = policy(Mode::Enforce);
        rules.implicit_self.push(named(
            "implicit:payload",
            implicit_package_selector(principal.clone(), "$PACKAGE", path),
        ));
        rules.path_bindings.push(PathBindingInput {
            source_id: "implicit:payload".to_string(),
            root_binding_id: "root-binding:package".to_string(),
            final_object_identities: vec![json!({
                "kind": "platform-object",
                "value": "file:verified-package",
            })],
            parent_identities: vec![],
        });
        let request = stage(
            "implicit",
            vec![principal.clone()],
            vec![loader_path_effect(path, "file:verified-package", "existing")],
        );
        let allowed = core.decide_stage(&request, &rules).unwrap();
        assert_eq!(allowed.outcome, Outcome::Allow);
        assert_eq!(allowed.effects[0].dimensions[0].stratum, 12);

        let mut wrong_root = rules.clone();
        wrong_root.implicit_self[0].selector =
            implicit_package_selector(principal.clone(), "$PROJECT", path);
        assert_eq!(
            core.decide_stage(&request, &wrong_root).unwrap().outcome,
            Outcome::Deny
        );

        let symlink = stage(
            "implicit-link",
            vec![principal],
            vec![loader_path_effect(path, "file:verified-package", "link-entry")],
        );
        assert!(core.decide_stage(&symlink, &rules).is_err());

        let mut no_follow_link = loader_path_effect(path, "file:verified-package", "link-entry");
        no_follow_link.occurrence["followMode"] = Value::String("no-follow-final".to_string());
        let canonical = core.normalize_effect(&no_follow_link).unwrap();
        assert_eq!(canonical.occurrence["followMode"], "no-follow-final");
        assert_eq!(canonical.occurrence["finalObjectState"]["kind"], "link-entry");
    }

    #[test]
    fn network_peer_class_and_ipv4_mapped_identity_are_data_driven() {
        let core = Rev2Core::embedded().unwrap();
        let principal = package("net");
        let mut public = policy(Mode::Enforce);
        public.static_floor.push(named(
            "public",
            fetch_selector(principal.clone(), "8.8.8.8", "public"),
        ));
        assert_eq!(
            core.decide_stage(
                &stage("public", vec![principal.clone()], vec![fetch_effect("8.8.8.8")]),
                &public,
            )
            .unwrap()
            .outcome,
            Outcome::Allow
        );
        assert_eq!(
            core.decide_stage(
                &stage("private", vec![principal.clone()], vec![fetch_effect("10.0.0.1")]),
                &public,
            )
            .unwrap()
            .outcome,
            Outcome::Deny
        );

        let mut cidr = policy(Mode::Enforce);
        cidr.static_floor.push(named(
            "private-cidr",
            fetch_host_selector(
                Some(principal.clone()),
                "cidr",
                "10.0.0.0/8",
                "private",
            ),
        ));
        assert_eq!(
            core.decide_stage(
                &stage(
                    "positive-cidr",
                    vec![principal.clone()],
                    vec![fetch_effect("10.2.3.4")],
                ),
                &cidr,
            )
            .unwrap()
            .outcome,
            Outcome::Allow
        );
        assert!(core
            .evaluate_match(
                "peer-class-conjunction",
                &json!(["non-ip"]),
                &json!({ "verifiedPeer": { "kind": "vsock", "value": "3:1024" } }),
                SelectorPolarity::Positive,
                "source:non-ip",
                &[],
            )
            .unwrap());

        let mut mapped = policy(Mode::Enforce);
        mapped.static_floor.push(named(
            "mapped",
            fetch_selector(principal.clone(), "192.168.1.1", "private"),
        ));
        assert_eq!(
            core.decide_stage(
                &stage(
                    "mapped",
                    vec![principal],
                    vec![fetch_effect("::ffff:192.168.1.1")],
                ),
                &mapped,
            )
            .unwrap()
            .outcome,
            Outcome::Allow
        );
    }

    #[test]
    fn canonicalization_branch_vectors_cover_opaque_paths_ports_and_dns_occurrences() {
        let core = Rev2Core::embedded().unwrap();
        let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let parent_path = engine.encode(b"/project/data");
        let child_path = engine.encode(b"/project/data/file");
        let principal = package("opaque-path");
        let authority = selector(
            Some(principal),
            "fs:read",
            json!({
                "kind": "path-tree",
                "path": { "encoding": "opaque-base64url", "value": parent_path },
                "root": "$PROJECT",
            }),
        );
        let parent_identity = json!({
            "kind": "platform-object",
            "value": "dir:opaque-parent",
        });
        let binding = PathBindingInput {
            source_id: "source:opaque-parent".to_string(),
            root_binding_id: "root-binding:1".to_string(),
            final_object_identities: vec![],
            parent_identities: vec![parent_identity.clone()],
        };
        for state_kind in ["missing", "proposed"] {
            let mut effect = path_effect("/unused", "unused");
            effect.occurrence["lexicalPath"] = json!({
                "encoding": "opaque-base64url",
                "value": child_path,
            });
            effect.occurrence["finalObjectState"] = json!({ "kind": state_kind });
            effect.occurrence["parentIdentity"] = parent_identity.clone();
            assert!(core
                .selector_matches_effect(
                    &authority,
                    &effect,
                    SelectorPolarity::Positive,
                    "source:opaque-parent",
                    std::slice::from_ref(&binding),
                )
                .unwrap());
        }

        for port in [
            json!({ "kind": "any" }),
            json!({ "kind": "range", "minimum": 8000, "maximum": 9000 }),
        ] {
            assert_eq!(
                core.normalize_schema("value.port-selector/2", &port).unwrap(),
                port
            );
        }
        assert!(core
            .normalize_schema(
                "occurrence.dns-query/2",
                &json!({
                    "absoluteName": "*.example.com",
                    "effectOwner": "owner:pkg",
                    "recordTypes": ["A"],
                    "route": { "attestation": null, "endpoint": null, "kind": "direct" },
                }),
            )
            .is_err());
        assert!(canonical_cidr("::ffff:0:0/95").is_err());
    }

    #[test]
    fn deny_only_gate_closes_an_authorable_definition_in_every_mode() {
        let core = Rev2Core::embedded().unwrap();
        let principal = package("deny-only");
        let mut effect = fetch_effect("8.8.8.8");
        effect.edge_id = DENY_ONLY_FETCH_EDGE.to_string();
        effect.effect_slot_id = DENY_ONLY_FETCH_SLOT.to_string();
        for mode in [Mode::Enforce, Mode::Audit, Mode::Permissive] {
            let mut rules = policy(mode);
            rules.static_floor.push(named(
                "would-otherwise-allow",
                fetch_selector(principal.clone(), "8.8.8.8", "public"),
            ));
            let decision = core
                .decide_stage(
                    &stage("deny-only", vec![principal.clone()], vec![effect.clone()]),
                    &rules,
                )
                .unwrap();
            assert_eq!(decision.outcome, Outcome::Deny);
            assert_eq!(decision.effects[0].dimensions[0].stratum, 3);
        }
    }

    #[test]
    fn dns_grant_never_bypasses_final_peer_ip_or_cidr_denials() {
        let core = Rev2Core::embedded().unwrap();
        let principal = package("dns");
        for (denied_kind, denied_value, peer) in [
            ("ip-exact", "10.1.2.3", "10.1.2.3"),
            ("cidr", "10.0.0.0/8", "10.1.2.3"),
            ("cidr", "10.0.0.0/8", "::ffff:10.1.2.3"),
            ("cidr", "::ffff:10.0.0.0/104", "::ffff:10.1.2.3"),
        ] {
            let mut rules = policy(Mode::Enforce);
            rules.static_floor.push(named(
                "dns-allow",
                fetch_host_selector(
                    Some(principal.clone()),
                    "dns-exact",
                    "api.example.com",
                    "private",
                ),
            ));
            rules.process_denials.push(named(
                "peer-denial",
                fetch_host_selector(None, denied_kind, denied_value, "private"),
            ));
            let denied = core
                .decide_stage(
                    &stage(
                        "dns-final-peer",
                        vec![principal.clone()],
                        vec![fetch_dns_effect("api.example.com", peer)],
                    ),
                    &rules,
                )
                .unwrap();
            assert_eq!(denied.outcome, Outcome::Deny);
            assert_eq!(denied.effects[0].dimensions[0].stratum, 5);
        }
        let mapped = core
            .normalize_selector(
                &fetch_host_selector(
                    None,
                    "cidr",
                    "::ffff:10.0.0.0/104",
                    "private",
                ),
                SelectorPolarity::Negative,
            )
            .unwrap();
        assert_eq!(mapped.resource["host"]["value"], "10.0.0.0/8");
    }

    #[test]
    fn one_stage_cannot_mix_unrelated_coverage_edge_invocations() {
        let core = Rev2Core::embedded().unwrap();
        let principal = package("atomic");
        let mut policy = policy(Mode::Enforce);
        policy.static_floor.push(named(
            "env-only",
            env_selector(principal.clone(), "TOKEN"),
        ));
        let request = stage(
            "atomic",
            vec![principal.clone()],
            vec![env_effect("TOKEN"), sys_effect("cpus")],
        );
        assert_eq!(
            core.decide_stage(&request, &policy).unwrap_err().reason_code,
            REASON_EDGE_SET_INVALID
        );

        let mut operation = StagedOperation::new(
            &core,
            "operation:atomic",
            captured_context("actor:atomic", vec![principal], "owner:pkg"),
            &policy,
        )
        .unwrap();
        let mut resources = TrackedProvisionalResources::default();
        resources.hold("reservation:atomic").unwrap();
        let authorization = operation
            .authorize_next(
                &core,
                &request,
                &policy,
                &mut resources,
                Interaction::NonInteractive,
            )
            .unwrap();
        assert!(matches!(authorization, StageAuthorization::Denied { .. }));
        assert_eq!(resources.released(), ["reservation:atomic"]);
    }

    #[test]
    fn masked_child_exports_use_repeatable_slots_and_commit_a_reduced_set() {
        let core = Rev2Core::embedded().unwrap();
        let principal = package("spawn");
        let optional_a = child_env_read_effect("OPTIONAL_A", false);
        let optional_b = child_env_read_effect("OPTIONAL_B", false);
        let literal = child_env_write_effect("LITERAL");
        let mut rules = policy(Mode::Enforce);
        rules
            .static_floor
            .push(named("spawn", spawn_selector(principal.clone())));
        rules.static_floor.push(named(
            "literal",
            child_env_write_selector(principal.clone(), "LITERAL"),
        ));
        rules
            .static_floor
            .push(named("post", env_selector(principal.clone(), "POST")));
        for (source_id, name) in [("mask-a", "OPTIONAL_A"), ("mask-b", "OPTIONAL_B")] {
            rules.compatibility_dispositions.push(CompatibilityDispositionInput {
                disposition_id: "env:ignore".to_string(),
                source_id: source_id.to_string(),
                selector: env_selector(principal.clone(), name),
            });
        }
        let request = stage(
            "spawn-optional",
            vec![principal.clone()],
            vec![
                spawn_effect(),
                optional_b.clone(),
                literal.clone(),
                optional_a.clone(),
            ],
        );
        let no_exports = core
            .decide_stage(
                &stage("spawn-empty", vec![principal.clone()], vec![spawn_effect()]),
                &rules,
            )
            .unwrap();
        assert_eq!(no_exports.outcome, Outcome::Allow);
        let decision = core.decide_stage(&request, &rules).unwrap();
        assert_eq!(decision.outcome, Outcome::Allow);
        assert_eq!(decision.committed_effects.len(), 2);
        assert!(decision
            .committed_effects
            .iter()
            .any(|effect| effect.capability == "process:spawn"));
        assert!(decision
            .committed_effects
            .iter()
            .any(|effect| effect.capability == "env:write"));
        assert_eq!(decision.omitted_effects.len(), 2);
        assert_eq!(
            decision
                .omitted_effects
                .iter()
                .map(|omission| omission.effect.occurrence["name"].as_str().unwrap())
                .collect::<Vec<_>>(),
            ["OPTIONAL_A", "OPTIONAL_B"]
        );

        let make_context = |actor_id: &str| {
            CapturedOperationContext::capture_host(
                actor_id,
                EngineIdentity::embedded(),
                vec![principal.clone()],
                "owner:pkg",
                principal.clone(),
                "0",
                vec![
                    SealedChildExportFact::capture_host(optional_a.clone()),
                    SealedChildExportFact::capture_host(optional_b.clone()),
                    SealedChildExportFact::capture_host(literal.clone()),
                ],
                Some(SPAWN_EDGE.to_string()),
            )
            .unwrap()
        };
        let mut operation = StagedOperation::new(
            &core,
            "operation:spawn",
            make_context("actor:spawn"),
            &rules,
        )
        .unwrap();
        let mut resources = TrackedProvisionalResources::default();
        let StageAuthorization::Permit { permit } = operation
            .authorize_next(
                &core,
                &request,
                &rules,
                &mut resources,
                Interaction::NonInteractive,
            )
            .unwrap()
        else {
            panic!("optional masks must return a reduced commit permit");
        };
        assert_eq!(permit.decision().omitted_effects.len(), 2);
        assert!(matches!(
            operation
                .commit(&core, permit, &request, &rules, &mut resources)
                .unwrap(),
            CommitResult::Committed { .. }
        ));

        let post = stage(
            "post-launch",
            vec![principal.clone()],
            vec![env_effect("POST")],
        );
        let StageAuthorization::Permit { permit } = operation
            .authorize_next(
                &core,
                &post,
                &rules,
                &mut resources,
                Interaction::NonInteractive,
            )
            .unwrap()
        else {
            panic!("a nonrepeatable post-launch stage should authorize");
        };
        assert!(matches!(
            operation
                .commit(&core, permit, &post, &rules, &mut resources)
                .unwrap(),
            CommitResult::Committed { .. }
        ));

        assert!(matches!(
            operation
                .authorize_next(
                    &core,
                    &stage("second-launch", vec![principal.clone()], vec![spawn_effect()]),
                    &rules,
                    &mut resources,
                    Interaction::NonInteractive,
                )
                .unwrap(),
            StageAuthorization::Denied { .. }
        ));

        let required = stage(
            "spawn-required",
            vec![principal.clone()],
            vec![spawn_effect(), child_env_read_effect("OPTIONAL_A", true)],
        );
        let required_decision = core.decide_stage(&required, &rules).unwrap();
        assert_eq!(required_decision.outcome, Outcome::Deny);
        assert!(required_decision.committed_effects.is_empty());

        let mut mixed_rules = policy(Mode::Enforce);
        mixed_rules
            .static_floor
            .push(named("spawn", spawn_selector(principal.clone())));
        let mixed = core
            .decide_stage(
                &stage(
                    "spawn-mixed-allow-deny",
                    vec![principal.clone()],
                    vec![spawn_effect(), literal.clone()],
                ),
                &mixed_rules,
            )
            .unwrap();
        assert_eq!(mixed.outcome, Outcome::Deny);
        assert!(mixed
            .effects
            .iter()
            .any(|effect| effect.outcome == Outcome::Allow));
        assert!(mixed
            .effects
            .iter()
            .any(|effect| effect.outcome == Outcome::Deny));
        assert!(mixed.committed_effects.is_empty());

        let mut prelaunch = StagedOperation::new(
            &core,
            "operation:prelaunch-switch",
            make_context("actor:prelaunch-switch"),
            &rules,
        )
        .unwrap();
        assert!(matches!(
            prelaunch
                .authorize_next(
                    &core,
                    &stage(
                        "prelaunch-switch",
                        vec![principal.clone()],
                        vec![env_effect("POST")],
                    ),
                    &rules,
                    &mut resources,
                    Interaction::NonInteractive,
                )
                .unwrap(),
            StageAuthorization::Denied { .. }
        ));

        for (case, effects) in [
            (
                "missing-write",
                vec![spawn_effect(), optional_a.clone(), optional_b.clone()],
            ),
            (
                "substituted-write",
                vec![
                    spawn_effect(),
                    optional_a.clone(),
                    optional_b.clone(),
                    child_env_write_effect("OTHER"),
                ],
            ),
            (
                "extra-write",
                vec![
                    spawn_effect(),
                    optional_a.clone(),
                    optional_b.clone(),
                    literal.clone(),
                    child_env_write_effect("EXTRA"),
                ],
            ),
        ] {
            let mut sealed_operation = StagedOperation::new(
                &core,
                format!("operation:{case}"),
                make_context(&format!("actor:{case}")),
                &rules,
            )
            .unwrap();
            assert!(matches!(
                sealed_operation
                    .authorize_next(
                        &core,
                        &stage(case, vec![principal.clone()], effects),
                        &rules,
                        &mut resources,
                        Interaction::NonInteractive,
                    )
                    .unwrap(),
                StageAuthorization::Denied { .. }
            ));
        }

        let duplicate = core.decide_stage(
            &stage(
                "spawn-duplicate",
                vec![principal.clone()],
                vec![spawn_effect(), optional_a.clone(), optional_a],
            ),
            &rules,
        );
        assert_eq!(duplicate.unwrap_err().reason_code, REASON_DUPLICATE_EFFECT);

        let mut second_spawn = spawn_effect();
        second_spawn.occurrence["objectIdentity"]["value"] = Value::String("exe:other".to_string());
        second_spawn.occurrence["requestedPath"]["value"] =
            Value::String("/bin/other".to_string());
        second_spawn.occurrence["launchSet"][0]["value"] =
            Value::String("/bin/other".to_string());
        let duplicate_fixed_slot = core.decide_stage(
            &stage(
                "spawn-two-fixed",
                vec![package("spawn")],
                vec![spawn_effect(), second_spawn],
            ),
            &rules,
        );
        assert_eq!(
            duplicate_fixed_slot.unwrap_err().reason_code,
            REASON_EDGE_SET_INVALID
        );
    }

    #[test]
    fn mixed_vocabulary_and_duplicate_effects_refuse_the_complete_stage() {
        let core = Rev2Core::embedded().unwrap();
        let principal = package("a");
        let effect = env_effect("TOKEN");
        let duplicate = core.decide_stage(
            &stage("dup", vec![principal.clone()], vec![effect.clone(), effect]),
            &policy(Mode::Enforce),
        );
        assert_eq!(duplicate.unwrap_err().reason_code, REASON_DUPLICATE_EFFECT);

        let mut mixed = policy(Mode::Enforce);
        let mut row = env_selector(principal.clone(), "TOKEN");
        row.identity.vocab_digest = "sha256-n-minus-one".to_string();
        mixed.static_floor.push(named("mixed", row));
        assert_eq!(
            core.decide_stage(&stage("mixed", vec![principal], vec![env_effect("TOKEN")]), &mixed)
                .unwrap_err()
                .reason_code,
            REASON_VOCAB_MISMATCH
        );
    }

    #[test]
    fn decision_bounds_refuse_oversized_identity_and_cartesian_work_preallocation() {
        let core = Rev2Core::embedded().unwrap();
        let boundary = PrincipalRef {
            kind: PrincipalKind::Package,
            key: "k".repeat(1024),
        };
        assert!(core
            .decide_stage(
                &stage("boundary", vec![boundary], vec![env_effect("TOKEN")]),
                &policy(Mode::Enforce),
            )
            .is_ok());
        let oversized = PrincipalRef {
            kind: PrincipalKind::Package,
            key: "k".repeat(1025),
        };
        assert_eq!(
            core.decide_stage(
                &stage("oversized", vec![oversized], vec![env_effect("TOKEN")]),
                &policy(Mode::Enforce),
            )
            .unwrap_err()
            .reason_code,
            REASON_SCHEMA_INVALID
        );
        let principals = (0..64)
            .map(|index| package(&format!("cell-{index}")))
            .collect();
        let effects = (0..257).map(|_| env_effect("TOKEN")).collect();
        assert_eq!(
            core.decide_stage(
                &stage("cartesian", principals, effects),
                &policy(Mode::Enforce),
            )
            .unwrap_err()
            .reason_code,
            REASON_SCHEMA_INVALID
        );
    }

    #[test]
    fn later_denial_releases_provisional_state_once_and_names_completed_stages() {
        let core = Rev2Core::embedded().unwrap();
        let principal = package("a");
        let mut policy = policy(Mode::Enforce);
        policy.static_floor.push(named("allow", env_selector(principal.clone(), "TOKEN")));
        let mut operation = StagedOperation::new(
            &core,
            "operation:1",
            captured_context("actor:1", vec![principal.clone()], "owner:pkg"),
            &policy,
        )
        .unwrap();
        let mut resources = TrackedProvisionalResources::default();
        let discover = stage("discover", vec![principal.clone()], vec![env_effect("TOKEN")]);
        let StageAuthorization::Permit { permit } = operation
            .authorize_next(
                &core,
                &discover,
                &policy,
                &mut resources,
                Interaction::NonInteractive,
            )
            .unwrap()
        else {
            panic!("discovery should receive a permit");
        };
        assert!(matches!(
            operation
                .commit(&core, permit, &discover, &policy, &mut resources)
                .unwrap(),
            CommitResult::Committed { .. }
        ));
        resources.hold("socket:provisional").unwrap();
        let denied = operation
            .authorize_next(
                &core,
                &stage("redirect", vec![principal.clone()], vec![env_effect("OTHER")]),
                &policy,
                &mut resources,
                Interaction::NonInteractive,
            )
            .unwrap();
        let StageAuthorization::Denied { denial } = denied else {
            panic!("later stage must deny");
        };
        assert_eq!(denial.completed_discovery_stages, ["discover"]);
        assert_eq!(denial.released_provisional_resources, ["socket:provisional"]);
        let repeated = operation
            .authorize_next(
                &core,
                &stage("redirect", vec![principal], vec![env_effect("OTHER")]),
                &policy,
                &mut resources,
                Interaction::NonInteractive,
            )
            .unwrap();
        assert!(matches!(
            repeated,
            StageAuthorization::AlreadyDenied { .. }
        ));
        assert_eq!(resources.released(), ["socket:provisional"]);
    }

    #[test]
    fn invalid_barrier_emits_terminal_evidence_only_once() {
        let core = Rev2Core::embedded().unwrap();
        let principal = package("barrier");
        let rules = policy(Mode::Enforce);
        let mut operation = StagedOperation::new(
            &core,
            "operation:barrier",
            captured_context("actor:barrier", vec![principal.clone()], "owner:pkg"),
            &rules,
        )
        .unwrap();
        let mut invalid = env_effect("TOKEN");
        invalid.edge_id = "unknown-edge:barrier".to_string();
        let request = stage("barrier", vec![principal], vec![invalid]);
        let mut resources = TrackedProvisionalResources::default();
        resources.hold("barrier:held").unwrap();
        assert!(matches!(
            operation
                .authorize_at_barrier(
                    &core,
                    OperationBarrier::RevocationBeforeNextEffectOrDelivery,
                    &request,
                    &rules,
                    &mut resources,
                    Interaction::NonInteractive,
                )
                .unwrap(),
            StageAuthorization::Denied { .. }
        ));
        assert!(matches!(
            operation
                .authorize_at_barrier(
                    &core,
                    OperationBarrier::RevocationBeforeNextEffectOrDelivery,
                    &request,
                    &rules,
                    &mut resources,
                    Interaction::NonInteractive,
                )
                .unwrap(),
            StageAuthorization::AlreadyDenied { .. }
        ));
        assert_eq!(resources.released(), ["barrier:held"]);
    }

    #[test]
    fn staged_operation_freezes_positive_scope_generation_and_source_binding() {
        let core = Rev2Core::embedded().unwrap();
        let principal = package("staged");

        let mut original = policy(Mode::Enforce);
        original.session_grants.push(named(
            "session:stable",
            env_selector(principal.clone(), "TOKEN"),
        ));
        original.escalation_ceiling.push(named(
            "ceiling:stable",
            env_selector(principal.clone(), "TOKEN"),
        ));
        let mut widened_operation = StagedOperation::new(
            &core,
            "operation:widened",
            captured_context("actor:widened", vec![principal.clone()], "owner:pkg"),
            &original,
        )
        .unwrap();
        let mut resources = TrackedProvisionalResources::default();
        let mut widened = original.clone();
        widened.session_grants[0].selector = env_selector(principal.clone(), "OTHER");
        let widened_result = widened_operation
            .authorize_next(
                &core,
                &stage("widened", vec![principal.clone()], vec![env_effect("OTHER")]),
                &widened,
                &mut resources,
                Interaction::NonInteractive,
            )
            .unwrap();
        assert!(matches!(widened_result, StageAuthorization::Denied { .. }));

        let mut generation_operation = StagedOperation::new(
            &core,
            "operation:generation",
            captured_context("actor:generation", vec![principal.clone()], "owner:pkg"),
            &original,
        )
        .unwrap();
        let mut next_generation = original.clone();
        next_generation.generations.session_overlay = "1".to_string();
        let generation_result = generation_operation
            .authorize_next(
                &core,
                &stage(
                    "generation",
                    vec![principal.clone()],
                    vec![env_effect("TOKEN")],
                ),
                &next_generation,
                &mut resources,
                Interaction::NonInteractive,
            )
            .unwrap();
        assert!(matches!(generation_result, StageAuthorization::Denied { .. }));

        let mut substitutable = policy(Mode::Enforce);
        substitutable.session_grants.extend([
            named("a:first", env_selector(principal.clone(), "TOKEN")),
            named("b:second", env_selector(principal.clone(), "TOKEN")),
        ]);
        substitutable.escalation_ceiling.push(named(
            "ceiling:substitution",
            env_selector(principal.clone(), "TOKEN"),
        ));
        let mut substitution_operation = StagedOperation::new(
            &core,
            "operation:substitution",
            captured_context("actor:substitution", vec![principal.clone()], "owner:pkg"),
            &substitutable,
        )
        .unwrap();
        let first_use = stage(
            "first-use",
            vec![principal.clone()],
            vec![env_effect("TOKEN")],
        );
        let StageAuthorization::Permit { permit } = substitution_operation
            .authorize_next(
                &core,
                &first_use,
                &substitutable,
                &mut resources,
                Interaction::NonInteractive,
            )
            .unwrap()
        else {
            panic!("first source should authorize");
        };
        assert!(matches!(
            substitution_operation
                .commit(
                    &core,
                    permit,
                    &first_use,
                    &substitutable,
                    &mut resources,
                )
                .unwrap(),
            CommitResult::Committed { .. }
        ));
        substitutable.session_grants.remove(0);
        let substitution = substitution_operation
            .authorize_next(
                &core,
                &stage("reuse", vec![principal], vec![env_effect("TOKEN")]),
                &substitutable,
                &mut resources,
                Interaction::NonInteractive,
            )
            .unwrap();
        assert!(matches!(substitution, StageAuthorization::Denied { .. }));
    }

    #[test]
    fn staged_operation_rejects_late_protected_exception_join() {
        let core = Rev2Core::embedded().unwrap();
        let principal = package("late-exception");
        let metadata = fetch_selector(principal.clone(), "169.254.169.254", "metadata");
        let mut rules = policy(Mode::Enforce);
        rules
            .static_floor
            .push(named("env", env_selector(principal.clone(), "TOKEN")));
        rules.static_floor.push(named("metadata", metadata.clone()));
        let mut operation = StagedOperation::new(
            &core,
            "operation:late-exception",
            captured_context(
                "actor:late-exception",
                vec![principal.clone()],
                "owner:pkg",
            ),
            &rules,
        )
        .unwrap();
        let mut resources = TrackedProvisionalResources::default();
        let first = stage("first", vec![principal.clone()], vec![env_effect("TOKEN")]);
        let StageAuthorization::Permit { permit } = operation
            .authorize_next(
                &core,
                &first,
                &rules,
                &mut resources,
                Interaction::NonInteractive,
            )
            .unwrap()
        else {
            panic!("unrelated first stage should authorize");
        };
        assert!(matches!(
            operation
                .commit(&core, permit, &first, &rules, &mut resources)
                .unwrap(),
            CommitResult::Committed { .. }
        ));
        rules.protected_exceptions.push(ProtectedExceptionInput {
            source_id: "late-exception".to_string(),
            reason: "must not join a running actor".to_string(),
            selector: metadata,
        });
        assert!(matches!(
            operation
                .authorize_next(
                    &core,
                    &stage(
                        "metadata",
                        vec![principal],
                        vec![fetch_effect("169.254.169.254")],
                    ),
                    &rules,
                    &mut resources,
                    Interaction::NonInteractive,
                )
                .unwrap(),
            StageAuthorization::Denied { .. }
        ));
    }

    #[test]
    fn staged_operation_cumulatively_freezes_observed_negatives() {
        let core = Rev2Core::embedded().unwrap();
        let principal = package("negative-freeze");
        let mut initial = policy(Mode::Enforce);
        initial
            .static_floor
            .push(named("token", env_selector(principal.clone(), "TOKEN")));
        initial
            .static_floor
            .push(named("other", env_selector(principal.clone(), "OTHER")));
        let mut same_generation_addition = initial.clone();
        same_generation_addition.process_denials.push(named(
            "deny-other",
            selector(None, "env:read", json!({ "name": "OTHER" })),
        ));
        let mut same_generation_operation = StagedOperation::new(
            &core,
            "operation:negative-same-generation",
            captured_context(
                "actor:negative-same-generation",
                vec![principal.clone()],
                "owner:pkg",
            ),
            &initial,
        )
        .unwrap();
        let mut resources = TrackedProvisionalResources::default();
        assert!(matches!(
            same_generation_operation
                .authorize_next(
                    &core,
                    &stage(
                        "same-generation-addition",
                        vec![principal.clone()],
                        vec![env_effect("TOKEN")],
                    ),
                    &same_generation_addition,
                    &mut resources,
                    Interaction::NonInteractive,
                )
                .unwrap(),
            StageAuthorization::Denied { .. }
        ));

        let mut commit_addition = StagedOperation::new(
            &core,
            "operation:negative-added-at-commit",
            captured_context(
                "actor:negative-added-at-commit",
                vec![principal.clone()],
                "owner:pkg",
            ),
            &initial,
        )
        .unwrap();
        let commit_addition_stage = stage(
            "negative-added-at-commit",
            vec![principal.clone()],
            vec![env_effect("TOKEN")],
        );
        let StageAuthorization::Permit { permit } = commit_addition
            .authorize_next(
                &core,
                &commit_addition_stage,
                &initial,
                &mut resources,
                Interaction::NonInteractive,
            )
            .unwrap()
        else {
            panic!("unchanged policy should authorize before the commit snapshot check");
        };
        let CommitResult::Denied { denial } = commit_addition
            .commit(
                &core,
                permit,
                &commit_addition_stage,
                &same_generation_addition,
                &mut resources,
            )
            .unwrap()
        else {
            panic!("same-generation unrelated negative addition must deny at commit");
        };
        assert_eq!(denial.reason_code, REASON_OPERATION_CONTEXT);

        let mut operation = StagedOperation::new(
            &core,
            "operation:negative-freeze",
            captured_context(
                "actor:negative-freeze",
                vec![principal.clone()],
                "owner:pkg",
            ),
            &initial,
        )
        .unwrap();
        let mut with_negative = initial.clone();
        with_negative.process_denials.push(named(
            "deny-other",
            selector(None, "env:read", json!({ "name": "OTHER" })),
        ));
        with_negative.generations.negative_overlay = "1".to_string();
        let first = stage("first", vec![principal.clone()], vec![env_effect("TOKEN")]);
        let StageAuthorization::Permit { permit } = operation
            .authorize_next(
                &core,
                &first,
                &with_negative,
                &mut resources,
                Interaction::NonInteractive,
            )
            .unwrap()
        else {
            panic!("unrelated denial should not block TOKEN");
        };
        assert!(matches!(
            operation
                .commit(
                    &core,
                    permit,
                    &first,
                    &with_negative,
                    &mut resources,
                )
                .unwrap(),
            CommitResult::Committed { .. }
        ));
        let mut removed = initial.clone();
        removed.generations.negative_overlay = "2".to_string();
        assert!(matches!(
            operation
                .authorize_next(
                    &core,
                    &stage("second", vec![principal], vec![env_effect("OTHER")]),
                    &removed,
                    &mut resources,
                    Interaction::NonInteractive,
                )
                .unwrap(),
            StageAuthorization::Denied { .. }
        ));

        let mut precommit = StagedOperation::new(
            &core,
            "operation:negative-precommit",
            captured_context(
                "actor:negative-precommit",
                vec![package("negative-freeze")],
                "owner:pkg",
            ),
            &initial,
        )
        .unwrap();
        let precommit_stage = stage(
            "precommit",
            vec![package("negative-freeze")],
            vec![env_effect("TOKEN")],
        );
        let StageAuthorization::Permit { permit } = precommit
            .authorize_next(
                &core,
                &precommit_stage,
                &with_negative,
                &mut resources,
                Interaction::NonInteractive,
            )
            .unwrap()
        else {
            panic!("negative addition should not block unrelated precommit stage");
        };
        let mut removed_before_commit = initial;
        removed_before_commit.generations.negative_overlay = "1".to_string();
        assert!(matches!(
            precommit
                .commit(
                    &core,
                    permit,
                    &precommit_stage,
                    &removed_before_commit,
                    &mut resources,
                )
                .unwrap(),
            CommitResult::Denied { .. }
        ));
    }

    #[test]
    fn masked_stages_advance_the_observed_generation_watermark() {
        let core = Rev2Core::embedded().unwrap();
        let principal = package("masked-watermark");
        let initial = policy(Mode::Audit);
        let mut generation_one_a = initial.clone();
        generation_one_a.process_denials.push(named(
            "deny-other-a",
            selector(None, "env:read", json!({ "name": "OTHER_A" })),
        ));
        generation_one_a.generations.negative_overlay = "1".to_string();
        let mut generation_one_ab = generation_one_a.clone();
        generation_one_ab.process_denials.push(named(
            "deny-other-b",
            selector(None, "env:read", json!({ "name": "OTHER_B" })),
        ));
        let masked_request = |stage_id: &str| {
            stage(
                stage_id,
                vec![principal.clone()],
                vec![env_effect("TOKEN")],
            )
        };
        let mut resources = TrackedProvisionalResources::default();

        let mut same_generation = StagedOperation::new(
            &core,
            "operation:masked-same-generation",
            captured_context(
                "actor:masked-same-generation",
                vec![principal.clone()],
                "owner:pkg",
            ),
            &initial,
        )
        .unwrap();
        assert!(matches!(
            same_generation
                .authorize_next(
                    &core,
                    &masked_request("masked-a"),
                    &generation_one_a,
                    &mut resources,
                    Interaction::NonInteractive,
                )
                .unwrap(),
            StageAuthorization::Masked { .. }
        ));
        assert_eq!(same_generation.last_generations.negative_overlay, "1");
        assert!(matches!(
            same_generation
                .authorize_next(
                    &core,
                    &masked_request("masked-a-plus-b"),
                    &generation_one_ab,
                    &mut resources,
                    Interaction::NonInteractive,
                )
                .unwrap(),
            StageAuthorization::Denied { .. }
        ));

        let mut rollback = StagedOperation::new(
            &core,
            "operation:masked-rollback",
            captured_context(
                "actor:masked-rollback",
                vec![principal.clone()],
                "owner:pkg",
            ),
            &initial,
        )
        .unwrap();
        assert!(matches!(
            rollback
                .authorize_next(
                    &core,
                    &masked_request("masked-before-rollback"),
                    &generation_one_a,
                    &mut resources,
                    Interaction::NonInteractive,
                )
                .unwrap(),
            StageAuthorization::Masked { .. }
        ));
        let mut generation_zero_a = generation_one_a;
        generation_zero_a.generations.negative_overlay = "0".to_string();
        assert!(matches!(
            rollback
                .authorize_next(
                    &core,
                    &masked_request("masked-rollback"),
                    &generation_zero_a,
                    &mut resources,
                    Interaction::NonInteractive,
                )
                .unwrap(),
            StageAuthorization::Denied { .. }
        ));
    }

    #[test]
    fn actor_digest_binds_canonical_occurrence_and_dimension_mapping() {
        let core = Rev2Core::embedded().unwrap();
        let principal = package("actor");
        let authority = path_selector(principal.clone(), "/project/data");
        let canonical = core
            .normalize_selector(&authority, SelectorPolarity::Positive)
            .unwrap();
        let source_id = canonical_row_digest(&canonical).unwrap();
        let mut policy = policy(Mode::Enforce);
        policy.static_floor.push(named("path", authority));
        policy.path_bindings.push(PathBindingInput {
            source_id,
            root_binding_id: "root-binding:1".to_string(),
            final_object_identities: vec![
                json!({ "kind": "platform-object", "value": "file:a" }),
                json!({ "kind": "platform-object", "value": "file:b" }),
            ],
            parent_identities: vec![],
        });

        let authorize = |path: &str, identity: &str| {
            let mut operation = StagedOperation::new(
                &core,
                "operation:actor",
                captured_context("actor:resource", vec![principal.clone()], "owner:pkg"),
                &policy,
            )
            .unwrap();
            let mut resources = TrackedProvisionalResources::default();
            let authorization = operation
                .authorize_next(
                    &core,
                    &stage(
                        "commit",
                        vec![principal.clone()],
                        vec![path_effect(path, identity)],
                    ),
                    &policy,
                    &mut resources,
                    Interaction::NonInteractive,
                )
                .unwrap();
            let StageAuthorization::Permit { permit } = authorization else {
                panic!("path occurrence should authorize");
            };
            assert_eq!(
                permit.decision().effects[0].dimensions[0]
                    .positive_source
                    .as_ref()
                    .unwrap()
                    .source_id,
                policy.path_bindings[0].source_id
            );
            permit.actor_digest().to_string()
        };

        assert_ne!(
            authorize("/project/data/a", "file:a"),
            authorize("/project/data/b", "file:b")
        );
    }

    #[test]
    fn actor_digest_is_sensitive_to_every_sticky_inventory_and_sealed_transition() {
        let core = Rev2Core::embedded().unwrap();
        let principal = package("actor-inventory");
        let mut base = policy(Mode::Enforce);
        base.static_floor.push(named(
            "token",
            env_selector(principal.clone(), "TOKEN"),
        ));
        let mut extra_positive = base.clone();
        extra_positive.static_floor.push(named(
            "other",
            env_selector(principal.clone(), "OTHER"),
        ));
        let mut extra_negative = base.clone();
        extra_negative.process_denials.push(named(
            "deny-other",
            selector(None, "env:read", json!({ "name": "OTHER" })),
        ));

        let digest = |
            initial_policy: &DecisionPolicyInput,
            current_policy: &DecisionPolicyInput,
            resource_ids: &[&str],
            sealed_launch_edge: bool,
            consumed_sealed_launch: bool,
            captured_repeatable_effect: bool,
        | {
            let sealed_child_exports = captured_repeatable_effect
                .then(|| {
                    SealedChildExportFact::capture_host(child_env_read_effect(
                        "SEALED_REPEATABLE",
                        false,
                    ))
                })
                .into_iter()
                .collect();
            let context = CapturedOperationContext::capture_host(
                "actor:inventory",
                EngineIdentity::embedded(),
                vec![principal.clone()],
                "owner:pkg",
                principal.clone(),
                "0",
                sealed_child_exports,
                sealed_launch_edge.then(|| SPAWN_EDGE.to_string()),
            )
            .unwrap();
            let mut operation = StagedOperation::new(
                &core,
                "operation:inventory",
                context,
                initial_policy,
            )
            .unwrap();
            operation.sealed_launch_consumed = consumed_sealed_launch;
            let mut resources = TrackedProvisionalResources::default();
            for id in resource_ids {
                resources.hold(*id).unwrap();
            }
            let StageAuthorization::Permit { permit } = operation
                .authorize_next(
                    &core,
                    &stage(
                        "inventory",
                        vec![principal.clone()],
                        vec![env_effect("TOKEN")],
                    ),
                    current_policy,
                    &mut resources,
                    Interaction::NonInteractive,
                )
                .unwrap()
            else {
                panic!("inventory sensitivity vector must authorize");
            };
            permit.actor_digest().to_string()
        };

        let baseline = digest(&base, &base, &[], false, false, false);
        let initial_and_current_positive =
            digest(&extra_positive, &extra_positive, &[], false, false, false);
        let same_initial_reduced_current =
            digest(&extra_positive, &base, &[], false, false, false);
        let cumulative_negative =
            digest(&extra_negative, &extra_negative, &[], false, false, false);
        let provisional_resource =
            digest(&base, &base, &["resource:a"], false, false, false);
        let consumed_without_edge = digest(&base, &base, &[], false, true, false);
        let consumed_sealed_launch = digest(&base, &base, &[], true, true, false);
        let consumed_sealed_repeatable = digest(&base, &base, &[], true, true, true);

        assert_ne!(baseline, initial_and_current_positive);
        assert_ne!(baseline, same_initial_reduced_current);
        assert_ne!(initial_and_current_positive, same_initial_reduced_current);
        assert_ne!(baseline, cumulative_negative);
        assert_ne!(baseline, provisional_resource);
        assert_ne!(baseline, consumed_without_edge);
        assert_ne!(consumed_without_edge, consumed_sealed_launch);
        assert_ne!(consumed_sealed_launch, consumed_sealed_repeatable);

        let mut launch_rules = policy(Mode::Enforce);
        launch_rules
            .static_floor
            .push(named("spawn", spawn_selector(principal.clone())));
        let launch_context = CapturedOperationContext::capture_host(
            "actor:real-sealed-transition",
            EngineIdentity::embedded(),
            vec![principal.clone()],
            "owner:pkg",
            principal.clone(),
            "0",
            vec![],
            Some(SPAWN_EDGE.to_string()),
        )
        .unwrap();
        let mut launch = StagedOperation::new(
            &core,
            "operation:real-sealed-transition",
            launch_context,
            &launch_rules,
        )
        .unwrap();
        let launch_request = stage(
            "real-sealed-transition",
            vec![principal],
            vec![spawn_effect()],
        );
        let mut resources = TrackedProvisionalResources::default();
        let StageAuthorization::Permit { permit } = launch
            .authorize_next(
                &core,
                &launch_request,
                &launch_rules,
                &mut resources,
                Interaction::NonInteractive,
            )
            .unwrap()
        else {
            panic!("real sealed launch transition must authorize");
        };
        assert!(!launch.sealed_launch_consumed);
        assert!(launch
            .pending_commit
            .as_ref()
            .unwrap()
            .sealed_launch_consumed_after_commit);
        assert!(matches!(
            launch
                .commit(
                    &core,
                    permit,
                    &launch_request,
                    &launch_rules,
                    &mut resources,
                )
                .unwrap(),
            CommitResult::Committed { .. }
        ));
        assert!(launch.sealed_launch_consumed);
    }

    #[test]
    fn commit_permit_is_one_shot_and_rechecks_revocation_at_commit_boundary() {
        let core = Rev2Core::embedded().unwrap();
        let principal = package("commit");
        let mut armed = policy(Mode::Enforce);
        armed
            .static_floor
            .push(named("allow", env_selector(principal.clone(), "TOKEN")));
        let request = stage("commit", vec![principal.clone()], vec![env_effect("TOKEN")]);
        let mut operation = StagedOperation::new(
            &core,
            "operation:commit",
            captured_context("actor:commit", vec![principal.clone()], "owner:pkg"),
            &armed,
        )
        .unwrap();
        let mut resources = TrackedProvisionalResources::default();
        resources.hold("commit:provisional").unwrap();
        let StageAuthorization::Permit { permit } = operation
            .authorize_next(
                &core,
                &request,
                &armed,
                &mut resources,
                Interaction::NonInteractive,
            )
            .unwrap()
        else {
            panic!("armed stage should receive a permit");
        };

        let mut revoked = armed.clone();
        revoked.session_revocations.push(named(
            "revoke-before-commit",
            env_selector(principal, "TOKEN"),
        ));
        let result = operation
            .commit(&core, permit, &request, &revoked, &mut resources)
            .unwrap();
        let CommitResult::Denied { denial } = result else {
            panic!("revocation before commit must consume and deny the permit");
        };
        assert_eq!(denial.reason_code, REASON_REVOKED);
        assert_eq!(resources.released(), ["commit:provisional"]);
        assert!(matches!(
            operation
                .authorize_next(
                    &core,
                    &request,
                    &armed,
                    &mut resources,
                    Interaction::NonInteractive,
                )
                .unwrap(),
            StageAuthorization::AlreadyDenied { .. }
        ));
    }

    #[test]
    fn commit_permit_binds_the_exact_provisional_resource_inventory() {
        let core = Rev2Core::embedded().unwrap();
        let principal = package("resource-snapshot");
        let mut rules = policy(Mode::Enforce);
        rules.static_floor.push(named(
            "allow",
            env_selector(principal.clone(), "TOKEN"),
        ));
        let request = stage(
            "resource-snapshot",
            vec![principal.clone()],
            vec![env_effect("TOKEN")],
        );

        let mut added = StagedOperation::new(
            &core,
            "operation:resource-added",
            captured_context(
                "actor:resource-added",
                vec![principal.clone()],
                "owner:pkg",
            ),
            &rules,
        )
        .unwrap();
        let mut added_resources = TrackedProvisionalResources::default();
        added_resources.hold("resource:a").unwrap();
        let StageAuthorization::Permit { permit } = added
            .authorize_next(
                &core,
                &request,
                &rules,
                &mut added_resources,
                Interaction::NonInteractive,
            )
            .unwrap()
        else {
            panic!("initial resource snapshot should authorize");
        };
        assert_eq!(permit.provisional_resource_ids, ["resource:a"]);
        added_resources.hold("resource:b").unwrap();
        let CommitResult::Denied { denial } = added
            .commit(&core, permit, &request, &rules, &mut added_resources)
            .unwrap()
        else {
            panic!("a post-authorize resource addition must deny");
        };
        assert_eq!(denial.reason_code, REASON_OPERATION_CONTEXT);
        assert_eq!(denial.released_provisional_resources, ["resource:a", "resource:b"]);

        let mut removed = StagedOperation::new(
            &core,
            "operation:resource-removed",
            captured_context(
                "actor:resource-removed",
                vec![principal],
                "owner:pkg",
            ),
            &rules,
        )
        .unwrap();
        let mut removed_resources = TrackedProvisionalResources::default();
        removed_resources.hold("resource:a").unwrap();
        let StageAuthorization::Permit { permit } = removed
            .authorize_next(
                &core,
                &request,
                &rules,
                &mut removed_resources,
                Interaction::NonInteractive,
            )
            .unwrap()
        else {
            panic!("initial resource snapshot should authorize");
        };
        assert_eq!(removed_resources.release_all(), ["resource:a"]);
        let CommitResult::Denied { denial } = removed
            .commit(&core, permit, &request, &rules, &mut removed_resources)
            .unwrap()
        else {
            panic!("a post-authorize resource removal must deny");
        };
        assert_eq!(denial.reason_code, REASON_OPERATION_CONTEXT);
        assert!(denial.released_provisional_resources.is_empty());
        assert_eq!(removed_resources.released(), ["resource:a"]);
    }

    #[test]
    fn provisional_resource_inventory_is_closed_and_bounded() {
        #[derive(Default)]
        struct RawResources {
            ids: Vec<String>,
        }

        impl ProvisionalResources for RawResources {
            fn held_ids(&self) -> Vec<String> {
                self.ids.clone()
            }

            fn release_all(&mut self) -> Vec<String> {
                std::mem::take(&mut self.ids)
            }
        }

        let too_many = RawResources {
            ids: (0..=MAX_PROVISIONAL_RESOURCE_ENTRIES)
                .map(|index| format!("resource:{index}"))
                .collect(),
        };
        assert!(canonical_provisional_resource_ids(&too_many).is_err());
        let too_long = RawResources {
            ids: vec!["r".repeat(1025)],
        };
        assert!(canonical_provisional_resource_ids(&too_long).is_err());
        let duplicate = RawResources {
            ids: vec!["resource:a".to_string(), "resource:a".to_string()],
        };
        assert!(canonical_provisional_resource_ids(&duplicate).is_err());
    }

    #[test]
    fn staged_generation_counters_never_roll_back() {
        let core = Rev2Core::embedded().unwrap();
        let principal = package("generation-order");
        let mut initial = policy(Mode::Enforce);
        initial
            .static_floor
            .push(named("allow", env_selector(principal.clone(), "TOKEN")));
        let mut operation = StagedOperation::new(
            &core,
            "operation:generation-order",
            captured_context("actor:generation-order", vec![principal.clone()], "owner:pkg"),
            &initial,
        )
        .unwrap();
        let mut resources = TrackedProvisionalResources::default();
        let first = stage("first", vec![principal.clone()], vec![env_effect("TOKEN")]);
        let StageAuthorization::Permit { permit } = operation
            .authorize_next(
                &core,
                &first,
                &initial,
                &mut resources,
                Interaction::NonInteractive,
            )
            .unwrap()
        else {
            panic!("first generation should authorize");
        };
        assert!(matches!(
            operation
                .commit(&core, permit, &first, &initial, &mut resources)
                .unwrap(),
            CommitResult::Committed { .. }
        ));

        let mut advanced = initial.clone();
        advanced.generations.negative_overlay = "1".to_string();
        let second = stage("second", vec![principal.clone()], vec![env_effect("TOKEN")]);
        let StageAuthorization::Permit { permit } = operation
            .authorize_next(
                &core,
                &second,
                &advanced,
                &mut resources,
                Interaction::NonInteractive,
            )
            .unwrap()
        else {
            panic!("advanced negative generation should reauthorize");
        };
        assert!(matches!(
            operation
                .commit(&core, permit, &second, &advanced, &mut resources)
                .unwrap(),
            CommitResult::Committed { .. }
        ));

        let rollback = operation
            .authorize_next(
                &core,
                &stage("rollback", vec![principal], vec![env_effect("TOKEN")]),
                &initial,
                &mut resources,
                Interaction::NonInteractive,
            )
            .unwrap();
        assert!(matches!(rollback, StageAuthorization::Denied { .. }));
    }

    #[test]
    fn mode_fallback_can_reauthorize_the_same_effect_at_a_new_stage() {
        let core = Rev2Core::embedded().unwrap();
        let principal = package("fallback-stage");
        let enforce = core
            .decide_stage(
                &stage(
                    "fallback-enforce",
                    vec![principal.clone()],
                    vec![sys_effect("cpus")],
                ),
                &policy(Mode::Enforce),
            )
            .unwrap();
        let dimension = &enforce.effects[0].dimensions[0];
        assert_eq!(dimension.outcome, Outcome::Deny);
        assert_eq!(dimension.stratum, 17);
        assert_eq!(dimension.reason_code, REASON_MISSING_AUTHORITY);
        assert!(dimension.positive_source.is_none());
        assert!(enforce.committed_effects.is_empty());

        for mode in [Mode::Permissive, Mode::Audit] {
            let rules = policy(mode);
            let mut operation = StagedOperation::new(
                &core,
                format!("operation:fallback:{mode:?}"),
                captured_context(
                    &format!("actor:fallback:{mode:?}"),
                    vec![principal.clone()],
                    "owner:pkg",
                ),
                &rules,
            )
            .unwrap();
            let mut resources = TrackedProvisionalResources::default();
            for stage_id in ["fallback-a", "fallback-b"] {
                let request = stage(
                    stage_id,
                    vec![principal.clone()],
                    vec![sys_effect("cpus")],
                );
                let StageAuthorization::Permit { permit } = operation
                    .authorize_next(
                        &core,
                        &request,
                        &rules,
                        &mut resources,
                        Interaction::NonInteractive,
                    )
                    .unwrap()
                else {
                    panic!("mode fallback should authorize at {stage_id}");
                };
                let dimension = &permit.decision().effects[0].dimensions[0];
                assert_eq!(dimension.stratum, 17);
                assert_eq!(
                    dimension.reason_code,
                    if mode == Mode::Audit {
                        REASON_AUDIT_ALLOW
                    } else {
                        REASON_ALLOW
                    }
                );
                let source = dimension.positive_source.as_ref().unwrap();
                assert_eq!(source.kind, "mode-fallback");
                assert_eq!(source.generation.as_deref(), Some("1"));
                assert!(matches!(
                    operation
                        .commit(&core, permit, &request, &rules, &mut resources)
                        .unwrap(),
                    CommitResult::Committed { .. }
                ));
            }
        }
    }

    #[test]
    fn staged_operation_lifetime_caps_history_before_actor_serialization() {
        assert!(!prospective_len_exceeds_bound(1, 1, 2));
        assert!(prospective_len_exceeds_bound(1, 2, 2));
        let current = BTreeSet::from(["a".to_string(), "b".to_string()]);
        assert!(!set_union_exceeds_bound(
            &current,
            &BTreeSet::from(["b".to_string(), "c".to_string()]),
            3,
        ));
        assert!(set_union_exceeds_bound(
            &current,
            &BTreeSet::from(["c".to_string(), "d".to_string()]),
            3,
        ));

        let core = Rev2Core::embedded().unwrap();
        let principal = package("lifetime-bound");
        let mut rules = policy(Mode::Enforce);
        rules.static_floor.push(named(
            "static-lifetime",
            env_selector(principal.clone(), "TOKEN"),
        ));
        let mut resources = TrackedProvisionalResources::default();

        let mut stages = StagedOperation::new(
            &core,
            "operation:stage-lifetime-bound",
            captured_context(
                "actor:stage-lifetime-bound",
                vec![principal.clone()],
                "owner:pkg",
            ),
            &rules,
        )
        .unwrap();
        stages.completed_stages = (0..MAX_OPERATION_COMMITTED_STAGES - 1)
            .map(|index| format!("completed:{index}"))
            .collect();
        let final_stage = stage(
            "completed:final",
            vec![principal.clone()],
            vec![env_effect("TOKEN")],
        );
        let StageAuthorization::Permit { permit } = stages
            .authorize_next(
                &core,
                &final_stage,
                &rules,
                &mut resources,
                Interaction::NonInteractive,
            )
            .unwrap()
        else {
            panic!("the exact operation stage bound must authorize");
        };
        assert_eq!(
            permit.completed_discovery_stages.len(),
            MAX_OPERATION_COMMITTED_STAGES
        );
        assert!(matches!(
            stages
                .commit(&core, permit, &final_stage, &rules, &mut resources)
                .unwrap(),
            CommitResult::Committed { .. }
        ));
        assert!(matches!(
            stages
                .authorize_next(
                    &core,
                    &stage(
                        "completed:over-bound",
                        vec![principal.clone()],
                        vec![env_effect("TOKEN")],
                    ),
                    &rules,
                    &mut resources,
                    Interaction::NonInteractive,
                )
                .unwrap(),
            StageAuthorization::Denied { .. }
        ));

        let mut sources = StagedOperation::new(
            &core,
            "operation:source-lifetime-bound",
            captured_context(
                "actor:source-lifetime-bound",
                vec![principal.clone()],
                "owner:pkg",
            ),
            &rules,
        )
        .unwrap();
        let filler = PositiveSource {
            kind: "static-row".to_string(),
            source_id: "filler".to_string(),
            generation: None,
        };
        for index in 0..MAX_OPERATION_CAPTURED_SOURCE_ENTRIES {
            sources
                .captured_positive_sources
                .insert(format!("filler:{index}"), filler.clone());
        }
        let source_count_before = sources.captured_positive_sources.len();
        let over_bound = sources
            .authorize_next(
                &core,
                &stage(
                    "source:over-bound",
                    vec![principal],
                    vec![env_effect("TOKEN")],
                ),
                &rules,
                &mut resources,
                Interaction::NonInteractive,
            )
            .unwrap();
        assert!(matches!(over_bound, StageAuthorization::Denied { .. }));
        assert_eq!(sources.captured_positive_sources.len(), source_count_before);
        assert!(sources.pending_commit.is_none());
    }

    #[test]
    fn staged_source_cannot_fall_from_static_to_mode_fallback() {
        let core = Rev2Core::embedded().unwrap();
        let principal = package("fallback-substitution");
        let mut rules = policy(Mode::Permissive);
        rules.static_floor.push(named(
            "static-sys",
            selector(
                Some(principal.clone()),
                "sys:read",
                json!({ "kind": "cpus" }),
            ),
        ));
        let mut operation = StagedOperation::new(
            &core,
            "operation:fallback-substitution",
            captured_context(
                "actor:fallback-substitution",
                vec![principal.clone()],
                "owner:pkg",
            ),
            &rules,
        )
        .unwrap();
        let mut resources = TrackedProvisionalResources::default();
        let first = stage("static", vec![principal.clone()], vec![sys_effect("cpus")]);
        let StageAuthorization::Permit { permit } = operation
            .authorize_next(
                &core,
                &first,
                &rules,
                &mut resources,
                Interaction::NonInteractive,
            )
            .unwrap()
        else {
            panic!("static source should authorize");
        };
        assert!(matches!(
            operation
                .commit(&core, permit, &first, &rules, &mut resources)
                .unwrap(),
            CommitResult::Committed { .. }
        ));
        rules.static_floor.clear();
        let substitution = operation
            .authorize_next(
                &core,
                &stage("fallback", vec![principal], vec![sys_effect("cpus")]),
                &rules,
                &mut resources,
                Interaction::NonInteractive,
            )
            .unwrap();
        assert!(matches!(substitution, StageAuthorization::Denied { .. }));
    }

    #[test]
    fn staged_actor_uses_host_captured_principals_owner_and_generation() {
        let core = Rev2Core::embedded().unwrap();
        let caller = package("caller");
        let deputy = package("deputy");
        let outsider = package("outsider");
        assert!(CapturedOperationContext::capture_host(
            "actor:invalid-owner",
            EngineIdentity::embedded(),
            vec![caller.clone(), deputy.clone()],
            "owner:outsider",
            outsider,
            "0",
            vec![],
            None,
        )
        .is_err());

        let mut rules = policy(Mode::Enforce);
        rules
            .static_floor
            .push(named("caller", env_selector(caller.clone(), "TOKEN")));
        rules
            .static_floor
            .push(named("deputy", env_selector(deputy.clone(), "TOKEN")));
        let make_context = |actor_id: &str| {
            CapturedOperationContext::capture_host(
                actor_id,
                EngineIdentity::embedded(),
                vec![caller.clone(), deputy.clone()],
                "owner:pkg",
                deputy.clone(),
                "0",
                vec![],
                None,
            )
            .unwrap()
        };
        let mut missing_caller_context = StagedOperation::new(
            &core,
            "operation:missing-principal",
            make_context("actor:missing-principal"),
            &rules,
        )
        .unwrap();
        let mut resources = TrackedProvisionalResources::default();
        assert!(matches!(
            missing_caller_context
                .authorize_next(
                    &core,
                    &stage("missing", vec![deputy.clone()], vec![env_effect("TOKEN")]),
                    &rules,
                    &mut resources,
                    Interaction::NonInteractive,
                )
                .unwrap(),
            StageAuthorization::Denied { .. }
        ));

        let mut foreign_owner = StagedOperation::new(
            &core,
            "operation:foreign-owner",
            make_context("actor:foreign-owner"),
            &rules,
        )
        .unwrap();
        let mut foreign_effect = env_effect("TOKEN");
        foreign_effect.effect_owner = "owner:foreign".to_string();
        foreign_effect.occurrence["effectOwner"] = Value::String("owner:foreign".to_string());
        assert!(matches!(
            foreign_owner
                .authorize_next(
                    &core,
                    &stage(
                        "foreign-owner",
                        vec![caller.clone(), deputy.clone()],
                        vec![foreign_effect],
                    ),
                    &rules,
                    &mut resources,
                    Interaction::NonInteractive,
                )
                .unwrap(),
            StageAuthorization::Denied { .. }
        ));

        let mut stale_owner = StagedOperation::new(
            &core,
            "operation:stale-owner",
            make_context("actor:stale-owner"),
            &rules,
        )
        .unwrap();
        let mut stale_effect = env_effect("TOKEN");
        stale_effect.occurrence["ownerGeneration"] = Value::String("1".to_string());
        assert!(matches!(
            stale_owner
                .authorize_next(
                    &core,
                    &stage("stale-owner", vec![caller, deputy], vec![stale_effect]),
                    &rules,
                    &mut resources,
                    Interaction::NonInteractive,
                )
                .unwrap(),
            StageAuthorization::Denied { .. }
        ));
    }

    #[test]
    fn interaction_releases_resources_before_restart() {
        let core = Rev2Core::embedded().unwrap();
        let principal = package("a");
        let mut policy = policy(Mode::Enforce);
        policy.static_floor.push(named("allow", env_selector(principal.clone(), "TOKEN")));
        let request = stage("promptable", vec![principal.clone()], vec![env_effect("TOKEN")]);
        let mut operation = StagedOperation::new(
            &core,
            "operation:prompt",
            captured_context("actor:prompt", vec![principal], "owner:pkg"),
            &policy,
        )
        .unwrap();
        let mut resources = TrackedProvisionalResources::default();
        resources.hold("lock:1").unwrap();
        let restart = operation
            .authorize_next(&core, &request, &policy, &mut resources, Interaction::MayPrompt)
            .unwrap();
        assert!(matches!(restart, StageAuthorization::RestartRequired { .. }));
        assert!(resources.held_ids().is_empty());
        assert!(matches!(
            operation
                .authorize_next(
                    &core,
                    &request,
                    &policy,
                    &mut resources,
                    Interaction::NonInteractive,
                )
                .unwrap(),
            StageAuthorization::AlreadyDenied { .. }
        ));

        let mut restarted_policy = policy.clone();
        restarted_policy.run_nonce = "run:after-prompt".to_string();
        restarted_policy.channel_epoch = "channel:after-prompt".to_string();
        let mut restarted = StagedOperation::new(
            &core,
            "operation:prompt-restarted",
            captured_context(
                "actor:prompt-restarted",
                request.principals.clone(),
                "owner:pkg",
            ),
            &restarted_policy,
        )
        .unwrap();
        assert!(matches!(
            restarted
                .authorize_next(
                    &core,
                    &request,
                    &restarted_policy,
                    &mut resources,
                    Interaction::NonInteractive,
                )
                .unwrap(),
            StageAuthorization::Permit { .. }
        ));
    }

    proptest! {
        #[test]
        fn generated_principal_intersection_is_order_invariant(
            name in "[A-Z]{1,12}",
            left in "[a-z]{1,8}",
            right in "[a-z]{1,8}",
        ) {
            prop_assume!(left != right);
            let core = Rev2Core::embedded().unwrap();
            let left = package(&left);
            let right = package(&right);
            let mut policy = policy(Mode::Enforce);
            policy.static_floor.push(named("left", env_selector(left.clone(), &name)));
            policy.static_floor.push(named("right", env_selector(right.clone(), &name)));
            let a = core.decide_stage(
                &stage("property", vec![left.clone(), right.clone()], vec![env_effect(&name)]),
                &policy,
            ).unwrap();
            let b = core.decide_stage(
                &stage("property", vec![right, left], vec![env_effect(&name)]),
                &policy,
            ).unwrap();
            prop_assert_eq!(a, b);
        }

        #[test]
        fn generated_cross_action_or_wrong_resource_never_matches(
            allowed in "[A-Z]{1,12}",
            requested in "[A-Z]{1,12}",
        ) {
            prop_assume!(allowed != requested);
            let core = Rev2Core::embedded().unwrap();
            let principal = package("property");
            let mut policy = policy(Mode::Enforce);
            policy.static_floor.push(named("allow", env_selector(principal.clone(), &allowed)));
            let result = core.decide_stage(
                &stage("property", vec![principal], vec![env_effect(&requested)]),
                &policy,
            ).unwrap();
            prop_assert_eq!(result.outcome, Outcome::Deny);
        }
    }
}

}

pub use shared::*;

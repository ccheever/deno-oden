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
const MAX_RISK_AUTHORITIES: usize = 4_096;
const MAX_RISK_FIELDS_PER_SCOPE: usize = 64;
const MAX_RISK_STRING_BYTES: usize = 4_096;
const MAX_RISK_ARRAY_ITEMS: usize = 4_096;
const I_JSON_SAFE_INTEGER_MAX: i64 = 9_007_199_254_740_991;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::io::{Read, Write};
use std::net::{IpAddr, Ipv6Addr};
use std::ops::Deref;
use std::str::FromStr;
use std::sync::{Arc, OnceLock};

use crate::rev2_registry_generated as generated;
use crate::rev2_registry_generated::{
    REV2_FILESYSTEM_CANDIDATE_CASE_PLANS, REV2_FILESYSTEM_CANDIDATE_OPERATIONS,
    REV2_PROFILE, REV2_REGISTRY_DIGEST, REV2_RUNTIME_SEMANTIC_PAYLOAD_JSON,
    REV2_RUNTIME_NEGATIVE_INVENTORY_DOMAIN, REV2_RUNTIME_PROTECTED_ROW_DIGEST_DOMAIN,
    REV2_TARGET_STATUS, REV2_VOCAB_DIGEST,
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
    pub predicate_id: String,
    pub reason_digest: String,
    pub canonical_row_digest: String,
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

/// One host-captured normalized authority row for advisory risk evaluation.
///
/// `fields` uses the exact generated risk-field names (for example,
/// `resource.name`). Definition-owned facts such as lifecycle and globality
/// are always taken from the authenticated runtime vocabulary. This type has
/// no wire deserializer and private fields: JavaScript and review-packet input
/// cannot manufacture or omit classifier facts. The trusted host projection
/// from canonical policy must eventually own complete fact derivation.
///
/// This intentionally does not implement `Deserialize`:
///
/// ```compile_fail
/// use oden_policy::rev2::RiskAuthorityInput;
/// let _: RiskAuthorityInput = serde_json::from_str("{}").unwrap();
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RiskAuthorityInput {
    capability: String,
    fields: BTreeMap<String, Value>,
}

impl RiskAuthorityInput {
    #[cfg(test)]
    fn capture_host(
        capability: impl Into<String>,
        fields: BTreeMap<String, Value>,
    ) -> Result<Self, CoreError> {
        let capability = capability.into();
        if capability.is_empty()
            || capability.len() > 256
            || fields.len() > MAX_RISK_FIELDS_PER_SCOPE
        {
            return Err(CoreError::new(
                REASON_SCHEMA_INVALID,
                "host risk projection has an invalid capability or field bound",
            ));
        }
        Ok(Self { capability, fields })
    }
}

/// Complete host-captured canonical-policy projection for one pure risk
/// evaluation.
///
/// Global fields are authority-wide classifier facts. They are evaluated only
/// by registry rules whose attachment is `global`; definition rules are
/// selected from each authority row's generated `riskRuleIds`. There is no
/// serde/oracle constructor. Only in-module exhaustive tests can currently
/// assemble these facts; production stays sealed until a trusted canonical
/// policy projection can derive every field.
///
/// No such constructor is exposed yet. The generated contract supplies direct
/// selector fields and definition lifecycle/globality, but it does not yet
/// supply all semantics needed for a complete projection:
///
/// - a generated source/sink role for each definition;
/// - the row positions included in complete-policy risk and the projection of
///   protected row metadata into `resource.protected`;
/// - a projection from canonical path `{ root, kind, path }` resources to
///   `resource.logicalPath` and `resource.objectClass` (the current special-file
///   data also lacks the credential/loader-control/protected classes named by
///   the rule);
/// - canonical distinct-scope, path-scope, peer-class, and port counting
///   algorithms, including duplicate/principal treatment; and
/// - selected public-suffix data plus the registrable-domain counting
///   algorithm (the generated input is currently `not-selected`).
///
/// Partial projection would silently omit applicable rules, so construction
/// stays module-private until those items land in the reviewed generated
/// dataset.
///
/// This intentionally does not implement `Deserialize`:
///
/// ```compile_fail
/// use oden_policy::rev2::RiskEvaluationInput;
/// let _: RiskEvaluationInput = serde_json::from_str("{}").unwrap();
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RiskEvaluationInput {
    identity: EngineIdentity,
    authorities: Vec<RiskAuthorityInput>,
    global_fields: BTreeMap<String, Value>,
}

impl RiskEvaluationInput {
    #[cfg(test)]
    fn capture_host(
        authorities: Vec<RiskAuthorityInput>,
        global_fields: BTreeMap<String, Value>,
    ) -> Result<Self, CoreError> {
        if authorities.len() > MAX_RISK_AUTHORITIES
            || global_fields.len() > MAX_RISK_FIELDS_PER_SCOPE
            || (authorities.is_empty() && !global_fields.is_empty())
        {
            return Err(CoreError::new(
                REASON_SCHEMA_INVALID,
                "host risk projection exceeds bounds or gives facts to an empty policy",
            ));
        }
        Ok(Self {
            identity: EngineIdentity::embedded(),
            authorities,
            global_fields,
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RiskReason {
    pub rule_id: String,
    pub reason_code: String,
    pub minimum_tier: u8,
}

/// Advisory-only risk result. It is not an authorization input and the
/// decision evaluator never reads it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RiskEvaluation {
    pub base_tier: u8,
    pub tier: u8,
    pub reasons: Vec<RiskReason>,
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

// The filesystem reference oracle is a semantic operation, not the detached
// evidence wrapper. The trusted parent owns run/build/oracle identity and wraps
// this exact expected-free input and semantic output in the evidence artifacts.
//
// @ref LLP 0019#pre-promotion-conformance-candidate-execution [implements] —
// the Rust oracle receives the complete execution projection and initial-only
// sandbox preimage, never manifest `expected`, trace, final state, or verdict.

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
pub enum FilesystemLogicalRoot {
    #[serde(rename = "$ABS")]
    Abs,
    #[serde(rename = "$HOME")]
    Home,
    #[serde(rename = "$PACKAGE")]
    Package,
    #[serde(rename = "$PROJECT")]
    Project,
    #[serde(rename = "$TMP")]
    Tmp,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FilesystemPlatformPath {
    pub encoding: FilesystemPlatformPathEncoding,
    pub value: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum FilesystemPlatformPathEncoding {
    OpaqueBase64url,
    Unicode,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FilesystemObjectIdentity {
    pub kind: FilesystemObjectIdentityKind,
    pub value: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum FilesystemObjectIdentityKind {
    OpaqueToken,
    PlatformObject,
    VerifiedContent,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum FilesystemObjectKind {
    BlockDevice,
    CharacterDevice,
    Directory,
    Fifo,
    Missing,
    RegularFile,
    Socket,
    Symlink,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FilesystemTargetPredicate {
    pub candidates: Vec<FilesystemTargetCandidate>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FilesystemTargetCandidate {
    pub target: String,
    pub feature_set: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FilesystemInvocation {
    pub kind: FilesystemInvocationKind,
    pub command: String,
    pub args: Vec<String>,
    pub cwd_root: FilesystemLogicalRoot,
    pub entrypoint: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum FilesystemInvocationKind {
    Loader,
    NativeHarness,
    PublicCommand,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case", rename_all_fields = "camelCase", deny_unknown_fields)]
pub enum FilesystemTargetParentRef {
    LogicalRoot {
        root: FilesystemLogicalRoot,
        binding_id: String,
    },
    DirectoryObject {
        object_id: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FilesystemTargetRef {
    pub object_id: String,
    pub parent: FilesystemTargetParentRef,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case", rename_all_fields = "camelCase", deny_unknown_fields)]
pub enum FilesystemOperationRequest {
    LstatSync {
        target_ref: FilesystemTargetRef,
    },
    MkdirSync {
        target_ref: FilesystemTargetRef,
        recursive: bool,
        requested_mode: u16,
    },
}

impl FilesystemOperationRequest {
    fn target_ref(&self) -> &FilesystemTargetRef {
        match self {
            Self::LstatSync { target_ref } | Self::MkdirSync { target_ref, .. } => target_ref,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FilesystemSetup {
    pub logical_roots: Vec<FilesystemSetupLogicalRoot>,
    pub objects: Vec<FilesystemSetupObject>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FilesystemSetupLogicalRoot {
    pub root: FilesystemLogicalRoot,
    pub binding_id: String,
    pub descriptor_slot: usize,
    pub object_identity: FilesystemObjectIdentity,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FilesystemSetupObject {
    pub object_id: String,
    pub root: FilesystemLogicalRoot,
    pub path: FilesystemPlatformPath,
    pub object_identity: Option<FilesystemObjectIdentity>,
    pub kind: FilesystemObjectKind,
    pub content: Option<FilesystemInlineContent>,
    pub content_digest: Option<String>,
    pub alias_target_object_id: Option<String>,
    pub link_target_object_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FilesystemInlineContent {
    pub kind: FilesystemInlineContentKind,
    pub bytes: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum FilesystemInlineContentKind {
    InlineBase64url,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FilesystemPathResource {
    pub root: FilesystemLogicalRoot,
    pub kind: FilesystemPathResourceKind,
    pub path: FilesystemPlatformPath,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum FilesystemPathResourceKind {
    PathExact,
    PathTree,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FilesystemAuthorityRow {
    pub source_id: String,
    pub source_class: FilesystemAuthoritySourceClass,
    pub channel: FilesystemAuthorityChannel,
    pub polarity: SelectorPolarity,
    pub principal_key: Option<String>,
    pub capability: String,
    pub resource: FilesystemPathResource,
    pub state: FilesystemAuthorityState,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum FilesystemAuthoritySourceClass {
    ProcessDenial,
    PrincipalDenial,
    StaticFloor,
    EscalationCeiling,
    SessionRevocation,
    SessionGrant,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum FilesystemAuthorityChannel {
    Process,
    Principal,
    Floor,
    EscalationCeiling,
    Session,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum FilesystemAuthorityState {
    Active,
    Dormant,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FilesystemExecutionPlan {
    pub actors: Vec<FilesystemExecutionActor>,
    pub trace_phases: Vec<FilesystemTracePhase>,
    pub resource_lifecycle: Vec<FilesystemResourceLifecycleEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FilesystemExecutionActor {
    pub actor_id: String,
    pub slot_id: String,
    pub principal_key: Option<String>,
    pub effect_owner: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum FilesystemTracePhase {
    HarnessAdmitted,
    PublicOpEntered,
    ActorsCaptured,
    NamespaceGateAcquired,
    DiscoveryComplete,
    AuthorizationComplete,
    SourcesRevalidated,
    TargetRevalidated,
    PreparationComplete,
    PostPrepareRevalidated,
    CoreCommitRecorded,
    NativeCommitRecorded,
    OperationCompleted,
    DeliverySerialized,
    ProvisionalResourcesReleased,
    NamespaceGateReleased,
    HarnessExited,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FilesystemResourceLifecycleEntry {
    pub sequence: usize,
    pub phase: FilesystemTracePhase,
    pub resource_id: String,
    pub resource_class: FilesystemResourceClass,
    pub transition: FilesystemResourceTransition,
    pub owner_before: Option<String>,
    pub owner_after: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum FilesystemResourceClass {
    InheritedRoot,
    Arena,
    ActorToken,
    NamespaceGate,
    AuthorityHandle,
    PreparedChild,
    ProvisionalResource,
    DeliveryLease,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum FilesystemResourceTransition {
    Acquire,
    Transfer,
    Release,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FilesystemFaultPlan {
    pub barrier_id: String,
    pub phase: FilesystemFaultPhase,
    pub action: FilesystemFaultAction,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum FilesystemFaultPhase {
    AfterDiscovery,
    AfterAuthorization,
    AfterSourceRevalidation,
    AfterTargetRevalidation,
    AfterPreparation,
    AfterPostPrepareRevalidation,
    AfterCoreCommit,
    AfterNativeCommit,
    BeforeDelivery,
    DuringDelivery,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case", rename_all_fields = "camelCase", deny_unknown_fields)]
pub enum FilesystemFaultAction {
    NamespaceMutation {
        mutation: FilesystemNamespaceMutation,
    },
    AuthorityRevocation {
        remove_source_ids: Vec<String>,
        activate_source_ids: Vec<String>,
    },
    ActorSequence {
        operation: FilesystemActorSequenceOperation,
    },
    NativeCommit {
        outcome: FilesystemNativeCommitOutcome,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FilesystemNamespaceMutation {
    pub kind: FilesystemNamespaceMutationKind,
    pub object_id: String,
    pub replacement_object_id: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum FilesystemNamespaceMutationKind {
    LinkSwap,
    ParentReplacement,
    PathReplacement,
    RootReplacement,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum FilesystemActorSequenceOperation {
    Cancel,
    OmitObservation,
    OmitPostPrepareRevalidation,
    OmitNativeCommit,
    RepeatNativeCommit,
    CompleteAfterNotCommitted,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum FilesystemNativeCommitOutcome {
    RaceExisting,
    NotCommitted,
    UncertainAfterSyscall,
    PanicAfterMutationBegin,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum FilesystemExecutionMode {
    Audit,
    Enforce,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum FilesystemInputMutation {
    None,
    TargetPathDotDot,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FilesystemExecutionProjection {
    pub case_id: String,
    pub edge_id: String,
    pub requirement_id: String,
    pub case_kind: String,
    pub case_plan_digest: String,
    pub mode: FilesystemExecutionMode,
    pub constrained_principal_keys: Vec<String>,
    pub effect_owner_key: String,
    pub input_mutation: FilesystemInputMutation,
    pub target_predicate: FilesystemTargetPredicate,
    pub invocation: FilesystemInvocation,
    pub operation_request: FilesystemOperationRequest,
    pub setup: FilesystemSetup,
    pub principals: Vec<PrincipalRef>,
    pub authority_rows: Vec<FilesystemAuthorityRow>,
    pub execution: FilesystemExecutionPlan,
    pub fault_plan: Option<FilesystemFaultPlan>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FilesystemMetadataProjection {
    pub mode: u32,
    pub size: String,
    pub link_count: String,
    pub device: String,
    pub inode: String,
    pub uid: Option<String>,
    pub gid: Option<String>,
    pub rdev: Option<String>,
    pub block_size: Option<String>,
    pub blocks: Option<String>,
    pub accessed_time_ns: Option<String>,
    pub modified_time_ns: Option<String>,
    pub changed_time_ns: Option<String>,
    pub birth_time_ns: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FilesystemRealizedObjectState {
    pub kind: FilesystemObjectKind,
    pub identity: Option<FilesystemObjectIdentity>,
    pub metadata: Option<FilesystemMetadataProjection>,
    pub content_digest: Option<String>,
    pub alias_target_object_id: Option<String>,
    pub link_target_object_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FilesystemInitialSandboxInventory {
    pub schema: String,
    pub phase: FilesystemSandboxPhase,
    pub logical_roots: Vec<FilesystemRealizedLogicalRoot>,
    pub objects: Vec<FilesystemInitialSandboxObject>,
    pub unexpected_entries: Vec<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum FilesystemSandboxPhase {
    Initial,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FilesystemRealizedLogicalRoot {
    pub root: FilesystemLogicalRoot,
    pub binding_id: String,
    pub fixture_identity: FilesystemObjectIdentity,
    pub platform_identity: FilesystemObjectIdentity,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FilesystemInitialSandboxObject {
    pub object_id: String,
    pub root: FilesystemLogicalRoot,
    pub path: FilesystemPlatformPath,
    pub fixture_identity: Option<FilesystemObjectIdentity>,
    pub state: FilesystemRealizedObjectState,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FilesystemParentCaptureFacts {
    pub captured_umask: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FilesystemCandidateOracleInput {
    pub case_projection: FilesystemExecutionProjection,
    pub case_projection_digest: String,
    pub initial_sandbox: FilesystemInitialSandboxInventory,
    pub initial_inventory_digest: String,
    pub parent_capture_facts: FilesystemParentCaptureFacts,
}

/// A closed, expected-free execution input admitted for the native filesystem
/// candidate. The fields remain private and the type deliberately implements
/// neither `Serialize` nor `Deserialize`: only
/// [`validate_filesystem_candidate_execution`] can construct it.
///
/// @ref LLP 0019#pre-promotion-conformance-candidate-execution [implements] —
/// Candidate execution receives only the registered execution projection and
/// initial sandbox preimage; oracle output, manifest expected data, trace,
/// final state, and verdict never enter this token.
#[derive(Debug)]
pub struct ValidatedFilesystemCandidateExecution {
    input: FilesystemCandidateOracleInput,
    runtime_slots: Vec<FilesystemEffectSlot>,
    target_setup_index: usize,
    target_initial_index: usize,
    parent_identity: FilesystemObjectIdentity,
}

impl ValidatedFilesystemCandidateExecution {
    pub fn execution_projection(&self) -> &FilesystemExecutionProjection {
        &self.input.case_projection
    }

    pub fn execution_projection_digest(&self) -> &str {
        &self.input.case_projection_digest
    }

    pub fn initial_sandbox(&self) -> &FilesystemInitialSandboxInventory {
        &self.input.initial_sandbox
    }

    pub fn initial_inventory_digest(&self) -> &str {
        &self.input.initial_inventory_digest
    }

    pub fn parent_capture_facts(&self) -> &FilesystemParentCaptureFacts {
        &self.input.parent_capture_facts
    }

    /// Slots normalized from the registered operation model. A generated
    /// pre-validation mutation has no runtime slots even though its fixture
    /// comparison retains the operation's base slots in the oracle path.
    pub fn runtime_slots(&self) -> &[FilesystemEffectSlot] {
        &self.runtime_slots
    }

    pub fn target_setup(&self) -> &FilesystemSetupObject {
        &self.input.case_projection.setup.objects[self.target_setup_index]
    }

    pub fn target_initial(&self) -> &FilesystemInitialSandboxObject {
        &self.input.initial_sandbox.objects[self.target_initial_index]
    }

    pub fn parent_identity(&self) -> &FilesystemObjectIdentity {
        &self.parent_identity
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "kebab-case", rename_all_fields = "camelCase", deny_unknown_fields)]
pub enum FilesystemFinalObjectState {
    Existing { identity: FilesystemObjectIdentity },
    LinkEntry { identity: FilesystemObjectIdentity },
    Missing,
    Proposed,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FilesystemPathOccurrence {
    pub root: FilesystemLogicalRoot,
    pub root_binding_id: String,
    pub lexical_path: FilesystemPlatformPath,
    pub follow_mode: FilesystemFollowMode,
    pub parent_identity: FilesystemObjectIdentity,
    pub final_object_state: FilesystemFinalObjectState,
    pub effect_owner: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum FilesystemFollowMode {
    NoFollowFinal,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FilesystemEffectSlot {
    pub slot_id: String,
    pub capability: String,
    pub effect_owner: String,
    pub occurrence: FilesystemPathOccurrence,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FilesystemOracleNormalization {
    pub operation_request: FilesystemOperationRequest,
    pub runtime_slots: Vec<FilesystemEffectSlot>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum FilesystemCoreEvaluationPhase {
    Initial,
    PostFault,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FilesystemCoreDimension {
    pub slot_id: String,
    pub principal_key: String,
    pub outcome: FilesystemCoreOutcome,
    pub stratum: u8,
    pub reason_code: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum FilesystemCoreOutcome {
    Allow,
    Deny,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FilesystemCoreEvaluation {
    pub sequence: usize,
    pub phase: FilesystemCoreEvaluationPhase,
    pub outcome: FilesystemCoreOutcome,
    pub dimensions: Vec<FilesystemCoreDimension>,
    pub committed_slot_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FilesystemSharedCoreEffectInput {
    pub identity: EngineIdentity,
    pub edge_id: String,
    pub effect_slot_id: String,
    pub capability: String,
    pub effect_owner: String,
    pub occurrence: FilesystemPathOccurrence,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FilesystemSharedCoreStageRequest {
    pub identity: EngineIdentity,
    pub stage_id: String,
    pub principals: Vec<PrincipalRef>,
    pub effects: Vec<FilesystemSharedCoreEffectInput>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FilesystemSharedCoreCanonicalEffect {
    pub edge_id: String,
    pub effect_slot_id: String,
    pub capability: String,
    pub effect_owner: String,
    pub projection_id: String,
    pub occurrence: FilesystemPathOccurrence,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FilesystemSharedCoreDimension {
    pub principal: PrincipalRef,
    pub outcome: FilesystemCoreOutcome,
    pub stratum: u8,
    pub reason_code: String,
    pub positive_source: Option<PositiveSource>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FilesystemSharedCoreEffectDecision {
    pub effect: FilesystemSharedCoreCanonicalEffect,
    pub outcome: FilesystemCoreOutcome,
    pub dimensions: Vec<FilesystemSharedCoreDimension>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FilesystemSharedCoreStageDecision {
    pub stage_id: String,
    pub outcome: FilesystemCoreOutcome,
    pub effects: Vec<FilesystemSharedCoreEffectDecision>,
    pub committed_effects: Vec<FilesystemSharedCoreCanonicalEffect>,
    pub omitted_effect_slot_ids: Vec<String>,
    pub canonical_effects_json: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FilesystemSharedCoreEvaluation {
    pub sequence: usize,
    pub phase: FilesystemCoreEvaluationPhase,
    pub stage_request: FilesystemSharedCoreStageRequest,
    pub stage_decision: FilesystemSharedCoreStageDecision,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum FilesystemCoreDisposition {
    Evaluated,
    NotReached,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FilesystemExpectedCore {
    pub disposition: FilesystemCoreDisposition,
    pub evaluations: Vec<FilesystemCoreEvaluation>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum FilesystemDecision {
    Allow,
    Deny,
    Refuse,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum FilesystemDelivery {
    Delivered,
    NotApplicable,
    Withheld,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum FilesystemCleanup {
    Complete,
    NotStarted,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FilesystemExpectedResult {
    pub class: String,
    pub digest: Option<FilesystemExpectedResultDigest>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FilesystemExpectedResultDigest {
    pub source: FilesystemExpectedDigestSource,
    pub algorithm: FilesystemExpectedDigestAlgorithm,
    pub domain: String,
    pub preimage: FilesystemExpectedDigestPreimage,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum FilesystemExpectedDigestSource {
    InitialTargetMetadata,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum FilesystemExpectedDigestAlgorithm {
    HjcsSha256Base64url,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum FilesystemExpectedDigestPreimage {
    ExactInitialFilesystemMetadataProjectionJcs,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FilesystemObservedResult {
    pub class: String,
    pub digest: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum FilesystemSideEffectKind {
    Create,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FilesystemSideEffect {
    pub kind: FilesystemSideEffectKind,
    pub object_id: String,
    pub digest: Option<String>,
    pub final_kind: Option<FilesystemObjectKind>,
    pub mode: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FilesystemExpectedOutcome {
    pub slots: Vec<FilesystemEffectSlot>,
    pub decision: FilesystemDecision,
    pub result: FilesystemExpectedResult,
    pub side_effects: Vec<FilesystemSideEffect>,
    pub delivery: FilesystemDelivery,
    pub cleanup: FilesystemCleanup,
    pub core: FilesystemExpectedCore,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FilesystemExpectedObservation {
    pub case_id: String,
    pub edge_id: String,
    pub requirement_id: String,
    pub case_kind: String,
    pub slots: Vec<FilesystemEffectSlot>,
    pub decision: FilesystemDecision,
    pub result: FilesystemObservedResult,
    pub side_effects: Vec<FilesystemSideEffect>,
    pub delivery: FilesystemDelivery,
    pub cleanup: FilesystemCleanup,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FilesystemCandidateOracleOutput {
    pub core_identity: EngineIdentity,
    pub normalization: FilesystemOracleNormalization,
    pub normalized_slots_digest: String,
    pub core_evaluations: Vec<FilesystemSharedCoreEvaluation>,
    pub expected_outcome: FilesystemExpectedOutcome,
    pub expected_outcome_digest: String,
    pub expected_observation: FilesystemExpectedObservation,
    pub expected_observation_digest: String,
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
    EvaluateFilesystemCandidate {
        input: Box<FilesystemCandidateOracleInput>,
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
    globality: String,
    base_risk: u8,
    risk_rule_ids: Vec<String>,
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
    #[serde(default)]
    positive_channels: Option<Vec<String>>,
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
    protected_receipt_schema: Option<Value>,
    risk_rules: Vec<RiskRule>,
    risk_evaluation_spec: RiskEvaluationSpec,
    #[serde(default)]
    sensitive_environment_names: Vec<String>,
    #[serde(default)]
    loader_control_environment_names: Vec<String>,
    ambient_network_config_neutralization: Option<Value>,
    ip_address_classes: Option<IpAddressClasses>,
    #[serde(default)]
    system_information_kinds: Vec<Value>,
    public_suffix_input: Value,
    #[serde(default)]
    special_files: Vec<SpecialFile>,
    #[serde(default)]
    derivation_rules: Vec<Value>,
    #[serde(default)]
    dispositions: Vec<Value>,
    #[serde(default)]
    lifetime_contracts: Vec<Value>,
    #[serde(default)]
    reason_codes: Vec<ReasonCodeDefinition>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RiskRule {
    id: String,
    attachment: String,
    minimum_tier: u8,
    reason_code: String,
    trigger: RiskTrigger,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RiskTrigger {
    kind: String,
    fields: Vec<String>,
    values: Vec<String>,
    threshold: Option<u64>,
    classifier_data_id: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RiskEvaluationSpec {
    fields: Vec<RiskFieldSpec>,
    trigger_kinds: Vec<RiskTriggerSpec>,
    classifier_data_ids: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct RiskFieldSpec {
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
#[serde(rename_all = "camelCase")]
struct RiskTriggerSpec {
    kind: String,
    allowed_field_types: Vec<String>,
    values: String,
    threshold: String,
    classifier_data: String,
    algorithm: String,
}

#[derive(Debug, Clone, Deserialize)]
struct SpecialFile {
    classification: String,
    path: String,
    platform: String,
}

#[derive(Debug, Clone, Deserialize)]
struct ReasonCodeDefinition {
    id: String,
    class: String,
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
    ipv4_mapped_ipv6: String,
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
    predicate_id: String,
    reason_digest: String,
    canonical_row_digest: String,
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

#[derive(Debug, Clone)]
#[doc(hidden)]
pub struct Rev2State {
    payload: RuntimePayload,
    definitions: BTreeMap<String, Definition>,
    edges: BTreeMap<String, EdgeSemantics>,
    schemas: BTreeMap<String, TypedSchema>,
    projections: BTreeMap<String, Projection>,
    match_operations: BTreeMap<String, String>,
    risk_rules: BTreeMap<String, RiskRule>,
    risk_fields: BTreeMap<String, RiskFieldSpec>,
    global_risk_rule_ids: Vec<String>,
}

#[derive(Debug)]
struct RiskIndex {
    rules: BTreeMap<String, RiskRule>,
    fields: BTreeMap<String, RiskFieldSpec>,
    global_rule_ids: Vec<String>,
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
        let risk_index = validate_runtime_risk_contract(&payload, &definitions)?;
        Ok(Self {
            state: Arc::new(Rev2State {
                payload,
                definitions,
                edges,
                schemas,
                projections,
                match_operations,
                risk_rules: risk_index.rules,
                risk_fields: risk_index.fields,
                global_risk_rule_ids: risk_index.global_rule_ids,
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

    /// Recompute the cache's complete normalized negative-inventory digest.
    /// Keeping normalization and row preimages inside the shared core prevents
    /// runtime protocol consumers from drifting into a second evaluator.
    ///
    /// @ref LLP 0019#bounded-decision-cache [implements] — Cached positive
    /// candidates bind the exact current strata 1–7 inventory and are accepted
    /// only after the same shared core re-evaluates it.
    pub fn negative_inventory_digest(
        &self,
        input: &DecisionPolicyInput,
    ) -> Result<String, CoreError> {
        let normalized = self.normalize_policy(input)?;
        inventory_digest(
            REV2_RUNTIME_NEGATIVE_INVENTORY_DOMAIN,
            &negative_inventory(&normalized)?,
        )
    }

    /// Evaluate generated review risk without consulting or mutating any
    /// authorization state.
    ///
    /// @ref LLP 0019#risk-and-review [implements] — Base tiers and every
    /// applicable promotion reason come from the authenticated runtime
    /// vocabulary; risk output never participates in allow/deny precedence.
    pub fn evaluate_risk(
        &self,
        input: &RiskEvaluationInput,
    ) -> Result<RiskEvaluation, CoreError> {
        self.validate_identity(&input.identity)?;
        if input.authorities.len() > MAX_RISK_AUTHORITIES {
            return Err(CoreError::new(
                REASON_SCHEMA_INVALID,
                "risk evaluation has an over-bound authority set",
            ));
        }
        if input.authorities.is_empty() {
            if !input.global_fields.is_empty() {
                return Err(CoreError::new(
                    REASON_SCHEMA_INVALID,
                    "an empty canonical policy cannot carry global risk facts",
                ));
            }
            return Ok(RiskEvaluation {
                base_tier: 0,
                tier: 0,
                reasons: Vec::new(),
            });
        }

        let mut base_tier = 0;
        let mut reasons: BTreeMap<(String, String), RiskReason> = BTreeMap::new();
        for authority in &input.authorities {
            if authority.capability.is_empty() || authority.capability.len() > 256 {
                return Err(CoreError::new(
                    REASON_SCHEMA_INVALID,
                    "risk authority capability is empty or over-bound",
                ));
            }
            let definition = self.definition(&authority.capability)?;
            base_tier = base_tier.max(definition.base_risk);
            let mut fields = self.validate_risk_field_scope(&authority.fields)?;
            fields.insert(
                "definition.lifecycle".to_string(),
                Value::String(definition.lifecycle.clone()),
            );
            fields.insert(
                "definition.globality".to_string(),
                Value::String(definition.globality.clone()),
            );
            for rule_id in &definition.risk_rule_ids {
                let rule = self.risk_rules.get(rule_id).ok_or_else(|| {
                    CoreError::new(
                        REASON_SCHEMA_INVALID,
                        format!("definition {} names unknown risk rule {rule_id}", definition.id),
                    )
                })?;
                if risk_rule_applies(
                    rule,
                    &fields,
                    &self.payload.policy_rules_and_classifiers,
                )? {
                    insert_risk_reason(&mut reasons, rule)?;
                }
            }
        }

        let global_fields = self.validate_risk_field_scope(&input.global_fields)?;
        for rule_id in &self.global_risk_rule_ids {
            let rule = self.risk_rules.get(rule_id).ok_or_else(|| {
                CoreError::new(
                    REASON_SCHEMA_INVALID,
                    format!("global risk index names unknown rule {rule_id}"),
                )
            })?;
            if risk_rule_applies(
                rule,
                &global_fields,
                &self.payload.policy_rules_and_classifiers,
            )? {
                insert_risk_reason(&mut reasons, rule)?;
            }
        }

        let reasons: Vec<RiskReason> = reasons.into_values().collect();
        let tier = reasons
            .iter()
            .fold(base_tier, |tier, reason| tier.max(reason.minimum_tier));
        Ok(RiskEvaluation {
            base_tier,
            tier,
            reasons,
        })
    }

    fn validate_risk_field_scope(
        &self,
        fields: &BTreeMap<String, Value>,
    ) -> Result<BTreeMap<String, Value>, CoreError> {
        if fields.len() > MAX_RISK_FIELDS_PER_SCOPE {
            return Err(CoreError::new(
                REASON_SCHEMA_INVALID,
                "risk field scope exceeds its generated-field bound",
            ));
        }
        let mut validated = BTreeMap::new();
        for (name, value) in fields {
            if name.starts_with("definition.") {
                return Err(CoreError::new(
                    REASON_SCHEMA_INVALID,
                    format!("risk field {name} is derived from the runtime definition"),
                ));
            }
            let spec = self.risk_fields.get(name).ok_or_else(|| {
                CoreError::new(REASON_SCHEMA_INVALID, format!("unknown risk field {name}"))
            })?;
            validate_risk_field_value(spec, value)?;
            validated.insert(name.clone(), value.clone());
        }
        Ok(validated)
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
        let static_floor = self.normalize_named_selectors(
            &input.static_floor,
            SelectorPolarity::Positive,
            PrincipalRequirement::Exact,
            "static floor",
        )?;
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
                || row.predicate_id.trim().is_empty()
                || row.predicate_id.len() > 256
            {
                return Err(CoreError::new(
                    REASON_SCHEMA_INVALID,
                    "protected exception source or predicate identity is invalid",
                ));
            }
            validate_digest_string(&row.reason_digest)?;
            validate_digest_string(&row.canonical_row_digest)?;
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
            let definition = self.definition(&selector.capability)?;
            if definition.protected_receipt_predicate_id.as_deref()
                != Some(row.predicate_id.as_str())
                || !self.generated_protected_predicate_exists(&row.predicate_id)
            {
                return Err(CoreError::new(
                    REASON_SCHEMA_INVALID,
                    "protected exception names no generated definition predicate",
                ));
            }
            let expected_digest = protected_row_digest(
                &row.source_id,
                &selector,
                &row.predicate_id,
                &row.reason_digest,
            )?;
            if row.canonical_row_digest != expected_digest {
                return Err(CoreError::new(
                    REASON_SCHEMA_INVALID,
                    "protected exception canonical row digest is invalid",
                ));
            }
            if !static_floor.iter().any(|static_row| {
                static_row.source_id == row.source_id && static_row.selector == selector
            }) {
                return Err(CoreError::new(
                    REASON_SCHEMA_INVALID,
                    "protected exception does not match its exact static row",
                ));
            }
            protected_exceptions.push(NormalizedProtectedException {
                source_id: row.source_id.clone(),
                predicate_id: row.predicate_id.clone(),
                reason_digest: row.reason_digest.clone(),
                canonical_row_digest: row.canonical_row_digest.clone(),
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
        let expected_receipt_digests: BTreeSet<String> = protected_exceptions
            .iter()
            .map(|exception| exception.canonical_row_digest.clone())
            .collect();
        if receipt_digests != expected_receipt_digests {
            return Err(CoreError::new(
                REASON_SCHEMA_INVALID,
                "validated receipt rows do not exactly cover protected canonical rows",
            ));
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
        // Alternative branches can bind different positive-source domains.
        // The generated effect row is authoritative when present; legacy and
        // homogeneous edges continue to use the edge-wide intersection.
        let positive_channels = edge
            .effects
            .iter()
            .find(|candidate| {
                candidate.effect_slot_id == effect.effect_slot_id
                    && candidate.capability == effect.capability
            })
            .and_then(|candidate| candidate.positive_channels.as_ref())
            .unwrap_or(&edge.positive_channels);
        if edge.gate.mechanism == "deny-only" && !principal.is_root() {
            return Ok(deny(3, REASON_LIFECYCLE));
        }

        let mut protected_static = None;
        if self.is_metadata_effect(effect)? {
            let mut exception = None;
            for row in &policy.protected_exceptions {
                if !selector_principal_matches(&row.selector, principal, false) {
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
                row.source_id == exception.source_id
                    && row.selector == exception.selector
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
                Some(predicate_id) => exact_static.is_some_and(|row| {
                    policy.protected_exceptions.iter().any(|exception| {
                        exception.source_id == row.source_id
                            && exception.selector == row.selector
                            && exception.predicate_id == *predicate_id
                            && policy
                                .validated_receipt_row_digests
                                .contains(&exception.canonical_row_digest)
                    })
                }),
            };
            // No root-edge predicate is advertised by the current generated
            // vocabulary. An unknown future predicate fails closed until its
            // generated evaluator lands.
            let root_edge_ok = definition.root_edge_predicate_id.is_none();
            let predicate_channel_ok = positive_channels.iter().any(|channel| channel == "floor");
            if !(edge_ok
                && positive_required_ok
                && receipt_ok
                && root_edge_ok
                && predicate_channel_ok)
            {
                return Ok(deny(8, REASON_POSITIVE_PREDICATE));
            }
            let row = exact_static.expect("every current positive predicate requires static row");
            return Ok(allow(
                8,
                PositiveSource {
                    kind: "predicate-static-row".to_string(),
                    source_id: row.source_id.clone(),
                    generation: None,
                },
            ));
        }

        if definition.channels.iter().any(|channel| channel == "floor")
            && positive_channels.iter().any(|channel| channel == "floor")
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
            && positive_channels.iter().any(|channel| channel == "handle")
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
            && positive_channels.iter().any(|channel| channel == "session")
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
            && positive_channels.iter().any(|channel| channel == "implicit-self")
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
            && positive_channels.iter().any(|channel| channel == "ambient-root")
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
            && positive_channels.iter().any(|channel| channel == "mode-fallback")
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
                if selector.get("kind").and_then(Value::as_str) != Some("path-exact")
                    || selector.get("root") != occurrence.get("root")
                {
                    return Ok(false);
                }
                let Some(selector_path) = selector.get("path") else {
                    return Ok(false);
                };
                let Some(lexical_path) = occurrence.get("lexicalPath") else {
                    return Ok(false);
                };
                Ok(decode_platform_path_bytes(selector_path)?
                    == decode_platform_path_bytes(lexical_path)?)
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

    fn generated_protected_predicate_exists(&self, predicate_id: &str) -> bool {
        let rules = &self.payload.policy_rules_and_classifiers;
        let predicate = rules.predicates.iter().find(|row| {
            row.get("id").and_then(Value::as_str) == Some(predicate_id)
        });
        let Some(predicate) = predicate else {
            return false;
        };
        if predicate.get("kind").and_then(Value::as_str) != Some("definition-positive")
            || predicate
                .pointer("/evaluator/algorithm")
                .and_then(Value::as_str)
                != Some("authenticated-protected-receipt")
        {
            return false;
        }
        let schema_id = rules
            .protected_receipt_schema
            .as_ref()
            .and_then(|schema| schema.get("id"))
            .and_then(Value::as_str);
        matches!(
            (generated_id_version(predicate_id), schema_id.and_then(generated_id_version)),
            (Some(predicate_version), Some(schema_version)) if predicate_version == schema_version
        )
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
                let payload = object.get("value").and_then(Value::as_str).ok_or_else(|| {
                    CoreError::new(REASON_SCHEMA_INVALID, "platform path has no value")
                })?;
                if !matches!(encoding, "opaque-base64url" | "unicode") {
                    return Err(CoreError::new(
                        REASON_SCHEMA_INVALID,
                        "unknown platform path encoding",
                    ));
                }
                decode_platform_path_payload(encoding, payload)?;
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

const FILESYSTEM_EXECUTION_PROJECTION_DIGEST_DOMAIN: &str =
    "oden:capsec:filesystem-execution-projection:2";
const FILESYSTEM_SANDBOX_INVENTORY_DIGEST_DOMAIN: &str =
    "oden:capsec:filesystem-sandbox-inventory:2";
const FILESYSTEM_CASE_PLAN_DIGEST_DOMAIN: &str = "oden:capsec:filesystem-case-plan:2";
const FILESYSTEM_LSTAT_METADATA_DIGEST_DOMAIN: &str =
    "oden:capsec:filesystem-lstat-metadata:2";
const FILESYSTEM_NORMALIZED_SLOTS_DIGEST_DOMAIN: &str =
    "oden:capsec:filesystem-normalized-slots:2";
const FILESYSTEM_EXPECTED_OUTCOME_DIGEST_DOMAIN: &str =
    "oden:capsec:filesystem-expected-outcome:2";
const FILESYSTEM_EXPECTED_OBSERVATION_DIGEST_DOMAIN: &str =
    "oden:capsec:filesystem-observed-result:2";
const FILESYSTEM_SANDBOX_INVENTORY_SCHEMA: &str =
    "oden/capsec-filesystem-sandbox-inventory/2";

fn generated_case_kind(
    kind: generated::Rev2FilesystemCandidateCaseKind,
) -> &'static str {
    use generated::Rev2FilesystemCandidateCaseKind as Kind;
    match kind {
        Kind::AuthorableCrossActionDenial => "authorable-cross-action-denial",
        Kind::AuthorableMissingPrincipalDenial => "authorable-missing-principal-denial",
        Kind::AuthorableNegative => "authorable-negative",
        Kind::AuthorableNoUserDenial => "authorable-no-user-denial",
        Kind::AuthorablePositive => "authorable-positive",
        Kind::AuthorableQuarantineDenial => "authorable-quarantine-denial",
        Kind::AuthorableWrongPrincipalDenial => "authorable-wrong-principal-denial",
        Kind::LstatExisting => "lstat-existing",
        Kind::LstatFinalMissing => "lstat-final-missing",
        Kind::LstatLinkEntry => "lstat-link-entry",
        Kind::MalformedResourceRefusal => "malformed-resource-refusal",
        Kind::MkdirExistingConflict => "mkdir-existing-conflict",
        Kind::MkdirLinkConflict => "mkdir-link-conflict",
        Kind::MkdirMissingCreate => "mkdir-missing-create",
        Kind::MultiEffectAllAuthorized => "multi-effect-all-authorized",
        Kind::MultiEffectNMinusOneDenied => "multi-effect-n-minus-one-denied",
        Kind::MultiEffectNoPartialCommit => "multi-effect-no-partial-commit",
        Kind::StagedBarrierAuthorization => "staged-barrier:authorization",
        Kind::StagedBarrierCancellation => "staged-barrier:cancellation",
        Kind::StagedBarrierCleanup => "staged-barrier:cleanup",
        Kind::StagedBarrierRevocation => "staged-barrier:revocation",
    }
}

fn generated_case_plan(
    case_kind: &str,
) -> Result<&'static generated::Rev2FilesystemCandidateCasePlanSpec, CoreError> {
    REV2_FILESYSTEM_CANDIDATE_CASE_PLANS
        .iter()
        .find(|plan| generated_case_kind(plan.case_kind) == case_kind)
        .ok_or_else(|| {
            CoreError::new(
                REASON_SCHEMA_INVALID,
                format!("unknown filesystem candidate case kind {case_kind}"),
            )
        })
}

fn generated_case_plan_digest(case_kind: &str) -> Result<String, CoreError> {
    let payload = parse_strict_json(REV2_RUNTIME_SEMANTIC_PAYLOAD_JSON)?;
    let plans = payload
        .pointer("/policyRulesAndClassifiers/filesystemCandidateCasePlans")
        .and_then(Value::as_array)
        .ok_or_else(|| {
            CoreError::new(
                REASON_SCHEMA_INVALID,
                "generated filesystem case-plan payload is missing",
            )
        })?;
    let plan = plans
        .iter()
        .find(|plan| plan.get("caseKind").and_then(Value::as_str) == Some(case_kind))
        .ok_or_else(|| {
            CoreError::new(
                REASON_SCHEMA_INVALID,
                format!("generated filesystem case plan is missing {case_kind}"),
            )
        })?;
    hjcs_digest(FILESYSTEM_CASE_PLAN_DIGEST_DOMAIN, plan)
}

fn operation_edge_id(
    operation: &generated::Rev2FilesystemCandidateOperationSpec,
) -> &'static str {
    match operation {
        generated::Rev2FilesystemCandidateOperationSpec::LstatSync { edge_id, .. }
        | generated::Rev2FilesystemCandidateOperationSpec::MkdirSync { edge_id, .. } => edge_id,
    }
}

fn generated_operation(
    edge_id: &str,
) -> Result<&'static generated::Rev2FilesystemCandidateOperationSpec, CoreError> {
    REV2_FILESYSTEM_CANDIDATE_OPERATIONS
        .iter()
        .find(|operation| operation_edge_id(operation) == edge_id)
        .ok_or_else(|| {
            CoreError::new(
                REASON_SCHEMA_INVALID,
                format!("unknown filesystem candidate edge {edge_id}"),
            )
        })
}

fn operation_slots(
    operation: &generated::Rev2FilesystemCandidateOperationSpec,
) -> &'static [generated::Rev2FilesystemCandidateSlotSpec] {
    match operation {
        generated::Rev2FilesystemCandidateOperationSpec::LstatSync { ordered_slots, .. }
        | generated::Rev2FilesystemCandidateOperationSpec::MkdirSync { ordered_slots, .. } => {
            ordered_slots
        }
    }
}

fn operation_classifications(
    operation: &generated::Rev2FilesystemCandidateOperationSpec,
) -> &'static [generated::Rev2FilesystemCandidateTargetStateClassificationSpec] {
    match operation {
        generated::Rev2FilesystemCandidateOperationSpec::LstatSync {
            target_state_classifications,
            ..
        }
        | generated::Rev2FilesystemCandidateOperationSpec::MkdirSync {
            target_state_classifications,
            ..
        } => target_state_classifications,
    }
}

fn operation_authorized_outcomes(
    operation: &generated::Rev2FilesystemCandidateOperationSpec,
) -> &'static [generated::Rev2FilesystemCandidateAuthorizedOutcomeSpec] {
    match operation {
        generated::Rev2FilesystemCandidateOperationSpec::LstatSync {
            authorized_outcomes,
            ..
        }
        | generated::Rev2FilesystemCandidateOperationSpec::MkdirSync {
            authorized_outcomes,
            ..
        } => authorized_outcomes,
    }
}

fn generated_capability(
    capability: generated::Rev2CapabilityId,
) -> Result<&'static str, CoreError> {
    match capability {
        generated::Rev2CapabilityId::FsList => Ok("fs:list"),
        generated::Rev2CapabilityId::FsWrite => Ok("fs:write"),
        _ => Err(CoreError::new(
            REASON_SCHEMA_INVALID,
            "filesystem operation contains a non-filesystem candidate capability",
        )),
    }
}

fn generated_initial_kind(
    kind: FilesystemObjectKind,
) -> generated::Rev2FilesystemCandidateInitialObjectKind {
    use generated::Rev2FilesystemCandidateInitialObjectKind as Generated;
    match kind {
        FilesystemObjectKind::BlockDevice => Generated::BlockDevice,
        FilesystemObjectKind::CharacterDevice => Generated::CharacterDevice,
        FilesystemObjectKind::Directory => Generated::Directory,
        FilesystemObjectKind::Fifo => Generated::Fifo,
        FilesystemObjectKind::Missing => Generated::Missing,
        FilesystemObjectKind::RegularFile => Generated::RegularFile,
        FilesystemObjectKind::Socket => Generated::Socket,
        FilesystemObjectKind::Symlink => Generated::Symlink,
    }
}

fn generated_target_edge_id(
    edge_id: generated::Rev2FilesystemCandidateOperationEdgeId,
) -> &'static str {
    use generated::Rev2FilesystemCandidateOperationEdgeId as Edge;
    match edge_id {
        Edge::NativeOpExtFsOpsRsOpFsLstatSync => {
            "native-op:ext/fs/ops.rs#op_fs_lstat_sync"
        }
        Edge::NativeOpExtFsOpsRsOpFsMkdirSync => {
            "native-op:ext/fs/ops.rs#op_fs_mkdir_sync"
        }
    }
}

fn generated_trace_phase(
    phase: FilesystemTracePhase,
) -> generated::Rev2FilesystemCandidateTracePhase {
    use generated::Rev2FilesystemCandidateTracePhase as Generated;
    match phase {
        FilesystemTracePhase::HarnessAdmitted => Generated::HarnessAdmitted,
        FilesystemTracePhase::PublicOpEntered => Generated::PublicOpEntered,
        FilesystemTracePhase::ActorsCaptured => Generated::ActorsCaptured,
        FilesystemTracePhase::NamespaceGateAcquired => Generated::NamespaceGateAcquired,
        FilesystemTracePhase::DiscoveryComplete => Generated::DiscoveryComplete,
        FilesystemTracePhase::AuthorizationComplete => Generated::AuthorizationComplete,
        FilesystemTracePhase::SourcesRevalidated => Generated::SourcesRevalidated,
        FilesystemTracePhase::TargetRevalidated => Generated::TargetRevalidated,
        FilesystemTracePhase::PreparationComplete => Generated::PreparationComplete,
        FilesystemTracePhase::PostPrepareRevalidated => Generated::PostPrepareRevalidated,
        FilesystemTracePhase::CoreCommitRecorded => Generated::CoreCommitRecorded,
        FilesystemTracePhase::NativeCommitRecorded => Generated::NativeCommitRecorded,
        FilesystemTracePhase::OperationCompleted => Generated::OperationCompleted,
        FilesystemTracePhase::DeliverySerialized => Generated::DeliverySerialized,
        FilesystemTracePhase::ProvisionalResourcesReleased => {
            Generated::ProvisionalResourcesReleased
        }
        FilesystemTracePhase::NamespaceGateReleased => Generated::NamespaceGateReleased,
        FilesystemTracePhase::HarnessExited => Generated::HarnessExited,
    }
}

// This reverse projection remains dormant until the first reviewed
// filesystem conformance case row is generated.
#[allow(dead_code)]
fn filesystem_trace_phase(
    phase: generated::Rev2FilesystemCandidateTracePhase,
) -> FilesystemTracePhase {
    use generated::Rev2FilesystemCandidateTracePhase as Generated;
    match phase {
        Generated::HarnessAdmitted => FilesystemTracePhase::HarnessAdmitted,
        Generated::PublicOpEntered => FilesystemTracePhase::PublicOpEntered,
        Generated::ActorsCaptured => FilesystemTracePhase::ActorsCaptured,
        Generated::NamespaceGateAcquired => FilesystemTracePhase::NamespaceGateAcquired,
        Generated::DiscoveryComplete => FilesystemTracePhase::DiscoveryComplete,
        Generated::AuthorizationComplete => FilesystemTracePhase::AuthorizationComplete,
        Generated::SourcesRevalidated => FilesystemTracePhase::SourcesRevalidated,
        Generated::TargetRevalidated => FilesystemTracePhase::TargetRevalidated,
        Generated::PreparationComplete => FilesystemTracePhase::PreparationComplete,
        Generated::PostPrepareRevalidated => FilesystemTracePhase::PostPrepareRevalidated,
        Generated::CoreCommitRecorded => FilesystemTracePhase::CoreCommitRecorded,
        Generated::NativeCommitRecorded => FilesystemTracePhase::NativeCommitRecorded,
        Generated::OperationCompleted => FilesystemTracePhase::OperationCompleted,
        Generated::DeliverySerialized => FilesystemTracePhase::DeliverySerialized,
        Generated::ProvisionalResourcesReleased => {
            FilesystemTracePhase::ProvisionalResourcesReleased
        }
        Generated::NamespaceGateReleased => FilesystemTracePhase::NamespaceGateReleased,
        Generated::HarnessExited => FilesystemTracePhase::HarnessExited,
    }
}

fn target_state(
    operation: &generated::Rev2FilesystemCandidateOperationSpec,
    kind: FilesystemObjectKind,
) -> Result<generated::Rev2FilesystemCandidateTargetState, CoreError> {
    let generated_kind = generated_initial_kind(kind);
    operation_classifications(operation)
        .iter()
        .find(|classification| classification.initial_kinds.contains(&generated_kind))
        .map(|classification| classification.target_state)
        .ok_or_else(|| {
            CoreError::new(
                REASON_SCHEMA_INVALID,
                "filesystem target kind has no generated classification",
            )
        })
}

fn validate_generated_operation_model(
    operation: &generated::Rev2FilesystemCandidateOperationSpec,
) -> Result<(), CoreError> {
    use generated::*;
    let valid = match operation {
        Rev2FilesystemCandidateOperationSpec::LstatSync {
            follow_mode,
            input_bindings,
            ordered_slots,
            result_model_id,
            ..
        } => {
            *follow_mode == Rev2FilesystemCandidateFollowMode::NoFollowFinal
                && input_bindings.target_ref
                    == Rev2FilesystemCandidateTargetRefInput::OperationRequestTargetRef
                && input_bindings.target_state
                    == Rev2FilesystemCandidateTargetStateInput::InitialSandboxObjectStateByTargetRef
                && input_bindings.parent_identity
                    == Rev2FilesystemCandidateParentIdentityInput::InitialSandboxParentIdentityByTargetRef
                && input_bindings.slot_actors
                    == Rev2FilesystemCandidateSlotActorsInput::ExecutionPlanActorBySlot
                && *result_model_id
                    == Rev2FilesystemCandidateLstatResultModelId::FilesystemResultLstatNoFollow2
                && matches!(
                    ordered_slots,
                    [Rev2FilesystemCandidateSlotSpec {
                        role: Rev2FilesystemCandidateSlotRole::TargetListObservation,
                        capability: Rev2CapabilityId::FsList,
                        ..
                    }]
                )
        }
        Rev2FilesystemCandidateOperationSpec::MkdirSync {
            follow_mode,
            input_bindings,
            recursive_policy,
            mode_derivation,
            ordered_slots,
            result_model_id,
            ..
        } => {
            *follow_mode == Rev2FilesystemCandidateFollowMode::NoFollowFinal
                && input_bindings.target_ref
                    == Rev2FilesystemCandidateTargetRefInput::OperationRequestTargetRef
                && input_bindings.target_state
                    == Rev2FilesystemCandidateTargetStateInput::InitialSandboxObjectStateByTargetRef
                && input_bindings.parent_identity
                    == Rev2FilesystemCandidateParentIdentityInput::InitialSandboxParentIdentityByTargetRef
                && input_bindings.slot_actors
                    == Rev2FilesystemCandidateSlotActorsInput::ExecutionPlanActorBySlot
                && input_bindings.requested_mode
                    == Rev2FilesystemCandidateRequestedModeInput::OperationRequestRequestedMode
                && input_bindings.captured_umask
                    == Rev2FilesystemCandidateCapturedUmaskInput::ParentCaptureCapturedUmask
                && *recursive_policy == Rev2FilesystemCandidateRecursivePolicy::RequireFalse
                && mode_derivation.algorithm
                    == Rev2FilesystemCandidateModeAlgorithm::DirectoryTypeOrMaskedRequestMinusUmask
                && mode_derivation.requested_mode_mask == 0o777
                && mode_derivation.captured_umask_mask == 0o777
                && mode_derivation.required_captured_umask == 0o077
                && mode_derivation.directory_type_bits == 0o040000
                && *result_model_id
                    == Rev2FilesystemCandidateMkdirResultModelId::FilesystemResultMkdirNoReplace2
                && matches!(
                    ordered_slots,
                    [
                        Rev2FilesystemCandidateSlotSpec {
                            role: Rev2FilesystemCandidateSlotRole::TargetWriteIntent,
                            capability: Rev2CapabilityId::FsWrite,
                            ..
                        },
                        Rev2FilesystemCandidateSlotSpec {
                            role: Rev2FilesystemCandidateSlotRole::TargetListObservation,
                            capability: Rev2CapabilityId::FsList,
                            ..
                        }
                    ]
                )
        }
    };
    if !valid {
        return Err(CoreError::new(
            REASON_SCHEMA_INVALID,
            "generated filesystem operation uses an unsupported future contract",
        ));
    }
    Ok(())
}

fn validate_generated_authorized_outcome(
    operation: &generated::Rev2FilesystemCandidateOperationSpec,
    state: generated::Rev2FilesystemCandidateTargetState,
    outcome: &generated::Rev2FilesystemCandidateAuthorizedOutcomeSpec,
) -> Result<(), CoreError> {
    use generated::*;
    let common = outcome.target_state == state
        && outcome.delivery == Rev2FilesystemCandidateDelivery::Delivered
        && outcome.cleanup == Rev2FilesystemCandidateCleanup::Complete
        && outcome.normalized_slot_states.len() == operation_slots(operation).len()
        && outcome
            .normalized_slot_states
            .iter()
            .zip(operation_slots(operation))
            .all(|(normalized, slot)| {
                normalized.effect_slot_id == slot.effect_slot_id
                    && match normalized.final_object_state {
                        Rev2FilesystemCandidateFinalObjectState::Existing
                        | Rev2FilesystemCandidateFinalObjectState::LinkEntry => {
                            normalized.identity_source
                                == Rev2FilesystemCandidateIdentitySource::InitialTargetIdentity
                        }
                        Rev2FilesystemCandidateFinalObjectState::Missing
                        | Rev2FilesystemCandidateFinalObjectState::Proposed => {
                            normalized.identity_source
                                == Rev2FilesystemCandidateIdentitySource::None
                        }
                    }
            });
    let model_valid = match (operation, state) {
        (
            Rev2FilesystemCandidateOperationSpec::LstatSync { .. },
            Rev2FilesystemCandidateTargetState::Existing
            | Rev2FilesystemCandidateTargetState::LinkEntry,
        ) => {
            outcome.native_result.class == Rev2FilesystemCandidateNativeResultClass::LstatComplete
                && outcome.native_result.metadata_digest.is_some_and(|model| {
                    model.source
                        == Rev2FilesystemCandidateMetadataDigestSource::InitialTargetMetadata
                        && model.algorithm
                            == Rev2FilesystemCandidateMetadataDigestAlgorithm::HjcsSha256Base64url
                        && model.domain
                            == Rev2FilesystemCandidateMetadataDigestDomain::OdenCapsecFilesystemLstatMetadata2
                        && model.preimage
                            == Rev2FilesystemCandidateMetadataDigestPreimage::ExactInitialFilesystemMetadataProjectionJcs
                })
                && outcome.permitted_side_effects.is_empty()
        }
        (
            Rev2FilesystemCandidateOperationSpec::LstatSync { .. },
            Rev2FilesystemCandidateTargetState::Missing,
        ) => {
            outcome.native_result.class == Rev2FilesystemCandidateNativeResultClass::LstatNotFound
                && outcome.native_result.metadata_digest.is_none()
                && outcome.permitted_side_effects.is_empty()
        }
        (
            Rev2FilesystemCandidateOperationSpec::MkdirSync { .. },
            Rev2FilesystemCandidateTargetState::Existing
            | Rev2FilesystemCandidateTargetState::LinkEntry,
        ) => {
            outcome.native_result.class
                == Rev2FilesystemCandidateNativeResultClass::MkdirAlreadyExists
                && outcome.native_result.metadata_digest.is_none()
                && outcome.permitted_side_effects.is_empty()
        }
        (
            Rev2FilesystemCandidateOperationSpec::MkdirSync { .. },
            Rev2FilesystemCandidateTargetState::Missing,
        ) => {
            outcome.native_result.class == Rev2FilesystemCandidateNativeResultClass::MkdirComplete
                && outcome.native_result.metadata_digest.is_none()
                && matches!(
                    outcome.permitted_side_effects,
                    [Rev2FilesystemCandidateCreateSideEffect {
                        kind: Rev2FilesystemCandidateSideEffectKind::Create,
                        object_id_source:
                            Rev2FilesystemCandidateSideEffectObjectIdSource::TargetRefObjectId,
                        digest_source: Rev2FilesystemCandidateSideEffectDigestSource::None,
                        final_kind: Rev2FilesystemCandidateSideEffectFinalKind::Directory,
                        mode_source:
                            Rev2FilesystemCandidateSideEffectModeSource::EffectiveDirectoryMode,
                    }]
                )
        }
    };
    if !common || !model_valid {
        return Err(CoreError::new(
            REASON_SCHEMA_INVALID,
            "generated filesystem outcome uses an unsupported future result contract",
        ));
    }
    Ok(())
}

fn mode_matches_case_plan(
    mode: FilesystemExecutionMode,
    plan: generated::Rev2FilesystemCandidateExecutionMode,
) -> bool {
    matches!(
        (mode, plan),
        (
            FilesystemExecutionMode::Audit,
            generated::Rev2FilesystemCandidateExecutionMode::Audit
        ) | (
            FilesystemExecutionMode::Enforce,
            generated::Rev2FilesystemCandidateExecutionMode::Enforce
        )
    )
}

fn mutation_matches_case_plan(
    mutation: FilesystemInputMutation,
    plan: generated::Rev2FilesystemCandidateInputMutation,
) -> bool {
    matches!(
        (mutation, plan),
        (
            FilesystemInputMutation::None,
            generated::Rev2FilesystemCandidateInputMutation::None
        ) | (
            FilesystemInputMutation::TargetPathDotDot,
            generated::Rev2FilesystemCandidateInputMutation::TargetPathDotDot
        )
    )
}

fn validate_fault_plan(
    projection: &FilesystemExecutionProjection,
    operation: &generated::Rev2FilesystemCandidateOperationSpec,
    plan: &generated::Rev2FilesystemCandidateCasePlanSpec,
) -> Result<(), CoreError> {
    use generated::Rev2FilesystemCandidateFaultPlan as Generated;
    let expected = match plan.fault_plan {
        Generated::None => None,
        Generated::CancelSafeBoundary => Some(FilesystemFaultPlan {
            barrier_id: "case-plan:after-authorization".to_string(),
            phase: FilesystemFaultPhase::AfterAuthorization,
            action: FilesystemFaultAction::ActorSequence {
                operation: FilesystemActorSequenceOperation::Cancel,
            },
        }),
        Generated::OmitRequiredStage => match operation {
            generated::Rev2FilesystemCandidateOperationSpec::LstatSync { .. } => {
                Some(FilesystemFaultPlan {
                    barrier_id: "case-plan:after-target-revalidation".to_string(),
                    phase: FilesystemFaultPhase::AfterTargetRevalidation,
                    action: FilesystemFaultAction::ActorSequence {
                        operation: FilesystemActorSequenceOperation::OmitObservation,
                    },
                })
            }
            generated::Rev2FilesystemCandidateOperationSpec::MkdirSync { .. } => {
                Some(FilesystemFaultPlan {
                    barrier_id: "case-plan:after-preparation".to_string(),
                    phase: FilesystemFaultPhase::AfterPreparation,
                    action: FilesystemFaultAction::ActorSequence {
                        operation: FilesystemActorSequenceOperation::OmitPostPrepareRevalidation,
                    },
                })
            }
        },
        Generated::RevokeAllAfterAuthorization | Generated::RevokeLastAfterAuthorization => {
            let indexes: Vec<usize> = if plan.fault_plan == Generated::RevokeAllAfterAuthorization {
                (0..operation_slots(operation).len()).collect()
            } else {
                vec![operation_slots(operation).len() - 1]
            };
            Some(FilesystemFaultPlan {
                barrier_id: "case-plan:after-authorization".to_string(),
                phase: FilesystemFaultPhase::AfterAuthorization,
                action: FilesystemFaultAction::AuthorityRevocation {
                    remove_source_ids: indexes
                        .iter()
                        .map(|index| format!("case:session-grant:{index}"))
                        .collect(),
                    activate_source_ids: indexes
                        .iter()
                        .map(|index| format!("case:session-revocation:{index}"))
                        .collect(),
                },
            })
        }
    };
    if projection.fault_plan != expected {
        return Err(CoreError::new(
            REASON_SCHEMA_INVALID,
            "filesystem fault plan differs from the generated case plan",
        ));
    }
    Ok(())
}

fn validate_case_principal_plan(
    projection: &FilesystemExecutionProjection,
    operation: &generated::Rev2FilesystemCandidateOperationSpec,
    plan: &generated::Rev2FilesystemCandidateCasePlanSpec,
) -> Result<Option<String>, CoreError> {
    use generated::Rev2FilesystemCandidatePrincipalPlan as Plan;
    let owner = projection
        .principals
        .iter()
        .find(|principal| principal.key == projection.effect_owner_key)
        .ok_or_else(|| {
            CoreError::new(
                REASON_SCHEMA_INVALID,
                "filesystem effect owner is absent from the principal pool",
            )
        })?;
    let actor_principal = match plan.principal_plan {
        Plan::Actor => {
            if projection.principals.len() != 1
                || owner.kind != PrincipalKind::Package
                || projection.constrained_principal_keys != [projection.effect_owner_key.clone()]
            {
                return Err(CoreError::new(
                    REASON_SCHEMA_INVALID,
                    "filesystem projection does not implement the actor principal plan",
                ));
            }
            Some(projection.effect_owner_key.clone())
        }
        Plan::ActorAndOther => {
            let other = projection
                .principals
                .iter()
                .find(|principal| principal.key != projection.effect_owner_key)
                .ok_or_else(|| {
                    CoreError::new(
                        REASON_SCHEMA_INVALID,
                        "filesystem actor-and-other plan has no other principal",
                    )
                })?;
            if projection.principals.len() != 2
                || projection
                    .principals
                    .iter()
                    .any(|principal| principal.kind != PrincipalKind::Package)
                || projection.constrained_principal_keys
                    != [projection.effect_owner_key.clone(), other.key.clone()]
            {
                return Err(CoreError::new(
                    REASON_SCHEMA_INVALID,
                    "filesystem projection does not implement the actor-and-other principal plan",
                ));
            }
            Some(projection.effect_owner_key.clone())
        }
        Plan::ActorUnconstrained => {
            if projection.principals.len() != 1
                || owner.kind != PrincipalKind::Package
                || !projection.constrained_principal_keys.is_empty()
            {
                return Err(CoreError::new(
                    REASON_SCHEMA_INVALID,
                    "filesystem projection does not implement the unconstrained actor plan",
                ));
            }
            None
        }
        Plan::ExplicitNoUser => {
            if projection.principals.len() != 1
                || owner.kind != PrincipalKind::NoUser
                || projection.constrained_principal_keys != [projection.effect_owner_key.clone()]
            {
                return Err(CoreError::new(
                    REASON_SCHEMA_INVALID,
                    "filesystem projection does not implement the explicit no-user plan",
                ));
            }
            Some(projection.effect_owner_key.clone())
        }
        Plan::Quarantine => {
            if projection.principals.len() != 1
                || owner.kind != PrincipalKind::Quarantine
                || projection.constrained_principal_keys != [projection.effect_owner_key.clone()]
            {
                return Err(CoreError::new(
                    REASON_SCHEMA_INVALID,
                    "filesystem projection does not implement the quarantine plan",
                ));
            }
            Some(projection.effect_owner_key.clone())
        }
    };
    if projection.execution.actors.len() != operation_slots(operation).len() {
        return Err(CoreError::new(
            REASON_SCHEMA_INVALID,
            "filesystem case plan actor count differs from operation slots",
        ));
    }
    let mut actor_ids = BTreeSet::new();
    for (actor, slot) in projection
        .execution
        .actors
        .iter()
        .zip(operation_slots(operation))
    {
        if actor.actor_id.is_empty()
            || actor.actor_id.len() > 4096
            || !actor.actor_id.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
            || !actor_ids.insert(actor.actor_id.as_str())
            || actor.slot_id != slot.effect_slot_id
            || actor.principal_key != actor_principal
            || actor.effect_owner != projection.effect_owner_key
        {
            return Err(CoreError::new(
                REASON_SCHEMA_INVALID,
                "filesystem actor binding differs from the generated principal and slot plan",
            ));
        }
    }
    Ok(actor_principal)
}

fn case_authority_row(
    source_id: String,
    source_class: FilesystemAuthoritySourceClass,
    principal_key: Option<String>,
    capability: String,
    resource: &FilesystemPathResource,
    state: FilesystemAuthorityState,
) -> FilesystemAuthorityRow {
    let (channel, polarity) = match source_class {
        FilesystemAuthoritySourceClass::ProcessDenial => {
            (FilesystemAuthorityChannel::Process, SelectorPolarity::Negative)
        }
        FilesystemAuthoritySourceClass::PrincipalDenial => {
            (FilesystemAuthorityChannel::Principal, SelectorPolarity::Negative)
        }
        FilesystemAuthoritySourceClass::StaticFloor => {
            (FilesystemAuthorityChannel::Floor, SelectorPolarity::Positive)
        }
        FilesystemAuthoritySourceClass::EscalationCeiling => (
            FilesystemAuthorityChannel::EscalationCeiling,
            SelectorPolarity::Positive,
        ),
        FilesystemAuthoritySourceClass::SessionRevocation => {
            (FilesystemAuthorityChannel::Session, SelectorPolarity::Negative)
        }
        FilesystemAuthoritySourceClass::SessionGrant => {
            (FilesystemAuthorityChannel::Session, SelectorPolarity::Positive)
        }
    };
    FilesystemAuthorityRow {
        source_id,
        source_class,
        channel,
        polarity,
        principal_key,
        capability,
        resource: resource.clone(),
        state,
    }
}

fn filesystem_authority_rows_equal(
    actual: &[FilesystemAuthorityRow],
    expected: &[FilesystemAuthorityRow],
) -> Result<bool, CoreError> {
    if actual.len() != expected.len() {
        return Ok(false);
    }
    for (actual, expected) in actual.iter().zip(expected) {
        if actual.source_id != expected.source_id
            || actual.source_class != expected.source_class
            || actual.channel != expected.channel
            || actual.polarity != expected.polarity
            || actual.principal_key != expected.principal_key
            || actual.capability != expected.capability
            || actual.state != expected.state
            || actual.resource.root != expected.resource.root
            || actual.resource.kind != expected.resource.kind
            || platform_path_bytes(&actual.resource.path)?
                != platform_path_bytes(&expected.resource.path)?
        {
            return Ok(false);
        }
    }
    Ok(true)
}

fn validate_case_authority_plan(
    projection: &FilesystemExecutionProjection,
    operation: &generated::Rev2FilesystemCandidateOperationSpec,
    plan: &generated::Rev2FilesystemCandidateCasePlanSpec,
    target: &FilesystemSetupObject,
    actor_principal: Option<&str>,
) -> Result<(), CoreError> {
    use generated::Rev2FilesystemCandidateAuthorityPlan as Plan;
    let actor_key = actor_principal.unwrap_or(&projection.effect_owner_key);
    let other_key = projection
        .principals
        .iter()
        .find(|principal| principal.key != projection.effect_owner_key)
        .map(|principal| principal.key.as_str());
    let resource = FilesystemPathResource {
        root: target.root,
        kind: FilesystemPathResourceKind::PathExact,
        path: target.path.clone(),
    };
    let row = |source_id: String,
               source_class: FilesystemAuthoritySourceClass,
               principal_key: Option<&str>,
               capability: String,
               state: FilesystemAuthorityState| {
        case_authority_row(
            source_id,
            source_class,
            principal_key.map(str::to_string),
            capability,
            &resource,
            state,
        )
    };
    let static_rows = |principal_key: &str| -> Result<Vec<_>, CoreError> {
        operation_slots(operation)
            .iter()
            .enumerate()
            .map(|(index, slot)| {
                Ok(row(
                    format!("case:static:{index}"),
                    FilesystemAuthoritySourceClass::StaticFloor,
                    Some(principal_key),
                    generated_capability(slot.capability)?.to_string(),
                    FilesystemAuthorityState::Active,
                ))
            })
            .collect()
    };
    let expected = match plan.authority_plan {
        Plan::None => Vec::new(),
        Plan::StaticAll | Plan::NoUserStaticAll => static_rows(actor_key)?,
        Plan::PrincipalDenialOverStaticAll => {
            let mut rows = static_rows(actor_key)?;
            for (index, slot) in operation_slots(operation).iter().enumerate() {
                rows.push(row(
                    format!("case:principal-denial:{index}"),
                    FilesystemAuthoritySourceClass::PrincipalDenial,
                    Some(actor_key),
                    generated_capability(slot.capability)?.to_string(),
                    FilesystemAuthorityState::Active,
                ));
            }
            rows
        }
        Plan::PrincipalDenialLastOverStaticAll => {
            let mut rows = static_rows(actor_key)?;
            let index = operation_slots(operation).len() - 1;
            let slot = &operation_slots(operation)[index];
            rows.push(row(
                format!("case:principal-denial:{index}"),
                FilesystemAuthoritySourceClass::PrincipalDenial,
                Some(actor_key),
                generated_capability(slot.capability)?.to_string(),
                FilesystemAuthorityState::Active,
            ));
            rows
        }
        Plan::ProcessDenialOverStaticAll => {
            let mut rows = static_rows(actor_key)?;
            for (index, slot) in operation_slots(operation).iter().enumerate() {
                rows.push(row(
                    format!("case:process-denial:{index}"),
                    FilesystemAuthoritySourceClass::ProcessDenial,
                    None,
                    generated_capability(slot.capability)?.to_string(),
                    FilesystemAuthorityState::Active,
                ));
            }
            rows
        }
        Plan::CrossActionFirst => operation_slots(operation)
            .iter()
            .enumerate()
            .map(|(index, slot)| {
                Ok(row(
                    if index == 0 {
                        "case:cross-action:0".to_string()
                    } else {
                        format!("case:static:{index}")
                    },
                    FilesystemAuthoritySourceClass::StaticFloor,
                    Some(actor_key),
                    if index == 0 {
                        "fs:read".to_string()
                    } else {
                        generated_capability(slot.capability)?.to_string()
                    },
                    FilesystemAuthorityState::Active,
                ))
            })
            .collect::<Result<Vec<_>, CoreError>>()?,
        Plan::WrongPrincipalStaticAll => static_rows(other_key.ok_or_else(|| {
            CoreError::new(
                REASON_SCHEMA_INVALID,
                "filesystem wrong-principal plan has no other principal",
            )
        })?)?,
        Plan::SessionAllDormantRevocationAll | Plan::SessionAllDormantRevocationLast => {
            let mut rows = Vec::new();
            for (index, slot) in operation_slots(operation).iter().enumerate() {
                rows.push(row(
                    format!("case:session-grant:{index}"),
                    FilesystemAuthoritySourceClass::SessionGrant,
                    Some(actor_key),
                    generated_capability(slot.capability)?.to_string(),
                    FilesystemAuthorityState::Active,
                ));
            }
            for (index, slot) in operation_slots(operation).iter().enumerate() {
                rows.push(row(
                    format!("case:ceiling:{index}"),
                    FilesystemAuthoritySourceClass::EscalationCeiling,
                    Some(actor_key),
                    generated_capability(slot.capability)?.to_string(),
                    FilesystemAuthorityState::Active,
                ));
            }
            for (index, slot) in operation_slots(operation).iter().enumerate() {
                rows.push(row(
                    format!("case:session-revocation:{index}"),
                    FilesystemAuthoritySourceClass::SessionRevocation,
                    Some(actor_key),
                    generated_capability(slot.capability)?.to_string(),
                    FilesystemAuthorityState::Dormant,
                ));
            }
            rows
        }
    };
    if !filesystem_authority_rows_equal(&projection.authority_rows, &expected)? {
        return Err(CoreError::new(
            REASON_SCHEMA_INVALID,
            "filesystem authority rows differ from the generated case plan",
        ));
    }
    Ok(())
}

fn logical_root_text(root: FilesystemLogicalRoot) -> &'static str {
    match root {
        FilesystemLogicalRoot::Abs => "$ABS",
        FilesystemLogicalRoot::Home => "$HOME",
        FilesystemLogicalRoot::Package => "$PACKAGE",
        FilesystemLogicalRoot::Project => "$PROJECT",
        FilesystemLogicalRoot::Tmp => "$TMP",
    }
}

fn push_resource_lifecycle(
    rows: &mut Vec<FilesystemResourceLifecycleEntry>,
    phase: FilesystemTracePhase,
    resource_id: String,
    resource_class: FilesystemResourceClass,
    transition: FilesystemResourceTransition,
    owner_before: Option<String>,
    owner_after: Option<String>,
) {
    rows.push(FilesystemResourceLifecycleEntry {
        sequence: rows.len(),
        phase,
        resource_id,
        resource_class,
        transition,
        owner_before,
        owner_after,
    });
}

fn case_plan_resource_lifecycle(
    projection: &FilesystemExecutionProjection,
    operation: &generated::Rev2FilesystemCandidateOperationSpec,
    plan: &generated::Rev2FilesystemCandidateCasePlanSpec,
    target: &FilesystemSetupObject,
    target_state: generated::Rev2FilesystemCandidateTargetState,
) -> Vec<FilesystemResourceLifecycleEntry> {
    let mut rows = Vec::new();
    let operation_owner = format!("operation:{}", projection.case_id);
    let native_owner = format!("native:{}", projection.edge_id);
    let delivery_owner = format!("delivery:{}", projection.case_id);
    for root in &projection.setup.logical_roots {
        push_resource_lifecycle(
            &mut rows,
            FilesystemTracePhase::HarnessAdmitted,
            format!("inherited-root:{}", root.binding_id),
            FilesystemResourceClass::InheritedRoot,
            FilesystemResourceTransition::Acquire,
            None,
            Some(operation_owner.clone()),
        );
    }
    push_resource_lifecycle(
        &mut rows,
        FilesystemTracePhase::HarnessAdmitted,
        format!("arena:{}", projection.case_id),
        FilesystemResourceClass::Arena,
        FilesystemResourceTransition::Acquire,
        None,
        Some(operation_owner.clone()),
    );
    if plan.lifecycle_requirement
        == generated::Rev2FilesystemCandidateLifecycleRequirement::NoneBeforeCore
    {
        push_resource_lifecycle(
            &mut rows,
            FilesystemTracePhase::HarnessExited,
            format!("arena:{}", projection.case_id),
            FilesystemResourceClass::Arena,
            FilesystemResourceTransition::Release,
            Some(operation_owner.clone()),
            None,
        );
        for root in projection.setup.logical_roots.iter().rev() {
            push_resource_lifecycle(
                &mut rows,
                FilesystemTracePhase::HarnessExited,
                format!("inherited-root:{}", root.binding_id),
                FilesystemResourceClass::InheritedRoot,
                FilesystemResourceTransition::Release,
                Some(operation_owner.clone()),
                None,
            );
        }
        return rows;
    }
    for actor in &projection.execution.actors {
        push_resource_lifecycle(
            &mut rows,
            FilesystemTracePhase::ActorsCaptured,
            format!("actor-token:{}", actor.actor_id),
            FilesystemResourceClass::ActorToken,
            FilesystemResourceTransition::Acquire,
            None,
            Some(actor.actor_id.clone()),
        );
    }
    push_resource_lifecycle(
        &mut rows,
        FilesystemTracePhase::NamespaceGateAcquired,
        format!("namespace-gate:{}", logical_root_text(target.root)),
        FilesystemResourceClass::NamespaceGate,
        FilesystemResourceTransition::Acquire,
        None,
        Some(operation_owner.clone()),
    );
    push_resource_lifecycle(
        &mut rows,
        FilesystemTracePhase::DiscoveryComplete,
        format!("provisional-resource:{}", target.object_id),
        FilesystemResourceClass::ProvisionalResource,
        FilesystemResourceTransition::Acquire,
        None,
        Some(operation_owner.clone()),
    );
    for slot in operation_slots(operation) {
        push_resource_lifecycle(
            &mut rows,
            FilesystemTracePhase::AuthorizationComplete,
            format!("authority-handle:{}", slot.effect_slot_id),
            FilesystemResourceClass::AuthorityHandle,
            FilesystemResourceTransition::Acquire,
            None,
            Some(operation_owner.clone()),
        );
    }
    let creates_child = plan.outcome_disposition
        == generated::Rev2FilesystemCandidateOutcomeDisposition::AuthorizedOperation
        && matches!(
            (operation, target_state),
            (
                generated::Rev2FilesystemCandidateOperationSpec::MkdirSync { .. },
                generated::Rev2FilesystemCandidateTargetState::Missing
            )
        );
    if creates_child {
        push_resource_lifecycle(
            &mut rows,
            FilesystemTracePhase::PreparationComplete,
            format!("prepared-child:{}", target.object_id),
            FilesystemResourceClass::PreparedChild,
            FilesystemResourceTransition::Acquire,
            None,
            Some(operation_owner.clone()),
        );
        push_resource_lifecycle(
            &mut rows,
            FilesystemTracePhase::CoreCommitRecorded,
            format!("prepared-child:{}", target.object_id),
            FilesystemResourceClass::PreparedChild,
            FilesystemResourceTransition::Transfer,
            Some(operation_owner.clone()),
            Some(native_owner.clone()),
        );
        push_resource_lifecycle(
            &mut rows,
            FilesystemTracePhase::NativeCommitRecorded,
            format!("prepared-child:{}", target.object_id),
            FilesystemResourceClass::PreparedChild,
            FilesystemResourceTransition::Release,
            Some(native_owner),
            None,
        );
    }
    if plan.outcome_disposition
        == generated::Rev2FilesystemCandidateOutcomeDisposition::AuthorizedOperation
    {
        push_resource_lifecycle(
            &mut rows,
            FilesystemTracePhase::OperationCompleted,
            format!("delivery-lease:{}", target.object_id),
            FilesystemResourceClass::DeliveryLease,
            FilesystemResourceTransition::Acquire,
            None,
            Some(operation_owner.clone()),
        );
        push_resource_lifecycle(
            &mut rows,
            FilesystemTracePhase::DeliverySerialized,
            format!("delivery-lease:{}", target.object_id),
            FilesystemResourceClass::DeliveryLease,
            FilesystemResourceTransition::Transfer,
            Some(operation_owner.clone()),
            Some(delivery_owner.clone()),
        );
        push_resource_lifecycle(
            &mut rows,
            FilesystemTracePhase::DeliverySerialized,
            format!("delivery-lease:{}", target.object_id),
            FilesystemResourceClass::DeliveryLease,
            FilesystemResourceTransition::Release,
            Some(delivery_owner),
            None,
        );
    }
    push_resource_lifecycle(
        &mut rows,
        FilesystemTracePhase::ProvisionalResourcesReleased,
        format!("provisional-resource:{}", target.object_id),
        FilesystemResourceClass::ProvisionalResource,
        FilesystemResourceTransition::Release,
        Some(operation_owner.clone()),
        None,
    );
    for slot in operation_slots(operation).iter().rev() {
        push_resource_lifecycle(
            &mut rows,
            FilesystemTracePhase::ProvisionalResourcesReleased,
            format!("authority-handle:{}", slot.effect_slot_id),
            FilesystemResourceClass::AuthorityHandle,
            FilesystemResourceTransition::Release,
            Some(operation_owner.clone()),
            None,
        );
    }
    for actor in projection.execution.actors.iter().rev() {
        push_resource_lifecycle(
            &mut rows,
            FilesystemTracePhase::ProvisionalResourcesReleased,
            format!("actor-token:{}", actor.actor_id),
            FilesystemResourceClass::ActorToken,
            FilesystemResourceTransition::Release,
            Some(actor.actor_id.clone()),
            None,
        );
    }
    push_resource_lifecycle(
        &mut rows,
        FilesystemTracePhase::NamespaceGateReleased,
        format!("namespace-gate:{}", logical_root_text(target.root)),
        FilesystemResourceClass::NamespaceGate,
        FilesystemResourceTransition::Release,
        Some(operation_owner.clone()),
        None,
    );
    push_resource_lifecycle(
        &mut rows,
        FilesystemTracePhase::HarnessExited,
        format!("arena:{}", projection.case_id),
        FilesystemResourceClass::Arena,
        FilesystemResourceTransition::Release,
        Some(operation_owner.clone()),
        None,
    );
    for root in projection.setup.logical_roots.iter().rev() {
        push_resource_lifecycle(
            &mut rows,
            FilesystemTracePhase::HarnessExited,
            format!("inherited-root:{}", root.binding_id),
            FilesystemResourceClass::InheritedRoot,
            FilesystemResourceTransition::Release,
            Some(operation_owner.clone()),
            None,
        );
    }
    rows
}

fn validate_case_plan_binding(
    projection: &FilesystemExecutionProjection,
    operation: &generated::Rev2FilesystemCandidateOperationSpec,
    plan: &generated::Rev2FilesystemCandidateCasePlanSpec,
    target_setup: &FilesystemSetupObject,
    state: generated::Rev2FilesystemCandidateTargetState,
) -> Result<(), CoreError> {
    let expected_case_plan_digest = generated_case_plan_digest(&projection.case_kind)?;
    if projection.case_plan_digest != expected_case_plan_digest
        || !mode_matches_case_plan(projection.mode, plan.execution_mode)
        || !mutation_matches_case_plan(projection.input_mutation, plan.input_mutation)
    {
        return Err(CoreError::new(
            REASON_SCHEMA_INVALID,
            "filesystem projection differs from its generated case plan",
        ));
    }
    let target = plan
        .target_states
        .iter()
        .find(|target| generated_target_edge_id(target.edge_id) == projection.edge_id)
        .ok_or_else(|| {
            CoreError::new(
                REASON_SCHEMA_INVALID,
                "filesystem case plan has no target row for the operation edge",
            )
        })?;
    let trace_phases: Vec<_> = projection
        .execution
        .trace_phases
        .iter()
        .copied()
        .map(generated_trace_phase)
        .collect();
    if target.initial_kind != generated_initial_kind(target_setup.kind)
        || target.target_state != state
        || target.trace_phases != trace_phases.as_slice()
    {
        return Err(CoreError::new(
            REASON_SCHEMA_INVALID,
            "filesystem material target or trace phases differ from the generated case plan",
        ));
    }
    let actor_principal = validate_case_principal_plan(projection, operation, plan)?;
    validate_case_authority_plan(
        projection,
        operation,
        plan,
        target_setup,
        actor_principal.as_deref(),
    )?;
    validate_fault_plan(projection, operation, plan)?;
    if projection.execution.resource_lifecycle
        != case_plan_resource_lifecycle(projection, operation, plan, target_setup, state)
    {
        return Err(CoreError::new(
            REASON_SCHEMA_INVALID,
            "filesystem resource lifecycle differs from the generated case plan",
        ));
    }
    Ok(())
}

fn require_platform_identity(
    identity: &FilesystemObjectIdentity,
    label: &str,
) -> Result<(), CoreError> {
    if identity.kind != FilesystemObjectIdentityKind::PlatformObject
        || !identity.value.starts_with("unix-dev-ino:")
        || identity.value.len() != "unix-dev-ino:".len() + 32
        || !identity.value["unix-dev-ino:".len()..]
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(CoreError::new(
            REASON_SCHEMA_INVALID,
            format!("{label} is not a canonical Unix platform identity"),
        ));
    }
    Ok(())
}

fn identity_label(identity: &FilesystemObjectIdentity) -> (u8, &str) {
    let kind = match identity.kind {
        FilesystemObjectIdentityKind::OpaqueToken => 0,
        FilesystemObjectIdentityKind::PlatformObject => 1,
        FilesystemObjectIdentityKind::VerifiedContent => 2,
    };
    (kind, identity.value.as_str())
}

fn validate_fixture_identity(
    identity: &FilesystemObjectIdentity,
    label: &str,
) -> Result<(), CoreError> {
    if identity.value.is_empty() || identity.value.chars().count() > 4096 {
        return Err(CoreError::new(
            REASON_SCHEMA_INVALID,
            format!("{label} is empty or unbounded"),
        ));
    }
    match identity.kind {
        FilesystemObjectIdentityKind::PlatformObject => require_platform_identity(identity, label),
        FilesystemObjectIdentityKind::VerifiedContent => validate_digest_string(&identity.value),
        FilesystemObjectIdentityKind::OpaqueToken => Ok(()),
    }
}

fn platform_path_bytes(path: &FilesystemPlatformPath) -> Result<Vec<u8>, CoreError> {
    let bytes = match path.encoding {
        FilesystemPlatformPathEncoding::Unicode => path.value.as_bytes().to_vec(),
        FilesystemPlatformPathEncoding::OpaqueBase64url => {
            let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(path.value.as_bytes())
                .map_err(|_| {
                    CoreError::new(
                        REASON_SCHEMA_INVALID,
                        "filesystem opaque path is not canonical base64url",
                    )
                })?;
            if base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&decoded) != path.value {
                return Err(CoreError::new(
                    REASON_SCHEMA_INVALID,
                    "filesystem opaque path is not canonical base64url",
                ));
            }
            decoded
        }
    };
    let first_component = bytes.split(|byte| *byte == b'/').next().unwrap_or_default();
    let has_drive_prefix = first_component.len() == 2
        && first_component[0].is_ascii_alphabetic()
        && first_component[1] == b':';
    if path.value.chars().count() > 4096
        || bytes.is_empty()
        || bytes[0] == b'/'
        || bytes.contains(&0)
        || bytes.contains(&b'\\')
        || has_drive_prefix
        || bytes.split(|byte| *byte == b'/').any(|component| {
            component.is_empty() || component == b"." || component == b".."
        })
    {
        return Err(CoreError::new(
            REASON_SCHEMA_INVALID,
            "filesystem path is not a descriptor-relative component sequence",
        ));
    }
    Ok(bytes)
}

fn canonical_unsigned_decimal(value: &str) -> Result<(), CoreError> {
    if value.is_empty()
        || value.len() > 40
        || (value.len() > 1 && value.starts_with('0'))
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(CoreError::new(
            REASON_SCHEMA_INVALID,
            "filesystem metadata integer is not canonical unsigned decimal",
        ));
    }
    Ok(())
}

fn canonical_signed_decimal(value: &str) -> Result<(), CoreError> {
    if value.is_empty() {
        return Err(CoreError::new(
            REASON_SCHEMA_INVALID,
            "filesystem metadata timestamp is not canonical signed decimal",
        ));
    }
    let digits = value.strip_prefix('-').unwrap_or(value);
    if digits.is_empty()
        || digits.len() > 40
        || (digits.len() > 1 && digits.starts_with('0'))
        || (value.starts_with('-') && digits == "0")
        || !digits.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(CoreError::new(
            REASON_SCHEMA_INVALID,
            "filesystem metadata timestamp is not canonical signed decimal",
        ));
    }
    Ok(())
}

fn canonical_unsigned_decimal_at_least(value: &str, minimum: usize) -> bool {
    let minimum = minimum.to_string();
    value.len() > minimum.len() || (value.len() == minimum.len() && value >= minimum.as_str())
}

fn validate_platform_metadata_identity(
    identity: &FilesystemObjectIdentity,
    metadata: &FilesystemMetadataProjection,
) -> Result<(), CoreError> {
    require_platform_identity(identity, "filesystem realized object identity")?;
    let payload = &identity.value["unix-dev-ino:".len()..];
    let device = u64::from_str_radix(&payload[..16], 16).map_err(|_| {
        CoreError::new(
            REASON_SCHEMA_INVALID,
            "filesystem platform identity device is outside u64",
        )
    })?;
    let inode = u64::from_str_radix(&payload[16..], 16).map_err(|_| {
        CoreError::new(
            REASON_SCHEMA_INVALID,
            "filesystem platform identity inode is outside u64",
        )
    })?;
    if metadata.device != device.to_string() || metadata.inode != inode.to_string() {
        return Err(CoreError::new(
            REASON_SCHEMA_INVALID,
            "filesystem platform identity differs from metadata device/inode",
        ));
    }
    Ok(())
}

fn metadata_kind_bits(kind: FilesystemObjectKind) -> Option<u32> {
    match kind {
        FilesystemObjectKind::Fifo => Some(0o010000),
        FilesystemObjectKind::CharacterDevice => Some(0o020000),
        FilesystemObjectKind::Directory => Some(0o040000),
        FilesystemObjectKind::BlockDevice => Some(0o060000),
        FilesystemObjectKind::RegularFile => Some(0o100000),
        FilesystemObjectKind::Symlink => Some(0o120000),
        FilesystemObjectKind::Socket => Some(0o140000),
        FilesystemObjectKind::Missing => None,
    }
}

fn validate_realized_state(
    setup: &FilesystemSetupObject,
    state: &FilesystemRealizedObjectState,
) -> Result<(), CoreError> {
    if setup.kind != state.kind
        || setup.content_digest != state.content_digest
        || setup.alias_target_object_id != state.alias_target_object_id
        || setup.link_target_object_id != state.link_target_object_id
    {
        return Err(CoreError::new(
            REASON_SCHEMA_INVALID,
            "filesystem realized object material differs from setup",
        ));
    }
    let setup_missing = setup.kind == FilesystemObjectKind::Missing;
    let setup_regular = setup.kind == FilesystemObjectKind::RegularFile;
    let setup_symlink = setup.kind == FilesystemObjectKind::Symlink;
    if setup_missing != setup.object_identity.is_none()
        || setup_regular != setup.content.is_some()
        || setup_regular != setup.content_digest.is_some()
        || setup_symlink != setup.link_target_object_id.is_some()
        || (setup.alias_target_object_id.is_some()
            && matches!(setup.kind, FilesystemObjectKind::Missing | FilesystemObjectKind::Directory))
    {
        return Err(CoreError::new(
            REASON_SCHEMA_INVALID,
            "filesystem setup identity, content, or link shape differs from its kind",
        ));
    }
    if let Some(fixture_identity) = setup.object_identity.as_ref() {
        validate_fixture_identity(fixture_identity, "filesystem setup object identity")?;
    }
    if state.kind == FilesystemObjectKind::Missing {
        if state.identity.is_some()
            || state.metadata.is_some()
            || state.content_digest.is_some()
            || state.alias_target_object_id.is_some()
            || state.link_target_object_id.is_some()
        {
            return Err(CoreError::new(
                REASON_SCHEMA_INVALID,
                "filesystem missing object carries material state",
            ));
        }
        return Ok(());
    }
    let identity = state.identity.as_ref().ok_or_else(|| {
        CoreError::new(
            REASON_SCHEMA_INVALID,
            "filesystem present object has no platform identity",
        )
    })?;
    let metadata = state.metadata.as_ref().ok_or_else(|| {
        CoreError::new(
            REASON_SCHEMA_INVALID,
            "filesystem present object has no metadata projection",
        )
    })?;
    validate_platform_metadata_identity(identity, metadata)?;
    if metadata.mode > 0xffff
        || metadata.mode & 0o170000 != metadata_kind_bits(state.kind).unwrap_or_default()
    {
        return Err(CoreError::new(
            REASON_SCHEMA_INVALID,
            "filesystem realized kind differs from authenticated S_IFMT bits",
        ));
    }
    for value in [
        Some(metadata.size.as_str()),
        Some(metadata.link_count.as_str()),
        Some(metadata.device.as_str()),
        Some(metadata.inode.as_str()),
        metadata.uid.as_deref(),
        metadata.gid.as_deref(),
        metadata.rdev.as_deref(),
        metadata.block_size.as_deref(),
        metadata.blocks.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        canonical_unsigned_decimal(value)?;
    }
    for value in [
        metadata.accessed_time_ns.as_deref(),
        metadata.modified_time_ns.as_deref(),
        metadata.changed_time_ns.as_deref(),
        metadata.birth_time_ns.as_deref(),
    ]
    .into_iter()
    .flatten()
    {
        canonical_signed_decimal(value)?;
    }
    match setup.object_identity.as_ref() {
        Some(identity) if identity.kind == FilesystemObjectIdentityKind::PlatformObject => {
            if Some(identity) != state.identity.as_ref() {
                return Err(CoreError::new(
                    REASON_SCHEMA_INVALID,
                    "filesystem fixed platform identity changed during realization",
                ));
            }
        }
        Some(identity) if identity.kind == FilesystemObjectIdentityKind::VerifiedContent => {
            if state.content_digest.as_deref() != Some(identity.value.as_str()) {
                return Err(CoreError::new(
                    REASON_SCHEMA_INVALID,
                    "filesystem verified-content identity differs from realized bytes",
                ));
            }
        }
        _ => {}
    }
    if setup.kind == FilesystemObjectKind::RegularFile {
        let content = setup.content.as_ref().ok_or_else(|| {
            CoreError::new(
                REASON_SCHEMA_INVALID,
                "filesystem regular-file setup has no materialization recipe",
            )
        })?;
        let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(content.bytes.as_bytes())
            .map_err(|_| {
                CoreError::new(
                    REASON_SCHEMA_INVALID,
                    "filesystem content recipe is not canonical base64url",
                )
            })?;
        if content.bytes.len() > 4096
            || base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&bytes) != content.bytes
        {
            return Err(CoreError::new(
                REASON_SCHEMA_INVALID,
                "filesystem content recipe is not canonical base64url",
            ));
        }
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        let digest = format!(
            "sha256-{}",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hasher.finalize())
        );
        if setup.content_digest.as_deref() != Some(digest.as_str()) {
            return Err(CoreError::new(
                REASON_SCHEMA_INVALID,
                "filesystem content recipe digest differs from setup",
            ));
        }
    } else if setup.content.is_some() {
        return Err(CoreError::new(
            REASON_SCHEMA_INVALID,
            "filesystem non-regular object carries an inline content recipe",
        ));
    }
    Ok(())
}

fn validate_initial_sandbox_completeness(
    input: &FilesystemCandidateOracleInput,
) -> Result<(), CoreError> {
    let setup = &input.case_projection.setup;
    let inventory = &input.initial_sandbox;
    if setup.logical_roots.len() != inventory.logical_roots.len()
        || setup.objects.len() != inventory.objects.len()
        || setup.logical_roots.is_empty()
        || setup.logical_roots.len() > 5
        || setup.objects.len() > 4096
    {
        return Err(CoreError::new(
            REASON_SCHEMA_INVALID,
            "filesystem initial inventory does not exactly cover setup",
        ));
    }
    let mut roots = BTreeSet::new();
    let mut binding_ids = BTreeSet::new();
    let mut fixture_root_ids = BTreeSet::new();
    let mut platform_root_ids = BTreeSet::new();
    for (index, setup_root) in setup.logical_roots.iter().enumerate() {
        if setup_root.descriptor_slot != index
            || (index > 0 && setup.logical_roots[index - 1].root >= setup_root.root)
            || !roots.insert(setup_root.root)
            || !binding_ids.insert(setup_root.binding_id.as_str())
            || !fixture_root_ids.insert(identity_label(&setup_root.object_identity))
        {
            return Err(CoreError::new(
                REASON_SCHEMA_INVALID,
                "filesystem logical roots are not dense and unique",
            ));
        }
        validate_fixture_identity(&setup_root.object_identity, "filesystem setup root identity")?;
        let realized = inventory
            .logical_roots
            .iter()
            .find(|root| root.root == setup_root.root)
            .ok_or_else(|| {
                CoreError::new(
                    REASON_SCHEMA_INVALID,
                    "filesystem setup root is absent from initial inventory",
                )
            })?;
        if realized.binding_id != setup_root.binding_id
            || realized.fixture_identity != setup_root.object_identity
            || (setup_root.object_identity.kind
                == FilesystemObjectIdentityKind::PlatformObject
                && realized.platform_identity != setup_root.object_identity)
        {
            return Err(CoreError::new(
                REASON_SCHEMA_INVALID,
                "filesystem logical-root realization differs from setup",
            ));
        }
        require_platform_identity(&realized.platform_identity, "filesystem root identity")?;
        if !platform_root_ids.insert(realized.platform_identity.value.as_str()) {
            return Err(CoreError::new(
                REASON_SCHEMA_INVALID,
                "filesystem logical roots share a platform identity",
            ));
        }
    }
    let mut object_ids = BTreeSet::new();
    let mut setup_locations = BTreeSet::new();
    let mut setup_fixture_ids = BTreeSet::new();
    let mut realized_by_id = BTreeMap::new();
    let mut realized_locations = BTreeSet::new();
    for realized in &inventory.objects {
        let path = platform_path_bytes(&realized.path)?;
        if realized_by_id
            .insert(realized.object_id.as_str(), realized)
            .is_some()
            || !realized_locations.insert((realized.root, path))
        {
            return Err(CoreError::new(
                REASON_SCHEMA_INVALID,
                "filesystem initial inventory duplicates an object id or location",
            ));
        }
    }
    for object in &setup.objects {
        if !object_ids.insert(object.object_id.as_str()) {
            return Err(CoreError::new(
                REASON_SCHEMA_INVALID,
                "filesystem setup duplicates an object id",
            ));
        }
        let path = platform_path_bytes(&object.path)?;
        if !setup_locations.insert((object.root, path))
            || object.object_identity.as_ref().is_some_and(|identity| {
                fixture_root_ids.contains(&identity_label(identity))
                    || !setup_fixture_ids.insert(identity_label(identity))
            })
        {
            return Err(CoreError::new(
                REASON_SCHEMA_INVALID,
                "filesystem setup duplicates an object location or fixture identity",
            ));
        }
        let realized = realized_by_id.get(object.object_id.as_str()).ok_or_else(|| {
            CoreError::new(
                REASON_SCHEMA_INVALID,
                "filesystem setup object is absent from initial inventory",
            )
        })?;
        if realized.root != object.root
            || realized.path != object.path
            || realized.fixture_identity != object.object_identity
            || !roots.contains(&object.root)
        {
            return Err(CoreError::new(
                REASON_SCHEMA_INVALID,
                "filesystem object realization differs from setup root, path, or fixture identity",
            ));
        }
        validate_realized_state(object, &realized.state)?;
    }
    for object in &setup.objects {
        if let Some(link_target) = object.link_target_object_id.as_deref() {
            if !object_ids.contains(link_target) {
                return Err(CoreError::new(
                    REASON_SCHEMA_INVALID,
                    "filesystem symlink target is absent",
                ));
            }
        }
        if let Some(alias_target) = object.alias_target_object_id.as_deref() {
            let target = setup
                .objects
                .iter()
                .find(|candidate| candidate.object_id == alias_target)
                .ok_or_else(|| {
                    CoreError::new(
                        REASON_SCHEMA_INVALID,
                        "filesystem hard-link alias target is absent",
                    )
                })?;
            let realized = realized_by_id[object.object_id.as_str()];
            let target_realized = realized_by_id[target.object_id.as_str()];
            if alias_target == object.object_id
                || target.alias_target_object_id.is_some()
                || object.kind == FilesystemObjectKind::Directory
                || object.kind == FilesystemObjectKind::Missing
                || object.kind != target.kind
                || object.content != target.content
                || realized.state.identity != target_realized.state.identity
                || realized.state.metadata != target_realized.state.metadata
                || realized.state.content_digest != target_realized.state.content_digest
                || realized.state.link_target_object_id != target_realized.state.link_target_object_id
            {
                return Err(CoreError::new(
                    REASON_SCHEMA_INVALID,
                    "filesystem hard-link alias does not realize one material object",
                ));
            }
        }
    }
    let mut identity_groups: BTreeMap<&str, Vec<&FilesystemSetupObject>> = BTreeMap::new();
    for object in &setup.objects {
        if let Some(identity) = realized_by_id[object.object_id.as_str()].state.identity.as_ref() {
            if platform_root_ids.contains(identity.value.as_str()) {
                return Err(CoreError::new(
                    REASON_SCHEMA_INVALID,
                    "filesystem object identity aliases a logical-root platform identity",
                ));
            }
            identity_groups.entry(identity.value.as_str()).or_default().push(object);
        }
    }
    for group in identity_groups.values() {
        if group.len() == 1 {
            if group[0].alias_target_object_id.is_some() {
                return Err(CoreError::new(
                    REASON_SCHEMA_INVALID,
                    "filesystem hard-link alias has no matching identity peer",
                ));
            }
            continue;
        }
        let canonical: Vec<_> = group
            .iter()
            .filter(|object| object.alias_target_object_id.is_none())
            .collect();
        if canonical.len() != 1
            || group.iter().any(|object| {
                object.object_id != canonical[0].object_id
                    && object.alias_target_object_id.as_deref()
                        != Some(canonical[0].object_id.as_str())
            })
        {
            return Err(CoreError::new(
                REASON_SCHEMA_INVALID,
                "filesystem shared identity has no exact hard-link canonical entry",
            ));
        }
        let link_count = &realized_by_id[canonical[0].object_id.as_str()]
            .state
            .metadata
            .as_ref()
            .ok_or_else(|| CoreError::new(REASON_SCHEMA_INVALID, "alias metadata is absent"))?
            .link_count;
        if !canonical_unsigned_decimal_at_least(link_count, group.len()) {
            return Err(CoreError::new(
                REASON_SCHEMA_INVALID,
                "filesystem hard-link count is smaller than the visible alias group",
            ));
        }
    }
    Ok(())
}

struct FilesystemCandidateExecutionMaterial<'a> {
    operation: &'static generated::Rev2FilesystemCandidateOperationSpec,
    plan: &'static generated::Rev2FilesystemCandidateCasePlanSpec,
    target_setup: &'a FilesystemSetupObject,
    target_initial: &'a FilesystemInitialSandboxObject,
    parent_identity: FilesystemObjectIdentity,
    target_state: generated::Rev2FilesystemCandidateTargetState,
    slots: Vec<FilesystemEffectSlot>,
}

fn filesystem_candidate_execution_material<'a>(
    input: &'a FilesystemCandidateOracleInput,
) -> Result<FilesystemCandidateExecutionMaterial<'a>, CoreError> {
    let projection = &input.case_projection;
    let target_candidates_valid = !projection.target_predicate.candidates.is_empty()
        && projection.target_predicate.candidates.len() <= 16
        && projection
            .target_predicate
            .candidates
            .iter()
            .all(|candidate| {
                !candidate.target.is_empty()
                    && candidate.target.len() <= 4096
                    && candidate
                        .target
                        .bytes()
                        .all(|byte| (0x21..=0x7e).contains(&byte))
                    && !candidate.feature_set.is_empty()
                    && candidate.feature_set.chars().count() <= 4096
                    && REV2_TARGET_STATUS.iter().any(|registered| {
                        registered.target == candidate.target
                            && registered.feature_set == candidate.feature_set
                    })
            })
        && projection
            .target_predicate
            .candidates
            .windows(2)
            .all(|pair| pair[0].target < pair[1].target);
    if !target_candidates_valid {
        return Err(CoreError::new(
            REASON_SCHEMA_INVALID,
            "filesystem target predicate is not an exact registered target tuple set",
        ));
    }
    if input.initial_sandbox.schema != FILESYSTEM_SANDBOX_INVENTORY_SCHEMA
        || input.initial_sandbox.phase != FilesystemSandboxPhase::Initial
        || !input.initial_sandbox.unexpected_entries.is_empty()
        || projection.case_id.trim().is_empty()
        || projection.requirement_id.trim().is_empty()
        || projection.effect_owner_key.trim().is_empty()
        || projection.invocation.kind != FilesystemInvocationKind::NativeHarness
        || projection.invocation.command != "oden-capsec-filesystem-fixture"
        || projection.invocation.args != [projection.case_id.clone()]
        || !projection
            .setup
            .logical_roots
            .iter()
            .any(|root| root.root == projection.invocation.cwd_root)
        || projection.invocation.entrypoint.is_some()
    {
        return Err(CoreError::new(
            REASON_SCHEMA_INVALID,
            "filesystem oracle identity, inventory, or native invocation is invalid",
        ));
    }
    validate_initial_sandbox_completeness(input)?;
    let operation = generated_operation(&projection.edge_id)?;
    let requirement_id = format!("fixture-requirement:{}:complete", projection.edge_id);
    if projection.requirement_id != requirement_id {
        return Err(CoreError::new(
            REASON_SCHEMA_INVALID,
            "filesystem requirement does not match the generated operation edge",
        ));
    }
    validate_generated_operation_model(operation)?;
    let request_kind_matches = matches!(
        (operation, &projection.operation_request),
        (
            generated::Rev2FilesystemCandidateOperationSpec::LstatSync { .. },
            FilesystemOperationRequest::LstatSync { .. }
        ) | (
            generated::Rev2FilesystemCandidateOperationSpec::MkdirSync { .. },
            FilesystemOperationRequest::MkdirSync {
                recursive: false,
                ..
            }
        )
    );
    if !request_kind_matches {
        return Err(CoreError::new(
            REASON_SCHEMA_INVALID,
            "filesystem operation request differs from the generated operation",
        ));
    }
    if let FilesystemOperationRequest::MkdirSync { requested_mode, .. } =
        &projection.operation_request
    {
        if *requested_mode > 0o7777 {
            return Err(CoreError::new(
                REASON_SCHEMA_INVALID,
                "filesystem mkdir requested mode is outside 0..4095",
            ));
        }
    }
    let required_umask = match operation {
        generated::Rev2FilesystemCandidateOperationSpec::LstatSync { .. } => 0o077,
        generated::Rev2FilesystemCandidateOperationSpec::MkdirSync {
            mode_derivation,
            ..
        } => mode_derivation.required_captured_umask,
    };
    if input.parent_capture_facts.captured_umask != required_umask {
        return Err(CoreError::new(
            REASON_SCHEMA_INVALID,
            "filesystem parent capture did not observe the required 0077 umask",
        ));
    }
    let target_ref = projection.operation_request.target_ref();
    let target_setup = projection
        .setup
        .objects
        .iter()
        .find(|object| object.object_id == target_ref.object_id)
        .ok_or_else(|| {
            CoreError::new(
                REASON_SCHEMA_INVALID,
                "filesystem operation target is absent from setup",
            )
        })?;
    let target_initial = input
        .initial_sandbox
        .objects
        .iter()
        .find(|object| object.object_id == target_ref.object_id)
        .ok_or_else(|| {
            CoreError::new(
                REASON_SCHEMA_INVALID,
                "filesystem operation target is absent from initial inventory",
            )
        })?;
    if target_setup.root != target_initial.root
        || target_setup.path != target_initial.path
        || target_setup.object_identity != target_initial.fixture_identity
        || target_setup.kind != target_initial.state.kind
        || target_setup.content_digest != target_initial.state.content_digest
        || target_setup.alias_target_object_id != target_initial.state.alias_target_object_id
        || target_setup.link_target_object_id != target_initial.state.link_target_object_id
    {
        return Err(CoreError::new(
            REASON_SCHEMA_INVALID,
            "filesystem initial inventory differs from the execution setup",
        ));
    }
    let setup_root = projection
        .setup
        .logical_roots
        .iter()
        .find(|root| root.root == target_setup.root)
        .ok_or_else(|| {
            CoreError::new(REASON_SCHEMA_INVALID, "filesystem target root is unbound")
        })?;
    let realized_root = input
        .initial_sandbox
        .logical_roots
        .iter()
        .find(|root| root.root == target_setup.root)
        .ok_or_else(|| {
            CoreError::new(
                REASON_SCHEMA_INVALID,
                "filesystem target root is absent from initial inventory",
            )
        })?;
    if setup_root.binding_id != realized_root.binding_id
        || setup_root.object_identity != realized_root.fixture_identity
    {
        return Err(CoreError::new(
            REASON_SCHEMA_INVALID,
            "filesystem root realization differs from setup",
        ));
    }
    require_platform_identity(&realized_root.platform_identity, "filesystem root identity")?;
    let target_path_bytes = platform_path_bytes(&target_setup.path)?;
    let parent_identity = match &target_ref.parent {
        FilesystemTargetParentRef::LogicalRoot { root, binding_id }
            if *root == target_setup.root
                && *binding_id == setup_root.binding_id
                && !target_path_bytes.contains(&b'/') =>
        {
            realized_root.platform_identity.clone()
        }
        FilesystemTargetParentRef::DirectoryObject { object_id } => {
            let parent_setup = projection
                .setup
                .objects
                .iter()
                .find(|object| object.object_id == *object_id)
                .ok_or_else(|| {
                    CoreError::new(
                        REASON_SCHEMA_INVALID,
                        "filesystem parent object is absent from setup",
                    )
                })?;
            let parent = input
                .initial_sandbox
                .objects
                .iter()
                .find(|object| object.object_id == *object_id)
                .ok_or_else(|| {
                    CoreError::new(
                        REASON_SCHEMA_INVALID,
                        "filesystem parent object is absent from initial inventory",
                    )
                })?;
            let separator = target_path_bytes.iter().rposition(|byte| *byte == b'/');
            if parent_setup.kind != FilesystemObjectKind::Directory
                || parent.state.kind != FilesystemObjectKind::Directory
                || parent.root != target_setup.root
                || separator.is_none()
                || platform_path_bytes(&parent_setup.path)?
                    != target_path_bytes[..separator.unwrap()]
            {
                return Err(CoreError::new(
                    REASON_SCHEMA_INVALID,
                    "filesystem target parent is not a same-root directory",
                ));
            }
            parent.state.identity.clone().ok_or_else(|| {
                CoreError::new(
                    REASON_SCHEMA_INVALID,
                    "filesystem target parent has no platform identity",
                )
            })?
        }
        _ => {
            return Err(CoreError::new(
                REASON_SCHEMA_INVALID,
                "filesystem target parent differs from setup",
            ));
        }
    };
    require_platform_identity(&parent_identity, "filesystem parent identity")?;
    if target_initial.state.kind != FilesystemObjectKind::Missing {
        let identity = target_initial.state.identity.as_ref().ok_or_else(|| {
            CoreError::new(
                REASON_SCHEMA_INVALID,
                "filesystem present target has no platform identity",
            )
        })?;
        require_platform_identity(identity, "filesystem target identity")?;
    } else if target_initial.state.identity.is_some() || target_initial.state.metadata.is_some() {
        return Err(CoreError::new(
            REASON_SCHEMA_INVALID,
            "filesystem missing target carries realized identity or metadata",
        ));
    }
    let target_state = target_state(operation, target_setup.kind)?;
    let plan = generated_case_plan(&projection.case_kind)?;
    validate_case_plan_binding(projection, operation, plan, target_setup, target_state)?;
    if projection.execution.actors.len() != operation_slots(operation).len() {
        return Err(CoreError::new(
            REASON_SCHEMA_INVALID,
            "filesystem operation slot plan is incomplete",
        ));
    }
    let mut slots = Vec::with_capacity(operation_slots(operation).len());
    for (index, slot_spec) in operation_slots(operation).iter().enumerate() {
        let actor = &projection.execution.actors[index];
        if actor.slot_id != slot_spec.effect_slot_id
            || actor.effect_owner != projection.effect_owner_key
        {
            return Err(CoreError::new(
                REASON_SCHEMA_INVALID,
                "filesystem execution actor differs from generated slot order",
            ));
        }
        use generated::Rev2FilesystemCandidateFinalObjectState as State;
        use generated::Rev2FilesystemCandidateSlotRole as Role;
        let normalized_state = match (target_state, slot_spec.role) {
            (generated::Rev2FilesystemCandidateTargetState::Existing, _) => State::Existing,
            (generated::Rev2FilesystemCandidateTargetState::LinkEntry, _) => State::LinkEntry,
            (generated::Rev2FilesystemCandidateTargetState::Missing, Role::TargetWriteIntent) => {
                State::Proposed
            }
            (
                generated::Rev2FilesystemCandidateTargetState::Missing,
                Role::TargetListObservation,
            ) => State::Missing,
        };
        let final_object_state = match normalized_state {
            State::Existing => FilesystemFinalObjectState::Existing {
                identity: target_initial.state.identity.clone().ok_or_else(|| {
                    CoreError::new(REASON_SCHEMA_INVALID, "existing target identity is missing")
                })?,
            },
            State::LinkEntry => FilesystemFinalObjectState::LinkEntry {
                identity: target_initial.state.identity.clone().ok_or_else(|| {
                    CoreError::new(REASON_SCHEMA_INVALID, "link-entry identity is missing")
                })?,
            },
            State::Missing => FilesystemFinalObjectState::Missing,
            State::Proposed => FilesystemFinalObjectState::Proposed,
        };
        slots.push(FilesystemEffectSlot {
            slot_id: slot_spec.effect_slot_id.to_string(),
            capability: generated_capability(slot_spec.capability)?.to_string(),
            effect_owner: projection.effect_owner_key.clone(),
            occurrence: FilesystemPathOccurrence {
                root: target_setup.root,
                root_binding_id: setup_root.binding_id.clone(),
                lexical_path: target_setup.path.clone(),
                follow_mode: FilesystemFollowMode::NoFollowFinal,
                parent_identity: parent_identity.clone(),
                final_object_state,
                effect_owner: projection.effect_owner_key.clone(),
            },
        });
    }
    Ok(FilesystemCandidateExecutionMaterial {
        operation,
        plan,
        target_setup,
        target_initial,
        parent_identity,
        target_state,
        slots,
    })
}

fn validate_filesystem_candidate_execution_input(
    input: &FilesystemCandidateOracleInput,
) -> Result<FilesystemCandidateExecutionMaterial<'_>, CoreError> {
    let projection_value = serde_json::to_value(&input.case_projection).map_err(schema_error)?;
    let inventory_value = serde_json::to_value(&input.initial_sandbox).map_err(schema_error)?;
    let computed_projection_digest = hjcs_digest(
        FILESYSTEM_EXECUTION_PROJECTION_DIGEST_DOMAIN,
        &projection_value,
    )?;
    let computed_inventory_digest = hjcs_digest(
        FILESYSTEM_SANDBOX_INVENTORY_DIGEST_DOMAIN,
        &inventory_value,
    )?;
    if input.case_projection_digest != computed_projection_digest
        || input.initial_inventory_digest != computed_inventory_digest
    {
        return Err(CoreError::new(
            REASON_SCHEMA_INVALID,
            "filesystem candidate input digest does not bind its complete preimage",
        ));
    }
    filesystem_candidate_execution_material(input)
}

/// Validate and bind the complete expected-free native candidate input.
///
/// This boundary checks the registered case and operation model, target tuple,
/// initial sandbox realization, actor and authority plans, exact phase and
/// resource lifecycle, and closed fault plan. It does not instantiate the
/// shared decision core, evaluate an outcome, or construct oracle output.
///
/// @ref LLP 0019#pre-promotion-conformance-candidate-execution [implements] —
/// The native candidate admits only a digest-bound generated execution
/// projection and initial-only inventory, independently of expected results.
pub fn validate_filesystem_candidate_execution(
    input: FilesystemCandidateOracleInput,
) -> Result<ValidatedFilesystemCandidateExecution, CoreError> {
    let (runtime_slots, target_object_id, parent_identity) = {
        let material = validate_filesystem_candidate_execution_input(&input)?;
        let runtime_slots = if input.case_projection.input_mutation
            == FilesystemInputMutation::TargetPathDotDot
        {
            Vec::new()
        } else {
            material.slots.clone()
        };
        (
            runtime_slots,
            material.target_setup.object_id.clone(),
            material.parent_identity.clone(),
        )
    };
    let target_setup_index = input
        .case_projection
        .setup
        .objects
        .iter()
        .position(|object| object.object_id == target_object_id)
        .ok_or_else(|| {
            CoreError::new(
                REASON_SCHEMA_INVALID,
                "validated filesystem target disappeared from setup",
            )
        })?;
    let target_initial_index = input
        .initial_sandbox
        .objects
        .iter()
        .position(|object| object.object_id == target_object_id)
        .ok_or_else(|| {
            CoreError::new(
                REASON_SCHEMA_INVALID,
                "validated filesystem target disappeared from initial inventory",
            )
        })?;
    Ok(ValidatedFilesystemCandidateExecution {
        input,
        runtime_slots,
        target_setup_index,
        target_initial_index,
        parent_identity,
    })
}

struct FilesystemOracleMaterial<'a> {
    operation: &'static generated::Rev2FilesystemCandidateOperationSpec,
    plan: &'static generated::Rev2FilesystemCandidateCasePlanSpec,
    target_setup: &'a FilesystemSetupObject,
    target_initial: &'a FilesystemInitialSandboxObject,
    parent_identity: FilesystemObjectIdentity,
    authorized_outcome: &'static generated::Rev2FilesystemCandidateAuthorizedOutcomeSpec,
    slots: Vec<FilesystemEffectSlot>,
}

fn filesystem_oracle_material<'a>(
    input: &'a FilesystemCandidateOracleInput,
) -> Result<FilesystemOracleMaterial<'a>, CoreError> {
    let material = validate_filesystem_candidate_execution_input(input)?;
    let authorized_outcome = operation_authorized_outcomes(material.operation)
        .iter()
        .find(|outcome| outcome.target_state == material.target_state)
        .ok_or_else(|| {
            CoreError::new(
                REASON_SCHEMA_INVALID,
                "filesystem target state has no generated authorized outcome",
            )
        })?;
    validate_generated_authorized_outcome(
        material.operation,
        material.target_state,
        authorized_outcome,
    )?;
    Ok(FilesystemOracleMaterial {
        operation: material.operation,
        plan: material.plan,
        target_setup: material.target_setup,
        target_initial: material.target_initial,
        parent_identity: material.parent_identity,
        authorized_outcome,
        slots: material.slots,
    })
}

fn projection_principal(
    projection: &FilesystemExecutionProjection,
    key: &str,
) -> Result<PrincipalRef, CoreError> {
    projection
        .principals
        .iter()
        .find(|principal| principal.key == key)
        .cloned()
        .ok_or_else(|| {
            CoreError::new(
                REASON_SCHEMA_INVALID,
                format!("filesystem projection names unknown principal {key}"),
            )
        })
}

fn filesystem_stage_request(
    projection: &FilesystemExecutionProjection,
    slots: &[FilesystemEffectSlot],
    phase: FilesystemCoreEvaluationPhase,
) -> Result<StageRequest, CoreError> {
    let principals = projection
        .constrained_principal_keys
        .iter()
        .map(|key| projection_principal(projection, key))
        .collect::<Result<Vec<_>, _>>()?;
    let effects = slots
        .iter()
        .map(|slot| {
            Ok(EffectInput {
                identity: EngineIdentity::embedded(),
                edge_id: projection.edge_id.clone(),
                effect_slot_id: slot.slot_id.clone(),
                capability: slot.capability.clone(),
                effect_owner: slot.effect_owner.clone(),
                occurrence: serde_json::to_value(&slot.occurrence).map_err(schema_error)?,
            })
        })
        .collect::<Result<Vec<_>, CoreError>>()?;
    Ok(StageRequest {
        identity: EngineIdentity::embedded(),
        stage_id: match phase {
            FilesystemCoreEvaluationPhase::Initial => "filesystem-oracle:initial",
            FilesystemCoreEvaluationPhase::PostFault => "filesystem-oracle:post-fault",
        }
        .to_string(),
        principals,
        effects,
    })
}

fn authority_row_active(
    row: &FilesystemAuthorityRow,
    fault: Option<&FilesystemFaultAction>,
) -> bool {
    match fault {
        Some(FilesystemFaultAction::AuthorityRevocation {
            remove_source_ids,
            activate_source_ids,
        }) => {
            if remove_source_ids.contains(&row.source_id) {
                false
            } else if activate_source_ids.contains(&row.source_id) {
                true
            } else {
                row.state == FilesystemAuthorityState::Active
            }
        }
        _ => row.state == FilesystemAuthorityState::Active,
    }
}

fn validate_authority_row_shape(row: &FilesystemAuthorityRow) -> Result<(), CoreError> {
    use FilesystemAuthorityChannel as Channel;
    use FilesystemAuthoritySourceClass as Class;
    let expected = match row.source_class {
        Class::ProcessDenial => (Channel::Process, SelectorPolarity::Negative, false),
        Class::PrincipalDenial => (Channel::Principal, SelectorPolarity::Negative, true),
        Class::StaticFloor => (Channel::Floor, SelectorPolarity::Positive, true),
        Class::EscalationCeiling => {
            (Channel::EscalationCeiling, SelectorPolarity::Positive, true)
        }
        Class::SessionRevocation => (Channel::Session, SelectorPolarity::Negative, true),
        Class::SessionGrant => (Channel::Session, SelectorPolarity::Positive, true),
    };
    if row.channel != expected.0
        || row.polarity != expected.1
        || row.principal_key.is_some() != expected.2
        || (row.state == FilesystemAuthorityState::Dormant
            && row.source_class != Class::SessionRevocation)
    {
        return Err(CoreError::new(
            REASON_SCHEMA_INVALID,
            "filesystem authority source class, channel, polarity, principal, or state differs",
        ));
    }
    Ok(())
}

fn filesystem_decision_policy(
    projection: &FilesystemExecutionProjection,
    material: &FilesystemOracleMaterial<'_>,
    phase: FilesystemCoreEvaluationPhase,
) -> Result<DecisionPolicyInput, CoreError> {
    let mode = match projection.mode {
        FilesystemExecutionMode::Audit => Mode::Audit,
        FilesystemExecutionMode::Enforce => Mode::Enforce,
    };
    let quota_owner = projection_principal(projection, &projection.effect_owner_key)?;
    let fault = match phase {
        FilesystemCoreEvaluationPhase::Initial => None,
        FilesystemCoreEvaluationPhase::PostFault => projection
            .fault_plan
            .as_ref()
            .map(|plan| &plan.action),
    };
    let mut policy = DecisionPolicyInput {
        identity: EngineIdentity::embedded(),
        mode,
        run_nonce: "filesystem-oracle:run".to_string(),
        channel_epoch: "filesystem-oracle:channel".to_string(),
        provenance: OperationProvenanceContext {
            policy_digest: REV2_VOCAB_DIGEST.to_string(),
            armed_snapshot_digest: REV2_REGISTRY_DIGEST.to_string(),
            quota_owner,
            terminal_evidence_id: "filesystem-oracle:terminal".to_string(),
        },
        generations: Generations {
            negative_overlay: if phase == FilesystemCoreEvaluationPhase::PostFault {
                "1".to_string()
            } else {
                "0".to_string()
            },
            policy_snapshot: "1".to_string(),
            revocation: if phase == FilesystemCoreEvaluationPhase::PostFault {
                "1".to_string()
            } else {
                "0".to_string()
            },
            session_overlay: if phase == FilesystemCoreEvaluationPhase::PostFault {
                "2".to_string()
            } else {
                "1".to_string()
            },
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
    };
    for row in &projection.authority_rows {
        validate_authority_row_shape(row)?;
        if row.resource.root != material.target_setup.root {
            return Err(CoreError::new(
                REASON_SCHEMA_INVALID,
                "filesystem authority row does not select the target logical root",
            ));
        }
        let principal = row
            .principal_key
            .as_deref()
            .map(|key| projection_principal(projection, key))
            .transpose()?;
        let named = NamedSelectorInput {
            source_id: row.source_id.clone(),
            selector: AuthoritySelectorInput {
                identity: EngineIdentity::embedded(),
                principal,
                capability: row.capability.clone(),
                resource: serde_json::to_value(&row.resource).map_err(schema_error)?,
            },
        };
        let active = authority_row_active(row, fault);
        if active {
            match row.source_class {
                FilesystemAuthoritySourceClass::ProcessDenial => {
                    policy.process_denials.push(named)
                }
                FilesystemAuthoritySourceClass::PrincipalDenial => {
                    policy.principal_denials.push(named)
                }
                FilesystemAuthoritySourceClass::StaticFloor => policy.static_floor.push(named),
                FilesystemAuthoritySourceClass::EscalationCeiling => {
                    policy.escalation_ceiling.push(named)
                }
                FilesystemAuthoritySourceClass::SessionRevocation => {
                    policy.session_revocations.push(named)
                }
                FilesystemAuthoritySourceClass::SessionGrant => policy.session_grants.push(named),
            }
        }
        if active {
            policy.path_bindings.push(PathBindingInput {
                source_id: row.source_id.clone(),
                root_binding_id: material.slots[0].occurrence.root_binding_id.clone(),
                final_object_identities: material
                    .target_initial
                    .state
                    .identity
                    .as_ref()
                    .map(|identity| serde_json::to_value(identity).map_err(schema_error))
                    .transpose()?
                    .into_iter()
                    .collect(),
                parent_identities: vec![
                    serde_json::to_value(&material.parent_identity).map_err(schema_error)?,
                ],
            });
        }
    }
    Ok(policy)
}

// @ref LLP 0019#pre-promotion-conformance-candidate-execution [implements] —
// Raw shared-core decisions retain canonical order, while the fixture-facing
// summary uses generated slot and constrained-principal role order.
fn summarize_core_decision(
    decision: &StageDecision,
    slots: &[FilesystemEffectSlot],
    constrained_principal_keys: &[String],
    sequence: usize,
    phase: FilesystemCoreEvaluationPhase,
    committed: bool,
) -> Result<FilesystemCoreEvaluation, CoreError> {
    let outcome = match decision.outcome {
        Outcome::Allow => FilesystemCoreOutcome::Allow,
        Outcome::Deny => FilesystemCoreOutcome::Deny,
        Outcome::Masked => {
            return Err(CoreError::new(
                REASON_SCHEMA_INVALID,
                "filesystem candidate core produced an unsupported masked outcome",
            ));
        }
    };
    let mut dimensions = Vec::new();
    for slot in slots {
        let effect = decision
            .effects
            .iter()
            .find(|effect| effect.effect.effect_slot_id == slot.slot_id)
            .ok_or_else(|| {
                CoreError::new(
                    REASON_SCHEMA_INVALID,
                    "filesystem core decision omitted a generated slot",
                )
            })?;
        let ordered_dimensions = if constrained_principal_keys.is_empty() {
            effect.dimensions.iter().collect::<Vec<_>>()
        } else {
            if effect.dimensions.len() != constrained_principal_keys.len() {
                return Err(CoreError::new(
                    REASON_SCHEMA_INVALID,
                    "filesystem core decision differs from the constrained principal set",
                ));
            }
            constrained_principal_keys
                .iter()
                .map(|principal_key| {
                    effect
                        .dimensions
                        .iter()
                        .find(|dimension| dimension.principal.key == *principal_key)
                        .ok_or_else(|| {
                            CoreError::new(
                                REASON_SCHEMA_INVALID,
                                "filesystem core decision omitted a constrained principal",
                            )
                        })
                })
                .collect::<Result<Vec<_>, CoreError>>()?
        };
        for dimension in ordered_dimensions {
            dimensions.push(FilesystemCoreDimension {
                slot_id: slot.slot_id.clone(),
                principal_key: dimension.principal.key.clone(),
                outcome: match dimension.outcome {
                    Outcome::Allow => FilesystemCoreOutcome::Allow,
                    Outcome::Deny => FilesystemCoreOutcome::Deny,
                    Outcome::Masked => {
                        return Err(CoreError::new(
                            REASON_SCHEMA_INVALID,
                            "filesystem core dimension produced an unsupported masked outcome",
                        ));
                    }
                },
                stratum: dimension.stratum,
                reason_code: dimension.reason_code.clone(),
            });
        }
    }
    Ok(FilesystemCoreEvaluation {
        sequence,
        phase,
        outcome,
        dimensions,
        committed_slot_ids: if committed {
            slots.iter().map(|slot| slot.slot_id.clone()).collect()
        } else {
            Vec::new()
        },
    })
}

fn expected_case_core_evaluations(
    projection: &FilesystemExecutionProjection,
    material: &FilesystemOracleMaterial<'_>,
) -> Result<Vec<FilesystemCoreEvaluation>, CoreError> {
    use generated::Rev2FilesystemCandidateCoreExpectation as Expectation;
    let expectation = material.plan.core_expectation;
    if expectation == Expectation::NotReached {
        return Ok(Vec::new());
    }
    let principal_key = if expectation == Expectation::UnattributedDenyAll {
        "no-user".to_string()
    } else {
        projection
            .execution
            .actors
            .first()
            .and_then(|actor| actor.principal_key.clone())
            .unwrap_or_else(|| projection.effect_owner_key.clone())
    };
    let other_key = projection
        .principals
        .iter()
        .find(|principal| principal.key != projection.effect_owner_key)
        .map(|principal| principal.key.clone());
    let dimension = |slot: &FilesystemEffectSlot,
                     index: usize,
                     expectation: Expectation|
     -> Result<FilesystemCoreDimension, CoreError> {
        let last = index + 1 == material.slots.len();
        let (outcome, stratum, reason) = match expectation {
            Expectation::StaticAllowAll => (FilesystemCoreOutcome::Allow, 9, REASON_ALLOW),
            Expectation::PrincipalDenyAll => {
                (FilesystemCoreOutcome::Deny, 6, REASON_PRINCIPAL_DENIAL)
            }
            Expectation::PrincipalDenyLast if last => {
                (FilesystemCoreOutcome::Deny, 6, REASON_PRINCIPAL_DENIAL)
            }
            Expectation::PrincipalDenyLast => (FilesystemCoreOutcome::Allow, 9, REASON_ALLOW),
            Expectation::ProcessDenyAll => {
                (FilesystemCoreOutcome::Deny, 5, REASON_PROCESS_CEILING)
            }
            Expectation::CrossActionFirstMissing if index == 0 => {
                (FilesystemCoreOutcome::Deny, 17, REASON_MISSING_AUTHORITY)
            }
            Expectation::CrossActionFirstMissing => {
                (FilesystemCoreOutcome::Allow, 9, REASON_ALLOW)
            }
            Expectation::MissingAuthorityAll => {
                (FilesystemCoreOutcome::Deny, 17, REASON_MISSING_AUTHORITY)
            }
            Expectation::UnattributedDenyAll => {
                (FilesystemCoreOutcome::Deny, 2, REASON_UNATTRIBUTED)
            }
            Expectation::QuarantineDenyAll => {
                (FilesystemCoreOutcome::Deny, 14, REASON_QUARANTINE)
            }
            Expectation::SessionRevokedAll => {
                (FilesystemCoreOutcome::Deny, 7, REASON_REVOKED)
            }
            Expectation::SessionRevokedLast if last => {
                (FilesystemCoreOutcome::Deny, 7, REASON_REVOKED)
            }
            Expectation::SessionRevokedLast => (FilesystemCoreOutcome::Allow, 11, REASON_ALLOW),
            Expectation::NotReached => {
                return Err(CoreError::new(
                    REASON_SCHEMA_INVALID,
                    "not-reached core expectation reached dimension derivation",
                ));
            }
        };
        Ok(FilesystemCoreDimension {
            slot_id: slot.slot_id.clone(),
            principal_key: principal_key.clone(),
            outcome,
            stratum,
            reason_code: reason.to_string(),
        })
    };
    let reviewed_dimensions = if expectation == Expectation::MissingAuthorityAll
        && material.plan.principal_plan
            == generated::Rev2FilesystemCandidatePrincipalPlan::ActorAndOther
    {
        let other = other_key.ok_or_else(|| {
            CoreError::new(
                REASON_SCHEMA_INVALID,
                "wrong-principal core expectation has no other identity",
            )
        })?;
        material
            .slots
            .iter()
            .flat_map(|slot| {
                [
                    FilesystemCoreDimension {
                        slot_id: slot.slot_id.clone(),
                        principal_key: projection.effect_owner_key.clone(),
                        outcome: FilesystemCoreOutcome::Deny,
                        stratum: 17,
                        reason_code: REASON_MISSING_AUTHORITY.to_string(),
                    },
                    FilesystemCoreDimension {
                        slot_id: slot.slot_id.clone(),
                        principal_key: other.clone(),
                        outcome: FilesystemCoreOutcome::Allow,
                        stratum: 9,
                        reason_code: REASON_ALLOW.to_string(),
                    },
                ]
            })
            .collect::<Vec<_>>()
    } else {
        material
            .slots
            .iter()
            .enumerate()
            .map(|(index, slot)| dimension(slot, index, expectation))
            .collect::<Result<Vec<_>, CoreError>>()?
    };
    let all_slots = || {
        material
            .slots
            .iter()
            .map(|slot| slot.slot_id.clone())
            .collect::<Vec<_>>()
    };
    if matches!(
        expectation,
        Expectation::SessionRevokedAll | Expectation::SessionRevokedLast
    ) {
        let initial_dimensions = material
            .slots
            .iter()
            .map(|slot| FilesystemCoreDimension {
                slot_id: slot.slot_id.clone(),
                principal_key: principal_key.clone(),
                outcome: FilesystemCoreOutcome::Allow,
                stratum: 11,
                reason_code: REASON_ALLOW.to_string(),
            })
            .collect();
        return Ok(vec![
            FilesystemCoreEvaluation {
                sequence: 0,
                phase: FilesystemCoreEvaluationPhase::Initial,
                outcome: FilesystemCoreOutcome::Allow,
                dimensions: initial_dimensions,
                committed_slot_ids: all_slots(),
            },
            FilesystemCoreEvaluation {
                sequence: 1,
                phase: FilesystemCoreEvaluationPhase::PostFault,
                outcome: FilesystemCoreOutcome::Deny,
                dimensions: reviewed_dimensions,
                committed_slot_ids: Vec::new(),
            },
        ]);
    }
    let outcome = if reviewed_dimensions
        .iter()
        .all(|dimension| dimension.outcome == FilesystemCoreOutcome::Allow)
    {
        FilesystemCoreOutcome::Allow
    } else {
        FilesystemCoreOutcome::Deny
    };
    Ok(vec![FilesystemCoreEvaluation {
        sequence: 0,
        phase: FilesystemCoreEvaluationPhase::Initial,
        outcome,
        dimensions: reviewed_dimensions,
        committed_slot_ids: if material.plan.committed_slots
            == generated::Rev2FilesystemCandidateCommittedSlots::All
        {
            all_slots()
        } else {
            Vec::new()
        },
    }])
}

fn filesystem_core_outcome(outcome: Outcome) -> Result<FilesystemCoreOutcome, CoreError> {
    match outcome {
        Outcome::Allow => Ok(FilesystemCoreOutcome::Allow),
        Outcome::Deny => Ok(FilesystemCoreOutcome::Deny),
        Outcome::Masked => Err(CoreError::new(
            REASON_SCHEMA_INVALID,
            "filesystem candidate core produced an unsupported masked outcome",
        )),
    }
}

fn filesystem_canonical_effect(
    effect: &CanonicalEffect,
) -> Result<FilesystemSharedCoreCanonicalEffect, CoreError> {
    Ok(FilesystemSharedCoreCanonicalEffect {
        edge_id: effect.edge_id.clone(),
        effect_slot_id: effect.effect_slot_id.clone(),
        capability: effect.capability.clone(),
        effect_owner: effect.effect_owner.clone(),
        projection_id: effect.projection_id.clone(),
        occurrence: serde_json::from_value(effect.occurrence.clone()).map_err(schema_error)?,
    })
}

fn shared_core_evaluation(
    request: &StageRequest,
    decision: &StageDecision,
    sequence: usize,
    phase: FilesystemCoreEvaluationPhase,
) -> Result<FilesystemSharedCoreEvaluation, CoreError> {
    if !decision.omitted_effects.is_empty() {
        return Err(CoreError::new(
            REASON_SCHEMA_INVALID,
            "filesystem candidate core emitted masked omissions",
        ));
    }
    let stage_request = FilesystemSharedCoreStageRequest {
        identity: request.identity.clone(),
        stage_id: request.stage_id.clone(),
        principals: request.principals.clone(),
        effects: request
            .effects
            .iter()
            .map(|effect| {
                Ok(FilesystemSharedCoreEffectInput {
                    identity: effect.identity.clone(),
                    edge_id: effect.edge_id.clone(),
                    effect_slot_id: effect.effect_slot_id.clone(),
                    capability: effect.capability.clone(),
                    effect_owner: effect.effect_owner.clone(),
                    occurrence: serde_json::from_value(effect.occurrence.clone())
                        .map_err(schema_error)?,
                })
            })
            .collect::<Result<Vec<_>, CoreError>>()?,
    };
    let stage_decision = FilesystemSharedCoreStageDecision {
        stage_id: decision.stage_id.clone(),
        outcome: filesystem_core_outcome(decision.outcome)?,
        effects: decision
            .effects
            .iter()
            .map(|effect| {
                Ok(FilesystemSharedCoreEffectDecision {
                    effect: filesystem_canonical_effect(&effect.effect)?,
                    outcome: filesystem_core_outcome(effect.outcome)?,
                    dimensions: effect
                        .dimensions
                        .iter()
                        .map(|dimension| {
                            Ok(FilesystemSharedCoreDimension {
                                principal: dimension.principal.clone(),
                                outcome: filesystem_core_outcome(dimension.outcome)?,
                                stratum: dimension.stratum,
                                reason_code: dimension.reason_code.clone(),
                                positive_source: dimension.positive_source.clone(),
                            })
                        })
                        .collect::<Result<Vec<_>, CoreError>>()?,
                })
            })
            .collect::<Result<Vec<_>, CoreError>>()?,
        committed_effects: decision
            .committed_effects
            .iter()
            .map(filesystem_canonical_effect)
            .collect::<Result<Vec<_>, CoreError>>()?,
        omitted_effect_slot_ids: Vec::new(),
        canonical_effects_json: decision.canonical_effects_json.clone(),
    };
    Ok(FilesystemSharedCoreEvaluation {
        sequence,
        phase,
        stage_request,
        stage_decision,
    })
}

fn generated_native_result_class(
    class: generated::Rev2FilesystemCandidateNativeResultClass,
) -> &'static str {
    use generated::Rev2FilesystemCandidateNativeResultClass as Class;
    match class {
        Class::LstatComplete => "lstat-complete",
        Class::LstatNotFound => "lstat-not-found",
        Class::MkdirAlreadyExists => "mkdir-already-exists",
        Class::MkdirComplete => "mkdir-complete",
    }
}

fn authorized_result(
    input: &FilesystemCandidateOracleInput,
    material: &FilesystemOracleMaterial<'_>,
) -> Result<
    (
        FilesystemExpectedResult,
        FilesystemObservedResult,
        Vec<FilesystemSideEffect>,
    ),
    CoreError,
> {
    let model = material.authorized_outcome.native_result;
    let expected_digest = model.metadata_digest.map(|_| FilesystemExpectedResultDigest {
        source: FilesystemExpectedDigestSource::InitialTargetMetadata,
        algorithm: FilesystemExpectedDigestAlgorithm::HjcsSha256Base64url,
        domain: FILESYSTEM_LSTAT_METADATA_DIGEST_DOMAIN.to_string(),
        preimage: FilesystemExpectedDigestPreimage::ExactInitialFilesystemMetadataProjectionJcs,
    });
    let observed_digest = if model.metadata_digest.is_some() {
        let metadata = material
            .target_initial
            .state
            .metadata
            .as_ref()
            .ok_or_else(|| {
                CoreError::new(
                    REASON_SCHEMA_INVALID,
                    "filesystem lstat result requires initial metadata",
                )
            })?;
        Some(hjcs_digest(
            FILESYSTEM_LSTAT_METADATA_DIGEST_DOMAIN,
            &serde_json::to_value(metadata).map_err(schema_error)?,
        )?)
    } else {
        None
    };
    let mut side_effects = Vec::new();
    if !material.authorized_outcome.permitted_side_effects.is_empty() {
        let (requested_mode, mode_derivation) = match (
            &input.case_projection.operation_request,
            material.operation,
        ) {
            (
                FilesystemOperationRequest::MkdirSync { requested_mode, .. },
                generated::Rev2FilesystemCandidateOperationSpec::MkdirSync {
                    mode_derivation,
                    ..
                },
            ) => (*requested_mode, *mode_derivation),
            _ => {
                return Err(CoreError::new(
                    REASON_SCHEMA_INVALID,
                    "filesystem generated side effect is not a mkdir operation",
                ));
            }
        };
        let mode = mode_derivation.directory_type_bits
            | ((requested_mode & mode_derivation.requested_mode_mask)
                & !(input.parent_capture_facts.captured_umask
                    & mode_derivation.captured_umask_mask));
        side_effects.push(FilesystemSideEffect {
            kind: FilesystemSideEffectKind::Create,
            object_id: material.target_setup.object_id.clone(),
            digest: None,
            final_kind: Some(FilesystemObjectKind::Directory),
            mode: Some(mode),
        });
    }
    let class = generated_native_result_class(model.class).to_string();
    Ok((
        FilesystemExpectedResult {
            class: class.clone(),
            digest: expected_digest,
        },
        FilesystemObservedResult {
            class,
            digest: observed_digest,
        },
        side_effects,
    ))
}

fn terminal_outcome(
    input: &FilesystemCandidateOracleInput,
    material: &FilesystemOracleMaterial<'_>,
    evaluations: &[FilesystemCoreEvaluation],
) -> Result<
    (
        FilesystemDecision,
        FilesystemExpectedResult,
        FilesystemObservedResult,
        Vec<FilesystemSideEffect>,
        FilesystemDelivery,
        FilesystemCleanup,
    ),
    CoreError,
> {
    use generated::Rev2FilesystemCandidateOutcomeDisposition as Disposition;
    match material.plan.outcome_disposition {
        Disposition::AuthorizedOperation => {
            if evaluations.last().map(|evaluation| evaluation.outcome)
                != Some(FilesystemCoreOutcome::Allow)
            {
                return Err(CoreError::new(
                    REASON_SCHEMA_INVALID,
                    "generated authorized filesystem case did not allow in the shared core",
                ));
            }
            let (expected, observed, side_effects) = authorized_result(input, material)?;
            Ok((
                FilesystemDecision::Allow,
                expected,
                observed,
                side_effects,
                FilesystemDelivery::Delivered,
                FilesystemCleanup::Complete,
            ))
        }
        Disposition::PermissionDenied => {
            if evaluations.last().map(|evaluation| evaluation.outcome)
                != Some(FilesystemCoreOutcome::Deny)
            {
                return Err(CoreError::new(
                    REASON_SCHEMA_INVALID,
                    "generated denied filesystem case did not deny in the shared core",
                ));
            }
            Ok(terminal_result(
                FilesystemDecision::Deny,
                "permission-denied",
                FilesystemCleanup::Complete,
            ))
        }
        Disposition::SchemaRefused => Ok(terminal_result(
            FilesystemDecision::Refuse,
            "schema-refused",
            FilesystemCleanup::NotStarted,
        )),
        Disposition::CancellationRefused => Ok(terminal_result(
            FilesystemDecision::Refuse,
            "operation-cancelled",
            FilesystemCleanup::Complete,
        )),
        Disposition::ActorSequenceRefused => Ok(terminal_result(
            FilesystemDecision::Refuse,
            "actor-sequence-refused",
            FilesystemCleanup::Complete,
        )),
    }
}

fn terminal_result(
    decision: FilesystemDecision,
    class: &str,
    cleanup: FilesystemCleanup,
) -> (
    FilesystemDecision,
    FilesystemExpectedResult,
    FilesystemObservedResult,
    Vec<FilesystemSideEffect>,
    FilesystemDelivery,
    FilesystemCleanup,
) {
    (
        decision,
        FilesystemExpectedResult {
            class: class.to_string(),
            digest: None,
        },
        FilesystemObservedResult {
            class: class.to_string(),
            digest: None,
        },
        Vec::new(),
        FilesystemDelivery::Withheld,
        cleanup,
    )
}

fn evaluate_filesystem_candidate(
    core: &Rev2Core,
    input: &FilesystemCandidateOracleInput,
) -> Result<FilesystemCandidateOracleOutput, CoreError> {
    let material = filesystem_oracle_material(input)?;
    let malformed = input.case_projection.input_mutation == FilesystemInputMutation::TargetPathDotDot;
    let mut evaluations = Vec::new();
    let mut shared_core_evaluations = Vec::new();
    if !malformed {
        let request = filesystem_stage_request(
            &input.case_projection,
            &material.slots,
            FilesystemCoreEvaluationPhase::Initial,
        )?;
        let policy = filesystem_decision_policy(
            &input.case_projection,
            &material,
            FilesystemCoreEvaluationPhase::Initial,
        )?;
        let decision = core.decide_stage(&request, &policy)?;
        let revocation_fault = matches!(
            input.case_projection.fault_plan.as_ref().map(|fault| &fault.action),
            Some(FilesystemFaultAction::AuthorityRevocation { .. })
        );
        let initial_committed = revocation_fault
            || material.plan.committed_slots
                == generated::Rev2FilesystemCandidateCommittedSlots::All;
        shared_core_evaluations.push(shared_core_evaluation(
            &request,
            &decision,
            0,
            FilesystemCoreEvaluationPhase::Initial,
        )?);
        evaluations.push(summarize_core_decision(
            &decision,
            &material.slots,
            &input.case_projection.constrained_principal_keys,
            0,
            FilesystemCoreEvaluationPhase::Initial,
            initial_committed,
        )?);
        if revocation_fault {
            let request = filesystem_stage_request(
                &input.case_projection,
                &material.slots,
                FilesystemCoreEvaluationPhase::PostFault,
            )?;
            let policy = filesystem_decision_policy(
                &input.case_projection,
                &material,
                FilesystemCoreEvaluationPhase::PostFault,
            )?;
            let decision = core.decide_stage(&request, &policy)?;
            shared_core_evaluations.push(shared_core_evaluation(
                &request,
                &decision,
                1,
                FilesystemCoreEvaluationPhase::PostFault,
            )?);
            evaluations.push(summarize_core_decision(
                &decision,
                &material.slots,
                &input.case_projection.constrained_principal_keys,
                1,
                FilesystemCoreEvaluationPhase::PostFault,
                false,
            )?);
        }
    }
    if evaluations != expected_case_core_evaluations(&input.case_projection, &material)? {
        return Err(CoreError::new(
            REASON_SCHEMA_INVALID,
            "shared-core result differs from the generated filesystem case expectation",
        ));
    }
    let (decision, expected_result, observed_result, side_effects, delivery, cleanup) =
        terminal_outcome(input, &material, &evaluations)?;
    let expected_core = FilesystemExpectedCore {
        disposition: if malformed {
            FilesystemCoreDisposition::NotReached
        } else {
            FilesystemCoreDisposition::Evaluated
        },
        evaluations: evaluations.clone(),
    };
    let expected_outcome = FilesystemExpectedOutcome {
        slots: material.slots.clone(),
        decision,
        result: expected_result,
        side_effects: side_effects.clone(),
        delivery,
        cleanup,
        core: expected_core,
    };
    let projection = &input.case_projection;
    let expected_observation = FilesystemExpectedObservation {
        case_id: projection.case_id.clone(),
        edge_id: projection.edge_id.clone(),
        requirement_id: projection.requirement_id.clone(),
        case_kind: projection.case_kind.clone(),
        slots: material.slots.clone(),
        decision,
        result: observed_result,
        side_effects,
        delivery,
        cleanup,
    };
    // A pre-validation mutation has no runtime-normalized slots. The expected
    // fixture-facing outcome still retains the generated base slots so the
    // parent can compare the refusal without treating malformed input as a new
    // operation shape.
    let runtime_slots = if malformed {
        Vec::new()
    } else {
        material.slots.clone()
    };
    let normalized_slots_digest = hjcs_digest(
        FILESYSTEM_NORMALIZED_SLOTS_DIGEST_DOMAIN,
        &serde_json::to_value(&runtime_slots).map_err(schema_error)?,
    )?;
    let expected_outcome_digest = hjcs_digest(
        FILESYSTEM_EXPECTED_OUTCOME_DIGEST_DOMAIN,
        &serde_json::to_value(&expected_outcome).map_err(schema_error)?,
    )?;
    let expected_observation_digest = hjcs_digest(
        FILESYSTEM_EXPECTED_OBSERVATION_DIGEST_DOMAIN,
        &serde_json::to_value(&expected_observation).map_err(schema_error)?,
    )?;
    Ok(FilesystemCandidateOracleOutput {
        core_identity: core.identity().clone(),
        normalization: FilesystemOracleNormalization {
            operation_request: projection.operation_request.clone(),
            runtime_slots,
        },
        normalized_slots_digest,
        core_evaluations: shared_core_evaluations,
        expected_outcome,
        expected_outcome_digest,
        expected_observation,
        expected_observation_digest,
    })
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
            OracleRequest::EvaluateFilesystemCandidate { input } => {
                serde_json::to_value(evaluate_filesystem_candidate(&core, &input)?)
                    .map_err(schema_error)
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
        "evaluateFilesystemCandidate" => &["operation", "input"],
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
            "canonicalRowDigest": exception.canonical_row_digest,
            "kind": "protected-exception",
            "predicateId": exception.predicate_id,
            "reasonDigest": exception.reason_digest,
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
            Some("path-exact") => {
                decode_platform_path_bytes(selector_path)?
                    == decode_platform_path_bytes(lexical_path)?
            }
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
                if polarity == SelectorPolarity::Negative {
                    // A parent identity authenticates the positive child
                    // location, but it is not an identity for every missing
                    // or proposed sibling. Negative matching remains lexical
                    // until the child has an object identity of its own.
                    false
                } else {
                    let parent = occurrence.get("parentIdentity").ok_or_else(match_type_error)?;
                    binding.parent_identities.contains(parent)
                }
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
    let parent_bytes = decode_platform_path_bytes(parent)?;
    let child_bytes = decode_platform_path_bytes(child)?;
    if parent_bytes == child_bytes {
        return Ok(true);
    }
    if parent_bytes.is_empty() || child_bytes.len() <= parent_bytes.len() {
        return Ok(false);
    }
    Ok(child_bytes.starts_with(&parent_bytes)
        && (parent_bytes.ends_with(b"/") || child_bytes[parent_bytes.len()] == b'/'))
}

fn decode_platform_path_bytes(path: &Value) -> Result<Vec<u8>, CoreError> {
    let path = path.as_object().ok_or_else(match_type_error)?;
    let encoding = path
        .get("encoding")
        .and_then(Value::as_str)
        .ok_or_else(match_type_error)?;
    let payload = path
        .get("value")
        .and_then(Value::as_str)
        .ok_or_else(match_type_error)?;
    decode_platform_path_payload(encoding, payload)
}

fn decode_platform_path_payload(encoding: &str, payload: &str) -> Result<Vec<u8>, CoreError> {
    if payload.is_empty() || payload.chars().count() > 4096 {
        return Err(CoreError::new(
            REASON_SCHEMA_INVALID,
            "platform path payload is empty or unbounded",
        ));
    }
    match encoding {
        "unicode" => Ok(payload.as_bytes().to_vec()),
        "opaque-base64url" => {
            let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
            let decoded = engine.decode(payload).map_err(|_| match_type_error())?;
            if engine.encode(&decoded) != payload {
                return Err(match_type_error());
            }
            Ok(decoded)
        }
        _ => Err(match_type_error()),
    }
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

#[cfg(test)]
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

fn protected_row_digest(
    source_id: &str,
    selector: &CanonicalAuthoritySelector,
    predicate_id: &str,
    reason_digest: &str,
) -> Result<String, CoreError> {
    let preimage = serde_json::json!({
        "sourceId": source_id,
        "selector": selector,
        "predicateId": predicate_id,
        "reasonDigest": reason_digest,
    });
    domain_digest(REV2_RUNTIME_PROTECTED_ROW_DIGEST_DOMAIN, &preimage)
}

fn generated_id_version(id: &str) -> Option<&str> {
    let (_, version) = id.rsplit_once('/')?;
    if version.is_empty()
        || version.starts_with('0')
        || !version.bytes().all(|byte| byte.is_ascii_digit())
    {
        return None;
    }
    Some(version)
}

// @ref LLP 0019#canonical-policy-artifact [implements] — Digest inputs use
// strict I-JSON and byte-exact RFC 8785 serialization.
fn canonicalize_value(value: &Value) -> Result<Value, CoreError> {
    Ok(match value {
        Value::Null | Value::Bool(_) | Value::String(_) => value.clone(),
        Value::Number(number) => {
            validate_i_json_number(number)?;
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
            keys.sort_by(|left, right| left.encode_utf16().cmp(right.encode_utf16()));
            for key in keys {
                sorted.insert(key.clone(), canonicalize_value(&object[key])?);
            }
            Value::Object(sorted)
        }
    })
}

fn validate_i_json_number(number: &serde_json::Number) -> Result<(), CoreError> {
    if let Some(value) = number.as_i64() {
        if !(-I_JSON_SAFE_INTEGER_MAX..=I_JSON_SAFE_INTEGER_MAX).contains(&value) {
            return Err(CoreError::new(
                REASON_SCHEMA_INVALID,
                "I-JSON integer exceeds the exact IEEE-754 safe range",
            ));
        }
        return Ok(());
    }
    if let Some(value) = number.as_u64() {
        if value > I_JSON_SAFE_INTEGER_MAX as u64 {
            return Err(CoreError::new(
                REASON_SCHEMA_INVALID,
                "I-JSON integer exceeds the exact IEEE-754 safe range",
            ));
        }
        return Ok(());
    }
    if number.as_f64().is_some_and(f64::is_finite) {
        return Ok(());
    }
    Err(CoreError::new(
        REASON_SCHEMA_INVALID,
        "non-finite JSON number",
    ))
}

fn write_canonical_json(value: &Value, output: &mut String) -> Result<(), CoreError> {
    match value {
        Value::Null => output.push_str("null"),
        Value::Bool(value) => output.push_str(if *value { "true" } else { "false" }),
        Value::Number(number) => {
            validate_i_json_number(number)?;
            if let Some(value) = number.as_i64() {
                output.push_str(&value.to_string());
            } else if let Some(value) = number.as_u64() {
                output.push_str(&value.to_string());
            } else {
                let value = number.as_f64().ok_or_else(|| {
                    CoreError::new(REASON_SCHEMA_INVALID, "invalid I-JSON number")
                })?;
                output.push_str(ryu_js::Buffer::new().format_finite(value));
            }
        }
        Value::String(value) => {
            output.push_str(&serde_json::to_string(value).map_err(schema_error)?);
        }
        Value::Array(values) => {
            output.push('[');
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    output.push(',');
                }
                write_canonical_json(value, output)?;
            }
            output.push(']');
        }
        Value::Object(object) => {
            output.push('{');
            let mut keys: Vec<&String> = object.keys().collect();
            keys.sort_by(|left, right| left.encode_utf16().cmp(right.encode_utf16()));
            for (index, key) in keys.into_iter().enumerate() {
                if index != 0 {
                    output.push(',');
                }
                output.push_str(&serde_json::to_string(key).map_err(schema_error)?);
                output.push(':');
                write_canonical_json(&object[key], output)?;
            }
            output.push('}');
        }
    }
    Ok(())
}

pub fn canonical_json(value: &Value) -> Result<String, CoreError> {
    let mut output = String::new();
    write_canonical_json(value, &mut output)?;
    Ok(output)
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

/// HJCS is the filesystem evidence framing, distinct from Rev2's historical
/// direct `domain || JCS` semantic digests: `UTF8(domain) || NUL || JCS(value)`.
pub fn hjcs_digest(domain: &str, value: &Value) -> Result<String, CoreError> {
    if domain.is_empty() || domain.as_bytes().contains(&0) {
        return Err(CoreError::new(
            REASON_SCHEMA_INVALID,
            "HJCS digest domain is empty or contains NUL",
        ));
    }
    let canonical = canonical_json(value)?;
    let mut hasher = Sha256::new();
    hasher.update(domain.as_bytes());
    hasher.update([0]);
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

    fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        if !(-I_JSON_SAFE_INTEGER_MAX..=I_JSON_SAFE_INTEGER_MAX).contains(&value) {
            return Err(E::custom(
                "I-JSON integer exceeds the exact IEEE-754 safe range",
            ));
        }
        Ok(StrictJson(Value::Number(value.into())))
    }

    fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E>
    where
        E: de::Error,
    {
        if value > I_JSON_SAFE_INTEGER_MAX as u64 {
            return Err(E::custom(
                "I-JSON integer exceeds the exact IEEE-754 safe range",
            ));
        }
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

// serde_json promotes integer tokens outside u64 into f64 before a Visitor can
// distinguish their lexical class. Preflight integer tokens so the safe-range
// rule cannot be bypassed through that lossy promotion; fractions and
// exponent-form numbers remain binary64 values.
fn validate_i_json_integer_tokens(input: &str) -> Result<(), CoreError> {
    let bytes = input.as_bytes();
    let mut index = 0;
    let mut in_string = false;
    let mut escaped = false;
    while index < bytes.len() {
        if in_string {
            if escaped {
                escaped = false;
            } else if bytes[index] == b'\\' {
                escaped = true;
            } else if bytes[index] == b'"' {
                in_string = false;
            }
            index += 1;
            continue;
        }
        if bytes[index] == b'"' {
            in_string = true;
            index += 1;
            continue;
        }
        if bytes[index] != b'-' && !bytes[index].is_ascii_digit() {
            index += 1;
            continue;
        }

        let token_start = index;
        if bytes[index] == b'-' {
            index += 1;
        }
        let digits_start = index;
        while index < bytes.len() && bytes[index].is_ascii_digit() {
            index += 1;
        }
        if digits_start == index {
            index = token_start + 1;
            continue;
        }
        let digits_end = index;
        let mut has_fraction_or_exponent = false;
        if index < bytes.len() && bytes[index] == b'.' {
            has_fraction_or_exponent = true;
            index += 1;
            while index < bytes.len() && bytes[index].is_ascii_digit() {
                index += 1;
            }
        }
        if index < bytes.len() && matches!(bytes[index], b'e' | b'E') {
            has_fraction_or_exponent = true;
            index += 1;
            if index < bytes.len() && matches!(bytes[index], b'+' | b'-') {
                index += 1;
            }
            while index < bytes.len() && bytes[index].is_ascii_digit() {
                index += 1;
            }
        }
        if has_fraction_or_exponent {
            continue;
        }

        let mut significant_start = digits_start;
        while significant_start < digits_end && bytes[significant_start] == b'0' {
            significant_start += 1;
        }
        let magnitude = &bytes[significant_start..digits_end];
        const SAFE_MAX: &[u8] = b"9007199254740991";
        if magnitude.len() > SAFE_MAX.len()
            || (magnitude.len() == SAFE_MAX.len() && magnitude > SAFE_MAX)
        {
            return Err(CoreError::new(
                REASON_SCHEMA_INVALID,
                "I-JSON integer exceeds the exact IEEE-754 safe range",
            ));
        }
    }
    Ok(())
}

pub fn parse_strict_json(input: &str) -> Result<Value, CoreError> {
    validate_i_json_integer_tokens(input)?;
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

fn validate_runtime_risk_contract(
    payload: &RuntimePayload,
    definitions: &BTreeMap<String, Definition>,
) -> Result<RiskIndex, CoreError> {
    let rules = &payload.policy_rules_and_classifiers;
    if !rules.public_suffix_input.is_object() {
        return Err(CoreError::new(
            REASON_SCHEMA_INVALID,
            "runtime public-suffix risk input is not a retained object",
        ));
    }
    if rules.risk_rules.is_empty() || rules.risk_rules.len() > 256 {
        return Err(CoreError::new(
            REASON_SCHEMA_INVALID,
            "runtime risk-rule set is empty or over-bound",
        ));
    }
    let risk_fields = unique_by_id(
        rules.risk_evaluation_spec.fields.iter().cloned(),
        |field| &field.name,
    )?;
    if risk_fields.is_empty() || risk_fields.len() > MAX_RISK_FIELDS_PER_SCOPE {
        return Err(CoreError::new(
            REASON_SCHEMA_INVALID,
            "runtime risk-field set is empty or over-bound",
        ));
    }
    for field in risk_fields.values() {
        if !matches!(field.value_type.as_str(), "boolean" | "integer" | "string" | "string-array")
            || !field.format.starts_with("risk-input:")
            || !matches!(field.canonicalization.as_str(), "identity" | "deduplicate-sort-canonical")
            || field.required
            || field.schema_ref.is_some()
        {
            return Err(CoreError::new(
                REASON_SCHEMA_INVALID,
                format!("risk field {} has an unsupported generated contract", field.name),
            ));
        }
    }

    let trigger_specs = unique_by_id(
        rules.risk_evaluation_spec.trigger_kinds.iter().cloned(),
        |spec| &spec.kind,
    )?;
    let classifier_ids: BTreeSet<&str> = rules
        .risk_evaluation_spec
        .classifier_data_ids
        .iter()
        .map(String::as_str)
        .collect();
    if classifier_ids.len() != rules.risk_evaluation_spec.classifier_data_ids.len() {
        return Err(CoreError::new(
            REASON_SCHEMA_INVALID,
            "runtime risk classifier IDs are not unique",
        ));
    }
    for classifier_id in &classifier_ids {
        if !risk_classifier_data_is_present(rules, classifier_id) {
            return Err(CoreError::new(
                REASON_SCHEMA_INVALID,
                format!("runtime risk classifier {classifier_id} has no retained data"),
            ));
        }
    }
    for spec in trigger_specs.values() {
        if risk_algorithm_for_kind(&spec.kind) != Some(spec.algorithm.as_str())
            || spec.allowed_field_types.is_empty()
            || spec.allowed_field_types.iter().any(|value_type| {
                !matches!(value_type.as_str(), "boolean" | "integer" | "string" | "string-array")
            })
            || !matches!(spec.values.as_str(), "required" | "forbidden")
            || !matches!(spec.threshold.as_str(), "required" | "forbidden")
            || !matches!(spec.classifier_data.as_str(), "required" | "optional" | "forbidden")
        {
            return Err(CoreError::new(
                REASON_SCHEMA_INVALID,
                format!("risk trigger kind {} has an unsupported generated contract", spec.kind),
            ));
        }
    }

    let reason_codes: BTreeMap<&str, &str> = rules
        .reason_codes
        .iter()
        .map(|row| (row.id.as_str(), row.class.as_str()))
        .collect();
    if reason_codes.len() != rules.reason_codes.len() {
        return Err(CoreError::new(
            REASON_SCHEMA_INVALID,
            "runtime reason-code IDs are not unique",
        ));
    }
    let risk_rules = unique_by_id(rules.risk_rules.iter().cloned(), |rule| &rule.id)?;
    let mut used_trigger_kinds = BTreeSet::new();
    let mut used_classifier_ids = BTreeSet::new();
    for rule in risk_rules.values() {
        if !matches!(rule.attachment.as_str(), "definition" | "global")
            || rule.minimum_tier > 4
            || rule.reason_code.is_empty()
            || reason_codes.get(rule.reason_code.as_str()) != Some(&"risk")
            || rule.trigger.fields.is_empty()
            || rule.trigger.fields.len() > MAX_RISK_FIELDS_PER_SCOPE
        {
            return Err(CoreError::new(
                REASON_SCHEMA_INVALID,
                format!("risk rule {} has an invalid tier, attachment, or reason", rule.id),
            ));
        }
        let trigger_spec = trigger_specs.get(&rule.trigger.kind).ok_or_else(|| {
            CoreError::new(
                REASON_SCHEMA_INVALID,
                format!("risk rule {} names unknown trigger kind {}", rule.id, rule.trigger.kind),
            )
        })?;
        used_trigger_kinds.insert(rule.trigger.kind.as_str());
        let trigger_fields: BTreeSet<&str> =
            rule.trigger.fields.iter().map(String::as_str).collect();
        let trigger_values: BTreeSet<&str> =
            rule.trigger.values.iter().map(String::as_str).collect();
        if trigger_fields.len() != rule.trigger.fields.len()
            || trigger_values.len() != rule.trigger.values.len()
        {
            return Err(CoreError::new(
                REASON_SCHEMA_INVALID,
                format!("risk rule {} repeats a field or value", rule.id),
            ));
        }
        for field_name in &rule.trigger.fields {
            let field = risk_fields.get(field_name).ok_or_else(|| {
                CoreError::new(
                    REASON_SCHEMA_INVALID,
                    format!("risk rule {} names unknown field {field_name}", rule.id),
                )
            })?;
            if !trigger_spec.allowed_field_types.contains(&field.value_type) {
                return Err(CoreError::new(
                    REASON_SCHEMA_INVALID,
                    format!(
                        "risk trigger {} rejects field type {}",
                        rule.id, field.value_type
                    ),
                ));
            }
        }
        validate_risk_trigger_slot(
            &rule.id,
            "values",
            !rule.trigger.values.is_empty(),
            &trigger_spec.values,
        )?;
        validate_risk_trigger_slot(
            &rule.id,
            "threshold",
            rule.trigger.threshold.is_some(),
            &trigger_spec.threshold,
        )?;
        validate_risk_trigger_slot(
            &rule.id,
            "classifierDataId",
            rule.trigger.classifier_data_id.is_some(),
            &trigger_spec.classifier_data,
        )?;
        if let Some(classifier_id) = &rule.trigger.classifier_data_id {
            if !classifier_ids.contains(classifier_id.as_str())
                || !risk_classifier_is_supported(&rule.trigger.kind, classifier_id)
            {
                return Err(CoreError::new(
                    REASON_SCHEMA_INVALID,
                    format!("risk rule {} names unsupported classifier {classifier_id}", rule.id),
                ));
            }
            used_classifier_ids.insert(classifier_id.as_str());
        }
    }
    if used_trigger_kinds.len() != trigger_specs.len()
        || used_classifier_ids.len() != classifier_ids.len()
    {
        return Err(CoreError::new(
            REASON_SCHEMA_INVALID,
            "runtime risk trigger or classifier registry is incomplete",
        ));
    }

    let mut referenced_definition_rules = BTreeSet::new();
    for definition in definitions.values() {
        if definition.base_risk > 4 {
            return Err(CoreError::new(
                REASON_SCHEMA_INVALID,
                format!("definition {} has out-of-range base risk", definition.id),
            ));
        }
        for (field_name, value) in [
            ("definition.lifecycle", definition.lifecycle.as_str()),
            ("definition.globality", definition.globality.as_str()),
        ] {
            let field = risk_fields.get(field_name).ok_or_else(|| {
                CoreError::new(
                    REASON_SCHEMA_INVALID,
                    format!("runtime risk schema omits derived field {field_name}"),
                )
            })?;
            validate_risk_field_value(field, &Value::String(value.to_string()))?;
        }
        let unique_rule_ids: BTreeSet<&str> =
            definition.risk_rule_ids.iter().map(String::as_str).collect();
        if unique_rule_ids.len() != definition.risk_rule_ids.len() {
            return Err(CoreError::new(
                REASON_SCHEMA_INVALID,
                format!("definition {} repeats a risk rule", definition.id),
            ));
        }
        for rule_id in &definition.risk_rule_ids {
            let rule = risk_rules.get(rule_id).ok_or_else(|| {
                CoreError::new(
                    REASON_SCHEMA_INVALID,
                    format!("definition {} names unknown risk rule {rule_id}", definition.id),
                )
            })?;
            if rule.attachment != "definition" {
                return Err(CoreError::new(
                    REASON_SCHEMA_INVALID,
                    format!("definition {} attaches global risk rule {rule_id}", definition.id),
                ));
            }
            referenced_definition_rules.insert(rule_id.as_str());
        }
    }
    let declared_definition_rules: BTreeSet<&str> = risk_rules
        .values()
        .filter(|rule| rule.attachment == "definition")
        .map(|rule| rule.id.as_str())
        .collect();
    if referenced_definition_rules != declared_definition_rules {
        return Err(CoreError::new(
            REASON_SCHEMA_INVALID,
            "runtime definition risk-rule references are incomplete",
        ));
    }
    let mut global_risk_rule_ids: Vec<String> = risk_rules
        .values()
        .filter(|rule| rule.attachment == "global")
        .map(|rule| rule.id.clone())
        .collect();
    global_risk_rule_ids.sort_by(|left, right| {
        let left_rule = &risk_rules[left];
        let right_rule = &risk_rules[right];
        (left_rule.reason_code.as_str(), left_rule.id.as_str())
            .cmp(&(right_rule.reason_code.as_str(), right_rule.id.as_str()))
    });
    if global_risk_rule_ids.is_empty() {
        return Err(CoreError::new(
            REASON_SCHEMA_INVALID,
            "runtime vocabulary has no global risk rules",
        ));
    }
    Ok(RiskIndex {
        rules: risk_rules,
        fields: risk_fields,
        global_rule_ids: global_risk_rule_ids,
    })
}

fn risk_algorithm_for_kind(kind: &str) -> Option<&'static str> {
    match kind {
        "accretion-threshold" | "count-at-least" => Some("numeric-at-least"),
        "field-equals" => Some("equals-any"),
        "field-member-in" => Some("member-in-values"),
        "named-set-member" => Some("classifier-member"),
        "path-classifier" => Some("classifier-path-match"),
        "source-sink-composition" => Some("source-sink-threshold"),
        _ => None,
    }
}

fn risk_classifier_data_is_present(rules: &Rules, classifier_id: &str) -> bool {
    match classifier_id {
        "ambientNetworkConfigNeutralization" => {
            rules.ambient_network_config_neutralization.is_some()
        }
        "ipAddressClasses" => rules.ip_address_classes.as_ref().is_some_and(|classes| {
            classes.ipv4_mapped_ipv6
                == "normalize-to-effective-ipv4-before-classification"
        }),
        "loaderControlEnvironmentNames" => !rules.loader_control_environment_names.is_empty(),
        "sensitiveEnvironmentNames" => !rules.sensitive_environment_names.is_empty(),
        "specialFiles" => !rules.special_files.is_empty(),
        "systemInformationKinds" => !rules.system_information_kinds.is_empty(),
        _ => false,
    }
}

fn risk_classifier_is_supported(kind: &str, classifier_id: &str) -> bool {
    matches!(
        (kind, classifier_id),
        ("field-member-in", "ambientNetworkConfigNeutralization")
            | ("field-member-in", "ipAddressClasses")
            | ("field-member-in", "systemInformationKinds")
            | ("named-set-member", "loaderControlEnvironmentNames")
            | ("named-set-member", "sensitiveEnvironmentNames")
            | ("path-classifier", "specialFiles")
    )
}

fn validate_risk_trigger_slot(
    rule_id: &str,
    slot: &str,
    present: bool,
    disposition: &str,
) -> Result<(), CoreError> {
    let valid = match disposition {
        "required" => present,
        "forbidden" => !present,
        "optional" => true,
        _ => false,
    };
    if valid {
        Ok(())
    } else {
        Err(CoreError::new(
            REASON_SCHEMA_INVALID,
            format!("risk rule {rule_id} violates its {slot} contract"),
        ))
    }
}

fn validate_risk_field_value(spec: &RiskFieldSpec, value: &Value) -> Result<(), CoreError> {
    let valid = match spec.value_type.as_str() {
        "boolean" => value.is_boolean(),
        "integer" => value
            .as_u64()
            .is_some_and(|integer| integer <= I_JSON_SAFE_INTEGER_MAX as u64),
        "string" => value
            .as_str()
            .is_some_and(|string| string.len() <= MAX_RISK_STRING_BYTES),
        "string-array" => value.as_array().is_some_and(|values| {
            values.len() <= MAX_RISK_ARRAY_ITEMS
                && values.iter().all(|entry| {
                    entry
                        .as_str()
                        .is_some_and(|string| string.len() <= MAX_RISK_STRING_BYTES)
                })
        }),
        _ => false,
    };
    if !valid {
        return Err(CoreError::new(
            REASON_SCHEMA_INVALID,
            format!("risk field {} has the wrong type or exceeds its bound", spec.name),
        ));
    }
    if let Some(allowed_values) = &spec.allowed_values {
        let allowed = match value {
            Value::String(value) => allowed_values.contains(value),
            Value::Bool(value) => allowed_values.iter().any(|allowed| allowed == &value.to_string()),
            _ => true,
        };
        if !allowed {
            return Err(CoreError::new(
                REASON_SCHEMA_INVALID,
                format!("risk field {} is outside its generated value domain", spec.name),
            ));
        }
    }
    Ok(())
}

fn insert_risk_reason(
    reasons: &mut BTreeMap<(String, String), RiskReason>,
    rule: &RiskRule,
) -> Result<(), CoreError> {
    let key = (rule.reason_code.clone(), rule.id.clone());
    let reason = RiskReason {
        rule_id: rule.id.clone(),
        reason_code: rule.reason_code.clone(),
        minimum_tier: rule.minimum_tier,
    };
    if let Some(previous) = reasons.insert(key, reason.clone()) {
        if previous != reason {
            return Err(CoreError::new(
                REASON_SCHEMA_INVALID,
                format!("risk rule {} produced inconsistent reasons", rule.id),
            ));
        }
    }
    Ok(())
}

fn risk_rule_applies(
    rule: &RiskRule,
    fields: &BTreeMap<String, Value>,
    rules: &Rules,
) -> Result<bool, CoreError> {
    match rule.trigger.kind.as_str() {
        "field-equals" => Ok(rule.trigger.fields.iter().any(|field| {
            fields.get(field).is_some_and(|value| {
                rule.trigger.values.iter().any(|expected| match value {
                    Value::Bool(actual) => expected == &actual.to_string(),
                    Value::String(actual) => expected == actual,
                    _ => false,
                })
            })
        })),
        "field-member-in" => Ok(rule.trigger.fields.iter().any(|field| {
            fields.get(field).is_some_and(|value| {
                risk_string_values(value).any(|actual| rule.trigger.values.iter().any(|expected| expected == actual))
            })
        })),
        "named-set-member" => {
            let classifier_id = rule.trigger.classifier_data_id.as_deref().ok_or_else(|| {
                CoreError::new(REASON_SCHEMA_INVALID, format!("risk rule {} has no classifier", rule.id))
            })?;
            Ok(rule.trigger.fields.iter().any(|field| {
                fields.get(field).is_some_and(|value| {
                    risk_string_values(value)
                        .any(|actual| risk_named_classifier_contains(rules, classifier_id, actual))
                })
            }))
        }
        "path-classifier" => Ok(risk_path_classifier_applies(rule, fields, rules)),
        "count-at-least" => {
            let threshold = rule.trigger.threshold.ok_or_else(|| {
                CoreError::new(REASON_SCHEMA_INVALID, format!("risk rule {} has no threshold", rule.id))
            })?;
            Ok(rule.trigger.fields.iter().any(|field| {
                fields.get(field).and_then(Value::as_u64).is_some_and(|value| value >= threshold)
            }))
        }
        "accretion-threshold" => {
            let threshold = rule.trigger.threshold.ok_or_else(|| {
                CoreError::new(REASON_SCHEMA_INVALID, format!("risk rule {} has no threshold", rule.id))
            })?;
            let total = rule.trigger.fields.iter().try_fold(0_u64, |total, field| {
                total.checked_add(fields.get(field).and_then(Value::as_u64).unwrap_or(0))
                    .ok_or_else(|| CoreError::new(REASON_SCHEMA_INVALID, "risk accretion count overflow"))
            })?;
            Ok(total >= threshold)
        }
        "source-sink-composition" => {
            let threshold = rule.trigger.threshold.ok_or_else(|| {
                CoreError::new(REASON_SCHEMA_INVALID, format!("risk rule {} has no threshold", rule.id))
            })?;
            let mut matched = BTreeSet::new();
            for field in &rule.trigger.fields {
                if let Some(value) = fields.get(field) {
                    for actual in risk_string_values(value) {
                        if rule.trigger.values.iter().any(|expected| expected == actual) {
                            matched.insert(actual);
                        }
                    }
                }
            }
            Ok(matched.len() as u64 >= threshold)
        }
        unknown => Err(CoreError::new(
            REASON_SCHEMA_INVALID,
            format!("risk rule {} has unsupported trigger kind {unknown}", rule.id),
        )),
    }
}

fn risk_string_values(value: &Value) -> impl Iterator<Item = &str> {
    value
        .as_str()
        .into_iter()
        .chain(value.as_array().into_iter().flatten().filter_map(Value::as_str))
}

fn risk_named_classifier_contains(rules: &Rules, classifier_id: &str, value: &str) -> bool {
    match classifier_id {
        "loaderControlEnvironmentNames" => rules
            .loader_control_environment_names
            .iter()
            .any(|candidate| candidate == value),
        "sensitiveEnvironmentNames" => rules
            .sensitive_environment_names
            .iter()
            .any(|candidate| candidate == value),
        _ => false,
    }
}

fn risk_path_classifier_applies(
    rule: &RiskRule,
    fields: &BTreeMap<String, Value>,
    rules: &Rules,
) -> bool {
    if fields
        .get("resource.objectClass")
        .and_then(Value::as_str)
        .is_some_and(|class| rule.trigger.values.iter().any(|expected| expected == class))
    {
        return true;
    }
    let Some(path) = fields.get("resource.logicalPath").and_then(Value::as_str) else {
        return false;
    };
    rules.special_files.iter().any(|special| {
        special.path == path
            && !special.platform.is_empty()
            && rule
                .trigger
                .values
                .iter()
                .any(|expected| expected == &special.classification)
    })
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
                || effect.positive_channels.as_ref().is_some_and(|channels| {
                    semantics.effect_mode != "alternative"
                        || channels.iter().any(|channel| {
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
                })
        });
    let branch_channel_overrides = semantics
        .effects
        .iter()
        .filter(|effect| effect.positive_channels.is_some())
        .count();
    let invalid = invalid
        || branch_channel_overrides != 0 && branch_channel_overrides != semantics.effects.len();
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
    use crate::rev2_registry_generated::{
        REV2_RUNTIME_EXTERNAL_RESPONSE_MAC_DOMAIN,
        REV2_RUNTIME_PERMISSION_BATCH_DIGEST_DOMAIN, REV2_RUNTIME_PERMISSION_BRANCHES,
        REV2_RUNTIME_PROTOCOL_FIXTURE_CORPUS_DIGEST,
        REV2_RUNTIME_PROTOCOL_FIXTURE_CORPUS_JSON,
        REV2_RUNTIME_PROTOCOL_SPEC_JSON,
        REV2_RUNTIME_PROTECTED_ROW_DIGEST_DOMAIN, REV2_RUNTIME_SESSION_POSITIVE_ROW_ID_DOMAIN,
        REV2_RUNTIME_SESSION_REVOCATION_ROW_ID_DOMAIN,
    };
    use proptest::prelude::*;
    use serde_json::json;

    // Compile-time negative assertion: the opaque candidate token must not
    // acquire a wire constructor through a future derive or blanket impl.
    const _: fn() = || {
        trait AmbiguousIfDeserialize<A> {
            fn marker() {}
        }
        impl<T: ?Sized> AmbiguousIfDeserialize<()> for T {}
        struct ImplementsDeserialize;
        impl<T: ?Sized + serde::de::DeserializeOwned>
            AmbiguousIfDeserialize<ImplementsDeserialize> for T
        {
        }
        let _ = <ValidatedFilesystemCandidateExecution as AmbiguousIfDeserialize<_>>::marker;
    };

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
    const PERMISSION_QUERY_EDGE: &str =
        "native-op:runtime/ops/permissions.rs#op_query_permission";
    const PERMISSION_QUERY_SYS_SLOT: &str =
        "native-op:runtime/ops/permissions.rs#op_query_permission:effect-slot:2";
    const PERMISSION_QUERY_RUN_SLOT: &str =
        "native-op:runtime/ops/permissions.rs#op_query_permission:effect-slot:1";
    const PERMISSION_REVOKE_EDGE: &str =
        "native-op:runtime/ops/permissions.rs#op_revoke_permission";
    const PERMISSION_REVOKE_SYS_SLOT: &str =
        "native-op:runtime/ops/permissions.rs#op_revoke_permission:effect-slot:2";
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

    fn fixture_hmac_sha256(key: &[u8], input: &[u8]) -> Vec<u8> {
        assert!(key.len() <= 64);
        let mut padded = [0_u8; 64];
        padded[..key.len()].copy_from_slice(key);
        let mut inner_pad = [0x36_u8; 64];
        let mut outer_pad = [0x5c_u8; 64];
        for index in 0..64 {
            inner_pad[index] ^= padded[index];
            outer_pad[index] ^= padded[index];
        }
        let mut inner = Sha256::new();
        inner.update(inner_pad);
        inner.update(input);
        let inner_digest = inner.finalize();
        let mut outer = Sha256::new();
        outer.update(outer_pad);
        outer.update(inner_digest);
        outer.finalize().to_vec()
    }

    fn fixture_base64url(value: &str) -> Vec<u8> {
        let engine = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let decoded = engine.decode(value).unwrap();
        assert_eq!(engine.encode(&decoded), value);
        decoded
    }

    #[test]
    fn generated_runtime_protocol_corpus_recomputes_in_the_shared_rust_core() {
        let corpus = parse_strict_json(REV2_RUNTIME_PROTOCOL_FIXTURE_CORPUS_JSON).unwrap();
        let mut source_bytes = REV2_RUNTIME_PROTOCOL_FIXTURE_CORPUS_JSON.as_bytes().to_vec();
        source_bytes.push(b'\n');
        let source_digest = Sha256::digest(source_bytes);
        assert_eq!(
            format!(
                "sha256-{}",
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(source_digest)
            ),
            REV2_RUNTIME_PROTOCOL_FIXTURE_CORPUS_DIGEST
        );

        let core = Rev2Core::embedded().unwrap();
        assert_eq!(
            corpus["branchBatchVectors"]
                .as_array()
                .unwrap()
                .iter()
                .map(|row| row["id"].as_str().unwrap())
                .collect::<Vec<_>>(),
            [
                "branch-dynamic-read-request",
                "branch-dynamic-sys-request",
                "branch-dynamic-write-request",
                "branch-static-ffi-query",
                "branch-static-ffi-request-refusal",
                "branch-static-run-query",
                "branch-static-run-request-refusal",
            ]
        );
        assert_eq!(
            corpus["sessionRowIdVectors"]
                .as_array()
                .unwrap()
                .iter()
                .map(|row| row["id"].as_str().unwrap())
                .collect::<Vec<_>>(),
            [
                "session-row-dynamic-read-package",
                "session-row-dynamic-sys-package",
                "session-row-dynamic-write-package",
            ]
        );
        for vector in corpus["branchBatchVectors"].as_array().unwrap() {
            let descriptor = vector["descriptor"].as_object().unwrap();
            let operation = vector["operation"].as_str().unwrap();
            let expected = vector["expected"].as_object().unwrap();
            let descriptor_name = descriptor["name"].as_str().unwrap();
            let descriptor_keys = descriptor.keys().map(String::as_str).collect::<BTreeSet<_>>();
            let matching = REV2_RUNTIME_PERMISSION_BRANCHES
                .iter()
                .filter(|branch| branch.descriptor_name == descriptor_name)
                .filter(|branch| {
                    let keys = branch
                        .descriptor_required_fields
                        .iter()
                        .chain(branch.descriptor_optional_fields.iter())
                        .copied()
                        .collect::<BTreeSet<_>>();
                    if keys != descriptor_keys {
                        return false;
                    }
                    branch.descriptor_scope_field.is_none_or(|field| {
                        descriptor
                            .get(field)
                            .and_then(Value::as_str)
                            .is_some_and(|value| !value.is_empty())
                    })
                })
                .collect::<Vec<_>>();
            assert_eq!(matching.len(), 1, "{}", vector["id"]);
            let branch = matching[0];
            assert_eq!(branch.id, expected["branchId"]);
            assert_eq!(branch.disposition, expected["branchDisposition"]);
            let transition = |slot: &crate::rev2_registry_generated::Rev2RuntimePermissionSlot| {
                match operation {
                    "query" => slot.transitions.query,
                    "request" => slot.transitions.request,
                    "revoke" => slot.transitions.revoke,
                    other => panic!("unknown fixture operation {other}"),
                }
            };
            let effect_slot =
                |slot: &crate::rev2_registry_generated::Rev2RuntimePermissionSlot| match operation {
                    "query" => slot.operation_effect_slot_ids.query,
                    "request" => slot.operation_effect_slot_ids.request,
                    "revoke" => slot.operation_effect_slot_ids.revoke,
                    other => panic!("unknown fixture operation {other}"),
                };
            let transitions = branch.slot_order.iter().map(transition).collect::<Vec<_>>();
            let disposition = if transitions.is_empty() {
                "refuse-unsupported-descriptor"
            } else if transitions.iter().all(|value| *value == transitions[0]) {
                transitions[0]
            } else {
                "refuse-unsupported-descriptor"
            };
            assert_eq!(disposition, expected["operationDisposition"]);
            assert_eq!(
                branch.slot_order.iter().map(|slot| slot.slot_id).collect::<Vec<_>>(),
                expected["logicalSlotIds"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(Value::as_str)
                    .collect::<Option<Vec<_>>>()
                    .unwrap()
            );
            assert_eq!(
                branch.slot_order.iter().filter_map(effect_slot).collect::<Vec<_>>(),
                expected["operationEffectSlotIds"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(Value::as_str)
                    .collect::<Option<Vec<_>>>()
                    .unwrap()
            );
            assert_eq!(
                branch.slot_order.iter().map(|slot| slot.capability).collect::<Vec<_>>(),
                expected["capabilities"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(Value::as_str)
                    .collect::<Option<Vec<_>>>()
                    .unwrap()
            );

            let Some(batch) = expected["batchWithoutDigest"].as_object() else {
                assert!(expected["batchDigest"].is_null());
                continue;
            };
            let batch_value = Value::Object(batch.clone());
            assert_eq!(
                domain_digest(REV2_RUNTIME_PERMISSION_BATCH_DIGEST_DOMAIN, &batch_value).unwrap(),
                expected["batchDigest"]
            );
            assert_eq!(batch["operation"], operation);
            let edge_id = batch["coverageEdgeId"].as_str().unwrap();
            let expected_edge = match operation {
                "query" => branch.operation_edge_ids.query,
                "request" => branch.operation_edge_ids.request,
                "revoke" => branch.operation_edge_ids.revoke,
                _ => unreachable!(),
            };
            assert_eq!(edge_id, expected_edge);
            for (index, effect) in batch["effects"].as_array().unwrap().iter().enumerate() {
                let selector = effect["selector"].as_object().unwrap();
                let owner: PrincipalRef =
                    serde_json::from_value(effect["effectOwner"].clone()).unwrap();
                let normalized_selector = core
                    .normalize_selector(
                        &AuthoritySelectorInput {
                            identity: EngineIdentity::embedded(),
                            principal: Some(
                                serde_json::from_value(selector["principal"].clone()).unwrap(),
                            ),
                            capability: selector["capability"].as_str().unwrap().to_string(),
                            resource: selector["resource"].clone(),
                        },
                        SelectorPolarity::Positive,
                    )
                    .unwrap();
                assert_eq!(
                    serde_json::to_value(normalized_selector).unwrap(),
                    Value::Object(selector.clone())
                );
                core.normalize_effect(&EffectInput {
                    identity: EngineIdentity::embedded(),
                    edge_id: edge_id.to_string(),
                    effect_slot_id: effect_slot(&branch.slot_order[index]).unwrap().to_string(),
                    capability: selector["capability"].as_str().unwrap().to_string(),
                    effect_owner: owner.key,
                    occurrence: effect["occurrence"].clone(),
                })
                .unwrap();
                if selector["capability"] == "process:spawn" {
                    assert_eq!(
                        effect["occurrence"]["launchSet"],
                        json!([{
                            "kind": "entry",
                            "value": effect["occurrence"]["requestedPath"]["value"],
                        }]),
                        "{}",
                        vector["id"]
                    );
                }
            }
        }

        for vector in corpus["externalResponseMacVectors"].as_array().unwrap() {
            let response = &vector["responseWithoutAuthenticationTag"];
            let canonical = canonical_json(response).unwrap();
            assert_eq!(canonical, vector["canonicalPayload"]);
            let mut input = REV2_RUNTIME_EXTERNAL_RESPONSE_MAC_DOMAIN.as_bytes().to_vec();
            input.extend_from_slice(canonical.as_bytes());
            assert_eq!(fixture_base64url(vector["macInputBase64url"].as_str().unwrap()), input);
            let key = fixture_base64url(vector["key"].as_str().unwrap());
            let tag = fixture_base64url(vector["authenticationTag"].as_str().unwrap());
            assert_eq!(key.len(), 32);
            assert_eq!(tag.len(), 32);
            assert_eq!(fixture_hmac_sha256(&key, &input), tag);
        }
        for vector in corpus["sessionRowIdVectors"].as_array().unwrap() {
            let mut preimage = vector["preimage"].clone();
            let selector = &preimage["identitySelector"];
            let normalized = core
                .normalize_selector(
                    &AuthoritySelectorInput {
                        identity: EngineIdentity::embedded(),
                        principal: Some(
                            serde_json::from_value(selector["principal"].clone()).unwrap(),
                        ),
                        capability: selector["capability"].as_str().unwrap().to_string(),
                        resource: selector["resource"].clone(),
                    },
                    SelectorPolarity::Positive,
                )
                .unwrap();
            preimage["identitySelector"] = json!({
                "capability": normalized.capability,
                "principal": normalized.principal,
                "resource": normalized.resource,
            });
            assert_eq!(canonical_json(&preimage).unwrap(), vector["canonicalPreimage"]);
            assert_eq!(
                domain_digest(REV2_RUNTIME_SESSION_POSITIVE_ROW_ID_DOMAIN, &preimage).unwrap(),
                vector["positiveRowId"]
            );
            assert_eq!(
                domain_digest(REV2_RUNTIME_SESSION_REVOCATION_ROW_ID_DOMAIN, &preimage).unwrap(),
                vector["revocationRowId"]
            );
        }
        for vector in corpus["protectedRowDigestVectors"].as_array().unwrap() {
            let mut preimage = vector["preimage"].clone();
            let selector = &preimage["selector"];
            let normalized = core
                .normalize_selector(
                    &AuthoritySelectorInput {
                        identity: EngineIdentity::embedded(),
                        principal: Some(
                            serde_json::from_value(selector["principal"].clone()).unwrap(),
                        ),
                        capability: selector["capability"].as_str().unwrap().to_string(),
                        resource: selector["resource"].clone(),
                    },
                    SelectorPolarity::Positive,
                )
                .unwrap();
            assert_eq!(serde_json::to_value(&normalized).unwrap(), *selector);
            preimage["selector"] = serde_json::to_value(normalized).unwrap();
            assert_eq!(canonical_json(&preimage).unwrap(), vector["canonicalPreimage"]);
            assert_eq!(
                domain_digest(REV2_RUNTIME_PROTECTED_ROW_DIGEST_DOMAIN, &preimage).unwrap(),
                vector["digest"]
            );
        }
        let protocol_spec = parse_strict_json(REV2_RUNTIME_PROTOCOL_SPEC_JSON).unwrap();
        let evidence_spec = &protocol_spec["runtimeInstallEvidence"];
        let evidence_keys = evidence_spec["commonFields"]
            .as_array()
            .unwrap()
            .iter()
            .map(Value::as_str)
            .collect::<Option<BTreeSet<_>>>()
            .unwrap();
        let identity_keys = evidence_spec["runtimeIdentityFields"]
            .as_array()
            .unwrap()
            .iter()
            .map(Value::as_str)
            .collect::<Option<BTreeSet<_>>>()
            .unwrap();
        for vector in corpus["runtimeInstallEvidenceVectors"].as_array().unwrap() {
            let evidence = vector["evidence"].as_object().unwrap();
            assert_eq!(evidence.keys().map(String::as_str).collect::<BTreeSet<_>>(), evidence_keys);
            assert_eq!(evidence["v"], evidence_spec["version"]);
            assert_eq!(evidence["event"], evidence_spec["event"]);
            assert_eq!(evidence["decisionStage"], evidence_spec["decisionStage"]);
            assert_eq!(
                evidence["runtimeContextSchema"],
                evidence_spec["runtimeContextSchema"]
            );
            let disposition = vector["disposition"].as_str().unwrap();
            let variant = evidence_spec["variants"]
                .as_array()
                .unwrap()
                .iter()
                .find(|row| row["id"] == disposition)
                .unwrap();
            assert_eq!(evidence["installed"], variant["installed"]);
            assert_eq!(evidence["armed"], variant["armed"]);
            let blockers = evidence["blockers"].as_array().unwrap();
            assert_eq!(canonical_set(Value::Array(blockers.clone()), "fixture", "blockers").unwrap(), evidence["blockers"]);
            assert_eq!(blockers.is_empty(), variant["blockers"] == "empty");
            for field in variant["nullFields"].as_array().unwrap() {
                assert!(evidence[field.as_str().unwrap()].is_null());
            }
            if disposition == "installed" {
                let identity = evidence["runtimeIdentity"].as_object().unwrap();
                assert_eq!(identity.keys().map(String::as_str).collect::<BTreeSet<_>>(), identity_keys);
                assert_eq!(evidence["vocabDigest"], identity["vocabDigest"]);
                assert_eq!(evidence["registryDigest"], identity["registryDigest"]);
                for field in [
                    "vocabDigest",
                    "registryDigest",
                    "policyDigest",
                    "armedSnapshotDigest",
                    "projectDigest",
                ] {
                    let encoded = identity[field]
                        .as_str()
                        .unwrap()
                        .strip_prefix("sha256-")
                        .unwrap();
                    assert_eq!(fixture_base64url(encoded).len(), 32);
                }
                assert!(evidence_spec["executionRoles"]
                    .as_array()
                    .unwrap()
                    .contains(&evidence["executionRole"]));
            }
        }
        for vector in corpus["canonicalSetVectors"].as_array().unwrap() {
            let normalized = canonical_set(vector["input"].clone(), "fixture", "input").unwrap();
            assert_eq!(normalized, vector["expected"]);
            assert_eq!(
                normalized
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(canonical_json)
                    .collect::<Result<Vec<_>, _>>()
                    .unwrap(),
                vector["expectedCanonicalElements"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(Value::as_str)
                    .collect::<Option<Vec<_>>>()
                    .unwrap()
            );
        }
    }

    #[test]
    fn shared_core_owns_the_cache_negative_inventory_digest() {
        let core = Rev2Core::embedded().unwrap();
        let mut input = policy(Mode::Enforce);
        let empty = core.negative_inventory_digest(&input).unwrap();
        assert_eq!(
            empty,
            domain_digest(
                REV2_RUNTIME_NEGATIVE_INVENTORY_DOMAIN,
                &serde_json::json!([]),
            )
            .unwrap()
        );
        input.principal_denials.push(NamedSelectorInput {
            source_id: "fixture:negative".to_string(),
            selector: selector(
                Some(package("negative")),
                "env:read",
                json!({ "name": "TOKEN" }),
            ),
        });
        let populated = core.negative_inventory_digest(&input).unwrap();
        assert_ne!(populated, empty);
        assert_eq!(populated, core.negative_inventory_digest(&input).unwrap());
    }

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

    fn permission_sys_effect(edge_id: &str, effect_slot_id: &str, kind: &str) -> EffectInput {
        let mut effect = sys_effect(kind);
        effect.edge_id = edge_id.to_string();
        effect.effect_slot_id = effect_slot_id.to_string();
        effect
    }

    fn permission_run_effect() -> EffectInput {
        let mut effect = spawn_effect();
        effect.edge_id = PERMISSION_QUERY_EDGE.to_string();
        effect.effect_slot_id = PERMISSION_QUERY_RUN_SLOT.to_string();
        effect
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

    fn filesystem_lstat_oracle_input() -> FilesystemCandidateOracleInput {
        let fixture_root = FilesystemObjectIdentity {
            kind: FilesystemObjectIdentityKind::OpaqueToken,
            value: "fixture:root".to_string(),
        };
        let fixture_file = FilesystemObjectIdentity {
            kind: FilesystemObjectIdentityKind::OpaqueToken,
            value: "fixture:file".to_string(),
        };
        let platform_root = FilesystemObjectIdentity {
            kind: FilesystemObjectIdentityKind::PlatformObject,
            value: "unix-dev-ino:00000000000000000000000000000001".to_string(),
        };
        let platform_file = FilesystemObjectIdentity {
            kind: FilesystemObjectIdentityKind::PlatformObject,
            value: "unix-dev-ino:00000000000000010000000000000002".to_string(),
        };
        let path = FilesystemPlatformPath {
            encoding: FilesystemPlatformPathEncoding::Unicode,
            value: "file.txt".to_string(),
        };
        let principal = PrincipalRef {
            kind: PrincipalKind::Package,
            key: "package:test".to_string(),
        };
        let setup = FilesystemSetup {
            logical_roots: vec![FilesystemSetupLogicalRoot {
                root: FilesystemLogicalRoot::Project,
                binding_id: "root:project".to_string(),
                descriptor_slot: 0,
                object_identity: fixture_root.clone(),
            }],
            objects: vec![FilesystemSetupObject {
                object_id: "object:file".to_string(),
                root: FilesystemLogicalRoot::Project,
                path: path.clone(),
                object_identity: Some(fixture_file.clone()),
                kind: FilesystemObjectKind::RegularFile,
                content: Some(FilesystemInlineContent {
                    kind: FilesystemInlineContentKind::InlineBase64url,
                    bytes: String::new(),
                }),
                content_digest: Some(
                    "sha256-47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU".to_string(),
                ),
                alias_target_object_id: None,
                link_target_object_id: None,
            }],
        };
        let case_kind = "lstat-existing".to_string();
        let mut projection = FilesystemExecutionProjection {
            case_id: "filesystem:lstat-sync:lstat-existing".to_string(),
            edge_id: "native-op:ext/fs/ops.rs#op_fs_lstat_sync".to_string(),
            requirement_id:
                "fixture-requirement:native-op:ext/fs/ops.rs#op_fs_lstat_sync:complete"
                    .to_string(),
            case_kind: case_kind.clone(),
            case_plan_digest: generated_case_plan_digest(&case_kind).unwrap(),
            mode: FilesystemExecutionMode::Enforce,
            constrained_principal_keys: vec![principal.key.clone()],
            effect_owner_key: principal.key.clone(),
            input_mutation: FilesystemInputMutation::None,
            target_predicate: FilesystemTargetPredicate {
                candidates: vec![FilesystemTargetCandidate {
                    target: "aarch64-apple-darwin".to_string(),
                    feature_set: REV2_TARGET_STATUS
                        .iter()
                        .find(|candidate| candidate.target == "aarch64-apple-darwin")
                        .unwrap()
                        .feature_set
                        .to_string(),
                }],
            },
            invocation: FilesystemInvocation {
                kind: FilesystemInvocationKind::NativeHarness,
                command: "oden-capsec-filesystem-fixture".to_string(),
                args: vec!["filesystem:lstat-sync:lstat-existing".to_string()],
                cwd_root: FilesystemLogicalRoot::Project,
                entrypoint: None,
            },
            operation_request: FilesystemOperationRequest::LstatSync {
                target_ref: FilesystemTargetRef {
                    object_id: "object:file".to_string(),
                    parent: FilesystemTargetParentRef::LogicalRoot {
                        root: FilesystemLogicalRoot::Project,
                        binding_id: "root:project".to_string(),
                    },
                },
            },
            setup,
            principals: vec![principal.clone()],
            authority_rows: vec![FilesystemAuthorityRow {
                source_id: "case:static:0".to_string(),
                source_class: FilesystemAuthoritySourceClass::StaticFloor,
                channel: FilesystemAuthorityChannel::Floor,
                polarity: SelectorPolarity::Positive,
                principal_key: Some(principal.key.clone()),
                capability: "fs:list".to_string(),
                resource: FilesystemPathResource {
                    root: FilesystemLogicalRoot::Project,
                    kind: FilesystemPathResourceKind::PathExact,
                    path: path.clone(),
                },
                state: FilesystemAuthorityState::Active,
            }],
            execution: FilesystemExecutionPlan {
                actors: vec![FilesystemExecutionActor {
                    actor_id: "actor:lstat".to_string(),
                    slot_id:
                        "native-op:ext/fs/ops.rs#op_fs_lstat_sync:effect-slot:0".to_string(),
                    principal_key: Some(principal.key.clone()),
                    effect_owner: principal.key,
                }],
                trace_phases: vec![
                    FilesystemTracePhase::HarnessAdmitted,
                    FilesystemTracePhase::PublicOpEntered,
                    FilesystemTracePhase::ActorsCaptured,
                    FilesystemTracePhase::NamespaceGateAcquired,
                    FilesystemTracePhase::DiscoveryComplete,
                    FilesystemTracePhase::AuthorizationComplete,
                    FilesystemTracePhase::SourcesRevalidated,
                    FilesystemTracePhase::TargetRevalidated,
                    FilesystemTracePhase::OperationCompleted,
                    FilesystemTracePhase::DeliverySerialized,
                    FilesystemTracePhase::ProvisionalResourcesReleased,
                    FilesystemTracePhase::NamespaceGateReleased,
                    FilesystemTracePhase::HarnessExited,
                ],
                resource_lifecycle: Vec::new(),
            },
            fault_plan: None,
        };
        let operation = generated_operation(&projection.edge_id).unwrap();
        let plan = generated_case_plan(&projection.case_kind).unwrap();
        let target = &projection.setup.objects[0];
        let state = target_state(operation, target.kind).unwrap();
        projection.execution.resource_lifecycle =
            case_plan_resource_lifecycle(&projection, operation, plan, target, state);
        let initial_sandbox = FilesystemInitialSandboxInventory {
            schema: FILESYSTEM_SANDBOX_INVENTORY_SCHEMA.to_string(),
            phase: FilesystemSandboxPhase::Initial,
            logical_roots: vec![FilesystemRealizedLogicalRoot {
                root: FilesystemLogicalRoot::Project,
                binding_id: "root:project".to_string(),
                fixture_identity: fixture_root,
                platform_identity: platform_root,
            }],
            objects: vec![FilesystemInitialSandboxObject {
                object_id: "object:file".to_string(),
                root: FilesystemLogicalRoot::Project,
                path,
                fixture_identity: Some(fixture_file),
                state: FilesystemRealizedObjectState {
                    kind: FilesystemObjectKind::RegularFile,
                    identity: Some(platform_file),
                    metadata: Some(FilesystemMetadataProjection {
                        mode: 0o100644,
                        size: "0".to_string(),
                        link_count: "1".to_string(),
                        device: "1".to_string(),
                        inode: "2".to_string(),
                        uid: Some("501".to_string()),
                        gid: Some("20".to_string()),
                        rdev: Some("0".to_string()),
                        block_size: Some("4096".to_string()),
                        blocks: Some("0".to_string()),
                        accessed_time_ns: Some("0".to_string()),
                        modified_time_ns: Some("0".to_string()),
                        changed_time_ns: Some("0".to_string()),
                        birth_time_ns: Some("0".to_string()),
                    }),
                    content_digest: Some(
                        "sha256-47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU".to_string(),
                    ),
                    alias_target_object_id: None,
                    link_target_object_id: None,
                },
            }],
            unexpected_entries: Vec::new(),
        };
        let case_projection_digest = hjcs_digest(
            FILESYSTEM_EXECUTION_PROJECTION_DIGEST_DOMAIN,
            &serde_json::to_value(&projection).unwrap(),
        )
        .unwrap();
        let initial_inventory_digest = hjcs_digest(
            FILESYSTEM_SANDBOX_INVENTORY_DIGEST_DOMAIN,
            &serde_json::to_value(&initial_sandbox).unwrap(),
        )
        .unwrap();
        FilesystemCandidateOracleInput {
            case_projection: projection,
            case_projection_digest,
            initial_sandbox,
            initial_inventory_digest,
            parent_capture_facts: FilesystemParentCaptureFacts {
                captured_umask: 0o077,
            },
        }
    }

    fn filesystem_malformed_oracle_input() -> FilesystemCandidateOracleInput {
        let mut input = filesystem_lstat_oracle_input();
        input.case_projection.case_kind = "malformed-resource-refusal".to_string();
        input.case_projection.case_plan_digest =
            generated_case_plan_digest(&input.case_projection.case_kind).unwrap();
        input.case_projection.input_mutation = FilesystemInputMutation::TargetPathDotDot;
        input.case_projection.execution.trace_phases = vec![
            FilesystemTracePhase::HarnessAdmitted,
            FilesystemTracePhase::PublicOpEntered,
            FilesystemTracePhase::HarnessExited,
        ];
        let operation = generated_operation(&input.case_projection.edge_id).unwrap();
        let plan = generated_case_plan(&input.case_projection.case_kind).unwrap();
        let target = &input.case_projection.setup.objects[0];
        let state = target_state(operation, target.kind).unwrap();
        input.case_projection.execution.resource_lifecycle = case_plan_resource_lifecycle(
            &input.case_projection,
            operation,
            plan,
            target,
            state,
        );
        input.case_projection_digest = hjcs_digest(
            FILESYSTEM_EXECUTION_PROJECTION_DIGEST_DOMAIN,
            &serde_json::to_value(&input.case_projection).unwrap(),
        )
        .unwrap();
        input
    }

    fn recompute_filesystem_oracle_input_digests(input: &mut FilesystemCandidateOracleInput) {
        input.case_projection_digest = hjcs_digest(
            FILESYSTEM_EXECUTION_PROJECTION_DIGEST_DOMAIN,
            &serde_json::to_value(&input.case_projection).unwrap(),
        )
        .unwrap();
        input.initial_inventory_digest = hjcs_digest(
            FILESYSTEM_SANDBOX_INVENTORY_DIGEST_DOMAIN,
            &serde_json::to_value(&input.initial_sandbox).unwrap(),
        )
        .unwrap();
    }

    fn bind_test_case_plan(input: &mut FilesystemCandidateOracleInput, case_kind: &str) {
        input.case_projection.case_kind = case_kind.to_string();
        input.case_projection.case_plan_digest = generated_case_plan_digest(case_kind).unwrap();
        let operation = generated_operation(&input.case_projection.edge_id).unwrap();
        let plan = generated_case_plan(case_kind).unwrap();
        let target = &input.case_projection.setup.objects[0];
        let state = target_state(operation, target.kind).unwrap();
        let target_plan = plan
            .target_states
            .iter()
            .find(|target| generated_target_edge_id(target.edge_id) == input.case_projection.edge_id)
            .unwrap();
        input.case_projection.execution.trace_phases = target_plan
            .trace_phases
            .iter()
            .copied()
            .map(filesystem_trace_phase)
            .collect();
        input.case_projection.execution.resource_lifecycle = case_plan_resource_lifecycle(
            &input.case_projection,
            operation,
            plan,
            target,
            state,
        );
        recompute_filesystem_oracle_input_digests(input);
    }

    fn filesystem_denied_oracle_input() -> FilesystemCandidateOracleInput {
        let mut input = filesystem_lstat_oracle_input();
        let static_row = input.case_projection.authority_rows[0].clone();
        input.case_projection.authority_rows = vec![
            static_row.clone(),
            case_authority_row(
                "case:principal-denial:0".to_string(),
                FilesystemAuthoritySourceClass::PrincipalDenial,
                static_row.principal_key.clone(),
                static_row.capability.clone(),
                &static_row.resource,
                FilesystemAuthorityState::Active,
            ),
        ];
        bind_test_case_plan(&mut input, "authorable-negative");
        input
    }

    fn filesystem_revoked_oracle_input() -> FilesystemCandidateOracleInput {
        let mut input = filesystem_lstat_oracle_input();
        let base = input.case_projection.authority_rows[0].clone();
        let principal = base.principal_key.clone();
        input.case_projection.authority_rows = vec![
            case_authority_row(
                "case:session-grant:0".to_string(),
                FilesystemAuthoritySourceClass::SessionGrant,
                principal.clone(),
                base.capability.clone(),
                &base.resource,
                FilesystemAuthorityState::Active,
            ),
            case_authority_row(
                "case:ceiling:0".to_string(),
                FilesystemAuthoritySourceClass::EscalationCeiling,
                principal.clone(),
                base.capability.clone(),
                &base.resource,
                FilesystemAuthorityState::Active,
            ),
            case_authority_row(
                "case:session-revocation:0".to_string(),
                FilesystemAuthoritySourceClass::SessionRevocation,
                principal,
                base.capability,
                &base.resource,
                FilesystemAuthorityState::Dormant,
            ),
        ];
        input.case_projection.fault_plan = Some(FilesystemFaultPlan {
            barrier_id: "case-plan:after-authorization".to_string(),
            phase: FilesystemFaultPhase::AfterAuthorization,
            action: FilesystemFaultAction::AuthorityRevocation {
                remove_source_ids: vec!["case:session-grant:0".to_string()],
                activate_source_ids: vec!["case:session-revocation:0".to_string()],
            },
        });
        bind_test_case_plan(&mut input, "staged-barrier:revocation");
        input
    }

    fn filesystem_mkdir_oracle_input() -> FilesystemCandidateOracleInput {
        let mut input = filesystem_lstat_oracle_input();
        input.case_projection.case_id = "filesystem:mkdir-sync:mkdir-missing-create".to_string();
        input.case_projection.edge_id =
            "native-op:ext/fs/ops.rs#op_fs_mkdir_sync".to_string();
        input.case_projection.requirement_id =
            "fixture-requirement:native-op:ext/fs/ops.rs#op_fs_mkdir_sync:complete".to_string();
        input.case_projection.invocation.args = vec![input.case_projection.case_id.clone()];
        input.case_projection.operation_request = FilesystemOperationRequest::MkdirSync {
            target_ref: FilesystemTargetRef {
                object_id: "object:file".to_string(),
                parent: FilesystemTargetParentRef::LogicalRoot {
                    root: FilesystemLogicalRoot::Project,
                    binding_id: "root:project".to_string(),
                },
            },
            recursive: false,
            requested_mode: 0o755,
        };
        let setup_target = &mut input.case_projection.setup.objects[0];
        setup_target.object_identity = None;
        setup_target.kind = FilesystemObjectKind::Missing;
        setup_target.content = None;
        setup_target.content_digest = None;
        input.initial_sandbox.objects[0].fixture_identity = None;
        input.initial_sandbox.objects[0].state = FilesystemRealizedObjectState {
            kind: FilesystemObjectKind::Missing,
            identity: None,
            metadata: None,
            content_digest: None,
            alias_target_object_id: None,
            link_target_object_id: None,
        };
        let principal = input.case_projection.effect_owner_key.clone();
        let resource = FilesystemPathResource {
            root: FilesystemLogicalRoot::Project,
            kind: FilesystemPathResourceKind::PathExact,
            path: input.case_projection.setup.objects[0].path.clone(),
        };
        input.case_projection.authority_rows = vec![
            case_authority_row(
                "case:static:0".to_string(),
                FilesystemAuthoritySourceClass::StaticFloor,
                Some(principal.clone()),
                "fs:write".to_string(),
                &resource,
                FilesystemAuthorityState::Active,
            ),
            case_authority_row(
                "case:static:1".to_string(),
                FilesystemAuthoritySourceClass::StaticFloor,
                Some(principal.clone()),
                "fs:list".to_string(),
                &resource,
                FilesystemAuthorityState::Active,
            ),
        ];
        input.case_projection.execution.actors = vec![
            FilesystemExecutionActor {
                actor_id: "actor:mkdir:write".to_string(),
                slot_id: "native-op:ext/fs/ops.rs#op_fs_mkdir_sync:effect-slot:0".to_string(),
                principal_key: Some(principal.clone()),
                effect_owner: principal.clone(),
            },
            FilesystemExecutionActor {
                actor_id: "actor:mkdir:list".to_string(),
                slot_id: "native-op:ext/fs/ops.rs#op_fs_mkdir_sync:effect-slot:1".to_string(),
                principal_key: Some(principal.clone()),
                effect_owner: principal,
            },
        ];
        bind_test_case_plan(&mut input, "mkdir-missing-create");
        input
    }

    fn matrix_filesystem_kind(
        kind: generated::Rev2FilesystemCandidateInitialObjectKind,
    ) -> FilesystemObjectKind {
        use generated::Rev2FilesystemCandidateInitialObjectKind as Kind;
        match kind {
            Kind::BlockDevice => FilesystemObjectKind::BlockDevice,
            Kind::CharacterDevice => FilesystemObjectKind::CharacterDevice,
            Kind::Directory => FilesystemObjectKind::Directory,
            Kind::Fifo => FilesystemObjectKind::Fifo,
            Kind::Missing => FilesystemObjectKind::Missing,
            Kind::RegularFile => FilesystemObjectKind::RegularFile,
            Kind::Socket => FilesystemObjectKind::Socket,
            Kind::Symlink => FilesystemObjectKind::Symlink,
        }
    }

    fn matrix_case_projection(
        plan: &generated::Rev2FilesystemCandidateCasePlanSpec,
    ) -> FilesystemExecutionProjection {
        use generated::Rev2FilesystemCandidateAuthorityPlan as AuthorityPlan;
        use generated::Rev2FilesystemCandidateExecutionMode as ExecutionMode;
        use generated::Rev2FilesystemCandidateFaultPlan as FaultPlan;
        use generated::Rev2FilesystemCandidateInputMutation as InputMutation;
        use generated::Rev2FilesystemCandidatePrincipalPlan as PrincipalPlan;

        let target_plan = plan.target_states.first().unwrap();
        let edge_id = generated_target_edge_id(target_plan.edge_id);
        let mut projection = if edge_id.ends_with("op_fs_lstat_sync") {
            filesystem_lstat_oracle_input().case_projection
        } else {
            filesystem_mkdir_oracle_input().case_projection
        };
        let case_kind = generated_case_kind(plan.case_kind);
        projection.case_id = format!("filesystem:matrix:{case_kind}");
        projection.invocation.args = vec![projection.case_id.clone()];
        projection.case_kind = case_kind.to_string();
        projection.case_plan_digest = generated_case_plan_digest(case_kind).unwrap();
        projection.mode = match plan.execution_mode {
            ExecutionMode::Audit => FilesystemExecutionMode::Audit,
            ExecutionMode::Enforce => FilesystemExecutionMode::Enforce,
        };
        projection.input_mutation = match plan.input_mutation {
            InputMutation::None => FilesystemInputMutation::None,
            InputMutation::TargetPathDotDot => FilesystemInputMutation::TargetPathDotDot,
        };
        projection.execution.trace_phases = target_plan
            .trace_phases
            .iter()
            .copied()
            .map(filesystem_trace_phase)
            .collect();

        let kind = matrix_filesystem_kind(target_plan.initial_kind);
        let target = &mut projection.setup.objects[0];
        target.kind = kind;
        target.alias_target_object_id = None;
        target.link_target_object_id =
            (kind == FilesystemObjectKind::Symlink).then(|| target.object_id.clone());
        if kind == FilesystemObjectKind::Missing {
            target.object_identity = None;
            target.content = None;
            target.content_digest = None;
        } else {
            target.object_identity = Some(FilesystemObjectIdentity {
                kind: FilesystemObjectIdentityKind::OpaqueToken,
                value: format!("fixture:matrix:{case_kind}"),
            });
            if kind == FilesystemObjectKind::RegularFile {
                target.content = Some(FilesystemInlineContent {
                    kind: FilesystemInlineContentKind::InlineBase64url,
                    bytes: String::new(),
                });
                target.content_digest = Some(
                    "sha256-47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU".to_string(),
                );
            } else {
                target.content = None;
                target.content_digest = None;
            }
        }

        let (owner_kind, owner_key) = match plan.principal_plan {
            PrincipalPlan::ExplicitNoUser => (PrincipalKind::NoUser, "no-user:matrix"),
            PrincipalPlan::Quarantine => (PrincipalKind::Quarantine, "quarantine:matrix"),
            _ => (PrincipalKind::Package, "package:matrix"),
        };
        projection.effect_owner_key = owner_key.to_string();
        projection.principals = vec![PrincipalRef {
            kind: owner_kind,
            key: owner_key.to_string(),
        }];
        if plan.principal_plan == PrincipalPlan::ActorAndOther {
            projection.principals.push(PrincipalRef {
                kind: PrincipalKind::Package,
                key: "package:other".to_string(),
            });
        }
        projection.constrained_principal_keys = match plan.principal_plan {
            PrincipalPlan::ActorUnconstrained => Vec::new(),
            PrincipalPlan::ActorAndOther => {
                vec![owner_key.to_string(), "package:other".to_string()]
            }
            _ => vec![owner_key.to_string()],
        };
        for actor in &mut projection.execution.actors {
            actor.principal_key = (plan.principal_plan != PrincipalPlan::ActorUnconstrained)
                .then(|| owner_key.to_string());
            actor.effect_owner = owner_key.to_string();
        }

        let operation = generated_operation(edge_id).unwrap();
        let resource = FilesystemPathResource {
            root: projection.setup.objects[0].root,
            kind: FilesystemPathResourceKind::PathExact,
            path: projection.setup.objects[0].path.clone(),
        };
        let row = |source_id: String,
                   source_class: FilesystemAuthoritySourceClass,
                   principal_key: Option<&str>,
                   capability: String,
                   state: FilesystemAuthorityState| {
            case_authority_row(
                source_id,
                source_class,
                principal_key.map(str::to_string),
                capability,
                &resource,
                state,
            )
        };
        let static_rows = |principal_key: &str| {
            operation_slots(operation)
                .iter()
                .enumerate()
                .map(|(index, slot)| {
                    row(
                        format!("case:static:{index}"),
                        FilesystemAuthoritySourceClass::StaticFloor,
                        Some(principal_key),
                        generated_capability(slot.capability).unwrap().to_string(),
                        FilesystemAuthorityState::Active,
                    )
                })
                .collect::<Vec<_>>()
        };
        projection.authority_rows = match plan.authority_plan {
            AuthorityPlan::None => Vec::new(),
            AuthorityPlan::StaticAll | AuthorityPlan::NoUserStaticAll => {
                static_rows(owner_key)
            }
            AuthorityPlan::PrincipalDenialOverStaticAll => {
                let mut rows = static_rows(owner_key);
                rows.extend(operation_slots(operation).iter().enumerate().map(
                    |(index, slot)| {
                        row(
                            format!("case:principal-denial:{index}"),
                            FilesystemAuthoritySourceClass::PrincipalDenial,
                            Some(owner_key),
                            generated_capability(slot.capability).unwrap().to_string(),
                            FilesystemAuthorityState::Active,
                        )
                    },
                ));
                rows
            }
            AuthorityPlan::PrincipalDenialLastOverStaticAll => {
                let mut rows = static_rows(owner_key);
                let index = operation_slots(operation).len() - 1;
                rows.push(row(
                    format!("case:principal-denial:{index}"),
                    FilesystemAuthoritySourceClass::PrincipalDenial,
                    Some(owner_key),
                    generated_capability(operation_slots(operation)[index].capability)
                        .unwrap()
                        .to_string(),
                    FilesystemAuthorityState::Active,
                ));
                rows
            }
            AuthorityPlan::ProcessDenialOverStaticAll => {
                let mut rows = static_rows(owner_key);
                rows.extend(operation_slots(operation).iter().enumerate().map(
                    |(index, slot)| {
                        row(
                            format!("case:process-denial:{index}"),
                            FilesystemAuthoritySourceClass::ProcessDenial,
                            None,
                            generated_capability(slot.capability).unwrap().to_string(),
                            FilesystemAuthorityState::Active,
                        )
                    },
                ));
                rows
            }
            AuthorityPlan::CrossActionFirst => operation_slots(operation)
                .iter()
                .enumerate()
                .map(|(index, slot)| {
                    row(
                        if index == 0 {
                            "case:cross-action:0".to_string()
                        } else {
                            format!("case:static:{index}")
                        },
                        FilesystemAuthoritySourceClass::StaticFloor,
                        Some(owner_key),
                        if index == 0 {
                            "fs:read".to_string()
                        } else {
                            generated_capability(slot.capability).unwrap().to_string()
                        },
                        FilesystemAuthorityState::Active,
                    )
                })
                .collect(),
            AuthorityPlan::WrongPrincipalStaticAll => static_rows("package:other"),
            AuthorityPlan::SessionAllDormantRevocationAll
            | AuthorityPlan::SessionAllDormantRevocationLast => {
                let mut rows = Vec::new();
                for (class, prefix, state) in [
                    (
                        FilesystemAuthoritySourceClass::SessionGrant,
                        "case:session-grant",
                        FilesystemAuthorityState::Active,
                    ),
                    (
                        FilesystemAuthoritySourceClass::EscalationCeiling,
                        "case:ceiling",
                        FilesystemAuthorityState::Active,
                    ),
                    (
                        FilesystemAuthoritySourceClass::SessionRevocation,
                        "case:session-revocation",
                        FilesystemAuthorityState::Dormant,
                    ),
                ] {
                    rows.extend(operation_slots(operation).iter().enumerate().map(
                        |(index, slot)| {
                            row(
                                format!("{prefix}:{index}"),
                                class,
                                Some(owner_key),
                                generated_capability(slot.capability).unwrap().to_string(),
                                state,
                            )
                        },
                    ));
                }
                rows
            }
        };

        projection.fault_plan = match plan.fault_plan {
            FaultPlan::None => None,
            FaultPlan::CancelSafeBoundary => Some(FilesystemFaultPlan {
                barrier_id: "case-plan:after-authorization".to_string(),
                phase: FilesystemFaultPhase::AfterAuthorization,
                action: FilesystemFaultAction::ActorSequence {
                    operation: FilesystemActorSequenceOperation::Cancel,
                },
            }),
            FaultPlan::OmitRequiredStage => Some(if edge_id.ends_with("op_fs_lstat_sync") {
                FilesystemFaultPlan {
                    barrier_id: "case-plan:after-target-revalidation".to_string(),
                    phase: FilesystemFaultPhase::AfterTargetRevalidation,
                    action: FilesystemFaultAction::ActorSequence {
                        operation: FilesystemActorSequenceOperation::OmitObservation,
                    },
                }
            } else {
                FilesystemFaultPlan {
                    barrier_id: "case-plan:after-preparation".to_string(),
                    phase: FilesystemFaultPhase::AfterPreparation,
                    action: FilesystemFaultAction::ActorSequence {
                        operation:
                            FilesystemActorSequenceOperation::OmitPostPrepareRevalidation,
                    },
                }
            }),
            FaultPlan::RevokeAllAfterAuthorization
            | FaultPlan::RevokeLastAfterAuthorization => {
                let indexes: Vec<_> = if plan.fault_plan == FaultPlan::RevokeAllAfterAuthorization {
                    (0..operation_slots(operation).len()).collect()
                } else {
                    vec![operation_slots(operation).len() - 1]
                };
                Some(FilesystemFaultPlan {
                    barrier_id: "case-plan:after-authorization".to_string(),
                    phase: FilesystemFaultPhase::AfterAuthorization,
                    action: FilesystemFaultAction::AuthorityRevocation {
                        remove_source_ids: indexes
                            .iter()
                            .map(|index| format!("case:session-grant:{index}"))
                            .collect(),
                        activate_source_ids: indexes
                            .iter()
                            .map(|index| format!("case:session-revocation:{index}"))
                            .collect(),
                    },
                })
            }
        };
        let state = target_state(operation, kind).unwrap();
        projection.execution.resource_lifecycle = case_plan_resource_lifecycle(
            &projection,
            operation,
            plan,
            &projection.setup.objects[0],
            state,
        );
        projection
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

    fn protected_core() -> Rev2Core {
        const PREDICATE: &str = "predicate.protected-receipt/2";
        let embedded = Rev2Core::embedded().unwrap();
        let mut state = (*embedded.state).clone();
        state
            .definitions
            .get_mut("network:fetch")
            .unwrap()
            .protected_receipt_predicate_id = Some(PREDICATE.to_string());
        state
            .payload
            .policy_rules_and_classifiers
            .predicates
            .push(json!({
                "id": PREDICATE,
                "kind": "definition-positive",
                "evaluator": { "algorithm": "authenticated-protected-receipt" },
            }));
        state
            .payload
            .policy_rules_and_classifiers
            .protected_receipt_schema = Some(json!({
                "id": "oden/capsec-protected-receipt/2",
            }));
        Rev2Core {
            state: Arc::new(state),
        }
    }

    fn protected_exception(
        core: &Rev2Core,
        source_id: &str,
        selector: AuthoritySelectorInput,
        reason: &str,
    ) -> ProtectedExceptionInput {
        let predicate_id = "predicate.protected-receipt/2".to_string();
        let reason_digest = domain_digest(
            "oden:capsec:protected-reason:2",
            &Value::String(reason.to_string()),
        )
        .unwrap();
        let canonical_selector = core
            .normalize_selector(&selector, SelectorPolarity::Positive)
            .unwrap();
        let canonical_row_digest = protected_row_digest(
            source_id,
            &canonical_selector,
            &predicate_id,
            &reason_digest,
        )
        .unwrap();
        ProtectedExceptionInput {
            source_id: source_id.to_string(),
            predicate_id,
            reason_digest,
            canonical_row_digest,
            selector,
        }
    }

    fn risk_fields(rows: Vec<(&str, Value)>) -> BTreeMap<String, Value> {
        rows.into_iter()
            .map(|(name, value)| (name.to_string(), value))
            .collect()
    }

    fn risk_authority(
        capability: &str,
        rows: Vec<(&str, Value)>,
    ) -> RiskAuthorityInput {
        RiskAuthorityInput::capture_host(capability, risk_fields(rows)).unwrap()
    }

    fn exhaustive_risk_input() -> RiskEvaluationInput {
        RiskEvaluationInput::capture_host(
            vec![
                risk_authority("cron:schedule", vec![]),
                risk_authority("env:process-write", vec![]),
                risk_authority("ffi:load", vec![]),
                risk_authority(
                    "network:connect",
                    vec![
                        ("resource.peerClasses", json!(["metadata"])),
                        ("resource.route.kind", json!("forward-proxy")),
                        ("normalizedAuthority.distinctScopes", json!(8)),
                    ],
                ),
                risk_authority(
                    "env:write",
                    vec![("resource.name", json!("NODE_OPTIONS"))],
                ),
                risk_authority(
                    "env:read",
                    vec![("resource.name", json!("OPENAI_API_KEY"))],
                ),
                risk_authority(
                    "fs:read",
                    vec![
                        ("resource.logicalPath", json!("$HOME/.ssh/id_ed25519")),
                        ("resource.objectClass", json!("credential")),
                    ],
                ),
                risk_authority(
                    "stdio:read",
                    vec![("resource.source", json!("terminal"))],
                ),
                risk_authority(
                    "sys:read",
                    vec![("resource.kind", json!("user-info"))],
                ),
            ],
            risk_fields(vec![
                ("authority.effects", json!(["source", "sink"])),
                ("resource.protected", json!(true)),
                ("normalizedAuthority.pathScopes", json!(1)),
                ("normalizedAuthority.registrableDomains", json!(1)),
                ("normalizedAuthority.ports", json!(1)),
                ("normalizedAuthority.peerClasses", json!(0)),
            ]),
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
    fn runtime_risk_contract_is_complete_and_unknown_rules_fail_closed() {
        let core = Rev2Core::embedded().unwrap();
        assert_eq!(core.risk_rules.len(), 14);
        assert_eq!(
            core.risk_rules.keys().map(String::as_str).collect::<Vec<_>>(),
            vec![
                "risk.authority-accretion",
                "risk.cross-capability-composition",
                "risk.deny-only",
                "risk.endpoint-class",
                "risk.env-loader-control-name",
                "risk.env-sensitive-name",
                "risk.path-sensitive",
                "risk.protected-resource-exception",
                "risk.route",
                "risk.scope-breadth",
                "risk.shared-process-mutation",
                "risk.stdio-source",
                "risk.system-info-kind",
                "risk.terminal",
            ]
        );

        let value = parse_strict_json(REV2_RUNTIME_SEMANTIC_PAYLOAD_JSON).unwrap();
        let mut payload: RuntimePayload = serde_json::from_value(value).unwrap();
        payload.definitions[0]
            .risk_rule_ids
            .push("risk.unknown-runtime-rule".to_string());
        let definitions =
            unique_by_id(payload.definitions.iter().cloned(), |row| &row.id).unwrap();
        let error = validate_runtime_risk_contract(&payload, &definitions).unwrap_err();
        assert_eq!(error.reason_code, REASON_SCHEMA_INVALID);
        assert!(error.message.contains("unknown risk rule"));
    }

    #[test]
    fn empty_canonical_policy_has_deterministic_tier_zero_risk() {
        let core = Rev2Core::embedded().unwrap();
        let empty = RiskEvaluationInput::capture_host(Vec::new(), BTreeMap::new()).unwrap();
        assert_eq!(
            core.evaluate_risk(&empty).unwrap(),
            RiskEvaluation {
                base_tier: 0,
                tier: 0,
                reasons: Vec::new(),
            }
        );
        assert!(RiskEvaluationInput::capture_host(
            Vec::new(),
            risk_fields(vec![("resource.protected", json!(true))]),
        )
        .is_err());
    }

    #[test]
    fn all_runtime_risk_rules_coapply_in_canonical_order_and_permutations_are_stable() {
        let core = Rev2Core::embedded().unwrap();
        let input = exhaustive_risk_input();
        let result = core.evaluate_risk(&input).unwrap();
        assert_eq!(result.base_tier, 4);
        assert_eq!(result.tier, 4);
        assert_eq!(result.reasons.len(), 14);
        assert_eq!(
            result
                .reasons
                .iter()
                .map(|reason| (reason.reason_code.as_str(), reason.rule_id.as_str()))
                .collect::<Vec<_>>(),
            vec![
                ("OD-RISK-AUTHORITY-ACCRETION", "risk.authority-accretion"),
                ("OD-RISK-CROSS-CAPABILITY", "risk.cross-capability-composition"),
                ("OD-RISK-DENY-ONLY", "risk.deny-only"),
                ("OD-RISK-ENDPOINT-CLASS", "risk.endpoint-class"),
                ("OD-RISK-ENV-LOADER-CONTROL", "risk.env-loader-control-name"),
                ("OD-RISK-ENV-SENSITIVE", "risk.env-sensitive-name"),
                ("OD-RISK-PATH-SENSITIVE", "risk.path-sensitive"),
                ("OD-RISK-PROTECTED-EXCEPTION", "risk.protected-resource-exception"),
                ("OD-RISK-ROUTE", "risk.route"),
                ("OD-RISK-SCOPE-BREADTH", "risk.scope-breadth"),
                ("OD-RISK-SHARED-MUTATION", "risk.shared-process-mutation"),
                ("OD-RISK-STDIO-SOURCE", "risk.stdio-source"),
                ("OD-RISK-SYSTEM-INFO", "risk.system-info-kind"),
                ("OD-RISK-TERMINAL", "risk.terminal"),
            ]
        );

        let mut permuted = input.clone();
        permuted.authorities.reverse();
        permuted.global_fields.insert(
            "authority.effects".to_string(),
            json!(["sink", "source", "sink"]),
        );
        assert_eq!(core.evaluate_risk(&permuted).unwrap(), result);
    }

    #[test]
    fn risk_is_advisory_and_invalid_or_spoofed_fields_fail_closed() {
        let core = Rev2Core::embedded().unwrap();
        let principal = package("risk-advisory");
        let request = stage("risk-advisory", vec![principal], vec![env_effect("TOKEN")]);
        let policy = policy(Mode::Enforce);
        let before = core.decide_stage(&request, &policy).unwrap();
        assert_eq!(before.outcome, Outcome::Deny);

        let risk = core.evaluate_risk(&exhaustive_risk_input()).unwrap();
        assert_eq!(risk.tier, 4);
        let after = core.decide_stage(&request, &policy).unwrap();
        assert_eq!(after, before);

        let mut spoofed = exhaustive_risk_input();
        spoofed.authorities[0].fields.insert(
            "definition.lifecycle".to_string(),
            json!("authorable"),
        );
        assert_eq!(
            core.evaluate_risk(&spoofed).unwrap_err().reason_code,
            REASON_SCHEMA_INVALID
        );
        let mut unknown = exhaustive_risk_input();
        unknown.global_fields.insert("attacker.field".to_string(), json!(1));
        assert_eq!(
            core.evaluate_risk(&unknown).unwrap_err().reason_code,
            REASON_SCHEMA_INVALID
        );
    }

    #[test]
    fn canonical_json_uses_rfc8785_ecmascript_number_rendering() {
        let value = parse_strict_json(
            "[333333333.33333329,1E30,4.50,2e-3,0.000000000000000000000000001,-0]",
        )
        .unwrap();
        assert_eq!(
            canonical_json(&value).unwrap(),
            "[333333333.3333333,1e+30,4.5,0.002,1e-27,0]"
        );
    }

    #[test]
    fn canonical_json_uses_rfc8785_utf16_property_ordering() {
        let value = json!({
            "\u{e000}": "bmp-private-use",
            "😀": "supplementary",
            "€": "euro",
            "ö": "o-diaeresis",
            "1": "one",
            "\r": "carriage-return",
        });
        assert_eq!(
            canonical_json(&value).unwrap(),
            "{\"\\r\":\"carriage-return\",\"1\":\"one\",\"ö\":\"o-diaeresis\",\"€\":\"euro\",\"😀\":\"supplementary\",\"\u{e000}\":\"bmp-private-use\"}"
        );
    }

    #[test]
    fn strict_i_json_rejects_decoded_duplicates_and_unsafe_integer_tokens() {
        for input in [r#"{"a":1,"a":2}"#, r#"{"a":1,"\u0061":2}"#] {
            let error = parse_strict_json(input).unwrap_err();
            assert_eq!(error.reason_code, REASON_SCHEMA_INVALID);
            assert!(error.message.contains("duplicate object key"));
        }

        for input in [
            "9007199254740992",
            "-9007199254740992",
            "18446744073709551616",
            "-18446744073709551616",
        ] {
            let error = parse_strict_json(input).unwrap_err();
            assert_eq!(error.reason_code, REASON_SCHEMA_INVALID);
            assert!(error.message.contains("safe range"));
        }

        let boundaries = parse_strict_json("[9007199254740991,-9007199254740991,1.25]")
            .unwrap();
        assert_eq!(
            canonical_json(&boundaries).unwrap(),
            "[9007199254740991,-9007199254740991,1.25]"
        );
        assert_eq!(
            parse_strict_json(r#"{"value":"18446744073709551616"}"#).unwrap(),
            json!({ "value": "18446744073709551616" })
        );

        let constructed_unsafe = json!(9_007_199_254_740_992_u64);
        assert_eq!(
            canonical_json(&constructed_unsafe).unwrap_err().reason_code,
            REASON_SCHEMA_INVALID
        );
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
            json!({ "operation": "evaluateFilesystemCandidate", "input": null, "unknown": true }),
        ] {
            let error = validate_oracle_request_envelope(&request).unwrap_err();
            assert!(error.message.contains("unknown oracle request field"));
        }
        assert!(validate_oracle_request_envelope(&json!({ "operation": "unknown" })).is_err());

        let risk_wire = json!({
            "operation": "evaluateRisk",
            "authorities": [],
            "globalFields": {},
        });
        let error = validate_oracle_request_envelope(&risk_wire).unwrap_err();
        assert_eq!(error.reason_code, REASON_SCHEMA_INVALID);
        assert_eq!(error.message, "unknown oracle operation evaluateRisk");
    }

    #[test]
    fn filesystem_candidate_execution_validation_excludes_expected_data() {
        let input = filesystem_lstat_oracle_input();
        let wire = serde_json::to_value(&input).unwrap();
        for field in [
            "expected",
            "finalSandbox",
            "trace",
            "observedResult",
            "oracleOutput",
            "verdict",
            "differences",
        ] {
            let mut extra_top_level = wire.clone();
            extra_top_level
                .as_object_mut()
                .unwrap()
                .insert(field.to_string(), json!({}));
            assert!(
                serde_json::from_value::<FilesystemCandidateOracleInput>(extra_top_level).is_err(),
                "candidate input admitted top-level {field}"
            );

            let mut extra_projection = wire.clone();
            extra_projection
                .get_mut("caseProjection")
                .and_then(Value::as_object_mut)
                .unwrap()
                .insert(field.to_string(), json!({}));
            assert!(
                serde_json::from_value::<FilesystemCandidateOracleInput>(extra_projection)
                    .is_err(),
                "candidate projection admitted {field}"
            );
        }

        let projection_digest = input.case_projection_digest.clone();
        let inventory_digest = input.initial_inventory_digest.clone();
        let validated = validate_filesystem_candidate_execution(input).unwrap();
        assert_eq!(validated.execution_projection_digest(), projection_digest);
        assert_eq!(validated.initial_inventory_digest(), inventory_digest);
        assert_eq!(
            validated.execution_projection().case_id,
            "filesystem:lstat-sync:lstat-existing"
        );
        assert_eq!(validated.runtime_slots().len(), 1);
        assert_eq!(validated.runtime_slots()[0].capability, "fs:list");
        assert_eq!(validated.target_setup().object_id, "object:file");
        assert_eq!(validated.target_initial().object_id, "object:file");
        assert_eq!(
            validated.parent_identity().kind,
            FilesystemObjectIdentityKind::PlatformObject
        );
        assert_eq!(validated.parent_capture_facts().captured_umask, 0o077);

        let mkdir = validate_filesystem_candidate_execution(filesystem_mkdir_oracle_input())
            .unwrap();
        assert_eq!(mkdir.runtime_slots().len(), 2);
        assert_eq!(
            mkdir.runtime_slots()[0].occurrence.final_object_state,
            FilesystemFinalObjectState::Proposed
        );
        assert_eq!(
            mkdir.runtime_slots()[1].occurrence.final_object_state,
            FilesystemFinalObjectState::Missing
        );

        let malformed =
            validate_filesystem_candidate_execution(filesystem_malformed_oracle_input()).unwrap();
        assert!(malformed.runtime_slots().is_empty());
    }

    #[test]
    fn filesystem_candidate_execution_validation_refuses_binding_drift() {
        let mut case_plan = filesystem_lstat_oracle_input();
        case_plan.case_projection.case_plan_digest =
            "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string();
        recompute_filesystem_oracle_input_digests(&mut case_plan);
        assert!(
            validate_filesystem_candidate_execution(case_plan)
                .unwrap_err()
                .message
                .contains("generated case plan")
        );

        let mut target_tuple = filesystem_lstat_oracle_input();
        target_tuple.case_projection.target_predicate.candidates[0].feature_set =
            "invented-feature-set".to_string();
        recompute_filesystem_oracle_input_digests(&mut target_tuple);
        assert!(
            validate_filesystem_candidate_execution(target_tuple)
                .unwrap_err()
                .message
                .contains("target predicate")
        );

        let mut actor = filesystem_mkdir_oracle_input();
        actor.case_projection.execution.actors[1].actor_id =
            actor.case_projection.execution.actors[0].actor_id.clone();
        recompute_filesystem_oracle_input_digests(&mut actor);
        assert!(
            validate_filesystem_candidate_execution(actor)
                .unwrap_err()
                .message
                .contains("actor binding")
        );

        let mut authority = filesystem_lstat_oracle_input();
        authority.case_projection.authority_rows[0].source_id = "case:static:wrong".to_string();
        recompute_filesystem_oracle_input_digests(&mut authority);
        assert!(
            validate_filesystem_candidate_execution(authority)
                .unwrap_err()
                .message
                .contains("authority rows")
        );

        let mut phases = filesystem_lstat_oracle_input();
        phases.case_projection.execution.trace_phases.pop();
        recompute_filesystem_oracle_input_digests(&mut phases);
        assert!(
            validate_filesystem_candidate_execution(phases)
                .unwrap_err()
                .message
                .contains("trace phases")
        );

        let mut lifecycle = filesystem_lstat_oracle_input();
        lifecycle.case_projection.execution.resource_lifecycle.pop();
        recompute_filesystem_oracle_input_digests(&mut lifecycle);
        assert!(
            validate_filesystem_candidate_execution(lifecycle)
                .unwrap_err()
                .message
                .contains("resource lifecycle")
        );

        let mut fault = filesystem_revoked_oracle_input();
        let Some(FilesystemFaultPlan {
            action: FilesystemFaultAction::AuthorityRevocation {
                remove_source_ids, ..
            },
            ..
        }) = fault.case_projection.fault_plan.as_mut()
        else {
            panic!("revocation fixture must contain a fault plan")
        };
        remove_source_ids[0] = "case:session-grant:wrong".to_string();
        recompute_filesystem_oracle_input_digests(&mut fault);
        assert!(
            validate_filesystem_candidate_execution(fault)
                .unwrap_err()
                .message
                .contains("fault plan")
        );

        let mut inventory = filesystem_lstat_oracle_input();
        inventory.initial_sandbox.objects[0]
            .state
            .metadata
            .as_mut()
            .unwrap()
            .device = "2".to_string();
        recompute_filesystem_oracle_input_digests(&mut inventory);
        assert!(
            validate_filesystem_candidate_execution(inventory)
                .unwrap_err()
                .message
                .contains("device/inode")
        );
    }

    #[test]
    fn filesystem_candidate_oracle_independently_evaluates_lstat() {
        let input = filesystem_lstat_oracle_input();
        let core = Rev2Core::embedded().unwrap();
        let output = evaluate_filesystem_candidate(&core, &input).unwrap();

        assert_eq!(output.core_identity, EngineIdentity::embedded());
        assert_eq!(output.normalization.runtime_slots.len(), 1);
        assert_eq!(output.core_evaluations.len(), 1);
        assert_eq!(
            output.core_evaluations[0].stage_decision.outcome,
            FilesystemCoreOutcome::Allow
        );
        assert_eq!(
            output.core_evaluations[0].stage_decision.effects[0].dimensions[0].stratum,
            9
        );
        assert_eq!(
            output.core_evaluations[0].stage_decision.effects[0].dimensions[0].reason_code,
            REASON_ALLOW
        );
        assert_eq!(output.expected_outcome.decision, FilesystemDecision::Allow);
        assert_eq!(output.expected_outcome.result.class, "lstat-complete");
        assert_eq!(
            output.expected_observation.result.digest,
            Some(
                hjcs_digest(
                    FILESYSTEM_LSTAT_METADATA_DIGEST_DOMAIN,
                    &serde_json::to_value(
                        input.initial_sandbox.objects[0].state.metadata.as_ref().unwrap()
                    )
                    .unwrap(),
                )
                .unwrap()
            )
        );
        assert_eq!(
            output.normalized_slots_digest,
            hjcs_digest(
                FILESYSTEM_NORMALIZED_SLOTS_DIGEST_DOMAIN,
                &serde_json::to_value(&output.expected_outcome.slots).unwrap(),
            )
            .unwrap()
        );
        assert_eq!(
            output.expected_outcome_digest,
            hjcs_digest(
                FILESYSTEM_EXPECTED_OUTCOME_DIGEST_DOMAIN,
                &serde_json::to_value(&output.expected_outcome).unwrap(),
            )
            .unwrap()
        );
        assert_eq!(
            output.expected_observation_digest,
            hjcs_digest(
                FILESYSTEM_EXPECTED_OBSERVATION_DIGEST_DOMAIN,
                &serde_json::to_value(&output.expected_observation).unwrap(),
            )
            .unwrap()
        );

        let wire = serde_json::to_value(&output).unwrap();
        assert!(wire.get("verdict").is_none());
        assert!(wire.get("differences").is_none());
        assert!(wire.get("referenceOracleDigest").is_none());
        assert!(wire.get("wasmDigest").is_none());
    }

    #[test]
    fn filesystem_candidate_oracle_recomputes_complete_preimage_digests() {
        let input = filesystem_lstat_oracle_input();
        let request = json!({
            "operation": "evaluateFilesystemCandidate",
            "input": input,
        });
        let response: Value =
            serde_json::from_str(&run_oracle_json(&canonical_json(&request).unwrap())).unwrap();
        assert_eq!(response.get("status").and_then(Value::as_str), Some("ok"));

        let mut tampered = filesystem_lstat_oracle_input();
        tampered.case_projection.effect_owner_key = "package:tampered".to_string();
        let error = evaluate_filesystem_candidate(&Rev2Core::embedded().unwrap(), &tampered)
            .unwrap_err();
        assert_eq!(error.reason_code, REASON_SCHEMA_INVALID);
        assert!(error.message.contains("complete preimage"));

        let mut wrong_umask = filesystem_lstat_oracle_input();
        wrong_umask.parent_capture_facts.captured_umask = 0o022;
        let error = evaluate_filesystem_candidate(&Rev2Core::embedded().unwrap(), &wrong_umask)
            .unwrap_err();
        assert_eq!(error.reason_code, REASON_SCHEMA_INVALID);
        assert!(error.message.contains("0077 umask"));
    }

    #[test]
    fn filesystem_candidate_oracle_malformed_input_has_no_runtime_slots() {
        let output = evaluate_filesystem_candidate(
            &Rev2Core::embedded().unwrap(),
            &filesystem_malformed_oracle_input(),
        )
        .unwrap();
        assert!(output.normalization.runtime_slots.is_empty());
        assert!(output.core_evaluations.is_empty());
        assert_eq!(output.expected_outcome.slots.len(), 1);
        assert_eq!(output.expected_outcome.decision, FilesystemDecision::Refuse);
        assert_eq!(
            output.normalized_slots_digest,
            hjcs_digest(
                FILESYSTEM_NORMALIZED_SLOTS_DIGEST_DOMAIN,
                &json!([]),
            )
            .unwrap()
        );
    }

    #[test]
    fn filesystem_candidate_oracle_evaluates_denial_and_revocation_through_shared_core() {
        let core = Rev2Core::embedded().unwrap();
        let denied = evaluate_filesystem_candidate(&core, &filesystem_denied_oracle_input())
            .unwrap();
        assert_eq!(denied.expected_outcome.decision, FilesystemDecision::Deny);
        assert_eq!(denied.expected_outcome.result.class, "permission-denied");
        assert_eq!(denied.core_evaluations.len(), 1);
        assert_eq!(
            denied.core_evaluations[0].stage_decision.outcome,
            FilesystemCoreOutcome::Deny
        );
        assert_eq!(
            denied.core_evaluations[0].stage_decision.effects[0].dimensions[0].stratum,
            6
        );

        let revoked = evaluate_filesystem_candidate(&core, &filesystem_revoked_oracle_input())
            .unwrap();
        assert_eq!(revoked.expected_outcome.decision, FilesystemDecision::Deny);
        assert_eq!(revoked.core_evaluations.len(), 2);
        assert_eq!(
            revoked.core_evaluations[0].phase,
            FilesystemCoreEvaluationPhase::Initial
        );
        assert_eq!(
            revoked.core_evaluations[0].stage_decision.outcome,
            FilesystemCoreOutcome::Allow
        );
        let initial = &revoked.core_evaluations[0].stage_decision.effects[0].dimensions[0];
        assert_eq!(initial.stratum, 11);
        assert_eq!(
            initial.positive_source.as_ref().map(|source| source.source_id.as_str()),
            Some("case:session-grant:0")
        );
        assert_eq!(
            revoked.core_evaluations[1].phase,
            FilesystemCoreEvaluationPhase::PostFault
        );
        assert_eq!(
            revoked.core_evaluations[1].stage_decision.outcome,
            FilesystemCoreOutcome::Deny
        );
        assert_eq!(
            revoked.core_evaluations[1].stage_decision.effects[0].dimensions[0].stratum,
            7
        );
    }

    #[test]
    fn filesystem_candidate_oracle_evaluates_mkdir_mode_and_both_effects() {
        let output = evaluate_filesystem_candidate(
            &Rev2Core::embedded().unwrap(),
            &filesystem_mkdir_oracle_input(),
        )
        .unwrap();
        assert_eq!(output.expected_outcome.decision, FilesystemDecision::Allow);
        assert_eq!(output.expected_outcome.result.class, "mkdir-complete");
        assert_eq!(output.normalization.runtime_slots.len(), 2);
        assert_eq!(output.normalization.runtime_slots[0].capability, "fs:write");
        assert_eq!(output.normalization.runtime_slots[1].capability, "fs:list");
        assert_eq!(output.expected_outcome.side_effects.len(), 1);
        assert_eq!(
            output.expected_outcome.side_effects[0].final_kind,
            Some(FilesystemObjectKind::Directory)
        );
        assert_eq!(output.expected_outcome.side_effects[0].mode, Some(0o040700));
        assert_eq!(
            output.core_evaluations[0].stage_decision.committed_effects.len(),
            2
        );
    }

    #[test]
    fn filesystem_candidate_oracle_preserves_generated_principal_role_order() {
        let mut input = filesystem_lstat_oracle_input();
        let owner_key = "package:z-owner".to_string();
        let other_key = "package:a-other".to_string();
        input.case_projection.effect_owner_key = owner_key.clone();
        input.case_projection.principals = vec![
            PrincipalRef {
                kind: PrincipalKind::Package,
                key: owner_key.clone(),
            },
            PrincipalRef {
                kind: PrincipalKind::Package,
                key: other_key.clone(),
            },
        ];
        input.case_projection.constrained_principal_keys =
            vec![owner_key.clone(), other_key.clone()];
        for actor in &mut input.case_projection.execution.actors {
            actor.principal_key = Some(owner_key.clone());
            actor.effect_owner = owner_key.clone();
        }
        let resource = input.case_projection.authority_rows[0].resource.clone();
        input.case_projection.authority_rows = vec![case_authority_row(
            "case:static:0".to_string(),
            FilesystemAuthoritySourceClass::StaticFloor,
            Some(other_key.clone()),
            "fs:list".to_string(),
            &resource,
            FilesystemAuthorityState::Active,
        )];
        bind_test_case_plan(&mut input, "authorable-wrong-principal-denial");

        let output =
            evaluate_filesystem_candidate(&Rev2Core::embedded().unwrap(), &input).unwrap();
        let shared_dimensions =
            &output.core_evaluations[0].stage_decision.effects[0].dimensions;
        assert_eq!(shared_dimensions[0].principal.key, other_key);
        assert_eq!(shared_dimensions[1].principal.key, owner_key);
        let summary_dimensions = &output.expected_outcome.core.evaluations[0].dimensions;
        assert_eq!(summary_dimensions[0].principal_key, owner_key);
        assert_eq!(summary_dimensions[1].principal_key, other_key);
    }

    #[test]
    fn filesystem_candidate_oracle_rejects_generated_plan_drift() {
        let core = Rev2Core::embedded().unwrap();

        let mut requirement = filesystem_lstat_oracle_input();
        requirement.case_projection.requirement_id = "filesystem-fixture:lstat-sync".to_string();
        recompute_filesystem_oracle_input_digests(&mut requirement);
        let error = evaluate_filesystem_candidate(&core, &requirement).unwrap_err();
        assert!(error.message.contains("requirement"));

        let mut target_tuple = filesystem_lstat_oracle_input();
        target_tuple.case_projection.target_predicate.candidates[0].feature_set =
            "invented-feature-set".to_string();
        recompute_filesystem_oracle_input_digests(&mut target_tuple);
        let error = evaluate_filesystem_candidate(&core, &target_tuple).unwrap_err();
        assert!(error.message.contains("target predicate"));

        let mut authority = filesystem_lstat_oracle_input();
        authority.case_projection.authority_rows[0].source_id = "case:static:wrong".to_string();
        recompute_filesystem_oracle_input_digests(&mut authority);
        let error = evaluate_filesystem_candidate(&core, &authority).unwrap_err();
        assert!(error.message.contains("authority rows"));

        let mut lifecycle = filesystem_lstat_oracle_input();
        lifecycle.case_projection.execution.resource_lifecycle.pop();
        recompute_filesystem_oracle_input_digests(&mut lifecycle);
        let error = evaluate_filesystem_candidate(&core, &lifecycle).unwrap_err();
        assert!(error.message.contains("resource lifecycle"));

        let mut fault = filesystem_revoked_oracle_input();
        let Some(FilesystemFaultPlan {
            action: FilesystemFaultAction::AuthorityRevocation {
                remove_source_ids, ..
            },
            ..
        }) = fault.case_projection.fault_plan.as_mut()
        else {
            panic!("revocation fixture must contain a revocation fault")
        };
        remove_source_ids[0] = "case:session-grant:wrong".to_string();
        recompute_filesystem_oracle_input_digests(&mut fault);
        let error = evaluate_filesystem_candidate(&core, &fault).unwrap_err();
        assert!(error.message.contains("fault plan"));

        let mut actor = filesystem_mkdir_oracle_input();
        actor.case_projection.execution.actors[1].actor_id =
            actor.case_projection.execution.actors[0].actor_id.clone();
        recompute_filesystem_oracle_input_digests(&mut actor);
        let error = evaluate_filesystem_candidate(&core, &actor).unwrap_err();
        assert!(error.message.contains("actor binding"));
    }

    #[test]
    fn filesystem_candidate_oracle_validates_every_generated_case_plan_family() {
        let mut principal_plans = BTreeSet::new();
        let mut authority_plans = BTreeSet::new();
        let mut fault_plans = BTreeSet::new();
        let mut core_expectations = BTreeSet::new();
        let mut outcome_dispositions = BTreeSet::new();
        let mut lifecycle_requirements = BTreeSet::new();
        let mut committed_slots = BTreeSet::new();
        let mut execution_modes = BTreeSet::new();
        let mut input_mutations = BTreeSet::new();

        for plan in REV2_FILESYSTEM_CANDIDATE_CASE_PLANS {
            let projection = matrix_case_projection(plan);
            let operation = generated_operation(&projection.edge_id).unwrap();
            let target = &projection.setup.objects[0];
            let state = target_state(operation, target.kind).unwrap();
            let outcome = operation_authorized_outcomes(operation)
                .iter()
                .find(|outcome| outcome.target_state == state)
                .unwrap();
            validate_generated_operation_model(operation).unwrap();
            validate_generated_authorized_outcome(operation, state, outcome).unwrap();
            validate_case_plan_binding(&projection, operation, plan, target, state).unwrap_or_else(
                |error| {
                panic!(
                    "{} did not validate: {}",
                    generated_case_kind(plan.case_kind),
                    error.message
                )
                },
            );

            principal_plans.insert(plan.principal_plan);
            authority_plans.insert(plan.authority_plan);
            fault_plans.insert(plan.fault_plan);
            core_expectations.insert(plan.core_expectation);
            outcome_dispositions.insert(plan.outcome_disposition);
            lifecycle_requirements.insert(plan.lifecycle_requirement);
            committed_slots.insert(plan.committed_slots);
            execution_modes.insert(plan.execution_mode);
            input_mutations.insert(plan.input_mutation);
        }

        assert_eq!(REV2_FILESYSTEM_CANDIDATE_CASE_PLANS.len(), 21);
        assert_eq!(principal_plans.len(), 5);
        assert_eq!(authority_plans.len(), 10);
        assert_eq!(fault_plans.len(), 5);
        assert_eq!(core_expectations.len(), 11);
        assert_eq!(outcome_dispositions.len(), 5);
        assert_eq!(lifecycle_requirements.len(), 2);
        assert_eq!(committed_slots.len(), 2);
        assert_eq!(execution_modes.len(), 2);
        assert_eq!(input_mutations.len(), 2);
    }

    #[test]
    fn filesystem_candidate_oracle_rejects_incomplete_or_ambiguous_initial_sandbox() {
        let core = Rev2Core::embedded().unwrap();

        let mut extra_inventory = filesystem_lstat_oracle_input();
        let mut extra = extra_inventory.initial_sandbox.objects[0].clone();
        extra.object_id = "object:extra".to_string();
        extra_inventory.initial_sandbox.objects.push(extra);
        recompute_filesystem_oracle_input_digests(&mut extra_inventory);
        let error = evaluate_filesystem_candidate(&core, &extra_inventory).unwrap_err();
        assert!(error.message.contains("exactly cover setup"));

        let mut duplicate_fixture_label = filesystem_lstat_oracle_input();
        let root_fixture = duplicate_fixture_label.case_projection.setup.logical_roots[0]
            .object_identity
            .clone();
        duplicate_fixture_label.case_projection.setup.objects[0].object_identity =
            Some(root_fixture.clone());
        duplicate_fixture_label.initial_sandbox.objects[0].fixture_identity = Some(root_fixture);
        recompute_filesystem_oracle_input_digests(&mut duplicate_fixture_label);
        let error =
            evaluate_filesystem_candidate(&core, &duplicate_fixture_label).unwrap_err();
        assert!(error.message.contains("fixture identity"));

        let mut duplicate_location = filesystem_lstat_oracle_input();
        let mut setup = duplicate_location.case_projection.setup.objects[0].clone();
        setup.object_id = "object:duplicate-location".to_string();
        setup.object_identity = Some(FilesystemObjectIdentity {
            kind: FilesystemObjectIdentityKind::OpaqueToken,
            value: "fixture:duplicate-location".to_string(),
        });
        let mut realized = duplicate_location.initial_sandbox.objects[0].clone();
        realized.object_id = setup.object_id.clone();
        realized.fixture_identity = setup.object_identity.clone();
        realized.state.identity = Some(FilesystemObjectIdentity {
            kind: FilesystemObjectIdentityKind::PlatformObject,
            value: "unix-dev-ino:00000000000000010000000000000003".to_string(),
        });
        realized.state.metadata.as_mut().unwrap().inode = "3".to_string();
        duplicate_location.case_projection.setup.objects.push(setup);
        duplicate_location.initial_sandbox.objects.push(realized);
        recompute_filesystem_oracle_input_digests(&mut duplicate_location);
        let error = evaluate_filesystem_candidate(&core, &duplicate_location).unwrap_err();
        assert!(error.message.contains("location"));

        let mut duplicate_identity = filesystem_lstat_oracle_input();
        let mut setup = duplicate_identity.case_projection.setup.objects[0].clone();
        setup.object_id = "object:unexplained-hard-link".to_string();
        setup.path.value = "alias.txt".to_string();
        setup.object_identity = Some(FilesystemObjectIdentity {
            kind: FilesystemObjectIdentityKind::OpaqueToken,
            value: "fixture:unexplained-hard-link".to_string(),
        });
        let mut realized = duplicate_identity.initial_sandbox.objects[0].clone();
        realized.object_id = setup.object_id.clone();
        realized.path = setup.path.clone();
        realized.fixture_identity = setup.object_identity.clone();
        duplicate_identity.case_projection.setup.objects.push(setup);
        duplicate_identity.initial_sandbox.objects.push(realized);
        recompute_filesystem_oracle_input_digests(&mut duplicate_identity);
        let error = evaluate_filesystem_candidate(&core, &duplicate_identity).unwrap_err();
        assert!(error.message.contains("hard-link canonical"));

        let mut root_alias = filesystem_lstat_oracle_input();
        let root_identity = root_alias.initial_sandbox.logical_roots[0]
            .platform_identity
            .clone();
        let state = &mut root_alias.initial_sandbox.objects[0].state;
        state.identity = Some(root_identity);
        let metadata = state.metadata.as_mut().unwrap();
        metadata.device = "0".to_string();
        metadata.inode = "1".to_string();
        recompute_filesystem_oracle_input_digests(&mut root_alias);
        let error = evaluate_filesystem_candidate(&core, &root_alias).unwrap_err();
        assert!(error.message.contains("logical-root platform identity"));
    }

    #[test]
    fn filesystem_candidate_oracle_enforces_metadata_and_setup_kind_contracts() {
        let core = Rev2Core::embedded().unwrap();

        let mut valid_wide_metadata = filesystem_lstat_oracle_input();
        let metadata = valid_wide_metadata.initial_sandbox.objects[0]
            .state
            .metadata
            .as_mut()
            .unwrap();
        metadata.size = "9999999999999999999999999999999999999999".to_string();
        metadata.accessed_time_ns = Some(format!("-{}", "9".repeat(40)));
        recompute_filesystem_oracle_input_digests(&mut valid_wide_metadata);
        evaluate_filesystem_candidate(&core, &valid_wide_metadata).unwrap();

        let mut equivalent_authority_path = filesystem_lstat_oracle_input();
        equivalent_authority_path.case_projection.authority_rows[0]
            .resource
            .path = FilesystemPlatformPath {
            encoding: FilesystemPlatformPathEncoding::OpaqueBase64url,
            value: base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b"file.txt"),
        };
        recompute_filesystem_oracle_input_digests(&mut equivalent_authority_path);
        let output = evaluate_filesystem_candidate(&core, &equivalent_authority_path).unwrap();
        assert_eq!(output.expected_outcome.decision, FilesystemDecision::Allow);

        let mut identity_mismatch = filesystem_lstat_oracle_input();
        identity_mismatch.initial_sandbox.objects[0]
            .state
            .metadata
            .as_mut()
            .unwrap()
            .device = "2".to_string();
        recompute_filesystem_oracle_input_digests(&mut identity_mismatch);
        let error = evaluate_filesystem_candidate(&core, &identity_mismatch).unwrap_err();
        assert!(error.message.contains("device/inode"));

        let mut oversized_mode = filesystem_lstat_oracle_input();
        oversized_mode.initial_sandbox.objects[0]
            .state
            .metadata
            .as_mut()
            .unwrap()
            .mode = 0o1100644;
        recompute_filesystem_oracle_input_digests(&mut oversized_mode);
        let error = evaluate_filesystem_candidate(&core, &oversized_mode).unwrap_err();
        assert!(error.message.contains("S_IFMT"));

        let mut missing_fixture_identity = filesystem_lstat_oracle_input();
        missing_fixture_identity.case_projection.setup.objects[0].object_identity = None;
        missing_fixture_identity.initial_sandbox.objects[0].fixture_identity = None;
        recompute_filesystem_oracle_input_digests(&mut missing_fixture_identity);
        let error = evaluate_filesystem_candidate(&core, &missing_fixture_identity).unwrap_err();
        assert!(error.message.contains("setup identity"));

        let mut missing_content = filesystem_lstat_oracle_input();
        missing_content.case_projection.setup.objects[0].content = None;
        recompute_filesystem_oracle_input_digests(&mut missing_content);
        let error = evaluate_filesystem_candidate(&core, &missing_content).unwrap_err();
        assert!(error.message.contains("content"));
    }

    #[test]
    fn filesystem_candidate_oracle_rejects_non_relative_or_noncanonical_paths() {
        let core = Rev2Core::embedded().unwrap();
        let mut drive = filesystem_lstat_oracle_input();
        drive.case_projection.setup.objects[0].path.value = "C:/file.txt".to_string();
        drive.initial_sandbox.objects[0].path =
            drive.case_projection.setup.objects[0].path.clone();
        recompute_filesystem_oracle_input_digests(&mut drive);
        let error = evaluate_filesystem_candidate(&core, &drive).unwrap_err();
        assert!(error.message.contains("descriptor-relative"));

        let noncanonical = FilesystemPlatformPath {
            encoding: FilesystemPlatformPathEncoding::OpaqueBase64url,
            value: "Zh".to_string(),
        };
        assert!(platform_path_bytes(&noncanonical).is_err());
    }

    #[test]
    fn filesystem_hjcs_uses_a_nul_frame() {
        let value = json!({ "a": 1 });
        let hjcs = hjcs_digest("domain", &value).unwrap();
        let direct = domain_digest("domain", &value).unwrap();
        assert_ne!(hjcs, direct);

        let mut hasher = Sha256::new();
        hasher.update(b"domain\0{\"a\":1}");
        assert_eq!(
            hjcs,
            format!(
                "sha256-{}",
                base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hasher.finalize())
            )
        );
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
        assert_eq!(
            allowed.effects[0]
                .dimensions
                .iter()
                .map(|dimension| (
                    dimension.stratum,
                    dimension
                        .positive_source
                        .as_ref()
                        .map(|source| source.source_id.as_str()),
                ))
                .collect::<Vec<_>>(),
            vec![(9, Some("a-row")), (9, Some("b-row"))],
        );
    }

    #[test]
    fn canonical_policy_row_digest_binds_full_principal_kind_and_key() {
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
    fn permission_alternative_branches_select_their_own_positive_channels() {
        let core = Rev2Core::embedded().unwrap();
        let principal = package("permission-session");
        let sys_selector = selector(
            Some(principal.clone()),
            "sys:read",
            json!({ "kind": "cpus" }),
        );
        let mut rules = policy(Mode::Enforce);
        rules.session_grants.push(named("session:sys", sys_selector.clone()));
        rules.escalation_ceiling.push(named("ceiling:sys", sys_selector));

        for (edge, slot) in [
            (PERMISSION_QUERY_EDGE, PERMISSION_QUERY_SYS_SLOT),
            (PERMISSION_REVOKE_EDGE, PERMISSION_REVOKE_SYS_SLOT),
        ] {
            let decision = core
                .decide_stage(
                    &stage(
                        "permission-dynamic",
                        vec![principal.clone()],
                        vec![permission_sys_effect(edge, slot, "cpus")],
                    ),
                    &rules,
                )
                .unwrap();
            assert_eq!(decision.outcome, Outcome::Allow);
            assert_eq!(decision.effects[0].dimensions[0].stratum, 11);
            assert_eq!(
                decision.effects[0].dimensions[0]
                    .positive_source
                    .as_ref()
                    .unwrap()
                    .kind,
                "session-row"
            );
        }

        // The same alternative edge contains a static-only run branch. Its
        // branch-local allowlist excludes session authority even though the
        // edge-wide union admits it for the dynamic branches.
        let run_selector = spawn_selector(principal.clone());
        rules
            .session_grants
            .push(named("session:run", run_selector.clone()));
        rules
            .escalation_ceiling
            .push(named("ceiling:run", run_selector));
        let decision = core
            .decide_stage(
                &stage(
                    "permission-static",
                    vec![principal],
                    vec![permission_run_effect()],
                ),
                &rules,
            )
            .unwrap();
        assert_eq!(decision.outcome, Outcome::Deny);
        assert_eq!(decision.effects[0].dimensions[0].stratum, 17);
        assert_eq!(
            decision.effects[0].dimensions[0].reason_code,
            REASON_MISSING_AUTHORITY
        );
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
        let core = protected_core();
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

        let exception = protected_exception(
            &core,
            "metadata-row",
            authority.clone(),
            "instance role credentials",
        );
        let mut excepted = policy(Mode::Enforce);
        excepted.static_floor.push(named("metadata-row", authority.clone()));
        excepted
            .validated_receipt_row_digests
            .push(exception.canonical_row_digest.clone());
        excepted.protected_exceptions.push(exception);
        let allowed = core.decide_stage(&request, &excepted).unwrap();
        assert_eq!(allowed.outcome, Outcome::Allow);
        assert_eq!(allowed.effects[0].dimensions[0].stratum, 8);
        assert_eq!(
            allowed.effects[0].dimensions[0]
                .positive_source
                .as_ref()
                .map(|source| source.source_id.as_str()),
            Some("metadata-row"),
        );

        let dns_authority = fetch_host_selector(
            Some(principal.clone()),
            "dns-exact",
            "evil.example",
            "metadata",
        );
        let mut dns_exception = policy(Mode::Enforce);
        dns_exception.static_floor.push(named("dns-static", dns_authority.clone()));
        let dns_protected = protected_exception(
            &core,
            "dns-static",
            dns_authority,
            "must never clear metadata by DNS",
        );
        dns_exception
            .validated_receipt_row_digests
            .push(dns_protected.canonical_row_digest.clone());
        dns_exception.protected_exceptions.push(dns_protected);
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

        let mut revoked = excepted.clone();
        revoked
            .session_revocations
            .push(named("revoked-metadata", authority.clone()));
        let denied_after_revocation = core.decide_stage(&request, &revoked).unwrap();
        assert_eq!(denied_after_revocation.effects[0].dimensions[0].stratum, 7);

        excepted
            .principal_denials
            .push(named("specific-denial", authority));
        let denied_after_exception = core.decide_stage(&request, &excepted).unwrap();
        assert_eq!(denied_after_exception.effects[0].dimensions[0].stratum, 6);
    }

    #[test]
    fn protected_exception_identity_preimage_and_receipt_substitution_fail_closed() {
        let core = protected_core();
        let principal = package("metadata-adversary");
        let authority = fetch_selector(principal, "169.254.169.254", "metadata");
        let valid = protected_exception(
            &core,
            "metadata-row",
            authority.clone(),
            "instance role credentials",
        );
        assert!(!serde_json::to_string(&valid)
            .unwrap()
            .contains("instance role credentials"));
        assert!(serde_json::from_value::<ProtectedExceptionInput>(json!({
            "sourceId": "metadata-row",
            "reason": "instance role credentials",
            "selector": valid.selector.clone(),
        }))
        .is_err());

        let evaluate = |exception: ProtectedExceptionInput, receipt_digest: String| {
            let mut policy = policy(Mode::Enforce);
            policy.static_floor.push(named("metadata-row", authority.clone()));
            policy.protected_exceptions.push(exception);
            policy.validated_receipt_row_digests.push(receipt_digest);
            core.decide_stage(
                &stage(
                    "protected-adversary",
                    vec![authority.principal.clone().unwrap()],
                    vec![fetch_effect("169.254.169.254")],
                ),
                &policy,
            )
        };

        let mut wrong_source = valid.clone();
        wrong_source.source_id = "metadata-substituted-source".to_string();
        let canonical = core
            .normalize_selector(&wrong_source.selector, SelectorPolarity::Positive)
            .unwrap();
        wrong_source.canonical_row_digest = protected_row_digest(
            &wrong_source.source_id,
            &canonical,
            &wrong_source.predicate_id,
            &wrong_source.reason_digest,
        )
        .unwrap();
        assert_eq!(
            evaluate(wrong_source.clone(), wrong_source.canonical_row_digest)
                .unwrap_err()
                .reason_code,
            REASON_SCHEMA_INVALID,
        );

        let mut wrong_selector = valid.clone();
        wrong_selector.selector.resource["port"]["exact"] = json!(443);
        let wrong_canonical = core
            .normalize_selector(&wrong_selector.selector, SelectorPolarity::Positive)
            .unwrap();
        wrong_selector.canonical_row_digest = protected_row_digest(
            &wrong_selector.source_id,
            &wrong_canonical,
            &wrong_selector.predicate_id,
            &wrong_selector.reason_digest,
        )
        .unwrap();
        assert_eq!(
            evaluate(wrong_selector.clone(), wrong_selector.canonical_row_digest)
                .unwrap_err()
                .reason_code,
            REASON_SCHEMA_INVALID,
        );

        let mut wrong_predicate = valid.clone();
        wrong_predicate.predicate_id = "predicate.exact-static-row-required/2".to_string();
        wrong_predicate.canonical_row_digest = protected_row_digest(
            &wrong_predicate.source_id,
            &canonical,
            &wrong_predicate.predicate_id,
            &wrong_predicate.reason_digest,
        )
        .unwrap();
        assert_eq!(
            evaluate(wrong_predicate.clone(), wrong_predicate.canonical_row_digest)
                .unwrap_err()
                .reason_code,
            REASON_SCHEMA_INVALID,
        );

        let mut wrong_reason = valid.clone();
        wrong_reason.reason_digest = REV2_REGISTRY_DIGEST.to_string();
        assert_eq!(
            evaluate(wrong_reason, valid.canonical_row_digest.clone())
                .unwrap_err()
                .reason_code,
            REASON_SCHEMA_INVALID,
        );

        let mut wrong_row = valid.clone();
        wrong_row.canonical_row_digest = REV2_VOCAB_DIGEST.to_string();
        assert_eq!(
            evaluate(wrong_row, REV2_VOCAB_DIGEST.to_string())
                .unwrap_err()
                .reason_code,
            REASON_SCHEMA_INVALID,
        );

        assert_eq!(
            evaluate(valid, REV2_REGISTRY_DIGEST.to_string())
                .unwrap_err()
                .reason_code,
            REASON_SCHEMA_INVALID,
        );
    }

    #[test]
    fn path_authority_requires_host_bound_object_identity() {
        let core = Rev2Core::embedded().unwrap();
        let principal = package("reader");
        let authority = path_selector(principal.clone(), "/project/data");
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
            source_id: "path-row".to_string(),
            root_binding_id: "root-binding:1".to_string(),
            final_object_identities: vec![json!({
                "kind": "platform-object",
                "value": "file:1",
            })],
            parent_identities: vec![],
        });
        let allowed = core.decide_stage(&request, &bound).unwrap();
        assert_eq!(allowed.outcome, Outcome::Allow);
        assert_eq!(
            allowed.effects[0].dimensions[0]
                .positive_source
                .as_ref()
                .map(|source| source.source_id.as_str()),
            Some("path-row"),
        );
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
        for source_id in ["positive".to_string(), "deny-object".to_string()] {
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
    fn negative_missing_path_binding_does_not_collapse_siblings_by_parent_identity() {
        let core = Rev2Core::embedded().unwrap();
        let principal = package("missing-sibling-reader");
        let parent_identity = json!({
            "kind": "platform-object",
            "value": "dir:shared-parent",
        });
        let mut rules = policy(Mode::Enforce);
        rules.static_floor.push(named(
            "positive",
            path_selector(principal.clone(), "/project"),
        ));
        rules.process_denials.push(named(
            "deny-secret",
            selector(
                None,
                "fs:read",
                json!({
                    "kind": "path-exact",
                    "path": {
                        "encoding": "opaque-base64url",
                        "value": base64::engine::general_purpose::URL_SAFE_NO_PAD
                            .encode(b"/project/secret"),
                    },
                    "root": "$PROJECT",
                }),
            ),
        ));
        for source_id in ["positive", "deny-secret"] {
            rules.path_bindings.push(PathBindingInput {
                source_id: source_id.to_string(),
                root_binding_id: "root-binding:1".to_string(),
                final_object_identities: vec![],
                parent_identities: vec![parent_identity.clone()],
            });
        }
        let proposed_effect = |path: &str| {
            let mut effect = path_effect(path, "unused-proposed-identity");
            effect.occurrence["finalObjectState"] = json!({ "kind": "proposed" });
            effect.occurrence["parentIdentity"] = parent_identity.clone();
            effect
        };

        let sibling = core
            .decide_stage(
                &stage(
                    "missing-sibling",
                    vec![principal.clone()],
                    vec![proposed_effect("/project/allowed")],
                ),
                &rules,
            )
            .unwrap();
        assert_eq!(sibling.outcome, Outcome::Allow);

        let secret = core
            .decide_stage(
                &stage(
                    "missing-secret",
                    vec![principal],
                    vec![proposed_effect("/project/secret")],
                ),
                &rules,
            )
            .unwrap();
        assert_eq!(secret.outcome, Outcome::Deny);
        assert_eq!(secret.effects[0].dimensions[0].stratum, 5);
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
        let error = core
            .normalize_schema(
                "value.platform-path/2",
                &json!({ "encoding": "opaque-base64url", "value": "Zh" }),
            )
            .unwrap_err();
        assert_eq!(error.reason_code, REASON_SCHEMA_INVALID);
        assert!(core
            .exact_match_clause(
                "path-exact-or-tree",
                &json!({
                    "kind": "path-exact",
                    "path": { "encoding": "unicode", "value": "/project/data/file" },
                    "root": "$PROJECT",
                }),
                &json!({
                    "lexicalPath": {
                        "encoding": "opaque-base64url",
                        "value": child_path.clone(),
                    },
                    "root": "$PROJECT",
                }),
            )
            .unwrap());
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
        for lexical_path in [
            json!({ "encoding": "opaque-base64url", "value": child_path }),
            json!({ "encoding": "unicode", "value": "/project/data/file" }),
        ] {
            for state_kind in ["missing", "proposed"] {
                let mut effect = path_effect("/unused", "unused");
                effect.occurrence["lexicalPath"] = lexical_path.clone();
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
        let core = protected_core();
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
        let exception = protected_exception(
            &core,
            "metadata",
            metadata,
            "must not join a running actor",
        );
        rules
            .validated_receipt_row_digests
            .push(exception.canonical_row_digest.clone());
        rules.protected_exceptions.push(exception);
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
        let mut policy = policy(Mode::Enforce);
        policy.static_floor.push(named("path", authority));
        policy.path_bindings.push(PathBindingInput {
            source_id: "path".to_string(),
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

// Copyright 2018-2026 the Deno authors. MIT license.

use std::borrow::Cow;
use std::cmp::Ordering;
use std::ffi::OsStr;
use std::fmt;
use std::fmt::Debug;
use std::hash::Hash;
use std::hash::Hasher;
use std::io::Read;
use std::io::Write;
use std::net::IpAddr;
use std::net::Ipv6Addr;
use std::net::SocketAddr;
use std::ops::Deref;
use std::path::Path;
use std::path::PathBuf;
use std::string::ToString;
use std::sync::Arc;
use std::sync::OnceLock;

use base64::Engine as _;
use base64::prelude::BASE64_STANDARD;
use capacity_builder::StringBuilder;
use deno_path_util::normalize_path;
use deno_path_util::url_to_file_path;
use deno_terminal::colors;
use deno_unsync::sync::AtomicFlag;
use fqdn::FQDN;
use hmac::Hmac;
use hmac::Mac;
use ipnet::IpNet;
use once_cell::sync::Lazy;
use parking_lot::Condvar;
use parking_lot::Mutex;
use serde::Deserialize;
use serde::Deserializer;
use serde::Serialize;
use serde::de;
use sha2::Sha256;
use url::Url;

pub mod broker;
mod ipc_pipe;
mod oden_dynamic;
mod oden_handle;
mod oden_policy;
mod oden_principal_index;
mod oden_protected;
mod oden_rev2_authority;
mod oden_rev2_context;
mod oden_rev2_executable;
mod oden_rev2_permission;
mod oden_rev2_policy;
mod oden_rev2_protocol;
mod oden_rev2_runtime;
mod oden_rev2_session;
pub mod prompter;
mod runtime_descriptor_parser;
pub mod which;

// @ref LLP 0019#stage-c-shared-core-implementation-checkpoint-eng-24015 [implements] -- The production permission crate compiles the reviewed Rev2 core directly; runtime actors remain dormant until trusted host state installs them.
#[path = "oden_rev2_core_generated.rs"]
pub mod rev2;
#[path = "oden_rev2_registry_generated.rs"]
mod rev2_registry_generated;

pub use oden_rev2_context::OdenRev2RuntimeAuthorityContext;
pub use oden_rev2_permission::OdenRev2PermissionError;
pub use oden_rev2_permission::OdenRev2PermissionOperation;
pub use oden_rev2_permission::oden_capsec_rev2_permission_operation;
pub use oden_rev2_policy::OdenRev2CompiledBuildIdentity;
pub use oden_rev2_policy::OdenRev2LoadState;
pub use oden_rev2_policy::OdenRev2LoadedPolicyContext;
pub use oden_rev2_runtime::OdenRev2ArmedContext;
pub use oden_rev2_runtime::OdenRev2CommittedLaunchEntry;
pub use oden_rev2_runtime::OdenRev2CommittedLaunchPayload;
pub use oden_rev2_runtime::OdenRev2HostActor;
pub use oden_rev2_runtime::OdenRev2HostAuthorization;
pub use oden_rev2_runtime::OdenRev2HostChildExport;
pub use oden_rev2_runtime::OdenRev2HostCommit;
pub use oden_rev2_runtime::OdenRev2HostError;
pub use oden_rev2_runtime::OdenRev2HostInteraction;
pub use oden_rev2_runtime::OdenRev2HostLaunchSeal;
pub use oden_rev2_runtime::OdenRev2HostSpawnEdge;
pub use oden_rev2_runtime::OdenRev2RequiredForCommit;

use prompter::MAYBE_CURRENT_STACKTRACE;
use prompter::PERMISSION_EMOJI;
use prompter::permission_prompt;
pub use runtime_descriptor_parser::RuntimePermissionDescriptorParser;

use self::oden_dynamic::DynamicDecider as OdenDynamicDecider;
use self::oden_dynamic::DynamicPermissionState as OdenDynamicPermissionState;
use self::oden_dynamic::DynamicQueryState as OdenDynamicQueryState;
use self::oden_dynamic::DynamicRequestCode as OdenDynamicRequestCode;
use self::oden_dynamic::DynamicRequestEvaluation as OdenDynamicRequestEvaluation;
use self::oden_dynamic::DynamicRequestResult as OdenDynamicRequestResult;
use self::oden_dynamic::OnRequest as OdenOnRequest;
use self::oden_dynamic::PolicyValidationIssue as OdenPolicyValidationIssue;
use self::oden_handle::HandleLookup as OdenHandleLookup;
use self::oden_policy::Decision as OdenDecision;
use self::oden_policy::Family as OdenFamily;
use self::oden_policy::Grant as OdenGrant;
use self::oden_policy::Mode as OdenMode;
use self::oden_policy::Policy as OdenPolicy;
use self::oden_policy::Principal as OdenPrincipal;
use self::oden_policy::Request as OdenRequest;
use self::oden_protected::ProtectedMetadataCheck as OdenProtectedMetadataCheck;
use self::oden_protected::ProtectedMetadataPolicy as OdenProtectedMetadataPolicy;
use self::oden_protected::ProtectedMetadataRowFile as OdenProtectedMetadataRowFile;
use self::prompter::PromptResponse;
use self::which::WhichSys;

/// The protocol class of a network operation at the package-capability layer.
///
/// Deno's process-level `net` descriptor deliberately combines these classes,
/// but Oden grants do not: HTTP request/response traffic, arbitrary outbound
/// streams, and listeners are distinct authority. Callers must select the
/// action at the resource-creating operation and carry it unchanged through
/// URL, DNS-resolution, redirect, Unix-socket, and vsock checks.
// @ref llp/0010-the-capability-surface.spec.md#network [implements] -- Network actions are authority classes, not aliases for one generic net descriptor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NetPermissionAction {
  Fetch,
  Connect,
  Listen,
}

impl NetPermissionAction {
  const fn as_str(self) -> &'static str {
    match self {
      Self::Fetch => "fetch",
      Self::Connect => "connect",
      Self::Listen => "listen",
    }
  }
}

/// Closed, operation-independent classification for URL schemes that can
/// reach package capability checks.
///
/// This is deliberately smaller than a URL parser. Consumers still perform
/// their own protocol validation, but they must all agree on which authority
/// class a recognized scheme can reach before endpoint or path matching.
/// `data:` carries no external authority because all bytes are already in the
/// supplied URL. `blob:` remains deny-only until ownership/delegation is
/// modeled. A scheme outside this table is structurally closed.
// @ref LLP 0019#fetch-versus-connect [implements] -- Schemes are classified before endpoint matching, with blob and unknown schemes closed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum OdenUrlSchemeClass {
  Network,
  File,
  InlineData,
  RuntimeInternal,
  ClosedBlob,
  ClosedUnknown,
}

fn oden_capsec_normalize_url_scheme(scheme: &str) -> String {
  // URL.protocol includes one trailing delimiter while url::Url::scheme()
  // does not. Strip at most that one delimiter: accepting every trailing ':'
  // would misclassify malformed `http::` as network authority.
  scheme
    .strip_suffix(':')
    .unwrap_or(scheme)
    .to_ascii_lowercase()
}

pub fn oden_capsec_classify_url_scheme(scheme: &str) -> OdenUrlSchemeClass {
  let normalized = oden_capsec_normalize_url_scheme(scheme);
  match normalized.as_str() {
    "http" | "https" => OdenUrlSchemeClass::Network,
    "file" => OdenUrlSchemeClass::File,
    "data" => OdenUrlSchemeClass::InlineData,
    // These names identify modules already owned by the runtime/package
    // resolver. They are not deputy protocols and never inherit network
    // authority merely because they have URL syntax.
    "node" | "npm" | "jsr" | "bun" | "ext" | "deno" => {
      OdenUrlSchemeClass::RuntimeInternal
    }
    "blob" => OdenUrlSchemeClass::ClosedBlob,
    _ => OdenUrlSchemeClass::ClosedUnknown,
  }
}

#[derive(Debug, Eq, PartialEq)]
pub enum BrokerResponse {
  Allow,
  Deny { message: Option<String> },
}

use self::broker::has_broker;
use self::broker::maybe_check_dynamic_with_broker;
use self::broker::maybe_check_with_broker;

pub type OtelAuditFn =
  fn(permission: &str, value: &str, stack: Option<&[String]>);

pub enum AuditSink {
  File(Mutex<std::fs::File>),
  Otel(OtelAuditFn),
}

pub static AUDIT_SINK: OnceLock<AuditSink> = OnceLock::new();

#[derive(Debug, thiserror::Error, deno_error::JsError)]
#[error("{}", custom_message.as_ref().cloned().unwrap_or_else(|| format!("Requires {access}, {}", format_permission_error(.name))))]
#[class("NotCapable")]
pub struct PermissionDeniedError {
  pub access: String,
  pub name: &'static str,
  pub custom_message: Option<String>,
  pub state: PermissionState,
}

fn format_permission_error(name: &'static str) -> String {
  if is_standalone() {
    format!(
      "specify the required permissions during compilation using `deno compile --allow-{name}`"
    )
  } else {
    format!("run again with the --allow-{name} flag")
  }
}

// --- Oden capsec Phase-0 engine hook (LLP 0001) -----------------------------
// Env-gated and inert by default. When armed, the permission layer resolves the
// acting principal from V8 script IDs captured at op dispatch and asks the
// fork-local copy of oden_policy for a layer-2 decision. Display names remain
// diagnostics only; sourceURL can forge them.
// @ref llp/0001-adding-capability-security-to-deno.plan.md
fn oden_capsec_decide(
  family: OdenFamily,
  action: &str,
  target: &str,
  api_name: Option<&str>,
) -> Result<(), PermissionCheckError> {
  oden_capsec_decide_inner(family, action, target, api_name, false, None)
}

fn oden_capsec_decide_aggregate(
  family: OdenFamily,
  action: &str,
  target: &str,
  api_name: Option<&str>,
) -> Result<(), PermissionCheckError> {
  oden_capsec_decide_inner(family, action, target, api_name, true, None)
}

/// Apply the ordinary capability decision to a principal the loader resolved
/// from its referrer. Loader admission has no op-dispatch stack, so asking the
/// generic decision path to rediscover the actor would collapse to a sentinel
/// instead of checking the package that requested the bytes.
fn oden_capsec_decide_for_principal(
  principal: OdenPrincipal,
  family: OdenFamily,
  action: &str,
  target: &str,
  api_name: Option<&str>,
) -> Result<(), PermissionCheckError> {
  oden_capsec_decide_inner(
    family,
    action,
    target,
    api_name,
    false,
    Some(principal),
  )
}

fn oden_capsec_decide_inner(
  family: OdenFamily,
  action: &str,
  target: &str,
  api_name: Option<&str>,
  aggregate: bool,
  explicit_principal: Option<OdenPrincipal>,
) -> Result<(), PermissionCheckError> {
  if !oden_capsec_active() {
    return Ok(());
  }
  oden_capsec_readiness_gate()?;
  let policy = oden_capsec_policy();
  // Normalize fs targets to an absolute, lexically-folded path so a relative
  // op (`./data/x`) matches an fs grant scope (also resolved absolute) and a
  // `..` escape resolves out of its granted scope. Non-fs targets pass through.
  let normalized_target = match family {
    OdenFamily::Fs => oden_normalize_fs_target(target),
    // Match Deno's own environment descriptor semantics: environment names
    // are case-insensitive on Windows. The reserved namespace must be too.
    OdenFamily::Env => EnvVarNameRef::new(Cow::Borrowed(target))
      .as_ref()
      .to_string(),
    _ => target.to_string(),
  };
  let req = OdenRequest {
    family,
    action: action.to_string(),
    target: normalized_target,
  };

  // @ref LLP 0015#audit-records [implements] — Shipping control variables
  // and the authenticated policy/audit directory are never package authority.
  // This layer-2 hard stop mirrors the parent-injected layer-1 deny flags and
  // wins even over an authored wildcard grant.
  let control_target = oden_capsec_is_control_request(&req, aggregate);
  if control_target {
    let principal = explicit_principal
      .clone()
      .unwrap_or_else(oden_capsec_principal);
    let label = principal.label();
    oden_capsec_audit_record(
      &label,
      family.name(),
      action,
      &req.target,
      "DENY(control plane)",
      None,
    );
    return Err(PermissionCheckError::PermissionDenied(
      PermissionDeniedError {
        access: format!("capsec control-plane access to {:?}", req.target),
        name: "capsec",
        custom_message: Some(
          "oden capsec: the engine policy and audit channel are not package authority"
            .to_string(),
        ),
        state: PermissionState::Denied,
      },
    ));
  }

  // Precedence row 3 (opt-in stack-intersection): if this capability class is
  // deputy-armed AND the live call chain plus the CPED scheduling principal
  // implicate more than one distinct non-ambient principal, decide over the
  // whole set (least privilege) so a deputy cannot launder a scheduler's
  // authority. Every other case -- every unarmed class, and the collapsed
  // single-principal case -- takes the byte-identical rows 1/2/4 path below.
  let intersection = if explicit_principal.is_none()
    && oden_capsec_deputy_class_armed(family, &req.action)
  {
    let constrained =
      OdenPolicy::constrained_principals(&oden_capsec_principal_set());
    (constrained.len() >= 2).then_some(constrained)
  } else {
    None
  };

  let (decision, principal_label, is_ambient_allow, suggestion) =
    match &intersection {
      Some(set) => {
        let decision = policy.decide_set(set, &req);
        let label = format!(
          "[{}]",
          set
            .iter()
            .map(OdenPrincipal::label)
            .collect::<Vec<_>>()
            .join(",")
        );
        // Suggest a grant for every ungranted member of the intersection.
        let toks: Vec<String> = set
          .iter()
          .filter(|p| !policy.grants(p, &req))
          .filter_map(|p| {
            oden_suggested_grant_token(p, family, action, &req.target)
              .map(|t| format!("{}={}", p.label(), t))
          })
          .collect();
        let suggestion = (!toks.is_empty()).then(|| toks.join(" ; "));
        (decision, label, false, suggestion)
      }
      None => {
        let principal = explicit_principal
          .clone()
          .unwrap_or_else(oden_capsec_principal);
        let decision = policy.decide(&principal, &req);
        let is_ambient_allow =
          principal.is_ambient() && decision == OdenDecision::Allow;
        // Suggest the grant that would allow a would-deny/deny
        // (audit-as-conversation).
        let suggestion = if matches!(decision, OdenDecision::Deny)
          || (matches!(decision, OdenDecision::AllowRecord)
            && !principal.is_ambient())
        {
          oden_suggested_grant_token(&principal, family, action, &req.target)
        } else {
          None
        };
        (decision, principal.label(), is_ambient_allow, suggestion)
      }
    };

  // Possession rescue (ENG-23784, authority-flow handles): if the op would be
  // denied by the possessor's OWN grants but the possessor is *actively using*
  // a handle whose attenuated capability covers it, the handle authorizes the
  // op. This is possession-checked, never frame-checked — holding the handle
  // (the open use window) is the authority, so no stack walk decides it. The
  // active window is empty on every path where no handle is in use, so this is
  // byte-identical to the pre-handle behavior when handles are not exercised.
  // The rescue does not widen: `active_covers` matches the attenuated scope, so
  // a use outside the handle's scope still denies through the normal path.
  if explicit_principal.is_none()
    && decision == OdenDecision::Deny
    && oden_handle::active_covers(&req)
  {
    oden_capsec_audit_record(
      &principal_label,
      family.name(),
      action,
      &req.target,
      "allow(handle)",
      None,
    );
    return Ok(());
  }

  let verdict = match (&decision, is_ambient_allow) {
    (OdenDecision::Allow, true) => "allow(ambient)",
    (OdenDecision::Allow, false) => "allow(granted)",
    (OdenDecision::AllowRecord, _) => "audit(record)",
    (OdenDecision::Deny, _) => "DENY(no grant)",
  };
  let api = api_name.unwrap_or_else(|| family.name());
  // Operational diagnostics travel only on the authenticated audit channel.
  // App stderr is application data and must remain byte-faithful.
  oden_capsec_audit_record(
    &principal_label,
    family.name(),
    action,
    &req.target,
    verdict,
    suggestion.as_deref(),
  );
  if decision == OdenDecision::Deny {
    let fix = suggestion
      .as_deref()
      .map(|t| format!(" — to allow: grant \"{principal_label}\" `{t}`"))
      .unwrap_or_default();
    return Err(PermissionCheckError::PermissionDenied(
      PermissionDeniedError {
        access: format!("{api} access to {target:?}"),
        name: "capsec",
        custom_message: Some(format!(
          "oden capsec: principal \"{principal_label}\" is not granted {}:{action}:{target}{fix}",
          family.name()
        )),
        state: PermissionState::Denied,
      },
    ));
  }
  Ok(())
}

/// Gate a security-sensitive surface that does not yet have a safe grant
/// grammar. Packages are denied under enforce and observed under audit;
/// root/runtime remain ambient. This is used for inspector/V8, WASI, native
/// database, storage, GPU, and process-global IPC entry points. (ENG-23953–57)
// @ref LLP 0010#escape-hatch-families [implements]
pub fn oden_capsec_guard_surface(
  family: &str,
  action: &str,
  target: &str,
  api_name: &str,
) -> Result<(), PermissionCheckError> {
  if !oden_capsec_active() {
    return Ok(());
  }
  oden_capsec_readiness_gate()?;
  let principal = oden_capsec_principal();
  let label = principal.label();
  if principal.is_ambient()
    || oden_capsec_mode(oden_capsec_policy_file()) == OdenMode::Permissive
  {
    return Ok(());
  }
  let mode = oden_capsec_mode(oden_capsec_policy_file());
  let verdict = if mode == OdenMode::Enforce {
    "DENY(default-closed surface)"
  } else {
    "audit(record)"
  };
  oden_capsec_audit_record(&label, family, action, target, verdict, None);
  if mode == OdenMode::Enforce {
    return Err(PermissionCheckError::PermissionDenied(
      PermissionDeniedError {
        access: format!("{api_name} access to {target:?}"),
        name: "capsec",
        custom_message: Some(format!(
          "oden capsec: principal \"{label}\" may not use default-closed {family}:{action}:{target}"
        )),
        state: PermissionState::Denied,
      },
    ));
  }
  Ok(())
}

/// Refuse forward-proxy routes while capsec is armed. The initial protected
/// metadata profile has no authenticated final-peer attestation for proxies,
/// so authorizing only the visible proxy peer would reintroduce DNS/redirect
/// laundering. Ambient proxy environment is neutralized separately; explicit
/// Deno and Node proxy routes call this boundary before opening a channel.
// @ref LLP 0019#proxies-and-network-deputies [implements]
pub fn oden_capsec_reject_forward_proxy(
  api_name: &str,
) -> Result<(), PermissionCheckError> {
  if !oden_capsec_profile_is(ODEN_CAPSEC_PROFILE) {
    return Ok(());
  }
  oden_capsec_readiness_gate()?;
  let principal = oden_capsec_principal();
  let label = principal.label();
  oden_capsec_audit_record(
    &label,
    "network",
    "forward-proxy",
    "unattested",
    "DENY(unattested final peer)",
    None,
  );
  Err(PermissionCheckError::PermissionDenied(
    PermissionDeniedError {
      access: format!("{api_name} forward-proxy access"),
      name: "capsec",
      custom_message: Some(
        "oden capsec: forward proxies are closed because this profile has no authenticated final-peer attestation"
          .to_string(),
      ),
      state: PermissionState::Denied,
    },
  ))
}

/// Enforce a Rev1.1 deny-only safety row before any ambient/mode fallback,
/// static/session authority, or active handle can rescue the operation.
/// Frozen `oden/capsec/1` binaries never enter this branch.
// @ref LLP 0019#system-information-and-process-mutation [implements]
pub fn oden_capsec_guard_deny_only_surface(
  family: &str,
  action: &str,
  target: &str,
  api_name: &str,
) -> Result<(), PermissionCheckError> {
  if !oden_capsec_profile_is(ODEN_CAPSEC_PROFILE) {
    return Ok(());
  }
  oden_capsec_readiness_gate()?;
  let constrained =
    OdenPolicy::constrained_principals(&oden_capsec_principal_set());
  if constrained.is_empty() {
    return Ok(());
  }
  let labels = constrained
    .iter()
    .map(OdenPrincipal::label)
    .collect::<Vec<_>>();
  for label in &labels {
    oden_capsec_audit_record(
      label,
      family,
      action,
      target,
      "DENY(deny-only surface)",
      None,
    );
  }
  let label = labels.join(",");
  Err(PermissionCheckError::PermissionDenied(
    PermissionDeniedError {
      access: format!("{api_name} access to {target:?}"),
      name: "capsec",
      custom_message: Some(format!(
        "oden capsec: principal set [{label}] may not use deny-only {family}:{action}:{target}"
      )),
      state: PermissionState::Denied,
    },
  ))
}

/// Record the root half of a conjunctive effect that occurs outside the stock
/// permission container. The deny-only guard keeps this helper unusable by a
/// constrained principal even if an internal op reference is passed around.
pub fn oden_capsec_record_root_ambient_effect(
  family: &str,
  action: &str,
  target: &str,
  api_name: &str,
) -> Result<(), PermissionCheckError> {
  oden_capsec_guard_deny_only_surface(family, action, target, api_name)?;
  if oden_capsec_profile_is(ODEN_CAPSEC_PROFILE) {
    oden_capsec_readiness_gate()?;
    oden_capsec_audit_record(
      "root/runtime",
      family,
      action,
      target,
      "allow(ambient)",
      None,
    );
  }
  Ok(())
}

const ODEN_TRUSTED_HOST_INSPECTOR_EFFECTS: [(&str, &str); 2] =
  [("runtime", "inspect"), ("inspector", "activate")];

/// Authorize a local inspector session created exclusively by the Rust host
/// for REPL, Jupyter, HMR, coverage, or desktop tooling. This seam is not
/// reachable from package JavaScript: package-originated inspector routes use
/// the ordinary terminal inspector checks below. Native host setup often runs
/// with no active JS frame (`no-user`), so deriving its authority from the
/// current principal set would misclassify trusted runtime control as package
/// activity and break the tool before user code starts.
// @ref LLP 0019#inspector [implements]
pub fn oden_capsec_check_runtime_local_inspector_session(
  target: &str,
) -> Result<(), PermissionCheckError> {
  if !oden_capsec_profile_is(ODEN_CAPSEC_PROFILE) {
    return Ok(());
  }
  oden_capsec_readiness_gate()?;
  for (family, action) in ODEN_TRUSTED_HOST_INSPECTOR_EFFECTS {
    oden_capsec_audit_record(
      "root/runtime",
      family,
      action,
      target,
      "allow(trusted host)",
      None,
    );
  }
  Ok(())
}

/// Authorize an inspector activation route from the exact Rev1.1 static floor.
/// Programmatic package callers must each hold `inspector:activate`; session
/// overlays and handles cannot satisfy this terminal predicate. Startup and
/// host-signal routes additionally require the exact root row, even though the
/// runtime-control principal is otherwise ambient.
// @ref LLP 0019#inspector [implements]
pub fn oden_capsec_check_inspector_activation(
  target: &str,
  api_name: &str,
  exact_root_static_row: bool,
) -> Result<(), PermissionCheckError> {
  if !oden_capsec_profile_is(ODEN_CAPSEC_PROFILE) {
    return Ok(());
  }
  oden_capsec_readiness_gate()?;
  let req = OdenRequest {
    family: OdenFamily::Inspector,
    action: "activate".to_string(),
    target: String::new(),
  };
  let policy = oden_capsec_policy();
  let (allowed, labels) = if exact_root_static_row {
    (
      oden_capsec_root_static_grants(&req),
      vec!["root/runtime-control".to_string()],
    )
  } else {
    let constrained =
      OdenPolicy::constrained_principals(&oden_capsec_principal_set());
    let labels = constrained
      .iter()
      .map(OdenPrincipal::label)
      .collect::<Vec<_>>();
    (
      constrained.is_empty()
        || constrained.iter().all(|p| policy.static_grants(p, &req)),
      labels,
    )
  };
  let programmatic_root = labels.is_empty() && !exact_root_static_row;
  let audit_labels = if labels.is_empty() {
    vec!["root/runtime".to_string()]
  } else {
    labels
  };
  let verdict = if allowed && exact_root_static_row {
    "allow(exact-root static inspector row)"
  } else if allowed && programmatic_root {
    "allow(ambient programmatic root)"
  } else if allowed {
    "allow(exact-static inspector row)"
  } else {
    "DENY(exact-static inspector row required)"
  };
  for label in &audit_labels {
    oden_capsec_audit_record(
      label,
      "inspector",
      "activate",
      target,
      verdict,
      (!allowed).then_some("inspector:activate"),
    );
  }
  if allowed {
    return Ok(());
  }
  Err(PermissionCheckError::PermissionDenied(
    PermissionDeniedError {
      access: format!("{api_name} access to {target:?}"),
      name: "capsec",
      custom_message: Some(format!(
        "oden capsec: inspector activation at {target:?} requires an exact static inspector:activate row"
      )),
      state: PermissionState::Denied,
    },
  ))
}

/// Evaluate the network half of an inspector conjunction over every
/// constrained principal, independent of the optional deputyClasses posture.
/// Inspector authority and its transport must have the same actor set.
pub fn oden_capsec_check_inspector_network_effect(
  action: NetPermissionAction,
  host: &str,
  port: u16,
  api_name: &str,
) -> Result<(), PermissionCheckError> {
  if !oden_capsec_profile_is(ODEN_CAPSEC_PROFILE) {
    return Ok(());
  }
  let hostname = Host::parse_for_query(host)?;
  let descriptor = NetDescriptor(hostname, Some(port.into()));
  let target = descriptor.display_name().into_owned();
  let req = OdenRequest {
    family: OdenFamily::Network,
    action: action.as_str().to_string(),
    target: target.clone(),
  };
  let constrained =
    OdenPolicy::constrained_principals(&oden_capsec_principal_set());
  let allowed = constrained.is_empty()
    || constrained
      .iter()
      .all(|principal| oden_capsec_policy().static_grants(principal, &req));
  let labels = if constrained.is_empty() {
    vec!["root/runtime".to_string()]
  } else {
    constrained
      .iter()
      .map(OdenPrincipal::label)
      .collect::<Vec<_>>()
  };
  let suggestion = format!("network:{}:{host}", action.as_str());
  for label in &labels {
    oden_capsec_audit_record(
      label,
      "network",
      action.as_str(),
      &target,
      if allowed {
        "allow(inspector conjunctive static network row)"
      } else {
        "DENY(inspector conjunctive static network row required)"
      },
      (!allowed).then_some(suggestion.as_str()),
    );
  }
  if allowed {
    Ok(())
  } else {
    Err(PermissionCheckError::PermissionDenied(
      PermissionDeniedError {
        access: format!("{api_name} access to {target:?}"),
        name: "capsec",
        custom_message: Some(format!(
          "oden capsec: inspector transport at {target:?} requires an exact static {suggestion} row"
        )),
        state: PermissionState::Denied,
      },
    ))
  }
}

/// Runtime-control listener activation is a conjunctive edge: the exact root
/// inspector row is mandatory, while the root principal supplies ambient
/// network-listen authority. Record both decisions before creating the socket.
// @ref LLP 0019#inspector [implements]
pub fn oden_capsec_check_inspector_listener_startup(
  target: &str,
  api_name: &str,
) -> Result<(), PermissionCheckError> {
  oden_capsec_check_inspector_activation(target, api_name, true)?;
  if !oden_capsec_profile_is(ODEN_CAPSEC_PROFILE) {
    return Ok(());
  }
  oden_capsec_audit_record(
    "root/runtime-control",
    "network",
    "listen",
    target,
    "allow(ambient)",
    None,
  );
  Ok(())
}

/// Programmatic root activation is distinct from an externally delivered host
/// signal: it uses the ordinary root definition channel, while still recording
/// the conjunctive listener effect before bind.
pub fn oden_capsec_check_inspector_listener_programmatic(
  target: &str,
  api_name: &str,
) -> Result<(), PermissionCheckError> {
  oden_capsec_check_inspector_activation(target, api_name, false)?;
  oden_capsec_record_inspector_root_network_effect("listen", target)
}

fn oden_programmatic_inspector_signal_channel()
-> &'static tokio::sync::broadcast::Sender<()> {
  static CHANNEL: OnceLock<tokio::sync::broadcast::Sender<()>> =
    OnceLock::new();
  CHANNEL.get_or_init(|| tokio::sync::broadcast::channel(16).0)
}

pub fn oden_capsec_subscribe_programmatic_inspector_signal()
-> tokio::sync::broadcast::Receiver<()> {
  oden_programmatic_inspector_signal_channel().subscribe()
}

pub fn oden_capsec_trigger_programmatic_inspector_signal() {
  let _ = oden_programmatic_inspector_signal_channel().send(());
}

/// Record a trusted runtime-control network effect that is part of an
/// inspector activation but occurs outside a PermissionsContainer (for
/// example the desktop DevTools multiplexer).
pub fn oden_capsec_record_inspector_root_network_effect(
  action: &str,
  target: &str,
) -> Result<(), PermissionCheckError> {
  if !oden_capsec_profile_is(ODEN_CAPSEC_PROFILE) {
    return Ok(());
  }
  oden_capsec_readiness_gate()?;
  oden_capsec_audit_record(
    "root/runtime-control",
    "network",
    action,
    target,
    "allow(ambient)",
    None,
  );
  Ok(())
}

#[derive(Default)]
struct OdenProtectedInspectorEndpoints {
  exact: std::collections::HashMap<SocketAddr, usize>,
  pending: std::collections::HashMap<IpAddr, usize>,
}

/// Use the same effective-address spelling as ordinary network permission
/// checks. Otherwise an IPv4-mapped IPv6 connect can reach an IPv4 inspector
/// listener without matching the listener's protected endpoint registration.
// @ref LLP 0019#inspector [implements]
fn oden_normalize_inspector_endpoint(endpoint: SocketAddr) -> SocketAddr {
  let normalized_ip = normalize_ip(endpoint.ip());
  if normalized_ip == endpoint.ip() {
    endpoint
  } else {
    SocketAddr::new(normalized_ip, endpoint.port())
  }
}

fn oden_protected_inspector_endpoints()
-> &'static Mutex<OdenProtectedInspectorEndpoints> {
  static ENDPOINTS: OnceLock<Mutex<OdenProtectedInspectorEndpoints>> =
    OnceLock::new();
  ENDPOINTS.get_or_init(Default::default)
}

/// Reserve an inspector endpoint before the listener is bound. Port-zero
/// reservations temporarily protect the whole address so another worker
/// cannot win the bind-to-registration race.
pub struct OdenInspectorEndpointReservation {
  requested: Option<SocketAddr>,
}

impl OdenInspectorEndpointReservation {
  pub fn commit(mut self, actual: SocketAddr) {
    if let Some(requested) = self.requested.take() {
      let actual = oden_normalize_inspector_endpoint(actual);
      let mut endpoints = oden_protected_inspector_endpoints().lock();
      if requested.port() == 0 {
        if let Some(count) = endpoints.pending.get_mut(&requested.ip()) {
          *count -= 1;
          if *count == 0 {
            endpoints.pending.remove(&requested.ip());
          }
        }
      } else {
        if let Some(count) = endpoints.exact.get_mut(&requested) {
          *count -= 1;
          if *count == 0 {
            endpoints.exact.remove(&requested);
          }
        }
      }
      *endpoints.exact.entry(actual).or_default() += 1;
    }
  }
}

impl Drop for OdenInspectorEndpointReservation {
  fn drop(&mut self) {
    let Some(requested) = self.requested.take() else {
      return;
    };
    let mut endpoints = oden_protected_inspector_endpoints().lock();
    if requested.port() == 0 {
      if let Some(count) = endpoints.pending.get_mut(&requested.ip()) {
        *count -= 1;
        if *count == 0 {
          endpoints.pending.remove(&requested.ip());
        }
      }
    } else {
      if let Some(count) = endpoints.exact.get_mut(&requested) {
        *count -= 1;
        if *count == 0 {
          endpoints.exact.remove(&requested);
        }
      }
    }
  }
}

pub fn oden_capsec_reserve_inspector_endpoint(
  requested: SocketAddr,
) -> OdenInspectorEndpointReservation {
  if !oden_capsec_profile_is(ODEN_CAPSEC_PROFILE) {
    return OdenInspectorEndpointReservation { requested: None };
  }
  let requested = oden_normalize_inspector_endpoint(requested);
  let mut endpoints = oden_protected_inspector_endpoints().lock();
  if requested.port() == 0 {
    *endpoints.pending.entry(requested.ip()).or_default() += 1;
  } else {
    *endpoints.exact.entry(requested).or_default() += 1;
  }
  OdenInspectorEndpointReservation {
    requested: Some(requested),
  }
}

pub fn oden_capsec_unprotect_inspector_endpoint(endpoint: SocketAddr) {
  if oden_capsec_profile_is(ODEN_CAPSEC_PROFILE) {
    let endpoint = oden_normalize_inspector_endpoint(endpoint);
    let mut endpoints = oden_protected_inspector_endpoints().lock();
    if let Some(count) = endpoints.exact.get_mut(&endpoint) {
      *count -= 1;
      if *count == 0 {
        endpoints.exact.remove(&endpoint);
      }
    }
  }
}

fn oden_capsec_check_protected_inspector_endpoint(
  action: NetPermissionAction,
  ip: IpAddr,
  port: u16,
  api_name: &str,
) -> Result<(), PermissionCheckError> {
  if !oden_capsec_profile_is(ODEN_CAPSEC_PROFILE)
    || action == NetPermissionAction::Listen
  {
    return Ok(());
  }
  let protected = oden_capsec_is_protected_inspector_endpoint(ip, port);
  if protected {
    oden_capsec_check_inspector_activation(
      &format!("protected-inspector:{ip}:{port}"),
      api_name,
      false,
    )?;
  }
  Ok(())
}

fn oden_capsec_is_protected_inspector_endpoint(ip: IpAddr, port: u16) -> bool {
  let ip = normalize_ip(ip);
  let endpoints = oden_protected_inspector_endpoints().lock();
  endpoints
    .pending
    .keys()
    .any(|pending_ip| pending_ip.is_unspecified() || *pending_ip == ip)
    || endpoints.exact.keys().any(|endpoint| {
      endpoint.port() == port
        && (endpoint.ip().is_unspecified() || endpoint.ip() == ip)
    })
}

#[cfg(unix)]
fn oden_capsec_fd_is_inet_stream(
  fd: std::os::fd::RawFd,
) -> Result<bool, std::io::Error> {
  let mut socket_type: libc::c_int = 0;
  let mut option_len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
  // SAFETY: `socket_type` and `option_len` are valid getsockopt output
  // arguments and the descriptor is borrowed only for this call.
  let result = unsafe {
    libc::getsockopt(
      fd,
      libc::SOL_SOCKET,
      libc::SO_TYPE,
      (&mut socket_type as *mut libc::c_int).cast(),
      &mut option_len,
    )
  };
  if result != 0 {
    let error = std::io::Error::last_os_error();
    if error.raw_os_error() == Some(libc::ENOTSOCK) {
      return Ok(false);
    }
    return Err(error);
  }
  if option_len as usize != std::mem::size_of::<libc::c_int>()
    || socket_type != libc::SOCK_STREAM
  {
    return Ok(false);
  }

  // A local address is enough to distinguish INET from Unix/vsock stream
  // sockets. We intentionally do not match its tuple against the live
  // inspector registry: listener shutdown would declassify retained streams,
  // and endpoint reuse would falsely classify unrelated future streams.
  let mut storage = std::mem::MaybeUninit::<libc::sockaddr_storage>::zeroed();
  let mut len =
    std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
  // SAFETY: the storage and length satisfy getsockname's output contract. The
  // descriptor is borrowed only for the duration of the call.
  let result = unsafe {
    libc::getsockname(
      fd,
      storage.as_mut_ptr().cast::<libc::sockaddr>(),
      &mut len,
    )
  };
  if result != 0 {
    return Err(std::io::Error::last_os_error());
  }
  if (len as usize) < std::mem::size_of::<libc::sa_family_t>() {
    return Err(std::io::Error::new(
      std::io::ErrorKind::InvalidData,
      "kernel returned a truncated socket address",
    ));
  }
  // SAFETY: the successful syscall initialized at least the family field.
  let storage = unsafe { storage.assume_init() };
  Ok(matches!(
    storage.ss_family as libc::c_int,
    libc::AF_INET | libc::AF_INET6
  ))
}

/// Refuse raw-descriptor passage of an INET stream while capsec is armed.
///
/// This deliberately classifies the borrowed OS descriptor rather than any
/// JavaScript handle or provenance claim. There is no portable query for a
/// persistent socket identity that survives dup while distinguishing endpoint
/// reuse, so the fail-closed contract categorically closes all raw INET stream
/// passage.
/// Files, pipes, Unix sockets, UDP, and other non-INET-stream descriptors keep
/// their existing behavior.
// @ref LLP 0001#the-inherited-hole-checklist [implements] — Numeric descriptors are guessable; validate the concrete object before child/IPC passage.
// @ref LLP 0019#operation-scoped-positive-authority-provenance [implements] — Socket object passage does not transfer authority.
pub fn oden_capsec_check_raw_inet_stream_fd_transfer(
  fd: i32,
  api_name: &str,
) -> Result<(), PermissionCheckError> {
  if !oden_capsec_profile_is(ODEN_CAPSEC_PROFILE) {
    return Ok(());
  }

  #[cfg(not(unix))]
  {
    oden_capsec_readiness_gate()?;
    let target = format!("raw-fd-unsupported-platform:{fd}");
    let mut principals =
      OdenPolicy::constrained_principals(&oden_capsec_principal_set());
    if principals.is_empty() {
      principals.push(oden_capsec_principal());
    }
    for principal in principals {
      oden_capsec_audit_record(
        &principal.label(),
        "inspector",
        "activate",
        &target,
        "DENY(raw descriptor passage without native classifier)",
        None,
      );
    }
    return Err(PermissionCheckError::PermissionDenied(
      PermissionDeniedError {
        access: format!("{api_name} access to {target:?}"),
        name: "capsec",
        custom_message: Some(
          "oden capsec: numeric descriptors cannot be transferred on a platform without a native socket classifier"
            .to_string(),
        ),
        state: PermissionState::Denied,
      },
    ));
  }

  #[cfg(unix)]
  {
    oden_capsec_readiness_gate()?;
    let inet_stream = oden_capsec_fd_is_inet_stream(fd).map_err(
      |error| {
        PermissionCheckError::PermissionDenied(PermissionDeniedError {
          access: format!("{api_name} classification of raw descriptor {fd}"),
          name: "capsec",
          custom_message: Some(format!(
            "oden capsec: refusing raw descriptor passage because its native socket identity could not be classified: {error}"
          )),
          state: PermissionState::Denied,
        })
      },
    )?;
    if !inet_stream {
      return Ok(());
    }

    let target = format!("raw-inet-stream-fd:{fd}");
    let mut principals =
      OdenPolicy::constrained_principals(&oden_capsec_principal_set());
    if principals.is_empty() {
      principals.push(oden_capsec_principal());
    }
    for principal in principals {
      oden_capsec_audit_record(
        &principal.label(),
        "inspector",
        "activate",
        &target,
        "DENY(raw INET stream fd passage)",
        None,
      );
    }
    Err(PermissionCheckError::PermissionDenied(
      PermissionDeniedError {
        access: format!("{api_name} access to {target:?}"),
        name: "capsec",
        custom_message: Some(
          "oden capsec: raw INET stream sockets cannot be transferred while capability security is armed"
            .to_string(),
        ),
        state: PermissionState::Denied,
      },
    ))
  }
}

/// Recheck a protected inspector endpoint when an already-connected stream is
/// used. Connection possession, pooling, or object passage cannot delegate a
/// terminal inspector row.
pub fn oden_capsec_check_protected_inspector_stream_use(
  endpoint: SocketAddr,
  api_name: &str,
) -> Result<(), PermissionCheckError> {
  if !oden_capsec_profile_is(ODEN_CAPSEC_PROFILE) {
    return Ok(());
  }
  oden_capsec_check_inspector_activation(
    &format!("protected-inspector-stream:{endpoint}"),
    api_name,
    false,
  )
}

/// Snapshot the protected-endpoint property when a connection becomes a live
/// resource. The returned endpoint is an immutable resource tag: listener
/// shutdown cannot declassify already-buffered inspector bytes, while a later
/// unrelated connection at a reused address receives no tag.
pub fn oden_capsec_protected_inspector_stream_tag(
  endpoint: SocketAddr,
) -> Option<SocketAddr> {
  (oden_capsec_profile_is(ODEN_CAPSEC_PROFILE)
    && oden_capsec_is_protected_inspector_endpoint(
      endpoint.ip(),
      endpoint.port(),
    ))
  .then_some(endpoint)
}

/// Unforgeable native provenance retained for the lifetime of a protected
/// inspector transport. JavaScript receives only an operation that rechecks
/// this record; neither the endpoint nor the actor identity is accepted back
/// from JavaScript as authority.
// @ref LLP 0019#operation-scoped-positive-authority-provenance [implements]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ProtectedInspectorStreamActor {
  endpoint: SocketAddr,
  actor_keys: Arc<[String]>,
}

impl ProtectedInspectorStreamActor {
  pub fn endpoint(&self) -> SocketAddr {
    self.endpoint
  }
}

/// Snapshot the actor only for an endpoint that is protected at connection
/// publication time. The trusted caller invokes this immediately after the
/// successful protected-connect decision and stores the result on the native
/// resource; a later listener shutdown cannot declassify that resource.
pub fn oden_capsec_protected_inspector_stream_actor(
  endpoint: SocketAddr,
) -> Option<ProtectedInspectorStreamActor> {
  let endpoint = oden_normalize_inspector_endpoint(endpoint);
  (oden_capsec_profile_is(ODEN_CAPSEC_PROFILE)
    && oden_capsec_is_protected_inspector_endpoint(
      endpoint.ip(),
      endpoint.port(),
    ))
  .then(|| ProtectedInspectorStreamActor {
    endpoint,
    actor_keys: oden_capsec_integrity_actor_keys().into(),
  })
}

/// Recheck a protected transport for the actor bound at connect. Independent
/// inspector authority held by a different package does not authorize object
/// passage: the integrity actor set must match before the ordinary terminal
/// permission/negative check is repeated.
pub fn oden_capsec_check_protected_inspector_stream_use_for_actor(
  actor: &ProtectedInspectorStreamActor,
  api_name: &str,
) -> Result<(), PermissionCheckError> {
  if !oden_capsec_profile_is(ODEN_CAPSEC_PROFILE) {
    return Ok(());
  }
  oden_capsec_readiness_gate()?;
  let current_actor_keys = oden_capsec_integrity_actor_keys();
  if current_actor_keys.as_slice() != actor.actor_keys.as_ref() {
    let target = format!("protected-inspector-stream:{}", actor.endpoint);
    let constrained =
      OdenPolicy::constrained_principals(&oden_capsec_principal_set());
    let labels = if constrained.is_empty() {
      vec!["root/runtime".to_string()]
    } else {
      constrained
        .iter()
        .map(OdenPrincipal::label)
        .collect::<Vec<_>>()
    };
    for label in labels {
      oden_capsec_audit_record(
        &label,
        "inspector",
        "activate",
        &target,
        "DENY(protected stream actor mismatch)",
        None,
      );
    }
    return Err(PermissionCheckError::PermissionDenied(
      PermissionDeniedError {
        access: format!("{api_name} access to {target:?}"),
        name: "capsec",
        custom_message: Some(format!(
          "oden capsec: protected inspector stream actor at {:?} does not match the actor bound at connect",
          actor.endpoint
        )),
        state: PermissionState::Denied,
      },
    ));
  }
  oden_capsec_check_protected_inspector_stream_use(actor.endpoint, api_name)
}

/// JS-backed stream wrappers retain this endpoint string after the native
/// resource has delivered a chunk into a queue. Re-evaluate at the reader
/// boundary so buffered bytes, tee branches, and Response clones cannot turn
/// object passage into inspector authority.
pub fn oden_capsec_check_protected_inspector_stream_target(
  target: &str,
  api_name: &str,
) -> Result<(), PermissionCheckError> {
  let Ok(endpoint) = target.parse::<SocketAddr>() else {
    return Err(PermissionCheckError::PermissionDenied(
      PermissionDeniedError {
        access: format!("{api_name} access to invalid endpoint {target:?}"),
        name: "capsec",
        custom_message: Some(
          "oden capsec: invalid protected stream endpoint".to_string(),
        ),
        state: PermissionState::Denied,
      },
    ));
  };
  oden_capsec_check_protected_inspector_stream_use(endpoint, api_name)
}

/// Preflight a signal as one conjunctive effect set. SIGUSR1 is not merely a
/// process-control effect: it can activate the inspector, so both rows are
/// evaluated and audited before delivery. There is no current-PID exemption.
// @ref LLP 0019#system-information-and-process-mutation [implements]
pub fn oden_capsec_check_process_signal(
  pid: i32,
  signal: &str,
  inspector_trigger: bool,
  api_name: &str,
) -> Result<(), PermissionCheckError> {
  if !oden_capsec_profile_is(ODEN_CAPSEC_PROFILE) {
    return Ok(());
  }
  oden_capsec_readiness_gate()?;
  let constrained =
    OdenPolicy::constrained_principals(&oden_capsec_principal_set());
  let labels = if constrained.is_empty() {
    vec!["root/runtime".to_string()]
  } else {
    constrained
      .iter()
      .map(OdenPrincipal::label)
      .collect::<Vec<_>>()
  };
  let target_class = if pid == std::process::id() as i32 {
    "self".to_string()
  } else {
    format!("pid:{pid}")
  };
  let signal_target = format!("{target_class}:{signal}");
  let signal_allowed = constrained.is_empty();
  for label in &labels {
    oden_capsec_audit_record(
      label,
      "process",
      "signal",
      &signal_target,
      if signal_allowed {
        "allow(ambient)"
      } else {
        "DENY(deny-only surface)"
      },
      None,
    );
  }

  let inspector_allowed = if inspector_trigger {
    let req = OdenRequest {
      family: OdenFamily::Inspector,
      action: "activate".to_string(),
      target: String::new(),
    };
    constrained.is_empty()
      || constrained
        .iter()
        .all(|principal| oden_capsec_policy().static_grants(principal, &req))
  } else {
    true
  };
  if inspector_trigger {
    for label in &labels {
      oden_capsec_audit_record(
        label,
        "inspector",
        "activate",
        &format!("signal:{signal_target}"),
        if inspector_allowed {
          "allow(exact-static inspector row)"
        } else {
          "DENY(exact-static inspector row required)"
        },
        (!inspector_allowed).then_some("inspector:activate"),
      );
    }
  }

  if signal_allowed && inspector_allowed {
    return Ok(());
  }
  Err(PermissionCheckError::PermissionDenied(
    PermissionDeniedError {
      access: format!("{api_name} access to {signal_target:?}"),
      name: "capsec",
      custom_message: Some(format!(
        "oden capsec: signal delivery at {signal_target:?} failed the complete process:signal{} preflight",
        if inspector_trigger {
          " + inspector:activate"
        } else {
          ""
        }
      )),
      state: PermissionState::Denied,
    },
  ))
}

/// Apply LLP 0019's built-in metadata stratum at the concrete peer selected
/// for a connection or datagram. This is deliberately a negative-only
/// continuation: matching the exact annotation does not return success until
/// every non-ambient principal still holds the ordinary exact static floor.
/// Session revocation therefore wins in permissive and audit as well as
/// enforce, and neither a handle nor mode fallback can rescue this path.
// @ref LLP 0019#protected-metadata-endpoints [implements]
// @ref LLP 0019#decision-precedence [implements]
fn oden_capsec_check_protected_metadata(
  action: NetPermissionAction,
  ip: IpAddr,
  port: u16,
  api_name: &str,
) -> Result<(), PermissionCheckError> {
  if !oden_capsec_profile_is(ODEN_CAPSEC_PROFILE)
    || action == NetPermissionAction::Listen
    || !oden_protected::is_protected_metadata_ip(ip)
  {
    return Ok(());
  }
  oden_capsec_readiness_gate()?;
  let target = oden_protected::endpoint_scope(ip, port);
  let request = OdenRequest {
    family: OdenFamily::Network,
    action: action.as_str().to_string(),
    target: target.clone(),
  };
  let file = oden_capsec_policy_file().ok_or_else(|| {
    PermissionCheckError::PermissionDenied(PermissionDeniedError {
      access: format!("{api_name} protected metadata access to {target:?}"),
      name: "capsec",
      custom_message: Some(
        "oden capsec: protected metadata requires a valid armed policy snapshot"
          .to_string(),
      ),
      state: PermissionState::Denied,
    })
  })?;

  // Stack intersection is mandatory for protected resources, independent of
  // the compatibility deputyClasses switch. If there are no constrained
  // principals, the direct ambient/root principal remains a dimension and
  // must carry its own exact root-scoped row.
  let mut principals =
    OdenPolicy::constrained_principals(&oden_capsec_principal_set());
  if principals.is_empty() {
    principals.push(oden_capsec_principal());
  }

  for principal in principals {
    let principal_key = principal.key();
    let evidence = match file.protected_metadata_policy.check(
      &principal_key,
      action.as_str(),
      ip,
      port,
    ) {
      OdenProtectedMetadataCheck::NotProtected => return Ok(()),
      OdenProtectedMetadataCheck::Deny => {
        oden_capsec_audit_record(
          &principal.label(),
          "network",
          action.as_str(),
          &target,
          "DENY(protected metadata guard)",
          None,
        );
        return Err(oden_protected_metadata_denied(
          api_name,
          &principal.label(),
          &target,
          "no exact protected exception",
        ));
      }
      OdenProtectedMetadataCheck::Continue(evidence) => evidence,
    };

    oden_capsec_protected_metadata_continuation_record(
      &principal.label(),
      action.as_str(),
      &target,
      evidence.reason_digest,
      evidence.receipt_digest,
      file.protected_metadata_policy.receipt_set_digest(),
    );

    // Root/runtime ordinary authority is evaluated only after the exact root
    // annotation above. Every constrained principal must independently retain
    // the exact static row; Policy::grants includes session revocations.
    if !principal.is_ambient()
      && !oden_capsec_policy().grants(&principal, &request)
    {
      oden_capsec_audit_record(
        &principal.label(),
        "network",
        action.as_str(),
        &target,
        "DENY(protected static floor or session revocation)",
        None,
      );
      return Err(oden_protected_metadata_denied(
        api_name,
        &principal.label(),
        &target,
        "ordinary exact static authority is absent or revoked",
      ));
    }
  }
  Ok(())
}

fn oden_protected_metadata_denied(
  api_name: &str,
  principal: &str,
  target: &str,
  reason: &str,
) -> PermissionCheckError {
  PermissionCheckError::PermissionDenied(PermissionDeniedError {
    access: format!("{api_name} protected metadata access to {target:?}"),
    name: "capsec",
    custom_message: Some(format!(
      "oden capsec: protected metadata denied for principal {principal:?}: {reason}"
    )),
    state: PermissionState::Denied,
  })
}

fn oden_capsec_protected_metadata_continuation_record(
  principal: &str,
  action: &str,
  target: &str,
  reason_digest: &str,
  receipt_digest: Option<&str>,
  receipt_set_digest: Option<&str>,
) {
  let rec = serde_json::json!({
    "v": 1,
    "event": "protected_metadata",
    "principal": principal,
    "capability": format!("network:{action}"),
    "target": target,
    // This records only that one refusal was cleared. The following ordinary
    // decision record is the allow/deny authority result.
    "decision": "continue",
    "decider": "protected-negative-continuation",
    "protected": {
      "class": "metadata",
      "reasonDigest": reason_digest,
      "receiptDigest": receipt_digest,
      "receiptSetDigest": receipt_set_digest,
    },
  });
  oden_capsec_write_audit_record(&rec);
}

/// Structural arming (LLP 0001, ENG-23764/23772): the presence of the policy
/// artifact arms capsec — either an explicit `ODEN_CAPSEC_POLICY` handoff (the
/// seam the oden CLI uses to pass a merged policy in a temp file) or a
/// committed `<root>/.oden/policy.json`. There is no boolean arm/disarm switch:
/// the artifact is the control surface, so an environment cannot arm
/// enforcement without a policy nor silently disarm one that is present.
/// Cached once per process — arming is a process-lifetime decision (the CPED
/// seal and lockdown are bootstrap-time), so a mid-run policy appearance must
/// not half-arm a running process. Kept in sync with the copy in
/// `libs/core/error.rs` (deno_core sits below this crate and cannot call it).
pub fn oden_capsec_armed() -> bool {
  static ARMED: std::sync::LazyLock<bool> =
    std::sync::LazyLock::new(oden_capsec_armed_uncached);
  *ARMED
}

/// Exact engine semantics advertised by the current binary. Revision 1 stays
/// frozen; Stage-B safety closures ship as the explicitly attested 1.1 patch
/// profile until the generated Revision-2 plane is ready.
pub const ODEN_CAPSEC_PROFILE: &str = "oden/capsec/1.1";

/// True only for a structurally armed execution on the exact requested engine
/// profile. The profile is compile-time/attested state, never a policy or
/// environment selector an application could use to downgrade enforcement.
pub fn oden_capsec_profile_is(profile: &str) -> bool {
  profile == ODEN_CAPSEC_PROFILE && oden_capsec_armed()
}

/// Apply the Stage-B closed-scheme invariant at a URL-consuming boundary.
/// The returned class tells the caller which ordinary operation check must
/// follow. This function does not substitute a network or filesystem check;
/// it only prevents a different or unknown scheme from borrowing either.
pub fn oden_capsec_gate_url_scheme(
  scheme: &str,
  api_name: &str,
) -> Result<OdenUrlSchemeClass, PermissionCheckError> {
  oden_capsec_gate_url_scheme_inner(scheme, api_name, None)
}

/// Require a URL-consuming network facade to receive an actual network
/// scheme. The shared classifier permits file/data/runtime-internal schemes to
/// continue to their own boundaries, but Node HTTP exposes a raw socket and
/// has no such alternate boundary. A caller-controlled Agent protocol must not
/// reinterpret those classes as `network:connect`.
// @ref LLP 0019#fetch-versus-connect [implements]
pub fn oden_capsec_require_network_url_scheme(
  scheme: &str,
  api_name: &str,
) -> Result<(), PermissionCheckError> {
  let class = oden_capsec_gate_url_scheme(scheme, api_name)?;
  if !oden_capsec_profile_is("oden/capsec/1.1")
    || class == OdenUrlSchemeClass::Network
  {
    return Ok(());
  }

  oden_capsec_readiness_gate()?;
  let principal = oden_capsec_principal();
  let label = principal.label();
  let normalized = oden_capsec_normalize_url_scheme(scheme);
  oden_capsec_audit_record(
    &label,
    "protocol",
    "classify",
    &normalized,
    "DENY(non-network scheme at network surface)",
    None,
  );
  Err(PermissionCheckError::PermissionDenied(
    PermissionDeniedError {
      access: format!("{api_name} URL scheme {normalized:?}"),
      name: "capsec",
      custom_message: Some(format!(
        "oden capsec: {api_name} cannot use {normalized}: because this surface requires a network URL scheme"
      )),
      state: PermissionState::Denied,
    },
  ))
}

fn oden_capsec_gate_url_scheme_inner(
  scheme: &str,
  api_name: &str,
  explicit_principal: Option<OdenPrincipal>,
) -> Result<OdenUrlSchemeClass, PermissionCheckError> {
  let class = oden_capsec_classify_url_scheme(scheme);
  if !oden_capsec_profile_is("oden/capsec/1.1")
    || !matches!(
      class,
      OdenUrlSchemeClass::ClosedBlob | OdenUrlSchemeClass::ClosedUnknown
    )
  {
    return Ok(class);
  }

  oden_capsec_readiness_gate()?;
  let principal = explicit_principal.unwrap_or_else(oden_capsec_principal);
  let label = principal.label();
  let normalized = oden_capsec_normalize_url_scheme(scheme);
  let reason = match class {
    OdenUrlSchemeClass::ClosedBlob => {
      "blob ownership and cross-principal delegation are not modeled"
    }
    OdenUrlSchemeClass::ClosedUnknown => "the URL scheme is not modeled",
    _ => unreachable!(),
  };
  oden_capsec_audit_record(
    &label,
    "protocol",
    "classify",
    &normalized,
    &format!("DENY(closed scheme: {reason})"),
    None,
  );
  Err(PermissionCheckError::PermissionDenied(
    PermissionDeniedError {
      access: format!("{api_name} URL scheme {normalized:?}"),
      name: "capsec",
      custom_message: Some(format!(
        "oden capsec: {api_name} cannot use {normalized}: ({reason})"
      )),
      state: PermissionState::Denied,
    },
  ))
}

/// Snapshot every shipping handoff before user code starts, initialize the
/// private audit writer (consuming/unlinking its one-shot key file), consume the
/// authenticated parent's temporary policy artifact, synchronize deno_core's
/// lower-layer arming bit, and erase the paths from the inherited environment.
/// Rust-side snapshots remain authoritative for the process lifetime. Current
/// JS environment reads and ordinary child inheritance are scrubbed; OS views
/// of the initial exec environment may retain stale path strings, but the key
/// was never there and the one-shot key/policy files are absent before user code.
pub const ODEN_CAPSEC_REV2_UNARMED_EXIT_CODE: i32 = 75;

static ODEN_CAPSEC_REV2_BOOTSTRAP: OnceLock<
  Result<Arc<OdenRev2RuntimeAuthorityContext>, String>,
> = OnceLock::new();

/// The one process-wide C04 authority context. Clones retain the same sealed
/// host object; no policy bytes or independently constructible state cross the
/// permissions boundary.
pub fn oden_capsec_rev2_runtime_authority_context()
-> Option<Arc<OdenRev2RuntimeAuthorityContext>> {
  ODEN_CAPSEC_REV2_BOOTSTRAP
    .get()
    .and_then(|result| result.as_ref().ok())
    .cloned()
}

pub fn oden_capsec_rev2_bootstrap_exit_code() -> Option<i32> {
  match ODEN_CAPSEC_REV2_BOOTSTRAP.get() {
    Some(Ok(_)) | None => None,
    Some(Err(_)) => Some(ODEN_CAPSEC_REV2_UNARMED_EXIT_CODE),
  }
}

#[allow(
  clippy::disallowed_methods,
  reason = "single-threaded bootstrap snapshots and removes the private inherited handoff before V8 or worker threads start"
)]
pub fn oden_capsec_init_control_plane(
  rev2_build_identity: OdenRev2CompiledBuildIdentity,
) -> bool {
  let explicit_policy =
    std::env::var_os("ODEN_CAPSEC_POLICY").filter(|path| !path.is_empty());
  let explicit_rev2 = std::env::var_os("ODEN_CAPSEC_REV2_SNAPSHOT")
    .filter(|path| !path.is_empty());
  // Rev1 and Rev2 are explicit, disjoint bootstrap protocols. In particular,
  // never parse a Rev1 policy as a side effect of a Rev2 attempt.
  let armed = if explicit_rev2.is_some() {
    false
  } else {
    oden_capsec_armed()
  };
  let mut rev2_armed = false;
  let _ = oden_capsec_project_root();
  if let Some(snapshot) = explicit_rev2.as_deref() {
    let loaded_result = if explicit_policy.is_some() {
      // Consume/unlink any securely opened one-shot candidate even though the
      // mixed protocol is unconditionally refused. This prevents a rejected
      // handoff retaining receipt or host-binding material on disk.
      let _ = oden_capsec_consume_rev2_snapshot(snapshot, &rev2_build_identity);
      if let Some(policy) = explicit_policy.as_deref()
        && let Some(control_root) =
          oden_capsec_audit_channel().lock().control_root()
      {
        let _ = oden_capsec_consume_parent_policy(policy, &control_root);
      }
      Err("OD-CAP-REV2-MIXED-HANDOFF".to_string())
    } else {
      oden_capsec_consume_rev2_snapshot(snapshot, &rev2_build_identity)
    };
    let evidence = match &loaded_result {
      Ok(context) => context.evidence(),
      Err(reason) => serde_json::json!({
        "v": 1,
        "event": "rev2_loaded_context",
        "profile": rev2_registry_generated::REV2_PROFILE,
        "vocabDigest": rev2_registry_generated::REV2_VOCAB_DIGEST,
        "registryDigest": rev2_registry_generated::REV2_REGISTRY_DIGEST,
        "policyDigest": null,
        "projectDigest": null,
        "armedSnapshotDigest": null,
        "loadedArmedSnapshotDigest": null,
        "conformanceReportDigest": null,
        "engineTarget": null,
        "engineFeatureSet": null,
        "executionRole": null,
        "runNonce": null,
        "channelEpoch": null,
        "configured": true,
        "decisionStage": "bootstrap",
        "verified": false,
        "armable": false,
        "armed": false,
        "conformant": false,
        "advertised": false,
        "blockers": [reason],
      }),
    };
    // @ref LLP 0019#stage-c-runtime-authority-and-typed-permission-checkpoint-c04--eng-24017 [implements] -- Only an authenticated Armable C03 context can claim and construct the process-wide C04 context, before the CLI creates V8.
    let runtime_result = loaded_result.and_then(|loaded| {
      OdenRev2RuntimeAuthorityContext::install(loaded).map(Arc::new)
    });
    rev2_armed = runtime_result.is_ok();
    let _ = ODEN_CAPSEC_REV2_BOOTSTRAP.set(runtime_result);
    oden_capsec_write_audit_record(&evidence);
  } else {
    // Keep the frozen Rev1 initialization order unchanged when no Rev2
    // candidate handoff exists.
    let _ = oden_capsec_policy_file();
    let _ = oden_capsec_policy_source();
  }
  if oden_capsec_audit_channel().lock().authenticated_failure() {
    oden_capsec_fatal_audit_failure();
  }
  if explicit_rev2.is_none()
    && let Some(policy) = explicit_policy
    && let Some(control_root) =
      oden_capsec_audit_channel().lock().control_root()
    && let Err(_reason) =
      oden_capsec_consume_parent_policy(&policy, &control_root)
  {
    oden_capsec_fatal_audit_failure();
  }
  // SAFETY: the CLI calls this during single-threaded bootstrap, before V8 or
  // user workers start. These values have already been copied into Rust-owned
  // process-lifetime state above.
  unsafe {
    for name in [
      "ODEN_CAPSEC_ROOT",
      "ODEN_CAPSEC_POLICY",
      "ODEN_CAPSEC_AUDIT",
      "ODEN_CAPSEC_AUDIT_KEY",
      "ODEN_CAPSEC_REV2_SNAPSHOT",
    ] {
      std::env::remove_var(name);
    }
  }
  armed || rev2_armed
}

#[allow(
  clippy::disallowed_methods,
  reason = "single-threaded bootstrap unlinks only the authenticated parent's already-parsed one-shot policy artifact before V8"
)]
fn oden_capsec_consume_parent_policy(
  policy: &std::ffi::OsStr,
  control_root: &Path,
) -> Result<(), String> {
  let policy = Path::new(policy);
  let parent = policy
    .parent()
    .ok_or_else(|| format!("{} has no parent", policy.display()))?;
  let parent = std::fs::canonicalize(parent)
    .map_err(|error| format!("{}: {error}", parent.display()))?;
  if parent != control_root {
    return Err(format!(
      "{} is outside authenticated control directory {}",
      policy.display(),
      control_root.display()
    ));
  }
  let metadata = std::fs::symlink_metadata(policy)
    .map_err(|error| format!("{}: {error}", policy.display()))?;
  if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
    std::fs::remove_file(policy)
      .map_err(|error| format!("{}: {error}", policy.display()))?;
    return Err(format!("{} is not a regular file", policy.display()));
  }
  std::fs::remove_file(policy)
    .map_err(|error| format!("{}: {error}", policy.display()))
}

const ODEN_CAPSEC_REV2_ENVELOPE_READ_CAP: u64 = 8 * 1024 * 1024;

#[allow(
  clippy::disallowed_methods,
  reason = "single-threaded bootstrap opens, bounds, snapshots, and unlinks the authenticated parent's one-shot Rev2 envelope before V8"
)]
fn oden_capsec_consume_rev2_snapshot(
  snapshot: &std::ffi::OsStr,
  build_identity: &OdenRev2CompiledBuildIdentity,
) -> Result<OdenRev2LoadedPolicyContext, String> {
  let (control_root, key) = {
    let channel = oden_capsec_audit_channel().lock();
    let control_root = channel
      .control_root()
      .ok_or_else(|| "OD-CAP-REV2-AUTH-CHANNEL".to_string())?;
    let key = channel
      .rev2_authentication_key()
      .ok_or_else(|| "OD-CAP-REV2-AUTH-KEY".to_string())?;
    (control_root, key)
  };
  let snapshot = Path::new(snapshot);
  let parent = snapshot
    .parent()
    .ok_or_else(|| "OD-CAP-REV2-SNAPSHOT-PARENT".to_string())?;
  let parent = std::fs::canonicalize(parent)
    .map_err(|_| "OD-CAP-REV2-SNAPSHOT-PARENT".to_string())?;
  if parent != control_root {
    return Err("OD-CAP-REV2-SNAPSHOT-CONTROL-ROOT".to_string());
  }
  let symlink_metadata = std::fs::symlink_metadata(snapshot)
    .map_err(|_| "OD-CAP-REV2-SNAPSHOT-MISSING".to_string())?;
  if !symlink_metadata.file_type().is_file()
    || symlink_metadata.file_type().is_symlink()
  {
    std::fs::remove_file(snapshot)
      .map_err(|_| "OD-CAP-REV2-SNAPSHOT-UNLINK".to_string())?;
    return Err("OD-CAP-REV2-SNAPSHOT-FILE-TYPE".to_string());
  }

  let mut options = std::fs::OpenOptions::new();
  options.read(true);
  #[cfg(unix)]
  {
    use std::os::unix::fs::OpenOptionsExt;
    options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
  }
  let file = match options.open(snapshot) {
    Ok(file) => file,
    Err(_) => {
      std::fs::remove_file(snapshot)
        .map_err(|_| "OD-CAP-REV2-SNAPSHOT-UNLINK".to_string())?;
      return Err("OD-CAP-REV2-SNAPSHOT-OPEN".to_string());
    }
  };
  let metadata = match file.metadata() {
    Ok(metadata) => metadata,
    Err(_) => {
      std::fs::remove_file(snapshot)
        .map_err(|_| "OD-CAP-REV2-SNAPSHOT-UNLINK".to_string())?;
      return Err("OD-CAP-REV2-SNAPSHOT-METADATA".to_string());
    }
  };
  let opened_identity = if !metadata.is_file() {
    Err("OD-CAP-REV2-SNAPSHOT-BOUNDS".to_string())
  } else {
    #[cfg(unix)]
    {
      use std::os::unix::fs::MetadataExt;
      if symlink_metadata.dev() != metadata.dev()
        || symlink_metadata.ino() != metadata.ino()
      {
        Err("OD-CAP-REV2-SNAPSHOT-IDENTITY".to_string())
      } else {
        Ok(())
      }
    }
    #[cfg(not(unix))]
    {
      Err("OD-CAP-REV2-SNAPSHOT-PLATFORM".to_string())
    }
  };
  // The authenticated control directory is parent-owned and private. Unlink
  // immediately after the no-follow open and identity comparison, so every
  // subsequent bounds/read/parse/authentication failure still consumes the
  // one-shot pathname while this retained descriptor supplies the exact bytes.
  std::fs::remove_file(snapshot)
    .map_err(|_| "OD-CAP-REV2-SNAPSHOT-UNLINK".to_string())?;
  opened_identity?;
  if metadata.len() > ODEN_CAPSEC_REV2_ENVELOPE_READ_CAP {
    return Err("OD-CAP-REV2-SNAPSHOT-BOUNDS".to_string());
  }
  let capacity = usize::try_from(metadata.len())
    .map_err(|_| "OD-CAP-REV2-SNAPSHOT-BOUNDS".to_string())?;
  let mut bytes = Vec::with_capacity(capacity);
  file
    .take(ODEN_CAPSEC_REV2_ENVELOPE_READ_CAP + 1)
    .read_to_end(&mut bytes)
    .map_err(|_| "OD-CAP-REV2-SNAPSHOT-READ".to_string())?;
  if bytes.len() > ODEN_CAPSEC_REV2_ENVELOPE_READ_CAP as usize {
    return Err("OD-CAP-REV2-SNAPSHOT-BOUNDS".to_string());
  }
  let mut context = oden_rev2_policy::verify_authenticated_envelope(
    &bytes,
    &key,
    build_identity,
  )?;
  if context.state() == OdenRev2LoadState::Armable {
    // @ref LLP 0019#c04-immutable-execution-installation-and-entry [implements] -- C04 converts the exact C03-retained descriptors into immutable native execution images before V8; failure keeps the candidate unarmed.
    context.install_immutable_executables(&control_root)?;
  }
  Ok(context)
}

#[allow(
  clippy::disallowed_methods,
  reason = "structural arming probes the policy artifact (explicit ODEN_CAPSEC_POLICY handoff or <root>/.oden/policy.json); read once and cached."
)]
fn oden_capsec_armed_uncached() -> bool {
  if std::env::var_os("ODEN_CAPSEC_POLICY").is_some_and(|v| !v.is_empty()) {
    return true;
  }
  let root = oden_capsec_project_root();
  if root.is_empty() {
    return false;
  }
  oden_policy_path_present(
    &std::path::Path::new(&root)
      .join(".oden")
      .join("policy.json"),
  )
}

#[allow(
  clippy::disallowed_methods,
  reason = "distinguishes an absent policy path from a present dangling symlink or uninspectable directory entry"
)]
fn oden_policy_path_present(path: &std::path::Path) -> bool {
  match std::fs::symlink_metadata(path) {
    Ok(_) => true,
    Err(err) => err.kind() != std::io::ErrorKind::NotFound,
  }
}

fn oden_capsec_active() -> bool {
  oden_capsec_armed()
}

pub fn oden_capsec_is_control_env_name(name: &str) -> bool {
  EnvVarNameRef::new(Cow::Borrowed(name))
    .as_ref()
    .starts_with("ODEN_CAPSEC_")
}

fn oden_capsec_is_control_request(req: &OdenRequest, aggregate: bool) -> bool {
  matches!(req.family, OdenFamily::Env)
    && oden_capsec_is_control_env_name(&req.target)
    || matches!(req.family, OdenFamily::Fs)
      && (aggregate && oden_capsec_has_control_root()
        || oden_capsec_is_control_path(&req.target))
}

fn oden_capsec_reject_control_specifier(
  specifier: &Url,
) -> Result<(), PermissionCheckError> {
  if !oden_capsec_active() || specifier.scheme() != "file" {
    return Ok(());
  }
  let Ok(path) = url_to_file_path(specifier) else {
    return Ok(());
  };
  let req = OdenRequest {
    family: OdenFamily::Fs,
    action: "read".to_string(),
    target: oden_normalize_fs_target(&path.to_string_lossy()),
  };
  if !oden_capsec_is_control_request(&req, false) {
    return Ok(());
  }
  let principal = oden_capsec_principal();
  let label = principal.label();
  oden_capsec_audit_record(
    &label,
    req.family.name(),
    &req.action,
    &req.target,
    "DENY(control plane import)",
    None,
  );
  Err(PermissionCheckError::PermissionDenied(
    PermissionDeniedError {
      access: format!("capsec control-plane import from {:?}", req.target),
      name: "capsec",
      custom_message: Some(
        "oden capsec: the engine policy and audit channel are not importable package authority"
          .to_string(),
      ),
      state: PermissionState::Denied,
    },
  ))
}

// Always-on seal conformance (LLP 0001 ENG-23775). The bootstrap runs the four
// seal conditions on every armed startup and reports the result here; a broken
// seal flips this to false so readiness reports `seal_applied = false` and
// enforce fails closed. Starts true (assume sound until a run reports otherwise).
static ODEN_SEAL_CONFORMANCE_OK: std::sync::atomic::AtomicBool =
  std::sync::atomic::AtomicBool::new(true);

/// Called by the bootstrap op once per armed startup with the seal self-test's
/// verdict. A single failure latches the flag closed for the process.
pub fn oden_capsec_report_seal(ok: bool) {
  if !ok {
    ODEN_SEAL_CONFORMANCE_OK.store(false, std::sync::atomic::Ordering::Relaxed);
  }
}

fn oden_capsec_seal_conformance_ok() -> bool {
  ODEN_SEAL_CONFORMANCE_OK.load(std::sync::atomic::Ordering::Relaxed)
}

// The acting principal's label for out-of-process consumers (the permission
// broker), so a brokered decision can key on the package, not just the process.
// None when capsec is inactive — the broker wire format is then unchanged.
// @ref llp/0001-adding-capability-security-to-deno.plan.md (Broker protocol)
pub(crate) fn oden_capsec_current_principal_label() -> Option<String> {
  if !oden_capsec_active() {
    return None;
  }
  Some(oden_capsec_principal().label())
}

/// The closed known fields of a `Deno.PermissionDescriptor`. Revision 1 ops
/// validate with the stock query parser before using this view. An installed
/// Revision 2 context instead selects a generated exact-field branch and uses
/// the stock parser only for spelling/path syntax, never for an authority
/// decision or wildcard fallback.
/// @ref llp/0015-dynamic-permissions-with-ceiling.plan.md (Deno.permissions.request)
pub struct OdenDynamicPermissionDescriptor<'a> {
  pub name: &'a str,
  pub path: Option<&'a str>,
  pub host: Option<&'a str>,
  pub variable: Option<&'a str>,
  pub kind: Option<&'a str>,
  pub command: Option<&'a str>,
}

pub fn oden_capsec_query_dynamic_permission(
  desc: &OdenDynamicPermissionDescriptor,
) -> Option<PermissionState> {
  if !oden_capsec_active() {
    return None;
  }
  let principal = oden_capsec_principal();
  if principal.is_ambient() {
    return None;
  }
  let req = oden_dynamic_request(desc);
  let control_request = req
    .as_ref()
    .is_some_and(|req| oden_capsec_is_dynamic_control_request(desc, req));
  let query = if oden_policy_invalid() || control_request {
    OdenDynamicQueryState::Denied
  } else {
    oden_capsec_policy().query_dynamic(&principal, req.as_ref())
  };
  let state = match query {
    OdenDynamicQueryState::Ambient => return None,
    OdenDynamicQueryState::Granted => PermissionState::Granted,
    OdenDynamicQueryState::Prompt => PermissionState::Prompt,
    OdenDynamicQueryState::Denied => PermissionState::Denied,
  };
  oden_capsec_dynamic_query_audit_record(
    "query",
    &principal,
    req.as_ref(),
    state,
  );
  Some(state)
}

pub fn oden_capsec_request_dynamic_permission(
  desc: &OdenDynamicPermissionDescriptor,
) -> Option<PermissionState> {
  if !oden_capsec_active() {
    return None;
  }
  let principal = oden_capsec_principal();
  if principal.is_ambient() {
    return None;
  }
  let req = oden_dynamic_request(desc);
  let policy = oden_capsec_policy();
  let control_request = req
    .as_ref()
    .is_some_and(|req| oden_capsec_is_dynamic_control_request(desc, req));
  let result = if control_request {
    OdenDynamicRequestResult {
      state: OdenDynamicPermissionState::Denied,
      code: OdenDynamicRequestCode::DenyCeiling,
      decider: None,
      session_grant: None,
      ceiling: None,
      memoized: false,
    }
  } else if oden_policy_invalid() {
    OdenDynamicRequestResult {
      state: OdenDynamicPermissionState::Denied,
      code: OdenDynamicRequestCode::Ambiguous,
      decider: None,
      session_grant: None,
      ceiling: None,
      memoized: false,
    }
  } else {
    match policy.evaluate_dynamic_request(&principal, req.as_ref()) {
      OdenDynamicRequestEvaluation::Ambient => return None,
      OdenDynamicRequestEvaluation::Terminal(result) => result,
      OdenDynamicRequestEvaluation::NeedsDecision { ceiling } => {
        let req = req
          .as_ref()
          .expect("a decider is requested only for a canonical request");
        let capability = OdenGrant::from_request(req).to_string_canonical();
        let ceiling_label = ceiling.to_string_canonical();
        let principal_label = principal.label();
        if let Some(response) = maybe_check_dynamic_with_broker(
          desc.name,
          &req.target,
          &principal_label,
          &capability,
          &ceiling_label,
        ) {
          policy.complete_dynamic_request(
            &principal,
            req,
            ceiling,
            OdenDynamicDecider::Broker,
            matches!(response, BrokerResponse::Allow),
          )
        } else if prompter::permission_prompt_available() {
          let message = format!(
            "package {principal_label} requests {capability} within its declared escalation ceiling {ceiling_label} for this run"
          );
          let allowed = matches!(
            permission_prompt(
              &message,
              "capsec",
              Some("Deno.permissions.request"),
              false,
            ),
            PromptResponse::Allow | PromptResponse::AllowAll
          );
          policy.complete_dynamic_request(
            &principal,
            req,
            ceiling,
            OdenDynamicDecider::Interactive,
            allowed,
          )
        } else {
          policy.unanswered_dynamic_request(&principal, req, ceiling)
        }
      }
    }
  };
  oden_capsec_dynamic_request_audit_record(
    "request",
    &principal,
    req.as_ref(),
    &result,
  );
  Some(match result.state {
    OdenDynamicPermissionState::Granted => PermissionState::Granted,
    OdenDynamicPermissionState::Denied => PermissionState::Denied,
  })
}

pub fn oden_capsec_revoke_dynamic_permission(
  desc: &OdenDynamicPermissionDescriptor,
) -> Option<PermissionState> {
  if !oden_capsec_active() {
    return None;
  }
  let principal = oden_capsec_principal();
  if principal.is_ambient() {
    return None;
  }
  let Some(req) = oden_dynamic_request(desc) else {
    oden_capsec_dynamic_query_audit_record(
      "revoke",
      &principal,
      None,
      PermissionState::Denied,
    );
    return Some(PermissionState::Denied);
  };
  let state = if oden_capsec_is_dynamic_control_request(desc, &req) {
    PermissionState::Denied
  } else {
    match oden_capsec_policy().revoke_dynamic(&principal, &req) {
      OdenDynamicQueryState::Ambient => return None,
      OdenDynamicQueryState::Granted => PermissionState::Granted,
      OdenDynamicQueryState::Prompt => PermissionState::Prompt,
      OdenDynamicQueryState::Denied => PermissionState::Denied,
    }
  };
  oden_capsec_dynamic_query_audit_record(
    "revoke",
    &principal,
    Some(&req),
    state,
  );
  Some(state)
}

fn oden_dynamic_request(
  desc: &OdenDynamicPermissionDescriptor,
) -> Option<OdenRequest> {
  let (family, action, target) = match desc.name {
    "read" => (OdenFamily::Fs, "read", oden_dynamic_path_target(desc.path)),
    "write" => (OdenFamily::Fs, "write", oden_dynamic_path_target(desc.path)),
    // Deno's net/env descriptors each combine action classes. The wildcard
    // action makes that breadth explicit in the layer-2 session grant.
    "net" => (
      OdenFamily::Network,
      "*",
      desc.host.unwrap_or("*").to_string(),
    ),
    "env" => (
      OdenFamily::Env,
      "*",
      EnvVarNameRef::new(Cow::Borrowed(desc.variable.unwrap_or("*")))
        .as_ref()
        .to_string(),
    ),
    "sys" => (
      OdenFamily::Sys,
      "read",
      desc.kind.unwrap_or("*").to_string(),
    ),
    "run" => (
      OdenFamily::Run,
      "run",
      desc.command.unwrap_or("*").to_string(),
    ),
    "ffi" => (
      OdenFamily::Ffi,
      "load",
      desc.path.unwrap_or("*").to_string(),
    ),
    // Import admission is a separate policy axis, not a host capability.
    "import" => return None,
    _ => return None,
  };
  Some(OdenRequest {
    family,
    action: action.to_string(),
    target,
  })
}

fn oden_dynamic_descriptor_is_aggregate(
  desc: &OdenDynamicPermissionDescriptor,
) -> bool {
  match desc.name {
    "read" | "write" | "ffi" => desc.path.is_none(),
    "env" => desc.variable.is_none(),
    "net" => desc.host.is_none(),
    "sys" => desc.kind.is_none(),
    "run" => desc.command.is_none(),
    _ => false,
  }
}

fn oden_capsec_is_dynamic_control_request(
  desc: &OdenDynamicPermissionDescriptor,
  req: &OdenRequest,
) -> bool {
  if oden_capsec_is_control_request(
    req,
    oden_dynamic_descriptor_is_aggregate(desc),
  ) {
    return true;
  }
  if desc.name != "env" {
    return false;
  }
  let Some(pattern) = desc.variable.and_then(|value| value.strip_suffix('*'))
  else {
    return false;
  };
  let normalized = EnvVarNameRef::new(Cow::Borrowed(pattern));
  let prefix = normalized.as_ref();
  "ODEN_CAPSEC_".starts_with(prefix) || prefix.starts_with("ODEN_CAPSEC_")
}

fn oden_dynamic_path_target(path: Option<&str>) -> String {
  match path {
    Some(path) => oden_normalize_fs_target(path),
    None => "*".to_string(),
  }
}

// The grant token a denied/would-deny principal would need, in the same
// vocabulary `.oden/policy.json` and `oden_policy::Grant::parse` speak — so a
// denial suggests its own fix and the audit synthesizer can lift it verbatim.
// Ambient/no-user principals get no suggestion (nothing to grant).
fn oden_suggested_grant_token(
  principal: &OdenPrincipal,
  family: OdenFamily,
  action: &str,
  target: &str,
) -> Option<String> {
  if principal.is_ambient() || matches!(principal, OdenPrincipal::NoUser) {
    return None;
  }
  let token = match family {
    OdenFamily::Ffi => "ffi".to_string(),
    OdenFamily::Run => format!("run:{target}"),
    OdenFamily::Env => format!("env:{action}:{target}"),
    OdenFamily::Fs => format!("fs:{action}:{target}"),
    OdenFamily::Network => {
      format!("network:{action}:{}", oden_host_of(target))
    }
    OdenFamily::Sys => format!("sys:{target}"),
    OdenFamily::Inspector => "inspector:activate".to_string(),
  };
  Some(token)
}

// Host/endpoint of a net target for a suggestion scope. URL and ordinary
// host:port targets collapse to their host, while authority-bearing endpoint
// forms remain whole so `unix:/path` and `vsock:cid:port` grants are usable.
fn oden_host_of(target: &str) -> String {
  if target.starts_with("unix:") || target.starts_with("vsock:") {
    return target.to_string();
  }
  let t = target
    .strip_prefix("https://")
    .or_else(|| target.strip_prefix("http://"))
    .unwrap_or(target);
  let t = t.split('/').next().unwrap_or(t);
  if let Some(bracketed) = t.strip_prefix('[')
    && let Some(end) = bracketed.find(']')
  {
    return format!("[{}]", &bracketed[..end]);
  }
  if t.matches(':').count() == 1 {
    return t.split(':').next().unwrap_or(t).to_string();
  }
  t.to_string()
}

// --- Readiness report + fail-closed honesty (LLP 0001 Phase 2) --------------
// "The mode name is the guarantee." Under audit/enforce the runtime reports its
// exact posture, every degraded configuration is named, and enforce fails
// closed when a load-bearing prerequisite is missing unless the operator
// explicitly accepts the degraded state with ODEN_CAPSEC_ALLOW_ADVISORY.
// @ref llp/0001-adding-capability-security-to-deno.plan.md (Mode honesty and readiness)
struct OdenReadiness {
  mode: OdenMode,
  attribution_armed: bool,
  seal_applied: bool,
  lockdown_on: bool,
  lockdown_posture: OdenLockdownPosture,
  compartment_globals_requested: bool,
  compartment_globals_on: bool,
  integrity: &'static oden_principal_index::LockState,
  policy_source: Option<String>,
  project_root: String,
}

impl OdenReadiness {
  // A prerequisite that is load-bearing for a *sound* enforce decision. Lockdown
  // is reported and named-as-degraded but not in this set: it is genuinely not
  // implemented yet, so requiring it would make every enforce run refuse — the
  // dishonest direction. Attribution + the CPED seal are what make the decision
  // itself trustworthy, so those are required under enforce.
  fn missing_required(&self) -> Vec<&'static str> {
    let mut missing = Vec::new();
    if !self.attribution_armed {
      missing.push("attribution capture (op-dispatch frame capture)");
    }
    if !self.seal_applied {
      missing.push("Deno.core / CPED seal");
    }
    if oden_policy_unreadable() {
      missing.push("valid capsec policy artifact");
    }
    missing
  }

  fn degraded_states(&self) -> Vec<String> {
    let mut degraded = Vec::new();
    if self.mode == OdenMode::Enforce && !self.lockdown_on {
      // Under the Phase-3 posture enforce defaults lockdown on, so this state
      // is only reachable through the explicit ODEN_CAPSEC_LOCKDOWN=0
      // override — named honestly rather than refused (LLP 0001 Phase 3).
      degraded.push(
        "enforce without lockdown (explicit override) — intrinsics unfrozen (integrity gap)"
          .to_string(),
      );
    }
    if self.compartment_globals_requested && !self.compartment_globals_on {
      if self.mode != OdenMode::Enforce {
        degraded.push(
          "compartment globals requested outside enforce — disabled (enforce-gated)"
            .to_string(),
        );
      } else if !self.lockdown_on {
        degraded.push(
          "compartment globals requested without lockdown — disabled (dynamic channels remain porous)"
            .to_string(),
        );
      }
    }
    if let Some(reason) = oden_policy_unreadable_reason() {
      degraded.push(format!(
        "policy artifact rejected — fail-closed enforce with zero grants: {reason}"
      ));
    }
    // Integrity binding of the loader principal index (ENG-23763). No lockfile
    // means package locators stay path-derived — the forged-version residual is
    // open for this run, which enforce must name. An unreadable lockfile is
    // already fail-closed (package principals quarantine), named for honesty.
    if self.mode == OdenMode::Enforce && self.integrity.is_absent() {
      degraded.push(
        "no deno.lock — package locators are path-derived, not integrity-bound"
          .to_string(),
      );
    }
    if self.integrity.is_unreadable() {
      degraded.push(
        "deno.lock present but unreadable — package principals fail closed to quarantine"
          .to_string(),
      );
    }
    degraded
  }

  fn render(&self) -> String {
    let mode = match self.mode {
      OdenMode::Permissive => "permissive",
      OdenMode::Audit => "audit",
      OdenMode::Enforce => "enforce",
    };
    let mut out = String::new();
    out.push_str("[oden-capsec] readiness report\n");
    out.push_str(&format!("  mode: {mode}\n"));
    out.push_str(&format!(
      "  attribution: {}\n",
      if self.attribution_armed {
        "armed"
      } else {
        "OFF"
      }
    ));
    out.push_str(&format!(
      "  cped-seal: {}\n",
      if self.seal_applied {
        "applied"
      } else {
        "NOT applied"
      }
    ));
    // State the lockdown posture AND its provenance: "the mode name is the
    // guarantee" means saying which default (or override) produced the bit.
    // Audit/permissive default-off is the measured compat-corpus NO-GO
    // decision (ENG-23880); enforce default-on is the Phase-2 security
    // prerequisite restored by the ENG-23781 compat repairs.
    // @ref llp/0001-adding-capability-security-to-deno.plan.md (Mode honesty and readiness)
    out.push_str(&format!(
      "  lockdown: {}\n",
      match (self.lockdown_on, self.lockdown_posture) {
        (true, OdenLockdownPosture::DefaultOnEnforce) => {
          "on (default under enforce)"
        }
        (true, _) => "on (explicit opt-in)",
        (false, OdenLockdownPosture::ExplicitOff) => {
          "off (explicit override)"
        }
        (false, _) => {
          "off (opt-in outside enforce; default-on measured NO-GO by the compat corpus)"
        }
      }
    ));
    // Compartment globals remains explicitly opt-in and enforce+lockdown gated.
    // The existing 32-package corpus does not authorize a default-on claim:
    // lockdown still breaks 4/32 after the runtime repairs, and the full
    // tooling-inclusive compartment corpus has not cleared the LLP 0014 bar.
    // @ref LLP 0014#kill-criteria [constrained-by]
    out.push_str(&format!(
      "  compartment-globals: {}\n",
      if self.compartment_globals_on {
        "on (explicit opt-in; enforce + lockdown gated)"
      } else {
        "off (opt-in only; default-on blocked by the compat-corpus gate)"
      }
    ));
    out.push_str(&format!(
      "  integrity: {}\n",
      self.integrity.readiness_label()
    ));
    out.push_str(&format!(
      "  policy-source: {}\n",
      self.policy_source.as_deref().unwrap_or("(none)")
    ));
    out.push_str(&format!("  root: {}\n", self.project_root));
    for d in self.degraded_states() {
      out.push_str(&format!("  DEGRADED: {d}\n"));
    }
    out
  }
}

#[allow(
  clippy::disallowed_methods,
  reason = "Phase-2 readiness probes whether the policy file exists on disk; a resolver replaces the raw fs read later."
)]
fn oden_capsec_policy_source() -> Option<String> {
  static POLICY_SOURCE: std::sync::LazyLock<Option<String>> =
    std::sync::LazyLock::new(|| {
      if let Some(policy) =
        std::env::var_os("ODEN_CAPSEC_POLICY").filter(|v| !v.is_empty())
      {
        if oden_capsec_parent_key_handoff_present() {
          Some("engine-handoff".to_string())
        } else {
          Some(
            std::path::PathBuf::from(policy)
              .to_string_lossy()
              .into_owned(),
          )
        }
      } else {
        let policy_path = std::path::Path::new(oden_capsec_project_root())
          .join(".oden")
          .join("policy.json");
        if oden_policy_path_present(&policy_path) {
          Some(policy_path.to_string_lossy().into_owned())
        } else {
          None
        }
      }
    });
  POLICY_SOURCE.clone()
}

#[allow(
  clippy::disallowed_methods,
  reason = "bootstrap distinguishes the authenticated parent's one-shot key file from direct explicit-policy usage before the audit channel consumes it"
)]
fn oden_capsec_parent_key_handoff_present() -> bool {
  let Some(audit) =
    std::env::var_os("ODEN_CAPSEC_AUDIT").filter(|path| !path.is_empty())
  else {
    return false;
  };
  let Some(control_root) = Path::new(&audit).parent() else {
    return false;
  };
  std::fs::symlink_metadata(control_root.join("audit.key")).is_ok_and(
    |metadata| {
      metadata.file_type().is_file()
        && !metadata.file_type().is_symlink()
        && metadata.len() == 32
    },
  )
}

fn oden_capsec_readiness() -> OdenReadiness {
  let root = oden_capsec_project_root();
  let file = oden_capsec_policy_file();
  // Arm-time fact (which artifact armed this process); snapshot to keep the
  // per-decide readiness gate off the filesystem (an exists() probe per
  // mediated op otherwise). Live state (seal conformance, forced-unarmed)
  // stays live below.
  let policy_source = oden_capsec_policy_source();
  OdenReadiness {
    mode: oden_capsec_mode(file),
    // Attribution is armed whenever capsec is active (they share the arm), but a
    // forced-degradation hook lets the honesty machinery be exercised.
    attribution_armed: oden_capsec_active()
      && !oden_capsec_env_flag("ODEN_CAPSEC_FORCE_UNARMED"),
    // The seal is applied when armed, not force-disabled, AND the always-on
    // conformance the bootstrap ran actually passed (a real broken seal, not
    // just the forced hook, flips this).
    seal_applied: oden_capsec_active()
      && !oden_capsec_env_flag("ODEN_CAPSEC_FORCE_UNSEALED")
      && oden_capsec_seal_conformance_ok(),
    lockdown_on: oden_capsec_lockdown_on(),
    lockdown_posture: oden_capsec_lockdown_posture(),
    compartment_globals_requested: oden_capsec_compartment_globals_requested(),
    compartment_globals_on: oden_capsec_compartment_globals_on(),
    integrity: oden_principal_index::lock_state(),
    policy_source,
    project_root: root.to_string(),
  }
}

#[allow(
  clippy::disallowed_methods,
  reason = "capsec readiness hooks are env-driven; the spike's control surface."
)]
fn oden_capsec_env_flag(name: &str) -> bool {
  std::env::var_os(name).is_some()
}

/// The lockdown posture (LLP 0001 Phase 3, ENG-23781): where the minimal
/// lockdown decision (freeze walk + Error taming, `odenHardenIntrinsics` in
/// `runtime/js/99_main.js`) came from, so the readiness report can state the
/// posture and its provenance, not just the bit.
///
/// Per-mode defaults, and why:
/// - **Enforce defaults lockdown ON** ("enforce implies lockdown"): enforce is
///   itself opt-in, so its compat price is paid knowingly, and enforcement
///   over unfrozen intrinsics has a known integrity gap (a patched shared
///   prototype runs attacker code under a victim's frames). The Phase-2 kill
///   criterion that had softened this to opt-in (`buildAllowedFlags` writing
///   `Symbol.iterator` over a frozen `Set.prototype`) is repaired by the
///   ENG-23781 ext/node lazy-write audit, so the design default is restored.
///   `ODEN_CAPSEC_LOCKDOWN=0` is the honestly-labeled override: readiness
///   names the degraded state.
/// - **Audit/permissive default lockdown OFF (opt-in)**: the Phase-1 compat
///   corpus run (ENG-23880, `fork/phase1-compat-corpus-report.md`) measured
///   default-on as a NO-GO — 100% breakage pre-repair, and a ~19% post-repair
///   floor (express/axios/dayjs/form-data) from the SES "override mistake"
///   (shadowing assignments over frozen Object/Function/Error prototypes),
///   which the ENG-23781 shims deliberately do NOT paper over. Default-on in
///   these modes stays gated on an override-mistake policy decision plus a
///   re-run corpus measuring ~0% breakage.
///
/// @ref llp/0001-adding-capability-security-to-deno.plan.md (Compartments and lockdown)
#[derive(Clone, Copy, PartialEq, Eq)]
enum OdenLockdownPosture {
  /// Enforce mode, no override: on by default.
  DefaultOnEnforce,
  /// Explicitly enabled via ODEN_CAPSEC_LOCKDOWN (audit/permissive opt-in).
  ExplicitOn,
  /// Audit/permissive, no opt-in: off by default (compat corpus NO-GO).
  DefaultOffOptIn,
  /// Explicitly disabled via ODEN_CAPSEC_LOCKDOWN=0|false|off — under
  /// enforce this is the named "enforce without lockdown" degraded state.
  ExplicitOff,
}

impl OdenLockdownPosture {
  fn is_on(self) -> bool {
    matches!(self, Self::DefaultOnEnforce | Self::ExplicitOn)
  }
}

// The posture is a process-lifetime, bootstrap-time decision (the freeze walk
// runs once at the end of bootstrap), so it snapshots like the arming probe.
#[allow(
  clippy::disallowed_methods,
  reason = "the lockdown override is env-driven by design (the non-authority control surface); the default is the policy artifact's mode."
)]
fn oden_capsec_lockdown_posture() -> OdenLockdownPosture {
  static POSTURE: std::sync::LazyLock<OdenLockdownPosture> =
    std::sync::LazyLock::new(|| {
      match std::env::var_os("ODEN_CAPSEC_LOCKDOWN") {
        // Same non-empty rule as the arming probe: an empty value is unset.
        Some(v) if !v.is_empty() => {
          let v = v.to_string_lossy().to_ascii_lowercase();
          if v == "0" || v == "false" || v == "off" {
            OdenLockdownPosture::ExplicitOff
          } else {
            OdenLockdownPosture::ExplicitOn
          }
        }
        _ => {
          if oden_capsec_mode(oden_capsec_policy_file()) == OdenMode::Enforce {
            OdenLockdownPosture::DefaultOnEnforce
          } else {
            OdenLockdownPosture::DefaultOffOptIn
          }
        }
      }
    });
  *POSTURE
}

/// Whether minimal lockdown (the intrinsic freeze walk + Error-constructor
/// taming) is active — the same decision `op_oden_capsec_flags` compiles for
/// the bootstrap JS in `runtime/ops/bootstrap.rs`. Only meaningful while
/// capsec is armed (lockdown stays inert without the policy artifact).
pub fn oden_capsec_lockdown_on() -> bool {
  oden_capsec_armed() && oden_capsec_lockdown_posture().is_on()
}

/// Whether the operator explicitly requested the Phase-3 reachability layer.
/// `0|false|off` are explicit off spellings; an empty value is unset.
#[allow(
  clippy::disallowed_methods,
  reason = "compartment globals is an explicit non-authority posture toggle, analogous to lockdown"
)]
fn oden_capsec_compartment_globals_requested() -> bool {
  static REQUESTED: std::sync::LazyLock<bool> =
    std::sync::LazyLock::new(|| {
      match std::env::var_os("ODEN_CAPSEC_COMPARTMENT_GLOBALS") {
        Some(v) if !v.is_empty() => !matches!(
          v.to_string_lossy().to_ascii_lowercase().as_str(),
          "0" | "false" | "off"
        ),
        _ => false,
      }
    });
  *REQUESTED
}

/// The shipped posture is deliberately narrower than the LLP 0014 aspiration:
/// explicit opt-in, enforce only, and only while lockdown is active. This keeps
/// the documented kill signal intact; current corpus evidence does not permit
/// a default-on claim.
// @ref LLP 0014#kill-criteria [constrained-by]
pub fn oden_capsec_compartment_globals_on() -> bool {
  oden_capsec_armed()
    && oden_capsec_compartment_globals_requested()
    && oden_capsec_mode(oden_capsec_policy_file()) == OdenMode::Enforce
    && oden_capsec_lockdown_on()
}

/// Stable endowment fingerprint for the loader's emit/V8 cache keys. The
/// locator resolves through the same integrity-bound principal index used by
/// op attribution; there is no second compartment identity system.
// @ref LLP 0014#at-which-loader-stage [implements]
pub fn oden_capsec_compartment_globals_fingerprint(
  locator: &str,
) -> Option<u64> {
  if !oden_capsec_compartment_globals_on()
    || locator.starts_with("ext:")
    || locator.starts_with("node:")
    || locator.starts_with("deno:")
  {
    return None;
  }
  let principal = oden_principal_index::resolve_locator(locator);
  let names = oden_capsec_policy().endowments(&principal);
  let mut hasher = std::collections::hash_map::DefaultHasher::new();
  oden_capsec_compartment_key(&principal, Some(locator)).hash(&mut hasher);
  for name in names {
    name.hash(&mut hasher);
  }
  Some(hasher.finish())
}

/// Snapshot descriptor consumed by trusted bootstrap JS to create/cache the
/// caller's filtered global record. The op resolving this function carries the
/// live module frame, so a package cannot request another principal's record.
// @ref LLP 0014#endowment-record-derivation-from-grants [implements]
pub fn oden_capsec_compartment_endowments()
-> Result<String, PermissionCheckError> {
  if !oden_capsec_compartment_globals_on() {
    return Err(PermissionCheckError::PermissionDenied(
      PermissionDeniedError {
        access: "compartment globals".to_string(),
        name: "capsec",
        custom_message: Some(
          "oden capsec: compartment globals is not active (requires explicit opt-in under enforce with lockdown)"
            .to_string(),
        ),
        state: PermissionState::Denied,
      },
    ));
  }
  oden_capsec_readiness_gate()?;
  let (principal, locator) = oden_capsec_principal_with_locator();
  let names = oden_capsec_policy()
    .endowments(&principal)
    .into_iter()
    .collect::<Vec<_>>()
    .join(",");
  Ok(format!(
    "{}\0{names}",
    oden_capsec_compartment_key(&principal, locator.as_deref())
  ))
}

/// A compartment is keyed by the integrity-bound principal *and* the exact
/// loader locator that produced it. The latter is required when a project has
/// no lockfile (and therefore no trustworthy package version claim), and also
/// prevents two physical package instances from aliasing one filtered-global
/// proxy merely because their human-readable policy selector is the same.
fn oden_capsec_compartment_key(
  principal: &OdenPrincipal,
  locator: Option<&str>,
) -> String {
  let Some(locator) = locator else {
    return principal.key();
  };
  let mut hasher = std::collections::hash_map::DefaultHasher::new();
  locator.hash(&mut hasher);
  oden_principal_index::integrity_of(locator).hash(&mut hasher);
  format!("{}#locator:{:016x}", principal.key(), hasher.finish())
}

// Emit the readiness report once, and enforce fail-closed honesty. Returns Err
// if enforce is requested with a missing required prerequisite and the operator
// has not accepted the degraded state via ODEN_CAPSEC_ALLOW_ADVISORY. Called at
// the top of every decision so the first mediated op reports posture and a
// dishonest enforce refuses before it can pretend to be sound.
fn oden_capsec_readiness_gate() -> Result<(), PermissionCheckError> {
  if oden_policy_invalid() {
    return Err(PermissionCheckError::PermissionDenied(
      PermissionDeniedError {
        access: "capsec policy".to_string(),
        name: "capsec",
        custom_message: Some(
          "oden capsec: policy authority envelope is invalid (static floor exceeds escalation ceiling)"
            .to_string(),
        ),
        state: PermissionState::Denied,
      },
    ));
  }
  static EMITTED: AtomicFlag = AtomicFlag::lowered();
  let readiness = oden_capsec_readiness();
  let first = EMITTED.raise();
  // The full report is gated on ODEN_CAPSEC_READINESS while capsec is itself
  // env-gated. It is consumed through engine-owned state/audit paths;
  // application stderr remains byte-faithful runtime content. The fail-closed
  // refusal below is unconditional.
  if first && oden_capsec_env_flag("ODEN_CAPSEC_READINESS") {
    let _ = readiness.render();
  }
  let missing = readiness.missing_required();
  if readiness.mode == OdenMode::Enforce && !missing.is_empty() {
    let advisory = oden_capsec_env_flag("ODEN_CAPSEC_ALLOW_ADVISORY");
    if !advisory {
      let policy_reason = oden_policy_unreadable_reason()
        .map(|reason| format!(" Policy error: {reason}."))
        .unwrap_or_default();
      return Err(PermissionCheckError::PermissionDenied(
        PermissionDeniedError {
          access: "capsec enforce".to_string(),
          name: "capsec",
          custom_message: Some(format!(
            "oden capsec: enforce refuses to run — missing {}. \
             Pass ODEN_CAPSEC_ALLOW_ADVISORY to accept the named degraded state.{policy_reason}",
            missing.join(", "),
          )),
          state: PermissionState::Denied,
        },
      ));
    }
  }
  Ok(())
}

// Per-package audit log. The shipping parent supplies a 256-bit key exactly
// once at bootstrap through a 0600 one-shot file, never argv/environment. The
// engine reads/unlinks the key, pre-opens the audit file, removes path env
// variables before JS starts, and writes a sequence + previous-MAC chain. The
// CLI adds a keyed terminal frame only after every worker has finished, and
// writer bytes are hard-bounded. A package may still find/rename/truncate the
// pathname through spawned OS authority after the key handoff is erased, but
// cannot repair the chain or terminal sequence; the parent rejects the whole
// stream. In-process FFI/NAPI is explicitly compartment-terminating and can
// read native memory, including the key, so it ends this guarantee. Direct fork
// fixtures without a key keep the legacy raw-NDJSON sink for development
// compatibility only.
// @ref LLP 0004#the-event-stream [implements]
// @ref LLP 0015#audit-records [implements]
fn oden_capsec_audit_record(
  principal: &str,
  family: &str,
  action: &str,
  target: &str,
  verdict: &str,
  suggestion: Option<&str>,
) {
  let decision = match verdict {
    v if v.starts_with("allow(ambient") => "allow-ambient",
    v if v.starts_with("allow(granted") => "allow-granted",
    // Generic allow verdicts (handle mint/scoped/transfer/use/revoke,
    // resource transfer) map to a plain allow so a handle audit record is not
    // misclassified as a deny by the prefix table above.
    v if v.starts_with("allow") => "allow",
    v if v.starts_with("audit") => "audit-record",
    _ => "deny",
  };
  // The grant suggestion makes the log the input to audit-as-conversation: a
  // would-deny/deny row carries the exact `{selector: grant}` that would allow
  // it, so `audit_synth.ts` can synthesize a starting policy from a real run.
  let rec = serde_json::json!({
    "v": 1,
    "principal": principal,
    "capability": format!("{family}:{action}"),
    "target": target,
    "decision": decision,
    "suggestion": suggestion,
  });
  oden_capsec_write_audit_record(&rec);
}

#[allow(
  clippy::disallowed_methods,
  reason = "the capsec audit sink path is supplied through the bootstrap environment and opened append-only"
)]
fn oden_capsec_write_audit_record(rec: &serde_json::Value) {
  let failed = match serde_json::to_vec(rec) {
    Ok(payload) => !oden_capsec_audit_channel().lock().write_record(&payload),
    Err(_) => oden_capsec_audit_channel().lock().authenticated_failure(),
  };
  if failed {
    // Evidence loss is process-fatal even when package code catches the
    // permission error or the call path historically ignored audit failures.
    // @ref LLP 0004#the-event-stream [constrained-by] — authenticated child evidence must never become a partial clean stream
    oden_capsec_fatal_audit_failure();
  }
}

/// Reserved process status for an authenticated audit-completeness failure.
/// This is an engine/tool failure, never the target program's requested code.
pub const ODEN_CAPSEC_AUDIT_FAILURE_EXIT_CODE: i32 = 74;

static ODEN_CAPSEC_AUDIT_FAILURE_LATCH: std::sync::atomic::AtomicBool =
  std::sync::atomic::AtomicBool::new(false);

pub fn oden_capsec_audit_failure_latched() -> bool {
  ODEN_CAPSEC_AUDIT_FAILURE_LATCH.load(std::sync::atomic::Ordering::SeqCst)
}

#[cold]
#[allow(
  clippy::disallowed_methods,
  reason = "authenticated evidence loss is a process-wide security failure that JavaScript must not catch or override"
)]
fn oden_capsec_fatal_audit_failure() -> ! {
  let first = !ODEN_CAPSEC_AUDIT_FAILURE_LATCH
    .swap(true, std::sync::atomic::Ordering::SeqCst);
  if first {
    let _ = std::io::stderr().write_all(
      b"oden capsec: fatal audit evidence failure (OD-CAP-AUDIT-INCOMPLETE); exiting with engine status 74\n",
    );
  }
  std::process::exit(ODEN_CAPSEC_AUDIT_FAILURE_EXIT_CODE)
}

const ODEN_AUDIT_DOMAIN: &[u8] = b"oden-capsec-audit-v1\0";
const ODEN_AUDIT_WRITE_CAP: usize = 1024 * 1024;
const ODEN_AUDIT_WORKER_DRAIN_TIMEOUT: std::time::Duration =
  std::time::Duration::from_secs(10);

struct OdenAuthenticatedAudit {
  file: std::fs::File,
  key: Vec<u8>,
  sequence: u64,
  previous: [u8; 32],
  terminal: bool,
  failed: bool,
  bytes_written: usize,
  control_root: PathBuf,
}

enum OdenAuditChannel {
  Disabled,
  Legacy(std::fs::File),
  Authenticated(OdenAuthenticatedAudit),
  Broken { authenticated: bool },
}

#[derive(Debug)]
enum OdenAuditKeyHandoff {
  Absent,
  Loaded(Vec<u8>),
  Broken,
}

#[cfg(unix)]
fn oden_audit_key_same_identity(
  expected: &std::fs::Metadata,
  actual: &std::fs::Metadata,
) -> bool {
  use std::os::unix::fs::MetadataExt;

  expected.dev() == actual.dev() && expected.ino() == actual.ino()
}

#[cfg(not(unix))]
fn oden_audit_key_same_identity(
  _expected: &std::fs::Metadata,
  _actual: &std::fs::Metadata,
) -> bool {
  true
}

// @ref LLP 0019#authenticated-verification-only-bootstrap-and-evidence [implements] -- The audit key is a one-shot authenticated handoff: inspect, no-follow open, identity-match, unlink, and read only from the retained descriptor.
#[allow(
  clippy::disallowed_methods,
  reason = "single-threaded bootstrap securely opens and consumes the parent-created one-shot audit key before V8"
)]
fn oden_capsec_consume_audit_key(path: &Path) -> OdenAuditKeyHandoff {
  let expected = match std::fs::symlink_metadata(path) {
    Ok(metadata) => metadata,
    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
      return OdenAuditKeyHandoff::Absent;
    }
    Err(_) => return OdenAuditKeyHandoff::Broken,
  };
  // Reject non-regular objects before open so a FIFO/device can never make
  // bootstrap block or read external bytes. Consume the presented directory
  // entry without following it; removing a symlink never touches its target.
  if !expected.file_type().is_file() || expected.file_type().is_symlink() {
    let _ = std::fs::remove_file(path);
    return OdenAuditKeyHandoff::Broken;
  }

  let mut options = std::fs::OpenOptions::new();
  options.read(true);
  #[cfg(unix)]
  {
    use std::os::unix::fs::OpenOptionsExt;
    options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
  }
  let mut file = match options.open(path) {
    Ok(file) => file,
    Err(_) => {
      let _ = std::fs::remove_file(path);
      return OdenAuditKeyHandoff::Broken;
    }
  };
  let opened = match file.metadata() {
    Ok(metadata) => metadata,
    Err(_) => {
      let _ = std::fs::remove_file(path);
      return OdenAuditKeyHandoff::Broken;
    }
  };
  if !opened.is_file() || !oden_audit_key_same_identity(&expected, &opened) {
    let _ = std::fs::remove_file(path);
    return OdenAuditKeyHandoff::Broken;
  }

  // Reinspect the directory entry immediately before unlink. This refuses a
  // deterministic pre/open or post-open replacement rather than consuming a
  // path that no longer names the retained descriptor.
  let current = match std::fs::symlink_metadata(path) {
    Ok(metadata) => metadata,
    Err(_) => return OdenAuditKeyHandoff::Broken,
  };
  if !current.file_type().is_file()
    || current.file_type().is_symlink()
    || !oden_audit_key_same_identity(&opened, &current)
  {
    let _ = std::fs::remove_file(path);
    return OdenAuditKeyHandoff::Broken;
  }
  if std::fs::remove_file(path).is_err() {
    return OdenAuditKeyHandoff::Broken;
  }

  // Once the exact opened pathname is consumed, every later size/read/EOF
  // failure remains an authenticated broken handoff. Bytes always come from
  // the retained descriptor, never from a second pathname lookup.
  if opened.len() != 32 {
    return OdenAuditKeyHandoff::Broken;
  }
  let mut key = vec![0; 32];
  if file.read_exact(&mut key).is_err() {
    return OdenAuditKeyHandoff::Broken;
  }
  let mut trailing = [0; 1];
  match file.read(&mut trailing) {
    Ok(0) => OdenAuditKeyHandoff::Loaded(key),
    _ => OdenAuditKeyHandoff::Broken,
  }
}

impl OdenAuditChannel {
  #[allow(
    clippy::disallowed_methods,
    reason = "single-threaded bootstrap must open and retain the parent-created audit descriptor before erasing its private environment handoff"
  )]
  fn from_env() -> Self {
    let Some(path) = std::env::var_os("ODEN_CAPSEC_AUDIT") else {
      return Self::Disabled;
    };
    let path = PathBuf::from(path);
    let Some(control_root) = path.parent() else {
      return Self::Broken {
        authenticated: false,
      };
    };
    let key_path = control_root.join("audit.key");
    let key = match oden_capsec_consume_audit_key(&key_path) {
      OdenAuditKeyHandoff::Absent => None,
      OdenAuditKeyHandoff::Loaded(key) => Some(key),
      OdenAuditKeyHandoff::Broken => {
        return Self::Broken {
          authenticated: true,
        };
      }
    };
    let mut options = std::fs::OpenOptions::new();
    options.append(true);
    if key.is_none() {
      options.create(true);
    }
    let Ok(file) = options.open(&path) else {
      return Self::Broken {
        authenticated: key.is_some(),
      };
    };
    let Some(key) = key else {
      return Self::Legacy(file);
    };
    let Ok(control_root) = std::fs::canonicalize(control_root) else {
      return Self::Broken {
        authenticated: true,
      };
    };
    let Ok(metadata) = file.metadata() else {
      return Self::Broken {
        authenticated: true,
      };
    };
    if !metadata.is_file() || metadata.len() != 0 {
      return Self::Broken {
        authenticated: true,
      };
    }
    Self::Authenticated(OdenAuthenticatedAudit {
      file,
      key,
      sequence: 0,
      previous: [0; 32],
      terminal: false,
      failed: false,
      bytes_written: 0,
      control_root,
    })
  }

  /// Write one row, returning false only when an authenticated handoff can no
  /// longer produce complete evidence. Legacy audit compatibility remains
  /// best-effort and never acquires authenticated-channel semantics.
  fn write_record(&mut self, payload: &[u8]) -> bool {
    match self {
      Self::Legacy(file) => {
        let _ = file.write_all(payload).and_then(|_| file.write_all(b"\n"));
        true
      }
      Self::Authenticated(channel) => channel.write_frame("record", payload),
      Self::Disabled
      | Self::Broken {
        authenticated: false,
      } => true,
      Self::Broken {
        authenticated: true,
      } => false,
    }
  }

  fn finish(&mut self) -> bool {
    if let Self::Authenticated(channel) = self
      && !channel.terminal
    {
      channel.terminal = channel.write_frame("terminal", &[]);
      if channel.terminal && channel.file.sync_all().is_err() {
        channel.failed = true;
      }
    }
    match self {
      Self::Authenticated(channel) => channel.terminal && !channel.failed,
      Self::Broken {
        authenticated: true,
      } => false,
      Self::Disabled
      | Self::Legacy(_)
      | Self::Broken {
        authenticated: false,
      } => true,
    }
  }

  fn fail(&mut self) -> bool {
    if let Self::Authenticated(channel) = self {
      channel.failed = true;
    }
    !self.authenticated_failure()
  }

  fn authenticated_failure(&self) -> bool {
    match self {
      Self::Authenticated(channel) => channel.failed,
      Self::Broken { authenticated } => *authenticated,
      Self::Disabled | Self::Legacy(_) => false,
    }
  }

  fn control_root(&self) -> Option<PathBuf> {
    match self {
      Self::Authenticated(channel) => Some(channel.control_root.clone()),
      Self::Disabled | Self::Legacy(_) | Self::Broken { .. } => None,
    }
  }

  fn rev2_authentication_key(&self) -> Option<Vec<u8>> {
    match self {
      Self::Authenticated(channel) if !channel.failed && !channel.terminal => {
        Some(channel.key.clone())
      }
      Self::Disabled
      | Self::Legacy(_)
      | Self::Authenticated(_)
      | Self::Broken { .. } => None,
    }
  }
}

impl OdenAuthenticatedAudit {
  fn write_frame(&mut self, kind: &str, payload: &[u8]) -> bool {
    if self.failed || self.terminal || self.sequence == u64::MAX {
      self.failed = true;
      return false;
    }
    let sequence = self.sequence + 1;
    let Ok(mut mac) = <Hmac<Sha256> as Mac>::new_from_slice(&self.key) else {
      self.failed = true;
      return false;
    };
    mac.update(ODEN_AUDIT_DOMAIN);
    mac.update(kind.as_bytes());
    mac.update(&[0]);
    mac.update(&sequence.to_be_bytes());
    mac.update(&self.previous);
    mac.update(payload);
    let digest: [u8; 32] = mac.finalize().into_bytes().into();
    let frame = serde_json::json!({
      "v": 1,
      "kind": kind,
      "seq": sequence,
      "prev": faster_hex::hex_string(&self.previous),
      "payload": BASE64_STANDARD.encode(payload),
      "mac": faster_hex::hex_string(&digest),
    });
    let Ok(encoded) = serde_json::to_vec(&frame) else {
      self.failed = true;
      return false;
    };
    let Some(next_size) = self
      .bytes_written
      .checked_add(encoded.len())
      .and_then(|size| size.checked_add(1))
    else {
      self.failed = true;
      return false;
    };
    if next_size > ODEN_AUDIT_WRITE_CAP
      || self
        .file
        .write_all(&encoded)
        .and_then(|_| self.file.write_all(b"\n"))
        .is_err()
    {
      self.failed = true;
      return false;
    }
    self.sequence = sequence;
    self.previous = digest;
    self.bytes_written = next_size;
    true
  }
}

fn oden_capsec_audit_channel() -> &'static Mutex<OdenAuditChannel> {
  static CHANNEL: OnceLock<Mutex<OdenAuditChannel>> = OnceLock::new();
  CHANNEL.get_or_init(|| Mutex::new(OdenAuditChannel::from_env()))
}

#[allow(
  clippy::disallowed_methods,
  reason = "the layer-2 control-plane reservation must resolve symlink and platform aliases independently of Deno's layer-1 path denial"
)]
fn oden_capsec_is_control_path(target: &str) -> bool {
  let root = oden_capsec_audit_channel().lock().control_root();
  root.is_some_and(|root| oden_path_resolves_within(Path::new(target), &root))
}

fn oden_capsec_has_control_root() -> bool {
  oden_capsec_audit_channel().lock().control_root().is_some()
}

#[allow(
  clippy::disallowed_methods,
  reason = "security boundary resolves the deepest existing ancestor to catch symlink and platform path aliases"
)]
fn oden_path_resolves_within(target: &Path, root: &Path) -> bool {
  if target.starts_with(root) {
    return true;
  }
  // Resolve the deepest existing ancestor, then put any non-existent suffix
  // back. This catches both an alias of the control directory itself and a
  // symlink leading to a not-yet-created target inside it.
  let mut ancestor = Some(target);
  while let Some(path) = ancestor {
    if let Ok(resolved) = std::fs::canonicalize(path) {
      let suffix = target.strip_prefix(path).unwrap_or(Path::new(""));
      return resolved.join(suffix).starts_with(root);
    }
    ancestor = path.parent();
  }
  false
}

struct OdenCapsecWorkerTracker {
  active: Mutex<usize>,
  drained: Condvar,
}

impl OdenCapsecWorkerTracker {
  fn new() -> Self {
    Self {
      active: Mutex::new(0),
      drained: Condvar::new(),
    }
  }

  fn started(&self) {
    let mut active = self.active.lock();
    *active = active
      .checked_add(1)
      .expect("oden capsec worker count overflow");
  }

  fn finished(&self) {
    let mut active = self.active.lock();
    *active = active
      .checked_sub(1)
      .expect("oden capsec worker guard dropped without registration");
    if *active == 0 {
      self.drained.notify_all();
    }
  }

  fn wait_until_drained(&self, timeout: std::time::Duration) -> bool {
    let deadline = std::time::Instant::now() + timeout;
    let mut active = self.active.lock();
    while *active != 0 {
      let Some(remaining) =
        deadline.checked_duration_since(std::time::Instant::now())
      else {
        return false;
      };
      if self.drained.wait_for(&mut active, remaining).timed_out()
        && *active != 0
      {
        return false;
      }
    }
    true
  }
}

fn oden_capsec_worker_tracker() -> &'static OdenCapsecWorkerTracker {
  static TRACKER: OnceLock<OdenCapsecWorkerTracker> = OnceLock::new();
  TRACKER.get_or_init(OdenCapsecWorkerTracker::new)
}

/// Process-lifetime guard for a web/Node worker thread. Registration happens
/// before its isolate is built; drop happens only after the worker runtime and
/// isolate are gone, so the authenticated terminal cannot race either worker
/// permission records or nested-worker creation.
pub struct OdenCapsecWorkerGuard {
  tracked: bool,
}

impl Drop for OdenCapsecWorkerGuard {
  fn drop(&mut self) {
    if self.tracked {
      oden_capsec_worker_tracker().finished();
    }
  }
}

pub fn oden_capsec_worker_guard() -> OdenCapsecWorkerGuard {
  let tracked = oden_capsec_armed();
  if tracked {
    oden_capsec_worker_tracker().started();
  }
  OdenCapsecWorkerGuard { tracked }
}

/// Write the authenticated terminal frame after the CLI has joined every
/// worker. Missing this marker (panic, signal, kill, write failure) is itself a
/// parent-visible tool failure, never a clean capability verdict.
pub fn oden_capsec_finish_audit_channel() {
  if !oden_capsec_finish_audit_channel_with(
    oden_capsec_worker_tracker(),
    oden_capsec_audit_channel(),
    ODEN_AUDIT_WORKER_DRAIN_TIMEOUT,
  ) {
    oden_capsec_fatal_audit_failure();
  }
}

fn oden_capsec_finish_audit_channel_with(
  tracker: &OdenCapsecWorkerTracker,
  channel: &Mutex<OdenAuditChannel>,
  timeout: std::time::Duration,
) -> bool {
  if tracker.wait_until_drained(timeout) {
    channel.lock().finish()
  } else {
    // No terminal means the parent rejects the entire run. Never certify a
    // prefix while a detached worker may still append a security decision.
    channel.lock().fail()
  }
}

// Structured runtime-request evidence. Grant and deny are symmetric inputs to
// LLP 0008's review loop; every attempt is appended even when the disposition
// was memoized, while the `memoized` bit lets renderers collapse prompt storms.
// @ref llp/0015-dynamic-permissions-with-ceiling.plan.md (Audit records)
fn oden_capsec_dynamic_request_audit_record(
  operation: &str,
  principal: &OdenPrincipal,
  req: Option<&OdenRequest>,
  result: &OdenDynamicRequestResult,
) {
  let principal_label = principal.label();
  let capability = req
    .map(OdenGrant::from_request)
    .map(|g| g.to_string_canonical());
  let target = req.map(|r| r.target.as_str()).unwrap_or("");
  let session_grant = result
    .session_grant
    .as_ref()
    .map(OdenGrant::to_string_canonical);
  let ceiling = result.ceiling.as_ref().map(OdenGrant::to_string_canonical);
  let decider = result.decider.map(OdenDynamicDecider::as_str);
  let principal_set = oden_capsec_principal_set()
    .iter()
    .map(OdenPrincipal::label)
    .collect::<Vec<_>>();
  let suggestion = match result.code {
    OdenDynamicRequestCode::Granted => session_grant.clone(),
    OdenDynamicRequestCode::AboveCeiling
    | OdenDynamicRequestCode::Unanswered
    | OdenDynamicRequestCode::Refused => capability.clone(),
    _ => None,
  };
  let rec = serde_json::json!({
    "v": 1,
    "event": "dynamic_request",
    "operation": operation,
    "principal": principal_label,
    "principalSet": principal_set,
    "capability": capability,
    "target": target,
    "decision": match result.state {
      OdenDynamicPermissionState::Granted => "granted",
      OdenDynamicPermissionState::Denied => "denied",
    },
    "code": result.code.as_str(),
    "decider": decider,
    "sessionGrant": session_grant,
    "ceiling": ceiling,
    "memoized": result.memoized,
    "suggestion": suggestion,
  });
  oden_capsec_write_audit_record(&rec);
}

fn oden_capsec_dynamic_query_audit_record(
  operation: &str,
  principal: &OdenPrincipal,
  req: Option<&OdenRequest>,
  state: PermissionState,
) {
  let capability = req
    .map(OdenGrant::from_request)
    .map(|g| g.to_string_canonical());
  let rec = serde_json::json!({
    "v": 1,
    "event": "dynamic_permission",
    "operation": operation,
    "principal": principal.label(),
    "capability": capability,
    "target": req.map(|r| r.target.as_str()).unwrap_or(""),
    "decision": match state {
      PermissionState::Granted | PermissionState::GrantedPartial => "granted",
      PermissionState::Prompt => "prompt",
      PermissionState::Ignored | PermissionState::DeniedPartial | PermissionState::Denied => "denied",
    },
    "code": if operation == "revoke" { "OD-CAP-REQ-REVOKED" } else { "OD-CAP-REQ-QUERY" },
  });
  oden_capsec_write_audit_record(&rec);
}

// --- Resource ownership (LLP 0001 Native resource ownership, ENG-23776) ------
// ResourceIds are table-local small integers: two workers can both own rid 3.
// Owner metadata therefore travels with the concrete resource rather than in a
// process-global rid map. Dropping the resource drops its metadata; lookup,
// use, and sanctioned transfer must first resolve the resource from the current
// OpState's table and then consult this Rust-only token.
// @ref llp/0001-adding-capability-security-to-deno.plan.md
pub struct OdenResourceOwner {
  owner: Mutex<Option<String>>,
}

impl OdenResourceOwner {
  /// Capture the acting package for a resource about to be inserted into the
  /// current OpState's resource table. Ambient and unarmed resources remain
  /// unowned; a package cannot use an unowned owner-checked resource by merely
  /// guessing its table-local rid.
  pub fn capture() -> Self {
    let owner = if oden_capsec_active() {
      let principal = oden_capsec_principal();
      (!principal.is_ambient() && !matches!(principal, OdenPrincipal::NoUser))
        .then(|| principal.label())
    } else {
      None
    };
    Self {
      owner: Mutex::new(owner),
    }
  }

  /// Audit an owner stamp after the resource table has assigned its local rid.
  pub fn record_open(&self, rid: u32, family: &str) {
    if !oden_capsec_active() {
      return;
    }
    let Some(label) = self.owner.lock().clone() else {
      return;
    };
    oden_capsec_audit_record(
      &label,
      family,
      "own",
      &rid.to_string(),
      "allow(owner)",
      None,
    );
  }

  /// Check use of the concrete resource that owns this token. The caller must
  /// obtain the token from the current OpState's resource-table object, never
  /// by looking up the numeric rid in process-global state.
  pub fn check(
    &self,
    rid: u32,
    family: &str,
  ) -> Result<(), PermissionCheckError> {
    if !oden_capsec_active() {
      return Ok(());
    }
    let principal = oden_capsec_principal();
    if principal.is_ambient() {
      return Ok(());
    }
    let label = principal.label();
    let owner = self.owner.lock().clone();
    let owner_label = owner.as_deref().unwrap_or("(untracked)");
    let mode = oden_capsec_mode(oden_capsec_policy_file());
    let decision = oden_resource_use_decision(&label, owner.as_deref(), mode);
    if matches!(decision, OdenDecision::Allow)
      && owner.as_deref() == Some(label.as_str())
    {
      return Ok(());
    }
    let verdict = match decision {
      OdenDecision::Deny => "DENY(cross-principal rid)",
      _ => "audit(record)",
    };
    if !matches!(decision, OdenDecision::Allow) {
      oden_capsec_audit_record(
        &label,
        family,
        "use",
        &rid.to_string(),
        verdict,
        None,
      );
    }
    if matches!(decision, OdenDecision::Deny) {
      return Err(oden_resource_owner_error(&label, owner_label, rid, family));
    }
    Ok(())
  }

  /// Check a resource-identity invariant that cannot degrade with policy mode.
  /// Trusted cleanup may release only the current actor's resource; audit and
  /// permissive mode are not authority to clean up another principal's child.
  /// Ambient root may clean up its deliberately unowned resources, while
  /// missing and quarantine attribution always fail closed.
  // @ref LLP 0019#operation-scoped-positive-authority-provenance [implements] — Async cleanup reauthenticates the original resource owner.
  pub fn check_deny_only(
    &self,
    rid: u32,
    family: &str,
  ) -> Result<(), PermissionCheckError> {
    if !oden_capsec_active() {
      return Ok(());
    }
    oden_capsec_readiness_gate()?;
    let principal = oden_capsec_principal();
    let label = principal.label();
    let owner = self.owner.lock().clone();
    let mode = oden_capsec_mode(oden_capsec_policy_file());
    if matches!(
      oden_deny_only_resource_use_decision(&principal, owner.as_deref(), mode),
      OdenDecision::Allow
    ) {
      return Ok(());
    }

    let owner_label = owner.as_deref().unwrap_or("(untracked)");
    oden_capsec_audit_record(
      &label,
      family,
      "cleanup",
      &rid.to_string(),
      "DENY(cleanup owner mismatch)",
      None,
    );
    Err(oden_resource_owner_error(&label, owner_label, rid, family))
  }

  fn transfer_for(
    &self,
    caller: &str,
    to_selector: &str,
    mode: OdenMode,
  ) -> (OdenDecision, Option<String>) {
    let mut owner = self.owner.lock();
    let decision = oden_resource_use_decision(caller, owner.as_deref(), mode);
    let from = owner.clone();
    if !matches!(decision, OdenDecision::Deny) {
      *owner = Some(to_selector.to_string());
    }
    (decision, from)
  }

  #[cfg(test)]
  fn for_test(owner: Option<&str>) -> Self {
    Self {
      owner: Mutex::new(owner.map(str::to_string)),
    }
  }

  #[cfg(test)]
  fn owner_for_test(&self) -> Option<String> {
    self.owner.lock().clone()
  }
}

fn oden_deny_only_resource_use_decision(
  principal: &OdenPrincipal,
  owner: Option<&str>,
  _mode: OdenMode,
) -> OdenDecision {
  let label = principal.label();
  let same_owner = owner == Some(label.as_str());
  let attributable =
    !matches!(principal, OdenPrincipal::NoUser | OdenPrincipal::Quarantine);
  if principal.is_ambient() && owner.is_none() || attributable && same_owner {
    OdenDecision::Allow
  } else {
    OdenDecision::Deny
  }
}

// Pure decision core, unit-testable without the op-dispatch stack: given the
// acting principal's label, the rid's recorded owner (if any), and the mode,
// decide whether a resource use is allowed. An untracked rid is not proof of
// authority: small integer ids are guessable, so package use fails closed.
fn oden_resource_use_decision(
  caller: &str,
  owner: Option<&str>,
  mode: OdenMode,
) -> OdenDecision {
  match owner {
    None => match mode {
      OdenMode::Enforce => OdenDecision::Deny,
      OdenMode::Audit => OdenDecision::AllowRecord,
      OdenMode::Permissive => OdenDecision::Allow,
    },
    Some(o) if o == caller => OdenDecision::Allow,
    Some(_) => match mode {
      OdenMode::Enforce => OdenDecision::Deny,
      OdenMode::Audit => OdenDecision::AllowRecord,
      OdenMode::Permissive => OdenDecision::Allow,
    },
  }
}

fn oden_resource_owner_error(
  label: &str,
  owner_label: &str,
  rid: u32,
  family: &str,
) -> PermissionCheckError {
  PermissionCheckError::PermissionDenied(PermissionDeniedError {
    access: format!("use of {family} resource {rid}"),
    name: "capsec",
    custom_message: Some(format!(
      "oden capsec: principal \"{label}\" may not use {family} resource {rid} \
       owned by \"{owner_label}\" (cross-principal rid)"
    )),
    state: PermissionState::Denied,
  })
}

/// The minimal transfer primitive: re-own the concrete resource token to
/// `to_selector` for a sanctioned cross-package handoff. Callers must retrieve
/// `owner` from the current resource-table object before invoking this helper.
/// A package may transfer only what it owns; ambient root/runtime may transfer
/// an unowned resource deliberately. After transfer the prior owner may not use
/// the resource.
pub fn oden_capsec_transfer_resource(
  owner: &OdenResourceOwner,
  rid: u32,
  family: &str,
  to_selector: &str,
) -> Result<(), PermissionCheckError> {
  if !oden_capsec_active() {
    return Ok(());
  }
  let principal = oden_capsec_principal();
  let caller = principal.label();
  let mode = oden_capsec_mode(oden_capsec_policy_file());
  let (decision, from) = if principal.is_ambient() {
    let mut current = owner.owner.lock();
    let from = current.clone();
    *current = Some(to_selector.to_string());
    (OdenDecision::Allow, from)
  } else {
    owner.transfer_for(&caller, to_selector, mode)
  };
  let from_label = from.as_deref().unwrap_or("(untracked)");
  if matches!(decision, OdenDecision::Deny) {
    return Err(oden_resource_owner_error(&caller, from_label, rid, family));
  }
  oden_capsec_audit_record(
    to_selector,
    family,
    "transfer",
    &rid.to_string(),
    &format!("allow(transfer from {from_label})"),
    None,
  );
  Ok(())
}

// --- Authority-flow handles / attenuators (LLP 0001 §Delegation and handles,
// ENG-23784) ------------------------------------------------------------------
// The general form of the minimal transfer primitive above: a package
// attenuates a capability it HOLDS into an unforgeable handle and hands the
// narrower one across a package boundary. Mint is frame-checked (the minter
// must hold the authority now); use is possession-checked (holding the handle
// is the authority — no stack walk); `scoped()` only narrows; revocation
// cascades; ids are unguessable. The host-side table + use window live in
// `oden_handle`; this is the glue that resolves the acting principal, consults
// the policy for the frame-check, and writes the mint/transfer/use/deny/revoke
// audit records. All inert unless capsec is armed.
// @ref llp/0001-adding-capability-security-to-deno.plan.md

// Encode/decode the unguessable 128-bit id as fixed-width hex for the JS
// carrier. The carrier holds this string under a bootstrap-private Symbol, so
// user code cannot read or forge it; a guessed/forged string decodes to an id
// the table does not know (fail closed).
fn oden_handle_id_hex(id: u128) -> String {
  format!("{id:032x}")
}

fn oden_handle_parse_id(hex: &str) -> Option<u128> {
  u128::from_str_radix(hex.trim(), 16).ok()
}

// Parse a capability string (`fs:read:./x`, `env:read:SECRET`,
// `network:fetch:example.com`, `ffi`) into the policy Grant it names, the
// Request form used for coverage checks, and a canonical string for audit. Fs
// scopes are resolved to absolute (root/$HOME relative) exactly as policy-file
// grants are, so a handle scope matches the absolute path an op requests.
fn oden_handle_parse_capability(
  cap_str: &str,
) -> Option<(OdenGrant, OdenRequest, String)> {
  let root = oden_capsec_project_root();
  let resolved = oden_resolve_grant_scopes(cap_str.trim(), root);
  let grant = OdenGrant::parse(&resolved).ok()?;
  let req = OdenRequest {
    family: grant.family,
    action: grant.action.clone(),
    target: grant.scope.clone(),
  };
  let canonical =
    format!("{}:{}:{}", grant.family.name(), grant.action, grant.scope);
  Some((grant, req, canonical))
}

fn oden_handle_denied(
  label: &str,
  action: &str,
  cap: &str,
  reason: &str,
) -> PermissionCheckError {
  oden_capsec_audit_record(
    label,
    "handle",
    action,
    cap,
    &format!("DENY({reason})"),
    None,
  );
  PermissionCheckError::PermissionDenied(PermissionDeniedError {
    access: format!("handle {action} for {cap:?}"),
    name: "capsec",
    custom_message: Some(format!(
      "oden capsec: principal \"{label}\" cannot {action} handle {cap} ({reason})"
    )),
    state: PermissionState::Denied,
  })
}

/// Mint an attenuated handle from a capability the acting principal HOLDS.
/// Frame-checked: the minter's own policy authority must cover the requested
/// capability (root/permissive hold everything; a package holds only its
/// grants), so a mint cannot exceed what the minter holds. Returns the
/// unguessable handle id (hex) on success.
pub fn oden_capsec_handle_mint(
  cap_str: &str,
) -> Result<String, PermissionCheckError> {
  if !oden_capsec_active() {
    return Err(oden_handle_inactive());
  }
  let principal = oden_capsec_principal();
  let label = principal.label();
  let Some((grant, req, canonical)) = oden_handle_parse_capability(cap_str)
  else {
    return Err(oden_handle_denied(
      &label,
      "mint",
      cap_str,
      "unparseable capability",
    ));
  };
  // Frame-check: the minter must actually hold the authority at mint time.
  let policy = oden_capsec_policy();
  let mode = oden_capsec_mode(oden_capsec_policy_file());
  let holds = principal.is_ambient()
    || mode == OdenMode::Permissive
    || policy.grants(&principal, &req);
  if !holds {
    return Err(oden_handle_denied(
      &label,
      "mint",
      &canonical,
      "mint exceeds holding",
    ));
  }
  let id =
    oden_handle::insert_handle(label.clone(), grant, canonical.clone(), None);
  oden_capsec_audit_record(
    &label,
    "handle",
    "mint",
    &canonical,
    "allow(mint)",
    None,
  );
  Ok(oden_handle_id_hex(id))
}

/// Re-attenuate: derive a narrower child handle from a parent the caller
/// possesses. Only narrows — the child capability must be covered by the
/// parent's, so over-broad re-widening is denied. Not frame-checked against the
/// caller's grants: possession of the parent handle is the authority to
/// attenuate it (the parent was itself frame-checked at mint).
pub fn oden_capsec_handle_scoped(
  parent_hex: &str,
  cap_str: &str,
) -> Result<String, PermissionCheckError> {
  if !oden_capsec_active() {
    return Err(oden_handle_inactive());
  }
  let principal = oden_capsec_principal();
  let label = principal.label();
  let Some((grant, req, canonical)) = oden_handle_parse_capability(cap_str)
  else {
    return Err(oden_handle_denied(
      &label,
      "scoped",
      cap_str,
      "unparseable capability",
    ));
  };
  let Some(parent_id) = oden_handle_parse_id(parent_hex) else {
    return Err(oden_handle_denied(
      &label,
      "scoped",
      &canonical,
      "unknown parent handle",
    ));
  };
  // The parent must be live (exists, not revoked, no revoked ancestor).
  let Some(parent_grant) =
    oden_handle::with_table(|t| t.parent_grant_if_live(parent_id))
  else {
    return Err(oden_handle_denied(
      &label,
      "scoped",
      &canonical,
      "parent handle revoked or unknown",
    ));
  };
  // Narrowing check: the child capability must be covered by the parent's.
  if !oden_policy::covers(std::slice::from_ref(&parent_grant), &req) {
    return Err(oden_handle_denied(
      &label,
      "scoped",
      &canonical,
      "scoped wider than parent",
    ));
  }
  let id = oden_handle::insert_handle(
    label.clone(),
    grant,
    canonical.clone(),
    Some(parent_id),
  );
  oden_capsec_audit_record(
    &label,
    "handle",
    "scoped",
    &canonical,
    "allow(scoped)",
    None,
  );
  Ok(oden_handle_id_hex(id))
}

/// Open a synchronous possession window on a handle: push its attenuated
/// capability onto the active-use stack so the enforcement funnel authorizes
/// covered ops for the duration of the possessor's callback. Possession-checked
/// — any principal holding the handle may use it; there is no frame walk. Emits
/// the boundary-crossing `transfer` record the first time a possessor other
/// than the minter uses it. A revoked/forged/unknown handle denies (the
/// use-after-revoke and forged-id red-team cases). Balanced by
/// `oden_capsec_handle_exit`.
pub fn oden_capsec_handle_enter(hex: &str) -> Result<(), PermissionCheckError> {
  if !oden_capsec_active() {
    return Err(oden_handle_inactive());
  }
  let principal = oden_capsec_principal();
  let label = principal.label();
  let Some(id) = oden_handle_parse_id(hex) else {
    return Err(oden_handle_denied(&label, "use", "?", "forged handle id"));
  };
  let lookup = oden_handle::with_table(|t| t.lookup(id));
  match lookup {
    OdenHandleLookup::Unknown => {
      Err(oden_handle_denied(&label, "use", "?", "forged handle id"))
    }
    OdenHandleLookup::Revoked => {
      Err(oden_handle_denied(&label, "use", "?", "handle revoked"))
    }
    OdenHandleLookup::Live {
      grant,
      cap_str,
      minter,
    } => {
      // Boundary-crossing audit: fire once per new cross-package possessor.
      let crossed = oden_handle::with_table(|t| t.note_possessor(id, &label));
      if crossed {
        oden_capsec_audit_record(
          &label,
          "handle",
          "transfer",
          &cap_str,
          &format!("allow(transfer {minter}->{label})"),
          None,
        );
      }
      oden_handle::push_active(grant);
      Ok(())
    }
  }
}

/// Close the most recent possession window opened by `oden_capsec_handle_enter`.
pub fn oden_capsec_handle_exit() {
  if !oden_capsec_active() {
    return;
  }
  oden_handle::pop_active();
}

/// Revoke a handle and every handle transitively derived from it. Idempotent:
/// an unknown or already-revoked handle is a no-op. Emits one `revoke` record
/// per handle actually revoked so the cascade is auditable.
pub fn oden_capsec_handle_revoke(hex: &str) {
  if !oden_capsec_active() {
    return;
  }
  let Some(id) = oden_handle_parse_id(hex) else {
    return;
  };
  let label = oden_capsec_principal().label();
  let revoked = oden_handle::with_table(|t| t.revoke_cascade(id));
  for (rid, cap) in revoked {
    let kind = if rid == id {
      "allow(revoke)"
    } else {
      "allow(revoke cascade)"
    };
    oden_capsec_audit_record(&label, "handle", "revoke", &cap, kind, None);
  }
}

// A handle op reached while capsec is inactive: the `Deno.oden` surface is only
// installed when armed, so this is defense in depth (a stray call denies rather
// than silently succeeding).
fn oden_handle_inactive() -> PermissionCheckError {
  PermissionCheckError::PermissionDenied(PermissionDeniedError {
    access: "oden handle operation".to_string(),
    name: "capsec",
    custom_message: Some(
      "oden capsec: authority-flow handles require an armed capsec policy"
        .to_string(),
    ),
    state: PermissionState::Denied,
  })
}

// Import gating (LLP 0001 Phase 2), attributed to the **referrer** — the module
// that issued the import, which the loader knows synchronously. This is the
// sound attribution point: the op-dispatch stack is empty at the loader
// boundary, so a package importing remote code cannot be seen there; the
// referrer can. A package pulling least-attested code — a remote (`http(s):`)
// or dynamically-minted (`data:`/`blob:`) specifier — is the runtime
// supply-chain vector the import graph gates. Frozen `/1` default-denied
// remote/data/blob imports from packages. `/1.1` first applies the shared URL
// classification: HTTP(S) stays behind this graph gate, data is a reasoned
// non-capability, blob/unknown schemes close structurally, and recognized
// runtime/file schemes continue to their own operation boundaries. Both static
// and dynamic imports are attributed to the referrer: a dependency's *static*
// remote import is as much a supply-chain reach as a dynamic one.
// @ref LLP 0019#fetch-versus-connect [implements]
pub fn oden_capsec_gate_import(
  specifier: &Url,
  referrer: &Url,
  _is_dynamic: bool,
) -> Result<(), PermissionCheckError> {
  if !oden_capsec_active() {
    return Ok(());
  }
  let scheme = specifier.scheme();
  let principal = oden_principal_index::resolve_locator(referrer.as_str());
  if oden_capsec_profile_is("oden/capsec/1.1") {
    match oden_capsec_gate_url_scheme_inner(
      scheme,
      "module import",
      Some(principal.clone()),
    )? {
      OdenUrlSchemeClass::Network => {}
      OdenUrlSchemeClass::File
      | OdenUrlSchemeClass::InlineData
      | OdenUrlSchemeClass::RuntimeInternal => return Ok(()),
      // Closed classes returned as an error above.
      OdenUrlSchemeClass::ClosedBlob | OdenUrlSchemeClass::ClosedUnknown => {
        unreachable!()
      }
    }
  } else if !matches!(scheme, "data" | "blob" | "http" | "https") {
    // Frozen Revision-1 behavior. In particular, its data/blob import rule is
    // preserved for engines that still advertise oden/capsec/1.
    return Ok(());
  }
  // Ambient referrers (root/runtime) may import freely. A non-ambient referrer
  // — a package, or the quarantine/no-user sentinels — is gated.
  if principal.is_ambient() {
    return Ok(());
  }
  oden_capsec_readiness_gate()?;
  let mode = oden_capsec_mode(oden_capsec_policy_file());
  let label = principal.label();
  let target = specifier.as_str();
  let deny = mode == OdenMode::Enforce;
  let verdict = if deny {
    "DENY(import graph default-denied under active profile)"
  } else if mode == OdenMode::Audit {
    "audit(record)"
  } else {
    "allow(permissive)"
  };
  oden_capsec_audit_record(&label, "import", scheme, target, verdict, None);
  if deny {
    return Err(PermissionCheckError::PermissionDenied(
      PermissionDeniedError {
        access: format!("import of {target:?}"),
        name: "capsec",
        custom_message: Some(format!(
          "oden capsec: principal \"{label}\" may not import {scheme}: code \
           (this scheme is graph-gated for packages by the active capsec profile)"
        )),
        state: PermissionState::Denied,
      },
    ));
  }
  Ok(())
}

fn oden_capsec_loader_read_identity_denied(
  principal: &OdenPrincipal,
  import_type: &str,
  target: &str,
  reason: &str,
) -> PermissionCheckError {
  let label = principal.label();
  oden_capsec_audit_record(
    &label,
    "fs",
    "read",
    target,
    &format!("DENY(loader identity: {reason})"),
    None,
  );
  PermissionCheckError::PermissionDenied(PermissionDeniedError {
    access: format!("typed import ({import_type}) access to {target:?}"),
    name: "capsec",
    custom_message: Some(format!(
      "oden capsec: typed import ({import_type}) has no trustworthy referrer/path identity ({reason})"
    )),
    state: PermissionState::Denied,
  })
}

/// Gate local typed-data bytes at the loader boundary using the principal of
/// the importing module. Static loader reads bypass Deno's ordinary read
/// permission check, and dynamic behavior is not a stable security contract,
/// so every text/JSON/bytes branch enters this one rule before source loading.
///
/// The Stage-B engine deliberately has no package-self fallback: that allow is
/// reserved for the integrity-bound, pre-armed payload inventory introduced by
/// the Rev2 registry. Until then an ungranted package read fails closed.
// @ref LLP 0019#typed-local-imports [implements] — Typed loader bytes emit referrer-attributed fs:read.
// @ref LLP 0019#reachability-does-not-replace-operation-checks [constrained-by] — Graph reachability never substitutes for this operation decision.
// @ref LLP 0019#implicit-package-self-access [constrained-by] — No ad hoc package-root read fallback before the generated payload inventory exists.
pub fn oden_capsec_gate_local_typed_import(
  specifier: &Url,
  referrer: Option<&Url>,
  import_type: &str,
) -> Result<(), PermissionCheckError> {
  if !oden_capsec_profile_is("oden/capsec/1.1") || specifier.scheme() != "file"
  {
    return Ok(());
  }
  oden_capsec_readiness_gate()?;

  let principal = referrer
    .map(|value| oden_principal_index::resolve_locator(value.as_str()))
    .unwrap_or(OdenPrincipal::NoUser);
  if !matches!(import_type, "text" | "json" | "bytes") {
    return Err(oden_capsec_loader_read_identity_denied(
      &principal,
      import_type,
      specifier.as_str(),
      "unknown typed-import kind",
    ));
  }
  if matches!(principal, OdenPrincipal::NoUser | OdenPrincipal::Quarantine) {
    return Err(oden_capsec_loader_read_identity_denied(
      &principal,
      import_type,
      specifier.as_str(),
      "missing or unattributable referrer",
    ));
  }
  let path = specifier.to_file_path().map_err(|_| {
    oden_capsec_loader_read_identity_denied(
      &principal,
      import_type,
      specifier.as_str(),
      "malformed local resource identity",
    )
  })?;
  let target = path.to_string_lossy();
  let api_name = format!("typed import ({import_type})");
  oden_capsec_decide_for_principal(
    principal,
    OdenFamily::Fs,
    "read",
    &target,
    Some(&api_name),
  )
}

// Interim worker stance (LLP 0001 Phase 2): worker creation by a package
// principal is default-denied under enforce until worker principal inheritance
// is designed. Root/runtime (ambient) are unaffected. Not yet a grantable
// capability — a loud compat break, never a silent gap.
// @ref llp/0001-adding-capability-security-to-deno.plan.md
pub fn oden_capsec_check_worker_create() -> Result<(), PermissionCheckError> {
  if !oden_capsec_active() {
    return Ok(());
  }
  oden_capsec_readiness_gate()?;
  let principal = oden_capsec_principal();
  if principal.is_ambient() {
    return Ok(());
  }
  let label = principal.label();
  let mode = oden_capsec_mode(oden_capsec_policy_file());
  let deny = mode == OdenMode::Enforce;
  let verdict = if deny {
    "DENY(worker default-denied under enforce)"
  } else {
    "audit(record)"
  };
  oden_capsec_audit_record(&label, "worker", "create", "", verdict, None);
  if deny {
    return Err(PermissionCheckError::PermissionDenied(
      PermissionDeniedError {
        access: "worker creation".to_string(),
        name: "capsec",
        custom_message: Some(format!(
          "oden capsec: principal \"{label}\" cannot create a Worker under enforce \
           (worker principal inheritance is not yet designed; default-denied)"
        )),
        state: PermissionState::Denied,
      },
    ));
  }
  Ok(())
}

/// `node:vm` deliberately does not register caller-controlled script names as
/// package identity. While compartment globals is active, a non-ambient
/// principal must therefore not create a second generated-code route that
/// bypasses the endowment-aware eval/Function callback. Root/runtime remain
/// able to create quarantine-by-design vm scripts.
// @ref LLP 0014#closing-the-dynamic-channels [implements]
pub fn oden_capsec_check_vm_code_generation() -> Result<(), PermissionCheckError>
{
  if !oden_capsec_compartment_globals_on() {
    return Ok(());
  }
  oden_capsec_readiness_gate()?;
  let principal = oden_capsec_principal();
  if principal.is_ambient() {
    return Ok(());
  }
  let label = principal.label();
  let verdict = "DENY(node:vm quarantine under compartment globals)";
  oden_capsec_audit_record(&label, "vm", "code-generation", "", verdict, None);
  Err(PermissionCheckError::PermissionDenied(
    PermissionDeniedError {
      access: "node:vm code generation".to_string(),
      name: "capsec",
      custom_message: Some(format!(
        "oden capsec: principal \"{label}\" cannot generate code through node:vm while compartment globals is active (vm scripts remain quarantine-by-design)"
      )),
      state: PermissionState::Denied,
    },
  ))
}

#[allow(
  clippy::disallowed_methods,
  reason = "Phase-0/1 capsec resolves the project root from an env var, falling back to cwd."
)]
/// The project root is the ARM-TIME policy anchor: grants were resolved and
/// principals classify against the root that armed this process, so a mid-run
/// `Deno.chdir()` must not re-anchor authority. Snapshot once — this also
/// removes a per-mediated-op `getcwd()` (macOS walks/opens parent dirs on a
/// path-cache miss; it and the readiness rebuild dominated the armed hot path
/// after the policy snapshot, ENG-23764 benchmark). Relative *fs targets*
/// still resolve against the live cwd in `oden_normalize_fs_target`, matching
/// what the OS will actually open.
fn oden_capsec_project_root() -> &'static str {
  static ROOT: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
    std::env::var("ODEN_CAPSEC_ROOT").unwrap_or_else(|_| {
      std::env::current_dir()
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_default()
    })
  });
  &ROOT
}

#[derive(Debug, serde::Deserialize, Default)]
struct OdenPolicyFile {
  // `Option<String>` alone would deserialize an explicit JSON `null` as
  // absence and silently fall back to audit. Invoke a string deserializer only
  // when the field is present so missing remains optional but null/wrong-shaped
  // values reject the artifact.
  #[serde(default, deserialize_with = "oden_deserialize_optional_mode")]
  mode: Option<String>,
  #[serde(default)]
  grants: std::collections::HashMap<String, String>,
  // Runtime-control authority has a separate namespace from package selectors.
  // In particular, an npm package literally named `root` must never satisfy an
  // exact-root startup predicate by occupying `grants["root"]`.
  #[serde(default, rename = "rootGrants")]
  root_grants: String,
  // Config-only dynamic-permission ceilings (LLP 0015). The string shorthand
  // defaults to `prompt`; the object form selects prompt/auto/deny.
  #[serde(default)]
  ceilings: std::collections::HashMap<String, OdenCeilingFile>,
  // The parent Oden CLI serializes its process-wide deny ceiling into the
  // immutable policy handoff so layer 2 can reject dynamic requests before a
  // prompt. Direct fork users may author the same field explicitly.
  #[serde(default, rename = "denyCeiling")]
  deny_ceiling: String,
  // Opt-in stack-intersection arming (LLP 0001 precedence row 3). Names the
  // capability classes (`env`, `env:read`, `fs:write`, or `*`) for which a
  // deputy must not launder a scheduler's authority: for an armed class the
  // decision intersects every non-ambient principal on the call chain plus the
  // CPED scheduling principal. Empty by default, so default enforce (rows 1/2/4)
  // is unaffected.
  #[serde(default, rename = "deputyClasses")]
  deputy_classes: Vec<String>,
  // LLP 0019 protected-resource annotations. These rows are not a second grant
  // channel: validation requires each one to decorate an existing exact static
  // network floor row. The engine uses them only to clear the built-in
  // metadata refusal, then continues ordinary evaluation.
  #[serde(default, rename = "protectedMetadata")]
  protected_metadata: Vec<OdenProtectedMetadataRowFile>,
  // Optional trusted-parent receipt binding. Presence enables the gate and
  // requires one receipt digest per row; null is malformed, not "gate off".
  #[serde(
    default,
    rename = "protectedMetadataReceiptSetDigest",
    deserialize_with = "oden_deserialize_optional_string"
  )]
  protected_metadata_receipt_set_digest: Option<String>,
  #[serde(skip)]
  protected_metadata_policy: OdenProtectedMetadataPolicy,
}

#[derive(Debug, serde::Deserialize, Clone)]
#[serde(untagged)]
enum OdenCeilingFile {
  Authority(String),
  Detailed {
    authority: String,
    #[serde(default = "oden_default_on_request")]
    on_request: String,
  },
}

fn oden_default_on_request() -> String {
  "prompt".to_string()
}

fn oden_deserialize_optional_mode<'de, D>(
  deserializer: D,
) -> Result<Option<String>, D::Error>
where
  D: serde::Deserializer<'de>,
{
  oden_deserialize_optional_string(deserializer)
}

fn oden_deserialize_optional_string<'de, D>(
  deserializer: D,
) -> Result<Option<String>, D::Error>
where
  D: serde::Deserializer<'de>,
{
  <String as serde::Deserialize>::deserialize(deserializer).map(Some)
}

// The policy source: `.oden/policy.json` in the project root — the same file
// the userland layer (LLP 0012) writes, so a grant authored there enforces
// unforgeably in the engine without a rewrite. Shape:
// `{ "mode": "enforce", "grants": { "<pkg>": "fs:read:./x,network:fetch:host" } }`.
// The artifact is the only mode/grant source: with structural arming there are
// no env-var grant or mode overrides an environment could use to widen or
// silently downgrade what the artifact says.
// @ref llp/0001-adding-capability-security-to-deno.plan.md ; llp/0012-userland-capability-layer.plan.md
/// Process-lifetime snapshot of the policy artifact. Same doctrine as the
/// ARMED probe: arming and policy content are bootstrap-time facts, and a
/// policy artifact that changes or vanishes mid-run must not re-shape a
/// running process's authority. Re-reading per decision also priced a file
/// read + JSON parse into every mediated op (~230x on a gated-op hot loop,
/// ENG-23764 throughput benchmark). The first-read fail-closed latch
/// (present-but-unreadable → enforce) fires inside this one read.
fn oden_capsec_policy_file() -> Option<&'static OdenPolicyFile> {
  static FILE: std::sync::LazyLock<Option<OdenPolicyFile>> =
    std::sync::LazyLock::new(oden_capsec_policy_file_uncached);
  FILE.as_ref()
}

fn oden_capsec_root_static_grants(req: &OdenRequest) -> bool {
  oden_capsec_policy_file()
    .and_then(|file| {
      OdenGrant::parse_many_for_profile(&file.root_grants, ODEN_CAPSEC_PROFILE)
        .ok()
    })
    .is_some_and(|grants| self::oden_policy::covers(&grants, req))
}

#[allow(
  clippy::disallowed_methods,
  reason = "bootstrap reads the explicit capsec policy handoff once; the sys-traits resolver is staged separately"
)]
fn oden_capsec_policy_file_uncached() -> Option<OdenPolicyFile> {
  // Explicit policy-file path override (ODEN_CAPSEC_POLICY) — the seam the oden
  // CLI uses to hand the engine a merged policy (`.oden/policy.json` unioned with
  // deno.json + import-site grants) from a one-shot temp file, without writing
  // into the project tree. Authenticated parent launches unlink that artifact
  // after this process-lifetime snapshot. Shares the env name with the userland
  // layer (LLP 0012). Falls back to <root>/.oden/policy.json, the committed
  // artifact, which bootstrap never unlinks.
  let path = match std::env::var_os("ODEN_CAPSEC_POLICY") {
    // Same non-empty rule as the arming probe, so the two cannot disagree.
    Some(p) if !p.is_empty() => std::path::PathBuf::from(p),
    _ => {
      let root = oden_capsec_project_root();
      if root.is_empty() {
        return None;
      }
      std::path::Path::new(&root)
        .join(".oden")
        .join("policy.json")
    }
  };
  // Fail closed on a present-but-unreadable artifact: the process armed on this
  // policy's existence, so losing or corrupting it mid-run must not downgrade
  // to audit-with-zero-grants. The latch forces enforce (packages get denied)
  // and readiness names the state.
  match std::fs::read_to_string(&path) {
    Ok(text) => match oden_parse_policy_file(&text, &path) {
      Ok(file) => Some(file),
      Err(reason) => {
        oden_policy_unreadable_latch(reason);
        None
      }
    },
    Err(err) => {
      if oden_capsec_armed() {
        oden_policy_unreadable_latch(format!(
          "{}: cannot read present artifact: {err}",
          path.display()
        ));
      }
      None
    }
  }
}

/// Parse and validate the complete artifact before any grant is installed. A
/// serde shape/syntax error includes line+column; a grant error includes the
/// JSON selector path and token offset. This is the fork-side source-location
/// adapter around the same strict grammar as TS / `crates/oden_policy`.
fn oden_parse_policy_file(
  text: &str,
  path: &std::path::Path,
) -> Result<OdenPolicyFile, String> {
  let mut file =
    serde_json::from_str::<OdenPolicyFile>(text).map_err(|err| {
      format!(
        "{}:{}:{}: invalid policy JSON/shape: {err}",
        path.display(),
        err.line(),
        err.column()
      )
    })?;

  if let Some(mode) = file.mode.as_deref()
    && !matches!(mode, "permissive" | "audit" | "enforce")
  {
    return Err(format!(
      "{}#mode: unknown mode {mode:?}; expected permissive, audit, or enforce",
      path.display()
    ));
  }
  let root_grants =
    OdenGrant::parse_many_for_profile(&file.root_grants, ODEN_CAPSEC_PROFILE)
      .map_err(|err| {
      format!("{}#rootGrants: invalid capsec grant: {err}", path.display())
    })?;
  if root_grants
    .iter()
    .any(|grant| grant.family != OdenFamily::Inspector)
  {
    return Err(format!(
      "{}#rootGrants: only the exact static inspector:activate row is supported in {}",
      path.display(),
      ODEN_CAPSEC_PROFILE
    ));
  }
  for (selector, grant_str) in &file.grants {
    if selector.trim().is_empty() {
      return Err(format!(
        "{}#grants: package selector must not be empty",
        path.display()
      ));
    }
    OdenGrant::parse_many_for_profile(grant_str, ODEN_CAPSEC_PROFILE).map_err(
      |err| {
        format!(
          "{}#grants[{:?}]: invalid capsec grant: {err}",
          path.display(),
          selector
        )
      },
    )?;
  }
  OdenGrant::parse_many(&file.deny_ceiling).map_err(|err| {
    format!(
      "{}#denyCeiling: invalid capsec grant: {err}",
      path.display()
    )
  })?;
  for (selector, ceiling) in &file.ceilings {
    if selector.trim().is_empty() {
      return Err(format!(
        "{}#ceilings: package selector must not be empty",
        path.display()
      ));
    }
    let (authority, on_request) = match ceiling {
      OdenCeilingFile::Authority(authority) => {
        (authority.as_str(), Some(OdenOnRequest::Prompt))
      }
      OdenCeilingFile::Detailed {
        authority,
        on_request,
      } => (
        authority.as_str(),
        OdenOnRequest::parse(on_request.as_str()),
      ),
    };
    if on_request.is_none() {
      return Err(format!(
        "{}#ceilings[{:?}].on_request: expected prompt, auto, or deny",
        path.display(),
        selector
      ));
    }
    OdenGrant::parse_many(authority).map_err(|err| {
      format!(
        "{}#ceilings[{:?}].authority: invalid capsec grant: {err}",
        path.display(),
        selector
      )
    })?;
  }
  file.protected_metadata_policy = OdenProtectedMetadataPolicy::compile(
    &file.protected_metadata,
    file.protected_metadata_receipt_set_digest.as_deref(),
    &file.grants,
    &file.deny_ceiling,
  )
  .map_err(|error| format!("{}#{error}", path.display()))?;
  Ok(file)
}

// Latched when the policy artifact that armed this process cannot be read or
// parsed. Forces enforce-with-zero-grants (fail closed) rather than the silent
// audit downgrade a deleted temp file would otherwise buy an attacker.
static ODEN_POLICY_UNREADABLE: std::sync::atomic::AtomicBool =
  std::sync::atomic::AtomicBool::new(false);
static ODEN_POLICY_INVALID_REASON: OnceLock<String> = OnceLock::new();

static ODEN_POLICY_INVALID: std::sync::atomic::AtomicBool =
  std::sync::atomic::AtomicBool::new(false);

fn oden_policy_unreadable_latch(reason: String) {
  let _ = ODEN_POLICY_INVALID_REASON.set(reason);
  ODEN_POLICY_UNREADABLE.store(true, std::sync::atomic::Ordering::Relaxed);
}

fn oden_policy_unreadable() -> bool {
  ODEN_POLICY_UNREADABLE.load(std::sync::atomic::Ordering::Relaxed)
}

fn oden_policy_invalid() -> bool {
  ODEN_POLICY_INVALID.load(std::sync::atomic::Ordering::Relaxed)
}

fn oden_policy_unreadable_reason() -> Option<&'static str> {
  ODEN_POLICY_INVALID_REASON.get().map(String::as_str)
}

// Resolve fs grant scopes against $HOME/root, mirroring the userland policy
// loader so a `fs:read:./data` grant authored in `.oden/policy.json` matches the
// absolute path the op actually requests.
#[allow(
  clippy::disallowed_methods,
  reason = "resolves fs grant scopes against $HOME to match the userland policy format"
)]
fn oden_resolve_grant_scopes(grant_str: &str, root: &str) -> String {
  let Ok(mut grants) =
    OdenGrant::parse_many_for_profile(grant_str, ODEN_CAPSEC_PROFILE)
  else {
    return grant_str.to_string();
  };
  for grant in &mut grants {
    if grant.family != OdenFamily::Fs {
      continue;
    }
    grant.scope = if let Some(r) = grant.scope.strip_prefix("~/") {
      match std::env::var("HOME") {
        Ok(home) => format!("{home}/{r}"),
        Err(_) => grant.scope.clone(),
      }
    } else if grant.scope.starts_with('/') {
      grant.scope.clone()
    } else {
      format!(
        "{root}/{}",
        grant.scope.strip_prefix("./").unwrap_or(&grant.scope)
      )
    };
  }
  grants
    .iter()
    .map(OdenGrant::to_string_canonical)
    .collect::<Vec<_>>()
    .join(",")
}

// Resolve an fs op target through the deepest existing ancestor. Existing
// paths therefore match on their real inode location; not-yet-existing write
// leaves inherit the canonical identity of the nearest existing directory.
// This closes lexical symlink-out grants while preserving creation semantics.
// @ref LLP 0010#paths [implements]
#[allow(
  clippy::disallowed_methods,
  reason = "resolves a relative fs op target against the process cwd for scope matching"
)]
fn oden_normalize_fs_target(target: &str) -> String {
  use std::path::Component;
  let p = std::path::Path::new(target);
  let abs = if p.is_absolute() {
    p.to_path_buf()
  } else {
    match std::env::current_dir() {
      Ok(cwd) => cwd.join(p),
      Err(_) => return target.to_string(),
    }
  };
  let mut out: Vec<Component> = Vec::new();
  for comp in abs.components() {
    match comp {
      Component::CurDir => {}
      Component::ParentDir => {
        if matches!(out.last(), Some(Component::Normal(_))) {
          out.pop();
        }
      }
      other => out.push(other),
    }
  }
  let mut pb = std::path::PathBuf::new();
  for c in out {
    pb.push(c.as_os_str());
  }
  if let Ok(real) = std::fs::canonicalize(&pb) {
    return real.to_string_lossy().into_owned();
  }

  let mut ancestor = pb.clone();
  let mut suffix = Vec::new();
  while !ancestor.as_os_str().is_empty() {
    if let Ok(real) = std::fs::canonicalize(&ancestor) {
      let mut resolved = real;
      for part in suffix.iter().rev() {
        resolved.push(part);
      }
      return resolved.to_string_lossy().into_owned();
    }
    let Some(name) = ancestor.file_name().map(|s| s.to_os_string()) else {
      break;
    };
    suffix.push(name);
    if !ancestor.pop() {
      break;
    }
  }
  pb.to_string_lossy().into_owned()
}

// The decision policy, built from the policy artifact alone (the retired
// ODEN_CAPSEC_GRANT env layering is gone — grants have exactly one authoring
// surface, so an environment cannot widen a package's authority).
fn oden_capsec_policy() -> &'static OdenPolicy {
  // Built once from the policy-file snapshot: grant-scope resolution does
  // path normalization, which must not run per mediated op.
  static POLICY: std::sync::LazyLock<OdenPolicy> = std::sync::LazyLock::new(
    || {
      let file = oden_capsec_policy_file();
      let root = oden_capsec_project_root();
      let mut policy = OdenPolicy::new(oden_capsec_mode(file));
      // Policy-file grants (the userland `.oden/policy.json` format).
      if let Some(file) = file {
        for (selector, grant_str) in &file.grants {
          // The artifact was validated atomically before it was admitted, so
          // this cannot fail. Preserve the exact selector bytes: trimming a
          // non-empty key here could accidentally turn `" dep "` into authority
          // for the real `dep` principal when the other policy planes do not.
          if policy
            .grant_for_profile(
              selector,
              &oden_resolve_grant_scopes(grant_str, root),
              ODEN_CAPSEC_PROFILE,
            )
            .is_err()
          {
            oden_policy_unreadable_latch(format!(
              "policy selector {selector:?} failed validation after scope resolution"
            ));
            return OdenPolicy::new(OdenMode::Enforce);
          }
        }
        policy
          .deny_ceiling(&oden_resolve_grant_scopes(&file.deny_ceiling, root));
        for (selector, ceiling) in &file.ceilings {
          let (authority, disposition) = match ceiling {
            OdenCeilingFile::Authority(authority) => {
              (authority.as_str(), Some(OdenOnRequest::Prompt))
            }
            OdenCeilingFile::Detailed {
              authority,
              on_request,
            } => (
              authority.as_str(),
              OdenOnRequest::parse(on_request.as_str()),
            ),
          };
          let disposition = disposition
            .expect("dynamic disposition validated before policy construction");
          policy.ceiling(
            selector,
            &oden_resolve_grant_scopes(authority, root),
            disposition,
          );
        }
      }
      for issue in policy.validate_envelopes() {
        match issue {
          OdenPolicyValidationIssue::FloorAboveCeiling { selector, grant } => {
            ODEN_POLICY_INVALID
              .store(true, std::sync::atomic::Ordering::Relaxed);
            let _ = (selector, grant);
          }
          OdenPolicyValidationIssue::CeilingConflicted {
            selector,
            ceiling,
            deny,
          } => {
            let _ = deny;
            oden_capsec_audit_record(
              &selector,
              "ceiling",
              "conflict",
              &ceiling,
              "deny(ceiling-conflicted)",
              None,
            );
          }
        }
      }
      policy
    },
  );
  &POLICY
}

// Mode comes from the policy artifact: file mode > default (audit). Unknown or
// wrong-shaped modes reject the entire artifact before this point, and any
// present-but-unreadable/malformed artifact forces enforce (fail closed). The retired
// ODEN_CAPSEC_MODE/_ENFORCE env overrides are gone: with structural arming the
// mode name is the artifact's guarantee, and no environment may downgrade it.
fn oden_capsec_mode(file: Option<&OdenPolicyFile>) -> OdenMode {
  fn parse_mode(s: &str) -> Option<OdenMode> {
    match s {
      "permissive" => Some(OdenMode::Permissive),
      "audit" => Some(OdenMode::Audit),
      "enforce" => Some(OdenMode::Enforce),
      _ => None,
    }
  }
  if oden_policy_unreadable() {
    return OdenMode::Enforce;
  }
  if let Some(m) = file.and_then(|f| f.mode.as_deref()).and_then(parse_mode) {
    return m;
  }
  OdenMode::Audit
}

fn oden_capsec_scheduling_principal<I>(
  principals: I,
) -> Option<(OdenPrincipal, String)>
where
  I: IntoIterator<Item = (OdenPrincipal, String)>,
{
  let mut root = None;
  for (principal, locator) in principals {
    if !principal.is_ambient() {
      return Some((principal, locator));
    }
    if principal == OdenPrincipal::Root && root.is_none() {
      root = Some((principal, locator));
    }
  }
  root
}

// @ref LLP 0019#operation-scoped-positive-authority-provenance [implements] -- Runtime is selected only after live and scheduled package actors have been exhausted.
fn oden_capsec_unattributed_principal(
  trusted_host_actor: bool,
) -> OdenPrincipal {
  if trusted_host_actor {
    OdenPrincipal::Runtime
  } else {
    OdenPrincipal::NoUser
  }
}

fn oden_capsec_apply_unattributed_fallback(
  principals: &mut Vec<OdenPrincipal>,
  trusted_host_actor: bool,
) {
  if principals.is_empty() {
    principals.push(oden_capsec_unattributed_principal(trusted_host_actor));
  }
}

fn oden_capsec_principal_with_locator() -> (OdenPrincipal, Option<String>) {
  let frames = prompter::current_oden_stacktrace();
  for frame in frames {
    // Principals come from the loader principal index — integrity-bound
    // classification (a locator whose lockfile binding fails resolves to
    // quarantine, never a path-string principal), memoized per script ID for
    // the op-dispatch hot path (ENG-23763).
    let locator = frame.locator;
    let principal = match locator.as_deref() {
      Some(locator) => oden_principal_index::resolve_frame(
        frame.isolate_id,
        frame.script_id,
        locator,
      ),
      None if oden_capsec_runtime_display(frame.display_name.as_deref()) => {
        continue;
      }
      None if frame.script_id.is_some() => OdenPrincipal::Quarantine,
      None => continue,
    };
    if principal == OdenPrincipal::Runtime {
      continue;
    }
    // Precedence row 1: the nearest live user frame wins.
    return (principal, locator);
  }
  // Precedence row 2: no live user frame, but one or more scheduling frames
  // survive in CPED. Trusted runtime/root wrappers may precede the package in
  // that captured stack, so select the nearest non-ambient scheduler. Preserve
  // root only when the captured stack contains no non-ambient scheduler; a
  // runtime-only stack remains unattributable and falls through to no-user.
  // @ref LLP 0019#operation-scoped-positive-authority-provenance [implements]
  let scheduling_locators = prompter::current_oden_cped_locator()
    .into_iter()
    .chain(prompter::current_oden_cped_stack());
  if let Some((principal, locator)) =
    oden_capsec_scheduling_principal(scheduling_locators.map(|locator| {
      (oden_principal_index::resolve_locator(&locator), locator)
    }))
  {
    return (principal, Some(locator));
  }
  // A Rust-owned host actor is the final ambient fallback, never an override:
  // any live or scheduled package/quarantine actor above remains authoritative.
  // Precedence row 4: no live user frame and no scheduling principal is the
  // fail-closed sentinel, except for the opaque Rust-owned host actor above.
  // A genuine timer/immediate boundary carries schedule-before-first-op through
  // ENG-23881; ordinary unattributed continuations still become no-user.
  (
    oden_capsec_unattributed_principal(
      prompter::current_oden_trusted_host_actor(),
    ),
    None,
  )
}

fn oden_capsec_principal() -> OdenPrincipal {
  oden_capsec_principal_with_locator().0
}

/// Canonical actor identity for lifetime-bound positive provenance. Package,
/// JSR, and URL actors include the physical integrity-bound locator instance;
/// ambient root remains the one distinguished root identity. Ambient entries
/// are discarded when any constrained actor exists, matching the decision
/// core's constrained-set semantics.
fn oden_capsec_integrity_actor_keys() -> Vec<String> {
  fn push(
    constrained: &mut std::collections::BTreeSet<String>,
    ambient: &mut std::collections::BTreeSet<String>,
    principal: OdenPrincipal,
    locator: Option<&str>,
  ) {
    if principal == OdenPrincipal::Runtime && locator.is_some() {
      return;
    }
    if principal.is_ambient() {
      ambient.insert(principal.key());
    } else {
      constrained.insert(oden_capsec_compartment_key(&principal, locator));
    }
  }

  let mut constrained = std::collections::BTreeSet::new();
  let mut ambient = std::collections::BTreeSet::new();
  let frames = prompter::current_oden_stacktrace();
  for frame in frames {
    match frame.locator.as_deref() {
      Some(locator) => push(
        &mut constrained,
        &mut ambient,
        oden_principal_index::resolve_frame(
          frame.isolate_id,
          frame.script_id,
          locator,
        ),
        Some(locator),
      ),
      None if oden_capsec_runtime_display(frame.display_name.as_deref()) => {}
      None if frame.script_id.is_some() => push(
        &mut constrained,
        &mut ambient,
        OdenPrincipal::Quarantine,
        None,
      ),
      None => {}
    }
  }
  if let Some(locator) = prompter::current_oden_cped_locator() {
    push(
      &mut constrained,
      &mut ambient,
      oden_principal_index::resolve_locator(&locator),
      Some(&locator),
    );
  }
  for locator in prompter::current_oden_cped_stack() {
    push(
      &mut constrained,
      &mut ambient,
      oden_principal_index::resolve_locator(&locator),
      Some(&locator),
    );
  }
  if !constrained.is_empty() {
    return constrained.into_iter().collect();
  }
  if !ambient.is_empty() {
    return ambient.into_iter().collect();
  }
  vec![
    oden_capsec_unattributed_principal(
      prompter::current_oden_trusted_host_actor(),
    )
    .key(),
  ]
}

// The full set of principals implicated in the current op, for stack-
// intersection (precedence row 3): every distinct non-ambient principal live on
// the call chain, plus the appended CPED scheduling principal(s) — the single
// scheduling locator (row 2) and the carried scheduling stack set
// (call-boundary attribution). Order is nearest-frame first, scheduler(s) last;
// duplicates collapse so self-scheduling is a single entry. Empty becomes the
// opaque Rust-host actor when present, otherwise the fail-closed no-user
// sentinel; a host actor never replaces a constrained entry already collected.
// @ref llp/0001-adding-capability-security-to-deno.plan.md (Async attribution row 3)
fn oden_capsec_principal_set() -> Vec<OdenPrincipal> {
  let mut out: Vec<OdenPrincipal> = Vec::new();
  fn push(out: &mut Vec<OdenPrincipal>, principal: OdenPrincipal) {
    if principal != OdenPrincipal::Runtime && !out.contains(&principal) {
      out.push(principal);
    }
  }
  // The live call chain (the "stack" of the stack-intersection).
  let frames = prompter::current_oden_stacktrace();
  for frame in frames {
    match frame.locator.as_deref() {
      Some(locator) => {
        push(
          &mut out,
          oden_principal_index::resolve_frame(
            frame.isolate_id,
            frame.script_id,
            locator,
          ),
        );
      }
      None if oden_capsec_runtime_display(frame.display_name.as_deref()) => {}
      None if frame.script_id.is_some() => {
        push(&mut out, OdenPrincipal::Quarantine);
      }
      None => {}
    }
  }
  // Row-3 append: the CPED scheduling principal (who scheduled this callback).
  if let Some(locator) = prompter::current_oden_cped_locator() {
    push(&mut out, oden_principal_index::resolve_locator(&locator));
  }
  // The complete stack captured at the genuine async schedule boundary
  // (ENG-23881). It is callback-scoped, so appending it closes nested async
  // deputies without contaminating unrelated later synchronous work.
  for locator in prompter::current_oden_cped_stack() {
    push(&mut out, oden_principal_index::resolve_locator(&locator));
  }
  oden_capsec_apply_unattributed_fallback(
    &mut out,
    prompter::current_oden_trusted_host_actor(),
  );
  out
}

/// Capture the live op/CPED principal intersection in the Rev2 identity
/// domain. This is host state, not a caller-provided actor claim.
/// @ref LLP 0019#operation-scoped-positive-authority-provenance [implements]
pub fn oden_rev2_capture_live_principals() -> Vec<rev2::PrincipalRef> {
  oden_rev2_capture_live_permission_actors().0
}

/// Capture the constrained principal set and the nearest live effect owner in
/// one synchronous host observation. The tuple is crate-private so callers
/// cannot substitute JavaScript-provided attribution between the two fields.
pub(crate) fn oden_rev2_capture_live_permission_actors()
-> (Vec<rev2::PrincipalRef>, rev2::PrincipalRef) {
  let mut mapped = Vec::new();
  let mut push = |principal: OdenPrincipal, locator: Option<&str>| {
    if principal != OdenPrincipal::Runtime {
      mapped.push(oden_rev2_map_attributed_principal(principal, locator));
    }
  };

  for frame in prompter::current_oden_stacktrace() {
    match frame.locator.as_deref() {
      Some(locator) => push(
        oden_principal_index::resolve_frame(
          frame.isolate_id,
          frame.script_id,
          locator,
        ),
        Some(locator),
      ),
      None if oden_capsec_runtime_display(frame.display_name.as_deref()) => {}
      None if frame.script_id.is_some() => {
        push(OdenPrincipal::Quarantine, None)
      }
      None => {}
    }
  }
  if let Some(locator) = prompter::current_oden_cped_locator() {
    push(
      oden_principal_index::resolve_locator(&locator),
      Some(&locator),
    );
  }
  for locator in prompter::current_oden_cped_stack() {
    push(
      oden_principal_index::resolve_locator(&locator),
      Some(&locator),
    );
  }
  if mapped.is_empty() {
    mapped.push(oden_rev2_map_attributed_principal(
      oden_capsec_unattributed_principal(
        prompter::current_oden_trusted_host_actor(),
      ),
      None,
    ));
  }
  let overlay_owner = mapped[0].clone();
  mapped.sort();
  mapped.dedup();
  (mapped, overlay_owner)
}

fn oden_rev2_map_attributed_principal(
  principal: OdenPrincipal,
  locator: Option<&str>,
) -> rev2::PrincipalRef {
  let kind = match &principal {
    OdenPrincipal::Root => rev2::PrincipalKind::Root,
    OdenPrincipal::Runtime => rev2::PrincipalKind::Runtime,
    OdenPrincipal::Package { .. } => rev2::PrincipalKind::Package,
    OdenPrincipal::Jsr { .. } => rev2::PrincipalKind::Jsr,
    OdenPrincipal::Url { .. } => rev2::PrincipalKind::Url,
    OdenPrincipal::Quarantine => rev2::PrincipalKind::Quarantine,
    OdenPrincipal::NoUser => rev2::PrincipalKind::NoUser,
  };
  let key = if matches!(
    principal,
    OdenPrincipal::Package { .. }
      | OdenPrincipal::Jsr { .. }
      | OdenPrincipal::Url { .. }
  ) {
    oden_capsec_compartment_key(&principal, locator)
  } else {
    principal.key()
  };
  rev2::PrincipalRef { kind, key }
}

// Deputy-class arming (LLP 0001 precedence row 3), opt-in. A capability class is
// armed by the policy file's `deputyClasses` array and/or the
// ODEN_CAPSEC_DEPUTY_CLASSES env (comma-separated); each entry is a family
// (`env`), a family:action (`fs:write`), or `*` for all classes. Empty by
// default, so default enforce (rows 1/2/4) is never intersected.
#[allow(
  clippy::disallowed_methods,
  reason = "Phase-4 deputy-class arming is opt-in through the policy file and an env var; the spike's control surface."
)]
fn oden_capsec_deputy_classes() -> Vec<String> {
  let mut classes: Vec<String> = oden_capsec_policy_file()
    .map(|f| f.deputy_classes.clone())
    .unwrap_or_default();
  if let Ok(env) = std::env::var("ODEN_CAPSEC_DEPUTY_CLASSES") {
    for c in env.split(',') {
      let c = c.trim();
      if !c.is_empty() {
        classes.push(c.to_string());
      }
    }
  }
  classes
}

fn oden_capsec_deputy_class_armed(family: OdenFamily, action: &str) -> bool {
  let classes = oden_capsec_deputy_classes();
  if classes.is_empty() {
    return false;
  }
  let fam = family.name();
  let fam_action = format!("{fam}:{action}");
  classes
    .iter()
    .any(|c| c == "*" || c == fam || c == fam_action.as_str())
}

fn oden_capsec_runtime_display(display_name: Option<&str>) -> bool {
  let Some(display_name) = display_name else {
    return false;
  };
  display_name.starts_with("ext:")
    || display_name.starts_with("node:")
    || display_name.starts_with("deno:")
}

fn write_audit<T>(flag_name: &str, value: T)
where
  T: Serialize,
{
  let Some(sink) = AUDIT_SINK.get() else {
    return;
  };

  let get_stack = MAYBE_CURRENT_STACKTRACE.lock();
  let stack = get_stack.as_ref().map(|s| s());

  match sink {
    AuditSink::File(file) => {
      let mut file = file.lock();

      let mut map = serde_json::Map::with_capacity(6);
      let _ = map.insert("v".into(), serde_json::Value::Number(1.into()));
      let _ = map.insert(
        "datetime".into(),
        #[allow(
          clippy::disallowed_methods,
          reason = "TODO: support passing in a sys here"
        )]
        serde_json::Value::String(
          chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
        ),
      );
      let _ = map.insert(
        "permission".into(),
        serde_json::to_value(flag_name).unwrap(),
      );
      let _ = map.insert("value".into(), serde_json::to_value(&value).unwrap());

      if let Some(ref stack) = stack {
        let _ =
          map.insert("stack".into(), serde_json::to_value(stack).unwrap());
      }

      let _ = file.write_all(
        format!("{}\n", serde_json::to_string(&map).unwrap()).as_bytes(),
      );
    }
    AuditSink::Otel(report_fn) => {
      let value_str = serde_json::to_value(&value)
        .map(|v| match v {
          serde_json::Value::String(s) => s,
          other => other.to_string(),
        })
        .unwrap_or_default();

      report_fn(flag_name, &value_str, stack.as_deref());
    }
  }
}

/// Fast exit from permission check routines if this permission
/// is in the "fully-granted" state.
macro_rules! audit_and_skip_check_if_is_permission_fully_granted {
  ($this:expr, $flag_name:expr, $value:expr) => {
    write_audit($flag_name, $value);

    if $this.is_allow_all() {
      return Ok(());
    }
  };
}

static DEBUG_LOG_ENABLED: Lazy<bool> =
  Lazy::new(|| log::log_enabled!(log::Level::Debug));

/// Quadri-state value for storing permission state
#[derive(
  Eq, PartialEq, Default, Debug, Clone, Copy, Deserialize, PartialOrd,
)]
pub enum PermissionState {
  Granted = 0,
  GrantedPartial = 1,
  #[default]
  Prompt = 2,
  Denied = 3,
  DeniedPartial = 4,
  Ignored = 5,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OpenAccessKind {
  Read,
  ReadNoFollow,
  Write,
  WriteNoFollow,
  ReadWrite,
  ReadWriteNoFollow,
}

impl OpenAccessKind {
  pub fn is_no_follow(&self) -> bool {
    match self {
      OpenAccessKind::ReadNoFollow
      | OpenAccessKind::WriteNoFollow
      | OpenAccessKind::ReadWriteNoFollow => true,
      OpenAccessKind::Read
      | OpenAccessKind::Write
      | OpenAccessKind::ReadWrite => false,
    }
  }

  pub fn is_read(&self) -> bool {
    match self {
      OpenAccessKind::Read
      | OpenAccessKind::ReadNoFollow
      | OpenAccessKind::ReadWrite
      | OpenAccessKind::ReadWriteNoFollow => true,
      OpenAccessKind::Write | OpenAccessKind::WriteNoFollow => false,
    }
  }

  pub fn is_write(&self) -> bool {
    match self {
      OpenAccessKind::Read | OpenAccessKind::ReadNoFollow => false,
      OpenAccessKind::Write
      | OpenAccessKind::WriteNoFollow
      | OpenAccessKind::ReadWrite
      | OpenAccessKind::ReadWriteNoFollow => true,
    }
  }
}

#[derive(Debug)]
pub struct PathWithRequested<'a> {
  pub path: Cow<'a, Path>,
  /// Custom requested display name when differs from resolved.
  pub requested: Option<Cow<'a, str>>,
}

impl<'a> PathWithRequested<'a> {
  pub fn only_path(path: Cow<'a, Path>) -> Self {
    Self {
      path,
      requested: None,
    }
  }

  pub fn display(&self) -> std::path::Display<'_> {
    match &self.requested {
      Some(requested) => Path::new(requested.as_ref()).display(),
      None => self.path.display(),
    }
  }

  pub fn as_owned(&self) -> PathBufWithRequested {
    PathBufWithRequested {
      path: self.path.to_path_buf(),
      requested: self.requested.as_ref().map(|r| r.to_string()),
    }
  }

  pub fn into_owned(self) -> PathBufWithRequested {
    PathBufWithRequested {
      path: self.path.into_owned(),
      requested: self.requested.map(|r| r.into_owned()),
    }
  }
}

impl Deref for PathWithRequested<'_> {
  type Target = Path;

  fn deref(&self) -> &Self::Target {
    &self.path
  }
}

impl AsRef<Path> for PathWithRequested<'_> {
  fn as_ref(&self) -> &Path {
    &self.path
  }
}

impl<'a> AsRef<PathWithRequested<'a>> for PathWithRequested<'a> {
  fn as_ref(&self) -> &PathWithRequested<'a> {
    self
  }
}

#[derive(Debug, Clone)]
pub struct PathBufWithRequested {
  pub path: PathBuf,
  /// Custom requested display name when differs from resolved.
  pub requested: Option<String>,
}

impl PathBufWithRequested {
  pub fn only_path(path: PathBuf) -> Self {
    Self {
      path,
      requested: None,
    }
  }

  pub fn as_path_with_requested(&self) -> PathWithRequested<'_> {
    PathWithRequested {
      path: Cow::Borrowed(self.path.as_path()),
      requested: self.requested.as_deref().map(Cow::Borrowed),
    }
  }
}

impl Deref for PathBufWithRequested {
  type Target = Path;

  fn deref(&self) -> &Self::Target {
    &self.path
  }
}

#[derive(Debug)]
pub struct CheckedPath<'a> {
  // these are private to prevent someone constructing this outside the crate
  path: PathWithRequested<'a>,
  canonicalized: bool,
}

impl<'a> CheckedPath<'a> {
  pub fn unsafe_new(path: Cow<'a, Path>) -> Self {
    Self {
      path: PathWithRequested {
        path,
        requested: None,
      },
      canonicalized: false,
    }
  }

  pub fn canonicalized(&self) -> bool {
    self.canonicalized
  }

  pub fn display(&self) -> std::path::Display<'_> {
    self.path.display()
  }

  pub fn into_path_with_requested(self) -> PathWithRequested<'a> {
    self.path
  }

  pub fn as_owned(&self) -> CheckedPathBuf {
    CheckedPathBuf {
      path: self.path.as_owned(),
      canonicalized: self.canonicalized,
    }
  }

  pub fn into_owned(self) -> CheckedPathBuf {
    CheckedPathBuf {
      path: self.path.into_owned(),
      canonicalized: self.canonicalized,
    }
  }

  pub fn into_path(self) -> Cow<'a, Path> {
    self.path.path
  }

  pub fn into_owned_path(self) -> PathBuf {
    self.path.path.into_owned()
  }
}

impl<'a> AsRef<PathWithRequested<'a>> for CheckedPath<'a> {
  fn as_ref(&self) -> &PathWithRequested<'a> {
    &self.path
  }
}

impl Deref for CheckedPath<'_> {
  type Target = Path;

  fn deref(&self) -> &Self::Target {
    &self.path.path
  }
}

impl AsRef<Path> for CheckedPath<'_> {
  fn as_ref(&self) -> &Path {
    &self.path.path
  }
}

#[derive(Debug, Clone)]
pub struct CheckedPathBuf {
  path: PathBufWithRequested,
  canonicalized: bool,
}

impl CheckedPathBuf {
  pub fn unsafe_new(path: PathBuf) -> Self {
    Self {
      path: PathBufWithRequested::only_path(path),
      canonicalized: false,
    }
  }

  pub fn as_checked_path(&self) -> CheckedPath<'_> {
    CheckedPath {
      path: self.path.as_path_with_requested(),
      canonicalized: self.canonicalized,
    }
  }

  pub fn into_path_buf(self) -> PathBuf {
    self.path.path
  }
}

impl Deref for CheckedPathBuf {
  type Target = Path;

  fn deref(&self) -> &Self::Target {
    &self.path.path
  }
}

impl AsRef<Path> for CheckedPathBuf {
  fn as_ref(&self) -> &Path {
    &self.path.path
  }
}

/// `AllowPartial` prescribes how to treat a permission which is partially
/// denied due to a `--deny-*` flag affecting a subscope of the queried
/// permission.
///
/// `TreatAsGranted` is used in place of `TreatAsPartialGranted` when we don't
/// want to wastefully check for partial denials when, say, checking read
/// access for a file.
#[derive(Debug, Copy, Clone, Eq, PartialEq)]
#[allow(clippy::enum_variant_names, reason = "more clear")]
enum AllowPartial {
  TreatAsGranted,
  TreatAsDenied,
  TreatAsPartialGranted,
}

impl From<bool> for AllowPartial {
  fn from(value: bool) -> Self {
    if value {
      Self::TreatAsGranted
    } else {
      Self::TreatAsDenied
    }
  }
}

struct PromptOptions<'a> {
  name: &'static str,
  msg: &'a str,
  api_name: Option<&'a str>,
  info: Option<&'a str>,
  is_unary: bool,
}

impl PermissionState {
  #[inline(always)]
  fn log_perm_access(
    name: &'static str,
    info: impl FnOnce() -> Option<String>,
  ) {
    // Eliminates log overhead (when logging is disabled),
    // log_enabled!(Debug) check in a hot path still has overhead
    // TODO(AaronO): generalize or upstream this optimization
    if *DEBUG_LOG_ENABLED {
      log::debug!(
        "{}",
        colors::bold(&format!(
          "{}️  Granted {}",
          PERMISSION_EMOJI,
          Self::fmt_access(name, info().as_deref())
        ))
      );
    }
  }

  fn fmt_access(name: &'static str, info: Option<&str>) -> String {
    format!(
      "{} access{}",
      name,
      info.map(|info| format!(" to {info}")).unwrap_or_default(),
    )
  }

  fn permission_denied_error(
    name: &'static str,
    info: Option<&str>,
    state: PermissionState,
  ) -> PermissionDeniedError {
    PermissionDeniedError {
      access: Self::fmt_access(name, info),
      name,
      custom_message: None,
      state,
    }
  }

  fn prompt(
    options: PromptOptions<'_>,
  ) -> (Result<(), PermissionDeniedError>, bool) {
    let PromptOptions {
      name,
      msg,
      api_name,
      info,
      is_unary,
    } = options;
    match permission_prompt(msg, name, api_name, is_unary) {
      PromptResponse::Allow => {
        Self::log_perm_access(name, || info.map(|i| i.to_string()));
        (Ok(()), false)
      }
      PromptResponse::AllowAll => {
        Self::log_perm_access(name, || info.map(|i| i.to_string()));
        (Ok(()), true)
      }
      PromptResponse::Deny => (
        Err(Self::permission_denied_error(
          name,
          info,
          PermissionState::Denied,
        )),
        false,
      ),
    }
  }

  #[inline]
  fn check(
    self,
    name: &'static str,
    api_name: Option<&str>,
    stringify_value_fn: impl Fn() -> Option<String>,
    info: impl Fn() -> Option<String>,
    prompt: bool,
  ) -> (Result<(), PermissionDeniedError>, bool, bool) {
    if let Some(resp) = maybe_check_with_broker(name, &stringify_value_fn) {
      match resp {
        BrokerResponse::Allow => {
          Self::log_perm_access(name, info);
          return (Ok(()), false, false);
        }
        BrokerResponse::Deny { message } => {
          return (
            Err(PermissionDeniedError {
              access: Self::fmt_access(name, info().as_deref()),
              name,
              custom_message: message,
              state: PermissionState::Denied,
            }),
            false,
            false,
          );
        }
      }
    }

    match self {
      PermissionState::Granted => {
        Self::log_perm_access(name, info);
        (Ok(()), false, false)
      }
      PermissionState::Prompt if prompt => {
        let info = info();
        let msg = StringBuilder::<String>::build(|builder| {
          builder.append(name);
          builder.append(" access");
          if let Some(info) = &info {
            builder.append(" to ");
            builder.append(info);
          }
        })
        .unwrap();
        let (result, is_allow_all) = Self::prompt(PromptOptions {
          name,
          msg: &msg,
          api_name,
          info: info.as_deref(),
          is_unary: true,
        });
        (result, true, is_allow_all)
      }
      state => {
        let err = Self::permission_denied_error(name, info().as_deref(), state);
        (Err(err), false, false)
      }
    }
  }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct UnitPermission {
  pub name: &'static str,
  pub description: &'static str,
  pub state: PermissionState,
  pub prompt: bool,
}

impl UnitPermission {
  pub fn query(&self) -> PermissionState {
    self.state
  }

  pub fn request(&mut self) -> PermissionState {
    if self.state == PermissionState::Prompt {
      if PromptResponse::Allow
        == permission_prompt(
          &format!("access to {}", self.description),
          self.name,
          Some("Deno.permissions.query()"),
          false,
        )
      {
        self.state = PermissionState::Granted;
      } else {
        self.state = PermissionState::Denied;
      }
    }
    self.state
  }

  pub fn revoke(&mut self) -> PermissionState {
    if self.state == PermissionState::Granted {
      self.state = PermissionState::Prompt;
    }
    self.state
  }

  pub fn check(
    &mut self,
    stringify_value_fn: impl Fn() -> Option<String>,
    info: impl Fn() -> Option<String>,
  ) -> Result<(), PermissionDeniedError> {
    let (result, prompted, _is_allow_all) =
      self
        .state
        .check(self.name, None, stringify_value_fn, info, self.prompt);
    if prompted {
      if result.is_ok() {
        self.state = PermissionState::Granted;
      } else {
        self.state = PermissionState::Denied;
      }
    }
    result
  }
}

/// A normalized environment variable name. On Windows this will
/// be uppercase and on other platforms it will stay as-is.
#[derive(Clone, Eq, PartialEq, Hash, Debug, Ord, PartialOrd)]
pub struct EnvVarName {
  inner: String,
}

impl EnvVarName {
  pub fn new(env: Cow<'_, str>) -> Self {
    EnvVarNameRef::new(env).into_owned()
  }

  pub fn as_env_var_name_ref(&self) -> EnvVarNameRef<'static> {
    EnvVarNameRef {
      inner: Cow::Owned(self.inner.clone()),
    }
  }
}

impl AsRef<str> for EnvVarName {
  fn as_ref(&self) -> &str {
    self.inner.as_ref()
  }
}

/// A normalized environment variable name. On Windows this will
/// be uppercase and on other platforms it will stay as-is.
#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub struct EnvVarNameRef<'a> {
  inner: Cow<'a, str>,
}

impl<'a> EnvVarNameRef<'a> {
  pub fn new(env: Cow<'a, str>) -> Self {
    Self {
      inner: if cfg!(windows) {
        Cow::Owned(env.to_uppercase())
      } else {
        env
      },
    }
  }

  pub fn into_owned(self) -> EnvVarName {
    EnvVarName {
      inner: self.inner.into_owned(),
    }
  }
}

impl AsRef<str> for EnvVarNameRef<'_> {
  fn as_ref(&self) -> &str {
    self.inner.as_ref()
  }
}

impl PartialEq<EnvVarNameRef<'_>> for EnvVarName {
  fn eq(&self, other: &EnvVarNameRef<'_>) -> bool {
    self.inner == other.inner
  }
}

pub trait AllowDescriptor: Debug + Eq + Clone + Hash {
  type QueryDesc<'a>: QueryDescriptor<AllowDesc = Self, DenyDesc = Self::DenyDesc>;
  type DenyDesc: DenyDescriptor;

  fn cmp_allow(&self, other: &Self) -> Ordering;
  fn cmp_deny(&self, other: &Self::DenyDesc) -> Ordering;
}

pub trait DenyDescriptor: Debug + Eq + Clone + Hash {
  fn cmp_deny(&self, other: &Self) -> Ordering;
}

pub trait QueryDescriptor: Debug {
  type AllowDesc: AllowDescriptor;
  type DenyDesc: DenyDescriptor;

  fn flag_name() -> &'static str;
  fn display_name(&self) -> Cow<'_, str>;

  fn from_allow(allow: &Self::AllowDesc) -> Self;

  fn as_allow(&self) -> Option<Self::AllowDesc>;
  fn as_deny(&self) -> Self::DenyDesc;

  /// Generic check function to check this descriptor against a `UnaryPermission`.
  fn check_in_permission(
    &self,
    perm: &mut UnaryPermission<Self::AllowDesc>,
    api_name: Option<&str>,
  ) -> Result<(), PermissionDeniedError>;

  fn matches_allow(&self, other: &Self::AllowDesc) -> bool;
  fn matches_deny(&self, other: &Self::DenyDesc) -> bool;

  /// Gets if this query descriptor should revoke the provided allow descriptor.
  fn revokes(&self, other: &Self::AllowDesc) -> bool;
  fn stronger_than_deny(&self, other: &Self::DenyDesc) -> bool;
  fn overlaps_deny(&self, other: &Self::DenyDesc) -> bool;
}

fn format_display_name(display_name: Cow<'_, str>) -> Cow<'_, str> {
  if display_name.starts_with('<') && display_name.ends_with('>') {
    display_name
  } else {
    Cow::Owned(format!("\"{}\"", display_name))
  }
}

#[derive(Debug, Clone, Eq, PartialEq)]
enum AllowOrDenyDescRef<'a, TAllowDesc: AllowDescriptor> {
  Allow(&'a TAllowDesc),
  Deny {
    desc: &'a TAllowDesc::DenyDesc,
    order: u8,
  },
}

#[derive(Debug, Clone, Eq, PartialEq)]
enum UnaryPermissionDesc<TAllowDesc: AllowDescriptor> {
  Granted(TAllowDesc),
  FlagDenied(TAllowDesc::DenyDesc),
  FlagIgnored(TAllowDesc::DenyDesc),
  PromptDenied(TAllowDesc::DenyDesc),
}

impl<TAllowDesc: AllowDescriptor> std::cmp::PartialOrd
  for UnaryPermissionDesc<TAllowDesc>
{
  fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
    Some(self.cmp(other))
  }
}

impl<TAllowDesc: AllowDescriptor> std::cmp::Ord
  for UnaryPermissionDesc<TAllowDesc>
{
  fn cmp(&self, other: &Self) -> Ordering {
    match self.allow_or_deny_desc() {
      AllowOrDenyDescRef::Allow(self_desc) => {
        match other.allow_or_deny_desc() {
          AllowOrDenyDescRef::Allow(other_desc) => {
            self_desc.cmp_allow(other_desc)
          }
          AllowOrDenyDescRef::Deny {
            desc: other_desc, ..
          } => match self_desc.cmp_deny(other_desc) {
            Ordering::Equal => {
              self.kind_precedence().cmp(&other.kind_precedence())
            }
            ord => ord,
          },
        }
      }
      AllowOrDenyDescRef::Deny {
        desc: self_desc,
        order: self_order,
      } => {
        match other.allow_or_deny_desc() {
          AllowOrDenyDescRef::Allow(other_desc) => {
            match other_desc.cmp_deny(self_desc) {
              Ordering::Equal => {
                self.kind_precedence().cmp(&other.kind_precedence())
              }
              // flip because we compared the other to self above
              Ordering::Less => Ordering::Greater,
              Ordering::Greater => Ordering::Less,
            }
          }
          AllowOrDenyDescRef::Deny {
            desc: other_desc,
            order: other_order,
          } => match self_desc.cmp_deny(other_desc) {
            Ordering::Equal => self_order.cmp(&other_order),
            ordering => ordering,
          },
        }
      }
    }
  }
}

impl<TAllowDesc: AllowDescriptor> UnaryPermissionDesc<TAllowDesc> {
  fn allow_or_deny_desc(&self) -> AllowOrDenyDescRef<'_, TAllowDesc> {
    match self {
      UnaryPermissionDesc::Granted(desc) => AllowOrDenyDescRef::Allow(desc),
      UnaryPermissionDesc::FlagDenied(desc) => {
        AllowOrDenyDescRef::Deny { desc, order: 0 }
      }
      UnaryPermissionDesc::PromptDenied(desc) => {
        AllowOrDenyDescRef::Deny { desc, order: 1 }
      }
      UnaryPermissionDesc::FlagIgnored(desc) => {
        AllowOrDenyDescRef::Deny { desc, order: 2 }
      }
    }
  }

  fn kind_precedence(&self) -> u8 {
    match self {
      UnaryPermissionDesc::FlagDenied(_) => 0,
      UnaryPermissionDesc::PromptDenied(_) => 1,
      UnaryPermissionDesc::FlagIgnored(_) => 2,
      UnaryPermissionDesc::Granted(_) => 3,
    }
  }
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct UnaryPermissionDescriptors<TAllowDesc: AllowDescriptor> {
  inner: Vec<UnaryPermissionDesc<TAllowDesc>>,
  has_flag_denied: bool,
  has_prompt_denied: bool,
  has_flag_ignored: bool,
}

impl<TAllowDesc: AllowDescriptor> Default
  for UnaryPermissionDescriptors<TAllowDesc>
{
  fn default() -> Self {
    Self {
      inner: Default::default(),
      has_flag_denied: false,
      has_prompt_denied: false,
      has_flag_ignored: false,
    }
  }
}

impl<TAllowDesc: AllowDescriptor> UnaryPermissionDescriptors<TAllowDesc> {
  pub fn with_capacity(capacity: usize) -> Self {
    Self {
      inner: Vec::with_capacity(capacity),
      ..Default::default()
    }
  }

  pub fn iter(&self) -> impl Iterator<Item = &UnaryPermissionDesc<TAllowDesc>> {
    self.inner.iter()
  }

  pub fn has_any_denied_or_ignored(&self) -> bool {
    self.has_flag_denied || self.has_prompt_denied || self.has_flag_ignored
  }

  pub fn has_prompt_denied(&self) -> bool {
    self.has_prompt_denied
  }

  pub fn insert(&mut self, item: UnaryPermissionDesc<TAllowDesc>) {
    match &item {
      UnaryPermissionDesc::Granted(_) => {}
      UnaryPermissionDesc::FlagDenied(_) => {
        self.has_flag_denied = true;
      }
      UnaryPermissionDesc::FlagIgnored(_) => {
        self.has_flag_ignored = true;
      }
      UnaryPermissionDesc::PromptDenied(_) => {
        self.has_prompt_denied = true;
      }
    }
    if let Err(insert_index) = self.inner.binary_search(&item) {
      self.inner.insert(insert_index, item);
    }
  }

  pub fn revoke_granted(&mut self, desc: &TAllowDesc::QueryDesc<'_>) {
    self.inner.retain(|v| match v {
      UnaryPermissionDesc::Granted(v) => !desc.revokes(v),
      UnaryPermissionDesc::FlagDenied(_)
      | UnaryPermissionDesc::FlagIgnored(_)
      | UnaryPermissionDesc::PromptDenied(_) => true,
    })
  }

  pub fn revoke_all_granted(&mut self) {
    self.inner.retain(|v| match v {
      UnaryPermissionDesc::Granted(_) => false,
      UnaryPermissionDesc::FlagDenied(_)
      | UnaryPermissionDesc::FlagIgnored(_)
      | UnaryPermissionDesc::PromptDenied(_) => true,
    })
  }
}

#[derive(Debug, Eq, PartialEq)]
pub struct UnaryPermission<TAllowDesc: AllowDescriptor> {
  granted_global: bool,
  flag_denied_global: bool,
  flag_ignored_global: bool,
  prompt_denied_global: bool,
  descriptors: UnaryPermissionDescriptors<TAllowDesc>,
  prompt: bool,
}

impl<TAllowDesc: AllowDescriptor> Default for UnaryPermission<TAllowDesc> {
  fn default() -> Self {
    UnaryPermission {
      granted_global: Default::default(),
      flag_denied_global: Default::default(),
      flag_ignored_global: Default::default(),
      prompt_denied_global: Default::default(),
      descriptors: Default::default(),
      prompt: Default::default(),
    }
  }
}

impl<TAllowDesc: AllowDescriptor> Clone for UnaryPermission<TAllowDesc> {
  fn clone(&self) -> Self {
    Self {
      granted_global: self.granted_global,
      flag_denied_global: self.flag_denied_global,
      flag_ignored_global: self.flag_ignored_global,
      prompt_denied_global: self.prompt_denied_global,
      descriptors: self.descriptors.clone(),
      prompt: self.prompt,
    }
  }
}

impl<
  TAllowDesc: AllowDescriptor<DenyDesc = TDenyDesc>,
  TDenyDesc: DenyDescriptor,
> UnaryPermission<TAllowDesc>
{
  pub fn allow_all() -> Self {
    Self {
      granted_global: true,
      ..Default::default()
    }
  }

  pub fn is_allow_all(&self) -> bool {
    self.granted_global
      && !self.flag_denied_global
      && !self.prompt_denied_global
      && !self.flag_ignored_global
      && !self.descriptors.has_any_denied_or_ignored()
      && !has_broker()
  }

  pub fn check_all_api(
    &mut self,
    api_name: Option<&str>,
  ) -> Result<(), PermissionDeniedError> {
    audit_and_skip_check_if_is_permission_fully_granted!(
      self,
      TAllowDesc::QueryDesc::flag_name(),
      ()
    );
    self.check_desc(None, false, api_name)
  }

  fn check_desc(
    &mut self,
    desc: Option<&TAllowDesc::QueryDesc<'_>>,
    assert_non_partial: bool,
    api_name: Option<&str>,
  ) -> Result<(), PermissionDeniedError> {
    let (result, prompted, is_allow_all) = self
      .query_desc(desc, AllowPartial::from(!assert_non_partial))
      .check(
        TAllowDesc::QueryDesc::flag_name(),
        api_name,
        || desc.map(|d| d.display_name().to_string()),
        || desc.map(|d| format_display_name(d.display_name()).into_owned()),
        self.prompt,
      );
    if prompted {
      if result.is_ok() {
        if is_allow_all {
          self.insert_granted(None);
        } else {
          self.insert_granted(desc);
        }
      } else {
        self.insert_prompt_denied(desc.map(|d| d.as_deny()));
      }
    }
    result
  }

  fn query_desc(
    &self,
    desc: Option<&TAllowDesc::QueryDesc<'_>>,
    allow_partial: AllowPartial,
  ) -> PermissionState {
    if let Some(state) =
      self.query_allowed_desc_for_exact_match(desc, allow_partial)
    {
      state
    } else if self.flag_ignored_global {
      PermissionState::Ignored
    } else if matches!(allow_partial, AllowPartial::TreatAsDenied)
      && self.is_partial_flag_denied(desc)
    {
      PermissionState::DeniedPartial
    } else if self.flag_denied_global
      || desc.is_none()
        && (self.prompt_denied_global || self.descriptors.has_prompt_denied())
    {
      PermissionState::Denied
    } else if self.granted_global {
      self.query_allowed_desc(desc, allow_partial)
    } else {
      PermissionState::Prompt
    }
  }

  fn query_allowed_desc_for_exact_match(
    &self,
    desc: Option<&TAllowDesc::QueryDesc<'_>>,
    allow_partial: AllowPartial,
  ) -> Option<PermissionState> {
    let desc = desc?;
    for item in self.descriptors.iter() {
      match item {
        UnaryPermissionDesc::Granted(v) => {
          if desc.matches_allow(v) {
            return Some(self.query_allowed_desc(Some(desc), allow_partial));
          }
        }
        UnaryPermissionDesc::FlagDenied(v) => {
          if desc.matches_deny(v) {
            return Some(PermissionState::Denied);
          }
        }
        UnaryPermissionDesc::FlagIgnored(v) => {
          if desc.matches_deny(v) {
            return Some(PermissionState::Ignored);
          }
        }
        UnaryPermissionDesc::PromptDenied(v) => {
          if desc.stronger_than_deny(v) {
            return Some(PermissionState::Denied);
          }
        }
      }
    }
    None
  }

  fn query_allowed_desc(
    &self,
    desc: Option<&TAllowDesc::QueryDesc<'_>>,
    allow_partial: AllowPartial,
  ) -> PermissionState {
    match allow_partial {
      AllowPartial::TreatAsGranted => PermissionState::Granted,
      AllowPartial::TreatAsDenied => {
        if self.is_partial_flag_denied(desc) {
          PermissionState::DeniedPartial
        } else {
          PermissionState::Granted
        }
      }
      AllowPartial::TreatAsPartialGranted => {
        if self.is_partial_flag_denied(desc) {
          PermissionState::GrantedPartial
        } else {
          PermissionState::Granted
        }
      }
    }
  }

  fn request_desc(
    &mut self,
    desc: Option<&TAllowDesc::QueryDesc<'_>>,
  ) -> PermissionState {
    let state = self.query_desc(desc, AllowPartial::TreatAsPartialGranted);
    if state == PermissionState::Granted {
      self.insert_granted(desc);
      return state;
    }
    if state != PermissionState::Prompt {
      return state;
    }
    if !self.prompt {
      return PermissionState::Denied;
    }
    let maybe_formatted_display_name =
      desc.map(|d| format_display_name(d.display_name()));
    let message = StringBuilder::<String>::build(|builder| {
      builder.append(TAllowDesc::QueryDesc::flag_name());
      builder.append(" access");
      if let Some(display_name) = &maybe_formatted_display_name {
        builder.append(" to ");
        builder.append(display_name)
      }
    })
    .unwrap();
    match permission_prompt(
      &message,
      TAllowDesc::QueryDesc::flag_name(),
      Some("Deno.permissions.request()"),
      true,
    ) {
      PromptResponse::Allow => {
        self.insert_granted(desc);
        PermissionState::Granted
      }
      PromptResponse::Deny => {
        self.insert_prompt_denied(desc.map(|d| d.as_deny()));
        PermissionState::Denied
      }
      PromptResponse::AllowAll => {
        self.insert_granted(None);
        PermissionState::Granted
      }
    }
  }

  fn revoke_desc(
    &mut self,
    desc: Option<&TAllowDesc::QueryDesc<'_>>,
  ) -> PermissionState {
    match desc {
      Some(desc) => {
        self.descriptors.revoke_granted(desc);
      }
      None => {
        self.granted_global = false;
        // Revoke global is a special case where the entire granted list is
        // cleared. It's inconsistent with the granular case where only
        // descriptors stronger than the revoked one are purged.
        self.descriptors.revoke_all_granted();
      }
    }
    self.query_desc(desc, AllowPartial::TreatAsPartialGranted)
  }

  fn is_partial_flag_denied(
    &self,
    query: Option<&TAllowDesc::QueryDesc<'_>>,
  ) -> bool {
    match query {
      None => {
        self.descriptors.has_flag_denied || self.descriptors.has_flag_ignored
      }
      Some(query) => self.descriptors.iter().any(|desc| match desc {
        UnaryPermissionDesc::FlagIgnored(v)
        | UnaryPermissionDesc::FlagDenied(v) => query.overlaps_deny(v),
        UnaryPermissionDesc::Granted(_)
        | UnaryPermissionDesc::PromptDenied(_) => false,
      }),
    }
  }

  fn insert_granted(
    &mut self,
    query: Option<&TAllowDesc::QueryDesc<'_>>,
  ) -> bool {
    let desc = match query.map(|q| q.as_allow()) {
      Some(Some(allow_desc)) => Some(allow_desc),
      Some(None) => {
        // the user was prompted for this descriptor in order to not
        // expose anything about the system to the program, but the
        // descriptor wasn't valid so no permission was raised
        return false;
      }
      None => None,
    };
    Self::list_insert(
      desc.map(UnaryPermissionDesc::Granted),
      &mut self.granted_global,
      &mut self.descriptors,
    );
    true
  }

  fn insert_prompt_denied(&mut self, desc: Option<TDenyDesc>) {
    Self::list_insert(
      desc.map(UnaryPermissionDesc::PromptDenied),
      &mut self.prompt_denied_global,
      &mut self.descriptors,
    );
  }

  fn list_insert(
    desc: Option<UnaryPermissionDesc<TAllowDesc>>,
    list_global: &mut bool,
    descriptors: &mut UnaryPermissionDescriptors<TAllowDesc>,
  ) {
    match desc {
      Some(desc) => {
        descriptors.insert(desc);
      }
      None => *list_global = true,
    }
  }

  fn create_child_permissions<E>(
    &mut self,
    flag: ChildUnaryPermissionArg,
    parse: impl Fn(&str) -> Result<Option<TAllowDesc>, E>,
  ) -> Result<UnaryPermission<TAllowDesc>, ChildPermissionError>
  where
    ChildPermissionError: From<E>,
  {
    let mut perms = Self::default();

    match flag {
      ChildUnaryPermissionArg::Inherit => {
        perms.clone_from(self);
      }
      ChildUnaryPermissionArg::Granted => {
        if self.check_all_api(None).is_err() {
          return Err(ChildPermissionError::Escalation);
        }
        perms.granted_global = true;
      }
      ChildUnaryPermissionArg::NotGranted => {}
      ChildUnaryPermissionArg::GrantedList(granted_list) => {
        for result in granted_list.iter().filter_map(|i| parse(i).transpose()) {
          let desc = result?;
          if TAllowDesc::QueryDesc::from_allow(&desc)
            .check_in_permission(self, None)
            .is_err()
          {
            return Err(ChildPermissionError::Escalation);
          }
          perms.descriptors.insert(UnaryPermissionDesc::Granted(desc));
        }
      }
    }
    perms.flag_denied_global = self.flag_denied_global;
    perms.prompt_denied_global = self.prompt_denied_global;
    perms.prompt = self.prompt;
    perms.flag_ignored_global = self.flag_ignored_global;
    for item in self.descriptors.iter() {
      match item {
        UnaryPermissionDesc::Granted(_) => {
          // ignore
        }
        UnaryPermissionDesc::FlagDenied(_)
        | UnaryPermissionDesc::FlagIgnored(_)
        | UnaryPermissionDesc::PromptDenied(_) => {
          perms.descriptors.insert(item.clone());
        }
      }
    }

    Ok(perms)
  }
}

#[derive(Clone, Debug)]
pub struct PathQueryDescriptor<'a> {
  path: Cow<'a, Path>,
  /// Lowercased on Windows for case-insensitive comparison; same as `path` on
  /// other platforms. Used by PartialEq, starts_with, etc.
  cmp_path: PathBuf,
  /// Custom requested display name when differs from resolved.
  requested: Option<String>,
  is_windows_device_path: bool,
}

impl PartialEq for PathQueryDescriptor<'_> {
  fn eq(&self, other: &Self) -> bool {
    self.cmp_path == other.cmp_path
  }
}

impl Eq for PathQueryDescriptor<'_> {}

impl PartialEq<PathDescriptor> for PathQueryDescriptor<'_> {
  fn eq(&self, other: &PathDescriptor) -> bool {
    self.cmp_path == other.cmp_path
  }
}

/// Returns a normalized copy of the path for filesystem-aware comparison.
///
/// - Windows (NTFS): ASCII-lowercased for case-insensitive matching.
/// - macOS (APFS/HFS+): NFKD-normalized and Unicode-case-folded, because
///   APFS resolves Unicode-equivalent and case-differing paths to the same
///   inode (e.g. `ß`/`ss`, `ﬁ`/`fi`, NFC/NFD forms, upper/lower).
/// - Other platforms: returns a clone (case-sensitive, no normalization).
#[inline]
#[cfg(windows)]
fn comparison_path(path: &Path) -> PathBuf {
  PathBuf::from(path.to_string_lossy().to_ascii_lowercase())
}

#[inline]
#[cfg(target_os = "macos")]
fn comparison_path(path: &Path) -> PathBuf {
  use unicode_normalization::UnicodeNormalization;
  // NFKD handles canonical decomposition (NFC->NFD) and compatibility
  // decomposition (ligatures like fi->fi). Uppercase then lowercase
  // approximates Unicode case folding (maps ss->SS->ss, etc.).
  let s = path.to_string_lossy();
  let normalized: String = s.nfkd().collect();
  PathBuf::from(normalized.to_uppercase().to_lowercase())
}

#[inline]
#[cfg(not(any(windows, target_os = "macos")))]
fn comparison_path(path: &Path) -> PathBuf {
  path.to_path_buf()
}

/// On Windows, strips a `\\?\` verbatim (extended-length) prefix from a path
/// when it can be losslessly represented without it, so that the permission
/// system treats `\\?\C:\foo` and `C:\foo` as the same path. The two forms
/// refer to the same file, so a grant for one must apply to the other (see
/// denoland/deno#18597).
///
/// `dunce::simplified` only strips the prefix when it is actually safe to do
/// so: it leaves verbatim paths that contain `.`/`..` components (taken
/// literally in verbatim mode), reserved device names (e.g. `CON`), or that
/// are too long to be expressed as a regular path, because those forms are
/// *not* equivalent to their stripped counterparts.
#[cfg(windows)]
#[inline]
fn strip_verbatim_prefix(path: Cow<'_, Path>) -> Cow<'_, Path> {
  let simplified = dunce::simplified(path.as_ref());
  if simplified.as_os_str().len() == path.as_os_str().len() {
    path
  } else {
    Cow::Owned(simplified.to_path_buf())
  }
}

#[cfg(not(windows))]
#[inline]
fn strip_verbatim_prefix(path: Cow<'_, Path>) -> Cow<'_, Path> {
  path
}

impl<'a> PathQueryDescriptor<'a> {
  pub fn new(
    sys: &impl sys_traits::EnvCurrentDir,
    path: Cow<'a, Path>,
  ) -> Result<Self, PathResolveError> {
    let path_bytes = path.as_os_str().as_encoded_bytes();
    if path_bytes.is_empty() {
      return Err(PathResolveError::EmptyPath);
    }
    let path = strip_verbatim_prefix(path);
    let path_bytes = path.as_os_str().as_encoded_bytes();
    let is_windows_device_path = cfg!(windows)
      && path_bytes.starts_with(br"\\.\")
      && !path_bytes.contains(&b':');
    let (path, requested) = if is_windows_device_path {
      // On Windows, normalize_path doesn't work with device-prefix-style
      // paths. We pass these through.
      (path, None)
    } else if path.is_absolute() {
      (normalize_path(path), None)
    } else {
      let cwd = sys
        .env_current_dir()
        .map_err(PathResolveError::CwdResolve)?;
      (
        normalize_path(Cow::Owned(cwd.join(path.as_ref()))),
        Some(path.to_string_lossy().into_owned()),
      )
    };
    let cmp_path = comparison_path(&path);
    Ok(Self {
      path,
      cmp_path,
      requested,
      is_windows_device_path,
    })
  }

  pub fn new_known_absolute(path: Cow<'a, Path>) -> Self {
    let path = strip_verbatim_prefix(path);
    let path_bytes = path.as_os_str().as_encoded_bytes();
    let is_windows_device_path = cfg!(windows)
      && path_bytes.starts_with(br"\\.\")
      && !path_bytes.contains(&b':');
    let path = if is_windows_device_path {
      // On Windows, normalize_path doesn't work with device-prefix-style
      // paths. We pass these through.
      path
    } else {
      normalize_path(path)
    };
    let cmp_path = comparison_path(&path);
    Self {
      path,
      cmp_path,
      requested: None,
      is_windows_device_path,
    }
  }

  pub fn with_requested(self, requested: String) -> Self {
    Self {
      requested: Some(requested),
      ..self
    }
  }

  pub fn starts_with(&self, base: &PathDescriptor) -> bool {
    self.cmp_path.starts_with(&base.cmp_path)
  }

  pub fn display_name(&self) -> Cow<'_, str> {
    match &self.requested {
      Some(requested) => Cow::Borrowed(requested.as_str()),
      None => self.path.to_string_lossy(),
    }
  }

  pub fn as_descriptor(&self) -> PathDescriptor {
    PathDescriptor {
      path: self.path.to_path_buf(),
      cmp_path: self.cmp_path.clone(),
      requested: self.requested.clone(),
      is_windows_device_path: self.is_windows_device_path,
    }
  }

  pub fn into_descriptor(self) -> PathDescriptor {
    PathDescriptor {
      path: self.path.into_owned(),
      cmp_path: self.cmp_path,
      requested: self.requested,
      is_windows_device_path: self.is_windows_device_path,
    }
  }

  pub fn into_ffi(self) -> FfiQueryDescriptor<'a> {
    FfiQueryDescriptor(self)
  }

  pub fn into_read(self) -> ReadQueryDescriptor<'a> {
    ReadQueryDescriptor(self)
  }

  pub fn into_write(self) -> WriteQueryDescriptor<'a> {
    WriteQueryDescriptor(self)
  }
}

#[derive(Clone, Debug)]
pub struct ReadQueryDescriptor<'a>(pub PathQueryDescriptor<'a>);

impl QueryDescriptor for ReadQueryDescriptor<'_> {
  type AllowDesc = ReadDescriptor;
  type DenyDesc = ReadDescriptor;

  fn flag_name() -> &'static str {
    "read"
  }

  fn display_name(&self) -> Cow<'_, str> {
    self.0.display_name()
  }

  fn from_allow(allow: &Self::AllowDesc) -> Self {
    allow.0.as_query_descriptor().into_read()
  }

  fn as_allow(&self) -> Option<Self::AllowDesc> {
    Some(self.0.as_descriptor().into_read())
  }

  fn as_deny(&self) -> Self::DenyDesc {
    self.0.as_descriptor().into_read()
  }

  fn check_in_permission(
    &self,
    perm: &mut UnaryPermission<Self::AllowDesc>,
    api_name: Option<&str>,
  ) -> Result<(), PermissionDeniedError> {
    audit_and_skip_check_if_is_permission_fully_granted!(
      perm,
      Self::flag_name(),
      ()
    );
    perm.check_desc(Some(self), true, api_name)
  }

  fn matches_allow(&self, other: &Self::AllowDesc) -> bool {
    self.0.starts_with(&other.0)
  }

  fn matches_deny(&self, other: &Self::DenyDesc) -> bool {
    self.0.starts_with(&other.0)
  }

  fn revokes(&self, other: &Self::AllowDesc) -> bool {
    self.matches_allow(other)
  }

  fn stronger_than_deny(&self, other: &Self::DenyDesc) -> bool {
    other.0.starts_with(&self.0)
  }

  fn overlaps_deny(&self, other: &Self::DenyDesc) -> bool {
    self.stronger_than_deny(other)
  }
}

#[derive(Clone, Debug)]
pub struct PathDescriptor {
  path: PathBuf,
  /// Lowercased on Windows for case-insensitive comparison; same as `path` on
  /// other platforms. Used by PartialEq, Hash, starts_with, cmp_*.
  cmp_path: PathBuf,
  /// Custom requested display name when differs from resolved.
  requested: Option<String>,
  is_windows_device_path: bool,
}

impl PartialEq for PathDescriptor {
  fn eq(&self, other: &Self) -> bool {
    self.cmp_path == other.cmp_path
  }
}

impl Eq for PathDescriptor {}

impl Hash for PathDescriptor {
  fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
    self.cmp_path.hash(state);
  }
}

impl PathDescriptor {
  pub fn new(
    sys: &impl sys_traits::EnvCurrentDir,
    path: Cow<'_, Path>,
  ) -> Result<Self, PathResolveError> {
    PathQueryDescriptor::new(sys, path).map(|p| p.into_descriptor())
  }

  pub fn new_known_cwd(path: Cow<'_, Path>, cwd: &Path) -> Self {
    let path = strip_verbatim_prefix(path);
    let path_bytes = path.as_os_str().as_encoded_bytes();
    let is_windows_device_path = cfg!(windows)
      && path_bytes.starts_with(br"\\.\")
      && !path_bytes.contains(&b':');
    let (path, display) = if is_windows_device_path {
      // On Windows, normalize_path doesn't work with device-prefix-style
      // paths. We pass these through.
      (path, None)
    } else if path.is_absolute() {
      (normalize_path(path), None)
    } else {
      (
        normalize_path(Cow::Owned(cwd.join(path.as_ref()))),
        Some(path.to_string_lossy().into_owned()),
      )
    };
    let cmp_path = comparison_path(&path);
    Self {
      path: path.into_owned(),
      cmp_path,
      requested: display,
      is_windows_device_path,
    }
  }

  pub fn new_known_absolute(path: Cow<'_, Path>) -> Self {
    PathQueryDescriptor::new_known_absolute(path).into_descriptor()
  }

  pub fn starts_with(&self, base: &PathQueryDescriptor) -> bool {
    self.cmp_path.starts_with(&base.cmp_path)
  }

  pub fn display_name(&self) -> Cow<'_, str> {
    match &self.requested {
      Some(requested) => Cow::Borrowed(requested.as_str()),
      None => self.path.to_string_lossy(),
    }
  }

  pub fn as_query_descriptor(&self) -> PathQueryDescriptor<'static> {
    PathQueryDescriptor {
      path: Cow::Owned(self.path.clone()),
      cmp_path: self.cmp_path.clone(),
      requested: self.requested.clone(),
      is_windows_device_path: self.is_windows_device_path,
    }
  }

  pub fn into_ffi(self) -> FfiDescriptor {
    FfiDescriptor(self)
  }

  pub fn into_read(self) -> ReadDescriptor {
    ReadDescriptor(self)
  }

  pub fn into_write(self) -> WriteDescriptor {
    WriteDescriptor(self)
  }

  pub fn into_path_buf(self) -> PathBuf {
    self.path
  }

  fn cmp_allow_allow(&self, other: &PathDescriptor) -> Ordering {
    if self.cmp_path == other.cmp_path {
      Ordering::Equal
    } else if other.cmp_path.starts_with(&self.cmp_path) {
      Ordering::Greater
    } else if self.cmp_path.starts_with(&other.cmp_path) {
      Ordering::Less
    } else {
      self.cmp_path.cmp(&other.cmp_path)
    }
  }

  fn cmp_allow_deny(&self, other: &PathDescriptor) -> Ordering {
    if other.cmp_path.starts_with(&self.cmp_path) {
      Ordering::Greater
    } else if self.cmp_path.starts_with(&other.cmp_path) {
      Ordering::Less
    } else {
      Ordering::Greater
    }
  }

  fn cmp_deny_deny(&self, other: &PathDescriptor) -> Ordering {
    self.cmp_allow_allow(other)
  }
}

#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub struct ReadDescriptor(pub PathDescriptor);

impl AllowDescriptor for ReadDescriptor {
  type QueryDesc<'a> = ReadQueryDescriptor<'a>;
  type DenyDesc = ReadDescriptor;

  fn cmp_allow(&self, other: &Self) -> Ordering {
    self.0.cmp_allow_allow(&other.0)
  }

  fn cmp_deny(&self, other: &Self::DenyDesc) -> Ordering {
    self.0.cmp_allow_deny(&other.0)
  }
}

impl DenyDescriptor for ReadDescriptor {
  fn cmp_deny(&self, other: &Self) -> Ordering {
    self.0.cmp_deny_deny(&other.0)
  }
}

#[derive(Clone, Debug)]
pub struct WriteQueryDescriptor<'a>(pub PathQueryDescriptor<'a>);

impl QueryDescriptor for WriteQueryDescriptor<'_> {
  type AllowDesc = WriteDescriptor;
  type DenyDesc = WriteDescriptor;

  fn flag_name() -> &'static str {
    "write"
  }

  fn display_name(&self) -> Cow<'_, str> {
    self.0.display_name()
  }

  fn from_allow(allow: &Self::AllowDesc) -> Self {
    WriteQueryDescriptor(allow.0.as_query_descriptor())
  }

  fn as_allow(&self) -> Option<Self::AllowDesc> {
    Some(WriteDescriptor(self.0.as_descriptor()))
  }

  fn as_deny(&self) -> Self::DenyDesc {
    WriteDescriptor(self.0.as_descriptor())
  }

  fn check_in_permission(
    &self,
    perm: &mut UnaryPermission<Self::AllowDesc>,
    api_name: Option<&str>,
  ) -> Result<(), PermissionDeniedError> {
    audit_and_skip_check_if_is_permission_fully_granted!(
      perm,
      Self::flag_name(),
      ()
    );
    perm.check_desc(Some(self), true, api_name)
  }

  fn matches_allow(&self, other: &Self::AllowDesc) -> bool {
    self.0.starts_with(&other.0)
  }

  fn matches_deny(&self, other: &Self::DenyDesc) -> bool {
    self.0.starts_with(&other.0)
  }

  fn revokes(&self, other: &Self::AllowDesc) -> bool {
    self.matches_allow(other)
  }

  fn stronger_than_deny(&self, other: &Self::DenyDesc) -> bool {
    other.0.starts_with(&self.0)
  }

  fn overlaps_deny(&self, other: &Self::DenyDesc) -> bool {
    self.stronger_than_deny(other)
  }
}

#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub struct WriteDescriptor(pub PathDescriptor);

impl AllowDescriptor for WriteDescriptor {
  type QueryDesc<'a> = WriteQueryDescriptor<'a>;
  type DenyDesc = WriteDescriptor;

  fn cmp_allow(&self, other: &Self) -> Ordering {
    self.0.cmp_allow_allow(&other.0)
  }

  fn cmp_deny(&self, other: &Self::DenyDesc) -> Ordering {
    self.0.cmp_allow_deny(&other.0)
  }
}

impl DenyDescriptor for WriteDescriptor {
  fn cmp_deny(&self, other: &Self) -> Ordering {
    self.0.cmp_deny_deny(&other.0)
  }
}

#[derive(Debug, Default, Clone, Copy, Eq, PartialEq)]
pub enum SubdomainWildcards {
  Enabled,
  #[default]
  Disabled,
}

/// Normalize IPv4-mapped IPv6 addresses (e.g. `::ffff:127.0.0.1`) to
/// their IPv4 equivalent so that permission checks treat them identically
/// to the bare IPv4 form.
fn normalize_ip(ip: IpAddr) -> IpAddr {
  match ip {
    IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
      Some(v4) => IpAddr::V4(v4),
      None => IpAddr::V6(v6),
    },
    ip => ip,
  }
}

#[derive(Clone, Eq, PartialEq, Hash, Debug, PartialOrd, Ord)]
pub enum Host {
  Fqdn(FQDN),
  FqdnWithSubdomainWildcard(FQDN),
  Ip(IpAddr),
  Vsock(u32),
  IpSubnet(IpNet),
  UnixSocket(PathBuf),
}

#[derive(Debug, thiserror::Error, deno_error::JsError)]
#[class(uri)]
pub enum HostParseError {
  #[error("invalid IPv6 address: '{0}'")]
  InvalidIpv6(String),
  #[error("invalid host: '{0}'")]
  InvalidHost(String),
  #[error("invalid empty host: '{0}'")]
  InvalidEmptyHost(String),
  #[error("invalid host '{host}': {error}")]
  Fqdn {
    #[source]
    error: fqdn::Error,
    host: String,
  },
}

/// Strip IPv6 zone index from an address string if present.
/// (e.g., fe80::1%eth0 or fe80::1%18)
fn strip_ipv6_zone_index(addr: &str) -> &str {
  if let Some(idx) = addr.find('%') {
    &addr[..idx]
  } else {
    addr
  }
}

impl Host {
  fn parse_for_query(s: &str) -> Result<Self, HostParseError> {
    Self::parse_inner(s, SubdomainWildcards::Disabled)
  }

  #[cfg(test)]
  fn parse_for_list(s: &str) -> Result<Self, HostParseError> {
    Self::parse_inner(s, SubdomainWildcards::Enabled)
  }

  fn parse_inner(
    s: &str,
    subdomain_wildcards: SubdomainWildcards,
  ) -> Result<Self, HostParseError> {
    if s.starts_with('[') && s.ends_with(']') {
      let ip_str = &s[1..s.len() - 1];
      let ip = strip_ipv6_zone_index(ip_str)
        .parse::<Ipv6Addr>()
        .map_err(|_| HostParseError::InvalidIpv6(s.to_string()))?;
      return Ok(Host::Ip(normalize_ip(IpAddr::V6(ip))));
    }
    let (without_trailing_dot, has_trailing_dot) =
      s.strip_suffix('.').map_or((s, false), |s| (s, true));

    let ip_result =
      strip_ipv6_zone_index(without_trailing_dot).parse::<IpAddr>();

    if let Ok(ip) = ip_result {
      if has_trailing_dot {
        return Err(HostParseError::InvalidHost(
          without_trailing_dot.to_string(),
        ));
      }
      Ok(Host::Ip(normalize_ip(ip)))
    } else if let Ok(ip_subnet) = s.parse::<IpNet>() {
      Ok(Host::IpSubnet(ip_subnet))
    } else {
      let lower = if s.chars().all(|c| c.is_ascii_lowercase()) {
        Cow::Borrowed(s)
      } else {
        Cow::Owned(s.to_ascii_lowercase())
      };
      let mut host_or_suffix = lower.as_ref();
      let mut has_subdomain_wildcard = false;
      if matches!(subdomain_wildcards, SubdomainWildcards::Enabled)
        && let Some(suffix) = lower.strip_prefix("*.")
      {
        host_or_suffix = suffix;
        has_subdomain_wildcard = true;
      }
      let fqdn = {
        use std::str::FromStr;
        FQDN::from_str(host_or_suffix).map_err(|e| HostParseError::Fqdn {
          error: e,
          host: s.to_string(),
        })?
      };
      if fqdn.is_root() {
        return Err(HostParseError::InvalidEmptyHost(s.to_string()));
      }
      if has_subdomain_wildcard {
        Ok(Host::FqdnWithSubdomainWildcard(fqdn))
      } else {
        Ok(Host::Fqdn(fqdn))
      }
    }
  }

  #[cfg(test)]
  #[track_caller]
  fn must_parse(s: &str) -> Self {
    Self::parse_for_list(s).unwrap()
  }
}

#[derive(Clone, Eq, PartialEq, Hash, Debug, PartialOrd, Ord)]
pub struct NetDescriptor(pub Host, pub Option<u32>);

impl QueryDescriptor for NetDescriptor {
  type AllowDesc = NetDescriptor;
  type DenyDesc = NetDescriptor;

  fn flag_name() -> &'static str {
    "net"
  }

  fn display_name(&self) -> Cow<'_, str> {
    Cow::from(format!("{}", self))
  }

  fn from_allow(allow: &Self::AllowDesc) -> Self {
    allow.clone()
  }

  fn as_allow(&self) -> Option<Self::AllowDesc> {
    Some(self.clone())
  }

  fn as_deny(&self) -> Self::DenyDesc {
    self.clone()
  }

  fn check_in_permission(
    &self,
    perm: &mut UnaryPermission<Self::AllowDesc>,
    api_name: Option<&str>,
  ) -> Result<(), PermissionDeniedError> {
    audit_and_skip_check_if_is_permission_fully_granted!(
      perm,
      Self::flag_name(),
      ()
    );
    perm.check_desc(Some(self), false, api_name)
  }

  fn matches_allow(&self, other: &Self::AllowDesc) -> bool {
    if other.1.is_some() && self.1 != other.1 {
      return false;
    }
    match (&other.0, &self.0) {
      (Host::Fqdn(a), Host::Fqdn(b)) => a == b,
      (Host::FqdnWithSubdomainWildcard(a), Host::Fqdn(b)) => {
        b.is_subdomain_of(a)
      }
      (
        Host::FqdnWithSubdomainWildcard(a),
        Host::FqdnWithSubdomainWildcard(b),
      ) => a == b,
      (Host::Ip(a), Host::Ip(b)) => a == b,
      (Host::Vsock(a), Host::Vsock(b)) => a == b,
      (Host::UnixSocket(a), Host::UnixSocket(b)) => a == b,
      (Host::IpSubnet(a), Host::Ip(b)) => a.contains(b),
      _ => false,
    }
  }

  fn matches_deny(&self, other: &Self::DenyDesc) -> bool {
    self.matches_allow(other)
  }

  fn revokes(&self, other: &Self::AllowDesc) -> bool {
    self.matches_allow(other)
  }

  fn stronger_than_deny(&self, other: &Self::DenyDesc) -> bool {
    self.matches_deny(other)
  }

  fn overlaps_deny(&self, _other: &Self::DenyDesc) -> bool {
    false
  }
}

impl AllowDescriptor for NetDescriptor {
  type QueryDesc<'a> = NetDescriptor;
  type DenyDesc = NetDescriptor;

  fn cmp_allow(&self, other: &Self) -> Ordering {
    match (self.1.is_some(), other.1.is_some()) {
      (true, false) => Ordering::Less,
      (false, true) => Ordering::Greater,
      (true, true) | (false, false) => match self.0.cmp(&other.0) {
        Ordering::Equal => self.1.cmp(&other.1),
        ordering => ordering,
      },
    }
  }

  fn cmp_deny(&self, other: &Self::DenyDesc) -> Ordering {
    match self.cmp_allow(other) {
      Ordering::Equal => Ordering::Greater,
      ordering => ordering,
    }
  }
}

impl DenyDescriptor for NetDescriptor {
  fn cmp_deny(&self, other: &Self) -> Ordering {
    self.cmp_allow(other)
  }
}

impl NetDescriptor {
  pub fn into_import(self) -> ImportDescriptor {
    ImportDescriptor(self)
  }
}

#[derive(Debug, thiserror::Error)]
pub enum NetDescriptorParseError {
  #[error("invalid value '{0}': URLs are not supported, only domains and ips")]
  Url(String),
  #[error("invalid IPv6 address in '{hostname}': '{ip}'")]
  InvalidIpv6 { hostname: String, ip: String },
  #[error("invalid port in '{hostname}': '{port}'")]
  InvalidPort { hostname: String, port: String },
  #[error("invalid host: '{0}'")]
  InvalidHost(String),
  #[error("invalid empty port in '{0}'")]
  EmptyPort(String),
  #[error("ipv6 addresses must be enclosed in square brackets: '{0}'")]
  Ipv6MissingSquareBrackets(String),
  #[error("{0}")]
  Host(#[from] HostParseError),
  #[error("invalid vsock: '{0}'")]
  InvalidVsock(String),
  #[error("invalid unix socket: '{0}' (path must be absolute and non-empty)")]
  InvalidUnixSocket(String),
}

#[derive(Debug, thiserror::Error, deno_error::JsError)]
pub enum NetDescriptorFromUrlParseError {
  #[class(type)]
  #[error("Missing host in url: '{0}'")]
  MissingHost(Url),
  #[class(inherit)]
  #[error("{0}")]
  Host(#[from] HostParseError),
}

impl NetDescriptor {
  pub fn parse_for_query(
    hostname: &str,
  ) -> Result<Self, NetDescriptorParseError> {
    Self::parse_inner(hostname, SubdomainWildcards::Disabled)
  }

  pub fn parse_for_list(
    hostname: &str,
  ) -> Result<Self, NetDescriptorParseError> {
    Self::parse_inner(hostname, SubdomainWildcards::Enabled)
  }

  fn parse_inner(
    hostname: &str,
    subdomain_wildcards: SubdomainWildcards,
  ) -> Result<Self, NetDescriptorParseError> {
    #[cfg(unix)]
    if let Some(vsock) = hostname.strip_prefix("vsock:") {
      let mut split = vsock.split(':');
      let Some(cid) = split.next().and_then(|c| {
        if c == "-1" {
          Some(u32::MAX)
        } else {
          c.parse().ok()
        }
      }) else {
        return Err(NetDescriptorParseError::InvalidVsock(hostname.into()));
      };
      let Some(port) = split.next().and_then(|p| p.parse().ok()) else {
        return Err(NetDescriptorParseError::InvalidVsock(hostname.into()));
      };
      return Ok(NetDescriptor(Host::Vsock(cid), Some(port)));
    }

    if let Some(rest) = hostname.strip_prefix("unix:") {
      let path = PathBuf::from(rest);
      if rest.is_empty() || !path.is_absolute() {
        return Err(NetDescriptorParseError::InvalidUnixSocket(
          hostname.to_string(),
        ));
      }
      // Lexically normalize `.`/`..` components (without resolving symlinks)
      // so the rule matches the path produced by the call side, which goes
      // through the same `normalize_path` in `PathQueryDescriptor`. Otherwise
      // `unix:/var/run/../run/foo.sock` would silently never match.
      let path = normalize_path(Cow::Owned(path)).into_owned();
      return Ok(NetDescriptor(Host::UnixSocket(path), None));
    }

    if hostname.starts_with("http://") || hostname.starts_with("https://") {
      return Err(NetDescriptorParseError::Url(hostname.to_string()));
    }

    if let Ok(socket) = hostname.parse::<SocketAddr>() {
      return Ok(NetDescriptor(
        Host::Ip(normalize_ip(socket.ip())),
        Some(socket.port().into()),
      ));
    }

    // If this is a IPv6 address enclosed in square brackets, parse it as such.
    if hostname.starts_with('[') {
      if let Some((ip, after)) = hostname.split_once(']') {
        let ip_str = &ip[1..];
        let ip =
          strip_ipv6_zone_index(ip_str)
            .parse::<Ipv6Addr>()
            .map_err(|_| NetDescriptorParseError::InvalidIpv6 {
              hostname: hostname.to_string(),
              ip: ip_str.to_string(),
            })?;
        let port = if let Some(port) = after.strip_prefix(':') {
          let port = port.parse::<u16>().map_err(|_| {
            NetDescriptorParseError::InvalidPort {
              hostname: hostname.to_string(),
              port: port.to_string(),
            }
          })?;
          Some(port)
        } else if after.is_empty() {
          None
        } else {
          return Err(NetDescriptorParseError::InvalidHost(
            hostname.to_string(),
          ));
        };
        return Ok(NetDescriptor(
          Host::Ip(normalize_ip(IpAddr::V6(ip))),
          port.map(Into::into),
        ));
      } else {
        return Err(NetDescriptorParseError::InvalidHost(hostname.to_string()));
      }
    }

    // Otherwise it is an IPv4 address or a FQDN with an optional port.
    let (host, port) = match hostname.split_once(':') {
      Some((_, "")) => {
        return Err(NetDescriptorParseError::EmptyPort(hostname.to_string()));
      }
      Some((host, port)) => (host, port),
      None => (hostname, ""),
    };
    let host = Host::parse_inner(host, subdomain_wildcards)?;

    let port = if port.is_empty() {
      None
    } else {
      let port = port.parse::<u16>().map_err(|_| {
        // If the user forgot to enclose an IPv6 address in square brackets, we
        // should give them a hint. There are always at least two colons in an
        // IPv6 address, so this heuristic finds likely a bare IPv6 address.
        if port.contains(':') {
          NetDescriptorParseError::Ipv6MissingSquareBrackets(
            hostname.to_string(),
          )
        } else {
          NetDescriptorParseError::InvalidPort {
            hostname: hostname.to_string(),
            port: port.to_string(),
          }
        }
      })?;
      Some(port)
    };

    Ok(NetDescriptor(host, port.map(Into::into)))
  }

  pub fn from_url(url: &Url) -> Result<Self, NetDescriptorFromUrlParseError> {
    let host = url.host_str().ok_or_else(|| {
      NetDescriptorFromUrlParseError::MissingHost(url.clone())
    })?;
    let host = Host::parse_for_query(host)?;
    let port = url.port_or_known_default();
    Ok(NetDescriptor(host, port.map(Into::into)))
  }

  pub fn from_vsock(
    cid: u32,
    port: u32,
  ) -> Result<Self, NetDescriptorParseError> {
    Ok(NetDescriptor(Host::Vsock(cid), Some(port)))
  }
}

impl fmt::Display for NetDescriptor {
  fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
    match &self.0 {
      Host::Fqdn(fqdn) => write!(f, "{fqdn}"),
      Host::FqdnWithSubdomainWildcard(fqdn) => write!(f, "*.{fqdn}"),
      Host::IpSubnet(ip_subnet) => write!(f, "{ip_subnet}"),
      Host::Ip(IpAddr::V4(ip)) => write!(f, "{ip}"),
      Host::Ip(IpAddr::V6(ip)) => write!(f, "[{ip}]"),
      Host::Vsock(cid) => write!(f, "vsock:{cid}"),
      Host::UnixSocket(path) => write!(f, "unix:{}", path.display()),
    }?;
    if let Some(port) = self.1 {
      write!(f, ":{}", port)?;
    }
    Ok(())
  }
}

#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub struct ImportDescriptor(NetDescriptor);

impl QueryDescriptor for ImportDescriptor {
  type AllowDesc = ImportDescriptor;
  type DenyDesc = ImportDescriptor;

  fn flag_name() -> &'static str {
    "import"
  }

  fn display_name(&self) -> Cow<'_, str> {
    self.0.display_name()
  }

  fn from_allow(allow: &Self::AllowDesc) -> Self {
    Self(NetDescriptor::from_allow(&allow.0))
  }

  fn as_allow(&self) -> Option<Self::AllowDesc> {
    self.0.as_allow().map(ImportDescriptor)
  }

  fn as_deny(&self) -> Self::DenyDesc {
    Self(self.0.as_deny())
  }

  fn check_in_permission(
    &self,
    perm: &mut UnaryPermission<Self::AllowDesc>,
    api_name: Option<&str>,
  ) -> Result<(), PermissionDeniedError> {
    audit_and_skip_check_if_is_permission_fully_granted!(
      perm,
      Self::flag_name(),
      ()
    );
    perm.check_desc(Some(self), false, api_name)
  }

  fn matches_allow(&self, other: &Self::AllowDesc) -> bool {
    self.0.matches_allow(&other.0)
  }

  fn matches_deny(&self, other: &Self::DenyDesc) -> bool {
    self.0.matches_deny(&other.0)
  }

  fn revokes(&self, other: &Self::AllowDesc) -> bool {
    self.0.revokes(&other.0)
  }

  fn stronger_than_deny(&self, other: &Self::DenyDesc) -> bool {
    self.0.stronger_than_deny(&other.0)
  }

  fn overlaps_deny(&self, other: &Self::DenyDesc) -> bool {
    self.0.overlaps_deny(&other.0)
  }
}

impl ImportDescriptor {
  pub fn parse_for_list(
    specifier: &str,
  ) -> Result<Self, NetDescriptorParseError> {
    Ok(ImportDescriptor(NetDescriptor::parse_for_list(specifier)?))
  }

  pub fn from_url(url: &Url) -> Result<Self, NetDescriptorFromUrlParseError> {
    Ok(ImportDescriptor(NetDescriptor::from_url(url)?))
  }
}

impl AllowDescriptor for ImportDescriptor {
  type QueryDesc<'a> = ImportDescriptor;
  type DenyDesc = ImportDescriptor;

  fn cmp_allow(&self, other: &Self) -> Ordering {
    self.0.cmp_allow(&other.0)
  }

  fn cmp_deny(&self, other: &Self::DenyDesc) -> Ordering {
    AllowDescriptor::cmp_deny(&self.0, &other.0)
  }
}

impl DenyDescriptor for ImportDescriptor {
  fn cmp_deny(&self, other: &Self) -> Ordering {
    DenyDescriptor::cmp_deny(&self.0, &other.0)
  }
}

#[derive(Debug, thiserror::Error)]
#[error("Empty env not allowed")]
pub struct EnvDescriptorParseError;

#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub enum EnvDescriptor {
  Name(EnvVarName),
  PrefixPattern(EnvVarName),
}

fn cmp_env_descriptor(a: &EnvDescriptor, b: &EnvDescriptor) -> Ordering {
  match a {
    EnvDescriptor::Name(self_name) => match b {
      EnvDescriptor::Name(other_name) => self_name.cmp(other_name),
      EnvDescriptor::PrefixPattern(_) => Ordering::Less,
    },
    EnvDescriptor::PrefixPattern(self_pattern) => match b {
      EnvDescriptor::Name(_) => Ordering::Greater,
      // for patterns, prefer more specific items first
      EnvDescriptor::PrefixPattern(other_pattern) => {
        other_pattern.cmp(self_pattern)
      }
    },
  }
}

impl EnvDescriptor {
  pub fn new(env: Cow<'_, str>) -> Self {
    if let Some(prefix_pattern) = env.as_ref().strip_suffix('*') {
      Self::PrefixPattern(EnvVarName::new(Cow::Borrowed(prefix_pattern)))
    } else {
      Self::Name(EnvVarName::new(env))
    }
  }
}

impl AllowDescriptor for EnvDescriptor {
  type QueryDesc<'a> = EnvQueryDescriptor<'a>;
  type DenyDesc = EnvDescriptor;

  fn cmp_allow(&self, other: &Self) -> Ordering {
    cmp_env_descriptor(self, other)
  }

  fn cmp_deny(&self, other: &Self::DenyDesc) -> Ordering {
    match cmp_env_descriptor(self, other) {
      Ordering::Equal => Ordering::Greater,
      ordering => ordering,
    }
  }
}

impl DenyDescriptor for EnvDescriptor {
  fn cmp_deny(&self, other: &Self) -> Ordering {
    cmp_env_descriptor(self, other)
  }
}

#[derive(Clone, Debug)]
enum EnvQueryDescriptorInner<'a> {
  Name(EnvVarNameRef<'a>),
  PrefixPattern(EnvVarNameRef<'a>),
}

#[derive(Clone, Debug)]
pub struct EnvQueryDescriptor<'a>(EnvQueryDescriptorInner<'a>);

impl<'a> EnvQueryDescriptor<'a> {
  pub fn new(env: Cow<'a, str>) -> Self {
    Self(EnvQueryDescriptorInner::Name(EnvVarNameRef::new(env)))
  }
}

impl QueryDescriptor for EnvQueryDescriptor<'_> {
  type AllowDesc = EnvDescriptor;
  type DenyDesc = EnvDescriptor;

  fn flag_name() -> &'static str {
    "env"
  }

  fn display_name(&self) -> Cow<'_, str> {
    Cow::from(match &self.0 {
      EnvQueryDescriptorInner::Name(env_var_name) => env_var_name.as_ref(),
      EnvQueryDescriptorInner::PrefixPattern(env_var_name) => {
        env_var_name.as_ref()
      }
    })
  }

  fn from_allow(allow: &Self::AllowDesc) -> Self {
    match allow {
      Self::AllowDesc::Name(s) => {
        Self(EnvQueryDescriptorInner::Name(s.as_env_var_name_ref()))
      }
      Self::AllowDesc::PrefixPattern(s) => Self(
        EnvQueryDescriptorInner::PrefixPattern(s.as_env_var_name_ref()),
      ),
    }
  }

  fn as_allow(&self) -> Option<Self::AllowDesc> {
    Some(match &self.0 {
      EnvQueryDescriptorInner::Name(env_var_name) => {
        Self::AllowDesc::Name(env_var_name.clone().into_owned())
      }
      EnvQueryDescriptorInner::PrefixPattern(env_var_name) => {
        Self::AllowDesc::PrefixPattern(env_var_name.clone().into_owned())
      }
    })
  }

  fn as_deny(&self) -> Self::DenyDesc {
    match &self.0 {
      EnvQueryDescriptorInner::Name(env_var_name) => {
        Self::DenyDesc::Name(env_var_name.clone().into_owned())
      }
      EnvQueryDescriptorInner::PrefixPattern(env_var_name) => {
        Self::DenyDesc::PrefixPattern(env_var_name.clone().into_owned())
      }
    }
  }

  fn check_in_permission(
    &self,
    perm: &mut UnaryPermission<Self::AllowDesc>,
    api_name: Option<&str>,
  ) -> Result<(), PermissionDeniedError> {
    audit_and_skip_check_if_is_permission_fully_granted!(
      perm,
      Self::flag_name(),
      ()
    );
    perm.check_desc(Some(self), false, api_name)
  }

  fn matches_allow(&self, other: &Self::AllowDesc) -> bool {
    match other {
      Self::AllowDesc::Name(n) => match &self.0 {
        EnvQueryDescriptorInner::Name(env_var_name) => n == env_var_name,
        EnvQueryDescriptorInner::PrefixPattern(env_var_name) => {
          env_var_name.as_ref().starts_with(n.as_ref())
        }
      },
      Self::AllowDesc::PrefixPattern(p) => match &self.0 {
        EnvQueryDescriptorInner::Name(env_var_name) => {
          env_var_name.as_ref().starts_with(p.as_ref())
        }
        EnvQueryDescriptorInner::PrefixPattern(env_var_name) => {
          env_var_name.as_ref().starts_with(p.as_ref())
        }
      },
    }
  }

  fn matches_deny(&self, other: &Self::DenyDesc) -> bool {
    match other {
      Self::AllowDesc::Name(n) => match &self.0 {
        EnvQueryDescriptorInner::Name(env_var_name) => n == env_var_name,
        EnvQueryDescriptorInner::PrefixPattern(env_var_name) => {
          env_var_name.as_ref().starts_with(n.as_ref())
        }
      },
      Self::AllowDesc::PrefixPattern(p) => match &self.0 {
        EnvQueryDescriptorInner::Name(env_var_name) => {
          env_var_name.as_ref().starts_with(p.as_ref())
        }
        EnvQueryDescriptorInner::PrefixPattern(env_var_name) => {
          p == env_var_name
        }
      },
    }
  }

  fn revokes(&self, other: &Self::AllowDesc) -> bool {
    match other {
      Self::AllowDesc::Name(n) => match &self.0 {
        EnvQueryDescriptorInner::Name(env_var_name) => n == env_var_name,
        EnvQueryDescriptorInner::PrefixPattern(env_var_name) => {
          env_var_name.as_ref().starts_with(n.as_ref())
        }
      },
      Self::AllowDesc::PrefixPattern(p) => match &self.0 {
        EnvQueryDescriptorInner::Name(env_var_name) => {
          env_var_name.as_ref().starts_with(p.as_ref())
        }
        EnvQueryDescriptorInner::PrefixPattern(env_var_name) => {
          p == env_var_name
        }
      },
    }
  }

  fn stronger_than_deny(&self, other: &Self::DenyDesc) -> bool {
    match other {
      Self::AllowDesc::Name(n) => match &self.0 {
        EnvQueryDescriptorInner::Name(env_var_name) => n == env_var_name,
        EnvQueryDescriptorInner::PrefixPattern(env_var_name) => {
          env_var_name.as_ref().starts_with(n.as_ref())
        }
      },
      Self::AllowDesc::PrefixPattern(p) => match &self.0 {
        EnvQueryDescriptorInner::Name(env_var_name) => {
          env_var_name.as_ref().starts_with(p.as_ref())
        }
        EnvQueryDescriptorInner::PrefixPattern(env_var_name) => {
          p == env_var_name
        }
      },
    }
  }

  fn overlaps_deny(&self, _other: &Self::DenyDesc) -> bool {
    false
  }
}

impl AsRef<str> for EnvQueryDescriptor<'_> {
  fn as_ref(&self) -> &str {
    match &self.0 {
      EnvQueryDescriptorInner::Name(env_var_name) => env_var_name.as_ref(),
      EnvQueryDescriptorInner::PrefixPattern(env_var_name) => {
        env_var_name.as_ref()
      }
    }
  }
}

#[derive(Clone, Debug)]
pub enum RunQueryDescriptor<'a> {
  Path(PathQueryDescriptor<'a>),
  /// This variant won't actually grant permissions because the path of
  /// the executable is unresolved. It's mostly used so that prompts and
  /// everything works the same way as when the command is resolved,
  /// meaning that a script can't tell
  /// if a command is resolved or not based on how long something
  /// takes to ask for permissions.
  Name(String),
}

#[derive(Debug, thiserror::Error, deno_error::JsError)]
pub enum PathResolveError {
  #[class(inherit)]
  #[error("failed resolving cwd: {0}")]
  CwdResolve(#[source] std::io::Error),
  #[class(inherit)]
  #[error(transparent)]
  Canonicalize(std::io::Error),
  #[class(inherit)]
  #[error(transparent)]
  NotFound(std::io::Error),
  #[class(generic)]
  #[error("Empty path is not allowed")]
  EmptyPath,
}

impl PathResolveError {
  pub fn kind(&self) -> std::io::ErrorKind {
    match self {
      Self::CwdResolve(e) | Self::Canonicalize(e) | Self::NotFound(e) => {
        e.kind()
      }
      Self::EmptyPath => std::io::ErrorKind::InvalidData,
    }
  }

  pub fn into_io_error(self) -> std::io::Error {
    match self {
      Self::CwdResolve(e) | Self::Canonicalize(e) | Self::NotFound(e) => e,
      PathResolveError::EmptyPath => {
        std::io::Error::new(self.kind(), format!("{}", self))
      }
    }
  }
}

impl<'a> RunQueryDescriptor<'a> {
  pub fn parse(
    requested: &'a str,
    sys: &impl which::WhichSys,
  ) -> Result<Self, PathResolveError> {
    if AllowRunDescriptor::is_path(requested) {
      let path = Path::new(requested);
      let resolved = PathQueryDescriptor::new(sys, Cow::Borrowed(path))?;
      Ok(RunQueryDescriptor::Path(resolved))
    } else {
      let cwd = sys
        .env_current_dir()
        .map_err(PathResolveError::CwdResolve)?;
      match which::which_in(sys.clone(), requested, sys.env_var_os("PATH"), cwd)
      {
        Ok(resolved) => {
          let cmp_path = comparison_path(&resolved);
          Ok(RunQueryDescriptor::Path(PathQueryDescriptor {
            path: Cow::Owned(resolved),
            cmp_path,
            requested: Some(requested.to_string()),
            is_windows_device_path: false,
          }))
        }
        Err(_) => Ok(RunQueryDescriptor::Name(requested.to_string())),
      }
    }
  }
}

impl QueryDescriptor for RunQueryDescriptor<'_> {
  type AllowDesc = AllowRunDescriptor;
  type DenyDesc = DenyRunDescriptor;

  fn flag_name() -> &'static str {
    "run"
  }

  fn display_name(&self) -> Cow<'_, str> {
    match self {
      RunQueryDescriptor::Path(path) => path.display_name(),
      RunQueryDescriptor::Name(name) => Cow::Borrowed(name),
    }
  }

  fn from_allow(allow: &Self::AllowDesc) -> Self {
    RunQueryDescriptor::Path(allow.0.as_query_descriptor())
  }

  fn as_allow(&self) -> Option<Self::AllowDesc> {
    match self {
      RunQueryDescriptor::Path(path) => {
        Some(AllowRunDescriptor(path.as_descriptor()))
      }
      RunQueryDescriptor::Name(_) => None,
    }
  }

  fn as_deny(&self) -> Self::DenyDesc {
    match self {
      RunQueryDescriptor::Path(path) => match &path.requested {
        Some(requested) => {
          if requested.contains('/')
            || (cfg!(windows) && requested.contains("\\"))
          {
            DenyRunDescriptor::Path(path.as_descriptor())
          } else {
            DenyRunDescriptor::Name(requested.clone())
          }
        }
        None => DenyRunDescriptor::Path(path.as_descriptor()),
      },
      RunQueryDescriptor::Name(name) => DenyRunDescriptor::Name(name.clone()),
    }
  }

  fn check_in_permission(
    &self,
    perm: &mut UnaryPermission<Self::AllowDesc>,
    api_name: Option<&str>,
  ) -> Result<(), PermissionDeniedError> {
    audit_and_skip_check_if_is_permission_fully_granted!(
      perm,
      Self::flag_name(),
      ()
    );
    perm.check_desc(Some(self), false, api_name)
  }

  fn matches_allow(&self, other: &Self::AllowDesc) -> bool {
    match self {
      RunQueryDescriptor::Path(path) => *path == other.0,
      RunQueryDescriptor::Name(_) => false,
    }
  }

  fn matches_deny(&self, other: &Self::DenyDesc) -> bool {
    match other {
      DenyRunDescriptor::Name(deny_desc) => match self {
        RunQueryDescriptor::Path(path) => {
          denies_run_name(deny_desc, &path.path)
        }
        RunQueryDescriptor::Name(query) => query == deny_desc,
      },
      DenyRunDescriptor::Path(deny_desc) => match self {
        RunQueryDescriptor::Path(path) => path.starts_with(deny_desc),
        RunQueryDescriptor::Name(query) => {
          denies_run_name(query, &deny_desc.path)
        }
      },
    }
  }

  fn revokes(&self, other: &Self::AllowDesc) -> bool {
    match self {
      RunQueryDescriptor::Path(path) => {
        if *path == other.0 {
          return true;
        }
        match &path.requested {
          Some(requested) if AllowRunDescriptor::is_path(requested) => false,
          None => false, // is path
          Some(requested) => denies_run_name(requested, &other.0.path),
        }
      }
      RunQueryDescriptor::Name(query) => denies_run_name(query, &other.0.path),
    }
  }

  fn stronger_than_deny(&self, other: &Self::DenyDesc) -> bool {
    self.matches_deny(other)
  }

  fn overlaps_deny(&self, _other: &Self::DenyDesc) -> bool {
    false
  }
}

pub enum RunDescriptorArg {
  Name(String),
  Path(PathBuf),
}

pub enum AllowRunDescriptorParseResult {
  /// An error occurred getting the descriptor that should
  /// be surfaced as a warning when launching deno, but should
  /// be ignored when creating a worker.
  Unresolved(Box<which::Error>),
  Descriptor(AllowRunDescriptor),
}

#[derive(Debug, thiserror::Error, deno_error::JsError)]
pub enum RunDescriptorParseError {
  #[class(generic)]
  #[error("{0}")]
  Which(#[from] which::Error),
  #[class(inherit)]
  #[error("{0}")]
  PathResolve(#[from] PathResolveError),
  #[class(generic)]
  #[error("Empty run query is not allowed")]
  EmptyRunQuery,
}

#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct AllowRunDescriptor(pub PathDescriptor);

impl AllowRunDescriptor {
  pub fn parse(
    text: &str,
    cwd: &Path,
    sys: &impl WhichSys,
  ) -> Result<AllowRunDescriptorParseResult, which::Error> {
    let is_path = Self::is_path(text);
    let path = if is_path {
      Cow::Borrowed(Path::new(text))
    } else {
      match which::which_in(
        sys.clone(),
        text,
        sys.env_var_os("PATH"),
        cwd.to_path_buf(),
      ) {
        Ok(path) => Cow::Owned(path),
        Err(err) => match err {
          which::Error::CannotGetCurrentDirAndPathListEmpty => {
            return Err(err);
          }
          which::Error::CannotFindBinaryPath
          | which::Error::CannotCanonicalize => {
            return Ok(AllowRunDescriptorParseResult::Unresolved(Box::new(
              err,
            )));
          }
        },
      }
    };
    let path = PathDescriptor::new_known_cwd(path, cwd);
    Ok(AllowRunDescriptorParseResult::Descriptor(
      AllowRunDescriptor(path),
    ))
  }

  pub fn is_path(text: &str) -> bool {
    if cfg!(windows) {
      text.contains('/') || text.contains('\\') || Path::new(text).is_absolute()
    } else {
      text.contains('/')
    }
  }
}

impl AllowDescriptor for AllowRunDescriptor {
  type QueryDesc<'a> = RunQueryDescriptor<'a>;
  type DenyDesc = DenyRunDescriptor;

  fn cmp_allow(&self, other: &Self) -> Ordering {
    self.0.cmp_allow_allow(&other.0)
  }

  fn cmp_deny(&self, other: &Self::DenyDesc) -> Ordering {
    match other {
      DenyRunDescriptor::Name(_) => Ordering::Less,
      DenyRunDescriptor::Path(_) => Ordering::Greater,
    }
  }
}

#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub enum DenyRunDescriptor {
  /// Warning: You may want to construct with `RunDescriptor::from()` for case
  /// handling.
  Name(String),
  /// Warning: You may want to construct with `RunDescriptor::from()` for case
  /// handling.
  Path(PathDescriptor),
}

impl DenyDescriptor for DenyRunDescriptor {
  fn cmp_deny(&self, other: &Self) -> Ordering {
    match self {
      DenyRunDescriptor::Name(self_name) => match other {
        DenyRunDescriptor::Name(other_name) => self_name.cmp(other_name),
        DenyRunDescriptor::Path(_) => Ordering::Greater,
      },
      DenyRunDescriptor::Path(self_path) => match other {
        DenyRunDescriptor::Name(_) => Ordering::Less,
        DenyRunDescriptor::Path(other_path) => {
          self_path.cmp_deny_deny(other_path)
        }
      },
    }
  }
}

impl DenyRunDescriptor {
  pub fn parse(text: &str, cwd: &Path) -> Self {
    if text.contains('/') || cfg!(windows) && text.contains('\\') {
      let path =
        PathDescriptor::new_known_cwd(Cow::Borrowed(Path::new(&text)), cwd);
      DenyRunDescriptor::Path(path)
    } else {
      DenyRunDescriptor::Name(text.to_string())
    }
  }
}

fn denies_run_name(name: &str, cmd_path: &Path) -> bool {
  let Some(file_stem) = cmd_path.file_stem() else {
    return false;
  };
  let Some(file_stem) = file_stem.to_str() else {
    return false;
  };
  if file_stem.len() < name.len() {
    return false;
  }
  let (prefix, suffix) = file_stem.split_at(name.len());
  if !prefix.eq_ignore_ascii_case(name) {
    return false;
  }
  // be broad and consider anything like `deno.something` as matching deny perms
  suffix.is_empty() || suffix.starts_with('.')
}

pub struct SpecialFilePathQueryDescriptor<'a> {
  path: Cow<'a, Path>,
  requested: Option<String>,
  canonicalized: bool,
}

impl<'a> SpecialFilePathQueryDescriptor<'a> {
  /// Construct from a `PathQueryDescriptor` without resolving symlinks.
  ///
  /// Used by no-follow access modes (lstat, readlink, readdir, etc.) where
  /// canonicalizing would change semantics by resolving the final path
  /// component. The /proc, /dev, /sys prefix guard in `check_special_file`
  /// still applies — it just uses the un-resolved path.
  pub fn from_path_query_no_canonicalize(
    path: PathQueryDescriptor<'a>,
  ) -> Self {
    let PathQueryDescriptor {
      path, requested, ..
    } = path;
    Self {
      path,
      requested,
      canonicalized: false,
    }
  }

  pub fn parse(
    sys: &impl sys_traits::FsCanonicalize,
    path: PathQueryDescriptor<'a>,
  ) -> Result<Self, PathResolveError> {
    let PathQueryDescriptor {
      is_windows_device_path,
      path,
      cmp_path: _,
      requested,
    } = path;
    // On Linux, /proc may contain magic links that we don't want to resolve
    let is_linux_special_path = cfg!(target_os = "linux")
      && (path.starts_with("/proc") || path.starts_with("/dev"));
    let needs_canonicalization =
      !is_windows_device_path && !is_linux_special_path;
    if needs_canonicalization {
      let original_path = path;
      let new_path = deno_path_util::fs::canonicalize_path_maybe_not_exists(
        sys,
        &original_path,
      )
      .map_err(PathResolveError::Canonicalize)?;
      Ok(Self {
        requested: requested
          .or_else(|| Some(original_path.to_string_lossy().into_owned())),
        path: Cow::Owned(new_path),
        canonicalized: true,
      })
    } else {
      Ok(Self {
        path,
        requested,
        canonicalized: false,
      })
    }
  }
}

#[derive(Debug, thiserror::Error, deno_error::JsError)]
pub enum SysDescriptorParseError {
  #[class(type)]
  #[error("unknown system info kind \"{0}\"")]
  InvalidKind(String),
  #[class(generic)]
  #[error("Empty sys not allowed")]
  Empty, // Error
}

#[derive(Clone, Eq, PartialEq, Hash, Debug, PartialOrd, Ord)]
pub struct SysDescriptor(String);

impl SysDescriptor {
  pub fn parse(kind: String) -> Result<Self, SysDescriptorParseError> {
    match kind.as_str() {
      "hostname" | "inspector" | "osRelease" | "osUptime" | "loadavg"
      | "networkInterfaces" | "systemMemoryInfo" | "uid" | "gid" | "cpus"
      | "homedir" | "getegid" | "statfs" | "getPriority" | "setPriority"
      | "userInfo" | "setegid" | "seteuid" | "setgid" | "setuid" | "ca" => {
        Ok(Self(kind))
      }

      // the underlying permission check changed to `userInfo` to better match the API,
      // alias this to avoid breaking existing projects with `--allow-sys=username`
      "username" => Ok(Self("userInfo".into())),
      _ => Err(SysDescriptorParseError::InvalidKind(kind)),
    }
  }

  pub fn into_string(self) -> String {
    self.0
  }
}

impl QueryDescriptor for SysDescriptor {
  type AllowDesc = SysDescriptor;
  type DenyDesc = SysDescriptor;

  fn flag_name() -> &'static str {
    "sys"
  }

  fn display_name(&self) -> Cow<'_, str> {
    Cow::from(self.0.to_string())
  }

  fn from_allow(allow: &Self::AllowDesc) -> Self {
    allow.clone()
  }

  fn as_allow(&self) -> Option<Self::AllowDesc> {
    Some(self.clone())
  }

  fn as_deny(&self) -> Self::DenyDesc {
    self.clone()
  }

  fn check_in_permission(
    &self,
    perm: &mut UnaryPermission<Self::AllowDesc>,
    api_name: Option<&str>,
  ) -> Result<(), PermissionDeniedError> {
    audit_and_skip_check_if_is_permission_fully_granted!(
      perm,
      Self::flag_name(),
      ()
    );
    perm.check_desc(Some(self), false, api_name)
  }

  fn matches_allow(&self, other: &Self::AllowDesc) -> bool {
    self == other
  }

  fn matches_deny(&self, other: &Self::DenyDesc) -> bool {
    self == other
  }

  fn revokes(&self, other: &Self::AllowDesc) -> bool {
    self == other
  }

  fn stronger_than_deny(&self, other: &Self::DenyDesc) -> bool {
    self == other
  }

  fn overlaps_deny(&self, _other: &Self::DenyDesc) -> bool {
    false
  }
}

impl AllowDescriptor for SysDescriptor {
  type QueryDesc<'a> = SysDescriptor;
  type DenyDesc = SysDescriptor;

  fn cmp_allow(&self, other: &Self) -> Ordering {
    self.cmp(other)
  }

  fn cmp_deny(&self, _other: &Self::DenyDesc) -> Ordering {
    Ordering::Greater
  }
}

impl DenyDescriptor for SysDescriptor {
  fn cmp_deny(&self, other: &Self) -> Ordering {
    self.cmp(other)
  }
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct FfiQueryDescriptor<'a>(pub PathQueryDescriptor<'a>);

impl QueryDescriptor for FfiQueryDescriptor<'_> {
  type AllowDesc = FfiDescriptor;
  type DenyDesc = FfiDescriptor;

  fn flag_name() -> &'static str {
    "ffi"
  }

  fn display_name(&self) -> Cow<'_, str> {
    self.0.display_name()
  }

  fn from_allow(allow: &Self::AllowDesc) -> Self {
    allow.0.as_query_descriptor().into_ffi()
  }

  fn as_allow(&self) -> Option<Self::AllowDesc> {
    Some(FfiDescriptor(self.0.as_descriptor()))
  }

  fn as_deny(&self) -> Self::DenyDesc {
    FfiDescriptor(self.0.as_descriptor())
  }

  fn check_in_permission(
    &self,
    perm: &mut UnaryPermission<Self::AllowDesc>,
    api_name: Option<&str>,
  ) -> Result<(), PermissionDeniedError> {
    audit_and_skip_check_if_is_permission_fully_granted!(
      perm,
      Self::flag_name(),
      ()
    );
    perm.check_desc(Some(self), true, api_name)
  }

  fn matches_allow(&self, other: &Self::AllowDesc) -> bool {
    self.0.starts_with(&other.0)
  }

  fn matches_deny(&self, other: &Self::DenyDesc) -> bool {
    self.0.starts_with(&other.0)
  }

  fn revokes(&self, other: &Self::AllowDesc) -> bool {
    self.matches_allow(other)
  }

  fn stronger_than_deny(&self, other: &Self::DenyDesc) -> bool {
    other.0.starts_with(&self.0)
  }

  fn overlaps_deny(&self, other: &Self::DenyDesc) -> bool {
    self.stronger_than_deny(other)
  }
}

#[derive(Clone, Eq, PartialEq, Hash, Debug)]
pub struct FfiDescriptor(pub PathDescriptor);

impl AllowDescriptor for FfiDescriptor {
  type QueryDesc<'a> = FfiQueryDescriptor<'a>;
  type DenyDesc = FfiDescriptor;

  fn cmp_allow(&self, other: &Self) -> Ordering {
    self.0.cmp_allow_allow(&other.0)
  }

  fn cmp_deny(&self, other: &Self::DenyDesc) -> Ordering {
    self.0.cmp_allow_deny(&other.0)
  }
}

impl DenyDescriptor for FfiDescriptor {
  fn cmp_deny(&self, other: &Self) -> Ordering {
    self.0.cmp_deny_deny(&other.0)
  }
}

impl UnaryPermission<ReadDescriptor> {
  pub fn query(&self, desc: Option<&ReadQueryDescriptor>) -> PermissionState {
    self.query_desc(desc, AllowPartial::TreatAsPartialGranted)
  }

  pub fn request(
    &mut self,
    path: Option<&ReadQueryDescriptor>,
  ) -> PermissionState {
    self.request_desc(path)
  }

  pub fn revoke(
    &mut self,
    desc: Option<&ReadQueryDescriptor>,
  ) -> PermissionState {
    self.revoke_desc(desc)
  }

  pub fn check(
    &mut self,
    desc: &ReadQueryDescriptor,
    api_name: Option<&str>,
  ) -> Result<(), PermissionDeniedError> {
    audit_and_skip_check_if_is_permission_fully_granted!(
      self,
      ReadQueryDescriptor::flag_name(),
      desc.display_name()
    );
    self.check_desc(Some(desc), true, api_name)
  }

  #[inline]
  pub fn check_partial(
    &mut self,
    desc: &ReadQueryDescriptor,
    api_name: Option<&str>,
  ) -> Result<(), PermissionDeniedError> {
    audit_and_skip_check_if_is_permission_fully_granted!(
      self,
      ReadQueryDescriptor::flag_name(),
      desc.display_name()
    );
    self.check_desc(Some(desc), false, api_name)
  }

  pub fn check_all(
    &mut self,
    api_name: Option<&str>,
  ) -> Result<(), PermissionDeniedError> {
    audit_and_skip_check_if_is_permission_fully_granted!(
      self,
      ReadQueryDescriptor::flag_name(),
      ()
    );
    self.check_desc(None, false, api_name)
  }
}

impl UnaryPermission<WriteDescriptor> {
  pub fn query(&self, path: Option<&WriteQueryDescriptor>) -> PermissionState {
    self.query_desc(path, AllowPartial::TreatAsPartialGranted)
  }

  pub fn request(
    &mut self,
    path: Option<&WriteQueryDescriptor>,
  ) -> PermissionState {
    self.request_desc(path)
  }

  pub fn revoke(
    &mut self,
    path: Option<&WriteQueryDescriptor>,
  ) -> PermissionState {
    self.revoke_desc(path)
  }

  pub fn check(
    &mut self,
    path: &WriteQueryDescriptor,
    api_name: Option<&str>,
  ) -> Result<(), PermissionDeniedError> {
    audit_and_skip_check_if_is_permission_fully_granted!(
      self,
      WriteQueryDescriptor::flag_name(),
      path.display_name()
    );
    self.check_desc(Some(path), true, api_name)
  }

  #[inline]
  pub fn check_partial(
    &mut self,
    path: &WriteQueryDescriptor,
    api_name: Option<&str>,
  ) -> Result<(), PermissionDeniedError> {
    audit_and_skip_check_if_is_permission_fully_granted!(
      self,
      WriteQueryDescriptor::flag_name(),
      path.display_name()
    );
    self.check_desc(Some(path), false, api_name)
  }

  pub fn check_all(
    &mut self,
    api_name: Option<&str>,
  ) -> Result<(), PermissionDeniedError> {
    audit_and_skip_check_if_is_permission_fully_granted!(
      self,
      WriteQueryDescriptor::flag_name(),
      ()
    );
    self.check_desc(None, false, api_name)
  }
}

impl UnaryPermission<NetDescriptor> {
  pub fn query(&self, host: Option<&NetDescriptor>) -> PermissionState {
    self.query_desc(host, AllowPartial::TreatAsPartialGranted)
  }

  pub fn request(&mut self, host: Option<&NetDescriptor>) -> PermissionState {
    self.request_desc(host)
  }

  pub fn revoke(&mut self, host: Option<&NetDescriptor>) -> PermissionState {
    self.revoke_desc(host)
  }

  pub fn check(
    &mut self,
    host: &NetDescriptor,
    api_name: Option<&str>,
  ) -> Result<(), PermissionDeniedError> {
    audit_and_skip_check_if_is_permission_fully_granted!(
      self,
      NetDescriptor::flag_name(),
      host.display_name()
    );
    self.check_desc(Some(host), false, api_name)
  }

  pub fn check_all(&mut self) -> Result<(), PermissionDeniedError> {
    audit_and_skip_check_if_is_permission_fully_granted!(
      self,
      NetDescriptor::flag_name(),
      ()
    );
    self.check_desc(None, false, None)
  }

  /// Check if a resolved IP address is explicitly denied.
  ///
  /// This is used after DNS resolution to ensure that deny rules written as
  /// IP literals (e.g. `--deny-net=127.0.0.1`) also block connections made
  /// via hostname aliases that resolve to the denied IP (e.g. numeric forms
  /// like `2130706433` which the OS resolver maps to `127.0.0.1`).
  ///
  /// Only checks deny rules — the allow check has already been performed
  /// against the original hostname.
  pub fn check_resolved_ip_deny(
    &mut self,
    desc: &NetDescriptor,
    api_name: Option<&str>,
  ) -> Result<(), PermissionDeniedError> {
    let info = format_display_name(desc.display_name()).into_owned();
    let denied = || {
      PermissionState::permission_denied_error(
        NetDescriptor::flag_name(),
        Some(info.as_str()),
        PermissionState::Denied,
      )
    };
    if self.flag_denied_global {
      return Err(denied());
    }
    for item in self.descriptors.iter() {
      match item {
        UnaryPermissionDesc::FlagDenied(v)
        | UnaryPermissionDesc::FlagIgnored(v)
          if desc.matches_deny(v) =>
        {
          return Err(denied());
        }
        _ => {}
      }
    }
    let _ = api_name;
    Ok(())
  }
}

impl UnaryPermission<ImportDescriptor> {
  pub fn query(&self, host: Option<&ImportDescriptor>) -> PermissionState {
    self.query_desc(host, AllowPartial::TreatAsPartialGranted)
  }

  pub fn request(
    &mut self,
    host: Option<&ImportDescriptor>,
  ) -> PermissionState {
    self.request_desc(host)
  }

  pub fn revoke(&mut self, host: Option<&ImportDescriptor>) -> PermissionState {
    self.revoke_desc(host)
  }

  pub fn check(
    &mut self,
    host: &ImportDescriptor,
    api_name: Option<&str>,
  ) -> Result<(), PermissionDeniedError> {
    audit_and_skip_check_if_is_permission_fully_granted!(
      self,
      ImportDescriptor::flag_name(),
      host.display_name()
    );
    self.check_desc(Some(host), false, api_name)
  }

  pub fn check_all(&mut self) -> Result<(), PermissionDeniedError> {
    audit_and_skip_check_if_is_permission_fully_granted!(
      self,
      ImportDescriptor::flag_name(),
      ()
    );
    self.check_desc(None, false, None)
  }
}

impl UnaryPermission<EnvDescriptor> {
  pub fn query(&self, env: Option<&str>) -> PermissionState {
    self.query_desc(
      env
        .map(|env| EnvQueryDescriptor::new(Cow::Borrowed(env)))
        .as_ref(),
      AllowPartial::TreatAsPartialGranted,
    )
  }

  pub fn request(&mut self, env: Option<&str>) -> PermissionState {
    self.request_desc(
      env
        .map(|env| EnvQueryDescriptor::new(Cow::Borrowed(env)))
        .as_ref(),
    )
  }

  pub fn revoke(&mut self, env: Option<&str>) -> PermissionState {
    self.revoke_desc(
      env
        .map(|env| EnvQueryDescriptor::new(Cow::Borrowed(env)))
        .as_ref(),
    )
  }

  pub fn check(
    &mut self,
    env: &str,
    api_name: Option<&str>,
  ) -> Result<(), PermissionDeniedError> {
    audit_and_skip_check_if_is_permission_fully_granted!(
      self,
      EnvQueryDescriptor::flag_name(),
      env
    );
    self.check_desc(
      Some(&EnvQueryDescriptor::new(Cow::Borrowed(env))),
      false,
      api_name,
    )
  }

  pub fn check_all(&mut self) -> Result<(), PermissionDeniedError> {
    audit_and_skip_check_if_is_permission_fully_granted!(
      self,
      EnvQueryDescriptor::flag_name(),
      ()
    );
    self.check_desc(None, true, None)
  }
}

impl UnaryPermission<SysDescriptor> {
  pub fn query(&self, kind: Option<&SysDescriptor>) -> PermissionState {
    self.query_desc(kind, AllowPartial::TreatAsPartialGranted)
  }

  pub fn request(&mut self, kind: Option<&SysDescriptor>) -> PermissionState {
    self.request_desc(kind)
  }

  pub fn revoke(&mut self, kind: Option<&SysDescriptor>) -> PermissionState {
    self.revoke_desc(kind)
  }

  pub fn check(
    &mut self,
    kind: &SysDescriptor,
    api_name: Option<&str>,
  ) -> Result<(), PermissionDeniedError> {
    audit_and_skip_check_if_is_permission_fully_granted!(
      self,
      SysDescriptor::flag_name(),
      kind.display_name()
    );
    self.check_desc(Some(kind), false, api_name)
  }

  pub fn check_all(&mut self) -> Result<(), PermissionDeniedError> {
    audit_and_skip_check_if_is_permission_fully_granted!(
      self,
      SysDescriptor::flag_name(),
      ()
    );
    self.check_desc(None, false, None)
  }
}

impl UnaryPermission<AllowRunDescriptor> {
  pub fn query(&self, cmd: Option<&RunQueryDescriptor>) -> PermissionState {
    self.query_desc(cmd, AllowPartial::TreatAsPartialGranted)
  }

  pub fn request(
    &mut self,
    cmd: Option<&RunQueryDescriptor>,
  ) -> PermissionState {
    self.request_desc(cmd)
  }

  pub fn revoke(
    &mut self,
    cmd: Option<&RunQueryDescriptor>,
  ) -> PermissionState {
    self.revoke_desc(cmd)
  }

  pub fn check(
    &mut self,
    cmd: &RunQueryDescriptor,
    api_name: Option<&str>,
  ) -> Result<(), PermissionDeniedError> {
    self.check_desc(Some(cmd), false, api_name)
  }

  pub fn check_all(
    &mut self,
    api_name: Option<&str>,
  ) -> Result<(), PermissionDeniedError> {
    self.check_desc(None, false, api_name)
  }

  /// Queries without prompting
  pub fn query_all(&mut self, api_name: Option<&str>) -> bool {
    if self.is_allow_all() {
      return true;
    }
    let (result, _prompted, _is_allow_all) =
      self.query_desc(None, AllowPartial::TreatAsDenied).check(
        RunQueryDescriptor::flag_name(),
        api_name,
        || None,
        || None,
        /* prompt */ false,
      );
    result.is_ok()
  }
}

impl UnaryPermission<FfiDescriptor> {
  pub fn query(&self, path: Option<&FfiQueryDescriptor>) -> PermissionState {
    self.query_desc(path, AllowPartial::TreatAsPartialGranted)
  }

  pub fn request(
    &mut self,
    path: Option<&FfiQueryDescriptor>,
  ) -> PermissionState {
    self.request_desc(path)
  }

  pub fn revoke(
    &mut self,
    path: Option<&FfiQueryDescriptor>,
  ) -> PermissionState {
    self.revoke_desc(path)
  }

  pub fn check(
    &mut self,
    path: &FfiQueryDescriptor,
    api_name: Option<&str>,
  ) -> Result<(), PermissionDeniedError> {
    audit_and_skip_check_if_is_permission_fully_granted!(
      self,
      FfiQueryDescriptor::flag_name(),
      path.display_name()
    );
    self.check_desc(Some(path), true, api_name)
  }

  pub fn check_partial(
    &mut self,
    path: Option<&FfiQueryDescriptor>,
  ) -> Result<(), PermissionDeniedError> {
    audit_and_skip_check_if_is_permission_fully_granted!(
      self,
      FfiQueryDescriptor::flag_name(),
      path.as_ref().map(|path| path.display_name())
    );
    self.check_desc(path, false, None)
  }

  pub fn check_all(&mut self) -> Result<(), PermissionDeniedError> {
    audit_and_skip_check_if_is_permission_fully_granted!(
      self,
      FfiQueryDescriptor::flag_name(),
      ()
    );
    self.check_desc(None, false, Some("all"))
  }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Permissions {
  // WARNING: update the methods below if ever adding anything here
  pub read: UnaryPermission<ReadDescriptor>,
  pub write: UnaryPermission<WriteDescriptor>,
  pub net: UnaryPermission<NetDescriptor>,
  pub env: UnaryPermission<EnvDescriptor>,
  pub sys: UnaryPermission<SysDescriptor>,
  pub run: UnaryPermission<AllowRunDescriptor>,
  pub ffi: UnaryPermission<FfiDescriptor>,
  pub import: UnaryPermission<ImportDescriptor>,
}

impl Permissions {
  pub fn all_granted(&self) -> bool {
    self.read.is_allow_all()
      && self.write.is_allow_all()
      && self.net.is_allow_all()
      && self.env.is_allow_all()
      && self.sys.is_allow_all()
      && self.run.is_allow_all()
      && self.ffi.is_allow_all()
      && self.import.is_allow_all()
  }
}

#[derive(Clone, Debug, Eq, PartialEq, Default, Serialize, Deserialize)]
pub struct PermissionsOptions {
  pub allow_env: Option<Vec<String>>,
  pub deny_env: Option<Vec<String>>,
  pub ignore_env: Option<Vec<String>>,
  pub allow_net: Option<Vec<String>>,
  pub deny_net: Option<Vec<String>>,
  pub allow_ffi: Option<Vec<String>>,
  pub deny_ffi: Option<Vec<String>>,
  pub allow_read: Option<Vec<String>>,
  pub deny_read: Option<Vec<String>>,
  pub ignore_read: Option<Vec<String>>,
  pub allow_run: Option<Vec<String>>,
  pub deny_run: Option<Vec<String>>,
  pub allow_sys: Option<Vec<String>>,
  pub deny_sys: Option<Vec<String>>,
  pub allow_write: Option<Vec<String>>,
  pub deny_write: Option<Vec<String>>,
  pub allow_import: Option<Vec<String>>,
  pub deny_import: Option<Vec<String>>,
  pub prompt: bool,
}

#[derive(Debug, thiserror::Error)]
pub enum PermissionsFromOptionsError {
  #[error("{0}")]
  PathResolve(#[from] PathResolveError),
  #[error("{0}")]
  SysDescriptorParse(#[from] SysDescriptorParseError),
  #[error("{0}")]
  NetDescriptorParse(#[from] NetDescriptorParseError),
  #[error("{0}")]
  EnvDescriptorParse(#[from] EnvDescriptorParseError),
  #[error("{0}")]
  RunDescriptorParse(#[from] RunDescriptorParseError),
  #[error("Empty command name not allowed in --allow-run=...")]
  RunEmptyCommandName,
}

impl Permissions {
  pub fn new_unary_with_ignore<TAllow: AllowDescriptor>(
    allow_list: Option<Vec<TAllow>>,
    deny_list: Option<Vec<TAllow::DenyDesc>>,
    ignore_list: Option<Vec<TAllow::DenyDesc>>,
    prompt: bool,
  ) -> UnaryPermission<TAllow> {
    let mut descriptors = UnaryPermissionDescriptors::with_capacity(
      allow_list.as_ref().map(|v| v.len()).unwrap_or(0)
        + ignore_list.as_ref().map(|v| v.len()).unwrap_or(0)
        + deny_list.as_ref().map(|v| v.len()).unwrap_or(0),
    );
    let granted_global = global_from_option(allow_list.as_ref());
    let flag_denied_global = global_from_option(deny_list.as_ref());
    let flag_ignored_global = global_from_option(ignore_list.as_ref());
    for item in allow_list.unwrap_or_default() {
      descriptors.insert(UnaryPermissionDesc::Granted(item));
    }
    for item in deny_list.unwrap_or_default() {
      descriptors.insert(UnaryPermissionDesc::FlagDenied(item));
    }
    for item in ignore_list.unwrap_or_default() {
      descriptors.insert(UnaryPermissionDesc::FlagIgnored(item));
    }
    UnaryPermission::<TAllow> {
      granted_global,
      flag_denied_global,
      flag_ignored_global,
      descriptors,
      prompt,
      ..Default::default()
    }
  }

  pub fn new_unary<TAllow: AllowDescriptor>(
    allow_list: Option<Vec<TAllow>>,
    deny_list: Option<Vec<TAllow::DenyDesc>>,
    prompt: bool,
  ) -> UnaryPermission<TAllow> {
    Self::new_unary_with_ignore(allow_list, deny_list, None, prompt)
  }

  pub const fn new_all(allow_state: bool) -> UnitPermission {
    unit_permission_from_flag_bools(
      allow_state,
      false,
      "all",
      "all",
      false, // never prompt for all
    )
  }

  pub fn from_options(
    parser: &dyn PermissionDescriptorParser,
    opts: &PermissionsOptions,
  ) -> Result<Self, PermissionsFromOptionsError> {
    fn resolve_allow_run(
      parser: &dyn PermissionDescriptorParser,
      allow_run: &[String],
    ) -> Result<Vec<AllowRunDescriptor>, PermissionsFromOptionsError> {
      let mut new_allow_run = Vec::with_capacity(allow_run.len());
      for unresolved in allow_run {
        if unresolved.is_empty() {
          return Err(PermissionsFromOptionsError::RunEmptyCommandName);
        }
        match parser.parse_allow_run_descriptor(unresolved)? {
          AllowRunDescriptorParseResult::Descriptor(descriptor) => {
            new_allow_run.push(descriptor);
          }
          AllowRunDescriptorParseResult::Unresolved(err) => {
            log::info!(
              "{} Failed to resolve '{}' for allow-run: {}",
              colors::gray("Info"),
              unresolved,
              err
            );
          }
        }
      }
      Ok(new_allow_run)
    }

    fn parse_maybe_vec<T: Eq + PartialEq + Hash, E>(
      items: Option<&[String]>,
      parse: impl Fn(&str) -> Result<T, E>,
    ) -> Result<Option<Vec<T>>, PermissionsFromOptionsError>
    where
      PermissionsFromOptionsError: From<E>,
    {
      match items {
        Some(items) => Ok(Some(
          items
            .iter()
            .map(|item| parse(item))
            .collect::<Result<Vec<_>, _>>()?,
        )),
        None => Ok(None),
      }
    }

    let mut deny_write = parse_maybe_vec(opts.deny_write.as_deref(), |item| {
      parser.parse_write_descriptor(item)
    })?;
    let allow_run = opts
      .allow_run
      .as_ref()
      .and_then(|raw_allow_run| {
        match resolve_allow_run(parser, raw_allow_run) {
          Ok(resolved_allow_run) => {
            if resolved_allow_run.is_empty() && !raw_allow_run.is_empty() {
              None // convert to no permissions if now empty
            } else {
              Some(Ok(resolved_allow_run))
            }
          }
          Err(err) => Some(Err(err)),
        }
      })
      .transpose()?;
    // add the allow_run list to deny_write
    if let Some(allow_run_vec) = &allow_run
      && !allow_run_vec.is_empty()
    {
      let deny_write = deny_write.get_or_insert_with(Default::default);
      deny_write.extend(
        allow_run_vec
          .iter()
          .map(|item| WriteDescriptor(item.0.clone())),
      );
    }

    Ok(Self {
      read: Permissions::new_unary_with_ignore(
        parse_maybe_vec(opts.allow_read.as_deref(), |item| {
          parser.parse_read_descriptor(item)
        })?,
        parse_maybe_vec(opts.deny_read.as_deref(), |item| {
          parser.parse_read_descriptor(item)
        })?,
        parse_maybe_vec(opts.ignore_read.as_deref(), |text| {
          parser.parse_read_descriptor(text)
        })?,
        opts.prompt,
      ),
      write: Permissions::new_unary(
        parse_maybe_vec(opts.allow_write.as_deref(), |item| {
          parser.parse_write_descriptor(item)
        })?,
        deny_write,
        opts.prompt,
      ),
      net: Permissions::new_unary(
        parse_maybe_vec(opts.allow_net.as_deref(), |item| {
          parser.parse_net_descriptor(item)
        })?,
        parse_maybe_vec(opts.deny_net.as_deref(), |item| {
          parser.parse_net_descriptor(item)
        })?,
        opts.prompt,
      ),
      env: Permissions::new_unary_with_ignore(
        parse_maybe_vec(opts.allow_env.as_deref(), |item| {
          parser.parse_env_descriptor(item)
        })?,
        parse_maybe_vec(opts.deny_env.as_deref(), |text| {
          parser.parse_env_descriptor(text)
        })?,
        parse_maybe_vec(opts.ignore_env.as_deref(), |text| {
          parser.parse_env_descriptor(text)
        })?,
        opts.prompt,
      ),
      sys: Permissions::new_unary(
        parse_maybe_vec(opts.allow_sys.as_deref(), |text| {
          parser.parse_sys_descriptor(text)
        })?,
        parse_maybe_vec(opts.deny_sys.as_deref(), |text| {
          parser.parse_sys_descriptor(text)
        })?,
        opts.prompt,
      ),
      run: Permissions::new_unary(
        allow_run,
        parse_maybe_vec(opts.deny_run.as_deref(), |text| {
          parser.parse_deny_run_descriptor(text)
        })?,
        opts.prompt,
      ),
      ffi: Permissions::new_unary(
        parse_maybe_vec(opts.allow_ffi.as_deref(), |text| {
          parser.parse_ffi_descriptor(text)
        })?,
        parse_maybe_vec(opts.deny_ffi.as_deref(), |text| {
          parser.parse_ffi_descriptor(text)
        })?,
        opts.prompt,
      ),
      import: Permissions::new_unary(
        parse_maybe_vec(opts.allow_import.as_deref(), |item| {
          parser.parse_import_descriptor(item)
        })?,
        parse_maybe_vec(opts.deny_import.as_deref(), |item| {
          parser.parse_import_descriptor(item)
        })?,
        opts.prompt,
      ),
    })
  }

  /// Create a set of permissions that explicitly allow everything.
  pub fn allow_all() -> Self {
    Self {
      read: UnaryPermission::allow_all(),
      write: UnaryPermission::allow_all(),
      net: UnaryPermission::allow_all(),
      env: UnaryPermission::allow_all(),
      sys: UnaryPermission::allow_all(),
      run: UnaryPermission::allow_all(),
      ffi: UnaryPermission::allow_all(),
      import: UnaryPermission::allow_all(),
    }
  }

  /// Create a set of permissions that enable nothing, but will allow prompting.
  pub fn none_with_prompt() -> Self {
    Self::none(true)
  }

  /// Create a set of permissions that enable nothing, and will not allow prompting.
  pub fn none_without_prompt() -> Self {
    Self::none(false)
  }

  fn none(prompt: bool) -> Self {
    Self {
      read: Permissions::new_unary(None, None, prompt),
      write: Permissions::new_unary(None, None, prompt),
      net: Permissions::new_unary(None, None, prompt),
      env: Permissions::new_unary(None, None, prompt),
      sys: Permissions::new_unary(None, None, prompt),
      run: Permissions::new_unary(None, None, prompt),
      ffi: Permissions::new_unary(None, None, prompt),
      import: Permissions::new_unary(None, None, prompt),
    }
  }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum CheckSpecifierKind {
  Static,
  Dynamic,
}

#[derive(Debug, thiserror::Error, deno_error::JsError)]
pub enum ChildPermissionError {
  #[class("NotCapable")]
  #[error("Can't escalate parent thread permissions")]
  Escalation,
  #[class(inherit)]
  #[error("{0}")]
  PathResolve(#[from] PathResolveError),
  #[class(uri)]
  #[error("{0}")]
  NetDescriptorParse(#[from] NetDescriptorParseError),
  #[class(generic)]
  #[error("{0}")]
  EnvDescriptorParse(#[from] EnvDescriptorParseError),
  #[class(inherit)]
  #[error("{0}")]
  SysDescriptorParse(#[from] SysDescriptorParseError),
  #[class(inherit)]
  #[error("{0}")]
  RunDescriptorParse(#[from] RunDescriptorParseError),
}

#[derive(Debug, thiserror::Error, deno_error::JsError)]
pub enum PermissionCheckError {
  #[class(inherit)]
  #[error(transparent)]
  PermissionDenied(#[from] PermissionDeniedError),
  #[class(uri)]
  #[error("Invalid file path.\n  Specifier: {0}")]
  InvalidFilePath(Url),
  #[class(inherit)]
  #[error(transparent)]
  NetDescriptorForUrlParse(#[from] NetDescriptorFromUrlParseError),
  #[class(inherit)]
  #[error(transparent)]
  SysDescriptorParse(#[from] SysDescriptorParseError),
  #[class(inherit)]
  #[error(transparent)]
  PathResolve(#[from] PathResolveError),
  #[class(uri)]
  #[error(transparent)]
  HostParse(#[from] HostParseError),
  #[class(inherit)]
  #[error(transparent)]
  Io(std::io::Error),
}

fn ignored_to_not_found(err: PermissionDeniedError) -> PermissionCheckError {
  #[cfg(target_arch = "wasm32")]
  fn not_found() -> std::io::Error {
    std::io::Error::new(
      std::io::ErrorKind::NotFound,
      "No such file or directory (os error 2)",
    )
  }

  #[cfg(all(not(windows), not(target_arch = "wasm32")))]
  fn not_found() -> std::io::Error {
    std::io::Error::from_raw_os_error(libc::ENOENT)
  }

  #[cfg(windows)]
  fn not_found() -> std::io::Error {
    std::io::Error::from_raw_os_error(
      windows_sys::Win32::Foundation::ERROR_FILE_NOT_FOUND as i32,
    )
  }

  if err.state == PermissionState::Ignored {
    PermissionCheckError::Io(not_found())
  } else {
    PermissionCheckError::PermissionDenied(err)
  }
}

impl PermissionCheckError {
  pub fn kind(&self) -> std::io::ErrorKind {
    match self {
      PermissionCheckError::PermissionDenied(_) => std::io::ErrorKind::Other,
      PermissionCheckError::InvalidFilePath(_) => std::io::ErrorKind::Other,
      PermissionCheckError::NetDescriptorForUrlParse(_)
      | PermissionCheckError::HostParse(_)
      | PermissionCheckError::SysDescriptorParse(_) => {
        std::io::ErrorKind::Other
      }
      PermissionCheckError::PathResolve(e) => e.kind(),
      PermissionCheckError::Io(e) => e.kind(),
    }
  }

  pub fn into_io_error(self) -> std::io::Error {
    match self {
      Self::PermissionDenied(_)
      | Self::InvalidFilePath(_)
      | Self::NetDescriptorForUrlParse(_)
      | Self::SysDescriptorParse(_)
      | Self::HostParse(_) => {
        std::io::Error::new(self.kind(), format!("{}", self))
      }
      Self::PathResolve(e) => e.into_io_error(),
      Self::Io(e) => e,
    }
  }
}

/// Wrapper struct for `Permissions` that can be shared across threads.
///
/// We need a way to have internal mutability for permissions as they might get
/// passed to a future that will prompt the user for permission (and in such
/// case might need to be mutated). Also for the Web Worker API we need a way
/// to send permissions to a new thread.
#[derive(Clone, Debug)]
pub struct PermissionsContainer {
  descriptor_parser: Arc<dyn PermissionDescriptorParser>,
  inner: Arc<Mutex<Permissions>>,
}

impl PermissionsContainer {
  pub fn new(
    descriptor_parser: Arc<dyn PermissionDescriptorParser>,
    perms: Permissions,
  ) -> Self {
    Self {
      descriptor_parser,
      inner: Arc::new(Mutex::new(perms)),
    }
  }

  pub fn deep_clone(&self) -> PermissionsContainer {
    Self {
      descriptor_parser: self.descriptor_parser.clone(),
      inner: Arc::new(Mutex::new(self.inner.lock().clone())),
    }
  }

  pub fn allow_all(
    descriptor_parser: Arc<dyn PermissionDescriptorParser>,
  ) -> Self {
    Self::new(descriptor_parser, Permissions::allow_all())
  }

  pub fn create_child_permissions(
    &self,
    child_permissions_arg: ChildPermissionsArg,
  ) -> Result<PermissionsContainer, ChildPermissionError> {
    let mut worker_perms = Permissions::none_without_prompt();

    let mut inner = self.inner.lock();

    // WARNING: When adding a permission here, ensure it is handled
    // in the worker_perms.all block above
    worker_perms.read = inner.read.create_child_permissions(
      child_permissions_arg.read,
      |text| {
        Ok::<_, PathResolveError>(Some(
          self.descriptor_parser.parse_read_descriptor(text)?,
        ))
      },
    )?;
    worker_perms.write = inner.write.create_child_permissions(
      child_permissions_arg.write,
      |text| {
        Ok::<_, PathResolveError>(Some(
          self.descriptor_parser.parse_write_descriptor(text)?,
        ))
      },
    )?;
    worker_perms.import = inner.import.create_child_permissions(
      child_permissions_arg.import,
      |text| {
        Ok::<_, NetDescriptorParseError>(Some(
          self.descriptor_parser.parse_import_descriptor(text)?,
        ))
      },
    )?;
    worker_perms.net = inner.net.create_child_permissions(
      child_permissions_arg.net,
      |text| {
        Ok::<_, NetDescriptorParseError>(Some(
          self.descriptor_parser.parse_net_descriptor(text)?,
        ))
      },
    )?;
    worker_perms.env = inner.env.create_child_permissions(
      child_permissions_arg.env,
      |text| {
        Ok::<_, EnvDescriptorParseError>(Some(
          self.descriptor_parser.parse_env_descriptor(text)?,
        ))
      },
    )?;
    worker_perms.sys = inner.sys.create_child_permissions(
      child_permissions_arg.sys,
      |text| {
        Ok::<_, SysDescriptorParseError>(Some(
          self.descriptor_parser.parse_sys_descriptor(text)?,
        ))
      },
    )?;
    worker_perms.run = inner.run.create_child_permissions(
      child_permissions_arg.run,
      |text| match self.descriptor_parser.parse_allow_run_descriptor(text)? {
        AllowRunDescriptorParseResult::Unresolved(_) => {
          Ok::<_, RunDescriptorParseError>(None)
        }
        AllowRunDescriptorParseResult::Descriptor(desc) => Ok(Some(desc)),
      },
    )?;
    worker_perms.ffi = inner.ffi.create_child_permissions(
      child_permissions_arg.ffi,
      |text| {
        Ok::<_, PathResolveError>(Some(
          self.descriptor_parser.parse_ffi_descriptor(text)?,
        ))
      },
    )?;

    Ok(PermissionsContainer::new(
      self.descriptor_parser.clone(),
      worker_perms,
    ))
  }

  #[inline(always)]
  pub fn check_specifier(
    &self,
    specifier: &Url,
    kind: CheckSpecifierKind,
  ) -> Result<(), PermissionCheckError> {
    if specifier.scheme() == "file" {
      let path = url_to_file_path(specifier).map_err(|_| {
        PermissionCheckError::InvalidFilePath(specifier.clone())
      })?;
      let path = self.descriptor_parser.parse_path_query(Cow::Owned(path))?;
      let special =
        self.descriptor_parser.parse_special_file_descriptor(path)?;
      self.check_special_file(
        special,
        OpenAccessKind::Read,
        Some(match kind {
          CheckSpecifierKind::Static => "static import",
          CheckSpecifierKind::Dynamic => "import()",
        }),
      )?;
    }
    // Static file modules are intentionally exempt from Deno's layer-1 read
    // permission. Oden's private policy/audit channel is not: enforce the
    // layer-2 reservation before the stock static-import fast path.
    oden_capsec_reject_control_specifier(specifier)?;
    let mut inner = self.inner.lock();
    match specifier.scheme() {
      "file" => {
        // Static source loading does not require an allow-read grant, but an
        // explicit --deny-read remains authoritative. This is the layer-1
        // half of Oden's private-control-directory boundary.
        if kind == CheckSpecifierKind::Static {
          let path = url_to_file_path(specifier).map_err(|_| {
            PermissionCheckError::InvalidFilePath(specifier.clone())
          })?;
          let desc = self
            .descriptor_parser
            .parse_path_query(Cow::Owned(path))?
            .into_read();
          if matches!(
            inner
              .read
              .query_desc(Some(&desc), AllowPartial::TreatAsDenied),
            PermissionState::Denied
              | PermissionState::DeniedPartial
              | PermissionState::Ignored
          ) {
            return inner
              .read
              .check(&desc, Some("static import"))
              .map_err(ignored_to_not_found);
          }
          return Ok(());
        }
        if inner.read.is_allow_all() {
          write_audit(ReadQueryDescriptor::flag_name(), specifier);

          return Ok(());
        }

        match url_to_file_path(specifier) {
          Ok(path) => {
            let desc = self
              .descriptor_parser
              .parse_path_query(Cow::Owned(path))?
              .into_read();
            inner
              .read
              .check(&desc, Some("import()"))
              .map_err(ignored_to_not_found)
          }
          Err(_) => {
            Err(PermissionCheckError::InvalidFilePath(specifier.clone()))
          }
        }
      }
      "data" => Ok(()),
      "blob" => Ok(()),
      _ => {
        if inner.import.is_allow_all() {
          write_audit(ImportDescriptor::flag_name(), specifier);

          return Ok(()); // avoid allocation below
        }

        let desc = self
          .descriptor_parser
          .parse_import_descriptor_from_url(specifier)?;
        inner.import.check(&desc, Some("import()"))?;
        Ok(())
      }
    }
  }

  #[must_use = "the resolved return value to mitigate time-of-check to time-of-use issues"]
  #[inline(always)]
  pub fn check_open<'a>(
    &self,
    path: Cow<'a, Path>,
    access_kind: OpenAccessKind,
    api_name: Option<&str>,
  ) -> Result<CheckedPath<'a>, PermissionCheckError> {
    self.check_open_with_requested(path, access_kind, None, api_name)
  }

  /// As `check_open()`, but permission error messages will anonymize the path
  /// by replacing it with the given `display`.
  #[must_use = "the resolved return value to mitigate time-of-check to time-of-use issues"]
  #[inline(always)]
  pub fn check_open_blind<'a>(
    &self,
    path: Cow<'a, Path>,
    access_kind: OpenAccessKind,
    display: &str,
    api_name: Option<&str>,
  ) -> Result<CheckedPath<'a>, PermissionCheckError> {
    self.check_open_with_requested(path, access_kind, Some(display), api_name)
  }

  #[inline(always)]
  fn check_open_with_requested<'a>(
    &self,
    path: Cow<'a, Path>,
    access_kind: OpenAccessKind,
    blind_requested: Option<&str>,
    api_name: Option<&str>,
  ) -> Result<CheckedPath<'a>, PermissionCheckError> {
    if oden_capsec_active() {
      let target = path.to_string_lossy().into_owned();
      if access_kind.is_read() {
        oden_capsec_decide(OdenFamily::Fs, "read", &target, api_name)?;
      }
      if access_kind.is_write() {
        oden_capsec_decide(OdenFamily::Fs, "write", &target, api_name)?;
      }
    }
    let path = {
      let mut inner = self.inner.lock();
      if inner.all_granted() {
        write_audit(ReadQueryDescriptor::flag_name(), &path);
        write_audit(WriteQueryDescriptor::flag_name(), &path);
        return Ok(CheckedPath {
          path: PathWithRequested {
            path,
            requested: None,
          },
          canonicalized: false,
        });
      }
      let should_check_read =
        access_kind.is_read() && !inner.read.is_allow_all();
      let should_check_write =
        access_kind.is_write() && !inner.write.is_allow_all();
      let path_descriptor =
        self.descriptor_parser.parse_path_query(path.clone())?;
      let path_descriptor = match blind_requested {
        Some(display) => {
          path_descriptor.with_requested(format!("<{}>", display))
        }
        None => path_descriptor,
      };
      if !should_check_read && !should_check_write {
        write_audit(ReadQueryDescriptor::flag_name(), &path);
        write_audit(WriteQueryDescriptor::flag_name(), &path);
        drop(inner);
        path_descriptor
      } else {
        // Use partial-deny semantics here: the operations gated by
        // `check_open` (open, stat, lstat, readDir, readFile, writeFile, …)
        // act on a single path and do not recurse, so a deny scope that lies
        // *under* the queried path should not block the operation. The strict
        // `check` (which fails on partial denies inside the requested scope)
        // remains in use for recursive operations like `fs::remove_all`.
        let path = if should_check_read {
          let inner = &mut inner.read;
          let desc = path_descriptor.into_read();
          inner
            .check_partial(&desc, api_name)
            .map_err(ignored_to_not_found)?;
          desc.0
        } else {
          path_descriptor
        };
        if should_check_write {
          let inner = &mut inner.write;
          let desc = path.into_write();
          inner.check_partial(&desc, api_name)?;
          desc.0
        } else {
          path
        }
      }
    };

    let special_path = if access_kind.is_no_follow() {
      // Don't canonicalize: lstat/readlink/readdir need to operate on the
      // un-resolved path. The /proc, /dev, /sys prefix guard inside
      // `check_special_file` still fires when the caller-supplied path is
      // itself a kernel-magic location (e.g. `/proc/self/root/...`).
      SpecialFilePathQueryDescriptor::from_path_query_no_canonicalize(path)
    } else {
      self.descriptor_parser.parse_special_file_descriptor(path)?
    };
    self.check_special_file(special_path, access_kind, api_name)
  }

  #[inline(always)]
  pub fn check_read_all(
    &self,
    api_name: &str,
  ) -> Result<(), PermissionCheckError> {
    oden_capsec_decide_aggregate(OdenFamily::Fs, "read", "*", Some(api_name))?;
    self
      .inner
      .lock()
      .read
      .check_all(Some(api_name))
      .map_err(ignored_to_not_found)
  }

  #[inline(always)]
  pub fn query_read_all(&self) -> bool {
    if oden_capsec_active() {
      return false;
    }
    self.inner.lock().read.query(None) == PermissionState::Granted
  }

  #[inline(always)]
  pub fn check_write_all(
    &self,
    api_name: &str,
  ) -> Result<(), PermissionCheckError> {
    oden_capsec_decide_aggregate(OdenFamily::Fs, "write", "*", Some(api_name))?;
    self.inner.lock().write.check_all(Some(api_name))?;
    Ok(())
  }

  #[inline(always)]
  pub fn check_write_partial<'a>(
    &self,
    path: Cow<'a, Path>,
    api_name: &str,
  ) -> Result<CheckedPath<'a>, PermissionCheckError> {
    if oden_capsec_active() {
      oden_capsec_decide(
        OdenFamily::Fs,
        "write",
        &path.to_string_lossy(),
        Some(api_name),
      )?;
    }
    let mut inner = self.inner.lock();
    let inner = &mut inner.write;
    if inner.is_allow_all() {
      write_audit(WriteQueryDescriptor::flag_name(), &path);
      Ok(CheckedPath {
        path: PathWithRequested {
          path,
          requested: None,
        },
        canonicalized: false,
      })
    } else {
      let desc = self.descriptor_parser.parse_path_query(path)?.into_write();
      inner.check_partial(&desc, Some(api_name))?;
      // skip checking for special permissions because we consider
      // write_partial as WriteNoFollow because it's only used for
      // fs::remove
      Ok(CheckedPath {
        path: PathWithRequested {
          path: desc.0.path,
          requested: desc.0.requested.map(Cow::Owned),
        },
        canonicalized: false,
      })
    }
  }

  /// Strict counterpart of [`Self::check_write_partial`]: every path below the
  /// query must be allowed. Use this for recursive write operations such as
  /// `fs::remove_all`, where a deny scope *inside* the requested tree must still
  /// block the operation. (`check_open` deliberately uses partial semantics, so
  /// recursive callers must not route through it.)
  #[inline(always)]
  pub fn check_write<'a>(
    &self,
    path: Cow<'a, Path>,
    api_name: &str,
  ) -> Result<CheckedPath<'a>, PermissionCheckError> {
    if oden_capsec_active() {
      oden_capsec_decide(
        OdenFamily::Fs,
        "write",
        &path.to_string_lossy(),
        Some(api_name),
      )?;
    }
    let mut inner = self.inner.lock();
    let inner = &mut inner.write;
    if inner.is_allow_all() {
      write_audit(WriteQueryDescriptor::flag_name(), &path);
      Ok(CheckedPath {
        path: PathWithRequested {
          path,
          requested: None,
        },
        canonicalized: false,
      })
    } else {
      let desc = self.descriptor_parser.parse_path_query(path)?.into_write();
      inner.check(&desc, Some(api_name))?;
      // skip checking for special permissions because this is treated as
      // WriteNoFollow (it's only used for the recursive `fs::remove` path)
      Ok(CheckedPath {
        path: PathWithRequested {
          path: desc.0.path,
          requested: desc.0.requested.map(Cow::Owned),
        },
        canonicalized: false,
      })
    }
  }

  #[inline(always)]
  pub fn check_run(
    &self,
    cmd: &RunQueryDescriptor,
    api_name: &str,
  ) -> Result<(), PermissionCheckError> {
    oden_capsec_decide(
      OdenFamily::Run,
      "run",
      &cmd.display_name(),
      Some(api_name),
    )?;
    self.inner.lock().run.check(cmd, Some(api_name))?;
    Ok(())
  }

  #[inline(always)]
  pub fn check_run_all(
    &mut self,
    api_name: &str,
  ) -> Result<(), PermissionCheckError> {
    oden_capsec_decide(OdenFamily::Run, "run", "*", Some(api_name))?;
    self.inner.lock().run.check_all(Some(api_name))?;
    Ok(())
  }

  #[inline(always)]
  pub fn query_run_all(&mut self, api_name: &str) -> bool {
    if oden_capsec_active() && !oden_capsec_principal().is_ambient() {
      return false;
    }
    self.inner.lock().run.query_all(Some(api_name))
  }

  #[inline(always)]
  pub fn check_sys(
    &self,
    kind: &str,
    api_name: &str,
  ) -> Result<(), PermissionCheckError> {
    oden_capsec_decide(OdenFamily::Sys, "read", kind, Some(api_name))?;
    self.inner.lock().sys.check(
      &self.descriptor_parser.parse_sys_descriptor(kind)?,
      Some(api_name),
    )?;
    Ok(())
  }

  #[inline(always)]
  pub fn check_env(&self, var: &str) -> Result<(), PermissionCheckError> {
    self.check_env_action(var, "read")
  }

  #[inline(always)]
  pub fn check_env_action(
    &self,
    var: &str,
    action: &str,
  ) -> Result<(), PermissionCheckError> {
    oden_capsec_decide(OdenFamily::Env, action, var, None)?;
    self.inner.lock().env.check(var, None)?;
    Ok(())
  }

  #[inline(always)]
  pub fn check_env_all(&self) -> Result<(), PermissionCheckError> {
    oden_capsec_decide_aggregate(OdenFamily::Env, "read", "*", None)?;
    self.inner.lock().env.check_all()?;
    Ok(())
  }

  #[inline(always)]
  pub fn check_sys_all(&self) -> Result<(), PermissionCheckError> {
    oden_capsec_decide(OdenFamily::Sys, "read", "*", None)?;
    self.inner.lock().sys.check_all()?;
    Ok(())
  }

  #[inline(always)]
  pub fn check_ffi_all(&self) -> Result<(), PermissionCheckError> {
    oden_capsec_decide(OdenFamily::Ffi, "load", "*", None)?;
    self.inner.lock().ffi.check_all()?;
    Ok(())
  }

  #[inline(always)]
  pub fn check_has_all_permissions(
    &self,
    context_path: &Path,
  ) -> Result<(), PermissionCheckError> {
    let inner = self.inner.lock();
    if inner.all_granted() {
      Ok(())
    } else {
      let display_name = format_display_name(context_path.to_string_lossy());
      Err(
        PermissionState::permission_denied_error(
          "all",
          Some(display_name.as_ref()),
          PermissionState::Denied,
        )
        .into(),
      )
    }
  }

  /// Checks special file access, returning the failed permission type if
  /// not successful.
  #[must_use = "the resolved return value to mitigate time-of-check to time-of-use issues"]
  pub fn check_special_file<'a>(
    &self,
    path: SpecialFilePathQueryDescriptor<'a>,
    access_kind: OpenAccessKind,
    _api_name: Option<&str>,
  ) -> Result<CheckedPath<'a>, PermissionCheckError> {
    let requested = path.requested;
    let canonicalized = path.canonicalized;
    let path = path.path;

    // Safe files with no major additional side-effects.
    if cfg!(unix)
      && (path == OsStr::new("/dev/random")
        || path == OsStr::new("/dev/urandom")
        || path == OsStr::new("/dev/zero")
        || path == OsStr::new("/dev/null"))
    {
      return Ok(CheckedPath {
        path: PathWithRequested {
          path,
          requested: requested.map(Cow::Owned),
        },
        canonicalized,
      });
    }

    // We allow /dev/tty access specifically for checking isatty() or reading input,
    // but we BLOCK write access to prevent permission prompt spoofing attacks.
    if cfg!(unix) && path == OsStr::new("/dev/tty") && !access_kind.is_write() {
      return Ok(CheckedPath {
        path: PathWithRequested {
          path,
          requested: requested.map(Cow::Owned),
        },
        canonicalized,
      });
    }

    /// We'll allow opening /proc/self/fd/{n} without additional permissions under the following conditions:
    ///
    /// 1. n > 2. This allows for opening bash-style redirections, but not stdio
    /// 2. the fd referred to by n is a pipe
    #[cfg(unix)]
    fn is_fd_file_is_pipe(path: &Path) -> bool {
      if let Some(fd) = path.file_name()
        && let Ok(s) = std::str::from_utf8(fd.as_encoded_bytes())
        && let Ok(n) = s.parse::<i32>()
        && n > 2
      {
        // SAFETY: This is proper use of the stat syscall
        unsafe {
          let mut stat = std::mem::zeroed::<libc::stat>();
          if libc::fstat(n, &mut stat as _) == 0
            && ((stat.st_mode & libc::S_IFMT) & libc::S_IFIFO) != 0
          {
            return true;
          }
        };
      }
      false
    }

    // On unixy systems, we allow opening /dev/fd/XXX for valid FDs that
    // are pipes.
    #[cfg(unix)]
    if path.starts_with("/dev/fd") && is_fd_file_is_pipe(&path) {
      return Ok(CheckedPath {
        path: PathWithRequested {
          path,
          requested: requested.map(Cow::Owned),
        },
        canonicalized,
      });
    }

    if cfg!(target_os = "linux") {
      // On Linux, we also allow opening /proc/self/fd/XXX for valid FDs that
      // are pipes.
      #[cfg(unix)]
      if path.starts_with("/proc/self/fd") && is_fd_file_is_pipe(&path) {
        return Ok(CheckedPath {
          path: PathWithRequested {
            path,
            requested: requested.map(Cow::Owned),
          },
          canonicalized,
        });
      }
      if path.starts_with("/dev")
        || path.starts_with("/proc")
        || path.starts_with("/sys")
      {
        if path.ends_with("/environ") {
          self.check_env_all()?;
        } else if path.starts_with("/proc/pressure/") {
          // Allow /proc/pressure/* files with just --allow-read since they are
          // read-only system monitoring files that only expose performance metrics
        } else {
          self.check_has_all_permissions(&path)?;
        }
      }
    } else if cfg!(unix) {
      if path.starts_with("/dev") {
        self.check_has_all_permissions(&path)?;
      }
    } else if cfg!(target_os = "windows") {
      // \\.\nul is allowed
      let s = path.as_os_str().as_encoded_bytes();
      if s.eq_ignore_ascii_case(br#"\\.\nul"#) {
        return Ok(CheckedPath {
          path: PathWithRequested {
            path,
            requested: requested.map(Cow::Owned),
          },
          canonicalized,
        });
      }

      fn is_normalized_windows_drive_path(path: &Path) -> bool {
        let s = path.as_os_str().as_encoded_bytes();
        if s.starts_with(br#"\\"#) {
          // \\?\X:\
          if s.starts_with(br#"\\?\"#) && s.len() >= 7 {
            s[4].is_ascii_alphabetic() && s[5] == b':' && s[6] == b'\\'
          } else {
            false
          }
        } else {
          // the input path was normalized with strip_unc_prefix, so it's a
          // normalized windows drive path
          true
        }
      }

      // If this is a normalized drive path, accept it
      if !is_normalized_windows_drive_path(&path) {
        self.check_has_all_permissions(&path)?;
      }
    } else {
      unimplemented!()
    }
    Ok(CheckedPath {
      path: PathWithRequested {
        path,
        requested: requested.map(Cow::Owned),
      },
      canonicalized,
    })
  }

  #[inline(always)]
  pub fn check_net_url(
    &mut self,
    action: NetPermissionAction,
    url: &Url,
    api_name: &str,
  ) -> Result<(), PermissionCheckError> {
    oden_capsec_decide(
      OdenFamily::Network,
      action.as_str(),
      url.as_str(),
      Some(api_name),
    )?;
    let mut inner = self.inner.lock();
    audit_and_skip_check_if_is_permission_fully_granted!(
      inner.net,
      NetDescriptor::flag_name(),
      url
    );
    let desc = self.descriptor_parser.parse_net_descriptor_from_url(url)?;
    inner.net.check(&desc, Some(api_name))?;
    Ok(())
  }

  #[inline(always)]
  pub fn check_net<T: AsRef<str>>(
    &mut self,
    action: NetPermissionAction,
    host: &(T, Option<u16>),
    api_name: &str,
  ) -> Result<(), PermissionCheckError> {
    let hostname = Host::parse_for_query(host.0.as_ref())?;
    let descriptor = NetDescriptor(hostname, host.1.map(Into::into));
    let target = descriptor.display_name().into_owned();
    oden_capsec_decide(
      OdenFamily::Network,
      action.as_str(),
      &target,
      Some(api_name),
    )?;
    let mut inner = self.inner.lock();
    let inner = &mut inner.net;
    audit_and_skip_check_if_is_permission_fully_granted!(
      inner,
      NetDescriptor::flag_name(),
      target
    );
    inner.check(&descriptor, Some(api_name))?;
    Ok(())
  }

  /// After resolving a hostname to an IP address, check that the resolved
  /// IP is not in the deny list. This prevents bypassing IP-literal deny
  /// rules via numeric hostname aliases or attacker-controlled DNS.
  #[inline(always)]
  pub fn check_net_resolved(
    &mut self,
    action: NetPermissionAction,
    resolved_ip: &std::net::IpAddr,
    port: u16,
    api_name: &str,
  ) -> Result<(), PermissionCheckError> {
    // The protected guard is engine-owned and runs at the actual candidate
    // boundary before stock layer-1 resolved-deny checks and before any
    // application bytes. Every caller repeats this for redirects, reconnects,
    // Happy-Eyeballs candidates, and UDP destinations.
    oden_capsec_check_protected_metadata(action, *resolved_ip, port, api_name)?;
    oden_capsec_check_protected_inspector_endpoint(
      action,
      *resolved_ip,
      port,
      api_name,
    )?;
    let mut inner = self.inner.lock();
    let desc = NetDescriptor(Host::Ip(*resolved_ip), Some(port.into()));
    inner.net.check_resolved_ip_deny(&desc, Some(api_name))?;
    Ok(())
  }

  #[inline(always)]
  pub fn check_net_vsock(
    &mut self,
    action: NetPermissionAction,
    cid: u32,
    port: u32,
    api_name: &str,
  ) -> Result<(), PermissionCheckError> {
    let target = format!("vsock:{cid}:{port}");
    oden_capsec_decide(
      OdenFamily::Network,
      action.as_str(),
      &target,
      Some(api_name),
    )?;
    let mut inner = self.inner.lock();
    audit_and_skip_check_if_is_permission_fully_granted!(
      inner.net,
      NetDescriptor::flag_name(),
      target
    );
    let desc = NetDescriptor(Host::Vsock(cid), Some(port));
    inner.net.check(&desc, Some(api_name))?;
    Ok(())
  }

  /// Network permission check for Unix domain socket endpoints.
  ///
  /// `path` must already be resolved to an absolute path (typically by the
  /// caller's earlier `check_open` pass). Matched lexically against
  /// `--allow-net=unix:<absolute-path>` rules. Both sides are lexically
  /// normalized (`.`/`..` components removed; rules at parse time, the query
  /// path by `check_open`), but symlinks are deliberately not resolved,
  /// mirroring `check_open`'s symlink-location semantics: a rule scopes the
  /// socket *location*, not the inode it points at.
  ///
  /// Abstract socket paths (Linux, leading NUL) are not absolute, so they
  /// cannot be expressed as a scoped `unix:` rule and are only reachable via
  /// an unscoped `--allow-net` grant.
  pub fn check_net_unix_socket(
    &mut self,
    action: NetPermissionAction,
    path: &Path,
    api_name: Option<&str>,
  ) -> Result<(), PermissionCheckError> {
    let target = format!("unix:{}", path.display());
    oden_capsec_decide(
      OdenFamily::Network,
      action.as_str(),
      &target,
      api_name,
    )?;
    let mut inner = self.inner.lock();
    audit_and_skip_check_if_is_permission_fully_granted!(
      inner.net,
      NetDescriptor::flag_name(),
      target
    );
    let desc = NetDescriptor(Host::UnixSocket(path.to_path_buf()), None);
    inner.net.check(&desc, api_name)?;
    Ok(())
  }

  #[inline(always)]
  pub fn check_ffi<'a>(
    &mut self,
    path: Cow<'a, Path>,
  ) -> Result<Cow<'a, Path>, PermissionCheckError> {
    if oden_capsec_active() {
      oden_capsec_decide(
        OdenFamily::Ffi,
        "load",
        &path.to_string_lossy(),
        None,
      )?;
    }
    let mut inner = self.inner.lock();
    let inner = &mut inner.ffi;
    if inner.is_allow_all() {
      write_audit(FfiQueryDescriptor::flag_name(), &path);
      Ok(path)
    } else {
      let desc = self.descriptor_parser.parse_path_query(path)?.into_ffi();
      inner.check(&desc, None)?;
      Ok(desc.0.path)
    }
  }

  #[must_use = "the resolved return value to mitigate time-of-check to time-of-use issues"]
  #[inline(always)]
  pub fn check_ffi_partial_no_path(
    &mut self,
  ) -> Result<(), PermissionCheckError> {
    oden_capsec_decide(OdenFamily::Ffi, "load", "*", None)?;
    let mut inner = self.inner.lock();
    let inner = &mut inner.ffi;
    if !inner.is_allow_all() {
      inner.check_partial(None)?;
    } else {
      write_audit(FfiQueryDescriptor::flag_name(), ());
    }
    Ok(())
  }

  #[must_use = "the resolved return value to mitigate time-of-check to time-of-use issues"]
  #[inline(always)]
  pub fn check_ffi_partial_with_path<'a>(
    &mut self,
    path: Cow<'a, Path>,
  ) -> Result<Cow<'a, Path>, PermissionCheckError> {
    if oden_capsec_active() {
      oden_capsec_decide(
        OdenFamily::Ffi,
        "load",
        &path.to_string_lossy(),
        None,
      )?;
    }
    let mut inner = self.inner.lock();
    let inner = &mut inner.ffi;
    if inner.is_allow_all() {
      write_audit(FfiQueryDescriptor::flag_name(), &path);
      Ok(path)
    } else {
      let desc = self.descriptor_parser.parse_path_query(path)?.into_ffi();
      inner.check_partial(Some(&desc))?;
      Ok(desc.0.path)
    }
  }

  // query

  #[inline(always)]
  pub fn query_read(
    &self,
    path: Option<&str>,
  ) -> Result<PermissionState, PathResolveError> {
    let inner = self.inner.lock();
    let permission = &inner.read;
    if permission.is_allow_all() {
      return Ok(PermissionState::Granted);
    }
    Ok(
      permission.query(
        path
          .map(|path| {
            Ok::<_, PathResolveError>(
              self
                .descriptor_parser
                .parse_path_query(Cow::Borrowed(Path::new(path)))?
                .into_read(),
            )
          })
          .transpose()?
          .as_ref(),
      ),
    )
  }

  #[inline(always)]
  pub fn query_write(
    &self,
    path: Option<&str>,
  ) -> Result<PermissionState, PathResolveError> {
    let inner = self.inner.lock();
    let permission = &inner.write;
    if permission.is_allow_all() {
      return Ok(PermissionState::Granted);
    }
    Ok(
      permission.query(
        path
          .map(|path| {
            Ok::<_, PathResolveError>(
              self
                .descriptor_parser
                .parse_path_query(Cow::Borrowed(Path::new(path)))?
                .into_write(),
            )
          })
          .transpose()?
          .as_ref(),
      ),
    )
  }

  #[inline(always)]
  pub fn query_net(
    &self,
    host: Option<&str>,
  ) -> Result<PermissionState, NetDescriptorParseError> {
    let inner = self.inner.lock();
    let permission = &inner.net;
    if permission.is_allow_all() {
      return Ok(PermissionState::Granted);
    }
    Ok(
      permission.query(
        match host {
          None => None,
          Some(h) => Some(self.descriptor_parser.parse_net_query(h)?),
        }
        .as_ref(),
      ),
    )
  }

  #[inline(always)]
  pub fn query_env(&self, var: Option<&str>) -> PermissionState {
    let inner = self.inner.lock();
    let permission = &inner.env;
    if permission.is_allow_all() {
      return PermissionState::Granted;
    }
    permission.query(var)
  }

  #[inline(always)]
  pub fn query_sys(
    &self,
    kind: Option<&str>,
  ) -> Result<PermissionState, SysDescriptorParseError> {
    let inner = self.inner.lock();
    let permission = &inner.sys;
    if permission.is_allow_all() {
      return Ok(PermissionState::Granted);
    }
    Ok(
      permission.query(
        kind
          .map(|kind| self.descriptor_parser.parse_sys_descriptor(kind))
          .transpose()?
          .as_ref(),
      ),
    )
  }

  #[inline(always)]
  pub fn query_run(
    &self,
    cmd: Option<&str>,
  ) -> Result<PermissionState, RunDescriptorParseError> {
    let inner = self.inner.lock();
    let permission = &inner.run;
    if permission.is_allow_all() {
      return Ok(PermissionState::Granted);
    }
    Ok(
      permission.query(
        cmd
          .map(|request| self.descriptor_parser.parse_run_query(request))
          .transpose()?
          .as_ref(),
      ),
    )
  }

  #[inline(always)]
  pub fn query_ffi(
    &self,
    path: Option<&str>,
  ) -> Result<PermissionState, PathResolveError> {
    let inner = self.inner.lock();
    let permission = &inner.ffi;
    if permission.is_allow_all() {
      return Ok(PermissionState::Granted);
    }
    Ok(
      permission.query(
        path
          .map(|path| {
            Ok::<_, PathResolveError>(
              self
                .descriptor_parser
                .parse_path_query(Cow::Borrowed(Path::new(path)))?
                .into_ffi(),
            )
          })
          .transpose()?
          .as_ref(),
      ),
    )
  }

  #[inline(always)]
  pub fn query_import(
    &self,
    host: Option<&str>,
  ) -> Result<PermissionState, NetDescriptorParseError> {
    let inner = self.inner.lock();
    let permission = &inner.import;
    if permission.is_allow_all() {
      return Ok(PermissionState::Granted);
    }
    Ok(
      permission.query(
        match host {
          None => None,
          Some(h) => {
            Some(self.descriptor_parser.parse_net_query(h)?.into_import())
          }
        }
        .as_ref(),
      ),
    )
  }

  // revoke

  #[inline(always)]
  pub fn revoke_read(
    &self,
    path: Option<&str>,
  ) -> Result<PermissionState, PathResolveError> {
    Ok(
      self.inner.lock().read.revoke(
        path
          .map(|path| {
            Ok::<_, PathResolveError>(
              self
                .descriptor_parser
                .parse_path_query(Cow::Borrowed(Path::new(path)))?
                .into_read(),
            )
          })
          .transpose()?
          .as_ref(),
      ),
    )
  }

  #[inline(always)]
  pub fn revoke_write(
    &self,
    path: Option<&str>,
  ) -> Result<PermissionState, PathResolveError> {
    Ok(
      self.inner.lock().write.revoke(
        path
          .map(|path| {
            Ok::<_, PathResolveError>(
              self
                .descriptor_parser
                .parse_path_query(Cow::Borrowed(Path::new(path)))?
                .into_write(),
            )
          })
          .transpose()?
          .as_ref(),
      ),
    )
  }

  #[inline(always)]
  pub fn revoke_net(
    &self,
    host: Option<&str>,
  ) -> Result<PermissionState, NetDescriptorParseError> {
    Ok(
      self.inner.lock().net.revoke(
        match host {
          None => None,
          Some(h) => Some(self.descriptor_parser.parse_net_query(h)?),
        }
        .as_ref(),
      ),
    )
  }

  #[inline(always)]
  pub fn revoke_env(&self, var: Option<&str>) -> PermissionState {
    self.inner.lock().env.revoke(var)
  }

  #[inline(always)]
  pub fn revoke_sys(
    &self,
    kind: Option<&str>,
  ) -> Result<PermissionState, SysDescriptorParseError> {
    Ok(
      self.inner.lock().sys.revoke(
        kind
          .map(|kind| self.descriptor_parser.parse_sys_descriptor(kind))
          .transpose()?
          .as_ref(),
      ),
    )
  }

  #[inline(always)]
  pub fn revoke_run(
    &self,
    cmd: Option<&str>,
  ) -> Result<PermissionState, RunDescriptorParseError> {
    Ok(
      self.inner.lock().run.revoke(
        cmd
          .map(|request| self.descriptor_parser.parse_run_query(request))
          .transpose()?
          .as_ref(),
      ),
    )
  }

  #[inline(always)]
  pub fn revoke_ffi(
    &self,
    path: Option<&str>,
  ) -> Result<PermissionState, PathResolveError> {
    Ok(
      self.inner.lock().ffi.revoke(
        path
          .map(|path| {
            Ok::<_, PathResolveError>(
              self
                .descriptor_parser
                .parse_path_query(Cow::Borrowed(Path::new(path)))?
                .into_ffi(),
            )
          })
          .transpose()?
          .as_ref(),
      ),
    )
  }

  #[inline(always)]
  pub fn revoke_import(
    &self,
    host: Option<&str>,
  ) -> Result<PermissionState, NetDescriptorParseError> {
    Ok(
      self.inner.lock().import.revoke(
        match host {
          None => None,
          Some(h) => {
            Some(self.descriptor_parser.parse_net_query(h)?.into_import())
          }
        }
        .as_ref(),
      ),
    )
  }

  // request

  #[inline(always)]
  pub fn request_read(
    &self,
    path: Option<&str>,
  ) -> Result<PermissionState, PathResolveError> {
    Ok(
      self.inner.lock().read.request(
        path
          .map(|path| {
            Ok::<_, PathResolveError>(
              self
                .descriptor_parser
                .parse_path_query(Cow::Borrowed(Path::new(path)))?
                .into_read(),
            )
          })
          .transpose()?
          .as_ref(),
      ),
    )
  }

  #[inline(always)]
  pub fn request_write(
    &self,
    path: Option<&str>,
  ) -> Result<PermissionState, PathResolveError> {
    Ok(
      self.inner.lock().write.request(
        path
          .map(|path| {
            Ok::<_, PathResolveError>(
              self
                .descriptor_parser
                .parse_path_query(Cow::Borrowed(Path::new(path)))?
                .into_write(),
            )
          })
          .transpose()?
          .as_ref(),
      ),
    )
  }

  #[inline(always)]
  pub fn request_net(
    &self,
    host: Option<&str>,
  ) -> Result<PermissionState, NetDescriptorParseError> {
    Ok(
      self.inner.lock().net.request(
        match host {
          None => None,
          Some(h) => Some(self.descriptor_parser.parse_net_query(h)?),
        }
        .as_ref(),
      ),
    )
  }

  #[inline(always)]
  pub fn request_env(&self, var: Option<&str>) -> PermissionState {
    self.inner.lock().env.request(var)
  }

  #[inline(always)]
  pub fn request_sys(
    &self,
    kind: Option<&str>,
  ) -> Result<PermissionState, SysDescriptorParseError> {
    Ok(
      self.inner.lock().sys.request(
        kind
          .map(|kind| self.descriptor_parser.parse_sys_descriptor(kind))
          .transpose()?
          .as_ref(),
      ),
    )
  }

  #[inline(always)]
  pub fn request_run(
    &self,
    cmd: Option<&str>,
  ) -> Result<PermissionState, RunDescriptorParseError> {
    Ok(
      self.inner.lock().run.request(
        cmd
          .map(|request| self.descriptor_parser.parse_run_query(request))
          .transpose()?
          .as_ref(),
      ),
    )
  }

  #[inline(always)]
  pub fn request_ffi(
    &self,
    path: Option<&str>,
  ) -> Result<PermissionState, PathResolveError> {
    Ok(
      self.inner.lock().ffi.request(
        path
          .map(|path| {
            Ok::<_, PathResolveError>(
              self
                .descriptor_parser
                .parse_path_query(Cow::Borrowed(Path::new(path)))?
                .into_ffi(),
            )
          })
          .transpose()?
          .as_ref(),
      ),
    )
  }

  #[inline(always)]
  pub fn request_import(
    &self,
    host: Option<&str>,
  ) -> Result<PermissionState, NetDescriptorParseError> {
    Ok(
      self.inner.lock().import.request(
        match host {
          None => None,
          Some(h) => {
            Some(self.descriptor_parser.parse_net_query(h)?.into_import())
          }
        }
        .as_ref(),
      ),
    )
  }
}

const fn unit_permission_from_flag_bools(
  allow_flag: bool,
  deny_flag: bool,
  name: &'static str,
  description: &'static str,
  prompt: bool,
) -> UnitPermission {
  UnitPermission {
    name,
    description,
    state: if deny_flag {
      PermissionState::Denied
    } else if allow_flag {
      PermissionState::Granted
    } else {
      PermissionState::Prompt
    },
    prompt,
  }
}

fn global_from_option<T>(flag: Option<&Vec<T>>) -> bool {
  matches!(flag, Some(v) if v.is_empty())
}

#[derive(Debug, Eq, PartialEq)]
pub enum ChildUnitPermissionArg {
  Inherit,
  Granted,
  NotGranted,
}

impl<'de> Deserialize<'de> for ChildUnitPermissionArg {
  fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
  where
    D: Deserializer<'de>,
  {
    struct ChildUnitPermissionArgVisitor;
    impl de::Visitor<'_> for ChildUnitPermissionArgVisitor {
      type Value = ChildUnitPermissionArg;

      fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("\"inherit\" or boolean")
      }

      fn visit_unit<E>(self) -> Result<ChildUnitPermissionArg, E>
      where
        E: de::Error,
      {
        Ok(ChildUnitPermissionArg::NotGranted)
      }

      fn visit_str<E>(self, v: &str) -> Result<ChildUnitPermissionArg, E>
      where
        E: de::Error,
      {
        if v == "inherit" {
          Ok(ChildUnitPermissionArg::Inherit)
        } else {
          Err(de::Error::invalid_value(de::Unexpected::Str(v), &self))
        }
      }

      fn visit_bool<E>(self, v: bool) -> Result<ChildUnitPermissionArg, E>
      where
        E: de::Error,
      {
        match v {
          true => Ok(ChildUnitPermissionArg::Granted),
          false => Ok(ChildUnitPermissionArg::NotGranted),
        }
      }
    }
    deserializer.deserialize_any(ChildUnitPermissionArgVisitor)
  }
}

#[derive(Debug, Eq, PartialEq)]
pub enum ChildUnaryPermissionArg {
  Inherit,
  Granted,
  NotGranted,
  GrantedList(Vec<String>),
}

impl<'de> Deserialize<'de> for ChildUnaryPermissionArg {
  fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
  where
    D: Deserializer<'de>,
  {
    struct ChildUnaryPermissionArgVisitor;
    impl<'de> de::Visitor<'de> for ChildUnaryPermissionArgVisitor {
      type Value = ChildUnaryPermissionArg;

      fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("\"inherit\" or boolean or string[]")
      }

      fn visit_unit<E>(self) -> Result<ChildUnaryPermissionArg, E>
      where
        E: de::Error,
      {
        Ok(ChildUnaryPermissionArg::NotGranted)
      }

      fn visit_str<E>(self, v: &str) -> Result<ChildUnaryPermissionArg, E>
      where
        E: de::Error,
      {
        if v == "inherit" {
          Ok(ChildUnaryPermissionArg::Inherit)
        } else {
          Err(de::Error::invalid_value(de::Unexpected::Str(v), &self))
        }
      }

      fn visit_bool<E>(self, v: bool) -> Result<ChildUnaryPermissionArg, E>
      where
        E: de::Error,
      {
        match v {
          true => Ok(ChildUnaryPermissionArg::Granted),
          false => Ok(ChildUnaryPermissionArg::NotGranted),
        }
      }

      fn visit_seq<V>(
        self,
        mut v: V,
      ) -> Result<ChildUnaryPermissionArg, V::Error>
      where
        V: de::SeqAccess<'de>,
      {
        let mut granted_list = vec![];
        while let Some(value) = v.next_element::<String>()? {
          granted_list.push(value);
        }
        Ok(ChildUnaryPermissionArg::GrantedList(granted_list))
      }
    }
    deserializer.deserialize_any(ChildUnaryPermissionArgVisitor)
  }
}

/// Directly deserializable from JS worker and test permission options.
#[derive(Debug, Eq, PartialEq)]
pub struct ChildPermissionsArg {
  env: ChildUnaryPermissionArg,
  net: ChildUnaryPermissionArg,
  ffi: ChildUnaryPermissionArg,
  import: ChildUnaryPermissionArg,
  read: ChildUnaryPermissionArg,
  run: ChildUnaryPermissionArg,
  sys: ChildUnaryPermissionArg,
  write: ChildUnaryPermissionArg,
}

impl ChildPermissionsArg {
  pub fn inherit() -> Self {
    ChildPermissionsArg {
      env: ChildUnaryPermissionArg::Inherit,
      net: ChildUnaryPermissionArg::Inherit,
      ffi: ChildUnaryPermissionArg::Inherit,
      import: ChildUnaryPermissionArg::Inherit,
      read: ChildUnaryPermissionArg::Inherit,
      run: ChildUnaryPermissionArg::Inherit,
      sys: ChildUnaryPermissionArg::Inherit,
      write: ChildUnaryPermissionArg::Inherit,
    }
  }

  pub fn none() -> Self {
    ChildPermissionsArg {
      env: ChildUnaryPermissionArg::NotGranted,
      net: ChildUnaryPermissionArg::NotGranted,
      ffi: ChildUnaryPermissionArg::NotGranted,
      import: ChildUnaryPermissionArg::NotGranted,
      read: ChildUnaryPermissionArg::NotGranted,
      run: ChildUnaryPermissionArg::NotGranted,
      sys: ChildUnaryPermissionArg::NotGranted,
      write: ChildUnaryPermissionArg::NotGranted,
    }
  }
}

impl<'de> Deserialize<'de> for ChildPermissionsArg {
  fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
  where
    D: Deserializer<'de>,
  {
    struct ChildPermissionsArgVisitor;
    impl<'de> de::Visitor<'de> for ChildPermissionsArgVisitor {
      type Value = ChildPermissionsArg;

      fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("\"inherit\" or \"none\" or object")
      }

      fn visit_unit<E>(self) -> Result<ChildPermissionsArg, E>
      where
        E: de::Error,
      {
        Ok(ChildPermissionsArg::inherit())
      }

      fn visit_str<E>(self, v: &str) -> Result<ChildPermissionsArg, E>
      where
        E: de::Error,
      {
        if v == "inherit" {
          Ok(ChildPermissionsArg::inherit())
        } else if v == "none" {
          Ok(ChildPermissionsArg::none())
        } else {
          Err(de::Error::invalid_value(de::Unexpected::Str(v), &self))
        }
      }

      fn visit_map<V>(self, mut v: V) -> Result<ChildPermissionsArg, V::Error>
      where
        V: de::MapAccess<'de>,
      {
        let mut child_permissions_arg = ChildPermissionsArg::none();
        while let Some((key, value)) =
          v.next_entry::<String, serde_json::Value>()?
        {
          if key == "env" {
            let arg = serde_json::from_value::<ChildUnaryPermissionArg>(value);
            child_permissions_arg.env = arg.map_err(|e| {
              de::Error::custom(format!("(deno.permissions.env) {e}"))
            })?;
          } else if key == "net" {
            let arg = serde_json::from_value::<ChildUnaryPermissionArg>(value);
            child_permissions_arg.net = arg.map_err(|e| {
              de::Error::custom(format!("(deno.permissions.net) {e}"))
            })?;
          } else if key == "ffi" {
            let arg = serde_json::from_value::<ChildUnaryPermissionArg>(value);
            child_permissions_arg.ffi = arg.map_err(|e| {
              de::Error::custom(format!("(deno.permissions.ffi) {e}"))
            })?;
          } else if key == "import" {
            let arg = serde_json::from_value::<ChildUnaryPermissionArg>(value);
            child_permissions_arg.import = arg.map_err(|e| {
              de::Error::custom(format!("(deno.permissions.import) {e}"))
            })?;
          } else if key == "read" {
            let arg = serde_json::from_value::<ChildUnaryPermissionArg>(value);
            child_permissions_arg.read = arg.map_err(|e| {
              de::Error::custom(format!("(deno.permissions.read) {e}"))
            })?;
          } else if key == "run" {
            let arg = serde_json::from_value::<ChildUnaryPermissionArg>(value);
            child_permissions_arg.run = arg.map_err(|e| {
              de::Error::custom(format!("(deno.permissions.run) {e}"))
            })?;
          } else if key == "sys" {
            let arg = serde_json::from_value::<ChildUnaryPermissionArg>(value);
            child_permissions_arg.sys = arg.map_err(|e| {
              de::Error::custom(format!("(deno.permissions.sys) {e}"))
            })?;
          } else if key == "write" {
            let arg = serde_json::from_value::<ChildUnaryPermissionArg>(value);
            child_permissions_arg.write = arg.map_err(|e| {
              de::Error::custom(format!("(deno.permissions.write) {e}"))
            })?;
          } else {
            return Err(de::Error::custom("unknown permission name"));
          }
        }
        Ok(child_permissions_arg)
      }
    }
    deserializer.deserialize_any(ChildPermissionsArgVisitor)
  }
}

/// Parses and normalizes permissions.
///
/// This trait is necessary because this crate doesn't have access
/// to the file system.
pub trait PermissionDescriptorParser: Debug + Send + Sync {
  fn parse_read_descriptor(
    &self,
    text: &str,
  ) -> Result<ReadDescriptor, PathResolveError>;

  fn parse_write_descriptor(
    &self,
    text: &str,
  ) -> Result<WriteDescriptor, PathResolveError>;

  fn parse_net_descriptor(
    &self,
    text: &str,
  ) -> Result<NetDescriptor, NetDescriptorParseError>;

  fn parse_net_descriptor_from_url(
    &self,
    url: &Url,
  ) -> Result<NetDescriptor, NetDescriptorFromUrlParseError> {
    NetDescriptor::from_url(url)
  }

  fn parse_import_descriptor(
    &self,
    text: &str,
  ) -> Result<ImportDescriptor, NetDescriptorParseError>;

  fn parse_import_descriptor_from_url(
    &self,
    url: &Url,
  ) -> Result<ImportDescriptor, NetDescriptorFromUrlParseError> {
    ImportDescriptor::from_url(url)
  }

  fn parse_env_descriptor(
    &self,
    text: &str,
  ) -> Result<EnvDescriptor, EnvDescriptorParseError>;

  fn parse_sys_descriptor(
    &self,
    text: &str,
  ) -> Result<SysDescriptor, SysDescriptorParseError>;

  fn parse_allow_run_descriptor(
    &self,
    text: &str,
  ) -> Result<AllowRunDescriptorParseResult, RunDescriptorParseError>;

  fn parse_deny_run_descriptor(
    &self,
    text: &str,
  ) -> Result<DenyRunDescriptor, PathResolveError>;

  fn parse_ffi_descriptor(
    &self,
    text: &str,
  ) -> Result<FfiDescriptor, PathResolveError>;

  // queries

  fn parse_path_query<'a>(
    &self,
    path: Cow<'a, Path>,
  ) -> Result<PathQueryDescriptor<'a>, PathResolveError>;

  fn parse_special_file_descriptor<'a>(
    &self,
    path: PathQueryDescriptor<'a>,
  ) -> Result<SpecialFilePathQueryDescriptor<'a>, PathResolveError>;

  fn parse_net_query(
    &self,
    text: &str,
  ) -> Result<NetDescriptor, NetDescriptorParseError>;

  fn parse_run_query<'a>(
    &self,
    requested: &'a str,
  ) -> Result<RunQueryDescriptor<'a>, RunDescriptorParseError>;
}

static IS_STANDALONE: AtomicFlag = AtomicFlag::lowered();

pub fn mark_standalone() {
  IS_STANDALONE.raise();
}

pub fn is_standalone() -> bool {
  IS_STANDALONE.is_raised()
}

#[cfg(test)]
mod tests {
  use std::net::Ipv4Addr;
  use std::sync::atomic::AtomicBool;

  use fqdn::fqdn;
  use prompter::tests::*;
  use serde_json::json;
  use sys_traits::EnvCurrentDir;

  use super::*;

  #[cfg(unix)]
  #[test]
  fn native_fd_classifier_closes_all_inet_stream_passage_by_object_type() {
    use std::os::fd::AsRawFd;
    use std::os::fd::FromRawFd;

    let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
      .expect("bind INET listener");
    let endpoint = listener.local_addr().unwrap();
    let client =
      std::net::TcpStream::connect(endpoint).expect("connect INET client");
    let (accepted, _) = listener.accept().expect("accept INET client");
    let ordinary_listener =
      std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
        .expect("bind ordinary listener");
    let udp = std::net::UdpSocket::bind(endpoint)
      .expect("TCP and UDP may share the same numeric endpoint");
    let (unix_stream, _) = std::os::unix::net::UnixStream::pair().unwrap();
    let file = std::fs::File::open("Cargo.toml").unwrap();
    let mut pipe_fds = [-1; 2];
    // SAFETY: pipe_fds has exactly the two output slots required by pipe().
    assert_eq!(unsafe { libc::pipe(pipe_fds.as_mut_ptr()) }, 0);
    // SAFETY: both descriptors were freshly returned by pipe().
    let pipe_read = unsafe { std::os::fd::OwnedFd::from_raw_fd(pipe_fds[0]) };
    // SAFETY: both descriptors were freshly returned by pipe().
    let _pipe_write = unsafe { std::os::fd::OwnedFd::from_raw_fd(pipe_fds[1]) };

    assert!(
      oden_capsec_fd_is_inet_stream(listener.as_raw_fd()).unwrap(),
      "INET listeners are categorically closed"
    );
    assert!(
      oden_capsec_fd_is_inet_stream(client.as_raw_fd()).unwrap(),
      "INET clients are categorically closed"
    );
    assert!(
      oden_capsec_fd_is_inet_stream(accepted.as_raw_fd()).unwrap(),
      "accepted INET streams are categorically closed"
    );

    // Model the fake-facade attack: JavaScript supplies only a guessed raw
    // integer, but the native duplicate still identifies the same socket.
    // SAFETY: fcntl either fails or returns a new owned descriptor.
    let dup =
      unsafe { libc::fcntl(client.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 0) };
    assert!(dup >= 0);
    // SAFETY: dup is the fresh descriptor returned above.
    let dup = unsafe { std::os::fd::OwnedFd::from_raw_fd(dup) };
    assert!(oden_capsec_fd_is_inet_stream(dup.as_raw_fd()).unwrap());

    // Model inspector shutdown/unregistration while the connected file
    // descriptions and their duplicates remain live. Classification stays
    // closed because it never consults the mutable endpoint registry.
    drop(listener);
    assert!(oden_capsec_fd_is_inet_stream(client.as_raw_fd()).unwrap());
    assert!(oden_capsec_fd_is_inet_stream(accepted.as_raw_fd()).unwrap());
    assert!(oden_capsec_fd_is_inet_stream(dup.as_raw_fd()).unwrap());

    assert!(
      oden_capsec_fd_is_inet_stream(ordinary_listener.as_raw_fd()).unwrap(),
      "endpoint reuse and unrelated TCP cannot evade the categorical close"
    );
    assert!(
      !oden_capsec_fd_is_inet_stream(udp.as_raw_fd()).unwrap(),
      "UDP remains compatible"
    );
    assert!(
      !oden_capsec_fd_is_inet_stream(unix_stream.as_raw_fd()).unwrap(),
      "Unix streams remain compatible"
    );
    assert!(
      !oden_capsec_fd_is_inet_stream(file.as_raw_fd()).unwrap(),
      "ordinary files remain compatible"
    );
    assert!(
      !oden_capsec_fd_is_inet_stream(pipe_read.as_raw_fd()).unwrap(),
      "ordinary pipes remain compatible"
    );
  }

  #[test]
  fn cped_principal_selection_skips_ambient_wrappers() {
    let package = OdenPrincipal::Package {
      name: "network-probe".to_string(),
      version: Some("1.0.0".to_string()),
    };
    assert_eq!(
      oden_capsec_scheduling_principal([
        (OdenPrincipal::Runtime, "ext:deno_node/net.ts".to_string()),
        (OdenPrincipal::Root, "file:///app/main.ts".to_string()),
        (
          package.clone(),
          "file:///app/node_modules/network-probe/index.js".to_string(),
        ),
      ]),
      Some((
        package,
        "file:///app/node_modules/network-probe/index.js".to_string(),
      ))
    );
    assert_eq!(
      oden_capsec_scheduling_principal([
        (OdenPrincipal::Root, "file:///app/main.ts".to_string()),
        (OdenPrincipal::Quarantine, "eval:dynamic".to_string()),
      ]),
      Some((OdenPrincipal::Quarantine, "eval:dynamic".to_string()))
    );
    assert_eq!(
      oden_capsec_scheduling_principal([
        (OdenPrincipal::Runtime, "ext:deno_node/net.ts".to_string()),
        (OdenPrincipal::Root, "file:///app/main.ts".to_string()),
      ]),
      Some((OdenPrincipal::Root, "file:///app/main.ts".to_string()))
    );
    assert_eq!(
      oden_capsec_scheduling_principal([(
        OdenPrincipal::Runtime,
        "ext:deno_node/net.ts".to_string(),
      )]),
      None
    );
  }

  #[test]
  fn trusted_host_actor_is_fallback_only_and_declares_both_effects() {
    assert_eq!(
      ODEN_TRUSTED_HOST_INSPECTOR_EFFECTS,
      [("runtime", "inspect"), ("inspector", "activate")]
    );

    let mut unattributed = Vec::new();
    oden_capsec_apply_unattributed_fallback(&mut unattributed, false);
    assert_eq!(unattributed, vec![OdenPrincipal::NoUser]);
    assert_eq!(
      OdenPolicy::constrained_principals(&unattributed),
      vec![OdenPrincipal::NoUser],
      "ordinary no-user attribution must remain fail-closed"
    );

    let mut trusted_host = Vec::new();
    oden_capsec_apply_unattributed_fallback(&mut trusted_host, true);
    assert_eq!(trusted_host, vec![OdenPrincipal::Runtime]);
    assert!(OdenPolicy::constrained_principals(&trusted_host).is_empty());

    let mut package_actor = vec![OdenPrincipal::Quarantine];
    oden_capsec_apply_unattributed_fallback(&mut package_actor, true);
    assert_eq!(
      package_actor,
      vec![OdenPrincipal::Quarantine],
      "trusted host actor must not replace a live or scheduled constrained actor"
    );
  }

  #[test]
  fn trusted_host_actor_never_overrides_live_or_scheduled_actor() {
    static ATTRIBUTION_TEST_LOCK: std::sync::Mutex<()> =
      std::sync::Mutex::new(());
    let _lock = ATTRIBUTION_TEST_LOCK.lock().unwrap();
    struct ResetAttribution;
    impl Drop for ResetAttribution {
      fn drop(&mut self) {
        prompter::clear_current_oden_stacktrace();
        prompter::set_current_oden_cped_locator(None);
        prompter::set_current_oden_cped_stack(None);
        prompter::set_current_oden_trusted_host_actor(false);
      }
    }
    let _reset = ResetAttribution;

    prompter::set_current_oden_cped_locator(None);
    prompter::set_current_oden_cped_stack(None);
    prompter::set_current_oden_trusted_host_actor(true);
    prompter::set_current_oden_stacktrace(Box::new(|| {
      vec![prompter::OdenStackFrame {
        isolate_id: Some(1),
        script_id: Some(1),
        locator: None,
        display_name: Some("file:///untrusted-package.js".to_string()),
      }]
    }));
    assert_eq!(oden_capsec_principal(), OdenPrincipal::Quarantine);
    assert_eq!(oden_capsec_principal_set(), vec![OdenPrincipal::Quarantine]);

    prompter::set_current_oden_stacktrace(Box::new(Vec::new));
    prompter::set_current_oden_cped_stack(Some(vec![
      "data:oden-unknown-scheduled-package".to_string(),
    ]));
    assert_ne!(oden_capsec_principal(), OdenPrincipal::Runtime);
    assert_ne!(oden_capsec_principal_set(), vec![OdenPrincipal::Runtime]);

    prompter::set_current_oden_cped_stack(None);
    assert_eq!(oden_capsec_principal(), OdenPrincipal::Runtime);
    assert_eq!(oden_capsec_principal_set(), vec![OdenPrincipal::Runtime]);

    prompter::set_current_oden_trusted_host_actor(false);
    assert_eq!(oden_capsec_principal(), OdenPrincipal::NoUser);
    assert_eq!(oden_capsec_principal_set(), vec![OdenPrincipal::NoUser]);
  }

  #[test]
  fn oden_url_scheme_classification_is_closed_and_action_independent() {
    use OdenUrlSchemeClass::*;

    assert_eq!(oden_capsec_classify_url_scheme("http"), Network);
    assert_eq!(oden_capsec_classify_url_scheme("HTTPS:"), Network);
    assert_eq!(oden_capsec_classify_url_scheme("file:"), File);
    assert_eq!(oden_capsec_classify_url_scheme("data"), InlineData);
    assert_eq!(oden_capsec_classify_url_scheme("node:"), RuntimeInternal);
    assert_eq!(oden_capsec_classify_url_scheme("ext:"), RuntimeInternal);
    assert_eq!(oden_capsec_classify_url_scheme("deno:"), RuntimeInternal);
    assert_eq!(oden_capsec_classify_url_scheme("blob:"), ClosedBlob);
    assert_eq!(oden_capsec_classify_url_scheme("http::"), ClosedUnknown);
    assert_eq!(
      oden_capsec_classify_url_scheme("future-transport:"),
      ClosedUnknown
    );
  }

  #[test]
  #[allow(
    clippy::disallowed_methods,
    reason = "isolated security test constructs the one-shot audit key handoff directly"
  )]
  fn oden_audit_key_regular_file_is_loaded_and_consumed() {
    let dir = std::env::temp_dir().join(format!(
      "oden-audit-key-regular-{}-{}",
      std::process::id(),
      rand::random::<u64>()
    ));
    std::fs::create_dir(&dir).unwrap();
    let path = dir.join("audit.key");
    assert!(matches!(
      oden_capsec_consume_audit_key(&path),
      OdenAuditKeyHandoff::Absent
    ));
    std::fs::write(&path, [7; 32]).unwrap();

    let OdenAuditKeyHandoff::Loaded(key) = oden_capsec_consume_audit_key(&path)
    else {
      panic!("regular audit key was not loaded");
    };
    assert_eq!(key, vec![7; 32]);
    assert_eq!(
      std::fs::symlink_metadata(&path).unwrap_err().kind(),
      std::io::ErrorKind::NotFound
    );
    std::fs::remove_dir_all(dir).unwrap();
  }

  #[cfg(unix)]
  #[test]
  #[allow(
    clippy::disallowed_methods,
    reason = "isolated security test proves a one-shot key symlink is neither followed nor consumed"
  )]
  fn oden_audit_key_symlink_is_consumed_without_touching_target() {
    use std::os::unix::fs::symlink;

    let dir = std::env::temp_dir().join(format!(
      "oden-audit-key-symlink-{}-{}",
      std::process::id(),
      rand::random::<u64>()
    ));
    std::fs::create_dir(&dir).unwrap();
    let target = dir.join("target");
    let path = dir.join("audit.key");
    std::fs::write(&target, [11; 32]).unwrap();
    symlink(&target, &path).unwrap();

    assert!(matches!(
      oden_capsec_consume_audit_key(&path),
      OdenAuditKeyHandoff::Broken
    ));
    assert_eq!(
      std::fs::symlink_metadata(&path).unwrap_err().kind(),
      std::io::ErrorKind::NotFound
    );
    assert_eq!(std::fs::read(&target).unwrap(), vec![11; 32]);
    std::fs::remove_dir_all(dir).unwrap();
  }

  #[cfg(unix)]
  #[test]
  #[allow(
    clippy::disallowed_methods,
    reason = "isolated security test constructs a rejected one-shot Rev1 policy symlink directly"
  )]
  fn oden_parent_policy_symlink_is_consumed_without_touching_target() {
    use std::os::unix::fs::symlink;

    let dir = std::env::temp_dir().join(format!(
      "oden-parent-policy-symlink-{}-{}",
      std::process::id(),
      rand::random::<u64>()
    ));
    std::fs::create_dir(&dir).unwrap();
    let target = dir.join("target.json");
    let path = dir.join("policy.json");
    std::fs::write(&target, b"{}\n").unwrap();
    symlink(&target, &path).unwrap();
    let control_root = std::fs::canonicalize(&dir).unwrap();

    assert!(
      oden_capsec_consume_parent_policy(path.as_os_str(), &control_root)
        .unwrap_err()
        .contains("is not a regular file")
    );
    assert_eq!(
      std::fs::symlink_metadata(&path).unwrap_err().kind(),
      std::io::ErrorKind::NotFound
    );
    assert_eq!(std::fs::read(&target).unwrap(), b"{}\n");
    std::fs::remove_dir_all(dir).unwrap();
  }

  #[test]
  #[allow(
    clippy::disallowed_methods,
    reason = "isolated security test constructs malformed one-shot audit key objects directly"
  )]
  fn oden_audit_key_wrong_size_is_consumed_but_wrong_type_is_not() {
    let dir = std::env::temp_dir().join(format!(
      "oden-audit-key-shape-{}-{}",
      std::process::id(),
      rand::random::<u64>()
    ));
    std::fs::create_dir(&dir).unwrap();
    let path = dir.join("audit.key");
    std::fs::write(&path, [3; 31]).unwrap();
    assert!(matches!(
      oden_capsec_consume_audit_key(&path),
      OdenAuditKeyHandoff::Broken
    ));
    assert_eq!(
      std::fs::symlink_metadata(&path).unwrap_err().kind(),
      std::io::ErrorKind::NotFound
    );

    std::fs::create_dir(&path).unwrap();
    assert!(matches!(
      oden_capsec_consume_audit_key(&path),
      OdenAuditKeyHandoff::Broken
    ));
    assert!(std::fs::metadata(&path).unwrap().is_dir());
    std::fs::remove_dir_all(dir).unwrap();
  }

  #[cfg(unix)]
  #[test]
  #[allow(
    clippy::disallowed_methods,
    reason = "isolated security test compares deterministic Unix file identities"
  )]
  fn oden_audit_key_identity_requires_the_same_unix_object() {
    let dir = std::env::temp_dir().join(format!(
      "oden-audit-key-identity-{}-{}",
      std::process::id(),
      rand::random::<u64>()
    ));
    std::fs::create_dir(&dir).unwrap();
    let first = dir.join("first");
    let alias = dir.join("alias");
    let other = dir.join("other");
    std::fs::write(&first, [1; 32]).unwrap();
    std::fs::hard_link(&first, &alias).unwrap();
    std::fs::write(&other, [2; 32]).unwrap();
    let first_metadata = std::fs::metadata(&first).unwrap();
    assert!(oden_audit_key_same_identity(
      &first_metadata,
      &std::fs::metadata(&alias).unwrap()
    ));
    assert!(!oden_audit_key_same_identity(
      &first_metadata,
      &std::fs::metadata(&other).unwrap()
    ));
    std::fs::remove_dir_all(dir).unwrap();
  }

  #[test]
  #[allow(
    clippy::disallowed_methods,
    reason = "isolated security test constructs and measures the authenticated audit file directly"
  )]
  fn oden_authenticated_audit_write_is_hard_bounded() {
    let dir = std::env::temp_dir().join(format!(
      "oden-audit-bound-{}-{}",
      std::process::id(),
      rand::random::<u64>()
    ));
    std::fs::create_dir(&dir).unwrap();
    let path = dir.join("audit.ndjson");
    let file = std::fs::OpenOptions::new()
      .create_new(true)
      .append(true)
      .open(&path)
      .unwrap();
    let audit = OdenAuthenticatedAudit {
      file,
      key: vec![7; 32],
      sequence: 0,
      previous: [0; 32],
      terminal: false,
      failed: false,
      bytes_written: 0,
      control_root: dir.clone(),
    };
    let payload = vec![b'x'; 4096];
    let mut channel = OdenAuditChannel::Authenticated(audit);
    while channel.write_record(&payload) {}
    assert!(channel.authenticated_failure());
    assert!(!channel.finish());
    let OdenAuditChannel::Authenticated(audit) = &channel else {
      unreachable!();
    };
    assert!(audit.failed);
    assert!(audit.bytes_written <= ODEN_AUDIT_WRITE_CAP);
    assert!(
      std::fs::metadata(&path).unwrap().len() <= ODEN_AUDIT_WRITE_CAP as u64
    );
    drop(channel);
    std::fs::remove_dir_all(dir).unwrap();
  }

  #[cfg(unix)]
  #[test]
  #[allow(
    clippy::disallowed_methods,
    reason = "isolated security test constructs a symlink alias for the private control directory"
  )]
  fn oden_control_path_resolution_catches_symlink_aliases() {
    use std::os::unix::fs::symlink;

    let dir = std::env::temp_dir().join(format!(
      "oden-audit-alias-{}-{}",
      std::process::id(),
      rand::random::<u64>()
    ));
    let control = dir.join("control");
    let alias = dir.join("alias");
    std::fs::create_dir_all(&control).unwrap();
    std::fs::write(control.join("audit.ndjson"), b"").unwrap();
    symlink(&control, &alias).unwrap();
    let canonical = std::fs::canonicalize(&control).unwrap();
    assert!(oden_path_resolves_within(
      &alias.join("audit.ndjson"),
      &canonical
    ));
    assert!(oden_path_resolves_within(
      &alias.join("not-created-yet"),
      &canonical
    ));
    assert!(!oden_path_resolves_within(&dir.join("outside"), &canonical));
    std::fs::remove_dir_all(dir).unwrap();
  }

  #[test]
  fn oden_worker_tracker_waits_for_detached_threads_and_times_out_closed() {
    let tracker = Arc::new(OdenCapsecWorkerTracker::new());
    let exited = Arc::new(AtomicBool::new(false));
    tracker.started();
    let worker_tracker = tracker.clone();
    let worker_exited = exited.clone();
    let thread = std::thread::spawn(move || {
      std::thread::sleep(std::time::Duration::from_millis(25));
      worker_exited.store(true, std::sync::atomic::Ordering::Release);
      worker_tracker.finished();
    });
    assert!(tracker.wait_until_drained(std::time::Duration::from_secs(1)));
    assert!(exited.load(std::sync::atomic::Ordering::Acquire));
    thread.join().unwrap();

    tracker.started();
    assert!(!tracker.wait_until_drained(std::time::Duration::ZERO));
    tracker.finished();
  }

  #[test]
  fn authenticated_channel_failures_require_fatal_finalization() {
    let mut broken = OdenAuditChannel::Broken {
      authenticated: true,
    };
    assert!(!broken.write_record(br#"{"principal":"lost"}"#));
    assert!(broken.authenticated_failure());
    assert!(!broken.finish());

    let mut legacy_failure = OdenAuditChannel::Broken {
      authenticated: false,
    };
    assert!(legacy_failure.write_record(br#"{"principal":"legacy"}"#));
    assert!(!legacy_failure.authenticated_failure());
    assert!(legacy_failure.finish());

    let tracker = OdenCapsecWorkerTracker::new();
    tracker.started();
    let channel = Mutex::new(OdenAuditChannel::Broken {
      authenticated: true,
    });
    assert!(!oden_capsec_finish_audit_channel_with(
      &tracker,
      &channel,
      std::time::Duration::ZERO,
    ));
    tracker.finished();
  }

  #[test]
  #[allow(
    clippy::disallowed_methods,
    reason = "isolated lifecycle test constructs and reads an authenticated audit file directly"
  )]
  fn oden_terminal_follows_a_registered_workers_late_frame() {
    let dir = std::env::temp_dir().join(format!(
      "oden-audit-worker-terminal-{}-{}",
      std::process::id(),
      rand::random::<u64>()
    ));
    std::fs::create_dir(&dir).unwrap();
    let path = dir.join("audit.ndjson");
    let file = std::fs::OpenOptions::new()
      .create_new(true)
      .append(true)
      .open(&path)
      .unwrap();
    let channel = Arc::new(Mutex::new(OdenAuditChannel::Authenticated(
      OdenAuthenticatedAudit {
        file,
        key: vec![9; 32],
        sequence: 0,
        previous: [0; 32],
        terminal: false,
        failed: false,
        bytes_written: 0,
        control_root: dir.clone(),
      },
    )));
    let tracker = Arc::new(OdenCapsecWorkerTracker::new());
    tracker.started();
    let worker_channel = channel.clone();
    let worker_tracker = tracker.clone();
    let thread = std::thread::spawn(move || {
      std::thread::sleep(std::time::Duration::from_millis(25));
      worker_channel
        .lock()
        .write_record(br#"{"principal":"late-worker"}"#);
      worker_tracker.finished();
    });

    assert!(oden_capsec_finish_audit_channel_with(
      &tracker,
      &channel,
      std::time::Duration::from_secs(1),
    ));
    thread.join().unwrap();
    let lines = std::fs::read_to_string(&path).unwrap();
    let frames = lines
      .lines()
      .map(|line| serde_json::from_str::<serde_json::Value>(line).unwrap())
      .collect::<Vec<_>>();
    assert_eq!(frames.len(), 2);
    assert_eq!(frames[0]["kind"], "record");
    assert_eq!(frames[1]["kind"], "terminal");
    drop(channel);
    std::fs::remove_dir_all(dir).unwrap();
  }

  #[test]
  fn oden_dynamic_env_patterns_cannot_overlap_the_control_namespace() {
    for variable in [
      "ODEN_CAPSEC_AUDIT_KEY",
      "*",
      "ODEN*",
      "ODEN_CAPSEC*",
      "ODEN_CAPSEC_FUTURE*",
    ] {
      let desc = OdenDynamicPermissionDescriptor {
        name: "env",
        path: None,
        host: None,
        variable: Some(variable),
        kind: None,
        command: None,
      };
      let req = oden_dynamic_request(&desc).unwrap();
      assert!(
        oden_capsec_is_dynamic_control_request(&desc, &req),
        "{variable} must overlap the reserved namespace"
      );
    }
    let unrelated = OdenDynamicPermissionDescriptor {
      name: "env",
      path: None,
      host: None,
      variable: Some("UNRELATED_*"),
      kind: None,
      command: None,
    };
    let req = oden_dynamic_request(&unrelated).unwrap();
    assert!(!oden_capsec_is_dynamic_control_request(&unrelated, &req));
  }

  #[test]
  fn oden_policy_artifact_validation_is_strict_and_source_aware() {
    let path = Path::new("/project/.oden/policy.json");
    let valid = oden_parse_policy_file(
      r#"{"mode":"enforce","grants":{"dep":"env:write:TOKEN,sys:hostname"}}"#,
      path,
    )
    .unwrap();
    assert_eq!(valid.mode.as_deref(), Some("enforce"));

    let malformed = oden_parse_policy_file("{", path).unwrap_err();
    assert!(malformed.contains("/project/.oden/policy.json:1:"));
    assert!(malformed.contains("invalid policy JSON/shape"));

    let wrong_shape = oden_parse_policy_file(
      r#"{"mode":"enforce","grants":["env:read:TOKEN"]}"#,
      path,
    )
    .unwrap_err();
    assert!(wrong_shape.contains("invalid policy JSON/shape"));

    let invalid_grant = oden_parse_policy_file(
      r#"{"mode":"enforce","grants":{"dep":"fs:read:/safe,env:writ:SECRET"}}"#,
      path,
    )
    .unwrap_err();
    assert!(invalid_grant.contains("#grants[\"dep\"]"));
    assert!(invalid_grant.contains("env:writ:SECRET"));

    let empty_selector = oden_parse_policy_file(
      r#"{"mode":"enforce","grants":{" ":"env:read:TOKEN"}}"#,
      path,
    )
    .unwrap_err();
    assert!(empty_selector.contains("package selector must not be empty"));

    let bad_mode =
      oden_parse_policy_file(r#"{"mode":"enfroce","grants":{}}"#, path)
        .unwrap_err();
    assert!(bad_mode.contains("#mode"));

    let null_mode =
      oden_parse_policy_file(r#"{"mode":null,"grants":{}}"#, path).unwrap_err();
    assert!(null_mode.contains("invalid policy JSON/shape"));

    let invalid_dynamic = oden_parse_policy_file(
      r#"{"mode":"enforce","denyCeiling":"env:writ:SECRET","ceilings":{}}"#,
      path,
    )
    .unwrap_err();
    assert!(invalid_dynamic.contains("#denyCeiling"));
    let invalid_disposition = oden_parse_policy_file(
      r#"{"mode":"enforce","ceilings":{"dep":{"authority":"env:read:TOKEN","on_request":"sometimes"}}}"#,
      path,
    )
    .unwrap_err();
    assert!(invalid_disposition.contains("#ceilings[\"dep\"].on_request"));

    assert_eq!(
      oden_resolve_grant_scopes(
        "file:READ:./data,FS:write:./output,env:TOKEN",
        "/project"
      ),
      "fs:read:/project/data,fs:write:/project/output,env:read:TOKEN"
    );
  }

  #[test]
  fn oden_network_scope_normalization_preserves_special_endpoints() {
    assert_eq!(
      oden_host_of("https://example.test:8443/path"),
      "example.test"
    );
    assert_eq!(oden_host_of("[::1]:8443"), "[::1]");
    assert_eq!(oden_host_of("unix:/tmp/oden.sock"), "unix:/tmp/oden.sock");
    assert_eq!(oden_host_of("vsock:2:8000"), "vsock:2:8000");
  }

  #[test]
  fn compartment_keys_do_not_alias_physical_package_instances() {
    let principal = OdenPrincipal::Package {
      name: "same-name".to_string(),
      version: None,
    };
    let first = oden_capsec_compartment_key(
      &principal,
      Some("file:///app/node_modules/same-name/mod.ts"),
    );
    let second = oden_capsec_compartment_key(
      &principal,
      Some("file:///app/node_modules/parent/node_modules/same-name/mod.ts"),
    );
    assert_ne!(first, second);
  }

  #[test]
  fn resource_use_decision_owner_semantics() {
    // An untracked rid is guessable and therefore denied under enforce.
    assert_eq!(
      oden_resource_use_decision("dep-a", None, OdenMode::Enforce),
      OdenDecision::Deny
    );
    // The owner uses its own rid freely.
    assert_eq!(
      oden_resource_use_decision("dep-a", Some("dep-a"), OdenMode::Enforce),
      OdenDecision::Allow
    );
    // A different package using a guessed/handed rid denies under enforce,
    // records under audit, allows under permissive.
    assert_eq!(
      oden_resource_use_decision("dep-b", Some("dep-a"), OdenMode::Enforce),
      OdenDecision::Deny
    );
    assert_eq!(
      oden_resource_use_decision("dep-b", Some("dep-a"), OdenMode::Audit),
      OdenDecision::AllowRecord
    );
    assert_eq!(
      oden_resource_use_decision("dep-b", Some("dep-a"), OdenMode::Permissive),
      OdenDecision::Allow
    );
  }

  #[test]
  fn deny_only_resource_owner_is_mode_independent() {
    let dep_a = OdenPrincipal::Package {
      name: "dep-a".to_string(),
      version: Some("1.0.0".to_string()),
    };
    let dep_b = OdenPrincipal::Package {
      name: "dep-b".to_string(),
      version: Some("1.0.0".to_string()),
    };
    for mode in [OdenMode::Enforce, OdenMode::Audit, OdenMode::Permissive] {
      assert_eq!(
        oden_deny_only_resource_use_decision(&dep_a, Some("dep-a"), mode),
        OdenDecision::Allow
      );
      assert_eq!(
        oden_deny_only_resource_use_decision(&dep_b, Some("dep-a"), mode),
        OdenDecision::Deny
      );
      assert_eq!(
        oden_deny_only_resource_use_decision(&dep_a, None, mode),
        OdenDecision::Deny
      );
      assert_eq!(
        oden_deny_only_resource_use_decision(&OdenPrincipal::Root, None, mode),
        OdenDecision::Allow
      );
      assert_eq!(
        oden_deny_only_resource_use_decision(
          &OdenPrincipal::Root,
          Some("dep-a"),
          mode
        ),
        OdenDecision::Deny
      );
      assert_eq!(
        oden_deny_only_resource_use_decision(
          &OdenPrincipal::Quarantine,
          Some("quarantine"),
          mode
        ),
        OdenDecision::Deny
      );
      assert_eq!(
        oden_deny_only_resource_use_decision(
          &OdenPrincipal::NoUser,
          None,
          mode
        ),
        OdenDecision::Deny
      );
    }
  }

  #[test]
  fn resource_owner_tokens_do_not_alias_worker_local_rids() {
    // Two workers may both allocate rid 3. The concrete resource tokens retain
    // independent owners, so opening in worker B cannot overwrite worker A.
    let worker_a = OdenResourceOwner::for_test(Some("dep-a"));
    let worker_b = OdenResourceOwner::for_test(Some("dep-b"));
    assert_eq!(
      oden_resource_use_decision(
        "dep-a",
        worker_a.owner_for_test().as_deref(),
        OdenMode::Enforce
      ),
      OdenDecision::Allow
    );
    assert_eq!(
      oden_resource_use_decision(
        "dep-b",
        worker_b.owner_for_test().as_deref(),
        OdenMode::Enforce
      ),
      OdenDecision::Allow
    );
    assert_eq!(
      oden_resource_use_decision(
        "dep-b",
        worker_a.owner_for_test().as_deref(),
        OdenMode::Enforce
      ),
      OdenDecision::Deny
    );

    // Dropping one resource also drops its owner metadata; no stale rid key can
    // survive and affect the other worker's same-numbered resource.
    drop(worker_a);
    assert_eq!(worker_b.owner_for_test().as_deref(), Some("dep-b"));
  }

  #[test]
  fn transfer_primitive_reowns_only_the_concrete_owner_token() {
    let owner = OdenResourceOwner::for_test(Some("dep-a"));
    let unrelated_same_rid = OdenResourceOwner::for_test(Some("dep-c"));

    // A non-owner cannot steal the resource through the sanctioned transfer.
    assert_eq!(
      owner.transfer_for("dep-b", "dep-b", OdenMode::Enforce).0,
      OdenDecision::Deny
    );
    assert_eq!(owner.owner_for_test().as_deref(), Some("dep-a"));

    // Its owner can transfer it. Only this concrete token changes; another
    // worker's same-numbered resource is unaffected.
    assert_eq!(
      owner.transfer_for("dep-a", "dep-b", OdenMode::Enforce).0,
      OdenDecision::Allow
    );
    assert_eq!(owner.owner_for_test().as_deref(), Some("dep-b"));
    assert_eq!(
      unrelated_same_rid.owner_for_test().as_deref(),
      Some("dep-c")
    );
  }
  use crate::prompter::set_prompter;

  // Creates vector of strings, Vec<String>
  macro_rules! svec {
      ($($x:expr),*) => (vec![$($x.to_string()),*]);
  }

  #[derive(Debug, Clone)]
  struct TestPermissionDescriptorParser;

  impl TestPermissionDescriptorParser {
    fn join_path_with_root(&self, path: &str) -> PathDescriptor {
      let path = if path.starts_with("C:\\") {
        PathBuf::from(path)
      } else {
        PathBuf::from("/").join(path)
      };
      let cmp_path = comparison_path(&path);
      PathDescriptor {
        path,
        cmp_path,
        requested: None,
        is_windows_device_path: false,
      }
    }
  }

  impl PermissionDescriptorParser for TestPermissionDescriptorParser {
    fn parse_read_descriptor(
      &self,
      text: &str,
    ) -> Result<ReadDescriptor, PathResolveError> {
      Ok(ReadDescriptor(self.join_path_with_root(text)))
    }

    fn parse_write_descriptor(
      &self,
      text: &str,
    ) -> Result<WriteDescriptor, PathResolveError> {
      Ok(WriteDescriptor(self.join_path_with_root(text)))
    }

    fn parse_net_descriptor(
      &self,
      text: &str,
    ) -> Result<NetDescriptor, NetDescriptorParseError> {
      NetDescriptor::parse_for_list(text)
    }

    fn parse_import_descriptor(
      &self,
      text: &str,
    ) -> Result<ImportDescriptor, NetDescriptorParseError> {
      ImportDescriptor::parse_for_list(text)
    }

    fn parse_env_descriptor(
      &self,
      text: &str,
    ) -> Result<EnvDescriptor, EnvDescriptorParseError> {
      Ok(EnvDescriptor::new(Cow::Borrowed(text)))
    }

    fn parse_sys_descriptor(
      &self,
      text: &str,
    ) -> Result<SysDescriptor, SysDescriptorParseError> {
      SysDescriptor::parse(text.to_string())
    }

    fn parse_allow_run_descriptor(
      &self,
      text: &str,
    ) -> Result<AllowRunDescriptorParseResult, RunDescriptorParseError> {
      Ok(AllowRunDescriptorParseResult::Descriptor(
        AllowRunDescriptor(self.join_path_with_root(text)),
      ))
    }

    fn parse_deny_run_descriptor(
      &self,
      text: &str,
    ) -> Result<DenyRunDescriptor, PathResolveError> {
      if text.contains("/") {
        Ok(DenyRunDescriptor::Path(self.join_path_with_root(text)))
      } else {
        Ok(DenyRunDescriptor::Name(text.to_string()))
      }
    }

    fn parse_ffi_descriptor(
      &self,
      text: &str,
    ) -> Result<FfiDescriptor, PathResolveError> {
      Ok(FfiDescriptor(self.join_path_with_root(text)))
    }

    fn parse_path_query<'a>(
      &self,
      path: Cow<'a, Path>,
    ) -> Result<PathQueryDescriptor<'a>, PathResolveError> {
      let cmp_path = comparison_path(&path);
      Ok(PathQueryDescriptor {
        path,
        cmp_path,
        requested: None,
        is_windows_device_path: false,
      })
    }

    fn parse_net_query(
      &self,
      text: &str,
    ) -> Result<NetDescriptor, NetDescriptorParseError> {
      NetDescriptor::parse_for_query(text)
    }

    fn parse_run_query<'a>(
      &self,
      requested: &'a str,
    ) -> Result<RunQueryDescriptor<'a>, RunDescriptorParseError> {
      RunQueryDescriptor::parse(requested, &sys_traits::impls::RealSys)
        .map_err(Into::into)
    }

    fn parse_special_file_descriptor<'a>(
      &self,
      path: PathQueryDescriptor<'a>,
    ) -> Result<SpecialFilePathQueryDescriptor<'a>, PathResolveError> {
      Ok(SpecialFilePathQueryDescriptor {
        path: path.path,
        requested: None,
        canonicalized: false,
      })
    }
  }

  #[test]
  fn check_paths() {
    set_prompter(Box::new(TestPrompter));
    let allowlist = svec!["/a/specific/dir/name", "/a/specific", "/b/c"];

    let parser = TestPermissionDescriptorParser;
    let perms = Permissions::from_options(
      &parser,
      &PermissionsOptions {
        allow_read: Some(allowlist.clone()),
        allow_write: Some(allowlist.clone()),
        allow_ffi: Some(allowlist),
        ..Default::default()
      },
    )
    .unwrap();
    let mut perms = PermissionsContainer::new(Arc::new(parser), perms);

    let cases = [
      // Inside of /a/specific and /a/specific/dir/name
      ("/a/specific/dir/name", true),
      // Inside of /a/specific but outside of /a/specific/dir/name
      ("/a/specific/dir", true),
      // Inside of /a/specific and /a/specific/dir/name
      ("/a/specific/dir/name/inner", true),
      // Inside of /a/specific but outside of /a/specific/dir/name
      ("/a/specific/other/dir", true),
      // Exact match with /b/c
      ("/b/c", true),
      // Sub path within /b/c
      ("/b/c/sub/path", true),
      // Sub path within /b/c, needs normalizing
      ("/b/c/sub/path/../path/.", true),
      // Inside of /b but outside of /b/c
      ("/b/e", false),
      // Inside of /a but outside of /a/specific
      ("/a/b", false),
    ];

    for (path, is_ok) in cases {
      assert_eq!(
        perms
          .check_open(
            Cow::Borrowed(Path::new(path)),
            OpenAccessKind::Read,
            Some("api")
          )
          .is_ok(),
        is_ok
      );
      assert_eq!(
        perms
          .check_open(
            Cow::Borrowed(Path::new(path)),
            OpenAccessKind::Write,
            Some("api")
          )
          .is_ok(),
        is_ok
      );
      assert_eq!(
        perms.check_ffi(Cow::Borrowed(Path::new(path))).is_ok(),
        is_ok
      );
    }
  }

  #[test]
  #[cfg(target_os = "macos")]
  fn check_paths_macos_unicode_normalization() {
    set_prompter(Box::new(TestPrompter));
    let parser = TestPermissionDescriptorParser;

    // Deny a path containing ß — on APFS this is the same file as one with "ss"
    let perms = Permissions::from_options(
      &parser,
      &PermissionsOptions {
        allow_read: Some(svec!["/data"]),
        deny_read: Some(svec!["/data/file_\u{00df}.txt"]),
        allow_write: Some(svec!["/data"]),
        deny_write: Some(svec!["/data/file_\u{00df}.txt"]),
        ..Default::default()
      },
    )
    .unwrap();
    let perms = PermissionsContainer::new(Arc::new(parser), perms);

    // Access via "ss" form must also be denied (APFS treats ß and ss as same file)
    assert!(
      perms
        .check_open(
          Cow::Borrowed(Path::new("/data/file_ss.txt")),
          OpenAccessKind::Read,
          Some("api")
        )
        .is_err(),
      "deny-read bypass via ß/ss equivalence"
    );
    assert!(
      perms
        .check_open(
          Cow::Borrowed(Path::new("/data/file_ss.txt")),
          OpenAccessKind::Write,
          Some("api")
        )
        .is_err(),
      "deny-write bypass via ß/ss equivalence"
    );

    // NFC é (U+00E9) vs NFD e + combining accent (U+0065 U+0301)
    let parser = TestPermissionDescriptorParser;
    let perms = Permissions::from_options(
      &parser,
      &PermissionsOptions {
        allow_read: Some(svec!["/data"]),
        deny_read: Some(svec!["/data/file_\u{00e9}.txt"]),
        ..Default::default()
      },
    )
    .unwrap();
    let perms = PermissionsContainer::new(Arc::new(parser), perms);
    assert!(
      perms
        .check_open(
          Cow::Borrowed(Path::new("/data/file_e\u{0301}.txt")),
          OpenAccessKind::Read,
          Some("api")
        )
        .is_err(),
      "deny-read bypass via NFC/NFD equivalence"
    );

    // Case insensitivity: APFS is case-insensitive by default
    let parser = TestPermissionDescriptorParser;
    let perms = Permissions::from_options(
      &parser,
      &PermissionsOptions {
        allow_read: Some(svec!["/data"]),
        deny_read: Some(svec!["/data/SECRET.txt"]),
        ..Default::default()
      },
    )
    .unwrap();
    let perms = PermissionsContainer::new(Arc::new(parser), perms);
    assert!(
      perms
        .check_open(
          Cow::Borrowed(Path::new("/data/secret.txt")),
          OpenAccessKind::Read,
          Some("api")
        )
        .is_err(),
      "deny-read bypass via case insensitivity"
    );

    // fi ligature (U+FB01) vs "fi" — NFKD compatibility decomposition
    let parser = TestPermissionDescriptorParser;
    let perms = Permissions::from_options(
      &parser,
      &PermissionsOptions {
        allow_read: Some(svec!["/data"]),
        deny_read: Some(svec!["/data/file_\u{fb01}.txt"]),
        ..Default::default()
      },
    )
    .unwrap();
    let perms = PermissionsContainer::new(Arc::new(parser), perms);
    assert!(
      perms
        .check_open(
          Cow::Borrowed(Path::new("/data/file_fi.txt")),
          OpenAccessKind::Read,
          Some("api")
        )
        .is_err(),
      "deny-read bypass via fi ligature equivalence"
    );
  }

  #[test]
  fn test_check_net_with_values() {
    set_prompter(Box::new(TestPrompter));
    let parser = TestPermissionDescriptorParser;
    let mut perms = Permissions::from_options(
      &parser,
      &PermissionsOptions {
        allow_net: Some(svec![
          "localhost",
          "deno.land",
          "github.com:3000",
          "127.0.0.1",
          "172.16.0.2:8000",
          "www.github.com:443",
          "80.example.com:80",
          "443.example.com:443",
          "*.discord.gg"
        ]),
        ..Default::default()
      },
    )
    .unwrap();

    let domain_tests = vec![
      ("localhost", 1234, true),
      ("deno.land", 0, true),
      ("deno.land", 3000, true),
      ("deno.lands", 0, false),
      ("deno.lands", 3000, false),
      ("github.com", 3000, true),
      ("github.com", 0, false),
      ("github.com", 2000, false),
      ("github.net", 3000, false),
      ("127.0.0.1", 0, true),
      ("127.0.0.1", 3000, true),
      ("127.0.0.2", 0, false),
      ("127.0.0.2", 3000, false),
      ("172.16.0.2", 8000, true),
      ("172.16.0.2", 0, false),
      ("172.16.0.2", 6000, false),
      ("172.16.0.1", 8000, false),
      ("443.example.com", 444, false),
      ("80.example.com", 81, false),
      ("80.example.com", 80, true),
      ("discord.gg", 0, true),
      ("foo.discord.gg", 0, true),
      // Just some random hosts that should err
      ("somedomain", 0, false),
      ("192.168.0.1", 0, false),
    ];

    for (host, port, is_ok) in domain_tests {
      let host = Host::parse_for_query(host).unwrap();
      let descriptor = NetDescriptor(host, Some(port));
      assert_eq!(
        is_ok,
        perms.net.check(&descriptor, None).is_ok(),
        "{descriptor}",
      );
    }
  }

  #[test]
  fn test_check_net_only_flag() {
    set_prompter(Box::new(TestPrompter));
    let parser = TestPermissionDescriptorParser;
    let mut perms = Permissions::from_options(
      &parser,
      &PermissionsOptions {
        allow_net: Some(svec![]), // this means `--allow-net` is present without values following `=` sign
        ..Default::default()
      },
    )
    .unwrap();

    let domain_tests = vec![
      ("localhost", 1234),
      ("deno.land", 0),
      ("deno.land", 3000),
      ("deno.lands", 0),
      ("deno.lands", 3000),
      ("github.com", 3000),
      ("github.com", 0),
      ("github.com", 2000),
      ("github.net", 3000),
      ("127.0.0.1", 0),
      ("127.0.0.1", 3000),
      ("127.0.0.2", 0),
      ("127.0.0.2", 3000),
      ("172.16.0.2", 8000),
      ("172.16.0.2", 0),
      ("172.16.0.2", 6000),
      ("172.16.0.1", 8000),
      ("somedomain", 0),
      ("192.168.0.1", 0),
    ];

    for (host_str, port) in domain_tests {
      let host = Host::parse_for_query(host_str).unwrap();
      let descriptor = NetDescriptor(host, Some(port));
      assert!(
        perms.net.check(&descriptor, None).is_ok(),
        "expected {host_str}:{port} to pass"
      );
    }
  }

  #[test]
  fn test_check_net_no_flag() {
    set_prompter(Box::new(TestPrompter));
    let parser = TestPermissionDescriptorParser;
    let mut perms = Permissions::from_options(
      &parser,
      &PermissionsOptions {
        allow_net: None,
        ..Default::default()
      },
    )
    .unwrap();

    let domain_tests = vec![
      ("localhost", 1234),
      ("deno.land", 0),
      ("deno.land", 3000),
      ("deno.lands", 0),
      ("deno.lands", 3000),
      ("github.com", 3000),
      ("github.com", 0),
      ("github.com", 2000),
      ("github.net", 3000),
      ("127.0.0.1", 0),
      ("127.0.0.1", 3000),
      ("127.0.0.2", 0),
      ("127.0.0.2", 3000),
      ("172.16.0.2", 8000),
      ("172.16.0.2", 0),
      ("172.16.0.2", 6000),
      ("172.16.0.1", 8000),
      ("somedomain", 0),
      ("192.168.0.1", 0),
    ];

    for (host_str, port) in domain_tests {
      let host = Host::parse_for_query(host_str).unwrap();
      let descriptor = NetDescriptor(host, Some(port));
      assert!(
        perms.net.check(&descriptor, None).is_err(),
        "expected {host_str}:{port} to fail"
      );
    }
  }

  #[test]
  fn test_check_net_deny_resolved_ip() {
    // Regression test: deny rules written as IP literals must also block
    // connections after DNS resolution, preventing bypasses via numeric
    // hostname aliases (e.g. 2130706433 → 127.0.0.1).
    set_prompter(Box::new(TestPrompter));
    let parser = TestPermissionDescriptorParser;
    let mut perms = Permissions::from_options(
      &parser,
      &PermissionsOptions {
        allow_net: Some(svec![]),
        deny_net: Some(svec!["127.0.0.1"]),
        ..Default::default()
      },
    )
    .unwrap();

    // The resolved IP 127.0.0.1 should be denied regardless of original
    // hostname.
    let denied_ip = std::net::IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
    let desc = NetDescriptor(Host::Ip(denied_ip), Some(12345));
    assert!(
      perms.net.check_resolved_ip_deny(&desc, None).is_err(),
      "resolved 127.0.0.1 should be denied"
    );

    // A different IP should not be denied.
    let allowed_ip = std::net::IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
    let desc = NetDescriptor(Host::Ip(allowed_ip), Some(12345));
    assert!(
      perms.net.check_resolved_ip_deny(&desc, None).is_ok(),
      "resolved 192.168.1.1 should not be denied"
    );
  }

  #[test]
  fn test_check_net_deny_resolved_ip_subnet() {
    // Regression test: subnet-based deny rules (e.g. --deny-net=127.0.0.0/8)
    // must also block resolved IPs that fall within the subnet, preventing
    // bypasses via numeric hostname aliases (e.g. 2130706433 → 127.0.0.1).
    set_prompter(Box::new(TestPrompter));
    let parser = TestPermissionDescriptorParser;
    let mut perms = Permissions::from_options(
      &parser,
      &PermissionsOptions {
        allow_net: Some(svec![]),
        deny_net: Some(svec!["127.0.0.0/8"]),
        ..Default::default()
      },
    )
    .unwrap();

    // 127.0.0.1 falls within the 127.0.0.0/8 subnet — should be denied.
    let denied_ip = std::net::IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
    let desc = NetDescriptor(Host::Ip(denied_ip), Some(8000));
    assert!(
      perms.net.check_resolved_ip_deny(&desc, None).is_err(),
      "resolved 127.0.0.1 should be denied by 127.0.0.0/8 subnet rule"
    );

    // 127.1.2.3 also falls within 127.0.0.0/8 — should be denied.
    let denied_ip2 = std::net::IpAddr::V4(Ipv4Addr::new(127, 1, 2, 3));
    let desc = NetDescriptor(Host::Ip(denied_ip2), Some(9000));
    assert!(
      perms.net.check_resolved_ip_deny(&desc, None).is_err(),
      "resolved 127.1.2.3 should be denied by 127.0.0.0/8 subnet rule"
    );

    // 192.168.1.1 is outside the subnet — should not be denied.
    let allowed_ip = std::net::IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
    let desc = NetDescriptor(Host::Ip(allowed_ip), Some(8000));
    assert!(
      perms.net.check_resolved_ip_deny(&desc, None).is_ok(),
      "resolved 192.168.1.1 should not be denied by 127.0.0.0/8 subnet rule"
    );
  }

  #[test]
  fn test_check_net_url() {
    let parser = TestPermissionDescriptorParser;
    let perms = Permissions::from_options(
      &parser,
      &PermissionsOptions {
        allow_net: Some(svec![
          "localhost",
          "deno.land",
          "github.com:3000",
          "127.0.0.1",
          "172.16.0.2:8000",
          "www.github.com:443"
        ]),
        ..Default::default()
      },
    )
    .unwrap();
    let mut perms = PermissionsContainer::new(Arc::new(parser), perms);

    let url_tests = vec![
      // Any protocol + port for localhost should be ok, since we don't specify
      ("http://localhost", true),
      ("https://localhost", true),
      ("https://localhost:4443", true),
      ("tcp://localhost:5000", true),
      ("udp://localhost:6000", true),
      // Correct domain + any port and protocol should be ok incorrect shouldn't
      ("https://deno.land/std/example/welcome.ts", true),
      ("https://deno.land:3000/std/example/welcome.ts", true),
      ("https://deno.lands/std/example/welcome.ts", false),
      ("https://deno.lands:3000/std/example/welcome.ts", false),
      // Correct domain + port should be ok all other combinations should err
      ("https://github.com:3000/denoland/deno", true),
      ("https://github.com/denoland/deno", false),
      ("https://github.com:2000/denoland/deno", false),
      ("https://github.net:3000/denoland/deno", false),
      // Correct ipv4 address + any port should be ok others should err
      ("tcp://127.0.0.1", true),
      ("https://127.0.0.1", true),
      ("tcp://127.0.0.1:3000", true),
      ("https://127.0.0.1:3000", true),
      ("tcp://127.0.0.2", false),
      ("https://127.0.0.2", false),
      ("tcp://127.0.0.2:3000", false),
      ("https://127.0.0.2:3000", false),
      // Correct address + port should be ok all other combinations should err
      ("tcp://172.16.0.2:8000", true),
      ("https://172.16.0.2:8000", true),
      ("tcp://172.16.0.2", false),
      ("https://172.16.0.2", false),
      ("tcp://172.16.0.2:6000", false),
      ("https://172.16.0.2:6000", false),
      ("tcp://172.16.0.1:8000", false),
      ("https://172.16.0.1:8000", false),
      // Testing issue #6531 (Network permissions check doesn't account for well-known default ports) so we dont regress
      ("https://www.github.com:443/robots.txt", true),
    ];

    for (url_str, is_ok) in url_tests {
      let u = Url::parse(url_str).unwrap();
      assert_eq!(
        is_ok,
        perms
          .check_net_url(NetPermissionAction::Fetch, &u, "api()")
          .is_ok(),
        "{}",
        u
      );
    }
  }

  #[test]
  fn check_specifiers() {
    set_prompter(Box::new(TestPrompter));
    let read_allowlist = if cfg!(target_os = "windows") {
      svec!["C:\\a"]
    } else {
      svec!["/a"]
    };
    let parser = TestPermissionDescriptorParser;
    let perms = Permissions::from_options(
      &parser,
      &PermissionsOptions {
        allow_read: Some(read_allowlist),
        allow_import: Some(svec!["localhost"]),
        ..Default::default()
      },
    )
    .unwrap();
    let perms = PermissionsContainer::new(Arc::new(parser), perms);

    #[cfg(target_os = "linux")]
    for kind in [CheckSpecifierKind::Static, CheckSpecifierKind::Dynamic] {
      assert!(
        perms
          .check_specifier(
            &Url::parse("file:///proc/self/environ").unwrap(),
            kind,
          )
          .is_err(),
        "{kind:?} file imports must pass the special-file env-all gate"
      );
    }

    let mut fixtures = vec![
      (
        Url::parse("http://localhost:4545/mod.ts").unwrap(),
        CheckSpecifierKind::Static,
        true,
      ),
      (
        Url::parse("http://localhost:4545/mod.ts").unwrap(),
        CheckSpecifierKind::Dynamic,
        true,
      ),
      (
        Url::parse("http://deno.land/x/mod.ts").unwrap(),
        CheckSpecifierKind::Dynamic,
        false,
      ),
      (
        Url::parse("data:text/plain,Hello%2C%20Deno!").unwrap(),
        CheckSpecifierKind::Dynamic,
        true,
      ),
    ];

    if cfg!(target_os = "windows") {
      fixtures.push((
        Url::parse("file:///C:/a/mod.ts").unwrap(),
        CheckSpecifierKind::Dynamic,
        true,
      ));
      fixtures.push((
        Url::parse("file:///C:/b/mod.ts").unwrap(),
        CheckSpecifierKind::Static,
        true,
      ));
      fixtures.push((
        Url::parse("file:///C:/b/mod.ts").unwrap(),
        CheckSpecifierKind::Dynamic,
        false,
      ));
    } else {
      fixtures.push((
        Url::parse("file:///a/mod.ts").unwrap(),
        CheckSpecifierKind::Dynamic,
        true,
      ));
      fixtures.push((
        Url::parse("file:///b/mod.ts").unwrap(),
        CheckSpecifierKind::Static,
        true,
      ));
      fixtures.push((
        Url::parse("file:///b/mod.ts").unwrap(),
        CheckSpecifierKind::Dynamic,
        false,
      ));
    }

    for (specifier, kind, expected) in fixtures {
      assert_eq!(
        perms.check_specifier(&specifier, kind).is_ok(),
        expected,
        "{}",
        specifier,
      );
    }

    let (blocked_path, blocked_url, allowed_url) =
      if cfg!(target_os = "windows") {
        (
          "C:\\private-control",
          Url::parse("file:///C:/private-control/policy.json").unwrap(),
          Url::parse("file:///C:/project/mod.ts").unwrap(),
        )
      } else {
        (
          "/private-control",
          Url::parse("file:///private-control/policy.json").unwrap(),
          Url::parse("file:///project/mod.ts").unwrap(),
        )
      };
    let parser = TestPermissionDescriptorParser;
    let explicitly_denied = Permissions::from_options(
      &parser,
      &PermissionsOptions {
        allow_read: None,
        deny_read: Some(svec![blocked_path]),
        ..Default::default()
      },
    )
    .unwrap();
    let explicitly_denied =
      PermissionsContainer::new(Arc::new(parser), explicitly_denied);
    assert!(
      explicitly_denied
        .check_specifier(&blocked_url, CheckSpecifierKind::Static)
        .is_err(),
      "an explicit deny-read must beat the static-import exemption"
    );
    assert!(
      explicitly_denied
        .check_specifier(&allowed_url, CheckSpecifierKind::Static)
        .is_ok(),
      "static imports remain allow-read exempt when no deny overlaps"
    );
  }

  #[test]
  fn test_query() {
    set_prompter(Box::new(TestPrompter));
    let parser = TestPermissionDescriptorParser;
    let perms1 = Permissions::allow_all();
    let perms2 = Permissions::from_options(
      &parser,
      &PermissionsOptions {
        allow_read: Some(svec!["/foo"]),
        allow_write: Some(svec!["/foo"]),
        allow_ffi: Some(svec!["/foo"]),
        allow_net: Some(svec!["127.0.0.1:8000"]),
        allow_env: Some(svec!["HOME"]),
        allow_sys: Some(svec!["hostname"]),
        allow_run: Some(svec!["/deno"]),
        ..Default::default()
      },
    )
    .unwrap();
    let perms3 = Permissions::from_options(
      &parser,
      &PermissionsOptions {
        deny_read: Some(svec!["/foo"]),
        deny_write: Some(svec!["/foo"]),
        deny_ffi: Some(svec!["/foo"]),
        deny_net: Some(svec!["127.0.0.1:8000"]),
        deny_env: Some(svec!["HOME"]),
        deny_sys: Some(svec!["hostname"]),
        deny_run: Some(svec!["deno"]),
        deny_import: Some(svec!["example.com:443"]),
        ..Default::default()
      },
    )
    .unwrap();
    let perms4 = Permissions::from_options(
      &parser,
      &PermissionsOptions {
        allow_read: Some(vec![]),
        deny_read: Some(svec!["/foo"]),
        allow_write: Some(vec![]),
        deny_write: Some(svec!["/foo"]),
        allow_ffi: Some(vec![]),
        deny_ffi: Some(svec!["/foo"]),
        allow_net: Some(vec![]),
        deny_net: Some(svec!["127.0.0.1:8000"]),
        allow_env: Some(vec![]),
        deny_env: Some(svec!["HOME"]),
        allow_sys: Some(vec![]),
        deny_sys: Some(svec!["hostname"]),
        allow_run: Some(vec![]),
        deny_run: Some(svec!["deno"]),
        allow_import: Some(vec![]),
        deny_import: Some(svec!["example.com:443"]),
        ..Default::default()
      },
    )
    .unwrap();
    let read_query = |path: &str| {
      parser
        .parse_path_query(Cow::Owned(PathBuf::from(path)))
        .unwrap()
        .into_read()
    };
    let write_query = |path: &str| {
      parser
        .parse_path_query(Cow::Owned(PathBuf::from(path)))
        .unwrap()
        .into_write()
    };
    let ffi_query = |path: &str| {
      parser
        .parse_path_query(Cow::Owned(PathBuf::from(path)))
        .unwrap()
        .into_ffi()
    };
    #[rustfmt::skip]
    {
      assert_eq!(perms1.read.query(None), PermissionState::Granted);
      assert_eq!(perms1.read.query(Some(&read_query("/foo"))), PermissionState::Granted);
      assert_eq!(perms2.read.query(None), PermissionState::Prompt);
      assert_eq!(perms2.read.query(Some(&read_query("/foo"))), PermissionState::Granted);
      assert_eq!(perms2.read.query(Some(&read_query("/foo/bar"))), PermissionState::Granted);
      assert_eq!(perms3.read.query(None), PermissionState::Prompt);
      assert_eq!(perms3.read.query(Some(&read_query("/foo"))), PermissionState::Denied);
      assert_eq!(perms3.read.query(Some(&read_query("/foo/bar"))), PermissionState::Denied);
      assert_eq!(perms4.read.query(None), PermissionState::GrantedPartial);
      assert_eq!(perms4.read.query(Some(&read_query("/foo"))), PermissionState::Denied);
      assert_eq!(perms4.read.query(Some(&read_query("/foo/bar"))), PermissionState::Denied);
      assert_eq!(perms4.read.query(Some(&read_query("/bar"))), PermissionState::Granted);
      assert_eq!(perms1.write.query(None), PermissionState::Granted);
      assert_eq!(perms1.write.query(Some(&write_query("/foo"))), PermissionState::Granted);
      assert_eq!(perms2.write.query(None), PermissionState::Prompt);
      assert_eq!(perms2.write.query(Some(&write_query("/foo"))), PermissionState::Granted);
      assert_eq!(perms2.write.query(Some(&write_query("/foo/bar"))), PermissionState::Granted);
      assert_eq!(perms3.write.query(None), PermissionState::Prompt);
      assert_eq!(perms3.write.query(Some(&write_query("/foo"))), PermissionState::Denied);
      assert_eq!(perms3.write.query(Some(&write_query("/foo/bar"))), PermissionState::Denied);
      assert_eq!(perms4.write.query(None), PermissionState::GrantedPartial);
      assert_eq!(perms4.write.query(Some(&write_query("/foo"))), PermissionState::Denied);
      assert_eq!(perms4.write.query(Some(&write_query("/foo/bar"))), PermissionState::Denied);
      assert_eq!(perms4.write.query(Some(&write_query("/bar"))), PermissionState::Granted);
      assert_eq!(perms1.ffi.query(None), PermissionState::Granted);
      assert_eq!(perms1.ffi.query(Some(&ffi_query("/foo"))), PermissionState::Granted);
      assert_eq!(perms2.ffi.query(None), PermissionState::Prompt);
      assert_eq!(perms2.ffi.query(Some(&ffi_query("/foo"))), PermissionState::Granted);
      assert_eq!(perms2.ffi.query(Some(&ffi_query("/foo/bar"))), PermissionState::Granted);
      assert_eq!(perms3.ffi.query(None), PermissionState::Prompt);
      assert_eq!(perms3.ffi.query(Some(&ffi_query("/foo"))), PermissionState::Denied);
      assert_eq!(perms3.ffi.query(Some(&ffi_query("/foo/bar"))), PermissionState::Denied);
      assert_eq!(perms4.ffi.query(None), PermissionState::GrantedPartial);
      assert_eq!(perms4.ffi.query(Some(&ffi_query("/foo"))), PermissionState::Denied);
      assert_eq!(perms4.ffi.query(Some(&ffi_query("/foo/bar"))), PermissionState::Denied);
      assert_eq!(perms4.ffi.query(Some(&ffi_query("/bar"))), PermissionState::Granted);
      assert_eq!(perms1.net.query(None), PermissionState::Granted);
      assert_eq!(perms1.net.query(Some(&NetDescriptor(Host::must_parse("127.0.0.1"), None))), PermissionState::Granted);
      assert_eq!(perms2.net.query(None), PermissionState::Prompt);
      assert_eq!(perms2.net.query(Some(&NetDescriptor(Host::must_parse("127.0.0.1"), Some(8000)))), PermissionState::Granted);
      assert_eq!(perms3.net.query(None), PermissionState::Prompt);
      assert_eq!(perms3.net.query(Some(&NetDescriptor(Host::must_parse("127.0.0.1"), Some(8000)))), PermissionState::Denied);
      assert_eq!(perms4.net.query(None), PermissionState::GrantedPartial);
      assert_eq!(perms4.net.query(Some(&NetDescriptor(Host::must_parse("127.0.0.1"), Some(8000)))), PermissionState::Denied);
      assert_eq!(perms4.net.query(Some(&NetDescriptor(Host::must_parse("192.168.0.1"), Some(8000)))), PermissionState::Granted);
      assert_eq!(perms1.env.query(None), PermissionState::Granted);
      assert_eq!(perms1.env.query(Some("HOME")), PermissionState::Granted);
      assert_eq!(perms2.env.query(None), PermissionState::Prompt);
      assert_eq!(perms2.env.query(Some("HOME")), PermissionState::Granted);
      assert_eq!(perms3.env.query(None), PermissionState::Prompt);
      assert_eq!(perms3.env.query(Some("HOME")), PermissionState::Denied);
      assert_eq!(perms4.env.query(None), PermissionState::GrantedPartial);
      assert_eq!(perms4.env.query(Some("HOME")), PermissionState::Denied);
      assert_eq!(perms4.env.query(Some("AWAY")), PermissionState::Granted);
      let sys_desc = |name: &str| SysDescriptor::parse(name.to_string()).unwrap();
      assert_eq!(perms1.sys.query(None), PermissionState::Granted);
      assert_eq!(perms1.sys.query(Some(&sys_desc("osRelease"))), PermissionState::Granted);
      assert_eq!(perms2.sys.query(None), PermissionState::Prompt);
      assert_eq!(perms2.sys.query(Some(&sys_desc("hostname"))), PermissionState::Granted);
      assert_eq!(perms3.sys.query(None), PermissionState::Prompt);
      assert_eq!(perms3.sys.query(Some(&sys_desc("hostname"))), PermissionState::Denied);
      assert_eq!(perms4.sys.query(None), PermissionState::GrantedPartial);
      assert_eq!(perms4.sys.query(Some(&sys_desc("hostname"))), PermissionState::Denied);
      assert_eq!(perms4.sys.query(Some(&sys_desc("uid"))), PermissionState::Granted);
      assert_eq!(perms1.run.query(None), PermissionState::Granted);
      let deno_run_query = RunQueryDescriptor::Path(PathQueryDescriptor::new_known_absolute(Cow::Owned(PathBuf::from("/deno"))).with_requested("deno".to_string()));
      let node_run_query = RunQueryDescriptor::Path(
        PathQueryDescriptor::new_known_absolute(Cow::Owned(PathBuf::from("/node"))).with_requested("node".to_string())
      );
      assert_eq!(perms1.run.query(Some(&deno_run_query)), PermissionState::Granted);
      assert_eq!(perms1.write.query(Some(&write_query("/deno"))), PermissionState::Granted);
      assert_eq!(perms2.run.query(None), PermissionState::Prompt);
      assert_eq!(perms2.run.query(Some(&deno_run_query)), PermissionState::Granted);
      assert_eq!(perms2.write.query(Some(&write_query("/deno"))), PermissionState::Denied);
      assert_eq!(perms3.run.query(None), PermissionState::Prompt);
      assert_eq!(perms3.run.query(Some(&deno_run_query)), PermissionState::Denied);
      assert_eq!(perms4.run.query(None), PermissionState::GrantedPartial);
      assert_eq!(perms4.run.query(Some(&deno_run_query)), PermissionState::Denied);
      assert_eq!(perms4.run.query(Some(&node_run_query)), PermissionState::Granted);
      assert_eq!(perms3.import.query(None), PermissionState::Prompt);
      assert_eq!(perms3.import.query(Some(&ImportDescriptor(NetDescriptor(Host::must_parse("example.com"), Some(443))))), PermissionState::Denied);
      assert_eq!(perms4.import.query(None), PermissionState::GrantedPartial);
      assert_eq!(perms4.import.query(Some(&ImportDescriptor(NetDescriptor(Host::must_parse("example.com"), Some(443))))), PermissionState::Denied);
      assert_eq!(perms4.import.query(Some(&ImportDescriptor(NetDescriptor(Host::must_parse("deno.land"), Some(443))))), PermissionState::Granted);
    };
    #[rustfmt::skip]
    {
      let perms = Permissions::from_options(
        &parser,
        &PermissionsOptions {
          allow_read: Some(svec!["/foo/specific"]),
          deny_read: Some(svec!["/foo"]),
          allow_write: Some(svec!["/foo/specific"]),
          deny_write: Some(svec!["/foo"]),
          allow_ffi: Some(svec!["/foo/specific"]),
          deny_ffi: Some(svec!["/foo"]),
          ..Default::default()
        },
      )
      .unwrap();
      assert_eq!(perms.read.query(Some(&read_query("/foo"))), PermissionState::Denied);
      assert_eq!(perms.read.query(Some(&read_query("/"))), PermissionState::Prompt);
      assert_eq!(perms.read.query(Some(&read_query("/foo/specific"))), PermissionState::Granted);
      assert_eq!(perms.read.query(Some(&read_query("/foo/specific/data.txt"))), PermissionState::Granted);
      assert_eq!(perms.write.query(Some(&write_query("/foo"))), PermissionState::Denied);
      assert_eq!(perms.write.query(Some(&write_query("/foo/specific"))), PermissionState::Granted);
      assert_eq!(perms.ffi.query(Some(&ffi_query("/foo"))), PermissionState::Denied);
      assert_eq!(perms.ffi.query(Some(&ffi_query("/foo/specific"))), PermissionState::Granted);
    };
    #[rustfmt::skip]
    {
      // flipped above
      let perms = Permissions::from_options(
        &parser,
        &PermissionsOptions {
          allow_read: Some(svec!["/foo"]),
          deny_read: Some(svec!["/foo/specific"]),
          allow_write: Some(svec!["/foo"]),
          deny_write: Some(svec!["/foo/specific"]),
          allow_ffi: Some(svec!["/foo"]),
          deny_ffi: Some(svec!["/foo/specific"]),
          ..Default::default()
        },
      )
      .unwrap();
      assert_eq!(perms.read.query(Some(&read_query("/foo"))), PermissionState::GrantedPartial);
      assert_eq!(perms.read.query(Some(&read_query("/foo/bar"))), PermissionState::Granted);
      assert_eq!(perms.read.query(Some(&read_query("/"))), PermissionState::Prompt);
      assert_eq!(perms.read.query(Some(&read_query("/foo/specific"))), PermissionState::Denied);
      assert_eq!(perms.read.query(Some(&read_query("/foo/specific/data.txt"))), PermissionState::Denied);
      assert_eq!(perms.write.query(Some(&write_query("/foo"))), PermissionState::GrantedPartial);
      assert_eq!(perms.write.query(Some(&write_query("/foo/bar"))), PermissionState::Granted);
      assert_eq!(perms.write.query(Some(&write_query("/foo/specific"))), PermissionState::Denied);
      assert_eq!(perms.ffi.query(Some(&ffi_query("/foo"))), PermissionState::GrantedPartial);
      assert_eq!(perms.ffi.query(Some(&ffi_query("/foo/bar"))), PermissionState::Granted);
      assert_eq!(perms.ffi.query(Some(&ffi_query("/foo/specific"))), PermissionState::Denied);
    };
  }

  #[test]
  fn test_request() {
    set_prompter(Box::new(TestPrompter));
    let parser = TestPermissionDescriptorParser;
    let mut perms: Permissions = Permissions::none_with_prompt();
    let mut perms_no_prompt: Permissions = Permissions::none_without_prompt();
    let read_query = |path: &str| {
      parser
        .parse_path_query(Cow::Owned(PathBuf::from(path)))
        .unwrap()
        .into_read()
    };
    let write_query = |path: &str| {
      parser
        .parse_path_query(Cow::Owned(PathBuf::from(path)))
        .unwrap()
        .into_write()
    };
    let ffi_query = |path: &str| {
      parser
        .parse_path_query(Cow::Owned(PathBuf::from(path)))
        .unwrap()
        .into_ffi()
    };
    #[rustfmt::skip]
    {
      let prompt_value = PERMISSION_PROMPT_STUB_VALUE_SETTER.lock();
      prompt_value.set(true);
      assert_eq!(perms.read.request(Some(&read_query("/foo"))), PermissionState::Granted);
      assert_eq!(perms.read.query(None), PermissionState::Prompt);
      prompt_value.set(false);
      assert_eq!(perms.read.request(Some(&read_query("/foo/bar"))), PermissionState::Granted);
      prompt_value.set(false);
      assert_eq!(perms.write.request(Some(&write_query("/foo"))), PermissionState::Denied);
      assert_eq!(perms.write.query(Some(&write_query("/foo/bar"))), PermissionState::Prompt);
      prompt_value.set(true);
      assert_eq!(perms.write.request(None), PermissionState::Denied);
      prompt_value.set(false);
      assert_eq!(perms.ffi.request(Some(&ffi_query("/foo"))), PermissionState::Denied);
      assert_eq!(perms.ffi.query(Some(&ffi_query("/foo/bar"))), PermissionState::Prompt);
      prompt_value.set(true);
      assert_eq!(perms.ffi.request(None), PermissionState::Denied);
      prompt_value.set(true);
      assert_eq!(perms.net.request(Some(&NetDescriptor(Host::must_parse("127.0.0.1"), None))), PermissionState::Granted);
      prompt_value.set(false);
      assert_eq!(perms.net.request(Some(&NetDescriptor(Host::must_parse("127.0.0.1"), Some(8000)))), PermissionState::Granted);
      prompt_value.set(true);
      assert_eq!(perms.env.request(Some("HOME")), PermissionState::Granted);
      assert_eq!(perms.env.query(None), PermissionState::Prompt);
      prompt_value.set(false);
      assert_eq!(perms.env.request(Some("HOME")), PermissionState::Granted);
      prompt_value.set(true);
      let sys_desc = |name: &str| SysDescriptor::parse(name.to_string()).unwrap();
      assert_eq!(perms.sys.request(Some(&sys_desc("hostname"))), PermissionState::Granted);
      assert_eq!(perms.sys.query(None), PermissionState::Prompt);
      prompt_value.set(false);
      assert_eq!(perms.sys.request(Some(&sys_desc("hostname"))), PermissionState::Granted);
      prompt_value.set(true);
      let run_query = RunQueryDescriptor::Path(PathQueryDescriptor::new_known_absolute(Cow::Owned(PathBuf::from("/deno"))).with_requested("deno".to_string()));
      assert_eq!(perms.run.request(Some(&run_query)), PermissionState::Granted);
      assert_eq!(perms.run.query(None), PermissionState::Prompt);
      prompt_value.set(false);
      assert_eq!(perms.run.request(Some(&run_query)), PermissionState::Granted);
      assert_eq!(perms_no_prompt.read.request(Some(&read_query("/foo"))), PermissionState::Denied);
    };
  }

  #[test]
  fn test_revoke() {
    set_prompter(Box::new(TestPrompter));
    let parser = TestPermissionDescriptorParser;
    let mut perms = Permissions::from_options(
      &parser,
      &PermissionsOptions {
        allow_read: Some(svec!["/foo", "/foo/baz"]),
        allow_write: Some(svec!["/foo", "/foo/baz"]),
        allow_ffi: Some(svec!["/foo", "/foo/baz"]),
        allow_net: Some(svec!["127.0.0.1", "127.0.0.1:8000"]),
        allow_env: Some(svec!["HOME"]),
        allow_sys: Some(svec!["hostname"]),
        allow_run: Some(svec!["/deno"]),
        ..Default::default()
      },
    )
    .unwrap();
    let read_query = |path: &str| {
      parser
        .parse_path_query(Cow::Owned(PathBuf::from(path)))
        .unwrap()
        .into_read()
    };
    let write_query = |path: &str| {
      parser
        .parse_path_query(Cow::Owned(PathBuf::from(path)))
        .unwrap()
        .into_write()
    };
    let ffi_query = |path: &str| {
      parser
        .parse_path_query(Cow::Owned(PathBuf::from(path)))
        .unwrap()
        .into_ffi()
    };
    #[rustfmt::skip]
    {
      assert_eq!(perms.read.revoke(Some(&read_query("/foo/bar"))), PermissionState::Prompt);
      assert_eq!(perms.read.query(Some(&read_query("/foo"))), PermissionState::Prompt);
      assert_eq!(perms.read.query(Some(&read_query("/foo/baz"))), PermissionState::Granted);
      assert_eq!(perms.write.revoke(Some(&write_query("/foo/bar"))), PermissionState::Prompt);
      assert_eq!(perms.write.query(Some(&write_query("/foo"))), PermissionState::Prompt);
      assert_eq!(perms.write.query(Some(&write_query("/foo/baz"))), PermissionState::Granted);
      assert_eq!(perms.ffi.revoke(Some(&ffi_query("/foo/bar"))), PermissionState::Prompt);
      assert_eq!(perms.ffi.query(Some(&ffi_query("/foo"))), PermissionState::Prompt);
      assert_eq!(perms.ffi.query(Some(&ffi_query("/foo/baz"))), PermissionState::Granted);
      assert_eq!(perms.net.revoke(Some(&NetDescriptor(Host::must_parse("127.0.0.1"), Some(9000)))), PermissionState::Prompt);
      assert_eq!(perms.net.query(Some(&NetDescriptor(Host::must_parse("127.0.0.1"), None))), PermissionState::Prompt);
      assert_eq!(perms.net.query(Some(&NetDescriptor(Host::must_parse("127.0.0.1"), Some(8000)))), PermissionState::Granted);
      assert_eq!(perms.env.revoke(Some("HOME")), PermissionState::Prompt);
      assert_eq!(perms.env.revoke(Some("hostname")), PermissionState::Prompt);
      let run_query = RunQueryDescriptor::Path(PathQueryDescriptor::new_known_absolute(Cow::Owned(PathBuf::from("/deno"))).with_requested("deno".to_string()));
      assert_eq!(perms.run.revoke(Some(&run_query)), PermissionState::Prompt);
    };
  }

  #[test]
  fn test_check() {
    set_prompter(Box::new(TestPrompter));
    let mut perms = Permissions::none_with_prompt();
    let prompt_value = PERMISSION_PROMPT_STUB_VALUE_SETTER.lock();
    let parser = TestPermissionDescriptorParser;
    let read_query = |path: &str| {
      parser
        .parse_path_query(Cow::Owned(PathBuf::from(path)))
        .unwrap()
        .into_read()
    };
    let write_query = |path: &str| {
      parser
        .parse_path_query(Cow::Owned(PathBuf::from(path)))
        .unwrap()
        .into_write()
    };
    let ffi_query = |path: &str| {
      parser
        .parse_path_query(Cow::Owned(PathBuf::from(path)))
        .unwrap()
        .into_ffi()
    };

    prompt_value.set(true);
    assert!(perms.read.check(&read_query("/foo"), None).is_ok());
    prompt_value.set(false);
    assert!(perms.read.check(&read_query("/foo"), None).is_ok());
    assert!(perms.read.check(&read_query("/bar"), None).is_err());

    prompt_value.set(true);
    assert!(perms.write.check(&write_query("/foo"), None).is_ok());
    prompt_value.set(false);
    assert!(perms.write.check(&write_query("/foo"), None).is_ok());
    assert!(perms.write.check(&write_query("/bar"), None).is_err());

    prompt_value.set(true);
    assert!(perms.ffi.check(&ffi_query("/foo"), None).is_ok());
    prompt_value.set(false);
    assert!(perms.ffi.check(&ffi_query("/foo"), None).is_ok());
    assert!(perms.ffi.check(&ffi_query("/bar"), None).is_err());

    prompt_value.set(true);
    assert!(
      perms
        .net
        .check(
          &NetDescriptor(Host::must_parse("127.0.0.1"), Some(8000)),
          None
        )
        .is_ok()
    );
    prompt_value.set(false);
    assert!(
      perms
        .net
        .check(
          &NetDescriptor(Host::must_parse("127.0.0.1"), Some(8000)),
          None
        )
        .is_ok()
    );
    assert!(
      perms
        .net
        .check(
          &NetDescriptor(Host::must_parse("127.0.0.1"), Some(8001)),
          None
        )
        .is_err()
    );
    assert!(
      perms
        .net
        .check(&NetDescriptor(Host::must_parse("127.0.0.1"), None), None)
        .is_err()
    );
    assert!(
      perms
        .net
        .check(
          &NetDescriptor(Host::must_parse("deno.land"), Some(8000)),
          None
        )
        .is_err()
    );
    assert!(
      perms
        .net
        .check(&NetDescriptor(Host::must_parse("deno.land"), None), None)
        .is_err()
    );

    let cwd = sys_traits::impls::RealSys.env_current_dir().unwrap();
    prompt_value.set(true);
    assert!(
      perms
        .run
        .check(
          &RunQueryDescriptor::Path(
            PathQueryDescriptor::new_known_absolute(Cow::Owned(
              cwd.join("cat")
            ))
            .with_requested("cat".to_string()),
          ),
          None
        )
        .is_ok()
    );
    prompt_value.set(false);
    assert!(
      perms
        .run
        .check(
          &RunQueryDescriptor::Path(
            PathQueryDescriptor::new_known_absolute(Cow::Owned(
              cwd.join("cat")
            ))
            .with_requested("cat".to_string())
          ),
          None
        )
        .is_ok()
    );
    assert!(
      perms
        .run
        .check(
          &RunQueryDescriptor::Path(
            PathQueryDescriptor::new_known_absolute(Cow::Owned(cwd.join("ls")))
              .with_requested("ls".to_string())
          ),
          None
        )
        .is_err()
    );

    prompt_value.set(true);
    assert!(perms.env.check("HOME", None).is_ok());
    prompt_value.set(false);
    assert!(perms.env.check("HOME", None).is_ok());
    assert!(perms.env.check("PATH", None).is_err());

    prompt_value.set(true);
    assert!(perms.env.check("hostname", None).is_ok());
    prompt_value.set(false);
    assert!(perms.env.check("hostname", None).is_ok());
    assert!(perms.env.check("osRelease", None).is_err());
  }

  #[test]
  fn test_check_fail() {
    set_prompter(Box::new(TestPrompter));
    let mut perms = Permissions::none_with_prompt();
    let prompt_value = PERMISSION_PROMPT_STUB_VALUE_SETTER.lock();
    let parser = TestPermissionDescriptorParser;
    let read_query = |path: &str| {
      parser
        .parse_path_query(Cow::Owned(PathBuf::from(path)))
        .unwrap()
        .into_read()
    };
    let write_query = |path: &str| {
      parser
        .parse_path_query(Cow::Owned(PathBuf::from(path)))
        .unwrap()
        .into_write()
    };
    let ffi_query = |path: &str| {
      parser
        .parse_path_query(Cow::Owned(PathBuf::from(path)))
        .unwrap()
        .into_ffi()
    };

    prompt_value.set(false);
    assert!(perms.read.check(&read_query("/foo"), None).is_err());
    prompt_value.set(true);
    assert!(perms.read.check(&read_query("/foo"), None).is_err());
    assert!(perms.read.check(&read_query("/bar"), None).is_ok());
    prompt_value.set(false);
    assert!(perms.read.check(&read_query("/bar"), None).is_ok());

    prompt_value.set(false);
    assert!(perms.write.check(&write_query("/foo"), None).is_err());
    prompt_value.set(true);
    assert!(perms.write.check(&write_query("/foo"), None).is_err());
    assert!(perms.write.check(&write_query("/bar"), None).is_ok());
    prompt_value.set(false);
    assert!(perms.write.check(&write_query("/bar"), None).is_ok());

    prompt_value.set(false);
    assert!(perms.ffi.check(&ffi_query("/foo"), None).is_err());
    prompt_value.set(true);
    assert!(perms.ffi.check(&ffi_query("/foo"), None).is_err());
    assert!(perms.ffi.check(&ffi_query("/bar"), None).is_ok());
    prompt_value.set(false);
    assert!(perms.ffi.check(&ffi_query("/bar"), None).is_ok());

    prompt_value.set(false);
    assert!(
      perms
        .net
        .check(
          &NetDescriptor(Host::must_parse("127.0.0.1"), Some(8000)),
          None
        )
        .is_err()
    );
    prompt_value.set(true);
    assert!(
      perms
        .net
        .check(
          &NetDescriptor(Host::must_parse("127.0.0.1"), Some(8000)),
          None
        )
        .is_err()
    );
    assert!(
      perms
        .net
        .check(
          &NetDescriptor(Host::must_parse("127.0.0.1"), Some(8001)),
          None
        )
        .is_ok()
    );
    assert!(
      perms
        .net
        .check(
          &NetDescriptor(Host::must_parse("deno.land"), Some(8000)),
          None
        )
        .is_ok()
    );
    prompt_value.set(false);
    assert!(
      perms
        .net
        .check(
          &NetDescriptor(Host::must_parse("127.0.0.1"), Some(8001)),
          None
        )
        .is_ok()
    );
    assert!(
      perms
        .net
        .check(
          &NetDescriptor(Host::must_parse("deno.land"), Some(8000)),
          None
        )
        .is_ok()
    );

    prompt_value.set(false);
    let cwd = sys_traits::impls::RealSys.env_current_dir().unwrap();
    assert!(
      perms
        .run
        .check(
          &RunQueryDescriptor::Path(
            PathQueryDescriptor::new_known_absolute(Cow::Owned(
              cwd.join("cat")
            ))
            .with_requested("cat".to_string())
          ),
          None
        )
        .is_err()
    );
    prompt_value.set(true);
    assert!(
      perms
        .run
        .check(
          &RunQueryDescriptor::Path(
            PathQueryDescriptor::new_known_absolute(Cow::Owned(
              cwd.join("cat")
            ))
            .with_requested("cat".to_string())
          ),
          None
        )
        .is_err()
    );
    assert!(
      perms
        .run
        .check(
          &RunQueryDescriptor::Path(
            PathQueryDescriptor::new_known_absolute(Cow::Owned(cwd.join("ls")))
              .with_requested("ls".to_string())
          ),
          None
        )
        .is_ok()
    );
    prompt_value.set(false);
    assert!(
      perms
        .run
        .check(
          &RunQueryDescriptor::Path(
            PathQueryDescriptor::new_known_absolute(Cow::Owned(cwd.join("ls")))
              .with_requested("ls".to_string())
          ),
          None
        )
        .is_ok()
    );

    prompt_value.set(false);
    assert!(perms.env.check("HOME", None).is_err());
    prompt_value.set(true);
    assert!(perms.env.check("HOME", None).is_err());
    assert!(perms.env.check("PATH", None).is_ok());
    prompt_value.set(false);
    assert!(perms.env.check("PATH", None).is_ok());

    prompt_value.set(false);
    let sys_desc = |name: &str| SysDescriptor::parse(name.to_string()).unwrap();
    assert!(perms.sys.check(&sys_desc("hostname"), None).is_err());
    prompt_value.set(true);
    assert!(perms.sys.check(&sys_desc("hostname"), None).is_err());
    assert!(perms.sys.check(&sys_desc("osRelease"), None).is_ok());
    prompt_value.set(false);
    assert!(perms.sys.check(&sys_desc("osRelease"), None).is_ok());
  }

  #[test]
  #[cfg(windows)]
  fn test_env_windows() {
    set_prompter(Box::new(TestPrompter));
    let prompt_value = PERMISSION_PROMPT_STUB_VALUE_SETTER.lock();
    let mut perms = Permissions::allow_all();
    perms.env = UnaryPermission {
      granted_global: false,
      ..Permissions::new_unary(
        Some(Vec::from([EnvDescriptor::new(Cow::Borrowed("HOME"))])),
        None,
        false,
      )
    };

    prompt_value.set(true);
    assert!(perms.env.check("HOME", None).is_ok());
    prompt_value.set(false);
    assert!(perms.env.check("HOME", None).is_ok());
    assert!(perms.env.check("hOmE", None).is_ok());

    assert_eq!(perms.env.revoke(Some("HomE")), PermissionState::Prompt);
  }

  #[test]
  fn test_env_wildcards() {
    set_prompter(Box::new(TestPrompter));
    let _prompt_value = PERMISSION_PROMPT_STUB_VALUE_SETTER.lock();
    let mut perms = Permissions::allow_all();
    perms.env = UnaryPermission {
      granted_global: false,
      ..Permissions::new_unary(
        Some(Vec::from([EnvDescriptor::new(Cow::Borrowed("HOME_*"))])),
        None,
        false,
      )
    };
    assert_eq!(perms.env.query(Some("HOME")), PermissionState::Prompt);
    assert_eq!(perms.env.query(Some("HOME_")), PermissionState::Granted);
    assert_eq!(perms.env.query(Some("HOME_TEST")), PermissionState::Granted);

    // assert no privilege escalation
    let parser = TestPermissionDescriptorParser;
    assert!(
      perms
        .env
        .create_child_permissions(
          ChildUnaryPermissionArg::GrantedList(vec!["HOME_SUB".to_string()]),
          |value| parser.parse_env_descriptor(value).map(Some),
        )
        .is_ok()
    );
    assert!(
      perms
        .env
        .create_child_permissions(
          ChildUnaryPermissionArg::GrantedList(vec!["HOME*".to_string()]),
          |value| parser.parse_env_descriptor(value).map(Some),
        )
        .is_err()
    );
    assert!(
      perms
        .env
        .create_child_permissions(
          ChildUnaryPermissionArg::GrantedList(vec!["OUTSIDE".to_string()]),
          |value| parser.parse_env_descriptor(value).map(Some),
        )
        .is_err()
    );
    assert!(
      perms
        .env
        .create_child_permissions(
          // ok because this is a subset of HOME_*
          ChildUnaryPermissionArg::GrantedList(vec!["HOME_S*".to_string()]),
          |value| parser.parse_env_descriptor(value).map(Some),
        )
        .is_ok()
    );
    {
      let mut perms = Permissions::none_without_prompt();
      perms.env = UnaryPermission {
        granted_global: false,
        ..Permissions::new_unary(
          Some(Vec::from([
            EnvDescriptor::new(Cow::Borrowed("PREFIX_ALLOWED*")),
            EnvDescriptor::new(Cow::Borrowed("PREFIX_EXPLICIT_ALLOWED")),
          ])),
          Some(Vec::from([EnvDescriptor::new(Cow::Borrowed("PREFIX*"))])),
          false,
        )
      };
      assert_eq!(
        perms.env.query(Some("PREFIX_TEST")),
        PermissionState::Denied
      );
      assert_eq!(
        perms.env.query(Some("PREFIX_ALLOWED_TEST")),
        PermissionState::Granted
      );
      assert_eq!(
        perms.env.query(Some("PREFIX_EXPLICIT_ALLOWED")),
        PermissionState::Granted
      );
    }
  }

  #[test]
  fn test_env_ignore() {
    set_prompter(Box::new(TestPrompter));
    let _prompt_value = PERMISSION_PROMPT_STUB_VALUE_SETTER.lock();
    {
      let mut perms = Permissions::none_without_prompt();
      perms.env = UnaryPermission {
        granted_global: false,
        ..Permissions::new_unary_with_ignore(
          Some(Vec::from([EnvDescriptor::new(Cow::Borrowed("ALLOWED_*"))])),
          Some(Vec::from([EnvDescriptor::new(Cow::Borrowed("DENIED_*"))])),
          Some(Vec::from([EnvDescriptor::new(Cow::Borrowed("IGNORED_*"))])),
          false,
        )
      };
      assert_eq!(
        perms.env.query(Some("ALLOWED_TEST")),
        PermissionState::Granted
      );
      assert_eq!(
        perms.env.query(Some("IGNORED_TEST")),
        PermissionState::Ignored
      );
      assert_eq!(
        perms.env.query(Some("DENIED_TEST")),
        PermissionState::Denied
      );
    }
    {
      let mut perms = Permissions::none_without_prompt();
      perms.env = UnaryPermission {
        granted_global: false,
        ..Permissions::new_unary_with_ignore(
          Some(Vec::from([EnvDescriptor::new(Cow::Borrowed(
            "PREFIX_ALLOWED*",
          ))])),
          Some(Vec::from([EnvDescriptor::new(Cow::Borrowed("PREFIX*"))])),
          Some(Vec::from([EnvDescriptor::new(Cow::Borrowed(
            "PREFIX_IGNORED*",
          ))])),
          false,
        )
      };
      assert_eq!(
        perms.env.query(Some("PREFIX_TEST")),
        PermissionState::Denied
      );
      assert_eq!(
        perms.env.query(Some("PREFIX_IGNORED_TEST")),
        PermissionState::Ignored
      );
      assert_eq!(
        perms.env.query(Some("PREFIX_ALLOWED_TEST")),
        PermissionState::Granted
      );
    }
  }

  #[test]
  fn test_read_ignore() {
    set_prompter(Box::new(TestPrompter));
    let _prompt_value = PERMISSION_PROMPT_STUB_VALUE_SETTER.lock();
    let parser = TestPermissionDescriptorParser;
    {
      let mut perms = Permissions::none_without_prompt();
      perms.read = UnaryPermission {
        granted_global: false,
        ..Permissions::new_unary_with_ignore(
          Some(Vec::from([ReadDescriptor(
            parser.join_path_with_root("allowed"),
          )])),
          Some(Vec::from([ReadDescriptor(
            parser.join_path_with_root("denied"),
          )])),
          Some(Vec::from([ReadDescriptor(
            parser.join_path_with_root("ignored"),
          )])),
          false,
        )
      };
      let allowed_query = parser
        .parse_path_query(Cow::Borrowed(Path::new("/allowed")))
        .unwrap()
        .into_read();
      assert_eq!(
        perms.read.query(Some(&allowed_query)),
        PermissionState::Granted
      );
      let ignored_query = parser
        .parse_path_query(Cow::Borrowed(Path::new("/ignored")))
        .unwrap()
        .into_read();
      assert_eq!(
        perms.read.query(Some(&ignored_query)),
        PermissionState::Ignored
      );
      let denied_query = parser
        .parse_path_query(Cow::Borrowed(Path::new("/denied")))
        .unwrap()
        .into_read();
      assert_eq!(
        perms.read.query(Some(&denied_query)),
        PermissionState::Denied
      );
    }
    {
      let mut perms = Permissions::none_without_prompt();
      perms.read = UnaryPermission {
        granted_global: false,
        ..Permissions::new_unary_with_ignore(
          Some(Vec::from([ReadDescriptor(
            parser.join_path_with_root("prefix/allowed"),
          )])),
          Some(Vec::from([ReadDescriptor(
            parser.join_path_with_root("prefix"),
          )])),
          Some(Vec::from([ReadDescriptor(
            parser.join_path_with_root("prefix/ignored"),
          )])),
          false,
        )
      };
      let denied_query = parser
        .parse_path_query(Cow::Borrowed(Path::new("/prefix/test")))
        .unwrap()
        .into_read();
      assert_eq!(
        perms.read.query(Some(&denied_query)),
        PermissionState::Denied
      );
      let ignored_query = parser
        .parse_path_query(Cow::Borrowed(Path::new("/prefix/ignored/test")))
        .unwrap()
        .into_read();
      assert_eq!(
        perms.read.query(Some(&ignored_query)),
        PermissionState::Ignored
      );
      let allowed_query = parser
        .parse_path_query(Cow::Borrowed(Path::new("/prefix/allowed/test")))
        .unwrap()
        .into_read();
      assert_eq!(
        perms.read.query(Some(&allowed_query)),
        PermissionState::Granted
      );
    }
  }

  #[test]
  fn test_check_partial_denied() {
    let parser = TestPermissionDescriptorParser;
    let mut perms = Permissions::from_options(
      &parser,
      &PermissionsOptions {
        allow_write: Some(vec![]),
        deny_write: Some(svec!["/foo/bar"]),
        ..Default::default()
      },
    )
    .unwrap();

    let write_query = parser
      .parse_path_query(Cow::Borrowed(Path::new("/foo")))
      .unwrap()
      .into_write();
    perms.write.check_partial(&write_query, None).unwrap();
    assert!(perms.write.check(&write_query, None).is_err());
  }

  // Regression test for https://github.com/denoland/deno/issues/27622.
  // Querying a path that is an ancestor of a denied path must succeed for
  // single-path read/write operations (`check_partial`), even though the
  // strict `check` continues to reject it.
  #[test]
  fn test_check_partial_ancestor_of_deny() {
    let parser = TestPermissionDescriptorParser;
    let mut perms = Permissions::from_options(
      &parser,
      &PermissionsOptions {
        allow_read: Some(vec![]),
        deny_read: Some(svec!["/mnt"]),
        allow_write: Some(vec![]),
        deny_write: Some(svec!["/foo/bar"]),
        ..Default::default()
      },
    )
    .unwrap();

    let root_read = parser
      .parse_path_query(Cow::Borrowed(Path::new("/")))
      .unwrap()
      .into_read();
    perms.read.check_partial(&root_read, None).unwrap();
    assert!(perms.read.check(&root_read, None).is_err());

    let foo_write = parser
      .parse_path_query(Cow::Borrowed(Path::new("/foo")))
      .unwrap()
      .into_write();
    perms.write.check_partial(&foo_write, None).unwrap();
    assert!(perms.write.check(&foo_write, None).is_err());

    // The actually-denied path is still denied under partial semantics.
    let mnt_read = parser
      .parse_path_query(Cow::Borrowed(Path::new("/mnt")))
      .unwrap()
      .into_read();
    assert!(perms.read.check_partial(&mnt_read, None).is_err());
    let mnt_sub_read = parser
      .parse_path_query(Cow::Borrowed(Path::new("/mnt/sub")))
      .unwrap()
      .into_read();
    assert!(perms.read.check_partial(&mnt_sub_read, None).is_err());
  }

  // Recursive remove must keep strict deny semantics: `check_write` rejects an
  // ancestor of a denied path, while the partial checks used by single-path ops
  // (`check_write_partial`, `check_open`) allow it. Without this, a recursive
  // `Deno.remove("/foo", { recursive: true })` under `--deny-write=/foo/bar`
  // would delete the denied descendant.
  #[test]
  fn test_check_write_strict_for_recursive_remove() {
    let parser = TestPermissionDescriptorParser;
    let perms = Permissions::from_options(
      &parser,
      &PermissionsOptions {
        allow_write: Some(vec![]),
        deny_write: Some(svec!["/foo/bar"]),
        ..Default::default()
      },
    )
    .unwrap();
    let perms = PermissionsContainer::new(Arc::new(parser), perms);

    // Strict write check (used by recursive remove) rejects the ancestor.
    assert!(
      perms
        .check_write(Cow::Borrowed(Path::new("/foo")), "Deno.removeSync()")
        .is_err(),
      "recursive remove of an ancestor of a denied path must be blocked"
    );

    // Partial checks (used by non-recursive remove and other single-path ops)
    // allow the ancestor.
    perms
      .check_write_partial(
        Cow::Borrowed(Path::new("/foo")),
        "Deno.removeSync()",
      )
      .unwrap();
    perms
      .check_open(
        Cow::Borrowed(Path::new("/foo")),
        OpenAccessKind::WriteNoFollow,
        Some("api"),
      )
      .unwrap();

    // The denied path itself is rejected by every variant.
    assert!(
      perms
        .check_write(Cow::Borrowed(Path::new("/foo/bar")), "Deno.removeSync()")
        .is_err()
    );
    assert!(
      perms
        .check_write_partial(
          Cow::Borrowed(Path::new("/foo/bar")),
          "Deno.removeSync()"
        )
        .is_err()
    );
  }

  #[test]
  fn test_check_allow_global_deny_global() {
    let parser = TestPermissionDescriptorParser;
    let mut perms = Permissions::from_options(
      &parser,
      &PermissionsOptions {
        allow_read: Some(vec![]),
        deny_read: Some(vec![]),
        allow_write: Some(vec![]),
        deny_write: Some(vec![]),
        ..Default::default()
      },
    )
    .unwrap();

    assert!(perms.read.check_all(None).is_err());
    let read_query = parser
      .parse_path_query(Cow::Borrowed(Path::new("/foo")))
      .unwrap()
      .into_read();
    assert!(perms.read.check(&read_query, None).is_err());

    assert!(perms.write.check_all(None).is_err());
    let write_query = parser
      .parse_path_query(Cow::Borrowed(Path::new("/foo")))
      .unwrap()
      .into_write();
    assert!(perms.write.check(&write_query, None).is_err());
  }

  #[test]
  fn test_net_fully_qualified_domain_name() {
    set_prompter(Box::new(TestPrompter));
    let parser = TestPermissionDescriptorParser;
    let perms = Permissions::from_options(
      &parser,
      &PermissionsOptions {
        allow_net: Some(svec!["allowed.domain", "1.1.1.1"]),
        deny_net: Some(svec!["denied.domain", "2.2.2.2"]),
        ..Default::default()
      },
    )
    .unwrap();
    let mut perms = PermissionsContainer::new(Arc::new(parser), perms);
    let cases = [
      ("allowed.domain.", true),
      ("1.1.1.1", true),
      ("denied.domain.", false),
      ("2.2.2.2", false),
    ];

    for (host, is_ok) in cases {
      assert_eq!(
        perms
          .check_net(NetPermissionAction::Connect, &(host, None), "api")
          .is_ok(),
        is_ok
      );
    }
  }

  #[test]
  fn test_net_ip_subnet() {
    set_prompter(Box::new(TestPrompter));
    let parser = TestPermissionDescriptorParser;
    let perms = Permissions::from_options(
      &parser,
      &PermissionsOptions {
        allow_net: Some(svec!["10.0.0.0/24"]),
        deny_net: Some(svec!["192.168.1.0/24", "172.16.0.0/12"]),
        ..Default::default()
      },
    )
    .unwrap();
    let mut perms = PermissionsContainer::new(Arc::new(parser), perms);
    let cases = [
      ("10.0.0.1", true),
      ("192.168.1.1", false),
      ("172.16.0.1", false),
    ];

    for (host, is_ok) in cases {
      assert_eq!(
        perms
          .check_net(NetPermissionAction::Connect, &(host, None), "api")
          .is_ok(),
        is_ok
      );
    }
  }

  #[test]
  fn test_net_ipv4_mapped_ipv6() {
    set_prompter(Box::new(TestPrompter));
    let parser = TestPermissionDescriptorParser;

    // Deny an IPv4 address, verify IPv4-mapped IPv6 form is also denied
    let perms = Permissions::from_options(
      &parser,
      &PermissionsOptions {
        allow_net: Some(vec![]),
        deny_net: Some(svec!["127.0.0.1"]),
        ..Default::default()
      },
    )
    .unwrap();
    let mut perms = PermissionsContainer::new(Arc::new(parser), perms);

    // Direct IPv4 is denied
    assert!(
      perms
        .check_net(NetPermissionAction::Connect, &("127.0.0.1", None), "api")
        .is_err()
    );
    // IPv4-mapped IPv6 form must also be denied
    assert!(
      perms
        .check_net(
          NetPermissionAction::Connect,
          &("::ffff:127.0.0.1", None),
          "api"
        )
        .is_err()
    );
    // Regular IPv6 loopback is a different address, should be allowed
    assert!(
      perms
        .check_net(NetPermissionAction::Connect, &("::1", None), "api")
        .is_ok()
    );
    // Other IPv4 addresses should be allowed
    assert!(
      perms
        .check_net(NetPermissionAction::Connect, &("192.168.1.1", None), "api")
        .is_ok()
    );

    // Allow an IPv4-mapped IPv6, verify it's accessible via IPv4 too
    let parser = TestPermissionDescriptorParser;
    let perms = Permissions::from_options(
      &parser,
      &PermissionsOptions {
        allow_net: Some(svec!["[::ffff:10.0.0.1]"]),
        ..Default::default()
      },
    )
    .unwrap();
    let mut perms = PermissionsContainer::new(Arc::new(parser), perms);

    assert!(
      perms
        .check_net(NetPermissionAction::Connect, &("10.0.0.1", None), "api")
        .is_ok()
    );
    assert!(
      perms
        .check_net(
          NetPermissionAction::Connect,
          &("::ffff:10.0.0.1", None),
          "api"
        )
        .is_ok()
    );

    // Port-qualified: deny 127.0.0.1:8080, verify IPv4-mapped form
    // with port is also denied (exercises the SocketAddr parse path)
    let parser = TestPermissionDescriptorParser;
    let perms = Permissions::from_options(
      &parser,
      &PermissionsOptions {
        allow_net: Some(vec![]),
        deny_net: Some(svec!["127.0.0.1:8080"]),
        ..Default::default()
      },
    )
    .unwrap();
    let mut perms = PermissionsContainer::new(Arc::new(parser), perms);

    assert!(
      perms
        .check_net(
          NetPermissionAction::Connect,
          &("127.0.0.1", Some(8080)),
          "api"
        )
        .is_err()
    );
    assert!(
      perms
        .check_net(
          NetPermissionAction::Connect,
          &("::ffff:127.0.0.1", Some(8080)),
          "api",
        )
        .is_err()
    );
    // Different port should be allowed
    assert!(
      perms
        .check_net(
          NetPermissionAction::Connect,
          &("::ffff:127.0.0.1", Some(9090)),
          "api",
        )
        .is_ok()
    );
  }

  #[test]
  fn test_deserialize_child_permissions_arg() {
    set_prompter(Box::new(TestPrompter));
    assert_eq!(
      ChildPermissionsArg::inherit(),
      ChildPermissionsArg {
        env: ChildUnaryPermissionArg::Inherit,
        net: ChildUnaryPermissionArg::Inherit,
        ffi: ChildUnaryPermissionArg::Inherit,
        import: ChildUnaryPermissionArg::Inherit,
        read: ChildUnaryPermissionArg::Inherit,
        run: ChildUnaryPermissionArg::Inherit,
        sys: ChildUnaryPermissionArg::Inherit,
        write: ChildUnaryPermissionArg::Inherit,
      }
    );
    assert_eq!(
      ChildPermissionsArg::none(),
      ChildPermissionsArg {
        env: ChildUnaryPermissionArg::NotGranted,
        net: ChildUnaryPermissionArg::NotGranted,
        ffi: ChildUnaryPermissionArg::NotGranted,
        import: ChildUnaryPermissionArg::NotGranted,
        read: ChildUnaryPermissionArg::NotGranted,
        run: ChildUnaryPermissionArg::NotGranted,
        sys: ChildUnaryPermissionArg::NotGranted,
        write: ChildUnaryPermissionArg::NotGranted,
      }
    );
    assert_eq!(
      serde_json::from_value::<ChildPermissionsArg>(json!("inherit")).unwrap(),
      ChildPermissionsArg::inherit()
    );
    assert_eq!(
      serde_json::from_value::<ChildPermissionsArg>(json!("none")).unwrap(),
      ChildPermissionsArg::none()
    );
    assert_eq!(
      serde_json::from_value::<ChildPermissionsArg>(json!({})).unwrap(),
      ChildPermissionsArg::none()
    );
    assert_eq!(
      serde_json::from_value::<ChildPermissionsArg>(json!({
        "env": ["foo", "bar"],
      }))
      .unwrap(),
      ChildPermissionsArg {
        env: ChildUnaryPermissionArg::GrantedList(svec!["foo", "bar"]),
        ..ChildPermissionsArg::none()
      }
    );
    assert_eq!(
      serde_json::from_value::<ChildPermissionsArg>(json!({
        "env": true,
        "net": true,
        "ffi": true,
        "import": true,
        "read": true,
        "run": true,
        "sys": true,
        "write": true,
      }))
      .unwrap(),
      ChildPermissionsArg {
        env: ChildUnaryPermissionArg::Granted,
        net: ChildUnaryPermissionArg::Granted,
        ffi: ChildUnaryPermissionArg::Granted,
        import: ChildUnaryPermissionArg::Granted,
        read: ChildUnaryPermissionArg::Granted,
        run: ChildUnaryPermissionArg::Granted,
        sys: ChildUnaryPermissionArg::Granted,
        write: ChildUnaryPermissionArg::Granted,
      }
    );
    assert_eq!(
      serde_json::from_value::<ChildPermissionsArg>(json!({
        "env": false,
        "net": false,
        "ffi": false,
        "import": false,
        "read": false,
        "run": false,
        "sys": false,
        "write": false,
      }))
      .unwrap(),
      ChildPermissionsArg {
        env: ChildUnaryPermissionArg::NotGranted,
        net: ChildUnaryPermissionArg::NotGranted,
        ffi: ChildUnaryPermissionArg::NotGranted,
        import: ChildUnaryPermissionArg::NotGranted,
        read: ChildUnaryPermissionArg::NotGranted,
        run: ChildUnaryPermissionArg::NotGranted,
        sys: ChildUnaryPermissionArg::NotGranted,
        write: ChildUnaryPermissionArg::NotGranted,
      }
    );
    assert_eq!(
      serde_json::from_value::<ChildPermissionsArg>(json!({
        "env": ["foo", "bar"],
        "net": ["foo", "bar:8000"],
        "ffi": ["foo", "file:///bar/baz"],
        "import": ["example.com"],
        "read": ["foo", "file:///bar/baz"],
        "run": ["foo", "file:///bar/baz", "./qux"],
        "sys": ["hostname", "osRelease"],
        "write": ["foo", "file:///bar/baz"],
      }))
      .unwrap(),
      ChildPermissionsArg {
        env: ChildUnaryPermissionArg::GrantedList(svec!["foo", "bar"]),
        net: ChildUnaryPermissionArg::GrantedList(svec!["foo", "bar:8000"]),
        ffi: ChildUnaryPermissionArg::GrantedList(svec![
          "foo",
          "file:///bar/baz"
        ]),
        import: ChildUnaryPermissionArg::GrantedList(svec!["example.com"]),
        read: ChildUnaryPermissionArg::GrantedList(svec![
          "foo",
          "file:///bar/baz"
        ]),
        run: ChildUnaryPermissionArg::GrantedList(svec![
          "foo",
          "file:///bar/baz",
          "./qux"
        ]),
        sys: ChildUnaryPermissionArg::GrantedList(svec![
          "hostname",
          "osRelease"
        ]),
        write: ChildUnaryPermissionArg::GrantedList(svec![
          "foo",
          "file:///bar/baz"
        ]),
      }
    );
  }

  #[test]
  fn test_create_child_permissions() {
    set_prompter(Box::new(TestPrompter));
    let parser = TestPermissionDescriptorParser;
    let main_perms = Permissions::from_options(
      &parser,
      &PermissionsOptions {
        allow_env: Some(vec![]),
        allow_net: Some(svec!["*.foo", "bar"]),
        ..Default::default()
      },
    )
    .unwrap();
    let main_perms = PermissionsContainer::new(Arc::new(parser), main_perms);
    assert_eq!(
      main_perms
        .create_child_permissions(ChildPermissionsArg {
          env: ChildUnaryPermissionArg::Inherit,
          net: ChildUnaryPermissionArg::GrantedList(svec!["foo"]),
          ffi: ChildUnaryPermissionArg::NotGranted,
          ..ChildPermissionsArg::none()
        })
        .unwrap()
        .inner
        .lock()
        .clone(),
      Permissions {
        env: Permissions::new_unary(Some(Vec::new()), None, false),
        net: Permissions::new_unary(
          Some(Vec::from([NetDescriptor::parse_for_list("foo").unwrap()])),
          None,
          false
        ),
        ..Permissions::none_without_prompt()
      }
    );
    assert!(
      main_perms
        .create_child_permissions(ChildPermissionsArg {
          net: ChildUnaryPermissionArg::Granted,
          ..ChildPermissionsArg::none()
        })
        .is_err()
    );
    assert!(
      main_perms
        .create_child_permissions(ChildPermissionsArg {
          net: ChildUnaryPermissionArg::GrantedList(svec!["foo", "bar", "baz"]),
          ..ChildPermissionsArg::none()
        })
        .is_err()
    );
    assert!(
      main_perms
        .create_child_permissions(ChildPermissionsArg {
          ffi: ChildUnaryPermissionArg::GrantedList(svec!["foo"]),
          ..ChildPermissionsArg::none()
        })
        .is_err()
    );
  }

  #[test]
  fn test_create_child_permissions_with_prompt() {
    set_prompter(Box::new(TestPrompter));
    let prompt_value = PERMISSION_PROMPT_STUB_VALUE_SETTER.lock();
    let main_perms = Permissions::from_options(
      &TestPermissionDescriptorParser,
      &PermissionsOptions {
        prompt: true,
        ..Default::default()
      },
    )
    .unwrap();
    let main_perms = PermissionsContainer::new(
      Arc::new(TestPermissionDescriptorParser),
      main_perms,
    );
    prompt_value.set(true);
    let worker_perms = main_perms
      .create_child_permissions(ChildPermissionsArg {
        read: ChildUnaryPermissionArg::Granted,
        run: ChildUnaryPermissionArg::GrantedList(svec!["foo", "bar"]),
        ..ChildPermissionsArg::none()
      })
      .unwrap();
    assert_eq!(
      main_perms.inner.lock().clone(),
      worker_perms.inner.lock().clone()
    );
    assert_eq!(
      main_perms
        .inner
        .lock()
        .run
        .descriptors
        .iter()
        .filter_map(|d| match d {
          UnaryPermissionDesc::Granted(d) => Some(d.clone()),
          _ => None,
        })
        .collect::<Vec<_>>(),
      Vec::from([
        AllowRunDescriptor(PathDescriptor::new_known_absolute(Cow::Owned(
          PathBuf::from("/bar")
        ))),
        AllowRunDescriptor(PathDescriptor::new_known_absolute(Cow::Owned(
          PathBuf::from("/foo")
        ))),
      ])
    );
  }

  #[test]
  fn test_create_child_permissions_with_inherited_denied_list() {
    set_prompter(Box::new(TestPrompter));
    let prompt_value = PERMISSION_PROMPT_STUB_VALUE_SETTER.lock();
    let parser = TestPermissionDescriptorParser;
    let main_perms = Permissions::from_options(
      &parser,
      &PermissionsOptions {
        prompt: true,
        ..Default::default()
      },
    )
    .unwrap();
    let main_perms =
      PermissionsContainer::new(Arc::new(parser.clone()), main_perms);
    prompt_value.set(false);
    assert!(
      main_perms
        .inner
        .lock()
        .write
        .check(
          &parser
            .parse_path_query(Cow::Borrowed(Path::new("foo")))
            .unwrap()
            .into_write(),
          None
        )
        .is_err()
    );
    let worker_perms = main_perms
      .create_child_permissions(ChildPermissionsArg::none())
      .unwrap();
    assert_eq!(
      worker_perms
        .inner
        .lock()
        .write
        .descriptors
        .iter()
        .filter_map(|d| match d {
          UnaryPermissionDesc::FlagDenied(d) => Some(d.clone()),
          _ => None,
        })
        .collect::<Vec<_>>(),
      main_perms
        .inner
        .lock()
        .write
        .descriptors
        .iter()
        .filter_map(|d| match d {
          UnaryPermissionDesc::FlagDenied(d) => Some(d.clone()),
          _ => None,
        })
        .collect::<Vec<_>>()
    );
  }

  #[test]
  fn test_host_parse_for_query() {
    let hosts = &[
      ("deno.land", Some(Host::Fqdn(fqdn!("deno.land")))),
      ("DENO.land", Some(Host::Fqdn(fqdn!("deno.land")))),
      ("deno.land.", Some(Host::Fqdn(fqdn!("deno.land")))),
      (
        "1.1.1.1",
        Some(Host::Ip(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)))),
      ),
      (
        "::1",
        Some(Host::Ip(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)))),
      ),
      (
        "[::1]",
        Some(Host::Ip(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)))),
      ),
      ("[::1", None),
      ("::1]", None),
      ("deno. land", None),
      ("1. 1.1.1", None),
      ("1.1.1.1.", None),
      ("1::1.", None),
      ("deno.land.", Some(Host::Fqdn(fqdn!("deno.land")))),
      (".deno.land", None),
      ("*.deno.land", None),
      // IPv4-mapped IPv6 addresses are normalized to IPv4
      (
        "::ffff:1.1.1.1",
        Some(Host::Ip(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)))),
      ),
      (
        "[::ffff:127.0.0.1]",
        Some(Host::Ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)))),
      ),
      // IPv6 addresses with zone indices
      (
        "fe80::1%18",
        Some(Host::Ip(IpAddr::V6(Ipv6Addr::new(
          0xfe80, 0, 0, 0, 0, 0, 0, 1,
        )))),
      ),
      (
        "[fe80::1%18]",
        Some(Host::Ip(IpAddr::V6(Ipv6Addr::new(
          0xfe80, 0, 0, 0, 0, 0, 0, 1,
        )))),
      ),
      (
        "fe80::1%eth0",
        Some(Host::Ip(IpAddr::V6(Ipv6Addr::new(
          0xfe80, 0, 0, 0, 0, 0, 0, 1,
        )))),
      ),
      (
        "[fe80::1%eth0]",
        Some(Host::Ip(IpAddr::V6(Ipv6Addr::new(
          0xfe80, 0, 0, 0, 0, 0, 0, 1,
        )))),
      ),
    ];

    for (host_str, expected) in hosts {
      assert_eq!(
        Host::parse_for_query(host_str).ok(),
        *expected,
        "{host_str}"
      );
    }
  }

  #[test]
  fn test_host_parse_for_list() {
    let hosts = &[
      ("deno.land", Some(Host::Fqdn(fqdn!("deno.land")))),
      (
        "*.deno.land",
        Some(Host::FqdnWithSubdomainWildcard(fqdn!("deno.land"))),
      ),
      ("DENO.land", Some(Host::Fqdn(fqdn!("deno.land")))),
      ("deno.land.", Some(Host::Fqdn(fqdn!("deno.land")))),
      (
        "1.1.1.1",
        Some(Host::Ip(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)))),
      ),
      (
        "::1",
        Some(Host::Ip(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)))),
      ),
      (
        "[::1]",
        Some(Host::Ip(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)))),
      ),
      ("[::1", None),
      ("::1]", None),
      ("deno. land", None),
      ("1. 1.1.1", None),
      ("1.1.1.1.", None),
      ("1::1.", None),
      ("deno.land.", Some(Host::Fqdn(fqdn!("deno.land")))),
      (".deno.land", None),
      // IPv4-mapped IPv6 addresses are normalized to IPv4
      (
        "::ffff:1.1.1.1",
        Some(Host::Ip(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)))),
      ),
      (
        "[::ffff:127.0.0.1]",
        Some(Host::Ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)))),
      ),
      // IPv6 addresses with zone indices
      (
        "fe80::1%18",
        Some(Host::Ip(IpAddr::V6(Ipv6Addr::new(
          0xfe80, 0, 0, 0, 0, 0, 0, 1,
        )))),
      ),
      (
        "[fe80::1%18]",
        Some(Host::Ip(IpAddr::V6(Ipv6Addr::new(
          0xfe80, 0, 0, 0, 0, 0, 0, 1,
        )))),
      ),
      (
        "fe80::1%eth0",
        Some(Host::Ip(IpAddr::V6(Ipv6Addr::new(
          0xfe80, 0, 0, 0, 0, 0, 0, 1,
        )))),
      ),
      (
        "[fe80::1%eth0]",
        Some(Host::Ip(IpAddr::V6(Ipv6Addr::new(
          0xfe80, 0, 0, 0, 0, 0, 0, 1,
        )))),
      ),
    ];

    for (host_str, expected) in hosts {
      assert_eq!(Host::parse_for_list(host_str).ok(), *expected, "{host_str}");
    }
  }

  #[test]
  fn test_net_descriptor_parse_for_query() {
    let cases = &[
      (
        "deno.land",
        Some(NetDescriptor(Host::Fqdn(fqdn!("deno.land")), None)),
      ),
      (
        "DENO.land",
        Some(NetDescriptor(Host::Fqdn(fqdn!("deno.land")), None)),
      ),
      (
        "deno.land:8000",
        Some(NetDescriptor(Host::Fqdn(fqdn!("deno.land")), Some(8000))),
      ),
      ("*.deno.land", None),
      ("deno.land:", None),
      ("deno.land:a", None),
      ("deno. land:a", None),
      ("deno.land.: a", None),
      (
        "1.1.1.1",
        Some(NetDescriptor(
          Host::Ip(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))),
          None,
        )),
      ),
      ("1.1.1.1.", None),
      ("1.1.1.1..", None),
      (
        "1.1.1.1:8000",
        Some(NetDescriptor(
          Host::Ip(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))),
          Some(8000),
        )),
      ),
      ("::", None),
      (":::80", None),
      ("::80", None),
      (
        "[::]",
        Some(NetDescriptor(
          Host::Ip(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0))),
          None,
        )),
      ),
      ("[::1", None),
      ("::1]", None),
      ("::1]", None),
      ("[::1]:", None),
      ("[::1]:a", None),
      (
        "[::1]:443",
        Some(NetDescriptor(
          Host::Ip(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1))),
          Some(443),
        )),
      ),
      ("", None),
      ("deno.land..", None),
      // IPv6 addresses with zone indices (bracketed with port)
      (
        "[fe80::1%18]:1234",
        Some(NetDescriptor(
          Host::Ip(IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1))),
          Some(1234),
        )),
      ),
      (
        "[fe80::1%eth0]:8080",
        Some(NetDescriptor(
          Host::Ip(IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1))),
          Some(8080),
        )),
      ),
    ];

    for (input, expected) in cases {
      assert_eq!(
        NetDescriptor::parse_for_query(input).ok(),
        *expected,
        "'{input}'"
      );
    }
  }

  #[test]
  fn test_net_descriptor_parse_for_list() {
    let cases = &[
      (
        "deno.land",
        Some(NetDescriptor(Host::Fqdn(fqdn!("deno.land")), None)),
      ),
      (
        "DENO.land",
        Some(NetDescriptor(Host::Fqdn(fqdn!("deno.land")), None)),
      ),
      (
        "deno.land:8000",
        Some(NetDescriptor(Host::Fqdn(fqdn!("deno.land")), Some(8000))),
      ),
      (
        "*.deno.land",
        Some(NetDescriptor(
          Host::FqdnWithSubdomainWildcard(fqdn!("deno.land")),
          None,
        )),
      ),
      ("deno.land:", None),
      ("deno.land:a", None),
      ("deno. land:a", None),
      ("deno.land.: a", None),
      (
        "1.1.1.1",
        Some(NetDescriptor(
          Host::Ip(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))),
          None,
        )),
      ),
      ("1.1.1.1.", None),
      ("1.1.1.1..", None),
      (
        "1.1.1.1:8000",
        Some(NetDescriptor(
          Host::Ip(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))),
          Some(8000),
        )),
      ),
      ("::", None),
      (":::80", None),
      ("::80", None),
      (
        "[::]",
        Some(NetDescriptor(
          Host::Ip(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0))),
          None,
        )),
      ),
      ("[::1", None),
      ("::1]", None),
      ("::1]", None),
      ("[::1]:", None),
      ("[::1]:a", None),
      (
        "[::1]:443",
        Some(NetDescriptor(
          Host::Ip(IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1))),
          Some(443),
        )),
      ),
      ("", None),
      ("deno.land..", None),
      // IPv6 addresses with zone indices (bracketed with port)
      (
        "[fe80::1%18]:1234",
        Some(NetDescriptor(
          Host::Ip(IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1))),
          Some(1234),
        )),
      ),
      (
        "[fe80::1%eth0]:8080",
        Some(NetDescriptor(
          Host::Ip(IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1))),
          Some(8080),
        )),
      ),
      // Unix socket rules are lexically normalized at parse time (`.`/`..`
      // removed, symlinks not resolved) to match the call-side path, which
      // goes through the same normalization in `check_open`.
      #[cfg(unix)]
      (
        "unix:/var/run/docker.sock",
        Some(NetDescriptor(
          Host::UnixSocket(PathBuf::from("/var/run/docker.sock")),
          None,
        )),
      ),
      #[cfg(unix)]
      (
        "unix:/var/run/../run/./docker.sock",
        Some(NetDescriptor(
          Host::UnixSocket(PathBuf::from("/var/run/docker.sock")),
          None,
        )),
      ),
      ("unix:", None),
      ("unix:relative.sock", None),
    ];

    for (input, expected) in cases {
      assert_eq!(
        NetDescriptor::parse_for_list(input).ok(),
        *expected,
        "'{input}'"
      );
    }
  }

  #[test]
  fn test_denies_run_name() {
    let cases = [
      #[cfg(windows)]
      ("deno", "C:\\deno.exe", true),
      #[cfg(windows)]
      ("deno", "C:\\sub\\deno.cmd", true),
      #[cfg(windows)]
      ("deno", "C:\\sub\\DeNO.cmd", true),
      #[cfg(windows)]
      ("DEno", "C:\\sub\\deno.cmd", true),
      #[cfg(windows)]
      ("deno", "C:\\other\\sub\\deno.batch", true),
      #[cfg(windows)]
      ("deno", "C:\\other\\sub\\deno", true),
      #[cfg(windows)]
      ("denort", "C:\\other\\sub\\deno.exe", false),
      ("deno", "/home/test/deno", true),
      ("deno", "/home/test/denot", false),
    ];
    for (name, cmd_path, denies) in cases {
      assert_eq!(
        denies_run_name(name, Path::new(cmd_path)),
        denies,
        "{} {}",
        name,
        cmd_path
      );
    }
  }

  #[test]
  fn test_env_check_all() {
    set_prompter(Box::new(TestPrompter));
    let parser = TestPermissionDescriptorParser;
    let mut perms = Permissions::from_options(
      &parser,
      &PermissionsOptions {
        allow_env: Some(vec![]),
        deny_env: Some(svec!["FOO"]),
        ..Default::default()
      },
    )
    .unwrap();

    assert!(perms.env.check_all().is_err());
  }

  #[test]
  fn test_env_sorting() {
    let mut items = vec![
      EnvDescriptor::new("TEST".into()),
      EnvDescriptor::new("TEST*".into()),
      EnvDescriptor::new("TEST2*".into()),
      EnvDescriptor::new("TEST_TEST".into()),
    ];
    items.sort_by(|a, b| a.cmp_allow(b));
    assert_eq!(
      items
        .into_iter()
        .map(|i| match i {
          EnvDescriptor::Name(name) => name.inner,
          EnvDescriptor::PrefixPattern(name) => format!("{}*", name.inner),
        })
        .collect::<Vec<_>>(),
      vec![
        "TEST".to_string(),
        "TEST_TEST".to_string(),
        "TEST2*".to_string(),
        "TEST*".to_string(),
      ]
    )
  }

  #[test]
  fn test_format_display_name() {
    assert_eq!(format_display_name(Cow::Borrowed("123")), "\"123\"");
    assert_eq!(format_display_name(Cow::Borrowed("<other>")), "<other>");
  }

  #[test]
  fn test_path_ordering_multiple_allows_and_denies() {
    let parser = TestPermissionDescriptorParser;
    let read_query = |path: &str| {
      parser
        .parse_path_query(Cow::Owned(PathBuf::from(path)))
        .unwrap()
        .into_read()
    };

    // Test multiple overlapping allows and denies
    let perms = Permissions::from_options(
      &parser,
      &PermissionsOptions {
        allow_read: Some(svec!["/foo/bar/baz", "/foo/qux"]),
        deny_read: Some(svec!["/foo/bar", "/foo"]),
        ..Default::default()
      },
    )
    .unwrap();

    // Most specific allow wins over less specific denies
    assert_eq!(
      perms.read.query(Some(&read_query("/foo/bar/baz"))),
      PermissionState::Granted
    );
    assert_eq!(
      perms.read.query(Some(&read_query("/foo/bar/baz/file.txt"))),
      PermissionState::Granted
    );

    // Deny /foo/bar blocks this
    assert_eq!(
      perms.read.query(Some(&read_query("/foo/bar"))),
      PermissionState::Denied
    );
    assert_eq!(
      perms.read.query(Some(&read_query("/foo/bar/other"))),
      PermissionState::Denied
    );

    // Allow /foo/qux works despite deny /foo
    assert_eq!(
      perms.read.query(Some(&read_query("/foo/qux"))),
      PermissionState::Granted
    );
    assert_eq!(
      perms.read.query(Some(&read_query("/foo/qux/file.txt"))),
      PermissionState::Granted
    );

    // Deny /foo blocks everything else under /foo
    assert_eq!(
      perms.read.query(Some(&read_query("/foo"))),
      PermissionState::Denied
    );
    assert_eq!(
      perms.read.query(Some(&read_query("/foo/other"))),
      PermissionState::Denied
    );

    // Unrelated path is prompt
    assert_eq!(
      perms.read.query(Some(&read_query("/bar"))),
      PermissionState::Prompt
    );
  }

  #[test]
  fn test_env_ordering_multiple_patterns() {
    // Test multiple overlapping env patterns
    let mut perms = Permissions::none_without_prompt();
    perms.env = UnaryPermission {
      granted_global: false,
      ..Permissions::new_unary(
        Some(Vec::from([
          EnvDescriptor::new(Cow::Borrowed("NODE_ENV")),
          EnvDescriptor::new(Cow::Borrowed("NODE_DEBUG_*")),
          EnvDescriptor::new(Cow::Borrowed("DENO_*")),
        ])),
        Some(Vec::from([
          EnvDescriptor::new(Cow::Borrowed("NODE_*")),
          EnvDescriptor::new(Cow::Borrowed("DENO_SECRET")),
        ])),
        true,
      )
    };

    // Exact match NODE_ENV beats pattern NODE_*
    assert_eq!(perms.env.query(Some("NODE_ENV")), PermissionState::Granted);

    // More specific pattern NODE_DEBUG_* beats less specific NODE_*
    assert_eq!(
      perms.env.query(Some("NODE_DEBUG_NATIVE")),
      PermissionState::Granted
    );

    // NODE_* deny blocks other NODE_ vars
    assert_eq!(perms.env.query(Some("NODE_PATH")), PermissionState::Denied);
    assert_eq!(
      perms.env.query(Some("NODE_OPTIONS")),
      PermissionState::Denied
    );

    // DENO_* allow works for most vars
    assert_eq!(perms.env.query(Some("DENO_DIR")), PermissionState::Granted);

    // But DENO_SECRET exact deny overrides DENO_* allow
    assert_eq!(
      perms.env.query(Some("DENO_SECRET")),
      PermissionState::Denied
    );

    assert_eq!(perms.env.query(Some("PATH")), PermissionState::Prompt);
  }

  #[test]
  fn test_env_ordering_nested_patterns() {
    // Test increasingly specific patterns
    let mut perms = Permissions::none_without_prompt();
    perms.env = UnaryPermission {
      granted_global: false,
      ..Permissions::new_unary(
        Some(Vec::from([
          EnvDescriptor::new(Cow::Borrowed("PREFIX_SUBPREFIX_ALLOWED*")),
          EnvDescriptor::new(Cow::Borrowed("PREFIX_ALLOWED*")),
        ])),
        Some(Vec::from([
          EnvDescriptor::new(Cow::Borrowed("PREFIX_SUBPREFIX*")),
          EnvDescriptor::new(Cow::Borrowed("PREFIX*")),
        ])),
        false,
      )
    };

    // Most specific allow pattern wins
    assert_eq!(
      perms.env.query(Some("PREFIX_SUBPREFIX_ALLOWED_VAR")),
      PermissionState::Granted
    );

    // Less specific deny blocks this
    assert_eq!(
      perms.env.query(Some("PREFIX_SUBPREFIX_OTHER")),
      PermissionState::Denied
    );

    // Medium specific allow wins
    assert_eq!(
      perms.env.query(Some("PREFIX_ALLOWED_VAR")),
      PermissionState::Granted
    );

    // Least specific deny blocks everything else
    assert_eq!(
      perms.env.query(Some("PREFIX_OTHER")),
      PermissionState::Denied
    );
  }

  #[test]
  fn test_net_ordering_with_ports() {
    let parser = TestPermissionDescriptorParser;

    // Test that host:port combinations are properly ordered
    let perms = Permissions::from_options(
      &parser,
      &PermissionsOptions {
        allow_net: Some(svec!["example.com:8080", "example.com:443"]),
        deny_net: Some(svec!["example.com"]),
        ..Default::default()
      },
    )
    .unwrap();

    assert_eq!(
      perms.net.query(Some(&NetDescriptor(
        Host::must_parse("example.com"),
        Some(8080)
      ))),
      PermissionState::Granted
    );
    assert_eq!(
      perms.net.query(Some(&NetDescriptor(
        Host::must_parse("example.com"),
        Some(443)
      ))),
      PermissionState::Granted
    );
    assert_eq!(
      perms.net.query(Some(&NetDescriptor(
        Host::must_parse("example.com"),
        Some(20)
      ))),
      PermissionState::Denied
    );
    assert_eq!(
      perms
        .net
        .query(Some(&NetDescriptor(Host::must_parse("example.com"), None))),
      PermissionState::Denied
    );
  }

  #[test]
  fn test_path_ordering_same_specificity() {
    let parser = TestPermissionDescriptorParser;
    let read_query = |path: &str| {
      parser
        .parse_path_query(Cow::Owned(PathBuf::from(path)))
        .unwrap()
        .into_read()
    };

    // When allow and deny have the same path, deny should win
    let perms = Permissions::from_options(
      &parser,
      &PermissionsOptions {
        allow_read: Some(svec!["/foo/bar"]),
        deny_read: Some(svec!["/foo/bar"]),
        ..Default::default()
      },
    )
    .unwrap();

    // Deny should take precedence when specificity is equal
    assert_eq!(
      perms.read.query(Some(&read_query("/foo/bar"))),
      PermissionState::Denied
    );
    assert_eq!(
      perms.read.query(Some(&read_query("/foo/bar/file.txt"))),
      PermissionState::Denied
    );
  }

  #[test]
  fn test_env_ordering_same_specificity() {
    // When allow and deny have the same env var, deny should win
    let mut perms = Permissions::none_without_prompt();
    perms.env = UnaryPermission {
      granted_global: false,
      ..Permissions::new_unary(
        Some(Vec::from([EnvDescriptor::new(Cow::Borrowed("TEST_VAR"))])),
        Some(Vec::from([EnvDescriptor::new(Cow::Borrowed("TEST_VAR"))])),
        false,
      )
    };

    // Deny should take precedence
    assert_eq!(perms.env.query(Some("TEST_VAR")), PermissionState::Denied);
  }

  #[test]
  fn test_env_ordering_pattern_same_specificity() {
    // When allow and deny have the same pattern, deny should win
    let mut perms = Permissions::none_without_prompt();
    perms.env = UnaryPermission {
      granted_global: false,
      ..Permissions::new_unary(
        Some(Vec::from([EnvDescriptor::new(Cow::Borrowed("TEST_*"))])),
        Some(Vec::from([EnvDescriptor::new(Cow::Borrowed("TEST_*"))])),
        false,
      )
    };

    // Deny should take precedence
    assert_eq!(perms.env.query(Some("TEST_VAR")), PermissionState::Denied);
    assert_eq!(
      perms.env.query(Some("TEST_ANOTHER")),
      PermissionState::Denied
    );
  }

  #[test]
  fn test_path_ordering_sibling_directories() {
    let parser = TestPermissionDescriptorParser;
    let read_query = |path: &str| {
      parser
        .parse_path_query(Cow::Owned(PathBuf::from(path)))
        .unwrap()
        .into_read()
    };

    // Test sibling directories (unrelated paths)
    let perms = Permissions::from_options(
      &parser,
      &PermissionsOptions {
        allow_read: Some(svec!["/foo/a"]),
        deny_read: Some(svec!["/foo/b"]),
        ..Default::default()
      },
    )
    .unwrap();

    assert_eq!(
      perms.read.query(Some(&read_query("/foo/a"))),
      PermissionState::Granted
    );
    assert_eq!(
      perms.read.query(Some(&read_query("/foo/a/file.txt"))),
      PermissionState::Granted
    );
    assert_eq!(
      perms.read.query(Some(&read_query("/foo/b"))),
      PermissionState::Denied
    );
    assert_eq!(
      perms.read.query(Some(&read_query("/foo/b/file.txt"))),
      PermissionState::Denied
    );
    assert_eq!(
      perms.read.query(Some(&read_query("/foo/c"))),
      PermissionState::Prompt
    );
  }

  #[test]
  fn test_write_ordering_deep_nesting() {
    let parser = TestPermissionDescriptorParser;
    let write_query = |path: &str| {
      parser
        .parse_path_query(Cow::Owned(PathBuf::from(path)))
        .unwrap()
        .into_write()
    };

    // Test deeply nested paths with multiple levels
    let perms = Permissions::from_options(
      &parser,
      &PermissionsOptions {
        allow_write: Some(svec!["/a/b/c/d/e/f"]),
        deny_write: Some(svec!["/a/b/c", "/a/b/c/d/e"]),
        ..Default::default()
      },
    )
    .unwrap();

    // Most specific allow wins
    assert_eq!(
      perms.write.query(Some(&write_query("/a/b/c/d/e/f"))),
      PermissionState::Granted
    );
    assert_eq!(
      perms.write.query(Some(&write_query("/a/b/c/d/e/f/g"))),
      PermissionState::Granted
    );

    // Deny at /a/b/c/d/e blocks this level
    assert_eq!(
      perms.write.query(Some(&write_query("/a/b/c/d/e"))),
      PermissionState::Denied
    );
    assert_eq!(
      perms.write.query(Some(&write_query("/a/b/c/d/e/other"))),
      PermissionState::Denied
    );

    // Deny at /a/b/c blocks broader access
    assert_eq!(
      perms.write.query(Some(&write_query("/a/b/c"))),
      PermissionState::Denied
    );
    assert_eq!(
      perms.write.query(Some(&write_query("/a/b/c/d"))),
      PermissionState::Denied
    );

    // Parent paths are prompt
    assert_eq!(
      perms.write.query(Some(&write_query("/a/b"))),
      PermissionState::Prompt
    );
  }

  #[test]
  fn test_ffi_ordering_similar_paths() {
    let parser = TestPermissionDescriptorParser;
    let ffi_query = |path: &str| {
      parser
        .parse_path_query(Cow::Owned(PathBuf::from(path)))
        .unwrap()
        .into_ffi()
    };

    // Test paths that share common prefixes but aren't ancestors
    let perms = Permissions::from_options(
      &parser,
      &PermissionsOptions {
        allow_ffi: Some(svec!["/usr/lib/custom", "/usr/lib64"]),
        deny_ffi: Some(svec!["/usr/lib"]),
        ..Default::default()
      },
    )
    .unwrap();

    // Allow should work for specific paths
    assert_eq!(
      perms.ffi.query(Some(&ffi_query("/usr/lib/custom"))),
      PermissionState::Granted
    );
    assert_eq!(
      perms
        .ffi
        .query(Some(&ffi_query("/usr/lib/custom/mylib.so"))),
      PermissionState::Granted
    );

    // /usr/lib64 is not under /usr/lib, so should be prompt (not denied)
    assert_eq!(
      perms.ffi.query(Some(&ffi_query("/usr/lib64"))),
      PermissionState::Granted
    );

    // Deny blocks /usr/lib
    assert_eq!(
      perms.ffi.query(Some(&ffi_query("/usr/lib"))),
      PermissionState::Denied
    );
    assert_eq!(
      perms.ffi.query(Some(&ffi_query("/usr/lib/other.so"))),
      PermissionState::Denied
    );
  }

  #[test]
  fn test_env_ordering_empty_prefix_pattern() {
    // Test edge case: what if someone tries a pattern that matches everything?
    let mut perms = Permissions::none_without_prompt();
    perms.env = UnaryPermission {
      granted_global: false,
      ..Permissions::new_unary(
        Some(Vec::from([EnvDescriptor::new(Cow::Borrowed(
          "ALLOWED_VAR",
        ))])),
        Some(Vec::from([EnvDescriptor::new(Cow::Borrowed("ALLOWED_*"))])),
        false,
      )
    };

    // Exact name ALLOWED_VAR should win over pattern ALLOWED_*
    assert_eq!(
      perms.env.query(Some("ALLOWED_VAR")),
      PermissionState::Granted
    );

    // Pattern ALLOWED_* should deny others
    assert_eq!(
      perms.env.query(Some("ALLOWED_OTHER")),
      PermissionState::Denied
    );
  }

  #[test]
  fn test_cmp_read_descriptors() {
    let parser = TestPermissionDescriptorParser;
    let parse_granted = |text: &str| {
      UnaryPermissionDesc::Granted(parser.parse_read_descriptor(text).unwrap())
    };
    let parse_flag_denied = |text: &str| {
      UnaryPermissionDesc::FlagDenied::<ReadDescriptor>(
        parser.parse_read_descriptor(text).unwrap(),
      )
    };
    let parse_prompt_denied = |text: &str| {
      UnaryPermissionDesc::PromptDenied::<ReadDescriptor>(
        parser.parse_read_descriptor(text).unwrap(),
      )
    };

    // Test path hierarchy: child < parent for granted
    check_comparison(
      &parse_granted("/foo/bar"),
      &parse_granted("/foo"),
      Ordering::Less,
    );
    check_comparison(
      &parse_granted("/foo/bar/baz"),
      &parse_granted("/foo/bar"),
      Ordering::Less,
    );
    check_comparison(
      &parse_granted("/a/b/c/d"),
      &parse_granted("/a"),
      Ordering::Less,
    );

    // Test path hierarchy: child < parent for flag denied
    check_comparison(
      &parse_flag_denied("/foo/bar"),
      &parse_flag_denied("/foo"),
      Ordering::Less,
    );
    check_comparison(
      &parse_flag_denied("/foo/bar/baz"),
      &parse_flag_denied("/foo/bar"),
      Ordering::Less,
    );

    // Test path hierarchy: child < parent for prompt denied
    check_comparison(
      &parse_prompt_denied("/foo/bar"),
      &parse_prompt_denied("/foo"),
      Ordering::Less,
    );
    check_comparison(
      &parse_prompt_denied("/foo/bar/baz"),
      &parse_prompt_denied("/foo/bar"),
      Ordering::Less,
    );

    // Test equal paths with same type
    check_comparison(
      &parse_granted("/foo/bar"),
      &parse_granted("/foo/bar"),
      Ordering::Equal,
    );
    check_comparison(
      &parse_flag_denied("/foo/bar"),
      &parse_flag_denied("/foo/bar"),
      Ordering::Equal,
    );
    check_comparison(
      &parse_prompt_denied("/foo/bar"),
      &parse_prompt_denied("/foo/bar"),
      Ordering::Equal,
    );

    // Test unrelated paths (lexicographic ordering)
    check_comparison(
      &parse_granted("/aaa"),
      &parse_granted("/bbb"),
      Ordering::Less,
    );
    check_comparison(
      &parse_granted("/xyz"),
      &parse_granted("/abc"),
      Ordering::Greater,
    );
    check_comparison(
      &parse_flag_denied("/aaa"),
      &parse_flag_denied("/zzz"),
      Ordering::Less,
    );

    // Test different types with same path
    // FlagDenied < PromptDenied < Granted (by kind_precedence)
    check_comparison(
      &parse_flag_denied("/foo"),
      &parse_granted("/foo"),
      Ordering::Less,
    );
    check_comparison(
      &parse_prompt_denied("/foo"),
      &parse_granted("/foo"),
      Ordering::Less,
    );
    check_comparison(
      &parse_flag_denied("/foo"),
      &parse_prompt_denied("/foo"),
      Ordering::Less,
    );

    // Test different types with parent/child relationship
    check_comparison(
      &parse_granted("/foo/bar"),
      &parse_flag_denied("/foo"),
      Ordering::Less,
    );
    check_comparison(
      &parse_granted("/foo"),
      &parse_flag_denied("/foo/bar"),
      Ordering::Greater,
    );
    check_comparison(
      &parse_prompt_denied("/foo/bar"),
      &parse_granted("/foo"),
      Ordering::Less,
    );

    // Test root vs subdirectories
    check_comparison(
      &parse_granted("/"),
      &parse_granted("/foo"),
      Ordering::Greater,
    );
    check_comparison(
      &parse_flag_denied("/"),
      &parse_flag_denied("/foo"),
      Ordering::Greater,
    );

    // Test deeply nested paths
    check_comparison(
      &parse_granted("/a/b/c/d/e/f"),
      &parse_granted("/a/b/c"),
      Ordering::Less,
    );
    check_comparison(
      &parse_granted("/a/b/c"),
      &parse_granted("/a/b/d"),
      Ordering::Less,
    );

    // Test paths with similar prefixes but different branches
    check_comparison(
      &parse_granted("/foo/bar"),
      &parse_granted("/foo/baz"),
      Ordering::Less,
    );
    check_comparison(
      &parse_granted("/prefix123"),
      &parse_granted("/prefix456"),
      Ordering::Less,
    );

    // Test two deny types with different descriptors (non-equal paths)
    check_comparison(
      &parse_flag_denied("/aaa"),
      &parse_prompt_denied("/bbb"),
      Ordering::Less,
    );
    check_comparison(
      &parse_flag_denied("/xyz"),
      &parse_prompt_denied("/abc"),
      Ordering::Greater,
    );
    check_comparison(
      &parse_prompt_denied("/foo/bar"),
      &parse_flag_denied("/foo/baz"),
      Ordering::Less,
    );

    // Test transitivity: FlagDenied < PromptDenied < Granted with same path
    check_comparison(
      &parse_flag_denied("/test"),
      &parse_prompt_denied("/test"),
      Ordering::Less,
    );
    check_comparison(
      &parse_prompt_denied("/test"),
      &parse_granted("/test"),
      Ordering::Less,
    );
    // Transitive: FlagDenied < Granted
    check_comparison(
      &parse_flag_denied("/test"),
      &parse_granted("/test"),
      Ordering::Less,
    );

    // Test mixed types with sibling paths
    check_comparison(
      &parse_granted("/foo/bar"),
      &parse_prompt_denied("/foo/baz"),
      Ordering::Greater,
    );
    check_comparison(
      &parse_flag_denied("/foo/aaa"),
      &parse_granted("/foo/zzz"),
      Ordering::Less,
    );

    // Test PromptDenied(child) vs FlagDenied(parent)
    check_comparison(
      &parse_prompt_denied("/foo/bar/baz"),
      &parse_flag_denied("/foo"),
      Ordering::Less,
    );
    check_comparison(
      &parse_prompt_denied("/a/b/c"),
      &parse_flag_denied("/a/b"),
      Ordering::Less,
    );
  }

  #[test]
  fn test_cmp_write_descriptors() {
    let parser = TestPermissionDescriptorParser;
    let parse_granted = |text: &str| {
      UnaryPermissionDesc::Granted(parser.parse_write_descriptor(text).unwrap())
    };
    let parse_flag_denied = |text: &str| {
      UnaryPermissionDesc::FlagDenied::<WriteDescriptor>(
        parser.parse_write_descriptor(text).unwrap(),
      )
    };
    let parse_prompt_denied = |text: &str| {
      UnaryPermissionDesc::PromptDenied::<WriteDescriptor>(
        parser.parse_write_descriptor(text).unwrap(),
      )
    };

    // Test path hierarchy: child < parent for granted
    check_comparison(
      &parse_granted("/foo/bar"),
      &parse_granted("/foo"),
      Ordering::Less,
    );
    check_comparison(
      &parse_granted("/foo/bar/baz"),
      &parse_granted("/foo/bar"),
      Ordering::Less,
    );
    check_comparison(
      &parse_granted("/a/b/c/d"),
      &parse_granted("/a"),
      Ordering::Less,
    );

    // Test path hierarchy: child < parent for flag denied
    check_comparison(
      &parse_flag_denied("/foo/bar"),
      &parse_flag_denied("/foo"),
      Ordering::Less,
    );
    check_comparison(
      &parse_flag_denied("/foo/bar/baz"),
      &parse_flag_denied("/foo/bar"),
      Ordering::Less,
    );

    // Test path hierarchy: child < parent for prompt denied
    check_comparison(
      &parse_prompt_denied("/foo/bar"),
      &parse_prompt_denied("/foo"),
      Ordering::Less,
    );
    check_comparison(
      &parse_prompt_denied("/foo/bar/baz"),
      &parse_prompt_denied("/foo/bar"),
      Ordering::Less,
    );

    // Test equal paths with same type
    check_comparison(
      &parse_granted("/foo/bar"),
      &parse_granted("/foo/bar"),
      Ordering::Equal,
    );
    check_comparison(
      &parse_flag_denied("/foo/bar"),
      &parse_flag_denied("/foo/bar"),
      Ordering::Equal,
    );
    check_comparison(
      &parse_prompt_denied("/foo/bar"),
      &parse_prompt_denied("/foo/bar"),
      Ordering::Equal,
    );

    // Test unrelated paths (lexicographic ordering)
    check_comparison(
      &parse_granted("/aaa"),
      &parse_granted("/bbb"),
      Ordering::Less,
    );
    check_comparison(
      &parse_granted("/xyz"),
      &parse_granted("/abc"),
      Ordering::Greater,
    );
    check_comparison(
      &parse_flag_denied("/aaa"),
      &parse_flag_denied("/zzz"),
      Ordering::Less,
    );

    // Test different types with same path
    // FlagDenied < PromptDenied < Granted (by kind_precedence)
    check_comparison(
      &parse_flag_denied("/foo"),
      &parse_granted("/foo"),
      Ordering::Less,
    );
    check_comparison(
      &parse_prompt_denied("/foo"),
      &parse_granted("/foo"),
      Ordering::Less,
    );
    check_comparison(
      &parse_flag_denied("/foo"),
      &parse_prompt_denied("/foo"),
      Ordering::Less,
    );

    // Test different types with parent/child relationship
    check_comparison(
      &parse_granted("/foo/bar"),
      &parse_flag_denied("/foo"),
      Ordering::Less,
    );
    check_comparison(
      &parse_granted("/foo"),
      &parse_flag_denied("/foo/bar"),
      Ordering::Greater,
    );
    check_comparison(
      &parse_prompt_denied("/foo/bar"),
      &parse_granted("/foo"),
      Ordering::Less,
    );

    // Test root vs subdirectories
    check_comparison(
      &parse_granted("/"),
      &parse_granted("/foo"),
      Ordering::Greater,
    );
    check_comparison(
      &parse_flag_denied("/"),
      &parse_flag_denied("/foo"),
      Ordering::Greater,
    );

    // Test deeply nested paths
    check_comparison(
      &parse_granted("/a/b/c/d/e/f"),
      &parse_granted("/a/b/c"),
      Ordering::Less,
    );
    check_comparison(
      &parse_granted("/a/b/c"),
      &parse_granted("/a/b/d"),
      Ordering::Less,
    );

    // Test paths with similar prefixes but different branches
    check_comparison(
      &parse_granted("/foo/bar"),
      &parse_granted("/foo/baz"),
      Ordering::Less,
    );
    check_comparison(
      &parse_granted("/prefix123"),
      &parse_granted("/prefix456"),
      Ordering::Less,
    );

    // Test two deny types with different descriptors
    check_comparison(
      &parse_flag_denied("/aaa"),
      &parse_prompt_denied("/bbb"),
      Ordering::Less,
    );
    check_comparison(
      &parse_prompt_denied("/foo/bar"),
      &parse_flag_denied("/foo/baz"),
      Ordering::Less,
    );

    // Test PromptDenied(child) vs FlagDenied(parent)
    check_comparison(
      &parse_prompt_denied("/foo/bar/baz"),
      &parse_flag_denied("/foo"),
      Ordering::Less,
    );
  }

  #[test]
  fn test_cmp_net_descriptors() {
    let parser = TestPermissionDescriptorParser;
    let parse_granted = |text: &str| {
      UnaryPermissionDesc::Granted(parser.parse_net_descriptor(text).unwrap())
    };
    let parse_flag_denied = |text: &str| {
      UnaryPermissionDesc::FlagDenied::<NetDescriptor>(
        parser.parse_net_descriptor(text).unwrap(),
      )
    };
    let parse_prompt_denied = |text: &str| {
      UnaryPermissionDesc::PromptDenied::<NetDescriptor>(
        parser.parse_net_descriptor(text).unwrap(),
      )
    };

    // Test host hierarchy: more specific < less specific for granted
    check_comparison(
      &parse_granted("example.com:8080"),
      &parse_granted("example.com"),
      Ordering::Less,
    );
    check_comparison(
      &parse_granted("sub.example.com"),
      &parse_granted("example.com"),
      Ordering::Less,
    );

    // Test host hierarchy: more specific < less specific for flag denied
    check_comparison(
      &parse_flag_denied("example.com:8080"),
      &parse_flag_denied("example.com"),
      Ordering::Less,
    );
    check_comparison(
      &parse_flag_denied("sub.example.com"),
      &parse_flag_denied("example.com"),
      Ordering::Less,
    );

    // Test host hierarchy: more specific < less specific for prompt denied
    check_comparison(
      &parse_prompt_denied("example.com:8080"),
      &parse_prompt_denied("example.com"),
      Ordering::Less,
    );
    check_comparison(
      &parse_prompt_denied("sub.example.com"),
      &parse_prompt_denied("example.com"),
      Ordering::Less,
    );

    // Test equal descriptors with same type
    check_comparison(
      &parse_granted("example.com:8080"),
      &parse_granted("example.com:8080"),
      Ordering::Equal,
    );
    check_comparison(
      &parse_flag_denied("example.com"),
      &parse_flag_denied("example.com"),
      Ordering::Equal,
    );
    check_comparison(
      &parse_prompt_denied("example.com:443"),
      &parse_prompt_denied("example.com:443"),
      Ordering::Equal,
    );

    // Test unrelated hosts (lexicographic ordering)
    check_comparison(
      &parse_granted("aaa.com"),
      &parse_granted("bbb.com"),
      Ordering::Less,
    );
    check_comparison(
      &parse_granted("xyz.org"),
      &parse_granted("abc.org"),
      Ordering::Greater,
    );
    check_comparison(
      &parse_flag_denied("aaa.com"),
      &parse_flag_denied("zzz.com"),
      Ordering::Less,
    );

    // Test different types with same descriptor
    // FlagDenied < PromptDenied < Granted (by kind_precedence)
    check_comparison(
      &parse_flag_denied("example.com"),
      &parse_granted("example.com"),
      Ordering::Less,
    );
    check_comparison(
      &parse_prompt_denied("example.com"),
      &parse_granted("example.com"),
      Ordering::Less,
    );
    check_comparison(
      &parse_flag_denied("example.com"),
      &parse_prompt_denied("example.com"),
      Ordering::Less,
    );

    // Test different types with hierarchy relationship
    check_comparison(
      &parse_granted("example.com:8080"),
      &parse_flag_denied("example.com"),
      Ordering::Less,
    );
    check_comparison(
      &parse_granted("example.com"),
      &parse_flag_denied("example.com:8080"),
      Ordering::Greater,
    );
    check_comparison(
      &parse_prompt_denied("example.com:8080"),
      &parse_granted("example.com"),
      Ordering::Less,
    );

    // Test port variations
    check_comparison(
      &parse_granted("example.com:80"),
      &parse_granted("example.com:443"),
      Ordering::Less,
    );
    check_comparison(
      &parse_granted("example.com:9000"),
      &parse_granted("example.com:8080"),
      Ordering::Greater,
    );

    // Test IP addresses
    check_comparison(
      &parse_granted("127.0.0.1:8080"),
      &parse_granted("127.0.0.1"),
      Ordering::Less,
    );
    check_comparison(
      &parse_granted("192.168.1.1"),
      &parse_granted("10.0.0.1"),
      Ordering::Greater,
    );

    // Test IPv6 addresses
    check_comparison(
      &parse_granted("[::1]:8080"),
      &parse_granted("[::1]"),
      Ordering::Less,
    );
    check_comparison(
      &parse_granted("[2001:db8::1]"),
      &parse_granted("[::1]"),
      Ordering::Greater,
    );

    // Test two deny types with different hosts
    check_comparison(
      &parse_flag_denied("aaa.com"),
      &parse_prompt_denied("bbb.com"),
      Ordering::Less,
    );
    check_comparison(
      &parse_prompt_denied("example.com:8080"),
      &parse_flag_denied("example.com:9000"),
      Ordering::Less,
    );

    // Test PromptDenied(specific) vs FlagDenied(general)
    check_comparison(
      &parse_prompt_denied("sub.example.com"),
      &parse_flag_denied("example.com"),
      Ordering::Less,
    );
  }

  #[test]
  fn test_cmp_env_descriptors() {
    let parser = TestPermissionDescriptorParser;
    let parse_granted = |text: &str| {
      UnaryPermissionDesc::Granted(parser.parse_env_descriptor(text).unwrap())
    };
    let parse_flag_denied = |text: &str| {
      UnaryPermissionDesc::FlagDenied::<EnvDescriptor>(
        parser.parse_env_descriptor(text).unwrap(),
      )
    };
    let parse_prompt_denied = |text: &str| {
      UnaryPermissionDesc::PromptDenied::<EnvDescriptor>(
        parser.parse_env_descriptor(text).unwrap(),
      )
    };

    // Test variable name ordering for granted
    check_comparison(
      &parse_granted("AAA"),
      &parse_granted("BBB"),
      Ordering::Less,
    );
    check_comparison(
      &parse_granted("XYZ"),
      &parse_granted("ABC"),
      Ordering::Greater,
    );

    // Test variable name ordering for flag denied
    check_comparison(
      &parse_flag_denied("HOME"),
      &parse_flag_denied("PATH"),
      Ordering::Less,
    );
    check_comparison(
      &parse_flag_denied("ZZZ"),
      &parse_flag_denied("AAA"),
      Ordering::Greater,
    );

    // Test variable name ordering for prompt denied
    check_comparison(
      &parse_prompt_denied("FOO"),
      &parse_prompt_denied("BAR"),
      Ordering::Greater,
    );
    check_comparison(
      &parse_prompt_denied("TEST_VAR"),
      &parse_prompt_denied("TEST_VAR2"),
      Ordering::Less,
    );

    // Test equal descriptors with same type
    check_comparison(
      &parse_granted("PATH"),
      &parse_granted("PATH"),
      Ordering::Equal,
    );
    check_comparison(
      &parse_flag_denied("HOME"),
      &parse_flag_denied("HOME"),
      Ordering::Equal,
    );
    check_comparison(
      &parse_prompt_denied("USER"),
      &parse_prompt_denied("USER"),
      Ordering::Equal,
    );

    // Test different types with same variable
    // FlagDenied < PromptDenied < Granted (by kind_precedence)
    check_comparison(
      &parse_flag_denied("PATH"),
      &parse_granted("PATH"),
      Ordering::Less,
    );
    check_comparison(
      &parse_prompt_denied("PATH"),
      &parse_granted("PATH"),
      Ordering::Less,
    );
    check_comparison(
      &parse_flag_denied("PATH"),
      &parse_prompt_denied("PATH"),
      Ordering::Less,
    );

    // Test different types with different variables
    check_comparison(
      &parse_granted("AAA"),
      &parse_flag_denied("BBB"),
      Ordering::Less,
    );
    check_comparison(
      &parse_flag_denied("AAA"),
      &parse_granted("BBB"),
      Ordering::Less,
    );
    check_comparison(
      &parse_prompt_denied("XXX"),
      &parse_granted("AAA"),
      Ordering::Greater,
    );

    // Test common environment variables
    check_comparison(
      &parse_granted("HOME"),
      &parse_granted("PATH"),
      Ordering::Less,
    );
    check_comparison(
      &parse_granted("USER"),
      &parse_granted("HOME"),
      Ordering::Greater,
    );

    // Test two deny types with different variables
    check_comparison(
      &parse_flag_denied("AAA"),
      &parse_prompt_denied("ZZZ"),
      Ordering::Less,
    );
    check_comparison(
      &parse_prompt_denied("HOME"),
      &parse_flag_denied("PATH"),
      Ordering::Less,
    );
  }

  #[test]
  fn test_cmp_sys_descriptors() {
    let parser = TestPermissionDescriptorParser;
    let parse_granted = |text: &str| {
      UnaryPermissionDesc::Granted(parser.parse_sys_descriptor(text).unwrap())
    };
    let parse_flag_denied = |text: &str| {
      UnaryPermissionDesc::FlagDenied::<SysDescriptor>(
        parser.parse_sys_descriptor(text).unwrap(),
      )
    };
    let parse_prompt_denied = |text: &str| {
      UnaryPermissionDesc::PromptDenied::<SysDescriptor>(
        parser.parse_sys_descriptor(text).unwrap(),
      )
    };

    // Test system info kind ordering for granted
    check_comparison(
      &parse_granted("hostname"),
      &parse_granted("osRelease"),
      Ordering::Less,
    );
    check_comparison(
      &parse_granted("uid"),
      &parse_granted("hostname"),
      Ordering::Greater,
    );

    // Test system info kind ordering for flag denied
    check_comparison(
      &parse_flag_denied("cpus"),
      &parse_flag_denied("loadavg"),
      Ordering::Less,
    );
    check_comparison(
      &parse_flag_denied("osRelease"),
      &parse_flag_denied("cpus"),
      Ordering::Greater,
    );

    // Test system info kind ordering for prompt denied
    check_comparison(
      &parse_prompt_denied("hostname"),
      &parse_prompt_denied("loadavg"),
      Ordering::Less,
    );
    check_comparison(
      &parse_prompt_denied("uid"),
      &parse_prompt_denied("gid"),
      Ordering::Greater,
    );

    // Test equal descriptors with same type
    check_comparison(
      &parse_granted("hostname"),
      &parse_granted("hostname"),
      Ordering::Equal,
    );
    check_comparison(
      &parse_flag_denied("osRelease"),
      &parse_flag_denied("osRelease"),
      Ordering::Equal,
    );
    check_comparison(
      &parse_prompt_denied("cpus"),
      &parse_prompt_denied("cpus"),
      Ordering::Equal,
    );

    // Test different types with same kind
    // FlagDenied < PromptDenied < Granted (by kind_precedence)
    check_comparison(
      &parse_flag_denied("hostname"),
      &parse_granted("hostname"),
      Ordering::Less,
    );
    check_comparison(
      &parse_prompt_denied("hostname"),
      &parse_granted("hostname"),
      Ordering::Less,
    );
    check_comparison(
      &parse_flag_denied("hostname"),
      &parse_prompt_denied("hostname"),
      Ordering::Less,
    );

    // Test different types with different kinds
    check_comparison(
      &parse_granted("cpus"),
      &parse_flag_denied("loadavg"),
      Ordering::Greater,
    );
    check_comparison(
      &parse_flag_denied("cpus"),
      &parse_granted("loadavg"),
      Ordering::Less,
    );
    check_comparison(
      &parse_prompt_denied("uid"),
      &parse_granted("hostname"),
      Ordering::Less,
    );

    // Test various system info kinds
    check_comparison(
      &parse_granted("gid"),
      &parse_granted("uid"),
      Ordering::Less,
    );
    check_comparison(
      &parse_granted("loadavg"),
      &parse_granted("hostname"),
      Ordering::Greater,
    );

    // Test two deny types with different kinds
    check_comparison(
      &parse_flag_denied("cpus"),
      &parse_prompt_denied("uid"),
      Ordering::Less,
    );
    check_comparison(
      &parse_prompt_denied("hostname"),
      &parse_flag_denied("osRelease"),
      Ordering::Less,
    );
  }

  #[test]
  fn test_cmp_ffi_descriptors() {
    let parser = TestPermissionDescriptorParser;
    let parse_granted = |text: &str| {
      UnaryPermissionDesc::Granted(parser.parse_ffi_descriptor(text).unwrap())
    };
    let parse_flag_denied = |text: &str| {
      UnaryPermissionDesc::FlagDenied::<FfiDescriptor>(
        parser.parse_ffi_descriptor(text).unwrap(),
      )
    };
    let parse_prompt_denied = |text: &str| {
      UnaryPermissionDesc::PromptDenied::<FfiDescriptor>(
        parser.parse_ffi_descriptor(text).unwrap(),
      )
    };

    // Test path hierarchy: child < parent for granted
    check_comparison(
      &parse_granted("/foo/bar"),
      &parse_granted("/foo"),
      Ordering::Less,
    );
    check_comparison(
      &parse_granted("/foo/bar/baz.so"),
      &parse_granted("/foo/bar"),
      Ordering::Less,
    );
    check_comparison(
      &parse_granted("/lib/native/module.so"),
      &parse_granted("/lib"),
      Ordering::Less,
    );

    // Test path hierarchy: child < parent for flag denied
    check_comparison(
      &parse_flag_denied("/foo/bar"),
      &parse_flag_denied("/foo"),
      Ordering::Less,
    );
    check_comparison(
      &parse_flag_denied("/foo/bar/baz.dylib"),
      &parse_flag_denied("/foo/bar"),
      Ordering::Less,
    );

    // Test path hierarchy: child < parent for prompt denied
    check_comparison(
      &parse_prompt_denied("/foo/bar"),
      &parse_prompt_denied("/foo"),
      Ordering::Less,
    );
    check_comparison(
      &parse_prompt_denied("/foo/bar/baz.dll"),
      &parse_prompt_denied("/foo/bar"),
      Ordering::Less,
    );

    // Test equal paths with same type
    check_comparison(
      &parse_granted("/lib/native.so"),
      &parse_granted("/lib/native.so"),
      Ordering::Equal,
    );
    check_comparison(
      &parse_flag_denied("/lib/native.so"),
      &parse_flag_denied("/lib/native.so"),
      Ordering::Equal,
    );
    check_comparison(
      &parse_prompt_denied("/lib/native.so"),
      &parse_prompt_denied("/lib/native.so"),
      Ordering::Equal,
    );

    // Test unrelated paths (lexicographic ordering)
    check_comparison(
      &parse_granted("/aaa/lib.so"),
      &parse_granted("/bbb/lib.so"),
      Ordering::Less,
    );
    check_comparison(
      &parse_granted("/xyz/lib.so"),
      &parse_granted("/abc/lib.so"),
      Ordering::Greater,
    );
    check_comparison(
      &parse_flag_denied("/aaa/lib.so"),
      &parse_flag_denied("/zzz/lib.so"),
      Ordering::Less,
    );

    // Test different types with same path
    // FlagDenied < PromptDenied < Granted (by kind_precedence)
    check_comparison(
      &parse_flag_denied("/lib/native.so"),
      &parse_granted("/lib/native.so"),
      Ordering::Less,
    );
    check_comparison(
      &parse_prompt_denied("/lib/native.so"),
      &parse_granted("/lib/native.so"),
      Ordering::Less,
    );
    check_comparison(
      &parse_flag_denied("/lib/native.so"),
      &parse_prompt_denied("/lib/native.so"),
      Ordering::Less,
    );

    // Test different types with parent/child relationship
    check_comparison(
      &parse_granted("/foo/bar/lib.so"),
      &parse_flag_denied("/foo"),
      Ordering::Less,
    );
    check_comparison(
      &parse_granted("/foo"),
      &parse_flag_denied("/foo/bar/lib.so"),
      Ordering::Greater,
    );
    check_comparison(
      &parse_prompt_denied("/foo/bar/lib.so"),
      &parse_granted("/foo"),
      Ordering::Less,
    );

    // Test root vs subdirectories
    check_comparison(
      &parse_granted("/"),
      &parse_granted("/foo"),
      Ordering::Greater,
    );
    check_comparison(
      &parse_flag_denied("/"),
      &parse_flag_denied("/foo"),
      Ordering::Greater,
    );

    // Test deeply nested paths
    check_comparison(
      &parse_granted("/a/b/c/d/e/f.so"),
      &parse_granted("/a/b/c"),
      Ordering::Less,
    );
    check_comparison(
      &parse_granted("/a/b/c"),
      &parse_granted("/a/b/d"),
      Ordering::Less,
    );

    // Test paths with similar prefixes but different branches
    check_comparison(
      &parse_granted("/foo/bar.so"),
      &parse_granted("/foo/baz.so"),
      Ordering::Less,
    );
    check_comparison(
      &parse_granted("/lib/native1.so"),
      &parse_granted("/lib/native2.so"),
      Ordering::Less,
    );

    // Test two deny types with different paths
    check_comparison(
      &parse_flag_denied("/aaa/lib.so"),
      &parse_prompt_denied("/bbb/lib.so"),
      Ordering::Less,
    );
    check_comparison(
      &parse_prompt_denied("/foo/bar.so"),
      &parse_flag_denied("/foo/baz.so"),
      Ordering::Less,
    );

    // Test PromptDenied(child) vs FlagDenied(parent)
    check_comparison(
      &parse_prompt_denied("/foo/bar/lib.so"),
      &parse_flag_denied("/foo"),
      Ordering::Less,
    );
  }

  #[test]
  fn test_cmp_import_descriptors() {
    let parser = TestPermissionDescriptorParser;
    let parse_granted = |text: &str| {
      UnaryPermissionDesc::Granted(
        parser.parse_import_descriptor(text).unwrap(),
      )
    };
    let parse_flag_denied = |text: &str| {
      UnaryPermissionDesc::FlagDenied::<ImportDescriptor>(
        parser.parse_import_descriptor(text).unwrap(),
      )
    };
    let parse_prompt_denied = |text: &str| {
      UnaryPermissionDesc::PromptDenied::<ImportDescriptor>(
        parser.parse_import_descriptor(text).unwrap(),
      )
    };

    // Test host hierarchy: more specific < less specific for granted
    check_comparison(
      &parse_granted("example.com:8080"),
      &parse_granted("example.com"),
      Ordering::Less,
    );
    check_comparison(
      &parse_granted("sub.example.com"),
      &parse_granted("example.com"),
      Ordering::Less,
    );

    // Test host hierarchy: more specific < less specific for flag denied
    check_comparison(
      &parse_flag_denied("example.com:8080"),
      &parse_flag_denied("example.com"),
      Ordering::Less,
    );
    check_comparison(
      &parse_flag_denied("sub.example.com"),
      &parse_flag_denied("example.com"),
      Ordering::Less,
    );

    // Test host hierarchy: more specific < less specific for prompt denied
    check_comparison(
      &parse_prompt_denied("example.com:8080"),
      &parse_prompt_denied("example.com"),
      Ordering::Less,
    );
    check_comparison(
      &parse_prompt_denied("sub.example.com"),
      &parse_prompt_denied("example.com"),
      Ordering::Less,
    );

    // Test equal descriptors with same type
    check_comparison(
      &parse_granted("deno.land"),
      &parse_granted("deno.land"),
      Ordering::Equal,
    );
    check_comparison(
      &parse_flag_denied("deno.land"),
      &parse_flag_denied("deno.land"),
      Ordering::Equal,
    );
    check_comparison(
      &parse_prompt_denied("deno.land:443"),
      &parse_prompt_denied("deno.land:443"),
      Ordering::Equal,
    );

    // Test unrelated hosts (lexicographic ordering)
    check_comparison(
      &parse_granted("aaa.com"),
      &parse_granted("bbb.com"),
      Ordering::Less,
    );
    check_comparison(
      &parse_granted("xyz.org"),
      &parse_granted("abc.org"),
      Ordering::Greater,
    );
    check_comparison(
      &parse_flag_denied("aaa.com"),
      &parse_flag_denied("zzz.com"),
      Ordering::Less,
    );

    // Test different types with same descriptor
    // FlagDenied < PromptDenied < Granted (by kind_precedence)
    check_comparison(
      &parse_flag_denied("deno.land"),
      &parse_granted("deno.land"),
      Ordering::Less,
    );
    check_comparison(
      &parse_prompt_denied("deno.land"),
      &parse_granted("deno.land"),
      Ordering::Less,
    );
    check_comparison(
      &parse_flag_denied("deno.land"),
      &parse_prompt_denied("deno.land"),
      Ordering::Less,
    );

    // Test different types with hierarchy relationship
    check_comparison(
      &parse_granted("deno.land:8080"),
      &parse_flag_denied("deno.land"),
      Ordering::Less,
    );
    check_comparison(
      &parse_granted("deno.land"),
      &parse_flag_denied("deno.land:8080"),
      Ordering::Greater,
    );
    check_comparison(
      &parse_prompt_denied("deno.land:8080"),
      &parse_granted("deno.land"),
      Ordering::Less,
    );

    // Test port variations
    check_comparison(
      &parse_granted("deno.land:80"),
      &parse_granted("deno.land:443"),
      Ordering::Less,
    );
    check_comparison(
      &parse_granted("deno.land:9000"),
      &parse_granted("deno.land:8080"),
      Ordering::Greater,
    );

    // Test two deny types with different hosts
    check_comparison(
      &parse_flag_denied("aaa.land"),
      &parse_prompt_denied("zzz.land"),
      Ordering::Less,
    );
    check_comparison(
      &parse_prompt_denied("deno.land:8080"),
      &parse_flag_denied("deno.land:9000"),
      Ordering::Less,
    );

    // Test PromptDenied(specific) vs FlagDenied(general)
    check_comparison(
      &parse_prompt_denied("sub.deno.land"),
      &parse_flag_denied("deno.land"),
      Ordering::Less,
    );
  }

  #[track_caller]
  fn check_comparison<TAllowDesc: AllowDescriptor>(
    first: &UnaryPermissionDesc<TAllowDesc>,
    second: &UnaryPermissionDesc<TAllowDesc>,
    expected: Ordering,
  ) {
    assert_eq!(first.cmp(second), expected);
    assert_eq!(
      second.cmp(first),
      match expected {
        Ordering::Less => Ordering::Greater,
        Ordering::Greater => Ordering::Less,
        Ordering::Equal => Ordering::Equal,
      },
      "failed second to first"
    );
  }

  #[test]
  #[cfg(windows)]
  fn check_path_case_insensitive() {
    set_prompter(Box::new(TestPrompter));
    let parser = TestPermissionDescriptorParser;
    let perms = Permissions::from_options(
      &parser,
      &PermissionsOptions {
        allow_read: Some(svec!["C:\\Users\\Admin"]),
        deny_read: Some(svec!["C:\\Users\\Admin\\Secret"]),
        ..Default::default()
      },
    )
    .unwrap();
    let perms = PermissionsContainer::new(Arc::new(parser), perms);

    // Matching case should be allowed
    assert!(
      perms
        .check_open(
          Cow::Borrowed(Path::new("C:\\Users\\Admin\\file.txt")),
          OpenAccessKind::Read,
          Some("api"),
        )
        .is_ok()
    );

    // Different case should also be allowed
    assert!(
      perms
        .check_open(
          Cow::Borrowed(Path::new("c:\\users\\admin\\file.txt")),
          OpenAccessKind::Read,
          Some("api"),
        )
        .is_ok()
    );

    // Deny with matching case should block
    assert!(
      perms
        .check_open(
          Cow::Borrowed(Path::new("C:\\Users\\Admin\\Secret\\data.txt")),
          OpenAccessKind::Read,
          Some("api"),
        )
        .is_err()
    );

    // Deny with different case should also block
    assert!(
      perms
        .check_open(
          Cow::Borrowed(Path::new("c:\\users\\admin\\secret\\data.txt")),
          OpenAccessKind::Read,
          Some("api"),
        )
        .is_err()
    );
  }

  #[test]
  #[cfg(windows)]
  fn path_descriptor_verbatim_prefix_equivalent() {
    // A `\\?\` verbatim (extended-length) path and its regular form refer to
    // the same file, so the permission system must treat them as equal
    // (denoland/deno#18597).
    let regular = PathDescriptor::new_known_absolute(Cow::Borrowed(Path::new(
      "C:\\Users\\Admin",
    )));
    let verbatim = PathDescriptor::new_known_absolute(Cow::Borrowed(
      Path::new("\\\\?\\C:\\Users\\Admin"),
    ));
    assert_eq!(regular, verbatim);
    // The stored path is the simplified form, not the verbatim one.
    assert_eq!(verbatim.path, PathBuf::from("C:\\Users\\Admin"));

    // A `\\?\` query is contained by a grant made with the regular path...
    let query = PathQueryDescriptor::new_known_absolute(Cow::Borrowed(
      Path::new("\\\\?\\C:\\Users\\Admin\\file.txt"),
    ));
    assert!(query.starts_with(&regular));
    // ...and a regular query is contained by a grant made with a `\\?\` path.
    let query = PathQueryDescriptor::new_known_absolute(Cow::Borrowed(
      Path::new("C:\\Users\\Admin\\file.txt"),
    ));
    assert!(query.starts_with(&verbatim));

    // An unrelated verbatim path is not contained.
    let query = PathQueryDescriptor::new_known_absolute(Cow::Borrowed(
      Path::new("\\\\?\\C:\\Other\\file.txt"),
    ));
    assert!(!query.starts_with(&regular));
  }

  #[test]
  fn test_is_allow_all_edge_cases() {
    let parser = TestPermissionDescriptorParser;

    // granted_global alone => is_allow_all true
    let perms = Permissions::from_options(
      &parser,
      &PermissionsOptions {
        allow_read: Some(vec![]),
        ..Default::default()
      },
    )
    .unwrap();
    assert!(perms.read.is_allow_all());

    // granted_global + flag_ignored_global => is_allow_all false
    let perms = Permissions::from_options(
      &parser,
      &PermissionsOptions {
        allow_read: Some(vec![]),
        ignore_read: Some(vec![]),
        ..Default::default()
      },
    )
    .unwrap();
    assert!(!perms.read.is_allow_all());

    // granted_global + flag_denied_global => is_allow_all false
    let perms = Permissions::from_options(
      &parser,
      &PermissionsOptions {
        allow_read: Some(vec![]),
        deny_read: Some(vec![]),
        ..Default::default()
      },
    )
    .unwrap();
    assert!(!perms.read.is_allow_all());

    // granted_global + specific deny descriptor => is_allow_all false
    let perms = Permissions::from_options(
      &parser,
      &PermissionsOptions {
        allow_read: Some(vec![]),
        deny_read: Some(svec!["/secret"]),
        ..Default::default()
      },
    )
    .unwrap();
    assert!(!perms.read.is_allow_all());

    // granted_global + specific ignore descriptor => is_allow_all false
    let perms = Permissions::from_options(
      &parser,
      &PermissionsOptions {
        allow_read: Some(vec![]),
        ignore_read: Some(svec!["/secret"]),
        ..Default::default()
      },
    )
    .unwrap();
    assert!(!perms.read.is_allow_all());

    // specific allow only (not global) => is_allow_all false
    let perms = Permissions::from_options(
      &parser,
      &PermissionsOptions {
        allow_read: Some(svec!["/foo"]),
        ..Default::default()
      },
    )
    .unwrap();
    assert!(!perms.read.is_allow_all());

    // no permissions at all => is_allow_all false
    let perms = Permissions::from_options(
      &parser,
      &PermissionsOptions {
        ..Default::default()
      },
    )
    .unwrap();
    assert!(!perms.read.is_allow_all());
  }

  #[test]
  fn test_revoke_and_requery_state_transitions() {
    set_prompter(Box::new(TestPrompter));
    let parser = TestPermissionDescriptorParser;
    let read_query = |path: &str| {
      parser
        .parse_path_query(Cow::Owned(PathBuf::from(path)))
        .unwrap()
        .into_read()
    };

    // Revoke specific path, then query child path
    let mut perms = Permissions::from_options(
      &parser,
      &PermissionsOptions {
        allow_read: Some(svec!["/foo"]),
        ..Default::default()
      },
    )
    .unwrap();
    assert_eq!(
      perms.read.query(Some(&read_query("/foo/bar"))),
      PermissionState::Granted
    );
    perms.read.revoke(Some(&read_query("/foo")));
    // After revoking /foo, child path /foo/bar should also be prompt
    assert_eq!(
      perms.read.query(Some(&read_query("/foo/bar"))),
      PermissionState::Prompt
    );

    // Revoke after prompt-granted
    let mut perms = Permissions::none_with_prompt();
    let prompt_value = PERMISSION_PROMPT_STUB_VALUE_SETTER.lock();
    prompt_value.set(true);
    assert_eq!(
      perms.read.request(Some(&read_query("/foo"))),
      PermissionState::Granted
    );
    assert_eq!(
      perms.read.query(Some(&read_query("/foo"))),
      PermissionState::Granted
    );
    perms.read.revoke(Some(&read_query("/foo")));
    assert_eq!(
      perms.read.query(Some(&read_query("/foo"))),
      PermissionState::Prompt
    );

    // Revoke global, then check specific descriptor still denied
    let mut perms = Permissions::from_options(
      &parser,
      &PermissionsOptions {
        allow_read: Some(vec![]),
        deny_read: Some(svec!["/secret"]),
        ..Default::default()
      },
    )
    .unwrap();
    assert_eq!(
      perms.read.query(Some(&read_query("/foo"))),
      PermissionState::Granted
    );
    perms.read.revoke(None);
    // /secret should still be denied (flag deny persists after revoke)
    assert_eq!(
      perms.read.query(Some(&read_query("/secret"))),
      PermissionState::Denied
    );
    // Other paths should be prompt after global revoke
    assert_eq!(
      perms.read.query(Some(&read_query("/foo"))),
      PermissionState::Prompt
    );
  }

  #[test]
  fn test_prompt_denied_accumulation_and_stronger_than() {
    set_prompter(Box::new(TestPrompter));
    let parser = TestPermissionDescriptorParser;
    let read_query = |path: &str| {
      parser
        .parse_path_query(Cow::Owned(PathBuf::from(path)))
        .unwrap()
        .into_read()
    };

    let mut perms = Permissions::none_with_prompt();
    let prompt_value = PERMISSION_PROMPT_STUB_VALUE_SETTER.lock();

    // Deny /foo at prompt, then check /foo/bar
    // Unlike flag denials, prompt denials use stronger_than_deny which only
    // blocks when the query path encompasses the denied path (parent of
    // denied), not child paths.
    prompt_value.set(false);
    assert_eq!(
      perms.read.request(Some(&read_query("/foo"))),
      PermissionState::Denied
    );
    // /foo/bar is a child of prompt-denied /foo, but prompt denials don't
    // propagate to children -- only flag denials do
    assert_eq!(
      perms.read.query(Some(&read_query("/foo/bar"))),
      PermissionState::Prompt
    );
    // /foo itself should still be denied
    assert_eq!(
      perms.read.query(Some(&read_query("/foo"))),
      PermissionState::Denied
    );

    // Deny /bar/baz at prompt, then check /bar (parent) -- parent
    // encompasses the denied child, so stronger_than_deny returns true
    prompt_value.set(false);
    assert_eq!(
      perms.read.request(Some(&read_query("/bar/baz"))),
      PermissionState::Denied
    );
    // Parent path /bar is "stronger than" prompt-deny of /bar/baz, so it
    // is also denied
    assert_eq!(
      perms.read.query(Some(&read_query("/bar"))),
      PermissionState::Denied
    );

    // Multiple prompt denials accumulate
    prompt_value.set(false);
    assert_eq!(
      perms.read.request(Some(&read_query("/x"))),
      PermissionState::Denied
    );
    prompt_value.set(false);
    assert_eq!(
      perms.read.request(Some(&read_query("/y"))),
      PermissionState::Denied
    );
    // Both should remain denied
    assert_eq!(
      perms.read.query(Some(&read_query("/x"))),
      PermissionState::Denied
    );
    assert_eq!(
      perms.read.query(Some(&read_query("/y"))),
      PermissionState::Denied
    );
    // Unrelated path still promptable
    assert_eq!(
      perms.read.query(Some(&read_query("/z"))),
      PermissionState::Prompt
    );
  }

  #[test]
  fn test_allow_deny_ignore_three_way_interaction() {
    set_prompter(Box::new(TestPrompter));
    let parser = TestPermissionDescriptorParser;
    let read_query = |path: &str| {
      parser
        .parse_path_query(Cow::Owned(PathBuf::from(path)))
        .unwrap()
        .into_read()
    };

    let perms = Permissions::from_options(
      &parser,
      &PermissionsOptions {
        allow_read: Some(svec!["/home"]),
        deny_read: Some(svec!["/home/secret"]),
        ignore_read: Some(svec!["/home/.cache"]),
        ..Default::default()
      },
    )
    .unwrap();

    // Regular file under /home => allowed
    assert_eq!(
      perms.read.query(Some(&read_query("/home/file.txt"))),
      PermissionState::Granted
    );
    // File under /home/secret => denied
    assert_eq!(
      perms.read.query(Some(&read_query("/home/secret/key"))),
      PermissionState::Denied
    );
    // File under /home/.cache => ignored (stealth deny)
    assert_eq!(
      perms.read.query(Some(&read_query("/home/.cache/data"))),
      PermissionState::Ignored
    );
    // /home itself => GrantedPartial (has deny and ignore holes)
    assert_eq!(
      perms.read.query(Some(&read_query("/home"))),
      PermissionState::GrantedPartial
    );
    // Outside /home => prompt
    assert_eq!(
      perms.read.query(Some(&read_query("/etc/passwd"))),
      PermissionState::Prompt
    );
  }

  #[test]
  fn test_check_all_api_with_specific_allows_only() {
    set_prompter(Box::new(TestPrompter));
    let parser = TestPermissionDescriptorParser;

    // Specific allows only (not global) => check_all should fail
    // (no prompt available)
    let mut perms = Permissions::from_options(
      &parser,
      &PermissionsOptions {
        allow_read: Some(svec!["/foo"]),
        prompt: false,
        ..Default::default()
      },
    )
    .unwrap();
    assert!(perms.read.check_all(None).is_err());

    // Global allow => check_all should succeed
    let mut perms = Permissions::from_options(
      &parser,
      &PermissionsOptions {
        allow_read: Some(vec![]),
        ..Default::default()
      },
    )
    .unwrap();
    assert!(perms.read.check_all(None).is_ok());

    // Global allow + specific deny => check_all still succeeds because
    // check_desc uses AllowPartial::TreatAsGranted for non-partial checks
    let mut perms = Permissions::from_options(
      &parser,
      &PermissionsOptions {
        allow_read: Some(vec![]),
        deny_read: Some(svec!["/secret"]),
        ..Default::default()
      },
    )
    .unwrap();
    assert!(perms.read.check_all(None).is_ok());

    // Global allow + global deny => check_all should fail
    let mut perms = Permissions::from_options(
      &parser,
      &PermissionsOptions {
        allow_read: Some(vec![]),
        deny_read: Some(vec![]),
        ..Default::default()
      },
    )
    .unwrap();
    assert!(perms.read.check_all(None).is_err());

    // Prompt-granted paths only => check_all should fail (not global,
    // no prompt)
    let mut perms = Permissions::none_with_prompt();
    let prompt_value = PERMISSION_PROMPT_STUB_VALUE_SETTER.lock();
    prompt_value.set(true);
    let read_query = parser
      .parse_path_query(Cow::Owned(PathBuf::from("/foo")))
      .unwrap()
      .into_read();
    assert!(perms.read.check(&read_query, None).is_ok());
    // Even though /foo was granted via prompt, check_all queries global
    // state. With prompt enabled it will try to prompt for global, and
    // the prompter returns true, so it grants global
    prompt_value.set(false);
    // Now prompter will deny the global prompt
    assert!(perms.read.check_all(None).is_err());
  }

  #[test]
  fn test_import_permission_check_and_deny() {
    set_prompter(Box::new(TestPrompter));
    let parser = TestPermissionDescriptorParser;

    // Import with allow and deny
    let mut perms = Permissions::from_options(
      &parser,
      &PermissionsOptions {
        allow_import: Some(svec!["deno.land:443", "jsr.io:443"]),
        deny_import: Some(svec!["evil.com:443"]),
        ..Default::default()
      },
    )
    .unwrap();

    // Allowed host
    assert!(
      perms
        .import
        .check(
          &ImportDescriptor(NetDescriptor(
            Host::must_parse("deno.land"),
            Some(443)
          )),
          None,
        )
        .is_ok()
    );

    // Denied host
    assert!(
      perms
        .import
        .check(
          &ImportDescriptor(NetDescriptor(
            Host::must_parse("evil.com"),
            Some(443)
          )),
          None,
        )
        .is_err()
    );

    // Not in allow list => denied (no prompt)
    assert!(
      perms
        .import
        .check(
          &ImportDescriptor(NetDescriptor(
            Host::must_parse("unknown.com"),
            Some(443)
          )),
          None,
        )
        .is_err()
    );

    // Global import allow with deny override
    let mut perms = Permissions::from_options(
      &parser,
      &PermissionsOptions {
        allow_import: Some(vec![]),
        deny_import: Some(svec!["evil.com:443"]),
        ..Default::default()
      },
    )
    .unwrap();

    // Allowed (global grant)
    assert!(
      perms
        .import
        .check(
          &ImportDescriptor(NetDescriptor(
            Host::must_parse("deno.land"),
            Some(443)
          )),
          None,
        )
        .is_ok()
    );

    // Denied (explicit deny overrides global allow)
    assert!(
      perms
        .import
        .check(
          &ImportDescriptor(NetDescriptor(
            Host::must_parse("evil.com"),
            Some(443)
          )),
          None,
        )
        .is_err()
    );

    // check_all with global allow + specific deny succeeds because
    // check_desc uses AllowPartial::TreatAsGranted
    assert!(perms.import.check_all().is_ok());

    // check_all with global allow + global deny fails
    let mut perms = Permissions::from_options(
      &parser,
      &PermissionsOptions {
        allow_import: Some(vec![]),
        deny_import: Some(vec![]),
        ..Default::default()
      },
    )
    .unwrap();
    assert!(perms.import.check_all().is_err());
  }

  #[test]
  fn test_check_open_read_write() {
    set_prompter(Box::new(TestPrompter));
    let parser = TestPermissionDescriptorParser;

    // ReadWrite requires both read AND write
    let perms = Permissions::from_options(
      &parser,
      &PermissionsOptions {
        allow_read: Some(svec!["/data"]),
        allow_write: Some(svec!["/data"]),
        ..Default::default()
      },
    )
    .unwrap();
    let perms = PermissionsContainer::new(Arc::new(parser), perms);

    // ReadWrite on allowed path => ok
    assert!(
      perms
        .check_open(
          Cow::Borrowed(Path::new("/data/file.txt")),
          OpenAccessKind::ReadWrite,
          Some("api"),
        )
        .is_ok()
    );

    // ReadWrite on path with only read => err
    let parser = TestPermissionDescriptorParser;
    let perms = Permissions::from_options(
      &parser,
      &PermissionsOptions {
        allow_read: Some(svec!["/readonly"]),
        ..Default::default()
      },
    )
    .unwrap();
    let perms = PermissionsContainer::new(Arc::new(parser), perms);
    assert!(
      perms
        .check_open(
          Cow::Borrowed(Path::new("/readonly/file.txt")),
          OpenAccessKind::ReadWrite,
          Some("api"),
        )
        .is_err()
    );

    // ReadWrite on path with only write => err
    let parser = TestPermissionDescriptorParser;
    let perms = Permissions::from_options(
      &parser,
      &PermissionsOptions {
        allow_write: Some(svec!["/writeonly"]),
        ..Default::default()
      },
    )
    .unwrap();
    let perms = PermissionsContainer::new(Arc::new(parser), perms);
    assert!(
      perms
        .check_open(
          Cow::Borrowed(Path::new("/writeonly/file.txt")),
          OpenAccessKind::ReadWrite,
          Some("api"),
        )
        .is_err()
    );
  }

  #[test]
  fn test_allow_run_auto_deny_write() {
    let parser = TestPermissionDescriptorParser;
    let perms = Permissions::from_options(
      &parser,
      &PermissionsOptions {
        allow_run: Some(svec!["/usr/bin/node"]),
        allow_write: Some(vec![]),
        ..Default::default()
      },
    )
    .unwrap();
    let perms = PermissionsContainer::new(Arc::new(parser), perms);

    // Writing to allowed run path should be denied
    assert!(
      perms
        .check_open(
          Cow::Borrowed(Path::new("/usr/bin/node")),
          OpenAccessKind::Write,
          Some("api"),
        )
        .is_err()
    );

    // Writing to other paths should be allowed (global write is granted)
    assert!(
      perms
        .check_open(
          Cow::Borrowed(Path::new("/tmp/file.txt")),
          OpenAccessKind::Write,
          Some("api"),
        )
        .is_ok()
    );
  }

  #[test]
  fn test_net_fqdn_with_subdomain_wildcard() {
    set_prompter(Box::new(TestPrompter));
    let parser = TestPermissionDescriptorParser;
    let perms = Permissions::from_options(
      &parser,
      &PermissionsOptions {
        allow_net: Some(svec!["*.example.com"]),
        deny_net: Some(svec!["*.evil.com"]),
        ..Default::default()
      },
    )
    .unwrap();
    let mut perms = PermissionsContainer::new(Arc::new(parser), perms);

    // Subdomain should match wildcard allow
    assert!(
      perms
        .check_net(
          NetPermissionAction::Connect,
          &("sub.example.com", None),
          "api"
        )
        .is_ok()
    );
    assert!(
      perms
        .check_net(
          NetPermissionAction::Connect,
          &("deep.sub.example.com", None),
          "api",
        )
        .is_ok()
    );

    // Bare domain DOES match wildcard: *.example.com matches example.com
    // because the fqdn crate's is_subdomain_of is inclusive (a domain is a
    // subdomain of itself). This is intentional and consistent with the
    // existing test_check_net_with_values test for *.discord.gg.
    assert!(
      perms
        .check_net(NetPermissionAction::Connect, &("example.com", None), "api")
        .is_ok()
    );

    // Subdomain of denied wildcard should be denied
    assert!(
      perms
        .check_net(NetPermissionAction::Connect, &("sub.evil.com", None), "api")
        .is_err()
    );

    // Bare domain also matches wildcard deny (same inclusive semantics)
    assert!(
      perms
        .check_net(NetPermissionAction::Connect, &("evil.com", None), "api")
        .is_err()
    );

    // Unrelated domain should prompt (denied since no-prompt by default
    // in test)
    assert!(
      perms
        .check_net(NetPermissionAction::Connect, &("other.com", None), "api")
        .is_err()
    );
  }

  #[test]
  fn test_empty_descriptor_edge_cases() {
    let parser = TestPermissionDescriptorParser;

    // Some(vec![]) means "grant all" (global grant)
    let perms = Permissions::from_options(
      &parser,
      &PermissionsOptions {
        allow_read: Some(vec![]),
        ..Default::default()
      },
    )
    .unwrap();
    assert!(perms.read.is_allow_all());

    // None means "no grant" (prompt mode)
    let perms = Permissions::from_options(
      &parser,
      &PermissionsOptions {
        ..Default::default()
      },
    )
    .unwrap();
    assert!(!perms.read.is_allow_all());
    let read_query = parser
      .parse_path_query(Cow::Owned(PathBuf::from("/foo")))
      .unwrap()
      .into_read();
    assert_eq!(perms.read.query(Some(&read_query)), PermissionState::Prompt);

    // Some(vec![]) for env means "grant all env"
    let perms = Permissions::from_options(
      &parser,
      &PermissionsOptions {
        allow_env: Some(vec![]),
        ..Default::default()
      },
    )
    .unwrap();
    assert!(perms.env.is_allow_all());
    assert_eq!(perms.env.query(None), PermissionState::Granted);

    // Some(vec![]) for net means "grant all net"
    let perms = Permissions::from_options(
      &parser,
      &PermissionsOptions {
        allow_net: Some(vec![]),
        ..Default::default()
      },
    )
    .unwrap();
    assert!(perms.net.is_allow_all());
    assert_eq!(perms.net.query(None), PermissionState::Granted);
  }

  mod proptests {
    use std::cmp::Ordering;
    use std::net::Ipv4Addr;

    use proptest::prelude::*;

    use super::*;

    // -- Strategies --

    fn arb_host() -> impl Strategy<Value = Host> {
      prop_oneof![
        any::<[u8; 4]>().prop_map(|b| Host::Ip(IpAddr::V4(Ipv4Addr::new(
          b[0], b[1], b[2], b[3]
        )))),
        "[a-z]{1,5}(\\.[a-z]{1,5}){1,3}".prop_filter_map("valid fqdn", |s| {
          use std::str::FromStr;
          fqdn::FQDN::from_str(&s).ok().map(Host::Fqdn)
        }),
      ]
    }

    fn arb_port() -> impl Strategy<Value = Option<u32>> {
      prop_oneof![Just(None), (1u32..=65535).prop_map(Some),]
    }

    fn arb_net_descriptor() -> impl Strategy<Value = NetDescriptor> {
      (arb_host(), arb_port()).prop_map(|(h, p)| NetDescriptor(h, p))
    }

    fn arb_env_descriptor() -> impl Strategy<Value = EnvDescriptor> {
      prop_oneof![
        "[A-Z_]{1,10}"
          .prop_map(|s| EnvDescriptor::Name(EnvVarName::new(Cow::Owned(s)))),
        "[A-Z_]{1,10}".prop_map(|s| EnvDescriptor::PrefixPattern(
          EnvVarName::new(Cow::Owned(s))
        )),
      ]
    }

    fn arb_unary_perm_desc_net()
    -> impl Strategy<Value = UnaryPermissionDesc<NetDescriptor>> {
      (arb_net_descriptor(), 0..4u8).prop_map(|(desc, kind)| match kind {
        0 => UnaryPermissionDesc::Granted(desc),
        1 => UnaryPermissionDesc::FlagDenied(desc),
        2 => UnaryPermissionDesc::FlagIgnored(desc),
        _ => UnaryPermissionDesc::PromptDenied(desc),
      })
    }

    fn arb_unary_perm_desc_env()
    -> impl Strategy<Value = UnaryPermissionDesc<EnvDescriptor>> {
      (arb_env_descriptor(), 0..4u8).prop_map(|(desc, kind)| match kind {
        0 => UnaryPermissionDesc::Granted(desc),
        1 => UnaryPermissionDesc::FlagDenied(desc.clone()),
        2 => UnaryPermissionDesc::FlagIgnored(desc.clone()),
        _ => UnaryPermissionDesc::PromptDenied(desc.clone()),
      })
    }

    // -- 1. Descriptor ordering invariants --

    // Transitivity: if a <= b and b <= c then a <= c
    proptest! {
      #[test]
      fn net_descriptor_ord_transitivity(
        a in arb_unary_perm_desc_net(),
        b in arb_unary_perm_desc_net(),
        c in arb_unary_perm_desc_net(),
      ) {
        let ab = a.cmp(&b);
        let bc = b.cmp(&c);
        let ac = a.cmp(&c);
        if ab != Ordering::Greater && bc != Ordering::Greater {
          prop_assert_ne!(ac, Ordering::Greater,
            "transitivity violated: a={:?}, b={:?}, c={:?}", a, b, c);
        }
        if ab != Ordering::Less && bc != Ordering::Less {
          prop_assert_ne!(ac, Ordering::Less,
            "transitivity violated: a={:?}, b={:?}, c={:?}", a, b, c);
        }
      }

      #[test]
      fn env_descriptor_ord_transitivity(
        a in arb_unary_perm_desc_env(),
        b in arb_unary_perm_desc_env(),
        c in arb_unary_perm_desc_env(),
      ) {
        let ab = a.cmp(&b);
        let bc = b.cmp(&c);
        let ac = a.cmp(&c);
        if ab != Ordering::Greater && bc != Ordering::Greater {
          prop_assert_ne!(ac, Ordering::Greater,
            "transitivity violated: a={:?}, b={:?}, c={:?}", a, b, c);
        }
        if ab != Ordering::Less && bc != Ordering::Less {
          prop_assert_ne!(ac, Ordering::Less,
            "transitivity violated: a={:?}, b={:?}, c={:?}", a, b, c);
        }
      }

      // Antisymmetry: if a <= b and b <= a then a == b
      #[test]
      fn net_descriptor_ord_antisymmetry(
        a in arb_unary_perm_desc_net(),
        b in arb_unary_perm_desc_net(),
      ) {
        let ab = a.cmp(&b);
        let ba = b.cmp(&a);
        match (ab, ba) {
          (Ordering::Less, Ordering::Less) => {
            prop_assert!(false, "antisymmetry violated: a < b and b < a, a={:?}, b={:?}", a, b);
          }
          (Ordering::Greater, Ordering::Greater) => {
            prop_assert!(false, "antisymmetry violated: a > b and b > a, a={:?}, b={:?}", a, b);
          }
          (Ordering::Equal, other) => {
            prop_assert_eq!(other, Ordering::Equal,
              "antisymmetry violated: a == b but b != a, a={:?}, b={:?}", a, b);
          }
          (_, Ordering::Equal) => {
            prop_assert_eq!(ab, Ordering::Equal,
              "antisymmetry violated: b == a but a != b, a={:?}, b={:?}", a, b);
          }
          _ => {} // Less/Greater is fine
        }
      }

      // Reflexivity: a == a
      #[test]
      fn net_descriptor_ord_reflexivity(
        a in arb_unary_perm_desc_net(),
      ) {
        prop_assert_eq!(a.cmp(&a), Ordering::Equal,
          "reflexivity violated: a={:?}", a);
      }

      // Binary search correctness: after inserting into descriptors,
      // the vec remains sorted
      #[test]
      fn net_descriptors_remain_sorted_after_inserts(
        descs in prop::collection::vec(arb_unary_perm_desc_net(), 1..20),
      ) {
        let mut descriptors = UnaryPermissionDescriptors::<NetDescriptor>::default();
        for d in &descs {
          descriptors.insert(d.clone());
        }
        let inner = &descriptors.inner;
        for i in 1..inner.len() {
          prop_assert!(inner[i - 1] <= inner[i],
            "not sorted at index {}: {:?} > {:?}", i, inner[i-1], inner[i]);
        }
      }

      #[test]
      fn env_descriptors_remain_sorted_after_inserts(
        descs in prop::collection::vec(arb_unary_perm_desc_env(), 1..20),
      ) {
        let mut descriptors = UnaryPermissionDescriptors::<EnvDescriptor>::default();
        for d in &descs {
          descriptors.insert(d.clone());
        }
        let inner = &descriptors.inner;
        for i in 1..inner.len() {
          prop_assert!(inner[i - 1] <= inner[i],
            "not sorted at index {}: {:?} > {:?}", i, inner[i-1], inner[i]);
        }
      }
    }

    // -- 2. Allow/deny resolution consistency --
    // query_desc() should never return Granted when a matching FlagDenied
    // descriptor exists in the list.

    proptest! {
      #[test]
      fn net_query_never_granted_when_flag_denied(
        allow_descs in prop::collection::vec(arb_net_descriptor(), 0..5),
        deny_descs in prop::collection::vec(arb_net_descriptor(), 1..5),
        query in arb_net_descriptor(),
      ) {
        set_prompter(Box::new(TestPrompter));

        let mut perm = UnaryPermission::<NetDescriptor>::default();
        for d in &allow_descs {
          perm.descriptors.insert(UnaryPermissionDesc::Granted(d.clone()));
        }
        for d in &deny_descs {
          perm.descriptors.insert(UnaryPermissionDesc::FlagDenied(d.clone()));
        }

        // If the query matches any deny descriptor, the result must not be Granted
        let matches_any_deny = deny_descs.iter().any(|d| query.matches_deny(d));
        if matches_any_deny {
          let state = perm.query_desc(
            Some(&query),
            AllowPartial::TreatAsPartialGranted,
          );
          prop_assert_ne!(state, PermissionState::Granted,
            "query returned Granted despite matching FlagDenied: query={:?}, deny={:?}", query, deny_descs);
          prop_assert_ne!(state, PermissionState::GrantedPartial,
            "query returned GrantedPartial despite matching FlagDenied: query={:?}, deny={:?}", query, deny_descs);
        }
      }
    }

    // -- 3. Path containment symmetry --
    // For paths: matches_allow(allow) && stronger_than_deny(deny_at_same_path)
    // should be consistent with containment direction.

    proptest! {
      #[test]
      fn path_containment_properties(
        base_segments in prop::collection::vec("[a-z]{1,5}", 1..5),
        extra_segments in prop::collection::vec("[a-z]{1,5}", 0..3),
      ) {
        let parser = TestPermissionDescriptorParser;

        let base_path = format!("/{}", base_segments.join("/"));
        let child_path = if extra_segments.is_empty() {
          base_path.clone()
        } else {
          format!("{}/{}", base_path, extra_segments.join("/"))
        };

        let base_desc = parser.parse_read_descriptor(&base_path).unwrap();
        let child_allow_desc = parser.parse_read_descriptor(&child_path).unwrap();

        let child_query = parser.parse_path_query(
          Cow::Owned(PathBuf::from(&child_path)),
        ).unwrap().into_read();
        let base_query = parser.parse_path_query(
          Cow::Owned(PathBuf::from(&base_path)),
        ).unwrap().into_read();

        // A child path should match_allow on a base (parent) allow descriptor
        prop_assert!(child_query.matches_allow(&base_desc),
          "child {} should match_allow base {}", child_path, base_path);

        // A base path should be stronger_than_deny of a child deny
        prop_assert!(base_query.stronger_than_deny(&child_allow_desc),
          "base {} should be stronger_than_deny of child {}", base_path, child_path);

        // If child matches allow on base, then child matches deny on base too
        // (because matches_deny delegates to same containment check for paths)
        prop_assert!(child_query.matches_deny(&base_desc),
          "matches_deny should agree with matches_allow for paths");

        // overlaps_deny is same as stronger_than_deny for paths
        prop_assert_eq!(
          base_query.overlaps_deny(&child_allow_desc),
          base_query.stronger_than_deny(&child_allow_desc),
          "overlaps_deny should agree with stronger_than_deny for paths"
        );
      }
    }

    // -- 4. Child permission escalation --
    // Child processes should never obtain permissions that the parent's
    // check() method would deny.

    proptest! {
      #[test]
      fn child_net_permissions_cannot_escalate(
        parent_allow in prop::collection::vec(arb_net_descriptor(), 0..5),
        parent_deny in prop::collection::vec(arb_net_descriptor(), 0..3),
        child_request in prop::collection::vec(arb_net_descriptor(), 0..5),
        query in arb_net_descriptor(),
      ) {
        set_prompter(Box::new(TestPrompter));
        let prompt_value = PERMISSION_PROMPT_STUB_VALUE_SETTER.lock();
        prompt_value.set(false);

        // Build parent permissions
        let mut parent = UnaryPermission::<NetDescriptor>::default();
        for d in &parent_allow {
          parent.descriptors.insert(UnaryPermissionDesc::Granted(d.clone()));
        }
        for d in &parent_deny {
          parent.descriptors.insert(UnaryPermissionDesc::FlagDenied(d.clone()));
        }

        // Try to create child permissions with the requested list
        let child_strs: Vec<String> = child_request.iter().map(|d| d.to_string()).collect();
        let child_result = parent.create_child_permissions(
          ChildUnaryPermissionArg::GrantedList(child_strs),
          |s| NetDescriptor::parse_for_list(s).map(Some),
        );

        if let Ok(child) = child_result {
          // For any query: if parent would deny, child must also deny
          let parent_state = parent.query_desc(
            Some(&query),
            AllowPartial::TreatAsDenied,
          );
          let child_state = child.query_desc(
            Some(&query),
            AllowPartial::TreatAsDenied,
          );

          if parent_state == PermissionState::Denied {
            prop_assert_ne!(child_state, PermissionState::Granted,
              "child escalated! query={:?}, parent_state={:?}, child_state={:?}",
              query, parent_state, child_state);
          }
        }
        // If child creation failed (Escalation), that's the correct behavior
      }

      #[test]
      fn child_inherit_preserves_denials(
        parent_allow in prop::collection::vec(arb_net_descriptor(), 0..3),
        parent_deny in prop::collection::vec(arb_net_descriptor(), 1..3),
        query in arb_net_descriptor(),
      ) {
        set_prompter(Box::new(TestPrompter));

        let mut parent = UnaryPermission::<NetDescriptor>::default();
        for d in &parent_allow {
          parent.descriptors.insert(UnaryPermissionDesc::Granted(d.clone()));
        }
        for d in &parent_deny {
          parent.descriptors.insert(UnaryPermissionDesc::FlagDenied(d.clone()));
        }

        let child = parent.create_child_permissions(
          ChildUnaryPermissionArg::Inherit,
          |s: &str| NetDescriptor::parse_for_list(s).map(Some),
        ).unwrap();

        // Inherited child should have identical query results
        let parent_state = parent.query_desc(Some(&query), AllowPartial::TreatAsDenied);
        let child_state = child.query_desc(Some(&query), AllowPartial::TreatAsDenied);
        prop_assert_eq!(parent_state, child_state,
          "inherited child diverged from parent: query={:?}", query);
      }
    }

    // -- 5. Net descriptor round-trip --
    // Parsing display_name() back through parse should yield an equivalent
    // descriptor.

    proptest! {
      #[test]
      fn net_descriptor_display_roundtrip(
        desc in arb_net_descriptor(),
      ) {
        let display = desc.display_name().to_string();
        // parse_for_list supports wildcards (superset of parse_for_query)
        if let Ok(parsed) = NetDescriptor::parse_for_list(&display) {
          prop_assert_eq!(&parsed, &desc,
            "round-trip failed: display={:?}, original={:?}, parsed={:?}",
            display, desc, parsed);
        }
        // If parsing fails, skip (some edge cases with subnet display may differ)
      }

      // Also test with port
      #[test]
      fn net_descriptor_display_roundtrip_with_port(
        host in arb_host(),
        port in 1u32..=65535,
      ) {
        let desc = NetDescriptor(host, Some(port));
        let display = desc.display_name().to_string();
        if let Ok(parsed) = NetDescriptor::parse_for_list(&display) {
          prop_assert_eq!(&parsed, &desc,
            "round-trip with port failed: display={:?}", display);
        }
      }
    }

    // -- 6. Global flag_denied overrides granted descriptors --

    proptest! {
      #[test]
      fn global_deny_overrides_all_grants_net(
        allow_descs in prop::collection::vec(arb_net_descriptor(), 1..5),
        query in arb_net_descriptor(),
      ) {
        set_prompter(Box::new(TestPrompter));

        let mut perm = UnaryPermission::<NetDescriptor> {
          flag_denied_global: true,
          ..Default::default()
        };
        for d in &allow_descs {
          perm.descriptors.insert(UnaryPermissionDesc::Granted(d.clone()));
        }

        let state = perm.query_desc(Some(&query), AllowPartial::TreatAsDenied);
        prop_assert_eq!(state, PermissionState::Denied,
          "flag_denied_global should deny everything: query={:?}", query);

        // Also check global query (None)
        let state_global = perm.query_desc(None, AllowPartial::TreatAsDenied);
        prop_assert_eq!(state_global, PermissionState::Denied,
          "flag_denied_global should deny global query too");
      }

      #[test]
      fn global_deny_overrides_granted_global_net(
        query in arb_net_descriptor(),
      ) {
        set_prompter(Box::new(TestPrompter));

        let perm = UnaryPermission::<NetDescriptor> {
          granted_global: true,
          flag_denied_global: true,
          ..Default::default()
        };

        let state = perm.query_desc(Some(&query), AllowPartial::TreatAsDenied);
        prop_assert_eq!(state, PermissionState::Denied,
          "flag_denied_global should override granted_global: query={:?}", query);
      }
    }

    // -- 7. Revoke consistency --
    // After revoke_desc(), query_desc() should never return Granted for
    // the revoked descriptor.

    proptest! {
      #[test]
      fn revoke_prevents_granted_net(
        allow_descs in prop::collection::vec(arb_net_descriptor(), 1..5),
        revoke_idx in 0usize..5,
      ) {
        set_prompter(Box::new(TestPrompter));

        let mut perm = UnaryPermission::<NetDescriptor>::default();
        for d in &allow_descs {
          perm.descriptors.insert(UnaryPermissionDesc::Granted(d.clone()));
        }

        let idx = revoke_idx % allow_descs.len();
        let to_revoke = &allow_descs[idx];

        perm.revoke_desc(Some(to_revoke));

        // After revoking, the descriptor should not be Granted
        let state = perm.query_desc(
          Some(to_revoke),
          AllowPartial::TreatAsDenied,
        );
        prop_assert_ne!(state, PermissionState::Granted,
          "revoked descriptor still Granted: {:?}", to_revoke);
      }

      #[test]
      fn revoke_global_clears_all_grants_net(
        allow_descs in prop::collection::vec(arb_net_descriptor(), 1..5),
        query in arb_net_descriptor(),
      ) {
        set_prompter(Box::new(TestPrompter));

        let mut perm = UnaryPermission::<NetDescriptor> {
          granted_global: true,
          ..Default::default()
        };
        for d in &allow_descs {
          perm.descriptors.insert(UnaryPermissionDesc::Granted(d.clone()));
        }

        // Revoke global
        perm.revoke_desc(None);

        prop_assert!(!perm.granted_global,
          "granted_global should be false after global revoke");

        // No descriptor should be Granted anymore (should be Prompt)
        let state = perm.query_desc(Some(&query), AllowPartial::TreatAsDenied);
        prop_assert_ne!(state, PermissionState::Granted,
          "query still Granted after global revoke: {:?}", query);
      }
    }

    // -- 8. Idempotent insert --
    // Inserting the same descriptor twice should not change the vec length.

    proptest! {
      #[test]
      fn idempotent_insert_net(
        desc in arb_unary_perm_desc_net(),
      ) {
        let mut descriptors = UnaryPermissionDescriptors::<NetDescriptor>::default();
        descriptors.insert(desc.clone());
        let len_after_first = descriptors.inner.len();

        descriptors.insert(desc.clone());
        let len_after_second = descriptors.inner.len();

        prop_assert_eq!(len_after_first, len_after_second,
          "duplicate insert changed vec length: desc={:?}", desc);
      }

      #[test]
      fn idempotent_insert_env(
        desc in arb_unary_perm_desc_env(),
      ) {
        let mut descriptors = UnaryPermissionDescriptors::<EnvDescriptor>::default();
        descriptors.insert(desc.clone());
        let len_after_first = descriptors.inner.len();

        descriptors.insert(desc.clone());
        let len_after_second = descriptors.inner.len();

        prop_assert_eq!(len_after_first, len_after_second,
          "duplicate insert changed vec length: desc={:?}", desc);
      }
    }

    // -- 9. Net matches_allow reflexivity --
    // Any NetDescriptor should matches_allow itself.

    proptest! {
      #[test]
      fn net_matches_allow_reflexive(
        desc in arb_net_descriptor(),
      ) {
        prop_assert!(desc.matches_allow(&desc),
          "descriptor should match its own allow: {:?}", desc);
      }

      #[test]
      fn net_matches_deny_reflexive(
        desc in arb_net_descriptor(),
      ) {
        prop_assert!(desc.matches_deny(&desc),
          "descriptor should match its own deny: {:?}", desc);
      }

      #[test]
      fn net_stronger_than_deny_reflexive(
        desc in arb_net_descriptor(),
      ) {
        prop_assert!(desc.stronger_than_deny(&desc),
          "descriptor should be stronger_than_deny of itself: {:?}", desc);
      }
    }

    // -- 10. Child NotGranted has no grants --
    // A child created with NotGranted should never return Granted.

    proptest! {
      #[test]
      fn child_not_granted_denies_everything_net(
        parent_allow in prop::collection::vec(arb_net_descriptor(), 1..5),
        query in arb_net_descriptor(),
      ) {
        set_prompter(Box::new(TestPrompter));
        let prompt_value = PERMISSION_PROMPT_STUB_VALUE_SETTER.lock();
        prompt_value.set(false);

        let mut parent = UnaryPermission::<NetDescriptor>::default();
        for d in &parent_allow {
          parent.descriptors.insert(UnaryPermissionDesc::Granted(d.clone()));
        }

        let child = parent.create_child_permissions(
          ChildUnaryPermissionArg::NotGranted,
          |s: &str| NetDescriptor::parse_for_list(s).map(Some),
        ).unwrap();

        let state = child.query_desc(Some(&query), AllowPartial::TreatAsDenied);
        prop_assert_ne!(state, PermissionState::Granted,
          "NotGranted child returned Granted: query={:?}", query);
        prop_assert_ne!(state, PermissionState::GrantedPartial,
          "NotGranted child returned GrantedPartial: query={:?}", query);
      }

      #[test]
      fn child_not_granted_global_not_granted_net(
        parent_allow in prop::collection::vec(arb_net_descriptor(), 0..3),
      ) {
        set_prompter(Box::new(TestPrompter));
        let prompt_value = PERMISSION_PROMPT_STUB_VALUE_SETTER.lock();
        prompt_value.set(false);

        let mut parent = UnaryPermission::<NetDescriptor> {
          granted_global: true,
          ..Default::default()
        };
        for d in &parent_allow {
          parent.descriptors.insert(UnaryPermissionDesc::Granted(d.clone()));
        }

        let child = parent.create_child_permissions(
          ChildUnaryPermissionArg::NotGranted,
          |s: &str| NetDescriptor::parse_for_list(s).map(Some),
        ).unwrap();

        prop_assert!(!child.granted_global,
          "NotGranted child should not have granted_global");

        let state = child.query_desc(None, AllowPartial::TreatAsDenied);
        prop_assert_ne!(state, PermissionState::Granted,
          "NotGranted child global query returned Granted");
      }
    }
  }
}

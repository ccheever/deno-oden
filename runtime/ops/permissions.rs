// Copyright 2018-2026 the Deno authors. MIT license.

use ::deno_permissions::OdenRev2ProcessMode;
use ::deno_permissions::PermissionState;
use ::deno_permissions::PermissionsContainer;
use deno_core::OpState;
use deno_core::ToV8;
use deno_core::op2;
use serde::Deserialize;

deno_core::extension!(
  deno_permissions,
  ops = [
    op_query_permission,
    op_revoke_permission,
    op_request_permission,
  ],
  state = |state| {
    let mode = ::deno_permissions::oden_capsec_rev2_process_mode();
    state.put(mode);
    if let Some(context) =
      ::deno_permissions::oden_capsec_rev2_runtime_authority_context()
    {
      state.put(context);
    }
  },
);

#[derive(Default)]
enum PermissionArgField {
  #[default]
  Absent,
  Null,
  String(String),
}

impl PermissionArgField {
  fn as_deref(&self) -> Option<&str> {
    match self {
      Self::String(value) => Some(value),
      Self::Absent | Self::Null => None,
    }
  }

  fn is_present(&self) -> bool {
    !matches!(self, Self::Absent)
  }
}

impl<'de> Deserialize<'de> for PermissionArgField {
  fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
  where
    D: serde::Deserializer<'de>,
  {
    Option::<String>::deserialize(deserializer)
      .map(|value| value.map_or(Self::Null, Self::String))
  }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PermissionArgs {
  name: String,
  #[serde(default)]
  path: PermissionArgField,
  #[serde(default)]
  host: PermissionArgField,
  #[serde(default)]
  variable: PermissionArgField,
  #[serde(default)]
  kind: PermissionArgField,
  #[serde(default)]
  command: PermissionArgField,
}

#[derive(ToV8)]
pub struct PermissionStatus {
  state: &'static str,
  partial: bool,
}

impl From<PermissionState> for PermissionStatus {
  fn from(state: PermissionState) -> Self {
    PermissionStatus {
      state: match state {
        PermissionState::Granted | PermissionState::GrantedPartial => "granted",
        PermissionState::Ignored
        | PermissionState::DeniedPartial
        | PermissionState::Denied => "denied",
        PermissionState::Prompt => "prompt",
      },
      partial: state == PermissionState::GrantedPartial,
    }
  }
}

#[derive(Debug, thiserror::Error, deno_error::JsError)]
pub enum PermissionError {
  #[class(reference)]
  #[error("No such permission name: {0}")]
  InvalidPermissionName(String),
  #[class(inherit)]
  #[error("{0}")]
  PathResolve(#[from] ::deno_permissions::PathResolveError),
  #[class(uri)]
  #[error("{0}")]
  NetDescriptorParse(#[from] ::deno_permissions::NetDescriptorParseError),
  #[class(inherit)]
  #[error("{0}")]
  SysDescriptorParse(#[from] ::deno_permissions::SysDescriptorParseError),
  #[class(inherit)]
  #[error("{0}")]
  RunDescriptorParse(#[from] ::deno_permissions::RunDescriptorParseError),
  #[class(generic)]
  #[error("{0}")]
  Rev2(String),
}

fn query_permission(
  permissions: &PermissionsContainer,
  args: &PermissionArgs,
) -> Result<PermissionState, PermissionError> {
  Ok(match args.name.as_ref() {
    "read" => permissions.query_read(args.path.as_deref())?,
    "write" => permissions.query_write(args.path.as_deref())?,
    "net" => permissions.query_net(args.host.as_deref())?,
    "env" => permissions.query_env(args.variable.as_deref()),
    "sys" => permissions.query_sys(args.kind.as_deref())?,
    "run" => permissions.query_run(args.command.as_deref())?,
    "ffi" => permissions.query_ffi(args.path.as_deref())?,
    "import" => permissions.query_import(args.host.as_deref())?,
    _ => return Err(PermissionError::InvalidPermissionName(args.name.clone())),
  })
}

fn dynamic_descriptor(
  args: &PermissionArgs,
) -> ::deno_permissions::OdenDynamicPermissionDescriptor<'_> {
  ::deno_permissions::OdenDynamicPermissionDescriptor {
    name: &args.name,
    path: args.path.as_deref(),
    host: args.host.as_deref(),
    variable: args.variable.as_deref(),
    kind: args.kind.as_deref(),
    command: args.command.as_deref(),
    presence: ::deno_permissions::OdenDynamicPermissionFieldPresence {
      path: args.path.is_present(),
      host: args.host.is_present(),
      variable: args.variable.is_present(),
      kind: args.kind.is_present(),
      command: args.command.is_present(),
    },
  }
}

fn resolve_rev2_permission<T>(
  candidate: Option<Result<T, PermissionError>>,
) -> Result<Option<T>, PermissionError> {
  candidate.transpose()
}

fn rev2_permission(
  state: &OpState,
  args: &PermissionArgs,
  operation: ::deno_permissions::OdenRev2PermissionOperation,
) -> Option<Result<PermissionState, PermissionError>> {
  #[cfg(all(test, debug_assertions, unix))]
  let fixture_call = state
    .try_borrow::<NativePermissionFixtureLocalContext>()
    .map(|local| local.call.clone());
  let context = match resolve_rev2_context(state) {
    Ok(Some(context)) => context,
    Ok(None) => return None,
    Err(error) => return Some(Err(error)),
  };
  let permissions = state.borrow::<PermissionsContainer>();
  #[cfg(all(test, debug_assertions, unix))]
  let permission = if let Some(call) = fixture_call {
    ::deno_permissions::oden_capsec_rev2_permission_fixture_operation(
      &call,
      context.as_ref(),
      permissions,
      operation,
      &dynamic_descriptor(args),
    )
  } else {
    ::deno_permissions::oden_capsec_rev2_permission_operation(
      context.as_ref(),
      permissions,
      operation,
      &dynamic_descriptor(args),
    )
  };
  #[cfg(not(all(test, debug_assertions, unix)))]
  let permission = ::deno_permissions::oden_capsec_rev2_permission_operation(
    context.as_ref(),
    permissions,
    operation,
    &dynamic_descriptor(args),
  );
  Some(permission.map_err(|error| PermissionError::Rev2(error.to_string())))
}

fn resolve_rev2_context(
  state: &OpState,
) -> Result<
  Option<std::sync::Arc<::deno_permissions::OdenRev2RuntimeAuthorityContext>>,
  PermissionError,
> {
  // @ref LLP 0019#typed-permission-batches [tests/constrained-by] -- The
  // pre-promotion fixture may bind one detached local authority Arc through
  // test OpState only; it must remain unable to publish or replace the global
  // runtime authority context.
  #[cfg(all(test, debug_assertions, unix))]
  if let Some(local) = state.try_borrow::<NativePermissionFixtureLocalContext>()
  {
    let state_mode = state.try_borrow::<OdenRev2ProcessMode>().copied();
    if state_mode != Some(OdenRev2ProcessMode::Rev2Installed)
      || state
        .try_borrow::<std::sync::Arc<
          ::deno_permissions::OdenRev2RuntimeAuthorityContext,
        >>()
        .is_some()
      || ::deno_permissions::oden_capsec_rev2_process_mode()
        != OdenRev2ProcessMode::Rev1
      || ::deno_permissions::oden_capsec_rev2_runtime_authority_context()
        .is_some()
    {
      return Err(PermissionError::Rev2(
        "OD-CAP-REV2-FIXTURE-OPSTATE-BINDING".to_string(),
      ));
    }
    return Ok(Some(local.authority.clone()));
  }
  let state_mode = state.try_borrow::<OdenRev2ProcessMode>().copied();
  let state_context = state
    .try_borrow::<std::sync::Arc<
      ::deno_permissions::OdenRev2RuntimeAuthorityContext,
    >>()
    .cloned();
  ::deno_permissions::oden_capsec_rev2_resolve_op_state_context(
    state_mode,
    state_context,
  )
  .map_err(|reason| PermissionError::Rev2(reason.to_string()))
}

#[cfg(all(test, debug_assertions, unix))]
struct NativePermissionFixtureLocalContext {
  authority:
    std::sync::Arc<::deno_permissions::OdenRev2RuntimeAuthorityContext>,
  call: ::deno_permissions::OdenRev2PermissionFixtureCall,
}

#[cfg(all(test, debug_assertions, unix))]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct NativePermissionFixtureFallbackCounters {
  stock: u64,
  rev1: u64,
  stock_prompt: u64,
}

#[cfg(all(test, debug_assertions, unix))]
thread_local! {
  static NATIVE_PERMISSION_FIXTURE_FALLBACK_COUNTERS:
    std::cell::Cell<NativePermissionFixtureFallbackCounters> =
      const { std::cell::Cell::new(NativePermissionFixtureFallbackCounters {
        stock: 0,
        rev1: 0,
        stock_prompt: 0,
      }) };
}

#[cfg(all(test, debug_assertions, unix))]
fn native_permission_fixture_reset_fallback_counters() {
  NATIVE_PERMISSION_FIXTURE_FALLBACK_COUNTERS.with(|counters| {
    counters.set(NativePermissionFixtureFallbackCounters::default())
  });
}

#[cfg(all(test, debug_assertions, unix))]
fn native_permission_fixture_fallback_counters()
-> NativePermissionFixtureFallbackCounters {
  NATIVE_PERMISSION_FIXTURE_FALLBACK_COUNTERS.with(std::cell::Cell::get)
}

#[cfg(all(test, debug_assertions, unix))]
fn native_permission_fixture_count_stock() {
  NATIVE_PERMISSION_FIXTURE_FALLBACK_COUNTERS.with(|counters| {
    let mut next = counters.get();
    next.stock = next.stock.saturating_add(1);
    counters.set(next);
  });
}

#[cfg(all(test, debug_assertions, unix))]
fn native_permission_fixture_count_rev1() {
  NATIVE_PERMISSION_FIXTURE_FALLBACK_COUNTERS.with(|counters| {
    let mut next = counters.get();
    next.rev1 = next.rev1.saturating_add(1);
    counters.set(next);
  });
}

#[cfg(all(test, debug_assertions, unix))]
fn native_permission_fixture_count_stock_prompt() {
  NATIVE_PERMISSION_FIXTURE_FALLBACK_COUNTERS.with(|counters| {
    let mut next = counters.get();
    next.stock_prompt = next.stock_prompt.saturating_add(1);
    counters.set(next);
  });
}

#[cfg(all(test, debug_assertions, unix))]
fn native_permission_fixture_record(event: &str) {
  ::deno_permissions::oden_capsec_rev2_permission_fixture_record_event(event);
}

#[cfg(all(test, debug_assertions, unix))]
fn native_permission_fixture_record_return(
  result: &Result<PermissionStatus, PermissionError>,
) {
  let state = match result {
    Ok(status) => status.state,
    Err(_) => "refused",
  };
  native_permission_fixture_record(&format!("op-returned:{state}"));
}

#[op2(stack_trace)]
pub fn op_query_permission(
  state: &mut OpState,
  #[serde] args: PermissionArgs,
) -> Result<PermissionStatus, PermissionError> {
  #[cfg(all(test, debug_assertions, unix))]
  native_permission_fixture_record("op-entered:query");
  let rev2 = rev2_permission(
    state,
    &args,
    ::deno_permissions::OdenRev2PermissionOperation::Query,
  );
  let resolved_rev2 = resolve_rev2_permission(rev2);
  #[cfg(all(test, debug_assertions, unix))]
  if resolved_rev2.is_err() {
    native_permission_fixture_record("op-returned:refused");
  }
  if let Some(permission) = resolved_rev2? {
    let result = Ok(PermissionStatus::from(permission));
    #[cfg(all(test, debug_assertions, unix))]
    native_permission_fixture_record_return(&result);
    return result;
  }
  #[cfg(all(test, debug_assertions, unix))]
  native_permission_fixture_count_stock();
  let permissions = state.borrow::<PermissionsContainer>();
  // Validate through the stock descriptor parser first. Layer 2 then
  // overrides the status for a package principal without mutating layer 1.
  let stock = query_permission(permissions, &args)?;
  #[cfg(all(test, debug_assertions, unix))]
  native_permission_fixture_count_rev1();
  let perm = ::deno_permissions::oden_capsec_query_dynamic_permission(
    &dynamic_descriptor(&args),
  )
  .unwrap_or(stock);
  let result = Ok(PermissionStatus::from(perm));
  #[cfg(all(test, debug_assertions, unix))]
  native_permission_fixture_record_return(&result);
  result
}

#[op2(stack_trace)]
pub fn op_revoke_permission(
  state: &mut OpState,
  #[serde] args: PermissionArgs,
) -> Result<PermissionStatus, PermissionError> {
  #[cfg(all(test, debug_assertions, unix))]
  native_permission_fixture_record("op-entered:revoke");
  let rev2 = rev2_permission(
    state,
    &args,
    ::deno_permissions::OdenRev2PermissionOperation::Revoke,
  );
  let resolved_rev2 = resolve_rev2_permission(rev2);
  #[cfg(all(test, debug_assertions, unix))]
  if resolved_rev2.is_err() {
    native_permission_fixture_record("op-returned:refused");
  }
  if let Some(permission) = resolved_rev2? {
    let result = Ok(PermissionStatus::from(permission));
    #[cfg(all(test, debug_assertions, unix))]
    native_permission_fixture_record_return(&result);
    return result;
  }
  #[cfg(all(test, debug_assertions, unix))]
  native_permission_fixture_count_stock();
  let permissions = state.borrow::<PermissionsContainer>();
  // Validation only; package revoke is a session overlay and must not narrow
  // the process-global permission object for every other principal.
  let _ = query_permission(permissions, &args)?;
  #[cfg(all(test, debug_assertions, unix))]
  native_permission_fixture_count_rev1();
  if let Some(perm) = ::deno_permissions::oden_capsec_revoke_dynamic_permission(
    &dynamic_descriptor(&args),
  ) {
    return Ok(PermissionStatus::from(perm));
  }
  let perm = match args.name.as_ref() {
    "read" => permissions.revoke_read(args.path.as_deref())?,
    "write" => permissions.revoke_write(args.path.as_deref())?,
    "net" => permissions.revoke_net(args.host.as_deref())?,
    "env" => permissions.revoke_env(args.variable.as_deref()),
    "sys" => permissions.revoke_sys(args.kind.as_deref())?,
    "run" => permissions.revoke_run(args.command.as_deref())?,
    "ffi" => permissions.revoke_ffi(args.path.as_deref())?,
    "import" => permissions.revoke_import(args.host.as_deref())?,
    _ => return Err(PermissionError::InvalidPermissionName(args.name)),
  };
  let result = Ok(PermissionStatus::from(perm));
  #[cfg(all(test, debug_assertions, unix))]
  native_permission_fixture_record_return(&result);
  result
}

#[op2(stack_trace)]
pub fn op_request_permission(
  state: &mut OpState,
  #[serde] args: PermissionArgs,
) -> Result<PermissionStatus, PermissionError> {
  #[cfg(all(test, debug_assertions, unix))]
  native_permission_fixture_record("op-entered:request");
  let rev2 = rev2_permission(
    state,
    &args,
    ::deno_permissions::OdenRev2PermissionOperation::Request,
  );
  let resolved_rev2 = resolve_rev2_permission(rev2);
  #[cfg(all(test, debug_assertions, unix))]
  if resolved_rev2.is_err() {
    native_permission_fixture_record("op-returned:refused");
  }
  if let Some(permission) = resolved_rev2? {
    let result = Ok(PermissionStatus::from(permission));
    #[cfg(all(test, debug_assertions, unix))]
    native_permission_fixture_record_return(&result);
    return result;
  }
  #[cfg(all(test, debug_assertions, unix))]
  native_permission_fixture_count_stock();
  let permissions = state.borrow::<PermissionsContainer>();
  // Validation only. A package request is decided against its immutable
  // escalation ceiling and can update only its layer-2 session overlay; it
  // never reaches stock request()/the process prompt.
  let _ = query_permission(permissions, &args)?;
  #[cfg(all(test, debug_assertions, unix))]
  native_permission_fixture_count_rev1();
  if let Some(perm) = ::deno_permissions::oden_capsec_request_dynamic_permission(
    &dynamic_descriptor(&args),
  ) {
    let result = Ok(PermissionStatus::from(perm));
    #[cfg(all(test, debug_assertions, unix))]
    native_permission_fixture_record_return(&result);
    return result;
  }
  #[cfg(all(test, debug_assertions, unix))]
  native_permission_fixture_count_stock_prompt();
  let perm = match args.name.as_ref() {
    "read" => permissions.request_read(args.path.as_deref())?,
    "write" => permissions.request_write(args.path.as_deref())?,
    "net" => permissions.request_net(args.host.as_deref())?,
    "env" => permissions.request_env(args.variable.as_deref()),
    "sys" => permissions.request_sys(args.kind.as_deref())?,
    "run" => permissions.request_run(args.command.as_deref())?,
    "ffi" => permissions.request_ffi(args.path.as_deref())?,
    "import" => permissions.request_import(args.host.as_deref())?,
    _ => return Err(PermissionError::InvalidPermissionName(args.name)),
  };
  let result = Ok(PermissionStatus::from(perm));
  #[cfg(all(test, debug_assertions, unix))]
  native_permission_fixture_record_return(&result);
  result
}

#[cfg(all(test, debug_assertions, unix))]
mod native_capsec_tests {
  use std::collections::BTreeSet;
  use std::path::Path;
  use std::path::PathBuf;
  use std::process::Command;
  use std::process::Stdio;
  use std::sync::Arc;
  use std::time::Duration;
  use std::time::Instant;
  use std::time::SystemTime;
  use std::time::UNIX_EPOCH;

  use deno_core::JsRuntime;
  use deno_core::RuntimeOptions;
  use deno_core::serde_json;
  use deno_core::v8;
  use serde::Deserialize;
  use serde::Serialize;

  use super::NativePermissionFixtureLocalContext;
  use super::deno_permissions;
  use super::native_permission_fixture_fallback_counters;
  use super::native_permission_fixture_reset_fallback_counters;

  const OPERATION_ENV: &str = "ODEN_REV2_PERMISSION_FIXTURE_OPERATION";
  const CASE_ENV: &str = "ODEN_REV2_PERMISSION_FIXTURE_CASE_KIND";
  const TARGET_ENV: &str = "ODEN_REV2_PERMISSION_FIXTURE_TARGET";
  const CHILD_MODE_ENV: &str =
    "ODEN_REV2_PERMISSION_FIXTURE_INTERNAL_CHILD_MODE";
  const ROOT_ENV: &str = "ODEN_REV2_PERMISSION_FIXTURE_INTERNAL_ROOT";
  const RESULT_ENV: &str = "ODEN_REV2_PERMISSION_FIXTURE_INTERNAL_RESULT";
  const TEST_NAME: &str = "ops::permissions::native_capsec_tests::rev2_dynamic_permission_fixture_case";
  const REPORT_PREFIX: &str = "ODEN_REV2_DYNAMIC_PERMISSION_FIXTURE_REPORT ";
  const MODES: [&str; 3] = ["permissive", "audit", "enforce"];

  const QUERY_CASES: [&str; 24] = [
    "alternative-branch:effect-10-run:run:authorized",
    "alternative-branch:effect-10-run:run:denied",
    "alternative-branch:effect-11-sys:read:authorized",
    "alternative-branch:effect-11-sys:read:denied",
    "alternative-branch:effect-3-ffi:load:authorized",
    "alternative-branch:effect-3-ffi:load:denied",
    "alternative-branch:effect-4-fs:read:authorized",
    "alternative-branch:effect-4-fs:read:denied",
    "alternative-branch:effect-5-fs:write:authorized",
    "alternative-branch:effect-5-fs:write:denied",
    "alternative-cross-action-denial",
    "alternative-no-unselected-branch-commit",
    "authorable-cross-action-denial",
    "authorable-missing-principal-denial",
    "authorable-negative",
    "authorable-no-user-denial",
    "authorable-positive",
    "authorable-quarantine-denial",
    "authorable-wrong-principal-denial",
    "malformed-resource-refusal",
    "staged-barrier:authorization",
    "staged-barrier:cancellation",
    "staged-barrier:cleanup",
    "staged-barrier:revocation",
  ];
  const REQUEST_CASES: [&str; 20] = [
    "alternative-branch:effect-11-sys:read:authorized",
    "alternative-branch:effect-11-sys:read:denied",
    "alternative-branch:effect-4-fs:read:authorized",
    "alternative-branch:effect-4-fs:read:denied",
    "alternative-branch:effect-5-fs:write:authorized",
    "alternative-branch:effect-5-fs:write:denied",
    "alternative-cross-action-denial",
    "alternative-no-unselected-branch-commit",
    "authorable-cross-action-denial",
    "authorable-missing-principal-denial",
    "authorable-negative",
    "authorable-no-user-denial",
    "authorable-positive",
    "authorable-quarantine-denial",
    "authorable-wrong-principal-denial",
    "malformed-resource-refusal",
    "staged-barrier:authorization",
    "staged-barrier:cancellation",
    "staged-barrier:cleanup",
    "staged-barrier:revocation",
  ];
  const REVOKE_CASES: [&str; 24] = [
    "alternative-branch:effect-10-run:run:authorized",
    "alternative-branch:effect-10-run:run:denied",
    "alternative-branch:effect-11-sys:read:authorized",
    "alternative-branch:effect-11-sys:read:denied",
    "alternative-branch:effect-3-ffi:load:authorized",
    "alternative-branch:effect-3-ffi:load:denied",
    "alternative-branch:effect-4-fs:read:authorized",
    "alternative-branch:effect-4-fs:read:denied",
    "alternative-branch:effect-5-fs:write:authorized",
    "alternative-branch:effect-5-fs:write:denied",
    "alternative-cross-action-denial",
    "alternative-no-unselected-branch-commit",
    "authorable-cross-action-denial",
    "authorable-missing-principal-denial",
    "authorable-negative",
    "authorable-no-user-denial",
    "authorable-positive",
    "authorable-quarantine-denial",
    "authorable-wrong-principal-denial",
    "malformed-resource-refusal",
    "staged-barrier:authorization",
    "staged-barrier:cancellation",
    "staged-barrier:cleanup",
    "staged-barrier:revocation",
  ];

  struct TestRoot(PathBuf);

  impl TestRoot {
    fn new() -> Self {
      let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
      let path = std::env::temp_dir().join(format!(
        "oden-rev2-native-permission-fixture-{}-{nonce}",
        std::process::id()
      ));
      std::fs::create_dir(&path).unwrap();
      Self(path)
    }
  }

  impl Drop for TestRoot {
    fn drop(&mut self) {
      let _ = std::fs::remove_dir_all(&self.0);
    }
  }

  #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
  #[serde(rename_all = "camelCase")]
  struct GenerationDelta {
    negative: i64,
    policy: i64,
    revocation: i64,
    session: i64,
  }

  #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
  #[serde(rename_all = "camelCase")]
  struct RowDelta {
    session_positive: i64,
    session_revocation: i64,
  }

  #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
  #[serde(rename_all = "camelCase")]
  struct FallbackCounters {
    mode_fallback: u64,
    stock: u64,
    rev1: u64,
    stock_prompt: u64,
  }

  #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
  struct ModeMap<T> {
    permissive: T,
    audit: T,
    enforce: T,
  }

  impl<T> ModeMap<T> {
    fn from_modes(mut take: impl FnMut(&str) -> T) -> Self {
      Self {
        permissive: take("permissive"),
        audit: take("audit"),
        enforce: take("enforce"),
      }
    }
  }

  #[derive(Debug, Deserialize)]
  #[serde(tag = "kind", rename_all = "camelCase")]
  enum JsCallResult {
    State { state: String, partial: bool },
    Refused { name: String, message: String },
  }

  #[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
  #[serde(rename_all = "camelCase")]
  struct ChildResult {
    selected_branch: String,
    selected_capability: String,
    public_state: String,
    refusal_reason: Option<String>,
    generation_delta: GenerationDelta,
    row_delta: RowDelta,
    unselected_session_rows_changed: u64,
    phase_trace: Vec<String>,
    fallback_counters: FallbackCounters,
  }

  #[derive(Serialize)]
  #[serde(rename_all = "camelCase")]
  struct NativeReport {
    schema: &'static str,
    case_id: String,
    operation_id: String,
    edge_id: String,
    requirement_id: String,
    case_kind: String,
    target: String,
    modes: [&'static str; 3],
    assertions: Vec<&'static str>,
    baseline_plan: &'static str,
    selected_branch: String,
    selected_capability: String,
    public_states: ModeMap<String>,
    refusal_reasons: ModeMap<Option<String>>,
    generation_delta: GenerationDelta,
    row_delta: RowDelta,
    unselected_session_rows_changed: u64,
    phase_traces: ModeMap<Vec<String>>,
    fallback_counters: ModeMap<FallbackCounters>,
    context_binding: &'static str,
    executed: bool,
    selected_test_count: u64,
    native_release_execution: bool,
    authority: &'static str,
  }

  fn supported_case(operation: &str, case_kind: &str) -> bool {
    match operation {
      "query" => QUERY_CASES.contains(&case_kind),
      "request" => REQUEST_CASES.contains(&case_kind),
      "revoke" => REVOKE_CASES.contains(&case_kind),
      _ => false,
    }
  }

  fn is_refused(case_kind: &str) -> bool {
    matches!(
      case_kind,
      "malformed-resource-refusal"
        | "authorable-missing-principal-denial"
        | "staged-barrier:cancellation"
    )
  }

  fn is_effect_bound_revocation(operation: &str, case_kind: &str) -> bool {
    matches!(operation, "query" | "request")
      && case_kind == "staged-barrier:revocation"
  }

  fn has_mode_fallback(case_kind: &str) -> bool {
    matches!(
      case_kind,
      "alternative-cross-action-denial"
        | "authorable-cross-action-denial"
        | "authorable-wrong-principal-denial"
    )
  }

  fn is_authorized(case_kind: &str) -> bool {
    case_kind == "authorable-positive"
      || case_kind == "staged-barrier:cleanup"
      || case_kind == "alternative-no-unselected-branch-commit"
      || (case_kind.starts_with("alternative-branch:")
        && case_kind.ends_with(":authorized"))
  }

  fn expected_state(
    operation: &str,
    case_kind: &str,
    mode: &str,
  ) -> &'static str {
    if is_refused(case_kind) {
      "refused"
    } else if case_kind == "alternative-no-unselected-branch-commit"
      && operation == "request"
    {
      "denied"
    } else if is_effect_bound_revocation(operation, case_kind)
      && operation == "request"
    {
      "denied"
    } else if case_kind == "alternative-no-unselected-branch-commit"
      || case_kind == "staged-barrier:revocation"
    {
      "prompt"
    } else if operation == "revoke" {
      "denied"
    } else if is_authorized(case_kind)
      || (has_mode_fallback(case_kind) && mode != "enforce")
    {
      "granted"
    } else {
      "denied"
    }
  }

  fn baseline_plan(operation: &str, case_kind: &str) -> &'static str {
    match case_kind {
      "authorable-missing-principal-denial" => {
        "empty-constrained-principal-set"
      }
      "malformed-resource-refusal" => "present-null-required-sys-kind",
      "alternative-no-unselected-branch-commit" => {
        "exact-selected-and-unrelated-session-revocations-plus-ceiling"
      }
      "staged-barrier:revocation"
        if is_effect_bound_revocation(operation, case_kind) =>
      {
        "zero-static-floor-plus-one-exact-ceiling-root-path-fact-session-positive"
      }
      "staged-barrier:revocation" => "one-exact-session-positive-plus-ceiling",
      "staged-barrier:cancellation" if operation == "revoke" => {
        "one-exact-path-fact-bound-session-positive-plus-static-floor-and-ceiling"
      }
      "staged-barrier:cleanup" if operation == "revoke" => {
        "one-exact-selected-fs-read-static-floor"
      }
      "staged-barrier:cancellation" | "staged-barrier:cleanup" => {
        "one-exact-selected-fs-read-static-floor"
      }
      "staged-barrier:authorization" => {
        "exact-static-floor-plus-process-denial"
      }
      "authorable-no-user-denial" => "explicit-no-user-plus-static-floor",
      "authorable-quarantine-denial" => {
        "quarantine-principal-without-positive-authority"
      }
      "alternative-cross-action-denial"
      | "authorable-cross-action-denial"
      | "authorable-wrong-principal-denial" => {
        "one-unselected-or-wrong-principal-static-floor"
      }
      "authorable-negative" => "exact-static-floor-plus-principal-denial",
      kind
        if kind.starts_with("alternative-branch:")
          && kind.ends_with(":denied") =>
      {
        "exact-static-floor-plus-principal-denial"
      }
      kind if is_authorized(kind) => "one-exact-selected-static-floor",
      _ => "one-exact-selected-principal-denial",
    }
  }

  fn semantic_assertion(operation: &str, case_kind: &str) -> &'static str {
    if case_kind.starts_with("alternative-branch:")
      && case_kind.ends_with(":authorized")
    {
      "selected-alternative-branch-authorized"
    } else if case_kind.starts_with("alternative-branch:")
      && case_kind.ends_with(":denied")
    {
      "selected-alternative-branch-denied"
    } else {
      match case_kind {
        "alternative-cross-action-denial" => {
          "cross-action-authority-denied-selected-branch"
        }
        "alternative-no-unselected-branch-commit" => {
          "unrelated-session-revocation-preserved-by-exact-identity"
        }
        "authorable-cross-action-denial" => {
          "cross-action-authority-does-not-match-selected-capability"
        }
        "authorable-missing-principal-denial" => {
          "missing-constrained-principal-refuses-before-core"
        }
        "authorable-negative" => "negative-stratum-precedes-positive-source",
        "authorable-no-user-denial" => "no-user-attribution-denies",
        "authorable-positive" if operation == "request" => {
          "static-floor-already-granted-request-does-not-mint-session-row"
        }
        "authorable-positive" if operation == "revoke" => {
          "valid-revoke-publishes-one-session-revocation"
        }
        "authorable-positive" => {
          "static-floor-query-is-granted-without-session-mutation"
        }
        "authorable-quarantine-denial" => {
          "quarantine-denies-without-mode-fallback"
        }
        "authorable-wrong-principal-denial" => {
          "wrong-principal-positive-does-not-authorize-actor"
        }
        "malformed-resource-refusal" => {
          "malformed-resource-refuses-before-session-transaction"
        }
        "staged-barrier:authorization" => {
          "negative-reentry-precedes-public-result-and-overlay-publication"
        }
        "staged-barrier:cancellation" => {
          "cancellation-releases-retained-fs-descriptor-ownership-without-result-or-publication"
        }
        "staged-barrier:cleanup" => {
          "normal-cleanup-releases-retained-fs-descriptor-ownership-before-v8-delivery"
        }
        "staged-barrier:revocation"
          if is_effect_bound_revocation(operation, case_kind) =>
        {
          "effect-bound-revocation-stales-batch-and-replays-from-initial"
        }
        "staged-barrier:revocation" => {
          "revoke-publication-rechecks-proposed-negative-before-result"
        }
        _ => panic!("closed case list omitted a semantic assertion"),
      }
    }
  }

  fn lifecycle_descriptor_count(operation: &str, case_kind: &str) -> usize {
    if operation == "revoke" && case_kind == "staged-barrier:cancellation" {
      11
    } else {
      7
    }
  }

  fn expected_trace(
    operation: &str,
    case_kind: &str,
    branch: &str,
    capability: &str,
    state: &str,
  ) -> Vec<String> {
    let mut trace = vec![
      format!("op-entered:{operation}"),
      format!("branch-selected:{branch}"),
      format!("capability-selected:{capability}"),
    ];
    if case_kind == "malformed-resource-refusal" {
      trace.extend([
        "descriptor-refused:required-nonempty-kind".to_string(),
        "op-returned:refused".to_string(),
      ]);
      return trace;
    }
    trace.push("actors-capture-attempted".to_string());
    if case_kind == "authorable-missing-principal-denial" {
      trace.push("op-returned:refused".to_string());
      return trace;
    }
    trace.extend([
      "actors-validated".to_string(),
      "host-effect-retained".to_string(),
    ]);
    let effect_bound_revocation =
      is_effect_bound_revocation(operation, case_kind);
    let lifecycle = effect_bound_revocation
      || matches!(
        case_kind,
        "staged-barrier:cancellation" | "staged-barrier:cleanup"
      );
    if lifecycle {
      trace.push(format!(
        "host-descriptors-retained:{}",
        lifecycle_descriptor_count(operation, case_kind)
      ));
    }
    trace.extend([
      "phase-entered:initial-query-or-request".to_string(),
      "phase-completed:initial-query-or-request".to_string(),
    ]);
    if case_kind == "staged-barrier:cancellation" {
      match operation {
        "query" => trace
          .push("cancellation-observed:before-result-production".to_string()),
        "request" => trace.extend([
          "phase-entered:already-granted-check".to_string(),
          "phase-completed:already-granted-check".to_string(),
          "cancellation-observed:before-result-production".to_string(),
        ]),
        "revoke" => trace.extend([
          "authority-transaction-proposed".to_string(),
          "cancellation-observed:before-overlay-publication".to_string(),
          "authority-transaction-discarded".to_string(),
        ]),
        _ => unreachable!(),
      }
      trace.extend([
        "cleanup-boundary-entered".to_string(),
        format!(
          "host-descriptors-released:{}",
          lifecycle_descriptor_count(operation, case_kind)
        ),
        "host-effect-released".to_string(),
        "cleanup-completed".to_string(),
        "op-returned:refused".to_string(),
      ]);
      return trace;
    }
    if effect_bound_revocation {
      if operation == "request" {
        trace.extend([
          "phase-entered:already-granted-check".to_string(),
          "phase-completed:already-granted-check".to_string(),
        ]);
      }
      trace.extend([
        "authority-revocation-published".to_string(),
        "phase-entered:result-production".to_string(),
        "stale-authority-view-observed".to_string(),
        "stale-authority-batch-discarded".to_string(),
        "fresh-authority-batch-replay-captured".to_string(),
        "phase-entered:initial-query-or-request".to_string(),
        "phase-completed:initial-query-or-request".to_string(),
      ]);
      if operation == "request" {
        trace.extend([
          "phase-entered:already-granted-check".to_string(),
          "phase-completed:already-granted-check".to_string(),
        ]);
      }
      trace.extend([
        "phase-entered:result-production".to_string(),
        "phase-completed:result-production".to_string(),
        format!(
          "host-descriptors-released:{}",
          lifecycle_descriptor_count(operation, case_kind)
        ),
        "host-effect-released".to_string(),
        format!("op-returned:{state}"),
      ]);
      return trace;
    }
    match operation {
      "query" => {}
      "request" => trace.extend([
        "phase-entered:already-granted-check".to_string(),
        "phase-completed:already-granted-check".to_string(),
      ]),
      "revoke" => trace.extend([
        "phase-entered:before-overlay-publication".to_string(),
        "phase-completed:before-overlay-publication".to_string(),
      ]),
      _ => unreachable!(),
    }
    trace.extend([
      "phase-entered:result-production".to_string(),
      "phase-completed:result-production".to_string(),
    ]);
    if operation == "revoke" {
      trace.push("authority-publication-completed".to_string());
    }
    if case_kind == "staged-barrier:cleanup" {
      trace.extend([
        "cleanup-boundary-entered".to_string(),
        format!(
          "host-descriptors-released:{}",
          lifecycle_descriptor_count(operation, case_kind)
        ),
        "host-effect-released".to_string(),
        "cleanup-completed".to_string(),
        format!("op-returned:{state}"),
      ]);
      return trace;
    }
    trace.extend([
      "host-effect-released".to_string(),
      format!("op-returned:{state}"),
    ]);
    trace
  }

  fn difference(after: u64, before: u64) -> i64 {
    i64::try_from(after).unwrap() - i64::try_from(before).unwrap()
  }

  fn count_difference(after: usize, before: usize) -> i64 {
    i64::try_from(after).unwrap() - i64::try_from(before).unwrap()
  }

  fn run_registered_op(
    operation: &str,
    fixture: &::deno_permissions::OdenRev2PermissionFixtureContext,
  ) -> JsCallResult {
    let tokio_runtime = tokio::runtime::Builder::new_current_thread()
      .enable_all()
      .build()
      .unwrap();
    let _enter = tokio_runtime.enter();
    let mut runtime = JsRuntime::new(RuntimeOptions {
      extensions: vec![deno_permissions::init()],
      ..Default::default()
    });
    {
      let state = runtime.op_state();
      let mut state = state.borrow_mut();
      state.put(::deno_permissions::OdenRev2ProcessMode::Rev2Installed);
      state.put(NativePermissionFixtureLocalContext {
        authority: fixture.authority.clone(),
        call: fixture.fixture_call(),
      });
      let parser = ::deno_permissions::RuntimePermissionDescriptorParser::new(
        sys_traits::impls::RealSys,
      );
      state.put(::deno_permissions::PermissionsContainer::new(
        Arc::new(parser),
        ::deno_permissions::Permissions::none_without_prompt(),
      ));
    }
    let descriptor = serde_json::to_string(&fixture.descriptor).unwrap();
    let source = format!(
      r#"JSON.stringify((() => {{
        try {{
          const value = Deno.core.ops.op_{operation}_permission({descriptor});
          return {{ kind: "state", state: value.state, partial: value.partial }};
        }} catch (error) {{
          return {{
            kind: "refused",
            name: String(error?.name ?? ""),
            message: String(error?.message ?? error),
          }};
        }}
      }})())"#
    );
    let value = runtime
      .execute_script("<rev2-native-permission-fixture>", source)
      .unwrap();
    let encoded = {
      deno_core::scope!(scope, runtime);
      let value = v8::Local::new(scope, value);
      value
        .to_string(scope)
        .expect("fixture result is a JSON string")
        .to_rust_string_lossy(scope)
    };
    serde_json::from_str(&encoded).unwrap()
  }

  fn expected_refusal(case_kind: &str) -> Option<(&'static str, &'static str)> {
    match case_kind {
      "malformed-resource-refusal" => Some((
        "Rev2 permission descriptor is invalid: kind must be nonempty",
        "descriptor-invalid:kind-must-be-nonempty",
      )),
      "authorable-missing-principal-denial" => Some((
        "Rev2 permission protocol refused: empty constrainedPrincipals",
        "protocol-refused:empty-constrained-principals",
      )),
      "staged-barrier:cancellation" => Some((
        "Rev2 permission protocol refused: OD-CAP-REV2-FIXTURE-CANCELLED",
        "fixture-cancelled-before-delivery-or-publication",
      )),
      _ => None,
    }
  }

  fn exact_set(values: &[String]) -> BTreeSet<&str> {
    values.iter().map(String::as_str).collect()
  }

  fn execute_child_case(
    operation: &str,
    case_kind: &str,
    mode: &str,
    root: &Path,
  ) -> ChildResult {
    let fixture =
      ::deno_permissions::oden_capsec_rev2_permission_fixture_context(
        operation, case_kind, mode, root,
      )
      .unwrap();
    if operation == "revoke" && case_kind == "staged-barrier:cancellation" {
      assert_eq!(
        fixture.exact_selected_floor_ceiling_and_root_binding_counts(),
        (1, 1, 1),
        "revoke lifecycle baseline lacks its exact authenticated path ceiling"
      );
    } else if is_effect_bound_revocation(operation, case_kind) {
      assert_eq!(
        fixture.exact_selected_floor_ceiling_and_root_binding_counts(),
        (0, 1, 1),
        "effect-bound revocation baseline must have zero static floor and one exact authenticated path ceiling"
      );
    }
    if case_kind == "alternative-no-unselected-branch-commit" {
      ::deno_permissions::oden_capsec_rev2_permission_fixture_seed_revocation(
        &fixture,
      );
    } else if case_kind == "staged-barrier:revocation"
      || (operation == "revoke" && case_kind == "staged-barrier:cancellation")
    {
      ::deno_permissions::oden_capsec_rev2_permission_fixture_seed_positive(
        &fixture,
      );
    }
    ::deno_permissions::oden_capsec_rev2_permission_fixture_set_actors(Some(
      &fixture,
    ));
    native_permission_fixture_reset_fallback_counters();
    let before =
      ::deno_permissions::oden_capsec_rev2_permission_fixture_observe(&fixture);
    let call = run_registered_op(operation, &fixture);
    let after =
      ::deno_permissions::oden_capsec_rev2_permission_fixture_observe(&fixture);
    let (
      trace,
      active_host_effects,
      mode_fallback_count,
      retained_descriptor_count,
      released_descriptor_count,
      active_retained_descriptors,
      actor_captures,
    ) = ::deno_permissions::oden_capsec_rev2_permission_fixture_take_trace();
    let native_fallback = native_permission_fixture_fallback_counters();
    ::deno_permissions::oden_capsec_rev2_permission_fixture_set_actors(None);

    assert_eq!(active_host_effects, 0, "host effect lease leaked");
    assert_eq!(
      active_retained_descriptors, 0,
      "retained descriptor ownership leaked"
    );
    let lifecycle = is_effect_bound_revocation(operation, case_kind)
      || matches!(
        case_kind,
        "staged-barrier:cancellation" | "staged-barrier:cleanup"
      );
    assert_eq!(
      retained_descriptor_count,
      if lifecycle {
        lifecycle_descriptor_count(operation, case_kind)
      } else {
        0
      },
      "retained descriptor ledger drifted"
    );
    assert_eq!(
      released_descriptor_count, retained_descriptor_count,
      "retained descriptor ownership was not released exactly once"
    );
    assert_eq!(
      fixture.lifecycle_hook_consumed(),
      true,
      "the exact fixture call binding was not consumed"
    );
    if lifecycle {
      assert_eq!(fixture.selected_branch, "permission.read.scoped/2");
      assert_eq!(fixture.selected_capability, "fs:read");
    }
    assert_eq!(
      actor_captures,
      if case_kind == "malformed-resource-refusal" {
        0
      } else {
        1
      },
      "actor capture count drifted"
    );
    let expected_state = expected_state(operation, case_kind, mode);
    let (public_state, refusal_reason) = match call {
      JsCallResult::State { state, partial } => {
        assert!(
          expected_refusal(case_kind).is_none(),
          "refusal case returned a public state"
        );
        assert!(!partial, "fixture singleton unexpectedly became partial");
        assert_eq!(state, expected_state);
        (state, None)
      }
      JsCallResult::Refused { name, message } => {
        let (expected_message, stable_reason) =
          expected_refusal(case_kind).expect("unexpected native refusal");
        assert_eq!(name, "Error", "native refusal class drifted");
        assert_eq!(message, expected_message, "native refusal text drifted");
        assert_eq!(expected_state, "refused");
        ("refused".to_string(), Some(stable_reason.to_string()))
      }
    };

    let generation_delta = GenerationDelta {
      negative: difference(
        after.negative_overlay_generation,
        before.negative_overlay_generation,
      ),
      policy: difference(
        after.policy_snapshot_generation,
        before.policy_snapshot_generation,
      ),
      revocation: difference(
        after.revocation_generation,
        before.revocation_generation,
      ),
      session: difference(
        after.session_overlay_generation,
        before.session_overlay_generation,
      ),
    };
    let row_delta = RowDelta {
      session_positive: count_difference(
        after.session_positive_row_ids.len(),
        before.session_positive_row_ids.len(),
      ),
      session_revocation: count_difference(
        after.session_revocation_row_ids.len(),
        before.session_revocation_row_ids.len(),
      ),
    };
    let revoke_mutation = operation == "revoke"
      && !is_refused(case_kind)
      && case_kind != "alternative-no-unselected-branch-commit";
    let revocation_mutation =
      revoke_mutation || is_effect_bound_revocation(operation, case_kind);
    let expected_generation = GenerationDelta {
      negative: i64::from(revocation_mutation),
      policy: 0,
      revocation: i64::from(revocation_mutation),
      session: i64::from(revocation_mutation),
    };
    let expected_rows = RowDelta {
      session_positive: if case_kind == "staged-barrier:revocation" {
        -1
      } else {
        0
      },
      session_revocation: if revocation_mutation {
        if case_kind == "authorable-wrong-principal-denial" {
          2
        } else {
          1
        }
      } else {
        0
      },
    };
    assert_eq!(generation_delta, expected_generation);
    assert_eq!(row_delta, expected_rows);
    for observation in [&before, &after] {
      assert!(
        observation.unexpected_session_positive_row_ids.is_empty(),
        "session positive row does not exactly match a selected selector/principal"
      );
      assert!(
        observation.unexpected_session_revocation_row_ids.is_empty(),
        "session revocation row is neither the exact selected selector/principal nor the exact unrelated baseline; actual={:?}; expected={:?}",
        observation.unexpected_session_revocation_rows,
        observation.expected_selected_session_revocation_selectors,
      );
    }
    assert_eq!(
      before.expected_selected_session_positive_row_ids,
      after.expected_selected_session_positive_row_ids
    );
    assert_eq!(
      before.expected_selected_session_revocation_row_ids,
      after.expected_selected_session_revocation_row_ids
    );
    assert_eq!(
      before.expected_unrelated_session_revocation_row_id,
      after.expected_unrelated_session_revocation_row_id
    );
    assert_eq!(
      before.negative_overlay_row_ids,
      after.negative_overlay_row_ids
    );
    assert_eq!(before.revocation_row_ids, after.revocation_row_ids);
    if operation == "revoke" && case_kind == "staged-barrier:cancellation" {
      assert_eq!(before.selected_session_positive_row_ids.len(), 1);
      assert_eq!(
        before.selected_session_positive_row_ids,
        before.expected_selected_session_positive_row_ids,
        "cancellation baseline positive is not the exact runtime-selector pair"
      );
      assert_eq!(
        before.session_positive_row_ids,
        before.selected_session_positive_row_ids,
        "cancellation baseline is not the only session positive"
      );
      assert_eq!(
        before.selected_session_positive_row_ids,
        after.selected_session_positive_row_ids,
        "cancelled revoke changed the exact positive row"
      );
      assert!(before.session_revocation_row_ids.is_empty());
      assert!(after.session_revocation_row_ids.is_empty());
    } else if case_kind == "alternative-no-unselected-branch-commit" {
      assert_eq!(before.session_positive_row_ids.len(), 0);
      assert_eq!(before.session_revocation_row_ids.len(), 2);
      assert_eq!(before.selected_session_revocation_row_ids.len(), 1);
      assert_eq!(before.unrelated_session_revocation_row_ids.len(), 1);
      assert_eq!(
        before.selected_session_revocation_row_ids,
        before.expected_selected_session_revocation_row_ids,
        "selected baseline row ID is not derived from the exact runtime selector, owner, actor, and snapshot"
      );
      assert_eq!(
        before.unrelated_session_revocation_row_ids,
        vec![before.expected_unrelated_session_revocation_row_id.clone()],
        "unrelated baseline row ID is not the exact derived identity"
      );
      assert_eq!(
        before.selected_session_revocation_row_ids,
        after.selected_session_revocation_row_ids,
        "selected revocation identity changed"
      );
      assert_eq!(
        before.unrelated_session_revocation_row_ids,
        after.unrelated_session_revocation_row_ids,
        "unrelated revocation identity changed"
      );
      assert_eq!(
        before.unselected_session_revocation_row_id,
        after.unselected_session_revocation_row_id
      );
      assert!(
        before.unselected_session_revocation_row_id.is_some(),
        "unselected revocation baseline is absent"
      );
      assert_eq!(
        exact_set(&before.session_revocation_row_ids),
        exact_set(&after.session_revocation_row_ids),
        "selected or unrelated revocation identity changed"
      );
    } else if revocation_mutation {
      let expected_selected_revocations =
        usize::try_from(expected_rows.session_revocation).unwrap();
      assert!(before.selected_session_revocation_row_ids.is_empty());
      assert_eq!(
        after.selected_session_revocation_row_ids.len(),
        expected_selected_revocations,
        "revocation did not publish every and only exact selected principal selector"
      );
      assert_eq!(
        after.selected_session_revocation_row_ids,
        after.expected_selected_session_revocation_row_ids,
        "revocation row IDs are not derived from the exact runtime selector, owner, actors, and snapshot"
      );
      assert!(before.unrelated_session_revocation_row_ids.is_empty());
      assert!(after.unrelated_session_revocation_row_ids.is_empty());
      assert_eq!(
        after.session_revocation_row_ids,
        after.selected_session_revocation_row_ids,
        "revocation published a non-selected row"
      );
      if case_kind == "staged-barrier:revocation" {
        assert_eq!(before.selected_session_positive_row_ids.len(), 1);
        assert!(after.selected_session_positive_row_ids.is_empty());
        assert_eq!(
          before.selected_session_positive_row_ids,
          before.expected_selected_session_positive_row_ids,
          "staged positive row ID is not the exact runtime-selector pair"
        );
        assert_eq!(
          before.session_positive_row_ids,
          before.selected_session_positive_row_ids,
          "staged positive is not the exact selected positive pair"
        );
      } else {
        assert!(before.selected_session_positive_row_ids.is_empty());
        assert!(after.selected_session_positive_row_ids.is_empty());
      }
    } else if !revocation_mutation {
      assert_eq!(
        exact_set(&before.session_positive_row_ids),
        exact_set(&after.session_positive_row_ids)
      );
      assert_eq!(
        exact_set(&before.session_revocation_row_ids),
        exact_set(&after.session_revocation_row_ids)
      );
    }

    let expected_mode_fallback =
      u64::from(has_mode_fallback(case_kind) && mode != "enforce");
    let fallback_counters = FallbackCounters {
      mode_fallback: mode_fallback_count,
      stock: native_fallback.stock,
      rev1: native_fallback.rev1,
      stock_prompt: native_fallback.stock_prompt,
    };
    assert_eq!(
      fallback_counters,
      FallbackCounters {
        mode_fallback: expected_mode_fallback,
        stock: 0,
        rev1: 0,
        stock_prompt: 0,
      }
    );
    assert_eq!(
      trace,
      expected_trace(
        operation,
        case_kind,
        fixture.selected_branch,
        fixture.selected_capability,
        &public_state,
      )
    );
    ChildResult {
      selected_branch: fixture.selected_branch.to_string(),
      selected_capability: fixture.selected_capability.to_string(),
      public_state,
      refusal_reason,
      generation_delta,
      row_delta,
      unselected_session_rows_changed: 0,
      phase_trace: trace,
      fallback_counters,
    }
  }

  fn run_child(
    operation: &str,
    case_kind: &str,
    target: &str,
    mode: &str,
    root: &Path,
  ) -> ChildResult {
    let result_path = root.join(format!("{mode}.result.json"));
    let stdout_path = root.join(format!("{mode}.stdout"));
    let stderr_path = root.join(format!("{mode}.stderr"));
    let mode_root = root.join(mode);
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
      .args([TEST_NAME, "--exact", "--nocapture", "--test-threads=1"])
      .stdout(Stdio::from(std::fs::File::create(&stdout_path).unwrap()))
      .stderr(Stdio::from(std::fs::File::create(&stderr_path).unwrap()));
    for (name, _) in std::env::vars_os() {
      if name.to_string_lossy().starts_with("ODEN_CAPSEC_")
        || name
          .to_string_lossy()
          .starts_with("ODEN_REV2_PERMISSION_FIXTURE_")
      {
        command.env_remove(name);
      }
    }
    command
      .env(OPERATION_ENV, operation)
      .env(CASE_ENV, case_kind)
      .env(TARGET_ENV, target)
      .env(CHILD_MODE_ENV, mode)
      .env(ROOT_ENV, &mode_root)
      .env(RESULT_ENV, &result_path);
    let mut child = command.spawn().unwrap();
    let deadline = Instant::now() + Duration::from_secs(60);
    let (status, timed_out) = loop {
      if let Some(status) = child.try_wait().unwrap() {
        break (status, false);
      }
      if Instant::now() >= deadline {
        let _ = child.kill();
        break (child.wait().unwrap(), true);
      }
      std::thread::sleep(Duration::from_millis(10));
    };
    let stdout = std::fs::read_to_string(&stdout_path).unwrap();
    let stderr = std::fs::read_to_string(&stderr_path).unwrap();
    assert!(
      !timed_out && status.success(),
      "native fixture child {mode} failed (timed_out={timed_out}, status={status}):\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    serde_json::from_slice(&std::fs::read(result_path).unwrap()).unwrap()
  }

  fn edge_id(operation: &str) -> String {
    format!("native-op:runtime/ops/permissions.rs#op_{operation}_permission")
  }

  #[test]
  fn rev2_dynamic_permission_fixture_case() {
    let operation =
      std::env::var(OPERATION_ENV).expect("fixture operation is required");
    let case_kind =
      std::env::var(CASE_ENV).expect("fixture case kind is required");
    let target = std::env::var(TARGET_ENV).expect("fixture target is required");
    assert!(
      supported_case(&operation, &case_kind),
      "unsupported native fixture operation/case pair"
    );
    assert_eq!(
      target,
      ::deno_permissions::oden_capsec_rev2_permission_fixture_compiled_target(),
      "fixture target must exactly equal the compiled target"
    );
    if let Ok(mode) = std::env::var(CHILD_MODE_ENV) {
      assert!(MODES.contains(&mode.as_str()), "child mode is not closed");
      let root = PathBuf::from(std::env::var_os(ROOT_ENV).unwrap());
      let result = execute_child_case(&operation, &case_kind, &mode, &root);
      let result_path = PathBuf::from(std::env::var_os(RESULT_ENV).unwrap());
      std::fs::write(result_path, serde_json::to_vec(&result).unwrap())
        .unwrap();
      return;
    }

    let root = TestRoot::new();
    let results = ModeMap::from_modes(|mode| {
      run_child(&operation, &case_kind, &target, mode, &root.0)
    });
    for result in [&results.audit, &results.enforce] {
      assert_eq!(result.selected_branch, results.permissive.selected_branch);
      assert_eq!(
        result.selected_capability,
        results.permissive.selected_capability
      );
      assert_eq!(result.generation_delta, results.permissive.generation_delta);
      assert_eq!(result.row_delta, results.permissive.row_delta);
      assert_eq!(result.unselected_session_rows_changed, 0);
    }
    let assertions = vec![
      "exact-generated-branch-and-capability",
      "public-state-matches-each-mode",
      "exact-session-selector-row-id-and-generation-delta",
      "unselected-session-rows-unchanged",
      "phase-trace-is-exact",
      "stock-rev1-and-prompt-fallback-not-entered",
      semantic_assertion(&operation, &case_kind),
    ];
    let edge_id = edge_id(&operation);
    let report = NativeReport {
      schema: "oden/capsec-dynamic-permission-fixture-report/2",
      case_id: format!("native-permission:{operation}:{case_kind}"),
      operation_id: operation.clone(),
      requirement_id: format!("fixture-requirement:{edge_id}:complete"),
      edge_id,
      case_kind,
      target,
      modes: MODES,
      assertions,
      baseline_plan: baseline_plan(
        &operation,
        &std::env::var(CASE_ENV).expect("fixture case remains present"),
      ),
      selected_branch: results.permissive.selected_branch.clone(),
      selected_capability: results.permissive.selected_capability.clone(),
      public_states: ModeMap {
        permissive: results.permissive.public_state.clone(),
        audit: results.audit.public_state.clone(),
        enforce: results.enforce.public_state.clone(),
      },
      refusal_reasons: ModeMap {
        permissive: results.permissive.refusal_reason.clone(),
        audit: results.audit.refusal_reason.clone(),
        enforce: results.enforce.refusal_reason.clone(),
      },
      generation_delta: results.permissive.generation_delta.clone(),
      row_delta: results.permissive.row_delta.clone(),
      unselected_session_rows_changed: 0,
      phase_traces: ModeMap {
        permissive: results.permissive.phase_trace.clone(),
        audit: results.audit.phase_trace.clone(),
        enforce: results.enforce.phase_trace.clone(),
      },
      fallback_counters: ModeMap {
        permissive: results.permissive.fallback_counters.clone(),
        audit: results.audit.fallback_counters.clone(),
        enforce: results.enforce.fallback_counters.clone(),
      },
      context_binding: "test-feature-opstate-only",
      executed: true,
      selected_test_count: 1,
      native_release_execution: false,
      authority: "development-fixture-execution-only",
    };
    eprintln!("{REPORT_PREFIX}{}", serde_json::to_string(&report).unwrap());
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn descriptor_fields_preserve_absent_null_and_string_presence() {
    let absent: PermissionArgs =
      deno_core::serde_json::from_str(r#"{"name":"sys","kind":"cpus"}"#)
        .unwrap();
    assert!(!absent.path.is_present());
    assert!(absent.kind.is_present());
    assert_eq!(absent.kind.as_deref(), Some("cpus"));

    let present_null: PermissionArgs = deno_core::serde_json::from_str(
      r#"{"name":"sys","kind":"cpus","path":null}"#,
    )
    .unwrap();
    assert!(present_null.path.is_present());
    assert_eq!(present_null.path.as_deref(), None);

    assert!(
      deno_core::serde_json::from_str::<PermissionArgs>(
        r#"{"name":"sys","kind":"cpus","unknown":true}"#,
      )
      .is_err()
    );
    assert!(
      deno_core::serde_json::from_str::<PermissionArgs>(
        r#"{"name":"sys","kind":"cpus","path":7}"#,
      )
      .is_err()
    );
  }

  #[test]
  fn installed_rev2_refusal_propagates_without_rev1_fallback() {
    let result = resolve_rev2_permission::<PermissionState>(Some(Err(
      PermissionError::Rev2("generated refusal".to_string()),
    )));
    assert!(matches!(
      result,
      Err(PermissionError::Rev2(reason)) if reason == "generated refusal"
    ));
  }

  #[test]
  fn absent_rev2_context_selects_the_existing_path() {
    assert!(
      resolve_rev2_permission::<PermissionState>(None)
        .unwrap()
        .is_none()
    );
  }

  #[test]
  fn rev2_opstate_marker_cannot_select_a_different_process_mode() {
    let mut state = OpState::new(None);
    assert!(resolve_rev2_context(&state).unwrap().is_none());
    state.put(::deno_permissions::OdenRev2ProcessMode::Rev2Installed);
    assert!(matches!(
      resolve_rev2_context(&state),
      Err(PermissionError::Rev2(reason))
        if reason == "OD-CAP-REV2-OPSTATE-MODE-MISMATCH"
    ));
  }

  #[test]
  fn installed_rev2_opstate_requires_the_exact_global_arc_and_marker() {
    use ::deno_permissions::OdenRev2ProcessMode;
    let validate = |state_mode, global, state, same| {
      ::deno_permissions::oden_capsec_rev2_validate_op_state_binding(
        OdenRev2ProcessMode::Rev2Installed,
        state_mode,
        global,
        state,
        same,
      )
    };
    assert_eq!(
      validate(None, true, true, true),
      Err("OD-CAP-REV2-OPSTATE-MODE-MISMATCH")
    );
    assert_eq!(
      validate(Some(OdenRev2ProcessMode::Rev2Installed), false, true, true),
      Err("OD-CAP-REV2-GLOBAL-CONTEXT-MISSING")
    );
    assert_eq!(
      validate(Some(OdenRev2ProcessMode::Rev2Installed), true, false, false),
      Err("OD-CAP-REV2-OPSTATE-CONTEXT-MISSING")
    );
    assert_eq!(
      validate(Some(OdenRev2ProcessMode::Rev2Installed), true, true, false),
      Err("OD-CAP-REV2-OPSTATE-CONTEXT-MISMATCH")
    );
    assert_eq!(
      validate(Some(OdenRev2ProcessMode::Rev2Installed), true, true, true),
      Ok(true)
    );
  }
}

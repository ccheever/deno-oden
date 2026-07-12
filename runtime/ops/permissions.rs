// Copyright 2018-2026 the Deno authors. MIT license.

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
    if let Some(context) =
      ::deno_permissions::oden_capsec_rev2_runtime_authority_context()
    {
      state.put(context);
    }
  },
);

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PermissionArgs {
  name: String,
  path: Option<String>,
  host: Option<String>,
  variable: Option<String>,
  kind: Option<String>,
  command: Option<String>,
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
  let context = state
    .try_borrow::<std::sync::Arc<
      ::deno_permissions::OdenRev2RuntimeAuthorityContext,
    >>()
    .cloned()?;
  let permissions = state.borrow::<PermissionsContainer>();
  Some(
    ::deno_permissions::oden_capsec_rev2_permission_operation(
      context.as_ref(),
      permissions,
      operation,
      &dynamic_descriptor(args),
    )
    .map_err(|error| PermissionError::Rev2(error.to_string())),
  )
}

#[op2(stack_trace)]
pub fn op_query_permission(
  state: &mut OpState,
  #[serde] args: PermissionArgs,
) -> Result<PermissionStatus, PermissionError> {
  let rev2 = rev2_permission(
    state,
    &args,
    ::deno_permissions::OdenRev2PermissionOperation::Query,
  );
  if let Some(permission) = resolve_rev2_permission(rev2)? {
    return Ok(PermissionStatus::from(permission));
  }
  let permissions = state.borrow::<PermissionsContainer>();
  // Validate through the stock descriptor parser first. Layer 2 then
  // overrides the status for a package principal without mutating layer 1.
  let stock = query_permission(permissions, &args)?;
  let perm = ::deno_permissions::oden_capsec_query_dynamic_permission(
    &dynamic_descriptor(&args),
  )
  .unwrap_or(stock);
  Ok(PermissionStatus::from(perm))
}

#[op2(stack_trace)]
pub fn op_revoke_permission(
  state: &mut OpState,
  #[serde] args: PermissionArgs,
) -> Result<PermissionStatus, PermissionError> {
  let rev2 = rev2_permission(
    state,
    &args,
    ::deno_permissions::OdenRev2PermissionOperation::Revoke,
  );
  if let Some(permission) = resolve_rev2_permission(rev2)? {
    return Ok(PermissionStatus::from(permission));
  }
  let permissions = state.borrow::<PermissionsContainer>();
  // Validation only; package revoke is a session overlay and must not narrow
  // the process-global permission object for every other principal.
  let _ = query_permission(permissions, &args)?;
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
  Ok(PermissionStatus::from(perm))
}

#[op2(stack_trace)]
pub fn op_request_permission(
  state: &mut OpState,
  #[serde] args: PermissionArgs,
) -> Result<PermissionStatus, PermissionError> {
  let rev2 = rev2_permission(
    state,
    &args,
    ::deno_permissions::OdenRev2PermissionOperation::Request,
  );
  if let Some(permission) = resolve_rev2_permission(rev2)? {
    return Ok(PermissionStatus::from(permission));
  }
  let permissions = state.borrow::<PermissionsContainer>();
  // Validation only. A package request is decided against its immutable
  // escalation ceiling and can update only its layer-2 session overlay; it
  // never reaches stock request()/the process prompt.
  let _ = query_permission(permissions, &args)?;
  if let Some(perm) = ::deno_permissions::oden_capsec_request_dynamic_permission(
    &dynamic_descriptor(&args),
  ) {
    return Ok(PermissionStatus::from(perm));
  }
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
  Ok(PermissionStatus::from(perm))
}

#[cfg(test)]
mod tests {
  use super::*;

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
}

// Copyright 2018-2026 the Deno authors. MIT license.

//! Oden capsec authority-flow ops (LLP 0001 §Delegation and handles,
//! ENG-23784). The JS-facing surface for handles and attenuators: the
//! `Deno.oden` namespace (installed only when capsec is armed) calls these ops
//! to mint an attenuated handle from a capability it holds, re-attenuate it
//! (`scoped`), open a synchronous possession window on it (`enter`/`exit`),
//! and revoke it (cascading through derived handles).
//!
//! Handles are unforgeable across package boundaries: the host-side table in
//! `deno_permissions::oden_handle` is keyed by an unguessable 128-bit id, and
//! the JS object is only a carrier holding that id under a bootstrap-private
//! Symbol. These ops are additive (Class A) and fully inert when capsec is not
//! armed — every one returns a denial or no-ops through the `deno_permissions`
//! glue's active-arming check.
//! @ref llp/0001-adding-capability-security-to-deno.plan.md

use deno_core::OpState;
use deno_core::op2;
use deno_permissions::PermissionCheckError;

deno_core::extension!(
  deno_oden,
  ops = [
    op_oden_handle_mint,
    op_oden_handle_scoped,
    op_oden_handle_enter,
    op_oden_handle_exit,
    op_oden_handle_revoke,
    op_oden_compartment_endowments,
    op_oden_guard_surface,
    op_oden_guard_deny_only_surface,
    op_oden_record_root_ambient_effect,
    op_oden_check_protected_inspector_stream_use,
    op_oden_attestation,
  ],
);

/// Versioned, compile-time feature attestation consumed by the Oden CLI before
/// selecting this binary as its enforcement backend. Behavioral probes remain
/// defense in depth; this closed feature set prevents a partially patched fork
/// from being certified by one passing env denial. (ENG-23930)
#[op2]
#[string]
pub fn op_oden_attestation() -> &'static str {
  debug_assert_eq!(deno_permissions::ODEN_CAPSEC_PROFILE, "oden/capsec/1.1");
  r#"{"schema":2,"profile":"oden/capsec/1.1","semantics":"oden-capsec-2026-07-10","features":["action-sensitive-env","action-sensitive-network","canonical-fs","closed-op-inventory","compartment-principal-key-v2","default-closed-escape-hatches","layer2-run-fastpath","native-runtime-control-gates","node-http-connect-scheme-closure","protected-metadata-final-peer","resource-ownership","typed-local-import-gate"]}"#
}

/// Default-deny a capability surface that has no safe scoped grant yet.
#[op2(fast, stack_trace)]
pub fn op_oden_guard_surface(
  #[string] family: String,
  #[string] action: String,
  #[string] target: String,
  #[string] api_name: String,
) -> Result<(), PermissionCheckError> {
  deno_permissions::oden_capsec_guard_surface(
    &family, &action, &target, &api_name,
  )
}

/// Rev1.1 native decision op for process-global and diagnostic rows whose
/// initial disposition is deny-only in every mode for package principals.
#[op2(fast, stack_trace)]
pub fn op_oden_guard_deny_only_surface(
  #[string] family: String,
  #[string] action: String,
  #[string] target: String,
  #[string] api_name: String,
) -> Result<(), PermissionCheckError> {
  deno_permissions::oden_capsec_guard_deny_only_surface(
    &family, &action, &target, &api_name,
  )
}

#[op2(fast, stack_trace)]
pub fn op_oden_record_root_ambient_effect(
  #[string] family: String,
  #[string] action: String,
  #[string] target: String,
  #[string] api_name: String,
) -> Result<(), PermissionCheckError> {
  deno_permissions::oden_capsec_record_root_ambient_effect(
    &family, &action, &target, &api_name,
  )
}

#[op2(fast, stack_trace)]
pub fn op_oden_check_protected_inspector_stream_use(
  state: &mut OpState,
  #[string] target: String,
  #[string] api_name: String,
) -> Result<(), PermissionCheckError> {
  check_protected_inspector_stream_use_inner(state, &target, &api_name)
}

fn check_protected_inspector_stream_use_inner(
  state: &mut OpState,
  target: &str,
  api_name: &str,
) -> Result<(), PermissionCheckError> {
  // Preserve the complete Rev1 path when no host-only Rev2 context is
  // installed. Presence selects the single Rev2 actor path: running the Rev1
  // policy matcher first would make Rev2 positive authority depend on a
  // second, incompatible policy engine. The actor still binds and validates
  // the exact structural target and stage before commit. Caller strings never
  // carry policy, effects, requiredForCommit, or a commit permit.
  // @ref LLP 0019#operation-scoped-positive-authority-provenance [implements]
  if let Some(context) =
    state.try_borrow_mut::<deno_permissions::OdenRev2ArmedContext>()
  {
    return context.consume_protected_inspector_stream_stage(target, api_name);
  }
  deno_permissions::oden_capsec_check_protected_inspector_stream_target(
    target, api_name,
  )
}

/// Return the caller-derived endowment descriptor used by trusted bootstrap JS
/// to construct a filtered global record. The live frame is load-bearing: user
/// code may call the installed helper, but it can only obtain its own record.
// @ref LLP 0014#endowment-record-derivation-from-grants [implements]
#[op2(stack_trace)]
#[string]
pub fn op_oden_compartment_endowments() -> Result<String, PermissionCheckError>
{
  deno_permissions::oden_capsec_compartment_endowments()
}

/// Mint an attenuated handle from a capability the acting principal holds
/// (frame-checked). Returns the unguessable handle id as hex. `stack_trace`:
/// the frame capture is what lets `deno_permissions` resolve the minter's
/// principal (row 1) for the frame-check.
#[op2(stack_trace)]
#[string]
pub fn op_oden_handle_mint(
  #[string] capability: String,
) -> Result<String, PermissionCheckError> {
  deno_permissions::oden_capsec_handle_mint(&capability)
}

/// Re-attenuate a possessed handle into a narrower child (only narrows).
/// `stack_trace` attributes the derived handle's minter for audit.
#[op2(stack_trace)]
#[string]
pub fn op_oden_handle_scoped(
  #[string] parent: String,
  #[string] capability: String,
) -> Result<String, PermissionCheckError> {
  deno_permissions::oden_capsec_handle_scoped(&parent, &capability)
}

/// Open a synchronous possession window on a handle (possession-checked). Use
/// itself is never frame-checked -- holding the handle is the authority -- but
/// `stack_trace` lets the glue attribute the *possessor* for the boundary
/// `transfer` and `use` audit records.
#[op2(fast, stack_trace)]
pub fn op_oden_handle_enter(
  #[string] id: String,
) -> Result<(), PermissionCheckError> {
  deno_permissions::oden_capsec_handle_enter(&id)
}

/// Close the most recent possession window.
#[op2(fast)]
pub fn op_oden_handle_exit() {
  deno_permissions::oden_capsec_handle_exit();
}

/// Revoke a handle and every handle transitively derived from it (cascade).
/// `stack_trace` attributes the revoker for audit.
#[op2(fast, stack_trace)]
pub fn op_oden_handle_revoke(#[string] id: String) {
  deno_permissions::oden_capsec_handle_revoke(&id);
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn absent_rev2_context_preserves_the_rev1_guard_result() {
    let target = "not-an-endpoint";
    let api_name = "oden-rev2-seam-test";
    let expected =
      deno_permissions::oden_capsec_check_protected_inspector_stream_target(
        target, api_name,
      )
      .unwrap_err()
      .to_string();
    let mut state = OpState::new(None);
    let actual =
      check_protected_inspector_stream_use_inner(&mut state, target, api_name)
        .unwrap_err()
        .to_string();
    assert_eq!(actual, expected);
  }

  #[test]
  fn installed_unbound_rev2_context_fails_closed_without_a_new_op() {
    let target = "not-an-endpoint";
    let api_name = "oden-rev2-seam-test";
    let rev1_error =
      deno_permissions::oden_capsec_check_protected_inspector_stream_target(
        target, api_name,
      )
      .unwrap_err()
      .to_string();
    let mut state = OpState::new(None);
    state.put(deno_permissions::OdenRev2ArmedContext::unbound_host());
    let error =
      check_protected_inspector_stream_use_inner(&mut state, target, api_name)
        .unwrap_err();
    assert!(error.to_string().contains("no native stage is bound"));
    assert_ne!(error.to_string(), rev1_error);
  }
}

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
  ],
);

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

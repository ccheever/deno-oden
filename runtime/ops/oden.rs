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
  protected_inspector_stream_op_implementation(state, &target, &api_name)
}

// Kept as one shared body so the sealed native fixture exercises the exact
// implementation called by the op2 dispatch wrapper, never a parallel policy
// adapter.
fn protected_inspector_stream_op_implementation(
  state: &mut OpState,
  target: &str,
  api_name: &str,
) -> Result<(), PermissionCheckError> {
  #[cfg(all(test, debug_assertions, unix))]
  deno_permissions::oden_capsec_rev2_protected_stream_fixture_record_event(
    "real-op-implementation-entered",
  );
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
    #[cfg(all(test, debug_assertions, unix))]
    deno_permissions::oden_capsec_rev2_protected_stream_fixture_record_event(
      "rev2-context-selected",
    );
    return context.consume_protected_inspector_stream_stage(target, api_name);
  }
  #[cfg(all(test, debug_assertions, unix))]
  deno_permissions::oden_capsec_rev2_protected_stream_fixture_record_event(
    "rev1-fallback-selected",
  );
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

  #[cfg(all(debug_assertions, unix))]
  use std::cell::Cell;
  #[cfg(all(debug_assertions, unix))]
  use std::rc::Rc;

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
    let actual = protected_inspector_stream_op_implementation(
      &mut state, target, api_name,
    )
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
    let error = protected_inspector_stream_op_implementation(
      &mut state, target, api_name,
    )
    .unwrap_err();
    assert!(error.to_string().contains("no native stage is bound"));
    assert_ne!(error.to_string(), rev1_error);
  }

  #[cfg(all(debug_assertions, unix))]
  #[derive(Clone, Debug, Eq, PartialEq)]
  struct ProtectedStreamCaseOutcome {
    deliveries: usize,
    exact_stage_matches: usize,
    malformed_arm_refusals: usize,
    op_failures: usize,
    released_resources: usize,
    session_revocations: usize,
    visible_bytes: usize,
    visible_objects: usize,
  }

  #[cfg(all(debug_assertions, unix))]
  #[derive(Default)]
  struct ProtectedStreamVisibility {
    bytes: Vec<u8>,
    objects: usize,
  }

  #[cfg(all(debug_assertions, unix))]
  fn assert_actual_protected_stream_callsites() {
    fn ordered_block(source: &str, label: &str, tokens: &[&str]) {
      assert!(tokens.len() >= 3);
      let mut anchors = source.match_indices(tokens[0]);
      let start = anchors
        .next()
        .map(|(offset, _)| offset)
        .unwrap_or_else(|| panic!("missing protected-stream block: {label}"));
      assert!(
        anchors.next().is_none(),
        "protected-stream block anchor is not unique: {label}"
      );
      let mut cursor = start;
      for token in tokens {
        let offset = source[cursor..].find(token).unwrap_or_else(|| {
          panic!("missing protected-stream token in {label}: {token}")
        });
        cursor += offset + token.len();
      }
      assert!(
        cursor - start <= 4096,
        "protected-stream block exceeds its source bound: {label}"
      );
    }

    let conn = include_str!("../../ext/net/01_net.js");
    ordered_block(
      conn,
      "Deno.Conn readable stream",
      &[
        "lazyStreams().setReadableStreamUseGuard(readable, () => {",
        "op_oden_check_protected_inspector_stream_use(",
        "\"Deno.Conn readable stream\"",
        "});",
        "this.#readable = readable",
      ],
    );
    let fetch = include_str!("../../ext/fetch/26_fetch.js");
    ordered_block(
      fetch,
      "fetch response body reader",
      &[
        "setReadableStreamUseGuard(readable, () => {",
        "op_oden_check_protected_inspector_stream_use(",
        "\"fetch response body reader\"",
        "});",
        "return readable",
      ],
    );
    let node =
      include_str!("../../ext/node/polyfills/internal/stream_base_commons.ts");
    ordered_block(
      node,
      "node:net.Socket native read delivery",
      &[
        "if (typeof protectedInspectorPeer === \"string\" && nread > 0) {",
        "try {",
        "op_oden_check_protected_inspector_stream_use(",
        "\"node:net.Socket native read delivery\"",
        "} catch (error) {",
        "return;",
        "const userBuf =",
      ],
    );
  }

  #[cfg(all(debug_assertions, unix))]
  fn protected_stream_delivery(
    state: &mut OpState,
    fixture: &deno_permissions::OdenRev2ProtectedStreamFixture,
    visibility: &mut ProtectedStreamVisibility,
  ) -> Result<(), String> {
    const PAYLOAD: &[u8] = b"protected-inspector-stream-fixture";
    let bytes_before = visibility.bytes.len();
    let objects_before = visibility.objects;
    deno_permissions::oden_capsec_rev2_protected_stream_fixture_record_event(
      "delivery-boundary-entered",
    );
    let result = protected_inspector_stream_op_implementation(
      state,
      fixture.target(),
      fixture.api_name(),
    );
    assert_eq!(visibility.bytes.len(), bytes_before);
    assert_eq!(visibility.objects, objects_before);
    if let Err(error) = result {
      deno_permissions::oden_capsec_rev2_protected_stream_fixture_record_event(
        "delivery-refused",
      );
      return Err(error.to_string());
    }
    deno_permissions::oden_capsec_rev2_protected_stream_fixture_record_event(
      "delivery-guard-passed",
    );
    visibility.objects += 1;
    visibility.bytes.extend_from_slice(PAYLOAD);
    deno_permissions::oden_capsec_rev2_protected_stream_fixture_record_event(
      "protected-object-visible",
    );
    deno_permissions::oden_capsec_rev2_protected_stream_fixture_record_event(
      "protected-bytes-visible",
    );
    Ok(())
  }

  #[cfg(all(debug_assertions, unix))]
  fn trace_count(trace: &[String], event: &str) -> usize {
    trace.iter().filter(|entry| entry.as_str() == event).count()
  }

  #[cfg(all(debug_assertions, unix))]
  fn assert_delivery_trace(trace: &[String]) {
    assert_eq!(trace_count(trace, "rev1-fallback-selected"), 0);
    for (index, event) in trace.iter().enumerate() {
      if event == "authorization-barrier-entered" {
        let prefix = &trace[..index];
        let exact_match = prefix
          .iter()
          .rposition(|entry| entry == "native-stage-exact-match")
          .expect("authorization follows an exact native stage");
        let live_principals = prefix
          .iter()
          .rposition(|entry| entry == "live-principals-matched")
          .expect("authorization follows live principal reconciliation");
        let policy = prefix
          .iter()
          .rposition(|entry| entry == "authorization-policy-projected")
          .expect("authorization follows live policy projection");
        assert!(exact_match < live_principals && live_principals < policy);
      }
      if event == "native-stage-committed" {
        let prefix = &trace[..index];
        let authorization = prefix
          .iter()
          .rposition(|entry| entry == "authorization-returned")
          .expect("commit follows authorization");
        let policy = prefix
          .iter()
          .rposition(|entry| entry == "commit-policy-projected")
          .expect("commit follows a second live policy projection");
        let barrier = prefix
          .iter()
          .rposition(|entry| entry == "commit-barrier-entered")
          .expect("commit follows its barrier");
        assert!(authorization < policy && policy < barrier);
      }
      if event == "protected-object-visible" {
        assert_eq!(
          trace.get(index.wrapping_sub(1)).map(String::as_str),
          Some("delivery-guard-passed")
        );
      }
      if event == "protected-bytes-visible" {
        assert_eq!(
          trace.get(index.wrapping_sub(1)).map(String::as_str),
          Some("protected-object-visible")
        );
      }
      if event == "delivery-guard-passed" {
        let prefix = &trace[..index];
        let authorization = prefix
          .iter()
          .rposition(|entry| entry == "authorization-barrier-entered")
          .expect("delivery follows an authorization barrier");
        let commit = prefix
          .iter()
          .rposition(|entry| entry == "native-stage-committed")
          .expect("delivery follows a committed native stage");
        assert!(authorization < commit);
      }
    }
  }

  #[cfg(all(debug_assertions, unix))]
  fn expected_deliveries(case_kind: &str) -> usize {
    match case_kind {
      "authorable-positive"
      | "predicate-vector:rev2.predicate.exact-static-present"
      | "staged-barrier:cleanup"
      | "staged-barrier:commit"
      | "staged-barrier:revocation" => 1,
      "staged-barrier:discovery" => 2,
      _ => 0,
    }
  }

  #[cfg(all(debug_assertions, unix))]
  fn expected_op_failures(case_kind: &str) -> usize {
    match case_kind {
      "authorable-positive"
      | "predicate-vector:rev2.predicate.exact-static-present"
      | "staged-barrier:cleanup"
      | "staged-barrier:discovery" => 0,
      _ => 1,
    }
  }

  #[cfg(all(debug_assertions, unix))]
  fn expected_exact_stage_matches(case_kind: &str) -> usize {
    match case_kind {
      "malformed-resource-refusal" | "staged-barrier:cancellation" => 0,
      "staged-barrier:discovery" | "staged-barrier:revocation" => 2,
      _ => 1,
    }
  }

  #[cfg(all(debug_assertions, unix))]
  fn expected_refusal_reason(case_kind: &str) -> &'static str {
    match case_kind {
      "authorable-cross-action-denial"
      | "authorable-wrong-principal-denial"
      | "authorable-quarantine-denial"
      | "predicate-vector:rev2.predicate.exact-static-missing" => {
        // This edge's exact-static predicate is stratum 8. A quarantine
        // principal with deliberately no positive row therefore refuses at
        // that edge-specific predicate before the generic stratum-14
        // quarantine reason.
        "OD-CAP-POSITIVE-PREDICATE"
      }
      "authorable-negative" | "staged-barrier:authorization" => {
        "OD-CAP-PRINCIPAL-DENIAL"
      }
      "authorable-missing-principal-denial" | "authorable-no-user-denial" => {
        "OD-CAP-UNATTRIBUTED"
      }
      "staged-barrier:revocation" => "OD-CAP-SESSION-REVOKED",
      "malformed-resource-refusal"
      | "staged-barrier:cancellation"
      | "staged-barrier:commit" => "no native stage is bound",
      _ => panic!("case has no expected refusal: {case_kind}"),
    }
  }

  #[cfg(all(debug_assertions, unix))]
  fn assert_expected_refusal(case_kind: &str, error: &str) {
    let reason = expected_refusal_reason(case_kind);
    assert!(
      error.contains(reason),
      "{case_kind} refused for unexpected reason: {error}"
    );
  }

  #[cfg(all(debug_assertions, unix))]
  fn execute_protected_stream_fixture_mode(
    case_kind: &str,
    mode: &str,
  ) -> ProtectedStreamCaseOutcome {
    deno_permissions::oden_capsec_rev2_protected_stream_fixture_reset_trace();
    let fixture =
      deno_permissions::OdenRev2ProtectedStreamFixture::new(case_kind, mode)
        .unwrap();
    assert!(fixture.verified_unarmed());
    assert!(fixture.case_kind() == case_kind);
    assert!(
      fixture
        .candidate_blockers()
        .iter()
        .any(|blocker| blocker.starts_with("target-unsupported-cells:"))
    );
    assert!(
      fixture
        .candidate_blockers()
        .iter()
        .any(|blocker| blocker == "target-not-advertised")
    );

    let released = Rc::new(Cell::new(0_usize));
    let mut context = fixture.fresh_context().unwrap();
    let mut state = OpState::new(None);
    let mut visibility = ProtectedStreamVisibility::default();
    let mut op_failures = 0;

    match case_kind {
      "malformed-resource-refusal" => {
        assert!(matches!(
          fixture.arm_malformed(&mut context),
          Err(deno_permissions::OdenRev2HostError::InvalidNativeStage)
        ));
        state.put(context);
        let error =
          protected_stream_delivery(&mut state, &fixture, &mut visibility)
            .unwrap_err();
        assert_expected_refusal(case_kind, &error);
        op_failures += 1;
      }
      "staged-barrier:cancellation" => {
        fixture.arm(&mut context, false, 1).unwrap();
        let released = released.clone();
        context
          .hold_provisional("fixture:cancel", move || {
            released.set(released.get() + 1);
          })
          .unwrap();
        let evidence = context.cancel().unwrap();
        assert_eq!(evidence.released_provisional_resources, ["fixture:cancel"]);
        state.put(context);
        let error =
          protected_stream_delivery(&mut state, &fixture, &mut visibility)
            .unwrap_err();
        assert_expected_refusal(case_kind, &error);
        op_failures += 1;
      }
      "staged-barrier:cleanup" => {
        fixture.arm(&mut context, false, 1).unwrap();
        let released = released.clone();
        context
          .hold_provisional("fixture:cleanup", move || {
            released.set(released.get() + 1);
          })
          .unwrap();
        let evidence = context.cleanup_non_authorizing().unwrap();
        assert_eq!(
          evidence.released_provisional_resources,
          ["fixture:cleanup"]
        );
        assert!(visibility.bytes.is_empty());
        assert_eq!(visibility.objects, 0);
        fixture.arm(&mut context, false, 2).unwrap();
        state.put(context);
        protected_stream_delivery(&mut state, &fixture, &mut visibility)
          .unwrap();
        state
          .try_take::<deno_permissions::OdenRev2ArmedContext>()
          .unwrap()
          .complete()
          .unwrap();
      }
      "staged-barrier:commit" => {
        fixture.arm(&mut context, false, 1).unwrap();
        state.put(context);
        protected_stream_delivery(&mut state, &fixture, &mut visibility)
          .unwrap();
        let error =
          protected_stream_delivery(&mut state, &fixture, &mut visibility)
            .unwrap_err();
        assert_expected_refusal(case_kind, &error);
        op_failures += 1;
      }
      "staged-barrier:discovery" | "staged-barrier:revocation" => {
        fixture.arm(&mut context, false, 1).unwrap();
        state.put(context);
        protected_stream_delivery(&mut state, &fixture, &mut visibility)
          .unwrap();
        let mut context = state
          .try_take::<deno_permissions::OdenRev2ArmedContext>()
          .unwrap();
        if case_kind == "staged-barrier:revocation" {
          fixture.seed_exact_revocation().unwrap();
        }
        fixture.arm(&mut context, true, 2).unwrap();
        state.put(context);
        let delivery =
          protected_stream_delivery(&mut state, &fixture, &mut visibility);
        if case_kind == "staged-barrier:discovery" {
          delivery.unwrap();
          state
            .try_take::<deno_permissions::OdenRev2ArmedContext>()
            .unwrap()
            .complete()
            .unwrap();
        } else {
          let error = delivery.unwrap_err();
          assert_expected_refusal(case_kind, &error);
          op_failures += 1;
        }
      }
      _ => {
        fixture.arm(&mut context, false, 1).unwrap();
        state.put(context);
        let delivery =
          protected_stream_delivery(&mut state, &fixture, &mut visibility);
        if expected_deliveries(case_kind) == 1 {
          delivery.unwrap();
          state
            .try_take::<deno_permissions::OdenRev2ArmedContext>()
            .unwrap()
            .complete()
            .unwrap();
        } else {
          let error = delivery.unwrap_err();
          assert_expected_refusal(case_kind, &error);
          op_failures += 1;
        }
      }
    }

    let observation = fixture.observe().unwrap();
    let trace =
      deno_permissions::oden_capsec_rev2_protected_stream_fixture_take_trace();
    assert_delivery_trace(&trace);
    let deliveries = trace_count(&trace, "protected-bytes-visible");
    assert_eq!(deliveries, expected_deliveries(case_kind));
    assert_eq!(op_failures, expected_op_failures(case_kind));
    let attempts = deliveries + op_failures;
    assert_eq!(trace_count(&trace, "delivery-boundary-entered"), attempts);
    assert_eq!(
      trace_count(&trace, "real-op-implementation-entered"),
      attempts
    );
    assert_eq!(trace_count(&trace, "rev2-context-selected"), attempts);
    assert_eq!(trace_count(&trace, "delivery-guard-passed"), deliveries);
    assert_eq!(trace_count(&trace, "delivery-refused"), op_failures);
    assert_eq!(
      trace_count(&trace, "native-stage-exact-match"),
      expected_exact_stage_matches(case_kind)
    );
    let malformed_arm_refusals =
      trace_count(&trace, "malformed-native-stage-refused");
    assert_eq!(
      malformed_arm_refusals,
      usize::from(case_kind == "malformed-resource-refusal")
    );
    assert_eq!(visibility.objects, deliveries);
    assert_eq!(
      visibility.bytes.len(),
      deliveries * b"protected-inspector-stream-fixture".len()
    );
    if case_kind == "staged-barrier:cancellation"
      || case_kind == "staged-barrier:cleanup"
    {
      assert_eq!(released.get(), 1);
    } else {
      assert_eq!(released.get(), 0);
    }
    if case_kind == "staged-barrier:revocation" {
      assert_eq!(observation.session_revocation_rows, 1);
    } else {
      assert_eq!(observation.session_revocation_rows, 0);
    }
    assert_eq!(observation.negative_overlay_rows, 0);
    assert_eq!(observation.revocation_rows, 0);
    assert_eq!(observation.session_positive_rows, 0);
    ProtectedStreamCaseOutcome {
      deliveries,
      exact_stage_matches: trace_count(&trace, "native-stage-exact-match"),
      malformed_arm_refusals,
      op_failures,
      released_resources: released.get(),
      session_revocations: observation.session_revocation_rows,
      visible_bytes: visibility.bytes.len(),
      visible_objects: visibility.objects,
    }
  }

  #[cfg(all(debug_assertions, unix))]
  fn selected_protected_stream_cases() -> Vec<&'static str> {
    let all =
      deno_permissions::oden_capsec_rev2_protected_stream_fixture_case_kinds();
    match std::env::var("ODEN_REV2_PROTECTED_STREAM_FIXTURE_CASE_KIND") {
      Ok(case_kind) => vec![
        all
          .iter()
          .copied()
          .find(|candidate| *candidate == case_kind)
          .unwrap_or_else(|| panic!("unregistered fixture case: {case_kind}")),
      ],
      Err(std::env::VarError::NotPresent) => all.to_vec(),
      Err(error) => panic!("invalid fixture case environment: {error}"),
    }
  }

  #[cfg(all(debug_assertions, unix))]
  fn validate_protected_stream_fixture_environment() {
    const ALLOWED: [&str; 2] = [
      "ODEN_REV2_PROTECTED_STREAM_FIXTURE_CASE_KIND",
      "ODEN_REV2_PROTECTED_STREAM_FIXTURE_TARGET",
    ];
    for (name, _) in std::env::vars() {
      if name.starts_with("ODEN_CAPSEC_") {
        panic!("ambient production authority input is forbidden: {name}");
      }
      if name.starts_with("ODEN_REV2_PROTECTED_STREAM_FIXTURE_")
        && !ALLOWED.contains(&name.as_str())
      {
        panic!("unknown protected-stream fixture input: {name}");
      }
    }
    if let Ok(target) =
      std::env::var("ODEN_REV2_PROTECTED_STREAM_FIXTURE_TARGET")
    {
      assert_eq!(
        target,
        deno_permissions::
          oden_capsec_rev2_protected_stream_fixture_compiled_target()
      );
    }
  }

  #[cfg(all(
    debug_assertions,
    any(
      all(target_os = "macos", target_arch = "aarch64"),
      all(target_os = "linux", target_arch = "x86_64")
    )
  ))]
  #[test]
  fn rev2_protected_inspector_stream_fixture_case() {
    validate_protected_stream_fixture_environment();
    assert_actual_protected_stream_callsites();
    let selected = selected_protected_stream_cases();
    for case_kind in selected {
      let mut baseline = None;
      let mut mode_results = Vec::new();
      for mode in ["permissive", "audit", "enforce"] {
        let outcome = execute_protected_stream_fixture_mode(case_kind, mode);
        if let Some(expected) = baseline.as_ref() {
          assert_eq!(
            &outcome, expected,
            "protected exact-static and denial semantics changed by mode"
          );
        } else {
          baseline = Some(outcome.clone());
        }
        mode_results.push(deno_core::serde_json::json!({
          "mode": mode,
          "deliveries": outcome.deliveries,
          "exactStageMatches": outcome.exact_stage_matches,
          "malformedArmRefusals": outcome.malformed_arm_refusals,
          "opFailures": outcome.op_failures,
          "releasedResources": outcome.released_resources,
          "sessionRevocations": outcome.session_revocations,
          "visibleBytes": outcome.visible_bytes,
          "visibleObjects": outcome.visible_objects,
        }));
      }
      eprintln!(
        "ODEN_REV2_PROTECTED_STREAM_FIXTURE_RESULT={}",
        deno_core::serde_json::to_string(&deno_core::serde_json::json!({
          "schema": "oden/capsec-rev2-protected-stream-native-result/1",
          "target": deno_permissions::
            oden_capsec_rev2_protected_stream_fixture_compiled_target(),
          "featureSet": deno_permissions::
            oden_capsec_rev2_protected_stream_fixture_compiled_feature_set(),
          "vocabDigest": deno_permissions::
            oden_capsec_rev2_protected_stream_fixture_compiled_vocab_digest(),
          "edgeId": "native-op:runtime/ops/oden.rs#op_oden_check_protected_inspector_stream_use",
          "caseKind": case_kind,
          "modes": mode_results,
          "assertions": [
            "actual-delivery-callsite-guards-before-visibility",
            "authorization-and-commit-before-visibility",
            "candidate-verified-unarmed",
            "case-specific-refusal-reason",
            "exact-native-stage-and-occurrence",
            "malformed-resource-refusal-is-exact",
            "mode-invariant-exact-static-semantics",
            "no-session-positive-authority-publication",
            "no-process-wide-c04",
            "no-rev1-or-fallback-authority",
            "provisional-release-is-exact",
            "real-op-implementation-invoked",
          ],
          "contextBinding": "verified-unarmed-debug-feature-unix-opstate-only",
          "nativeReleaseExecution": false,
          "cellsChanged": 0,
        }))
        .unwrap()
      );
    }
  }
}

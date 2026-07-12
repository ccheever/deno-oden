// Copyright 2018-2026 the Deno authors. MIT license.

//! External compile/use coverage for the trusted Rev2 launch-seal API.

use std::cell::Cell;
use std::rc::Rc;

use deno_permissions::OdenRev2ArmedContext;
use deno_permissions::OdenRev2HostActor;
use deno_permissions::OdenRev2HostChildExport;
use deno_permissions::OdenRev2HostInteraction;
use deno_permissions::OdenRev2HostLaunchSeal;
use deno_permissions::OdenRev2HostSpawnEdge;
use deno_permissions::OdenRev2RequiredForCommit;
use deno_permissions::rev2::AuthoritySelectorInput;
use deno_permissions::rev2::DecisionPolicyInput;
use deno_permissions::rev2::EngineIdentity;
use deno_permissions::rev2::Generations;
use deno_permissions::rev2::Mode;
use deno_permissions::rev2::NamedSelectorInput;
use deno_permissions::rev2::OperationProvenanceContext;
use deno_permissions::rev2::PrincipalKind;
use deno_permissions::rev2::PrincipalRef;
use serde_json::json;

#[test]
fn public_host_api_constructs_every_supported_spawn_edge() {
  for edge in [
    OdenRev2HostSpawnEdge::DenoSpawnChild,
    OdenRev2HostSpawnEdge::NodeSpawnChild,
    OdenRev2HostSpawnEdge::DeprecatedRun,
  ] {
    let read = OdenRev2HostChildExport::capture_broker_env_read_host(
      edge,
      "owner:root",
      "0",
      "ODEN_READ",
      "read-value",
      OdenRev2RequiredForCommit::Required,
    )
    .expect("trusted broker read should seal");
    let write = OdenRev2HostChildExport::capture_literal_env_write_host(
      edge,
      "owner:root",
      "0",
      "ODEN_WRITE",
      "write-value",
    )
    .expect("trusted literal write should seal");

    OdenRev2HostLaunchSeal::capture_spawn_host(edge, vec![read, write], 1024)
      .expect("the public edge type must compose with the public launch API");
  }
}

fn inspector_policy(
  target: &str,
  principal: PrincipalRef,
) -> DecisionPolicyInput {
  let identity = EngineIdentity::embedded();
  DecisionPolicyInput {
    identity: identity.clone(),
    mode: Mode::Enforce,
    run_nonce: "run:external-host-api".to_string(),
    channel_epoch: "channel:external-host-api".to_string(),
    provenance: OperationProvenanceContext {
      policy_digest: identity.vocab_digest,
      armed_snapshot_digest: identity.registry_digest,
      quota_owner: PrincipalRef {
        kind: PrincipalKind::Runtime,
        key: "runtime:quota-owner".to_string(),
      },
      terminal_evidence_id: "terminal:external-host-api".to_string(),
    },
    generations: Generations {
      policy_snapshot: "1".to_string(),
      ..Generations::default()
    },
    process_denials: Vec::new(),
    principal_denials: Vec::new(),
    session_revocations: Vec::new(),
    escalation_ceiling: Vec::new(),
    static_floor: vec![NamedSelectorInput {
      source_id: "floor:external-inspector".to_string(),
      selector: AuthoritySelectorInput {
        identity: EngineIdentity::embedded(),
        principal: Some(principal),
        capability: "inspector:activate".to_string(),
        resource: json!({
          "route": { "attestation": null, "endpoint": null, "kind": "direct" },
          "session": { "kind": "inspector", "value": target },
        }),
      },
    }],
    handles: Vec::new(),
    session_grants: Vec::new(),
    implicit_self: Vec::new(),
    protected_exceptions: Vec::new(),
    compatibility_dispositions: Vec::new(),
    validated_receipt_row_digests: Vec::new(),
    path_bindings: Vec::new(),
  }
}

#[test]
fn public_armed_context_can_complete_or_cancel_without_exposing_a_permit() {
  struct ResetAttribution;
  impl Drop for ResetAttribution {
    fn drop(&mut self) {
      deno_permissions::prompter::set_current_oden_stacktrace(Box::new(
        Vec::new,
      ));
      deno_permissions::prompter::set_current_oden_cped_locator(None);
      deno_permissions::prompter::set_current_oden_cped_stack(None);
      deno_permissions::prompter::set_current_oden_trusted_host_actor(false);
    }
  }
  let _reset = ResetAttribution;
  let locator = format!(
    "file://{}/external-rev2-host-api.ts",
    env!("CARGO_MANIFEST_DIR")
  );
  deno_permissions::prompter::set_current_oden_stacktrace(Box::new(
    move || {
      vec![deno_permissions::prompter::OdenStackFrame {
        isolate_id: Some(24021),
        script_id: Some(24022),
        locator: Some(locator.clone()),
        display_name: None,
      }]
    },
  ));
  deno_permissions::prompter::set_current_oden_cped_locator(None);
  deno_permissions::prompter::set_current_oden_cped_stack(None);
  deno_permissions::prompter::set_current_oden_trusted_host_actor(false);

  let target = "127.0.0.1:9229";
  let principals = deno_permissions::oden_rev2_capture_live_principals();
  let principal = principals[0].clone();
  let policy = inspector_policy(target, principal.clone());
  let actor = OdenRev2HostActor::capture_host(
    "operation:external-host-api",
    "actor:external-host-api",
    principals.clone(),
    "owner:external-host-api",
    principal.clone(),
    "0",
    None,
    &policy,
  )
  .unwrap();
  let cleanup_called = Rc::new(Cell::new(false));
  let cleanup = cleanup_called.clone();
  let mut context = OdenRev2ArmedContext::capture_host(actor);
  context
    .hold_provisional("rid:external-cleanup", move || cleanup.set(true))
    .unwrap();
  let cleanup_evidence = context.cleanup_non_authorizing().unwrap();
  assert_eq!(
    cleanup_evidence.released_provisional_resources,
    ["rid:external-cleanup"]
  );
  assert!(cleanup_called.get());

  let release_called = Rc::new(Cell::new(false));
  let release = release_called.clone();
  context
    .hold_provisional("rid:external-complete", move || release.set(true))
    .unwrap();
  let supplied = policy.clone();
  context
    .arm_protected_inspector_stream_stage(
      target,
      "external-host-api",
      "external-host-api",
      move || Ok(supplied.clone()),
      false,
      OdenRev2HostInteraction::NonInteractive,
    )
    .unwrap();
  context
    .consume_protected_inspector_stream_stage(target, "external-host-api")
    .unwrap();
  assert!(context.take_committed_launch_payload().is_none());
  assert_eq!(context.complete().unwrap(), ["rid:external-complete"]);
  assert!(!release_called.get());

  let cancel_actor = OdenRev2HostActor::capture_host(
    "operation:external-host-api-cancel",
    "actor:external-host-api-cancel",
    principals,
    "owner:external-host-api",
    principal,
    "0",
    None,
    &policy,
  )
  .unwrap();
  let cancel_called = Rc::new(Cell::new(false));
  let release = cancel_called.clone();
  let mut cancel_context = OdenRev2ArmedContext::capture_host(cancel_actor);
  cancel_context
    .hold_provisional("rid:external-cancel", move || release.set(true))
    .unwrap();
  let evidence = cancel_context.cancel().unwrap();
  assert_eq!(
    evidence.released_provisional_resources,
    ["rid:external-cancel"]
  );
  assert!(cancel_called.get());
}

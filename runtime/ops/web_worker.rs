// Copyright 2018-2026 the Deno authors. MIT license.

mod sync_fetch;

use std::cell::RefCell;
use std::rc::Rc;

use deno_core::CancelFuture;
use deno_core::DetachedBuffer;
use deno_core::JsBuffer;
use deno_core::JsRuntimeInspector;
use deno_core::OpState;
use deno_core::op2;
use deno_web::JsMessageData;
use deno_web::MessagePortError;
use deno_web::RecvMessageData;
pub use sync_fetch::SyncFetchError;

use self::sync_fetch::op_worker_sync_fetch;
use crate::web_worker::WebWorkerInternalHandle;
use crate::web_worker::WorkerControlEvent;
use crate::web_worker::WorkerThreadType;

deno_core::extension!(
  deno_web_worker,
  ops = [
    op_worker_post_message,
    op_worker_post_message_raw,
    op_worker_recv_message,
    op_worker_recv_message_sync,
    op_worker_maybe_wait_for_debugger,
    // Notify host that guest worker closes.
    op_worker_close,
    op_worker_get_type,
    op_worker_sync_fetch,
  ],
);

pub struct WaitForWorkerDebuggerOnMessage(pub bool);

#[op2]
fn op_worker_post_message(
  state: &mut OpState,
  #[serde] data: JsMessageData,
) -> Result<(), MessagePortError> {
  let handle = state.borrow::<WebWorkerInternalHandle>().clone();
  handle.port.send(state, data)
}

/// Fast-path post: takes a pre-serialized buffer directly, bypassing
/// the JsMessageData serde overhead. Only for messages with no transferables.
#[op2]
fn op_worker_post_message_raw(
  state: &mut OpState,
  #[buffer(detach)] data: JsBuffer,
) -> Result<(), MessagePortError> {
  let handle = state.borrow::<WebWorkerInternalHandle>().clone();
  let detached = DetachedBuffer::from_v8slice(data.into_parts());
  if let Some(tx) = &*handle.port.tx.borrow() {
    tx.send((detached, vec![])).ok();
  }
  Ok(())
}

#[op2(async(lazy), fast)]
async fn op_worker_recv_message(
  state: Rc<RefCell<OpState>>,
) -> Result<Option<RecvMessageData>, MessagePortError> {
  let handle = {
    let state = state.borrow();
    state.borrow::<WebWorkerInternalHandle>().clone()
  };
  handle
    .port
    .recv(state.clone())
    .or_cancel(handle.cancel)
    .await?
}

#[op2]
fn op_worker_recv_message_sync(
  state: &mut OpState,
) -> Result<Option<JsMessageData>, MessagePortError> {
  let handle = state.borrow::<WebWorkerInternalHandle>().clone();
  handle.port.try_recv_sync(state)
}

#[op2(fast)]
fn op_worker_maybe_wait_for_debugger(
  state: &mut OpState,
) -> Result<(), deno_permissions::PermissionCheckError> {
  worker_maybe_wait_for_debugger_impl(state)
}

fn worker_maybe_wait_for_debugger_impl(
  state: &mut OpState,
) -> Result<(), deno_permissions::PermissionCheckError> {
  let should_wait = state
    .try_borrow::<WaitForWorkerDebuggerOnMessage>()
    .map(|wait| wait.0)
    .unwrap_or(false);
  if !should_wait {
    return Ok(());
  }

  // The worker helper is a delayed startup edge with no package caller. It
  // consumes the same exact root static row as the server/startup route before
  // mutating wait state or touching the inspector session.
  // @ref LLP 0019#inspector [implements]
  deno_permissions::oden_capsec_check_inspector_activation(
    "startup:worker-wait-for-debugger",
    "worker debugger wait helper",
    true,
  )?;
  if let Some(wait) = state.try_borrow_mut::<WaitForWorkerDebuggerOnMessage>() {
    wait.0 = false;
  }

  if let Some(inspector) = state.try_borrow::<Rc<JsRuntimeInspector>>() {
    inspector.wait_for_debugger_enabled_for_worker_message();
  }
  Ok(())
}

#[op2(fast)]
fn op_worker_close(state: &mut OpState) {
  // Notify parent that we're finished
  let exit_code = state
    .try_borrow::<deno_os::ExitCode>()
    .map(|e| e.get())
    .unwrap_or(0);
  let mut handle = state.borrow_mut::<WebWorkerInternalHandle>().clone();

  // Send the exit code to the parent before terminating
  let _ = handle.post_event(WorkerControlEvent::Close(exit_code));
  handle.terminate();
}

#[op2]
fn op_worker_get_type(state: &mut OpState) -> WorkerThreadType {
  let handle = state.borrow::<WebWorkerInternalHandle>().clone();
  handle.worker_type
}

#[cfg(test)]
#[allow(
  clippy::disallowed_methods,
  reason = "isolated native-route tests create temporary policy and audit artifacts and execute the current test binary"
)]
mod tests {
  use std::process::Command;
  use std::process::Stdio;
  use std::time::Duration;
  use std::time::Instant;
  use std::time::SystemTime;
  use std::time::UNIX_EPOCH;

  use deno_core::OpState;

  use super::*;

  const CHILD_SCENARIO: &str = "ODEN_TEST_WORKER_DEBUGGER_ROUTE";
  const TEST_NAME: &str = "ops::web_worker::tests::worker_debugger_wait_requires_exact_root_row_before_mutation";
  const TARGET: &str = "startup:worker-wait-for-debugger";

  struct TestDir(std::path::PathBuf);

  impl TestDir {
    fn new() -> Self {
      let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
      let path = std::env::temp_dir().join(format!(
        "oden-worker-debugger-route-{}-{nonce}",
        std::process::id()
      ));
      std::fs::create_dir(&path).unwrap();
      Self(path)
    }
  }

  impl Drop for TestDir {
    fn drop(&mut self) {
      let _ = std::fs::remove_dir_all(&self.0);
    }
  }

  fn run_child(
    scenario: &str,
    policy: &std::path::Path,
    audit: &std::path::Path,
  ) {
    let stdout_path = audit.with_extension(format!("{scenario}.stdout"));
    let stderr_path = audit.with_extension(format!("{scenario}.stderr"));
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
      .args([TEST_NAME, "--exact", "--nocapture", "--test-threads=1"])
      .stdout(Stdio::from(std::fs::File::create(&stdout_path).unwrap()))
      .stderr(Stdio::from(std::fs::File::create(&stderr_path).unwrap()));
    for (name, _) in std::env::vars_os() {
      if name.to_string_lossy().starts_with("ODEN_CAPSEC_")
        || name == CHILD_SCENARIO
      {
        command.env_remove(name);
      }
    }
    command
      .env(CHILD_SCENARIO, scenario)
      .env("ODEN_CAPSEC_POLICY", policy)
      .env("ODEN_CAPSEC_AUDIT", audit);
    let mut child = command.spawn().unwrap();
    let deadline = Instant::now() + Duration::from_secs(15);
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
    let stdout = std::fs::read_to_string(stdout_path).unwrap();
    let stderr = std::fs::read_to_string(stderr_path).unwrap();
    assert!(
      !timed_out && status.success(),
      "child scenario {scenario} failed (timed_out={timed_out}, status={status}):\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
  }

  fn assert_audit(audit: &std::path::Path, decision: &str, principal: &str) {
    let records = std::fs::read_to_string(audit).unwrap();
    let found = records.lines().any(|line| {
      let record: deno_core::serde_json::Value =
        deno_core::serde_json::from_str(line).unwrap();
      record["capability"] == "inspector:activate"
        && record["target"] == TARGET
        && record["decision"] == decision
        && record["principal"] == principal
    });
    assert!(found, "missing exact {decision} audit row in {records}");
  }

  #[test]
  fn worker_debugger_wait_requires_exact_root_row_before_mutation() {
    if let Ok(scenario) = std::env::var(CHILD_SCENARIO) {
      let mut state = OpState::new(None);
      state.put(WaitForWorkerDebuggerOnMessage(true));
      match scenario.as_str() {
        "deny" => {
          let error = worker_maybe_wait_for_debugger_impl(&mut state)
            .expect_err("missing exact root row must deny");
          assert!(
            error.to_string().contains(TARGET)
              && error
                .to_string()
                .contains("exact static inspector:activate row"),
            "unexpected denial: {error}"
          );
          assert!(
            state.borrow::<WaitForWorkerDebuggerOnMessage>().0,
            "denial must happen before clearing the wait flag"
          );

          state.put(WaitForWorkerDebuggerOnMessage(false));
          worker_maybe_wait_for_debugger_impl(&mut state)
            .expect("a worker with no pending wait must remain a no-op");
        }
        "allow" => {
          worker_maybe_wait_for_debugger_impl(&mut state)
            .expect("exact root row should authorize the startup helper");
          assert!(
            !state.borrow::<WaitForWorkerDebuggerOnMessage>().0,
            "authorized route must consume the one-shot wait flag"
          );
        }
        other => panic!("unknown child scenario {other}"),
      }
      return;
    }

    let dir = TestDir::new();
    let deny_policy = dir.0.join("deny.json");
    let allow_policy = dir.0.join("allow.json");
    let deny_audit = dir.0.join("deny.ndjson");
    let allow_audit = dir.0.join("allow.ndjson");
    std::fs::write(&deny_policy, r#"{"mode":"permissive","grants":{}}"#)
      .unwrap();
    std::fs::write(
      &allow_policy,
      r#"{"mode":"permissive","grants":{},"rootGrants":"inspector:activate"}"#,
    )
    .unwrap();

    run_child("deny", &deny_policy, &deny_audit);
    run_child("allow", &allow_policy, &allow_audit);
    assert_audit(&deny_audit, "deny", "root/runtime-control");
    assert_audit(&allow_audit, "allow", "root/runtime-control");
  }
}

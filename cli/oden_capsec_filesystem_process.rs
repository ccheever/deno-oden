// Copyright 2018-2026 the Deno authors. MIT license.

use std::io;
use std::os::unix::process::CommandExt;
use std::process::Child;
use std::process::Command;
use std::process::ExitStatus;
use std::thread;
use std::time::Duration;
use std::time::Instant;

const STATUS_POLL_INTERVAL: Duration = Duration::from_millis(10);
// The caller's Instant is the final cleanup deadline. Candidate execution
// stops this far ahead of it so SIGKILL, direct-child reap, and kernel-observed
// group disappearance share the same original bound.
const CLEANUP_RESERVE: Duration = Duration::from_millis(250);

/// Applies only the process-group attribute required by [`ProcessGroupChild`].
///
/// Executable selection, retained-image execution, argv/environment closure,
/// descriptor inheritance, and the actual spawn remain the trusted parent's
/// responsibility. A process group alone is not complete-tree containment;
/// this dormant helper must not be activated until a platform containment or
/// verified no-fork/no-escape boundary prevents descendants from leaving it.
/// This helper intentionally does not provide a path-based spawn shortcut.
pub(crate) fn configure_isolated_process_group(command: &mut Command) {
  command.process_group(0);
}

/// Owns one already-spawned direct child and its verified isolated process
/// group under one immutable absolute deadline.
///
/// Construction consumes the `Child`, which is the ownership proof for the
/// direct PID. The kernel-observed process group must be led by that same PID
/// and must differ from the parent's group before group signalling is enabled.
// @ref LLP 0019#pre-promotion-conformance-candidate-execution [implements] —
// Parent-owned monotonic deadlines kill the verified native child group and
// reap the direct child before evidence can continue.
#[derive(Debug)]
pub(crate) struct ProcessGroupChild {
  child: Option<Child>,
  direct_pid: libc::pid_t,
  process_group_id: libc::pid_t,
  deadline: Instant,
  group_needs_kill: bool,
}

impl ProcessGroupChild {
  pub(crate) fn wrap(mut child: Child, deadline: Instant) -> io::Result<Self> {
    let direct_pid = match libc::pid_t::try_from(child.id()) {
      Ok(pid) if pid > 0 => pid,
      _ => {
        return Err(reject_unverified_child(
          child,
          invalid_input("direct child PID is outside the Unix PID range"),
        ));
      }
    };
    // SAFETY: getpgrp has no arguments and cannot fail.
    let parent_process_group = unsafe { libc::getpgrp() };
    let process_group_id = match get_process_group(direct_pid) {
      Ok(process_group_id) => process_group_id,
      Err(error) => match try_wait_direct_child(&mut child) {
        Ok(Some(_)) => {
          return Err(invalid_input(
            "direct child exited before lifecycle ownership completed",
          ));
        }
        Ok(None) | Err(_) => {
          return Err(reject_unverified_child(child, error));
        }
      },
    };

    if process_group_id == parent_process_group {
      return Err(reject_unverified_child(
        child,
        invalid_input(format!(
          "direct child process group {process_group_id} aliases parent process group"
        )),
      ));
    }
    if process_group_id != direct_pid {
      return Err(reject_unverified_child(
        child,
        invalid_input(format!(
          "direct child {direct_pid} is not the leader of its process group {process_group_id}"
        )),
      ));
    }

    let mut owned = Self {
      child: Some(child),
      direct_pid,
      process_group_id,
      deadline,
      group_needs_kill: true,
    };
    if Instant::now() >= deadline {
      return Err(owned.fail_closed(io::Error::new(
        io::ErrorKind::TimedOut,
        "native child deadline expired before lifecycle ownership completed",
      )));
    }
    match owned.try_wait_direct_child() {
      Ok(Some(_)) => {
        let primary = invalid_input(
          "direct child exited before lifecycle ownership completed",
        );
        return Err(match owned.finish_reaped_direct_child() {
          Ok(_) => primary,
          Err(cleanup) => with_cleanup_error(primary, cleanup),
        });
      }
      Ok(None) => {}
      Err(error) => return Err(owned.fail_closed(error)),
    }
    Ok(owned)
  }

  pub(crate) fn direct_pid(&self) -> libc::pid_t {
    self.direct_pid
  }

  pub(crate) fn process_group_id(&self) -> libc::pid_t {
    self.process_group_id
  }

  pub(crate) fn deadline(&self) -> Instant {
    self.deadline
  }

  /// Polls only the owned direct child. The deadline stored at construction is
  /// reused for every poll and is never extended after partial progress.
  pub(crate) fn wait(mut self) -> io::Result<ExitStatus> {
    loop {
      let now = Instant::now();
      if now >= self.cleanup_start() {
        return Err(self.fail_closed(io::Error::new(
          io::ErrorKind::TimedOut,
          "native child did not exit before its reserved cleanup window",
        )));
      }

      match self.try_wait_direct_child() {
        Ok(Some(status)) => {
          return match self.finish_reaped_direct_child() {
            Ok(false) => Ok(status),
            Ok(true) => Err(io::Error::other(
              "direct child exited while descendants remained in its process group",
            )),
            Err(error) => Err(error),
          };
        }
        Ok(None) => {}
        Err(error) => return Err(self.fail_closed(error)),
      }

      let remaining = self
        .cleanup_start()
        .saturating_duration_since(Instant::now());
      if remaining.is_zero() {
        continue;
      }
      thread::sleep(remaining.min(STATUS_POLL_INTERVAL));
    }
  }

  fn cleanup_start(&self) -> Instant {
    self
      .deadline
      .checked_sub(CLEANUP_RESERVE)
      .unwrap_or(self.deadline)
  }

  fn try_wait_direct_child(&mut self) -> io::Result<Option<ExitStatus>> {
    let child = self
      .child
      .as_mut()
      .expect("direct child is present until terminal status is observed");
    try_wait_direct_child(child)
  }

  /// Returns whether descendants remained after the direct child was reaped.
  /// Any such group is killed and observed gone before the caller can proceed.
  fn finish_reaped_direct_child(&mut self) -> io::Result<bool> {
    self.child.take();
    match process_group_exists(self.process_group_id) {
      Ok(false) => {
        self.group_needs_kill = false;
        Ok(false)
      }
      Ok(true) => {
        self.kill_group_and_wait_for_disappearance()?;
        Ok(true)
      }
      Err(probe_error) => match self.kill_group_and_wait_for_disappearance() {
        Ok(()) => Err(probe_error),
        Err(cleanup_error) => {
          Err(with_cleanup_error(probe_error, cleanup_error))
        }
      },
    }
  }

  fn kill_group_and_wait_for_disappearance(&mut self) -> io::Result<()> {
    let kill_result = kill_process_group(self.process_group_id);
    let disappearance_result = self.wait_for_group_disappearance();
    match (kill_result, disappearance_result) {
      (Ok(()), Ok(())) => Ok(()),
      (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
      (Err(kill_error), Err(disappearance_error)) => {
        Err(with_cleanup_error(kill_error, disappearance_error))
      }
    }
  }

  fn wait_for_group_disappearance(&mut self) -> io::Result<()> {
    loop {
      let remaining = self.deadline.saturating_duration_since(Instant::now());
      if remaining.is_zero() {
        return Err(io::Error::new(
          io::ErrorKind::TimedOut,
          "native child process group did not disappear before the final deadline",
        ));
      }
      if !process_group_exists(self.process_group_id)? {
        self.group_needs_kill = false;
        return Ok(());
      }
      thread::sleep(remaining.min(STATUS_POLL_INTERVAL));
    }
  }

  fn fail_closed(&mut self, primary: io::Error) -> io::Error {
    match self.kill_group_and_reap() {
      Ok(_) => primary,
      Err(cleanup) => with_cleanup_error(primary, cleanup),
    }
  }

  fn kill_group_and_reap(&mut self) -> io::Result<ExitStatus> {
    let mut cleanup_error = None;
    if let Err(error) = kill_process_group(self.process_group_id) {
      append_cleanup_error(&mut cleanup_error, error);
    }

    let status = match self.reap_direct_child_before_deadline() {
      Ok(status) => Some(status),
      Err(error) => {
        append_cleanup_error(&mut cleanup_error, error);
        None
      }
    };
    if let Err(error) = self.wait_for_group_disappearance() {
      append_cleanup_error(&mut cleanup_error, error);
    }

    match (status, cleanup_error) {
      (Some(status), None) => Ok(status),
      (_, Some(error)) => Err(error),
      (None, None) => {
        unreachable!("missing reap status always carries an error")
      }
    }
  }

  fn reap_direct_child_before_deadline(&mut self) -> io::Result<ExitStatus> {
    loop {
      let remaining = self.deadline.saturating_duration_since(Instant::now());
      if remaining.is_zero() {
        return Err(io::Error::new(
          io::ErrorKind::TimedOut,
          "direct child was not reaped before the final deadline",
        ));
      }
      match self.try_wait_direct_child()? {
        Some(status) => {
          self.child.take();
          return Ok(status);
        }
        None => thread::sleep(remaining.min(STATUS_POLL_INTERVAL)),
      }
    }
  }
}

impl Drop for ProcessGroupChild {
  fn drop(&mut self) {
    if self.group_needs_kill {
      let _ = kill_process_group(self.process_group_id);
    }
    if let Some(child) = self.child.as_mut() {
      if wait_for_direct_child(child).is_ok() {
        self.child.take();
      }
    }
    if self.group_needs_kill && Instant::now() < self.deadline {
      let _ = self.wait_for_group_disappearance();
    }
  }
}

fn get_process_group(pid: libc::pid_t) -> io::Result<libc::pid_t> {
  loop {
    // SAFETY: pid came from an owned std::process::Child.
    let result = unsafe { libc::getpgid(pid) };
    if result >= 0 {
      return Ok(result);
    }
    let error = io::Error::last_os_error();
    if error.kind() != io::ErrorKind::Interrupted {
      return Err(error);
    }
  }
}

fn process_group_exists(process_group_id: libc::pid_t) -> io::Result<bool> {
  debug_assert!(process_group_id > 0);
  loop {
    // SAFETY: signal zero probes the positive, verified group id.
    let result = unsafe { libc::kill(-process_group_id, 0) };
    if result == 0 {
      return Ok(true);
    }
    let error = io::Error::last_os_error();
    if error.kind() == io::ErrorKind::Interrupted {
      continue;
    }
    if error.raw_os_error() == Some(libc::ESRCH) {
      return Ok(false);
    }
    return Err(error);
  }
}

fn kill_process_group(process_group_id: libc::pid_t) -> io::Result<()> {
  debug_assert!(process_group_id > 0);
  loop {
    // SAFETY: a negative, nonzero PID targets the verified process group.
    let result = unsafe { libc::kill(-process_group_id, libc::SIGKILL) };
    if result == 0 {
      return Ok(());
    }
    let error = io::Error::last_os_error();
    if error.kind() == io::ErrorKind::Interrupted {
      continue;
    }
    if error.raw_os_error() == Some(libc::ESRCH) {
      return Ok(());
    }
    return Err(error);
  }
}

fn reject_unverified_child(mut child: Child, primary: io::Error) -> io::Error {
  match try_wait_direct_child(&mut child) {
    Ok(Some(_)) => primary,
    Ok(None) => match kill_direct_child_and_reap(&mut child) {
      Ok(_) => primary,
      Err(cleanup) => with_cleanup_error(primary, cleanup),
    },
    Err(observe_error) => match kill_direct_child_and_reap(&mut child) {
      Ok(_) => with_cleanup_error(primary, observe_error),
      Err(cleanup) => {
        with_cleanup_error(with_cleanup_error(primary, observe_error), cleanup)
      }
    },
  }
}

fn kill_direct_child_and_reap(child: &mut Child) -> io::Result<ExitStatus> {
  let kill_result = match child.kill() {
    Err(error) if error.raw_os_error() == Some(libc::ESRCH) => Ok(()),
    result => result,
  };
  let reap_result = wait_for_direct_child(child);
  match (kill_result, reap_result) {
    (Ok(()), Ok(status)) => Ok(status),
    (Err(error), Ok(_)) | (Ok(()), Err(error)) => Err(error),
    (Err(kill_error), Err(reap_error)) => {
      Err(with_cleanup_error(kill_error, reap_error))
    }
  }
}

fn wait_for_direct_child(child: &mut Child) -> io::Result<ExitStatus> {
  loop {
    match child.wait() {
      Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
      result => return result,
    }
  }
}

fn try_wait_direct_child(child: &mut Child) -> io::Result<Option<ExitStatus>> {
  loop {
    match child.try_wait() {
      Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
      result => return result,
    }
  }
}

fn invalid_input(message: impl Into<String>) -> io::Error {
  io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

fn with_cleanup_error(primary: io::Error, cleanup: io::Error) -> io::Error {
  io::Error::new(
    primary.kind(),
    format!("{primary}; fail-closed cleanup failed: {cleanup}"),
  )
}

fn append_cleanup_error(accumulated: &mut Option<io::Error>, error: io::Error) {
  *accumulated = Some(match accumulated.take() {
    Some(previous) => with_cleanup_error(previous, error),
    None => error,
  });
}

#[cfg(test)]
mod tests {
  use std::io::BufRead;
  use std::io::BufReader;
  use std::process::Stdio;

  use super::*;

  #[test]
  fn normal_exit_is_observed_and_reaped() {
    let mut command = Command::new("/bin/sh");
    command
      .arg("-c")
      .arg("read ignored; exit 7")
      .stdin(Stdio::piped())
      .stdout(Stdio::null())
      .stderr(Stdio::null());
    configure_isolated_process_group(&mut command);
    let mut child = command.spawn().unwrap();
    let release = child.stdin.take().unwrap();
    let pid = libc::pid_t::try_from(child.id()).unwrap();
    let owned =
      ProcessGroupChild::wrap(child, Instant::now() + Duration::from_secs(2))
        .unwrap();

    assert_eq!(owned.direct_pid(), pid);
    assert_eq!(owned.process_group_id(), pid);
    assert!(owned.deadline() > Instant::now());
    drop(release);
    assert_eq!(owned.wait().unwrap().code(), Some(7));
    assert_direct_child_reaped(pid);
    assert_process_group_absent_now(pid);
  }

  #[test]
  fn normal_leader_exit_with_lingering_descendant_refuses() {
    let mut command = Command::new("/bin/sh");
    command
      .arg("-c")
      .arg("sleep 30 & echo $!; read ignored; exit 0")
      .stdin(Stdio::piped())
      .stdout(Stdio::piped())
      .stderr(Stdio::null());
    configure_isolated_process_group(&mut command);
    let mut child = command.spawn().unwrap();
    let release = child.stdin.take().unwrap();
    let pid = libc::pid_t::try_from(child.id()).unwrap();
    let stdout = child.stdout.take().unwrap();
    let descendant_pid = BufReader::new(stdout)
      .lines()
      .next()
      .expect("shell reports descendant PID")
      .unwrap()
      .parse::<libc::pid_t>()
      .unwrap();
    assert_eq!(get_process_group(descendant_pid).unwrap(), pid);
    let owned =
      ProcessGroupChild::wrap(child, Instant::now() + Duration::from_secs(2))
        .unwrap();

    drop(release);
    let error = owned.wait().unwrap_err();

    assert_eq!(error.kind(), io::ErrorKind::Other);
    assert_direct_child_reaped(pid);
    assert_process_group_absent_now(pid);
    assert_process_disappears(descendant_pid);
    assert_process_group_disappears(pid);
  }

  #[test]
  fn already_exited_child_is_reaped_and_refused() {
    let child = isolated_shell("exit 0", false);
    let pid = libc::pid_t::try_from(child.id()).unwrap();
    thread::sleep(Duration::from_millis(100));

    let error =
      ProcessGroupChild::wrap(child, Instant::now() + Duration::from_secs(2))
        .unwrap_err();

    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    assert_direct_child_reaped(pid);
    assert_process_group_disappears(pid);
  }

  #[test]
  fn timeout_kills_group_and_reaps_direct_child() {
    let child = isolated_shell("exec sleep 30", false);
    let pid = libc::pid_t::try_from(child.id()).unwrap();
    let final_deadline = Instant::now() + Duration::from_millis(400);
    let owned = ProcessGroupChild::wrap(child, final_deadline).unwrap();

    let error = owned.wait().unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert!(Instant::now() < final_deadline);
    assert_direct_child_reaped(pid);
    assert_process_group_absent_now(pid);
    assert_process_group_disappears(pid);
  }

  #[test]
  fn timeout_kills_descendants_in_the_verified_group() {
    let mut child = isolated_shell("sleep 30 & echo $!; wait", true);
    let pid = libc::pid_t::try_from(child.id()).unwrap();
    let stdout = child.stdout.take().unwrap();
    let mut lines = BufReader::new(stdout).lines();
    let descendant_pid = lines
      .next()
      .expect("shell reports descendant PID")
      .unwrap()
      .parse::<libc::pid_t>()
      .unwrap();
    assert_eq!(get_process_group(descendant_pid).unwrap(), pid);

    let final_deadline = Instant::now() + Duration::from_millis(400);
    let owned = ProcessGroupChild::wrap(child, final_deadline).unwrap();
    assert_eq!(owned.wait().unwrap_err().kind(), io::ErrorKind::TimedOut);

    assert!(Instant::now() < final_deadline);
    assert_direct_child_reaped(pid);
    assert_process_group_absent_now(pid);
    assert_process_disappears(descendant_pid);
    assert_process_group_disappears(pid);
  }

  #[test]
  fn nonisolated_child_is_rejected_killed_and_reaped() {
    let child = plain_shell("exec sleep 30");
    let pid = libc::pid_t::try_from(child.id()).unwrap();
    let error =
      ProcessGroupChild::wrap(child, Instant::now() + Duration::from_secs(2))
        .unwrap_err();

    assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
    assert_direct_child_reaped(pid);
    assert_process_disappears(pid);
  }

  #[test]
  fn drop_kills_group_and_reaps_direct_child() {
    let child = isolated_shell("exec sleep 30", false);
    let pid = libc::pid_t::try_from(child.id()).unwrap();
    let owned =
      ProcessGroupChild::wrap(child, Instant::now() + Duration::from_secs(30))
        .unwrap();

    drop(owned);

    assert_direct_child_reaped(pid);
    assert_process_disappears(pid);
    assert_process_group_disappears(pid);
  }

  fn isolated_shell(script: &str, capture_stdout: bool) -> Child {
    let mut command = Command::new("/bin/sh");
    command.arg("-c").arg(script);
    if capture_stdout {
      command.stdout(Stdio::piped());
    } else {
      command.stdout(Stdio::null());
    }
    command.stderr(Stdio::null());
    configure_isolated_process_group(&mut command);
    command.spawn().unwrap()
  }

  fn plain_shell(script: &str) -> Child {
    Command::new("/bin/sh")
      .arg("-c")
      .arg(script)
      .stdout(Stdio::null())
      .stderr(Stdio::null())
      .spawn()
      .unwrap()
  }

  fn assert_direct_child_reaped(pid: libc::pid_t) {
    let mut status = 0;
    loop {
      // SAFETY: status points to writable storage and WNOHANG is valid.
      let result = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
      if result < 0 {
        let error = io::Error::last_os_error();
        if error.kind() == io::ErrorKind::Interrupted {
          continue;
        }
        assert_eq!(error.raw_os_error(), Some(libc::ECHILD));
        return;
      }
      panic!("direct child {pid} was not reaped; waitpid returned {result}");
    }
  }

  fn assert_process_disappears(pid: libc::pid_t) {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
      // SAFETY: signal zero probes existence without delivering a signal.
      let result = unsafe { libc::kill(pid, 0) };
      if result < 0
        && io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
      {
        return;
      }
      assert!(
        Instant::now() < deadline,
        "process {pid} remained after fail-closed cleanup"
      );
      thread::sleep(Duration::from_millis(10));
    }
  }

  fn assert_process_group_disappears(process_group_id: libc::pid_t) {
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
      // SAFETY: signal zero probes the positive, verified group id.
      let result = unsafe { libc::kill(-process_group_id, 0) };
      if result < 0
        && io::Error::last_os_error().raw_os_error() == Some(libc::ESRCH)
      {
        return;
      }
      assert!(
        Instant::now() < deadline,
        "process group {process_group_id} remained after fail-closed cleanup"
      );
      thread::sleep(Duration::from_millis(10));
    }
  }

  fn assert_process_group_absent_now(process_group_id: libc::pid_t) {
    // SAFETY: signal zero probes the positive, verified group id.
    let result = unsafe { libc::kill(-process_group_id, 0) };
    assert!(result < 0, "process group {process_group_id} still exists");
    assert_eq!(io::Error::last_os_error().raw_os_error(), Some(libc::ESRCH));
  }
}

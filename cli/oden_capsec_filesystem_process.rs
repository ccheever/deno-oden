// Copyright 2018-2026 the Deno authors. MIT license.

use std::fmt;
use std::io;
use std::os::unix::process::CommandExt;
use std::os::unix::process::ExitStatusExt;
use std::process::Child;
use std::process::Command;
use std::thread;
use std::time::Duration;
use std::time::Instant;

const STATUS_POLL_INTERVAL: Duration = Duration::from_millis(10);
pub(crate) const CLEANUP_RESERVE: Duration = Duration::from_millis(2_000);

pub(crate) fn configure_supervisor_process_group(command: &mut Command) {
  command.process_group(0);
}

pub(crate) fn configure_candidate_process_group(
  command: &mut Command,
  supervisor_process_group: libc::pid_t,
) -> io::Result<()> {
  if supervisor_process_group <= 0 {
    return Err(invalid_input("candidate process group must be positive"));
  }
  command.process_group(supervisor_process_group);
  Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ChildRole {
  Supervisor,
  Candidate,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct TerminalObservationFact {
  pub(crate) order: u64,
  pub(crate) role: ChildRole,
  pub(crate) pid: libc::pid_t,
  pub(crate) wait_code: libc::c_int,
  pub(crate) wait_status: libc::c_int,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ExactReapFact {
  pub(crate) order: u64,
  pub(crate) role: ChildRole,
  pub(crate) pid: libc::pid_t,
  pub(crate) exit_code: Option<i32>,
  pub(crate) signal: Option<i32>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum GroupScrubOutcome {
  Delivered,
  AlreadyAbsent,
  DarwinTerminalLeaderPermissionDenied,
  Refused { raw_os_error: Option<i32> },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct GroupScrubFact {
  pub(crate) order: u64,
  pub(crate) process_group_id: libc::pid_t,
  pub(crate) outcome: GroupScrubOutcome,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum FinalProbeOutcome {
  Absent,
  Present,
  Refused { raw_os_error: Option<i32> },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct FinalGroupProbeFact {
  pub(crate) order: u64,
  pub(crate) process_group_id: libc::pid_t,
  pub(crate) outcome: FinalProbeOutcome,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LifecyclePath {
  Success,
  Failure,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ParentLifecycleTerminalFacts {
  pub(crate) path: LifecyclePath,
  pub(crate) supervisor_pid: libc::pid_t,
  pub(crate) candidate_pid: Option<libc::pid_t>,
  pub(crate) observations: Vec<TerminalObservationFact>,
  pub(crate) scrubs: Vec<GroupScrubFact>,
  pub(crate) exact_reaps: Vec<ExactReapFact>,
  pub(crate) final_probes: Vec<FinalGroupProbeFact>,
  pub(crate) deadline_exceeded: bool,
  pub(crate) eligible: bool,
  pub(crate) cleanup_errors: Vec<String>,
}

#[derive(Debug)]
pub(crate) struct ParentLifecycleFailure {
  pub(crate) error: io::Error,
  pub(crate) facts: ParentLifecycleTerminalFacts,
}

impl fmt::Display for ParentLifecycleFailure {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    self.error.fmt(formatter)
  }
}

impl std::error::Error for ParentLifecycleFailure {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RawTerminal {
  wait_code: libc::c_int,
  wait_status: libc::c_int,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct RawReap {
  exit_code: Option<i32>,
  signal: Option<i32>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum KernelScrubOutcome {
  Delivered,
  AlreadyAbsent,
}

trait LifecycleBackend {
  type Handle;

  fn child_pid(&self, child: &Self::Handle) -> io::Result<libc::pid_t>;
  fn process_group(&mut self, pid: libc::pid_t) -> io::Result<libc::pid_t>;
  fn parent_process_group(&mut self) -> io::Result<libc::pid_t>;
  fn observe_terminal(
    &mut self,
    pid: libc::pid_t,
  ) -> io::Result<Option<RawTerminal>>;
  fn reap_exact(&mut self, child: &mut Self::Handle) -> io::Result<RawReap>;
  fn scrub_group(
    &mut self,
    process_group_id: libc::pid_t,
  ) -> io::Result<KernelScrubOutcome>;
  fn probe_group_absent(
    &mut self,
    process_group_id: libc::pid_t,
  ) -> io::Result<bool>;
  fn kill_direct(&mut self, child: &mut Self::Handle) -> io::Result<()>;
  fn now(&self) -> Instant;
  fn sleep(&mut self, duration: Duration);
  fn is_darwin(&self) -> bool;
}

struct Running<H> {
  handle: H,
}

struct TerminalObserved<H> {
  handle: H,
  observation: TerminalObservationFact,
}

struct Reaped {
  observation: TerminalObservationFact,
  reap: ExactReapFact,
}

struct ExactChild<S> {
  role: ChildRole,
  pid: libc::pid_t,
  state: S,
}

enum ChildSlot<H> {
  Running(ExactChild<Running<H>>),
  TerminalObserved(ExactChild<TerminalObserved<H>>),
  Reaped(ExactChild<Reaped>),
  Transitioning,
}

impl<H> ChildSlot<H> {
  fn pid(&self) -> libc::pid_t {
    match self {
      Self::Running(child) => child.pid,
      Self::TerminalObserved(child) => child.pid,
      Self::Reaped(child) => child.pid,
      Self::Transitioning => unreachable!("child transition is synchronous"),
    }
  }

  fn is_running(&self) -> bool {
    matches!(self, Self::Running(_))
  }

  fn is_reaped(&self) -> bool {
    matches!(self, Self::Reaped(_))
  }

  fn observation(&self) -> Option<&TerminalObservationFact> {
    match self {
      Self::TerminalObserved(child) => Some(&child.state.observation),
      Self::Reaped(child) => Some(&child.state.observation),
      Self::Running(_) => None,
      Self::Transitioning => unreachable!("child transition is synchronous"),
    }
  }
}

struct FactBuilder {
  path: LifecyclePath,
  supervisor_pid: libc::pid_t,
  candidate_pid: Option<libc::pid_t>,
  observations: Vec<TerminalObservationFact>,
  scrubs: Vec<GroupScrubFact>,
  exact_reaps: Vec<ExactReapFact>,
  final_probes: Vec<FinalGroupProbeFact>,
  deadline_exceeded: bool,
  eligible: bool,
  cleanup_errors: Vec<String>,
}

impl FactBuilder {
  fn terminal(&self) -> ParentLifecycleTerminalFacts {
    ParentLifecycleTerminalFacts {
      path: self.path,
      supervisor_pid: self.supervisor_pid,
      candidate_pid: self.candidate_pid,
      observations: self.observations.clone(),
      scrubs: self.scrubs.clone(),
      exact_reaps: self.exact_reaps.clone(),
      final_probes: self.final_probes.clone(),
      deadline_exceeded: self.deadline_exceeded,
      eligible: self.eligible,
      cleanup_errors: self.cleanup_errors.clone(),
    }
  }
}

struct ParentLifecycleCellImpl<B: LifecycleBackend> {
  backend: B,
  supervisor: ChildSlot<B::Handle>,
  candidate: Option<ChildSlot<B::Handle>>,
  process_group_id: libc::pid_t,
  final_deadline: Instant,
  work_deadline: Instant,
  next_order: u64,
  facts: FactBuilder,
  terminal: bool,
  candidate_outside_group: bool,
}

/// Owns the supervisor group leader and candidate group member as exact direct
/// children. No method returns until every admitted handle is reaped and the
/// post-reap ESRCH proof is terminal.
// @ref LLP 0019#parent-supervisor-transport-and-single-process-lifetime-cell
// [implements] — WNOWAIT observations precede exact candidate/supervisor reaps;
// destructive group signalling is forbidden after the leader reap.
pub(crate) struct ParentLifecycleCell {
  inner: ParentLifecycleCellImpl<UnixBackend>,
}

impl ParentLifecycleCell {
  pub(crate) fn new(
    supervisor: Child,
    final_deadline: Instant,
  ) -> io::Result<Self> {
    Ok(Self {
      inner: ParentLifecycleCellImpl::with_backend(
        supervisor,
        UnixBackend,
        final_deadline,
      )?,
    })
  }

  pub(crate) fn process_group_id(&self) -> libc::pid_t {
    self.inner.process_group_id()
  }

  pub(crate) fn final_deadline(&self) -> Instant {
    self.inner.final_deadline()
  }

  pub(crate) fn work_deadline(&self) -> Instant {
    self.inner.work_deadline()
  }

  pub(crate) fn admit_candidate(
    &mut self,
    candidate: Child,
  ) -> Result<(), ParentLifecycleFailure> {
    self.inner.admit_candidate(candidate)
  }

  pub(crate) fn reap_successful_candidate(
    &mut self,
  ) -> Result<ExactReapFact, ParentLifecycleFailure> {
    self.inner.reap_successful_candidate()
  }

  pub(crate) fn finish_success(
    &mut self,
  ) -> Result<ParentLifecycleTerminalFacts, ParentLifecycleFailure> {
    self.inner.finish_success()
  }

  pub(crate) fn refuse(
    &mut self,
    primary: io::Error,
  ) -> ParentLifecycleFailure {
    self.inner.refuse(primary)
  }
}

impl<B: LifecycleBackend> ParentLifecycleCellImpl<B> {
  fn with_backend(
    mut supervisor: B::Handle,
    mut backend: B,
    final_deadline: Instant,
  ) -> io::Result<Self> {
    let supervisor_pid = match backend.child_pid(&supervisor) {
      Ok(pid) if pid > 0 => pid,
      Ok(_) => {
        cleanup_unadmitted(&mut backend, &mut supervisor);
        return Err(invalid_input("supervisor PID must be positive"));
      }
      Err(error) => {
        cleanup_unadmitted(&mut backend, &mut supervisor);
        return Err(error);
      }
    };
    let parent_group = match backend.parent_process_group() {
      Ok(group) => group,
      Err(error) => {
        cleanup_unadmitted(&mut backend, &mut supervisor);
        return Err(error);
      }
    };
    let process_group_id = match backend.process_group(supervisor_pid) {
      Ok(group) => group,
      Err(error) => {
        cleanup_unadmitted(&mut backend, &mut supervisor);
        return Err(error);
      }
    };
    if process_group_id != supervisor_pid || process_group_id == parent_group {
      cleanup_unadmitted(&mut backend, &mut supervisor);
      return Err(invalid_input(
        "supervisor is not the isolated leader of its process group",
      ));
    }

    let work_deadline = final_deadline
      .checked_sub(CLEANUP_RESERVE)
      .unwrap_or(final_deadline);
    let mut cell = Self {
      backend,
      supervisor: ChildSlot::Running(ExactChild {
        role: ChildRole::Supervisor,
        pid: supervisor_pid,
        state: Running { handle: supervisor },
      }),
      candidate: None,
      process_group_id,
      final_deadline,
      work_deadline,
      next_order: 1,
      facts: FactBuilder {
        path: LifecyclePath::Success,
        supervisor_pid,
        candidate_pid: None,
        observations: Vec::new(),
        scrubs: Vec::new(),
        exact_reaps: Vec::new(),
        final_probes: Vec::new(),
        deadline_exceeded: false,
        eligible: false,
        cleanup_errors: Vec::new(),
      },
      terminal: false,
      candidate_outside_group: false,
    };
    if cell.backend.now() >= work_deadline {
      let failure = cell.refuse(io::Error::new(
        io::ErrorKind::TimedOut,
        "lifecycle began inside its fixed cleanup reserve",
      ));
      return Err(failure.error);
    }
    Ok(cell)
  }

  fn process_group_id(&self) -> libc::pid_t {
    self.process_group_id
  }

  fn final_deadline(&self) -> Instant {
    self.final_deadline
  }

  fn work_deadline(&self) -> Instant {
    self.work_deadline
  }

  fn admit_candidate(
    &mut self,
    mut candidate: B::Handle,
  ) -> Result<(), ParentLifecycleFailure> {
    assert!(
      !self.terminal,
      "terminal lifecycle cannot admit a candidate"
    );
    if self.candidate.is_some() {
      cleanup_unadmitted(&mut self.backend, &mut candidate);
      return Err(self.refuse(invalid_input("candidate is already admitted")));
    }
    let candidate_pid = match self.backend.child_pid(&candidate) {
      Ok(pid) if pid > 0 => pid,
      Ok(_) => {
        cleanup_unadmitted(&mut self.backend, &mut candidate);
        return Err(
          self.refuse(invalid_input("candidate PID must be positive")),
        );
      }
      Err(error) => {
        cleanup_unadmitted(&mut self.backend, &mut candidate);
        return Err(self.refuse(error));
      }
    };
    self.facts.candidate_pid = Some(candidate_pid);
    self.candidate = Some(ChildSlot::Running(ExactChild {
      role: ChildRole::Candidate,
      pid: candidate_pid,
      state: Running { handle: candidate },
    }));

    let candidate_group = match self.backend.process_group(candidate_pid) {
      Ok(group) => group,
      Err(error) => {
        self.candidate_outside_group = true;
        return Err(self.refuse(error));
      }
    };
    if candidate_pid == self.facts.supervisor_pid
      || candidate_group != self.process_group_id
    {
      self.candidate_outside_group = true;
      return Err(self.refuse(invalid_input(
        "candidate did not join the owned supervisor process group",
      )));
    }
    match self.observe_once(ChildRole::Supervisor) {
      Ok(false) => {}
      Ok(true) => {
        return Err(self.refuse(invalid_input(
          "supervisor exited before candidate admission completed",
        )));
      }
      Err(error) => return Err(self.refuse(error)),
    }
    match self.observe_once(ChildRole::Candidate) {
      Ok(false) => Ok(()),
      Ok(true) => Err(
        self
          .refuse(invalid_input("candidate exited before admission completed")),
      ),
      Err(error) => Err(self.refuse(error)),
    }
  }

  /// Reaps a successful candidate only after a WNOWAIT observation and an
  /// immediate second proof that the exact supervisor remains unreaped.
  fn reap_successful_candidate(
    &mut self,
  ) -> Result<ExactReapFact, ParentLifecycleFailure> {
    assert!(!self.terminal, "terminal lifecycle cannot reap a candidate");
    loop {
      if self.backend.now() >= self.work_deadline {
        return Err(self.refuse(io::Error::new(
          io::ErrorKind::TimedOut,
          "candidate did not exit before the cleanup reserve",
        )));
      }
      match self.observe_once(ChildRole::Supervisor) {
        Ok(false) => {}
        Ok(true) => {
          return Err(self.refuse(io::Error::other(
            "supervisor exited before candidate exact reap",
          )));
        }
        Err(error) => return Err(self.refuse(error)),
      }
      match self.observe_once(ChildRole::Candidate) {
        Ok(false) => {
          self.backend.sleep(STATUS_POLL_INTERVAL);
          continue;
        }
        Ok(true) => {}
        Err(error) => return Err(self.refuse(error)),
      }
      match self.observe_once(ChildRole::Supervisor) {
        Ok(false) => {}
        Ok(true) => {
          return Err(self.refuse(io::Error::other(
            "supervisor exited at candidate exact-reap boundary",
          )));
        }
        Err(error) => return Err(self.refuse(error)),
      }
      let observation = self
        .candidate
        .as_ref()
        .and_then(ChildSlot::observation)
        .cloned()
        .expect("candidate was observed terminal");
      let reap = match self.reap_role(ChildRole::Candidate) {
        Ok(reap) => reap,
        Err(error) => return Err(self.refuse(error)),
      };
      if !terminal_is_success(&observation) || !reap_is_success(&reap) {
        return Err(
          self.refuse(io::Error::other("candidate did not exit successfully")),
        );
      }
      if !observation_matches_reap(&observation, &reap) {
        return Err(self.refuse(io::Error::other(
          "candidate WNOWAIT observation disagreed with exact reap",
        )));
      }
      return Ok(reap);
    }
  }

  fn finish_success(
    &mut self,
  ) -> Result<ParentLifecycleTerminalFacts, ParentLifecycleFailure> {
    assert!(!self.terminal, "lifecycle is already terminal");
    if !self.candidate.as_ref().is_some_and(ChildSlot::is_reaped) {
      return Err(self.refuse(io::Error::other(
        "success requires an admitted, exactly reaped candidate",
      )));
    }
    loop {
      if self.backend.now() >= self.work_deadline {
        return Err(self.refuse(io::Error::new(
          io::ErrorKind::TimedOut,
          "supervisor did not exit before the cleanup reserve",
        )));
      }
      match self.observe_once(ChildRole::Supervisor) {
        Ok(true) => break,
        Ok(false) => self.backend.sleep(STATUS_POLL_INTERVAL),
        Err(error) => return Err(self.refuse(error)),
      }
    }
    let observation = self
      .supervisor
      .observation()
      .cloned()
      .expect("supervisor was observed terminal");
    if !terminal_is_success(&observation) {
      return Err(
        self.refuse(io::Error::other("supervisor did not exit successfully")),
      );
    }

    let scrub = self.backend.scrub_group(self.process_group_id);
    match scrub {
      Ok(KernelScrubOutcome::Delivered) => {
        self.record_scrub(GroupScrubOutcome::Delivered)
      }
      Ok(KernelScrubOutcome::AlreadyAbsent) => {
        self.record_scrub(GroupScrubOutcome::AlreadyAbsent)
      }
      Err(error)
        if cfg!(target_os = "macos")
          && self.backend.is_darwin()
          && error.raw_os_error() == Some(libc::EPERM)
          && self.supervisor.observation().is_some()
          && self.candidate.as_ref().is_some_and(ChildSlot::is_reaped) =>
      {
        self.record_scrub(
          GroupScrubOutcome::DarwinTerminalLeaderPermissionDenied,
        );
      }
      Err(error) => {
        self.record_scrub(GroupScrubOutcome::Refused {
          raw_os_error: error.raw_os_error(),
        });
        return Err(self.refuse(error));
      }
    }

    let reap = match self.reap_role(ChildRole::Supervisor) {
      Ok(reap) => reap,
      Err(error) => return Err(self.refuse(error)),
    };
    let mut refusal = None;
    if !reap_is_success(&reap) || !observation_matches_reap(&observation, &reap)
    {
      refusal = Some(io::Error::other(
        "supervisor WNOWAIT observation disagreed with exact successful reap",
      ));
    }
    let first_probe = self.record_probe();
    if !matches!(first_probe, FinalProbeOutcome::Absent) {
      refusal.get_or_insert_with(|| {
        io::Error::other("post-reap group probe was not ESRCH")
      });
    }
    if self.backend.now() >= self.final_deadline {
      self.facts.deadline_exceeded = true;
      refusal.get_or_insert_with(|| {
        io::Error::new(
          io::ErrorKind::TimedOut,
          "cleanup exceeded the immutable final deadline",
        )
      });
    }
    if let Some(error) = refusal {
      self.facts.path = LifecyclePath::Failure;
      self.wait_for_absence_after_leader_reap();
      self.terminal = true;
      return Err(self.failure(error));
    }
    self.facts.eligible = true;
    self.terminal = true;
    Ok(self.facts.terminal())
  }

  fn refuse(&mut self, primary: io::Error) -> ParentLifecycleFailure {
    assert!(!self.terminal, "lifecycle is already terminal");
    self.facts.path = LifecyclePath::Failure;
    self.facts.eligible = false;

    if !self.supervisor.is_reaped() {
      self.scrub_until_accepted();
    }
    if self.candidate_outside_group {
      self.kill_outside_candidate();
    }
    self.observe_all_terminal();
    self.reap_until_done(ChildRole::Candidate);
    self.reap_until_done(ChildRole::Supervisor);
    self.wait_for_absence_after_leader_reap();
    self.terminal = true;
    self.failure(primary)
  }

  fn failure(&self, primary: io::Error) -> ParentLifecycleFailure {
    let error = if self.facts.cleanup_errors.is_empty() {
      primary
    } else {
      io::Error::new(
        primary.kind(),
        format!(
          "{primary}; cleanup observations: {}",
          self.facts.cleanup_errors.join("; ")
        ),
      )
    };
    ParentLifecycleFailure {
      error,
      facts: self.facts.terminal(),
    }
  }

  fn slot(&self, role: ChildRole) -> Option<&ChildSlot<B::Handle>> {
    match role {
      ChildRole::Supervisor => Some(&self.supervisor),
      ChildRole::Candidate => self.candidate.as_ref(),
    }
  }

  fn slot_mut(&mut self, role: ChildRole) -> Option<&mut ChildSlot<B::Handle>> {
    match role {
      ChildRole::Supervisor => Some(&mut self.supervisor),
      ChildRole::Candidate => self.candidate.as_mut(),
    }
  }

  fn observe_once(&mut self, role: ChildRole) -> io::Result<bool> {
    let Some(slot) = self.slot(role) else {
      return Ok(false);
    };
    if !slot.is_running() {
      return Ok(slot.observation().is_some());
    }
    let pid = slot.pid();
    let Some(raw) = self.backend.observe_terminal(pid)? else {
      return Ok(false);
    };
    let observation = TerminalObservationFact {
      order: self.take_order(),
      role,
      pid,
      wait_code: raw.wait_code,
      wait_status: raw.wait_status,
    };
    let slot = self.slot_mut(role).expect("role remained owned");
    let previous = std::mem::replace(slot, ChildSlot::Transitioning);
    let ChildSlot::Running(child) = previous else {
      unreachable!("only running children are observed")
    };
    debug_assert_eq!(child.role, role);
    *slot = ChildSlot::TerminalObserved(ExactChild {
      role,
      pid,
      state: TerminalObserved {
        handle: child.state.handle,
        observation: observation.clone(),
      },
    });
    self.facts.observations.push(observation);
    self.mark_deadline();
    Ok(true)
  }

  fn reap_role(&mut self, role: ChildRole) -> io::Result<ExactReapFact> {
    let slot = self.slot_mut(role).ok_or_else(|| {
      invalid_input("attempted to reap a child that was never admitted")
    })?;
    let previous = std::mem::replace(slot, ChildSlot::Transitioning);
    let ChildSlot::TerminalObserved(mut child) = previous else {
      *slot = previous;
      return Err(invalid_input(
        "exact reap requires a prior WNOWAIT terminal observation",
      ));
    };
    let raw = match self.backend.reap_exact(&mut child.state.handle) {
      Ok(raw) => raw,
      Err(error) => {
        *self.slot_mut(role).expect("role remained owned") =
          ChildSlot::TerminalObserved(child);
        return Err(error);
      }
    };
    let reap = ExactReapFact {
      order: self.take_order(),
      role,
      pid: child.pid,
      exit_code: raw.exit_code,
      signal: raw.signal,
    };
    *self.slot_mut(role).expect("role remained owned") =
      ChildSlot::Reaped(ExactChild {
        role,
        pid: child.pid,
        state: Reaped {
          observation: child.state.observation,
          reap: reap.clone(),
        },
      });
    self.facts.exact_reaps.push(reap.clone());
    self.mark_deadline();
    Ok(reap)
  }

  fn scrub_until_accepted(&mut self) {
    loop {
      match self.backend.scrub_group(self.process_group_id) {
        Ok(KernelScrubOutcome::Delivered) => {
          self.record_scrub(GroupScrubOutcome::Delivered);
          return;
        }
        Ok(KernelScrubOutcome::AlreadyAbsent) => {
          self.record_scrub(GroupScrubOutcome::AlreadyAbsent);
          return;
        }
        Err(error) => {
          self.record_scrub(GroupScrubOutcome::Refused {
            raw_os_error: error.raw_os_error(),
          });
          self
            .facts
            .cleanup_errors
            .push(format!("failure-path group scrub refused: {error}"));
          self.mark_deadline();
          self.backend.sleep(STATUS_POLL_INTERVAL);
        }
      }
    }
  }

  fn kill_outside_candidate(&mut self) {
    let Some(ChildSlot::Running(candidate)) = self.candidate.as_mut() else {
      return;
    };
    if let Err(error) = self.backend.kill_direct(&mut candidate.state.handle) {
      self.facts.cleanup_errors.push(format!(
        "out-of-group candidate direct kill refused: {error}"
      ));
    }
  }

  fn observe_all_terminal(&mut self) {
    loop {
      let supervisor_done = !self.supervisor.is_running();
      let candidate_done = self
        .candidate
        .as_ref()
        .is_none_or(|candidate| !candidate.is_running());
      if supervisor_done && candidate_done {
        return;
      }
      for role in [ChildRole::Supervisor, ChildRole::Candidate] {
        if self.slot(role).is_some_and(ChildSlot::is_running)
          && let Err(error) = self.observe_once(role)
        {
          self
            .facts
            .cleanup_errors
            .push(format!("{role:?} WNOWAIT observation failed: {error}"));
        }
      }
      self.mark_deadline();
      self.backend.sleep(STATUS_POLL_INTERVAL);
    }
  }

  fn reap_until_done(&mut self, role: ChildRole) {
    loop {
      let Some(slot) = self.slot(role) else {
        return;
      };
      if slot.is_reaped() {
        return;
      }
      if slot.is_running() {
        self.observe_all_terminal();
        continue;
      }
      match self.reap_role(role) {
        Ok(_) => return,
        Err(error) => {
          self
            .facts
            .cleanup_errors
            .push(format!("{role:?} exact reap failed: {error}"));
          self.mark_deadline();
          self.backend.sleep(STATUS_POLL_INTERVAL);
        }
      }
    }
  }

  fn record_scrub(&mut self, outcome: GroupScrubOutcome) {
    let order = self.take_order();
    self.facts.scrubs.push(GroupScrubFact {
      order,
      process_group_id: self.process_group_id,
      outcome,
    });
    self.mark_deadline();
  }

  fn record_probe(&mut self) -> FinalProbeOutcome {
    let outcome = match self.backend.probe_group_absent(self.process_group_id) {
      Ok(true) => FinalProbeOutcome::Absent,
      Ok(false) => FinalProbeOutcome::Present,
      Err(error) => FinalProbeOutcome::Refused {
        raw_os_error: error.raw_os_error(),
      },
    };
    let order = self.take_order();
    self.facts.final_probes.push(FinalGroupProbeFact {
      order,
      process_group_id: self.process_group_id,
      outcome: outcome.clone(),
    });
    self.mark_deadline();
    outcome
  }

  fn wait_for_absence_after_leader_reap(&mut self) {
    debug_assert!(self.supervisor.is_reaped());
    if self
      .facts
      .final_probes
      .last()
      .is_some_and(|probe| probe.outcome == FinalProbeOutcome::Absent)
    {
      return;
    }
    loop {
      if matches!(self.record_probe(), FinalProbeOutcome::Absent) {
        return;
      }
      self.facts.cleanup_errors.push(
        "post-reap signal-zero probe was not ESRCH; no destructive retry issued"
          .to_string(),
      );
      self.backend.sleep(STATUS_POLL_INTERVAL);
    }
  }

  fn take_order(&mut self) -> u64 {
    let order = self.next_order;
    self.next_order += 1;
    order
  }

  fn mark_deadline(&mut self) {
    if self.backend.now() >= self.final_deadline {
      self.facts.deadline_exceeded = true;
    }
  }
}

impl<B: LifecycleBackend> Drop for ParentLifecycleCellImpl<B> {
  fn drop(&mut self) {
    if !self.terminal {
      let _ = self.refuse(io::Error::other(
        "parent lifecycle dropped before terminalization",
      ));
    }
  }
}

fn terminal_is_success(observation: &TerminalObservationFact) -> bool {
  observation.wait_code == libc::CLD_EXITED && observation.wait_status == 0
}

fn reap_is_success(reap: &ExactReapFact) -> bool {
  reap.exit_code == Some(0) && reap.signal.is_none()
}

fn observation_matches_reap(
  observation: &TerminalObservationFact,
  reap: &ExactReapFact,
) -> bool {
  match observation.wait_code {
    libc::CLD_EXITED => {
      reap.exit_code == Some(observation.wait_status) && reap.signal.is_none()
    }
    libc::CLD_KILLED | libc::CLD_DUMPED => {
      reap.exit_code.is_none() && reap.signal == Some(observation.wait_status)
    }
    _ => false,
  }
}

fn cleanup_unadmitted<B: LifecycleBackend>(
  backend: &mut B,
  child: &mut B::Handle,
) {
  let _ = backend.kill_direct(child);
  if let Ok(pid) = backend.child_pid(child) {
    loop {
      match backend.observe_terminal(pid) {
        Ok(Some(_)) => break,
        Ok(None) | Err(_) => backend.sleep(STATUS_POLL_INTERVAL),
      }
    }
  }
  while backend.reap_exact(child).is_err() {
    backend.sleep(STATUS_POLL_INTERVAL);
  }
}

fn invalid_input(message: impl Into<String>) -> io::Error {
  io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

struct UnixBackend;

impl LifecycleBackend for UnixBackend {
  type Handle = Child;

  fn child_pid(&self, child: &Child) -> io::Result<libc::pid_t> {
    libc::pid_t::try_from(child.id())
      .map_err(|_| invalid_input("child PID is outside the Unix PID range"))
  }

  fn process_group(&mut self, pid: libc::pid_t) -> io::Result<libc::pid_t> {
    loop {
      // SAFETY: pid belongs to an exact direct-child handle.
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

  fn parent_process_group(&mut self) -> io::Result<libc::pid_t> {
    // SAFETY: getpgrp has no arguments and cannot fail.
    Ok(unsafe { libc::getpgrp() })
  }

  fn observe_terminal(
    &mut self,
    pid: libc::pid_t,
  ) -> io::Result<Option<RawTerminal>> {
    loop {
      // SAFETY: zero is a valid initial state for siginfo_t, and waitid writes
      // it before a nonzero si_pid is inspected. WNOWAIT preserves reap rights.
      let mut info: libc::siginfo_t = unsafe { std::mem::zeroed() };
      // SAFETY: info is writable and pid names an owned direct child.
      let result = unsafe {
        libc::waitid(
          libc::P_PID,
          pid as libc::id_t,
          &mut info,
          libc::WEXITED | libc::WNOHANG | libc::WNOWAIT,
        )
      };
      if result == 0 {
        // SAFETY: waitid initialized info on success.
        let observed_pid = unsafe { info.si_pid() };
        if observed_pid == 0 {
          return Ok(None);
        }
        if observed_pid != pid {
          return Err(io::Error::other(
            "waitid returned a different direct-child identity",
          ));
        }
        // SAFETY: waitid initialized the child status fields on success.
        let wait_status = unsafe { info.si_status() };
        return Ok(Some(RawTerminal {
          wait_code: info.si_code,
          wait_status,
        }));
      }
      let error = io::Error::last_os_error();
      if error.kind() != io::ErrorKind::Interrupted {
        return Err(error);
      }
    }
  }

  fn reap_exact(&mut self, child: &mut Child) -> io::Result<RawReap> {
    loop {
      match child.wait() {
        Ok(status) => {
          return Ok(RawReap {
            exit_code: status.code(),
            signal: status.signal(),
          });
        }
        Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
        Err(error) => return Err(error),
      }
    }
  }

  fn scrub_group(
    &mut self,
    process_group_id: libc::pid_t,
  ) -> io::Result<KernelScrubOutcome> {
    loop {
      // SAFETY: the negative id is the verified, still-pinned child group.
      let result = unsafe { libc::kill(-process_group_id, libc::SIGKILL) };
      if result == 0 {
        return Ok(KernelScrubOutcome::Delivered);
      }
      let error = io::Error::last_os_error();
      if error.kind() == io::ErrorKind::Interrupted {
        continue;
      }
      if error.raw_os_error() == Some(libc::ESRCH) {
        return Ok(KernelScrubOutcome::AlreadyAbsent);
      }
      return Err(error);
    }
  }

  fn probe_group_absent(
    &mut self,
    process_group_id: libc::pid_t,
  ) -> io::Result<bool> {
    loop {
      // SAFETY: signal zero observes but does not mutate the numeric group.
      let result = unsafe { libc::kill(-process_group_id, 0) };
      if result == 0 {
        return Ok(false);
      }
      let error = io::Error::last_os_error();
      if error.kind() == io::ErrorKind::Interrupted {
        continue;
      }
      if error.raw_os_error() == Some(libc::ESRCH) {
        return Ok(true);
      }
      return Err(error);
    }
  }

  fn kill_direct(&mut self, child: &mut Child) -> io::Result<()> {
    match child.kill() {
      Err(error) if error.raw_os_error() == Some(libc::ESRCH) => Ok(()),
      result => result,
    }
  }

  fn now(&self) -> Instant {
    Instant::now()
  }

  fn sleep(&mut self, duration: Duration) {
    thread::sleep(duration);
  }

  fn is_darwin(&self) -> bool {
    cfg!(target_os = "macos")
  }
}

#[cfg(test)]
mod tests {
  use std::collections::HashMap;
  use std::collections::VecDeque;

  use super::*;

  #[derive(Clone, Copy, Debug, Eq, PartialEq)]
  struct FakeHandle(libc::pid_t);

  #[derive(Clone, Copy)]
  enum Observation {
    Running,
    Exit(i32),
    Signal(i32),
  }

  #[derive(Clone, Copy)]
  enum Scrub {
    Delivered,
    Absent,
    Error(i32),
  }

  #[derive(Clone, Debug, Eq, PartialEq)]
  enum Event {
    Observe(libc::pid_t),
    Scrub(libc::pid_t),
    Reap(libc::pid_t),
    Probe(libc::pid_t),
  }

  struct FakeBackend {
    now: Instant,
    parent_group: libc::pid_t,
    groups: HashMap<libc::pid_t, libc::pid_t>,
    observations: HashMap<libc::pid_t, VecDeque<Observation>>,
    terminal: HashMap<libc::pid_t, RawTerminal>,
    reaped: Vec<libc::pid_t>,
    scrubs: VecDeque<Scrub>,
    probes: VecDeque<io::Result<bool>>,
    events: Vec<Event>,
    darwin: bool,
  }

  impl FakeBackend {
    fn new(supervisor: libc::pid_t, candidate: libc::pid_t) -> Self {
      Self {
        now: Instant::now(),
        parent_group: 99,
        groups: HashMap::from([
          (supervisor, supervisor),
          (candidate, supervisor),
        ]),
        observations: HashMap::new(),
        terminal: HashMap::new(),
        reaped: Vec::new(),
        scrubs: VecDeque::new(),
        probes: VecDeque::from([Ok(true)]),
        events: Vec::new(),
        darwin: false,
      }
    }

    fn script(
      &mut self,
      pid: libc::pid_t,
      script: impl IntoIterator<Item = Observation>,
    ) {
      self.observations.insert(pid, script.into_iter().collect());
    }
  }

  impl LifecycleBackend for FakeBackend {
    type Handle = FakeHandle;

    fn child_pid(&self, child: &FakeHandle) -> io::Result<libc::pid_t> {
      Ok(child.0)
    }

    fn process_group(&mut self, pid: libc::pid_t) -> io::Result<libc::pid_t> {
      self
        .groups
        .get(&pid)
        .copied()
        .ok_or_else(|| io::Error::from_raw_os_error(libc::ESRCH))
    }

    fn parent_process_group(&mut self) -> io::Result<libc::pid_t> {
      Ok(self.parent_group)
    }

    fn observe_terminal(
      &mut self,
      pid: libc::pid_t,
    ) -> io::Result<Option<RawTerminal>> {
      self.events.push(Event::Observe(pid));
      if let Some(observation) = self
        .observations
        .get_mut(&pid)
        .and_then(VecDeque::pop_front)
      {
        match observation {
          Observation::Running => return Ok(None),
          Observation::Exit(status) => {
            self.terminal.insert(
              pid,
              RawTerminal {
                wait_code: libc::CLD_EXITED,
                wait_status: status,
              },
            );
          }
          Observation::Signal(signal) => {
            self.terminal.insert(
              pid,
              RawTerminal {
                wait_code: libc::CLD_KILLED,
                wait_status: signal,
              },
            );
          }
        }
      }
      Ok(self.terminal.get(&pid).copied())
    }

    fn reap_exact(&mut self, child: &mut FakeHandle) -> io::Result<RawReap> {
      self.events.push(Event::Reap(child.0));
      let terminal = self
        .terminal
        .get(&child.0)
        .copied()
        .ok_or_else(|| io::Error::other("fake child is running"))?;
      self.reaped.push(child.0);
      Ok(match terminal.wait_code {
        libc::CLD_EXITED => RawReap {
          exit_code: Some(terminal.wait_status),
          signal: None,
        },
        _ => RawReap {
          exit_code: None,
          signal: Some(terminal.wait_status),
        },
      })
    }

    fn scrub_group(
      &mut self,
      process_group_id: libc::pid_t,
    ) -> io::Result<KernelScrubOutcome> {
      self.events.push(Event::Scrub(process_group_id));
      match self.scrubs.pop_front().unwrap_or(Scrub::Delivered) {
        Scrub::Delivered => {
          for (&pid, &group) in &self.groups {
            if group == process_group_id && !self.reaped.contains(&pid) {
              self.terminal.entry(pid).or_insert(RawTerminal {
                wait_code: libc::CLD_KILLED,
                wait_status: libc::SIGKILL,
              });
            }
          }
          Ok(KernelScrubOutcome::Delivered)
        }
        Scrub::Absent => Ok(KernelScrubOutcome::AlreadyAbsent),
        Scrub::Error(errno) => Err(io::Error::from_raw_os_error(errno)),
      }
    }

    fn probe_group_absent(
      &mut self,
      process_group_id: libc::pid_t,
    ) -> io::Result<bool> {
      self.events.push(Event::Probe(process_group_id));
      self.probes.pop_front().unwrap_or(Ok(true))
    }

    fn kill_direct(&mut self, child: &mut FakeHandle) -> io::Result<()> {
      self.terminal.insert(
        child.0,
        RawTerminal {
          wait_code: libc::CLD_KILLED,
          wait_status: libc::SIGKILL,
        },
      );
      Ok(())
    }

    fn now(&self) -> Instant {
      self.now
    }
    fn sleep(&mut self, duration: Duration) {
      self.now += duration;
    }
    fn is_darwin(&self) -> bool {
      self.darwin
    }
  }

  #[test]
  fn deterministic_success_orders_observe_reap_scrub_reap_probe() {
    let supervisor = 200;
    let candidate = 201;
    let mut backend = FakeBackend::new(supervisor, candidate);
    backend.script(
      supervisor,
      [
        Observation::Running,
        Observation::Running,
        Observation::Running,
        Observation::Exit(0),
      ],
    );
    backend.script(candidate, [Observation::Running, Observation::Exit(0)]);
    let deadline = backend.now + Duration::from_secs(10);
    let mut cell = ParentLifecycleCellImpl::with_backend(
      FakeHandle(supervisor),
      backend,
      deadline,
    )
    .unwrap();
    cell.admit_candidate(FakeHandle(candidate)).unwrap();
    cell.reap_successful_candidate().unwrap();
    let facts = cell.finish_success().unwrap();

    assert!(facts.eligible);
    assert_eq!(
      facts
        .observations
        .iter()
        .map(|fact| fact.role)
        .collect::<Vec<_>>(),
      [ChildRole::Candidate, ChildRole::Supervisor]
    );
    assert_eq!(
      facts
        .exact_reaps
        .iter()
        .map(|fact| fact.role)
        .collect::<Vec<_>>(),
      [ChildRole::Candidate, ChildRole::Supervisor]
    );
    assert!(matches!(
      facts.scrubs.as_slice(),
      [GroupScrubFact {
        outcome: GroupScrubOutcome::Delivered,
        ..
      }]
    ));
    assert!(matches!(
      facts.final_probes.as_slice(),
      [FinalGroupProbeFact {
        outcome: FinalProbeOutcome::Absent,
        ..
      }]
    ));
    assert_eq!(
      cell.backend.events,
      [
        Event::Observe(supervisor),
        Event::Observe(candidate),
        Event::Observe(supervisor),
        Event::Observe(candidate),
        Event::Observe(supervisor),
        Event::Reap(candidate),
        Event::Observe(supervisor),
        Event::Scrub(supervisor),
        Event::Reap(supervisor),
        Event::Probe(supervisor),
      ]
    );
    let ordered = facts
      .observations
      .iter()
      .map(|fact| fact.order)
      .chain(facts.scrubs.iter().map(|fact| fact.order))
      .chain(facts.exact_reaps.iter().map(|fact| fact.order))
      .chain(facts.final_probes.iter().map(|fact| fact.order))
      .collect::<Vec<_>>();
    let mut sorted = ordered.clone();
    sorted.sort_unstable();
    assert_eq!(sorted, (1..=sorted.len() as u64).collect::<Vec<_>>());
  }

  #[test]
  fn deterministic_failure_scrubs_before_observing_and_reaps_leader_last() {
    let supervisor = 300;
    let candidate = 301;
    let mut backend = FakeBackend::new(supervisor, candidate);
    backend.script(supervisor, [Observation::Running]);
    backend.script(candidate, [Observation::Running]);
    let deadline = backend.now + Duration::from_secs(10);
    let mut cell = ParentLifecycleCellImpl::with_backend(
      FakeHandle(supervisor),
      backend,
      deadline,
    )
    .unwrap();
    cell.admit_candidate(FakeHandle(candidate)).unwrap();
    cell.backend.events.clear();
    let failure = cell.refuse(io::Error::other("injected failure"));
    assert_eq!(
      cell.backend.events,
      [
        Event::Scrub(supervisor),
        Event::Observe(supervisor),
        Event::Observe(candidate),
        Event::Reap(candidate),
        Event::Reap(supervisor),
        Event::Probe(supervisor),
      ]
    );
    assert_eq!(failure.facts.path, LifecyclePath::Failure);
    assert!(!failure.facts.eligible);
  }

  #[test]
  fn darwin_terminal_zombie_eperm_is_success_only_before_leader_reap() {
    if !cfg!(target_os = "macos") {
      return;
    }
    let supervisor = 400;
    let candidate = 401;
    let mut backend = FakeBackend::new(supervisor, candidate);
    backend.script(
      supervisor,
      [
        Observation::Running,
        Observation::Running,
        Observation::Running,
        Observation::Exit(0),
      ],
    );
    backend.script(candidate, [Observation::Running, Observation::Exit(0)]);
    backend.scrubs.push_back(Scrub::Error(libc::EPERM));
    backend.darwin = true;
    let deadline = backend.now + Duration::from_secs(10);
    let mut cell = ParentLifecycleCellImpl::with_backend(
      FakeHandle(supervisor),
      backend,
      deadline,
    )
    .unwrap();
    cell.admit_candidate(FakeHandle(candidate)).unwrap();
    cell.reap_successful_candidate().unwrap();
    let facts = cell.finish_success().unwrap();
    assert!(facts.eligible);
    assert!(matches!(
      facts.scrubs.as_slice(),
      [GroupScrubFact {
        outcome: GroupScrubOutcome::DarwinTerminalLeaderPermissionDenied,
        ..
      }]
    ));
    assert_eq!(
      cell.backend.events,
      [
        Event::Observe(supervisor),
        Event::Observe(candidate),
        Event::Observe(supervisor),
        Event::Observe(candidate),
        Event::Observe(supervisor),
        Event::Reap(candidate),
        Event::Observe(supervisor),
        Event::Scrub(supervisor),
        Event::Reap(supervisor),
        Event::Probe(supervisor),
      ]
    );
  }

  #[test]
  fn failure_path_never_accepts_eperm() {
    let supervisor = 500;
    let mut backend = FakeBackend::new(supervisor, 501);
    backend.groups.remove(&501);
    backend
      .scrubs
      .extend([Scrub::Error(libc::EPERM), Scrub::Delivered]);
    let deadline = backend.now + Duration::from_secs(10);
    let mut cell = ParentLifecycleCellImpl::with_backend(
      FakeHandle(supervisor),
      backend,
      deadline,
    )
    .unwrap();
    let failure = cell.refuse(io::Error::other("injected failure"));
    assert!(matches!(
      failure.facts.scrubs.as_slice(),
      [
        GroupScrubFact {
          outcome: GroupScrubOutcome::Refused {
            raw_os_error: Some(libc::EPERM)
          },
          ..
        },
        GroupScrubFact {
          outcome: GroupScrubOutcome::Delivered,
          ..
        },
      ]
    ));
  }

  #[test]
  fn reserve_is_exactly_two_seconds_and_deadline_is_immutable() {
    let supervisor = 600;
    let backend = FakeBackend::new(supervisor, 601);
    let deadline = backend.now + Duration::from_secs(10);
    let cell = ParentLifecycleCellImpl::with_backend(
      FakeHandle(supervisor),
      backend,
      deadline,
    )
    .unwrap();
    assert_eq!(CLEANUP_RESERVE, Duration::from_millis(2_000));
    assert_eq!(cell.final_deadline(), deadline);
    assert_eq!(cell.work_deadline(), deadline - CLEANUP_RESERVE);
    drop(cell);
  }
}

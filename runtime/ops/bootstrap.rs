// Copyright 2018-2026 the Deno authors. MIT license.

use deno_core::OpState;
use deno_core::op2;
use deno_terminal::colors::ColorLevel;

use crate::BootstrapOptions;

deno_core::extension!(
  deno_bootstrap,
  ops = [
    op_bootstrap_args,
    op_bootstrap_pid,
    op_bootstrap_numcpus,
    op_bootstrap_user_agent,
    op_bootstrap_language,
    op_bootstrap_log_level,
    op_bootstrap_color_depth,
    op_bootstrap_no_color,
    op_bootstrap_stdout_no_color,
    op_bootstrap_stderr_no_color,
    op_bootstrap_unstable_args,
    op_bootstrap_is_from_unconfigured_runtime,
    op_oden_capsec_flags,
    op_oden_capsec_seal_report,
    op_proto_set_attempted,
    op_proto_get_attempted,
    op_snapshot_options,
  ],
  options = {
    snapshot_options: Option<SnapshotOptions>,
    is_from_unconfigured_runtime: bool,
  },
  state = |state, options| {
    if let Some(snapshot_options) = options.snapshot_options {
      state.put::<SnapshotOptions>(snapshot_options);
    }
    state.put(IsFromUnconfiguredRuntime(options.is_from_unconfigured_runtime));
  },
);

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SnapshotOptions {
  pub ts_version: String,
  pub v8_version: &'static str,
  pub target: String,
}

struct IsFromUnconfiguredRuntime(bool);

impl Default for SnapshotOptions {
  fn default() -> Self {
    let arch = std::env::consts::ARCH;
    let platform = std::env::consts::OS;
    let target = match platform {
      "macos" => format!("{}-apple-darwin", arch),
      "linux" => format!("{}-unknown-linux-gnu", arch),
      "windows" => format!("{}-pc-windows-msvc", arch),
      rest => format!("{}-{}", arch, rest),
    };

    Self {
      ts_version: "n/a".to_owned(),
      v8_version: deno_core::v8::VERSION_STRING,
      target,
    }
  }
}

// Note: Called at snapshot time, op perf is not a concern.
#[op2]
#[serde]
pub fn op_snapshot_options(state: &mut OpState) -> SnapshotOptions {
  // `SnapshotOptions` is only placed into the op state when the runtime is
  // bootstrapped with a startup snapshot. Embedders that bootstrap without one
  // (`startup_snapshot: None`) never insert it, so fall back to the default
  // instead of panicking when the value is absent.
  state.try_take::<SnapshotOptions>().unwrap_or_default()
}

#[op2]
pub fn op_bootstrap_args(state: &mut OpState) -> Vec<String> {
  state.borrow::<BootstrapOptions>().args.clone()
}

#[op2(fast)]
#[smi]
pub fn op_bootstrap_pid() -> u32 {
  std::process::id()
}

#[op2(fast)]
#[smi]
pub fn op_bootstrap_numcpus(state: &mut OpState) -> u32 {
  state.borrow::<BootstrapOptions>().cpu_count as u32
}

#[op2]
#[string]
pub fn op_bootstrap_user_agent(state: &mut OpState) -> String {
  state.borrow::<BootstrapOptions>().user_agent.clone()
}

#[op2]
pub fn op_bootstrap_unstable_args(state: &mut OpState) -> Vec<String> {
  let options = state.borrow::<BootstrapOptions>();
  let mut flags = Vec::with_capacity(options.unstable_features.len());
  for unstable_feature in &options.unstable_features {
    if let Some(granular_flag) =
      deno_features::UNSTABLE_FEATURES.get((*unstable_feature) as usize)
    {
      flags.push(format!("--unstable-{}", granular_flag.name));
    }
  }
  flags
}

#[op2]
#[string]
pub fn op_bootstrap_language(state: &mut OpState) -> String {
  state.borrow::<BootstrapOptions>().locale.clone()
}

#[op2(fast)]
#[smi]
pub fn op_bootstrap_log_level(state: &mut OpState) -> i32 {
  state.borrow::<BootstrapOptions>().log_level as i32
}

#[op2(fast)]
pub fn op_bootstrap_color_depth(state: &mut OpState) -> i32 {
  let options = state.borrow::<BootstrapOptions>();
  match options.color_level {
    ColorLevel::None => 1,
    ColorLevel::Ansi => 4,
    ColorLevel::Ansi256 => 8,
    ColorLevel::TrueColor => 24,
  }
}

#[op2(fast)]
pub fn op_bootstrap_no_color(_state: &mut OpState) -> bool {
  !deno_terminal::colors::use_color()
}

#[op2(fast)]
pub fn op_bootstrap_stdout_no_color(_state: &mut OpState) -> bool {
  if deno_terminal::colors::force_color() {
    return false;
  }

  !deno_terminal::is_stdout_tty() || !deno_terminal::colors::use_color()
}

#[op2(fast)]
pub fn op_bootstrap_stderr_no_color(_state: &mut OpState) -> bool {
  if deno_terminal::colors::force_color() {
    return false;
  }

  !deno_terminal::is_stderr_tty() || !deno_terminal::colors::use_color()
}

#[op2(fast)]
pub fn op_bootstrap_is_from_unconfigured_runtime(state: &mut OpState) -> bool {
  state.borrow::<IsFromUnconfiguredRuntime>().0
}

// Oden capsec: report whether the capability layer is armed so trusted
// bootstrap JS can seal the continuation-preserved-embedder-data primitives
// (LLP 0001 §Async attribution) before user code runs. Bit 0 = capsec armed —
// structural arming, the policy artifact's presence (ODEN_CAPSEC_POLICY handoff
// or `<root>/.oden/policy.json`); bit 1 = run the seal self-test
// (`ODEN_CAPSEC_SEAL_SELFTEST`). Called once at bootstrap, before
// `removeImportedOps()`, so it never enters the steady-state op surface.
// Probing here (not a snapshot-baked value) keeps the seal a per-process
// runtime decision.
// @ref llp/0001-adding-capability-security-to-deno.plan.md
#[op2(fast)]
#[smi]
#[allow(
  clippy::disallowed_methods,
  reason = "capsec test hooks (seal self-test, lockdown opt-in) are env-driven; arming itself is the structural probe in deno_permissions."
)]
pub fn op_oden_capsec_flags() -> u32 {
  let mut flags = 0u32;
  if deno_permissions::oden_capsec_armed() {
    flags |= 1;
  }
  if std::env::var_os("ODEN_CAPSEC_SEAL_SELFTEST").is_some() {
    flags |= 2;
  }
  // Bit 2 (value 4) = minimal lockdown (freeze the primordial intrinsics +
  // Error-constructor taming). The decision is mode-aware and lives in
  // `deno_permissions::oden_capsec_lockdown_on` (Phase 3 / ENG-23781):
  // enforce defaults it ON ("enforce implies lockdown", with
  // `ODEN_CAPSEC_LOCKDOWN=0` as the honestly-labeled override); audit and
  // permissive keep it OPT-IN because the compat corpus (ENG-23880) measured
  // default-on there as a NO-GO (post-repair floor ~19% breakage via the SES
  // override mistake). The readiness report states the posture and its
  // provenance either way.
  // @ref llp/0001-adding-capability-security-to-deno.plan.md
  if deno_permissions::oden_capsec_lockdown_on() {
    flags |= 4;
  }
  flags
}

// Always-on seal conformance (LLP 0001 ENG-23775): the bootstrap runs the four
// seal conditions on every armed startup and reports the result here. The flag
// lives in `deno_permissions` (where readiness reads it), so a broken seal makes
// enforce fail closed rather than silently trusting an unsound attribution slot.
#[op2(fast)]
pub fn op_oden_capsec_seal_report(ok: bool) {
  deno_permissions::oden_capsec_report_seal(ok);
}

// Called (at most once) from the disabled `Object.prototype.__proto__` setter
// in 99_main.js when user code assigns to `__proto__`. Records a process-global
// flag so that, if the program later crashes, the uncaught-error formatter can
// suggest `--unstable-unsafe-proto`. See `crate::fmt_errors::PROTO_SET_ATTEMPTED`.
#[op2(fast)]
pub fn op_proto_set_attempted() {
  crate::fmt_errors::PROTO_SET_ATTEMPTED
    .store(true, std::sync::atomic::Ordering::Relaxed);
}

// Called (at most once) from the disabled `Object.prototype.__proto__` getter
// in 99_main.js when user code reads `__proto__` (the read returns `undefined`).
// Records a process-global flag; the uncaught-error formatter only acts on it
// when the crashing error also mentions `__proto__`, since reads are common and
// usually harmless. See `crate::fmt_errors::PROTO_GET_ATTEMPTED`.
#[op2(fast)]
pub fn op_proto_get_attempted() {
  crate::fmt_errors::PROTO_GET_ATTEMPTED
    .store(true, std::sync::atomic::Ordering::Relaxed);
}

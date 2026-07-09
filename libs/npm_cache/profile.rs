// Copyright 2018-2026 the Deno authors. MIT license.

//! Env-gated installer profiling.
//!
//! @ref llp/0002-the-oden-installer.plan.md#benchmark-first
//!
//! Set `DENO_NPM_INSTALL_PROFILE=1` to emit one NDJSON line per pipeline
//! event (packument fetch, tarball download, decompress, extract, clone,
//! phase totals) to stderr. Overhead is a single branch when disabled.
//! The `bench/install` harness in the oden repository consumes this output.

#[cfg(not(target_arch = "wasm32"))]
mod real {
  use std::sync::OnceLock;
  use std::time::Instant;

  fn anchor() -> Instant {
    static ANCHOR: OnceLock<Instant> = OnceLock::new();
    *ANCHOR.get_or_init(Instant::now)
  }

  fn now_ms() -> f64 {
    anchor().elapsed().as_secs_f64() * 1000.0
  }

  pub fn enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| {
      #[allow(
        clippy::disallowed_methods,
        reason = "process-global profiling toggle, deliberately not per-sys"
      )]
      std::env::var_os("DENO_NPM_INSTALL_PROFILE")
        .is_some_and(|v| !v.is_empty() && v != "0")
    })
  }

  /// Times one event; emits on `finish`. Obtain via [`start`].
  pub struct EventTimer {
    event: &'static str,
    key: String,
    start_ms: f64,
  }

  /// Starts timing `event` for `key` (a package name or nv). Returns `None`
  /// when profiling is disabled so callers pay only a branch.
  pub fn start(event: &'static str, key: &str) -> Option<EventTimer> {
    if !enabled() {
      return None;
    }
    Some(EventTimer {
      event,
      key: key.to_string(),
      start_ms: now_ms(),
    })
  }

  impl EventTimer {
    pub fn finish(self) {
      self.finish_with_bytes(None);
    }

    pub fn finish_with_bytes(self, bytes: Option<u64>) {
      let end_ms = now_ms();
      // package names/nvs never contain characters needing JSON escaping
      match bytes {
        Some(b) => eprintln!(
          "{{\"e\":\"{}\",\"k\":\"{}\",\"t0\":{:.2},\"t1\":{:.2},\"bytes\":{}}}",
          self.event, self.key, self.start_ms, end_ms, b
        ),
        None => eprintln!(
          "{{\"e\":\"{}\",\"k\":\"{}\",\"t0\":{:.2},\"t1\":{:.2}}}",
          self.event, self.key, self.start_ms, end_ms
        ),
      }
    }
  }

  /// Emits an instantaneous event (no duration).
  pub fn mark(event: &'static str, key: &str) {
    if !enabled() {
      return;
    }
    let t = now_ms();
    eprintln!(
      "{{\"e\":\"{event}\",\"k\":\"{key}\",\"t0\":{t:.2},\"t1\":{t:.2}}}"
    );
  }
}

#[cfg(not(target_arch = "wasm32"))]
pub use real::*;

#[cfg(target_arch = "wasm32")]
mod stub {
  pub struct EventTimer;

  pub fn enabled() -> bool {
    false
  }

  pub fn start(_event: &'static str, _key: &str) -> Option<EventTimer> {
    None
  }

  impl EventTimer {
    pub fn finish(self) {}
    pub fn finish_with_bytes(self, _bytes: Option<u64>) {}
  }

  pub fn mark(_event: &'static str, _key: &str) {}
}

#[cfg(target_arch = "wasm32")]
pub use stub::*;

// Copyright 2018-2026 the Deno authors. MIT license.

//! TLS key logging support for debugging encrypted traffic.
//!
//! When the `SSLKEYLOGFILE` environment variable is set, TLS session keys
//! are written to the specified file in NSS Key Log format, which can be
//! used by tools like Wireshark to decrypt TLS traffic.

use std::env;
use std::fs::OpenOptions;
use std::sync::Arc;
use std::sync::OnceLock;

use rustls::KeyLog;
use rustls::KeyLogFile;
use rustls::NoKeyLog;

const ODEN_REV2_TLS_KEY_LOG_ALREADY_INITIALIZED: &str =
  "OD-CAP-REV2-TLS-KEYLOG-ALREADY-INITIALIZED";

enum SslKeyLogState {
  Ambient(Arc<dyn KeyLog + Send + Sync>),
  OdenRev2Disabled,
}

static SSL_KEY_LOG: OnceLock<SslKeyLogState> = OnceLock::new();

fn disable_oden_rev2_no_key_log_in(
  state: &OnceLock<SslKeyLogState>,
) -> Result<(), &'static str> {
  match state.get_or_init(|| SslKeyLogState::OdenRev2Disabled) {
    SslKeyLogState::OdenRev2Disabled => Ok(()),
    SslKeyLogState::Ambient(_) => {
      Err(ODEN_REV2_TLS_KEY_LOG_ALREADY_INITIALIZED)
    }
  }
}

fn get_ssl_key_log_in(
  state: &OnceLock<SslKeyLogState>,
  ambient_initializer: impl FnOnce() -> Arc<dyn KeyLog + Send + Sync>,
) -> Arc<dyn KeyLog + Send + Sync> {
  match state.get_or_init(|| SslKeyLogState::Ambient(ambient_initializer())) {
    SslKeyLogState::Ambient(key_log) => key_log.clone(),
    SslKeyLogState::OdenRev2Disabled => Arc::new(NoKeyLog),
  }
}

/// Installs the process-wide Rev2 prohibition on TLS session key logging.
///
/// This must run before the TLS extension initializes. Repeating an installed
/// prohibition is harmless, but attempting to install it after any ambient
/// key-log initialization is a stable bootstrap refusal.
///
/// @ref LLP 0019#tls-session-key-logging [implements] — Every explicit Rev2
/// candidate disables the ambient key-log hook before verification or TLS
/// extension initialization.
pub fn disable_oden_rev2_no_key_log() -> Result<(), &'static str> {
  disable_oden_rev2_no_key_log_in(&SSL_KEY_LOG)
}

/// Eagerly initializes the global TLS key logger.
///
/// `KeyLogFile::new()` reads `SSLKEYLOGFILE` from the process environment.
/// Callers can use this to snapshot that value early, instead of on first TLS
/// config construction.
pub(super) fn init_ssl_key_log() {
  let _ = get_ssl_key_log();
}

pub fn get_ssl_key_log() -> Arc<dyn KeyLog> {
  get_ssl_key_log_in(&SSL_KEY_LOG, || {
    if let Some(path) = env::var_os("SSLKEYLOGFILE")
      && let Err(e) = {
        #[allow(
          clippy::disallowed_methods,
          reason = "keylog file uses direct fs access"
        )]
        let result = OpenOptions::new().append(true).create(true).open(&path);
        result
      }
    {
      log::warn!(
        "SSLKEYLOGFILE is set but '{}' could not be opened: {e}",
        path.to_string_lossy()
      );
    }
    Arc::new(KeyLogFile::new())
  })
}

#[cfg(test)]
mod tests {
  use std::sync::atomic::AtomicUsize;
  use std::sync::atomic::Ordering;

  use super::*;

  #[test]
  fn oden_rev2_disabled_key_log_never_calls_ambient_initializer() {
    let state = OnceLock::new();
    let ambient_calls = AtomicUsize::new(0);

    disable_oden_rev2_no_key_log_in(&state).unwrap();
    for _ in 0..2 {
      let key_log = get_ssl_key_log_in(&state, || {
        ambient_calls.fetch_add(1, Ordering::SeqCst);
        Arc::new(NoKeyLog)
      });
      assert!(!key_log.will_log("CLIENT_RANDOM"));
    }

    assert_eq!(ambient_calls.load(Ordering::SeqCst), 0);
  }

  #[test]
  fn oden_rev2_late_key_log_disablement_refuses_stably() {
    let state = OnceLock::new();
    let ambient_calls = AtomicUsize::new(0);
    let ambient = get_ssl_key_log_in(&state, || {
      ambient_calls.fetch_add(1, Ordering::SeqCst);
      Arc::new(NoKeyLog)
    });

    assert_eq!(
      disable_oden_rev2_no_key_log_in(&state),
      Err(ODEN_REV2_TLS_KEY_LOG_ALREADY_INITIALIZED)
    );
    assert_eq!(
      disable_oden_rev2_no_key_log_in(&state),
      Err(ODEN_REV2_TLS_KEY_LOG_ALREADY_INITIALIZED)
    );
    let repeated = get_ssl_key_log_in(&state, || {
      ambient_calls.fetch_add(1, Ordering::SeqCst);
      Arc::new(NoKeyLog)
    });
    assert!(Arc::ptr_eq(&ambient, &repeated));
    assert_eq!(ambient_calls.load(Ordering::SeqCst), 1);
  }

  #[test]
  fn oden_rev2_key_log_disablement_is_repeatable_before_initialization() {
    let state = OnceLock::new();

    assert_eq!(disable_oden_rev2_no_key_log_in(&state), Ok(()));
    assert_eq!(disable_oden_rev2_no_key_log_in(&state), Ok(()));
  }
}

// Copyright 2018-2026 the Deno authors. MIT license.

use std::io::BufRead;
use std::io::BufReader;
use std::io::Write;
use std::path::PathBuf;
use std::sync::OnceLock;
use std::sync::atomic::AtomicU32;

use parking_lot::Mutex;

use super::BrokerResponse;
use crate::ipc_pipe::IpcPipe;

// TODO(bartlomieju): currently randomly selected exit code, it should
// be documented
static BROKER_EXIT_CODE: i32 = 87;

static PERMISSION_BROKER: OnceLock<PermissionBroker> = OnceLock::new();
static PID: OnceLock<u32> = OnceLock::new();

pub fn set_broker(broker: PermissionBroker) {
  assert!(PERMISSION_BROKER.set(broker).is_ok());
  assert!(PID.set(std::process::id()).is_ok());
}

pub fn has_broker() -> bool {
  PERMISSION_BROKER.get().is_some()
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct PermissionBrokerRequest<'a> {
  v: u32,
  pid: u32,
  id: u32,
  datetime: String,
  permission: &'a str,
  value: Option<String>,
  // The acting package principal (Oden capsec). Omitted when capsec is
  // inactive so the wire format is unchanged for stock Deno; present when a
  // package is on the stack, so a broker can key its decision on caller
  // identity, not just the process. Upstreaming candidate (shrinks the diff).
  // @ref llp/0001-adding-capability-security-to-deno.plan.md (Broker protocol)
  #[serde(skip_serializing_if = "Option::is_none")]
  principal: Option<String>,
  // Dynamic-request fields are additive and omitted for stock permission
  // checks, preserving the existing broker wire format byte-for-byte.
  // @ref llp/0015-dynamic-permissions-with-ceiling.plan.md (Deciders for row 8)
  #[serde(skip_serializing_if = "Option::is_none")]
  kind: Option<&'a str>,
  #[serde(skip_serializing_if = "Option::is_none")]
  ceiling_context: Option<DynamicCeilingContext<'a>>,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
struct DynamicCeilingContext<'a> {
  capability: &'a str,
  covering_ceiling: &'a str,
}

#[derive(Debug, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
struct PermissionBrokerResponse {
  id: u32,
  result: String,
  reason: Option<String>,
}

pub struct PermissionBroker {
  stream: Mutex<IpcPipe>,
  next_id: AtomicU32,
}

impl PermissionBroker {
  pub fn new(socket_path: impl Into<PathBuf>) -> Self {
    let socket_path = socket_path.into();
    let stream = match IpcPipe::connect(&socket_path) {
      Ok(s) => s,
      Err(err) => {
        log::error!("Failed to create permission broker: {:?}", err);
        std::process::exit(BROKER_EXIT_CODE);
      }
    };
    Self {
      stream: Mutex::new(stream),
      next_id: std::sync::atomic::AtomicU32::new(1),
    }
  }

  fn check(
    &self,
    permission: &str,
    stringified_value: Option<String>,
    principal: Option<String>,
    dynamic: Option<DynamicCeilingContext<'_>>,
  ) -> std::io::Result<BrokerResponse> {
    let mut stream = self.stream.lock();
    let id = self
      .next_id
      .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let request = PermissionBrokerRequest {
      v: 1,
      pid: *PID.get().unwrap(),
      id,
      #[allow(clippy::disallowed_methods, reason = "TODO: use sys_traits")]
      datetime: chrono::Utc::now().to_rfc3339(),
      permission,
      value: stringified_value,
      principal,
      kind: dynamic.as_ref().map(|_| "dynamic_request"),
      ceiling_context: dynamic,
    };

    let msg = format!("{}\n", serde_json::to_string(&request).unwrap());
    log::trace!("-> broker req   {}", msg);
    stream.write_all(msg.as_bytes())?;

    // Read response using line reader
    let mut reader = BufReader::new(&mut *stream);
    let mut response_line = String::new();
    reader.read_line(&mut response_line)?;

    let response =
      serde_json::from_str::<PermissionBrokerResponse>(response_line.trim())
        .map_err(std::io::Error::other)?;

    log::trace!("<- broker resp  {:?}", response);

    if response.id != id {
      return Err(std::io::Error::other(
        "Permission broker response ID mismatch",
      ));
    }

    let prompt_response = match response.result.as_str() {
      "allow" => BrokerResponse::Allow,
      "deny" => BrokerResponse::Deny {
        message: response.reason,
      },
      _ => {
        return Err(std::io::Error::other(
          "Permission broker unknown result variant",
        ));
      }
    };

    Ok(prompt_response)
  }
}

pub fn maybe_check_with_broker(
  name: &str,
  stringified_value_fn: impl Fn() -> Option<String>,
) -> Option<BrokerResponse> {
  let broker = PERMISSION_BROKER.get()?;

  let resp = match broker.check(
    name,
    stringified_value_fn(),
    super::oden_capsec_current_principal_label(),
    None,
  ) {
    Ok(resp) => resp,
    Err(err) => {
      log::error!("{:?}", err);
      std::process::exit(BROKER_EXIT_CODE);
    }
  };
  Some(resp)
}

/// Ask an attached broker to decide a package's within-ceiling runtime
/// request. Broker presence outranks the local TTY prompt.
pub fn maybe_check_dynamic_with_broker(
  permission: &str,
  value: &str,
  principal: &str,
  capability: &str,
  covering_ceiling: &str,
) -> Option<BrokerResponse> {
  let broker = PERMISSION_BROKER.get()?;
  let resp = match broker.check(
    permission,
    Some(value.to_string()),
    Some(principal.to_string()),
    Some(DynamicCeilingContext {
      capability,
      covering_ceiling,
    }),
  ) {
    Ok(resp) => resp,
    Err(err) => {
      log::error!("{:?}", err);
      std::process::exit(BROKER_EXIT_CODE);
    }
  };
  Some(resp)
}

#[cfg(test)]
mod tests {
  use super::*;

  fn request<'a>(
    dynamic: Option<DynamicCeilingContext<'a>>,
  ) -> PermissionBrokerRequest<'a> {
    PermissionBrokerRequest {
      v: 1,
      pid: 42,
      id: 7,
      datetime: "2026-07-09T00:00:00Z".to_string(),
      permission: "env",
      value: Some("DYNAMIC".to_string()),
      principal: Some("requester@1.0.0".to_string()),
      kind: dynamic.as_ref().map(|_| "dynamic_request"),
      ceiling_context: dynamic,
    }
  }

  #[test]
  fn stock_request_omits_dynamic_fields() {
    let value = serde_json::to_value(request(None)).unwrap();
    assert!(value.get("kind").is_none());
    assert!(value.get("ceilingContext").is_none());
    assert_eq!(value["principal"], "requester@1.0.0");
  }

  #[test]
  fn dynamic_request_adds_principal_and_ceiling_context() {
    let value = serde_json::to_value(request(Some(DynamicCeilingContext {
      capability: "env:*:DYNAMIC",
      covering_ceiling: "env:*:DYNAMIC",
    })))
    .unwrap();
    assert_eq!(value["kind"], "dynamic_request");
    assert_eq!(value["principal"], "requester@1.0.0");
    assert_eq!(value["ceilingContext"]["capability"], "env:*:DYNAMIC");
    assert_eq!(value["ceilingContext"]["coveringCeiling"], "env:*:DYNAMIC");
  }
}

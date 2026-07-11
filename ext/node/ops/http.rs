// Copyright 2018-2026 the Deno authors. MIT license.

use deno_core::GarbageCollected;
use deno_core::OpState;
use deno_core::op2;
use deno_core::v8;
use deno_permissions::NetPermissionAction;
use deno_permissions::PermissionCheckError;
use deno_permissions::PermissionsContainer;
use deno_permissions::oden_capsec_gate_url_scheme;
use deno_permissions::oden_capsec_profile_is;

/// Opaque, endpoint-bound proof that the built-in Node HTTP agent is opening
/// this socket for request/response traffic rather than for `node:net`.
///
/// The token is minted only by captured runtime code and kept out of the
/// package-visible options object. A caller can ask the HTTP agent for a socket
/// (Node exposes that API), but cannot fabricate a token for an arbitrary raw
/// `node:net` / Unix-pipe connection.
#[derive(Clone)]
pub(crate) struct NodeHttpNetToken {
  endpoint: NodeHttpEndpoint,
  api_name: String,
}

#[derive(Clone)]
enum NodeHttpEndpoint {
  Tcp { hostname: String, port: u16 },
  Unix { path: String },
}

// SAFETY: the token owns only Rust strings and has no V8 edges.
unsafe impl GarbageCollected for NodeHttpNetToken {
  fn trace(&self, _visitor: &mut v8::cppgc::Visitor) {}

  fn get_name(&self) -> &'static std::ffi::CStr {
    c"NodeHttpNetToken"
  }
}

impl NodeHttpNetToken {
  pub(crate) fn tcp_api_name(&self, hostname: &str, port: u16) -> Option<&str> {
    match &self.endpoint {
      NodeHttpEndpoint::Tcp {
        hostname: expected,
        port: expected_port,
      } if expected.eq_ignore_ascii_case(hostname)
        && *expected_port == port =>
      {
        Some(&self.api_name)
      }
      _ => None,
    }
  }

  pub(crate) fn unix_api_name(&self, path: &str) -> Option<&str> {
    match &self.endpoint {
      NodeHttpEndpoint::Unix { path: expected } if expected == path => {
        Some(&self.api_name)
      }
      _ => None,
    }
  }
}

#[op2]
#[cppgc]
pub fn op_node_http_net_token(
  #[string] hostname: String,
  port: u16,
  #[string] path: Option<String>,
  #[string] api_name: String,
) -> NodeHttpNetToken {
  let endpoint = match path {
    Some(path) => NodeHttpEndpoint::Unix { path },
    None => NodeHttpEndpoint::Tcp { hostname, port },
  };
  NodeHttpNetToken { endpoint, api_name }
}

/// Classify the request protocol before Node's agent or a caller-supplied
/// connection hook can select a transport. Protocol validation remains in the
/// Node compatibility layer; this closes blob/unknown schemes first under the
/// Stage-B profile so no custom agent can reinterpret them as network grants.
#[op2(fast, stack_trace)]
pub fn op_node_http_check_url_scheme(
  #[string] scheme: &str,
  #[string] api_name: &str,
) -> Result<(), PermissionCheckError> {
  oden_capsec_gate_url_scheme(scheme, api_name).map(|_| ())
}

// When a node:http / node:https request is routed through a proxy, the socket
// is connected to the proxy endpoint, so the proxy is the only host the connect
// op permission-checks. Without this, `--allow-net=<proxy>` alone would let a
// request reach a target host that is outside `--allow-net` or explicitly in
// `--deny-net`. Enforce `--allow-net` for the request target here, mirroring
// the target check fetch() performs, before the connection to the proxy is
// established.
//
// This fails closed: a denied or unparseable target propagates its error,
// matching check_net_url() in fetch(). Targets node:http rejects on its own
// (invalid header characters such as CR/LF, which would also fail check_net's
// host parser) are filtered out before this op is called, so they surface as
// ERR_INVALID_CHAR rather than being masked here.
#[op2(fast, stack_trace)]
pub fn op_node_http_check_proxy_net(
  state: &mut OpState,
  #[string] hostname: &str,
  port: u16,
  #[string] api_name: &str,
) -> Result<(), PermissionCheckError> {
  deno_permissions::oden_capsec_reject_forward_proxy(api_name)?;
  if oden_capsec_profile_is("oden/capsec/1.1") {
    state.borrow_mut::<PermissionsContainer>().check_net(
      NetPermissionAction::Connect,
      &(hostname, Some(port)),
      api_name,
    )
  } else {
    state.borrow_mut::<PermissionsContainer>().check_net(
      NetPermissionAction::Fetch,
      &(hostname, Some(port)),
      api_name,
    )
  }
}

/// The /1.1 protected-peer patch profile cannot safely reuse a Node Agent
/// socket across requests because the JS pool key has no authenticated Oden
/// principal dimension. Trusted Node glue uses this bit to destroy the socket
/// before assigning it to a queued or later request.
#[op2(fast)]
pub fn op_node_http_capsec_no_reuse() -> bool {
  deno_permissions::oden_capsec_profile_is(
    deno_permissions::ODEN_CAPSEC_PROFILE,
  )
}

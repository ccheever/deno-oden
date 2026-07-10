// Copyright 2018-2026 the Deno authors. MIT license.

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::convert::Infallible;
use std::future::Future;
use std::net::SocketAddr;

use bytes::Bytes;
use futures::FutureExt;
use futures::future::LocalBoxFuture;
use http_body_util::combinators::UnsyncBoxBody;
use hyper::Request;
use hyper::Response;
use hyper::StatusCode;
use once_cell::sync::Lazy;
use parking_lot::Mutex;
use percent_encoding;
use serde_json::json;

use super::ServerKind;
use super::ServerOptions;
use super::empty_body;
use super::hyper_utils::HandlerOutput;
use super::run_server;
use super::string_body;

static CAPTURED_PURLS: Lazy<Mutex<BTreeMap<String, BTreeSet<String>>>> =
  Lazy::new(Default::default);

pub fn api(port: u16) -> Vec<LocalBoxFuture<'static, ()>> {
  run_socket_dev_server(port, "socket.dev server error", socket_dev_handler)
}

fn run_socket_dev_server<F, S>(
  port: u16,
  error_msg: &'static str,
  handler: F,
) -> Vec<LocalBoxFuture<'static, ()>>
where
  F: Fn(Request<hyper::body::Incoming>) -> S + Copy + 'static,
  S: Future<Output = HandlerOutput> + 'static,
{
  let socket_dev_addr = SocketAddr::from(([127, 0, 0, 1], port));
  vec![
    run_socket_dev_server_for_addr(socket_dev_addr, error_msg, handler)
      .boxed_local(),
  ]
}

async fn run_socket_dev_server_for_addr<F, S>(
  addr: SocketAddr,
  error_msg: &'static str,
  handler: F,
) where
  F: Fn(Request<hyper::body::Incoming>) -> S + Copy + 'static,
  S: Future<Output = HandlerOutput> + 'static,
{
  run_server(
    ServerOptions {
      addr,
      kind: ServerKind::Auto,
      error_msg,
    },
    handler,
  )
  .await
}

async fn socket_dev_handler(
  req: Request<hyper::body::Incoming>,
) -> Result<Response<UnsyncBoxBody<Bytes, Infallible>>, anyhow::Error> {
  let path = req.uri().path().to_string();
  let method = req.method().clone();

  if method == hyper::Method::GET
    && let Some(capture_id) = path.strip_prefix("/capture/")
  {
    let purls = CAPTURED_PURLS
      .lock()
      .get(capture_id)
      .cloned()
      .unwrap_or_default();
    return Ok(
      Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/json")
        .body(string_body(&json!({ "purls": purls }).to_string()))?,
    );
  }

  if method == hyper::Method::GET
    && let Some(scenario_path) = path.strip_prefix("/scenario/")
  {
    let mut parts = scenario_path.splitn(4, '/');
    let scenario = parts.next();
    let capture_id = parts.next();
    let purl_segment = parts.next();
    let encoded_purl = parts.next();
    if let (
      Some(scenario),
      Some(capture_id),
      Some("purl"),
      Some(encoded_purl),
    ) = (scenario, capture_id, purl_segment, encoded_purl)
    {
      let decoded_purl =
        percent_encoding::percent_decode_str(encoded_purl).decode_utf8()?;
      CAPTURED_PURLS
        .lock()
        .entry(capture_id.to_string())
        .or_default()
        .insert(decoded_purl.to_string());
      if scenario == "outage" {
        return Ok(
          Response::builder()
            .status(StatusCode::SERVICE_UNAVAILABLE)
            .body(empty_body())?,
        );
      }
      let response_json = socket_response_for_purl(&decoded_purl, scenario)?;
      return Ok(
        Response::builder()
          .status(StatusCode::OK)
          .header("Content-Type", "application/json")
          .body(string_body(&response_json.to_string()))?,
      );
    }
  }

  // Handle authenticated mode: POST /v0/purl
  if method == hyper::Method::POST {
    let scenario = path
      .strip_prefix("/scenario/")
      .and_then(|path| path.split_once('/'));
    return handle_authenticated_request(req, scenario).await;
  }

  // Expected format: /purl/{percent_encoded_purl}
  // where purl is like: pkg:npm/package-name@version
  if !path.starts_with("/purl/") {
    return Ok(
      Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(empty_body())?,
    );
  }

  // Extract the percent-encoded purl
  let encoded_purl = &path[6..]; // Skip "/purl/"

  // Decode the percent-encoded purl
  let decoded_purl =
    match percent_encoding::percent_decode_str(encoded_purl).decode_utf8() {
      Ok(s) => s.to_string(),
      Err(_) => {
        return Ok(
          Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(empty_body())?,
        );
      }
    };

  // Parse the purl format: pkg:npm/package-name@version
  if !decoded_purl.starts_with("pkg:npm/") {
    return Ok(
      Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(empty_body())?,
    );
  }

  let package_part = &decoded_purl[8..]; // Skip "pkg:npm/"

  // Split by @ to get name and version (split from the right to handle scoped packages like @scope/package@1.0.0)
  let parts: Vec<&str> = package_part.rsplitn(2, '@').collect();
  if parts.len() != 2 {
    return Ok(
      Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(empty_body())?,
    );
  }

  let version = parts[0];
  let name = parts[1];

  // Create the response JSON matching the FirewallResponse structure
  let response_json = json!({
    "id": "81646",
    "name": name,
    "version": version,
    "score": {
      "license": 1.0,
      "maintenance": 0.77,
      "overall": 0.77,
      "quality": 0.94,
      "supplyChain": 1.0,
      "vulnerability": 1.0
    },
    "alerts": [
      { "type": "malware", "action": "error", "severity": "critical", "category": "supplyChainRisk" }
    ]
  });

  let response_body = response_json.to_string();
  Ok(
    Response::builder()
      .status(StatusCode::OK)
      .header("Content-Type", "application/json")
      .body(string_body(&response_body))?,
  )
}

fn socket_response_for_purl(
  purl: &str,
  scenario: &str,
) -> Result<serde_json::Value, anyhow::Error> {
  let package_part = purl
    .strip_prefix("pkg:npm/")
    .ok_or_else(|| anyhow::anyhow!("invalid npm PURL"))?;
  let mut parts = package_part.rsplitn(2, '@');
  let version = parts
    .next()
    .ok_or_else(|| anyhow::anyhow!("PURL is missing a version"))?;
  let name = parts
    .next()
    .ok_or_else(|| anyhow::anyhow!("PURL is missing a package name"))?;
  let is_malware = match scenario {
    "direct-malware" => purl == "pkg:npm/@denotest/add@1.0.0",
    "transitive-malware" => purl == "pkg:npm/@denotest/with-vuln2@1.5.0",
    _ => false,
  };
  let alerts = if is_malware {
    vec![json!({
      "type": "malware",
      "action": "error",
      "severity": "critical",
      "category": "supplyChainRisk"
    })]
  } else {
    Vec::new()
  };
  Ok(json!({
    "id": "81646",
    "inputPurl": purl,
    "name": name,
    "version": version,
    "score": {
      "license": 1.0,
      "maintenance": 0.78,
      "overall": 0.78,
      "quality": 0.94,
      "supplyChain": 1.0,
      "vulnerability": 1.0
    },
    "alerts": alerts
  }))
}

async fn handle_authenticated_request(
  req: Request<hyper::body::Incoming>,
  scenario: Option<(&str, &str)>,
) -> Result<Response<UnsyncBoxBody<Bytes, Infallible>>, anyhow::Error> {
  use http_body_util::BodyExt;

  // Read the request body
  let body_bytes = req.collect().await?.to_bytes();
  let body_str = String::from_utf8(body_bytes.to_vec())?;

  // Parse the JSON body
  let body_json: serde_json::Value = serde_json::from_str(&body_str)?;
  let components = body_json["components"]
    .as_array()
    .ok_or_else(|| anyhow::anyhow!("Missing components array"))?;

  if let Some((_, capture_id)) = scenario {
    let mut captures = CAPTURED_PURLS.lock();
    let captured = captures.entry(capture_id.to_string()).or_default();
    captured.extend(
      components
        .iter()
        .filter_map(|component| component["purl"].as_str())
        .map(ToOwned::to_owned),
    );
  }

  if matches!(scenario, Some(("outage", _))) {
    return Ok(
      Response::builder()
        .status(StatusCode::SERVICE_UNAVAILABLE)
        .body(empty_body())?,
    );
  }

  // Build newline-delimited JSON response
  let mut responses = Vec::new();

  for component in components {
    let purl = component["purl"]
      .as_str()
      .ok_or_else(|| anyhow::anyhow!("Missing purl field"))?;

    // Parse the purl format: pkg:npm/package-name@version
    if !purl.starts_with("pkg:npm/") {
      continue;
    }

    let package_part = &purl[8..]; // Skip "pkg:npm/"
    let parts: Vec<&str> = package_part.rsplitn(2, '@').collect();
    if parts.len() != 2 {
      continue;
    }

    let version = parts[0];
    let name = parts[1];

    let is_malware = match scenario.map(|(scenario, _)| scenario) {
      Some("direct-malware") => purl == "pkg:npm/@denotest/add@1.0.0",
      Some("transitive-malware") => {
        purl == "pkg:npm/@denotest/with-vuln2@1.5.0"
      }
      // Preserve the original all-malware response for existing Socket tests.
      None => true,
      Some(_) => false,
    };
    let alerts = if is_malware {
      vec![json!({
        "type": "malware",
        "action": "error",
        "severity": "critical",
        "category": "supplyChainRisk"
      })]
    } else {
      Vec::new()
    };

    let response_json = json!({
      "id": "81646",
      "inputPurl": purl,
      "name": name,
      "version": version,
      "score": {
        "license": 1.0,
        "maintenance": 0.78,
        "overall": 0.78,
        "quality": 0.94,
        "supplyChain": 1.0,
        "vulnerability": 1.0
      },
      "alerts": alerts
    });

    responses.push(response_json.to_string());
  }

  // Join with newlines for newline-delimited JSON
  let response_body = responses.join("\n");

  Ok(
    Response::builder()
      .status(StatusCode::OK)
      .header("Content-Type", "application/x-ndjson")
      .body(string_body(&response_body))?,
  )
}

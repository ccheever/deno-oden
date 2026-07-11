// Copyright 2018-2026 the Deno authors. MIT license.

//! Engine-owned protected-resource guards for Oden capability security.
//!
//! The metadata guard is deliberately separate from ordinary grant matching:
//! an exact protected row only clears the built-in refusal. The caller must
//! continue through the ordinary static/session/negative decision path.

use std::collections::HashMap;
use std::collections::HashSet;
use std::net::IpAddr;
use std::net::Ipv4Addr;
use std::net::Ipv6Addr;

use serde::Deserialize;
use serde::Deserializer;
use sha2::Digest;
use sha2::Sha256;

use super::oden_policy::Family;
use super::oden_policy::Grant;
use super::oden_policy::Request;
use super::oden_policy::covers;

const REASON_DOMAIN: &[u8] = b"oden:protected-resource-reason:1\0";
const RECEIPT_SET_DOMAIN: &[u8] = b"oden:protected-metadata-receipt-set:1\0";

// The Stage-B registry slice. These addresses are metadata-specific before
// any broader link-local, CGNAT, or ULA classification. IPv4-mapped IPv6 is
// normalized before lookup.
#[cfg(test)]
const PROTECTED_METADATA_IPS: &[&str] = &[
  "169.254.169.254", // AWS, Azure, Google Cloud, and other IMDS endpoints
  "169.254.170.2",   // Amazon ECS task credentials
  "100.100.100.200", // Alibaba Cloud IMDS (also inside CGNAT space)
  "fd00:ec2::254",   // AWS IMDS IPv6
  "fd20:ce::254",    // Google Cloud metadata IPv6
];
const METADATA_V4_A: Ipv4Addr = Ipv4Addr::new(169, 254, 169, 254);
const METADATA_V4_B: Ipv4Addr = Ipv4Addr::new(169, 254, 170, 2);
const METADATA_V4_C: Ipv4Addr = Ipv4Addr::new(100, 100, 100, 200);
const METADATA_V6_A: Ipv6Addr =
  Ipv6Addr::new(0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254);
const METADATA_V6_B: Ipv6Addr =
  Ipv6Addr::new(0xfd20, 0x00ce, 0, 0, 0, 0, 0, 0x0254);

/// One exact static protected-metadata annotation in the armed snapshot.
///
/// `reasonDigest` is review metadata, never matcher input. When the optional
/// approval gate is enabled, `receiptDigest` is the already-validated receipt
/// binding supplied by the trusted parent; the engine binds the complete set
/// and never consults mutable ledger state.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct ProtectedMetadataRowFile {
  pub principal: String,
  pub action: String,
  pub ip: String,
  pub port: u16,
  pub reason_digest: String,
  #[serde(default, deserialize_with = "deserialize_optional_string")]
  pub receipt_digest: Option<String>,
}

fn deserialize_optional_string<'de, D>(
  deserializer: D,
) -> Result<Option<String>, D::Error>
where
  D: Deserializer<'de>,
{
  <String as Deserialize>::deserialize(deserializer).map(Some)
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ProtectedMetadataRow {
  principal: String,
  action: String,
  ip: IpAddr,
  port: u16,
  reason_digest: String,
  receipt_digest: Option<String>,
}

/// Evidence attached to the negative-only continuation audit record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct ProtectedMetadataEvidence<'a> {
  pub reason_digest: &'a str,
  pub receipt_digest: Option<&'a str>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) enum ProtectedMetadataCheck<'a> {
  NotProtected,
  Deny,
  Continue(ProtectedMetadataEvidence<'a>),
}

#[derive(Clone, Debug, Default)]
pub(super) struct ProtectedMetadataPolicy {
  rows: Vec<ProtectedMetadataRow>,
  receipt_set_digest: Option<String>,
}

impl ProtectedMetadataPolicy {
  pub fn compile(
    rows: &[ProtectedMetadataRowFile],
    receipt_set_digest: Option<&str>,
    grants: &HashMap<String, String>,
    deny_ceiling: &str,
  ) -> Result<Self, String> {
    if rows.is_empty() {
      if receipt_set_digest.is_some() {
        return Err(
          "protectedMetadataReceiptSetDigest requires at least one protectedMetadata row"
            .to_string(),
        );
      }
      return Ok(Self::default());
    }

    let deny = Grant::parse_many(deny_ceiling)
      .map_err(|error| format!("invalid deny ceiling: {error}"))?;
    let receipt_gate = match receipt_set_digest {
      Some(digest) => {
        validate_digest("protectedMetadataReceiptSetDigest", digest)?;
        true
      }
      None => false,
    };
    let mut seen = HashSet::new();
    let mut compiled = Vec::with_capacity(rows.len());

    for (index, row) in rows.iter().enumerate() {
      let at = format!("protectedMetadata[{index}]");
      let selector = principal_selector(&row.principal).ok_or_else(|| {
        format!("{at}.principal is not an exact integrity-bound principal")
      })?;
      if !matches!(row.action.as_str(), "fetch" | "connect") {
        return Err(format!(
          "{at}.action must be the exact action fetch or connect"
        ));
      }
      if row.port == 0 {
        return Err(format!("{at}.port must be an exact nonzero port"));
      }
      validate_digest(&format!("{at}.reasonDigest"), &row.reason_digest)?;
      if row.reason_digest == empty_reason_digest() {
        return Err(format!(
          "{at}.reasonDigest cannot bind an empty protected-resource reason"
        ));
      }
      match (receipt_gate, row.receipt_digest.as_deref()) {
        (true, Some(digest)) => {
          validate_digest(&format!("{at}.receiptDigest"), digest)?;
        }
        (true, None) => {
          return Err(format!(
            "{at}.receiptDigest is required by protectedMetadataReceiptSetDigest"
          ));
        }
        (false, Some(_)) => {
          return Err(format!(
            "{at}.receiptDigest requires protectedMetadataReceiptSetDigest"
          ));
        }
        (false, None) => {}
      }

      let ip = row
        .ip
        .parse::<IpAddr>()
        .map_err(|_| format!("{at}.ip must be a canonical IP literal"))?;
      let normalized = normalize_ip(ip);
      if normalized != ip || normalized.to_string() != row.ip {
        return Err(format!(
          "{at}.ip must use the canonical effective IP spelling"
        ));
      }
      if !is_protected_metadata_ip(normalized) {
        return Err(format!(
          "{at}.ip is not in the protected metadata classifier"
        ));
      }

      let identity = (
        row.principal.clone(),
        row.action.clone(),
        normalized,
        row.port,
      );
      if !seen.insert(identity) {
        return Err(format!(
          "{at} duplicates an existing principal/action/IP/port row"
        ));
      }

      // The annotation never manufactures authority. It must decorate one
      // exact existing static network row, including the exact port.
      let expected_scope = endpoint_scope(normalized, row.port);
      let floor = grants
        .get(&selector)
        .ok_or_else(|| format!("{at} has no static floor for {selector:?}"))?;
      let floor = Grant::parse_many(floor).map_err(|error| {
        format!("{at} has an invalid static floor: {error}")
      })?;
      let exact_floor = floor.iter().any(|grant| {
        grant.family == Family::Network
          && grant.action == row.action
          && grant.scope == expected_scope
      });
      if !exact_floor {
        return Err(format!(
          "{at} requires exact static row network:{}:{expected_scope} for {selector:?}",
          row.action
        ));
      }

      let request = Request {
        family: Family::Network,
        action: row.action.clone(),
        target: expected_scope,
      };
      if covers(&deny, &request) {
        return Err(format!(
          "{at} is shadowed by the ordinary immutable deny ceiling"
        ));
      }

      compiled.push(ProtectedMetadataRow {
        principal: row.principal.clone(),
        action: row.action.clone(),
        ip: normalized,
        port: row.port,
        reason_digest: row.reason_digest.clone(),
        receipt_digest: row.receipt_digest.clone(),
      });
    }

    compiled
      .sort_by(|left, right| binding_line(left).cmp(&binding_line(right)));
    if let Some(expected) = receipt_set_digest {
      let actual = receipt_set_digest_for(&compiled);
      if actual != expected {
        return Err(format!(
          "protectedMetadataReceiptSetDigest mismatch: expected {expected}, computed {actual}"
        ));
      }
    }

    Ok(Self {
      rows: compiled,
      receipt_set_digest: receipt_set_digest.map(str::to_string),
    })
  }

  pub fn check(
    &self,
    principal: &str,
    action: &str,
    ip: IpAddr,
    port: u16,
  ) -> ProtectedMetadataCheck<'_> {
    let ip = normalize_ip(ip);
    if !is_protected_metadata_ip(ip) {
      return ProtectedMetadataCheck::NotProtected;
    }
    let Some(row) = self.rows.iter().find(|row| {
      row.principal == principal
        && row.action == action
        && row.ip == ip
        && row.port == port
    }) else {
      return ProtectedMetadataCheck::Deny;
    };
    ProtectedMetadataCheck::Continue(ProtectedMetadataEvidence {
      reason_digest: &row.reason_digest,
      receipt_digest: row.receipt_digest.as_deref(),
    })
  }

  pub fn receipt_set_digest(&self) -> Option<&str> {
    self.receipt_set_digest.as_deref()
  }
}

pub(super) fn normalize_ip(ip: IpAddr) -> IpAddr {
  match ip {
    IpAddr::V6(ip) => ip
      .to_ipv4_mapped()
      .map(IpAddr::V4)
      .unwrap_or(IpAddr::V6(ip)),
    IpAddr::V4(_) => ip,
  }
}

pub(super) fn is_protected_metadata_ip(ip: IpAddr) -> bool {
  match normalize_ip(ip) {
    IpAddr::V4(ip) => {
      matches!(ip, METADATA_V4_A | METADATA_V4_B | METADATA_V4_C)
    }
    IpAddr::V6(ip) => matches!(ip, METADATA_V6_A | METADATA_V6_B),
  }
}

pub(super) fn endpoint_scope(ip: IpAddr, port: u16) -> String {
  match normalize_ip(ip) {
    IpAddr::V4(ip) => format!("{ip}:{port}"),
    IpAddr::V6(ip) => format!("[{ip}]:{port}"),
  }
}

fn principal_selector(principal: &str) -> Option<String> {
  if principal == "root" {
    return Some("root".to_string());
  }
  if let Some(rest) = principal
    .strip_prefix("npm:")
    .or_else(|| principal.strip_prefix("jsr:"))
  {
    let version_at = rest.rfind('@')?;
    let (name, version) = rest.split_at(version_at);
    if name.is_empty() || version.len() <= 1 || version == "@<unversioned>" {
      return None;
    }
    return Some(name.to_string());
  }
  if let Some(url) = principal.strip_prefix("url:")
    && (url.starts_with("https://") || url.starts_with("http://"))
    && url.len() > "https://".len()
  {
    return Some(url.to_string());
  }
  None
}

fn validate_digest(field: &str, digest: &str) -> Result<(), String> {
  if digest.len() != 64
    || !digest
      .bytes()
      .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
  {
    return Err(format!("{field} must be a lowercase SHA-256 digest"));
  }
  Ok(())
}

fn sha256_hex(parts: &[&[u8]]) -> String {
  let mut hasher = Sha256::new();
  for part in parts {
    hasher.update(part);
  }
  let digest = hasher.finalize();
  digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn empty_reason_digest() -> String {
  sha256_hex(&[REASON_DOMAIN])
}

fn binding_line(row: &ProtectedMetadataRow) -> String {
  format!(
    "{}\0{}\0{}\0{}\0{}\0{}",
    row.principal,
    row.action,
    row.ip,
    row.port,
    row.reason_digest,
    row.receipt_digest.as_deref().unwrap_or("")
  )
}

fn receipt_set_digest_for(rows: &[ProtectedMetadataRow]) -> String {
  let joined = rows.iter().map(binding_line).collect::<Vec<_>>().join("\n");
  sha256_hex(&[RECEIPT_SET_DOMAIN, joined.as_bytes()])
}

#[cfg(test)]
mod tests {
  use super::*;
  use std::net::Ipv4Addr;
  use std::net::Ipv6Addr;

  fn reason() -> String {
    sha256_hex(&[REASON_DOMAIN, b"instance role credentials"])
  }

  fn base_row() -> ProtectedMetadataRowFile {
    ProtectedMetadataRowFile {
      principal: "root".to_string(),
      action: "fetch".to_string(),
      ip: "169.254.169.254".to_string(),
      port: 80,
      reason_digest: reason(),
      receipt_digest: None,
    }
  }

  fn grants() -> HashMap<String, String> {
    HashMap::from([(
      "root".to_string(),
      "network:fetch:169.254.169.254:80".to_string(),
    )])
  }

  #[test]
  fn classifies_all_registry_addresses_and_ipv4_mapped_ipv6() {
    for address in PROTECTED_METADATA_IPS {
      let ip = address.parse::<IpAddr>().unwrap();
      assert!(is_protected_metadata_ip(ip), "missed {address}");
    }
    assert!(is_protected_metadata_ip(IpAddr::V6(
      Ipv4Addr::new(169, 254, 169, 254).to_ipv6_mapped()
    )));
    assert!(!is_protected_metadata_ip(IpAddr::V4(Ipv4Addr::new(
      169, 254, 169, 253
    ))));
    assert!(!is_protected_metadata_ip(IpAddr::V6(Ipv6Addr::LOCALHOST)));
  }

  #[test]
  fn exact_row_is_a_negative_only_continuation() {
    let policy =
      ProtectedMetadataPolicy::compile(&[base_row()], None, &grants(), "")
        .unwrap();
    assert!(matches!(
      policy.check("root", "fetch", "169.254.169.254".parse().unwrap(), 80),
      ProtectedMetadataCheck::Continue(_)
    ));
    for (principal, action, ip, port) in [
      ("npm:root@1.0.0", "fetch", "169.254.169.254", 80),
      ("root", "connect", "169.254.169.254", 80),
      ("root", "fetch", "169.254.170.2", 80),
      ("root", "fetch", "169.254.169.254", 443),
    ] {
      assert_eq!(
        policy.check(principal, action, ip.parse().unwrap(), port),
        ProtectedMetadataCheck::Deny
      );
    }
    assert_eq!(
      policy.check("root", "fetch", "192.0.2.1".parse().unwrap(), 80),
      ProtectedMetadataCheck::NotProtected
    );
  }

  #[test]
  fn malformed_or_non_exact_rows_fail_closed() {
    let cases = [
      ("principal", "runtime"),
      ("principal", "dep"),
      ("action", "*"),
      ("action", "listen"),
      ("ip", "metadata.google.internal"),
      ("ip", "169.254.169.0/24"),
      ("ip", "::ffff:169.254.169.254"),
      ("ip", "192.0.2.1"),
      ("reasonDigest", "abc"),
    ];
    for (field, value) in cases {
      let mut row = base_row();
      match field {
        "principal" => row.principal = value.to_string(),
        "action" => row.action = value.to_string(),
        "ip" => row.ip = value.to_string(),
        "reasonDigest" => row.reason_digest = value.to_string(),
        _ => unreachable!(),
      }
      assert!(
        ProtectedMetadataPolicy::compile(&[row], None, &grants(), "").is_err(),
        "accepted malformed {field}={value:?}"
      );
    }

    let mut row = base_row();
    row.port = 0;
    assert!(
      ProtectedMetadataPolicy::compile(&[row], None, &grants(), "").is_err()
    );

    let mut missing_floor = grants();
    missing_floor.insert(
      "root".to_string(),
      "network:fetch:169.254.169.254".to_string(),
    );
    assert!(
      ProtectedMetadataPolicy::compile(&[base_row()], None, &missing_floor, "")
        .is_err()
    );
  }

  #[test]
  fn shadowed_rows_and_duplicates_are_rejected() {
    for ceiling in [
      "network:fetch:169.254.169.254:80",
      "network:fetch:169.254.169.254",
      "network:*:*",
    ] {
      assert!(
        ProtectedMetadataPolicy::compile(
          &[base_row()],
          None,
          &grants(),
          ceiling
        )
        .is_err(),
        "accepted row shadowed by {ceiling}"
      );
    }
    assert!(
      ProtectedMetadataPolicy::compile(
        &[base_row(), base_row()],
        None,
        &grants(),
        ""
      )
      .is_err()
    );
  }

  #[test]
  fn receipt_set_is_all_or_nothing_and_digest_bound() {
    let receipt = "b".repeat(64);
    let mut row = base_row();
    row.receipt_digest = Some(receipt);

    assert!(
      ProtectedMetadataPolicy::compile(&[row.clone()], None, &grants(), "")
        .is_err()
    );
    assert!(
      ProtectedMetadataPolicy::compile(
        &[base_row()],
        Some(&"a".repeat(64)),
        &grants(),
        ""
      )
      .is_err()
    );

    let provisional = ProtectedMetadataPolicy::compile(
      &[row.clone()],
      Some(&"a".repeat(64)),
      &grants(),
      "",
    )
    .unwrap_err();
    let computed = provisional
      .split("computed ")
      .nth(1)
      .expect("digest mismatch reports computed value");
    assert_eq!(
      computed,
      "f6bf551be239f8f5a96c6779c149fc251cf09e2d5bec6b5edb1fee8cc713dcdb"
    );
    let policy =
      ProtectedMetadataPolicy::compile(&[row], Some(computed), &grants(), "")
        .unwrap();
    assert_eq!(policy.receipt_set_digest(), Some(computed));
  }
}

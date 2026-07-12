// Copyright 2018-2026 the Deno authors. MIT license.

//! Stable, polarity-separated C04 session-row identity.
//!
//! This module deliberately stops before authority-state mutation. It turns
//! one already-canonical logical selector into the exact generated row IDs and
//! classifies a same-ID existing row as idempotent or conflicting. The later
//! permission adapter can consume this narrow result without reimplementing
//! the digest preimage or collision policy.
//!
//! @ref LLP 0019#typed-permission-batches [implements] -- Session identity is
//! stable across retries, excludes batch/transient fields, and uses distinct
//! positive and revocation digest domains.

#![allow(
  dead_code,
  reason = "the generated session-row builder precedes its authority-transaction adapter"
)]

use serde::Serialize;
use serde_json::Value;
use std::fmt;

use crate::oden_rev2_authority::RuntimeIdentityBinding;
use crate::rev2::CanonicalAuthoritySelector;
use crate::rev2::PrincipalRef;
use crate::rev2::canonical_json;
use crate::rev2::domain_digest;
use crate::rev2_registry_generated::REV2_RUNTIME_AUTHORITY_MAX_ROW_BYTES;
use crate::rev2_registry_generated::REV2_RUNTIME_SESSION_DUPLICATE_DISPOSITION;
use crate::rev2_registry_generated::REV2_RUNTIME_SESSION_IDENTITY_SELECTOR_FIELDS;
use crate::rev2_registry_generated::REV2_RUNTIME_SESSION_POSITIVE_ROW_ID_DOMAIN;
use crate::rev2_registry_generated::REV2_RUNTIME_SESSION_REVOCATION_ROW_ID_DOMAIN;
use crate::rev2_registry_generated::REV2_RUNTIME_SESSION_ROW_ID_PREIMAGE_SCHEMA;
use crate::rev2_registry_generated::REV2_RUNTIME_SESSION_ROW_IDENTITY_FIELDS;

const EXPECTED_IDENTITY_FIELDS: &[&str] = &[
  "identity.armedSnapshotDigest",
  "overlayOwner",
  "principal",
  "slot.capability",
  "identitySelector",
];
const EXPECTED_SELECTOR_FIELDS: &[&str] =
  &["principal", "capability", "resource"];
const EXPECTED_DUPLICATE_DISPOSITION: &str =
  "identical-row-is-idempotent-replacement;conflicting-row-refuses";

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum SessionRowIdentityError {
  GeneratedContractDrift,
  MissingPrincipal,
  PrincipalMismatch,
  EmptyCapability,
  BoundExceeded,
  ConflictingRow,
  Digest(String),
}

impl fmt::Display for SessionRowIdentityError {
  fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
    match self {
      Self::GeneratedContractDrift => {
        formatter.write_str("generated session-row contract drifted")
      }
      Self::MissingPrincipal => {
        formatter.write_str("session selector has no principal")
      }
      Self::PrincipalMismatch => formatter
        .write_str("session selector principal differs from its dimension"),
      Self::EmptyCapability => {
        formatter.write_str("session selector has an empty capability")
      }
      Self::BoundExceeded => {
        formatter.write_str("session-row identity exceeds generated bound")
      }
      Self::ConflictingRow => {
        formatter.write_str("same session-row ID names a different row")
      }
      Self::Digest(error) => {
        write!(formatter, "session-row digest failed: {error}")
      }
    }
  }
}

impl std::error::Error for SessionRowIdentityError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SessionRowAdmission {
  Insert,
  Idempotent,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct OdenRev2SessionRowIds {
  positive: String,
  revocation: String,
}

impl OdenRev2SessionRowIds {
  pub(crate) fn positive(&self) -> &str {
    &self.positive
  }

  pub(crate) fn revocation(&self) -> &str {
    &self.revocation
  }
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SessionIdentitySelector<'a> {
  principal: &'a PrincipalRef,
  capability: &'a str,
  resource: &'a Value,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct SessionRowIdPreimage<'a> {
  schema: &'static str,
  armed_snapshot_digest: &'a str,
  overlay_owner: &'a PrincipalRef,
  principal: &'a PrincipalRef,
  capability: &'a str,
  identity_selector: SessionIdentitySelector<'a>,
}

fn ensure_generated_contract() -> Result<(), SessionRowIdentityError> {
  if REV2_RUNTIME_SESSION_ROW_IDENTITY_FIELDS != EXPECTED_IDENTITY_FIELDS
    || REV2_RUNTIME_SESSION_IDENTITY_SELECTOR_FIELDS != EXPECTED_SELECTOR_FIELDS
    || REV2_RUNTIME_SESSION_DUPLICATE_DISPOSITION
      != EXPECTED_DUPLICATE_DISPOSITION
  {
    return Err(SessionRowIdentityError::GeneratedContractDrift);
  }
  Ok(())
}

pub(crate) fn session_row_ids(
  identity: &RuntimeIdentityBinding,
  overlay_owner: &PrincipalRef,
  principal: &PrincipalRef,
  selector: &CanonicalAuthoritySelector,
) -> Result<OdenRev2SessionRowIds, SessionRowIdentityError> {
  ensure_generated_contract()?;
  let selector_principal = selector
    .principal
    .as_ref()
    .ok_or(SessionRowIdentityError::MissingPrincipal)?;
  if selector_principal != principal {
    return Err(SessionRowIdentityError::PrincipalMismatch);
  }
  if selector.capability.is_empty() {
    return Err(SessionRowIdentityError::EmptyCapability);
  }
  let preimage = SessionRowIdPreimage {
    schema: REV2_RUNTIME_SESSION_ROW_ID_PREIMAGE_SCHEMA,
    armed_snapshot_digest: identity.armed_snapshot_digest(),
    overlay_owner,
    principal,
    capability: &selector.capability,
    identity_selector: SessionIdentitySelector {
      principal,
      capability: &selector.capability,
      resource: &selector.resource,
    },
  };
  let value = serde_json::to_value(preimage)
    .map_err(|error| SessionRowIdentityError::Digest(error.to_string()))?;
  let canonical = canonical_json(&value)
    .map_err(|error| SessionRowIdentityError::Digest(error.to_string()))?;
  if canonical.len() > REV2_RUNTIME_AUTHORITY_MAX_ROW_BYTES {
    return Err(SessionRowIdentityError::BoundExceeded);
  }
  let positive =
    domain_digest(REV2_RUNTIME_SESSION_POSITIVE_ROW_ID_DOMAIN, &value)
      .map_err(|error| SessionRowIdentityError::Digest(error.to_string()))?;
  let revocation =
    domain_digest(REV2_RUNTIME_SESSION_REVOCATION_ROW_ID_DOMAIN, &value)
      .map_err(|error| SessionRowIdentityError::Digest(error.to_string()))?;
  if positive == revocation {
    return Err(SessionRowIdentityError::GeneratedContractDrift);
  }
  Ok(OdenRev2SessionRowIds {
    positive,
    revocation,
  })
}

pub(crate) fn classify_same_id_row(
  existing: Option<&CanonicalAuthoritySelector>,
  proposed: &CanonicalAuthoritySelector,
) -> Result<SessionRowAdmission, SessionRowIdentityError> {
  match existing {
    None => Ok(SessionRowAdmission::Insert),
    Some(existing) if existing == proposed => {
      Ok(SessionRowAdmission::Idempotent)
    }
    Some(_) => Err(SessionRowIdentityError::ConflictingRow),
  }
}

#[cfg(test)]
mod tests {
  use super::*;
  use crate::rev2::PrincipalKind;

  fn digest() -> String {
    "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string()
  }

  fn identity() -> RuntimeIdentityBinding {
    RuntimeIdentityBinding::new(
      digest(),
      digest(),
      digest(),
      digest(),
      digest(),
      "run:test".to_string(),
      "channel:test".to_string(),
    )
    .unwrap()
  }

  fn principal(key: &str) -> PrincipalRef {
    PrincipalRef {
      kind: PrincipalKind::Package,
      key: key.to_string(),
    }
  }

  fn selector(
    principal: &PrincipalRef,
    projection_id: &str,
    path: &str,
  ) -> CanonicalAuthoritySelector {
    CanonicalAuthoritySelector {
      principal: Some(principal.clone()),
      capability: "fs:read".to_string(),
      projection_id: projection_id.to_string(),
      resource: serde_json::json!({
        "kind": "path-exact",
        "root": "$PROJECT",
        "path": path,
      }),
    }
  }

  #[test]
  fn exact_preimage_has_stable_polarity_separated_ids() {
    let subject = principal("pkg:subject");
    let overlay_owner = principal("pkg:overlay");
    let ids = session_row_ids(
      &identity(),
      &overlay_owner,
      &subject,
      &selector(&subject, "projection.fs:read.positive/2", "src/main.ts"),
    )
    .unwrap();
    assert_eq!(
      ids.positive(),
      "sha256-5vzeP0xCxZa0kP11K621ub390CkgnrZOqDD87QEYn-o"
    );
    assert_eq!(
      ids.revocation(),
      "sha256-HNhrFl4bPF_a5bdXtUB7L9y4mtUpKYFyR_mSImqhCj4"
    );
    assert_ne!(ids.positive(), ids.revocation());
  }

  #[test]
  fn projection_polarity_does_not_change_logical_row_identity() {
    let subject = principal("pkg:subject");
    let overlay_owner = principal("pkg:overlay");
    let positive = session_row_ids(
      &identity(),
      &overlay_owner,
      &subject,
      &selector(&subject, "projection.fs:read.positive/2", "src/main.ts"),
    )
    .unwrap();
    let negative = session_row_ids(
      &identity(),
      &overlay_owner,
      &subject,
      &selector(&subject, "projection.fs:read.negative/2", "src/main.ts"),
    )
    .unwrap();
    assert_eq!(positive, negative);
  }

  #[test]
  fn same_id_rows_are_idempotent_or_refused_never_replaced() {
    let subject = principal("pkg:subject");
    let exact =
      selector(&subject, "projection.fs:read.positive/2", "src/main.ts");
    assert_eq!(
      classify_same_id_row(None, &exact).unwrap(),
      SessionRowAdmission::Insert
    );
    assert_eq!(
      classify_same_id_row(Some(&exact), &exact).unwrap(),
      SessionRowAdmission::Idempotent
    );
    let conflicting =
      selector(&subject, "projection.fs:read.positive/2", "src/other.ts");
    assert_eq!(
      classify_same_id_row(Some(&exact), &conflicting),
      Err(SessionRowIdentityError::ConflictingRow)
    );
  }

  #[test]
  fn identity_refuses_dimension_substitution_and_generated_row_overflow() {
    let subject = principal("pkg:subject");
    let other = principal("pkg:other");
    let overlay_owner = principal("pkg:overlay");
    assert_eq!(
      session_row_ids(
        &identity(),
        &overlay_owner,
        &other,
        &selector(&subject, "projection.fs:read.positive/2", "src/main.ts",),
      ),
      Err(SessionRowIdentityError::PrincipalMismatch)
    );

    let oversized = "x".repeat(REV2_RUNTIME_AUTHORITY_MAX_ROW_BYTES + 1);
    assert_eq!(
      session_row_ids(
        &identity(),
        &overlay_owner,
        &subject,
        &selector(&subject, "projection.fs:read.positive/2", &oversized,),
      ),
      Err(SessionRowIdentityError::BoundExceeded)
    );
  }
}

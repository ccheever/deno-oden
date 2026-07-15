// Copyright 2018-2026 the Deno authors. MIT license.

// @ref LLP 0019#frozen-parent-standalone-allowlist-and-byte-graph [implements] —
// This first fail-closed slice keeps the reviewed contract inventories and
// parent-allowlist rendering as exact raw-byte and domain-separated canonical-
// JSON projections. It intentionally exposes no allowlist constructor until
// the domain-bound configuration, VFS, static-edge, and HBYTES projectors land;
// generated outputs and later image/evidence authority are absent as well.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::Serialize;
use sha2::Digest as _;
use sha2::Sha256;
use thiserror::Error;

pub const ODEN_PARENT_ALLOWLIST_SCHEMA: &str =
  "oden/capsec-filesystem-parent-standalone-allowlist/2";
pub const ODEN_PARENT_ALLOWLIST_DIGEST_DOMAIN: &str =
  "oden:capsec:filesystem-parent-standalone-allowlist:2";
pub const ODEN_PARENT_CAPTURE_CONTRACT_INVENTORY_DIGEST_DOMAIN: &str =
  "oden:capsec:filesystem-parent-capture-contract-inventory:2";
pub const ODEN_PARENT_SOURCE_CLOSURE_CONTRACT_INVENTORY_DIGEST_DOMAIN: &str =
  "oden:capsec:filesystem-parent-source-closure-contract-inventory:2";
pub const ODEN_PARENT_RELEASE_CONTRACT_INVENTORY_DIGEST_DOMAIN: &str =
  "oden:capsec:filesystem-parent-release-contract-inventory:2";
pub const ODEN_PARENT_ENTRYPOINT_KEY: &str = "repo:src/release.ts";
pub const ODEN_PARENT_PRIMITIVE_ID: &str = "oden.filesystem-parent-capture/2";
pub const ODEN_PARENT_PRIVATE_MODULE_SPECIFIER: &str =
  "oden-internal:filesystem-parent-capture-v2";
pub const ODEN_PARENT_PROFILE: &str = "oden/capsec/2";

pub const ODEN_PARENT_GENERATED_JSON_PATH: &str =
  "generated/capsec/rev2/filesystem-parent-standalone-allowlist.json";
pub const ODEN_PARENT_GENERATED_RUST_PATH: &str =
  "fork/deno/cli/lib/standalone/oden_parent_allowlist_generated.rs";

#[derive(Debug, Error, PartialEq, Eq)]
pub enum OdenParentAllowlistError {
  #[error("contract inventory is empty")]
  EmptyInventory,
  #[error("invalid repository-relative contract path: {0}")]
  InvalidContractPath(String),
  #[error("generated output cannot be a contract-inventory member: {0}")]
  GeneratedOutputMember(String),
  #[error(
    "contract paths are duplicated or not in raw UTF-8 order: {previous} then {current}"
  )]
  UnsortedContractPaths { previous: String, current: String },
  #[error("invalid canonical sha256 digest for {field}: {value}")]
  InvalidSha256Digest { field: &'static str, value: String },
  #[error("digest domain must be nonempty printable ASCII without NUL")]
  InvalidDigestDomain,
  #[error("canonical JSON rendering failed: {0}")]
  CanonicalJson(String),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct CanonicalSha256Digest(String);

impl CanonicalSha256Digest {
  pub fn parse(
    field: &'static str,
    value: impl Into<String>,
  ) -> Result<Self, OdenParentAllowlistError> {
    let value = value.into();
    let encoded = value.strip_prefix("sha256-").ok_or_else(|| {
      OdenParentAllowlistError::InvalidSha256Digest {
        field,
        value: value.clone(),
      }
    })?;
    let decoded = URL_SAFE_NO_PAD.decode(encoded).map_err(|_| {
      OdenParentAllowlistError::InvalidSha256Digest {
        field,
        value: value.clone(),
      }
    })?;
    if decoded.len() != 32 || URL_SAFE_NO_PAD.encode(&decoded) != encoded {
      return Err(OdenParentAllowlistError::InvalidSha256Digest {
        field,
        value,
      });
    }
    Ok(Self(format!("sha256-{encoded}")))
  }

  pub fn as_str(&self) -> &str {
    &self.0
  }
}

#[derive(Clone, Copy, Debug)]
pub struct ContractFile<'a> {
  pub path: &'a str,
  pub bytes: &'a [u8],
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ContractInventoryRow {
  #[serde(rename = "byteDigest")]
  byte_digest: CanonicalSha256Digest,
  path: String,
}

impl ContractInventoryRow {
  pub fn path(&self) -> &str {
    &self.path
  }

  pub fn byte_digest(&self) -> &CanonicalSha256Digest {
    &self.byte_digest
  }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContractInventory {
  rows: Vec<ContractInventoryRow>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContractInventoryKind {
  Capture,
  SourceClosure,
  Release,
}

impl ContractInventoryKind {
  fn digest_domain(self) -> &'static str {
    match self {
      Self::Capture => ODEN_PARENT_CAPTURE_CONTRACT_INVENTORY_DIGEST_DOMAIN,
      Self::SourceClosure => {
        ODEN_PARENT_SOURCE_CLOSURE_CONTRACT_INVENTORY_DIGEST_DOMAIN
      }
      Self::Release => ODEN_PARENT_RELEASE_CONTRACT_INVENTORY_DIGEST_DOMAIN,
    }
  }
}

impl ContractInventory {
  pub fn from_files(
    files: &[ContractFile<'_>],
  ) -> Result<Self, OdenParentAllowlistError> {
    if files.is_empty() {
      return Err(OdenParentAllowlistError::EmptyInventory);
    }

    let mut rows = Vec::with_capacity(files.len());
    let mut previous: Option<&str> = None;
    for file in files {
      validate_contract_path(file.path)?;
      if matches!(
        file.path,
        ODEN_PARENT_GENERATED_JSON_PATH | ODEN_PARENT_GENERATED_RUST_PATH
      ) {
        return Err(OdenParentAllowlistError::GeneratedOutputMember(
          file.path.to_string(),
        ));
      }
      if let Some(previous) = previous
        && previous.as_bytes() >= file.path.as_bytes()
      {
        return Err(OdenParentAllowlistError::UnsortedContractPaths {
          previous: previous.to_string(),
          current: file.path.to_string(),
        });
      }
      rows.push(ContractInventoryRow {
        byte_digest: raw_sha256_digest(file.bytes),
        path: file.path.to_string(),
      });
      previous = Some(file.path);
    }

    Ok(Self { rows })
  }

  pub fn rows(&self) -> &[ContractInventoryRow] {
    &self.rows
  }

  pub fn canonical_jcs(&self) -> Result<Vec<u8>, OdenParentAllowlistError> {
    closed_shape_jcs(&self.rows)
  }

  pub fn digest(
    &self,
    kind: ContractInventoryKind,
  ) -> Result<CanonicalSha256Digest, OdenParentAllowlistError> {
    hjcs_digest(kind.digest_domain(), &self.canonical_jcs()?)
  }
}

#[cfg(test)]
#[derive(Clone, Debug, PartialEq, Eq)]
struct OdenParentAllowlistDigests {
  capture_contract_digest: CanonicalSha256Digest,
  entrypoint_source_digest: CanonicalSha256Digest,
  release_contract_digest: CanonicalSha256Digest,
  source_closure_contract_digest: CanonicalSha256Digest,
  standalone_configuration_digest: CanonicalSha256Digest,
  static_import_edge_digest: CanonicalSha256Digest,
  synthetic_module_source_digest: CanonicalSha256Digest,
  vfs_graph_digest: CanonicalSha256Digest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct OdenParentAllowlist {
  #[serde(rename = "captureContractDigest")]
  capture_contract_digest: CanonicalSha256Digest,
  #[serde(rename = "engineProvenanceSchema")]
  engine_provenance_schema: u8,
  #[serde(rename = "entrypointKey")]
  entrypoint_key: &'static str,
  #[serde(rename = "entrypointSourceDigest")]
  entrypoint_source_digest: CanonicalSha256Digest,
  #[serde(rename = "parentPrimitiveId")]
  parent_primitive_id: &'static str,
  #[serde(rename = "privateModuleSpecifier")]
  private_module_specifier: &'static str,
  profile: &'static str,
  #[serde(rename = "releaseContractDigest")]
  release_contract_digest: CanonicalSha256Digest,
  schema: &'static str,
  #[serde(rename = "sourceClosureContractDigest")]
  source_closure_contract_digest: CanonicalSha256Digest,
  #[serde(rename = "standaloneConfigurationDigest")]
  standalone_configuration_digest: CanonicalSha256Digest,
  #[serde(rename = "staticImportEdgeDigest")]
  static_import_edge_digest: CanonicalSha256Digest,
  #[serde(rename = "syntheticModuleSourceDigest")]
  synthetic_module_source_digest: CanonicalSha256Digest,
  #[serde(rename = "vfsGraphDigest")]
  vfs_graph_digest: CanonicalSha256Digest,
}

impl OdenParentAllowlist {
  #[cfg(test)]
  fn new(digests: OdenParentAllowlistDigests) -> Self {
    Self {
      capture_contract_digest: digests.capture_contract_digest,
      engine_provenance_schema: 2,
      entrypoint_key: ODEN_PARENT_ENTRYPOINT_KEY,
      entrypoint_source_digest: digests.entrypoint_source_digest,
      parent_primitive_id: ODEN_PARENT_PRIMITIVE_ID,
      private_module_specifier: ODEN_PARENT_PRIVATE_MODULE_SPECIFIER,
      profile: ODEN_PARENT_PROFILE,
      release_contract_digest: digests.release_contract_digest,
      schema: ODEN_PARENT_ALLOWLIST_SCHEMA,
      source_closure_contract_digest: digests.source_closure_contract_digest,
      standalone_configuration_digest: digests.standalone_configuration_digest,
      static_import_edge_digest: digests.static_import_edge_digest,
      synthetic_module_source_digest: digests.synthetic_module_source_digest,
      vfs_graph_digest: digests.vfs_graph_digest,
    }
  }

  pub fn canonical_jcs(&self) -> Result<Vec<u8>, OdenParentAllowlistError> {
    closed_shape_jcs(self)
  }

  pub fn digest(
    &self,
  ) -> Result<CanonicalSha256Digest, OdenParentAllowlistError> {
    hjcs_digest(ODEN_PARENT_ALLOWLIST_DIGEST_DOMAIN, &self.canonical_jcs()?)
  }

  pub fn render_json_file(&self) -> Result<Vec<u8>, OdenParentAllowlistError> {
    let mut output = self.canonical_jcs()?;
    output.push(b'\n');
    Ok(output)
  }

  pub fn render_rust_module(
    &self,
  ) -> Result<Vec<u8>, OdenParentAllowlistError> {
    let jcs = self.canonical_jcs()?;
    let jcs = std::str::from_utf8(&jcs).map_err(|error| {
      OdenParentAllowlistError::CanonicalJson(error.to_string())
    })?;
    let digest = self.digest()?;
    Ok(
      format!(
        "// Copyright 2018-2026 the Deno authors. MIT license.\n\
       // This file is generated deterministically. Do not edit.\n\n\
       pub const ODEN_PARENT_ALLOWLIST_JCS: &[u8] = br#\"{jcs}\"#;\n\
       pub const ODEN_PARENT_ALLOWLIST_DIGEST: &str = \"{}\";\n",
        digest.as_str()
      )
      .into_bytes(),
    )
  }
}

pub fn raw_sha256_digest(bytes: &[u8]) -> CanonicalSha256Digest {
  let digest = Sha256::digest(bytes);
  CanonicalSha256Digest(format!("sha256-{}", URL_SAFE_NO_PAD.encode(digest)))
}

fn hjcs_digest(
  domain: &str,
  canonical_jcs: &[u8],
) -> Result<CanonicalSha256Digest, OdenParentAllowlistError> {
  validate_digest_domain(domain)?;
  let mut hasher = Sha256::new();
  hasher.update(domain.as_bytes());
  hasher.update([0]);
  hasher.update(canonical_jcs);
  Ok(CanonicalSha256Digest(format!(
    "sha256-{}",
    URL_SAFE_NO_PAD.encode(hasher.finalize())
  )))
}

// This serializer is confined to the closed inventory row/array and allowlist
// shapes above: object fields are declared in JCS member order, values are
// strings or the exact safe integer 2, and array order is validated before
// serialization. Nested maps or general numeric values require a full JCS
// projector and must not be routed through this helper.
fn closed_shape_jcs(
  value: &impl Serialize,
) -> Result<Vec<u8>, OdenParentAllowlistError> {
  serde_json::to_vec(value)
    .map_err(|error| OdenParentAllowlistError::CanonicalJson(error.to_string()))
}

fn validate_digest_domain(
  domain: &str,
) -> Result<(), OdenParentAllowlistError> {
  if domain.is_empty()
    || !domain
      .as_bytes()
      .iter()
      .all(|byte| (0x20..=0x7e).contains(byte))
  {
    return Err(OdenParentAllowlistError::InvalidDigestDomain);
  }
  Ok(())
}

fn validate_contract_path(path: &str) -> Result<(), OdenParentAllowlistError> {
  if path.is_empty()
    || path.starts_with('/')
    || path.contains('\\')
    || path.contains('\0')
    || path
      .split('/')
      .any(|component| component.is_empty() || matches!(component, "." | ".."))
  {
    return Err(OdenParentAllowlistError::InvalidContractPath(
      path.to_string(),
    ));
  }
  Ok(())
}

#[cfg(test)]
mod tests {
  use super::*;

  const ZERO_DIGEST: &str =
    "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

  fn zero_digest(field: &'static str) -> CanonicalSha256Digest {
    CanonicalSha256Digest::parse(field, ZERO_DIGEST).unwrap()
  }

  fn test_allowlist() -> OdenParentAllowlist {
    OdenParentAllowlist::new(OdenParentAllowlistDigests {
      capture_contract_digest: zero_digest("captureContractDigest"),
      entrypoint_source_digest: zero_digest("entrypointSourceDigest"),
      release_contract_digest: zero_digest("releaseContractDigest"),
      source_closure_contract_digest: zero_digest(
        "sourceClosureContractDigest",
      ),
      standalone_configuration_digest: zero_digest(
        "standaloneConfigurationDigest",
      ),
      static_import_edge_digest: zero_digest("staticImportEdgeDigest"),
      synthetic_module_source_digest: zero_digest(
        "syntheticModuleSourceDigest",
      ),
      vfs_graph_digest: zero_digest("vfsGraphDigest"),
    })
  }

  #[test]
  fn raw_digest_and_inventory_jcs_have_exact_preimages() {
    assert_eq!(
      raw_sha256_digest(b"").as_str(),
      "sha256-47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU"
    );
    assert_eq!(
      raw_sha256_digest(b"abc").as_str(),
      "sha256-ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0"
    );

    let inventory = ContractInventory::from_files(&[
      ContractFile {
        path: "a",
        bytes: b"",
      },
      ContractFile {
        path: "b",
        bytes: b"abc",
      },
    ])
    .unwrap();
    assert_eq!(
      inventory.canonical_jcs().unwrap(),
      br#"[{"byteDigest":"sha256-47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU","path":"a"},{"byteDigest":"sha256-ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0","path":"b"}]"#
    );
  }

  #[test]
  fn hjcs_is_domain_nul_then_canonical_bytes() {
    let domain = "oden:test:projection:1";
    let jcs = br#"{"a":1}"#;
    let mut expected = Sha256::new();
    expected.update(domain.as_bytes());
    expected.update([0]);
    expected.update(jcs);
    assert_eq!(
      hjcs_digest(domain, jcs).unwrap().as_str(),
      format!("sha256-{}", URL_SAFE_NO_PAD.encode(expected.finalize()))
    );
    assert_eq!(
      hjcs_digest("", jcs),
      Err(OdenParentAllowlistError::InvalidDigestDomain)
    );
    assert_eq!(
      hjcs_digest("oden\0test", jcs),
      Err(OdenParentAllowlistError::InvalidDigestDomain)
    );
  }

  #[test]
  fn inventories_refuse_invalid_membership() {
    assert_eq!(
      ContractInventory::from_files(&[]),
      Err(OdenParentAllowlistError::EmptyInventory)
    );
    for path in ["", "/a", "a//b", "a/./b", "a/../b", "a\\b"] {
      assert!(matches!(
        ContractInventory::from_files(&[ContractFile { path, bytes: b"x" }]),
        Err(OdenParentAllowlistError::InvalidContractPath(_))
      ));
    }
    for path in [
      ODEN_PARENT_GENERATED_JSON_PATH,
      ODEN_PARENT_GENERATED_RUST_PATH,
    ] {
      assert_eq!(
        ContractInventory::from_files(&[ContractFile { path, bytes: b"x" }]),
        Err(OdenParentAllowlistError::GeneratedOutputMember(
          path.to_string()
        ))
      );
    }
    for files in [
      [
        ContractFile {
          path: "b",
          bytes: b"x",
        },
        ContractFile {
          path: "a",
          bytes: b"x",
        },
      ],
      [
        ContractFile {
          path: "a",
          bytes: b"x",
        },
        ContractFile {
          path: "a",
          bytes: b"y",
        },
      ],
    ] {
      assert!(matches!(
        ContractInventory::from_files(&files),
        Err(OdenParentAllowlistError::UnsortedContractPaths { .. })
      ));
    }
  }

  #[test]
  fn canonical_digest_parser_refuses_aliases_and_wrong_widths() {
    for value in [
      "sha256-short",
      "SHA256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
      "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB",
    ] {
      assert!(matches!(
        CanonicalSha256Digest::parse("test", value),
        Err(OdenParentAllowlistError::InvalidSha256Digest { .. })
      ));
    }
  }

  #[test]
  fn allowlist_renderings_are_exact_and_deterministic() {
    let allowlist = test_allowlist();
    let jcs = allowlist.canonical_jcs().unwrap();
    assert_eq!(
      jcs,
      format!(
        "{{\"captureContractDigest\":\"{ZERO_DIGEST}\",\"engineProvenanceSchema\":2,\"entrypointKey\":\"repo:src/release.ts\",\"entrypointSourceDigest\":\"{ZERO_DIGEST}\",\"parentPrimitiveId\":\"oden.filesystem-parent-capture/2\",\"privateModuleSpecifier\":\"oden-internal:filesystem-parent-capture-v2\",\"profile\":\"oden/capsec/2\",\"releaseContractDigest\":\"{ZERO_DIGEST}\",\"schema\":\"oden/capsec-filesystem-parent-standalone-allowlist/2\",\"sourceClosureContractDigest\":\"{ZERO_DIGEST}\",\"standaloneConfigurationDigest\":\"{ZERO_DIGEST}\",\"staticImportEdgeDigest\":\"{ZERO_DIGEST}\",\"syntheticModuleSourceDigest\":\"{ZERO_DIGEST}\",\"vfsGraphDigest\":\"{ZERO_DIGEST}\"}}"
      )
      .into_bytes()
    );

    let mut json_file = jcs.clone();
    json_file.push(b'\n');
    assert_eq!(allowlist.render_json_file().unwrap(), json_file);
    let rust = allowlist.render_rust_module().unwrap();
    assert_eq!(rust, allowlist.render_rust_module().unwrap());
    let jcs_text = std::str::from_utf8(&jcs).unwrap();
    let mut digest = Sha256::new();
    digest.update(ODEN_PARENT_ALLOWLIST_DIGEST_DOMAIN.as_bytes());
    digest.update([0]);
    digest.update(&jcs);
    let digest =
      format!("sha256-{}", URL_SAFE_NO_PAD.encode(digest.finalize()));
    assert_eq!(
      rust,
      format!(
        "// Copyright 2018-2026 the Deno authors. MIT license.\n\
         // This file is generated deterministically. Do not edit.\n\n\
         pub const ODEN_PARENT_ALLOWLIST_JCS: &[u8] = br#\"{jcs_text}\"#;\n\
         pub const ODEN_PARENT_ALLOWLIST_DIGEST: &str = \"{digest}\";\n"
      )
      .into_bytes()
    );
  }
}

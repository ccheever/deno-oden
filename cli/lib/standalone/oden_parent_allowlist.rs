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
pub const ODEN_PARENT_ENTRYPOINT_SOURCE_DIGEST_DOMAIN: &str =
  "oden:capsec:filesystem-parent-entrypoint-source:2";
pub const ODEN_PARENT_SYNTHETIC_MODULE_SOURCE_DIGEST_DOMAIN: &str =
  "oden:capsec:filesystem-parent-synthetic-module-source:2";
pub const ODEN_PARENT_VFS_ORIGINAL_BYTES_DIGEST_DOMAIN: &str =
  "oden:capsec:filesystem-parent-vfs-original-bytes:2";
pub const ODEN_PARENT_VFS_EMITTED_BYTES_DIGEST_DOMAIN: &str =
  "oden:capsec:filesystem-parent-vfs-emitted-bytes:2";
pub const ODEN_PARENT_VFS_SOURCE_MAP_BYTES_DIGEST_DOMAIN: &str =
  "oden:capsec:filesystem-parent-vfs-source-map-bytes:2";
pub const ODEN_PARENT_ENTRYPOINT_KEY: &str = "repo:src/release.ts";
pub const ODEN_PARENT_PRIMITIVE_ID: &str = "oden.filesystem-parent-capture/2";
pub const ODEN_PARENT_PRIVATE_MODULE_SPECIFIER: &str =
  "oden-internal:filesystem-parent-capture-v2";
pub const ODEN_PARENT_PROFILE: &str = "oden/capsec/2";

pub const ODEN_PARENT_GENERATED_JSON_PATH: &str =
  "generated/capsec/rev2/filesystem-parent-standalone-allowlist.json";
pub const ODEN_PARENT_GENERATED_RUST_PATH: &str =
  "fork/deno/cli/lib/standalone/oden_parent_allowlist_generated.rs";

const MAX_IJSON_SAFE_INTEGER: u64 = 9_007_199_254_740_991;

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
  #[error("parent projection contains a number outside its I-JSON/JCS range")]
  InvalidIJsonNumber,
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

macro_rules! define_hbytes_digest {
  ($name:ident, $domain:ident) => {
    #[derive(Clone, Debug, PartialEq, Eq, Serialize)]
    #[serde(transparent)]
    pub struct $name(CanonicalSha256Digest);

    impl $name {
      pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(framed_sha256_digest($domain, bytes))
      }

      pub fn as_str(&self) -> &str {
        self.0.as_str()
      }
    }
  };
}

define_hbytes_digest!(
  OdenParentEntrypointSourceDigest,
  ODEN_PARENT_ENTRYPOINT_SOURCE_DIGEST_DOMAIN
);
define_hbytes_digest!(
  OdenParentSyntheticModuleSourceDigest,
  ODEN_PARENT_SYNTHETIC_MODULE_SOURCE_DIGEST_DOMAIN
);
define_hbytes_digest!(
  OdenParentVfsOriginalBytesDigest,
  ODEN_PARENT_VFS_ORIGINAL_BYTES_DIGEST_DOMAIN
);
define_hbytes_digest!(
  OdenParentVfsEmittedBytesDigest,
  ODEN_PARENT_VFS_EMITTED_BYTES_DIGEST_DOMAIN
);
define_hbytes_digest!(
  OdenParentVfsSourceMapBytesDigest,
  ODEN_PARENT_VFS_SOURCE_MAP_BYTES_DIGEST_DOMAIN
);

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
    // This closed derive-generated shape has no floats, maps, flattening, or
    // custom serialization that could become lossy while constructing Value.
    let value = serde_json::to_value(&self.rows).map_err(|error| {
      OdenParentAllowlistError::CanonicalJson(error.to_string())
    })?;
    canonical_value_jcs(&value)
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
  entrypoint_source_digest: OdenParentEntrypointSourceDigest,
  release_contract_digest: CanonicalSha256Digest,
  source_closure_contract_digest: CanonicalSha256Digest,
  standalone_configuration_digest: CanonicalSha256Digest,
  static_import_edge_digest: CanonicalSha256Digest,
  synthetic_module_source_digest: OdenParentSyntheticModuleSourceDigest,
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
  entrypoint_source_digest: OdenParentEntrypointSourceDigest,
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
  synthetic_module_source_digest: OdenParentSyntheticModuleSourceDigest,
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
    // This closed derive-generated shape has no floats, maps, flattening, or
    // custom serialization that could become lossy while constructing Value.
    let value = serde_json::to_value(self).map_err(|error| {
      OdenParentAllowlistError::CanonicalJson(error.to_string())
    })?;
    canonical_value_jcs(&value)
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
  Ok(framed_sha256_digest(domain, canonical_jcs))
}

fn framed_sha256_digest(domain: &str, bytes: &[u8]) -> CanonicalSha256Digest {
  let mut hasher = Sha256::new();
  hasher.update(domain.as_bytes());
  hasher.update([0]);
  hasher.update(bytes);
  CanonicalSha256Digest(format!(
    "sha256-{}",
    URL_SAFE_NO_PAD.encode(hasher.finalize())
  ))
}

// This writer accepts only an already-validated JSON value and supplies RFC
// 8785's recursive UTF-16 member ordering and ECMAScript number rendering.
// Projection constructors enforce their narrower frozen field ranges. Raw
// artifact readers and any future typed projection with maps, floats,
// flattening, or custom serialization must reject duplicate keys and
// non-finite numbers before constructing Value; serde_json's generic typed
// conversion is not such a gate.
fn canonical_value_jcs(
  value: &serde_json::Value,
) -> Result<Vec<u8>, OdenParentAllowlistError> {
  let mut output = String::new();
  write_parent_jcs(value, &mut output)?;
  Ok(output.into_bytes())
}

fn write_parent_jcs(
  value: &serde_json::Value,
  output: &mut String,
) -> Result<(), OdenParentAllowlistError> {
  use serde_json::Value;

  match value {
    Value::Null => output.push_str("null"),
    Value::Bool(value) => {
      output.push_str(if *value { "true" } else { "false" })
    }
    Value::Number(value) => {
      if let Some(value) = value.as_i64() {
        if value.unsigned_abs() > MAX_IJSON_SAFE_INTEGER {
          return Err(OdenParentAllowlistError::InvalidIJsonNumber);
        }
        output.push_str(&value.to_string());
      } else if let Some(value) = value.as_u64() {
        if value > MAX_IJSON_SAFE_INTEGER {
          return Err(OdenParentAllowlistError::InvalidIJsonNumber);
        }
        output.push_str(&value.to_string());
      } else {
        let value = value
          .as_f64()
          .filter(|value| value.is_finite())
          .ok_or(OdenParentAllowlistError::InvalidIJsonNumber)?;
        output.push_str(ryu_js::Buffer::new().format_finite(value));
      }
    }
    Value::String(value) => {
      output.push_str(&serde_json::to_string(value).map_err(|error| {
        OdenParentAllowlistError::CanonicalJson(error.to_string())
      })?)
    }
    Value::Array(values) => {
      output.push('[');
      for (index, value) in values.iter().enumerate() {
        if index != 0 {
          output.push(',');
        }
        write_parent_jcs(value, output)?;
      }
      output.push(']');
    }
    Value::Object(object) => {
      output.push('{');
      let mut keys = object.keys().collect::<Vec<_>>();
      keys.sort_by(|left, right| left.encode_utf16().cmp(right.encode_utf16()));
      for (index, key) in keys.into_iter().enumerate() {
        if index != 0 {
          output.push(',');
        }
        output.push_str(&serde_json::to_string(key).map_err(|error| {
          OdenParentAllowlistError::CanonicalJson(error.to_string())
        })?);
        output.push(':');
        write_parent_jcs(&object[key], output)?;
      }
      output.push('}');
    }
  }
  Ok(())
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
      entrypoint_source_digest: OdenParentEntrypointSourceDigest(zero_digest(
        "entrypointSourceDigest",
      )),
      release_contract_digest: zero_digest("releaseContractDigest"),
      source_closure_contract_digest: zero_digest(
        "sourceClosureContractDigest",
      ),
      standalone_configuration_digest: zero_digest(
        "standaloneConfigurationDigest",
      ),
      static_import_edge_digest: zero_digest("staticImportEdgeDigest"),
      synthetic_module_source_digest: OdenParentSyntheticModuleSourceDigest(
        zero_digest("syntheticModuleSourceDigest"),
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
  fn hbytes_wrappers_bind_exact_raw_bytes_to_distinct_literal_domains() {
    let bytes = b"abc";
    let vectors = [
      (
        OdenParentEntrypointSourceDigest::from_bytes(bytes)
          .as_str()
          .to_string(),
        "sha256-Gz80-ugkSnF9eX_ClTKpFACYBemRqjY3agHjlIxdtBk",
      ),
      (
        OdenParentSyntheticModuleSourceDigest::from_bytes(bytes)
          .as_str()
          .to_string(),
        "sha256-BO7B__WMBq831KL6Xpd0uNBG9yYG3o5KbS7KLe1LeFA",
      ),
      (
        OdenParentVfsOriginalBytesDigest::from_bytes(bytes)
          .as_str()
          .to_string(),
        "sha256-Xa9ES5m9VrGE5rvE9rqtIXNgaKE7xBh7GWag5b2fCOQ",
      ),
      (
        OdenParentVfsEmittedBytesDigest::from_bytes(bytes)
          .as_str()
          .to_string(),
        "sha256-f96yONRjpIVsMqCulsTZmpUxEgwM5ndvVHiKh8ml13w",
      ),
      (
        OdenParentVfsSourceMapBytesDigest::from_bytes(bytes)
          .as_str()
          .to_string(),
        "sha256-PeoQea76eSnl2DojUMCEd4CgzXAAgdf2NBQncr9t1S4",
      ),
    ];
    for (actual, expected) in &vectors {
      assert_eq!(actual.as_str(), *expected);
    }
    let digests = vectors
      .iter()
      .map(|(actual, _)| actual)
      .collect::<std::collections::HashSet<_>>();
    assert_eq!(digests.len(), vectors.len());
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

  #[test]
  fn nested_jcs_uses_utf16_key_order_and_ecmascript_numbers() {
    let value = serde_json::json!({
      "\u{e000}": {"z": 1, "a": true},
      "😀": "supplementary",
      "€": "euro",
      "ö": "o-diaeresis",
      "1": "one",
      "\r": "carriage-return",
    });
    assert_eq!(
      canonical_value_jcs(&value).unwrap(),
      "{\"\\r\":\"carriage-return\",\"1\":\"one\",\"ö\":\"o-diaeresis\",\"€\":\"euro\",\"😀\":\"supplementary\",\"\u{e000}\":{\"a\":true,\"z\":1}}"
        .as_bytes()
    );

    let string = "\"\\\u{0008}\t\n\u{000c}\r\u{0000}\u{2028}\u{2029}😀";
    assert_eq!(
      canonical_value_jcs(&serde_json::json!([string, 3, 1, 2])).unwrap(),
      "[\"\\\"\\\\\\b\\t\\n\\f\\r\\u0000\u{2028}\u{2029}😀\",3,1,2]".as_bytes()
    );

    assert_eq!(
      canonical_value_jcs(&serde_json::json!([
        333333333.33333329,
        1E30,
        4.50,
        2e-3,
        0.000000000000000000000000001,
        -0.0,
        -1,
      ]))
      .unwrap(),
      "[333333333.3333333,1e+30,4.5,0.002,1e-27,0,-1]".as_bytes()
    );
    for value in [
      serde_json::json!(9_007_199_254_740_992_u64),
      serde_json::json!(-9_007_199_254_740_992_i64),
    ] {
      assert_eq!(
        canonical_value_jcs(&value),
        Err(OdenParentAllowlistError::InvalidIJsonNumber)
      );
    }
    assert_eq!(
      canonical_value_jcs(&serde_json::json!(MAX_IJSON_SAFE_INTEGER)).unwrap(),
      MAX_IJSON_SAFE_INTEGER.to_string().as_bytes()
    );
    assert_eq!(
      canonical_value_jcs(&serde_json::json!(-9_007_199_254_740_991_i64))
        .unwrap(),
      b"-9007199254740991"
    );
  }
}

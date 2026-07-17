// Copyright 2018-2026 the Deno authors. MIT license.

// @ref LLP 0019#frozen-parent-standalone-allowlist-and-byte-graph [implements] —
// This fail-closed slice keeps the reviewed contract inventories and parent-
// allowlist construction/rendering as exact raw-byte and domain-separated
// canonical-JSON projections. The constructor is pure and derives every digest
// from typed inputs; compiler adapters, generator execution, startup
// recomputation, generated outputs, and later image/evidence authority remain
// absent.

use std::ffi::OsStr;
use std::ffi::OsString;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use deno_runtime::deno_node::is_builtin_node_module;
use deno_runtime::deno_telemetry::OtelConfig;
use deno_runtime::deno_telemetry::OtelConsoleConfig;
use deno_semver::jsr::JsrPackageNvReference;
use deno_semver::jsr::JsrPackageReqReference;
use serde::Serialize;
use sha2::Digest as _;
use sha2::Sha256;
use thiserror::Error;

use crate::args::UnstableConfig;
use crate::standalone::binary::SerializedWorkspaceResolver;

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
pub const ODEN_PARENT_STANDALONE_CONFIGURATION_SCHEMA: &str =
  "oden/capsec-filesystem-parent-standalone-configuration/2";
pub const ODEN_PARENT_STANDALONE_CONFIGURATION_DIGEST_DOMAIN: &str =
  "oden:capsec:filesystem-parent-standalone-configuration:2";
pub const ODEN_PARENT_WORKSPACE_RESOLVER_DIGEST_DOMAIN: &str =
  "oden:capsec:filesystem-parent-workspace-resolver:2";
pub const ODEN_PARENT_UNSTABLE_CONFIG_DIGEST_DOMAIN: &str =
  "oden:capsec:filesystem-parent-unstable-config:2";
pub const ODEN_PARENT_OTEL_CONFIG_DIGEST_DOMAIN: &str =
  "oden:capsec:filesystem-parent-otel-config:2";
pub const ODEN_PARENT_VFS_GRAPH_SCHEMA: &str =
  "oden/capsec-filesystem-parent-vfs-graph/2";
pub const ODEN_PARENT_VFS_GRAPH_DIGEST_DOMAIN: &str =
  "oden:capsec:filesystem-parent-vfs-graph:2";
pub const ODEN_PARENT_IMPORT_ATTRIBUTES_DIGEST_DOMAIN: &str =
  "oden:capsec:filesystem-parent-import-attributes:2";
pub const ODEN_PARENT_STATIC_IMPORT_EDGE_SCHEMA: &str =
  "oden/capsec-filesystem-parent-static-import-edge/2";
pub const ODEN_PARENT_STATIC_IMPORT_EDGE_DIGEST_DOMAIN: &str =
  "oden:capsec:filesystem-parent-static-import-edge:2";
pub const ODEN_PARENT_ENTRYPOINT_SOURCE_DIGEST_DOMAIN: &str =
  "oden:capsec:filesystem-parent-entrypoint-source:2";
pub const ODEN_PARENT_SYNTHETIC_MODULE_SOURCE_DIGEST_DOMAIN: &str =
  "oden:capsec:filesystem-parent-synthetic-module-source:2";
pub const ODEN_PARENT_MODULE_SOURCE_BYTES_DIGEST_DOMAIN: &str =
  "oden:capsec:filesystem-parent-module-source-bytes:2";
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
// @ref LLP 0019#frozen-parent-standalone-allowlist-and-byte-graph [implements] —
// Freeze the reviewed V8 brand-slot identifier.
pub const ODEN_PARENT_V8_BRAND_SLOT_ID: &str =
  "oden.filesystem-parent-capture-v8-brand/2";
// @ref LLP 0019#frozen-parent-standalone-allowlist-and-byte-graph [implements] —
// Freeze the reviewed snapshot-visible native-op symbol.
pub const ODEN_PARENT_NATIVE_OP_SYMBOL: &str =
  "op_oden_filesystem_parent_capture_v2";
// @ref LLP 0019#frozen-parent-standalone-allowlist-and-byte-graph [implements] —
// Retain the exact reviewed 288-byte source as its sole byte authority.
pub const ODEN_PARENT_SYNTHETIC_MODULE_SOURCE: &[u8; 288] =
  b"import { op_oden_filesystem_parent_capture_v2 } from \"ext:core/ops\";\n\
const brand = import.meta[\"oden.filesystem-parent-capture-v8-brand/2\"];\n\
delete import.meta[\"oden.filesystem-parent-capture-v8-brand/2\"];\n\
export default (request) => op_oden_filesystem_parent_capture_v2(brand, request);\n";
pub const ODEN_PARENT_PROFILE: &str = "oden/capsec/2";

pub const ODEN_PARENT_GENERATED_JSON_PATH: &str =
  "generated/capsec/rev2/filesystem-parent-standalone-allowlist.json";
pub const ODEN_PARENT_GENERATED_RUST_PATH: &str =
  "fork/deno/cli/lib/standalone/oden_parent_allowlist_generated.rs";
pub const ODEN_PARENT_TARGET_POLICY_GENERATED_RUST_PATH: &str =
  "fork/deno/cli/lib/standalone/oden_parent_target_policy_generated.rs";
pub const ODEN_PARENT_GENERATED_PATHS: [&str; 3] = [
  ODEN_PARENT_GENERATED_JSON_PATH,
  ODEN_PARENT_GENERATED_RUST_PATH,
  ODEN_PARENT_TARGET_POLICY_GENERATED_RUST_PATH,
];
pub const ODEN_PARENT_ALLOWLIST_REFUSAL_EXIT_CODE: i32 = 76;

const ODEN_PARENT_ALLOWLIST_RESERVED_PREFIX: &[u8; 29] =
  b"--_oden-parent-allowlist-mode";
const ODEN_PARENT_ALLOWLIST_GENERATE_ARG: &[u8] =
  b"--_oden-parent-allowlist-mode=generate";
const ODEN_PARENT_ALLOWLIST_CHECK_ARG: &[u8] =
  b"--_oden-parent-allowlist-mode=check";

// @ref LLP 0019#frozen-parent-standalone-allowlist-and-byte-graph [implements] —
// Classify the unmodified native argv units before any general CLI or Oden/Deno
// initialization. Exact mode vectors remain fail-closed at their entrypoints
// until the separately frozen handler and admission authority are implemented.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OdenParentAllowlistRawDispatch {
  Absent,
  Generate,
  Check,
  Refuse,
}

pub fn classify_oden_parent_allowlist_raw_argv(
  args: &[OsString],
) -> OdenParentAllowlistRawDispatch {
  if args.len() == 3 && os_str_eq_ascii(&args[1], b"compile") {
    if os_str_eq_ascii(&args[2], ODEN_PARENT_ALLOWLIST_GENERATE_ARG) {
      return OdenParentAllowlistRawDispatch::Generate;
    }
    if os_str_eq_ascii(&args[2], ODEN_PARENT_ALLOWLIST_CHECK_ARG) {
      return OdenParentAllowlistRawDispatch::Check;
    }
  }

  if args
    .iter()
    .skip(1)
    .any(|arg| os_str_is_oden_parent_allowlist_reserved_family(arg))
  {
    OdenParentAllowlistRawDispatch::Refuse
  } else {
    OdenParentAllowlistRawDispatch::Absent
  }
}

#[cfg(unix)]
fn os_str_eq_ascii(value: &OsStr, expected: &[u8]) -> bool {
  use std::os::unix::ffi::OsStrExt;

  value.as_bytes() == expected
}

#[cfg(windows)]
fn os_str_eq_ascii(value: &OsStr, expected: &[u8]) -> bool {
  use std::os::windows::ffi::OsStrExt;

  value
    .encode_wide()
    .eq(expected.iter().copied().map(u16::from))
}

#[cfg(unix)]
fn os_str_is_oden_parent_allowlist_reserved_family(value: &OsStr) -> bool {
  use std::os::unix::ffi::OsStrExt;

  let units = value.as_bytes();
  units.len() >= ODEN_PARENT_ALLOWLIST_RESERVED_PREFIX.len()
    && units
      .iter()
      .take(ODEN_PARENT_ALLOWLIST_RESERVED_PREFIX.len())
      .zip(ODEN_PARENT_ALLOWLIST_RESERVED_PREFIX)
      .all(|(&actual, &expected)| actual.to_ascii_lowercase() == expected)
}

#[cfg(windows)]
fn os_str_is_oden_parent_allowlist_reserved_family(value: &OsStr) -> bool {
  use std::os::windows::ffi::OsStrExt;

  let mut units = value.encode_wide();
  ODEN_PARENT_ALLOWLIST_RESERVED_PREFIX
    .iter()
    .copied()
    .all(|expected| {
      units.next().is_some_and(|actual| {
        let folded = if actual >= u16::from(b'A') && actual <= u16::from(b'Z') {
          actual + u16::from(b'a' - b'A')
        } else {
          actual
        };
        folded == u16::from(expected)
      })
    })
}

const MAX_IJSON_SAFE_INTEGER: u64 = 9_007_199_254_740_991;
const ODEN_PARENT_REPOSITORY_RELATIVE_PATH_MAX_BYTES: usize = 4_096;
const ODEN_PARENT_REPOSITORY_RELATIVE_COMPONENT_MAX_BYTES: usize = 255;

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
  #[error("parent unstable configuration is not exactly all-disabled")]
  NonDefaultUnstableConfig,
  #[error("parent OTEL configuration is not exactly all-disabled")]
  NonDefaultOtelConfig,
  #[error("duplicate decoded import-attribute key: {0}")]
  DuplicateImportAttribute(String),
  #[error("invalid parent static import edge: {0}")]
  InvalidStaticImportEdge(&'static str),
  #[error("inconsistent parent allowlist inputs: {0}")]
  InconsistentAllowlistInputs(&'static str),
  #[error("invalid parent VFS {role} key: {key}")]
  InvalidVfsKey { role: &'static str, key: String },
  #[error("invalid parent VFS module {key}: {reason}")]
  InvalidVfsModule { key: String, reason: &'static str },
  #[error("invalid parent VFS dependency in {module}: {reason}")]
  InvalidVfsDependency {
    module: String,
    reason: &'static str,
  },
  #[error("duplicate parent VFS {collection} key: {key}")]
  DuplicateVfsKey {
    collection: &'static str,
    key: String,
  },
  #[error("parent VFS key occurs as both a module and file: {0}")]
  AmbiguousVfsKey(String),
  #[error(
    "duplicate parent VFS dependency coordinates in {module}: {source_byte_start}..{source_byte_end}"
  )]
  DuplicateVfsDependencyCoordinates {
    module: String,
    source_byte_start: u64,
    source_byte_end: u64,
  },
  #[error("parent VFS entrypoint module is missing")]
  MissingVfsEntrypoint,
  #[error("unresolved parent VFS dependency from {module}: {resolved_key}")]
  UnresolvedVfsDependency {
    module: String,
    resolved_key: String,
  },
  #[error("unreachable parent VFS module: {0}")]
  UnreachableVfsModule(String),
  #[error("unreachable parent VFS file: {0}")]
  UnreachableVfsFile(String),
  #[error("invalid parent VFS private edge: {0}")]
  InvalidVfsPrivateEdge(&'static str),
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
macro_rules! define_frozen_source_hbytes_digest {
  ($name:ident, $domain:ident) => {
    #[derive(Clone, Debug, PartialEq, Eq, Serialize)]
    #[serde(transparent)]
    pub struct $name(CanonicalSha256Digest);

    impl $name {
      pub fn from_frozen_source() -> Self {
        Self(framed_sha256_digest(
          $domain,
          ODEN_PARENT_SYNTHETIC_MODULE_SOURCE,
        ))
      }

      #[cfg(test)]
      fn from_test_bytes(bytes: &[u8]) -> Self {
        Self(framed_sha256_digest($domain, bytes))
      }

      pub fn as_str(&self) -> &str {
        self.0.as_str()
      }
    }
  };
}

define_frozen_source_hbytes_digest!(
  OdenParentSyntheticModuleSourceDigest,
  ODEN_PARENT_SYNTHETIC_MODULE_SOURCE_DIGEST_DOMAIN
);
define_frozen_source_hbytes_digest!(
  OdenParentModuleSourceBytesDigest,
  ODEN_PARENT_MODULE_SOURCE_BYTES_DIGEST_DOMAIN
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

macro_rules! define_hjcs_digest_type {
  ($name:ident) => {
    #[derive(Clone, Debug, PartialEq, Eq, Serialize)]
    #[serde(transparent)]
    pub struct $name(CanonicalSha256Digest);

    impl $name {
      pub fn as_str(&self) -> &str {
        self.0.as_str()
      }
    }
  };
}

define_hjcs_digest_type!(OdenParentStandaloneConfigurationDigest);
define_hjcs_digest_type!(OdenParentWorkspaceResolverDigest);
define_hjcs_digest_type!(OdenParentUnstableConfigDigest);
define_hjcs_digest_type!(OdenParentOtelConfigDigest);
define_hjcs_digest_type!(OdenParentImportAttributesDigest);
define_hjcs_digest_type!(OdenParentStaticImportEdgeDigest);
define_hjcs_digest_type!(OdenParentVfsGraphDigest);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum OdenParentVfsMediaType {
  TypeScript,
  JavaScript,
  Json,
  Wasm,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub enum OdenParentVfsDependencyKind {
  #[serde(rename = "static-import")]
  StaticImport,
  #[serde(rename = "static-export")]
  StaticExport,
  #[serde(rename = "dynamic-import")]
  DynamicImport,
}

impl OdenParentVfsDependencyKind {
  fn as_serialized_str(self) -> &'static str {
    match self {
      Self::StaticImport => "static-import",
      Self::StaticExport => "static-export",
      Self::DynamicImport => "dynamic-import",
    }
  }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OdenParentObservedImportAttribute<'a> {
  pub key: &'a str,
  pub value: &'a str,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct OdenParentImportAttributes(
  serde_json::Map<String, serde_json::Value>,
);

impl OdenParentImportAttributes {
  /// Consumes direct, decoded strict-AST observations while duplicate keys are
  /// still visible. A parser-produced map or generic JSON object is ineligible
  /// because either may already have overwritten a duplicate decoded key. The
  /// adapter must refuse unknown attribute sets or values rather than omit or
  /// map them to an empty object.
  pub fn from_observed_pairs(
    attributes: &[OdenParentObservedImportAttribute<'_>],
  ) -> Result<Self, OdenParentAllowlistError> {
    let mut object = serde_json::Map::new();
    for attribute in attributes {
      if object
        .insert(
          attribute.key.to_string(),
          serde_json::Value::String(attribute.value.to_string()),
        )
        .is_some()
      {
        return Err(OdenParentAllowlistError::DuplicateImportAttribute(
          attribute.key.to_string(),
        ));
      }
    }
    Ok(Self(object))
  }

  pub fn canonical_jcs(&self) -> Result<Vec<u8>, OdenParentAllowlistError> {
    canonical_value_jcs(&serde_json::Value::Object(self.0.clone()))
  }

  pub fn digest(
    &self,
  ) -> Result<OdenParentImportAttributesDigest, OdenParentAllowlistError> {
    Ok(OdenParentImportAttributesDigest(hjcs_digest(
      ODEN_PARENT_IMPORT_ATTRIBUTES_DIGEST_DOMAIN,
      &self.canonical_jcs()?,
    )?))
  }
}

#[derive(Clone, Copy, Debug)]
pub struct OdenParentVfsDependencyObservation<'a> {
  pub kind: OdenParentVfsDependencyKind,
  pub raw_specifier: &'a str,
  pub resolved_key: &'a str,
  pub source_byte_start: u64,
  pub source_byte_end: u64,
  pub import_attributes: &'a [OdenParentObservedImportAttribute<'a>],
}

#[derive(Clone, Copy, Debug)]
pub struct OdenParentVfsModuleObservation<'a> {
  pub key: &'a str,
  pub media_type: OdenParentVfsMediaType,
  pub original_bytes: &'a [u8],
  pub emitted_bytes: &'a [u8],
  pub source_map_bytes: Option<&'a [u8]>,
  pub dependencies: &'a [OdenParentVfsDependencyObservation<'a>],
}

#[derive(Clone, Copy, Debug)]
pub struct OdenParentVfsFileObservation<'a> {
  pub key: &'a str,
  pub executable: bool,
  pub original_bytes: &'a [u8],
  pub emitted_bytes: &'a [u8],
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct OdenParentVfsDependencyRow {
  import_attributes_digest: OdenParentImportAttributesDigest,
  kind: OdenParentVfsDependencyKind,
  raw_specifier: String,
  resolved_key: String,
  source_byte_end: u64,
  source_byte_start: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct OdenParentVfsModuleRow {
  dependencies: Vec<OdenParentVfsDependencyRow>,
  emitted_byte_digest: OdenParentVfsEmittedBytesDigest,
  key: String,
  media_type: OdenParentVfsMediaType,
  original_byte_digest: OdenParentVfsOriginalBytesDigest,
  source_map_digest: Option<OdenParentVfsSourceMapBytesDigest>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
struct OdenParentVfsFileRow {
  emitted_byte_digest: OdenParentVfsEmittedBytesDigest,
  executable: bool,
  key: String,
  kind: &'static str,
  original_byte_digest: OdenParentVfsOriginalBytesDigest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OdenParentVfsGraph {
  entrypoint_key: &'static str,
  files: Vec<OdenParentVfsFileRow>,
  modules: Vec<OdenParentVfsModuleRow>,
  schema: &'static str,
}

impl OdenParentVfsGraph {
  /// Projects caller-independent digest rows from exact observed byte slices.
  /// The compiler adapter remains responsible for proving that observations
  /// came from the pinned parser, resolver, lock, and serialized stores; this
  /// constructor cannot authenticate that provenance merely from copied
  /// values.
  pub fn from_observations(
    modules: &[OdenParentVfsModuleObservation<'_>],
    files: &[OdenParentVfsFileObservation<'_>],
  ) -> Result<Self, OdenParentAllowlistError> {
    let mut module_rows = modules
      .iter()
      .map(project_vfs_module)
      .collect::<Result<Vec<_>, _>>()?;
    let mut file_rows = files
      .iter()
      .map(project_vfs_file)
      .collect::<Result<Vec<_>, _>>()?;

    module_rows
      .sort_by(|left, right| left.key.as_bytes().cmp(right.key.as_bytes()));
    file_rows
      .sort_by(|left, right| left.key.as_bytes().cmp(right.key.as_bytes()));
    refuse_duplicate_vfs_keys(
      module_rows.iter().map(|row| row.key.as_str()),
      "module",
    )?;
    refuse_duplicate_vfs_keys(
      file_rows.iter().map(|row| row.key.as_str()),
      "file",
    )?;
    refuse_ambiguous_vfs_keys(&module_rows, &file_rows)?;
    validate_vfs_graph_links(&module_rows, &file_rows)?;

    Ok(Self {
      entrypoint_key: ODEN_PARENT_ENTRYPOINT_KEY,
      files: file_rows,
      modules: module_rows,
      schema: ODEN_PARENT_VFS_GRAPH_SCHEMA,
    })
  }

  fn require_static_import_edge(
    &self,
    edge: &OdenParentStaticImportEdge,
  ) -> Result<(), OdenParentAllowlistError> {
    let inconsistent = || {
      OdenParentAllowlistError::InconsistentAllowlistInputs(
        "static edge does not equal the VFS entrypoint private dependency",
      )
    };
    let entrypoint_index =
      vfs_module_index(&self.modules, ODEN_PARENT_ENTRYPOINT_KEY)
        .ok_or_else(inconsistent)?;
    let entrypoint = &self.modules[entrypoint_index];
    let dependency =
      entrypoint.dependencies.first().ok_or_else(inconsistent)?;
    if entrypoint.original_byte_digest
      != edge.entrypoint_vfs_original_byte_digest
      || edge.dependency_ordinal != 0
      || edge.occurrence_count != 1
      || dependency.kind != edge.kind
      || dependency.raw_specifier != edge.raw_specifier
      || dependency.resolved_key != edge.resolved_specifier
      || dependency.source_byte_start != edge.source_byte_start
      || dependency.source_byte_end != edge.source_byte_end
      || dependency.import_attributes_digest
        != edge.import_attributes.digest()?
    {
      return Err(inconsistent());
    }
    Ok(())
  }

  pub fn canonical_jcs(&self) -> Result<Vec<u8>, OdenParentAllowlistError> {
    // Projection rows are closed derive-generated shapes. The only dynamic
    // object, import attributes, has already been reduced to its typed digest.
    let value = serde_json::to_value(self).map_err(|error| {
      OdenParentAllowlistError::CanonicalJson(error.to_string())
    })?;
    canonical_value_jcs(&value)
  }

  pub fn digest(
    &self,
  ) -> Result<OdenParentVfsGraphDigest, OdenParentAllowlistError> {
    Ok(OdenParentVfsGraphDigest(hjcs_digest(
      ODEN_PARENT_VFS_GRAPH_DIGEST_DOMAIN,
      &self.canonical_jcs()?,
    )?))
  }
}

fn project_vfs_module(
  observation: &OdenParentVfsModuleObservation<'_>,
) -> Result<OdenParentVfsModuleRow, OdenParentAllowlistError> {
  validate_vfs_module_key(observation.key)?;
  if observation.key == ODEN_PARENT_ENTRYPOINT_KEY
    && observation.media_type != OdenParentVfsMediaType::TypeScript
  {
    return Err(OdenParentAllowlistError::InvalidVfsModule {
      key: observation.key.to_string(),
      reason: "entrypoint media type is not TypeScript",
    });
  }
  if observation.media_type != OdenParentVfsMediaType::Wasm
    && std::str::from_utf8(observation.original_bytes).is_err()
  {
    return Err(OdenParentAllowlistError::InvalidVfsModule {
      key: observation.key.to_string(),
      reason: "textual original bytes are not UTF-8",
    });
  }
  if matches!(
    observation.media_type,
    OdenParentVfsMediaType::Json | OdenParentVfsMediaType::Wasm
  ) && !observation.dependencies.is_empty()
  {
    return Err(OdenParentAllowlistError::InvalidVfsModule {
      key: observation.key.to_string(),
      reason: "Json and Wasm modules cannot contain dependency rows",
    });
  }

  let mut dependencies = observation
    .dependencies
    .iter()
    .map(|dependency| {
      project_vfs_dependency(
        observation.key,
        observation.original_bytes,
        dependency,
      )
    })
    .collect::<Result<Vec<_>, _>>()?;
  dependencies.sort_by(compare_vfs_dependencies);
  for pair in dependencies.windows(2) {
    if pair[0].source_byte_start == pair[1].source_byte_start
      && pair[0].source_byte_end == pair[1].source_byte_end
    {
      return Err(
        OdenParentAllowlistError::DuplicateVfsDependencyCoordinates {
          module: observation.key.to_string(),
          source_byte_start: pair[1].source_byte_start,
          source_byte_end: pair[1].source_byte_end,
        },
      );
    }
  }

  Ok(OdenParentVfsModuleRow {
    dependencies,
    emitted_byte_digest: OdenParentVfsEmittedBytesDigest::from_bytes(
      observation.emitted_bytes,
    ),
    key: observation.key.to_string(),
    media_type: observation.media_type,
    original_byte_digest: OdenParentVfsOriginalBytesDigest::from_bytes(
      observation.original_bytes,
    ),
    source_map_digest: observation
      .source_map_bytes
      .map(OdenParentVfsSourceMapBytesDigest::from_bytes),
  })
}

fn project_vfs_dependency(
  module_key: &str,
  original_bytes: &[u8],
  observation: &OdenParentVfsDependencyObservation<'_>,
) -> Result<OdenParentVfsDependencyRow, OdenParentAllowlistError> {
  if observation.raw_specifier.is_empty()
    || observation.raw_specifier.contains('\0')
  {
    return Err(OdenParentAllowlistError::InvalidVfsDependency {
      module: module_key.to_string(),
      reason: "raw specifier is empty or contains NUL",
    });
  }
  validate_vfs_dependency_key(observation.resolved_key)?;
  validate_vfs_raw_resolved_relationship(module_key, observation)?;
  validate_vfs_dependency_range(module_key, original_bytes, observation)?;
  let import_attributes = OdenParentImportAttributes::from_observed_pairs(
    observation.import_attributes,
  )?;

  Ok(OdenParentVfsDependencyRow {
    import_attributes_digest: import_attributes.digest()?,
    kind: observation.kind,
    raw_specifier: observation.raw_specifier.to_string(),
    resolved_key: observation.resolved_key.to_string(),
    source_byte_end: observation.source_byte_end,
    source_byte_start: observation.source_byte_start,
  })
}

fn validate_vfs_raw_resolved_relationship(
  module_key: &str,
  observation: &OdenParentVfsDependencyObservation<'_>,
) -> Result<(), OdenParentAllowlistError> {
  let invalid = |reason| OdenParentAllowlistError::InvalidVfsDependency {
    module: module_key.to_string(),
    reason,
  };
  let raw = observation.raw_specifier;

  if raw == ODEN_PARENT_PRIVATE_MODULE_SPECIFIER
    || observation.resolved_key == ODEN_PARENT_PRIVATE_MODULE_SPECIFIER
  {
    if module_key != ODEN_PARENT_ENTRYPOINT_KEY
      || observation.kind != OdenParentVfsDependencyKind::StaticImport
      || raw != ODEN_PARENT_PRIVATE_MODULE_SPECIFIER
      || observation.resolved_key != ODEN_PARENT_PRIVATE_MODULE_SPECIFIER
      || !observation.import_attributes.is_empty()
    {
      return Err(invalid(
        "private edge is not the exact entrypoint static import",
      ));
    }
    return Ok(());
  }

  if raw.starts_with("node:") || observation.resolved_key.starts_with("node:") {
    if raw != observation.resolved_key || !validate_node_vfs_key(raw) {
      return Err(invalid(
        "node builtin raw and resolved specifiers are not identical",
      ));
    }
    return Ok(());
  }

  if raw.starts_with("jsr:") {
    if !validate_jsr_raw_resolved_relationship(raw, observation.resolved_key) {
      return Err(invalid(
        "JSR request and exact resolved key are not a matching canonical package/version pair",
      ));
    }
    return Ok(());
  }

  if has_explicit_specifier_scheme(raw) {
    return Err(invalid(
      "raw specifier uses a forbidden or unknown explicit scheme",
    ));
  }
  Ok(())
}

fn has_explicit_specifier_scheme(specifier: &str) -> bool {
  let Some(colon) = specifier.find(':') else {
    return false;
  };
  let scheme = &specifier[..colon];
  let mut bytes = scheme.bytes();
  matches!(bytes.next(), Some(first) if first.is_ascii_alphabetic())
    && bytes.all(|byte| {
      byte.is_ascii_alphanumeric() || matches!(byte, b'+' | b'-' | b'.')
    })
}

fn validate_vfs_dependency_range(
  module_key: &str,
  original_bytes: &[u8],
  observation: &OdenParentVfsDependencyObservation<'_>,
) -> Result<(), OdenParentAllowlistError> {
  let invalid = |reason| OdenParentAllowlistError::InvalidVfsDependency {
    module: module_key.to_string(),
    reason,
  };
  if observation.source_byte_start > MAX_IJSON_SAFE_INTEGER
    || observation.source_byte_end > MAX_IJSON_SAFE_INTEGER
    || observation.source_byte_end <= observation.source_byte_start
  {
    return Err(invalid(
      "source byte range is not a nonempty safe-integer range",
    ));
  }
  let start = usize::try_from(observation.source_byte_start)
    .map_err(|_| invalid("source byte start does not fit usize"))?;
  let end = usize::try_from(observation.source_byte_end)
    .map_err(|_| invalid("source byte end does not fit usize"))?;
  if start == 0 || end >= original_bytes.len() {
    return Err(invalid(
      "source byte range is out of bounds or lacks adjacent delimiters",
    ));
  }
  let payload = &original_bytes[start..end];
  if payload != observation.raw_specifier.as_bytes() {
    return Err(invalid(
      "source byte range does not equal the raw specifier",
    ));
  }
  let opening = original_bytes[start - 1];
  let closing = original_bytes[end];
  if opening != closing || !matches!(opening, b'\'' | b'"' | b'`') {
    return Err(invalid(
      "source byte range is not payload-only between matching delimiters",
    ));
  }
  if payload.contains(&opening) {
    return Err(invalid(
      "module specifier payload contains its unescaped delimiter",
    ));
  }
  if payload.contains(&b'\\') {
    return Err(invalid("module specifier payload contains an escape"));
  }
  if opening == b'`' && payload.windows(2).any(|window| window == b"${") {
    return Err(invalid("template module specifier contains interpolation"));
  }
  Ok(())
}

fn compare_vfs_dependencies(
  left: &OdenParentVfsDependencyRow,
  right: &OdenParentVfsDependencyRow,
) -> std::cmp::Ordering {
  left
    .source_byte_start
    .cmp(&right.source_byte_start)
    .then_with(|| left.source_byte_end.cmp(&right.source_byte_end))
    // `kind` is a string-valued tuple component, so compare its serialized raw
    // bytes: dynamic-import < static-export < static-import.
    .then_with(|| {
      left
        .kind
        .as_serialized_str()
        .as_bytes()
        .cmp(right.kind.as_serialized_str().as_bytes())
    })
    .then_with(|| {
      left
        .raw_specifier
        .as_bytes()
        .cmp(right.raw_specifier.as_bytes())
    })
    .then_with(|| {
      left
        .resolved_key
        .as_bytes()
        .cmp(right.resolved_key.as_bytes())
    })
}

fn project_vfs_file(
  observation: &OdenParentVfsFileObservation<'_>,
) -> Result<OdenParentVfsFileRow, OdenParentAllowlistError> {
  validate_vfs_file_key(observation.key)?;
  Ok(OdenParentVfsFileRow {
    emitted_byte_digest: OdenParentVfsEmittedBytesDigest::from_bytes(
      observation.emitted_bytes,
    ),
    executable: observation.executable,
    key: observation.key.to_string(),
    kind: "file",
    original_byte_digest: OdenParentVfsOriginalBytesDigest::from_bytes(
      observation.original_bytes,
    ),
  })
}

fn refuse_duplicate_vfs_keys<'a>(
  keys: impl Iterator<Item = &'a str>,
  collection: &'static str,
) -> Result<(), OdenParentAllowlistError> {
  let mut previous: Option<&str> = None;
  for key in keys {
    if previous == Some(key) {
      return Err(OdenParentAllowlistError::DuplicateVfsKey {
        collection,
        key: key.to_string(),
      });
    }
    previous = Some(key);
  }
  Ok(())
}

fn refuse_ambiguous_vfs_keys(
  modules: &[OdenParentVfsModuleRow],
  files: &[OdenParentVfsFileRow],
) -> Result<(), OdenParentAllowlistError> {
  let mut module_index = 0;
  let mut file_index = 0;
  while module_index < modules.len() && file_index < files.len() {
    match modules[module_index]
      .key
      .as_bytes()
      .cmp(files[file_index].key.as_bytes())
    {
      std::cmp::Ordering::Less => module_index += 1,
      std::cmp::Ordering::Greater => file_index += 1,
      std::cmp::Ordering::Equal => {
        return Err(OdenParentAllowlistError::AmbiguousVfsKey(
          modules[module_index].key.clone(),
        ));
      }
    }
  }
  Ok(())
}

fn validate_vfs_graph_links(
  modules: &[OdenParentVfsModuleRow],
  files: &[OdenParentVfsFileRow],
) -> Result<(), OdenParentAllowlistError> {
  let entrypoint_index = vfs_module_index(modules, ODEN_PARENT_ENTRYPOINT_KEY)
    .ok_or(OdenParentAllowlistError::MissingVfsEntrypoint)?;

  for module in modules {
    for dependency in &module.dependencies {
      if is_terminal_vfs_dependency_key(&dependency.resolved_key) {
        continue;
      }
      if vfs_module_index(modules, &dependency.resolved_key).is_none()
        && vfs_file_index(files, &dependency.resolved_key).is_none()
      {
        return Err(OdenParentAllowlistError::UnresolvedVfsDependency {
          module: module.key.clone(),
          resolved_key: dependency.resolved_key.clone(),
        });
      }
    }
  }

  let mut reachable_modules = vec![false; modules.len()];
  let mut reachable_files = vec![false; files.len()];
  let mut pending = vec![entrypoint_index];
  while let Some(module_index) = pending.pop() {
    if std::mem::replace(&mut reachable_modules[module_index], true) {
      continue;
    }
    for dependency in &modules[module_index].dependencies {
      if let Some(dependency_index) =
        vfs_module_index(modules, &dependency.resolved_key)
        && !reachable_modules[dependency_index]
      {
        pending.push(dependency_index);
      } else if let Some(file_index) =
        vfs_file_index(files, &dependency.resolved_key)
      {
        reachable_files[file_index] = true;
      }
    }
  }
  if let Some((_, module)) = reachable_modules
    .iter()
    .zip(modules)
    .find(|(reachable, _)| !**reachable)
  {
    return Err(OdenParentAllowlistError::UnreachableVfsModule(
      module.key.clone(),
    ));
  }
  if let Some((_, file)) = reachable_files
    .iter()
    .zip(files)
    .find(|(reachable, _)| !**reachable)
  {
    return Err(OdenParentAllowlistError::UnreachableVfsFile(
      file.key.clone(),
    ));
  }
  let private_edge_count = modules
    .iter()
    .flat_map(|module| &module.dependencies)
    .filter(|dependency| {
      dependency.resolved_key == ODEN_PARENT_PRIVATE_MODULE_SPECIFIER
    })
    .count();
  if private_edge_count != 1 {
    return Err(OdenParentAllowlistError::InvalidVfsPrivateEdge(
      "private edge does not occur exactly once",
    ));
  }
  if modules[entrypoint_index]
    .dependencies
    .first()
    .is_none_or(|dependency| {
      dependency.resolved_key != ODEN_PARENT_PRIVATE_MODULE_SPECIFIER
    })
  {
    return Err(OdenParentAllowlistError::InvalidVfsPrivateEdge(
      "private edge is not the entrypoint's first sorted dependency",
    ));
  }
  Ok(())
}

fn vfs_module_index(
  modules: &[OdenParentVfsModuleRow],
  key: &str,
) -> Option<usize> {
  modules
    .binary_search_by(|module| module.key.as_bytes().cmp(key.as_bytes()))
    .ok()
}

fn vfs_file_index(files: &[OdenParentVfsFileRow], key: &str) -> Option<usize> {
  files
    .binary_search_by(|file| file.key.as_bytes().cmp(key.as_bytes()))
    .ok()
}

fn is_terminal_vfs_dependency_key(key: &str) -> bool {
  key == ODEN_PARENT_PRIVATE_MODULE_SPECIFIER || key.starts_with("node:")
}

fn validate_vfs_module_key(key: &str) -> Result<(), OdenParentAllowlistError> {
  if validate_repo_vfs_key(key) || validate_jsr_vfs_key(key) {
    Ok(())
  } else {
    Err(invalid_vfs_key("module", key))
  }
}

fn validate_vfs_file_key(key: &str) -> Result<(), OdenParentAllowlistError> {
  if validate_repo_vfs_key(key) {
    Ok(())
  } else {
    Err(invalid_vfs_key("file", key))
  }
}

fn validate_vfs_dependency_key(
  key: &str,
) -> Result<(), OdenParentAllowlistError> {
  if key == ODEN_PARENT_PRIVATE_MODULE_SPECIFIER
    || validate_repo_vfs_key(key)
    || validate_jsr_vfs_key(key)
    || validate_node_vfs_key(key)
  {
    Ok(())
  } else {
    Err(invalid_vfs_key("dependency", key))
  }
}

fn invalid_vfs_key(role: &'static str, key: &str) -> OdenParentAllowlistError {
  OdenParentAllowlistError::InvalidVfsKey {
    role,
    key: key.to_string(),
  }
}

// @ref LLP 0019#frozen-parent-standalone-allowlist-and-byte-graph [implements] —
// Construct a repository VFS key only from the exact canonical retained-root-
// relative path grammar; callers cannot supply or preserve an alternate key
// prefix, percent encoding, or generated-output spelling.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct OdenParentRepoVfsKey(String);

impl OdenParentRepoVfsKey {
  pub fn from_repository_relative_path(
    path: &str,
  ) -> Result<Self, OdenParentAllowlistError> {
    validate_repository_relative_path(path)?;
    let key = format!("repo:{path}");
    if !validate_repo_vfs_key(&key) {
      return Err(invalid_vfs_key("repository", &key));
    }
    Ok(Self(key))
  }

  pub fn as_str(&self) -> &str {
    &self.0
  }
}

fn validate_repo_vfs_key(key: &str) -> bool {
  let Some(path) = key.strip_prefix("repo:") else {
    return false;
  };
  !path.contains('%')
    && !is_oden_parent_generated_path(path)
    && validate_repository_relative_path(path).is_ok()
}

fn is_oden_parent_generated_path(path: &str) -> bool {
  ODEN_PARENT_GENERATED_PATHS
    .iter()
    .any(|generated_path| path.eq_ignore_ascii_case(generated_path))
}

fn validate_jsr_vfs_key(key: &str) -> bool {
  if key.is_empty() || key.contains(['\0', '%']) {
    return false;
  }
  let Ok(reference) = JsrPackageNvReference::from_str(key) else {
    return false;
  };
  if reference.to_string() != key
    || !validate_jsr_package_name(reference.nv().name.as_str())
  {
    return false;
  }
  let Some(path) = reference.sub_path() else {
    return false;
  };
  !path.is_empty() && validate_repository_relative_path(path).is_ok()
}

fn validate_jsr_package_name(name: &str) -> bool {
  fn valid_component(component: &str) -> bool {
    !component.is_empty()
      && !matches!(component, "." | "..")
      && !component.contains(['@', '/', '\\', '\0', '%'])
      && component.bytes().all(|byte| {
        byte.is_ascii_lowercase()
          || byte.is_ascii_digit()
          || matches!(byte, b'-' | b'_' | b'.' | b'~')
      })
  }

  if let Some(scoped) = name.strip_prefix('@') {
    let mut components = scoped.split('/');
    let Some(scope) = components.next() else {
      return false;
    };
    let Some(package) = components.next() else {
      return false;
    };
    components.next().is_none()
      && valid_component(scope)
      && valid_component(package)
  } else {
    valid_component(name)
  }
}

fn validate_jsr_raw_specifier(specifier: &str) -> bool {
  if specifier.contains(['\0', '%']) {
    return false;
  }
  let Ok(reference) = JsrPackageReqReference::from_str(specifier) else {
    return false;
  };
  if reference.to_string() != specifier
    || !validate_jsr_package_name(reference.req().name.as_str())
    || reference.req().version_req.tag().is_some()
  {
    return false;
  }
  match reference.sub_path() {
    Some(path) => {
      !path.is_empty() && validate_repository_relative_path(path).is_ok()
    }
    None => true,
  }
}

fn validate_jsr_raw_resolved_relationship(raw: &str, resolved: &str) -> bool {
  if !validate_jsr_raw_specifier(raw) || !validate_jsr_vfs_key(resolved) {
    return false;
  }
  let Ok(request) = JsrPackageReqReference::from_str(raw) else {
    return false;
  };
  let Ok(exact) = JsrPackageNvReference::from_str(resolved) else {
    return false;
  };
  if request.req().name != exact.nv().name {
    return false;
  }
  if let Ok(raw_exact) = JsrPackageNvReference::from_str(raw)
    && raw_exact.to_string() == raw
  {
    return raw_exact.nv().version == exact.nv().version;
  }
  let version_req = &request.req().version_req;
  if version_req.version_text().contains('+') {
    return false;
  }
  version_req.matches(&exact.nv().version)
}

fn validate_node_vfs_key(key: &str) -> bool {
  let Some(module_name) = key.strip_prefix("node:") else {
    return false;
  };
  !module_name.is_empty()
    && !module_name.contains(['\0', '%'])
    && is_builtin_node_module(module_name)
}

#[derive(Clone, Copy, Debug)]
pub struct OdenParentStaticImportEdgeObservation<'a> {
  pub entrypoint_source_bytes: &'a [u8],
  pub dependency_ordinal: u64,
  pub occurrence_count: u64,
  pub kind: OdenParentVfsDependencyKind,
  pub raw_specifier: &'a str,
  pub resolved_specifier: &'a str,
  pub referrer_key: &'a str,
  pub import_attributes: &'a OdenParentImportAttributes,
  pub source_byte_start: u64,
  pub source_byte_end: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OdenParentStaticImportEdge {
  dependency_ordinal: u64,
  entrypoint_source_digest: OdenParentEntrypointSourceDigest,
  #[serde(skip_serializing)]
  entrypoint_vfs_original_byte_digest: OdenParentVfsOriginalBytesDigest,
  import_attributes: OdenParentImportAttributes,
  kind: OdenParentVfsDependencyKind,
  occurrence_count: u64,
  raw_specifier: &'static str,
  referrer_key: &'static str,
  resolved_specifier: &'static str,
  schema: &'static str,
  source_byte_end: u64,
  source_byte_start: u64,
  synthetic_module_source_digest: OdenParentSyntheticModuleSourceDigest,
}

impl OdenParentStaticImportEdge {
  /// Projects already-observed parser facts and the one frozen synthetic source.
  /// The observation accepts no synthetic-source bytes; that digest is derived
  /// only from [`ODEN_PARENT_SYNTHETIC_MODULE_SOURCE`]. This pure boundary does
  /// not prove parser ordinal/occurrence provenance or that a runtime registered
  /// and evaluated that source; those remain adapter/integration gates and
  /// cannot be replaced by this constructor succeeding.
  pub fn from_observation(
    observation: OdenParentStaticImportEdgeObservation<'_>,
  ) -> Result<Self, OdenParentAllowlistError> {
    if observation.dependency_ordinal != 0 {
      return Err(OdenParentAllowlistError::InvalidStaticImportEdge(
        "dependency ordinal is not zero",
      ));
    }
    if observation.occurrence_count != 1 {
      return Err(OdenParentAllowlistError::InvalidStaticImportEdge(
        "occurrence count is not one",
      ));
    }
    if observation.kind != OdenParentVfsDependencyKind::StaticImport {
      return Err(OdenParentAllowlistError::InvalidStaticImportEdge(
        "dependency kind is not static-import",
      ));
    }
    if observation.raw_specifier != ODEN_PARENT_PRIVATE_MODULE_SPECIFIER {
      return Err(OdenParentAllowlistError::InvalidStaticImportEdge(
        "raw specifier is not the private module",
      ));
    }
    if observation.resolved_specifier != ODEN_PARENT_PRIVATE_MODULE_SPECIFIER {
      return Err(OdenParentAllowlistError::InvalidStaticImportEdge(
        "resolved specifier is not the private module",
      ));
    }
    if observation.referrer_key != ODEN_PARENT_ENTRYPOINT_KEY {
      return Err(OdenParentAllowlistError::InvalidStaticImportEdge(
        "referrer is not the parent entrypoint",
      ));
    }
    if !observation.import_attributes.0.is_empty() {
      return Err(OdenParentAllowlistError::InvalidStaticImportEdge(
        "import attributes are not empty",
      ));
    }
    if observation
      .entrypoint_source_bytes
      .starts_with(b"\xef\xbb\xbf")
      || std::str::from_utf8(observation.entrypoint_source_bytes).is_err()
    {
      return Err(OdenParentAllowlistError::InvalidStaticImportEdge(
        "entrypoint source is not BOM-free UTF-8",
      ));
    }
    validate_static_import_edge_range(&observation)?;

    Ok(Self {
      dependency_ordinal: 0,
      entrypoint_source_digest: OdenParentEntrypointSourceDigest::from_bytes(
        observation.entrypoint_source_bytes,
      ),
      entrypoint_vfs_original_byte_digest:
        OdenParentVfsOriginalBytesDigest::from_bytes(
          observation.entrypoint_source_bytes,
        ),
      import_attributes: observation.import_attributes.clone(),
      kind: OdenParentVfsDependencyKind::StaticImport,
      occurrence_count: 1,
      raw_specifier: ODEN_PARENT_PRIVATE_MODULE_SPECIFIER,
      referrer_key: ODEN_PARENT_ENTRYPOINT_KEY,
      resolved_specifier: ODEN_PARENT_PRIVATE_MODULE_SPECIFIER,
      schema: ODEN_PARENT_STATIC_IMPORT_EDGE_SCHEMA,
      source_byte_end: observation.source_byte_end,
      source_byte_start: observation.source_byte_start,
      synthetic_module_source_digest:
        OdenParentSyntheticModuleSourceDigest::from_frozen_source(),
    })
  }

  pub fn canonical_jcs(&self) -> Result<Vec<u8>, OdenParentAllowlistError> {
    // The only map is the validated duplicate-free attributes object; all
    // remaining fields are closed derive-generated scalar projections.
    let value = serde_json::to_value(self).map_err(|error| {
      OdenParentAllowlistError::CanonicalJson(error.to_string())
    })?;
    canonical_value_jcs(&value)
  }

  pub fn digest(
    &self,
  ) -> Result<OdenParentStaticImportEdgeDigest, OdenParentAllowlistError> {
    Ok(OdenParentStaticImportEdgeDigest(hjcs_digest(
      ODEN_PARENT_STATIC_IMPORT_EDGE_DIGEST_DOMAIN,
      &self.canonical_jcs()?,
    )?))
  }
}

fn validate_static_import_edge_range(
  observation: &OdenParentStaticImportEdgeObservation<'_>,
) -> Result<(), OdenParentAllowlistError> {
  if observation.source_byte_start > MAX_IJSON_SAFE_INTEGER
    || observation.source_byte_end > MAX_IJSON_SAFE_INTEGER
    || observation.source_byte_end <= observation.source_byte_start
  {
    return Err(OdenParentAllowlistError::InvalidStaticImportEdge(
      "source byte range is not a nonempty safe-integer range",
    ));
  }
  let start = usize::try_from(observation.source_byte_start).map_err(|_| {
    OdenParentAllowlistError::InvalidStaticImportEdge(
      "source byte start does not fit usize",
    )
  })?;
  let end = usize::try_from(observation.source_byte_end).map_err(|_| {
    OdenParentAllowlistError::InvalidStaticImportEdge(
      "source byte end does not fit usize",
    )
  })?;
  let bytes = observation.entrypoint_source_bytes;
  if start == 0 || end >= bytes.len() {
    return Err(OdenParentAllowlistError::InvalidStaticImportEdge(
      "source byte range is out of bounds or lacks delimiters",
    ));
  }
  if &bytes[start..end] != observation.raw_specifier.as_bytes() {
    return Err(OdenParentAllowlistError::InvalidStaticImportEdge(
      "source byte range does not equal the raw specifier",
    ));
  }
  let opening = bytes[start - 1];
  let closing = bytes[end];
  if opening != closing || !matches!(opening, b'\'' | b'"' | b'`') {
    return Err(OdenParentAllowlistError::InvalidStaticImportEdge(
      "source byte range is not payload-only between matching delimiters",
    ));
  }
  Ok(())
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
      validate_repository_relative_path(file.path)?;
      if is_oden_parent_generated_path(file.path) {
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OdenParentStandaloneConfiguration {
  app_name: &'static str,
  app_version: Option<&'static str>,
  bundle: bool,
  ca_data_digest: Option<CanonicalSha256Digest>,
  ca_stores: Option<Vec<&'static str>>,
  cached_only: bool,
  certificate: Option<&'static str>,
  code_cache_enabled: bool,
  config_file: &'static str,
  cwd: &'static str,
  denort: &'static str,
  embedded_args: Vec<&'static str>,
  entrypoint_key: &'static str,
  env_files: Vec<&'static str>,
  error_reporting_url: Option<&'static str>,
  eszip: bool,
  exclude: Vec<&'static str>,
  exclude_unused_npm: bool,
  frozen: bool,
  icon: Option<&'static str>,
  ignored_tls_certificate_errors: Vec<&'static str>,
  import_map_override: Option<&'static str>,
  include: Vec<&'static str>,
  instance_commitments: &'static str,
  location: Option<&'static str>,
  lock_file: &'static str,
  log_level: Option<&'static str>,
  minify: bool,
  node_modules_mode: &'static str,
  no_prompt: bool,
  no_terminal: bool,
  no_update_check: bool,
  npmrc_override: Option<&'static str>,
  otel_config_digest: OdenParentOtelConfigDigest,
  output: &'static str,
  permissions: &'static str,
  preload_modules: Vec<&'static str>,
  release_base_url: Option<&'static str>,
  require_modules: Vec<&'static str>,
  schema: &'static str,
  seed: Option<u64>,
  self_extracting: bool,
  source_file: &'static str,
  subcommand: &'static str,
  target: Option<&'static str>,
  type_check: &'static str,
  unstable_config_digest: OdenParentUnstableConfigDigest,
  unstable_features: Vec<&'static str>,
  v8_flags: Vec<&'static str>,
  vfs_case_sensitivity: &'static str,
  vendor: bool,
  watch: bool,
  workspace_resolver_digest: OdenParentWorkspaceResolverDigest,
}

impl OdenParentStandaloneConfiguration {
  pub fn from_effective(
    workspace_resolver: &SerializedWorkspaceResolver,
    unstable_config: &UnstableConfig,
    otel_config: &OtelConfig,
  ) -> Result<Self, OdenParentAllowlistError> {
    let unstable_config_digest = unstable_config_digest(unstable_config)?;
    let otel_config_digest = otel_config_digest(otel_config)?;
    let workspace_resolver_digest =
      workspace_resolver_digest(workspace_resolver)?;

    Ok(Self {
      app_name: "oden",
      app_version: None,
      bundle: false,
      ca_data_digest: None,
      ca_stores: None,
      cached_only: false,
      certificate: None,
      code_cache_enabled: true,
      config_file: "$REPOSITORY/deno.json",
      cwd: "$REPOSITORY",
      denort: "$DENORT",
      embedded_args: Vec::new(),
      entrypoint_key: ODEN_PARENT_ENTRYPOINT_KEY,
      env_files: Vec::new(),
      error_reporting_url: None,
      eszip: false,
      exclude: Vec::new(),
      exclude_unused_npm: false,
      frozen: true,
      icon: None,
      ignored_tls_certificate_errors: Vec::new(),
      import_map_override: None,
      include: Vec::new(),
      instance_commitments: "$INSTANCE",
      location: None,
      lock_file: "$REPOSITORY/deno.lock",
      log_level: None,
      minify: false,
      node_modules_mode: "none",
      no_prompt: true,
      no_terminal: false,
      no_update_check: true,
      npmrc_override: None,
      otel_config_digest,
      output: "$OUTPUT",
      permissions: "all",
      preload_modules: Vec::new(),
      release_base_url: None,
      require_modules: Vec::new(),
      schema: ODEN_PARENT_STANDALONE_CONFIGURATION_SCHEMA,
      seed: None,
      self_extracting: false,
      source_file: "$REPOSITORY/src/release.ts",
      subcommand: "compile",
      target: None,
      type_check: "none",
      unstable_config_digest,
      unstable_features: Vec::new(),
      v8_flags: Vec::new(),
      vfs_case_sensitivity: "target-default",
      vendor: false,
      watch: false,
      workspace_resolver_digest,
    })
  }

  pub fn canonical_jcs(&self) -> Result<Vec<u8>, OdenParentAllowlistError> {
    // The closed configuration contains neither floats nor maps and uses only
    // derive-generated serialization, so this explicit conversion cannot
    // erase a non-finite value or duplicate member.
    let value = serde_json::to_value(self).map_err(|error| {
      OdenParentAllowlistError::CanonicalJson(error.to_string())
    })?;
    canonical_value_jcs(&value)
  }

  pub fn digest(
    &self,
  ) -> Result<OdenParentStandaloneConfigurationDigest, OdenParentAllowlistError>
  {
    Ok(OdenParentStandaloneConfigurationDigest(hjcs_digest(
      ODEN_PARENT_STANDALONE_CONFIGURATION_DIGEST_DOMAIN,
      &self.canonical_jcs()?,
    )?))
  }
}

fn workspace_resolver_jcs(
  workspace_resolver: &SerializedWorkspaceResolver,
) -> Result<Vec<u8>, OdenParentAllowlistError> {
  // All dynamic objects are typed string-keyed maps, which guarantee unique
  // decoded keys; nested package-json values are already serde_json::Value.
  let value = serde_json::to_value(workspace_resolver).map_err(|error| {
    OdenParentAllowlistError::CanonicalJson(error.to_string())
  })?;
  canonical_value_jcs(&value)
}

fn workspace_resolver_digest(
  workspace_resolver: &SerializedWorkspaceResolver,
) -> Result<OdenParentWorkspaceResolverDigest, OdenParentAllowlistError> {
  Ok(OdenParentWorkspaceResolverDigest(hjcs_digest(
    ODEN_PARENT_WORKSPACE_RESOLVER_DIGEST_DOMAIN,
    &workspace_resolver_jcs(workspace_resolver)?,
  )?))
}

fn unstable_config_jcs(
  unstable_config: &UnstableConfig,
) -> Result<Vec<u8>, OdenParentAllowlistError> {
  let expected = UnstableConfig {
    legacy_flag_enabled: false,
    detect_cjs: false,
    lazy_dynamic_imports: false,
    raw_imports: false,
    sloppy_imports: false,
    npm_lazy_caching: false,
    tsgo: false,
    features: Vec::new(),
  };
  if unstable_config != &expected {
    return Err(OdenParentAllowlistError::NonDefaultUnstableConfig);
  }
  let value = serde_json::to_value(unstable_config).map_err(|error| {
    OdenParentAllowlistError::CanonicalJson(error.to_string())
  })?;
  canonical_value_jcs(&value)
}

fn unstable_config_digest(
  unstable_config: &UnstableConfig,
) -> Result<OdenParentUnstableConfigDigest, OdenParentAllowlistError> {
  Ok(OdenParentUnstableConfigDigest(hjcs_digest(
    ODEN_PARENT_UNSTABLE_CONFIG_DIGEST_DOMAIN,
    &unstable_config_jcs(unstable_config)?,
  )?))
}

fn otel_config_jcs(
  otel_config: &OtelConfig,
) -> Result<Vec<u8>, OdenParentAllowlistError> {
  let expected = OtelConfig {
    tracing_enabled: false,
    metrics_enabled: false,
    console: OtelConsoleConfig::Ignore,
    deterministic_prefix: None,
    propagators: std::collections::HashSet::new(),
  };
  let expected = serde_json::to_value(expected).map_err(|error| {
    OdenParentAllowlistError::CanonicalJson(error.to_string())
  })?;
  let value = serde_json::to_value(otel_config).map_err(|error| {
    OdenParentAllowlistError::CanonicalJson(error.to_string())
  })?;
  if value != expected {
    return Err(OdenParentAllowlistError::NonDefaultOtelConfig);
  }
  canonical_value_jcs(&value)
}

fn otel_config_digest(
  otel_config: &OtelConfig,
) -> Result<OdenParentOtelConfigDigest, OdenParentAllowlistError> {
  Ok(OdenParentOtelConfigDigest(hjcs_digest(
    ODEN_PARENT_OTEL_CONFIG_DIGEST_DOMAIN,
    &otel_config_jcs(otel_config)?,
  )?))
}

#[cfg(test)]
#[derive(Clone, Debug, PartialEq, Eq)]
struct OdenParentAllowlistDigests {
  capture_contract_digest: CanonicalSha256Digest,
  entrypoint_source_digest: OdenParentEntrypointSourceDigest,
  release_contract_digest: CanonicalSha256Digest,
  source_closure_contract_digest: CanonicalSha256Digest,
  standalone_configuration_digest: OdenParentStandaloneConfigurationDigest,
  static_import_edge_digest: OdenParentStaticImportEdgeDigest,
  synthetic_module_source_digest: OdenParentSyntheticModuleSourceDigest,
  vfs_graph_digest: OdenParentVfsGraphDigest,
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
  standalone_configuration_digest: OdenParentStandaloneConfigurationDigest,
  #[serde(rename = "staticImportEdgeDigest")]
  static_import_edge_digest: OdenParentStaticImportEdgeDigest,
  #[serde(rename = "syntheticModuleSourceDigest")]
  synthetic_module_source_digest: OdenParentSyntheticModuleSourceDigest,
  #[serde(rename = "vfsGraphDigest")]
  vfs_graph_digest: OdenParentVfsGraphDigest,
}

/// Complete typed inputs to the pure allowlist projection.
///
/// This value carries no caller-authored digest string, target, fork, engine,
/// image, execution, signing, or evidence field. Constructing an allowlist is
/// not compiler, generator, startup, or release authority.
#[derive(Clone, Copy, Debug)]
pub struct OdenParentAllowlistInputs<'a> {
  pub capture_contract: &'a ContractInventory,
  pub source_closure_contract: &'a ContractInventory,
  pub release_contract: &'a ContractInventory,
  pub configuration: &'a OdenParentStandaloneConfiguration,
  pub vfs_graph: &'a OdenParentVfsGraph,
  pub static_import_edge: &'a OdenParentStaticImportEdge,
}

impl OdenParentAllowlist {
  pub fn from_inputs(
    inputs: OdenParentAllowlistInputs<'_>,
  ) -> Result<Self, OdenParentAllowlistError> {
    inputs
      .vfs_graph
      .require_static_import_edge(inputs.static_import_edge)?;
    Ok(Self {
      capture_contract_digest: inputs
        .capture_contract
        .digest(ContractInventoryKind::Capture)?,
      engine_provenance_schema: 2,
      entrypoint_key: ODEN_PARENT_ENTRYPOINT_KEY,
      entrypoint_source_digest: inputs
        .static_import_edge
        .entrypoint_source_digest
        .clone(),
      parent_primitive_id: ODEN_PARENT_PRIMITIVE_ID,
      private_module_specifier: ODEN_PARENT_PRIVATE_MODULE_SPECIFIER,
      profile: ODEN_PARENT_PROFILE,
      release_contract_digest: inputs
        .release_contract
        .digest(ContractInventoryKind::Release)?,
      schema: ODEN_PARENT_ALLOWLIST_SCHEMA,
      source_closure_contract_digest: inputs
        .source_closure_contract
        .digest(ContractInventoryKind::SourceClosure)?,
      standalone_configuration_digest: inputs.configuration.digest()?,
      static_import_edge_digest: inputs.static_import_edge.digest()?,
      synthetic_module_source_digest: inputs
        .static_import_edge
        .synthetic_module_source_digest
        .clone(),
      vfs_graph_digest: inputs.vfs_graph.digest()?,
    })
  }

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

fn validate_repository_relative_path(
  path: &str,
) -> Result<(), OdenParentAllowlistError> {
  if path.is_empty()
    || path.len() > ODEN_PARENT_REPOSITORY_RELATIVE_PATH_MAX_BYTES
    || !path.is_ascii()
    || path.starts_with('/')
    || path.contains('\\')
    || path.contains('\0')
    || path.split('/').any(|component| {
      component.is_empty()
        || component.len() > ODEN_PARENT_REPOSITORY_RELATIVE_COMPONENT_MAX_BYTES
        || matches!(component, "." | "..")
    })
  {
    return Err(OdenParentAllowlistError::InvalidContractPath(
      path.to_string(),
    ));
  }
  Ok(())
}

#[cfg(test)]
mod tests {
  use std::ffi::OsString;

  use super::*;

  const ZERO_DIGEST: &str =
    "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
  const STATIC_IMPORT_ENTRYPOINT_SOURCE: &[u8] =
    b"import capture from \"oden-internal:filesystem-parent-capture-v2\";\n";
  const VFS_ENTRYPOINT_SOURCE: &[u8] = b"import \"oden-internal:filesystem-parent-capture-v2\";\nconst dep = import(\"./dep.ts\");\nexport * from \"node:fs\";\nconst tool = import(\"../assets/tool.sh\");\n";
  const VFS_DEPENDENCY_SOURCE: &[u8] = b"export const dep: number = 1;\n";
  const VFS_EMPTY_ATTRIBUTES: &[OdenParentObservedImportAttribute<'static>] =
    &[];
  const VFS_PHASE_ATTRIBUTES: &[OdenParentObservedImportAttribute<'static>] =
    &[OdenParentObservedImportAttribute {
      key: "phase",
      value: "runtime",
    }];

  fn raw_argv<const N: usize>(args: [&str; N]) -> Vec<OsString> {
    args.into_iter().map(OsString::from).collect()
  }

  #[test]
  fn raw_allowlist_dispatch_admits_only_the_two_exact_vectors() {
    for (selector, expected) in [
      (
        "--_oden-parent-allowlist-mode=generate",
        OdenParentAllowlistRawDispatch::Generate,
      ),
      (
        "--_oden-parent-allowlist-mode=check",
        OdenParentAllowlistRawDispatch::Check,
      ),
    ] {
      assert_eq!(
        classify_oden_parent_allowlist_raw_argv(&raw_argv([
          "arbitrary-argv-zero",
          "compile",
          selector,
        ])),
        expected,
      );
    }

    for args in [
      raw_argv(["deno", "compile", "--_oden-parent-allowlist-mode"]),
      raw_argv(["deno", "compile", "--_oden-parent-allowlist-mode=other"]),
      raw_argv(["deno", "compile", "--_ODEN-PARENT-ALLOWLIST-MODE=generate"]),
      raw_argv([
        "deno",
        "compile",
        "--_oden-parent-allowlist-mode=generate\r",
      ]),
      raw_argv([
        "deno",
        "compile",
        "--_oden-parent-allowlist-mode=generate\n",
      ]),
      raw_argv(["deno", "Compile", "--_oden-parent-allowlist-mode=generate"]),
      raw_argv([
        "deno",
        "compile",
        "--_oden-parent-allowlist-mode=generate-suffix",
      ]),
      raw_argv([
        "deno",
        "compile",
        "--_oden-parent-allowlist-mode-extension=generate",
      ]),
      raw_argv(["deno", "--", "--_oden-parent-allowlist-mode=generate"]),
      raw_argv(["deno", "--quiet", "--_oden-parent-allowlist-mode=generate"]),
      raw_argv([
        "deno",
        "compile",
        "--_oden-parent-allowlist-mode",
        "generate",
      ]),
      raw_argv([
        "deno",
        "compile",
        "--_oden-parent-allowlist-mode=generate",
        "--_oden-parent-allowlist-mode=generate",
      ]),
      raw_argv([
        "deno",
        "compile",
        "src/main.ts",
        "--_oden-parent-allowlist-mode=generate",
      ]),
      raw_argv([
        "deno",
        "compile",
        "--target",
        "x86_64-unknown-linux-gnu",
        "--_oden-parent-allowlist-mode=generate",
      ]),
      raw_argv([
        "deno",
        "compile",
        "--_oden-parent-allowlist-mode=generate",
        "src/main.ts",
      ]),
    ] {
      assert_eq!(
        classify_oden_parent_allowlist_raw_argv(&args),
        OdenParentAllowlistRawDispatch::Refuse,
        "{args:?}",
      );
    }
  }

  #[test]
  fn raw_allowlist_dispatch_ignores_argv_zero_and_unrelated_arguments() {
    for args in [
      raw_argv(["deno"]),
      raw_argv(["deno", "run", "src/main.ts"]),
      raw_argv([
        "--_oden-parent-allowlist-mode=generate",
        "run",
        "src/main.ts",
      ]),
      raw_argv(["deno", "compile", "--x_oden-parent-allowlist-mode=generate"]),
    ] {
      assert_eq!(
        classify_oden_parent_allowlist_raw_argv(&args),
        OdenParentAllowlistRawDispatch::Absent,
        "{args:?}",
      );
    }
  }

  #[cfg(unix)]
  #[test]
  fn raw_allowlist_dispatch_scans_non_utf8_native_units_without_loss() {
    use std::os::unix::ffi::OsStringExt;

    let mut reserved = ODEN_PARENT_ALLOWLIST_RESERVED_PREFIX.to_vec();
    reserved.push(0xff);
    assert_eq!(
      classify_oden_parent_allowlist_raw_argv(&[
        OsString::from("deno"),
        OsString::from_vec(reserved),
      ]),
      OdenParentAllowlistRawDispatch::Refuse,
    );

    let mut unrelated = ODEN_PARENT_ALLOWLIST_RESERVED_PREFIX.to_vec();
    unrelated[2] = 0xff;
    assert_eq!(
      classify_oden_parent_allowlist_raw_argv(&[
        OsString::from("deno"),
        OsString::from_vec(unrelated),
      ]),
      OdenParentAllowlistRawDispatch::Absent,
    );
  }

  #[cfg(windows)]
  #[test]
  fn raw_allowlist_dispatch_scans_non_unicode_wide_units_without_loss() {
    use std::os::windows::ffi::OsStringExt;

    let mut reserved = ODEN_PARENT_ALLOWLIST_RESERVED_PREFIX
      .iter()
      .copied()
      .map(u16::from)
      .collect::<Vec<_>>();
    reserved.push(0xd800);
    assert_eq!(
      classify_oden_parent_allowlist_raw_argv(&[
        OsString::from("deno"),
        OsString::from_wide(&reserved),
      ]),
      OdenParentAllowlistRawDispatch::Refuse,
    );

    let mut unrelated = ODEN_PARENT_ALLOWLIST_RESERVED_PREFIX
      .iter()
      .copied()
      .map(u16::from)
      .collect::<Vec<_>>();
    unrelated[2] = 0x0100;
    assert_eq!(
      classify_oden_parent_allowlist_raw_argv(&[
        OsString::from("deno"),
        OsString::from_wide(&unrelated),
      ]),
      OdenParentAllowlistRawDispatch::Absent,
    );
  }

  fn zero_digest(field: &'static str) -> CanonicalSha256Digest {
    CanonicalSha256Digest::parse(field, ZERO_DIGEST).unwrap()
  }

  fn minimal_workspace_resolver() -> SerializedWorkspaceResolver {
    serde_json::from_value(serde_json::json!({
      "catalogs": {},
      "import_map": null,
      "jsr_pkgs": [],
      "package_jsons": {},
      "pkg_json_resolution": "Enabled",
    }))
    .unwrap()
  }

  fn empty_import_attributes() -> OdenParentImportAttributes {
    OdenParentImportAttributes::from_observed_pairs(&[]).unwrap()
  }

  fn valid_static_import_edge_observation<'a>(
    entrypoint_source_bytes: &'a [u8],
    import_attributes: &'a OdenParentImportAttributes,
  ) -> OdenParentStaticImportEdgeObservation<'a> {
    OdenParentStaticImportEdgeObservation {
      entrypoint_source_bytes,
      dependency_ordinal: 0,
      occurrence_count: 1,
      kind: OdenParentVfsDependencyKind::StaticImport,
      raw_specifier: ODEN_PARENT_PRIVATE_MODULE_SPECIFIER,
      resolved_specifier: ODEN_PARENT_PRIVATE_MODULE_SPECIFIER,
      referrer_key: ODEN_PARENT_ENTRYPOINT_KEY,
      import_attributes,
      source_byte_start: 21,
      source_byte_end: 63,
    }
  }

  fn assert_invalid_static_import_edge(
    observation: OdenParentStaticImportEdgeObservation<'_>,
  ) {
    assert!(matches!(
      OdenParentStaticImportEdge::from_observation(observation),
      Err(OdenParentAllowlistError::InvalidStaticImportEdge(_))
    ));
  }

  fn exact_vfs_dependencies() -> [OdenParentVfsDependencyObservation<'static>; 4]
  {
    // Deliberately reverse source order. The projection must own the normative
    // tuple sort rather than inherit graph traversal order.
    [
      OdenParentVfsDependencyObservation {
        kind: OdenParentVfsDependencyKind::DynamicImport,
        raw_specifier: "../assets/tool.sh",
        resolved_key: "repo:assets/tool.sh",
        source_byte_start: 131,
        source_byte_end: 148,
        import_attributes: VFS_EMPTY_ATTRIBUTES,
      },
      OdenParentVfsDependencyObservation {
        kind: OdenParentVfsDependencyKind::StaticExport,
        raw_specifier: "node:fs",
        resolved_key: "node:fs",
        source_byte_start: 100,
        source_byte_end: 107,
        import_attributes: VFS_EMPTY_ATTRIBUTES,
      },
      OdenParentVfsDependencyObservation {
        kind: OdenParentVfsDependencyKind::DynamicImport,
        raw_specifier: "./dep.ts",
        resolved_key: "repo:src/dep.ts",
        source_byte_start: 73,
        source_byte_end: 81,
        import_attributes: VFS_PHASE_ATTRIBUTES,
      },
      OdenParentVfsDependencyObservation {
        kind: OdenParentVfsDependencyKind::StaticImport,
        raw_specifier: ODEN_PARENT_PRIVATE_MODULE_SPECIFIER,
        resolved_key: ODEN_PARENT_PRIVATE_MODULE_SPECIFIER,
        source_byte_start: 8,
        source_byte_end: 50,
        import_attributes: VFS_EMPTY_ATTRIBUTES,
      },
    ]
  }

  fn exact_vfs_modules<'a>(
    dependencies: &'a [OdenParentVfsDependencyObservation<'a>],
  ) -> [OdenParentVfsModuleObservation<'a>; 2] {
    // Deliberately reverse raw-key order.
    [
      OdenParentVfsModuleObservation {
        key: ODEN_PARENT_ENTRYPOINT_KEY,
        media_type: OdenParentVfsMediaType::TypeScript,
        original_bytes: VFS_ENTRYPOINT_SOURCE,
        emitted_bytes: b"// emitted entry\n",
        source_map_bytes: None,
        dependencies,
      },
      OdenParentVfsModuleObservation {
        key: "repo:src/dep.ts",
        media_type: OdenParentVfsMediaType::TypeScript,
        original_bytes: VFS_DEPENDENCY_SOURCE,
        emitted_bytes: b"export const dep = 1;\n",
        source_map_bytes: Some(b"{}"),
        dependencies: &[],
      },
    ]
  }

  fn exact_vfs_files() -> [OdenParentVfsFileObservation<'static>; 1] {
    [OdenParentVfsFileObservation {
      key: "repo:assets/tool.sh",
      executable: true,
      original_bytes: b"#!/bin/sh\n",
      emitted_bytes: b"#!/bin/sh\n",
    }]
  }

  fn minimal_entrypoint_module<'a>(
    original_bytes: &'a [u8],
    media_type: OdenParentVfsMediaType,
    dependencies: &'a [OdenParentVfsDependencyObservation<'a>],
  ) -> OdenParentVfsModuleObservation<'a> {
    OdenParentVfsModuleObservation {
      key: ODEN_PARENT_ENTRYPOINT_KEY,
      media_type,
      original_bytes,
      emitted_bytes: original_bytes,
      source_map_bytes: None,
      dependencies,
    }
  }

  fn assert_invalid_vfs_dependency(
    module_source: &[u8],
    dependency: &OdenParentVfsDependencyObservation<'_>,
  ) {
    assert!(matches!(
      project_vfs_dependency(
        ODEN_PARENT_ENTRYPOINT_KEY,
        module_source,
        dependency,
      ),
      Err(OdenParentAllowlistError::InvalidVfsDependency { .. })
    ));
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
      standalone_configuration_digest: OdenParentStandaloneConfigurationDigest(
        zero_digest("standaloneConfigurationDigest"),
      ),
      static_import_edge_digest: OdenParentStaticImportEdgeDigest(zero_digest(
        "staticImportEdgeDigest",
      )),
      synthetic_module_source_digest: OdenParentSyntheticModuleSourceDigest(
        zero_digest("syntheticModuleSourceDigest"),
      ),
      vfs_graph_digest: OdenParentVfsGraphDigest(zero_digest("vfsGraphDigest")),
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

    let same_inventory = ContractInventory::from_files(&[ContractFile {
      path: "same",
      bytes: b"same-bytes",
    }])
    .unwrap();
    assert_eq!(
      same_inventory.canonical_jcs().unwrap(),
      br#"[{"byteDigest":"sha256-etVQn6waG-Slmuh5WUaIQNKAi6sbPNVnZzMZSqgu8zg","path":"same"}]"#
    );
    for (kind, expected) in [
      (
        ContractInventoryKind::Capture,
        "sha256-VczDRRJw8Sqsnf2rJH0cS4c85UQdjaj-o19EJjM4IIo",
      ),
      (
        ContractInventoryKind::SourceClosure,
        "sha256-IIZQIdyiQ3xm1J2IOCWXrNXPvKJDBGmFSXyoQtI2YxE",
      ),
      (
        ContractInventoryKind::Release,
        "sha256-315XYsExIIxHce003s1dd5F4L7oI89UW4Z7gh0Czw9o",
      ),
    ] {
      assert_eq!(same_inventory.digest(kind).unwrap().as_str(), expected);
    }
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
        OdenParentSyntheticModuleSourceDigest::from_test_bytes(bytes)
          .as_str()
          .to_string(),
        "sha256-BO7B__WMBq831KL6Xpd0uNBG9yYG3o5KbS7KLe1LeFA",
      ),
      (
        OdenParentModuleSourceBytesDigest::from_test_bytes(bytes)
          .as_str()
          .to_string(),
        "sha256-e0y_p9s41j53L5SCWycRwPHGaXTyYf9gV4eqbq7DwpM",
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
  fn import_attributes_are_complete_utf16_sorted_and_domain_bound() {
    let empty = OdenParentImportAttributes::from_observed_pairs(&[]).unwrap();
    assert_eq!(empty.canonical_jcs().unwrap(), b"{}");
    assert_eq!(
      empty.digest().unwrap().as_str(),
      "sha256-pQu6gFhNGdfrlk8npWVB1g5yzOEBfC2d-LaLn8riE4E"
    );

    let attributes = [
      OdenParentObservedImportAttribute {
        key: "\u{e000}",
        value: "private-use",
      },
      OdenParentObservedImportAttribute {
        key: "😀",
        value: "supplementary",
      },
      OdenParentObservedImportAttribute {
        key: "€",
        value: "euro",
      },
      OdenParentObservedImportAttribute {
        key: "ö",
        value: "o-diaeresis",
      },
      OdenParentObservedImportAttribute {
        key: "type",
        value: "json",
      },
      OdenParentObservedImportAttribute {
        key: "1",
        value: "one",
      },
      OdenParentObservedImportAttribute {
        key: "\r",
        value: "quote:\" backslash:\\ nul:\u{0000}",
      },
    ];
    let projection =
      OdenParentImportAttributes::from_observed_pairs(&attributes).unwrap();
    assert_eq!(
      projection.canonical_jcs().unwrap(),
      "{\"\\r\":\"quote:\\\" backslash:\\\\ nul:\\u0000\",\"1\":\"one\",\"type\":\"json\",\"ö\":\"o-diaeresis\",\"€\":\"euro\",\"😀\":\"supplementary\",\"\u{e000}\":\"private-use\"}"
        .as_bytes()
    );

    let mut reversed = attributes;
    reversed.reverse();
    let reversed =
      OdenParentImportAttributes::from_observed_pairs(&reversed).unwrap();
    assert_eq!(projection.canonical_jcs(), reversed.canonical_jcs());
    assert_eq!(projection.digest(), reversed.digest());

    assert_eq!(
      OdenParentImportAttributes::from_observed_pairs(&[
        OdenParentObservedImportAttribute {
          key: "a",
          value: "first",
        },
        OdenParentObservedImportAttribute {
          key: "a",
          value: "second",
        },
      ]),
      Err(OdenParentAllowlistError::DuplicateImportAttribute(
        "a".to_string()
      ))
    );
  }

  #[test]
  fn vfs_graph_has_exact_closed_preimage_and_domain_bound_digest() {
    let dependencies = exact_vfs_dependencies();
    let modules = exact_vfs_modules(&dependencies);
    let graph =
      OdenParentVfsGraph::from_observations(&modules, &exact_vfs_files())
        .unwrap();

    assert_eq!(
      graph.canonical_jcs().unwrap(),
      br#"{"entrypointKey":"repo:src/release.ts","files":[{"emittedByteDigest":"sha256-MhZ4XV-h7I_D7gZb98mlhyrc5zzF3q3zHyV9fE_P0X4","executable":true,"key":"repo:assets/tool.sh","kind":"file","originalByteDigest":"sha256-6-ebFsIF1KFwWJhZGebLtbu-_CMaWvqU-dcBU8dM_e8"}],"modules":[{"dependencies":[],"emittedByteDigest":"sha256-nfpQ0yntYLuoJ0X65xhTGY8yBnQZVgoCTYPoxegN2Ws","key":"repo:src/dep.ts","mediaType":"TypeScript","originalByteDigest":"sha256-c_nPEQEXgCXGlhYKk114yr0iR_XmrQFeGBuan8msWrg","sourceMapDigest":"sha256-UdlnEIsiMmLbbsUPuVPeqVEqVHeJrhTUnQ5RdIdVZUQ"},{"dependencies":[{"importAttributesDigest":"sha256-pQu6gFhNGdfrlk8npWVB1g5yzOEBfC2d-LaLn8riE4E","kind":"static-import","rawSpecifier":"oden-internal:filesystem-parent-capture-v2","resolvedKey":"oden-internal:filesystem-parent-capture-v2","sourceByteEnd":50,"sourceByteStart":8},{"importAttributesDigest":"sha256-LNypBtkDUvfqsc4BKMRI__a4SXiw-D8L7fRfJd9MBIQ","kind":"dynamic-import","rawSpecifier":"./dep.ts","resolvedKey":"repo:src/dep.ts","sourceByteEnd":81,"sourceByteStart":73},{"importAttributesDigest":"sha256-pQu6gFhNGdfrlk8npWVB1g5yzOEBfC2d-LaLn8riE4E","kind":"static-export","rawSpecifier":"node:fs","resolvedKey":"node:fs","sourceByteEnd":107,"sourceByteStart":100},{"importAttributesDigest":"sha256-pQu6gFhNGdfrlk8npWVB1g5yzOEBfC2d-LaLn8riE4E","kind":"dynamic-import","rawSpecifier":"../assets/tool.sh","resolvedKey":"repo:assets/tool.sh","sourceByteEnd":148,"sourceByteStart":131}],"emittedByteDigest":"sha256-2kKiuC56y-MQrKKlmKKUEKWtKzhNIymeA9vKrI9XZbY","key":"repo:src/release.ts","mediaType":"TypeScript","originalByteDigest":"sha256-hFUU7XRIPpCzeE4xlbBzKini2ENmDGIyrLTDgjt5QxI","sourceMapDigest":null}],"schema":"oden/capsec-filesystem-parent-vfs-graph/2"}"#
    );
    assert_eq!(
      graph.digest().unwrap().as_str(),
      "sha256-rkWftckU7n9GjIPFTkA1krB6BY8WcZ-zoOPw2a-MiPw"
    );
  }

  #[test]
  fn vfs_graph_sorts_observations_and_dependency_kind_by_raw_spelling() {
    let mut dependencies = exact_vfs_dependencies();
    let modules = exact_vfs_modules(&dependencies);
    let graph =
      OdenParentVfsGraph::from_observations(&modules, &exact_vfs_files())
        .unwrap();

    dependencies.reverse();
    let mut modules = exact_vfs_modules(&dependencies);
    modules.reverse();
    let permuted =
      OdenParentVfsGraph::from_observations(&modules, &exact_vfs_files())
        .unwrap();
    assert_eq!(graph.canonical_jcs(), permuted.canonical_jcs());
    assert_eq!(graph.digest(), permuted.digest());

    let attributes_digest = empty_import_attributes().digest().unwrap();
    let row = |kind| OdenParentVfsDependencyRow {
      import_attributes_digest: attributes_digest.clone(),
      kind,
      raw_specifier: "same".to_string(),
      resolved_key: "repo:same.ts".to_string(),
      source_byte_end: 2,
      source_byte_start: 1,
    };
    let mut rows = vec![
      row(OdenParentVfsDependencyKind::StaticImport),
      row(OdenParentVfsDependencyKind::DynamicImport),
      row(OdenParentVfsDependencyKind::StaticExport),
    ];
    rows.sort_by(compare_vfs_dependencies);
    assert_eq!(
      rows.iter().map(|row| row.kind).collect::<Vec<_>>(),
      vec![
        OdenParentVfsDependencyKind::DynamicImport,
        OdenParentVfsDependencyKind::StaticExport,
        OdenParentVfsDependencyKind::StaticImport,
      ]
    );
  }

  #[test]
  fn vfs_keys_accept_only_closed_canonical_namespaces() {
    for key in [
      "repo:src/release.ts",
      "jsr:@scope/pkg@1.2.3/mod.ts",
      "jsr:pkg@1.2.3/mod.ts",
      "jsr:@scope/pkg@1.2.3-beta.1+build.2/mod.ts",
    ] {
      validate_vfs_module_key(key).unwrap();
    }
    validate_vfs_file_key("repo:assets/tool.sh").unwrap();
    for key in [
      "repo:src/dep.ts",
      "jsr:@scope/pkg@1.2.3/mod.ts",
      "node:fs",
      "node:assert/strict",
      ODEN_PARENT_PRIVATE_MODULE_SPECIFIER,
    ] {
      validate_vfs_dependency_key(key).unwrap();
    }

    for key in [
      "",
      "repo:",
      "repo:/absolute.ts",
      "repo:src//empty.ts",
      "repo:src/./dot.ts",
      "repo:src/../escape.ts",
      "repo:src\\windows.ts",
      "repo:src/%2e%2e/escape.ts",
      "repo:src/é.ts",
      "jsr:pkg@1.2.3/src/é.ts",
      "repo:generated/capsec/rev2/filesystem-parent-standalone-allowlist.json",
      "repo:fork/deno/cli/lib/standalone/oden_parent_allowlist_generated.rs",
      "repo:fork/deno/cli/lib/standalone/oden_parent_target_policy_generated.rs",
      "npm:pkg@1.0.0",
      "https://example.test/mod.ts",
      "data:text/javascript,export{}",
      "blob:https://example.test/id",
      "oden-internal:other",
      "node:fs",
      ODEN_PARENT_PRIVATE_MODULE_SPECIFIER,
    ] {
      assert!(matches!(
        validate_vfs_module_key(key),
        Err(OdenParentAllowlistError::InvalidVfsKey { role: "module", .. })
      ));
    }
    for key in [
      "jsr:@scope/pkg@1.2.3/mod.ts",
      "node:fs",
      ODEN_PARENT_PRIVATE_MODULE_SPECIFIER,
    ] {
      assert!(matches!(
        validate_vfs_file_key(key),
        Err(OdenParentAllowlistError::InvalidVfsKey { role: "file", .. })
      ));
    }
    for key in [
      "node:not-a-deno-builtin",
      "node:",
      "node:%66s",
      "npm:pkg@1.0.0",
      "http://example.test/mod.ts",
      "oden-internal:filesystem-parent-capture-v1",
    ] {
      assert!(matches!(
        validate_vfs_dependency_key(key),
        Err(OdenParentAllowlistError::InvalidVfsKey {
          role: "dependency",
          ..
        })
      ));
    }

    for path in ODEN_PARENT_GENERATED_PATHS {
      for path in [path.to_string(), path.to_ascii_uppercase()] {
        let key = format!("repo:{path}");
        assert!(matches!(
          validate_vfs_module_key(&key),
          Err(OdenParentAllowlistError::InvalidVfsKey { role: "module", .. })
        ));
        assert!(matches!(
          validate_vfs_file_key(&key),
          Err(OdenParentAllowlistError::InvalidVfsKey { role: "file", .. })
        ));
        assert!(matches!(
          validate_vfs_dependency_key(&key),
          Err(OdenParentAllowlistError::InvalidVfsKey {
            role: "dependency",
            ..
          })
        ));
      }
    }
  }

  #[test]
  fn repository_relative_path_grammar_is_shared_by_inventory_and_vfs_keys() {
    let mut max_path_components = vec!["a".repeat(255); 15];
    max_path_components.push("b".repeat(254));
    max_path_components.push("c".to_string());
    let max_path = max_path_components.join("/");
    assert_eq!(max_path.len(), 4_096);
    assert!(max_path.split('/').all(|component| component.len() <= 255));

    let max_key =
      OdenParentRepoVfsKey::from_repository_relative_path(&max_path).unwrap();
    assert_eq!(max_key.as_str(), format!("repo:{max_path}"));
    ContractInventory::from_files(&[ContractFile {
      path: &max_path,
      bytes: b"x",
    }])
    .unwrap();
    assert!(validate_jsr_vfs_key(&format!("jsr:pkg@1.2.3/{max_path}")));
    assert!(validate_jsr_raw_specifier(&format!(
      "jsr:pkg@1.2.3/{max_path}"
    )));

    let overlong_path = format!("{max_path}d");
    let overlong_component = "d".repeat(256);
    for path in [
      "".to_string(),
      "/absolute".to_string(),
      "a//b".to_string(),
      "a/./b".to_string(),
      "a/../b".to_string(),
      "a\\b".to_string(),
      "a\0b".to_string(),
      "src/é.ts".to_string(),
      overlong_path.clone(),
      overlong_component,
    ] {
      assert!(
        OdenParentRepoVfsKey::from_repository_relative_path(&path).is_err()
      );
      assert!(matches!(
        ContractInventory::from_files(&[ContractFile {
          path: &path,
          bytes: b"x",
        }]),
        Err(OdenParentAllowlistError::InvalidContractPath(_))
      ));
    }
    assert!(!validate_jsr_vfs_key(&format!(
      "jsr:pkg@1.2.3/{overlong_path}"
    )));
    assert!(!validate_jsr_raw_specifier(&format!(
      "jsr:pkg@1.2.3/{overlong_path}"
    )));

    ContractInventory::from_files(&[ContractFile {
      path: "literal%path",
      bytes: b"x",
    }])
    .unwrap();
    assert!(matches!(
      OdenParentRepoVfsKey::from_repository_relative_path("literal%path"),
      Err(OdenParentAllowlistError::InvalidVfsKey {
        role: "repository",
        ..
      })
    ));

    for path in ODEN_PARENT_GENERATED_PATHS {
      for path in [path.to_string(), path.to_ascii_uppercase()] {
        assert!(matches!(
          OdenParentRepoVfsKey::from_repository_relative_path(&path),
          Err(OdenParentAllowlistError::InvalidVfsKey {
            role: "repository",
            ..
          })
        ));
      }
    }
  }

  #[test]
  fn frozen_synthetic_module_source_has_exact_bytes_and_digests() {
    assert!(ODEN_PARENT_SYNTHETIC_MODULE_SOURCE.is_ascii());
    assert_eq!(
      ODEN_PARENT_V8_BRAND_SLOT_ID,
      "oden.filesystem-parent-capture-v8-brand/2"
    );
    assert_eq!(
      ODEN_PARENT_NATIVE_OP_SYMBOL,
      "op_oden_filesystem_parent_capture_v2"
    );
    let source = std::str::from_utf8(ODEN_PARENT_SYNTHETIC_MODULE_SOURCE)
      .expect("frozen synthetic source must be UTF-8");
    assert_eq!(source.matches(ODEN_PARENT_V8_BRAND_SLOT_ID).count(), 2);
    assert_eq!(source.matches(ODEN_PARENT_NATIVE_OP_SYMBOL).count(), 2);
    assert_eq!(
      ODEN_PARENT_SYNTHETIC_MODULE_SOURCE
        .split_inclusive(|byte| *byte == b'\n')
        .map(<[u8]>::len)
        .collect::<Vec<_>>(),
      [69, 72, 65, 82]
    );
    assert_eq!(
      raw_sha256_digest(ODEN_PARENT_SYNTHETIC_MODULE_SOURCE).as_str(),
      "sha256-JLUhYAHIYwAwqD0kyDWIw370bOvruOYfsgWFyuCQbV4"
    );
    assert_eq!(
      OdenParentSyntheticModuleSourceDigest::from_frozen_source().as_str(),
      "sha256-0aagkSSUwopjaS2bzw7TI_xLwvJR-49_hi6EInvzXWc"
    );
    assert_eq!(
      OdenParentModuleSourceBytesDigest::from_frozen_source().as_str(),
      "sha256-T1K9punNmmQg5hG0xH4fG77YNzXShmNUF09mdkMv7lQ"
    );
  }

  #[test]
  fn vfs_jsr_keys_refuse_malformed_or_noncanonical_components() {
    for key in [
      "jsr:@scope/pkg@1.2.3",
      "jsr:@scope/pkg@1/mod.ts",
      "jsr:@scope/pkg@v1.2.3/mod.ts",
      "jsr:@scope/pkg@^1.2.3/mod.ts",
      "jsr:@scope/pkg@latest/mod.ts",
      "jsr:scope/pkg@1.2.3/mod.ts",
      "jsr:@scope/extra/pkg@1.2.3/mod.ts",
      "jsr:@/pkg@1.2.3/mod.ts",
      "jsr:@scope/@1.2.3/mod.ts",
      "jsr:@scope/pkg%2fextra@1.2.3/mod.ts",
      "jsr:@scope/pkg@1.2.3/%2e%2e/mod.ts",
      "jsr:@scope/pkg@1.2.3/../mod.ts",
      "jsr:@scope/pkg@1.2.3/a//b.ts",
      "jsr:@scope/pkg@1.2.3/a\\b.ts",
      "jsr:@scope/pkg\0@1.2.3/mod.ts",
      "jsr:@scope/pkg@1.2.3/mod\0.ts",
      "jsr:@scope/pkg name@1.2.3/mod.ts",
      "jsr:@scope/pkg?query@1.2.3/mod.ts",
      "jsr:@scope/pkg:colon@1.2.3/mod.ts",
      "jsr:@Scope/pkg@1.2.3/mod.ts",
    ] {
      assert!(matches!(
        validate_vfs_module_key(key),
        Err(OdenParentAllowlistError::InvalidVfsKey { role: "module", .. })
      ));
    }
  }

  #[test]
  fn vfs_dependencies_require_exact_safe_payload_byte_ranges() {
    let source = b"import \"./dep.ts\";\n";
    let valid = OdenParentVfsDependencyObservation {
      kind: OdenParentVfsDependencyKind::StaticImport,
      raw_specifier: "./dep.ts",
      resolved_key: "repo:src/dep.ts",
      source_byte_start: 8,
      source_byte_end: 16,
      import_attributes: VFS_EMPTY_ATTRIBUTES,
    };
    project_vfs_dependency(ODEN_PARENT_ENTRYPOINT_KEY, source, &valid).unwrap();

    for (start, end) in [
      (0, 8),
      (8, 8),
      (16, 8),
      (9, 16),
      (8, 15),
      (8, source.len() as u64),
      (MAX_IJSON_SAFE_INTEGER + 1, MAX_IJSON_SAFE_INTEGER + 1),
      (8, MAX_IJSON_SAFE_INTEGER + 1),
    ] {
      let dependency = OdenParentVfsDependencyObservation {
        source_byte_start: start,
        source_byte_end: end,
        ..valid
      };
      assert_invalid_vfs_dependency(source, &dependency);
    }

    for raw_specifier in ["", "./dep\0.ts", "./other.ts"] {
      let dependency = OdenParentVfsDependencyObservation {
        raw_specifier,
        ..valid
      };
      assert_invalid_vfs_dependency(source, &dependency);
    }

    let mismatched = b"import './dep.ts\";\n";
    assert_invalid_vfs_dependency(mismatched, &valid);
    let unsupported = b"import #./dep.ts#;\n";
    assert_invalid_vfs_dependency(unsupported, &valid);

    let interior_delimiter = b"import \"a\"b\";\n";
    let interior_delimiter_dependency = OdenParentVfsDependencyObservation {
      raw_specifier: "a\"b",
      source_byte_start: 8,
      source_byte_end: 11,
      ..valid
    };
    assert_invalid_vfs_dependency(
      interior_delimiter,
      &interior_delimiter_dependency,
    );

    let escaped = br#"import "./\x64ep.ts";"#;
    let escaped_dependency = OdenParentVfsDependencyObservation {
      raw_specifier: r"./\x64ep.ts",
      source_byte_start: 8,
      source_byte_end: 19,
      ..valid
    };
    assert_invalid_vfs_dependency(escaped, &escaped_dependency);

    let interpolated = b"import(`./${name}.ts`);";
    let interpolated_dependency = OdenParentVfsDependencyObservation {
      kind: OdenParentVfsDependencyKind::DynamicImport,
      raw_specifier: "./${name}.ts",
      source_byte_start: 8,
      source_byte_end: 20,
      ..valid
    };
    assert_invalid_vfs_dependency(interpolated, &interpolated_dependency);

    let multibyte = "import \"./é.ts\";\n".as_bytes();
    let multibyte_dependency = OdenParentVfsDependencyObservation {
      raw_specifier: "./é.ts",
      source_byte_start: 8,
      source_byte_end: 15,
      ..valid
    };
    project_vfs_dependency(
      ODEN_PARENT_ENTRYPOINT_KEY,
      multibyte,
      &multibyte_dependency,
    )
    .unwrap();
  }

  #[test]
  fn vfs_modules_refuse_nontext_and_noncode_dependency_rows() {
    let dependency = OdenParentVfsDependencyObservation {
      kind: OdenParentVfsDependencyKind::StaticImport,
      raw_specifier: "./dep.ts",
      resolved_key: "repo:src/dep.ts",
      source_byte_start: 8,
      source_byte_end: 16,
      import_attributes: VFS_EMPTY_ATTRIBUTES,
    };
    for media_type in
      [OdenParentVfsMediaType::Json, OdenParentVfsMediaType::Wasm]
    {
      let module = OdenParentVfsModuleObservation {
        key: "repo:src/noncode",
        media_type,
        original_bytes: b"import \"./dep.ts\";\n",
        emitted_bytes: b"",
        source_map_bytes: None,
        dependencies: std::slice::from_ref(&dependency),
      };
      assert!(matches!(
        project_vfs_module(&module),
        Err(OdenParentAllowlistError::InvalidVfsModule { .. })
      ));
    }

    for media_type in [
      OdenParentVfsMediaType::TypeScript,
      OdenParentVfsMediaType::JavaScript,
      OdenParentVfsMediaType::Json,
    ] {
      let module = OdenParentVfsModuleObservation {
        key: "repo:src/non-utf8",
        media_type,
        original_bytes: &[0xff],
        emitted_bytes: b"",
        source_map_bytes: None,
        dependencies: &[],
      };
      assert!(matches!(
        project_vfs_module(&module),
        Err(OdenParentAllowlistError::InvalidVfsModule { .. })
      ));
    }

    for media_type in [
      OdenParentVfsMediaType::TypeScript,
      OdenParentVfsMediaType::JavaScript,
      OdenParentVfsMediaType::Json,
    ] {
      project_vfs_module(&OdenParentVfsModuleObservation {
        key: "repo:src/text",
        media_type,
        original_bytes: b"{}",
        emitted_bytes: b"{}",
        source_map_bytes: None,
        dependencies: &[],
      })
      .unwrap();
    }
    project_vfs_module(&OdenParentVfsModuleObservation {
      key: "repo:src/module.wasm",
      media_type: OdenParentVfsMediaType::Wasm,
      original_bytes: &[0xff],
      emitted_bytes: &[0xff],
      source_map_bytes: None,
      dependencies: &[],
    })
    .unwrap();
  }

  #[test]
  fn vfs_media_types_have_exact_closed_serialized_spellings() {
    assert_eq!(
      [
        OdenParentVfsMediaType::TypeScript,
        OdenParentVfsMediaType::JavaScript,
        OdenParentVfsMediaType::Json,
        OdenParentVfsMediaType::Wasm,
      ]
      .map(|media_type| serde_json::to_string(&media_type).unwrap()),
      [
        r#""TypeScript""#,
        r#""JavaScript""#,
        r#""Json""#,
        r#""Wasm""#,
      ]
    );
  }

  #[test]
  fn vfs_graph_refuses_duplicate_ambiguous_or_incomplete_topology() {
    let entrypoint =
      minimal_entrypoint_module(b"", OdenParentVfsMediaType::TypeScript, &[]);
    assert!(matches!(
      OdenParentVfsGraph::from_observations(&[entrypoint, entrypoint], &[]),
      Err(OdenParentAllowlistError::DuplicateVfsKey {
        collection: "module",
        ..
      })
    ));

    let file = OdenParentVfsFileObservation {
      key: "repo:asset",
      executable: false,
      original_bytes: b"asset",
      emitted_bytes: b"asset",
    };
    assert!(matches!(
      OdenParentVfsGraph::from_observations(&[entrypoint], &[file, file]),
      Err(OdenParentAllowlistError::DuplicateVfsKey {
        collection: "file",
        ..
      })
    ));
    let ambiguous_file = OdenParentVfsFileObservation {
      key: ODEN_PARENT_ENTRYPOINT_KEY,
      ..file
    };
    assert_eq!(
      OdenParentVfsGraph::from_observations(&[entrypoint], &[ambiguous_file]),
      Err(OdenParentAllowlistError::AmbiguousVfsKey(
        ODEN_PARENT_ENTRYPOINT_KEY.to_string()
      ))
    );

    let missing = OdenParentVfsModuleObservation {
      key: "repo:src/other.ts",
      ..entrypoint
    };
    assert_eq!(
      OdenParentVfsGraph::from_observations(&[missing], &[]),
      Err(OdenParentAllowlistError::MissingVfsEntrypoint)
    );
    assert_eq!(
      OdenParentVfsGraph::from_observations(&[entrypoint, missing], &[]),
      Err(OdenParentAllowlistError::UnreachableVfsModule(
        "repo:src/other.ts".to_string()
      ))
    );

    let source = b"import \"./missing.ts\";\n";
    let unresolved_dependency = OdenParentVfsDependencyObservation {
      kind: OdenParentVfsDependencyKind::StaticImport,
      raw_specifier: "./missing.ts",
      resolved_key: "repo:src/missing.ts",
      source_byte_start: 8,
      source_byte_end: 20,
      import_attributes: VFS_EMPTY_ATTRIBUTES,
    };
    let unresolved = minimal_entrypoint_module(
      source,
      OdenParentVfsMediaType::TypeScript,
      std::slice::from_ref(&unresolved_dependency),
    );
    assert_eq!(
      OdenParentVfsGraph::from_observations(&[unresolved], &[]),
      Err(OdenParentAllowlistError::UnresolvedVfsDependency {
        module: ODEN_PARENT_ENTRYPOINT_KEY.to_string(),
        resolved_key: "repo:src/missing.ts".to_string(),
      })
    );
  }

  #[test]
  fn vfs_graph_requires_every_nonmodule_file_to_be_reached() {
    let source = b"import \"oden-internal:filesystem-parent-capture-v2\";\nimport \"./asset\";\n";
    let dependencies = [
      OdenParentVfsDependencyObservation {
        kind: OdenParentVfsDependencyKind::StaticImport,
        raw_specifier: ODEN_PARENT_PRIVATE_MODULE_SPECIFIER,
        resolved_key: ODEN_PARENT_PRIVATE_MODULE_SPECIFIER,
        source_byte_start: 8,
        source_byte_end: 50,
        import_attributes: VFS_EMPTY_ATTRIBUTES,
      },
      OdenParentVfsDependencyObservation {
        kind: OdenParentVfsDependencyKind::StaticImport,
        raw_specifier: "./asset",
        resolved_key: "repo:asset",
        source_byte_start: 61,
        source_byte_end: 68,
        import_attributes: VFS_EMPTY_ATTRIBUTES,
      },
    ];
    let entrypoint = minimal_entrypoint_module(
      source,
      OdenParentVfsMediaType::TypeScript,
      &dependencies,
    );
    let file = OdenParentVfsFileObservation {
      key: "repo:asset",
      executable: false,
      original_bytes: b"asset",
      emitted_bytes: b"asset",
    };
    OdenParentVfsGraph::from_observations(&[entrypoint], &[file]).unwrap();

    assert_eq!(
      OdenParentVfsGraph::from_observations(&[entrypoint], &[]),
      Err(OdenParentAllowlistError::UnresolvedVfsDependency {
        module: ODEN_PARENT_ENTRYPOINT_KEY.to_string(),
        resolved_key: "repo:asset".to_string(),
      })
    );

    let private_only = minimal_entrypoint_module(
      b"import \"oden-internal:filesystem-parent-capture-v2\";\n",
      OdenParentVfsMediaType::TypeScript,
      std::slice::from_ref(&dependencies[0]),
    );
    assert_eq!(
      OdenParentVfsGraph::from_observations(&[private_only], &[file]),
      Err(OdenParentAllowlistError::UnreachableVfsFile(
        "repo:asset".to_string()
      ))
    );
  }

  #[test]
  fn vfs_graph_refuses_duplicate_coordinates_and_attributes() {
    let source = b"import \"./dep.ts\";\n";
    let dependency = OdenParentVfsDependencyObservation {
      kind: OdenParentVfsDependencyKind::StaticImport,
      raw_specifier: "./dep.ts",
      resolved_key: "repo:src/dep.ts",
      source_byte_start: 8,
      source_byte_end: 16,
      import_attributes: VFS_EMPTY_ATTRIBUTES,
    };
    let duplicate = OdenParentVfsDependencyObservation {
      kind: OdenParentVfsDependencyKind::DynamicImport,
      ..dependency
    };
    let dependencies = [dependency, duplicate];
    let entrypoint = minimal_entrypoint_module(
      source,
      OdenParentVfsMediaType::TypeScript,
      &dependencies,
    );
    assert_eq!(
      OdenParentVfsGraph::from_observations(&[entrypoint], &[]),
      Err(
        OdenParentAllowlistError::DuplicateVfsDependencyCoordinates {
          module: ODEN_PARENT_ENTRYPOINT_KEY.to_string(),
          source_byte_start: 8,
          source_byte_end: 16,
        }
      )
    );

    let duplicate_attributes = [
      OdenParentObservedImportAttribute {
        key: "type",
        value: "json",
      },
      OdenParentObservedImportAttribute {
        key: "type",
        value: "bytes",
      },
    ];
    let dependency = OdenParentVfsDependencyObservation {
      import_attributes: &duplicate_attributes,
      ..dependency
    };
    let entrypoint = minimal_entrypoint_module(
      source,
      OdenParentVfsMediaType::TypeScript,
      std::slice::from_ref(&dependency),
    );
    assert_eq!(
      OdenParentVfsGraph::from_observations(&[entrypoint], &[]),
      Err(OdenParentAllowlistError::DuplicateImportAttribute(
        "type".to_string()
      ))
    );
  }

  #[test]
  fn vfs_graph_treats_only_node_and_exact_private_keys_as_terminal_leaves() {
    let source = b"import \"oden-internal:filesystem-parent-capture-v2\";\nimport \"node:fs\";\n";
    let dependencies = [
      OdenParentVfsDependencyObservation {
        kind: OdenParentVfsDependencyKind::StaticImport,
        raw_specifier: ODEN_PARENT_PRIVATE_MODULE_SPECIFIER,
        resolved_key: ODEN_PARENT_PRIVATE_MODULE_SPECIFIER,
        source_byte_start: 8,
        source_byte_end: 50,
        import_attributes: VFS_EMPTY_ATTRIBUTES,
      },
      OdenParentVfsDependencyObservation {
        kind: OdenParentVfsDependencyKind::StaticImport,
        raw_specifier: "node:fs",
        resolved_key: "node:fs",
        source_byte_start: 61,
        source_byte_end: 68,
        import_attributes: VFS_EMPTY_ATTRIBUTES,
      },
    ];
    let entrypoint = minimal_entrypoint_module(
      source,
      OdenParentVfsMediaType::TypeScript,
      &dependencies,
    );
    OdenParentVfsGraph::from_observations(&[entrypoint], &[]).unwrap();
  }

  #[test]
  fn vfs_graph_requires_private_edge_to_sort_first() {
    let source = b"import \"node:fs\";\nimport \"oden-internal:filesystem-parent-capture-v2\";\n";
    let dependencies = [
      OdenParentVfsDependencyObservation {
        kind: OdenParentVfsDependencyKind::StaticImport,
        raw_specifier: "node:fs",
        resolved_key: "node:fs",
        source_byte_start: 8,
        source_byte_end: 15,
        import_attributes: VFS_EMPTY_ATTRIBUTES,
      },
      OdenParentVfsDependencyObservation {
        kind: OdenParentVfsDependencyKind::StaticImport,
        raw_specifier: ODEN_PARENT_PRIVATE_MODULE_SPECIFIER,
        resolved_key: ODEN_PARENT_PRIVATE_MODULE_SPECIFIER,
        source_byte_start: 26,
        source_byte_end: 68,
        import_attributes: VFS_EMPTY_ATTRIBUTES,
      },
    ];
    let entrypoint = minimal_entrypoint_module(
      source,
      OdenParentVfsMediaType::TypeScript,
      &dependencies,
    );
    assert_eq!(
      OdenParentVfsGraph::from_observations(&[entrypoint], &[]),
      Err(OdenParentAllowlistError::InvalidVfsPrivateEdge(
        "private edge is not the entrypoint's first sorted dependency"
      ))
    );
  }

  #[test]
  fn vfs_graph_requires_one_exact_private_entrypoint_edge() {
    let missing =
      minimal_entrypoint_module(b"", OdenParentVfsMediaType::TypeScript, &[]);
    assert_eq!(
      OdenParentVfsGraph::from_observations(&[missing], &[]),
      Err(OdenParentAllowlistError::InvalidVfsPrivateEdge(
        "private edge does not occur exactly once"
      ))
    );

    let source = b"import \"oden-internal:filesystem-parent-capture-v2\";\nimport \"oden-internal:filesystem-parent-capture-v2\";\n";
    let private_edge =
      |source_byte_start, source_byte_end| OdenParentVfsDependencyObservation {
        kind: OdenParentVfsDependencyKind::StaticImport,
        raw_specifier: ODEN_PARENT_PRIVATE_MODULE_SPECIFIER,
        resolved_key: ODEN_PARENT_PRIVATE_MODULE_SPECIFIER,
        source_byte_start,
        source_byte_end,
        import_attributes: VFS_EMPTY_ATTRIBUTES,
      };
    let dependencies = [private_edge(8, 50), private_edge(61, 103)];
    let duplicate = minimal_entrypoint_module(
      source,
      OdenParentVfsMediaType::TypeScript,
      &dependencies,
    );
    assert_eq!(
      OdenParentVfsGraph::from_observations(&[duplicate], &[]),
      Err(OdenParentAllowlistError::InvalidVfsPrivateEdge(
        "private edge does not occur exactly once"
      ))
    );

    let nonempty_attributes = [OdenParentObservedImportAttribute {
      key: "type",
      value: "json",
    }];
    for (module, kind, raw, resolved, attributes) in [
      (
        "repo:src/other.ts",
        OdenParentVfsDependencyKind::StaticImport,
        ODEN_PARENT_PRIVATE_MODULE_SPECIFIER,
        ODEN_PARENT_PRIVATE_MODULE_SPECIFIER,
        VFS_EMPTY_ATTRIBUTES,
      ),
      (
        ODEN_PARENT_ENTRYPOINT_KEY,
        OdenParentVfsDependencyKind::DynamicImport,
        ODEN_PARENT_PRIVATE_MODULE_SPECIFIER,
        ODEN_PARENT_PRIVATE_MODULE_SPECIFIER,
        VFS_EMPTY_ATTRIBUTES,
      ),
      (
        ODEN_PARENT_ENTRYPOINT_KEY,
        OdenParentVfsDependencyKind::StaticImport,
        "./capture.ts",
        ODEN_PARENT_PRIVATE_MODULE_SPECIFIER,
        VFS_EMPTY_ATTRIBUTES,
      ),
      (
        ODEN_PARENT_ENTRYPOINT_KEY,
        OdenParentVfsDependencyKind::StaticImport,
        ODEN_PARENT_PRIVATE_MODULE_SPECIFIER,
        "repo:src/capture.ts",
        VFS_EMPTY_ATTRIBUTES,
      ),
      (
        ODEN_PARENT_ENTRYPOINT_KEY,
        OdenParentVfsDependencyKind::StaticImport,
        ODEN_PARENT_PRIVATE_MODULE_SPECIFIER,
        ODEN_PARENT_PRIVATE_MODULE_SPECIFIER,
        &nonempty_attributes,
      ),
    ] {
      let source = format!("import \"{raw}\";\n");
      let dependency = OdenParentVfsDependencyObservation {
        kind,
        raw_specifier: raw,
        resolved_key: resolved,
        source_byte_start: 8,
        source_byte_end: (8 + raw.len()) as u64,
        import_attributes: attributes,
      };
      assert!(matches!(
        project_vfs_dependency(module, source.as_bytes(), &dependency),
        Err(OdenParentAllowlistError::InvalidVfsDependency { .. })
      ));
    }

    let dependency = private_edge(8, 50);
    let javascript = minimal_entrypoint_module(
      b"import \"oden-internal:filesystem-parent-capture-v2\";\n",
      OdenParentVfsMediaType::JavaScript,
      std::slice::from_ref(&dependency),
    );
    assert!(matches!(
      OdenParentVfsGraph::from_observations(&[javascript], &[]),
      Err(OdenParentAllowlistError::InvalidVfsModule { .. })
    ));
  }

  #[test]
  fn vfs_dependencies_refuse_raw_scheme_laundering() {
    for raw in ["./dep.ts", "alias", "#mapped"] {
      let source = format!("import \"{raw}\";\n");
      let dependency = OdenParentVfsDependencyObservation {
        kind: OdenParentVfsDependencyKind::StaticImport,
        raw_specifier: raw,
        resolved_key: "repo:src/dep.ts",
        source_byte_start: 8,
        source_byte_end: (8 + raw.len()) as u64,
        import_attributes: VFS_EMPTY_ATTRIBUTES,
      };
      project_vfs_dependency(
        ODEN_PARENT_ENTRYPOINT_KEY,
        source.as_bytes(),
        &dependency,
      )
      .unwrap();
    }

    let jsr_raw = "jsr:@scope/pkg@^1.2.3/mod.ts";
    let source = format!("import \"{jsr_raw}\";\n");
    let jsr = OdenParentVfsDependencyObservation {
      kind: OdenParentVfsDependencyKind::StaticImport,
      raw_specifier: jsr_raw,
      resolved_key: "jsr:@scope/pkg@1.2.4/mod.ts",
      source_byte_start: 8,
      source_byte_end: (8 + jsr_raw.len()) as u64,
      import_attributes: VFS_EMPTY_ATTRIBUTES,
    };
    project_vfs_dependency(ODEN_PARENT_ENTRYPOINT_KEY, source.as_bytes(), &jsr)
      .unwrap();

    let jsr_build_raw = "jsr:@scope/pkg@1.2.3+build.a/mod.ts";
    let source = format!("import \"{jsr_build_raw}\";\n");
    let jsr_build = OdenParentVfsDependencyObservation {
      kind: OdenParentVfsDependencyKind::StaticImport,
      raw_specifier: jsr_build_raw,
      resolved_key: "jsr:@scope/pkg@1.2.3+build.a/mod.ts",
      source_byte_start: 8,
      source_byte_end: (8 + jsr_build_raw.len()) as u64,
      import_attributes: VFS_EMPTY_ATTRIBUTES,
    };
    project_vfs_dependency(
      ODEN_PARENT_ENTRYPOINT_KEY,
      source.as_bytes(),
      &jsr_build,
    )
    .unwrap();

    for raw in [
      "npm:pkg@1.0.0",
      "http://example.test/mod.ts",
      "https://example.test/mod.ts",
      "data:text/javascript,export{}",
      "blob:https://example.test/id",
      "file:///tmp/mod.ts",
      "repo:src/dep.ts",
      "custom:dep",
      "oden-internal:other",
      "jsr:@scope/pkg@latest/mod.ts",
    ] {
      let source = format!("import \"{raw}\";\n");
      let dependency = OdenParentVfsDependencyObservation {
        kind: OdenParentVfsDependencyKind::StaticImport,
        raw_specifier: raw,
        resolved_key: "repo:src/dep.ts",
        source_byte_start: 8,
        source_byte_end: (8 + raw.len()) as u64,
        import_attributes: VFS_EMPTY_ATTRIBUTES,
      };
      assert!(matches!(
        project_vfs_dependency(
          ODEN_PARENT_ENTRYPOINT_KEY,
          source.as_bytes(),
          &dependency,
        ),
        Err(OdenParentAllowlistError::InvalidVfsDependency { .. })
      ));
    }

    for (raw, resolved) in [
      ("node:fs", "repo:src/dep.ts"),
      ("./dep.ts", "node:fs"),
      ("jsr:@scope/pkg@1.2.3/mod.ts", "repo:src/dep.ts"),
      (
        "jsr:@scope/pkg@^1.2.3/mod.ts",
        "jsr:@other/pkg@1.2.4/mod.ts",
      ),
      (
        "jsr:@scope/pkg@^1.2.3/mod.ts",
        "jsr:@scope/pkg@2.0.0/mod.ts",
      ),
      (
        "jsr:@scope/pkg@1.2.3+build.a/mod.ts",
        "jsr:@scope/pkg@1.2.3+build.b/mod.ts",
      ),
      (
        "jsr:@scope/pkg@1.2.3/mod.ts",
        "jsr:@scope/pkg@1.2.3+build.a/mod.ts",
      ),
      (
        "jsr:@scope/pkg@^1.2.3+build.a/mod.ts",
        "jsr:@scope/pkg@1.2.3+build.a/mod.ts",
      ),
    ] {
      let source = format!("import \"{raw}\";\n");
      let dependency = OdenParentVfsDependencyObservation {
        kind: OdenParentVfsDependencyKind::StaticImport,
        raw_specifier: raw,
        resolved_key: resolved,
        source_byte_start: 8,
        source_byte_end: (8 + raw.len()) as u64,
        import_attributes: VFS_EMPTY_ATTRIBUTES,
      };
      assert!(matches!(
        project_vfs_dependency(
          ODEN_PARENT_ENTRYPOINT_KEY,
          source.as_bytes(),
          &dependency,
        ),
        Err(OdenParentAllowlistError::InvalidVfsDependency { .. })
      ));
    }
  }

  #[test]
  fn vfs_graph_accepts_reachable_exact_jsr_module_keys() {
    let source = b"import \"oden-internal:filesystem-parent-capture-v2\";\nimport \"jsr:@scope/pkg@1.2.3/mod.ts\";\n";
    let dependencies = [
      OdenParentVfsDependencyObservation {
        kind: OdenParentVfsDependencyKind::StaticImport,
        raw_specifier: ODEN_PARENT_PRIVATE_MODULE_SPECIFIER,
        resolved_key: ODEN_PARENT_PRIVATE_MODULE_SPECIFIER,
        source_byte_start: 8,
        source_byte_end: 50,
        import_attributes: VFS_EMPTY_ATTRIBUTES,
      },
      OdenParentVfsDependencyObservation {
        kind: OdenParentVfsDependencyKind::StaticImport,
        raw_specifier: "jsr:@scope/pkg@1.2.3/mod.ts",
        resolved_key: "jsr:@scope/pkg@1.2.3/mod.ts",
        source_byte_start: 61,
        source_byte_end: 88,
        import_attributes: VFS_EMPTY_ATTRIBUTES,
      },
    ];
    let entrypoint = minimal_entrypoint_module(
      source,
      OdenParentVfsMediaType::TypeScript,
      &dependencies,
    );
    let jsr = OdenParentVfsModuleObservation {
      key: "jsr:@scope/pkg@1.2.3/mod.ts",
      media_type: OdenParentVfsMediaType::JavaScript,
      original_bytes: b"export {};\n",
      emitted_bytes: b"export {};\n",
      source_map_bytes: None,
      dependencies: &[],
    };
    OdenParentVfsGraph::from_observations(&[entrypoint, jsr], &[]).unwrap();
  }

  #[test]
  fn static_import_edge_has_exact_preimage_and_digest() {
    let attributes = empty_import_attributes();
    let edge = OdenParentStaticImportEdge::from_observation(
      valid_static_import_edge_observation(
        STATIC_IMPORT_ENTRYPOINT_SOURCE,
        &attributes,
      ),
    )
    .unwrap();

    assert_eq!(
      edge.entrypoint_source_digest.as_str(),
      "sha256-eZBxibEvt5Bi1O2dNl_Ttk_26zeBlhoKBakZTbamdA0"
    );
    assert_eq!(
      edge.synthetic_module_source_digest.as_str(),
      "sha256-0aagkSSUwopjaS2bzw7TI_xLwvJR-49_hi6EInvzXWc"
    );
    assert_eq!(
      edge.canonical_jcs().unwrap(),
      br#"{"dependencyOrdinal":0,"entrypointSourceDigest":"sha256-eZBxibEvt5Bi1O2dNl_Ttk_26zeBlhoKBakZTbamdA0","importAttributes":{},"kind":"static-import","occurrenceCount":1,"rawSpecifier":"oden-internal:filesystem-parent-capture-v2","referrerKey":"repo:src/release.ts","resolvedSpecifier":"oden-internal:filesystem-parent-capture-v2","schema":"oden/capsec-filesystem-parent-static-import-edge/2","sourceByteEnd":63,"sourceByteStart":21,"syntheticModuleSourceDigest":"sha256-0aagkSSUwopjaS2bzw7TI_xLwvJR-49_hi6EInvzXWc"}"#
    );
    assert_eq!(
      edge.digest().unwrap().as_str(),
      "sha256-uzM8qmg3Tfn4AhqUkD1A5PcUV4xBnoNlFvLIWXOIvW8"
    );
  }

  #[test]
  fn static_import_edge_refuses_every_nonfrozen_parser_fact() {
    let empty = empty_import_attributes();
    let nonempty = OdenParentImportAttributes::from_observed_pairs(&[
      OdenParentObservedImportAttribute {
        key: "type",
        value: "json",
      },
    ])
    .unwrap();

    macro_rules! assert_rejected {
      ($field:ident, $value:expr) => {{
        let mut observation = valid_static_import_edge_observation(
          STATIC_IMPORT_ENTRYPOINT_SOURCE,
          &empty,
        );
        observation.$field = $value;
        assert_invalid_static_import_edge(observation);
      }};
    }

    assert_rejected!(dependency_ordinal, 1);
    assert_rejected!(occurrence_count, 0);
    assert_rejected!(occurrence_count, 2);
    assert_rejected!(kind, OdenParentVfsDependencyKind::StaticExport);
    assert_rejected!(kind, OdenParentVfsDependencyKind::DynamicImport);
    assert_rejected!(raw_specifier, "./capture.ts");
    assert_rejected!(resolved_specifier, "repo:src/capture.ts");
    assert_rejected!(referrer_key, "repo:src/not-release.ts");

    let mut observation = valid_static_import_edge_observation(
      STATIC_IMPORT_ENTRYPOINT_SOURCE,
      &empty,
    );
    observation.import_attributes = &nonempty;
    assert_invalid_static_import_edge(observation);
  }

  #[test]
  fn static_import_edge_refuses_unsafe_or_inexact_byte_ranges() {
    let attributes = empty_import_attributes();

    macro_rules! assert_rejected_range {
      ($start:expr, $end:expr) => {{
        let mut observation = valid_static_import_edge_observation(
          STATIC_IMPORT_ENTRYPOINT_SOURCE,
          &attributes,
        );
        observation.source_byte_start = $start;
        observation.source_byte_end = $end;
        assert_invalid_static_import_edge(observation);
      }};
    }

    assert_rejected_range!(0, 42);
    assert_rejected_range!(21, 21);
    assert_rejected_range!(63, 21);
    assert_rejected_range!(22, 63);
    assert_rejected_range!(21, 62);
    assert_rejected_range!(21, STATIC_IMPORT_ENTRYPOINT_SOURCE.len() as u64);
    assert_rejected_range!(MAX_IJSON_SAFE_INTEGER + 1, MAX_IJSON_SAFE_INTEGER);
    assert_rejected_range!(21, MAX_IJSON_SAFE_INTEGER + 1);

    let mismatched_delimiters =
      b"import capture from \"oden-internal:filesystem-parent-capture-v2';\n";
    assert_invalid_static_import_edge(valid_static_import_edge_observation(
      mismatched_delimiters,
      &attributes,
    ));

    let unsupported_delimiters =
      b"import capture from #oden-internal:filesystem-parent-capture-v2#;\n";
    assert_invalid_static_import_edge(valid_static_import_edge_observation(
      unsupported_delimiters,
      &attributes,
    ));

    let escaped_spelling =
      b"import capture from \"oden-internal:filesystem-parent-capture-v\\x32\";\n";
    assert_invalid_static_import_edge(valid_static_import_edge_observation(
      escaped_spelling,
      &attributes,
    ));
  }

  #[test]
  fn static_import_edge_uses_byte_offsets_and_refuses_invalid_sources() {
    let attributes = empty_import_attributes();
    let multibyte_prefix = "const é = 1;\nimport capture from \"oden-internal:filesystem-parent-capture-v2\";\n";
    let bytes = multibyte_prefix.as_bytes();
    let start = bytes
      .windows(ODEN_PARENT_PRIVATE_MODULE_SPECIFIER.len())
      .position(|window| {
        window == ODEN_PARENT_PRIVATE_MODULE_SPECIFIER.as_bytes()
      })
      .unwrap();
    let end = start + ODEN_PARENT_PRIVATE_MODULE_SPECIFIER.len();
    let mut observation =
      valid_static_import_edge_observation(bytes, &attributes);
    observation.source_byte_start = start as u64;
    observation.source_byte_end = end as u64;
    let edge =
      OdenParentStaticImportEdge::from_observation(observation).unwrap();
    assert_eq!(edge.source_byte_start, start as u64);
    assert_ne!(start, multibyte_prefix[..start].chars().count());

    let bom_source =
      [b"\xef\xbb\xbf".as_slice(), STATIC_IMPORT_ENTRYPOINT_SOURCE].concat();
    assert_invalid_static_import_edge(valid_static_import_edge_observation(
      &bom_source,
      &attributes,
    ));

    let invalid_utf8 =
      [b"\xff".as_slice(), STATIC_IMPORT_ENTRYPOINT_SOURCE].concat();
    assert_invalid_static_import_edge(valid_static_import_edge_observation(
      &invalid_utf8,
      &attributes,
    ));
  }

  #[test]
  fn standalone_configuration_has_exact_nested_and_outer_preimages() {
    let workspace_resolver = minimal_workspace_resolver();
    let unstable_config = UnstableConfig::default();
    let otel_config = OtelConfig::default();

    assert_eq!(
      workspace_resolver_jcs(&workspace_resolver).unwrap(),
      br#"{"catalogs":{},"import_map":null,"jsr_pkgs":[],"package_jsons":{},"pkg_json_resolution":"Enabled"}"#
    );
    assert_eq!(
      workspace_resolver_digest(&workspace_resolver)
        .unwrap()
        .as_str(),
      "sha256-5tnJCOwbbNhY6XztrtzCsCyFtVVEI52Ql9ZfPT_RzpA"
    );
    assert_eq!(
      unstable_config_jcs(&unstable_config).unwrap(),
      br#"{"detect_cjs":false,"features":[],"lazy_dynamic_imports":false,"legacy_flag_enabled":false,"npm_lazy_caching":false,"raw_imports":false,"sloppy_imports":false,"tsgo":false}"#
    );
    assert_eq!(
      unstable_config_digest(&unstable_config).unwrap().as_str(),
      "sha256-3bm9CFAujFyBxa0mC_ZuV0ohi2GzVki7a_ChzijHkcA"
    );
    assert_eq!(
      otel_config_jcs(&otel_config).unwrap(),
      br#"{"console":"Ignore","deterministic_prefix":null,"metrics_enabled":false,"propagators":[],"tracing_enabled":false}"#
    );
    assert_eq!(
      otel_config_digest(&otel_config).unwrap().as_str(),
      "sha256-5VucB53YhCjW9oYT5iPoCaq2ABFWi5lCs3QPFeObpDM"
    );

    let configuration = OdenParentStandaloneConfiguration::from_effective(
      &workspace_resolver,
      &unstable_config,
      &otel_config,
    )
    .unwrap();
    let expected = br#"{"appName":"oden","appVersion":null,"bundle":false,"caDataDigest":null,"caStores":null,"cachedOnly":false,"certificate":null,"codeCacheEnabled":true,"configFile":"$REPOSITORY/deno.json","cwd":"$REPOSITORY","denort":"$DENORT","embeddedArgs":[],"entrypointKey":"repo:src/release.ts","envFiles":[],"errorReportingUrl":null,"eszip":false,"exclude":[],"excludeUnusedNpm":false,"frozen":true,"icon":null,"ignoredTlsCertificateErrors":[],"importMapOverride":null,"include":[],"instanceCommitments":"$INSTANCE","location":null,"lockFile":"$REPOSITORY/deno.lock","logLevel":null,"minify":false,"noPrompt":true,"noTerminal":false,"noUpdateCheck":true,"nodeModulesMode":"none","npmrcOverride":null,"otelConfigDigest":"sha256-5VucB53YhCjW9oYT5iPoCaq2ABFWi5lCs3QPFeObpDM","output":"$OUTPUT","permissions":"all","preloadModules":[],"releaseBaseUrl":null,"requireModules":[],"schema":"oden/capsec-filesystem-parent-standalone-configuration/2","seed":null,"selfExtracting":false,"sourceFile":"$REPOSITORY/src/release.ts","subcommand":"compile","target":null,"typeCheck":"none","unstableConfigDigest":"sha256-3bm9CFAujFyBxa0mC_ZuV0ohi2GzVki7a_ChzijHkcA","unstableFeatures":[],"v8Flags":[],"vendor":false,"vfsCaseSensitivity":"target-default","watch":false,"workspaceResolverDigest":"sha256-5tnJCOwbbNhY6XztrtzCsCyFtVVEI52Ql9ZfPT_RzpA"}"#;
    assert_eq!(configuration.canonical_jcs().unwrap(), expected);
    assert_eq!(
      serde_json::from_slice::<serde_json::Value>(expected)
        .unwrap()
        .as_object()
        .unwrap()
        .len(),
      53
    );
    assert_eq!(
      configuration.digest().unwrap().as_str(),
      "sha256-x9M9FXwQ28M8pffL0_q_JClOqFv8mzGLNvR1FGYNe6g"
    );
  }

  #[test]
  fn standalone_configuration_refuses_every_nondefault_unstable_field() {
    let workspace_resolver = minimal_workspace_resolver();
    let otel_config = OtelConfig::default();
    let cases = [
      UnstableConfig {
        legacy_flag_enabled: true,
        ..Default::default()
      },
      UnstableConfig {
        detect_cjs: true,
        ..Default::default()
      },
      UnstableConfig {
        lazy_dynamic_imports: true,
        ..Default::default()
      },
      UnstableConfig {
        raw_imports: true,
        ..Default::default()
      },
      UnstableConfig {
        sloppy_imports: true,
        ..Default::default()
      },
      UnstableConfig {
        npm_lazy_caching: true,
        ..Default::default()
      },
      UnstableConfig {
        tsgo: true,
        ..Default::default()
      },
      UnstableConfig {
        features: vec!["kv".to_string()],
        ..Default::default()
      },
    ];
    for unstable_config in cases {
      assert_eq!(
        OdenParentStandaloneConfiguration::from_effective(
          &workspace_resolver,
          &unstable_config,
          &otel_config,
        ),
        Err(OdenParentAllowlistError::NonDefaultUnstableConfig)
      );
    }
  }

  #[test]
  fn standalone_configuration_refuses_every_nondefault_otel_field() {
    use deno_runtime::deno_telemetry::OtelPropagators;

    let workspace_resolver = minimal_workspace_resolver();
    let unstable_config = UnstableConfig::default();
    let mut tracing = OtelConfig::default();
    tracing.tracing_enabled = true;
    let mut metrics = OtelConfig::default();
    metrics.metrics_enabled = true;
    let mut capture = OtelConfig::default();
    capture.console = OtelConsoleConfig::Capture;
    let mut replace = OtelConfig::default();
    replace.console = OtelConsoleConfig::Replace;
    let mut deterministic_prefix = OtelConfig::default();
    deterministic_prefix.deterministic_prefix = Some(0);
    let mut trace_context = OtelConfig::default();
    trace_context
      .propagators
      .insert(OtelPropagators::TraceContext);
    let mut baggage = OtelConfig::default();
    baggage.propagators.insert(OtelPropagators::Baggage);
    let mut none = OtelConfig::default();
    none.propagators.insert(OtelPropagators::None);

    for otel_config in [
      tracing,
      metrics,
      capture,
      replace,
      deterministic_prefix,
      trace_context,
      baggage,
      none,
    ] {
      assert_eq!(
        OdenParentStandaloneConfiguration::from_effective(
          &workspace_resolver,
          &unstable_config,
          &otel_config,
        ),
        Err(OdenParentAllowlistError::NonDefaultOtelConfig)
      );
    }
  }

  #[test]
  fn standalone_configuration_binds_the_actual_workspace_projection() {
    let minimal = minimal_workspace_resolver();
    let catalogued: SerializedWorkspaceResolver =
      serde_json::from_value(serde_json::json!({
        "catalogs": { "release": { "example": "jsr:@scope/example@1.0.0" } },
        "import_map": null,
        "jsr_pkgs": [],
        "package_jsons": {},
        "pkg_json_resolution": "Enabled",
      }))
      .unwrap();
    let unstable_config = UnstableConfig::default();
    let otel_config = OtelConfig::default();
    let minimal = OdenParentStandaloneConfiguration::from_effective(
      &minimal,
      &unstable_config,
      &otel_config,
    )
    .unwrap();
    let catalogued = OdenParentStandaloneConfiguration::from_effective(
      &catalogued,
      &unstable_config,
      &otel_config,
    )
    .unwrap();
    assert_ne!(minimal.digest().unwrap(), catalogued.digest().unwrap());
  }

  #[test]
  fn inventories_refuse_invalid_membership() {
    assert_eq!(
      ContractInventory::from_files(&[]),
      Err(OdenParentAllowlistError::EmptyInventory)
    );
    for path in ["", "/a", "a//b", "a/./b", "a/../b", "a\\b", "unicode/é"] {
      assert!(matches!(
        ContractInventory::from_files(&[ContractFile { path, bytes: b"x" }]),
        Err(OdenParentAllowlistError::InvalidContractPath(_))
      ));
    }
    for path in ODEN_PARENT_GENERATED_PATHS {
      for path in [path.to_string(), path.to_ascii_uppercase()] {
        assert_eq!(
          ContractInventory::from_files(&[ContractFile {
            path: &path,
            bytes: b"x",
          }]),
          Err(OdenParentAllowlistError::GeneratedOutputMember(path))
        );
      }
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
  fn production_allowlist_constructor_derives_only_typed_input_digests() {
    let capture = ContractInventory::from_files(&[ContractFile {
      path: "capture",
      bytes: b"capture-v1",
    }])
    .unwrap();
    let source_closure = ContractInventory::from_files(&[ContractFile {
      path: "source-closure",
      bytes: b"source-closure-v1",
    }])
    .unwrap();
    let release = ContractInventory::from_files(&[ContractFile {
      path: "release",
      bytes: b"release-v1",
    }])
    .unwrap();
    let workspace_resolver = minimal_workspace_resolver();
    let configuration = OdenParentStandaloneConfiguration::from_effective(
      &workspace_resolver,
      &UnstableConfig::default(),
      &OtelConfig::default(),
    )
    .unwrap();
    let attributes = empty_import_attributes();
    let mut static_import_edge_observation =
      valid_static_import_edge_observation(VFS_ENTRYPOINT_SOURCE, &attributes);
    static_import_edge_observation.source_byte_start = 8;
    static_import_edge_observation.source_byte_end = 50;
    let static_import_edge = OdenParentStaticImportEdge::from_observation(
      static_import_edge_observation,
    )
    .unwrap();
    let dependencies = exact_vfs_dependencies();
    let modules = exact_vfs_modules(&dependencies);
    let files = exact_vfs_files();
    let vfs_graph =
      OdenParentVfsGraph::from_observations(&modules, &files).unwrap();

    let mut mismatched_entrypoint_source = VFS_ENTRYPOINT_SOURCE.to_vec();
    let declaration = mismatched_entrypoint_source
      .windows(b"const dep".len())
      .position(|window| window == b"const dep")
      .unwrap();
    mismatched_entrypoint_source[declaration + 6] = b'D';
    let mut mismatched_edge_observation = valid_static_import_edge_observation(
      &mismatched_entrypoint_source,
      &attributes,
    );
    mismatched_edge_observation.source_byte_start = 8;
    mismatched_edge_observation.source_byte_end = 50;
    let mismatched_static_import_edge =
      OdenParentStaticImportEdge::from_observation(mismatched_edge_observation)
        .unwrap();
    assert!(matches!(
      OdenParentAllowlist::from_inputs(OdenParentAllowlistInputs {
        capture_contract: &capture,
        source_closure_contract: &source_closure,
        release_contract: &release,
        configuration: &configuration,
        vfs_graph: &vfs_graph,
        static_import_edge: &mismatched_static_import_edge,
      }),
      Err(OdenParentAllowlistError::InconsistentAllowlistInputs(_))
    ));

    let construct =
      |capture_contract: &ContractInventory,
       source_closure_contract: &ContractInventory,
       release_contract: &ContractInventory,
       configuration: &OdenParentStandaloneConfiguration,
       vfs_graph: &OdenParentVfsGraph,
       static_import_edge: &OdenParentStaticImportEdge| {
        OdenParentAllowlist::from_inputs(OdenParentAllowlistInputs {
          capture_contract,
          source_closure_contract,
          release_contract,
          configuration,
          vfs_graph,
          static_import_edge,
        })
        .unwrap()
      };
    let allowlist = construct(
      &capture,
      &source_closure,
      &release,
      &configuration,
      &vfs_graph,
      &static_import_edge,
    );

    assert_eq!(
      allowlist.capture_contract_digest,
      capture.digest(ContractInventoryKind::Capture).unwrap()
    );
    assert_eq!(
      allowlist.source_closure_contract_digest,
      source_closure
        .digest(ContractInventoryKind::SourceClosure)
        .unwrap()
    );
    assert_eq!(
      allowlist.release_contract_digest,
      release.digest(ContractInventoryKind::Release).unwrap()
    );
    assert_ne!(
      capture.digest(ContractInventoryKind::Capture).unwrap(),
      capture
        .digest(ContractInventoryKind::SourceClosure)
        .unwrap()
    );
    assert_ne!(
      release.digest(ContractInventoryKind::Release).unwrap(),
      release.digest(ContractInventoryKind::Capture).unwrap()
    );
    assert_ne!(
      source_closure
        .digest(ContractInventoryKind::SourceClosure)
        .unwrap(),
      source_closure
        .digest(ContractInventoryKind::Release)
        .unwrap()
    );
    assert_eq!(
      allowlist.entrypoint_source_digest,
      static_import_edge.entrypoint_source_digest
    );
    assert_eq!(
      allowlist.synthetic_module_source_digest,
      static_import_edge.synthetic_module_source_digest
    );
    assert_eq!(
      allowlist.static_import_edge_digest,
      static_import_edge.digest().unwrap()
    );
    assert_eq!(
      allowlist.standalone_configuration_digest,
      configuration.digest().unwrap()
    );
    assert_eq!(allowlist.vfs_graph_digest, vfs_graph.digest().unwrap());
    let allowlist_value = serde_json::from_slice::<serde_json::Value>(
      &allowlist.canonical_jcs().unwrap(),
    )
    .unwrap();
    let allowlist_object = allowlist_value.as_object().unwrap();
    assert_eq!(allowlist_object.len(), 14);
    for (field, expected) in [
      ("schema", ODEN_PARENT_ALLOWLIST_SCHEMA),
      ("profile", ODEN_PARENT_PROFILE),
      ("entrypointKey", ODEN_PARENT_ENTRYPOINT_KEY),
      ("parentPrimitiveId", ODEN_PARENT_PRIMITIVE_ID),
      (
        "privateModuleSpecifier",
        ODEN_PARENT_PRIVATE_MODULE_SPECIFIER,
      ),
    ] {
      assert_eq!(
        allowlist_object.get(field).and_then(|value| value.as_str()),
        Some(expected)
      );
    }
    assert_eq!(
      allowlist_object
        .get("engineProvenanceSchema")
        .and_then(|value| value.as_u64()),
      Some(2)
    );
    assert_eq!(allowlist.render_json_file().unwrap().last(), Some(&b'\n'));
    assert_eq!(
      allowlist.render_rust_module().unwrap(),
      allowlist.render_rust_module().unwrap()
    );

    let assert_only_fields_change =
      |left: &OdenParentAllowlist,
       right: &OdenParentAllowlist,
       fields: &[&str]| {
        let mut left_value = serde_json::to_value(left)
          .unwrap()
          .as_object()
          .unwrap()
          .clone();
        let mut right_value = serde_json::to_value(right)
          .unwrap()
          .as_object()
          .unwrap()
          .clone();
        for field in fields {
          assert_ne!(left_value.get(*field), right_value.get(*field));
          left_value.remove(*field);
          right_value.remove(*field);
        }
        assert_eq!(left_value, right_value);
        assert_ne!(left.digest().unwrap(), right.digest().unwrap());
      };

    let changed_capture = ContractInventory::from_files(&[ContractFile {
      path: "capture",
      bytes: b"capture-v2",
    }])
    .unwrap();
    let changed_source_closure =
      ContractInventory::from_files(&[ContractFile {
        path: "source-closure",
        bytes: b"source-closure-v2",
      }])
      .unwrap();
    let changed_release = ContractInventory::from_files(&[ContractFile {
      path: "release",
      bytes: b"release-v2",
    }])
    .unwrap();
    assert_only_fields_change(
      &allowlist,
      &construct(
        &changed_capture,
        &source_closure,
        &release,
        &configuration,
        &vfs_graph,
        &static_import_edge,
      ),
      &["captureContractDigest"],
    );
    assert_only_fields_change(
      &allowlist,
      &construct(
        &capture,
        &changed_source_closure,
        &release,
        &configuration,
        &vfs_graph,
        &static_import_edge,
      ),
      &["sourceClosureContractDigest"],
    );
    assert_only_fields_change(
      &allowlist,
      &construct(
        &capture,
        &source_closure,
        &changed_release,
        &configuration,
        &vfs_graph,
        &static_import_edge,
      ),
      &["releaseContractDigest"],
    );

    let changed_workspace_resolver: SerializedWorkspaceResolver =
      serde_json::from_value(serde_json::json!({
        "catalogs": { "release": { "example": "jsr:@scope/example@1.0.0" } },
        "import_map": null,
        "jsr_pkgs": [],
        "package_jsons": {},
        "pkg_json_resolution": "Enabled",
      }))
      .unwrap();
    let changed_configuration =
      OdenParentStandaloneConfiguration::from_effective(
        &changed_workspace_resolver,
        &UnstableConfig::default(),
        &OtelConfig::default(),
      )
      .unwrap();
    assert_only_fields_change(
      &allowlist,
      &construct(
        &capture,
        &source_closure,
        &release,
        &changed_configuration,
        &vfs_graph,
        &static_import_edge,
      ),
      &["standaloneConfigurationDigest"],
    );

    let mut changed_files = exact_vfs_files();
    changed_files[0].emitted_bytes = b"#!/bin/sh\n# changed\n";
    let changed_vfs_graph =
      OdenParentVfsGraph::from_observations(&modules, &changed_files).unwrap();
    assert_only_fields_change(
      &allowlist,
      &construct(
        &capture,
        &source_closure,
        &release,
        &configuration,
        &changed_vfs_graph,
        &static_import_edge,
      ),
      &["vfsGraphDigest"],
    );

    let mut changed_entrypoint_source = VFS_ENTRYPOINT_SOURCE.to_vec();
    let declaration = changed_entrypoint_source
      .windows(b"const dep".len())
      .position(|window| window == b"const dep")
      .unwrap();
    changed_entrypoint_source[declaration + 6] = b'D';
    let mut changed_entrypoint_observation =
      valid_static_import_edge_observation(
        &changed_entrypoint_source,
        &attributes,
      );
    changed_entrypoint_observation.source_byte_start = 8;
    changed_entrypoint_observation.source_byte_end = 50;
    let changed_entrypoint_edge = OdenParentStaticImportEdge::from_observation(
      changed_entrypoint_observation,
    )
    .unwrap();
    let changed_dependencies = exact_vfs_dependencies();
    let mut changed_modules = exact_vfs_modules(&changed_dependencies);
    changed_modules
      .iter_mut()
      .find(|module| module.key == ODEN_PARENT_ENTRYPOINT_KEY)
      .unwrap()
      .original_bytes = &changed_entrypoint_source;
    let changed_entrypoint_vfs_graph =
      OdenParentVfsGraph::from_observations(&changed_modules, &files).unwrap();
    assert_only_fields_change(
      &allowlist,
      &construct(
        &capture,
        &source_closure,
        &release,
        &configuration,
        &changed_entrypoint_vfs_graph,
        &changed_entrypoint_edge,
      ),
      &[
        "entrypointSourceDigest",
        "staticImportEdgeDigest",
        "vfsGraphDigest",
      ],
    );
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

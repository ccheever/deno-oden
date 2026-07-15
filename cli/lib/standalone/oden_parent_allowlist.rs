// Copyright 2018-2026 the Deno authors. MIT license.

// @ref LLP 0019#frozen-parent-standalone-allowlist-and-byte-graph [implements] —
// This first fail-closed slice keeps the reviewed contract inventories and
// parent-allowlist rendering as exact raw-byte and domain-separated canonical-
// JSON projections. It intentionally exposes no allowlist constructor while
// the VFS/static-edge projectors, generator, and startup recomputation gates
// remain absent; generated outputs and later image/evidence authority are
// absent as well.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use deno_runtime::deno_telemetry::OtelConfig;
use deno_runtime::deno_telemetry::OtelConsoleConfig;
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
pub const ODEN_PARENT_IMPORT_ATTRIBUTES_DIGEST_DOMAIN: &str =
  "oden:capsec:filesystem-parent-import-attributes:2";
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
  #[error("parent unstable configuration is not exactly all-disabled")]
  NonDefaultUnstableConfig,
  #[error("parent OTEL configuration is not exactly all-disabled")]
  NonDefaultOtelConfig,
  #[error("duplicate decoded import-attribute key: {0}")]
  DuplicateImportAttribute(String),
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
  standalone_configuration_digest: OdenParentStandaloneConfigurationDigest,
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

// Copyright 2018-2026 the Deno authors. MIT license.

use std::borrow::Cow;
use std::collections::BTreeMap;

use deno_media_type::MediaType;
use deno_resolver::workspace::PackageJsonDepResolution;
use deno_runtime::deno_permissions::PermissionsOptions;
use deno_runtime::deno_telemetry::OtelConfig;
use deno_semver::Version;
use indexmap::IndexMap;
use serde::Deserialize;
use serde::Serialize;
use url::Url;

use super::virtual_fs::FileSystemCaseSensitivity;
use crate::args::UnstableConfig;

pub const MAGIC_BYTES: &[u8; 8] = b"d3n0l4nd";

pub const ODEN_PARENT_CAPTURE_V2_METADATA_SCHEMA: &str =
  "oden/capsec-filesystem-parent-standalone-metadata/2";
pub const ODEN_PARENT_CAPTURE_V2_METADATA_DIGEST_DOMAIN: &str =
  "oden:capsec:filesystem-parent-standalone-metadata:2";
pub const ODEN_PARENT_CAPTURE_V2_MODULE_SPECIFIER: &str =
  "oden-internal:filesystem-parent-capture-v2";
pub const ODEN_PARENT_CAPTURE_V2_PRIMITIVE_ID: &str =
  "oden.filesystem-parent-capture/2";
pub const ODEN_CAPSEC_REV2_PROFILE: &str = "oden/capsec/2";

pub trait DenoRtDeserializable<'a>: Sized {
  fn deserialize(input: &'a [u8]) -> std::io::Result<(&'a [u8], Self)>;
}

impl<'a> DenoRtDeserializable<'a> for Cow<'a, [u8]> {
  fn deserialize(input: &'a [u8]) -> std::io::Result<(&'a [u8], Self)> {
    let (input, data) = read_bytes_with_u32_len(input)?;
    Ok((input, Cow::Borrowed(data)))
  }
}

pub trait DenoRtSerializable<'a> {
  fn serialize(
    &'a self,
    builder: &mut capacity_builder::BytesBuilder<'a, Vec<u8>>,
  );
}

#[derive(Deserialize, Serialize)]
pub enum NodeModules {
  Managed {
    /// Relative path for the node_modules directory in the vfs.
    node_modules_dir: Option<String>,
  },
  Byonm {
    root_node_modules_dir: Option<String>,
  },
}

#[derive(Deserialize, Serialize)]
pub struct SerializedWorkspaceResolverImportMap {
  pub specifier: String,
  pub json: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SerializedResolverWorkspaceJsrPackage {
  pub relative_base: String,
  pub name: String,
  pub version: Option<Version>,
  pub exports: IndexMap<String, String>,
}

#[derive(Deserialize, Serialize)]
pub struct SerializedWorkspaceResolver {
  pub import_map: Option<SerializedWorkspaceResolverImportMap>,
  pub jsr_pkgs: Vec<SerializedResolverWorkspaceJsrPackage>,
  pub package_jsons: BTreeMap<String, serde_json::Value>,
  pub pkg_json_resolution: PackageJsonDepResolution,
  #[serde(default)]
  pub catalogs: IndexMap<String, IndexMap<String, String>>,
}

// @ref LLP 0019#pre-promotion-conformance-candidate-execution [implements] —
// Reserve the exact closed standalone-parent record without enabling its
// private extension. Generic and older standalone metadata omit this field.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OdenParentCaptureV2Metadata {
  pub schema: String,
  pub profile: String,
  pub target: String,
  pub feature_set: String,
  pub fork_commit: String,
  pub parent_build_marker: String,
  pub denort_base_image_digest: String,
  pub entrypoint_key: String,
  pub entrypoint_source_digest: String,
  pub vfs_graph_digest: String,
  pub private_module_specifier: String,
  pub static_import_edge_digest: String,
  pub parent_primitive_id: String,
  pub paired_engine_build_marker: String,
  pub paired_engine_digest: String,
  pub engine_provenance_schema: u8,
  pub capture_contract_digest: String,
  pub source_closure_contract_digest: String,
  pub release_contract_digest: String,
  pub generated_allowlist_digest: String,
}

impl OdenParentCaptureV2Metadata {
  /// Validate the closed wire-level syntax before any generated allowlist or
  /// image-specific relation is consulted. Passing this check alone never
  /// enables the private parent extension.
  pub fn validate_closed_syntax(&self) -> Result<(), &'static str> {
    if self.schema != ODEN_PARENT_CAPTURE_V2_METADATA_SCHEMA {
      return Err("metadata schema is not the frozen Oden parent schema");
    }
    if self.profile != ODEN_CAPSEC_REV2_PROFILE {
      return Err("metadata profile is not Oden capsec Rev2");
    }
    if !matches!(
      self.target.as_str(),
      "aarch64-apple-darwin"
        | "x86_64-apple-darwin"
        | "aarch64-unknown-linux-gnu"
        | "x86_64-unknown-linux-gnu"
    ) {
      return Err("metadata target is not in the Oden v1 release matrix");
    }
    if !is_oden_parent_token(&self.feature_set, 1, 128)
      || !is_oden_parent_token(&self.parent_build_marker, 1, 256)
      || !is_oden_parent_token(&self.paired_engine_build_marker, 1, 256)
    {
      return Err("metadata feature set or build marker is malformed");
    }
    if !is_lower_hex(&self.fork_commit, 40) {
      return Err("metadata fork commit is malformed");
    }
    if self.entrypoint_key.is_empty()
      || self.entrypoint_key.len() > 4096
      || self.entrypoint_key.bytes().any(|byte| byte == 0)
    {
      return Err("metadata entrypoint key is malformed");
    }
    if self.private_module_specifier != ODEN_PARENT_CAPTURE_V2_MODULE_SPECIFIER
    {
      return Err("metadata private module specifier is not frozen");
    }
    if self.parent_primitive_id != ODEN_PARENT_CAPTURE_V2_PRIMITIVE_ID {
      return Err("metadata parent primitive id is not frozen");
    }
    if self.engine_provenance_schema != 2 {
      return Err("metadata engine provenance schema is unsupported");
    }
    for digest in [
      &self.denort_base_image_digest,
      &self.entrypoint_source_digest,
      &self.vfs_graph_digest,
      &self.static_import_edge_digest,
      &self.paired_engine_digest,
      &self.capture_contract_digest,
      &self.source_closure_contract_digest,
      &self.release_contract_digest,
      &self.generated_allowlist_digest,
    ] {
      if !is_sha256_base64url_digest(digest) {
        return Err("metadata contains a malformed digest");
      }
    }
    Ok(())
  }
}

fn is_lower_hex(value: &str, length: usize) -> bool {
  value.len() == length
    && value
      .bytes()
      .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_sha256_base64url_digest(value: &str) -> bool {
  let Some(value) = value.strip_prefix("sha256-") else {
    return false;
  };
  value.len() == 43
    && value
      .bytes()
      .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

fn is_oden_parent_token(value: &str, minimum: usize, maximum: usize) -> bool {
  (minimum..=maximum).contains(&value.len())
    && value.bytes().all(|byte| {
      byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-')
    })
}

// Note: Don't use hashmaps/hashsets. Ensure the serialization
// is deterministic.
#[derive(Deserialize, Serialize)]
pub struct Metadata {
  pub argv: Vec<String>,
  pub seed: Option<u64>,
  pub code_cache_key: Option<u64>,
  pub permissions: PermissionsOptions,
  pub location: Option<Url>,
  pub v8_flags: Vec<String>,
  pub log_level: Option<log::Level>,
  pub ca_stores: Option<Vec<String>>,
  pub ca_data: Option<Vec<u8>>,
  pub unsafely_ignore_certificate_errors: Option<Vec<String>>,
  pub env_vars_from_env_file: IndexMap<String, String>,
  pub workspace_resolver: SerializedWorkspaceResolver,
  pub entrypoint_key: String,
  pub preload_modules: Vec<String>,
  pub require_modules: Vec<String>,
  pub node_modules: Option<NodeModules>,
  pub unstable_config: UnstableConfig,
  pub otel_config: OtelConfig,
  pub vfs_case_sensitivity: FileSystemCaseSensitivity,
  /// When set, the binary is self-extracting. The value is a precomputed
  /// hash of the VFS data used for versioning the extraction directory.
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub self_extracting: Option<String>,
  /// Stable identity for the compiled app, used to locate its persistent
  /// origin storage (default `Deno.openKv()`, `localStorage`, `caches`).
  /// Resolved at compile time from `--app-name`, falling back to the output
  /// file name.
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub app_name: Option<String>,
  /// Application version from deno.json or package.json, used for
  /// auto-update support in desktop apps.
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub app_version: Option<String>,
  /// Error reporting URL from deno.json `desktop.errorReporting.url`.
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub error_reporting_url: Option<String>,
  /// Auto-update release base URL from deno.json `desktop.release.baseUrl`.
  #[serde(default, skip_serializing_if = "Option::is_none")]
  pub release_base_url: Option<String>,
  /// Exact Oden-only parent-capture brand. Absence preserves generic
  /// standalone compatibility; presence is fail-closed until native startup
  /// validates the complete record and private module graph.
  #[serde(
    default,
    rename = "odenParentCaptureV2",
    skip_serializing_if = "Option::is_none"
  )]
  pub oden_parent_capture_v2: Option<OdenParentCaptureV2Metadata>,
}

#[cfg(test)]
mod oden_parent_capture_v2_metadata_tests {
  use super::*;

  fn record_json() -> serde_json::Value {
    serde_json::json!({
      "schema": ODEN_PARENT_CAPTURE_V2_METADATA_SCHEMA,
      "profile": "oden/capsec/2",
      "target": "x86_64-unknown-linux-gnu",
      "featureSet": "default",
      "forkCommit": "1".repeat(40),
      "parentBuildMarker": "oden-parent-build-v2",
      "denortBaseImageDigest": "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      "entrypointKey": "src/main.ts",
      "entrypointSourceDigest": "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      "vfsGraphDigest": "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      "privateModuleSpecifier": ODEN_PARENT_CAPTURE_V2_MODULE_SPECIFIER,
      "staticImportEdgeDigest": "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      "parentPrimitiveId": "oden.filesystem-parent-capture/2",
      "pairedEngineBuildMarker": "oden-engine-build-v2",
      "pairedEngineDigest": "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      "engineProvenanceSchema": 2,
      "captureContractDigest": "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      "sourceClosureContractDigest": "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      "releaseContractDigest": "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
      "generatedAllowlistDigest": "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    })
  }

  #[test]
  fn parent_record_has_exact_camel_case_wire_shape() {
    let record: OdenParentCaptureV2Metadata =
      serde_json::from_value(record_json()).unwrap();
    assert_eq!(record.schema, ODEN_PARENT_CAPTURE_V2_METADATA_SCHEMA);
    assert_eq!(
      record.private_module_specifier,
      ODEN_PARENT_CAPTURE_V2_MODULE_SPECIFIER
    );
    record.validate_closed_syntax().unwrap();
    assert_eq!(serde_json::to_value(record).unwrap(), record_json());
  }

  #[test]
  fn parent_record_rejects_unknown_fields() {
    let mut value = record_json();
    value
      .as_object_mut()
      .unwrap()
      .insert("extra".to_string(), serde_json::Value::Bool(true));
    assert!(
      serde_json::from_value::<OdenParentCaptureV2Metadata>(value).is_err()
    );
  }

  #[test]
  fn parent_record_closed_syntax_refuses_wrong_identity() {
    for (field, replacement) in [
      ("schema", serde_json::json!("wrong")),
      ("profile", serde_json::json!("oden/capsec/1.1")),
      ("target", serde_json::json!("x86_64-pc-windows-msvc")),
      ("forkCommit", serde_json::json!("A".repeat(40))),
      (
        "privateModuleSpecifier",
        serde_json::json!("oden-internal:other"),
      ),
      ("engineProvenanceSchema", serde_json::json!(1)),
      ("pairedEngineDigest", serde_json::json!("sha256-short")),
    ] {
      let mut value = record_json();
      value
        .as_object_mut()
        .unwrap()
        .insert(field.to_string(), replacement);
      let record: OdenParentCaptureV2Metadata =
        serde_json::from_value(value).unwrap();
      assert!(record.validate_closed_syntax().is_err(), "accepted {field}");
    }
  }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct SpecifierId(u32);

impl SpecifierId {
  pub fn new(id: u32) -> Self {
    Self(id)
  }
}

impl<'a> capacity_builder::BytesAppendable<'a> for SpecifierId {
  fn append_to_builder<TBytes: capacity_builder::BytesType>(
    self,
    builder: &mut capacity_builder::BytesBuilder<'a, TBytes>,
  ) {
    builder.append_le(self.0);
  }
}

impl<'a> DenoRtSerializable<'a> for SpecifierId {
  fn serialize(
    &'a self,
    builder: &mut capacity_builder::BytesBuilder<'a, Vec<u8>>,
  ) {
    builder.append_le(self.0);
  }
}

impl<'a> DenoRtDeserializable<'a> for SpecifierId {
  fn deserialize(input: &'a [u8]) -> std::io::Result<(&'a [u8], Self)> {
    let (input, id) = read_u32(input)?;
    Ok((input, Self(id)))
  }
}

#[derive(Deserialize, Serialize)]
pub enum CjsExportAnalysisEntry {
  Esm,
  Cjs(Vec<String>),
  Error(String),
}

const HAS_TRANSPILED_FLAG: u8 = 1 << 0;
const HAS_SOURCE_MAP_FLAG: u8 = 1 << 1;
const HAS_CJS_EXPORT_ANALYSIS_FLAG: u8 = 1 << 2;
const HAS_VALID_UTF8_FLAG: u8 = 1 << 3;

pub struct RemoteModuleEntry<'a> {
  pub media_type: MediaType,
  pub is_valid_utf8: bool,
  pub data: Cow<'a, [u8]>,
  pub maybe_transpiled: Option<Cow<'a, [u8]>>,
  pub maybe_source_map: Option<Cow<'a, [u8]>>,
  pub maybe_cjs_export_analysis: Option<Cow<'a, [u8]>>,
}

impl<'a> DenoRtSerializable<'a> for RemoteModuleEntry<'a> {
  fn serialize(
    &'a self,
    builder: &mut capacity_builder::BytesBuilder<'a, Vec<u8>>,
  ) {
    fn append_maybe_data<'a>(
      builder: &mut capacity_builder::BytesBuilder<'a, Vec<u8>>,
      maybe_data: Option<&'a [u8]>,
    ) {
      if let Some(data) = maybe_data {
        builder.append_le(data.len() as u32);
        builder.append(data);
      }
    }

    let mut has_data_flags = 0;
    if self.is_valid_utf8 {
      has_data_flags |= HAS_VALID_UTF8_FLAG;
    }
    if self.maybe_transpiled.is_some() {
      has_data_flags |= HAS_TRANSPILED_FLAG;
    }
    if self.maybe_source_map.is_some() {
      has_data_flags |= HAS_SOURCE_MAP_FLAG;
    }
    if self.maybe_cjs_export_analysis.is_some() {
      has_data_flags |= HAS_CJS_EXPORT_ANALYSIS_FLAG;
    }
    builder.append(serialize_media_type(self.media_type));
    builder.append_le(self.data.len() as u32);
    builder.append(self.data.as_ref());
    builder.append(has_data_flags);
    append_maybe_data(builder, self.maybe_transpiled.as_deref());
    append_maybe_data(builder, self.maybe_source_map.as_deref());
    append_maybe_data(builder, self.maybe_cjs_export_analysis.as_deref());
  }
}

impl<'a> DenoRtDeserializable<'a> for RemoteModuleEntry<'a> {
  fn deserialize(input: &'a [u8]) -> std::io::Result<(&'a [u8], Self)> {
    #[allow(clippy::type_complexity, reason = "private code")]
    fn deserialize_data_if_has_flag(
      input: &[u8],
      has_data_flags: u8,
      flag: u8,
    ) -> std::io::Result<(&[u8], Option<Cow<'_, [u8]>>)> {
      if has_data_flags & flag != 0 {
        let (input, bytes) = read_bytes_with_u32_len(input)?;
        Ok((input, Some(Cow::Borrowed(bytes))))
      } else {
        Ok((input, None))
      }
    }

    let (input, media_type) = MediaType::deserialize(input)?;
    let (input, data) = read_bytes_with_u32_len(input)?;
    let (input, has_data_flags) = read_u8(input)?;
    let (input, maybe_transpiled) =
      deserialize_data_if_has_flag(input, has_data_flags, HAS_TRANSPILED_FLAG)?;
    let (input, maybe_source_map) =
      deserialize_data_if_has_flag(input, has_data_flags, HAS_SOURCE_MAP_FLAG)?;
    let is_valid_utf8 = has_data_flags & HAS_VALID_UTF8_FLAG != 0;
    let (input, maybe_cjs_export_analysis) = deserialize_data_if_has_flag(
      input,
      has_data_flags,
      HAS_CJS_EXPORT_ANALYSIS_FLAG,
    )?;
    Ok((
      input,
      Self {
        media_type,
        data: Cow::Borrowed(data),
        is_valid_utf8,
        maybe_transpiled,
        maybe_source_map,
        maybe_cjs_export_analysis,
      },
    ))
  }
}

fn serialize_media_type(media_type: MediaType) -> u8 {
  match media_type {
    MediaType::JavaScript => 0,
    MediaType::Jsx => 1,
    MediaType::Mjs => 2,
    MediaType::Cjs => 3,
    MediaType::TypeScript => 4,
    MediaType::Mts => 5,
    MediaType::Cts => 6,
    MediaType::Dts => 7,
    MediaType::Dmts => 8,
    MediaType::Dcts => 9,
    MediaType::Tsx => 10,
    MediaType::Json => 11,
    MediaType::Jsonc => 12,
    MediaType::Json5 => 13,
    MediaType::Markdown => 14,
    MediaType::Wasm => 15,
    MediaType::Css => 16,
    MediaType::Html => 17,
    MediaType::SourceMap => 18,
    MediaType::Sql => 19,
    MediaType::Unknown => 20,
  }
}

impl<'a> DenoRtDeserializable<'a> for MediaType {
  fn deserialize(input: &'a [u8]) -> std::io::Result<(&'a [u8], Self)> {
    let (input, value) = read_u8(input)?;
    let value = match value {
      0 => MediaType::JavaScript,
      1 => MediaType::Jsx,
      2 => MediaType::Mjs,
      3 => MediaType::Cjs,
      4 => MediaType::TypeScript,
      5 => MediaType::Mts,
      6 => MediaType::Cts,
      7 => MediaType::Dts,
      8 => MediaType::Dmts,
      9 => MediaType::Dcts,
      10 => MediaType::Tsx,
      11 => MediaType::Json,
      12 => MediaType::Jsonc,
      13 => MediaType::Json5,
      14 => MediaType::Markdown,
      15 => MediaType::Wasm,
      16 => MediaType::Css,
      17 => MediaType::Html,
      18 => MediaType::SourceMap,
      19 => MediaType::Sql,
      20 => MediaType::Unknown,
      value => {
        return Err(std::io::Error::new(
          std::io::ErrorKind::InvalidData,
          format!("Unknown media type value: {value}"),
        ));
      }
    };
    Ok((input, value))
  }
}

/// Data stored keyed by specifier.
pub struct SpecifierDataStore<TData> {
  data: IndexMap<SpecifierId, TData>,
}

impl<TData> Default for SpecifierDataStore<TData> {
  fn default() -> Self {
    Self {
      data: IndexMap::new(),
    }
  }
}

impl<TData> SpecifierDataStore<TData> {
  pub fn with_capacity(capacity: usize) -> Self {
    Self {
      data: IndexMap::with_capacity(capacity),
    }
  }

  pub fn iter(&self) -> impl Iterator<Item = (SpecifierId, &TData)> {
    self.data.iter().map(|(k, v)| (*k, v))
  }

  #[allow(clippy::len_without_is_empty, reason = "not useful")]
  pub fn len(&self) -> usize {
    self.data.len()
  }

  pub fn contains(&self, specifier: SpecifierId) -> bool {
    self.data.contains_key(&specifier)
  }

  pub fn add(&mut self, specifier: SpecifierId, value: TData) {
    self.data.insert(specifier, value);
  }

  pub fn get(&self, specifier: SpecifierId) -> Option<&TData> {
    self.data.get(&specifier)
  }
}

impl<'a, TData> SpecifierDataStore<TData>
where
  TData: DenoRtSerializable<'a> + 'a,
{
  pub fn serialize(
    &'a self,
    builder: &mut capacity_builder::BytesBuilder<'a, Vec<u8>>,
  ) {
    builder.append_le(self.len() as u32);
    for (specifier, value) in self.iter() {
      builder.append(specifier);
      value.serialize(builder);
    }
  }
}

impl<'a, TData> DenoRtDeserializable<'a> for SpecifierDataStore<TData>
where
  TData: DenoRtDeserializable<'a>,
{
  fn deserialize(input: &'a [u8]) -> std::io::Result<(&'a [u8], Self)> {
    let (input, len) = read_u32_as_usize(input)?;
    let mut data = IndexMap::with_capacity(len);
    let mut input = input;
    for _ in 0..len {
      let (new_input, specifier) = SpecifierId::deserialize(input)?;
      let (new_input, value) = TData::deserialize(new_input)?;
      data.insert(specifier, value);
      input = new_input;
    }
    Ok((input, Self { data }))
  }
}

fn read_bytes_with_u32_len(input: &[u8]) -> std::io::Result<(&[u8], &[u8])> {
  let (input, len) = read_u32_as_usize(input)?;
  let (input, data) = read_bytes(input, len)?;
  Ok((input, data))
}

fn read_u32_as_usize(input: &[u8]) -> std::io::Result<(&[u8], usize)> {
  read_u32(input).map(|(input, len)| (input, len as usize))
}

fn read_u32(input: &[u8]) -> std::io::Result<(&[u8], u32)> {
  let (input, len_bytes) = read_bytes(input, 4)?;
  let len = u32::from_le_bytes(len_bytes.try_into().unwrap());
  Ok((input, len))
}

fn read_u8(input: &[u8]) -> std::io::Result<(&[u8], u8)> {
  check_has_len(input, 1)?;
  Ok((&input[1..], input[0]))
}

fn read_bytes(input: &[u8], len: usize) -> std::io::Result<(&[u8], &[u8])> {
  check_has_len(input, len)?;
  let (len_bytes, input) = input.split_at(len);
  Ok((input, len_bytes))
}

#[inline(always)]
fn check_has_len(input: &[u8], len: usize) -> std::io::Result<()> {
  if input.len() < len {
    Err(std::io::Error::new(
      std::io::ErrorKind::InvalidData,
      "Unexpected end of data",
    ))
  } else {
    Ok(())
  }
}

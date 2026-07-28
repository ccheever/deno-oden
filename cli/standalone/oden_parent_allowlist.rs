// Copyright 2018-2026 the Deno authors. MIT license.

// @ref LLP 0019#frozen-parent-standalone-allowlist-and-byte-graph [implements] —
// These generator-side slices freeze the exact capture, source-closure, and
// release contract memberships. One authoring-only Generate session now holds
// the retained root across graph observation, inventory reads, composition,
// and per-file atomic replacement of the two allowlist review candidates. A
// distinct embedded-only Check session now reconciles the in-memory, compiled,
// and checked-in candidates without writing. The target-policy carrier,
// brand/admission, and release authority stay absent or fail-closed.

#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::ffi::CString;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::fs::File;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::io::Read;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::io::Seek;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::io::SeekFrom;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::io::Write;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::os::fd::AsRawFd;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::os::fd::FromRawFd;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::os::fd::IntoRawFd;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::os::fd::RawFd;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::os::unix::ffi::OsStrExt;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::path::Path;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::path::PathBuf;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::sync::Arc;

#[cfg(any(target_os = "linux", target_os = "macos"))]
use deno_ast::ModuleSpecifier;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use deno_lib::standalone::oden_parent_allowlist::ContractFile;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use deno_lib::standalone::oden_parent_allowlist::ContractInventory;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use deno_lib::standalone::oden_parent_allowlist::OdenParentAllowlist;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use deno_lib::standalone::oden_parent_allowlist::OdenParentAllowlistInputs;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use deno_lib::standalone::oden_parent_allowlist::OdenParentRepoVfsKey;
#[cfg(any(test, target_os = "linux", target_os = "macos"))]
use deno_lib::standalone::oden_parent_allowlist::ODEN_PARENT_GENERATED_JSON_PATH;
#[cfg(any(test, target_os = "linux", target_os = "macos"))]
use deno_lib::standalone::oden_parent_allowlist::ODEN_PARENT_GENERATED_PATHS;
#[cfg(any(test, target_os = "linux", target_os = "macos"))]
use deno_lib::standalone::oden_parent_allowlist::ODEN_PARENT_GENERATED_RUST_PATH;
#[cfg(test)]
use deno_lib::standalone::oden_parent_allowlist::ODEN_PARENT_TARGET_POLICY_GENERATED_RUST_PATH;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use deno_lib::standalone::oden_parent_allowlist::OdenParentAllowlistError;
use deno_lib::standalone::oden_parent_allowlist::OdenParentAllowlistRawDispatch;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use deno_lib::standalone::oden_parent_allowlist::OdenParentStandaloneConfiguration;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use deno_lib::standalone::oden_parent_allowlist::OdenParentStaticImportEdge;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use deno_lib::standalone::oden_parent_allowlist::OdenParentVfsGraph;
use deno_lib::standalone::oden_parent_allowlist::ODEN_PARENT_ALLOWLIST_REFUSAL_EXIT_CODE;

const ODEN_PARENT_ALLOWLIST_AUTHORING_FEATURE: &str =
  "__oden_parent_allowlist_authoring";
const ODEN_PARENT_ALLOWLIST_EMBEDDED_FEATURE: &str =
  "__oden_parent_allowlist_embedded";

// @ref LLP 0019#frozen-parent-standalone-allowlist-and-byte-graph [implements] —
// Decode only the compile-time role shape. Generate and Check eligibility can
// each be consumed once by its distinct narrow session; every other shape
// refuses, and compilation shape alone grants no downstream authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OdenParentAllowlistRoleDecision {
  GenerateEligible,
  CheckEligible,
  Refuse,
}

#[derive(Clone, Copy)]
struct OdenParentAllowlistCompiledRoleFacts<'a> {
  supported_os: bool,
  authoring: bool,
  embedded: bool,
  root_feature_inventory: &'a str,
}

fn decode_oden_parent_allowlist_role(
  dispatch: OdenParentAllowlistRawDispatch,
  facts: OdenParentAllowlistCompiledRoleFacts<'_>,
) -> OdenParentAllowlistRoleDecision {
  if !facts.supported_os
    || !root_feature_inventory_matches_role_bits(facts)
  {
    return OdenParentAllowlistRoleDecision::Refuse;
  }

  match (dispatch, facts.authoring, facts.embedded) {
    (OdenParentAllowlistRawDispatch::Generate, true, false) => {
      OdenParentAllowlistRoleDecision::GenerateEligible
    }
    (OdenParentAllowlistRawDispatch::Check, false, true) => {
      OdenParentAllowlistRoleDecision::CheckEligible
    }
    _ => OdenParentAllowlistRoleDecision::Refuse,
  }
}

fn root_feature_inventory_matches_role_bits(
  facts: OdenParentAllowlistCompiledRoleFacts<'_>,
) -> bool {
  let mut previous = None;
  let mut inventory_authoring = false;
  let mut inventory_embedded = false;

  for feature in facts.root_feature_inventory.split(',') {
    if feature.is_empty()
      || previous.is_some_and(|previous: &str| {
        previous.as_bytes() >= feature.as_bytes()
      })
    {
      return false;
    }
    inventory_authoring |= feature == ODEN_PARENT_ALLOWLIST_AUTHORING_FEATURE;
    inventory_embedded |= feature == ODEN_PARENT_ALLOWLIST_EMBEDDED_FEATURE;
    previous = Some(feature);
  }

  inventory_authoring == facts.authoring
    && inventory_embedded == facts.embedded
}

fn compiled_oden_parent_allowlist_role_facts(
) -> OdenParentAllowlistCompiledRoleFacts<'static> {
  OdenParentAllowlistCompiledRoleFacts {
    supported_os: cfg!(any(target_os = "linux", target_os = "macos")),
    authoring: cfg!(feature = "__oden_parent_allowlist_authoring"),
    embedded: cfg!(feature = "__oden_parent_allowlist_embedded"),
    root_feature_inventory: env!("ODEN_REV2_BUILD_CARGO_FEATURES"),
  }
}

/// Opaque one-shot proof that this root crate has the exact supported,
/// authoring-only shape for the reserved Generate route. It deliberately has
/// no public constructor and is neither `Clone` nor `Copy`.
pub(crate) struct OdenParentAllowlistGenerateEligibility {
  _private: (),
}

/// Opaque one-shot proof that this root crate has the exact supported,
/// embedded-only shape for the reserved Check route. It deliberately has no
/// public constructor and is neither `Clone` nor `Copy`.
#[cfg(any(test, feature = "__oden_parent_allowlist_embedded"))]
pub(crate) struct OdenParentAllowlistCheckEligibility {
  _private: (),
}

#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub(crate) struct OdenParentAllowlistGenerateError(
  OdenParentAllowlistGenerateFailure,
);

impl From<OdenParentAllowlistGenerateFailure>
  for OdenParentAllowlistGenerateError
{
  fn from(value: OdenParentAllowlistGenerateFailure) -> Self {
    Self(value)
  }
}

#[cfg(any(test, feature = "__oden_parent_allowlist_embedded"))]
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub(crate) struct OdenParentAllowlistCheckError(
  OdenParentAllowlistCheckFailure,
);

#[cfg(any(test, feature = "__oden_parent_allowlist_embedded"))]
impl From<OdenParentAllowlistCheckFailure> for OdenParentAllowlistCheckError {
  fn from(value: OdenParentAllowlistCheckFailure) -> Self {
    Self(value)
  }
}

fn admit_oden_parent_allowlist_generate_with(
  dispatch: OdenParentAllowlistRawDispatch,
  facts: OdenParentAllowlistCompiledRoleFacts<'_>,
) -> Result<
  OdenParentAllowlistGenerateEligibility,
  OdenParentAllowlistGenerateFailure,
> {
  if decode_oden_parent_allowlist_role(dispatch, facts)
    != OdenParentAllowlistRoleDecision::GenerateEligible
  {
    return Err(OdenParentAllowlistGenerateFailure::IneligibleRole);
  }
  Ok(OdenParentAllowlistGenerateEligibility { _private: () })
}

#[cfg(any(test, feature = "__oden_parent_allowlist_embedded"))]
fn admit_oden_parent_allowlist_check_with(
  dispatch: OdenParentAllowlistRawDispatch,
  facts: OdenParentAllowlistCompiledRoleFacts<'_>,
) -> Result<
  OdenParentAllowlistCheckEligibility,
  OdenParentAllowlistCheckFailure,
> {
  if decode_oden_parent_allowlist_role(dispatch, facts)
    != OdenParentAllowlistRoleDecision::CheckEligible
  {
    return Err(OdenParentAllowlistCheckFailure::IneligibleRole);
  }
  Ok(OdenParentAllowlistCheckEligibility { _private: () })
}

// @ref LLP 0019#frozen-parent-standalone-allowlist-and-byte-graph [implements] —
// Mint a one-shot Generate eligibility value only for the exact supported,
// authoring-only compiled shape. Check and every other role remain ineligible.
pub(crate) fn admit_oden_parent_allowlist_generate(
  dispatch: OdenParentAllowlistRawDispatch,
) -> Result<
  OdenParentAllowlistGenerateEligibility,
  OdenParentAllowlistGenerateError,
> {
  admit_oden_parent_allowlist_generate_with(
    dispatch,
    compiled_oden_parent_allowlist_role_facts(),
  )
  .map_err(Into::into)
}

// @ref LLP 0019#frozen-parent-standalone-allowlist-and-byte-graph [implements] —
// Mint a one-shot Check eligibility value only for the exact supported,
// embedded-only root shape. This permits one non-authoritative reconciliation
// and cannot construct final admission or any downstream capability.
#[cfg(feature = "__oden_parent_allowlist_embedded")]
pub(crate) fn admit_oden_parent_allowlist_check(
  dispatch: OdenParentAllowlistRawDispatch,
) -> Result<
  OdenParentAllowlistCheckEligibility,
  OdenParentAllowlistCheckError,
> {
  admit_oden_parent_allowlist_check_with(
    dispatch,
    compiled_oden_parent_allowlist_role_facts(),
  )
  .map_err(Into::into)
}

pub(crate) fn refusal_exit_code_for_oden_parent_allowlist_dispatch(
  dispatch: OdenParentAllowlistRawDispatch,
) -> i32 {
  match decode_oden_parent_allowlist_role(
    dispatch,
    compiled_oden_parent_allowlist_role_facts(),
  ) {
    OdenParentAllowlistRoleDecision::GenerateEligible
    | OdenParentAllowlistRoleDecision::CheckEligible
    | OdenParentAllowlistRoleDecision::Refuse => {
      ODEN_PARENT_ALLOWLIST_REFUSAL_EXIT_CODE
    }
  }
}

/// Parent-root-relative definitions that comprise the capture contract.
///
/// Delegated schemas are members only when the parent-capture path parses or
/// emits them. Executable imported helpers remain independently VFS-bound.
#[allow(dead_code)]
pub(crate) const ODEN_PARENT_CAPTURE_CONTRACT_PATHS: &[&str] = &[
  "fork/deno/cli/lib/standalone/oden_parent_allowlist.rs",
  "fork/deno/cli/standalone/oden_parent_allowlist.rs",
  "schemas/capsec/rev2/filesystem-candidate-arena.schema.json",
  "schemas/capsec/rev2/filesystem-candidate-ready-frame.schema.json",
  "schemas/capsec/rev2/filesystem-candidate-request-frame.schema.json",
  "schemas/capsec/rev2/filesystem-candidate-response-frame.schema.json",
  "schemas/capsec/rev2/filesystem-candidate-spawn-request.schema.json",
  "schemas/capsec/rev2/filesystem-candidate-spawn-result.schema.json",
  "schemas/capsec/rev2/filesystem-candidate-terminal.schema.json",
  "schemas/capsec/rev2/filesystem-capture-contract.schema.json",
  "schemas/capsec/rev2/filesystem-conformance-case-evidence.schema.json",
  "schemas/capsec/rev2/filesystem-conformance-engine-trace.schema.json",
  "schemas/capsec/rev2/filesystem-conformance-manifest.schema.json",
  "schemas/capsec/rev2/filesystem-conformance-reference-oracle-input.schema.json",
  "schemas/capsec/rev2/filesystem-conformance-reference-oracle-output.schema.json",
  "schemas/capsec/rev2/filesystem-conformance-runner-comparison.schema.json",
  "schemas/capsec/rev2/filesystem-conformance-sandbox-realization.schema.json",
  "schemas/capsec/rev2/filesystem-descriptor-slots.schema.json",
  "schemas/capsec/rev2/filesystem-disk-budget-journal.schema.json",
  "schemas/capsec/rev2/filesystem-disk-budget-observation.schema.json",
  "schemas/capsec/rev2/filesystem-no-descendant-observation.schema.json",
  "schemas/capsec/rev2/filesystem-no-descendant-source-closure.schema.json",
  "schemas/capsec/rev2/filesystem-parent-capture.schema.json",
  "schemas/capsec/rev2/filesystem-parent-comparison.schema.json",
  "schemas/capsec/rev2/filesystem-parent-standalone-metadata.schema.json",
  "schemas/capsec/rev2/filesystem-parent-transcript.schema.json",
  "schemas/capsec/rev2/filesystem-supervisor-report.schema.json",
  "schemas/capsec/rev2/filesystem-supervisor-request.schema.json",
  "src/capsec/rev2_filesystem_capture_contract.ts",
];

/// Parent-root-relative definitions that comprise the source-closure contract.
///
/// The dormant retained-file loader can snapshot this literal authority, but
/// no mode may consume it until the release inventory is separately reviewed.
#[allow(dead_code)]
pub(crate) const ODEN_PARENT_SOURCE_CLOSURE_CONTRACT_PATHS: &[&str] = &[
  "fork/deno/cli/lib/standalone/oden_parent_allowlist.rs",
  "fork/deno/cli/standalone/oden_parent_allowlist.rs",
  "schemas/capsec/rev2/filesystem-capture-contract.schema.json",
  "schemas/capsec/rev2/filesystem-linked-image-manifest.schema.json",
  "schemas/capsec/rev2/filesystem-no-descendant-source-closure.schema.json",
  "schemas/capsec/rev2/filesystem-source-closure-reconciliation.schema.json",
  "schemas/capsec/rev2/filesystem-source-closure-reconstruction.schema.json",
  "schemas/capsec/rev2/filesystem-source-closure-static-fixture-projection.schema.json",
  "schemas/capsec/rev2/filesystem-source-closure-static-fixture.schema.json",
  "schemas/capsec/rev2/filesystem-startup-analysis.schema.json",
  "schemas/capsec/rev2/filesystem-startup-manifest.schema.json",
  "scripts/release/filesystem-reachability-analyzer.ts",
  "scripts/release/filesystem-source-closure-comparator.ts",
  "scripts/release/filesystem-source-closure-validator.ts",
  "scripts/release/filesystem-source-closure.ts",
  "src/capsec/rev2_filesystem_capture_contract.ts",
  "src/capsec/rev2_filesystem_linked_image_manifest.ts",
  "src/capsec/rev2_filesystem_source_closure_reconciliation.ts",
  "src/capsec/rev2_filesystem_source_closure_reconstruction.ts",
  "src/capsec/rev2_filesystem_source_closure_static_fixture.ts",
  "src/capsec/rev2_filesystem_startup_analysis.ts",
  "src/capsec/rev2_filesystem_startup_manifest.ts",
];

/// Parent-root-relative definitions that comprise the release contract.
///
/// The complete reviewed membership is fixed and all 33 definition paths now
/// exist. The live `third_party/components.json` instance is deliberately
/// excluded: it must bind the final fork Gitlink, whose commit contains the
/// generated Rust allowlist carrier, so hashing that instance here would create
/// a commit/digest self-reference. Its schema, decoder/generator definition,
/// exact Gitlink join, notice approval, and package-byte gates remain separate
/// release requirements. Authoring Generate may retain these exact definition
/// bytes for two deterministic review candidates, but Check, source
/// authentication, generated-input freeze, and downstream admission remain
/// separate gates.
#[allow(dead_code)]
pub(crate) const ODEN_PARENT_RELEASE_CONTRACT_PATHS: &[&str] = &[
  ".github/workflows/release.yml",
  "Cargo.lock",
  "Cargo.toml",
  "LICENSE",
  "deno.json",
  "deno.lock",
  "fork/deno/cli/lib/standalone/oden_parent_allowlist.rs",
  "fork/deno/cli/standalone/oden_parent_allowlist.rs",
  "release-signing.json",
  "release.json",
  "rust-toolchain.toml",
  "schemas/release/build-metadata.schema.json",
  "schemas/release/engine-provenance.schema.json",
  "schemas/release/release-contract-pin.schema.json",
  "schemas/release/release-metadata.schema.json",
  "schemas/release/release-signing.schema.json",
  "schemas/release/rustsec-audit.schema.json",
  "schemas/release/third-party-components.schema.json",
  "schemas/release/third-party-notices-approval.schema.json",
  "schemas/release/third-party-notices-header.schema.json",
  "scripts/install.sh",
  "scripts/release/build-artifact.ts",
  "scripts/release/checksums.ts",
  "scripts/release/contract-pin.ts",
  "scripts/release/engine-provenance.ts",
  "scripts/release/metadata.ts",
  "scripts/release/preflight.ts",
  "scripts/release/rust-audit.ts",
  "scripts/release/signing.ts",
  "scripts/release/third-party-notices.ts",
  "scripts/verify-fork.sh",
  "security/rustsec-ignores.json",
  "src/release.ts",
];

#[cfg(any(test, target_os = "linux", target_os = "macos"))]
const ODEN_PARENT_CONTRACT_PATH_MAX_BYTES: usize = 4_096;
#[cfg(any(test, target_os = "linux", target_os = "macos"))]
const ODEN_PARENT_CONTRACT_COMPONENT_MAX_BYTES: usize = 255;
#[cfg(any(target_os = "linux", target_os = "macos"))]
const ODEN_PARENT_CONTRACT_FILE_MAX_BYTES: u64 = 4_194_304;
#[cfg(any(target_os = "linux", target_os = "macos"))]
const ODEN_PARENT_CONTRACT_INVENTORY_MAX_BYTES: u64 = 67_108_864;
#[cfg(any(target_os = "linux", target_os = "macos"))]
const ODEN_PARENT_BOOTSTRAP_ASSET_PATH: &str = "src/capsec/bootstrap.ts";
#[cfg(any(target_os = "linux", target_os = "macos"))]
const ODEN_PARENT_BOOTSTRAP_ASSET_KEY: &str = "repo:src/capsec/bootstrap.ts";
#[cfg(any(target_os = "linux", target_os = "macos"))]
const ODEN_PARENT_BOOTSTRAP_ASSET_MAX_BYTES: u64 = 65_536;

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[derive(Clone, Copy)]
struct RetainedContractFileLimits {
  file_bytes: u64,
  inventory_bytes: u64,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
const ODEN_PARENT_RETAINED_CONTRACT_FILE_LIMITS: RetainedContractFileLimits =
  RetainedContractFileLimits {
    file_bytes: ODEN_PARENT_CONTRACT_FILE_MAX_BYTES,
    inventory_bytes: ODEN_PARENT_CONTRACT_INVENTORY_MAX_BYTES,
  };

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[derive(Debug, thiserror::Error)]
enum OdenParentRetainedContractError {
  #[error("contract inventory path list is empty")]
  EmptyPathList,
  #[error("invalid contract inventory path {path:?}: {reason}")]
  InvalidPath {
    path: String,
    reason: &'static str,
  },
  #[error("generated output cannot be a contract inventory member: {0}")]
  GeneratedOutputMember(String),
  #[error(
    "contract inventory paths are duplicated or not in raw UTF-8 order: {previous} then {current}"
  )]
  UnsortedPaths { previous: String, current: String },
  #[error("failed to open retained repository root: {source}")]
  OpenRoot {
    #[source]
    source: std::io::Error,
  },
  #[error("failed to read the current directory during retained-root {phase}: {source}")]
  ReadCurrentDirectory {
    phase: &'static str,
    #[source]
    source: std::io::Error,
  },
  #[error("current directory is not absolute: {0:?}")]
  CurrentDirectoryNotAbsolute(PathBuf),
  #[error("current directory changed during retained-root {phase}: {before:?} then {after:?}")]
  CurrentDirectoryChanged {
    phase: &'static str,
    before: PathBuf,
    after: PathBuf,
  },
  #[error("current directory does not name retained root during {phase}: expected {expected:?}, observed {observed:?}")]
  CurrentDirectoryDoesNotNameRoot {
    phase: &'static str,
    expected: PathBuf,
    observed: PathBuf,
  },
  #[cfg(test)]
  #[error("test retained-root path is not absolute: {0:?}")]
  TestRootNotAbsolute(PathBuf),
  #[error("retained repository root is not a directory")]
  RootNotDirectory,
  #[error("retained repository root name no longer identifies its held descriptor: {0}")]
  RootNameChanged(String),
  #[error("failed to open {component:?} while resolving {path:?}: {source}")]
  OpenComponent {
    path: String,
    component: String,
    #[source]
    source: std::io::Error,
  },
  #[error("retained path component is not a directory: {0}")]
  ComponentNotDirectory(String),
  #[error(
    "retained contract path {path:?} failed exact raw-name observation: {source}"
  )]
  ExactNameObservation {
    path: String,
    #[source]
    source: Box<OdenParentDirectRepoSourceError>,
  },
  #[error("failed to inspect retained descriptor {path:?}: {source}")]
  InspectDescriptor {
    path: String,
    #[source]
    source: std::io::Error,
  },
  #[error("retained contract member is not a regular file: {0}")]
  NotRegularFile(String),
  #[error("retained contract member must have exactly one link: {path} has {links}")]
  InvalidLinkCount { path: String, links: u64 },
  #[error(
    "retained contract member size is outside 1..={limit} bytes: {path} has {size}"
  )]
  InvalidFileSize {
    path: String,
    size: i64,
    limit: u64,
  },
  #[error(
    "retained contract inventory exceeds {limit} bytes after {path}: {size}"
  )]
  InventoryTooLarge {
    path: String,
    size: u64,
    limit: u64,
  },
  #[error("failed to read exact retained bytes for {path:?}: {source}")]
  ReadFile {
    path: String,
    #[source]
    source: std::io::Error,
  },
  #[error("retained contract member grew beyond its snapshotted size: {0}")]
  TrailingBytes(String),
  #[error("retained descriptor changed while reading inventory member {member}: {descriptor}")]
  DescriptorChanged { member: String, descriptor: String },
  #[error("retained contract inventory projection failed: {0}")]
  Inventory(#[from] OdenParentAllowlistError),
}

#[derive(Debug, thiserror::Error)]
enum OdenParentAllowlistGenerateFailure {
  #[error("compiled role is not eligible for parent allowlist generation")]
  IneligibleRole,
  #[cfg(any(target_os = "linux", target_os = "macos"))]
  #[error("retained contract input failed: {0}")]
  Retained(#[from] OdenParentRetainedContractError),
  #[cfg(any(target_os = "linux", target_os = "macos"))]
  #[error("allowlist candidate projection failed: {0}")]
  Projection(#[from] OdenParentAllowlistError),
  #[cfg(any(target_os = "linux", target_os = "macos"))]
  #[error("generated output directory observation failed: {0}")]
  DirectoryObservation(#[from] OdenParentDirectRepoSourceError),
  #[cfg(any(target_os = "linux", target_os = "macos"))]
  #[error("generated output path is not the reviewed fixed spelling: {0}")]
  InvalidOutputPath(&'static str),
  #[cfg(any(target_os = "linux", target_os = "macos"))]
  #[error("failed to open generated output {path:?}: {source}")]
  OpenOutput {
    path: &'static str,
    #[source]
    source: std::io::Error,
  },
  #[cfg(any(target_os = "linux", target_os = "macos"))]
  #[error("generated output is not a direct regular one-link file: {0}")]
  InvalidExistingOutput(&'static str),
  #[cfg(any(target_os = "linux", target_os = "macos"))]
  #[error(
    "failed to create same-directory temporary output for {path:?}: {source}"
  )]
  CreateTemporary {
    path: &'static str,
    #[source]
    source: std::io::Error,
  },
  #[cfg(any(target_os = "linux", target_os = "macos"))]
  #[error(
    "failed to set deterministic temporary-output mode for {path:?}: {source}"
  )]
  SetTemporaryMode {
    path: &'static str,
    #[source]
    source: std::io::Error,
  },
  #[cfg(any(target_os = "linux", target_os = "macos"))]
  #[error("failed to write temporary output for {path:?}: {source}")]
  WriteTemporary {
    path: &'static str,
    #[source]
    source: std::io::Error,
  },
  #[cfg(any(target_os = "linux", target_os = "macos"))]
  #[error("failed to synchronize temporary output for {path:?}: {source}")]
  SyncTemporary {
    path: &'static str,
    #[source]
    source: std::io::Error,
  },
  #[cfg(any(target_os = "linux", target_os = "macos"))]
  #[error("failed to verify temporary output for {path:?}: {source}")]
  VerifyTemporary {
    path: &'static str,
    #[source]
    source: std::io::Error,
  },
  #[cfg(any(target_os = "linux", target_os = "macos"))]
  #[error("temporary output bytes or descriptor changed for {0:?}")]
  TemporaryChanged(&'static str),
  #[cfg(any(target_os = "linux", target_os = "macos"))]
  #[error("generated output name changed before replacement: {0:?}")]
  OutputNameChanged(&'static str),
  #[cfg(any(target_os = "linux", target_os = "macos"))]
  #[error("temporary output name changed before replacement: {0:?}")]
  TemporaryNameChanged(&'static str),
  #[cfg(any(target_os = "linux", target_os = "macos"))]
  #[error("generated output directory changed before replacement: {0:?}")]
  OutputDirectoryChanged(&'static str),
  #[cfg(any(target_os = "linux", target_os = "macos"))]
  #[error("failed to atomically replace generated output {path:?}: {source}")]
  RenameOutput {
    path: &'static str,
    #[source]
    source: std::io::Error,
  },
  #[cfg(any(target_os = "linux", target_os = "macos"))]
  #[error(
    "failed to synchronize generated output directory for {path:?}: {source}"
  )]
  SyncOutputDirectory {
    path: &'static str,
    #[source]
    source: std::io::Error,
  },
  #[cfg(any(target_os = "linux", target_os = "macos"))]
  #[error("atomically replaced output does not name the staged object: {0:?}")]
  ReplacedOutputMismatch(&'static str),
}

#[cfg(any(test, feature = "__oden_parent_allowlist_embedded"))]
#[derive(Debug, thiserror::Error)]
enum OdenParentAllowlistCheckFailure {
  #[error("compiled role is not eligible for parent allowlist checking")]
  IneligibleRole,
  #[cfg(any(target_os = "linux", target_os = "macos"))]
  #[error("compiled allowlist candidate validation failed: {0}")]
  CandidateValidation(#[from] OdenParentAllowlistError),
  #[cfg(any(target_os = "linux", target_os = "macos"))]
  #[error("allowlist candidate-file reconciliation failed: {0}")]
  CandidateFiles(#[from] OdenParentAllowlistCandidateFileFailure),
}

/// File-only reconciliation failures shared by raw Check and the later full-
/// projection candidate. This type has no role, dispatch, embedded-candidate,
/// graph, inventory, output, or admission transition.
#[cfg(any(test, feature = "__oden_parent_allowlist_embedded"))]
#[derive(Debug, thiserror::Error)]
enum OdenParentAllowlistCandidateFileFailure {
  #[cfg(any(target_os = "linux", target_os = "macos"))]
  #[error("retained candidate-file input failed: {0}")]
  Retained(#[from] OdenParentRetainedContractError),
  #[cfg(any(target_os = "linux", target_os = "macos"))]
  #[error("allowlist candidate-file observation failed: {0}")]
  DirectRepository(#[from] OdenParentDirectRepoSourceError),
  #[cfg(any(target_os = "linux", target_os = "macos"))]
  #[error("allowlist candidate-file path is outside the fixed pair: {0}")]
  InvalidPath(&'static str),
  #[cfg(any(target_os = "linux", target_os = "macos"))]
  #[error("allowlist candidate file has an inexact mode: {0}")]
  InexactMode(&'static str),
}

#[cfg(any(test, feature = "__oden_parent_allowlist_embedded"))]
impl From<OdenParentRetainedContractError> for OdenParentAllowlistCheckFailure {
  fn from(value: OdenParentRetainedContractError) -> Self {
    Self::CandidateFiles(OdenParentAllowlistCandidateFileFailure::from(value))
  }
}

#[cfg(any(test, feature = "__oden_parent_allowlist_embedded"))]
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub(crate) struct OdenParentAllowlistFullRegenerationError(
  OdenParentAllowlistFullRegenerationFailure,
);

#[cfg(any(test, feature = "__oden_parent_allowlist_embedded"))]
impl From<OdenParentAllowlistFullRegenerationFailure>
  for OdenParentAllowlistFullRegenerationError
{
  fn from(value: OdenParentAllowlistFullRegenerationFailure) -> Self {
    Self(value)
  }
}

/// Failure-only result for the production-uncalled full-projection sink. It
/// deliberately cannot carry a validated record or downstream capability.
#[cfg(any(test, feature = "__oden_parent_allowlist_embedded"))]
#[derive(Debug, thiserror::Error)]
enum OdenParentAllowlistFullRegenerationFailure {
  #[cfg(any(target_os = "linux", target_os = "macos"))]
  #[error("retained full-regeneration input failed: {0}")]
  Retained(#[from] OdenParentRetainedContractError),
  #[cfg(any(target_os = "linux", target_os = "macos"))]
  #[error("full-regeneration candidate projection failed: {0}")]
  Projection(#[from] OdenParentAllowlistError),
  #[cfg(any(target_os = "linux", target_os = "macos"))]
  #[error("regenerated allowlist differs from the compiled candidate")]
  CompiledCandidateMismatch,
  #[cfg(any(target_os = "linux", target_os = "macos"))]
  #[error("full-regeneration candidate-file reconciliation failed: {0}")]
  CandidateFiles(#[from] OdenParentAllowlistCandidateFileFailure),
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[derive(Debug, thiserror::Error)]
enum OdenParentDirectRepoSourceError {
  #[error("retained-root descriptor operation failed: {0}")]
  RetainedDescriptor(#[from] OdenParentRetainedContractError),
  #[error("invalid direct repository file URL: {0}")]
  InvalidFileUrl(&'static str),
  #[error("invalid reviewed bootstrap asset: {0}")]
  InvalidBootstrapAsset(&'static str),
  #[error("direct repository file URL {specifier} is not a strict descendant of retained root {root:?}")]
  OutsideRetainedRoot { specifier: String, root: PathBuf },
  #[error("direct repository file path is not exact UTF-8")]
  NonUtf8RelativePath,
  #[error("direct repository VFS key construction failed: {0}")]
  RepoKey(#[from] OdenParentAllowlistError),
  #[error("failed to enumerate retained directory {directory:?}: {source}")]
  EnumerateDirectory {
    directory: String,
    #[source]
    source: std::io::Error,
  },
  #[error("retained directory {0:?} returned a non-NUL-terminated entry name")]
  MalformedDirectoryEntry(String),
  #[error("retained directory {directory:?} contains {matches} exact raw entries named {component:?}, expected one")]
  InvalidExactComponentCount {
    directory: String,
    component: String,
    matches: usize,
  },
  #[error("retained directory {directory:?} contains {matches} ASCII-case-folded raw entries named {component:?}, expected one")]
  InvalidCaseFoldedComponentCount {
    directory: String,
    component: String,
    matches: usize,
  },
  #[error("direct repository path component is not a directory: {0}")]
  ComponentNotDirectory(String),
  #[error("direct repository source is not a regular file: {0}")]
  NotRegularFile(String),
  #[error("direct repository source must have exactly one link: {path} has {links}")]
  InvalidLinkCount { path: String, links: u64 },
  #[error("direct repository source size differs from supplied candidate bytes: {path} expected {expected}, descriptor has {actual}")]
  SizeMismatch {
    path: String,
    expected: u64,
    actual: i64,
  },
  #[error("failed to read direct repository source {path:?}: {source}")]
  ReadFile {
    path: String,
    #[source]
    source: std::io::Error,
  },
  #[error("direct repository source ended before supplied candidate bytes at offset {offset}: {path}")]
  UnexpectedEof { path: String, offset: u64 },
  #[error("direct repository source differs from supplied candidate bytes at offset {offset}: {path}")]
  ByteMismatch { path: String, offset: u64 },
  #[error("direct repository source has bytes after the exact supplied candidate-byte length: {0}")]
  TrailingBytes(String),
  #[cfg(any(test, feature = "__oden_parent_allowlist_embedded"))]
  #[error("failed to inspect retained direct repository name {path:?}: {source}")]
  InspectName {
    path: String,
    #[source]
    source: std::io::Error,
  },
  #[cfg(any(test, feature = "__oden_parent_allowlist_embedded"))]
  #[error("retained direct repository name changed: {0}")]
  NameChanged(String),
  #[error("retained descriptor changed while reading direct repository source {member}: {descriptor}")]
  DescriptorChanged { member: String, descriptor: String },
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub(super) struct OdenParentDirectRepoSourceObservationError(
  #[from] OdenParentDirectRepoSourceError,
);

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[derive(Clone, Debug, PartialEq, Eq)]
struct DescriptorSnapshot {
  device: u64,
  inode: u64,
  mode: u32,
  links: u64,
  size: i64,
  modified_seconds: i64,
  modified_nanoseconds: i64,
  changed_seconds: i64,
  changed_nanoseconds: i64,
  #[cfg(target_os = "macos")]
  generation: u32,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl DescriptorSnapshot {
  fn from_stat(stat: libc::stat) -> Self {
    let (modified_seconds, modified_nanoseconds) =
      (stat.st_mtime as i64, stat.st_mtime_nsec as i64);
    let (changed_seconds, changed_nanoseconds) =
      (stat.st_ctime as i64, stat.st_ctime_nsec as i64);

    Self {
      device: stat.st_dev as u64,
      inode: stat.st_ino as u64,
      mode: stat.st_mode as u32,
      links: stat.st_nlink as u64,
      size: stat.st_size as i64,
      modified_seconds,
      modified_nanoseconds,
      changed_seconds,
      changed_nanoseconds,
      #[cfg(target_os = "macos")]
      generation: stat.st_gen,
    }
  }

  fn capture(
    descriptor: &File,
    path: &str,
  ) -> Result<Self, OdenParentRetainedContractError> {
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: `descriptor` remains live for the call and `stat` points to
    // writable storage large enough for one platform `stat` value.
    if unsafe { libc::fstat(descriptor.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
      return Err(OdenParentRetainedContractError::InspectDescriptor {
        path: path.to_string(),
        source: std::io::Error::last_os_error(),
      });
    }
    // SAFETY: a successful `fstat` initialized the complete value.
    let stat = unsafe { stat.assume_init() };
    Ok(Self::from_stat(stat))
  }

  fn capture_named_path_no_follow(
    path: &Path,
  ) -> Result<Self, OdenParentRetainedContractError> {
    let encoded_path = CString::new(path.as_os_str().as_bytes()).map_err(|_| {
      OdenParentRetainedContractError::InspectDescriptor {
        path: path.to_string_lossy().into_owned(),
        source: std::io::Error::from(std::io::ErrorKind::InvalidInput),
      }
    })?;
    let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: `encoded_path` is NUL-terminated, `stat` is writable storage for
    // one platform stat value, and AT_SYMLINK_NOFOLLOW prevents a final-name
    // symlink from being treated as the held repository directory.
    if unsafe {
      libc::fstatat(
        libc::AT_FDCWD,
        encoded_path.as_ptr(),
        stat.as_mut_ptr(),
        libc::AT_SYMLINK_NOFOLLOW,
      )
    } != 0
    {
      return Err(OdenParentRetainedContractError::InspectDescriptor {
        path: path.to_string_lossy().into_owned(),
        source: std::io::Error::last_os_error(),
      });
    }
    // SAFETY: successful `fstatat` initialized the complete value.
    Ok(Self::from_stat(unsafe { stat.assume_init() }))
  }

  fn is_directory(&self) -> bool {
    self.mode & libc::S_IFMT as u32 == libc::S_IFDIR as u32
  }

  fn is_regular_file(&self) -> bool {
    self.mode & libc::S_IFMT as u32 == libc::S_IFREG as u32
  }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
struct RetainedRepositoryRoot {
  path: PathBuf,
  descriptor: File,
  snapshot: DescriptorSnapshot,
  requires_current_name: bool,
}

/// One authoring Generate session owns the eligibility transition and the
/// single retained repository root used by graph observation, contract-byte
/// loading, and both fixed output replacements. It is intentionally neither
/// `Clone` nor `Copy` and exposes no root descriptor.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) struct OdenParentAllowlistGenerateSession {
  root: RetainedRepositoryRoot,
}

/// One embedded-only Check session owns its distinct eligibility transition
/// and a retained repository root used only for candidate reconstruction and
/// fixed-file reads. No writer accepts this type. It is intentionally neither
/// `Clone` nor `Copy` and exposes no root descriptor.
#[cfg(all(
  any(target_os = "linux", target_os = "macos"),
  any(test, feature = "__oden_parent_allowlist_embedded")
))]
pub(crate) struct OdenParentAllowlistCheckSession {
  root: RetainedRepositoryRoot,
}

/// One production-uncalled full-regeneration candidate owns a retained root
/// that may be borrowed by the existing graph/direct-file observer and is
/// finally consumed by the read-only inventory/embedded/file reconciliation
/// sink. No production constructor exists, and no writer accepts this type.
/// It is intentionally neither `Clone` nor `Copy`.
#[cfg(all(
  any(target_os = "linux", target_os = "macos"),
  any(test, feature = "__oden_parent_allowlist_embedded")
))]
#[allow(dead_code)]
pub(crate) struct OdenParentAllowlistFullRegenerationSession {
  root: RetainedRepositoryRoot,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl RetainedRepositoryRoot {
  fn open_current() -> Result<Self, OdenParentRetainedContractError> {
    let before = std::env::current_dir().map_err(|source| {
      OdenParentRetainedContractError::ReadCurrentDirectory {
        phase: "before",
        source,
      }
    })?;
    if !before.is_absolute() {
      return Err(
        OdenParentRetainedContractError::CurrentDirectoryNotAbsolute(before),
      );
    }
    let literal_current = CString::new(".").expect("literal dot has no NUL");
    let flags = libc::O_RDONLY
      | libc::O_DIRECTORY
      | libc::O_NOFOLLOW
      | libc::O_CLOEXEC;
    // SAFETY: the literal `.` is NUL-terminated for the call; successful
    // `open` returns one new descriptor owned by this function.
    let raw_descriptor = unsafe { libc::open(literal_current.as_ptr(), flags) };
    if raw_descriptor < 0 {
      return Err(OdenParentRetainedContractError::OpenRoot {
        source: std::io::Error::last_os_error(),
      });
    }
    // SAFETY: successful `open` returned a new uniquely owned descriptor.
    let descriptor = unsafe { File::from_raw_fd(raw_descriptor) };
    let snapshot = DescriptorSnapshot::capture(&descriptor, ".")?;
    if !snapshot.is_directory() {
      return Err(OdenParentRetainedContractError::RootNotDirectory);
    }
    let after = std::env::current_dir().map_err(|source| {
      OdenParentRetainedContractError::ReadCurrentDirectory {
        phase: "after",
        source,
      }
    })?;
    if !after.is_absolute() {
      return Err(
        OdenParentRetainedContractError::CurrentDirectoryNotAbsolute(after),
      );
    }
    if before.as_os_str().as_bytes() != after.as_os_str().as_bytes() {
      return Err(OdenParentRetainedContractError::CurrentDirectoryChanged {
        phase: "open",
        before,
        after,
      });
    }
    let root = Self {
      path: before,
      descriptor,
      snapshot,
      requires_current_name: true,
    };
    root.require_current_and_named_paths_stable("initial reconciliation")?;
    Ok(root)
  }

  #[cfg(test)]
  fn open_test_absolute(
    path: &Path,
  ) -> Result<Self, OdenParentRetainedContractError> {
    if !path.is_absolute() {
      return Err(OdenParentRetainedContractError::TestRootNotAbsolute(
        path.to_path_buf(),
      ));
    }
    let encoded_path = CString::new(path.as_os_str().as_bytes()).map_err(|_| {
      OdenParentRetainedContractError::OpenRoot {
        source: std::io::Error::from(std::io::ErrorKind::InvalidInput),
      }
    })?;
    let flags = libc::O_RDONLY
      | libc::O_DIRECTORY
      | libc::O_NOFOLLOW
      | libc::O_CLOEXEC;
    // SAFETY: `encoded_path` is NUL-terminated for the call; successful `open`
    // returns one new descriptor owned by this function.
    let raw_descriptor = unsafe { libc::open(encoded_path.as_ptr(), flags) };
    if raw_descriptor < 0 {
      return Err(OdenParentRetainedContractError::OpenRoot {
        source: std::io::Error::last_os_error(),
      });
    }
    // SAFETY: successful `open` returned a new uniquely owned descriptor.
    let descriptor = unsafe { File::from_raw_fd(raw_descriptor) };
    let snapshot = DescriptorSnapshot::capture(&descriptor, ".")?;
    if !snapshot.is_directory() {
      return Err(OdenParentRetainedContractError::RootNotDirectory);
    }
    let root = Self {
      path: path.to_path_buf(),
      descriptor,
      snapshot,
      requires_current_name: false,
    };
    root.require_current_and_named_paths_stable("test reconciliation")?;
    Ok(root)
  }

  fn require_current_and_named_paths_stable(
    &self,
    phase: &'static str,
  ) -> Result<(), OdenParentRetainedContractError> {
    let before = if self.requires_current_name {
      let before = std::env::current_dir().map_err(|source| {
        OdenParentRetainedContractError::ReadCurrentDirectory {
          phase,
          source,
        }
      })?;
      if before.as_os_str().as_bytes() != self.path.as_os_str().as_bytes() {
        return Err(
          OdenParentRetainedContractError::CurrentDirectoryDoesNotNameRoot {
            phase,
            expected: self.path.clone(),
            observed: before,
          },
        );
      }
      let literal_current =
        DescriptorSnapshot::capture_named_path_no_follow(Path::new("."))?;
      if literal_current != self.snapshot {
        return Err(OdenParentRetainedContractError::RootNameChanged(
          "literal .".to_string(),
        ));
      }
      Some(before)
    } else {
      None
    };

    let absolute =
      DescriptorSnapshot::capture_named_path_no_follow(&self.path)?;
    if absolute != self.snapshot {
      return Err(OdenParentRetainedContractError::RootNameChanged(
        self.path.to_string_lossy().into_owned(),
      ));
    }

    if let Some(before) = before {
      let after = std::env::current_dir().map_err(|source| {
        OdenParentRetainedContractError::ReadCurrentDirectory {
          phase,
          source,
        }
      })?;
      if before.as_os_str().as_bytes() != after.as_os_str().as_bytes() {
        return Err(OdenParentRetainedContractError::CurrentDirectoryChanged {
          phase,
          before,
          after,
        });
      }
      if after.as_os_str().as_bytes() != self.path.as_os_str().as_bytes() {
        return Err(
          OdenParentRetainedContractError::CurrentDirectoryDoesNotNameRoot {
            phase,
            expected: self.path.clone(),
            observed: after,
          },
        );
      }
    }
    Ok(())
  }

  fn require_stable(
    &self,
    member: &str,
  ) -> Result<(), OdenParentRetainedContractError> {
    require_descriptor_stable(
      &self.descriptor,
      &self.snapshot,
      ".",
      member,
    )
  }
}

// @ref LLP 0019#frozen-parent-standalone-allowlist-and-byte-graph [implements] —
// Consume exact authoring eligibility before acquiring the one retained root
// that must span graph construction, inventory reads, and output replacement.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) fn begin_oden_parent_allowlist_generate_session(
  _eligibility: OdenParentAllowlistGenerateEligibility,
) -> Result<OdenParentAllowlistGenerateSession, OdenParentAllowlistGenerateError>
{
  RetainedRepositoryRoot::open_current()
    .map(|root| OdenParentAllowlistGenerateSession { root })
    .map_err(|error| OdenParentAllowlistGenerateFailure::from(error).into())
}

// @ref LLP 0019#frozen-parent-standalone-allowlist-and-byte-graph [implements] —
// Consume exact Check eligibility before acquiring its one retained root. The
// resulting type has no path to the Generate writer or final admission.
#[cfg(all(
  any(target_os = "linux", target_os = "macos"),
  feature = "__oden_parent_allowlist_embedded"
))]
pub(crate) fn begin_oden_parent_allowlist_check_session(
  _eligibility: OdenParentAllowlistCheckEligibility,
) -> Result<OdenParentAllowlistCheckSession, OdenParentAllowlistCheckError> {
  RetainedRepositoryRoot::open_current()
    .map(|root| OdenParentAllowlistCheckSession { root })
    .map_err(|error| {
      OdenParentAllowlistCheckFailure::CandidateFiles(
        OdenParentAllowlistCandidateFileFailure::from(error),
      )
      .into()
    })
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl OdenParentAllowlistGenerateSession {
  pub(crate) fn repository_root_path(&self) -> &Path {
    &self.root.path
  }

  pub(crate) fn require_stable_reconciliation(
    &self,
  ) -> Result<(), OdenParentAllowlistGenerateError> {
    let result = (|| {
      self
        .root
        .require_current_and_named_paths_stable("generate session")?;
      self.root.require_stable("<generate-session>")?;
      Ok::<(), OdenParentRetainedContractError>(())
    })();
    result
      .map_err(OdenParentAllowlistGenerateFailure::from)
      .map_err(Into::into)
  }

  #[cfg(test)]
  fn begin_for_test(
    _eligibility: OdenParentAllowlistGenerateEligibility,
    path: &Path,
  ) -> Result<Self, OdenParentAllowlistGenerateError> {
    RetainedRepositoryRoot::open_test_absolute(path)
      .map(|root| Self { root })
      .map_err(|error| OdenParentAllowlistGenerateFailure::from(error).into())
  }
}

#[cfg(all(
  any(target_os = "linux", target_os = "macos"),
  any(test, feature = "__oden_parent_allowlist_embedded")
))]
impl OdenParentAllowlistCheckSession {
  #[cfg(test)]
  fn begin_for_test(
    _eligibility: OdenParentAllowlistCheckEligibility,
    path: &Path,
  ) -> Result<Self, OdenParentAllowlistCheckError> {
    RetainedRepositoryRoot::open_test_absolute(path)
      .map(|root| Self { root })
      .map_err(|error| {
        OdenParentAllowlistCheckFailure::CandidateFiles(
          OdenParentAllowlistCandidateFileFailure::from(error),
        )
        .into()
      })
  }
}

#[cfg(all(
  any(target_os = "linux", target_os = "macos"),
  any(test, feature = "__oden_parent_allowlist_embedded")
))]
impl OdenParentAllowlistFullRegenerationSession {
  #[allow(dead_code)]
  pub(crate) fn repository_root_path(&self) -> &Path {
    &self.root.path
  }

  #[allow(dead_code)]
  pub(crate) fn require_stable_reconciliation(
    &self,
  ) -> Result<(), OdenParentAllowlistFullRegenerationError> {
    let result = (|| {
      self
        .root
        .require_current_and_named_paths_stable("full regeneration session")?;
      self.root.require_stable("<full-regeneration-session>")?;
      Ok::<(), OdenParentRetainedContractError>(())
    })();
    result
      .map_err(OdenParentAllowlistFullRegenerationFailure::from)
      .map_err(Into::into)
  }

  #[cfg(test)]
  pub(crate) fn begin_for_test(
    path: &Path,
  ) -> Result<Self, OdenParentAllowlistFullRegenerationError> {
    RetainedRepositoryRoot::open_test_absolute(path)
      .map(|root| Self { root })
      .map_err(OdenParentAllowlistFullRegenerationFailure::from)
      .map_err(Into::into)
  }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
struct HeldDirectory {
  path: String,
  descriptor: File,
  snapshot: DescriptorSnapshot,
}

// @ref LLP 0019#frozen-parent-standalone-allowlist-and-byte-graph [implements] —
// Bind one canonical repository key and caller-supplied candidate Arc to the
// exact retained no-follow direct file, without constructing a VFS row.
/// Candidate-only direct-file identity. This proves only the retained lexical
/// root, exact file descriptor identity/mode, and equality with one supplied
/// candidate byte allocation during this observation. It does not prove graph
/// provenance or authenticate a Git tree, graph reachability, emitted bytes/
/// maps, serialized stores, JSR identity, configuration, allowlist output,
/// compiler activation, or release authority. Process-wide concurrent cwd
/// mutation is unsupported: observed changes refuse, but an away-and-back ABA
/// is not transactionally excluded and remains for activation/process-wide
/// locking. The independent current-root wrapper remains production-uncalled;
/// admitted Generate instead acquires its session-owned root before graph
/// construction and uses that same root for graph-byte joins, the reviewed
/// bootstrap asset, contract inventories, and fixed outputs.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[allow(dead_code)]
#[derive(Debug)]
pub(super) struct OdenParentDirectRepoSourceCandidate {
  key: OdenParentRepoVfsKey,
  specifier: ModuleSpecifier,
  original_bytes: Arc<[u8]>,
  executable: bool,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl OdenParentDirectRepoSourceCandidate {
  pub(super) fn key(&self) -> &OdenParentRepoVfsKey {
    &self.key
  }

  pub(super) fn specifier(&self) -> &ModuleSpecifier {
    &self.specifier
  }

  pub(super) fn original_bytes(&self) -> &Arc<[u8]> {
    &self.original_bytes
  }

  pub(super) fn executable(&self) -> bool {
    self.executable
  }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
struct OdenParentDirectRepoSourceRead<'a> {
  root: &'a RetainedRepositoryRoot,
  key: OdenParentRepoVfsKey,
  specifier: ModuleSpecifier,
  original_bytes: Arc<[u8]>,
  executable: bool,
  path: String,
  descriptor: File,
  snapshot: DescriptorSnapshot,
  held_directories: Vec<HeldDirectory>,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[derive(Debug)]
struct RetainedContractFile {
  path: String,
  bytes: Vec<u8>,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[derive(Debug)]
struct RetainedContractFiles {
  #[allow(dead_code)]
  files: Vec<RetainedContractFile>,
  inventory: ContractInventory,
}

// @ref LLP 0019#frozen-parent-standalone-allowlist-and-byte-graph [implements] —
// Compose only the exact three dormant byte inventories without producing an
// allowlist, generated output, or raw-dispatch capability.
/// Owned byte snapshots of the three reviewed literal inventories. This
/// composition is not a coherent repository snapshot or release authority and
/// has no rendering or output behavior.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[allow(dead_code)]
struct RetainedContractByteBundle {
  capture: RetainedContractFiles,
  source_closure: RetainedContractFiles,
  release: RetainedContractFiles,
}

/// Already-typed compiler projections accepted by the pure candidate
/// compositor. This local adapter adds no path, mode, or authority input.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[allow(dead_code)]
#[derive(Clone, Copy, Debug)]
struct OdenParentAllowlistCompilerProjectionInput<'a> {
  configuration: &'a OdenParentStandaloneConfiguration,
  vfs_graph: &'a OdenParentVfsGraph,
  static_import_edge: &'a OdenParentStaticImportEdge,
}

/// Owned candidate bytes for the two allowlist renderings. These bytes have no
/// output path and confer no generator, compiler, or release authority.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[allow(dead_code)]
#[derive(Clone, Debug, PartialEq, Eq)]
struct OdenParentAllowlistCandidateOutput {
  canonical_jcs: Vec<u8>,
  digest: String,
  json_file: Vec<u8>,
  rust_module: Vec<u8>,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl RetainedContractFiles {
  #[allow(dead_code)]
  fn inventory(&self) -> &ContractInventory {
    &self.inventory
  }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn invalid_path(
  path: &str,
  reason: &'static str,
) -> OdenParentRetainedContractError {
  OdenParentRetainedContractError::InvalidPath {
    path: path.to_string(),
    reason,
  }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn validate_retained_contract_paths(
  paths: &[&str],
) -> Result<(), OdenParentRetainedContractError> {
  if paths.is_empty() {
    return Err(OdenParentRetainedContractError::EmptyPathList);
  }
  let mut previous: Option<&str> = None;
  for path in paths {
    let bytes = path.as_bytes();
    if bytes.is_empty() {
      return Err(invalid_path(path, "path is empty"));
    }
    if bytes.len() > ODEN_PARENT_CONTRACT_PATH_MAX_BYTES {
      return Err(invalid_path(path, "path exceeds 4096 UTF-8 bytes"));
    }
    if !path.is_ascii() {
      return Err(invalid_path(
        path,
        "path is not canonical ASCII",
      ));
    }
    if path.starts_with('/') {
      return Err(invalid_path(path, "path is absolute"));
    }
    if path.contains('\\') {
      return Err(invalid_path(path, "path contains a backslash"));
    }
    if path.contains('\0') {
      return Err(invalid_path(path, "path contains NUL"));
    }
    for component in path.split('/') {
      if component.is_empty() || matches!(component, "." | "..") {
        return Err(invalid_path(path, "path has a forbidden component"));
      }
      if component.len() > ODEN_PARENT_CONTRACT_COMPONENT_MAX_BYTES {
        return Err(invalid_path(
          path,
          "path component exceeds 255 UTF-8 bytes",
        ));
      }
    }
    if ODEN_PARENT_GENERATED_PATHS
      .iter()
      .any(|generated_path| path.eq_ignore_ascii_case(generated_path))
    {
      return Err(OdenParentRetainedContractError::GeneratedOutputMember(
        path.to_string(),
      ));
    }
    if let Some(previous) = previous
      && previous.as_bytes() >= bytes
    {
      return Err(OdenParentRetainedContractError::UnsortedPaths {
        previous: previous.to_string(),
        current: path.to_string(),
      });
    }
    previous = Some(path);
  }
  Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn open_component(
  directory: RawFd,
  path: &str,
  component: &str,
  flags: libc::c_int,
) -> Result<File, OdenParentRetainedContractError> {
  let component_bytes = CString::new(component.as_bytes()).map_err(|_| {
    invalid_path(path, "path component contains NUL")
  })?;
  // SAFETY: `directory` names a live retained directory, `component_bytes`
  // is one NUL-terminated component, and successful `openat` returns one new
  // descriptor owned by this function.
  let raw_descriptor =
    unsafe { libc::openat(directory, component_bytes.as_ptr(), flags) };
  if raw_descriptor < 0 {
    return Err(OdenParentRetainedContractError::OpenComponent {
      path: path.to_string(),
      component: component.to_string(),
      source: std::io::Error::last_os_error(),
    });
  }
  // SAFETY: successful `openat` returned a new uniquely owned descriptor.
  Ok(unsafe { File::from_raw_fd(raw_descriptor) })
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn require_descriptor_stable(
  descriptor: &File,
  expected: &DescriptorSnapshot,
  descriptor_path: &str,
  member: &str,
) -> Result<(), OdenParentRetainedContractError> {
  let actual = DescriptorSnapshot::capture(descriptor, descriptor_path)?;
  if &actual != expected {
    return Err(OdenParentRetainedContractError::DescriptorChanged {
      member: member.to_string(),
      descriptor: descriptor_path.to_string(),
    });
  }
  Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
struct OdenParentDirectoryStream {
  raw: *mut libc::DIR,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl OdenParentDirectoryStream {
  fn from_descriptor(
    descriptor: File,
    directory: &str,
  ) -> Result<Self, OdenParentDirectRepoSourceError> {
    let raw_descriptor = descriptor.into_raw_fd();
    // SAFETY: `raw_descriptor` is a uniquely owned independent directory
    // description. On success fdopendir assumes ownership; on failure this
    // function closes it below.
    let raw = unsafe { libc::fdopendir(raw_descriptor) };
    if raw.is_null() {
      let source = std::io::Error::last_os_error();
      // SAFETY: fdopendir failed and therefore did not take ownership.
      unsafe { libc::close(raw_descriptor) };
      return Err(OdenParentDirectRepoSourceError::EnumerateDirectory {
        directory: directory.to_string(),
        source,
      });
    }
    Ok(Self { raw })
  }

  fn close(
    mut self,
    directory: &str,
  ) -> Result<(), OdenParentDirectRepoSourceError> {
    let raw = std::mem::replace(&mut self.raw, std::ptr::null_mut());
    // SAFETY: `raw` is the live stream uniquely owned by this value. closedir
    // closes both the stream and its independent descriptor.
    if unsafe { libc::closedir(raw) } != 0 {
      return Err(OdenParentDirectRepoSourceError::EnumerateDirectory {
        directory: directory.to_string(),
        source: std::io::Error::last_os_error(),
      });
    }
    Ok(())
  }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl Drop for OdenParentDirectoryStream {
  fn drop(&mut self) {
    if !self.raw.is_null() {
      // SAFETY: a non-null pointer is the still-live stream uniquely owned by
      // this value. Drop is only the error-path fallback; successful scans
      // call `close` and require its result.
      unsafe { libc::closedir(self.raw) };
      self.raw = std::ptr::null_mut();
    }
  }
}

#[cfg(target_os = "linux")]
fn clear_oden_parent_readdir_errno() {
  // SAFETY: libc exposes the calling thread's writable errno cell.
  unsafe { *libc::__errno_location() = 0 };
}

#[cfg(target_os = "macos")]
fn clear_oden_parent_readdir_errno() {
  // SAFETY: libc exposes the calling thread's writable errno cell.
  unsafe { *libc::__error() = 0 };
}

#[cfg(target_os = "linux")]
fn oden_parent_readdir_errno() -> libc::c_int {
  // SAFETY: libc exposes the calling thread's readable errno cell.
  unsafe { *libc::__errno_location() }
}

#[cfg(target_os = "macos")]
fn oden_parent_readdir_errno() -> libc::c_int {
  // SAFETY: libc exposes the calling thread's readable errno cell.
  unsafe { *libc::__error() }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn fixed_array_length<T, const N: usize>(_: *const [T; N]) -> usize {
  N
}

#[cfg(target_os = "linux")]
unsafe fn oden_parent_dirent_name(
  entry: *const libc::dirent,
  directory: &str,
) -> Result<Vec<u8>, OdenParentDirectRepoSourceError> {
  // SAFETY: the caller guarantees the fixed d_reclen header is accessible.
  let record_length_pointer =
    unsafe { std::ptr::addr_of!((*entry).d_reclen) };
  // SAFETY: readdir supplied a record containing d_reclen; unaligned access
  // avoids creating a full-size dirent reference for a short Linux record.
  let record_length =
    unsafe { std::ptr::read_unaligned(record_length_pointer) } as usize;
  let name_offset = std::mem::offset_of!(libc::dirent, d_name);
  let Some(record_name_bytes) = record_length.checked_sub(name_offset) else {
    return Err(
      OdenParentDirectRepoSourceError::MalformedDirectoryEntry(
        directory.to_string(),
      ),
    );
  };
  // SAFETY: only the field address is formed; the slice below is separately
  // capped to the record and declared-array bounds.
  let name_array_pointer = unsafe { std::ptr::addr_of!((*entry).d_name) };
  let bound = record_name_bytes.min(fixed_array_length(name_array_pointer));
  // SAFETY: `bound` is capped by both this record's d_reclen bytes after the
  // d_name offset and the platform declaration's fixed array capacity.
  let name = unsafe {
    std::slice::from_raw_parts(name_array_pointer.cast::<u8>(), bound)
  };
  let Some(name_end) = name.iter().position(|unit| *unit == 0) else {
    return Err(
      OdenParentDirectRepoSourceError::MalformedDirectoryEntry(
        directory.to_string(),
      ),
    );
  };
  Ok(name[..name_end].to_vec())
}

#[cfg(target_os = "macos")]
unsafe fn oden_parent_dirent_name(
  entry: *const libc::dirent,
  directory: &str,
) -> Result<Vec<u8>, OdenParentDirectRepoSourceError> {
  // SAFETY: the caller guarantees both fixed header fields are accessible.
  let record_length_pointer =
    unsafe { std::ptr::addr_of!((*entry).d_reclen) };
  // SAFETY: same fixed-header guarantee as d_reclen.
  let name_length_pointer =
    unsafe { std::ptr::addr_of!((*entry).d_namlen) };
  // SAFETY: readdir supplied a record containing both fixed header fields;
  // unaligned reads avoid creating a full-size dirent reference.
  let record_length =
    unsafe { std::ptr::read_unaligned(record_length_pointer) } as usize;
  // SAFETY: same fixed-header guarantee as d_reclen above.
  let name_length =
    unsafe { std::ptr::read_unaligned(name_length_pointer) } as usize;
  // SAFETY: only the field address is formed; the slice below is separately
  // capped to the record and declared-array bounds.
  let name_array_pointer = unsafe { std::ptr::addr_of!((*entry).d_name) };
  let capacity = fixed_array_length(name_array_pointer);
  let name_offset = std::mem::offset_of!(libc::dirent, d_name);
  let Some(record_name_bytes) = record_length.checked_sub(name_offset) else {
    return Err(
      OdenParentDirectRepoSourceError::MalformedDirectoryEntry(
        directory.to_string(),
      ),
    );
  };
  let Some(terminated_length) = name_length.checked_add(1) else {
    return Err(
      OdenParentDirectRepoSourceError::MalformedDirectoryEntry(
        directory.to_string(),
      ),
    );
  };
  if name_length >= capacity || terminated_length > record_name_bytes {
    return Err(
      OdenParentDirectRepoSourceError::MalformedDirectoryEntry(
        directory.to_string(),
      ),
    );
  }
  // SAFETY: `terminated_length` is within both d_reclen's record bytes and
  // the declared fixed d_name capacity.
  let name = unsafe {
    std::slice::from_raw_parts(
      name_array_pointer.cast::<u8>(),
      terminated_length,
    )
  };
  if name[name_length] != 0 || name[..name_length].contains(&0) {
    return Err(
      OdenParentDirectRepoSourceError::MalformedDirectoryEntry(
        directory.to_string(),
      ),
    );
  }
  Ok(name[..name_length].to_vec())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn require_exact_directory_component(
  directory: &File,
  expected_snapshot: &DescriptorSnapshot,
  directory_path: &str,
  member_path: &str,
  component: &str,
) -> Result<(), OdenParentDirectRepoSourceError> {
  let scan_flags = libc::O_RDONLY
    | libc::O_DIRECTORY
    | libc::O_NOFOLLOW
    | libc::O_CLOEXEC;
  // Opening `.` relative to the held directory creates an independent open
  // file description. A dup is ineligible because it shares directory offset.
  let scan_descriptor = open_component(
    directory.as_raw_fd(),
    member_path,
    ".",
    scan_flags,
  )?;
  let scan_snapshot =
    DescriptorSnapshot::capture(&scan_descriptor, directory_path)?;
  if &scan_snapshot != expected_snapshot {
    return Err(OdenParentDirectRepoSourceError::DescriptorChanged {
      member: member_path.to_string(),
      descriptor: directory_path.to_string(),
    });
  }
  let stream =
    OdenParentDirectoryStream::from_descriptor(scan_descriptor, directory_path)?;
  let scan_result = (|| {
    let mut exact_matches = 0_usize;
    let mut folded_matches = 0_usize;
    loop {
      clear_oden_parent_readdir_errno();
      // SAFETY: `stream.raw` is a live uniquely owned DIR. Each returned
      // pointer is inspected only until the next readdir call.
      let entry = unsafe { libc::readdir(stream.raw) };
      if entry.is_null() {
        let errno = oden_parent_readdir_errno();
        if errno != 0 {
          return Err(OdenParentDirectRepoSourceError::EnumerateDirectory {
            directory: directory_path.to_string(),
            source: std::io::Error::from_raw_os_error(errno),
          });
        }
        break;
      }
      // SAFETY: readdir returned a record with its fixed header accessible.
      // The helper copies only record-bounded name bytes before the next
      // readdir; d_type is intentionally ignored.
      let name = unsafe { oden_parent_dirent_name(entry, directory_path) }?;
      if name == component.as_bytes() {
        exact_matches = exact_matches.saturating_add(1);
      }
      if name.eq_ignore_ascii_case(component.as_bytes()) {
        folded_matches = folded_matches.saturating_add(1);
      }
    }
    Ok((exact_matches, folded_matches))
  })();
  let close_result = stream.close(directory_path);
  let (exact_matches, folded_matches) = match scan_result {
    Ok(matches) => matches,
    Err(error) => {
      let _ = close_result;
      return Err(error);
    }
  };
  close_result?;
  if exact_matches != 1 {
    return Err(
      OdenParentDirectRepoSourceError::InvalidExactComponentCount {
        directory: directory_path.to_string(),
        component: component.to_string(),
        matches: exact_matches,
      },
    );
  }
  if folded_matches != 1 {
    return Err(
      OdenParentDirectRepoSourceError::InvalidCaseFoldedComponentCount {
        directory: directory_path.to_string(),
        component: component.to_string(),
        matches: folded_matches,
      },
    );
  }
  Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn require_exact_retained_contract_component(
  directory: &File,
  expected_snapshot: &DescriptorSnapshot,
  directory_path: &str,
  member_path: &str,
  component: &str,
) -> Result<(), OdenParentRetainedContractError> {
  require_exact_directory_component(
    directory,
    expected_snapshot,
    directory_path,
    member_path,
    component,
  )
  .map_err(|source| OdenParentRetainedContractError::ExactNameObservation {
    path: member_path.to_string(),
    source: Box::new(source),
  })
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn direct_repo_relative_path_and_key(
  root: &RetainedRepositoryRoot,
  specifier: &ModuleSpecifier,
) -> Result<(String, OdenParentRepoVfsKey), OdenParentDirectRepoSourceError> {
  if specifier.scheme() != "file" {
    return Err(OdenParentDirectRepoSourceError::InvalidFileUrl(
      "scheme is not file",
    ));
  }
  if specifier.host_str().is_some() {
    return Err(OdenParentDirectRepoSourceError::InvalidFileUrl(
      "URL has a host",
    ));
  }
  if !specifier.username().is_empty()
    || specifier.password().is_some()
    || specifier.port().is_some()
  {
    return Err(OdenParentDirectRepoSourceError::InvalidFileUrl(
      "URL has userinfo or a port",
    ));
  }
  if specifier.query().is_some() || specifier.fragment().is_some() {
    return Err(OdenParentDirectRepoSourceError::InvalidFileUrl(
      "URL has a query or fragment",
    ));
  }
  let decoded_path = specifier.to_file_path().map_err(|_| {
    OdenParentDirectRepoSourceError::InvalidFileUrl(
      "URL cannot be decoded as an absolute platform path",
    )
  })?;
  if !decoded_path.is_absolute() {
    return Err(OdenParentDirectRepoSourceError::InvalidFileUrl(
      "decoded path is not absolute",
    ));
  }
  let round_trip = ModuleSpecifier::from_file_path(&decoded_path).map_err(|_| {
    OdenParentDirectRepoSourceError::InvalidFileUrl(
      "decoded path cannot be encoded as a file URL",
    )
  })?;
  if round_trip.as_str().as_bytes() != specifier.as_str().as_bytes() {
    return Err(OdenParentDirectRepoSourceError::InvalidFileUrl(
      "URL spelling is not the byte-exact path round trip",
    ));
  }
  let relative_path = decoded_path.strip_prefix(&root.path).map_err(|_| {
    OdenParentDirectRepoSourceError::OutsideRetainedRoot {
      specifier: specifier.to_string(),
      root: root.path.clone(),
    }
  })?;
  if relative_path.as_os_str().is_empty() {
    return Err(OdenParentDirectRepoSourceError::OutsideRetainedRoot {
      specifier: specifier.to_string(),
      root: root.path.clone(),
    });
  }
  let relative_path = relative_path
    .to_str()
    .ok_or(OdenParentDirectRepoSourceError::NonUtf8RelativePath)?
    .to_string();
  let key =
    OdenParentRepoVfsKey::from_repository_relative_path(&relative_path)?;
  Ok((relative_path, key))
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn read_oden_parent_direct_repo_source<'a>(
  root: &'a RetainedRepositoryRoot,
  specifier: &ModuleSpecifier,
  original_bytes: Arc<[u8]>,
) -> Result<OdenParentDirectRepoSourceRead<'a>, OdenParentDirectRepoSourceError>
{
  root.require_stable("<direct-source-entry>")?;
  root.require_current_and_named_paths_stable("candidate entry")?;
  let (path, key) = direct_repo_relative_path_and_key(root, specifier)?;
  let components = path.split('/').collect::<Vec<_>>();
  let (file_name, directory_components) = components
    .split_last()
    .expect("typed repository key path has at least one component");
  let directory_flags = libc::O_RDONLY
    | libc::O_DIRECTORY
    | libc::O_NOFOLLOW
    | libc::O_CLOEXEC;
  let mut held_directories: Vec<HeldDirectory> =
    Vec::with_capacity(directory_components.len());
  let mut directory_path = String::new();
  for component in directory_components {
    let (parent_descriptor, parent_snapshot, parent_path) =
      match held_directories.last() {
        Some(directory) => (
          &directory.descriptor,
          &directory.snapshot,
          directory.path.as_str(),
        ),
        None => (&root.descriptor, &root.snapshot, "."),
      };
    require_exact_directory_component(
      parent_descriptor,
      parent_snapshot,
      parent_path,
      &path,
      component,
    )?;
    if !directory_path.is_empty() {
      directory_path.push('/');
    }
    directory_path.push_str(component);
    let descriptor = open_component(
      parent_descriptor.as_raw_fd(),
      &path,
      component,
      directory_flags,
    )?;
    let snapshot = DescriptorSnapshot::capture(&descriptor, &directory_path)?;
    if !snapshot.is_directory() {
      return Err(
        OdenParentDirectRepoSourceError::ComponentNotDirectory(
          directory_path,
        ),
      );
    }
    held_directories.push(HeldDirectory {
      path: directory_path.clone(),
      descriptor,
      snapshot,
    });
  }

  let (parent_descriptor, parent_snapshot, parent_path) =
    match held_directories.last() {
      Some(directory) => (
        &directory.descriptor,
        &directory.snapshot,
        directory.path.as_str(),
      ),
      None => (&root.descriptor, &root.snapshot, "."),
    };
  require_exact_directory_component(
    parent_descriptor,
    parent_snapshot,
    parent_path,
    &path,
    file_name,
  )?;
  let file_flags = libc::O_RDONLY
    | libc::O_NONBLOCK
    | libc::O_NOFOLLOW
    | libc::O_CLOEXEC;
  let mut descriptor = open_component(
    parent_descriptor.as_raw_fd(),
    &path,
    file_name,
    file_flags,
  )?;
  let snapshot = DescriptorSnapshot::capture(&descriptor, &path)?;
  if !snapshot.is_regular_file() {
    return Err(OdenParentDirectRepoSourceError::NotRegularFile(path));
  }
  if snapshot.links != 1 {
    return Err(OdenParentDirectRepoSourceError::InvalidLinkCount {
      path,
      links: snapshot.links,
    });
  }
  let expected_size = original_bytes.len() as u64;
  if snapshot.size < 0 || snapshot.size as u64 != expected_size {
    return Err(OdenParentDirectRepoSourceError::SizeMismatch {
      path,
      expected: expected_size,
      actual: snapshot.size,
    });
  }

  let mut offset = 0_usize;
  let mut buffer = [0_u8; 8_192];
  while offset < original_bytes.len() {
    let remaining = original_bytes.len() - offset;
    let chunk_length = remaining.min(buffer.len());
    let read_length = descriptor
      .read(&mut buffer[..chunk_length])
      .map_err(|source| OdenParentDirectRepoSourceError::ReadFile {
        path: path.clone(),
        source,
      })?;
    if read_length == 0 {
      return Err(OdenParentDirectRepoSourceError::UnexpectedEof {
        path,
        offset: offset as u64,
      });
    }
    let expected = &original_bytes[offset..offset + read_length];
    if buffer[..read_length] != *expected {
      let mismatch = buffer[..read_length]
        .iter()
        .zip(expected)
        .position(|(actual, expected)| actual != expected)
        .expect("unequal slices have a mismatching byte");
      return Err(OdenParentDirectRepoSourceError::ByteMismatch {
        path,
        offset: (offset + mismatch) as u64,
      });
    }
    offset += read_length;
  }
  let mut trailing = [0_u8; 1];
  let trailing_length = descriptor.read(&mut trailing).map_err(|source| {
    OdenParentDirectRepoSourceError::ReadFile {
      path: path.clone(),
      source,
    }
  })?;
  if trailing_length != 0 {
    return Err(OdenParentDirectRepoSourceError::TrailingBytes(path));
  }
  let executable = snapshot.mode & 0o111 != 0;

  Ok(OdenParentDirectRepoSourceRead {
    root,
    key,
    specifier: specifier.clone(),
    original_bytes,
    executable,
    path,
    descriptor,
    snapshot,
    held_directories,
  })
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn finish_oden_parent_direct_repo_source(
  read: OdenParentDirectRepoSourceRead<'_>,
) -> Result<OdenParentDirectRepoSourceCandidate, OdenParentDirectRepoSourceError>
{
  let actual = DescriptorSnapshot::capture(&read.descriptor, &read.path)?;
  if actual != read.snapshot {
    return Err(OdenParentDirectRepoSourceError::DescriptorChanged {
      member: read.path.clone(),
      descriptor: read.path,
    });
  }
  for directory in read.held_directories.iter().rev() {
    let actual = DescriptorSnapshot::capture(&directory.descriptor, &directory.path)?;
    if actual != directory.snapshot {
      return Err(OdenParentDirectRepoSourceError::DescriptorChanged {
        member: read.path.clone(),
        descriptor: directory.path.clone(),
      });
    }
  }
  read.root.require_stable(&read.path)?;
  read
    .root
    .require_current_and_named_paths_stable("candidate terminal")?;
  Ok(OdenParentDirectRepoSourceCandidate {
    key: read.key,
    specifier: read.specifier,
    original_bytes: read.original_bytes,
    executable: read.executable,
  })
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[allow(dead_code)]
fn observe_oden_parent_direct_repo_source_candidate_with_current_root(
  specifier: &ModuleSpecifier,
  original_bytes: Arc<[u8]>,
) -> Result<OdenParentDirectRepoSourceCandidate, OdenParentDirectRepoSourceError>
{
  let root = RetainedRepositoryRoot::open_current()?;
  let read =
    read_oden_parent_direct_repo_source(&root, specifier, original_bytes)?;
  finish_oden_parent_direct_repo_source(read)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn observe_direct_repository_source_with_retained_root(
  root: &RetainedRepositoryRoot,
  specifier: &ModuleSpecifier,
  original_bytes: Arc<[u8]>,
) -> Result<
  OdenParentDirectRepoSourceCandidate,
  OdenParentDirectRepoSourceObservationError,
> {
  let read =
    read_oden_parent_direct_repo_source(root, specifier, original_bytes)?;
  finish_oden_parent_direct_repo_source(read).map_err(Into::into)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn observe_bootstrap_asset_source_with_retained_root(
  root: &RetainedRepositoryRoot,
  specifier: &ModuleSpecifier,
) -> Result<
  OdenParentDirectRepoSourceCandidate,
  OdenParentDirectRepoSourceObservationError,
> {
  let candidate = (|| {
      let expected = ModuleSpecifier::from_file_path(
        root.path.join(ODEN_PARENT_BOOTSTRAP_ASSET_PATH),
      )
      .map_err(|_| {
        OdenParentDirectRepoSourceError::InvalidBootstrapAsset(
          "retained root cannot form the frozen file URL",
        )
      })?;
      if specifier.as_str().as_bytes() != expected.as_str().as_bytes() {
        return Err(OdenParentDirectRepoSourceError::InvalidBootstrapAsset(
          "specifier is not the frozen repository bootstrap path",
        ));
      }

      validate_retained_contract_paths(&[ODEN_PARENT_BOOTSTRAP_ASSET_PATH])?;
      let mut aggregate_bytes = 0_u64;
      fn ignore_post_read(_: &str) {}
      let mut post_read_hook = ignore_post_read;
      let retained = load_one_retained_contract_file(
        root,
        ODEN_PARENT_BOOTSTRAP_ASSET_PATH,
        &mut aggregate_bytes,
        RetainedContractFileLimits {
          file_bytes: ODEN_PARENT_BOOTSTRAP_ASSET_MAX_BYTES,
          inventory_bytes: ODEN_PARENT_BOOTSTRAP_ASSET_MAX_BYTES,
        },
        &mut post_read_hook,
      )?;
      let original_bytes = Arc::<[u8]>::from(retained.bytes);
      let read = read_oden_parent_direct_repo_source(
        root,
        specifier,
        original_bytes,
      )?;
      let candidate = finish_oden_parent_direct_repo_source(read)?;
      if candidate.key().as_str() != ODEN_PARENT_BOOTSTRAP_ASSET_KEY
        || candidate.executable()
      {
        return Err(OdenParentDirectRepoSourceError::InvalidBootstrapAsset(
          "retained file role is not canonical and nonexecutable",
        ));
      }
      Ok(candidate)
  })()?;
  Ok(candidate)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl OdenParentAllowlistGenerateSession {
  /// Observe one direct repository source through the session's already-held
  /// root. This creates no independent root or path authority; terminal
  /// reconciliation remains part of the existing direct-source boundary.
  pub(super) fn observe_direct_repository_source(
    &self,
    specifier: &ModuleSpecifier,
    original_bytes: Arc<[u8]>,
  ) -> Result<
    OdenParentDirectRepoSourceCandidate,
    OdenParentDirectRepoSourceObservationError,
  > {
    observe_direct_repository_source_with_retained_root(
      &self.root,
      specifier,
      original_bytes,
    )
  }

  /// Read the one reviewed non-module bootstrap asset through this session's
  /// retained root. The returned Arc is allocated only from the exact
  /// no-follow descriptor bytes; no pathname loader or caller byte candidate
  /// can supply this role.
  pub(super) fn observe_bootstrap_asset_source(
    &self,
    specifier: &ModuleSpecifier,
  ) -> Result<
    OdenParentDirectRepoSourceCandidate,
    OdenParentDirectRepoSourceObservationError,
  > {
    observe_bootstrap_asset_source_with_retained_root(&self.root, specifier)
  }
}

#[cfg(all(
  any(target_os = "linux", target_os = "macos"),
  any(test, feature = "__oden_parent_allowlist_embedded")
))]
#[allow(dead_code)]
impl OdenParentAllowlistFullRegenerationSession {
  /// Borrow the same retained root for one exact graph-owned direct-file join.
  /// This observation grants no compositor, writer, or admission authority.
  pub(super) fn observe_direct_repository_source(
    &self,
    specifier: &ModuleSpecifier,
    original_bytes: Arc<[u8]>,
  ) -> Result<
    OdenParentDirectRepoSourceCandidate,
    OdenParentDirectRepoSourceObservationError,
  > {
    observe_direct_repository_source_with_retained_root(
      &self.root,
      specifier,
      original_bytes,
    )
  }

  /// Borrow the same retained root for the reviewed bootstrap asset. Only the
  /// later consuming reconciliation sink can use the owning session.
  pub(super) fn observe_bootstrap_asset_source(
    &self,
    specifier: &ModuleSpecifier,
  ) -> Result<
    OdenParentDirectRepoSourceCandidate,
    OdenParentDirectRepoSourceObservationError,
  > {
    observe_bootstrap_asset_source_with_retained_root(&self.root, specifier)
  }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[allow(dead_code)]
pub(super) fn observe_oden_parent_direct_repo_source_candidate(
  specifier: &ModuleSpecifier,
  original_bytes: Arc<[u8]>,
) -> Result<
  OdenParentDirectRepoSourceCandidate,
  OdenParentDirectRepoSourceObservationError,
> {
  observe_oden_parent_direct_repo_source_candidate_with_current_root(
    specifier,
    original_bytes,
  )
  .map_err(Into::into)
}

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
fn observe_oden_parent_direct_repo_source_from_test_root<H>(
  root_path: &Path,
  specifier: &ModuleSpecifier,
  original_bytes: Arc<[u8]>,
  post_read_hook: H,
) -> Result<OdenParentDirectRepoSourceCandidate, OdenParentDirectRepoSourceError>
where
  H: FnOnce(),
{
  let root = RetainedRepositoryRoot::open_test_absolute(root_path)?;
  let read =
    read_oden_parent_direct_repo_source(&root, specifier, original_bytes)?;
  post_read_hook();
  finish_oden_parent_direct_repo_source(read)
}

#[cfg(all(test, any(target_os = "linux", target_os = "macos")))]
pub(super) fn observe_oden_parent_direct_repo_source_for_join_from_test_root<H>(
  root_path: &Path,
  specifier: &ModuleSpecifier,
  original_bytes: Arc<[u8]>,
  post_read_hook: H,
) -> Result<
  OdenParentDirectRepoSourceCandidate,
  OdenParentDirectRepoSourceObservationError,
>
where
  H: FnOnce(),
{
  observe_oden_parent_direct_repo_source_from_test_root(
    root_path,
    specifier,
    original_bytes,
    post_read_hook,
  )
  .map_err(Into::into)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn load_one_retained_contract_file<H>(
  root: &RetainedRepositoryRoot,
  path: &str,
  aggregate_bytes: &mut u64,
  limits: RetainedContractFileLimits,
  post_read_hook: &mut H,
) -> Result<RetainedContractFile, OdenParentRetainedContractError>
where
  H: FnMut(&str),
{
  let components = path.split('/').collect::<Vec<_>>();
  let (file_name, directory_components) = components
    .split_last()
    .expect("validated retained path has at least one component");
  let directory_flags = libc::O_RDONLY
    | libc::O_DIRECTORY
    | libc::O_NOFOLLOW
    | libc::O_CLOEXEC;
  let mut held_directories: Vec<HeldDirectory> =
    Vec::with_capacity(directory_components.len());
  let mut directory_path = String::new();
  for component in directory_components {
    let (parent, parent_snapshot, parent_path) = match held_directories.last() {
      Some(parent) => (
        &parent.descriptor,
        &parent.snapshot,
        parent.path.as_str(),
      ),
      None => (&root.descriptor, &root.snapshot, "."),
    };
    require_exact_retained_contract_component(
      parent,
      parent_snapshot,
      parent_path,
      path,
      component,
    )?;
    if !directory_path.is_empty() {
      directory_path.push('/');
    }
    directory_path.push_str(component);
    let descriptor =
      open_component(parent.as_raw_fd(), path, component, directory_flags)?;
    let snapshot = DescriptorSnapshot::capture(&descriptor, &directory_path)?;
    if !snapshot.is_directory() {
      return Err(
        OdenParentRetainedContractError::ComponentNotDirectory(
          directory_path,
        ),
      );
    }
    held_directories.push(HeldDirectory {
      path: directory_path.clone(),
      descriptor,
      snapshot,
    });
  }

  let file_flags = libc::O_RDONLY
    | libc::O_NONBLOCK
    | libc::O_NOFOLLOW
    | libc::O_CLOEXEC;
  let (parent, parent_snapshot, parent_path) = match held_directories.last() {
    Some(parent) => (
      &parent.descriptor,
      &parent.snapshot,
      parent.path.as_str(),
    ),
    None => (&root.descriptor, &root.snapshot, "."),
  };
  require_exact_retained_contract_component(
    parent,
    parent_snapshot,
    parent_path,
    path,
    file_name,
  )?;
  let mut descriptor =
    open_component(parent.as_raw_fd(), path, file_name, file_flags)?;
  let snapshot = DescriptorSnapshot::capture(&descriptor, path)?;
  if !snapshot.is_regular_file() {
    return Err(OdenParentRetainedContractError::NotRegularFile(
      path.to_string(),
    ));
  }
  if snapshot.links != 1 {
    return Err(OdenParentRetainedContractError::InvalidLinkCount {
      path: path.to_string(),
      links: snapshot.links,
    });
  }
  if snapshot.size < 1 || snapshot.size as u64 > limits.file_bytes {
    return Err(OdenParentRetainedContractError::InvalidFileSize {
      path: path.to_string(),
      size: snapshot.size,
      limit: limits.file_bytes,
    });
  }
  let size = snapshot.size as u64;
  let next_aggregate = aggregate_bytes.checked_add(size).ok_or_else(|| {
    OdenParentRetainedContractError::InventoryTooLarge {
      path: path.to_string(),
      size: u64::MAX,
      limit: limits.inventory_bytes,
    }
  })?;
  if next_aggregate > limits.inventory_bytes {
    return Err(OdenParentRetainedContractError::InventoryTooLarge {
      path: path.to_string(),
      size: next_aggregate,
      limit: limits.inventory_bytes,
    });
  }

  let mut bytes = vec![0; size as usize];
  descriptor.read_exact(&mut bytes).map_err(|source| {
    OdenParentRetainedContractError::ReadFile {
      path: path.to_string(),
      source,
    }
  })?;
  let mut trailing = [0_u8; 1];
  let trailing_length = descriptor.read(&mut trailing).map_err(|source| {
    OdenParentRetainedContractError::ReadFile {
      path: path.to_string(),
      source,
    }
  })?;
  if trailing_length != 0 {
    return Err(OdenParentRetainedContractError::TrailingBytes(
      path.to_string(),
    ));
  }

  post_read_hook(path);
  require_descriptor_stable(&descriptor, &snapshot, path, path)?;
  for directory in held_directories.iter().rev() {
    require_descriptor_stable(
      &directory.descriptor,
      &directory.snapshot,
      &directory.path,
      path,
    )?;
  }
  root.require_stable(path)?;
  *aggregate_bytes = next_aggregate;

  Ok(RetainedContractFile {
    path: path.to_string(),
    bytes,
  })
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn load_validated_retained_contract_files_from_root<H>(
  root: &RetainedRepositoryRoot,
  paths: &[&str],
  limits: RetainedContractFileLimits,
  mut post_read_hook: H,
) -> Result<RetainedContractFiles, OdenParentRetainedContractError>
where
  H: FnMut(&str),
{
  let mut aggregate_bytes = 0_u64;
  let mut files = Vec::with_capacity(paths.len());
  for path in paths {
    // A member's owned bytes are accepted only after its retained descriptor
    // chain is stable. Multi-member tree authentication and reconciliation
    // remain separate downstream gates; this local projection is not a
    // coherent repository snapshot.
    files.push(load_one_retained_contract_file(
      root,
      path,
      &mut aggregate_bytes,
      limits,
      &mut post_read_hook,
    )?);
  }
  root.require_stable("<complete-inventory>")?;
  let contract_files = files
    .iter()
    .map(|file| ContractFile {
      path: &file.path,
      bytes: &file.bytes,
    })
    .collect::<Vec<_>>();
  let inventory = ContractInventory::from_files(&contract_files)?;
  Ok(RetainedContractFiles { files, inventory })
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn load_retained_contract_files_with<O, H>(
  paths: &[&str],
  limits: RetainedContractFileLimits,
  open_root: O,
  post_read_hook: H,
) -> Result<RetainedContractFiles, OdenParentRetainedContractError>
where
  O: FnOnce() -> Result<RetainedRepositoryRoot, OdenParentRetainedContractError>,
  H: FnMut(&str),
{
  // Validate every literal before opening `.` or any member path.
  validate_retained_contract_paths(paths)?;
  let root = open_root()?;
  load_validated_retained_contract_files_from_root(
    &root,
    paths,
    limits,
    post_read_hook,
  )
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn load_retained_contract_files_from_root(
  root: &RetainedRepositoryRoot,
  paths: &[&str],
) -> Result<RetainedContractFiles, OdenParentRetainedContractError> {
  validate_retained_contract_paths(paths)?;
  load_validated_retained_contract_files_from_root(
    root,
    paths,
    ODEN_PARENT_RETAINED_CONTRACT_FILE_LIMITS,
    |_| {},
  )
}

/// Independent Linux/macOS loader retained for tests and non-session callers.
/// Authoring Generate instead uses the borrowed-root loader so graph, all three
/// inventories, and output replacement cannot silently select different roots.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[allow(dead_code)]
fn load_retained_contract_files(
  paths: &[&str],
) -> Result<RetainedContractFiles, OdenParentRetainedContractError> {
  load_retained_contract_files_with(
    paths,
    ODEN_PARENT_RETAINED_CONTRACT_FILE_LIMITS,
    RetainedRepositoryRoot::open_current,
    |_| {},
  )
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn load_retained_contract_byte_bundle_with<O>(
  mut open_root: O,
) -> Result<RetainedContractByteBundle, OdenParentRetainedContractError>
where
  O: FnMut() -> Result<RetainedRepositoryRoot, OdenParentRetainedContractError>,
{
  let capture = load_retained_contract_files_with(
    ODEN_PARENT_CAPTURE_CONTRACT_PATHS,
    ODEN_PARENT_RETAINED_CONTRACT_FILE_LIMITS,
    || open_root(),
    |_| {},
  )?;
  let source_closure = load_retained_contract_files_with(
    ODEN_PARENT_SOURCE_CLOSURE_CONTRACT_PATHS,
    ODEN_PARENT_RETAINED_CONTRACT_FILE_LIMITS,
    || open_root(),
    |_| {},
  )?;
  let release = load_retained_contract_files_with(
    ODEN_PARENT_RELEASE_CONTRACT_PATHS,
    ODEN_PARENT_RETAINED_CONTRACT_FILE_LIMITS,
    || open_root(),
    |_| {},
  )?;

  Ok(RetainedContractByteBundle {
    capture,
    source_closure,
    release,
  })
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn load_retained_contract_byte_bundle_from_root(
  root: &RetainedRepositoryRoot,
) -> Result<RetainedContractByteBundle, OdenParentRetainedContractError> {
  root.require_current_and_named_paths_stable("generate inventory start")?;
  root.require_stable("<generate-inventories>")?;
  let capture = load_retained_contract_files_from_root(
    root,
    ODEN_PARENT_CAPTURE_CONTRACT_PATHS,
  )?;
  let source_closure = load_retained_contract_files_from_root(
    root,
    ODEN_PARENT_SOURCE_CLOSURE_CONTRACT_PATHS,
  )?;
  let release = load_retained_contract_files_from_root(
    root,
    ODEN_PARENT_RELEASE_CONTRACT_PATHS,
  )?;
  root.require_stable("<generate-inventories>")?;
  root.require_current_and_named_paths_stable("generate inventory terminal")?;
  Ok(RetainedContractByteBundle {
    capture,
    source_closure,
    release,
  })
}

/// Independent-root composition seam retained for focused tests. The admitted
/// authoring path uses `load_retained_contract_byte_bundle_from_root` and never
/// reopens the repository root.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[allow(dead_code)]
fn load_retained_contract_byte_bundle(
) -> Result<RetainedContractByteBundle, OdenParentRetainedContractError> {
  load_retained_contract_byte_bundle_with(
    RetainedRepositoryRoot::open_current,
  )
}

// @ref LLP 0019#frozen-parent-standalone-allowlist-and-byte-graph [implements] —
// Compose only authoring review-candidate bytes; source authentication and all
// generated-input, Check, admission, brand, and release authority stay separate.
/// Purely composes the retained inventory projections with already-typed
/// compiler projections. This pure function performs no I/O; its admitted
/// production caller is only the authoring Generate session.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[allow(dead_code)]
fn compose_oden_parent_allowlist_candidate(
  retained: &RetainedContractByteBundle,
  compiler: OdenParentAllowlistCompilerProjectionInput<'_>,
) -> Result<OdenParentAllowlistCandidateOutput, OdenParentAllowlistError> {
  let allowlist = OdenParentAllowlist::from_inputs(OdenParentAllowlistInputs {
    capture_contract: retained.capture.inventory(),
    source_closure_contract: retained.source_closure.inventory(),
    release_contract: retained.release.inventory(),
    configuration: compiler.configuration,
    vfs_graph: compiler.vfs_graph,
    static_import_edge: compiler.static_import_edge,
  })?;
  let canonical_jcs = allowlist.canonical_jcs()?;
  let digest = allowlist.digest()?.as_str().to_string();
  Ok(OdenParentAllowlistCandidateOutput {
    canonical_jcs,
    digest,
    json_file: allowlist.render_json_file()?,
    rust_module: allowlist.render_rust_module()?,
  })
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
const ODEN_PARENT_GENERATED_JSON_TEMP_NAME: &str =
  ".filesystem-parent-standalone-allowlist.json.oden-generate.tmp";
#[cfg(any(target_os = "linux", target_os = "macos"))]
const ODEN_PARENT_GENERATED_RUST_TEMP_NAME: &str =
  ".oden_parent_allowlist_generated.rs.oden-generate.tmp";

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn same_descriptor_identity(
  left: &DescriptorSnapshot,
  right: &DescriptorSnapshot,
) -> bool {
  left.device == right.device && left.inode == right.inode
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn capture_named_output_no_follow(
  directory: RawFd,
  name: &CString,
  path: &'static str,
) -> Result<Option<DescriptorSnapshot>, OdenParentAllowlistGenerateFailure> {
  let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
  // SAFETY: `directory` is a live held directory, `name` is one terminated
  // component, and AT_SYMLINK_NOFOLLOW prevents a final symlink traversal.
  if unsafe {
    libc::fstatat(
      directory,
      name.as_ptr(),
      stat.as_mut_ptr(),
      libc::AT_SYMLINK_NOFOLLOW,
    )
  } != 0
  {
    let source = std::io::Error::last_os_error();
    if source.raw_os_error() == Some(libc::ENOENT) {
      return Ok(None);
    }
    return Err(OdenParentAllowlistGenerateFailure::OpenOutput {
      path,
      source,
    });
  }
  // SAFETY: successful `fstatat` initialized the complete value.
  Ok(Some(DescriptorSnapshot::from_stat(unsafe {
    stat.assume_init()
  })))
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn validate_fixed_generate_output_path(
  path: &'static str,
) -> Result<(), OdenParentAllowlistGenerateFailure> {
  if (path != ODEN_PARENT_GENERATED_JSON_PATH
    && path != ODEN_PARENT_GENERATED_RUST_PATH)
    || path.is_empty()
    || !path.is_ascii()
    || path.starts_with('/')
    || path.contains(['\\', '\0'])
    || path.split('/').any(|component| {
      component.is_empty()
        || matches!(component, "." | "..")
        || component.len() > ODEN_PARENT_CONTRACT_COMPONENT_MAX_BYTES
    })
  {
    return Err(OdenParentAllowlistGenerateFailure::InvalidOutputPath(path));
  }
  Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
struct PreparedGenerateOutput {
  path: &'static str,
  file_name: CString,
  temporary_name: CString,
  held_directories: Vec<HeldDirectory>,
  existing: Option<(File, DescriptorSnapshot)>,
  temporary: File,
  temporary_snapshot: DescriptorSnapshot,
  directory_snapshot_after_stage: DescriptorSnapshot,
  temporary_is_named: bool,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
struct CreatedTemporaryNameGuard<'a> {
  directory: RawFd,
  name: &'a CString,
  temporary: RawFd,
  armed: bool,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl Drop for CreatedTemporaryNameGuard<'_> {
  fn drop(&mut self) {
    if !self.armed {
      return;
    }
    let mut held = std::mem::MaybeUninit::<libc::stat>::uninit();
    let mut named = std::mem::MaybeUninit::<libc::stat>::uninit();
    // SAFETY: both descriptors remain live for this local guard. The named
    // lookup is no-follow, and unlink occurs only for the exact held inode.
    let held_ok =
      unsafe { libc::fstat(self.temporary, held.as_mut_ptr()) } == 0;
    // SAFETY: `name` remains borrowed and terminated for the guard lifetime.
    let named_ok = unsafe {
      libc::fstatat(
        self.directory,
        self.name.as_ptr(),
        named.as_mut_ptr(),
        libc::AT_SYMLINK_NOFOLLOW,
      )
    } == 0;
    if held_ok && named_ok {
      // SAFETY: successful stat calls initialized both values.
      let held = unsafe { held.assume_init() };
      // SAFETY: same successful-stat condition.
      let named = unsafe { named.assume_init() };
      if held.st_dev == named.st_dev && held.st_ino == named.st_ino {
        // SAFETY: the comparison above binds this name to the held temporary.
        unsafe { libc::unlinkat(self.directory, self.name.as_ptr(), 0) };
      }
    }
  }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl PreparedGenerateOutput {
  fn directory(&self) -> &HeldDirectory {
    self
      .held_directories
      .last()
      .expect("fixed generated output has a parent directory")
  }

  fn require_held_directories_stable(
    &self,
  ) -> Result<(), OdenParentAllowlistGenerateFailure> {
    let final_index = self.held_directories.len() - 1;
    for (index, directory) in self.held_directories.iter().enumerate() {
      let expected = if index == final_index {
        &self.directory_snapshot_after_stage
      } else {
        &directory.snapshot
      };
      let actual =
        DescriptorSnapshot::capture(&directory.descriptor, &directory.path)?;
      if &actual != expected {
        return Err(
          OdenParentAllowlistGenerateFailure::OutputDirectoryChanged(self.path),
        );
      }
    }
    Ok(())
  }

  fn require_existing_name_stable(
    &self,
  ) -> Result<(), OdenParentAllowlistGenerateFailure> {
    let observed = capture_named_output_no_follow(
      self.directory().descriptor.as_raw_fd(),
      &self.file_name,
      self.path,
    )?;
    match (&self.existing, observed) {
      (None, None) => Ok(()),
      (Some((descriptor, expected)), Some(actual)) => {
        let held = DescriptorSnapshot::capture(descriptor, self.path)?;
        if held == *expected && actual == *expected {
          Ok(())
        } else {
          Err(OdenParentAllowlistGenerateFailure::OutputNameChanged(
            self.path,
          ))
        }
      }
      _ => Err(OdenParentAllowlistGenerateFailure::OutputNameChanged(
        self.path,
      )),
    }
  }

  fn require_temporary_stable(
    &mut self,
    expected_bytes: &[u8],
  ) -> Result<(), OdenParentAllowlistGenerateFailure> {
    let held = DescriptorSnapshot::capture(&self.temporary, self.path)?;
    let named = capture_named_output_no_follow(
      self.directory().descriptor.as_raw_fd(),
      &self.temporary_name,
      self.path,
    )?;
    let held_matches = if self.temporary_is_named {
      held == self.temporary_snapshot
    } else {
      same_descriptor_identity(&held, &self.temporary_snapshot)
        && held.is_regular_file()
        && held.links == 1
        && held.size == self.temporary_snapshot.size
        && held.mode == self.temporary_snapshot.mode
    };
    let name_matches = if self.temporary_is_named {
      named.as_ref() == Some(&self.temporary_snapshot)
    } else {
      named.is_none()
    };
    if !held_matches || !name_matches {
      return Err(OdenParentAllowlistGenerateFailure::TemporaryNameChanged(
        self.path,
      ));
    }
    self.temporary.seek(SeekFrom::Start(0)).map_err(|source| {
      OdenParentAllowlistGenerateFailure::VerifyTemporary {
        path: self.path,
        source,
      }
    })?;
    let mut observed = [0_u8; 8_192];
    let mut offset = 0_usize;
    while offset < expected_bytes.len() {
      let length = observed.len().min(expected_bytes.len() - offset);
      self
        .temporary
        .read_exact(&mut observed[..length])
        .map_err(|source| {
          OdenParentAllowlistGenerateFailure::VerifyTemporary {
            path: self.path,
            source,
          }
        })?;
      if observed[..length] != expected_bytes[offset..offset + length] {
        return Err(OdenParentAllowlistGenerateFailure::TemporaryChanged(
          self.path,
        ));
      }
      offset += length;
    }
    let mut trailing = [0_u8; 1];
    let trailing_length =
      self.temporary.read(&mut trailing).map_err(|source| {
        OdenParentAllowlistGenerateFailure::VerifyTemporary {
          path: self.path,
          source,
        }
      })?;
    if trailing_length != 0 {
      return Err(OdenParentAllowlistGenerateFailure::TemporaryChanged(
        self.path,
      ));
    }
    Ok(())
  }

  fn require_precommit(
    &mut self,
    root: &RetainedRepositoryRoot,
    expected_bytes: &[u8],
  ) -> Result<(), OdenParentAllowlistGenerateFailure> {
    root.require_current_and_named_paths_stable("generate precommit")?;
    root.require_stable(self.path)?;
    self.require_held_directories_stable()?;
    self.require_existing_name_stable()?;
    self.require_temporary_stable(expected_bytes)?;
    Ok(())
  }

  fn commit(
    &mut self,
    root: &RetainedRepositoryRoot,
    expected_bytes: &[u8],
  ) -> Result<(), OdenParentAllowlistGenerateFailure> {
    self.require_precommit(root, expected_bytes)?;
    let directory_fd = self.directory().descriptor.as_raw_fd();
    // SAFETY: both names are terminated single components and `directory_fd`
    // is the retained same directory for source and destination. POSIX rename
    // atomically installs the completely written temporary object.
    if unsafe {
      libc::renameat(
        directory_fd,
        self.temporary_name.as_ptr(),
        directory_fd,
        self.file_name.as_ptr(),
      )
    } != 0
    {
      return Err(OdenParentAllowlistGenerateFailure::RenameOutput {
        path: self.path,
        source: std::io::Error::last_os_error(),
      });
    }
    self.temporary_is_named = false;

    let installed =
      capture_named_output_no_follow(directory_fd, &self.file_name, self.path)?
        .ok_or(OdenParentAllowlistGenerateFailure::ReplacedOutputMismatch(
          self.path,
        ))?;
    if !same_descriptor_identity(&installed, &self.temporary_snapshot)
      || !installed.is_regular_file()
      || installed.links != 1
      || installed.size != expected_bytes.len() as i64
      || installed.mode & 0o777 != 0o644
    {
      return Err(OdenParentAllowlistGenerateFailure::ReplacedOutputMismatch(
        self.path,
      ));
    }
    self.require_temporary_stable(expected_bytes)?;
    self.directory().descriptor.sync_all().map_err(|source| {
      OdenParentAllowlistGenerateFailure::SyncOutputDirectory {
        path: self.path,
        source,
      }
    })?;
    root.require_current_and_named_paths_stable("generate commit")?;
    root.require_stable(self.path)?;
    let durable_name =
      capture_named_output_no_follow(directory_fd, &self.file_name, self.path)?
        .ok_or(OdenParentAllowlistGenerateFailure::ReplacedOutputMismatch(
          self.path,
        ))?;
    if !same_descriptor_identity(&durable_name, &self.temporary_snapshot)
      || !durable_name.is_regular_file()
      || durable_name.links != 1
      || durable_name.size != expected_bytes.len() as i64
      || durable_name.mode & 0o777 != 0o644
    {
      return Err(OdenParentAllowlistGenerateFailure::ReplacedOutputMismatch(
        self.path,
      ));
    }
    let committed_directory =
      DescriptorSnapshot::capture(&self.directory().descriptor, self.path)?;
    if !same_descriptor_identity(
      &committed_directory,
      &self.directory_snapshot_after_stage,
    ) || !committed_directory.is_directory()
    {
      return Err(OdenParentAllowlistGenerateFailure::OutputDirectoryChanged(
        self.path,
      ));
    }
    let final_index = self
      .held_directories
      .len()
      .checked_sub(1)
      .expect("fixed generated output has a parent directory");
    self.held_directories[final_index].snapshot = committed_directory.clone();
    self.directory_snapshot_after_stage = committed_directory;
    Ok(())
  }

  fn require_installed_from_root(
    &mut self,
    root: &RetainedRepositoryRoot,
    expected_bytes: &[u8],
  ) -> Result<(), OdenParentAllowlistGenerateFailure> {
    root.require_current_and_named_paths_stable("generate terminal output")?;
    root.require_stable(self.path)?;
    self.require_held_directories_stable()?;
    self.require_temporary_stable(expected_bytes)?;

    let (reopened_directories, reopened_file_name) =
      open_generate_output_directory(root, self.path)?;
    if reopened_file_name.as_bytes() != self.file_name.as_bytes()
      || reopened_directories.len() != self.held_directories.len()
      || reopened_directories.iter().zip(&self.held_directories).any(
        |(reopened, held)| {
          reopened.path != held.path || reopened.snapshot != held.snapshot
        },
      )
    {
      return Err(OdenParentAllowlistGenerateFailure::OutputDirectoryChanged(
        self.path,
      ));
    }
    let reopened_directory = reopened_directories
      .last()
      .expect("fixed generated output has a parent directory");
    require_generate_output_name_state(
      reopened_directory,
      &reopened_file_name,
      self.path,
      true,
    )?;
    let installed = capture_named_output_no_follow(
      reopened_directory.descriptor.as_raw_fd(),
      &reopened_file_name,
      self.path,
    )?
    .ok_or(OdenParentAllowlistGenerateFailure::ReplacedOutputMismatch(
      self.path,
    ))?;
    if !same_descriptor_identity(&installed, &self.temporary_snapshot)
      || !installed.is_regular_file()
      || installed.links != 1
      || installed.size != expected_bytes.len() as i64
      || installed.mode & 0o777 != 0o644
    {
      return Err(OdenParentAllowlistGenerateFailure::ReplacedOutputMismatch(
        self.path,
      ));
    }
    self.require_temporary_stable(expected_bytes)?;
    root.require_current_and_named_paths_stable("generate terminal output")?;
    root.require_stable(self.path)?;
    Ok(())
  }

  fn remove_owned_temporary_name(&mut self) {
    if !self.temporary_is_named {
      return;
    }
    let directory_fd = self.directory().descriptor.as_raw_fd();
    let named = capture_named_output_no_follow(
      directory_fd,
      &self.temporary_name,
      self.path,
    );
    if matches!(
      named,
      Ok(Some(ref snapshot))
        if same_descriptor_identity(snapshot, &self.temporary_snapshot)
    ) {
      // SAFETY: the retained directory and fixed temporary component name the
      // same inode still held by `temporary`; never unlink a replaced name.
      if unsafe {
        libc::unlinkat(directory_fd, self.temporary_name.as_ptr(), 0)
      } == 0
      {
        self.temporary_is_named = false;
      }
    }
  }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl Drop for PreparedGenerateOutput {
  fn drop(&mut self) {
    self.remove_owned_temporary_name();
  }
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn open_generate_output_directory(
  root: &RetainedRepositoryRoot,
  path: &'static str,
) -> Result<(Vec<HeldDirectory>, CString), OdenParentAllowlistGenerateFailure> {
  validate_fixed_generate_output_path(path)?;
  let components = path.split('/').collect::<Vec<_>>();
  let (file_name, directory_components) = components
    .split_last()
    .expect("validated fixed output is nonempty");
  let file_name = CString::new(file_name.as_bytes())
    .map_err(|_| OdenParentAllowlistGenerateFailure::InvalidOutputPath(path))?;
  let flags =
    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
  let mut held: Vec<HeldDirectory> =
    Vec::with_capacity(directory_components.len());
  let mut directory_path = String::new();
  for component in directory_components {
    let (parent, parent_snapshot, parent_path) = match held.last() {
      Some(parent) => {
        (&parent.descriptor, &parent.snapshot, parent.path.as_str())
      }
      None => (&root.descriptor, &root.snapshot, "."),
    };
    require_exact_directory_component(
      parent,
      parent_snapshot,
      parent_path,
      path,
      component,
    )?;
    if !directory_path.is_empty() {
      directory_path.push('/');
    }
    directory_path.push_str(component);
    let descriptor =
      open_component(parent.as_raw_fd(), path, component, flags)?;
    let snapshot = DescriptorSnapshot::capture(&descriptor, &directory_path)?;
    if !snapshot.is_directory() {
      return Err(OdenParentAllowlistGenerateFailure::InvalidOutputPath(path));
    }
    held.push(HeldDirectory {
      path: directory_path.clone(),
      descriptor,
      snapshot,
    });
  }
  Ok((held, file_name))
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn open_existing_generate_output(
  directory: &HeldDirectory,
  file_name: &CString,
  path: &'static str,
) -> Result<
  Option<(File, DescriptorSnapshot)>,
  OdenParentAllowlistGenerateFailure,
> {
  let flags =
    libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC;
  // SAFETY: `directory` is retained and `file_name` is one terminated
  // component. O_NOFOLLOW rejects a final-name symlink.
  let raw = unsafe {
    libc::openat(directory.descriptor.as_raw_fd(), file_name.as_ptr(), flags)
  };
  if raw < 0 {
    let source = std::io::Error::last_os_error();
    if source.raw_os_error() == Some(libc::ENOENT) {
      require_generate_output_name_state(directory, file_name, path, false)?;
      return Ok(None);
    }
    return Err(OdenParentAllowlistGenerateFailure::OpenOutput {
      path,
      source,
    });
  }
  // SAFETY: successful openat returned one uniquely owned descriptor.
  let descriptor = unsafe { File::from_raw_fd(raw) };
  let snapshot = DescriptorSnapshot::capture(&descriptor, path)?;
  if !snapshot.is_regular_file() || snapshot.links != 1 {
    return Err(OdenParentAllowlistGenerateFailure::InvalidExistingOutput(
      path,
    ));
  }
  require_generate_output_name_state(directory, file_name, path, true)?;
  Ok(Some((descriptor, snapshot)))
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn require_generate_output_name_state(
  directory: &HeldDirectory,
  file_name: &CString,
  path: &'static str,
  exact_present: bool,
) -> Result<(), OdenParentAllowlistGenerateFailure> {
  let scan_flags = libc::O_RDONLY
    | libc::O_DIRECTORY
    | libc::O_NOFOLLOW
    | libc::O_CLOEXEC;
  // Use an independent open file description so a prior directory scan cannot
  // hide a later entry behind a shared offset.
  let scan_descriptor = open_component(
    directory.descriptor.as_raw_fd(),
    path,
    ".",
    scan_flags,
  )?;
  let scan_snapshot =
    DescriptorSnapshot::capture(&scan_descriptor, &directory.path)?;
  if scan_snapshot != directory.snapshot {
    return Err(OdenParentDirectRepoSourceError::DescriptorChanged {
      member: path.to_string(),
      descriptor: directory.path.clone(),
    }
    .into());
  }

  let stream =
    OdenParentDirectoryStream::from_descriptor(scan_descriptor, &directory.path)?;
  let scan_result = (|| {
    let expected = file_name.as_bytes();
    let mut exact_matches = 0_usize;
    let mut folded_matches = 0_usize;
    loop {
      clear_oden_parent_readdir_errno();
      // SAFETY: `stream.raw` is a live uniquely owned DIR. The helper copies
      // only record-bounded name bytes before the next readdir call.
      let entry = unsafe { libc::readdir(stream.raw) };
      if entry.is_null() {
        let errno = oden_parent_readdir_errno();
        if errno != 0 {
          return Err(OdenParentDirectRepoSourceError::EnumerateDirectory {
            directory: directory.path.clone(),
            source: std::io::Error::from_raw_os_error(errno),
          });
        }
        break;
      }
      // SAFETY: readdir returned a record with its fixed header accessible.
      let name = unsafe { oden_parent_dirent_name(entry, &directory.path) }?;
      if name == expected {
        exact_matches = exact_matches.saturating_add(1);
      }
      if name.eq_ignore_ascii_case(expected) {
        folded_matches = folded_matches.saturating_add(1);
      }
    }
    Ok((exact_matches, folded_matches))
  })();
  let close_result = stream.close(&directory.path);
  let (exact_matches, folded_matches) = match scan_result {
    Ok(matches) => matches,
    Err(error) => {
      let _ = close_result;
      return Err(error.into());
    }
  };
  close_result?;

  let after =
    DescriptorSnapshot::capture(&directory.descriptor, &directory.path)?;
  let expected_exact_matches = usize::from(exact_present);
  if after != directory.snapshot
    || exact_matches != expected_exact_matches
    || folded_matches != expected_exact_matches
  {
    return Err(OdenParentAllowlistGenerateFailure::OutputNameChanged(path));
  }
  Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn prepare_generate_output(
  root: &RetainedRepositoryRoot,
  path: &'static str,
  temporary_name: &'static str,
  bytes: &[u8],
) -> Result<PreparedGenerateOutput, OdenParentAllowlistGenerateFailure> {
  let (held_directories, file_name) =
    open_generate_output_directory(root, path)?;
  let directory = held_directories
    .last()
    .expect("fixed generated output has a parent directory");
  let existing = open_existing_generate_output(directory, &file_name, path)?;
  let temporary_name = CString::new(temporary_name.as_bytes())
    .expect("fixed temporary name is one ASCII component");
  let flags = libc::O_RDWR
    | libc::O_CREAT
    | libc::O_EXCL
    | libc::O_NOFOLLOW
    | libc::O_CLOEXEC;
  // SAFETY: the retained directory and terminated fixed name are valid; O_EXCL
  // creates one new same-directory object or refuses without following a name.
  let raw = unsafe {
    libc::openat(
      directory.descriptor.as_raw_fd(),
      temporary_name.as_ptr(),
      flags,
      0o600,
    )
  };
  if raw < 0 {
    return Err(OdenParentAllowlistGenerateFailure::CreateTemporary {
      path,
      source: std::io::Error::last_os_error(),
    });
  }
  // SAFETY: successful openat returned one uniquely owned descriptor.
  let mut temporary = unsafe { File::from_raw_fd(raw) };
  let mut temporary_name_guard = CreatedTemporaryNameGuard {
    directory: directory.descriptor.as_raw_fd(),
    name: &temporary_name,
    temporary: temporary.as_raw_fd(),
    armed: true,
  };
  // SAFETY: `temporary` remains live and 0644 is the deterministic checked-in
  // source/data mode, independent of the invoking process's umask.
  if unsafe { libc::fchmod(temporary.as_raw_fd(), 0o644) } != 0 {
    let source = std::io::Error::last_os_error();
    return Err(OdenParentAllowlistGenerateFailure::SetTemporaryMode {
      path,
      source,
    });
  }
  temporary.write_all(bytes).map_err(|source| {
    OdenParentAllowlistGenerateFailure::WriteTemporary { path, source }
  })?;
  temporary.sync_all().map_err(|source| {
    OdenParentAllowlistGenerateFailure::SyncTemporary { path, source }
  })?;
  let temporary_snapshot = DescriptorSnapshot::capture(&temporary, path)?;
  if !temporary_snapshot.is_regular_file()
    || temporary_snapshot.links != 1
    || temporary_snapshot.size != bytes.len() as i64
    || temporary_snapshot.mode & 0o777 != 0o644
  {
    return Err(OdenParentAllowlistGenerateFailure::TemporaryChanged(path));
  }
  let directory_snapshot_after_stage =
    DescriptorSnapshot::capture(&directory.descriptor, &directory.path)?;
  temporary_name_guard.armed = false;
  drop(temporary_name_guard);
  let mut prepared = PreparedGenerateOutput {
    path,
    file_name,
    temporary_name,
    held_directories,
    existing,
    temporary,
    temporary_snapshot,
    directory_snapshot_after_stage,
    temporary_is_named: true,
  };
  prepared.require_temporary_stable(bytes)?;
  Ok(prepared)
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn write_oden_parent_allowlist_candidate_outputs_with_root(
  root: &RetainedRepositoryRoot,
  candidate: &OdenParentAllowlistCandidateOutput,
) -> Result<(), OdenParentAllowlistGenerateFailure> {
  write_oden_parent_allowlist_candidate_outputs_with_root_and_post_commit_hook(
    root,
    candidate,
    || {},
  )
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn write_oden_parent_allowlist_candidate_outputs_with_root_and_post_commit_hook<
  H,
>(
  root: &RetainedRepositoryRoot,
  candidate: &OdenParentAllowlistCandidateOutput,
  post_commit_hook: H,
) -> Result<(), OdenParentAllowlistGenerateFailure>
where
  H: FnOnce(),
{
  root.require_current_and_named_paths_stable("generate output start")?;
  root.require_stable("<generate-outputs>")?;
  let mut json = prepare_generate_output(
    root,
    ODEN_PARENT_GENERATED_JSON_PATH,
    ODEN_PARENT_GENERATED_JSON_TEMP_NAME,
    &candidate.json_file,
  )?;
  let mut rust = prepare_generate_output(
    root,
    ODEN_PARENT_GENERATED_RUST_PATH,
    ODEN_PARENT_GENERATED_RUST_TEMP_NAME,
    &candidate.rust_module,
  )?;

  // Complete both same-directory temporary files and validate both final names
  // before either checked-in output is replaced.
  json.require_precommit(root, &candidate.json_file)?;
  rust.require_precommit(root, &candidate.rust_module)?;
  json.commit(root, &candidate.json_file)?;
  rust.commit(root, &candidate.rust_module)?;
  post_commit_hook();
  json.require_installed_from_root(root, &candidate.json_file)?;
  rust.require_installed_from_root(root, &candidate.rust_module)?;
  root.require_current_and_named_paths_stable("generate output terminal")?;
  root.require_stable("<generate-outputs>")?;
  Ok(())
}

// @ref LLP 0019#frozen-parent-standalone-allowlist-and-byte-graph [implements] —
// Consume the authoring session whose one retained root already spanned graph
// observation, retain all three inventories through that same root, compose
// the typed candidate, and replace only the two fixed generated files through
// no-follow same-directory stages.
/// Authoring-only Generate endpoint. It creates no standalone image, does not
/// expose candidate bytes, and grants no Check, release, brand, or admission
/// authority. Callers must discard every error and use the reserved refusal
/// exit without emitting application output.
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) fn generate_oden_parent_allowlist_outputs(
  session: OdenParentAllowlistGenerateSession,
  configuration: &OdenParentStandaloneConfiguration,
  vfs_graph: &OdenParentVfsGraph,
  static_import_edge: &OdenParentStaticImportEdge,
) -> Result<(), OdenParentAllowlistGenerateError> {
  let result = (|| {
    session
      .root
      .require_current_and_named_paths_stable("generate projection start")?;
    let retained =
      load_retained_contract_byte_bundle_from_root(&session.root)?;
    let candidate = compose_oden_parent_allowlist_candidate(
      &retained,
      OdenParentAllowlistCompilerProjectionInput {
        configuration,
        vfs_graph,
        static_import_edge,
      },
    )?;
    session
      .root
      .require_current_and_named_paths_stable("generate projection terminal")?;
    write_oden_parent_allowlist_candidate_outputs_with_root(
      &session.root,
      &candidate,
    )
  })();
  result.map_err(Into::into)
}

#[cfg(all(
  any(target_os = "linux", target_os = "macos"),
  any(test, feature = "__oden_parent_allowlist_embedded")
))]
fn open_oden_parent_allowlist_checked_output<'a>(
  root: &'a RetainedRepositoryRoot,
  path: &'static str,
  expected_bytes: &[u8],
) -> Result<
  OdenParentAllowlistCheckedOutputRead<'a>,
  OdenParentAllowlistCandidateFileFailure,
> {
  if path != ODEN_PARENT_GENERATED_JSON_PATH
    && path != ODEN_PARENT_GENERATED_RUST_PATH
  {
    return Err(OdenParentAllowlistCandidateFileFailure::InvalidPath(path));
  }
  root.require_stable(path)?;
  root.require_current_and_named_paths_stable("check output open")?;
  let components = path.split('/').collect::<Vec<_>>();
  let (file_name, directory_components) = components
    .split_last()
    .expect("fixed checked output is nonempty");
  let directory_flags =
    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
  let mut held_directories: Vec<HeldDirectory> =
    Vec::with_capacity(directory_components.len());
  let mut directory_path = String::new();
  for component in directory_components {
    let (parent_descriptor, parent_snapshot, parent_path) =
      match held_directories.last() {
        Some(directory) => (
          &directory.descriptor,
          &directory.snapshot,
          directory.path.as_str(),
        ),
        None => (&root.descriptor, &root.snapshot, "."),
      };
    require_exact_directory_component(
      parent_descriptor,
      parent_snapshot,
      parent_path,
      path,
      component,
    )?;
    if !directory_path.is_empty() {
      directory_path.push('/');
    }
    directory_path.push_str(component);
    let descriptor = open_component(
      parent_descriptor.as_raw_fd(),
      path,
      component,
      directory_flags,
    )?;
    let snapshot = DescriptorSnapshot::capture(&descriptor, &directory_path)?;
    if !snapshot.is_directory() {
      return Err(
        OdenParentDirectRepoSourceError::ComponentNotDirectory(directory_path)
          .into(),
      );
    }
    held_directories.push(HeldDirectory {
      path: directory_path.clone(),
      descriptor,
      snapshot,
    });
  }

  let directory = held_directories
    .last()
    .expect("fixed checked output has a parent directory");
  require_exact_directory_component(
    &directory.descriptor,
    &directory.snapshot,
    &directory.path,
    path,
    file_name,
  )?;
  let file_name = CString::new(file_name.as_bytes())
    .expect("fixed checked output name has no NUL");
  let file_flags =
    libc::O_RDONLY | libc::O_NONBLOCK | libc::O_NOFOLLOW | libc::O_CLOEXEC;
  let descriptor = open_component(
    directory.descriptor.as_raw_fd(),
    path,
    file_name.to_str().expect("fixed checked name is ASCII"),
    file_flags,
  )?;
  let snapshot = DescriptorSnapshot::capture(&descriptor, path)?;
  if !snapshot.is_regular_file() {
    return Err(
      OdenParentDirectRepoSourceError::NotRegularFile(path.to_string()).into(),
    );
  }
  if snapshot.links != 1 {
    return Err(
      OdenParentDirectRepoSourceError::InvalidLinkCount {
        path: path.to_string(),
        links: snapshot.links,
      }
      .into(),
    );
  }
  if snapshot.size < 0
    || snapshot.size as u64 != expected_bytes.len() as u64
  {
    return Err(
      OdenParentDirectRepoSourceError::SizeMismatch {
        path: path.to_string(),
        expected: expected_bytes.len() as u64,
        actual: snapshot.size,
      }
      .into(),
    );
  }
  if snapshot.mode & 0o7777 != 0o644 {
    return Err(OdenParentAllowlistCandidateFileFailure::InexactMode(path));
  }
  let read = OdenParentAllowlistCheckedOutputRead {
    root,
    path,
    file_name,
    expected_bytes: Arc::<[u8]>::from(expected_bytes.to_vec()),
    descriptor,
    snapshot,
    held_directories,
  };
  require_oden_parent_allowlist_checked_output_name_stable(&read)?;
  Ok(read)
}

#[cfg(all(
  any(target_os = "linux", target_os = "macos"),
  any(test, feature = "__oden_parent_allowlist_embedded")
))]
struct OdenParentAllowlistCheckedOutputRead<'a> {
  root: &'a RetainedRepositoryRoot,
  path: &'static str,
  file_name: CString,
  expected_bytes: Arc<[u8]>,
  descriptor: File,
  snapshot: DescriptorSnapshot,
  held_directories: Vec<HeldDirectory>,
}

#[cfg(all(
  any(target_os = "linux", target_os = "macos"),
  any(test, feature = "__oden_parent_allowlist_embedded")
))]
fn require_oden_parent_allowlist_checked_output_name_stable(
  read: &OdenParentAllowlistCheckedOutputRead<'_>,
) -> Result<(), OdenParentAllowlistCandidateFileFailure> {
  let directory = read
    .held_directories
    .last()
    .expect("fixed checked output has a parent directory");
  require_exact_directory_component(
    &directory.descriptor,
    &directory.snapshot,
    &directory.path,
    read.path,
    read.file_name.to_str().expect("fixed checked name is ASCII"),
  )?;
  let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
  // SAFETY: the retained directory and terminated fixed name remain live;
  // AT_SYMLINK_NOFOLLOW observes the current name itself.
  if unsafe {
    libc::fstatat(
      directory.descriptor.as_raw_fd(),
      read.file_name.as_ptr(),
      stat.as_mut_ptr(),
      libc::AT_SYMLINK_NOFOLLOW,
    )
  } != 0
  {
    return Err(
      OdenParentDirectRepoSourceError::InspectName {
        path: read.path.to_string(),
        source: std::io::Error::last_os_error(),
      }
      .into(),
    );
  }
  // SAFETY: successful fstatat initialized the complete stat value.
  let named = DescriptorSnapshot::from_stat(unsafe { stat.assume_init() });
  if named != read.snapshot {
    return Err(
      OdenParentDirectRepoSourceError::NameChanged(read.path.to_string())
        .into(),
    );
  }
  Ok(())
}

#[cfg(all(
  any(target_os = "linux", target_os = "macos"),
  any(test, feature = "__oden_parent_allowlist_embedded")
))]
fn require_oden_parent_allowlist_checked_output_bytes(
  read: &mut OdenParentAllowlistCheckedOutputRead<'_>,
) -> Result<(), OdenParentAllowlistCandidateFileFailure> {
  read.descriptor.seek(SeekFrom::Start(0)).map_err(|source| {
    OdenParentDirectRepoSourceError::ReadFile {
      path: read.path.to_string(),
      source,
    }
  })?;
  let mut offset = 0_usize;
  let mut buffer = [0_u8; 8_192];
  while offset < read.expected_bytes.len() {
    let length = buffer.len().min(read.expected_bytes.len() - offset);
    let read_length = read
      .descriptor
      .read(&mut buffer[..length])
      .map_err(|source| OdenParentDirectRepoSourceError::ReadFile {
        path: read.path.to_string(),
        source,
      })?;
    if read_length == 0 {
      return Err(
        OdenParentDirectRepoSourceError::UnexpectedEof {
          path: read.path.to_string(),
          offset: offset as u64,
        }
        .into(),
      );
    }
    let expected = &read.expected_bytes[offset..offset + read_length];
    if buffer[..read_length] != *expected {
      let mismatch = buffer[..read_length]
        .iter()
        .zip(expected)
        .position(|(actual, expected)| actual != expected)
        .expect("unequal checked-output slices have a mismatching byte");
      return Err(
        OdenParentDirectRepoSourceError::ByteMismatch {
          path: read.path.to_string(),
          offset: (offset + mismatch) as u64,
        }
        .into(),
      );
    }
    offset += read_length;
  }
  let mut trailing = [0_u8; 1];
  if read.descriptor.read(&mut trailing).map_err(|source| {
    OdenParentDirectRepoSourceError::ReadFile {
      path: read.path.to_string(),
      source,
    }
  })? != 0
  {
    return Err(
      OdenParentDirectRepoSourceError::TrailingBytes(read.path.to_string())
        .into(),
    );
  }
  Ok(())
}

#[cfg(all(
  any(target_os = "linux", target_os = "macos"),
  any(test, feature = "__oden_parent_allowlist_embedded")
))]
fn require_oden_parent_allowlist_checked_output_descriptor_tree_stable(
  read: &OdenParentAllowlistCheckedOutputRead<'_>,
) -> Result<(), OdenParentAllowlistCandidateFileFailure> {
  require_oden_parent_allowlist_checked_output_name_stable(&read)?;
  if DescriptorSnapshot::capture(&read.descriptor, read.path)? != read.snapshot
  {
    return Err(
      OdenParentDirectRepoSourceError::DescriptorChanged {
        member: read.path.to_string(),
        descriptor: read.path.to_string(),
      }
      .into(),
    );
  }
  for directory in read.held_directories.iter().rev() {
    if DescriptorSnapshot::capture(&directory.descriptor, &directory.path)?
      != directory.snapshot
    {
      return Err(
        OdenParentDirectRepoSourceError::DescriptorChanged {
          member: read.path.to_string(),
          descriptor: directory.path.clone(),
        }
        .into(),
      );
    }
  }
  read.root.require_stable(read.path)?;
  read
    .root
    .require_current_and_named_paths_stable("check output terminal")?;
  Ok(())
}

#[cfg(all(
  any(target_os = "linux", target_os = "macos"),
  any(test, feature = "__oden_parent_allowlist_embedded")
))]
fn require_oden_parent_allowlist_checked_output_reachable_from_root(
  read: &OdenParentAllowlistCheckedOutputRead<'_>,
) -> Result<(), OdenParentAllowlistCandidateFileFailure> {
  let reopened = open_oden_parent_allowlist_checked_output(
    read.root,
    read.path,
    &read.expected_bytes,
  )?;
  if reopened.snapshot != read.snapshot
    || reopened.held_directories.len() != read.held_directories.len()
    || reopened
      .held_directories
      .iter()
      .zip(&read.held_directories)
      .any(|(reopened, original)| {
        reopened.path != original.path || reopened.snapshot != original.snapshot
      })
  {
    return Err(
      OdenParentDirectRepoSourceError::NameChanged(read.path.to_string())
        .into(),
    );
  }
  require_oden_parent_allowlist_checked_output_descriptor_tree_stable(
    &reopened,
  )?;
  Ok(())
}

#[cfg(all(
  any(target_os = "linux", target_os = "macos"),
  any(test, feature = "__oden_parent_allowlist_embedded")
))]
fn finish_oden_parent_allowlist_checked_output(
  read: &OdenParentAllowlistCheckedOutputRead<'_>,
) -> Result<(), OdenParentAllowlistCandidateFileFailure> {
  require_oden_parent_allowlist_checked_output_descriptor_tree_stable(read)?;
  require_oden_parent_allowlist_checked_output_reachable_from_root(read)?;
  require_oden_parent_allowlist_checked_output_descriptor_tree_stable(read)
}

#[cfg(all(
  any(target_os = "linux", target_os = "macos"),
  any(test, feature = "__oden_parent_allowlist_embedded")
))]
fn require_oden_parent_allowlist_candidate_files(
  root: &RetainedRepositoryRoot,
  candidate: &OdenParentAllowlistCandidateOutput,
) -> Result<(), OdenParentAllowlistCandidateFileFailure> {
  require_oden_parent_allowlist_candidate_files_with_post_open_hook(
    root,
    candidate,
    || {},
  )
}

#[cfg(all(
  any(target_os = "linux", target_os = "macos"),
  any(test, feature = "__oden_parent_allowlist_embedded")
))]
fn require_oden_parent_allowlist_candidate_files_with_post_open_hook<H>(
  root: &RetainedRepositoryRoot,
  candidate: &OdenParentAllowlistCandidateOutput,
  post_open_hook: H,
) -> Result<(), OdenParentAllowlistCandidateFileFailure>
where
  H: FnOnce(),
{
  // Open and retain both descriptors before reading either. The expected
  // lengths come only from the typed in-memory candidate, never file stat.
  let mut json = open_oden_parent_allowlist_checked_output(
    root,
    ODEN_PARENT_GENERATED_JSON_PATH,
    &candidate.json_file,
  )?;
  let mut rust = open_oden_parent_allowlist_checked_output(
    root,
    ODEN_PARENT_GENERATED_RUST_PATH,
    &candidate.rust_module,
  )?;
  require_oden_parent_allowlist_checked_output_name_stable(&json)?;
  require_oden_parent_allowlist_checked_output_name_stable(&rust)?;
  root.require_stable("<check-files>")?;
  post_open_hook();

  require_oden_parent_allowlist_checked_output_bytes(&mut json)?;
  require_oden_parent_allowlist_checked_output_bytes(&mut rust)?;

  require_oden_parent_allowlist_checked_output_name_stable(&json)?;
  require_oden_parent_allowlist_checked_output_name_stable(&rust)?;
  finish_oden_parent_allowlist_checked_output(&json)?;
  finish_oden_parent_allowlist_checked_output(&rust)?;
  // Retain both original descriptors through a final cross-file pass. These
  // sequential observations deliberately do not claim a coherent snapshot.
  require_oden_parent_allowlist_checked_output_descriptor_tree_stable(&json)?;
  require_oden_parent_allowlist_checked_output_descriptor_tree_stable(&rust)?;
  root.require_stable("<check-files-terminal>")?;
  root.require_current_and_named_paths_stable("check files terminal")?;
  Ok(())
}

#[cfg(all(
  any(target_os = "linux", target_os = "macos"),
  feature = "__oden_parent_allowlist_embedded"
))]
fn checked_oden_parent_allowlist_candidate_output(
  candidate_jcs: &[u8],
  candidate_digest: &str,
) -> Result<OdenParentAllowlistCandidateOutput, OdenParentAllowlistError> {
  let (json_file, rust_module) = deno_lib::standalone::oden_parent_allowlist::render_checked_oden_parent_allowlist_candidate_files(
    candidate_jcs,
    candidate_digest,
  )?;
  Ok(OdenParentAllowlistCandidateOutput {
    canonical_jcs: candidate_jcs.to_vec(),
    digest: candidate_digest.to_string(),
    json_file,
    rust_module,
  })
}

// @ref LLP 0019#frozen-parent-standalone-allowlist-and-byte-graph [implements] —
// Consume a distinct retained-root session only after a caller has supplied
// the already-typed complete compiler projection. Reload all three literal
// inventories, regenerate both renderings, validate and compare the inert
// compiled pair, and descriptor-compare the two fixed files without invoking
// graph construction or any writer. This production-compiled sink has no
// production constructor or caller and returns no validated record, admission,
// output, brand, or release capability.
#[cfg(all(
  any(target_os = "linux", target_os = "macos"),
  any(test, feature = "__oden_parent_allowlist_embedded")
))]
fn reconcile_oden_parent_allowlist_full_regeneration_with_compiled_candidate(
  session: OdenParentAllowlistFullRegenerationSession,
  configuration: &OdenParentStandaloneConfiguration,
  vfs_graph: &OdenParentVfsGraph,
  static_import_edge: &OdenParentStaticImportEdge,
  compiled: &OdenParentAllowlistCandidateOutput,
) -> Result<(), OdenParentAllowlistFullRegenerationError> {
  let result = (|| {
    session
      .root
      .require_current_and_named_paths_stable("full regeneration start")?;
    session.root.require_stable("<full-regeneration-start>")?;

    let retained =
      load_retained_contract_byte_bundle_from_root(&session.root)?;
    let regenerated = compose_oden_parent_allowlist_candidate(
      &retained,
      OdenParentAllowlistCompilerProjectionInput {
        configuration,
        vfs_graph,
        static_import_edge,
      },
    )?;
    session.root.require_current_and_named_paths_stable(
      "full regeneration projection terminal",
    )?;
    session
      .root
      .require_stable("<full-regeneration-projection>")?;

    if regenerated != *compiled {
      return Err(
        OdenParentAllowlistFullRegenerationFailure::CompiledCandidateMismatch,
      );
    }

    require_oden_parent_allowlist_candidate_files(
      &session.root,
      &regenerated,
    )?;
    session
      .root
      .require_current_and_named_paths_stable("full regeneration terminal")?;
    session.root.require_stable("<full-regeneration-terminal>")?;
    Ok::<(), OdenParentAllowlistFullRegenerationFailure>(())
  })();
  result.map_err(Into::into)
}

/// Production-uncalled full-projection reconciliation candidate. The caller
/// cannot select paths or inventory membership, and success is intentionally
/// represented only by `()`.
#[cfg(all(
  feature = "__oden_parent_allowlist_embedded",
  any(target_os = "linux", target_os = "macos")
))]
#[allow(dead_code)]
pub(crate) fn reconcile_oden_parent_allowlist_full_regeneration(
  session: OdenParentAllowlistFullRegenerationSession,
  configuration: &OdenParentStandaloneConfiguration,
  vfs_graph: &OdenParentVfsGraph,
  static_import_edge: &OdenParentStaticImportEdge,
) -> Result<(), OdenParentAllowlistFullRegenerationError> {
  let (embedded_jcs, embedded_digest) = deno_lib::standalone::oden_parent_allowlist::embedded_oden_parent_allowlist_candidate();
  let compiled = checked_oden_parent_allowlist_candidate_output(
    embedded_jcs,
    embedded_digest,
  )
  .map_err(OdenParentAllowlistFullRegenerationFailure::from)
  .map_err(OdenParentAllowlistFullRegenerationError::from)?;
  reconcile_oden_parent_allowlist_full_regeneration_with_compiled_candidate(
    session,
    configuration,
    vfs_graph,
    static_import_edge,
    &compiled,
  )
}

// @ref LLP 0019#frozen-parent-standalone-allowlist-and-byte-graph [implements] —
// Validate the private compiled JCS/HJCS pair, reconstruct its two deterministic
// source files, then hold and compare only those fixed checked-in files. This
// synchronous route performs no graph, inventory, config, cache, network,
// create, truncate, rename, unlink, sync, or write work and returns no
// validated record or admission capability. It deliberately does not establish
// freshness against current repository inputs; authenticated compile preflight
// remains a later, separate boundary.
#[cfg(all(
  feature = "__oden_parent_allowlist_embedded",
  any(target_os = "linux", target_os = "macos")
))]
pub(crate) fn check_oden_parent_allowlist_outputs(
  session: OdenParentAllowlistCheckSession,
) -> Result<(), OdenParentAllowlistCheckError> {
  let result = (|| {
    session
      .root
      .require_current_and_named_paths_stable("check start")?;
    session.root.require_stable("<check-start>")?;

    let (embedded_jcs, embedded_digest) = deno_lib::standalone::oden_parent_allowlist::embedded_oden_parent_allowlist_candidate();
    let candidate = checked_oden_parent_allowlist_candidate_output(
      embedded_jcs,
      embedded_digest,
    )?;
    require_oden_parent_allowlist_candidate_files(&session.root, &candidate)?;
    session
      .root
      .require_current_and_named_paths_stable("check terminal")?;
    session.root.require_stable("<check-terminal>")?;
    Ok::<(), OdenParentAllowlistCheckFailure>(())
  })();
  result.map_err(Into::into)
}

#[cfg(test)]
mod tests {
  use super::*;

  #[cfg(any(target_os = "linux", target_os = "macos"))]
  use std::cell::Cell;
  #[cfg(any(target_os = "linux", target_os = "macos"))]
  use std::os::unix::fs::MetadataExt;
  #[cfg(any(target_os = "linux", target_os = "macos"))]
  use std::os::unix::fs::PermissionsExt;

  #[cfg(any(target_os = "linux", target_os = "macos"))]
  use deno_lib::args::UnstableConfig;
  #[cfg(any(target_os = "linux", target_os = "macos"))]
  use deno_lib::standalone::binary::SerializedWorkspaceResolver;
  #[cfg(any(target_os = "linux", target_os = "macos"))]
  use deno_lib::standalone::oden_parent_allowlist::ODEN_PARENT_ENTRYPOINT_KEY;
  #[cfg(any(target_os = "linux", target_os = "macos"))]
  use deno_lib::standalone::oden_parent_allowlist::ODEN_PARENT_PRIVATE_MODULE_SPECIFIER;
  #[cfg(any(target_os = "linux", target_os = "macos"))]
  use deno_lib::standalone::oden_parent_allowlist::OdenParentImportAttributes;
  #[cfg(any(target_os = "linux", target_os = "macos"))]
  use deno_lib::standalone::oden_parent_allowlist::OdenParentStaticImportEdgeObservation;
  #[cfg(any(target_os = "linux", target_os = "macos"))]
  use deno_lib::standalone::oden_parent_allowlist::OdenParentVfsDependencyKind;
  #[cfg(any(target_os = "linux", target_os = "macos"))]
  use deno_lib::standalone::oden_parent_allowlist::OdenParentVfsDependencyObservation;
  #[cfg(any(target_os = "linux", target_os = "macos"))]
  use deno_lib::standalone::oden_parent_allowlist::OdenParentVfsMediaType;
  #[cfg(any(target_os = "linux", target_os = "macos"))]
  use deno_lib::standalone::oden_parent_allowlist::OdenParentVfsModuleObservation;
  #[cfg(any(target_os = "linux", target_os = "macos"))]
  use deno_lib::standalone::oden_parent_allowlist::raw_sha256_digest;
  #[cfg(any(target_os = "linux", target_os = "macos"))]
  use deno_runtime::deno_telemetry::OtelConfig;

  #[cfg(any(target_os = "linux", target_os = "macos"))]
  const CANDIDATE_ENTRYPOINT_SOURCE: &[u8] =
    b"import \"oden-internal:filesystem-parent-capture-v2\";\n";

  fn role_facts(
    supported_os: bool,
    authoring: bool,
    embedded: bool,
    root_feature_inventory: &str,
  ) -> OdenParentAllowlistCompiledRoleFacts<'_> {
    OdenParentAllowlistCompiledRoleFacts {
      supported_os,
      authoring,
      embedded,
      root_feature_inventory,
    }
  }

  #[test]
  fn role_decoder_matches_the_supported_os_matrix() {
    use OdenParentAllowlistRawDispatch as Dispatch;
    use OdenParentAllowlistRoleDecision as Decision;

    let rows = [
      (
        role_facts(true, false, false, "default"),
        Decision::Refuse,
        Decision::Refuse,
      ),
      (
        role_facts(
          true,
          true,
          false,
          "__oden_parent_allowlist_authoring,default",
        ),
        Decision::GenerateEligible,
        Decision::Refuse,
      ),
      (
        role_facts(
          true,
          false,
          true,
          "__oden_parent_allowlist_embedded,__vendored_zlib_ng,default,upgrade",
        ),
        Decision::Refuse,
        Decision::CheckEligible,
      ),
      (
        role_facts(
          true,
          true,
          true,
          "__oden_parent_allowlist_authoring,__oden_parent_allowlist_embedded",
        ),
        Decision::Refuse,
        Decision::Refuse,
      ),
    ];

    for (facts, generate, check) in rows {
      assert_eq!(
        decode_oden_parent_allowlist_role(Dispatch::Generate, facts),
        generate
      );
      assert_eq!(
        decode_oden_parent_allowlist_role(Dispatch::Check, facts),
        check
      );
    }
  }

  #[test]
  fn generate_eligibility_is_minted_only_for_exact_authoring_generate() {
    use OdenParentAllowlistRawDispatch as Dispatch;

    assert!(
      admit_oden_parent_allowlist_generate_with(
        Dispatch::Generate,
        role_facts(
          true,
          true,
          false,
          "__oden_parent_allowlist_authoring,default",
        ),
      )
      .is_ok()
    );
    for (dispatch, facts) in [
      (
        Dispatch::Check,
        role_facts(
          true,
          true,
          false,
          "__oden_parent_allowlist_authoring,default",
        ),
      ),
      (
        Dispatch::Generate,
        role_facts(true, false, false, "default"),
      ),
      (
        Dispatch::Generate,
        role_facts(
          true,
          true,
          true,
          "__oden_parent_allowlist_authoring,__oden_parent_allowlist_embedded",
        ),
      ),
      (
        Dispatch::Generate,
        role_facts(
          false,
          true,
          false,
          "__oden_parent_allowlist_authoring,default",
        ),
      ),
    ] {
      assert!(matches!(
        admit_oden_parent_allowlist_generate_with(dispatch, facts),
        Err(OdenParentAllowlistGenerateFailure::IneligibleRole)
      ));
    }
  }

  #[test]
  fn check_eligibility_is_minted_only_for_exact_embedded_check() {
    use OdenParentAllowlistRawDispatch as Dispatch;

    assert!(
      admit_oden_parent_allowlist_check_with(
        Dispatch::Check,
        role_facts(
          true,
          false,
          true,
          "__oden_parent_allowlist_embedded,__vendored_zlib_ng,default,upgrade",
        ),
      )
      .is_ok()
    );
    for (dispatch, facts) in [
      (
        Dispatch::Generate,
        role_facts(
          true,
          false,
          true,
          "__oden_parent_allowlist_embedded,__vendored_zlib_ng,default,upgrade",
        ),
      ),
      (
        Dispatch::Check,
        role_facts(true, false, false, "default"),
      ),
      (
        Dispatch::Check,
        role_facts(
          true,
          true,
          true,
          "__oden_parent_allowlist_authoring,__oden_parent_allowlist_embedded",
        ),
      ),
      (
        Dispatch::Check,
        role_facts(
          false,
          false,
          true,
          "__oden_parent_allowlist_embedded,__vendored_zlib_ng,default,upgrade",
        ),
      ),
    ] {
      assert!(matches!(
        admit_oden_parent_allowlist_check_with(dispatch, facts),
        Err(OdenParentAllowlistCheckFailure::IneligibleRole)
      ));
    }
  }

  #[cfg(any(target_os = "linux", target_os = "macos"))]
  fn test_generate_eligibility() -> OdenParentAllowlistGenerateEligibility {
    admit_oden_parent_allowlist_generate_with(
      OdenParentAllowlistRawDispatch::Generate,
      role_facts(
        true,
        true,
        false,
        "__oden_parent_allowlist_authoring,default",
      ),
    )
    .unwrap()
  }

  #[cfg(any(target_os = "linux", target_os = "macos"))]
  fn test_check_eligibility() -> OdenParentAllowlistCheckEligibility {
    admit_oden_parent_allowlist_check_with(
      OdenParentAllowlistRawDispatch::Check,
      role_facts(
        true,
        false,
        true,
        "__oden_parent_allowlist_embedded,__vendored_zlib_ng,default,upgrade",
      ),
    )
    .unwrap()
  }

  #[test]
  fn role_decoder_unsupported_os_overrides_every_role_shape() {
    use OdenParentAllowlistRawDispatch as Dispatch;
    use OdenParentAllowlistRoleDecision as Decision;

    for facts in [
      role_facts(false, false, false, "default"),
      role_facts(
        false,
        true,
        false,
        "__oden_parent_allowlist_authoring",
      ),
      role_facts(
        false,
        false,
        true,
        "__oden_parent_allowlist_embedded",
      ),
      role_facts(
        false,
        true,
        true,
        "__oden_parent_allowlist_authoring,__oden_parent_allowlist_embedded",
      ),
    ] {
      assert_eq!(
        decode_oden_parent_allowlist_role(Dispatch::Generate, facts),
        Decision::Refuse
      );
      assert_eq!(
        decode_oden_parent_allowlist_role(Dispatch::Check, facts),
        Decision::Refuse
      );
    }
  }

  #[test]
  fn role_decoder_requires_exact_bidirectional_role_token_joins() {
    use OdenParentAllowlistRawDispatch as Dispatch;
    use OdenParentAllowlistRoleDecision as Decision;

    for facts in [
      role_facts(true, true, false, "default"),
      role_facts(
        true,
        false,
        false,
        "__oden_parent_allowlist_authoring,default",
      ),
      role_facts(true, false, true, "default"),
      role_facts(
        true,
        false,
        false,
        "__oden_parent_allowlist_embedded,default",
      ),
    ] {
      assert_eq!(
        decode_oden_parent_allowlist_role(Dispatch::Generate, facts),
        Decision::Refuse
      );
      assert_eq!(
        decode_oden_parent_allowlist_role(Dispatch::Check, facts),
        Decision::Refuse
      );
    }
  }

  #[test]
  fn role_decoder_uses_exact_canonical_inventory_tokens() {
    use OdenParentAllowlistRawDispatch as Dispatch;
    use OdenParentAllowlistRoleDecision as Decision;

    for inventory in [
      "",
      ",__oden_parent_allowlist_authoring",
      "__oden_parent_allowlist_authoring,",
      "__oden_parent_allowlist_authoring,,default",
      "__oden_parent_allowlist_authoring,__oden_parent_allowlist_authoring",
      "default,__oden_parent_allowlist_authoring",
      "__ODEN_PARENT_ALLOWLIST_AUTHORING,default",
      "__oden_parent_allowlist_authoring ,default",
      "__oden_parent_allowlist_authoring-suffix,default",
      "prefix-__oden_parent_allowlist_authoring,default",
    ] {
      assert_eq!(
        decode_oden_parent_allowlist_role(
          Dispatch::Generate,
          role_facts(true, true, false, inventory),
        ),
        Decision::Refuse,
        "inventory {inventory:?} must refuse",
      );
    }

    assert_eq!(
      decode_oden_parent_allowlist_role(
        Dispatch::Generate,
        role_facts(
          true,
          true,
          false,
          "__oden_parent_allowlist_authoring,__vendored_zlib_ng,default,upgrade",
        ),
      ),
      Decision::GenerateEligible,
    );
  }

  #[test]
  fn role_decoder_never_treats_absent_or_refuse_as_eligible() {
    use OdenParentAllowlistRawDispatch as Dispatch;
    use OdenParentAllowlistRoleDecision as Decision;

    for dispatch in [Dispatch::Absent, Dispatch::Refuse] {
      assert_eq!(
        decode_oden_parent_allowlist_role(
          dispatch,
          role_facts(
            true,
            true,
            false,
            "__oden_parent_allowlist_authoring,default",
          ),
        ),
        Decision::Refuse,
      );
      assert_eq!(
        decode_oden_parent_allowlist_role(
          dispatch,
          role_facts(true, false, true, "__oden_parent_allowlist_embedded"),
        ),
        Decision::Refuse,
      );
    }
  }

  #[test]
  fn compiled_role_marker_matches_both_cfg_bits() {
    assert!(root_feature_inventory_matches_role_bits(
      compiled_oden_parent_allowlist_role_facts()
    ));
  }

  #[test]
  fn role_wrapper_is_refusal_only_for_every_dispatch() {
    for dispatch in [
      OdenParentAllowlistRawDispatch::Absent,
      OdenParentAllowlistRawDispatch::Generate,
      OdenParentAllowlistRawDispatch::Check,
      OdenParentAllowlistRawDispatch::Refuse,
    ] {
      assert_eq!(
        crate::oden_parent_allowlist_refusal_exit_code_for_raw_dispatch(
          dispatch
        ),
        ODEN_PARENT_ALLOWLIST_REFUSAL_EXIT_CODE,
      );
    }
  }

  #[test]
  fn capture_contract_paths_are_closed_sorted_literals() {
    assert_closed_sorted_literals(ODEN_PARENT_CAPTURE_CONTRACT_PATHS, 29);
    assert_handwritten_rust_authorities(ODEN_PARENT_CAPTURE_CONTRACT_PATHS);
  }

  #[test]
  fn source_closure_contract_paths_are_closed_sorted_literals() {
    assert_closed_sorted_literals(
      ODEN_PARENT_SOURCE_CLOSURE_CONTRACT_PATHS,
      22,
    );
    assert_handwritten_rust_authorities(
      ODEN_PARENT_SOURCE_CLOSURE_CONTRACT_PATHS,
    );
  }

  #[test]
  fn release_contract_paths_are_closed_sorted_literals() {
    assert_closed_sorted_literals(ODEN_PARENT_RELEASE_CONTRACT_PATHS, 33);
    assert_handwritten_rust_authorities(ODEN_PARENT_RELEASE_CONTRACT_PATHS);
    assert!(
      !ODEN_PARENT_RELEASE_CONTRACT_PATHS
        .contains(&"third_party/components.json")
    );
    for retained_definition in [
      "schemas/release/third-party-components.schema.json",
      "scripts/release/third-party-notices.ts",
    ] {
      assert!(
        ODEN_PARENT_RELEASE_CONTRACT_PATHS.contains(&retained_definition)
      );
    }
  }

  #[cfg(any(target_os = "linux", target_os = "macos"))]
  #[test]
  fn release_contract_inventory_excludes_live_component_instance_bytes() {
    let root = tempfile::tempdir().unwrap();
    materialize_retained_contract_tree(root.path(), "release-contract");
    let manifest = root.path().join("third_party/components.json");
    std::fs::create_dir_all(manifest.parent().unwrap()).unwrap();
    std::fs::write(&manifest, b"{\"forkCommit\":\"predecessor\"}\n").unwrap();
    let before = load_from_test_root(
      root.path(),
      ODEN_PARENT_RELEASE_CONTRACT_PATHS,
      ODEN_PARENT_RETAINED_CONTRACT_FILE_LIMITS,
      |_| {},
    )
    .unwrap();

    std::fs::write(&manifest, b"{\"forkCommit\":\"final\"}\n").unwrap();
    let after = load_from_test_root(
      root.path(),
      ODEN_PARENT_RELEASE_CONTRACT_PATHS,
      ODEN_PARENT_RETAINED_CONTRACT_FILE_LIMITS,
      |_| {},
    )
    .unwrap();

    assert_eq!(before.inventory(), after.inventory());
    assert!(
      before
        .inventory()
        .rows()
        .iter()
        .all(|row| row.path() != "third_party/components.json")
    );
  }

  #[cfg(any(target_os = "linux", target_os = "macos"))]
  fn direct_file_specifier(path: &Path) -> ModuleSpecifier {
    ModuleSpecifier::from_file_path(path).unwrap()
  }

  #[cfg(any(target_os = "linux", target_os = "macos"))]
  fn observe_direct_from_test_root(
    root: &Path,
    specifier: &ModuleSpecifier,
    bytes: Arc<[u8]>,
  ) -> Result<
    OdenParentDirectRepoSourceCandidate,
    OdenParentDirectRepoSourceError,
  > {
    observe_oden_parent_direct_repo_source_from_test_root(
      root,
      specifier,
      bytes,
      || {},
    )
  }

  #[cfg(any(target_os = "linux", target_os = "macos"))]
  #[test]
  fn direct_repo_source_accepts_exact_key_arc_mode_and_zero_bytes() {
    let current = std::env::current_dir().unwrap();
    let retained_current = RetainedRepositoryRoot::open_current().unwrap();
    assert_eq!(
      retained_current.path.as_os_str().as_bytes(),
      current.as_os_str().as_bytes()
    );
    retained_current
      .require_current_and_named_paths_stable("test terminal")
      .unwrap();
    assert!(matches!(
      RetainedRepositoryRoot::open_test_absolute(Path::new(".")),
      Err(OdenParentRetainedContractError::TestRootNotAbsolute(_))
    ));

    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("bin")).unwrap();
    let executable_path = root.path().join("bin/tool");
    std::fs::write(&executable_path, b"exact candidate bytes").unwrap();
    std::fs::set_permissions(
      &executable_path,
      std::fs::Permissions::from_mode(0o751),
    )
    .unwrap();
    let specifier = direct_file_specifier(&executable_path);
    let supplied: Arc<[u8]> = Arc::from(&b"exact candidate bytes"[..]);
    let candidate = observe_direct_from_test_root(
      root.path(),
      &specifier,
      supplied.clone(),
    )
    .unwrap();
    assert_eq!(candidate.key.as_str(), "repo:bin/tool");
    assert_eq!(candidate.specifier, specifier);
    assert!(Arc::ptr_eq(&candidate.original_bytes, &supplied));
    assert!(candidate.executable);

    let empty_path = root.path().join("empty");
    std::fs::write(&empty_path, []).unwrap();
    std::fs::set_permissions(
      &empty_path,
      std::fs::Permissions::from_mode(0o640),
    )
    .unwrap();
    let empty: Arc<[u8]> = Arc::from(&b""[..]);
    let candidate = observe_direct_from_test_root(
      root.path(),
      &direct_file_specifier(&empty_path),
      empty.clone(),
    )
    .unwrap();
    assert_eq!(candidate.key.as_str(), "repo:empty");
    assert!(Arc::ptr_eq(&candidate.original_bytes, &empty));
    assert!(!candidate.executable);

    let binary_path = root.path().join("binary");
    let binary: Arc<[u8]> = Arc::from(&[0_u8, 0xff, b'\r', b'\n'][..]);
    std::fs::write(&binary_path, binary.as_ref()).unwrap();
    let candidate = observe_direct_from_test_root(
      root.path(),
      &direct_file_specifier(&binary_path),
      binary.clone(),
    )
    .unwrap();
    assert!(Arc::ptr_eq(&candidate.original_bytes, &binary));
  }

  #[cfg(any(target_os = "linux", target_os = "macos"))]
  #[test]
  fn direct_repo_source_refuses_url_and_key_aliases() {
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("src")).unwrap();
    let file_path = root.path().join("src/file.ts");
    std::fs::write(&file_path, b"source").unwrap();
    let valid = direct_file_specifier(&file_path);
    let bytes = || Arc::<[u8]>::from(&b"source"[..]);

    let root_url = direct_file_specifier(root.path());
    assert!(matches!(
      observe_direct_from_test_root(root.path(), &root_url, bytes()),
      Err(OdenParentDirectRepoSourceError::OutsideRetainedRoot { .. })
    ));
    let outside_root = tempfile::tempdir().unwrap();
    let outside_path = outside_root.path().join("outside.ts");
    std::fs::write(&outside_path, b"source").unwrap();
    assert!(matches!(
      observe_direct_from_test_root(
        root.path(),
        &direct_file_specifier(&outside_path),
        bytes(),
      ),
      Err(OdenParentDirectRepoSourceError::OutsideRetainedRoot { .. })
    ));

    let mut host = valid.clone();
    host.set_host(Some("localhost")).unwrap();
    assert!(matches!(
      observe_direct_from_test_root(root.path(), &host, bytes()),
      Err(OdenParentDirectRepoSourceError::InvalidFileUrl("URL has a host"))
    ));
    let mut query = valid.clone();
    query.set_query(Some("alias"));
    assert!(matches!(
      observe_direct_from_test_root(root.path(), &query, bytes()),
      Err(OdenParentDirectRepoSourceError::InvalidFileUrl(
        "URL has a query or fragment"
      ))
    ));
    let mut fragment = valid.clone();
    fragment.set_fragment(Some("alias"));
    assert!(matches!(
      observe_direct_from_test_root(root.path(), &fragment, bytes()),
      Err(OdenParentDirectRepoSourceError::InvalidFileUrl(
        "URL has a query or fragment"
      ))
    ));

    let alternate_percent = ModuleSpecifier::parse(
      &valid.as_str().replace("file.ts", "%66ile.ts"),
    )
    .unwrap();
    assert!(matches!(
      observe_direct_from_test_root(
        root.path(),
        &alternate_percent,
        bytes(),
      ),
      Err(OdenParentDirectRepoSourceError::InvalidFileUrl(
        "URL spelling is not the byte-exact path round trip"
      ))
    ));

    for path in [
      root.path().join("literal%path"),
      root.path().join("unicode-é.ts"),
      root.path().join(ODEN_PARENT_GENERATED_JSON_PATH),
      root.path().join("a".repeat(256)),
      root.path().join(format!("{}a", "a/".repeat(2_048))),
    ] {
      assert!(matches!(
        observe_direct_from_test_root(
          root.path(),
          &direct_file_specifier(&path),
          bytes(),
        ),
        Err(OdenParentDirectRepoSourceError::RepoKey(_))
      ));
    }

    let traversed = valid.join("../../../outside.ts").unwrap();
    assert!(matches!(
      observe_direct_from_test_root(root.path(), &traversed, bytes()),
      Err(OdenParentDirectRepoSourceError::OutsideRetainedRoot { .. })
    ));

    let root_name = root.path().file_name().unwrap().to_str().unwrap();
    let prefix_sibling = root
      .path()
      .with_file_name(format!("{root_name}-sibling"));
    let prefix_sibling_specifier =
      direct_file_specifier(&prefix_sibling.join("outside.ts"));
    assert!(matches!(
      observe_direct_from_test_root(
        root.path(),
        &prefix_sibling_specifier,
        bytes(),
      ),
      Err(OdenParentDirectRepoSourceError::OutsideRetainedRoot { .. })
    ));
    let encoded_traversal = ModuleSpecifier::parse(&format!(
      "{}/%2e%2e/{root_name}-sibling/outside.ts",
      root_url.as_str()
    ))
    .unwrap();
    assert_eq!(encoded_traversal, prefix_sibling_specifier);
    assert!(!encoded_traversal.as_str().contains("%2e"));
    assert!(matches!(
      observe_direct_from_test_root(
        root.path(),
        &encoded_traversal,
        bytes(),
      ),
      Err(OdenParentDirectRepoSourceError::OutsideRetainedRoot { .. })
    ));
  }

  #[cfg(any(target_os = "linux", target_os = "macos"))]
  #[test]
  fn direct_repo_source_refuses_links_specials_and_inexact_bytes() {
    use std::os::unix::fs::symlink;

    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("target"), b"target").unwrap();
    symlink("target", root.path().join("final-link")).unwrap();
    std::fs::create_dir(root.path().join("real-dir")).unwrap();
    std::fs::write(root.path().join("real-dir/member"), b"member").unwrap();
    symlink("real-dir", root.path().join("dir-link")).unwrap();
    std::fs::hard_link(root.path().join("target"), root.path().join("alias"))
      .unwrap();
    std::fs::create_dir(root.path().join("directory")).unwrap();
    std::fs::write(root.path().join("wrong"), b"abc").unwrap();
    let fifo_path = root.path().join("fifo");
    let fifo = CString::new(fifo_path.as_os_str().as_bytes()).unwrap();
    // SAFETY: `fifo` is NUL-terminated and the mode is valid.
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);

    for path in [root.path().join("final-link"), root.path().join("dir-link/member")] {
      assert!(matches!(
        observe_direct_from_test_root(
          root.path(),
          &direct_file_specifier(&path),
          Arc::from(&b"target"[..]),
        ),
        Err(OdenParentDirectRepoSourceError::RetainedDescriptor(
          OdenParentRetainedContractError::OpenComponent { .. }
        ))
      ));
    }
    assert!(matches!(
      observe_direct_from_test_root(
        root.path(),
        &direct_file_specifier(&root.path().join("alias")),
        Arc::from(&b"target"[..]),
      ),
      Err(OdenParentDirectRepoSourceError::InvalidLinkCount {
        links: 2,
        ..
      })
    ));
    assert!(matches!(
      observe_direct_from_test_root(
        root.path(),
        &direct_file_specifier(&root.path().join("wrong")),
        Arc::from(&b"abcd"[..]),
      ),
      Err(OdenParentDirectRepoSourceError::SizeMismatch {
        expected: 4,
        actual: 3,
        ..
      })
    ));
    for path in [root.path().join("directory"), fifo_path] {
      assert!(matches!(
        observe_direct_from_test_root(
          root.path(),
          &direct_file_specifier(&path),
          Arc::from(&b""[..]),
        ),
        Err(OdenParentDirectRepoSourceError::NotRegularFile(_))
      ));
    }
    assert!(matches!(
      observe_direct_from_test_root(
        root.path(),
        &direct_file_specifier(&root.path().join("wrong")),
        Arc::from(&b"abd"[..]),
      ),
      Err(OdenParentDirectRepoSourceError::ByteMismatch {
        offset: 2,
        ..
      })
    ));
    assert!(matches!(
      observe_direct_from_test_root(
        root.path(),
        &direct_file_specifier(&root.path().join("wrong")),
        Arc::from(&b"ab"[..]),
      ),
      Err(OdenParentDirectRepoSourceError::SizeMismatch {
        expected: 2,
        actual: 3,
        ..
      })
    ));
  }

  #[cfg(any(target_os = "linux", target_os = "macos"))]
  #[test]
  fn direct_repo_source_detects_mutation_and_requires_exact_case() {
    let file_root = tempfile::tempdir().unwrap();
    let file_path = file_root.path().join("member");
    std::fs::write(&file_path, b"member").unwrap();
    let file_mode = file_path.metadata().unwrap().permissions().mode();
    let file_result = observe_oden_parent_direct_repo_source_from_test_root(
      file_root.path(),
      &direct_file_specifier(&file_path),
      Arc::from(&b"member"[..]),
      || {
        std::fs::set_permissions(
          &file_path,
          std::fs::Permissions::from_mode(file_mode ^ 0o100),
        )
        .unwrap();
      },
    );
    std::fs::set_permissions(
      &file_path,
      std::fs::Permissions::from_mode(file_mode),
    )
    .unwrap();
    assert!(matches!(
      file_result,
      Err(OdenParentDirectRepoSourceError::DescriptorChanged {
        ref descriptor,
        ..
      }) if descriptor == "member"
    ));

    let growth_root = tempfile::tempdir().unwrap();
    let growth_path = growth_root.path().join("member");
    std::fs::write(&growth_path, b"member").unwrap();
    let growth_result = observe_oden_parent_direct_repo_source_from_test_root(
      growth_root.path(),
      &direct_file_specifier(&growth_path),
      Arc::from(&b"member"[..]),
      || {
        std::fs::write(&growth_path, b"member grew").unwrap();
      },
    );
    assert!(matches!(
      growth_result,
      Err(OdenParentDirectRepoSourceError::DescriptorChanged {
        ref descriptor,
        ..
      }) if descriptor == "member"
    ));

    let truncation_root = tempfile::tempdir().unwrap();
    let truncation_path = truncation_root.path().join("member");
    std::fs::write(&truncation_path, b"member").unwrap();
    let truncation_result =
      observe_oden_parent_direct_repo_source_from_test_root(
        truncation_root.path(),
        &direct_file_specifier(&truncation_path),
        Arc::from(&b"member"[..]),
        || {
          std::fs::write(&truncation_path, b"mem").unwrap();
        },
      );
    assert!(matches!(
      truncation_result,
      Err(OdenParentDirectRepoSourceError::DescriptorChanged {
        ref descriptor,
        ..
      }) if descriptor == "member"
    ));

    let intermediate_root = tempfile::tempdir().unwrap();
    let intermediate = intermediate_root.path().join("dir");
    std::fs::create_dir(&intermediate).unwrap();
    let member = intermediate.join("member");
    std::fs::write(&member, b"member").unwrap();
    let intermediate_mode = intermediate.metadata().unwrap().permissions().mode();
    let intermediate_result =
      observe_oden_parent_direct_repo_source_from_test_root(
        intermediate_root.path(),
        &direct_file_specifier(&member),
        Arc::from(&b"member"[..]),
        || {
          std::fs::set_permissions(
            &intermediate,
            std::fs::Permissions::from_mode(intermediate_mode ^ 0o100),
          )
          .unwrap();
        },
      );
    std::fs::set_permissions(
      &intermediate,
      std::fs::Permissions::from_mode(intermediate_mode),
    )
    .unwrap();
    assert!(matches!(
      intermediate_result,
      Err(OdenParentDirectRepoSourceError::DescriptorChanged {
        ref descriptor,
        ..
      }) if descriptor == "dir"
    ));

    let root = tempfile::tempdir().unwrap();
    let member = root.path().join("member");
    std::fs::write(&member, b"member").unwrap();
    let root_mode = root.path().metadata().unwrap().permissions().mode();
    let root_result = observe_oden_parent_direct_repo_source_from_test_root(
      root.path(),
      &direct_file_specifier(&member),
      Arc::from(&b"member"[..]),
      || {
        std::fs::set_permissions(
          root.path(),
          std::fs::Permissions::from_mode(root_mode ^ 0o100),
        )
        .unwrap();
      },
    );
    std::fs::set_permissions(
      root.path(),
      std::fs::Permissions::from_mode(root_mode),
    )
    .unwrap();
    assert!(matches!(
      root_result,
      Err(OdenParentDirectRepoSourceError::RetainedDescriptor(
        OdenParentRetainedContractError::DescriptorChanged {
          ref descriptor,
          ..
        }
      )) if descriptor == "."
    ));

    let case_root = tempfile::tempdir().unwrap();
    std::fs::write(case_root.path().join("Case.ts"), b"case").unwrap();
    let wrong_case = direct_file_specifier(&case_root.path().join("case.ts"));
    assert!(matches!(
      observe_direct_from_test_root(
        case_root.path(),
        &wrong_case,
        Arc::from(&b"case"[..]),
      ),
      Err(OdenParentDirectRepoSourceError::InvalidExactComponentCount {
        ref component,
        matches: 0,
        ..
      }) if component == "case.ts"
    ));
  }

  #[cfg(any(target_os = "linux", target_os = "macos"))]
  #[test]
  fn direct_repo_dirent_name_is_record_bounded() {
    // SAFETY: all-zero integers and c_char arrays are valid dirent field
    // values; the test sets every field consumed by the platform extractor.
    let mut entry = unsafe { std::mem::zeroed::<libc::dirent>() };
    let name_offset = std::mem::offset_of!(libc::dirent, d_name);
    entry.d_name[0] = b'a' as libc::c_char;
    entry.d_name[1] = 0;

    #[cfg(target_os = "linux")]
    {
      entry.d_reclen = (name_offset + 2).try_into().unwrap();
      // SAFETY: `entry` is a complete local dirent with a two-byte d_name
      // record containing `a\0`.
      assert_eq!(
        unsafe { oden_parent_dirent_name(&entry, ".") }.unwrap(),
        b"a"
      );
      entry.d_name[1] = b'b' as libc::c_char;
      // SAFETY: the complete local dirent remains addressable; the extractor
      // must refuse because the record-bounded name has no NUL.
      assert!(matches!(
        unsafe { oden_parent_dirent_name(&entry, ".") },
        Err(OdenParentDirectRepoSourceError::MalformedDirectoryEntry(_))
      ));
    }

    #[cfg(target_os = "macos")]
    {
      entry.d_reclen = (name_offset + 2).try_into().unwrap();
      entry.d_namlen = 1;
      // SAFETY: `entry` is a complete local dirent whose d_namlen and
      // following NUL fit inside d_reclen.
      assert_eq!(
        unsafe { oden_parent_dirent_name(&entry, ".") }.unwrap(),
        b"a"
      );
      entry.d_namlen = entry.d_name.len().try_into().unwrap();
      // SAFETY: the full local struct is addressable; the extractor must
      // refuse d_namlen at the declared capacity with no following NUL slot.
      assert!(matches!(
        unsafe { oden_parent_dirent_name(&entry, ".") },
        Err(OdenParentDirectRepoSourceError::MalformedDirectoryEntry(_))
      ));
    }
  }

  #[cfg(any(target_os = "linux", target_os = "macos"))]
  fn load_from_test_root<H>(
    root: &Path,
    paths: &[&str],
    limits: RetainedContractFileLimits,
    post_read_hook: H,
  ) -> Result<RetainedContractFiles, OdenParentRetainedContractError>
  where
    H: FnMut(&str),
  {
    load_retained_contract_files_with(
      paths,
      limits,
      || RetainedRepositoryRoot::open_test_absolute(root),
      post_read_hook,
    )
  }

  #[cfg(any(target_os = "linux", target_os = "macos"))]
  fn retained_fixture_bytes(snapshot: &str, path: &str) -> Vec<u8> {
    format!("{snapshot} retained snapshot for {path}\n").into_bytes()
  }

  #[cfg(any(target_os = "linux", target_os = "macos"))]
  fn materialize_retained_contract_tree(root: &Path, snapshot: &str) {
    for path in ODEN_PARENT_CAPTURE_CONTRACT_PATHS
      .iter()
      .chain(ODEN_PARENT_SOURCE_CLOSURE_CONTRACT_PATHS)
      .chain(ODEN_PARENT_RELEASE_CONTRACT_PATHS)
    {
      let destination = root.join(path);
      if destination.exists() {
        continue;
      }
      std::fs::create_dir_all(destination.parent().unwrap()).unwrap();
      std::fs::write(destination, retained_fixture_bytes(snapshot, path))
        .unwrap();
    }
  }

  #[cfg(any(target_os = "linux", target_os = "macos"))]
  fn load_bundle_from_test_root(
    root: &Path,
  ) -> Result<RetainedContractByteBundle, OdenParentRetainedContractError> {
    load_retained_contract_byte_bundle_with(|| {
      RetainedRepositoryRoot::open_test_absolute(root)
    })
  }

  #[cfg(any(target_os = "linux", target_os = "macos"))]
  fn assert_retained_partition(
    retained: &RetainedContractFiles,
    expected_paths: &[&str],
    expected_snapshot: &str,
  ) {
    let file_paths = retained
      .files
      .iter()
      .map(|file| file.path.as_str())
      .collect::<Vec<_>>();
    assert_eq!(file_paths, expected_paths);
    let inventory_paths = retained
      .inventory()
      .rows()
      .iter()
      .map(|row| row.path())
      .collect::<Vec<_>>();
    assert_eq!(inventory_paths, expected_paths);

    for (file, expected_path) in
      retained.files.iter().zip(expected_paths.iter().copied())
    {
      let expected_bytes =
        retained_fixture_bytes(expected_snapshot, expected_path);
      assert_eq!(file.bytes, expected_bytes);
      let row = retained
        .inventory()
        .rows()
        .iter()
        .find(|row| row.path() == expected_path)
        .unwrap();
      assert_eq!(
        row.byte_digest().as_str(),
        raw_sha256_digest(&expected_bytes).as_str()
      );
    }
  }

  #[cfg(any(target_os = "linux", target_os = "macos"))]
  fn assert_generated_paths_absent(root: &Path) {
    for path in ODEN_PARENT_GENERATED_PATHS {
      match std::fs::symlink_metadata(root.join(path)) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Ok(_) => panic!("unexpected output {path}"),
        Err(error) => panic!("failed to inspect {path}: {error}"),
      }
    }
  }

  #[cfg(any(target_os = "linux", target_os = "macos"))]
  struct GeneratedPathSentinel {
    path: String,
    bytes: Vec<u8>,
    device: u64,
    inode: u64,
    mode: u32,
    links: u64,
  }

  #[cfg(any(target_os = "linux", target_os = "macos"))]
  fn seed_generated_path_sentinels(
    root: &Path,
  ) -> Vec<GeneratedPathSentinel> {
    ODEN_PARENT_GENERATED_PATHS
      .iter()
      .enumerate()
      .map(|(index, path)| {
        let destination = root.join(path);
        std::fs::create_dir_all(destination.parent().unwrap()).unwrap();
        let bytes = format!("sentinel-{index}\n").into_bytes();
        std::fs::write(&destination, &bytes).unwrap();
        let metadata = std::fs::symlink_metadata(&destination).unwrap();
        assert!(metadata.file_type().is_file());
        GeneratedPathSentinel {
          path: path.to_string(),
          bytes,
          device: metadata.dev(),
          inode: metadata.ino(),
          mode: metadata.mode(),
          links: metadata.nlink(),
        }
      })
      .collect()
  }

  #[cfg(any(target_os = "linux", target_os = "macos"))]
  fn assert_generated_path_sentinels_unchanged(
    root: &Path,
    sentinels: &[GeneratedPathSentinel],
  ) {
    for sentinel in sentinels {
      let destination = root.join(&sentinel.path);
      let metadata = std::fs::symlink_metadata(&destination).unwrap();
      assert!(metadata.file_type().is_file());
      assert_eq!(metadata.dev(), sentinel.device);
      assert_eq!(metadata.ino(), sentinel.inode);
      assert_eq!(metadata.mode(), sentinel.mode);
      assert_eq!(metadata.nlink(), sentinel.links);
      assert_eq!(std::fs::read(destination).unwrap(), sentinel.bytes);
    }
  }

  #[cfg(any(target_os = "linux", target_os = "macos"))]
  fn candidate_configuration_with_unstable(
    unstable: &UnstableConfig,
  ) -> OdenParentStandaloneConfiguration {
    let workspace_resolver = SerializedWorkspaceResolver {
      import_map: None,
      jsr_pkgs: Vec::new(),
      package_jsons: Default::default(),
      pkg_json_resolution:
        deno_resolver::workspace::PackageJsonDepResolution::Enabled,
      catalogs: Default::default(),
    };
    OdenParentStandaloneConfiguration::from_effective(
      &workspace_resolver,
      unstable,
      &OtelConfig::default(),
    )
    .unwrap()
  }

  #[cfg(any(target_os = "linux", target_os = "macos"))]
  fn candidate_configuration() -> OdenParentStandaloneConfiguration {
    candidate_configuration_with_unstable(&UnstableConfig::default())
  }

  #[cfg(any(target_os = "linux", target_os = "macos"))]
  fn candidate_vfs_and_static_edge(
  ) -> (OdenParentVfsGraph, OdenParentStaticImportEdge) {
    let dependency = [OdenParentVfsDependencyObservation {
      kind: OdenParentVfsDependencyKind::StaticImport,
      raw_specifier: ODEN_PARENT_PRIVATE_MODULE_SPECIFIER,
      resolved_key: ODEN_PARENT_PRIVATE_MODULE_SPECIFIER,
      source_byte_start: 8,
      source_byte_end: 50,
      import_attributes: &[],
    }];
    let module = [OdenParentVfsModuleObservation {
      key: ODEN_PARENT_ENTRYPOINT_KEY,
      media_type: OdenParentVfsMediaType::TypeScript,
      original_bytes: CANDIDATE_ENTRYPOINT_SOURCE,
      emitted_bytes: CANDIDATE_ENTRYPOINT_SOURCE,
      source_map_bytes: None,
      dependencies: &dependency,
    }];
    let vfs_graph =
      OdenParentVfsGraph::from_observations(&module, &[]).unwrap();
    let import_attributes =
      OdenParentImportAttributes::from_observed_pairs(&[]).unwrap();
    let static_import_edge = OdenParentStaticImportEdge::from_observation(
      OdenParentStaticImportEdgeObservation {
        entrypoint_source_bytes: CANDIDATE_ENTRYPOINT_SOURCE,
        dependency_ordinal: 0,
        occurrence_count: 1,
        kind: OdenParentVfsDependencyKind::StaticImport,
        raw_specifier: ODEN_PARENT_PRIVATE_MODULE_SPECIFIER,
        resolved_specifier: ODEN_PARENT_PRIVATE_MODULE_SPECIFIER,
        referrer_key: ODEN_PARENT_ENTRYPOINT_KEY,
        import_attributes: &import_attributes,
        source_byte_start: 8,
        source_byte_end: 50,
      },
    )
    .unwrap();
    (vfs_graph, static_import_edge)
  }

  #[cfg(any(target_os = "linux", target_os = "macos"))]
  fn candidate_output_for_root(
    root: &Path,
  ) -> OdenParentAllowlistCandidateOutput {
    let retained = load_bundle_from_test_root(root).unwrap();
    let configuration = candidate_configuration();
    let (vfs_graph, static_import_edge) = candidate_vfs_and_static_edge();
    compose_oden_parent_allowlist_candidate(
      &retained,
      OdenParentAllowlistCompilerProjectionInput {
        configuration: &configuration,
        vfs_graph: &vfs_graph,
        static_import_edge: &static_import_edge,
      },
    )
    .unwrap()
  }

  #[cfg(any(target_os = "linux", target_os = "macos"))]
  fn create_generate_output_directories(root: &Path) {
    for path in [
      ODEN_PARENT_GENERATED_JSON_PATH,
      ODEN_PARENT_GENERATED_RUST_PATH,
    ] {
      std::fs::create_dir_all(root.join(path).parent().unwrap()).unwrap();
    }
  }

  #[cfg(any(target_os = "linux", target_os = "macos"))]
  fn seed_check_candidate_outputs(
    root: &Path,
    candidate: &OdenParentAllowlistCandidateOutput,
  ) {
    create_generate_output_directories(root);
    for (path, bytes) in [
      (
        ODEN_PARENT_GENERATED_JSON_PATH,
        candidate.json_file.as_slice(),
      ),
      (
        ODEN_PARENT_GENERATED_RUST_PATH,
        candidate.rust_module.as_slice(),
      ),
    ] {
      let destination = root.join(path);
      std::fs::write(&destination, bytes).unwrap();
      std::fs::set_permissions(
        destination,
        std::fs::Permissions::from_mode(0o644),
      )
      .unwrap();
    }
  }

  #[cfg(any(target_os = "linux", target_os = "macos"))]
  #[derive(Debug, PartialEq, Eq)]
  struct CandidateFileSnapshot {
    path: &'static str,
    device: u64,
    inode: u64,
    links: u64,
    mode: u32,
    size: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
    bytes: Vec<u8>,
  }

  #[cfg(any(target_os = "linux", target_os = "macos"))]
  fn snapshot_candidate_files(root: &Path) -> Vec<CandidateFileSnapshot> {
    [
      ODEN_PARENT_GENERATED_JSON_PATH,
      ODEN_PARENT_GENERATED_RUST_PATH,
    ]
    .into_iter()
    .map(|path| {
      let metadata = std::fs::symlink_metadata(root.join(path)).unwrap();
      CandidateFileSnapshot {
        path,
        device: metadata.dev(),
        inode: metadata.ino(),
        links: metadata.nlink(),
        mode: metadata.mode(),
        size: metadata.len(),
        modified_seconds: metadata.mtime(),
        modified_nanoseconds: metadata.mtime_nsec(),
        changed_seconds: metadata.ctime(),
        changed_nanoseconds: metadata.ctime_nsec(),
        bytes: std::fs::read(root.join(path)).unwrap(),
      }
    })
    .collect()
  }

  #[cfg(any(target_os = "linux", target_os = "macos"))]
  fn assert_generate_temporaries_absent(root: &Path) {
    for (path, temporary_name) in [
      (
        ODEN_PARENT_GENERATED_JSON_PATH,
        ODEN_PARENT_GENERATED_JSON_TEMP_NAME,
      ),
      (
        ODEN_PARENT_GENERATED_RUST_PATH,
        ODEN_PARENT_GENERATED_RUST_TEMP_NAME,
      ),
    ] {
      let temporary = root.join(path).parent().unwrap().join(temporary_name);
      assert!(matches!(
        std::fs::symlink_metadata(temporary),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound
      ));
    }
  }

  #[cfg(any(target_os = "linux", target_os = "macos"))]
  #[test]
  fn generate_session_refuses_named_root_substitution_before_observation_or_output() {
    let outer = tempfile::tempdir().unwrap();
    let selected = outer.path().join("selected");
    let substitute = outer.path().join("substitute");
    let held_away = outer.path().join("held-away");
    std::fs::create_dir(&selected).unwrap();
    std::fs::create_dir(&substitute).unwrap();
    materialize_retained_contract_tree(&selected, "selected-root");
    materialize_retained_contract_tree(&substitute, "substitute-root");
    create_generate_output_directories(&selected);
    create_generate_output_directories(&substitute);
    let entrypoint_path = selected.join("src/release.ts");
    let entrypoint_bytes: Arc<[u8]> =
      std::fs::read(&entrypoint_path).unwrap().into();
    let entrypoint = ModuleSpecifier::from_file_path(&entrypoint_path).unwrap();
    let session = OdenParentAllowlistGenerateSession::begin_for_test(
      test_generate_eligibility(),
      &selected,
    )
    .unwrap();
    assert_eq!(session.repository_root_path(), selected);
    session.require_stable_reconciliation().unwrap();

    std::fs::rename(&selected, &held_away).unwrap();
    std::fs::rename(&substitute, &selected).unwrap();

    assert!(session.require_stable_reconciliation().is_err());
    assert!(
      session
        .observe_direct_repository_source(&entrypoint, entrypoint_bytes)
        .is_err()
    );
    let configuration = candidate_configuration();
    let (vfs_graph, static_import_edge) = candidate_vfs_and_static_edge();
    assert!(
      generate_oden_parent_allowlist_outputs(
        session,
        &configuration,
        &vfs_graph,
        &static_import_edge,
      )
      .is_err()
    );
    assert_generated_paths_absent(&selected);
    assert_generate_temporaries_absent(&selected);
  }

  #[cfg(any(target_os = "linux", target_os = "macos"))]
  #[test]
  fn check_session_is_distinct_and_refuses_named_root_substitution() {
    let outer = tempfile::tempdir().unwrap();
    let selected = outer.path().join("selected");
    let substitute = outer.path().join("substitute");
    let held_away = outer.path().join("held-away");
    std::fs::create_dir(&selected).unwrap();
    std::fs::create_dir(&substitute).unwrap();
    let session = OdenParentAllowlistCheckSession::begin_for_test(
      test_check_eligibility(),
      &selected,
    )
    .unwrap();
    assert_eq!(session.root.path, selected);
    session
      .root
      .require_current_and_named_paths_stable("check test initial")
      .unwrap();
    session.root.require_stable("<check-test-initial>").unwrap();

    std::fs::rename(&selected, &held_away).unwrap();
    std::fs::rename(&substitute, &selected).unwrap();

    assert!(
      session
        .root
        .require_current_and_named_paths_stable("check test substituted")
        .is_err()
    );
  }

  #[cfg(any(target_os = "linux", target_os = "macos"))]
  #[test]
  fn full_regeneration_session_is_distinct_and_refuses_named_root_substitution()
  {
    let outer = tempfile::tempdir().unwrap();
    let selected = outer.path().join("selected");
    let substitute = outer.path().join("substitute");
    let held_away = outer.path().join("held-away");
    std::fs::create_dir(&selected).unwrap();
    std::fs::create_dir(&substitute).unwrap();
    materialize_retained_contract_tree(&selected, "selected-regeneration");
    materialize_retained_contract_tree(&substitute, "substitute-regeneration");
    let configuration = candidate_configuration();
    let (vfs_graph, static_import_edge) = candidate_vfs_and_static_edge();
    let compiled = candidate_output_for_root(&selected);
    seed_check_candidate_outputs(&selected, &compiled);
    let session =
      OdenParentAllowlistFullRegenerationSession::begin_for_test(&selected)
        .unwrap();
    session.require_stable_reconciliation().unwrap();

    std::fs::rename(&selected, &held_away).unwrap();
    std::fs::rename(&substitute, &selected).unwrap();
    let before = snapshot_candidate_files(&held_away);

    assert!(session.require_stable_reconciliation().is_err());
    assert!(
      reconcile_oden_parent_allowlist_full_regeneration_with_compiled_candidate(
        session,
        &configuration,
        &vfs_graph,
        &static_import_edge,
        &compiled,
      )
      .is_err()
    );
    assert_eq!(snapshot_candidate_files(&held_away), before);
    assert_generated_paths_absent(&selected);
    assert_generate_temporaries_absent(&held_away);
    assert_generate_temporaries_absent(&selected);
  }

  #[cfg(any(target_os = "linux", target_os = "macos"))]
  #[test]
  fn full_regeneration_reconciliation_accepts_exact_inputs_and_preserves_files()
  {
    let root = tempfile::tempdir().unwrap();
    materialize_retained_contract_tree(root.path(), "full-regeneration-exact");
    let configuration = candidate_configuration();
    let (vfs_graph, static_import_edge) = candidate_vfs_and_static_edge();
    let compiled = candidate_output_for_root(root.path());
    seed_check_candidate_outputs(root.path(), &compiled);
    let before = snapshot_candidate_files(root.path());
    let session = OdenParentAllowlistFullRegenerationSession::begin_for_test(
      root.path(),
    )
    .unwrap();

    reconcile_oden_parent_allowlist_full_regeneration_with_compiled_candidate(
      session,
      &configuration,
      &vfs_graph,
      &static_import_edge,
      &compiled,
    )
    .unwrap();

    assert_eq!(snapshot_candidate_files(root.path()), before);
    assert_generate_temporaries_absent(root.path());
  }

  #[cfg(any(target_os = "linux", target_os = "macos"))]
  #[test]
  fn full_regeneration_reconciliation_refuses_each_inventory_partition_drift()
  {
    for (partition, path, expected_membership) in [
      (
        "capture",
        "schemas/capsec/rev2/filesystem-candidate-arena.schema.json",
        [true, false, false],
      ),
      (
        "source-closure",
        "scripts/release/filesystem-reachability-analyzer.ts",
        [false, true, false],
      ),
      (
        "release",
        ".github/workflows/release.yml",
        [false, false, true],
      ),
    ] {
      assert_eq!(
        [
          ODEN_PARENT_CAPTURE_CONTRACT_PATHS.contains(&path),
          ODEN_PARENT_SOURCE_CLOSURE_CONTRACT_PATHS.contains(&path),
          ODEN_PARENT_RELEASE_CONTRACT_PATHS.contains(&path),
        ],
        expected_membership,
      );
      let root = tempfile::tempdir().unwrap();
      materialize_retained_contract_tree(
        root.path(),
        &format!("full-regeneration-{partition}"),
      );
      let configuration = candidate_configuration();
      let (vfs_graph, static_import_edge) = candidate_vfs_and_static_edge();
      let compiled = candidate_output_for_root(root.path());
      seed_check_candidate_outputs(root.path(), &compiled);
      let session = OdenParentAllowlistFullRegenerationSession::begin_for_test(
        root.path(),
      )
      .unwrap();
      std::fs::write(
        root.path().join(path),
        format!("independent {partition} drift\n"),
      )
      .unwrap();
      let before = snapshot_candidate_files(root.path());

      assert!(matches!(
        reconcile_oden_parent_allowlist_full_regeneration_with_compiled_candidate(
          session,
          &configuration,
          &vfs_graph,
          &static_import_edge,
          &compiled,
        ),
        Err(OdenParentAllowlistFullRegenerationError(
          OdenParentAllowlistFullRegenerationFailure::CompiledCandidateMismatch
        ))
      ));
      assert_eq!(snapshot_candidate_files(root.path()), before);
      assert_generate_temporaries_absent(root.path());
    }
  }

  #[cfg(any(target_os = "linux", target_os = "macos"))]
  #[test]
  fn full_regeneration_reconciliation_refuses_configuration_graph_and_edge_drift()
  {
    let root = tempfile::tempdir().unwrap();
    materialize_retained_contract_tree(
      root.path(),
      "full-regeneration-projection-drift",
    );
    let configuration = candidate_configuration();
    let (vfs_graph, static_import_edge) = candidate_vfs_and_static_edge();
    let compiled = candidate_output_for_root(root.path());
    seed_check_candidate_outputs(root.path(), &compiled);
    let before = snapshot_candidate_files(root.path());

    let changed_workspace_resolver: SerializedWorkspaceResolver =
      deno_core::serde_json::from_value(deno_core::serde_json::json!({
        "catalogs": {
          "release": { "example": "jsr:@scope/example@1.0.0" }
        },
        "import_map": null,
        "jsr_pkgs": [],
        "package_jsons": {},
        "pkg_json_resolution": "Enabled",
      }))
      .unwrap();
    let changed_configuration = OdenParentStandaloneConfiguration::from_effective(
      &changed_workspace_resolver,
      &UnstableConfig::default(),
      &OtelConfig::default(),
    )
    .unwrap();

    let dependency = [OdenParentVfsDependencyObservation {
      kind: OdenParentVfsDependencyKind::StaticImport,
      raw_specifier: ODEN_PARENT_PRIVATE_MODULE_SPECIFIER,
      resolved_key: ODEN_PARENT_PRIVATE_MODULE_SPECIFIER,
      source_byte_start: 8,
      source_byte_end: 50,
      import_attributes: &[],
    }];
    let changed_emission =
      b"import \"oden-internal:filesystem-parent-capture-v2\";\n// changed emission\n";
    let module = [OdenParentVfsModuleObservation {
      key: ODEN_PARENT_ENTRYPOINT_KEY,
      media_type: OdenParentVfsMediaType::TypeScript,
      original_bytes: CANDIDATE_ENTRYPOINT_SOURCE,
      emitted_bytes: changed_emission,
      source_map_bytes: None,
      dependencies: &dependency,
    }];
    let changed_vfs_graph =
      OdenParentVfsGraph::from_observations(&module, &[]).unwrap();

    let changed_edge_source =
      b"// prefix\nimport \"oden-internal:filesystem-parent-capture-v2\";\n";
    let private_bytes = ODEN_PARENT_PRIVATE_MODULE_SPECIFIER.as_bytes();
    let changed_start = changed_edge_source
      .windows(private_bytes.len())
      .position(|window| window == private_bytes)
      .unwrap() as u64;
    let import_attributes =
      OdenParentImportAttributes::from_observed_pairs(&[]).unwrap();
    let changed_edge = OdenParentStaticImportEdge::from_observation(
      OdenParentStaticImportEdgeObservation {
        entrypoint_source_bytes: changed_edge_source,
        dependency_ordinal: 0,
        occurrence_count: 1,
        kind: OdenParentVfsDependencyKind::StaticImport,
        raw_specifier: ODEN_PARENT_PRIVATE_MODULE_SPECIFIER,
        resolved_specifier: ODEN_PARENT_PRIVATE_MODULE_SPECIFIER,
        referrer_key: ODEN_PARENT_ENTRYPOINT_KEY,
        import_attributes: &import_attributes,
        source_byte_start: changed_start,
        source_byte_end: changed_start + private_bytes.len() as u64,
      },
    )
    .unwrap();

    for (candidate_configuration, candidate_graph, candidate_edge) in [
      (&changed_configuration, &vfs_graph, &static_import_edge),
      (&configuration, &changed_vfs_graph, &static_import_edge),
      (&configuration, &vfs_graph, &changed_edge),
    ] {
      let session =
        OdenParentAllowlistFullRegenerationSession::begin_for_test(root.path())
          .unwrap();
      assert!(
        reconcile_oden_parent_allowlist_full_regeneration_with_compiled_candidate(
          session,
          candidate_configuration,
          candidate_graph,
          candidate_edge,
          &compiled,
        )
        .is_err()
      );
      assert_eq!(snapshot_candidate_files(root.path()), before);
      assert_generate_temporaries_absent(root.path());
    }
  }

  #[cfg(any(target_os = "linux", target_os = "macos"))]
  #[test]
  fn full_regeneration_reconciliation_refuses_compiled_and_checked_file_drift()
  {
    let root = tempfile::tempdir().unwrap();
    materialize_retained_contract_tree(
      root.path(),
      "full-regeneration-compiled-drift",
    );
    let configuration = candidate_configuration();
    let (vfs_graph, static_import_edge) = candidate_vfs_and_static_edge();
    let compiled = candidate_output_for_root(root.path());
    seed_check_candidate_outputs(root.path(), &compiled);

    let mut changed_jcs = compiled.clone();
    changed_jcs.canonical_jcs[0] ^= 1;
    let mut changed_digest = compiled.clone();
    changed_digest.digest.push('x');
    let mut changed_json_rendering = compiled.clone();
    changed_json_rendering.json_file[0] ^= 1;
    let mut changed_rust_rendering = compiled.clone();
    changed_rust_rendering.rust_module[0] ^= 1;
    for changed in [
      changed_jcs,
      changed_digest,
      changed_json_rendering,
      changed_rust_rendering,
    ] {
      let before = snapshot_candidate_files(root.path());
      let session =
        OdenParentAllowlistFullRegenerationSession::begin_for_test(root.path())
          .unwrap();
      assert!(matches!(
        reconcile_oden_parent_allowlist_full_regeneration_with_compiled_candidate(
          session,
          &configuration,
          &vfs_graph,
          &static_import_edge,
          &changed,
        ),
        Err(OdenParentAllowlistFullRegenerationError(
          OdenParentAllowlistFullRegenerationFailure::CompiledCandidateMismatch
        ))
      ));
      assert_eq!(snapshot_candidate_files(root.path()), before);
    }

    for changed_paths in [
      vec![ODEN_PARENT_GENERATED_JSON_PATH],
      vec![ODEN_PARENT_GENERATED_RUST_PATH],
      vec![
        ODEN_PARENT_GENERATED_JSON_PATH,
        ODEN_PARENT_GENERATED_RUST_PATH,
      ],
    ] {
      seed_check_candidate_outputs(root.path(), &compiled);
      for path in changed_paths {
        let destination = root.path().join(path);
        let mut bytes = std::fs::read(&destination).unwrap();
        bytes[0] ^= 1;
        std::fs::write(destination, bytes).unwrap();
      }
      let before = snapshot_candidate_files(root.path());
      let session =
        OdenParentAllowlistFullRegenerationSession::begin_for_test(root.path())
          .unwrap();
      assert!(
        reconcile_oden_parent_allowlist_full_regeneration_with_compiled_candidate(
          session,
          &configuration,
          &vfs_graph,
          &static_import_edge,
          &compiled,
        )
        .is_err()
      );
      assert_eq!(snapshot_candidate_files(root.path()), before);
      assert_generate_temporaries_absent(root.path());
    }
  }

  #[cfg(any(target_os = "linux", target_os = "macos"))]
  #[test]
  fn generate_session_uses_its_held_root_for_inventories_and_outputs() {
    let root = tempfile::tempdir().unwrap();
    materialize_retained_contract_tree(root.path(), "session-root");
    create_generate_output_directories(root.path());
    let session = OdenParentAllowlistGenerateSession::begin_for_test(
      test_generate_eligibility(),
      root.path(),
    )
    .unwrap();
    assert_eq!(session.repository_root_path(), root.path());
    let configuration = candidate_configuration();
    let (vfs_graph, static_import_edge) = candidate_vfs_and_static_edge();

    generate_oden_parent_allowlist_outputs(
      session,
      &configuration,
      &vfs_graph,
      &static_import_edge,
    )
    .unwrap();

    for path in [
      ODEN_PARENT_GENERATED_JSON_PATH,
      ODEN_PARENT_GENERATED_RUST_PATH,
    ] {
      let metadata =
        std::fs::symlink_metadata(root.path().join(path)).unwrap();
      assert!(metadata.file_type().is_file());
      assert_eq!(metadata.nlink(), 1);
    }
    assert_generate_temporaries_absent(root.path());
  }

  #[cfg(any(target_os = "linux", target_os = "macos"))]
  #[test]
  fn bootstrap_asset_source_is_owned_by_the_held_exact_descriptor_read() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join(ODEN_PARENT_BOOTSTRAP_ASSET_PATH);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    let bytes = b"export async function bootstrap() {}\n";
    std::fs::write(&path, bytes).unwrap();
    let specifier = ModuleSpecifier::from_file_path(&path).unwrap();
    let session = OdenParentAllowlistGenerateSession::begin_for_test(
      test_generate_eligibility(),
      root.path(),
    )
    .unwrap();

    let candidate = session
      .observe_bootstrap_asset_source(&specifier)
      .unwrap();
    assert_eq!(candidate.specifier(), &specifier);
    assert_eq!(candidate.key().as_str(), ODEN_PARENT_BOOTSTRAP_ASSET_KEY);
    assert_eq!(candidate.original_bytes().as_ref(), bytes);
    assert!(!candidate.executable());

    let alias = ModuleSpecifier::from_file_path(
      root.path().join("src/capsec/Bootstrap.ts"),
    )
    .unwrap();
    assert!(session.observe_bootstrap_asset_source(&alias).is_err());

    std::fs::write(
      &path,
      vec![b'x'; ODEN_PARENT_BOOTSTRAP_ASSET_MAX_BYTES as usize + 1],
    )
    .unwrap();
    assert!(
      session
        .observe_bootstrap_asset_source(&specifier)
        .is_err()
    );
  }

  #[cfg(any(target_os = "linux", target_os = "macos"))]
  #[test]
  fn generate_writer_atomically_replaces_each_of_two_fixed_outputs() {
    let root = tempfile::tempdir().unwrap();
    materialize_retained_contract_tree(root.path(), "generate");
    create_generate_output_directories(root.path());
    let sentinels = seed_generated_path_sentinels(root.path());
    let candidate = candidate_output_for_root(root.path());
    let retained_root =
      RetainedRepositoryRoot::open_test_absolute(root.path()).unwrap();

    write_oden_parent_allowlist_candidate_outputs_with_root(
      &retained_root,
      &candidate,
    )
    .unwrap();

    for (path, expected) in [
      (
        ODEN_PARENT_GENERATED_JSON_PATH,
        candidate.json_file.as_slice(),
      ),
      (
        ODEN_PARENT_GENERATED_RUST_PATH,
        candidate.rust_module.as_slice(),
      ),
    ] {
      let destination = root.path().join(path);
      assert_eq!(std::fs::read(&destination).unwrap(), expected);
      let metadata = std::fs::symlink_metadata(destination).unwrap();
      let before = sentinels
        .iter()
        .find(|sentinel| sentinel.path == path)
        .unwrap();
      assert_ne!(metadata.ino(), before.inode);
      assert_eq!(metadata.nlink(), 1);
      assert_eq!(metadata.mode() & 0o777, 0o644);
    }
    let carrier = sentinels
      .iter()
      .find(|sentinel| {
        sentinel.path == ODEN_PARENT_TARGET_POLICY_GENERATED_RUST_PATH
      })
      .unwrap();
    assert_generated_path_sentinels_unchanged(
      root.path(),
      std::slice::from_ref(carrier),
    );
    assert_generate_temporaries_absent(root.path());
  }

  #[cfg(any(target_os = "linux", target_os = "macos"))]
  #[test]
  fn generate_writer_creates_absent_outputs_from_complete_stages() {
    let root = tempfile::tempdir().unwrap();
    materialize_retained_contract_tree(root.path(), "generate-absent");
    create_generate_output_directories(root.path());
    let candidate = candidate_output_for_root(root.path());
    assert_generated_paths_absent(root.path());
    let retained_root =
      RetainedRepositoryRoot::open_test_absolute(root.path()).unwrap();

    write_oden_parent_allowlist_candidate_outputs_with_root(
      &retained_root,
      &candidate,
    )
    .unwrap();

    assert_eq!(
      std::fs::read(root.path().join(ODEN_PARENT_GENERATED_JSON_PATH)).unwrap(),
      candidate.json_file,
    );
    assert_eq!(
      std::fs::read(root.path().join(ODEN_PARENT_GENERATED_RUST_PATH)).unwrap(),
      candidate.rust_module,
    );
    assert!(matches!(
      std::fs::symlink_metadata(
        root
          .path()
          .join(ODEN_PARENT_TARGET_POLICY_GENERATED_RUST_PATH)
      ),
      Err(error) if error.kind() == std::io::ErrorKind::NotFound
    ));
    assert_generate_temporaries_absent(root.path());
  }

  #[cfg(any(target_os = "linux", target_os = "macos"))]
  #[test]
  fn generate_writer_refuses_a_wrong_case_alias_for_an_absent_exact_output() {
    let root = tempfile::tempdir().unwrap();
    materialize_retained_contract_tree(root.path(), "generate-case-alias");
    create_generate_output_directories(root.path());
    let exact = root.path().join(ODEN_PARENT_GENERATED_JSON_PATH);
    let alias = exact
      .parent()
      .unwrap()
      .join("Filesystem-parent-standalone-allowlist.json");
    let alias_bytes = b"wrong-case output alias\n";
    std::fs::write(&alias, alias_bytes).unwrap();
    let exact_was_absent = matches!(
      std::fs::symlink_metadata(&exact),
      Err(error) if error.kind() == std::io::ErrorKind::NotFound
    );
    let candidate = candidate_output_for_root(root.path());
    let retained_root =
      RetainedRepositoryRoot::open_test_absolute(root.path()).unwrap();

    assert!(
      write_oden_parent_allowlist_candidate_outputs_with_root(
        &retained_root,
        &candidate,
      )
      .is_err()
    );
    assert_eq!(std::fs::read(&alias).unwrap(), alias_bytes);
    if exact_was_absent {
      assert!(matches!(
        std::fs::symlink_metadata(&exact),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound
      ));
    }
    assert!(matches!(
      std::fs::symlink_metadata(
        root.path().join(ODEN_PARENT_GENERATED_RUST_PATH)
      ),
      Err(error) if error.kind() == std::io::ErrorKind::NotFound
    ));
    assert_generate_temporaries_absent(root.path());
  }

  #[cfg(any(target_os = "linux", target_os = "macos"))]
  #[test]
  fn generate_writer_refuses_success_after_a_committed_ancestor_is_rebound() {
    let root = tempfile::tempdir().unwrap();
    materialize_retained_contract_tree(root.path(), "generate-rebound");
    create_generate_output_directories(root.path());
    let candidate = candidate_output_for_root(root.path());
    let retained_root =
      RetainedRepositoryRoot::open_test_absolute(root.path()).unwrap();
    let selected = root.path().join("generated/capsec/rev2");
    let detached = root.path().join("generated/capsec/rev2-detached");

    let result =
      write_oden_parent_allowlist_candidate_outputs_with_root_and_post_commit_hook(
        &retained_root,
        &candidate,
        || {
          std::fs::rename(&selected, &detached).unwrap();
          std::fs::create_dir(&selected).unwrap();
        },
      );

    assert!(matches!(
      result,
      Err(OdenParentAllowlistGenerateFailure::OutputDirectoryChanged(
        ODEN_PARENT_GENERATED_JSON_PATH
      ))
        | Err(OdenParentAllowlistGenerateFailure::DirectoryObservation(_))
        | Err(OdenParentAllowlistGenerateFailure::ReplacedOutputMismatch(
          ODEN_PARENT_GENERATED_JSON_PATH
        ))
    ));
    assert_eq!(
      std::fs::read(detached.join("filesystem-parent-standalone-allowlist.json"))
        .unwrap(),
      candidate.json_file,
    );
    assert_eq!(
      std::fs::read(root.path().join(ODEN_PARENT_GENERATED_RUST_PATH)).unwrap(),
      candidate.rust_module,
    );
    assert_generate_temporaries_absent(root.path());
  }

  #[cfg(any(target_os = "linux", target_os = "macos"))]
  #[test]
  fn generate_writer_refuses_links_and_specials_before_any_replacement() {
    enum InvalidOutput {
      Symlink,
      Hardlink,
      Fifo,
    }

    for invalid in [
      InvalidOutput::Symlink,
      InvalidOutput::Hardlink,
      InvalidOutput::Fifo,
    ] {
      let root = tempfile::tempdir().unwrap();
      materialize_retained_contract_tree(root.path(), "generate-refusal");
      create_generate_output_directories(root.path());
      let first = root.path().join(ODEN_PARENT_GENERATED_JSON_PATH);
      let second = root.path().join(ODEN_PARENT_GENERATED_RUST_PATH);
      let first_bytes = b"first output sentinel\n";
      std::fs::write(&first, first_bytes).unwrap();
      let victim = root.path().join("victim");
      std::fs::write(&victim, b"victim\n").unwrap();
      match invalid {
        InvalidOutput::Symlink => {
          std::os::unix::fs::symlink(&victim, &second).unwrap();
        }
        InvalidOutput::Hardlink => {
          std::fs::hard_link(&victim, &second).unwrap();
        }
        InvalidOutput::Fifo => {
          let encoded = CString::new(second.as_os_str().as_bytes()).unwrap();
          // SAFETY: `encoded` is a terminated test-only pathname.
          assert_eq!(unsafe { libc::mkfifo(encoded.as_ptr(), 0o600) }, 0);
        }
      }
      let candidate = candidate_output_for_root(root.path());
      let retained_root =
        RetainedRepositoryRoot::open_test_absolute(root.path()).unwrap();

      assert!(
        write_oden_parent_allowlist_candidate_outputs_with_root(
          &retained_root,
          &candidate,
        )
        .is_err()
      );
      assert_eq!(std::fs::read(&first).unwrap(), first_bytes);
      assert_eq!(std::fs::read(&victim).unwrap(), b"victim\n");
      assert_generate_temporaries_absent(root.path());
    }
  }

  #[cfg(any(target_os = "linux", target_os = "macos"))]
  #[test]
  fn check_candidate_preserves_identity_mode_size_mtime_ctime_and_bytes() {
    let root = tempfile::tempdir().unwrap();
    materialize_retained_contract_tree(root.path(), "check-exact");
    let candidate = candidate_output_for_root(root.path());
    seed_check_candidate_outputs(root.path(), &candidate);
    let before = [
      ODEN_PARENT_GENERATED_JSON_PATH,
      ODEN_PARENT_GENERATED_RUST_PATH,
    ]
    .map(|path| {
      let metadata = std::fs::symlink_metadata(root.path().join(path)).unwrap();
      (
        path,
        metadata.ino(),
        metadata.nlink(),
        metadata.len(),
        metadata.mode(),
        metadata.mtime(),
        metadata.mtime_nsec(),
        metadata.ctime(),
        metadata.ctime_nsec(),
        std::fs::read(root.path().join(path)).unwrap(),
      )
    });
    let retained_root =
      RetainedRepositoryRoot::open_test_absolute(root.path()).unwrap();

    require_oden_parent_allowlist_candidate_files(
      &retained_root,
      &candidate,
    )
    .unwrap();

    for before in before {
      let metadata =
        std::fs::symlink_metadata(root.path().join(before.0)).unwrap();
      assert_eq!(metadata.ino(), before.1);
      assert_eq!(metadata.nlink(), before.2);
      assert_eq!(metadata.len(), before.3);
      assert_eq!(metadata.mode(), before.4);
      assert_eq!(metadata.mtime(), before.5);
      assert_eq!(metadata.mtime_nsec(), before.6);
      assert_eq!(metadata.ctime(), before.7);
      assert_eq!(metadata.ctime_nsec(), before.8);
      assert_eq!(std::fs::read(root.path().join(before.0)).unwrap(), before.9);
    }
    assert_generate_temporaries_absent(root.path());
  }

  #[cfg(all(
    feature = "__oden_parent_allowlist_embedded",
    any(target_os = "linux", target_os = "macos")
  ))]
  #[test]
  fn check_endpoint_reconciles_the_actual_compiled_candidate() {
    let root = tempfile::tempdir().unwrap();
    let (embedded_jcs, embedded_digest) = deno_lib::standalone::oden_parent_allowlist::embedded_oden_parent_allowlist_candidate();
    let candidate = checked_oden_parent_allowlist_candidate_output(
      embedded_jcs,
      embedded_digest,
    )
    .unwrap();
    seed_check_candidate_outputs(root.path(), &candidate);
    let session = OdenParentAllowlistCheckSession::begin_for_test(
      test_check_eligibility(),
      root.path(),
    )
    .unwrap();

    check_oden_parent_allowlist_outputs(session).unwrap();
    assert_generate_temporaries_absent(root.path());
  }

  #[cfg(any(target_os = "linux", target_os = "macos"))]
  #[test]
  fn check_candidate_refuses_missing_alias_drift_mode_links_and_specials() {
    enum InvalidOutput {
      Missing,
      WrongCase,
      Trailing,
      ByteDrift,
      Mode,
      Symlink,
      Hardlink,
      Fifo,
    }

    for invalid in [
      InvalidOutput::Missing,
      InvalidOutput::WrongCase,
      InvalidOutput::Trailing,
      InvalidOutput::ByteDrift,
      InvalidOutput::Mode,
      InvalidOutput::Symlink,
      InvalidOutput::Hardlink,
      InvalidOutput::Fifo,
    ] {
      let root = tempfile::tempdir().unwrap();
      materialize_retained_contract_tree(root.path(), "check-refusal");
      let candidate = candidate_output_for_root(root.path());
      seed_check_candidate_outputs(root.path(), &candidate);
      let json = root.path().join(ODEN_PARENT_GENERATED_JSON_PATH);
      let rust = root.path().join(ODEN_PARENT_GENERATED_RUST_PATH);
      match invalid {
        InvalidOutput::Missing => std::fs::remove_file(&rust).unwrap(),
        InvalidOutput::WrongCase => {
          let alias = json
            .parent()
            .unwrap()
            .join("Filesystem-parent-standalone-allowlist.json");
          std::fs::rename(&json, alias).unwrap();
        }
        InvalidOutput::Trailing => {
          use std::io::Write as _;
          std::fs::OpenOptions::new()
            .append(true)
            .open(&json)
            .unwrap()
            .write_all(b"\n")
            .unwrap();
        }
        InvalidOutput::ByteDrift => {
          let mut bytes = candidate.rust_module.clone();
          bytes[0] ^= 1;
          std::fs::write(&rust, bytes).unwrap();
        }
        InvalidOutput::Mode => {
          std::fs::set_permissions(
            &json,
            std::fs::Permissions::from_mode(0o600),
          )
          .unwrap();
        }
        InvalidOutput::Symlink => {
          let victim = root.path().join("check-symlink-victim");
          std::fs::write(&victim, &candidate.rust_module).unwrap();
          std::fs::remove_file(&rust).unwrap();
          std::os::unix::fs::symlink(&victim, &rust).unwrap();
        }
        InvalidOutput::Hardlink => {
          let victim = root.path().join("check-hardlink-victim");
          std::fs::write(&victim, &candidate.rust_module).unwrap();
          std::fs::remove_file(&rust).unwrap();
          std::fs::hard_link(&victim, &rust).unwrap();
        }
        InvalidOutput::Fifo => {
          std::fs::remove_file(&rust).unwrap();
          let encoded = CString::new(rust.as_os_str().as_bytes()).unwrap();
          // SAFETY: `encoded` is a terminated test-only pathname.
          assert_eq!(unsafe { libc::mkfifo(encoded.as_ptr(), 0o644) }, 0);
        }
      }
      let retained_root =
        RetainedRepositoryRoot::open_test_absolute(root.path()).unwrap();
      assert!(
        require_oden_parent_allowlist_candidate_files(
          &retained_root,
          &candidate,
        )
        .is_err()
      );
      assert_generate_temporaries_absent(root.path());
    }
  }

  #[cfg(any(target_os = "linux", target_os = "macos"))]
  #[test]
  fn check_candidate_refuses_an_additional_ascii_case_alias() {
    use std::io::Write as _;

    let root = tempfile::tempdir().unwrap();
    materialize_retained_contract_tree(root.path(), "check-case-alias");
    let candidate = candidate_output_for_root(root.path());
    seed_check_candidate_outputs(root.path(), &candidate);
    let json = root.path().join(ODEN_PARENT_GENERATED_JSON_PATH);
    let alias = json
      .parent()
      .unwrap()
      .join("Filesystem-parent-standalone-allowlist.json");
    let mut alias_file = match std::fs::OpenOptions::new()
      .write(true)
      .create_new(true)
      .open(&alias)
    {
      Ok(file) => file,
      Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
        // A case-insensitive filesystem cannot materialize this adversarial
        // state; the folded-name scanner is exercised on case-sensitive CI.
        return;
      }
      Err(error) => panic!("failed to create case alias: {error}"),
    };
    alias_file.write_all(&candidate.json_file).unwrap();
    drop(alias_file);
    let retained_root =
      RetainedRepositoryRoot::open_test_absolute(root.path()).unwrap();

    assert!(matches!(
      require_oden_parent_allowlist_candidate_files(
        &retained_root,
        &candidate,
      ),
      Err(OdenParentAllowlistCandidateFileFailure::DirectRepository(
        OdenParentDirectRepoSourceError::InvalidCaseFoldedComponentCount {
          matches: 2,
          ..
        }
      ))
    ));
  }

  #[cfg(any(target_os = "linux", target_os = "macos"))]
  #[test]
  fn check_candidate_detects_post_open_name_replacement() {
    let root = tempfile::tempdir().unwrap();
    materialize_retained_contract_tree(root.path(), "check-replacement");
    let candidate = candidate_output_for_root(root.path());
    seed_check_candidate_outputs(root.path(), &candidate);
    let json = root.path().join(ODEN_PARENT_GENERATED_JSON_PATH);
    let detached = json.with_extension("json.detached");
    let retained_root =
      RetainedRepositoryRoot::open_test_absolute(root.path()).unwrap();

    assert!(
      require_oden_parent_allowlist_candidate_files_with_post_open_hook(
        &retained_root,
        &candidate,
        || {
          std::fs::rename(&json, &detached).unwrap();
          std::fs::write(&json, &candidate.json_file).unwrap();
          std::fs::set_permissions(
            &json,
            std::fs::Permissions::from_mode(0o644),
          )
          .unwrap();
        },
      )
      .is_err()
    );
    assert_eq!(std::fs::read(detached).unwrap(), candidate.json_file);
  }

  #[cfg(any(target_os = "linux", target_os = "macos"))]
  #[test]
  fn check_candidate_detects_post_open_ancestor_rebinding() {
    let root = tempfile::tempdir().unwrap();
    materialize_retained_contract_tree(root.path(), "check-rebinding");
    let candidate = candidate_output_for_root(root.path());
    seed_check_candidate_outputs(root.path(), &candidate);
    let ancestor = root.path().join("generated/capsec/rev2");
    let detached = root.path().join("generated/capsec/rev2.detached");
    let retained_root =
      RetainedRepositoryRoot::open_test_absolute(root.path()).unwrap();

    assert!(
      require_oden_parent_allowlist_candidate_files_with_post_open_hook(
        &retained_root,
        &candidate,
        || {
          std::fs::rename(&ancestor, &detached).unwrap();
          std::fs::create_dir(&ancestor).unwrap();
          let replacement = root.path().join(ODEN_PARENT_GENERATED_JSON_PATH);
          std::fs::write(&replacement, &candidate.json_file).unwrap();
          std::fs::set_permissions(
            replacement,
            std::fs::Permissions::from_mode(0o644),
          )
          .unwrap();
        },
      )
      .is_err()
    );
    assert_eq!(
      std::fs::read(
        detached.join("filesystem-parent-standalone-allowlist.json")
      )
      .unwrap(),
      candidate.json_file
    );
  }

  #[cfg(any(target_os = "linux", target_os = "macos"))]
  #[test]
  fn generate_writer_preserves_a_preexisting_temporary_name_and_outputs() {
    let root = tempfile::tempdir().unwrap();
    materialize_retained_contract_tree(root.path(), "generate-temp-refusal");
    create_generate_output_directories(root.path());
    let sentinels = seed_generated_path_sentinels(root.path());
    let temporary = root
      .path()
      .join(ODEN_PARENT_GENERATED_JSON_PATH)
      .parent()
      .unwrap()
      .join(ODEN_PARENT_GENERATED_JSON_TEMP_NAME);
    let temporary_bytes = b"unowned temporary sentinel\n";
    std::fs::write(&temporary, temporary_bytes).unwrap();
    let candidate = candidate_output_for_root(root.path());
    let retained_root =
      RetainedRepositoryRoot::open_test_absolute(root.path()).unwrap();

    assert!(
      write_oden_parent_allowlist_candidate_outputs_with_root(
        &retained_root,
        &candidate,
      )
      .is_err()
    );
    assert_generated_path_sentinels_unchanged(root.path(), &sentinels);
    assert_eq!(std::fs::read(&temporary).unwrap(), temporary_bytes);
    let rust_temporary = root
      .path()
      .join(ODEN_PARENT_GENERATED_RUST_PATH)
      .parent()
      .unwrap()
      .join(ODEN_PARENT_GENERATED_RUST_TEMP_NAME);
    assert!(matches!(
      std::fs::symlink_metadata(rust_temporary),
      Err(error) if error.kind() == std::io::ErrorKind::NotFound
    ));
  }

  #[cfg(any(target_os = "linux", target_os = "macos"))]
  #[test]
  fn candidate_compositor_matches_direct_typed_projection_deterministically() {
    let absent_root = tempfile::tempdir().unwrap();
    materialize_retained_contract_tree(absent_root.path(), "candidate");
    assert_generated_paths_absent(absent_root.path());
    let retained = load_bundle_from_test_root(absent_root.path()).unwrap();
    let configuration = candidate_configuration();
    let (vfs_graph, static_import_edge) = candidate_vfs_and_static_edge();
    let compiler = OdenParentAllowlistCompilerProjectionInput {
      configuration: &configuration,
      vfs_graph: &vfs_graph,
      static_import_edge: &static_import_edge,
    };

    let candidate =
      compose_oden_parent_allowlist_candidate(&retained, compiler).unwrap();
    let repeated =
      compose_oden_parent_allowlist_candidate(&retained, compiler).unwrap();
    assert_eq!(candidate, repeated);
    assert_generated_paths_absent(absent_root.path());

    let direct = OdenParentAllowlist::from_inputs(OdenParentAllowlistInputs {
      capture_contract: retained.capture.inventory(),
      source_closure_contract: retained.source_closure.inventory(),
      release_contract: retained.release.inventory(),
      configuration: &configuration,
      vfs_graph: &vfs_graph,
      static_import_edge: &static_import_edge,
    })
    .unwrap();
    assert_eq!(candidate.json_file, direct.render_json_file().unwrap());
    assert_eq!(candidate.rust_module, direct.render_rust_module().unwrap());

    let json_jcs = candidate.json_file.strip_suffix(b"\n").unwrap();
    let json_jcs = std::str::from_utf8(json_jcs).unwrap();
    let rust_module = std::str::from_utf8(&candidate.rust_module).unwrap();
    assert!(rust_module.contains(&format!(
      "pub const ODEN_PARENT_ALLOWLIST_JCS: &[u8] = br#\"{json_jcs}\"#;"
    )));
    assert!(rust_module.contains(direct.digest().unwrap().as_str()));
  }

  #[cfg(any(target_os = "linux", target_os = "macos"))]
  #[test]
  fn candidate_compositor_has_no_output_or_dispatch_authority() {
    let sentinel_root = tempfile::tempdir().unwrap();
    materialize_retained_contract_tree(sentinel_root.path(), "candidate");
    let sentinels = seed_generated_path_sentinels(sentinel_root.path());
    let sentinel_retained =
      load_bundle_from_test_root(sentinel_root.path()).unwrap();
    let configuration = candidate_configuration();
    let (vfs_graph, static_import_edge) = candidate_vfs_and_static_edge();
    compose_oden_parent_allowlist_candidate(
      &sentinel_retained,
      OdenParentAllowlistCompilerProjectionInput {
        configuration: &configuration,
        vfs_graph: &vfs_graph,
        static_import_edge: &static_import_edge,
      },
    )
    .unwrap();
    assert_generated_path_sentinels_unchanged(
      sentinel_root.path(),
      &sentinels,
    );

    for dispatch in [
      OdenParentAllowlistRawDispatch::Generate,
      OdenParentAllowlistRawDispatch::Check,
    ] {
      assert_eq!(
        crate::oden_parent_allowlist_refusal_exit_code_for_raw_dispatch(
          dispatch
        ),
        ODEN_PARENT_ALLOWLIST_REFUSAL_EXIT_CODE,
      );
    }
  }

  #[cfg(any(target_os = "linux", target_os = "macos"))]
  #[test]
  fn retained_bundle_preserves_exact_partitions_order_and_owned_snapshots() {
    let capture_root = tempfile::tempdir().unwrap();
    let source_closure_root = tempfile::tempdir().unwrap();
    let release_root = tempfile::tempdir().unwrap();
    materialize_retained_contract_tree(capture_root.path(), "capture-root");
    materialize_retained_contract_tree(
      source_closure_root.path(),
      "source-closure-root",
    );
    materialize_retained_contract_tree(release_root.path(), "release-root");

    let mut roots = [
      capture_root.path(),
      source_closure_root.path(),
      release_root.path(),
    ]
    .into_iter();
    let bundle = load_retained_contract_byte_bundle_with(|| {
      RetainedRepositoryRoot::open_test_absolute(roots.next().unwrap())
    })
    .unwrap();
    assert!(roots.next().is_none());
    assert_retained_partition(
      &bundle.capture,
      ODEN_PARENT_CAPTURE_CONTRACT_PATHS,
      "capture-root",
    );
    assert_retained_partition(
      &bundle.source_closure,
      ODEN_PARENT_SOURCE_CLOSURE_CONTRACT_PATHS,
      "source-closure-root",
    );
    assert_retained_partition(
      &bundle.release,
      ODEN_PARENT_RELEASE_CONTRACT_PATHS,
      "release-root",
    );

    let shared_path = ODEN_PARENT_CAPTURE_CONTRACT_PATHS[0];
    assert!(ODEN_PARENT_SOURCE_CLOSURE_CONTRACT_PATHS.contains(&shared_path));
    assert!(ODEN_PARENT_RELEASE_CONTRACT_PATHS.contains(&shared_path));
    for root in [
      capture_root.path(),
      source_closure_root.path(),
      release_root.path(),
    ] {
      std::fs::write(root.join(shared_path), b"later tree bytes\n").unwrap();
    }

    assert_retained_partition(
      &bundle.capture,
      ODEN_PARENT_CAPTURE_CONTRACT_PATHS,
      "capture-root",
    );
    assert_retained_partition(
      &bundle.source_closure,
      ODEN_PARENT_SOURCE_CLOSURE_CONTRACT_PATHS,
      "source-closure-root",
    );
    assert_retained_partition(
      &bundle.release,
      ODEN_PARENT_RELEASE_CONTRACT_PATHS,
      "release-root",
    );
  }

  #[cfg(any(target_os = "linux", target_os = "macos"))]
  #[test]
  fn retained_bundle_refuses_a_missing_member_in_each_partition() {
    for missing_path in [
      "schemas/capsec/rev2/filesystem-candidate-arena.schema.json",
      "schemas/capsec/rev2/filesystem-linked-image-manifest.schema.json",
      "release.json",
    ] {
      let root = tempfile::tempdir().unwrap();
      materialize_retained_contract_tree(root.path(), "missing-member-root");
      std::fs::remove_file(root.path().join(missing_path)).unwrap();
      let sentinels = seed_generated_path_sentinels(root.path());

      let result = load_bundle_from_test_root(root.path());
      assert!(matches!(
        result,
        Err(OdenParentRetainedContractError::ExactNameObservation {
          ref path,
          ..
        }) if path == missing_path
      ));
      assert_generated_path_sentinels_unchanged(
        root.path(),
        &sentinels,
      );
    }
  }

  #[cfg(any(target_os = "linux", target_os = "macos"))]
  #[test]
  fn retained_bundle_has_no_generated_output_behavior() {
    let absent_root = tempfile::tempdir().unwrap();
    materialize_retained_contract_tree(absent_root.path(), "absent-root");
    assert_generated_paths_absent(absent_root.path());
    load_bundle_from_test_root(absent_root.path()).unwrap();
    assert_generated_paths_absent(absent_root.path());

    let sentinel_root = tempfile::tempdir().unwrap();
    materialize_retained_contract_tree(sentinel_root.path(), "sentinel-root");
    let sentinels = seed_generated_path_sentinels(sentinel_root.path());

    load_bundle_from_test_root(sentinel_root.path()).unwrap();
    assert_generated_path_sentinels_unchanged(
      sentinel_root.path(),
      &sentinels,
    );
  }

  #[cfg(any(target_os = "linux", target_os = "macos"))]
  #[test]
  fn retained_loader_preserves_exact_order_and_raw_inventory_bytes() {
    let root = tempfile::tempdir().unwrap();
    std::fs::create_dir(root.path().join("nested")).unwrap();
    let first = [0_u8, 0xff, b'\r', b'\n', 0x80];
    let second = b"no-normalization\r\n";
    std::fs::write(root.path().join("a.bin"), first).unwrap();
    std::fs::write(root.path().join("nested/raw.bin"), second).unwrap();

    let retained = load_from_test_root(
      root.path(),
      &["a.bin", "nested/raw.bin"],
      ODEN_PARENT_RETAINED_CONTRACT_FILE_LIMITS,
      |_| {},
    )
    .unwrap();
    assert_eq!(retained.files.len(), 2);
    assert_eq!(retained.files[0].path, "a.bin");
    assert_eq!(retained.files[0].bytes, first);
    assert_eq!(retained.files[1].path, "nested/raw.bin");
    assert_eq!(retained.files[1].bytes, second);

    let inventory = retained.inventory();
    assert_eq!(inventory.rows()[0].path(), "a.bin");
    assert_eq!(
      inventory.rows()[0].byte_digest().as_str(),
      raw_sha256_digest(&first).as_str()
    );
    assert_eq!(inventory.rows()[1].path(), "nested/raw.bin");
    assert_eq!(
      inventory.rows()[1].byte_digest().as_str(),
      raw_sha256_digest(second).as_str()
    );
  }

  #[cfg(any(target_os = "linux", target_os = "macos"))]
  #[test]
  fn retained_loader_requires_exact_raw_case_for_every_path_component() {
    let directory_root = tempfile::tempdir().unwrap();
    std::fs::create_dir(directory_root.path().join("CaseDir")).unwrap();
    std::fs::write(
      directory_root.path().join("CaseDir/member.json"),
      b"directory case\n",
    )
    .unwrap();
    let directory_result = load_from_test_root(
      directory_root.path(),
      &["casedir/member.json"],
      ODEN_PARENT_RETAINED_CONTRACT_FILE_LIMITS,
      |_| {},
    );
    assert!(matches!(
      directory_result,
      Err(OdenParentRetainedContractError::ExactNameObservation {
        source,
        ..
      }) if matches!(
        *source,
        OdenParentDirectRepoSourceError::InvalidExactComponentCount {
          ref component,
          matches: 0,
          ..
        } if component == "casedir"
      )
    ));

    let file_root = tempfile::tempdir().unwrap();
    std::fs::create_dir(file_root.path().join("exact")).unwrap();
    std::fs::write(
      file_root.path().join("exact/Member.json"),
      b"file case\n",
    )
    .unwrap();
    let file_result = load_from_test_root(
      file_root.path(),
      &["exact/member.json"],
      ODEN_PARENT_RETAINED_CONTRACT_FILE_LIMITS,
      |_| {},
    );
    assert!(matches!(
      file_result,
      Err(OdenParentRetainedContractError::ExactNameObservation {
        source,
        ..
      }) if matches!(
        *source,
        OdenParentDirectRepoSourceError::InvalidExactComponentCount {
          ref component,
          matches: 0,
          ..
        } if component == "member.json"
      )
    ));
  }

  #[cfg(any(target_os = "linux", target_os = "macos"))]
  #[test]
  fn retained_loader_validates_the_complete_list_before_opening_root() {
    let root_opened = Cell::new(false);
    let assert_prevalidated = |paths: &[&str]| {
      root_opened.set(false);
      let result = load_retained_contract_files_with(
        paths,
        ODEN_PARENT_RETAINED_CONTRACT_FILE_LIMITS,
        || {
          root_opened.set(true);
          RetainedRepositoryRoot::open_current()
        },
        |_| {},
      );
      assert!(result.is_err());
      assert!(!root_opened.get());
    };

    assert_prevalidated(&[]);
    assert_prevalidated(&["b", "a"]);
    assert_prevalidated(&["a", "a"]);
    assert_prevalidated(&["ok", "../escape"]);
    assert_prevalidated(&[ODEN_PARENT_GENERATED_JSON_PATH]);
    assert_prevalidated(&[ODEN_PARENT_GENERATED_RUST_PATH]);
    assert_prevalidated(&[ODEN_PARENT_TARGET_POLICY_GENERATED_RUST_PATH]);
    assert_prevalidated(&[
      "GENERATED/CAPSEC/REV2/FILESYSTEM-PARENT-STANDALONE-ALLOWLIST.JSON",
    ]);
    assert_prevalidated(&[
      "FORK/DENO/CLI/LIB/STANDALONE/ODEN_PARENT_ALLOWLIST_GENERATED.RS",
    ]);
    assert_prevalidated(&[
      "FORK/DENO/CLI/LIB/STANDALONE/ODEN_PARENT_TARGET_POLICY_GENERATED.RS",
    ]);
    assert_prevalidated(&["unicode/\u{212a}.txt"]);

    let oversized_component = "a".repeat(256);
    assert_prevalidated(&[&oversized_component]);
    let oversized_path = format!("{}a", "a/".repeat(2_048));
    assert_eq!(oversized_path.len(), 4_097);
    assert_prevalidated(&[&oversized_path]);
  }

  #[cfg(any(target_os = "linux", target_os = "macos"))]
  #[test]
  fn retained_loader_refuses_missing_empty_oversized_and_nonregular_members() {
    let root = tempfile::tempdir().unwrap();

    let missing = load_from_test_root(
      root.path(),
      &["missing"],
      ODEN_PARENT_RETAINED_CONTRACT_FILE_LIMITS,
      |_| {},
    );
    assert!(matches!(
      missing,
      Err(OdenParentRetainedContractError::ExactNameObservation {
        ref path,
        ..
      }) if path == "missing"
    ));

    std::fs::write(root.path().join("empty"), []).unwrap();
    let empty = load_from_test_root(
      root.path(),
      &["empty"],
      ODEN_PARENT_RETAINED_CONTRACT_FILE_LIMITS,
      |_| {},
    );
    assert!(matches!(
      empty,
      Err(OdenParentRetainedContractError::InvalidFileSize {
        size: 0,
        ..
      })
    ));

    let oversized_path = root.path().join("oversized");
    File::create(&oversized_path)
      .unwrap()
      .set_len(ODEN_PARENT_CONTRACT_FILE_MAX_BYTES + 1)
      .unwrap();
    let oversized = load_from_test_root(
      root.path(),
      &["oversized"],
      ODEN_PARENT_RETAINED_CONTRACT_FILE_LIMITS,
      |_| {},
    );
    assert!(matches!(
      oversized,
      Err(OdenParentRetainedContractError::InvalidFileSize { .. })
    ));

    std::fs::create_dir(root.path().join("directory")).unwrap();
    let directory = load_from_test_root(
      root.path(),
      &["directory"],
      ODEN_PARENT_RETAINED_CONTRACT_FILE_LIMITS,
      |_| {},
    );
    assert!(matches!(
      directory,
      Err(OdenParentRetainedContractError::NotRegularFile(_))
    ));

    let fifo_path = root.path().join("fifo");
    let fifo = CString::new(fifo_path.as_os_str().as_bytes()).unwrap();
    // SAFETY: `fifo` is a live NUL-terminated path and the mode is valid.
    assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
    let fifo = load_from_test_root(
      root.path(),
      &["fifo"],
      ODEN_PARENT_RETAINED_CONTRACT_FILE_LIMITS,
      |_| {},
    );
    assert!(matches!(
      fifo,
      Err(OdenParentRetainedContractError::NotRegularFile(_))
    ));
  }

  #[cfg(any(target_os = "linux", target_os = "macos"))]
  #[test]
  fn retained_loader_refuses_final_and_intermediate_symlinks_and_hardlinks() {
    use std::os::unix::fs::symlink;

    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("target"), b"target").unwrap();
    symlink("target", root.path().join("final-link")).unwrap();
    let final_link = load_from_test_root(
      root.path(),
      &["final-link"],
      ODEN_PARENT_RETAINED_CONTRACT_FILE_LIMITS,
      |_| {},
    );
    assert!(matches!(
      final_link,
      Err(OdenParentRetainedContractError::OpenComponent { .. })
    ));

    std::fs::create_dir(root.path().join("real-dir")).unwrap();
    std::fs::write(root.path().join("real-dir/member"), b"member").unwrap();
    symlink("real-dir", root.path().join("dir-link")).unwrap();
    let intermediate_link = load_from_test_root(
      root.path(),
      &["dir-link/member"],
      ODEN_PARENT_RETAINED_CONTRACT_FILE_LIMITS,
      |_| {},
    );
    assert!(matches!(
      intermediate_link,
      Err(OdenParentRetainedContractError::OpenComponent { .. })
    ));

    std::fs::hard_link(root.path().join("target"), root.path().join("alias"))
      .unwrap();
    let hard_link = load_from_test_root(
      root.path(),
      &["alias"],
      ODEN_PARENT_RETAINED_CONTRACT_FILE_LIMITS,
      |_| {},
    );
    assert!(matches!(
      hard_link,
      Err(OdenParentRetainedContractError::InvalidLinkCount {
        links: 2,
        ..
      })
    ));
  }

  #[cfg(any(target_os = "linux", target_os = "macos"))]
  #[test]
  fn retained_loader_enforces_the_aggregate_limit_before_allocation() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("a"), b"aa").unwrap();
    std::fs::write(root.path().join("b"), b"bb").unwrap();
    let result = load_from_test_root(
      root.path(),
      &["a", "b"],
      RetainedContractFileLimits {
        file_bytes: 4,
        inventory_bytes: 3,
      },
      |_| {},
    );
    assert!(matches!(
      result,
      Err(OdenParentRetainedContractError::InventoryTooLarge {
        size: 4,
        limit: 3,
        ..
      })
    ));
  }

  #[cfg(any(target_os = "linux", target_os = "macos"))]
  #[test]
  fn retained_loader_detects_post_read_file_root_and_intermediate_changes() {
    let file_root = tempfile::tempdir().unwrap();
    let file_path = file_root.path().join("member");
    std::fs::write(&file_path, b"member").unwrap();
    let file_mode = file_path.metadata().unwrap().permissions().mode();
    let file_result = load_from_test_root(
      file_root.path(),
      &["member"],
      ODEN_PARENT_RETAINED_CONTRACT_FILE_LIMITS,
      |_| {
        std::fs::write(&file_path, b"change").unwrap();
        std::fs::set_permissions(
          &file_path,
          std::fs::Permissions::from_mode(file_mode ^ 0o100),
        )
        .unwrap();
      },
    );
    std::fs::write(&file_path, b"member").unwrap();
    std::fs::set_permissions(
      &file_path,
      std::fs::Permissions::from_mode(file_mode),
    )
    .unwrap();
    assert!(matches!(
      file_result,
      Err(OdenParentRetainedContractError::DescriptorChanged {
        ref descriptor,
        ..
      }) if descriptor == "member"
    ));

    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("member"), b"member").unwrap();
    let root_mode = root.path().metadata().unwrap().permissions().mode();
    let root_result = load_from_test_root(
      root.path(),
      &["member"],
      ODEN_PARENT_RETAINED_CONTRACT_FILE_LIMITS,
      |_| {
        std::fs::set_permissions(
          root.path(),
          std::fs::Permissions::from_mode(root_mode ^ 0o100),
        )
        .unwrap();
      },
    );
    std::fs::set_permissions(
      root.path(),
      std::fs::Permissions::from_mode(root_mode),
    )
    .unwrap();
    assert!(matches!(
      root_result,
      Err(OdenParentRetainedContractError::DescriptorChanged {
        ref descriptor,
        ..
      }) if descriptor == "."
    ));

    let intermediate_root = tempfile::tempdir().unwrap();
    let intermediate = intermediate_root.path().join("dir");
    std::fs::create_dir(&intermediate).unwrap();
    std::fs::write(intermediate.join("member"), b"member").unwrap();
    let intermediate_mode = intermediate.metadata().unwrap().permissions().mode();
    let intermediate_result = load_from_test_root(
      intermediate_root.path(),
      &["dir/member"],
      ODEN_PARENT_RETAINED_CONTRACT_FILE_LIMITS,
      |_| {
        std::fs::set_permissions(
          &intermediate,
          std::fs::Permissions::from_mode(intermediate_mode ^ 0o100),
        )
        .unwrap();
      },
    );
    std::fs::set_permissions(
      &intermediate,
      std::fs::Permissions::from_mode(intermediate_mode),
    )
    .unwrap();
    assert!(matches!(
      intermediate_result,
      Err(OdenParentRetainedContractError::DescriptorChanged {
        ref descriptor,
        ..
      }) if descriptor == "dir"
    ));
  }

  fn assert_closed_sorted_literals(paths: &[&str], expected_len: usize) {
    assert_eq!(paths.len(), expected_len);

    for path in paths {
      assert!(!path.is_empty());
      assert!(path.is_ascii());
      assert!(!path.starts_with('/'));
      assert!(!path.ends_with('/'));
      assert!(!path.contains('\\'));
      assert!(path.len() <= ODEN_PARENT_CONTRACT_PATH_MAX_BYTES);
      assert!(!path.split('/').any(|part| {
        part.is_empty() || part == "." || part == ".."
      }));
      assert!(path
        .split('/')
        .all(|part| part.len() <= ODEN_PARENT_CONTRACT_COMPONENT_MAX_BYTES));
      assert!(!ODEN_PARENT_GENERATED_PATHS
        .iter()
        .any(|generated_path| path.eq_ignore_ascii_case(generated_path)));
    }

    for pair in paths.windows(2) {
      assert!(pair[0].as_bytes() < pair[1].as_bytes());
    }
  }

  fn assert_handwritten_rust_authorities(paths: &[&str]) {
    assert!(paths.contains(
      &"fork/deno/cli/lib/standalone/oden_parent_allowlist.rs"
    ));
    assert!(paths.contains(
      &"fork/deno/cli/standalone/oden_parent_allowlist.rs"
    ));
  }
}

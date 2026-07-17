// Copyright 2018-2026 the Deno authors. MIT license.

// @ref LLP 0019#frozen-parent-standalone-allowlist-and-byte-graph [implements] —
// These generator-side slices freeze the exact capture, source-closure, and
// release contract memberships and a dormant descriptor-anchored retained-file
// loader. The build-metadata definition, candidate codec, and an uncalled pure
// in-memory allowlist compositor now exist, while generate/check execution and
// all three generated outputs remain absent, so neither reserved mode gains
// authority or an output.

#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::ffi::CString;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::fs::File;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::io::Read;
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
#[cfg(test)]
use deno_lib::standalone::oden_parent_allowlist::ODEN_PARENT_GENERATED_JSON_PATH;
#[cfg(any(test, target_os = "linux", target_os = "macos"))]
use deno_lib::standalone::oden_parent_allowlist::ODEN_PARENT_GENERATED_PATHS;
#[cfg(test)]
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
// Decode only the compile-time role shape. Even eligible rows remain pure,
// output-free refusals until the separate handler and admission authority exist.
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
/// The complete reviewed membership is fixed and all 32 definition paths now
/// exist. Retained loading and the uncalled in-memory candidate compositor
/// cannot authorize an allowlist; the absent generator/checker and mode
/// handlers remain separate gates.
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
  "schemas/release/release-metadata.schema.json",
  "schemas/release/release-signing.schema.json",
  "schemas/release/rustsec-audit.schema.json",
  "schemas/release/third-party-components.schema.json",
  "schemas/release/third-party-notices-approval.schema.json",
  "schemas/release/third-party-notices-header.schema.json",
  "scripts/install.sh",
  "scripts/release/build-artifact.ts",
  "scripts/release/checksums.ts",
  "scripts/release/engine-provenance.ts",
  "scripts/release/metadata.ts",
  "scripts/release/preflight.ts",
  "scripts/release/rust-audit.ts",
  "scripts/release/signing.ts",
  "scripts/release/third-party-notices.ts",
  "scripts/verify-fork.sh",
  "security/rustsec-ignores.json",
  "src/release.ts",
  "third_party/components.json",
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

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[derive(Debug, thiserror::Error)]
enum OdenParentDirectRepoSourceError {
  #[error("retained-root descriptor operation failed: {0}")]
  RetainedDescriptor(#[from] OdenParentRetainedContractError),
  #[error("invalid direct repository file URL: {0}")]
  InvalidFileUrl(&'static str),
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
  #[error("retained descriptor changed while reading direct repository source {member}: {descriptor}")]
  DescriptorChanged { member: String, descriptor: String },
}

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
/// locking. There is no production caller. This wrapper opens the root only
/// when observation begins, not before graph build; later binary integration
/// must acquire and retain the root before graph construction and bind the
/// graph-owned Arc separately.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[allow(dead_code)]
#[derive(Debug)]
struct OdenParentDirectRepoSourceCandidate {
  key: OdenParentRepoVfsKey,
  specifier: ModuleSpecifier,
  original_bytes: Arc<[u8]>,
  executable: bool,
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
#[derive(Debug, PartialEq, Eq)]
struct OdenParentAllowlistCandidateOutput {
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
    let mut matches = 0_usize;
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
        matches = matches.saturating_add(1);
      }
    }
    Ok(matches)
  })();
  let close_result = stream.close(directory_path);
  let matches = match scan_result {
    Ok(matches) => matches,
    Err(error) => {
      let _ = close_result;
      return Err(error);
    }
  };
  close_result?;
  if matches != 1 {
    return Err(
      OdenParentDirectRepoSourceError::InvalidExactComponentCount {
        directory: directory_path.to_string(),
        component: component.to_string(),
        matches,
      },
    );
  }
  Ok(())
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
fn observe_oden_parent_direct_repo_source_candidate(
  specifier: &ModuleSpecifier,
  original_bytes: Arc<[u8]>,
) -> Result<OdenParentDirectRepoSourceCandidate, OdenParentDirectRepoSourceError>
{
  let root = RetainedRepositoryRoot::open_current()?;
  let read =
    read_oden_parent_direct_repo_source(&root, specifier, original_bytes)?;
  finish_oden_parent_direct_repo_source(read)
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
  let mut current_directory = root.descriptor.as_raw_fd();
  let mut held_directories = Vec::with_capacity(directory_components.len());
  let mut directory_path = String::new();
  for component in directory_components {
    if !directory_path.is_empty() {
      directory_path.push('/');
    }
    directory_path.push_str(component);
    let descriptor =
      open_component(current_directory, path, component, directory_flags)?;
    let snapshot = DescriptorSnapshot::capture(&descriptor, &directory_path)?;
    if !snapshot.is_directory() {
      return Err(
        OdenParentRetainedContractError::ComponentNotDirectory(
          directory_path,
        ),
      );
    }
    current_directory = descriptor.as_raw_fd();
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
  let mut descriptor =
    open_component(current_directory, path, file_name, file_flags)?;
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
fn load_retained_contract_files_with<O, H>(
  paths: &[&str],
  limits: RetainedContractFileLimits,
  open_root: O,
  mut post_read_hook: H,
) -> Result<RetainedContractFiles, OdenParentRetainedContractError>
where
  O: FnOnce() -> Result<RetainedRepositoryRoot, OdenParentRetainedContractError>,
  H: FnMut(&str),
{
  // Validate every literal before opening `.` or any member path.
  validate_retained_contract_paths(paths)?;
  let root = open_root()?;
  let mut aggregate_bytes = 0_u64;
  let mut files = Vec::with_capacity(paths.len());
  for path in paths {
    // A member's owned bytes are accepted only after its retained descriptor
    // chain is stable. Multi-member tree authentication and reconciliation
    // remain separate downstream gates; this local projection is not a
    // coherent repository snapshot.
    files.push(load_one_retained_contract_file(
      &root,
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

/// Dormant Linux/macOS-only loader for one already reviewed literal path
/// inventory. Its returned bytes are not source authentication or authority;
/// the uncalled candidate compositor and absent generator/checker and mode
/// handlers keep both modes fail-closed.
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

/// Dormant, output-free composition of the exact three retained inventories.
/// Its owned bytes and inventory rows confer no repository, build, or release
/// authority and are not connected to either raw dispatch mode.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[allow(dead_code)]
fn load_retained_contract_byte_bundle(
) -> Result<RetainedContractByteBundle, OdenParentRetainedContractError> {
  load_retained_contract_byte_bundle_with(
    RetainedRepositoryRoot::open_current,
  )
}

// @ref LLP 0019#frozen-parent-standalone-allowlist-and-byte-graph [implements] —
// Compose only unauthenticated candidate bytes; mode admission and output
// ownership remain separate absent authorities.
/// Purely composes the retained inventory projections with already-typed
/// compiler projections. This function performs no I/O, has no production
/// caller, and is not connected to either raw-dispatch mode.
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

  Ok(OdenParentAllowlistCandidateOutput {
    json_file: allowlist.render_json_file()?,
    rust_module: allowlist.render_rust_module()?,
  })
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
    assert_closed_sorted_literals(ODEN_PARENT_RELEASE_CONTRACT_PATHS, 32);
    assert_handwritten_rust_authorities(ODEN_PARENT_RELEASE_CONTRACT_PATHS);
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
  fn candidate_configuration() -> OdenParentStandaloneConfiguration {
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
      &UnstableConfig::default(),
      &OtelConfig::default(),
    )
    .unwrap()
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
        Err(OdenParentRetainedContractError::OpenComponent {
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
      Err(OdenParentRetainedContractError::OpenComponent { .. })
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

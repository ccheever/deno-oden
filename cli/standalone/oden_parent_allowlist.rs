// Copyright 2018-2026 the Deno authors. MIT license.

// @ref LLP 0019#frozen-parent-standalone-allowlist-and-byte-graph [implements] —
// These generator-side slices freeze the exact capture and source-closure
// contract memberships and a dormant descriptor-anchored retained-file
// loader. Release membership, allowlist construction, generate/check
// execution, and both generated outputs remain absent, so neither reserved
// mode gains authority or an output path.

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
use std::os::fd::RawFd;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::os::unix::ffi::OsStrExt;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::path::Path;

#[cfg(any(target_os = "linux", target_os = "macos"))]
use deno_lib::standalone::oden_parent_allowlist::ContractFile;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use deno_lib::standalone::oden_parent_allowlist::ContractInventory;
#[cfg(any(test, target_os = "linux", target_os = "macos"))]
use deno_lib::standalone::oden_parent_allowlist::ODEN_PARENT_GENERATED_JSON_PATH;
#[cfg(any(test, target_os = "linux", target_os = "macos"))]
use deno_lib::standalone::oden_parent_allowlist::ODEN_PARENT_GENERATED_RUST_PATH;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use deno_lib::standalone::oden_parent_allowlist::OdenParentAllowlistError;

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
  #[error("retained repository root is not a directory")]
  RootNotDirectory,
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
    let (modified_seconds, modified_nanoseconds) =
      (stat.st_mtime as i64, stat.st_mtime_nsec as i64);
    let (changed_seconds, changed_nanoseconds) =
      (stat.st_ctime as i64, stat.st_ctime_nsec as i64);

    Ok(Self {
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
    })
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
  descriptor: File,
  snapshot: DescriptorSnapshot,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
impl RetainedRepositoryRoot {
  fn open_current() -> Result<Self, OdenParentRetainedContractError> {
    Self::open_path(Path::new("."))
  }

  fn open_path(path: &Path) -> Result<Self, OdenParentRetainedContractError> {
    let path = CString::new(path.as_os_str().as_bytes()).map_err(|_| {
      OdenParentRetainedContractError::OpenRoot {
        source: std::io::Error::from(std::io::ErrorKind::InvalidInput),
      }
    })?;
    let flags = libc::O_RDONLY
      | libc::O_DIRECTORY
      | libc::O_NOFOLLOW
      | libc::O_CLOEXEC;
    // SAFETY: `path` is NUL-terminated for the call; successful `open`
    // returns one new descriptor owned by this function.
    let raw_descriptor = unsafe { libc::open(path.as_ptr(), flags) };
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
    Ok(Self {
      descriptor,
      snapshot,
    })
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
    if path.eq_ignore_ascii_case(ODEN_PARENT_GENERATED_JSON_PATH)
      || path.eq_ignore_ascii_case(ODEN_PARENT_GENERATED_RUST_PATH)
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
/// the absent release list and constructor keep both modes fail-closed.
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

#[cfg(test)]
mod tests {
  use super::*;

  #[cfg(any(target_os = "linux", target_os = "macos"))]
  use std::cell::Cell;
  #[cfg(any(target_os = "linux", target_os = "macos"))]
  use std::os::unix::fs::PermissionsExt;

  #[cfg(any(target_os = "linux", target_os = "macos"))]
  use deno_lib::standalone::oden_parent_allowlist::raw_sha256_digest;

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
      || RetainedRepositoryRoot::open_path(root),
      post_read_hook,
    )
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
    assert_prevalidated(&[
      "GENERATED/CAPSEC/REV2/FILESYSTEM-PARENT-STANDALONE-ALLOWLIST.JSON",
    ]);
    assert_prevalidated(&[
      "FORK/DENO/CLI/LIB/STANDALONE/ODEN_PARENT_ALLOWLIST_GENERATED.RS",
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
      assert_ne!(*path, ODEN_PARENT_GENERATED_JSON_PATH);
      assert_ne!(*path, ODEN_PARENT_GENERATED_RUST_PATH);
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

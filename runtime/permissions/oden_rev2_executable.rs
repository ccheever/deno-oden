// Copyright 2018-2026 the Deno authors. MIT license.

//! Immutable native images derived from C03-retained executable descriptors.
//!
//! This module is deliberately below process-spawn wiring. It installs an
//! object that a later C04 spawn commit can consume without reopening the
//! authenticated canonical path.
//!
//! @ref LLP 0019#executables-and-native-libraries [implements] -- Executable
//! bytes are copied only from the retained authorized object and made
//! immutable before V8.
//! @ref LLP 0019#armed-identity-and-exact-linked-bindings [implements] -- The
//! staged image is rehashed against C03's exact canonical content identity;
//! failure never falls back to pathname execution.
//! @ref LLP 0019#c04-immutable-execution-installation-and-entry [implements]
//! -- Installation is bounded, target-specific, and complete before V8.

#![allow(
  dead_code,
  reason = "the first C04 slice installs immutable images before the later process-spawn wiring consumes these narrow getters"
)]

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use sha2::Digest;
use sha2::Sha256;
use std::fs::File;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;

#[cfg(unix)]
use std::os::fd::AsRawFd;
#[cfg(unix)]
use std::os::fd::FromRawFd;
#[cfg(unix)]
use std::os::unix::fs::FileExt;

use crate::oden_rev2_policy::OdenRev2RetainedObject;
use crate::rev2::PrincipalRef;
use crate::rev2_registry_generated::REV2_RUNTIME_EXECUTABLE_MAX_AGGREGATE_BYTES;
use crate::rev2_registry_generated::REV2_RUNTIME_EXECUTABLE_MAX_IMAGE_BYTES;
use crate::rev2_registry_generated::REV2_RUNTIME_EXECUTABLE_MAX_IMAGES;

const STAGE_ERROR_PREFIX: &str = "OD-CAP-REV2-EXECUTABLE-STAGE";
const COPY_BUFFER_BYTES: usize = 64 * 1024;
// C04 provisional limits come from the reviewed generated runtime contract.
// Per-target limits still replace these before a target may advertise Rev2;
// until then exceeding any generated bound refuses arming.
const MAX_INSTALLED_EXECUTABLES: usize = REV2_RUNTIME_EXECUTABLE_MAX_IMAGES;
const MAX_EXECUTABLE_IMAGE_BYTES: u64 =
  REV2_RUNTIME_EXECUTABLE_MAX_IMAGE_BYTES as u64;
const MAX_EXECUTABLE_AGGREGATE_BYTES: u64 =
  REV2_RUNTIME_EXECUTABLE_MAX_AGGREGATE_BYTES as u64;

struct BoundedRetainedExecutable<'a> {
  object: &'a OdenRev2RetainedObject,
  byte_len: u64,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
enum InstallationState {
  #[default]
  Fresh,
  Failed,
  Installed,
}

#[derive(Clone, Debug, Default)]
pub(crate) struct OdenRev2InstalledExecutableContext {
  state: InstallationState,
  executables: Arc<[OdenRev2InstalledExecutable]>,
}

impl OdenRev2InstalledExecutableContext {
  pub(crate) fn empty() -> Self {
    Self::default()
  }

  pub(crate) fn install_once(
    &mut self,
    retained: &[OdenRev2RetainedObject],
    control_root: &Path,
  ) -> Result<(), String> {
    if self.state != InstallationState::Fresh {
      return Err(format!("{STAGE_ERROR_PREFIX}-ALREADY-INSTALLED"));
    }
    // Failure is terminal. Mark it before touching host state so every early
    // return leaves a context that cannot be mistaken for a successful empty
    // installation or retried against changed host state.
    self.state = InstallationState::Failed;
    let _ = control_root;
    let executable_objects = retained
      .iter()
      .filter(|object| object.role().is_some())
      .collect::<Vec<_>>();
    if executable_objects.is_empty() {
      self.state = InstallationState::Installed;
      return Ok(());
    }

    let executable_objects = validate_install_bounds(&executable_objects)?;

    #[cfg(target_os = "linux")]
    let executables = install_linux(&executable_objects)?;
    #[cfg(target_os = "macos")]
    let executables = install_macos(&executable_objects, control_root)?;
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let executables = {
      return Err(format!("{STAGE_ERROR_PREFIX}-PLATFORM-UNSUPPORTED"));
    };

    self.executables = executables.into();
    self.state = InstallationState::Installed;
    Ok(())
  }

  pub(crate) fn as_slice(&self) -> &[OdenRev2InstalledExecutable] {
    &self.executables
  }

  pub(crate) fn is_installed(&self) -> bool {
    self.state == InstallationState::Installed
  }

  pub(crate) fn by_binding_id(
    &self,
    binding_id: &str,
  ) -> Option<&OdenRev2InstalledExecutable> {
    self
      .executables
      .iter()
      .find(|executable| executable.binding_id == binding_id)
  }
}

#[derive(Clone, Debug)]
pub(crate) struct OdenRev2InstalledExecutable {
  binding_id: String,
  source_id: String,
  role: String,
  principal: Option<PrincipalRef>,
  canonical_path: PathBuf,
  object_identity: String,
  canonical_content_identity: String,
  provenance_digest: String,
  byte_len: u64,
  image: Arc<OdenRev2ImmutableExecutableImage>,
}

impl OdenRev2InstalledExecutable {
  pub(crate) fn binding_id(&self) -> &str {
    &self.binding_id
  }

  pub(crate) fn source_id(&self) -> &str {
    &self.source_id
  }

  pub(crate) fn role(&self) -> &str {
    &self.role
  }

  pub(crate) fn principal(&self) -> Option<&PrincipalRef> {
    self.principal.as_ref()
  }

  pub(crate) fn canonical_path(&self) -> &Path {
    &self.canonical_path
  }

  pub(crate) fn object_identity(&self) -> &str {
    &self.object_identity
  }

  pub(crate) fn canonical_content_identity(&self) -> &str {
    &self.canonical_content_identity
  }

  pub(crate) fn provenance_digest(&self) -> &str {
    &self.provenance_digest
  }

  pub(crate) fn byte_len(&self) -> u64 {
    self.byte_len
  }

  pub(crate) fn image(&self) -> &OdenRev2ImmutableExecutableImage {
    &self.image
  }
}

#[derive(Debug)]
pub(crate) struct OdenRev2ImmutableExecutableImage {
  inner: OdenRev2ImmutableExecutableImageInner,
}

#[derive(Debug)]
enum OdenRev2ImmutableExecutableImageInner {
  #[cfg(target_os = "linux")]
  LinuxMemfd {
    file: File,
    seals: libc::c_int,
    explicit_exec: bool,
  },
  #[cfg(target_os = "macos")]
  MacImmutablePath {
    directory: Arc<MacStagingDirectory>,
    file: File,
    path: PathBuf,
    flags: u32,
  },
}

impl OdenRev2ImmutableExecutableImage {
  pub(crate) fn file(&self) -> &File {
    match &self.inner {
      #[cfg(target_os = "linux")]
      OdenRev2ImmutableExecutableImageInner::LinuxMemfd { file, .. } => file,
      #[cfg(target_os = "macos")]
      OdenRev2ImmutableExecutableImageInner::MacImmutablePath {
        file, ..
      } => file,
    }
  }

  pub(crate) fn platform_kind(&self) -> &'static str {
    match &self.inner {
      #[cfg(target_os = "linux")]
      OdenRev2ImmutableExecutableImageInner::LinuxMemfd { .. } => {
        "linux-sealed-memfd"
      }
      #[cfg(target_os = "macos")]
      OdenRev2ImmutableExecutableImageInner::MacImmutablePath { .. } => {
        "macos-private-immutable-path"
      }
    }
  }

  #[cfg(target_os = "linux")]
  pub(crate) fn linux_seals(&self) -> libc::c_int {
    match &self.inner {
      OdenRev2ImmutableExecutableImageInner::LinuxMemfd { seals, .. } => *seals,
    }
  }

  #[cfg(target_os = "linux")]
  pub(crate) fn linux_explicit_exec(&self) -> bool {
    match &self.inner {
      OdenRev2ImmutableExecutableImageInner::LinuxMemfd {
        explicit_exec,
        ..
      } => *explicit_exec,
    }
  }

  #[cfg(target_os = "macos")]
  pub(crate) fn macos_path(&self) -> &Path {
    match &self.inner {
      OdenRev2ImmutableExecutableImageInner::MacImmutablePath {
        path, ..
      } => path,
    }
  }

  #[cfg(target_os = "macos")]
  pub(crate) fn macos_flags(&self) -> u32 {
    match &self.inner {
      OdenRev2ImmutableExecutableImageInner::MacImmutablePath {
        flags, ..
      } => *flags,
    }
  }

  #[cfg(target_os = "macos")]
  pub(crate) fn macos_directory(&self) -> &File {
    match &self.inner {
      OdenRev2ImmutableExecutableImageInner::MacImmutablePath {
        directory,
        ..
      } => &directory.file,
    }
  }
}

fn installed_metadata(
  retained: &OdenRev2RetainedObject,
  byte_len: u64,
  image: OdenRev2ImmutableExecutableImage,
) -> Result<OdenRev2InstalledExecutable, String> {
  let role = retained
    .role()
    .ok_or_else(|| format!("{STAGE_ERROR_PREFIX}-METADATA"))?;
  let canonical_content_identity = retained
    .canonical_content_identity()
    .ok_or_else(|| format!("{STAGE_ERROR_PREFIX}-METADATA"))?;
  let provenance_digest = retained
    .provenance_digest()
    .ok_or_else(|| format!("{STAGE_ERROR_PREFIX}-METADATA"))?;
  Ok(OdenRev2InstalledExecutable {
    binding_id: retained.binding_id().to_string(),
    source_id: retained.source_id().to_string(),
    role: role.to_string(),
    principal: retained.principal().cloned(),
    canonical_path: retained.canonical_path().to_path_buf(),
    object_identity: retained.object_identity().to_string(),
    canonical_content_identity: canonical_content_identity.to_string(),
    provenance_digest: provenance_digest.to_string(),
    byte_len,
    image: Arc::new(image),
  })
}

fn validate_install_bounds<'a>(
  retained: &[&'a OdenRev2RetainedObject],
) -> Result<Vec<BoundedRetainedExecutable<'a>>, String> {
  if retained.len() > MAX_INSTALLED_EXECUTABLES {
    return Err(format!("{STAGE_ERROR_PREFIX}-COUNT-BOUNDS"));
  }
  let mut total = 0_u64;
  let mut bounded = Vec::with_capacity(retained.len());
  for object in retained {
    let byte_len = object
      .file()
      .metadata()
      .map_err(|_| format!("{STAGE_ERROR_PREFIX}-SOURCE-METADATA"))?
      .len();
    if byte_len == 0 || byte_len > MAX_EXECUTABLE_IMAGE_BYTES {
      return Err(format!("{STAGE_ERROR_PREFIX}-IMAGE-BOUNDS"));
    }
    total = total
      .checked_add(byte_len)
      .ok_or_else(|| format!("{STAGE_ERROR_PREFIX}-AGGREGATE-BOUNDS"))?;
    if total > MAX_EXECUTABLE_AGGREGATE_BYTES {
      return Err(format!("{STAGE_ERROR_PREFIX}-AGGREGATE-BOUNDS"));
    }
    bounded.push(BoundedRetainedExecutable { object, byte_len });
  }
  Ok(bounded)
}

#[cfg(target_os = "linux")]
fn install_linux(
  retained: &[BoundedRetainedExecutable<'_>],
) -> Result<Vec<OdenRev2InstalledExecutable>, String> {
  use std::ffi::CString;

  let required_seals = libc::F_SEAL_WRITE
    | libc::F_SEAL_GROW
    | libc::F_SEAL_SHRINK
    | libc::F_SEAL_SEAL;
  let mut installed = Vec::with_capacity(retained.len());
  for (index, bounded) in retained.iter().enumerate() {
    let object = bounded.object;
    let expected = object
      .canonical_content_identity()
      .ok_or_else(|| format!("{STAGE_ERROR_PREFIX}-METADATA"))?;
    let name = CString::new(format!("oden-rev2-executable-{index}"))
      .map_err(|_| format!("{STAGE_ERROR_PREFIX}-MEMFD-NAME"))?;
    let (file, explicit_exec) = create_linux_memfd(&name)?;
    copy_and_verify(object.file(), &file, expected, bounded.byte_len)?;
    // SAFETY: the descriptor is valid and exclusively owned by `file` here.
    if unsafe { libc::fchmod(file.as_raw_fd(), 0o500) } != 0 {
      return Err(format!("{STAGE_ERROR_PREFIX}-MEMFD-MODE"));
    }
    // SAFETY: F_ADD_SEALS is valid for a memfd created with ALLOW_SEALING.
    if unsafe {
      libc::fcntl(file.as_raw_fd(), libc::F_ADD_SEALS, required_seals)
    } != 0
    {
      return Err(format!("{STAGE_ERROR_PREFIX}-MEMFD-SEAL"));
    }
    // SAFETY: F_GET_SEALS accepts no fourth argument and does not mutate memory.
    let seals = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GET_SEALS) };
    if seals < 0 || seals & required_seals != required_seals {
      return Err(format!("{STAGE_ERROR_PREFIX}-MEMFD-SEAL-VERIFY"));
    }
    verify_opened_digest(&file, expected, bounded.byte_len)?;
    installed.push(installed_metadata(
      object,
      bounded.byte_len,
      OdenRev2ImmutableExecutableImage {
        inner: OdenRev2ImmutableExecutableImageInner::LinuxMemfd {
          file,
          seals,
          explicit_exec,
        },
      },
    )?);
  }
  Ok(installed)
}

#[cfg(target_os = "linux")]
const LINUX_MFD_EXEC: libc::c_uint = 0x0010;

#[cfg(target_os = "linux")]
fn linux_memfd_flags(explicit_exec: bool) -> libc::c_uint {
  libc::MFD_CLOEXEC
    | libc::MFD_ALLOW_SEALING
    | if explicit_exec { LINUX_MFD_EXEC } else { 0 }
}

#[cfg(target_os = "linux")]
fn create_linux_memfd(name: &std::ffi::CStr) -> Result<(File, bool), String> {
  // MFD_EXEC was added in Linux 6.3. Request it first so kernels with the
  // executable-memfd policy distinguish this image explicitly. EINVAL is the
  // only permitted legacy-kernel fallback; every other failure refuses.
  // SAFETY: name is a valid NUL-terminated C string. A successful descriptor
  // is immediately wrapped below.
  let explicit =
    unsafe { libc::memfd_create(name.as_ptr(), linux_memfd_flags(true)) };
  if explicit >= 0 {
    // SAFETY: memfd_create returned a new owned descriptor.
    return Ok((unsafe { File::from_raw_fd(explicit) }, true));
  }
  if std::io::Error::last_os_error().raw_os_error() != Some(libc::EINVAL) {
    return Err(format!("{STAGE_ERROR_PREFIX}-MEMFD-CREATE"));
  }
  // SAFETY: same valid name; this retry removes only the flag unknown to old
  // kernels and retains CLOEXEC plus ALLOW_SEALING.
  let legacy =
    unsafe { libc::memfd_create(name.as_ptr(), linux_memfd_flags(false)) };
  if legacy < 0 {
    return Err(format!("{STAGE_ERROR_PREFIX}-MEMFD-LEGACY-CREATE"));
  }
  // SAFETY: memfd_create returned a new owned descriptor.
  Ok((unsafe { File::from_raw_fd(legacy) }, false))
}

#[cfg(target_os = "macos")]
#[derive(Debug)]
struct MacStagingDirectory {
  parent: File,
  file: File,
  parent_entry: std::ffi::CString,
  path: PathBuf,
  entries: std::sync::Mutex<Vec<std::ffi::CString>>,
}

#[cfg(target_os = "macos")]
impl MacStagingDirectory {
  fn register(&self, entry: std::ffi::CString) -> Result<(), String> {
    self
      .entries
      .lock()
      .map_err(|_| format!("{STAGE_ERROR_PREFIX}-MACOS-STAGING-STATE"))?
      .push(entry);
    Ok(())
  }

  fn seal(&self) -> Result<u32, String> {
    use std::os::unix::fs::MetadataExt;

    // SAFETY: `file` owns a live directory descriptor.
    if unsafe { libc::fchmod(self.file.as_raw_fd(), 0o700) } != 0 {
      return Err(format!("{STAGE_ERROR_PREFIX}-MACOS-DIRECTORY-MODE"));
    }
    // SAFETY: fchflags operates on the retained directory descriptor.
    if unsafe { libc::fchflags(self.file.as_raw_fd(), libc::UF_IMMUTABLE) } != 0
    {
      return Err(format!("{STAGE_ERROR_PREFIX}-MACOS-DIRECTORY-IMMUTABLE"));
    }
    let flags = macos_file_flags(&self.file)?;
    let metadata = self
      .file
      .metadata()
      .map_err(|_| format!("{STAGE_ERROR_PREFIX}-MACOS-DIRECTORY-METADATA"))?;
    if flags & libc::UF_IMMUTABLE == 0 || metadata.mode() & 0o777 != 0o700 {
      return Err(format!(
        "{STAGE_ERROR_PREFIX}-MACOS-DIRECTORY-IMMUTABLE-VERIFY"
      ));
    }
    Ok(flags)
  }
}

#[cfg(target_os = "macos")]
impl Drop for MacStagingDirectory {
  fn drop(&mut self) {
    // Best-effort teardown for tests and future orderly runtime shutdown. The
    // authenticated parent must still treat an uncleared stage as a cleanup
    // failure; this destructor never weakens install-time verification.
    // SAFETY: descriptors remain owned by this value throughout Drop.
    unsafe {
      libc::fchflags(self.file.as_raw_fd(), 0);
    }
    if let Ok(entries) = self.entries.lock() {
      for entry in entries.iter() {
        // SAFETY: entry is a retained single-component CString and the
        // directory descriptor is live. O_NOFOLLOW_ANY prevents substitution.
        let raw = unsafe {
          libc::openat(
            self.file.as_raw_fd(),
            entry.as_ptr(),
            libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW_ANY,
          )
        };
        if raw >= 0 {
          // SAFETY: openat returned a new owned descriptor.
          let file = unsafe { File::from_raw_fd(raw) };
          // SAFETY: the descriptor is live; failure is best-effort in Drop.
          unsafe {
            libc::fchflags(file.as_raw_fd(), 0);
          }
        }
        // SAFETY: descriptor/name are valid and this is not a directory.
        unsafe {
          libc::unlinkat(self.file.as_raw_fd(), entry.as_ptr(), 0);
        }
      }
    }
    // SAFETY: parent and entry identify the exact directory created by this
    // value. AT_REMOVEDIR refuses a non-directory replacement.
    unsafe {
      libc::unlinkat(
        self.parent.as_raw_fd(),
        self.parent_entry.as_ptr(),
        libc::AT_REMOVEDIR,
      );
    }
  }
}

#[cfg(target_os = "macos")]
fn install_macos(
  retained: &[BoundedRetainedExecutable<'_>],
  control_root: &Path,
) -> Result<Vec<OdenRev2InstalledExecutable>, String> {
  let directory = create_macos_staging_directory(control_root)?;
  let mut installed = Vec::with_capacity(retained.len());
  for (index, bounded) in retained.iter().enumerate() {
    installed.push(install_macos_file(directory.clone(), bounded, index)?);
  }
  directory.seal()?;
  Ok(installed)
}

#[cfg(target_os = "macos")]
fn create_macos_staging_directory(
  control_root: &Path,
) -> Result<Arc<MacStagingDirectory>, String> {
  use std::ffi::CString;
  use std::os::unix::ffi::OsStrExt;
  use std::os::unix::fs::MetadataExt;
  use std::sync::atomic::AtomicU64;
  use std::sync::atomic::Ordering;

  static NEXT_STAGE: AtomicU64 = AtomicU64::new(0);

  if !control_root.is_absolute() {
    return Err(format!("{STAGE_ERROR_PREFIX}-MACOS-CONTROL-ROOT"));
  }
  let control_root_c = CString::new(control_root.as_os_str().as_bytes())
    .map_err(|_| format!("{STAGE_ERROR_PREFIX}-MACOS-CONTROL-ROOT"))?;
  // SAFETY: control_root is an absolute NUL-terminated path. O_NOFOLLOW_ANY
  // rejects symlinks in every component before returning a descriptor.
  let parent_raw = unsafe {
    libc::open(
      control_root_c.as_ptr(),
      libc::O_RDONLY
        | libc::O_CLOEXEC
        | libc::O_DIRECTORY
        | libc::O_NOFOLLOW_ANY,
    )
  };
  if parent_raw < 0 {
    return Err(format!("{STAGE_ERROR_PREFIX}-MACOS-CONTROL-ROOT"));
  }
  // SAFETY: open returned a new owned descriptor.
  let parent = unsafe { File::from_raw_fd(parent_raw) };
  let parent_metadata = parent
    .metadata()
    .map_err(|_| format!("{STAGE_ERROR_PREFIX}-MACOS-CONTROL-ROOT"))?;
  if !parent_metadata.is_dir() || parent_metadata.mode() & 0o077 != 0 {
    return Err(format!("{STAGE_ERROR_PREFIX}-MACOS-CONTROL-ROOT"));
  }

  for _ in 0..64 {
    let serial = NEXT_STAGE.fetch_add(1, Ordering::Relaxed);
    let entry =
      CString::new(format!(".oden-rev2-exec-{}-{serial}", std::process::id()))
        .map_err(|_| format!("{STAGE_ERROR_PREFIX}-MACOS-DIRECTORY-NAME"))?;
    // SAFETY: parent is a live directory descriptor and entry is one valid
    // NUL-terminated path component. mkdirat is atomic with respect to names.
    let created =
      unsafe { libc::mkdirat(parent.as_raw_fd(), entry.as_ptr(), 0o700) };
    if created != 0 {
      if std::io::Error::last_os_error().kind()
        == std::io::ErrorKind::AlreadyExists
      {
        continue;
      }
      return Err(format!("{STAGE_ERROR_PREFIX}-MACOS-DIRECTORY-CREATE"));
    }
    // SAFETY: openat is anchored to the retained parent; O_NOFOLLOW_ANY
    // rejects a substituted link in any traversed component.
    let raw = unsafe {
      libc::openat(
        parent.as_raw_fd(),
        entry.as_ptr(),
        libc::O_RDONLY
          | libc::O_CLOEXEC
          | libc::O_DIRECTORY
          | libc::O_NOFOLLOW_ANY,
      )
    };
    if raw < 0 {
      // SAFETY: remove only the directory entry just created above.
      unsafe {
        libc::unlinkat(parent.as_raw_fd(), entry.as_ptr(), libc::AT_REMOVEDIR);
      }
      return Err(format!("{STAGE_ERROR_PREFIX}-MACOS-DIRECTORY-OPEN"));
    }
    // SAFETY: openat returned a new owned descriptor.
    let file = unsafe { File::from_raw_fd(raw) };
    // SAFETY: file owns the exact directory descriptor opened immediately
    // above; mode changes cannot redirect to another object.
    if unsafe { libc::fchmod(file.as_raw_fd(), 0o700) } != 0 {
      // SAFETY: remove only the directory entry just created above.
      unsafe {
        libc::unlinkat(parent.as_raw_fd(), entry.as_ptr(), libc::AT_REMOVEDIR);
      }
      return Err(format!("{STAGE_ERROR_PREFIX}-MACOS-DIRECTORY-MODE"));
    }
    let path = control_root.join(
      entry
        .to_str()
        .map_err(|_| format!("{STAGE_ERROR_PREFIX}-MACOS-DIRECTORY-NAME"))?,
    );
    return Ok(Arc::new(MacStagingDirectory {
      parent,
      file,
      parent_entry: entry,
      path,
      entries: std::sync::Mutex::new(Vec::new()),
    }));
  }
  Err(format!("{STAGE_ERROR_PREFIX}-MACOS-DIRECTORY-COLLISION"))
}

#[cfg(target_os = "macos")]
fn install_macos_file(
  directory: Arc<MacStagingDirectory>,
  bounded: &BoundedRetainedExecutable<'_>,
  index: usize,
) -> Result<OdenRev2InstalledExecutable, String> {
  use std::ffi::CString;
  use std::os::unix::fs::MetadataExt;

  let retained = bounded.object;
  let expected = retained
    .canonical_content_identity()
    .ok_or_else(|| format!("{STAGE_ERROR_PREFIX}-METADATA"))?;
  let entry = CString::new(format!("image-{index}"))
    .map_err(|_| format!("{STAGE_ERROR_PREFIX}-MACOS-FILE-NAME"))?;
  // SAFETY: the directory and entry are valid. O_EXCL and O_NOFOLLOW_ANY
  // prevent replacement; only a fresh regular file can be returned.
  let raw = unsafe {
    libc::openat(
      directory.file.as_raw_fd(),
      entry.as_ptr(),
      libc::O_RDWR
        | libc::O_CREAT
        | libc::O_EXCL
        | libc::O_CLOEXEC
        | libc::O_NOFOLLOW_ANY,
      0o600,
    )
  };
  if raw < 0 {
    return Err(format!("{STAGE_ERROR_PREFIX}-MACOS-FILE-CREATE"));
  }
  // SAFETY: openat returned a new owned descriptor.
  let writable = unsafe { File::from_raw_fd(raw) };
  directory.register(entry.clone())?;
  let path = directory.path.join(
    entry
      .to_str()
      .map_err(|_| format!("{STAGE_ERROR_PREFIX}-MACOS-FILE-NAME"))?,
  );

  copy_and_verify(retained.file(), &writable, expected, bounded.byte_len)?;
  // SAFETY: writable is the retained exact destination descriptor.
  if unsafe { libc::fchmod(writable.as_raw_fd(), 0o500) } != 0 {
    return Err(format!("{STAGE_ERROR_PREFIX}-MACOS-FILE-MODE"));
  }
  // SAFETY: fchflags binds immutability to the exact staged descriptor.
  if unsafe { libc::fchflags(writable.as_raw_fd(), libc::UF_IMMUTABLE) } != 0 {
    return Err(format!("{STAGE_ERROR_PREFIX}-MACOS-FILE-IMMUTABLE"));
  }
  let flags = macos_file_flags(&writable)?;
  if flags & libc::UF_IMMUTABLE == 0 {
    return Err(format!("{STAGE_ERROR_PREFIX}-MACOS-FILE-IMMUTABLE-VERIFY"));
  }
  verify_opened_digest(&writable, expected, bounded.byte_len)?;
  let writable_metadata = writable
    .metadata()
    .map_err(|_| format!("{STAGE_ERROR_PREFIX}-MACOS-FILE-METADATA"))?;

  // Retain a read-only descriptor after sealing so later runtime code cannot
  // accidentally acquire a writable handle from the installed context.
  // SAFETY: directory/entry remain retained and immutable; no-follow rejects
  // substitution even if the filesystem violates the expected flag behavior.
  let read_raw = unsafe {
    libc::openat(
      directory.file.as_raw_fd(),
      entry.as_ptr(),
      libc::O_RDONLY | libc::O_CLOEXEC | libc::O_NOFOLLOW_ANY,
    )
  };
  if read_raw < 0 {
    return Err(format!("{STAGE_ERROR_PREFIX}-MACOS-FILE-REOPEN"));
  }
  // SAFETY: openat returned a new owned descriptor.
  let file = unsafe { File::from_raw_fd(read_raw) };
  let read_metadata = file
    .metadata()
    .map_err(|_| format!("{STAGE_ERROR_PREFIX}-MACOS-FILE-METADATA"))?;
  if !read_metadata.is_file()
    || writable_metadata.dev() != read_metadata.dev()
    || writable_metadata.ino() != read_metadata.ino()
    || read_metadata.mode() & 0o777 != 0o500
  {
    return Err(format!("{STAGE_ERROR_PREFIX}-MACOS-FILE-IDENTITY"));
  }
  let read_flags = macos_file_flags(&file)?;
  if read_flags & libc::UF_IMMUTABLE == 0 {
    return Err(format!("{STAGE_ERROR_PREFIX}-MACOS-FILE-IMMUTABLE-VERIFY"));
  }
  verify_opened_digest(&file, expected, bounded.byte_len)?;
  drop(writable);

  installed_metadata(
    retained,
    bounded.byte_len,
    OdenRev2ImmutableExecutableImage {
      inner: OdenRev2ImmutableExecutableImageInner::MacImmutablePath {
        directory,
        file,
        path,
        flags: read_flags,
      },
    },
  )
}

#[cfg(target_os = "macos")]
fn macos_file_flags(file: &File) -> Result<u32, String> {
  let mut stat = std::mem::MaybeUninit::<libc::stat>::uninit();
  // SAFETY: stat points to writable storage and file owns a live descriptor.
  if unsafe { libc::fstat(file.as_raw_fd(), stat.as_mut_ptr()) } != 0 {
    return Err(format!("{STAGE_ERROR_PREFIX}-MACOS-FILE-METADATA"));
  }
  // SAFETY: successful fstat initialized the complete structure.
  Ok(unsafe { stat.assume_init() }.st_flags)
}

#[cfg(unix)]
fn copy_and_verify(
  source: &File,
  destination: &File,
  expected: &str,
  expected_len: u64,
) -> Result<(), String> {
  use std::os::unix::fs::MetadataExt;

  let before = source
    .metadata()
    .map_err(|_| format!("{STAGE_ERROR_PREFIX}-SOURCE-METADATA"))?;
  if !before.is_file() {
    return Err(format!("{STAGE_ERROR_PREFIX}-SOURCE-TYPE"));
  }
  if before.len() != expected_len
    || before.len() == 0
    || before.len() > MAX_EXECUTABLE_IMAGE_BYTES
  {
    return Err(format!("{STAGE_ERROR_PREFIX}-SOURCE-BOUNDS-RACED"));
  }
  let mut digest = Sha256::new();
  let mut buffer = [0_u8; COPY_BUFFER_BYTES];
  let mut offset = 0_u64;
  loop {
    let read = loop {
      match source.read_at(&mut buffer, offset) {
        Ok(read) => break read,
        Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
        Err(_) => return Err(format!("{STAGE_ERROR_PREFIX}-SOURCE-READ")),
      }
    };
    if read == 0 {
      break;
    }
    let next_offset = offset
      .checked_add(read as u64)
      .ok_or_else(|| format!("{STAGE_ERROR_PREFIX}-BOUNDS"))?;
    if next_offset > expected_len {
      return Err(format!("{STAGE_ERROR_PREFIX}-SOURCE-BOUNDS-RACED"));
    }
    let mut written = 0;
    while written < read {
      let write_offset = offset
        .checked_add(written as u64)
        .ok_or_else(|| format!("{STAGE_ERROR_PREFIX}-BOUNDS"))?;
      let count = loop {
        match destination.write_at(&buffer[written..read], write_offset) {
          Ok(count) => break count,
          Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
          Err(_) => {
            return Err(format!("{STAGE_ERROR_PREFIX}-DESTINATION-WRITE"));
          }
        }
      };
      if count == 0 {
        return Err(format!("{STAGE_ERROR_PREFIX}-DESTINATION-WRITE"));
      }
      written += count;
    }
    digest.update(&buffer[..read]);
    offset = next_offset;
  }
  let after = source
    .metadata()
    .map_err(|_| format!("{STAGE_ERROR_PREFIX}-SOURCE-METADATA"))?;
  if before.dev() != after.dev()
    || before.ino() != after.ino()
    || before.len() != after.len()
    || before.mtime() != after.mtime()
    || before.mtime_nsec() != after.mtime_nsec()
    || before.ctime() != after.ctime()
    || before.ctime_nsec() != after.ctime_nsec()
    || offset != after.len()
  {
    return Err(format!("{STAGE_ERROR_PREFIX}-SOURCE-RACED"));
  }
  let actual = format!("sha256-{}", URL_SAFE_NO_PAD.encode(digest.finalize()));
  if actual != expected {
    return Err(format!("{STAGE_ERROR_PREFIX}-DIGEST"));
  }
  destination
    .sync_all()
    .map_err(|_| format!("{STAGE_ERROR_PREFIX}-DESTINATION-SYNC"))?;
  verify_opened_digest(destination, expected, expected_len)
}

#[cfg(unix)]
fn verify_opened_digest(
  file: &File,
  expected: &str,
  expected_len: u64,
) -> Result<(), String> {
  use std::os::unix::fs::MetadataExt;

  let before = file
    .metadata()
    .map_err(|_| format!("{STAGE_ERROR_PREFIX}-DESTINATION-METADATA"))?;
  if !before.is_file() {
    return Err(format!("{STAGE_ERROR_PREFIX}-DESTINATION-TYPE"));
  }
  if before.len() != expected_len {
    return Err(format!("{STAGE_ERROR_PREFIX}-DESTINATION-BOUNDS"));
  }
  let mut digest = Sha256::new();
  let mut buffer = [0_u8; COPY_BUFFER_BYTES];
  let mut offset = 0_u64;
  loop {
    let read = loop {
      match file.read_at(&mut buffer, offset) {
        Ok(read) => break read,
        Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
        Err(_) => {
          return Err(format!("{STAGE_ERROR_PREFIX}-DESTINATION-READ"));
        }
      }
    };
    if read == 0 {
      break;
    }
    let next_offset = offset
      .checked_add(read as u64)
      .ok_or_else(|| format!("{STAGE_ERROR_PREFIX}-BOUNDS"))?;
    if next_offset > expected_len {
      return Err(format!("{STAGE_ERROR_PREFIX}-DESTINATION-BOUNDS"));
    }
    digest.update(&buffer[..read]);
    offset = next_offset;
  }
  let after = file
    .metadata()
    .map_err(|_| format!("{STAGE_ERROR_PREFIX}-DESTINATION-METADATA"))?;
  if before.dev() != after.dev()
    || before.ino() != after.ino()
    || before.len() != after.len()
    || before.mtime() != after.mtime()
    || before.mtime_nsec() != after.mtime_nsec()
    || before.ctime() != after.ctime()
    || before.ctime_nsec() != after.ctime_nsec()
    || offset != after.len()
  {
    return Err(format!("{STAGE_ERROR_PREFIX}-DESTINATION-RACED"));
  }
  let actual = format!("sha256-{}", URL_SAFE_NO_PAD.encode(digest.finalize()));
  if actual != expected {
    return Err(format!("{STAGE_ERROR_PREFIX}-DIGEST"));
  }
  Ok(())
}

#[cfg(all(test, unix))]
#[allow(
  clippy::disallowed_methods,
  reason = "focused staging tests create and inspect isolated temporary filesystem fixtures"
)]
mod tests {
  use super::*;
  use std::io::Read;
  use std::io::Seek;
  use std::io::SeekFrom;
  use std::os::unix::fs::PermissionsExt;
  use std::sync::atomic::AtomicU64;
  use std::sync::atomic::Ordering;

  static NEXT_TEST: AtomicU64 = AtomicU64::new(0);

  fn test_root(label: &str) -> PathBuf {
    let serial = NEXT_TEST.fetch_add(1, Ordering::Relaxed);
    let root = std::env::temp_dir().join(format!(
      "oden-rev2-stage-test-{label}-{}-{serial}",
      std::process::id()
    ));
    std::fs::create_dir(&root).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
      .unwrap();
    std::fs::canonicalize(root).unwrap()
  }

  fn digest(bytes: &[u8]) -> String {
    format!("sha256-{}", URL_SAFE_NO_PAD.encode(Sha256::digest(bytes)))
  }

  fn retained(path: &Path, expected: &str) -> OdenRev2RetainedObject {
    OdenRev2RetainedObject::executable_for_test(
      "binding:object",
      "source:spawn",
      "object",
      expected,
      digest(b"binding provenance"),
      path.to_path_buf(),
      File::open(path).unwrap(),
    )
  }

  fn install(
    retained: &[OdenRev2RetainedObject],
    root: &Path,
  ) -> Result<OdenRev2InstalledExecutableContext, String> {
    let mut context = OdenRev2InstalledExecutableContext::empty();
    context.install_once(retained, root)?;
    Ok(context)
  }

  fn read_image(image: &OdenRev2ImmutableExecutableImage) -> Vec<u8> {
    let mut file = image.file().try_clone().unwrap();
    file.seek(SeekFrom::Start(0)).unwrap();
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes).unwrap();
    bytes
  }

  #[test]
  fn immutable_stage_rechecks_digest_and_detaches_from_source_mutation() {
    let root = test_root("detach");
    let source = root.join("source");
    let original = b"#!/bin/sh\necho authenticated\n";
    std::fs::write(&source, original).unwrap();
    let retained = retained(&source, &digest(original));
    let mut installed = install(&[retained], &root).unwrap();
    assert_eq!(installed.as_slice().len(), 1);
    let executable = &installed.as_slice()[0];
    assert_eq!(executable.binding_id(), "binding:object");
    assert_eq!(executable.source_id(), "source:spawn");
    assert_eq!(executable.role(), "object");
    assert_eq!(executable.canonical_content_identity(), digest(original));
    assert_eq!(
      executable.provenance_digest(),
      digest(b"binding provenance")
    );
    assert_eq!(executable.byte_len(), original.len() as u64);
    assert_eq!(read_image(executable.image()), original);

    std::fs::write(&source, b"attacker replacement").unwrap();
    assert_eq!(read_image(executable.image()), original);
    assert_eq!(
      installed.install_once(&[], &root).unwrap_err(),
      "OD-CAP-REV2-EXECUTABLE-STAGE-ALREADY-INSTALLED"
    );

    drop(installed);
    std::fs::remove_file(source).unwrap();
    std::fs::remove_dir(root).unwrap();
  }

  #[test]
  fn immutable_stage_refuses_wrong_authenticated_digest_without_fallback() {
    let root = test_root("digest");
    let source = root.join("source");
    std::fs::write(&source, b"actual bytes").unwrap();
    let retained = retained(&source, &digest(b"different bytes"));
    let error = install(&[retained], &root).unwrap_err();
    assert_eq!(error, "OD-CAP-REV2-EXECUTABLE-STAGE-DIGEST");
    assert_eq!(std::fs::read_dir(&root).unwrap().count(), 1);
    std::fs::remove_file(source).unwrap();
    std::fs::remove_dir(root).unwrap();
  }

  #[test]
  fn immutable_stage_refuses_count_image_and_aggregate_bound_overflow() {
    let root = test_root("bounds");
    let source = root.join("source");
    std::fs::write(&source, b"bounded bytes").unwrap();
    let one = retained(&source, &digest(b"bounded bytes"));
    let too_many = vec![one.clone(); MAX_INSTALLED_EXECUTABLES + 1];
    assert_eq!(
      install(&too_many, &root).unwrap_err(),
      "OD-CAP-REV2-EXECUTABLE-STAGE-COUNT-BOUNDS"
    );

    let oversized = root.join("oversized");
    let oversized_file = std::fs::File::create(&oversized).unwrap();
    oversized_file
      .set_len(MAX_EXECUTABLE_IMAGE_BYTES + 1)
      .unwrap();
    drop(oversized_file);
    let oversized_retained = retained(&oversized, &digest(b"unused"));
    assert_eq!(
      install(&[oversized_retained], &root).unwrap_err(),
      "OD-CAP-REV2-EXECUTABLE-STAGE-IMAGE-BOUNDS"
    );

    let aggregate = root.join("aggregate");
    let aggregate_file = std::fs::File::create(&aggregate).unwrap();
    let aggregate_part = 400 * 1024 * 1024;
    aggregate_file.set_len(aggregate_part).unwrap();
    drop(aggregate_file);
    let aggregate_retained = retained(&aggregate, &digest(b"unused"));
    assert_eq!(
      install(
        &[
          aggregate_retained.clone(),
          aggregate_retained.clone(),
          aggregate_retained,
        ],
        &root,
      )
      .unwrap_err(),
      "OD-CAP-REV2-EXECUTABLE-STAGE-AGGREGATE-BOUNDS"
    );

    std::fs::remove_file(aggregate).unwrap();
    std::fs::remove_file(oversized).unwrap();
    std::fs::remove_file(source).unwrap();
    std::fs::remove_dir(root).unwrap();
  }

  #[test]
  fn generated_runtime_contract_owns_executable_stage_bounds() {
    assert_eq!(
      MAX_INSTALLED_EXECUTABLES,
      REV2_RUNTIME_EXECUTABLE_MAX_IMAGES
    );
    assert_eq!(
      MAX_EXECUTABLE_IMAGE_BYTES,
      REV2_RUNTIME_EXECUTABLE_MAX_IMAGE_BYTES as u64
    );
    assert_eq!(
      MAX_EXECUTABLE_AGGREGATE_BYTES,
      REV2_RUNTIME_EXECUTABLE_MAX_AGGREGATE_BYTES as u64
    );
  }

  #[test]
  fn immutable_stage_consumes_even_an_empty_installation() {
    let root = test_root("empty-once");
    let mut installed = OdenRev2InstalledExecutableContext::empty();
    installed.install_once(&[], &root).unwrap();
    assert!(installed.as_slice().is_empty());
    assert_eq!(
      installed.install_once(&[], &root).unwrap_err(),
      "OD-CAP-REV2-EXECUTABLE-STAGE-ALREADY-INSTALLED"
    );
    std::fs::remove_dir(root).unwrap();
  }

  #[cfg(target_os = "linux")]
  #[test]
  fn linux_image_has_irreversible_write_and_size_seals() {
    let root = test_root("linux-seals");
    let source = root.join("source");
    let bytes = b"sealed linux bytes";
    std::fs::write(&source, bytes).unwrap();
    let retained = retained(&source, &digest(bytes));
    let installed = install(&[retained], &root).unwrap();
    let image = installed.as_slice()[0].image();
    let required = libc::F_SEAL_WRITE
      | libc::F_SEAL_GROW
      | libc::F_SEAL_SHRINK
      | libc::F_SEAL_SEAL;
    assert_eq!(image.platform_kind(), "linux-sealed-memfd");
    assert_eq!(
      linux_memfd_flags(true),
      libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING | LINUX_MFD_EXEC
    );
    assert_eq!(
      linux_memfd_flags(false),
      libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING
    );
    let _explicit_exec_or_legacy_kernel = image.linux_explicit_exec();
    assert_eq!(image.linux_seals() & required, required);
    assert!(image.file().write_at(b"x", 0).is_err());
    assert!(image.file().set_len(1).is_err());
    drop(installed);
    std::fs::remove_file(source).unwrap();
    std::fs::remove_dir(root).unwrap();
  }

  #[cfg(target_os = "macos")]
  #[test]
  fn macos_image_is_private_read_only_and_immutable() {
    use std::os::unix::fs::MetadataExt;

    let root = test_root("macos-flags");
    let source = root.join("source");
    let bytes = b"immutable macos bytes";
    std::fs::write(&source, bytes).unwrap();
    let retained = retained(&source, &digest(bytes));
    let installed = install(&[retained], &root).unwrap();
    let image = installed.as_slice()[0].image();
    assert_eq!(image.platform_kind(), "macos-private-immutable-path");
    assert_eq!(image.macos_flags() & libc::UF_IMMUTABLE, libc::UF_IMMUTABLE);
    assert_eq!(
      macos_file_flags(image.macos_directory()).unwrap() & libc::UF_IMMUTABLE,
      libc::UF_IMMUTABLE
    );
    assert_eq!(
      image.macos_directory().metadata().unwrap().mode() & 0o777,
      0o700
    );
    assert_eq!(image.file().metadata().unwrap().mode() & 0o777, 0o500);
    assert!(image.file().write_at(b"x", 0).is_err());
    let stage_path = image.macos_path().to_path_buf();
    assert!(stage_path.starts_with(&root));
    assert_eq!(std::fs::read(&stage_path).unwrap(), bytes);
    assert!(std::fs::write(&stage_path, b"path mutation").is_err());
    assert!(std::fs::remove_file(&stage_path).is_err());
    assert!(std::fs::rename(&stage_path, root.join("replacement")).is_err());

    drop(installed);
    assert!(!stage_path.exists());
    std::fs::remove_file(source).unwrap();
    std::fs::remove_dir(root).unwrap();
  }

  #[cfg(target_os = "macos")]
  #[test]
  fn macos_stage_refuses_a_nonprivate_control_root() {
    let root = test_root("macos-control-root");
    let source = root.join("source");
    let bytes = b"authenticated bytes";
    std::fs::write(&source, bytes).unwrap();
    std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o755))
      .unwrap();
    let retained = retained(&source, &digest(bytes));
    let error = install(&[retained], &root).unwrap_err();
    assert_eq!(error, "OD-CAP-REV2-EXECUTABLE-STAGE-MACOS-CONTROL-ROOT");
    assert_eq!(std::fs::read_dir(&root).unwrap().count(), 1);
    std::fs::remove_file(source).unwrap();
    std::fs::remove_dir(root).unwrap();
  }
}

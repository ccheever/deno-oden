// Copyright 2018-2026 the Deno authors. MIT license.

mod interface;
mod ops;
mod std_fs;

pub use deno_io::fs::FsError;
pub use deno_maybe_sync as sync;
pub use deno_maybe_sync::MaybeSend;
pub use deno_maybe_sync::MaybeSync;

pub use crate::interface::FileSystem;
pub use crate::interface::FileSystemRc;
pub use crate::interface::FsDirEntry;
pub use crate::interface::FsFileType;
pub use crate::interface::FsReadDir;
pub use crate::interface::FsReadDirRc;
pub use crate::interface::OpenOptions;
pub use crate::ops::FsOpsError;
pub use crate::ops::FsOpsErrorKind;
pub use crate::ops::OperationError;
use crate::ops::*;
pub use crate::std_fs::RealFs;
pub use crate::std_fs::open_options_for_checked_path;

pub const UNSTABLE_FEATURE_NAME: &str = "fs";

/// Consume one dormant Candidate capsule through the exact registered
/// synchronous public-op implementation. No production dispatcher calls this
/// seam, and its opaque result carries no expectation or release authority.
///
/// @ref LLP 0019#pre-promotion-conformance-candidate-execution
/// [constrained-by]
#[doc(hidden)]
#[allow(dead_code)]
pub(crate) fn oden_capsec_rev2_execute_lstat_candidate(
  capsule: deno_permissions::OdenRev2LstatCandidateCapsule,
) -> Result<
  deno_permissions::OdenRev2LstatCandidateArtifacts,
  deno_permissions::OdenRev2FilesystemError,
> {
  if deno_permissions::oden_capsec_rev2_process_mode()
    != deno_permissions::OdenRev2ProcessMode::Rev1
    || deno_permissions::oden_capsec_rev2_runtime_authority_context().is_some()
  {
    return Err(deno_permissions::OdenRev2FilesystemError::Refused(
      "OD-CAP-REV2-FILESYSTEM-CANDIDATE-PROCESS-BOUNDARY".to_string(),
    ));
  }
  let (binding, target_path) = capsule.into_execution_parts();
  let target = target_path.to_str().ok_or_else(|| {
    deno_permissions::OdenRev2FilesystemError::Refused(
      "OD-CAP-REV2-FILESYSTEM-CANDIDATE-TARGET-UNICODE".to_string(),
    )
  })?;
  let mut state = deno_core::OpState::new(None);
  let fs: FileSystemRc = deno_maybe_sync::new_rc(RealFs);
  state.put(fs);
  state.put(binding);
  let mut stat = [0_u32; 64];
  let public_op = ops::op_fs_lstat_sync_impl(&mut state, target, &mut stat);
  if deno_permissions::oden_capsec_rev2_process_mode()
    != deno_permissions::OdenRev2ProcessMode::Rev1
    || deno_permissions::oden_capsec_rev2_runtime_authority_context().is_some()
  {
    return Err(deno_permissions::OdenRev2FilesystemError::Refused(
      "OD-CAP-REV2-FILESYSTEM-CANDIDATE-PROCESS-BOUNDARY".to_string(),
    ));
  }
  let public_op_succeeded = match public_op {
    Ok(()) => true,
    Err(error)
      if matches!(
        error.0.as_ref(),
        FsOpsErrorKind::Io(source)
          if source.raw_os_error() == Some(libc::ENOENT)
      ) =>
    {
      false
    }
    Err(_) => {
      return Err(deno_permissions::OdenRev2FilesystemError::Refused(
        "OD-CAP-REV2-FILESYSTEM-CANDIDATE-PUBLIC-RESULT".to_string(),
      ));
    }
  };
  let binding = state
    .try_take::<std::sync::Arc<
      deno_permissions::OdenRev2LstatCandidateOpStateBinding,
    >>()
    .ok_or_else(|| {
      deno_permissions::OdenRev2FilesystemError::Refused(
        "OD-CAP-REV2-FILESYSTEM-CANDIDATE-OPSTATE-BINDING".to_string(),
      )
    })?;
  drop(state);
  let binding = std::sync::Arc::try_unwrap(binding).map_err(|_| {
    deno_permissions::OdenRev2FilesystemError::Refused(
      "OD-CAP-REV2-FILESYSTEM-CANDIDATE-OPSTATE-SHARED".to_string(),
    )
  })?;
  binding.finish(public_op_succeeded)
}

deno_core::extension!(deno_fs,
  deps = [ deno_web ],
  ops = [
    op_fs_cwd,
    op_fs_umask,
    op_fs_chdir,

    op_fs_open_sync,
    op_fs_open_async,
    op_fs_mkdir_sync,
    op_fs_mkdir_async,
    op_fs_chmod_sync,
    op_fs_chmod_async,
    op_fs_chown_sync,
    op_fs_chown_async,
    op_fs_remove_sync,
    op_fs_remove_async,
    op_fs_copy_file_sync,
    op_fs_copy_file_async,
    op_fs_stat_sync,
    op_fs_stat_async,
    op_fs_lstat_sync,
    op_fs_lstat_async,
    op_fs_realpath_sync,
    op_fs_realpath_async,
    op_fs_read_dir_sync,
    op_fs_read_dir_async,
    op_fs_read_dir_async_next,
    op_fs_rename_sync,
    op_fs_rename_async,
    op_fs_link_sync,
    op_fs_link_async,
    op_fs_symlink_sync,
    op_fs_symlink_async,
    op_fs_read_link_sync,
    op_fs_read_link_async,
    op_fs_truncate_sync,
    op_fs_truncate_async,
    op_fs_utime_sync,
    op_fs_utime_async,
    op_fs_make_temp_dir_sync,
    op_fs_make_temp_dir_async,
    op_fs_make_temp_file_sync,
    op_fs_make_temp_file_async,
    op_fs_write_file_sync,
    op_fs_write_file_async,
    op_fs_read_file_sync,
    op_fs_read_file_async,
    op_fs_read_file_text_sync,
    op_fs_read_file_text_async,

    op_fs_seek_sync,
    op_fs_seek_async,
    op_fs_file_sync_data_sync,
    op_fs_file_sync_data_async,
    op_fs_file_sync_sync,
    op_fs_file_sync_async,
    op_fs_file_stat_sync,
    op_fs_file_stat_async,
    op_fs_fchmod_async,
    op_fs_fchmod_sync,
    op_fs_fchown_async,
    op_fs_fchown_sync,
    op_fs_flock_async,
    op_fs_flock_sync,
    op_fs_flock_try_async,
    op_fs_flock_try_sync,
    op_fs_funlock_async,
    op_fs_funlock_sync,
    op_fs_ftruncate_sync,
    op_fs_file_truncate_async,
    op_fs_futime_sync,
    op_fs_futime_async,

  ],
  lazy_loaded_js = [ "30_fs.js" ],
  options = {
    fs: FileSystemRc,
  },
  state = |state, options| {
    state.put(options.fs);
  },
);

#[cfg(all(
  test,
  any(
    all(target_arch = "aarch64", target_vendor = "apple", target_os = "macos"),
    all(
      target_arch = "x86_64",
      target_vendor = "unknown",
      target_os = "linux",
      target_env = "gnu"
    )
  )
))]
mod lstat_candidate_public_op_tests {
  use std::fs::File;
  use std::fs::OpenOptions;
  use std::path::Path;
  use std::path::PathBuf;
  use std::sync::atomic::AtomicU64;
  use std::sync::atomic::Ordering;

  use deno_core::OpState;

  use super::FileSystemRc;
  use super::FsOpsErrorKind;
  use super::RealFs;

  const FIXTURE_ARTIFACT_DIGEST: &str =
    "sha256-_z_uHneEtf-CblX6irBb_2qsDzhDhxLAaDZTCP2aWAM";
  const EXISTING_CASE: &str = "filesystem:lstat-sync:lstat-existing";
  const FINAL_MISSING_CASE: &str = "filesystem:lstat-sync:lstat-final-missing";

  static NEXT_ROOT: AtomicU64 = AtomicU64::new(1);

  struct TempRoot(PathBuf);

  impl TempRoot {
    fn new(label: &str) -> Self {
      let sequence = NEXT_ROOT.fetch_add(1, Ordering::Relaxed);
      let path = std::env::temp_dir().join(format!(
        "oden-lstat-public-op-{}-{label}-{sequence}",
        std::process::id()
      ));
      std::fs::create_dir(&path).unwrap();
      Self(std::fs::canonicalize(path).unwrap())
    }

    fn project(&self) -> PathBuf {
      let path = self.0.join("project");
      std::fs::create_dir(&path).unwrap();
      path
    }
  }

  impl Drop for TempRoot {
    fn drop(&mut self) {
      std::fs::remove_dir_all(&self.0).unwrap();
    }
  }

  fn retained_root(path: &Path) -> File {
    use std::os::unix::fs::OpenOptionsExt;

    OpenOptions::new()
      .read(true)
      .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
      .open(path)
      .unwrap()
  }

  fn retained_arena(path: &Path) -> File {
    use std::os::unix::fs::OpenOptionsExt;

    let arena = OpenOptions::new()
      .read(true)
      .write(true)
      .create_new(true)
      .custom_flags(libc::O_CLOEXEC)
      .open(path)
      .unwrap();
    arena.set_len(8 * 1024 * 1024).unwrap();
    arena
  }

  fn assert_existing_candidate_prepare_refuses(
    label: &str,
    prepare_project: impl FnOnce(&Path, &Path),
  ) {
    let root = TempRoot::new(label);
    let project = root.project();
    prepare_project(&root.0, &project);
    assert!(
      deno_permissions::oden_capsec_rev2_prepare_lstat_candidate(
        FIXTURE_ARTIFACT_DIGEST,
        EXISTING_CASE,
        retained_root(&project),
        retained_arena(&root.0.join("arena")),
      )
      .is_err(),
      "{label}"
    );
  }

  fn exact_existing_project(label: &str) -> (TempRoot, PathBuf) {
    let root = TempRoot::new(label);
    let project = root.project();
    std::fs::write(project.join("input.txt"), b"").unwrap();
    (root, project)
  }

  fn candidate_state(
    binding: std::sync::Arc<
      deno_permissions::OdenRev2LstatCandidateOpStateBinding,
    >,
  ) -> OpState {
    let mut state = OpState::new(None);
    let fs: FileSystemRc = deno_maybe_sync::new_rc(RealFs);
    state.put(fs);
    state.put(binding);
    state
  }

  #[test]
  fn lstat_candidate_public_op_traverses_exact_existing_case() {
    assert_eq!(
      deno_permissions::oden_capsec_rev2_process_mode(),
      deno_permissions::OdenRev2ProcessMode::Rev1
    );
    assert!(
      deno_permissions::oden_capsec_rev2_runtime_authority_context().is_none()
    );
    let root = TempRoot::new("existing");
    let project = root.project();
    std::fs::write(project.join("input.txt"), b"").unwrap();
    let capsule = deno_permissions::oden_capsec_rev2_prepare_lstat_candidate(
      FIXTURE_ARTIFACT_DIGEST,
      EXISTING_CASE,
      retained_root(&project),
      retained_arena(&root.0.join("arena")),
    )
    .unwrap();

    super::oden_capsec_rev2_execute_lstat_candidate(capsule).unwrap();

    assert_eq!(
      deno_permissions::oden_capsec_rev2_process_mode(),
      deno_permissions::OdenRev2ProcessMode::Rev1
    );
    assert!(
      deno_permissions::oden_capsec_rev2_runtime_authority_context().is_none()
    );
    assert_eq!(std::fs::read(project.join("input.txt")).unwrap(), b"");
  }

  #[test]
  fn lstat_candidate_public_op_traverses_exact_final_missing_case() {
    let root = TempRoot::new("missing");
    let project = root.project();
    let capsule = deno_permissions::oden_capsec_rev2_prepare_lstat_candidate(
      FIXTURE_ARTIFACT_DIGEST,
      FINAL_MISSING_CASE,
      retained_root(&project),
      retained_arena(&root.0.join("arena")),
    )
    .unwrap();

    super::oden_capsec_rev2_execute_lstat_candidate(capsule).unwrap();

    assert_eq!(std::fs::read_dir(&project).unwrap().count(), 0);
    assert_eq!(
      deno_permissions::oden_capsec_rev2_process_mode(),
      deno_permissions::OdenRev2ProcessMode::Rev1
    );
    assert!(
      deno_permissions::oden_capsec_rev2_runtime_authority_context().is_none()
    );
  }

  #[test]
  fn lstat_candidate_public_op_refuses_inexact_descriptor_topology() {
    let existing = TempRoot::new("descriptor-existing-empty");
    let existing_project = existing.project();
    assert!(
      deno_permissions::oden_capsec_rev2_prepare_lstat_candidate(
        FIXTURE_ARTIFACT_DIGEST,
        EXISTING_CASE,
        retained_root(&existing_project),
        retained_arena(&existing.0.join("arena")),
      )
      .is_err()
    );

    let missing = TempRoot::new("descriptor-missing-present");
    let missing_project = missing.project();
    std::fs::write(missing_project.join("input.txt"), b"").unwrap();
    assert!(
      deno_permissions::oden_capsec_rev2_prepare_lstat_candidate(
        FIXTURE_ARTIFACT_DIGEST,
        FINAL_MISSING_CASE,
        retained_root(&missing_project),
        retained_arena(&missing.0.join("arena")),
      )
      .is_err()
    );
  }

  #[test]
  fn lstat_candidate_public_op_refuses_links_specials_case_and_bytes() {
    assert_existing_candidate_prepare_refuses(
      "descriptor-source-symlink",
      |root, project| {
        let target = root.join("symlink-target");
        std::fs::write(&target, b"").unwrap();
        std::os::unix::fs::symlink(&target, project.join("input.txt")).unwrap();
      },
    );
    assert_existing_candidate_prepare_refuses(
      "descriptor-source-hard-link",
      |root, project| {
        let target = root.join("hard-link-target");
        std::fs::write(&target, b"").unwrap();
        std::fs::hard_link(&target, project.join("input.txt")).unwrap();
      },
    );
    assert_existing_candidate_prepare_refuses(
      "descriptor-source-fifo",
      |_root, project| {
        use std::os::unix::ffi::OsStrExt;

        let path = std::ffi::CString::new(
          project.join("input.txt").as_os_str().as_bytes(),
        )
        .unwrap();
        // SAFETY: `path` is one live, terminated pathname and the mode is
        // limited to ordinary owner read/write fixture permissions.
        assert_eq!(unsafe { libc::mkfifo(path.as_ptr(), 0o600) }, 0);
      },
    );
    assert_existing_candidate_prepare_refuses(
      "descriptor-source-case-alias",
      |_root, project| {
        std::fs::write(project.join("Input.txt"), b"").unwrap();
      },
    );
    assert_existing_candidate_prepare_refuses(
      "descriptor-source-nonzero",
      |_root, project| {
        std::fs::write(project.join("input.txt"), b"x").unwrap();
      },
    );
  }

  #[test]
  fn lstat_candidate_public_op_refuses_inexact_arena() {
    use std::os::unix::fs::FileExt;
    use std::os::unix::fs::OpenOptionsExt;

    let (directory_root, directory_project) =
      exact_existing_project("arena-directory");
    let directory = directory_root.0.join("arena-directory");
    std::fs::create_dir(&directory).unwrap();
    assert!(
      deno_permissions::oden_capsec_rev2_prepare_lstat_candidate(
        FIXTURE_ARTIFACT_DIGEST,
        EXISTING_CASE,
        retained_root(&directory_project),
        retained_root(&directory),
      )
      .is_err()
    );

    let (size_root, size_project) = exact_existing_project("arena-size");
    let wrong_size = OpenOptions::new()
      .read(true)
      .write(true)
      .create_new(true)
      .custom_flags(libc::O_CLOEXEC)
      .open(size_root.0.join("arena"))
      .unwrap();
    wrong_size.set_len(8 * 1024 * 1024 - 1).unwrap();
    assert!(
      deno_permissions::oden_capsec_rev2_prepare_lstat_candidate(
        FIXTURE_ARTIFACT_DIGEST,
        EXISTING_CASE,
        retained_root(&size_project),
        wrong_size,
      )
      .is_err()
    );

    let (content_root, content_project) =
      exact_existing_project("arena-content");
    let nonzero = retained_arena(&content_root.0.join("arena"));
    assert_eq!(nonzero.write_at(&[1], 4096).unwrap(), 1);
    assert!(
      deno_permissions::oden_capsec_rev2_prepare_lstat_candidate(
        FIXTURE_ARTIFACT_DIGEST,
        EXISTING_CASE,
        retained_root(&content_project),
        nonzero,
      )
      .is_err()
    );

    let (readonly_root, readonly_project) =
      exact_existing_project("arena-readonly");
    let readonly_path = readonly_root.0.join("arena");
    let writable = retained_arena(&readonly_path);
    drop(writable);
    let readonly = OpenOptions::new()
      .read(true)
      .custom_flags(libc::O_CLOEXEC)
      .open(&readonly_path)
      .unwrap();
    assert!(
      deno_permissions::oden_capsec_rev2_prepare_lstat_candidate(
        FIXTURE_ARTIFACT_DIGEST,
        EXISTING_CASE,
        retained_root(&readonly_project),
        readonly,
      )
      .is_err()
    );

    let (linked_root, linked_project) =
      exact_existing_project("arena-hard-link");
    let linked_path = linked_root.0.join("arena");
    let linked = retained_arena(&linked_path);
    std::fs::hard_link(&linked_path, linked_root.0.join("arena-alias"))
      .unwrap();
    assert!(
      deno_permissions::oden_capsec_rev2_prepare_lstat_candidate(
        FIXTURE_ARTIFACT_DIGEST,
        EXISTING_CASE,
        retained_root(&linked_project),
        linked,
      )
      .is_err()
    );

    let (append_root, append_project) = exact_existing_project("arena-append");
    let append_path = append_root.0.join("arena");
    let seed = retained_arena(&append_path);
    drop(seed);
    let append = OpenOptions::new()
      .read(true)
      .append(true)
      .custom_flags(libc::O_CLOEXEC)
      .open(&append_path)
      .unwrap();
    assert!(
      deno_permissions::oden_capsec_rev2_prepare_lstat_candidate(
        FIXTURE_ARTIFACT_DIGEST,
        EXISTING_CASE,
        retained_root(&append_project),
        append,
      )
      .is_err()
    );
  }

  #[test]
  fn lstat_candidate_public_op_refuses_rename_and_synthetic_twin() {
    let root = TempRoot::new("root-replacement");
    let project = root.project();
    std::fs::write(project.join("input.txt"), b"").unwrap();
    let capsule = deno_permissions::oden_capsec_rev2_prepare_lstat_candidate(
      FIXTURE_ARTIFACT_DIGEST,
      EXISTING_CASE,
      retained_root(&project),
      retained_arena(&root.0.join("arena")),
    )
    .unwrap();
    let displaced = root.0.join("displaced");
    std::fs::rename(&project, &displaced).unwrap();
    std::fs::create_dir(&project).unwrap();
    std::fs::write(project.join("input.txt"), b"").unwrap();

    assert!(super::oden_capsec_rev2_execute_lstat_candidate(capsule).is_err());
    assert_eq!(std::fs::read(displaced.join("input.txt")).unwrap(), b"");
    assert_eq!(std::fs::read(project.join("input.txt")).unwrap(), b"");
  }

  #[test]
  fn lstat_candidate_public_op_detects_descriptor_relative_mutation() {
    let root = TempRoot::new("root-mutation");
    let project = root.project();
    let source = project.join("input.txt");
    std::fs::write(&source, b"").unwrap();
    let capsule = deno_permissions::oden_capsec_rev2_prepare_lstat_candidate(
      FIXTURE_ARTIFACT_DIGEST,
      EXISTING_CASE,
      retained_root(&project),
      retained_arena(&root.0.join("arena")),
    )
    .unwrap();
    std::fs::remove_file(&source).unwrap();
    std::fs::write(&source, b"").unwrap();

    assert!(super::oden_capsec_rev2_execute_lstat_candidate(capsule).is_err());
  }

  #[test]
  fn lstat_candidate_public_op_detects_retained_root_and_arena_mutation() {
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::FileExt;

    let root = TempRoot::new("root-flags-mutation");
    let project = root.project();
    std::fs::write(project.join("input.txt"), b"").unwrap();
    let retained = retained_root(&project);
    let root_mutator = retained.try_clone().unwrap();
    let capsule = deno_permissions::oden_capsec_rev2_prepare_lstat_candidate(
      FIXTURE_ARTIFACT_DIGEST,
      EXISTING_CASE,
      retained,
      retained_arena(&root.0.join("arena")),
    )
    .unwrap();
    // SAFETY: both operations target a live duplicate of the retained root
    // open-file description and modify only its mutable status flags.
    let flags = unsafe { libc::fcntl(root_mutator.as_raw_fd(), libc::F_GETFL) };
    assert!(flags >= 0);
    // SAFETY: same live duplicate and one supported mutable status flag.
    assert_eq!(
      unsafe {
        libc::fcntl(
          root_mutator.as_raw_fd(),
          libc::F_SETFL,
          flags | libc::O_APPEND,
        )
      },
      0
    );
    drop(root_mutator);
    assert!(super::oden_capsec_rev2_execute_lstat_candidate(capsule).is_err());

    let arena_root = TempRoot::new("arena-live-mutation");
    let arena_project = arena_root.project();
    std::fs::write(arena_project.join("input.txt"), b"").unwrap();
    let arena = retained_arena(&arena_root.0.join("arena"));
    let arena_mutator = arena.try_clone().unwrap();
    let capsule = deno_permissions::oden_capsec_rev2_prepare_lstat_candidate(
      FIXTURE_ARTIFACT_DIGEST,
      EXISTING_CASE,
      retained_root(&arena_project),
      arena,
    )
    .unwrap();
    assert_eq!(arena_mutator.write_at(&[1], 0).unwrap(), 1);
    drop(arena_mutator);
    assert!(super::oden_capsec_rev2_execute_lstat_candidate(capsule).is_err());
  }

  #[test]
  fn lstat_candidate_public_op_selects_only_exact_generated_identity() {
    let root = TempRoot::new("identity");
    let project = root.project();
    std::fs::write(project.join("input.txt"), b"").unwrap();
    for (index, (digest, case_id)) in [
      (
        "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        EXISTING_CASE,
      ),
      (FIXTURE_ARTIFACT_DIGEST, "filesystem:lstat-sync:existing"),
      (
        FIXTURE_ARTIFACT_DIGEST,
        "filesystem:lstat-sync:LSTAT-existing",
      ),
    ]
    .into_iter()
    .enumerate()
    {
      assert!(
        deno_permissions::oden_capsec_rev2_prepare_lstat_candidate(
          digest,
          case_id,
          retained_root(&project),
          retained_arena(&root.0.join(format!("arena-{index}"))),
        )
        .is_err(),
        "{digest} {case_id}"
      );
    }
    assert!(
      deno_permissions::oden_capsec_rev2_prepare_lstat_candidate(
        FIXTURE_ARTIFACT_DIGEST,
        "filesystem:lstat-sync:lstat-existing/",
        retained_root(&project),
        retained_arena(&root.0.join("arena-alias")),
      )
      .is_err()
    );
  }

  #[test]
  fn lstat_candidate_public_op_refuses_replay_and_mixed_opstate() {
    let root = TempRoot::new("one-shot");
    let project = root.project();
    std::fs::write(project.join("input.txt"), b"").unwrap();
    let capsule = deno_permissions::oden_capsec_rev2_prepare_lstat_candidate(
      FIXTURE_ARTIFACT_DIGEST,
      EXISTING_CASE,
      retained_root(&project),
      retained_arena(&root.0.join("arena")),
    )
    .unwrap();
    let (binding, target) = capsule.into_execution_parts();
    let target = target.to_str().unwrap();
    let mut state = candidate_state(binding);
    let mut stat = [0_u32; 64];
    assert!(
      super::ops::op_fs_lstat_sync_impl(&mut state, target, &mut stat).is_ok()
    );
    assert!(
      super::ops::op_fs_lstat_sync_impl(&mut state, target, &mut stat).is_err()
    );
    let binding = state
      .try_take::<std::sync::Arc<
        deno_permissions::OdenRev2LstatCandidateOpStateBinding,
      >>()
      .unwrap();
    drop(state);
    std::sync::Arc::try_unwrap(binding)
      .ok()
      .unwrap()
      .finish(true)
      .unwrap();

    let second_root = TempRoot::new("mixed");
    let second_project = second_root.project();
    std::fs::write(second_project.join("input.txt"), b"").unwrap();
    let second = deno_permissions::oden_capsec_rev2_prepare_lstat_candidate(
      FIXTURE_ARTIFACT_DIGEST,
      EXISTING_CASE,
      retained_root(&second_project),
      retained_arena(&second_root.0.join("arena")),
    )
    .unwrap();
    let (second_binding, second_target) = second.into_execution_parts();
    let mut mixed = candidate_state(second_binding);
    mixed.put(deno_permissions::OdenRev2ProcessMode::Rev1);
    assert!(
      super::ops::op_fs_lstat_sync_impl(
        &mut mixed,
        second_target.to_str().unwrap(),
        &mut stat,
      )
      .is_err()
    );
    let second_binding = mixed
      .try_take::<std::sync::Arc<
        deno_permissions::OdenRev2LstatCandidateOpStateBinding,
      >>()
      .unwrap();
    drop(mixed);
    assert!(
      std::sync::Arc::try_unwrap(second_binding)
        .ok()
        .unwrap()
        .finish(false)
        .is_err()
    );
    assert_eq!(
      std::fs::read(second_project.join("input.txt")).unwrap(),
      b""
    );
  }

  #[test]
  fn lstat_candidate_public_op_refuses_direct_candidate_sync_entry() {
    let root = TempRoot::new("direct-candidate-sync");
    let project = root.project();
    std::fs::write(project.join("input.txt"), b"").unwrap();
    let capsule = deno_permissions::oden_capsec_rev2_prepare_lstat_candidate(
      FIXTURE_ARTIFACT_DIGEST,
      EXISTING_CASE,
      retained_root(&project),
      retained_arena(&root.0.join("arena")),
    )
    .unwrap();
    let (binding, target) = capsule.into_execution_parts();

    assert!(
      deno_permissions::oden_capsec_rev2_lstat_candidate_sync(
        &binding, &target,
      )
      .is_err()
    );

    let mut state = candidate_state(binding);
    let mut stat = [0_u32; 64];
    assert!(
      super::ops::op_fs_lstat_sync_impl(
        &mut state,
        target.to_str().unwrap(),
        &mut stat,
      )
      .is_ok()
    );
    let binding = state
      .try_take::<std::sync::Arc<
        deno_permissions::OdenRev2LstatCandidateOpStateBinding,
      >>()
      .unwrap();
    drop(state);
    std::sync::Arc::try_unwrap(binding)
      .ok()
      .unwrap()
      .finish(true)
      .unwrap();
  }

  #[test]
  fn lstat_candidate_public_op_terminalization_refuses_a_binding_clone() {
    let root = TempRoot::new("binding-clone");
    let project = root.project();
    std::fs::write(project.join("input.txt"), b"").unwrap();
    let capsule = deno_permissions::oden_capsec_rev2_prepare_lstat_candidate(
      FIXTURE_ARTIFACT_DIGEST,
      EXISTING_CASE,
      retained_root(&project),
      retained_arena(&root.0.join("arena")),
    )
    .unwrap();
    let (binding, target) = capsule.into_execution_parts();
    let leaked = std::sync::Arc::clone(&binding);
    let mut state = candidate_state(binding);
    let mut stat = [0_u32; 64];
    assert!(
      super::ops::op_fs_lstat_sync_impl(
        &mut state,
        target.to_str().unwrap(),
        &mut stat,
      )
      .is_ok()
    );
    let binding = state
      .try_take::<std::sync::Arc<
        deno_permissions::OdenRev2LstatCandidateOpStateBinding,
      >>()
      .unwrap();
    drop(state);
    let binding = std::sync::Arc::try_unwrap(binding)
      .err()
      .expect("the leaked clone must prevent terminalization");
    drop(leaked);
    std::sync::Arc::try_unwrap(binding)
      .ok()
      .unwrap()
      .finish(true)
      .unwrap();
  }

  #[test]
  fn lstat_candidate_public_op_missing_is_direct_io_enoent() {
    let root = TempRoot::new("direct-enoent");
    let project = root.project();
    let capsule = deno_permissions::oden_capsec_rev2_prepare_lstat_candidate(
      FIXTURE_ARTIFACT_DIGEST,
      FINAL_MISSING_CASE,
      retained_root(&project),
      retained_arena(&root.0.join("arena")),
    )
    .unwrap();
    let (binding, target) = capsule.into_execution_parts();
    let mut state = candidate_state(binding);
    let mut stat = [0_u32; 64];
    let error = super::ops::op_fs_lstat_sync_impl(
      &mut state,
      target.to_str().unwrap(),
      &mut stat,
    )
    .unwrap_err();
    assert!(matches!(
      error.0.as_ref(),
      FsOpsErrorKind::Io(source)
        if source.raw_os_error() == Some(libc::ENOENT)
    ));
    let binding = state
      .try_take::<std::sync::Arc<
        deno_permissions::OdenRev2LstatCandidateOpStateBinding,
      >>()
      .unwrap();
    drop(state);
    std::sync::Arc::try_unwrap(binding)
      .ok()
      .unwrap()
      .finish(false)
      .unwrap();
  }

  #[test]
  fn lstat_candidate_public_op_refuses_wrong_edge_before_claim_or_mutation() {
    let root = TempRoot::new("wrong-edge");
    let project = root.project();
    std::fs::write(project.join("input.txt"), b"").unwrap();
    let capsule = deno_permissions::oden_capsec_rev2_prepare_lstat_candidate(
      FIXTURE_ARTIFACT_DIGEST,
      EXISTING_CASE,
      retained_root(&project),
      retained_arena(&root.0.join("arena")),
    )
    .unwrap();
    let (binding, target) = capsule.into_execution_parts();
    let state = candidate_state(binding);
    let wrong_edge_target = project.join("mkdir-must-not-exist");

    assert!(
      super::ops::resolve_rev2_filesystem_context(
        &state,
        &wrong_edge_target,
        "Deno.mkdirSync()",
      )
      .is_err()
    );
    assert!(!wrong_edge_target.exists());

    let mut state = state;
    let mut stat = [0_u32; 64];
    assert!(
      super::ops::op_fs_lstat_sync_impl(
        &mut state,
        target.to_str().unwrap(),
        &mut stat,
      )
      .is_ok()
    );
    let binding = state
      .try_take::<std::sync::Arc<
        deno_permissions::OdenRev2LstatCandidateOpStateBinding,
      >>()
      .unwrap();
    drop(state);
    std::sync::Arc::try_unwrap(binding)
      .ok()
      .unwrap()
      .finish(true)
      .unwrap();
    assert!(!wrong_edge_target.exists());
    assert_eq!(
      deno_permissions::oden_capsec_rev2_process_mode(),
      deno_permissions::OdenRev2ProcessMode::Rev1
    );
    assert!(
      deno_permissions::oden_capsec_rev2_runtime_authority_context().is_none()
    );
  }
}

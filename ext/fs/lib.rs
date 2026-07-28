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
  deno_permissions::OdenRev2LstatCandidateObservation,
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
  state.put(binding.clone());
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
  binding.finish(public_op.is_ok())
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
      &project,
      retained_root(&project),
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
      &project,
      retained_root(&project),
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
  fn lstat_candidate_public_op_refuses_descriptor_and_named_path_mismatch() {
    let left = TempRoot::new("descriptor-left");
    let right = TempRoot::new("descriptor-right");
    let left_project = left.project();
    let right_project = right.project();
    std::fs::write(left_project.join("input.txt"), b"").unwrap();
    std::fs::write(right_project.join("input.txt"), b"").unwrap();

    assert!(
      deno_permissions::oden_capsec_rev2_prepare_lstat_candidate(
        FIXTURE_ARTIFACT_DIGEST,
        EXISTING_CASE,
        &left_project,
        retained_root(&right_project),
      )
      .is_err()
    );
    assert_eq!(std::fs::read(left_project.join("input.txt")).unwrap(), b"");
    assert_eq!(std::fs::read(right_project.join("input.txt")).unwrap(), b"");
  }

  #[test]
  fn lstat_candidate_public_op_refuses_named_root_replacement() {
    let root = TempRoot::new("root-replacement");
    let project = root.project();
    std::fs::write(project.join("input.txt"), b"").unwrap();
    let capsule = deno_permissions::oden_capsec_rev2_prepare_lstat_candidate(
      FIXTURE_ARTIFACT_DIGEST,
      EXISTING_CASE,
      &project,
      retained_root(&project),
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
  fn lstat_candidate_public_op_selects_only_exact_generated_identity() {
    let root = TempRoot::new("identity");
    let project = root.project();
    std::fs::write(project.join("input.txt"), b"").unwrap();
    for (digest, case_id) in [
      (
        "sha256-AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        EXISTING_CASE,
      ),
      (FIXTURE_ARTIFACT_DIGEST, "filesystem:lstat-sync:existing"),
      (
        FIXTURE_ARTIFACT_DIGEST,
        "filesystem:lstat-sync:LSTAT-existing",
      ),
    ] {
      assert!(
        deno_permissions::oden_capsec_rev2_prepare_lstat_candidate(
          digest,
          case_id,
          &project,
          retained_root(&project),
        )
        .is_err(),
        "{digest} {case_id}"
      );
    }
    let dot_alias = project.join(".");
    assert!(
      deno_permissions::oden_capsec_rev2_prepare_lstat_candidate(
        FIXTURE_ARTIFACT_DIGEST,
        EXISTING_CASE,
        &dot_alias,
        retained_root(&project),
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
      &project,
      retained_root(&project),
    )
    .unwrap();
    let (binding, target) = capsule.into_execution_parts();
    let target = target.to_str().unwrap();
    let mut state = candidate_state(binding.clone());
    let mut stat = [0_u32; 64];
    assert!(
      super::ops::op_fs_lstat_sync_impl(&mut state, target, &mut stat).is_ok()
    );
    binding.finish(true).unwrap();
    assert!(
      super::ops::op_fs_lstat_sync_impl(&mut state, target, &mut stat).is_err()
    );

    let second_root = TempRoot::new("mixed");
    let second_project = second_root.project();
    std::fs::write(second_project.join("input.txt"), b"").unwrap();
    let second = deno_permissions::oden_capsec_rev2_prepare_lstat_candidate(
      FIXTURE_ARTIFACT_DIGEST,
      EXISTING_CASE,
      &second_project,
      retained_root(&second_project),
    )
    .unwrap();
    let (second_binding, second_target) = second.into_execution_parts();
    let mut mixed = candidate_state(second_binding.clone());
    mixed.put(deno_permissions::OdenRev2ProcessMode::Rev1);
    assert!(
      super::ops::op_fs_lstat_sync_impl(
        &mut mixed,
        second_target.to_str().unwrap(),
        &mut stat,
      )
      .is_err()
    );
    assert!(second_binding.finish(false).is_err());
    assert_eq!(
      std::fs::read(second_project.join("input.txt")).unwrap(),
      b""
    );
  }

  #[test]
  fn lstat_candidate_public_op_refuses_wrong_edge_before_claim_or_mutation() {
    let root = TempRoot::new("wrong-edge");
    let project = root.project();
    std::fs::write(project.join("input.txt"), b"").unwrap();
    let capsule = deno_permissions::oden_capsec_rev2_prepare_lstat_candidate(
      FIXTURE_ARTIFACT_DIGEST,
      EXISTING_CASE,
      &project,
      retained_root(&project),
    )
    .unwrap();
    let (binding, target) = capsule.into_execution_parts();
    let state = candidate_state(binding.clone());
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
    binding.finish(true).unwrap();
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

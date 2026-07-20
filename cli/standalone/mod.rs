// Copyright 2018-2026 the Deno authors. MIT license.

pub mod binary;
pub mod native_addons;
mod oden_parent_allowlist;
mod virtual_fs;

pub(crate) use oden_parent_allowlist::OdenParentAllowlistGenerateSession;
#[cfg(all(
  any(target_os = "linux", target_os = "macos"),
  feature = "__oden_parent_allowlist_embedded"
))]
pub(crate) use oden_parent_allowlist::admit_oden_parent_allowlist_check;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) use oden_parent_allowlist::admit_oden_parent_allowlist_generate;
#[cfg(all(
  any(target_os = "linux", target_os = "macos"),
  feature = "__oden_parent_allowlist_embedded"
))]
pub(crate) use oden_parent_allowlist::begin_oden_parent_allowlist_check_session;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) use oden_parent_allowlist::begin_oden_parent_allowlist_generate_session;
#[cfg(all(
  feature = "__oden_parent_allowlist_embedded",
  any(target_os = "linux", target_os = "macos")
))]
pub(crate) use oden_parent_allowlist::check_oden_parent_allowlist_outputs;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub(crate) use oden_parent_allowlist::generate_oden_parent_allowlist_outputs;
pub(crate) use oden_parent_allowlist::refusal_exit_code_for_oden_parent_allowlist_dispatch;

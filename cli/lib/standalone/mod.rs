// Copyright 2018-2026 the Deno authors. MIT license.

pub mod base_image;
pub mod binary;
pub mod oden_parent_allowlist;
// @ref LLP 0019#frozen-parent-standalone-allowlist-and-byte-graph [implements] —
// Compile the deterministic candidate only in the embedded shared-library
// shape. The module remains private; one handwritten accessor exposes only its
// inert JCS and digest bytes for fail-closed reconciliation.
#[cfg(feature = "__oden_parent_allowlist_embedded")]
mod oden_parent_allowlist_generated;
pub mod virtual_fs;

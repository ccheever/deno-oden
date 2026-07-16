// Copyright 2018-2026 the Deno authors. MIT license.

// @ref LLP 0019#frozen-parent-standalone-allowlist-and-byte-graph [implements] —
// This first generator-side slice freezes only the exact source-closure
// contract membership. Capture/release membership, retained-file loading,
// allowlist construction, generate/check execution, and both generated outputs
// remain absent, so neither reserved mode gains authority or an output path.

/// Parent-root-relative definitions that comprise the source-closure contract.
///
/// The later retained-file loader consumes this literal authority only after
/// the capture and release inventories have been separately reviewed.
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

#[cfg(test)]
mod tests {
  use super::*;
  use deno_lib::standalone::oden_parent_allowlist::ODEN_PARENT_GENERATED_JSON_PATH;
  use deno_lib::standalone::oden_parent_allowlist::ODEN_PARENT_GENERATED_RUST_PATH;

  #[test]
  fn source_closure_contract_paths_are_closed_sorted_literals() {
    assert_eq!(ODEN_PARENT_SOURCE_CLOSURE_CONTRACT_PATHS.len(), 22);

    for path in ODEN_PARENT_SOURCE_CLOSURE_CONTRACT_PATHS {
      assert!(!path.is_empty());
      assert!(path.is_ascii());
      assert!(!path.starts_with('/'));
      assert!(!path.ends_with('/'));
      assert!(!path.contains('\\'));
      assert!(!path.split('/').any(|part| {
        part.is_empty() || part == "." || part == ".."
      }));
      assert_ne!(*path, ODEN_PARENT_GENERATED_JSON_PATH);
      assert_ne!(*path, ODEN_PARENT_GENERATED_RUST_PATH);
    }

    for pair in ODEN_PARENT_SOURCE_CLOSURE_CONTRACT_PATHS.windows(2) {
      assert!(pair[0].as_bytes() < pair[1].as_bytes());
    }

    assert!(ODEN_PARENT_SOURCE_CLOSURE_CONTRACT_PATHS.contains(
      &"fork/deno/cli/lib/standalone/oden_parent_allowlist.rs"
    ));
    assert!(ODEN_PARENT_SOURCE_CLOSURE_CONTRACT_PATHS.contains(
      &"fork/deno/cli/standalone/oden_parent_allowlist.rs"
    ));
  }
}

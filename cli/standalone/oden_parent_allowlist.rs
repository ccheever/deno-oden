// Copyright 2018-2026 the Deno authors. MIT license.

// @ref LLP 0019#frozen-parent-standalone-allowlist-and-byte-graph [implements] —
// These generator-side slices freeze only the exact capture and source-closure
// contract memberships. Release membership, retained-file loading, allowlist
// construction, generate/check execution, and both generated outputs remain
// absent, so neither reserved mode gains authority or an output path.

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

  fn assert_closed_sorted_literals(paths: &[&str], expected_len: usize) {
    assert_eq!(paths.len(), expected_len);

    for path in paths {
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

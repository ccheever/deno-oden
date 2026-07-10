// Copyright 2018-2026 the Deno authors. MIT license.

use deno_error::JsErrorBox;
use deno_npm::NpmSystemInfo;
use deno_npm::registry::NpmPackageVersionInfo;
use deno_npm::resolution::NpmResolutionSnapshot;
use deno_semver::package::PackageNv;

/// A supply-chain verdict source consulted by the npm resolver before package
/// contents can be linked into a project. Implementations own policy, durable
/// caching, and user-facing reporting; the installer owns placement of the
/// gate so warm/shared package caches cannot bypass it.
///
/// `prefetch()` is advisory and must never make a final allow/block decision.
/// It lets a provider overlap lookups with registry and tarball work as concrete
/// versions enter the graph. `ensure_verdicts()` is the authoritative gate.
///
/// @ref llp/0002-the-oden-installer.plan.md#where-the-check-sits
#[async_trait::async_trait(?Send)]
pub trait NpmPackageVerdictProvider: std::fmt::Debug + Send + Sync {
  fn prefetch(&self, _nv: &PackageNv, _version_info: &NpmPackageVersionInfo) {}

  async fn ensure_verdicts(
    &self,
    snapshot: &NpmResolutionSnapshot,
    system_info: &NpmSystemInfo,
    force_refresh: bool,
  ) -> Result<(), JsErrorBox>;
}

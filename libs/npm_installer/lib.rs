// Copyright 2018-2026 the Deno authors. MIT license.

use std::borrow::Cow;
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use deno_config::deno_json::NodeModulesLinkerMode;
use deno_error::JsErrorBox;
use deno_npm::NpmSystemInfo;
use deno_npm::registry::NpmPackageInfo;
use deno_npm::registry::NpmRegistryPackageInfoLoadError;
use deno_npm::resolution::UnmetPeerDepDiagnostic;
use deno_npm_cache::NpmCache;
use deno_npm_cache::NpmCacheHttpClient;
use deno_resolver::lockfile::LockfileLock;
use deno_resolver::npm::managed::NpmResolutionCell;
use deno_resolver::workspace::WorkspaceNpmLinkPackagesRc;
use deno_semver::package::PackageNv;
use deno_semver::package::PackageReq;

mod bin_entries;
mod extra_info;
mod factory;
mod flag;
mod fs;
mod global;
pub mod graph;
mod hoisted;
pub mod initializer;
pub mod lifecycle_scripts;
mod local;
pub mod package_json;
pub mod process_state;
pub mod resolution;
mod rt;

pub use bin_entries::BinEntries;
use deno_terminal::colors;
use deno_unsync::sync::AtomicFlag;
use deno_unsync::sync::TaskQueue;
use parking_lot::Mutex;
use rustc_hash::FxHashSet;

pub use self::extra_info::CachedNpmPackageExtraInfoProvider;
pub use self::extra_info::ExpectedExtraInfo;
pub use self::extra_info::NpmPackageExtraInfoProvider;
use self::extra_info::NpmPackageExtraInfoProviderSys;
pub use self::factory::InstallReporter;
pub use self::factory::NpmInstallerFactory;
pub use self::factory::NpmInstallerFactoryOptions;
pub use self::factory::NpmInstallerFactorySys;
use self::global::GlobalNpmPackageInstaller;
use self::hoisted::HoistedNpmPackageInstaller;
use self::initializer::NpmResolutionInitializer;
use self::lifecycle_scripts::LifecycleScriptsExecutor;
use self::local::LocalNpmInstallSys;
use self::local::LocalNpmPackageInstaller;
use self::local::LocalNpmPackageInstallerOptions;
pub use self::local::LocalSetupCache;
pub use self::local::node_modules_package_actual_dir_to_name;
pub use self::local::remove_unused_node_modules_symlinks;
use self::package_json::EnsurePackageJsonDepsError;
use self::package_json::NpmInstallDepsProvider;
use self::resolution::AddPkgReqsResult;
use self::resolution::NpmResolutionInstaller;
use self::resolution::NpmResolutionInstallerSys;
pub use self::resolution::format_unmet_peer_dep_warning;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PackageCaching<'a> {
  Only(Cow<'a, [PackageReq]>),
  All,
}

/// The set of npm packages that are allowed to run lifecycle scripts.
#[derive(Debug, Clone, Eq, PartialEq, Default)]
pub enum PackagesAllowedScripts {
  All,
  Some(Vec<PackageReq>),
  #[default]
  None,
}

/// Info needed to run NPM lifecycle scripts
#[derive(Clone, Debug, Eq, PartialEq, Default)]
pub struct LifecycleScriptsConfig {
  pub allowed: PackagesAllowedScripts,
  pub denied: Vec<PackageReq>,
  pub initial_cwd: PathBuf,
  pub root_dir: PathBuf,
  /// Part of an explicit `deno install`
  pub explicit_install: bool,
}

pub trait InstallProgressReporter:
  std::fmt::Debug + Send + Sync + 'static
{
  fn blocking(&self, message: &str);
  fn initializing(&self, nv: &PackageNv);
  fn initialized(&self, nv: &PackageNv);

  fn scripts_not_run_warning(
    &self,
    warning: crate::lifecycle_scripts::LifecycleScriptsWarning,
  );

  fn deprecated_message(&self, message: String);
}
pub trait Reporter: std::fmt::Debug + Send + Sync + Clone + 'static {
  type Guard;
  type ClearGuard;

  fn on_blocking(&self, message: &str) -> Self::Guard;
  fn on_initializing(&self, message: &str) -> Self::Guard;
  fn clear_guard(&self) -> Self::ClearGuard;
}

#[derive(Debug, Clone)]
pub struct LogReporter;

impl Reporter for LogReporter {
  type Guard = ();
  type ClearGuard = ();

  fn on_blocking(&self, message: &str) -> Self::Guard {
    log::info!("{} {}", deno_terminal::colors::cyan("Blocking"), message);
  }

  fn on_initializing(&self, message: &str) -> Self::Guard {
    log::info!("{} {}", deno_terminal::colors::green("Initialize"), message);
  }

  fn clear_guard(&self) -> Self::ClearGuard {}
}

/// Part of the resolution that interacts with the file system.
#[async_trait::async_trait(?Send)]
pub(crate) trait NpmPackageFsInstaller:
  std::fmt::Debug + Send + Sync
{
  async fn cache_packages<'a>(
    &self,
    caching: PackageCaching<'a>,
  ) -> Result<(), JsErrorBox>;
}

#[sys_traits::auto_impl]
pub trait NpmInstallerSys:
  NpmResolutionInstallerSys + LocalNpmInstallSys + NpmPackageExtraInfoProviderSys
{
}

pub struct NpmInstallerOptions<TSys: NpmInstallerSys> {
  pub clean_on_install: bool,
  pub maybe_lockfile: Option<Arc<LockfileLock<TSys>>>,
  pub maybe_node_modules_path: Option<PathBuf>,
  pub linker_mode: NodeModulesLinkerMode,
  pub lifecycle_scripts: Arc<LifecycleScriptsConfig>,
  pub system_info: NpmSystemInfo,
  pub workspace_link_packages: WorkspaceNpmLinkPackagesRc,
  /// Whether `jsr:` dependencies are installed into `node_modules` via JSR's
  /// npm compatibility registry (the `jsrDepsInNodeModules` config option).
  pub jsr_deps_in_node_modules: bool,
}

#[derive(Debug)]
pub struct NpmInstaller<
  TNpmCacheHttpClient: NpmCacheHttpClient,
  TSys: NpmInstallerSys,
> {
  fs_installer: Arc<dyn NpmPackageFsInstaller>,
  npm_install_deps_provider: Arc<NpmInstallDepsProvider>,
  npm_resolution_initializer: Arc<NpmResolutionInitializer<TSys>>,
  npm_resolution_installer:
    Arc<NpmResolutionInstaller<TNpmCacheHttpClient, TSys>>,
  maybe_lockfile: Option<Arc<LockfileLock<TSys>>>,
  npm_cache: Arc<NpmCache<TSys>>,
  npm_resolution: Arc<NpmResolutionCell>,
  system_info: NpmSystemInfo,
  tarball_cache: Arc<deno_npm_cache::TarballCache<TNpmCacheHttpClient, TSys>>,
  /// See [`Self::enable_tarball_prefetch`].
  tarball_prefetch_flag: AtomicFlag,
  top_level_install_flag: AtomicFlag,
  install_queue: TaskQueue,
  cached_reqs: Mutex<FxHashSet<PackageReq>>,
}

/// Maximum tarball downloads a prefetcher runs concurrently, or `None` when
/// prefetching is disabled. Even with the tarball cache on its own
/// connection pool, an uncapped prefetch flood competes with packument
/// fetches for bandwidth and stretches resolution — measured on the LLP
/// 0002 fixture, uncapped prefetching on a shared connection stretched
/// resolution from ~4.7s to ~12.6s and made the cold install slower than no
/// prefetching at all. The post-resolution caching pass is intentionally
/// not capped (nothing else needs the network by then); this cap only
/// protects the resolution window. `DENO_NPM_PREFETCH_CONCURRENCY`
/// overrides it for tuning; `0` disables prefetching entirely.
fn prefetch_downloads_cap() -> Option<usize> {
  #[allow(
    clippy::disallowed_methods,
    reason = "process-global tuning/kill-switch knob, deliberately not per-sys"
  )]
  match std::env::var("DENO_NPM_PREFETCH_CONCURRENCY")
    .ok()
    .and_then(|v| v.parse::<usize>().ok())
  {
    Some(0) => None,
    Some(n) => Some(n),
    None => Some(16),
  }
}

// @ref llp/0002-the-oden-installer.plan.md#the-recipe
/// Fire-and-forget tarball prefetcher: spawns `TarballCache::ensure_package`
/// for each version the resolver settles on, so downloads and extraction
/// overlap the packument fetch wave instead of starting after resolution
/// completes. `ensure_package` deduplicates in-flight work internally (the
/// post-resolution caching pass joins the same in-flight future rather than
/// re-downloading) and its failures are recorded there too, so errors here
/// are only logged: packages that stay in the graph surface the same error
/// through the caching pass, and versions that left the graph don't matter.
#[derive(Debug)]
struct SpawningTarballPrefetcher<
  TNpmCacheHttpClient: NpmCacheHttpClient,
  TSys: NpmInstallerSys,
> {
  seen: Mutex<FxHashSet<PackageNv>>,
  system_info: NpmSystemInfo,
  #[cfg(not(target_arch = "wasm32"))]
  download_permits: Arc<tokio::sync::Semaphore>,
  tarball_cache: Arc<deno_npm_cache::TarballCache<TNpmCacheHttpClient, TSys>>,
}

impl<TNpmCacheHttpClient: NpmCacheHttpClient, TSys: NpmInstallerSys>
  resolution::TarballPrefetcher
  for SpawningTarballPrefetcher<TNpmCacheHttpClient, TSys>
{
  fn prefetch(
    &self,
    nv: &PackageNv,
    version_info: &deno_npm::registry::NpmPackageVersionInfo,
  ) {
    let Some(dist) = &version_info.dist else {
      return;
    };
    // Optional os/cpu-specific packages for other platforms stay in the
    // resolution graph and are only filtered out at install time — measured
    // on the LLP 0002 fixture they are over half the tarball bytes
    // (platform binaries like @next/swc-* for every platform), so filter
    // here too rather than downloading them.
    let system = deno_npm::NpmResolutionPackageSystemInfo {
      cpu: version_info.cpu.clone(),
      os: version_info.os.clone(),
    };
    if !system.matches_system(&self.system_info) {
      return;
    }
    if !self.seen.lock().insert(nv.clone()) {
      return;
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
      let download_permits = self.download_permits.clone();
      let tarball_cache = self.tarball_cache.clone();
      let nv = nv.clone();
      let dist = dist.clone();
      drop(deno_unsync::spawn(async move {
        let Ok(_permit) = download_permits.acquire_owned().await else {
          return; // semaphore closed (never happens; defensive)
        };
        if let Err(err) = tarball_cache.ensure_package(&nv, &dist).await {
          log::debug!("npm tarball prefetch failed for {nv}: {err:#}");
        }
      }));
    }
  }
}

impl<TNpmCacheHttpClient: NpmCacheHttpClient, TSys: NpmInstallerSys>
  NpmInstaller<TNpmCacheHttpClient, TSys>
{
  #[allow(clippy::too_many_arguments, reason = "construction")]
  pub fn new<TReporter: Reporter>(
    install_reporter: Option<Arc<dyn InstallReporter>>,
    lifecycle_scripts_executor: Arc<dyn LifecycleScriptsExecutor>,
    npm_cache: Arc<NpmCache<TSys>>,
    npm_install_deps_provider: Arc<NpmInstallDepsProvider>,
    npm_registry_info_provider: Arc<
      dyn deno_npm::registry::NpmRegistryApi + Send + Sync,
    >,
    npm_resolution: Arc<NpmResolutionCell>,
    npm_resolution_initializer: Arc<NpmResolutionInitializer<TSys>>,
    npm_resolution_installer: Arc<
      NpmResolutionInstaller<TNpmCacheHttpClient, TSys>,
    >,
    reporter: &TReporter,
    sys: TSys,
    tarball_cache: Arc<deno_npm_cache::TarballCache<TNpmCacheHttpClient, TSys>>,
    options: NpmInstallerOptions<TSys>,
  ) -> Self {
    let system_info = options.system_info.clone();
    let fs_installer: Arc<dyn NpmPackageFsInstaller> =
      match options.maybe_node_modules_path {
        Some(node_modules_folder) => {
          let extra_info_provider = Arc::new(NpmPackageExtraInfoProvider::new(
            npm_registry_info_provider,
            Arc::new(sys.clone()),
            options.workspace_link_packages,
          ));
          match options.linker_mode {
            NodeModulesLinkerMode::Hoisted => {
              Arc::new(HoistedNpmPackageInstaller::new(
                lifecycle_scripts_executor,
                npm_cache.clone(),
                extra_info_provider,
                npm_install_deps_provider.clone(),
                (*reporter).clone(),
                npm_resolution.clone(),
                sys,
                tarball_cache.clone(),
                LocalNpmPackageInstallerOptions {
                  clean_on_install: options.clean_on_install,
                  lifecycle_scripts: options.lifecycle_scripts,
                  system_info: options.system_info,
                  reporter: install_reporter,
                  node_modules_folder,
                  jsr_deps_in_node_modules: options.jsr_deps_in_node_modules,
                },
              ))
            }
            NodeModulesLinkerMode::Isolated => {
              Arc::new(LocalNpmPackageInstaller::new(
                lifecycle_scripts_executor,
                npm_cache.clone(),
                extra_info_provider,
                npm_install_deps_provider.clone(),
                (*reporter).clone(),
                npm_resolution.clone(),
                sys,
                tarball_cache.clone(),
                LocalNpmPackageInstallerOptions {
                  clean_on_install: options.clean_on_install,
                  lifecycle_scripts: options.lifecycle_scripts,
                  system_info: options.system_info,
                  reporter: install_reporter,
                  node_modules_folder,
                  jsr_deps_in_node_modules: options.jsr_deps_in_node_modules,
                },
              ))
            }
          }
        }
        None => Arc::new(GlobalNpmPackageInstaller::new(
          npm_cache.clone(),
          tarball_cache.clone(),
          sys,
          npm_resolution.clone(),
          options.lifecycle_scripts,
          options.system_info,
          install_reporter,
        )),
      };
    Self {
      fs_installer,
      npm_install_deps_provider,
      npm_cache,
      npm_resolution,
      npm_resolution_initializer,
      npm_resolution_installer,
      maybe_lockfile: options.maybe_lockfile,
      system_info,
      tarball_cache,
      tarball_prefetch_flag: Default::default(),
      top_level_install_flag: Default::default(),
      install_queue: Default::default(),
      cached_reqs: Default::default(),
    }
  }

  /// Opts this installer into tarball prefetching: subsequent resolutions
  /// start downloading a package's tarball the moment its version is
  /// chosen, overlapping the packument fetch wave (the dominant
  /// cold-install phase) instead of downloading everything afterwards.
  /// Only call this from flows that will certainly cache every resolved
  /// package afterwards (the explicit install flows); resolution-only
  /// flows (`deno outdated`, `--lockfile-only`) must not, or they would
  /// download every tarball, and `deno run`-style auto-install stays
  /// opted out so its download-progress output stays deterministic.
  pub fn enable_tarball_prefetch(&self) {
    self.tarball_prefetch_flag.raise();
  }

  /// Adds package requirements to the resolver and ensures everything is setup.
  /// This includes setting up the `node_modules` directory, if applicable.
  pub async fn add_and_cache_package_reqs(
    &self,
    packages: &[PackageReq],
  ) -> Result<(), JsErrorBox> {
    self.npm_resolution_initializer.ensure_initialized().await?;
    let result = self
      .add_package_reqs_raw(
        packages,
        Some(PackageCaching::Only(packages.into())),
      )
      .await;
    self.warn_unmet_peer_diagnostics();
    result.dependencies_result
  }

  pub async fn add_package_reqs_no_cache(
    &self,
    packages: &[PackageReq],
  ) -> Result<(), JsErrorBox> {
    self.npm_resolution_initializer.ensure_initialized().await?;
    let result = self.add_package_reqs_raw(packages, None).await;
    self.warn_unmet_peer_diagnostics();
    result.dependencies_result
  }

  pub async fn add_package_reqs(
    &self,
    packages: &[PackageReq],
    caching: PackageCaching<'_>,
  ) -> Result<(), JsErrorBox> {
    self.npm_resolution_initializer.ensure_initialized().await?;
    let result = self.add_package_reqs_raw(packages, Some(caching)).await;
    self.warn_unmet_peer_diagnostics();
    result.dependencies_result
  }

  /// Drains the unmet peer dependency diagnostics collected during npm
  /// resolution. Callers that have a module graph available should render these
  /// with [`format_unmet_peer_dep_warning`] and an importer map; otherwise see
  /// [`Self::warn_unmet_peer_diagnostics`].
  pub fn take_unmet_peer_diagnostics(&self) -> Vec<UnmetPeerDepDiagnostic> {
    self.npm_resolution_installer.take_unmet_peer_diagnostics()
  }

  /// Renders any pending unmet peer dependency diagnostics without importer
  /// information. Used by resolution entry points that don't build a module
  /// graph (the importing module isn't known there anyway).
  fn warn_unmet_peer_diagnostics(&self) {
    if !log::log_enabled!(log::Level::Warn) {
      // still drain so the diagnostics don't accumulate
      let _ = self.take_unmet_peer_diagnostics();
      return;
    }
    let diagnostics = self.take_unmet_peer_diagnostics();
    if !diagnostics.is_empty() {
      log::warn!(
        "{}",
        format_unmet_peer_dep_warning(&diagnostics, &HashMap::new())
      );
    }
  }

  pub async fn add_package_reqs_raw(
    &self,
    packages: &[PackageReq],
    caching: Option<PackageCaching<'_>>,
  ) -> AddPkgReqsResult {
    if packages.is_empty() && !self.npm_resolution.is_pending() {
      return AddPkgReqsResult {
        dependencies_result: Ok(()),
        results: vec![],
      };
    }

    #[cfg(debug_assertions)]
    self.npm_resolution_initializer.debug_assert_initialized();

    // Overlap tarball downloads with resolution: while the resolver is still
    // fetching packuments, versions it has already settled on can start
    // downloading and extracting into the global cache. Only armed for
    // flows that opted in via `enable_tarball_prefetch` (the explicit
    // install flows, which cache every resolved package right after) and
    // when downloading is allowed at all. Deliberately not armed for
    // `deno run`-style auto-install even though it caches too: prefetch
    // interleaves download progress lines nondeterministically, and the
    // run flow's output is asserted byte-for-byte by a large spec corpus —
    // if it opts in later, its download reporting needs to be made
    // order-insensitive first.
    let prefetch_cap = if self.tarball_prefetch_flag.is_raised()
      && !matches!(
        self.npm_cache.cache_setting(),
        deno_npm_cache::NpmCacheSetting::Only
      ) {
      prefetch_downloads_cap()
    } else {
      None
    };
    let prefetch = prefetch_cap.is_some();
    if let Some(cap) = prefetch_cap {
      #[cfg(target_arch = "wasm32")]
      let _ = cap;
      self.npm_resolution_installer.set_tarball_prefetcher(Some(
        Arc::new(SpawningTarballPrefetcher {
          seen: Default::default(),
          system_info: self.system_info.clone(),
          #[cfg(not(target_arch = "wasm32"))]
          download_permits: Arc::new(tokio::sync::Semaphore::new(cap)),
          tarball_cache: self.tarball_cache.clone(),
        }),
      ));
    }
    let mut result = self
      .npm_resolution_installer
      .add_package_reqs(packages)
      .await;
    if prefetch {
      self.npm_resolution_installer.set_tarball_prefetcher(None);
    }

    if result.dependencies_result.is_ok()
      && let Some(lockfile) = self.maybe_lockfile.as_ref()
    {
      result.dependencies_result = lockfile.error_if_changed();
    }
    if result.dependencies_result.is_ok()
      && let Some(caching) = caching
    {
      result.dependencies_result =
        self.maybe_cache_packages(packages, caching).await;
    }

    result
  }

  async fn maybe_cache_packages(
    &self,
    packages: &[PackageReq],
    caching: PackageCaching<'_>,
  ) -> Result<(), JsErrorBox> {
    // the async mutex is unfortunate, but needed to handle the edge case where two workers
    // try to cache the same package at the same time. we need to hold the lock while we cache
    // and since that crosses an await point, we need the async mutex.
    //
    // should have a negligible perf impact because acquiring the lock is still in the order of nanoseconds
    // while caching typically takes micro or milli seconds.
    let _permit = self.install_queue.acquire().await;
    let uncached = {
      let cached_reqs = self.cached_reqs.lock();
      packages
        .iter()
        .filter(|req| !cached_reqs.contains(req))
        .collect::<Vec<_>>()
    };

    if uncached.is_empty() {
      // Even when every requested package is already cached we still need to
      // sync the node_modules directory for a full install (e.g. after
      // `deno remove`), otherwise stale packages are left on disk. Only do this
      // for `All` caching so the hot path of running a script (which caches a
      // specific subset) keeps short-circuiting.
      if matches!(caching, PackageCaching::All) {
        return self.fs_installer.cache_packages(caching).await;
      }
      return Ok(());
    }
    let result = self.fs_installer.cache_packages(caching).await;
    if result.is_ok() {
      let mut cached_reqs = self.cached_reqs.lock();
      for req in uncached {
        cached_reqs.insert(req.clone());
      }
    }
    result
  }

  pub async fn cache_package_info(
    &self,
    package_name: &str,
  ) -> Result<Arc<NpmPackageInfo>, NpmRegistryPackageInfoLoadError> {
    self
      .npm_resolution_installer
      .cache_package_info(package_name)
      .await
  }

  pub async fn cache_packages(
    &self,
    caching: PackageCaching<'_>,
  ) -> Result<(), JsErrorBox> {
    if self.npm_resolution.is_pending() {
      self.add_package_reqs(&[], caching).await
    } else {
      self.npm_resolution_initializer.ensure_initialized().await?;
      self.fs_installer.cache_packages(caching).await
    }
  }

  pub fn ensure_no_pkg_json_dep_errors(
    &self,
  ) -> Result<(), EnsurePackageJsonDepsError> {
    for err in self.npm_install_deps_provider.pkg_json_dep_errors() {
      match err.source.as_kind() {
        deno_package_json::PackageJsonDepValueParseErrorKind::JsrRequiresScope { .. } |
        deno_package_json::PackageJsonDepValueParseErrorKind::VersionReq { .. } => {
          return Err(Box::new(err.clone()).into());
        }
        deno_package_json::PackageJsonDepValueParseErrorKind::Unsupported {
          ..
        }
        | deno_package_json::PackageJsonDepValueParseErrorKind::EmptyName => {
          // only warn for these
          log::warn!(
            "{} {}\n    at {}",
            colors::yellow("Warning"),
            err.source,
            err.location,
          )
        }
      }
    }
    // A `workspace:<range>` whose member version doesn't satisfy the range is
    // always a hard error, the same way `deno run` rejects it during
    // resolution.
    if let Some(err) = self
      .npm_install_deps_provider
      .workspace_member_version_errors()
      .first()
    {
      return Err(Box::new(err.clone()).into());
    }
    Ok(())
  }

  /// Ensures that the top level `package.json` dependencies are installed.
  ///
  /// Returns `true` if the top level packages are already installed. A
  /// return value of `false` means that new packages were added to the npm resolution.
  pub async fn ensure_top_level_package_json_install(
    &self,
  ) -> Result<bool, JsErrorBox> {
    if !self.top_level_install_flag.raise() {
      return Ok(true); // already did this
    }

    self.npm_resolution_initializer.ensure_initialized().await?;

    let pkg_json_remote_pkgs = self.npm_install_deps_provider.remote_pkgs();
    if pkg_json_remote_pkgs.is_empty() {
      return Ok(true);
    }

    // check if something needs resolving before bothering to load all
    // the package information (which is slow). As in the resolver fast path,
    // when offline (`--cached-only`) prefer the existing resolution over a
    // re-resolution that would need registry metadata not in the cache, even
    // if the lockfile was flagged as changed for a non-npm reason.
    if (!self.npm_resolution.is_pending()
      || self.npm_resolution_installer.is_cached_only())
      && pkg_json_remote_pkgs.iter().all(|pkg| {
        self
          .npm_resolution
          .resolve_pkg_id_from_pkg_req(&pkg.req)
          .is_ok()
      })
    {
      log::debug!(
        "All package.json deps resolvable. Skipping top level install."
      );
      return Ok(true); // everything is already resolvable
    }

    let pkg_reqs = pkg_json_remote_pkgs
      .iter()
      .map(|pkg| pkg.req.clone())
      .collect::<Vec<_>>();
    self.add_package_reqs_no_cache(&pkg_reqs).await?;

    Ok(false)
  }

  /// Run a resolution install if the npm snapshot is in a pending state
  /// due to a config file change.
  pub async fn install_resolution_if_pending(&self) -> Result<(), JsErrorBox> {
    self.npm_resolution_initializer.ensure_initialized().await?;
    self
      .npm_resolution_installer
      .install_if_pending()
      .await
      .map_err(JsErrorBox::from_err)?;
    self.warn_unmet_peer_diagnostics();
    Ok(())
  }
}

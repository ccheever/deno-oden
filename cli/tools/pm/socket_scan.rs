// Copyright 2018-2026 the Deno authors. MIT license.

use std::collections::BTreeMap;
use std::collections::HashMap;
use std::collections::HashSet;
use std::collections::VecDeque;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use std::time::Instant;
use std::time::SystemTime;
use std::time::UNIX_EPOCH;

use base64::Engine;
use base64::engine::general_purpose::STANDARD_NO_PAD;
use deno_core::error::AnyError;
use deno_core::futures;
use deno_core::futures::StreamExt;
use deno_core::parking_lot::Mutex;
use deno_core::serde::Deserialize;
use deno_core::serde::Serialize;
use deno_core::serde_json;
use deno_core::url::Url;
use deno_error::JsErrorBox;
use deno_npm::NpmPackageId;
use deno_npm::NpmSystemInfo;
use deno_npm::registry::NpmPackageVersionInfo;
use deno_npm::resolution::NpmResolutionSnapshot;
use deno_npm_installer::verdicts::NpmPackageVerdictProvider;
use deno_npmrc::ResolvedNpmRc;
use deno_path_util::fs::atomic_write_file_with_retries;
use deno_semver::package::PackageNv;
use hmac::Hmac;
use hmac::Mac;
use http::header::AUTHORIZATION;
use http::header::HeaderValue;
use sha2::Sha256;
use sys_traits::FsFileLock;
use sys_traits::FsFileLockMode;

use crate::http_util;
use crate::http_util::HttpClientProvider;
use crate::sys::CliSys;

const STORE_VERSION: u8 = 1;
const REPORT_VERSION: u8 = 1;
const DEFAULT_TTL_SECS: u64 = 24 * 60 * 60;
const MAX_BATCH_SIZE: usize = 1024;
const ANONYMOUS_CONCURRENCY: usize = 20;
const DEFAULT_PUBLIC_REGISTRY: &str = deno_npmrc::NPM_DEFAULT_REGISTRY;
const DEFAULT_ANONYMOUS_API: &str = "https://firewall-api.socket.dev/";
const DEFAULT_ORG_API: &str = "https://api.socket.dev/";
const MAX_STORE_ENTRIES: usize = 16_384;
const MAX_STORE_BYTES: usize = 16 * 1024 * 1024;
const MAX_STORE_FIELD_BYTES: usize = 16 * 1024;
const MAX_PERSISTED_TTL_SECS: u64 = 7 * 24 * 60 * 60;
const MAX_FUTURE_CLOCK_SKEW_SECS: u64 = 5 * 60;
const STORE_LOCK_TIMEOUT: Duration = Duration::from_secs(30);
const STORE_LOCK_RETRY: Duration = Duration::from_millis(10);

// @ref llp/0002-the-oden-installer.plan.md#failure-mode
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum ScanMode {
  Default,
  Strict,
  Off,
  Audit,
}

impl ScanMode {
  fn from_env() -> Result<Option<Self>, JsErrorBox> {
    let Some(value) = std::env::var("ODEN_SOCKET_SCAN_MODE").ok() else {
      return Ok(None);
    };
    let mode = match value.as_str() {
      "default" => Self::Default,
      "strict" => Self::Strict,
      "off" => Self::Off,
      "audit" => Self::Audit,
      _ => {
        return Err(JsErrorBox::type_error(format!(
          "invalid ODEN_SOCKET_SCAN_MODE {value:?}; expected default, strict, off, or audit"
        )));
      }
    };
    Ok(Some(mode))
  }

  fn requires_live_non_blocking_proof(self) -> bool {
    matches!(self, Self::Strict | Self::Audit)
  }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
enum VerdictStatus {
  Clean,
  Blocked,
  Suspicious,
  Unverified,
  UnscannedByPolicy,
  UnsupportedSource,
}

impl VerdictStatus {
  fn as_str(&self) -> &'static str {
    match self {
      Self::Clean => "clean",
      Self::Blocked => "blocked",
      Self::Suspicious => "suspicious",
      Self::Unverified => "unverified",
      Self::UnscannedByPolicy => "unscanned_by_policy",
      Self::UnsupportedSource => "unsupported_source",
    }
  }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct Finding {
  r#type: String,
  #[serde(skip_serializing_if = "Option::is_none")]
  severity: Option<String>,
  #[serde(skip_serializing_if = "Option::is_none")]
  action: Option<String>,
  #[serde(skip_serializing_if = "Option::is_none")]
  id: Option<String>,
}

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct CachedVerdict {
  name: String,
  version: String,
  #[serde(skip_serializing_if = "Option::is_none")]
  integrity: Option<String>,
  status: VerdictStatus,
  provider: String,
  checked_at: u64,
  expires_at: u64,
  #[serde(skip_serializing_if = "Option::is_none")]
  finding: Option<Finding>,
}

#[derive(Clone, Debug, Default, Deserialize, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct VerdictStore {
  v: u8,
  entries: BTreeMap<String, CachedVerdict>,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct PackageRequest {
  name: String,
  version: String,
  integrity: Option<String>,
  /// Registry selected by the current npm configuration.
  registry: String,
  /// Persisted resolved tarball URL. This remains authoritative when a
  /// lockfile is reused under different npm configuration.
  tarball: String,
}

impl PackageRequest {
  fn purl(&self) -> String {
    format!("pkg:npm/{}@{}", self.name, self.version)
  }

  fn key(&self) -> String {
    format!(
      "{}|{}|{}|{}",
      self.report_registry(),
      tarball_provenance(&self.tarball),
      self.purl(),
      self.integrity.as_deref().unwrap_or("integrity-unknown")
    )
  }

  fn report_registry(&self) -> String {
    if tarball_belongs_to_registry(&self.tarball, &self.registry) {
      normalize_registry(&self.registry)
    } else {
      tarball_origin_registry(&self.tarball)
        .unwrap_or_else(|| normalize_registry(&self.registry))
    }
  }
}

fn cached_entry_matches_request(
  entry: &CachedVerdict,
  request: &PackageRequest,
) -> bool {
  entry.name == request.name
    && entry.version == request.version
    && entry.integrity == request.integrity
}

fn live_entry(
  request: &PackageRequest,
  status: VerdictStatus,
  finding: Option<Finding>,
  now: u64,
  ttl_secs: u64,
) -> CachedVerdict {
  CachedVerdict {
    name: request.name.clone(),
    version: request.version.clone(),
    integrity: request.integrity.clone(),
    status,
    provider: "socket".to_string(),
    checked_at: now,
    expires_at: now.saturating_add(ttl_secs),
    finding,
  }
}

fn unverified_entry(
  request: &PackageRequest,
  now: u64,
  kind: &str,
  detail: Option<String>,
) -> CachedVerdict {
  CachedVerdict {
    name: request.name.clone(),
    version: request.version.clone(),
    integrity: request.integrity.clone(),
    status: VerdictStatus::Unverified,
    provider: "socket".to_string(),
    checked_at: now,
    expires_at: now,
    finding: Some(Finding {
      r#type: kind.to_string(),
      severity: None,
      action: None,
      id: detail,
    }),
  }
}

#[derive(Clone, Debug)]
enum LookupResult {
  Verdict {
    status: VerdictStatus,
    finding: Option<Finding>,
  },
  Unavailable(String),
}

// @ref llp/0002-the-oden-installer.plan.md#verdict-cache-revocation-and-re-checking
// [constrained-by] — The per-user store has no lifecycle-script-inaccessible
// key. Strict mode and audit therefore require live proof for every
// non-blocking cached result; default mode may honor cached conclusive state
// only as its declared fail-open posture, within the validated TTL and with
// expiry-driven refresh. Cached blocks stay fail-closed while revalidation is
// unavailable, including across policy opt-out writes.
fn select_public_entry(
  mode: ScanMode,
  request: &PackageRequest,
  previous: Option<CachedVerdict>,
  lookup: Option<LookupResult>,
  live_proved_in_operation: bool,
  now: u64,
  ttl_secs: u64,
) -> (CachedVerdict, bool, bool) {
  match lookup {
    Some(LookupResult::Verdict { status, finding }) => (
      live_entry(request, status, finding, now, ttl_secs),
      false,
      false,
    ),
    Some(LookupResult::Unavailable(error)) => {
      let previous = previous.filter(|entry| {
        cached_entry_matches_request(entry, request)
          && entry.provider == "socket"
      });
      match previous {
        Some(previous) if previous.status == VerdictStatus::Blocked => {
          (previous, true, true)
        }
        Some(previous)
          if !mode.requires_live_non_blocking_proof()
            && matches!(
              previous.status,
              VerdictStatus::Clean | VerdictStatus::Suspicious
            ) =>
        {
          (previous, true, true)
        }
        _ => (
          unverified_entry(request, now, "provider_unavailable", Some(error)),
          false,
          false,
        ),
      }
    }
    None => {
      let previous = previous.filter(|entry| {
        cached_entry_matches_request(entry, request)
          && entry.provider == "socket"
      });
      match previous {
        Some(previous)
          if mode.requires_live_non_blocking_proof()
            && !live_proved_in_operation
            && matches!(
              previous.status,
              VerdictStatus::Clean | VerdictStatus::Suspicious
            ) =>
        {
          (
            unverified_entry(request, now, "live_verdict_required", None),
            false,
            false,
          )
        }
        Some(previous) => {
          let cached = if matches!(
            previous.status,
            VerdictStatus::Clean
              | VerdictStatus::Suspicious
              | VerdictStatus::Blocked
          ) {
            !live_proved_in_operation
          } else {
            false
          };
          let stale = cached
            && previous.expires_at <= now
            && matches!(
              previous.status,
              VerdictStatus::Clean
                | VerdictStatus::Suspicious
                | VerdictStatus::Blocked
            );
          if !cached {
            // A prior gate in this command obtained or attempted the live
            // result. Do not relabel that result as persisted-cache proof.
            (previous, false, stale)
          } else {
            (previous, true, stale)
          }
        }
        None => (
          unverified_entry(request, now, "missing_verdict", None),
          false,
          false,
        ),
      }
    }
  }
}

#[derive(Debug, Default)]
struct PrefetchState {
  queued: BTreeMap<String, PackageRequest>,
  results: HashMap<String, LookupResult>,
  worker_running: bool,
}

#[derive(Clone)]
struct SecretString(String);

impl std::fmt::Debug for SecretString {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.write_str("[redacted]")
  }
}

#[derive(Clone)]
struct SecretBytes(Vec<u8>);

impl std::fmt::Debug for SecretBytes {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.write_str("[redacted]")
  }
}

#[derive(Debug)]
struct ProviderInner {
  http_client_provider: Arc<HttpClientProvider>,
  npmrc: Arc<ResolvedNpmRc>,
  public_registry: String,
  api_key: Option<SecretString>,
  org_slug: Option<String>,
  store_path: PathBuf,
  report_path: Option<PathBuf>,
  report_key: Option<SecretBytes>,
  mode: ScanMode,
  ttl_secs: u64,
  store: Mutex<VerdictStore>,
  prefetch: Mutex<PrefetchState>,
  prefetch_notify: tokio::sync::Notify,
  checked_this_operation: Mutex<HashSet<String>>,
  live_entries_this_operation: Mutex<HashMap<String, CachedVerdict>>,
}

#[derive(Clone, Debug)]
pub struct SocketVerdictProvider {
  inner: Arc<ProviderInner>,
}

impl SocketVerdictProvider {
  pub fn from_env(
    http_client_provider: Arc<HttpClientProvider>,
    npmrc: Arc<ResolvedNpmRc>,
    npm_cache_root: PathBuf,
  ) -> Result<Option<Arc<dyn NpmPackageVerdictProvider>>, JsErrorBox> {
    let Some(mode) = ScanMode::from_env()? else {
      return Ok(None);
    };
    let public_registry = std::env::var("ODEN_SOCKET_PUBLIC_REGISTRY")
      .unwrap_or_else(|_| DEFAULT_PUBLIC_REGISTRY.to_string());
    let ttl_secs = std::env::var("ODEN_SOCKET_VERDICT_TTL_SECS")
      .ok()
      .and_then(|value| value.parse().ok())
      .unwrap_or(DEFAULT_TTL_SECS)
      .min(MAX_PERSISTED_TTL_SECS);
    let store_path =
      npm_cache_root.join(".oden").join("socket-verdicts-v1.json");
    let report_path =
      std::env::var_os("ODEN_SOCKET_REPORT_PATH").map(PathBuf::from);
    let report_key = read_report_key()?;
    let api_key = if mode == ScanMode::Off {
      None
    } else {
      read_api_key()?
    };
    let org_slug = (mode != ScanMode::Off)
      .then(|| std::env::var("SOCKET_ORG_SLUG").ok())
      .flatten();
    let store = load_store(&store_path);
    Ok(Some(Arc::new(Self {
      inner: Arc::new(ProviderInner {
        http_client_provider,
        npmrc,
        public_registry: normalize_registry(&public_registry),
        api_key,
        org_slug,
        store_path,
        report_path,
        report_key,
        mode,
        ttl_secs,
        store: Mutex::new(store),
        prefetch: Default::default(),
        prefetch_notify: Default::default(),
        checked_this_operation: Default::default(),
        live_entries_this_operation: Default::default(),
      }),
    })))
  }

  fn request_for_version_info(
    &self,
    nv: &PackageNv,
    version_info: &NpmPackageVersionInfo,
  ) -> Option<PackageRequest> {
    let dist = version_info.dist.as_ref()?;
    let registry = self.inner.npmrc.get_registry_url(&nv.name).to_string();
    Some(PackageRequest {
      name: nv.name.to_string(),
      version: nv.version.to_string(),
      integrity: dist.integrity().for_lockfile().map(|v| v.into_owned()),
      registry,
      tarball: dist.tarball.clone(),
    })
  }

  // @ref llp/0002-the-oden-installer.plan.md#privacy [implements] — Current
  // registry configuration and persisted tarball provenance must both be
  // public before an identity may leave the installer.
  fn is_public_request(&self, request: &PackageRequest) -> bool {
    normalize_registry(&request.registry) == self.inner.public_registry
      && tarball_belongs_to_registry(
        &request.tarball,
        &self.inner.public_registry,
      )
  }

  fn cache_is_fresh(&self, request: &PackageRequest, now: u64) -> bool {
    if request.integrity.is_none() {
      // A version-only cache entry cannot distinguish a republished tarball.
      return false;
    }
    let key = request.key();
    let live_entry = self
      .inner
      .live_entries_this_operation
      .lock()
      .get(&key)
      .cloned();
    if live_entry.is_some_and(|entry| {
      cached_entry_matches_request(&entry, request)
        && entry.provider == "socket"
        && matches!(
          entry.status,
          VerdictStatus::Clean
            | VerdictStatus::Suspicious
            | VerdictStatus::Blocked
        )
    }) {
      return true;
    }
    if self.inner.mode.requires_live_non_blocking_proof() {
      // Strict/audit cannot use the unauthenticated store as proof. Default
      // mode may use a structurally valid fresh entry as its explicitly
      // bounded fail-open performance hint; expiry still schedules refresh.
      return false;
    }
    self
      .inner
      .store
      .lock()
      .entries
      .get(&key)
      .is_some_and(|entry| {
        cached_entry_matches_request(entry, request)
          && entry.provider == "socket"
          && entry.expires_at > now
          && matches!(
            entry.status,
            VerdictStatus::Clean | VerdictStatus::Suspicious
          )
      })
  }

  fn schedule_lookup(&self, request: PackageRequest) {
    let key = request.key();
    let should_spawn = {
      let mut state = self.inner.prefetch.lock();
      if state.results.contains_key(&key) || state.queued.contains_key(&key) {
        return;
      }
      state.queued.insert(key, request);
      if state.worker_running {
        false
      } else {
        state.worker_running = true;
        true
      }
    };
    if should_spawn {
      let provider = self.clone();
      drop(deno_unsync::spawn(async move {
        provider.run_prefetch_worker().await;
      }));
    }
  }

  async fn run_prefetch_worker(self) {
    // Yield once so versions resolved in the same wave coalesce into one
    // provider batch instead of spending one quota unit group per package.
    tokio::task::yield_now().await;
    loop {
      let batch = {
        let mut state = self.inner.prefetch.lock();
        if state.queued.is_empty() {
          state.worker_running = false;
          self.inner.prefetch_notify.notify_waiters();
          return;
        }
        let keys = state
          .queued
          .keys()
          .take(MAX_BATCH_SIZE)
          .cloned()
          .collect::<Vec<_>>();
        keys
          .into_iter()
          .filter_map(|key| state.queued.remove(&key))
          .collect::<Vec<_>>()
      };
      let results = self.fetch_batch(&batch).await;
      self.persist_live_results(&batch, &results).await;
      {
        let mut state = self.inner.prefetch.lock();
        for request in batch {
          let result =
            results.get(&request.key()).cloned().unwrap_or_else(|| {
              LookupResult::Unavailable(
                "Socket returned no verdict for the requested PURL".to_string(),
              )
            });
          state.results.insert(request.key(), result);
        }
      }
      self.inner.prefetch_notify.notify_waiters();
    }
  }

  async fn persist_live_results(
    &self,
    requests: &[PackageRequest],
    results: &HashMap<String, LookupResult>,
  ) {
    let now = unix_now();
    let updates = requests
      .iter()
      .filter_map(|request| {
        let LookupResult::Verdict { status, finding } =
          results.get(&request.key())?
        else {
          return None;
        };
        Some((
          request.key(),
          live_entry(
            request,
            status.clone(),
            finding.clone(),
            now,
            self.inner.ttl_secs,
          ),
        ))
      })
      .collect::<BTreeMap<_, _>>();
    if updates.is_empty() {
      return;
    }
    self
      .inner
      .live_entries_this_operation
      .lock()
      .extend(updates.clone());
    match persist_store_updates_async(
      self.inner.store_path.clone(),
      updates,
      now,
    )
    .await
    {
      Ok(store) => *self.inner.store.lock() = store,
      Err(err) => {
        log::warn!("Failed persisting refreshed Oden Socket verdicts: {err}")
      }
    }
  }

  async fn wait_for_lookups(&self, keys: &[String]) {
    loop {
      let notified = self.inner.prefetch_notify.notified();
      let complete = {
        let state = self.inner.prefetch.lock();
        keys.iter().all(|key| state.results.contains_key(key))
          || (!state.worker_running && state.queued.is_empty())
      };
      if complete {
        return;
      }
      notified.await;
    }
  }

  async fn fetch_batch(
    &self,
    requests: &[PackageRequest],
  ) -> HashMap<String, LookupResult> {
    if requests.is_empty() {
      return HashMap::new();
    }
    let lookup_profile = deno_npm_cache::profile::start(
      "socket_lookup_batch",
      &requests.len().to_string(),
    );
    let result = match (&self.inner.api_key, &self.inner.org_slug) {
      (Some(api_key), Some(org_slug)) => {
        self
          .fetch_authenticated(requests, &api_key.0, org_slug)
          .await
      }
      (None, None) => self.fetch_anonymous(requests).await,
      _ => Err(
        "Socket authentication is incomplete; set both SOCKET_API_KEY and SOCKET_ORG_SLUG"
          .to_string(),
      ),
    };
    let output = match result {
      Ok(results) => results,
      Err(error) => requests
        .iter()
        .map(|request| {
          (request.key(), LookupResult::Unavailable(error.clone()))
        })
        .collect(),
    };
    if let Some(profile) = lookup_profile {
      profile.finish();
    }
    output
  }

  async fn fetch_authenticated(
    &self,
    requests: &[PackageRequest],
    api_key: &str,
    org_slug: &str,
  ) -> Result<HashMap<String, LookupResult>, String> {
    let mut url = if let Ok(override_url) = std::env::var("ODEN_SOCKET_API_URL")
      .or_else(|_| std::env::var("SOCKET_DEV_URL"))
    {
      Url::parse(&override_url).map_err(|err| err.to_string())?
    } else {
      let mut url = Url::parse(DEFAULT_ORG_API).unwrap();
      url
        .path_segments_mut()
        .map_err(|_| "invalid Socket API base URL".to_string())?
        .extend(["v0", "orgs", org_slug, "purl"]);
      url
        .query_pairs_mut()
        .append_pair("alerts", "true")
        .append_pair("compact", "true")
        .append_pair("purlErrors", "true");
      url
    };
    if url.query().is_none() {
      url
        .query_pairs_mut()
        .append_pair("alerts", "true")
        .append_pair("compact", "true")
        .append_pair("purlErrors", "true");
    }
    let body = serde_json::json!({
      "components": requests
        .iter()
        .map(|request| serde_json::json!({ "purl": request.purl() }))
        .collect::<Vec<_>>()
    });
    let auth = HeaderValue::from_str(&format!("Bearer {api_key}"))
      .map_err(|err| err.to_string())?;
    let client = self
      .inner
      .http_client_provider
      .get_or_create()
      .map_err(|err| err.to_string())?;
    let response = client
      .post_json(url, &body)
      .map_err(|err| err.to_string())?
      .header(AUTHORIZATION, auth)
      .send()
      .await
      .map_err(|err| err.to_string())?;
    if !response.status().is_success() {
      return Err(format!("Socket API returned HTTP {}", response.status()));
    }
    let text = http_util::body_to_string(response)
      .await
      .map_err(|err| err.to_string())?;
    parse_socket_response(requests, &text)
  }

  async fn fetch_anonymous(
    &self,
    requests: &[PackageRequest],
  ) -> Result<HashMap<String, LookupResult>, String> {
    let base = std::env::var("ODEN_SOCKET_API_URL")
      .or_else(|_| std::env::var("SOCKET_DEV_URL"))
      .unwrap_or_else(|_| DEFAULT_ANONYMOUS_API.to_string());
    let base = if base.ends_with('/') {
      base
    } else {
      format!("{base}/")
    };
    let output =
      futures::stream::iter(requests.iter().cloned().map(|request| {
        let provider = self.inner.http_client_provider.clone();
        let base = base.clone();
        async move {
          let response = match Url::parse(&format!(
            "{}purl/{}",
            base,
            percent_encoding::utf8_percent_encode(
              &request.purl(),
              percent_encoding::NON_ALPHANUMERIC
            )
          )) {
            Ok(url) => match provider.get_or_create() {
              Ok(client) => client
                .download_text(url)
                .await
                .map_err(|err| err.to_string()),
              Err(err) => Err(err.to_string()),
            },
            Err(err) => Err(err.to_string()),
          };
          let result = match response {
            Ok(text) => {
              parse_socket_response(std::slice::from_ref(&request), &text)
                .map(|mut parsed| {
                  parsed.remove(&request.key()).unwrap_or_else(|| {
                    LookupResult::Unavailable(
                      "Socket returned no verdict for the requested PURL"
                        .to_string(),
                    )
                  })
                })
                .unwrap_or_else(LookupResult::Unavailable)
            }
            Err(error) => LookupResult::Unavailable(error),
          };
          (request.key(), result)
        }
      }))
      .buffer_unordered(ANONYMOUS_CONCURRENCY)
      .collect::<HashMap<_, _>>()
      .await;
    Ok(output)
  }

  fn requests_for_snapshot(
    &self,
    snapshot: &NpmResolutionSnapshot,
    system_info: &NpmSystemInfo,
  ) -> BTreeMap<String, PackageRequest> {
    snapshot
      .all_packages_for_every_system()
      .filter(|package| package.system.matches_system(system_info))
      .filter_map(|package| {
        let dist = package.dist.as_ref()?;
        let registry = self
          .inner
          .npmrc
          .get_registry_url(&package.id.nv.name)
          .to_string();
        let request = PackageRequest {
          name: package.id.nv.name.to_string(),
          version: package.id.nv.version.to_string(),
          integrity: dist.integrity().for_lockfile().map(|v| v.into_owned()),
          registry,
          tarball: dist.tarball.clone(),
        };
        Some((request.key(), request))
      })
      .collect()
  }

  fn dependency_paths(
    &self,
    snapshot: &NpmResolutionSnapshot,
  ) -> HashMap<String, Vec<String>> {
    let mut paths = HashMap::new();
    let mut visited = HashSet::<NpmPackageId>::new();
    let mut queue = VecDeque::new();
    for package_id in snapshot.top_level_packages() {
      queue.push_back((package_id.clone(), vec![package_id.nv.to_string()]));
    }
    while let Some((id, path)) = queue.pop_front() {
      if !visited.insert(id.clone()) {
        continue;
      }
      paths
        .entry(id.nv.to_string())
        .or_insert_with(|| path.clone());
      let Some(package) = snapshot.package_from_id(&id) else {
        continue;
      };
      for dependency in package.dependencies.values() {
        let mut dependency_path = path.clone();
        dependency_path.push(dependency.nv.to_string());
        queue.push_back((dependency.clone(), dependency_path));
      }
    }
    paths
  }

  fn write_report(&self, mut records: Vec<ReportRecord>, error: Option<&str>) {
    let Some(path) = &self.inner.report_path else {
      return;
    };
    records.sort_by(|a, b| (&a.name, &a.version).cmp(&(&b.name, &b.version)));
    let total = records.len();
    // Keep a fixed schema so a consumer never has to guess whether a missing
    // status means zero or an incomplete provider report.
    let mut summary = BTreeMap::from([
      ("blocked", 0usize),
      ("clean", 0usize),
      ("suspicious", 0usize),
      ("unscanned_by_policy", 0usize),
      ("unsupported_source", 0usize),
      ("unverified", 0usize),
    ]);
    for record in &records {
      *summary.entry(record.status.as_str()).or_insert(0usize) += 1;
    }
    let include_all = report_all_enabled();
    if !include_all {
      records.retain(|record| record.status != VerdictStatus::Clean);
      records.truncate(100);
    }
    let shown = records.len();
    let report = ScanReport {
      v: REPORT_VERSION,
      provider: "socket",
      mode: self.inner.mode,
      total,
      shown,
      summary,
      records,
      error: error.map(ToOwned::to_owned),
    };
    if let Err(err) =
      write_report_atomic(path, &report, self.inner.report_key.as_ref())
    {
      log::warn!("Failed writing Oden Socket scan report: {err:#}");
    }
  }
}

// @ref llp/0002-the-oden-installer.plan.md#verdict-cache-revocation-and-re-checking
#[async_trait::async_trait(?Send)]
impl NpmPackageVerdictProvider for SocketVerdictProvider {
  fn prefetch(&self, nv: &PackageNv, version_info: &NpmPackageVersionInfo) {
    if self.inner.mode == ScanMode::Off {
      return;
    }
    let Some(request) = self.request_for_version_info(nv, version_info) else {
      return;
    };
    if !self.is_public_request(&request)
      || self.cache_is_fresh(&request, unix_now())
    {
      return;
    }
    self.schedule_lookup(request);
  }

  async fn ensure_verdicts(
    &self,
    snapshot: &NpmResolutionSnapshot,
    system_info: &NpmSystemInfo,
    force_refresh: bool,
  ) -> Result<(), JsErrorBox> {
    let now = unix_now();
    let disk_store = load_store_at(&self.inner.store_path, now);
    // Disk is the complete persisted layer, not an append-only hint. Missing,
    // invalid, externally pruned, or deleted state must disappear from memory
    // at the next gate. Current-operation live proof is retained separately.
    *self.inner.store.lock() = disk_store;
    let requests = self.requests_for_snapshot(snapshot, system_info);
    let mut records = Vec::with_capacity(requests.len());

    if self.inner.mode == ScanMode::Off {
      // Off is an explicit policy decision for this invocation, so its report
      // says unscanned and the operation proceeds. Merge-on-write deliberately
      // refuses to let that per-operation record erase a durable Socket block;
      // a later scanned mode must still revalidate or honor the block.
      let (store_changed, store_updates) = {
        let mut store = self.inner.store.lock();
        let mut store_changed = false;
        let mut store_updates = BTreeMap::new();
        for (key, request) in requests {
          let status = if self.is_public_request(&request) {
            VerdictStatus::UnscannedByPolicy
          } else {
            VerdictStatus::UnsupportedSource
          };
          let previous = store.entries.get(&key).filter(|entry| {
            entry.name == request.name
              && entry.version == request.version
              && entry.integrity == request.integrity
              && entry.status == status
              && entry.provider == "policy"
              && entry.finding.is_none()
          });
          let cached = previous.is_some();
          let entry = previous.cloned().unwrap_or_else(|| CachedVerdict {
            name: request.name.clone(),
            version: request.version.clone(),
            integrity: request.integrity.clone(),
            status: status.clone(),
            provider: "policy".to_string(),
            checked_at: now,
            expires_at: now,
            finding: None,
          });
          store_changed |= !cached;
          store.entries.insert(key.clone(), entry.clone());
          if !cached {
            store_updates.insert(key, entry.clone());
          }
          records.push(ReportRecord::from_entry(
            entry,
            cached,
            false,
            request.report_registry(),
            None,
          ));
        }
        (store_changed, store_updates)
      };
      if store_changed {
        match persist_store_updates_async(
          self.inner.store_path.clone(),
          store_updates,
          now,
        )
        .await
        {
          Ok(store) => *self.inner.store.lock() = store,
          Err(err) => {
            log::warn!("Failed persisting Oden scan policy state: {err}")
          }
        }
      }
      self.write_report(records, None);
      return Ok(());
    }

    let mut lookup_keys = Vec::new();
    for (key, request) in &requests {
      if !self.is_public_request(request) {
        continue;
      }
      if !force_refresh
        && self.inner.checked_this_operation.lock().contains(key)
      {
        continue;
      }
      let lookup_plan = {
        let store = self.inner.store.lock();
        match store.entries.get(key) {
          None => Some(true),
          Some(_) if request.integrity.is_none() => Some(true),
          Some(entry) if !cached_entry_matches_request(entry, request) => {
            Some(true)
          }
          Some(entry) if entry.provider != "socket" => Some(true),
          Some(_) if force_refresh => Some(true),
          Some(_) if self.inner.mode.requires_live_non_blocking_proof() => {
            Some(true)
          }
          Some(entry)
            if matches!(
              entry.status,
              VerdictStatus::Blocked
                | VerdictStatus::Unverified
                | VerdictStatus::UnscannedByPolicy
                | VerdictStatus::UnsupportedSource
            ) =>
          {
            Some(true)
          }
          Some(entry) if entry.expires_at <= now => Some(false),
          Some(_) => None,
        }
      };
      match lookup_plan {
        Some(must_wait) => {
          self.schedule_lookup(request.clone());
          if must_wait {
            lookup_keys.push(key.clone());
          } else {
            deno_npm_cache::profile::mark(
              "socket_cached_verdict_background_refresh",
              &format!("{}@{}", request.name, request.version),
            );
          }
        }
        None => {
          deno_npm_cache::profile::mark(
            "socket_cache_hit",
            &format!("{}@{}", request.name, request.version),
          );
        }
      }
    }
    self.wait_for_lookups(&lookup_keys).await;

    let mut blocked = Vec::new();
    let mut missing = Vec::new();
    let mut suspicious = Vec::new();
    let mut checked_keys = Vec::new();
    let mut live_entries_to_remember = HashMap::new();
    let mut store_updates = BTreeMap::new();
    let live_entries_before =
      self.inner.live_entries_this_operation.lock().clone();
    {
      let mut store = self.inner.store.lock();
      let mut prefetch = self.inner.prefetch.lock();
      for (key, request) in requests {
        let public = self.is_public_request(&request);
        if public {
          checked_keys.push(key.clone());
        }
        let live_previous = live_entries_before.get(&key).cloned();
        let mut live_proved_in_operation = public && live_previous.is_some();
        let previous = live_previous
          .clone()
          .or_else(|| store.entries.get(&key).cloned());
        let mut lookup = prefetch.results.remove(&key);
        let lookup_is_live =
          matches!(lookup, Some(LookupResult::Verdict { .. }));
        if lookup_is_live {
          live_proved_in_operation = true;
          if live_previous.is_some() {
            // `persist_live_results` already timestamped and retained this
            // provider response. Do not mint a newer timestamp at each gate.
            lookup = None;
          }
        }
        let (entry, cached, stale) = if !public {
          if let Some(previous) = previous.filter(|entry| {
            entry.name == request.name
              && entry.version == request.version
              && entry.integrity == request.integrity
              && entry.status == VerdictStatus::UnsupportedSource
              && entry.provider == "policy"
              && entry.finding.is_none()
          }) {
            (previous, true, false)
          } else {
            (
              CachedVerdict {
                name: request.name.clone(),
                version: request.version.clone(),
                integrity: request.integrity.clone(),
                status: VerdictStatus::UnsupportedSource,
                provider: "policy".to_string(),
                checked_at: now,
                expires_at: now,
                finding: None,
              },
              false,
              false,
            )
          }
        } else {
          select_public_entry(
            self.inner.mode,
            &request,
            previous,
            lookup,
            live_proved_in_operation,
            now,
            self.inner.ttl_secs,
          )
        };

        if lookup_is_live {
          live_entries_to_remember.insert(key.clone(), entry.clone());
        }

        match entry.status {
          VerdictStatus::Blocked => blocked.push(entry.clone()),
          VerdictStatus::Unverified => missing.push(entry.clone()),
          VerdictStatus::Suspicious => suspicious.push(entry.clone()),
          _ => {}
        }
        records.push(ReportRecord::from_entry(
          entry.clone(),
          cached,
          stale,
          request.report_registry(),
          None,
        ));
        if store.entries.get(&key) != Some(&entry) {
          store_updates.insert(key.clone(), entry.clone());
        }
        store.entries.insert(key, entry);
      }
    }
    let mut block_capacity_error = None;
    if !store_updates.is_empty() {
      match persist_store_updates_async(
        self.inner.store_path.clone(),
        store_updates,
        now,
      )
      .await
      {
        Ok(store) => *self.inner.store.lock() = store,
        Err(err) if err.is_block_capacity_exceeded() => {
          block_capacity_error = Some(err.to_string());
        }
        Err(err) => {
          log::warn!("Failed persisting Oden Socket verdicts: {err}")
        }
      }
    }
    self
      .inner
      .checked_this_operation
      .lock()
      .extend(checked_keys);
    self
      .inner
      .live_entries_this_operation
      .lock()
      .extend(live_entries_to_remember);

    let include_all_paths = report_all_enabled();
    let dependency_paths = if include_all_paths
      || !blocked.is_empty()
      || !missing.is_empty()
      || !suspicious.is_empty()
    {
      self.dependency_paths(snapshot)
    } else {
      HashMap::new()
    };
    for record in &mut records {
      if include_all_paths
        || matches!(
          record.status,
          VerdictStatus::Blocked
            | VerdictStatus::Suspicious
            | VerdictStatus::Unverified
        )
      {
        record.dependency_path = dependency_paths
          .get(&format!("{}@{}", record.name, record.version))
          .cloned()
          .unwrap_or_default();
      }
    }
    let stale_count = records.iter().filter(|record| record.stale).count();
    if stale_count > 0 {
      log::warn!(
        "Socket is honoring {} stale cached package verdict(s); a best-effort refresh was queued off the blocking path. Run `oden audit` to require a current result.",
        stale_count
      );
    }
    if !suspicious.is_empty() {
      log::warn!(
        "Socket flagged {} package(s) for review; run `oden audit --json` for details",
        suspicious.len()
      );
    }
    if !missing.is_empty() {
      log::warn!(
        "Socket could not verify {} package(s); the unverified state was saved. Default installs fail open, while strict installs and audits require a current verdict.",
        missing.len()
      );
    }

    if let Some(error) = block_capacity_error {
      self.write_report(records, Some(&error));
      return Err(JsErrorBox::generic(error));
    }

    if let Some(entry) = blocked.first() {
      let path = dependency_paths
        .get(&format!("{}@{}", entry.name, entry.version))
        .map(|path| path.join(" -> "))
        .unwrap_or_else(|| format!("{}@{}", entry.name, entry.version));
      let error = format!(
        "Socket blocked confirmed malicious npm package {}@{} (finding: malware; dependency path: {})",
        entry.name, entry.version, path
      );
      self.write_report(records, Some(&error));
      return Err(JsErrorBox::generic(error));
    }
    if self.inner.mode.requires_live_non_blocking_proof() && !missing.is_empty()
    {
      let names = missing
        .iter()
        .take(5)
        .map(|entry| format!("{}@{}", entry.name, entry.version))
        .collect::<Vec<_>>()
        .join(", ");
      let error = match self.inner.mode {
        ScanMode::Strict => format!(
          "Socket strict scan has no valid verdict for {} package(s): {}",
          missing.len(),
          names
        ),
        ScanMode::Audit => format!(
          "Socket audit has no current verdict for {} package(s): {}",
          missing.len(),
          names
        ),
        ScanMode::Default | ScanMode::Off => unreachable!(),
      };
      self.write_report(records, Some(&error));
      return Err(JsErrorBox::generic(error));
    }
    self.write_report(records, None);
    Ok(())
  }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct SocketAlert {
  #[serde(default)]
  key: Option<String>,
  #[serde(default)]
  id: Option<String>,
  #[serde(rename = "type")]
  r#type: String,
  #[serde(default)]
  severity: Option<String>,
  #[serde(default)]
  action: Option<String>,
}

fn parse_socket_response(
  requests: &[PackageRequest],
  text: &str,
) -> Result<HashMap<String, LookupResult>, String> {
  let values = match serde_json::from_str::<serde_json::Value>(text) {
    Ok(serde_json::Value::Array(values)) => values,
    Ok(value) => vec![value],
    Err(_) => text
      .lines()
      .filter(|line| !line.trim().is_empty())
      .map(|line| serde_json::from_str(line).map_err(|err| err.to_string()))
      .collect::<Result<Vec<serde_json::Value>, String>>()?,
  };
  let by_purl = requests
    .iter()
    .map(|request| (request.purl(), request))
    .collect::<HashMap<_, _>>();
  let by_nv = requests
    .iter()
    .map(|request| (format!("{}@{}", request.name, request.version), request))
    .collect::<HashMap<_, _>>();
  let mut output = HashMap::new();
  for value in values {
    let kind = value
      .get("_type")
      .and_then(|value| value.as_str())
      .unwrap_or_default();
    if matches!(kind, "purlError" | "summary") {
      continue;
    }
    let input_purl = value.get("inputPurl").and_then(|value| value.as_str());
    let name = value.get("name").and_then(|value| value.as_str());
    let version = value.get("version").and_then(|value| value.as_str());
    let request = input_purl
      .and_then(|purl| by_purl.get(purl).copied())
      .or_else(|| by_nv.get(&format!("{}@{}", name?, version?)).copied());
    let Some(request) = request else {
      continue;
    };
    let alerts = value
      .get("alerts")
      .cloned()
      .map(serde_json::from_value::<Vec<SocketAlert>>)
      .transpose()
      .map_err(|err| err.to_string())?
      .unwrap_or_default();
    let unknown = alerts.iter().find(|alert| {
      matches!(alert.r#type.as_str(), "pendingScan" | "notFound")
    });
    let confirmed = alerts
      .iter()
      .find(|alert| alert.r#type.eq_ignore_ascii_case("malware"));
    let suspicious = alerts
      .iter()
      .find(|alert| alert.r#type.eq_ignore_ascii_case("gptMalware"));
    // A confirmed malware finding dominates partial-result markers from other
    // scanners in the same response. Never let `pendingScan` mask known bad.
    let result = if let Some(alert) = confirmed {
      LookupResult::Verdict {
        status: VerdictStatus::Blocked,
        finding: Some(finding_from_alert(alert)),
      }
    } else if let Some(alert) = suspicious {
      LookupResult::Verdict {
        status: VerdictStatus::Suspicious,
        finding: Some(finding_from_alert(alert)),
      }
    } else if let Some(alert) = unknown {
      LookupResult::Unavailable(format!(
        "Socket returned {} for {}",
        alert.r#type,
        request.purl()
      ))
    } else {
      LookupResult::Verdict {
        status: VerdictStatus::Clean,
        finding: None,
      }
    };
    output.insert(request.key(), result);
  }
  Ok(output)
}

fn finding_from_alert(alert: &SocketAlert) -> Finding {
  Finding {
    r#type: alert.r#type.clone(),
    severity: alert.severity.clone(),
    action: alert.action.clone(),
    id: alert.id.clone().or_else(|| alert.key.clone()),
  }
}

#[derive(Debug, Serialize)]
struct ScanReport {
  v: u8,
  provider: &'static str,
  mode: ScanMode,
  total: usize,
  shown: usize,
  summary: BTreeMap<&'static str, usize>,
  records: Vec<ReportRecord>,
  #[serde(skip_serializing_if = "Option::is_none")]
  error: Option<String>,
}

#[derive(Debug, Serialize)]
struct SignedReportEnvelope {
  v: u8,
  alg: &'static str,
  payload: String,
  mac: String,
}

#[derive(Debug, Serialize)]
struct ReportRecord {
  name: String,
  version: String,
  #[serde(skip_serializing_if = "Option::is_none")]
  integrity: Option<String>,
  status: VerdictStatus,
  provider: String,
  registry: String,
  cached: bool,
  stale: bool,
  dependency_path: Vec<String>,
  #[serde(skip_serializing_if = "Option::is_none")]
  finding: Option<Finding>,
}

impl ReportRecord {
  fn from_entry(
    entry: CachedVerdict,
    cached: bool,
    stale: bool,
    registry: String,
    dependency_path: Option<&Vec<String>>,
  ) -> Self {
    Self {
      name: entry.name,
      version: entry.version,
      integrity: entry.integrity,
      status: entry.status,
      provider: entry.provider,
      registry,
      cached,
      stale,
      dependency_path: dependency_path.cloned().unwrap_or_default(),
      finding: entry.finding,
    }
  }
}

fn read_api_key() -> Result<Option<SecretString>, JsErrorBox> {
  let Some(path) =
    std::env::var_os("ODEN_SOCKET_API_KEY_FILE").map(PathBuf::from)
  else {
    if std::env::var_os("SOCKET_API_KEY").is_some() {
      return Err(JsErrorBox::generic(
        "refusing to keep SOCKET_API_KEY in the installer environment where lifecycle scripts could inherit it; invoke through `oden`, which transfers the token through a one-shot credential file",
      ));
    }
    return Ok(None);
  };
  if std::env::var_os("SOCKET_API_KEY").is_some() {
    return Err(JsErrorBox::generic(
      "SOCKET_API_KEY remained in the child environment despite the one-shot credential handoff",
    ));
  }
  let metadata = std::fs::symlink_metadata(&path).map_err(|err| {
    JsErrorBox::generic(format!(
      "failed to inspect Socket credential file {}: {err}",
      path.display()
    ))
  })?;
  if !metadata.is_file() || metadata.file_type().is_symlink() {
    return Err(JsErrorBox::generic(
      "Socket credential handoff is not a regular non-symlink file",
    ));
  }
  #[cfg(unix)]
  {
    use std::os::unix::fs::PermissionsExt;
    if metadata.permissions().mode() & 0o077 != 0 {
      return Err(JsErrorBox::generic(
        "Socket credential handoff must not be accessible to group or other users",
      ));
    }
  }
  let contents = std::fs::read_to_string(&path).map_err(|err| {
    JsErrorBox::generic(format!(
      "failed to read Socket credential handoff {}: {err}",
      path.display()
    ))
  });
  // The credential is one-shot: unlink it before any dependency lifecycle
  // script can execute. Keeping only the token in provider memory also keeps it
  // out of child-process environments and debug output.
  std::fs::remove_file(&path).map_err(|err| {
    JsErrorBox::generic(format!(
      "failed to consume Socket credential handoff {}: {err}",
      path.display()
    ))
  })?;
  let token = contents?;
  let token = token.trim();
  if token.is_empty() {
    return Err(JsErrorBox::generic("Socket API token is empty"));
  }
  Ok(Some(SecretString(token.to_string())))
}

fn read_report_key() -> Result<Option<SecretBytes>, JsErrorBox> {
  let Some(path) =
    std::env::var_os("ODEN_SOCKET_REPORT_KEY_FILE").map(PathBuf::from)
  else {
    return Ok(None);
  };
  let metadata = std::fs::symlink_metadata(&path).map_err(|err| {
    JsErrorBox::generic(format!(
      "failed to inspect Socket report-key file {}: {err}",
      path.display()
    ))
  })?;
  if !metadata.is_file() || metadata.file_type().is_symlink() {
    return Err(JsErrorBox::generic(
      "Socket report-key handoff is not a regular non-symlink file",
    ));
  }
  #[cfg(unix)]
  {
    use std::os::unix::fs::PermissionsExt;
    if metadata.permissions().mode() & 0o077 != 0 {
      return Err(JsErrorBox::generic(
        "Socket report-key handoff must not be accessible to group or other users",
      ));
    }
  }
  let key = std::fs::read(&path).map_err(|err| {
    JsErrorBox::generic(format!(
      "failed to read Socket report-key handoff {}: {err}",
      path.display()
    ))
  });
  // Consume the key before dependency lifecycle scripts can run. The path may
  // remain in their environment, but there is no secret left there to recover.
  std::fs::remove_file(&path).map_err(|err| {
    JsErrorBox::generic(format!(
      "failed to consume Socket report-key handoff {}: {err}",
      path.display()
    ))
  })?;
  let key = key?;
  if key.len() != 32 {
    return Err(JsErrorBox::generic(
      "Socket report authentication key must be exactly 32 bytes",
    ));
  }
  Ok(Some(SecretBytes(key)))
}

#[derive(Clone, Copy, Debug)]
struct StoreLimits {
  max_entries: usize,
  max_bytes: usize,
}

impl Default for StoreLimits {
  fn default() -> Self {
    Self {
      max_entries: MAX_STORE_ENTRIES,
      max_bytes: MAX_STORE_BYTES,
    }
  }
}

#[derive(Debug, thiserror::Error)]
enum VerdictStoreError {
  #[error("Socket verdict store I/O failed: {0}")]
  Io(#[from] std::io::Error),
  #[error("invalid Socket verdict store: {0}")]
  Invalid(String),
  #[error("timed out acquiring Socket verdict store lock at {0}")]
  LockTimeout(PathBuf),
  #[error("Socket verdict store worker failed: {0}")]
  Worker(String),
  #[error(
    "Socket verdict store bounds cannot retain all {blocked_entries} blocked entries ({blocked_bytes} bytes)"
  )]
  BlockCapacityExceeded {
    blocked_entries: usize,
    blocked_bytes: usize,
  },
}

impl VerdictStoreError {
  fn is_block_capacity_exceeded(&self) -> bool {
    matches!(self, Self::BlockCapacityExceeded { .. })
  }
}

fn empty_store() -> VerdictStore {
  VerdictStore {
    v: STORE_VERSION,
    entries: BTreeMap::new(),
  }
}

fn store_lock_path(path: &Path) -> PathBuf {
  let mut value = path.as_os_str().to_os_string();
  value.push(".lock");
  PathBuf::from(value)
}

struct VerdictStoreLock {
  path: PathBuf,
  file: sys_traits::impls::RealFsFile,
}

impl VerdictStoreLock {
  fn acquire(path: &Path) -> Result<Self, VerdictStoreError> {
    let parent = path.parent().ok_or_else(|| {
      VerdictStoreError::Invalid("store path has no parent".to_string())
    })?;
    std::fs::create_dir_all(parent)?;
    let lock_path = store_lock_path(path);
    let mut options = sys_traits::OpenOptions::new();
    options.create = true;
    options.read = true;
    options.write = true;
    options.mode = Some(0o600);
    let mut file =
      sys_traits::FsOpen::fs_open(&CliSys::default(), &lock_path, &options)?;
    let started = Instant::now();
    loop {
      match file.fs_file_try_lock(FsFileLockMode::Exclusive) {
        Ok(()) => {
          return Ok(Self {
            path: lock_path,
            file,
          });
        }
        Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
          if started.elapsed() >= STORE_LOCK_TIMEOUT {
            return Err(VerdictStoreError::LockTimeout(lock_path));
          }
          std::thread::sleep(STORE_LOCK_RETRY);
        }
        Err(err) => return Err(err.into()),
      }
    }
  }
}

impl Drop for VerdictStoreLock {
  fn drop(&mut self) {
    if let Err(err) = self.file.fs_file_unlock() {
      log::debug!(
        "Failed releasing Socket verdict store lock at {}: {err}",
        self.path.display()
      );
    }
  }
}

fn serialized_store_size(
  store: &VerdictStore,
) -> Result<usize, VerdictStoreError> {
  serde_json::to_vec(store)
    .map(|bytes| bytes.len())
    .map_err(|err| VerdictStoreError::Invalid(err.to_string()))
}

fn validate_store_field(
  label: &str,
  value: &str,
) -> Result<(), VerdictStoreError> {
  if value.is_empty() || value.len() > MAX_STORE_FIELD_BYTES {
    return Err(VerdictStoreError::Invalid(format!(
      "{label} has invalid length {}",
      value.len()
    )));
  }
  if value.contains('\0') {
    return Err(VerdictStoreError::Invalid(format!(
      "{label} contains a NUL byte"
    )));
  }
  Ok(())
}

fn validate_store_entry(
  key: &str,
  entry: &CachedVerdict,
  now: u64,
) -> Result<(), VerdictStoreError> {
  validate_store_field("entry key", key)?;
  validate_store_field("package name", &entry.name)?;
  validate_store_field("package version", &entry.version)?;
  validate_store_field("provider", &entry.provider)?;
  if let Some(integrity) = &entry.integrity {
    validate_store_field("integrity", integrity)?;
  }
  if entry.name.contains('|') || entry.version.contains('|') {
    return Err(VerdictStoreError::Invalid(
      "package identity contains the store-key delimiter".to_string(),
    ));
  }

  let parts = key.split('|').collect::<Vec<_>>();
  if parts.len() != 4 {
    return Err(VerdictStoreError::Invalid(
      "entry key does not contain registry, tarball, PURL, and integrity"
        .to_string(),
    ));
  }
  let registry = Url::parse(parts[0]).map_err(|_| {
    VerdictStoreError::Invalid(
      "entry key has invalid registry provenance".to_string(),
    )
  })?;
  if !registry.username().is_empty()
    || registry.password().is_some()
    || registry.query().is_some()
    || registry.fragment().is_some()
    || normalize_registry(parts[0]) != parts[0]
  {
    return Err(VerdictStoreError::Invalid(
      "entry key has non-normalized registry provenance".to_string(),
    ));
  }
  if parts[1] != "invalid-tarball-url"
    && tarball_provenance(parts[1]) != parts[1]
  {
    return Err(VerdictStoreError::Invalid(
      "entry key has non-normalized tarball provenance".to_string(),
    ));
  }
  if parts[2] != format!("pkg:npm/{}@{}", entry.name, entry.version) {
    return Err(VerdictStoreError::Invalid(
      "entry key PURL does not match the cached package identity".to_string(),
    ));
  }
  if parts[3] != entry.integrity.as_deref().unwrap_or("integrity-unknown") {
    return Err(VerdictStoreError::Invalid(
      "entry key integrity does not match the cached verdict".to_string(),
    ));
  }

  if entry.checked_at > now.saturating_add(MAX_FUTURE_CLOCK_SKEW_SECS) {
    return Err(VerdictStoreError::Invalid(
      "entry check time is implausibly far in the future".to_string(),
    ));
  }
  if entry.expires_at < entry.checked_at
    || entry.expires_at.saturating_sub(entry.checked_at)
      > MAX_PERSISTED_TTL_SECS
  {
    return Err(VerdictStoreError::Invalid(
      "entry expiry is outside the permitted TTL window".to_string(),
    ));
  }
  if let Some(finding) = &entry.finding {
    validate_store_field("finding type", &finding.r#type)?;
    for (label, value) in [
      ("finding severity", finding.severity.as_deref()),
      ("finding action", finding.action.as_deref()),
      ("finding id", finding.id.as_deref()),
    ] {
      if let Some(value) = value {
        validate_store_field(label, value)?;
      }
    }
  }

  let valid_shape = match (&entry.provider[..], &entry.status, &entry.finding) {
    ("socket", VerdictStatus::Clean, None) => true,
    ("socket", VerdictStatus::Blocked, Some(finding)) => {
      finding.r#type.eq_ignore_ascii_case("malware")
    }
    ("socket", VerdictStatus::Suspicious, Some(finding)) => {
      finding.r#type.eq_ignore_ascii_case("gptMalware")
    }
    ("socket", VerdictStatus::Unverified, Some(finding)) => matches!(
      finding.r#type.as_str(),
      "provider_unavailable" | "missing_verdict" | "live_verdict_required"
    ),
    (
      "policy",
      VerdictStatus::UnscannedByPolicy | VerdictStatus::UnsupportedSource,
      None,
    ) => true,
    _ => false,
  };
  if !valid_shape {
    return Err(VerdictStoreError::Invalid(
      "entry provider, status, and finding are inconsistent".to_string(),
    ));
  }
  Ok(())
}

fn validate_store(
  store: &VerdictStore,
  now: u64,
  limits: StoreLimits,
) -> Result<(), VerdictStoreError> {
  if store.v != STORE_VERSION {
    return Err(VerdictStoreError::Invalid(format!(
      "unsupported schema version {}",
      store.v
    )));
  }
  if store.entries.len() > limits.max_entries {
    return Err(VerdictStoreError::Invalid(format!(
      "entry count {} exceeds limit {}",
      store.entries.len(),
      limits.max_entries
    )));
  }
  for (key, entry) in &store.entries {
    validate_store_entry(key, entry, now)?;
  }
  let bytes = serialized_store_size(store)?;
  if bytes > limits.max_bytes {
    return Err(VerdictStoreError::Invalid(format!(
      "serialized size {bytes} exceeds limit {}",
      limits.max_bytes
    )));
  }
  Ok(())
}

fn read_store_checked(
  path: &Path,
  now: u64,
  limits: StoreLimits,
) -> Result<Option<VerdictStore>, VerdictStoreError> {
  let metadata = match std::fs::symlink_metadata(path) {
    Ok(metadata) => metadata,
    Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
    Err(err) => return Err(err.into()),
  };
  if !metadata.is_file() || metadata.file_type().is_symlink() {
    return Err(VerdictStoreError::Invalid(
      "store path is not a regular non-symlink file".to_string(),
    ));
  }
  #[cfg(unix)]
  {
    use std::os::unix::fs::PermissionsExt;
    if metadata.permissions().mode() & 0o077 != 0 {
      return Err(VerdictStoreError::Invalid(
        "store file is accessible to group or other users".to_string(),
      ));
    }
  }
  if metadata.len() > limits.max_bytes as u64 {
    return Err(VerdictStoreError::Invalid(format!(
      "file size {} exceeds limit {}",
      metadata.len(),
      limits.max_bytes
    )));
  }
  let mut bytes = Vec::with_capacity(metadata.len() as usize);
  File::open(path)?
    .take((limits.max_bytes + 1) as u64)
    .read_to_end(&mut bytes)?;
  if bytes.len() > limits.max_bytes {
    return Err(VerdictStoreError::Invalid(format!(
      "file size exceeds limit {}",
      limits.max_bytes
    )));
  }
  let store = serde_json::from_slice::<VerdictStore>(&bytes)
    .map_err(|err| VerdictStoreError::Invalid(err.to_string()))?;
  validate_store(&store, now, limits)?;
  Ok(Some(store))
}

fn load_store(path: &Path) -> VerdictStore {
  load_store_at(path, unix_now())
}

fn load_store_at(path: &Path, now: u64) -> VerdictStore {
  match read_store_checked(path, now, StoreLimits::default()) {
    Ok(Some(store)) => store,
    Ok(None) => empty_store(),
    Err(err) => {
      log::warn!(
        "Ignoring untrusted Oden Socket verdict cache at {}: {err}",
        path.display()
      );
      empty_store()
    }
  }
}

fn verdict_retention_rank(status: &VerdictStatus) -> u8 {
  match status {
    VerdictStatus::Blocked => 5,
    VerdictStatus::Suspicious => 4,
    VerdictStatus::Clean => 3,
    VerdictStatus::Unverified => 2,
    VerdictStatus::UnscannedByPolicy | VerdictStatus::UnsupportedSource => 1,
  }
}

fn incoming_entry_wins(
  existing: &CachedVerdict,
  incoming: &CachedVerdict,
) -> bool {
  let existing_conclusive = existing.provider == "socket"
    && matches!(
      existing.status,
      VerdictStatus::Clean | VerdictStatus::Suspicious | VerdictStatus::Blocked
    );
  let incoming_conclusive = incoming.provider == "socket"
    && matches!(
      incoming.status,
      VerdictStatus::Clean | VerdictStatus::Suspicious | VerdictStatus::Blocked
    );
  if existing.provider == "socket"
    && existing.status == VerdictStatus::Blocked
    && !incoming_conclusive
  {
    return false;
  }
  if existing_conclusive
    && incoming.provider == "socket"
    && incoming.status == VerdictStatus::Unverified
  {
    return false;
  }
  if incoming_conclusive && !existing_conclusive {
    return true;
  }
  let existing_order = (
    existing.checked_at,
    verdict_retention_rank(&existing.status),
    existing.expires_at,
  );
  let incoming_order = (
    incoming.checked_at,
    verdict_retention_rank(&incoming.status),
    incoming.expires_at,
  );
  if incoming_order != existing_order {
    return incoming_order > existing_order;
  }
  let existing_bytes = serde_json::to_vec(existing).unwrap_or_default();
  let incoming_bytes = serde_json::to_vec(incoming).unwrap_or_default();
  incoming_bytes > existing_bytes
}

fn enforce_store_limits(
  store: &mut VerdictStore,
  limits: StoreLimits,
) -> Result<(), VerdictStoreError> {
  let mut eviction_order = store
    .entries
    .iter()
    .filter(|(_, entry)| entry.status != VerdictStatus::Blocked)
    .map(|(key, entry)| {
      (
        verdict_retention_rank(&entry.status),
        entry.checked_at,
        entry.expires_at,
        key.clone(),
      )
    })
    .collect::<Vec<_>>();
  eviction_order.sort();
  let mut next = 0;
  let mut serialized_bytes = serialized_store_size(store)?;
  while store.entries.len() > limits.max_entries
    || serialized_bytes > limits.max_bytes
  {
    let Some((_, _, _, key)) = eviction_order.get(next) else {
      let blocked_entries = store.entries.len();
      return Err(VerdictStoreError::BlockCapacityExceeded {
        blocked_entries,
        blocked_bytes: serialized_bytes,
      });
    };
    let entry = store.entries.get(key).expect("eviction key must exist");
    let contribution = serde_json::to_vec(key)
      .and_then(|key_bytes| {
        serde_json::to_vec(entry)
          .map(|entry_bytes| key_bytes.len() + 1 + entry_bytes.len())
      })
      .map_err(|err| VerdictStoreError::Invalid(err.to_string()))?;
    let comma = usize::from(store.entries.len() > 1);
    store.entries.remove(key);
    serialized_bytes = serialized_bytes.saturating_sub(contribution + comma);
    next += 1;
  }
  debug_assert_eq!(serialized_bytes, serialized_store_size(store)?);
  Ok(())
}

fn persist_store_updates_with_limits(
  path: &Path,
  updates: &BTreeMap<String, CachedVerdict>,
  now: u64,
  limits: StoreLimits,
) -> Result<VerdictStore, VerdictStoreError> {
  let _lock = VerdictStoreLock::acquire(path)?;
  let mut store = match read_store_checked(path, now, limits) {
    Ok(Some(store)) => store,
    Ok(None) => empty_store(),
    Err(err) => {
      log::warn!(
        "Replacing untrusted Oden Socket verdict cache at {}: {err}",
        path.display()
      );
      empty_store()
    }
  };
  for (key, incoming) in updates {
    validate_store_entry(key, incoming, now)?;
    let replace = store
      .entries
      .get(key)
      .is_none_or(|existing| incoming_entry_wins(existing, incoming));
    if replace {
      store.entries.insert(key.clone(), incoming.clone());
    }
  }
  enforce_store_limits(&mut store, limits)?;
  validate_store(&store, now, limits)?;
  let bytes = serde_json::to_vec(&store)
    .map_err(|err| VerdictStoreError::Invalid(err.to_string()))?;
  atomic_write_file_with_retries(&CliSys::default(), path, &bytes, 0o600)?;
  Ok(store)
}

fn persist_store_updates(
  path: &Path,
  updates: &BTreeMap<String, CachedVerdict>,
  now: u64,
) -> Result<VerdictStore, VerdictStoreError> {
  persist_store_updates_with_limits(path, updates, now, StoreLimits::default())
}

async fn persist_store_updates_async(
  path: PathBuf,
  updates: BTreeMap<String, CachedVerdict>,
  now: u64,
) -> Result<VerdictStore, VerdictStoreError> {
  tokio::task::spawn_blocking(move || {
    persist_store_updates(&path, &updates, now)
  })
  .await
  .map_err(|err| VerdictStoreError::Worker(err.to_string()))?
}

// @ref llp/0004-structured-verdicts.plan.md#the-event-stream
// Only the HMAC-authenticated payload may cross from the paired engine into
// Oden-authored events; lifecycle output remains untrusted runtime data.
fn write_report_atomic(
  path: &Path,
  report: &ScanReport,
  key: Option<&SecretBytes>,
) -> Result<(), AnyError> {
  let Some(key) = key else {
    // Direct fork invocations and native integration specs have no wrapper
    // trust boundary. Oden always supplies a key and rejects unsigned reports.
    return write_json_atomic(path, report);
  };
  let payload = serde_json::to_vec(report)?;
  let mut signer = Hmac::<Sha256>::new_from_slice(&key.0)
    .map_err(|err| deno_core::anyhow::anyhow!(err.to_string()))?;
  signer.update(&payload);
  let mac = signer.finalize().into_bytes();
  let envelope = SignedReportEnvelope {
    v: REPORT_VERSION,
    alg: "hmac-sha256",
    payload: STANDARD_NO_PAD.encode(payload),
    mac: STANDARD_NO_PAD.encode(mac),
  };
  write_json_atomic(path, &envelope)
}

fn write_json_atomic(
  path: &Path,
  value: &impl Serialize,
) -> Result<(), AnyError> {
  let parent = path
    .parent()
    .ok_or_else(|| deno_core::anyhow::anyhow!("path has no parent"))?;
  std::fs::create_dir_all(parent)?;
  let bytes = serde_json::to_vec_pretty(value)?;
  atomic_write_file_with_retries(&CliSys::default(), path, &bytes, 0o600)?;
  Ok(())
}

fn unix_now() -> u64 {
  SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .unwrap_or_default()
    .as_secs()
}

fn tarball_belongs_to_registry(tarball: &str, registry: &str) -> bool {
  let Ok(tarball) = Url::parse(tarball) else {
    return false;
  };
  let Ok(registry) = Url::parse(&normalize_registry(registry)) else {
    return false;
  };
  if !tarball.username().is_empty()
    || tarball.password().is_some()
    || !registry.username().is_empty()
    || registry.password().is_some()
  {
    return false;
  }
  tarball.scheme() == registry.scheme()
    && tarball.host_str() == registry.host_str()
    && tarball.port_or_known_default() == registry.port_or_known_default()
    && tarball.path().starts_with(registry.path())
}

fn tarball_provenance(value: &str) -> String {
  let Ok(mut url) = Url::parse(value) else {
    return "invalid-tarball-url".to_string();
  };
  if url.set_username("").is_err() || url.set_password(None).is_err() {
    return "invalid-tarball-url".to_string();
  }
  url.set_query(None);
  url.set_fragment(None);
  url.to_string()
}

fn tarball_origin_registry(value: &str) -> Option<String> {
  let url = Url::parse(value).ok()?;
  let origin = url.origin().ascii_serialization();
  (origin != "null").then(|| normalize_registry(&origin))
}

fn normalize_registry(value: &str) -> String {
  format!("{}/", value.trim_end_matches('/'))
}

fn report_all_enabled() -> bool {
  std::env::var_os("ODEN_SOCKET_REPORT_ALL")
    .is_some_and(|value| !value.is_empty() && value != "0")
}

#[cfg(test)]
mod tests {
  use super::*;

  use std::process::Child;
  use std::process::Command;
  use std::time::Duration;

  use sys_traits::BaseFsCreateDir;
  use sys_traits::BaseFsMetadata;
  use sys_traits::BaseFsOpen;
  use sys_traits::BaseFsRemoveFile;
  use sys_traits::BaseFsRename;
  use sys_traits::CreateDirOptions;
  use sys_traits::OpenOptions;
  use sys_traits::SystemRandom;
  use sys_traits::ThreadSleep;

  struct RenameBarrierSys {
    inner: CliSys,
    ready: PathBuf,
    go: PathBuf,
    before_rename: bool,
  }

  impl RenameBarrierSys {
    fn barrier(&self) {
      std::fs::write(&self.ready, b"ready").unwrap();
      wait_for_file(&self.go);
    }
  }

  impl BaseFsCreateDir for RenameBarrierSys {
    fn base_fs_create_dir(
      &self,
      path: &Path,
      options: &CreateDirOptions,
    ) -> std::io::Result<()> {
      self.inner.base_fs_create_dir(path, options)
    }
  }

  impl BaseFsMetadata for RenameBarrierSys {
    type Metadata = <CliSys as BaseFsMetadata>::Metadata;

    fn base_fs_metadata(&self, path: &Path) -> std::io::Result<Self::Metadata> {
      self.inner.base_fs_metadata(path)
    }

    fn base_fs_symlink_metadata(
      &self,
      path: &Path,
    ) -> std::io::Result<Self::Metadata> {
      self.inner.base_fs_symlink_metadata(path)
    }
  }

  impl BaseFsOpen for RenameBarrierSys {
    type File = <CliSys as BaseFsOpen>::File;

    fn base_fs_open(
      &self,
      path: &Path,
      options: &OpenOptions,
    ) -> std::io::Result<Self::File> {
      self.inner.base_fs_open(path, options)
    }
  }

  impl BaseFsRemoveFile for RenameBarrierSys {
    fn base_fs_remove_file(&self, path: &Path) -> std::io::Result<()> {
      self.inner.base_fs_remove_file(path)
    }
  }

  impl BaseFsRename for RenameBarrierSys {
    fn base_fs_rename(&self, from: &Path, to: &Path) -> std::io::Result<()> {
      if self.before_rename {
        self.barrier();
      }
      let result = self.inner.base_fs_rename(from, to);
      if !self.before_rename && result.is_ok() {
        self.barrier();
      }
      result
    }
  }

  impl SystemRandom for RenameBarrierSys {
    fn sys_random(&self, buf: &mut [u8]) -> std::io::Result<()> {
      self.inner.sys_random(buf)
    }
  }

  impl ThreadSleep for RenameBarrierSys {
    fn thread_sleep(&self, duration: Duration) {
      self.inner.thread_sleep(duration)
    }
  }

  fn request(name: &str, version: &str) -> PackageRequest {
    PackageRequest {
      name: name.to_string(),
      version: version.to_string(),
      integrity: Some("sha512-test".to_string()),
      registry: DEFAULT_PUBLIC_REGISTRY.to_string(),
      tarball: format!("{}{}-{}.tgz", DEFAULT_PUBLIC_REGISTRY, name, version),
    }
  }

  fn cached_verdict(
    request: &PackageRequest,
    status: VerdictStatus,
    checked_at: u64,
  ) -> CachedVerdict {
    let finding = match status {
      VerdictStatus::Blocked => Some(Finding {
        r#type: "malware".to_string(),
        severity: Some("critical".to_string()),
        action: Some("error".to_string()),
        id: Some(format!("finding-{}", request.name)),
      }),
      VerdictStatus::Suspicious => Some(Finding {
        r#type: "gptMalware".to_string(),
        severity: Some("high".to_string()),
        action: Some("warn".to_string()),
        id: Some(format!("finding-{}", request.name)),
      }),
      VerdictStatus::Unverified => Some(Finding {
        r#type: "provider_unavailable".to_string(),
        severity: None,
        action: None,
        id: Some("test outage".to_string()),
      }),
      VerdictStatus::Clean
      | VerdictStatus::UnscannedByPolicy
      | VerdictStatus::UnsupportedSource => None,
    };
    let provider = if matches!(
      status,
      VerdictStatus::UnscannedByPolicy | VerdictStatus::UnsupportedSource
    ) {
      "policy"
    } else {
      "socket"
    };
    CachedVerdict {
      name: request.name.clone(),
      version: request.version.clone(),
      integrity: request.integrity.clone(),
      status,
      provider: provider.to_string(),
      checked_at,
      expires_at: checked_at.saturating_add(60),
      finding,
    }
  }

  fn updates(
    values: impl IntoIterator<Item = (PackageRequest, CachedVerdict)>,
  ) -> BTreeMap<String, CachedVerdict> {
    values
      .into_iter()
      .map(|(request, entry)| (request.key(), entry))
      .collect()
  }

  fn wait_for_file(path: &Path) {
    let deadline = Instant::now() + Duration::from_secs(15);
    while !path.exists() {
      assert!(
        Instant::now() < deadline,
        "timed out waiting for {}",
        path.display()
      );
      std::thread::sleep(Duration::from_millis(10));
    }
  }

  fn spawn_store_helper(
    action: &str,
    path: &Path,
    name: &str,
    ready: &Path,
    go: &Path,
    now: u64,
  ) -> Child {
    Command::new(std::env::current_exe().unwrap())
      .arg("store_subprocess_helper")
      .arg("--nocapture")
      .arg("--test-threads=1")
      .env("ODEN_STORE_TEST_ACTION", action)
      .env("ODEN_STORE_TEST_PATH", path)
      .env("ODEN_STORE_TEST_NAME", name)
      .env("ODEN_STORE_TEST_READY", ready)
      .env("ODEN_STORE_TEST_GO", go)
      .env("ODEN_STORE_TEST_NOW", now.to_string())
      .spawn()
      .unwrap()
  }

  #[test]
  fn store_subprocess_helper() {
    let Ok(action) = std::env::var("ODEN_STORE_TEST_ACTION") else {
      return;
    };
    let path = PathBuf::from(std::env::var_os("ODEN_STORE_TEST_PATH").unwrap());
    let name = std::env::var("ODEN_STORE_TEST_NAME").unwrap();
    let ready =
      PathBuf::from(std::env::var_os("ODEN_STORE_TEST_READY").unwrap());
    let go = PathBuf::from(std::env::var_os("ODEN_STORE_TEST_GO").unwrap());
    let now = std::env::var("ODEN_STORE_TEST_NOW")
      .unwrap()
      .parse::<u64>()
      .unwrap();
    match action.as_str() {
      "write" => {
        std::fs::write(&ready, b"ready").unwrap();
        wait_for_file(&go);
        let request = request(&name, "1.0.0");
        let entry = cached_verdict(&request, VerdictStatus::Clean, now);
        persist_store_updates(&path, &updates([(request, entry)]), now)
          .unwrap();
      }
      "atomic_cut_before" | "atomic_cut_after" => {
        let _lock = VerdictStoreLock::acquire(&path).unwrap();
        let request = request(&name, "1.0.0");
        let entry = cached_verdict(&request, VerdictStatus::Clean, now);
        let mut candidate = load_store_at(&path, now);
        candidate.entries.insert(request.key(), entry);
        enforce_store_limits(&mut candidate, StoreLimits::default()).unwrap();
        validate_store(&candidate, now, StoreLimits::default()).unwrap();
        let bytes = serde_json::to_vec(&candidate).unwrap();
        let sys = RenameBarrierSys {
          inner: CliSys::default(),
          ready,
          go,
          before_rename: action == "atomic_cut_before",
        };
        atomic_write_file_with_retries(&sys, &path, &bytes, 0o600).unwrap();
      }
      _ => panic!("unknown helper action {action}"),
    }
  }

  #[test]
  fn parses_confirmed_and_suspicious_verdicts_by_type() {
    let requests = vec![
      request("bad", "1.0.0"),
      request("maybe", "2.0.0"),
      request("bad-and-pending", "3.0.0"),
    ];
    let response = r#"{"inputPurl":"pkg:npm/bad@1.0.0","name":"bad","version":"1.0.0","alerts":[{"type":"malware","action":"ignore","severity":"critical"}]}
{"inputPurl":"pkg:npm/maybe@2.0.0","name":"maybe","version":"2.0.0","alerts":[{"type":"gptMalware","action":"error","severity":"high"}]}
{"inputPurl":"pkg:npm/bad-and-pending@3.0.0","name":"bad-and-pending","version":"3.0.0","alerts":[{"type":"pendingScan"},{"type":"malware","action":"error","severity":"critical"}]}"#;
    let parsed = parse_socket_response(&requests, response).unwrap();
    assert!(matches!(
      parsed.get(&requests[0].key()),
      Some(LookupResult::Verdict {
        status: VerdictStatus::Blocked,
        ..
      })
    ));
    assert!(matches!(
      parsed.get(&requests[1].key()),
      Some(LookupResult::Verdict {
        status: VerdictStatus::Suspicious,
        ..
      })
    ));
    assert!(matches!(
      parsed.get(&requests[2].key()),
      Some(LookupResult::Verdict {
        status: VerdictStatus::Blocked,
        ..
      })
    ));
  }

  #[test]
  fn pending_and_missing_responses_are_not_clean() {
    let requests = vec![request("pending", "1.0.0")];
    let response = r#"{"name":"pending","version":"1.0.0","alerts":[{"type":"pendingScan"}]}"#;
    let parsed = parse_socket_response(&requests, response).unwrap();
    assert!(matches!(
      parsed.get(&requests[0].key()),
      Some(LookupResult::Unavailable(_))
    ));
    assert!(
      parse_socket_response(
        &requests,
        r#"{"_type":"purlError","value":{"error":"not found"}}"#
      )
      .unwrap()
      .is_empty()
    );
  }

  #[test]
  fn registry_comparison_is_exact_after_trailing_slash_normalization() {
    assert_eq!(
      normalize_registry("https://registry.npmjs.org"),
      "https://registry.npmjs.org/"
    );
    assert_ne!(
      normalize_registry("https://registry.example/npm"),
      DEFAULT_PUBLIC_REGISTRY
    );
  }

  #[test]
  fn cache_identity_binds_registry_tarball_provenance_and_integrity() {
    let original = request("same-name", "1.0.0");
    let mut private = original.clone();
    private.registry = "https://registry.example/npm/".to_string();
    private.tarball =
      "https://registry.example/npm/same-name-1.0.0.tgz".to_string();
    let mut drifted = original.clone();
    drifted.tarball =
      "https://registry.private.example/same-name-1.0.0.tgz".to_string();
    let mut republished = original.clone();
    republished.integrity = Some("sha512-different".to_string());
    assert_ne!(original.key(), private.key());
    assert_ne!(original.key(), drifted.key());
    assert_ne!(original.key(), republished.key());
  }

  #[test]
  fn public_registry_requires_matching_persisted_tarball_provenance() {
    assert!(tarball_belongs_to_registry(
      "https://registry.npmjs.org/chalk/-/chalk-5.0.1.tgz",
      DEFAULT_PUBLIC_REGISTRY,
    ));
    assert!(!tarball_belongs_to_registry(
      "https://registry.private.example/chalk/-/chalk-5.0.1.tgz",
      DEFAULT_PUBLIC_REGISTRY,
    ));
    assert!(!tarball_belongs_to_registry(
      "https://registry.npmjs.org.evil.example/chalk.tgz",
      DEFAULT_PUBLIC_REGISTRY,
    ));
  }

  #[test]
  fn strict_and_audit_modes_require_live_non_blocking_proof() {
    let request = request("cached-clean", "1.0.0");
    let clean = cached_verdict(&request, VerdictStatus::Clean, 1_000);
    for mode in [ScanMode::Strict, ScanMode::Audit] {
      let (entry, cached, stale) = select_public_entry(
        mode,
        &request,
        Some(clean.clone()),
        Some(LookupResult::Unavailable("offline".to_string())),
        false,
        1_001,
        60,
      );
      assert_eq!(entry.status, VerdictStatus::Unverified);
      assert!(!cached);
      assert!(!stale);
    }

    let (default, cached, stale) = select_public_entry(
      ScanMode::Default,
      &request,
      Some(clean),
      Some(LookupResult::Unavailable("offline".to_string())),
      false,
      1_001,
      60,
    );
    assert_eq!(default.status, VerdictStatus::Clean);
    assert!(cached);
    assert!(stale);
  }

  #[test]
  fn cached_block_remains_fail_closed_when_revalidation_is_unavailable() {
    let request = request("cached-block", "1.0.0");
    let blocked = cached_verdict(&request, VerdictStatus::Blocked, 1_000);
    for mode in [ScanMode::Default, ScanMode::Strict] {
      let (entry, cached, stale) = select_public_entry(
        mode,
        &request,
        Some(blocked.clone()),
        Some(LookupResult::Unavailable("offline".to_string())),
        false,
        1_001,
        60,
      );
      assert_eq!(entry.status, VerdictStatus::Blocked);
      assert!(cached);
      assert!(stale);
    }
  }

  #[test]
  fn store_validation_rejects_tamper_future_dates_and_key_drift() {
    let now = 10_000;
    let request = request("validated", "1.0.0");
    let entry = cached_verdict(&request, VerdictStatus::Clean, now);
    let mut store = VerdictStore {
      v: STORE_VERSION,
      entries: updates([(request.clone(), entry.clone())]),
    };
    validate_store(&store, now, StoreLimits::default()).unwrap();

    store.entries.get_mut(&request.key()).unwrap().provider =
      "forged-provider".to_string();
    assert!(validate_store(&store, now, StoreLimits::default()).is_err());

    let mut future = entry.clone();
    future.checked_at = now + MAX_FUTURE_CLOCK_SKEW_SECS + 1;
    future.expires_at = future.checked_at + 60;
    let future = VerdictStore {
      v: STORE_VERSION,
      entries: updates([(request.clone(), future)]),
    };
    assert!(validate_store(&future, now, StoreLimits::default()).is_err());

    let wrong_key = VerdictStore {
      v: STORE_VERSION,
      entries: BTreeMap::from([("https://registry.npmjs.org/|invalid-tarball-url|pkg:npm/other@1.0.0|sha512-test".to_string(), entry)]),
    };
    assert!(validate_store(&wrong_key, now, StoreLimits::default()).is_err());

    let unknown_field = serde_json::json!({
      "v": STORE_VERSION,
      "entries": {},
      "authority": "forged"
    });
    assert!(
      serde_json::from_value::<VerdictStore>(unknown_field).is_err(),
      "unknown schema fields must fail closed"
    );
  }

  #[test]
  fn entry_validation_rejects_ttl_provenance_integrity_and_shape_drift() {
    let now = 10_000;
    let request = request("validation", "1.0.0");
    let key = request.key();
    let clean = cached_verdict(&request, VerdictStatus::Clean, now);
    validate_store_entry(&key, &clean, now).unwrap();

    let mut overlong_ttl = clean.clone();
    overlong_ttl.expires_at =
      overlong_ttl.checked_at + MAX_PERSISTED_TTL_SECS + 1;

    let mut integrity_drift = clean.clone();
    integrity_drift.integrity = Some("sha512-forged".to_string());

    let mut invalid_shape = clean.clone();
    invalid_shape.status = VerdictStatus::Blocked;

    let parts = key.split('|').collect::<Vec<_>>();
    let non_normalized_registry = format!(
      "https://registry.npmjs.org|{}|{}|{}",
      parts[1], parts[2], parts[3]
    );
    let non_normalized_tarball = format!(
      "{}|{}?credential=leak|{}|{}",
      parts[0], parts[1], parts[2], parts[3]
    );

    for (label, candidate_key, candidate_entry) in [
      ("ttl", key.clone(), overlong_ttl),
      ("integrity", key.clone(), integrity_drift),
      ("registry", non_normalized_registry, clean.clone()),
      ("tarball", non_normalized_tarball, clean.clone()),
      ("shape", key.clone(), invalid_shape),
    ] {
      assert!(
        validate_store_entry(&candidate_key, &candidate_entry, now).is_err(),
        "{label} drift must be rejected"
      );
    }
  }

  #[test]
  fn merge_rejects_same_key_rollback_and_outage_demotion() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store.json");
    let request = request("rollback", "1.0.0");

    let blocked = cached_verdict(&request, VerdictStatus::Blocked, 1_100);
    persist_store_updates(
      &path,
      &updates([(request.clone(), blocked.clone())]),
      1_200,
    )
    .unwrap();

    let rolled_back = cached_verdict(&request, VerdictStatus::Clean, 1_050);
    let store = persist_store_updates(
      &path,
      &updates([(request.clone(), rolled_back)]),
      1_200,
    )
    .unwrap();
    assert_eq!(store.entries.get(&request.key()), Some(&blocked));

    let unverified = cached_verdict(&request, VerdictStatus::Unverified, 1_150);
    let store = persist_store_updates(
      &path,
      &updates([(request.clone(), unverified)]),
      1_200,
    )
    .unwrap();
    assert_eq!(store.entries.get(&request.key()), Some(&blocked));

    let policy_opt_out =
      cached_verdict(&request, VerdictStatus::UnscannedByPolicy, 1_150);
    let store = persist_store_updates(
      &path,
      &updates([(request.clone(), policy_opt_out)]),
      1_200,
    )
    .unwrap();
    assert_eq!(store.entries.get(&request.key()), Some(&blocked));

    let cleared = cached_verdict(&request, VerdictStatus::Clean, 1_151);
    let store = persist_store_updates(
      &path,
      &updates([(request.clone(), cleared.clone())]),
      1_200,
    )
    .unwrap();
    assert_eq!(store.entries.get(&request.key()), Some(&cleared));

    let policy_opt_out =
      cached_verdict(&request, VerdictStatus::UnscannedByPolicy, 1_152);
    let store = persist_store_updates(
      &path,
      &updates([(request.clone(), policy_opt_out.clone())]),
      1_200,
    )
    .unwrap();
    assert_eq!(store.entries.get(&request.key()), Some(&policy_opt_out));
  }

  #[test]
  fn deterministic_eviction_never_removes_blocked_verdicts() {
    let blocked_request = request("blocked", "1.0.0");
    let old_clean_request = request("old-clean", "1.0.0");
    let new_clean_request = request("new-clean", "1.0.0");
    let unverified_request = request("unverified", "1.0.0");
    let mut store = VerdictStore {
      v: STORE_VERSION,
      entries: updates([
        (
          blocked_request.clone(),
          cached_verdict(&blocked_request, VerdictStatus::Blocked, 100),
        ),
        (
          old_clean_request.clone(),
          cached_verdict(&old_clean_request, VerdictStatus::Clean, 100),
        ),
        (
          new_clean_request.clone(),
          cached_verdict(&new_clean_request, VerdictStatus::Clean, 200),
        ),
        (
          unverified_request.clone(),
          cached_verdict(&unverified_request, VerdictStatus::Unverified, 300),
        ),
      ]),
    };
    let mut repeated = store.clone();
    let limits = StoreLimits {
      max_entries: 2,
      max_bytes: MAX_STORE_BYTES,
    };
    enforce_store_limits(&mut store, limits).unwrap();
    enforce_store_limits(&mut repeated, limits).unwrap();
    assert_eq!(store, repeated);
    assert!(store.entries.contains_key(&blocked_request.key()));
    assert!(store.entries.contains_key(&new_clean_request.key()));
    assert!(!store.entries.contains_key(&old_clean_request.key()));
    assert!(!store.entries.contains_key(&unverified_request.key()));
  }

  #[test]
  fn repeated_gate_reuses_live_result_after_store_eviction() {
    let blocked_request = request("bounded-block", "1.0.0");
    let clean_request = request("live-clean", "1.0.0");
    let mut bounded_store = VerdictStore {
      v: STORE_VERSION,
      entries: updates([
        (
          blocked_request.clone(),
          cached_verdict(&blocked_request, VerdictStatus::Blocked, 100),
        ),
        (
          clean_request.clone(),
          cached_verdict(&clean_request, VerdictStatus::Clean, 200),
        ),
      ]),
    };
    enforce_store_limits(
      &mut bounded_store,
      StoreLimits {
        max_entries: 1,
        max_bytes: MAX_STORE_BYTES,
      },
    )
    .unwrap();
    assert!(!bounded_store.entries.contains_key(&clean_request.key()));

    let live_entry = cached_verdict(&clean_request, VerdictStatus::Clean, 200);
    let live_entries =
      HashMap::from([(clean_request.key(), live_entry.clone())]);
    for now in [201, 202] {
      let (entry, cached, stale) = select_public_entry(
        ScanMode::Strict,
        &clean_request,
        live_entries.get(&clean_request.key()).cloned(),
        None,
        true,
        now,
        60,
      );
      assert_eq!(entry, live_entry);
      assert!(!cached);
      assert!(!stale);
    }
  }

  #[test]
  fn block_only_store_overflow_fails_closed() {
    let first = request("blocked-one", "1.0.0");
    let second = request("blocked-two", "1.0.0");
    let mut store = VerdictStore {
      v: STORE_VERSION,
      entries: updates([
        (
          first.clone(),
          cached_verdict(&first, VerdictStatus::Blocked, 100),
        ),
        (
          second.clone(),
          cached_verdict(&second, VerdictStatus::Blocked, 100),
        ),
      ]),
    };
    let err = enforce_store_limits(
      &mut store,
      StoreLimits {
        max_entries: 1,
        max_bytes: MAX_STORE_BYTES,
      },
    )
    .unwrap_err();
    assert!(err.is_block_capacity_exceeded());
    assert_eq!(store.entries.len(), 2);
  }

  #[test]
  fn byte_bound_evicts_clean_before_block_and_rejects_block_overflow() {
    let blocked_request = request("byte-blocked", "1.0.0");
    let clean_request = request("byte-clean", "1.0.0");
    let blocked = cached_verdict(&blocked_request, VerdictStatus::Blocked, 100);
    let clean = cached_verdict(&clean_request, VerdictStatus::Clean, 100);
    let blocked_only = VerdictStore {
      v: STORE_VERSION,
      entries: updates([(blocked_request.clone(), blocked.clone())]),
    };
    let blocked_bytes = serialized_store_size(&blocked_only).unwrap();
    let mut mixed = VerdictStore {
      v: STORE_VERSION,
      entries: updates([
        (blocked_request.clone(), blocked),
        (clean_request.clone(), clean),
      ]),
    };
    enforce_store_limits(
      &mut mixed,
      StoreLimits {
        max_entries: 10,
        max_bytes: blocked_bytes,
      },
    )
    .unwrap();
    assert!(mixed.entries.contains_key(&blocked_request.key()));
    assert!(!mixed.entries.contains_key(&clean_request.key()));

    let mut blocked_only = blocked_only;
    let err = enforce_store_limits(
      &mut blocked_only,
      StoreLimits {
        max_entries: 10,
        max_bytes: blocked_bytes - 1,
      },
    )
    .unwrap_err();
    assert!(err.is_block_capacity_exceeded());
  }

  #[test]
  fn oversized_and_malformed_store_bytes_are_never_loaded() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store.json");
    std::fs::write(&path, vec![b'x'; 65]).unwrap();
    #[cfg(unix)]
    {
      use std::os::unix::fs::PermissionsExt;
      std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
        .unwrap();
    }
    let err = read_store_checked(
      &path,
      1_000,
      StoreLimits {
        max_entries: 10,
        max_bytes: 64,
      },
    )
    .unwrap_err();
    assert!(err.to_string().contains("exceeds limit"));

    std::fs::write(&path, br#"{"v":1,"entries":{},"extra":true}"#).unwrap();
    let err =
      read_store_checked(&path, 1_000, StoreLimits::default()).unwrap_err();
    assert!(err.to_string().contains("unknown field"));
  }

  #[test]
  fn next_gate_drops_tampered_disk_authority_and_live_write_self_heals() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store.json");
    let now = 10_000;
    let original_request = request("valid-before-tamper", "1.0.0");
    persist_store_updates(
      &path,
      &updates([(
        original_request.clone(),
        cached_verdict(&original_request, VerdictStatus::Clean, now),
      )]),
      now,
    )
    .unwrap();
    let mut memory_store = load_store_at(&path, now);
    assert!(memory_store.entries.contains_key(&original_request.key()));

    #[cfg(unix)]
    {
      use std::os::unix::fs::PermissionsExt;
      use std::os::unix::fs::symlink;

      std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644))
        .unwrap();
      assert!(
        read_store_checked(&path, now, StoreLimits::default())
          .unwrap_err()
          .to_string()
          .contains("accessible to group or other users")
      );
      persist_store_updates(
        &path,
        &updates([(
          original_request.clone(),
          cached_verdict(&original_request, VerdictStatus::Clean, now),
        )]),
        now,
      )
      .unwrap();
      assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o077,
        0
      );

      std::fs::remove_file(&path).unwrap();
      symlink("missing-target", &path).unwrap();
      assert!(
        read_store_checked(&path, now, StoreLimits::default())
          .unwrap_err()
          .to_string()
          .contains("regular non-symlink")
      );
      persist_store_updates(
        &path,
        &updates([(
          original_request.clone(),
          cached_verdict(&original_request, VerdictStatus::Clean, now),
        )]),
        now,
      )
      .unwrap();
      assert!(
        !std::fs::symlink_metadata(&path)
          .unwrap()
          .file_type()
          .is_symlink()
      );
    }

    std::fs::write(&path, br#"{"v":1,"entries":{},"forged":true}"#).unwrap();
    memory_store = load_store_at(&path, now);
    assert!(memory_store.entries.is_empty());

    let replacement_request = request("live-after-tamper", "1.0.0");
    let replacement =
      cached_verdict(&replacement_request, VerdictStatus::Clean, now + 1);
    let repaired = persist_store_updates(
      &path,
      &updates([(replacement_request.clone(), replacement.clone())]),
      now + 1,
    )
    .unwrap();
    assert_eq!(
      repaired.entries.get(&replacement_request.key()),
      Some(&replacement)
    );
    assert_eq!(
      read_store_checked(&path, now + 1, StoreLimits::default())
        .unwrap()
        .unwrap(),
      repaired
    );
  }

  #[test]
  fn cross_process_merge_preserves_disjoint_writers() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store.json");
    let ready_a = dir.path().join("ready-a");
    let ready_b = dir.path().join("ready-b");
    let go = dir.path().join("go");
    let now = unix_now();
    let mut first =
      spawn_store_helper("write", &path, "writer-a", &ready_a, &go, now);
    let mut second =
      spawn_store_helper("write", &path, "writer-b", &ready_b, &go, now);
    wait_for_file(&ready_a);
    wait_for_file(&ready_b);
    std::fs::write(&go, b"go").unwrap();
    assert!(first.wait().unwrap().success());
    assert!(second.wait().unwrap().success());

    let store = read_store_checked(&path, now, StoreLimits::default())
      .unwrap()
      .unwrap();
    assert!(
      store
        .entries
        .contains_key(&request("writer-a", "1.0.0").key())
    );
    assert!(
      store
        .entries
        .contains_key(&request("writer-b", "1.0.0").key())
    );
  }

  #[test]
  fn atomic_rename_crash_cuts_preserve_old_or_new_state_and_release_lock() {
    let dir = tempfile::tempdir().unwrap();
    let now = unix_now();
    for (action, rename_committed) in
      [("atomic_cut_before", false), ("atomic_cut_after", true)]
    {
      let phase_dir = dir.path().join(action);
      std::fs::create_dir(&phase_dir).unwrap();
      let path = phase_dir.join("store.json");
      let original_request = request("before-crash", "1.0.0");
      let original =
        cached_verdict(&original_request, VerdictStatus::Clean, now);
      persist_store_updates(
        &path,
        &updates([(original_request.clone(), original.clone())]),
        now,
      )
      .unwrap();

      let ready = phase_dir.join("crash-ready");
      let go = phase_dir.join("unused-go");
      let candidate_request = request("crash-candidate", "1.0.0");
      let mut child = spawn_store_helper(
        action,
        &path,
        &candidate_request.name,
        &ready,
        &go,
        now,
      );
      wait_for_file(&ready);
      child.kill().unwrap();
      assert!(!child.wait().unwrap().success());

      let after_crash = read_store_checked(&path, now, StoreLimits::default())
        .unwrap()
        .unwrap();
      assert_eq!(
        after_crash.entries.get(&original_request.key()),
        Some(&original)
      );
      assert_eq!(
        after_crash.entries.contains_key(&candidate_request.key()),
        rename_committed
      );
      if !rename_committed {
        assert!(std::fs::read_dir(&phase_dir).unwrap().any(|entry| {
          entry
            .unwrap()
            .path()
            .extension()
            .is_some_and(|extension| extension == "tmp")
        }));
      }

      let recovered_request = request("after-crash", "1.0.0");
      let recovered =
        cached_verdict(&recovered_request, VerdictStatus::Clean, now);
      let recovered_store = persist_store_updates(
        &path,
        &updates([(recovered_request.clone(), recovered.clone())]),
        now,
      )
      .unwrap();
      assert_eq!(
        recovered_store.entries.get(&original_request.key()),
        Some(&original)
      );
      assert_eq!(
        recovered_store.entries.get(&recovered_request.key()),
        Some(&recovered)
      );
      assert_eq!(
        recovered_store
          .entries
          .contains_key(&candidate_request.key()),
        rename_committed
      );
    }
  }

  #[test]
  fn persistent_stale_lockfile_has_no_owner_authority() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("store.json");
    let lock_path = store_lock_path(&path);
    std::fs::write(&lock_path, b"stale pid 123").unwrap();
    let now = unix_now();
    let request = request("stale-lock", "1.0.0");
    let entry = cached_verdict(&request, VerdictStatus::Clean, now);
    let store =
      persist_store_updates(&path, &updates([(request.clone(), entry)]), now)
        .unwrap();
    assert!(store.entries.contains_key(&request.key()));
  }

  #[test]
  fn signed_report_envelope_authenticates_exact_payload_bytes() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("report.json");
    let key = SecretBytes(vec![0x5a; 32]);
    let report = ScanReport {
      v: REPORT_VERSION,
      provider: "socket",
      mode: ScanMode::Default,
      total: 0,
      shown: 0,
      summary: BTreeMap::from([
        ("blocked", 0),
        ("clean", 0),
        ("suspicious", 0),
        ("unscanned_by_policy", 0),
        ("unsupported_source", 0),
        ("unverified", 0),
      ]),
      records: Vec::new(),
      error: None,
    };
    write_report_atomic(&path, &report, Some(&key)).unwrap();
    let envelope: serde_json::Value =
      serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    assert_eq!(envelope["v"], REPORT_VERSION);
    assert_eq!(envelope["alg"], "hmac-sha256");
    let payload = STANDARD_NO_PAD
      .decode(envelope["payload"].as_str().unwrap())
      .unwrap();
    let mac = STANDARD_NO_PAD
      .decode(envelope["mac"].as_str().unwrap())
      .unwrap();
    let mut verifier = Hmac::<Sha256>::new_from_slice(&key.0).unwrap();
    verifier.update(&payload);
    verifier.verify_slice(&mac).unwrap();
    let decoded: serde_json::Value = serde_json::from_slice(&payload).unwrap();
    assert_eq!(decoded["provider"], "socket");

    let mut tampered = payload;
    tampered.push(b' ');
    let mut verifier = Hmac::<Sha256>::new_from_slice(&key.0).unwrap();
    verifier.update(&tampered);
    assert!(verifier.verify_slice(&mac).is_err());
  }
}

// Copyright 2018-2026 the Deno authors. MIT license.

use std::collections::BTreeMap;
use std::collections::HashMap;
use std::collections::HashSet;
use std::collections::VecDeque;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;
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

  fn is_strict(self) -> bool {
    self == Self::Strict
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

#[derive(Debug, Default, Deserialize, Serialize)]
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

#[derive(Clone, Debug)]
enum LookupResult {
  Verdict {
    status: VerdictStatus,
    finding: Option<Finding>,
  },
  Unavailable(String),
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
      .unwrap_or(DEFAULT_TTL_SECS);
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
    self
      .inner
      .store
      .lock()
      .entries
      .get(&request.key())
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
    let requests = self.requests_for_snapshot(snapshot, system_info);
    let mut records = Vec::with_capacity(requests.len());

    if self.inner.mode == ScanMode::Off {
      let mut store = self.inner.store.lock();
      let mut store_changed = false;
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
        store.entries.insert(key, entry.clone());
        records.push(ReportRecord::from_entry(
          entry,
          cached,
          false,
          request.report_registry(),
          None,
        ));
      }
      if store_changed
        && let Err(err) = write_store(&self.inner.store_path, &store)
      {
        log::warn!("Failed persisting Oden scan policy state: {err:#}");
      }
      drop(store);
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
      let needs_lookup = {
        let store = self.inner.store.lock();
        match store.entries.get(key) {
          None => true,
          Some(_) if request.integrity.is_none() => true,
          Some(entry) if !cached_entry_matches_request(entry, request) => true,
          Some(entry) if entry.provider != "socket" => true,
          Some(_) if force_refresh => true,
          Some(entry) => {
            entry.expires_at <= now
              || matches!(
                entry.status,
                VerdictStatus::Blocked
                  | VerdictStatus::Unverified
                  | VerdictStatus::UnscannedByPolicy
              )
          }
        }
      };
      if needs_lookup {
        lookup_keys.push(key.clone());
        self.schedule_lookup(request.clone());
      } else {
        deno_npm_cache::profile::mark(
          "socket_cache_hit",
          &format!("{}@{}", request.name, request.version),
        );
      }
    }
    self.wait_for_lookups(&lookup_keys).await;

    let mut blocked = Vec::new();
    let mut missing = Vec::new();
    let mut suspicious = Vec::new();
    let mut store_changed = false;
    let mut checked_keys = Vec::new();
    {
      let mut store = self.inner.store.lock();
      let mut prefetch = self.inner.prefetch.lock();
      for (key, request) in requests {
        let public = self.is_public_request(&request);
        if public {
          checked_keys.push(key.clone());
        }
        let checked_in_operation =
          public && self.inner.checked_this_operation.lock().contains(&key);
        let previous = store.entries.get(&key).cloned();
        let lookup = prefetch.results.remove(&key);
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
          match lookup {
            Some(LookupResult::Verdict { status, finding }) => (
              CachedVerdict {
                name: request.name.clone(),
                version: request.version.clone(),
                integrity: request.integrity.clone(),
                status,
                provider: "socket".to_string(),
                checked_at: now,
                expires_at: now.saturating_add(self.inner.ttl_secs),
                finding,
              },
              false,
              false,
            ),
            Some(LookupResult::Unavailable(error)) => match previous {
              Some(previous)
                if cached_entry_matches_request(&previous, &request)
                  && previous.provider == "socket"
                  && matches!(
                    previous.status,
                    VerdictStatus::Clean
                      | VerdictStatus::Suspicious
                      | VerdictStatus::Blocked
                  ) =>
              {
                (previous, true, true)
              }
              _ => (
                CachedVerdict {
                  name: request.name.clone(),
                  version: request.version.clone(),
                  integrity: request.integrity.clone(),
                  status: VerdictStatus::Unverified,
                  provider: "socket".to_string(),
                  checked_at: now,
                  expires_at: now,
                  finding: Some(Finding {
                    r#type: "provider_unavailable".to_string(),
                    severity: None,
                    action: None,
                    id: Some(error),
                  }),
                },
                false,
                false,
              ),
            },
            None => match previous {
              Some(previous)
                if cached_entry_matches_request(&previous, &request)
                  && previous.provider == "socket" =>
              {
                let stale = previous.expires_at <= now;
                if checked_in_operation
                  && previous.status == VerdictStatus::Unverified
                {
                  // A prior gate in this command already attempted the live
                  // lookup. Preserve fail-open provenance without issuing the
                  // same outage request again.
                  (previous, false, false)
                } else {
                  (previous, true, stale)
                }
              }
              _ => (
                CachedVerdict {
                  name: request.name.clone(),
                  version: request.version.clone(),
                  integrity: request.integrity.clone(),
                  status: VerdictStatus::Unverified,
                  provider: "socket".to_string(),
                  checked_at: now,
                  expires_at: now,
                  finding: Some(Finding {
                    r#type: "missing_verdict".to_string(),
                    severity: None,
                    action: None,
                    id: None,
                  }),
                },
                false,
                false,
              ),
            },
          }
        };

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
        store_changed |= store.entries.get(&key) != Some(&entry);
        store.entries.insert(key, entry);
      }
      if store_changed
        && let Err(err) = write_store(&self.inner.store_path, &store)
      {
        log::warn!("Failed persisting Oden Socket verdicts: {err:#}");
      }
    }
    self
      .inner
      .checked_this_operation
      .lock()
      .extend(checked_keys);

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
        "Socket could not refresh {} cached package verdict(s); honoring the stale conclusive state. Run `oden audit` to retry.",
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
        "Socket could not verify {} package(s); installation is proceeding in fail-open mode and the unverified state was saved. Run `oden audit` to retry.",
        missing.len()
      );
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
    if self.inner.mode.is_strict() && !missing.is_empty() {
      let names = missing
        .iter()
        .take(5)
        .map(|entry| format!("{}@{}", entry.name, entry.version))
        .collect::<Vec<_>>()
        .join(", ");
      let error = format!(
        "Socket strict scan has no valid verdict for {} package(s): {}",
        missing.len(),
        names
      );
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
      .or_else(|| {
        Some(by_nv.get(&format!("{}@{}", name?, version?)).copied()?)
      });
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

fn load_store(path: &Path) -> VerdictStore {
  let Ok(bytes) = std::fs::read(path) else {
    return VerdictStore {
      v: STORE_VERSION,
      entries: Default::default(),
    };
  };
  match serde_json::from_slice::<VerdictStore>(&bytes) {
    Ok(store) if store.v == STORE_VERSION => store,
    Ok(_) => {
      log::warn!(
        "Ignoring unsupported Oden Socket verdict cache at {}",
        path.display()
      );
      VerdictStore {
        v: STORE_VERSION,
        entries: Default::default(),
      }
    }
    Err(err) => {
      log::warn!(
        "Ignoring invalid Oden Socket verdict cache at {}: {}",
        path.display(),
        err
      );
      VerdictStore {
        v: STORE_VERSION,
        entries: Default::default(),
      }
    }
  }
}

fn write_store(path: &Path, store: &VerdictStore) -> Result<(), AnyError> {
  write_json_atomic(path, store)
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

  fn request(name: &str, version: &str) -> PackageRequest {
    PackageRequest {
      name: name.to_string(),
      version: version.to_string(),
      integrity: Some("sha512-test".to_string()),
      registry: DEFAULT_PUBLIC_REGISTRY.to_string(),
      tarball: format!("{}{}-{}.tgz", DEFAULT_PUBLIC_REGISTRY, name, version),
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

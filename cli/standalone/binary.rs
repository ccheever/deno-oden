// Copyright 2018-2026 the Deno authors. MIT license.

use std::borrow::Cow;
use std::cell::Cell;
use std::collections::HashMap;
use std::collections::HashSet;
use std::collections::VecDeque;
use std::env;
use std::ffi::OsString;
use std::fs;
use std::fs::File;
use std::path::Component;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;

use capacity_builder::BytesAppendable;
use deno_ast::MediaType;
use deno_ast::ModuleKind;
use deno_ast::ModuleSpecifier;
use deno_ast::SourceRangedForSpanned;
use deno_ast::StartSourcePos;
use deno_ast::swc::ast;
use deno_ast::swc::ecma_visit::Visit;
use deno_ast::swc::ecma_visit::VisitWith;
use deno_cache_dir::CACHE_PERM;
use deno_core::anyhow::Context;
use deno_core::anyhow::bail;
use deno_core::error::AnyError;
use deno_core::serde_json;
use deno_core::url::Url;
use deno_graph::Dependency;
use deno_graph::ImportKind;
use deno_graph::ModuleGraph;
use deno_graph::Resolution;
use deno_graph::analysis::ImportAttribute;
use deno_graph::analysis::ImportAttributes;
use deno_graph::source::ResolutionMode;
use deno_lib::args::CaData;
use deno_lib::args::UnstableConfig;
use deno_lib::shared::ReleaseChannel;
use deno_lib::standalone::binary::CjsExportAnalysisEntry;
use deno_lib::standalone::binary::MAGIC_BYTES;
use deno_lib::standalone::binary::Metadata;
use deno_lib::standalone::binary::NodeModules;
use deno_lib::standalone::binary::RemoteModuleEntry;
use deno_lib::standalone::binary::SerializedResolverWorkspaceJsrPackage;
use deno_lib::standalone::binary::SerializedWorkspaceResolver;
use deno_lib::standalone::binary::SerializedWorkspaceResolverImportMap;
use deno_lib::standalone::binary::SpecifierDataStore;
use deno_lib::standalone::binary::SpecifierId;
use deno_lib::standalone::oden_parent_allowlist::ODEN_PARENT_ENTRYPOINT_KEY;
use deno_lib::standalone::oden_parent_allowlist::ODEN_PARENT_PRIVATE_MODULE_SPECIFIER;
use deno_lib::standalone::oden_parent_allowlist::OdenParentAllowlistError;
use deno_lib::standalone::oden_parent_allowlist::OdenParentImportAttributes;
use deno_lib::standalone::oden_parent_allowlist::OdenParentObservedImportAttribute as OdenParentProjectedImportAttribute;
use deno_lib::standalone::oden_parent_allowlist::OdenParentStaticImportEdge;
use deno_lib::standalone::oden_parent_allowlist::OdenParentStaticImportEdgeObservation;
use deno_lib::standalone::oden_parent_allowlist::OdenParentVfsDependencyKind;
use deno_lib::standalone::virtual_fs::BuiltVfs;
use deno_lib::standalone::virtual_fs::DENO_COMPILE_GLOBAL_NODE_MODULES_DIR_NAME;
use deno_lib::standalone::virtual_fs::VfsBuilder;
use deno_lib::standalone::virtual_fs::VfsEntry;
use deno_lib::standalone::virtual_fs::VirtualDirectory;
use deno_lib::standalone::virtual_fs::VirtualDirectoryEntries;
use deno_lib::standalone::virtual_fs::WindowsSystemRootablePath;
use deno_lib::util::hash::FastInsecureHasher;
use deno_lib::util::text_encoding::is_valid_utf8;
use deno_lib::util::v8::construct_v8_flags;
use deno_lib::version::DENO_VERSION_INFO;
use deno_npm::NpmSystemInfo;
use deno_npm::resolution::SerializedNpmResolutionSnapshot;
use deno_npm::resolution::ValidSerializedNpmResolutionSnapshot;
use deno_path_util::fs::atomic_write_file_with_retries;
use deno_path_util::url_from_directory_path;
use deno_path_util::url_to_file_path;
use deno_resolver::file_fetcher::FetchLocalOptions;
use deno_resolver::file_fetcher::FetchOptions;
use deno_resolver::file_fetcher::FetchPermissionsOptionRef;
use deno_resolver::workspace::WorkspaceResolver;
use deno_semver::npm::NpmPackageReqReference;
use indexmap::IndexMap;
use node_resolver::analyze::ResolvedCjsAnalysis;

use super::virtual_fs::output_vfs;
use crate::args::CliOptions;
use crate::args::CompileFlags;
use crate::args::CompileFlagsExt;
use crate::args::get_default_v8_flags;
use crate::cache::DenoDir;
use crate::file_fetcher::CliFileFetcher;
use crate::http_util::HttpClientProvider;
use crate::module_loader::CliEmitter;
use crate::node::CliCjsModuleExportAnalyzer;
use crate::npm::CliNpmResolver;
use crate::resolver::CliCjsTracker;
use crate::sys::CliSys;
use crate::util::archive;
use crate::util::env::handle_dotenv_error;
use crate::util::env::handle_dotenv_io_error;
use crate::util::env::handle_dotenv_not_found;
use crate::util::progress_bar::ProgressBar;
use crate::util::progress_bar::ProgressBarStyle;
use crate::util::progress_bar::ProgressMessagePrompt;

/// A URL that can be designated as the base for relative URLs.
///
/// After creation, this URL may be used to get the key for a
/// module in the binary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum StandaloneRelativeFileBaseUrl<'a> {
  WindowsSystemRoot,
  Path(&'a Url),
}

impl StandaloneRelativeFileBaseUrl<'_> {
  /// Gets the module map key of the provided specifier.
  ///
  /// * Descendant file specifiers will be made relative to the base.
  /// * Non-descendant file specifiers will stay as-is (absolute).
  /// * Non-file specifiers will stay as-is.
  pub fn specifier_key<'b>(&self, target: &'b Url) -> Cow<'b, str> {
    if target.scheme() != "file" {
      return Cow::Borrowed(target.as_str());
    }
    let base = match self {
      Self::Path(base) => base,
      Self::WindowsSystemRoot => return Cow::Borrowed(target.path()),
    };

    match base.make_relative(target) {
      Some(relative) => {
        // This is not a great scenario to have because it means that the
        // specifier is outside the vfs and could cause the binary to act
        // strangely. If you encounter this, the fix is to add more paths
        // to the vfs builder by calling `add_possible_min_root_dir`.
        debug_assert!(
          !relative.starts_with("../"),
          "{} -> {} ({})",
          base.as_str(),
          target.as_str(),
          relative,
        );
        Cow::Owned(relative)
      }
      None => Cow::Borrowed(target.as_str()),
    }
  }
}

struct SpecifierStore<'a> {
  data: IndexMap<&'a Url, SpecifierId>,
}

impl<'a> SpecifierStore<'a> {
  pub fn with_capacity(capacity: usize) -> Self {
    Self {
      data: IndexMap::with_capacity(capacity),
    }
  }

  pub fn get_or_add(&mut self, specifier: &'a Url) -> SpecifierId {
    let len = self.data.len();
    let entry = self.data.entry(specifier);
    match entry {
      indexmap::map::Entry::Occupied(occupied_entry) => *occupied_entry.get(),
      indexmap::map::Entry::Vacant(vacant_entry) => {
        let new_id = SpecifierId::new(len as u32);
        vacant_entry.insert(new_id);
        new_id
      }
    }
  }

  pub fn for_serialization(
    self,
    base_url: &StandaloneRelativeFileBaseUrl<'a>,
  ) -> SpecifierStoreForSerialization<'a> {
    SpecifierStoreForSerialization {
      data: self
        .data
        .into_iter()
        .map(|(specifier, id)| (base_url.specifier_key(specifier), id))
        .collect(),
    }
  }
}

struct SpecifierStoreForSerialization<'a> {
  data: Vec<(Cow<'a, str>, SpecifierId)>,
}

impl<'a> BytesAppendable<'a> for &'a SpecifierStoreForSerialization<'a> {
  fn append_to_builder<TBytes: capacity_builder::BytesType>(
    self,
    builder: &mut capacity_builder::BytesBuilder<'a, TBytes>,
  ) {
    builder.append_le(self.data.len() as u32);
    for (specifier_str, id) in &self.data {
      builder.append_le(specifier_str.len() as u32);
      builder.append(specifier_str.as_ref());
      builder.append(*id);
    }
  }
}

/// Given a canonical npm package folder (e.g.
/// `<.deno>/<id>/node_modules/@scope/name`), walk up to the enclosing
/// `node_modules/` directory. Embedding from there picks up sibling
/// symlinks the deno linker creates for direct dependencies, which the
/// canonical folder itself doesn't contain.
fn pkg_folder_node_modules_root(folder: &Path) -> Option<&Path> {
  let mut current = folder.parent()?;
  loop {
    if current.file_name() == Some(std::ffi::OsStr::new("node_modules")) {
      return Some(current);
    }
    current = current.parent()?;
  }
}

pub fn is_standalone_binary(exe_path: &Path) -> bool {
  let Ok(data) = std::fs::read(exe_path) else {
    return false;
  };
  libsui::utils::is_elf(&data)
    || libsui::utils::is_pe(&data)
    || libsui::utils::is_macho(&data)
}

/// Validate a user-provided `--app-name`. The name becomes a single directory
/// component under the platform's app data directory at runtime. Because a
/// binary can be cross-compiled, validate against the union of what every
/// target OS allows so the baked identity resolves to one unambiguous
/// directory component everywhere, rather than escaping the directory or
/// failing on the target's filesystem. Done here so the user gets a clear
/// compile-time error instead of a surprising (or unusable) store location.
fn validate_app_name(app_name: &str) -> Result<(), AnyError> {
  const RESERVED_NAMES: [&str; 22] = [
    "con", "prn", "aux", "nul", "com1", "com2", "com3", "com4", "com5", "com6",
    "com7", "com8", "com9", "lpt1", "lpt2", "lpt3", "lpt4", "lpt5", "lpt6",
    "lpt7", "lpt8", "lpt9",
  ];

  // Windows reserved device names match case-insensitively against the portion
  // before the first `.` (so `nul`, `NUL`, and `nul.txt` all match).
  let stem = app_name.split('.').next().unwrap_or(app_name);
  let is_reserved_name =
    RESERVED_NAMES.iter().any(|n| stem.eq_ignore_ascii_case(n));

  let reason = if app_name.is_empty() {
    Some("must not be empty")
  } else if app_name == "." || app_name == ".." {
    Some("must not be `.` or `..`")
  } else if app_name
    // `/` and `\` are path separators; `<>:"|?*` are reserved on Windows;
    // control characters are rejected by the filesystem.
    .contains(|c: char| {
      matches!(c, '/' | '\\' | '<' | '>' | ':' | '"' | '|' | '?' | '*')
        || c.is_control()
    })
  {
    Some("must not contain path separators or any of `<>:\"|?*`")
  } else if app_name.ends_with('.')
    || app_name.ends_with(' ')
    || app_name.starts_with(' ')
  {
    // Windows silently strips trailing dots and spaces, which would change the
    // identity out from under the user; a leading space is an error-prone
    // directory name everywhere, so reject it too.
    Some("must not start or end with a space, or end with a `.`")
  } else if is_reserved_name {
    Some("must not be a reserved device name (e.g. `CON`, `NUL`, `COM1`)")
  } else {
    None
  };

  if let Some(reason) = reason {
    bail!("Invalid `--app-name` value {:?}: {}.", app_name, reason);
  }
  Ok(())
}

/// Resolve the stable app identity baked into a compiled binary: an explicit
/// `--app-name`, otherwise the output file name (minus any `.exe` extension).
/// The derived default is held to the same rules as an explicit flag, since it
/// becomes a single directory component at runtime (possibly on a different
/// target OS when cross-compiling); otherwise an output name like `aux` or one
/// with a trailing dot would silently break persistent storage on the target.
fn resolve_app_name(
  compile_flags: &CompileFlags,
  display_output_filename: &str,
) -> Result<String, AnyError> {
  let app_name = compile_flags.app_name.clone().unwrap_or_else(|| {
    display_output_filename
      .strip_suffix(".exe")
      .unwrap_or(display_output_filename)
      .to_string()
  });
  validate_app_name(&app_name)?;
  Ok(app_name)
}

pub struct WriteBinOptions<'a> {
  pub writer: File,
  pub display_output_filename: &'a str,
  pub graph: &'a ModuleGraph,
  pub entrypoint: &'a ModuleSpecifier,
  pub include_paths: &'a [ModuleSpecifier],
  pub exclude_paths: Vec<PathBuf>,
  pub compile_flags: &'a CompileFlags,
}

#[allow(dead_code)]
#[derive(Clone, Debug, PartialEq, Eq)]
struct OdenParentObservedImportAttribute {
  key: String,
  value: String,
}

#[allow(dead_code)]
#[derive(Clone, Debug, PartialEq, Eq)]
struct OdenParentObservedRuntimeDependency {
  kind: OdenParentVfsDependencyKind,
  raw_specifier: String,
  resolved_specifier: ModuleSpecifier,
  source_byte_start: u64,
  source_byte_end: u64,
  import_attributes: Vec<OdenParentObservedImportAttribute>,
}

#[allow(dead_code)]
#[derive(Clone, Debug, PartialEq, Eq)]
struct OdenParentReleaseEntrypointCandidate {
  entrypoint_specifier: ModuleSpecifier,
  original_bytes: Arc<[u8]>,
  runtime_dependencies: Vec<OdenParentObservedRuntimeDependency>,
  static_import_edge: OdenParentStaticImportEdge,
}

#[allow(dead_code)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OdenParentOrdinaryEsmMediaType {
  JavaScript,
  TypeScript,
}

#[allow(dead_code)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OdenParentOrdinaryEsmDependencyTargetKind {
  JavaScript,
  TypeScript,
  Json,
  Wasm,
  NodeBuiltin,
}

#[allow(dead_code)]
#[derive(Clone, Debug, PartialEq, Eq)]
struct OdenParentGraphRedirectHop {
  requested_specifier: ModuleSpecifier,
  redirected_specifier: ModuleSpecifier,
}

#[allow(dead_code)]
#[derive(Clone, Debug, PartialEq, Eq)]
struct OdenParentOrdinaryEsmRuntimeDependencyCandidate {
  observation: OdenParentObservedRuntimeDependency,
  redirect_chain: Vec<OdenParentGraphRedirectHop>,
  graph_final_specifier: ModuleSpecifier,
  target_kind: OdenParentOrdinaryEsmDependencyTargetKind,
}

#[allow(dead_code)]
#[derive(Clone, Debug, PartialEq, Eq)]
struct OdenParentOrdinaryEsmGraphModuleCandidate {
  graph_final_module_specifier: ModuleSpecifier,
  media_type: OdenParentOrdinaryEsmMediaType,
  original_bytes: Arc<[u8]>,
  runtime_dependencies: Vec<OdenParentOrdinaryEsmRuntimeDependencyCandidate>,
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
enum OdenParentRuntimeDependencyObservationError {
  #[error("invalid original module bytes: {0}")]
  InvalidOriginalBytes(&'static str),
  #[error("pinned parser refused the exact original module bytes: {0}")]
  Parse(String),
  #[error("unsupported runtime dependency syntax: {0}")]
  UnsupportedAst(&'static str),
  #[error("module specifier is not one exact unescaped string literal: {0}")]
  InvalidLiteral(&'static str),
  #[error("unsupported import attributes: {0}")]
  InvalidImportAttributes(&'static str),
  #[error("unsupported deno_graph dependency fact: {0}")]
  UnsupportedGraph(String),
  #[error("AST and deno_graph dependency facts do not reconcile: {0}")]
  GraphMismatch(String),
  #[error("deno_graph contains an unmatched dependency occurrence: {0}")]
  GraphLeftover(String),
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
enum OdenParentReleaseEntrypointCandidateError {
  #[error("invalid release entrypoint graph fact: {0}")]
  InvalidGraph(&'static str),
  #[error(transparent)]
  RuntimeDependency(#[from] OdenParentRuntimeDependencyObservationError),
  #[error(transparent)]
  StaticImportEdge(#[from] OdenParentAllowlistError),
}

#[derive(Debug, PartialEq, Eq, thiserror::Error)]
enum OdenParentOrdinaryEsmGraphModuleCandidateError {
  #[error("invalid ordinary ESM graph fact: {0}")]
  InvalidGraph(&'static str),
  #[error(transparent)]
  RuntimeDependency(#[from] OdenParentRuntimeDependencyObservationError),
}

#[derive(Debug)]
struct OdenParentExactStringLiteral {
  decoded: String,
  full_start: usize,
  full_end: usize,
  payload_start: usize,
  payload_end: usize,
}

#[derive(Debug)]
struct OdenParentAstRuntimeDependency {
  kind: OdenParentVfsDependencyKind,
  raw_specifier: String,
  full_start: usize,
  full_end: usize,
  source_byte_start: usize,
  source_byte_end: usize,
  import_attributes_present: bool,
  import_attributes: Vec<OdenParentObservedImportAttribute>,
}

struct OdenParentRuntimeDependencyAstCollector<'a> {
  original_bytes: &'a [u8],
  source_start: StartSourcePos,
  observations: Vec<OdenParentAstRuntimeDependency>,
  error: Option<OdenParentRuntimeDependencyObservationError>,
}

impl OdenParentRuntimeDependencyAstCollector<'_> {
  fn exact_string_literal(
    &self,
    literal: &ast::Str,
  ) -> Result<
    OdenParentExactStringLiteral,
    OdenParentRuntimeDependencyObservationError,
  > {
    let full_range = literal.range().as_byte_range(self.source_start);
    let Some(full_bytes) = self.original_bytes.get(full_range.clone()) else {
      return Err(OdenParentRuntimeDependencyObservationError::InvalidLiteral(
        "parser range is outside the supplied original bytes",
      ));
    };
    let Some(raw) = literal.raw.as_ref() else {
      return Err(OdenParentRuntimeDependencyObservationError::InvalidLiteral(
        "parser did not retain the raw token",
      ));
    };
    if raw.as_bytes() != full_bytes {
      return Err(OdenParentRuntimeDependencyObservationError::InvalidLiteral(
        "parser raw token differs from the supplied original bytes",
      ));
    }
    if full_bytes.len() < 2
      || !matches!(full_bytes.first(), Some(b'\'' | b'"'))
      || full_bytes.first() != full_bytes.last()
    {
      return Err(OdenParentRuntimeDependencyObservationError::InvalidLiteral(
        "token is not bounded by one matching quote pair",
      ));
    }
    let Some(decoded) = literal.value.as_str() else {
      return Err(OdenParentRuntimeDependencyObservationError::InvalidLiteral(
        "decoded token is not Unicode",
      ));
    };
    let payload_start = full_range.start + 1;
    let payload_end = full_range.end - 1;
    if self.original_bytes[payload_start..payload_end] != *decoded.as_bytes() {
      return Err(OdenParentRuntimeDependencyObservationError::InvalidLiteral(
        "raw payload contains an escape or differs from the decoded value",
      ));
    }
    Ok(OdenParentExactStringLiteral {
      decoded: decoded.to_string(),
      full_start: full_range.start,
      full_end: full_range.end,
      payload_start,
      payload_end,
    })
  }

  fn exact_identifier(
    &self,
    identifier: &ast::IdentName,
  ) -> Result<String, OdenParentRuntimeDependencyObservationError> {
    let range = identifier.range().as_byte_range(self.source_start);
    let Some(raw_bytes) = self.original_bytes.get(range) else {
      return Err(
        OdenParentRuntimeDependencyObservationError::InvalidImportAttributes(
          "identifier range is outside the supplied original bytes",
        ),
      );
    };
    if raw_bytes != identifier.sym.as_bytes() {
      return Err(
        OdenParentRuntimeDependencyObservationError::InvalidImportAttributes(
          "attribute identifier is escaped or differs from its decoded value",
        ),
      );
    }
    Ok(identifier.sym.to_string())
  }

  fn exact_property_name(
    &self,
    name: &ast::PropName,
  ) -> Result<String, OdenParentRuntimeDependencyObservationError> {
    match name {
      ast::PropName::Ident(identifier) => self.exact_identifier(identifier),
      ast::PropName::Str(value) => {
        Ok(self.exact_string_literal(value)?.decoded)
      }
      _ => Err(
        OdenParentRuntimeDependencyObservationError::InvalidImportAttributes(
          "attribute key is computed or is not a string/identifier",
        ),
      ),
    }
  }

  fn exact_import_attributes(
    &self,
    object: &ast::ObjectLit,
  ) -> Result<
    Vec<OdenParentObservedImportAttribute>,
    OdenParentRuntimeDependencyObservationError,
  > {
    let mut attributes = Vec::with_capacity(object.props.len());
    for property in &object.props {
      let ast::PropOrSpread::Prop(property) = property else {
        return Err(
          OdenParentRuntimeDependencyObservationError::InvalidImportAttributes(
            "attribute spread is not supported",
          ),
        );
      };
      let ast::Prop::KeyValue(property) = &**property else {
        return Err(
          OdenParentRuntimeDependencyObservationError::InvalidImportAttributes(
            "attribute is not a key/value pair",
          ),
        );
      };
      let key = self.exact_property_name(&property.key)?;
      let ast::Expr::Lit(ast::Lit::Str(value)) = &*property.value else {
        return Err(
          OdenParentRuntimeDependencyObservationError::InvalidImportAttributes(
            "attribute value is not a string literal",
          ),
        );
      };
      attributes.push(OdenParentObservedImportAttribute {
        key,
        value: self.exact_string_literal(value)?.decoded,
      });
    }
    Ok(attributes)
  }

  fn dynamic_import_attributes(
    &self,
    arguments: &[ast::ExprOrSpread],
  ) -> Result<
    (bool, Vec<OdenParentObservedImportAttribute>),
    OdenParentRuntimeDependencyObservationError,
  > {
    match arguments {
      [_specifier] => Ok((false, Vec::new())),
      [_specifier, options] if options.spread.is_none() => {
        let ast::Expr::Object(options) = &*options.expr else {
          return Err(
            OdenParentRuntimeDependencyObservationError::InvalidImportAttributes(
              "dynamic-import options are not an object literal",
            ),
          );
        };
        if options.props.len() != 1 {
          return Err(
            OdenParentRuntimeDependencyObservationError::InvalidImportAttributes(
              "dynamic-import options are not exactly one `with` property",
            ),
          );
        }
        let ast::PropOrSpread::Prop(property) = &options.props[0] else {
          return Err(
            OdenParentRuntimeDependencyObservationError::InvalidImportAttributes(
              "dynamic-import options contain a spread",
            ),
          );
        };
        let ast::Prop::KeyValue(property) = &**property else {
          return Err(
            OdenParentRuntimeDependencyObservationError::InvalidImportAttributes(
              "dynamic-import option is not a key/value pair",
            ),
          );
        };
        if self.exact_property_name(&property.key)? != "with" {
          return Err(
            OdenParentRuntimeDependencyObservationError::InvalidImportAttributes(
              "dynamic-import option is not `with`",
            ),
          );
        }
        let ast::Expr::Object(attributes) = &*property.value else {
          return Err(
            OdenParentRuntimeDependencyObservationError::InvalidImportAttributes(
              "dynamic-import `with` value is not an object literal",
            ),
          );
        };
        Ok((true, self.exact_import_attributes(attributes)?))
      }
      [_specifier, _options] => Err(
        OdenParentRuntimeDependencyObservationError::InvalidImportAttributes(
          "dynamic-import options use spread syntax",
        ),
      ),
      _ => Err(OdenParentRuntimeDependencyObservationError::UnsupportedAst(
        "dynamic import does not have exactly one specifier and at most one options object",
      )),
    }
  }

  fn record_static(
    &mut self,
    kind: OdenParentVfsDependencyKind,
    source: &ast::Str,
    attributes: Option<&ast::ObjectLit>,
  ) {
    if self.error.is_some() {
      return;
    }
    let result = (|| {
      let source = self.exact_string_literal(source)?;
      let import_attributes = attributes
        .map(|attributes| self.exact_import_attributes(attributes))
        .transpose()?
        .unwrap_or_default();
      Ok(OdenParentAstRuntimeDependency {
        kind,
        raw_specifier: source.decoded,
        full_start: source.full_start,
        full_end: source.full_end,
        source_byte_start: source.payload_start,
        source_byte_end: source.payload_end,
        import_attributes_present: attributes.is_some(),
        import_attributes,
      })
    })();
    match result {
      Ok(observation) => self.observations.push(observation),
      Err(error) => self.error = Some(error),
    }
  }
}

impl Visit for OdenParentRuntimeDependencyAstCollector<'_> {
  fn visit_import_decl(&mut self, node: &ast::ImportDecl) {
    if node.type_only {
      self.error =
        Some(OdenParentRuntimeDependencyObservationError::UnsupportedAst(
          "type-only import",
        ));
      return;
    }
    if node.phase != ast::ImportPhase::Evaluation {
      self.error =
        Some(OdenParentRuntimeDependencyObservationError::UnsupportedAst(
          "source/defer import phase",
        ));
      return;
    }
    self.record_static(
      OdenParentVfsDependencyKind::StaticImport,
      &node.src,
      node.with.as_deref(),
    );
  }

  fn visit_export_all(&mut self, node: &ast::ExportAll) {
    if node.type_only {
      self.error =
        Some(OdenParentRuntimeDependencyObservationError::UnsupportedAst(
          "type-only export",
        ));
      return;
    }
    self.record_static(
      OdenParentVfsDependencyKind::StaticExport,
      &node.src,
      node.with.as_deref(),
    );
  }

  fn visit_named_export(&mut self, node: &ast::NamedExport) {
    let Some(source) = &node.src else {
      return;
    };
    if node.type_only {
      self.error =
        Some(OdenParentRuntimeDependencyObservationError::UnsupportedAst(
          "type-only export",
        ));
      return;
    }
    self.record_static(
      OdenParentVfsDependencyKind::StaticExport,
      source,
      node.with.as_deref(),
    );
  }

  fn visit_ts_import_type(&mut self, _node: &ast::TsImportType) {
    self.error =
      Some(OdenParentRuntimeDependencyObservationError::UnsupportedAst(
        "TypeScript import type expression",
      ));
  }

  fn visit_ts_import_equals_decl(&mut self, _node: &ast::TsImportEqualsDecl) {
    self.error =
      Some(OdenParentRuntimeDependencyObservationError::UnsupportedAst(
        "TypeScript import-equals dependency",
      ));
  }

  fn visit_call_expr(&mut self, node: &ast::CallExpr) {
    node.visit_children_with(self);
    if self.error.is_some() {
      return;
    }
    let import = match &node.callee {
      ast::Callee::Import(import) => import,
      ast::Callee::Expr(callee) if matches!(&**callee, ast::Expr::Ident(identifier) if identifier.sym == "require") =>
      {
        self.error =
          Some(OdenParentRuntimeDependencyObservationError::UnsupportedAst(
            "require call",
          ));
        return;
      }
      _ => return,
    };
    if import.phase != ast::ImportPhase::Evaluation {
      self.error =
        Some(OdenParentRuntimeDependencyObservationError::UnsupportedAst(
          "source/defer dynamic-import phase",
        ));
      return;
    }
    let Some(specifier) = node.args.first() else {
      self.error =
        Some(OdenParentRuntimeDependencyObservationError::UnsupportedAst(
          "dynamic import has no specifier",
        ));
      return;
    };
    if specifier.spread.is_some() {
      self.error =
        Some(OdenParentRuntimeDependencyObservationError::UnsupportedAst(
          "dynamic-import specifier uses spread syntax",
        ));
      return;
    }
    let ast::Expr::Lit(ast::Lit::Str(specifier)) = &*specifier.expr else {
      self.error =
        Some(OdenParentRuntimeDependencyObservationError::UnsupportedAst(
          "computed or template dynamic-import specifier",
        ));
      return;
    };
    let result = (|| {
      let specifier = self.exact_string_literal(specifier)?;
      let (import_attributes_present, import_attributes) =
        self.dynamic_import_attributes(&node.args)?;
      Ok(OdenParentAstRuntimeDependency {
        kind: OdenParentVfsDependencyKind::DynamicImport,
        raw_specifier: specifier.decoded,
        full_start: specifier.full_start,
        full_end: specifier.full_end,
        source_byte_start: specifier.payload_start,
        source_byte_end: specifier.payload_end,
        import_attributes_present,
        import_attributes,
      })
    })();
    match result {
      Ok(observation) => self.observations.push(observation),
      Err(error) => self.error = Some(error),
    }
  }
}

fn oden_parent_position_byte_offset(
  source: &str,
  position: deno_graph::Position,
) -> Option<usize> {
  let mut line_start = 0;
  for _ in 0..position.line {
    let newline = source[line_start..].find('\n')?;
    line_start = line_start.checked_add(newline + 1)?;
  }
  let line_end = source[line_start..]
    .find('\n')
    .map(|index| line_start + index)
    .unwrap_or(source.len());
  let line = &source[line_start..line_end];
  if position.character == line.chars().count() {
    return Some(line_end);
  }
  line
    .char_indices()
    .nth(position.character)
    .map(|(index, _)| line_start + index)
}

fn oden_parent_position_range_bytes(
  source: &str,
  range: &deno_graph::PositionRange,
) -> Option<std::ops::Range<usize>> {
  let start = oden_parent_position_byte_offset(source, range.start)?;
  let end = oden_parent_position_byte_offset(source, range.end)?;
  (start <= end).then_some(start..end)
}

fn oden_parent_graph_import_attributes_are_supported(
  attributes: &ImportAttributes,
) -> bool {
  match attributes {
    ImportAttributes::None => true,
    ImportAttributes::Unknown => false,
    ImportAttributes::Known(attributes) => attributes
      .values()
      .all(|value| matches!(value, ImportAttribute::Known(_))),
  }
}

fn oden_parent_graph_import_attributes_match(
  graph_attributes: &ImportAttributes,
  ast_attributes_present: bool,
  ast_attributes: &[OdenParentObservedImportAttribute],
) -> bool {
  let ImportAttributes::Known(graph_attributes) = graph_attributes else {
    return !ast_attributes_present
      && ast_attributes.is_empty()
      && matches!(graph_attributes, ImportAttributes::None);
  };
  if !ast_attributes_present {
    return false;
  }
  let mut collapsed = HashMap::with_capacity(ast_attributes.len());
  for attribute in ast_attributes {
    collapsed.insert(attribute.key.as_str(), attribute.value.as_str());
  }
  graph_attributes.len() == collapsed.len()
    && graph_attributes.iter().all(|(key, value)| {
      let ImportAttribute::Known(value) = value else {
        return false;
      };
      collapsed.get(key.as_str()).copied() == Some(value.as_str())
    })
}

struct OdenParentGraphRuntimeDependencyOccurrence<'a> {
  dependency_key: &'a str,
  import: &'a deno_graph::Import,
  resolved_specifier: &'a ModuleSpecifier,
  full_range: std::ops::Range<usize>,
  used: bool,
}

// @ref LLP 0019#frozen-parent-standalone-allowlist-and-byte-graph [implements] --
// Preserve exact parser occurrences before deno_graph's attribute-map loss.
#[allow(dead_code)]
fn observe_oden_parent_runtime_dependencies(
  specifier: &ModuleSpecifier,
  media_type: MediaType,
  original_bytes: &[u8],
  graph_dependencies: &IndexMap<String, Dependency>,
) -> Result<
  Vec<OdenParentObservedRuntimeDependency>,
  OdenParentRuntimeDependencyObservationError,
> {
  let original_source = std::str::from_utf8(original_bytes).map_err(|_| {
    OdenParentRuntimeDependencyObservationError::InvalidOriginalBytes(
      "source is not UTF-8",
    )
  })?;
  if original_bytes.starts_with(&[0xef, 0xbb, 0xbf]) {
    return Err(
      OdenParentRuntimeDependencyObservationError::InvalidOriginalBytes(
        "UTF-8 BOM is not an admitted original-byte preimage",
      ),
    );
  }
  if !matches!(media_type, MediaType::JavaScript | MediaType::TypeScript) {
    return Err(
      OdenParentRuntimeDependencyObservationError::InvalidOriginalBytes(
        "media type is not JavaScript or TypeScript",
      ),
    );
  }

  let parsed = deno_ast::parse_module(deno_ast::ParseParams {
    specifier: specifier.clone(),
    text: original_source.to_string().into(),
    media_type,
    capture_tokens: false,
    maybe_syntax: None,
    scope_analysis: false,
  })
  .map_err(|error| {
    OdenParentRuntimeDependencyObservationError::Parse(error.to_string())
  })?;
  if parsed.text().as_bytes() != original_bytes {
    return Err(
      OdenParentRuntimeDependencyObservationError::InvalidOriginalBytes(
        "parser text differs from supplied original bytes",
      ),
    );
  }

  let mut collector = OdenParentRuntimeDependencyAstCollector {
    original_bytes,
    source_start: parsed.text_info_lazy().range().start,
    observations: Vec::new(),
    error: None,
  };
  parsed.program().visit_with(&mut collector);
  if let Some(error) = collector.error {
    return Err(error);
  }

  let mut graph_occurrences = Vec::new();
  for (dependency_key, dependency) in graph_dependencies {
    if !matches!(dependency.maybe_type, Resolution::None)
      || dependency.maybe_deno_types_specifier.is_some()
    {
      return Err(
        OdenParentRuntimeDependencyObservationError::UnsupportedGraph(format!(
          "type dependency for {dependency_key:?}"
        )),
      );
    }
    let Resolution::Ok(resolution) = &dependency.maybe_code else {
      return Err(
        OdenParentRuntimeDependencyObservationError::UnsupportedGraph(format!(
          "missing successful code resolution for {dependency_key:?}"
        )),
      );
    };
    if dependency.imports.is_empty() {
      return Err(
        OdenParentRuntimeDependencyObservationError::UnsupportedGraph(format!(
          "code resolution for {dependency_key:?} has no imports"
        )),
      );
    }
    if dependency.is_dynamic
      != dependency.imports.iter().all(|import| import.is_dynamic)
    {
      return Err(OdenParentRuntimeDependencyObservationError::GraphMismatch(
        format!("aggregate dynamic flag for {dependency_key:?}"),
      ));
    }
    if resolution.range.specifier != *specifier
      || resolution.range.resolution_mode != Some(ResolutionMode::Import)
    {
      return Err(OdenParentRuntimeDependencyObservationError::GraphMismatch(
        format!("resolution referrer for {dependency_key:?}"),
      ));
    }
    let Some(resolution_range) = oden_parent_position_range_bytes(
      original_source,
      &resolution.range.range,
    ) else {
      return Err(OdenParentRuntimeDependencyObservationError::GraphMismatch(
        format!("resolution range for {dependency_key:?}"),
      ));
    };

    let mut first_import_range = None;
    let mut first_import_attributes = None;
    for import in &dependency.imports {
      if import.kind != ImportKind::Es {
        return Err(
          OdenParentRuntimeDependencyObservationError::UnsupportedGraph(
            format!(
              "non-ES runtime kind {:?} for {dependency_key:?}",
              import.kind
            ),
          ),
        );
      }
      if import.specifier != *dependency_key
        || import.specifier_range.specifier != *specifier
        || import.specifier_range.resolution_mode
          != Some(ResolutionMode::Import)
      {
        return Err(
          OdenParentRuntimeDependencyObservationError::GraphMismatch(format!(
            "specifier/referrer for {dependency_key:?}"
          )),
        );
      }
      if !oden_parent_graph_import_attributes_are_supported(&import.attributes)
      {
        return Err(
          OdenParentRuntimeDependencyObservationError::UnsupportedGraph(
            format!("unknown import attributes for {dependency_key:?}"),
          ),
        );
      }
      if let Some(first_import_attributes) = first_import_attributes {
        if first_import_attributes != &import.attributes {
          return Err(
            OdenParentRuntimeDependencyObservationError::GraphMismatch(
              format!(
                "heterogeneous import attributes share one code resolution for {dependency_key:?}"
              ),
            ),
          );
        }
      } else {
        first_import_attributes = Some(&import.attributes);
      }
      let Some(full_range) = oden_parent_position_range_bytes(
        original_source,
        &import.specifier_range.range,
      ) else {
        return Err(
          OdenParentRuntimeDependencyObservationError::GraphMismatch(format!(
            "import range for {dependency_key:?}"
          )),
        );
      };
      first_import_range.get_or_insert_with(|| full_range.clone());
      graph_occurrences.push(OdenParentGraphRuntimeDependencyOccurrence {
        dependency_key,
        import,
        resolved_specifier: &resolution.specifier,
        full_range,
        used: false,
      });
    }
    let first_attribute_type = match first_import_attributes.unwrap() {
      ImportAttributes::Known(attributes) => match attributes.get("type") {
        Some(ImportAttribute::Known(value)) => Some(value.as_str()),
        Some(ImportAttribute::Unknown) => unreachable!(
          "unknown graph attribute values were refused before this join"
        ),
        None => None,
      },
      ImportAttributes::None => None,
      ImportAttributes::Unknown => unreachable!(
        "unknown graph attribute sets were refused before this join"
      ),
    };
    if dependency.maybe_attribute_type.as_deref() != first_attribute_type {
      return Err(OdenParentRuntimeDependencyObservationError::GraphMismatch(
        format!("attribute-type resolution input for {dependency_key:?}"),
      ));
    }
    if first_import_range.as_ref() != Some(&resolution_range) {
      return Err(OdenParentRuntimeDependencyObservationError::GraphMismatch(
        format!(
          "code resolution does not point to the first import for {dependency_key:?}"
        ),
      ));
    }
  }

  let mut observations = Vec::with_capacity(collector.observations.len());
  for ast_observation in collector.observations {
    let matching = graph_occurrences
      .iter()
      .enumerate()
      .filter_map(|(index, graph_occurrence)| {
        (!graph_occurrence.used
          && graph_occurrence.dependency_key == ast_observation.raw_specifier
          && graph_occurrence.import.is_dynamic
            == (ast_observation.kind
              == OdenParentVfsDependencyKind::DynamicImport)
          && graph_occurrence.full_range
            == (ast_observation.full_start..ast_observation.full_end)
          && oden_parent_graph_import_attributes_match(
            &graph_occurrence.import.attributes,
            ast_observation.import_attributes_present,
            &ast_observation.import_attributes,
          ))
        .then_some(index)
      })
      .collect::<Vec<_>>();
    let [matching_index] = matching.as_slice() else {
      return Err(OdenParentRuntimeDependencyObservationError::GraphMismatch(
        format!(
          "expected one graph occurrence for {:?} at [{}..{}), found {}",
          ast_observation.raw_specifier,
          ast_observation.source_byte_start,
          ast_observation.source_byte_end,
          matching.len()
        ),
      ));
    };
    let graph_occurrence = &mut graph_occurrences[*matching_index];
    graph_occurrence.used = true;
    observations.push(OdenParentObservedRuntimeDependency {
      kind: ast_observation.kind,
      raw_specifier: ast_observation.raw_specifier,
      resolved_specifier: graph_occurrence.resolved_specifier.clone(),
      source_byte_start: ast_observation.source_byte_start as u64,
      source_byte_end: ast_observation.source_byte_end as u64,
      import_attributes: ast_observation.import_attributes,
    });
  }

  if let Some(leftover) = graph_occurrences.iter().find(|value| !value.used) {
    return Err(OdenParentRuntimeDependencyObservationError::GraphLeftover(
      format!(
        "{:?} at [{}..{})",
        leftover.dependency_key,
        leftover.full_range.start + 1,
        leftover.full_range.end.saturating_sub(1)
      ),
    ));
  }
  Ok(observations)
}

fn project_oden_parent_graph_redirect_chain(
  graph: &ModuleGraph,
  start: &ModuleSpecifier,
) -> Result<
  (Vec<OdenParentGraphRedirectHop>, ModuleSpecifier),
  OdenParentOrdinaryEsmGraphModuleCandidateError,
> {
  let mut seen = HashSet::new();
  let mut current = start.clone();
  seen.insert(current.clone());
  let mut redirect_chain = Vec::new();
  while let Some(next) = graph.redirects.get(&current) {
    if !seen.insert(next.clone()) {
      return Err(
        OdenParentOrdinaryEsmGraphModuleCandidateError::InvalidGraph(
          "dependency redirect chain contains a self redirect or cycle",
        ),
      );
    }
    redirect_chain.push(OdenParentGraphRedirectHop {
      requested_specifier: current,
      redirected_specifier: next.clone(),
    });
    current = next.clone();
  }
  if graph.resolve(start) != &current {
    return Err(
      OdenParentOrdinaryEsmGraphModuleCandidateError::InvalidGraph(
        "independent dependency redirect walk differs from graph resolution",
      ),
    );
  }
  Ok((redirect_chain, current))
}

fn oden_parent_is_candidate_jsr_redirect_chain(
  redirect_chain: &[OdenParentGraphRedirectHop],
) -> bool {
  let [hop] = redirect_chain else {
    return false;
  };
  hop.requested_specifier.scheme() == "jsr"
    && hop.requested_specifier.query().is_none()
    && hop.requested_specifier.fragment().is_none()
    && hop.redirected_specifier.scheme() == "https"
    && hop.redirected_specifier.host_str() == Some("jsr.io")
    && hop.redirected_specifier.username().is_empty()
    && hop.redirected_specifier.password().is_none()
    && hop.redirected_specifier.port().is_none()
    && hop.redirected_specifier.query().is_none()
    && hop.redirected_specifier.fragment().is_none()
}

fn oden_parent_graph_final_has_candidate_jsr_request(
  graph: &ModuleGraph,
  graph_final_specifier: &ModuleSpecifier,
) -> bool {
  graph.redirects.keys().any(|request| {
    request.scheme() == "jsr"
      && project_oden_parent_graph_redirect_chain(graph, request)
        .ok()
        .is_some_and(|(redirect_chain, candidate_final)| {
          candidate_final == *graph_final_specifier
            && oden_parent_is_candidate_jsr_redirect_chain(&redirect_chain)
        })
  })
}

fn oden_parent_ordinary_esm_dependency_target_kind(
  target: &deno_graph::Module,
  graph_final_specifier: &ModuleSpecifier,
) -> Result<
  OdenParentOrdinaryEsmDependencyTargetKind,
  OdenParentOrdinaryEsmGraphModuleCandidateError,
> {
  if target.specifier() != graph_final_specifier {
    return Err(
      OdenParentOrdinaryEsmGraphModuleCandidateError::InvalidGraph(
        "dependency target module specifier differs from graph-final specifier",
      ),
    );
  }
  match target {
    deno_graph::Module::Js(target) => {
      if target.is_script {
        return Err(
          OdenParentOrdinaryEsmGraphModuleCandidateError::InvalidGraph(
            "dependency target is a script rather than ESM",
          ),
        );
      }
      match target.media_type {
        MediaType::JavaScript => {
          Ok(OdenParentOrdinaryEsmDependencyTargetKind::JavaScript)
        }
        MediaType::TypeScript => {
          Ok(OdenParentOrdinaryEsmDependencyTargetKind::TypeScript)
        }
        _ => Err(
          OdenParentOrdinaryEsmGraphModuleCandidateError::InvalidGraph(
            "dependency JavaScript-family target has an unadmitted media type",
          ),
        ),
      }
    }
    deno_graph::Module::Json(target)
      if target.media_type == MediaType::Json =>
    {
      Ok(OdenParentOrdinaryEsmDependencyTargetKind::Json)
    }
    deno_graph::Module::Wasm(_) => {
      Ok(OdenParentOrdinaryEsmDependencyTargetKind::Wasm)
    }
    deno_graph::Module::Node(target) => {
      let exact_specifier = format!("node:{}", target.module_name);
      if target.module_name.is_empty()
        || graph_final_specifier.query().is_some()
        || graph_final_specifier.fragment().is_some()
        || graph_final_specifier.as_str() != exact_specifier
      {
        return Err(
          OdenParentOrdinaryEsmGraphModuleCandidateError::InvalidGraph(
            "dependency target is not an exact node builtin leaf",
          ),
        );
      }
      Ok(OdenParentOrdinaryEsmDependencyTargetKind::NodeBuiltin)
    }
    deno_graph::Module::Json(_)
    | deno_graph::Module::Npm(_)
    | deno_graph::Module::External(_) => Err(
      OdenParentOrdinaryEsmGraphModuleCandidateError::InvalidGraph(
        "dependency target graph module kind is not admitted",
      ),
    ),
  }
}

// @ref LLP 0019#frozen-parent-standalone-allowlist-and-byte-graph [implements] --
// Retain only one graph-final ordinary ESM module candidate and its exact edges.
#[allow(dead_code)]
fn observe_oden_parent_ordinary_esm_graph_module_candidate(
  graph: &ModuleGraph,
  module_specifier: &ModuleSpecifier,
) -> Result<
  OdenParentOrdinaryEsmGraphModuleCandidate,
  OdenParentOrdinaryEsmGraphModuleCandidateError,
> {
  if graph.graph_kind() != deno_graph::GraphKind::CodeOnly {
    return Err(
      OdenParentOrdinaryEsmGraphModuleCandidateError::InvalidGraph(
        "module graph is not CodeOnly",
      ),
    );
  }
  if module_specifier.query().is_some()
    || module_specifier.fragment().is_some()
  {
    return Err(
      OdenParentOrdinaryEsmGraphModuleCandidateError::InvalidGraph(
        "module specifier has a query or fragment",
      ),
    );
  }
  if graph.redirects.contains_key(module_specifier)
    || graph.resolve(module_specifier) != module_specifier
  {
    return Err(
      OdenParentOrdinaryEsmGraphModuleCandidateError::InvalidGraph(
        "module specifier is redirected or aliased rather than graph-final",
      ),
    );
  }
  let input_scheme_is_admitted = module_specifier.scheme() == "file"
    || (module_specifier.scheme() == "https"
      && oden_parent_graph_final_has_candidate_jsr_request(
        graph,
        module_specifier,
      ));
  if !input_scheme_is_admitted {
    return Err(
      OdenParentOrdinaryEsmGraphModuleCandidateError::InvalidGraph(
        "module specifier is neither a direct file nor a candidate JSR registry target",
      ),
    );
  }

  let module = graph
    .try_get(module_specifier)
    .map_err(|_| {
      OdenParentOrdinaryEsmGraphModuleCandidateError::InvalidGraph(
        "module graph target failed to load",
      )
    })?
    .ok_or(
      OdenParentOrdinaryEsmGraphModuleCandidateError::InvalidGraph(
        "module graph target is absent",
      ),
    )?;
  let deno_graph::Module::Js(module) = module else {
    return Err(
      OdenParentOrdinaryEsmGraphModuleCandidateError::InvalidGraph(
        "module graph target is not JavaScript-family",
      ),
    );
  };
  if module.specifier != *module_specifier {
    return Err(
      OdenParentOrdinaryEsmGraphModuleCandidateError::InvalidGraph(
        "module row specifier differs from supplied graph-final specifier",
      ),
    );
  }
  if module.is_script {
    return Err(
      OdenParentOrdinaryEsmGraphModuleCandidateError::InvalidGraph(
        "module graph target is a script rather than ESM",
      ),
    );
  }
  let media_type = match module.media_type {
    MediaType::JavaScript => OdenParentOrdinaryEsmMediaType::JavaScript,
    MediaType::TypeScript => OdenParentOrdinaryEsmMediaType::TypeScript,
    _ => {
      return Err(
        OdenParentOrdinaryEsmGraphModuleCandidateError::InvalidGraph(
          "module graph target is not JavaScript or TypeScript",
        ),
      );
    }
  };
  let original_bytes = module.source.try_get_original_bytes().ok_or(
    OdenParentOrdinaryEsmGraphModuleCandidateError::InvalidGraph(
      "module graph source does not retain its original bytes",
    ),
  )?;
  let observed_runtime_dependencies =
    observe_oden_parent_runtime_dependencies(
      &module.specifier,
      module.media_type,
      original_bytes.as_ref(),
      &module.dependencies,
    )?;

  let mut runtime_dependencies =
    Vec::with_capacity(observed_runtime_dependencies.len());
  for observation in observed_runtime_dependencies {
    let (redirect_chain, graph_final_specifier) =
      project_oden_parent_graph_redirect_chain(
        graph,
        &observation.resolved_specifier,
      )?;
    if observation.raw_specifier == ODEN_PARENT_PRIVATE_MODULE_SPECIFIER
      || observation.resolved_specifier.as_str()
        == ODEN_PARENT_PRIVATE_MODULE_SPECIFIER
      || graph_final_specifier.as_str()
        == ODEN_PARENT_PRIVATE_MODULE_SPECIFIER
      || redirect_chain.iter().any(|hop| {
        hop.requested_specifier.as_str()
          == ODEN_PARENT_PRIVATE_MODULE_SPECIFIER
          || hop.redirected_specifier.as_str()
            == ODEN_PARENT_PRIVATE_MODULE_SPECIFIER
      })
    {
      return Err(
        OdenParentOrdinaryEsmGraphModuleCandidateError::InvalidGraph(
          "ordinary module depends on the private Oden internal target",
        ),
      );
    }
    if graph_final_specifier.query().is_some()
      || graph_final_specifier.fragment().is_some()
    {
      return Err(
        OdenParentOrdinaryEsmGraphModuleCandidateError::InvalidGraph(
          "dependency graph-final specifier has a query or fragment",
        ),
      );
    }
    let candidate_jsr_redirect =
      oden_parent_is_candidate_jsr_redirect_chain(&redirect_chain);
    let admitted_direct_scheme = redirect_chain.is_empty()
      && matches!(graph_final_specifier.scheme(), "file" | "node");
    if !admitted_direct_scheme && !candidate_jsr_redirect {
      return Err(
        OdenParentOrdinaryEsmGraphModuleCandidateError::InvalidGraph(
          "dependency is not a direct file/node target or candidate JSR redirect chain",
        ),
      );
    }
    let target = graph
      .try_get(&graph_final_specifier)
      .map_err(|_| {
        OdenParentOrdinaryEsmGraphModuleCandidateError::InvalidGraph(
          "dependency graph-final target failed to load",
        )
      })?
      .ok_or(
        OdenParentOrdinaryEsmGraphModuleCandidateError::InvalidGraph(
          "dependency graph-final target is absent",
        ),
      )?;
    let target_kind = oden_parent_ordinary_esm_dependency_target_kind(
      target,
      &graph_final_specifier,
    )?;
    runtime_dependencies.push(
      OdenParentOrdinaryEsmRuntimeDependencyCandidate {
        observation,
        redirect_chain,
        graph_final_specifier,
        target_kind,
      },
    );
  }

  Ok(OdenParentOrdinaryEsmGraphModuleCandidate {
    graph_final_module_specifier: module_specifier.clone(),
    media_type,
    original_bytes,
    runtime_dependencies,
  })
}

// @ref LLP 0019#frozen-parent-standalone-allowlist-and-byte-graph [implements] --
// Bind only the graph-owned release-entry bytes and exact private edge.
#[allow(dead_code)]
fn observe_oden_parent_release_entrypoint_candidate(
  graph: &ModuleGraph,
  entrypoint: &ModuleSpecifier,
) -> Result<
  OdenParentReleaseEntrypointCandidate,
  OdenParentReleaseEntrypointCandidateError,
> {
  if entrypoint.scheme() != "file"
    || entrypoint.query().is_some()
    || entrypoint.fragment().is_some()
  {
    return Err(OdenParentReleaseEntrypointCandidateError::InvalidGraph(
      "entrypoint is not one query-free and fragment-free file URL",
    ));
  }
  if !graph.roots.contains(entrypoint) {
    return Err(OdenParentReleaseEntrypointCandidateError::InvalidGraph(
      "entrypoint is not an exact graph root",
    ));
  }
  if graph.redirects.contains_key(entrypoint)
    || graph.resolve(entrypoint) != entrypoint
  {
    return Err(OdenParentReleaseEntrypointCandidateError::InvalidGraph(
      "entrypoint is redirected or aliased",
    ));
  }
  let module = graph
    .try_get(entrypoint)
    .map_err(|_| {
      OdenParentReleaseEntrypointCandidateError::InvalidGraph(
        "entrypoint module failed to load",
      )
    })?
    .ok_or(OdenParentReleaseEntrypointCandidateError::InvalidGraph(
      "entrypoint module is absent",
    ))?;
  let deno_graph::Module::Js(module) = module else {
    return Err(OdenParentReleaseEntrypointCandidateError::InvalidGraph(
      "entrypoint is not a JavaScript-family graph module",
    ));
  };
  if module.specifier != *entrypoint {
    return Err(OdenParentReleaseEntrypointCandidateError::InvalidGraph(
      "entrypoint module specifier differs from the exact graph root",
    ));
  }
  if module.media_type != MediaType::TypeScript || module.is_script {
    return Err(OdenParentReleaseEntrypointCandidateError::InvalidGraph(
      "entrypoint is not one exact ESM TypeScript module",
    ));
  }
  let original_bytes = module.source.try_get_original_bytes().ok_or(
    OdenParentReleaseEntrypointCandidateError::InvalidGraph(
      "entrypoint graph source does not retain its original bytes",
    ),
  )?;
  let runtime_dependencies = observe_oden_parent_runtime_dependencies(
    &module.specifier,
    module.media_type,
    original_bytes.as_ref(),
    &module.dependencies,
  )?;
  if original_bytes.len() != 278 {
    return Err(OdenParentReleaseEntrypointCandidateError::InvalidGraph(
      "entrypoint original-byte length is not 278",
    ));
  }
  let [private_dependency, main_dependency] = runtime_dependencies.as_slice()
  else {
    return Err(OdenParentReleaseEntrypointCandidateError::InvalidGraph(
      "entrypoint does not have exactly two runtime dependencies",
    ));
  };
  let private_occurrence_count = runtime_dependencies
    .iter()
    .filter(|dependency| {
      dependency.raw_specifier == ODEN_PARENT_PRIVATE_MODULE_SPECIFIER
        || dependency.resolved_specifier.as_str()
          == ODEN_PARENT_PRIVATE_MODULE_SPECIFIER
    })
    .count();
  if private_occurrence_count != 1 {
    return Err(OdenParentReleaseEntrypointCandidateError::InvalidGraph(
      "private dependency does not occur exactly once",
    ));
  }
  if private_dependency.kind != OdenParentVfsDependencyKind::StaticImport
    || private_dependency.raw_specifier != ODEN_PARENT_PRIVATE_MODULE_SPECIFIER
    || private_dependency.resolved_specifier.as_str()
      != ODEN_PARENT_PRIVATE_MODULE_SPECIFIER
    || private_dependency.source_byte_start != 121
    || private_dependency.source_byte_end != 163
    || !private_dependency.import_attributes.is_empty()
  {
    return Err(OdenParentReleaseEntrypointCandidateError::InvalidGraph(
      "dependency ordinal zero is not the exact private static import",
    ));
  }
  if graph
    .redirects
    .contains_key(&private_dependency.resolved_specifier)
    || graph.resolve(&private_dependency.resolved_specifier)
      != &private_dependency.resolved_specifier
  {
    return Err(OdenParentReleaseEntrypointCandidateError::InvalidGraph(
      "private dependency resolved specifier is not graph-final",
    ));
  }
  let expected_main_specifier = entrypoint.join("./main.ts").map_err(|_| {
    OdenParentReleaseEntrypointCandidateError::InvalidGraph(
      "entrypoint cannot resolve the fixed main dependency",
    )
  })?;
  if main_dependency.kind != OdenParentVfsDependencyKind::StaticImport
    || main_dependency.raw_specifier != "./main.ts"
    || main_dependency.resolved_specifier != expected_main_specifier
    || main_dependency.source_byte_start != 188
    || main_dependency.source_byte_end != 197
    || !main_dependency.import_attributes.is_empty()
  {
    return Err(OdenParentReleaseEntrypointCandidateError::InvalidGraph(
      "dependency ordinal one is not the exact main static import",
    ));
  }
  if graph
    .redirects
    .contains_key(&main_dependency.resolved_specifier)
    || graph.resolve(&main_dependency.resolved_specifier)
      != &main_dependency.resolved_specifier
  {
    return Err(OdenParentReleaseEntrypointCandidateError::InvalidGraph(
      "main dependency resolved specifier is not graph-final",
    ));
  }

  let projected_attributes = private_dependency
    .import_attributes
    .iter()
    .map(|attribute| OdenParentProjectedImportAttribute {
      key: attribute.key.as_str(),
      value: attribute.value.as_str(),
    })
    .collect::<Vec<_>>();
  let import_attributes =
    OdenParentImportAttributes::from_observed_pairs(&projected_attributes)?;
  let static_import_edge = OdenParentStaticImportEdge::from_observation(
    OdenParentStaticImportEdgeObservation {
      entrypoint_source_bytes: original_bytes.as_ref(),
      dependency_ordinal: 0,
      occurrence_count: private_occurrence_count as u64,
      kind: private_dependency.kind,
      raw_specifier: private_dependency.raw_specifier.as_str(),
      resolved_specifier: private_dependency.resolved_specifier.as_str(),
      referrer_key: ODEN_PARENT_ENTRYPOINT_KEY,
      import_attributes: &import_attributes,
      source_byte_start: private_dependency.source_byte_start,
      source_byte_end: private_dependency.source_byte_end,
    },
  )?;

  Ok(OdenParentReleaseEntrypointCandidate {
    entrypoint_specifier: entrypoint.clone(),
    original_bytes,
    runtime_dependencies,
    static_import_edge,
  })
}

#[cfg(test)]
mod oden_parent_runtime_dependency_observer_tests {
  use std::collections::HashMap;

  use deno_graph::BuildOptions;
  use deno_graph::GraphKind;
  use deno_graph::Import;
  use deno_graph::Position;
  use deno_graph::PositionRange;
  use deno_graph::Range;
  use deno_graph::ResolutionResolved;
  use deno_graph::source::MemoryLoader;
  use deno_graph::source::Source;

  use super::*;

  const RELEASE_ENTRY_SOURCE: &str = concat!(
    "// @ref LLP 0016#branded-parent-allowlist-and-compile-input [implements] — Inert private wrapper.\n",
    "import capture from \"oden-internal:filesystem-parent-capture-v2\";\n",
    "import { main } from \"./main.ts\";\n",
    "\n",
    "void capture;\n",
    "\n",
    "if (import.meta.main) {\n",
    "  Deno.exit(await main(Deno.args));\n",
    "}\n",
  );

  #[derive(Clone, Copy)]
  enum ReleaseGraphDependencyRedirect {
    None,
    Private,
    Main,
  }

  fn release_graph(
    entrypoint_text: &str,
    entrypoint_source: &[u8],
  ) -> (ModuleGraph, ModuleSpecifier) {
    release_graph_with_dependency_redirect(
      entrypoint_text,
      entrypoint_source,
      ReleaseGraphDependencyRedirect::None,
    )
  }

  fn release_graph_with_dependency_redirect(
    entrypoint_text: &str,
    entrypoint_source: &[u8],
    redirect: ReleaseGraphDependencyRedirect,
  ) -> (ModuleGraph, ModuleSpecifier) {
    let entrypoint = ModuleSpecifier::parse(entrypoint_text).unwrap();
    let main_specifier = entrypoint.join("./main.ts").unwrap();
    let redirected_main_specifier =
      entrypoint.join("./redirected-main.ts").unwrap();
    let extra_specifier = entrypoint.join("./x").unwrap();
    let private_specifier =
      ModuleSpecifier::parse(ODEN_PARENT_PRIVATE_MODULE_SPECIFIER).unwrap();
    let redirected_private_specifier = ModuleSpecifier::parse(
      "oden-internal:filesystem-parent-capture-v2-redirected",
    )
    .unwrap();
    let module_source =
      |specifier: &ModuleSpecifier, content: &[u8], javascript_header: bool| {
        (
          specifier.to_string(),
          Source::Module {
            specifier: specifier.to_string(),
            maybe_headers: javascript_header.then(|| {
              vec![(
                "content-type".to_string(),
                "application/javascript".to_string(),
              )]
            }),
            content: content.to_vec(),
          },
        )
      };
    let mut sources = vec![
      module_source(&entrypoint, entrypoint_source, false),
      module_source(&extra_specifier, b"export default null;\n", true),
    ];
    if matches!(redirect, ReleaseGraphDependencyRedirect::Main) {
      sources.push((
        main_specifier.to_string(),
        Source::Redirect(redirected_main_specifier.to_string()),
      ));
      sources.push(module_source(
        &redirected_main_specifier,
        b"export async function main() { return 0; }\n",
        false,
      ));
    } else {
      sources.push(module_source(
        &main_specifier,
        b"export async function main() { return 0; }\n",
        false,
      ));
    }
    if matches!(redirect, ReleaseGraphDependencyRedirect::Private) {
      sources.push((
        private_specifier.to_string(),
        Source::Redirect(redirected_private_specifier.to_string()),
      ));
      sources.push(module_source(
        &redirected_private_specifier,
        b"export default null;\n",
        true,
      ));
    } else {
      sources.push(module_source(
        &private_specifier,
        b"export default null;\n",
        true,
      ));
    }
    let loader = MemoryLoader::new(sources, Vec::new());
    let mut graph = ModuleGraph::new(GraphKind::CodeOnly);
    deno_core::futures::executor::block_on(graph.build(
      vec![entrypoint.clone()],
      Vec::new(),
      &loader,
      BuildOptions::default(),
    ));
    (graph, entrypoint)
  }

  type TestModuleSource = (String, Source<String, Vec<u8>>);

  fn test_module_source(
    specifier: &str,
    content: &[u8],
    content_type: Option<&str>,
  ) -> TestModuleSource {
    (
      specifier.to_string(),
      Source::Module {
        specifier: specifier.to_string(),
        maybe_headers: content_type.map(|content_type| {
          vec![("content-type".to_string(), content_type.to_string())]
        }),
        content: content.to_vec(),
      },
    )
  }

  fn ordinary_esm_graph(
    graph_kind: GraphKind,
    module_specifier: &str,
    module_source: &[u8],
    module_content_type: Option<&str>,
    mut dependency_sources: Vec<TestModuleSource>,
    skip_dynamic_deps: bool,
  ) -> (ModuleGraph, ModuleSpecifier) {
    let module_specifier = ModuleSpecifier::parse(module_specifier).unwrap();
    dependency_sources.push(test_module_source(
      module_specifier.as_str(),
      module_source,
      module_content_type,
    ));
    let loader = MemoryLoader::new(dependency_sources, Vec::new());
    let mut graph = ModuleGraph::new(graph_kind);
    deno_core::futures::executor::block_on(graph.build(
      vec![module_specifier.clone()],
      Vec::new(),
      &loader,
      BuildOptions {
        skip_dynamic_deps,
        ..Default::default()
      },
    ));
    (graph, module_specifier)
  }

  fn exact_line(code: &str, byte_length_with_lf: usize) -> String {
    assert!(code.is_ascii());
    assert!(code.len() < byte_length_with_lf);
    format!(
      "{code}{}\n",
      " ".repeat(byte_length_with_lf - code.len() - 1)
    )
  }

  fn utf16le_source(source: &str) -> Vec<u8> {
    let mut bytes = vec![0xff, 0xfe];
    for unit in source.encode_utf16() {
      bytes.extend(unit.to_le_bytes());
    }
    bytes
  }

  #[derive(Clone)]
  struct TestGraphOccurrence<'a> {
    raw_specifier: &'a str,
    resolved_specifier: &'a str,
    full_start: usize,
    is_dynamic: bool,
    attributes: Option<Vec<(&'a str, &'a str)>>,
  }

  fn test_referrer() -> ModuleSpecifier {
    ModuleSpecifier::parse("file:///repo/src/test.ts").unwrap()
  }

  fn position_at(source: &str, byte_offset: usize) -> Position {
    let prefix = &source[..byte_offset];
    let line = prefix.bytes().filter(|byte| *byte == b'\n').count();
    let line_start = prefix.rfind('\n').map(|index| index + 1).unwrap_or(0);
    Position {
      line,
      character: source[line_start..byte_offset].chars().count(),
    }
  }

  fn graph_range(
    source: &str,
    referrer: &ModuleSpecifier,
    start: usize,
    end: usize,
  ) -> Range {
    Range {
      specifier: referrer.clone(),
      range: PositionRange {
        start: position_at(source, start),
        end: position_at(source, end),
      },
      resolution_mode: Some(ResolutionMode::Import),
    }
  }

  fn graph_attributes(attributes: Option<&[(&str, &str)]>) -> ImportAttributes {
    let Some(attributes) = attributes else {
      return ImportAttributes::None;
    };
    let mut graph_attributes = HashMap::new();
    for (key, value) in attributes {
      graph_attributes.insert(
        (*key).to_string(),
        ImportAttribute::Known((*value).to_string()),
      );
    }
    ImportAttributes::Known(graph_attributes)
  }

  fn graph_dependencies(
    source: &str,
    referrer: &ModuleSpecifier,
    occurrences: &[TestGraphOccurrence<'_>],
  ) -> IndexMap<String, Dependency> {
    let mut dependencies = IndexMap::<String, Dependency>::new();
    for occurrence in occurrences {
      let full_end = occurrence.full_start + occurrence.raw_specifier.len() + 2;
      let range =
        graph_range(source, referrer, occurrence.full_start, full_end);
      let dependency = dependencies
        .entry(occurrence.raw_specifier.to_string())
        .or_default();
      let attributes = graph_attributes(occurrence.attributes.as_deref());
      if dependency.imports.is_empty() {
        dependency.maybe_code = Resolution::Ok(Box::new(ResolutionResolved {
          specifier: ModuleSpecifier::parse(occurrence.resolved_specifier)
            .unwrap(),
          range: range.clone(),
        }));
        dependency.is_dynamic = occurrence.is_dynamic;
        dependency.maybe_attribute_type = match &attributes {
          ImportAttributes::Known(attributes) => {
            attributes.get("type").and_then(|value| match value {
              ImportAttribute::Known(value) => Some(value.clone()),
              ImportAttribute::Unknown => None,
            })
          }
          ImportAttributes::None | ImportAttributes::Unknown => None,
        };
      } else {
        dependency.is_dynamic &= occurrence.is_dynamic;
      }
      dependency.imports.push(Import {
        specifier: occurrence.raw_specifier.to_string(),
        kind: ImportKind::Es,
        specifier_range: range,
        is_dynamic: occurrence.is_dynamic,
        is_side_effect: false,
        attributes,
      });
    }
    dependencies
  }

  fn observe(
    source: &str,
    occurrences: &[TestGraphOccurrence<'_>],
  ) -> Result<
    Vec<OdenParentObservedRuntimeDependency>,
    OdenParentRuntimeDependencyObservationError,
  > {
    let referrer = test_referrer();
    let graph = graph_dependencies(source, &referrer, occurrences);
    observe_oden_parent_runtime_dependencies(
      &referrer,
      MediaType::TypeScript,
      source.as_bytes(),
      &graph,
    )
  }

  fn double_quoted_start(source: &str, specifier: &str) -> usize {
    source.find(&format!("\"{specifier}\"")).unwrap()
  }

  #[test]
  fn oden_parent_runtime_dependency_observer_private_edge_and_determinism() {
    let source = RELEASE_ENTRY_SOURCE;
    assert_eq!(source.as_bytes().len(), 278);
    let private = "oden-internal:filesystem-parent-capture-v2";
    let main = "./main.ts";
    let occurrences = [
      TestGraphOccurrence {
        raw_specifier: private,
        resolved_specifier: private,
        full_start: double_quoted_start(source, private),
        is_dynamic: false,
        attributes: None,
      },
      TestGraphOccurrence {
        raw_specifier: main,
        resolved_specifier: "file:///repo/src/main.ts",
        full_start: double_quoted_start(source, main),
        is_dynamic: false,
        attributes: None,
      },
    ];
    let first = observe(source, &occurrences).unwrap();
    let second = observe(source, &occurrences).unwrap();
    assert_eq!(first, second);
    assert_eq!(first.len(), 2);
    assert_eq!(
      first
        .iter()
        .map(|dependency| dependency.raw_specifier.as_str())
        .collect::<Vec<_>>(),
      vec![private, main]
    );
    assert_eq!(first[0].kind, OdenParentVfsDependencyKind::StaticImport);
    assert_eq!(first[0].raw_specifier, private);
    assert_eq!(first[0].resolved_specifier.as_str(), private);
    assert_eq!(first[0].source_byte_start, 121);
    assert_eq!(first[0].source_byte_end, 163);
    assert!(first[0].import_attributes.is_empty());
  }

  #[test]
  fn oden_parent_runtime_dependency_observer_reconciles_pinned_graph_facts() {
    let specifier =
      ModuleSpecifier::parse("file:///repo/src/release.ts").unwrap();
    let parsed = deno_ast::parse_module(deno_ast::ParseParams {
      specifier: specifier.clone(),
      text: RELEASE_ENTRY_SOURCE.to_string().into(),
      media_type: MediaType::TypeScript,
      capture_tokens: false,
      maybe_syntax: None,
      scope_analysis: false,
    })
    .unwrap();
    let module = deno_graph::parse_module_from_ast(
      deno_graph::ParseModuleFromAstOptions {
        graph_kind: deno_graph::GraphKind::CodeOnly,
        specifier: specifier.clone(),
        maybe_headers: None,
        mtime: None,
        parsed_source: &parsed,
        file_system: &deno_graph::source::NullFileSystem,
        jsr_url_provider: &deno_graph::source::DefaultJsrUrlProvider,
        maybe_resolver: None,
      },
    );
    let observed = observe_oden_parent_runtime_dependencies(
      &specifier,
      MediaType::TypeScript,
      RELEASE_ENTRY_SOURCE.as_bytes(),
      &module.dependencies,
    )
    .unwrap();
    assert_eq!(observed.len(), 2);
    assert_eq!(
      observed[0].raw_specifier,
      "oden-internal:filesystem-parent-capture-v2"
    );
    assert_eq!(observed[0].source_byte_start, 121);
    assert_eq!(observed[0].source_byte_end, 163);
  }

  #[test]
  fn oden_parent_ordinary_esm_candidate_retains_ts_js_edges_and_graph_bytes() {
    let source = concat!(
      "import \"./dep.ts\";\n",
      "export { value } from \"./export.js\";\n",
      "const dynamic = import(\"./dynamic.ts\");\n",
      "import { readFile } from \"node:fs\";\n",
    );
    let (graph, module_specifier) = ordinary_esm_graph(
      GraphKind::CodeOnly,
      "file:///repo/src/ordinary.ts",
      source.as_bytes(),
      None,
      vec![
        test_module_source(
          "file:///repo/src/dep.ts",
          b"export const dep = 1;\n",
          None,
        ),
        test_module_source(
          "file:///repo/src/export.js",
          b"export const value = 2;\n",
          Some("application/javascript"),
        ),
        test_module_source(
          "file:///repo/src/dynamic.ts",
          b"export const dynamic = 3;\n",
          None,
        ),
      ],
      false,
    );
    let graph_original_bytes = match graph.get(&module_specifier).unwrap() {
      deno_graph::Module::Js(module) => {
        module.source.try_get_original_bytes().unwrap()
      }
      _ => unreachable!(),
    };

    let first = observe_oden_parent_ordinary_esm_graph_module_candidate(
      &graph,
      &module_specifier,
    )
    .unwrap();
    let second = observe_oden_parent_ordinary_esm_graph_module_candidate(
      &graph,
      &module_specifier,
    )
    .unwrap();
    assert_eq!(first, second);
    assert_eq!(
      first.graph_final_module_specifier,
      ModuleSpecifier::parse("file:///repo/src/ordinary.ts").unwrap()
    );
    assert_eq!(first.media_type, OdenParentOrdinaryEsmMediaType::TypeScript);
    assert!(Arc::ptr_eq(&first.original_bytes, &graph_original_bytes));
    assert_eq!(first.original_bytes.as_ref(), source.as_bytes());
    assert_eq!(first.runtime_dependencies.len(), 4);
    assert_eq!(
      first
        .runtime_dependencies
        .iter()
        .map(|dependency| dependency.observation.kind)
        .collect::<Vec<_>>(),
      vec![
        OdenParentVfsDependencyKind::StaticImport,
        OdenParentVfsDependencyKind::StaticExport,
        OdenParentVfsDependencyKind::DynamicImport,
        OdenParentVfsDependencyKind::StaticImport,
      ]
    );
    let expected = [
      (
        "./dep.ts",
        "file:///repo/src/dep.ts",
        OdenParentOrdinaryEsmDependencyTargetKind::TypeScript,
      ),
      (
        "./export.js",
        "file:///repo/src/export.js",
        OdenParentOrdinaryEsmDependencyTargetKind::JavaScript,
      ),
      (
        "./dynamic.ts",
        "file:///repo/src/dynamic.ts",
        OdenParentOrdinaryEsmDependencyTargetKind::TypeScript,
      ),
      (
        "node:fs",
        "node:fs",
        OdenParentOrdinaryEsmDependencyTargetKind::NodeBuiltin,
      ),
    ];
    for (dependency, (raw, graph_final, target_kind)) in
      first.runtime_dependencies.iter().zip(expected)
    {
      assert_eq!(dependency.observation.raw_specifier, raw);
      assert_eq!(dependency.graph_final_specifier.as_str(), graph_final);
      assert_eq!(dependency.target_kind, target_kind);
      assert!(dependency.redirect_chain.is_empty());
      let full_start = double_quoted_start(source, raw);
      assert_eq!(
        dependency.observation.source_byte_start,
        (full_start + 1) as u64
      );
      assert_eq!(
        dependency.observation.source_byte_end,
        (full_start + 1 + raw.len()) as u64
      );
    }

    let javascript_source = "import \"./dep.js\";\nexport const root = 1;\n";
    let (javascript_graph, javascript_specifier) = ordinary_esm_graph(
      GraphKind::CodeOnly,
      "file:///repo/src/ordinary.js",
      javascript_source.as_bytes(),
      Some("application/javascript"),
      vec![test_module_source(
        "file:///repo/src/dep.js",
        b"export const dep = 1;\n",
        Some("application/javascript"),
      )],
      false,
    );
    let javascript =
      observe_oden_parent_ordinary_esm_graph_module_candidate(
        &javascript_graph,
        &javascript_specifier,
      )
      .unwrap();
    assert_eq!(
      javascript.media_type,
      OdenParentOrdinaryEsmMediaType::JavaScript
    );
  }

  #[tokio::test]
  async fn oden_parent_ordinary_esm_candidate_retains_candidate_jsr_redirect()
  {
    use deno_graph::packages::JsrPackageInfo;
    use deno_graph::packages::JsrPackageInfoVersion;
    use deno_graph::packages::JsrPackageVersionInfo;
    use deno_semver::Version;

    let root = ModuleSpecifier::parse("file:///repo/src/jsr-user.ts").unwrap();
    let source = "import \"jsr:@package/foo@1.0.0\";\n";
    let final_specifier = ModuleSpecifier::parse(
      "https://jsr.io/@package/foo/1.0.0/mod.ts",
    )
    .unwrap();
    let mut loader = MemoryLoader::default();
    loader.add_source_with_text(&root, source);
    loader.add_jsr_package_info(
      "@package/foo",
      &JsrPackageInfo {
        versions: HashMap::from([(
          Version::parse_standard("1.0.0").unwrap(),
          JsrPackageInfoVersion::default(),
        )]),
        latest: None,
      },
    );
    loader.add_jsr_version_info(
      "@package/foo",
      "1.0.0",
      &JsrPackageVersionInfo {
        exports: deno_core::serde_json::json!({ ".": "./mod.ts" }),
        ..Default::default()
      },
    );
    loader.add_source_with_text(
      &final_specifier,
      "export const packageValue = 1;\n",
    );
    let mut graph = ModuleGraph::new(GraphKind::CodeOnly);
    graph
      .build(
        vec![root.clone()],
        Vec::new(),
        &loader,
        BuildOptions::default(),
      )
      .await;

    let candidate = observe_oden_parent_ordinary_esm_graph_module_candidate(
      &graph, &root,
    )
    .unwrap();
    let [dependency] = candidate.runtime_dependencies.as_slice() else {
      panic!("expected exactly one JSR dependency")
    };
    assert_eq!(
      dependency.observation.resolved_specifier.as_str(),
      "jsr:@package/foo@1.0.0"
    );
    assert_eq!(dependency.redirect_chain.len(), 1);
    assert_eq!(
      dependency.redirect_chain[0].requested_specifier,
      dependency.observation.resolved_specifier
    );
    assert_eq!(
      dependency.redirect_chain[0].redirected_specifier,
      final_specifier
    );
    assert_eq!(dependency.graph_final_specifier, final_specifier);
    assert_eq!(
      dependency.target_kind,
      OdenParentOrdinaryEsmDependencyTargetKind::TypeScript
    );

    let registry_module =
      observe_oden_parent_ordinary_esm_graph_module_candidate(
        &graph,
        &final_specifier,
      )
      .unwrap();
    assert_eq!(
      registry_module.graph_final_module_specifier,
      final_specifier
    );
    assert_eq!(
      registry_module.media_type,
      OdenParentOrdinaryEsmMediaType::TypeScript
    );
    assert_eq!(
      registry_module.original_bytes.as_ref(),
      b"export const packageValue = 1;\n"
    );
    assert!(registry_module.runtime_dependencies.is_empty());

    let request_specifier = dependency.observation.resolved_specifier.clone();
    let mut wrong_host = graph.clone();
    wrong_host.redirects.insert(
      request_specifier.clone(),
      ModuleSpecifier::parse("https://example.com/mod.ts").unwrap(),
    );
    assert!(matches!(
      observe_oden_parent_ordinary_esm_graph_module_candidate(
        &wrong_host,
        &root,
      ),
      Err(OdenParentOrdinaryEsmGraphModuleCandidateError::InvalidGraph(
        "dependency is not a direct file/node target or candidate JSR redirect chain"
      ))
    ));

    let mut second_registry_redirect = graph;
    second_registry_redirect.redirects.insert(
      final_specifier,
      ModuleSpecifier::parse("https://jsr.io/@package/foo/1.0.0/other.ts")
        .unwrap(),
    );
    assert!(matches!(
      observe_oden_parent_ordinary_esm_graph_module_candidate(
        &second_registry_redirect,
        &root,
      ),
      Err(OdenParentOrdinaryEsmGraphModuleCandidateError::InvalidGraph(
        "dependency is not a direct file/node target or candidate JSR redirect chain"
      ))
    ));
  }

  #[test]
  fn oden_parent_ordinary_esm_candidate_refuses_graph_modes_and_redirect_loops()
  {
    let source = "import \"./dep.ts\";\nexport const root = 1;\n";
    let dependency_specifier =
      ModuleSpecifier::parse("file:///repo/src/dep.ts").unwrap();
    let (all_graph, all_specifier) = ordinary_esm_graph(
      GraphKind::All,
      "file:///repo/src/all.ts",
      source.as_bytes(),
      None,
      vec![test_module_source(
        "file:///repo/src/dep.ts",
        b"export const dep = 1;\n",
        None,
      )],
      false,
    );
    assert!(matches!(
      observe_oden_parent_ordinary_esm_graph_module_candidate(
        &all_graph,
        &all_specifier,
      ),
      Err(OdenParentOrdinaryEsmGraphModuleCandidateError::InvalidGraph(
        "module graph is not CodeOnly"
      ))
    ));

    let (graph, module_specifier) = ordinary_esm_graph(
      GraphKind::CodeOnly,
      "file:///repo/src/ordinary.ts",
      source.as_bytes(),
      None,
      vec![test_module_source(
        "file:///repo/src/dep.ts",
        b"export const dep = 1;\n",
        None,
      )],
      false,
    );
    let mut self_redirected_input = graph.clone();
    self_redirected_input
      .redirects
      .insert(module_specifier.clone(), module_specifier.clone());
    assert!(matches!(
      observe_oden_parent_ordinary_esm_graph_module_candidate(
        &self_redirected_input,
        &module_specifier,
      ),
      Err(OdenParentOrdinaryEsmGraphModuleCandidateError::InvalidGraph(
        "module specifier is redirected or aliased rather than graph-final"
      ))
    ));

    let mut self_redirected_dependency = graph.clone();
    self_redirected_dependency
      .redirects
      .insert(dependency_specifier.clone(), dependency_specifier.clone());
    assert!(matches!(
      observe_oden_parent_ordinary_esm_graph_module_candidate(
        &self_redirected_dependency,
        &module_specifier,
      ),
      Err(OdenParentOrdinaryEsmGraphModuleCandidateError::InvalidGraph(
        "dependency redirect chain contains a self redirect or cycle"
      ))
    ));

    let alternate =
      ModuleSpecifier::parse("file:///repo/src/alternate.ts").unwrap();
    let mut cyclic_dependency = graph;
    cyclic_dependency
      .redirects
      .insert(dependency_specifier.clone(), alternate.clone());
    cyclic_dependency
      .redirects
      .insert(alternate, dependency_specifier);
    assert!(matches!(
      observe_oden_parent_ordinary_esm_graph_module_candidate(
        &cyclic_dependency,
        &module_specifier,
      ),
      Err(OdenParentOrdinaryEsmGraphModuleCandidateError::InvalidGraph(
        "dependency redirect chain contains a self redirect or cycle"
      ))
    ));
  }

  #[test]
  fn oden_parent_ordinary_esm_candidate_refuses_missing_error_and_url_suffixes()
  {
    let dynamic_source =
      "void import(\"./missing.ts\");\nexport const root = 1;\n";
    let (missing_graph, missing_specifier) = ordinary_esm_graph(
      GraphKind::CodeOnly,
      "file:///repo/src/missing-user.ts",
      dynamic_source.as_bytes(),
      None,
      Vec::new(),
      true,
    );
    assert!(matches!(
      observe_oden_parent_ordinary_esm_graph_module_candidate(
        &missing_graph,
        &missing_specifier,
      ),
      Err(OdenParentOrdinaryEsmGraphModuleCandidateError::InvalidGraph(
        "dependency graph-final target is absent"
      ))
    ));

    let error_source = "import \"./error.ts\";\nexport const root = 1;\n";
    let error_dependency = "file:///repo/src/error.ts";
    let error_entry: TestModuleSource = (
      error_dependency.to_string(),
      Source::Err(Arc::new(deno_error::JsErrorBox::generic(
        "fixture load error",
      ))),
    );
    let (error_graph, error_specifier) = ordinary_esm_graph(
      GraphKind::CodeOnly,
      "file:///repo/src/error-user.ts",
      error_source.as_bytes(),
      None,
      vec![error_entry],
      false,
    );
    assert!(matches!(
      observe_oden_parent_ordinary_esm_graph_module_candidate(
        &error_graph,
        &error_specifier,
      ),
      Err(OdenParentOrdinaryEsmGraphModuleCandidateError::InvalidGraph(
        "dependency graph-final target failed to load"
      ))
    ));

    let mut query_input = error_specifier.clone();
    query_input.set_query(Some("candidate=1"));
    assert!(matches!(
      observe_oden_parent_ordinary_esm_graph_module_candidate(
        &error_graph,
        &query_input,
      ),
      Err(OdenParentOrdinaryEsmGraphModuleCandidateError::InvalidGraph(
        "module specifier has a query or fragment"
      ))
    ));
    let mut fragment_input = error_specifier;
    fragment_input.set_fragment(Some("candidate"));
    assert!(matches!(
      observe_oden_parent_ordinary_esm_graph_module_candidate(
        &error_graph,
        &fragment_input,
      ),
      Err(OdenParentOrdinaryEsmGraphModuleCandidateError::InvalidGraph(
        "module specifier has a query or fragment"
      ))
    ));

    let query_source =
      "import \"./dep.ts?candidate=1\";\nexport const root = 1;\n";
    let (query_graph, query_specifier) = ordinary_esm_graph(
      GraphKind::CodeOnly,
      "file:///repo/src/query-user.ts",
      query_source.as_bytes(),
      None,
      vec![test_module_source(
        "file:///repo/src/dep.ts?candidate=1",
        b"export const dep = 1;\n",
        None,
      )],
      false,
    );
    assert!(matches!(
      observe_oden_parent_ordinary_esm_graph_module_candidate(
        &query_graph,
        &query_specifier,
      ),
      Err(OdenParentOrdinaryEsmGraphModuleCandidateError::InvalidGraph(
        "dependency graph-final specifier has a query or fragment"
      ))
    ));
  }

  #[test]
  fn oden_parent_ordinary_esm_candidate_refuses_scripts_media_and_missing_original()
  {
    let (script_graph, script_specifier) = ordinary_esm_graph(
      GraphKind::CodeOnly,
      "file:///repo/src/script.js",
      b"globalThis.value = 1;\n",
      Some("application/javascript"),
      Vec::new(),
      false,
    );
    assert!(matches!(
      observe_oden_parent_ordinary_esm_graph_module_candidate(
        &script_graph,
        &script_specifier,
      ),
      Err(OdenParentOrdinaryEsmGraphModuleCandidateError::InvalidGraph(
        "module graph target is a script rather than ESM"
      ))
    ));

    let (jsx_graph, jsx_specifier) = ordinary_esm_graph(
      GraphKind::CodeOnly,
      "file:///repo/src/module.jsx",
      b"export default <div />;\n",
      Some("text/jsx"),
      Vec::new(),
      false,
    );
    assert!(matches!(
      observe_oden_parent_ordinary_esm_graph_module_candidate(
        &jsx_graph,
        &jsx_specifier,
      ),
      Err(OdenParentOrdinaryEsmGraphModuleCandidateError::InvalidGraph(
        "module graph target is not JavaScript or TypeScript"
      ))
    ));

    let utf16_source = utf16le_source("export const value = 1;\n");
    let (decoded_graph, decoded_specifier) = ordinary_esm_graph(
      GraphKind::CodeOnly,
      "file:///repo/src/decoded.ts",
      &utf16_source,
      None,
      Vec::new(),
      false,
    );
    assert!(matches!(
      observe_oden_parent_ordinary_esm_graph_module_candidate(
        &decoded_graph,
        &decoded_specifier,
      ),
      Err(OdenParentOrdinaryEsmGraphModuleCandidateError::InvalidGraph(
        "module graph source does not retain its original bytes"
      ))
    ));

    let dependency_script_source =
      "import \"./script-dep.js\";\nexport const root = 1;\n";
    let (dependency_script_graph, dependency_script_specifier) =
      ordinary_esm_graph(
        GraphKind::CodeOnly,
        "file:///repo/src/dependency-script-user.ts",
        dependency_script_source.as_bytes(),
        None,
        vec![test_module_source(
          "file:///repo/src/script-dep.js",
          b"globalThis.value = 1;\n",
          Some("application/javascript"),
        )],
        false,
      );
    assert!(matches!(
      observe_oden_parent_ordinary_esm_graph_module_candidate(
        &dependency_script_graph,
        &dependency_script_specifier,
      ),
      Err(OdenParentOrdinaryEsmGraphModuleCandidateError::InvalidGraph(
        "dependency target is a script rather than ESM"
      ))
    ));
  }

  #[test]
  fn oden_parent_ordinary_esm_candidate_refuses_private_and_preserves_entrypoint_adapter()
  {
    let (graph, entrypoint) = release_graph(
      "file:///repo/src/release.ts",
      RELEASE_ENTRY_SOURCE.as_bytes(),
    );
    assert!(matches!(
      observe_oden_parent_ordinary_esm_graph_module_candidate(
        &graph,
        &entrypoint,
      ),
      Err(OdenParentOrdinaryEsmGraphModuleCandidateError::InvalidGraph(
        "ordinary module depends on the private Oden internal target"
      ))
    ));
    assert!(
      observe_oden_parent_release_entrypoint_candidate(&graph, &entrypoint)
        .is_ok()
    );
  }

  #[test]
  fn oden_parent_ordinary_esm_candidate_refuses_unjustified_schemes_and_external_targets()
  {
    for module_specifier in [
      "https://example.com/direct.ts",
      "data:text/javascript,export%20default%201",
      "blob:https://example.com/00000000-0000-0000-0000-000000000000",
      "npm:package@1.0.0",
    ] {
      let graph = ModuleGraph::new(GraphKind::CodeOnly);
      let module_specifier = ModuleSpecifier::parse(module_specifier).unwrap();
      assert!(matches!(
        observe_oden_parent_ordinary_esm_graph_module_candidate(
          &graph,
          &module_specifier,
        ),
        Err(OdenParentOrdinaryEsmGraphModuleCandidateError::InvalidGraph(
          "module specifier is neither a direct file nor a candidate JSR registry target"
        ))
      ));
    }

    let source =
      "import \"https://example.com/external.ts\";\nexport const root = 1;\n";
    let external_source: TestModuleSource = (
      "https://example.com/external.ts".to_string(),
      Source::External("https://example.com/external.ts".to_string()),
    );
    let (graph, module_specifier) = ordinary_esm_graph(
      GraphKind::CodeOnly,
      "file:///repo/src/external-user.ts",
      source.as_bytes(),
      None,
      vec![external_source],
      false,
    );
    assert!(matches!(
      observe_oden_parent_ordinary_esm_graph_module_candidate(
        &graph,
        &module_specifier,
      ),
      Err(OdenParentOrdinaryEsmGraphModuleCandidateError::InvalidGraph(
        "dependency is not a direct file/node target or candidate JSR redirect chain"
      ))
    ));
  }

  #[test]
  fn oden_parent_release_entrypoint_candidate_binds_graph_bytes_and_edge() {
    let (graph, entrypoint) = release_graph(
      "file:///repo/src/release.ts",
      RELEASE_ENTRY_SOURCE.as_bytes(),
    );
    assert!(graph.valid().is_ok());
    let graph_original_bytes = match graph.get(&entrypoint).unwrap() {
      deno_graph::Module::Js(module) => {
        module.source.try_get_original_bytes().unwrap()
      }
      _ => unreachable!(),
    };

    let first =
      observe_oden_parent_release_entrypoint_candidate(&graph, &entrypoint)
        .unwrap();
    let second =
      observe_oden_parent_release_entrypoint_candidate(&graph, &entrypoint)
        .unwrap();
    assert_eq!(first, second);
    assert_eq!(first.entrypoint_specifier, entrypoint);
    assert!(Arc::ptr_eq(&first.original_bytes, &graph_original_bytes));
    assert_eq!(
      first.original_bytes.as_ref(),
      RELEASE_ENTRY_SOURCE.as_bytes()
    );
    assert_eq!(first.runtime_dependencies.len(), 2);
    assert_eq!(
      first.runtime_dependencies[0].raw_specifier,
      ODEN_PARENT_PRIVATE_MODULE_SPECIFIER
    );
    assert_eq!(first.runtime_dependencies[0].source_byte_start, 121);
    assert_eq!(first.runtime_dependencies[0].source_byte_end, 163);
    assert_eq!(
      first.runtime_dependencies[1].resolved_specifier,
      entrypoint.join("./main.ts").unwrap()
    );
    assert_eq!(first.runtime_dependencies[1].source_byte_start, 188);
    assert_eq!(first.runtime_dependencies[1].source_byte_end, 197);
    assert_eq!(first.static_import_edge.canonical_jcs().unwrap().len(), 514);
    assert_eq!(
      first.static_import_edge.digest().unwrap().as_str(),
      "sha256-QjCXbnZVWa11HTOJYfKV-tIL5iuvi2tuqLDEpi8MTG0"
    );
  }

  #[test]
  fn oden_parent_release_entrypoint_candidate_refuses_graph_identity_and_media()
  {
    let (graph, entrypoint) = release_graph(
      "file:///repo/src/release.ts",
      RELEASE_ENTRY_SOURCE.as_bytes(),
    );

    let mut missing_root = graph.clone();
    missing_root.roots.clear();
    assert!(matches!(
      observe_oden_parent_release_entrypoint_candidate(
        &missing_root,
        &entrypoint,
      ),
      Err(OdenParentReleaseEntrypointCandidateError::InvalidGraph(
        "entrypoint is not an exact graph root"
      ))
    ));

    let mut self_redirected = graph.clone();
    self_redirected
      .redirects
      .insert(entrypoint.clone(), entrypoint.clone());
    assert!(matches!(
      observe_oden_parent_release_entrypoint_candidate(
        &self_redirected,
        &entrypoint,
      ),
      Err(OdenParentReleaseEntrypointCandidateError::InvalidGraph(
        "entrypoint is redirected or aliased"
      ))
    ));

    let mut redirected = graph;
    redirected
      .redirects
      .insert(entrypoint.clone(), entrypoint.join("./main.ts").unwrap());
    assert!(matches!(
      observe_oden_parent_release_entrypoint_candidate(
        &redirected,
        &entrypoint,
      ),
      Err(OdenParentReleaseEntrypointCandidateError::InvalidGraph(
        "entrypoint is redirected or aliased"
      ))
    ));

    let (javascript_graph, javascript_entrypoint) = release_graph(
      "file:///repo/src/release.js",
      RELEASE_ENTRY_SOURCE.as_bytes(),
    );
    assert!(matches!(
      observe_oden_parent_release_entrypoint_candidate(
        &javascript_graph,
        &javascript_entrypoint,
      ),
      Err(OdenParentReleaseEntrypointCandidateError::InvalidGraph(
        "entrypoint is not one exact ESM TypeScript module"
      ))
    ));

    let (direct_graph, direct_entrypoint) = release_graph(
      "file:///repo/src/release.ts",
      RELEASE_ENTRY_SOURCE.as_bytes(),
    );
    let private_specifier =
      ModuleSpecifier::parse(ODEN_PARENT_PRIVATE_MODULE_SPECIFIER).unwrap();
    let mut self_redirected_private = direct_graph.clone();
    self_redirected_private
      .redirects
      .insert(private_specifier.clone(), private_specifier);
    assert!(matches!(
      observe_oden_parent_release_entrypoint_candidate(
        &self_redirected_private,
        &direct_entrypoint,
      ),
      Err(OdenParentReleaseEntrypointCandidateError::InvalidGraph(
        "private dependency resolved specifier is not graph-final"
      ))
    ));

    let main_specifier = direct_entrypoint.join("./main.ts").unwrap();
    let mut self_redirected_main = direct_graph;
    self_redirected_main
      .redirects
      .insert(main_specifier.clone(), main_specifier);
    assert!(matches!(
      observe_oden_parent_release_entrypoint_candidate(
        &self_redirected_main,
        &direct_entrypoint,
      ),
      Err(OdenParentReleaseEntrypointCandidateError::InvalidGraph(
        "main dependency resolved specifier is not graph-final"
      ))
    ));
  }

  #[test]
  fn oden_parent_release_entrypoint_candidate_refuses_dependency_redirects() {
    let (private_graph, private_entrypoint) =
      release_graph_with_dependency_redirect(
        "file:///repo/src/release.ts",
        RELEASE_ENTRY_SOURCE.as_bytes(),
        ReleaseGraphDependencyRedirect::Private,
      );
    assert!(matches!(
      observe_oden_parent_release_entrypoint_candidate(
        &private_graph,
        &private_entrypoint,
      ),
      Err(OdenParentReleaseEntrypointCandidateError::InvalidGraph(
        "private dependency resolved specifier is not graph-final"
      ))
    ));

    let (main_graph, main_entrypoint) = release_graph_with_dependency_redirect(
      "file:///repo/src/release.ts",
      RELEASE_ENTRY_SOURCE.as_bytes(),
      ReleaseGraphDependencyRedirect::Main,
    );
    assert!(matches!(
      observe_oden_parent_release_entrypoint_candidate(
        &main_graph,
        &main_entrypoint,
      ),
      Err(OdenParentReleaseEntrypointCandidateError::InvalidGraph(
        "main dependency resolved specifier is not graph-final"
      ))
    ));
  }

  #[test]
  fn oden_parent_release_entrypoint_candidate_refuses_ineligible_original_bytes()
   {
    let bom_source =
      [b"\xef\xbb\xbf".as_slice(), RELEASE_ENTRY_SOURCE.as_bytes()].concat();
    let (bom_graph, bom_entrypoint) =
      release_graph("file:///repo/src/release.ts", &bom_source);
    assert!(matches!(
      observe_oden_parent_release_entrypoint_candidate(
        &bom_graph,
        &bom_entrypoint,
      ),
      Err(
        OdenParentReleaseEntrypointCandidateError::RuntimeDependency(
          OdenParentRuntimeDependencyObservationError::InvalidOriginalBytes(_)
        )
      )
    ));

    let utf16_source = utf16le_source(RELEASE_ENTRY_SOURCE);
    let (utf16_graph, utf16_entrypoint) =
      release_graph("file:///repo/src/release.ts", &utf16_source);
    assert!(matches!(
      observe_oden_parent_release_entrypoint_candidate(
        &utf16_graph,
        &utf16_entrypoint,
      ),
      Err(OdenParentReleaseEntrypointCandidateError::InvalidGraph(
        "entrypoint graph source does not retain its original bytes"
      ))
    ));
  }

  #[test]
  fn oden_parent_release_entrypoint_candidate_refuses_dependency_shape_changes()
  {
    let private_line = concat!(
      "import capture from \"",
      "oden-internal:filesystem-parent-capture-v2",
      "\";\n",
    );
    let main_line = "import { main } from \"./main.ts\";\n";

    let missing_private = RELEASE_ENTRY_SOURCE.replace(
      private_line,
      &exact_line("// private import removed", private_line.len()),
    );
    assert_eq!(missing_private.len(), 278);
    let (missing_graph, missing_entrypoint) =
      release_graph("file:///repo/src/release.ts", missing_private.as_bytes());
    assert!(matches!(
      observe_oden_parent_release_entrypoint_candidate(
        &missing_graph,
        &missing_entrypoint,
      ),
      Err(OdenParentReleaseEntrypointCandidateError::InvalidGraph(
        "entrypoint does not have exactly two runtime dependencies"
      ))
    ));

    let extra_dependency = RELEASE_ENTRY_SOURCE.replace(
      "void capture;\n",
      &exact_line("import \"./x\";", "void capture;\n".len()),
    );
    assert_eq!(extra_dependency.len(), 278);
    let (extra_graph, extra_entrypoint) =
      release_graph("file:///repo/src/release.ts", extra_dependency.as_bytes());
    assert!(matches!(
      observe_oden_parent_release_entrypoint_candidate(
        &extra_graph,
        &extra_entrypoint,
      ),
      Err(OdenParentReleaseEntrypointCandidateError::InvalidGraph(
        "entrypoint does not have exactly two runtime dependencies"
      ))
    ));

    let reordered = RELEASE_ENTRY_SOURCE.replacen(
      &format!("{private_line}{main_line}"),
      &format!("{main_line}{private_line}"),
      1,
    );
    assert_eq!(reordered.len(), 278);
    let (reordered_graph, reordered_entrypoint) =
      release_graph("file:///repo/src/release.ts", reordered.as_bytes());
    assert!(matches!(
      observe_oden_parent_release_entrypoint_candidate(
        &reordered_graph,
        &reordered_entrypoint,
      ),
      Err(OdenParentReleaseEntrypointCandidateError::InvalidGraph(
        "dependency ordinal zero is not the exact private static import"
      ))
    ));

    let computed = RELEASE_ENTRY_SOURCE.replace(
      private_line,
      &exact_line(
        "const capture = await import(globalThis.__oden_specifier);",
        private_line.len(),
      ),
    );
    assert_eq!(computed.len(), 278);
    let (computed_graph, computed_entrypoint) =
      release_graph("file:///repo/src/release.ts", computed.as_bytes());
    assert!(matches!(
      observe_oden_parent_release_entrypoint_candidate(
        &computed_graph,
        &computed_entrypoint,
      ),
      Err(
        OdenParentReleaseEntrypointCandidateError::RuntimeDependency(
          OdenParentRuntimeDependencyObservationError::UnsupportedAst(_)
        )
      )
    ));
  }

  #[test]
  fn oden_parent_runtime_dependency_observer_static_export() {
    let source =
      "export { value } from \"./dep.ts\" with { type: \"json\" };\n";
    let raw_specifier = "./dep.ts";
    let observed = observe(
      source,
      &[TestGraphOccurrence {
        raw_specifier,
        resolved_specifier: "file:///repo/src/dep.ts",
        full_start: double_quoted_start(source, raw_specifier),
        is_dynamic: false,
        attributes: Some(vec![("type", "json")]),
      }],
    )
    .unwrap();
    assert_eq!(observed.len(), 1);
    assert_eq!(observed[0].kind, OdenParentVfsDependencyKind::StaticExport);
    assert_eq!(
      observed[0].import_attributes,
      vec![OdenParentObservedImportAttribute {
        key: "type".to_string(),
        value: "json".to_string(),
      }]
    );
  }

  #[test]
  fn oden_parent_runtime_dependency_observer_literal_dynamic_import() {
    let source = concat!(
      "const value = await import(\"./dep.ts\", ",
      "{ with: { type: \"json\" } });\n",
    );
    let raw_specifier = "./dep.ts";
    let observed = observe(
      source,
      &[TestGraphOccurrence {
        raw_specifier,
        resolved_specifier: "file:///repo/src/dep.ts",
        full_start: double_quoted_start(source, raw_specifier),
        is_dynamic: true,
        attributes: Some(vec![("type", "json")]),
      }],
    )
    .unwrap();
    assert_eq!(observed.len(), 1);
    assert_eq!(observed[0].kind, OdenParentVfsDependencyKind::DynamicImport);
  }

  #[test]
  fn oden_parent_runtime_dependency_observer_preserves_duplicate_attributes() {
    let source = concat!(
      "const value = import(\"./data.json\", ",
      "{ with: { type: \"json\", type: \"text\" } });\n",
    );
    let raw_specifier = "./data.json";
    let observed = observe(
      source,
      &[TestGraphOccurrence {
        raw_specifier,
        resolved_specifier: "file:///repo/src/data.json",
        full_start: double_quoted_start(source, raw_specifier),
        is_dynamic: true,
        attributes: Some(vec![("type", "json"), ("type", "text")]),
      }],
    )
    .unwrap();
    assert_eq!(
      observed[0].import_attributes,
      vec![
        OdenParentObservedImportAttribute {
          key: "type".to_string(),
          value: "json".to_string(),
        },
        OdenParentObservedImportAttribute {
          key: "type".to_string(),
          value: "text".to_string(),
        },
      ]
    );
  }

  #[test]
  fn oden_parent_runtime_dependency_observer_refuses_computed_and_escaped() {
    assert!(matches!(
      observe("await import(specifier);\n", &[]),
      Err(OdenParentRuntimeDependencyObservationError::UnsupportedAst(
        _
      ))
    ));
    assert!(matches!(
      observe("await import(`./dep.ts`);\n", &[]),
      Err(OdenParentRuntimeDependencyObservationError::UnsupportedAst(
        _
      ))
    ));
    assert!(matches!(
      observe("import \"./de\\u0070.ts\";\n", &[]),
      Err(OdenParentRuntimeDependencyObservationError::InvalidLiteral(
        _
      ))
    ));
  }

  #[test]
  fn oden_parent_runtime_dependency_observer_refuses_require_types_and_bad_options()
   {
    assert!(matches!(
      observe("require(\"./dep.ts\");\n", &[]),
      Err(OdenParentRuntimeDependencyObservationError::UnsupportedAst(
        _
      ))
    ));
    assert!(matches!(
      observe("import type { Value } from \"./dep.ts\";\n", &[]),
      Err(OdenParentRuntimeDependencyObservationError::UnsupportedAst(
        _
      ))
    ));
    assert!(matches!(
      observe("import value = require(\"./dep.ts\");\n", &[]),
      Err(OdenParentRuntimeDependencyObservationError::UnsupportedAst(
        _
      ))
    ));
    assert!(matches!(
      observe(
        "await import(\"./dep.ts\", { assert: { type: \"json\" } });\n",
        &[],
      ),
      Err(
        OdenParentRuntimeDependencyObservationError::InvalidImportAttributes(_)
      )
    ));
  }

  #[test]
  fn oden_parent_runtime_dependency_observer_preserves_multibyte_and_cr_offsets()
   {
    let source = "const β = 1;\r\nimport \"./dep.ts\";\r\n";
    let raw_specifier = "./dep.ts";
    let full_start = double_quoted_start(source, raw_specifier);
    let observed = observe(
      source,
      &[TestGraphOccurrence {
        raw_specifier,
        resolved_specifier: "file:///repo/src/dep.ts",
        full_start,
        is_dynamic: false,
        attributes: None,
      }],
    )
    .unwrap();
    assert_eq!(observed[0].source_byte_start, (full_start + 1) as u64);
    assert_eq!(
      observed[0].source_byte_end,
      (full_start + 1 + raw_specifier.len()) as u64
    );
  }

  #[test]
  fn oden_parent_runtime_dependency_observer_reconciles_grouped_attribute_resolution()
   {
    let raw_specifier = "./dep.ts";
    let source = concat!(
      "import \"./dep.ts\" with { type: \"json\" };\n",
      "import \"./dep.ts\" with { type: \"json\" };\n",
    );
    let starts = source
      .match_indices("\"./dep.ts\"")
      .map(|(index, _)| index)
      .collect::<Vec<_>>();
    let observed = observe(
      source,
      &[
        TestGraphOccurrence {
          raw_specifier,
          resolved_specifier: "file:///repo/src/dep.ts",
          full_start: starts[0],
          is_dynamic: false,
          attributes: Some(vec![("type", "json")]),
        },
        TestGraphOccurrence {
          raw_specifier,
          resolved_specifier: "file:///repo/src/dep.ts",
          full_start: starts[1],
          is_dynamic: false,
          attributes: Some(vec![("type", "json")]),
        },
      ],
    )
    .unwrap();
    assert_eq!(observed.len(), 2);
    assert!(observed[0].source_byte_start < observed[1].source_byte_start);

    let source = concat!(
      "import \"./dep.ts\" with { type: \"json\" };\n",
      "import \"./dep.ts\" with { type: \"text\" };\n",
    );
    let starts = source
      .match_indices("\"./dep.ts\"")
      .map(|(index, _)| index)
      .collect::<Vec<_>>();
    assert!(matches!(
      observe(
        source,
        &[
          TestGraphOccurrence {
            raw_specifier,
            resolved_specifier: "file:///repo/src/dep.ts",
            full_start: starts[0],
            is_dynamic: false,
            attributes: Some(vec![("type", "json")]),
          },
          TestGraphOccurrence {
            raw_specifier,
            resolved_specifier: "file:///repo/src/dep.ts",
            full_start: starts[1],
            is_dynamic: false,
            attributes: Some(vec![("type", "text")]),
          },
        ],
      ),
      Err(OdenParentRuntimeDependencyObservationError::GraphMismatch(
        _
      ))
    ));

    let source = "import \"./dep.ts\" with { type: \"json\" };\n";
    let referrer = test_referrer();
    let mut graph = graph_dependencies(
      source,
      &referrer,
      &[TestGraphOccurrence {
        raw_specifier,
        resolved_specifier: "file:///repo/src/dep.ts",
        full_start: double_quoted_start(source, raw_specifier),
        is_dynamic: false,
        attributes: Some(vec![("type", "json")]),
      }],
    );
    graph.get_mut(raw_specifier).unwrap().maybe_attribute_type =
      Some("text".to_string());
    assert!(matches!(
      observe_oden_parent_runtime_dependencies(
        &referrer,
        MediaType::TypeScript,
        source.as_bytes(),
        &graph,
      ),
      Err(OdenParentRuntimeDependencyObservationError::GraphMismatch(
        _
      ))
    ));
  }

  #[test]
  fn oden_parent_runtime_dependency_observer_refuses_graph_mismatch_and_leftover()
   {
    let source = "import \"./dep.ts\";\n";
    let raw_specifier = "./dep.ts";
    let mismatch = observe(
      source,
      &[TestGraphOccurrence {
        raw_specifier,
        resolved_specifier: "file:///repo/src/dep.ts",
        full_start: double_quoted_start(source, raw_specifier),
        is_dynamic: true,
        attributes: None,
      }],
    );
    assert!(matches!(
      mismatch,
      Err(OdenParentRuntimeDependencyObservationError::GraphMismatch(
        _
      ))
    ));

    let source = "const value = \"./dep.ts\";\n";
    let leftover = observe(
      source,
      &[TestGraphOccurrence {
        raw_specifier,
        resolved_specifier: "file:///repo/src/dep.ts",
        full_start: double_quoted_start(source, raw_specifier),
        is_dynamic: false,
        attributes: None,
      }],
    );
    assert!(matches!(
      leftover,
      Err(OdenParentRuntimeDependencyObservationError::GraphLeftover(
        _
      ))
    ));

    let source = "import \"./dep.ts\";\n";
    let mut wrong_mode_graph = graph_dependencies(
      source,
      &test_referrer(),
      &[TestGraphOccurrence {
        raw_specifier,
        resolved_specifier: "file:///repo/src/dep.ts",
        full_start: double_quoted_start(source, raw_specifier),
        is_dynamic: false,
        attributes: None,
      }],
    );
    wrong_mode_graph.get_mut(raw_specifier).unwrap().imports[0]
      .specifier_range
      .resolution_mode = None;
    assert!(
      observe_oden_parent_runtime_dependencies(
        &test_referrer(),
        MediaType::TypeScript,
        source.as_bytes(),
        &wrong_mode_graph,
      )
      .is_err()
    );
  }
}

pub struct DenoCompileBinaryWriter<'a> {
  cjs_module_export_analyzer: &'a CliCjsModuleExportAnalyzer,
  cjs_tracker: &'a CliCjsTracker,
  cli_options: &'a CliOptions,
  deno_dir: &'a DenoDir,
  emitter: &'a CliEmitter,
  file_fetcher: &'a CliFileFetcher,
  http_client_provider: &'a HttpClientProvider,
  npm_resolver: &'a CliNpmResolver,
  workspace_resolver: &'a WorkspaceResolver<CliSys>,
  npm_system_info: NpmSystemInfo,
  is_desktop: bool,
}

impl<'a> DenoCompileBinaryWriter<'a> {
  #[allow(clippy::too_many_arguments, reason = "construction")]
  pub fn new(
    cjs_module_export_analyzer: &'a CliCjsModuleExportAnalyzer,
    cjs_tracker: &'a CliCjsTracker,
    cli_options: &'a CliOptions,
    deno_dir: &'a DenoDir,
    emitter: &'a CliEmitter,
    file_fetcher: &'a CliFileFetcher,
    http_client_provider: &'a HttpClientProvider,
    npm_resolver: &'a CliNpmResolver,
    workspace_resolver: &'a WorkspaceResolver<CliSys>,
    npm_system_info: NpmSystemInfo,
    is_desktop: bool,
  ) -> Self {
    Self {
      cjs_module_export_analyzer,
      cjs_tracker,
      cli_options,
      deno_dir,
      emitter,
      file_fetcher,
      http_client_provider,
      npm_resolver,
      workspace_resolver,
      npm_system_info,
      is_desktop,
    }
  }

  pub async fn write_bin(
    &self,
    options: WriteBinOptions<'_>,
  ) -> Result<(), AnyError> {
    // Select base binary based on target
    let mut original_binary =
      self.get_base_binary(options.compile_flags).await?;

    if options.compile_flags.no_terminal {
      let target = options.compile_flags.resolve_target();
      if !target.contains("windows") {
        bail!(
          "The `--no-terminal` flag is only available when targeting Windows (current: {})",
          target,
        )
      }
      set_windows_binary_to_gui(&mut original_binary)
        .context("Setting windows binary to GUI.")?;
    }
    if options.compile_flags.icon.is_some() {
      let target = options.compile_flags.resolve_target();
      // Desktop builds handle icons during app bundle packaging.
      if !target.contains("windows") && !self.is_desktop {
        bail!(
          "The `--icon` flag is only available when targeting Windows (current: {})",
          target,
        );
      }
    }
    // Validate the resolved app name (explicit `--app-name` or the default
    // derived from the output file name) up front, so an invalid name fails
    // before we do any work to write the binary. The returned name is discarded
    // here; the value actually baked into the metadata is resolved again at the
    // write site below.
    resolve_app_name(options.compile_flags, options.display_output_filename)?;
    self.write_standalone_binary(options, original_binary).await
  }

  async fn get_base_binary(
    &self,
    compile_flags: &CompileFlags,
  ) -> Result<Vec<u8>, AnyError> {
    if self.is_desktop {
      return self.get_desktop_base_binary(compile_flags).await;
    }

    // Used for testing.
    //
    // Phase 2 of the 'min sized' deno compile RFC talks
    // about adding this as a flag.
    if let Some(path) = get_dev_binary_path() {
      log::debug!("Resolved denort: {}", path.to_string_lossy());
      return std::fs::read(&path).with_context(|| {
        format!("Could not find denort at '{}'", path.to_string_lossy())
      });
    }

    let target = compile_flags.resolve_target();
    let binary_name = format!("denort-{target}.zip");

    let binary_path_suffix = match DENO_VERSION_INFO.release_channel {
      ReleaseChannel::Canary => {
        format!("canary/{}/{}", DENO_VERSION_INFO.git_hash, binary_name)
      }
      _ => {
        format!("release/v{}/{}", DENO_VERSION_INFO.deno, binary_name)
      }
    };

    let download_directory = self.deno_dir.dl_folder_path();
    let binary_path = download_directory.join(&binary_path_suffix);
    log::debug!("Resolved denort: {}", binary_path.display());

    let read_file = |path: &Path| -> Result<Vec<u8>, AnyError> {
      std::fs::read(path).with_context(|| format!("Reading {}", path.display()))
    };
    let archive_data = if binary_path.exists() {
      read_file(&binary_path)?
    } else {
      self
        .download_base_binary(&binary_path, &binary_path_suffix)
        .await
        .context("Setting up base binary.")?
    };
    let temp_dir = tempfile::TempDir::new()?;
    let base_binary_path = archive::unpack_into_dir(archive::UnpackArgs {
      exe_name: if target.contains("windows") {
        "denort.exe"
      } else {
        "denort"
      },
      archive_name: &binary_name,
      archive_data: &archive_data,
      dest_path: temp_dir.path(),
    })?;
    let base_binary = read_file(&base_binary_path)?;
    drop(temp_dir); // delete the temp dir
    Ok(base_binary)
  }

  async fn get_desktop_base_binary(
    &self,
    compile_flags: &CompileFlags,
  ) -> Result<Vec<u8>, AnyError> {
    // For development: check DENORT_DESKTOP_BIN env var or look
    // for libdenort next to the deno executable.
    if let Some(path) = get_dev_desktop_binary_path() {
      log::debug!("Resolved libdenort: {}", path.to_string_lossy());
      return std::fs::read(&path).with_context(|| {
        format!("Could not find libdenort at '{}'", path.to_string_lossy())
      });
    }

    let target = compile_flags.resolve_target();
    let lib_ext = if target.contains("darwin") {
      "dylib"
    } else if target.contains("windows") {
      "dll"
    } else {
      "so"
    };
    let lib_name = if target.contains("windows") {
      format!("denort.{lib_ext}")
    } else {
      format!("libdenort.{lib_ext}")
    };
    let binary_name = format!("libdenort-{target}.zip");

    let binary_path_suffix = match DENO_VERSION_INFO.release_channel {
      ReleaseChannel::Canary => {
        format!("canary/{}/{}", DENO_VERSION_INFO.git_hash, binary_name)
      }
      _ => {
        format!("release/v{}/{}", DENO_VERSION_INFO.deno, binary_name)
      }
    };

    let download_directory = self.deno_dir.dl_folder_path();
    let binary_path = download_directory.join(&binary_path_suffix);
    log::debug!("Resolved libdenort: {}", binary_path.display());

    let read_file = |path: &Path| -> Result<Vec<u8>, AnyError> {
      std::fs::read(path).with_context(|| format!("Reading {}", path.display()))
    };
    let archive_data = if binary_path.exists() {
      read_file(&binary_path)?
    } else {
      self
        .download_base_binary(&binary_path, &binary_path_suffix)
        .await
        .context("Setting up desktop base binary.")?
    };
    let temp_dir = tempfile::TempDir::new()?;
    let base_binary_path = archive::unpack_into_dir(archive::UnpackArgs {
      exe_name: &lib_name,
      archive_name: &binary_name,
      archive_data: &archive_data,
      dest_path: temp_dir.path(),
    })?;
    let base_binary = read_file(&base_binary_path)?;
    drop(temp_dir);
    Ok(base_binary)
  }

  async fn download_base_binary(
    &self,
    output_path: &Path,
    binary_path_suffix: &str,
  ) -> Result<Vec<u8>, AnyError> {
    let download_url = format!("https://dl.deno.land/{binary_path_suffix}");
    let response = {
      let progress_bars = ProgressBar::new(ProgressBarStyle::DownloadBars);
      let progress = progress_bars.update(&download_url);

      self
        .http_client_provider
        .get_or_create()?
        .download_with_progress_and_retries(
          download_url.parse()?,
          &Default::default(),
          &progress,
        )
        .await?
    };
    let bytes = response
      .into_bytes()
      .with_context(|| format!("Failed downloading '{}'", download_url))?;

    let create_dir_all = |dir: &Path| {
      std::fs::create_dir_all(dir)
        .with_context(|| format!("Creating {}", dir.display()))
    };
    create_dir_all(output_path.parent().unwrap())?;
    atomic_write_file_with_retries(
      &CliSys::default(),
      output_path,
      &bytes,
      CACHE_PERM,
    )
    .with_context(|| format!("Writing {}", output_path.display()))?;
    Ok(bytes)
  }

  /// This functions creates a standalone deno binary by appending a bundle
  /// and magic trailer to the currently executing binary.
  async fn write_standalone_binary(
    &self,
    options: WriteBinOptions<'_>,
    original_bin: Vec<u8>,
  ) -> Result<(), AnyError> {
    let WriteBinOptions {
      writer,
      display_output_filename,
      graph,
      entrypoint,
      include_paths,
      exclude_paths,
      compile_flags,
    } = options;
    let ca_data = match self.cli_options.ca_data() {
      Some(CaData::File(ca_file)) => Some(
        std::fs::read(ca_file).with_context(|| format!("Reading {ca_file}"))?,
      ),
      Some(CaData::Bytes(bytes)) => Some(bytes.clone()),
      None => None,
    };
    let mut vfs = VfsBuilder::new();
    for path in exclude_paths {
      vfs.add_exclude_path(path);
    }
    // Embed the workspace package.json files so the standalone binary's node
    // resolver can read their "exports" (and other) fields at runtime. Without
    // this, resolving a workspace member by its package name falls back to
    // legacy `index.js` resolution instead of honoring the package's exports.
    for pkg_json in self.cli_options.workspace().package_jsons() {
      vfs.add_path(&pkg_json.path)?;
    }
    let progress_bar = ProgressBar::new(ProgressBarStyle::ProgressBars);
    // With --bundle the JS graph is self-contained, so the whole npm tree
    // is intentionally left out of the binary. The exception is packages
    // that ship native (.node) addons: the package JS is still bundled, but
    // its `.node` file imports stay external (`external = ["*.node"]` in
    // compile.rs) so the addon loader resolves them against the embedded VFS
    // at runtime. For that to work the package's installed folder, plus the
    // closure of its dependencies, must be embedded in the VFS.
    let npm_snapshot = if compile_flags.bundle {
      self
        .fill_bundle_native_addon_vfs(&mut vfs, &progress_bar)
        .context("Embedding native addon packages.")?
    } else {
      match &self.npm_resolver {
        CliNpmResolver::Managed(managed) => {
          if graph.modules().any(|m| m.npm().is_some()) {
            let snapshot = managed.resolution().snapshot();
            // When the user opts in (or via the existing unstable lazy-caching
            // path), prune the resolution snapshot to packages reachable from
            // npm specifiers in the graph. Otherwise embed the full snapshot
            // so non-statically-analyzable dynamic imports keep working.
            let snapshot = if compile_flags.exclude_unused_npm
              || self.cli_options.unstable_npm_lazy_caching()
            {
              let reqs = graph
                .specifiers()
                .filter_map(|(s, _)| {
                  NpmPackageReqReference::from_specifier(s)
                    .ok()
                    .map(|req_ref| req_ref.into_inner().req)
                })
                .collect::<Vec<_>>();
              snapshot.subset(&reqs)
            } else {
              snapshot
            }
            .as_valid_serialized_for_system(&self.npm_system_info);
            if !snapshot.as_serialized().packages.is_empty() {
              self
                .fill_npm_vfs(&mut vfs, Some(&snapshot), &progress_bar)
                .context("Building npm vfs.")?;
              Some(snapshot)
            } else {
              None
            }
          } else {
            None
          }
        }
        CliNpmResolver::Byonm(_) => {
          self.fill_npm_vfs(&mut vfs, None, &progress_bar)?;
          None
        }
      }
    };
    for include_file in include_paths {
      let path = deno_path_util::url_to_file_path(include_file)?;
      vfs
        .add_path(&path)
        .with_context(|| format!("Including {}", path.display()))?;
    }
    let specifiers_count = graph.specifiers_count();
    let mut specifier_store = SpecifierStore::with_capacity(specifiers_count);
    let mut remote_modules_store =
      SpecifierDataStore::with_capacity(specifiers_count);
    let mut asset_module_urls = graph.asset_module_urls();
    let progress =
      progress_bar.update_with_prompt(ProgressMessagePrompt::Compile, "");
    progress.set_total_size(specifiers_count as u64);
    let mut modules_done: u64 = 0;
    // todo(dsherret): transpile and analyze CJS in parallel
    for module in graph.modules() {
      if module.specifier().scheme() == "data" {
        continue; // don't store data urls as an entry as they're in the code
      }
      let mut maybe_source_map = None;
      let mut maybe_transpiled = None;
      let mut maybe_cjs_analysis = None;
      let (maybe_original_source, media_type) = match module {
        deno_graph::Module::Js(m) => {
          let specifier = &m.specifier;
          let original_bytes = match m.source.try_get_original_bytes() {
            Some(bytes) => bytes,
            None => self.load_asset_bypass_permissions(specifier).await?.source,
          };
          if self.cjs_tracker.is_maybe_cjs(specifier, m.media_type)? {
            if self.cjs_tracker.is_cjs_with_known_is_script(
              specifier,
              m.media_type,
              m.is_script,
            )? {
              let cjs_analysis = self
                .cjs_module_export_analyzer
                .analyze_all_exports(
                  module.specifier(),
                  Some(Cow::Borrowed(m.source.text.as_ref())),
                )
                .await?;
              maybe_cjs_analysis = Some(match cjs_analysis {
                ResolvedCjsAnalysis::Esm(_) => CjsExportAnalysisEntry::Esm,
                ResolvedCjsAnalysis::Cjs(exports) => {
                  CjsExportAnalysisEntry::Cjs(
                    exports.into_iter().collect::<Vec<_>>(),
                  )
                }
              });
            } else {
              maybe_cjs_analysis = Some(CjsExportAnalysisEntry::Esm);
            }
          }
          if m.media_type.is_emittable() {
            let module_kind = match maybe_cjs_analysis.as_ref() {
              Some(CjsExportAnalysisEntry::Cjs(_)) => ModuleKind::Cjs,
              _ => ModuleKind::Esm,
            };
            let (source, source_map) =
              self.emitter.emit_source_for_deno_compile(
                &m.specifier,
                m.media_type,
                module_kind,
                &m.source.text,
              )?;
            if source != m.source.text.as_ref() {
              maybe_source_map = Some(source_map.into_bytes());
              maybe_transpiled = Some(source.into_bytes());
            }
          }
          (Some(original_bytes), m.media_type)
        }
        deno_graph::Module::Json(m) => {
          let original_bytes = match m.source.try_get_original_bytes() {
            Some(bytes) => bytes,
            None => {
              self
                .load_asset_bypass_permissions(&m.specifier)
                .await?
                .source
            }
          };
          (Some(original_bytes), m.media_type)
        }
        deno_graph::Module::Wasm(m) => {
          (Some(m.source.clone()), MediaType::Wasm)
        }
        deno_graph::Module::Npm(_)
        | deno_graph::Module::Node(_)
        | deno_graph::Module::External(_) => (None, MediaType::Unknown),
      };
      if let Some(original_source) = maybe_original_source {
        asset_module_urls.swap_remove(module.specifier());
        let maybe_cjs_export_analysis = maybe_cjs_analysis
          .as_ref()
          .map(bincode::serialize)
          .transpose()?;
        if module.specifier().scheme() == "file" {
          let file_path = deno_path_util::url_to_file_path(module.specifier())?;
          vfs
            .add_file_with_data(
              &file_path,
              deno_lib::standalone::virtual_fs::AddFileDataOptions {
                data: original_source.to_vec(),
                maybe_transpiled,
                maybe_source_map,
                maybe_cjs_export_analysis,
                mtime: file_path
                  .metadata()
                  .ok()
                  .and_then(|m| m.modified().ok()),
              },
            )
            .with_context(|| {
              format!("Failed adding '{}'", file_path.display())
            })?;
        } else {
          let specifier_id = specifier_store.get_or_add(module.specifier());
          remote_modules_store.add(
            specifier_id,
            RemoteModuleEntry {
              media_type,
              is_valid_utf8: is_valid_utf8(&original_source),
              data: Cow::Owned(original_source.to_vec()),
              maybe_transpiled: maybe_transpiled.map(Cow::Owned),
              maybe_source_map: maybe_source_map.map(Cow::Owned),
              maybe_cjs_export_analysis: maybe_cjs_export_analysis
                .map(Cow::Owned),
            },
          );
        }
      }
      modules_done += 1;
      progress.set_position(modules_done);
    }
    drop(progress);

    for url in asset_module_urls {
      if graph.try_get(url).is_err() {
        // skip because there was an error loading this module
        continue;
      }
      match url.scheme() {
        "file" => {
          let file_path = deno_path_util::url_to_file_path(url)?;
          vfs.add_path(&file_path)?;
        }
        "http" | "https" => {
          let specifier_id = specifier_store.get_or_add(url);
          if !remote_modules_store.contains(specifier_id) {
            // it's ok to bypass permissions here because we verified the module
            // loaded successfully in the graph
            let file = self.load_asset_bypass_permissions(url).await?;
            remote_modules_store.add(
              specifier_id,
              RemoteModuleEntry {
                media_type: MediaType::from_specifier_and_headers(
                  &file.url,
                  file.maybe_headers.as_ref(),
                ),
                is_valid_utf8: is_valid_utf8(&file.source),
                data: Cow::Owned(file.source.to_vec()),
                maybe_cjs_export_analysis: None,
                maybe_source_map: None,
                maybe_transpiled: None,
              },
            );
          }
        }
        _ => {}
      }
    }

    let mut redirects_store =
      SpecifierDataStore::with_capacity(graph.redirects.len());
    for (from, to) in &graph.redirects {
      redirects_store.add(
        specifier_store.get_or_add(from),
        specifier_store.get_or_add(to),
      );
    }

    if let Some(import_map) = self.workspace_resolver.maybe_import_map()
      && let Ok(file_path) = url_to_file_path(import_map.base_url())
      && let Some(import_map_parent_dir) = file_path.parent()
    {
      // tell the vfs about the import map's parent directory in case it
      // falls outside what the root of where the VFS will be based
      vfs.add_possible_min_root_dir(import_map_parent_dir);
    }
    if let Some(node_modules_dir) = self.npm_resolver.root_node_modules_path() {
      // ensure the vfs doesn't go below the node_modules directory's parent
      if let Some(parent) = node_modules_dir.parent() {
        vfs.add_possible_min_root_dir(parent);
      }
    }

    // do CJS export analysis on all the files in the VFS
    // todo(dsherret): analyze cjs in parallel
    let mut to_add = Vec::new();
    for (file_path, file) in vfs.iter_files() {
      if file.cjs_export_analysis_offset.is_some() {
        continue; // already analyzed
      }
      let specifier = deno_path_util::url_from_file_path(&file_path)?;
      let media_type = MediaType::from_specifier(&specifier);
      // Only script-flavored files can carry CJS exports. Extensions answer
      // this for everything except extensionless files (`MediaType::Unknown`),
      // which may be real modules (an npm `"main"` with no extension — see
      // test-module-main-extension-lookup); those are disambiguated by content
      // below rather than skipped outright.
      if !matches!(
        media_type,
        MediaType::JavaScript
          | MediaType::Mjs
          | MediaType::Cjs
          | MediaType::Jsx
          | MediaType::TypeScript
          | MediaType::Mts
          | MediaType::Cts
          | MediaType::Tsx
          | MediaType::Dts
          | MediaType::Dmts
          | MediaType::Dcts
          | MediaType::Unknown
      ) {
        continue;
      }
      if self.cjs_tracker.is_maybe_cjs(&specifier, media_type)? {
        // Strict UTF-8 (not `from_utf8_lossy`): binary assets (images,
        // fonts, …) that resolve to `Unknown` are skipped rather than
        // mangled into garbage that panics swc. Extensionless *text*
        // modules still flow through.
        let Some(bytes) = vfs.file_bytes(file.offset) else {
          continue;
        };
        let Ok(source) = std::str::from_utf8(bytes) else {
          continue;
        };
        let cjs_analysis_result = self
          .cjs_module_export_analyzer
          .analyze_all_exports(&specifier, Some(source.into()))
          .await;
        let analysis = match cjs_analysis_result {
          Ok(ResolvedCjsAnalysis::Esm(_)) => CjsExportAnalysisEntry::Esm,
          Ok(ResolvedCjsAnalysis::Cjs(exports)) => {
            CjsExportAnalysisEntry::Cjs(exports.into_iter().collect::<Vec<_>>())
          }
          Err(err) => {
            log::debug!(
              "Had cjs export analysis error for '{}': {}",
              specifier,
              err
            );
            CjsExportAnalysisEntry::Error(err.to_string())
          }
        };
        to_add.push((file_path, bincode::serialize(&analysis)?));
      }
    }
    for (file_path, analysis) in to_add {
      vfs.add_cjs_export_analysis(&file_path, analysis);
    }

    let vfs = self.build_vfs_consolidating_global_npm_cache(vfs);

    let root_dir_url = match &vfs.root_path {
      WindowsSystemRootablePath::Path(dir) => {
        Some(url_from_directory_path(dir)?)
      }
      WindowsSystemRootablePath::WindowSystemRoot => None,
    };
    let root_dir_url = match &root_dir_url {
      Some(url) => StandaloneRelativeFileBaseUrl::Path(url),
      None => StandaloneRelativeFileBaseUrl::WindowsSystemRoot,
    };

    let code_cache_key = if self.cli_options.code_cache_enabled() {
      let mut hasher = FastInsecureHasher::new_deno_versioned();
      for module in graph.modules() {
        if let Some(source) = module.source() {
          hasher
            .write(root_dir_url.specifier_key(module.specifier()).as_bytes());
          hasher.write(source.as_bytes());
        }
      }
      Some(hasher.finish())
    } else {
      None
    };

    let node_modules = match &self.npm_resolver {
      CliNpmResolver::Managed(_) => {
        npm_snapshot.as_ref().map(|_| NodeModules::Managed {
          node_modules_dir: self.npm_resolver.root_node_modules_path().map(
            |path| {
              root_dir_url
                .specifier_key(
                  &ModuleSpecifier::from_directory_path(path).unwrap(),
                )
                .into_owned()
            },
          ),
        })
      }
      CliNpmResolver::Byonm(resolver) => Some(NodeModules::Byonm {
        root_node_modules_dir: resolver.root_node_modules_path().map(
          |node_modules_dir| {
            root_dir_url
              .specifier_key(
                &ModuleSpecifier::from_directory_path(node_modules_dir)
                  .unwrap(),
              )
              .into_owned()
          },
        ),
      }),
    };

    let env_vars_from_env_file = {
      let mut aggregated_env_vars = IndexMap::new();
      for env_file_name in self.cli_options.env_file_names().rev() {
        match deno_dotenv::find_path_and_content(
          &CliSys::default(),
          self.cli_options.initial_cwd(),
          env_file_name,
        ) {
          Ok(Some((env_file_path, content))) => {
            match get_file_env_vars(&content) {
              Ok(env_vars) => {
                aggregated_env_vars.extend(env_vars);
                log::info!(
                  "{} Environment variables from the file \"{}\" were embedded in the generated executable file",
                  crate::colors::yellow("Warning"),
                  env_file_path.display()
                );
              }
              Err(e) => {
                handle_dotenv_error(
                  &e,
                  &env_file_path,
                  self.cli_options.log_level(),
                );
              }
            };
          }
          Ok(None) => {
            handle_dotenv_not_found(
              env_file_name,
              self.cli_options.log_level(),
            );
          }
          Err(e) => {
            handle_dotenv_io_error(&e, self.cli_options.log_level());
          }
        };
      }
      aggregated_env_vars
    };

    output_vfs(&vfs, display_output_filename);

    let preload_modules = self
      .cli_options
      .preload_modules()?
      .into_iter()
      .map(|s| root_dir_url.specifier_key(&s).into_owned())
      .collect::<Vec<_>>();

    let require_modules = self
      .cli_options
      .require_modules()?
      .into_iter()
      .map(|s| root_dir_url.specifier_key(&s).into_owned())
      .collect::<Vec<_>>();

    let metadata = Metadata {
      argv: compile_flags.args.clone(),
      seed: self.cli_options.seed(),
      code_cache_key,
      location: self.cli_options.location_flag().clone(),
      permissions: self.cli_options.permissions_options()?,
      v8_flags: construct_v8_flags(
        &get_default_v8_flags(),
        self.cli_options.v8_flags(),
        vec![],
      ),
      unsafely_ignore_certificate_errors: self
        .cli_options
        .unsafely_ignore_certificate_errors()
        .clone(),
      log_level: self.cli_options.log_level(),
      ca_stores: self.cli_options.ca_stores().clone(),
      ca_data,
      env_vars_from_env_file,
      entrypoint_key: root_dir_url.specifier_key(entrypoint).into_owned(),
      preload_modules,
      require_modules,
      workspace_resolver: SerializedWorkspaceResolver {
        import_map: self.workspace_resolver.maybe_import_map().map(|i| {
          SerializedWorkspaceResolverImportMap {
            specifier: if i.base_url().scheme() == "file" {
              root_dir_url.specifier_key(i.base_url()).into_owned()
            } else {
              // just make a remote url local
              "deno.json".to_string()
            },
            json: i.to_json(),
          }
        }),
        jsr_pkgs: self
          .workspace_resolver
          .jsr_packages()
          .iter()
          .map(|pkg| SerializedResolverWorkspaceJsrPackage {
            relative_base: root_dir_url.specifier_key(&pkg.base).into_owned(),
            name: pkg.name.clone(),
            version: pkg.version.clone(),
            exports: pkg.exports.clone(),
          })
          .collect(),
        package_jsons: self
          .workspace_resolver
          .package_jsons()
          .map(|pkg_json| {
            (
              root_dir_url
                .specifier_key(&pkg_json.specifier())
                .into_owned(),
              serde_json::to_value(pkg_json).unwrap(),
            )
          })
          .collect(),
        pkg_json_resolution: self.workspace_resolver.pkg_json_dep_resolution(),
        catalogs: self.workspace_resolver.catalogs().clone(),
      },
      node_modules,
      unstable_config: UnstableConfig {
        legacy_flag_enabled: false,
        detect_cjs: self.cli_options.unstable_detect_cjs(),
        features: self
          .cli_options
          .unstable_features()
          .into_iter()
          .map(|s| s.to_string())
          .collect(),
        lazy_dynamic_imports: self.cli_options.unstable_lazy_dynamic_imports(),
        npm_lazy_caching: self.cli_options.unstable_npm_lazy_caching(),
        raw_imports: self.cli_options.unstable_raw_imports(),
        sloppy_imports: self.cli_options.unstable_sloppy_imports(),
        tsgo: self.cli_options.unstable_tsgo(),
      },
      otel_config: self.cli_options.otel_config(),
      vfs_case_sensitivity: vfs.case_sensitivity,
      self_extracting: if compile_flags.self_extracting {
        let mut hasher = FastInsecureHasher::new_deno_versioned();
        for file in &vfs.files {
          hasher.write_u64(file.len() as u64);
          hasher.write(file);
        }
        Some(format!("{:016x}", hasher.finish()))
      } else {
        None
      },
      // Bake in a stable app identity so origin-bound storage (default
      // `Deno.openKv()`, `localStorage`, `caches`) persists to a per-app
      // directory at runtime. Prefer an explicit `--app-name`, otherwise derive
      // it from the output file name (minus any `.exe` extension). Resolving
      // here keeps the identity stable even if the binary is later renamed. The
      // name is already validated in `write_bin` (via `resolve_app_name`).
      app_name: Some(resolve_app_name(compile_flags, display_output_filename)?),
      app_version: self
        .cli_options
        .workspace()
        .root_deno_json()
        .and_then(|c| c.json.version.clone()),
      error_reporting_url: self
        .cli_options
        .start_dir
        .to_desktop_config()
        .ok()
        .and_then(|c| c.error_reporting.as_ref()?.url.clone()),
      release_base_url: self
        .cli_options
        .start_dir
        .to_desktop_config()
        .ok()
        .and_then(|c| c.release.as_ref()?.base_url.clone()),
      // The generic compiler cannot mint the Oden parent brand. A later
      // checkpoint wires the explicit build-only contract after native
      // validation; keeping this absent preserves the closed activation gate.
      oden_parent_capture_v2: None,
    };

    let (data_section_bytes, section_sizes) = serialize_binary_data_section(
      &metadata,
      npm_snapshot.map(|s| s.into_serialized()),
      &specifier_store.for_serialization(&root_dir_url),
      &redirects_store,
      &remote_modules_store,
      &vfs,
    )
    .context("Serializing binary data section.")?;

    log::info!(
      "\n{} {}",
      crate::colors::bold("Files:"),
      crate::util::display::human_size(section_sizes.vfs as f64)
    );
    log::info!(
      "{} {}",
      crate::colors::bold("Metadata:"),
      crate::util::display::human_size(section_sizes.metadata as f64)
    );
    log::info!(
      "{} {}\n",
      crate::colors::bold("Remote modules:"),
      crate::util::display::human_size(section_sizes.remote_modules as f64)
    );

    write_binary_bytes(writer, original_bin, data_section_bytes, compile_flags)
      .context("Writing binary bytes")
  }

  async fn load_asset_bypass_permissions(
    &self,
    specifier: &ModuleSpecifier,
  ) -> Result<
    deno_cache_dir::file_fetcher::File,
    deno_resolver::file_fetcher::FetchError,
  > {
    self
      .file_fetcher
      .fetch_with_options(
        specifier,
        FetchPermissionsOptionRef::AllowAll,
        FetchOptions {
          local: FetchLocalOptions {
            include_mtime: false,
          },
          maybe_auth: None,
          maybe_accept: None,
          maybe_cache_setting: Some(
            &deno_cache_dir::file_fetcher::CacheSetting::Use,
          ),
        },
      )
      .await
  }

  /// Decide what to embed for `deno compile --bundle`. The bundle is
  /// always shipped; this controls the npm portion. We need it when
  /// either the CJS-from-ESM wrapper pointed at on-disk paths during
  /// rewriting, or the resolved tree has a native (`.node`) addon — in
  /// both cases the compiled binary will do node-module resolution at
  /// runtime. Pure-ESM bundles with no native addons skip this and ship
  /// nothing npm-related.
  ///
  /// When embedding is needed, we ship only the packages actually
  /// reached: the rewriter recorded every absolute path it pointed at,
  /// and we map each path back to its owning npm package and walk that
  /// closure. The full resolution snapshot still goes in the metadata
  /// so denort can resolve packages by name at runtime.
  fn fill_bundle_native_addon_vfs(
    &self,
    builder: &mut VfsBuilder,
    progress_bar: &ProgressBar,
  ) -> Result<Option<ValidSerializedNpmResolutionSnapshot>, AnyError> {
    let needs_for_cjs_wrapper =
      self.cli_options.compile_bundle_embed_node_modules();
    let referenced_paths = self.cli_options.compile_bundle_referenced_paths();
    // For BYONM the addon scan walks the workspace `node_modules` trees, so
    // it needs the workspace root (managed npm ignores it).
    let workspace_root = self
      .cli_options
      .workspace()
      .root_dir_url()
      .to_file_path()
      .ok();
    let needs_for_native_addons = !needs_for_cjs_wrapper
      && !super::native_addons::find_native_addon_packages(
        self.npm_resolver,
        &self.npm_system_info,
        workspace_root.as_deref(),
      )?
      .is_empty();
    if !needs_for_cjs_wrapper && !needs_for_native_addons {
      return Ok(None);
    }

    match self.npm_resolver {
      CliNpmResolver::Managed(managed) => {
        let snapshot = managed
          .resolution()
          .snapshot()
          .as_valid_serialized_for_system(&self.npm_system_info);
        if snapshot.as_serialized().packages.is_empty() {
          return Ok(None);
        }
        // `collect_bundle_required_packages` only returns `None` for BYONM,
        // which is handled by the `CliNpmResolver::Byonm` arm below, so a
        // managed resolver always yields `Some` here.
        let Some(needed_ids) =
          super::native_addons::collect_bundle_required_packages(
            self.npm_resolver,
            &self.npm_system_info,
            referenced_paths,
          )?
        else {
          unreachable!(
            "collect_bundle_required_packages returns None only for BYONM"
          );
        };
        let progress =
          progress_bar.update_with_prompt(ProgressMessagePrompt::Compile, "");
        progress.set_total_size(needed_ids.len() as u64);
        // Dedup the set of `<deno-cache>/<id>/node_modules/` directories we
        // add: a single id's node_modules dir contains the canonical package
        // folder plus sibling symlinks to its direct deps. Going one level up
        // from the canonical folder picks both up so node-module resolution at
        // runtime can follow the symlink chain (e.g. the NAPI-RS
        // platform-specific sibling package).
        let mut embedded_roots: std::collections::HashSet<PathBuf> =
          std::collections::HashSet::new();
        let mut done: u64 = 0;
        for id in &needed_ids {
          if let Ok(folder) = managed.resolve_pkg_folder_from_pkg_id(id)
            && folder.exists()
          {
            let root_to_add =
              pkg_folder_node_modules_root(&folder).unwrap_or(folder.as_path());
            if embedded_roots.insert(root_to_add.to_path_buf()) {
              builder.add_dir_recursive(root_to_add).with_context(|| {
                format!("Embedding npm package at '{}'", root_to_add.display())
              })?;
            }
          }
          done += 1;
          progress.set_position(done);
        }
        Ok(Some(snapshot))
      }
      CliNpmResolver::Byonm(_) => {
        self.fill_npm_vfs(builder, None, progress_bar)?;
        Ok(None)
      }
    }
  }

  fn fill_npm_vfs(
    &self,
    builder: &mut VfsBuilder,
    snapshot: Option<&ValidSerializedNpmResolutionSnapshot>,
    progress_bar: &ProgressBar,
  ) -> Result<(), AnyError> {
    fn maybe_warn_different_system(system_info: &NpmSystemInfo) {
      if system_info != &NpmSystemInfo::default() {
        log::warn!(
          "{} The node_modules directory may be incompatible with the target system.",
          crate::colors::yellow("Warning")
        );
      }
    }

    match &self.npm_resolver {
      CliNpmResolver::Managed(npm_resolver) => {
        if let Some(node_modules_path) = npm_resolver.root_node_modules_path() {
          maybe_warn_different_system(&self.npm_system_info);
          let _progress =
            progress_bar.update_with_prompt(ProgressMessagePrompt::Compile, "");
          builder.add_dir_recursive(node_modules_path)?;
          Ok(())
        } else {
          let snapshot = snapshot.unwrap();
          // we'll flatten to remove any custom registries later
          let mut packages =
            snapshot.as_serialized().packages.iter().collect::<Vec<_>>();
          packages.sort_by(|a, b| a.id.cmp(&b.id)); // determinism
          let current_system = NpmSystemInfo::default();
          let progress =
            progress_bar.update_with_prompt(ProgressMessagePrompt::Compile, "");
          progress.set_total_size(packages.len() as u64);
          let mut packages_done: u64 = 0;
          for package in packages {
            let folder =
              npm_resolver.resolve_pkg_folder_from_pkg_id(&package.id)?;
            if !package.system.matches_system(&current_system)
              && !folder.exists()
            {
              log::warn!(
                "{} Ignoring 'npm:{}' because it was not present on the current system.",
                crate::colors::yellow("Warning"),
                package.id
              );
            } else {
              builder.add_dir_recursive(&folder)?;
            }
            packages_done += 1;
            progress.set_position(packages_done);
          }
          drop(progress);
          Ok(())
        }
      }
      CliNpmResolver::Byonm(_) => {
        maybe_warn_different_system(&self.npm_system_info);
        let _progress =
          progress_bar.update_with_prompt(ProgressMessagePrompt::Compile, "");
        // traverse and add all the node_modules directories in the workspace
        let mut pending_dirs = VecDeque::new();
        pending_dirs.push_back(
          self
            .cli_options
            .workspace()
            .root_dir_url()
            .to_file_path()
            .unwrap(),
        );
        while let Some(pending_dir) = pending_dirs.pop_front() {
          let Ok(entries) = fs::read_dir(&pending_dir) else {
            // Don't bother surfacing this error as it might be an error
            // like "access denied". In this case, just skip over it.
            continue;
          };
          let mut entries = entries.filter_map(|e| e.ok()).collect::<Vec<_>>();
          entries.sort_by_cached_key(|entry| entry.file_name()); // determinism
          for entry in entries {
            let path = entry.path();
            if !path.is_dir() {
              continue;
            }
            if path.ends_with("node_modules") {
              builder.add_dir_recursive(&path)?;
            } else {
              pending_dirs.push_back(path);
            }
          }
        }
        Ok(())
      }
    }
  }

  fn build_vfs_consolidating_global_npm_cache(
    &self,
    mut vfs: VfsBuilder,
  ) -> BuiltVfs {
    match &self.npm_resolver {
      CliNpmResolver::Managed(npm_resolver) => {
        if npm_resolver.root_node_modules_path().is_some() {
          return vfs.build();
        }

        let global_cache_root_path = npm_resolver.global_cache_root_path();

        // Flatten all the registries folders into a single ".deno_compile_node_modules/localhost" folder
        // that will be used by denort when loading the npm cache. This avoids us exposing
        // the user's private registry information and means we don't have to bother
        // serializing all the different registry config into the binary.
        //
        // A registry url may include a sub-path (e.g.
        // `http://mirrors.example.com/npm/`), in which case the on-disk cache
        // layout is `<global_cache>/<host>/<sub>/<pkg>/...` rather than
        // `<global_cache>/<host>/<pkg>/...`. Walk to each known registry's
        // package root before flattening so packages always end up directly
        // under `localhost/`.
        let known_registries_dirnames: Vec<String> =
          npm_resolver.known_registries_dirnames().to_vec();
        let mut localhost_entries: IndexMap<String, VfsEntry> = IndexMap::new();
        let mut registry_top_segments: HashSet<String> = HashSet::new();
        for registry_dirname in &known_registries_dirnames {
          if let Some(first) = registry_dirname.split('/').next()
            && !first.is_empty()
          {
            registry_top_segments.insert(first.to_string());
          }
          let registry_path = global_cache_root_path.join(registry_dirname);
          let Some(registry_dir) = vfs.get_dir_mut(&registry_path) else {
            continue;
          };
          for entry in registry_dir.entries.take_inner() {
            log::debug!("Flattening {} into node_modules", entry.name());
            if let Some(existing) =
              localhost_entries.insert(entry.name().to_string(), entry)
            {
              panic!(
                "Unhandled scenario where a duplicate entry was found: {:?}",
                existing
              );
            }
          }
        }

        let Some(root_dir) = vfs.get_dir_mut(global_cache_root_path) else {
          return vfs.build();
        };

        root_dir.name = DENO_COMPILE_GLOBAL_NODE_MODULES_DIR_NAME.to_string();
        let mut new_entries = Vec::with_capacity(root_dir.entries.len());
        for entry in root_dir.entries.take_inner() {
          match &entry {
            VfsEntry::Dir(dir) if registry_top_segments.contains(&dir.name) => {
              // The packages under this registry host dir have already been
              // flattened into `localhost_entries`. Drop the (now empty)
              // intermediate directory tree so it isn't embedded twice.
            }
            _ => {
              new_entries.push(entry);
            }
          }
        }
        new_entries.push(VfsEntry::Dir(VirtualDirectory {
          name: "localhost".to_string(),
          entries: VirtualDirectoryEntries::new(
            localhost_entries.into_iter().map(|(_, v)| v).collect(),
          ),
        }));
        root_dir.entries = VirtualDirectoryEntries::new(new_entries);

        // it's better to not expose the user's cache directory, so take it out
        // of there
        let case_sensitivity = vfs.case_sensitivity();
        let parent = global_cache_root_path.parent().unwrap();
        let parent_dir = vfs.get_dir_mut(parent).unwrap();
        let index = parent_dir
          .entries
          .binary_search(
            DENO_COMPILE_GLOBAL_NODE_MODULES_DIR_NAME,
            case_sensitivity,
          )
          .unwrap();
        let npm_global_cache_dir_entry = parent_dir.entries.remove(index);

        // go up from the ancestors removing empty directories...
        // this is not as optimized as it could be
        let mut last_name =
          Cow::Borrowed(DENO_COMPILE_GLOBAL_NODE_MODULES_DIR_NAME);
        for ancestor in
          parent.ancestors().map(Some).chain(std::iter::once(None))
        {
          let dir = if let Some(ancestor) = ancestor {
            vfs.get_dir_mut(ancestor).unwrap()
          } else if cfg!(windows) {
            vfs.get_system_root_dir_mut()
          } else {
            break;
          };
          if let Ok(index) =
            dir.entries.binary_search(&last_name, case_sensitivity)
          {
            dir.entries.remove(index);
          }
          last_name = Cow::Owned(dir.name.clone());
          if !dir.entries.is_empty() {
            break;
          }
        }

        // now build the vfs and add the global cache dir entry there
        let mut built_vfs = vfs.build();
        built_vfs
          .entries
          .insert(npm_global_cache_dir_entry, case_sensitivity);
        built_vfs
      }
      CliNpmResolver::Byonm(_) => vfs.build(),
    }
  }
}

#[allow(clippy::too_many_arguments, reason = "private code")]
fn write_binary_bytes(
  mut file_writer: File,
  original_bin: Vec<u8>,
  data_section_bytes: Vec<u8>,
  compile_flags: &CompileFlags,
) -> Result<(), AnyError> {
  let target = compile_flags.resolve_target();
  if target.contains("linux") {
    libsui::Elf::new(&original_bin).append(
      "d3n0l4nd",
      &data_section_bytes,
      &mut file_writer,
    )?;
  } else if target.contains("windows") {
    let mut pe = libsui::PortableExecutable::from(&original_bin)?;
    if let Some(icon) = compile_flags.icon.as_ref() {
      let icon = std::fs::read(icon)?;
      pe = pe.set_icon(&icon)?;
    }

    pe.write_resource("d3n0l4nd", data_section_bytes)?
      .build(&mut file_writer)?;
  } else if target.contains("darwin") {
    libsui::Macho::from(original_bin)?
      .write_section("d3n0l4nd", data_section_bytes)?
      .build_and_sign(&mut file_writer)?;
  }
  Ok(())
}

struct BinaryDataSectionSizes {
  metadata: usize,
  remote_modules: usize,
  vfs: usize,
}

/// Binary format:
/// * d3n0l4nd
/// * <metadata_len><metadata>
/// * <npm_snapshot_len><npm_snapshot>
/// * <specifiers>
/// * <redirects>
/// * <remote_modules>
/// * <vfs_headers_len><vfs_headers>
/// * <vfs_file_data_len><vfs_file_data>
/// * d3n0l4nd
#[allow(clippy::too_many_arguments, reason = "private code")]
fn serialize_binary_data_section(
  metadata: &Metadata,
  npm_snapshot: Option<SerializedNpmResolutionSnapshot>,
  specifiers: &SpecifierStoreForSerialization,
  redirects: &SpecifierDataStore<SpecifierId>,
  remote_modules: &SpecifierDataStore<RemoteModuleEntry<'_>>,
  vfs: &BuiltVfs,
) -> Result<(Vec<u8>, BinaryDataSectionSizes), AnyError> {
  let metadata = serde_json::to_string(metadata)?;
  let npm_snapshot =
    npm_snapshot.map(serialize_npm_snapshot).unwrap_or_default();
  let serialized_vfs = serde_json::to_string(&vfs.entries)?;

  let remote_modules_len = Cell::new(0);
  let metadata_len = Cell::new(0);
  let vfs_len = Cell::new(0);

  let bytes = capacity_builder::BytesBuilder::build(|builder| {
    builder.append(MAGIC_BYTES);
    // 1. Metadata
    {
      builder.append_le(metadata.len() as u64);
      builder.append(&metadata);
    }
    // 2. Npm snapshot
    {
      builder.append_le(npm_snapshot.len() as u64);
      builder.append(&npm_snapshot);
    }
    metadata_len.set(builder.len());
    // 3. Specifiers
    builder.append(specifiers);
    // 4. Redirects
    redirects.serialize(builder);
    // 5. Remote modules
    remote_modules.serialize(builder);
    remote_modules_len.set(builder.len() - metadata_len.get());
    // 6. VFS
    {
      builder.append_le(serialized_vfs.len() as u64);
      builder.append(&serialized_vfs);
      let vfs_bytes_len = vfs.files.iter().map(|f| f.len() as u64).sum::<u64>();
      builder.append_le(vfs_bytes_len);
      for file in &vfs.files {
        builder.append(file);
      }
    }
    vfs_len.set(builder.len() - remote_modules_len.get());

    // write the magic bytes at the end so we can use it
    // to make sure we've deserialized correctly
    builder.append(MAGIC_BYTES);
  })?;

  Ok((
    bytes,
    BinaryDataSectionSizes {
      metadata: metadata_len.get(),
      remote_modules: remote_modules_len.get(),
      vfs: vfs_len.get(),
    },
  ))
}

fn serialize_npm_snapshot(
  mut snapshot: SerializedNpmResolutionSnapshot,
) -> Vec<u8> {
  fn append_string(bytes: &mut Vec<u8>, string: &str) {
    let len = string.len() as u32;
    bytes.extend_from_slice(&len.to_le_bytes());
    bytes.extend_from_slice(string.as_bytes());
  }

  snapshot.packages.sort_by(|a, b| a.id.cmp(&b.id)); // determinism
  let ids_to_stored_ids = snapshot
    .packages
    .iter()
    .enumerate()
    .map(|(i, pkg)| (&pkg.id, i as u32))
    .collect::<HashMap<_, _>>();

  let mut root_packages: Vec<_> = snapshot.root_packages.iter().collect();
  root_packages.sort();
  let mut bytes = Vec::new();

  bytes.extend_from_slice(&(snapshot.packages.len() as u32).to_le_bytes());
  for pkg in &snapshot.packages {
    append_string(&mut bytes, &pkg.id.as_serialized());
  }

  bytes.extend_from_slice(&(root_packages.len() as u32).to_le_bytes());
  for (req, id) in root_packages {
    append_string(&mut bytes, &req.to_string());
    let id = ids_to_stored_ids.get(&id).unwrap();
    bytes.extend_from_slice(&id.to_le_bytes());
  }

  for pkg in &snapshot.packages {
    let deps_len = pkg.dependencies.len() as u32;
    bytes.extend_from_slice(&deps_len.to_le_bytes());
    let mut deps: Vec<_> = pkg.dependencies.iter().collect();
    deps.sort();
    for (req, id) in deps {
      append_string(&mut bytes, req);
      let id = ids_to_stored_ids.get(&id).unwrap();
      bytes.extend_from_slice(&id.to_le_bytes());
    }
  }

  bytes
}

fn get_denort_path(deno_exe: PathBuf) -> Option<OsString> {
  let mut denort = deno_exe;
  denort.set_file_name(if cfg!(windows) {
    "denort.exe"
  } else {
    "denort"
  });
  denort.exists().then(|| denort.into_os_string())
}

fn get_dev_binary_path() -> Option<OsString> {
  env::var_os("DENORT_BIN").or_else(|| {
    env::current_exe().ok().and_then(|exec_path| {
      if exec_path
        .components()
        .any(|component| component == Component::Normal("target".as_ref()))
      {
        get_denort_path(exec_path)
      } else {
        None
      }
    })
  })
}

fn get_libdenort_path(deno_exe: PathBuf) -> Option<OsString> {
  let mut libdenort = deno_exe;
  if cfg!(target_os = "macos") {
    libdenort.set_file_name("libdenort.dylib");
  } else if cfg!(windows) {
    libdenort.set_file_name("denort.dll");
  } else {
    libdenort.set_file_name("libdenort.so");
  }
  libdenort.exists().then(|| libdenort.into_os_string())
}

fn get_dev_desktop_binary_path() -> Option<OsString> {
  env::var_os("DENORT_DESKTOP_BIN").or_else(|| {
    env::current_exe().ok().and_then(|exec_path| {
      if exec_path
        .components()
        .any(|component| component == Component::Normal("target".as_ref()))
      {
        // Prefer release libdenort (optimized) over debug.
        let target_dir = exec_path.parent().and_then(|p| p.parent());
        target_dir
          .and_then(|d| {
            get_libdenort_path(d.join("release").join("libdenort.dylib"))
          })
          .or_else(|| get_libdenort_path(exec_path.clone()))
      } else {
        None
      }
    })
  })
}

/// This function returns the environment variables specified
/// in the passed environment file.
fn get_file_env_vars(
  content: &str,
) -> Result<IndexMap<String, String>, deno_dotenv::ParseError> {
  let mut file_env_vars = IndexMap::new();
  for item in deno_dotenv::from_content_sanitized_iter_with_substitution(
    &CliSys::default(),
    content,
  )? {
    let Ok((key, val)) = item else {
      continue; // this failure will be warned about on load
    };
    file_env_vars.insert(key, val);
  }
  Ok(file_env_vars)
}

/// This function sets the subsystem field in the PE header to 2 (GUI subsystem)
/// For more information about the PE header: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format
fn set_windows_binary_to_gui(bin: &mut [u8]) -> Result<(), AnyError> {
  // Get the PE header offset located in an i32 found at offset 60
  // See: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#ms-dos-stub-image-only
  let start_pe = u32::from_le_bytes((bin[60..64]).try_into()?);

  // Get image type (PE32 or PE32+) indicates whether the binary is 32 or 64 bit
  // The used offset and size values can be found here:
  // https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#optional-header-image-only
  let start_32 = start_pe as usize + 28;
  let magic_32 =
    u16::from_le_bytes(bin[(start_32)..(start_32 + 2)].try_into()?);

  let start_64 = start_pe as usize + 24;
  let magic_64 =
    u16::from_le_bytes(bin[(start_64)..(start_64 + 2)].try_into()?);

  // Take the standard fields size for the current architecture (32 or 64 bit)
  // This is the ofset for the Windows-Specific fields
  let standard_fields_size = if magic_32 == 0x10b {
    28
  } else if magic_64 == 0x20b {
    24
  } else {
    bail!("Could not find a matching magic field in the PE header")
  };

  // Set the subsystem field (offset 68) to 2 (GUI subsystem)
  // For all possible options, see: https://learn.microsoft.com/en-us/windows/win32/debug/pe-format#optional-header-windows-specific-fields-image-only
  let subsystem_offset = 68;
  let subsystem_start =
    start_pe as usize + standard_fields_size + subsystem_offset;
  let subsystem: u16 = 2;
  bin[(subsystem_start)..(subsystem_start + 2)]
    .copy_from_slice(&subsystem.to_le_bytes());
  Ok(())
}

// Copyright 2018-2026 the Deno authors. MIT license.

//! @ref LLP 0019#parentsupervisor-transport-and-single-process-lifetime-cell [implements] — authorize the sealed edge from ModuleMap-owned identities at graph load and V8 instantiation

use std::cell::Cell;
use std::cell::RefCell;
use std::collections::HashMap;
use std::sync::Arc;

use deno_error::JsErrorBox;

use super::ModuleId;
use super::ModuleImportPhase;
use super::ModuleRequest;
use super::RequestedModuleType;
use crate::ModuleSpecifier;
use crate::v8;

/// Runtime-only authorization for one sealed static-import edge.
///
/// The policy binds exact source bytes and module names for a trusted main
/// module and an in-binary target module. The target may itself import one
/// exact dependency (typically a virtual native module). The target must be
/// registered as a `lazy_loaded_esm` source; it is never obtained from the
/// embedder's [`super::ModuleLoader`]. Both protected edges use one canonical,
/// single-line static import statement in their respective pinned sources.
///
/// Policy state is deliberately held outside `ModuleMapSnapshotData`: an
/// embedder must install a fresh policy on every runtime that uses the edge.
#[derive(Clone, Debug)]
pub struct SealedStaticImportPolicy {
  pub(crate) trusted_main_specifier: ModuleSpecifier,
  pub(crate) trusted_main_source: Arc<str>,
  pub(crate) target_specifier: ModuleSpecifier,
  pub(crate) target_source: Arc<str>,
  pub(crate) target_dependency: ModuleSpecifier,
}

impl SealedStaticImportPolicy {
  pub fn new(
    trusted_main_specifier: ModuleSpecifier,
    trusted_main_source: impl Into<Arc<str>>,
    target_specifier: ModuleSpecifier,
    target_source: impl Into<Arc<str>>,
    target_dependency: ModuleSpecifier,
  ) -> Result<Self, JsErrorBox> {
    if trusted_main_specifier == target_specifier
      || trusted_main_specifier == target_dependency
      || target_specifier == target_dependency
    {
      return Err(JsErrorBox::type_error(
        "Sealed static import policy requires distinct main, target, and dependency specifiers",
      ));
    }
    Ok(Self {
      trusted_main_specifier,
      trusted_main_source: trusted_main_source.into(),
      target_specifier,
      target_source: target_source.into(),
      target_dependency,
    })
  }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SealedModuleRole {
  Ordinary,
  TrustedMain,
  Target,
}

#[derive(Clone)]
struct ModuleIdentity {
  id: ModuleId,
  handle: v8::Global<v8::Module>,
}

pub(crate) struct SealedStaticImportState {
  policy: SealedStaticImportPolicy,
  trusted_main: RefCell<Option<ModuleIdentity>>,
  target: RefCell<Option<ModuleIdentity>>,
  target_dependency: RefCell<Option<ModuleIdentity>>,
  recursive_edge_consumed: Cell<bool>,
  main_instantiation_edge_consumed: Cell<bool>,
  target_instantiation_edge_consumed: Cell<bool>,
}

impl SealedStaticImportState {
  pub(crate) fn new(policy: SealedStaticImportPolicy) -> Self {
    Self {
      policy,
      trusted_main: RefCell::new(None),
      target: RefCell::new(None),
      target_dependency: RefCell::new(None),
      recursive_edge_consumed: Cell::new(false),
      main_instantiation_edge_consumed: Cell::new(false),
      target_instantiation_edge_consumed: Cell::new(false),
    }
  }

  fn refuse(reason: impl Into<String>) -> JsErrorBox {
    JsErrorBox::type_error(format!(
      "Sealed static import authorization refused: {}",
      reason.into()
    ))
  }

  pub(crate) fn target_specifier(&self) -> &str {
    self.policy.target_specifier.as_str()
  }

  pub(crate) fn target_dependency_specifier(&self) -> &str {
    self.policy.target_dependency.as_str()
  }

  pub(crate) fn validate_startup_snapshot_mappings(
    &self,
    contains_name: impl Fn(&str) -> bool,
    alias_chain_touches: impl Fn(&str) -> bool,
  ) -> Result<(), JsErrorBox> {
    if contains_name(self.policy.trusted_main_specifier.as_str())
      || alias_chain_touches(self.policy.trusted_main_specifier.as_str())
    {
      return Err(Self::refuse(
        "the startup snapshot already mapped the trusted main name",
      ));
    }
    if contains_name(self.policy.target_specifier.as_str())
      || alias_chain_touches(self.policy.target_specifier.as_str())
    {
      return Err(Self::refuse(
        "the startup snapshot already mapped the target name",
      ));
    }
    Ok(())
  }

  pub(crate) fn is_target_specifier(&self, specifier: &str) -> bool {
    specifier == self.policy.target_specifier.as_str()
  }

  pub(crate) fn reject_direct_target_request(
    &self,
    specifier: &str,
  ) -> Result<(), JsErrorBox> {
    if self.is_target_specifier(specifier) {
      return Err(Self::refuse(
        "the target was requested outside a ModuleMap-owned static edge",
      ));
    }
    Ok(())
  }

  pub(crate) fn classify_compilation(
    &self,
    main: bool,
    name: &str,
    source: &[u8],
    is_dynamic_import: bool,
  ) -> Result<SealedModuleRole, JsErrorBox> {
    if main {
      if is_dynamic_import {
        return Err(Self::refuse("the trusted main was dynamically loaded"));
      }
      if name != self.policy.trusted_main_specifier.as_str() {
        return Err(Self::refuse("the main module name did not match"));
      }
      if source != self.policy.trusted_main_source.as_bytes() {
        return Err(Self::refuse("the main module source did not match"));
      }
      if Self::canonical_static_import_count(
        source,
        self.policy.target_specifier.as_str(),
      ) != 1
      {
        return Err(Self::refuse(
          "the main source did not contain exactly one canonical target spelling",
        ));
      }
      if self.trusted_main.borrow().is_some() {
        return Err(Self::refuse("the trusted main was compiled twice"));
      }
      return Ok(SealedModuleRole::TrustedMain);
    }

    if name == self.policy.trusted_main_specifier.as_str() {
      return Err(Self::refuse(
        "a side module used the trusted main module name",
      ));
    }

    if name == self.policy.target_specifier.as_str() {
      if is_dynamic_import {
        return Err(Self::refuse("the target was dynamically loaded"));
      }
      if !self.recursive_edge_consumed.get() {
        return Err(Self::refuse(
          "the target was compiled outside the trusted recursive edge",
        ));
      }
      if source != self.policy.target_source.as_bytes() {
        return Err(Self::refuse("the target module source did not match"));
      }
      if Self::canonical_static_import_count(
        source,
        self.policy.target_dependency.as_str(),
      ) != 1
      {
        return Err(Self::refuse(
          "the target source did not contain exactly one canonical dependency spelling",
        ));
      }
      if self.target.borrow().is_some() {
        return Err(Self::refuse("the target module was compiled twice"));
      }
      return Ok(SealedModuleRole::Target);
    }

    Ok(SealedModuleRole::Ordinary)
  }

  /// Count deliberately narrow, single-line static-import statements. The
  /// exact source is already pinned, so rejecting multiline, escaped, or
  /// comment-bearing spellings is a fail-closed canonicalization rule rather
  /// than a general-purpose JavaScript parser.
  fn canonical_static_import_count(source: &[u8], specifier: &str) -> usize {
    let double_quoted = format!("\"{specifier}\"");
    let single_quoted = format!("'{specifier}'");
    let double_from = format!(" from {double_quoted}");
    let single_from = format!(" from {single_quoted}");
    source
      .split(|byte| *byte == b'\n')
      .filter(|line| {
        let line = trim_ascii(line);
        if line.windows(2).any(|window| window == b"//")
          || line.windows(2).any(|window| window == b"/*")
        {
          return false;
        }
        let Some(statement) = line.strip_suffix(b";") else {
          return false;
        };
        let Some(import_clause) =
          trim_ascii(statement).strip_prefix(b"import ")
        else {
          return false;
        };
        if import_clause.contains(&b';') {
          return false;
        }
        import_clause == double_quoted.as_bytes()
          || import_clause == single_quoted.as_bytes()
          || import_clause.ends_with(double_from.as_bytes())
          || import_clause.ends_with(single_from.as_bytes())
      })
      .count()
  }

  pub(crate) fn resolve_static_request(
    &self,
    role: SealedModuleRole,
    raw_specifier: &str,
    import_attributes: &HashMap<String, String>,
  ) -> Option<Result<ModuleSpecifier, JsErrorBox>> {
    if raw_specifier == self.policy.target_specifier.as_str() {
      return Some(if role != SealedModuleRole::TrustedMain {
        Err(Self::refuse(
          "the target was requested outside the trusted main",
        ))
      } else if !import_attributes.is_empty() {
        Err(Self::refuse("the trusted edge carried import attributes"))
      } else {
        Ok(self.policy.target_specifier.clone())
      });
    }

    if role == SealedModuleRole::Target {
      return Some(
        if raw_specifier != self.policy.target_dependency.as_str() {
          Err(Self::refuse(
            "the target requested an unexpected dependency",
          ))
        } else if !import_attributes.is_empty() {
          Err(Self::refuse("the target edge carried import attributes"))
        } else {
          Ok(self.policy.target_dependency.clone())
        },
      );
    }

    None
  }

  pub(crate) fn reject_loader_resolution(
    &self,
    raw_specifier: &str,
    resolved_specifier: &ModuleSpecifier,
  ) -> Result<(), JsErrorBox> {
    if resolved_specifier == &self.policy.target_specifier
      && raw_specifier != self.policy.target_specifier.as_str()
    {
      return Err(Self::refuse(
        "a loader resolved an alternate spelling to the target",
      ));
    }
    Ok(())
  }

  pub(crate) fn validate_loaded_specifiers(
    &self,
    specified: &str,
    found: Option<&str>,
  ) -> Result<(), JsErrorBox> {
    if specified == self.policy.target_specifier.as_str() {
      if self.recursive_edge_consumed.get()
        && self.target.borrow().is_none()
        && found.is_none()
      {
        return Ok(());
      }
      return Err(Self::refuse(
        "the target source did not arrive through the consumed recursive route",
      ));
    }
    if specified != self.policy.target_specifier.as_str()
      && found == Some(self.policy.target_specifier.as_str())
    {
      return Err(Self::refuse(
        "a loader substituted the target as a found module URL",
      ));
    }
    Ok(())
  }

  pub(crate) fn validate_requests(
    &self,
    role: SealedModuleRole,
    requests: &[ModuleRequest],
  ) -> Result<(), JsErrorBox> {
    match role {
      SealedModuleRole::Ordinary => Ok(()),
      SealedModuleRole::TrustedMain => {
        let matching: Vec<_> = requests
          .iter()
          .filter(|request| {
            request.reference.specifier == self.policy.target_specifier
          })
          .collect();
        if matching.len() != 1 {
          return Err(Self::refuse(
            "the trusted main did not contain exactly one target edge",
          ));
        }
        self.validate_exact_request(
          matching[0],
          self.policy.target_specifier.as_str(),
          "trusted main",
        )
      }
      SealedModuleRole::Target => {
        if requests.len() != 1 {
          return Err(Self::refuse(
            "the target did not contain exactly one dependency edge",
          ));
        }
        if requests[0].reference.specifier != self.policy.target_dependency {
          return Err(Self::refuse(
            "the target dependency did not resolve exactly",
          ));
        }
        self.validate_exact_request(
          &requests[0],
          self.policy.target_dependency.as_str(),
          "target",
        )
      }
    }
  }

  fn validate_exact_request(
    &self,
    request: &ModuleRequest,
    expected_raw_specifier: &str,
    edge_name: &str,
  ) -> Result<(), JsErrorBox> {
    if request.specifier_key.as_deref() != Some(expected_raw_specifier)
      || request.reference.requested_module_type != RequestedModuleType::None
      || request.phase != ModuleImportPhase::Evaluation
    {
      return Err(Self::refuse(format!(
        "the {edge_name} edge was not the exact evaluation import"
      )));
    }
    Ok(())
  }

  pub(crate) fn record_module(
    &self,
    role: SealedModuleRole,
    id: ModuleId,
    handle: v8::Global<v8::Module>,
    dependency: Option<(ModuleId, v8::Global<v8::Module>)>,
  ) -> Result<(), JsErrorBox> {
    let identity = ModuleIdentity { id, handle };
    match role {
      SealedModuleRole::Ordinary => {
        debug_assert!(dependency.is_none());
        Ok(())
      }
      SealedModuleRole::TrustedMain => {
        debug_assert!(dependency.is_none());
        let mut main = self.trusted_main.borrow_mut();
        if main.is_some() {
          return Err(Self::refuse("the trusted main identity was replaced"));
        }
        *main = Some(identity);
        Ok(())
      }
      SealedModuleRole::Target => {
        let Some((dependency_id, dependency_handle)) = dependency else {
          return Err(Self::refuse(
            "the target dependency identity was absent",
          ));
        };
        let mut target = self.target.borrow_mut();
        let mut target_dependency = self.target_dependency.borrow_mut();
        if target.is_some() || target_dependency.is_some() {
          return Err(Self::refuse("the target identity was replaced"));
        }
        *target = Some(identity);
        *target_dependency = Some(ModuleIdentity {
          id: dependency_id,
          handle: dependency_handle,
        });
        Ok(())
      }
    }
  }

  pub(crate) fn authorize_recursive_edge(
    &self,
    referrer_id: ModuleId,
    referrer_handle: &v8::Global<v8::Module>,
    request: &ModuleRequest,
    source: Option<&[u8]>,
  ) -> Result<(), JsErrorBox> {
    let trusted_main = self.trusted_main.borrow();
    let Some(trusted_main) = trusted_main.as_ref() else {
      return Err(Self::refuse("the trusted main identity was absent"));
    };
    if trusted_main.id != referrer_id || trusted_main.handle != *referrer_handle
    {
      return Err(Self::refuse(
        "the recursive edge referrer was not the trusted main handle",
      ));
    }
    self.validate_exact_request(
      request,
      self.policy.target_specifier.as_str(),
      "recursive",
    )?;
    if request.reference.specifier != self.policy.target_specifier {
      return Err(Self::refuse(
        "the recursive edge did not resolve to the target",
      ));
    }
    let Some(source) = source else {
      return Err(Self::refuse(
        "the target was absent from the lazy-loaded extension sources",
      ));
    };
    if source != self.policy.target_source.as_bytes() {
      return Err(Self::refuse("the lazy-loaded target source did not match"));
    }
    if self.recursive_edge_consumed.replace(true) {
      return Err(Self::refuse("the recursive target route was repeated"));
    }
    Ok(())
  }

  pub(crate) fn authorize_instantiation_edge(
    &self,
    referrer_id: Option<ModuleId>,
    referrer_handle: &v8::Global<v8::Module>,
    raw_specifier: &str,
    resolved_specifier: Option<&ModuleSpecifier>,
    import_attributes: &HashMap<String, String>,
  ) -> Option<Result<ModuleSpecifier, JsErrorBox>> {
    let main_matches =
      self.trusted_main.borrow().as_ref().is_some_and(|identity| {
        Some(identity.id) == referrer_id && identity.handle == *referrer_handle
      });
    let target_matches =
      self.target.borrow().as_ref().is_some_and(|identity| {
        Some(identity.id) == referrer_id && identity.handle == *referrer_handle
      });

    let names_target = raw_specifier == self.policy.target_specifier.as_str()
      || resolved_specifier == Some(&self.policy.target_specifier);

    if main_matches && names_target {
      if !self.recursive_edge_consumed.get()
        || self.target.borrow().is_none()
        || self.target_dependency.borrow().is_none()
      {
        return Some(Err(Self::refuse(
          "the target identity was not established by the recursive route",
        )));
      }
      return Some(self.authorize_exact_instantiation(
        raw_specifier,
        resolved_specifier,
        import_attributes,
        &self.policy.target_specifier,
        &self.main_instantiation_edge_consumed,
        "trusted main",
      ));
    }

    if target_matches {
      return Some(self.authorize_exact_instantiation(
        raw_specifier,
        resolved_specifier,
        import_attributes,
        &self.policy.target_dependency,
        &self.target_instantiation_edge_consumed,
        "target",
      ));
    }

    if names_target {
      return Some(Err(Self::refuse(
        "the instantiation referrer was not the trusted main handle",
      )));
    }

    None
  }

  pub(crate) fn validate_authorized_instantiation_identity(
    &self,
    resolved_specifier: &ModuleSpecifier,
    id: ModuleId,
    handle: &v8::Global<v8::Module>,
    is_alias: bool,
  ) -> Result<(), JsErrorBox> {
    if is_alias {
      return Err(Self::refuse(
        "an authorized instantiation name was replaced by an alias",
      ));
    }
    let expected = if resolved_specifier == &self.policy.target_specifier {
      self.target.borrow()
    } else if resolved_specifier == &self.policy.target_dependency {
      self.target_dependency.borrow()
    } else {
      return Err(Self::refuse(
        "the authorized instantiation name was unexpected",
      ));
    };
    let Some(expected) = expected.as_ref() else {
      return Err(Self::refuse(
        "the authorized instantiation identity was absent",
      ));
    };
    if expected.id != id || expected.handle != *handle {
      return Err(Self::refuse(
        "the authorized instantiation did not resolve to its recorded ModuleMap handle",
      ));
    }
    Ok(())
  }

  pub(crate) fn reject_normal_instantiation_identity(
    &self,
    id: ModuleId,
    handle: &v8::Global<v8::Module>,
  ) -> Result<(), JsErrorBox> {
    if self
      .target
      .borrow()
      .as_ref()
      .is_some_and(|target| target.id == id && target.handle == *handle)
    {
      return Err(Self::refuse(
        "a normal instantiation path resolved to the protected target handle",
      ));
    }
    Ok(())
  }

  fn authorize_exact_instantiation(
    &self,
    raw_specifier: &str,
    resolved_specifier: Option<&ModuleSpecifier>,
    import_attributes: &HashMap<String, String>,
    expected: &ModuleSpecifier,
    consumed: &Cell<bool>,
    edge_name: &str,
  ) -> Result<ModuleSpecifier, JsErrorBox> {
    if raw_specifier != expected.as_str()
      || resolved_specifier != Some(expected)
      || !import_attributes.is_empty()
    {
      return Err(Self::refuse(format!(
        "the {edge_name} instantiation edge was not exact"
      )));
    }
    if consumed.replace(true) {
      return Err(Self::refuse(format!(
        "the {edge_name} instantiation edge was repeated"
      )));
    }
    Ok(expected.clone())
  }
}

fn trim_ascii(mut value: &[u8]) -> &[u8] {
  while value.first().is_some_and(u8::is_ascii_whitespace) {
    value = &value[1..];
  }
  while value.last().is_some_and(u8::is_ascii_whitespace) {
    value = &value[..value.len() - 1];
  }
  value
}

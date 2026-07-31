// Copyright 2018-2026 the Deno authors. MIT license.

//! Caller-safe attribution for `eval` and the `Function` constructor.
//!
//! V8's code-generation callback runs before the dynamically generated script
//! has a script ID. We capture the live caller through already-registered,
//! unforgeable script IDs and append a callback-owned CSPRNG sourceURL nonce.
//! The first later engine frame carrying that nonce consumes it and binds that
//! frame's script ID to the stored caller locator. Unknown, stale, replayed,
//! cross-isolate, non-string, and no-caller paths never register and therefore
//! retain Oden's quarantine default.
//!
//! @ref llp/0001-adding-capability-security-to-deno.plan.md#attribution-of-evalnew-function-code [implements] — bind dynamic code at compile time without making unknown scripts transparent

use std::collections::HashMap;
use std::pin::pin;
use std::sync::LazyLock;
use std::sync::Mutex;

use deno_ast::MediaType;
use deno_ast::ParseParams;
use deno_ast::swc::ast::AssignTarget;
use deno_ast::swc::ast::Expr;
use deno_ast::swc::ast::Program;
use deno_ast::swc::ast::Prop;
use deno_ast::swc::ast::SimpleAssignTarget;
use deno_ast::swc::ast::Stmt;
use deno_ast::swc::common::Span;
use deno_ast::swc::common::Spanned;
use deno_ast::swc::common::SyntaxContext;
use deno_ast::swc::ecma_visit::Visit;
use deno_ast::swc::ecma_visit::VisitWith;
use indexmap::IndexMap;
use rand::RngCore;
use url::Url;

use crate::error::JsStackFrame;
use crate::oden_v8_abi::ModifyCodeGenerationFromStringsResult;

const EVAL_SOURCE_URL_PREFIX: &str = "oden-eval://";
const EVAL_CONTEXT_PREFIX: &str = "oden-eval-context:";
const COMPARTMENT_HELPER: &str = "__oden_compartment_globals__";
const MAX_PENDING_EVALS_PER_ISOLATE: usize = 4096;
// Context embedder slots 1/2 belong to ContextState/ModuleMap, while node:vm
// uses 1/2/3 plus its own tag in slot 4. Slot 5 is Oden's unforgeable realm
// tag. At the
// first observed operation V8's per-frame function context, rather than the
// op callback's current context, prevents a nonce observed in one realm from
// being replayed by eval or node:vm code in another context of the isolate.
const ODEN_EVAL_CONTEXT_SLOT: i32 = 5;
// Trusted runtime bootstrap sets this slot only after installing the
// non-configurable helper. A user-created property with the same public name
// therefore cannot opt an audit/non-compartment context into source rewriting.
const ODEN_EVAL_ENDOWMENT_SLOT: i32 = 6;

const ODEN_DYNAMIC_GLOBALS: &[&str] = &[
  "BroadcastChannel",
  "Deno",
  "EventSource",
  "WebSocket",
  "Worker",
  "alert",
  "caches",
  "confirm",
  "fetch",
  "global",
  "globalThis",
  "localStorage",
  "navigator",
  "process",
  "prompt",
  "self",
  "sessionStorage",
];

#[derive(Debug)]
struct SourceEdit {
  start: usize,
  end: usize,
  replacement: String,
}

struct DynamicEndowmentEdits<'a> {
  unresolved: SyntaxContext,
  alias_name: &'a str,
  record_name: &'a str,
  edits: Vec<SourceEdit>,
  shadows_injected_name: bool,
  contains_with: bool,
  unsupported_assignment_pattern: bool,
}

impl DynamicEndowmentEdits<'_> {
  fn is_rewritten_global(&self, ident: &deno_ast::swc::ast::Ident) -> bool {
    ident.ctxt == self.unresolved
      && ODEN_DYNAMIC_GLOBALS.contains(&ident.sym.as_ref())
  }

  fn note_injected_name(&mut self, ident: &deno_ast::swc::ast::Ident) {
    if ident.sym == self.alias_name || ident.sym == self.record_name {
      self.shadows_injected_name = true;
    }
  }

  fn replace_ident(&mut self, ident: &deno_ast::swc::ast::Ident) {
    if !self.is_rewritten_global(ident) {
      return;
    }
    if let Some((start, end)) = byte_range(ident.span) {
      self.edits.push(SourceEdit {
        start,
        end,
        replacement: format!("{}.{}", self.record_name, ident.sym),
      });
    }
  }

  fn pattern_has_rewritten_global(
    &self,
    pattern: &deno_ast::swc::ast::Pat,
  ) -> bool {
    use deno_ast::swc::ast::ObjectPatProp;
    use deno_ast::swc::ast::Pat;
    match pattern {
      Pat::Ident(binding) => self.is_rewritten_global(&binding.id),
      Pat::Array(array) => array
        .elems
        .iter()
        .flatten()
        .any(|pattern| self.pattern_has_rewritten_global(pattern)),
      Pat::Rest(rest) => self.pattern_has_rewritten_global(&rest.arg),
      Pat::Object(object) => {
        object.props.iter().any(|property| match property {
          ObjectPatProp::KeyValue(property) => {
            self.pattern_has_rewritten_global(&property.value)
          }
          ObjectPatProp::Assign(property) => {
            self.is_rewritten_global(&property.key.id)
          }
          ObjectPatProp::Rest(rest) => {
            self.pattern_has_rewritten_global(&rest.arg)
          }
        })
      }
      Pat::Assign(assign) => self.pattern_has_rewritten_global(&assign.left),
      Pat::Expr(_) | Pat::Invalid(_) => false,
    }
  }

  fn assignment_target_pattern_has_rewritten_global(
    &self,
    pattern: &deno_ast::swc::ast::AssignTargetPat,
  ) -> bool {
    use deno_ast::swc::ast::AssignTargetPat;
    match pattern {
      AssignTargetPat::Array(array) => array
        .elems
        .iter()
        .flatten()
        .any(|pattern| self.pattern_has_rewritten_global(pattern)),
      AssignTargetPat::Object(object) => object.props.iter().any(|property| {
        use deno_ast::swc::ast::ObjectPatProp;
        match property {
          ObjectPatProp::KeyValue(property) => {
            self.pattern_has_rewritten_global(&property.value)
          }
          ObjectPatProp::Assign(property) => {
            self.is_rewritten_global(&property.key.id)
          }
          ObjectPatProp::Rest(rest) => {
            self.pattern_has_rewritten_global(&rest.arg)
          }
        }
      }),
      AssignTargetPat::Invalid(_) => false,
    }
  }

  fn rewrite_for_head(&mut self, head: &deno_ast::swc::ast::ForHead) {
    use deno_ast::swc::ast::ForHead;
    use deno_ast::swc::ast::Pat;
    let ForHead::Pat(pattern) = head else {
      return;
    };
    if let Pat::Ident(binding) = &**pattern {
      self.replace_ident(&binding.id);
    } else if self.pattern_has_rewritten_global(pattern) {
      self.unsupported_assignment_pattern = true;
    }
  }
}

impl Visit for DynamicEndowmentEdits<'_> {
  fn visit_ident(&mut self, ident: &deno_ast::swc::ast::Ident) {
    self.note_injected_name(ident);
  }

  fn visit_expr(&mut self, expr: &Expr) {
    if let Expr::Ident(ident) = expr {
      self.note_injected_name(ident);
      self.replace_ident(ident);
      return;
    }
    expr.visit_children_with(self);
  }

  fn visit_prop(&mut self, prop: &Prop) {
    if let Prop::Shorthand(ident) = prop {
      self.note_injected_name(ident);
      if self.is_rewritten_global(ident)
        && let Some((start, end)) = byte_range(ident.span)
      {
        self.edits.push(SourceEdit {
          start,
          end,
          replacement: format!(
            "{}: {}.{}",
            ident.sym, self.record_name, ident.sym
          ),
        });
      }
      return;
    }
    prop.visit_children_with(self);
  }

  fn visit_assign_expr(&mut self, assign: &deno_ast::swc::ast::AssignExpr) {
    assign.visit_children_with(self);
    match &assign.left {
      AssignTarget::Simple(SimpleAssignTarget::Ident(ident)) => {
        self.note_injected_name(&ident.id);
        self.replace_ident(&ident.id);
      }
      AssignTarget::Pat(pattern)
        if self.assignment_target_pattern_has_rewritten_global(pattern) =>
      {
        self.unsupported_assignment_pattern = true;
      }
      _ => {}
    }
  }

  fn visit_for_in_stmt(&mut self, statement: &deno_ast::swc::ast::ForInStmt) {
    statement.visit_children_with(self);
    self.rewrite_for_head(&statement.left);
  }

  fn visit_for_of_stmt(&mut self, statement: &deno_ast::swc::ast::ForOfStmt) {
    statement.visit_children_with(self);
    self.rewrite_for_head(&statement.left);
  }

  fn visit_with_stmt(&mut self, _with: &deno_ast::swc::ast::WithStmt) {
    // An outer `with` Proxy could intercept the callback-owned random binding.
    // Dynamic code is forced strict below, so rejecting this construct is both
    // fail-closed and aligned with the emitted program V8 will validate.
    self.contains_with = true;
  }
}

enum DynamicRewrite {
  Rewritten(String),
  ParseError,
  Refused,
}

fn byte_range(span: Span) -> Option<(usize, usize)> {
  let start = usize::try_from(span.lo.0.checked_sub(1)?).ok()?;
  let end = usize::try_from(span.hi.0.checked_sub(1)?).ok()?;
  (start <= end).then_some((start, end))
}

fn function_constructor_body_start(program: &Program) -> Option<usize> {
  let Program::Script(script) = program else {
    return None;
  };
  let [Stmt::Expr(statement)] = script.body.as_slice() else {
    return None;
  };
  let mut expr = &*statement.expr;
  while let Expr::Paren(paren) = expr {
    expr = &paren.expr;
  }
  let Expr::Fn(function) = expr else {
    return None;
  };
  let body = function.function.body.as_ref()?;
  let (start, _) = byte_range(body.span())?;
  Some(start + 1)
}

fn apply_source_edits(
  source: &str,
  mut edits: Vec<SourceEdit>,
  insertion: usize,
  prologue: &str,
) -> Option<String> {
  edits.sort_by_key(|edit| (edit.start, edit.end));
  for pair in edits.windows(2) {
    if pair[0].end > pair[1].start {
      return None;
    }
  }
  if insertion > source.len() || !source.is_char_boundary(insertion) {
    return None;
  }
  let extra = edits.iter().fold(prologue.len(), |total, edit| {
    total.saturating_add(
      edit.replacement.len().saturating_sub(edit.end - edit.start),
    )
  });
  let mut rewritten = String::with_capacity(source.len().saturating_add(extra));
  let mut cursor = 0;
  let mut inserted = false;
  for edit in edits {
    if !inserted && insertion <= edit.start {
      rewritten.push_str(&source[cursor..insertion]);
      rewritten.push_str(prologue);
      cursor = insertion;
      inserted = true;
    }
    if edit.start < cursor
      || edit.end > source.len()
      || !source.is_char_boundary(edit.start)
      || !source.is_char_boundary(edit.end)
    {
      return None;
    }
    rewritten.push_str(&source[cursor..edit.start]);
    rewritten.push_str(&edit.replacement);
    cursor = edit.end;
  }
  if !inserted {
    rewritten.push_str(&source[cursor..insertion]);
    rewritten.push_str(prologue);
    cursor = insertion;
  }
  rewritten.push_str(&source[cursor..]);
  Some(rewritten)
}

/// Parse with the same SWC scope analysis used by the module transform, then
/// edit only parser-identified unresolved authority-bearing identifiers. The
/// original Function-constructor parameter prefix stays byte-for-byte intact,
/// preserving V8's native parameter/body injection boundary.
// @ref LLP 0014#closing-the-dynamic-channels [implements]
fn rewrite_dynamic_source(source: &str, alias_name: &str) -> DynamicRewrite {
  let Ok(specifier) = Url::parse("oden-dynamic://source.js") else {
    return DynamicRewrite::Refused;
  };
  let parsed = match deno_ast::parse_script(ParseParams {
    specifier,
    text: source.into(),
    media_type: MediaType::JavaScript,
    capture_tokens: false,
    scope_analysis: true,
    maybe_syntax: None,
  }) {
    Ok(parsed) => parsed,
    Err(_) => return DynamicRewrite::ParseError,
  };
  let unresolved = parsed.unresolved_context();
  let program = parsed.program();
  let function_body_start = function_constructor_body_start(&program);
  let insertion = function_body_start.unwrap_or(0);
  let record_name = format!("{alias_name}_record");
  let mut visitor = DynamicEndowmentEdits {
    unresolved,
    alias_name,
    record_name: &record_name,
    edits: Vec::new(),
    shadows_injected_name: false,
    contains_with: false,
    unsupported_assignment_pattern: false,
  };
  program.visit_with(&mut visitor);
  if visitor.shadows_injected_name
    || visitor.contains_with
    || visitor.unsupported_assignment_pattern
  {
    return DynamicRewrite::Refused;
  }
  if function_body_start.is_some()
    && visitor.edits.iter().any(|edit| edit.start < insertion)
  {
    // Rewriting a default parameter would move V8's already-computed
    // `parameters_end_pos` and weaken its native injection validation.
    return DynamicRewrite::Refused;
  }
  // Keep the prologue on the existing first/body line. Dynamic sources have
  // no source-map channel here, so preserving line count keeps later stack
  // frame line numbers stable (only the first-line column is displaced).
  let prologue = format!("\"use strict\";const {record_name}={alias_name}();");
  apply_source_edits(source, visitor.edits, insertion, &prologue)
    .map(DynamicRewrite::Rewritten)
    .unwrap_or(DynamicRewrite::Refused)
}

#[derive(Debug)]
struct PendingEval {
  context_id: String,
  caller_locator: String,
}

#[derive(Default)]
struct PendingEvalRegistry {
  by_isolate: HashMap<usize, IndexMap<String, PendingEval>>,
}

impl PendingEvalRegistry {
  fn insert(
    &mut self,
    isolate_id: usize,
    source_url: String,
    pending: PendingEval,
  ) {
    let entries = self.by_isolate.entry(isolate_id).or_default();
    // Syntax errors and never-called returned functions can leave an identity
    // pending. IndexMap is the single authoritative bounded structure: both
    // lookup and ordering metadata disappear together on every removal.
    // swap-removal keeps consumption and eviction bounded O(1); eviction is
    // deliberately fail-closed because the forgotten script quarantines.
    if entries.contains_key(&source_url) {
      entries.swap_remove(&source_url);
    }
    while entries.len() >= MAX_PENDING_EVALS_PER_ISOLATE {
      entries.swap_remove_index(0);
    }
    entries.insert(source_url, pending);
  }

  fn contains(&self, source_url: &str, isolate_id: usize) -> bool {
    self
      .by_isolate
      .get(&isolate_id)
      .is_some_and(|entries| entries.contains_key(source_url))
  }

  fn remove_for_isolate(
    &mut self,
    source_url: &str,
    isolate_id: usize,
  ) -> Option<PendingEval> {
    let (removed, empty) = {
      let entries = self.by_isolate.get_mut(&isolate_id)?;
      let removed = entries.swap_remove(source_url);
      (removed, entries.is_empty())
    };
    if empty {
      self.by_isolate.remove(&isolate_id);
    }
    removed
  }

  fn remove_for_context(
    &mut self,
    source_url: &str,
    isolate_id: usize,
    context_id: &str,
  ) -> Option<PendingEval> {
    let (removed, empty) = {
      let entries = self.by_isolate.get_mut(&isolate_id)?;
      let removed = entries
        .get(source_url)
        .is_some_and(|pending| pending.context_id == context_id)
        .then(|| entries.swap_remove(source_url))
        .flatten();
      (removed, entries.is_empty())
    };
    if empty {
      self.by_isolate.remove(&isolate_id);
    }
    removed
  }

  fn clear_isolate(&mut self, isolate_id: usize) {
    self.by_isolate.remove(&isolate_id);
  }

  #[cfg(test)]
  fn len_for_isolate(&self, isolate_id: usize) -> usize {
    self.by_isolate.get(&isolate_id).map_or(0, IndexMap::len)
  }
}

static PENDING_EVALS: LazyLock<Mutex<PendingEvalRegistry>> =
  LazyLock::new(|| Mutex::new(PendingEvalRegistry::default()));

fn registry() -> std::sync::MutexGuard<'static, PendingEvalRegistry> {
  // A poisoned attribution table must not turn unknown scripts into caller
  // authority. Recovering the owned data preserves the same one-shot rules.
  PENDING_EVALS
    .lock()
    .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn is_runtime_locator(locator: &str) -> bool {
  locator.starts_with("ext:")
    || locator.starts_with("node:")
    || locator.starts_with("deno:")
    || locator.starts_with("[ext:")
}

fn live_caller_locator(frames: &[JsStackFrame]) -> Option<String> {
  for frame in frames {
    if frame.is_native {
      continue;
    }
    let (Some(isolate_id), Some(script_id)) =
      (frame.isolate_id, frame.script_id)
    else {
      // A JavaScript frame with no engine identity is an unknown user-code
      // barrier. Never make it transparent to a registered frame below it.
      return None;
    };
    let Some(locator) =
      crate::error::oden_script_locator(isolate_id, script_id)
    else {
      // In particular, node:vm -> eval must not inherit the app/package below
      // the unregistered vm frame. Unknown means quarantine, not "keep walking."
      return None;
    };
    if !is_runtime_locator(&locator) {
      return Some(locator);
    }
  }
  None
}

fn random_hex_identity(prefix: &str) -> Option<String> {
  let mut bytes = [0_u8; 16];
  rand::rngs::OsRng.try_fill_bytes(&mut bytes).ok()?;
  const HEX: &[u8; 16] = b"0123456789abcdef";
  let mut identity = String::with_capacity(prefix.len() + 32);
  identity.push_str(prefix);
  for byte in bytes {
    identity.push(HEX[(byte >> 4) as usize] as char);
    identity.push(HEX[(byte & 0x0f) as usize] as char);
  }
  Some(identity)
}

fn context_id<'s>(
  scope: &mut v8::PinScope<'s, '_>,
  context: v8::Local<'s, v8::Context>,
) -> Option<String> {
  let value =
    materialized_context_embedder_data(scope, context, ODEN_EVAL_CONTEXT_SLOT)?;
  let value = v8::Local::<v8::String>::try_from(value).ok()?;
  Some(value.to_rust_string_lossy(scope))
}

/// Read one logical rusty_v8 Context embedder slot only after proving its
/// physical field exists.
///
/// @ref LLP 0019#workers-vm-wasi-and-native-code [implements] -- The dynamic
/// compilation callback also receives secondary and node:vm contexts. Their
/// missing Oden metadata is a fail-closed/attribution-only state, never license
/// for an unchecked V8 embedder-field read.
fn materialized_context_embedder_data<'s>(
  scope: &mut v8::PinScope<'s, '_, ()>,
  context: v8::Local<'s, v8::Context>,
  logical_slot: i32,
) -> Option<v8::Local<'s, v8::Value>> {
  if !crate::oden_v8_abi::context_embedder_data_slot_is_materialized(
    context,
    logical_slot,
  ) {
    return None;
  }
  context.get_embedder_data(scope, logical_slot)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DynamicEndowmentState {
  Unmanaged,
  AttributionOnly,
  Enabled,
}

fn dynamic_endowment_state<'s>(
  scope: &mut v8::PinScope<'s, '_>,
  context: v8::Local<'s, v8::Context>,
) -> DynamicEndowmentState {
  let Some(value) = materialized_context_embedder_data(
    scope,
    context,
    ODEN_EVAL_ENDOWMENT_SLOT,
  ) else {
    return DynamicEndowmentState::Unmanaged;
  };
  if value.is_true() {
    DynamicEndowmentState::Enabled
  } else if value.is_false() {
    DynamicEndowmentState::AttributionOnly
  } else {
    DynamicEndowmentState::Unmanaged
  }
}

/// Attribution-only contexts may preserve the original source when metadata
/// setup fails. Once trusted bootstrap arms the endowment marker, every such
/// failure must deny instead: allowing the original string would expose the
/// realm's raw globals.
fn allow_unmodified_source(compartment_active: bool) -> bool {
  !compartment_active
}

pub(crate) fn enable_dynamic_endowments(scope: &mut v8::PinScope<'_, '_>) {
  let context = scope.get_current_context();
  if dynamic_endowment_state(scope, context) == DynamicEndowmentState::Unmanaged
  {
    // Contexts not created by JsRuntime (notably node:vm) do not carry Oden
    // attribution metadata. Materialize the identity slot before marking the
    // context active so its inevitable missing identity is a bounded,
    // fail-closed state.
    let missing_identity: v8::Local<v8::Value> = v8::undefined(scope).into();
    context.set_embedder_data(ODEN_EVAL_CONTEXT_SLOT, missing_identity);
  }
  // Setting the marker must never leave a foreign context on V8's
  // unconditional fast path: that path bypasses this isolate's callback and
  // therefore bypasses both attribution and compartment rewriting.
  context.set_allow_generation_from_strings(false);
  let enabled = v8::Boolean::new(scope, true);
  context.set_embedder_data(ODEN_EVAL_ENDOWMENT_SLOT, enabled.into());
}

fn context_alias_name(context_id: &str) -> Option<String> {
  let identity = context_id.strip_prefix(EVAL_CONTEXT_PREFIX)?;
  if identity.len() != 32
    || !identity.bytes().all(|byte| byte.is_ascii_hexdigit())
  {
    return None;
  }
  Some(format!("__oden_dynamic_endow_{identity}"))
}

enum CompartmentAlias {
  Off,
  Ready(String),
  Refused,
}

fn prepare_compartment_alias(
  scope: &mut v8::PinScope,
  context: v8::Local<v8::Context>,
  context_id: &str,
  compartment_active: bool,
) -> CompartmentAlias {
  if !compartment_active {
    return CompartmentAlias::Off;
  }
  let Some(alias_name) = context_alias_name(context_id) else {
    return CompartmentAlias::Refused;
  };
  let Some(helper_key) = v8::String::new(scope, COMPARTMENT_HELPER) else {
    return CompartmentAlias::Refused;
  };
  let global = context.global(scope);
  let Some(helper) = global.get(scope, helper_key.into()) else {
    return CompartmentAlias::Refused;
  };
  if !helper.is_function() {
    return CompartmentAlias::Refused;
  }
  let Some(alias_key) = v8::String::new(scope, &alias_name) else {
    return CompartmentAlias::Refused;
  };
  // Define directly instead of reading first: an inherited accessor for the
  // unpredictable name must not run user code from inside V8's compile hook.
  // Re-defining the same non-configurable data property is idempotent.
  if global.define_own_property(
    scope,
    alias_key.into(),
    helper,
    v8::PropertyAttribute::READ_ONLY
      | v8::PropertyAttribute::DONT_ENUM
      | v8::PropertyAttribute::DONT_DELETE,
  ) != Some(true)
  {
    return CompartmentAlias::Refused;
  }
  CompartmentAlias::Ready(alias_name)
}

fn remember_pending_eval(
  isolate_id: usize,
  context_id: String,
  caller_locator: String,
) -> Option<String> {
  // A collision is cryptographically negligible, but never overwrite an
  // unconsumed identity. Four attempts keep RNG failure/collision fail-closed.
  for _ in 0..4 {
    let source_url = random_hex_identity(EVAL_SOURCE_URL_PREFIX)?;
    let mut pending = registry();
    if pending.contains(&source_url, isolate_id) {
      continue;
    }
    pending.insert(
      isolate_id,
      source_url.clone(),
      PendingEval {
        context_id,
        caller_locator,
      },
    );
    return Some(source_url);
  }
  None
}

fn forget_pending_eval(source_url: &str, isolate_id: usize) {
  registry().remove_for_isolate(source_url, isolate_id);
}

pub(crate) fn clear_isolate(isolate_id: usize) {
  registry().clear_isolate(isolate_id);
}

fn frame_has_pending_identity(
  pending: &PendingEvalRegistry,
  frame: &JsStackFrame,
  isolate_id: usize,
) -> bool {
  frame.is_eval
    && frame.isolate_id == Some(isolate_id)
    && frame.file_name.as_deref().is_some_and(|source_url| {
      source_url.starts_with(EVAL_SOURCE_URL_PREFIX)
        && pending.contains(source_url, isolate_id)
    })
}

/// Consume callback-owned identities and register their first observed script
/// IDs. A displayed sourceURL alone never grants identity: it must match an
/// unconsumed CSPRNG entry for the same isolate.
pub(crate) fn bind_pending_frames(
  scope: &mut v8::PinScope,
  frames: &[JsStackFrame],
) {
  // A never-called Function must not arm a process-wide tax. Inspect the
  // already-captured cheap frames first and do not even acquire the registry
  // mutex unless this isolate is executing an eval frame with Oden's nonce.
  if !frames.iter().any(|frame| {
    frame.is_eval
      && frame.file_name.as_deref().is_some_and(|source_url| {
        source_url.starts_with(EVAL_SOURCE_URL_PREFIX)
      })
  }) {
    return;
  }
  // SAFETY: `scope` is active for the stack walk below; the pointer is passed
  // back to V8 immediately and is not retained as a dereferenceable handle.
  let isolate = unsafe { scope.as_raw_isolate_ptr() };
  let isolate_id = crate::error::oden_isolate_key(isolate);
  {
    let pending = registry();
    if !frames
      .iter()
      .any(|frame| frame_has_pending_identity(&pending, frame, isolate_id))
    {
      return;
    }
  }
  // V8's experimental per-function context walk and its allocation happen
  // only after an exact pending nonce match in this isolate.
  let script_contexts =
    crate::oden_v8_abi::current_script_data(scope, isolate, frames.len())
      .into_iter()
      .filter_map(|data| {
        let script_id = usize::try_from(data.function.script_id()).ok()?;
        let context_id = context_id(scope, data.context)?;
        Some((script_id, context_id))
      })
      .collect::<Vec<_>>();
  let mut bindings = Vec::new();
  {
    let mut pending = registry();
    for frame in frames {
      let (Some(isolate_id), Some(script_id), Some(source_url)) = (
        frame.isolate_id,
        frame.script_id,
        frame.file_name.as_deref(),
      ) else {
        continue;
      };
      // A visible nonce can be copied into a node:vm filename before the
      // original eval executes. Context equality plus V8's eval-origin bit
      // prevents that display-only replay from consuming the pending identity.
      if !frame.is_eval {
        continue;
      }
      if crate::error::oden_script_locator(isolate_id, script_id).is_some() {
        continue;
      }
      let Some(frame_context_id) =
        script_contexts
          .iter()
          .find_map(|(candidate_id, context_id)| {
            (*candidate_id == script_id).then_some(context_id.as_str())
          })
      else {
        continue;
      };
      if let Some(entry) =
        pending.remove_for_context(source_url, isolate_id, frame_context_id)
      {
        bindings.push((isolate_id, script_id, entry.caller_locator));
      }
    }
  }
  for (isolate_id, script_id, locator) in bindings {
    crate::error::oden_register_dynamic_script_locator_by_key(
      isolate_id, script_id, &locator,
    );
  }
}

fn modify_code_generation<'s>(
  context: v8::Local<'s, v8::Context>,
  source: v8::Local<'s, v8::Value>,
) -> ModifyCodeGenerationFromStringsResult<'s> {
  let scope = pin!(unsafe { v8::CallbackScope::new(context) });
  let scope = &mut scope.init();
  let endowment_state = dynamic_endowment_state(scope, context);
  if endowment_state == DynamicEndowmentState::Unmanaged {
    // V8 calls this callback only after the context disabled its unconditional
    // string-codegen fast path. An unmanaged/malformed context must not turn
    // that denial back into permission (notably node:vm
    // codeGeneration.strings:false).
    return ModifyCodeGenerationFromStringsResult {
      codegen_allowed: false,
      modified_source: None,
    };
  }
  let compartment_active = endowment_state == DynamicEndowmentState::Enabled;
  let Some(context_id) = context_id(scope, context) else {
    return ModifyCodeGenerationFromStringsResult {
      codegen_allowed: allow_unmodified_source(compartment_active),
      modified_source: None,
    };
  };

  // Bind an outer eval before resolving it as the caller of a nested eval.
  // SAFETY: the callback scope is active; the pointer is used immediately for
  // stack capture and as an opaque isolate-scoped registry key.
  let isolate = unsafe { scope.as_raw_isolate_ptr() };
  let frames = crate::error::capture_op_stack_frames(scope, isolate);
  let Some(caller_locator) = live_caller_locator(&frames) else {
    return ModifyCodeGenerationFromStringsResult {
      codegen_allowed: allow_unmodified_source(compartment_active),
      modified_source: None,
    };
  };
  let Ok(source) = v8::Local::<v8::String>::try_from(source) else {
    // Direct eval of a non-string returns the value unchanged. Do not coerce or
    // tag it; preserving JS semantics is more important than attribution of a
    // script that V8 will not create.
    return ModifyCodeGenerationFromStringsResult {
      codegen_allowed: true,
      modified_source: None,
    };
  };

  let source = match prepare_compartment_alias(
    scope,
    context,
    &context_id,
    compartment_active,
  ) {
    CompartmentAlias::Off => source,
    CompartmentAlias::Ready(alias_name) => {
      let rust_source = source.to_rust_string_lossy(scope);
      let Some(roundtrip_source) = v8::String::new(scope, &rust_source) else {
        return ModifyCodeGenerationFromStringsResult {
          codegen_allowed: false,
          modified_source: None,
        };
      };
      if !roundtrip_source.strict_equals(source.into()) {
        // SWC consumes UTF-8 while V8 strings may contain lone UTF-16
        // surrogates. Never silently change such source through lossy UTF-8.
        return ModifyCodeGenerationFromStringsResult {
          codegen_allowed: false,
          modified_source: None,
        };
      }
      match rewrite_dynamic_source(&rust_source, &alias_name) {
        DynamicRewrite::Rewritten(rewritten) => {
          let Some(rewritten) = v8::String::new(scope, &rewritten) else {
            return ModifyCodeGenerationFromStringsResult {
              codegen_allowed: false,
              modified_source: None,
            };
          };
          rewritten
        }
        DynamicRewrite::ParseError | DynamicRewrite::Refused => {
          return ModifyCodeGenerationFromStringsResult {
            codegen_allowed: false,
            modified_source: None,
          };
        }
      }
    }
    CompartmentAlias::Refused => {
      return ModifyCodeGenerationFromStringsResult {
        codegen_allowed: false,
        modified_source: None,
      };
    }
  };

  let isolate_id = crate::error::oden_isolate_key(isolate);
  let Some(source_url) =
    remember_pending_eval(isolate_id, context_id, caller_locator)
  else {
    return ModifyCodeGenerationFromStringsResult {
      codegen_allowed: allow_unmodified_source(compartment_active),
      modified_source: None,
    };
  };
  let suffix = format!("\n//# sourceURL={source_url}\n");
  let modified_source = v8::String::new(scope, &suffix)
    .and_then(|suffix| v8::String::concat(scope, source, suffix));
  if modified_source.is_none() {
    forget_pending_eval(&source_url, isolate_id);
  }
  ModifyCodeGenerationFromStringsResult {
    codegen_allowed: modified_source.is_some()
      || allow_unmodified_source(compartment_active),
    modified_source,
  }
}

#[allow(improper_ctypes_definitions)]
unsafe extern "C" fn code_generation_callback<'s>(
  context: v8::Local<'s, v8::Context>,
  source: v8::Local<'s, v8::Value>,
  _is_code_like: bool,
) -> ModifyCodeGenerationFromStringsResult<'s> {
  // No Rust unwind may cross V8's C++ callback boundary. Denial is the only
  // safe fallback: allowing the original string would bypass compartment
  // rewriting when the panic happened on an armed endowment context.
  std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
    modify_code_generation(context, source)
  }))
  .unwrap_or(ModifyCodeGenerationFromStringsResult {
    codegen_allowed: false,
    modified_source: None,
  })
}

pub(crate) fn maybe_install_callback(isolate: &mut v8::Isolate) {
  if !crate::error::oden_capsec_armed() {
    return;
  }
  unsafe {
    crate::oden_v8_abi::set_modify_code_generation_from_strings_callback(
      isolate,
      code_generation_callback,
    );
  }
}

pub(crate) fn maybe_enable_for_context(
  scope: &mut v8::PinScope<'_, '_, ()>,
  context: v8::Local<v8::Context>,
) {
  if crate::error::oden_capsec_armed() {
    // Disable V8's unconditional fast path before allocating the context
    // identity. If CSPRNG or V8 string allocation fails, a context that is
    // subsequently marked for dynamic endowments must still reach the callback
    // and fail closed on its missing identity. Marker-off contexts continue to
    // allow their original source, preserving the attribution-only behavior.
    initialize_context_attribution(scope, context, || {
      random_hex_identity(EVAL_CONTEXT_PREFIX)
    });
  }
}

fn initialize_context_attribution(
  scope: &mut v8::PinScope<'_, '_, ()>,
  context: v8::Local<v8::Context>,
  identity: impl FnOnce() -> Option<String>,
) {
  // Materialize both exact logical slots before disabling V8's unconditional
  // fast path. rusty_v8's field-count growth initializes intervening storage
  // but its get_embedder_data contract still requires that the requested slot
  // itself was set.
  let missing_identity: v8::Local<v8::Value> = v8::undefined(scope).into();
  context.set_embedder_data(ODEN_EVAL_CONTEXT_SLOT, missing_identity);
  let disabled = v8::Boolean::new(scope, false);
  context.set_embedder_data(ODEN_EVAL_ENDOWMENT_SLOT, disabled.into());
  context.set_allow_generation_from_strings(false);

  if let Some(context_id) = identity()
    && let Some(value) = v8::String::new(scope, &context_id)
  {
    context.set_embedder_data(ODEN_EVAL_CONTEXT_SLOT, value.into());
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  const TEST_ALIAS: &str =
    "__oden_dynamic_endow_0123456789abcdef0123456789abcdef";

  fn rewritten(source: &str) -> String {
    let DynamicRewrite::Rewritten(source) =
      rewrite_dynamic_source(source, TEST_ALIAS)
    else {
      panic!("source was not rewritten");
    };
    source
  }

  fn pending_eval(context_id: &str) -> PendingEval {
    PendingEval {
      context_id: context_id.to_string(),
      caller_locator: "file:///root/app.js".to_string(),
    }
  }

  fn frame(isolate_id: usize, file_name: &str, is_eval: bool) -> JsStackFrame {
    JsStackFrame {
      isolate_id: Some(isolate_id),
      script_id: Some(1),
      type_name: None,
      function_name: None,
      method_name: None,
      file_name: Some(file_name.to_string()),
      line_number: Some(1),
      column_number: Some(1),
      eval_origin: None,
      is_top_level: Some(true),
      is_eval,
      is_native: false,
      is_constructor: false,
      is_async: false,
      is_promise_all: false,
      is_wasm: false,
      promise_index: None,
    }
  }

  fn install_actual_codegen_callback(runtime: &mut crate::JsRuntime) {
    unsafe {
      crate::oden_v8_abi::set_modify_code_generation_from_strings_callback(
        runtime.v8_isolate(),
        code_generation_callback,
      );
    }
  }

  fn assert_dynamic_script_denied(
    scope: &mut v8::PinScope<'_, '_>,
    source: &str,
  ) {
    v8::tc_scope!(let tc_scope, scope);
    let source = v8::String::new(tc_scope, source).unwrap();
    let script = v8::Script::compile(tc_scope, source, None).unwrap();
    assert!(script.run(tc_scope).is_none());
    assert!(tc_scope.has_caught());
    let exception = tc_scope.exception().unwrap();
    let message = exception
      .to_string(tc_scope)
      .unwrap()
      .to_rust_string_lossy(tc_scope);
    assert!(
      message.contains("Code generation from strings disallowed"),
      "unexpected dynamic-code denial: {message}"
    );
  }

  #[test]
  fn missing_identity_preserves_attribution_only_but_armed_context_denies() {
    let mut runtime = crate::JsRuntime::new(crate::RuntimeOptions::default());
    install_actual_codegen_callback(&mut runtime);
    let context = runtime.main_context();
    {
      v8::scope!(let scope, runtime.v8_isolate());
      let context = v8::Local::new(scope, &context);
      initialize_context_attribution(scope, context, || None);
      let scope = &mut v8::ContextScope::new(scope, context);
      assert_eq!(
        dynamic_endowment_state(scope, context),
        DynamicEndowmentState::AttributionOnly
      );
      assert_eq!(context_id(scope, context), None);
    }

    runtime
      .execute_script(
        "file:///missing-attribution-identity.js",
        "if (Function('return 42')() !== 42) throw new Error('changed');",
      )
      .unwrap();

    {
      v8::scope!(let scope, runtime.v8_isolate());
      let context = v8::Local::new(scope, &context);
      let scope = &mut v8::ContextScope::new(scope, context);
      enable_dynamic_endowments(scope);
      assert_eq!(
        dynamic_endowment_state(scope, context),
        DynamicEndowmentState::Enabled
      );
      assert_eq!(context_id(scope, context), None);
    }
    let error = runtime
      .execute_script(
        "file:///armed-missing-attribution-identity.js",
        "Function('return 42')()",
      )
      .unwrap_err();
    assert!(
      error
        .to_string()
        .contains("Code generation from strings disallowed"),
      "unexpected armed missing-identity denial: {error}"
    );
  }

  #[test]
  fn identity_only_old_crash_shape_is_bounded_and_denied() {
    let mut runtime = crate::JsRuntime::new(crate::RuntimeOptions::default());
    install_actual_codegen_callback(&mut runtime);
    let context = runtime.main_context();
    {
      v8::scope!(let scope, runtime.v8_isolate());
      let context = v8::Local::new(scope, &context);
      let identity =
        v8::String::new(scope, "oden-eval-0123456789abcdef0123456789abcdef")
          .unwrap();
      context.set_embedder_data(ODEN_EVAL_CONTEXT_SLOT, identity.into());
      context.set_allow_generation_from_strings(false);
      let scope = &mut v8::ContextScope::new(scope, context);
      assert_eq!(
        dynamic_endowment_state(scope, context),
        DynamicEndowmentState::Unmanaged
      );
      assert_eq!(
        context_id(scope, context).as_deref(),
        Some("oden-eval-0123456789abcdef0123456789abcdef")
      );
    }

    for _ in 0..1000 {
      let error = runtime
        .execute_script(
          "file:///identity-only-old-crash-shape.js",
          "Function('return 42')()",
        )
        .unwrap_err();
      assert!(
        error
          .to_string()
          .contains("Code generation from strings disallowed"),
        "unexpected identity-only denial: {error}"
      );
    }
  }

  #[test]
  fn managed_context_materializes_both_slots_before_dynamic_codegen() {
    let mut runtime = crate::JsRuntime::new(crate::RuntimeOptions::default());
    install_actual_codegen_callback(&mut runtime);
    let context = runtime.main_context();
    {
      v8::scope!(let scope, runtime.v8_isolate());
      let context = v8::Local::new(scope, &context);
      initialize_context_attribution(scope, context, || {
        Some("oden-eval-0123456789abcdef0123456789abcdef".to_string())
      });
      let scope = &mut v8::ContextScope::new(scope, context);
      assert!(
        crate::oden_v8_abi::context_embedder_data_slot_is_materialized(
          context,
          ODEN_EVAL_CONTEXT_SLOT,
        )
      );
      assert!(
        crate::oden_v8_abi::context_embedder_data_slot_is_materialized(
          context,
          ODEN_EVAL_ENDOWMENT_SLOT,
        )
      );
      assert_eq!(
        dynamic_endowment_state(scope, context),
        DynamicEndowmentState::AttributionOnly
      );
    }

    runtime
      .execute_script(
        "file:///managed-attribution-only.js",
        "if (eval('40 + 2') !== 42) throw new Error('changed');",
      )
      .unwrap();
  }

  #[test]
  fn unmanaged_node_vm_shaped_context_keeps_string_codegen_denied() {
    let mut runtime = crate::JsRuntime::new(crate::RuntimeOptions::default());
    install_actual_codegen_callback(&mut runtime);

    v8::scope!(let scope, runtime.v8_isolate());
    let context = v8::Context::new(scope, Default::default());
    unsafe {
      context.set_aligned_pointer_in_embedder_data(1, std::ptr::null_mut());
      context.set_aligned_pointer_in_embedder_data(2, std::ptr::null_mut());
      context.set_aligned_pointer_in_embedder_data(3, std::ptr::null_mut());
    }
    context.clear_all_slots();
    context.set_allow_generation_from_strings(false);
    assert!(
      !crate::oden_v8_abi::context_embedder_data_slot_is_materialized(
        context,
        ODEN_EVAL_CONTEXT_SLOT,
      )
    );
    assert!(
      !crate::oden_v8_abi::context_embedder_data_slot_is_materialized(
        context,
        ODEN_EVAL_ENDOWMENT_SLOT,
      )
    );

    let scope = &mut v8::ContextScope::new(scope, context);
    assert_eq!(
      dynamic_endowment_state(scope, context),
      DynamicEndowmentState::Unmanaged
    );
    assert_dynamic_script_denied(scope, "Function('return 42')()");
    assert_dynamic_script_denied(scope, "eval('40 + 2')");
  }

  #[test]
  fn arming_unmanaged_context_disables_codegen_fast_path() {
    let mut runtime = crate::JsRuntime::new(crate::RuntimeOptions::default());
    install_actual_codegen_callback(&mut runtime);

    v8::scope!(let scope, runtime.v8_isolate());
    let context = v8::Context::new(scope, Default::default());
    assert!(context.is_code_generation_from_strings_allowed());
    assert!(
      !crate::oden_v8_abi::context_embedder_data_slot_is_materialized(
        context,
        ODEN_EVAL_CONTEXT_SLOT,
      )
    );
    assert!(
      !crate::oden_v8_abi::context_embedder_data_slot_is_materialized(
        context,
        ODEN_EVAL_ENDOWMENT_SLOT,
      )
    );

    let scope = &mut v8::ContextScope::new(scope, context);
    enable_dynamic_endowments(scope);
    assert!(!context.is_code_generation_from_strings_allowed());
    assert_eq!(
      dynamic_endowment_state(scope, context),
      DynamicEndowmentState::Enabled
    );
    assert_eq!(context_id(scope, context), None);
    assert_dynamic_script_denied(scope, "Function('return 42')()");
    assert_dynamic_script_denied(scope, "eval('40 + 2')");
  }

  #[test]
  fn marked_metadata_or_allocation_failure_denies_original_source() {
    assert!(!allow_unmodified_source(true));
    assert!(allow_unmodified_source(false));
  }

  #[test]
  fn dynamic_rewrite_is_scope_aware_and_preserves_eval_completion_shape() {
    let output = rewritten(
      "const local = 40; const object = { fetch, local }; eval('local'); local + 2",
    );
    assert!(output.starts_with(&format!(
      "\"use strict\";const {TEST_ALIAS}_record={TEST_ALIAS}();"
    )));
    assert!(
      output
        .contains(&format!("{{ fetch: {TEST_ALIAS}_record.fetch, local }}"))
    );
    assert!(output.contains("eval('local')"));
    assert!(output.ends_with("local + 2"));
  }

  #[test]
  fn function_constructor_prefix_and_parameter_bindings_stay_native() {
    let source =
      "(function anonymous(fetch\n) {\nreturn [fetch, globalThis.fetch]\n})";
    let output = rewritten(source);
    let prefix = "(function anonymous(fetch\n) {";
    assert!(output.starts_with(prefix));
    assert!(output.contains("return [fetch,"));
    assert!(output.contains(&format!("{TEST_ALIAS}_record.globalThis.fetch")));
  }

  #[test]
  fn function_constructor_default_global_and_with_are_refused() {
    let default_global =
      "(function anonymous(value = fetch\n) {\nreturn value\n})";
    assert!(matches!(
      rewrite_dynamic_source(default_global, TEST_ALIAS),
      DynamicRewrite::Refused
    ));
    assert!(matches!(
      rewrite_dynamic_source("with ({}) { fetch }", TEST_ALIAS),
      DynamicRewrite::Refused
    ));
  }

  #[test]
  fn dynamic_assignment_targets_cannot_mutate_the_raw_global() {
    let output = rewritten("fetch = 1; for (globalThis of []) {};");
    assert!(output.contains(&format!("{TEST_ALIAS}_record.fetch = 1")));
    assert!(
      output.contains(&format!("for ({TEST_ALIAS}_record.globalThis of [])"))
    );
    for source in [
      "({ fetch } = value)",
      "[fetch] = value",
      "for ({ fetch } of values) {}",
    ] {
      assert!(matches!(
        rewrite_dynamic_source(source, TEST_ALIAS),
        DynamicRewrite::Refused
      ));
    }
  }

  #[test]
  fn invalid_source_is_classified_as_a_parse_error() {
    assert!(matches!(
      rewrite_dynamic_source("function (", TEST_ALIAS),
      DynamicRewrite::ParseError
    ));
  }

  #[test]
  fn pending_identity_is_one_shot_and_isolate_scoped() {
    let url = remember_pending_eval(
      7,
      "context-1".to_string(),
      "file:///root/app.js".to_string(),
    )
    .expect("CSPRNG identity");
    assert!(registry().remove_for_isolate(&url, 8).is_none());
    assert!(
      registry()
        .remove_for_context(&url, 7, "context-2")
        .is_none()
    );
    assert!(
      registry()
        .remove_for_context(&url, 7, "context-1")
        .is_some()
    );
    assert!(registry().remove_for_isolate(&url, 7).is_none());
  }

  #[test]
  fn pending_registry_evicts_fail_closed() {
    let mut pending = PendingEvalRegistry::default();
    for i in 0..=MAX_PENDING_EVALS_PER_ISOLATE {
      pending.insert(
        1,
        format!("{EVAL_SOURCE_URL_PREFIX}{i:032x}"),
        pending_eval("context-1"),
      );
    }
    assert_eq!(pending.len_for_isolate(1), MAX_PENDING_EVALS_PER_ISOLATE);
    assert!(
      !pending.contains(&format!("{EVAL_SOURCE_URL_PREFIX}{:032x}", 0), 1)
    );
  }

  #[test]
  fn out_of_order_consumption_does_not_retain_ordering_metadata() {
    let mut registry = PendingEvalRegistry::default();
    let oldest = format!("{EVAL_SOURCE_URL_PREFIX}{:032x}", 0);
    registry.insert(1, oldest.clone(), pending_eval("context-1"));

    for i in 1..(MAX_PENDING_EVALS_PER_ISOLATE * 4) {
      let source_url = format!("{EVAL_SOURCE_URL_PREFIX}{i:032x}");
      registry.insert(1, source_url.clone(), pending_eval("context-1"));
      assert!(
        registry
          .remove_for_context(&source_url, 1, "context-1")
          .is_some()
      );
    }

    assert_eq!(registry.len_for_isolate(1), 1);
    assert!(registry.contains(&oldest, 1));
  }

  #[test]
  fn abandoned_eval_does_not_arm_sibling_or_root_slow_path() {
    let mut registry = PendingEvalRegistry::default();
    let nonce = format!("{EVAL_SOURCE_URL_PREFIX}{:032x}", 7);
    registry.insert(11, nonce.clone(), pending_eval("context-1"));

    let root_op = frame(11, "file:///root/main.ts", false);
    assert!(!frame_has_pending_identity(&registry, &root_op, 11));

    let sibling_replay = frame(22, &nonce, true);
    assert!(!frame_has_pending_identity(&registry, &sibling_replay, 22));

    let matching_eval = frame(11, &nonce, true);
    assert!(frame_has_pending_identity(&registry, &matching_eval, 11));
  }

  #[test]
  fn isolate_cleanup_reclaims_pending_and_dynamic_locators() {
    let isolate_id = usize::MAX - 101;
    let static_script_id = usize::MAX - 102;
    let mut pending = PendingEvalRegistry::default();
    pending.insert(
      isolate_id,
      format!("{EVAL_SOURCE_URL_PREFIX}{:032x}", 1),
      pending_eval("context-1"),
    );
    assert_eq!(pending.len_for_isolate(isolate_id), 1);
    pending.clear_isolate(isolate_id);
    assert_eq!(pending.len_for_isolate(isolate_id), 0);

    crate::error::oden_register_dynamic_script_locator_by_key(
      isolate_id,
      1,
      "file:///root/app.js",
    );
    crate::error::oden_register_script_locator_by_key(
      isolate_id,
      static_script_id,
      "file:///root/static.js",
    );
    assert_eq!(
      crate::error::oden_dynamic_script_locator_count(isolate_id),
      1
    );
    crate::error::oden_clear_script_locators(isolate_id);
    assert!(crate::error::oden_script_locator(isolate_id, 1).is_none());
    assert!(
      crate::error::oden_script_locator(isolate_id, static_script_id).is_none()
    );
  }

  #[test]
  fn dynamic_script_locators_are_bounded_without_evicting_static_modules() {
    let isolate_id = usize::MAX - 202;
    let static_script_id = usize::MAX - 2_048;
    crate::error::oden_register_script_locator_by_key(
      isolate_id,
      static_script_id,
      "file:///root/static.js",
    );
    for script_id in
      0..(crate::error::MAX_DYNAMIC_SCRIPT_LOCATORS_PER_ISOLATE * 4)
    {
      crate::error::oden_register_dynamic_script_locator_by_key(
        isolate_id,
        script_id,
        "file:///root/eval.js",
      );
    }

    assert_eq!(
      crate::error::oden_dynamic_script_locator_count(isolate_id),
      crate::error::MAX_DYNAMIC_SCRIPT_LOCATORS_PER_ISOLATE
    );
    assert_eq!(
      crate::error::oden_script_locator(isolate_id, static_script_id)
        .as_deref(),
      Some("file:///root/static.js")
    );
    crate::error::oden_clear_script_locators(isolate_id);
  }

  #[test]
  fn script_locator_registry_is_isolate_scoped_without_global_fallback() {
    let script_id = usize::MAX - 7;
    crate::error::oden_register_script_locator_by_key(
      101,
      script_id,
      "file:///worker-a.js",
    );
    crate::error::oden_register_script_locator_by_key(
      202,
      script_id,
      "file:///worker-b.js",
    );
    assert_eq!(
      crate::error::oden_script_locator(101, script_id).as_deref(),
      Some("file:///worker-a.js")
    );
    assert_eq!(
      crate::error::oden_script_locator(202, script_id).as_deref(),
      Some("file:///worker-b.js")
    );

    crate::error::oden_register_script_locator_by_key(
      0,
      script_id - 1,
      "file:///legacy-global.js",
    );
    assert!(crate::error::oden_script_locator(303, script_id - 1).is_none());
    crate::error::oden_clear_script_locators(101);
    crate::error::oden_clear_script_locators(202);
    crate::error::oden_clear_script_locators(0);
  }
}

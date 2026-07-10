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

use indexmap::IndexMap;
use rand::RngCore;

use crate::error::JsStackFrame;
use crate::oden_v8_abi::ModifyCodeGenerationFromStringsResult;

const EVAL_SOURCE_URL_PREFIX: &str = "oden-eval://";
const MAX_PENDING_EVALS_PER_ISOLATE: usize = 4096;
// Context embedder slots 1/2 belong to ContextState/ModuleMap, while node:vm
// uses 1/2/3 plus its own tag in slot 4. Slot 5 is Oden's unforgeable realm
// tag. At the
// first observed operation V8's per-frame function context, rather than the
// op callback's current context, prevents a nonce observed in one realm from
// being replayed by eval or node:vm code in another context of the isolate.
const ODEN_EVAL_CONTEXT_SLOT: i32 = 5;

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

fn context_id(
  scope: &mut v8::PinScope,
  context: v8::Local<v8::Context>,
) -> Option<String> {
  let value = context.get_embedder_data(scope, ODEN_EVAL_CONTEXT_SLOT)?;
  let value = v8::Local::<v8::String>::try_from(value).ok()?;
  Some(value.to_rust_string_lossy(scope))
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
  let Some(context_id) = context_id(scope, context) else {
    return ModifyCodeGenerationFromStringsResult {
      codegen_allowed: true,
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
      codegen_allowed: true,
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

  let isolate_id = crate::error::oden_isolate_key(isolate);
  let Some(source_url) =
    remember_pending_eval(isolate_id, context_id, caller_locator)
  else {
    return ModifyCodeGenerationFromStringsResult {
      codegen_allowed: true,
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
    codegen_allowed: true,
    modified_source,
  }
}

#[allow(improper_ctypes_definitions)]
unsafe extern "C" fn code_generation_callback<'s>(
  context: v8::Local<'s, v8::Context>,
  source: v8::Local<'s, v8::Value>,
  _is_code_like: bool,
) -> ModifyCodeGenerationFromStringsResult<'s> {
  // No Rust unwind may cross V8's C++ callback boundary. A panic leaves the
  // source unmodified and thus unregistered/quarantined, while still allowing
  // V8 to preserve ordinary JavaScript code-generation semantics.
  std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
    modify_code_generation(context, source)
  }))
  .unwrap_or(ModifyCodeGenerationFromStringsResult {
    codegen_allowed: true,
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
    // V8 invokes the callback only when the context's unconditional fast path
    // is disabled. The callback always returns allow; this is an attribution
    // opt-in, not a code-generation policy change.
    if let Some(context_id) = random_hex_identity("oden-eval-context:")
      && let Some(value) = v8::String::new(scope, &context_id)
    {
      context.set_embedder_data(ODEN_EVAL_CONTEXT_SLOT, value.into());
      context.set_allow_generation_from_strings(false);
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;

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
    assert_eq!(
      crate::error::oden_dynamic_script_locator_count(isolate_id),
      1
    );
    crate::error::oden_clear_script_locators(isolate_id);
    assert!(crate::error::oden_script_locator(isolate_id, 1).is_none());
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

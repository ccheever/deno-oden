// Copyright 2018-2026 the Deno authors. MIT license.

//! Exact-pin V8 ABI seam used by Oden's eval attribution.
//!
//! rusty_v8 149.4.0 bundles V8's public
//! `Isolate::SetModifyCodeGenerationFromStringsCallback` and
//! `StackTrace::CurrentScriptData` implementations in every supported prebuilt
//! archive, but does not expose their small C/Rust wrappers. Calling the public
//! C++ members directly avoids maintaining custom 139 MiB archives. This
//! module is intentionally coupled to the exact `=149.4.0` workspace pin:
//! changing that pin requires re-proving the symbols and layouts below. A
//! missing/changed symbol fails at link time.
//!
//! @ref llp/0001-adding-capability-security-to-deno.plan.md#attribution-of-evalnew-function-code [implements] — eval compilation must bind to its live caller without a read-time fail-open fallback

use std::ffi::c_void;

// rusty_v8 reserves two physical Context embedder-data fields before the
// logical slot numbers exposed by Context::{get,set}_embedder_data.
const RUSTY_V8_INTERNAL_CONTEXT_SLOT_COUNT: u32 = 2;

unsafe extern "C" {
  fn v8__Context__GetNumberOfEmbedderDataFields(
    context: *const v8::Context,
  ) -> u32;
}

/// ABI mirror of V8 14.9's `StackTrace::ScriptData`.
///
/// V8 deliberately reports the root script ID in `id` for eval frames. Oden
/// instead calls `function.script_id()` on the returned function to pair the
/// engine-observed dynamic script ID with its native context.
#[repr(C)]
#[derive(Clone, Copy)]
pub(crate) struct CurrentScriptData<'s> {
  pub(crate) id: i32,
  pub(crate) function: v8::Local<'s, v8::Function>,
  pub(crate) context: v8::Local<'s, v8::Context>,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct MemorySpan<T> {
  data: *mut T,
  size: usize,
}

/// ABI mirror of V8 14.9's `ModifyCodeGenerationFromStringsResult`.
///
/// `MaybeLocal<String>` is one nullable pointer. `Option<Local<String>>` uses
/// that same nullable-pointer representation; the assertions make a rusty_v8
/// layout change fail during compilation.
#[repr(C)]
pub(crate) struct ModifyCodeGenerationFromStringsResult<'s> {
  pub(crate) codegen_allowed: bool,
  pub(crate) modified_source: Option<v8::Local<'s, v8::String>>,
}

#[allow(improper_ctypes_definitions)]
pub(crate) type ModifyCodeGenerationFromStringsCallback =
  for<'s> unsafe extern "C" fn(
    context: v8::Local<'s, v8::Context>,
    source: v8::Local<'s, v8::Value>,
    is_code_like: bool,
  ) -> ModifyCodeGenerationFromStringsResult<'s>;

const _: () = {
  assert!(
    std::mem::size_of::<v8::UnsafeRawIsolatePtr>()
      == std::mem::size_of::<*mut c_void>()
  );
  assert!(
    std::mem::size_of::<v8::Local<'static, v8::String>>()
      == std::mem::size_of::<*mut c_void>()
  );
  assert!(
    std::mem::size_of::<Option<v8::Local<'static, v8::String>>>()
      == std::mem::size_of::<*mut c_void>()
  );
  assert!(
    std::mem::offset_of!(
      ModifyCodeGenerationFromStringsResult<'static>,
      codegen_allowed
    ) == 0
  );
  assert!(
    std::mem::offset_of!(
      ModifyCodeGenerationFromStringsResult<'static>,
      modified_source
    ) == 8
  );
  assert!(
    std::mem::size_of::<ModifyCodeGenerationFromStringsResult<'static>>() == 16
  );
  assert!(std::mem::offset_of!(CurrentScriptData<'static>, id) == 0);
  assert!(std::mem::offset_of!(CurrentScriptData<'static>, function) == 8);
  assert!(std::mem::offset_of!(CurrentScriptData<'static>, context) == 16);
  assert!(std::mem::size_of::<CurrentScriptData<'static>>() == 24);
  assert!(std::mem::size_of::<MemorySpan<c_void>>() == 16);
};

#[cfg(not(target_pointer_width = "64"))]
compile_error!(
  "Oden's rusty_v8 149.4.0 eval ABI seam is proven only for 64-bit targets"
);

// Clang/GCC use the Itanium C++ ABI on macOS and Linux. The symbol was
// verified in all four v149.4.0 simdutf release archives:
// aarch64/x86_64 × apple-darwin/unknown-linux-gnu.
#[cfg(target_family = "unix")]
#[allow(
  improper_ctypes,
  reason = "Local and Option<Local> are pointer-layout ABI mirrors asserted above"
)]
unsafe extern "C" {
  #[link_name = "_ZN2v87Isolate42SetModifyCodeGenerationFromStringsCallbackEPFNS_37ModifyCodeGenerationFromStringsResultENS_5LocalINS_7ContextEEENS2_INS_5ValueEEEbE"]
  fn set_modify_code_generation_from_strings_callback_abi(
    isolate: *mut c_void,
    callback: ModifyCodeGenerationFromStringsCallback,
  );

  #[link_name = "_ZN2v810StackTrace17CurrentScriptDataEPNS_7IsolateENS_10MemorySpanINS0_10ScriptDataEEE"]
  fn current_script_data_abi(
    isolate: *mut c_void,
    frame_data: MemorySpan<CurrentScriptData<'static>>,
  ) -> MemorySpan<CurrentScriptData<'static>>;
}

// MSVC uses a different decoration for the same public member. The symbol was
// verified in both v149.4.0 simdutf Windows release archives (x86_64/aarch64).
#[cfg(all(target_os = "windows", target_env = "msvc"))]
#[allow(
  improper_ctypes,
  reason = "Local and Option<Local> are pointer-layout ABI mirrors asserted above"
)]
unsafe extern "C" {
  #[link_name = "?SetModifyCodeGenerationFromStringsCallback@Isolate@v8@@QEAAXP6A?AUModifyCodeGenerationFromStringsResult@2@V?$Local@VContext@v8@@@2@V?$Local@VValue@v8@@@2@_N@Z@Z"]
  fn set_modify_code_generation_from_strings_callback_abi(
    isolate: *mut c_void,
    callback: ModifyCodeGenerationFromStringsCallback,
  );

  #[link_name = "?CurrentScriptData@StackTrace@v8@@SA?AV?$MemorySpan@UScriptData@StackTrace@v8@@@2@PEAVIsolate@2@V32@@Z"]
  fn current_script_data_abi(
    isolate: *mut c_void,
    frame_data: MemorySpan<CurrentScriptData<'static>>,
  ) -> MemorySpan<CurrentScriptData<'static>>;
}

#[cfg(all(target_os = "windows", not(target_env = "msvc")))]
compile_error!(
  "Oden's rusty_v8 149.4.0 eval ABI seam supports Windows MSVC only"
);

/// Install V8's dynamic-code-generation callback on an isolate.
///
/// # Safety
///
/// The callback must obey V8's callback contract and must not unwind across
/// the C++ boundary. The exact rusty_v8 pin and target gates above are part of
/// that safety contract.
pub(crate) unsafe fn set_modify_code_generation_from_strings_callback(
  isolate: &mut v8::Isolate,
  callback: ModifyCodeGenerationFromStringsCallback,
) {
  let raw = unsafe { isolate.as_raw_isolate_ptr() };
  // SAFETY: UnsafeRawIsolatePtr is repr(transparent) over V8's Isolate*, and
  // the compile-time assertion above pins the pointer layout.
  let raw =
    unsafe { std::mem::transmute::<v8::UnsafeRawIsolatePtr, *mut c_void>(raw) };
  unsafe {
    set_modify_code_generation_from_strings_callback_abi(raw, callback)
  };
}

fn context_embedder_data_field_count(context: v8::Local<v8::Context>) -> u32 {
  // This is rusty_v8's existing C wrapper around V8's public bounded field
  // count. Unlike Context::get_embedder_data, it never reads a requested field
  // and is therefore safe when a logical slot has not been materialized.
  unsafe { v8__Context__GetNumberOfEmbedderDataFields(&*context) }
}

/// Return whether rusty_v8 has materialized one logical Context embedder slot.
///
/// Context::get_embedder_data performs an unchecked inline field read in
/// release builds, despite its Option result. Callers must prove the logical
/// slot exists through this helper before every read.
///
/// @ref LLP 0019#workers-vm-wasi-and-native-code [implements] -- Dynamic
/// compilation callbacks can receive main, secondary, or node:vm contexts;
/// missing attribution/endowment metadata must remain a bounded state rather
/// than an out-of-range V8 field access.
pub(crate) fn context_embedder_data_slot_is_materialized(
  context: v8::Local<v8::Context>,
  logical_slot: i32,
) -> bool {
  let Ok(logical_slot) = u32::try_from(logical_slot) else {
    return false;
  };
  let Some(physical_slot) =
    logical_slot.checked_add(RUSTY_V8_INTERNAL_CONTEXT_SLOT_COUNT)
  else {
    return false;
  };
  context_embedder_data_field_count(context) > physical_slot
}

/// Capture the current JavaScript functions and their native contexts.
///
/// V8 writes local handles into the caller-provided storage. The returned
/// lifetime is tied to `scope`, whose active handle scope owns those handles.
pub(crate) fn current_script_data<'s>(
  _scope: &mut v8::PinScope<'s, '_>,
  isolate: v8::UnsafeRawIsolatePtr,
  frame_limit: usize,
) -> Vec<CurrentScriptData<'s>> {
  if frame_limit == 0 {
    return Vec::new();
  }
  let mut storage =
    vec![std::mem::MaybeUninit::<CurrentScriptData<'s>>::uninit(); frame_limit];
  let raw = unsafe {
    std::mem::transmute::<v8::UnsafeRawIsolatePtr, *mut c_void>(isolate)
  };
  let input = MemorySpan {
    data: storage.as_mut_ptr().cast::<CurrentScriptData<'static>>(),
    size: storage.len(),
  };
  // SAFETY: the exact-pin layout assertions cover MemorySpan and ScriptData;
  // `scope` proves that V8 has an active handle scope for the returned Locals.
  let written = unsafe { current_script_data_abi(raw, input) }.size;
  debug_assert!(written <= storage.len());
  let written = written.min(storage.len());
  storage
    .into_iter()
    .take(written)
    .map(|value| unsafe { value.assume_init() })
    .collect()
}

#[cfg(test)]
mod tests {
  use std::pin::pin;

  use super::*;

  #[allow(improper_ctypes_definitions)]
  unsafe extern "C" fn replace_eval_source<'s>(
    context: v8::Local<'s, v8::Context>,
    _source: v8::Local<'s, v8::Value>,
    _is_code_like: bool,
  ) -> ModifyCodeGenerationFromStringsResult<'s> {
    // V8 invokes the callback with an active HandleScope. CallbackScope wraps
    // it without opening a nested scope, so the returned Local remains valid
    // for V8 to consume after this Rust frame returns.
    let scope = pin!(unsafe { v8::CallbackScope::new(context) });
    let scope = &mut scope.init();
    ModifyCodeGenerationFromStringsResult {
      codegen_allowed: true,
      modified_source: v8::String::new(scope, "40 + 2"),
    }
  }

  #[test]
  fn exact_pin_callback_links_and_modifies_source() {
    let mut runtime = crate::JsRuntime::new(crate::RuntimeOptions::default());
    unsafe {
      set_modify_code_generation_from_strings_callback(
        runtime.v8_isolate(),
        replace_eval_source,
      );
    }

    let context = runtime.main_context();
    {
      v8::scope!(let scope, runtime.v8_isolate());
      let context = v8::Local::new(scope, &context);
      // V8 bypasses the callback when this flag is true and the source is
      // already a string. False means "consult the callback", not "deny".
      context.set_allow_generation_from_strings(false);
    }

    runtime
      .execute_script(
        "oden_v8_abi_test.js",
        "if (eval('1 + 1') !== 42) throw new Error('source was not modified');",
      )
      .unwrap();
  }

  #[test]
  fn logical_context_embedder_slots_are_bounded_exactly() {
    let mut runtime = crate::JsRuntime::new(crate::RuntimeOptions::default());
    v8::scope!(let scope, runtime.v8_isolate());
    let context = v8::Context::new(scope, Default::default());

    assert_eq!(context_embedder_data_field_count(context), 0);
    assert!(!context_embedder_data_slot_is_materialized(context, -1));
    assert!(!context_embedder_data_slot_is_materialized(context, 0));
    assert!(!context_embedder_data_slot_is_materialized(
      context,
      i32::MAX
    ));

    let identity = v8::String::new(scope, "fixture-context-id").unwrap();
    context.set_embedder_data(5, identity.into());
    assert_eq!(
      context_embedder_data_field_count(context),
      RUSTY_V8_INTERNAL_CONTEXT_SLOT_COUNT + 6
    );
    assert!(context_embedder_data_slot_is_materialized(context, 5));
    assert!(!context_embedder_data_slot_is_materialized(context, 6));

    let disabled = v8::Boolean::new(scope, false);
    context.set_embedder_data(6, disabled.into());
    assert_eq!(
      context_embedder_data_field_count(context),
      RUSTY_V8_INTERNAL_CONTEXT_SLOT_COUNT + 7
    );
    assert!(context_embedder_data_slot_is_materialized(context, 5));
    assert!(context_embedder_data_slot_is_materialized(context, 6));

    context.clear_all_slots();
  }
}

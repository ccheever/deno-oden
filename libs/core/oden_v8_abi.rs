// Copyright 2018-2026 the Deno authors. MIT license.

//! Exact-pin V8 ABI seam used by Oden's eval attribution.
//!
//! rusty_v8 149.4.0 bundles V8's public
//! `Isolate::SetModifyCodeGenerationFromStringsCallback` implementation in
//! every supported prebuilt archive, but does not expose its six-line C/Rust
//! wrapper. Calling the public C++ member directly avoids maintaining custom
//! 139 MiB archives. This module is intentionally coupled to the exact
//! `=149.4.0` workspace pin: changing that pin requires re-proving the symbols
//! and layouts below. A missing/changed symbol fails at link time.
//!
//! @ref llp/0001-adding-capability-security-to-deno.plan.md#attribution-of-evalnew-function-code [implements] — eval compilation must bind to its live caller without a read-time fail-open fallback

use std::ffi::c_void;

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
}

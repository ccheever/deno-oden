// deno-lint-ignore-file
// Copyright 2018-2026 the Deno authors. MIT license.

(function () {
const { core, primordials } = __bootstrap;
const {
  ReflectApply,
  SafeWeakSet,
  SafeWeakMap,
  WeakMapPrototypeGet,
  WeakMapPrototypeSet,
  WeakSetPrototypeAdd,
  WeakSetPrototypeDelete,
  WeakSetPrototypeHas,
} = primordials;

// Guard and hook state stays outside every user-reachable stream/state object.
// @ref LLP 0019#operation-scoped-positive-authority-provenance [implements]
const streamUseGuards = new SafeWeakMap();
const streamGuardAttachHooks = new SafeWeakMap();
const streamDeliveryPreflights = new SafeWeakMap();
const activeStreamDeliveryPreflights = new SafeWeakSet();
const streamTrustedDeliveryCallbacks = new SafeWeakMap();
const streamCleanupDeliveryCallbacks = new SafeWeakMap();
const trustedDeliveryCallbacks = new SafeWeakMap();
const trustedDeliveryPreflights = new SafeWeakMap();

function getStreamUseGuard(stream) {
  return WeakMapPrototypeGet(streamUseGuards, stream);
}

function hasStreamUseGuard(stream) {
  return getStreamUseGuard(stream) !== undefined;
}

function runStreamUseGuard(stream) {
  const guard = getStreamUseGuard(stream);
  if (guard !== undefined) guard();
}

function setStreamUseGuard(stream, guard) {
  const existing = getStreamUseGuard(stream);
  if (existing === undefined) {
    const attach = WeakMapPrototypeGet(streamGuardAttachHooks, stream);
    if (attach !== undefined) attach();
    WeakMapPrototypeSet(streamUseGuards, stream, guard);
  } else if (existing !== guard) {
    WeakMapPrototypeSet(streamUseGuards, stream, () => {
      existing();
      guard();
    });
  }
}

function propagateStreamUseGuard(source, target) {
  const guard = getStreamUseGuard(source);
  if (guard !== undefined) setStreamUseGuard(target, guard);
}

function registerStreamGuardAttachHook(stream, hook) {
  if (hasStreamUseGuard(stream)) {
    hook();
    return;
  }
  const existing = WeakMapPrototypeGet(streamGuardAttachHooks, stream);
  if (existing === undefined) {
    WeakMapPrototypeSet(streamGuardAttachHooks, stream, hook);
  } else {
    WeakMapPrototypeSet(streamGuardAttachHooks, stream, () => {
      existing();
      hook();
    });
  }
}

function markTrustedDeliveryCallback(callback, preflight) {
  WeakMapPrototypeSet(trustedDeliveryCallbacks, callback, true);
  if (preflight !== undefined) {
    WeakMapPrototypeSet(trustedDeliveryPreflights, callback, preflight);
  }
  return callback;
}

function captureDeliveryCallback(callback, invoke = callback) {
  return {
    callback: invoke,
    context: WeakMapPrototypeGet(trustedDeliveryCallbacks, callback) === true
      ? undefined
      : core.ops.op_oden_callback_context(callback),
    preflight: WeakMapPrototypeGet(trustedDeliveryPreflights, callback),
  };
}

function captureTrustedDeliveryCallback(callback, invoke = callback) {
  return {
    callback: invoke,
    context: undefined,
    preflight: WeakMapPrototypeGet(trustedDeliveryPreflights, callback),
  };
}

function markStreamTrustedDeliveryCallback(stream, callback) {
  let callbacks = WeakMapPrototypeGet(streamTrustedDeliveryCallbacks, stream);
  if (callbacks === undefined) {
    callbacks = new SafeWeakSet();
    WeakMapPrototypeSet(streamTrustedDeliveryCallbacks, stream, callbacks);
  }
  WeakSetPrototypeAdd(callbacks, callback);
}

function isStreamTrustedDeliveryCallback(stream, callback) {
  const callbacks = WeakMapPrototypeGet(streamTrustedDeliveryCallbacks, stream);
  return callbacks !== undefined && WeakSetPrototypeHas(callbacks, callback);
}

function markStreamCleanupDeliveryCallback(stream, callback) {
  let callbacks = WeakMapPrototypeGet(streamCleanupDeliveryCallbacks, stream);
  if (callbacks === undefined) {
    callbacks = new SafeWeakSet();
    WeakMapPrototypeSet(streamCleanupDeliveryCallbacks, stream, callbacks);
  }
  WeakSetPrototypeAdd(callbacks, callback);
}

function isStreamCleanupDeliveryCallback(stream, callback) {
  const callbacks = WeakMapPrototypeGet(streamCleanupDeliveryCallbacks, stream);
  return callbacks !== undefined && WeakSetPrototypeHas(callbacks, callback);
}

function runCapturedPreflight(stream, captured) {
  runStreamUseGuard(stream);
  if (captured.preflight !== undefined) captured.preflight();
}

function preflightCapturedDelivery(stream, captured) {
  if (!hasStreamUseGuard(stream)) return;
  if (captured.context === undefined) {
    runCapturedPreflight(stream, captured);
    return;
  }
  const previous = core.getAsyncContext();
  core.setAsyncContext(captured.context);
  try {
    runCapturedPreflight(stream, captured);
  } finally {
    core.setAsyncContext(previous);
  }
}

function runCapturedDelivery(stream, captured, receiver, args) {
  if (!hasStreamUseGuard(stream)) {
    return ReflectApply(captured.callback, receiver, args);
  }
  if (captured.context === undefined) {
    runCapturedPreflight(stream, captured);
    return ReflectApply(captured.callback, receiver, args);
  }
  const previous = core.getAsyncContext();
  core.setAsyncContext(captured.context);
  try {
    runCapturedPreflight(stream, captured);
    return ReflectApply(captured.callback, receiver, args);
  } finally {
    core.setAsyncContext(previous);
  }
}

function runCapturedCleanup(captured, receiver, args) {
  if (captured.context === undefined) {
    return ReflectApply(captured.callback, receiver, args);
  }
  const previous = core.getAsyncContext();
  core.setAsyncContext(captured.context);
  try {
    return ReflectApply(captured.callback, receiver, args);
  } finally {
    core.setAsyncContext(previous);
  }
}

function registerStreamDeliveryPreflight(stream, preflight) {
  const existing = WeakMapPrototypeGet(streamDeliveryPreflights, stream);
  if (existing === undefined) {
    WeakMapPrototypeSet(streamDeliveryPreflights, stream, preflight);
  } else {
    WeakMapPrototypeSet(streamDeliveryPreflights, stream, () => {
      existing();
      preflight();
    });
  }
}

function preflightStreamDelivery(stream) {
  runStreamUseGuard(stream);
  if (WeakSetPrototypeHas(activeStreamDeliveryPreflights, stream)) return;
  const preflight = WeakMapPrototypeGet(streamDeliveryPreflights, stream);
  if (preflight === undefined) return;
  WeakSetPrototypeAdd(activeStreamDeliveryPreflights, stream);
  try {
    preflight();
  } finally {
    WeakSetPrototypeDelete(activeStreamDeliveryPreflights, stream);
  }
}

return {
  captureDeliveryCallback,
  captureTrustedDeliveryCallback,
  getStreamUseGuard,
  hasStreamUseGuard,
  markTrustedDeliveryCallback,
  isStreamTrustedDeliveryCallback,
  isStreamCleanupDeliveryCallback,
  markStreamCleanupDeliveryCallback,
  markStreamTrustedDeliveryCallback,
  preflightCapturedDelivery,
  preflightStreamDelivery,
  propagateStreamUseGuard,
  registerStreamDeliveryPreflight,
  registerStreamGuardAttachHook,
  runCapturedDelivery,
  runCapturedCleanup,
  runStreamUseGuard,
  setStreamUseGuard,
};
})();

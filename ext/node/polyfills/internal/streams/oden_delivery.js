// deno-lint-ignore-file
// Copyright 2018-2026 the Deno authors. MIT license.

(function () {
const { core, primordials } = __bootstrap;
const {
  ArrayPrototypeIndexOf,
  ArrayPrototypePush,
  ArrayPrototypeSplice,
  ReflectApply,
  SafeWeakSet,
  SafeWeakMap,
  SymbolAsyncIterator,
  SymbolIterator,
  TypeError,
  WeakMapPrototypeGet,
  WeakMapPrototypeDelete,
  WeakMapPrototypeSet,
  WeakSetPrototypeAdd,
  WeakSetPrototypeDelete,
  WeakSetPrototypeHas,
} = primordials;

// Guard and hook state stays outside every user-reachable stream/state object.
// @ref LLP 0019#operation-scoped-positive-authority-provenance [implements]
const streamUseGuards = new SafeWeakMap();
const streamUseGuardRunners = new SafeWeakMap();
const streamUseGuardParts = new SafeWeakMap();
const streamUseGuardPartLists = new SafeWeakMap();
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

function streamUseGuardRunner(stream) {
  let runner = WeakMapPrototypeGet(streamUseGuardRunners, stream);
  if (runner === undefined) {
    runner = () => {
      const parts = WeakMapPrototypeGet(streamUseGuardPartLists, stream);
      if (parts === undefined) return;
      for (let i = 0; i < parts.length; i++) parts[i]();
    };
    WeakMapPrototypeSet(streamUseGuardRunners, stream, runner);
  }
  return runner;
}

function addStreamUseGuardPart(stream, guard) {
  let parts = WeakMapPrototypeGet(streamUseGuardParts, stream);
  if (parts === undefined) {
    parts = new SafeWeakSet();
    WeakMapPrototypeSet(streamUseGuardParts, stream, parts);
    WeakMapPrototypeSet(streamUseGuardPartLists, stream, []);
  }
  if (WeakSetPrototypeHas(parts, guard)) return false;
  WeakSetPrototypeAdd(parts, guard);
  ArrayPrototypePush(
    WeakMapPrototypeGet(streamUseGuardPartLists, stream),
    guard,
  );
  return true;
}

function setStreamUseGuard(stream, guard) {
  if (!addStreamUseGuardPart(stream, guard)) return;
  const parts = WeakMapPrototypeGet(streamUseGuardParts, stream);
  const partList = WeakMapPrototypeGet(streamUseGuardPartLists, stream);
  try {
    const attach = WeakMapPrototypeGet(streamGuardAttachHooks, stream);
    if (attach !== undefined) attach(guard);
    if (getStreamUseGuard(stream) === undefined) {
      WeakMapPrototypeSet(
        streamUseGuards,
        stream,
        streamUseGuardRunner(stream),
      );
    }
  } catch (error) {
    WeakSetPrototypeDelete(parts, guard);
    const index = ArrayPrototypeIndexOf(partList, guard);
    if (index !== -1) ArrayPrototypeSplice(partList, index, 1);
    if (partList.length === 0) {
      WeakMapPrototypeDelete(streamUseGuards, stream);
    }
    throw error;
  }
}

function propagateStreamUseGuard(source, target) {
  const parts = WeakMapPrototypeGet(streamUseGuardPartLists, source);
  if (parts === undefined) return;
  for (let i = 0; i < parts.length; i++) {
    setStreamUseGuard(target, parts[i]);
  }
}

function linkStreamUseGuard(source, target) {
  if (
    source === null || target === null ||
    source === undefined || target === undefined ||
    typeof source !== "object" && typeof source !== "function" ||
    typeof target !== "object" && typeof target !== "function"
  ) {
    return;
  }
  registerStreamGuardAttachHook(
    source,
    (guard) => setStreamUseGuard(target, guard),
  );
}

function registerStreamGuardAttachHook(stream, hook) {
  const existing = WeakMapPrototypeGet(streamGuardAttachHooks, stream);
  if (existing === undefined) {
    WeakMapPrototypeSet(streamGuardAttachHooks, stream, hook);
  } else {
    WeakMapPrototypeSet(streamGuardAttachHooks, stream, (guard) => {
      existing(guard);
      hook(guard);
    });
  }
  const parts = WeakMapPrototypeGet(streamUseGuardPartLists, stream);
  if (parts !== undefined) {
    for (let i = 0; i < parts.length; i++) hook(parts[i]);
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

// Internal continuations resume the actor that initiated an operation, rather
// than the module provenance of the core callback used to implement it.
function captureCurrentDeliveryCallback(callback, invoke = callback) {
  return {
    callback: invoke,
    context: core.ops.op_oden_schedule_context(),
    preflight: undefined,
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

function runCapturedCallback(captured, receiver, args) {
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

function runCapturedCleanup(captured, receiver, args) {
  return runCapturedCallback(captured, receiver, args);
}

function runIterableDelivery(target, captured, receiver, args) {
  return hasStreamUseGuard(target)
    ? runCapturedDelivery(target, captured, receiver, args)
    : runCapturedCallback(captured, receiver, args);
}

function wrapIterableDelivery(iterable, recipient) {
  const snapshotFactories = function () {
    const asyncFactory = this?.[SymbolAsyncIterator];
    const syncFactory = typeof asyncFactory === "function"
      ? undefined
      : this?.[SymbolIterator];
    return [asyncFactory, syncFactory];
  };
  const capturedFactorySnapshot = captureDeliveryCallback(
    recipient ?? snapshotFactories,
    snapshotFactories,
  );
  const [asyncFactory, syncFactory] = runIterableDelivery(
    iterable,
    capturedFactorySnapshot,
    iterable,
    [],
  );
  const factory = asyncFactory ?? syncFactory;
  if (typeof factory !== "function") {
    throw new TypeError("value is not iterable");
  }

  const capturedFactory = captureDeliveryCallback(
    recipient ?? factory,
    factory,
  );
  const wrapper = {};
  const iteratorSymbol = typeof asyncFactory === "function"
    ? SymbolAsyncIterator
    : SymbolIterator;

  wrapper[iteratorSymbol] = function deliveryIteratorFactory() {
    const iterator = runIterableDelivery(
      wrapper,
      capturedFactory,
      iterable,
      [],
    );
    const snapshotMethods = function () {
      return [this?.next, this?.return, this?.throw];
    };
    const capturedSnapshot = captureDeliveryCallback(
      recipient ?? factory,
      snapshotMethods,
    );
    const [next, iteratorReturn, iteratorThrow] = runIterableDelivery(
      wrapper,
      capturedSnapshot,
      iterator,
      [],
    );
    if (typeof next !== "function") {
      throw new TypeError("iterator.next is not callable");
    }
    const capturedNext = captureDeliveryCallback(recipient ?? next, next);
    const wrappedIterator = {
      next(value) {
        return runIterableDelivery(
          wrapper,
          capturedNext,
          iterator,
          [value],
        );
      },
    };

    if (typeof iteratorReturn === "function") {
      const capturedReturn = captureDeliveryCallback(
        recipient ?? iteratorReturn,
        iteratorReturn,
      );
      wrappedIterator.return = function (value) {
        return runCapturedCleanup(capturedReturn, iterator, [value]);
      };
    }

    if (typeof iteratorThrow === "function") {
      const capturedThrow = captureDeliveryCallback(
        recipient ?? iteratorThrow,
        iteratorThrow,
      );
      wrappedIterator.throw = function (error) {
        return runIterableDelivery(
          wrapper,
          capturedThrow,
          iterator,
          [error],
        );
      };
    }

    wrappedIterator[iteratorSymbol] = function () {
      return this;
    };
    linkStreamUseGuard(wrapper, wrappedIterator);
    return wrappedIterator;
  };

  linkStreamUseGuard(iterable, wrapper);
  return wrapper;
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
  captureCurrentDeliveryCallback,
  captureTrustedDeliveryCallback,
  getStreamUseGuard,
  hasStreamUseGuard,
  markTrustedDeliveryCallback,
  isStreamTrustedDeliveryCallback,
  isStreamCleanupDeliveryCallback,
  linkStreamUseGuard,
  markStreamCleanupDeliveryCallback,
  markStreamTrustedDeliveryCallback,
  preflightCapturedDelivery,
  preflightStreamDelivery,
  propagateStreamUseGuard,
  registerStreamDeliveryPreflight,
  registerStreamGuardAttachHook,
  runCapturedCallback,
  runCapturedDelivery,
  runCapturedCleanup,
  runStreamUseGuard,
  setStreamUseGuard,
  wrapIterableDelivery,
};
})();

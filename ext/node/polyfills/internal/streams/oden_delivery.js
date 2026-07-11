// deno-lint-ignore-file
// Copyright 2018-2026 the Deno authors. MIT license.

(function () {
const { core, primordials } = __bootstrap;
const {
  ArrayPrototypeIndexOf,
  ArrayPrototypePop,
  ArrayPrototypePush,
  ArrayPrototypeSplice,
  PromisePrototypeThen,
  PromiseResolve,
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
const activeStreamUseGuardParts = new SafeWeakSet();
const activeStreamUseGuardPartContexts = new SafeWeakMap();
const activeStreamUseGuardPartList = [];
const activeStreamUseAdmissionContexts = [];
let streamUseGuardScopeDepth = 0;
let forceStreamUseGuardRecheckDepth = 0;
let untrustedDeliveryCallbackDepth = 0;
const streamGuardAttachHooks = new SafeWeakMap();
const streamDeliveryPreflights = new SafeWeakMap();
const activeStreamDeliveryPreflights = new SafeWeakSet();
const streamTrustedDeliveryCallbacks = new SafeWeakMap();
const streamCleanupDeliveryCallbacks = new SafeWeakMap();
const streamDestroyDeliverySnapshots = new SafeWeakMap();
const snapshottedStreamDestroyDeliveries = new SafeWeakSet();
const streamOperationIterables = new SafeWeakSet();
const trustedDeliveryCallbacks = new SafeWeakMap();
const trustedDeliveryContexts = new SafeWeakMap();
const trustedDeliveryPreflights = new SafeWeakMap();

function getStreamUseGuard(stream) {
  return WeakMapPrototypeGet(streamUseGuards, stream);
}

function hasStreamUseGuard(stream) {
  return getStreamUseGuard(stream) !== undefined;
}

function runStreamUseGuard(stream) {
  const guard = getStreamUseGuard(stream);
  if (guard !== undefined) return runInStreamUseGuardScope(guard);
}

function runInStreamUseGuardScope(callback) {
  streamUseGuardScopeDepth++;
  try {
    return callback();
  } finally {
    streamUseGuardScopeDepth--;
    if (streamUseGuardScopeDepth === 0) {
      while (activeStreamUseGuardPartList.length > 0) {
        const part = ArrayPrototypePop(activeStreamUseGuardPartList);
        WeakMapPrototypeDelete(activeStreamUseGuardPartContexts, part);
        WeakSetPrototypeDelete(
          activeStreamUseGuardParts,
          part,
        );
      }
    }
  }
}

function runWithForcedStreamUseGuardRecheck(callback) {
  forceStreamUseGuardRecheckDepth++;
  try {
    return callback();
  } finally {
    forceStreamUseGuardRecheckDepth--;
  }
}

function streamUseGuardRunner(stream) {
  let runner = WeakMapPrototypeGet(streamUseGuardRunners, stream);
  if (runner === undefined) {
    runner = () => {
      const parts = WeakMapPrototypeGet(streamUseGuardPartLists, stream);
      if (parts === undefined) return;
      let context;
      for (let i = 0; i < parts.length; i++) {
        const part = parts[i];
        const active = WeakSetPrototypeHas(activeStreamUseGuardParts, part);
        if (active && forceStreamUseGuardRecheckDepth === 0) {
          const partContext = WeakMapPrototypeGet(
            activeStreamUseGuardPartContexts,
            part,
          );
          if (
            partContext !== undefined && context !== undefined &&
            partContext !== context
          ) {
            throw new TypeError("stream use guard actors differ");
          }
          if (partContext !== undefined) context = partContext;
          continue;
        }
        if (!active) {
          WeakSetPrototypeAdd(activeStreamUseGuardParts, part);
          ArrayPrototypePush(activeStreamUseGuardPartList, part);
        }
        const partContext = part();
        if (!active && partContext !== undefined) {
          WeakMapPrototypeSet(
            activeStreamUseGuardPartContexts,
            part,
            partContext,
          );
        }
        if (
          partContext !== undefined && context !== undefined &&
          partContext !== context
        ) {
          throw new TypeError("stream use guard actors differ");
        }
        if (partContext !== undefined) context = partContext;
      }
      return context;
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

function runWithoutAsyncContext(run) {
  const previous = core.getAsyncContext();
  core.setAsyncContext(undefined);
  try {
    return run();
  } finally {
    core.setAsyncContext(previous);
  }
}

function installDefaultEventDeliveryHook(stream) {
  const events = core.loadExtScript("ext:deno_node/_events.mjs");
  events.setDefaultEventListenerDeliveryHook(stream, {
    isProtected() {
      return getStreamUseGuard(stream) !== undefined;
    },
    capture(
      type,
      recipient,
      listener = recipient,
      _direct = false,
      trusted = false,
    ) {
      const captured = trusted ||
          isStreamTrustedDeliveryCallback(stream, recipient)
        ? captureTrustedDeliveryCallback(recipient, listener)
        : captureDeliveryCallback(recipient, listener);
      if (type === "data") {
        return {
          invoke(receiver, args) {
            return runCapturedDelivery(stream, captured, receiver, args);
          },
          preflight() {
            preflightCapturedDelivery(stream, captured);
          },
        };
      }
      // Lifecycle events carry no bytes. They remain observable after
      // revocation, but every listener resumes only in its own CPED.
      // @ref LLP 0019#operation-scoped-positive-authority-provenance [implements]
      return {
        invoke(receiver, args) {
          return runCapturedCallback(captured, receiver, args);
        },
        preflight() {},
      };
    },
    captureRejection() {
      if (getStreamUseGuard(stream) === undefined) return undefined;
      const recipient = runWithoutAsyncContext(
        () => stream[events.captureRejectionSymbol],
      );
      if (typeof recipient !== "function") return null;
      const captured = isStreamTrustedDeliveryCallback(stream, recipient)
        ? captureTrustedDeliveryCallback(recipient)
        : captureDeliveryCallback(recipient);
      return {
        invoke(receiver, args) {
          return runCapturedDelivery(stream, captured, receiver, args);
        },
        preflight() {
          preflightCapturedDelivery(stream, captured);
        },
      };
    },
    runUseGuard() {
      return runStreamUseGuard(stream);
    },
  });
}

function snapshotStreamDestroyDelivery(stream) {
  if (WeakSetPrototypeHas(snapshottedStreamDestroyDeliveries, stream)) return;
  WeakSetPrototypeAdd(snapshottedStreamDestroyDeliveries, stream);
  try {
    const destroy = runWithoutAsyncContext(() => stream._destroy);
    if (typeof destroy === "function") {
      WeakMapPrototypeSet(streamDestroyDeliverySnapshots, stream, {
        captured: captureDeliveryCallback(destroy),
        error: undefined,
      });
    }
  } catch (error) {
    WeakMapPrototypeSet(streamDestroyDeliverySnapshots, stream, {
      captured: undefined,
      error,
    });
  }
}

function getStreamDestroyDeliverySnapshot(stream) {
  return WeakMapPrototypeGet(streamDestroyDeliverySnapshots, stream);
}

function setStreamUseGuard(stream, guard) {
  if (!addStreamUseGuardPart(stream, guard)) return;
  const parts = WeakMapPrototypeGet(streamUseGuardParts, stream);
  const partList = WeakMapPrototypeGet(streamUseGuardPartLists, stream);
  const hadDestroySnapshot = WeakSetPrototypeHas(
    snapshottedStreamDestroyDeliveries,
    stream,
  );
  try {
    // Freeze terminal cleanup at the protection boundary. A later package
    // replacement may run in its own CPED, but it cannot suppress the native
    // recipient that actually tears the protected resource down.
    // @ref LLP 0019#operation-scoped-positive-authority-provenance [implements]
    snapshotStreamDestroyDelivery(stream);
    const attach = WeakMapPrototypeGet(streamGuardAttachHooks, stream);
    if (attach !== undefined) attach(guard);
    if (getStreamUseGuard(stream) === undefined) {
      WeakMapPrototypeSet(
        streamUseGuards,
        stream,
        streamUseGuardRunner(stream),
      );
    }
    installDefaultEventDeliveryHook(stream);
  } catch (error) {
    if (!hadDestroySnapshot) {
      WeakSetPrototypeDelete(snapshottedStreamDestroyDeliveries, stream);
      WeakMapPrototypeDelete(streamDestroyDeliverySnapshots, stream);
    }
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

// An admission is issued only after every stable constituent guard succeeds
// under the public caller. It is closure-private and may authorize trusted
// loader transitions for that operation; package callbacks still force a live
// constituent recheck before delivery.
function createStreamUseAdmission(stream, requestedContext = undefined) {
  const current = WeakMapPrototypeGet(streamUseGuardPartLists, stream);
  const parts = [];
  const contexts = [];
  const operationContext = requestedContext ??
    activeStreamUseAdmissionContexts[
      activeStreamUseAdmissionContexts.length - 1
    ] ??
    core.ops.op_oden_schedule_context();
  if (current !== undefined) {
    const previous = operationContext === undefined
      ? undefined
      : core.getAsyncContext();
    if (operationContext !== undefined) core.setAsyncContext(operationContext);
    try {
      runInStreamUseGuardScope(() => {
        streamUseGuardRunner(stream)();
        for (let i = 0; i < current.length; i++) {
          const part = current[i];
          ArrayPrototypePush(parts, part);
          ArrayPrototypePush(
            contexts,
            WeakMapPrototypeGet(activeStreamUseGuardPartContexts, part) ??
              operationContext,
          );
        }
      });
    } finally {
      if (operationContext !== undefined) core.setAsyncContext(previous);
    }
  }
  return { context: operationContext, contexts, stream, parts };
}

function streamUseAdmissionContext(stream, admission) {
  if (admission.stream !== stream) {
    throw new TypeError("stream use admission target changed");
  }
  const current = WeakMapPrototypeGet(streamUseGuardPartLists, stream);
  const parts = admission.parts;
  if ((current?.length ?? 0) !== parts.length) {
    throw new TypeError("stream use admission constituents changed");
  }
  for (let i = 0; i < parts.length; i++) {
    if (current[i] !== parts[i]) {
      throw new TypeError("stream use admission constituents changed");
    }
  }
  if (admission.context !== undefined) return admission.context;
  // A synchronous public guard may authenticate from the live call stack even
  // when no raw schedule context exists yet. Preserve the context returned by
  // that exact successful guard as the fallback for its loader continuations.
  // Multiple constituents may collapse only when they returned the exact same
  // unforgeable snapshot. Choosing either distinct snapshot would lend that
  // actor's authority to the other constituent and make attachment order part
  // of the security decision.
  // @ref LLP 0019#operation-scoped-positive-authority-provenance [implements]
  let context;
  for (let i = 0; i < admission.contexts.length; i++) {
    const partContext = admission.contexts[i];
    if (
      partContext !== undefined && context !== undefined &&
      partContext !== context
    ) {
      throw new TypeError("stream use admission actors differ");
    }
    if (partContext !== undefined) context = partContext;
  }
  return context;
}

function runWithStreamUseAdmission(stream, admission, callback) {
  const admittedContext = streamUseAdmissionContext(stream, admission);
  const parts = admission.parts;
  const previous = admittedContext === undefined
    ? undefined
    : core.getAsyncContext();
  if (admittedContext !== undefined) core.setAsyncContext(admittedContext);
  ArrayPrototypePush(activeStreamUseAdmissionContexts, admittedContext);
  try {
    return runInStreamUseGuardScope(() => {
      for (let i = 0; i < parts.length; i++) {
        const part = parts[i];
        if (!WeakSetPrototypeHas(activeStreamUseGuardParts, part)) {
          WeakSetPrototypeAdd(activeStreamUseGuardParts, part);
          ArrayPrototypePush(activeStreamUseGuardPartList, part);
          const context = admission.contexts[i];
          if (context !== undefined) {
            WeakMapPrototypeSet(
              activeStreamUseGuardPartContexts,
              part,
              context,
            );
          }
        }
      }
      return callback();
    });
  } finally {
    ArrayPrototypePop(activeStreamUseAdmissionContexts);
    if (admittedContext !== undefined) core.setAsyncContext(previous);
  }
}

function runWithStreamUseAdmissionRecheck(
  stream,
  admission,
  callback,
) {
  const admittedContext = streamUseAdmissionContext(stream, admission);
  const previous = admittedContext === undefined
    ? undefined
    : core.getAsyncContext();
  if (admittedContext !== undefined) core.setAsyncContext(admittedContext);
  ArrayPrototypePush(activeStreamUseAdmissionContexts, admittedContext);
  try {
    return runWithForcedStreamUseGuardRecheck(() => {
      runStreamUseGuard(stream);
      return callback();
    });
  } finally {
    ArrayPrototypePop(activeStreamUseAdmissionContexts);
    if (admittedContext !== undefined) core.setAsyncContext(previous);
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

function markTrustedDeliveryCallback(callback, preflight, context = undefined) {
  WeakMapPrototypeSet(trustedDeliveryCallbacks, callback, true);
  if (context !== undefined) {
    WeakMapPrototypeSet(trustedDeliveryContexts, callback, context);
  }
  if (preflight !== undefined) {
    WeakMapPrototypeSet(trustedDeliveryPreflights, callback, preflight);
  }
  return callback;
}

function markStreamOperationIterable(iterable) {
  WeakSetPrototypeAdd(streamOperationIterables, iterable);
  return iterable;
}

function captureDeliveryCallback(callback, invoke = callback) {
  const trusted = WeakMapPrototypeGet(trustedDeliveryCallbacks, callback) ===
    true;
  return {
    callback: invoke,
    context: trusted
      ? WeakMapPrototypeGet(trustedDeliveryContexts, callback)
      : core.ops.op_oden_callback_context(callback),
    preflight: WeakMapPrototypeGet(trustedDeliveryPreflights, callback),
    trusted,
  };
}

function captureTrustedDeliveryCallback(callback, invoke = callback) {
  return {
    callback: invoke,
    context: undefined,
    preflight: WeakMapPrototypeGet(trustedDeliveryPreflights, callback),
    trusted: true,
  };
}

// Internal continuations resume the actor that initiated an operation, rather
// than the module provenance of the core callback used to implement it.
function selectCurrentDeliveryContext(scheduleContext) {
  // Package callbacks execute with their own restored CPED but can remain
  // nested inside a trusted operation admission. Never let that admission
  // replace their scheduling actor. Loader-only continuations retain the
  // scoped admission that authorized the operation.
  if (untrustedDeliveryCallbackDepth > 0) return scheduleContext;
  return activeStreamUseAdmissionContexts[
    activeStreamUseAdmissionContexts.length - 1
  ] ?? scheduleContext;
}

function captureCurrentDeliveryCallback(callback, invoke = callback) {
  // A live package frame is more specific than an enclosing trusted admission.
  // Capture it first so package work scheduled inside a root-admitted operation
  // cannot inherit the root actor. The admission remains a scoped fallback for
  // loader-only continuations whose engine snapshot is genuinely absent.
  // @ref LLP 0019#operation-scoped-positive-authority-provenance [implements]
  const scheduleContext = core.ops.op_oden_schedule_context();
  return {
    callback: invoke,
    context: selectCurrentDeliveryContext(scheduleContext),
    preflight: undefined,
    trusted: true,
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
  const callbacks = WeakMapPrototypeGet(
    streamTrustedDeliveryCallbacks,
    stream,
  );
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
  const callbacks = WeakMapPrototypeGet(
    streamCleanupDeliveryCallbacks,
    stream,
  );
  return callbacks !== undefined && WeakSetPrototypeHas(callbacks, callback);
}

function runCapturedPreflight(stream, captured) {
  runStreamUseGuard(stream);
  if (captured.preflight !== undefined) captured.preflight();
}

function preflightCapturedDelivery(stream, captured) {
  if (!hasStreamUseGuard(stream)) return;
  const preflight = () =>
    runInStreamUseGuardScope(() => {
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
    });
  return captured.trusted
    ? preflight()
    : runWithForcedStreamUseGuardRecheck(preflight);
}

function runCapturedDelivery(stream, captured, receiver, args) {
  const deliver = () => {
    if (!hasStreamUseGuard(stream)) {
      return runCapturedCallback(captured, receiver, args);
    }
    if (captured.context === undefined) {
      runCapturedPreflight(stream, captured);
      return invokeCapturedCallback(captured, receiver, args);
    }
    const previous = core.getAsyncContext();
    core.setAsyncContext(captured.context);
    try {
      runCapturedPreflight(stream, captured);
      return invokeCapturedCallback(captured, receiver, args);
    } finally {
      core.setAsyncContext(previous);
    }
  };
  return captured.trusted
    ? runInStreamUseGuardScope(deliver)
    : runWithForcedStreamUseGuardRecheck(deliver);
}

function invokeCapturedCallback(captured, receiver, args) {
  if (captured.trusted !== false || captured.context === undefined) {
    return ReflectApply(captured.callback, receiver, args);
  }
  untrustedDeliveryCallbackDepth++;
  try {
    return ReflectApply(captured.callback, receiver, args);
  } finally {
    untrustedDeliveryCallbackDepth--;
  }
}

function runCapturedCallback(captured, receiver, args) {
  if (captured.context === undefined) {
    return invokeCapturedCallback(captured, receiver, args);
  }
  const previous = core.getAsyncContext();
  core.setAsyncContext(captured.context);
  try {
    return invokeCapturedCallback(captured, receiver, args);
  } finally {
    core.setAsyncContext(previous);
  }
}

function runCapturedCleanup(captured, receiver, args) {
  return runCapturedCallback(captured, receiver, args);
}

function runCapturedCleanupResult(captured, receiver, args, project) {
  const invoke = () =>
    project(invokeCapturedCallback(captured, receiver, args));
  if (captured.context === undefined) return invoke();
  const previous = core.getAsyncContext();
  core.setAsyncContext(captured.context);
  try {
    return invoke();
  } finally {
    core.setAsyncContext(previous);
  }
}

function runIterableDelivery(target, captured, receiver, args) {
  return hasStreamUseGuard(target)
    ? runCapturedDelivery(target, captured, receiver, args)
    : runCapturedCallback(captured, receiver, args);
}

function wrapIterableDelivery(iterable, recipient) {
  const operationIterable = recipient === undefined &&
    WeakSetPrototypeHas(streamOperationIterables, iterable);
  const captureIterableCallback = (callback, invoke = callback) => {
    const captured = captureDeliveryCallback(recipient ?? callback, invoke);
    // Internal operator generators execute loader forwarding code, while their
    // application callbacks are captured and checked separately. Keep the
    // forwarding callbacks on the constituent-bound operation admission rather
    // than their loader function provenance.
    if (operationIterable) captured.context = undefined;
    return captured;
  };
  const snapshotFactories = function () {
    const asyncFactory = this?.[SymbolAsyncIterator];
    const syncFactory = typeof asyncFactory === "function"
      ? undefined
      : this?.[SymbolIterator];
    return [asyncFactory, syncFactory];
  };
  const capturedFactorySnapshot = captureIterableCallback(
    snapshotFactories,
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

  const capturedFactory = captureIterableCallback(factory, factory);
  const wrapper = {};
  const iteratorSymbol = typeof asyncFactory === "function"
    ? SymbolAsyncIterator
    : SymbolIterator;
  let deliveryAdmission;
  let seedActor;
  const runDeliveryOperation = (callback) => {
    deliveryAdmission ??= createStreamUseAdmission(wrapper, seedActor);
    return runWithStreamUseAdmission(wrapper, deliveryAdmission, callback);
  };
  // Async iterator fulfillment is a delivery boundary of the original
  // operation, so its captured actor must re-enter every live constituent
  // guard after the producer settles and before the result becomes observable.
  // @ref LLP 0019#operation-scoped-positive-authority-provenance [implements]
  const settleDeliveryOperation = (result) =>
    PromisePrototypeThen(
      PromiseResolve(result),
      (value) =>
        runWithStreamUseAdmissionRecheck(
          wrapper,
          deliveryAdmission,
          () => value,
        ),
    );
  const normalizedCleanupResult = () => ({
    done: true,
    value: undefined,
  });

  wrapper[iteratorSymbol] = function deliveryIteratorFactory() {
    const factoryAdmission = createStreamUseAdmission(wrapper, seedActor);
    return runWithStreamUseAdmission(wrapper, factoryAdmission, () => {
      const iterator = runIterableDelivery(
        wrapper,
        capturedFactory,
        iterable,
        [],
      );
      const snapshotMethods = function () {
        return [this?.next, this?.return, this?.throw];
      };
      const capturedSnapshot = captureIterableCallback(
        factory,
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
      const capturedNext = captureIterableCallback(next, next);
      const wrappedIterator = {
        next(value) {
          const result = runDeliveryOperation(() =>
            runIterableDelivery(
              wrapper,
              capturedNext,
              iterator,
              [value],
            )
          );
          return iteratorSymbol === SymbolAsyncIterator
            ? settleDeliveryOperation(result)
            : result;
        },
      };

      if (typeof iteratorReturn === "function") {
        const capturedReturn = captureIterableCallback(
          iteratorReturn,
          iteratorReturn,
        );
        wrappedIterator.return = function (value) {
          // `return` is a teardown request, not a delivery authorization. Run
          // the producer's cleanup in its captured CPED, propagate failure,
          // and discard every producer-controlled result value.
          // @ref LLP 0019#operation-scoped-positive-authority-provenance [implements]
          return runCapturedCleanupResult(
            capturedReturn,
            iterator,
            [value],
            (result) =>
              iteratorSymbol === SymbolAsyncIterator
                ? PromisePrototypeThen(
                  PromiseResolve(result),
                  normalizedCleanupResult,
                )
                : normalizedCleanupResult(),
          );
        };
      }

      if (typeof iteratorThrow === "function") {
        const capturedThrow = captureIterableCallback(
          iteratorThrow,
          iteratorThrow,
        );
        wrappedIterator.throw = function (error) {
          const result = runDeliveryOperation(() =>
            runIterableDelivery(
              wrapper,
              capturedThrow,
              iterator,
              [error],
            )
          );
          return iteratorSymbol === SymbolAsyncIterator
            ? settleDeliveryOperation(result)
            : result;
        };
      }

      wrappedIterator[iteratorSymbol] = function () {
        return this;
      };
      linkStreamUseGuard(wrapper, wrappedIterator);
      return wrappedIterator;
    });
  };

  linkStreamUseGuard(iterable, wrapper);
  const seedAdmission = createStreamUseAdmission(
    wrapper,
    capturedFactorySnapshot.context,
  );
  seedActor = streamUseAdmissionContext(wrapper, seedAdmission);
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
  createStreamUseAdmission,
  getStreamUseGuard,
  getStreamDestroyDeliverySnapshot,
  hasStreamUseGuard,
  markTrustedDeliveryCallback,
  markStreamOperationIterable,
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
  runWithStreamUseAdmission,
  runWithStreamUseAdmissionRecheck,
  setStreamUseGuard,
  wrapIterableDelivery,
};
})();

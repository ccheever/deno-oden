// deno-lint-ignore-file
// Copyright 2018-2026 the Deno authors. MIT license.

(function () {
const { core, primordials } = __bootstrap;
const lazyProcess = core.createLazyLoader("node:process");
const { nextTick: ProtectedDestroyNextTick } = core.loadExtScript(
  "ext:deno_node/_next_tick.ts",
);
const {
  protectedEventEmitterEmit,
  protectedEventEmitterListenerCount,
  protectedEventEmitterOnce,
} = core.loadExtScript("ext:deno_node/_events.mjs");
const {
  captureDeliveryCallback,
  getStreamDestroyDeliverySnapshot,
  getStreamUseGuard,
  runCapturedCleanup,
} = core.loadExtScript(
  "ext:deno_node/internal/streams/oden_delivery.js",
);
const imported1 = core.loadExtScript("ext:deno_node/internal/errors.ts");

const {
  isDestroyed,
  isFinished,
  isServerRequest,
  kAutoDestroy,
  kClosed,
  kCloseEmitted,
  kConstructed,
  kDestroyed,
  kEmitClose,
  kErrored,
  kErrorEmitted,
  kIsDestroyed,
  kState,
} = core.loadExtScript("ext:deno_node/internal/streams/utils.js");

const {
  AbortError,
  aggregateTwoErrors,
  codes: {
    ERR_MULTIPLE_CALLBACK,
  },
} = imported1;

"use strict";

const {
  FunctionPrototypeCall,
  Symbol,
  TypeError,
} = primordials;

const kDestroy = Symbol("kDestroy");
const kConstruct = Symbol("kConstruct");

function isProtectedStream(stream) {
  return getStreamUseGuard(stream) !== undefined;
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

function protectedNextTick(callback, ...args) {
  return runWithoutAsyncContext(() =>
    FunctionPrototypeCall(
      ProtectedDestroyNextTick,
      undefined,
      callback,
      ...args,
    )
  );
}

function invokeProtectedCallback(captured, receiver, args) {
  if (captured === undefined) return;
  return runWithoutAsyncContext(() =>
    runCapturedCleanup(captured, receiver, args)
  );
}

function emitProtected(stream, type, ...args) {
  return runWithoutAsyncContext(() =>
    FunctionPrototypeCall(
      protectedEventEmitterEmit,
      stream,
      type,
      ...args,
    )
  );
}

function onceProtected(stream, type, listener) {
  return runWithoutAsyncContext(() =>
    FunctionPrototypeCall(
      protectedEventEmitterOnce,
      stream,
      type,
      listener,
    )
  );
}

function findProtectedStreamStates(stream) {
  const readable = core.loadExtScript(
    "ext:deno_node/internal/streams/readable.js",
  );
  const writable = core.loadExtScript(
    "ext:deno_node/internal/streams/writable.js",
  );
  const r = readable.isRegisteredReadable(stream)
    ? readable.readableStateForStream(stream)
    : undefined;
  const w = writable.isRegisteredWritable(stream)
    ? writable.writableStateForStream(stream)
    : undefined;
  return { r, readable, w, writable };
}

function protectedStreamStates(stream) {
  const states = findProtectedStreamStates(stream);
  if (states.r === undefined && states.w === undefined) {
    throw new Error("guarded stream is missing registered state");
  }
  return states;
}

function protectedReadableEnabled(states, stream) {
  if (states.r === undefined) return false;
  const isReadableEnabled = states.readable.isReadableEnabled;
  return typeof isReadableEnabled === "function"
    ? isReadableEnabled(stream)
    : states.r.readable !== false;
}

function protectedWritableEnabled(states, stream) {
  if (states.w === undefined) return false;
  const isWritableEnabled = states.writable.isWritableEnabled;
  return typeof isWritableEnabled === "function"
    ? isWritableEnabled(stream)
    : states.w.writable !== false;
}

function checkError(err, w, r) {
  if (err) {
    // Avoid V8 leak, https://github.com/nodejs/node/pull/34103#issuecomment-652002364
    err.stack; // eslint-disable-line no-unused-expressions

    if (w && !w.errored) {
      w.errored = err;
    }
    if (r && !r.errored) {
      r.errored = err;
    }
  }
}

function checkProtectedError(err, w, r) {
  if (!err) return;
  // Error objects and compatibility accessors are package-mutable. Cleanup is
  // already running without ambient authority; make the security-relevant bit
  // transition directly and treat the public error value as best effort.
  try {
    err.stack;
  } catch {
    // Stack materialization is diagnostic only.
  }
  const setError = (state) => {
    if (!state || (state[kState] & kErrored) !== 0) return;
    state[kState] |= kErrored;
    try {
      state.errored = err;
    } catch {
      // A poisoned compatibility setter cannot prevent terminal cleanup.
    }
  };
  setError(w);
  setError(r);
}

// Backwards compat. cb() is undocumented and unused in core but
// unfortunately might be used by modules.
function destroy(err, cb) {
  if (isProtectedStream(this)) {
    return runWithoutAsyncContext(() => destroyProtected(this, err, cb));
  }
  const r = this._readableState;
  const w = this._writableState;
  // With duplex streams we use the writable side for state.
  const s = w || r;

  if (
    (w && (w[kState] & kDestroyed) !== 0) ||
    (r && (r[kState] & kDestroyed) !== 0)
  ) {
    if (typeof cb === "function") {
      cb();
    }

    return this;
  }

  // We set destroyed to true before firing error callbacks in order
  // to make it re-entrance safe in case destroy() is called within callbacks
  checkError(err, w, r);

  if (w) {
    w[kState] |= kDestroyed;
  }
  if (r) {
    r[kState] |= kDestroyed;
  }

  // If still constructing then defer calling _destroy.
  if ((s[kState] & kConstructed) === 0) {
    this.once(kDestroy, function (er) {
      _destroy(this, aggregateTwoErrors(er, err), cb);
    });
  } else {
    _destroy(this, err, cb);
  }

  return this;
}

function destroyProtected(self, err, cb) {
  // Terminal cleanup is available after revocation, but it runs with ambient
  // authority cleared, closure-owned state identity, and frozen recipients.
  // Object passage or a late bound/native method replacement cannot turn
  // destruction into one final protected read or write.
  // @ref LLP 0019#operation-scoped-positive-authority-provenance [implements]
  const { r, w } = protectedStreamStates(self);
  const s = w || r;
  const capturedCallback = typeof cb === "function"
    ? captureDeliveryCallback(cb)
    : undefined;

  if (
    (w && (w[kState] & kDestroyed) !== 0) ||
    (r && (r[kState] & kDestroyed) !== 0)
  ) {
    invokeProtectedCallback(capturedCallback, self, []);
    return self;
  }

  checkProtectedError(err, w, r);
  if (w) w[kState] |= kDestroyed;
  if (r) r[kState] |= kDestroyed;

  const frozenDestroy = getStreamDestroyDeliverySnapshot(self);
  let capturedDestroy = frozenDestroy?.captured;
  let destroyLookupError = frozenDestroy?.error;
  if (frozenDestroy === undefined) {
    let destroyMethod;
    try {
      destroyMethod = self._destroy;
      if (typeof destroyMethod !== "function") {
        destroyLookupError = new TypeError("stream._destroy is not a function");
      }
    } catch (error) {
      destroyLookupError = error;
    }
    if (destroyLookupError === undefined) {
      capturedDestroy = captureDeliveryCallback(destroyMethod);
    }
  }
  const destroyError = destroyLookupError === undefined
    ? err
    : aggregateTwoErrors(destroyLookupError, err);
  if ((s[kState] & kConstructed) === 0) {
    onceProtected(self, kDestroy, function (constructionError) {
      destroyProtectedImplementation(
        self,
        capturedDestroy,
        aggregateTwoErrors(constructionError, destroyError),
        capturedCallback,
        r,
        w,
      );
    });
  } else {
    destroyProtectedImplementation(
      self,
      capturedDestroy,
      destroyError,
      capturedCallback,
      r,
      w,
    );
  }
  return self;
}

function destroyProtectedImplementation(
  self,
  capturedDestroy,
  err,
  capturedCallback,
  r,
  w,
) {
  let called = false;
  function onDestroy(destroyError) {
    return runWithoutAsyncContext(() => {
      if (called) return;
      called = true;
      checkProtectedError(destroyError, w, r);
      if (w) w[kState] |= kClosed;
      if (r) r[kState] |= kClosed;
      invokeProtectedCallback(capturedCallback, self, [destroyError]);
      if (destroyError) {
        protectedNextTick(emitErrorCloseNT, self, destroyError, r, w, true);
      } else {
        protectedNextTick(emitCloseNT, self, r, w, true);
      }
    });
  }

  if (capturedDestroy === undefined) {
    onDestroy(err);
    return;
  }
  try {
    invokeProtectedCallback(
      capturedDestroy,
      self,
      [err || null, onDestroy],
    );
  } catch (destroyError) {
    onDestroy(destroyError);
  }
}

function _destroy(self, err, cb) {
  let called = false;

  function onDestroy(err) {
    if (called) {
      return;
    }
    called = true;

    const r = self._readableState;
    const w = self._writableState;

    checkError(err, w, r);

    if (w) {
      w[kState] |= kClosed;
    }
    if (r) {
      r[kState] |= kClosed;
    }

    if (typeof cb === "function") {
      cb(err);
    }

    if (err) {
      lazyProcess().nextTick(emitErrorCloseNT, self, err);
    } else {
      lazyProcess().nextTick(emitCloseNT, self);
    }
  }
  try {
    self._destroy(err || null, onDestroy);
  } catch (err) {
    onDestroy(err);
  }
}

function emitErrorCloseNT(self, err, r, w, protectedDelivery = false) {
  emitErrorNT(self, err, r, w, protectedDelivery);
  emitCloseNT(self, r, w, protectedDelivery);
}

function emitCloseNT(self, r, w, protectedDelivery = false) {
  if (!protectedDelivery) {
    r = self._readableState;
    w = self._writableState;
  }

  if (w) {
    w[kState] |= kCloseEmitted;
  }
  if (r) {
    r[kState] |= kCloseEmitted;
  }

  if (
    (w && (w[kState] & kEmitClose) !== 0) ||
    (r && (r[kState] & kEmitClose) !== 0)
  ) {
    if (protectedDelivery) emitProtected(self, "close");
    else self.emit("close");
  }
}

function emitErrorNT(self, err, r, w, protectedDelivery = false) {
  if (!protectedDelivery) {
    r = self._readableState;
    w = self._writableState;
  }

  if (
    (w && (w[kState] & kErrorEmitted) !== 0) ||
    (r && (r[kState] & kErrorEmitted) !== 0)
  ) {
    return;
  }

  if (w) {
    w[kState] |= kErrorEmitted;
  }
  if (r) {
    r[kState] |= kErrorEmitted;
  }

  if (protectedDelivery) emitProtected(self, "error", err);
  else self.emit("error", err);
}

function undestroy() {
  if (isProtectedStream(this)) {
    return runWithoutAsyncContext(() => {
      const states = protectedStreamStates(this);
      undestroyStates(
        states.r,
        states.w,
        protectedReadableEnabled(states, this),
        protectedWritableEnabled(states, this),
      );
    });
  }
  const r = this._readableState;
  const w = this._writableState;
  undestroyStates(r, w, r?.readable !== false, w?.writable !== false);
}

function undestroyStates(r, w, readableEnabled, writableEnabled) {
  if (r) {
    r.constructed = true;
    r.closed = false;
    r.closeEmitted = false;
    r.destroyed = false;
    r.errored = null;
    r.errorEmitted = false;
    r.reading = false;
    r.ended = !readableEnabled;
    r.endEmitted = !readableEnabled;
  }

  if (w) {
    w.constructed = true;
    w.destroyed = false;
    w.closed = false;
    w.closeEmitted = false;
    w.errored = null;
    w.errorEmitted = false;
    w.finalCalled = false;
    w.prefinished = false;
    w.ended = !writableEnabled;
    w.ending = !writableEnabled;
    w.finished = !writableEnabled;
  }
}

function errorOrDestroy(stream, err, sync) {
  if (isProtectedStream(stream)) {
    return runWithoutAsyncContext(() =>
      errorOrDestroyProtected(stream, err, sync)
    );
  }
  // We have tests that rely on errors being emitted
  // in the same tick, so changing this is semver major.
  // For now when you opt-in to autoDestroy we allow
  // the error to be emitted nextTick. In a future
  // semver major update we should change the default to this.

  const r = stream._readableState;
  const w = stream._writableState;

  if (
    (w && (w[kState] ? (w[kState] & kDestroyed) !== 0 : w.destroyed)) ||
    (r && (r[kState] ? (r[kState] & kDestroyed) !== 0 : r.destroyed))
  ) {
    return this;
  }

  if (
    (r && (r[kState] & kAutoDestroy) !== 0) ||
    (w && (w[kState] & kAutoDestroy) !== 0)
  ) {
    stream.destroy(err);
  } else if (err) {
    // Avoid V8 leak, https://github.com/nodejs/node/pull/34103#issuecomment-652002364
    err.stack; // eslint-disable-line no-unused-expressions

    if (w && (w[kState] & kErrored) === 0) {
      w.errored = err;
    }
    if (r && (r[kState] & kErrored) === 0) {
      r.errored = err;
    }
    if (sync) {
      lazyProcess().nextTick(emitErrorNT, stream, err);
    } else {
      emitErrorNT(stream, err);
    }
  }
}

function errorOrDestroyProtected(stream, err, sync) {
  const { r, w } = protectedStreamStates(stream);
  if (
    (w && (w[kState] & kDestroyed) !== 0) ||
    (r && (r[kState] & kDestroyed) !== 0)
  ) {
    return;
  }

  if (
    (r && (r[kState] & kAutoDestroy) !== 0) ||
    (w && (w[kState] & kAutoDestroy) !== 0)
  ) {
    return FunctionPrototypeCall(destroy, stream, err);
  }
  if (!err) return;

  checkProtectedError(err, w, r);
  if (sync) {
    protectedNextTick(emitErrorNT, stream, err, r, w, true);
  } else {
    emitErrorNT(stream, err, r, w, true);
  }
}

function construct(stream, cb) {
  if (isProtectedStream(stream)) {
    return runWithoutAsyncContext(() => constructProtected(stream, cb));
  }
  if (typeof stream._construct !== "function") {
    return;
  }

  const r = stream._readableState;
  const w = stream._writableState;

  if (r) {
    r[kState] &= ~kConstructed;
  }
  if (w) {
    w[kState] &= ~kConstructed;
  }

  stream.once(kConstruct, cb);

  if (stream.listenerCount(kConstruct) > 1) {
    // Duplex
    return;
  }

  lazyProcess().nextTick(constructNT, stream);
}

function constructProtected(stream, cb) {
  const { r, w } = protectedStreamStates(stream);
  const constructMethod = stream._construct;
  if (typeof constructMethod !== "function") return;
  const capturedConstruct = captureDeliveryCallback(constructMethod);

  if (r) r[kState] &= ~kConstructed;
  if (w) w[kState] &= ~kConstructed;

  onceProtected(stream, kConstruct, cb);
  const listenerCount = FunctionPrototypeCall(
    protectedEventEmitterListenerCount,
    stream,
    kConstruct,
  );
  if (listenerCount > 1) return;
  protectedNextTick(
    constructProtectedNT,
    stream,
    capturedConstruct,
    r,
    w,
  );
}

function constructProtectedNT(stream, capturedConstruct, r, w) {
  let called = false;
  function onConstruct(err) {
    return runWithoutAsyncContext(() => {
      if (called) {
        errorOrDestroyProtected(stream, err ?? new ERR_MULTIPLE_CALLBACK());
        return;
      }
      called = true;
      const s = w || r;
      if (r) r[kState] |= kConstructed;
      if (w) w[kState] |= kConstructed;
      if ((s[kState] & kDestroyed) !== 0) {
        emitProtected(stream, kDestroy, err);
      } else if (err) {
        errorOrDestroyProtected(stream, err, true);
      } else {
        emitProtected(stream, kConstruct);
      }
    });
  }

  try {
    invokeProtectedCallback(capturedConstruct, stream, [
      (err) => protectedNextTick(onConstruct, err),
    ]);
  } catch (err) {
    protectedNextTick(onConstruct, err);
  }
}

function constructNT(stream) {
  let called = false;

  function onConstruct(err) {
    if (called) {
      errorOrDestroy(stream, err ?? new ERR_MULTIPLE_CALLBACK());
      return;
    }
    called = true;

    const r = stream._readableState;
    const w = stream._writableState;
    const s = w || r;

    if (r) {
      r[kState] |= kConstructed;
    }
    if (w) {
      w[kState] |= kConstructed;
    }

    if (s.destroyed) {
      stream.emit(kDestroy, err);
    } else if (err) {
      errorOrDestroy(stream, err, true);
    } else {
      stream.emit(kConstruct);
    }
  }

  try {
    stream._construct((err) => {
      lazyProcess().nextTick(onConstruct, err);
    });
  } catch (err) {
    lazyProcess().nextTick(onConstruct, err);
  }
}

function isRequest(stream) {
  return stream?.setHeader && typeof stream.abort === "function";
}

function emitCloseLegacy(stream, protectedDelivery = false) {
  if (protectedDelivery) emitProtected(stream, "close");
  else stream.emit("close");
}

function emitErrorCloseLegacy(stream, err, protectedDelivery = false) {
  if (protectedDelivery) {
    emitProtected(stream, "error", err);
    protectedNextTick(emitCloseLegacy, stream, true);
  } else {
    stream.emit("error", err);
    lazyProcess().nextTick(emitCloseLegacy, stream);
  }
}

// Normalize destroy for legacy.
function destroyer(stream, err) {
  if (!stream) {
    return;
  }
  if (isProtectedStream(stream)) {
    return runWithoutAsyncContext(() => destroyerProtected(stream, err));
  }
  if (isDestroyed(stream)) {
    return;
  }

  if (!err && !isFinished(stream)) {
    err = new AbortError();
  }

  // TODO: Remove isRequest branches.
  if (isServerRequest(stream)) {
    stream.socket = null;
    stream.destroy(err);
  } else if (isRequest(stream)) {
    stream.abort();
  } else if (isRequest(stream.req)) {
    stream.req.abort();
  } else if (typeof stream.destroy === "function") {
    stream.destroy(err);
  } else if (typeof stream.close === "function") {
    // TODO: Don't lose err?
    stream.close();
  } else if (err) {
    lazyProcess().nextTick(emitErrorCloseLegacy, stream, err);
  } else {
    lazyProcess().nextTick(emitCloseLegacy, stream);
  }

  if (!stream.destroyed) {
    stream[kIsDestroyed] = true;
  }
}

function destroyerProtected(stream, err) {
  const states = findProtectedStreamStates(stream);
  const { r, w } = states;
  if (r !== undefined || w !== undefined) {
    if (
      (r && (r[kState] & kDestroyed) !== 0) ||
      (w && (w[kState] & kDestroyed) !== 0)
    ) {
      return;
    }

    // A cleanup-only destroy may synthesize AbortError, but it must never
    // inspect package-replaced public state or dispatch a mutable `.destroy`.
    const readableDone = !r || (r[kState] & (1 << 10)) !== 0 ||
      !protectedReadableEnabled(states, stream);
    const writableDone = !w || (w[kState] & (1 << 13)) !== 0 ||
      !protectedWritableEnabled(states, stream);
    if (!err && !(readableDone && writableDone)) {
      err = new AbortError();
    }
    return FunctionPrototypeCall(destroy, stream, err);
  }

  // Legacy/custom streams do not have a private Node state identity. Snapshot
  // one cleanup recipient while authority is cleared and invoke it in the
  // recipient's own callback context; never reload a public method later.
  let method;
  let methodAcceptsError = false;
  try {
    method = stream.destroy;
    if (typeof method === "function") {
      methodAcceptsError = true;
    } else {
      method = stream.abort;
    }
    if (typeof method !== "function") method = stream.close;
    if (typeof method !== "function") method = undefined;
  } catch (methodError) {
    method = undefined;
    err = aggregateTwoErrors(methodError, err);
  }
  if (method !== undefined) {
    const captured = captureDeliveryCallback(method);
    try {
      invokeProtectedCallback(
        captured,
        stream,
        methodAcceptsError && err !== undefined ? [err] : [],
      );
    } catch (methodError) {
      protectedNextTick(
        emitErrorCloseLegacy,
        stream,
        aggregateTwoErrors(methodError, err),
        true,
      );
    }
  } else if (err) {
    protectedNextTick(emitErrorCloseLegacy, stream, err, true);
  } else {
    protectedNextTick(emitCloseLegacy, stream, true);
  }
  try {
    stream[kIsDestroyed] = true;
  } catch {
    // The compatibility marker is best effort after cleanup was dispatched.
  }
}

const _defaultExport2 = {
  construct,
  destroyer,
  destroy,
  undestroy,
  errorOrDestroy,
};

return {
  construct,
  destroyer,
  destroy,
  undestroy,
  errorOrDestroy,
  default: _defaultExport2,
};
})();

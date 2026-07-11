// deno-lint-ignore-file
// Copyright 2018-2026 the Deno authors. MIT license.

(function () {
const { core, primordials } = __bootstrap;
const lazyProcess = core.createLazyLoader("node:process");
const { nextTick: ProtectedEosNextTick } = core.loadExtScript(
  "ext:deno_node/_next_tick.ts",
);
const {
  addEventEmitterListener,
  removeEventEmitterListener,
} = core.loadExtScript("ext:deno_node/_events.mjs");
const {
  captureDeliveryCallback,
  getStreamUseGuard,
  runCapturedCleanup,
} = core.loadExtScript(
  "ext:deno_node/internal/streams/oden_delivery.js",
);
const {
  getReadableStreamUseGuard,
  getWritableStreamUseGuard,
} = core.loadExtScript("ext:deno_web/06_streams.js");
const imported1 = core.loadExtScript("ext:deno_node/internal/errors.ts");
const { kEmptyObject, once } = core.loadExtScript(
  "ext:deno_node/internal/util.mjs",
);
const {
  validateAbortSignal,
  validateBoolean,
  validateFunction,
  validateObject,
} = core.loadExtScript("ext:deno_node/internal/validators.mjs");

const {
  isClosed,
  isNodeStream,
  isReadable,
  isReadableErrored,
  isReadableFinished,
  isReadableNodeStream,
  isReadableStream,
  isWritable,
  isWritableErrored,
  isWritableFinished,
  isWritableNodeStream,
  isWritableStream,
  kAutoDestroy,
  kClosed,
  kCloseEmitted,
  kDestroyed,
  kEmitClose,
  kErrored,
  kErrorEmitted,
  kIsClosedPromise,
  kState,
  willEmitClose: _willEmitClose,
} = core.loadExtScript("ext:deno_node/internal/streams/utils.js");

const _mod2 = core.loadExtScript(
  "ext:deno_node/internal/events/abort_listener.mjs",
);

const {
  AbortError,
  codes: {
    ERR_INVALID_ARG_TYPE,
    ERR_STREAM_PREMATURE_CLOSE,
  },
} = imported1;

// Ported from https://github.com/mafintosh/end-of-stream with
// permission from the author, Mathias Buus (@mafintosh).

"use strict";

const {
  FunctionPrototypeCall,
  Promise,
  PromisePrototypeThen,
  SymbolDispose,
} = primordials;

let addAbortListener;

const kReadableEnded = 1 << 9;
const kReadableEndEmitted = 1 << 10;
const kWritableFinished = 1 << 13;
const kWritableEnded = 1 << 30;

function runWithoutAsyncContext(run) {
  const previous = core.getAsyncContext();
  core.setAsyncContext(undefined);
  try {
    return run();
  } finally {
    core.setAsyncContext(previous);
  }
}

function hasProtectedStreamGuard(stream) {
  return getStreamUseGuard(stream) !== undefined ||
    getReadableStreamUseGuard(stream) !== undefined ||
    getWritableStreamUseGuard(stream) !== undefined;
}

function protectedNextTick(callback, ...args) {
  return runWithoutAsyncContext(() =>
    FunctionPrototypeCall(
      ProtectedEosNextTick,
      undefined,
      callback,
      ...args,
    )
  );
}

function protectedStreamStates(stream) {
  const readable = core.loadExtScript(
    "ext:deno_node/internal/streams/readable.js",
  );
  const writable = core.loadExtScript(
    "ext:deno_node/internal/streams/writable.js",
  );
  return {
    readable,
    r: readable.isRegisteredReadable(stream)
      ? readable.readableStateForStream(stream)
      : undefined,
    writable,
    w: writable.isRegisteredWritable(stream)
      ? writable.writableStateForStream(stream)
      : undefined,
  };
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

function protectedStateError(w, r) {
  const states = [w, r];
  for (let i = 0; i < states.length; i++) {
    const state = states[i];
    if (!state || (state[kState] & kErrored) === 0) continue;
    try {
      const error = state.errored;
      if (error && typeof error !== "boolean") return error;
    } catch {
      // A poisoned compatibility getter cannot block terminal observation.
    }
  }
  return undefined;
}

function isRequest(stream) {
  return stream.setHeader && typeof stream.abort === "function";
}

const nop = () => {};

function eos(stream, options, callback) {
  if (arguments.length === 2) {
    callback = options;
    options = kEmptyObject;
  } else if (options == null) {
    options = kEmptyObject;
  } else {
    validateObject(options, "options");
  }
  validateFunction(callback, "callback");

  if (hasProtectedStreamGuard(stream)) {
    return runWithoutAsyncContext(() => {
      const protectedOptions = {
        error: options.error,
        readable: options.readable,
        signal: options.signal,
        writable: options.writable,
      };
      validateAbortSignal(protectedOptions.signal, "options.signal");
      const states = protectedStreamStates(stream);
      if (states.r !== undefined || states.w !== undefined) {
        return eosProtected(stream, protectedOptions, callback, states);
      }
      if (isReadableStream(stream) || isWritableStream(stream)) {
        return eosProtectedWeb(stream, protectedOptions, callback);
      }
      if (!isNodeStream(stream)) {
        throw new ERR_INVALID_ARG_TYPE("stream", [
          "ReadableStream",
          "WritableStream",
          "Stream",
        ], stream);
      }
      return eosProtectedCustom(stream, protectedOptions, callback);
    });
  }

  validateAbortSignal(options.signal, "options.signal");

  // Capture the current async context so that the callback runs in the
  // same AsyncLocalStorage scope that was active when eos() was called.
  // In Node.js this happens automatically through the native AsyncWrap
  // layer, but Deno's ops don't propagate Node-style async context.
  const snapshot = core.getAsyncContext();
  const originalCallback = callback;
  callback = function (...args) {
    const previousContext = core.getAsyncContext();
    try {
      core.setAsyncContext(snapshot);
      return originalCallback.apply(this, args);
    } finally {
      core.setAsyncContext(previousContext);
    }
  };

  callback = once(callback);

  if (isReadableStream(stream) || isWritableStream(stream)) {
    return eosWeb(stream, options, callback);
  }

  if (!isNodeStream(stream)) {
    throw new ERR_INVALID_ARG_TYPE("stream", [
      "ReadableStream",
      "WritableStream",
      "Stream",
    ], stream);
  }

  const readable = options.readable ?? isReadableNodeStream(stream);
  const writable = options.writable ?? isWritableNodeStream(stream);

  const wState = stream._writableState;
  const rState = stream._readableState;

  const onlegacyfinish = () => {
    if (!stream.writable) {
      onfinish();
    }
  };

  // TODO (ronag): Improve soft detection to include core modules and
  // common ecosystem modules that do properly emit 'close' but fail
  // this generic check.
  let willEmitClose = _willEmitClose(stream) &&
    isReadableNodeStream(stream) === readable &&
    isWritableNodeStream(stream) === writable;

  let writableFinished = isWritableFinished(stream, false);
  const onfinish = () => {
    writableFinished = true;
    // Stream should not be destroyed here. If it is that
    // means that user space is doing something differently and
    // we cannot trust willEmitClose.
    if (stream.destroyed) {
      willEmitClose = false;
    }

    if (willEmitClose && (!stream.readable || readable)) {
      return;
    }

    if (!readable || readableFinished) {
      callback.call(stream);
    }
  };

  let readableFinished = isReadableFinished(stream, false);
  const onend = () => {
    readableFinished = true;
    // Stream should not be destroyed here. If it is that
    // means that user space is doing something differently and
    // we cannot trust willEmitClose.
    if (stream.destroyed) {
      willEmitClose = false;
    }

    if (willEmitClose && (!stream.writable || writable)) {
      return;
    }

    if (!writable || writableFinished) {
      callback.call(stream);
    }
  };

  const onerror = (err) => {
    callback.call(stream, err);
  };

  let closed = isClosed(stream);

  const onclose = () => {
    closed = true;

    const errored = isWritableErrored(stream) || isReadableErrored(stream);

    if (errored && typeof errored !== "boolean") {
      return callback.call(stream, errored);
    }

    if (readable && !readableFinished && isReadableNodeStream(stream, true)) {
      if (!isReadableFinished(stream, false)) {
        return callback.call(stream, new ERR_STREAM_PREMATURE_CLOSE());
      }
    }
    if (writable && !writableFinished) {
      if (!isWritableFinished(stream, false)) {
        return callback.call(stream, new ERR_STREAM_PREMATURE_CLOSE());
      }
    }

    callback.call(stream);
  };

  const onclosed = () => {
    closed = true;

    const errored = isWritableErrored(stream) || isReadableErrored(stream);

    if (errored && typeof errored !== "boolean") {
      return callback.call(stream, errored);
    }

    callback.call(stream);
  };

  const onrequest = () => {
    stream.req.on("finish", onfinish);
  };

  if (isRequest(stream)) {
    stream.on("complete", onfinish);
    if (!willEmitClose) {
      stream.on("abort", onclose);
    }
    if (stream.req) {
      onrequest();
    } else {
      stream.on("request", onrequest);
    }
  } else if (writable && !wState) { // legacy streams
    stream.on("end", onlegacyfinish);
    stream.on("close", onlegacyfinish);
  }

  // Not all streams will emit 'close' after 'aborted'.
  if (!willEmitClose && typeof stream.aborted === "boolean") {
    stream.on("aborted", onclose);
  }

  stream.on("end", onend);
  stream.on("finish", onfinish);
  if (options.error !== false) {
    stream.on("error", onerror);
  }
  stream.on("close", onclose);

  if (closed) {
    lazyProcess().nextTick(onclose);
  } else if (wState?.errorEmitted || rState?.errorEmitted) {
    if (!willEmitClose) {
      lazyProcess().nextTick(onclosed);
    }
  } else if (
    !readable &&
    (!willEmitClose || isReadable(stream)) &&
    (writableFinished || isWritable(stream) === false) &&
    (wState == null || wState.pendingcb === undefined || wState.pendingcb === 0)
  ) {
    lazyProcess().nextTick(onclosed);
  } else if (
    !writable &&
    (!willEmitClose || isWritable(stream)) &&
    (readableFinished || isReadable(stream) === false)
  ) {
    lazyProcess().nextTick(onclosed);
  } else if ((rState && stream.req && stream.aborted)) {
    lazyProcess().nextTick(onclosed);
  }

  const cleanup = () => {
    callback = nop;
    stream.removeListener("aborted", onclose);
    stream.removeListener("complete", onfinish);
    stream.removeListener("abort", onclose);
    stream.removeListener("request", onrequest);
    if (stream.req) stream.req.removeListener("finish", onfinish);
    stream.removeListener("end", onlegacyfinish);
    stream.removeListener("close", onlegacyfinish);
    stream.removeListener("finish", onfinish);
    stream.removeListener("end", onend);
    stream.removeListener("error", onerror);
    stream.removeListener("close", onclose);
  };

  if (options.signal && !closed) {
    const abort = () => {
      // Keep it because cleanup removes it.
      const endCallback = callback;
      cleanup();
      endCallback.call(
        stream,
        new AbortError(undefined, { cause: options.signal.reason }),
      );
    };
    if (options.signal.aborted) {
      lazyProcess().nextTick(abort);
    } else {
      addAbortListener ??= _mod2.addAbortListener;
      const disposable = addAbortListener(options.signal, abort);
      const originalCallback = callback;
      callback = once((...args) => {
        disposable[SymbolDispose]();
        originalCallback.apply(stream, args);
      });
    }
  }

  return cleanup;
}

function eosProtected(stream, options, callback, states) {
  // Lifecycle observation carries no application bytes and may continue after
  // revocation. It must nevertheless preserve private state identity and run
  // every recipient in its own provenance, never the caller's ambient grant.
  // @ref LLP 0019#operation-scoped-positive-authority-provenance [implements]
  const { r, w } = states;

  const capturedCallback = captureDeliveryCallback(callback);
  let callbackCalled = false;
  let callbackEnabled = true;
  let abortDisposable;
  function invokeCallback(...args) {
    if (callbackCalled || !callbackEnabled) return;
    callbackCalled = true;
    return runWithoutAsyncContext(() => {
      abortDisposable?.[SymbolDispose]();
      abortDisposable = undefined;
      return runCapturedCleanup(capturedCallback, stream, args);
    });
  }

  const hasReadable = protectedReadableEnabled(states, stream);
  const hasWritable = protectedWritableEnabled(states, stream);
  const readable = options.readable ?? hasReadable;
  const writable = options.writable ?? hasWritable;
  const state = w || r;
  let willEmitClose = !!state &&
    (state[kState] & (kAutoDestroy | kEmitClose | kClosed)) ===
      (kAutoDestroy | kEmitClose) &&
    hasReadable === readable && hasWritable === writable;
  let writableFinished = !writable || !w ||
    (w[kState] & kWritableFinished) !== 0 ||
    ((w[kState] & kWritableEnded) !== 0 && w.length === 0);
  let readableFinished = !readable || !r ||
    (r[kState] & kReadableEndEmitted) !== 0 ||
    ((r[kState] & kReadableEnded) !== 0 && r.length === 0);

  const streamReadable = () =>
    protectedReadableEnabled(states, stream) &&
    (r[kState] & (kReadableEndEmitted | kDestroyed)) === 0;
  const streamWritable = () =>
    protectedWritableEnabled(states, stream) &&
    (w[kState] & (kWritableEnded | kDestroyed)) === 0;

  const onfinish = () =>
    runWithoutAsyncContext(() => {
      writableFinished = true;
      if (
        (w?.[kState] & kDestroyed) !== 0 ||
        (r?.[kState] & kDestroyed) !== 0
      ) willEmitClose = false;
      if (willEmitClose && (!streamReadable() || readable)) return;
      if (!readable || readableFinished) invokeCallback();
    });
  const onend = () =>
    runWithoutAsyncContext(() => {
      readableFinished = true;
      if (
        (w?.[kState] & kDestroyed) !== 0 ||
        (r?.[kState] & kDestroyed) !== 0
      ) willEmitClose = false;
      if (willEmitClose && (!streamWritable() || writable)) return;
      if (!writable || writableFinished) invokeCallback();
    });
  const onerror = (err) => runWithoutAsyncContext(() => invokeCallback(err));
  let closed = !!state &&
    (state[kState] & (kClosed | kCloseEmitted)) !== 0;
  const onclose = () =>
    runWithoutAsyncContext(() => {
      closed = true;
      const errored = protectedStateError(w, r);
      if (errored !== undefined) {
        invokeCallback(errored);
        return;
      }
      if (readable && !readableFinished) {
        const ended = !!r && (
          (r[kState] & kReadableEndEmitted) !== 0 ||
          (r[kState] & kReadableEnded) !== 0 && r.length === 0
        );
        if (!ended) {
          invokeCallback(new ERR_STREAM_PREMATURE_CLOSE());
          return;
        }
      }
      if (writable && !writableFinished) {
        const ended = !!w && (
          (w[kState] & kWritableFinished) !== 0 ||
          (w[kState] & kWritableEnded) !== 0 && w.length === 0
        );
        if (!ended) {
          invokeCallback(new ERR_STREAM_PREMATURE_CLOSE());
          return;
        }
      }
      invokeCallback();
    });
  const onclosed = () =>
    runWithoutAsyncContext(() => {
      closed = true;
      const errored = protectedStateError(w, r);
      if (errored !== undefined) invokeCallback(errored);
      else invokeCallback();
    });

  addEventEmitterListener(stream, "end", onend);
  addEventEmitterListener(stream, "finish", onfinish);
  if (options.error !== false) {
    addEventEmitterListener(stream, "error", onerror);
  }
  addEventEmitterListener(stream, "close", onclose);

  if (closed) {
    protectedNextTick(onclose);
  } else if (
    (w && (w[kState] & kErrorEmitted) !== 0) ||
    (r && (r[kState] & kErrorEmitted) !== 0)
  ) {
    if (!willEmitClose) protectedNextTick(onclosed);
  } else if (
    !readable &&
    (!willEmitClose || streamReadable()) &&
    (writableFinished || !streamWritable()) &&
    (w == null || w.pendingcb === undefined || w.pendingcb === 0)
  ) {
    protectedNextTick(onclosed);
  } else if (
    !writable &&
    (!willEmitClose || streamWritable()) &&
    (readableFinished || !streamReadable())
  ) {
    protectedNextTick(onclosed);
  }

  const cleanup = () =>
    runWithoutAsyncContext(() => {
      callbackEnabled = false;
      abortDisposable?.[SymbolDispose]();
      abortDisposable = undefined;
      removeEventEmitterListener(stream, "end", onend);
      removeEventEmitterListener(stream, "finish", onfinish);
      removeEventEmitterListener(stream, "error", onerror);
      removeEventEmitterListener(stream, "close", onclose);
    });

  if (options.signal && !closed) {
    const abort = () =>
      runWithoutAsyncContext(() => {
        cleanup();
        callbackEnabled = true;
        invokeCallback(
          new AbortError(undefined, { cause: options.signal.reason }),
        );
      });
    if (options.signal.aborted) {
      protectedNextTick(abort);
    } else {
      addAbortListener ??= _mod2.addAbortListener;
      abortDisposable = addAbortListener(options.signal, abort);
    }
  }

  return cleanup;
}

function eosProtectedCustom(stream, options, callback) {
  const capturedCallback = captureDeliveryCallback(callback);
  const onMethod = stream.on;
  const removeMethod = stream.removeListener;
  if (typeof onMethod !== "function") {
    throw new ERR_INVALID_ARG_TYPE("stream", ["Stream"], stream);
  }
  const capturedOn = captureDeliveryCallback(onMethod);
  const capturedRemove = typeof removeMethod === "function"
    ? captureDeliveryCallback(removeMethod)
    : undefined;
  const hasReadable = isReadableNodeStream(stream);
  const hasWritable = isWritableNodeStream(stream);
  const readable = options.readable ?? hasReadable;
  const writable = options.writable ?? hasWritable;
  let readableFinished = !readable ||
    isReadableFinished(stream, false) === true;
  let writableFinished = !writable ||
    isWritableFinished(stream, false) === true;
  let closed = isClosed(stream) === true;
  let willEmitClose = _willEmitClose(stream) === true &&
    hasReadable === readable && hasWritable === writable;
  let callbackCalled = false;
  let callbackEnabled = true;
  let abortDisposable;
  const registrations = [];

  function done(err) {
    if (callbackCalled || !callbackEnabled) return;
    callbackCalled = true;
    return runWithoutAsyncContext(() => {
      abortDisposable?.[SymbolDispose]();
      abortDisposable = undefined;
      return runCapturedCleanup(
        capturedCallback,
        stream,
        err === undefined ? [] : [err],
      );
    });
  }

  const onfinish = () =>
    runWithoutAsyncContext(() => {
      writableFinished = true;
      if (stream.destroyed === true) willEmitClose = false;
      if (!willEmitClose && (!readable || readableFinished)) done();
    });
  const onend = () =>
    runWithoutAsyncContext(() => {
      readableFinished = true;
      if (stream.destroyed === true) willEmitClose = false;
      if (!willEmitClose && (!writable || writableFinished)) done();
    });
  const onerror = (err) => runWithoutAsyncContext(() => done(err));
  const onclose = () =>
    runWithoutAsyncContext(() => {
      closed = true;
      if (readable && !readableFinished) {
        done(new ERR_STREAM_PREMATURE_CLOSE());
      } else if (writable && !writableFinished) {
        done(new ERR_STREAM_PREMATURE_CLOSE());
      } else {
        done();
      }
    });

  const add = (
    target,
    capturedTargetOn,
    capturedTargetRemove,
    type,
    listener,
  ) => {
    runWithoutAsyncContext(() =>
      runCapturedCleanup(capturedTargetOn, target, [type, listener])
    );
    registrations[registrations.length] = {
      capturedRemove: capturedTargetRemove,
      listener,
      target,
      type,
    };
  };

  add(stream, capturedOn, capturedRemove, "end", onend);
  add(stream, capturedOn, capturedRemove, "finish", onfinish);
  if (options.error !== false) {
    add(stream, capturedOn, capturedRemove, "error", onerror);
  }
  add(stream, capturedOn, capturedRemove, "close", onclose);

  const cleanup = () =>
    runWithoutAsyncContext(() => {
      callbackEnabled = false;
      abortDisposable?.[SymbolDispose]();
      abortDisposable = undefined;
      for (let i = 0; i < registrations.length; i++) {
        const registration = registrations[i];
        if (registration.capturedRemove === undefined) continue;
        runCapturedCleanup(
          registration.capturedRemove,
          registration.target,
          [registration.type, registration.listener],
        );
      }
    });

  if (closed) {
    protectedNextTick(onclose);
  } else if (readableFinished && writableFinished && !willEmitClose) {
    protectedNextTick(done);
  }

  if (options.signal && !closed) {
    const abort = () =>
      runWithoutAsyncContext(() => {
        cleanup();
        callbackEnabled = true;
        done(new AbortError(undefined, { cause: options.signal.reason }));
      });
    if (options.signal.aborted) {
      protectedNextTick(abort);
    } else {
      addAbortListener ??= _mod2.addAbortListener;
      abortDisposable = addAbortListener(options.signal, abort);
    }
  }

  return cleanup;
}

function eosProtectedWeb(stream, options, callback) {
  const capturedCallback = captureDeliveryCallback(callback);
  let callbackCalled = false;
  let isAborted = false;
  let abortDisposable;
  function invokeCallback(...args) {
    if (callbackCalled) return;
    callbackCalled = true;
    return runWithoutAsyncContext(() => {
      abortDisposable?.[SymbolDispose]();
      abortDisposable = undefined;
      return runCapturedCleanup(capturedCallback, stream, args);
    });
  }

  if (options.signal) {
    const abort = () =>
      runWithoutAsyncContext(() => {
        isAborted = true;
        invokeCallback(
          new AbortError(undefined, { cause: options.signal.reason }),
        );
      });
    if (options.signal.aborted) {
      protectedNextTick(abort);
    } else {
      addAbortListener ??= _mod2.addAbortListener;
      abortDisposable = addAbortListener(options.signal, abort);
    }
  }

  const resolver = (...args) => {
    if (!isAborted) protectedNextTick(invokeCallback, ...args);
  };
  PromisePrototypeThen(
    stream[kIsClosedPromise].promise,
    resolver,
    resolver,
  );
  return () =>
    runWithoutAsyncContext(() => {
      isAborted = true;
      callbackCalled = true;
      abortDisposable?.[SymbolDispose]();
      abortDisposable = undefined;
    });
}

function eosWeb(stream, options, callback) {
  let isAborted = false;
  let abort = nop;
  if (options.signal) {
    abort = () => {
      isAborted = true;
      callback.call(
        stream,
        new AbortError(undefined, { cause: options.signal.reason }),
      );
    };
    if (options.signal.aborted) {
      lazyProcess().nextTick(abort);
    } else {
      addAbortListener ??= _mod2.addAbortListener;
      const disposable = addAbortListener(options.signal, abort);
      const originalCallback = callback;
      callback = once((...args) => {
        disposable[SymbolDispose]();
        originalCallback.apply(stream, args);
      });
    }
  }
  const resolverFn = (...args) => {
    if (!isAborted) {
      lazyProcess().nextTick(() => callback.apply(stream, args));
    }
  };
  PromisePrototypeThen(
    stream[kIsClosedPromise].promise,
    resolverFn,
    resolverFn,
  );
  return nop;
}

function finished(stream, opts) {
  let autoCleanup = false;
  if (opts === null) {
    opts = kEmptyObject;
  }
  if (opts?.cleanup) {
    validateBoolean(opts.cleanup, "cleanup");
    autoCleanup = opts.cleanup;
  }
  return new Promise((resolve, reject) => {
    const cleanup = eos(stream, opts, (err) => {
      if (autoCleanup) {
        cleanup();
      }
      if (err) {
        reject(err);
      } else {
        resolve();
      }
    });
  });
}

return {
  finished,
  eos,
  default: eos,
};
})();

// Copyright 2018-2026 the Deno authors. MIT license.
// Copyright Joyent, Inc. and other Node contributors.
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to permit
// persons to whom the Software is furnished to do so, subject to the
// following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
// NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
// USE OR OTHER DEALINGS IN THE SOFTWARE.

(function () {
const { core, primordials } = __bootstrap;
const {
  op_oden_check_protected_inspector_stream_use,
  op_stream_base_register_protected_onread,
} = core.ops;

const { ownerSymbol } = core.loadExtScript(
  "ext:deno_node/internal/async_hooks.ts",
);
// deno-lint-ignore no-unused-vars
const { HandleWrap } = core.loadExtScript(
  "ext:deno_node/internal_binding/handle_wrap.ts",
);
const {
  kArrayBufferOffset,
  kBytesWritten,
  kLastWriteWasAsync,
  kReadBytesOrError,
  streamBaseState,
  WriteWrap,
} = core.loadExtScript("ext:deno_node/internal_binding/stream_wrap.ts");
const { errnoException } = core.loadExtScript(
  "ext:deno_node/internal/errors.ts",
);
const lazyInternalTimers = () =>
  core.loadExtScript("ext:deno_node/internal/timers.mjs");
const lazyTimers = core.createLazyLoader("node:timers");
const { codeMap } = core.loadExtScript(
  "ext:deno_node/internal_binding/uv.ts",
);
const { Buffer, protectedBufferFrom: BufferFrom } = core.loadExtScript(
  "ext:deno_node/internal/buffer.mjs",
);
const { isUint8Array } = core.loadExtScript(
  "ext:deno_node/internal/util/types.ts",
);
const { validateFunction } = core.loadExtScript(
  "ext:deno_node/internal/validators.mjs",
);

const {
  Array,
  ArrayBufferPrototype,
  FunctionPrototypeBind,
  FunctionPrototypeCall,
  MapPrototypeGet,
  ObjectDefineProperty,
  ObjectPrototypeIsPrototypeOf,
  SafeWeakMap,
  Symbol,
  TypedArrayPrototypeGetBuffer,
  WeakMapPrototypeDelete,
  WeakMapPrototypeGet,
  WeakMapPrototypeSet,
} = primordials;

const kMaybeDestroy = Symbol("kMaybeDestroy");
const kUpdateTimer = Symbol("kUpdateTimer");
const kAfterAsyncWrite = Symbol("kAfterAsyncWrite");
const kBoundSession = Symbol("kBoundSession");
const kHandle = Symbol("kHandle");
const kSession = Symbol("kSession");
const kBuffer = Symbol("kBuffer");
const kBufferGen = Symbol("kBufferGen");
const kBufferCb = Symbol("kBufferCb");

// The public owner symbol and stream/handle methods are mutable. net.ts binds
// each protected handle to its exact Socket and captured internal delivery and
// cleanup functions before user code observes the connection.
const protectedStreamBindings = new SafeWeakMap();
const protectedWriteRequests = new SafeWeakMap();

function registerProtectedStreamBinding(
  handle,
  stream,
  isDestroyed,
  isEndEmitted,
  push,
  stop,
  destroy,
  finish,
  updateTimer,
  writes,
  afterAsyncWrite,
) {
  WeakMapPrototypeSet(protectedStreamBindings, handle, {
    __proto__: null,
    stream,
    isDestroyed,
    isEndEmitted,
    push,
    stop,
    destroy,
    finish,
    updateTimer,
    writes,
    afterAsyncWrite,
  });
}

function runWithoutAsyncContext(run) {
  const prior = core.getAsyncContext();
  core.setAsyncContext(undefined);
  try {
    return run();
  } finally {
    core.setAsyncContext(prior);
  }
}

// deno-lint-ignore no-explicit-any
function handleWriteReq(req: any, data: any, encoding: string) {
  const { handle } = req;
  const protectedBinding = WeakMapPrototypeGet(
    protectedStreamBindings,
    handle,
  );
  const writes = protectedBinding?.writes;

  switch (encoding) {
    case "buffer": {
      const ret = writes === undefined
        ? handle.writeBuffer(req, data)
        : writes.writeBuffer(req, data);

      if (streamBaseState[kLastWriteWasAsync]) {
        req.buffer = data;
      }

      return ret;
    }
    case "latin1":
    case "binary":
      return writes === undefined
        ? handle.writeLatin1String(req, data)
        : writes.writeLatin1String(req, data);
    case "utf8":
    case "utf-8":
      return writes === undefined
        ? handle.writeUtf8String(req, data)
        : writes.writeUtf8String(req, data);
    case "ascii":
      return writes === undefined
        ? handle.writeAsciiString(req, data)
        : writes.writeAsciiString(req, data);
    case "ucs2":
    case "ucs-2":
    case "utf16le":
    case "utf-16le":
      return writes === undefined
        ? handle.writeUcs2String(req, data)
        : writes.writeUcs2String(req, data);
    default: {
      const buffer = FunctionPrototypeCall(
        BufferFrom,
        Buffer,
        data,
        encoding,
      );
      const ret = writes === undefined
        ? handle.writeBuffer(req, buffer)
        : writes.writeBuffer(req, buffer);

      if (streamBaseState[kLastWriteWasAsync]) {
        req.buffer = buffer;
      }

      return ret;
    }
  }
}

// deno-lint-ignore no-explicit-any
function onWriteComplete(this: any, status: number) {
  const protectedRequest = WeakMapPrototypeGet(protectedWriteRequests, this);
  if (protectedRequest !== undefined) {
    WeakMapPrototypeDelete(protectedWriteRequests, this);
    return runWithoutAsyncContext(() => {
      const { binding, callback } = protectedRequest;
      if (status < 0) {
        const ex = errnoException(status, "write", this.error);
        if (typeof callback === "function") callback(ex);
        else binding.destroy(ex);
        return;
      }
      if (binding.isDestroyed()) {
        if (typeof callback === "function") callback(null);
        return;
      }
      binding.updateTimer();
      binding.afterAsyncWrite(this);
      if (typeof callback === "function") callback(null);
    });
  }

  let stream = this.handle[ownerSymbol];

  if (stream.constructor.name === "ReusedHandle") {
    stream = stream.handle;
  }

  if (status < 0) {
    const ex = errnoException(status, "write", this.error);

    if (typeof this.callback === "function") {
      this.callback(ex);
    } else {
      stream.destroy(ex);
    }

    return;
  }

  if (stream.destroyed) {
    if (typeof this.callback === "function") {
      this.callback(null);
    }

    return;
  }

  stream[kUpdateTimer]();
  stream[kAfterAsyncWrite](this);

  if (typeof this.callback === "function") {
    this.callback(null);
  }
}

function createWriteWrap(
  handle: HandleWrap,
  callback: (err?: Error | null) => void,
) {
  const req = new WriteWrap<HandleWrap>();
  const protectedBinding = WeakMapPrototypeGet(
    protectedStreamBindings,
    handle,
  );

  if (protectedBinding === undefined) {
    req.handle = handle;
    req.oncomplete = onWriteComplete;
    req.async = false;
    req.bytes = 0;
    req.buffer = null;
    req.callback = callback;
  } else {
    // Native completion reflectively reloads `oncomplete`; install exact own
    // data properties so package-mutated WriteWrap prototypes/setters cannot
    // redirect protected completion or its canonical handle.
    // @ref LLP 0019#operation-scoped-positive-authority-provenance [implements]
    for (
      const [key, value, writable] of [
        ["handle", handle, false],
        ["oncomplete", onWriteComplete, false],
        ["async", false, true],
        ["bytes", 0, true],
        ["buffer", null, true],
        ["_chunks", null, true],
        ["error", undefined, true],
        ["callback", callback, false],
      ]
    ) {
      ObjectDefineProperty(req, key, {
        __proto__: null,
        configurable: false,
        enumerable: true,
        value,
        writable,
      });
    }
    WeakMapPrototypeSet(protectedWriteRequests, req, {
      __proto__: null,
      binding: protectedBinding,
      callback,
    });
  }

  return req;
}

function writevGeneric(
  // deno-lint-ignore no-explicit-any
  owner: any,
  // deno-lint-ignore no-explicit-any
  data: any,
  cb: (err?: Error | null) => void,
  protectedHandle?: HandleWrap,
) {
  const req = createWriteWrap(protectedHandle ?? owner[kHandle], cb);
  const allBuffers = data.allBuffers;
  let chunks;

  if (allBuffers) {
    chunks = data;

    for (let i = 0; i < data.length; i++) {
      data[i] = data[i].chunk;
    }
  } else {
    chunks = new Array(data.length << 1);

    for (let i = 0; i < data.length; i++) {
      const entry = data[i];
      const enc = entry.encoding;
      // The native writev only handles utf8, latin1, ascii, ucs2, and
      // buffer.  For other encodings (base64, hex, etc.) pre-convert to
      // a Buffer so the bytes are correct on the wire.
      if (
        typeof entry.chunk === "string" && enc !== "utf8" &&
        enc !== "utf-8" && enc !== "latin1" && enc !== "binary" &&
        enc !== "ascii" && enc !== "ucs2" && enc !== "ucs-2" &&
        enc !== "utf16le" && enc !== "utf-16le" && enc !== "buffer"
      ) {
        chunks[i * 2] = FunctionPrototypeCall(
          BufferFrom,
          Buffer,
          entry.chunk,
          enc,
        );
        chunks[i * 2 + 1] = "buffer";
      } else {
        chunks[i * 2] = entry.chunk;
        chunks[i * 2 + 1] = enc;
      }
    }
  }

  const binding = WeakMapPrototypeGet(protectedStreamBindings, req.handle);
  const err = binding === undefined
    ? req.handle.writev(req, chunks, allBuffers)
    : binding.writes.writev(req, chunks, allBuffers);

  // Retain chunks
  if (err === 0) {
    req._chunks = chunks;
  }

  afterWriteDispatched(req, err, cb);

  return req;
}

function writeGeneric(
  // deno-lint-ignore no-explicit-any
  owner: any,
  // deno-lint-ignore no-explicit-any
  data: any,
  encoding: string,
  cb: (err?: Error | null) => void,
  protectedHandle?: HandleWrap,
) {
  const req = createWriteWrap(protectedHandle ?? owner[kHandle], cb);
  const err = handleWriteReq(req, data, encoding);

  afterWriteDispatched(req, err, cb);

  return req;
}

function afterWriteDispatched(
  // deno-lint-ignore no-explicit-any
  req: any,
  err: number,
  cb: (err?: Error | null) => void,
) {
  req.bytes = streamBaseState[kBytesWritten];
  req.async = !!streamBaseState[kLastWriteWasAsync];

  if (err !== 0) {
    return cb(errnoException(err, "write", req.error));
  }

  if (!req.async && typeof req.callback === "function") {
    req.callback();
  }
}

// Here we differ from Node slightly. Node makes use of the `kReadBytesOrError`
// entry of the `streamBaseState` array from the `stream_wrap` internal binding.
// Here we pass the `nread` value directly to this method as async Deno APIs
// don't grant us the ability to rely on some mutable array entry setting.
function onStreamRead(
  // deno-lint-ignore no-explicit-any
  this: any,
  arrayBuffer: Uint8Array,
  nread?: number,
  protectedInspectorPeer?: string,
) {
  // deno-lint-ignore no-this-alias
  const handle = this;
  const protectedBinding = typeof protectedInspectorPeer === "string"
    ? WeakMapPrototypeGet(protectedStreamBindings, handle)
    : undefined;
  let stream;
  if (protectedBinding !== undefined) {
    stream = protectedBinding.stream;
  } else {
    // Ordinary Node streams retain their public ownerSymbol behavior.
    stream = handle[ownerSymbol];
    if (stream.constructor.name === "ReusedHandle") {
      stream = stream.handle;
    }
  }

  if (
    typeof protectedInspectorPeer === "string" &&
    protectedBinding === undefined
  ) {
    throw new Error("protected native stream is missing its trusted binding");
  }

  // When called from the native (Rust) read callback, nread is communicated
  // via streamBaseState[kReadBytesOrError] rather than as a direct argument.
  if (nread === undefined) {
    nread = streamBaseState[kReadBytesOrError];
  }

  // Native code supplies this immutable peer argument only after accepting
  // this exact loader-authenticated callback. The callback-scoped CPED has
  // already been restored, so the recheck sees the actor that started this
  // delivery before any application byte reaches a JS buffer or stream.
  // @ref LLP 0019#operation-scoped-positive-authority-provenance [implements]
  if (typeof protectedInspectorPeer === "string" && nread > 0) {
    try {
      op_oden_check_protected_inspector_stream_use(
        protectedInspectorPeer,
        "node:net.Socket native read delivery",
      );
    } catch (error) {
      // Revocation/denial is a delivery barrier, not an uncaught native
      // callback exception. Captured functions avoid package-mutated methods.
      protectedBinding.stop();
      protectedBinding.destroy(error);
      return;
    }
  }
  if (protectedBinding === undefined) stream[kUpdateTimer]();
  else protectedBinding.updateTimer();

  const streamDestroyed = protectedBinding === undefined
    ? stream.destroyed
    : protectedBinding.isDestroyed();
  if (nread > 0 && !streamDestroyed) {
    let ret;
    let result;
    // A package can discover and mutate compatibility symbols after connect.
    // Protected native delivery never enters the onread-buffer callback path,
    // even if kBuffer is forged after the native useUserBuffer rejection.
    const userBuf = protectedBinding === undefined ? stream[kBuffer] : null;

    if (userBuf) {
      result = stream[kBufferCb](nread, userBuf) !== false;
      const bufGen = stream[kBufferGen];

      if (bufGen !== null) {
        const nextBuf = bufGen();

        if (isUint8Array(nextBuf)) {
          stream[kBuffer] = ret = nextBuf;
          // Re-point the handle at the rotated buffer so the next
          // libuv read lands in the new slab. Node's native
          // OnStreamRead consumes onread's return value here; we
          // forward it explicitly to keep the buffer hand-off
          // purely on the JS side.
          if (typeof handle.useUserBuffer === "function") {
            handle.useUserBuffer(nextBuf);
          }
        }
      }
    } else {
      const offset = streamBaseState[kArrayBufferOffset];
      // Performance note: Pass ArrayBuffer to Buffer#from to avoid
      // copy. When called from native (Rust) code, arrayBuffer is
      // already an ArrayBuffer; from JS it may be a Uint8Array.
      const ab =
        ObjectPrototypeIsPrototypeOf(ArrayBufferPrototype, arrayBuffer)
          ? arrayBuffer
          : TypedArrayPrototypeGetBuffer(arrayBuffer);
      const buf = FunctionPrototypeCall(
        BufferFrom,
        Buffer,
        ab,
        offset,
        nread,
      );
      // Ignore use of primordial here. The `push` method is from a `Readable`
      // stream instance.
      // deno-lint-ignore prefer-primordials
      result = protectedBinding === undefined
        ? stream.push(buf)
        : protectedBinding.push(stream, buf);
    }

    if (!result) {
      if (protectedBinding === undefined) handle.reading = false;

      if (!streamDestroyed) {
        const err = protectedBinding === undefined
          ? handle.readStop()
          : protectedBinding.stop();

        if (err) {
          const error = errnoException(err, "read");
          if (protectedBinding === undefined) stream.destroy(error);
          else protectedBinding.destroy(error);
        }
      }
    }

    return ret;
  }

  if (nread === 0) {
    return;
  }

  // Bytes arrived on a stream the consumer already destroyed (e.g. during a
  // re-entrant handshake callback that called socket.destroy()). Drop them;
  // forwarding a positive nread to errnoException would raise RangeError.
  if (nread > 0) {
    return;
  }

  if (nread !== MapPrototypeGet(codeMap, "EOF")) {
    // CallJSOnreadMethod expects the return value to be a buffer.
    // Ref: https://github.com/nodejs/node/pull/34375
    const error = errnoException(nread, "read");
    if (protectedBinding === undefined) stream.destroy(error);
    else protectedBinding.destroy(error);

    return;
  }

  if (protectedBinding !== undefined) {
    // Protected EOF stays entirely on the closure-owned path: private state,
    // captured push/read implementations, and no reflected kMaybeDestroy
    // lookup that package code could replace before the native callback.
    if (!protectedBinding.isEndEmitted()) {
      protectedBinding.finish();
    }
    return;
  }

  // Ordinary streams retain Node's public compatibility hooks.
  // Defer this until we actually emit end.
  const readableState = stream._readableState;
  if (readableState.endEmitted) {
    if (stream[kMaybeDestroy]) {
      stream[kMaybeDestroy]();
    }
  } else {
    if (stream[kMaybeDestroy]) {
      stream.on("end", stream[kMaybeDestroy]);
    }

    // Push a null to signal the end of data.
    // Do it before `maybeDestroy` for correct order of events:
    // `end` -> `close`
    // Ignore use of primordial. The `push` method is from a `Readable` stream
    // instance.
    // deno-lint-ignore prefer-primordials
    stream.push(null);
    stream.read(0);
  }
}

if (!op_stream_base_register_protected_onread(onStreamRead)) {
  throw new Error("failed to register protected native stream callback");
}

function setStreamTimeout(
  // deno-lint-ignore no-explicit-any
  this: any,
  msecs: number,
  callback?: () => void,
) {
  if (this.destroyed) {
    return this;
  }

  this.timeout = msecs;

  // Type checking identical to timers.enroll()
  msecs = lazyInternalTimers().getTimerDuration(msecs, "msecs");

  // Attempt to clear an existing timer in both cases -
  //  even if it will be rescheduled we don't want to leak an existing timer.
  lazyTimers().clearTimeout(this[lazyInternalTimers().kTimeout]);

  if (msecs === 0) {
    if (callback !== undefined) {
      validateFunction(callback, "callback");
      this.removeListener("timeout", callback);
    }
  } else {
    this[lazyInternalTimers().kTimeout] = lazyInternalTimers()
      .setUnrefTimeout(
        FunctionPrototypeBind(this._onTimeout, this),
        msecs,
      );

    if (this[kSession]) {
      this[kSession][kUpdateTimer]();
    }

    if (callback !== undefined) {
      validateFunction(callback, "callback");
      this.once("timeout", callback);
    }
  }

  return this;
}

return {
  kMaybeDestroy,
  kUpdateTimer,
  kAfterAsyncWrite,
  kBoundSession,
  kHandle,
  kSession,
  kBuffer,
  kBufferGen,
  kBufferCb,
  writevGeneric,
  writeGeneric,
  onStreamRead,
  registerProtectedStreamBinding,
  setStreamTimeout,
};
})();

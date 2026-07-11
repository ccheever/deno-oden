// deno-lint-ignore-file
// Copyright 2018-2026 the Deno authors. MIT license.

(function () {
const { core, primordials } = __bootstrap;
const lazyProcess = core.createLazyLoader("node:process");
const process = lazyProcess().default;
const { nextTick: ProtectedReadableNextTick } = core.loadExtScript(
  "ext:deno_node/_next_tick.ts",
);
const {
  addEventEmitterListener,
  emitPreparedEvent,
  EventEmitter: EE,
  isEventEmitterPublicEmit,
  isEventEmitterPublicLifecycleMethod,
  isEventEmitterPublicListenerCount,
  prepareEventListenerDelivery,
  protectedEventEmitterEmit,
  protectedEventEmitterListenerCount,
  removeEventEmitterListener,
  setEventListenerDeliveryHook,
} = core.loadExtScript("ext:deno_node/_events.mjs");
const { Stream } = core.loadExtScript(
  "ext:deno_node/internal/streams/legacy.js",
);
const {
  Buffer,
  protectedBufferAlloc,
  protectedBufferAllocUnsafe,
  protectedBufferFrom,
  protectedBufferIsBuffer,
  protectedBufferIsEncoding,
  protectedBufferToString,
  protectedFastBuffer,
} = core.loadExtScript("ext:deno_node/internal/buffer.mjs");
const { addAbortSignal } = core.loadExtScript(
  "ext:deno_node/internal/streams/add-abort-signal.js",
);
const eos =
  core.loadExtScript("ext:deno_node/internal/streams/end-of-stream.js")
    .default;
const destroyImpl =
  core.loadExtScript("ext:deno_node/internal/streams/destroy.js").default;
const {
  getDefaultHighWaterMark,
  getHighWaterMark,
} = core.loadExtScript("ext:deno_node/internal/streams/state.js");

const {
  kAutoDestroy,
  kClosed,
  kCloseEmitted,
  kConstructed,
  kDestroyed,
  kEmitClose,
  kErrored,
  kErrorEmitted,
  kObjectMode,
  kOnConstructed,
  kState,
} = core.loadExtScript("ext:deno_node/internal/streams/utils.js");

const imported1 = core.loadExtScript("ext:deno_node/internal/errors.ts");
const { validateObject } = core.loadExtScript(
  "ext:deno_node/internal/validators.mjs",
);
const {
  endStringDecoder,
  StringDecoder,
  transferStringDecoder,
  writeStringDecoder,
} = core.loadExtScript("ext:deno_node/string_decoder.ts");
const lazyFrom = core.createLazyLoader(
  "ext:deno_node/internal/streams/from.js",
);
const _mod2 = core.loadExtScript("ext:deno_node/internal/util/debuglog.ts");
const webStreamsAdaptersSpecifier =
  "ext:deno_node/internal/webstreams/adapters.js";
const {
  captureCurrentDeliveryCallback,
  captureDeliveryCallback,
  captureTrustedDeliveryCallback,
  getStreamUseGuard,
  linkStreamUseGuard,
  markTrustedDeliveryCallback,
  isStreamTrustedDeliveryCallback,
  markStreamTrustedDeliveryCallback,
  preflightCapturedDelivery,
  preflightStreamDelivery,
  registerStreamDeliveryPreflight,
  registerStreamGuardAttachHook,
  runCapturedCallback,
  runCapturedDelivery,
  runStreamUseGuard,
  setStreamUseGuard,
  wrapIterableDelivery,
} = core.loadExtScript(
  "ext:deno_node/internal/streams/oden_delivery.js",
);

const {
  AbortError,
  aggregateTwoErrors,
  codes: {
    ERR_INVALID_ARG_TYPE,
    ERR_METHOD_NOT_IMPLEMENTED,
    ERR_OUT_OF_RANGE,
    ERR_STREAM_PUSH_AFTER_EOF,
    ERR_STREAM_UNSHIFT_AFTER_END_EVENT,
    ERR_UNKNOWN_ENCODING,
  },
} = imported1;

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

"use strict";

const {
  ArrayBufferIsView,
  ArrayPrototypeIndexOf,
  ArrayPrototypePush,
  ArrayPrototypeSlice,
  ArrayPrototypeSplice,
  ArrayPrototypeUnshift,
  DataViewPrototypeGetBuffer,
  DataViewPrototypeGetByteLength,
  DataViewPrototypeGetByteOffset,
  FunctionPrototypeBind,
  FunctionPrototypeCall,
  NumberIsInteger,
  NumberIsNaN,
  NumberParseInt,
  ObjectDefineProperties,
  ObjectKeys,
  ObjectSetPrototypeOf,
  Promise,
  ReflectApply,
  SafeSet,
  SafeWeakMap,
  StringPrototypeSlice,
  Symbol,
  SymbolAsyncDispose,
  SymbolAsyncIterator,
  SymbolSpecies,
  TypedArrayPrototypeGetBuffer,
  TypedArrayPrototypeGetByteLength,
  TypedArrayPrototypeGetByteOffset,
  TypedArrayPrototypeSet,
  WeakMapPrototypeDelete,
  WeakMapPrototypeGet,
  WeakMapPrototypeSet,
} = primordials;

Readable.ReadableState = ReadableState;

let debug = _mod2.debuglog("stream", (fn) => {
  debug = fn;
});

const FastBuffer = protectedFastBuffer ?? Buffer[SymbolSpecies];
const BufferAlloc = protectedBufferAlloc ?? Buffer.alloc;
const BufferAllocUnsafe = protectedBufferAllocUnsafe ?? Buffer.allocUnsafe;
const BufferFrom = Buffer.from;
const BufferIsBuffer = protectedBufferIsBuffer ?? Buffer.isBuffer;
const BufferIsEncoding = protectedBufferIsEncoding ?? Buffer.isEncoding;
const BufferPrototypeToString = protectedBufferToString ??
  Buffer.prototype.toString;
const isTypedArray = core.isTypedArray;
let ReadablePrototypeRead;
let ReadablePrototypePush;
let ReadablePublicAsyncIterator;
let ReadablePublicOff;
let ReadablePublicOn;
let ReadablePublicPipe;
let ReadablePublicRemoveListener;
let ReadablePublicUnpipe;
let ReadablePrototypePause;
let ReadablePrototypeResume;

function bufferAlloc(length) {
  return FunctionPrototypeCall(BufferAlloc, Buffer, length);
}

function bufferAllocUnsafe(length) {
  return FunctionPrototypeCall(BufferAllocUnsafe, Buffer, length);
}

function bufferFrom(value, encodingOrOffset, length) {
  return FunctionPrototypeCall(
    protectedBufferFrom ?? BufferFrom,
    Buffer,
    value,
    encodingOrOffset,
    length,
  );
}

function bufferFromArrayBufferView(view) {
  const typedArray = isTypedArray(view);
  return bufferFrom(
    typedArray
      ? TypedArrayPrototypeGetBuffer(view)
      : DataViewPrototypeGetBuffer(view),
    typedArray
      ? TypedArrayPrototypeGetByteOffset(view)
      : DataViewPrototypeGetByteOffset(view),
    typedArray
      ? TypedArrayPrototypeGetByteLength(view)
      : DataViewPrototypeGetByteLength(view),
  );
}

function bufferToString(buffer, encoding) {
  return FunctionPrototypeCall(BufferPrototypeToString, buffer, encoding);
}

function readableChunkLength(state, chunk) {
  if ((state[kState] & kObjectMode) !== 0) return 1;
  if (typeof chunk === "string") return chunk.length;
  return getGuardedReadableState(state) === undefined
    ? chunk.length
    : TypedArrayPrototypeGetByteLength(chunk);
}

function readableBufferChunkLength(state, chunk) {
  if ((state[kState] & kDecoder) !== 0) return chunk.length;
  return getGuardedReadableState(state) === undefined
    ? chunk.length
    : TypedArrayPrototypeGetByteLength(chunk);
}

function readableBufferView(state, data, offset = 0, length) {
  if (getGuardedReadableState(state) === undefined) {
    return new FastBuffer(
      data.buffer,
      data.byteOffset + offset,
      length ?? data.length - offset,
    );
  }
  const byteOffset = TypedArrayPrototypeGetByteOffset(data);
  const byteLength = TypedArrayPrototypeGetByteLength(data);
  return new FastBuffer(
    TypedArrayPrototypeGetBuffer(data),
    byteOffset + offset,
    length ?? byteLength - offset,
  );
}

ObjectSetPrototypeOf(Readable.prototype, Stream.prototype);
ObjectSetPrototypeOf(Readable, Stream);
const nop = () => {};
const directEventDeliverySentinel = FunctionPrototypeBind(nop, undefined);

function nextTickWithCurrent(callback, ...args) {
  const captured = captureCurrentDeliveryCallback(callback);
  scheduleCapturedNextTick(captured, args);
}

function nextTickWithContext(context, callback, ...args) {
  const captured = context === undefined
    ? captureCurrentDeliveryCallback(callback)
    : { callback, context, preflight: undefined };
  scheduleCapturedNextTick(captured, args);
}

function scheduleCapturedNextTick(captured, args) {
  FunctionPrototypeCall(
    ProtectedReadableNextTick,
    process,
    () => runCapturedCallback(captured, undefined, args),
  );
}

// Protected native sockets can otherwise prefetch into this module's JS
// buffer under the creator's context and later expose those bytes through a
// passed Readable. Keep closure-private per-consumer guards and run them before
// any public operation can start flow or dequeue buffered data.
// @ref LLP 0019#operation-scoped-positive-authority-provenance [implements]
const guardedReadableStates = new SafeWeakMap();
const originalReadableStates = new SafeWeakMap();
// Native EOF cleanup is allowed after revocation, but it must still use the
// construction-time state and captured implementation. The override is
// closure-private and exists only for that exact terminal transition.
const protectedReadableOperationStates = new SafeWeakMap();

function registerReadableState(stream, state) {
  const registered = WeakMapPrototypeGet(originalReadableStates, stream);
  if (registered !== undefined && registered !== state) {
    throw new Error("Readable state identity changed");
  }
  WeakMapPrototypeSet(originalReadableStates, stream, state);
}

function readableStateForStream(stream) {
  const operationState = WeakMapPrototypeGet(
    protectedReadableOperationStates,
    stream,
  );
  if (operationState !== undefined) return operationState;
  const original = WeakMapPrototypeGet(originalReadableStates, stream);
  return original !== undefined && getStreamUseGuard(stream) !== undefined
    ? original
    : stream._readableState;
}

function isRegisteredReadable(stream) {
  return WeakMapPrototypeGet(originalReadableStates, stream) !== undefined;
}

function isReadableDestroyed(stream) {
  const state = WeakMapPrototypeGet(originalReadableStates, stream);
  return state === undefined || (state[kState] & kDestroyed) !== 0;
}

function isReadableActive(stream) {
  const state = WeakMapPrototypeGet(originalReadableStates, stream);
  return state !== undefined && state.readable !== false &&
    (state[kState] & (kDestroyed | kErrored | kErrorEmitted | kEndEmitted)) ===
      0;
}

function readableObjectMode(stream) {
  const state = WeakMapPrototypeGet(originalReadableStates, stream);
  return state !== undefined && (state[kState] & kObjectMode) !== 0;
}

function readableHighWaterMark(stream) {
  const state = WeakMapPrototypeGet(originalReadableStates, stream);
  return state?.highWaterMark;
}

// Native callers only need an admission signal. Never return the retained
// ReadableState object across this internal boundary.
function getProtectedReadableState(stream) {
  return isRegisteredReadable(stream) ? true : undefined;
}

function isProtectedReadableDestroyed(stream) {
  const state = WeakMapPrototypeGet(originalReadableStates, stream);
  return state === undefined || (state[kState] & kDestroyed) !== 0;
}

function isProtectedReadableEndEmitted(stream) {
  const state = WeakMapPrototypeGet(originalReadableStates, stream);
  return state === undefined || (state[kState] & kEndEmitted) !== 0;
}

function shouldStartProtectedReadable(stream) {
  const state = WeakMapPrototypeGet(originalReadableStates, stream);
  return state !== undefined && (state[kState] & kPaused) === 0 &&
    (state[kState] & (kDataListening | kReadableListening)) !== 0;
}

function hasProtectedReadableDecoder(stream) {
  const state = WeakMapPrototypeGet(originalReadableStates, stream);
  return state !== undefined && (state[kState] & kDecoder) !== 0;
}

function getReadableOperationState(stream) {
  const state = readableStateForStream(stream);
  if (state === undefined) {
    throw new Error("guarded Readable is missing registered state");
  }
  return state;
}

function isReadablePublicRead(callback) {
  return callback === ReadablePrototypeRead;
}

function isReadablePublicPush(callback) {
  return callback === ReadablePrototypePush;
}

function isReadablePublicLifecycleMethod(callback) {
  return callback === ReadablePublicOn || callback === ReadablePublicOff ||
    callback === ReadablePublicRemoveListener;
}

function isReadablePublicPipe(callback) {
  return callback === ReadablePublicPipe;
}

function isReadablePublicUnpipe(callback) {
  return callback === ReadablePublicUnpipe;
}

function isReadablePublicPause(callback) {
  return callback === ReadablePrototypePause;
}

function isReadablePublicResume(callback) {
  return callback === ReadablePrototypeResume;
}

function pauseReadable(stream) {
  return FunctionPrototypeCall(ReadablePrototypePause, stream);
}

function resumeReadable(stream) {
  return FunctionPrototypeCall(ReadablePrototypeResume, stream);
}

function addReadableListener(stream, type, listener) {
  return FunctionPrototypeCall(ReadablePublicOn, stream, type, listener);
}

function createReadableAsyncIterator(stream) {
  return FunctionPrototypeCall(ReadablePublicAsyncIterator, stream);
}

function getReadableUseGuard(source) {
  return getStreamUseGuard(source);
}

function setReadableUseGuard(stream, guard) {
  setStreamUseGuard(stream, guard);
}

function runReadableUseGuard(stream) {
  return runStreamUseGuard(stream);
}

function getGuardedReadableState(state) {
  return WeakMapPrototypeGet(guardedReadableStates, state);
}

function readableStateBuffer(state) {
  const guarded = getGuardedReadableState(state);
  if (guarded === undefined) return state.buffer;
  runStreamUseGuard(guarded.stream);
  return guarded.buffer;
}

function readableStateBufferIndex(state) {
  const guarded = getGuardedReadableState(state);
  if (guarded === undefined) return state.bufferIndex;
  runStreamUseGuard(guarded.stream);
  return guarded.bufferIndex;
}

function setReadableStateBufferIndex(state, index) {
  const guarded = getGuardedReadableState(state);
  if (guarded === undefined) state.bufferIndex = index;
  else {
    runStreamUseGuard(guarded.stream);
    guarded.bufferIndex = index;
  }
}

function writeReadableStateDecoder(state, chunk) {
  const guarded = getGuardedReadableState(state);
  if (guarded === undefined) return state[kDecoderValue].write(chunk);
  runStreamUseGuard(guarded.stream);
  return writeStringDecoder(guarded.decoder, chunk);
}

function endReadableStateDecoder(state) {
  const guarded = getGuardedReadableState(state);
  if (guarded === undefined) return state[kDecoderValue].end();
  runStreamUseGuard(guarded.stream);
  return endStringDecoder(guarded.decoder);
}

function setReadableStateDecoder(state, value) {
  const guarded = getGuardedReadableState(state);
  if (guarded === undefined) {
    state[kDecoderValue] = value;
  } else {
    runStreamUseGuard(guarded.stream);
    guarded.decoder = value ? transferStringDecoder(value) : null;
    state[kDecoderValue] = null;
  }
  if (value) state[kState] |= kDecoder;
  else state[kState] &= ~kDecoder;
}

function protectReadableState(stream, guard = undefined) {
  const state = WeakMapPrototypeGet(originalReadableStates, stream);
  if (state === undefined) return;
  if (getGuardedReadableState(state) === undefined) {
    const publicBuffer = state.buffer;
    const privateBuffer = ArrayPrototypeSlice(
      publicBuffer,
      state.bufferIndex,
    );
    const decoder = (state[kState] & kDecoder) !== 0
      ? transferStringDecoder(state[kDecoderValue])
      : null;
    // Clear every retained reference synchronously before the guard becomes
    // visible. The public fields remain compatibility-shaped decoys; all
    // engine paths switch to the closure-private record below.
    publicBuffer.length = 0;
    state.buffer = [];
    state.bufferIndex = 0;
    state[kDecoderValue] = null;
    WeakMapPrototypeSet(guardedReadableStates, state, {
      buffer: privateBuffer,
      bufferIndex: 0,
      decoder,
      stream,
    });
  }
  if (guard !== undefined) {
    for (let i = 0; i < state.pipes.length; i++) {
      setStreamUseGuard(state.pipes[i], guard);
    }
  }
}

function installReadableDeliveryHook(stream) {
  setEventListenerDeliveryHook(stream, {
    isProtected() {
      return getStreamUseGuard(stream) !== undefined;
    },
    capture(type, recipient, listener = recipient, direct = false) {
      const captured = captureDeliveryCallback(
        type === "data" && direct ? directEventDeliverySentinel : recipient,
        listener,
      );
      if (type !== "data") {
        // Lifecycle events carry no queued bytes, so they need no read
        // preflight. They still restore the exact listener CPED so native or
        // root-side emission cannot lend ambient authority to callback work.
        // @ref LLP 0019#operation-scoped-positive-authority-provenance [implements]
        return {
          invoke(receiver, args) {
            return getStreamUseGuard(stream) === undefined
              ? ReflectApply(captured.callback, receiver, args)
              : runCapturedCallback(captured, receiver, args);
          },
          preflight: nop,
        };
      }
      return {
        invoke(receiver, args) {
          return runCapturedDelivery(stream, captured, receiver, args);
        },
        preflight() {
          preflightCapturedDelivery(stream, captured);
        },
      };
    },
    captureRejection() {
      if (getStreamUseGuard(stream) === undefined) return undefined;
      const recipient = stream[EE.captureRejectionSymbol];
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
  });
}

function emitReadableData(stream, chunk) {
  const listeners = prepareEventListenerDelivery(stream, "data");
  return emitPreparedEvent(stream, "data", [chunk], listeners);
}

const { errorOrDestroy } = destroyImpl;

const kErroredValue = Symbol("kErroredValue");
const kDefaultEncodingValue = Symbol("kDefaultEncodingValue");
const kDecoderValue = Symbol("kDecoderValue");
const kEncodingValue = Symbol("kEncodingValue");

const kEnded = 1 << 9;
const kEndEmitted = 1 << 10;
const kReading = 1 << 11;
const kSync = 1 << 12;
const kNeedReadable = 1 << 13;
const kEmittedReadable = 1 << 14;
const kReadableListening = 1 << 15;
const kResumeScheduled = 1 << 16;
const kMultiAwaitDrain = 1 << 17;
const kReadingMore = 1 << 18;
const kDataEmitted = 1 << 19;
const kDefaultUTF8Encoding = 1 << 20;
const kDecoder = 1 << 21;
const kEncoding = 1 << 22;
const kHasFlowing = 1 << 23;
const kFlowing = 1 << 24;
const kHasPaused = 1 << 25;
const kPaused = 1 << 26;
const kDataListening = 1 << 27;

// TODO(benjamingr) it is likely slower to do it this way than with free functions
function makeBitMapDescriptor(bit) {
  return {
    enumerable: false,
    get() {
      return (this[kState] & bit) !== 0;
    },
    set(value) {
      if (value) this[kState] |= bit;
      else this[kState] &= ~bit;
    },
  };
}
ObjectDefineProperties(ReadableState.prototype, {
  objectMode: makeBitMapDescriptor(kObjectMode),
  ended: makeBitMapDescriptor(kEnded),
  endEmitted: makeBitMapDescriptor(kEndEmitted),
  reading: makeBitMapDescriptor(kReading),
  // Stream is still being constructed and cannot be
  // destroyed until construction finished or failed.
  // Async construction is opt in, therefore we start as
  // constructed.
  constructed: makeBitMapDescriptor(kConstructed),
  // A flag to be able to tell if the event 'readable'/'data' is emitted
  // immediately, or on a later tick.  We set this to true at first, because
  // any actions that shouldn't happen until "later" should generally also
  // not happen before the first read call.
  sync: makeBitMapDescriptor(kSync),
  // Whenever we return null, then we set a flag to say
  // that we're awaiting a 'readable' event emission.
  needReadable: makeBitMapDescriptor(kNeedReadable),
  emittedReadable: makeBitMapDescriptor(kEmittedReadable),
  readableListening: makeBitMapDescriptor(kReadableListening),
  resumeScheduled: makeBitMapDescriptor(kResumeScheduled),
  // True if the error was already emitted and should not be thrown again.
  errorEmitted: makeBitMapDescriptor(kErrorEmitted),
  emitClose: makeBitMapDescriptor(kEmitClose),
  autoDestroy: makeBitMapDescriptor(kAutoDestroy),
  // Has it been destroyed.
  destroyed: makeBitMapDescriptor(kDestroyed),
  // Indicates whether the stream has finished destroying.
  closed: makeBitMapDescriptor(kClosed),
  // True if close has been emitted or would have been emitted
  // depending on emitClose.
  closeEmitted: makeBitMapDescriptor(kCloseEmitted),
  multiAwaitDrain: makeBitMapDescriptor(kMultiAwaitDrain),
  // If true, a maybeReadMore has been scheduled.
  readingMore: makeBitMapDescriptor(kReadingMore),
  dataEmitted: makeBitMapDescriptor(kDataEmitted),

  // Indicates whether the stream has errored. When true no further
  // _read calls, 'data' or 'readable' events should occur. This is needed
  // since when autoDestroy is disabled we need a way to tell whether the
  // stream has failed.
  errored: {
    __proto__: null,
    enumerable: false,
    get() {
      return (this[kState] & kErrored) !== 0 ? this[kErroredValue] : null;
    },
    set(value) {
      if (value) {
        this[kErroredValue] = value;
        this[kState] |= kErrored;
      } else {
        this[kState] &= ~kErrored;
      }
    },
  },

  defaultEncoding: {
    __proto__: null,
    enumerable: false,
    get() {
      return (this[kState] & kDefaultUTF8Encoding) !== 0
        ? "utf8"
        : this[kDefaultEncodingValue];
    },
    set(value) {
      if (value === "utf8" || value === "utf-8") {
        this[kState] |= kDefaultUTF8Encoding;
      } else {
        this[kState] &= ~kDefaultUTF8Encoding;
        this[kDefaultEncodingValue] = value;
      }
    },
  },

  decoder: {
    __proto__: null,
    enumerable: false,
    get() {
      const guarded = getGuardedReadableState(this);
      if (guarded === undefined) {
        return (this[kState] & kDecoder) !== 0 ? this[kDecoderValue] : null;
      }
      runStreamUseGuard(guarded.stream);
      return (this[kState] & kDecoder) !== 0
        ? new StringDecoder(guarded.decoder.encoding)
        : null;
    },
    set(value) {
      setReadableStateDecoder(this, value);
    },
  },

  encoding: {
    __proto__: null,
    enumerable: false,
    get() {
      return (this[kState] & kEncoding) !== 0 ? this[kEncodingValue] : null;
    },
    set(value) {
      if (value) {
        this[kEncodingValue] = value;
        this[kState] |= kEncoding;
      } else {
        this[kState] &= ~kEncoding;
      }
    },
  },

  flowing: {
    __proto__: null,
    enumerable: false,
    get() {
      return (this[kState] & kHasFlowing) !== 0
        ? (this[kState] & kFlowing) !== 0
        : null;
    },
    set(value) {
      if (value == null) {
        this[kState] &= ~(kHasFlowing | kFlowing);
      } else if (value) {
        this[kState] |= kHasFlowing | kFlowing;
      } else {
        this[kState] |= kHasFlowing;
        this[kState] &= ~kFlowing;
      }
    },
  },
});

function ReadableState(options, stream, isDuplex) {
  // Bit map field to store ReadableState more efficiently with 1 bit per field
  // instead of a V8 slot per field.
  this[kState] = kEmitClose | kAutoDestroy | kConstructed | kSync;
  WeakMapPrototypeSet(originalReadableStates, stream, this);
  markStreamTrustedDeliveryCallback(
    stream,
    Readable.prototype[EE.captureRejectionSymbol],
  );

  // Object stream flag. Used to make read(n) ignore n and to
  // make all the buffer merging and length checks go away.
  if (options?.objectMode) {
    this[kState] |= kObjectMode;
  }

  if (isDuplex && options?.readableObjectMode) {
    this[kState] |= kObjectMode;
  }

  // The point at which it stops calling _read() to fill the buffer
  // Note: 0 is a valid value, means "don't call _read preemptively ever"
  this.highWaterMark = options
    ? getHighWaterMark(this, options, "readableHighWaterMark", isDuplex)
    : getDefaultHighWaterMark(false);

  this.buffer = [];
  this.bufferIndex = 0;
  this.length = 0;
  this.pipes = [];

  // Should close be emitted on destroy. Defaults to true.
  if (options && options.emitClose === false) this[kState] &= ~kEmitClose;

  // Should .destroy() be called after 'end' (and potentially 'finish').
  if (options && options.autoDestroy === false) this[kState] &= ~kAutoDestroy;

  // Crypto is kind of old and crusty.  Historically, its default string
  // encoding is 'binary' so we have to make this configurable.
  // Everything else in the universe uses 'utf8', though.
  const defaultEncoding = options?.defaultEncoding;
  if (
    defaultEncoding == null || defaultEncoding === "utf8" ||
    defaultEncoding === "utf-8"
  ) {
    this[kState] |= kDefaultUTF8Encoding;
  } else if (BufferIsEncoding(defaultEncoding)) {
    this.defaultEncoding = defaultEncoding;
  } else {
    throw new ERR_UNKNOWN_ENCODING(defaultEncoding);
  }

  // Ref the piped dest which we need a drain event on it
  // type: null | Writable | Set<Writable>.
  this.awaitDrainWriters = null;

  if (options?.encoding) {
    this.decoder = new StringDecoder(options.encoding);
    this.encoding = options.encoding;
  }

  registerStreamGuardAttachHook(
    stream,
    (guard) => protectReadableState(stream, guard),
  );
  registerStreamDeliveryPreflight(
    stream,
    () => prepareEventListenerDelivery(stream, "data"),
  );
  installReadableDeliveryHook(stream);
}

ReadableState.prototype[kOnConstructed] = function onConstructed(stream) {
  if ((this[kState] & kNeedReadable) !== 0) {
    maybeReadMore(stream, this);
  }
};

function Readable(options) {
  if (!(this instanceof Readable)) {
    return new Readable(options);
  }

  this._events ??= {
    close: undefined,
    error: undefined,
    data: undefined,
    end: undefined,
    readable: undefined,
    // Skip uncommon events...
    // pause: undefined,
    // resume: undefined,
    // pipe: undefined,
    // unpipe: undefined,
    // [destroyImpl.kConstruct]: undefined,
    // [destroyImpl.kDestroy]: undefined,
  };

  this._readableState = new ReadableState(options, this, false);
  registerReadableState(this, this._readableState);

  if (options) {
    if (typeof options.read === "function") {
      this._read = options.read;
    }

    if (typeof options.destroy === "function") {
      this._destroy = options.destroy;
    }

    if (typeof options.construct === "function") {
      this._construct = options.construct;
    }

    if (options.signal) {
      addAbortSignal(options.signal, this);
    }
  }

  Stream.call(this, options);

  if (this._construct != null) {
    destroyImpl.construct(this, () => {
      readableStateForStream(this)[kOnConstructed](this);
    });
  }
}

Readable.prototype.destroy = destroyImpl.destroy;
Readable.prototype._undestroy = destroyImpl.undestroy;
Readable.prototype._destroy = function (err, cb) {
  cb(err);
};

Readable.prototype[EE.captureRejectionSymbol] = function (err) {
  this.destroy(err);
};

Readable.prototype[SymbolAsyncDispose] = function () {
  let error;
  if (!this.destroyed) {
    error = this.readableEnded ? null : new AbortError();
    this.destroy(error);
  }
  return new Promise((resolve, reject) =>
    eos(this, (err) => (err && err !== error ? reject(err) : resolve(null)))
  );
};

// Manually shove something into the read() buffer.
// This returns true if the highWaterMark has not been hit yet,
// similar to how Writable.write() returns true if you should
// write() some more.
Readable.prototype.push = function (chunk, encoding) {
  debug("push", chunk);

  const state = readableStateForStream(this);
  return (state[kState] & kObjectMode) === 0
    ? readableAddChunkPushByteMode(this, state, chunk, encoding)
    : readableAddChunkPushObjectMode(this, state, chunk, encoding);
};
ReadablePrototypePush = Readable.prototype.push;

function pushReadableChunk(stream, chunk, encoding = undefined) {
  return FunctionPrototypeCall(
    ReadablePrototypePush,
    stream,
    chunk,
    encoding,
  );
}

// Native protected streams call this closure-owned entry point instead of the
// public `stream.push` method. Direct-flow delivery also uses the captured
// EventEmitter implementation, so package replacement of either instance
// method cannot become a byte sink.
// @ref LLP 0019#operation-scoped-positive-authority-provenance [implements]
function pushProtectedReadableChunk(stream, chunk) {
  const state = WeakMapPrototypeGet(originalReadableStates, stream);
  if (state === undefined) {
    throw new Error("protected native stream is missing readable state");
  }
  // Positive native delivery was actor-checked immediately before this exact
  // call. Preserve that already-authenticated CPED for loader-owned follow-up
  // scheduling; rebuilding it from trusted loader frames would erase the
  // consumer and turn the continuation into no-user.
  let deliveryContext;
  if (chunk !== null) {
    const checkedContext = runReadableUseGuard(stream);
    // Native delivery already restored its authenticated actor in CPED. Prefer
    // that raw snapshot over rebuilding from the trusted adapter's live frames;
    // the guard-return snapshot remains the public-operation fallback.
    deliveryContext = core.getAsyncContext() ?? checkedContext;
  }
  return (state[kState] & kObjectMode) === 0
    ? readableAddChunkPushByteMode(
      stream,
      state,
      chunk,
      undefined,
      deliveryContext,
    )
    : readableAddChunkPushObjectMode(
      stream,
      state,
      chunk,
      undefined,
      deliveryContext,
    );
}

// Unshift should *always* be something directly out of read().
Readable.prototype.unshift = function (chunk, encoding) {
  debug("unshift", chunk);
  const state = readableStateForStream(this);
  return (state[kState] & kObjectMode) === 0
    ? readableAddChunkUnshiftByteMode(this, state, chunk, encoding)
    : readableAddChunkUnshiftObjectMode(this, state, chunk);
};

function readableAddChunkUnshiftByteMode(stream, state, chunk, encoding) {
  if (chunk === null) {
    state[kState] &= ~kReading;
    onEofChunk(stream, state);

    return false;
  }

  if (typeof chunk === "string") {
    encoding ||= state.defaultEncoding;
    if (state.encoding !== encoding) {
      if (state.encoding) {
        // When unshifting, if state.encoding is set, we have to save
        // the string in the BufferList with the state encoding.
        chunk = bufferToString(bufferFrom(chunk, encoding), state.encoding);
      } else {
        chunk = bufferFrom(chunk, encoding);
      }
    }
  } else if (ArrayBufferIsView(chunk)) {
    chunk = bufferFromArrayBufferView(chunk);
  } else if (chunk !== undefined && !BufferIsBuffer(chunk)) {
    errorOrDestroy(
      stream,
      new ERR_INVALID_ARG_TYPE(
        "chunk",
        ["string", "Buffer", "TypedArray", "DataView"],
        chunk,
      ),
    );
    return false;
  }

  if (!(chunk && readableChunkLength(state, chunk) > 0)) {
    return canPushMore(state);
  }

  return readableAddChunkUnshiftValue(stream, state, chunk);
}

function readableAddChunkUnshiftObjectMode(stream, state, chunk) {
  if (chunk === null) {
    state[kState] &= ~kReading;
    onEofChunk(stream, state);

    return false;
  }

  return readableAddChunkUnshiftValue(stream, state, chunk);
}

function readableAddChunkUnshiftValue(stream, state, chunk) {
  if ((state[kState] & kEndEmitted) !== 0) {
    errorOrDestroy(stream, new ERR_STREAM_UNSHIFT_AFTER_END_EVENT());
  } else if ((state[kState] & (kDestroyed | kErrored)) !== 0) {
    return false;
  } else {
    addChunk(stream, state, chunk, true);
  }

  return canPushMore(state);
}

function readableAddChunkPushByteMode(
  stream,
  state,
  chunk,
  encoding,
  deliveryContext,
) {
  if (chunk === null) {
    state[kState] &= ~kReading;
    onEofChunk(stream, state);
    return false;
  }

  if (typeof chunk === "string") {
    encoding ||= state.defaultEncoding;
    if (state.encoding !== encoding) {
      chunk = bufferFrom(chunk, encoding);
      encoding = "";
    }
  } else if (BufferIsBuffer(chunk)) {
    encoding = "";
  } else if (ArrayBufferIsView(chunk)) {
    chunk = bufferFromArrayBufferView(chunk);
    encoding = "";
  } else if (chunk !== undefined) {
    errorOrDestroy(
      stream,
      new ERR_INVALID_ARG_TYPE(
        "chunk",
        ["string", "Buffer", "TypedArray", "DataView"],
        chunk,
      ),
    );
    return false;
  }

  if (!chunk || readableChunkLength(state, chunk) <= 0) {
    state[kState] &= ~kReading;
    maybeReadMore(stream, state);

    return canPushMore(state);
  }

  if ((state[kState] & kEnded) !== 0) {
    errorOrDestroy(stream, new ERR_STREAM_PUSH_AFTER_EOF());
    return false;
  }

  if ((state[kState] & (kDestroyed | kErrored)) !== 0) {
    return false;
  }

  state[kState] &= ~kReading;
  if ((state[kState] & kDecoder) !== 0 && !encoding) {
    chunk = writeReadableStateDecoder(state, chunk);
    if (chunk.length === 0) {
      maybeReadMore(stream, state);
      return canPushMore(state);
    }
  }

  addChunk(stream, state, chunk, false, deliveryContext);
  return canPushMore(state);
}

function readableAddChunkPushObjectMode(
  stream,
  state,
  chunk,
  encoding,
  deliveryContext,
) {
  if (chunk === null) {
    state[kState] &= ~kReading;
    onEofChunk(stream, state);
    return false;
  }

  if ((state[kState] & kEnded) !== 0) {
    errorOrDestroy(stream, new ERR_STREAM_PUSH_AFTER_EOF());
    return false;
  }

  if ((state[kState] & (kDestroyed | kErrored)) !== 0) {
    return false;
  }

  state[kState] &= ~kReading;

  if ((state[kState] & kDecoder) !== 0 && !encoding) {
    chunk = writeReadableStateDecoder(state, chunk);
  }

  addChunk(stream, state, chunk, false, deliveryContext);
  return canPushMore(state);
}

function canPushMore(state) {
  // We can push more data if we are below the highWaterMark.
  // Also, if we have no data yet, we can stand some more bytes.
  // This is to work around cases where hwm=0, such as the repl.
  return (state[kState] & kEnded) === 0 &&
    (state.length < state.highWaterMark || state.length === 0);
}

function addChunk(
  stream,
  state,
  chunk,
  addToFront,
  deliveryContext,
) {
  if (
    (state[kState] & (kFlowing | kSync | kDataListening)) ===
      (kFlowing | kDataListening) && state.length === 0
  ) {
    // Use the guard to avoid creating `Set()` repeatedly
    // when we have multiple pipes.
    if ((state[kState] & kMultiAwaitDrain) !== 0) {
      state.awaitDrainWriters.clear();
    } else {
      state.awaitDrainWriters = null;
    }

    state[kState] |= kDataEmitted;
    emitReadableData(stream, chunk);
  } else {
    // Update the buffer info.
    state.length += readableChunkLength(state, chunk);
    const buffer = readableStateBuffer(state);
    if (addToFront) {
      const bufferIndex = readableStateBufferIndex(state);
      if (bufferIndex > 0) {
        setReadableStateBufferIndex(state, bufferIndex - 1);
        buffer[bufferIndex - 1] = chunk;
      } else {
        ArrayPrototypeUnshift(buffer, chunk); // Slow path
      }
    } else {
      ArrayPrototypePush(buffer, chunk);
    }

    if ((state[kState] & kNeedReadable) !== 0) {
      emitReadable(stream, state, deliveryContext);
    }
  }
  maybeReadMore(stream, state, deliveryContext);
}

Readable.prototype.isPaused = function () {
  const state = readableStateForStream(this);
  return (state[kState] & kPaused) !== 0 ||
    (state[kState] & (kHasFlowing | kFlowing)) === kHasFlowing;
};

// Backwards compatibility.
Readable.prototype.setEncoding = function (enc) {
  const state = readableStateForStream(this);

  const decoder = new StringDecoder(enc);
  state.decoder = decoder;
  // If setEncoding(null), decoder.encoding equals utf8.
  state.encoding = decoder.encoding;

  // Iterate over current buffer to convert already stored Buffers:
  let content = "";
  const buffer = readableStateBuffer(state);
  for (
    const data of ArrayPrototypeSlice(
      buffer,
      readableStateBufferIndex(state),
    )
  ) {
    content += writeReadableStateDecoder(state, data);
  }
  buffer.length = 0;
  setReadableStateBufferIndex(state, 0);

  if (content !== "") {
    ArrayPrototypePush(buffer, content);
  }
  state.length = content.length;
  return this;
};

// Don't raise the hwm > 1GB.
const MAX_HWM = 0x40000000;
function computeNewHighWaterMark(n) {
  if (n > MAX_HWM) {
    throw new ERR_OUT_OF_RANGE("size", "<= 1GiB", n);
  } else {
    // Get the next highest power of 2 to prevent increasing hwm excessively in
    // tiny amounts.
    n--;
    n |= n >>> 1;
    n |= n >>> 2;
    n |= n >>> 4;
    n |= n >>> 8;
    n |= n >>> 16;
    n++;
  }
  return n;
}

// This function is designed to be inlinable, so please take care when making
// changes to the function body.
function howMuchToRead(n, state) {
  if (n <= 0 || (state.length === 0 && (state[kState] & kEnded) !== 0)) {
    return 0;
  }
  if ((state[kState] & kObjectMode) !== 0) {
    return 1;
  }
  if (NumberIsNaN(n)) {
    // Only flow one buffer at a time.
    if ((state[kState] & kFlowing) !== 0 && state.length) {
      return readableBufferChunkLength(
        state,
        readableStateBuffer(state)[readableStateBufferIndex(state)],
      );
    }
    // Fast path for buffers.
    if ((state[kState] & kDecoder) === 0 && state.length) {
      return readableBufferChunkLength(
        state,
        readableStateBuffer(state)[readableStateBufferIndex(state)],
      );
    }
    return state.length;
  }
  if (n <= state.length) {
    return n;
  }
  return (state[kState] & kEnded) !== 0 ? state.length : 0;
}

// You can override either this method, or the async _read(n) below.
Readable.prototype.read = function (n) {
  const protectedState = WeakMapPrototypeGet(
    protectedReadableOperationStates,
    this,
  );
  // Consume the single exact-call admission before any user callback can run.
  // A reentrant public read must perform its own live authorization.
  if (protectedState !== undefined) {
    WeakMapPrototypeDelete(protectedReadableOperationStates, this);
  }
  // Closure-owned native EOF cleanup is always allowed. Positive delivery was
  // already authorized before the protected operation state is installed.
  if (protectedState === undefined) runReadableUseGuard(this);
  debug("read", n);
  // Same as parseInt(undefined, 10), however V8 7.3 performance regressed
  // in this scenario, so we are doing it manually.
  if (n === undefined) {
    n = NaN;
  } else if (!NumberIsInteger(n)) {
    n = NumberParseInt(n, 10);
  }
  const state = protectedState ?? readableStateForStream(this);
  const nOrig = n;

  // If we're asking for more than the current hwm, then raise the hwm.
  if (n > state.highWaterMark) {
    state.highWaterMark = computeNewHighWaterMark(n);
  }

  if (n !== 0) {
    state[kState] &= ~kEmittedReadable;
  }

  // If we're doing read(0) to trigger a readable event, but we
  // already have a bunch of data in the buffer, then just trigger
  // the 'readable' event and move on.
  if (
    n === 0 &&
    (state[kState] & kNeedReadable) !== 0 &&
    ((state.highWaterMark !== 0
      ? state.length >= state.highWaterMark
      : state.length > 0) ||
      (state[kState] & kEnded) !== 0)
  ) {
    debug("read: emitReadable");
    if (state.length === 0 && (state[kState] & kEnded) !== 0) {
      endReadable(this, state);
    } else {
      emitReadable(this, state);
    }
    return null;
  }

  n = howMuchToRead(n, state);

  // If we've ended, and we're now clear, then finish it up.
  if (n === 0 && (state[kState] & kEnded) !== 0) {
    if (state.length === 0) {
      endReadable(this, state);
    }
    return null;
  }

  // All the actual chunk generation logic needs to be
  // *below* the call to _read.  The reason is that in certain
  // synthetic stream cases, such as passthrough streams, _read
  // may be a completely synchronous operation which may change
  // the state of the read buffer, providing enough data when
  // before there was *not* enough.
  //
  // So, the steps are:
  // 1. Figure out what the state of things will be after we do
  // a read from the buffer.
  //
  // 2. If that resulting state will trigger a _read, then call _read.
  // Note that this may be asynchronous, or synchronous.  Yes, it is
  // deeply ugly to write APIs this way, but that still doesn't mean
  // that the Readable class should behave improperly, as streams are
  // designed to be sync/async agnostic.
  // Take note if the _read call is sync or async (ie, if the read call
  // has returned yet), so that we know whether or not it's safe to emit
  // 'readable' etc.
  //
  // 3. Actually pull the requested chunks out of the buffer and return.

  // if we need a readable event, then we need to do some reading.
  let doRead = (state[kState] & kNeedReadable) !== 0;
  debug("need readable", doRead);

  // If we currently have less than the highWaterMark, then also read some.
  if (state.length === 0 || state.length - n < state.highWaterMark) {
    doRead = true;
    debug("length less than watermark", doRead);
  }

  // However, if we've ended, then there's no point, if we're already
  // reading, then it's unnecessary, if we're constructing we have to wait,
  // and if we're destroyed or errored, then it's not allowed,
  if (
    (state[kState] &
      (kReading | kEnded | kDestroyed | kErrored | kConstructed)) !==
      kConstructed
  ) {
    doRead = false;
    debug("reading, ended or constructing", doRead);
  } else if (doRead) {
    debug("do read");
    state[kState] |= kReading | kSync;
    // If the length is currently zero, then we *need* a readable event.
    if (state.length === 0) {
      state[kState] |= kNeedReadable;
    }

    // Call internal read method
    try {
      this._read(state.highWaterMark);
    } catch (err) {
      errorOrDestroy(this, err);
    }
    state[kState] &= ~kSync;

    // If _read pushed data synchronously, then `reading` will be false,
    // and we need to re-evaluate how much data we can return to the user.
    if ((state[kState] & kReading) === 0) {
      n = howMuchToRead(nOrig, state);
    }
  }

  let ret;
  let preparedDataListeners;
  if (n > 0) {
    // Capture and authorize the complete recipient set before private data is
    // removed from the queue. The same snapshot is used for delivery below.
    preparedDataListeners = prepareEventListenerDelivery(this, "data");
    ret = fromList(n, state);
  } else {
    ret = null;
  }

  if (ret === null) {
    state[kState] |= state.length <= state.highWaterMark ? kNeedReadable : 0;
    n = 0;
  } else {
    state.length -= n;
    if ((state[kState] & kMultiAwaitDrain) !== 0) {
      state.awaitDrainWriters.clear();
    } else {
      state.awaitDrainWriters = null;
    }
  }

  if (state.length === 0) {
    // If we have nothing in the buffer, then we want to know
    // as soon as we *do* get something into the buffer.
    if ((state[kState] & kEnded) === 0) {
      state[kState] |= kNeedReadable;
    }

    // If we tried to read() past the EOF, then emit end on the next tick.
    if (nOrig !== n && (state[kState] & kEnded) !== 0) {
      endReadable(this, state);
    }
  }

  if (
    ret !== null && (state[kState] & (kErrorEmitted | kCloseEmitted)) === 0
  ) {
    state[kState] |= kDataEmitted;
    emitPreparedEvent(this, "data", [ret], preparedDataListeners);
  }

  return ret;
};
ReadablePrototypeRead = Readable.prototype.read;

function readReadableChunk(stream, size = undefined) {
  return FunctionPrototypeCall(ReadablePrototypeRead, stream, size);
}

// Loader-owned scheduled flow must not call a package-replaced public `read`
// method while carrying the initiating operation's context. Recheck the live
// consumer, then run the exact implementation against the registered state.
// @ref LLP 0019#operation-scoped-positive-authority-provenance [implements]
function readGuardedReadable(stream, state, size) {
  if (getStreamUseGuard(stream) === undefined) {
    return stream.read(size);
  }
  runReadableUseGuard(stream);
  const registeredState = WeakMapPrototypeGet(originalReadableStates, stream);
  if (registeredState === undefined || registeredState !== state) {
    throw new Error("guarded Readable state identity changed");
  }
  const operationState = WeakMapPrototypeGet(
    protectedReadableOperationStates,
    stream,
  );
  if (operationState !== undefined) {
    if (operationState !== state) {
      throw new Error("protected Readable operation state changed");
    }
    return FunctionPrototypeCall(ReadablePrototypeRead, stream, size);
  }
  WeakMapPrototypeSet(protectedReadableOperationStates, stream, state);
  try {
    return FunctionPrototypeCall(ReadablePrototypeRead, stream, size);
  } finally {
    WeakMapPrototypeDelete(protectedReadableOperationStates, stream);
  }
}

function emitGuardedReadableEvent(stream, event, ...args) {
  return getStreamUseGuard(stream) === undefined
    ? stream.emit(event, ...args)
    : FunctionPrototypeCall(
      protectedEventEmitterEmit,
      stream,
      event,
      ...args,
    );
}

// Native protected EOF delivery calls the exact loader-owned read(0) with the
// construction-time state. Neither a replaced `read` method nor a replaced
// `_readableState` property participates in the transition to `end`.
// @ref LLP 0019#operation-scoped-positive-authority-provenance [implements]
function readProtectedReadableZero(stream) {
  const state = WeakMapPrototypeGet(originalReadableStates, stream);
  if (state === undefined) {
    throw new Error("protected native stream is missing readable state");
  }
  WeakMapPrototypeSet(protectedReadableOperationStates, stream, state);
  try {
    return FunctionPrototypeCall(ReadablePrototypeRead, stream, 0);
  } finally {
    WeakMapPrototypeDelete(protectedReadableOperationStates, stream);
  }
}

function onEofChunk(stream, state) {
  debug("onEofChunk");
  if ((state[kState] & kEnded) !== 0) return;
  if ((state[kState] & kDecoder) !== 0) {
    const chunk = endReadableStateDecoder(state);
    if (chunk?.length) {
      ArrayPrototypePush(readableStateBuffer(state), chunk);
      state.length += readableChunkLength(state, chunk);
    }
  }
  state[kState] |= kEnded;

  if ((state[kState] & kSync) !== 0) {
    // If we are sync, wait until next tick to emit the data.
    // Otherwise we risk emitting data in the flow()
    // the readable code triggers during a read() call.
    emitReadable(stream);
  } else {
    // Emit 'readable' now to make sure it gets picked up.
    state[kState] &= ~kNeedReadable;
    state[kState] |= kEmittedReadable;
    // We have to emit readable now that we are EOF. Modules
    // in the ecosystem (e.g. dicer) rely on this event being sync.
    emitReadable_(stream);
  }
}

// Don't emit readable right away in sync mode, because this can trigger
// another read() call => stack overflow.  This way, it might trigger
// a nextTick recursion warning, but that's not so bad.
function emitReadable(
  stream,
  state = getReadableOperationState(stream),
  deliveryContext,
) {
  debug("emitReadable");
  state[kState] &= ~kNeedReadable;
  if ((state[kState] & kEmittedReadable) === 0) {
    debug("emitReadable", (state[kState] & kFlowing) !== 0);
    state[kState] |= kEmittedReadable;
    nextTickWithContext(deliveryContext, emitReadable_, stream, state);
  }
}

function emitReadable_(stream, state = getReadableOperationState(stream)) {
  debug("emitReadable_");
  if (
    (state[kState] & (kDestroyed | kErrored)) === 0 &&
    (state.length || (state[kState] & kEnded) !== 0)
  ) {
    emitGuardedReadableEvent(stream, "readable");
    state[kState] &= ~kEmittedReadable;
  }

  // The stream needs another readable event if:
  // 1. It is not flowing, as the flow mechanism will take
  //    care of it.
  // 2. It is not ended.
  // 3. It is below the highWaterMark, so we can schedule
  //    another readable later.
  state[kState] |= (state[kState] & (kFlowing | kEnded)) === 0 &&
      state.length <= state.highWaterMark
    ? kNeedReadable
    : 0;
  flow(stream);
}

// At this point, the user has presumably seen the 'readable' event,
// and called read() to consume some data.  that may have triggered
// in turn another _read(n) call, in which case reading = true if
// it's in progress.
// However, if we're not ended, or reading, and the length < hwm,
// then go ahead and try to read some more preemptively.
function maybeReadMore(stream, state, deliveryContext) {
  if ((state[kState] & (kReadingMore | kConstructed)) === kConstructed) {
    state[kState] |= kReadingMore;
    nextTickWithContext(
      deliveryContext,
      maybeReadMore_,
      stream,
      state,
      getStreamUseGuard(stream),
    );
  }
}

function maybeReadMore_(stream, state, scheduledGuard) {
  // A constructor-side prefetch may have been queued before a native stream
  // became protected. It carries no consumer actor, so retire it when the
  // stable guard identity changed; an authorized read/listener schedules new
  // work under its own operation context.
  if (getStreamUseGuard(stream) !== scheduledGuard) {
    state[kState] &= ~kReadingMore;
    return;
  }
  // Attempt to read more data if we should.
  //
  // The conditions for reading more data are (one of):
  // - Not enough data buffered (state.length < state.highWaterMark). The loop
  //   is responsible for filling the buffer with enough data if such data
  //   is available. If highWaterMark is 0 and we are not in the flowing mode
  //   we should _not_ attempt to buffer any extra data. We'll get more data
  //   when the stream consumer calls read() instead.
  // - No data in the buffer, and the stream is in flowing mode. In this mode
  //   the loop below is responsible for ensuring read() is called. Failing to
  //   call read here would abort the flow and there's no other mechanism for
  //   continuing the flow if the stream consumer has just subscribed to the
  //   'data' event.
  //
  // In addition to the above conditions to keep reading data, the following
  // conditions prevent the data from being read:
  // - The stream has ended (state.ended).
  // - There is already a pending 'read' operation (state.reading). This is a
  //   case where the stream has called the implementation defined _read()
  //   method, but they are processing the call asynchronously and have _not_
  //   called push() with new data. In this case we skip performing more
  //   read()s. The execution ends in this method again after the _read() ends
  //   up calling push() with more data.
  while (
    (state[kState] & (kReading | kEnded)) === 0 &&
    (state.length < state.highWaterMark ||
      ((state[kState] & kFlowing) !== 0 && state.length === 0))
  ) {
    const len = state.length;
    debug("maybeReadMore read 0");
    readGuardedReadable(stream, state, 0);
    if (len === state.length) {
      // Didn't get any data, stop spinning.
      break;
    }
  }
  state[kState] &= ~kReadingMore;
}

// Abstract method.  to be overridden in specific implementation classes.
// call cb(er, data) where data is <= n in length.
// for virtual (non-string, non-buffer) streams, "length" is somewhat
// arbitrary, and perhaps not very meaningful.
Readable.prototype._read = function (n) {
  throw new ERR_METHOD_NOT_IMPLEMENTED("_read()");
};

Readable.prototype.pipe = function (dest, pipeOpts) {
  runReadableUseGuard(this);
  if (
    dest !== null && (typeof dest === "object" || typeof dest === "function")
  ) {
    // Every pipe destination is a transition, not an authority boundary. A
    // live constituent link covers both current protection and protection
    // attached after a preconstructed pipe has been assembled.
    // @ref LLP 0019#operation-scoped-positive-authority-provenance [implements]
    linkStreamUseGuard(this, dest);
  }
  const src = this;
  const state = readableStateForStream(this);
  const destWrite = dest.write;
  const {
    isRegisteredWritable,
    isWritablePublicEnd,
    isWritablePublicWrite,
    writableNeedsDrain,
    writableStateForStream,
  } = core.loadExtScript("ext:deno_node/internal/streams/writable.js");
  if (isWritablePublicWrite(destWrite) && !isRegisteredWritable(dest)) {
    throw new ERR_INVALID_ARG_TYPE("dest", "Writable", dest);
  }
  const capturedDestWrite = isWritablePublicWrite(destWrite)
    ? captureTrustedDeliveryCallback(destWrite)
    : captureDeliveryCallback(destWrite);
  const targetIsRegistered = (target) =>
    isRegisteredReadable(target) || isRegisteredWritable(target);
  const captureLifecycleMethod = (target, method) =>
    targetIsRegistered(target) &&
      (isReadablePublicLifecycleMethod(method) ||
        isReadablePublicUnpipe(method) ||
        isEventEmitterPublicEmit(method) ||
        isEventEmitterPublicLifecycleMethod(method) ||
        isEventEmitterPublicListenerCount(method))
      ? captureTrustedDeliveryCallback(method)
      : captureDeliveryCallback(method);
  const capturedSrcOnce = captureLifecycleMethod(src, src.once);
  const capturedSrcOn = captureLifecycleMethod(src, src.on);
  const capturedSrcRemoveListener = captureLifecycleMethod(
    src,
    src.removeListener,
  );
  const capturedSrcUnpipe = captureLifecycleMethod(src, src.unpipe);
  const capturedDestEmit = captureLifecycleMethod(dest, dest.emit);
  const capturedDestListenerCount = captureLifecycleMethod(
    dest,
    dest.listenerCount,
  );
  const capturedDestOn = captureLifecycleMethod(dest, dest.on);
  const capturedDestOnce = captureLifecycleMethod(dest, dest.once);
  const capturedDestPrependListener = captureLifecycleMethod(
    dest,
    dest.prependListener,
  );
  const capturedDestRemoveListener = captureLifecycleMethod(
    dest,
    dest.removeListener,
  );

  if (state.pipes.length === 1) {
    if ((state[kState] & kMultiAwaitDrain) === 0) {
      state[kState] |= kMultiAwaitDrain;
      state.awaitDrainWriters = new SafeSet(
        state.awaitDrainWriters ? [state.awaitDrainWriters] : [],
      );
    }
  }

  state.pipes.push(dest);
  debug("pipe count=%d opts=%j", state.pipes.length, pipeOpts);

  const doEnd = (!pipeOpts || pipeOpts.end !== false) &&
    dest !== process.stdout &&
    dest !== process.stderr;
  const destEnd = doEnd ? dest.end : undefined;
  if (
    doEnd && isWritablePublicEnd(destEnd) && !isRegisteredWritable(dest)
  ) {
    throw new ERR_INVALID_ARG_TYPE("dest", "Writable", dest);
  }
  const capturedDestEnd = !doEnd
    ? undefined
    : isWritablePublicEnd(destEnd)
    ? captureTrustedDeliveryCallback(destEnd)
    : captureDeliveryCallback(destEnd);

  const endFn = doEnd ? onend : unpipe;
  if ((state[kState] & kEndEmitted) !== 0) {
    nextTickWithCurrent(endFn);
  } else {
    runCapturedCallback(capturedSrcOnce, src, ["end", endFn]);
  }

  runCapturedCallback(capturedDestOn, dest, ["unpipe", onunpipe]);
  function onunpipe(readable, unpipeInfo) {
    debug("onunpipe");
    if (readable === src) {
      if (unpipeInfo && unpipeInfo.hasUnpiped === false) {
        unpipeInfo.hasUnpiped = true;
        cleanup();
      }
    }
  }

  function onend() {
    debug("onend");
    runCapturedDelivery(dest, capturedDestEnd, dest, []);
  }

  let ondrain;

  let cleanedUp = false;
  function cleanup() {
    debug("cleanup");
    // Cleanup event handlers once the pipe is broken.
    runCapturedCallback(capturedDestRemoveListener, dest, ["close", onclose]);
    runCapturedCallback(capturedDestRemoveListener, dest, [
      "finish",
      onfinish,
    ]);
    if (ondrain) {
      runCapturedCallback(capturedDestRemoveListener, dest, [
        "drain",
        ondrain,
      ]);
    }
    runCapturedCallback(capturedDestRemoveListener, dest, ["error", onerror]);
    runCapturedCallback(capturedDestRemoveListener, dest, [
      "unpipe",
      onunpipe,
    ]);
    runCapturedCallback(capturedSrcRemoveListener, src, ["end", onend]);
    runCapturedCallback(capturedSrcRemoveListener, src, ["end", unpipe]);
    runCapturedCallback(capturedSrcRemoveListener, src, ["data", ondata]);

    cleanedUp = true;

    // If the reader is waiting for a drain event from this
    // specific writer, then it would cause it to never start
    // flowing again.
    // So, if this is awaiting a drain, then we just call it now.
    // If we don't know, then assume that we are waiting for one.
    if (
      ondrain && state.awaitDrainWriters &&
      (!dest._writableState || dest._writableState.needDrain)
    ) {
      ondrain();
    }
  }

  function pause() {
    // If the user unpiped during `dest.write()`, it is possible
    // to get stuck in a permanently paused state if that write
    // also returned false.
    // => Check whether `dest` is still a piping destination.
    if (!cleanedUp) {
      if (state.pipes.length === 1 && state.pipes[0] === dest) {
        debug("false write response, pause", 0);
        state.awaitDrainWriters = dest;
        state[kState] &= ~kMultiAwaitDrain;
      } else if (state.pipes.length > 1 && state.pipes.includes(dest)) {
        debug("false write response, pause", state.awaitDrainWriters.size);
        state.awaitDrainWriters.add(dest);
      }
      FunctionPrototypeCall(ReadablePrototypePause, src);
    }
    if (!ondrain) {
      // When the dest drains, it reduces the awaitDrain counter
      // on the source.  This would be more elegant with a .once()
      // handler in flow(), but adding and removing repeatedly is
      // too slow.
      ondrain = pipeOnDrain(src, dest);
      runCapturedCallback(capturedDestOn, dest, ["drain", ondrain]);
    }
  }

  markTrustedDeliveryCallback(
    ondata,
    () => {
      preflightCapturedDelivery(dest, capturedDestWrite);
      preflightStreamDelivery(dest);
    },
  );
  runCapturedCallback(capturedSrcOn, src, ["data", ondata]);
  function ondata(chunk) {
    debug("ondata");
    const ret = runCapturedDelivery(dest, capturedDestWrite, dest, [chunk]);
    debug("dest.write", ret);
    if (ret === false) {
      pause();
    }
  }

  // If the dest has an error, then stop piping into it.
  // However, don't suppress the throwing behavior for this.
  function onerror(er) {
    debug("onerror", er);
    unpipe();
    runCapturedCallback(capturedDestRemoveListener, dest, ["error", onerror]);
    if (
      runCapturedCallback(capturedDestListenerCount, dest, ["error"]) === 0
    ) {
      const s = isRegisteredWritable(dest)
        ? writableStateForStream(dest)
        : isRegisteredReadable(dest)
        ? readableStateForStream(dest)
        : undefined;
      if (s && !s.errorEmitted) {
        // User incorrectly emitted 'error' directly on the stream.
        errorOrDestroy(dest, er);
      } else {
        runCapturedCallback(capturedDestEmit, dest, ["error", er]);
      }
    }
  }

  // Make sure our error handler is attached before userland ones.
  runCapturedCallback(capturedDestPrependListener, dest, ["error", onerror]);

  // Both close and finish should trigger unpipe, but only once.
  function onclose() {
    runCapturedCallback(capturedDestRemoveListener, dest, [
      "finish",
      onfinish,
    ]);
    unpipe();
  }
  runCapturedCallback(capturedDestOnce, dest, ["close", onclose]);
  function onfinish() {
    debug("onfinish");
    runCapturedCallback(capturedDestRemoveListener, dest, ["close", onclose]);
    unpipe();
  }
  runCapturedCallback(capturedDestOnce, dest, ["finish", onfinish]);

  function unpipe() {
    debug("unpipe");
    runCapturedCallback(capturedSrcUnpipe, src, [dest]);
  }

  // Tell the dest that it's being piped to.
  runCapturedCallback(capturedDestEmit, dest, ["pipe", src]);

  // Start the flow if it hasn't been started already.

  if (isRegisteredWritable(dest) && writableNeedsDrain(dest)) {
    pause();
  } else if ((state[kState] & kFlowing) === 0) {
    debug("pipe resume");
    FunctionPrototypeCall(ReadablePrototypeResume, src);
  }

  return dest;
};
ReadablePublicPipe = Readable.prototype.pipe;

function pipeOnDrain(src, dest) {
  return function pipeOnDrainFunctionResult() {
    const state = readableStateForStream(src);

    // `ondrain` will call directly,
    // `this` maybe not a reference to dest,
    // so we use the real dest here.
    if (state.awaitDrainWriters === dest) {
      debug("pipeOnDrain", 1);
      state.awaitDrainWriters = null;
    } else if ((state[kState] & kMultiAwaitDrain) !== 0) {
      debug("pipeOnDrain", state.awaitDrainWriters.size);
      state.awaitDrainWriters.delete(dest);
    }

    if (
      (!state.awaitDrainWriters || state.awaitDrainWriters.size === 0) &&
      (state[kState] & kDataListening) !== 0
    ) {
      FunctionPrototypeCall(ReadablePrototypeResume, src);
    }
  };
}

Readable.prototype.unpipe = function (dest) {
  const state = readableStateForStream(this);
  const unpipeInfo = { hasUnpiped: false };

  // If we're not piping anywhere, then do nothing.
  if (state.pipes.length === 0) {
    return this;
  }

  if (!dest) {
    // remove all.
    const dests = state.pipes;
    state.pipes = [];
    FunctionPrototypeCall(ReadablePrototypePause, this);

    for (let i = 0; i < dests.length; i++) {
      dests[i].emit("unpipe", this, { hasUnpiped: false });
    }
    return this;
  }

  // Try to find the right one.
  const index = ArrayPrototypeIndexOf(state.pipes, dest);
  if (index === -1) {
    return this;
  }

  state.pipes.splice(index, 1);
  if (state.pipes.length === 0) {
    FunctionPrototypeCall(ReadablePrototypePause, this);
  }

  dest.emit("unpipe", this, unpipeInfo);

  return this;
};
ReadablePublicUnpipe = Readable.prototype.unpipe;

// Set up data events if they are asked for
// Ensure readable listeners eventually get something.
Readable.prototype.on = function (ev, fn) {
  if (ev === "data" || ev === "readable") {
    runReadableUseGuard(this);
  }
  const res = addEventEmitterListener(this, ev, fn);
  const state = readableStateForStream(this);

  if (ev === "data") {
    state[kState] |= kDataListening;

    // Update readableListening so that resume() may be a no-op
    // a few lines down. This is needed to support once('readable').
    state[kState] |= FunctionPrototypeCall(
        protectedEventEmitterListenerCount,
        this,
        "readable",
      ) > 0
      ? kReadableListening
      : 0;

    // Try start flowing on next tick if stream isn't explicitly paused.
    if ((state[kState] & (kHasFlowing | kFlowing)) !== kHasFlowing) {
      this.resume();
    }
  } else if (ev === "readable") {
    if ((state[kState] & (kEndEmitted | kReadableListening)) === 0) {
      state[kState] |= kReadableListening | kNeedReadable | kHasFlowing;
      state[kState] &= ~(kFlowing | kEmittedReadable);
      debug("on readable");
      if (state.length) {
        emitReadable(this);
      } else if ((state[kState] & kReading) === 0) {
        nextTickWithCurrent(nReadingNextTick, this);
      }
    }
  }

  return res;
};
ReadablePublicOn = Readable.prototype.on;
Readable.prototype.addListener = Readable.prototype.on;

Readable.prototype.removeListener = function (ev, fn) {
  const state = readableStateForStream(this);

  const res = removeEventEmitterListener(this, ev, fn);

  if (ev === "readable") {
    // We need to check if there is someone still listening to
    // readable and reset the state. However this needs to happen
    // after readable has been emitted but before I/O (nextTick) to
    // support once('readable', fn) cycles. This means that calling
    // resume within the same tick will have no
    // effect.
    nextTickWithCurrent(updateReadableListening, this);
  } else if (
    ev === "data" &&
    FunctionPrototypeCall(protectedEventEmitterListenerCount, this, "data") ===
      0
  ) {
    state[kState] &= ~kDataListening;
  }

  return res;
};
ReadablePublicRemoveListener = Readable.prototype.removeListener;
Readable.prototype.off = Readable.prototype.removeListener;
ReadablePublicOff = Readable.prototype.off;

Readable.prototype.removeAllListeners = function (ev) {
  const res = Stream.prototype.removeAllListeners.apply(this, arguments);

  if (ev === "readable" || ev === undefined) {
    // We need to check if there is someone still listening to
    // readable and reset the state. However this needs to happen
    // after readable has been emitted but before I/O (nextTick) to
    // support once('readable', fn) cycles. This means that calling
    // resume within the same tick will have no
    // effect.
    nextTickWithCurrent(updateReadableListening, this);
  }

  return res;
};

function updateReadableListening(self) {
  const state = readableStateForStream(self);

  if (
    FunctionPrototypeCall(
      protectedEventEmitterListenerCount,
      self,
      "readable",
    ) > 0
  ) {
    state[kState] |= kReadableListening;
  } else {
    state[kState] &= ~kReadableListening;
  }

  if (
    (state[kState] & (kHasPaused | kPaused | kResumeScheduled)) ===
      (kHasPaused | kResumeScheduled)
  ) {
    // Flowing needs to be set to true now, otherwise
    // the upcoming resume will not flow.
    state[kState] |= kHasFlowing | kFlowing;

    // Crude way to check if we should resume.
  } else if ((state[kState] & kDataListening) !== 0) {
    FunctionPrototypeCall(ReadablePrototypeResume, self);
  } else if ((state[kState] & kReadableListening) === 0) {
    state[kState] &= ~(kHasFlowing | kFlowing);
  }
}

function nReadingNextTick(self) {
  debug("readable nexttick read 0");
  readGuardedReadable(self, readableStateForStream(self), 0);
}

// pause() and resume() are remnants of the legacy readable stream API
// If the user uses them, then switch into old mode.
Readable.prototype.resume = function () {
  runReadableUseGuard(this);
  const state = getReadableOperationState(this);
  if ((state[kState] & kDestroyed) !== 0) {
    return this;
  }
  if ((state[kState] & kFlowing) === 0) {
    debug("resume");
    // We flow only if there is no one listening
    // for readable, but we still have to call
    // resume().
    state[kState] |= kHasFlowing;
    if ((state[kState] & kReadableListening) === 0) {
      state[kState] |= kFlowing;
    } else {
      state[kState] &= ~kFlowing;
    }
    resume(this, state);
  }
  state[kState] |= kHasPaused;
  state[kState] &= ~kPaused;
  return this;
};
ReadablePrototypeResume = Readable.prototype.resume;

function resume(stream, state) {
  if ((state[kState] & kResumeScheduled) === 0) {
    state[kState] |= kResumeScheduled;
    nextTickWithCurrent(resume_, stream, state);
  }
}

function resume_(stream, state) {
  debug("resume", (state[kState] & kReading) !== 0);
  if ((state[kState] & kReading) === 0) {
    readGuardedReadable(stream, state, 0);
  }

  state[kState] &= ~kResumeScheduled;
  emitGuardedReadableEvent(stream, "resume");
  flow(stream);
  if ((state[kState] & (kFlowing | kReading)) === kFlowing) {
    readGuardedReadable(stream, state, 0);
  }
}

Readable.prototype.pause = function () {
  // Pausing remains available as lifecycle control after revocation, but a
  // guarded stream still uses its registered state and exact event dispatch.
  const state = getReadableOperationState(this);
  if ((state[kState] & kDestroyed) !== 0) {
    return this;
  }
  debug("call pause");
  if ((state[kState] & (kHasFlowing | kFlowing)) !== kHasFlowing) {
    debug("pause");
    state[kState] |= kHasFlowing;
    state[kState] &= ~kFlowing;
    emitGuardedReadableEvent(this, "pause");
  }
  state[kState] |= kHasPaused | kPaused;
  return this;
};
ReadablePrototypePause = Readable.prototype.pause;

function flow(stream) {
  const state = getReadableOperationState(stream);
  debug("flow");
  while (
    (state[kState] & kFlowing) !== 0 &&
    readGuardedReadable(stream, state, undefined) !== null
  );
}

// Wrap an old-style stream as the async data source.
// This is *not* part of the readable stream interface.
// It is an ugly unfortunate mess of history.
Readable.prototype.wrap = function (stream) {
  linkStreamUseGuard(stream, this);
  let paused = false;

  // TODO (ronag): Should this.destroy(err) emit
  // 'error' on the wrapped stream? Would require
  // a static factory method, e.g. Readable.wrap(stream).

  const wrapped = this;
  const registeredSource = isRegisteredReadable(stream);
  const captureSourceMethod = (method, trusted) =>
    trusted && registeredSource
      ? captureTrustedDeliveryCallback(method)
      : captureDeliveryCallback(method);
  const sourceOn = stream.on;
  const sourcePause = stream.pause;
  const sourceResume = stream.resume;
  const capturedSourceOn = captureSourceMethod(
    sourceOn,
    isReadablePublicLifecycleMethod(sourceOn) ||
      isEventEmitterPublicLifecycleMethod(sourceOn),
  );
  const capturedSourcePause = typeof sourcePause === "function"
    ? captureSourceMethod(sourcePause, isReadablePublicPause(sourcePause))
    : undefined;
  const capturedSourceResume = typeof sourceResume === "function"
    ? captureSourceMethod(sourceResume, isReadablePublicResume(sourceResume))
    : undefined;
  const addSourceListener = (type, listener) =>
    runCapturedCallback(capturedSourceOn, stream, [type, listener]);

  function ondata(chunk) {
    if (
      !FunctionPrototypeCall(ReadablePrototypePush, wrapped, chunk) &&
      capturedSourcePause !== undefined
    ) {
      paused = true;
      runCapturedCallback(capturedSourcePause, stream, []);
    }
  }
  markTrustedDeliveryCallback(
    ondata,
    () => preflightStreamDelivery(wrapped),
  );
  addSourceListener("data", ondata);

  addSourceListener("end", () => {
    FunctionPrototypeCall(ReadablePrototypePush, wrapped, null);
  });

  addSourceListener("error", (err) => {
    errorOrDestroy(wrapped, err);
  });

  addSourceListener("close", () => {
    destroyReadableStream(wrapped);
  });

  addSourceListener("destroy", () => {
    destroyReadableStream(wrapped);
  });

  this._read = () => {
    if (paused && capturedSourceResume !== undefined) {
      paused = false;
      runCapturedCallback(capturedSourceResume, stream, []);
    }
  };

  // Proxy all the other methods. Important when wrapping filters and duplexes.
  const streamKeys = ObjectKeys(stream);
  for (let j = 1; j < streamKeys.length; j++) {
    const i = streamKeys[j];
    const method = stream[i];
    if (this[i] === undefined && typeof method === "function") {
      const capturedMethod = captureDeliveryCallback(method);
      this[i] = (...args) => runCapturedCallback(capturedMethod, stream, args);
    }
  }

  return this;
};

Readable.prototype[SymbolAsyncIterator] = function () {
  runReadableUseGuard(this);
  return streamToAsyncIterator(this);
};
ReadablePublicAsyncIterator = Readable.prototype[SymbolAsyncIterator];

Readable.prototype.iterator = function (options) {
  runReadableUseGuard(this);
  if (options !== undefined) {
    validateObject(options, "options");
  }
  return streamToAsyncIterator(this, options);
};

function streamToAsyncIterator(stream, options) {
  if (typeof stream.read !== "function") {
    stream = Readable.wrap(stream, { objectMode: true });
  }

  const iter = createAsyncIterator(stream, options);
  iter.stream = stream;
  linkStreamUseGuard(stream, iter);
  return iter;
}

async function* createAsyncIterator(stream, options) {
  let callback = nop;

  function next(resolve) {
    if (this === stream) {
      callback();
      callback = nop;
    } else {
      callback = resolve;
    }
  }

  stream.on("readable", next);

  let error;
  const cleanup = eos(stream, { writable: false }, (err) => {
    error = err ? aggregateTwoErrors(error, err) : null;
    callback();
    callback = nop;
  });

  try {
    while (true) {
      const chunk = stream.destroyed ? null : stream.read();
      if (chunk !== null) {
        yield chunk;
      } else if (error) {
        throw error;
      } else if (error === null) {
        return;
      } else {
        await new Promise(next);
      }
    }
  } catch (err) {
    error = aggregateTwoErrors(error, err);
    throw error;
  } finally {
    if (
      (error || options?.destroyOnReturn !== false) &&
      (error === undefined || readableStateForStream(stream).autoDestroy)
    ) {
      destroyImpl.destroyer(stream, null);
    } else {
      stream.off("readable", next);
      cleanup();
    }
  }
}

// Making it explicit these properties are not enumerable
// because otherwise some prototype manipulation in
// userland will fail.
ObjectDefineProperties(Readable.prototype, {
  readable: {
    __proto__: null,
    get() {
      const r = readableStateForStream(this);
      // r.readable === false means that this is part of a Duplex stream
      // where the readable side was disabled upon construction.
      // Compat. The user might manually disable readable side through
      // deprecated setter.
      return !!r && r.readable !== false && !r.destroyed && !r.errorEmitted &&
        !r.endEmitted;
    },
    set(val) {
      // Backwards compat.
      const state = readableStateForStream(this);
      if (state) {
        state.readable = !!val;
      }
    },
  },

  readableDidRead: {
    __proto__: null,
    enumerable: false,
    get: function () {
      return readableStateForStream(this).dataEmitted;
    },
  },

  readableAborted: {
    __proto__: null,
    enumerable: false,
    get: function () {
      return !!(
        readableStateForStream(this).readable !== false &&
        (readableStateForStream(this).destroyed ||
          readableStateForStream(this).errored) &&
        !readableStateForStream(this).endEmitted
      );
    },
  },

  readableHighWaterMark: {
    __proto__: null,
    enumerable: false,
    get: function () {
      return readableStateForStream(this).highWaterMark;
    },
  },

  readableBuffer: {
    __proto__: null,
    enumerable: false,
    get: function () {
      const state = readableStateForStream(this);
      const guarded = getGuardedReadableState(state);
      if (guarded === undefined) return state?.buffer;
      runReadableUseGuard(this);
      return ArrayPrototypeSlice(guarded.buffer, guarded.bufferIndex);
    },
  },

  readableFlowing: {
    __proto__: null,
    enumerable: false,
    get: function () {
      return readableStateForStream(this).flowing;
    },
    set: function (state) {
      const readableState = readableStateForStream(this);
      if (readableState) {
        readableState.flowing = state;
      }
    },
  },

  readableLength: {
    __proto__: null,
    enumerable: false,
    get() {
      return readableStateForStream(this).length;
    },
  },

  readableObjectMode: {
    __proto__: null,
    enumerable: false,
    get() {
      const state = readableStateForStream(this);
      return state ? state.objectMode : false;
    },
  },

  readableEncoding: {
    __proto__: null,
    enumerable: false,
    get() {
      const state = readableStateForStream(this);
      return state ? state.encoding : null;
    },
  },

  errored: {
    __proto__: null,
    enumerable: false,
    get() {
      const state = readableStateForStream(this);
      return state ? state.errored : null;
    },
  },

  closed: {
    __proto__: null,
    get() {
      const state = readableStateForStream(this);
      return state ? state.closed : false;
    },
  },

  destroyed: {
    __proto__: null,
    enumerable: false,
    get() {
      const state = readableStateForStream(this);
      return state ? state.destroyed : false;
    },
    set(value) {
      // We ignore the value if the stream
      // has not been initialized yet.
      const state = readableStateForStream(this);
      if (!state) {
        return;
      }

      // Backward compatibility, the user is explicitly
      // managing destroyed.
      state.destroyed = value;
    },
  },

  readableEnded: {
    __proto__: null,
    enumerable: false,
    get() {
      const state = readableStateForStream(this);
      return state ? state.endEmitted : false;
    },
  },
});

ObjectDefineProperties(ReadableState.prototype, {
  // Legacy getter for `pipesCount`.
  pipesCount: {
    __proto__: null,
    get() {
      return this.pipes.length;
    },
  },

  // Legacy property for `paused`.
  paused: {
    __proto__: null,
    get() {
      return (this[kState] & kPaused) !== 0;
    },
    set(value) {
      this[kState] |= kHasPaused;
      if (value) {
        this[kState] |= kPaused;
      } else {
        this[kState] &= ~kPaused;
      }
    },
  },
});

// Exposed for testing purposes only.
Readable._fromList = fromList;

// Pluck off n bytes from an array of buffers.
// Length is the combined lengths of all the buffers in the list.
// This function is designed to be inlinable, so please take care when making
// changes to the function body.
function fromList(n, state) {
  // nothing buffered.
  if (state.length === 0) {
    return null;
  }

  let idx = readableStateBufferIndex(state);
  let ret;

  const buf = readableStateBuffer(state);
  const len = buf.length;

  if ((state[kState] & kObjectMode) !== 0) {
    ret = buf[idx];
    buf[idx++] = null;
  } else if (!n || n >= state.length) {
    // Read it all, truncate the list.
    if ((state[kState] & kDecoder) !== 0) {
      ret = "";
      while (idx < len) {
        ret += buf[idx];
        buf[idx++] = null;
      }
    } else if (len - idx === 0) {
      ret = bufferAlloc(0);
    } else if (len - idx === 1) {
      ret = buf[idx];
      buf[idx++] = null;
    } else {
      ret = bufferAllocUnsafe(state.length);

      let i = 0;
      while (idx < len) {
        TypedArrayPrototypeSet(ret, buf[idx], i);
        i += readableBufferChunkLength(state, buf[idx]);
        buf[idx++] = null;
      }
    }
  } else if (n < readableBufferChunkLength(state, buf[idx])) {
    // `slice` is the same for buffers and strings.
    if ((state[kState] & kDecoder) !== 0) {
      ret = StringPrototypeSlice(buf[idx], 0, n);
      buf[idx] = StringPrototypeSlice(buf[idx], n);
    } else {
      const data = buf[idx];
      const dataLength = readableBufferChunkLength(state, data);
      ret = readableBufferView(state, data, 0, n);
      buf[idx] = readableBufferView(state, data, n, dataLength - n);
    }
  } else if (n === readableBufferChunkLength(state, buf[idx])) {
    // First chunk is a perfect match.
    ret = buf[idx];
    buf[idx++] = null;
  } else if ((state[kState] & kDecoder) !== 0) {
    ret = "";
    while (idx < len) {
      const str = buf[idx];
      if (n > str.length) {
        ret += str;
        n -= str.length;
        buf[idx++] = null;
      } else {
        if (n === str.length) {
          ret += str;
          buf[idx++] = null;
        } else {
          ret += StringPrototypeSlice(str, 0, n);
          buf[idx] = StringPrototypeSlice(str, n);
        }
        break;
      }
    }
  } else {
    ret = bufferAllocUnsafe(n);

    const retLen = n;
    while (idx < len) {
      const data = buf[idx];
      const dataLength = readableBufferChunkLength(state, data);
      if (n > dataLength) {
        TypedArrayPrototypeSet(ret, data, retLen - n);
        n -= dataLength;
        buf[idx++] = null;
      } else {
        if (n === dataLength) {
          TypedArrayPrototypeSet(ret, data, retLen - n);
          buf[idx++] = null;
        } else {
          TypedArrayPrototypeSet(
            ret,
            readableBufferView(state, data, 0, n),
            retLen - n,
          );
          buf[idx] = readableBufferView(
            state,
            data,
            n,
            dataLength - n,
          );
        }
        break;
      }
    }
  }

  if (idx === len) {
    buf.length = 0;
    setReadableStateBufferIndex(state, 0);
  } else if (idx > 1024) {
    ArrayPrototypeSplice(buf, 0, idx);
    setReadableStateBufferIndex(state, 0);
  } else {
    setReadableStateBufferIndex(state, idx);
  }

  return ret;
}

function endReadable(stream, state = getReadableOperationState(stream)) {
  debug("endReadable");
  if ((state[kState] & kEndEmitted) === 0) {
    state[kState] |= kEnded;
    nextTickWithCurrent(endReadableNT, state, stream);
  }
}

function endReadableNT(state, stream) {
  debug("endReadableNT");

  // Check that we didn't get one last unshift.
  if (
    (state[kState] & (kErrored | kCloseEmitted | kEndEmitted)) === 0 &&
    state.length === 0
  ) {
    state[kState] |= kEndEmitted;
    emitGuardedReadableEvent(stream, "end");

    if (stream.writable && stream.allowHalfOpen === false) {
      nextTickWithCurrent(endWritableNT, stream);
    } else if (state.autoDestroy) {
      // In case of duplex streams we need a way to detect
      // if the writable side is ready for autoDestroy as well.
      const wState = stream._writableState;
      const autoDestroy = !wState || (
        wState.autoDestroy &&
        // We don't expect the writable to ever 'finish'
        // if writable is explicitly set to false.
        (wState.finished || wState.writable === false)
      );

      if (autoDestroy) {
        destroyReadableStream(stream);
      }
    }
  }
}

function endWritableNT(stream) {
  if (getStreamUseGuard(stream) !== undefined) {
    const {
      endProtectedWritableCleanup,
      isRegisteredWritable,
      writableStateForStream,
    } = core.loadExtScript("ext:deno_node/internal/streams/writable.js");
    if (!isRegisteredWritable(stream)) return;
    const state = writableStateForStream(stream);
    if (
      state.writable !== false && !state.ending && !state.ended &&
      !state.destroyed
    ) {
      endProtectedWritableCleanup(stream);
    }
    return;
  }
  const writable = stream.writable && !stream.writableEnded &&
    !stream.destroyed;
  if (writable) {
    stream.end();
  }
}

function destroyReadableStream(stream, error) {
  if (getStreamUseGuard(stream) === undefined) {
    FunctionPrototypeCall(destroyImpl.destroy, stream, error);
    return;
  }
  const {
    destroyProtectedWritable,
    isRegisteredWritable,
  } = core.loadExtScript("ext:deno_node/internal/streams/writable.js");
  if (isRegisteredWritable(stream)) {
    destroyProtectedWritable(stream, error);
    return;
  }
  FunctionPrototypeCall(destroyImpl.destroy, stream, error);
}

Readable.from = function (iterable, opts) {
  const guardedIterable =
    typeof iterable === "string" || BufferIsBuffer(iterable)
      ? iterable
      : wrapIterableDelivery(iterable);
  const readable = lazyFrom().default(Readable, guardedIterable, opts);
  linkStreamUseGuard(iterable, guardedIterable);
  linkStreamUseGuard(guardedIterable, readable);
  return readable;
};

let webStreamsAdapters;

// Lazy to avoid circular references
function lazyWebStreams() {
  if (webStreamsAdapters === undefined) {
    webStreamsAdapters = core.loadExtScript(webStreamsAdaptersSpecifier);
  }
  return webStreamsAdapters;
}

Readable.fromWeb = function (readableStream, options) {
  return lazyWebStreams().newStreamReadableFromReadableStream(
    readableStream,
    options,
  );
};

Readable.toWeb = function (streamReadable, options) {
  return lazyWebStreams().newReadableStreamFromStreamReadable(
    streamReadable,
    options,
  );
};

Readable.wrap = function (src, options) {
  return new Readable({
    objectMode: src.readableObjectMode ?? src.objectMode ?? true,
    ...options,
    destroy(err, callback) {
      destroyImpl.destroyer(src, err);
      callback(err);
    },
  }).wrap(src);
};

return {
  addReadableListener,
  createReadableAsyncIterator,
  default: Readable,
  destroyReadableStream,
  getProtectedReadableState,
  getReadableUseGuard,
  hasProtectedReadableDecoder,
  isRegisteredReadable,
  isReadableActive,
  isReadableDestroyed,
  isProtectedReadableDestroyed,
  isProtectedReadableEndEmitted,
  isReadablePublicLifecycleMethod,
  isReadablePublicPipe,
  isReadablePublicPause,
  isReadablePublicPush,
  isReadablePublicRead,
  isReadablePublicResume,
  isReadablePublicUnpipe,
  pauseReadable,
  pushProtectedReadableChunk,
  pushReadableChunk,
  readProtectedReadableZero,
  readReadableChunk,
  Readable,
  readableStateForStream,
  readableHighWaterMark,
  readableObjectMode,
  registerReadableState,
  resumeReadable,
  setReadableUseGuard,
  shouldStartProtectedReadable,
};
})();

// deno-lint-ignore-file
// Copyright 2018-2026 the Deno authors. MIT license.

(function () {
const { core, primordials } = __bootstrap;
const lazyProcess = core.createLazyLoader("node:process");
const process = lazyProcess().default;
const { nextTick: ProtectedWritableNextTick } = core.loadExtScript(
  "ext:deno_node/_next_tick.ts",
);
const { EventEmitter: EE } = core.loadExtScript("ext:deno_node/_events.mjs");
const _mod1 =
  core.loadExtScript("ext:deno_node/internal/streams/legacy.js").default;
const {
  Buffer,
  protectedBufferFrom,
  protectedBufferIsBuffer,
  protectedBufferIsEncoding,
} = core.loadExtScript("ext:deno_node/internal/buffer.mjs");
const destroyImpl =
  core.loadExtScript("ext:deno_node/internal/streams/destroy.js").default;
const eos =
  core.loadExtScript("ext:deno_node/internal/streams/end-of-stream.js").default;
const { addAbortSignal } = core.loadExtScript(
  "ext:deno_node/internal/streams/add-abort-signal.js",
);
const {
  getDefaultHighWaterMark,
  getHighWaterMark,
} = core.loadExtScript("ext:deno_node/internal/streams/state.js");
const imported2 = core.loadExtScript("ext:deno_node/internal/errors.ts");

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

const webStreamsAdaptersSpecifier =
  "ext:deno_node/internal/webstreams/adapters.js";
const {
  captureCurrentDeliveryCallback,
  captureDeliveryCallback,
  captureTrustedDeliveryCallback,
  getStreamUseGuard,
  isStreamCleanupDeliveryCallback,
  isStreamTrustedDeliveryCallback,
  preflightCapturedDelivery,
  registerStreamDeliveryPreflight,
  registerStreamGuardAttachHook,
  runCapturedCallback,
  runCapturedDelivery,
  runCapturedCleanup,
  runStreamUseGuard,
  setStreamUseGuard,
} = core.loadExtScript(
  "ext:deno_node/internal/streams/oden_delivery.js",
);

const {
  AbortError,
  codes: {
    ERR_INVALID_ARG_TYPE,
    ERR_METHOD_NOT_IMPLEMENTED,
    ERR_MULTIPLE_CALLBACK,
    ERR_STREAM_ALREADY_FINISHED,
    ERR_STREAM_CANNOT_PIPE,
    ERR_STREAM_DESTROYED,
    ERR_STREAM_NULL_VALUES,
    ERR_STREAM_WRITE_AFTER_END,
    ERR_UNKNOWN_ENCODING,
  },
} = imported2;

const Stream = _mod1.Stream;
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

// A bit simpler than readable streams.
// Implement an async ._write(chunk, encoding, cb), and it'll handle all
// the drain event emission and buffering.

"use strict";

const {
  ArrayBufferIsView,
  ArrayPrototypePush,
  ArrayPrototypeSlice,
  ArrayPrototypeSplice,
  DataViewPrototypeGetBuffer,
  DataViewPrototypeGetByteLength,
  DataViewPrototypeGetByteOffset,
  Error,
  FunctionPrototypeCall,
  FunctionPrototypeSymbolHasInstance,
  ObjectDefineProperties,
  ObjectDefineProperty,
  ObjectSetPrototypeOf,
  Promise,
  SafeWeakMap,
  StringPrototypeToLowerCase,
  Symbol,
  SymbolAsyncDispose,
  SymbolHasInstance,
  TypedArrayPrototypeGetBuffer,
  TypedArrayPrototypeGetByteLength,
  TypedArrayPrototypeGetByteOffset,
  WeakMapPrototypeDelete,
  WeakMapPrototypeGet,
  WeakMapPrototypeSet,
} = primordials;

function writableNextTick(callback, ...args) {
  return FunctionPrototypeCall(
    ProtectedWritableNextTick,
    process,
    callback,
    ...args,
  );
}

Writable.WritableState = WritableState;

const { errorOrDestroy } = destroyImpl;

ObjectSetPrototypeOf(Writable.prototype, Stream.prototype);
ObjectSetPrototypeOf(Writable, Stream);
const BufferFrom = Buffer.from;
const BufferIsBuffer = protectedBufferIsBuffer ?? Buffer.isBuffer;
const BufferIsEncoding = protectedBufferIsEncoding ?? Buffer.isEncoding;
const isTypedArray = core.isTypedArray;

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

function writableChunkLength(state, chunk) {
  if ((state[kState] & kObjectMode) !== 0) return 1;
  return typeof chunk === "string"
    ? chunk.length
    : TypedArrayPrototypeGetByteLength(chunk);
}

function nop() {}

const kOnFinishedValue = Symbol("kOnFinishedValue");
const kErroredValue = Symbol("kErroredValue");
const kDefaultEncodingValue = Symbol("kDefaultEncodingValue");
const kWriteCbValue = Symbol("kWriteCbValue");
const kAfterWriteTickInfoValue = Symbol("kAfterWriteTickInfoValue");
const kBufferedValue = Symbol("kBufferedValue");
// Protected input queues and implementation identities cannot remain on the
// reflectable WritableState/stream surface after authority attaches.
// @ref LLP 0019#operation-scoped-positive-authority-provenance [implements]
const guardedWritableStates = new SafeWeakMap();
const originalWritableStates = new SafeWeakMap();
// Protected composition must not read liveness or sizing decisions from the
// reflectable WritableState. Retain engine-owned scalar values separately so
// a package-held state reference cannot install a getter that later runs as a
// more-authorized consumer.
// @ref LLP 0019#operation-scoped-positive-authority-provenance [implements]
const writableEnabledValues = new SafeWeakMap();
const writableHighWaterMarkValues = new SafeWeakMap();
const bufferedWriteAdmissions = new SafeWeakMap();
// Completion callbacks retain the CPED of each registration independently of
// the continuation that eventually completes the write. The raw callback slots
// remain untouched for ordinary Node compatibility; protected dispatch uses
// only these closure-private records so object passage cannot borrow a later
// root writer's authority.
// @ref LLP 0019#operation-scoped-positive-authority-provenance [implements]
const activeWriteCallbackRecords = new SafeWeakMap();
const activeAfterWriteTickInfos = new SafeWeakMap();
const afterWriteTickCallbackRecords = new SafeWeakMap();
const bufferedWriteCallbackRecords = new SafeWeakMap();
const endCallbackRecords = new SafeWeakMap();
const writableCallbackSequenceValues = new SafeWeakMap();
const protectedWritableCleanupEnds = new SafeWeakMap();
let WritablePrototypeWrite;
let WritablePrototypeUncork;
let WritablePublicDestroy;
let WritablePublicEnd;
let WritablePublicWrite;

function isRegisteredWritable(stream) {
  return WeakMapPrototypeGet(originalWritableStates, stream) !== undefined;
}

function isWritableDestroyed(stream) {
  const state = WeakMapPrototypeGet(originalWritableStates, stream);
  return state === undefined || (state[kState] & kDestroyed) !== 0;
}

function isWritableActive(stream) {
  const state = WeakMapPrototypeGet(originalWritableStates, stream);
  return state !== undefined && writableStateEnabled(state) &&
    (state[kState] & (kEnding | kEnded | kDestroyed | kErrored)) === 0;
}

function isWritableEnabled(stream) {
  const state = WeakMapPrototypeGet(originalWritableStates, stream);
  return state !== undefined && writableStateEnabled(state);
}

function isWritableEnded(stream) {
  const state = WeakMapPrototypeGet(originalWritableStates, stream);
  return state === undefined || (state[kState] & kEnding) !== 0;
}

function writableObjectMode(stream) {
  const state = WeakMapPrototypeGet(originalWritableStates, stream);
  return state !== undefined && (state[kState] & kObjectMode) !== 0;
}

function writableHighWaterMark(stream) {
  const state = WeakMapPrototypeGet(originalWritableStates, stream);
  return state === undefined ? undefined : writableStateHighWaterMark(state);
}

function writableStateEnabled(state) {
  return getGuardedWritableState(state) === undefined
    ? state.writable !== false
    : WeakMapPrototypeGet(writableEnabledValues, state) !== false;
}

function setWritableStateEnabled(state, value) {
  const enabled = value !== false;
  WeakMapPrototypeSet(writableEnabledValues, state, enabled);
  if (getGuardedWritableState(state) === undefined) {
    state.writable = enabled;
  }
}

function setWritableActive(stream, value) {
  const state = WeakMapPrototypeGet(originalWritableStates, stream) ??
    stream._writableState;
  if (state !== undefined) setWritableStateEnabled(state, value);
}

function writableStateHighWaterMark(state) {
  return getGuardedWritableState(state) === undefined
    ? state.highWaterMark
    : WeakMapPrototypeGet(writableHighWaterMarkValues, state);
}

function isWritablePublicWrite(callback) {
  return callback === WritablePublicWrite;
}

function isWritablePublicEnd(callback) {
  return callback === WritablePublicEnd;
}

function isWritablePublicUncork(callback) {
  return callback === WritablePrototypeUncork;
}

function isWritableStateProtected(stream) {
  const state = WeakMapPrototypeGet(originalWritableStates, stream);
  return state !== undefined && getGuardedWritableState(state) !== undefined;
}

function setWritableUseGuard(stream, guard) {
  if (!prepareWritableForProtection(stream)) return false;
  setStreamUseGuard(stream, guard);
  return true;
}

function prepareWritableForProtection(stream) {
  if (!isRegisteredWritable(stream)) return false;
  protectWritableState(stream);
  return true;
}

function protectedWritableWrite(stream, chunk, encoding, callback) {
  return FunctionPrototypeCall(
    WritablePublicWrite,
    stream,
    chunk,
    encoding,
    callback,
  );
}

function protectedWritableEnd(stream, chunk, encoding, callback) {
  return FunctionPrototypeCall(
    WritablePublicEnd,
    stream,
    chunk,
    encoding,
    callback,
  );
}

// An EOF half-close carries no application bytes. Keep its bypass private and
// consume it at exact end() entry so reentrant package calls cannot inherit it.
// @ref LLP 0019#operation-scoped-positive-authority-provenance [implements]
function canEndProtectedWritableCleanup(stream, state) {
  if (getStreamUseGuard(stream) === undefined) return true;
  const guarded = getGuardedWritableState(state);
  return state.length === 0 &&
    (guarded === undefined || guarded.final === null ||
      guarded.finalCleanupSafe);
}

function endProtectedWritableCleanup(stream) {
  if (!isRegisteredWritable(stream)) {
    throw new Error("protected Writable is missing registered state");
  }
  const state = writableStateForStream(stream);
  // Cleanup must never flush a queued write or invoke an application final
  // hook. An authorized operation may still call public end() normally.
  if (!canEndProtectedWritableCleanup(stream, state)) {
    return false;
  }
  WeakMapPrototypeSet(protectedWritableCleanupEnds, stream, true);
  try {
    return FunctionPrototypeCall(
      WritablePublicEnd,
      stream,
      undefined,
      undefined,
      undefined,
    );
  } finally {
    WeakMapPrototypeDelete(protectedWritableCleanupEnds, stream);
  }
}

function protectedWritableUncork(stream) {
  return FunctionPrototypeCall(WritablePrototypeUncork, stream);
}

function destroyProtectedWritable(stream, error) {
  return FunctionPrototypeCall(WritablePublicDestroy, stream, error);
}

function writableStateForStream(stream) {
  const original = WeakMapPrototypeGet(originalWritableStates, stream);
  return original !== undefined &&
      (getStreamUseGuard(stream) !== undefined ||
        getGuardedWritableState(original) !== undefined)
    ? original
    : stream._writableState;
}

function getGuardedWritableState(state) {
  return WeakMapPrototypeGet(guardedWritableStates, state);
}

function captureWritableCallback(state, callback) {
  if (callback === nop) return undefined;
  const sequence =
    (WeakMapPrototypeGet(writableCallbackSequenceValues, state) ??
      0) + 1;
  WeakMapPrototypeSet(writableCallbackSequenceValues, state, sequence);
  return {
    captured: captureDeliveryCallback(callback),
    sequence,
  };
}

function singleWriteCallbackCompletion(record) {
  return record === undefined ? undefined : {
    callback: record.captured.callback,
    kind: "single",
    record,
    sequence: record.sequence,
  };
}

function takeBufferedWriteCallbackRecord(entry) {
  const record = WeakMapPrototypeGet(bufferedWriteCallbackRecords, entry);
  WeakMapPrototypeDelete(bufferedWriteCallbackRecords, entry);
  return record;
}

function batchWriteCallbackCompletion(callback, buffered, start) {
  const members = [];
  for (let i = start; i < buffered.length; i++) {
    const entry = buffered[i];
    const record = takeBufferedWriteCallbackRecord(entry);
    if (record !== undefined) {
      ArrayPrototypePush(members, { entry, record });
    }
  }
  return members.length === 0 ? undefined : {
    callback,
    kind: "writev",
    members,
    sequence: members[0].record.sequence,
  };
}

function setActiveWriteCallbackRecord(state, completion) {
  if (completion === undefined) {
    WeakMapPrototypeDelete(activeWriteCallbackRecords, state);
  } else {
    WeakMapPrototypeSet(activeWriteCallbackRecords, state, completion);
  }
}

function takeActiveWriteCallbackRecord(state) {
  const completion = WeakMapPrototypeGet(activeWriteCallbackRecords, state);
  WeakMapPrototypeDelete(activeWriteCallbackRecords, state);
  return completion;
}

function insertWriteCallbackRecord(records, completion) {
  if (completion === undefined) return;
  let index = records.length;
  while (
    index > 0 && records[index - 1].sequence > completion.sequence
  ) {
    index--;
  }
  ArrayPrototypeSplice(records, index, 0, completion);
}

function invokeProtectedWriteCallback(stream, completion, error) {
  if (completion.kind === "single") {
    return runCapturedCallback(
      completion.record.captured,
      undefined,
      [error],
    );
  }

  // Node invokes _writev completion callbacks with the buffered request as
  // `this`; that request contains the application chunk and encoding. Treat
  // the complete recipient set as byte delivery before exposing any entry.
  // @ref LLP 0019#operation-scoped-positive-authority-provenance [implements]
  for (let i = 0; i < completion.members.length; i++) {
    preflightCapturedDelivery(stream, completion.members[i].record.captured);
  }
  for (let i = 0; i < completion.members.length; i++) {
    const member = completion.members[i];
    runCapturedDelivery(
      stream,
      member.record.captured,
      member.entry,
      [error],
    );
  }
}

function runScheduledWriteCallback(stream, state, record, callback, error) {
  if (getGuardedWritableState(state) === undefined) {
    return FunctionPrototypeCall(callback, undefined, error);
  }
  if (record === undefined) return;
  return runCapturedCallback(record.captured, undefined, [error]);
}

function captureEndCallback(callback) {
  return {
    callback,
    captured: captureDeliveryCallback(callback),
  };
}

function runScheduledEndCallback(state, record, callback, error) {
  if (getGuardedWritableState(state) === undefined) {
    return FunctionPrototypeCall(callback, undefined, error);
  }
  return runCapturedCallback(record.captured, undefined, [error]);
}

function appendEndCallbackRecord(state, record) {
  let records = WeakMapPrototypeGet(endCallbackRecords, state);
  if (records === undefined) {
    records = { callbacks: [], receiver: [] };
    WeakMapPrototypeSet(endCallbackRecords, state, records);
  }
  ArrayPrototypePush(records.callbacks, record.captured);
  ArrayPrototypePush(records.receiver, record.callback);
}

function canInspectGuardedWritable(state) {
  const guarded = getGuardedWritableState(state);
  if (guarded === undefined) return true;
  if (getStreamUseGuard(guarded.stream) === undefined) return false;
  runStreamUseGuard(guarded.stream);
  return true;
}

function writableStateBuffer(state) {
  const guarded = getGuardedWritableState(state);
  if (guarded === undefined) return state[kBufferedValue];
  runStreamUseGuard(guarded.stream);
  return guarded.buffer;
}

function writableStateBufferForCleanup(state) {
  const guarded = getGuardedWritableState(state);
  return guarded === undefined ? state[kBufferedValue] : guarded.buffer;
}

function writableStateBufferIndex(state) {
  const guarded = getGuardedWritableState(state);
  if (guarded === undefined) return state.bufferedIndex;
  runStreamUseGuard(guarded.stream);
  return guarded.bufferedIndex;
}

function setWritableStateBufferIndex(state, index) {
  const guarded = getGuardedWritableState(state);
  if (guarded === undefined) state.bufferedIndex = index;
  else {
    runStreamUseGuard(guarded.stream);
    guarded.bufferedIndex = index;
  }
}

function setWritableStateBuffer(state, value) {
  const guarded = getGuardedWritableState(state);
  if (guarded === undefined) {
    state[kBufferedValue] = value;
    state.bufferedIndex = 0;
  } else {
    runStreamUseGuard(guarded.stream);
    guarded.buffer = value;
    guarded.bufferedIndex = 0;
    state[kBufferedValue] = null;
    state.bufferedIndex = 0;
  }
}

// Once protection attaches, callback identity and coalescing state must never
// be read from or written through a package-poisonable WritableState slot.
// @ref LLP 0019#operation-scoped-positive-authority-provenance [implements]
function clearReflectableWritableCallbackSlot(state, key) {
  ObjectDefineProperty(state, key, {
    __proto__: null,
    configurable: true,
    enumerable: false,
    value: null,
    writable: true,
  });
}

function protectWritableState(stream) {
  const state = WeakMapPrototypeGet(originalWritableStates, stream);
  if (state === undefined || getGuardedWritableState(state) !== undefined) {
    return;
  }
  const publicBuffer = state[kBufferedValue];
  const privateBuffer = publicBuffer === null
    ? null
    : ArrayPrototypeSlice(publicBuffer, state.bufferedIndex);
  if (publicBuffer !== null) publicBuffer.length = 0;
  state[kBufferedValue] = null;
  state.bufferedIndex = 0;
  if ((state[kState] & kWriteCb) !== 0) {
    clearReflectableWritableCallbackSlot(state, kWriteCbValue);
    state[kState] &= ~kWriteCb;
  }
  if ((state[kState] & kAfterWriteTickInfo) !== 0) {
    clearReflectableWritableCallbackSlot(state, kAfterWriteTickInfoValue);
    state[kState] &= ~kAfterWriteTickInfo;
  }
  if ((state[kState] & kOnFinished) !== 0) {
    clearReflectableWritableCallbackSlot(state, kOnFinishedValue);
  }

  const write = stream._write;
  const writev = stream._writev;
  const final = stream._final;
  const capture = (callback, trusted = false) =>
    trusted || isStreamTrustedDeliveryCallback(stream, callback)
      ? captureTrustedDeliveryCallback(callback)
      : captureDeliveryCallback(callback);
  WeakMapPrototypeSet(guardedWritableStates, state, {
    buffer: privateBuffer,
    bufferedIndex: 0,
    onwrite: state.onwrite,
    stream,
    final: typeof final === "function" ? capture(final) : null,
    finalCleanupSafe: typeof final === "function" &&
      isStreamCleanupDeliveryCallback(stream, final),
    write: typeof write === "function"
      ? capture(write, write === WritablePrototypeWrite)
      : null,
    writeIsDefault: write === WritablePrototypeWrite,
    writev: typeof writev === "function" ? capture(writev) : null,
  });
}

function hasWritableWritev(stream, state) {
  const guarded = getGuardedWritableState(state);
  if (guarded === undefined) return typeof stream._writev === "function";
  return guarded.writev !== null;
}

function preflightWritableImplementation(stream) {
  const state = writableStateForStream(stream);
  const guarded = getGuardedWritableState(state);
  if (guarded === undefined) return;
  const captured = guarded.writeIsDefault && guarded.writev !== null
    ? guarded.writev
    : guarded.write;
  preflightCapturedDelivery(stream, captured);
}

function writableOnwrite(state) {
  const guarded = getGuardedWritableState(state);
  if (guarded === undefined) return state.onwrite;
  return guarded.onwrite;
}

function hasWritableFinal(stream, state) {
  const guarded = getGuardedWritableState(state);
  if (guarded === undefined) return typeof stream._final === "function";
  if (guarded.final === null) return false;
  if (
    guarded.buffer !== null &&
    guarded.bufferedIndex < guarded.buffer.length
  ) {
    runStreamUseGuard(stream);
    throw new Error("guarded writable queue reached _final before delivery");
  }
  if (!guarded.finalCleanupSafe) runStreamUseGuard(stream);
  return true;
}

function invokeWritableFinal(stream, state, callback) {
  const guarded = getGuardedWritableState(state);
  if (guarded === undefined) {
    return FunctionPrototypeCall(stream._final, stream, callback);
  }
  return guarded.finalCleanupSafe
    ? runCapturedCleanup(guarded.final, stream, [callback])
    : runCapturedDelivery(stream, guarded.final, stream, [callback]);
}

function invokeWritableImplementation(
  stream,
  state,
  writev,
  chunk,
  encoding,
  cb,
) {
  const guarded = getGuardedWritableState(state);
  if (guarded === undefined) {
    if (writev) {
      return FunctionPrototypeCall(stream._writev, stream, chunk, cb);
    }
    return FunctionPrototypeCall(stream._write, stream, chunk, encoding, cb);
  }

  if (writev) {
    return runCapturedDelivery(
      stream,
      guarded.writev,
      stream,
      [chunk, cb],
    );
  }
  if (guarded.writeIsDefault) {
    if (guarded.writev === null) {
      throw new ERR_METHOD_NOT_IMPLEMENTED("_write()");
    }
    return runCapturedDelivery(
      stream,
      guarded.writev,
      stream,
      [[{ chunk, encoding }], cb],
    );
  }
  return runCapturedDelivery(
    stream,
    guarded.write,
    stream,
    [chunk, encoding, cb],
  );
}

function invokeAdmittedWritableImplementation({
  cb,
  chunk,
  encoding,
  state,
  stream,
  writev,
}) {
  return invokeWritableImplementation(
    stream,
    state,
    writev,
    chunk,
    encoding,
    cb,
  );
}

const directWritableAdmission = captureDeliveryCallback(
  nop,
  invokeAdmittedWritableImplementation,
);

function writableAdmission(entry) {
  return WeakMapPrototypeGet(bufferedWriteAdmissions, entry) ??
    directWritableAdmission;
}

function preflightWritableAdmission(stream, entry) {
  preflightCapturedDelivery(stream, writableAdmission(entry));
}

function invokeWritableAdmission(
  admission,
  stream,
  state,
  writev,
  chunk,
  encoding,
  cb,
) {
  return runCapturedCallback(admission, undefined, [{
    cb,
    chunk,
    encoding,
    state,
    stream,
    writev,
  }]);
}

// When an options object passed to `new Writable(...)` carries this symbol set
// to `true`, the resulting `WritableState` stores its packed `kState` bitfield
// behind an accessor (a closure-held value) instead of a plain own data
// property. `process.stdout`/`process.stderr` opt in via this flag (see
// `createWritableStdioStream`). Those stdio streams are long lived and, under
// test runners like Jest that evaluate every test file in its own module
// realm, are re-created and exercised across a huge number of realms. In that
// scenario a synchronous write started through `writeOrBuffer()` could observe
// a stale value when `onwrite()` read `state[kState]` back from the data slot,
// making the freshly-set `kExpectWriteCb` bit look unset and throwing a
// spurious `ERR_MULTIPLE_CALLBACK`. Reading/writing the field through an
// accessor sidesteps that and keeps the bitfield optimization for every other
// (non-stdio) stream. See denoland/deno#24646.
const kForceStableState = Symbol("kForceStableState");
Writable.kForceStableState = kForceStableState;

const kSync = 1 << 9;
const kFinalCalled = 1 << 10;
const kNeedDrain = 1 << 11;
const kEnding = 1 << 12;
const kFinished = 1 << 13;
const kDecodeStrings = 1 << 14;
const kWriting = 1 << 15;
const kBufferProcessing = 1 << 16;
const kPrefinished = 1 << 17;
const kAllBuffers = 1 << 18;
const kAllNoop = 1 << 19;
const kOnFinished = 1 << 20;
const kHasWritable = 1 << 21;
const kWritable = 1 << 22;
const kCorked = 1 << 23;
const kDefaultUTF8Encoding = 1 << 24;
const kWriteCb = 1 << 25;
const kExpectWriteCb = 1 << 26;
const kAfterWriteTickInfo = 1 << 27;
const kAfterWritePending = 1 << 28;
const kBuffered = 1 << 29;
const kEnded = 1 << 30;

function writableNeedsDrain(stream) {
  const state = writableStateForStream(stream);
  return state !== undefined && (state[kState] & kNeedDrain) !== 0;
}

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
ObjectDefineProperties(WritableState.prototype, {
  // Object stream flag to indicate whether or not this stream
  // contains buffers or objects.
  objectMode: makeBitMapDescriptor(kObjectMode),

  // if _final has been called.
  finalCalled: makeBitMapDescriptor(kFinalCalled),

  // drain event flag.
  needDrain: makeBitMapDescriptor(kNeedDrain),

  // At the start of calling end()
  ending: makeBitMapDescriptor(kEnding),

  // When end() has been called, and returned.
  ended: makeBitMapDescriptor(kEnded),

  // When 'finish' is emitted.
  finished: makeBitMapDescriptor(kFinished),

  // Has it been destroyed.
  destroyed: makeBitMapDescriptor(kDestroyed),

  // Should we decode strings into buffers before passing to _write?
  // this is here so that some node-core streams can optimize string
  // handling at a lower level.
  decodeStrings: makeBitMapDescriptor(kDecodeStrings),

  // A flag to see when we're in the middle of a write.
  writing: makeBitMapDescriptor(kWriting),

  // A flag to be able to tell if the onwrite cb is called immediately,
  // or on a later tick.  We set this to true at first, because any
  // actions that shouldn't happen until "later" should generally also
  // not happen before the first write call.
  sync: makeBitMapDescriptor(kSync),

  // A flag to know if we're processing previously buffered items, which
  // may call the _write() callback in the same tick, so that we don't
  // end up in an overlapped onwrite situation.
  bufferProcessing: makeBitMapDescriptor(kBufferProcessing),

  // Stream is still being constructed and cannot be
  // destroyed until construction finished or failed.
  // Async construction is opt in, therefore we start as
  // constructed.
  constructed: makeBitMapDescriptor(kConstructed),

  // Emit prefinish if the only thing we're waiting for is _write cbs
  // This is relevant for synchronous Transform streams.
  prefinished: makeBitMapDescriptor(kPrefinished),

  // True if the error was already emitted and should not be thrown again.
  errorEmitted: makeBitMapDescriptor(kErrorEmitted),

  // Should close be emitted on destroy. Defaults to true.
  emitClose: makeBitMapDescriptor(kEmitClose),

  // Should .destroy() be called after 'finish' (and potentially 'end').
  autoDestroy: makeBitMapDescriptor(kAutoDestroy),

  // Indicates whether the stream has finished destroying.
  closed: makeBitMapDescriptor(kClosed),

  // True if close has been emitted or would have been emitted
  // depending on emitClose.
  closeEmitted: makeBitMapDescriptor(kCloseEmitted),

  allBuffers: makeBitMapDescriptor(kAllBuffers),
  allNoop: makeBitMapDescriptor(kAllNoop),

  // Indicates whether the stream has errored. When true all write() calls
  // should return false. This is needed since when autoDestroy
  // is disabled we need a way to tell whether the stream has failed.
  // This is/should be a cold path.
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

  writable: {
    __proto__: null,
    enumerable: false,
    get() {
      return (this[kState] & kHasWritable) !== 0
        ? (this[kState] & kWritable) !== 0
        : undefined;
    },
    set(value) {
      if (value == null) {
        this[kState] &= ~(kHasWritable | kWritable);
      } else if (value) {
        this[kState] |= kHasWritable | kWritable;
      } else {
        this[kState] |= kHasWritable;
        this[kState] &= ~kWritable;
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

  // The callback that the user supplies to write(chunk, encoding, cb).
  writecb: {
    __proto__: null,
    enumerable: false,
    get() {
      return (this[kState] & kWriteCb) !== 0 ? this[kWriteCbValue] : nop;
    },
    set(value) {
      this[kWriteCbValue] = value;
      if (value) {
        this[kState] |= kWriteCb;
      } else {
        this[kState] &= ~kWriteCb;
      }
    },
  },

  // Storage for data passed to the afterWrite() callback in case of
  // synchronous _write() completion.
  afterWriteTickInfo: {
    __proto__: null,
    enumerable: false,
    get() {
      return (this[kState] & kAfterWriteTickInfo) !== 0
        ? this[kAfterWriteTickInfoValue]
        : null;
    },
    set(value) {
      this[kAfterWriteTickInfoValue] = value;
      if (value) {
        this[kState] |= kAfterWriteTickInfo;
      } else {
        this[kState] &= ~kAfterWriteTickInfo;
      }
    },
  },

  buffered: {
    __proto__: null,
    enumerable: false,
    get() {
      if ((this[kState] & kBuffered) === 0) return [];
      const guarded = getGuardedWritableState(this);
      if (guarded === undefined) return this[kBufferedValue];
      if (!canInspectGuardedWritable(this)) return [];
      return ArrayPrototypeSlice(guarded.buffer, guarded.bufferedIndex);
    },
    set(value) {
      if (value) {
        const guarded = getGuardedWritableState(this);
        if (guarded === undefined) {
          this[kBufferedValue] = value;
        } else if (getStreamUseGuard(guarded.stream) === undefined) {
          return;
        } else {
          runStreamUseGuard(guarded.stream);
          guarded.buffer = ArrayPrototypeSlice(value);
          guarded.bufferedIndex = 0;
          value.length = 0;
          this[kBufferedValue] = null;
          this.bufferedIndex = 0;
        }
        this[kState] |= kBuffered;
      } else {
        setWritableStateBuffer(this, null);
        this[kState] &= ~kBuffered;
      }
    },
  },
});

function WritableState(options, stream, isDuplex) {
  // Bit map field to store WritableState more efficiently with 1 bit per field
  // instead of a V8 slot per field.
  this[kState] = kSync | kConstructed | kEmitClose | kAutoDestroy;
  WeakMapPrototypeSet(originalWritableStates, stream, this);
  WeakMapPrototypeSet(writableEnabledValues, this, true);

  // Opt-in (used by `process.stdout`/`process.stderr`): keep the `kState`
  // bitfield behind an accessor so reads always observe the latest write, even
  // across the heavy module-realm churn that test runners like Jest produce.
  // See the comment on `kForceStableState` above and denoland/deno#24646.
  if (options?.[kForceStableState]) {
    let state = this[kState];
    ObjectDefineProperty(this, kState, {
      __proto__: null,
      configurable: true,
      enumerable: false,
      get() {
        return state;
      },
      set(value) {
        state = value;
      },
    });
  }

  if (options?.objectMode) {
    this[kState] |= kObjectMode;
  }

  if (isDuplex && options?.writableObjectMode) {
    this[kState] |= kObjectMode;
  }

  // The point at which write() starts returning false
  // Note: 0 is a valid value, means that we always return false if
  // the entire buffer is not flushed immediately on write().
  const highWaterMark = options
    ? getHighWaterMark(this, options, "writableHighWaterMark", isDuplex)
    : getDefaultHighWaterMark(false);
  this.highWaterMark = highWaterMark;
  WeakMapPrototypeSet(writableHighWaterMarkValues, this, highWaterMark);

  if (!options || options.decodeStrings !== false) {
    this[kState] |= kDecodeStrings;
  }

  // Should close be emitted on destroy. Defaults to true.
  if (options && options.emitClose === false) this[kState] &= ~kEmitClose;

  // Should .destroy() be called after 'end' (and potentially 'finish').
  if (options && options.autoDestroy === false) this[kState] &= ~kAutoDestroy;

  // Crypto is kind of old and crusty.  Historically, its default string
  // encoding is 'binary' so we have to make this configurable.
  // Everything else in the universe uses 'utf8', though.
  const defaultEncoding = options ? options.defaultEncoding : null;
  if (
    defaultEncoding == null || defaultEncoding === "utf8" ||
    defaultEncoding === "utf-8"
  ) {
    this[kState] |= kDefaultUTF8Encoding;
  } else if (BufferIsEncoding(defaultEncoding)) {
    this[kState] &= ~kDefaultUTF8Encoding;
    this[kDefaultEncodingValue] = defaultEncoding;
  } else {
    throw new ERR_UNKNOWN_ENCODING(defaultEncoding);
  }

  // Not an actual buffer we keep track of, but a measurement
  // of how much we're waiting to get pushed to some underlying
  // socket or file.
  this.length = 0;

  // When true all writes will be buffered until .uncork() call.
  this.corked = 0;

  // The callback that's passed to _write(chunk, cb).
  this.onwrite = onwrite.bind(undefined, stream);

  // The amount that is being written when _write is called.
  this.writelen = 0;

  resetBuffer(this);

  // Number of pending user-supplied write callbacks
  // this must be 0 before 'finish' can be emitted.
  this.pendingcb = 0;

  registerStreamGuardAttachHook(stream, () => protectWritableState(stream));
  registerStreamDeliveryPreflight(
    stream,
    () => preflightWritableImplementation(stream),
  );
}

function resetBuffer(state) {
  const guarded = getGuardedWritableState(state);
  if (guarded === undefined) {
    state[kBufferedValue] = null;
    state.bufferedIndex = 0;
  } else {
    guarded.buffer = null;
    guarded.bufferedIndex = 0;
    state[kBufferedValue] = null;
    state.bufferedIndex = 0;
  }
  state[kState] |= kAllBuffers | kAllNoop;
  state[kState] &= ~kBuffered;
}

WritableState.prototype.getBuffer = function getBuffer() {
  return (this[kState] & kBuffered) === 0
    ? []
    : !canInspectGuardedWritable(this)
    ? []
    : ArrayPrototypeSlice(
      writableStateBuffer(this),
      writableStateBufferIndex(this),
    );
};

ObjectDefineProperty(WritableState.prototype, "bufferedRequestCount", {
  __proto__: null,
  get() {
    return (this[kState] & kBuffered) === 0
      ? 0
      : !canInspectGuardedWritable(this)
      ? 0
      : writableStateBuffer(this).length - writableStateBufferIndex(this);
  },
});

WritableState.prototype[kOnConstructed] = function onConstructed(stream) {
  if ((this[kState] & kWriting) === 0) {
    clearBuffer(stream, this);
  }

  if ((this[kState] & kEnding) !== 0) {
    finishMaybe(stream, this);
  }
};

function Writable(options) {
  if (!(this instanceof Writable)) {
    return new Writable(options);
  }

  this._events ??= {
    close: undefined,
    error: undefined,
    prefinish: undefined,
    finish: undefined,
    drain: undefined,
    // Skip uncommon events...
    // [destroyImpl.kConstruct]: undefined,
    // [destroyImpl.kDestroy]: undefined,
  };

  this._writableState = new WritableState(options, this, false);

  if (options) {
    if (typeof options.write === "function") {
      this._write = options.write;
    }

    if (typeof options.writev === "function") {
      this._writev = options.writev;
    }

    if (typeof options.destroy === "function") {
      this._destroy = options.destroy;
    }

    if (typeof options.final === "function") {
      this._final = options.final;
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
      writableStateForStream(this)[kOnConstructed](this);
    });
  }
}

ObjectDefineProperty(Writable, SymbolHasInstance, {
  __proto__: null,
  value: function (object) {
    if (FunctionPrototypeSymbolHasInstance(this, object)) return true;
    if (this !== Writable) return false;

    return object && object._writableState instanceof WritableState;
  },
});

// Otherwise people can pipe Writable streams, which is just wrong.
Writable.prototype.pipe = function () {
  errorOrDestroy(this, new ERR_STREAM_CANNOT_PIPE());
};

function _write(stream, chunk, encoding, cb) {
  const state = writableStateForStream(stream);
  runStreamUseGuard(stream);
  const admission = captureCurrentDeliveryCallback(
    invokeAdmittedWritableImplementation,
  );

  if (cb == null || typeof cb !== "function") {
    cb = nop;
  }

  if (chunk === null) {
    throw new ERR_STREAM_NULL_VALUES();
  }

  if ((state[kState] & kObjectMode) === 0) {
    if (!encoding) {
      encoding = (state[kState] & kDefaultUTF8Encoding) !== 0
        ? "utf8"
        : state.defaultEncoding;
    } else if (encoding !== "buffer" && !BufferIsEncoding(encoding)) {
      throw new ERR_UNKNOWN_ENCODING(encoding);
    }

    if (typeof chunk === "string") {
      if (encoding === "buffer") {
        throw new ERR_UNKNOWN_ENCODING(encoding);
      }
      if ((state[kState] & kDecodeStrings) !== 0) {
        chunk = bufferFrom(chunk, encoding);
        encoding = "buffer";
      }
    } else if (BufferIsBuffer(chunk)) {
      encoding = "buffer";
    } else if (ArrayBufferIsView(chunk)) {
      chunk = bufferFromArrayBufferView(chunk);
      encoding = "buffer";
    } else {
      throw new ERR_INVALID_ARG_TYPE(
        "chunk",
        ["string", "Buffer", "TypedArray", "DataView"],
        chunk,
      );
    }
  }

  // Capture before any asynchronous error or completion can resume. This is
  // intentionally unconditional: an ordinary in-flight or corked Writable may
  // become protected before its callback is delivered.
  const callbackRecord = captureWritableCallback(state, cb);

  let err;
  if ((state[kState] & kEnding) !== 0) {
    err = new ERR_STREAM_WRITE_AFTER_END();
  } else if ((state[kState] & kDestroyed) !== 0) {
    err = new ERR_STREAM_DESTROYED("write");
  }

  if (err) {
    writableNextTick(
      runScheduledWriteCallback,
      stream,
      state,
      callbackRecord,
      cb,
      err,
    );
    errorOrDestroy(stream, err, true);
    return err;
  }

  state.pendingcb++;
  return writeOrBuffer(
    stream,
    state,
    chunk,
    encoding,
    cb,
    admission,
    callbackRecord,
  );
}

Writable.prototype.write = function (chunk, encoding, cb) {
  if (encoding != null && typeof encoding === "function") {
    cb = encoding;
    encoding = null;
  }

  return _write(this, chunk, encoding, cb) === true;
};
WritablePublicWrite = Writable.prototype.write;

Writable.prototype.cork = function () {
  const state = writableStateForStream(this);

  state[kState] |= kCorked;
  state.corked++;
};

Writable.prototype.uncork = function () {
  runStreamUseGuard(this);
  const state = writableStateForStream(this);

  if (state.corked) {
    state.corked--;

    if (!state.corked) {
      state[kState] &= ~kCorked;
    }

    if ((state[kState] & kWriting) === 0) {
      clearBuffer(this, state);
    }
  }
};
WritablePrototypeUncork = Writable.prototype.uncork;

Writable.prototype.setDefaultEncoding = function setDefaultEncoding(encoding) {
  // node::ParseEncoding() requires lower case.
  if (typeof encoding === "string") {
    encoding = StringPrototypeToLowerCase(encoding);
  }
  if (!BufferIsEncoding(encoding)) {
    throw new ERR_UNKNOWN_ENCODING(encoding);
  }
  writableStateForStream(this).defaultEncoding = encoding;
  return this;
};

// If we're already writing something, then just put this
// in the queue, and wait our turn.  Otherwise, call _write
// If we return false, then we need a drain event, so set that flag.
function writeOrBuffer(
  stream,
  state,
  chunk,
  encoding,
  callback,
  admission,
  callbackRecord,
) {
  const len = writableChunkLength(state, chunk);

  state.length += len;

  if (
    (state[kState] & (kWriting | kErrored | kCorked | kConstructed)) !==
      kConstructed
  ) {
    if ((state[kState] & kBuffered) === 0) {
      state[kState] |= kBuffered;
      setWritableStateBuffer(state, []);
    }

    const entry = { chunk, encoding, callback };
    WeakMapPrototypeSet(bufferedWriteAdmissions, entry, admission);
    if (callbackRecord !== undefined) {
      WeakMapPrototypeSet(
        bufferedWriteCallbackRecords,
        entry,
        callbackRecord,
      );
    }
    ArrayPrototypePush(writableStateBuffer(state), entry);
    if ((state[kState] & kAllBuffers) !== 0 && encoding !== "buffer") {
      state[kState] &= ~kAllBuffers;
    }
    if ((state[kState] & kAllNoop) !== 0 && callback !== nop) {
      state[kState] &= ~kAllNoop;
    }
  } else {
    state.writelen = len;
    if (callback !== nop && getGuardedWritableState(state) === undefined) {
      state.writecb = callback;
    }
    setActiveWriteCallbackRecord(
      state,
      singleWriteCallbackCompletion(callbackRecord),
    );
    state[kState] |= kWriting | kSync | kExpectWriteCb;
    // The immediate path is still on the admitting call stack. Preserve that
    // live actor instead of replacing it with a detached-continuation stamp;
    // buffered paths below restore their stored admission explicitly.
    invokeWritableImplementation(
      stream,
      state,
      false,
      chunk,
      encoding,
      writableOnwrite(state),
    );
    state[kState] &= ~kSync;
  }

  const ret = state.length < writableStateHighWaterMark(state) ||
    state.length === 0;

  if (!ret) {
    state[kState] |= kNeedDrain;
  }

  // Return false if errored or destroyed in order to break
  // any synchronous while(stream.write(data)) loops.
  return ret && (state[kState] & (kDestroyed | kErrored)) === 0;
}

function doWrite(
  stream,
  state,
  writev,
  len,
  chunk,
  encoding,
  cb,
  admission,
  completion,
) {
  state.writelen = len;
  if (cb !== nop && getGuardedWritableState(state) === undefined) {
    state.writecb = cb;
  }
  setActiveWriteCallbackRecord(state, completion);
  state[kState] |= kWriting | kSync | kExpectWriteCb;
  if ((state[kState] & kDestroyed) !== 0) {
    writableOnwrite(state)(new ERR_STREAM_DESTROYED("write"));
  } else if (writev) {
    invokeWritableAdmission(
      admission,
      stream,
      state,
      true,
      chunk,
      encoding,
      writableOnwrite(state),
    );
  } else {
    invokeWritableAdmission(
      admission,
      stream,
      state,
      false,
      chunk,
      encoding,
      writableOnwrite(state),
    );
  }
  state[kState] &= ~kSync;
}

function onwriteError(stream, state, er, cb, completion) {
  --state.pendingcb;

  if (getGuardedWritableState(state) === undefined) {
    cb(er);
  } else if (completion !== undefined) {
    invokeProtectedWriteCallback(stream, completion, er);
  }
  // Ensure callbacks are invoked even when autoDestroy is
  // not enabled. Passing `er` here doesn't make sense since
  // it's related to one specific write, not to the buffered
  // writes.
  errorBuffer(state);
  // This can emit error, but error must always follow cb.
  errorOrDestroy(stream, er);
}

function onwrite(stream, er) {
  const state = writableStateForStream(stream);

  if ((state[kState] & kExpectWriteCb) === 0) {
    errorOrDestroy(stream, new ERR_MULTIPLE_CALLBACK());
    return;
  }

  const sync = (state[kState] & kSync) !== 0;
  const completion = takeActiveWriteCallbackRecord(state);
  const protectedState = getGuardedWritableState(state) !== undefined;
  const cb = protectedState
    ? completion?.callback ?? nop
    : (state[kState] & kWriteCb) !== 0
    ? state[kWriteCbValue]
    : nop;

  if (protectedState) state[kState] &= ~kWriteCb;
  else state.writecb = null;
  state[kState] &= ~(kWriting | kExpectWriteCb);
  state.length -= state.writelen;
  state.writelen = 0;

  if (er) {
    // Avoid V8 leak, https://github.com/nodejs/node/pull/34103#issuecomment-652002364
    er.stack; // eslint-disable-line no-unused-expressions

    if ((state[kState] & kErrored) === 0) {
      state[kErroredValue] = er;
      state[kState] |= kErrored;
    }

    // In case of duplex streams we need to notify the readable side of the
    // error.
    if (stream._readableState && !stream._readableState.errored) {
      stream._readableState.errored = er;
    }

    if (sync) {
      writableNextTick(onwriteError, stream, state, er, cb, completion);
    } else {
      onwriteError(stream, state, er, cb, completion);
    }
  } else {
    if ((state[kState] & kBuffered) !== 0) {
      clearBuffer(stream, state);
    }

    if (sync) {
      const needDrain = (state[kState] & kNeedDrain) !== 0 &&
        state.length === 0;
      const needTick = needDrain || (state[kState] & kDestroyed !== 0) ||
        cb !== nop;

      // It is a common case that the callback passed to .write() is always
      // the same. In that case, we do not schedule a new nextTick(), but
      // rather just increase a counter, to improve performance and avoid
      // memory allocations.
      if (cb === nop) {
        if ((state[kState] & kAfterWritePending) === 0 && needTick) {
          writableNextTick(
            afterWrite,
            stream,
            state,
            1,
            cb,
            undefined,
          );
          state[kState] |= kAfterWritePending;
        } else {
          state.pendingcb--;
          if ((state[kState] & kEnding) !== 0) {
            finishMaybe(stream, state, true);
          }
        }
      } else {
        const activeTickInfo = protectedState
          ? WeakMapPrototypeGet(activeAfterWriteTickInfos, state)
          : (state[kState] & kAfterWriteTickInfo) !== 0
          ? state[kAfterWriteTickInfoValue]
          : undefined;
        const callbackRecords = WeakMapPrototypeGet(
          afterWriteTickCallbackRecords,
          activeTickInfo,
        );
        if (callbackRecords?.callback === cb) {
          callbackRecords.count++;
          insertWriteCallbackRecord(
            callbackRecords.completions,
            completion,
          );
          if (!protectedState) activeTickInfo.count++;
        } else if (needTick) {
          const tickInfo = { count: 1, cb, stream, state };
          const newCallbackRecords = {
            callback: cb,
            completions: [],
            count: 1,
            state,
            stream,
          };
          insertWriteCallbackRecord(
            newCallbackRecords.completions,
            completion,
          );
          WeakMapPrototypeSet(
            activeAfterWriteTickInfos,
            state,
            tickInfo,
          );
          WeakMapPrototypeSet(
            afterWriteTickCallbackRecords,
            tickInfo,
            newCallbackRecords,
          );
          if (!protectedState) {
            state[kAfterWriteTickInfoValue] = tickInfo;
            state[kState] |= kAfterWriteTickInfo;
          }
          writableNextTick(afterWriteTick, tickInfo);
          state[kState] |= kAfterWritePending;
        } else {
          state.pendingcb--;
          if ((state[kState] & kEnding) !== 0) {
            finishMaybe(stream, state, true);
          }
        }
      }
    } else {
      afterWrite(
        stream,
        state,
        1,
        cb,
        completion === undefined ? undefined : [completion],
      );
    }
  }
}

function afterWriteTick(info) {
  const callbackRecords = WeakMapPrototypeGet(
    afterWriteTickCallbackRecords,
    info,
  );
  WeakMapPrototypeDelete(afterWriteTickCallbackRecords, info);
  const protectedState = callbackRecords !== undefined &&
    getGuardedWritableState(callbackRecords.state) !== undefined;
  const stream = protectedState ? callbackRecords.stream : info.stream;
  const state = protectedState ? callbackRecords.state : info.state;
  const count = protectedState ? callbackRecords.count : info.count;
  const cb = protectedState ? callbackRecords.callback : info.cb;
  WeakMapPrototypeDelete(activeAfterWriteTickInfos, state);
  state[kState] &= ~kAfterWriteTickInfo;
  if (!protectedState) state[kAfterWriteTickInfoValue] = null;
  return afterWrite(
    stream,
    state,
    count,
    cb,
    protectedState ? callbackRecords.completions : undefined,
  );
}

function afterWrite(stream, state, count, cb, callbackRecords) {
  state[kState] &= ~kAfterWritePending;

  const needDrain =
    (state[kState] & (kEnding | kNeedDrain | kDestroyed)) === kNeedDrain &&
    state.length === 0;
  if (needDrain) {
    state[kState] &= ~kNeedDrain;
    stream.emit("drain");
  }

  if (getGuardedWritableState(state) === undefined) {
    while (count-- > 0) {
      state.pendingcb--;
      cb(null);
    }
  } else if (cb === nop) {
    state.pendingcb -= count;
  } else {
    for (let i = 0; i < count; i++) {
      state.pendingcb--;
      const completion = callbackRecords?.[i];
      if (completion !== undefined) {
        invokeProtectedWriteCallback(stream, completion, null);
      }
    }
  }

  if ((state[kState] & kDestroyed) !== 0) {
    errorBuffer(state);
  }

  if ((state[kState] & kEnding) !== 0) {
    finishMaybe(stream, state, true);
  }
}

// If there's something in the buffer waiting, then invoke callbacks.
function errorBuffer(state) {
  const previous = core.getAsyncContext();
  core.setAsyncContext(undefined);
  try {
    errorBufferWithoutContext(state);
  } finally {
    core.setAsyncContext(previous);
  }
}

// Destroy-time queue cleanup must not lend the destroying operation's
// positive context to package callbacks or originless bound gadgets.
// @ref LLP 0019#operation-scoped-positive-authority-provenance [implements]
function errorBufferWithoutContext(state) {
  if ((state[kState] & kWriting) !== 0) {
    return;
  }

  if ((state[kState] & kBuffered) !== 0) {
    const buffered = writableStateBufferForCleanup(state);
    const guarded = getGuardedWritableState(state);
    const bufferedIndex = guarded?.bufferedIndex ?? state.bufferedIndex;
    for (let n = bufferedIndex; n < buffered.length; ++n) {
      const entry = buffered[n];
      const { chunk, callback } = entry;
      const callbackRecord = takeBufferedWriteCallbackRecord(entry);
      const len = writableChunkLength(state, chunk);
      state.length -= len;
      const error = state.errored ?? new ERR_STREAM_DESTROYED("write");
      if (guarded === undefined) callback(error);
      else if (callbackRecord !== undefined) {
        runCapturedCallback(callbackRecord.captured, undefined, [error]);
      }
    }
  }

  callFinishedCallbacks(
    state,
    state.errored ?? new ERR_STREAM_DESTROYED("end"),
  );

  resetBuffer(state);
}

// If there's something in the buffer waiting, then process it.
function clearBuffer(stream, state) {
  if (
    (state[kState] &
      (kDestroyed | kBufferProcessing | kCorked | kBuffered | kConstructed)) !==
      (kBuffered | kConstructed)
  ) {
    return;
  }

  const objectMode = (state[kState] & kObjectMode) !== 0;
  const guarded = getGuardedWritableState(state);
  const buffered = writableStateBufferForCleanup(state);
  const bufferedIndex = guarded?.bufferedIndex ?? state.bufferedIndex;
  const bufferedLength = buffered.length - bufferedIndex;

  if (!bufferedLength) {
    return;
  }

  // A queued write keeps the actor that admitted it. Recheck every member of
  // a prospective _writev batch before any chunk leaves the private queue;
  // this also prevents pre-activation corked writes from being laundered by a
  // later root-side uncork.
  // @ref LLP 0019#operation-scoped-positive-authority-provenance [implements]
  for (let n = bufferedIndex; n < buffered.length; n++) {
    preflightWritableAdmission(stream, buffered[n]);
  }

  let i = bufferedIndex;

  state[kState] |= kBufferProcessing;
  if (bufferedLength > 1 && hasWritableWritev(stream, state)) {
    state.pendingcb -= bufferedLength - 1;

    const callback = (state[kState] & kAllNoop) !== 0 ? nop : (err) => {
      for (let n = i; n < buffered.length; ++n) {
        buffered[n].callback(err);
      }
    };
    // Make a copy of `buffered` if it's going to be used by `callback` above,
    // since `doWrite` will mutate the array.
    const chunks = (state[kState] & kAllNoop) !== 0 && i === 0
      ? buffered
      : ArrayPrototypeSlice(buffered, i);
    chunks.allBuffers = (state[kState] & kAllBuffers) !== 0;
    const completion = batchWriteCallbackCompletion(callback, buffered, i);

    doWrite(
      stream,
      state,
      true,
      state.length,
      chunks,
      "",
      callback,
      writableAdmission(buffered[i]),
      completion,
    );

    resetBuffer(state);
  } else {
    do {
      const entry = buffered[i];
      const { chunk, encoding, callback } = entry;
      const callbackRecord = takeBufferedWriteCallbackRecord(entry);
      buffered[i++] = null;
      const len = objectMode ? 1 : writableChunkLength(state, chunk);
      doWrite(
        stream,
        state,
        false,
        len,
        chunk,
        encoding,
        callback,
        writableAdmission(entry),
        singleWriteCallbackCompletion(callbackRecord),
      );
    } while (i < buffered.length && (state[kState] & kWriting) === 0);

    if (i === buffered.length) {
      resetBuffer(state);
    } else if (i > 256) {
      ArrayPrototypeSplice(buffered, 0, i);
      if (guarded === undefined) state.bufferedIndex = 0;
      else guarded.bufferedIndex = 0;
    } else {
      if (guarded === undefined) state.bufferedIndex = i;
      else guarded.bufferedIndex = i;
    }
  }
  state[kState] &= ~kBufferProcessing;
}

Writable.prototype._write = function (chunk, encoding, cb) {
  if (this._writev) {
    this._writev([{ chunk, encoding }], cb);
  } else {
    throw new ERR_METHOD_NOT_IMPLEMENTED("_write()");
  }
};

WritablePrototypeWrite = Writable.prototype._write;

Writable.prototype._writev = null;

Writable.prototype.end = function (chunk, encoding, cb) {
  const cleanupEnd = WeakMapPrototypeGet(protectedWritableCleanupEnds, this) ===
    true;
  if (cleanupEnd) {
    WeakMapPrototypeDelete(protectedWritableCleanupEnds, this);
  }
  const state = writableStateForStream(this);

  if (typeof chunk === "function") {
    cb = chunk;
    chunk = null;
    encoding = null;
  } else if (typeof encoding === "function") {
    cb = encoding;
    encoding = null;
  }

  // A no-chunk half-close with no queued delivery or unsafe application final
  // hook is terminal cleanup, not a new byte effect. Keep the public Node
  // behavior aligned with the private pipe-cleanup entry while still guarding
  // every end() that can flush or manufacture application data.
  if (
    !cleanupEnd &&
    (chunk != null || !canEndProtectedWritableCleanup(this, state))
  ) {
    runStreamUseGuard(this);
  }

  // Capture at registration, before an end chunk can complete synchronously.
  // This must also cover an ordinary stream that becomes protected before its
  // deferred finish callback runs.
  const callbackRecord = typeof cb === "function"
    ? captureEndCallback(cb)
    : undefined;

  let err;

  if (chunk != null) {
    const ret = _write(this, chunk, encoding);
    if (ret instanceof Error) {
      err = ret;
    }
  }

  // .end() fully uncorks.
  if ((state[kState] & kCorked) !== 0) {
    state.corked = 1;
    FunctionPrototypeCall(WritablePrototypeUncork, this);
  }

  if (err) {
    // Do nothing...
  } else if ((state[kState] & (kEnding | kErrored)) === 0) {
    // This is forgiving in terms of unnecessary calls to end() and can hide
    // logic errors. However, usually such errors are harmless and causing a
    // hard error can be disproportionately destructive. It is not always
    // trivial for the user to determine whether end() needs to be called
    // or not.

    state[kState] |= kEnding;
    finishMaybe(this, state, true);
    state[kState] |= kEnded;
  } else if ((state[kState] & kFinished) !== 0) {
    err = new ERR_STREAM_ALREADY_FINISHED("end");
  } else if ((state[kState] & kDestroyed) !== 0) {
    err = new ERR_STREAM_DESTROYED("end");
  }

  if (typeof cb === "function") {
    if (err) {
      writableNextTick(
        runScheduledEndCallback,
        state,
        callbackRecord,
        cb,
        err,
      );
    } else if ((state[kState] & kErrored) !== 0) {
      writableNextTick(
        runScheduledEndCallback,
        state,
        callbackRecord,
        cb,
        state[kErroredValue],
      );
    } else if ((state[kState] & kFinished) !== 0) {
      writableNextTick(
        runScheduledEndCallback,
        state,
        callbackRecord,
        cb,
        null,
      );
    } else {
      state[kState] |= kOnFinished;
      if (getGuardedWritableState(state) === undefined) {
        state[kOnFinishedValue] ??= [];
        state[kOnFinishedValue].push(cb);
      }
      appendEndCallbackRecord(state, callbackRecord);
    }
  }

  return this;
};
WritablePublicEnd = Writable.prototype.end;

function needFinish(state) {
  return (
    // State is ended && constructed but not destroyed, finished, writing, errorEmitted or closedEmitted
    (state[kState] & (
        kEnding |
        kDestroyed |
        kConstructed |
        kFinished |
        kWriting |
        kErrorEmitted |
        kCloseEmitted |
        kErrored |
        kBuffered
      )) === (kEnding | kConstructed) && state.length === 0
  );
}

function onFinish(stream, state, err) {
  if ((state[kState] & kPrefinished) !== 0) {
    errorOrDestroy(stream, err ?? new ERR_MULTIPLE_CALLBACK());
    return;
  }
  state.pendingcb--;
  if (err) {
    callFinishedCallbacks(state, err);
    errorOrDestroy(stream, err, (state[kState] & kSync) !== 0);
  } else if (needFinish(state)) {
    state[kState] |= kPrefinished;
    stream.emit("prefinish");
    // Backwards compat. Don't check state.sync here.
    // Some streams assume 'finish' will be emitted
    // asynchronously relative to _final callback.
    state.pendingcb++;
    writableNextTick(finish, stream, state);
  }
}

function prefinish(stream, state) {
  if ((state[kState] & (kPrefinished | kFinalCalled)) !== 0) {
    return;
  }

  if (
    hasWritableFinal(stream, state) && (state[kState] & kDestroyed) === 0
  ) {
    state[kState] |= kFinalCalled | kSync;
    state.pendingcb++;

    try {
      invokeWritableFinal(stream, state, (err) => onFinish(stream, state, err));
    } catch (err) {
      onFinish(stream, state, err);
    }

    state[kState] &= ~kSync;
  } else {
    state[kState] |= kFinalCalled | kPrefinished;
    stream.emit("prefinish");
  }
}

function finishMaybe(stream, state, sync) {
  if (needFinish(state)) {
    prefinish(stream, state);
    if (state.pendingcb === 0) {
      if (sync) {
        state.pendingcb++;
        writableNextTick(
          (stream, state) => {
            if (needFinish(state)) {
              finish(stream, state);
            } else {
              state.pendingcb--;
            }
          },
          stream,
          state,
        );
      } else if (needFinish(state)) {
        state.pendingcb++;
        finish(stream, state);
      }
    }
  }
}

function finish(stream, state) {
  state.pendingcb--;
  state[kState] |= kFinished;

  callFinishedCallbacks(state, null);

  stream.emit("finish");

  if ((state[kState] & kAutoDestroy) !== 0) {
    // In case of duplex streams we need a way to detect
    // if the readable side is ready for autoDestroy as well.
    const rState = stream._readableState;
    const autoDestroy = !rState || (
      rState.autoDestroy &&
      // We don't expect the readable to ever 'end'
      // if readable is explicitly set to false.
      (rState.endEmitted || rState.readable === false)
    );
    if (autoDestroy) {
      stream.destroy();
    }
  }
}

function callFinishedCallbacks(state, err) {
  if ((state[kState] & kOnFinished) === 0) {
    WeakMapPrototypeDelete(endCallbackRecords, state);
    return;
  }

  const protectedState = getGuardedWritableState(state) !== undefined;
  const onfinishCallbacks = protectedState
    ? undefined
    : state[kOnFinishedValue];
  if (!protectedState) state[kOnFinishedValue] = null;
  state[kState] &= ~kOnFinished;
  const records = WeakMapPrototypeGet(endCallbackRecords, state);
  WeakMapPrototypeDelete(endCallbackRecords, state);
  if (!protectedState) {
    for (let i = 0; i < onfinishCallbacks.length; i++) {
      onfinishCallbacks[i](err);
    }
    return;
  }
  if (records === undefined) return;
  for (let i = 0; i < records.callbacks.length; i++) {
    runCapturedCallback(records.callbacks[i], records.receiver, [err]);
  }
}

ObjectDefineProperties(Writable.prototype, {
  closed: {
    __proto__: null,
    get() {
      const state = writableStateForStream(this);
      return state ? (state[kState] & kClosed) !== 0 : false;
    },
  },

  destroyed: {
    __proto__: null,
    get() {
      const state = writableStateForStream(this);
      return state ? (state[kState] & kDestroyed) !== 0 : false;
    },
    set(value) {
      // Backward compatibility, the user is explicitly managing destroyed.
      const state = writableStateForStream(this);
      if (!state) return;

      if (value) state[kState] |= kDestroyed;
      else state[kState] &= ~kDestroyed;
    },
  },

  writable: {
    __proto__: null,
    get() {
      const w = writableStateForStream(this);
      // w.writable === false means that this is part of a Duplex stream
      // where the writable side was disabled upon construction.
      // Compat. The user might manually disable writable side through
      // deprecated setter.
      return !!w && writableStateEnabled(w) &&
        (w[kState] & (kEnding | kEnded | kDestroyed | kErrored)) === 0;
    },
    set(val) {
      // Backwards compatible.
      const state = writableStateForStream(this);
      if (state) setWritableStateEnabled(state, !!val);
    },
  },

  writableFinished: {
    __proto__: null,
    get() {
      const state = writableStateForStream(this);
      return state ? (state[kState] & kFinished) !== 0 : false;
    },
  },

  writableObjectMode: {
    __proto__: null,
    get() {
      const state = writableStateForStream(this);
      return state ? (state[kState] & kObjectMode) !== 0 : false;
    },
  },

  writableBuffer: {
    __proto__: null,
    get() {
      const state = writableStateForStream(this);
      return state && state.getBuffer();
    },
  },

  writableEnded: {
    __proto__: null,
    get() {
      const state = writableStateForStream(this);
      return state ? (state[kState] & kEnding) !== 0 : false;
    },
  },

  writableNeedDrain: {
    __proto__: null,
    get() {
      const state = writableStateForStream(this);
      return state
        ? (state[kState] & (kDestroyed | kEnding | kNeedDrain)) === kNeedDrain
        : false;
    },
  },

  writableHighWaterMark: {
    __proto__: null,
    get() {
      const state = writableStateForStream(this);
      return state === undefined
        ? undefined
        : writableStateHighWaterMark(state);
    },
  },

  writableCorked: {
    __proto__: null,
    get() {
      const state = writableStateForStream(this);
      return state ? state.corked : 0;
    },
  },

  writableLength: {
    __proto__: null,
    get() {
      const state = writableStateForStream(this);
      return state?.length;
    },
  },

  errored: {
    __proto__: null,
    enumerable: false,
    get() {
      const state = writableStateForStream(this);
      return state ? state.errored : null;
    },
  },

  writableAborted: {
    __proto__: null,
    get: function () {
      const state = writableStateForStream(this);
      return (
        (state[kState] & (kHasWritable | kWritable)) !== kHasWritable &&
        (state[kState] & (kDestroyed | kErrored)) !== 0 &&
        (state[kState] & kFinished) === 0
      );
    },
  },
});

const destroy = destroyImpl.destroy;
Writable.prototype.destroy = function (err, cb) {
  const state = writableStateForStream(this);

  // Invoke pending callbacks.
  if (
    (state[kState] & (kBuffered | kOnFinished)) !== 0 &&
    (state[kState] & kDestroyed) === 0
  ) {
    writableNextTick(errorBuffer, state);
  }

  destroy.call(this, err, cb);
  return this;
};
WritablePublicDestroy = Writable.prototype.destroy;

Writable.prototype._undestroy = destroyImpl.undestroy;
Writable.prototype._destroy = function (err, cb) {
  cb(err);
};

Writable.prototype[EE.captureRejectionSymbol] = function (err) {
  this.destroy(err);
};

let webStreamsAdapters;

// Lazy to avoid circular references
function lazyWebStreams() {
  if (webStreamsAdapters === undefined) {
    webStreamsAdapters = core.loadExtScript(webStreamsAdaptersSpecifier);
  }
  return webStreamsAdapters;
}

Writable.fromWeb = function (writableStream, options) {
  return lazyWebStreams().newStreamWritableFromWritableStream(
    writableStream,
    options,
  );
};

Writable.toWeb = function (streamWritable) {
  return lazyWebStreams().newWritableStreamFromStreamWritable(
    streamWritable,
  );
};

Writable.prototype[SymbolAsyncDispose] = function () {
  let error;
  if (!this.destroyed) {
    error = this.writableFinished ? null : new AbortError();
    this.destroy(error);
  }
  return new Promise((resolve, reject) =>
    eos(
      this,
      (err) => (err && err.name !== "AbortError" ? reject(err) : resolve(null)),
    )
  );
};

return {
  default: Writable,
  destroyProtectedWritable,
  endProtectedWritableCleanup,
  isRegisteredWritable,
  isWritableActive,
  isWritableDestroyed,
  isWritableEnabled,
  isWritableEnded,
  isWritablePublicEnd,
  isWritablePublicUncork,
  isWritablePublicWrite,
  isWritableStateProtected,
  prepareWritableForProtection,
  protectedWritableEnd,
  protectedWritableUncork,
  protectedWritableWrite,
  setWritableActive,
  setWritableUseGuard,
  Writable,
  writableNeedsDrain,
  writableHighWaterMark,
  writableObjectMode,
  writableStateForStream,
};
})();

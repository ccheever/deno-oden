// deno-lint-ignore-file
// Copyright 2018-2026 the Deno authors. MIT license.
import process from "node:process";
import { core, primordials } from "ext:core/mod.js";
const { nextTick: ProtectedDuplexifyNextTick } = core.loadExtScript(
  "ext:deno_node/_next_tick.ts",
);

const {
  isDuplexNodeStream,
  isIterable,
  isNodeStream,
  isReadable,
  isReadableNodeStream,
  isReadableStream,
  isWritable,
  isWritableNodeStream,
  isWritableStream,
} = core.loadExtScript("ext:deno_node/internal/streams/utils.js");

const eos =
  core.loadExtScript("ext:deno_node/internal/streams/end-of-stream.js").default;
const imported1 = core.loadExtScript("ext:deno_node/internal/errors.ts");
const { destroyer } = core.loadExtScript(
  "ext:deno_node/internal/streams/destroy.js",
);
import Duplex from "node:_stream_duplex";
import Readable from "node:_stream_readable";
import Writable from "node:_stream_writable";
const {
  getReadableUseGuard,
  isRegisteredReadable,
  isReadablePublicLifecycleMethod,
  isReadablePublicRead,
  pushReadableChunk,
  setReadableActive,
} = core.loadExtScript("ext:deno_node/internal/streams/readable.js");
const {
  isRegisteredWritable,
  isWritablePublicEnd,
  isWritablePublicWrite,
  setWritableActive,
} = core.loadExtScript("ext:deno_node/internal/streams/writable.js");
const { isEventEmitterPublicLifecycleMethod } = core.loadExtScript(
  "ext:deno_node/_events.mjs",
);
const {
  captureCurrentDeliveryCallback,
  captureDeliveryCallback,
  captureTrustedDeliveryCallback,
  linkStreamUseGuard,
  markStreamTrustedDeliveryCallback,
  preflightCapturedDelivery,
  preflightStreamDelivery,
  registerStreamDeliveryPreflight,
  runCapturedCallback,
  runCapturedDelivery,
  runStreamUseGuard,
  wrapIterableDelivery,
} = core.loadExtScript(
  "ext:deno_node/internal/streams/oden_delivery.js",
);
import from from "ext:deno_node/internal/streams/from.js";
const { isBlob } = core.loadExtScript("ext:deno_web/09_file.js");
const { AbortController } = core.loadExtScript(
  "ext:deno_web/03_abort_signal.js",
);

const {
  AbortError,
  codes: {
    ERR_INVALID_ARG_TYPE,
    ERR_INVALID_RETURN_VALUE,
  },
} = imported1;

"use strict";

const {
  FunctionPrototypeCall,
  PromiseWithResolvers,
} = primordials;

let _Duplexify;

function nextTickWithCurrent(callback, ...args) {
  const captured = captureCurrentDeliveryCallback(callback);
  FunctionPrototypeCall(
    ProtectedDuplexifyNextTick,
    process,
    () => runCapturedCallback(captured, undefined, args),
  );
}

function captureReadableMethod(stream, method) {
  return isRegisteredReadable(stream) && isReadablePublicRead(method)
    ? captureTrustedDeliveryCallback(method)
    : captureDeliveryCallback(method);
}

function captureWritableMethod(stream, method, end = false) {
  return isRegisteredWritable(stream) &&
      (isWritablePublicWrite(method) || end && isWritablePublicEnd(method))
    ? captureTrustedDeliveryCallback(method)
    : captureDeliveryCallback(method);
}

function captureLifecycleMethod(stream, method) {
  return (isReadablePublicLifecycleMethod(method) ||
      isEventEmitterPublicLifecycleMethod(method)) &&
      (isRegisteredReadable(stream) || isRegisteredWritable(stream))
    ? captureTrustedDeliveryCallback(method)
    : captureDeliveryCallback(method);
}

function markDuplexifyImplementations(stream) {
  if (typeof stream._write === "function") {
    markStreamTrustedDeliveryCallback(stream, stream._write);
  }
  if (typeof stream._final === "function") {
    markStreamTrustedDeliveryCallback(stream, stream._final);
  }
}

function registerBodyPreflight(stream, carrier, capturedBody) {
  registerStreamDeliveryPreflight(
    stream,
    () => preflightCapturedDelivery(carrier, capturedBody),
  );
}

function getThen() {
  return this?.then;
}

function propagateReadableUseGuard(source, readable) {
  // Keep constituent provenance live across preconstructed conversions.
  // @ref LLP 0019#operation-scoped-positive-authority-provenance [implements]
  linkStreamUseGuard(source, readable);
  return readable;
}

export default function duplexify(body, name) {
  // This is needed for pre node 17.
  class Duplexify extends Duplex {
    constructor(options) {
      super(options);

      // https://github.com/nodejs/node/pull/34385

      if (options?.readable === false) {
        setReadableActive(this, false);
        this._readableState.ended = true;
        this._readableState.endEmitted = true;
      }

      if (options?.writable === false) {
        setWritableActive(this, false);
        this._writableState.ending = true;
        this._writableState.ended = true;
        this._writableState.finished = true;
      }
    }
  }

  _Duplexify = Duplexify;

  if (isDuplexNodeStream(body)) {
    return body;
  }

  if (isReadableNodeStream(body)) {
    return _duplexify({ readable: body });
  }

  if (isWritableNodeStream(body)) {
    return _duplexify({ writable: body });
  }

  if (isNodeStream(body)) {
    return _duplexify({ writable: false, readable: false });
  }

  if (isReadableStream(body)) {
    return _duplexify({ readable: Readable.fromWeb(body) });
  }

  if (isWritableStream(body)) {
    return _duplexify({ writable: Writable.fromWeb(body) });
  }

  if (typeof body === "function") {
    const {
      bindDuplex,
      capturedBody,
      carrier,
      destroy,
      final,
      value,
      write,
    } = fromAsyncGen(body);

    // Body might be a constructor function instead of an async generator function.
    if (isDuplexNodeStream(value)) {
      bindDuplex(value);
      return value;
    }

    if (isIterable(value)) {
      const guardedValue = wrapIterableDelivery(value, body);
      const readable = from(Duplexify, guardedValue, {
        // TODO (ronag): highWaterMark?
        objectMode: true,
        write,
        final,
        destroy,
      });
      markDuplexifyImplementations(readable);
      bindDuplex(readable);
      linkStreamUseGuard(carrier, guardedValue);
      registerBodyPreflight(readable, carrier, capturedBody);
      return readable;
    }

    const capturedThenGetter = captureDeliveryCallback(body, getThen);
    const then = runCapturedDelivery(
      carrier,
      capturedThenGetter,
      value,
      [],
    );
    if (typeof then === "function") {
      let promise;
      const d = new Duplexify({
        // TODO (ronag): highWaterMark?
        objectMode: true,
        readable: false,
        write,
        final(cb) {
          final(async () => {
            try {
              await promise;
              nextTickWithCurrent(cb, null);
            } catch (err) {
              nextTickWithCurrent(cb, err);
            }
          });
        },
        destroy,
      });
      markDuplexifyImplementations(d);
      bindDuplex(d);
      registerBodyPreflight(d, carrier, capturedBody);
      const capturedThen = captureDeliveryCallback(body, then);
      promise = runCapturedDelivery(carrier, capturedThen, value, [
        (val) => {
          preflightCapturedDelivery(carrier, capturedBody);
          if (val != null) {
            throw new ERR_INVALID_RETURN_VALUE("nully", "body", val);
          }
        },
        (err) => {
          destroyer(d, err);
        },
      ]);
      return d;
    }

    throw new ERR_INVALID_RETURN_VALUE(
      "Iterable, AsyncIterable or AsyncFunction",
      name,
      value,
    );
  }

  if (isBlob(body)) {
    return duplexify(body.arrayBuffer());
  }

  if (isIterable(body)) {
    const guardedBody = wrapIterableDelivery(body);
    const readable = from(Duplexify, guardedBody, {
      // TODO (ronag): highWaterMark?
      objectMode: true,
      writable: false,
    });
    return propagateReadableUseGuard(body, readable);
  }

  const bodyReadable = body?.readable;
  const bodyWritable = body?.writable;
  if (isReadableStream(bodyReadable) && isWritableStream(bodyWritable)) {
    return Duplexify.fromWeb(body);
  }

  if (
    typeof bodyWritable === "object" ||
    typeof bodyReadable === "object"
  ) {
    const readable = bodyReadable
      ? isReadableNodeStream(bodyReadable)
        ? bodyReadable
        : duplexify(bodyReadable)
      : undefined;

    const writable = bodyWritable
      ? isWritableNodeStream(bodyWritable)
        ? bodyWritable
        : duplexify(bodyWritable)
      : undefined;

    return _duplexify({ readable, writable });
  }

  const then = body?.then;
  if (typeof then === "function") {
    const d = new Duplexify({
      objectMode: true,
      writable: false,
      read() {},
    });
    propagateReadableUseGuard(body, d);
    const capturedThen = captureDeliveryCallback(then);
    const invokeThen = getReadableUseGuard(d) === undefined
      ? runCapturedCallback
      : (captured, receiver, args) =>
        runCapturedDelivery(d, captured, receiver, args);
    invokeThen(capturedThen, body, [
      (val) => {
        runStreamUseGuard(d);
        if (val != null) {
          pushReadableChunk(d, val);
        }
        pushReadableChunk(d, null);
      },
      (err) => {
        destroyer(d, err);
      },
    ]);
    return d;
  }

  throw new ERR_INVALID_ARG_TYPE(
    name,
    [
      "Blob",
      "ReadableStream",
      "WritableStream",
      "Stream",
      "Iterable",
      "AsyncIterable",
      "Function",
      "{ readable, writable } pair",
      "Promise",
    ],
    body,
  );
}

function fromAsyncGen(fn) {
  let { promise, resolve } = PromiseWithResolvers();
  const ac = new AbortController();
  const signal = ac.signal;
  const carrier = {};
  const capturedBody = captureDeliveryCallback(fn);
  const input = async function* () {
  while (true) {
    const _promise = promise;
    promise = null;
    const { chunk, done, cb } = await _promise;
    nextTickWithCurrent(() => runCapturedCallback(cb, undefined, []));
    if (done) return;
    if (signal.aborted) {
      throw new AbortError(undefined, { cause: signal.reason });
    }
    preflightCapturedDelivery(carrier, capturedBody);
    ({ promise, resolve } = PromiseWithResolvers());
    yield chunk;
  }
  }();
  const guardedInput = wrapIterableDelivery(input, fn);
  const value = runCapturedDelivery(
    carrier,
    capturedBody,
    undefined,
    [guardedInput, { signal }],
  );

  return {
    bindDuplex(stream) {
      linkStreamUseGuard(stream, carrier);
      linkStreamUseGuard(carrier, guardedInput);
    },
    capturedBody,
    carrier,
    value,
    write(chunk, encoding, cb) {
      preflightCapturedDelivery(carrier, capturedBody);
      const _resolve = resolve;
      resolve = null;
      _resolve({
        chunk,
        done: false,
        cb: captureCurrentDeliveryCallback(cb),
      });
    },
    final(cb) {
      preflightCapturedDelivery(carrier, capturedBody);
      const _resolve = resolve;
      resolve = null;
      _resolve({ done: true, cb: captureCurrentDeliveryCallback(cb) });
    },
    destroy(err, cb) {
      ac.abort();
      cb(err);
    },
  };
}

function _duplexify(pair) {
  const r = pair.readable && typeof pair.readable.read !== "function"
    ? Readable.wrap(pair.readable)
    : pair.readable;
  const w = pair.writable;

  let readable = !!isReadable(r);
  let writable = !!isWritable(w);

  let ondrain;
  let onfinish;
  let onreadable;
  let onend;
  let onclose;
  let d;

  function onfinished(err) {
    const cb = onclose;
    onclose = null;

    if (cb) {
      cb(err);
    } else if (err) {
      destroyer(d, err);
    }
  }

  // TODO(ronag): Avoid double buffering.
  // Implement Writable/Readable/Duplex traits.
  // See, https://github.com/nodejs/node/pull/33515.
  d = new _Duplexify({
    // TODO (ronag): highWaterMark?
    readableObjectMode: !!r?.readableObjectMode,
    writableObjectMode: !!w?.writableObjectMode,
    readable,
    writable,
  });

  function pushDuplexifiedEnd() {
    pushReadableChunk(d, null);
  }
  onend = captureCurrentDeliveryCallback(pushDuplexifiedEnd);

  let preflightWrite;

  if (writable) {
    const capturedWrite = captureWritableMethod(w, w.write);
    const capturedEnd = captureWritableMethod(w, w.end, true);
    const capturedOn = captureLifecycleMethod(w, w.on);
    preflightWrite = () => {
      preflightCapturedDelivery(d, capturedWrite);
      preflightStreamDelivery(w);
    };
    eos(w, (err) => {
      writable = false;
      if (err) {
        destroyer(r, err);
      }
      onfinished(err);
    });

    d._write = function duplexifiedWrite(chunk, encoding, callback) {
      const continuation = captureCurrentDeliveryCallback(callback);
      if (
        runCapturedDelivery(
          d,
          capturedWrite,
          w,
          [chunk, encoding],
        )
      ) {
        runCapturedCallback(continuation, undefined, []);
      } else {
        ondrain = continuation;
      }
    };

    d._final = function duplexifiedFinal(callback) {
      onend = captureCurrentDeliveryCallback(pushDuplexifiedEnd);
      runCapturedDelivery(d, capturedEnd, w, []);
      onfinish = captureCurrentDeliveryCallback(callback);
    };

    runCapturedCallback(capturedOn, w, ["drain", function () {
      if (ondrain) {
        const cb = ondrain;
        ondrain = null;
        runCapturedCallback(cb, undefined, []);
      }
    }]);

    runCapturedCallback(capturedOn, w, ["finish", function () {
      if (onfinish) {
        const cb = onfinish;
        onfinish = null;
        runCapturedCallback(cb, undefined, []);
      }
    }]);
  }

  if (readable) {
    const capturedRead = captureReadableMethod(r, r.read);
    const capturedOn = captureLifecycleMethod(r, r.on);
    eos(r, (err) => {
      readable = false;
      if (err) {
        // Propagate a readable-side error to the writable side (mirrors the
        // writable eos handler above, which destroys the readable side).
        destroyer(w, err);
      }
      onfinished(err);
    });

    runCapturedCallback(capturedOn, r, ["readable", function () {
      if (onreadable) {
        const cb = onreadable;
        onreadable = null;
        runCapturedDelivery(d, cb, d, []);
      }
    }]);

    runCapturedCallback(capturedOn, r, ["end", function () {
      runCapturedDelivery(d, onend, d, []);
    }]);

    const readFromPair = d._read = function duplexifiedRead() {
      while (true) {
        const buf = runCapturedDelivery(d, capturedRead, r, []);

        if (buf === null) {
          onreadable = captureCurrentDeliveryCallback(readFromPair);
          return;
        }

        if (!pushReadableChunk(d, buf)) {
          return;
        }
      }
    };
  }

  d._destroy = function duplexifiedDestroy(err, callback) {
    if (!err && onclose !== null) {
      err = new AbortError();
    }

    onreadable = null;
    ondrain = null;
    onfinish = null;

    if (onclose === null) {
      callback(err);
    } else {
      onclose = callback;
      destroyer(w, err);
      destroyer(r, err);
    }
  };

  markDuplexifyImplementations(d);
  if (preflightWrite !== undefined) {
    registerStreamDeliveryPreflight(d, preflightWrite);
  }

  // Every _duplexify branch creates a buffering destination. Link all sides
  // after capturing exact methods; constituent identity deduplication keeps
  // these bidirectional preconstructed links cycle-safe.
  // @ref LLP 0019#operation-scoped-positive-authority-provenance [implements]
  if (r !== null && (typeof r === "object" || typeof r === "function")) {
    linkStreamUseGuard(r, d);
    linkStreamUseGuard(d, r);
  }
  if (w !== null && (typeof w === "object" || typeof w === "function")) {
    linkStreamUseGuard(w, d);
    linkStreamUseGuard(d, w);
  }

  return d;
}

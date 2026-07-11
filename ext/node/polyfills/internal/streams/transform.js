// deno-lint-ignore-file
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

// a transform stream is a readable/writable stream where you do
// something with the data.  Sometimes it's called a "filter",
// but that's not a great name for it, since that implies a thing where
// some bits pass through, and others are simply ignored.  (That would
// be a valid example of a transform, of course.)
//
// While the output is causally related to the input, it's not a
// necessarily symmetric or synchronous transformation.  For example,
// a zlib stream might take multiple plain-text writes(), and then
// emit a single compressed chunk some time in the future.
//
// Here's how this works:
//
// The Transform stream has all the aspects of the readable and writable
// stream classes.  When you write(chunk), that calls _write(chunk,cb)
// internally, and returns false if there's a lot of pending writes
// buffered up.  When you call read(), that calls _read(n) until
// there's enough pending readable data buffered up.
//
// In a transform stream, the written data is placed in a buffer.  When
// _read(n) is called, it transforms the queued up data, calling the
// buffered _write cb's as it consumes chunks.  If consuming a single
// written chunk would result in multiple output chunks, then the first
// outputted bit calls the readcb, and subsequent chunks just go into
// the read buffer, and will cause it to emit 'readable' if necessary.
//
// This way, back-pressure is actually determined by the reading side,
// since _read has to be called to start processing a new chunk.  However,
// a pathological inflate type of transform can cause excessive buffering
// here.  For example, imagine a stream where every byte of input is
// interpreted as an integer from 0-255, and then results in that many
// bytes of output.  Writing the 4 bytes {ff,ff,ff,ff} would result in
// 1kb of data being output.  In this case, you could write a very small
// amount of input, and end up with a very large amount of output.  In
// such a pathological inflating mechanism, there'd be no way to tell
// the system to stop doing the transform.  A single 4MB write could
// cause the system to run out of memory.
//
// However, even in such a pathological case, only a single written chunk
// would be consumed, and then the rest would wait (un-transformed) until
// the results of the previous transformed chunk were consumed.

(function () {
const { core, primordials } = __bootstrap;
const lazyProcess = core.createLazyLoader("node:process");
const process = lazyProcess().default;
const { nextTick: ProtectedTransformNextTick } = core.loadExtScript(
  "ext:deno_node/_next_tick.ts",
);
const _mod1 = core.loadExtScript("ext:deno_node/internal/errors.ts");
const Duplex = core.loadExtScript(
  "ext:deno_node/internal/streams/duplex.js",
).default;
const { readableStateForStream } = core.loadExtScript(
  "ext:deno_node/internal/streams/readable.js",
);
const { writableStateForStream } = core.loadExtScript(
  "ext:deno_node/internal/streams/writable.js",
);
const { getHighWaterMark } = core.loadExtScript(
  "ext:deno_node/internal/streams/state.js",
);
const {
  captureCurrentDeliveryCallback,
  captureDeliveryCallback,
  captureTrustedDeliveryCallback,
  isStreamTrustedDeliveryCallback,
  markStreamTrustedDeliveryCallback,
  preflightCapturedDelivery,
  registerStreamDeliveryPreflight,
  registerStreamGuardAttachHook,
  runCapturedDelivery,
  runCapturedCallback,
  runStreamUseGuard,
} = core.loadExtScript(
  "ext:deno_node/internal/streams/oden_delivery.js",
);

function nextTickWithCurrent(callback, ...args) {
  const captured = captureCurrentDeliveryCallback(callback);
  FunctionPrototypeCall(
    ProtectedTransformNextTick,
    process,
    () => runCapturedCallback(captured, undefined, args),
  );
}

const {
  ERR_METHOD_NOT_IMPLEMENTED,
} = _mod1.codes;

const {
  FunctionPrototypeCall,
  ObjectSetPrototypeOf,
  SafeWeakMap,
  Symbol,
  WeakMapPrototypeGet,
  WeakMapPrototypeSet,
} = primordials;

ObjectSetPrototypeOf(Transform.prototype, Duplex.prototype);
ObjectSetPrototypeOf(Transform, Duplex);

const kCallback = Symbol("kCallback");
// Freeze package callback recipients at protection time and authorize them
// before either input chunks or derived output cross the Transform boundary.
// @ref LLP 0019#operation-scoped-positive-authority-provenance [implements]
const guardedTransforms = new SafeWeakMap();
const ReadablePrototypePush = Duplex.prototype.push;
let TransformPrototypeWrite;

function protectTransform(stream) {
  if (WeakMapPrototypeGet(guardedTransforms, stream) !== undefined) return;
  const transform = stream._transform;
  const flush = stream._flush;
  const capture = (callback) =>
    isStreamTrustedDeliveryCallback(stream, callback)
      ? captureTrustedDeliveryCallback(callback)
      : captureDeliveryCallback(callback);
  WeakMapPrototypeSet(guardedTransforms, stream, {
    flush: typeof flush === "function" ? capture(flush) : null,
    transform: typeof transform === "function" ? capture(transform) : null,
    writeIsTransform: stream._write === TransformPrototypeWrite,
  });
}

function preflightTransformImplementation(stream) {
  const guarded = WeakMapPrototypeGet(guardedTransforms, stream);
  if (guarded?.writeIsTransform && guarded.transform !== null) {
    preflightCapturedDelivery(stream, guarded.transform);
  }
}

function invokeTransform(stream, chunk, encoding, callback) {
  const guarded = WeakMapPrototypeGet(guardedTransforms, stream);
  if (guarded === undefined) {
    return FunctionPrototypeCall(
      stream._transform,
      stream,
      chunk,
      encoding,
      callback,
    );
  }
  return runCapturedDelivery(
    stream,
    guarded.transform,
    stream,
    [chunk, encoding, callback],
  );
}

function pushTransformOutput(stream, chunk) {
  runStreamUseGuard(stream);
  return FunctionPrototypeCall(ReadablePrototypePush, stream, chunk);
}

function Transform(options) {
  if (!(this instanceof Transform)) {
    return new Transform(options);
  }

  // TODO (ronag): This should preferably always be
  // applied but would be semver-major. Or even better;
  // make Transform a Readable with the Writable interface.
  const readableHighWaterMark = options
    ? getHighWaterMark(this, options, "readableHighWaterMark", true)
    : null;
  if (readableHighWaterMark === 0) {
    // A Duplex will buffer both on the writable and readable side while
    // a Transform just wants to buffer hwm number of elements. To avoid
    // buffering twice we disable buffering on the writable side.
    options = {
      ...options,
      highWaterMark: null,
      readableHighWaterMark,
      writableHighWaterMark: options.writableHighWaterMark || 0,
    };
  }

  Duplex.call(this, options);

  // We have implemented the _read method, and done the other things
  // that Readable wants before the first _read call, so unset the
  // sync guard flag.
  readableStateForStream(this).sync = false;

  this[kCallback] = null;

  if (options) {
    if (typeof options.transform === "function") {
      this._transform = options.transform;
    }

    if (typeof options.flush === "function") {
      this._flush = options.flush;
    }
  }

  markStreamTrustedDeliveryCallback(this, TransformPrototypeWrite);
  markStreamTrustedDeliveryCallback(this, final);
  if (this._transform === Transform.prototype._transform) {
    markStreamTrustedDeliveryCallback(this, this._transform);
  }

  registerStreamGuardAttachHook(this, () => protectTransform(this));
  registerStreamDeliveryPreflight(
    this,
    () => preflightTransformImplementation(this),
  );

  // When the writable side finishes, then flush out anything remaining.
  // Backwards compat. Some Transform streams incorrectly implement _final
  // instead of or in addition to _flush. By using 'prefinish' instead of
  // implementing _final we continue supporting this unfortunate use case.
  this.on("prefinish", prefinish);
}

function final(cb) {
  const guarded = WeakMapPrototypeGet(guardedTransforms, this);
  const flush = guarded === undefined
    ? (typeof this._flush === "function" ? this._flush : null)
    : guarded.flush;
  if (flush !== null && !this.destroyed) {
    const onflush = (er, data) => {
      if (er) {
        if (cb) {
          cb(er);
        } else {
          this.destroy(er);
        }
        return;
      }

      if (data != null) {
        pushTransformOutput(this, data);
      }
      pushTransformOutput(this, null);
      if (cb) {
        cb();
      }
    };
    if (guarded === undefined) {
      FunctionPrototypeCall(flush, this, onflush);
    } else {
      runCapturedDelivery(this, flush, this, [onflush]);
    }
  } else {
    pushTransformOutput(this, null);
    if (cb) {
      cb();
    }
  }
}

function prefinish() {
  if (this._final !== final) {
    final.call(this);
  }
}

Transform.prototype._final = final;

Transform.prototype._transform = function (chunk, encoding, callback) {
  throw new ERR_METHOD_NOT_IMPLEMENTED("_transform()");
};

Transform.prototype._write = function (chunk, encoding, callback) {
  const rState = readableStateForStream(this);
  const wState = writableStateForStream(this);
  const length = rState.length;

  invokeTransform(this, chunk, encoding, (err, val) => {
    if (err) {
      callback(err);
      return;
    }

    if (val != null) {
      pushTransformOutput(this, val);
    }

    if (rState.ended) {
      // If user has called this.push(null) we have to
      // delay the callback to properly propagate the new
      // state.
      nextTickWithCurrent(callback);
    } else if (
      wState.ended || // Backwards compat.
      length === rState.length || // Backwards compat.
      rState.length < rState.highWaterMark
    ) {
      callback();
    } else {
      this[kCallback] = callback;
    }
  });
};
TransformPrototypeWrite = Transform.prototype._write;

Transform.prototype._read = function () {
  if (this[kCallback]) {
    const callback = this[kCallback];
    this[kCallback] = null;
    callback();
  }
};

return { default: Transform, Transform };
})();

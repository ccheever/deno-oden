// deno-lint-ignore-file
// Copyright 2018-2026 the Deno authors. MIT license.

import process from "node:process";
import { core, primordials } from "ext:core/mod.js";
const eos =
  core.loadExtScript("ext:deno_node/internal/streams/end-of-stream.js").default;
const destroyImpl =
  core.loadExtScript("ext:deno_node/internal/streams/destroy.js").default;
import Duplex from "node:_stream_duplex";
const imported1 = core.loadExtScript("ext:deno_node/internal/errors.ts");
const {
  validateAbortSignal,
  validateFunction,
} = core.loadExtScript("ext:deno_node/internal/validators.mjs");

const {
  isIterable,
  isNodeStream,
  isReadable,
  isReadableFinished,
  isReadableNodeStream,
  isReadableStream,
  isTransformStream,
  isWebStream,
  isWritableStream,
} = core.loadExtScript("ext:deno_node/internal/streams/utils.js");

const { AbortController } = core.loadExtScript(
  "ext:deno_web/03_abort_signal.js",
);
import _mod3 from "node:_stream_readable";
const _mod4 = core.loadExtScript(
  "ext:deno_node/internal/events/abort_listener.mjs",
);
import _mod5 from "node:_stream_passthrough";
const {
  createReadableAsyncIterator,
  isRegisteredReadable,
  isReadablePublicLifecycleMethod,
  isReadablePublicPipe,
  setReadableUseGuard,
} = core.loadExtScript("ext:deno_node/internal/streams/readable.js");
const {
  isRegisteredWritable,
  isWritablePublicEnd,
  isWritablePublicWrite,
} = core.loadExtScript("ext:deno_node/internal/streams/writable.js");
const { isEventEmitterPublicLifecycleMethod } = core.loadExtScript(
  "ext:deno_node/_events.mjs",
);
const {
  getReadableStreamUseGuard,
  getWritableStreamUseGuard,
  registerReadableStreamGuardAttachHook,
  registerWritableStreamGuardAttachHook,
  setReadableStreamUseGuard,
  setWritableStreamUseGuard,
} = core.loadExtScript("ext:deno_web/06_streams.js");
const {
  captureCurrentDeliveryCallback,
  captureDeliveryCallback,
  captureTrustedDeliveryCallback,
  preflightCapturedDelivery,
  preflightStreamDelivery,
  registerStreamGuardAttachHook,
  runCapturedCallback,
  runCapturedCleanup,
  runCapturedDelivery,
  wrapIterableDelivery,
} = core.loadExtScript(
  "ext:deno_node/internal/streams/oden_delivery.js",
);

const {
  AbortError,
  aggregateTwoErrors,
  codes: {
    ERR_INVALID_ARG_TYPE,
    ERR_INVALID_RETURN_VALUE,
    ERR_MISSING_ARGS,
    ERR_STREAM_DESTROYED,
    ERR_STREAM_PREMATURE_CLOSE,
    ERR_STREAM_UNABLE_TO_PIPE,
  },
} = imported1;

// Ported from https://github.com/mafintosh/pump with
// permission from the author, Mathias Buus (@mafintosh).

"use strict";

const {
  ArrayIsArray,
  ArrayPrototypeForEach,
  ArrayPrototypePop,
  ArrayPrototypePush,
  ArrayPrototypeShift,
  Promise,
  SymbolDispose,
} = primordials;

let PassThrough;
let addAbortListener;
function captureReadableMethod(stream, method) {
  return isReadablePublicPipe(method) && isRegisteredReadable(stream)
    ? captureTrustedDeliveryCallback(method)
    : captureDeliveryCallback(method);
}

function captureWritableMethod(stream, method) {
  return isRegisteredWritable(stream) &&
      (isWritablePublicEnd(method) || isWritablePublicWrite(method))
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

function applyGuardPart(target, guard) {
  if (target === null || target === undefined) return;
  if (isTransformStream(target)) {
    setReadableStreamUseGuard(target.readable, guard);
    setWritableStreamUseGuard?.(target.writable, guard);
  } else if (isReadableStream(target)) {
    setReadableStreamUseGuard(target, guard);
  } else if (isWritableStream(target)) {
    setWritableStreamUseGuard?.(target, guard);
  } else if (typeof target === "object" || typeof target === "function") {
    setReadableUseGuard(target, guard);
  }
}

function linkGuardSource(source, target) {
  if (source === null || source === undefined) return target;
  const linkReadableWeb = (readable) => {
    if (typeof registerReadableStreamGuardAttachHook === "function") {
      registerReadableStreamGuardAttachHook(
        readable,
        (guard) => applyGuardPart(target, guard),
      );
    } else {
      const guard = getReadableStreamUseGuard(readable);
      if (guard !== undefined) applyGuardPart(target, guard);
    }
  };
  const linkWritableWeb = (writable) => {
    if (typeof registerWritableStreamGuardAttachHook === "function") {
      registerWritableStreamGuardAttachHook(
        writable,
        (guard) => applyGuardPart(target, guard),
      );
    } else {
      const guard = getWritableStreamUseGuard?.(writable);
      if (guard !== undefined) applyGuardPart(target, guard);
    }
  };
  if (isTransformStream(source)) {
    linkReadableWeb(source.readable);
    linkWritableWeb(source.writable);
  } else if (isReadableStream(source)) {
    linkReadableWeb(source);
  } else if (isWritableStream(source)) {
    linkWritableWeb(source);
  } else if (typeof source === "object" || typeof source === "function") {
    registerStreamGuardAttachHook(
      source,
      (guard) => applyGuardPart(target, guard),
    );
  }
  return target;
}

function propagateReadableGuards(source, target) {
  return linkGuardSource(source, target);
}

function deliveryCarrierFor(value) {
  const carrier = {};
  linkGuardSource(value, carrier);
  return carrier;
}

function invokeCaptured(carrier, captured, receiver, args) {
  return runCapturedDelivery(carrier, captured, receiver, args);
}

function getThen() {
  return this?.then;
}

function wrapPipelineIterable(iterable, recipient, inheritedFrom) {
  if (inheritedFrom !== undefined) {
    linkGuardSource(inheritedFrom, iterable);
  }
  const wrapped = wrapIterableDelivery(iterable, recipient);
  linkGuardSource(iterable, wrapped);
  return wrapped;
}

function destroyer(stream, reading, writing) {
  let finished = false;
  const capturedOn = captureLifecycleMethod(
    stream,
    stream.on,
  );
  runCapturedCallback(capturedOn, stream, ["close", () => {
    finished = true;
  }]);

  const cleanup = eos(
    stream,
    { readable: reading, writable: writing },
    (err) => {
      finished = !err;
    },
  );

  return {
    destroy: (err) => {
      if (finished) return;
      finished = true;
      destroyImpl.destroyer(stream, err || new ERR_STREAM_DESTROYED("pipe"));
    },
    cleanup,
  };
}

function popCallback(streams) {
  // Streams should never be an empty array. It should always contain at least
  // a single stream. Therefore optimize for the average case instead of
  // checking for length === 0 as well.
  validateFunction(streams[streams.length - 1], "streams[stream.length - 1]");
  return ArrayPrototypePop(streams);
}

function makeAsyncIterable(val) {
  if (isIterable(val)) {
    return wrapPipelineIterable(val);
  } else if (isReadableNodeStream(val)) {
    // Legacy streams are not Iterable.
    return wrapPipelineIterable(fromReadable(val), undefined, val);
  }
  throw new ERR_INVALID_ARG_TYPE(
    "val",
    ["Readable", "Iterable", "AsyncIterable"],
    val,
  );
}

async function* fromReadable(val) {
  yield* createReadableAsyncIterator(val);
}

async function pumpToNode(iterable, writable, finish, { end }) {
  propagateReadableGuards(iterable, writable);
  iterable = wrapPipelineIterable(iterable);
  let error;
  let onresolve = null;
  const capturedOn = captureLifecycleMethod(
    writable,
    writable.on,
  );
  const capturedOff = captureLifecycleMethod(
    writable,
    writable.off,
  );
  const capturedWrite = captureWritableMethod(
    writable,
    writable.write,
  );
  const capturedEnd = captureWritableMethod(
    writable,
    writable.end,
  );

  const resume = (err) => {
    if (err) {
      error = err;
    }

    if (onresolve) {
      const callback = onresolve;
      onresolve = null;
      callback();
    }
  };

  const wait = () =>
    new Promise((resolve, reject) => {
      if (error) {
        reject(error);
      } else {
        onresolve = () => {
          if (error) {
            reject(error);
          } else {
            resolve();
          }
        };
      }
    });

  runCapturedCallback(capturedOn, writable, ["drain", resume]);
  const cleanup = eos(writable, { readable: false }, resume);

  try {
    if (writable.writableNeedDrain) {
      await wait();
    }

    preflightStreamDelivery(writable);
    for await (const chunk of iterable) {
      preflightStreamDelivery(writable);
      if (!runCapturedDelivery(
        writable,
        capturedWrite,
        writable,
        [chunk],
      )) {
        await wait();
      }
      preflightStreamDelivery(writable);
    }

    if (end) {
      runCapturedDelivery(writable, capturedEnd, writable, []);
      await wait();
    }

    finish();
  } catch (err) {
    finish(error !== err ? aggregateTwoErrors(error, err) : err);
  } finally {
    cleanup();
    runCapturedCleanup(capturedOff, writable, ["drain", resume]);
  }
}

async function pumpToWeb(readable, writable, finish, { end }) {
  if (isTransformStream(writable)) {
    writable = writable.writable;
  }
  // https://streams.spec.whatwg.org/#example-manual-write-with-backpressure
  const writer = writable.getWriter();
  const capturedWrite = captureDeliveryCallback(writer.write);
  const capturedClose = captureDeliveryCallback(writer.close);
  const capturedAbort = captureDeliveryCallback(writer.abort);
  const carrier = deliveryCarrierFor(readable);
  try {
    for await (const chunk of readable) {
      await writer.ready;
      invokeCaptured(carrier, capturedWrite, writer, [chunk]).catch(() => {});
    }

    await writer.ready;

    if (end) {
      await invokeCaptured(carrier, capturedClose, writer, []);
    }

    finish();
  } catch (err) {
    try {
      await runCapturedCleanup(capturedAbort, writer, [err]);
      finish(err);
    } catch (err) {
      finish(err);
    }
  }
}

function pipeline(...streams) {
  return pipelineImpl(streams, popCallback(streams));
}

function pipelineImpl(streams, callback, opts) {
  if (streams.length === 1 && ArrayIsArray(streams[0])) {
    streams = streams[0];
  }

  if (streams.length < 2) {
    throw new ERR_MISSING_ARGS("streams");
  }

  const ac = new AbortController();
  const signal = ac.signal;
  const outerSignal = opts?.signal;

  // Need to cleanup event listeners if last stream is readable
  // https://github.com/nodejs/node/issues/35452
  const lastStreamCleanup = [];

  validateAbortSignal(outerSignal, "options.signal");

  function abort() {
    finishImpl(new AbortError(undefined, { cause: outerSignal?.reason }));
  }

  addAbortListener ??= _mod4.addAbortListener;
  let disposable;
  if (outerSignal) {
    disposable = addAbortListener(outerSignal, abort);
  }

  let error;
  let value;
  const destroys = [];
  const capturedCallback = captureDeliveryCallback(callback);
  let callbackCalled = false;
  let ret;

  let finishCount = 0;

  function finish(err) {
    finishImpl(err, --finishCount === 0);
  }

  function finishOnlyHandleError(err) {
    finishImpl(err, false);
  }

  function finishImpl(err, final) {
    if (err && (!error || error.code === "ERR_STREAM_PREMATURE_CLOSE")) {
      error = err;
    }

    if (!error && !final) {
      return;
    }

    while (destroys.length) {
      ArrayPrototypeShift(destroys)(error);
    }

    disposable?.[SymbolDispose]();
    ac.abort();

    if (final) {
      if (!error) {
        ArrayPrototypeForEach(lastStreamCleanup, (fn) => fn());
      }
      process.nextTick(() => {
        if (callbackCalled) return;
        callbackCalled = true;
        const carrier = deliveryCarrierFor(ret);
        if (!error && value != null && carrier !== undefined) {
          runCapturedDelivery(
            carrier,
            capturedCallback,
            undefined,
            [error, value],
          );
        } else {
          runCapturedCallback(capturedCallback, undefined, [error, value]);
        }
      });
    }
  }

  for (let i = 0; i < streams.length; i++) {
    const stream = streams[i];
    const reading = i < streams.length - 1;
    const writing = i > 0;
    const next = i + 1 < streams.length ? streams[i + 1] : null;
    const end = reading || opts?.end !== false;
    const isLastStream = i === streams.length - 1;

    if (isNodeStream(stream)) {
      const capturedStreamOn = captureLifecycleMethod(
        stream,
        stream.on,
      );
      const capturedStreamRemove = captureLifecycleMethod(
        stream,
        stream.removeListener,
      );
      if (next !== null && (next?.closed || next?.destroyed)) {
        throw new ERR_STREAM_UNABLE_TO_PIPE();
      }

      if (end) {
        const { destroy, cleanup } = destroyer(stream, reading, writing);
        ArrayPrototypePush(destroys, destroy);

        if (isReadable(stream) && isLastStream) {
          ArrayPrototypePush(lastStreamCleanup, cleanup);
        }
      }

      // Catch stream errors that occur after pipe/pump has completed.
      function onError(err) {
        if (
          err &&
          err.name !== "AbortError" &&
          err.code !== "ERR_STREAM_PREMATURE_CLOSE"
        ) {
          finishOnlyHandleError(err);
        }
      }
      runCapturedCallback(capturedStreamOn, stream, ["error", onError]);
      if (isReadable(stream) && isLastStream) {
        ArrayPrototypePush(lastStreamCleanup, () => {
          runCapturedCleanup(
            capturedStreamRemove,
            stream,
            ["error", onError],
          );
        });
      }
    }

    if (i === 0) {
      if (typeof stream === "function") {
        const capturedSource = captureDeliveryCallback(stream);
        ret = runCapturedCallback(capturedSource, undefined, [{ signal }]);
        if (!isIterable(ret)) {
          throw new ERR_INVALID_RETURN_VALUE(
            "Iterable, AsyncIterable or Stream",
            "source",
            ret,
          );
        }
        ret = wrapPipelineIterable(ret, stream);
      } else if (
        isIterable(stream) || isReadableNodeStream(stream) ||
        isTransformStream(stream)
      ) {
        ret = stream;
      } else {
        ret = Duplex.from(stream);
      }
    } else if (typeof stream === "function") {
      if (isTransformStream(ret)) {
        ret = makeAsyncIterable(ret?.readable);
      } else {
        ret = makeAsyncIterable(ret);
      }
      const stageInput = ret;
      const stageCarrier = deliveryCarrierFor(stageInput);
      const capturedStage = captureDeliveryCallback(stream);
      ret = invokeCaptured(
        stageCarrier,
        capturedStage,
        undefined,
        [stageInput, { signal }],
      );

      if (reading) {
        if (!isIterable(ret, true)) {
          throw new ERR_INVALID_RETURN_VALUE(
            "AsyncIterable",
            `transform[${i - 1}]`,
            ret,
          );
        }
        ret = wrapPipelineIterable(ret, stream, stageInput);
      } else {
        PassThrough ??= _mod5;

        // If the last argument to pipeline is not a stream
        // we must create a proxy stream so that pipeline(...)
        // always returns a stream which can be further
        // composed through `.pipe(stream)`.

        const pt = new PassThrough({
          objectMode: true,
        });
        propagateReadableGuards(stageInput, pt);
        const capturedPtWrite = captureWritableMethod(
          pt,
          pt.write,
        );
        const capturedPtEnd = captureWritableMethod(
          pt,
          pt.end,
        );
        const capturedPtDestroy = captureDeliveryCallback(pt.destroy);

        // Handle Promises/A+ spec, `then` could be a getter that throws on
        // second use.
        const capturedThenGetter = captureDeliveryCallback(stream, getThen);
        const then = invokeCaptured(
          stageCarrier,
          capturedThenGetter,
          ret,
          [],
        );
        if (typeof then === "function") {
          finishCount++;
          const capturedThen = captureDeliveryCallback(stream, then);
          invokeCaptured(stageCarrier, capturedThen, ret, [
            (val) => {
              try {
                if (stageCarrier !== undefined) {
                  preflightCapturedDelivery(stageCarrier, capturedStage);
                }
                if (val != null) {
                  runCapturedDelivery(
                    pt,
                    capturedPtWrite,
                    pt,
                    [val],
                  );
                }
                if (end) {
                  runCapturedDelivery(pt, capturedPtEnd, pt, []);
                }
                value = val;
                process.nextTick(finish);
              } catch (err) {
                value = undefined;
                runCapturedCleanup(capturedPtDestroy, pt, [err]);
                process.nextTick(finish, err);
              }
            },
            (err) => {
              runCapturedCleanup(capturedPtDestroy, pt, [err]);
              process.nextTick(finish, err);
            },
          ]);
        } else if (isIterable(ret, true)) {
          finishCount++;
          pumpToNode(
            wrapPipelineIterable(ret, stream, stageInput),
            pt,
            finish,
            { end },
          );
        } else if (isReadableStream(ret) || isTransformStream(ret)) {
          const toRead = ret.readable || ret;
          finishCount++;
          pumpToNode(
            wrapPipelineIterable(toRead, stream, stageInput),
            pt,
            finish,
            { end },
          );
        } else {
          throw new ERR_INVALID_RETURN_VALUE(
            "AsyncIterable or Promise",
            "destination",
            ret,
          );
        }

        ret = pt;

        const { destroy, cleanup } = destroyer(ret, false, true);
        ArrayPrototypePush(destroys, destroy);
        if (isLastStream) {
          ArrayPrototypePush(lastStreamCleanup, cleanup);
        }
      }
    } else if (isNodeStream(stream)) {
      propagateReadableGuards(ret, stream);
      if (isReadableNodeStream(ret)) {
        finishCount += 2;
        const cleanup = pipe(ret, stream, finish, finishOnlyHandleError, {
          end,
        });
        if (isReadable(stream) && isLastStream) {
          ArrayPrototypePush(lastStreamCleanup, cleanup);
        }
      } else if (isTransformStream(ret) || isReadableStream(ret)) {
        const toRead = ret.readable || ret;
        finishCount++;
        pumpToNode(toRead, stream, finish, { end });
      } else if (isIterable(ret)) {
        finishCount++;
        pumpToNode(ret, stream, finish, { end });
      } else {
        throw new ERR_INVALID_ARG_TYPE(
          "val",
          [
            "Readable",
            "Iterable",
            "AsyncIterable",
            "ReadableStream",
            "TransformStream",
          ],
          ret,
        );
      }
      ret = stream;
    } else if (isWebStream(stream)) {
      propagateReadableGuards(ret, stream);
      if (isReadableNodeStream(ret)) {
        finishCount++;
        pumpToWeb(makeAsyncIterable(ret), stream, finish, { end });
      } else if (isReadableStream(ret) || isIterable(ret)) {
        finishCount++;
        pumpToWeb(ret, stream, finish, { end });
      } else if (isTransformStream(ret)) {
        finishCount++;
        pumpToWeb(ret.readable, stream, finish, { end });
      } else {
        throw new ERR_INVALID_ARG_TYPE(
          "val",
          [
            "Readable",
            "Iterable",
            "AsyncIterable",
            "ReadableStream",
            "TransformStream",
          ],
          ret,
        );
      }
      ret = stream;
    } else {
      ret = Duplex.from(stream);
    }
  }

  if (signal?.aborted || outerSignal?.aborted) {
    process.nextTick(abort);
  }

  return ret;
}

function pipe(src, dst, finish, finishOnlyHandleError, { end }) {
  let ended = false;
  propagateReadableGuards(src, dst);
  const capturedDstOn = captureLifecycleMethod(
    dst,
    dst.on,
  );
  const capturedDstEnd = captureWritableMethod(
    dst,
    dst.end,
  );
  const capturedSrcPipe = captureReadableMethod(
    src,
    src.pipe,
  );
  const capturedSrcOnce = captureLifecycleMethod(
    src,
    src.once,
  );
  runCapturedCallback(capturedDstOn, dst, ["close", () => {
    if (!ended) {
      // Finish if the destination closes before the source has completed.
      finishOnlyHandleError(new ERR_STREAM_PREMATURE_CLOSE());
    }
  }]);

  runCapturedDelivery(
    src,
    capturedSrcPipe,
    src,
    [dst, { end: false }],
  ); // If end is true we already will have a listener to end dst.

  if (end) {
    // Compat. Before node v10.12.0 stdio used to throw an error so
    // pipe() did/does not end() stdio destinations.
    // Now they allow it but "secretly" don't close the underlying fd.

    function endFn() {
      ended = true;
      runCapturedDelivery(dst, capturedDstEnd, dst, []);
    }
    const capturedEndFn = captureCurrentDeliveryCallback(endFn);
    const resumeEnd = () =>
      runCapturedCallback(capturedEndFn, undefined, []);

    if (isReadableFinished(src)) { // End the destination if the source has already ended.
      process.nextTick(resumeEnd);
    } else {
      runCapturedCallback(capturedSrcOnce, src, ["end", resumeEnd]);
    }
  } else {
    finish();
  }

  eos(src, { readable: true, writable: false }, (err) => {
    const rState = src._readableState;
    if (
      err &&
      err.code === "ERR_STREAM_PREMATURE_CLOSE" &&
      (rState?.ended && !rState.errored && !rState.errorEmitted)
    ) {
      // Some readable streams will emit 'close' before 'end'. However, since
      // this is on the readable side 'end' should still be emitted if the
      // stream has been ended and no error emitted. This should be allowed in
      // favor of backwards compatibility. Since the stream is piped to a
      // destination this should not result in any observable difference.
      // We don't need to check if this is a writable premature close since
      // eos will only fail with premature close on the reading side for
      // duplex streams.
      runCapturedCallback(capturedSrcOnce, src, ["end", finish]);
      runCapturedCallback(capturedSrcOnce, src, ["error", finish]);
    } else {
      finish(err);
    }
  });
  return eos(dst, { readable: false, writable: true }, finish);
}

const _defaultExport2 = { pipelineImpl, pipeline };
export default _defaultExport2;
export { pipeline, pipelineImpl };

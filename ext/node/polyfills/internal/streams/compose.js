// deno-lint-ignore-file
// Copyright 2018-2026 the Deno authors. MIT license.

import { core, primordials } from "ext:core/mod.js";
import { pipeline } from "ext:deno_node/internal/streams/pipeline.js";
import Duplex from "node:_stream_duplex";
const {
  isRegisteredReadable,
  isReadablePublicLifecycleMethod,
  isReadablePublicRead,
  pushReadableChunk,
  setReadableUseGuard,
} = core.loadExtScript("ext:deno_node/internal/streams/readable.js");
const {
  destroyProtectedWritable,
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
} = core.loadExtScript(
  "ext:deno_web/06_streams.js",
);
const {
  captureCurrentDeliveryCallback,
  captureDeliveryCallback,
  captureTrustedDeliveryCallback,
  markStreamTrustedDeliveryCallback,
  preflightCapturedDelivery,
  preflightStreamDelivery,
  registerStreamDeliveryPreflight,
  registerStreamGuardAttachHook,
  runCapturedCallback,
  runCapturedDelivery,
} = core.loadExtScript(
  "ext:deno_node/internal/streams/oden_delivery.js",
);
const { destroyer } = core.loadExtScript(
  "ext:deno_node/internal/streams/destroy.js",
);

const {
  isNodeStream,
  isReadable,
  isReadableStream,
  isTransformStream,
  isWebStream,
  isWritable,
  isWritableStream,
} = core.loadExtScript("ext:deno_node/internal/streams/utils.js");

const imported1 = core.loadExtScript("ext:deno_node/internal/errors.ts");
const eos =
  core.loadExtScript("ext:deno_node/internal/streams/end-of-stream.js").default;

const {
  AbortError,
  codes: {
    ERR_INVALID_ARG_VALUE,
    ERR_MISSING_ARGS,
  },
} = imported1;

"use strict";

const {
  ArrayPrototypeSlice,
} = primordials;

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
  if (source === null || source === undefined) return;
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
}

function connectGuardEndpoints(left, right) {
  linkGuardSource(left, right);
  linkGuardSource(right, left);
}

export default function compose(...streams) {
  if (streams.length === 0) {
    throw new ERR_MISSING_ARGS("streams");
  }

  if (streams.length === 1) {
    return Duplex.from(streams[0]);
  }

  const orgStreams = ArrayPrototypeSlice(streams);

  if (typeof streams[0] === "function") {
    streams[0] = Duplex.from(streams[0]);
  }

  if (typeof streams[streams.length - 1] === "function") {
    const idx = streams.length - 1;
    streams[idx] = Duplex.from(streams[idx]);
  }

  for (let n = 0; n < streams.length; ++n) {
    if (!isNodeStream(streams[n]) && !isWebStream(streams[n])) {
      // TODO(ronag): Add checks for non streams.
      continue;
    }
    if (
      n < streams.length - 1 &&
      !(
        isReadable(streams[n]) ||
        isReadableStream(streams[n]) ||
        isTransformStream(streams[n])
      )
    ) {
      throw new ERR_INVALID_ARG_VALUE(
        `streams[${n}]`,
        orgStreams[n],
        "must be readable",
      );
    }
    if (
      n > 0 &&
      !(
        isWritable(streams[n]) ||
        isWritableStream(streams[n]) ||
        isTransformStream(streams[n])
      )
    ) {
      throw new ERR_INVALID_ARG_VALUE(
        `streams[${n}]`,
        orgStreams[n],
        "must be writable",
      );
    }
  }

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
      destroyProtectedWritable(d, err);
    } else if (!readable && !writable) {
      destroyProtectedWritable(d);
    }
  }

  const head = streams[0];
  const tail = pipeline(streams, onfinished);

  const writable = !!(
    isWritable(head) ||
    isWritableStream(head) ||
    isTransformStream(head)
  );
  const readable = !!(
    isReadable(tail) ||
    isReadableStream(tail) ||
    isTransformStream(tail)
  );

  // TODO(ronag): Avoid double buffering.
  // Implement Writable/Readable/Duplex traits.
  // See, https://github.com/nodejs/node/pull/33515.
  d = new Duplex({
    // TODO (ronag): highWaterMark?
    writableObjectMode: !!head?.writableObjectMode,
    readableObjectMode: !!tail?.readableObjectMode,
    writable,
    readable,
  });

  function pushComposedEnd() {
    pushReadableChunk(d, null);
  }
  onend = captureCurrentDeliveryCallback(pushComposedEnd);

  let preflightHeadWrite;

  if (writable) {
    if (isNodeStream(head)) {
      const capturedHeadWrite = captureWritableMethod(head, head.write);
      const capturedHeadEnd = captureWritableMethod(head, head.end, true);
      const capturedHeadOn = captureLifecycleMethod(head, head.on);
      preflightHeadWrite = () => {
        preflightCapturedDelivery(d, capturedHeadWrite);
        preflightStreamDelivery(head);
      };
      d._write = function composedWrite(chunk, encoding, callback) {
        const continuation = captureCurrentDeliveryCallback(callback);
        if (
          runCapturedDelivery(
            d,
            capturedHeadWrite,
            head,
            [chunk, encoding],
          )
        ) {
          runCapturedCallback(continuation, undefined, []);
        } else {
          ondrain = continuation;
        }
      };

      d._final = function composedFinal(callback) {
        onend = captureCurrentDeliveryCallback(pushComposedEnd);
        runCapturedDelivery(d, capturedHeadEnd, head, []);
        onfinish = captureCurrentDeliveryCallback(callback);
      };

      runCapturedCallback(capturedHeadOn, head, ["drain", function () {
        if (ondrain) {
          const cb = ondrain;
          ondrain = null;
          runCapturedCallback(cb, undefined, []);
        }
      }]);
    } else if (isWebStream(head)) {
      const writable = isTransformStream(head) ? head.writable : head;
      const writer = writable.getWriter();
      const capturedWriterWrite = captureDeliveryCallback(writer.write);
      const capturedWriterClose = captureDeliveryCallback(writer.close);
      preflightHeadWrite = () =>
        preflightCapturedDelivery(d, capturedWriterWrite);

      d._write = async function composedWebWrite(chunk, encoding, callback) {
        const continuation = captureCurrentDeliveryCallback(callback);
        try {
          await writer.ready;
          runCapturedDelivery(
            d,
            capturedWriterWrite,
            writer,
            [chunk],
          ).catch(() => {});
          runCapturedCallback(continuation, undefined, []);
        } catch (err) {
          runCapturedCallback(continuation, undefined, [err]);
        }
      };

      d._final = async function composedWebFinal(callback) {
        const continuation = captureCurrentDeliveryCallback(callback);
        onend = captureCurrentDeliveryCallback(pushComposedEnd);
        try {
          await writer.ready;
          runCapturedDelivery(d, capturedWriterClose, writer, [])
            .catch(() => {});
          onfinish = continuation;
        } catch (err) {
          runCapturedCallback(continuation, undefined, [err]);
        }
      };
    }

    const toRead = isTransformStream(tail) ? tail.readable : tail;

    eos(toRead, () => {
      if (onfinish) {
        const cb = onfinish;
        onfinish = null;
        runCapturedCallback(cb, undefined, []);
      }
    });
  }

  if (readable) {
    if (isNodeStream(tail)) {
      const capturedTailOn = captureLifecycleMethod(tail, tail.on);
      const capturedTailRead = captureReadableMethod(tail, tail.read);
      runCapturedCallback(capturedTailOn, tail, ["readable", function () {
        if (onreadable) {
          const cb = onreadable;
          onreadable = null;
          runCapturedDelivery(d, cb, d, []);
        }
      }]);

      runCapturedCallback(capturedTailOn, tail, ["end", function () {
        runCapturedDelivery(d, onend, d, []);
      }]);

      const readFromTail = d._read = function composedRead() {
        while (true) {
          const buf = runCapturedDelivery(
            d,
            capturedTailRead,
            tail,
            [],
          );
          if (buf === null) {
            onreadable = captureCurrentDeliveryCallback(readFromTail);
            return;
          }

          if (!pushReadableChunk(d, buf)) {
            return;
          }
        }
      };
    } else if (isWebStream(tail)) {
      const readable = isTransformStream(tail) ? tail.readable : tail;
      const reader = readable.getReader();
      const capturedReaderRead = captureDeliveryCallback(reader.read);
      d._read = async function composedWebRead() {
        while (true) {
          try {
            const { value, done } = await runCapturedDelivery(
              d,
              capturedReaderRead,
              reader,
              [],
            );

            if (!pushReadableChunk(d, value)) {
              return;
            }

            if (done) {
              pushReadableChunk(d, null);
              return;
            }
          } catch {
            return;
          }
        }
      };
    }
  }

  d._destroy = function composedDestroy(err, callback) {
    if (!err && onclose !== null) {
      err = new AbortError();
    }

    onreadable = null;
    ondrain = null;
    onfinish = null;

    if (isNodeStream(tail)) {
      destroyer(tail, err);
    }

    if (onclose === null) {
      callback(err);
    } else {
      onclose = callback;
    }
  };

  if (typeof d._write === "function") {
    markStreamTrustedDeliveryCallback(d, d._write);
  }
  if (typeof d._final === "function") {
    markStreamTrustedDeliveryCallback(d, d._final);
  }
  if (preflightHeadWrite !== undefined) {
    registerStreamDeliveryPreflight(d, preflightHeadWrite);
  }

  // Link every preconstructed side only after exact implementations are
  // frozen. Constituent identity deduplication makes the bidirectional graph
  // cycle-safe and forwards guards attached after compose() returns.
  // @ref LLP 0019#operation-scoped-positive-authority-provenance [implements]
  connectGuardEndpoints(head, d);
  connectGuardEndpoints(tail, d);

  return d;
}

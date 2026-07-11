// deno-lint-ignore-file
// Copyright 2018-2026 the Deno authors. MIT license.
(function () {
const { core, primordials } = __bootstrap;
const {
  ArrayBufferIsView,
  ArrayPrototypeMap,
  FunctionPrototypeCall,
  PromisePrototypeThen,
  PromiseResolve,
  PromiseWithResolvers,
  SafePromiseAll,
  SafePromisePrototypeFinally,
  Uint8Array,
} = primordials;
const {
  captureDeliveryCallback,
  captureTrustedDeliveryCallback,
  markStreamCleanupDeliveryCallback,
  markStreamTrustedDeliveryCallback,
  markTrustedDeliveryCallback,
  registerStreamGuardAttachHook,
  runCapturedCleanup,
  runCapturedDelivery,
  setStreamUseGuard,
} = core.loadExtScript("ext:deno_node/internal/streams/oden_delivery.js");
const { pushReadableChunk } = core.loadExtScript(
  "ext:deno_node/internal/streams/readable.js",
);
const {
  acquireReadableStreamDefaultReader,
  acquireWritableStreamDefaultWriter,
  markWritableStreamTrustedCallback,
  readableByteStreamControllerClose,
  readableByteStreamControllerEnqueue,
  readableByteStreamControllerError,
  readableByteStreamControllerGetDesiredSize,
  readableStreamDefaultReaderClosedPromise,
  readableStreamDefaultReaderReadPromise,
  readableStreamDefaultControllerClose,
  readableStreamDefaultControllerEnqueue,
  readableStreamDefaultControllerError,
  readableStreamDefaultControllerGetDesiredSize,
  readableStreamReaderGenericCancel,
  registerReadableStreamGuardAttachHook,
  registerWritableStreamGuardAttachHook,
  setReadableStreamUseGuard,
  setWritableStreamUseGuard,
  writableStreamDefaultWriterAbort,
  writableStreamDefaultWriterClose,
  writableStreamDefaultWriterClosedPromise,
  writableStreamDefaultWriterReadyPromise,
  writableStreamDefaultWriterWrite,
} = core.loadExtScript("ext:deno_web/06_streams.js");
const { destroy, destroyer } = core.loadExtScript(
  "ext:deno_node/internal/streams/destroy.js",
);
const finished =
  core.loadExtScript("ext:deno_node/internal/streams/end-of-stream.js").default;
const {
  isDestroyed,
  isReadable,
  isReadableEnded,
  isWritable,
  isWritableEnded,
} = core.loadExtScript("ext:deno_node/internal/streams/utils.js");
const { ReadableStream, WritableStream } = core.loadExtScript(
  "ext:deno_node/stream/web.js",
);
const {
  validateBoolean,
  validateObject,
  validateOneOf,
} = core.loadExtScript("ext:deno_node/internal/validators.mjs");
const {
  kEmptyObject,
  normalizeEncoding,
} = core.loadExtScript("ext:deno_node/internal/util.mjs");
const {
  AbortError,
  ERR_INVALID_ARG_VALUE,
  ERR_INVALID_ARG_TYPE,
} = core.loadExtScript("ext:deno_node/internal/errors.ts");
const lazyProcess = core.createLazyLoader("node:process");
const { Buffer } = core.loadExtScript("ext:deno_node/internal/buffer.mjs");
const lazyStream = core.createLazyLoader("node:stream");
const {
  isRegisteredWritable,
  isWritablePublicWrite,
  writableNeedsDrain,
} = core.loadExtScript("ext:deno_node/internal/streams/writable.js");

function uponPromise(promise, onFulfilled, onRejected) {
  return PromisePrototypeThen(promise, onFulfilled, onRejected);
}

function destroyNodeStream(stream, error) {
  return FunctionPrototypeCall(destroy, stream, error);
}

function isWritableStream(object) {
  return object instanceof WritableStream;
}

function isReadableStream(object) {
  return object instanceof ReadableStream;
}

function newStreamReadableFromReadableStream(
  readableStream,
  options = kEmptyObject,
) {
  if (!isReadableStream(readableStream)) {
    throw new ERR_INVALID_ARG_TYPE(
      "readableStream",
      "ReadableStream",
      readableStream,
    );
  }

  validateObject(options, "options");
  const {
    highWaterMark,
    encoding,
    objectMode = false,
    signal,
  } = options;

  if (encoding !== undefined && !Buffer.isEncoding(encoding)) {
    throw new ERR_INVALID_ARG_VALUE(encoding, "options.encoding");
  }
  validateBoolean(objectMode, "options.objectMode");

  const reader = acquireReadableStreamDefaultReader(readableStream);
  let closed = false;

  const readable = new (lazyStream().Readable)({
    objectMode,
    highWaterMark,
    encoding,
    signal,

    read() {
      uponPromise(
        readableStreamDefaultReaderReadPromise(reader),
        (chunk) => {
          try {
            if (chunk.done) {
              pushReadableChunk(readable, null);
            } else {
              pushReadableChunk(readable, chunk.value);
            }
          } catch (error) {
            destroyNodeStream(readable, error);
          }
        },
        (error) => destroyNodeStream(readable, error),
      );
    },

    destroy(error, callback) {
      function done() {
        try {
          callback(error);
        } catch (error) {
          // In a next tick because this is happening within
          // a promise context, and if there are any errors
          // thrown we don't want those to cause an unhandled
          // rejection. Let's just escape the promise and
          // handle it separately.
          lazyProcess().default.nextTick(() => {
            throw error;
          });
        }
      }

      if (!closed) {
        uponPromise(
          readableStreamReaderGenericCancel(reader, error),
          done,
          done,
        );
        return;
      }

      done();
    },
  });

  registerStreamGuardAttachHook(readable, (guard) => {
    setReadableStreamUseGuard(readableStream, guard);
  });
  registerReadableStreamGuardAttachHook(readableStream, (guard) => {
    setStreamUseGuard(readable, guard);
  });

  uponPromise(
    readableStreamDefaultReaderClosedPromise(reader),
    () => {
      closed = true;
    },
    (error) => {
      closed = true;
      destroyNodeStream(readable, error);
    },
  );

  return readable;
}

function newStreamWritableFromWritableStream(
  writableStream,
  options = kEmptyObject,
) {
  if (!isWritableStream(writableStream)) {
    throw new ERR_INVALID_ARG_TYPE(
      "writableStream",
      "WritableStream",
      writableStream,
    );
  }

  validateObject(options, "options");
  const {
    highWaterMark,
    decodeStrings = true,
    objectMode = false,
    signal,
  } = options;

  validateBoolean(objectMode, "options.objectMode");
  validateBoolean(decodeStrings, "options.decodeStrings");

  const writer = acquireWritableStreamDefaultWriter(writableStream);
  let closed = false;

  const writable = new (lazyStream().Writable)({
    highWaterMark,
    objectMode,
    decodeStrings,
    signal,

    writev(chunks, callback) {
      function done(error) {
        error = error.filter((e) => e);
        try {
          callback(error.length === 0 ? undefined : error);
        } catch (error) {
          // In a next tick because this is happening within
          // a promise context, and if there are any errors
          // thrown we don't want those to cause an unhandled
          // rejection. Let's just escape the promise and
          // handle it separately.
          lazyProcess().default.nextTick(() =>
            destroyNodeStream(writable, error)
          );
        }
      }

      uponPromise(
        writableStreamDefaultWriterReadyPromise(writer),
        () =>
          uponPromise(
            SafePromiseAll(
              ArrayPrototypeMap(chunks, (data) =>
                writableStreamDefaultWriterWrite(writer, data.chunk)),
            ),
            done,
            done,
          ),
        done,
      );
    },

    write(chunk, encoding, callback) {
      if (typeof chunk === "string" && decodeStrings && !objectMode) {
        chunk = Buffer.from(chunk, encoding);
        chunk = new Uint8Array(
          chunk.buffer,
          chunk.byteOffset,
          chunk.byteLength,
        );
      }

      function done(error) {
        try {
          callback(error);
        } catch (error) {
          destroyNodeStream(writable, error);
        }
      }

      uponPromise(
        writableStreamDefaultWriterReadyPromise(writer),
        () =>
          uponPromise(
            writableStreamDefaultWriterWrite(writer, chunk),
            done,
            done,
          ),
        done,
      );
    },

    destroy(error, callback) {
      function done() {
        try {
          callback(error);
        } catch (error) {
          // In a next tick because this is happening within
          // a promise context, and if there are any errors
          // thrown we don't want those to cause an unhandled
          // rejection. Let's just escape the promise and
          // handle it separately.
          lazyProcess().default.nextTick(() => {
            throw error;
          });
        }
      }

      if (!closed) {
        if (error != null) {
          uponPromise(
            writableStreamDefaultWriterAbort(writer, error),
            done,
            done,
          );
        } else {
          uponPromise(
            writableStreamDefaultWriterClose(writer),
            done,
            done,
          );
        }
        return;
      }

      done();
    },

    final(callback) {
      function done(error) {
        try {
          callback(error);
        } catch (error) {
          // In a next tick because this is happening within
          // a promise context, and if there are any errors
          // thrown we don't want those to cause an unhandled
          // rejection. Let's just escape the promise and
          // handle it separately.
          lazyProcess().default.nextTick(() =>
            destroyNodeStream(writable, error)
          );
        }
      }

      if (!closed) {
        uponPromise(
          writableStreamDefaultWriterClose(writer),
          done,
          done,
        );
      }
    },
  });

  markStreamTrustedDeliveryCallback(writable, writable._write);
  markStreamTrustedDeliveryCallback(writable, writable._writev);
  markStreamCleanupDeliveryCallback(writable, writable._final);

  registerStreamGuardAttachHook(writable, (guard) => {
    setWritableStreamUseGuard(writableStream, guard);
  });
  registerWritableStreamGuardAttachHook(writableStream, (guard) => {
    setStreamUseGuard(writable, guard);
  });

  uponPromise(
    writableStreamDefaultWriterClosedPromise(writer),
    () => {
      closed = true;
    },
    (error) => {
      closed = true;
      destroyNodeStream(writable, error);
    },
  );

  return writable;
}

function newStreamDuplexFromReadableWritablePair(
  pair,
  options = kEmptyObject,
) {
  validateObject(pair, "pair");
  const {
    readable: readableStream,
    writable: writableStream,
  } = pair;

  if (!isReadableStream(readableStream)) {
    throw new ERR_INVALID_ARG_TYPE(
      "pair.readable",
      "ReadableStream",
      readableStream,
    );
  }
  if (!isWritableStream(writableStream)) {
    throw new ERR_INVALID_ARG_TYPE(
      "pair.writable",
      "WritableStream",
      writableStream,
    );
  }

  validateObject(options, "options");
  const {
    allowHalfOpen = false,
    objectMode = false,
    encoding,
    decodeStrings = true,
    highWaterMark,
    signal,
  } = options;

  validateBoolean(objectMode, "options.objectMode");
  if (encoding !== undefined && !Buffer.isEncoding(encoding)) {
    throw new ERR_INVALID_ARG_VALUE(encoding, "options.encoding");
  }

  const writer = acquireWritableStreamDefaultWriter(writableStream);
  const reader = acquireReadableStreamDefaultReader(readableStream);
  let writableClosed = false;
  let readableClosed = false;

  const duplex = new (lazyStream().Duplex)({
    allowHalfOpen,
    highWaterMark,
    objectMode,
    encoding,
    decodeStrings,
    signal,

    writev(chunks, callback) {
      function done(error) {
        error = error.filter((e) => e);
        try {
          callback(error.length === 0 ? undefined : error);
        } catch (error) {
          // In a next tick because this is happening within
          // a promise context, and if there are any errors
          // thrown we don't want those to cause an unhandled
          // rejection. Let's just escape the promise and
          // handle it separately.
          lazyProcess().default.nextTick(() =>
            destroyNodeStream(duplex, error)
          );
        }
      }

      uponPromise(
        writableStreamDefaultWriterReadyPromise(writer),
        () =>
          uponPromise(
            SafePromiseAll(
              ArrayPrototypeMap(chunks, (data) =>
                writableStreamDefaultWriterWrite(writer, data.chunk)),
            ),
            done,
            done,
          ),
        done,
      );
    },

    write(chunk, encoding, callback) {
      if (typeof chunk === "string" && decodeStrings && !objectMode) {
        chunk = Buffer.from(chunk, encoding);
        chunk = new Uint8Array(
          chunk.buffer,
          chunk.byteOffset,
          chunk.byteLength,
        );
      }

      function done(error) {
        try {
          callback(error);
        } catch (error) {
          destroyNodeStream(duplex, error);
        }
      }

      uponPromise(
        writableStreamDefaultWriterReadyPromise(writer),
        () =>
          uponPromise(
            writableStreamDefaultWriterWrite(writer, chunk),
            done,
            done,
          ),
        done,
      );
    },

    final(callback) {
      function done(error) {
        try {
          callback(error);
        } catch (error) {
          // In a next tick because this is happening within
          // a promise context, and if there are any errors
          // thrown we don't want those to cause an unhandled
          // rejection. Let's just escape the promise and
          // handle it separately.
          lazyProcess().default.nextTick(() =>
            destroyNodeStream(duplex, error)
          );
        }
      }

      if (!writableClosed) {
        uponPromise(
          writableStreamDefaultWriterClose(writer),
          done,
          done,
        );
      }
    },

    read() {
      uponPromise(
        readableStreamDefaultReaderReadPromise(reader),
        (chunk) => {
          try {
            if (chunk.done) {
              pushReadableChunk(duplex, null);
            } else {
              pushReadableChunk(duplex, chunk.value);
            }
          } catch (error) {
            destroyNodeStream(duplex, error);
          }
        },
        (error) => destroyNodeStream(duplex, error),
      );
    },

    destroy(error, callback) {
      function done() {
        try {
          callback(error);
        } catch (error) {
          // In a next tick because this is happening within
          // a promise context, and if there are any errors
          // thrown we don't want those to cause an unhandled
          // rejection. Let's just escape the promise and
          // handle it separately.
          lazyProcess().default.nextTick(() => {
            throw error;
          });
        }
      }

      async function closeWriter() {
        if (!writableClosed) {
          await writableStreamDefaultWriterAbort(writer, error);
        }
      }

      async function closeReader() {
        if (!readableClosed) {
          await readableStreamReaderGenericCancel(reader, error);
        }
      }

      if (!writableClosed || !readableClosed) {
        uponPromise(
          SafePromiseAll([
            closeWriter(),
            closeReader(),
          ]),
          done,
          done,
        );
        return;
      }

      done();
    },
  });

  markStreamTrustedDeliveryCallback(duplex, duplex._write);
  markStreamTrustedDeliveryCallback(duplex, duplex._writev);
  markStreamCleanupDeliveryCallback(duplex, duplex._final);

  registerStreamGuardAttachHook(duplex, (guard) => {
    setReadableStreamUseGuard(readableStream, guard);
    setWritableStreamUseGuard(writableStream, guard);
  });
  registerReadableStreamGuardAttachHook(readableStream, (guard) => {
    setStreamUseGuard(duplex, guard);
  });
  registerWritableStreamGuardAttachHook(writableStream, (guard) => {
    setStreamUseGuard(duplex, guard);
  });

  uponPromise(
    writableStreamDefaultWriterClosedPromise(writer),
    () => {
      writableClosed = true;
    },
    (error) => {
      writableClosed = true;
      readableClosed = true;
      destroyNodeStream(duplex, error);
    },
  );

  uponPromise(
    readableStreamDefaultReaderClosedPromise(reader),
    () => {
      readableClosed = true;
    },
    (error) => {
      writableClosed = true;
      readableClosed = true;
      destroyNodeStream(duplex, error);
    },
  );

  return duplex;
}

function newReadableStreamFromStreamReadable(
  streamReadable,
  options = kEmptyObject,
) {
  // Not using the internal/streams/utils isReadableNodeStream utility
  // here because it will return false if streamReadable is a Duplex
  // whose readable option is false. For a Duplex that is not readable,
  // we want it to pass this check but return a closed ReadableStream.
  if (typeof streamReadable?._readableState !== "object") {
    throw new ERR_INVALID_ARG_TYPE(
      "streamReadable",
      "stream.Readable",
      streamReadable,
    );
  }
  validateObject(options, "options");
  if (options.type !== undefined) {
    validateOneOf(options.type, "options.type", ["bytes", undefined]);
  }

  if (isDestroyed(streamReadable) || !isReadable(streamReadable)) {
    const readable = new ReadableStream();
    readable.cancel();
    return readable;
  }

  const objectMode = streamReadable.readableObjectMode;
  const highWaterMark = streamReadable.readableHighWaterMark;

  const evaluateStrategyOrFallback = (strategy) => {
    // If there is a strategy available, use it
    if (strategy) {
      return strategy;
    }

    if (objectMode) {
      // When running in objectMode explicitly but no strategy, we just fall
      // back to CountQueuingStrategy
      return new CountQueuingStrategy({ highWaterMark });
    }

    // When not running in objectMode explicitly, we just fall
    // back to a minimal strategy that just specifies the highWaterMark
    // and no size algorithm. Using a ByteLengthQueuingStrategy here
    // is unnecessary.
    return { highWaterMark };
  };

  const strategy = evaluateStrategyOrFallback(options?.strategy);
  const isByteStream = options?.type === "bytes";

  let controller;

  function onData(chunk) {
    // Copy the Buffer to detach it from the pool.
    if (ArrayBufferIsView(chunk) && !objectMode) {
      chunk = new Uint8Array(chunk);
    }
    if (isByteStream) {
      readableByteStreamControllerEnqueue(controller, chunk);
    } else {
      readableStreamDefaultControllerEnqueue(controller, chunk);
    }
    const desiredSize = isByteStream
      ? readableByteStreamControllerGetDesiredSize(controller)
      : readableStreamDefaultControllerGetDesiredSize(controller);
    if (desiredSize <= 0) {
      streamReadable.pause();
    }
  }
  markTrustedDeliveryCallback(onData);

  streamReadable.pause();

  let isCanceled = false;

  // Only watch the readable side: a Duplex exposed via Readable.toWeb should
  // close the ReadableStream once its readable side ends, even if the writable
  // side is still open (otherwise the reader would hang waiting on the writable
  // half to finish).
  const cleanup = finished(streamReadable, { writable: false }, (error) => {
    if (error?.code === "ERR_STREAM_PREMATURE_CLOSE") {
      const err = new AbortError(undefined, { cause: error });
      error = err;
    }

    cleanup();
    // This is a protection against non-standard, legacy streams
    // that happen to emit an error event again after finished is called.
    streamReadable.on("error", () => {});
    if (error) {
      return isByteStream
        ? readableByteStreamControllerError(controller, error)
        : readableStreamDefaultControllerError(controller, error);
    }
    if (isCanceled) {
      return;
    }
    if (isByteStream) {
      readableByteStreamControllerClose(controller);
    } else {
      readableStreamDefaultControllerClose(controller);
    }
  });

  streamReadable.on("data", onData);

  const underlyingSource = {
    start(c) {
      controller = c;
    },

    pull() {
      streamReadable.resume();
    },

    cancel(reason) {
      isCanceled = true;
      destroyer(streamReadable, reason);
    },
  };
  if (isByteStream) {
    underlyingSource.type = "bytes";
  }
  const readable = new ReadableStream(underlyingSource, strategy);
  registerStreamGuardAttachHook(streamReadable, (guard) => {
    setReadableStreamUseGuard(readable, guard);
  });
  registerReadableStreamGuardAttachHook(readable, (guard) => {
    setStreamUseGuard(streamReadable, guard);
  });
  return readable;
}

function newWritableStreamFromStreamWritable(streamWritable) {
  // Not using the internal/streams/utils isWritableNodeStream utility
  // here because it will return false if streamWritable is a Duplex
  // whose writable option is false. For a Duplex that is not writable,
  // we want it to pass this check but return a closed WritableStream.
  // We check if the given stream is a stream.Writable or http.OutgoingMessage
  const checkIfWritableOrOutgoingMessage = streamWritable &&
    typeof streamWritable?.write === "function" &&
    typeof streamWritable?.on === "function";
  if (!checkIfWritableOrOutgoingMessage) {
    throw new ERR_INVALID_ARG_TYPE(
      "streamWritable",
      "stream.Writable",
      streamWritable,
    );
  }

  if (isDestroyed(streamWritable) || !isWritable(streamWritable)) {
    const writable = new WritableStream();
    writable.close();
    return writable;
  }

  const nodeWrite = streamWritable.write;
  const capturedNodeWrite = isWritablePublicWrite(nodeWrite) &&
      isRegisteredWritable(streamWritable)
    ? captureTrustedDeliveryCallback(nodeWrite)
    : captureDeliveryCallback(nodeWrite);
  const nodeEnd = streamWritable.end;
  const capturedNodeEnd = typeof nodeEnd === "function"
    ? captureDeliveryCallback(nodeEnd)
    : undefined;

  const highWaterMark = streamWritable.writableHighWaterMark;
  const strategy = streamWritable.writableObjectMode
    ? new CountQueuingStrategy({ highWaterMark })
    : { highWaterMark };

  let controller;
  let backpressurePromise;
  let closed;

  function onDrain() {
    if (backpressurePromise !== undefined) {
      backpressurePromise.resolve();
    }
  }

  const cleanup = finished(streamWritable, (error) => {
    if (error?.code === "ERR_STREAM_PREMATURE_CLOSE") {
      const err = new AbortError(undefined, { cause: error });
      error = err;
    }

    cleanup();
    // This is a protection against non-standard, legacy streams
    // that happen to emit an error event again after finished is called.
    streamWritable.on("error", () => {});
    if (error != null) {
      if (backpressurePromise !== undefined) {
        backpressurePromise.reject(error);
      }
      // If closed is not undefined, the error is happening
      // after the WritableStream close has already started.
      // We need to reject it here.
      if (closed !== undefined) {
        closed.reject(error);
        closed = undefined;
      }
      controller.error(error);
      controller = undefined;
      return;
    }

    if (closed !== undefined) {
      closed.resolve();
      closed = undefined;
      return;
    }
    controller.error(new AbortError());
    controller = undefined;
  });

  streamWritable.on("drain", onDrain);

  const underlyingSink = {
    start(c) {
      controller = c;
    },

    async write(chunk) {
      if (
        writableNeedsDrain(streamWritable) ||
        !runCapturedDelivery(
          streamWritable,
          capturedNodeWrite,
          streamWritable,
          [chunk],
        )
      ) {
        backpressurePromise = PromiseWithResolvers();
        return SafePromisePrototypeFinally(
          backpressurePromise.promise,
          () => {
            backpressurePromise = undefined;
          },
        );
      }
    },

    abort(reason) {
      destroyNodeStream(streamWritable, reason);
    },

    close() {
      if (closed === undefined && !isWritableEnded(streamWritable)) {
        closed = PromiseWithResolvers();
        if (capturedNodeEnd === undefined) {
          closed.resolve();
        } else {
          runCapturedCleanup(
            capturedNodeEnd,
            streamWritable,
            [],
          );
        }
        return closed.promise;
      }

      controller = undefined;
      return PromiseResolve();
    },
  };
  markWritableStreamTrustedCallback(underlyingSink.write);
  markWritableStreamTrustedCallback(underlyingSink.close);
  markWritableStreamTrustedCallback(underlyingSink.abort);
  const writable = new WritableStream(underlyingSink, strategy);
  registerStreamGuardAttachHook(streamWritable, (guard) => {
    setWritableStreamUseGuard(writable, guard);
  });
  registerWritableStreamGuardAttachHook(writable, (guard) => {
    setStreamUseGuard(streamWritable, guard);
  });
  return writable;
}

function newReadableWritablePairFromDuplex(
  duplex,
  options = kEmptyObject,
) {
  // Not using the internal/streams/utils isWritableNodeStream and
  // isReadableNodestream utilities here because they will return false
  // if the duplex was created with writable or readable options set to
  // false. Instead, we'll check the readable and writable state after
  // and return closed WritableStream or closed ReadableStream as
  // necessary.
  if (
    typeof duplex?._writableState !== "object" ||
    typeof duplex?._readableState !== "object"
  ) {
    throw new ERR_INVALID_ARG_TYPE("duplex", "stream.Duplex", duplex);
  }

  if (isDestroyed(duplex)) {
    const writable = new WritableStream();
    const readable = new ReadableStream();
    writable.close();
    readable.cancel();
    return { readable, writable };
  }

  const writable = isWritable(duplex)
    ? newWritableStreamFromStreamWritable(duplex)
    : new WritableStream();

  if (!isWritable(duplex)) {
    writable.close();
  }

  const readableType = options?.readableType || options?.type;
  const readableOptions = readableType ? { type: readableType } : kEmptyObject;

  const readable = isReadable(duplex)
    ? newReadableStreamFromStreamReadable(duplex, readableOptions)
    : new ReadableStream();

  if (!isReadable(duplex)) {
    readable.cancel();
  }

  return { writable, readable };
}

return {
  newReadableStreamFromStreamReadable,
  newWritableStreamFromStreamWritable,
  newStreamReadableFromReadableStream,
  newStreamWritableFromWritableStream,
  newStreamDuplexFromReadableWritablePair,
  newReadableWritablePairFromDuplex,
};
})();

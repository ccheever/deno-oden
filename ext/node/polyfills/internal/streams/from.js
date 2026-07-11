// deno-lint-ignore-file
// Copyright 2018-2026 the Deno authors. MIT license.

import process from "node:process";
import { core, primordials } from "ext:core/mod.js";
const { nextTick: ProtectedFromNextTick } = core.loadExtScript(
  "ext:deno_node/_next_tick.ts",
);
const { Buffer } = core.loadExtScript("ext:deno_node/internal/buffer.mjs");
const _mod1 = core.loadExtScript("ext:deno_node/internal/errors.ts");

const {
  ERR_INVALID_ARG_TYPE,
  ERR_STREAM_NULL_VALUES,
} = _mod1.codes;

"use strict";

const {
  FunctionPrototypeCall,
  PromisePrototypeThen,
  SymbolAsyncIterator,
  SymbolIterator,
} = primordials;

const {
  captureCurrentDeliveryCallback,
  runCapturedCallback,
} = core.loadExtScript(
  "ext:deno_node/internal/streams/oden_delivery.js",
);

function nextTickWithCurrent(callback, ...args) {
  const captured = captureCurrentDeliveryCallback(callback);
  FunctionPrototypeCall(
    ProtectedFromNextTick,
    process,
    () => runCapturedCallback(captured, undefined, args),
  );
}

function from(Readable, iterable, opts) {
  const {
    destroyReadableStream,
    pushReadableChunk,
  } = core.loadExtScript("ext:deno_node/internal/streams/readable.js");
  let iterator;
  if (typeof iterable === "string" || iterable instanceof Buffer) {
    return new Readable({
      objectMode: true,
      ...opts,
      read() {
        pushReadableChunk(this, iterable);
        pushReadableChunk(this, null);
      },
    });
  }

  let isAsync;
  if (iterable?.[SymbolAsyncIterator]) {
    isAsync = true;
    iterator = iterable[SymbolAsyncIterator]();
  } else if (iterable?.[SymbolIterator]) {
    isAsync = false;
    iterator = iterable[SymbolIterator]();
  } else {
    throw new ERR_INVALID_ARG_TYPE("iterable", ["Iterable"], iterable);
  }

  const readable = new Readable({
    objectMode: true,
    highWaterMark: 1,
    // TODO(ronag): What options should be allowed?
    ...opts,
  });

  // Flag to protect against _read
  // being called before last iteration completion.
  let reading = false;
  let isAsyncValues = false;

  readable._read = function () {
    if (!reading) {
      reading = true;

      if (isAsync) {
        nextAsync();
      } else if (isAsyncValues) {
        nextSyncWithAsyncValues();
      } else {
        nextSyncWithSyncValues();
      }
    }
  };

  readable._destroy = function (error, cb) {
    PromisePrototypeThen(
      close(error),
      () => nextTickWithCurrent(cb, error), // nextTick is here in case cb throws
      (e) => nextTickWithCurrent(cb, e || error),
    );
  };

  async function close(error) {
    const hadError = (error !== undefined) && (error !== null);
    const hasThrow = typeof iterator.throw === "function";
    if (hadError && hasThrow) {
      const { value, done } = await iterator.throw(error);
      await value;
      if (done) {
        return;
      }
    }
    if (typeof iterator.return === "function") {
      const { value } = await iterator.return();
      await value;
    }
  }

  // There are a lot of duplication here, it's done on purpose for performance
  // reasons - avoid await when not needed.

  function nextSyncWithSyncValues() {
    for (;;) {
      try {
        const { value, done } = iterator.next();

        if (done) {
          pushReadableChunk(readable, null);
          return;
        }

        if (
          value &&
          typeof value.then === "function"
        ) {
          return changeToAsyncValues(value);
        }

        if (value === null) {
          reading = false;
          throw new ERR_STREAM_NULL_VALUES();
        }

        if (pushReadableChunk(readable, value)) {
          continue;
        }

        reading = false;
      } catch (err) {
        destroyReadableStream(readable, err);
      }
      break;
    }
  }

  async function changeToAsyncValues(value) {
    isAsyncValues = true;

    try {
      const res = await value;

      if (res === null) {
        reading = false;
        throw new ERR_STREAM_NULL_VALUES();
      }

      if (pushReadableChunk(readable, res)) {
        nextSyncWithAsyncValues();
        return;
      }

      reading = false;
    } catch (err) {
      destroyReadableStream(readable, err);
    }
  }

  async function nextSyncWithAsyncValues() {
    for (;;) {
      try {
        const { value, done } = iterator.next();

        if (done) {
          pushReadableChunk(readable, null);
          return;
        }

        const res = (value &&
            typeof value.then === "function")
          ? await value
          : value;

        if (res === null) {
          reading = false;
          throw new ERR_STREAM_NULL_VALUES();
        }

        if (pushReadableChunk(readable, res)) {
          continue;
        }

        reading = false;
      } catch (err) {
        destroyReadableStream(readable, err);
      }
      break;
    }
  }

  async function nextAsync() {
    for (;;) {
      try {
        const { value, done } = await iterator.next();

        if (done) {
          pushReadableChunk(readable, null);
          return;
        }

        if (value === null) {
          reading = false;
          throw new ERR_STREAM_NULL_VALUES();
        }

        if (pushReadableChunk(readable, value)) {
          continue;
        }

        reading = false;
      } catch (err) {
        destroyReadableStream(readable, err);
      }
      break;
    }
  }
  return readable;
}

const _defaultExport = from;
export default _defaultExport;
export { from };

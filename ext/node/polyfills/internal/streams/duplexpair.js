// deno-lint-ignore-file
// Copyright 2018-2026 the Deno authors. MIT license.

import process from "node:process";
import { core, primordials } from "ext:core/mod.js";
const { nextTick: ProtectedDuplexPairNextTick } = core.loadExtScript(
  "ext:deno_node/_next_tick.ts",
);
import { Duplex } from "node:stream";
const { addReadableListener, pushReadableChunk } = core.loadExtScript(
  "ext:deno_node/internal/streams/readable.js",
);
const {
  captureDeliveryCallback,
  linkStreamUseGuard,
  markStreamTrustedDeliveryCallback,
  preflightStreamDelivery,
  registerStreamDeliveryPreflight,
  runCapturedCallback,
  runStreamUseGuard,
} = core.loadExtScript(
  "ext:deno_node/internal/streams/oden_delivery.js",
);
const assert = core.loadExtScript(
  "ext:deno_node/internal/assert.mjs",
);
"use strict";
const {
  ArrayBufferIsView,
  DataViewPrototypeGetByteLength,
  FunctionPrototypeCall,
  Symbol,
  TypedArrayPrototypeGetByteLength,
} = primordials;

const kInitOtherSide = Symbol("InitOtherSide");
const isTypedArray = core.isTypedArray;

function isEmptyChunk(chunk) {
  if (typeof chunk === "string") return chunk.length === 0;
  if (!ArrayBufferIsView(chunk)) return false;
  return (isTypedArray(chunk)
    ? TypedArrayPrototypeGetByteLength(chunk)
    : DataViewPrototypeGetByteLength(chunk)) === 0;
}

class DuplexSide extends Duplex {
  #callback = null;
  #otherSide = null;

  constructor(options) {
    super(options);
    this.#callback = null;
    this.#otherSide = null;
    markStreamTrustedDeliveryCallback(this, DuplexSide.prototype._write);
    markStreamTrustedDeliveryCallback(this, DuplexSide.prototype._final);
    registerStreamDeliveryPreflight(this, () => {
      if (this.#otherSide !== null) {
        preflightStreamDelivery(this.#otherSide);
      }
    });
  }

  [kInitOtherSide](otherSide) {
    // Ensure this can only be set once, to enforce encapsulation.
    if (this.#otherSide === null) {
      this.#otherSide = otherSide;
      linkStreamUseGuard(this, otherSide);
    } else {
      assert(this.#otherSide === null);
    }
  }

  _read() {
    const callback = this.#callback;
    if (callback) {
      this.#callback = null;
      runCapturedCallback(callback, undefined, []);
    }
  }

  _write(chunk, encoding, callback) {
    runStreamUseGuard(this);
    assert(this.#otherSide !== null);
    assert(this.#otherSide.#callback === null);
    const capturedCallback = captureDeliveryCallback(callback);
    // A duplex-pair write crosses into the distinct readable counterpart;
    // its live constituent link is a destination transition, not an
    // authority transfer.
    // @ref LLP 0019#operation-scoped-positive-authority-provenance [implements]
    if (isEmptyChunk(chunk)) {
      FunctionPrototypeCall(
        ProtectedDuplexPairNextTick,
        process,
        () => runCapturedCallback(capturedCallback, undefined, []),
      );
    } else {
      pushReadableChunk(this.#otherSide, chunk);
      this.#otherSide.#callback = capturedCallback;
    }
  }

  _final(callback) {
    runStreamUseGuard(this);
    addReadableListener(this.#otherSide, "end", callback);
    pushReadableChunk(this.#otherSide, null);
  }
}

function duplexPair(options) {
  const side0 = new DuplexSide(options);
  const side1 = new DuplexSide(options);
  side0[kInitOtherSide](side1);
  side1[kInitOtherSide](side0);
  return [side0, side1];
}
export default duplexPair;
export { duplexPair };

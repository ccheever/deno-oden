#!/usr/bin/env -S deno run --allow-read
// Copyright 2018-2026 the Deno authors. MIT license.
//
// Exhaustive compartment-global inventory. The explicit EXPECTED_GLOBALS list
// is the rebase tripwire: a newly added ambient global is UNCLASSIFIED until a
// reviewer assigns it a posture. `--check` also verifies the generated markdown
// manifest, so runtime drift and classification drift are both loud.
//
// @ref LLP 0014#implementation-slicing [implements] -- Slice 0 inventory gate.

const ROOT = new URL("../../", import.meta.url).pathname;
const MANIFEST = ROOT + "tools/oden/global_inventory.manifest.md";

const EXPECTED_GLOBALS = [
  "AbortController",
  "AbortSignal",
  "AggregateError",
  "Array",
  "ArrayBuffer",
  "AsyncDisposableStack",
  "Atomics",
  "BigInt",
  "BigInt64Array",
  "BigUint64Array",
  "Blob",
  "Boolean",
  "BroadcastChannel",
  "Buffer",
  "ByteLengthQueuingStrategy",
  "Cache",
  "CacheStorage",
  "CloseEvent",
  "CompressionStream",
  "CountQueuingStrategy",
  "Crypto",
  "CryptoKey",
  "CustomEvent",
  "DOMException",
  "DOMMatrix",
  "DOMMatrixReadOnly",
  "DOMPoint",
  "DOMPointReadOnly",
  "DOMQuad",
  "DOMRect",
  "DOMRectReadOnly",
  "DataView",
  "Date",
  "DecompressionStream",
  "Deno",
  "DisposableStack",
  "Error",
  "ErrorEvent",
  "EvalError",
  "Event",
  "EventSource",
  "EventTarget",
  "File",
  "FileReader",
  "FinalizationRegistry",
  "Float16Array",
  "Float32Array",
  "Float64Array",
  "FormData",
  "Function",
  "GPU",
  "GPUAdapter",
  "GPUAdapterInfo",
  "GPUBindGroup",
  "GPUBindGroupLayout",
  "GPUBuffer",
  "GPUBufferUsage",
  "GPUCanvasContext",
  "GPUColorWrite",
  "GPUCommandBuffer",
  "GPUCommandEncoder",
  "GPUCompilationInfo",
  "GPUCompilationMessage",
  "GPUComputePassEncoder",
  "GPUComputePipeline",
  "GPUDevice",
  "GPUDeviceLostInfo",
  "GPUError",
  "GPUInternalError",
  "GPUMapMode",
  "GPUOutOfMemoryError",
  "GPUPipelineError",
  "GPUPipelineLayout",
  "GPUQuerySet",
  "GPUQueue",
  "GPURenderBundle",
  "GPURenderBundleEncoder",
  "GPURenderPassEncoder",
  "GPURenderPipeline",
  "GPUSampler",
  "GPUShaderModule",
  "GPUShaderStage",
  "GPUSupportedFeatures",
  "GPUSupportedLimits",
  "GPUTexture",
  "GPUTextureUsage",
  "GPUTextureView",
  "GPUUncapturedErrorEvent",
  "GPUValidationError",
  "Headers",
  "ImageBitmap",
  "ImageBitmapRenderingContext",
  "ImageData",
  "Infinity",
  "Int16Array",
  "Int32Array",
  "Int8Array",
  "Intl",
  "Iterator",
  "JSON",
  "Location",
  "Lock",
  "LockManager",
  "Map",
  "Math",
  "MessageChannel",
  "MessageEvent",
  "MessagePort",
  "NaN",
  "Navigator",
  "NavigatorUAData",
  "Number",
  "Object",
  "OffscreenCanvas",
  "Performance",
  "PerformanceEntry",
  "PerformanceMark",
  "PerformanceMeasure",
  "PerformanceObserver",
  "PerformanceObserverEntryList",
  "ProgressEvent",
  "Promise",
  "PromiseRejectionEvent",
  "Proxy",
  "QuotaExceededError",
  "RangeError",
  "ReadableByteStreamController",
  "ReadableStream",
  "ReadableStreamBYOBReader",
  "ReadableStreamBYOBRequest",
  "ReadableStreamDefaultController",
  "ReadableStreamDefaultReader",
  "ReferenceError",
  "Reflect",
  "RegExp",
  "Request",
  "Response",
  "Set",
  "SharedArrayBuffer",
  "Storage",
  "String",
  "SubtleCrypto",
  "SuppressedError",
  "Symbol",
  "SyntaxError",
  "Temporal",
  "TextDecoder",
  "TextDecoderStream",
  "TextEncoder",
  "TextEncoderStream",
  "TransformStream",
  "TransformStreamDefaultController",
  "TypeError",
  "URIError",
  "URL",
  "URLPattern",
  "URLSearchParams",
  "Uint16Array",
  "Uint32Array",
  "Uint8Array",
  "Uint8ClampedArray",
  "WeakMap",
  "WeakRef",
  "WeakSet",
  "WebAssembly",
  "WebSocket",
  "Window",
  "Worker",
  "WritableStream",
  "WritableStreamDefaultController",
  "WritableStreamDefaultWriter",
  "alert",
  "atob",
  "btoa",
  "caches",
  "clearImmediate",
  "clearInterval",
  "clearTimeout",
  "close",
  "closed",
  "confirm",
  "console",
  "createImageBitmap",
  "crypto",
  "decodeURI",
  "decodeURIComponent",
  "encodeURI",
  "encodeURIComponent",
  "escape",
  "eval",
  "fetch",
  "global",
  "globalThis",
  "isFinite",
  "isNaN",
  "localStorage",
  "location",
  "name",
  "navigator",
  "onbeforeunload",
  "onerror",
  "onload",
  "onunhandledrejection",
  "onunload",
  "parseFloat",
  "parseInt",
  "performance",
  "process",
  "prompt",
  "queueMicrotask",
  "reportError",
  "self",
  "sessionStorage",
  "setImmediate",
  "setInterval",
  "setTimeout",
  "structuredClone",
  "undefined",
  "unescape",
] as const;

type Status =
  | "always-endowed"
  | "grant-derived"
  | "never-endowed"
  | "mediated-view";
type Classification = { status: Status; reason: string };

const OVERRIDES: Record<string, Classification> = {
  BroadcastChannel: {
    status: "grant-derived",
    reason:
      "requires ipc:broadcast (family not yet authorable in the shared v1 vocabulary; fail-closed)",
  },
  EventSource: {
    status: "grant-derived",
    reason:
      "network:fetch derives the HTTP event-stream client; op boundary still checks endpoint",
  },
  WebSocket: {
    status: "grant-derived",
    reason:
      "network:connect derives WebSocket; fetch grants deliberately do not",
  },
  caches: {
    status: "grant-derived",
    reason:
      "requires storage:cache (family not yet authorable in the shared v1 vocabulary; fail-closed)",
  },
  fetch: {
    status: "grant-derived",
    reason:
      "network:fetch derives reachability; resolved endpoint is still op-gated",
  },
  localStorage: {
    status: "grant-derived",
    reason:
      "requires storage:local (family not yet authorable in the shared v1 vocabulary; fail-closed)",
  },
  sessionStorage: {
    status: "grant-derived",
    reason:
      "requires storage:session (family not yet authorable in the shared v1 vocabulary; fail-closed)",
  },
  Deno: {
    status: "never-endowed",
    reason:
      "privileged namespace; package authority flows through endowments/handles, not raw Deno.*",
  },
  Worker: {
    status: "never-endowed",
    reason:
      "worker inheritance is undesigned and package worker creation is default-denied under enforce",
  },
  alert: { status: "never-endowed", reason: "interactive stdio surface" },
  confirm: { status: "never-endowed", reason: "interactive stdio surface" },
  eval: {
    status: "never-endowed",
    reason:
      "direct evaluator reach stays fail-closed pending ENG-23783; Function-family quarantine remains a residual",
  },
  process: {
    status: "never-endowed",
    reason:
      "privileged Node namespace; pure-field mediation remains an LLP 0014 open question",
  },
  prompt: { status: "never-endowed", reason: "interactive stdio surface" },
  global: {
    status: "mediated-view",
    reason:
      "rewritten to the per-principal filtered global record, never the real global",
  },
  globalThis: {
    status: "mediated-view",
    reason:
      "rewritten to the per-principal filtered global record, never the real global",
  },
  navigator: {
    status: "mediated-view",
    reason:
      "filtered view; navigator.gpu remains unavailable without the future gpu:access family",
  },
  self: {
    status: "mediated-view",
    reason:
      "rewritten to the per-principal filtered global record, never the real global",
  },
  Function: {
    status: "always-endowed",
    reason:
      "pure constructor value today; generated-code attribution remains fail-closed/quarantined under ENG-23783",
  },
};

const REMOVED = [
  ["globalThis.__bootstrap", "deleted at end of bootstrap"],
  ["Deno.core", "not installed on the public Deno namespace"],
  [
    "Deno[Deno.internal].core compile/eval/async primitives",
    "captured then sealed while capsec is armed",
  ],
  [
    "__oden_compartment_globals__ (when mode is off)",
    "installed only for explicit enforce+lockdown opt-in",
  ],
] as const;

function classification(name: string): Classification {
  return OVERRIDES[name] ?? {
    status: "always-endowed",
    reason:
      "inert/pure/local runtime surface with no separately grantable external authority in LLP 0010",
  };
}

function currentGlobals(): string[] {
  return Reflect.ownKeys(globalThis).filter((key): key is string =>
    typeof key === "string"
  ).sort();
}

function validate(): string[] {
  const errors: string[] = [];
  const expected = new Set<string>(EXPECTED_GLOBALS);
  const current = new Set(currentGlobals());
  for (const name of current) {
    if (!expected.has(name)) {
      errors.push(`UNCLASSIFIED ambient global added by runtime: ${name}`);
    }
  }
  for (const name of expected) {
    if (!current.has(name)) {
      errors.push(`classified ambient global disappeared: ${name}`);
    }
  }
  for (const name of Object.keys(OVERRIDES)) {
    if (!expected.has(name)) {
      errors.push(`classification names a non-inventory global: ${name}`);
    }
  }
  return errors;
}

function render(): string {
  const counts = new Map<Status, number>();
  for (const name of EXPECTED_GLOBALS) {
    const status = classification(name).status;
    counts.set(status, (counts.get(status) ?? 0) + 1);
  }
  const out = [
    "# Oden exhaustive ambient-global inventory (generated)",
    "",
    `Pin inventory: ${EXPECTED_GLOBALS.length} ambient string-key globals. ` +
    `${counts.get("always-endowed") ?? 0} always-endowed; ` +
    `${counts.get("grant-derived") ?? 0} grant-derived; ` +
    `${counts.get("never-endowed") ?? 0} never-endowed; ` +
    `${counts.get("mediated-view") ?? 0} mediated views.`,
    "",
    "| global | classification | per-entry rationale |",
    "| --- | --- | --- |",
  ];
  for (const name of EXPECTED_GLOBALS) {
    const value = classification(name);
    out.push(`| \`${name}\` | ${value.status} | ${value.reason} |`);
  }
  out.push(
    "",
    "## Removed/sealed surfaces",
    "",
    "| surface | disposition |",
    "| --- | --- |",
  );
  for (const [name, reason] of REMOVED) {
    out.push(`| \`${name}\` | ${reason} |`);
  }
  out.push("");
  return out.join("\n");
}

function main() {
  const errors = validate();
  if (Deno.args.includes("--check")) {
    let committed = "";
    try {
      committed = Deno.readTextFileSync(MANIFEST);
    } catch {
      errors.push("global inventory manifest is missing");
    }
    if (committed !== render()) {
      errors.push("global inventory manifest is stale");
    }
    if (errors.length) {
      console.error("global inventory gate FAILED:");
      for (const error of errors) console.error(`  - ${error}`);
      Deno.exit(1);
    }
    console.log(
      `global inventory gate OK: ${EXPECTED_GLOBALS.length} globals classified`,
    );
    return;
  }
  Deno.stdout.writeSync(new TextEncoder().encode(render()));
}

main();

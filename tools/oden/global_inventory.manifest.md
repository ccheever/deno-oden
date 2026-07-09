# Oden exhaustive ambient-global inventory (generated)

Pin inventory: 219 ambient string-key globals. 201 always-endowed; 7 grant-derived; 7 never-endowed; 4 mediated views.

| global | classification | per-entry rationale |
| --- | --- | --- |
| `AbortController` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `AbortSignal` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `AggregateError` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `Array` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `ArrayBuffer` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `AsyncDisposableStack` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `Atomics` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `BigInt` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `BigInt64Array` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `BigUint64Array` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `Blob` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `Boolean` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `BroadcastChannel` | grant-derived | requires ipc:broadcast (family not yet authorable in the shared v1 vocabulary; fail-closed) |
| `Buffer` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `ByteLengthQueuingStrategy` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `Cache` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `CacheStorage` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `CloseEvent` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `CompressionStream` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `CountQueuingStrategy` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `Crypto` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `CryptoKey` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `CustomEvent` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `DOMException` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `DOMMatrix` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `DOMMatrixReadOnly` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `DOMPoint` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `DOMPointReadOnly` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `DOMQuad` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `DOMRect` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `DOMRectReadOnly` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `DataView` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `Date` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `DecompressionStream` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `Deno` | never-endowed | privileged namespace; package authority flows through endowments/handles, not raw Deno.* |
| `DisposableStack` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `Error` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `ErrorEvent` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `EvalError` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `Event` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `EventSource` | grant-derived | network:fetch derives the HTTP event-stream client; op boundary still checks endpoint |
| `EventTarget` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `File` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `FileReader` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `FinalizationRegistry` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `Float16Array` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `Float32Array` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `Float64Array` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `FormData` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `Function` | always-endowed | pure constructor value today; generated-code attribution remains fail-closed/quarantined under ENG-23783 |
| `GPU` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `GPUAdapter` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `GPUAdapterInfo` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `GPUBindGroup` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `GPUBindGroupLayout` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `GPUBuffer` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `GPUBufferUsage` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `GPUCanvasContext` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `GPUColorWrite` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `GPUCommandBuffer` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `GPUCommandEncoder` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `GPUCompilationInfo` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `GPUCompilationMessage` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `GPUComputePassEncoder` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `GPUComputePipeline` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `GPUDevice` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `GPUDeviceLostInfo` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `GPUError` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `GPUInternalError` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `GPUMapMode` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `GPUOutOfMemoryError` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `GPUPipelineError` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `GPUPipelineLayout` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `GPUQuerySet` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `GPUQueue` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `GPURenderBundle` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `GPURenderBundleEncoder` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `GPURenderPassEncoder` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `GPURenderPipeline` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `GPUSampler` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `GPUShaderModule` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `GPUShaderStage` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `GPUSupportedFeatures` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `GPUSupportedLimits` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `GPUTexture` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `GPUTextureUsage` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `GPUTextureView` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `GPUUncapturedErrorEvent` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `GPUValidationError` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `Headers` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `ImageBitmap` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `ImageBitmapRenderingContext` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `ImageData` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `Infinity` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `Int16Array` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `Int32Array` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `Int8Array` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `Intl` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `Iterator` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `JSON` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `Location` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `Lock` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `LockManager` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `Map` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `Math` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `MessageChannel` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `MessageEvent` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `MessagePort` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `NaN` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `Navigator` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `NavigatorUAData` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `Number` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `Object` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `OffscreenCanvas` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `Performance` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `PerformanceEntry` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `PerformanceMark` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `PerformanceMeasure` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `PerformanceObserver` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `PerformanceObserverEntryList` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `ProgressEvent` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `Promise` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `PromiseRejectionEvent` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `Proxy` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `QuotaExceededError` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `RangeError` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `ReadableByteStreamController` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `ReadableStream` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `ReadableStreamBYOBReader` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `ReadableStreamBYOBRequest` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `ReadableStreamDefaultController` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `ReadableStreamDefaultReader` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `ReferenceError` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `Reflect` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `RegExp` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `Request` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `Response` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `Set` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `SharedArrayBuffer` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `Storage` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `String` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `SubtleCrypto` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `SuppressedError` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `Symbol` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `SyntaxError` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `Temporal` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `TextDecoder` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `TextDecoderStream` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `TextEncoder` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `TextEncoderStream` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `TransformStream` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `TransformStreamDefaultController` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `TypeError` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `URIError` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `URL` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `URLPattern` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `URLSearchParams` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `Uint16Array` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `Uint32Array` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `Uint8Array` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `Uint8ClampedArray` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `WeakMap` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `WeakRef` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `WeakSet` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `WebAssembly` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `WebSocket` | grant-derived | network:connect derives WebSocket; fetch grants deliberately do not |
| `Window` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `Worker` | never-endowed | worker inheritance is undesigned and package worker creation is default-denied under enforce |
| `WritableStream` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `WritableStreamDefaultController` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `WritableStreamDefaultWriter` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `alert` | never-endowed | interactive stdio surface |
| `atob` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `btoa` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `caches` | grant-derived | requires storage:cache (family not yet authorable in the shared v1 vocabulary; fail-closed) |
| `clearImmediate` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `clearInterval` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `clearTimeout` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `close` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `closed` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `confirm` | never-endowed | interactive stdio surface |
| `console` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `createImageBitmap` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `crypto` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `decodeURI` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `decodeURIComponent` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `encodeURI` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `encodeURIComponent` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `escape` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `eval` | never-endowed | direct evaluator reach stays fail-closed pending ENG-23783; Function-family quarantine remains a residual |
| `fetch` | grant-derived | network:fetch derives reachability; resolved endpoint is still op-gated |
| `global` | mediated-view | rewritten to the per-principal filtered global record, never the real global |
| `globalThis` | mediated-view | rewritten to the per-principal filtered global record, never the real global |
| `isFinite` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `isNaN` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `localStorage` | grant-derived | requires storage:local (family not yet authorable in the shared v1 vocabulary; fail-closed) |
| `location` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `name` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `navigator` | mediated-view | filtered view; navigator.gpu remains unavailable without the future gpu:access family |
| `onbeforeunload` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `onerror` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `onload` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `onunhandledrejection` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `onunload` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `parseFloat` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `parseInt` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `performance` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `process` | never-endowed | privileged Node namespace; pure-field mediation remains an LLP 0014 open question |
| `prompt` | never-endowed | interactive stdio surface |
| `queueMicrotask` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `reportError` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `self` | mediated-view | rewritten to the per-principal filtered global record, never the real global |
| `sessionStorage` | grant-derived | requires storage:session (family not yet authorable in the shared v1 vocabulary; fail-closed) |
| `setImmediate` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `setInterval` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `setTimeout` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `structuredClone` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `undefined` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |
| `unescape` | always-endowed | inert/pure/local runtime surface with no separately grantable external authority in LLP 0010 |

## Removed/sealed surfaces

| surface | disposition |
| --- | --- |
| `globalThis.__bootstrap` | deleted at end of bootstrap |
| `Deno.core` | not installed on the public Deno namespace |
| `Deno[Deno.internal].core compile/eval/async primitives` | captured then sealed while capsec is armed |
| `__oden_compartment_globals__ (when mode is off)` | installed only for explicit enforce+lockdown opt-in |

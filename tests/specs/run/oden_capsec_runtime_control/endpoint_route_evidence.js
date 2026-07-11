const root = new URL("../../../../", import.meta.url);

async function source(path) {
  return await Deno.readTextFile(new URL(path, root));
}

function section(text, start, end) {
  const startIndex = text.indexOf(start);
  const endIndex = text.indexOf(end, startIndex + start.length);
  return startIndex >= 0 && endIndex > startIndex
    ? text.slice(startIndex, endIndex)
    : "";
}

function ordered(text, first, second) {
  const firstIndex = text.indexOf(first);
  const secondIndex = text.indexOf(second);
  return firstIndex >= 0 && secondIndex > firstIndex;
}

const websocket = await source("ext/websocket/lib.rs");
const legacyWebSocket = await source("ext/websocket/01_websocket.js");
const streams = await source("ext/web/06_streams.js");
const nodeReadable = await source(
  "ext/node/polyfills/internal/streams/readable.js",
);
const nodeStream = await source("ext/node/polyfills/stream.ts");
const nodeDuplex = await source(
  "ext/node/polyfills/internal/streams/duplex.js",
);
const nodeDuplexify = await source(
  "ext/node/polyfills/internal/streams/duplexify.js",
);
const nodeCompose = await source(
  "ext/node/polyfills/internal/streams/compose.js",
);
const nodeDuplexPair = await source(
  "ext/node/polyfills/internal/streams/duplexpair.js",
);
const net = await source("ext/net/01_net.js");
const netIo = await source("ext/net/io.rs");
const netOps = await source("ext/net/ops.rs");

const ping = section(
  websocket,
  "pub async fn op_ws_send_ping(",
  "pub async fn op_ws_next_event(",
);
const pingTimer = section(
  legacyWebSocket,
  "[_serverHandleIdleTimeout]()",
  '[SymbolFor("Deno.privateCustomInspect")]',
);
const backing = section(
  streams,
  "function getReadableStreamResourceBacking(stream)",
  "async function readableStreamCollectIntoUint8Array(stream)",
);
const collector = section(
  streams,
  "async function readableStreamCollectIntoUint8Array(stream)",
  "function writableStreamForRid(",
);
const nodePipe = section(
  nodeReadable,
  "Readable.prototype.pipe = function (dest, pipeOpts)",
  "Readable.prototype.unpipe = function (dest)",
);
const nodeIterator = section(
  nodeReadable,
  "function streamToAsyncIterator(stream, options)",
  "async function* createAsyncIterator(stream, options)",
);
const nodeFrom = section(
  nodeReadable,
  "Readable.from = function (iterable, opts)",
  "let webStreamsAdapters;",
);
const nodeOperators = section(
  nodeStream,
  "const streamKeys = ObjectKeys(streamReturningOperators);",
  "const promiseKeys = ObjectKeys(promiseReturningOperators);",
);
const nodeDuplexConversions = section(
  nodeDuplex,
  "Duplex.fromWeb = function (pair, options)",
  "let duplexify;",
);
const nodeDuplexifyFunction = section(
  nodeDuplexify,
  'if (typeof body === "function")',
  "if (isBlob(body))",
);
const nodeDuplexifyIterable = section(
  nodeDuplexify,
  "if (isIterable(body))",
  "if (\n    isReadableStream(body?.readable)",
);
const nodeDuplexifyPair = section(
  nodeDuplexify,
  "function _duplexify(pair)",
  "return d;",
);
const queueBarrier = section(
  streams,
  "const queueInternalAccessToken = ObjectCreate(null);",
  "/**\n * @param {ArrayBufferLike} O",
);
const requestBarrier = section(
  streams,
  "const readableRequestDispatches = new SafeWeakMap();",
  "function getReadableBYOBRequestViewInternal(byobRequest)",
);
const readableEnqueue = section(
  streams,
  "function readableStreamDefaultControllerEnqueue(controller, chunk)",
  "function readableStreamDefaultControllerError(controller, e)",
);
const readableSizeCallback = section(
  streams,
  "function invokeReadableControllerSizeAlgorithm(",
  "function setReadableReaderQueue(reader, slot, queue)",
);
const webIteratorFastPath = section(
  streams,
  "const readableStreamAsyncIteratorPrototype = ObjectSetPrototypeOf({",
  "class ByteLengthQueuingStrategy",
);
const webReaderFastPath = section(
  streams,
  "class ReadableStreamDefaultReader",
  "class ReadableStreamBYOBReadIntoRequest",
);

function guardCaughtBeforeQueueInspection(text, streamMarker) {
  const streamIndex = text.indexOf(streamMarker);
  const tryIndex = text.indexOf("try {", streamIndex);
  const guardIndex = text.indexOf(
    "runReadableStreamUseGuard(stream);",
    tryIndex,
  );
  const queueIndex = text.indexOf("queueSize(controller[_queue])", guardIndex);
  return streamIndex >= 0 && tryIndex > streamIndex &&
    guardIndex > tryIndex && queueIndex > guardIndex;
}

const evidence = {
  websocketPingGuard: ping.includes(
    'resource.check_protected_inspector_use("WebSocket.ping")',
  ),
  websocketPingPublicReachability: pingTimer.includes(
    "await PromisePrototypeCatch(op_ws_send_ping(this[_rid]), () => {});",
  ),
  unrefableBackingSharedGuard: backing.includes(
    "function getReadableStreamResourceBackingUnrefable(stream)",
  ) && backing.match(/runReadableStreamUseGuard\(stream\);/g)?.length === 2,
  unrefableBackingDominated: collector.includes(
    "getReadableStreamResourceBacking(stream) ||\n    getReadableStreamResourceBackingUnrefable(stream)",
  ),
  nodeIteratorCarrierPropagation: nodeIterator.includes(
    "WeakMapPrototypeSet(readableIteratorUseGuards, iter, sourceGuard)",
  ) && nodeFrom.includes("getReadableUseGuard(iterable)"),
  nodePipeReadableDestinationPropagation: ordered(
    nodePipe,
    "runReadableUseGuard(this);",
    "setStreamUseGuard(dest, sourceGuard);",
  ) && ordered(
    nodePipe,
    "setStreamUseGuard(dest, sourceGuard);",
    "state.pipes.push(dest);",
  ),
  nodeStreamOperatorPropagation: nodeOperators.includes(
    "const sourceGuard = getReadableUseGuard(this);",
  ) && nodeOperators.includes("setReadableUseGuard(readable, sourceGuard);"),
  nodeDuplexWebConversionPropagation: nodeDuplexConversions.includes(
    "getReadableStreamUseGuard(readableStream)",
  ) && nodeDuplexConversions.includes(
    "setReadableUseGuard(duplex, sourceGuard);",
  ) && nodeDuplexConversions.includes(
    "setReadableStreamUseGuard(pair.readable, sourceGuard);",
  ),
  nodeDuplexifyPropagation: nodeDuplexifyFunction.includes(
    "propagateReadableUseGuard(value, from(Duplexify, value",
  ) && nodeDuplexifyIterable.includes(
    "propagateReadableUseGuard(body, from(Duplexify, body",
  ) && nodeDuplexifyPair.includes("setReadableUseGuard(d, sourceGuard);"),
  nodeComposeNodeAndWebPropagation: nodeCompose.includes(
    "const guardedSources = [head, tail];",
  ) && nodeCompose.includes("getReadableStreamUseGuard(readableSource)") &&
    nodeCompose.includes("setReadableUseGuard(d, sourceGuard);"),
  nodeDuplexPairCounterpartPropagation: nodeDuplexPair.includes(
    "const sourceGuard = getReadableUseGuard(this);",
  ) && nodeDuplexPair.includes(
    "setReadableUseGuard(this.#otherSide, sourceGuard);",
  ),
  webReaderFastDequeueGuardOrder: ordered(
    webReaderFastPath,
    "runReadableStreamUseGuard(stream);",
    "const chunk = dequeueValue(controller);",
  ),
  webIteratorFastDequeueGuardOrder: ordered(
    webIteratorFastPath,
    "runReadableStreamUseGuard(stream);",
    "const chunk = dequeueValue(controller);",
  ),
  webQueueTokenAndCapturedDispatch: queueBarrier.includes(
    "const queueInternalAccessToken = ObjectCreate(null);",
  ) && queueBarrier.includes(
    "const queuePrototypeIsInternalQueue = Queue.prototype.isInternalQueue;",
  ) && queueBarrier.includes(
    "void this.#size;",
  ) && queueBarrier.includes(
    "ReflectApply(queuePrototypeDequeue, queue",
  ),
  webQueueInternalCallsStillGuarded: queueBarrier.includes(
    "both public and internal operations recheck",
  ) && queueBarrier.includes(
    "runReadableStreamUseGuard(streams[i]);",
  ) && !queueBarrier.includes(
    "if (accessToken === queueInternalAccessToken) return",
  ),
  webQueueDynamicDispatchClosed:
    (streams.match(/\.(?:enqueueWithSize|dequeueNode|dequeue|peek)\(/g) ?? [])
        .length === 0 &&
    (streams.match(/\.enqueue\(/g) ?? []).length === 1,
  webRequestDispatchCaptured: requestBarrier.includes(
    "const readableRequestDispatches = new SafeWeakMap();",
  ) && streams.includes(
    "ReadableStreamDefaultReadRequest.prototype.chunkSteps;",
  ) && streams.includes(
    "ReadableStreamBYOBReadIntoRequest.prototype.chunkSteps;",
  ) && streams.includes(
    "ReadableStreamAsyncIteratorReadRequest.prototype.chunkSteps;",
  ) && (streams.match(/registerReadableLiteralRequest\(/g) ?? []).length ===
      7 &&
    (streams.match(/\.(?:chunkSteps|closeSteps|errorSteps)\(/g) ?? [])
        .length ===
      0,
  webReadableSizeCallbackCaptured: streams.includes(
    "const readableControllerSizeAlgorithms = new SafeWeakMap();",
  ) && readableEnqueue.includes(
    "const sizeAlgorithm = getReadableControllerSizeAlgorithm(controller);",
  ) && readableEnqueue.includes(
    "chunkSize = invokeReadableControllerSizeAlgorithm(",
  ) && streams.includes(
    "const callbackContext = op_oden_callback_context(callback);",
  ) && readableSizeCallback.indexOf(
        "setAsyncContext(callbackRecord.callbackContext);",
      ) < readableSizeCallback.indexOf("runReadableStreamUseGuard(stream);") &&
    readableSizeCallback.indexOf("runReadableStreamUseGuard(stream);") <
      readableSizeCallback.indexOf("callbackRecord.callback,"),
  webFastPathsRejectGuardErrors: guardCaughtBeforeQueueInspection(
    webIteratorFastPath,
    "const stream = reader[_stream]",
  ) && guardCaughtBeforeQueueInspection(
    webReaderFastPath,
    "const stream = this[_stream]",
  ),
  webBYOBViewClosurePrivate: streams.includes(
    "const readableBYOBRequestViews = new SafeWeakMap();",
  ) && streams.includes(
    "return getReadableBYOBRequestView(this);",
  ) && !streams.includes("  [_view];"),
  webProtectedSlotsSealed: streams.includes(
    "function sealProtectedReadableSlot(object, slot)",
  ) && streams.includes(
    "sealProtectedReadableSlot(controller, _pendingPullIntos);",
  ) && streams.includes(
    "sealProtectedReadableSlot(reader, _readRequests);",
  ),
  webCanonicalGraphIgnoresRetagSlots: streams.includes(
    "const canonicalReadableSlots = new SafeWeakMap();",
  ) && streams.includes(
    "slots[slot] = canonicalSlots[slot];",
  ) && !section(
    streams,
    "function sealProtectedReadableSlot(object, slot)",
    "function setProtectedReadableSlot(object, slot, value)",
  ).includes("object[slot]") && streams.includes(
    "const controller = getCanonicalReadableSlot(stream, _controller);",
  ) && streams.includes(
    "setProtectedReadableSlot(stream, _controller, controller);",
  ) && streams.includes(
    "setProtectedReadableSlot(controller, _stream, stream);",
  ),
  webStateViewsRecheck: streams.includes(
    "function createReadableByteStreamControllerStateView(controller)",
  ) && streams.includes(
    "runReadableControllerUseGuard(controller);",
  ),
  webCleanupUsesNarrowToken: streams.includes(
    "readableByteStreamControllerClose(this, queueCleanupAccessToken);",
  ) && streams.includes(
    "readableStreamDefaultControllerClose(this, queueCleanupAccessToken);",
  ) && streams.includes("function queueCleanupDrain(queue, callback)"),
  webResourceBackingClosurePrivate: streams.includes(
    "const readableResourceBackings = new SafeWeakMap();",
  ) && streams.includes(
    "const readableResourceBackingUnrefables = new SafeWeakMap();",
  ) && streams.includes(
    "function getReadableResourceBackingView(stream, unrefable)",
  ) && streams.includes(
    "sealProtectedReadableResourceBackingSlot(stream, _resourceBacking, false);",
  ) && streams.includes(
    "return getReadableResourceBackingView(this, true);",
  ) && !collector.includes("stream[_resourceBacking]"),
  webResourceBackingViewRechecks: streams.includes(
    'ObjectDefineProperty(view, "rid", {',
  ) && streams.includes(
    "runReadableStreamUseGuard(stream);\n      const current = unrefable",
  ),
  netReadableCarriesNativeProtectedPeer: netIo.includes(
    "pub fn protected_inspector_peer(&self) -> Option<SocketAddr>",
  ) && netOps.includes(
    "let protected_network_peer = resource",
  ) && net.includes(
    "#protectedNetworkPeer = null;",
  ) && net.includes(
    "lazyStreams().setReadableStreamUseGuard(readable, () => {",
  ) && net.indexOf(
        "lazyStreams().setReadableStreamUseGuard(readable, () => {",
      ) < net.indexOf("this.#readable = readable;"),
};

console.log(JSON.stringify(Object.fromEntries(
  Object.entries(evidence).map(([name, value]) => [
    name,
    value ? "EVIDENCED" : "MISSING",
  ]),
)));

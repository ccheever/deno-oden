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
    "setReadableUseGuard(dest, sourceGuard);",
  ) && ordered(
    nodePipe,
    "setReadableUseGuard(dest, sourceGuard);",
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
};

console.log(JSON.stringify(Object.fromEntries(
  Object.entries(evidence).map(([name, value]) => [
    name,
    value ? "EVIDENCED" : "MISSING",
  ]),
)));

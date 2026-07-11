import inspector from "node:inspector";
import net from "node:net";
import { createRequire } from "node:module";
import { Readable } from "node:stream";

const port = Number(Deno.args[0]);
const wsUrl = inspector.url();
if (!wsUrl) throw new Error("startup inspector URL missing");
const httpUrl = `http://127.0.0.1:${port}/json/list`;
const dnsHttpUrl = `http://localhost:${port}/json/list`;
const dnsWsUrl = wsUrl.replace("127.0.0.1", "localhost");
const require = createRequire(import.meta.url);
const endpointProbe = require("endpoint-denied");
const allowedEndpointProbe = require("endpoint-allowed");

function bounded(promise, label, milliseconds = 1_000) {
  let timeoutId;
  const timeout = new Promise((_, reject) => {
    timeoutId = setTimeout(
      () => reject(new Error(`${label} timed out`)),
      milliseconds,
    );
  });
  return Promise.race([promise, timeout]).finally(() =>
    clearTimeout(timeoutId)
  );
}

const kNodeWebStreamsState = Symbol.for("nodejs.webstreams.kState");

function readableReflection(body) {
  const streamState = body[kNodeWebStreamsState];
  const controller = streamState.controller;
  const controllerState = controller[kNodeWebStreamsState];
  return {
    controller,
    controllerState,
    queue: controllerState.queue,
    streamState,
  };
}

function queueMethodsFor(queue) {
  const prototype = Object.getPrototypeOf(queue);
  return {
    dequeue: prototype.dequeue,
    dequeueNode: prototype.dequeueNode,
    enqueue: prototype.enqueue,
    peek: prototype.peek,
    size: Object.getOwnPropertyDescriptor(prototype, "size").get,
  };
}

function describedSymbol(object, description) {
  let current = object;
  while (current !== null) {
    const symbol = Reflect.ownKeys(current).find((key) =>
      typeof key === "symbol" && key.description === description
    );
    if (symbol !== undefined) return symbol;
    current = Object.getPrototypeOf(current);
  }
  throw new Error(`missing ${description} symbol`);
}

function ordinaryQueue() {
  const stream = new ReadableStream({
    start(controller) {
      controller.enqueue("ordinary-first");
    },
  });
  return readableReflection(stream).queue;
}

function pendingRequestFixtures(queueMethods) {
  const defaultStream = new ReadableStream();
  const defaultReader = defaultStream.getReader();
  const defaultPromise = defaultReader.read();
  const defaultRequest = Reflect.apply(
    queueMethods.peek,
    defaultReader[kNodeWebStreamsState].readRequests,
    [],
  );

  const iteratorStream = new ReadableStream();
  const iterator = iteratorStream.values();
  const iteratorPromise = iterator.next();
  const iteratorReaderSymbol = Reflect.ownKeys(iterator).find((key) =>
    typeof key === "symbol" && key.description === "[[reader]]"
  );
  const iteratorReader = iterator[iteratorReaderSymbol];
  const iteratorRequest = Reflect.apply(
    queueMethods.peek,
    iteratorReader[kNodeWebStreamsState].readRequests,
    [],
  );

  const byobStream = new ReadableStream({
    type: "bytes",
  });
  const byobReader = byobStream.getReader({ mode: "byob" });
  const byobPromise = byobReader.read(new Uint8Array(8));
  const byobRequest = Reflect.apply(
    queueMethods.peek,
    byobReader[kNodeWebStreamsState].readIntoRequests,
    [],
  );

  return {
    cleanup() {
      Promise.allSettled([
        defaultReader.cancel(),
        iterator.return(),
        byobReader.cancel(),
        defaultPromise,
        iteratorPromise,
        byobPromise,
      ]);
      try {
        defaultReader.releaseLock();
      } catch {
        // Cleanup is best effort after closing the ordinary controls.
      }
      try {
        byobReader.releaseLock();
      } catch {
        // Cleanup is best effort after closing the ordinary controls.
      }
    },
    requests: {
      byob: byobRequest,
      default: defaultRequest,
      iterator: iteratorRequest,
    },
  };
}

async function openNodeInspectorResponse() {
  const socket = await openNodeInspectorSocket();
  await bounded(
    new Promise((resolve, reject) => {
      socket.write(
        "GET /json/list HTTP/1.1\r\nHost: localhost\r\n\r\n",
        (error) => error ? reject(error) : resolve(),
      );
    }),
    "Node inspector request",
  );
  return socket;
}

async function openNodeInspectorSocket() {
  const socket = net.connect(port, "localhost");
  const connected = new Promise((resolve, reject) => {
    const onConnect = () => {
      socket.removeListener("error", onError);
      resolve(socket);
    };
    const onError = (error) => {
      socket.removeListener("connect", onConnect);
      reject(error);
    };
    socket.once("connect", onConnect);
    socket.once("error", onError);
  });
  try {
    return await bounded(connected, "Node inspector connect");
  } catch (error) {
    socket.destroy();
    throw error;
  }
}

async function closeWebSocket(socket) {
  if (socket.readyState === WebSocket.CLOSED) return;
  let onClose;
  const closed = new Promise((resolve) => {
    onClose = resolve;
    socket.addEventListener("close", onClose, { once: true });
  });
  socket.close();
  try {
    await bounded(closed, "WebSocket close", 250);
  } catch {
    socket.removeEventListener("close", onClose);
  }
}

async function probeWebSocketSend(url, data, verifyRootRestoration = false) {
  return await new Promise((resolve, reject) => {
    const socket = new WebSocket(url);
    let settled = false;
    const onOpenedError = () => {};
    const finish = async (outcome, isError) => {
      if (settled) return;
      settled = true;
      clearTimeout(timeoutId);
      socket.removeEventListener("error", onOpenError);
      socket.removeEventListener("error", onOpenedError);
      await closeWebSocket(socket);
      if (isError) reject(outcome);
      else resolve(outcome);
    };
    const onOpenError = () => {
      finish(new Error("root websocket failed"), true);
    };
    socket.addEventListener("error", onOpenError, { once: true });
    socket.addEventListener("open", async () => {
      socket.removeEventListener("error", onOpenError);
      socket.addEventListener("error", onOpenedError);
      const packageResult = endpointProbe.websocketSend(socket, data);
      let rootResult;
      if (verifyRootRestoration) {
        try {
          socket.send(JSON.stringify({ id: 99, method: "Runtime.enable" }));
          rootResult = "ALLOWED";
        } catch {
          rootResult = "BROKEN";
        }
      }
      await finish({ packageResult, rootResult }, false);
    }, { once: true });
    const timeoutId = setTimeout(
      () => finish(new Error("WebSocket open timed out"), true),
      1_000,
    );
  });
}

async function probeClassicWebSocketListener(url) {
  return await new Promise((resolve, reject) => {
    const socket = new WebSocket(url);
    let settled = false;
    const finish = async (outcome, isError) => {
      if (settled) return;
      settled = true;
      clearTimeout(timeoutId);
      socket.removeEventListener("error", onOpenError);
      await closeWebSocket(socket);
      if (isError) reject(outcome);
      else resolve(outcome);
    };
    const onOpenError = () => {
      finish(new Error("root websocket failed"), true);
    };
    socket.addEventListener("error", onOpenError, { once: true });
    socket.addEventListener("open", async () => {
      socket.removeEventListener("error", onOpenError);
      const observation = endpointProbe.classicWebSocketListener(socket);
      socket.send(JSON.stringify({
        id: 42,
        method: "Runtime.evaluate",
        params: { expression: "'protected-inspector-byte'" },
      }));
      await finish(await observation, false);
    }, { once: true });
    const timeoutId = setTimeout(
      () => finish(new Error("classic WebSocket probe timed out"), true),
      2_000,
    );
  });
}

const denoConn = await Deno.connect({ hostname: "127.0.0.1", port });
const rootResponse = await fetch(httpUrl);
const rootDnsResponse = await fetch(dnsHttpUrl);
const readerResponse = await fetch(httpUrl);
const getReaderResponse = await fetch(httpUrl);
const byobResponse = await fetch(httpUrl);
const cloneResponse = await fetch(httpUrl);
const teeResponse = await fetch(httpUrl);
const iteratorResponse = await fetch(httpUrl);
const valuesResponse = await fetch(httpUrl);
const pipeToResponse = await fetch(httpUrl);
const pipeThroughResponse = await fetch(httpUrl);
const transferResponse = await fetch(httpUrl);
const webToNodeResponse = await fetch(httpUrl);
const reflectedQueueResponse = await fetch(httpUrl);
const retainedStateResponse = await fetch(httpUrl);
const poisonedDefaultResponse = await fetch(httpUrl);
const poisonedIteratorResponse = await fetch(httpUrl);
const poisonedBYOBResponse = await fetch(httpUrl);
const cleanupCancelResponse = await fetch(httpUrl);
const cleanupErrorResponse = await fetch(httpUrl);
const cleanupReleaseResponse = await fetch(httpUrl);
const packageSizeResponse = await fetch(httpUrl);
const rootSizeResponse = await fetch(httpUrl);
const backingResponse = await fetch(httpUrl);
const webToNodeStream = Readable.fromWeb(webToNodeResponse.body);

const backingDenoConn = await Deno.connect({ hostname: "127.0.0.1", port });
await backingDenoConn.write(
  new TextEncoder().encode(
    "GET /json/list HTTP/1.1\r\nHost: localhost\r\n\r\n",
  ),
);
const protectedConnStream = backingDenoConn.readable;
const fetchBackingSymbol = describedSymbol(
  backingResponse.body,
  "[[resourceBacking]]",
);
const connBackingSymbol = describedSymbol(
  protectedConnStream,
  "[[resourceBackingUnrefable]]",
);
const retainedFetchBacking = backingResponse.body[fetchBackingSymbol];
const retainedConnBacking = protectedConnStream[connBackingSymbol];
const protectedConnRid = retainedConnBacking.rid;

const cleanupCloseConn = await Deno.connect({
  hostname: "127.0.0.1",
  port,
});
const cleanupCloseController = readableReflection(
  cleanupCloseConn.readable,
).controller;

const ordinaryListener = Deno.listen({ hostname: "127.0.0.1", port: 0 });
const ordinaryAccept = ordinaryListener.accept();
const ordinaryClientConn = await Deno.connect(ordinaryListener.addr);
const ordinaryServerConn = await ordinaryAccept;
ordinaryListener.close();
const ordinaryConnStream = ordinaryClientConn.readable;
const ordinaryConnBackingSymbol = describedSymbol(
  ordinaryConnStream,
  "[[resourceBackingUnrefable]]",
);

const reflectedQueueState = readableReflection(reflectedQueueResponse.body);
const cleanupErrorController =
  readableReflection(cleanupErrorResponse.body).controller;
const cleanupReader = cleanupReleaseResponse.body.getReader();
const ordinaryReflectedQueue = ordinaryQueue();
const queueMethods = queueMethodsFor(ordinaryReflectedQueue);
const pendingRequests = pendingRequestFixtures(queueMethods);
let requestPrototypeProof;
try {
  const poisonStatus = endpointProbe.poisonRequestPrototypes(
    pendingRequests.requests,
  );
  const poisonedDefaultReader = poisonedDefaultResponse.body.getReader();
  const poisonedIterator = poisonedIteratorResponse.body.values();
  const poisonedBYOBReader = poisonedBYOBResponse.body.getReader({
    mode: "byob",
  });
  const [defaultRead, iteratorRead, byobRead] = await Promise.all([
    poisonedDefaultReader.read(),
    poisonedIterator.next(),
    poisonedBYOBReader.read(new Uint8Array(4096)),
  ]);
  const leakOutcome = endpointProbe.requestPrototypeLeakOutcome();
  requestPrototypeProof = {
    byob: poisonStatus === "POISONED" && leakOutcome.byob === "CLOSED" &&
        !byobRead.done && byobRead.value instanceof Uint8Array
      ? "CLOSED"
      : "BROKEN",
    default: poisonStatus === "POISONED" &&
        leakOutcome.default === "CLOSED" && !defaultRead.done &&
        defaultRead.value instanceof Uint8Array
      ? "CLOSED"
      : "BROKEN",
    iterator: poisonStatus === "POISONED" &&
        leakOutcome.iterator === "CLOSED" && !iteratorRead.done &&
        iteratorRead.value instanceof Uint8Array
      ? "CLOSED"
      : "BROKEN",
  };
  poisonedDefaultReader.releaseLock();
  await poisonedIterator.return();
  poisonedBYOBReader.releaseLock();
} finally {
  endpointProbe.restoreRequestPrototypes();
  await pendingRequests.cleanup();
}

const packageSizeTransform = endpointProbe.makePackageSizeTransform();
const packageSizeOutput = packageSizeResponse.body.pipeThrough(
  packageSizeTransform,
);
await new Promise((resolve) => setTimeout(resolve, 0));
let packageSizeDelivery;
try {
  await new Response(packageSizeOutput).arrayBuffer();
  packageSizeDelivery = "ALLOWED";
} catch {
  packageSizeDelivery = "DENIED";
}
const packageSizeProof = packageSizeDelivery === "DENIED" &&
    endpointProbe.packageSizeCallbackOutcome() === "CLOSED"
  ? "CLOSED"
  : "BROKEN";

let rootSizeSawChunk = false;
const rootSizeTransform = new TransformStream(undefined, undefined, {
  highWaterMark: 1,
  size(chunk) {
    rootSizeSawChunk = chunk instanceof Uint8Array;
    return 1;
  },
});
const rootSizeOutput = rootSizeResponse.body.pipeThrough(rootSizeTransform);
await new Promise((resolve) => setTimeout(resolve, 0));
const rootSizeBytes = await new Response(rootSizeOutput).arrayBuffer();
const rootSizeProof = rootSizeSawChunk && rootSizeBytes.byteLength > 0
  ? "ALLOWED"
  : "BROKEN";

const retainedTransform = new TransformStream();
const retainedStreamState = retainedTransform.readable[kNodeWebStreamsState];
const retainedController = retainedStreamState.controller;
const retainedControllerState = retainedController[kNodeWebStreamsState];
const retainedQueue = retainedControllerState.queue;
const retainedControllerSymbol = describedSymbol(
  retainedTransform.readable,
  "[[controller]]",
);
const retainedQueueSymbol = describedSymbol(retainedController, "[[queue]]");
const decoyReflection = readableReflection(new ReadableStream());
retainedTransform.readable[retainedControllerSymbol] =
  decoyReflection.controller;
retainedController[retainedQueueSymbol] = decoyReflection.queue;
const preTransitionSlotReplacementArmed =
  retainedTransform.readable[retainedControllerSymbol] ===
    decoyReflection.controller &&
  retainedController[retainedQueueSymbol] === decoyReflection.queue;
Object.setPrototypeOf(retainedQueue, null);
const retainedOutput = retainedStateResponse.body.pipeThrough(
  retainedTransform,
);
const preTransitionSlotsRestored =
  retainedTransform.readable[retainedControllerSymbol] ===
    retainedController &&
  retainedController[retainedQueueSymbol] === retainedQueue;

const reflectedBYOBConn = await Deno.connect({
  hostname: "127.0.0.1",
  port,
});
const reflectedBYOBStream = reflectedBYOBConn.readable;
const reflectedBYOBReader = reflectedBYOBStream.getReader({
  mode: "byob",
});
const reflectedBYOBRead = reflectedBYOBReader.read(new Uint8Array(4096));
const reflectedBYOBController =
  reflectedBYOBStream[kNodeWebStreamsState].controller;
const reflectedBYOBRequest = reflectedBYOBController.byobRequest;
const byobViewSymbol = [
  ...Reflect.ownKeys(reflectedBYOBRequest),
  ...Reflect.ownKeys(Object.getPrototypeOf(reflectedBYOBRequest)),
].find((key) => typeof key === "symbol" && key.description === "[[view]]");

const readDenoConn = await Deno.connect({ hostname: "127.0.0.1", port });
await readDenoConn.write(
  new TextEncoder().encode(
    "GET /json/list HTTP/1.1\r\nHost: localhost\r\n\r\n",
  ),
);
const readNodeSocket = await openNodeInspectorResponse();
const iteratorNodeSocket = await openNodeInspectorResponse();
const pipeNodeSocket = await openNodeInspectorResponse();
const explicitIteratorNodeSocket = await openNodeInspectorResponse();
const fromNodeSocket = await openNodeInspectorResponse();
const wrapNodeSocket = await openNodeInspectorResponse();
const nodeToWebSocket = await openNodeInspectorResponse();
const nodeToWebStream = Readable.toWeb(nodeToWebSocket);
const denoReadableConn = await Deno.connect({ hostname: "127.0.0.1", port });
const readableStreamFromResponse = await fetch(httpUrl);
let responseReader;
let responseByobReader;
let responseIterator;
let explicitNodeIterator;
let fromNodeReadable;
let wrapNodeReadable;
let readableStreamFrom;
let readableStreamFromReader;

try {
  const allowedWebSockets = await allowedEndpointProbe(wsUrl);
  const result = await endpointProbe({
    dnsHttpUrl,
    dnsWsUrl,
    denoConn,
    httpUrl,
    readDenoConn,
    readNodeSocket,
    getReaderResponse,
    cloneResponse,
    teeResponse,
    valuesResponse,
    pipeToResponse,
    pipeThroughResponse,
    transferResponse,
    iteratorNodeSocket,
    pipeNodeSocket,
    nodeToWebStream,
    webToNodeStream,
    denoReadableStream: denoReadableConn.readable,
    protectedFetchBackingStream: backingResponse.body,
    protectedFetchBackingSymbol: fetchBackingSymbol,
    retainedFetchBacking,
    protectedConnBackingStream: protectedConnStream,
    protectedConnBackingSymbol: connBackingSymbol,
    retainedConnBacking,
    protectedConnRid,
    ordinaryConnBackingStream: ordinaryConnStream,
    ordinaryConnBackingSymbol,
    byobRequest: reflectedBYOBRequest,
    byobViewSymbol,
    cleanupCancelStream: cleanupCancelResponse.body,
    cleanupCloseController,
    cleanupErrorController,
    cleanupReader,
    ordinaryQueue: ordinaryReflectedQueue,
    queueMethods,
    reflectedQueue: reflectedQueueState.queue,
    retainedControllerState,
    retainedQueue,
    retainedStreamState,
    preTransitionSlotReplacementArmed,
    rootResponse,
    rootDnsResponse,
    wsUrl,
  });
  result.defaultReadRequestPrototypePoisoning = requestPrototypeProof.default;
  result.iteratorReadRequestPrototypePoisoning = requestPrototypeProof.iterator;
  result.byobReadRequestPrototypePoisoning = requestPrototypeProof.byob;
  result.packageReadableSizeCallback = packageSizeProof;
  result.rootReadableSizeCallback = rootSizeProof;
  responseReader = readerResponse.body.getReader();
  responseByobReader = byobResponse.body.getReader({ mode: "byob" });
  responseIterator = iteratorResponse.body.values();
  explicitNodeIterator = explicitIteratorNodeSocket.iterator();
  fromNodeReadable = Readable.from(fromNodeSocket);
  wrapNodeReadable = new Readable({ read() {} });
  wrapNodeReadable.wrap(wrapNodeSocket);
  readableStreamFrom = ReadableStream.from(readableStreamFromResponse.body);
  readableStreamFromReader = readableStreamFrom.getReader();
  Object.assign(
    result,
    await endpointProbe.derived({
      responseReader,
      responseByobReader,
      responseIterator,
      explicitNodeIterator,
      fromNodeReadable,
      wrapNodeReadable,
      readableStreamFromReader,
    }),
  );
  const restoredReaderResult = await responseReader.read();
  result.rootResponseReaderAfterPackage = !restoredReaderResult.done &&
      restoredReaderResult.value instanceof Uint8Array
    ? "ALLOWED"
    : "BROKEN";
  const reflectedQueueText = await reflectedQueueResponse.text();
  result.rootReflectedQueueAfterPackage = reflectedQueueText.includes(
      "webSocketDebuggerUrl",
    )
    ? "ALLOWED"
    : "BROKEN";
  const retainedOutputText = await new Response(retainedOutput).text();
  result.rootRetainedOutputAfterPackage = retainedOutputText.includes(
      "webSocketDebuggerUrl",
    )
    ? "ALLOWED"
    : "BROKEN";
  result.rootPreTransitionSlotsAfterPackage =
    preTransitionSlotReplacementArmed && preTransitionSlotsRestored &&
      retainedOutputText.includes("webSocketDebuggerUrl")
      ? "ALLOWED"
      : "BROKEN";
  await reflectedBYOBConn.write(
    new TextEncoder().encode(
      "GET /json/list HTTP/1.1\r\nHost: localhost\r\n\r\n",
    ),
  );
  const reflectedBYOBResult = await reflectedBYOBRead;
  result.rootBYOBRequestAfterPackage = !reflectedBYOBResult.done &&
      reflectedBYOBResult.value instanceof Uint8Array
    ? "ALLOWED"
    : "BROKEN";
  const backingResponseText = await backingResponse.text();
  const backingConnBuffer = new Uint8Array(8192);
  const backingConnBytes = await backingDenoConn.read(backingConnBuffer);
  result.rootResourceBackingsAfterPackage = (retainedFetchBacking === null ||
      typeof retainedFetchBacking.rid === "number") &&
      typeof retainedConnBacking.rid === "number" &&
      backingResponseText.includes("webSocketDebuggerUrl") &&
      backingConnBytes !== null && backingConnBytes > 0
    ? "ALLOWED"
    : "BROKEN";
  const text = await probeWebSocketSend(
    wsUrl,
    JSON.stringify({ id: 1, method: "Runtime.enable" }),
    true,
  );
  result.passedWebSocket = text.packageResult;
  result.rootWebSocketAfterPackage = text.rootResult;
  result.passedDnsWebSocket = (await probeWebSocketSend(
    dnsWsUrl,
    JSON.stringify({ id: 2, method: "Runtime.enable" }),
  )).packageResult;
  result.passedWebSocketBinary = (await probeWebSocketSend(
    wsUrl,
    new Uint8Array([1, 2, 3]),
  )).packageResult;
  result.passedWebSocketArrayBuffer = (await probeWebSocketSend(
    wsUrl,
    new Uint8Array([1, 2, 3]).buffer,
  )).packageResult;
  result.allowedWebSocketStreamText = allowedWebSockets.websocketStreamText;
  result.allowedWebSocketStreamBinary = allowedWebSockets.websocketStreamBinary;
  result.passedWebSocketStreamText = await allowedEndpointProbe.withOpenStream(
    wsUrl,
    endpointProbe.websocketStreamWrite,
    JSON.stringify({ id: 81, method: "Runtime.enable" }),
  );
  result.passedWebSocketStreamBinary = await allowedEndpointProbe
    .withOpenStream(
      wsUrl,
      endpointProbe.websocketStreamWrite,
      new Uint8Array([1, 2, 3]),
    );
  result.passedWebSocketStreamRead = await allowedEndpointProbe
    .withOpenStreamReader(
      wsUrl,
      endpointProbe.websocketStreamRead,
    );
  result.passedWebSocketPing = await allowedEndpointProbe.withOpenWebSocket(
    wsUrl,
    endpointProbe.websocketPing,
  );
  result.classicWebSocketListenerDelivery = await probeClassicWebSocketListener(
    dnsWsUrl,
  );
  const responseAfterClose = await fetch(dnsHttpUrl);
  inspector.close();
  result.passedResponseAfterClose = await endpointProbe.afterClose(
    responseAfterClose,
  );
  console.log(JSON.stringify(result));
} finally {
  try {
    responseReader?.releaseLock();
  } catch {
    // A guard regression may have disturbed or released the reader.
  }
  try {
    responseByobReader?.releaseLock();
  } catch {
    // A guard regression may have disturbed or released the reader.
  }
  try {
    reflectedBYOBReader.releaseLock();
  } catch {
    // The reflected request test may already have completed or errored.
  }
  try {
    reflectedBYOBConn.close();
  } catch {
    // The reflected BYOB read may already have closed the connection.
  }
  try {
    await responseIterator?.return();
  } catch {
    // The denied next() should not consume, but cleanup remains best effort.
  }
  try {
    await explicitNodeIterator?.return();
  } catch {
    // The denied next() should not consume, but cleanup remains best effort.
  }
  try {
    readableStreamFromReader?.releaseLock();
    await readableStreamFrom?.cancel();
  } catch {
    // A guard regression may have disturbed or released the derived stream.
  }
  fromNodeReadable?.destroy();
  wrapNodeReadable?.destroy();
  denoConn.close();
  readDenoConn.close();
  readNodeSocket.destroy();
  iteratorNodeSocket.destroy();
  pipeNodeSocket.destroy();
  explicitIteratorNodeSocket.destroy();
  fromNodeSocket.destroy();
  wrapNodeSocket.destroy();
  nodeToWebSocket.destroy();
  try {
    denoReadableConn.close();
  } catch {
    // The failed stream collector may already have canceled the connection.
  }
  try {
    backingDenoConn.close();
  } catch {
    // A backing-route regression may have consumed or closed the connection.
  }
  try {
    cleanupCloseConn.close();
  } catch {
    // Stream close does not need to close the shared native resource.
  }
  try {
    ordinaryClientConn.close();
  } catch {
    // Ordinary resource cleanup is best effort.
  }
  try {
    ordinaryServerConn.close();
  } catch {
    // Ordinary resource cleanup is best effort.
  }
  webToNodeStream.destroy();
}

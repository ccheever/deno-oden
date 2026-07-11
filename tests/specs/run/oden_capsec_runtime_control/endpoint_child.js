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
const webToNodeStream = Readable.fromWeb(webToNodeResponse.body);

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
    rootResponse,
    rootDnsResponse,
    wsUrl,
  });
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
  webToNodeStream.destroy();
}

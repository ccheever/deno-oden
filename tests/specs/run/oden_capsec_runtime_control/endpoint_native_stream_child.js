import inspector from "node:inspector";
import { Buffer } from "node:buffer";
import net from "node:net";
import { createRequire } from "node:module";

const port = Number(Deno.args[0]);
const require = createRequire(import.meta.url);
const probe = require("native-stream-denied");
const { HTTPParser } = process.binding("http_parser");
const { UDP } = process.binding("udp_wrap");

function probeUdpOpen(socket) {
  const protectedHandle = socket._handle;
  const udp = new UDP();
  const result = udp.open(protectedHandle.fd);
  udp.close();
  return {
    result,
    unchanged: socket._handle === protectedHandle &&
      typeof protectedHandle.protectedInspectorPeer() === "string",
  };
}

function attachParser(socket) {
  const parser = new HTTPParser();
  parser.initialize(HTTPParser.RESPONSE, undefined, 0, 0);
  const parserProbe = probe.makeParserProbe();
  const callbacks = parserProbe.callbacks;
  parser[HTTPParser.kOnMessageBegin] = callbacks.messageBegin;
  parser[HTTPParser.kOnHeaders] = callbacks.headers;
  parser[HTTPParser.kOnHeadersComplete] = callbacks.headersComplete;
  parser[HTTPParser.kOnBody] = callbacks.body;
  parser[HTTPParser.kOnMessageComplete] = callbacks.messageComplete;
  parser[HTTPParser.kOnExecute] = callbacks.execute;
  const accepted = parser.consume(socket._handle);
  return {
    completed: parserProbe.completed,
    snapshot() {
      return { accepted, ...parserProbe.snapshot() };
    },
    restore() {
      parser.unconsume();
      parser.close();
    },
  };
}

function bounded(promise, label, milliseconds = 2_000) {
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

function connectPaused(targetPort) {
  const socket = new net.Socket();
  socket.pause();
  const connected = new Promise((resolve, reject) => {
    const onConnect = () => {
      socket.removeListener("error", onError);
      resolve();
    };
    const onError = (error) => {
      socket.removeListener("connect", onConnect);
      reject(error);
    };
    socket.once("connect", onConnect);
    socket.once("error", onError);
  });
  socket.connect(targetPort, "127.0.0.1");
  return { socket, connected };
}

async function writeSocket(socket, text) {
  await bounded(
    new Promise((resolve, reject) => {
      const midpoint = Math.floor(text.length / 2);
      socket.cork();
      socket.write(text.slice(0, midpoint));
      socket.write(
        text.slice(midpoint),
        (error) => error ? reject(error) : resolve(),
      );
      socket.uncork();
    }),
    "socket write",
  );
}

async function protectedControl() {
  const { socket, connected } = connectPaused(port);
  const pendingOwner = probe.retargetPendingOwner(socket);
  const preConnect = probe.preparePreConnect(socket);
  let replacement;
  let writePoison;
  let parser;
  try {
    await bounded(connected, "protected connect");
    // Keep the prototype detached through native tag discovery, then restore
    // ordinary handle methods before the root-owned write/read control.
    preConnect.restore();
    pendingOwner.restore();
    parser = attachParser(socket);
    const fdForIpc = probe.probeFdForIpc(socket);
    const reconnect = probe.probeReconnect(socket);
    const takeStream = probe.probeTakeStream(socket);
    const http2Consume = probe.probeHttp2Consume(socket);
    const tlsAttach = probe.probeTlsAttach(socket);
    const udpOpen = probeUdpOpen(socket);
    const synchronousRawOps = probe.probeSynchronousRawOps(socket);
    writePoison = probe.poisonProtectedWrites(socket);
    await writeSocket(
      socket,
      "GET /json/list HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
    );
    const writePoisonSnapshot = writePoison.snapshot();
    writePoison.restore();

    replacement = probe.replaceProtectedDelivery(socket);
    let response = "";
    const ended = new Promise((resolve, reject) => {
      socket.on("data", (chunk) => {
        response += chunk.toString();
      });
      socket.once("end", resolve);
      socket.once("error", reject);
    });
    socket.resume();
    await bounded(ended, "protected EOF");

    const beforeTag = preConnect.snapshot();
    const afterTag = replacement.snapshot();
    return {
      beforeTag,
      afterTag,
      bodyObserved: response.includes("webSocketDebuggerUrl"),
      eofObserved: true,
      fdForIpc,
      http2Consume,
      pendingOwner: pendingOwner.snapshot(),
      parser: parser.snapshot(),
      reconnect,
      takeStream,
      tlsAttach,
      udpOpen,
      synchronousRawOps,
      writePoison: writePoisonSnapshot,
    };
  } finally {
    replacement?.restore();
    writePoison?.restore();
    preConnect.restore();
    pendingOwner.restore();
    parser?.restore();
    socket.destroy();
  }
}

async function expectProtectedOnreadRefusal(options, label) {
  const socket = new net.Socket(options);
  const refused = new Promise((resolve) => {
    socket.once("error", resolve);
  });
  try {
    socket.connect(port, "127.0.0.1");
    const error = await bounded(refused, label);
    return error?.code ?? error?.name ?? "UNKNOWN";
  } finally {
    socket.destroy();
  }
}

async function protectedOnreadControls() {
  const packageOwned = probe.makeOnreadOption(0x64);
  const packageCode = await expectProtectedOnreadRefusal(
    packageOwned.options,
    "package onread refusal",
  );

  const rootBuffer = Buffer.alloc(4096, 0x75);
  let rootCallbackBytes = 0;
  let rootCallbackCount = 0;
  const rootCode = await expectProtectedOnreadRefusal(
    {
      onread: {
        buffer: rootBuffer,
        callback(nread) {
          rootCallbackCount++;
          rootCallbackBytes += Math.max(0, nread ?? 0);
        },
      },
    },
    "root onread refusal",
  );

  return {
    packageCode,
    packageSnapshot: packageOwned.snapshot(),
    rootBufferUnchanged: rootBuffer.every((byte) => byte === 0x75),
    rootCallbackBytes,
    rootCallbackCount,
    rootCode,
  };
}

async function protectedBufferedDestroyControl() {
  const { socket, connected } = connectPaused(port);
  let poison;
  try {
    await bounded(connected, "buffered destroy connect");
    poison = probe.poisonBufferedDestroy(socket);
    socket.cork();
    socket.write("buffered-destroy-control", poison.callback);
    socket.destroy();
    await bounded(poison.completed, "buffered destroy callback");
    return poison.snapshot();
  } finally {
    poison?.restore();
    socket.destroy();
  }
}

async function protectedHandleReplacementControl() {
  const socket = new net.Socket();
  socket.pause();
  const refused = new Promise((resolve) => socket.once("error", resolve));
  socket.connect(port, "127.0.0.1");
  const replacement = probe.prepareHandleReplacement(socket);
  try {
    const error = await bounded(refused, "handle replacement refusal");
    return {
      code: error?.code ?? error?.name ?? "UNKNOWN",
      ...replacement.snapshot(),
    };
  } finally {
    replacement.restore();
    socket.destroy();
  }
}

async function protectedSameScriptCallbackControl() {
  const { socket, connected } = connectPaused(port);
  let replacement;
  try {
    await bounded(connected, "same-script callback connect");
    replacement = probe.prepareSameScriptOnread(socket);
    const directResult = socket._handle.readStart(replacement.callback);
    socket.read(0);
    return { directResult, ...replacement.snapshot() };
  } finally {
    replacement?.restore();
    socket.destroy();
  }
}

async function ordinaryControl() {
  const listener = Deno.listen({ hostname: "127.0.0.1", port: 0 });
  const accepted = listener.accept();
  const { socket, connected } = connectPaused(listener.addr.port);
  try {
    const connection = await bounded(accepted, "ordinary accept");
    await bounded(connected, "ordinary connect");
    const ordinary = probe.prepareOrdinaryDelivery(socket);
    socket.resume();
    await connection.write(new TextEncoder().encode("ordinary-control"));
    connection.close();
    await bounded(ordinary.callback, "ordinary callback");
    return ordinary.snapshot();
  } finally {
    socket.destroy();
    listener.close();
  }
}

async function ordinaryParserControl() {
  const listener = Deno.listen({ hostname: "127.0.0.1", port: 0 });
  const accepted = listener.accept();
  const { socket, connected } = connectPaused(listener.addr.port);
  let parser;
  try {
    const connection = await bounded(accepted, "ordinary parser accept");
    await bounded(connected, "ordinary parser connect");
    parser = attachParser(socket);
    socket.resume();
    await connection.write(
      new TextEncoder().encode(
        "HTTP/1.1 200 OK\r\nContent-Length: 7\r\nConnection: close\r\n\r\ncontrol",
      ),
    );
    connection.close();
    await bounded(parser.completed, "ordinary parser callback");
    return parser.snapshot();
  } finally {
    parser?.restore();
    socket.destroy();
    listener.close();
  }
}

async function ordinaryWritableCompatibilityControl() {
  const socket = new net.Socket();
  let customWrites = 0;
  try {
    socket.cork();
    const completed = new Promise((resolve, reject) => {
      socket.write(
        "ordinary-buffered-write",
        (error) => error ? reject(error) : resolve(),
      );
    });
    const stateBuffer = socket._writableState.buffered;
    const publicBuffer = socket.writableBuffer;
    const bufferVisible = stateBuffer.length === 1 &&
      publicBuffer.length === 1 && stateBuffer[0] === publicBuffer[0];

    socket._writev = null;
    socket._write = function (_chunk, _encoding, callback) {
      customWrites++;
      callback();
    };
    socket.uncork();
    await bounded(completed, "ordinary customized write");
    return {
      bufferVisible,
      customWrites,
      remainingBuffered: socket._writableState.getBuffer().length,
    };
  } finally {
    socket.destroy();
  }
}

const protectedResult = await protectedControl();
const falseyHttpTokenResult = await bounded(
  probe.connectWithFalseyHttpToken(port),
  "falsey HTTP token connect",
);
const handleReplacementResult = await protectedHandleReplacementControl();
const sameScriptCallbackResult = await protectedSameScriptCallbackControl();
const protectedOnreadResult = await protectedOnreadControls();
const bufferedDestroyResult = await protectedBufferedDestroyControl();
const ordinaryResult = await ordinaryControl();
const ordinaryParserResult = await ordinaryParserControl();
const ordinaryWritableResult = await ordinaryWritableCompatibilityControl();
inspector.close();

const counters = protectedResult.afterTag.counters;
console.log(JSON.stringify({
  passedNodeNativeFalseyHttpToken: falseyHttpTokenResult,
  passedNodeNativeOnreadReplacement: counters.onread === 0
    ? "DENIED"
    : "BROKEN",
  passedNodeNativeOwnerReplacement:
    protectedResult.afterTag.ownerFound && counters.owner === 0
      ? "DENIED"
      : "BROKEN",
  passedNodeNativePushReplacement: counters.push === 0 ? "DENIED" : "BROKEN",
  passedNodeNativeEmitReplacement: counters.emit === 0 ? "DENIED" : "BROKEN",
  passedNodeNativeEofReentrantRead:
    counters.eofReadAttempts === 1 && counters.eofReadDenied === 1
      ? "DENIED"
      : "BROKEN",
  passedNodeNativeBufferFromReplacement: counters.bufferFrom === 0
    ? "DENIED"
    : "BROKEN",
  passedNodeNativeBufferedDestroy: bufferedDestroyResult.callbackCount === 1 &&
      bufferedDestroyResult.callbackDenied === 1 &&
      bufferedDestroyResult.callbackHadError &&
      bufferedDestroyResult.nextTickGadgetCalls === 0
    ? "DENIED"
    : "BROKEN",
  passedNodeNativeForgedOnreadSymbols:
    protectedResult.afterTag.symbolBufferFound &&
      counters.symbolBuffer === 0 &&
      protectedResult.afterTag.symbolBufferUnchanged
      ? "DENIED"
      : "BROKEN",
  passedNodeNativePrivateLifecycle: protectedResult.afterTag.destroyFrozen &&
      counters.stateDestroyed === 0 && counters.timeoutRefresh === 0 &&
      counters.read === 0 && counters.handleGet === 0 &&
      protectedResult.afterTag.terminalBytesWritten === 0
    ? "DENIED"
    : "BROKEN",
  passedNodeNativeParserConsume: protectedResult.parser.accepted === false &&
      protectedResult.parser.bodyBytes === 0 &&
      protectedResult.parser.execute === 0 &&
      protectedResult.parser.headersComplete === 0 &&
      protectedResult.parser.messageComplete === 0
    ? "DENIED"
    : "BROKEN",
  passedNodeNativeHttp2Consume: protectedResult.http2Consume.result === -13 &&
      protectedResult.http2Consume.unchanged
    ? "EACCES"
    : "BROKEN",
  passedNodeNativeFdForIpc: protectedResult.fdForIpc.result === -13 &&
      protectedResult.fdForIpc.unchanged
    ? "EACCES"
    : "BROKEN",
  passedNodeNativeTakeStream: protectedResult.takeStream.refused &&
      protectedResult.takeStream.unchanged
    ? "EACCES"
    : "BROKEN",
  passedNodeNativeReconnect: protectedResult.reconnect.result === -13 &&
      protectedResult.reconnect.unchanged
    ? "EACCES"
    : "BROKEN",
  passedNodeNativeTlsAttach: protectedResult.tlsAttach.refused &&
      protectedResult.tlsAttach.unchanged
    ? "EACCES"
    : "BROKEN",
  passedNodeNativeUdpOpen: protectedResult.udpOpen.result !== 0 &&
      protectedResult.udpOpen.unchanged
    ? "DENIED"
    : "BROKEN",
  passedNodeNativeRawOps:
    Object.values(protectedResult.synchronousRawOps).every((value) =>
        value === -13
      )
      ? "DENIED"
      : "BROKEN",
  passedNodeNativeWriteReplacement: protectedResult.writePoison.handleFound &&
      protectedResult.writePoison.writeWrapSurfaceBlocked &&
      protectedResult.writePoison.methodsFrozen &&
      protectedResult.writePoison.decoyWrites === 0 &&
      protectedResult.writePoison.requestChunkSets === 0 &&
      protectedResult.writePoison.requestErrorGets === 0 &&
      protectedResult.writePoison.bufferFromWrites === 0 &&
      protectedResult.bodyObserved
    ? "DENIED"
    : "BROKEN",
  passedNodeNativePreConnectUserBuffer:
    protectedResult.beforeTag.result === 0 &&
      protectedResult.beforeTag.unchanged
      ? "DENIED"
      : "BROKEN",
  passedNodeNativeProtectedMethodReplacement:
    protectedResult.beforeTag.prototypeDetached &&
      protectedResult.beforeTag.asyncContextMutated &&
      protectedResult.beforeTag.prototypePeerMutationRejected &&
      protectedResult.beforeTag.protectedInspectorPeerCalls === 0
      ? "DENIED"
      : "BROKEN",
  passedNodeNativeConnectGadgets:
    protectedResult.beforeTag.connectGadgetInstalled &&
      protectedResult.beforeTag.unrefGadgetInstalled &&
      protectedResult.bodyObserved
      ? "DENIED"
      : "BROKEN",
  passedNodeNativeHandleReplacement:
    handleReplacementResult.code === "EACCES" &&
      handleReplacementResult.replacementApplied
      ? "EACCES"
      : "BROKEN",
  passedNodeNativeSameScriptCallback:
    sameScriptCallbackResult.directResult === -13 &&
      sameScriptCallbackResult.timeoutUnchanged
      ? "DENIED"
      : "BROKEN",
  passedNodeNativePendingOwnerReplacement:
    protectedResult.pendingOwner.ownerFound &&
      protectedResult.pendingOwner.bufferUnchanged &&
      protectedResult.pendingOwner.callbackBytes === 0 &&
      protectedResult.pendingOwner.callbackCount === 0 &&
      protectedResult.pendingOwner.dataBytes === 0
      ? "DENIED"
      : "BROKEN",
  passedNodeNativePostConnectUserBuffer:
    protectedResult.afterTag.postConnectResult === -13 &&
      protectedResult.afterTag.postConnectUnchanged
      ? "EACCES"
      : "BROKEN",
  passedNodeNativePackageOnreadOption:
    protectedOnreadResult.packageCode === "EACCES" &&
      protectedOnreadResult.packageSnapshot.callbackBytes === 0 &&
      protectedOnreadResult.packageSnapshot.callbackCount === 0 &&
      protectedOnreadResult.packageSnapshot.unchanged
      ? "EACCES"
      : "BROKEN",
  rootNodeNativeOnreadOptionRefusal:
    protectedOnreadResult.rootCode === "EACCES" &&
      protectedOnreadResult.rootCallbackBytes === 0 &&
      protectedOnreadResult.rootCallbackCount === 0 &&
      protectedOnreadResult.rootBufferUnchanged
      ? "EACCES"
      : "BROKEN",
  rootNodeNativeRead: protectedResult.bodyObserved ? "ALLOWED" : "BROKEN",
  rootNodeNativeEof: protectedResult.eofObserved ? "ALLOWED" : "BROKEN",
  ordinaryNodeNativeOnread: ordinaryResult.callbackCount > 0
    ? "ALLOWED"
    : "BROKEN",
  ordinaryNodeNativeUserBuffer:
    ordinaryResult.result === 0 && ordinaryResult.changed
      ? "ALLOWED"
      : "BROKEN",
  ordinaryNodeNativeParserConsume: ordinaryParserResult.accepted === true &&
      ordinaryParserResult.bodyBytes === 7 &&
      ordinaryParserResult.execute > 0 &&
      ordinaryParserResult.headersComplete === 1 &&
      ordinaryParserResult.messageComplete === 1
    ? "ALLOWED"
    : "BROKEN",
  ordinaryNodeWritableCompatibility: ordinaryWritableResult.bufferVisible &&
      ordinaryWritableResult.customWrites === 1 &&
      ordinaryWritableResult.remainingBuffered === 0
    ? "ALLOWED"
    : "BROKEN",
}));

import inspector from "node:inspector";
import net from "node:net";
import { createRequire } from "node:module";
import { compose, PassThrough, pipeline, Readable } from "node:stream";

const port = Number(Deno.args[0]);
if (!inspector.url()) throw new Error("startup inspector URL missing");
const httpUrl = `http://127.0.0.1:${port}/json/list`;

const require = createRequire(import.meta.url);
const deniedProbe = require("endpoint-denied");
const sources = new Set();
const nodeStreams = new Set();
const webStreams = new Set();

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

function webQueue(readable) {
  const controllerKey = Reflect.ownKeys(readable).find((key) =>
    typeof key === "symbol" && key.description === "[[controller]]"
  );
  const controller = controllerKey === undefined
    ? undefined
    : readable[controllerKey];
  const queueKey = Reflect.ownKeys(controller ?? {}).find((key) =>
    typeof key === "symbol" && key.description === "[[queue]]"
  );
  return queueKey === undefined ? undefined : controller[queueKey];
}

async function waitForWebBuffer(readable, label) {
  await bounded(
    (async () => {
      while ((webQueue(readable)?.size ?? 0) === 0) {
        await new Promise((resolve) => setTimeout(resolve, 5));
      }
    })(),
    label,
  );
}

async function waitForNodeBuffer(readable, label) {
  await bounded(
    (async () => {
      while (readable.readableLength === 0) {
        await new Promise((resolve) => setTimeout(resolve, 5));
      }
    })(),
    label,
  );
}

async function protectedWebBuffer(label) {
  const response = await fetch(httpUrl);
  const output = response.body.pipeThrough(
    new TransformStream(undefined, undefined, { highWaterMark: 16 }),
  );
  webStreams.add(output);
  await waitForWebBuffer(output, label);
  return output;
}

async function protectedNodeBuffer(label) {
  const web = await protectedWebBuffer(`${label} Web source`);
  const node = Readable.fromWeb(web);
  nodeStreams.add(node);
  // Call the adapter's trusted _read directly so the Web guard executes while
  // the root frame is present, without scheduling Readable's unattributed
  // next-tick read path.
  node._read(0);
  await waitForNodeBuffer(node, label);
  for (let attempt = 0; !node._readableState.ended && attempt < 20; attempt++) {
    node._read(0);
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
  if (!node._readableState.ended) {
    throw new Error(`${label} did not reach buffered EOF`);
  }
  return node;
}

async function openInspectorSocket() {
  const socket = net.connect(port, "127.0.0.1");
  sources.add(socket);
  await bounded(
    new Promise((resolve, reject) => {
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
    }),
    "inspector connect",
  );
  return socket;
}

async function requestInspector(socket) {
  await bounded(
    new Promise((resolve, reject) => {
      socket.write(
        "GET /json/list HTTP/1.1\r\nHost: localhost\r\n\r\n",
        (error) => error ? reject(error) : resolve(),
      );
    }),
    "inspector request",
  );
}

function startNativeRead(socket) {
  socket._handle.reading = true;
  const error = socket._handle.readStart();
  if (error) throw new Error(`native readStart failed: ${error}`);
}

function rootRetentionAfterDenial(readable, before) {
  const unchanged = readable.readableLength === before;
  let chunk;
  try {
    chunk = readable.read();
  } catch {
    return "BROKEN";
  }
  return unchanged && chunk?.length > 0 ? "ALLOWED" : "BROKEN";
}

const result = {};
let completed = false;

try {
  console.error("phase:web-public");
  const publicWeb = await protectedWebBuffer("public Web read");
  result.webPublicRead = await deniedProbe.consumeBufferedWebReadable(
    publicWeb,
  );

  console.error("phase:web-reflection");
  const reflectedWeb = await protectedWebBuffer("reflected Web read");
  result.webDirectQueueReflection = await deniedProbe
    .inspectBufferedWebReadable(reflectedWeb);

  console.error("phase:node-public");
  const publicNode = await protectedNodeBuffer("public Node read");
  const publicNodeLength = publicNode.readableLength;
  result.nodePublicRead = deniedProbe.consumeBufferedNodeReadable(publicNode);
  result.rootAfterNodePublicDenial = rootRetentionAfterDenial(
    publicNode,
    publicNodeLength,
  );

  console.error("phase:node-reflection");
  const reflectedNode = await protectedNodeBuffer("reflected Node read");
  result.nodeDirectStateReflection = deniedProbe
    .inspectBufferedNodeReadable(reflectedNode);

  console.error("phase:prearmed-listener");
  const prearmedSource = await protectedNodeBuffer("prearmed Node source");
  const prearmedDestination = new PassThrough();
  nodeStreams.add(prearmedDestination);
  const prearmedOutcome = deniedProbe.awaitNodeData(prearmedDestination);
  prearmedSource.pipe(prearmedDestination);
  prearmedSource.read();
  prearmedSource.unpipe(prearmedDestination);
  prearmedSource.pause();
  prearmedDestination.pause();
  // Both resume callbacks were already queued by pipe/listener registration.
  // Keep them from initiating a second, unattributed protected read after the
  // synchronous delivery this exploit measures.
  prearmedSource._readableState.reading = true;
  prearmedDestination._readableState.reading = true;
  result.pipePrearmedDataListener = await bounded(
    prearmedOutcome,
    "prearmed data listener",
  );

  console.error("phase:borrowed-listener");
  const borrowedSource = await protectedNodeBuffer("borrowed listener source");
  const borrowedOutcome = deniedProbe.awaitNodeData(borrowedSource, "borrowed");
  borrowedSource.read();
  result.borrowedEventEmitterDataListener = await bounded(
    borrowedOutcome,
    "borrowed EventEmitter listener",
  );

  console.error("phase:onread");
  const onreadSocket = await openInspectorSocket();
  const onreadOutcome = deniedProbe.armNativeOnread(onreadSocket);
  startNativeRead(onreadSocket);
  await requestInspector(onreadSocket);
  result.nativeOnreadReplacement = await bounded(
    onreadOutcome,
    "native onread replacement",
  );

  console.error("phase:user-buffer");
  const userBufferSocket = await openInspectorSocket();
  const userBufferOutcome = deniedProbe.armNativeUserBuffer(userBufferSocket);
  startNativeRead(userBufferSocket);
  await requestInspector(userBufferSocket);
  result.nativeUseUserBuffer = await bounded(
    userBufferOutcome,
    "native user buffer",
  );

  console.error("phase:pipeline");
  const pipelineSource = await protectedWebBuffer("pipeline Web source");
  const pipelineDestination = new PassThrough();
  nodeStreams.add(pipelineDestination);
  pipelineDestination.on("error", () => {});
  let finishPipeline;
  const pipelineDone = new Promise((resolve) => {
    finishPipeline = resolve;
  });
  pipeline(pipelineSource, pipelineDestination, (error) => {
    finishPipeline(error === undefined ? "CLEAN" : "ROOT_REFUSED");
  });
  const pipelineReady = await Promise.race([
    waitForNodeBuffer(pipelineDestination, "pipeline Node destination").then(
      () => "BUFFERED",
      () => "TIMEOUT",
    ),
    pipelineDone,
  ]);
  result.pipelineWebToNodeDestination = pipelineReady === "BUFFERED"
    ? deniedProbe.consumeBufferedNodeReadable(pipelineDestination)
    : pipelineReady;

  console.error("phase:compose");
  const composeSource = await protectedWebBuffer("compose Web source");
  const composed = compose(composeSource, new PassThrough());
  nodeStreams.add(composed);
  let finishCompose;
  const composeFailed = new Promise((resolve) => {
    finishCompose = resolve;
  });
  composed.on("error", () => finishCompose("ROOT_REFUSED"));
  composed._read(0);
  const composeReady = await Promise.race([
    waitForNodeBuffer(composed, "compose Node destination").then(
      () => "BUFFERED",
      () => "TIMEOUT",
    ),
    composeFailed,
  ]);
  if (composeReady === "BUFFERED") {
    const composeLength = composed.readableLength;
    result.composeWebToNodeDestination = deniedProbe
      .consumeBufferedNodeReadable(composed);
    result.rootAfterComposeDenial = rootRetentionAfterDenial(
      composed,
      composeLength,
    );
  } else {
    result.composeWebToNodeDestination = composeReady;
    result.rootAfterComposeDenial = "NOT_APPLICABLE";
  }

  console.error("phase:done");
  console.log(JSON.stringify(result));
  completed = true;
} finally {
  for (const readable of nodeStreams) {
    try {
      readable.destroy();
    } catch {
      // Cleanup cannot grant authority and must not replace a harness result.
    }
  }
  for (const readable of webStreams) {
    try {
      readable.cancel().catch(() => {});
    } catch {
      // Adapters and pipelines may own the reader lock during cleanup.
    }
  }
  for (const source of sources) {
    try {
      source.destroy();
    } catch {
      // A native callback may already have closed its socket.
    }
  }
  try {
    inspector.close();
  } catch {
    // Closing remains best-effort after a native callback replacement.
  }
  // Replaced native callbacks can strand compatibility handles that no longer
  // participate in normal Socket teardown. The parent harness has already
  // captured every bounded outcome, so terminate this isolated child.
  if (completed) Deno.exit(0);
}

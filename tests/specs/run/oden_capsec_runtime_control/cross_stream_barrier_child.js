import inspector from "node:inspector";
import { createRequire } from "node:module";
import { Duplex, PassThrough, Readable, Writable } from "node:stream";

const port = Number(Deno.args[0]);
if (!inspector.url()) throw new Error("startup inspector URL missing");
const httpUrl = `http://127.0.0.1:${port}/json/list`;
const require = createRequire(import.meta.url);
const deniedProbe = require("endpoint-denied");
const nodeStreams = new Set();
const webStreams = new Set();

function bounded(promise, label, milliseconds = 3_000) {
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

async function pipeOutcome(promise, label) {
  try {
    await bounded(promise, label);
    return "CLEAN";
  } catch (error) {
    return error?.message === `${label} timed out` ? "HUNG" : "REFUSED";
  }
}

async function protectedWeb() {
  const response = await fetch(httpUrl);
  webStreams.add(response.body);
  return response.body;
}

async function protectedNode() {
  const readable = Readable.fromWeb(await protectedWeb());
  nodeStreams.add(readable);
  return readable;
}

function nodePipeOutcome(source, destination, label) {
  return bounded(
    new Promise((resolve) => {
      let settled = false;
      const finish = (outcome) => {
        if (settled) return;
        settled = true;
        resolve(outcome);
      };
      destination.once("error", () => finish("REFUSED"));
      destination.once("finish", () => finish("CLEAN"));
      source.once("error", () => finish("REFUSED"));
      try {
        source.pipe(destination);
        source.resume();
      } catch {
        finish("REFUSED");
      }
    }),
    label,
  ).catch(() => "HUNG");
}

const result = {};
let completed = false;

try {
  const sizeProbe = deniedProbe.makeWebWritableDeliveryProbe(true);
  webStreams.add(sizeProbe.writable);
  result.webWritableSizePipe = await pipeOutcome(
    (await protectedWeb()).pipeTo(sizeProbe.writable),
    "Web writable size pipe",
  );
  result.webWritableSizeCalls = sizeProbe.sizeCalls();
  result.webWritableSizeWriteCalls = sizeProbe.writeCalls();

  const writeProbe = deniedProbe.makeWebWritableDeliveryProbe(false);
  webStreams.add(writeProbe.writable);
  result.webWritableWritePipe = await pipeOutcome(
    (await protectedWeb()).pipeTo(writeProbe.writable),
    "Web writable write pipe",
  );
  result.webWritableWriteCalls = writeProbe.writeCalls();

  const transformProbe = deniedProbe.makeWebTransformDeliveryProbe();
  webStreams.add(transformProbe.stream.readable);
  webStreams.add(transformProbe.stream.writable);
  const transformed = (await protectedWeb()).pipeThrough(
    transformProbe.stream,
  );
  webStreams.add(transformed);
  const transformedReader = transformed.getReader();
  result.webTransformRead = await pipeOutcome(
    transformedReader.read(),
    "Web transform read",
  );
  transformedReader.releaseLock();
  result.webTransformCalls = transformProbe.transformCalls();

  let rootWriteStarted;
  const rootWriteStartedPromise = new Promise((resolve) => {
    rootWriteStarted = resolve;
  });
  let releaseRootWrite;
  const pendingRootWrite = new Promise((resolve) => {
    releaseRootWrite = resolve;
  });
  const rootWritable = new WritableStream({
    write() {
      rootWriteStarted();
      return pendingRootWrite;
    },
  });
  webStreams.add(rootWritable);
  const rootQueuePipe = (await protectedWeb()).pipeTo(rootWritable);
  await bounded(rootWriteStartedPromise, "root sink write start");
  result.webWritableQueueReflection = deniedProbe
    .inspectBufferedWebWritable(rootWritable);
  releaseRootWrite();
  result.webWritableRootSinkPipe = await pipeOutcome(
    rootQueuePipe,
    "root sink pipe",
  );

  const webAdapterProbe = deniedProbe.makeWebWritableDeliveryProbe(false);
  const nodeWebDestination = Writable.fromWeb(webAdapterProbe.writable);
  nodeStreams.add(nodeWebDestination);
  webStreams.add(webAdapterProbe.writable);
  result.webToNodeWritableAdapter = await nodePipeOutcome(
    await protectedNode(),
    nodeWebDestination,
    "Web-to-Node writable adapter",
  );
  result.webToNodeWritableAdapterCalls = webAdapterProbe.writeCalls();

  const nodeAdapterProbe = deniedProbe.makeNodeWritableDeliveryProbe();
  nodeStreams.add(nodeAdapterProbe.writable);
  const webNodeDestination = Writable.toWeb(nodeAdapterProbe.writable);
  webStreams.add(webNodeDestination);
  result.nodeToWebWritableAdapter = await pipeOutcome(
    (await protectedWeb()).pipeTo(webNodeDestination),
    "Node-to-Web writable adapter",
  );
  result.nodeToWebWritableAdapterCalls = nodeAdapterProbe.writeCalls();

  const readableToWebProbe = deniedProbe.makeWebWritableDeliveryProbe(false);
  const convertedWebReadable = Readable.toWeb(await protectedNode());
  webStreams.add(convertedWebReadable);
  webStreams.add(readableToWebProbe.writable);
  result.nodeReadableToWebSink = await pipeOutcome(
    convertedWebReadable.pipeTo(readableToWebProbe.writable),
    "Node readable to Web sink",
  );
  result.nodeReadableToWebSinkCalls = readableToWebProbe.writeCalls();

  const readableToNodeProbe = deniedProbe.makeNodeWritableDeliveryProbe();
  nodeStreams.add(readableToNodeProbe.writable);
  result.webReadableToNodeSink = await nodePipeOutcome(
    await protectedNode(),
    readableToNodeProbe.writable,
    "Web readable to Node sink",
  );
  result.webReadableToNodeSinkCalls = readableToNodeProbe.writeCalls();

  const lateWebTransform = new TransformStream();
  webStreams.add(lateWebTransform.readable);
  webStreams.add(lateWebTransform.writable);
  const lateWebProbe = deniedProbe.makeWebWritableDeliveryProbe(false);
  webStreams.add(lateWebProbe.writable);
  const lateWebEgress = lateWebTransform.readable.pipeTo(
    lateWebProbe.writable,
  );
  const lateWebIngress = pipeOutcome(
    (await protectedWeb()).pipeTo(lateWebTransform.writable),
    "preconstructed Web ingress",
  );
  result.preconstructedWebPipe = await pipeOutcome(
    lateWebEgress,
    "preconstructed Web egress",
  );
  result.preconstructedWebPipeCalls = lateWebProbe.writeCalls();
  await lateWebIngress;

  const lateNodeTransform = new TransformStream();
  webStreams.add(lateNodeTransform.readable);
  webStreams.add(lateNodeTransform.writable);
  const lateNodeReadable = Readable.fromWeb(lateNodeTransform.readable);
  nodeStreams.add(lateNodeReadable);
  const lateNodeProbe = deniedProbe.makeNodeWritableDeliveryProbe();
  nodeStreams.add(lateNodeProbe.writable);
  const lateNodeEgress = nodePipeOutcome(
    lateNodeReadable,
    lateNodeProbe.writable,
    "preconstructed Web-to-Node egress",
  );
  const lateNodeIngress = pipeOutcome(
    (await protectedWeb()).pipeTo(lateNodeTransform.writable),
    "preconstructed Web-to-Node ingress",
  );
  result.preconstructedWebToNodePipe = await lateNodeEgress;
  result.preconstructedWebToNodePipeCalls = lateNodeProbe.writeCalls();
  await lateNodeIngress;

  const lateNodeBridge = new PassThrough();
  nodeStreams.add(lateNodeBridge);
  // Exercise the public Duplex facade as well as the per-side adapters whose
  // guard propagation is checked by endpoint_route_evidence.js.
  const lateNodeWebPair = Duplex.toWeb(lateNodeBridge);
  const lateNodeWebReadable = lateNodeWebPair.readable;
  webStreams.add(lateNodeWebReadable);
  webStreams.add(lateNodeWebPair.writable);
  const lateNodeWebProbe = deniedProbe.makeWebWritableDeliveryProbe(false);
  webStreams.add(lateNodeWebProbe.writable);
  const lateNodeWebEgress = lateNodeWebReadable.pipeTo(
    lateNodeWebProbe.writable,
  );
  const lateNodeWebIngress = nodePipeOutcome(
    await protectedNode(),
    lateNodeBridge,
    "preconstructed Node-to-Web ingress",
  );
  result.preconstructedNodeToWebPipe = await pipeOutcome(
    lateNodeWebEgress,
    "preconstructed Node-to-Web egress",
  );
  result.preconstructedNodeToWebPipeCalls = lateNodeWebProbe.writeCalls();
  await lateNodeWebIngress;

  const lateTeeTransform = new TransformStream();
  webStreams.add(lateTeeTransform.readable);
  webStreams.add(lateTeeTransform.writable);
  const lateTeeBranches = lateTeeTransform.readable.tee();
  webStreams.add(lateTeeBranches[0]);
  webStreams.add(lateTeeBranches[1]);
  const lateTeeProbe = deniedProbe.makeWebWritableDeliveryProbe(false);
  webStreams.add(lateTeeProbe.writable);
  const lateTeeEgress = lateTeeBranches[0].pipeTo(lateTeeProbe.writable);
  const lateTeeIngress = pipeOutcome(
    (await protectedWeb()).pipeTo(lateTeeTransform.writable),
    "preconstructed Web tee ingress",
  );
  result.preconstructedWebTee = await pipeOutcome(
    lateTeeEgress,
    "preconstructed Web tee egress",
  );
  result.preconstructedWebTeeCalls = lateTeeProbe.writeCalls();
  await lateTeeBranches[1].cancel().catch(() => {});
  await lateTeeIngress;

  const lateFromTransform = new TransformStream();
  webStreams.add(lateFromTransform.readable);
  webStreams.add(lateFromTransform.writable);
  const lateIterator = lateFromTransform.readable.values();
  const lateDerived = ReadableStream.from(lateIterator);
  webStreams.add(lateDerived);
  const lateFromProbe = deniedProbe.makeWebWritableDeliveryProbe(false);
  webStreams.add(lateFromProbe.writable);
  const lateFromEgress = lateDerived.pipeTo(lateFromProbe.writable);
  const lateFromIngress = pipeOutcome(
    (await protectedWeb()).pipeTo(lateFromTransform.writable),
    "preconstructed ReadableStream.from ingress",
  );
  result.preconstructedReadableStreamFrom = await pipeOutcome(
    lateFromEgress,
    "preconstructed ReadableStream.from egress",
  );
  result.preconstructedReadableStreamFromCalls = lateFromProbe.writeCalls();
  await lateFromIngress;

  const latePairSource = new TransformStream();
  webStreams.add(latePairSource.readable);
  webStreams.add(latePairSource.writable);
  const latePairSink = new WritableStream();
  webStreams.add(latePairSink);
  let latePairController;
  const latePairReadable = new ReadableStream({
    start(controller) {
      latePairController = controller;
    },
  });
  webStreams.add(latePairReadable);
  const latePairOutput = latePairSource.readable.pipeThrough({
    readable: latePairReadable,
    writable: latePairSink,
  });
  const latePairProbe = deniedProbe.makeWebWritableDeliveryProbe(false);
  webStreams.add(latePairProbe.writable);
  const latePairEgress = latePairOutput.pipeTo(latePairProbe.writable);
  const latePairIngress = pipeOutcome(
    (await protectedWeb()).pipeTo(latePairSource.writable),
    "preconstructed Web pipeThrough ingress",
  );
  latePairController.enqueue(new Uint8Array([1]));
  latePairController.close();
  result.preconstructedWebPipeThrough = await pipeOutcome(
    latePairEgress,
    "preconstructed Web pipeThrough egress",
  );
  result.preconstructedWebPipeThroughCalls = latePairProbe.writeCalls();
  await latePairIngress;

  const flushProbe = deniedProbe.makeWebTransformFlushProbe();
  webStreams.add(flushProbe.stream.readable);
  webStreams.add(flushProbe.stream.writable);
  const flushIngress = (await protectedWeb()).pipeTo(
    flushProbe.stream.writable,
  );
  webStreams.add(flushProbe.stream.readable);
  const flushRead = new Response(flushProbe.stream.readable).arrayBuffer();
  result.webTransformFlushIngress = await pipeOutcome(
    flushIngress,
    "Web transform flush ingress",
  );
  result.webTransformFlush = await pipeOutcome(
    flushRead,
    "Web transform flush",
  );
  result.webTransformFlushCalls = flushProbe.flushCalls();

  const closeContextProbe = deniedProbe.makeWebWritableCloseContextProbe(
    httpUrl,
  );
  webStreams.add(closeContextProbe.writable);
  result.webWritableClose = await pipeOutcome(
    closeContextProbe.writable.close(),
    "Web writable close",
  );
  result.webWritableCloseCalls = closeContextProbe.closeCalls();
  result.webWritableCloseActor = closeContextProbe.closeOutcome();

  const ordinaryProbe = deniedProbe.makeWebWritableDeliveryProbe(false);
  const ordinary = new ReadableStream({
    start(controller) {
      controller.enqueue(new Uint8Array([1, 2, 3]));
      controller.close();
    },
  });
  result.ordinaryWebPipe = await pipeOutcome(
    ordinary.pipeTo(ordinaryProbe.writable),
    "ordinary Web pipe",
  );
  result.ordinaryWebWriteCalls = ordinaryProbe.writeCalls();

  console.log(JSON.stringify(result));
  completed = true;
} finally {
  for (const stream of nodeStreams) {
    try {
      stream.destroy();
    } catch {
      // Cleanup cannot grant authority or replace the measured outcome.
    }
  }
  for (const stream of webStreams) {
    try {
      if (typeof stream.cancel === "function") {
        stream.cancel().catch(() => {});
      } else if (typeof stream.abort === "function") {
        stream.abort().catch(() => {});
      }
    } catch {
      // A pipe or adapter may still own the stream lock.
    }
  }
  try {
    inspector.close();
  } catch {
    // Best effort after the isolated endpoint fixture.
  }
  if (completed) Deno.exit(0);
}

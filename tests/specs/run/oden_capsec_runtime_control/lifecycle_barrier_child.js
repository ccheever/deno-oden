import inspector from "node:inspector";
import { createRequire } from "node:module";
import { finished, Readable, Writable } from "node:stream";

const port = Number(Deno.args[0]);
if (!inspector.url()) throw new Error("startup inspector URL missing");
const httpUrl = `http://127.0.0.1:${port}/json/list`;
const require = createRequire(import.meta.url);
const denied = require("stream-lifecycle-denied");
const streams = new Set();
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

async function protectedWebBuffer(label) {
  const response = await fetch(httpUrl);
  const web = response.body.pipeThrough(
    new TransformStream(undefined, undefined, { highWaterMark: 16 }),
  );
  webStreams.add(web);
  await bounded(
    (async () => {
      while ((webQueue(web)?.size ?? 0) === 0) {
        await new Promise((resolve) => setTimeout(resolve, 5));
      }
    })(),
    `${label} Web buffer`,
  );
  return web;
}

async function protectedNode(label) {
  const stream = Readable.fromWeb(await protectedWebBuffer(label));
  streams.add(stream);
  stream._read(0);
  await bounded(
    (async () => {
      while (stream.readableLength === 0) {
        await new Promise((resolve) => setTimeout(resolve, 5));
      }
    })(),
    `${label} buffer`,
  );
  return stream;
}

function retained(stream, before) {
  return stream.readableLength === before ? "CLOSED" : "LEAK";
}

const result = {};
let completed = false;
try {
  const eosMethods = await protectedNode("eos methods");
  const eosMethodsBefore = eosMethods.readableLength;
  const restoreEosMethods = denied.poisonLifecycle(eosMethods);
  let cleanupEosMethods;
  try {
    cleanupEosMethods = finished(eosMethods, () => {});
    cleanupEosMethods();
  } finally {
    restoreEosMethods();
  }
  result.eosBoundLifecycle = retained(eosMethods, eosMethodsBefore);

  const eosState = await protectedNode("eos state");
  const eosStateBefore = eosState.readableLength;
  const restoreEosState = denied.poisonState(eosState);
  let cleanupEosState;
  try {
    cleanupEosState = finished(eosState, () => {});
    cleanupEosState();
  } finally {
    restoreEosState();
  }
  result.eosBoundStateGetter = retained(eosState, eosStateBefore);

  const protectedWeb = await protectedWebBuffer("web cleanup");
  const webCloser = Readable.fromWeb(protectedWeb);
  streams.add(webCloser);
  webCloser._read(0);
  let webCleanupCalls = 0;
  const cleanupWeb = finished(protectedWeb, () => webCleanupCalls++);
  cleanupWeb();
  await bounded(
    (async () => {
      for await (const _chunk of webCloser) {
        // Drain the protected source under the root consumer's provenance.
      }
    })(),
    "web cleanup close",
  );
  await new Promise((resolve) => setTimeout(resolve, 20));
  result.webCleanupCalls = webCleanupCalls;

  const onceStream = await protectedNode("once wrapper");
  const onceBefore = onceStream.readableLength;
  let onceRootCalls = 0;
  onceStream.once("oden-lifecycle", () => onceRootCalls++);
  onceStream.on("removeListener", () => {});
  const exactEmit = onceStream.emit;
  const restoreOnce = denied.poisonOnceLifecycle(onceStream);
  try {
    Reflect.apply(exactEmit, onceStream, ["oden-lifecycle"]);
  } finally {
    restoreOnce();
  }
  result.onceBoundRemove = retained(onceStream, onceBefore);
  result.onceRootCalls = onceRootCalls;

  const writableCarrier = await protectedNode("writable carrier");
  const writableOnly = new Writable({
    write(_chunk, _encoding, callback) {
      callback();
    },
  });
  writableCarrier.pipe(writableOnly, { end: false });
  writableCarrier.unpipe(writableOnly);
  writableCarrier.pause();
  const writableGadget = await protectedNode("writable listener gadget");
  const writableGadgetBefore = writableGadget.readableLength;
  writableOnly.on(
    "oden-lifecycle",
    denied.boundRead(writableGadget),
  );
  try {
    writableOnly.emit("oden-lifecycle");
  } catch {
    // The denied listener's attempted read is the expected closed result.
  }
  result.writableListenerDelivery = retained(
    writableGadget,
    writableGadgetBefore,
  );
  writableOnly.destroy();

  const destroyMethod = await protectedNode("destroy method");
  const destroyMethodBefore = destroyMethod.readableLength;
  destroyMethod.on("error", () => {});
  const restoreDestroyMethod = denied.poisonDestroy(destroyMethod);
  try {
    destroyMethod.destroy();
  } finally {
    restoreDestroyMethod();
  }
  result.destroyBoundImplementation = retained(
    destroyMethod,
    destroyMethodBefore,
  );

  const destroyState = await protectedNode("destroy state");
  const destroyStateBefore = destroyState.readableLength;
  destroyState.on("error", () => {});
  const restoreDestroyState = denied.poisonState(destroyState);
  try {
    destroyState.destroy();
  } finally {
    restoreDestroyState();
  }
  result.destroyBoundStateGetter = retained(destroyState, destroyStateBefore);

  console.log(JSON.stringify(result));
  completed = true;
} finally {
  for (const stream of streams) {
    try {
      stream.destroy();
    } catch {
      // Cleanup must not replace the fixture result.
    }
  }
  for (const stream of webStreams) {
    try {
      stream.cancel().catch(() => {});
    } catch {
      // An adapter may still own the reader lock.
    }
  }
  try {
    inspector.close();
  } catch {
    // Best effort after the isolated endpoint fixture.
  }
  if (completed) Deno.exit(0);
}

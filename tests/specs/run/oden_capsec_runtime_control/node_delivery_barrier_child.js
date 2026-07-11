import inspector from "node:inspector";
import { createRequire } from "node:module";
import { EventEmitter } from "node:events";
import { PassThrough, Readable, Transform, Writable } from "node:stream";

const port = Number(Deno.args[0]);
if (!inspector.url()) throw new Error("startup inspector URL missing");
const httpUrl = `http://127.0.0.1:${port}/json/list`;
const require = createRequire(import.meta.url);
const deniedProbe = require("endpoint-denied");
const streams = new Set();
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

function attempt(operation) {
  try {
    operation();
    return "ALLOWED";
  } catch {
    return "DENIED";
  }
}

async function probeOutcome(probe, label, milliseconds = 100) {
  return await Promise.race([
    probe.outcome,
    new Promise((resolve) =>
      setTimeout(() => resolve("NO_DELIVERY"), milliseconds)
    ),
  ]).catch((error) => {
    throw new Error(`${label}: ${error?.stack ?? error}`);
  });
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

async function protectedNodeBuffer(label) {
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

  const node = Readable.fromWeb(web);
  streams.add(node);
  node._read(0);
  await bounded(
    (async () => {
      while (node.readableLength === 0) {
        await new Promise((resolve) => setTimeout(resolve, 5));
      }
    })(),
    `${label} Node buffer`,
  );
  for (let attempt = 0; !node._readableState.ended && attempt < 20; attempt++) {
    node._read(0);
    await new Promise((resolve) => setTimeout(resolve, 5));
  }
  return node;
}

function rootReadOutcome(readable) {
  try {
    return readable.read() == null ? "EMPTY" : "ROOT_ALLOWED";
  } catch {
    return "BROKEN";
  }
}

const result = {};
let completed = false;
const phase = (name) => console.error(`phase:${name}`);

try {
  phase("direct");
  const direct = await protectedNodeBuffer("direct state");
  const directLength = direct.readableLength;
  result.directReadableState = deniedProbe.inspectBufferedNodeReadable(direct);
  result.directFromList = deniedProbe.directFromList(direct);
  result.directDenialRetainsBuffer = direct.readableLength === directLength
    ? rootReadOutcome(direct)
    : "BROKEN";

  phase("retained-readable");
  const retainedSource = await protectedNodeBuffer("retained readable");
  const retainedDestination = new PassThrough();
  streams.add(retainedDestination);
  const retainedReadableArray = retainedDestination._readableState.buffer;
  retainedSource.pipe(retainedDestination);
  retainedSource.read();
  retainedSource.unpipe(retainedDestination);
  retainedSource.pause();
  result.retainedReadableArray = deniedProbe.inspectRetainedArray(
    retainedReadableArray,
  );
  result.retainedReadableRoot = rootReadOutcome(retainedDestination);

  phase("listeners");
  const rootRegistered = await protectedNodeBuffer("root registered listener");
  const rootRegisteredProbe = deniedProbe.makeDeliveryProbe();
  const rootRegisteredLength = rootRegistered.readableLength;
  result.rootRegistersPackageListener = attempt(() =>
    rootRegistered.on("data", rootRegisteredProbe.callback)
  );
  result.rootRegisteredPackageCalls = rootRegisteredProbe.calls();
  result.rootRegisteredRetainsBuffer = rootRegistered.readableLength ===
      rootRegisteredLength
    ? "YES"
    : "NO";

  const borrowed = await protectedNodeBuffer("borrowed listener");
  const borrowedProbe = deniedProbe.makeDeliveryProbe();
  result.borrowedListener = attempt(() =>
    EventEmitter.prototype.addListener.call(
      borrowed,
      "data",
      borrowedProbe.callback,
    )
  );
  result.borrowedListenerCalls = borrowedProbe.calls();

  const directListener = await protectedNodeBuffer("direct listener");
  const directProbe = deniedProbe.makeDeliveryProbe();
  let forgedRootCalls = 0;
  const forgedRoot = () => forgedRootCalls++;
  directProbe.callback.listener = forgedRoot;
  directListener._events.data = directProbe.callback;
  result.directListener = attempt(() => directListener.read());
  result.directListenerCalls = directProbe.calls();
  result.forgedListenerRootCalls = forgedRootCalls;

  const transplanted = await protectedNodeBuffer("transplanted listener");
  const transplantedProbe = deniedProbe.makeDeliveryProbe();
  result.lifecycleRegisteredPackageListener = attempt(() =>
    transplanted.on("end", transplantedProbe.callback)
  );
  transplanted._events.data = transplantedProbe.callback;
  result.lifecycleToDataTransplant = attempt(() => transplanted.read());
  result.lifecycleToDataTransplantCalls = transplantedProbe.calls();

  const ordered = await protectedNodeBuffer("ordered listeners");
  const orderedProbe = deniedProbe.makeDeliveryProbe();
  let orderedRootCalls = 0;
  ordered._events.data = [() => orderedRootCalls++, orderedProbe.callback];
  result.completeSetPreflight = attempt(() => ordered.read());
  result.completeSetRootCalls = orderedRootCalls;
  result.completeSetPackageCalls = orderedProbe.calls();

  const switching = await protectedNodeBuffer("switching events");
  const switchingProbe = deniedProbe.makeDeliveryProbe();
  let switchingReads = 0;
  let switchingRootCalls = 0;
  const switchingRoot = () => switchingRootCalls++;
  switching._events = new Proxy(Object.create(null), {
    get(_target, key) {
      if (key === "data") {
        return ++switchingReads === 1 ? switchingRoot : switchingProbe.callback;
      }
      return undefined;
    },
  });
  result.switchingEvents = attempt(() => switching.read());
  result.switchingEventsReads = switchingReads;
  result.switchingEventsRootCalls = switchingRootCalls;
  result.switchingEventsPackageCalls = switchingProbe.calls();

  const eventsGetterTarget = await protectedNodeBuffer("events getter target");
  const eventsGetterGadget = await protectedNodeBuffer("events getter gadget");
  const eventsGetterGadgetBefore = eventsGetterGadget.readableLength;
  const eventsGetterProbe = deniedProbe.poisonEventsGetter(
    eventsGetterTarget,
    eventsGetterGadget,
  );
  try {
    result.boundEventsGetter = attempt(() => eventsGetterTarget.read());
    result.boundEventsGetterCalls = eventsGetterProbe.calls() > 0
      ? "CALLED"
      : "MISSING";
    result.boundEventsGetterRetainsGadget =
      eventsGetterGadget.readableLength ===
          eventsGetterGadgetBefore
        ? "YES"
        : "NO";
  } finally {
    eventsGetterProbe.restore();
  }

  const eventsProxyTarget = await protectedNodeBuffer("events proxy target");
  const eventsProxyGadget = await protectedNodeBuffer("events proxy gadget");
  const eventsProxyGadgetBefore = eventsProxyGadget.readableLength;
  const eventsProxyProbe = deniedProbe.poisonEventsProxy(
    eventsProxyTarget,
    eventsProxyGadget,
  );
  try {
    result.boundEventsProxy = attempt(() => eventsProxyTarget.read());
    result.boundEventsProxyCalls = eventsProxyProbe.calls() > 0
      ? "CALLED"
      : "MISSING";
    result.boundEventsProxyRetainsGadget = eventsProxyGadget.readableLength ===
        eventsProxyGadgetBefore
      ? "YES"
      : "NO";
  } finally {
    eventsProxyProbe.restore();
  }

  const listenerProxyTarget = await protectedNodeBuffer(
    "listener proxy target",
  );
  const listenerProxyGadget = await protectedNodeBuffer(
    "listener proxy gadget",
  );
  const listenerProxyGadgetBefore = listenerProxyGadget.readableLength;
  let listenerProxyRootCalls = 0;
  const listenerProxyProbe = deniedProbe.proxyListenerArray(
    [() => listenerProxyRootCalls++, () => listenerProxyRootCalls++],
    listenerProxyGadget,
  );
  listenerProxyTarget._events.data = listenerProxyProbe.listeners;
  result.boundListenerArrayProxy = attempt(() => listenerProxyTarget.read());
  result.boundListenerArrayProxyCalls = listenerProxyProbe.calls() > 0
    ? "CALLED"
    : "MISSING";
  result.boundListenerArrayProxyRootCalls = listenerProxyRootCalls;
  result.boundListenerArrayProxyRetainsGadget =
    listenerProxyGadget.readableLength === listenerProxyGadgetBefore
      ? "YES"
      : "NO";

  const scheduledSource = await protectedNodeBuffer("scheduled listener");
  const scheduledTarget = await protectedNodeBuffer("scheduled target");
  const scheduledProbe = deniedProbe.makeDeliveryProbe(
    "scheduled",
    scheduledTarget,
  );
  result.scheduledListener = attempt(() =>
    scheduledSource.on("data", scheduledProbe.callback)
  );
  result.scheduledListenerOutcome = await probeOutcome(
    scheduledProbe,
    "scheduled listener",
  );

  phase("rejections");
  const previousCapture = EventEmitter.captureRejections;
  EventEmitter.captureRejections = true;
  const rejected = await protectedNodeBuffer("rejected listener");
  EventEmitter.captureRejections = previousCapture;
  const rejectionProbe = deniedProbe.makeDeliveryProbe("rejection");
  let thenCalled = 0;
  rejected[EventEmitter.captureRejectionSymbol] = rejectionProbe.callback;
  rejected.on("data", () => ({
    then() {
      thenCalled++;
    },
  }));
  result.rejectionRecipient = attempt(() => rejected.read());
  result.rejectionHandlerCalls = rejectionProbe.calls();
  result.rejectionThenCalled = thenCalled;
  rejected.removeAllListeners("data");
  rejected.destroy();

  phase("rejections-bound");
  EventEmitter.captureRejections = true;
  const boundRejected = await protectedNodeBuffer("bound rejection handler");
  EventEmitter.captureRejections = previousCapture;
  const boundRejectionProbe = deniedProbe.makeDeliveryProbe("rejection");
  let boundListenerCalls = 0;
  boundRejected[EventEmitter.captureRejectionSymbol] = boundRejectionProbe
    .callback.bind(null);
  boundRejected.on("data", () => {
    boundListenerCalls++;
    return { then() {} };
  });
  result.boundRejectionRecipient = attempt(() => boundRejected.read());
  result.boundRejectionHandlerCalls = boundRejectionProbe.calls();
  result.boundRejectionListenerCalls = boundListenerCalls;
  boundRejected.removeAllListeners("data");
  boundRejected.destroy();

  phase("rejections-switching");
  EventEmitter.captureRejections = true;
  const switchingRejected = await protectedNodeBuffer(
    "switching rejection handler",
  );
  EventEmitter.captureRejections = previousCapture;
  const switchingRejectionProbe = deniedProbe.makeDeliveryProbe("rejection");
  let rejectionGetterReads = 0;
  let rootRejectionCalls = 0;
  const rootRejectionHandler = () => rootRejectionCalls++;
  Object.defineProperty(
    switchingRejected,
    EventEmitter.captureRejectionSymbol,
    {
      configurable: true,
      get() {
        return ++rejectionGetterReads === 1
          ? rootRejectionHandler
          : switchingRejectionProbe.callback;
      },
    },
  );
  switchingRejected.on("data", () => ({
    then(_resolve, reject) {
      reject(new Error("expected rejection"));
    },
  }));
  result.switchingRejectionRecipient = attempt(() => switchingRejected.read());
  await new Promise((resolve) => setTimeout(resolve, 0));
  result.switchingRejectionGetterReads = rejectionGetterReads;
  result.switchingRejectionRootCalls = rootRejectionCalls;
  result.switchingRejectionPackageCalls = switchingRejectionProbe.calls();

  const captureSwitch = await protectedNodeBuffer("switching capture flag");
  const captureSwitchProbe = deniedProbe.makeDeliveryProbe("rejection");
  const captureKey = Reflect.ownKeys(captureSwitch).find((key) =>
    typeof key === "symbol" && key.description === "kCapture"
  );
  if (captureKey === undefined) throw new Error("kCapture symbol missing");
  let captureReads = 0;
  let captureThenCalls = 0;
  Object.defineProperty(captureSwitch, captureKey, {
    configurable: true,
    get() {
      return ++captureReads !== 1;
    },
  });
  captureSwitch[EventEmitter.captureRejectionSymbol] =
    captureSwitchProbe.callback;
  captureSwitch.on("data", () => ({
    then() {
      captureThenCalls++;
    },
  }));
  result.switchingCaptureFlag = attempt(() => captureSwitch.read());
  result.switchingCaptureFlagReads = captureReads;
  result.switchingCaptureThenCalls = captureThenCalls;
  result.switchingCaptureHandlerCalls = captureSwitchProbe.calls();
  captureSwitch.removeAllListeners("data");
  captureSwitch.destroy();

  EventEmitter.captureRejections = true;
  const boundCapture = await protectedNodeBuffer("bound capture flag");
  EventEmitter.captureRejections = previousCapture;
  const boundCaptureGadget = await protectedNodeBuffer(
    "bound capture flag gadget",
  );
  const boundCaptureGadgetBefore = boundCaptureGadget.readableLength;
  const boundCaptureKey = Reflect.ownKeys(boundCapture).find((key) =>
    typeof key === "symbol" && key.description === "kCapture"
  );
  if (boundCaptureKey === undefined) throw new Error("bound kCapture missing");
  let boundCaptureRootCalls = 0;
  boundCapture.on("data", () => boundCaptureRootCalls++);
  const boundCaptureProbe = deniedProbe.poisonPropertyGetter(
    boundCapture,
    boundCaptureKey,
    true,
    boundCaptureGadget,
  );
  try {
    result.boundCaptureFlag = attempt(() => boundCapture.read());
    result.boundCaptureFlagCalls = boundCaptureProbe.calls() > 0
      ? "CALLED"
      : "MISSING";
    result.boundCaptureFlagRootCalls = boundCaptureRootCalls;
  result.boundCaptureFlagRetainsGadget = boundCaptureGadget.readableLength ===
        boundCaptureGadgetBefore
      ? "YES"
      : "NO";
  } finally {
    boundCaptureProbe.restore();
  }

  EventEmitter.captureRejections = true;
  const thenableTarget = await protectedNodeBuffer("thenable target");
  EventEmitter.captureRejections = previousCapture;
  const thenableGadget = await protectedNodeBuffer("thenable gadget");
  const thenableGadgetBefore = thenableGadget.readableLength;
  const thenableProbe = deniedProbe.makeThenableGetterProbe(thenableGadget);
  thenableTarget.on("oden-thenable", thenableProbe.listener);
  result.boundThenableGetter = attempt(() =>
    thenableTarget.emit("oden-thenable")
  );
  result.boundThenableGetterCalls = thenableProbe.calls();
  result.boundThenableGetterRetainsGadget = thenableGadget.readableLength ===
      thenableGadgetBefore
    ? "YES"
    : "NO";

  phase("rejections-done");
  phase("controls");
  const ordinary = new PassThrough();
  streams.add(ordinary);
  const ordinaryProbe = deniedProbe.makeDeliveryProbe();
  ordinary.on("data", ordinaryProbe.callback);
  ordinary.end(Buffer.from("ordinary"));
  const ordinaryOutcome = await probeOutcome(
    ordinaryProbe,
    "ordinary listener",
  );
  result.ordinaryPackageListener = ordinaryOutcome === "LEAK"
    ? "ALLOWED"
    : ordinaryOutcome;

  const rootControl = await protectedNodeBuffer("root listener control");
  let rootControlCalls = 0;
  rootControl.on("data", () => rootControlCalls++);
  result.protectedRootListener = attempt(() => rootControl.read());
  result.protectedRootListenerCalls = rootControlCalls;

  phase("writes");
  const writeReplacementSource = await protectedNodeBuffer(
    "write replacement",
  );
  const writeReplacementDestination = new PassThrough();
  streams.add(writeReplacementDestination);
  const writeReplacementProbe = deniedProbe.makeDeliveryProbe("write");
  writeReplacementDestination.write = writeReplacementProbe.callback;
  result.packageDestWrite = attempt(() =>
    writeReplacementSource.pipe(writeReplacementDestination)
  );
  result.packageDestWriteCalls = writeReplacementProbe.calls();

  const packageWriteSource = await protectedNodeBuffer("package write sink");
  const packageWriteProbe = deniedProbe.makeDeliveryProbe("write");
  const packageWriteDestination = new Writable({
    write: packageWriteProbe.callback,
  });
  packageWriteDestination.on("error", () => {});
  streams.add(packageWriteDestination);
  result.packageWriteImplementation = attempt(() =>
    packageWriteSource.pipe(packageWriteDestination)
  );
  result.packageWriteImplementationCalls = packageWriteProbe.calls();

  const replacedWriteSource = await protectedNodeBuffer("replaced write");
  let rootWriteCalls = 0;
  const replacedWriteDestination = new Writable({
    write(_chunk, _encoding, done) {
      rootWriteCalls++;
      done();
    },
  });
  replacedWriteDestination.on("error", () => {});
  streams.add(replacedWriteDestination);
  replacedWriteSource.pipe(replacedWriteDestination);
  const replacedWriteProbe = deniedProbe.makeDeliveryProbe("write");
  replacedWriteDestination._write = replacedWriteProbe.callback;
  replacedWriteSource.read();
  result.replacedWriteCalls = replacedWriteProbe.calls();
  result.replacedWriteRootCalls = rootWriteCalls;

  const replacedPublicWriteSource = await protectedNodeBuffer(
    "replaced public write",
  );
  let publicWriteRootCalls = 0;
  const replacedPublicWriteDestination = new Writable({
    write(_chunk, _encoding, done) {
      publicWriteRootCalls++;
      done();
    },
  });
  replacedPublicWriteDestination.on("error", () => {});
  streams.add(replacedPublicWriteDestination);
  replacedPublicWriteSource.pipe(replacedPublicWriteDestination);
  const replacedPublicWriteProbe = deniedProbe.makeDeliveryProbe("write");
  replacedPublicWriteDestination.write = replacedPublicWriteProbe.callback;
  replacedPublicWriteSource.read();
  result.replacedPublicWriteCalls = replacedPublicWriteProbe.calls();
  result.replacedPublicWriteRootCalls = publicWriteRootCalls;

  const defaultWritevSource = await protectedNodeBuffer("default writev");
  const defaultWritevDestination = new Writable();
  defaultWritevDestination.on("error", () => {});
  streams.add(defaultWritevDestination);
  defaultWritevSource.pipe(defaultWritevDestination);
  const defaultWritevProbe = deniedProbe.makeDeliveryProbe("write");
  defaultWritevDestination._writev = defaultWritevProbe.callback;
  result.defaultWritevReplacement = attempt(() => defaultWritevSource.read());
  result.defaultWritevReplacementCalls = defaultWritevProbe.calls();

  phase("state-identity");
  const writableStateSource = await protectedNodeBuffer("writable state");
  let stateRootWriteCalls = 0;
  const writableStateDestination = new Writable({
    write(_chunk, _encoding, done) {
      stateRootWriteCalls++;
      done();
    },
  });
  writableStateDestination.on("error", () => {});
  streams.add(writableStateDestination);
  writableStateSource.pipe(writableStateDestination);
  const originalWritableState = writableStateDestination._writableState;
  deniedProbe.replaceWritableState(writableStateDestination);
  const writableStateProbe = deniedProbe.makeDeliveryProbe("write");
  writableStateDestination._write = writableStateProbe.callback;
  writableStateSource.read();
  result.replacedWritableStateCalls = writableStateProbe.calls();
  result.replacedWritableStateRootCalls = stateRootWriteCalls;
  writableStateDestination._writableState = originalWritableState;

  const readableStateSource = await protectedNodeBuffer("readable state");
  const readableStateDestination = new PassThrough();
  streams.add(readableStateDestination);
  readableStateSource.pipe(readableStateDestination);
  const originalReadableState = readableStateDestination._readableState;
  const fakeReadableState = deniedProbe.replaceReadableState(
    readableStateDestination,
  );
  readableStateSource.read();
  result.replacedReadableStateFakeBuffer = deniedProbe.inspectRetainedArray(
    fakeReadableState.buffer,
  );
  result.replacedReadableStateRoot = rootReadOutcome(readableStateDestination);
  readableStateDestination._readableState = originalReadableState;

  phase("transform");
  const pushSource = await protectedNodeBuffer("push replacement");
  const pushDestination = new PassThrough();
  streams.add(pushDestination);
  pushSource.pipe(pushDestination);
  const pushProbe = deniedProbe.makeDeliveryProbe("write");
  pushDestination.push = pushProbe.callback;
  pushSource.read();
  result.replacedPushCalls = pushProbe.calls();
  result.replacedPushRoot = rootReadOutcome(pushDestination);

  const transformSource = await protectedNodeBuffer("transform replacement");
  let rootTransformCalls = 0;
  const transformDestination = new Transform({
    transform(chunk, _encoding, done) {
      rootTransformCalls++;
      done(null, chunk);
    },
  });
  streams.add(transformDestination);
  transformSource.pipe(transformDestination);
  const transformProbe = deniedProbe.makeDeliveryProbe("transform");
  transformDestination._transform = transformProbe.callback;
  transformSource.read();
  result.replacedTransformCalls = transformProbe.calls();
  result.replacedTransformRootCalls = rootTransformCalls;

  const packageTransformSource = await protectedNodeBuffer("package transform");
  const packageTransformProbe = deniedProbe.makeDeliveryProbe("transform");
  const packageTransformDestination = new Transform({
    transform: packageTransformProbe.callback,
  });
  packageTransformDestination.on("error", () => {});
  streams.add(packageTransformDestination);
  result.packageTransform = attempt(() =>
    packageTransformSource.pipe(packageTransformDestination)
  );
  result.packageTransformCalls = packageTransformProbe.calls();

  const gadgetSource = await protectedNodeBuffer("write gadget");
  const gadget = {
    on() {},
    once() {},
    emit() {},
    removeListener() {},
    write: Writable.prototype.write,
  };
  result.writablePrototypeGadget = attempt(() => gadgetSource.pipe(gadget));

  phase("writable-buffer");
  const retainedWritableSource = await protectedNodeBuffer("retained writable");
  let retainedSinkCalls = 0;
  const retainedWritable = new Writable({
    write(_chunk, _encoding, done) {
      retainedSinkCalls++;
      done();
    },
  });
  retainedWritable.on("error", () => {});
  retainedWritable.cork();
  retainedWritable.write(Buffer.from("ordinary queued"));
  const retainedWritableArray = retainedWritable._writableState.buffered;
  streams.add(retainedWritable);
  retainedWritableSource.pipe(retainedWritable);
  retainedWritableSource.read();
  result.retainedWritableArray = deniedProbe.inspectRetainedArray(
    retainedWritableArray,
  );
  result.directWritableState = deniedProbe.inspectWritableState(
    retainedWritable,
  );
  retainedWritable.destroy();
  await new Promise((resolve) => setTimeout(resolve, 0));
  result.destroyDoesNotFlush = retainedSinkCalls;

  const emptyEndSource = await protectedNodeBuffer("empty writable end");
  let emptyEndSinkCalls = 0;
  const emptyEndWritable = new Writable({
    autoDestroy: false,
    write(_chunk, _encoding, done) {
      emptyEndSinkCalls++;
      done();
    },
  });
  streams.add(emptyEndWritable);
  emptyEndSource.pause();
  emptyEndSource.pipe(emptyEndWritable);
  emptyEndSource.unpipe(emptyEndWritable);
  emptyEndSource.pause();
  result.packageNoChunkEndQueue = emptyEndWritable.writableLength === 0
    ? "ZERO"
    : "NONZERO";
  result.packageNoChunkEnd = deniedProbe.endWritable(emptyEndWritable);
  result.packageNoChunkEndSinkCalls = emptyEndSinkCalls;

  const queuedEndSource = await protectedNodeBuffer("queued writable end");
  let queuedEndSinkCalls = 0;
  const queuedEndWritable = new Writable({
    autoDestroy: false,
    write(_chunk, _encoding, done) {
      queuedEndSinkCalls++;
      done();
    },
  });
  queuedEndWritable.on("error", () => {});
  queuedEndWritable.cork();
  queuedEndWritable.write(Buffer.from("protected queued bytes"));
  streams.add(queuedEndWritable);
  queuedEndSource.pause();
  queuedEndSource.pipe(queuedEndWritable);
  queuedEndSource.unpipe(queuedEndWritable);
  queuedEndSource.pause();
  result.packageQueuedEndQueue = queuedEndWritable.writableLength > 0
    ? "NONZERO"
    : "ZERO";
  result.packageQueuedEnd = deniedProbe.endWritable(queuedEndWritable);
  result.packageQueuedEndSinkCalls = queuedEndSinkCalls;
  queuedEndWritable.destroy();
  await new Promise((resolve) => setTimeout(resolve, 0));
  result.packageQueuedEndSinkCallsAfterCleanup = queuedEndSinkCalls;

  phase("decoder");
  const decoderDestination = new PassThrough();
  decoderDestination.setEncoding("utf8");
  decoderDestination.push(Buffer.from([0xe2, 0x82]));
  const retainedDecoder = decoderDestination._readableState.decoder;
  const decoderSource = await protectedNodeBuffer("decoder attachment");
  streams.add(decoderDestination);
  decoderSource.pipe(decoderDestination);
  decoderSource.unpipe(decoderDestination);
  result.retainedDecoder = deniedProbe.inspectRetainedDecoder(retainedDecoder);
  result.directDecoder = deniedProbe.inspectReadableDecoder(decoderDestination);
  decoderDestination.push(Buffer.from([0xac]));
  result.privateDecoderRoot = decoderDestination.read() === "€"
    ? "ROOT_ALLOWED"
    : "BROKEN";

  phase("poison");
  const poisonedReadable = await protectedNodeBuffer("poisoned readable");
  const readablePoison = deniedProbe.poisonBufferAccessors();
  try {
    poisonedReadable.read();
  } finally {
    readablePoison.restore();
  }
  result.poisonedReadableBufferAccessors = readablePoison.outcome();

  const poisonAttachSource = await protectedNodeBuffer(
    "poisoned writable attach",
  );
  const poisonedWritable = new Writable({
    write(_chunk, _encoding, done) {
      done();
    },
  });
  poisonedWritable.on("error", () => {});
  streams.add(poisonedWritable);
  poisonAttachSource.pipe(poisonedWritable);
  poisonAttachSource.unpipe(poisonedWritable);
  const poisonedWritableChunk = Buffer.from("protected buffer");
  const writablePoison = deniedProbe.poisonBufferAccessors();
  try {
    poisonedWritable.write(poisonedWritableChunk);
  } finally {
    writablePoison.restore();
  }
  result.poisonedWritableBufferAccessors = writablePoison.outcome();

  console.log(JSON.stringify(result));
  completed = true;
} finally {
  EventEmitter.captureRejections = false;
  for (const stream of streams) {
    try {
      stream.destroy();
    } catch {
      // Cleanup must remain non-delivering and cannot replace fixture output.
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

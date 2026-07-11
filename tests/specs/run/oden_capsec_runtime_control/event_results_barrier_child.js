import inspector from "node:inspector";
import { EventEmitter, on as eventsOn, once as eventsOnce } from "node:events";
import { createRequire } from "node:module";
import { connect } from "node:net";
import { PassThrough } from "node:stream";

const port = Number(Deno.args[0]);
if (!inspector.url()) throw new Error("startup inspector URL missing");
const require = createRequire(import.meta.url);
const deniedProbe = require("endpoint-denied");
const streams = new Set();
let protectedTemplate;
let protectedTemplateReady;

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

function ensureProtectedTemplate() {
  if (protectedTemplate === undefined) {
    protectedTemplate = connect({ host: "127.0.0.1", port });
    streams.add(protectedTemplate);
    protectedTemplateReady = bounded(
      new Promise((resolve, reject) => {
        protectedTemplate.once("connect", resolve);
        protectedTemplate.once("error", reject);
      }),
      "protected template connect",
    );
  }
  return protectedTemplateReady;
}

function beginProtectedBuffer(label) {
  const node = new PassThrough();
  streams.add(node);
  const ready = (async () => {
    await ensureProtectedTemplate();
    protectedTemplate.pause();
    protectedTemplate.pipe(node, { end: false });
    protectedTemplate.unpipe(node);
    protectedTemplate.pause();
    node.push(Buffer.from(`protected:${label}`));
    return node;
  })();
  return { node, ready };
}

async function protectedBuffer(label) {
  return await beginProtectedBuffer(label).ready;
}

const result = {};
let completed = false;

try {
  const onceRoot = await protectedBuffer("events.once root");
  const onceRootPromise = eventsOnce(onceRoot, "data");
  onceRoot.read();
  const onceRootArgs = await bounded(onceRootPromise, "events.once root");
  result.eventsOnceRoot = onceRootArgs[0] == null ? "EMPTY" : "ROOT_ALLOWED";

  const oncePackageRegistration = await protectedBuffer(
    "events.once package registration",
  );
  result.eventsOncePackageRegistration = await bounded(
    deniedProbe.consumeRegisteredEventOnce(oncePackageRegistration),
    "events.once package registration",
  );
  result.eventsOncePackageRegistrationRoot =
    oncePackageRegistration.read() == null ? "EMPTY" : "ROOT_ALLOWED";

  const oncePassed = await protectedBuffer("events.once passage");
  const oncePassedPromise = eventsOnce(oncePassed, "data");
  result.eventsOncePromiseBrand = deniedProbe.inspectEventPromiseBrand(
    oncePassedPromise,
  );
  const oncePassedPackage = deniedProbe.consumeEventPromise(
    oncePassedPromise,
  );
  oncePassed.read();
  result.eventsOncePassedPromise = await bounded(
    oncePassedPackage,
    "events.once package passage",
  );
  result.eventsOncePromiseResolve = await bounded(
    deniedProbe.consumeResolvedEventPromise(oncePassedPromise),
    "events.once Promise.resolve passage",
  );
  result.eventsOncePromiseAll = await bounded(
    deniedProbe.consumeAllEventPromises(oncePassedPromise),
    "events.once Promise.all passage",
  );
  result.eventsOncePromiseRace = await bounded(
    deniedProbe.consumeRacedEventPromise(oncePassedPromise),
    "events.once Promise.race passage",
  );
  result.eventsOnceCapturedPromiseThen = await bounded(
    deniedProbe.consumeEventPromiseWithCapturedThen(oncePassedPromise),
    "events.once captured Promise.prototype.then passage",
  );
  const oncePassedRootArgs = await bounded(
    oncePassedPromise,
    "events.once retained root promise",
  );
  result.eventsOncePassedPromiseRoot = oncePassedRootArgs[0] == null
    ? "EMPTY"
    : "ROOT_ALLOWED";

  const onceCallback = await protectedBuffer("events.once callback");
  const onceCallbackPromise = eventsOnce(onceCallback, "data");
  const oncePackageCallback = onceCallbackPromise.then(
    deniedProbe.inspectEventArguments,
  );
  onceCallback.read();
  result.eventsOncePackageCallback = await bounded(
    oncePackageCallback,
    "events.once package callback",
  );

  const preprotectedSetup = beginProtectedBuffer(
    "events.once pre-protection",
  );
  preprotectedSetup.node.pause();
  const preprotectedPromise = eventsOnce(preprotectedSetup.node, "data");
  const preprotectedSource = await preprotectedSetup.ready;
  preprotectedSource.read();
  const preprotectedArgs = await bounded(
    preprotectedPromise,
    "events.once pre-protection delivery",
  );
  result.eventsOncePreProtection = preprotectedArgs[0] == null
    ? "EMPTY"
    : "ROOT_ALLOWED";

  const poisonedPreprotectedSetup = beginProtectedBuffer(
    "events.once poisoned pre-protection",
  );
  poisonedPreprotectedSetup.node.pause();
  const poisonedOnceRegistration = deniedProbe.poisonEventRegistrationMethods(
    poisonedPreprotectedSetup.node,
  );
  let poisonedPreprotectedPromise;
  let poisonedOnceCalls;
  try {
    poisonedPreprotectedPromise = eventsOnce(
      poisonedPreprotectedSetup.node,
      "data",
    );
    poisonedOnceCalls = poisonedOnceRegistration.calls();
  } finally {
    poisonedOnceRegistration.restore();
  }
  const poisonedPreprotectedSource = await poisonedPreprotectedSetup.ready;
  const poisonedOnceCleanup = deniedProbe.poisonEventRegistrationMethods(
    poisonedPreprotectedSource,
  );
  try {
    poisonedPreprotectedSource.read();
    const poisonedPreprotectedArgs = await bounded(
      poisonedPreprotectedPromise,
      "events.once poisoned pre-protection delivery",
    );
    result.eventsOncePoisonedPreProtection = poisonedPreprotectedArgs[0] == null
      ? "EMPTY"
      : "ROOT_ALLOWED";
    result.eventsOncePoisonedRegistrationCalls = poisonedOnceCalls +
      poisonedOnceCleanup.calls();
  } finally {
    poisonedOnceCleanup.restore();
  }

  const packagePreprotectedSetup = beginProtectedBuffer(
    "events.once package pre-protection",
  );
  packagePreprotectedSetup.node.pause();
  const packagePreprotectedPromise = deniedProbe.consumeRegisteredEventOnce(
    packagePreprotectedSetup.node,
  );
  const packagePreprotectedSource = await packagePreprotectedSetup.ready;
  packagePreprotectedSource.read();
  result.eventsOncePackagePreProtection = await bounded(
    packagePreprotectedPromise,
    "events.once package pre-protection delivery",
  );

  const replaySource = await protectedBuffer(
    "trusted listener registration replay",
  );
  const registrationReplayProbe = deniedProbe.makeRegistrationReplayProbe(
    replaySource,
  );
  result.trustedRegistrationProbeListener = deniedProbe.registerEventListener(
    replaySource,
    "newListener",
    registrationReplayProbe.callback,
  );
  const replayPromise = eventsOnce(replaySource, "data");
  replaySource.read();
  const replayArgs = await bounded(
    replayPromise,
    "trusted listener registration replay root delivery",
  );
  result.trustedRegistrationReplay = registrationReplayProbe.outcome();
  result.trustedRegistrationReplayRoot = replayArgs[0] == null
    ? "EMPTY"
    : "ROOT_ALLOWED";

  const trustedSource = await protectedBuffer("trusted listener source");
  const trustedTarget = await protectedBuffer("trusted listener target");
  const trustedTargetLength = trustedTarget.readableLength;
  const trustedPromise = eventsOnce(trustedSource, "data");
  trustedPromise.catch(() => {});
  const trustedListener = trustedSource._events.data;
  result.trustedListenerReregister = deniedProbe.registerEventListener(
    trustedTarget,
    "data",
    trustedListener,
  );
  trustedTarget._events.data = trustedListener;
  result.trustedListenerTransplant = attempt(() => trustedTarget.read());
  result.trustedListenerTransplantRetainsBuffer =
    trustedTarget.readableLength === trustedTargetLength ? "YES" : "NO";

  const iteratorRootSource = await protectedBuffer("events.on root");
  const iteratorRoot = eventsOn(iteratorRootSource, "data");
  iteratorRootSource.read();
  const iteratorRootResult = await bounded(
    iteratorRoot.next(),
    "events.on root delivery",
  );
  result.eventsOnRoot = iteratorRootResult.value?.[0] == null
    ? "EMPTY"
    : "ROOT_ALLOWED";
  result.eventsOnPassedResult = await bounded(
    deniedProbe.consumeEventIteratorResult(iteratorRootResult),
    "events.on package result passage",
  );
  result.eventsOnPassedResultGetter = await bounded(
    deniedProbe.consumeEventIteratorResultGetter(iteratorRootResult),
    "events.on package result getter passage",
  );
  result.eventsOnPassedResultRoot = iteratorRootResult.value?.[0] == null
    ? "EMPTY"
    : "ROOT_ALLOWED";
  await iteratorRoot.return();

  const iteratorPackageRegistration = await protectedBuffer(
    "events.on package registration",
  );
  result.eventsOnPackageRegistration = await bounded(
    deniedProbe.consumeRegisteredEventIterator(iteratorPackageRegistration),
    "events.on package registration",
  );
  result.eventsOnPackageRegistrationRoot =
    iteratorPackageRegistration.read() == null ? "EMPTY" : "ROOT_ALLOWED";

  const iteratorPassedSource = await protectedBuffer(
    "events.on iterator passage",
  );
  const iteratorPassed = eventsOn(iteratorPassedSource, "data");
  iteratorPassedSource.read();
  result.eventsOnPassedIterator = await bounded(
    deniedProbe.consumeEventIterator(iteratorPassed),
    "events.on package iterator",
  );
  const iteratorRetainedResult = await bounded(
    iteratorPassed.next(),
    "events.on retained root delivery",
  );
  result.eventsOnIteratorDenialRetainsValue =
    iteratorRetainedResult.value?.[0] == null ? "EMPTY" : "ROOT_ALLOWED";
  await iteratorPassed.return();

  const iteratorPromiseSource = await protectedBuffer(
    "events.on promise passage",
  );
  const iteratorPromise = eventsOn(iteratorPromiseSource, "data");
  const rootNextPromise = iteratorPromise.next();
  iteratorPromiseSource.read();
  result.eventsOnPassedNextPromise = await bounded(
    deniedProbe.consumeEventIteratorPromise(rootNextPromise),
    "events.on package next promise",
  );
  const rootNextResult = await bounded(
    rootNextPromise,
    "events.on root next promise",
  );
  result.eventsOnPassedNextPromiseRoot = rootNextResult.value?.[0] == null
    ? "EMPTY"
    : "ROOT_ALLOWED";
  await iteratorPromise.return();

  const iteratorPreprotectedSetup = beginProtectedBuffer(
    "events.on package pre-protection",
  );
  iteratorPreprotectedSetup.node.pause();
  const iteratorPreprotectedPromise = deniedProbe
    .consumeRegisteredEventIterator(iteratorPreprotectedSetup.node);
  const iteratorPreprotectedSource = await iteratorPreprotectedSetup.ready;
  iteratorPreprotectedSource.read();
  result.eventsOnPackagePreProtection = await bounded(
    iteratorPreprotectedPromise,
    "events.on package pre-protection delivery",
  );

  const poisonedIteratorSetup = beginProtectedBuffer(
    "events.on poisoned pre-protection",
  );
  poisonedIteratorSetup.node.pause();
  const poisonedIteratorRegistration = deniedProbe
    .poisonEventRegistrationMethods(poisonedIteratorSetup.node);
  let poisonedIterator;
  let poisonedIteratorCalls;
  try {
    poisonedIterator = eventsOn(poisonedIteratorSetup.node, "data");
    poisonedIteratorCalls = poisonedIteratorRegistration.calls();
  } finally {
    poisonedIteratorRegistration.restore();
  }
  const poisonedIteratorSource = await poisonedIteratorSetup.ready;
  const poisonedIteratorCleanup = deniedProbe.poisonEventRegistrationMethods(
    poisonedIteratorSource,
  );
  try {
    poisonedIteratorSource.read();
    const poisonedIteratorResult = await bounded(
      poisonedIterator.next(),
      "events.on poisoned pre-protection delivery",
    );
    result.eventsOnPoisonedPreProtection =
      poisonedIteratorResult.value?.[0] == null ? "EMPTY" : "ROOT_ALLOWED";
    await poisonedIterator.return();
    result.eventsOnPoisonedRegistrationCalls = poisonedIteratorCalls +
      poisonedIteratorCleanup.calls();
  } finally {
    poisonedIteratorCleanup.restore();
  }

  const lifecycleSource = await protectedBuffer(
    "events.once lifecycle observability",
  );
  const lifecycleObservation = deniedProbe.observeEventLifecycle(
    lifecycleSource,
    "oden-lifecycle",
  );
  lifecycleSource.emit("oden-lifecycle");
  result.eventsOnceLifecyclePackage = await bounded(
    lifecycleObservation,
    "events.once package lifecycle observation",
  );

  const iteratorCleanupSource = await protectedBuffer(
    "events.on lifecycle cleanup",
  );
  const iteratorCleanup = eventsOn(iteratorCleanupSource, "data");
  result.eventsOnPackageCleanup = await bounded(
    deniedProbe.closeEventIterator(iteratorCleanup),
    "events.on package cleanup",
  );
  const iteratorCleanupResult = await bounded(
    iteratorCleanup.next(),
    "events.on root post-cleanup result",
  );
  result.eventsOnPackageCleanupRoot = iteratorCleanupResult.done === true
    ? "CLOSED"
    : "BROKEN";

  const ordinary = new PassThrough();
  streams.add(ordinary);
  const ordinaryPromise = deniedProbe.consumeEventPromise(
    eventsOnce(ordinary, "data"),
  );
  ordinary.end(Buffer.from("ordinary"));
  result.eventsOnceOrdinaryPackage = await bounded(
    ordinaryPromise,
    "ordinary events.once package delivery",
  );

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
  try {
    inspector.close();
  } catch {
    // Best effort after the isolated endpoint fixture.
  }
  if (completed) Deno.exit(0);
}

import inspector from "node:inspector";
import { createRequire } from "node:module";
import {
  compose,
  duplexPair,
  Duplex,
  PassThrough,
  pipeline,
  Readable,
  Transform,
  Writable,
} from "node:stream";

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

function permissionOutcome(error) {
  return error instanceof Deno.errors.NotCapable ||
      error instanceof Deno.errors.PermissionDenied ||
      error instanceof Error &&
        /^oden capsec: inspector activation at "protected-inspector-stream:[^"]+" requires an exact static inspector:activate row$/
          .test(error.message)
    ? "DENIED"
    : "BROKEN";
}

function attempt(operation) {
  try {
    operation();
    return "ALLOWED";
  } catch (error) {
    return permissionOutcome(error);
  }
}

async function attemptAsync(operation) {
  try {
    await operation();
    return "ALLOWED";
  } catch (error) {
    return permissionOutcome(error);
  }
}

async function pipelineOutcome(stages, label) {
  return await bounded(new Promise((resolve) => {
    try {
      const output = pipeline(...stages, (error) => {
        resolve(error == null ? "ALLOWED" : permissionOutcome(error));
      });
      if (output?.destroy) streams.add(output);
    } catch (error) {
      resolve(permissionOutcome(error));
    }
  }), label);
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
  await bounded((async () => {
    while ((webQueue(web)?.size ?? 0) === 0) {
      await new Promise((resolve) => setTimeout(resolve, 5));
    }
  })(), `${label} Web buffer`);

  const node = Readable.fromWeb(web);
  streams.add(node);
  node._read(0);
  await bounded((async () => {
    while (node.readableLength === 0) {
      await new Promise((resolve) => setTimeout(resolve, 5));
    }
  })(), `${label} Node buffer`);
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

function rootSink() {
  const sink = new Writable({
    objectMode: true,
    write(_chunk, _encoding, done) {
      done();
    },
  });
  sink.on("error", () => {});
  streams.add(sink);
  return sink;
}

function countingSink(counter) {
  const sink = new Writable({
    write(_chunk, _encoding, done) {
      counter.writes++;
      done();
    },
  });
  sink.on("error", () => {});
  streams.add(sink);
  return sink;
}

function rootIdentity(chunk) {
  return chunk;
}

async function operatorOutcome(source, kind, probe) {
  if (kind === "map") {
    return await attemptAsync(() => source.map(probe.callback).toArray());
  }
  if (kind === "filter") {
    return await attemptAsync(() => source.filter(probe.callback).toArray());
  }
  if (kind === "forEach") {
    return await attemptAsync(() => source.forEach(probe.callback));
  }
  if (kind === "some") {
    return await attemptAsync(() => source.some(probe.callback));
  }
  if (kind === "every") {
    return await attemptAsync(() => source.every(probe.callback));
  }
  if (kind === "find") {
    return await attemptAsync(() => source.find(probe.callback));
  }
  return await attemptAsync(() => source.reduce(probe.callback, 0));
}

async function replacedReadOutcome(source, replacement, label) {
  const output = source.map((chunk) => chunk);
  output.on("error", () => {});
  streams.add(output);
  output._read = replacement;
  try {
    const values = await bounded(output.toArray(), label);
    return values.length > 0 ? "ROOT_ALLOWED" : "BROKEN";
  } catch {
    output.destroy();
    return "BROKEN";
  }
}

async function attachGuardWithoutDelivery(source, destination) {
  source.pause();
  source.pipe(destination);
  source.unpipe(destination);
  source.pause();
  await new Promise((resolve) => setTimeout(resolve, 0));
}

const result = {};
let completed = false;

try {
  // Run root-positive controls before awaiting any package-owned callback.
  // A package-produced Promise intentionally retains that package in the
  // continuation actor set, so controls after the denial matrix would no
  // longer be root-only calls.
  console.error("phase:root-controls");
  const rootOperatorSource = await protectedNodeBuffer("root map");
  const rootValues = await rootOperatorSource.map(rootIdentity).toArray();
  result.protectedRootMap = rootValues.length > 0 ? "ROOT_ALLOWED" : "BROKEN";

  for (const kind of ["forEach", "reduce", "some", "every", "find"]) {
    const source = await protectedNodeBuffer(`root ${kind}`);
    if (kind === "forEach") {
      let calls = 0;
      await source.forEach(() => calls++);
      result.protectedRootForEach = calls > 0 ? "ROOT_ALLOWED" : "BROKEN";
    } else if (kind === "reduce") {
      const count = await source.reduce((total) => total + 1, 0);
      result.protectedRootReduce = count > 0 ? "ROOT_ALLOWED" : "BROKEN";
    } else if (kind === "some") {
      result.protectedRootSome = await source.some(() => true)
        ? "ROOT_ALLOWED"
        : "BROKEN";
    } else if (kind === "every") {
      result.protectedRootEvery = await source.every(() => true)
        ? "ROOT_ALLOWED"
        : "BROKEN";
    } else {
      result.protectedRootFind = await source.find(() => true) != null
        ? "ROOT_ALLOWED"
        : "BROKEN";
    }
  }

  const nestedRootSource = await protectedNodeBuffer("nested root map");
  const nestedRootValues = await nestedRootSource
    .map(rootIdentity)
    .map(rootIdentity)
    .toArray();
  result.nestedRootMap = nestedRootValues.length > 0
    ? "ROOT_ALLOWED"
    : "BROKEN";

  const compositeRootGuardA = await protectedNodeBuffer(
    "composite root guard A",
  );
  const compositeRootGuardB = await protectedNodeBuffer(
    "composite root guard B",
  );
  const compositeRoot = new PassThrough();
  compositeRoot.on("error", () => {});
  streams.add(compositeRoot);
  await attachGuardWithoutDelivery(compositeRootGuardA, compositeRoot);
  await attachGuardWithoutDelivery(compositeRootGuardB, compositeRoot);
  compositeRoot.end(Buffer.from("composite root"));
  const compositeRootValues = await compositeRoot.toArray();
  result.compositeRootAdmission = compositeRootValues.length > 0
    ? "ROOT_ALLOWED"
    : "BROKEN";

  console.error("phase:replaced-read");
  const packageReadSource = await protectedNodeBuffer(
    "package replaced _read",
  );
  const packageReadProbe = deniedProbe.makeCompositionProbe("read");
  result.replacedPackageRead = await replacedReadOutcome(
    packageReadSource,
    packageReadProbe.callback,
    "package replaced _read",
  );
  result.replacedPackageReadCalls = packageReadProbe.calls();

  const rootReadSource = await protectedNodeBuffer("root replaced _read");
  let replacedRootReadCalls = 0;
  result.replacedRootRead = await replacedReadOutcome(
    rootReadSource,
    () => {
      replacedRootReadCalls++;
    },
    "root replaced _read",
  );
  result.replacedRootReadCalls = replacedRootReadCalls;

  console.error("phase:admission-controls");
  const nestedPackageSource = await protectedNodeBuffer("nested package map");
  const nestedPackageInner = nestedPackageSource.map(rootIdentity);
  nestedPackageInner.on("error", () => {});
  streams.add(nestedPackageInner);
  const nestedPackageProbe = deniedProbe.makeCompositionProbe("map");

  const compositePackageGuardA = await protectedNodeBuffer(
    "composite package guard A",
  );
  const compositePackageGuardB = await protectedNodeBuffer(
    "composite package guard B",
  );
  const compositePackage = new PassThrough();
  compositePackage.on("error", () => {});
  streams.add(compositePackage);
  await attachGuardWithoutDelivery(compositePackageGuardA, compositePackage);
  await attachGuardWithoutDelivery(compositePackageGuardB, compositePackage);
  compositePackage.end(Buffer.from("composite package"));
  const compositePackageProbe = deniedProbe.makeCompositionProbe("map");

  const reentrantGuardSource = await protectedNodeBuffer(
    "reentrant package read",
  );
  const reentrantReadProbe = deniedProbe.makeReentrantReadProbe();
  reentrantReadProbe.stream.on("error", () => {});
  streams.add(reentrantReadProbe.stream);
  await attachGuardWithoutDelivery(
    reentrantGuardSource,
    reentrantReadProbe.stream,
  );

  result.nestedPackageMap = await operatorOutcome(
    nestedPackageInner,
    "map",
    nestedPackageProbe,
  );
  result.nestedPackageMapCalls = nestedPackageProbe.calls();
  result.nestedPackageMapRetained = rootReadOutcome(nestedPackageSource);
  result.compositePackageAdmission = await operatorOutcome(
    compositePackage,
    "map",
    compositePackageProbe,
  );
  result.compositePackageAdmissionCalls = compositePackageProbe.calls();
  result.compositePackageAdmissionRetained = rootReadOutcome(compositePackage);
  result.reentrantPackageRead = await attemptAsync(() =>
    reentrantReadProbe.stream.toArray()
  );
  result.reentrantPackageReadCalls = reentrantReadProbe.calls();
  result.reentrantPackageReadInner = reentrantReadProbe.outcome();
  result.reentrantPackageReadRetained = rootReadOutcome(reentrantGuardSource);

  console.error("phase:pipeline-node");
  const nodeSource = await protectedNodeBuffer("pipeline node destination");
  const nodeWriteProbe = deniedProbe.makeDeliveryProbe("write");
  const packageWritable = new Writable({ write: nodeWriteProbe.callback });
  packageWritable.on("error", () => {});
  streams.add(packageWritable);
  result.pipelineNodeToNode = await pipelineOutcome(
    [nodeSource, packageWritable],
    "pipeline node destination",
  );
  result.pipelineNodeToNodeCalls = nodeWriteProbe.calls();
  result.pipelineNodeToNodeRetained = rootReadOutcome(nodeSource);

  console.error("phase:pipeline-function");
  const transformSource = await protectedNodeBuffer("pipeline function");
  const transformProbe = deniedProbe.makeCompositionProbe(
    "pipelineTransform",
  );
  result.pipelineFunctionTransform = await pipelineOutcome(
    [transformSource, transformProbe.callback, rootSink()],
    "pipeline function transform",
  );
  result.pipelineFunctionTransformCalls = transformProbe.calls();
  result.pipelineFunctionRetained = rootReadOutcome(transformSource);

  console.error("phase:pipeline-promise");
  const lastPromiseSource = await protectedNodeBuffer("pipeline last promise");
  const lastPromiseProbe = deniedProbe.makeCompositionProbe("pipelinePromise");
  result.pipelineLastPromise = await pipelineOutcome(
    [lastPromiseSource, lastPromiseProbe.callback],
    "pipeline last promise",
  );
  result.pipelineLastPromiseCalls = lastPromiseProbe.calls();
  result.pipelineLastPromiseRetained = rootReadOutcome(lastPromiseSource);

  console.error("phase:pipeline-iterable");
  const lastIterableSource = await protectedNodeBuffer(
    "pipeline last iterable",
  );
  const lastIterableProbe = deniedProbe.makeCompositionProbe(
    "pipelineTransform",
  );
  result.pipelineLastIterable = await pipelineOutcome(
    [lastIterableSource, lastIterableProbe.callback],
    "pipeline last iterable",
  );
  result.pipelineLastIterableCalls = lastIterableProbe.calls();
  result.pipelineLastIterableRetained = rootReadOutcome(lastIterableSource);

  console.error("phase:compose-package");
  const composePackageSource = await protectedNodeBuffer("compose package");
  const composeProbe = deniedProbe.makeDeliveryProbe("transform");
  const packageTransform = new Transform({ transform: composeProbe.callback });
  packageTransform.on("error", () => {});
  streams.add(packageTransform);
  result.composePackageTransform = attempt(() =>
    compose(composePackageSource, packageTransform)
  );
  result.composePackageTransformCalls = composeProbe.calls();
  result.composePackageRetained = rootReadOutcome(composePackageSource);

  console.error("phase:compose-methods");
  const composeGuardSource = await protectedNodeBuffer("compose methods");
  class ComposeHead extends PassThrough {}
  class ComposeTail extends PassThrough {}
  const composeHead = new ComposeHead();
  const composeTail = new ComposeTail();
  composeHead.on("error", () => {});
  composeTail.on("error", () => {});
  streams.add(composeHead);
  streams.add(composeTail);
  await attachGuardWithoutDelivery(composeGuardSource, composeTail);
  const composed = compose(composeHead, composeTail);
  composed.on("error", () => {});
  streams.add(composed);
  const writeProbe = deniedProbe.makeCompositionProbe("write");
  const readProbe = deniedProbe.makeCompositionProbe("read");
  const pushProbe = deniedProbe.makeCompositionProbe("push");
  const headPrototype = Object.getPrototypeOf(composeHead);
  const tailPrototype = Object.getPrototypeOf(composeTail);
  const writeDescriptor = Object.getOwnPropertyDescriptor(
    headPrototype,
    "write",
  );
  const readDescriptor = Object.getOwnPropertyDescriptor(
    tailPrototype,
    "read",
  );
  const pushDescriptor = Object.getOwnPropertyDescriptor(
    composed,
    "push",
  );
  Object.defineProperty(headPrototype, "write", {
    configurable: true,
    value: writeProbe.callback,
    writable: true,
  });
  Object.defineProperty(tailPrototype, "read", {
    configurable: true,
    value: readProbe.callback,
    writable: true,
  });
  Object.defineProperty(composed, "push", {
    configurable: true,
    value: pushProbe.callback,
    writable: true,
  });
  let composedValues;
  try {
    composed.end(Buffer.from("root composition control"));
    composedValues = await bounded(composed.toArray(), "composed root read");
  } finally {
    if (writeDescriptor === undefined) delete headPrototype.write;
    else Object.defineProperty(headPrototype, "write", writeDescriptor);
    if (readDescriptor === undefined) delete tailPrototype.read;
    else Object.defineProperty(tailPrototype, "read", readDescriptor);
    if (pushDescriptor === undefined) delete composed.push;
    else Object.defineProperty(composed, "push", pushDescriptor);
  }
  result.composeCapturedWriteCalls = writeProbe.calls();
  result.composeCapturedReadCalls = readProbe.calls();
  result.composeCapturedPushCalls = pushProbe.calls();
  result.composeRootControl = composedValues.length > 0
    ? "ROOT_ALLOWED"
    : "BROKEN";

  console.error("phase:pair-package");
  const pairSource = await protectedNodeBuffer("duplex pair listener");
  const [pairInput, pairOutput] = duplexPair();
  pairInput.on("error", () => {});
  pairOutput.on("error", () => {});
  streams.add(pairInput);
  streams.add(pairOutput);
  const pairProbe = deniedProbe.makeDeliveryProbe();
  pairOutput.on("data", pairProbe.callback);
  result.duplexPairPrearmedListener = attempt(() => pairSource.pipe(pairInput));
  result.duplexPairPrearmedCalls = pairProbe.calls();
  result.duplexPairRetained = rootReadOutcome(pairSource);

  console.error("phase:pair-root");
  const pairRootSource = await protectedNodeBuffer("duplex pair root");
  const [rootPairInput, rootPairOutput] = duplexPair();
  rootPairInput.on("error", () => {});
  rootPairOutput.on("error", () => {});
  streams.add(rootPairInput);
  streams.add(rootPairOutput);
  pairRootSource.pipe(rootPairInput);
  pairRootSource.read();
  result.duplexPairRootControl = rootReadOutcome(rootPairOutput);

  console.error("phase:duplex-generator");
  const generatorSource = await protectedNodeBuffer("duplex generator");
  const generatorProbe = deniedProbe.makeCompositionProbe("duplexGenerator");
  const generatorDuplex = Duplex.from(generatorProbe.callback);
  generatorDuplex.on("error", () => {});
  streams.add(generatorDuplex);
  result.duplexifyAsyncGenerator = attempt(() =>
    generatorSource.pipe(generatorDuplex)
  );
  result.duplexifyAsyncGeneratorCalls = generatorProbe.calls();
  result.duplexifyAsyncGeneratorRetained = rootReadOutcome(generatorSource);

  console.error("phase:duplex-promise");
  const promiseSource = await protectedNodeBuffer("duplex promise");
  const promiseProbe = deniedProbe.makeCompositionProbe("duplexPromise");
  const promiseDuplex = Duplex.from(promiseProbe.callback);
  promiseDuplex.on("error", () => {});
  streams.add(promiseDuplex);
  result.duplexifyPromise = attempt(() => promiseSource.pipe(promiseDuplex));
  result.duplexifyPromiseCalls = promiseProbe.calls();
  result.duplexifyPromiseRetained = rootReadOutcome(promiseSource);

  console.error("phase:operators");
  for (
    const kind of [
      "map",
      "filter",
      "forEach",
      "reduce",
      "some",
      "every",
      "find",
    ]
  ) {
    const source = await protectedNodeBuffer(`operator ${kind}`);
    const probe = deniedProbe.makeCompositionProbe(kind);
    result[`${kind}Callback`] = await operatorOutcome(source, kind, probe);
    result[`${kind}CallbackCalls`] = probe.calls();
    result[`${kind}Retained`] = rootReadOutcome(source);
  }

  console.error("phase:bound-proxy");
  const boundSource = await protectedNodeBuffer("bound map");
  const boundProbe = deniedProbe.makeBoundCompositionProbe("map");
  result.boundMapCallback = await operatorOutcome(
    boundSource,
    "map",
    boundProbe,
  );
  result.boundMapCallbackCalls = boundProbe.calls();
  result.boundMapRetained = rootReadOutcome(boundSource);

  const proxySource = await protectedNodeBuffer("proxy map");
  const proxyProbe = deniedProbe.makeProxyCompositionProbe("map");
  result.proxyMapCallback = await operatorOutcome(
    proxySource,
    "map",
    proxyProbe,
  );
  result.proxyMapCallbackCalls = proxyProbe.calls();
  result.proxyMapRetained = rootReadOutcome(proxySource);

  console.error("phase:controls");
  const ordinaryProbe = deniedProbe.makeCompositionProbe("map");
  const ordinaryValues = await Readable.from([Buffer.from("ordinary")])
    .map(ordinaryProbe.callback)
    .toArray();
  result.ordinaryPackageMap = ordinaryValues.length === 1
    ? "ALLOWED"
    : "BROKEN";
  result.ordinaryPackageMapCalls = ordinaryProbe.calls();

  const lifecycleSource = await protectedNodeBuffer("lifecycle callback");
  const lifecycleProbe = deniedProbe.makeDeliveryProbe(
    "scheduled",
    lifecycleSource,
  );
  lifecycleSource.on("timeout", lifecycleProbe.callback);
  lifecycleSource.emit("timeout");
  result.lifecycleCallback = await bounded(
    lifecycleProbe.outcome,
    "lifecycle callback",
  );
  result.lifecycleCallbackCalls = lifecycleProbe.calls();
  result.lifecycleRetained = rootReadOutcome(lifecycleSource);

  const preActivationSource = await protectedNodeBuffer(
    "pre-activation writable admission",
  );
  const preActivationCounter = { writes: 0 };
  const preActivationSink = countingSink(preActivationCounter);
  const preActivationProbe = deniedProbe.makeWritableAdmissionProbe(
    preActivationSink,
  );
  preActivationSource.on("timeout", preActivationProbe.callback);
  preActivationSource.emit("timeout");
  result.preActivationWrite = preActivationProbe.outcome();
  result.preActivationWriteCalls = preActivationProbe.calls();
  await attachGuardWithoutDelivery(preActivationSource, preActivationSink);
  result.preActivationRootUncork = attempt(() =>
    preActivationSink.uncork()
  );
  result.preActivationFlushedWrites = preActivationCounter.writes;
  result.preActivationRetained = rootReadOutcome(preActivationSource);

  const protectedAdmissionSource = await protectedNodeBuffer(
    "protected writable admission",
  );
  const protectedAdmissionCounter = { writes: 0 };
  const protectedAdmissionSink = countingSink(protectedAdmissionCounter);
  await attachGuardWithoutDelivery(
    protectedAdmissionSource,
    protectedAdmissionSink,
  );
  const protectedAdmissionProbe = deniedProbe.makeWritableAdmissionProbe(
    protectedAdmissionSink,
  );
  protectedAdmissionSource.on("timeout", protectedAdmissionProbe.callback);
  protectedAdmissionSource.emit("timeout");
  result.protectedAdmissionWrite = protectedAdmissionProbe.outcome();
  result.protectedAdmissionWriteCalls = protectedAdmissionProbe.calls();
  result.protectedAdmissionRootUncork = attempt(() =>
    protectedAdmissionSink.uncork()
  );
  result.protectedAdmissionFlushedWrites = protectedAdmissionCounter.writes;
  result.protectedAdmissionRetained = rootReadOutcome(
    protectedAdmissionSource,
  );

  console.error("phase:cleanup");
  const cleanupGuardSource = await protectedNodeBuffer("compose cleanup");
  const cleanupHead = new PassThrough();
  const cleanupTail = new PassThrough();
  cleanupHead.on("error", () => {});
  cleanupTail.on("error", () => {});
  streams.add(cleanupHead);
  streams.add(cleanupTail);
  await attachGuardWithoutDelivery(cleanupGuardSource, cleanupTail);
  const cleanupComposition = compose(cleanupHead, cleanupTail);
  cleanupComposition.on("error", () => {});
  streams.add(cleanupComposition);
  result.packageDestroyCleanup = deniedProbe.destroyStream(cleanupComposition);

  console.log(JSON.stringify(result));
  completed = true;
} finally {
  for (const stream of streams) {
    try {
      stream.destroy();
    } catch {
      // Cleanup cannot replace the fixture result or deliver buffered bytes.
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

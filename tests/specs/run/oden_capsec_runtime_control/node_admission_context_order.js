import { Readable } from "node:stream";

const core = Deno[Deno.internal].core;
const {
  captureCurrentDeliveryCallback,
  captureDeliveryCallback,
  createStreamUseAdmission,
  currentStreamUseAdmissionContext,
  runCapturedCallback,
  runWithStreamUseAdmission,
  setStreamUseGuard,
} = core.loadExtScript(
  "ext:deno_node/internal/streams/oden_delivery.js",
);
const {
  markReadableStreamTrustedCallback,
  setReadableStreamUseGuard,
} = core.loadExtScript("ext:deno_web/06_streams.js");
const originalScheduleContext = core.ops.op_oden_schedule_context;

function runInContext(context, callback) {
  const previous = core.getAsyncContext();
  core.setAsyncContext(context);
  try {
    return callback();
  } finally {
    core.setAsyncContext(previous);
  }
}

function actorGuard(actor) {
  return actorsGuard(actor);
}

function actorsGuard(...actors) {
  return () => {
    const actor = core.getAsyncContext();
    for (let i = 0; i < actors.length; i++) {
      if (actor === actors[i]) return actor;
    }
    throw new Deno.errors.NotCapable("synthetic stream actor denied");
  };
}

async function waitFor(condition) {
  for (let attempt = 0; attempt < 20; attempt++) {
    if (condition()) return;
    await new Promise((resolve) => setTimeout(resolve, 0));
  }
  throw new Error("pull did not start");
}

function deniedOutcome(promise) {
  return Promise.resolve(promise).then(
    () => "ALLOWED",
    (error) => error instanceof Deno.errors.NotCapable ? "DENIED" : "BROKEN",
  );
}

async function boundedDeniedOutcome(promise) {
  let timeoutId;
  const result = await Promise.race([
    deniedOutcome(promise),
    new Promise((resolve) => {
      timeoutId = setTimeout(() => resolve("HUNG"), 1_000);
    }),
  ]);
  clearTimeout(timeoutId);
  return result;
}

async function concurrentNodeIteratorOutcome() {
  const actorA = {};
  const actorB = {};
  const stream = new Readable({ read() {} });
  setStreamUseGuard(stream, actorGuard(actorA));
  const iterator = runInContext(
    actorA,
    () => stream.iterator({ destroyOnReturn: false }),
  );
  try {
    const first = runInContext(actorA, () => iterator.next());
    const passed = await deniedOutcome(
      runInContext(actorB, () => iterator.next()),
    );
    runInContext(actorA, () => stream.push(new Uint8Array([0x2a])));
    const root = await first;
    return passed === "DENIED" && !root.done && root.value?.[0] === 0x2a
      ? "CLOSED"
      : "BROKEN";
  } finally {
    await iterator.return();
    stream.destroy();
  }
}

async function acceptedConcurrentNodeIteratorOutcome() {
  const actorA = {};
  const actorB = {};
  const guardActors = [];
  const stream = new Readable({ read() {} });
  setStreamUseGuard(stream, () => {
    const actor = actorsGuard(actorA, actorB)();
    guardActors.push(actor);
    return actor;
  });
  const iterator = runInContext(
    actorA,
    () => stream.iterator({ destroyOnReturn: false }),
  );
  try {
    const first = runInContext(actorA, () => iterator.next());
    const second = runInContext(actorB, () => iterator.next());
    const actorBCallsAtAdmission = guardActors.filter((actor) =>
      actor === actorB
    ).length;
    runInContext(actorA, () => stream.push(new Uint8Array([0x2a])));
    const firstResult = await first;
    runInContext(actorA, () => stream.push(new Uint8Array([0x2b])));
    const secondResult = await second;
    const actorBCallsAfterSettlement = guardActors.filter((actor) =>
      actor === actorB
    ).length;
    const prototypeProbe = (async function* () {})();
    const asyncGeneratorPrototype = Object.getPrototypeOf(
      Object.getPrototypeOf(prototypeProbe),
    );
    const iteratorPrototype = Object.getPrototypeOf(iterator);
    const prototypeCompatible = iteratorPrototype !== asyncGeneratorPrototype &&
      Object.getPrototypeOf(iteratorPrototype) === asyncGeneratorPrototype;
    const methodSurfaceCompatible = iterator.next === iteratorPrototype.next &&
      iterator.return === iteratorPrototype.return &&
      iterator.throw === iteratorPrototype.throw &&
      iterator.next.name === prototypeProbe.next.name &&
      iterator.next.length === prototypeProbe.next.length &&
      iterator.return.name === prototypeProbe.return.name &&
      iterator.return.length === prototypeProbe.return.length &&
      iterator.throw.name === prototypeProbe.throw.name &&
      iterator.throw.length === prototypeProbe.throw.length;
    // The target-hiding wrapper must differ from the branded intrinsic so a
    // method retained before late protection cannot call the hidden target.
    // Every observable method shape and receiver failure remains controlled.
    const targetHidingMethodDivergence =
      iterator.next !== prototypeProbe.next &&
      iterator.return !== prototypeProbe.return &&
      iterator.throw !== prototypeProbe.throw;
    const asyncIteratorIdentity = iterator[Symbol.asyncIterator]() === iterator;
    const brandingStream = new Readable({ objectMode: true, read() {} });
    brandingStream.push("branding");
    const brandingIterator = brandingStream.iterator({
      destroyOnReturn: false,
    });
    const sharedMethods = iterator.next === brandingIterator.next &&
      iterator.return === brandingIterator.return &&
      iterator.throw === brandingIterator.throw;
    let receiverBranded = false;
    try {
      await Reflect.apply(brandingIterator.next, {}, []);
    } catch (error) {
      receiverBranded = error instanceof TypeError;
    }
    await brandingIterator.return();
    brandingStream.destroy();
    const wrappedNext = iterator.next;
    const ownNext = () => "OVERRIDE";
    iterator.next = ownNext;
    const ownOverride = iterator.next === ownNext;
    delete iterator.next;
    const overrideRestored = iterator.next === wrappedNext;
    await prototypeProbe.return();
    return !firstResult.done && firstResult.value?.[0] === 0x2a &&
        !secondResult.done && secondResult.value?.[0] === 0x2b &&
        actorBCallsAfterSettlement > actorBCallsAtAdmission &&
        prototypeCompatible && methodSurfaceCompatible &&
        targetHidingMethodDivergence &&
        asyncIteratorIdentity && sharedMethods && receiverBranded &&
        ownOverride && overrideRestored &&
        Object.keys(iterator).join() === "stream"
      ? "BOUND"
      : "BROKEN";
  } finally {
    await iterator.return();
    stream.destroy();
  }
}

async function revokedQueuedNodeIteratorOutcome() {
  const actorA = {};
  const actorB = {};
  let actorBAllowed = true;
  let actorBChecks = 0;
  const stream = new Readable({ objectMode: true, read() {} });
  stream.push("first");
  stream.push("second");
  setStreamUseGuard(stream, () => {
    const actor = core.getAsyncContext();
    if (actor === actorB) {
      actorBChecks++;
      if (!actorBAllowed) {
        throw new Deno.errors.NotCapable("synthetic actor B revoked");
      }
    } else if (actor !== actorA) {
      throw new Deno.errors.NotCapable("synthetic stream actor denied");
    }
    return actor;
  });
  const iterator = runInContext(
    actorA,
    () => stream.iterator({ destroyOnReturn: false }),
  );
  try {
    const first = runInContext(actorA, () => iterator.next());
    const revoked = runInContext(actorB, () => iterator.next());
    const actorBChecksAtAdmission = actorBChecks;
    actorBAllowed = false;
    const firstResult = await first;
    const revokedResult = await boundedDeniedOutcome(revoked);
    const recovery = await runInContext(actorA, () => iterator.next());
    return firstResult.value === "first" && revokedResult === "DENIED" &&
        actorBChecks > actorBChecksAtAdmission && recovery.value === "second"
      ? "CLOSED"
      : "BROKEN";
  } finally {
    await iterator.return();
    stream.destroy();
  }
}

async function lateProtectedNodeIteratorOutcome() {
  const actorA = {};
  const actorB = {};
  const stream = new Readable({ objectMode: true, read() {} });
  stream.push("secret");
  const iterator = stream.iterator({ destroyOnReturn: false });
  const retainedNext = iterator.next;
  setStreamUseGuard(stream, actorGuard(actorA));
  try {
    const denied = await boundedDeniedOutcome(
      runInContext(
        actorB,
        () => Reflect.apply(retainedNext, iterator, []),
      ),
    );
    const root = await runInContext(actorA, () => iterator.next());
    return denied === "DENIED" && root.value === "secret" ? "CLOSED" : "BROKEN";
  } finally {
    await iterator.return();
    stream.destroy();
  }
}

async function revokedSettlingNodeIteratorOutcome() {
  const actorA = {};
  const actorB = {};
  let actorBAllowed = true;
  let actorBChecks = 0;
  const stream = new Readable({ objectMode: true, read() {} });
  stream.push("discarded");
  stream.push("recovery");
  setStreamUseGuard(stream, () => {
    const actor = core.getAsyncContext();
    if (actor === actorB) {
      actorBChecks++;
      if (!actorBAllowed) {
        throw new Deno.errors.NotCapable("synthetic actor B revoked");
      }
    } else if (actor !== actorA) {
      throw new Deno.errors.NotCapable("synthetic stream actor denied");
    }
    return actor;
  });
  const iterator = runInContext(
    actorB,
    () => stream.iterator({ destroyOnReturn: false }),
  );
  try {
    const revoked = runInContext(actorB, () => iterator.next());
    const actorBChecksAtActivation = actorBChecks;
    actorBAllowed = false;
    const revokedResult = await boundedDeniedOutcome(revoked);
    const recovery = await runInContext(actorA, () => iterator.next());
    return revokedResult === "DENIED" &&
        actorBChecks > actorBChecksAtActivation && recovery.value === "recovery"
      ? "CLOSED"
      : "BROKEN";
  } finally {
    await iterator.return();
    stream.destroy();
  }
}

async function revokedQueuedNodeCleanupOutcome(method) {
  const actorA = {};
  const actorB = {};
  let actorBAllowed = true;
  const stream = new Readable({ objectMode: true, read() {} });
  stream.push("first");
  stream.push("must-not-deliver");
  setStreamUseGuard(stream, () => {
    const actor = core.getAsyncContext();
    if (actor === actorB && !actorBAllowed) {
      throw new Deno.errors.NotCapable("synthetic actor B revoked");
    }
    if (actor !== actorA && actor !== actorB) {
      throw new Deno.errors.NotCapable("synthetic stream actor denied");
    }
    return actor;
  });
  const iterator = runInContext(
    actorA,
    () => stream.iterator({ destroyOnReturn: false }),
  );
  const injected = new Error("queued iterator throw");
  try {
    const first = runInContext(actorA, () => iterator.next());
    const cleanup = runInContext(
      actorB,
      () =>
        method === "return"
          ? iterator.return("returned")
          : iterator.throw(injected),
    );
    actorBAllowed = false;
    const firstResult = await first;
    if (firstResult.value !== "first") return "BROKEN";
    if (method === "return") {
      const result = await cleanup;
      return result.done && result.value === "returned" ? "CLEAN" : "BROKEN";
    }
    try {
      await cleanup;
      return "BROKEN";
    } catch (error) {
      return error === injected ? "CLEAN" : "BROKEN";
    }
  } finally {
    await iterator.return().catch(() => {});
    stream.destroy();
  }
}

async function concurrentWebPullOutcome(type) {
  const actorA = {};
  const actorB = {};
  const releases = [];
  const pullActors = [];
  const resumeActors = [];
  let pullCount = 0;
  async function pull(controller) {
    const value = ++pullCount;
    pullActors.push(core.getAsyncContext());
    await new Promise((resolve) => releases.push(resolve));
    resumeActors.push(core.getAsyncContext());
    if (type === "bytes") {
      controller.byobRequest.view[0] = value;
      controller.byobRequest.respond(1);
    } else {
      controller.enqueue(value);
    }
    if (value === 2) controller.close();
  }
  markReadableStreamTrustedCallback(pull);
  const source = type === "bytes" ? { type, pull } : { pull };
  const stream = new ReadableStream(source, { highWaterMark: 0 });
  setReadableStreamUseGuard(stream, actorGuard(actorA));
  const reader = runInContext(
    actorA,
    () =>
      type === "bytes"
        ? stream.getReader({ mode: "byob" })
        : stream.getReader(),
  );
  reader.closed.catch(() => {});
  const read = () =>
    type === "bytes" ? reader.read(new Uint8Array(8)) : reader.read();
  try {
    const first = runInContext(actorA, read);
    let firstError;
    first.catch((error) => firstError = error);
    await waitFor(() => releases.length === 1 || firstError !== undefined);
    if (firstError !== undefined) throw firstError;
    const passed = await deniedOutcome(runInContext(actorB, read));
    runInContext(actorB, releases[0]);
    const firstResult = await first;

    const second = runInContext(actorA, read);
    await waitFor(() => releases.length === 2);
    runInContext(actorB, releases[1]);
    const secondResult = await second;
    const firstValue = type === "bytes"
      ? firstResult.value?.[0]
      : firstResult.value;
    const secondValue = type === "bytes"
      ? secondResult.value?.[0]
      : secondResult.value;
    return passed === "DENIED" && firstValue === 1 && secondValue === 2 &&
        pullActors.length === 2 && pullActors.every((actor) =>
          actor === actorA
        ) &&
        resumeActors.length === 2 &&
        resumeActors.every((actor) => actor === actorA)
      ? "CLOSED"
      : "BROKEN";
  } finally {
    await runInContext(actorA, () => reader.cancel()).catch(() => {});
    reader.releaseLock();
  }
}

async function acceptedConcurrentWebPullOutcome(type) {
  const actorA = {};
  const actorB = {};
  const releaseActor = {};
  const releases = [];
  const pullActors = [];
  const resumeActors = [];
  let pullCount = 0;
  async function pull(controller) {
    const value = ++pullCount;
    pullActors.push(core.getAsyncContext());
    await new Promise((resolve) => releases.push(resolve));
    resumeActors.push(core.getAsyncContext());
    if (type === "bytes") {
      controller.byobRequest.view[0] = value;
      controller.byobRequest.respond(1);
    } else {
      controller.enqueue(value);
    }
    if (value === 2) controller.close();
  }
  markReadableStreamTrustedCallback(pull);
  const source = type === "bytes" ? { type, pull } : { pull };
  const stream = new ReadableStream(source, { highWaterMark: 0 });
  setReadableStreamUseGuard(stream, actorsGuard(actorA, actorB));
  const reader = runInContext(
    actorA,
    () =>
      type === "bytes"
        ? stream.getReader({ mode: "byob" })
        : stream.getReader(),
  );
  reader.closed.catch(() => {});
  const read = () =>
    type === "bytes" ? reader.read(new Uint8Array(8)) : reader.read();
  try {
    const first = runInContext(actorA, read);
    const second = runInContext(actorB, read);
    await waitFor(() => releases.length === 1);
    runInContext(releaseActor, releases[0]);
    await waitFor(() => releases.length === 2);
    runInContext(releaseActor, releases[1]);
    const firstResult = await first;
    const secondResult = await second;
    const firstValue = type === "bytes"
      ? firstResult.value?.[0]
      : firstResult.value;
    const secondValue = type === "bytes"
      ? secondResult.value?.[0]
      : secondResult.value;
    return firstValue === 1 && secondValue === 2 &&
        pullActors.length === 2 && pullActors[0] === actorA &&
        pullActors[1] === actorB && resumeActors.length === 2 &&
        resumeActors[0] === actorA && resumeActors[1] === actorB
      ? "BOUND"
      : "BROKEN";
  } finally {
    await runInContext(actorA, () => reader.cancel()).catch(() => {});
    reader.releaseLock();
  }
}

async function revokedQueuedWebPullOutcome(type) {
  const actorA = {};
  const actorB = {};
  const releaseActor = {};
  let actorBAllowed = true;
  let actorBChecks = 0;
  let releaseFirstPull;
  let pullCount = 0;
  async function pull(controller) {
    const value = ++pullCount;
    if (type === "bytes") {
      controller.byobRequest.view[0] = value;
      controller.byobRequest.respond(1);
    } else {
      controller.enqueue(value);
    }
    if (value === 1) {
      await new Promise((resolve) => releaseFirstPull = resolve);
    }
  }
  markReadableStreamTrustedCallback(pull);
  const source = type === "bytes" ? { type, pull } : { pull };
  const stream = new ReadableStream(source, { highWaterMark: 0 });
  setReadableStreamUseGuard(stream, () => {
    const actor = core.getAsyncContext();
    if (actor === actorB) {
      actorBChecks++;
      if (!actorBAllowed) {
        throw new Deno.errors.NotCapable("synthetic Web actor B revoked");
      }
    } else if (actor !== actorA) {
      throw new Deno.errors.NotCapable("synthetic Web stream actor denied");
    }
    return actor;
  });
  const reader = runInContext(
    actorA,
    () =>
      type === "bytes"
        ? stream.getReader({ mode: "byob" })
        : stream.getReader(),
  );
  reader.closed.catch(() => {});
  const read = () =>
    type === "bytes" ? reader.read(new Uint8Array(8)) : reader.read();
  try {
    const first = runInContext(actorA, read);
    await waitFor(() => releaseFirstPull !== undefined);
    const firstResult = await first;
    const queued = runInContext(actorB, read);
    const actorBChecksAtAdmission = actorBChecks;
    actorBAllowed = false;
    runInContext(releaseActor, releaseFirstPull);
    const queuedResult = await boundedDeniedOutcome(queued);
    const firstValue = type === "bytes"
      ? firstResult.value?.[0]
      : firstResult.value;
    return firstValue === 1 && queuedResult === "DENIED" &&
        actorBChecks > actorBChecksAtAdmission && pullCount === 1
      ? "CLOSED"
      : "BROKEN";
  } finally {
    await runInContext(actorA, () => reader.cancel()).catch(() => {});
    reader.releaseLock();
  }
}

function nestedUntrustedAdmissionOutcome() {
  const actorA = {};
  const actorB = {};
  const outer = {};
  const target = {};
  const targetActors = [];
  setStreamUseGuard(outer, actorGuard(actorA));
  setStreamUseGuard(target, () => {
    const actor = core.getAsyncContext();
    targetActors.push(actor);
    if (actor !== actorB) {
      throw new Deno.errors.NotCapable("nested callback borrowed outer actor");
    }
    return actor;
  });
  const captured = captureDeliveryCallback(() => {
    const admission = createStreamUseAdmission(target);
    return admission.context === actorB &&
        currentStreamUseAdmissionContext() === actorB
      ? "LIVE"
      : "BROKEN";
  });
  captured.context = actorB;
  const admission = runInContext(
    actorA,
    () => createStreamUseAdmission(outer),
  );
  try {
    const result = runWithStreamUseAdmission(
      outer,
      admission,
      () => runCapturedCallback(captured, undefined, []),
    );
    return result === "LIVE" && targetActors.length === 1 &&
        targetActors[0] === actorB
      ? "LIVE"
      : "BROKEN";
  } catch {
    return "BROKEN";
  }
}

async function concurrentOperationOutcomes() {
  const previous = core.getAsyncContext();
  core.ops.op_oden_schedule_context = () => core.getAsyncContext();
  try {
    return {
      nodeIterator: await concurrentNodeIteratorOutcome(),
      acceptedNodeIterator: await acceptedConcurrentNodeIteratorOutcome(),
      revokedQueuedNodeIterator: await revokedQueuedNodeIteratorOutcome(),
      lateProtectedNodeIterator: await lateProtectedNodeIteratorOutcome(),
      revokedSettlingNodeIterator: await revokedSettlingNodeIteratorOutcome(),
      revokedQueuedNodeReturn: await revokedQueuedNodeCleanupOutcome("return"),
      revokedQueuedNodeThrow: await revokedQueuedNodeCleanupOutcome("throw"),
      webDefaultPull: await concurrentWebPullOutcome("default"),
      webBYOBPull: await concurrentWebPullOutcome("bytes"),
      acceptedWebDefaultPull: await acceptedConcurrentWebPullOutcome(
        "default",
      ),
      acceptedWebBYOBPull: await acceptedConcurrentWebPullOutcome("bytes"),
      revokedQueuedWebDefaultPull: await revokedQueuedWebPullOutcome(
        "default",
      ),
      revokedQueuedWebBYOBPull: await revokedQueuedWebPullOutcome("bytes"),
      nestedUntrustedAdmission: nestedUntrustedAdmissionOutcome(),
    };
  } finally {
    core.ops.op_oden_schedule_context = originalScheduleContext;
    core.setAsyncContext(previous);
  }
}

function capturePriorityOutcome(untrusted) {
  const stream = {};
  const admissionActor = {};
  const admission = createStreamUseAdmission(stream, admissionActor);
  const previous = core.getAsyncContext();
  core.setAsyncContext(undefined);
  try {
    return runWithStreamUseAdmission(stream, admission, () => {
      const currentContext = {};
      const scheduleContext = currentContext;
      const capture = () => {
        core.setAsyncContext(currentContext);
        core.ops.op_oden_schedule_context = () => scheduleContext;
        return captureCurrentDeliveryCallback(() => {}).context;
      };
      // Model an untrusted package callback (CPED B) executing inside a
      // trusted root admission (actor A) and scheduling a loader helper. The
      // callback scope must keep B; a loader-only call keeps A.
      const captured = untrusted
        ? runCapturedCallback(
          captureDeliveryCallback(capture),
          undefined,
          [],
        )
        : capture();
      if (captured === scheduleContext && untrusted) {
        return "LIVE";
      }
      return captured === admissionActor ? "ADMISSION" : "BROKEN";
    });
  } finally {
    core.ops.op_oden_schedule_context = originalScheduleContext;
    core.setAsyncContext(previous);
  }
}

function admissionOutcome(contexts) {
  const stream = {};
  for (const context of contexts) {
    setStreamUseGuard(stream, () => context);
  }
  const previous = core.getAsyncContext();
  core.setAsyncContext(undefined);
  try {
    const admission = createStreamUseAdmission(stream);
    return runWithStreamUseAdmission(stream, admission, () => "ALLOWED");
  } catch (error) {
    if (
      error instanceof TypeError &&
      /^stream use (?:guard|admission) actors differ$/.test(error.message)
    ) {
      return "DENIED";
    }
    throw error;
  } finally {
    core.setAsyncContext(previous);
  }
}

// Distinct operation actors never collapse to one constituent's authority,
// and reversing attachment order cannot change that decision. Identical
// snapshots still deduplicate so ordinary same-actor composition stays live.
// @ref LLP 0019#operation-scoped-positive-authority-provenance [tests]
const actorA = {};
const actorB = {};
const sharedActor = {};
const concurrent = await concurrentOperationOutcomes();
console.log(JSON.stringify({
  sameActor: admissionOutcome([sharedActor, sharedActor]),
  actorAB: admissionOutcome([actorA, actorB]),
  actorBA: admissionOutcome([actorB, actorA]),
  untrustedSchedule: capturePriorityOutcome(true),
  missingSchedule: capturePriorityOutcome(false),
  concurrentNodeIterator: concurrent.nodeIterator,
  acceptedConcurrentNodeIterator: concurrent.acceptedNodeIterator,
  revokedQueuedNodeIterator: concurrent.revokedQueuedNodeIterator,
  lateProtectedNodeIterator: concurrent.lateProtectedNodeIterator,
  revokedSettlingNodeIterator: concurrent.revokedSettlingNodeIterator,
  revokedQueuedNodeReturn: concurrent.revokedQueuedNodeReturn,
  revokedQueuedNodeThrow: concurrent.revokedQueuedNodeThrow,
  concurrentWebDefaultPull: concurrent.webDefaultPull,
  concurrentWebBYOBPull: concurrent.webBYOBPull,
  acceptedConcurrentWebDefaultPull: concurrent.acceptedWebDefaultPull,
  acceptedConcurrentWebBYOBPull: concurrent.acceptedWebBYOBPull,
  revokedQueuedWebDefaultPull: concurrent.revokedQueuedWebDefaultPull,
  revokedQueuedWebBYOBPull: concurrent.revokedQueuedWebBYOBPull,
  nestedUntrustedAdmission: concurrent.nestedUntrustedAdmission,
}));

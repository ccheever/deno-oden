import { Readable } from "node:stream";

const core = Deno[Deno.internal].core;
const {
  captureCurrentDeliveryCallback,
  captureDeliveryCallback,
  createStreamUseAdmission,
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
  return () => {
    if (core.getAsyncContext() !== actor) {
      throw new Deno.errors.NotCapable("synthetic stream actor denied");
    }
    return actor;
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

async function concurrentOperationOutcomes() {
  const previous = core.getAsyncContext();
  core.ops.op_oden_schedule_context = () => core.getAsyncContext();
  try {
    return {
      nodeIterator: await concurrentNodeIteratorOutcome(),
      webDefaultPull: await concurrentWebPullOutcome("default"),
      webBYOBPull: await concurrentWebPullOutcome("bytes"),
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
  concurrentWebDefaultPull: concurrent.webDefaultPull,
  concurrentWebBYOBPull: concurrent.webBYOBPull,
}));

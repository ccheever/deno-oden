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
const originalScheduleContext = core.ops.op_oden_schedule_context;

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
console.log(JSON.stringify({
  sameActor: admissionOutcome([sharedActor, sharedActor]),
  actorAB: admissionOutcome([actorA, actorB]),
  actorBA: admissionOutcome([actorB, actorA]),
  untrustedSchedule: capturePriorityOutcome(true),
  missingSchedule: capturePriorityOutcome(false),
}));

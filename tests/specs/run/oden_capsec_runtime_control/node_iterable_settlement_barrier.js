const core = Deno[Deno.internal].core;
const {
  setStreamUseGuard,
  wrapIterableDelivery,
} = core.loadExtScript(
  "ext:deno_node/internal/streams/oden_delivery.js",
);
const { Readable } = core.loadExtScript(
  "ext:deno_node/internal/streams/readable.js",
);

function deferred() {
  let reject;
  let resolve;
  const promise = new Promise((resolvePromise, rejectPromise) => {
    resolve = resolvePromise;
    reject = rejectPromise;
  });
  return { promise, reject, resolve };
}

function mutableGuard(state) {
  state.checks++;
  if (!state.live) throw new Error("fixture iterator guard revoked");
}

function deferredNextSettlement() {
  const result = deferred();
  const state = { checks: 0, live: true };
  let calls = 0;
  const source = {
    [Symbol.asyncIterator]() {
      return {
        next() {
          calls++;
          return result.promise;
        },
      };
    },
  };
  setStreamUseGuard(source, () => mutableGuard(state));
  const iterator = wrapIterableDelivery(source)[Symbol.asyncIterator]();
  const resultPromise = iterator.next();
  const checksAtStart = state.checks;
  state.live = false;
  result.resolve({ done: false, value: "DEFERRED_NEXT_SENTINEL" });
  return resultPromise.then(
    (settled) => ({
      calls,
      outcome: settled.value === "DEFERRED_NEXT_SENTINEL" ? "LEAKED" : "BROKEN",
      settlementChecks: state.checks - checksAtStart,
    }),
    (error) => ({
      calls,
      outcome: error?.message === "fixture iterator guard revoked"
        ? "DENIED"
        : "BROKEN",
      settlementChecks: state.checks - checksAtStart,
    }),
  );
}

function rejectedNextSettlement() {
  const result = deferred();
  const state = { checks: 0, live: true };
  const rejection = new Error("fixture iterator rejection");
  let calls = 0;
  const source = {
    [Symbol.asyncIterator]() {
      return {
        next() {
          calls++;
          return result.promise;
        },
      };
    },
  };
  setStreamUseGuard(source, () => mutableGuard(state));
  const iterator = wrapIterableDelivery(source)[Symbol.asyncIterator]();
  const resultPromise = iterator.next();
  const checksAtStart = state.checks;
  state.live = false;
  result.reject(rejection);
  return resultPromise.then(
    () => ({ calls, outcome: "BROKEN", settlementChecks: -1 }),
    (error) => ({
      calls,
      outcome: error === rejection ? "PRESERVED" : "BROKEN",
      settlementChecks: state.checks - checksAtStart,
    }),
  );
}

function deferredThrowSettlement() {
  const result = deferred();
  const state = { checks: 0, live: true };
  let calls = 0;
  let sentinelCalls = 0;
  const sentinel = {
    then(resolve) {
      sentinelCalls++;
      resolve();
    },
  };
  const source = {
    [Symbol.asyncIterator]() {
      return {
        next() {
          return new Promise(() => {});
        },
        throw() {
          calls++;
          return result.promise;
        },
      };
    },
  };
  setStreamUseGuard(source, () => mutableGuard(state));
  const readable = Readable.from(source);
  readable.on("error", () => {});
  const closed = new Promise((resolve) => readable.once("close", resolve));
  readable.destroy(new Error("fixture iterator throw"));
  const checksAtStart = state.checks;
  state.live = false;
  result.resolve({ done: true, value: sentinel });
  return closed.then(() => ({
    calls,
    outcome: state.checks > checksAtStart && sentinelCalls === 0
      ? "DENIED"
      : sentinelCalls > 0
      ? "LEAKED"
      : "BROKEN",
    sentinel: sentinelCalls === 0 ? "CLOSED" : "LEAKED",
    settlementChecks: state.checks - checksAtStart,
  }));
}

function iteratorReturnCanary(async) {
  const pending = deferred();
  const state = { checks: 0, live: true };
  let calls = 0;
  let input;
  const result = { done: true, value: "RETURN_VALUE_SENTINEL" };
  const iteratorFactory = () => ({
    next() {
      return async
        ? Promise.resolve({ done: false, value: "UNREACHABLE" })
        : { done: false, value: "UNREACHABLE" };
    },
    return(value) {
      calls++;
      input = value;
      return async ? pending.promise : result;
    },
  });
  const source = async
    ? { [Symbol.asyncIterator]: iteratorFactory }
    : { [Symbol.iterator]: iteratorFactory };
  setStreamUseGuard(source, () => mutableGuard(state));
  const wrapped = wrapIterableDelivery(source);
  const iterator = async
    ? wrapped[Symbol.asyncIterator]()
    : wrapped[Symbol.iterator]();
  const checksAtCleanup = state.checks;
  state.live = false;
  const cleanupResult = iterator.return("RETURN_INPUT");
  if (async) pending.resolve(result);
  return Promise.resolve(cleanupResult).then(
    (settled) => ({
      calls,
      cleanupChecks: state.checks - checksAtCleanup,
      input: input === "RETURN_INPUT" ? "PRESERVED" : "BROKEN",
      outcome: settled.done === true && settled.value === undefined
        ? "CLOSED"
        : settled.value === "RETURN_VALUE_SENTINEL"
        ? "LEAKED"
        : "BROKEN",
    }),
    () => ({
      calls,
      cleanupChecks: state.checks - checksAtCleanup,
      input: input === "RETURN_INPUT" ? "PRESERVED" : "BROKEN",
      outcome: "BROKEN",
    }),
  );
}

// The mutable guards model a negative/revocation generation changing after
// method admission but before the producer's Promise settles. The throw case
// intentionally travels through Readable.from(...).destroy(error), while
// return remains cleanup-only after the same guard has become negative.
// @ref LLP 0019#operation-scoped-positive-authority-provenance [tests]
const [next, rejectedNext, iteratorThrow, syncReturn, asyncReturn] =
  await Promise.all([
    deferredNextSettlement(),
    rejectedNextSettlement(),
    deferredThrowSettlement(),
    iteratorReturnCanary(false),
    iteratorReturnCanary(true),
  ]);

console.log(JSON.stringify({
  deferredNextSettlement: next.outcome,
  deferredNextCalls: next.calls,
  deferredNextSettlementChecks: next.settlementChecks,
  deferredThrowSettlement: iteratorThrow.outcome,
  deferredThrowCalls: iteratorThrow.calls,
  deferredThrowSentinel: iteratorThrow.sentinel,
  deferredThrowSettlementChecks: iteratorThrow.settlementChecks,
  rejectedNext: rejectedNext.outcome,
  rejectedNextCalls: rejectedNext.calls,
  rejectedNextSettlementChecks: rejectedNext.settlementChecks,
  syncReturnCleanup: syncReturn.outcome,
  syncReturnCalls: syncReturn.calls,
  syncReturnCleanupChecks: syncReturn.cleanupChecks,
  syncReturnInput: syncReturn.input,
  asyncReturnCleanup: asyncReturn.outcome,
  asyncReturnCalls: asyncReturn.calls,
  asyncReturnCleanupChecks: asyncReturn.cleanupChecks,
  asyncReturnInput: asyncReturn.input,
}));

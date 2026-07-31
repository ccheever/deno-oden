import { createRequire } from "node:module";
import asyncHooks from "node:async_hooks";
import diagnostics from "node:diagnostics_channel";
import inspector from "node:inspector";
import os from "node:os";
import { execFile, spawn } from "node:child_process";
import traceEvents from "node:trace_events";
import v8 from "node:v8";

const require = createRequire(import.meta.url);
const probe = require("deny-probe");
const existingRootListener = () => {};
const laterRootListener = () => {};
let exceptionCount = 0;
const rootExceptionListener = () => exceptionCount++;
let processSignalCount = 0;
const rootProcessSignalListener = () => processSignalCount++;
const rootResizeListener = () => {};
const rootMetaListener = () => {};
Deno.addSignalListener("SIGUSR2", existingRootListener);
const rootChild = spawn(Deno.execPath(), [
  "eval",
  "setTimeout(() => {}, 10_000)",
]);
const rootExecChild = execFile(
  Deno.execPath(),
  ["eval", "setTimeout(() => {}, 10_000)"],
  { maxBuffer: 1 },
  () => {},
);
const rootDenoChild = new Deno.Command(Deno.execPath(), {
  args: ["eval", "setTimeout(() => {}, 10_000)"],
  stdout: "null",
  stderr: "null",
}).spawn();
let rootDenoExited = false;
const rootDenoStatus = rootDenoChild.status.then((status) => {
  rootDenoExited = true;
  return status;
});
process.on("uncaughtException", rootExceptionListener);
process.on("SIGUSR2", rootProcessSignalListener);
process.on("newListener", rootMetaListener);
const artifactDir = Deno.makeTempDirSync({ prefix: "oden-runtime-control-" });

try {
  let asyncHookInitCount = 0;
  const rootHook = asyncHooks.createHook({
    init() {
      asyncHookInitCount++;
    },
  }).enable();
  const rootChannel = diagnostics.channel("oden-stage-b-active");
  let rootChannelPublishes = 0;
  const rootChannelSubscriber = () => rootChannelPublishes++;
  rootChannel.subscribe(rootChannelSubscriber);
  const rootChannelStore = new asyncHooks.AsyncLocalStorage();
  const rootInactiveChannel = diagnostics.channel("oden-stage-b-inactive");
  const consoleChannel = diagnostics.channel("console.log");
  let internalPublishes = 0;
  const consoleSubscriber = () => internalPublishes++;
  consoleChannel.subscribe(consoleSubscriber);
  const rootBinding = process.binding("async_wrap");
  const rootBindingFields = rootBinding.async_hook_fields;
  const rootBindingDescriptorValue = Object.getOwnPropertyDescriptor(
    rootBinding,
    "async_hook_fields",
  ).value;
  const bindingFieldBefore = rootBindingFields[0];
  const rootTracing = traceEvents.createTracing({ categories: ["node"] });
  rootTracing.enable();
  const rootGcProfiler = new v8.GCProfiler();
  rootGcProfiler.start();
  const rootGcProfilerDispose = new v8.GCProfiler();
  rootGcProfilerDispose.start();
  const rootFatalException = process._fatalException;
  const rootStdoutIsTTY = process.stdout.isTTY === true;
  if (rootStdoutIsTTY) process.stdout.on("resize", rootResizeListener);
  const result = await probe.run({
    cwd: Deno.cwd(),
    artifactDir,
    umask: process.umask(),
    egid: typeof process.getegid === "function" ? process.getegid() : null,
    euid: typeof process.geteuid === "function" ? process.geteuid() : null,
    gid: typeof process.getgid === "function" ? process.getgid() : null,
    uid: typeof process.getuid === "function" ? process.getuid() : null,
    priority: os.getPriority(process.pid),
    title: process.title,
    rootHook,
    rootChannel,
    rootChannelStore,
    rootChannelSubscriber,
    rootChild,
    rootExecChild,
    rootDenoChild,
    rootInactiveChannel,
    rootBinding,
    rootBindingFields,
    rootBindingDescriptorValue,
    rootTracing,
    rootGcProfiler,
    rootGcProfilerDispose,
    rootFatalException,
    rootExceptionListener,
    rootMetaListener,
    rootProcessSignalListener,
    rootSignalListener: existingRootListener,
    inspectorConsole: inspector.console,
    inspectorConsoleLog: inspector.console.log,
    rootResizeListener,
  });

  Deno.addSignalListener("SIGHUP", laterRootListener);
  Deno.kill(Deno.pid, "SIGUSR2");
  Deno.kill(Deno.pid, "SIGHUP");
  await new Promise((resolve) => setTimeout(resolve, 20));
  const counts = probe.signalCounts();
  result.signalExistingLaunder = counts.existing === 0 ? "DENIED" : "LEAKED";
  result.signalFailedAddLaunder = counts.failed === 0 ? "DENIED" : "LEAKED";
  const initCountBeforeCheck = asyncHookInitCount;
  const resource = new asyncHooks.AsyncResource("oden-state-integrity-check");
  resource.emitDestroy();
  result.asyncHookLaunder = result.asyncHookLaunder === "DENIED" &&
      result.asyncHookDisableLaunder === "DENIED" &&
      result.asyncHookReflectMutation === "ALLOWED" &&
      asyncHookInitCount > initCountBeforeCheck
    ? "DENIED"
    : "LEAKED";
  const bindingIntact = result.bindingPassedRead === "DENIED" &&
    result.bindingPassedNestedRead === "DENIED" &&
    result.bindingPassedNestedWrite === "DENIED" &&
    result.bindingDescriptorPassedRead === "DENIED" &&
    result.bindingDescriptorPassedWrite === "DENIED" &&
    rootBindingFields[0] === bindingFieldBefore;
  rootHook.disable();
  rootChannel.publish({ root: true });
  result.diagnosticsUnchanged = result.diagnosticsPublishLaunder === "DENIED" &&
      result.diagnosticsRunStoresLaunder === "DENIED" &&
      result.diagnosticsUnsubscribeLaunder === "DENIED" &&
      result.diagnosticsBindStoreLaunder === "DENIED" &&
      result.diagnosticsUnbindStoreLaunder === "DENIED" &&
      result.diagnosticsBackingRead === "ALLOWED" &&
      result.diagnosticsBackingWrite === "ALLOWED" &&
      rootChannel.hasSubscribers && rootChannelPublishes === 1 &&
      !rootInactiveChannel.hasSubscribers
    ? "DENIED"
    : "LEAKED";
  result.internalDiagnosticsPublish =
    result.internalDiagnosticsPublish === "ALLOWED" && internalPublishes > 0
      ? "ALLOWED"
      : "BROKEN";
  result.bindingUnchanged = bindingIntact ? "DENIED" : "LEAKED";
  result.traceDisableLaunder = result.traceDisableLaunder === "DENIED" &&
      result.traceReflectMutation === "ALLOWED" &&
      Reflect.ownKeys(rootTracing).length === 0 && rootTracing.enabled
    ? "DENIED"
    : "LEAKED";
  rootTracing.disable();
  const rootGcStopReport = rootGcProfiler.stop();
  const rootGcDisposeReport = rootGcProfilerDispose.stop();
  result.gcProfilerUnchanged = result.gcProfilerReflectMutation === "ALLOWED" &&
      result.gcProfilerStopLaunder === "DENIED" &&
      result.gcProfilerDisposeLaunder === "DENIED" &&
      Reflect.ownKeys(rootGcProfiler).length === 0 &&
      Reflect.ownKeys(rootGcProfilerDispose).length === 0 &&
      rootGcStopReport !== undefined && rootGcDisposeReport !== undefined
    ? "DENIED"
    : "LEAKED";
  result.inspectorConsoleSealed = result.inspectorConsoleGet === "DENIED" &&
      result.inspectorConsoleDescriptor === "DENIED" &&
      result.inspectorConsoleOwnKeys === "DENIED" &&
      result.inspectorConsoleSet === "DENIED" &&
      result.inspectorConsoleDefine === "DENIED" &&
      result.inspectorConsoleDelete === "DENIED" &&
      result.inspectorConsolePrototype === "DENIED" &&
      result.inspectorConsoleCall === "DENIED" &&
      result.inspectorConsoleHas === "DENIED" &&
      result.inspectorConsoleSetPrototype === "DENIED" &&
      result.inspectorConsoleIsExtensible === "DENIED" &&
      result.inspectorConsolePreventExtensions === "DENIED" &&
      typeof inspector.console.log === "function"
    ? "DENIED"
    : "LEAKED";
  process.emit(
    "uncaughtException",
    new Error("root state-integrity check"),
    "uncaughtException",
  );
  result.processExceptionRootListenerCount = process.listenerCount(
    "uncaughtException",
    rootExceptionListener,
  );
  result.processExceptionRootEmissionCount = exceptionCount;
  result.processExceptionUnchanged = result.processExceptionOn === "DENIED" &&
      result.processExceptionOnce === "DENIED" &&
      result.processExceptionPrepend === "DENIED" &&
      result.processExceptionPrependOnce === "DENIED" &&
      result.processExceptionRemove === "DENIED" &&
      result.processExceptionRemoveAll === "DENIED" &&
      result.processExceptionEmit === "DENIED" &&
      result.processExceptionBorrowedOn === "DENIED" &&
      result.processExceptionEventsRead === "DENIED" &&
      result.processExceptionEventsWrite === "DENIED" &&
      result.processExceptionEventsOwnKeys === "DENIED" &&
      result.processExceptionEventsDescriptor === "DENIED" &&
      result.processEventsReplace === "DENIED" &&
      result.processExceptionAddListener === "DENIED" &&
      result.processExceptionListenerCount === "DENIED" &&
      result.processExceptionRawListeners === "DENIED" &&
      result.processExceptionRootListenerCount === 1 &&
      result.processExceptionRootEmissionCount === 1
    ? "DENIED"
    : "LEAKED";
  result.processSignalUnchanged = result.processSignalOn === "DENIED" &&
      result.processSignalOnce === "DENIED" &&
      result.processSignalPrepend === "DENIED" &&
      result.processSignalPrependOnce === "DENIED" &&
      result.processSignalRemove === "DENIED" &&
      result.processSignalRemoveAll === "DENIED" &&
      result.processSignalEmit === "DENIED" &&
      result.processSignalObserve === "DENIED" &&
      result.processSignalEventsRead === "DENIED" &&
      result.processSignalEventsDescriptor === "DENIED" &&
      result.processSignalEventsWrite === "DENIED" &&
      result.processSignalAddListener === "DENIED" &&
      result.processSignalListenerCount === "DENIED" &&
      result.processSignalRawListeners === "DENIED" &&
      process.listenerCount("SIGUSR2", rootProcessSignalListener) === 1 &&
      processSignalCount === 1
    ? "DENIED"
    : "LEAKED";
  result.processMetaUnchanged = result.processMetaOn === "DENIED" &&
      result.processMetaEmit === "DENIED" &&
      result.processMetaEventsRead === "DENIED" &&
      result.processMetaEventsDescriptor === "DENIED" &&
      result.processMetaBorrowedOn === "DENIED" &&
      result.processMetaOff === "DENIED" &&
      result.processMetaOnce === "DENIED" &&
      result.processMetaPrepend === "DENIED" &&
      result.processMetaPrependOnce === "DENIED" &&
      result.processMetaRemoveAll === "DENIED" &&
      result.processOrdinaryEvent === "ALLOWED"
    ? "DENIED"
    : "LEAKED";
  result.ttyResizeUnchanged = rootStdoutIsTTY
    ? result.ttyResize === "DENIED" &&
        process.stdout.listenerCount("resize", rootResizeListener) === 1
      ? "DENIED"
      : "LEAKED"
    : "UNAVAILABLE";
  result.nodePassedDisposeDeniedNoKill =
    result.nodePassedDisposeDeniedNoKill === "DENIED"
      ? !rootChild.killed ? "DENIED" : "LEAKED"
      : result.nodePassedDisposeDeniedNoKill;
  result.execFilePassedCleanupNoKill =
    result.execFilePassedCleanupNoKill === "DENIED"
      ? !rootExecChild.killed ? "DENIED" : "LEAKED"
      : result.execFilePassedCleanupNoKill;
  result.denoPassedAsyncDisposeDeniedNoKill =
    result.denoPassedAsyncDisposeDeniedNoKill === "DENIED"
      ? !rootDenoExited ? "DENIED" : "LEAKED"
      : result.denoPassedAsyncDisposeDeniedNoKill;
  rootChannel.unsubscribe(rootChannelSubscriber);
  consoleChannel.unsubscribe(consoleSubscriber);
  console.log(JSON.stringify(result));
} finally {
  rootChild.kill("SIGTERM");
  rootExecChild.kill("SIGTERM");
  try {
    rootDenoChild.kill("SIGTERM");
  } catch {
    // It may have reached its bounded fallback exit already.
  }
  await rootDenoStatus;
  process.removeListener("uncaughtException", rootExceptionListener);
  process.removeListener("SIGUSR2", rootProcessSignalListener);
  process.removeListener("newListener", rootMetaListener);
  if (process.stdout.isTTY === true) {
    process.stdout.removeListener("resize", rootResizeListener);
  }
  try {
    Deno.removeSignalListener("SIGUSR2", existingRootListener);
  } catch {
    // A guard regression may already have removed it; the result records that.
  }
  try {
    Deno.removeSignalListener("SIGHUP", laterRootListener);
  } catch {
    // The root registration may have failed for a platform-specific reason.
  }
  await Deno.remove(artifactDir, { recursive: true });
}

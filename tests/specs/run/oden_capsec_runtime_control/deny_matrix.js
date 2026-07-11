import { createRequire } from "node:module";
import asyncHooks from "node:async_hooks";
import diagnostics from "node:diagnostics_channel";
import inspector from "node:inspector";
import os from "node:os";
import { spawn } from "node:child_process";
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
Deno.addSignalListener("SIGUSR2", existingRootListener);
const rootChild = spawn(Deno.execPath(), [
  "eval",
  "setTimeout(() => {}, 10_000)",
]);
process.on("uncaughtException", rootExceptionListener);
process.on("SIGUSR2", rootProcessSignalListener);

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
    umask: process.umask(),
    identity: typeof process.geteuid === "function" ? process.geteuid() : null,
    priority: os.getPriority(process.pid),
    title: process.title,
    rootHook,
    rootChannel,
    rootChild,
    rootInactiveChannel,
    rootBinding,
    rootBindingFields,
    rootBindingDescriptorValue,
    rootTracing,
    rootGcProfiler,
    rootGcProfilerDispose,
    rootFatalException,
    rootExceptionListener,
    rootProcessSignalListener,
    inspectorConsole: inspector.console,
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
      typeof inspector.console.log === "function"
    ? "DENIED"
    : "LEAKED";
  process.emit(
    "uncaughtException",
    new Error("root state-integrity check"),
    "uncaughtException",
  );
  result.processExceptionUnchanged = result.processExceptionOn === "DENIED" &&
      result.processExceptionOnce === "DENIED" &&
      result.processExceptionPrepend === "DENIED" &&
      result.processExceptionRemove === "DENIED" &&
      result.processExceptionRemoveAll === "DENIED" &&
      result.processExceptionEmit === "DENIED" &&
      result.processExceptionBorrowedOn === "DENIED" &&
      result.processExceptionEventsRead === "DENIED" &&
      result.processExceptionEventsWrite === "DENIED" &&
      result.processExceptionEventsOwnKeys === "DENIED" &&
      result.processExceptionEventsDescriptor === "DENIED" &&
      result.processEventsReplace === "DENIED" &&
      process.listenerCount("uncaughtException", rootExceptionListener) === 1 &&
      exceptionCount === 1
    ? "DENIED"
    : "LEAKED";
  result.processSignalUnchanged = result.processSignalOn === "DENIED" &&
      result.processSignalPrepend === "DENIED" &&
      result.processSignalRemove === "DENIED" &&
      result.processSignalRemoveAll === "DENIED" &&
      result.processSignalEmit === "DENIED" &&
      result.processSignalObserve === "DENIED" &&
      result.processSignalEventsRead === "DENIED" &&
      result.processSignalEventsDescriptor === "DENIED" &&
      result.processSignalEventsWrite === "DENIED" &&
      process.listenerCount("SIGUSR2", rootProcessSignalListener) === 1 &&
      processSignalCount === 1
    ? "DENIED"
    : "LEAKED";
  result.processMetaUnchanged = result.processMetaOn === "DENIED" &&
      result.processMetaEmit === "DENIED" &&
      result.processMetaEventsRead === "DENIED" &&
      result.processMetaEventsDescriptor === "DENIED" &&
      result.processMetaBorrowedOn === "DENIED" &&
      result.processOrdinaryEvent === "ALLOWED"
    ? "DENIED"
    : "LEAKED";
  result.ttyResizeUnchanged = rootStdoutIsTTY
    ? result.ttyResize === "DENIED" &&
        process.stdout.listenerCount("resize", rootResizeListener) === 1
      ? "DENIED"
      : "LEAKED"
    : "UNAVAILABLE";
  rootChannel.unsubscribe(rootChannelSubscriber);
  consoleChannel.unsubscribe(consoleSubscriber);
  console.log(JSON.stringify(result));
} finally {
  rootChild.kill("SIGTERM");
  process.removeListener("uncaughtException", rootExceptionListener);
  process.removeListener("SIGUSR2", rootProcessSignalListener);
  if (process.stdout.isTTY === true) {
    process.stdout.removeListener("resize", rootResizeListener);
  }
  Deno.removeSignalListener("SIGUSR2", existingRootListener);
  try {
    Deno.removeSignalListener("SIGHUP", laterRootListener);
  } catch {
    // The root registration may have failed for a platform-specific reason.
  }
}

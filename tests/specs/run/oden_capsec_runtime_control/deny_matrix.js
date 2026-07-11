import { createRequire } from "node:module";
import asyncHooks from "node:async_hooks";
import diagnostics from "node:diagnostics_channel";
import os from "node:os";
import { spawn } from "node:child_process";

const require = createRequire(import.meta.url);
const probe = require("deny-probe");
const existingRootListener = () => {};
const laterRootListener = () => {};
Deno.addSignalListener("SIGUSR2", existingRootListener);
const rootChild = spawn(Deno.execPath(), ["eval", "setTimeout(() => {}, 10_000)"]);

try {
  const rootHook = asyncHooks.createHook({ init() {} });
  const rootChannel = diagnostics.channel("oden-stage-b-inactive");
  const result = await probe.run({
    cwd: Deno.cwd(),
    umask: process.umask(),
    identity: typeof process.geteuid === "function" ? process.geteuid() : null,
    priority: os.getPriority(process.pid),
    title: process.title,
    rootHook,
    rootChannel,
    rootChild,
  });

  Deno.addSignalListener("SIGHUP", laterRootListener);
  Deno.kill(Deno.pid, "SIGUSR2");
  Deno.kill(Deno.pid, "SIGHUP");
  await new Promise((resolve) => setTimeout(resolve, 20));
  const counts = probe.signalCounts();
  result.signalExistingLaunder = counts.existing === 0 ? "DENIED" : "LEAKED";
  result.signalFailedAddLaunder = counts.failed === 0 ? "DENIED" : "LEAKED";
  result.asyncHookLaunder = result.asyncHookLaunder === "DENIED" &&
      (() => {
        rootHook.enable();
        rootHook.disable();
        return true;
      })()
    ? "DENIED"
    : "LEAKED";
  result.diagnosticsUnchanged = !rootChannel.hasSubscribers ? "DENIED" : "LEAKED";
  console.log(JSON.stringify(result));
} finally {
  rootChild.kill("SIGTERM");
  Deno.removeSignalListener("SIGUSR2", existingRootListener);
  try {
    Deno.removeSignalListener("SIGHUP", laterRootListener);
  } catch {
    // The root registration may have failed for a platform-specific reason.
  }
}

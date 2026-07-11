import { createRequire } from "node:module";
import diagnostics from "node:diagnostics_channel";
import inspector from "node:inspector";
import os from "node:os";

const require = createRequire(import.meta.url);
const denied = require("native-route-denied");
const allowed = require("native-route-allowed");
const openNoListen = require("native-route-open-no-listen");
const marker = Deno.args[0];

function exactDenial(operation, ...fragments) {
  try {
    operation();
    return "LEAKED";
  } catch (error) {
    const isPermission = error instanceof Deno.errors.NotCapable ||
      error instanceof Deno.errors.PermissionDenied ||
      error?.name === "NotCapable" || error?.name === "PermissionDenied";
    const text = String(error);
    return isPermission &&
        fragments.every((fragment) => text.includes(fragment))
      ? "DENIED"
      : `BROKEN:${error?.name ?? "Error"}:${text}`;
  }
}

const results = {};

// @ref LLP 0019#system-information-and-process-mutation [tests] — A custom
// watchdog signal is denied before spawn, while terminal owned-child cleanup
// remains usable.
results.spawnSyncCustomSignal = exactDenial(
  () => denied.spawnSyncCustomSignal(marker),
  `process:signal:spawnSync-watchdog:${os.constants.signals.SIGUSR1}`,
);
try {
  Deno.statSync(marker);
  results.spawnSyncNoEarlyEffect = "LEAKED";
} catch (error) {
  results.spawnSyncNoEarlyEffect = error instanceof Deno.errors.NotFound
    ? "DENIED"
    : "BROKEN";
}
results.spawnSyncTerminalCleanup =
  denied.spawnSyncTerminalCleanup() === "allowed" ? "ALLOWED" : "BROKEN";

let rootSignalCount = 0;
const rootSignal = () => rootSignalCount++;
Deno.addSignalListener("SIGUSR2", rootSignal);
results.signalBind = exactDenial(
  denied.bindSignal,
  "process:signal:listen:SIGUSR2",
);
Deno.kill(Deno.pid, "SIGUSR2");
const signalDeadline = performance.now() + 1_000;
while (rootSignalCount === 0 && performance.now() < signalDeadline) {
  await new Promise((resolve) => setTimeout(resolve, 10));
}
results.signalBindNoMutation = denied.signalCount() === 0 ? "DENIED" : "LEAKED";
results.signalBindRootControl = rootSignalCount === 1 ? "ALLOWED" : "BROKEN";
Deno.removeSignalListener("SIGUSR2", rootSignal);

const inactive = diagnostics.channel("oden-native-route-inactive");
// @ref LLP 0019#runtime-and-memory-inspection [tests] — Passing an inactive
// root channel reaches Channel.subscribe itself without allowing markActive.
results.channelSubscribe = exactDenial(
  () => denied.subscribeChannel(inactive),
  "runtime:inspect:oden-native-route-inactive",
);
results.channelSubscribeNoMutation = inactive.hasSubscribers
  ? "LEAKED"
  : "DENIED";

// @ref LLP 0019#inspector [tests] — Passed listener/session objects do not
// delegate URL observation, listener teardown, or protocol dispatch.
inspector.open(0, "127.0.0.1", false);
const rootSession = new inspector.Session();
rootSession.connect();
const rootUrl = inspector.url();
results.inspectorUrl = exactDenial(
  denied.inspectorUrl,
  "node:inspector.url",
  "inspector:activate",
);
results.inspectorClose = exactDenial(
  denied.inspectorClose,
  "node:inspector.close",
  "inspector:activate",
);
results.inspectorDispatch = exactDenial(
  () => denied.inspectorDispatch(rootSession),
  "node:inspector.Session.post",
  "inspector:activate",
);
results.inspectorPassedSessionIntact = inspector.url() === rootUrl
  ? "DENIED"
  : "LEAKED";
const rootProtocol = await new Promise((resolve, reject) => {
  rootSession.post(
    "Runtime.enable",
    (error) => error ? reject(error) : resolve(true),
  );
});
rootSession.disconnect();
inspector.close();
results.inspectorRootControl = rootProtocol && inspector.url() === undefined
  ? "ALLOWED"
  : "BROKEN";

results.inspectorOpen = exactDenial(
  openNoListen.inspectorOpen,
  "inspector transport",
  "127.0.0.1:0",
  "network:listen:127.0.0.1",
);
results.inspectorOpenNoMutation = inspector.url() === undefined
  ? "DENIED"
  : "LEAKED";
results.inspectorAllowedPackage = await allowed.run() ? "ALLOWED" : "BROKEN";

console.log(JSON.stringify(results));

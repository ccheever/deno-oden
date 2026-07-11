import { createRequire } from "node:module";
import { once } from "node:events";
import { Worker } from "node:worker_threads";

const require = createRequire(import.meta.url);
const probe = require("internal-launder");
const rootFile = await Deno.open("./root-secret.txt");

let finishTimer;
const timerResult = new Promise((resolve) => {
  finishTimer = resolve;
});
const results = probe.run(() => {
  try {
    Deno.cwd();
    finishTimer("LAUNDERED");
  } catch {
    finishTimer("DENIED");
  }
});
results.actorRecovery = await probe.tryRecoverActorAuthority();
results.rootRid = await probe.tryReadRootRid("root-rid-secret");
rootFile.close();
results.timer = await timerResult;

const rawCoreOutcomes = {};
function rawCoreCallback(name) {
  return () => {
    try {
      Deno.cwd();
      rawCoreOutcomes[name] = "LAUNDERED";
    } catch {
      rawCoreOutcomes[name] = "DENIED";
    }
  };
}
const rawCoreExposed = probe.scheduleRawCore({
  createTimer: rawCoreCallback("createTimer"),
  queueNextTick: rawCoreCallback("queueNextTick"),
  refreshTimer: rawCoreCallback("refreshTimer"),
  queueImmediate: rawCoreCallback("queueImmediate"),
});
await new Promise((resolve) => setImmediate(resolve));
await new Promise((resolve) => setTimeout(resolve, 10));
results.rawCore = rawCoreExposed.length === 0
  ? "HIDDEN"
  : `EXPOSED:${rawCoreExposed.join(",")}:${JSON.stringify(rawCoreOutcomes)}`;

const fetchResponse = await fetch("data:text/plain,prototype-probe");
await fetchResponse.body?.cancel();
results.prototype = probe.inheritedRawTargetLeakStatus();

// Deno.serve's default listen path reads raw `internals.log`. If the package's
// accessor installation reached that target, this trusted read would expose
// the raw object as the accessor receiver.
const server = Deno.serve(
  { hostname: "127.0.0.1", port: 0 },
  () => new Response("ok"),
);
await server.shutdown();
results.trustedRead = probe.rawTargetLeakStatus();
console.log(JSON.stringify(results));

// The package's attempted writes and deletes must not poison the raw helpers
// later consumed by trusted worker setup.
const worker = new Worker(new URL("./worker.js", import.meta.url));
const [message] = await once(worker, "message");
worker.unref();
console.log(message);

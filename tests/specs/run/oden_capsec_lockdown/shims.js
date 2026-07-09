// The ENG-23781 lockdown compat tail, exercised under real lockdown:
// 1) the ext/node lazy-write audit -- the lazy node:process bootstrap
//    (buildAllowedFlags via node:cluster), error-constructor `.name`
//    shadowing (AbortError, Deno.errors.*, node error codes);
// 2) the Error-constructor taming -- prepareStackTrace / getCallSites /
//    stackTraceLimit stay assignable while Error is otherwise frozen.
import cluster from "node:cluster";
import util from "node:util";
import fs from "node:fs";

// buildAllowedFlags runs lazily on node:process init via the cluster import;
// pre-lockdown it wrote `keys`/Symbol.iterator over the frozen Set.prototype.
console.log(
  "cluster+allowedNodeEnvironmentFlags:",
  typeof cluster === "object" &&
    process.allowedNodeEnvironmentFlags.size >= 0 &&
    typeof process.allowedNodeEnvironmentFlags[Symbol.iterator] === "function",
);

// Deno.errors.* constructors define `name` on the instance (was a shadowing
// assignment over the frozen Error.prototype.name).
try {
  Deno.lstatSync("./definitely-not-here-xyz");
} catch (e) {
  console.log("deno error class:", e.name, Object.hasOwn(e, "name"));
}

// node error mapping (uv error codes ride the same constructors).
try {
  fs.lstatSync("./definitely-not-here-xyz");
} catch (e) {
  console.log("node error code:", e.code);
}

// AbortError (ext:deno_node/internal/errors.ts) -- the execa-class break.
const ac = new AbortController();
const timer = import("node:timers/promises").then(({ setTimeout: st }) => {
  const p = st(1000, "never", { signal: ac.signal });
  ac.abort();
  return p.catch((e) => console.log("abort error:", e.name, e.code));
});
await timer;

// getCallSites swaps Error.prepareStackTrace under the hood; the taming keeps
// that slot writable while Error itself is frozen.
const sites = util.getCallSites(2);
console.log(
  "getCallSites:",
  Array.isArray(sites) && sites.length > 0 &&
    typeof sites[0].functionName === "string",
);

// Userland source-map-support style install.
const orig = Error.prepareStackTrace;
Error.prepareStackTrace = () => "PST_SHIM_OK";
console.log("prepareStackTrace:", new Error("x").stack);
Error.prepareStackTrace = orig;

// stackTraceLimit must stay a real writable DATA property (V8 reads it with
// GetDataProperty; an accessor would disable stack capture entirely).
Error.stackTraceLimit = 1;
try {
  null.x;
} catch (e) {
  const frames = e.stack.split("\n").filter((l) =>
    l.trim().startsWith("at ")
  ).length;
  console.log("stackTraceLimit:", frames === 1);
}
Error.stackTraceLimit = 10;

// The rest of the Error constructor is pinned.
console.log(
  "error tamed:",
  !Object.isExtensible(Error),
  Object.getOwnPropertyDescriptor(Error, "captureStackTrace").writable ===
    false,
  typeof Error.captureStackTrace === "function",
);

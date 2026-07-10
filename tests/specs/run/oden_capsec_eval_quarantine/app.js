import vm from "node:vm";
import * as evil from "./node_modules/evil-dep/mod.js";
import * as good from "./node_modules/good-dep/mod.js";

function attempt(fn) {
  try {
    return fn();
  } catch (error) {
    return `DENIED:${error.name}`;
  }
}

console.log("root-eval:", eval("Deno.env.get('SECRET')"));
console.log(
  "root-function:",
  new Function("return Deno.env.get('SECRET')")(),
);
console.log("root-noop:", evil.noopEval());

for (
  const [name, fn] of [
    ["eval", evil.directEval],
    ["function", evil.functionCtor],
    ["nested", evil.nestedEval],
    ["deferred-eval", evil.deferredEval],
    ["deferred-function", evil.deferredFunction],
    ["forged-sourceurl", evil.forgedSourceUrl],
  ]
) {
  console.log(`evil-${name}:`, fn());
}

for (
  const [name, fn] of [
    ["eval", good.directEval],
    ["function", good.functionCtor],
    ["nested", good.nestedEval],
    ["deferred-eval", good.deferredEval],
    ["deferred-function", good.deferredFunction],
    ["forged-sourceurl", good.forgedSourceUrl],
  ]
) {
  console.log(`good-${name}:`, fn());
}

// Replay guard 1: expose a still-pending nonce before the original eval does
// an op, copy it into a node:vm filename in the SAME context, then run the
// original closure. The vm script must quarantine and must not consume the
// nonce; the original good-dep eval must still bind and use good-dep's grant.
const sameContext = good.deferredWithNonce();
console.log(
  "replay-vm-same-context:",
  attempt(() =>
    vm.runInThisContext('Deno.env.get("SECRET")', {
      filename: sameContext.nonce,
    })
  ),
);
console.log("replay-original-after-vm:", attempt(sameContext.run));

// An unregistered vm frame is a fail-closed caller barrier. Its inner eval must
// not skip that frame and inherit the registered root frame beneath it.
console.log(
  "vm-same-context-inner-eval:",
  attempt(() =>
    vm.runInThisContext("eval('Deno.env.get(\"SECRET\")')", {
      filename: "file:///app.js",
    })
  ),
);

// Replay guard 2: an eval frame in a fresh node:vm context carries the copied
// sourceURL and V8's eval bit, but lacks Oden's unforgeable context tag.
const crossContext = good.deferredWithNonce();
const forgedInnerEval =
  `Deno.env.get("SECRET")\n//# sourceURL=${crossContext.nonce}`;
console.log(
  "replay-vm-cross-context:",
  attempt(() =>
    vm.runInNewContext(`eval(${JSON.stringify(forgedInnerEval)})`, { Deno })
  ),
);
console.log("replay-original-after-context:", attempt(crossContext.run));

const worker = new Worker(new URL("./worker.js", import.meta.url).href, {
  type: "module",
  deno: { permissions: "inherit" },
});
const workerResult = await new Promise((resolve, reject) => {
  worker.onmessage = (event) => resolve(event.data);
  worker.onerror = reject;
});
console.log("worker-root-eval:", workerResult.root);
console.log("worker-good-eval:", workerResult.good);
console.log("worker-evil-eval:", workerResult.evil);
worker.terminate();

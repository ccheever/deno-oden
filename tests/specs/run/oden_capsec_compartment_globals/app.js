import * as blocked from "./node_modules/blocked-esm/index.js";
import * as granted from "./node_modules/granted-esm/index.js";
import { getFetch } from "./node_modules/grantor-dep/index.js";
import { useLeakedFetch } from "./node_modules/recipient-dep/index.js";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const blockedCjs = require("blocked-cjs");
const grantedCjs = require("granted-cjs");

function result(fn) {
  try {
    return fn();
  } catch (error) {
    const denied = error.message.match(/global "([^"]+)"/);
    return denied ? `${error.name}:${denied[1]}` : error.name;
  }
}

console.log("direct", result(blocked.direct));
console.log("global", JSON.stringify(blocked.globalPaths().map(result)));
console.log("enumeration", JSON.stringify(blocked.enumeration()));
console.log("reflective", result(blocked.reflective));
console.log("eval", JSON.stringify(blocked.evalPaths().map(result)));
console.log(
  "evaluators",
  JSON.stringify(await blocked.evaluatorDenials()),
);
console.log(
  "eval-compat",
  JSON.stringify(blocked.evaluatorCompatibility()),
);
console.log(
  "dynamic-namespaces",
  JSON.stringify(blocked.dynamicNamespaceDenials()),
);
console.log("strict-this", blocked.strictThis());
console.log("node-esm", JSON.stringify(blocked.namespaces().map(result)));
console.log("helper", result(blocked.helperPath));
console.log("async", await blocked.asyncReach());
console.log("local-binding", blocked.localBinding("local-value"));
console.log("granted-esm", JSON.stringify(granted.reachability()));
console.log(
  "granted-evaluators",
  JSON.stringify(await granted.evaluatorReachability()),
);
console.log("blocked-cjs", JSON.stringify(blockedCjs.probe()));
console.log("granted-cjs", JSON.stringify(grantedCjs.probe()));
console.log("cjs-top-this", blockedCjs.topThis);
console.log("node-cjs", JSON.stringify(blockedCjs.nodeBackdoors()));
console.log("leaked-op", JSON.stringify(await useLeakedFetch(getFetch())));

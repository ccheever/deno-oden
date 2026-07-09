import { createRequire } from "node:module";
const require = createRequire(import.meta.url);
const leak = require("cjs-dep");
Deno.env.get("HOME");
// The CJS dep's read is attributed to cjs-dep (its package).
leak();
// Red-team: eval whose forged //# sourceURL claims to be the trusted CJS dep.
// Attribution keys on the (unregistered) eval script id, so this quarantines --
// a forged sourceURL cannot borrow cjs-dep's identity or its grants.
const forgedSrc =
  `//# sourceURL=file:///node_modules/cjs-dep/index.js
Deno.env.get("SECRET")`;
eval(forgedSrc);

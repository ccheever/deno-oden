import { createRequire } from "node:module";
const require = createRequire(import.meta.url);
const leak = require("evil-dep");
try {
  leak();
  console.log("require: ALLOWED");
} catch (e) {
  console.log("require: DENIED", e.constructor.name);
}

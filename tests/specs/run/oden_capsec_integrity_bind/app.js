import { createRequire } from "node:module";
const require = createRequire(import.meta.url);
const out = {};
for (const dep of ["dep-a", "dep-b", "dep-c"]) {
  try {
    out[dep] = require(dep)();
  } catch {
    out[dep] = "LOAD-FAILED";
  }
}
console.log(JSON.stringify(out));

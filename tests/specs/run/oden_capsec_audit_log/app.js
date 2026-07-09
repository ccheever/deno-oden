import { createRequire } from "node:module";
createRequire(import.meta.url)("dep-x")();
console.log("done");

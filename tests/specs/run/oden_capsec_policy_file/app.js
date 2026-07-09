import { createRequire } from "node:module";
console.log(JSON.stringify(createRequire(import.meta.url)("dep-a")()));

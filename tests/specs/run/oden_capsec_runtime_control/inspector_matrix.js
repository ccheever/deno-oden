import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
console.log(JSON.stringify({
  denied: await require("inspector-denied")(),
  noListen: await require("inspector-no-listen")(),
  allowed: await require("inspector-allowed")(),
}));

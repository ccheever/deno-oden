import { createRequire } from "node:module";
import inspector from "node:inspector";

const require = createRequire(import.meta.url);
const rootSession = new inspector.Session();
console.log(JSON.stringify({
  denied: await require("inspector-denied")(rootSession),
  noListen: await require("inspector-no-listen")(),
  allowed: await require("inspector-allowed")(),
}));

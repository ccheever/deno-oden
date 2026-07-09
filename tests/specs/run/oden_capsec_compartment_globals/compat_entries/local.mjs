import { localBinding } from "../node_modules/compat-local/index.js";
if (localBinding("ok") !== "ok") throw new Error("local binding rewritten");
console.log("local ok");

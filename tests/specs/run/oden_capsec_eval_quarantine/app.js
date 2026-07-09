import { tryEval, tryFunction } from "./node_modules/evil-dep/mod.js";
console.log("eval:", tryEval());
console.log("newFunction:", tryFunction());

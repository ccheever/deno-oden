import { compute } from "../node_modules/compat-compute/index.js";
if (compute([1, 2, 3]) !== 6) throw new Error("compute mismatch");
console.log("compute ok");

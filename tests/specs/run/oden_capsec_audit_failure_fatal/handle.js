import { mint } from "./node_modules/handle-dep/index.js";

console.log("handle-before");
try {
  mint();
} catch {
  console.log("handle-caught");
}
console.log("handle-after");

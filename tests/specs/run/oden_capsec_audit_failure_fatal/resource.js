import { openWatcher } from "./node_modules/resource-dep/index.js";

console.log("resource-before");
try {
  openWatcher();
} catch {
  console.log("resource-caught");
}
console.log("resource-after");

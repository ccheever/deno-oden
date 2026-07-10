import { createWorker } from "./node_modules/evil-dep/index.js";

console.log("worker-before");
try {
  createWorker();
} catch {
  console.log("worker-caught");
}
console.log("worker-after");

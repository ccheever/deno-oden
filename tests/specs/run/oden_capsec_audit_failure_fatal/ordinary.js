import { ordinary } from "./node_modules/evil-dep/index.js";

console.log("ordinary-before");
try {
  ordinary();
  console.log("ordinary-allowed");
} catch {
  console.log("ordinary-caught");
}
console.log("ordinary-after");

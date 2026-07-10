import { request } from "./node_modules/evil-dep/index.js";

console.log("request-before");
try {
  console.log(request());
} catch {
  console.log("request-caught");
}
console.log("request-after");

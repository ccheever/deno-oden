import { query } from "./node_modules/evil-dep/index.js";

console.log("query-before");
try {
  console.log(query());
} catch {
  console.log("query-caught");
}
console.log("query-after");

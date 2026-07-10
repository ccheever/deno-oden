import { importData } from "./node_modules/evil-dep/index.js";

console.log("import-before");
try {
  await importData();
} catch {
  console.log("import-caught");
}
console.log("import-after");

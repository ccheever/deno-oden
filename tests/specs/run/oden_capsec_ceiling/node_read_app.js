import { readFileSync } from "node:fs";
try {
  readFileSync("secret.txt", "utf8");
  console.log("READ ok");
} catch (e) {
  console.log("DENIED:", e.name);
}

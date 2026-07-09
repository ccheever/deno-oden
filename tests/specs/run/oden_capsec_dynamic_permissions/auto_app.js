import { exercise } from "./node_modules/requester/index.js";

const result = exercise();
for (const [name, value] of Object.entries(result)) {
  console.log(`${name}: ${value}`);
}
const requests = Deno.readTextFileSync("auto-audit.ndjson").trim().split("\n")
  .map((line) => JSON.parse(line))
  .filter((row) => row.event === "dynamic_request");
console.log(`request-codes: ${requests.map((row) => row.code).join(",")}`);

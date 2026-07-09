import { exercise } from "./node_modules/prompter-dep/index.js";

const result = exercise();
console.log(`first: ${result.first}`);
console.log(`second: ${result.second}`);
const requests = Deno.readTextFileSync("prompt-audit.ndjson").trim().split("\n")
  .map((line) => JSON.parse(line))
  .filter((row) => row.event === "dynamic_request");
console.log(`codes: ${requests.map((row) => row.code).join(",")}`);
console.log(`memoized: ${requests.map((row) => row.memoized).join(",")}`);

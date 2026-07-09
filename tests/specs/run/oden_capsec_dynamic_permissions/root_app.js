const descriptor = { name: "env", variable: "ROOT_VALUE" };
console.log(`query: ${Deno.permissions.querySync(descriptor).state}`);
console.log(`request: ${Deno.permissions.requestSync(descriptor).state}`);
const dynamic = Deno.readTextFileSync("root-audit.ndjson").trim().split("\n")
  .filter(Boolean)
  .map((line) => JSON.parse(line))
  .filter((row) =>
    row.event === "dynamic_request" || row.event === "dynamic_permission"
  );
console.log(`dynamic-events: ${dynamic.length}`);

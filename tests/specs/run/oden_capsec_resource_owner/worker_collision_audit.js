const rows = Deno.readTextFileSync("worker-collision-audit.ndjson").trim()
  .split("\n")
  .map((line) => JSON.parse(line));
const owns = rows.filter((row) =>
  row.capability === "fs:watch:own" &&
  (row.principal === "worker-a" || row.principal === "worker-b")
);
const principals = [...new Set(owns.map((row) => row.principal))].sort();
const rids = new Set(owns.map((row) => row.target));
console.log(`owners:${principals.join(",")}`);
console.log(`same-rid:${owns.length === 2 && rids.size === 1}`);

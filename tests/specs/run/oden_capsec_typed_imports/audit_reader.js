const expected = [
  "computed-bytes.bin",
  "computed-json.json",
  "computed-text.txt",
  "literal-bytes.bin",
  "literal-json.json",
  "literal-text.txt",
  "require.json",
  "static-bytes.bin",
  "static-json.json",
  "static-text.txt",
];
const observed = new Map(expected.map((name) => [name, 0]));
for (
  const line of Deno.readTextFileSync("typed-audit.ndjson").trim().split("\n")
) {
  const row = JSON.parse(line);
  if (row.principal !== "typed-good" || row.capability !== "fs:read") continue;
  const name = String(row.target).split(/[\\/]/).at(-1);
  if (name && observed.has(name)) observed.set(name, observed.get(name) + 1);
}
for (const name of expected) console.log(`${name}:${observed.get(name)}`);

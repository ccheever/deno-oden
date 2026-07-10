const mode = Deno.args[0];
await Deno.mkdir("control", { recursive: true });
await Deno.writeFile("control/audit.key", new Uint8Array(32), { mode: 0o600 });
await Deno.writeTextFile(
  "control/policy.json",
  JSON.stringify({
    mode: "enforce",
    grants: { "audit-overflow": "env:read:*" },
  }),
  { mode: 0o600 },
);
if (mode === "overflow") {
  await Deno.writeTextFile("control/audit.ndjson", "", { mode: 0o600 });
} else if (mode === "broken") {
  await Deno.mkdir("control/unavailable");
} else {
  throw new Error(`unknown setup mode: ${mode}`);
}

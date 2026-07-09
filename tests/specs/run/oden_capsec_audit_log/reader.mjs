for (const l of Deno.readTextFileSync("audit.ndjson").trim().split("\n")) {
  const r = JSON.parse(l);
  if (r.principal === "dep-x" && r.capability === "env:read") {
    console.log(r.target, r.decision);
  }
}

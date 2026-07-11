// Copyright 2018-2026 the Deno authors. MIT license.

Deno.test("unarmed test internals preserve the upstream hook surface", () => {
  const internals = Deno[Deno.internal] as Record<PropertyKey, unknown>;
  if (typeof internals.installTestIsolateExitHandler !== "function") {
    throw new Error("missing installTestIsolateExitHandler");
  }
  if (typeof internals.flushTestSnapshots !== "function") {
    throw new Error("missing flushTestSnapshots");
  }
  if (Object.hasOwn(internals, "testSnapshotInUpdateMode")) {
    throw new Error("unarmed internals gained private armed snapshot hook");
  }
});

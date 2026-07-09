// Closed global inventory probe (LLP 0001 Phase 1). Enumerates the powerful
// ambient surface capsec must keep out of user reach. Armed, every entry must be
// sealed/removed; if a rebase re-exposes one, REACHABLE-powerful goes non-empty
// and the armed assertion fails -- a new reachable powerful global to classify.
const internal = Deno[Deno.internal];
const c = internal?.core;
const powerful = [
  "AsyncVariable", "compileFunction", "evalContext", "getAsyncContext",
  "kNoAsyncContextRestore", "scopeAsyncContext", "setAsyncContext",
];
const reachable = powerful.filter((k) => c && typeof c[k] !== "undefined").sort();
console.log("bootstrap:", typeof globalThis.__bootstrap);
console.log("Deno.core:", typeof Deno.core);
console.log("extras-op:", typeof c?.ops?.op_get_extras_binding_object);
console.log("REACHABLE-powerful:", JSON.stringify(reachable));

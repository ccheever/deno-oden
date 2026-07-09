// Oden capsec Phase-0: CPED seal conformance (LLP 0001 async attribution).
// Conditions 1 (sealed) and 2 (AsyncLocalStorage coexists) are proven here in
// user space; conditions 3 and 4 are proven by the trusted bootstrap self-test
// (ODEN_CAPSEC_SEAL_SELFTEST), which prints to stderr before this runs.
const internal = Deno[Deno.internal];
const c = internal?.core;
const names = [
  "getAsyncContext",
  "setAsyncContext",
  "scopeAsyncContext",
  "AsyncVariable",
  "kNoAsyncContextRestore",
  // Script-creation forgery surface: registering under a forged specifier.
  "compileFunction",
  "evalContext",
];
let sealed = true;
for (const n of names) {
  if (c && typeof c[n] !== "undefined") sealed = false;
}
if (c?.ops?.op_get_extras_binding_object) sealed = false;
console.log(`cond1 sealed: ${sealed ? "PASS" : "FAIL"}`);

import { AsyncLocalStorage } from "node:async_hooks";
const als = new AsyncLocalStorage();
async function deep() {
  await new Promise((r) => setTimeout(r, 1));
  await Promise.resolve();
  return als.getStore();
}
const got = await als.run({ reqId: 42 }, async () => {
  const a = als.getStore()?.reqId;
  const b = await deep();
  return { a, b: b?.reqId };
});
const coexists = got.a === 42 && got.b === 42 && als.getStore() === undefined;
console.log(`cond2 coexists: ${coexists ? "PASS" : "FAIL"}`);

import { leak } from "./node_modules/evil-dep/mod.js";
leak();
// Drive collection for the FinalizationRegistry channel across several
// event-loop turns so its cleanup task is scheduled and drained; --expose-gc
// (set in __test__.jsonc) makes globalThis.gc available and deterministic.
for (let turn = 0; turn < 5; turn++) {
  if (globalThis.gc) {
    for (let i = 0; i < 8; i++) globalThis.gc();
  }
  await new Promise((r) => setTimeout(r, 30));
}

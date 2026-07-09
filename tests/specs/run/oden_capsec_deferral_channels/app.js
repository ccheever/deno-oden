import { leak } from "./node_modules/evil-dep/mod.js";
leak();
// Keep the event loop alive long enough for timers / setImmediate to fire.
await new Promise((r) => setTimeout(r, 50));

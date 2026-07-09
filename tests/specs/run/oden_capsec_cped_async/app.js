import { leak } from "./node_modules/evil-dep/mod.js";
// Root does a benign op first (stamps CPED = root), then schedules a detached,
// frame-less op of the SAME shape as evil-dep's. It must attribute to root
// (ambient) via row 2, while evil-dep's detached op attributes to evil-dep --
// proving the decision keys on who scheduled the callback, not the live stack.
Deno.env.get("HOME");
setTimeout(Deno.env.get.bind(null, "ROOT_SECRET"), 0);
leak();

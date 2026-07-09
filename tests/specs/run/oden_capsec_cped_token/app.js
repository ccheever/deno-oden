import { leak } from "./node_modules/evil-dep/mod.js";
// Same shape as oden_capsec_cped_async, but run under the ODEN_CAPSEC_FORGE_CPED
// red-team hook: the stamp writes an UNREGISTERED token. Row-1 (live-frame) ops
// still attribute correctly, but the detached row-2 reads resolve a stale token
// -> the no-user sentinel + a stale-token audit signal, never the scheduler.
Deno.env.get("HOME");
setTimeout(Deno.env.get.bind(null, "ROOT_SECRET"), 0);
leak();

import { leak } from "./node_modules/evil-dep/mod.js";
// Same shape as oden_capsec_cped_async, but run under the ODEN_CAPSEC_FORGE_CPED
// red-team hook: the stamp writes an UNREGISTERED token. Row-1 (live-frame) ops
// still attribute correctly, but detached non-boundary microtask reads resolve a
// stale token -> the no-user sentinel + a stale-token audit signal, never the
// scheduler. Timer/immediate snapshots have their own independent forge test.
Deno.env.get("HOME");
queueMicrotask(Deno.env.get.bind(null, "ROOT_SECRET"));
leak();

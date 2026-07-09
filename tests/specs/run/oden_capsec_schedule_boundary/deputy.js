import {
  schedule,
  scheduleThroughDeputy,
} from "./node_modules/evil-dep/deputy.js";
import { touch } from "./node_modules/evil-dep/sync.js";
import { read } from "./node_modules/lib-dep/index.js";

// Regression guard for the unsound op-slot approach: evil-dep acts, then the
// granted lib-dep performs its own unrelated synchronous op. The earlier
// principal must not pollute lib-dep's decision.
touch();
read("sync-own");

// Async confused deputy: evil-dep schedules lib-dep's bound function. At
// callback time only lib-dep has a live frame; the schedule slot must append
// evil-dep when env is an armed deputy class.
schedule();
await new Promise((resolve) => setTimeout(resolve, 20));
// Stronger nested form: evil-dep calls granted lib-dep, and lib-dep itself
// schedules its bound callback through setImmediate. The schedule snapshot must
// carry the complete [lib-dep, evil-dep] stack, not only the nearest lib-dep
// frame; separating the two callbacks also makes their assertions deterministic.
scheduleThroughDeputy();
await new Promise((resolve) => setTimeout(resolve, 20));

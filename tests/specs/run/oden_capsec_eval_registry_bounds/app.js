import { leavePending } from "./node_modules/evil-dep/mod.js";
import { executeOutOfOrder } from "./node_modules/good-dep/mod.js";

function rootOpSample(iterations) {
  const start = performance.now();
  for (let i = 0; i < iterations; i++) {
    Deno.env.get("SECRET");
  }
  return performance.now() - start;
}

for (let i = 0; i < 3; i++) rootOpSample(4_000);
const baseline = Math.min(
  ...Array.from({ length: 5 }, () => rootOpSample(4_000)),
);

leavePending();
console.log("out-of-order-attribution:", executeOutOfOrder(5_000));

const withAbandonedEval = Math.min(
  ...Array.from({ length: 5 }, () => rootOpSample(4_000)),
);
if (withAbandonedEval > Math.max(baseline * 8, baseline + 250)) {
  throw new Error(
    `abandoned eval slowed root ops: baseline=${baseline}ms armed=${withAbandonedEval}ms`,
  );
}
console.log("root-hot-path-unaffected:", true);

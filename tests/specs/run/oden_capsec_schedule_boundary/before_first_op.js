// The dependency schedules a bound-native op before doing any gated op. The
// callback has no user frame, so only the snapshot-scoped schedule slot can
// attribute it to first-dep. Audit mode keeps the expected denial record from
// terminating the process.
import "./node_modules/first-dep/index.js";
await new Promise((resolve) => setTimeout(resolve, 40));
console.log("before-first-op: done");

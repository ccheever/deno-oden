// Root (first-party, ambient) doing the same dynamic import is allowed.
const m = await import("data:text/javascript,export const v = 7;");
console.log("root pulled " + m.v);

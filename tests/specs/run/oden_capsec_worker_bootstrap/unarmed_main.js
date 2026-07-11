const internals = Deno[Deno.internal];
const upstreamPrototype = Object.getPrototypeOf(internals) === Object.prototype;
const inheritedMethods = typeof internals.hasOwnProperty === "function" &&
  typeof internals.toString === "function";
console.log(
  upstreamPrototype && inheritedMethods
    ? "unarmed-internals-prototype-ok"
    : "unarmed-internals-prototype-changed",
);

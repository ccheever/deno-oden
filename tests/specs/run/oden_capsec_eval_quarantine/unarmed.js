const value = { marker: "same" };
const stack = eval("new Error().stack");
console.log("unarmed-eval:", eval("40 + 2"));
console.log("unarmed-function:", new Function("return 6 * 7")());
console.log("unarmed-noop:", eval(value) === value);
console.log("unarmed-no-oden-sourceurl:", !stack.includes("oden-eval://"));

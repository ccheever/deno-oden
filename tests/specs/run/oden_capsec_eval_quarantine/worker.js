import { directEval as evilEval } from "./node_modules/evil-dep/mod.js";
import { directEval as goodEval } from "./node_modules/good-dep/mod.js";

let root;
try {
  root = eval("Deno.env.get('SECRET')");
} catch (error) {
  root = `DENIED:${error.name}`;
}
postMessage({ root, good: goodEval(), evil: evilEval() });

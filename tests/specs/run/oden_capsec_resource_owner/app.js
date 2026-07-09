import { openWatch } from "./node_modules/watcher-dep/index.js";
import { poll } from "./node_modules/poller-dep/index.js";
const watcher = openWatch("./watchdir");
console.log(await poll(watcher));

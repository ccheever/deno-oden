import { fetchType } from "../node_modules/compat-fetch/index.js";
if (fetchType() !== "function") throw new Error("fetch missing");
console.log("fetch ok");

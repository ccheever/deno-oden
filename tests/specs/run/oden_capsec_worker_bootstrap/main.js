import { once } from "node:events";
import { Worker } from "node:worker_threads";

const worker = new Worker(new URL("./worker.js", import.meta.url));
const [message] = await once(worker, "message");
worker.unref();
console.log(message);

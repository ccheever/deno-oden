import { once } from "node:events";
import { Worker as NodeWorker } from "node:worker_threads";

const worker = new NodeWorker(new URL("./worker.js", import.meta.url));
const [message] = await once(worker, "message");
worker.unref();
console.log(message);

const webWorker = new Worker(new URL("./web_worker.js", import.meta.url), {
  type: "module",
});
const webWorkerMessage = await new Promise((resolve, reject) => {
  webWorker.onmessage = (event) => resolve(event.data);
  webWorker.onerror = (event) => reject(event.error ?? event.message);
});
webWorker.terminate();
console.log(webWorkerMessage);

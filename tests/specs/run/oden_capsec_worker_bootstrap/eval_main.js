import { once } from "node:events";
import { Worker } from "node:worker_threads";

async function receive(worker) {
  const [message] = await once(worker, "message");
  worker.unref();
  return message;
}

const evalWorker = new Worker(
  'const { parentPort } = require("node:worker_threads"); ' +
    'parentPort.postMessage("eval-worker-ok");',
  { eval: true },
);
console.log(await receive(evalWorker));

const source = 'import { parentPort } from "node:worker_threads"; ' +
  'parentPort.postMessage("data-worker-ok");';
const dataWorker = new Worker(
  new URL(`data:text/javascript,${encodeURIComponent(source)}`),
);
console.log(await receive(dataWorker));

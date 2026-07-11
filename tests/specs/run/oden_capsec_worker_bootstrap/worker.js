import process from "node:process";
import { parentPort } from "node:worker_threads";

const normalizedArgv = process.argv[1].replaceAll("\\", "/");
parentPort.postMessage(
  normalizedArgv.endsWith("/worker.js")
    ? "worker-bootstrap-ok"
    : `unexpected-worker-argv:${process.argv[1]}`,
);

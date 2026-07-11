import process from "node:process";

const normalizedArgv = process.argv[1].replaceAll("\\", "/");
self.postMessage(
  normalizedArgv.endsWith("/web_worker.js")
    ? "web-worker-process-bootstrap-ok"
    : `unexpected-web-worker-argv:${process.argv[1]}`,
);

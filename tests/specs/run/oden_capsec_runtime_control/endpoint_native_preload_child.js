import inspector from "node:inspector";
import { createRequire } from "node:module";

const port = Number(Deno.args[0]);
const require = createRequire(import.meta.url);
const probe = require("native-stream-denied");
const poison = probe.poisonBeforeNetLoad();

function bounded(promise, label, milliseconds = 2_000) {
  let timeoutId;
  const timeout = new Promise((_, reject) => {
    timeoutId = setTimeout(
      () => reject(new Error(`${label} timed out`)),
      milliseconds,
    );
  });
  return Promise.race([promise, timeout]).finally(() =>
    clearTimeout(timeoutId)
  );
}

let socket;
try {
  const net = await import("node:net");
  socket = new net.Socket();
  socket.pause();
  await bounded(
    new Promise((resolve, reject) => {
      socket.once("connect", resolve);
      socket.once("error", reject);
      socket.connect(port, "127.0.0.1");
    }),
    "preload-poison connect",
  );

  let response = "";
  const ended = new Promise((resolve, reject) => {
    socket.on("data", (chunk) => {
      response += chunk.toString();
    });
    socket.once("end", resolve);
    socket.once("error", reject);
  });
  socket.write(
    "GET /json/list HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
  );
  socket.resume();
  await bounded(ended, "preload-poison response");
  const snapshot = poison.snapshot();
  const zero = Object.values(snapshot.counters).every((value) => value === 0);
  console.log(JSON.stringify({
    passedNodeNativePreloadPoison: response.includes("webSocketDebuggerUrl") &&
        snapshot.tcpSurfaceBlocked && zero
      ? "DENIED"
      : "BROKEN",
  }));
} finally {
  socket?.destroy();
  poison.restore();
  inspector.close();
}

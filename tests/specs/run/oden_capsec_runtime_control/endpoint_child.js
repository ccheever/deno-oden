import inspector from "node:inspector";
import net from "node:net";
import { createRequire } from "node:module";

const port = Number(Deno.args[0]);
const wsUrl = inspector.url();
if (!wsUrl) throw new Error("startup inspector URL missing");
const httpUrl = `http://127.0.0.1:${port}/json/list`;
const dnsHttpUrl = `http://localhost:${port}/json/list`;
const dnsWsUrl = wsUrl.replace("127.0.0.1", "localhost");
const require = createRequire(import.meta.url);
const endpointProbe = require("endpoint-denied");

const denoConn = await Deno.connect({ hostname: "127.0.0.1", port });
const nodeSocket = await new Promise((resolve, reject) => {
  const socket = net.connect(port, "127.0.0.1", () => resolve(socket));
  socket.once("error", reject);
});
const rootResponse = await fetch(httpUrl);
const rootDnsResponse = await fetch(dnsHttpUrl);
const rootWebSocket = await new Promise((resolve, reject) => {
  const socket = new WebSocket(wsUrl);
  socket.addEventListener("open", () => resolve(socket), { once: true });
  socket.addEventListener("error", () => reject(new Error("root websocket failed")), {
    once: true,
  });
});
const rootDnsWebSocket = await new Promise((resolve, reject) => {
  const socket = new WebSocket(dnsWsUrl);
  socket.addEventListener("open", () => resolve(socket), { once: true });
  socket.addEventListener("error", () => reject(new Error("root DNS websocket failed")), {
    once: true,
  });
});

const readDenoConn = await Deno.connect({ hostname: "127.0.0.1", port });
await readDenoConn.write(
  new TextEncoder().encode("GET /json/list HTTP/1.1\r\nHost: localhost\r\n\r\n"),
);
const readNodeSocket = await new Promise((resolve, reject) => {
  const socket = net.connect(port, "localhost", () => resolve(socket));
  socket.once("error", reject);
});
readNodeSocket.write("GET /json/list HTTP/1.1\r\nHost: localhost\r\n\r\n");
const readWebSocket = await new Promise((resolve, reject) => {
  const socket = new WebSocket(dnsWsUrl);
  socket.addEventListener("open", () => resolve(socket), { once: true });
  socket.addEventListener("error", () => reject(new Error("root read websocket failed")), {
    once: true,
  });
});
readWebSocket.send(JSON.stringify({
  id: 42,
  method: "Runtime.evaluate",
  params: { expression: "'protected-inspector-byte'" },
}));

try {
  const result = await endpointProbe({
    dnsHttpUrl,
    dnsWsUrl,
    denoConn,
    httpUrl,
    nodeSocket,
    readDenoConn,
    readNodeSocket,
    readWebSocket,
    rootResponse,
    rootDnsResponse,
    rootWebSocket,
    rootDnsWebSocket,
    wsUrl,
  });
  const responseAfterClose = await fetch(dnsHttpUrl);
  inspector.close();
  result.passedResponseAfterClose = await endpointProbe.afterClose(
    responseAfterClose,
  );
  console.log(JSON.stringify(result));
} finally {
  denoConn.close();
  readDenoConn.close();
  nodeSocket.destroy();
  readNodeSocket.destroy();
  rootWebSocket.close();
  rootDnsWebSocket.close();
  readWebSocket.close();
}

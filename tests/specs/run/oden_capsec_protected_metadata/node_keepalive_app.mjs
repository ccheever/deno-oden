import http from "node:http";

const peers = new Set();
const server = Deno.serve(
  { hostname: "127.0.0.1", port: 0, onListen() {} },
  (_request, info) => {
    peers.add(`${info.remoteAddr.hostname}:${info.remoteAddr.port}`);
    return new Response("ok");
  },
);
const agent = new http.Agent({ keepAlive: true, maxSockets: 1 });

async function request(path) {
  await new Promise((resolve, reject) => {
    http.get(
      { hostname: "127.0.0.1", port: server.addr.port, path, agent },
      (response) => {
        response.resume();
        response.on("end", resolve);
      },
    ).on("error", reject);
  });
}

await request("/one");
await request("/two");
agent.destroy();
await server.shutdown();
console.log(`NODE_KEEPALIVE:${peers.size === 2 ? "RECHECKED" : "REUSED"}`);

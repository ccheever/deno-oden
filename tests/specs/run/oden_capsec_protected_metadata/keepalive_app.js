const peers = new Set();
const server = Deno.serve(
  { hostname: "127.0.0.1", port: 0, onListen() {} },
  (_request, info) => {
    peers.add(`${info.remoteAddr.hostname}:${info.remoteAddr.port}`);
    return new Response("ok");
  },
);

for (let index = 0; index < 2; index++) {
  const response = await fetch(`http://127.0.0.1:${server.addr.port}/${index}`);
  await response.text();
}
await server.shutdown();
console.log(`KEEPALIVE:${peers.size === 2 ? "RECHECKED" : "REUSED"}`);

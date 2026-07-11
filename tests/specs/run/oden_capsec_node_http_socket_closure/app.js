import http from "node:http";
import {
  runNodeHttpSocketRoutes,
  runUrlSchemeMatrix,
} from "./node_modules/node-http-closure-probe/index.js";

function track(server) {
  const sockets = new Set();
  server.on("connection", (socket) => {
    sockets.add(socket);
    socket.once("close", () => sockets.delete(socket));
  });
  return sockets;
}

function listen(server, options) {
  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(options, () => {
      server.removeListener("error", reject);
      resolve();
    });
  });
}

async function close(server, sockets) {
  for (const socket of sockets) socket.destroy();
  await new Promise((resolve) => server.close(resolve));
}

async function runRoutes(expected) {
  const handler = (request, response) => {
    if (request.url === "/redirect") {
      response.writeHead(302, { location: "/ok" });
      response.end();
    } else {
      response.writeHead(200, { connection: "keep-alive" });
      response.end("ok");
    }
  };
  const server = http.createServer(handler);
  const serverSockets = track(server);
  server.on("connect", (_request, socket) => {
    socket.write("HTTP/1.1 200 Connection Established\r\n\r\n");
    socket.on("data", (chunk) => socket.write(chunk));
  });
  server.on("upgrade", (_request, socket) => {
    socket.write(
      "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: oden-test\r\n\r\n",
    );
    socket.on("data", (chunk) => socket.write(chunk));
  });

  // Keep the AF_UNIX path below the platform limit even when this fixture is
  // copied into a deeply nested integration-test directory.
  const unixPath = `/tmp/oden-node-http-${Deno.pid}.sock`;
  try {
    Deno.removeSync(unixPath);
  } catch {
    // Absent before the test is expected.
  }
  const unixServer = http.createServer(handler);
  const unixSockets = track(unixServer);
  const proxyServer = http.createServer((_request, response) => {
    response.writeHead(200, { connection: "close" });
    response.end("proxy");
  });
  const proxySockets = track(proxyServer);

  await listen(server, { hostname: "127.0.0.1", port: 0 });
  await listen(unixServer, unixPath);
  await listen(proxyServer, { hostname: "127.0.0.1", port: 0 });
  const port = server.address().port;
  const proxyPort = proxyServer.address().port;
  try {
    await runNodeHttpSocketRoutes(expected, {
      origin: `http://127.0.0.1:${port}`,
      proxy: `http://127.0.0.1:${proxyPort}`,
      unixPath,
    });
  } finally {
    await close(server, serverSockets);
    await close(unixServer, unixSockets);
    await close(proxyServer, proxySockets);
    try {
      Deno.removeSync(unixPath);
    } catch {
      // The runtime may remove a closed Unix listener itself.
    }
  }
}

const fixtureMode = Deno.env.get("ODEN_TEST_FIXTURE_MODE") ?? Deno.args[0];
const fixtureExpected = Deno.env.get("ODEN_TEST_FIXTURE_EXPECTED") ?? Deno.args[1];
if (fixtureMode === "routes") {
  await runRoutes(fixtureExpected);
} else if (fixtureMode === "schemes") {
  await runUrlSchemeMatrix(
    fixtureExpected,
    new URL("./fixture.txt", import.meta.url),
  );
} else {
  throw new Error(`unknown fixture mode: ${fixtureMode}`);
}

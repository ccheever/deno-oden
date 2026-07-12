import http from "node:http";
import https from "node:https";
import diagnosticsChannel from "node:diagnostics_channel";
import {
  runNodeHttpSocketRoutes,
  runQueuedBuiltInHttpsReplacement,
  runQueuedBuiltInReplacement,
  runUrlSchemeMatrix,
} from "./node_modules/node-http-closure-probe/index.js";
import {
  createOwnerAlternatingAddRequestAgent,
  createOwnerAlternatingCreateConnectionAgent,
  createOwnerAlternatingCreateSocketAgent,
  createOwnerBrandedCallbackFactory,
  createOwnerBrandedCreateSocketOverride,
  createOwnerBrandedReturnFactory,
  createOwnerBrandedSyncAgent,
  createOwnerCallbackCreateConnection,
  createOwnerDelayedAgent,
  createOwnerForgedEndpointAgent,
  createOwnerFreeSocketsAgent,
  createOwnerHttpAgentForHttps,
  createOwnerHttpsAgentWithHttpFactory,
  createOwnerPoisonedPoolAgent,
  createOwnerPublicFreeAgent,
  createOwnerSyncAgent,
  createOwnerSyncCreateConnection,
  installOwnerClientRequestAgentAccessor,
  installOwnerNetCreateConnectionOverride,
  installOwnerNetSocketConnectOverride,
  installOwnerOnSocketOverride,
  installOwnerTlsSocketConnectOverride,
  openSocket,
  openUnixSocket,
} from "./node_modules/socket-owner/index.js";
import {
  checkNativeTcpSocket,
  checkNativeUnixSocket,
  requestHttps,
  requestWithAgent,
  requestWithAgentLikeSocket,
  requestWithAlternatingHostname,
  requestWithAlternatingPort,
  requestWithAlternatingPortCoercion,
  requestWithAlternatingSocketPath,
  requestWithCreateConnectionSocket,
  requestWithDelayedAgentLikeSocket,
  requestWithExternalCreateConnectionSocket,
  requestWithFalsyAgent,
  requestWithHttpsSocket,
  requestWithInvalidPortString,
  requestWithReusedAgentLikeSocket,
  requestWithUnixAgentLikeSocket,
  requestWithUnixCreateConnectionSocket,
} from "./node_modules/socket-borrower/index.js";

function track(server, onBytes = () => {}) {
  const sockets = new Set();
  server.on("connection", (socket) => {
    sockets.add(socket);
    socket.on("data", (chunk) => onBytes(chunk.length));
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
  let countBorrowedRequests = false;
  let borrowedRequests = 0;
  let borrowedBytes = 0;
  let injectedBytes = 0;
  let proxyBytes = 0;
  let proxyConnections = 0;
  let routeBytes = 0;
  let routeConnections = 0;
  const handler = (request, response) => {
    if (countBorrowedRequests) borrowedRequests++;
    if (request.url === "/queued-first") {
      setTimeout(() => {
        response.writeHead(200, { connection: "keep-alive" });
        response.end("queued first");
      }, 40);
    } else if (request.url === "/redirect") {
      response.writeHead(302, { location: "/ok" });
      response.end();
    } else {
      response.writeHead(200, { connection: "keep-alive" });
      response.end("ok");
    }
  };
  const server = http.createServer(handler);
  server.on("connection", () => routeConnections++);
  const serverSockets = track(server, (bytes) => {
    routeBytes += bytes;
    if (countBorrowedRequests) borrowedBytes += bytes;
  });
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
  const injectionUnixPath = `/tmp/oden-node-http-inject-${Deno.pid}.sock`;
  for (const path of [unixPath, injectionUnixPath]) {
    try {
      Deno.removeSync(path);
    } catch {
      // Absent before the test is expected.
    }
  }
  const unixServer = http.createServer(handler);
  unixServer.on("connection", () => routeConnections++);
  const unixSockets = track(unixServer, (bytes) => {
    routeBytes += bytes;
    if (countBorrowedRequests) borrowedBytes += bytes;
  });
  const injectionServer = http.createServer((_request, response) => {
    response.writeHead(200, { connection: "close" });
    response.end("injected transport reached");
  });
  const injectionSockets = track(
    injectionServer,
    (bytes) => injectedBytes += bytes,
  );
  const injectionUnixServer = http.createServer((_request, response) => {
    response.writeHead(200, { connection: "close" });
    response.end("injected Unix transport reached");
  });
  const injectionUnixSockets = track(
    injectionUnixServer,
    (bytes) => injectedBytes += bytes,
  );
  const proxyServer = http.createServer((_request, response) => {
    response.writeHead(200, { connection: "close" });
    response.end("proxy");
  });
  proxyServer.on("connection", () => proxyConnections++);
  proxyServer.on("connection", () => routeConnections++);
  const proxySockets = track(proxyServer, (bytes) => {
    proxyBytes += bytes;
    routeBytes += bytes;
  });
  const httpsServer = https.createServer({
    cert: Deno.readTextFileSync(new URL("./localhost.crt", import.meta.url)),
    key: Deno.readTextFileSync(new URL("./localhost.key", import.meta.url)),
  }, handler);
  httpsServer.on("connection", () => routeConnections++);
  const httpsSockets = track(httpsServer, (bytes) => {
    routeBytes += bytes;
    if (countBorrowedRequests) borrowedBytes += bytes;
  });

  await listen(server, { hostname: "127.0.0.1", port: 0 });
  await listen(unixServer, unixPath);
  await listen(proxyServer, { hostname: "127.0.0.1", port: 0 });
  await listen(httpsServer, { hostname: "127.0.0.1", port: 0 });
  await listen(injectionServer, { hostname: "127.0.0.1", port: 0 });
  await listen(injectionUnixServer, injectionUnixPath);
  const port = server.address().port;
  const proxyPort = proxyServer.address().port;
  try {
    await runNodeHttpSocketRoutes(
      expected,
      {
        origin: `http://127.0.0.1:${port}`,
        httpsOrigin: `https://127.0.0.1:${httpsServer.address().port}`,
        proxy: `http://127.0.0.1:${proxyPort}`,
        unixPath,
      },
      () => routeBytes,
      () => routeConnections,
    );
    if (expected === "connect") {
      await runQueuedBuiltInReplacement(`http://127.0.0.1:${port}`);
      await runQueuedBuiltInHttpsReplacement(
        `https://127.0.0.1:${httpsServer.address().port}`,
      );
    }
    countBorrowedRequests = true;
    const handoffFailures = [];
    const categoricalBytesStart = borrowedBytes;
    if (proxyConnections !== 0 || proxyBytes !== 0) {
      handoffFailures.push(
        `closed forward proxy observed ${proxyConnections} connection(s) and ${proxyBytes} raw byte(s)`,
      );
    }
    for (
      const [name, request, open, target, routeExpected] of [
        // coverage-route: borrowed-create-connection
        [
          "borrowed-create-connection",
          requestWithCreateConnectionSocket,
          () => openSocket("127.0.0.1", port),
          `http://127.0.0.1:${port}/ok`,
          "denied",
        ],
        // coverage-route: borrowed-agent-like
        [
          "borrowed-agent-like",
          requestWithAgentLikeSocket,
          () => openSocket("127.0.0.1", port),
          `http://127.0.0.1:${port}/ok`,
          "denied",
        ],
        // coverage-route: borrowed-unix-create-connection
        [
          "borrowed-unix-create-connection",
          requestWithUnixCreateConnectionSocket,
          () => openUnixSocket(unixPath),
          unixPath,
          "denied",
        ],
        // coverage-route: borrowed-unix-agent-like
        [
          "borrowed-unix-agent-like",
          requestWithUnixAgentLikeSocket,
          () => openUnixSocket(unixPath),
          unixPath,
          "denied",
        ],
        // coverage-route: borrowed-agent-like-reuse-closed
        [
          "borrowed-agent-like-reuse-closed",
          requestWithReusedAgentLikeSocket,
          () => openSocket("127.0.0.1", port),
          `http://127.0.0.1:${port}/ok`,
          "denied",
        ],
      ]
    ) {
      const socket = await open();
      const outcome = await request(socket, target);
      const wanted = routeExpected ??
        (expected === "connect" ? "connected" : "denied");
      if (outcome !== wanted) {
        handoffFailures.push(`${name}: expected ${wanted}, got ${outcome}`);
      }
      console.log(`NODE_HTTP_SOCKET_ROUTE ${name} ${outcome.toUpperCase()}`);
    }
    // coverage-route: borrowed-delayed-agent-like
    const delayedSocket = await openSocket("127.0.0.1", port);
    const delayedAgent = createOwnerDelayedAgent(delayedSocket);
    try {
      const outcome = await requestWithDelayedAgentLikeSocket(
        delayedSocket,
        `http://127.0.0.1:${port}/ok`,
        delayedAgent.agent,
      );
      const wanted = "denied";
      if (outcome !== wanted) {
        handoffFailures.push(
          `borrowed-delayed-agent-like: expected ${wanted}, got ${outcome}`,
        );
      }
      if (delayedAgent.hostileCalls() !== 0) {
        handoffFailures.push(
          `borrowed-delayed-agent-like: hostile addRequest called ${delayedAgent.hostileCalls()} time(s)`,
        );
      }
      console.log(
        `NODE_HTTP_SOCKET_ROUTE borrowed-delayed-agent-like ${outcome.toUpperCase()}`,
      );
    } finally {
      delayedAgent.stop();
      delayedSocket.destroy();
    }
    // coverage-route: borrowed-owner-create-connection
    const ownerHookSocket = await openSocket("127.0.0.1", port);
    const ownerHook = createOwnerSyncCreateConnection(ownerHookSocket);
    try {
      const outcome = await requestWithExternalCreateConnectionSocket(
        ownerHookSocket,
        `http://127.0.0.1:${port}/ok`,
        ownerHook,
      );
      const wanted = "denied";
      if (outcome !== wanted) {
        handoffFailures.push(
          `borrowed-owner-create-connection: expected ${wanted}, got ${outcome}`,
        );
      }
      console.log(
        `NODE_HTTP_SOCKET_ROUTE borrowed-owner-create-connection ${outcome.toUpperCase()}`,
      );
      if (ownerHook.hostileCalls() !== 0) {
        handoffFailures.push(
          `borrowed-owner-create-connection: factory called ${ownerHook.hostileCalls()} time(s)`,
        );
      }
    } finally {
      ownerHookSocket.destroy();
    }
    // coverage-route: borrowed-owner-callback-connection-closed
    const ownerCallbackSocket = await openSocket("127.0.0.1", port);
    const ownerCallback = createOwnerCallbackCreateConnection(
      ownerCallbackSocket,
    );
    try {
      const outcome = await requestWithExternalCreateConnectionSocket(
        ownerCallbackSocket,
        `http://127.0.0.1:${port}/ok`,
        ownerCallback,
      );
      if (outcome !== "denied") {
        handoffFailures.push(
          `borrowed-owner-callback-connection-closed: expected denied, got ${outcome}`,
        );
      }
      console.log(
        `NODE_HTTP_SOCKET_ROUTE borrowed-owner-callback-connection-closed ${outcome.toUpperCase()}`,
      );
      if (ownerCallback.hostileCalls() !== 0) {
        handoffFailures.push(
          `borrowed-owner-callback-connection-closed: factory called ${ownerCallback.hostileCalls()} time(s)`,
        );
      }
    } finally {
      ownerCallbackSocket.destroy();
    }
    // coverage-route: borrowed-owner-sync-agent-like
    const ownerSyncSocket = await openSocket("127.0.0.1", port);
    const ownerSyncAgent = createOwnerSyncAgent(ownerSyncSocket);
    try {
      const outcome = await requestWithDelayedAgentLikeSocket(
        ownerSyncSocket,
        `http://127.0.0.1:${port}/ok`,
        ownerSyncAgent,
      );
      if (outcome !== "denied") {
        handoffFailures.push(
          `borrowed-owner-sync-agent-like: expected denied, got ${outcome}`,
        );
      }
      console.log(
        `NODE_HTTP_SOCKET_ROUTE borrowed-owner-sync-agent-like ${outcome.toUpperCase()}`,
      );
      if (ownerSyncAgent.hostileCalls() !== 0) {
        handoffFailures.push(
          `borrowed-owner-sync-agent-like: addRequest called ${ownerSyncAgent.hostileCalls()} time(s)`,
        );
      }
    } finally {
      ownerSyncSocket.destroy();
    }
    // coverage-route: borrowed-owner-branded-agent-like
    const ownerBrandedSocket = await openSocket("127.0.0.1", port);
    const ownerBrandedAgent = createOwnerBrandedSyncAgent(ownerBrandedSocket);
    try {
      const outcome = await requestWithDelayedAgentLikeSocket(
        ownerBrandedSocket,
        `http://127.0.0.1:${port}/ok`,
        ownerBrandedAgent,
      );
      if (outcome !== "denied") {
        handoffFailures.push(
          `borrowed-owner-branded-agent-like: expected denied, got ${outcome}`,
        );
      }
      console.log(
        `NODE_HTTP_SOCKET_ROUTE borrowed-owner-branded-agent-like ${outcome.toUpperCase()}`,
      );
      if (ownerBrandedAgent.hostileCalls() !== 0) {
        handoffFailures.push(
          `borrowed-owner-branded-agent-like: addRequest called ${ownerBrandedAgent.hostileCalls()} time(s)`,
        );
      }
    } finally {
      ownerBrandedAgent.destroy();
      ownerBrandedSocket.destroy();
    }

    const runNativeRoute = (name, outcome, wanted) => {
      if (outcome !== wanted) {
        handoffFailures.push(`${name}: expected ${wanted}, got ${outcome}`);
      }
      console.log(`NODE_HTTP_SOCKET_ROUTE ${name} ${outcome.toUpperCase()}`);
    };

    // coverage-route: native-bound-tcp-check
    const nativeTcpSocket = await openSocket("127.0.0.1", port);
    try {
      runNativeRoute(
        "native-bound-tcp-check",
        checkNativeTcpSocket(
          nativeTcpSocket,
          `http://127.0.0.1:${port}/ok`,
        ),
        expected === "connect" ? "connected" : "denied",
      );
    } finally {
      nativeTcpSocket.destroy();
    }

    // coverage-route: native-bound-unix-check
    const nativeUnixSocket = await openUnixSocket(unixPath);
    try {
      runNativeRoute(
        "native-bound-unix-check",
        checkNativeUnixSocket(nativeUnixSocket, unixPath),
        expected === "connect" ? "connected" : "denied",
      );
    } finally {
      nativeUnixSocket.destroy();
    }

    // coverage-route: native-accepted-tcp-closed
    let acceptedTcp;
    const acceptedTcpReady = new Promise((resolve) => {
      server.once("connection", (socket) => {
        acceptedTcp = socket;
        resolve();
      });
    });
    const acceptedTcpClient = await openSocket("127.0.0.1", port);
    await acceptedTcpReady;
    try {
      runNativeRoute(
        "native-accepted-tcp-closed",
        checkNativeTcpSocket(
          acceptedTcp,
          `http://127.0.0.1:${port}/ok`,
        ),
        "denied",
      );
    } finally {
      acceptedTcpClient.destroy();
      acceptedTcp.destroy();
    }

    // coverage-route: native-accepted-unix-closed
    let acceptedUnix;
    const acceptedUnixReady = new Promise((resolve) => {
      unixServer.once("connection", (socket) => {
        acceptedUnix = socket;
        resolve();
      });
    });
    const acceptedUnixClient = await openUnixSocket(unixPath);
    await acceptedUnixReady;
    try {
      runNativeRoute(
        "native-accepted-unix-closed",
        checkNativeUnixSocket(acceptedUnix, unixPath),
        "denied",
      );
    } finally {
      acceptedUnixClient.destroy();
      acceptedUnix.destroy();
    }

    for (
      const [name, makeAgent] of [
        // coverage-route: borrowed-owner-agent-return-connection-closed
        [
          "borrowed-owner-agent-return-connection-closed",
          createOwnerBrandedReturnFactory,
        ],
        // coverage-route: borrowed-owner-agent-callback-connection-closed
        [
          "borrowed-owner-agent-callback-connection-closed",
          createOwnerBrandedCallbackFactory,
        ],
        // coverage-route: borrowed-owner-agent-create-socket-closed
        [
          "borrowed-owner-agent-create-socket-closed",
          createOwnerBrandedCreateSocketOverride,
        ],
      ]
    ) {
      const socket = await openSocket("127.0.0.1", port);
      const agent = makeAgent(socket);
      try {
        const outcome = await requestWithDelayedAgentLikeSocket(
          socket,
          `http://127.0.0.1:${port}/ok`,
          agent,
        );
        runNativeRoute(name, outcome, "denied");
        if (agent.hostileCalls() !== 0) {
          handoffFailures.push(
            `${name}: hostile method called ${agent.hostileCalls()} time(s)`,
          );
        }
      } finally {
        agent.destroy();
        socket.destroy();
      }
    }

    for (
      const [name, agent] of [
        // coverage-route: cross-kind-http-agent-for-https-closed
        [
          "cross-kind-http-agent-for-https-closed",
          createOwnerHttpAgentForHttps(),
        ],
        // coverage-route: cross-kind-https-agent-http-factory-closed
        [
          "cross-kind-https-agent-http-factory-closed",
          createOwnerHttpsAgentWithHttpFactory(),
        ],
      ]
    ) {
      try {
        const outcome = await requestHttps(
          `https://127.0.0.1:${httpsServer.address().port}/ok`,
          agent,
        );
        runNativeRoute(name, outcome, "denied");
      } finally {
        agent.destroy();
      }
    }

    // coverage-route: falsy-agent-zero-closed
    const falsyAgentNetOverride = installOwnerNetCreateConnectionOverride();
    try {
      const outcome = await requestWithFalsyAgent(
        `http://127.0.0.1:${port}/ok`,
      );
      runNativeRoute("falsy-agent-zero-closed", outcome, "denied");
      if (falsyAgentNetOverride.calls() !== 0) {
        handoffFailures.push(
          `falsy-agent-zero-closed: public net factory called ${falsyAgentNetOverride.calls()} time(s)`,
        );
      }
    } finally {
      falsyAgentNetOverride.restore();
    }

    await new Promise((resolve) => setTimeout(resolve, 20));
    if (borrowedBytes !== categoricalBytesStart) {
      handoffFailures.push(
        `categorically denied handoffs delivered ${
          borrowedBytes - categoricalBytesStart
        } raw byte(s)`,
      );
    }

    // coverage-route: client-request-agent-accessor
    const requestAgentAccessor = installOwnerClientRequestAgentAccessor();
    const accessorNetOverride = installOwnerNetCreateConnectionOverride();
    const accessorAgent = new http.Agent();
    try {
      const outcome = await requestWithAgent(
        `http://127.0.0.1:${port}/ok`,
        accessorAgent,
      );
      runNativeRoute(
        "client-request-agent-accessor",
        outcome,
        expected === "connect" ? "connected" : "denied",
      );
      if (
        requestAgentAccessor.reads() !== 0 ||
        requestAgentAccessor.writes() !== 0 ||
        accessorNetOverride.calls() !== 0
      ) {
        handoffFailures.push(
          `client-request-agent-accessor: reads=${requestAgentAccessor.reads()} writes=${requestAgentAccessor.writes()} net calls=${accessorNetOverride.calls()}`,
        );
      }
    } finally {
      accessorNetOverride.restore();
      requestAgentAccessor.restore();
      accessorAgent.destroy();
    }

    for (
      const [name, makeAgent] of [
        // coverage-route: alternating-add-request-getter
        [
          "alternating-add-request-getter",
          createOwnerAlternatingAddRequestAgent,
        ],
        // coverage-route: alternating-create-socket-getter
        [
          "alternating-create-socket-getter",
          createOwnerAlternatingCreateSocketAgent,
        ],
        // coverage-route: alternating-create-connection-getter
        [
          "alternating-create-connection-getter",
          createOwnerAlternatingCreateConnectionAgent,
        ],
      ]
    ) {
      const socket = await openSocket(
        "127.0.0.1",
        injectionServer.address().port,
      );
      const probe = makeAgent(socket);
      try {
        const outcome = await requestWithDelayedAgentLikeSocket(
          socket,
          `http://127.0.0.1:${port}/ok`,
          probe.agent,
        );
        runNativeRoute(
          name,
          outcome,
          expected === "connect" ? "connected" : "denied",
        );
        const wantedReads = expected === "connect" ? 1 : 0;
        if (probe.reads() !== wantedReads || probe.hostileCalls() !== 0) {
          handoffFailures.push(
            `${name}: getter reads=${probe.reads()} hostile calls=${probe.hostileCalls()}`,
          );
        }
      } finally {
        probe.agent.destroy();
        socket.destroy();
      }
    }

    for (
      const [name, makeProbe] of [
        // coverage-route: public-agent-free-injection
        [
          "public-agent-free-injection",
          (socket) =>
            createOwnerPublicFreeAgent(socket, "127.0.0.1", port, false),
        ],
        // coverage-route: public-socket-free-injection
        [
          "public-socket-free-injection",
          (socket) =>
            createOwnerPublicFreeAgent(socket, "127.0.0.1", port, true),
        ],
      ]
    ) {
      const socket = await openSocket(
        "127.0.0.1",
        injectionServer.address().port,
      );
      const probe = makeProbe(socket);
      const timer = setTimeout(probe.emit, 0);
      try {
        const outcome = await requestWithDelayedAgentLikeSocket(
          socket,
          `http://127.0.0.1:${port}/ok`,
          probe.agent,
        );
        runNativeRoute(
          name,
          outcome,
          expected === "connect" ? "connected" : "denied",
        );
      } finally {
        clearTimeout(timer);
        probe.agent.destroy();
        socket.destroy();
      }
    }

    // coverage-route: public-free-sockets-injection
    const freeSocketsSocket = await openSocket(
      "127.0.0.1",
      injectionServer.address().port,
    );
    const freeSocketsAgent = createOwnerFreeSocketsAgent(
      freeSocketsSocket,
      "127.0.0.1",
      port,
    );
    try {
      const outcome = await requestWithDelayedAgentLikeSocket(
        freeSocketsSocket,
        `http://127.0.0.1:${port}/ok`,
        freeSocketsAgent,
      );
      runNativeRoute(
        "public-free-sockets-injection",
        outcome,
        expected === "connect" ? "connected" : "denied",
      );
    } finally {
      freeSocketsAgent.destroy();
      freeSocketsSocket.destroy();
    }

    // coverage-route: public-agent-pool-state-poison
    const poolPoison = createOwnerPoisonedPoolAgent();
    poolPoison.agent.on("keylog", () => {});
    try {
      const outcome = await requestWithAgent(
        `http://127.0.0.1:${port}/ok`,
        poolPoison.agent,
      );
      runNativeRoute(
        "public-agent-pool-state-poison",
        outcome,
        expected === "connect" ? "connected" : "denied",
      );
      poolPoison.agent.destroy();
      if (poolPoison.reads() !== 0 || poolPoison.hostileCalls() !== 0) {
        handoffFailures.push(
          `public-agent-pool-state-poison: reads=${poolPoison.reads()} hostile calls=${poolPoison.hostileCalls()}`,
        );
      }
    } finally {
      poolPoison.agent.destroy();
    }

    // coverage-route: forged-agent-endpoint-options
    const forgedEndpointAgent = createOwnerForgedEndpointAgent(
      injectionServer.address().port,
      injectionUnixPath,
    );
    try {
      const outcome = await requestWithAgent(
        `http://127.0.0.1:${port}/ok`,
        forgedEndpointAgent,
      );
      runNativeRoute(
        "forged-agent-endpoint-options",
        outcome,
        expected === "connect" ? "connected" : "denied",
      );
    } finally {
      forgedEndpointAgent.destroy();
    }

    // coverage-route: tampered-client-on-socket
    const tamperedSocket = await openSocket(
      "127.0.0.1",
      injectionServer.address().port,
    );
    const onSocketOverride = installOwnerOnSocketOverride(tamperedSocket);
    const tamperedAgent = new http.Agent();
    try {
      const outcome = await requestWithDelayedAgentLikeSocket(
        tamperedSocket,
        `http://127.0.0.1:${port}/ok`,
        tamperedAgent,
      );
      runNativeRoute(
        "tampered-client-on-socket",
        outcome,
        expected === "connect" ? "connected" : "denied",
      );
      if (onSocketOverride.calls() !== 0) {
        handoffFailures.push(
          `tampered-client-on-socket: override called ${onSocketOverride.calls()} time(s)`,
        );
      }
    } finally {
      onSocketOverride.restore();
      tamperedAgent.destroy();
      tamperedSocket.destroy();
    }

    // coverage-route: borrowed-https-options-socket-closed
    const httpsSocketBytesStart = borrowedBytes;
    const httpsSocket = await openSocket(
      "127.0.0.1",
      injectionServer.address().port,
    );
    try {
      runNativeRoute(
        "borrowed-https-options-socket-closed",
        await requestWithHttpsSocket(
          httpsSocket,
          `https://127.0.0.1:${httpsServer.address().port}/ok`,
        ),
        "denied",
      );
    } finally {
      httpsSocket.destroy();
    }
    await new Promise((resolve) => setTimeout(resolve, 20));
    if (borrowedBytes !== httpsSocketBytesStart) {
      handoffFailures.push(
        `borrowed-https-options-socket-closed delivered ${
          borrowedBytes - httpsSocketBytesStart
        } target byte(s)`,
      );
    }

    // coverage-route: alternating-port-getter
    const portGetter = await requestWithAlternatingPort(
      `http://127.0.0.1:${port}/ok`,
      injectionServer.address().port,
    );
    runNativeRoute(
      "alternating-port-getter",
      portGetter.outcome,
      expected === "connect" ? "connected" : "denied",
    );
    if (portGetter.reads !== 1) {
      handoffFailures.push(
        `alternating-port-getter: getter read ${portGetter.reads} time(s)`,
      );
    }

    // coverage-route: alternating-port-coercion-closed
    const portCoercionBytesStart = borrowedBytes;
    const portCoercion = await requestWithAlternatingPortCoercion(
      `http://127.0.0.1:${port}/ok`,
      injectionServer.address().port,
    );
    runNativeRoute(
      "alternating-port-coercion-closed",
      portCoercion.outcome,
      "denied",
    );
    if (portCoercion.reads !== 0) {
      handoffFailures.push(
        `alternating-port-coercion-closed: valueOf called ${portCoercion.reads} time(s)`,
      );
    }
    // coverage-route: invalid-port-string-closed
    runNativeRoute(
      "invalid-port-string-closed",
      await requestWithInvalidPortString(
        `http://127.0.0.1:${port}/ok`,
        "80x",
      ),
      "denied",
    );
    await new Promise((resolve) => setTimeout(resolve, 20));
    if (borrowedBytes !== portCoercionBytesStart) {
      handoffFailures.push(
        `invalid port denials delivered ${
          borrowedBytes - portCoercionBytesStart
        } raw byte(s)`,
      );
    }

    // coverage-route: alternating-hostname-getter
    const hostnameGetter = await requestWithAlternatingHostname(
      `http://127.0.0.1:${port}/ok`,
      "endpoint-drift.invalid",
    );
    runNativeRoute(
      "alternating-hostname-getter",
      hostnameGetter.outcome,
      expected === "connect" ? "connected" : "denied",
    );
    if (hostnameGetter.reads !== 1) {
      handoffFailures.push(
        `alternating-hostname-getter: getter read ${hostnameGetter.reads} time(s)`,
      );
    }

    // coverage-route: alternating-socket-path-getter
    const socketPathGetter = await requestWithAlternatingSocketPath(
      unixPath,
      injectionUnixPath,
    );
    runNativeRoute(
      "alternating-socket-path-getter",
      socketPathGetter.outcome,
      expected === "connect" ? "connected" : "denied",
    );
    if (socketPathGetter.reads !== 1) {
      handoffFailures.push(
        `alternating-socket-path-getter: getter read ${socketPathGetter.reads} time(s)`,
      );
    }

    // coverage-route: net-client-socket-diagnostics-closed
    const diagnosticChannel = diagnosticsChannel.channel("net.client.socket");
    let diagnosticEvents = 0;
    const diagnosticListener = () => diagnosticEvents++;
    diagnosticChannel.subscribe(diagnosticListener);
    const diagnosticAgent = new http.Agent();
    try {
      const outcome = await requestWithAgent(
        `http://127.0.0.1:${port}/ok`,
        diagnosticAgent,
      );
      runNativeRoute(
        "net-client-socket-diagnostics-closed",
        outcome,
        expected === "connect" ? "connected" : "denied",
      );
      if (diagnosticEvents !== 0) {
        handoffFailures.push(
          `net-client-socket-diagnostics-closed: observed ${diagnosticEvents} socket event(s)`,
        );
      }
    } finally {
      diagnosticChannel.unsubscribe(diagnosticListener);
      diagnosticAgent.destroy();
    }

    // coverage-route: tampered-net-socket-prototype-closed
    const prototypeBytesStart = borrowedBytes;
    const netPrototypeOverride = installOwnerNetSocketConnectOverride();
    const netPrototypeAgent = new http.Agent();
    try {
      const outcome = await requestWithAgent(
        `http://127.0.0.1:${port}/ok`,
        netPrototypeAgent,
      );
      runNativeRoute(
        "tampered-net-socket-prototype-closed",
        outcome,
        "denied",
      );
      if (netPrototypeOverride.calls() !== 0) {
        handoffFailures.push(
          `tampered-net-socket-prototype-closed: override called ${netPrototypeOverride.calls()} time(s)`,
        );
      }
    } finally {
      netPrototypeOverride.restore();
      netPrototypeAgent.destroy();
    }

    // coverage-route: tampered-tls-socket-prototype-closed
    const tlsPrototypeOverride = installOwnerTlsSocketConnectOverride();
    try {
      const outcome = await requestHttps(
        `https://127.0.0.1:${httpsServer.address().port}/ok`,
      );
      runNativeRoute(
        "tampered-tls-socket-prototype-closed",
        outcome,
        "denied",
      );
      if (tlsPrototypeOverride.calls() !== 0) {
        handoffFailures.push(
          `tampered-tls-socket-prototype-closed: override called ${tlsPrototypeOverride.calls()} time(s)`,
        );
      }
    } finally {
      tlsPrototypeOverride.restore();
    }
    await new Promise((resolve) => setTimeout(resolve, 20));
    if (borrowedBytes !== prototypeBytesStart) {
      handoffFailures.push(
        `tampered socket prototype denials delivered ${
          borrowedBytes - prototypeBytesStart
        } raw byte(s)`,
      );
    }
    await new Promise((resolve) => setTimeout(resolve, 20));
    if (
      expected === "fetch" &&
      (borrowedRequests !== 0 || borrowedBytes !== 0)
    ) {
      handoffFailures.push(
        `fetch-only borrowed routes delivered ${borrowedRequests} HTTP request(s) and ${borrowedBytes} raw byte(s) before denial`,
      );
    }
    if (injectedBytes !== 0) {
      handoffFailures.push(
        `hostile injected transports delivered ${injectedBytes} raw byte(s)`,
      );
    }
    if (handoffFailures.length > 0) {
      throw new Error(handoffFailures.join("; "));
    }
  } finally {
    await close(server, serverSockets);
    await close(unixServer, unixSockets);
    await close(proxyServer, proxySockets);
    await close(httpsServer, httpsSockets);
    await close(injectionServer, injectionSockets);
    await close(injectionUnixServer, injectionUnixSockets);
    for (const path of [unixPath, injectionUnixPath]) {
      try {
        Deno.removeSync(path);
      } catch {
        // The runtime may remove a closed Unix listener itself.
      }
    }
  }
}

async function runHandoffPeerClosure() {
  let requests = 0;
  let peerBytes = 0;
  const server = http.createServer((_request, response) => {
    requests++;
    response.writeHead(200, { connection: "keep-alive" });
    response.end("unexpected peer reached");
  });
  const sockets = track(server, (bytes) => peerBytes += bytes);
  await listen(server, { hostname: "127.0.0.1", port: 0 });
  const port = server.address().port;
  const declared = `http://allowed.example:${port}/ok`;
  try {
    for (
      const [name, request] of [
        // coverage-route: borrowed-peer-create-connection
        ["borrowed-peer-create-connection", requestWithCreateConnectionSocket],
        // coverage-route: borrowed-peer-agent-like
        ["borrowed-peer-agent-like", requestWithAgentLikeSocket],
      ]
    ) {
      const socket = await openSocket("localhost", port);
      const outcome = await request(socket, declared);
      if (outcome !== "denied") {
        throw new Error(`${name}: expected denied, got ${outcome}`);
      }
      console.log(`NODE_HTTP_SOCKET_ROUTE ${name} DENIED`);
    }

    // coverage-route: native-hidden-peer-check
    const hiddenPeerSocket = await openSocket("localhost", port);
    try {
      const outcome = checkNativeTcpSocket(hiddenPeerSocket, declared);
      if (outcome !== "denied") {
        throw new Error(
          `native-hidden-peer-check: expected denied, got ${outcome}`,
        );
      }
      console.log("NODE_HTTP_SOCKET_ROUTE native-hidden-peer-check DENIED");
    } finally {
      hiddenPeerSocket.destroy();
    }

    // coverage-route: borrowed-accepted-socket-closed
    let accepted;
    const acceptedReady = new Promise((resolve) => {
      server.once("connection", (socket) => {
        accepted = socket;
        resolve();
      });
    });
    const client = await openSocket("localhost", port);
    let acceptedBytes = 0;
    client.on("data", (chunk) => acceptedBytes += chunk.length);
    await acceptedReady;
    try {
      // coverage-route: native-accepted-peer-closed
      const nativeOutcome = checkNativeTcpSocket(accepted, declared);
      const outcome = await requestWithCreateConnectionSocket(
        accepted,
        declared,
      );
      if (outcome !== "denied") {
        throw new Error(
          `borrowed-accepted-socket-closed: expected denied, got ${outcome}`,
        );
      }
      console.log(
        "NODE_HTTP_SOCKET_ROUTE borrowed-accepted-socket-closed DENIED",
      );
      if (nativeOutcome !== "denied") {
        throw new Error(
          `native-accepted-peer-closed: expected denied, got ${nativeOutcome}`,
        );
      }
      console.log(
        "NODE_HTTP_SOCKET_ROUTE native-accepted-peer-closed DENIED",
      );
    } finally {
      client.destroy();
      accepted?.destroy();
    }
    await new Promise((resolve) => setTimeout(resolve, 20));
    if (requests !== 0 || peerBytes !== 0 || acceptedBytes !== 0) {
      throw new Error(
        `borrowed peer closure leaked ${requests} HTTP request(s), ${peerBytes} inbound byte(s), and ${acceptedBytes} accepted-socket byte(s)`,
      );
    }
  } finally {
    await close(server, sockets);
  }
  console.log("NODE_HTTP_SOCKET_HANDOFF_PEER_CLOSURE PASS");
}

async function runSchemes(expected) {
  let connections = 0;
  let requests = 0;
  const server = http.createServer((request, response) => {
    requests++;
    if (request.url === "/module.js") {
      response.writeHead(200, { "content-type": "text/javascript" });
      response.end("export default 'REMOTE_BORROWED';");
    } else {
      response.writeHead(200, { connection: "close" });
      response.end("network scheme reached TCP");
    }
  });
  server.on("connection", () => connections++);
  const sockets = track(server);
  await listen(server, { hostname: "127.0.0.1", port: 0 });
  try {
    await runUrlSchemeMatrix(
      expected,
      new URL("./fixture.txt", import.meta.url),
      `http://127.0.0.1:${server.address().port}`,
    );
    if (connections !== 0 || requests !== 0) {
      throw new Error(
        `non-network scheme reached ${connections} TCP connection(s) and ${requests} HTTP request(s)`,
      );
    }
  } finally {
    await close(server, sockets);
  }
}

const fixtureMode = Deno.env.get("ODEN_TEST_FIXTURE_MODE") ?? Deno.args[0];
const fixtureExpected = Deno.env.get("ODEN_TEST_FIXTURE_EXPECTED") ??
  Deno.args[1];
if (fixtureMode === "routes") {
  await runRoutes(fixtureExpected);
} else if (fixtureMode === "schemes") {
  await runSchemes(fixtureExpected);
} else if (fixtureMode === "handoff-peer") {
  await runHandoffPeerClosure();
} else {
  throw new Error(`unknown fixture mode: ${fixtureMode}`);
}

import { createRequire } from "node:module";
import { AsyncResource } from "node:async_hooks";
import net from "node:net";

const port = Number(Deno.args[0]);
const method = Deno.args[1];
const require = createRequire(import.meta.url);
const endpointProbe = require("endpoint-denied");

function bounded(promise, label, milliseconds = 1_000) {
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

async function openSocket() {
  const socket = net.connect({ port, host: "localhost" });
  try {
    await bounded(
      new Promise((resolve, reject) => {
        socket.once("connect", resolve);
        socket.once("error", reject);
      }),
      "Node inspector connect",
    );
    return socket;
  } catch (error) {
    socket.destroy();
    throw error;
  }
}

function writeOnce(socket, chunk, encoding) {
  return new Promise((resolve) => {
    let settled = false;
    const onError = () => finish("BROKEN");
    const finish = (value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timeoutId);
      socket.removeListener("error", onError);
      resolve(value);
    };
    socket.once("error", onError);
    const timeoutId = setTimeout(() => finish("HUNG"), 1_000);
    try {
      socket.write(
        chunk,
        encoding,
        (error) => finish(error ? "BROKEN" : "ALLOWED"),
      );
    } catch {
      finish("BROKEN");
    }
  });
}

function rootWrite(method, socket) {
  switch (method) {
    case "default":
      return writeOnce(
        socket,
        "GET /json/list HTTP/1.1\r\nHost: localhost\r\n\r\n",
      );
    case "buffer":
      return writeOnce(
        socket,
        Buffer.from("GET /json/list HTTP/1.1\r\n\r\n"),
      );
    case "writev":
      return new Promise((resolve) => {
        let settled = false;
        const onError = () => finish("BROKEN");
        const finish = (value) => {
          if (settled) return;
          settled = true;
          clearTimeout(timeoutId);
          socket.removeListener("error", onError);
          resolve(value);
        };
        socket.once("error", onError);
        const timeoutId = setTimeout(() => finish("HUNG"), 1_000);
        try {
          socket.cork();
          socket.write(Buffer.from("GET "));
          socket.write(
            Buffer.from("/json/list HTTP/1.1\r\n\r\n"),
            (error) => finish(error ? "BROKEN" : "ALLOWED"),
          );
          socket.uncork();
        } catch {
          finish("BROKEN");
        }
      });
    case "ascii":
    case "latin1":
    case "ucs2":
      return writeOnce(
        socket,
        "GET /json/list HTTP/1.1\r\n\r\n",
        method,
      );
    default:
      return Promise.resolve("BROKEN");
  }
}

const deniedSocket = await openSocket();
const rootScope = new AsyncResource("oden-endpoint-node-write-root-control");
let rootSocket;
try {
  const { denied } = await endpointProbe({
    nodeWrite: {
      httpUrl: `http://127.0.0.1:${port}/json/list`,
      method,
      socket: deniedSocket,
    },
  });
  // The same method must regain the root actor after the package promise
  // settles; a positive control before the call cannot detect sticky actor
  // attribution on the return edge.
  const root = await rootScope.runInAsyncScope(async () => {
    rootSocket = await openSocket();
    return await rootWrite(method, rootSocket);
  });
  console.log(JSON.stringify({ denied, root }));
} finally {
  rootScope.emitDestroy();
  deniedSocket.destroy();
  rootSocket?.destroy();
}

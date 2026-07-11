import { fork, spawn } from "node:child_process";
import fs from "node:fs";
import inspector from "node:inspector";
import net from "node:net";

const here = new URL(".", import.meta.url);
const port = Number(Deno.args[0]);
if (!inspector.url()) throw new Error("startup inspector URL missing");

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

async function connectInspector() {
  const socket = net.connect(port, "127.0.0.1");
  return await bounded(
    new Promise((resolve, reject) => {
      socket.once("connect", () => resolve(socket));
      socket.once("error", reject);
    }),
    "inspector TCP connect",
  );
}

function fakeSocketFacade(socketPrototype, tcpPrototype, rawFd) {
  // A package can satisfy the JavaScript prototype tests with a facade and
  // return any guessed integer from fdForIpc(). The native op must classify
  // the concrete descriptor rather than trusting this object graph.
  const fakeTcp = Object.create(tcpPrototype);
  Object.defineProperty(fakeTcp, "fdForIpc", {
    configurable: true,
    value: () => rawFd,
  });
  Object.defineProperty(fakeTcp, "socketTypeForIpc", {
    configurable: true,
    value: () => 0,
  });
  const fakeSocket = Object.create(socketPrototype);
  Object.defineProperty(fakeSocket, "_handle", {
    configurable: true,
    value: fakeTcp,
  });
  return fakeSocket;
}

async function probeIpcFakeFacade(socketPrototype, tcpPrototype, rawFd) {
  const receiver = fork(
    new URL("fd_transfer_receiver.cjs", here).pathname,
    [],
    {
      execArgv: ["run", "--allow-all"],
      stdio: ["ignore", "ignore", "ignore", "ipc"],
    },
  );
  receiver.on("error", () => {});
  const receiverClosed = new Promise((resolve) => {
    receiver.once("close", resolve);
  });
  let receivedHandle = false;
  receiver.on("message", (message) => {
    receivedHandle ||= message?.receivedHandle === true;
  });

  if (rawFd < 0) throw new Error("failed to duplicate inspector fd");
  const fakeSocket = fakeSocketFacade(socketPrototype, tcpPrototype, rawFd);
  const outcome = await bounded(
    new Promise((resolve) => {
      try {
        receiver.send(
          { probe: "fake-facade" },
          fakeSocket,
          { keepOpen: true },
          (error) => resolve(error ? "REFUSED" : "BROKEN"),
        );
      } catch (error) {
        resolve(
          String(error).includes("raw INET stream sockets")
            ? "REFUSED"
            : "BROKEN",
        );
      }
    }),
    "fake-facade IPC refusal",
  );

  try {
    receiver.disconnect();
  } catch {
    // A synchronous refusal can leave the compatibility channel mid-send;
    // killing below is sufficient cleanup.
  }
  try {
    receiver.kill();
  } catch {
    // The receiver may have exited after its channel was disconnected.
  }
  await bounded(receiverClosed, "IPC receiver cleanup");
  return outcome === "REFUSED" && !receivedHandle ? "REFUSED" : "BROKEN";
}

async function probeNumericStdio(rawFd) {
  if (rawFd < 0) throw new Error("failed to duplicate inspector fd");

  return await bounded(
    new Promise((resolve) => {
      let child;
      try {
        child = spawn(Deno.execPath(), ["eval", "Deno.exit(79)"], {
          stdio: ["ignore", "ignore", "ignore", rawFd],
        });
      } catch (error) {
        resolve(
          String(error).includes("raw INET stream sockets")
            ? "REFUSED"
            : "BROKEN",
        );
        return;
      }
      let spawned = false;
      child.once("spawn", () => {
        spawned = true;
      });
      child.once("error", (error) => {
        resolve(
          !spawned && String(error).includes("raw INET stream sockets")
            ? "REFUSED"
            : "BROKEN",
        );
      });
      child.once("exit", () => resolve("BROKEN"));
    }),
    "numeric stdio refusal",
  );
}

async function probeOrdinaryFileStdio() {
  const fd = fs.openSync("/dev/null", "r");
  try {
    return await bounded(
      new Promise((resolve) => {
        let child;
        try {
          child = spawn(Deno.execPath(), ["eval", "Deno.exit(0)"], {
            stdio: ["ignore", "ignore", "ignore", fd],
          });
        } catch {
          resolve("BROKEN");
          return;
        }
        child.once("error", () => resolve("BROKEN"));
        child.once(
          "exit",
          (code) => resolve(code === 0 ? "ALLOWED" : "BROKEN"),
        );
      }),
      "ordinary file stdio control",
    );
  } finally {
    fs.closeSync(fd);
  }
}

const socket = await connectInspector();
try {
  const socketPrototype = Object.getPrototypeOf(socket);
  const tcpPrototype = Object.getPrototypeOf(socket._handle);
  const openIpcFd = socket._handle.fdForIpc();
  const openSpawnFd = socket._handle.fdForIpc();
  const retainedIpcFd = socket._handle.fdForIpc();
  const retainedSpawnFd = socket._handle.fdForIpc();
  const ipcFakeFacade = await probeIpcFakeFacade(
    socketPrototype,
    tcpPrototype,
    openIpcFd,
  );
  const spawnNumericStdio = await probeNumericStdio(openSpawnFd);

  // Unregister and stop the inspector listener while duplicated connected
  // descriptors remain live. The raw-fd barrier must not consult that mutable
  // endpoint registry or declassify the retained file descriptions.
  inspector.close();
  const ipcAfterInspectorClose = await probeIpcFakeFacade(
    socketPrototype,
    tcpPrototype,
    retainedIpcFd,
  );
  const spawnAfterInspectorClose = await probeNumericStdio(retainedSpawnFd);
  const ordinaryFileStdio = await probeOrdinaryFileStdio();

  console.log(JSON.stringify({
    ipcAfterInspectorClose,
    ipcFakeFacade,
    ordinaryFileStdio,
    spawnAfterInspectorClose,
    spawnNumericStdio,
  }));
} finally {
  socket.destroy();
}

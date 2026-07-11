import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import os from "node:os";

const here = dirname(fileURLToPath(import.meta.url));
const temp = Deno.makeTempDirSync({ prefix: "oden-native-routes-" });
const audit = join(temp, "audit.ndjson");
const marker = join(temp, "spawned-before-denial");

function fail(message, detail = "") {
  throw new Error(`${message}${detail ? `: ${detail}` : ""}`);
}

try {
  const inherited = Object.fromEntries(
    Object.entries(Deno.env.toObject()).filter(([name]) =>
      !name.startsWith("ODEN_CAPSEC_")
    ),
  );
  const process = new Deno.Command(Deno.execPath(), {
    args: ["run", "--allow-all", join(here, "routes_child.js"), marker],
    cwd: here,
    clearEnv: true,
    env: {
      ...inherited,
      ODEN_CAPSEC_POLICY: join(here, "policy.json"),
      ODEN_CAPSEC_AUDIT: audit,
      ODEN_CAPSEC_ROOT: here,
      // Cargo and local shells may inject loader paths. Restricted run grants
      // intentionally reject non-empty loader variables before the route this
      // fixture is trying to reach.
      DYLD_FALLBACK_LIBRARY_PATH: "",
      LD_LIBRARY_PATH: "",
    },
    stdout: "piped",
    stderr: "piped",
  }).spawn();

  const outputPromise = process.output();
  let timeoutId;
  const bounded = await Promise.race([
    outputPromise.then((output) => ({ kind: "output", output })),
    new Promise((resolve) => {
      timeoutId = setTimeout(
        () => resolve({ kind: "timeout" }),
        15_000,
      );
    }),
  ]);
  clearTimeout(timeoutId);
  if (bounded.kind === "timeout") {
    try {
      process.kill("SIGKILL");
    } catch {
      // A process that exits on the deadline is still not valid evidence.
    }
    const killed = await outputPromise;
    fail(
      "native route child timed out",
      new TextDecoder().decode(killed.stderr).trim(),
    );
  }
  const child = bounded.output;

  const stdout = new TextDecoder().decode(child.stdout).trim();
  const stderr = new TextDecoder().decode(child.stderr).trim();
  if (!child.success) fail("native route child failed", stderr || stdout);
  const routes = JSON.parse(stdout);

  const expectedRoutes = {
    spawnSyncCustomSignal: "DENIED",
    spawnSyncTerminalCleanup: "ALLOWED",
    spawnSyncNoEarlyEffect: "DENIED",
    signalBind: "DENIED",
    signalBindNoMutation: "DENIED",
    signalBindRootControl: "ALLOWED",
    channelSubscribe: "DENIED",
    channelSubscribeNoMutation: "DENIED",
    inspectorOpen: "DENIED",
    inspectorOpenNoMutation: "DENIED",
    inspectorUrl: "DENIED",
    inspectorClose: "DENIED",
    inspectorDispatch: "DENIED",
    inspectorPassedSessionIntact: "DENIED",
    inspectorRootControl: "ALLOWED",
    inspectorAllowedPackage: "ALLOWED",
  };
  for (const [name, expected] of Object.entries(expectedRoutes)) {
    if (routes[name] !== expected) {
      fail(`unexpected ${name}`, JSON.stringify(routes));
    }
  }

  const records = Deno.readTextFileSync(audit)
    .trim()
    .split("\n")
    .filter(Boolean)
    .map((line) => JSON.parse(line));
  const deniedPrincipal = (record) =>
    record.principal === "native-route-denied" ||
    record.principal === "native-route-denied@1.0.0";
  const has = (capability, target, decision, principal = deniedPrincipal) =>
    records.some((record) =>
      record.capability === capability && record.target === target &&
      record.decision === decision && principal(record)
    );
  const allowedPrincipal = (record) =>
    record.principal === "native-route-allowed" ||
    record.principal === "native-route-allowed@1.0.0";
  const openNoListenPrincipal = (record) =>
    record.principal === "native-route-open-no-listen" ||
    record.principal === "native-route-open-no-listen@1.0.0";
  const spawnSignalTarget =
    `spawnSync-watchdog:${os.constants.signals.SIGUSR1}`;

  const auditRoutes = {
    auditSpawnSync: has(
        "process:signal",
        spawnSignalTarget,
        "deny",
      )
      ? "DENIED"
      : "MISSING",
    auditSignalBind: has("process:signal", "listen:SIGUSR2", "deny")
      ? "DENIED"
      : "MISSING",
    auditChannelSubscribe: has(
        "runtime:inspect",
        "oden-native-route-inactive",
        "deny",
      )
      ? "DENIED"
      : "MISSING",
    auditInspectorOpen: has(
        "network:listen",
        "127.0.0.1:0",
        "deny",
        openNoListenPrincipal,
      )
      ? "DENIED"
      : "MISSING",
    auditInspectorOpenActivation: has(
        "inspector:activate",
        "node:inspector.open",
        "allow",
        openNoListenPrincipal,
      )
      ? "ALLOWED"
      : "MISSING",
    auditInspectorUrl: has(
        "inspector:activate",
        "node:inspector.url",
        "deny",
      )
      ? "DENIED"
      : "MISSING",
    auditInspectorClose: has(
        "inspector:activate",
        "node:inspector.close",
        "deny",
      )
      ? "DENIED"
      : "MISSING",
    auditInspectorDispatch: has(
        "inspector:activate",
        "node:inspector.Session.post",
        "deny",
      )
      ? "DENIED"
      : "MISSING",
    auditInspectorAllowedOpen: has(
        "inspector:activate",
        "node:inspector.open",
        "allow",
        allowedPrincipal,
      )
      ? "ALLOWED"
      : "MISSING",
    auditInspectorAllowedUrl: has(
        "inspector:activate",
        "node:inspector.url",
        "allow",
        allowedPrincipal,
      )
      ? "ALLOWED"
      : "MISSING",
    auditInspectorAllowedClose: has(
        "inspector:activate",
        "node:inspector.close",
        "allow",
        allowedPrincipal,
      )
      ? "ALLOWED"
      : "MISSING",
    auditInspectorAllowedDispatch: has(
        "inspector:activate",
        "node:inspector.Session.post",
        "allow",
        allowedPrincipal,
      )
      ? "ALLOWED"
      : "MISSING",
  };
  for (const [name, value] of Object.entries(auditRoutes)) {
    const expected = name.startsWith("auditInspectorAllowed") ||
        name === "auditInspectorOpenActivation"
      ? "ALLOWED"
      : "DENIED";
    if (value !== expected) fail(`missing exact ${name} audit row`);
  }

  console.log(JSON.stringify({ ...routes, ...auditRoutes }));
} finally {
  Deno.removeSync(temp, { recursive: true });
}

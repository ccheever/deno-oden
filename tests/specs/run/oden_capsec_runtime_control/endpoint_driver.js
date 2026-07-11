const here = new URL(".", import.meta.url);
const decoder = new TextDecoder();
const auditDir = Deno.makeTempDirSync({ prefix: "oden-endpoint-audit-" });

function reservePort() {
  const listener = Deno.listen({ hostname: "127.0.0.1", port: 0 });
  const port = listener.addr.port;
  listener.close();
  return port;
}

function readAudit(path) {
  const text = Deno.readTextFileSync(path).trim();
  return text === "" ? [] : text.split("\n").map((line) => JSON.parse(line));
}

async function runInspectorChild(script, extraArgs, label, timeoutMs) {
  const port = reservePort();
  const auditPath = `${auditDir}/${label}.ndjson`;
  const childProcess = new Deno.Command(Deno.execPath(), {
    args: [
      "run",
      "--allow-all",
      "--unstable-net",
      `--inspect=127.0.0.1:${port}`,
      new URL(script, here).pathname,
      String(port),
      ...extraArgs,
    ],
    env: {
      ...Deno.env.toObject(),
      ODEN_CAPSEC_AUDIT: auditPath,
      ODEN_CAPSEC_POLICY: new URL("capsec_endpoint.json", here).pathname,
    },
    stdout: "piped",
    stderr: "piped",
  }).spawn();
  const outputPromise = childProcess.output();
  let timeoutId;
  const timeout = new Promise((resolve) => {
    timeoutId = setTimeout(() => resolve(null), timeoutMs);
  });
  const output = await Promise.race([outputPromise, timeout]);
  clearTimeout(timeoutId);

  if (output === null) {
    try {
      childProcess.kill("SIGKILL");
    } catch {
      // The child may have exited on the timeout boundary.
    }
    await outputPromise;
    throw new Error(`${label} endpoint fixture child hung`);
  }
  if (!output.success) throw new Error(decoder.decode(output.stderr));
  return {
    port,
    result: JSON.parse(decoder.decode(output.stdout).trim()),
    records: readAudit(auditPath),
  };
}

function exactInspectorAuditIndex(
  records,
  principal,
  port,
  decision,
  afterIndex = -1,
) {
  return records.findIndex((record, index) =>
    index > afterIndex && record.v === 1 && record.principal === principal &&
    record.capability === "inspector:activate" &&
    record.target === `protected-inspector-stream:127.0.0.1:${port}` &&
    record.decision === decision && record.suggestion === null
  );
}

const nodeWrites = [
  ["default", "passedNodeSocket", "rootNodeSocket"],
  ["buffer", "passedNodeSocketWriteBuffer", "rootNodeSocketWriteBuffer"],
  ["writev", "passedNodeSocketWritev", "rootNodeSocketWritev"],
  ["ascii", "passedNodeSocketWriteAscii", "rootNodeSocketWriteAscii"],
  ["latin1", "passedNodeSocketWriteLatin1", "rootNodeSocketWriteLatin1"],
  ["ucs2", "passedNodeSocketWriteUcs2", "rootNodeSocketWriteUcs2"],
];

try {
  const main = await runInspectorChild(
    "endpoint_child.js",
    [],
    "main",
    10_000,
  );
  const result = main.result;
  let allNodeWritesEvidenced = true;
  for (const [method, deniedField, rootField] of nodeWrites) {
    const isolated = await runInspectorChild(
      "endpoint_node_write_child.js",
      [method],
      `node-${method}`,
      5_000,
    );
    const deniedAuditIndex = exactInspectorAuditIndex(
      isolated.records,
      "endpoint-denied",
      isolated.port,
      "deny",
    );
    const rootAuditIndex = exactInspectorAuditIndex(
      isolated.records,
      "root/runtime",
      isolated.port,
      "allow-ambient",
      deniedAuditIndex,
    );
    const evidenced = isolated.result.denied === "EACCES" &&
      isolated.result.root === "ALLOWED" &&
      deniedAuditIndex >= 0 && rootAuditIndex > deniedAuditIndex;
    result[deniedField] = evidenced ? "DENIED" : "BROKEN";
    result[rootField] = isolated.result.root;
    allNodeWritesEvidenced &&= evidenced;
  }
  result.nodeWriteAudit = allNodeWritesEvidenced ? "EVIDENCED" : "BROKEN";
  const nativeStream = await runInspectorChild(
    "endpoint_native_stream_child.js",
    [],
    "native-stream",
    8_000,
  );
  Object.assign(result, nativeStream.result);
  const nativePreload = await runInspectorChild(
    "endpoint_native_preload_child.js",
    [],
    "native-preload",
    8_000,
  );
  Object.assign(result, nativePreload.result);
  console.log(JSON.stringify(result));
} finally {
  Deno.removeSync(auditDir, { recursive: true });
}

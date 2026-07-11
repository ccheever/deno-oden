const here = new URL(".", import.meta.url);
const policy = new URL("capsec_enforce.json", here).pathname;
const child = new URL("startup_child.js", here).pathname;
const decoder = new TextDecoder();
const encoder = new TextEncoder();

async function runBounded(args, auditPath, input) {
  const childProcess = new Deno.Command(Deno.execPath(), {
    args,
    env: {
      ...Deno.env.toObject(),
      ODEN_CAPSEC_AUDIT: auditPath,
      ODEN_CAPSEC_POLICY: policy,
    },
    stdin: input === undefined ? "null" : "piped",
    stdout: "piped",
    stderr: "piped",
  }).spawn();
  const outputPromise = childProcess.output();
  if (input !== undefined) {
    const writer = childProcess.stdin.getWriter();
    await writer.write(encoder.encode(input));
    await writer.close();
  }

  let timeoutId;
  const timeout = new Promise((resolve) => {
    timeoutId = setTimeout(() => resolve(null), 5_000);
  });
  const output = await Promise.race([outputPromise, timeout]);
  clearTimeout(timeoutId);
  if (output !== null) return output;

  try {
    childProcess.kill("SIGKILL");
  } catch {
    // The child may have exited on the timeout boundary.
  }
  await outputPromise;
  return null;
}

async function regularFiles(path) {
  const files = [];
  for await (const entry of Deno.readDir(path)) {
    if (entry.isFile) files.push(entry.name);
  }
  return files;
}

async function auditRecords(path) {
  try {
    const text = await Deno.readTextFile(path);
    return text.trim().split("\n").filter(Boolean).map((line) =>
      JSON.parse(line)
    );
  } catch {
    return [];
  }
}

function exactTrustedHostGuards(records, target) {
  return ["runtime:inspect", "inspector:activate"].every((capability) =>
    records.filter((record) =>
      record.v === 1 &&
      record.principal === "root/runtime" &&
      record.capability === capability &&
      record.target === target &&
      record.decision === "allow" &&
      record.suggestion === null
    ).length === 1
  );
}

const coverageDir = await Deno.makeTempDir({ prefix: "oden-coverage-" });
const profileDir = await Deno.makeTempDir({ prefix: "oden-cpu-profile-" });
const auditDir = await Deno.makeTempDir({ prefix: "oden-tooling-audit-" });
try {
  const coverageAuditPath = `${auditDir}/coverage.ndjson`;
  const coverage = await runBounded([
    "run",
    "--no-config",
    "--allow-all",
    `--coverage=${coverageDir}`,
    child,
  ], coverageAuditPath);
  const coverageFiles = await regularFiles(coverageDir);
  const coverageRecords = await auditRecords(coverageAuditPath);

  const cpuAuditPath = `${auditDir}/cpu.ndjson`;
  const cpu = await runBounded([
    "run",
    "--no-config",
    "--allow-all",
    `--cpu-prof-dir=${profileDir}`,
    "--cpu-prof-name=trusted-tooling.cpuprofile",
    child,
  ], cpuAuditPath);
  const cpuFiles = await regularFiles(profileDir);
  const cpuRecords = await auditRecords(cpuAuditPath);

  const replAuditPath = `${auditDir}/repl.ndjson`;
  const repl = await runBounded(
    ["repl", "--no-config", "--quiet"],
    replAuditPath,
    "1 + 1\n",
  );
  const replRecords = await auditRecords(replAuditPath);

  console.log(JSON.stringify({
    coverage: coverage !== null && coverage.success &&
        coverageFiles.some((name) => name.endsWith(".json")) &&
        decoder.decode(coverage.stdout).includes("STARTED")
      ? "ALLOWED"
      : coverage === null
      ? "HUNG"
      : "BROKEN",
    coverageGuards: exactTrustedHostGuards(
        coverageRecords,
        "coverage:precise",
      )
      ? "ALLOWED"
      : "BROKEN",
    cpu: cpu !== null && cpu.success &&
        cpuFiles.includes("trusted-tooling.cpuprofile") &&
        decoder.decode(cpu.stdout).includes("STARTED")
      ? "ALLOWED"
      : cpu === null
      ? "HUNG"
      : "BROKEN",
    cpuGuards: exactTrustedHostGuards(cpuRecords, "profiler:cpu")
      ? "ALLOWED"
      : "BROKEN",
    repl: repl !== null && repl.success &&
        /(^|\s)2(\s|$)/.test(decoder.decode(repl.stdout))
      ? "ALLOWED"
      : repl === null
      ? "HUNG"
      : "BROKEN",
    localInspectorSessionGuards: exactTrustedHostGuards(
        replRecords,
        "inspector:local-session",
      )
      ? "ALLOWED"
      : "BROKEN",
  }));
} finally {
  await Deno.remove(coverageDir, { recursive: true });
  await Deno.remove(profileDir, { recursive: true });
  await Deno.remove(auditDir, { recursive: true });
}

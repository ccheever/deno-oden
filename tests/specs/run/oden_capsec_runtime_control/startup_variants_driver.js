const here = new URL(".", import.meta.url);
const child = new URL("startup_child.js", here).pathname;
const noRootPolicy = new URL("capsec_no_root.json", here).pathname;
const exactRootPolicy = new URL("capsec_root.json", here).pathname;
const decoder = new TextDecoder();

async function runBounded(args, policy, extraEnv = {}) {
  const childProcess = new Deno.Command(Deno.execPath(), {
    args: ["run", "--allow-all", ...args, child],
    env: {
      ...Deno.env.toObject(),
      ...extraEnv,
      ODEN_CAPSEC_POLICY: policy,
    },
    stdout: "piped",
    stderr: "piped",
  }).spawn();
  const outputPromise = childProcess.output();
  let timeoutId;
  const timeout = new Promise((resolve) => {
    timeoutId = setTimeout(() => resolve(null), 2_000);
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
    return null;
  }
  return output;
}

async function denied(args) {
  const output = await runBounded(args, noRootPolicy);
  if (output === null) return "HUNG";
  const stdout = decoder.decode(output.stdout);
  const stderr = decoder.decode(output.stderr);
  return !output.success && !stdout.includes("STARTED") &&
      stderr.includes("oden capsec: inspector activation at") &&
      stderr.includes("requires an exact static inspector:activate row")
    ? "DENIED"
    : "BROKEN";
}

async function nodeOptions(policy, expected) {
  const output = await runBounded([], policy, {
    NODE_OPTIONS: "--inspect=127.0.0.1:0",
  });
  if (output === null) return "HUNG";
  const stdout = decoder.decode(output.stdout);
  const stderr = decoder.decode(output.stderr);
  const started = output.success && stdout.includes("STARTED");
  const debuggerListening = stderr.includes("Debugger listening on ws://");
  return started && debuggerListening === (expected === "ALLOWED")
    ? expected
    : "BROKEN";
}

console.log(JSON.stringify({
  inspectBrk: await denied(["--inspect-brk=127.0.0.1:0"]),
  inspectWait: await denied(["--inspect-wait=127.0.0.1:0"]),
  inspectPublishUid: await denied([
    "--inspect=127.0.0.1:0",
    "--inspect-publish-uid=http",
  ]),
  nodeOptionsIgnored: await nodeOptions(noRootPolicy, "IGNORED"),
  nodeOptionsAllowed: await nodeOptions(exactRootPolicy, "ALLOWED"),
}));

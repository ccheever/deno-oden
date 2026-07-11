const here = new URL(".", import.meta.url);

async function probe(policy) {
  const childProcess = new Deno.Command(Deno.execPath(), {
    args: [
      "run",
      "--allow-all",
      "--inspect=127.0.0.1:0",
      new URL("startup_child.js", here).pathname,
    ],
    env: {
      ...Deno.env.toObject(),
      ODEN_CAPSEC_POLICY: new URL(policy, here).pathname,
    },
    stdout: "piped",
    stderr: "piped",
  }).spawn();
  const outputPromise = childProcess.output();
  let timeoutId;
  const timeout = new Promise((resolve) => {
    timeoutId = setTimeout(() => resolve(null), 3_000);
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
    return "HUNG";
  }
  const stdout = new TextDecoder().decode(output.stdout);
  return { success: output.success, started: stdout.includes("STARTED") };
}

console.log(JSON.stringify({
  noRoot: await probe("capsec_no_root.json"),
  root: await probe("capsec_root.json"),
}));

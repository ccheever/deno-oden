const here = new URL(".", import.meta.url);

async function probe(policy, programmatic = false) {
  const child = new Deno.Command(Deno.execPath(), {
    args: [
      "run",
      "--allow-all",
      new URL("signal_child.js", here).pathname,
      ...(programmatic ? ["self"] : []),
    ],
    env: {
      ...Deno.env.toObject(),
      ODEN_CAPSEC_POLICY: new URL(policy, here).pathname,
    },
    stdout: "piped",
    stderr: "piped",
  }).spawn();
  let timedOut = false;
  const timeoutId = setTimeout(() => {
    timedOut = true;
    try {
      child.kill("SIGKILL");
    } catch {
      // The child may have exited on the timeout boundary.
    }
  }, 3_000);
  const reader = child.stdout.getReader();
  const decoder = new TextDecoder();
  let stdout = "";
  while (!stdout.includes("READY\n")) {
    const chunk = await reader.read();
    if (chunk.done) break;
    stdout += decoder.decode(chunk.value, { stream: true });
  }
  if (timedOut) {
    await child.status;
    return "HUNG";
  }
  if (!stdout.includes("READY\n")) {
    clearTimeout(timeoutId);
    throw new Error("child exited before readiness");
  }
  if (!programmatic) Deno.kill(child.pid, "SIGUSR1");
  while (true) {
    const chunk = await reader.read();
    if (chunk.done) break;
    stdout += decoder.decode(chunk.value, { stream: true });
  }
  stdout += decoder.decode();
  const status = await child.status;
  clearTimeout(timeoutId);
  if (timedOut) return "HUNG";
  return { success: status.success, open: stdout.includes("INSPECTOR=OPEN") };
}

console.log(JSON.stringify({
  noRoot: await probe("capsec_no_root.json"),
  root: await probe("capsec_root.json"),
  programmaticRoot: await probe("capsec_no_root.json", true),
}));

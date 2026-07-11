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
  const reader = child.stdout.getReader();
  const decoder = new TextDecoder();
  let stdout = "";
  while (!stdout.includes("READY\n")) {
    const chunk = await reader.read();
    if (chunk.done) break;
    stdout += decoder.decode(chunk.value, { stream: true });
  }
  if (!stdout.includes("READY\n")) {
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
  return { success: status.success, open: stdout.includes("INSPECTOR=OPEN") };
}

console.log(JSON.stringify({
  noRoot: await probe("capsec_no_root.json"),
  root: await probe("capsec_root.json"),
  programmaticRoot: await probe("capsec_no_root.json", true),
}));

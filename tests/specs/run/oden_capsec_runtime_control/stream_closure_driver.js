const here = new URL(".", import.meta.url);
const decoder = new TextDecoder();

// This is an intentionally unregistered red-team harness. LEAK is a failing
// security outcome captured in stream_closure_baseline_327.evidence.json, not
// an accepted test golden. Register it only after every required field closes.

function reservePort() {
  const listener = Deno.listen({ hostname: "127.0.0.1", port: 0 });
  const port = listener.addr.port;
  listener.close();
  return port;
}

const port = reservePort();
const child = new Deno.Command(Deno.execPath(), {
  args: [
    "run",
    "--allow-all",
    "--unstable-net",
    `--inspect=127.0.0.1:${port}`,
    new URL("stream_closure_child.js", here).pathname,
    String(port),
  ],
  env: {
    ...Deno.env.toObject(),
    ODEN_CAPSEC_POLICY: new URL("capsec_endpoint.json", here).pathname,
  },
  stdout: "piped",
  stderr: "piped",
}).spawn();

const outputPromise = child.output();
let timeoutId;
const timeout = new Promise((resolve) => {
  timeoutId = setTimeout(() => resolve(null), 15_000);
});
const output = await Promise.race([outputPromise, timeout]);
clearTimeout(timeoutId);

if (output === null) {
  try {
    child.kill("SIGKILL");
  } catch {
    // The child may have exited on the timeout boundary.
  }
  const killed = await outputPromise;
  throw new Error(
    `stream closure fixture child hung\n${decoder.decode(killed.stderr)}`,
  );
}
if (!output.success) throw new Error(decoder.decode(output.stderr));
console.log(decoder.decode(output.stdout).trim());

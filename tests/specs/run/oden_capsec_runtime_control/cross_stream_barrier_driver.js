const here = new URL(".", import.meta.url);
const decoder = new TextDecoder();

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
    new URL("cross_stream_barrier_child.js", here).pathname,
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
  timeoutId = setTimeout(() => resolve(null), 30_000);
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
    `cross-stream barrier child hung\n${decoder.decode(killed.stderr)}`,
  );
}
if (!output.success) throw new Error(decoder.decode(output.stderr));
console.log(decoder.decode(output.stdout).trim());

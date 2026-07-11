const here = new URL(".", import.meta.url);
const decoder = new TextDecoder();

const listener = Deno.listen({ hostname: "127.0.0.1", port: 0 });
const port = listener.addr.port;
listener.close();

const child = new Deno.Command(Deno.execPath(), {
  args: [
    "run",
    "--allow-all",
    `--inspect=127.0.0.1:${port}`,
    new URL("fd_transfer_child.js", here).pathname,
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
  timeoutId = setTimeout(() => resolve(null), 10_000);
});
const output = await Promise.race([outputPromise, timeout]);
clearTimeout(timeoutId);
if (output === null) {
  try {
    child.kill("SIGKILL");
  } catch {
    // Child may have exited on the timeout boundary.
  }
  await outputPromise;
  throw new Error("fd-transfer fixture child hung");
}
if (!output.success) throw new Error(decoder.decode(output.stderr));
console.log(decoder.decode(output.stdout).trim());

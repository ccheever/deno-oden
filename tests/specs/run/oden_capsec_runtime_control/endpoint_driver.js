const here = new URL(".", import.meta.url);
const probe = Deno.listen({ hostname: "127.0.0.1", port: 0 });
const port = probe.addr.port;
probe.close();

const output = await new Deno.Command(Deno.execPath(), {
  args: [
    "run",
    "--allow-all",
    `--inspect=127.0.0.1:${port}`,
    new URL("endpoint_child.js", here).pathname,
    String(port),
  ],
  env: {
    ...Deno.env.toObject(),
    ODEN_CAPSEC_POLICY: new URL("capsec_endpoint.json", here).pathname,
  },
  stdout: "piped",
  stderr: "piped",
}).output();

if (!output.success) {
  throw new Error(new TextDecoder().decode(output.stderr));
}
console.log(new TextDecoder().decode(output.stdout).trim());

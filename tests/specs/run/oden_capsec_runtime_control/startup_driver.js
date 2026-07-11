const here = new URL(".", import.meta.url);

async function probe(policy) {
  const command = new Deno.Command(Deno.execPath(), {
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
  });
  const output = await command.output();
  const stdout = new TextDecoder().decode(output.stdout);
  return { success: output.success, started: stdout.includes("STARTED") };
}

console.log(JSON.stringify({
  noRoot: await probe("capsec_no_root.json"),
  root: await probe("capsec_root.json"),
}));

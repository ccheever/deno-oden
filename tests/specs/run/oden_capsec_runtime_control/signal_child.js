import inspector from "node:inspector";

console.log("READY");
if (Deno.args[0] === "self") Deno.kill(Deno.pid, "SIGUSR1");
await new Promise((resolve) => setTimeout(resolve, 600));
const open = inspector.url() !== undefined;
console.log(`INSPECTOR=${open ? "OPEN" : "CLOSED"}`);
if (open) inspector.close();

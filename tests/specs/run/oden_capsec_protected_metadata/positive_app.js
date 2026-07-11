let protectedDenied = false;
try {
  const conn = await Deno.connect({
    hostname: "fd00:ec2::254",
    port: 1,
    signal: AbortSignal.timeout(500),
  });
  conn.close();
} catch (error) {
  protectedDenied = error?.name === "NotCapable" &&
    String(error?.message).includes("protected metadata denied");
}
console.log(`EXACT:${protectedDenied ? "DENIED" : "CONTINUED"}`);

const audit = Deno.readTextFileSync("positive-audit.ndjson");
const evidence = audit.includes('"decider":"protected-negative-continuation"') &&
  audit.includes('"reasonDigest":"607c9120956161f11d18408e12fe1bd98be86c88d14eacafb0b46378dfd21e0f"') &&
  audit.includes('"receiptDigest":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"') &&
  audit.includes('"receiptSetDigest":"260cedec1913d7d3da2c4edc4cf3eb5b276e14068cb89eb4877fd3a3b7d2606c"');
console.log(`EVIDENCE:${evidence ? "BOUND" : "MISSING"}`);

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
  audit.includes('"receiptSetDigest":"553e836b2e8476419f6078dfb9f6d1cc87ba07ac0392c6fc8b6eeb7c87644d65"');
console.log(`EVIDENCE:${evidence ? "BOUND" : "MISSING"}`);

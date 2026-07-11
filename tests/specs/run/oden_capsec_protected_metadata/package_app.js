import { connectProtected } from "./node_modules/protected-dep/index.js";

let protectedDenied = false;
try {
  const conn = await connectProtected();
  conn.close();
} catch (error) {
  protectedDenied = error?.name === "NotCapable" &&
    String(error?.message).includes("protected metadata denied");
}
console.log(`PACKAGE:${protectedDenied ? "DENIED" : "CONTINUED"}`);

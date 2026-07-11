function protectedDenial(error) {
  return error?.name === "NotCapable" &&
    (String(error?.message).includes("protected metadata denied") ||
      String(error?.message).includes("forward proxies are closed"));
}

async function report(label, operation) {
  try {
    const resource = await operation();
    resource?.close?.();
    console.log(`${label}:UNEXPECTED-ALLOW`);
  } catch (error) {
    console.log(`${label}:${protectedDenial(error) ? "DENIED" : "OTHER"}`);
  }
}

switch (Deno.args[0]) {
  case "direct":
    await report("DIRECT", () =>
      Deno.connect({ hostname: "169.254.169.254", port: 80 }));
    break;
  case "mapped":
    await report("MAPPED", () =>
      Deno.connect({ hostname: "::ffff:169.254.169.254", port: 80 }));
    break;
  case "redirect": {
    const server = Deno.serve(
      { hostname: "127.0.0.1", port: 0, onListen() {} },
      () => Response.redirect("http://169.254.169.254/latest/meta-data/"),
    );
    const port = server.addr.port;
    await report("REDIRECT", () => fetch(`http://127.0.0.1:${port}/`));
    await server.shutdown();
    break;
  }
  case "udp": {
    const socket = Deno.listenDatagram({
      hostname: "127.0.0.1",
      port: 0,
      transport: "udp",
    });
    await report("UDP", () =>
      socket.send(new Uint8Array([1]), {
        hostname: "169.254.170.2",
        port: 80,
        transport: "udp",
      }));
    socket.close();
    break;
  }
  case "proxy":
    await report("PROXY", () =>
      Promise.resolve(Deno.createHttpClient({
        proxy: { url: "http://127.0.0.1:9" },
      })));
    break;
  default:
    throw new Error(`unknown probe ${Deno.args[0]}`);
}

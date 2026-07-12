import { runNetworkActionMatrix } from "./node_modules/network-probe/index.js";

const grantedAction = Deno.args[0];
const socketPath = `${Deno.cwd()}/.oden-network-actions-${Deno.pid}.sock`;
const reservation = Deno.listen({ hostname: "127.0.0.1", port: 0 });
const closedPort = reservation.addr.port;
reservation.close();
await runNetworkActionMatrix(
  grantedAction,
  socketPath,
  Deno.args[1],
  closedPort,
);

import { runNetworkActionMatrix } from "./node_modules/network-probe/index.js";

const grantedAction = Deno.args[0];
const socketPath = `${Deno.cwd()}/.oden-network-actions-${Deno.pid}.sock`;
await runNetworkActionMatrix(grantedAction, socketPath, Deno.args[1]);

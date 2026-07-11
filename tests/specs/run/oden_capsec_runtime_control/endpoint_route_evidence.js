const root = new URL("../../../../", import.meta.url);

async function source(path) {
  return await Deno.readTextFile(new URL(path, root));
}

function section(text, start, end) {
  const startIndex = text.indexOf(start);
  const endIndex = text.indexOf(end, startIndex + start.length);
  return startIndex >= 0 && endIndex > startIndex
    ? text.slice(startIndex, endIndex)
    : "";
}

const websocket = await source("ext/websocket/lib.rs");
const legacyWebSocket = await source("ext/websocket/01_websocket.js");
const streams = await source("ext/web/06_streams.js");

const ping = section(
  websocket,
  "pub async fn op_ws_send_ping(",
  "pub async fn op_ws_next_event(",
);
const pingTimer = section(
  legacyWebSocket,
  "[_serverHandleIdleTimeout]()",
  '[SymbolFor("Deno.privateCustomInspect")]',
);
const backing = section(
  streams,
  "function getReadableStreamResourceBacking(stream)",
  "async function readableStreamCollectIntoUint8Array(stream)",
);
const collector = section(
  streams,
  "async function readableStreamCollectIntoUint8Array(stream)",
  "function writableStreamForRid(",
);

const evidence = {
  websocketPingGuard: ping.includes(
    'resource.check_protected_inspector_use("WebSocket.ping")',
  ),
  websocketPingPublicReachability: pingTimer.includes(
    "await PromisePrototypeCatch(op_ws_send_ping(this[_rid]), () => {});",
  ),
  unrefableBackingSharedGuard: backing.includes(
    "function getReadableStreamResourceBackingUnrefable(stream)",
  ) && backing.match(/runReadableStreamUseGuard\(stream\);/g)?.length === 2,
  unrefableBackingDominated: collector.includes(
    "getReadableStreamResourceBacking(stream) ||\n    getReadableStreamResourceBackingUnrefable(stream)",
  ),
};

console.log(JSON.stringify(Object.fromEntries(
  Object.entries(evidence).map(([name, value]) => [
    name,
    value ? "EVIDENCED" : "MISSING",
  ]),
)));

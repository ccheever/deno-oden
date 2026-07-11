const root = new URL("../../../../", import.meta.url);

async function source(path) {
  return await Deno.readTextFile(new URL(path, root));
}

function section(text, startMarker, endMarker) {
  const start = text.indexOf(startMarker);
  const end = text.indexOf(endMarker, start + startMarker.length);
  return start >= 0 && end > start ? text.slice(start, end) : "";
}

function containsAll(text, markers) {
  return text !== "" && markers.every((marker) => text.includes(marker));
}

function ordered(text, ...markers) {
  let index = -1;
  for (const marker of markers) {
    index = text.indexOf(marker, index + 1);
    if (index < 0) return false;
  }
  return true;
}

const flags = await source("cli/args/flags.rs");
const factory = await source("cli/factory.rs");
const runtimeWorker = await source("runtime/worker.rs");
const webWorker = await source("runtime/web_worker.rs");
const webWorkerOps = await source("runtime/ops/web_worker.rs");
const requireOps = await source("ext/node/ops/require.rs");
const inspectorOps = await source("ext/node/ops/inspector.rs");
const lsp = await source("cli/lsp/tsc.rs");
const desktopRuntime = await source("cli/rt_desktop/lib.rs");
const desktop = await source("cli/tools/desktop.rs");

const startupFactory = section(
  factory,
  "pub fn maybe_start_inspector_server(",
  "pub async fn module_load_preparer(",
);
const mainWorkerFromOptions = section(
  runtimeWorker,
  "fn from_options<",
  "pub fn bootstrap(&mut self",
);
const webWorkerFromOptions = section(
  webWorker,
  "pub fn from_options<",
  "pub fn bootstrap(&mut self",
);
const webWorkerWait = section(
  webWorkerOps,
  "fn op_worker_maybe_wait_for_debugger(",
  "fn op_worker_close(",
);
const cjsBreakNext = section(
  requireOps,
  "pub fn op_require_break_on_next_statement(",
  "pub fn op_require_can_parse_as_esm(",
);
const cjsBreakAuthorization = section(
  requireOps,
  "fn with_require_break_authorization<T>(",
  "pub fn op_require_can_parse_as_esm(",
);
const nodeReplConnect = section(
  inspectorOps,
  "pub fn op_node_repl_inspector_connect<'s>(",
  "pub fn op_inspector_dispatch(",
);
const lspEnsureStarted = section(
  lsp,
  "pub fn ensure_started(&self)",
  "pub fn is_started(&self)",
);
const desktopRuntimeRun = desktopRuntime.slice(
  desktopRuntime.indexOf("async fn run_desktop("),
);
const desktopHmr = section(
  desktop,
  "async fn run_desktop_hmr(",
  "async fn package_desktop_app(",
);

const evidenced = {
  inspectFlagParsed: flags.includes('Arg::new("inspect")'),
  inspectBrkFlagParsed: flags.includes('Arg::new("inspect-brk")'),
  inspectWaitFlagParsed: flags.includes('Arg::new("inspect-wait")'),
  inspectPublishUidFlagParsed: flags.includes(
    'Arg::new("inspect-publish-uid")',
  ),
  inspectRendererFlagParsed: flags.includes('Arg::new("inspect-renderer")'),
  nodeOptionsInspectParsed: flags.includes("is_inspect_node_option"),
  startupPreflight: ordered(
    startupFactory,
    "oden_capsec_check_inspector_listener_startup(",
    "create_inspector_server(",
  ),
  runtimeRegistration: ordered(
    mainWorkerFromOptions,
    "oden_capsec_check_inspector_activation(",
    "server.register_inspector(",
  ),
  webWorkerPairing: ordered(
    webWorkerFromOptions,
    "oden_capsec_check_inspector_activation(",
    '"runtime:web-worker-session-pair"',
    "create_worker_inspector_session_pair(",
  ),
  webWorkerWait: ordered(
    webWorkerWait,
    "oden_capsec_check_inspector_activation(",
    '"startup:worker-wait-for-debugger"',
    "wait_for_debugger_enabled_for_worker_message(",
  ),
  cjsBreakNext: cjsBreakNext.includes("with_require_break_authorization(||") &&
    cjsBreakNext.includes("wait_for_session_and_break_on_next_statement(") &&
    ordered(
      cjsBreakAuthorization,
      "oden_capsec_check_inspector_activation(",
      '"node:require.break-on-next-statement"',
      "Ok(effect())",
    ),
  nodeReplConnect: ordered(
    nodeReplConnect,
    "oden_capsec_check_inspector_activation(",
    '"node:repl.inspector-preview"',
    "create_local_session(",
  ),
  lspPreflight: ordered(
    lspEnsureStarted,
    '"LSP TypeScript inspector startup"',
    "InspectorServer::new(",
  ),
  desktopRuntimePreflight: ordered(
    desktopRuntimeRun,
    '"desktop inspector startup"',
    "create_inspector_server(",
  ),
  desktopMuxPreflight: containsAll(desktopHmr, [
    '"desktop DevTools multiplexer startup"',
    '"desktop-mux-internal-port-allocation"',
    '"desktop-mux-deno-and-cef-upstreams"',
  ]) && ordered(
    desktopHmr,
    "oden_capsec_check_inspector_listener_startup(",
    "oden_capsec_record_inspector_root_network_effect(",
    "spawn_mux(",
  ),
};

console.log(JSON.stringify(Object.fromEntries(
  Object.entries(evidenced).map(([name, value]) => [
    name,
    value ? "EVIDENCED" : "MISSING",
  ]),
)));

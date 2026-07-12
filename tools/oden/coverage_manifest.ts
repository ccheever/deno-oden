#!/usr/bin/env -S deno run --allow-read
// Copyright 2018-2026 the Deno authors. MIT license.
//
// Oden op-coverage completeness manifest (LLP 0001 Phase 0).
//
// Enumerates three things that together define the capsec mediation surface:
//   1. the capsec-mediated permission checks — every `oden_capsec_decide(...)`
//      call site, by (family, action) and enclosing fn, in the permission layer;
//   2. the op-body pre-check *skips* — every `query_read_all()` call site (the
//      fast paths that bypass the permission container when read is fully
//      granted), which capsec forces closed while armed;
//   3. the capability taxonomy / descriptor mapping for every mediated
//      family:action pair.
//
// The manifest is committed. `--check` regenerates it and diffs against the
// committed copy, exiting non-zero on drift — so a new upstream op that touches a
// mediated resource, or a new op-body skip, is a loud rebase delta rather than a
// silent coverage gap.
//
// Self-contained: uses only Deno built-ins (the fork's vendored std may be
// absent). Run from `fork/deno`: `deno run --allow-read tools/oden/coverage_manifest.ts [--check]`.
// @ref llp/0001-adding-capability-security-to-deno.plan.md

const ROOT = new URL("../../", import.meta.url).pathname;
const MANIFEST = ROOT + "tools/oden/op_coverage.manifest.md";

// Directories scanned for op-body skips. Kept explicit so the scan is stable.
const SKIP_SCAN_DIRS = ["ext", "runtime", "libs"];
const MEDIATION_FILE = "runtime/permissions/lib.rs";
const NETWORK_ACTIONS = ["fetch", "connect", "listen"] as const;

type NetworkAction = (typeof NETWORK_ACTIONS)[number];

type TaxonomyEntry = {
  deno: string;
  target: string;
  grant: string;
};

const CAPABILITY_TAXONOMY: Record<string, TaxonomyEntry> = {
  "env:read": {
    deno: "EnvDescriptor / EnvQueryDescriptor",
    target: "name or *",
    grant: "env:read:<name>",
  },
  "env:write": {
    deno: "EnvDescriptor / EnvQueryDescriptor",
    target: "name",
    grant: "env:write:<name>",
  },
  "ffi:load": {
    deno: "FfiQueryDescriptor",
    target: "path or *",
    grant: "ffi",
  },
  "fs:read": {
    deno: "ReadDescriptor / ReadQueryDescriptor",
    target: "canonical path or *",
    grant: "fs:read:<path>",
  },
  "fs:write": {
    deno: "WriteDescriptor / WriteQueryDescriptor",
    target: "canonical path or *",
    grant: "fs:write:<path>",
  },
  "network:connect": {
    deno: "NetDescriptor (typed operation action)",
    target: "host, URL, vsock, or unix socket",
    grant: "network:connect:<endpoint>",
  },
  "network:fetch": {
    deno: "NetDescriptor / ImportDescriptor (typed operation action)",
    target:
      "direct HTTP(S) host/redirect, vsock, or Unix socket; attested proxy only in a later profile",
    grant: "network:fetch:<endpoint>",
  },
  "network:listen": {
    deno: "NetDescriptor (typed operation action)",
    target: "bound host, vsock, or unix socket",
    grant: "network:listen:<endpoint>",
  },
  "run:run": {
    deno: "RunQueryDescriptor",
    target: "command display name or *",
    grant: "run:<command>",
  },
  "sys:read": {
    deno: "SysDescriptor / SysQueryDescriptor",
    target: "system-information kind or *",
    grant: "sys:read:<kind>",
  },
  "worker:create": {
    deno: "op_create_worker capsec gate",
    target: "worker specifier",
    grant:
      "default-denied for package principals until inheritance is designed",
  },
  "import:graph": {
    deno: "ModuleLoader inner_resolve capsec gate (referrer-attributed)",
    target: "resolved HTTP(S) graph target; frozen /1 also gates data:/blob:",
    grant:
      "package HTTP(S) imports deny; /1.1 data is quarantined non-capability and blob/unknown close structurally",
  },
};

function* walk(dir: string): Generator<string> {
  let entries: Deno.DirEntry[];
  try {
    entries = [...Deno.readDirSync(dir)];
  } catch {
    return;
  }
  entries.sort((a, b) => (a.name < b.name ? -1 : 1));
  for (const e of entries) {
    const p = dir + "/" + e.name;
    if (e.isDirectory) {
      if (e.name === "target" || e.name === "node_modules") continue;
      yield* walk(p);
    } else if (e.isFile && p.endsWith(".rs")) {
      yield p;
    }
  }
}

type RustCall = {
  args: string[];
  fn: string;
  line: number;
  name: string;
  offset: number;
};

/**
 * Replace Rust comments and string/character contents with spaces while
 * preserving offsets and newlines. Balanced-call parsing can then ignore
 * parentheses and commas that are not syntax. This is deliberately a small
 * lexer, not a line regex: every matching call is either parsed or fatal.
 */
function maskRust(src: string): string {
  // `split("")` intentionally preserves UTF-16 code-unit offsets; spreading
  // would collapse astral characters and desynchronize every later slice.
  const out = src.split("");
  let i = 0;
  let blockDepth = 0;
  let quote: '"' | "'" | null = null;
  let rawHashes = -1;

  const blank = (at: number) => {
    if (out[at] !== "\n" && out[at] !== "\r") out[at] = " ";
  };

  while (i < src.length) {
    if (blockDepth > 0) {
      if (src.startsWith("/*", i)) {
        blank(i++);
        blank(i++);
        blockDepth++;
      } else if (src.startsWith("*/", i)) {
        blank(i++);
        blank(i++);
        blockDepth--;
      } else {
        blank(i++);
      }
      continue;
    }

    if (rawHashes >= 0) {
      const close = '"' + "#".repeat(rawHashes);
      if (src.startsWith(close, i)) {
        for (let j = 0; j < close.length; j++) blank(i++);
        rawHashes = -1;
      } else {
        blank(i++);
      }
      continue;
    }

    if (quote !== null) {
      if (src[i] === "\\") {
        blank(i++);
        if (i < src.length) blank(i++);
      } else if (src[i] === quote) {
        blank(i++);
        quote = null;
      } else {
        blank(i++);
      }
      continue;
    }

    if (src.startsWith("//", i)) {
      while (i < src.length && src[i] !== "\n") blank(i++);
      continue;
    }
    if (src.startsWith("/*", i)) {
      blank(i++);
      blank(i++);
      blockDepth = 1;
      continue;
    }

    const raw = src.slice(i).match(/^r(#+)?"/);
    if (raw) {
      rawHashes = raw[1]?.length ?? 0;
      for (let j = 0; j < raw[0].length; j++) blank(i++);
      continue;
    }
    if (src[i] === '"') {
      quote = '"';
      blank(i++);
      continue;
    }
    // Do not mistake Rust lifetimes ('a) for character literals.
    if (
      src[i] === "'" &&
      (src[i + 2] === "'" ||
        (src[i + 1] === "\\" && src[i + 3] === "'"))
    ) {
      quote = "'";
      blank(i++);
      continue;
    }
    i++;
  }

  if (blockDepth !== 0 || quote !== null || rawHashes >= 0) {
    throw new Error("unterminated Rust comment or literal while scanning");
  }
  return out.join("");
}

function lineAt(src: string, offset: number): number {
  let line = 1;
  for (let i = 0; i < offset; i++) if (src.charCodeAt(i) === 10) line++;
  return line;
}

function enclosingFn(masked: string, offset: number): string {
  // The name token is sufficient here and avoids pretending nested Rust
  // generic bounds (for example `T: AsRef<str>`) are a regular language.
  const re = /\bfn\s+([A-Za-z_][A-Za-z0-9_]*)\b/g;
  let found = "<module>";
  for (let m; (m = re.exec(masked)) && m.index < offset;) found = m[1];
  return found;
}

function rustFunctionBodyMasked(src: string, fnName: string): string {
  const masked = maskRust(src);
  const fnMatch = new RegExp(`\\bfn\\s+${fnName}\\b`).exec(masked);
  if (fnMatch === null) throw new Error(`missing Rust function ${fnName}()`);
  const open = masked.indexOf("{", fnMatch.index + fnMatch[0].length);
  if (open === -1) {
    throw new Error(`missing body for Rust function ${fnName}()`);
  }
  let depth = 0;
  for (let i = open; i < masked.length; i++) {
    if (masked[i] === "{") depth++;
    if (masked[i] === "}" && --depth === 0) {
      return masked.slice(open + 1, i);
    }
  }
  throw new Error(`unterminated body for Rust function ${fnName}()`);
}

function closeParen(masked: string, open: number): number {
  let depth = 0;
  for (let i = open; i < masked.length; i++) {
    if (masked[i] === "(") depth++;
    if (masked[i] === ")" && --depth === 0) return i;
  }
  throw new Error(`unterminated Rust call at line ${lineAt(masked, open)}`);
}

function splitArgs(
  src: string,
  masked: string,
  start: number,
  end: number,
): string[] {
  const args: string[] = [];
  let part = start;
  const stack: string[] = [];
  const closes: Record<string, string> = { ")": "(", "]": "[", "}": "{" };
  for (let i = start; i < end; i++) {
    const c = masked[i];
    if (c === "(" || c === "[" || c === "{") stack.push(c);
    else if (c === ")" || c === "]" || c === "}") {
      if (stack.pop() !== closes[c]) {
        throw new Error(`unbalanced Rust argument at line ${lineAt(src, i)}`);
      }
    } else if (c === "," && stack.length === 0) {
      args.push(src.slice(part, i).trim());
      part = i + 1;
    }
  }
  const final = src.slice(part, end).trim();
  if (final !== "") args.push(final);
  return args;
}

function collectCalls(
  src: string,
  callRe: RegExp,
  requireReceiver: boolean,
): RustCall[] {
  const masked = maskRust(src);
  const calls: RustCall[] = [];
  for (let m; (m = callRe.exec(masked));) {
    const name = m.groups?.name;
    if (!name) throw new Error("call scanner regex must provide a name group");
    const nameOffset = m.index + m[0].indexOf(name);
    if (requireReceiver) {
      const prefix = masked.slice(m.index, nameOffset);
      if (!prefix.includes(".") && !prefix.includes("::")) continue;
    } else if (
      /\bfn\s*$/.test(masked.slice(Math.max(0, m.index - 12), m.index))
    ) {
      continue;
    }
    const open = masked.indexOf("(", nameOffset + name.length);
    const close = closeParen(masked, open);
    calls.push({
      args: splitArgs(src, masked, open + 1, close),
      fn: enclosingFn(masked, nameOffset),
      line: lineAt(src, nameOffset),
      name,
      offset: nameOffset,
    });
  }
  return calls;
}

type NetworkCheck = RustCall & {
  action: NetworkAction;
  actionSource: "explicit" | "propagated";
  file: string;
};

const PROPAGATED_NETWORK_ACTIONS: Record<string, readonly NetworkAction[]> = {
  "ext/fetch/dns.rs:check_resolved": ["fetch", "connect"],
  "ext/net/ops_unix.rs:check_unix_socket_path": NETWORK_ACTIONS,
  "ext/node/ops/dns.rs:op_node_getaddrinfo": ["fetch", "connect"],
};

function collectNetworkChecks(): NetworkCheck[] {
  const enumSrc = Deno.readTextFileSync(ROOT + MEDIATION_FILE);
  const enumBody = maskRust(enumSrc).match(
    /pub enum NetPermissionAction\s*\{([^}]+)\}/s,
  );
  if (!enumBody) throw new Error("NetPermissionAction enum is missing");
  const variants = enumBody[1].split(",")
    .map((variant) => variant.trim())
    .filter(Boolean)
    .map((variant) => variant.toLowerCase())
    .sort();
  const expected = [...NETWORK_ACTIONS].sort();
  if (variants.join(",") !== expected.join(",")) {
    throw new Error(
      `NetPermissionAction must be exactly ${expected.join(", ")}; found ${
        variants.join(", ")
      }`,
    );
  }

  const found: NetworkCheck[] = [];
  const callRe =
    /\b(?<name>check_net(?:_url|_resolved|_vsock|_unix_socket)?)\s*\(/g;
  for (const file of walk(ROOT.replace(/\/$/, ""))) {
    const rel = file.slice(ROOT.length);
    const src = Deno.readTextFileSync(file);
    for (const call of collectCalls(src, callRe, false)) {
      const first = call.args[0]?.replace(/\s+/g, " ").trim();
      const explicit = first?.match(
        /^NetPermissionAction::(Fetch|Connect|Listen)$/,
      );
      if (explicit) {
        found.push({
          ...call,
          action: explicit[1].toLowerCase() as NetworkAction,
          actionSource: "explicit",
          file: rel,
        });
        continue;
      }
      const helper = `${rel}:${call.fn}`;
      const propagated = PROPAGATED_NETWORK_ACTIONS[helper];
      if (first === "action" && propagated) {
        for (const action of propagated) {
          found.push({
            ...call,
            action,
            actionSource: "propagated",
            file: rel,
          });
        }
        continue;
      }
      throw new Error(
        `unclassified ${call.name} action at ${rel}:${call.line} in ${call.fn}(): ${
          call.args[0] ?? "<missing>"
        }`,
      );
    }
  }
  if (found.length === 0) throw new Error("no network permission calls found");
  return found.sort((a, b) =>
    `${a.file}:${String(a.line).padStart(8, "0")}:${a.action}`.localeCompare(
      `${b.file}:${String(b.line).padStart(8, "0")}:${b.action}`,
    )
  );
}

type NetworkSurface = {
  action: NetworkAction | "closed";
  enforcement: "categorical" | "direct" | "inherited";
  file: string;
  fn: string;
  guard?: string;
  note: string;
  surface: string;
};

type NodeHttpSocketRoute = {
  action: "connect" | "closed";
  boundary: string;
  file: string;
  fixture: string;
  fn: string;
  route: string;
};

const NODE_HTTP_SOCKET_FIXTURE =
  "tests/specs/run/oden_capsec_node_http_socket_closure/node_modules/node-http-closure-probe/index.js";
const NODE_HTTP_SOCKET_SPEC =
  "tests/specs/run/oden_capsec_node_http_socket_closure/__test__.jsonc";
const NODE_HTTP_SOCKET_FETCH_POLICY =
  "tests/specs/run/oden_capsec_node_http_socket_closure/fetch_routes.json";
const NODE_HTTP_SOCKET_CONNECT_POLICY =
  "tests/specs/run/oden_capsec_node_http_socket_closure/connect.json";
const NODE_HTTP_SOCKET_FETCH_GOLDEN =
  "tests/specs/run/oden_capsec_node_http_socket_closure/routes_fetch.out";
const NODE_HTTP_SOCKET_CONNECT_GOLDEN =
  "tests/specs/run/oden_capsec_node_http_socket_closure/routes_connect.out";

// Every route in Node's request/response API that can reveal, delegate, or
// reuse the transport must lead to a connect-class native boundary or a
// stronger categorical closure. The generated rows are behavioral claims:
// validation binds every ID to the registered spec, distinct policies, and
// per-route goldens, while separate source checks pin the token classifiers.
const NODE_HTTP_SOCKET_ROUTES: NodeHttpSocketRoute[] = [
  {
    action: "connect",
    route: "request socket event/property",
    boundary: "built-in agent TCP creation",
    file: "ext/node/ops/tcp_wrap.rs",
    fn: "connect",
    fixture: "request-socket-event-property",
  },
  {
    action: "connect",
    route: "response socket write",
    boundary: "built-in agent TCP creation",
    file: "ext/node/ops/tcp_wrap.rs",
    fn: "connect",
    fixture: "response-socket-write",
  },
  {
    action: "connect",
    route: "CONNECT tunnel/socket delegation",
    boundary: "built-in agent TCP creation",
    file: "ext/node/ops/tcp_wrap.rs",
    fn: "connect",
    fixture: "connect-tunnel-raw-write",
  },
  {
    action: "connect",
    route: "101 Upgrade socket delegation",
    boundary: "built-in agent TCP creation",
    file: "ext/node/ops/tcp_wrap.rs",
    fn: "connect",
    fixture: "upgrade-raw-write",
  },
  {
    action: "connect",
    route: "custom Agent.createConnection",
    boundary: "raw Node TCP creation",
    file: "ext/node/ops/tcp_wrap.rs",
    fn: "connect",
    fixture: "custom-agent",
  },
  {
    action: "connect",
    route: "request createConnection hook",
    boundary: "raw Node TCP creation",
    file: "ext/node/ops/tcp_wrap.rs",
    fn: "connect",
    fixture: "create-connection-hook",
  },
  {
    action: "connect",
    route: "redirect hop",
    boundary: "each built-in agent TCP creation",
    file: "ext/node/ops/tcp_wrap.rs",
    fn: "connect",
    fixture: "redirect-hop",
  },
  {
    action: "connect",
    route: "keep-alive reuse attempt",
    boundary: "pool reuse closed; each request creates a checked socket",
    file: "ext/node/ops/tcp_wrap.rs",
    fn: "connect",
    fixture: "keepalive-reuse-closed",
  },
  {
    action: "closed",
    route: "forward-proxy target and peer",
    boundary: "categorically refused without final-peer attestation",
    file: "ext/node/ops/http.rs",
    fn: "op_node_http_check_proxy_net",
    fixture: "forward-proxy-closed",
  },
  {
    action: "connect",
    route: "Unix-domain HTTP socket",
    boundary: "built-in agent pipe creation",
    file: "ext/node/ops/pipe_wrap.rs",
    fn: "connect",
    fixture: "unix-socket",
  },
];

// Resource-creating and packet-originating network surfaces. Direct rows must
// contain a classified check in the named function. Categorical rows must call
// their named closed-surface guard. Inherited rows name the operation that
// consumes an already-authorized resource. Node route rows are behavioral and
// bind exact spec registration, isolated policies, per-route output, and the
// profile-specific TCP/Unix token classifiers. Every function is also
// existence-checked so upstream renames or removals are manifest drift.
const NETWORK_SURFACES: NetworkSurface[] = [
  {
    surface: "fetch() HTTP(S)",
    action: "fetch",
    file: "ext/fetch/lib.rs",
    fn: "op_fetch",
    enforcement: "direct",
    note: "URL before request",
  },
  {
    surface: "Deno.createHttpClient() forward proxy",
    action: "closed",
    file: "ext/fetch/lib.rs",
    fn: "op_fetch_custom_client",
    guard: "oden_capsec_reject_forward_proxy",
    enforcement: "categorical",
    note: "refused in /1.1 without final-peer attestation",
  },
  {
    surface: "remote KV HTTP",
    action: "fetch",
    file: "ext/kv/remote.rs",
    fn: "check_net_url",
    enforcement: "direct",
    note: "every remote request URL",
  },
  {
    surface: "WebSocket permission/create",
    action: "connect",
    file: "ext/websocket/lib.rs",
    fn: "op_ws_check_permission_and_cancel_handle",
    enforcement: "direct",
    note: "initial URL",
  },
  {
    surface: "WebSocket redirect/final URL",
    action: "connect",
    file: "ext/websocket/lib.rs",
    fn: "op_ws_create",
    enforcement: "direct",
    note: "connector and redirect",
  },
  {
    surface: "Deno TCP connect",
    action: "connect",
    file: "ext/net/ops.rs",
    fn: "op_net_connect_tcp_inner",
    enforcement: "direct",
    note: "logical host plus resolved IP",
  },
  {
    surface: "Deno TCP listen",
    action: "listen",
    file: "ext/net/ops.rs",
    fn: "op_net_listen_tcp",
    enforcement: "direct",
    note: "bind host plus resolved IP",
  },
  {
    surface: "Deno UDP send",
    action: "connect",
    file: "ext/net/ops.rs",
    fn: "op_net_send_udp",
    enforcement: "direct",
    note: "destination plus resolved IP",
  },
  {
    surface: "Deno UDP listen",
    action: "listen",
    file: "ext/net/ops.rs",
    fn: "net_listen_udp",
    enforcement: "direct",
    note: "bind host plus resolved IP",
  },
  {
    surface: "Deno standalone DNS (v1 resolve fold)",
    action: "fetch",
    file: "ext/net/ops.rs",
    fn: "op_dns_resolve",
    enforcement: "direct",
    note: "configured name-server endpoint",
  },
  {
    surface: "Deno TLS connect",
    action: "connect",
    file: "ext/net/ops_tls.rs",
    fn: "op_net_connect_tls",
    enforcement: "direct",
    note: "logical host plus resolved IP",
  },
  {
    surface: "Deno TLS listen",
    action: "listen",
    file: "ext/net/ops_tls.rs",
    fn: "op_net_listen_tls",
    enforcement: "direct",
    note: "bind host plus resolved IP",
  },
  {
    surface: "Deno Unix stream connect",
    action: "connect",
    file: "ext/net/ops_unix.rs",
    fn: "op_net_connect_unix",
    enforcement: "inherited",
    note: "typed check_unix_socket_path helper",
  },
  {
    surface: "Deno Unix datagram send",
    action: "connect",
    file: "ext/net/ops_unix.rs",
    fn: "op_net_send_unixpacket",
    enforcement: "inherited",
    note: "typed check_unix_socket_path helper",
  },
  {
    surface: "Deno Unix stream listen",
    action: "listen",
    file: "ext/net/ops_unix.rs",
    fn: "op_net_listen_unix",
    enforcement: "inherited",
    note: "typed check_unix_socket_path helper",
  },
  {
    surface: "Deno Unix datagram listen",
    action: "listen",
    file: "ext/net/ops_unix.rs",
    fn: "net_listen_unixpacket",
    enforcement: "inherited",
    note: "typed check_unix_socket_path helper",
  },
  {
    surface: "Deno vsock connect",
    action: "connect",
    file: "ext/net/ops.rs",
    fn: "op_net_connect_vsock",
    enforcement: "direct",
    note: "vsock:cid:port",
  },
  {
    surface: "Deno vsock listen",
    action: "listen",
    file: "ext/net/ops.rs",
    fn: "op_net_listen_vsock",
    enforcement: "direct",
    note: "vsock:cid:port",
  },
  {
    surface: "Deno QUIC endpoint bind",
    action: "listen",
    file: "ext/net/quic.rs",
    fn: "op_quic_endpoint_create",
    enforcement: "direct",
    note: "can-listen endpoint creation",
  },
  {
    surface: "Deno QUIC listener",
    action: "listen",
    file: "ext/net/quic.rs",
    fn: "op_quic_endpoint_listen",
    enforcement: "inherited",
    note: "authorized can-listen endpoint",
  },
  {
    surface: "Deno QUIC connect",
    action: "connect",
    file: "ext/net/quic.rs",
    fn: "op_quic_endpoint_connect",
    enforcement: "direct",
    note: "logical host plus resolved IP",
  },
  {
    surface: "WebTransport connect",
    action: "connect",
    file: "ext/net/quic.rs",
    fn: "op_webtransport_connect",
    enforcement: "inherited",
    note: "authorized QUIC connection",
  },
  {
    surface: "Node HTTP(S) direct connection",
    action: "connect",
    file: "ext/node/ops/tcp_wrap.rs",
    fn: "connect",
    enforcement: "direct",
    note: "socket-exposing HTTP token is connect-class in /1.1",
  },
  {
    surface: "Node HTTP(S) proxy",
    action: "closed",
    file: "ext/node/ops/http.rs",
    fn: "op_node_http_check_proxy_net",
    guard: "oden_capsec_reject_forward_proxy",
    enforcement: "categorical",
    note: "refused in /1.1 before the legacy connect-class fallback",
  },
  {
    surface: "Node TCP connect",
    action: "connect",
    file: "ext/node/ops/tcp_wrap.rs",
    fn: "connect",
    enforcement: "direct",
    note: "untokenized raw socket",
  },
  {
    surface: "Node TCP bind/listen",
    action: "listen",
    file: "ext/node/ops/tcp_wrap.rs",
    fn: "bind_inner",
    enforcement: "direct",
    note: "bind before listener creation",
  },
  {
    surface: "Node UDP send",
    action: "connect",
    file: "ext/node/ops/udp.rs",
    fn: "op_node_udp_send",
    enforcement: "direct",
    note: "destination plus resolved IP",
  },
  {
    surface: "Node UDP bind",
    action: "listen",
    file: "ext/node/ops/udp.rs",
    fn: "op_node_udp_bind",
    enforcement: "direct",
    note: "bind host plus resolved IP",
  },
  {
    surface: "Node HTTP(S) Unix socket",
    action: "connect",
    file: "ext/node/ops/pipe_wrap.rs",
    fn: "connect",
    enforcement: "direct",
    note: "socket-exposing HTTP token is connect-class in /1.1",
  },
  {
    surface: "Node Unix pipe connect",
    action: "connect",
    file: "ext/node/ops/pipe_wrap.rs",
    fn: "connect",
    enforcement: "direct",
    note: "untokenized raw pipe",
  },
  {
    surface: "Node Unix pipe bind",
    action: "listen",
    file: "ext/node/ops/pipe_wrap.rs",
    fn: "bind",
    enforcement: "direct",
    note: "bind path",
  },
  {
    surface: "Node Unix pipe listen",
    action: "listen",
    file: "ext/node/ops/pipe_wrap.rs",
    fn: "listen",
    enforcement: "direct",
    note: "bound path recheck",
  },
  {
    surface: "Node standalone and fetch-internal DNS lookup (v1 fold)",
    action: "fetch",
    file: "ext/node/ops/dns.rs",
    fn: "op_node_getaddrinfo",
    enforcement: "direct",
    note: "standalone query or parent fetch target",
  },
  {
    surface: "Node connect-internal DNS lookup",
    action: "connect",
    file: "ext/node/ops/dns.rs",
    fn: "op_node_getaddrinfo",
    enforcement: "direct",
    note: "parent operation target",
  },
  {
    surface: "Node DNS reverse lookup (v1 resolve fold)",
    action: "fetch",
    file: "ext/node/ops/dns.rs",
    fn: "op_node_getnameinfo",
    enforcement: "direct",
    note: "query target",
  },
  {
    surface: "Node inspector listener",
    action: "listen",
    file: "ext/node/ops/inspector.rs",
    fn: "op_inspector_open",
    enforcement: "direct",
    note: "inspector bind host/port",
  },
];

function validateNetworkSurfaces(network: NetworkCheck[]): void {
  const direct = new Set(
    network.map((call) => `${call.file}:${call.fn}:${call.action}`),
  );
  const errors: string[] = [];
  for (const row of NETWORK_SURFACES) {
    const src = Deno.readTextFileSync(ROOT + row.file);
    const fnRe = new RegExp(`\\bfn\\s+${row.fn}\\b`);
    if (!fnRe.test(maskRust(src))) {
      errors.push(`${row.surface}: missing ${row.file}:${row.fn}()`);
    } else if (row.enforcement === "categorical") {
      const guard = row.guard;
      const calls = guard
        ? collectCalls(
          src,
          new RegExp(`\\b(?<name>${guard})\\s*\\(`, "g"),
          false,
        )
        : [];
      if (!guard || !calls.some((call) => call.fn === row.fn)) {
        errors.push(
          `${row.surface}: ${row.file}:${row.fn}() has no categorical ${
            guard ?? "guard"
          }`,
        );
      }
    } else if (
      row.enforcement === "direct" &&
      !direct.has(`${row.file}:${row.fn}:${row.action}`)
    ) {
      errors.push(
        `${row.surface}: ${row.file}:${row.fn}() has no classified ${row.action} check`,
      );
    }
  }
  const tcpBody = rustFunctionBodyMasked(
    Deno.readTextFileSync(ROOT + "ext/node/ops/tcp_wrap.rs"),
    "oden_net_decision",
  ).replace(/\s+/g, " ");
  if (
    !/Some\s*\(\s*api_name\s*\)\s+if\s+oden_capsec_profile_is\s*\([^)]*\)\s*=>\s*\{\s*\(\s*NetPermissionAction::Connect\s*,\s*api_name\s*\)/
      .test(
        tcpBody,
      ) ||
    !/Some\s*\(\s*api_name\s*\)\s*=>\s*\(\s*NetPermissionAction::Fetch\s*,\s*api_name\s*\)/
      .test(
        tcpBody,
      )
  ) {
    errors.push(
      "Node HTTP TCP token must select Connect in /1.1 and preserve the unarmed Fetch fallback",
    );
  }

  const pipeBody = rustFunctionBodyMasked(
    Deno.readTextFileSync(ROOT + "ext/node/ops/pipe_wrap.rs"),
    "connect",
  ).replace(/\s+/g, " ");
  if (
    !/if\s+let\s+Some\s*\(\s*api_name\s*\)\s*=\s*self\.oden_http_api_name\s*\(\s*path\s*\)\s*\{.*?if\s+oden_capsec_profile_is\s*\([^)]*\)\s*\{.*?check_net_unix_socket\s*\(\s*NetPermissionAction::Connect.*?\}\s*else\s*\{.*?check_net_unix_socket\s*\(\s*NetPermissionAction::Fetch/
      .test(
        pipeBody,
      )
  ) {
    errors.push(
      "Node HTTP Unix token must select Connect in /1.1 and preserve the unarmed Fetch fallback",
    );
  }

  const dnsBody = rustFunctionBodyMasked(
    Deno.readTextFileSync(ROOT + "ext/node/ops/dns.rs"),
    "op_node_getaddrinfo",
  ).replace(/\s+/g, " ");
  if (
    !/match\s+action\s*\{\s*0\s*=>\s*NetPermissionAction::Fetch\s*,\s*1\s*=>\s*NetPermissionAction::Connect\s*,\s*action\s*=>\s*return\s+Err\s*\(\s*DnsError::InvalidNetworkAction\s*\(\s*action\s*\)\s*\)/
      .test(dnsBody)
  ) {
    errors.push(
      "Node internal DNS action must use the closed 0=Fetch, 1=Connect mapping",
    );
  }

  const nodeNetSource = Deno.readTextFileSync(
    ROOT + "ext/node/polyfills/net.ts",
  ).replace(/\s+/g, " ");
  if (
    !/WeakMapPrototypeSet\( canonicalSocketDnsActions, this, validatedOdenHttpNetToken && !op_node_http_capsec_no_reuse\(\) \? NET_ACTION_FETCH : NET_ACTION_CONNECT, \)/
      .test(nodeNetSource)
  ) {
    errors.push(
      "Node DNS selector must preserve legacy tokenized HTTP Fetch and select Connect otherwise",
    );
  }
  const markedLookupActions = nodeNetSource.match(
    /emitLookup\[kPermTokenSink\] = true; emitLookup\[kPermTokenAction\] = WeakMapPrototypeGet\(canonicalSocketDnsActions, self\) \?\? NET_ACTION_CONNECT;/g,
  ) ?? [];
  if (markedLookupActions.length !== 2) {
    errors.push(
      "Node DNS action must be installed only beside both authenticated built-in lookup markers",
    );
  }
  const caresSource = Deno.readTextFileSync(
    ROOT + "ext/node/polyfills/internal_binding/cares_wrap.ts",
  ).replace(/\s+/g, " ");
  if (
    !/const action = req\.callback\[kPermTokenSink\] \? req\.callback\[kPermTokenAction\] : NET_ACTION_FETCH;/
      .test(
        caresSource,
      )
  ) {
    errors.push(
      "Node standalone DNS must stay Fetch while only authenticated internal lookups carry a parent action",
    );
  }

  const fixture = Deno.readTextFileSync(ROOT + NODE_HTTP_SOCKET_FIXTURE);
  const spec = JSON.parse(Deno.readTextFileSync(ROOT + NODE_HTTP_SOCKET_SPEC));
  const fetchPolicy = JSON.parse(
    Deno.readTextFileSync(ROOT + NODE_HTTP_SOCKET_FETCH_POLICY),
  );
  const connectPolicy = JSON.parse(
    Deno.readTextFileSync(ROOT + NODE_HTTP_SOCKET_CONNECT_POLICY),
  );
  const fetchGolden = Deno.readTextFileSync(
    ROOT + NODE_HTTP_SOCKET_FETCH_GOLDEN,
  );
  const connectGolden = Deno.readTextFileSync(
    ROOT + NODE_HTTP_SOCKET_CONNECT_GOLDEN,
  );

  const fetchSpec = spec.tests?.fetch_grant_cannot_reach_node_http_sockets;
  if (
    fetchSpec?.args !== "run --allow-all app.js routes fetch" ||
    fetchSpec?.envs?.ODEN_CAPSEC_POLICY !== "fetch_routes.json" ||
    fetchSpec?.output !== "routes_fetch.out" || fetchSpec?.exitCode !== 0
  ) {
    errors.push("Node HTTP fetch-denial route spec registration drifted");
  }
  const connectSpec = spec.tests
    ?.connect_grant_covers_explicit_node_http_socket_routes;
  if (
    connectSpec?.args !== "run --allow-all app.js routes connect" ||
    connectSpec?.envs?.ODEN_CAPSEC_POLICY !== "connect.json" ||
    connectSpec?.output !== "routes_connect.out" || connectSpec?.exitCode !== 0
  ) {
    errors.push("Node HTTP connect route spec registration drifted");
  }

  const fetchCaps = new Set(
    String(fetchPolicy.grants?.["node-http-closure-probe"] ?? "").split(","),
  );
  if (
    !fetchCaps.has("network:fetch:*") || fetchCaps.has("network:connect:*") ||
    !fetchCaps.has("fs:read:/") || !fetchCaps.has("fs:write:/")
  ) {
    errors.push(
      "Node HTTP fetch route policy must isolate network:fetch while clearing Unix filesystem prechecks",
    );
  }
  const connectCaps = new Set(
    String(connectPolicy.grants?.["node-http-closure-probe"] ?? "").split(","),
  );
  if (
    !connectCaps.has("network:connect:*") ||
    !connectCaps.has("fs:read:/") || !connectCaps.has("fs:write:/")
  ) {
    errors.push(
      "Node HTTP connect route policy must include connect and Unix filesystem authority",
    );
  }

  for (const row of NODE_HTTP_SOCKET_ROUTES) {
    const occurrenceCount = fixture.split(`\"${row.fixture}\"`).length - 1;
    if (occurrenceCount !== 1) {
      errors.push(
        `${row.route}: fixture ${row.fixture} must occur exactly once in ${NODE_HTTP_SOCKET_FIXTURE}`,
      );
    }
    const fetchLine = `NODE_HTTP_SOCKET_ROUTE ${row.fixture} DENIED`;
    const connectOutcome = row.action === "connect" ? "CONNECTED" : "DENIED";
    const connectLine =
      `NODE_HTTP_SOCKET_ROUTE ${row.fixture} ${connectOutcome}`;
    if (!fetchGolden.split("\n").includes(fetchLine)) {
      errors.push(`${row.route}: fetch-denial golden row missing`);
    }
    if (!connectGolden.split("\n").includes(connectLine)) {
      errors.push(`${row.route}: connect golden row missing`);
    }
  }
  if (!fetchGolden.includes("NODE_HTTP_SOCKET_ROUTES fetch PASS")) {
    errors.push("Node HTTP fetch route aggregate golden missing");
  }
  if (!connectGolden.includes("NODE_HTTP_SOCKET_ROUTES connect PASS")) {
    errors.push("Node HTTP connect route aggregate golden missing");
  }
  if (errors.length > 0) {
    throw new Error(
      "network resource/action registry is incomplete:\n" +
        errors.map((error) => `  - ${error}`).join("\n"),
    );
  }
}

// --- 1. mediated (family, action) pairs + enclosing fn -----------------------
function collectMediation(network: NetworkCheck[]): string[] {
  const src = Deno.readTextFileSync(ROOT + MEDIATION_FILE);
  const found = new Set<string>();
  const networkByMethod = new Map<string, Set<NetworkAction>>();
  for (const call of network) {
    const actions = networkByMethod.get(call.name) ?? new Set<NetworkAction>();
    actions.add(call.action);
    networkByMethod.set(call.name, actions);
  }
  const decideRe = /(?<name>oden_capsec_decide)\s*\(/g;
  for (const call of collectCalls(src, decideRe, false)) {
    const familyMatch = call.args[0]?.match(/^OdenFamily::([A-Za-z]+)$/);
    if (!familyMatch) {
      throw new Error(
        `unclassified capsec family at ${MEDIATION_FILE}:${call.line}`,
      );
    }
    const family = familyMatch[1].toLowerCase();
    const literalAction = call.args[1]?.match(/^"([a-z]+)"$/)?.[1];
    if (literalAction) {
      found.add(`${family}:${literalAction}\tvia ${call.fn}()`);
    } else if (
      family === "env" && call.fn === "check_env_action" &&
      call.args[1]?.replace(/\s+/g, "") === "action"
    ) {
      found.add("env:read\tvia check_env_action()");
      found.add("env:write\tvia check_env_action()");
    } else if (
      family === "network" &&
      call.args[1]?.replace(/\s+/g, "") === "action.as_str()"
    ) {
      const actions = networkByMethod.get(call.fn);
      if (!actions || actions.size === 0) {
        throw new Error(
          `network mediation in ${call.fn}() has no classified call sites`,
        );
      }
      for (const action of actions) {
        found.add(`${family}:${action}\tvia ${call.fn}()`);
      }
    } else {
      throw new Error(
        `unclassified capsec action at ${MEDIATION_FILE}:${call.line}: ${
          call.args[1] ?? "<missing>"
        }`,
      );
    }
  }
  // Standalone capsec checks that don't go through oden_capsec_decide.
  if (src.includes("fn oden_capsec_check_worker_create")) {
    found.add("worker:create\tvia oden_capsec_check_worker_create()");
  }
  if (src.includes("fn oden_capsec_gate_import")) {
    found.add(
      "import:graph\tvia oden_capsec_gate_import() [loader-attributed]",
    );
  }
  return [...found].sort();
}

// --- 2. op-body pre-check skips (every query_*_all call site) ----------------
function collectSkips(): string[] {
  const skips: string[] = [];
  for (const d of SKIP_SCAN_DIRS) {
    for (const file of walk(ROOT + d.replace(/\/$/, ""))) {
      const rel = file.slice(ROOT.length);
      const src = Deno.readTextFileSync(file);
      const lines = src.split("\n");
      for (let i = 0; i < lines.length; i++) {
        // Call sites, not the definition (`pub fn query_read_all`).
        const match = lines[i].match(/\b(query_[a-z0-9_]+_all)\s*\(/);
        if (match && !lines[i].includes(`fn ${match[1]}`)) {
          skips.push(`${match[1]}\t${rel}:${i + 1}`);
        }
      }
    }
  }
  return skips.sort();
}

function collectPermissionMethods(): string[] {
  const src = Deno.readTextFileSync(ROOT + MEDIATION_FILE);
  return [...src.matchAll(/\bpub fn (check_[a-z0-9_]+)\s*(?:<[^>]*>)?\s*\(/g)]
    .map((match) => match[1])
    .filter((name, index, all) => all.indexOf(name) === index)
    .sort();
}

function collectResourceCreationSites(): string[] {
  const sites: string[] = [];
  for (const d of SKIP_SCAN_DIRS) {
    for (const file of walk(ROOT + d)) {
      const rel = file.slice(ROOT.length);
      const src = Deno.readTextFileSync(file);
      for (
        const match of src.matchAll(/resource_table\s*\.\s*add(?:_rc)?\s*\(/gs)
      ) {
        const line = src.slice(0, match.index ?? 0).split("\n").length;
        sites.push(`${rel}:${line}`);
      }
    }
  }
  return sites.sort();
}

function capabilityOf(mediationLine: string): string {
  return mediationLine.split("\t", 1)[0];
}

function validateTaxonomy(mediation: string[]): void {
  const mediated = new Set(mediation.map(capabilityOf));
  const mapped = new Set(Object.keys(CAPABILITY_TAXONOMY));
  const errors: string[] = [];

  for (const capability of mediated) {
    if (!mapped.has(capability)) {
      errors.push(`missing taxonomy mapping for mediated ${capability}`);
    }
  }
  for (const capability of mapped) {
    if (!mediated.has(capability)) {
      errors.push(`taxonomy mapping has no mediated check for ${capability}`);
    }
  }

  if (errors.length > 0) {
    throw new Error(
      "capability taxonomy is not total against the op-coverage manifest:\n" +
        errors.map((e) => `  - ${e}`).join("\n"),
    );
  }
}

function renderTaxonomy(): string[] {
  const out: string[] = [];
  out.push("## Capability taxonomy / descriptor mapping");
  out.push("");
  out.push(
    "`--check` fails if this table and the mediated family:action set drift.",
  );
  out.push("");
  out.push(
    "| Capability | Deno descriptor / gate | Target shape | Grant / status |",
  );
  out.push("| --- | --- | --- | --- |");
  for (const capability of Object.keys(CAPABILITY_TAXONOMY).sort()) {
    const row = CAPABILITY_TAXONOMY[capability];
    out.push(
      `| ${capability} | ${row.deno} | ${row.target} | ${row.grant} |`,
    );
  }
  out.push("");
  return out;
}

function renderNetworkChecks(network: NetworkCheck[]): string[] {
  const out: string[] = [];
  out.push("## Network permission call-site matrix");
  out.push("");
  out.push(
    "The balanced Rust scanner classifies every `check_net*` call. A missing,",
  );
  out.push(
    "unknown, or implicitly selected action fails generation. `propagated` is",
  );
  out.push(
    "allowed only at audited typed helpers named by the generator.",
  );
  out.push("");
  out.push("| Action | Check | Enclosing function | Source | Selection |");
  out.push("| --- | --- | --- | --- | --- |");
  for (const call of network) {
    out.push(
      `| ${call.action} | ${call.name} | ${call.fn}() | ${call.file}:${call.line} | ${call.actionSource} |`,
    );
  }
  out.push("");
  return out;
}

function renderNetworkSurfaces(): string[] {
  const out: string[] = [];
  out.push("## Network resource/API action matrix");
  out.push("");
  out.push(
    "Resource-creating and packet-originating APIs are registered explicitly.",
  );
  out.push(
    "Direct rows must contain the named classified check; categorical rows",
  );
  out.push(
    "must contain their closed-surface guard; inherited rows consume an",
  );
  out.push(
    "already-authorized resource named in the note. Behavioral rows bind a",
  );
  out.push(
    "registered raw-engine spec, isolated policies, and per-route goldens.",
  );
  out.push("");
  out.push("| Surface | Action | Enforcement | Rust owner | Note |");
  out.push("| --- | --- | --- | --- | --- |");
  for (const row of NETWORK_SURFACES) {
    out.push(
      `| ${row.surface} | ${row.action} | ${row.enforcement} | ${row.file}:${row.fn}() | ${row.note} |`,
    );
  }
  for (const row of NODE_HTTP_SOCKET_ROUTES) {
    out.push(
      `| Node HTTP route: ${row.route} | ${row.action} | behavioral | ${row.file}:${row.fn}() | ${row.boundary}; registered raw-engine fixture ${row.fixture} |`,
    );
  }
  out.push("");
  return out;
}

function render(): string {
  const network = collectNetworkChecks();
  const mediation = collectMediation(network);
  const skips = collectSkips();
  const permissionMethods = collectPermissionMethods();
  const resourceSites = collectResourceCreationSites();
  validateTaxonomy(mediation);
  validateNetworkSurfaces(network);
  const out: string[] = [];
  out.push("# Oden op-coverage manifest (generated)");
  out.push("");
  out.push(
    "Generated by `tools/oden/coverage_manifest.ts`. Do not edit by hand —",
  );
  out.push("run the generator and commit. Drift fails the rebase canary.");
  out.push("");
  out.push("## Capsec-mediated permission checks (family:action via fn)");
  out.push("");
  for (const m of mediation) out.push(`- ${m}`);
  out.push("");
  out.push(...renderTaxonomy());
  out.push(...renderNetworkChecks(network));
  out.push(...renderNetworkSurfaces());
  out.push("## Permission methods (closed inventory)");
  out.push("");
  for (const method of permissionMethods) out.push(`- ${method}()`);
  out.push("");
  out.push("## Resource-creating op sites (closed inventory)");
  out.push("");
  for (const site of resourceSites) out.push(`- ${site}`);
  out.push("");
  out.push("## Op-body pre-check skips (query_*_all call sites)");
  out.push("");
  out.push(
    "These bypass the permission container when a family is fully granted; capsec",
  );
  out.push(
    "forces each relevant query false while armed. Each site must remain",
  );
  out.push("covered by the layer-2-independence proof.");
  out.push("");
  for (const s of skips) out.push(`- ${s}`);
  out.push("");
  return out.join("\n");
}

const rendered = render();
if (Deno.args.includes("--check")) {
  let committed = "";
  try {
    committed = Deno.readTextFileSync(MANIFEST);
  } catch {
    console.error("op-coverage manifest missing; run the generator.");
    Deno.exit(1);
  }
  if (committed.trimEnd() !== rendered.trimEnd()) {
    console.error(
      "op-coverage manifest DRIFT — regenerate and review:\n" +
        "  deno run --allow-read tools/oden/coverage_manifest.ts > tools/oden/op_coverage.manifest.md",
    );
    Deno.exit(1);
  }
  console.log("op-coverage manifest: up to date");
} else {
  console.log(rendered);
}

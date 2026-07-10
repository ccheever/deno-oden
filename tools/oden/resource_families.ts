#!/usr/bin/env -S deno run --allow-read
// Copyright 2018-2026 the Deno authors. MIT license.
//
// Oden resource-family classification (LLP 0001 Phase 2, Native resource
// ownership). Every resource in deno_core's resource table is classified into
// one of four ownership classes. A rid is a small guessable, table-local
// integer, so owner metadata must live on the concrete resource rather than in
// a process-global rid map; it cannot be used across a package boundary it was
// never handed to. The classes:
//
//   * ambient            — any principal may use it (no owner check); the
//                          resource carries no cross-package authority.
//   * owner-checked      — use is checked against the opening principal; a
//                          guessed rid from another package denies. Owner
//                          metadata makes rid-guessing worthless.
//   * possession-delegable — owner-checked, but may be handed to another package
//                          via the minimal transfer primitive (re-owns that
//                          concrete resource's owner token).
//   * terminal           — compartment-terminating; holding it is full trust for
//                          that package (FFI / native addons), gated at load.
//
// This is the named Phase-2 artifact. `--check` scans `impl Resource for` across
// ext/ and fails if any resource family lacks a classification here — so a new
// upstream resource family is a loud rebase delta, not a silent unclassified
// (and therefore unowned) authority. Sequencing rule (LLP 0001): a family is
// never owner-*checked* before its sanctioned delegation path exists; until a
// family's checks land, same-process rid guessing for it is a NAMED interim
// residual (the `residual` field), visible here and in the audit log.
//
//   deno run --allow-read tools/oden/resource_families.ts [--check]
//
// @ref llp/0001-adding-capability-security-to-deno.plan.md (Native resource ownership)

const ROOT = new URL("../../", import.meta.url).pathname;
const SCAN_DIRS = ["ext", "runtime", "libs"];

type Class = "ambient" | "owner-checked" | "possession-delegable" | "terminal";

interface Entry {
  class: Class;
  family: string; // human family name
  // Whether the use-time owner check is wired yet; if false, same-process rid
  // guessing for this family is a named interim residual (audit-logged).
  checked: boolean;
  note: string;
}

// Keyed by the `impl Resource for <Name>` type name.
const CLASSIFICATION: Record<string, Entry> = {
  // --- net: sockets — owner-checked, delegable across packages via transfer ---
  TcpStreamResource: {
    class: "possession-delegable",
    family: "net:tcp",
    checked: false,
    note: "socket; endpoint-scoped grant at open",
  },
  TlsStreamResource: {
    class: "possession-delegable",
    family: "net:tls",
    checked: false,
    note: "tls socket",
  },
  UdpSocketResource: {
    class: "possession-delegable",
    family: "net:udp",
    checked: false,
    note: "datagram socket",
  },
  UnixStreamResource: {
    class: "possession-delegable",
    family: "net:unix",
    checked: false,
    note: "unix socket",
  },
  UnixDatagramResource: {
    class: "possession-delegable",
    family: "net:unixgram",
    checked: false,
    note: "unix datagram",
  },
  VsockStreamResource: {
    class: "possession-delegable",
    family: "net:vsock",
    checked: false,
    note: "vsock",
  },
  NamedPipe: {
    class: "possession-delegable",
    family: "net:pipe",
    checked: false,
    note: "windows named pipe",
  },
  NetworkListenerResource: {
    class: "possession-delegable",
    family: "net:listener",
    checked: false,
    note: "server listener socket; delegable to a worker",
  },
  TunnelStreamResource: {
    class: "possession-delegable",
    family: "net:tunnel",
    checked: false,
    note: "tunnel stream",
  },
  RecvStreamResource: {
    class: "possession-delegable",
    family: "net:quic-recv",
    checked: false,
    note: "quic recv stream",
  },
  SendStreamResource: {
    class: "possession-delegable",
    family: "net:quic-send",
    checked: false,
    note: "quic send stream",
  },
  // --- child processes + their stdio — owner-checked (spawn already gated) ---
  ChildResource: {
    class: "owner-checked",
    family: "process:child",
    checked: false,
    note: "spawn gated at open; child handle owner-checked",
  },
  ChildStdinResource: {
    class: "owner-checked",
    family: "process:stdin",
    checked: false,
    note: "child stdio fd; ownership follows the child",
  },
  ChildStdoutResource: {
    class: "owner-checked",
    family: "process:stdout",
    checked: false,
    note: "child stdio fd",
  },
  ChildStderrResource: {
    class: "owner-checked",
    family: "process:stderr",
    checked: false,
    note: "child stdio fd",
  },
  // --- filesystem handles — owner-checked (opener owns) ---
  ReadDirResource: {
    class: "owner-checked",
    family: "fs:readdir",
    checked: false,
    note: "directory read handle; opener owns",
  },
  // --- websocket — owner-checked; cancel handle follows the socket ---
  ServerWebSocket: {
    class: "owner-checked",
    family: "websocket",
    checked: false,
    note: "endpoint-scoped; opener owns",
  },
  WsCancelResource: {
    class: "owner-checked",
    family: "websocket:cancel",
    checked: false,
    note: "cancel handle follows the socket",
  },
  // --- KV — owner-checked; a handle opened by a package stays its own ---
  DatabaseResource: {
    class: "owner-checked",
    family: "kv:db",
    checked: false,
    note: "kv handle; opener owns",
  },
  DatabaseWatcherResource: {
    class: "owner-checked",
    family: "kv:watch",
    checked: false,
    note: "kv watcher follows the db handle",
  },
  QueueMessageResource: {
    class: "owner-checked",
    family: "kv:queue-msg",
    checked: false,
    note: "queue message handle",
  },
  // --- cache — owner-checked (app-scoped response bodies) ---
  CacheResponseResource: {
    class: "owner-checked",
    family: "cache:response",
    checked: false,
    note: "cache response body handle",
  },
  // --- web: message ports are THE delegation channel (possession-delegable) ---
  MessagePortResource: {
    class: "possession-delegable",
    family: "web:messageport",
    checked: false,
    note: "the structured-transfer channel; possession is authority",
  },
  ReadableStreamResource: {
    class: "possession-delegable",
    family: "web:stream",
    checked: false,
    note: "stream body; delegable",
  },
  HeldLockResource: {
    class: "owner-checked",
    family: "web:lock-held",
    checked: false,
    note: "Web Locks held lock; owner releases",
  },
  PendingLockResource: {
    class: "owner-checked",
    family: "web:lock-pending",
    checked: false,
    note: "Web Locks pending acquire",
  },
  // --- ffi — terminal (compartment-terminating; full trust, gated at load) ---
  DynamicLibraryResource: {
    class: "terminal",
    family: "ffi:dylib",
    checked: true,
    note:
      "FFI load is compartment-terminating; gated at open, terminal thereafter",
  },
  UnsafeCallbackResource: {
    class: "terminal",
    family: "ffi:callback",
    checked: true,
    note: "FFI callback; terminal",
  },
  // --- files + io — owner-checked / delegable (opener owns; fd registry) ---
  FileResource: {
    class: "possession-delegable",
    family: "fs:file",
    checked: false,
    note: "open file handle; opener owns, delegable",
  },
  PipeResource: {
    class: "possession-delegable",
    family: "io:pipe",
    checked: false,
    note: "pipe fd",
  },
  FsEventsResource: {
    class: "owner-checked",
    family: "fs:watch",
    checked: false,
    note: "Deno.watchFs watcher; opener owns (ENG-23799 gates attach)",
  },
  SignalStreamResource: {
    class: "owner-checked",
    family: "os:signal",
    checked: false,
    note: "signal listener; opener owns",
  },
  // --- fetch — owner-checked (client + body streams; opener owns) ---
  HttpClientResource: {
    class: "owner-checked",
    family: "fetch:client",
    checked: false,
    note: "http client handle",
  },
  FetchRequestResource: {
    class: "owner-checked",
    family: "fetch:request",
    checked: false,
    note: "outbound request body",
  },
  FetchResponseResource: {
    class: "owner-checked",
    family: "fetch:response",
    checked: false,
    note: "response body stream",
  },
  FetchCancelHandle: {
    class: "ambient",
    family: "fetch:cancel",
    checked: false,
    note: "cancel token; no cross-package authority",
  },
  // --- http server — owner-checked (the serving principal owns the conn/stream) ---
  HttpConnResource: {
    class: "owner-checked",
    family: "http:conn",
    checked: false,
    note: "server connection",
  },
  HttpJoinHandle: {
    class: "owner-checked",
    family: "http:join",
    checked: false,
    note: "serve task join handle",
  },
  HttpRequestBody: {
    class: "owner-checked",
    family: "http:reqbody",
    checked: false,
    note: "inbound request body",
  },
  RawH1RequestBody: {
    class: "owner-checked",
    family: "http:reqbody-h1",
    checked: false,
    note: "h1 inbound body",
  },
  HttpStreamReadResource: {
    class: "owner-checked",
    family: "http:read",
    checked: false,
    note: "server stream read half",
  },
  HttpStreamWriteResource: {
    class: "owner-checked",
    family: "http:write",
    checked: false,
    note: "server stream write half",
  },
  UpgradeStream: {
    class: "owner-checked",
    family: "http:upgrade",
    checked: false,
    note: "upgraded (websocket) stream",
  },
  // --- node net wrappers — delegable sockets ---
  NodeUdpSocketResource: {
    class: "possession-delegable",
    family: "node:udp",
    checked: false,
    note: "node udp socket",
  },
  JSDuplexResource: {
    class: "possession-delegable",
    family: "node:duplex",
    checked: false,
    note: "node duplex stream wrapper",
  },
  JSStreamTlsResource: {
    class: "possession-delegable",
    family: "node:tls",
    checked: false,
    note: "node tls stream wrapper",
  },
  // --- worker message channel — the delegation transport ---
  ThreadMessageReceiver: {
    class: "possession-delegable",
    family: "worker:message",
    checked: false,
    note: "worker message channel; possession is authority",
  },
  // --- node crypto contexts — owner-checked, ephemeral ---
  CipherContext: {
    class: "owner-checked",
    family: "crypto:cipher",
    checked: false,
    note: "cipher context; opener owns",
  },
  DecipherContext: {
    class: "owner-checked",
    family: "crypto:decipher",
    checked: false,
    note: "decipher context",
  },
  // --- kv cron — owner-checked registration ---
  CronResource: {
    class: "owner-checked",
    family: "cron",
    checked: false,
    note: "cron registration; opener owns",
  },
  // --- ambient: internal control handles with no cross-package authority ---
  CancelHandle: {
    class: "ambient",
    family: "control:cancel",
    checked: false,
    note: "internal cancel token",
  },
  WasmStreamingResource: {
    class: "ambient",
    family: "wasm:streaming",
    checked: false,
    note: "wasm compile buffer; ephemeral",
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

// Discover `impl Resource for <Name>` across the tree.
function discoverFamilies(): Set<string> {
  const found = new Set<string>();
  const re = /impl(?:<[^>]*>)?\s+Resource\s+for\s+([A-Za-z0-9_]+)/g;
  for (const d of SCAN_DIRS) {
    for (const file of walk(ROOT + d)) {
      let src: string;
      try {
        src = Deno.readTextFileSync(file);
      } catch {
        continue;
      }
      let m: RegExpExecArray | null;
      while ((m = re.exec(src)) !== null) found.add(m[1]);
    }
  }
  return found;
}

function validate(found: Set<string>): string[] {
  const errors: string[] = [];
  const classified = new Set(Object.keys(CLASSIFICATION));
  for (const name of found) {
    if (!classified.has(name)) {
      errors.push(
        `unclassified resource family \`${name}\` — every resource must have an ` +
          `ownership class (an unclassified resource is an UNOWNED authority)`,
      );
    }
  }
  for (const name of classified) {
    if (!found.has(name)) {
      errors.push(
        `classification for \`${name}\` has no matching \`impl Resource for\` — ` +
          `stale entry (removed upstream?)`,
      );
    }
  }
  return errors;
}

function render(): string {
  const out: string[] = [];
  out.push("# Oden resource-family classification (generated)");
  out.push("");
  out.push(
    "Generated by `tools/oden/resource_families.ts`. Every resource in the table",
  );
  out.push(
    "carries an ownership class so a guessed rid cannot cross a package boundary.",
  );
  out.push("`--check` fails if any `impl Resource for` lacks a class here.");
  out.push("");
  const byClass: Record<Class, string[]> = {
    "ambient": [],
    "owner-checked": [],
    "possession-delegable": [],
    "terminal": [],
  };
  const counts: Record<Class, number> = {
    "ambient": 0,
    "owner-checked": 0,
    "possession-delegable": 0,
    "terminal": 0,
  };
  for (const name of Object.keys(CLASSIFICATION).sort()) {
    const e = CLASSIFICATION[name];
    counts[e.class]++;
    const check = e.checked
      ? "checked"
      : "residual (rid-guess audited, not yet denied)";
    byClass[e.class].push(`| ${name} | ${e.family} | ${check} | ${e.note} |`);
  }
  out.push("## Summary");
  out.push("");
  for (const c of Object.keys(counts) as Class[]) {
    out.push(`- **${c}**: ${counts[c]}`);
  }
  out.push("");
  for (const c of Object.keys(byClass) as Class[]) {
    if (byClass[c].length === 0) continue;
    out.push(`## ${c}`);
    out.push("");
    out.push("| resource | family | owner-check status | note |");
    out.push("| --- | --- | --- | --- |");
    out.push(...byClass[c]);
    out.push("");
  }
  out.push("## Named interim residuals");
  out.push("");
  out.push(
    "Families classified owner-checked/possession-delegable whose use-time owner",
  );
  out.push(
    "check is not yet wired: same-process rid guessing for these is audited, not",
  );
  out.push(
    "yet denied (LLP 0001 sequencing — a family is never owner-checked before its",
  );
  out.push("delegation path exists). Wiring the check per family closes each.");
  out.push("");
  const residuals = Object.entries(CLASSIFICATION)
    .filter(([, e]) => !e.checked && e.class !== "ambient")
    .map(([n]) => n)
    .sort();
  out.push(`- ${residuals.length} residual families: ${residuals.join(", ")}`);
  out.push("");
  return out.join("\n");
}

function main() {
  const found = discoverFamilies();
  const errors = validate(found);
  if (Deno.args.includes("--check")) {
    if (errors.length) {
      console.error("resource-family classification FAILURES:");
      for (const e of errors) console.error("  - " + e);
      Deno.exit(1);
    }
    console.log("resource-family classification: every family classified");
    return;
  }
  if (errors.length) {
    // Still render, but surface the drift on stderr.
    for (const e of errors) console.error("WARN: " + e);
  }
  console.log(render());
}

main();

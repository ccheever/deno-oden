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
  "network:fetch": {
    deno: "NetDescriptor / ImportDescriptor",
    target: "host, URL, vsock, or unix socket",
    grant: "network:fetch:<host>",
  },
  "network:connect": {
    deno: "NetDescriptor",
    target: "host, URL, vsock, or unix socket",
    grant: "network:connect:<host>",
  },
  "network:listen": {
    deno: "NetDescriptor",
    target: "bind host, vsock, or unix socket",
    grant: "network:listen:<host>",
  },
  "run:run": {
    deno: "RunQueryDescriptor",
    target: "command display name or *",
    grant: "run:<command>",
  },
  "sys:read": {
    deno: "SysDescriptor",
    target: "information kind or *",
    grant: "sys:<kind>",
  },
  "worker:create": {
    deno: "op_create_worker capsec gate",
    target: "worker specifier",
    grant:
      "default-denied for package principals until inheritance is designed",
  },
  "import:graph": {
    deno: "ModuleLoader inner_resolve capsec gate (referrer-attributed)",
    target: "resolved import specifier (data:/blob:/http(s):)",
    grant:
      "remote/data imports default-denied for package principals under enforce",
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

// --- 1. mediated (family, action) pairs + enclosing fn -----------------------
function collectMediation(): string[] {
  const src = Deno.readTextFileSync(ROOT + MEDIATION_FILE);
  const found = new Set<string>();
  const functions = [...src.matchAll(/\bfn\s+([a-z0-9_]+)\s*(?:<[^>]*>)?\s*\(/g)]
    .map((match) => ({ name: match[1], index: match.index ?? 0 }));
  const enclosing = (index: number): string => {
    let name = "<module>";
    for (const fn of functions) {
      if (fn.index > index) break;
      name = fn.name;
    }
    return name;
  };
  // Match over the whole source, not one line: rustfmt deliberately lays many
  // calls out vertically. (ENG-23978)
  const decideRe =
    /oden_capsec_decide\(\s*OdenFamily::([A-Za-z]+)\s*,\s*"([a-z]+)"/gs;
  for (const match of src.matchAll(decideRe)) {
    const family = match[1].toLowerCase();
    const action = match[2];
    found.add(`${family}:${action}\tvia ${enclosing(match.index ?? 0)}()`);
  }
  // Action-parameterized network helpers are classified at their public API,
  // so the manifest cannot collapse them to the helper's variable `action`.
  const semanticMethods: Record<string, string> = {
    check_env: "env:read",
    check_env_action: "env:write",
    check_net: "network:connect",
    check_net_fetch: "network:fetch",
    check_net_listen: "network:listen",
    check_net_url: "network:fetch",
    check_net_url_connect: "network:connect",
    check_net_vsock: "network:connect",
    check_net_vsock_listen: "network:listen",
  };
  for (const [method, capability] of Object.entries(semanticMethods)) {
    if (!new RegExp(`\\bfn\\s+${method}\\b`).test(src)) {
      throw new Error(`semantic permission method missing: ${method}`);
    }
    found.add(`${capability}\tvia ${method}()`);
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
      for (const match of src.matchAll(/resource_table\s*\.\s*add(?:_rc)?\s*\(/gs)) {
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

function render(): string {
  const mediation = collectMediation();
  const skips = collectSkips();
  const permissionMethods = collectPermissionMethods();
  const resourceSites = collectResourceCreationSites();
  validateTaxonomy(mediation);
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

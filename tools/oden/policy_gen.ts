#!/usr/bin/env -S deno run --allow-read --allow-write --allow-run
// Copyright 2018-2026 the Deno authors. MIT license.
//
// Oden policy generation from import-site grants (LLP 0001 Phase 1).
//
// Walks the module graph of an entry (via `deno info --json`, i.e. deno_graph),
// reads grant attributes authored at first-party import sites, unions them with
// the root config's `oden`/`ibex` grants block, and emits the committed
// `.oden/policy.json` artifact that the engine's `decide()` already consumes
// (`runtime/permissions/oden_policy.rs`). Two rules make the artifact the
// ceiling rather than a suggestion:
//
//   1. "Only your code grants" — grant attributes are honored *only* on
//      first-party (root) modules. A `with { grants: ... }` written inside a
//      node_modules / npm / jsr / remote dependency is ignored for policy and
//      reported as a self-grant supply-chain signal (it never widens authority).
//   2. The generated artifact is byte-reproducible, so `--check` regenerates and
//      diffs against the committed copy — reporting expansions (new or broadened
//      grants: high severity) distinctly from shrinkages, and exiting non-zero on
//      any drift so an unreviewed authority change fails CI.
//
// Self-contained (Deno built-ins + `deno info`). Run from `fork/deno`.
//
//   deno run -A tools/oden/policy_gen.ts <entry> [--out .oden/policy.json]
//   deno run -A tools/oden/policy_gen.ts <entry> --check
//
// @ref llp/0001-adding-capability-security-to-deno.plan.md (Phase 1; "only your
// code grants"; drift severity is class-sensitive)

const GRANT_KEYS = ["grants", "endow", "builtins", "also"];

// Capability families whose expansion is high-severity in drift review
// (LLP 0016 R5 / LLP 0001 "Drift severity is class-sensitive").
const HIGH_SEVERITY =
  /^(run|process|ffi|napi)\b|^fs:write\b|^env\b|^network:\*/;

type Policy = {
  mode: "permissive" | "audit" | "enforce";
  grants: Record<string, string>;
};

type GraphModule = {
  kind: string;
  specifier: string;
  local?: string;
  error?: string;
  dependencies?: {
    specifier: string;
    code?: { specifier: string };
    type?: { specifier: string };
  }[];
};

type Graph = { roots: string[]; modules: GraphModule[] };

function runDenoInfo(entry: string): Graph {
  const cmd = new Deno.Command(Deno.execPath(), {
    args: ["info", "--json", entry],
    stdout: "piped",
    stderr: "piped",
  });
  const { code, stdout, stderr } = cmd.outputSync();
  if (code !== 0) {
    throw new Error(
      "deno info failed:\n" + new TextDecoder().decode(stderr),
    );
  }
  return JSON.parse(new TextDecoder().decode(stdout)) as Graph;
}

// A module is first-party (root) if it is a local file outside any
// node_modules tree and not a remote/npm/jsr specifier. These are the only
// modules whose grant attributes count.
function isFirstParty(m: GraphModule, projectRoot: string): boolean {
  if (!m.local) return false;
  if (!m.specifier.startsWith("file://")) return false;
  if (m.local.includes("/node_modules/")) return false;
  return m.local.startsWith(projectRoot);
}

// Map an imported specifier to the policy selector (bare package name) it grants
// to. Relative/first-party targets return null (root needs no grant).
function selectorOf(spec: string): string | null {
  if (spec.startsWith("npm:")) return npmBareName(spec.slice(4));
  if (spec.startsWith("jsr:")) return jsrBareName(spec.slice(4));
  if (spec.startsWith("node:")) return null; // builtins gated by import graph
  if (spec.startsWith("http://") || spec.startsWith("https://")) {
    if (spec.startsWith("https://jsr.io/")) {
      return jsrBareName(spec.slice("https://jsr.io/".length));
    }
    return spec; // URL locator is the canonical URL
  }
  if (spec.startsWith("./") || spec.startsWith("../") || spec.startsWith("/")) {
    return null; // first-party relative import
  }
  if (spec.startsWith("file://")) return null;
  // Bare specifier resolving through node_modules → its package name.
  return npmBareName(spec);
}

function npmBareName(spec: string): string {
  if (spec.startsWith("@")) {
    const slash = spec.indexOf("/");
    if (slash === -1) return spec;
    const rest = spec.slice(slash + 1);
    const name = rest.split(/[@/]/)[0];
    return `${spec.slice(0, slash)}/${name}`;
  }
  return spec.split(/[@/]/)[0];
}

function jsrBareName(spec: string): string {
  const segs = spec.split("/");
  if (segs[0]?.startsWith("@") && segs[1]) {
    return `${segs[0]}/${segs[1].split("@")[0]}`;
  }
  return segs[0] ?? spec;
}

type SiteGrant = { selector: string; grant: string };

// Extract (specifier, grant-string) pairs from a module source's import sites.
// Handles static `import ... from "spec" with { grants: "..." }`, side-effect
// `import "spec" with { ... }`, and dynamic `import("spec", { with: { ... } })`.
// Regex-based on purpose: this is authoring-side tooling, not the enforcement
// path, and the grant string is opaque to it (the engine parses grants).
function extractSiteGrants(source: string): {
  specifier: string;
  attrs: Record<string, string>;
}[] {
  const out: { specifier: string; attrs: Record<string, string> }[] = [];
  // Static/side-effect import with attributes:  ... "spec" with { ... }
  const staticRe = /(["'])((?:[^"'\\]|\\.)*?)\1\s*with\s*(\{[\s\S]*?\})/g;
  // Dynamic import:  import( "spec" , { with: { ... } } )
  const dynRe =
    /import\s*\(\s*(["'])((?:[^"'\\]|\\.)*?)\1\s*,\s*(\{[\s\S]*?\})\s*\)/g;
  for (const re of [staticRe, dynRe]) {
    let mm: RegExpExecArray | null;
    while ((mm = re.exec(source)) !== null) {
      const specifier = mm[2];
      const attrs = parseAttrs(mm[3]);
      if (Object.keys(attrs).length) out.push({ specifier, attrs });
    }
  }
  return out;
}

// Pull grant-family keys out of an attribute object literal. Only string-literal
// values are read; a dynamic value cannot author a static grant.
function parseAttrs(block: string): Record<string, string> {
  const attrs: Record<string, string> = {};
  for (const key of GRANT_KEYS) {
    const re = new RegExp(
      `(?:^|[{,\\s])${key}\\s*:\\s*(["'])((?:[^"'\\\\]|\\\\.)*?)\\1`,
    );
    const m = re.exec(block);
    if (m) attrs[key] = m[2];
  }
  return attrs;
}

// grants: comma-joined family:action:scope tokens. endow/builtins/also carry
// their own namespaces; we fold endow into `endow:<name>` etc. so the artifact
// records them without the engine having to special-case authoring syntax.
function grantsFromAttrs(attrs: Record<string, string>): string[] {
  const tokens: string[] = [];
  if (attrs.grants) tokens.push(...splitList(attrs.grants));
  for (const key of ["endow", "builtins", "also"]) {
    if (attrs[key]) {
      for (const v of splitList(attrs[key])) tokens.push(`${key}:${v}`);
    }
  }
  return tokens;
}

function splitList(s: string): string[] {
  return s.split(",").map((t) => t.trim()).filter(Boolean);
}

function readRootConfigGrants(projectRoot: string): Record<string, string[]> {
  const grants: Record<string, string[]> = {};
  for (const name of ["deno.json", "deno.jsonc"]) {
    let text: string;
    try {
      text = Deno.readTextFileSync(`${projectRoot}/${name}`);
    } catch {
      continue;
    }
    let cfg: Record<string, unknown>;
    try {
      cfg = JSON.parse(stripJsonc(text));
    } catch {
      continue;
    }
    const block = (cfg.oden ?? cfg.ibex) as
      | { grants?: Record<string, string> }
      | undefined;
    if (block?.grants) {
      for (const [sel, g] of Object.entries(block.grants)) {
        (grants[sel] ??= []).push(...splitList(g));
      }
    }
    break;
  }
  return grants;
}

function stripJsonc(text: string): string {
  // Tolerant JSONC: strip // and /* */ comments and trailing commas.
  return text
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .replace(/(^|[^:])\/\/[^\n]*/g, "$1")
    .replace(/,(\s*[}\]])/g, "$1");
}

function generate(entry: string): {
  policy: Policy;
  selfGrants: SiteGrant[];
} {
  const projectRoot = Deno.cwd();
  const graph = runDenoInfo(entry);
  const perSelector: Record<string, Set<string>> = {};
  const selfGrants: SiteGrant[] = [];

  for (const m of graph.modules) {
    if (m.error || !m.local) continue;
    let source: string;
    try {
      source = Deno.readTextFileSync(m.local);
    } catch {
      continue;
    }
    const firstParty = isFirstParty(m, projectRoot);
    for (const site of extractSiteGrants(source)) {
      const selector = selectorOf(site.specifier);
      if (selector === null) continue;
      const grants = grantsFromAttrs(site.attrs);
      if (!grants.length) continue;
      if (!firstParty) {
        // A dependency authored a grant. Ignored for policy; surfaced.
        for (const g of grants) selfGrants.push({ selector, grant: g });
        continue;
      }
      perSelector[selector] ??= new Set();
      for (const g of grants) perSelector[selector].add(g);
    }
  }

  // Union with root config grants.
  for (const [sel, gs] of Object.entries(readRootConfigGrants(projectRoot))) {
    for (const g of gs) (perSelector[sel] ??= new Set()).add(g);
  }

  const grants: Record<string, string> = {};
  for (const sel of Object.keys(perSelector).sort()) {
    const list = [...perSelector[sel]].filter(Boolean).sort();
    if (list.length) grants[sel] = list.join(",");
  }
  return { policy: { mode: "audit", grants }, selfGrants };
}

// Byte-reproducible serialization: sorted keys, 2-space indent, trailing NL.
function serialize(policy: Policy): string {
  const grants: Record<string, string> = {};
  for (const k of Object.keys(policy.grants).sort()) {
    grants[k] = policy.grants[k];
  }
  return JSON.stringify({ mode: policy.mode, grants }, null, 2) + "\n";
}

type Drift = { expansions: string[]; shrinkages: string[] };

function diffPolicies(committed: Policy, fresh: Policy): Drift {
  const expansions: string[] = [];
  const shrinkages: string[] = [];
  if (committed.mode !== fresh.mode) {
    expansions.push(`mode: ${committed.mode} -> ${fresh.mode}`);
  }
  const sels = new Set([
    ...Object.keys(committed.grants),
    ...Object.keys(fresh.grants),
  ]);
  for (const sel of [...sels].sort()) {
    const before = new Set(splitList(committed.grants[sel] ?? ""));
    const after = new Set(splitList(fresh.grants[sel] ?? ""));
    for (const g of after) {
      if (!before.has(g)) {
        const sev = HIGH_SEVERITY.test(g) ? " [HIGH]" : "";
        expansions.push(`+ ${sel}: ${g}${sev}`);
      }
    }
    for (const g of before) {
      if (!after.has(g)) shrinkages.push(`- ${sel}: ${g}`);
    }
  }
  return { expansions, shrinkages };
}

function main() {
  const args = [...Deno.args];
  const check = args.includes("--check");
  const outIdx = args.indexOf("--out");
  const out = outIdx !== -1 ? args[outIdx + 1] : ".oden/policy.json";
  const positional = args.filter((a, i) =>
    !a.startsWith("--") && args[i - 1] !== "--out"
  );
  const entry = positional[0];
  if (!entry) {
    console.error(
      "usage: policy_gen.ts <entry> [--out .oden/policy.json] [--check]",
    );
    Deno.exit(2);
  }

  const { policy, selfGrants } = generate(entry);
  const rendered = serialize(policy);

  if (selfGrants.length) {
    console.error(
      "supply-chain signal: dependency self-grant attempts ignored",
    );
    for (const s of selfGrants) {
      console.error(`  - ${s.selector} tried to grant itself \`${s.grant}\``);
    }
  }

  if (check) {
    let committedText: string;
    try {
      committedText = Deno.readTextFileSync(out);
    } catch {
      console.error(`no committed policy at ${out}; run without --check first`);
      Deno.exit(1);
    }
    if (committedText === rendered) {
      console.log(`policy artifact ${out}: up to date`);
      return;
    }
    const committed = JSON.parse(committedText) as Policy;
    const drift = diffPolicies(committed, policy);
    console.error(`policy drift against ${out}:`);
    for (const e of drift.expansions) console.error(`  ${e}`);
    for (const s of drift.shrinkages) console.error(`  ${s}`);
    Deno.exit(1);
  }

  Deno.writeTextFileSync(out, rendered);
  console.log(`wrote ${out} (${Object.keys(policy.grants).length} principals)`);
}

main();

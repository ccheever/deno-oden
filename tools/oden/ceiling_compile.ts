#!/usr/bin/env -S deno run --allow-read --allow-run
// Copyright 2018-2026 the Deno authors. MIT license.
//
// Oden deny-ceiling compiler (LLP 0001 Phase 1 carve-out; LLP 0003 mechanism 5;
// LLP 0008 layer-1 working default).
//
// The deny ceiling is the one enforcement slice Phase 1 delivers: a committed
// ceiling file naming capabilities that *no* principal — including root — may
// use. Its v1 implementation compiles to Deno's process-level layer-1
// `--deny-*` flags, so root-binding and audit-activeness fall out of the
// substrate without amending layer-2 semantics. Crucially the ceiling holds
// even when layer 1 is otherwise wide open: `--allow-all` grants everything,
// but a compiled `--deny-*` still denies, so a `node:` require read of a
// ceiling target under `--allow-all` is refused (the "fast-skip-with-denies"
// property — the layer-1 companion to the layer-2-independence spike).
//
// Ceiling file (`.oden/ceiling.json`): a family → deny-scope map.
//   { "read": ["/etc/shadow"], "write": ["/etc"], "net": ["10.0.0.0/8"],
//     "env": ["AWS_SECRET_ACCESS_KEY"], "sys": ["networkInterfaces"],
//     "run": ["curl"], "ffi": true, "import": ["evil.example.com"] }
// A `true` value denies the whole family (bare `--deny-x`); a string list scopes
// the denial (`--deny-x=a,b`); an absent family adds no flag.
//
//   deno run -A tools/oden/ceiling_compile.ts <ceiling.json>            # print flags
//   deno run -A tools/oden/ceiling_compile.ts <ceiling.json> --exec <entry> [args...]
//
// @ref llp/0001-adding-capability-security-to-deno.plan.md (Phase 1 ceiling
// carve-out; fast-skip-with-denies fixture)

// Ceiling family → Deno layer-1 deny flag. Ordered for stable output.
const FAMILY_TO_FLAG: Record<string, string> = {
  read: "--deny-read",
  write: "--deny-write",
  net: "--deny-net",
  env: "--deny-env",
  sys: "--deny-sys",
  run: "--deny-run",
  ffi: "--deny-ffi",
  import: "--deny-import",
};

// Accept the finer oden-family aliases so a ceiling can be authored in the same
// vocabulary as grants (fs:read, network, …) or in raw Deno terms.
const ALIASES: Record<string, string> = {
  "fs:read": "read",
  "fs:write": "write",
  "network": "net",
  "fetch": "net",
};

type Ceiling = Record<string, true | string[]>;

function normalizeFamily(family: string): string {
  return ALIASES[family] ?? family;
}

export function compile(ceiling: Ceiling): string[] {
  const flags: string[] = [];
  for (const family of Object.keys(FAMILY_TO_FLAG)) {
    // Collect from every source family (raw + aliases) that maps here.
    const scopes: string[] = [];
    let denyAll = false;
    for (const [rawFamily, value] of Object.entries(ceiling)) {
      if (normalizeFamily(rawFamily) !== family) continue;
      if (value === true) {
        denyAll = true;
      } else if (Array.isArray(value)) {
        for (const s of value) {
          if (typeof s !== "string") {
            throw new Error(
              `ceiling ${rawFamily}: scope entries must be strings`,
            );
          }
          scopes.push(s);
        }
      } else {
        throw new Error(`ceiling ${rawFamily}: value must be true or string[]`);
      }
    }
    const flag = FAMILY_TO_FLAG[family];
    if (denyAll) {
      flags.push(flag); // bare deny wins over any scoping
    } else if (scopes.length) {
      flags.push(`${flag}=${[...new Set(scopes)].sort().join(",")}`);
    }
  }
  return flags;
}

function loadCeiling(path: string): Ceiling {
  let text: string;
  try {
    text = Deno.readTextFileSync(path);
  } catch (e) {
    throw new Error(`cannot read ceiling ${path}: ${(e as Error).message}`);
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch (e) {
    throw new Error(
      `ceiling ${path} is not valid JSON: ${(e as Error).message}`,
    );
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new Error(`ceiling ${path} must be a JSON object`);
  }
  const ceiling = parsed as Record<string, unknown>;
  for (const family of Object.keys(ceiling)) {
    if (!(normalizeFamily(family) in FAMILY_TO_FLAG)) {
      throw new Error(
        `ceiling ${path}: unknown family \`${family}\` ` +
          `(known: ${Object.keys(FAMILY_TO_FLAG).join(", ")})`,
      );
    }
  }
  return ceiling as Ceiling;
}

function main() {
  const args = [...Deno.args];
  const path = args.shift();
  if (!path) {
    console.error(
      "usage: ceiling_compile.ts <ceiling.json> [--exec <entry> [args...]]",
    );
    Deno.exit(2);
  }

  let flags: string[];
  try {
    flags = compile(loadCeiling(path));
  } catch (e) {
    console.error((e as Error).message);
    Deno.exit(1);
  }

  const execIdx = args.indexOf("--exec");
  if (execIdx === -1) {
    console.log(flags.join(" "));
    return;
  }

  const rest = args.slice(execIdx + 1);
  if (!rest.length) {
    console.error("--exec requires an entry file");
    Deno.exit(2);
  }
  // Prove fast-skip-with-denies: layer 1 is thrown wide open with --allow-all,
  // yet the compiled ceiling denies still bite.
  const cmd = new Deno.Command(Deno.execPath(), {
    args: ["run", "--allow-all", ...flags, ...rest],
    stdout: "inherit",
    stderr: "inherit",
  });
  const { code } = cmd.outputSync();
  Deno.exit(code);
}

if (import.meta.main) main();

#!/usr/bin/env -S deno run --allow-read
// Copyright 2018-2026 the Deno authors. MIT license.
//
// Oden stack-trace annotation audit (LLP 0001 Phase 1, ENG-23764).
//
// The chosen principal-capture point rides the `#[op2(stack_trace)]`
// annotation set: capture code is emitted only into annotated ops' generated
// dispatch. That makes the annotation set load-bearing for attribution — a
// permission-checking op *without* the annotation dispatches with no captured
// frames, so the principal falls to the CPED slot or the fail-closed no-user
// sentinel (row 4): under enforce that is a false DENY (loud), never a silent
// allow. This audit closes the drift risk: it statically enumerates every op
// whose body (or same-file helpers, two hops) performs a permission check and
// fails if any such op lacks `stack_trace`.
//
// Run from `fork/deno`:
//   deno run --allow-read tools/oden/stack_trace_audit.ts [--check] [--list]
//
// --check exits non-zero on violations (canary gate); --list prints the
// full classification.
// @ref llp/0001-adding-capability-security-to-deno.plan.md

const ROOT = new URL("../../", import.meta.url).pathname;
const SCAN_DIRS = ["ext", "runtime/ops"];

// Direct evidence that a function body consults the permission layer.
// check_or_exit / check_unstable are feature-flag gates, not permission
// checks; a lookahead excludes them.
const CHECK_RE =
  /\bPermissionsContainer\b|[.:]check_(?!or_exit|unstable)[a-z_]+\s*[(:<]|\bquery_read_all\s*\(/;

// Ops that match CHECK_RE but are deliberately not annotated, each with the
// reason the miss is sound. Keep this list justified and short.
const EXEMPT: Record<string, string> = {
  // Permission *introspection* ops: they read permission state (query/request
  // /revoke) rather than exercising a capability; attribution of the caller
  // is not load-bearing for soundness (the userland layer mediates prompts).
};

async function* rsFiles(dir: string): AsyncGenerator<string> {
  const entries = [];
  for await (const entry of Deno.readDir(dir)) entries.push(entry);
  entries.sort((a, b) => a.name < b.name ? -1 : a.name > b.name ? 1 : 0);
  for (const e of entries) {
    const p = `${dir}/${e.name}`;
    if (e.isDirectory) yield* rsFiles(p);
    else if (e.name.endsWith(".rs")) yield p;
  }
}

type Fn = { name: string; attrs: string; body: string; isOp: boolean };

// Extract fns with their attribute block and brace-counted body.
function extractFns(src: string): Fn[] {
  const fns: Fn[] = [];
  const re =
    /((?:#\[[^\]]*\]\s*)*)(?:pub(?:\([a-z]+\))?\s+)?(?:async\s+)?fn\s+([A-Za-z0-9_]+)/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(src)) !== null) {
    const attrs = m[1] ?? "";
    const name = m[2];
    // Find the body: first '{' after the signature (skip fns ending in ';').
    let i = re.lastIndex;
    let depth = 0;
    let start = -1;
    for (; i < src.length; i++) {
      const ch = src[i];
      if (ch === ";" && depth === 0 && start === -1) break; // trait decl
      if (ch === "{") {
        if (depth === 0) start = i;
        depth++;
      } else if (ch === "}") {
        depth--;
        if (depth === 0 && start !== -1) break;
      }
    }
    const body = start === -1 ? "" : src.slice(start, i + 1);
    fns.push({ name, attrs, body, isOp: /#\[op2[\](]/.test(attrs) });
  }
  return fns;
}

function calledLocals(body: string, locals: Map<string, Fn>): Fn[] {
  const out: Fn[] = [];
  for (const [name, fn] of locals) {
    if (new RegExp(`\\b${name}\\s*[(:<]`).test(body)) out.push(fn);
  }
  return out;
}

const checkArg = Deno.args.includes("--check");
const listArg = Deno.args.includes("--list");

let opCount = 0;
let annotated = 0;
let checking = 0;
const violations: string[] = [];
const exemptHits: string[] = [];

for (const dir of SCAN_DIRS) {
  for await (const path of rsFiles(ROOT + dir)) {
    const src = await Deno.readTextFile(path);
    if (!src.includes("#[op2")) continue;
    const fns = extractFns(src);
    const locals = new Map(fns.filter((f) => !f.isOp).map((f) => [f.name, f]));
    for (const fn of fns) {
      if (!fn.isOp) continue;
      opCount++;
      const hasAnnotation = /stack_trace/.test(fn.attrs);
      if (hasAnnotation) annotated++;
      // Direct check, or via same-file helpers (two hops).
      let checks = CHECK_RE.test(fn.body);
      if (!checks) {
        for (const h1 of calledLocals(fn.body, locals)) {
          if (CHECK_RE.test(h1.body)) checks = true;
          else {
            for (const h2 of calledLocals(h1.body, locals)) {
              if (CHECK_RE.test(h2.body)) checks = true;
            }
          }
          if (checks) break;
        }
      }
      if (checks) checking++;
      const rel = path.slice(ROOT.length);
      if (listArg && (checks || hasAnnotation)) {
        console.log(
          `${checks ? "CHECKS" : "      "} ${
            hasAnnotation ? "ANNOT" : "     "
          } ${fn.name} (${rel})`,
        );
      }
      if (checks && !hasAnnotation) {
        if (fn.name in EXEMPT) {
          exemptHits.push(`${fn.name} — ${EXEMPT[fn.name]}`);
        } else {
          violations.push(`${fn.name} (${rel})`);
        }
      }
    }
  }
}

console.log(
  `stack-trace audit: ${opCount} ops scanned, ${annotated} annotated, ${checking} permission-checking, ${exemptHits.length} exempt, ${violations.length} violations`,
);
for (const e of exemptHits) console.log(`  exempt: ${e}`);
for (const v of violations) console.log(`  VIOLATION: ${v}`);

if (violations.length > 0) {
  console.error(
    "stack-trace audit: FAILED — permission-checking op(s) missing #[op2(stack_trace)]; capture will not fire for them (fail-closed misattribution). Annotate or justify in EXEMPT.",
  );
  if (checkArg) Deno.exit(1);
}

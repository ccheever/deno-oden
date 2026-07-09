#!/usr/bin/env -S deno run --allow-read --allow-write
// Copyright 2018-2026 the Deno authors. MIT license.
//
// Oden audit → policy synthesizer (LLP 0001 Phase 4; audit-as-conversation).
//
// The second half of the agent-facing feedback loop: the engine emits, per
// would-deny/deny, a structured grant suggestion into the `ODEN_CAPSEC_AUDIT`
// NDJSON stream (`runtime/permissions/lib.rs`); this tool reads a real run's
// audit log and synthesizes a starting `.oden/policy.json` that grants each
// principal exactly the authority it was observed to need. So "run code nobody
// read, then accept the grants it actually used" becomes one reviewable step:
//
//   ODEN_CAPSEC_SPIKE=1 ODEN_CAPSEC_MODE=audit ODEN_CAPSEC_AUDIT=run.ndjson \
//     deno run --allow-all app.js
//   deno run -A tools/oden/audit_synth.ts run.ndjson --out .oden/policy.json
//
// The synthesized policy is a *proposal*, not an auto-accept: it prints a
// per-principal summary so a human/agent reviews the widening before committing.
//
// @ref llp/0001-adding-capability-security-to-deno.plan.md (Phase 4 audit
// feedback loop) ; llp/0008-grant-review-conversation.plan.md

type AuditRecord = {
  principal: string;
  capability: string; // "family:action"
  target: string;
  decision: "allow-ambient" | "allow-granted" | "audit-record" | "deny";
  suggestion?: string | null;
};

// Reconstruct a grant token from a record when the engine did not attach a
// suggestion (older logs / ambient rows never carry one).
function tokenFor(r: AuditRecord): string | null {
  if (r.suggestion) return r.suggestion;
  const [family, action] = r.capability.split(":");
  switch (family) {
    case "ffi":
      return "ffi";
    case "run":
      return `run:${r.target}`;
    case "env":
      return `env:read:${r.target}`;
    case "fs":
      return `fs:${action}:${r.target}`;
    case "network":
      return `network:${action}:${hostOf(r.target)}`;
    default:
      return null;
  }
}

function hostOf(target: string): string {
  const t = target.replace(/^https?:\/\//, "").split("/")[0];
  return t.split(":")[0];
}

// A row that would fail under enforce absent a grant: an ungranted (audit-record)
// or denied access. Ambient/granted rows need no grant.
function isWouldDeny(r: AuditRecord): boolean {
  return r.decision === "audit-record" || r.decision === "deny";
}

function synthesize(records: AuditRecord[]): {
  policy: { mode: string; grants: Record<string, string> };
  summary: Map<string, Set<string>>;
} {
  const perPrincipal = new Map<string, Set<string>>();
  for (const r of records) {
    if (!isWouldDeny(r)) continue;
    if (r.principal === "root" || r.principal === "runtime") continue;
    if (r.principal === "no-user") continue; // fail-closed sentinel, not grantable
    const token = tokenFor(r);
    if (!token) continue;
    (perPrincipal.get(r.principal) ?? setInto(perPrincipal, r.principal))
      .add(token);
  }
  const grants: Record<string, string> = {};
  for (const p of [...perPrincipal.keys()].sort()) {
    grants[p] = [...perPrincipal.get(p)!].sort().join(",");
  }
  return { policy: { mode: "enforce", grants }, summary: perPrincipal };
}

function setInto(m: Map<string, Set<string>>, k: string): Set<string> {
  const s = new Set<string>();
  m.set(k, s);
  return s;
}

function main() {
  const args = [...Deno.args];
  const outIdx = args.indexOf("--out");
  const positional = args.filter((a, i) =>
    !a.startsWith("--") && args[i - 1] !== "--out"
  );
  const logPath = positional[0];
  if (!logPath) {
    console.error("usage: audit_synth.ts <audit.ndjson> [--out policy.json]");
    Deno.exit(2);
  }
  const text = Deno.readTextFileSync(logPath);
  const records: AuditRecord[] = [];
  for (const line of text.split("\n")) {
    if (!line.trim()) continue;
    try {
      records.push(JSON.parse(line) as AuditRecord);
    } catch { /* skip malformed */ }
  }
  const { policy, summary } = synthesize(records);

  console.error("synthesized policy proposal (review before committing):");
  if (summary.size === 0) {
    console.error("  (no ungranted package accesses observed)");
  }
  for (const p of [...summary.keys()].sort()) {
    console.error(`  ${p}: ${[...summary.get(p)!].sort().join(", ")}`);
  }

  const rendered = JSON.stringify(policy, null, 2) + "\n";
  if (outIdx !== -1) {
    Deno.writeTextFileSync(args[outIdx + 1], rendered);
    console.log(`wrote ${args[outIdx + 1]}`);
  } else {
    console.log(rendered);
  }
}

if (import.meta.main) main();

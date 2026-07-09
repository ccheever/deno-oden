#!/usr/bin/env -S deno run --allow-read --allow-write --allow-run --allow-env
// Copyright 2018-2026 the Deno authors. MIT license.
//
// Oden compat-corpus harness (LLP 0001 Phase 1; Ibex LLP 0016 R1).
//
// Runs a corpus of package graphs under audit and aggregates the per-package
// would-deny audit stream (`ODEN_CAPSEC_AUDIT` NDJSON) into the numbers that
// price every later default:
//
//   * per-principal would-deny volume — how much authority each package would
//     need granted to run under enforce (the observability story), and
//   * legitimate-hit rate against a proposed deny-ceiling default set — for each
//     ceiling candidate, the fraction of corpus packages that legitimately touch
//     it. A high legitimate-hit rate means promoting that ceiling default would
//     break real code, so this is the measurement that gates ceiling
//     ratification and default-set promotion (LLP 0008 round-1 revision).
//
// SCOPE: this harness is the runnable mechanism; the *dominant cost* of the
// ticket — actually installing and running the real top-N npm graphs — needs a
// network + install step outside this sandbox, and the lockdown-mode arm needs
// the freeze walk (a separate Phase-2 deliverable). Both are called out in the
// report so a clean-looking run is never mistaken for "the corpus was run."
// A small self-contained sample corpus lives under
// tests/specs/run/oden_capsec_compat_corpus/ so the harness itself is exercised.
//
//   deno run -A tools/oden/compat_corpus.ts <corpus.json> [--out report.md]
//
// corpus.json:
//   { "root": ".",
//     "entries": [ { "name": "left-pad-demo", "entry": "demo/lp.js" } ],
//     "ceiling": { "env": ["AWS_SECRET_ACCESS_KEY"], "fs:read": ["/etc"],
//                  "run": ["*"] } }
//
// @ref llp/0001-adding-capability-security-to-deno.plan.md (Phase 1 compat corpus)

type Entry = { name: string; entry: string; args?: string[] };
type Corpus = {
  root?: string;
  entries: Entry[];
  ceiling?: Record<string, string[]>;
};

type AuditRecord = {
  principal: string;
  capability: string; // "family:action"
  target: string;
  decision: "allow-ambient" | "allow-granted" | "audit-record" | "deny";
};

function loadCorpus(path: string): Corpus {
  const corpus = JSON.parse(Deno.readTextFileSync(path)) as Corpus;
  if (!Array.isArray(corpus.entries)) {
    throw new Error("corpus must have an `entries` array");
  }
  return corpus;
}

function runEntry(root: string, entry: Entry): AuditRecord[] {
  const auditFile = Deno.makeTempFileSync({ suffix: ".ndjson" });
  // Structural arming: the policy artifact arms the child, handed off via
  // ODEN_CAPSEC_POLICY (audit mode, zero grants) without touching the corpus
  // entry's own tree.
  const policyFile = Deno.makeTempFileSync({ suffix: ".json" });
  Deno.writeTextFileSync(policyFile, JSON.stringify({ mode: "audit" }));
  try {
    const cmd = new Deno.Command(Deno.execPath(), {
      args: ["run", "--allow-all", entry.entry, ...(entry.args ?? [])],
      cwd: root,
      env: {
        ODEN_CAPSEC_POLICY: policyFile,
        ODEN_CAPSEC_AUDIT: auditFile,
      },
      stdout: "null",
      stderr: "null",
    });
    cmd.outputSync(); // exit code ignored: a crashing sample still yields audit rows
    const text = Deno.readTextFileSync(auditFile);
    const records: AuditRecord[] = [];
    for (const line of text.split("\n")) {
      if (!line.trim()) continue;
      try {
        records.push(JSON.parse(line) as AuditRecord);
      } catch {
        // skip malformed line
      }
    }
    return records;
  } finally {
    try {
      Deno.removeSync(auditFile);
      Deno.removeSync(policyFile);
    } catch { /* ignore */ }
  }
}

// A record is a would-deny (would fail under enforce absent a grant) when it is
// an ungranted, non-ambient access — the audit-record decision.
function isWouldDeny(r: AuditRecord): boolean {
  return r.decision === "audit-record" || r.decision === "deny";
}

// Does an audit record fall inside a proposed ceiling entry? A ceiling key
// matches the record when it names either the record's family (`env`) or its
// full capability (`fs:read` — the exact vocabulary the engine emits), and a
// scope entry `*`/prefix-matches the target.
function hitsCeiling(
  r: AuditRecord,
  ceiling: Record<string, string[]>,
): boolean {
  const family = r.capability.split(":")[0];
  for (const [key, scopes] of Object.entries(ceiling)) {
    if (key !== family && key !== r.capability) continue;
    for (const s of scopes) {
      if (s === "*" || r.target === s || r.target.startsWith(s)) return true;
    }
  }
  return false;
}

type Report = {
  perPrincipal: Map<string, { total: number; wouldDeny: number }>;
  perCapability: Map<string, number>; // would-deny count by capability
  ceilingHits: Map<string, Set<string>>; // ceiling entry -> principals touching it
  entriesRun: number;
  totalRecords: number;
};

function aggregate(corpus: Corpus, all: AuditRecord[][]): Report {
  const perPrincipal = new Map<string, { total: number; wouldDeny: number }>();
  const perCapability = new Map<string, number>();
  const ceilingHits = new Map<string, Set<string>>();
  const ceiling = corpus.ceiling ?? {};
  for (const [fam, scopes] of Object.entries(ceiling)) {
    for (const s of scopes) ceilingHits.set(`${fam}:${s}`, new Set());
  }

  let totalRecords = 0;
  for (const records of all) {
    for (const r of records) {
      totalRecords++;
      const p = perPrincipal.get(r.principal) ?? { total: 0, wouldDeny: 0 };
      p.total++;
      if (isWouldDeny(r)) {
        p.wouldDeny++;
        perCapability.set(
          r.capability,
          (perCapability.get(r.capability) ?? 0) + 1,
        );
      }
      perPrincipal.set(r.principal, p);
      // Legitimate-hit rate counts *any* real touch of a ceiling target, not
      // only would-denies: even a granted/ambient touch means promoting that
      // ceiling default would have blocked legitimate code.
      for (const [fam, scopes] of Object.entries(ceiling)) {
        for (const s of scopes) {
          if (hitsCeiling(r, { [fam]: [s] })) {
            ceilingHits.get(`${fam}:${s}`)!.add(r.principal);
          }
        }
      }
    }
  }
  return {
    perPrincipal,
    perCapability,
    ceilingHits,
    entriesRun: all.length,
    totalRecords,
  };
}

function render(report: Report): string {
  const principals = report.perPrincipal.size || 1;
  const out: string[] = [];
  out.push("# Oden compat-corpus report (generated)");
  out.push("");
  out.push(
    `Ran ${report.entriesRun} corpus entries under audit; ` +
      `${report.totalRecords} mediated ops observed across ` +
      `${report.perPrincipal.size} principals.`,
  );
  out.push("");
  out.push("## Would-deny volume per principal (enforce readiness)");
  out.push("");
  out.push("| principal | mediated ops | would-deny under enforce |");
  out.push("| --- | --- | --- |");
  for (
    const [p, v] of [...report.perPrincipal].sort((a, b) =>
      b[1].wouldDeny - a[1].wouldDeny
    )
  ) {
    out.push(`| ${p} | ${v.total} | ${v.wouldDeny} |`);
  }
  out.push("");
  out.push("## Would-deny by capability");
  out.push("");
  out.push("| capability | would-deny count |");
  out.push("| --- | --- |");
  for (
    const [c, n] of [...report.perCapability].sort((a, b) => b[1] - a[1])
  ) {
    out.push(`| ${c} | ${n} |`);
  }
  out.push("");
  out.push("## Legitimate-hit rate vs proposed deny-ceiling defaults");
  out.push("");
  out.push(
    "For each ceiling candidate, the fraction of corpus principals that " +
      "legitimately touch it. A high rate prices the default as too costly to " +
      "promote (LLP 0008 ceiling ratification).",
  );
  out.push("");
  out.push("| ceiling candidate | principals hit | legitimate-hit rate |");
  out.push("| --- | --- | --- |");
  if (report.ceilingHits.size === 0) {
    out.push("| _(no ceiling in corpus)_ | — | — |");
  }
  for (const [entry, hits] of report.ceilingHits) {
    const rate = ((hits.size / principals) * 100).toFixed(1);
    out.push(`| ${entry} | ${hits.size} | ${rate}% |`);
  }
  out.push("");
  out.push("## Scope caveats (do not mistake a clean run for a full corpus)");
  out.push("");
  out.push(
    "- **Corpus size**: this reflects the entries actually run. Pricing the " +
      "real defaults needs the top-N npm graphs installed and run — a " +
      "network + install step outside the sandbox.",
  );
  out.push(
    "- **Lockdown arm not run**: the separate under-lockdown pass needs the " +
      "freeze walk (Phase-2 minimal lockdown). Until then only the audit arm " +
      "is measured, and the lockdown-default kill criterion stays unpriced.",
  );
  out.push("");
  return out.join("\n");
}

function main() {
  const args = [...Deno.args];
  const corpusPath = args.find((a) =>
    !a.startsWith("--") &&
    args[args.indexOf(a) - 1] !== "--out"
  );
  if (!corpusPath) {
    console.error("usage: compat_corpus.ts <corpus.json> [--out report.md]");
    Deno.exit(2);
  }
  const outIdx = args.indexOf("--out");
  const corpus = loadCorpus(corpusPath);
  const root = corpus.root
    ? new URL(corpus.root + "/", `file://${Deno.realPathSync(corpusPath)}`)
      .pathname
    : new URL(".", `file://${Deno.realPathSync(corpusPath)}`).pathname;

  const all = corpus.entries.map((e) => runEntry(root, e));
  const report = aggregate(corpus, all);
  const rendered = render(report);

  if (outIdx !== -1) {
    Deno.writeTextFileSync(args[outIdx + 1], rendered);
    console.log(`wrote ${args[outIdx + 1]}`);
  } else {
    console.log(rendered);
  }
}

if (import.meta.main) main();

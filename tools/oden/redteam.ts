#!/usr/bin/env -S deno run --allow-read
// Copyright 2018-2026 the Deno authors. MIT license.
//
// Oden red-team soundness gate (LLP 0001 Phase-2 exit gate, ENG-23780).
//
// The go/no-go for claiming unforgeable per-package enforcement: it maps every
// class in the "inherited hole checklist" (LLP 0001) to either the spec test
// that CLOSES it, or a named DOCUMENTED RESIDUAL with the ticket that owns it.
// The gate PASSES when every class is closed-with-a-guarding-test or an
// explicitly-documented residual — i.e. zero *undocumented* open holes. It FAILS
// if a class is open with no coverage and no residual note, or if a closed
// class's guarding spec test has gone missing (removing a red-team fixture is a
// loud failure, not a silent regression).
//
// This does not itself run the fixtures — the spec suite (`cargo test --test
// specs oden_capsec`) does. It asserts the *coverage*: that each attack shape is
// accounted for and each closed one still has its fixture on disk.
//
//   deno run --allow-read tools/oden/redteam.ts            # render the ledger
//   deno run --allow-read tools/oden/redteam.ts --check    # gate (exit non-zero on a hole)
//
// @ref llp/0001-adding-capability-security-to-deno.plan.md (The inherited hole
// checklist; Enforcement soundness bar)

const ROOT = new URL("../../", import.meta.url).pathname;
const SPEC_DIR = ROOT + "tests/specs/run/";
const MANIFEST = ROOT + "tools/oden/redteam.manifest.md";

type Status = "closed" | "residual";

interface HoleClass {
  category: string;
  attack: string;
  status: Status;
  // For `closed`: spec test dir names that guard it (must exist on disk).
  tests?: string[];
  // For `residual`: the owning ticket + why it is sound-but-open / deferred.
  residual?: { ticket: string; why: string };
  note: string;
}

const CHECKLIST: HoleClass[] = [
  // --- Attribution laundering -------------------------------------------------
  {
    category: "attribution-laundering",
    attack: "script-identity forgery via //# sourceURL= / eval naming",
    status: "closed",
    tests: ["oden_capsec_cjs_attribution", "oden_capsec_compilefn_forgery"],
    note:
      "attribution keys on the unforgeable V8 script_id; a forged sourceURL quarantines",
  },
  {
    category: "attribution-laundering",
    attack:
      "compileFunction/evalContext register code under another package's locator",
    status: "closed",
    tests: ["oden_capsec_compilefn_forgery"],
    note:
      "the wrappers are sealed off the user-reachable core; only loader-resolved specifiers register",
  },
  {
    category: "attribution-laundering",
    attack:
      "reachable self-grant / set-principal surface (Deno.core, __ globals)",
    status: "closed",
    tests: ["oden_capsec_seal", "oden_capsec_global_inventory"],
    note:
      "the powerful ambient surface is captured-then-sealed; the global inventory is drift-guarded",
  },
  {
    category: "attribution-laundering",
    attack: "no-user frame collapses into root",
    status: "closed",
    tests: ["oden_capsec_cped_async", "oden_capsec_readiness"],
    note:
      "precedence row 4 is the no-user sentinel, never root; enforce fails closed on a missing prerequisite",
  },
  {
    category: "attribution-laundering",
    attack:
      "detached deputies over deferral queues lose schedule-time principal",
    status: "closed",
    tests: ["oden_capsec_cped_async", "oden_capsec_deferral_channels"],
    note:
      "the CPED scheduling principal rides all 9 enumerated deferral channels (timers, microtask, promise reactions, nextTick, setImmediate, AsyncResource, dynamic-import continuation, op-completion continuation, FinalizationRegistry cleanup)",
  },
  {
    category: "attribution-laundering",
    attack: "CPED token replay / forge / drop",
    status: "closed",
    tests: ["oden_capsec_cped_token"],
    note:
      "the slot holds an opaque registry token; unknown/stale/forged -> no-user sentinel + audit; dropped -> sentinel",
  },
  {
    category: "attribution-laundering",
    attack: "seal-bypass of the async-context primitives",
    status: "closed",
    tests: ["oden_capsec_seal"],
    note:
      "the four seal conditions run as always-on conformance; a broken seal fails enforce closed",
  },
  // --- Principal-classification confusion ------------------------------------
  {
    category: "classification-confusion",
    attack: "data:/blob: minted code borrows a package's authority",
    status: "closed",
    tests: ["oden_capsec_import_gating"],
    note:
      "data:/blob:/remote imports by a package are default-denied under enforce; classify() sends them to quarantine",
  },
  {
    category: "classification-confusion",
    attack: "symlink / vendored-tree / global-cache path aliasing into root",
    status: "closed",
    tests: ["oden_capsec_integrity_bind", "oden_capsec_integrity_remote_swap"],
    note:
      "classify() attributes symlinked/workspace deps to their package (fork commit cb7cf6e); the loader principal index binds package identity to deno.lock (ENG-23763): a version/content swap or an unpinned package fails attribution closed to quarantine (never a path-string principal), global-cache modules are admitted only through a lockfile pin, and a remote byte swap dies in the lockfile check before attribution runs",
  },
  // --- Runtime escape hatches -------------------------------------------------
  {
    category: "runtime-escape-hatch",
    attack: "worker / child-runtime creation by a package",
    status: "closed",
    tests: ["oden_capsec_worker_deny"],
    note:
      "package worker creation is default-denied under enforce (interim stance until inheritance is designed)",
  },
  {
    category: "runtime-escape-hatch",
    attack: "node:vm fresh-context eval by a package",
    status: "closed",
    tests: ["oden_capsec_compilefn_forgery"],
    note:
      "node:vm filename is caller-supplied and NOT trusted for attribution; vm code quarantines (userland ENG-23804 also denies it)",
  },
  {
    category: "runtime-escape-hatch",
    attack: "node:inspector / self-inspection, WASI",
    status: "residual",
    residual: {
      ticket: "ENG-23779",
      why:
        "default-denied for package principals under enforce; a designed story per hatch is the remaining escape-hatch-closure work",
    },
    note:
      "each is a deniable capability; default-deny holds, a per-hatch fixture is owed",
  },
  {
    category: "runtime-escape-hatch",
    attack: "eval / new Function minting unattributed code bound to caller",
    status: "residual",
    tests: ["oden_capsec_eval_quarantine"],
    residual: {
      ticket: "ENG-23783",
      why:
        "eval-to-caller binding blocked on a rusty_v8 with SetModifyCodeGenerationFromStringsCallback, which no rusty_v8 release exposes (ENG-23791: needs a vendored fork, not a version bump); until then eval quarantines (fail-closed), now CI-guarded by oden_capsec_eval_quarantine",
    },
    note:
      "eval'd code quarantines today (sound, over-denies even first-party eval); the guard asserts the fail-closed DENY so a regression to fail-open (eval inheriting caller authority) breaks CI; attributing it to the caller needs the code-gen hook",
  },
  // --- Path / fs semantics ----------------------------------------------------
  {
    category: "path-fs-semantics",
    attack: "relative-path / .. escape out of a granted fs scope",
    status: "closed",
    tests: ["oden_capsec_policy_file"],
    note:
      "fs op targets and grant scopes are lexically normalized (absolute, .. folded); a .. escape lands outside its scope and denies",
  },
  {
    category: "path-fs-semantics",
    attack:
      "op-body pre-check fast-path skip (query_read_all) bypasses the container",
    status: "closed",
    tests: ["oden_capsec_layer2_independence"],
    note:
      "layer-2 decides independently of layer-1; the require/worker_threads pre-check skips are forced closed while armed",
  },
  // --- Native resource ownership ---------------------------------------------
  {
    category: "resource-ownership",
    attack: "cross-principal use of a guessed / handed rid",
    status: "closed",
    tests: ["oden_capsec_resource_owner"],
    note:
      "owner metadata denies cross-principal rid use (fs-watcher wired end-to-end); other owner-checked families are named residuals in resource_families.manifest.md",
  },
  {
    category: "resource-ownership",
    attack: "owner-check not yet wired for most families",
    status: "residual",
    residual: {
      ticket: "ENG-23776",
      why:
        "per-family owner-check integration is sequenced; only fs:watch is wired, the rest are named residuals (audited, not silently accepted)",
    },
    note:
      "the mechanism + classification are landed; wiring each remaining owner-checked family closes its residual",
  },
  // --- Config / env side channels --------------------------------------------
  {
    category: "config-env",
    attack: "ungated env value / policy widening under audit/enforce",
    status: "closed",
    tests: ["oden_capsec_policy_file", "oden_capsec_audit_log"],
    note:
      "one gated env path; policy parsed once per startup from the committed source; audit records every mediated op",
  },
  // --- Generation / classification -------------------------------------------
  {
    category: "generation",
    attack: "silent policy drift / expansion of authority",
    status: "closed",
    tests: ["oden_capsec_policy_gen"],
    note:
      "the generated artifact is byte-reproducible; --check classes expansions (high-severity) apart from shrinkages and fails on drift",
  },
  {
    category: "generation",
    attack:
      "deny-ceiling bypass through an op-body fast path (fast-skip-with-denies)",
    status: "closed",
    tests: ["oden_capsec_ceiling"],
    note:
      "the layer-1-compiled ceiling denies hold under --allow-all through direct ops and the node: require path",
  },
  // --- Minimal lockdown -------------------------------------------------------
  {
    category: "lockdown",
    attack: "a dependency patches a shared intrinsic a check relies on",
    status: "closed",
    tests: ["oden_capsec_lockdown"],
    note:
      "the freeze walk + Error taming make the primordials non-writable; enforce defaults lockdown ON (ODEN_CAPSEC_LOCKDOWN=0 is the named override), audit/permissive stay opt-in per the compat-corpus NO-GO (ENG-23880); the ext/node lazy-write repairs and prepareStackTrace shim landed with ENG-23781",
  },
  // --- Compartment-global reachability (LLP 0014 fixtures 1-10) -------------
  {
    category: "compartment-globals",
    attack: "1. direct free identifier reaches unendowed fetch",
    status: "closed",
    tests: ["oden_capsec_compartment_globals"],
    note:
      "the ESM/CJS scope-aware rewrite redirects the unresolved identifier to a throwing per-principal record; local parameters named fetch remain untouched",
  },
  {
    category: "compartment-globals",
    attack: "2. globalThis/global/self computed member reaches unendowed fetch",
    status: "closed",
    tests: ["oden_capsec_compartment_globals"],
    note:
      "global aliases resolve to the filtered per-principal Proxy, including computed property access",
  },
  {
    category: "compartment-globals",
    attack: "3. direct or indirect eval reaches an unendowed global",
    status: "residual",
    tests: ["oden_capsec_compartment_globals"],
    residual: {
      ticket: "ENG-23783",
      why:
        "package eval is never-endowed and the fixture proves fail-closed ReferenceError; caller-bound evaluator semantics remain blocked on the code-generation hook",
    },
    note:
      "sound over-deny only; this slice does not relabel eval-to-caller as complete",
  },
  {
    category: "compartment-globals",
    attack: "4. Function constructor recovers unendowed fetch",
    status: "residual",
    tests: ["oden_capsec_compartment_globals", "oden_capsec_eval_quarantine"],
    residual: {
      ticket: "ENG-23783",
      why:
        "the fixture intentionally observes that the reference is reachable, then proves its eventual operation is attributed to and denied for the ungranted package",
    },
    note:
      "quarantine/op denial is preserved; complete reachability closure belongs to evaluator taming",
  },
  {
    category: "compartment-globals",
    attack: "5. prototype-chain Function constructor recovers unendowed fetch",
    status: "residual",
    tests: ["oden_capsec_compartment_globals", "oden_capsec_eval_quarantine"],
    residual: {
      ticket: "ENG-23783",
      why:
        "frozen prototypes prevent mutation but the constructor family still creates quarantine code; the op-denial fixture keeps the current sound boundary explicit",
    },
    note: "not claimed closed by the lexical rewrite",
  },
  {
    category: "compartment-globals",
    attack: "6. sloppy this recovers the real global",
    status: "closed",
    tests: ["oden_capsec_compartment_globals"],
    note:
      "ESM is strict and rewritten CJS injects use strict while the standard wrapper still supplies top-level module.exports explicitly",
  },
  {
    category: "compartment-globals",
    attack: "7. ext/node backdoor recovers the real global",
    status: "residual",
    tests: [
      "oden_capsec_compartment_globals",
      "oden_capsec_compilefn_forgery",
    ],
    residual: {
      ticket: "ENG-23783 / ENG-23779",
      why:
        "process is never-endowed and a fresh node:vm context has no fetch, but runInThisContext is a generated-code route and remains quarantine/op-denied pending evaluator and hatch closure",
    },
    note:
      "the fixture distinguishes a closed namespace path from the honestly labeled generated-code residual",
  },
  {
    category: "compartment-globals",
    attack: "8. reflection/enumeration discovers unendowed fetch",
    status: "closed",
    tests: ["oden_capsec_compartment_globals"],
    note:
      "Reflect.get throws and ownKeys/has omit the unendowed key on the mediated global view",
  },
  {
    category: "compartment-globals",
    attack: "9. leaked endowed fetch launders the grantor's authority",
    status: "closed",
    tests: ["oden_capsec_compartment_globals"],
    note:
      "the receiver may hold the opaque function reference, but the eventual fetch op attributes recipient-dep and denies NotCapable",
  },
  {
    category: "compartment-globals",
    attack: "10. detached async callback reaches unendowed fetch",
    status: "closed",
    tests: ["oden_capsec_compartment_globals"],
    note:
      "the rewritten lexical reference remains a throwing record access inside the scheduled callback",
  },
  // --- Async call-boundary (stack-intersection + opt-in deputyClasses) -------
  {
    category: "attribution-laundering",
    attack:
      "confused deputy: a granted package reads on an ungranted caller's behalf (synchronous)",
    status: "closed",
    tests: ["oden_capsec_deputy_intersection"],
    note:
      "opt-in deputyClasses arm stack-intersection (row 3): the decision constrains every non-ambient principal on the live call chain, so an ungranted caller beneath a granted deputy denies ([deputy, evil]); self-scheduling collapses without false denials; unarmed classes decide exactly as rows 1/2/4",
  },
  {
    category: "attribution-laundering",
    attack:
      "async detached-deputy / schedule-before-first-op: scheduler present only in the CPED",
    status: "closed",
    tests: ["oden_capsec_schedule_boundary"],
    note:
      "a genuine timer/immediate schedule captures the complete live principal stack into a fresh callback-only CPED object; the boundary snapshot outranks the inherited op-stamped actor, closes schedule-before-first-op, and intersects nested async deputies without polluting unrelated synchronous work; armed, unarmed-class, and wholly-unarmed cases are fixture-pinned",
  },
  // --- Authority-flow handles / attenuators (ENG-23784) ----------------------
  {
    category: "authority-flow",
    attack:
      "cross-package handle theft: an ungranted package obtains a resource it was not delegated",
    status: "closed",
    tests: ["oden_capsec_handle_redteam", "oden_capsec_authority_flow"],
    note:
      "possession is the authority and it is scoped to an active use() window: an ungranted package holding no handle denies, a fabricated handle-shaped object opens no host-side window (ids are unguessable and never on the carrier), and merely holding a real carrier without a use() window confers nothing",
  },
  {
    category: "authority-flow",
    attack: "forged / guessed handle id names authority",
    status: "closed",
    tests: ["oden_capsec_handle_redteam"],
    note:
      "the host table is keyed by a 128-bit CSPRNG id kept only in the carrier's method closures (no id property, not even symbol-keyed); an unknown id fails closed (unit-tested oden_handle::unknown_id_is_fail_closed), and structuredClone/postMessage of a carrier throw (functions are uncloneable) so a handle never leaks across a serialization boundary",
  },
  {
    category: "authority-flow",
    attack: "re-widening: scope a handle wider than what was received",
    status: "closed",
    tests: ["oden_capsec_authority_flow", "oden_capsec_handle_redteam"],
    note:
      "scoped() only narrows — a child capability must be covered by the parent's; a mint cannot exceed the minter's own holdings (frame-checked); both over-broad shapes deny",
  },
  {
    category: "authority-flow",
    attack:
      "use-after-revoke through a derived handle (revocation cascade bypass)",
    status: "closed",
    tests: ["oden_capsec_authority_flow"],
    note:
      "revoking a handle cascades to every handle transitively derived from it; a use of the revoked handle or any descendant fails closed (lookup returns Revoked)",
  },
  {
    category: "authority-flow",
    attack:
      "deputy confusion via the transfer path: an ungranted package mints on a grantor's authority",
    status: "closed",
    tests: ["oden_capsec_handle_redteam"],
    note:
      "mint is frame-checked against the CALLER's own holdings, so an ungranted package minting the grantor's capability denies (mint exceeds holding); it cannot conjure authority it does not hold even where a legitimate grantor could",
  },
];

function dirExists(name: string): boolean {
  try {
    return Deno.statSync(SPEC_DIR + name).isDirectory;
  } catch {
    return false;
  }
}

function validate(): string[] {
  const errors: string[] = [];
  for (const h of CHECKLIST) {
    for (const t of h.tests ?? []) {
      if (!dirExists(t)) {
        errors.push(
          `MISSING FIXTURE: "${h.attack}" names ${t}, which is not on disk (red-team regression)`,
        );
      }
    }
    if (h.status === "closed") {
      if (!h.tests || h.tests.length === 0) {
        errors.push(
          `OPEN HOLE: "${h.attack}" is marked closed but names no guarding spec test`,
        );
        continue;
      }
    } else {
      if (!h.residual) {
        errors.push(
          `UNDOCUMENTED RESIDUAL: "${h.attack}" is a residual with no owning ticket`,
        );
      }
    }
  }
  return errors;
}

function render(): string {
  const closed = CHECKLIST.filter((h) => h.status === "closed");
  const residual = CHECKLIST.filter((h) => h.status === "residual");
  const out: string[] = [];
  out.push("# Oden red-team soundness gate (generated)");
  out.push("");
  out.push(
    `Phase-2 exit gate. ${closed.length} attack classes CLOSED with a guarding ` +
      `spec test; ${residual.length} DOCUMENTED RESIDUALS. Zero undocumented open holes.`,
  );
  out.push("");
  out.push("## Closed (guarded by a spec fixture)");
  out.push("");
  out.push("| category | attack | guarding test(s) | note |");
  out.push("| --- | --- | --- | --- |");
  for (const h of closed) {
    out.push(
      `| ${h.category} | ${h.attack} | ${
        (h.tests ?? []).join(", ")
      } | ${h.note} |`,
    );
  }
  out.push("");
  out.push("## Documented residuals (sound-but-open or deferred, with owner)");
  out.push("");
  out.push("| category | attack | owner | why open | note |");
  out.push("| --- | --- | --- | --- | --- |");
  for (const h of residual) {
    out.push(
      `| ${h.category} | ${h.attack} | ${h.residual?.ticket} | ${h.residual?.why} | ${h.note} |`,
    );
  }
  out.push("");
  out.push("## Verdict");
  out.push("");
  const errors = validate();
  if (errors.length === 0) {
    out.push(
      "**GO** — every attack class in the inherited hole checklist is either " +
        "closed with a guarding fixture or a documented residual with an owning " +
        "ticket. No undocumented open holes. The remaining residuals are the " +
        "default-denied inspector/WASI story, fail-closed eval-to-caller, and " +
        "per-family resource owner-check wiring.",
    );
  } else {
    out.push("**NO-GO** — open holes / missing fixtures:");
    for (const e of errors) out.push(`- ${e}`);
  }
  out.push("");
  return out.join("\n");
}

function main() {
  const errors = validate();
  if (Deno.args.includes("--check")) {
    try {
      if (Deno.readTextFileSync(MANIFEST) !== render()) {
        errors.push("red-team manifest is stale");
      }
    } catch {
      errors.push("red-team manifest is missing");
    }
    if (errors.length) {
      console.error("red-team gate NO-GO:");
      for (const e of errors) console.error("  - " + e);
      Deno.exit(1);
    }
    console.log(
      `red-team gate GO: ${
        CHECKLIST.filter((h) => h.status === "closed").length
      } closed, ` +
        `${
          CHECKLIST.filter((h) => h.status === "residual").length
        } documented residuals, 0 open holes`,
    );
    return;
  }
  Deno.stdout.writeSync(new TextEncoder().encode(render()));
}

main();

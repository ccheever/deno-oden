#!/usr/bin/env -S deno run --allow-read --allow-write --allow-run --allow-env
// Copyright 2018-2026 the Deno authors. MIT license.
//
// Two-arm LLP 0014 compatibility harness. Every entry runs under the same
// broad enforce policy and enforce-implied lockdown: control keeps compartment
// globals off; experiment explicitly enables them. This isolates rewrite /
// reachability breakage from the policy and lockdown prerequisites shared by
// both arms.
//
// @ref LLP 0014#kill-criteria [tests]

type Entry = { name: string; entry: string; args?: string[] };
type Corpus = { root?: string; entries: Entry[] };
type Arm = { code: number; stdout: string; stderr: string };
type Kind =
  | "compatible"
  | "legitimate-tradeoff"
  | "derivation-gap"
  | "transform-bug"
  | "baseline-failure";
type Result = {
  name: string;
  kind: Kind;
  control: Arm;
  experiment: Arm;
  detail: string;
};

const decoder = new TextDecoder();
const SAFE_LOADER_ENV = {
  LD_LIBRARY_PATH: "",
  LD_PRELOAD: "",
  DYLD_FALLBACK_LIBRARY_PATH: "",
  DYLD_LIBRARY_PATH: "",
  DYLD_INSERT_LIBRARIES: "",
};
const BROAD_GRANTS = "fs:*:*,network:*:*,env:*,run:*,ffi";
const DERIVED = new Set(["fetch", "EventSource", "WebSocket"]);
const INTENTIONAL = new Set([
  "Deno",
  "Worker",
  "alert",
  "confirm",
  "process",
  "prompt",
]);

function loadCorpus(path: string): Corpus {
  const corpus = JSON.parse(Deno.readTextFileSync(path)) as Corpus;
  if (!Array.isArray(corpus.entries)) {
    throw new Error("corpus must have an entries array");
  }
  return corpus;
}

function corpusRoot(path: string, configured?: string): string {
  const file = new URL(`file://${Deno.realPathSync(path)}`);
  return new URL(`${configured ?? "."}/`, file).pathname;
}

function packageNames(root: string): string[] {
  const names = new Set<string>();
  const visited = new Set<string>();
  const pending = [`${root}/node_modules`];
  while (pending.length) {
    const dir = pending.pop()!;
    let real: string;
    try {
      real = Deno.realPathSync(dir);
    } catch {
      continue;
    }
    if (visited.has(real)) continue;
    visited.add(real);
    let entries: Deno.DirEntry[];
    try {
      entries = [...Deno.readDirSync(dir)];
    } catch {
      continue;
    }
    for (const entry of entries) {
      if (!entry.isDirectory && !entry.isSymlink) continue;
      if (entry.name === ".bin") continue;
      const path = `${dir}/${entry.name}`;
      if (entry.name.startsWith("@")) {
        pending.push(path);
        continue;
      }
      try {
        const pkg = JSON.parse(
          Deno.readTextFileSync(`${path}/package.json`),
        ) as { name?: string };
        if (pkg.name) names.add(pkg.name);
      } catch { /* not a package root */ }
      pending.push(`${path}/node_modules`);
    }
  }
  return [...names].sort();
}

function run(
  root: string,
  policy: string,
  entry: Entry,
  compartment: boolean,
): Arm {
  const result = new Deno.Command(Deno.execPath(), {
    cwd: root,
    args: ["run", "--allow-all", entry.entry, ...(entry.args ?? [])],
    env: {
      ...SAFE_LOADER_ENV,
      DENO_NO_UPDATE_CHECK: "1",
      NO_COLOR: "1",
      ODEN_CAPSEC_ALLOW_ADVISORY: "1",
      ODEN_CAPSEC_COMPARTMENT_GLOBALS: compartment ? "1" : "0",
      ODEN_CAPSEC_POLICY: policy,
      ODEN_CAPSEC_ROOT: root,
    },
    stdout: "piped",
    stderr: "piped",
  }).outputSync();
  return {
    code: result.code,
    stdout: decoder.decode(result.stdout),
    stderr: decoder.decode(result.stderr),
  };
}

function concise(stderr: string): string {
  const useful = stderr.split("\n").filter((line) =>
    line.includes("Oden compartment:") ||
    line.startsWith("error:") ||
    line.includes("Uncaught")
  );
  return (useful.at(-1) ?? `exit without a classified error`).trim().slice(
    0,
    180,
  );
}

function classify(name: string, control: Arm, experiment: Arm): Result {
  if (control.code !== 0) {
    return {
      name,
      kind: "baseline-failure",
      control,
      experiment,
      detail: `shared enforce/lockdown control exited ${control.code}: ${
        concise(control.stderr)
      }`,
    };
  }
  if (experiment.code === 0) {
    return {
      name,
      kind: "compatible",
      control,
      experiment,
      detail: control.stdout === experiment.stdout
        ? "same output"
        : "both exited 0; corpus entry assertions passed (stdout is nondeterministic)",
    };
  }
  const match = experiment.stderr.match(
    /Oden compartment: global "([^"]+)" is not endowed/,
  );
  if (match && DERIVED.has(match[1])) {
    return {
      name,
      kind: "derivation-gap",
      control,
      experiment,
      detail: `${match[1]} missing despite the corpus-wide network:* grant`,
    };
  }
  if (match && INTENTIONAL.has(match[1])) {
    return {
      name,
      kind: "legitimate-tradeoff",
      control,
      experiment,
      detail: `${match[1]} is intentionally never-endowed`,
    };
  }
  return {
    name,
    kind: "transform-bug",
    control,
    experiment,
    detail: concise(experiment.stderr),
  };
}

function percent(value: number, total: number): string {
  return total === 0 ? "n/a" : `${((value / total) * 100).toFixed(1)}%`;
}

function render(results: Result[], packages: number): string {
  const counts = new Map<Kind, number>();
  for (const result of results) {
    counts.set(result.kind, (counts.get(result.kind) ?? 0) + 1);
  }
  const eligible = results.length - (counts.get("baseline-failure") ?? 0);
  const transform = counts.get("transform-bug") ?? 0;
  const gaps = counts.get("derivation-gap") ?? 0;
  const out = [
    "# Oden compartment-globals compatibility report (generated)",
    "",
    `Ran ${results.length} entries / ${packages} installed package selectors in two arms. ` +
    `${eligible} entries cleared the shared enforce+lockdown control and are in the compartment denominator.`,
    "",
    "| classification | entries | rate among control-pass entries |",
    "| --- | ---: | ---: |",
    `| compatible | ${counts.get("compatible") ?? 0} | ${
      percent(counts.get("compatible") ?? 0, eligible)
    } |`,
    `| derivation-gap | ${gaps} | ${percent(gaps, eligible)} |`,
    `| transform-bug | ${transform} | ${percent(transform, eligible)} |`,
    `| legitimate-tradeoff | ${counts.get("legitimate-tradeoff") ?? 0} | ${
      percent(counts.get("legitimate-tradeoff") ?? 0, eligible)
    } |`,
    `| baseline-failure (excluded) | ${
      counts.get("baseline-failure") ?? 0
    } | — |`,
    "",
    "## Per-entry result",
    "",
    "| entry | classification | control / experiment | detail |",
    "| --- | --- | --- | --- |",
  ];
  for (const result of results) {
    out.push(
      `| ${result.name} | ${result.kind} | ${result.control.code} / ${result.experiment.code} | ${
        result.detail.replaceAll("|", "\\|")
      } |`,
    );
  }
  out.push(
    "",
    "## Posture",
    "",
    transform > 0
      ? "**NO DEFAULT / TRANSFORM BLOCKED.** At least one control-pass entry has transform-caused behavior change."
      : gaps / Math.max(eligible, 1) > 0.05
      ? "**OPT-IN ONLY.** Derivation gaps exceed LLP 0014's ~5% descope threshold."
      : "**OPT-IN ONLY.** This run found no transform blocker above the stated threshold, but it does not certify the external lockdown prerequisite or a tooling-inclusive default-on corpus.",
    "",
    "A `legitimate-tradeoff` is priced reachability enforcement, not a transform defect. " +
      "A `baseline-failure` is excluded because the shared enforce/lockdown control already failed; it cannot be credited as compartment compatibility.",
    "",
  );
  return out.join("\n");
}

function main() {
  const corpusPath = Deno.args.find((arg) => !arg.startsWith("--"));
  if (!corpusPath) {
    console.error("usage: compartment_compat.ts <corpus.json>");
    Deno.exit(2);
  }
  const corpus = loadCorpus(corpusPath);
  const root = corpusRoot(corpusPath, corpus.root);
  const names = packageNames(root);
  const grants = Object.fromEntries(names.map((name) => [name, BROAD_GRANTS]));
  const policy = Deno.makeTempFileSync({ suffix: ".json" });
  Deno.writeTextFileSync(policy, JSON.stringify({ mode: "enforce", grants }));
  try {
    const results = corpus.entries.map((entry) =>
      classify(
        entry.name,
        run(root, policy, entry, false),
        run(root, policy, entry, true),
      )
    );
    Deno.stdout.writeSync(
      new TextEncoder().encode(render(results, names.length)),
    );
  } finally {
    Deno.removeSync(policy);
  }
}

if (import.meta.main) main();

// Copyright 2018-2026 the Deno authors. MIT license.
//
// Same-build A/B gate for LLP 0014's opt-in compartment-global rewrite.
// Generates a representative 400-module TypeScript graph, interleaves control
// and feature runs, and records cold/warm startup, peak RSS, emitted/cache byte
// size, and warm cache reuse. Exits non-zero when a regression budget is
// exceeded. Run from fork/deno:
//
//   DENO=./target/debug/deno REPS=5 deno run -A tools/oden/bench_compartment_globals.ts
//
// @ref LLP 0013#measurement-protocol
// @ref LLP 0014#at-which-loader-stage

const join = (...parts: string[]) => parts.join("/").replaceAll(/\/{2,}/g, "/");

const deno = Deno.env.get("DENO") ?? "./target/debug/deno";
const reps = Number(Deno.env.get("REPS") ?? "5");
const moduleCount = Number(Deno.env.get("MODULES") ?? "400");

const budget = {
  // Debug-fork calibration (2026-07-10, Apple Silicon, 400 modules) measured
  // 11.3% cold and 17.6% warm overhead at seven interleaved reps. These fail loudly on material drift;
  // release/default-on promotion still requires a release-build recalibration.
  coldStartupRatio: 1.35,
  warmStartupRatio: 1.50,
  peakRssRatio: 1.20,
  emittedBytesRatio: 1.15,
  cacheReuseDrop: 0.05,
} as const;

interface Sample {
  elapsedMs: number;
  peakRssBytes: number;
  emittedBytes: number;
  cacheReuse: number;
}

type Arm = "control" | "compartment";
type Phase = "cold" | "warm";

const root = await Deno.makeTempDir({ prefix: "oden-compartment-perf-" });
const graph = join(root, "graph");
const pkg = join(graph, "node_modules", "perfgraph");
const policy = join(root, "policy.json");

async function scaffold(): Promise<void> {
  await Deno.mkdir(pkg, { recursive: true });
  await Deno.writeTextFile(
    join(pkg, "package.json"),
    JSON.stringify({ name: "perfgraph", version: "1.0.0", type: "module" }),
  );
  for (let i = moduleCount - 1; i >= 0; i--) {
    const next = i + 1 < moduleCount
      ? `import { value as next } from "./m${i + 1}.ts";\n`
      : "const next = 0;\n";
    // Ten percent of modules are true rewrite candidates; the other ninety
    // percent exercise the sound no-candidate fast path.
    const candidate = i % 10 === 0
      ? "export const authority = () => fetch;\n"
      : "export const authority = () => next;\n";
    await Deno.writeTextFile(
      join(pkg, `m${i}.ts`),
      `${next}${candidate}export const value: number = next + 1;\n`,
    );
  }
  await Deno.writeTextFile(
    join(pkg, "index.ts"),
    'export { value } from "./m0.ts";\n',
  );
  await Deno.writeTextFile(
    join(graph, "app.ts"),
    'import { value } from "./node_modules/perfgraph/index.ts";\nconsole.log(value);\n',
  );
  await Deno.writeTextFile(
    policy,
    JSON.stringify({ mode: "enforce", grants: {} }),
  );
}

async function files(
  dir: string,
): Promise<Map<string, { size: number; mtime: number }>> {
  const out = new Map<string, { size: number; mtime: number }>();
  try {
    for await (const entry of Deno.readDir(dir)) {
      const path = join(dir, entry.name);
      if (entry.isDirectory) {
        for (const [child, stat] of await files(path)) out.set(child, stat);
      } else if (entry.isFile) {
        const stat = await Deno.stat(path);
        out.set(path, { size: stat.size, mtime: stat.mtime?.getTime() ?? 0 });
      }
    }
  } catch (error) {
    if (!(error instanceof Deno.errors.NotFound)) throw error;
  }
  return out;
}

function rss(stderr: string): number {
  const mac = stderr.match(/(\d+)\s+maximum resident set size/);
  if (mac) return Number(mac[1]);
  const linux = stderr.match(/Maximum resident set size \(kbytes\):\s*(\d+)/);
  return linux ? Number(linux[1]) * 1024 : 0;
}

async function invoke(
  arm: Arm,
  denoDir: string,
): Promise<{ elapsedMs: number; peakRssBytes: number }> {
  const env: Record<string, string> = {
    DENO_DIR: denoDir,
    ODEN_CAPSEC_POLICY: policy,
    ODEN_CAPSEC_ROOT: graph,
    ODEN_CAPSEC_ALLOW_ADVISORY: "1",
  };
  if (arm === "compartment") env.ODEN_CAPSEC_COMPARTMENT_GLOBALS = "1";
  const timeArgs = Deno.build.os === "darwin" ? ["-l"] : ["-v"];
  const start = performance.now();
  const result = await new Deno.Command("/usr/bin/time", {
    args: [...timeArgs, deno, "run", "--allow-all", join(graph, "app.ts")],
    env,
    stdout: "null",
    stderr: "piped",
  }).output();
  const elapsedMs = performance.now() - start;
  const stderr = new TextDecoder().decode(result.stderr);
  if (!result.success) {
    throw new Error(`benchmark child failed (${result.code}):\n${stderr}`);
  }
  return { elapsedMs, peakRssBytes: rss(stderr) };
}

async function sample(arm: Arm, phase: Phase, rep: number): Promise<Sample> {
  const denoDir = join(root, `cache-${arm}-${phase}-${rep}`);
  if (phase === "warm") await invoke(arm, denoDir);
  const before = await files(denoDir);
  const measured = await invoke(arm, denoDir);
  const after = await files(denoDir);
  let unchanged = 0;
  for (const [path, stat] of before) {
    const next = after.get(path);
    if (next && next.size === stat.size && next.mtime === stat.mtime) {
      unchanged++;
    }
  }
  return {
    ...measured,
    emittedBytes: [...after.values()].reduce((sum, stat) => sum + stat.size, 0),
    cacheReuse: before.size === 0 ? 0 : unchanged / before.size,
  };
}

function median(values: number[]): number {
  const sorted = values.toSorted((a, b) => a - b);
  return sorted[Math.floor(sorted.length / 2)];
}

await scaffold();
const results: Record<Arm, Record<Phase, Sample[]>> = {
  control: { cold: [], warm: [] },
  compartment: { cold: [], warm: [] },
};

try {
  for (const phase of ["cold", "warm"] as const) {
    for (let rep = 0; rep < reps; rep++) {
      // Alternate first arm so thermal/order effects are symmetric.
      const arms: Arm[] = rep % 2 === 0
        ? ["control", "compartment"]
        : ["compartment", "control"];
      for (const arm of arms) {
        results[arm][phase].push(await sample(arm, phase, rep));
      }
    }
  }

  const metric = (arm: Arm, phase: Phase, key: keyof Sample) =>
    median(results[arm][phase].map((sample) => sample[key]));
  const ratio = (feature: number, control: number) => feature / control;
  const coldRatio = ratio(
    metric("compartment", "cold", "elapsedMs"),
    metric("control", "cold", "elapsedMs"),
  );
  const warmRatio = ratio(
    metric("compartment", "warm", "elapsedMs"),
    metric("control", "warm", "elapsedMs"),
  );
  const rssRatio = ratio(
    metric("compartment", "warm", "peakRssBytes"),
    metric("control", "warm", "peakRssBytes"),
  );
  const bytesRatio = ratio(
    metric("compartment", "warm", "emittedBytes"),
    metric("control", "warm", "emittedBytes"),
  );
  const reuseDrop = metric("control", "warm", "cacheReuse") -
    metric("compartment", "warm", "cacheReuse");

  console.log(
    `# compartment globals A/B: modules=${moduleCount} reps=${reps} binary=${deno}`,
  );
  for (const phase of ["cold", "warm"] as const) {
    for (const arm of ["control", "compartment"] as const) {
      console.log(JSON.stringify({
        arm,
        phase,
        startup_ms: metric(arm, phase, "elapsedMs"),
        peak_rss_bytes: metric(arm, phase, "peakRssBytes"),
        emitted_bytes: metric(arm, phase, "emittedBytes"),
        cache_reuse: metric(arm, phase, "cacheReuse"),
      }));
    }
  }

  const failures = [
    ["cold startup", coldRatio, budget.coldStartupRatio],
    ["warm startup", warmRatio, budget.warmStartupRatio],
    ["peak RSS", rssRatio, budget.peakRssRatio],
    ["emitted bytes", bytesRatio, budget.emittedBytesRatio],
  ].filter(([, actual, limit]) => Number(actual) > Number(limit));
  if (reuseDrop > budget.cacheReuseDrop) {
    failures.push(["cache reuse drop", reuseDrop, budget.cacheReuseDrop]);
  }
  if (failures.length) {
    throw new Error(
      `compartment performance budget exceeded:\n${
        failures.map(([name, actual, limit]) =>
          `  ${name}: ${Number(actual).toFixed(3)} > ${
            Number(limit).toFixed(3)
          }`
        ).join("\n")
      }`,
    );
  }
  console.log("PASS: compartment performance budgets satisfied");
} finally {
  await Deno.remove(root, { recursive: true }).catch(() => {});
}

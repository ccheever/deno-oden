// Copyright 2018-2026 the Deno authors. MIT license.
//
// Oden per-op throughput workloads (LLP 0001 Phase 1). Each workload is a
// tight loop over one op shape, so armed-vs-inert and fork-vs-upstream deltas
// price the mediation path (raw-frame capture, CPED stamp/read, decide()) at
// the op level rather than at startup. Driven by bench_throughput.sh; runs on
// upstream deno too (no Oden APIs used).
//
//   deno run --allow-env --allow-read bench_throughput_workloads.js <workload> <iters>
//
// Prints one line: <workload> ns_per_op=<n> total_ms=<n> iters=<n>
// @ref llp/0001-adding-capability-security-to-deno.plan.md

const workload = Deno.args[0];
const iters = Number(Deno.args[1] ?? 0);
const benchFile = Deno.env.get("ODEN_BENCH_FILE") ?? "";

// Gated ops (carry #[op2(stack_trace)], check permissions):
//   env_get     op_get_env            fast path + capture
//   lstat       op_fs_lstat_sync      slow path + capture
//   read_small  op_fs_read_file_text_sync
//   read_async  op_fs_read_file_text_async (async dispatch)
// Non-gated controls (no stack_trace annotation, no permission check):
//   url_parse   op_url_parse
//   now         Date.now (op_now-ish hot path)
const workloads = {
  env_get: (n) => {
    let sink = 0;
    for (let i = 0; i < n; i++) sink += Deno.env.get("PATH").length;
    return sink;
  },
  lstat: (n) => {
    let sink = 0;
    for (let i = 0; i < n; i++) sink += Deno.lstatSync(benchFile).size;
    return sink;
  },
  read_small: (n) => {
    let sink = 0;
    for (let i = 0; i < n; i++) {
      sink += Deno.readTextFileSync(benchFile).length;
    }
    return sink;
  },
  read_async: async (n) => {
    let sink = 0;
    for (let i = 0; i < n; i++) sink += (await Deno.readTextFile(benchFile)).length;
    return sink;
  },
  url_parse: (n) => {
    let sink = 0;
    for (let i = 0; i < n; i++) {
      sink += new URL("https://example.com/a/b?c=d#e").pathname.length;
    }
    return sink;
  },
  now: (n) => {
    let sink = 0;
    for (let i = 0; i < n; i++) sink += Date.now() % 2;
    return sink;
  },
};

const fn = workloads[workload];
if (!fn || !iters) {
  console.error(`usage: bench_throughput_workloads.js <${Object.keys(workloads).join("|")}> <iters>`);
  Deno.exit(2);
}

// Warmup: enough to tier up, not enough to matter.
await fn(Math.max(1000, Math.floor(iters / 20)));

const start = performance.now();
const sink = await fn(iters);
const totalMs = performance.now() - start;
const nsPerOp = (totalMs * 1e6) / iters;

// sink printed so the loop cannot be dead-code-eliminated.
console.log(
  `${workload} ns_per_op=${nsPerOp.toFixed(1)} total_ms=${totalMs.toFixed(1)} iters=${iters} sink=${sink % 10}`,
);

// Copyright 2018-2026 the Deno authors. MIT license.

interface Finding {
  type: string;
  severity?: string;
  action?: string;
  id?: string;
}

interface ReportRecord {
  name: string;
  version: string;
  status: string;
  provider: string;
  registry: string;
  cached: boolean;
  stale: boolean;
  dependency_path: string[];
  finding?: Finding;
}

interface ScanReport {
  v: number;
  provider: string;
  mode: string;
  total: number;
  shown: number;
  summary: Record<string, number>;
  records: ReportRecord[];
  error?: string;
}

function assert(condition: unknown, message: string): asserts condition {
  if (!condition) {
    throw new Error(message);
  }
}

function assertEquals(actual: unknown, expected: unknown, context: string) {
  const actualJson = JSON.stringify(actual);
  const expectedJson = JSON.stringify(expected);
  assert(
    actualJson === expectedJson,
    `${context}: expected ${expectedJson}, got ${actualJson}`,
  );
}

const [scenario, reportPath, captureId] = Deno.args;
assert(scenario != null, "missing scenario argument");
assert(reportPath != null, "missing report path argument");
assert(captureId != null, "missing capture id argument");

const report: ScanReport = JSON.parse(await Deno.readTextFile(reportPath));
assertEquals(report.v, 1, "report version");
assertEquals(report.provider, "socket", "report provider");

function expectRecords(count: number, summary: Record<string, number>) {
  assertEquals(report.total, count, "report total");
  assertEquals(report.shown, count, "report shown");
  assertEquals(report.summary, {
    blocked: 0,
    clean: 0,
    suspicious: 0,
    unscanned_by_policy: 0,
    unsupported_source: 0,
    unverified: 0,
    ...summary,
  }, "report summary");
  assertEquals(report.records.length, count, "report record count");
}

function expectRecord(
  name: string,
  version: string,
  expected: Partial<ReportRecord>,
) {
  const matches = report.records.filter((record) =>
    record.name === name && record.version === version
  );
  assertEquals(matches.length, 1, `record count for ${name}@${version}`);
  const record = matches[0];
  for (const [key, value] of Object.entries(expected)) {
    assertEquals(
      record[key as keyof ReportRecord],
      value,
      `${name}@${version} ${key}`,
    );
  }
  return record;
}

function expectPublicAdd(
  status: string,
  provider: string,
  cached: boolean,
  stale: boolean,
) {
  return expectRecord("@denotest/add", "1.0.0", {
    status,
    provider,
    registry: "http://localhost:4260/",
    cached,
    stale,
    dependency_path: ["@denotest/add@1.0.0"],
  });
}

switch (scenario) {
  case "clean": {
    assertEquals(report.mode, "default", "scan mode");
    expectRecords(1, { clean: 1 });
    // `install` gates the resolved graph more than once. The final report uses
    // the fresh verdict populated by the first gate, while capture below proves
    // that this command did perform the provider lookup.
    const record = expectPublicAdd("clean", "socket", true, false);
    assertEquals(record.finding, undefined, "clean finding");
    assertEquals(report.error, undefined, "clean report error");
    break;
  }
  case "direct_malware": {
    assertEquals(report.mode, "default", "scan mode");
    expectRecords(1, { blocked: 1 });
    const record = expectPublicAdd("blocked", "socket", false, false);
    assertEquals(record.finding?.type, "malware", "malware finding type");
    assertEquals(record.finding?.severity, "critical", "malware severity");
    assertEquals(record.finding?.action, "error", "malware action");
    assertEquals(
      report.error,
      "Socket blocked confirmed malicious npm package @denotest/add@1.0.0 (finding: malware; dependency path: @denotest/add@1.0.0)",
      "direct malware error",
    );
    break;
  }
  case "transitive_malware": {
    assertEquals(report.mode, "default", "scan mode");
    expectRecords(2, { blocked: 1, clean: 1 });
    expectRecord("@denotest/using-vuln", "1.0.0", {
      status: "clean",
      provider: "socket",
      registry: "http://localhost:4260/",
      cached: false,
      stale: false,
      dependency_path: ["@denotest/using-vuln@1.0.0"],
    });
    const blocked = expectRecord("@denotest/with-vuln2", "1.5.0", {
      status: "blocked",
      provider: "socket",
      registry: "http://localhost:4260/",
      cached: false,
      stale: false,
      dependency_path: [
        "@denotest/using-vuln@1.0.0",
        "@denotest/with-vuln2@1.5.0",
      ],
    });
    assertEquals(blocked.finding?.type, "malware", "malware finding type");
    assertEquals(
      report.error,
      "Socket blocked confirmed malicious npm package @denotest/with-vuln2@1.5.0 (finding: malware; dependency path: @denotest/using-vuln@1.0.0 -> @denotest/with-vuln2@1.5.0)",
      "transitive malware error",
    );
    break;
  }
  case "outage_default": {
    assertEquals(report.mode, "default", "scan mode");
    expectRecords(1, { unverified: 1 });
    const record = expectPublicAdd("unverified", "socket", false, false);
    assertEquals(
      record.finding?.type,
      "provider_unavailable",
      "outage finding type",
    );
    assert(
      record.finding?.id?.includes("503") === true,
      `outage finding should name HTTP status 503, got ${record.finding?.id}`,
    );
    assertEquals(report.error, undefined, "fail-open report error");
    break;
  }
  case "outage_strict": {
    assertEquals(report.mode, "strict", "scan mode");
    expectRecords(1, { unverified: 1 });
    const record = expectPublicAdd("unverified", "socket", false, false);
    assertEquals(
      record.finding?.type,
      "provider_unavailable",
      "outage finding type",
    );
    assertEquals(
      report.error,
      "Socket strict scan has no valid verdict for 1 package(s): @denotest/add@1.0.0",
      "strict outage error",
    );
    break;
  }
  case "warm_off": {
    assertEquals(report.mode, "off", "scan mode");
    expectRecords(1, { unscanned_by_policy: 1 });
    expectRecord("@denotest/add", "1.0.0", {
      status: "unscanned_by_policy",
      provider: "policy",
      registry: "http://localhost:4260/",
      cached: true,
      stale: false,
      dependency_path: [],
    });
    assertEquals(report.error, undefined, "off report error");
    break;
  }
  case "warm_default": {
    assertEquals(report.mode, "default", "scan mode");
    expectRecords(1, { clean: 1 });
    expectPublicAdd("clean", "socket", false, false);
    assertEquals(report.error, undefined, "warm cache report error");
    break;
  }
  case "cache_seed": {
    assertEquals(report.mode, "default", "scan mode");
    expectRecords(1, { clean: 1 });
    expectPublicAdd("clean", "socket", true, false);
    assertEquals(report.error, undefined, "seed report error");
    break;
  }
  case "stale_seed": {
    assertEquals(report.mode, "default", "scan mode");
    expectRecords(1, { clean: 1 });
    expectPublicAdd("clean", "socket", true, true);
    assertEquals(report.error, undefined, "seed report error");
    break;
  }
  case "cache_fresh": {
    assertEquals(report.mode, "default", "scan mode");
    expectRecords(1, { clean: 1 });
    expectPublicAdd("clean", "socket", true, false);
    assertEquals(report.error, undefined, "cached report error");
    break;
  }
  case "stale_cached": {
    assertEquals(report.mode, "default", "scan mode");
    expectRecords(1, { clean: 1 });
    expectPublicAdd("clean", "socket", true, true);
    assertEquals(report.error, undefined, "stale report error");
    break;
  }
  case "private_registry": {
    assertEquals(report.mode, "default", "scan mode");
    expectRecords(2, { clean: 1, unsupported_source: 1 });
    expectRecord("chalk", "5.0.1", {
      status: "clean",
      provider: "socket",
      registry: "http://localhost:4260/",
      cached: true,
      stale: false,
      dependency_path: ["chalk@5.0.1"],
    });
    expectRecord("@denotest/basic", "1.0.0", {
      status: "unsupported_source",
      provider: "policy",
      registry: "http://localhost:4261/",
      cached: true,
      stale: false,
      dependency_path: ["@denotest/basic@1.0.0"],
    });
    assertEquals(report.error, undefined, "private registry report error");
    break;
  }
  case "private_registry_from_persisted_tarball": {
    assertEquals(report.mode, "default", "scan mode");
    expectRecords(2, { clean: 1, unsupported_source: 1 });
    expectRecord("chalk", "5.0.1", {
      status: "clean",
      provider: "socket",
      registry: "http://localhost:4260/",
      cached: true,
      stale: false,
      dependency_path: ["chalk@5.0.1"],
    });
    expectRecord("@denotest/basic", "1.0.0", {
      status: "unsupported_source",
      provider: "policy",
      registry: "http://localhost:4261/",
      cached: true,
      stale: false,
      dependency_path: ["@denotest/basic@1.0.0"],
    });
    assertEquals(
      report.error,
      undefined,
      "persisted private registry report error",
    );
    break;
  }
  default:
    throw new Error(`unknown report assertion scenario: ${scenario}`);
}

const expectedCaptures: Record<string, string[]> = {
  clean: ["pkg:npm/@denotest/add@1.0.0"],
  direct_malware: ["pkg:npm/@denotest/add@1.0.0"],
  transitive_malware: [
    "pkg:npm/@denotest/using-vuln@1.0.0",
    "pkg:npm/@denotest/with-vuln2@1.5.0",
  ],
  outage_default: ["pkg:npm/@denotest/add@1.0.0"],
  outage_strict: ["pkg:npm/@denotest/add@1.0.0"],
  warm_off: [],
  warm_default: ["pkg:npm/@denotest/add@1.0.0"],
  cache_seed: ["pkg:npm/@denotest/add@1.0.0"],
  cache_fresh: [],
  stale_seed: ["pkg:npm/@denotest/add@1.0.0"],
  stale_cached: ["pkg:npm/@denotest/add@1.0.0"],
  // The private @denotest/basic identity must never leave the installer.
  private_registry: ["pkg:npm/chalk@5.0.1"],
  // Both verdicts are cached, so a second install should not send either
  // identity after the private registry configuration has been removed.
  private_registry_from_persisted_tarball: [],
};

const captureResponse = await fetch(
  `http://localhost:4268/capture/${captureId}`,
);
assert(
  captureResponse.ok,
  `capture endpoint returned ${captureResponse.status}`,
);
const capture: { purls: string[] } = await captureResponse.json();
assertEquals(capture.purls, expectedCaptures[scenario], "captured PURLs");

console.log(`ok ${scenario}`);

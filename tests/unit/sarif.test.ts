import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { toSarif } from "../../src/scanner/sarif.js";
import type { ScanResult } from "../../src/scanner/types.js";

describe("toSarif (SARIF 2.1.0)", () => {
  test("produces valid SARIF 2.1.0 with rules, security-severity, RSC tags, and lockfile URI", () => {
    const scanResult: ScanResult = {
      scannedAt: "2026-11-28T00:00:00.000Z",
      projectPath: "/repo",
      packageManager: "pnpm",
      clean: false,
      totalsBySeverity: { critical: 0, high: 1, moderate: 1, low: 0, info: 0 },
      findings: [
        {
          packageName: "react-server-dom-webpack",
          installedVersion: "19.1.2",
          severity: "high",
          title: "React Server Components DoS",
          url: "https://github.com/advisories/GHSA-479c-33wc-g2pg",
          cwe: ["CWE-400"],
          cvssScore: 7.5,
          vulnerableRange: ">=19.1.0 <19.1.6",
          fixAvailable: true,
          fixPackage: "react-server-dom-webpack",
          fixedIn: "19.2.8",
          fixIsBreaking: false,
          isRscRelated: true,
        },
        {
          packageName: "postcss",
          installedVersion: "8.4.0",
          severity: "moderate",
          title: "PostCSS parsing issue",
          url: "https://github.com/advisories/GHSA-9999-8888-7777",
          cwe: [],
          cvssScore: null,
          vulnerableRange: "<8.5.0",
          fixAvailable: false,
          fixPackage: null,
          fixedIn: null,
          fixIsBreaking: null,
          isRscRelated: false,
        },
      ],
      rscFindings: [],
    };

    const sarif = toSarif(scanResult, "0.2.0");
    assert.equal(sarif.version, "2.1.0");
    assert.equal(sarif.runs.length, 1);

    const run = sarif.runs[0]!;
    assert.equal(run.tool.driver.name, "rsc-sentinel");
    assert.equal(run.tool.driver.version, "0.2.0");
    assert.equal(run.tool.driver.rules.length, 2);
    assert.equal(run.results.length, 2);

    const rscRule = run.tool.driver.rules[0]!;
    assert.equal(rscRule.id, "react-server-dom-webpack/GHSA-479C-33WC-G2PG");
    assert.equal(rscRule.properties["security-severity"], "7.5");
    assert.ok(rscRule.properties.tags.includes("rsc"));
    assert.ok(rscRule.properties.tags.includes("CWE-400"));

    const rscRes = run.results[0]!;
    assert.equal(rscRes.level, "error");
    assert.equal(
      rscRes.locations[0]?.physicalLocation.artifactLocation.uri,
      "pnpm-lock.yaml",
    );

    const modRes = run.results[1]!;
    assert.equal(modRes.level, "warning");
  });

  test("produces valid empty SARIF 2.1.0 for a clean scan", () => {
    const clean: ScanResult = {
      scannedAt: "2026-11-28T00:00:00.000Z",
      projectPath: "/repo",
      packageManager: "npm",
      clean: true,
      totalsBySeverity: { critical: 0, high: 0, moderate: 0, low: 0, info: 0 },
      findings: [],
      rscFindings: [],
    };
    const sarif = toSarif(clean, "0.2.0");
    assert.equal(sarif.version, "2.1.0");
    assert.deepEqual(sarif.runs[0]?.results, []);
    assert.deepEqual(sarif.runs[0]?.tool.driver.rules, []);
  });
});

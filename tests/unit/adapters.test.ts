import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { detectPackageManager } from "../../src/utils/pm-runner.js";
import {
  normalizePnpmAuditReport,
  normalizeYarnAuditOutput,
} from "../../src/scanner/adapters.js";
import { analyzeAuditReport } from "../../src/scanner/analyze.js";

describe("detectPackageManager", () => {
  test("detects pnpm, yarn, npm, or null from lockfiles", () => {
    const dir = mkdtempSync(join(tmpdir(), "rsc-sentinel-pm-"));
    try {
      assert.equal(detectPackageManager(dir), null);

      writeFileSync(join(dir, "package-lock.json"), "{}");
      assert.equal(detectPackageManager(dir), "npm");

      writeFileSync(join(dir, "yarn.lock"), "");
      assert.equal(detectPackageManager(dir), "yarn");

      writeFileSync(join(dir, "pnpm-lock.yaml"), "");
      assert.equal(detectPackageManager(dir), "pnpm");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });
});

describe("normalizePnpmAuditReport", () => {
  test("converts pnpm advisories map into canonical NpmAuditReport and tags RSC", () => {
    const rawPnpm = {
      advisories: {
        "1116378": {
          id: 1116378,
          module_name: "react-server-dom-webpack",
          title: "React Server Components Denial of Service",
          url: "https://github.com/advisories/GHSA-479c-33wc-g2pg",
          severity: "high",
          cwe: ["CWE-400"],
          cvss: { score: 7.5, vectorString: "CVSS:3.1/..." },
          vulnerable_versions: ">=19.1.0 <19.1.6",
          patched_versions: ">=19.1.6",
        },
      },
    };

    const report = normalizePnpmAuditReport(rawPnpm);
    assert.ok(report);
    const result = analyzeAuditReport(report, process.cwd());
    assert.equal(result.findings.length, 1);
    assert.equal(result.rscFindings.length, 1);
    assert.equal(result.findings[0]?.packageName, "react-server-dom-webpack");
    assert.equal(result.findings[0]?.fixedIn, ">=19.1.6");
    assert.equal(result.findings[0]?.cvssScore, 7.5);
  });

  test("returns null for malformed input", () => {
    assert.equal(normalizePnpmAuditReport(null), null);
    assert.equal(normalizePnpmAuditReport([]), null);
    assert.equal(normalizePnpmAuditReport({ foo: "bar" }), null);
  });
});

describe("normalizeYarnAuditOutput", () => {
  test("parses Yarn Classic v1 NDJSON auditAdvisory lines", () => {
    const ndjson = [
      JSON.stringify({
        type: "auditAdvisory",
        data: {
          advisory: {
            id: 42,
            module_name: "next",
            title: "Server Action CSRF bypass",
            url: "https://github.com/advisories/GHSA-aaaa-bbbb-cccc",
            severity: "critical",
            cwe: "CWE-352",
            vulnerable_versions: "<15.2.0",
            patched_versions: ">=15.2.0",
          },
        },
      }),
      JSON.stringify({ type: "auditSummary", data: { vulnerabilities: { critical: 1 } } }),
    ].join("\n");

    const report = normalizeYarnAuditOutput(ndjson);
    assert.ok(report);
    const result = analyzeAuditReport(report, process.cwd());
    assert.equal(result.findings.length, 1);
    assert.equal(result.rscFindings.length, 1);
    assert.equal(result.findings[0]?.severity, "critical");
    assert.deepEqual(result.findings[0]?.cwe, ["CWE-352"]);
  });

  test("parses Yarn Berry NDJSON item lines", () => {
    const berryNdjson = JSON.stringify({
      value: "react-server-dom-turbopack",
      children: {
        ID: 99,
        Issue: "Flight protocol DoS",
        URL: "https://github.com/advisories/GHSA-1111-2222-3333",
        Severity: "high",
        "Vulnerable Versions": "<19.2.0",
        "Patched Versions": ">=19.2.0",
      },
    });

    const report = normalizeYarnAuditOutput(berryNdjson);
    assert.ok(report);
    const result = analyzeAuditReport(report, process.cwd());
    assert.equal(result.findings.length, 1);
    assert.equal(result.rscFindings.length, 1);
    assert.equal(result.findings[0]?.fixedIn, ">=19.2.0");
  });

  test("returns clean empty report for empty stdout", () => {
    const report = normalizeYarnAuditOutput("   ");
    assert.ok(report);
    assert.deepEqual(report.vulnerabilities, {});
  });
});

import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, mkdirSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { analyzeAuditReport } from "../dist/scanner/analyze.js";
import type { NpmAuditReport } from "../dist/scanner/types.js";

/**
 * Shaped directly off real `npm audit --json` output captured against the
 * live registry (see project notes) — not invented from assumption.
 */
function makeReport(): NpmAuditReport {
  return {
    auditReportVersion: 2,
    vulnerabilities: {
      "react-server-dom-webpack": {
        name: "react-server-dom-webpack",
        severity: "high",
        isDirect: true,
        via: [
          {
            source: 1116378,
            name: "react-server-dom-webpack",
            dependency: "react-server-dom-webpack",
            title: "React Server Components have a Denial of Service Vulnerability",
            url: "https://github.com/advisories/GHSA-479c-33wc-g2pg",
            severity: "high",
            cwe: ["CWE-400", "CWE-502"],
            cvss: { score: 7.5, vectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" },
            range: ">=19.1.0 <19.1.6",
          },
        ],
        effects: [],
        range: "19.1.0 - 19.1.5",
        nodes: ["node_modules/react-server-dom-webpack"],
        fixAvailable: { name: "react-server-dom-webpack", version: "19.2.8", isSemVerMajor: false },
      },
      postcss: {
        name: "postcss",
        severity: "high",
        isDirect: false,
        via: [
          {
            source: 999,
            name: "postcss",
            dependency: "postcss",
            title: "PostCSS: Arbitrary file read via sourceMappingURL",
            url: "https://github.com/advisories/GHSA-6g55-p6wh-862q",
            severity: "high",
            cwe: ["CWE-22"],
            cvss: { score: 7.5, vectorString: "x" },
            range: "<=8.5.11",
          },
          // A string entry: references the parent dependency chain, not an advisory.
          "next",
        ],
        effects: ["next"],
        range: "<=8.5.11",
        nodes: ["node_modules/postcss"],
        fixAvailable: { name: "next", version: "16.3.0", isSemVerMajor: true },
      },
    },
    metadata: {
      vulnerabilities: { info: 0, low: 0, moderate: 0, high: 2, critical: 0, total: 2 },
      dependencies: { prod: 2, dev: 0, optional: 0, peer: 0, peerOptional: 0, total: 2 },
    },
  };
}

function makeFakeProject(): string {
  const dir = mkdtempSync(join(tmpdir(), "rsc-sentinel-test-"));
  mkdirSync(join(dir, "node_modules", "react-server-dom-webpack"), { recursive: true });
  writeFileSync(
    join(dir, "node_modules", "react-server-dom-webpack", "package.json"),
    JSON.stringify({ name: "react-server-dom-webpack", version: "19.1.2" }),
  );
  return dir;
}

test("tags react-server-dom-webpack findings as RSC-related", () => {
  const projectPath = makeFakeProject();
  const result = analyzeAuditReport(makeReport(), projectPath);

  assert.equal(result.findings.length, 2);
  assert.equal(result.rscFindings.length, 1);
  assert.equal(result.rscFindings[0]?.packageName, "react-server-dom-webpack");
  assert.equal(result.rscFindings[0]?.url, "https://github.com/advisories/GHSA-479c-33wc-g2pg");
});

test("resolves the actually-installed version from node_modules, not a declared range", () => {
  const projectPath = makeFakeProject();
  const result = analyzeAuditReport(makeReport(), projectPath);
  const finding = result.rscFindings[0];
  assert.equal(finding?.installedVersion, "19.1.2");
});

test("does not tag postcss (a non-RSC package) as RSC-related", () => {
  const projectPath = makeFakeProject();
  const result = analyzeAuditReport(makeReport(), projectPath);
  const postcssFinding = result.findings.find((f) => f.packageName === "postcss");
  assert.equal(postcssFinding?.isRscRelated, false);
});

test("skips string entries in `via` instead of crashing on them", () => {
  const projectPath = makeFakeProject();
  // The postcss vulnerability's `via` array includes a plain string ("next") —
  // this must not produce a bogus finding or throw.
  const result = analyzeAuditReport(makeReport(), projectPath);
  const namesOnly = result.findings.map((f) => f.title);
  assert.ok(!namesOnly.includes("next"));
});

test("reports fixIsBreaking correctly for semver-major vs non-major fixes", () => {
  const projectPath = makeFakeProject();
  const result = analyzeAuditReport(makeReport(), projectPath);
  const rscFix = result.findings.find((f) => f.packageName === "react-server-dom-webpack");
  const postcssFix = result.findings.find((f) => f.packageName === "postcss");
  assert.equal(rscFix?.fixIsBreaking, false);
  assert.equal(postcssFix?.fixIsBreaking, true);
});

test("clean is false when findings exist, totalsBySeverity sums correctly", () => {
  const projectPath = makeFakeProject();
  const result = analyzeAuditReport(makeReport(), projectPath);
  assert.equal(result.clean, false);
  assert.equal(result.totalsBySeverity.high, 2);
  assert.equal(result.totalsBySeverity.critical, 0);
});

test("clean is true and findings empty for a report with no vulnerabilities", () => {
  const projectPath = makeFakeProject();
  const emptyReport: NpmAuditReport = {
    auditReportVersion: 2,
    vulnerabilities: {},
    metadata: {
      vulnerabilities: { info: 0, low: 0, moderate: 0, high: 0, critical: 0, total: 0 },
      dependencies: { prod: 0, dev: 0, optional: 0, peer: 0, peerOptional: 0, total: 0 },
    },
  };
  const result = analyzeAuditReport(emptyReport, projectPath);
  assert.equal(result.clean, true);
  assert.deepEqual(result.findings, []);
});

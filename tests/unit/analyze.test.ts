import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync, mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  analyzeAuditReport,
  filterScanResult,
  isRscRelated,
} from "../../src/scanner/analyze.js";
import type { NpmAuditReport } from "../../src/scanner/types.js";

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
            cvss: {
              score: 7.5,
              vectorString: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
            },
            range: ">=19.1.0 <19.1.6",
          },
          // Duplicate advisory URL must be deduplicated
          {
            source: 1116378,
            name: "react-server-dom-webpack",
            dependency: "react-server-dom-webpack",
            title: "React Server Components have a Denial of Service Vulnerability",
            url: "https://github.com/advisories/GHSA-479c-33wc-g2pg",
            severity: "high",
            cwe: ["CWE-400", "CWE-502"],
            cvss: { score: 7.5, vectorString: "x" },
            range: ">=19.1.0 <19.1.6",
          },
        ],
        effects: [],
        range: "19.1.0 - 19.1.5",
        nodes: ["node_modules/react-server-dom-webpack"],
        fixAvailable: {
          name: "react-server-dom-webpack",
          version: "19.2.8",
          isSemVerMajor: false,
        },
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
          "next",
        ],
        effects: ["next"],
        range: "<=8.5.11",
        nodes: ["node_modules/postcss"],
        fixAvailable: { name: "next", version: "16.3.0", isSemVerMajor: true },
      },
      "minor-pkg": {
        name: "minor-pkg",
        severity: "moderate",
        isDirect: true,
        via: [
          {
            source: 123,
            name: "minor-pkg",
            dependency: "minor-pkg",
            title: "Moderate issue with boolean fixAvailable",
            url: "https://github.com/advisories/GHSA-0000-0000-0001",
            severity: "moderate",
            cwe: [],
            range: "<1.2.0",
          },
        ],
        effects: [],
        range: "<1.2.0",
        nodes: ["node_modules/minor-pkg"],
        fixAvailable: true,
      },
    },
  };
}

function makeFakeProject(): string {
  const dir = mkdtempSync(join(tmpdir(), "rsc-sentinel-analyze-"));
  mkdirSync(join(dir, "node_modules", "react-server-dom-webpack"), {
    recursive: true,
  });
  writeFileSync(
    join(dir, "node_modules", "react-server-dom-webpack", "package.json"),
    JSON.stringify({ name: "react-server-dom-webpack", version: "19.1.2" }),
  );
  return dir;
}

describe("analyzeAuditReport", () => {
  test("tags RSC packages and deduplicates identical advisory URLs", () => {
    const projectPath = makeFakeProject();
    try {
      const result = analyzeAuditReport(makeReport(), projectPath);
      assert.equal(result.findings.length, 3);
      assert.equal(result.rscFindings.length, 1);
      assert.equal(result.rscFindings[0]?.packageName, "react-server-dom-webpack");
      assert.equal(result.rscFindings[0]?.installedVersion, "19.1.2");
    } finally {
      rmSync(projectPath, { recursive: true, force: true });
    }
  });

  test("preserves fixPackage for transitive fixes and handles boolean fixAvailable=true", () => {
    const projectPath = makeFakeProject();
    try {
      const result = analyzeAuditReport(makeReport(), projectPath);

      const postcss = result.findings.find((f) => f.packageName === "postcss");
      assert.equal(postcss?.fixAvailable, true);
      assert.equal(postcss?.fixPackage, "next");
      assert.equal(postcss?.fixedIn, "16.3.0");
      assert.equal(postcss?.fixIsBreaking, true);

      const minor = result.findings.find((f) => f.packageName === "minor-pkg");
      assert.equal(minor?.fixAvailable, true);
      assert.equal(minor?.fixPackage, null);
      assert.equal(minor?.fixedIn, null);
      assert.equal(minor?.fixIsBreaking, false);
    } finally {
      rmSync(projectPath, { recursive: true, force: true });
    }
  });

  test("sorts deterministically: severity desc, RSC first, CVSS desc, package asc", () => {
    const projectPath = makeFakeProject();
    try {
      const result = analyzeAuditReport(makeReport(), projectPath);
      // Both react-server-dom-webpack and postcss are high (CVSS 7.5),
      // so RSC finding MUST sort first, followed by postcss, then moderate minor-pkg.
      assert.deepEqual(
        result.findings.map((f) => f.packageName),
        ["react-server-dom-webpack", "postcss", "minor-pkg"],
      );
    } finally {
      rmSync(projectPath, { recursive: true, force: true });
    }
  });

  test("clean is true when vulnerabilities object is empty", () => {
    const projectPath = makeFakeProject();
    try {
      const result = analyzeAuditReport({ vulnerabilities: {} }, projectPath);
      assert.equal(result.clean, true);
      assert.deepEqual(result.findings, []);
      assert.equal(result.totalsBySeverity.high, 0);
    } finally {
      rmSync(projectPath, { recursive: true, force: true });
    }
  });

  test("isRscRelated matches react-server-dom-* packages and Flight/RSC titles", () => {
    assert.equal(isRscRelated("react-server-dom-esm", "Generic DoS"), true);
    assert.equal(isRscRelated("react-server-dom-custom", "Generic DoS"), true);
    assert.equal(isRscRelated("next", "Server Action CSRF bypass"), true);
    assert.equal(isRscRelated("next", "Flight payload recursion"), true);
    assert.equal(isRscRelated("postcss", "Arbitrary file read"), false);
  });

  test("filterScanResult filters by rscOnly and minSeverity and recomputes totals", () => {
    const projectPath = makeFakeProject();
    try {
      const full = analyzeAuditReport(makeReport(), projectPath);

      const rscOnly = filterScanResult(full, { rscOnly: true });
      assert.equal(rscOnly.findings.length, 1);
      assert.equal(rscOnly.totalsBySeverity.high, 1);
      assert.equal(rscOnly.totalsBySeverity.moderate, 0);

      const criticalOnly = filterScanResult(full, { minSeverity: "critical" });
      assert.equal(criticalOnly.clean, true);
      assert.equal(criticalOnly.findings.length, 0);
    } finally {
      rmSync(projectPath, { recursive: true, force: true });
    }
  });
});

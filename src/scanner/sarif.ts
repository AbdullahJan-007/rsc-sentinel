import type { Finding, ScanResult, Severity } from "./types.js";

export type SarifLevel = "error" | "warning" | "note";

export interface SarifRule {
  id: string;
  name: string;
  shortDescription: { text: string };
  fullDescription: { text: string };
  helpUri?: string;
  properties: {
    tags: string[];
    "security-severity"?: string;
  };
}

export interface SarifResult {
  ruleId: string;
  level: SarifLevel;
  message: { text: string };
  locations: Array<{
    physicalLocation: {
      artifactLocation: { uri: string };
    };
  }>;
  properties: {
    packageName: string;
    installedVersion: string | null;
    severity: Severity;
    isRscRelated: boolean;
    vulnerableRange: string;
    fixAvailable: boolean;
    fixPackage: string | null;
    fixedIn: string | null;
    fixIsBreaking: boolean | null;
    cvssScore: number | null;
    cwe: string[];
  };
}

export interface SarifLog {
  $schema: string;
  version: "2.1.0";
  runs: Array<{
    tool: {
      driver: {
        name: string;
        version: string;
        informationUri: string;
        rules: SarifRule[];
      };
    };
    results: SarifResult[];
  }>;
}

const SARIF_SCHEMA =
  "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json";

function severityToSarifLevel(severity: Severity): SarifLevel {
  if (severity === "critical" || severity === "high") return "error";
  if (severity === "moderate") return "warning";
  return "note";
}

function severityToDefaultScore(severity: Severity): string {
  switch (severity) {
    case "critical":
      return "9.5";
    case "high":
      return "7.5";
    case "moderate":
      return "5.3";
    case "low":
      return "3.1";
    case "info":
      return "1.0";
  }
}

function ruleIdForFinding(f: Finding): string {
  const ghsaMatch = f.url.match(/GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}/i);
  if (ghsaMatch) {
    return `${f.packageName}/${ghsaMatch[0].toUpperCase()}`;
  }
  const cveMatch = f.title.match(/CVE-\d{4}-\d{4,}/i);
  if (cveMatch) {
    return `${f.packageName}/${cveMatch[0].toUpperCase()}`;
  }
  const slug = f.title
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "")
    .slice(0, 48);
  return `${f.packageName}/${slug || "advisory"}`;
}

function artifactUriForPm(pm?: "npm" | "pnpm" | "yarn"): string {
  if (pm === "pnpm") return "pnpm-lock.yaml";
  if (pm === "yarn") return "yarn.lock";
  return "package-lock.json";
}

/**
 * Converts a `ScanResult` into a spec-compliant SARIF 2.1.0 document suitable
 * for GitHub Code Scanning (`github/codeql-action/upload-sarif@v3`).
 */
export function toSarif(
  result: ScanResult,
  toolVersion = "0.2.0",
): SarifLog {
  const rulesById = new Map<string, SarifRule>();
  const results: SarifResult[] = [];
  const artifactUri = artifactUriForPm(result.packageManager);

  for (const f of result.findings) {
    const ruleId = ruleIdForFinding(f);

    if (!rulesById.has(ruleId)) {
      const tags = ["security", "dependency"];
      if (f.isRscRelated) tags.push("rsc", "react-server-components");
      for (const cwe of f.cwe) tags.push(cwe);

      const rule: SarifRule = {
        id: ruleId,
        name: f.title,
        shortDescription: { text: `${f.packageName}: ${f.title}` },
        fullDescription: {
          text:
            `${f.title}. Package: ${f.packageName}` +
            (f.installedVersion ? `@${f.installedVersion}` : "") +
            `. Vulnerable range: ${f.vulnerableRange}.`,
        },
        properties: {
          tags,
          "security-severity":
            f.cvssScore !== null
              ? f.cvssScore.toFixed(1)
              : severityToDefaultScore(f.severity),
        },
      };
      if (f.url) {
        rule.helpUri = f.url;
      }
      rulesById.set(ruleId, rule);
    }

    const fixSummary =
      f.fixPackage && f.fixedIn
        ? `Upgrade ${f.fixPackage} to ${f.fixedIn}${f.fixIsBreaking ? " (semver-major)" : ""}.`
        : f.fixedIn
          ? `Upgrade to ${f.fixedIn}${f.fixIsBreaking ? " (semver-major)" : ""}.`
          : f.fixAvailable
            ? "Fix available via package manager audit fix."
            : "No fix published yet.";

    results.push({
      ruleId,
      level: severityToSarifLevel(f.severity),
      message: {
        text:
          `[${f.severity.toUpperCase()}]${f.isRscRelated ? " [RSC]" : ""} ` +
          `${f.packageName}${f.installedVersion ? `@${f.installedVersion}` : ""}: ` +
          `${f.title} (vulnerable: ${f.vulnerableRange}). ${fixSummary}`,
      },
      locations: [
        {
          physicalLocation: {
            artifactLocation: { uri: artifactUri },
          },
        },
      ],
      properties: {
        packageName: f.packageName,
        installedVersion: f.installedVersion,
        severity: f.severity,
        isRscRelated: f.isRscRelated,
        vulnerableRange: f.vulnerableRange,
        fixAvailable: f.fixAvailable,
        fixPackage: f.fixPackage,
        fixedIn: f.fixedIn,
        fixIsBreaking: f.fixIsBreaking,
        cvssScore: f.cvssScore,
        cwe: f.cwe,
      },
    });
  }

  return {
    $schema: SARIF_SCHEMA,
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "rsc-sentinel",
            version: toolVersion,
            informationUri: "https://github.com/AbdullahJan-007/rsc-sentinel",
            rules: [...rulesById.values()],
          },
        },
        results,
      },
    ],
  };
}

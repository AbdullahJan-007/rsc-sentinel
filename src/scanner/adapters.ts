/**
 * Adapters that normalize `pnpm audit --json` and `yarn audit --json` /
 * `yarn npm audit --json` outputs into the canonical `NpmAuditReport` shape
 * consumed by `analyzeAuditReport`.
 */

import {
  isSeverity,
  type NpmAuditAdvisory,
  type NpmAuditReport,
  type NpmAuditVulnerability,
  type Severity,
} from "./types.js";

interface LegacyAdvisoryObject {
  id?: number;
  module_name?: string;
  title?: string;
  url?: string;
  severity?: string;
  cwe?: string | string[];
  cvss?: {
    score?: number;
    vectorString?: string;
  };
  vulnerable_versions?: string;
  patched_versions?: string;
  findings?: Array<{ version?: string; paths?: string[] }>;
}

function normalizeSeverity(raw: unknown): Severity {
  if (typeof raw === "string" && isSeverity(raw.toLowerCase())) {
    return raw.toLowerCase() as Severity;
  }
  return "info";
}

function normalizeCwe(raw: unknown): string[] {
  if (Array.isArray(raw)) {
    return raw.filter((c): c is string => typeof c === "string");
  }
  if (typeof raw === "string" && raw.length > 0) {
    return [raw];
  }
  return [];
}

function addAdvisoryToMap(
  vulns: Record<string, NpmAuditVulnerability>,
  adv: LegacyAdvisoryObject,
): void {
  const pkg = typeof adv.module_name === "string" ? adv.module_name : "";
  if (!pkg) return;

  const severity = normalizeSeverity(adv.severity);
  const advisory: NpmAuditAdvisory = {
    source: typeof adv.id === "number" ? adv.id : 0,
    name: pkg,
    dependency: pkg,
    title: typeof adv.title === "string" ? adv.title : "Untitled advisory",
    url: typeof adv.url === "string" ? adv.url : "",
    severity,
    cwe: normalizeCwe(adv.cwe),
    range:
      typeof adv.vulnerable_versions === "string"
        ? adv.vulnerable_versions
        : "*",
  };
  if (
    adv.cvss &&
    typeof adv.cvss.score === "number" &&
    Number.isFinite(adv.cvss.score)
  ) {
    advisory.cvss = {
      score: adv.cvss.score,
      vectorString:
        typeof adv.cvss.vectorString === "string" ? adv.cvss.vectorString : "",
    };
  }

  const patched =
    typeof adv.patched_versions === "string" ? adv.patched_versions.trim() : "";
  const hasFix = patched.length > 0 && patched !== "<0.0.0";

  const existing = vulns[pkg];
  if (existing) {
    existing.via.push(advisory);
    if (!existing.fixAvailable && hasFix) {
      existing.fixAvailable = {
        name: pkg,
        version: patched,
        isSemVerMajor: false,
      };
    }
    return;
  }

  vulns[pkg] = {
    name: pkg,
    severity,
    isDirect: true,
    via: [advisory],
    effects: [],
    range: advisory.range,
    nodes: [`node_modules/${pkg}`],
    fixAvailable: hasFix
      ? { name: pkg, version: patched, isSemVerMajor: false }
      : false,
  };
}

/**
 * Parses `pnpm audit --json` output into a canonical `NpmAuditReport`.
 * `pnpm audit --json` emits `{ advisories: Record<string, LegacyAdvisoryObject>, metadata: ... }`.
 */
export function normalizePnpmAuditReport(parsed: unknown): NpmAuditReport | null {
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    return null;
  }

  // Some newer pnpm versions may emit npm v2 `vulnerabilities` directly.
  if (
    "vulnerabilities" in parsed &&
    parsed.vulnerabilities &&
    typeof parsed.vulnerabilities === "object" &&
    !Array.isArray(parsed.vulnerabilities)
  ) {
    return parsed as NpmAuditReport;
  }

  if (!("advisories" in parsed)) {
    return null;
  }
  const advisories = (parsed as { advisories: unknown }).advisories;
  if (!advisories || typeof advisories !== "object" || Array.isArray(advisories)) {
    return null;
  }

  const vulns: Record<string, NpmAuditVulnerability> = {};
  for (const entry of Object.values(advisories as Record<string, unknown>)) {
    if (entry && typeof entry === "object" && !Array.isArray(entry)) {
      addAdvisoryToMap(vulns, entry as LegacyAdvisoryObject);
    }
  }

  return {
    auditReportVersion: 2,
    vulnerabilities: vulns,
  };
}

/**
 * Parses Yarn audit output into a canonical `NpmAuditReport`.
 * Supports BOTH:
 * - Yarn Classic (v1) `yarn audit --json` (NDJSON lines with `{ type: "auditAdvisory", data: { advisory } }`)
 * - Yarn Berry (v2/v3/v4) `yarn npm audit --json` (single JSON `{ advisories: { ... } }` or NDJSON lines)
 */
export function normalizeYarnAuditOutput(stdout: string): NpmAuditReport | null {
  const trimmed = stdout.trim();
  if (!trimmed) {
    return { auditReportVersion: 2, vulnerabilities: {} };
  }

  // First try single JSON document (Yarn Berry `yarn npm audit --json` without --all or standard format)
  try {
    const single = JSON.parse(trimmed) as unknown;
    const asPnpmShape = normalizePnpmAuditReport(single);
    if (asPnpmShape) return asPnpmShape;
  } catch {
    // Fall through to NDJSON parsing (Yarn Classic v1 & Yarn Berry streaming lines)
  }

  const vulns: Record<string, NpmAuditVulnerability> = {};
  let parsedAnyValidLine = false;

  for (const rawLine of trimmed.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line) continue;
    let obj: unknown;
    try {
      obj = JSON.parse(line);
    } catch {
      continue;
    }
    if (!obj || typeof obj !== "object" || Array.isArray(obj)) continue;
    parsedAnyValidLine = true;

    const record = obj as {
      type?: unknown;
      data?: { advisory?: unknown };
      children?: unknown;
      value?: unknown;
    };

    // Yarn Classic v1 NDJSON format
    if (
      record.type === "auditAdvisory" &&
      record.data &&
      typeof record.data === "object" &&
      record.data.advisory &&
      typeof record.data.advisory === "object"
    ) {
      addAdvisoryToMap(vulns, record.data.advisory as LegacyAdvisoryObject);
      continue;
    }

    // Yarn Berry `yarn npm audit --json` NDJSON item format:
    // { value: "pkg", children: { ID: 123, Issue: "...", URL: "...", Severity: "...", ... } }
    if (
      typeof record.value === "string" &&
      record.children &&
      typeof record.children === "object" &&
      !Array.isArray(record.children)
    ) {
      const c = record.children as Record<string, unknown>;
      if (typeof c.Issue === "string" || typeof c.URL === "string") {
        addAdvisoryToMap(vulns, {
          id: typeof c.ID === "number" ? c.ID : 0,
          module_name: record.value,
          title: typeof c.Issue === "string" ? c.Issue : "Untitled advisory",
          url: typeof c.URL === "string" ? c.URL : "",
          severity: typeof c.Severity === "string" ? c.Severity : "info",
          vulnerable_versions:
            typeof c["Vulnerable Versions"] === "string"
              ? c["Vulnerable Versions"]
              : "*",
          patched_versions:
            typeof c["Patched Versions"] === "string"
              ? c["Patched Versions"]
              : "",
        });
      }
    }
  }

  return parsedAnyValidLine
    ? { auditReportVersion: 2, vulnerabilities: vulns }
    : null;
}

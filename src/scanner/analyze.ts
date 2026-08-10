import type {
  Finding,
  NpmAuditAdvisory,
  NpmAuditReport,
  ScanResult,
  Severity,
} from "./types.js";
import { getInstalledVersion } from "../utils/installed-version.js";

const SEVERITY_ORDER: Record<Severity, number> = {
  critical: 4,
  high: 3,
  moderate: 2,
  low: 1,
  info: 0,
};

/**
 * Packages that ARE React Server Components / Flight-protocol internals.
 * A finding against one of these is always RSC-related regardless of what
 * the advisory title says.
 */
const RSC_PACKAGE_PREFIXES = [
  "react-server-dom-webpack",
  "react-server-dom-turbopack",
  "react-server-dom-parcel",
];

/**
 * For packages like `next` that aren't RSC-only, fall back to matching the
 * advisory title against known vocabulary. This is inherently fuzzy — it's
 * a triage hint for the report, not a security boundary.
 */
const RSC_TITLE_PATTERN =
  /server component|server action|flight protocol|rsc\b/i;

function isRscRelated(packageName: string, title: string): boolean {
  if (RSC_PACKAGE_PREFIXES.some((p) => packageName === p)) return true;
  return RSC_TITLE_PATTERN.test(title);
}

function toFinding(
  packageName: string,
  advisory: NpmAuditAdvisory,
  fixedIn: string | null,
  fixIsBreaking: boolean | null,
  installedVersion: string | null,
): Finding {
  return {
    packageName,
    installedVersion,
    severity: advisory.severity,
    title: advisory.title,
    url: advisory.url,
    cwe: advisory.cwe ?? [],
    cvssScore: advisory.cvss?.score ?? null,
    vulnerableRange: advisory.range,
    fixedIn,
    fixIsBreaking,
    isRscRelated: isRscRelated(packageName, advisory.title),
  };
}

/**
 * Normalizes a raw npm audit report into de-duplicated, RSC-tagged findings,
 * and resolves the actually-installed version for each affected package.
 */
export function analyzeAuditReport(
  report: NpmAuditReport,
  projectPath: string,
): ScanResult {
  const findings: Finding[] = [];
  const seenUrls = new Set<string>();

  for (const [packageName, vuln] of Object.entries(report.vulnerabilities)) {
    const fix = vuln.fixAvailable;
    const fixedIn = typeof fix === "object" ? fix.version : null;
    const fixIsBreaking = typeof fix === "object" ? fix.isSemVerMajor : null;
    const installedVersion = getInstalledVersion(projectPath, packageName);

    for (const entry of vuln.via) {
      // String entries reference a dependency name this vulnerability is
      // inherited *through*, not an advisory in its own right — that
      // dependency gets its own entry in report.vulnerabilities, where
      // we'll pick up its actual advisory objects.
      if (typeof entry === "string") continue;

      // The same advisory can appear more than once for a package (e.g.
      // once per range npm split it into) — dedupe by advisory URL.
      const dedupeKey = `${packageName}::${entry.url}`;
      if (seenUrls.has(dedupeKey)) continue;
      seenUrls.add(dedupeKey);

      findings.push(
        toFinding(packageName, entry, fixedIn, fixIsBreaking, installedVersion),
      );
    }
  }

  findings.sort((a, b) => SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity]);

  const totalsBySeverity: Record<Severity, number> = {
    critical: 0,
    high: 0,
    moderate: 0,
    low: 0,
    info: 0,
  };
  for (const f of findings) totalsBySeverity[f.severity]++;

  return {
    scannedAt: new Date().toISOString(),
    projectPath,
    findings,
    rscFindings: findings.filter((f) => f.isRscRelated),
    totalsBySeverity,
    clean: findings.length === 0,
  };
}

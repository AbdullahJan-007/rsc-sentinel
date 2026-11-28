import {
  SEVERITY_ORDER,
  isSeverity,
  type Finding,
  type NpmAuditAdvisory,
  type NpmAuditFixAvailable,
  type NpmAuditReport,
  type ScanResult,
  type Severity,
} from "./types.js";
import { getInstalledVersion } from "../utils/installed-version.js";

/**
 * Packages that ARE React Server Components / Flight-protocol internals.
 * A finding against any of these is always RSC-related regardless of title.
 */
const RSC_PACKAGE_EXACT = new Set([
  "react-server-dom-webpack",
  "react-server-dom-turbopack",
  "react-server-dom-parcel",
  "react-server-dom-esm",
]);

/**
 * For broader packages (such as `next` or `react`), match the advisory title
 * against RSC / Flight-protocol / App Router vocabulary.
 */
const RSC_TITLE_PATTERN =
  /server component|server action|flight protocol|flight payload|\brsc\b|app router/i;

export function isRscRelated(packageName: string, title: string): boolean {
  if (
    RSC_PACKAGE_EXACT.has(packageName) ||
    packageName.startsWith("react-server-dom-")
  ) {
    return true;
  }
  return RSC_TITLE_PATTERN.test(title);
}

function normalizeFix(fix: NpmAuditFixAvailable | undefined): {
  fixAvailable: boolean;
  fixPackage: string | null;
  fixedIn: string | null;
  fixIsBreaking: boolean | null;
} {
  if (fix === true) {
    return {
      fixAvailable: true,
      fixPackage: null,
      fixedIn: null,
      fixIsBreaking: false,
    };
  }
  if (fix && typeof fix === "object") {
    return {
      fixAvailable: true,
      fixPackage: typeof fix.name === "string" ? fix.name : null,
      fixedIn: typeof fix.version === "string" ? fix.version : null,
      fixIsBreaking: Boolean(fix.isSemVerMajor),
    };
  }
  return {
    fixAvailable: false,
    fixPackage: null,
    fixedIn: null,
    fixIsBreaking: null,
  };
}

function toFinding(
  packageName: string,
  advisory: NpmAuditAdvisory,
  fix: ReturnType<typeof normalizeFix>,
  installedVersion: string | null,
): Finding {
  const severity: Severity = isSeverity(advisory.severity)
    ? advisory.severity
    : "info";

  return {
    packageName,
    installedVersion,
    severity,
    title: typeof advisory.title === "string" ? advisory.title : "Untitled advisory",
    url: typeof advisory.url === "string" ? advisory.url : "",
    cwe: Array.isArray(advisory.cwe)
      ? advisory.cwe.filter((c): c is string => typeof c === "string")
      : [],
    cvssScore:
      typeof advisory.cvss?.score === "number" && Number.isFinite(advisory.cvss.score)
        ? advisory.cvss.score
        : null,
    vulnerableRange: typeof advisory.range === "string" ? advisory.range : "*",
    fixAvailable: fix.fixAvailable,
    fixPackage: fix.fixPackage,
    fixedIn: fix.fixedIn,
    fixIsBreaking: fix.fixIsBreaking,
    isRscRelated: isRscRelated(packageName, advisory.title ?? ""),
  };
}

function compareFindings(a: Finding, b: Finding): number {
  const sevDiff = SEVERITY_ORDER[b.severity] - SEVERITY_ORDER[a.severity];
  if (sevDiff !== 0) return sevDiff;

  if (a.isRscRelated !== b.isRscRelated) {
    return a.isRscRelated ? -1 : 1;
  }

  const cvssA = a.cvssScore ?? -1;
  const cvssB = b.cvssScore ?? -1;
  if (cvssB !== cvssA) return cvssB - cvssA;

  const pkgDiff = a.packageName.localeCompare(b.packageName);
  if (pkgDiff !== 0) return pkgDiff;

  return a.url.localeCompare(b.url);
}

function computeTotals(findings: readonly Finding[]): Record<Severity, number> {
  const totals: Record<Severity, number> = {
    critical: 0,
    high: 0,
    moderate: 0,
    low: 0,
    info: 0,
  };
  for (const f of findings) {
    totals[f.severity]++;
  }
  return totals;
}

/**
 * Normalizes a raw `npm audit --json` report into de-duplicated, deterministically
 * sorted, RSC-tagged findings, resolving the actually-installed version for each
 * affected package (including nested and monorepo-hoisted dependencies).
 */
export function analyzeAuditReport(
  report: NpmAuditReport,
  projectPath: string,
): ScanResult {
  const findings: Finding[] = [];
  const seenKeys = new Set<string>();

  const vulns = report.vulnerabilities ?? {};

  for (const [packageName, vuln] of Object.entries(vulns)) {
    if (!vuln || typeof vuln !== "object" || !Array.isArray(vuln.via)) {
      continue;
    }

    const fix = normalizeFix(vuln.fixAvailable);
    const installedVersion = getInstalledVersion(
      projectPath,
      packageName,
      Array.isArray(vuln.nodes) ? vuln.nodes : undefined,
    );

    for (const entry of vuln.via) {
      if (typeof entry === "string" || !entry || typeof entry !== "object") {
        continue;
      }

      const advisoryKey = entry.url || `${entry.source}:${entry.title}`;
      const dedupeKey = `${packageName}::${advisoryKey}`;
      if (seenKeys.has(dedupeKey)) continue;
      seenKeys.add(dedupeKey);

      findings.push(toFinding(packageName, entry, fix, installedVersion));
    }
  }

  findings.sort(compareFindings);

  return {
    scannedAt: new Date().toISOString(),
    projectPath,
    findings,
    rscFindings: findings.filter((f) => f.isRscRelated),
    totalsBySeverity: computeTotals(findings),
    clean: findings.length === 0,
  };
}

export interface FilterOptions {
  /** Only retain findings where `isRscRelated === true`. */
  rscOnly?: boolean;
  /** Minimum severity threshold to retain (inclusive). */
  minSeverity?: Severity;
}

/**
 * Returns a filtered view of a `ScanResult` with recomputed severity totals
 * and `clean` status. Useful for CI gates (`--rsc-only`, `--fail-on high`).
 */
export function filterScanResult(
  result: ScanResult,
  options: FilterOptions,
): ScanResult {
  const minRank = options.minSeverity ? SEVERITY_ORDER[options.minSeverity] : 0;

  const filtered = result.findings.filter((f) => {
    if (options.rscOnly && !f.isRscRelated) return false;
    if (SEVERITY_ORDER[f.severity] < minRank) return false;
    return true;
  });

  const out: ScanResult = {
    scannedAt: result.scannedAt,
    projectPath: result.projectPath,
    findings: filtered,
    rscFindings: filtered.filter((f) => f.isRscRelated),
    totalsBySeverity: computeTotals(filtered),
    clean: filtered.length === 0,
  };
  if (result.packageManager !== undefined) {
    out.packageManager = result.packageManager;
  }
  return out;
}

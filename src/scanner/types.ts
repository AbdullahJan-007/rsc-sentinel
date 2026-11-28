/**
 * Types for `npm audit --json` and normalized `rsc-sentinel` scan reports.
 *
 * Modeled directly off real output captured from npm 10.x / 11.x against
 * `registry.npmjs.org`.
 */

export type Severity = "info" | "low" | "moderate" | "high" | "critical";

export const SEVERITY_ORDER: Readonly<Record<Severity, number>> = {
  info: 0,
  low: 1,
  moderate: 2,
  high: 3,
  critical: 4,
};

export const VALID_SEVERITIES: readonly Severity[] = [
  "info",
  "low",
  "moderate",
  "high",
  "critical",
];

export function isSeverity(value: string): value is Severity {
  return (VALID_SEVERITIES as readonly string[]).includes(value);
}

export interface NpmAuditAdvisory {
  source: number;
  name: string;
  dependency: string;
  title: string;
  url: string;
  severity: Severity;
  cwe: string[];
  cvss?: {
    score: number;
    vectorString: string;
  };
  range: string;
}

/**
 * `via` entries are either a full advisory object, or a plain string naming
 * another package this vulnerability is inherited through.
 */
export type NpmAuditViaEntry = NpmAuditAdvisory | string;

export type NpmAuditFixAvailable =
  | boolean
  | {
      name: string;
      version: string;
      isSemVerMajor: boolean;
    };

export interface NpmAuditVulnerability {
  name: string;
  severity: Severity;
  isDirect: boolean;
  via: NpmAuditViaEntry[];
  effects: string[];
  range: string;
  nodes: string[];
  fixAvailable: NpmAuditFixAvailable;
}

export interface NpmAuditReport {
  auditReportVersion?: number;
  vulnerabilities: Record<string, NpmAuditVulnerability>;
  metadata?: {
    vulnerabilities?: Record<Severity, number> & { total: number };
    dependencies?: {
      prod: number;
      dev: number;
      optional: number;
      peer: number;
      peerOptional: number;
      total: number;
    };
  };
}

/**
 * Normalized, de-duplicated finding used by the rest of this package.
 * One per (package, advisory) pair.
 */
export interface Finding {
  packageName: string;
  /**
   * The version actually resolved in `node_modules` (including nested and
   * hoisted monorepo installs), read from that package's own `package.json`.
   * Null if the package folder could not be read.
   */
  installedVersion: string | null;
  severity: Severity;
  title: string;
  url: string;
  cwe: string[];
  cvssScore: number | null;
  vulnerableRange: string;
  /** True when npm reports any fix is available (boolean `true` or fix object). */
  fixAvailable: boolean;
  /** Package to upgrade when npm specifies a fix target (may differ from `packageName` for transitive deps). */
  fixPackage: string | null;
  /** Target version to upgrade to, if npm specifies one. */
  fixedIn: string | null;
  /** True if the fix requires a semver-major upgrade, false if non-breaking, null if no fix is published. */
  fixIsBreaking: boolean | null;
  /** True if this advisory's package or title matches React Server Components / Flight-protocol patterns. */
  isRscRelated: boolean;
}

export interface ScanResult {
  scannedAt: string;
  projectPath: string;
  /** Package manager whose lockfile/audit tool produced this result. */
  packageManager?: "npm" | "pnpm" | "yarn";
  findings: Finding[];
  /** Subset of `findings` where `isRscRelated` is true. */
  rscFindings: Finding[];
  totalsBySeverity: Record<Severity, number>;
  clean: boolean;
}

/**
 * Types for `npm audit --json`.
 *
 * These are modeled directly off real output captured from npm 10.x against
 * the live registry (registry.npmjs.org), not assumed from documentation.
 * `via` is the one field worth double-checking if npm changes its report
 * format in the future: it mixes two shapes in the same array.
 */

export type Severity = "info" | "low" | "moderate" | "high" | "critical";

export interface NpmAuditAdvisory {
  source: number;
  name: string;
  dependency: string;
  title: string;
  url: string;
  severity: Severity;
  cwe: string[];
  cvss: {
    score: number;
    vectorString: string;
  };
  range: string;
}

/**
 * `via` entries are either a full advisory object, or a plain string naming
 * another package this vulnerability is inherited through (a transitive
 * dependency chain reference, not an advisory itself).
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
  auditReportVersion: number;
  vulnerabilities: Record<string, NpmAuditVulnerability>;
  metadata: {
    vulnerabilities: Record<Severity, number> & { total: number };
    dependencies: {
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
 * One per (package, advisory) pair — a single package can have several
 * of these if multiple advisories apply to the installed version.
 */
export interface Finding {
  packageName: string;
  /**
   * The version actually resolved in node_modules, read directly from that
   * package's own package.json — not the declared range from the parent
   * package.json. A declared range like "^19.1.0" tells you nothing about
   * whether the resolved copy is patched; the resolved version does.
   * Null if the package folder couldn't be read (e.g. hoisting quirks,
   * workspaces).
   */
  installedVersion: string | null;
  severity: Severity;
  title: string;
  url: string;
  cwe: string[];
  cvssScore: number | null;
  vulnerableRange: string;
  fixedIn: string | null;
  fixIsBreaking: boolean | null;
  /** True if this advisory's title/package matches known RSC/Flight-protocol patterns. */
  isRscRelated: boolean;
}

export interface ScanResult {
  scannedAt: string;
  projectPath: string;
  findings: Finding[];
  /** Findings sorted into this bucket if isRscRelated is true. */
  rscFindings: Finding[];
  totalsBySeverity: Record<Severity, number>;
  clean: boolean;
}

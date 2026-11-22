import { resolve } from "node:path";
import { runNpmAudit } from "./npm-audit.js";
import { analyzeAuditReport, filterScanResult } from "./analyze.js";
import type { ScanResult, Severity } from "./types.js";

export interface ScanOptions {
  /** Project directory containing `package.json` and `package-lock.json`. Defaults to `process.cwd()`. */
  projectPath?: string;
  /** Timeout in milliseconds for `npm audit --json`. Default: 60000 (60s). */
  timeoutMs?: number;
  /** When true, only include RSC / Flight-protocol related findings. */
  rscOnly?: boolean;
  /** Minimum severity threshold to include in results (inclusive). */
  minSeverity?: Severity;
}

/**
 * Scans a project for known React Server Components / Next.js vulnerabilities
 * using live data from npm's audit endpoint (`npm audit --json`).
 */
export async function scan(options: ScanOptions = {}): Promise<ScanResult> {
  const projectPath = resolve(options.projectPath ?? process.cwd());
  const auditOpts =
    options.timeoutMs !== undefined ? { timeoutMs: options.timeoutMs } : {};
  const report = await runNpmAudit(projectPath, auditOpts);
  const fullResult = analyzeAuditReport(report, projectPath);

  if (options.rscOnly || options.minSeverity) {
    const filterOpts: { rscOnly?: boolean; minSeverity?: Severity } = {};
    if (options.rscOnly !== undefined) filterOpts.rscOnly = options.rscOnly;
    if (options.minSeverity !== undefined) filterOpts.minSeverity = options.minSeverity;
    return filterScanResult(fullResult, filterOpts);
  }

  return fullResult;
}

export { NpmAuditError } from "./npm-audit.js";
export type { NpmAuditErrorCode, RunNpmAuditOptions } from "./npm-audit.js";
export { analyzeAuditReport, filterScanResult, isRscRelated } from "./analyze.js";
export type { FilterOptions } from "./analyze.js";
export { SEVERITY_ORDER, VALID_SEVERITIES, isSeverity } from "./types.js";
export type {
  Finding,
  ScanResult,
  Severity,
  NpmAuditReport,
  NpmAuditAdvisory,
  NpmAuditVulnerability,
  NpmAuditViaEntry,
  NpmAuditFixAvailable,
} from "./types.js";

import { resolve } from "node:path";
import { runAudit } from "./npm-audit.js";
import { analyzeAuditReport, filterScanResult } from "./analyze.js";
import type { PackageManager } from "../utils/pm-runner.js";
import type { ScanResult, Severity } from "./types.js";

export interface ScanOptions {
  /** Project directory containing `package.json` and a lockfile. Defaults to `process.cwd()`. */
  projectPath?: string;
  /** Package manager to use (`"auto"` detects from lockfile). Default: `"auto"`. */
  packageManager?: "auto" | PackageManager;
  /** Timeout in milliseconds for the audit command. Default: 60000 (60s). */
  timeoutMs?: number;
  /** When true, only include RSC / Flight-protocol related findings. */
  rscOnly?: boolean;
  /** Minimum severity threshold to include in results (inclusive). */
  minSeverity?: Severity;
}

/**
 * Scans a project for known React Server Components / Next.js vulnerabilities
 * using live advisory data from npm, pnpm, or yarn.
 */
export async function scan(options: ScanOptions = {}): Promise<ScanResult> {
  const projectPath = resolve(options.projectPath ?? process.cwd());
  const auditOpts: {
    timeoutMs?: number;
    packageManager?: "auto" | PackageManager;
  } = {};
  if (options.timeoutMs !== undefined) auditOpts.timeoutMs = options.timeoutMs;
  if (options.packageManager !== undefined) {
    auditOpts.packageManager = options.packageManager;
  }

  const { packageManager, report } = await runAudit(projectPath, auditOpts);
  const fullResult: ScanResult = {
    ...analyzeAuditReport(report, projectPath),
    packageManager,
  };

  if (options.rscOnly || options.minSeverity) {
    const filterOpts: { rscOnly?: boolean; minSeverity?: Severity } = {};
    if (options.rscOnly !== undefined) filterOpts.rscOnly = options.rscOnly;
    if (options.minSeverity !== undefined) filterOpts.minSeverity = options.minSeverity;
    return filterScanResult(fullResult, filterOpts);
  }

  return fullResult;
}

export { NpmAuditError, runAudit, runNpmAudit } from "./npm-audit.js";
export type {
  NpmAuditErrorCode,
  RunNpmAuditOptions,
  AuditExecutionResult,
} from "./npm-audit.js";
export { analyzeAuditReport, filterScanResult, isRscRelated } from "./analyze.js";
export type { FilterOptions } from "./analyze.js";
export {
  normalizePnpmAuditReport,
  normalizeYarnAuditOutput,
} from "./adapters.js";
export { toSarif } from "./sarif.js";
export type { SarifLog, SarifRule, SarifResult, SarifLevel } from "./sarif.js";
export { detectPackageManager } from "../utils/pm-runner.js";
export type { PackageManager } from "../utils/pm-runner.js";
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

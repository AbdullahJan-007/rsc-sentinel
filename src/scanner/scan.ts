import { runNpmAudit } from "./npm-audit.js";
import { analyzeAuditReport } from "./analyze.js";
import type { ScanResult } from "./types.js";

export interface ScanOptions {
  /** Defaults to process.cwd(). */
  projectPath?: string;
}

/**
 * Scans a project for known React Server Components / Next.js vulnerabilities
 * using live data from npm's audit endpoint — the same data source `npm
 * audit` itself uses, not a hand-maintained version table. This means the
 * result reflects whatever is currently published to the advisory database
 * at the time it's run, including advisories that didn't exist yet when
 * this package was written.
 */
export async function scan(options: ScanOptions = {}): Promise<ScanResult> {
  const projectPath = options.projectPath ?? process.cwd();
  const report = await runNpmAudit(projectPath);
  return analyzeAuditReport(report, projectPath);
}

export { NpmAuditError } from "./npm-audit.js";
export type {
  Finding,
  ScanResult,
  Severity,
  NpmAuditReport,
} from "./types.js";

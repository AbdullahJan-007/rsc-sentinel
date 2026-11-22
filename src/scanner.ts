export {
  scan,
  NpmAuditError,
  analyzeAuditReport,
  filterScanResult,
  isRscRelated,
  SEVERITY_ORDER,
  VALID_SEVERITIES,
  isSeverity,
} from "./scanner/scan.js";

export { runNpmAudit } from "./scanner/npm-audit.js";
export { getInstalledVersion, isValidPackageName } from "./utils/installed-version.js";

export type {
  ScanOptions,
  NpmAuditErrorCode,
  RunNpmAuditOptions,
  FilterOptions,
  Finding,
  ScanResult,
  Severity,
  NpmAuditReport,
  NpmAuditAdvisory,
  NpmAuditVulnerability,
  NpmAuditViaEntry,
  NpmAuditFixAvailable,
} from "./scanner/scan.js";

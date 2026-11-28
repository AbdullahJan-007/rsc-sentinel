export {
  scan,
  runAudit,
  runNpmAudit,
  NpmAuditError,
  analyzeAuditReport,
  filterScanResult,
  isRscRelated,
  normalizePnpmAuditReport,
  normalizeYarnAuditOutput,
  toSarif,
  detectPackageManager,
  SEVERITY_ORDER,
  VALID_SEVERITIES,
  isSeverity,
} from "./scanner/scan.js";

export { getInstalledVersion, isValidPackageName } from "./utils/installed-version.js";

export type {
  ScanOptions,
  NpmAuditErrorCode,
  RunNpmAuditOptions,
  AuditExecutionResult,
  FilterOptions,
  PackageManager,
  SarifLog,
  SarifRule,
  SarifResult,
  SarifLevel,
  Finding,
  ScanResult,
  Severity,
  NpmAuditReport,
  NpmAuditAdvisory,
  NpmAuditVulnerability,
  NpmAuditViaEntry,
  NpmAuditFixAvailable,
} from "./scanner/scan.js";

export { scan } from "./scanner/scan.js";
export type { ScanOptions } from "./scanner/scan.js";
export { NpmAuditError } from "./scanner/npm-audit.js";
export type {
  Finding,
  ScanResult,
  Severity,
  NpmAuditReport,
} from "./scanner/types.js";

export {
  withActionGuard,
  ActionGuardError,
} from "./middleware/protect-action.js";
export type {
  ActionGuardOptions,
  ActionGuardReason,
} from "./middleware/protect-action.js";

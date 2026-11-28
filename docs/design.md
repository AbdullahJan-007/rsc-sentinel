# Technical Design — `rsc-sentinel`

## 1. Public API Design

### 1.1 `rsc-sentinel/guard`

```ts
import {
  createActionGuard,
  withActionGuard,
  ActionGuardError,
  isActionGuardError,
  isNextControlFlowError,
  type ActionGuard,
  type ActionGuardOptions,
  type ActionGuardReason,
  type ActionGuardResult,
} from "rsc-sentinel/guard";
```

#### Next.js `"use server"` Pattern
Next.js's SWC compiler enforces that every export of a `"use server"` module MUST be an `export async function` declaration. `createActionGuard()` is designed specifically for this convention:

```ts
"use server";
import { createActionGuard } from "rsc-sentinel/guard";

const guard = createActionGuard({
  maxFormDataBytes: 512 * 1024,
  maxFormDataEntries: 100,
  timeoutMs: 15_000,
  onBlocked: (reason, detail) => console.warn(`[guard:${reason}] ${detail}`),
});

export async function submitContact(formData: FormData) {
  return guard.safeRun([formData], async (signal) => {
    return { submitted: true };
  });
}
```

---

### 1.2 `rsc-sentinel/scanner`

```ts
import {
  scan,
  runAudit,
  runNpmAudit,
  analyzeAuditReport,
  filterScanResult,
  normalizePnpmAuditReport,
  normalizeYarnAuditOutput,
  toSarif,
  detectPackageManager,
  getInstalledVersion,
  NpmAuditError,
  isRscRelated,
  isSeverity,
  SEVERITY_ORDER,
  VALID_SEVERITIES,
  type ScanOptions,
  type ScanResult,
  type Finding,
  type Severity,
  type PackageManager,
  type SarifLog,
} from "rsc-sentinel/scanner";
```

---

## 2. Security & Reliability Mechanisms

### 2.1 Path-Safe Version Resolution (`getInstalledVersion`)
- Validates `packageName` against `/^(?:@[a-z0-9-~][a-z0-9-._~]*\/)?[a-z0-9-~][a-z0-9-._~]*$/i`.
- Rejects null bytes (`\0`) and checks `isPathInside(root, candidate)` using `path.relative()` before reading from disk.
- Resolution order: `vuln.nodes` → direct `node_modules` → ancestor hoisted `node_modules` (max depth 10).

### 2.2 Short-Circuiting & Cycle-Safe Payload Inspection
- Uses a single module-scoped `TextEncoder` instance and checks limits during iteration.
- Tracks visited objects with `WeakSet<object>` to prevent stack overflow on cyclic references.
- Iterates `Object.keys()` only (immune to prototype-chain traversal).
- Isolates `onBlocked` and `onLateError` callbacks inside `try/catch`.

### 2.3 SARIF 2.1.0 Schema (`toSarif`)
- Maps `critical`/`high` → `"error"`, `moderate` → `"warning"`, `low`/`info` → `"note"`.
- Derives stable rule IDs (`<packageName>/<GHSA-ID>` or `<packageName>/<CVE-ID>`), attaches CVSS `security-severity`, `rsc` & CWE tags, `helpUri`, and lockfile `artifactLocation.uri` (`package-lock.json`, `pnpm-lock.yaml`, or `yarn.lock`).

### 2.4 Cross-Platform Test Runner (`scripts/run-tests.mjs`)
- Discovers compiled `dist-test/tests/**/*.test.js` files via `node:fs` and spawns `node --test <explicit files>`, eliminating `cmd.exe` vs `bash` glob-expansion discrepancies across Node 20, 22, and 24.

---

## 3. CLI Specification

### Commands
- `rsc-sentinel check [--json | --sarif] [--path <dir>] [--pm <auto|npm|pnpm|yarn>] [--rsc-only] [--fail-on <severity>] [--timeout <ms>]`
- `rsc-sentinel fix [--force] [--path <dir>] [--pm <auto|npm|pnpm|yarn>]`
- `rsc-sentinel --help` / `-h`
- `rsc-sentinel --version` / `-v`

### Exit Codes
| Code | Meaning |
| --- | --- |
| `0` | Clean scan / successful fix / `--help` / `--version` |
| `1` | One or more vulnerabilities found meeting the threshold (or `fix` left unresolved issues) |
| `2` | Invalid arguments, conflicting flags (`--json` + `--sarif`), unknown command, missing `package.json`/lockfile, PM unavailable, or timeout |

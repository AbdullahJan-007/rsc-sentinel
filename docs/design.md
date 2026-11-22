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

#### Recommended Next.js `"use server"` Pattern
Next.js's SWC compiler enforces that every export of a `"use server"` module MUST be an `export async function` declaration. Exporting `export const fn = withActionGuard(...)` fails `next build`.

Therefore, `createActionGuard()` is the primary Next.js API:

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
    // Pass `signal` to fetch() or DB drivers for cooperative cancellation.
    return { submitted: true };
  });
}
```

#### Why `safeRun` Returns `ActionGuardResult<T>`
In Next.js production builds, thrown `Error` instances crossing the Server → Client boundary are stripped to a generic digest error (`"An error occurred in the Server Components render"`). `err instanceof ActionGuardError` in a Client Component will **not** work in production. Returning `{ ok: true, data }` or `{ ok: false, error: { reason, message } }` is 100% RSC-serializable and works identically in dev and prod.

---

### 1.2 `rsc-sentinel/scanner`

```ts
import {
  scan,
  analyzeAuditReport,
  filterScanResult,
  runNpmAudit,
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
} from "rsc-sentinel/scanner";
```

---

## 2. Security Mechanisms

### 2.1 Path-Safe Version Resolution (`getInstalledVersion`)
- Validates `packageName` against `/^(?:@[a-z0-9-~][a-z0-9-._~]*\/)?[a-z0-9-~][a-z0-9-._~]*$/i`.
- Rejects null bytes (`\0`) and checks `isPathInside(root, candidate)` using `path.relative()` before touching the filesystem.
- Prevents hostile or corrupted audit reports from reading `package.json` outside `node_modules`.

### 2.2 Short-Circuiting & Cycle-Safe Payload Inspection
- Uses a single module-scoped `TextEncoder` instance.
- Checks limits **during** iteration (not after summing the entire payload), so a 100 MB payload fails on the first offending entry/chunk.
- Uses `WeakSet<object>` for visited objects to prevent infinite recursion on cyclic object graphs.
- Uses `Object.keys()` (own enumerable properties only) to avoid prototype-chain traversal.
- Wraps `onBlocked` and `onLateError` in `try/catch` so observability failures can never disable security enforcement.

### 2.3 Deterministic Finding Sort Order
Findings are sorted by:
1. `SEVERITY_ORDER[severity]` descending (`critical` → `info`)
2. `isRscRelated` descending (RSC findings first within same severity)
3. `cvssScore` descending (`null` treated as `-1`)
4. `packageName` ascending (`localeCompare`)
5. `url` ascending (`localeCompare`)

---

## 3. CLI Specification

### Commands
- `rsc-sentinel check [--json] [--path <dir>] [--rsc-only] [--fail-on <severity>] [--timeout <ms>]`
- `rsc-sentinel fix [--force] [--path <dir>]`
- `rsc-sentinel --help` / `-h`
- `rsc-sentinel --version` / `-v`

### Exit Codes
| Code | Meaning |
| --- | --- |
| `0` | Clean scan / successful fix / `--help` / `--version` |
| `1` | One or more vulnerabilities found meeting the threshold (or `fix` left unresolved issues) |
| `2` | Invalid arguments, unknown command, missing `package.json`/`package-lock.json`, `npm` missing, timeout, or invalid audit output |

### JSON Error Contract (`--json`)
When `--json` is passed and an exit-code-`2` error occurs, stdout always receives valid JSON:
```json
{
  "error": {
    "code": "NO_LOCKFILE",
    "message": "No package-lock.json found..."
  }
}
```

# System Architecture — `rsc-sentinel`

## 1. High-Level Architecture

`rsc-sentinel` is intentionally split into **two isolated runtime domains** exposed through explicit `package.json` subpath exports so Next.js bundlers (Turbopack / Webpack) never pull Node.js-only modules into Edge or Client graphs.

```mermaid
flowchart TD
    subgraph NextApp["Next.js App Router / Edge / Client"]
        SA["'use server' Action"]
        CC["Client Component"]
    end

    subgraph GuardPkg["rsc-sentinel/guard (Zero Node Builtins)"]
        CAG["createActionGuard / withActionGuard"]
        INSP["Short-Circuit Payload Inspector"]
        TO["Timeout + AbortSignal + LateError Catch"]
        ERR["ActionGuardError & ActionGuardResult"]
    end

    subgraph ScannerPkg["rsc-sentinel/scanner (Node.js >= 20)"]
        CLI["bin/rsc-sentinel.js -> src/cli.ts"]
        SCAN["scan() Orchestrator"]
        RUNNER["Cross-Platform execPackageManager (npm / pnpm / yarn)"]
        ADAPT["PM Adapters (pnpm / yarn Berry & Classic)"]
        ANALYZE["analyzeAuditReport + filterScanResult"]
        VER["getInstalledVersion (Path-Safe Resolver)"]
        SARIF["toSarif() (SARIF 2.1.0 Formatter)"]
    end

    SA --> CAG
    CC --> ERR
    CAG --> INSP
    CAG --> TO
    TO --> ERR

    CLI --> SCAN
    CLI --> SARIF
    CLI --> RUNNER
    SCAN --> RUNNER
    RUNNER --> ADAPT
    ADAPT --> ANALYZE
    ANALYZE --> VER
```

---

## 2. Package Entrypoint & Subpath Isolation

| Entrypoint | Source File | Runtime Target | Node.js Builtins? |
| --- | --- | --- | --- |
| `rsc-sentinel/guard` | `src/guard.ts` | Next.js Server Actions, Edge Runtime, Browser/Client, Node.js | **NONE** (Web APIs only) |
| `rsc-sentinel/scanner` | `src/scanner.ts` | Node.js `>= 20` (CI, scripts, dev tools) | `node:child_process`, `node:fs`, `node:path`, `node:util` |
| `rsc-sentinel` (root) | `src/index.ts` | Node.js `>= 20` convenience barrel | Re-exports both |
| `rsc-sentinel` (CLI bin) | `bin/rsc-sentinel.js` -> `src/cli.ts` | Node.js `>= 20` terminal / CI | Node builtins |

---

## 3. Data Flow

### 3.1 Multi-PM Scanner & SARIF Pipeline
1. **Pre-flight & lockfile detection (`runAudit` + `detectPackageManager`):** Verifies `package.json` (`NO_PACKAGE_JSON`) and auto-detects `pnpm-lock.yaml` → `pnpm`, `yarn.lock` → `yarn`, or `package-lock.json` / `npm-shrinkwrap.json` → `npm` (or honors `--pm <manager>`).
2. **Cross-platform execution (`execPackageManager`):** Runs fixed audit commands (`npm audit --json`, `pnpm audit --json`, `yarn npm audit --json` with fallback to `yarn audit --json`) with a 32 MiB buffer cap and configurable timeout (default 60s). On Windows, safely dispatches via `cmd.exe /d /s /c <pm> ...` with `windowsHide: true`.
3. **Adapter normalization (`adapters.ts`):** Converts pnpm `advisories` maps and Yarn Berry/Classic NDJSON into the canonical `NpmAuditReport` shape.
4. **Analysis (`analyzeAuditReport`):**
   - Skips transitive string pointers in `via` and deduplicates by `(packageName, advisoryUrl)`.
   - Resolves actual installed versions from `node_modules` via `vuln.nodes` → local `node_modules` → hoisted ancestor `node_modules`.
   - Normalizes `fixAvailable` (`true` | `false` | `{ name, version, isSemVerMajor }`), tags `isRscRelated`, and sorts deterministically.
5. **Filtering & Output (`filterScanResult` / `toSarif`):** Applies `--rsc-only` and `--fail-on <severity>`, then outputs human-readable text, strict JSON (`--json`), or SARIF 2.1.0 (`--sarif`).

### 3.2 Server Action Guard Pipeline
1. **Eager config validation:** Rejects invalid numeric limits (`NaN`, `Infinity`, `<= 0`) with `RangeError` at guard construction time.
2. **Pre-execution inspection (`inspectArguments`):**
   - `FormData`: counts entries (`maxFormDataEntries`) and UTF-8 bytes of keys, string values, `Blob.size`, and `File.name` (`maxFormDataBytes`), short-circuiting on first breach.
   - Non-`FormData`: traverses strings, `Blob`, `ArrayBuffer`, `TypedArray`, `Map`, `Set`, arrays, and own enumerable object keys with depth enforcement (`maxObjectDepth`), cycle tracking (`WeakSet`), and byte caps (`maxPayloadBytes`).
3. **Bounded execution (`executeGuarded`):**
   - Creates an `AbortController` and passes `controller.signal` to the action.
   - Races the action promise against a `setTimeout` promise and attaches a late-rejection handler (`onLateError`) so post-timeout rejections never crash Node.js.
4. **Result serialization (`safeRun` / `wrapSafe`):**
   - Re-throws Next.js control-flow errors (`NEXT_REDIRECT`, `NEXT_NOT_FOUND`, `NEXT_HTTP_ERROR_FALLBACK`) untouched.
   - Converts `ActionGuardError` into `{ ok: false, error: { reason, message } }`.

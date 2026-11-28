# Architecture Decisions & Security Audit — `rsc-sentinel`

A permanent record of security findings resolved between `v0.1.0` and `v0.2.0` and the architectural decisions behind the current design.

---

## 1. Security & Reliability Fixes (`v0.1.0` → `v0.2.0`)

| ID | Severity | Area | Issue in `v0.1.0` | Resolution in `v0.2.0` |
| --- | --- | --- | --- | --- |
| **SEC-01** | Critical | Next.js Bundling | Single root entrypoint (`src/index.ts`) combined Node-only scanner (`node:child_process`, `node:fs`) with `withActionGuard`, breaking Edge Runtime and Client bundles. | Split into subpath exports: `rsc-sentinel/guard` (zero Node builtins), `rsc-sentinel/scanner` (Node-only), and root barrel; added `"sideEffects": false`. |
| **SEC-02** | Critical | Next.js `"use server"` | Exporting `export const fn = withActionGuard(...)` from a `"use server"` file fails Next.js SWC compilation. | Introduced `createActionGuard()` with `run()` / `safeRun()` for `export async function` declarations and updated examples. |
| **SEC-03** | Critical | RSC Error Serialization | Thrown `ActionGuardError` instances are stripped across the Server-to-Client boundary in Next.js production builds. | Added RSC-serializable `ActionGuardResult<T>` (`safeRun` / `wrapSafe`) and `isNextControlFlowError()` passthrough for `redirect()` / `notFound()`. |
| **SEC-04** | Critical | Package Metadata | `package.json` listed `rsc-sentinel` inside its own `dependencies` (circular self-dependency). | Removed `dependencies` (zero runtime dependencies) and added `repository`, `homepage`, `bugs`, and `publishConfig`. |
| **SEC-05** | Critical | Windows CLI Execution | `execFile("npm", ...)` failed with `ENOENT` on Windows Node.js 20.12+/22/24 due to `.cmd` shim restrictions. | Added cross-platform `src/utils/pm-runner.ts` (`execPackageManager`) supporting `npm`, `pnpm`, and `yarn` via `cmd.exe /d /s /c <pm> ...` on `win32` with `windowsHide: true`. |
| **SEC-06** | High | Guard Config Bypass | Passing `NaN`, `0`, `-1`, or `Infinity` for numeric guard options silently disabled size/timeout checks (`size > NaN === false`). | Added eager `RangeError` validation for all numeric options in `resolveOptions()`. |
| **SEC-07** | High | Payload DoS Bypasses | Only `FormData` total bytes were checked; field-floods, massive non-`FormData` payloads, deeply nested objects, and oversized `File.name` bypassed inspection. | Added `maxFormDataEntries`, `maxPayloadBytes`, `maxObjectDepth`, `File.name` byte counting, cycle-safe `WeakSet` tracking, and short-circuit evaluation. |
| **SEC-08** | High | Timeout Crash Safety | `Promise.race([action(), timeout])` left the losing action promise unobserved; late rejections triggered `UnhandledPromiseRejection`. | Attached a late-rejection handler (`onLateError`) and cooperative `AbortController` `AbortSignal`. |
| **SEC-09** | High | Path Traversal & Hoisting | `getInstalledVersion` joined `packageName` directly without path validation and missed nested `vuln.nodes` and hoisted monorepo installs. | Added npm package name validation, `isPathInside` containment checks, `vuln.nodes` resolution, and ancestor `node_modules` traversal. |
| **SEC-10** | Medium | Scanner, CLI & Windows Node 20 CI | `isAuditReport` accepted `vulnerabilities: null`; boolean `fixAvailable: true` reported no fix; `fixPackage` was omitted; unknown commands exited `0`; `VERSION` was hardcoded; Windows `cmd.exe` did not expand `*.test.js` globs on Node 20. | Hardened report validation, normalized all `fixAvailable` shapes, added multi-PM adapters (`pnpm`/`yarn`), `--sarif`, `--pm`, `--rsc-only`, `--fail-on`, `--timeout`, dynamic version loading, and `scripts/run-tests.mjs` (verified 9/9 CI matrix green). |

---

## 2. Architectural Decision Records (ADRs)

- **ADR-001 — Explicit Subpath Exports:** Expose `rsc-sentinel/guard` separately from `rsc-sentinel/scanner` rather than relying solely on bundler tree-shaking, guaranteeing zero Node.js builtin leakage into Next.js Edge and Client bundles.
- **ADR-002 — Compiled Test Suite + Explicit Runner (`scripts/run-tests.mjs`):** Compile TypeScript tests into `dist-test/` with `tsconfig.test.json` and invoke `node --test` with explicit discovered file paths rather than shell globs, ensuring 100% deterministic execution across Node 20, 22, and 24 on Windows, macOS, and Linux.
- **ADR-003 — Backwards-Compatible Guard API:** Keep `withActionGuard` exported alongside `createActionGuard` so existing `v0.1.0` consumers upgrade to `v0.2.0` without breaking imports.
- **ADR-004 — Multi-PM Adapter Normalization:** Normalize `pnpm audit --json` and `yarn` (Berry & Classic) outputs into the canonical `NpmAuditReport` shape so downstream deduplication, RSC tagging, installed-version resolution, filtering, and SARIF export remain a single unified pipeline.
- **ADR-005 — SARIF 2.1.0 Native Output:** Emit spec-compliant SARIF 2.1.0 directly via `toSarif()` / `--sarif` with zero external dependencies for first-class GitHub Code Scanning integration.

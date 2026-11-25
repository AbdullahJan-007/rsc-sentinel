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
| **SEC-05** | Critical | Windows CLI Execution | `execFile("npm", ...)` failed with `ENOENT` on Windows Node.js 20.12+/22/24 due to `.cmd` shim restrictions. | Added cross-platform `src/utils/npm-runner.ts` (`execNpm`) using `cmd.exe /d /s /c npm ...` on `win32` with `windowsHide: true` and configurable timeout. |
| **SEC-06** | High | Guard Config Bypass | Passing `NaN`, `0`, `-1`, or `Infinity` for numeric guard options silently disabled size/timeout checks (`size > NaN === false`). | Added eager `RangeError` validation for all numeric options in `resolveOptions()`. |
| **SEC-07** | High | Payload DoS Bypasses | Only `FormData` total bytes were checked; field-floods, massive non-`FormData` payloads, deeply nested objects, and oversized `File.name` bypassed inspection. | Added `maxFormDataEntries`, `maxPayloadBytes`, `maxObjectDepth`, `File.name` byte counting, cycle-safe `WeakSet` tracking, and short-circuit evaluation. |
| **SEC-08** | High | Timeout Crash Safety | `Promise.race([action(), timeout])` left the losing action promise unobserved; late rejections triggered `UnhandledPromiseRejection`. | Attached a late-rejection handler (`onLateError`) and cooperative `AbortController` `AbortSignal`. |
| **SEC-09** | High | Path Traversal & Hoisting | `getInstalledVersion` joined `packageName` directly without path validation and missed nested `vuln.nodes` and hoisted monorepo installs. | Added npm package name validation, `isPathInside` containment checks, `vuln.nodes` resolution, and ancestor `node_modules` traversal. |
| **SEC-10** | Medium | Scanner & CLI Edge Cases | `isAuditReport` accepted `vulnerabilities: null`; boolean `fixAvailable: true` reported no fix; `fixPackage` was omitted; unknown commands exited `0`; `VERSION` was hardcoded; test script used Node 22+ `--experimental-strip-types`. | Hardened report validation, normalized all `fixAvailable` shapes, added `--rsc-only`/`--fail-on`/`--timeout` and structured `--json` errors, loaded version dynamically, and compiled tests via `tsconfig.test.json`. |

---

## 2. Architectural Decision Records (ADRs)

- **ADR-001 — Explicit Subpath Exports:** Expose `rsc-sentinel/guard` separately from `rsc-sentinel/scanner` rather than relying solely on bundler tree-shaking, guaranteeing zero Node.js builtin leakage into Next.js Edge and Client bundles.
- **ADR-002 — Compiled Test Suite for Node 20+:** Compile TypeScript tests into `dist-test/` with `tsconfig.test.json` instead of relying on `--experimental-strip-types`, ensuring full compatibility with `"engines": { "node": ">=20.0.0" }`.
- **ADR-003 — Backwards-Compatible Guard API:** Keep `withActionGuard` exported alongside `createActionGuard` so existing `v0.1.0` consumers upgrade to `v0.2.0` without breaking imports.

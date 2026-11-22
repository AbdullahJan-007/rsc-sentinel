# Engineering Memory & Red-Team Audit Log — `rsc-sentinel`

This document records every bug, security vulnerability, and architectural decision uncovered during the v0.1.0 → v0.2.0 Staff Engineering & Red-Team overhaul so regressions never recur.

---

## 1. Red-Team & Production Audit Findings (v0.1.0 → Fixed in v0.2.0)

| ID | Severity | Area | Root Cause in v0.1.0 | Fix Implemented in v0.2.0 |
| --- | --- | --- | --- | --- |
| **SEC-01** | Critical | Next.js Bundling | Single root export (`src/index.ts`) mixed `node:child_process`/`node:fs` scanner with `withActionGuard`, breaking Next.js Edge/Client bundles. | Split into subpath exports: `rsc-sentinel/guard` (zero Node builtins), `rsc-sentinel/scanner` (Node-only), and root barrel; added `"sideEffects": false`. |
| **SEC-02** | Critical | Next.js `"use server"` | Docs & `examples/nextjs-demo/app/actions.ts` used `export const x = withActionGuard(...)`, which fails Next.js SWC compiler (`A "use server" file can only export async functions`). | Added `createActionGuard()` with `run()` / `safeRun()` for `export async function` declarations; fixed demo & README. |
| **SEC-03** | Critical | RSC Error Serialization | Throwing `ActionGuardError` across Next.js Server → Client boundary in production strips error class & message; `instanceof ActionGuardError` failed in prod. | Added RSC-serializable `ActionGuardResult<T>` (`safeRun` / `wrapSafe`) + Next.js `NEXT_REDIRECT`/`NEXT_NOT_FOUND` passthrough. |
| **SEC-04** | Critical | npm Packaging | `package.json` accidentally listed `"rsc-sentinel": "^0.1.0"` inside its own `dependencies` (circular self-dependency). | Removed `dependencies` completely (zero runtime deps); added `repository`, `homepage`, `bugs`, `publishConfig`. |
| **SEC-05** | Critical | Windows CLI Crash | `execFile("npm", ...)` failed with `ENOENT` on Windows Node 20.12+/22/24 (CVE-2024-27980 `.cmd` shim change), crashing `rsc-sentinel check` and `fix`. | Created `src/utils/npm-runner.ts` (`execNpm`) with safe `cmd.exe /d /s /c npm ...` on win32 + configurable timeout + explicit `ENOENT`/`TIMEOUT` errors. |
| **SEC-06** | High | Guard Bypass (`NaN`) | Passing `NaN`, `0`, `-1`, or `Infinity` for `maxFormDataBytes` or `timeoutMs` silently disabled checks (`size > NaN` is `false`). | Eager `RangeError` validation in `resolveOptions()` for all numeric guard options. |
| **SEC-07** | High | Guard DoS Bypasses | Only `FormData` byte size was checked — attackers could bypass with 100k 1-byte fields, massive non-FormData strings/objects/TypedArrays, deeply nested objects, or huge `File.name`. | Added `maxFormDataEntries`, `maxPayloadBytes`, `maxObjectDepth`, `File.name` byte counting, cycle-safe `WeakSet`, and short-circuiting inspection. |
| **SEC-08** | High | Process Crash on Timeout | `Promise.race([action(), timeout])` left the losing `action()` promise unobserved — a late rejection triggered `UnhandledPromiseRejection` and crashed Node. | Attached `.catch()` forwarding to `onLateError`, plus cooperative `AbortController` `AbortSignal`. |
| **SEC-09** | High | Path Traversal & Hoisting | `getInstalledVersion` joined `packageName` blindly (path traversal risk) and missed nested `vuln.nodes` and hoisted monorepo `node_modules`. | Added strict npm name regex, `isPathInside` containment check, `vuln.nodes` lookup, and ancestor `node_modules` walk. |
| **SEC-10** | Medium | Scanner & CLI Bugs | `isAuditReport` accepted `vulnerabilities: null`; `fixAvailable: true` showed "none published yet"; `fixPackage` was omitted; unknown CLI command exited `0`; `VERSION` was hardcoded; `--experimental-strip-types` broke Node 20. | Fixed all 6 issues; compiled tests via `tsconfig.test.json`; added `--rsc-only`, `--fail-on`, `--timeout`, and JSON error output. |

---

## 2. Key Architectural Decisions (ADRs)

- **ADR-001 (Subpath Exports):** Expose `rsc-sentinel/guard` separately from `rsc-sentinel/scanner` rather than relying solely on tree-shaking, guaranteeing zero Node-builtin leakage in Next.js Edge/Client bundles.
- **ADR-002 (Compiled Tests for Node 20+):** Compile tests into `dist-test/` with `tsconfig.test.json` instead of using `--experimental-strip-types`, ensuring 100% compatibility with `"engines": { "node": ">=20.0.0" }`.
- **ADR-003 (Keep `withActionGuard` Backwards-Compatible):** Retain `withActionGuard` alongside `createActionGuard` so existing v0.1.0 callers upgrade to v0.2.0 seamlessly without breaking imports.

# Product Requirements Document (PRD) — `rsc-sentinel`

- **Product:** `rsc-sentinel` (npm package & CLI)
- **Target Release:** `v0.2.0`
- **Owner:** Abdullah Jan
- **Status:** Production-Ready (9/9 CI Matrix Passing)

---

## 1. Executive Summary

`rsc-sentinel` is a lightweight, zero-runtime-dependency security toolkit for **Next.js App Router** and **React Server Components (RSC)** applications. It solves two real-world operational gaps:

1. **Live Multi-PM RSC Vulnerability Detection (CLI & Programmatic Scanner):** Auto-detects `npm`, `pnpm`, and `yarn` lockfiles, queries live advisory databases at runtime, resolves the *actually installed* versions in `node_modules` (including nested and monorepo-hoisted copies), highlights RSC / Flight-protocol advisories (such as CVE-2026-23869 and successors), and emits human-readable reports, strict JSON, or **SARIF 2.1.0** for GitHub Code Scanning.
2. **Next.js-Native Server Action Hardening (`rsc-sentinel/guard`):** A zero-Node-builtin runtime guard providing per-action defense-in-depth — `FormData` byte caps, field-flood entry caps, non-`FormData` payload byte/depth caps, cooperative `AbortSignal` timeouts, unhandled-rejection protection, and RSC-serializable result unions.

---

## 2. Target Users & Jobs-to-be-Done

| Persona | Job to Be Done | Primary Interface |
| --- | --- | --- |
| **Next.js App Router Developer** | Harden `"use server"` actions with per-action size, entry, depth, and timeout limits without breaking Turbopack/Webpack or `"use server"` compiler rules. | `import { createActionGuard } from "rsc-sentinel/guard"` |
| **Platform / Security Engineer** | Gate CI/CD pipelines on live RSC advisories across `npm`, `pnpm`, or `yarn` with deterministic exit codes, JSON, or SARIF 2.1.0 for GitHub Code Scanning. | `npx rsc-sentinel check --rsc-only --fail-on high --sarif` |
| **Full-Stack Maintainer** | Verify whether `node_modules` is actually patched (not just `package.json` semver ranges) and apply safe fixes. | `npx rsc-sentinel check` & `npx rsc-sentinel fix` |

---

## 3. Functional Requirements

### 3.1 Live Vulnerability Scanner (`rsc-sentinel/scanner` & CLI)
- **FR-1:** Auto-detect and query live audit data across `npm` (`package-lock.json`), `pnpm` (`pnpm-lock.yaml`), and `yarn` (`yarn.lock` — Berry & Classic) on Windows, macOS, and Linux (Node.js `>= 20.0.0`).
- **FR-2:** Tag RSC/Flight-protocol advisories automatically via package prefix (`react-server-dom-*`) and advisory title patterns (`Server Component`, `Server Action`, `Flight protocol`, `RSC`, `App Router`).
- **FR-3:** Resolve the *actually installed* version from `node_modules` via `vuln.nodes`, direct `node_modules`, and ancestor monorepo hoisting, while strictly preventing path traversal.
- **FR-4:** Normalize `fixAvailable` across all npm/pnpm/yarn shapes, surfacing the exact package to upgrade (`fixPackage`).
- **FR-5:** Support CI flags `--pm <auto|npm|pnpm|yarn>`, `--rsc-only`, `--fail-on <severity>`, `--timeout <ms>`, `--path <dir>`, `--json` (including structured JSON errors), and `--sarif` (SARIF 2.1.0).
- **FR-6:** Deterministic exit codes: `0` (clean), `1` (findings present), `2` (usage/config/runtime error).

### 3.2 Server Action Guard (`rsc-sentinel/guard`)
- **FR-7:** Zero Node.js builtin imports so it bundles cleanly in Next.js App Router Server Actions, Edge Runtime, and Client Components.
- **FR-8:** Compatible with Next.js `"use server"` strict `export async function` rule via `createActionGuard().run()` and `safeRun()`.
- **FR-9:** Enforce `maxFormDataBytes` (including `File.name` bytes, short-circuiting early), `maxFormDataEntries` (anti-field-flood), `maxPayloadBytes` (non-`FormData` args), `maxObjectDepth` (anti-stack-exhaustion, circular-safe), and `timeoutMs` with cooperative `AbortSignal`.
- **FR-10:** Eagerly validate all numeric options (`RangeError` on `NaN`, `Infinity`, `<= 0`) to eliminate silent bypasses.
- **FR-11:** Never trigger `UnhandledPromiseRejection` when a timed-out action later rejects; forward to `onLateError`.
- **FR-12:** Preserve Next.js internal control-flow errors (`NEXT_REDIRECT`, `NEXT_NOT_FOUND`, `NEXT_HTTP_ERROR_FALLBACK`) untouched in `safeRun` / `wrapSafe`.

---

## 4. Non-Functional Requirements

- **Zero Runtime Dependencies:** `"dependencies"` in `package.json` MUST remain empty.
- **Strict TypeScript:** `strict`, `noUncheckedIndexedAccess`, `exactOptionalPropertyTypes`.
- **Cross-OS & Cross-Node Verification:** Verified in CI across `ubuntu-latest`, `windows-latest`, `macos-latest` × Node `20`, `22`, `24` (9/9 matrix green).
- **Tree-Shakeable Packaging:** `"sideEffects": false` and explicit subpath `"exports"` (`"."`, `"./guard"`, `"./scanner"`).

---

## 5. Honest Scope & Non-Goals

- **Does NOT preempt synchronous CPU-bound infinite loops:** JavaScript is single-threaded; `timeoutMs` rescues async hangs and triggers `AbortSignal`, but cannot interrupt synchronous Flight deserialization DoS. Patching packages (`rsc-sentinel check`) and reverse-proxy/WAF timeouts remain mandatory.
- **Does NOT replace Next.js `serverActions.bodySizeLimit`:** Complements it with per-action fine-grained caps.
- **Yarn `fix`:** Yarn does not ship an automated `audit fix` command; `rsc-sentinel fix` detects Yarn and directs users to `yarn up <pkg>` / `resolutions`.

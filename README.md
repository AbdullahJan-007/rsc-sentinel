# rsc-sentinel

[![npm version](https://img.shields.io/npm/v/rsc-sentinel.svg)](https://www.npmjs.com/package/rsc-sentinel)
[![CI](https://github.com/AbdullahJan-007/rsc-sentinel/actions/workflows/ci.yml/badge.svg)](https://github.com/AbdullahJan-007/rsc-sentinel/actions/workflows/ci.yml)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/AbdullahJan-007/rsc-sentinel/blob/main/LICENSE)
[![node: >=20](https://img.shields.io/badge/node-%3E%3D20.0.0-brightgreen.svg)](https://nodejs.org)
[![zero dependencies](https://img.shields.io/badge/dependencies-0-brightgreen.svg)](https://www.npmjs.com/package/rsc-sentinel?activeTab=dependencies)

**Live React Server Components (RSC) vulnerability scanning and zero-dependency Server Action hardening for Next.js App Router.**

`rsc-sentinel` pairs a live CLI/programmatic scanner backed by npm's advisory database with a Web-standard runtime guard (`rsc-sentinel/guard`) built specifically for Next.js Server Actions, Edge Runtime, and CI pipelines.

---

## Features

- **Zero Runtime Dependencies** — Pure TypeScript compiled to clean ESM with `"sideEffects": false`.
- **Bundler-Safe Subpath Exports** — `rsc-sentinel/guard` uses zero Node.js builtins (`FormData`, `Blob`, `TextEncoder`, `AbortController`, `setTimeout`), preventing Turbopack/Webpack errors in Next.js App Router, Edge Runtime, and Client Components.
- **Next.js `"use server"` Native** — `createActionGuard()` works directly inside `export async function` declarations, returns RSC-serializable result unions (`safeRun`), and preserves `redirect()` / `notFound()` control-flow errors untouched.
- **Defense-in-Depth Input Guards** — Enforces `FormData` byte limits (including `File.name`), `FormData` entry caps (anti-field-flood), non-`FormData` payload byte limits, and circular-safe object nesting depth caps with short-circuit evaluation.
- **Cooperative Cancellation & Crash Safety** — Passes an `AbortSignal` into actions on timeout and captures late rejections via `onLateError` so Node.js never crashes with `UnhandledPromiseRejection`.
- **Live Multi-PM RSC Advisory Scanner** — Auto-detects `npm` (`package-lock.json`), `pnpm` (`pnpm-lock.yaml`), and `yarn` (`yarn.lock`) across Windows, macOS, and Linux; resolves the *actually installed* version in `node_modules` (including nested and monorepo-hoisted copies); tags RSC / Flight-protocol advisories; and supports `--rsc-only`, `--fail-on`, `--pm`, `--timeout`, `--json`, and **SARIF 2.1.0 (`--sarif`)** for GitHub Code Scanning.

---

## Installation

```bash
npm install rsc-sentinel
```

- **Node.js:** `>= 20.0.0`
- **Next.js:** `>= 15.0.0` (optional peer dependency — the CLI scanner runs on any npm project)

---

## Package Entrypoints

| Entrypoint | Runtime Target | Exports |
| --- | --- | --- |
| `rsc-sentinel/guard` | Next.js Server Actions, Edge Runtime, Browser, Node.js | `createActionGuard`, `withActionGuard`, `ActionGuardError`, `isActionGuardError`, `isNextControlFlowError` |
| `rsc-sentinel/scanner` | Node.js `>= 20` | `scan`, `analyzeAuditReport`, `filterScanResult`, `runNpmAudit`, `getInstalledVersion`, `NpmAuditError` |
| `rsc-sentinel` | Node.js `>= 20` | Re-exports both `./guard` and `./scanner` |

> **Next.js projects:** Always import from `rsc-sentinel/guard` inside App Router files (`"use server"`, Route Handlers, Edge Runtime, or Client Components) so bundlers never inspect Node.js scanner modules.

---

## Server Action Guard (`rsc-sentinel/guard`)

### Next.js App Router Usage

Next.js requires every export of a `"use server"` file to be an `export async function` declaration. Create a shared guard instance and invoke `guard.safeRun()` inside your exported action:

```ts
// app/actions.ts
"use server";

import { createActionGuard } from "rsc-sentinel/guard";

const contactGuard = createActionGuard({
  maxFormDataBytes: 512 * 1024, // 512 KiB
  maxFormDataEntries: 50,       // block field-flood payloads
  maxPayloadBytes: 256 * 1024,  // non-FormData argument cap
  maxObjectDepth: 16,           // block deeply nested payloads
  timeoutMs: 15_000,            // 15s async timeout + AbortSignal
  onBlocked: (reason, detail) => {
    console.warn(`[rsc-sentinel] blocked (${reason}): ${detail}`);
  },
  onLateError: (err) => {
    console.error("[rsc-sentinel] late error after timeout:", err);
  },
});

export async function submitContact(formData: FormData) {
  return contactGuard.safeRun([formData], async (signal) => {
    const email = String(formData.get("email") ?? "").trim();
    const res = await fetch("https://api.example.com/contact", {
      method: "POST",
      body: JSON.stringify({ email }),
      signal, // aborted automatically if timeoutMs is exceeded
    });
    return { status: res.status };
  });
}
```

### Handling Results on the Client

In Next.js production builds, thrown `Error` subclasses crossing the Server-to-Client boundary are stripped to a generic digest error. `safeRun()` returns a plain RSC-serializable discriminated union that works identically in development and production:

```ts
const result = await submitContact(formData);

if (!result.ok) {
  // result.error.reason: "size_limit" | "entry_limit" | "depth_limit" | "timeout"
  console.error(result.error.reason, result.error.message);
} else {
  console.log(result.data.status);
}
```

### Guard API

| Method | Behavior |
| --- | --- |
| `guard.run(args, (signal) => Promise<T>)` | Validates `args`, enforces `timeoutMs` with `AbortSignal`, throws `ActionGuardError` if blocked. |
| `guard.safeRun(args, (signal) => Promise<T>)` | Same as `run`, returning `{ ok: true, data } \| { ok: false, error: { reason, message } }`. Re-throws Next.js `redirect()` / `notFound()` errors untouched. |
| `guard.wrap(action)` / `withActionGuard(action, opts)` | Wraps an async function, throwing `ActionGuardError` if blocked. |
| `guard.wrapSafe(action)` | Wraps an async function, returning `ActionGuardResult<T>` if blocked. |

### Options Reference

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `maxFormDataBytes` | `number` | `1048576` (1 MiB) | Maximum total bytes across `FormData` keys, string values, `Blob.size`, and `File.name`. Short-circuits immediately on breach. |
| `maxFormDataEntries` | `number` | `1000` | Maximum number of entries allowed in a single `FormData` argument. |
| `maxPayloadBytes` | `number` | `1048576` (1 MiB) | Maximum estimated UTF-8/binary bytes across non-`FormData` arguments (strings, objects, arrays, TypedArrays, Blobs). |
| `maxObjectDepth` | `number` | `32` | Maximum nesting depth for objects, arrays, Maps, and Sets (circular-reference safe). |
| `timeoutMs` | `number` | `30000` (30s) | Async timeout in milliseconds; aborts the cooperative `AbortSignal`. |
| `onBlocked` | `(reason, detail) => void` | `undefined` | Observability callback invoked before rejection. Wrapped in `try/catch`. |
| `onLateError` | `(error) => void` | `undefined` | Captures rejections occurring after a timeout has already settled the call. |

All numeric options are validated eagerly at construction time and throw `RangeError` on `NaN`, `Infinity`, `0`, or negative values.

### Timeout Scope & Security Model

`timeoutMs` protects callers from hung **asynchronous** operations (stalled database queries, slow upstream fetches) and signals cancellation via `AbortSignal`. Because JavaScript runs on a single event loop, a JS timer cannot preempt a synchronous, CPU-bound loop (such as unpatched Flight deserialization DoS advisories like CVE-2026-23869). Keep React and Next.js patched (`npx rsc-sentinel check`) and enforce reverse-proxy or WAF timeouts at the edge.

---

## CLI Vulnerability Scanner

### Usage

```bash
# Scan the current project
npx rsc-sentinel check

# CI gate: fail only on HIGH or CRITICAL RSC-related findings, output JSON
npx rsc-sentinel check --rsc-only --fail-on high --json

# Scan a specific directory with a 30s timeout
npx rsc-sentinel check --path ./apps/web --timeout 30000

# Apply available non-breaking npm audit fixes
npx rsc-sentinel fix

# Allow semver-major upgrades (review & test before committing)
npx rsc-sentinel fix --force
```

### Commands & Flags

| Command / Flag | Description |
| --- | --- |
| `rsc-sentinel check` | Run a live vulnerability scan (default command). |
| `--json` | Output machine-readable JSON (including structured error payloads on exit code `2`). |
| `--sarif` | Output spec-compliant SARIF 2.1.0 JSON for GitHub Code Scanning. |
| `--path <dir>` | Target project directory (defaults to `process.cwd()`). |
| `--pm <manager>` | Package manager: `auto` \| `npm` \| `pnpm` \| `yarn` (default: `auto`). |
| `--rsc-only` | Report and gate exit code strictly on RSC / Flight-protocol findings. |
| `--fail-on <severity>` | Minimum severity threshold: `info` \| `low` \| `moderate` \| `high` \| `critical` (default: `info`). |
| `--timeout <ms>` | Timeout for the audit command in milliseconds (default: `60000`). |
| `rsc-sentinel fix [--force]` | Delegate remediation to `npm audit fix` / `pnpm audit --fix`. |
| `-h, --help` | Print usage information. |
| `-v, --version` | Print installed version. |

### Exit Codes

| Code | Meaning |
| --- | --- |
| `0` | Clean — no findings meeting the filter threshold. |
| `1` | Vulnerabilities detected (or `fix` left unresolved advisories). |
| `2` | Invalid arguments, unknown command, missing `package.json` or `package-lock.json`, `npm` unavailable, or timeout. |

### GitHub Actions & Code Scanning (SARIF)

```yaml
- name: Check RSC security advisories
  run: npx rsc-sentinel check --rsc-only --fail-on high --sarif > rsc-sentinel.sarif

- name: Upload SARIF to GitHub Security tab
  if: always()
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: rsc-sentinel.sarif
```

### Programmatic Scanner API (`rsc-sentinel/scanner`)

```ts
import { scan } from "rsc-sentinel/scanner";

const result = await scan({
  projectPath: process.cwd(),
  rscOnly: true,
  minSeverity: "high",
  timeoutMs: 30_000,
});

if (!result.clean) {
  console.error(`Found ${result.rscFindings.length} RSC findings`);
}
```

---

## Documentation & Examples

- [Changelog](https://github.com/AbdullahJan-007/rsc-sentinel/blob/main/CHANGELOG.md)
- [Security Policy](https://github.com/AbdullahJan-007/rsc-sentinel/blob/main/SECURITY.md)
- [Next.js App Router Demo](https://github.com/AbdullahJan-007/rsc-sentinel/tree/main/examples/nextjs-demo)
- [Product Requirements (PRD)](https://github.com/AbdullahJan-007/rsc-sentinel/blob/main/docs/PRD.md)
- [System Architecture](https://github.com/AbdullahJan-007/rsc-sentinel/blob/main/docs/architecture.md)
- [Technical Design](https://github.com/AbdullahJan-007/rsc-sentinel/blob/main/docs/design.md)
- [Engineering & Security Standards](https://github.com/AbdullahJan-007/rsc-sentinel/blob/main/docs/rules.md)
- [Architecture Decisions & Security Audit](https://github.com/AbdullahJan-007/rsc-sentinel/blob/main/docs/memory.md)
- [Release Tracker](https://github.com/AbdullahJan-007/rsc-sentinel/blob/main/docs/tracker.md)

---

## License

MIT © [Abdullah Jan](https://github.com/AbdullahJan-007)

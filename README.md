# rsc-sentinel

[![npm version](https://img.shields.io/npm/v/rsc-sentinel.svg)](https://www.npmjs.com/package/rsc-sentinel)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)
[![node: >=20](https://img.shields.io/badge/node-%3E%3D20.0.0-brightgreen.svg)](https://nodejs.org)

**Live vulnerability scanning and production-hardened Server Action guards for Next.js App Router & React Server Components (RSC).**

Zero runtime dependencies. Tree-shakeable subpath exports. Built for Node.js 20+ (Windows, macOS, Linux) and Next.js 15/16 App Router.

---

## Why `rsc-sentinel`?

1. **Live RSC Vulnerability Scanner (`rsc-sentinel` CLI & `rsc-sentinel/scanner`):**
   Queries npm's live advisory database (`npm audit --json`) at runtime — never a stale hardcoded CVE list. Resolves the *actually installed* version from `node_modules` (including nested and monorepo-hoisted copies), highlights React Server Components / Flight-protocol advisories (such as CVE-2026-23869 and successors), and gives CI pipelines deterministic exit codes and strict JSON output.
2. **Next.js-Native Server Action Guard (`rsc-sentinel/guard`):**
   Zero Node.js builtins (Web-standard APIs only — safe in Server Actions, Edge Runtime, and Client Components). Adds per-action defense-in-depth:
   - `FormData` byte limits (including `File.name` bytes, short-circuiting early)
   - `FormData` entry limits (blocks field-flood DoS)
   - Non-`FormData` payload byte & object nesting depth limits (circular-reference safe)
   - Async hang timeouts with cooperative `AbortSignal` cancellation & zero unhandled rejections
   - RSC-serializable `ActionGuardResult<T>` for `useActionState` (works in Next.js production builds where thrown errors are stripped)
   - Automatic passthrough for Next.js `redirect()` / `notFound()` control-flow errors

---

## Install

```bash
npm install rsc-sentinel
```

Requires **Node.js >= 20.0.0**. Next.js (`>= 15.0.0`) is an optional peer dependency — you can use the CLI scanner on any npm project.

---

## Package Entrypoints

| Import Path | Runtime | Use Case |
| --- | --- | --- |
| `rsc-sentinel/guard` | Next.js Server Actions, Edge Runtime, Browser, Node.js | **Recommended for Next.js apps.** Zero Node.js builtins (`createActionGuard`, `withActionGuard`, `ActionGuardError`, `isActionGuardError`). |
| `rsc-sentinel/scanner` | Node.js `>= 20` | Programmatic vulnerability scanning (`scan`, `analyzeAuditReport`, `filterScanResult`, `NpmAuditError`). |
| `rsc-sentinel` | Node.js `>= 20` | Convenience root barrel re-exporting both. |

---

## Quick Start: Next.js App Router Server Action Guard

> **Next.js `"use server"` rule:** Every export in a `"use server"` file must be an `export async function` declaration (not `export const x = withActionGuard(...)`). Use `createActionGuard()` inside your exported `async function`:

```ts
// app/actions.ts
"use server";

import { createActionGuard } from "rsc-sentinel/guard";

const contactGuard = createActionGuard({
  maxFormDataBytes: 512 * 1024, // 512 KiB
  maxFormDataEntries: 50,       // block field-flood DoS
  maxPayloadBytes: 256 * 1024,  // non-FormData args cap
  maxObjectDepth: 16,           // block deeply-nested object DoS
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
      signal, // automatically aborted if timeoutMs fires
    });
    return { status: res.status };
  });
}
```

### Handling Results in a Client Component

Because `safeRun` returns a plain RSC-serializable union (`{ ok: true, data } | { ok: false, error: { reason, message } }`), it works identically in development and production builds:

```ts
const result = await submitContact(formData);
if (!result.ok) {
  // result.error.reason: "size_limit" | "entry_limit" | "depth_limit" | "timeout"
  console.log(result.error.reason, result.error.message);
}
```

### Guard Options

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `maxFormDataBytes` | `number` | `1048576` (1 MiB) | Max total bytes across keys, string values, `Blob.size`, and `File.name`. Short-circuits immediately when exceeded. |
| `maxFormDataEntries` | `number` | `1000` | Max number of entries allowed in a `FormData` argument. |
| `maxPayloadBytes` | `number` | `1048576` (1 MiB) | Max estimated UTF-8/binary bytes across non-`FormData` arguments. |
| `maxObjectDepth` | `number` | `32` | Max nesting depth for objects/arrays/Maps/Sets (circular-safe). |
| `timeoutMs` | `number` | `30000` (30s) | Async timeout in milliseconds; aborts the `AbortSignal` passed to `run`/`safeRun`. |
| `onBlocked` | `(reason, detail) => void` | `undefined` | Observability hook called before rejecting. Isolated in `try/catch`. |
| `onLateError` | `(error) => void` | `undefined` | Captures rejections occurring after timeout so Node.js never emits `UnhandledPromiseRejection`. |

### Honest Scope of `timeoutMs`

`timeoutMs` rescues callers from hung **asynchronous** work (stalled DB queries, unresponsive upstream fetches) and triggers cooperative cancellation via `AbortSignal`. Because JavaScript runs on a single event loop, a JS timer **cannot** preempt a synchronous, CPU-bound infinite loop (such as unpatched CVE-2026-23869 Flight deserialization DoS). Always stay on patched React/Next.js versions (`npx rsc-sentinel check`) and enforce reverse-proxy / WAF timeouts at the infrastructure layer.

---

## Quick Start: CLI Vulnerability Scanner

### Check your project

```bash
npx rsc-sentinel check
```

### CI / Production Flags

```bash
# Fail CI only on HIGH or CRITICAL RSC-related vulnerabilities, outputting JSON:
npx rsc-sentinel check --rsc-only --fail-on high --json

# Scan another directory with a custom 30s timeout:
npx rsc-sentinel check --path ./apps/web --timeout 30000

# Apply non-breaking npm fixes (or allow semver-major with --force):
npx rsc-sentinel fix
npx rsc-sentinel fix --force
```

### All Commands & Flags

| Command / Flag | Description |
| --- | --- |
| `rsc-sentinel check` | Scan project and print a human-readable report (default command). |
| `--json` | Emit machine-readable JSON (including structured errors on exit code `2`). |
| `--path <dir>` | Project directory to scan (defaults to `process.cwd()`). |
| `--rsc-only` | Report and gate exit code strictly on RSC / Flight-protocol findings. |
| `--fail-on <severity>` | Minimum severity threshold: `info` \| `low` \| `moderate` \| `high` \| `critical` (default: `info`). |
| `--timeout <ms>` | Timeout for `npm audit --json` in milliseconds (default: `60000`). |
| `rsc-sentinel fix [--force]` | Run `npm audit fix` (with optional `--force` for semver-major upgrades). |
| `-h, --help` | Print CLI help. |
| `-v, --version` | Print installed version. |

### Exit Codes

| Exit Code | Meaning |
| --- | --- |
| `0` | Clean — no vulnerabilities matching the filter criteria. |
| `1` | Vulnerabilities found (or `fix` left unresolved issues). |
| `2` | Invalid arguments, unknown command, missing `package.json` / `package-lock.json`, `npm` unavailable, or timeout. |

### GitHub Actions Example

```yaml
- name: Scan for RSC vulnerabilities
  run: npx rsc-sentinel check --rsc-only --fail-on high
```

---

## Engineering Documentation

- [Product Requirements (PRD)](./docs/PRD.md)
- [System Architecture](./docs/architecture.md)
- [Technical Design](./docs/design.md)
- [Engineering & Security Rules](./docs/rules.md)
- [Red-Team Audit Log & Decisions](./docs/memory.md)
- [Release Tracker](./docs/tracker.md)

---

## Development & Verification

```bash
npm install
npm run typecheck
npm test            # Unit + Security Red-Team + CLI Integration suites
npm run pack:check  # Verify npm tarball contents
```

## License

MIT © Abdullah Jan

# Changelog

All notable changes to `rsc-sentinel` are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-11-28

### Added
- **Subpath exports:** `rsc-sentinel/guard` (zero Node.js builtins, safe for Next.js App Router, Edge Runtime, and Client Components) and `rsc-sentinel/scanner` (Node.js `>= 20`).
- **Next.js `"use server"` native guard API:** `createActionGuard()` with `run()`, `safeRun()`, `wrap()`, `wrapSafe()`, cooperative `AbortSignal` timeout cancellation, RSC-serializable `ActionGuardResult<T>`, and `isNextControlFlowError()` passthrough for `redirect()` / `notFound()`.
- **Defense-in-depth guard limits:** `maxFormDataEntries`, `maxPayloadBytes`, `maxObjectDepth`, `File.name` byte accounting, circular-reference protection, short-circuiting payload inspection, and `onLateError` unhandled-rejection protection.
- **Multi-package-manager scanner:** Auto-detects and scans `npm` (`package-lock.json`), `pnpm` (`pnpm-lock.yaml`), and `yarn` (`yarn.lock` — both Yarn Berry and Yarn Classic) with `--pm <auto|npm|pnpm|yarn>`.
- **SARIF 2.1.0 output:** `--sarif` CLI flag and `toSarif()` API for GitHub Code Scanning (`github/codeql-action/upload-sarif@v3`).
- **CI CLI flags:** `--rsc-only`, `--fail-on <severity>`, `--timeout <ms>`, and structured JSON errors in `--json` mode.
- **GitHub Actions CI & Release workflows:** Cross-OS matrix (Ubuntu, Windows, macOS × Node 20, 22, 24) and npm provenance publishing workflow.
- **Documentation & Tests:** Full engineering docs (`docs/`), `SECURITY.md`, `CHANGELOG.md`, and 45+ unit, security red-team, and CLI integration tests compiled for Node 20+.

### Fixed
- Removed accidental circular self-dependency (`"rsc-sentinel"` inside `dependencies`) — package now has zero runtime dependencies.
- Fixed Windows `ENOENT` crash when executing `npm`/`pnpm`/`yarn` `.cmd` shims under Node.js 20.12+/22/24.
- Fixed silent guard bypass when `NaN`, `0`, `Infinity`, or negative numbers were passed as options (now throws `RangeError` eagerly).
- Fixed `UnhandledPromiseRejection` crash when a timed-out action rejected after `Promise.race` settled.
- Fixed path-traversal risk in `getInstalledVersion` and added support for nested `vuln.nodes` and monorepo-hoisted `node_modules`.
- Fixed `fixAvailable: true` reporting "none published yet", surfaced `fixPackage` for transitive upgrades, loaded CLI version dynamically from `package.json`, and returned exit code `2` for unknown commands/flags.

## [0.1.0] - 2026-08-01

### Added
- Initial live `npm audit --json` RSC vulnerability scanner (`rsc-sentinel check` / `rsc-sentinel fix`).
- Initial `withActionGuard` Server Action wrapper with `maxFormDataBytes` and `timeoutMs`.

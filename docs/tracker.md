# Release Tracker — `rsc-sentinel`

## `v0.2.0` — Production Hardening, Multi-PM Scanner, SARIF & CI

| ID | Area | Scope | Status | Verification |
| --- | --- | --- | --- | --- |
| **T-01** | Security Audit | End-to-end audit of `v0.1.0` scanner, guard, CLI, and packaging | Completed | 10 issues documented in `docs/memory.md` |
| **T-02** | Packaging | Zero runtime dependencies, `./guard` & `./scanner` exports, `sideEffects: false`, repository metadata | Completed | `npm pack --dry-run` verified (39.8 kB, 60 files) |
| **T-03** | Guard | Zero Node builtins, `createActionGuard`, `safeRun`, `AbortSignal`, entry/depth/payload limits, cycle safety, `onLateError`, Next.js redirect passthrough | Completed | Unit & red-team security suites passing |
| **T-04** | Multi-PM Scanner | Cross-platform `execPackageManager` (`npm`, `pnpm`, `yarn`), lockfile auto-detection, path-safe `getInstalledVersion`, normalized `fixAvailable` & `fixPackage`, deterministic sorting | Completed | Unit & CLI live tests passing |
| **T-05** | SARIF 2.1.0 | `toSarif()` formatter and `--sarif` CLI flag for GitHub Code Scanning | Completed | Unit & CLI integration tests passing |
| **T-06** | CLI | Dynamic version loading, clean `parseArgs` errors, unknown command exit `2`, `--pm`, `--rsc-only`, `--fail-on`, `--timeout`, `--json`, `--sarif` | Completed | Subprocess integration suite passing |
| **T-07** | CI & Cross-OS Tests | Explicit `scripts/run-tests.mjs` runner + GitHub Actions CI matrix (Ubuntu/Windows/macOS × Node 20/22/24) + provenance npm release workflow | Completed | **9/9 CI jobs green** (Run #46116419243, 47/47 tests) |
| **T-08** | Docs & Policies | npm-ready `README.md`, `CHANGELOG.md`, `SECURITY.md`, `docs/*`, updated `examples/nextjs-demo` | Completed | All docs synced with `v0.2.0` |
| **T-09** | npm Release | Publish `rsc-sentinel@0.2.0` to npm registry (via `npm publish` or `v0.2.0` tag) | Ready to Publish | Push tag `v0.2.0` or run `npm publish` |

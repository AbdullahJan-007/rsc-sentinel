# Release Tracker — `rsc-sentinel`

## `v0.2.0` — Production Hardening & Next.js Subpath Exports

| ID | Area | Scope | Status | Verification |
| --- | --- | --- | --- | --- |
| **T-01** | Security Audit | End-to-end audit of `v0.1.0` scanner, guard, CLI, and packaging | Completed | 10 issues documented in `docs/memory.md` |
| **T-02** | Packaging | Zero runtime dependencies, `./guard` & `./scanner` exports, `sideEffects: false`, repository metadata | Completed | `npm pack --dry-run` verified |
| **T-03** | Guard | Zero Node builtins, `createActionGuard`, `safeRun`, `AbortSignal`, entry/depth/payload limits, cycle safety, `onLateError`, Next.js redirect passthrough | Completed | Unit & security test suites passing |
| **T-04** | Scanner | Cross-platform `execNpm`, path-safe `getInstalledVersion` (nested + monorepo), normalized `fixAvailable` & `fixPackage`, deterministic sorting, `filterScanResult` | Completed | Unit & Windows CLI live scan passing |
| **T-05** | CLI | Dynamic version loading, clean `parseArgs` errors, unknown command exit `2`, `--rsc-only`, `--fail-on`, `--timeout`, structured `--json` errors | Completed | Subprocess integration suite passing |
| **T-06** | Examples | Updated `examples/nextjs-demo` to `rsc-sentinel/guard` and valid `"use server"` `export async function` | Completed | Aligned with Next.js 15/16 App Router |
| **T-07** | Testing | Unit, security red-team, and CLI integration suites compiled via `tsconfig.test.json` for Node 20+ | Completed | 36/36 tests passing |
| **T-08** | Documentation | `README.md` (npm-ready), `docs/PRD.md`, `docs/architecture.md`, `docs/design.md`, `docs/rules.md`, `docs/memory.md`, `docs/tracker.md` | Completed | All links and examples verified |
| **T-09** | npm Release | Publish `rsc-sentinel@0.2.0` to npm registry | Ready to Publish | Run `npm publish` |

---

## Roadmap (`v0.3.0`)

- [ ] `pnpm-lock.yaml` (`pnpm audit --json`) scanner adapter
- [ ] `yarn.lock` (`yarn npm audit --json`) scanner adapter
- [ ] SARIF (`--sarif`) output for GitHub Code Scanning
- [ ] GitHub Actions CI matrix (Node 20 / 22 / 24 on Linux, macOS, Windows)

# Release & Engineering Tracker — `rsc-sentinel`

## Current Release: `v0.2.0` (Production Hardening & Next.js Subpath Exports)

| Task ID | Category | Description | Status | Verification |
| --- | --- | --- | --- | --- |
| **T-01** | Audit | Full Staff Engineer & Security Red-Team audit of v0.1.0 | ✅ Done | 10 critical/high/medium issues logged in `docs/memory.md` |
| **T-02** | Packaging | Remove circular self-dependency; add `./guard` & `./scanner` exports, `sideEffects: false`, repo metadata | ✅ Done | `npm pack --dry-run` verified |
| **T-03** | Guard | Harden `protect-action.ts`: zero Node builtins, `createActionGuard`, `safeRun`, `AbortSignal`, entry/depth/payload limits, cycle safety, `onLateError`, Next.js redirect passthrough | ✅ Done | Unit + Red-Team tests passing |
| **T-04** | Scanner | Cross-platform `execNpm` (fixes Windows `ENOENT`), path-safe `getInstalledVersion` (nested + monorepo), `fixAvailable` boolean + `fixPackage`, deterministic sorting, `filterScanResult` | ✅ Done | Unit + Windows live scan passing |
| **T-05** | CLI | Dynamic version from `package.json`, graceful `parseArgs`, unknown command exit `2`, `--rsc-only`, `--fail-on`, `--timeout`, structured `--json` errors | ✅ Done | Integration subprocess tests passing |
| **T-06** | Examples | Fix `examples/nextjs-demo/app/actions.ts` to use `rsc-sentinel/guard` and valid `"use server"` `export async function` | ✅ Done | Updated & aligned with Next.js 15/16 |
| **T-07** | Tests | Unit (`tests/unit/*`), Security Red-Team (`tests/security/*`), Integration (`tests/integration/*`) compiled via `tsconfig.test.json` for Node 20+ | ✅ Done | All suites passing with 0 warnings |
| **T-08** | Docs | Author `docs/PRD.md`, `docs/architecture.md`, `docs/design.md`, `docs/rules.md`, `docs/memory.md`, `docs/tracker.md` and upgrade `README.md` | ✅ Done | All docs complete & accurate |
| **T-09** | Publish | Run `npm publish` to update npm registry page to `v0.2.0` | ⏳ Ready for User | Run `npm publish` after `git commit` & `git push` |

---

## Upcoming Roadmap (`v0.3.0`)
- [ ] `pnpm-lock.yaml` (`pnpm audit --json`) adapter support
- [ ] `yarn.lock` (`yarn npm audit --json`) adapter support
- [ ] SARIF output format (`--sarif`) for GitHub Code Scanning / Security tab integration
- [ ] GitHub Actions CI workflow matrix (Node 20 / 22 / 24 on Ubuntu, macOS, Windows)

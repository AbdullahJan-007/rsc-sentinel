# Engineering, Security & Release Rules — `rsc-sentinel`

These rules are mandatory for all human contributors and AI agents working on `rsc-sentinel`.

---

## 1. Runtime & Bundler Isolation Rules
1. **Zero Node.js builtins in `src/middleware/*` and `src/guard.ts`:**
   - Never import `node:fs`, `node:child_process`, `node:path`, `node:os`, or `node:util` inside the guard entrypoint (`rsc-sentinel/guard`).
   - Only Web-standard APIs (`FormData`, `Blob`, `File`, `TextEncoder`, `AbortController`, `setTimeout`, `ArrayBuffer`) are permitted so Next.js App Router, Edge Runtime, and Client Components bundle cleanly.
2. **Zero Runtime Dependencies:**
   - `package.json` `"dependencies"` MUST remain absent/empty.
   - Never accidentally add `rsc-sentinel` to its own `dependencies`.
3. **Next.js `"use server"` Compliance:**
   - All docs and examples MUST use `export async function ...` declarations inside `"use server"` files — NEVER `export const action = withActionGuard(...)`.
   - Always preserve Next.js control-flow errors (`NEXT_REDIRECT`, `NEXT_NOT_FOUND`, `NEXT_HTTP_ERROR_FALLBACK`) untouched.

---

## 2. TypeScript & Code Quality Rules
1. **Strict Compiler Flags:** Never weaken `strict`, `noUncheckedIndexedAccess`, or `exactOptionalPropertyTypes` in `tsconfig.json`.
2. **No `any` or `@ts-ignore`:** Use `unknown` and narrow with explicit runtime guards.
3. **No Experimental Node Flags in Tests or Runtime:** `npm test` and CLI execution MUST work cleanly on Node.js `>= 20.0.0` with zero experimental flags.
4. **Dynamic Versioning:** Never hardcode the package version in `src/cli.ts`; always read from `package.json`.

---

## 3. Security & Red-Team Rules
1. **Fail Closed on Invalid Configuration:** Every numeric limit in `ActionGuardOptions` MUST be validated eagerly as a positive finite number (`RangeError` on `NaN`, `Infinity`, `<= 0`).
2. **Zero Unhandled Rejections:** Any `Promise.race` timeout MUST attach a rejection handler to the background action promise (`onLateError`) so late failures cannot crash the Node.js process.
3. **Observability Cannot Break Security:** `onBlocked` and `onLateError` callbacks MUST execute inside `try/catch`.
4. **Path Traversal Protection:** Any path derived from external audit reports (`packageName`, `vuln.nodes`) MUST be regex-validated and containment-checked (`isPathInside`) before filesystem reads.
5. **Cross-Platform Safe Subprocess Execution:** Never pass untrusted user input into a shell command. Only fixed allowlisted `npm` arguments may be executed via `execNpm`.
6. **Honest Security Claims:** Never claim `timeoutMs` can preempt synchronous CPU-bound loops. Always document its exact async scope.

---

## 4. Pre-Publish Verification Checklist
Before running `npm publish`, ALL of the following MUST pass:
```bash
npm run clean
npm run typecheck
npm test
npm run pack:check
```
- Verify `npm pack --dry-run` contains ONLY `dist/`, `bin/`, `README.md`, `LICENSE`, `package.json` (no `tests/`, `dist-test/`, `examples/`, or `.tgz`).
- Verify `node ./bin/rsc-sentinel.js --version` matches `package.json`.
- Verify `node ./bin/rsc-sentinel.js check` succeeds on Windows/POSIX.

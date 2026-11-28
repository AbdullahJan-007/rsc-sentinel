# Engineering & Security Standards — `rsc-sentinel`

Standards governing runtime isolation, TypeScript safety, security invariants, CI compatibility, and npm release verification for `rsc-sentinel`.

---

## 1. Runtime & Bundler Isolation

1. **Zero Node.js Builtins in `rsc-sentinel/guard`:**
   - `src/guard.ts` and `src/middleware/*` MUST NOT import `node:fs`, `node:child_process`, `node:path`, `node:os`, or `node:util`.
   - Only Web-standard APIs (`FormData`, `Blob`, `File`, `TextEncoder`, `AbortController`, `setTimeout`, `ArrayBuffer`) are permitted so Next.js App Router, Edge Runtime, and Client Components bundle cleanly.
2. **Zero Runtime Dependencies:**
   - `package.json` `"dependencies"` MUST remain empty.
3. **Next.js `"use server"` Compatibility:**
   - Documentation and examples MUST use `export async function` declarations inside `"use server"` modules.
   - Next.js internal control-flow errors (`NEXT_REDIRECT`, `NEXT_NOT_FOUND`, `NEXT_HTTP_ERROR_FALLBACK`) MUST always be re-thrown untouched.

---

## 2. TypeScript & Cross-Platform Compatibility

1. **Strict Compiler Settings:** Maintain `strict`, `noUncheckedIndexedAccess`, and `exactOptionalPropertyTypes` in `tsconfig.json`.
2. **Type Safety:** Avoid `any` and `@ts-ignore`; use `unknown` with explicit runtime type guards.
3. **Node.js `>= 20.0.0` Compatibility:** Runtime code and tests MUST run cleanly across Linux, macOS, and Windows on Node.js 20, 22, and 24 without experimental flags or shell glob assumptions (`scripts/run-tests.mjs` passes explicit file paths to `node --test`).
4. **Single Source of Truth for Version:** `src/cli.ts` reads the package version dynamically from `package.json`.

---

## 3. Security Invariants

1. **Fail Closed on Invalid Options:** All numeric limits in `ActionGuardOptions` are validated eagerly and throw `RangeError` on `NaN`, `Infinity`, `0`, or negative values.
2. **Zero Unhandled Rejections:** Timeout races attach a `.catch()` handler to the background action promise (`onLateError`) so late failures never terminate the Node.js process.
3. **Isolated Observability Hooks:** `onBlocked` and `onLateError` execute inside `try/catch` so logging failures cannot bypass or mask guard rejections.
4. **Path Containment:** Package names and `vuln.nodes` entries from audit reports are regex-validated and containment-checked (`isPathInside`) before filesystem reads.
5. **Safe Subprocess Execution:** Only fixed, static package manager arguments (`npm`, `pnpm`, `yarn`) are passed to `execPackageManager`; untrusted user input is never interpolated into shell commands.
6. **Accurate Security Claims:** Documentation explicitly distinguishes async timeout protection from synchronous CPU-exhaustion bugs.

---

## 4. Pre-Release Verification

Before publishing to npm, run:

```bash
npm run clean
npm run typecheck
npm test
npm run pack:check
```

Verify:
- All 9 CI matrix jobs (`ubuntu`, `windows`, `macos` × Node `20`, `22`, `24`) are green.
- `npm pack --dry-run` includes only `dist/`, `bin/`, `README.md`, `LICENSE`, and `package.json`.
- `node ./bin/rsc-sentinel.js --version` matches `package.json`.

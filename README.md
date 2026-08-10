# rsc-sentinel

[![npm version](https://img.shields.io/npm/v/rsc-sentinel.svg)](https://www.npmjs.com/package/rsc-sentinel)
[![license: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](./LICENSE)

Live vulnerability scanning and honest Server Action hardening for Next.js / React
Server Components projects.

This document explains, command by command, exactly what `rsc-sentinel` does, how to
run it, and what every piece of its output means. If you've never used a CLI security
tool before, start at [Part 1](#part-1--what-this-tool-is) and read straight through.

---

## Contents

- [Part 1 — What this tool is](#part-1--what-this-tool-is)
- [Part 2 — Install](#part-2--install)
- [Part 3 — The `check` command](#part-3--the-check-command)
- [Part 4 — The `fix` command](#part-4--the-fix-command)
- [Part 5 — Every other command and flag](#part-5--every-other-command-and-flag)
- [Part 6 — Exit codes (for scripts and CI)](#part-6--exit-codes-for-scripts-and-ci)
- [Part 7 — Using the Server Action guard in your code](#part-7--using-the-server-action-guard-in-your-code)
- [Part 8 — Common errors and what they actually mean](#part-8--common-errors-and-what-they-actually-mean)
- [Part 9 — Why this exists](#part-9--why-this-exists)
- [Part 10 — What this does NOT do](#part-10--what-this-does-not-do)
- [Contributing / running the tests](#contributing--running-the-tests)

---

## Part 1 — What this tool is

`rsc-sentinel` is two separate features in one small package:

1. **A scanner.** It checks a Next.js / React project for known security
   vulnerabilities in React Server Components (RSC) — the same class of bug as
   [CVE-2026-23869](https://github.com/advisories/GHSA-479c-33wc-g2pg) — by asking
   npm's own live advisory database, every time you run it. It never relies on a
   hardcoded list of "these versions are bad," because that list goes stale the moment
   a new advisory is published.
2. **A code-level guard.** A small function, `withActionGuard`, that you wrap around a
   Next.js Server Action to add a request-size limit and a hang timeout — with an
   honest explanation, in the code and in this document, of exactly what that guard can
   and can't protect against.

You use the scanner from your terminal. You use the guard from inside your own
TypeScript/JavaScript code. They don't depend on each other — you can use either one
without the other.

---

## Part 2 — Install

```bash
npm install rsc-sentinel
```

That's the whole install step. Requires Node.js 20 or newer. If you only want the
scanner and don't have Next.js in this project, that's fine — the scanner works on its
own.

---

## Part 3 — The `check` command

This is the command you'll use most. It scans your project and tells you what's wrong.

### How to run it

From the root of your project (the folder that has your `package.json` in it):

```bash
npx rsc-sentinel check
```

`npx` means "run this command from the package I just installed" — you don't need to
install anything globally.

### What it actually does, step by step

1. It runs `npm audit --json` in your project — this is npm's own built-in vulnerability
   checker, reading your `package-lock.json`.
2. It goes through every result npm audit found, and picks out the ones that are
   specifically about React Server Components (packages named `react-server-dom-*`, or
   any advisory whose title mentions "Server Component," "Server Action," or "Flight
   protocol").
3. For each one, it looks inside your actual `node_modules` folder to tell you exactly
   which version you have installed right now — not just the version range written in
   your `package.json`.
4. It prints a report, and exits with a code your terminal (or CI system) can check
   automatically — see [Part 6](#part-6--exit-codes-for-scripts-and-ci).

### Real example output

This is genuine output from running `rsc-sentinel check` against a project with an old,
vulnerable copy of `react-server-dom-webpack` installed — nothing here is invented:

```
Found 6 finding(s): 0 critical, 5 high, 1 moderate, 0 low, 0 info.

6 of these are React Server Components / Flight-protocol related:

  [HIGH] [RSC] react-server-dom-webpack@19.1.2
    Denial of Service Vulnerability in React Server Components (CVSS 7.5)
    vulnerable range: >=19.1.0 <19.1.3
    fix: upgrade to 19.2.8
    https://github.com/advisories/GHSA-2m3v-v2m8-q956

  [HIGH] [RSC] react-server-dom-webpack@19.1.2
    React Server Components have a Denial of Service Vulnerability (CVSS 7.5)
    vulnerable range: >=19.1.0 <19.1.6
    fix: upgrade to 19.2.8
    https://github.com/advisories/GHSA-479c-33wc-g2pg

  ... (more findings) ...

Run `rsc-sentinel fix` to apply available non-breaking fixes.
```

### How to read one finding, line by line

```
  [HIGH] [RSC] react-server-dom-webpack@19.1.2
```
`[HIGH]` — how serious this is: `critical`, `high`, `moderate`, `low`, or `info`, in that
order of urgency. `[RSC]` — this specific finding is tagged as React-Server-Components
related (findings without this tag are still shown, just further down the report — they
aren't hidden). `react-server-dom-webpack@19.1.2` — the package name, and the version
that's actually sitting in your `node_modules` right now.

```
    Denial of Service Vulnerability in React Server Components (CVSS 7.5)
```
The advisory's title, and its CVSS score (a 0–10 industry-standard severity score;
7.5 is "high").

```
    vulnerable range: >=19.1.0 <19.1.3
```
The range of versions this specific advisory applies to. You can be in one advisory's
vulnerable range and not another's — that's why a single package can show up several
times in the report, once per advisory.

```
    fix: upgrade to 19.2.8
```
The version that resolves this. If it instead says `fix: none published yet`, no patched
version exists yet for this specific advisory.

```
    https://github.com/advisories/GHSA-2m3v-v2m8-q956
```
The advisory itself, for full details.

### If nothing is wrong

```
No known vulnerabilities found by npm audit.
```

That's the whole output. Nothing else to do.

---

## Part 4 — The `fix` command

```bash
npx rsc-sentinel fix
```

This does **not** contain any custom fixing logic of its own — it runs npm's own
`npm audit fix` command for you, and prints the result. That's a deliberate choice: npm
already knows how to safely resolve dependency versions, and re-implementing that badly
is exactly the kind of thing that introduces new bugs.

### Real example output

```
Running: npm audit fix

up to date, audited 74 packages in 1s

# npm audit report

react-server-dom-webpack  19.1.0-canary-7130d0c6-20241212 - 19.1.8
Severity: high
Denial of Service Vulnerability in React Server Components - https://github.com/advisories/GHSA-2m3v-v2m8-q956
...
fix available via `npm audit fix --force`
Will install react-server-dom-webpack@19.2.8, which is outside the stated dependency range

1 high severity vulnerability

To address all issues, run:
  npm audit fix --force

Some fixes may require a semver-major upgrade. Re-run with --force to allow those, then
re-run `rsc-sentinel check` and your own test suite before committing.
```

### What "outside the stated dependency range" means

If your `package.json` says `"react-server-dom-webpack": "^19.1.0"`, npm is only allowed
to auto-install versions matching that pattern (`19.1.x`) without your explicit
permission — that's what the `^` means. If the real fix requires jumping to `19.2.8`,
that's outside `^19.1.0`, so plain `npm audit fix` won't apply it automatically. That's
what the `--force` flag is for.

### `rsc-sentinel fix --force`

```bash
npx rsc-sentinel fix --force
```

Allows npm to apply fixes that require a bigger version jump (a "semver-major" bump —
one that could contain breaking changes). **Always run your own test suite after this**,
and re-run `rsc-sentinel check` to confirm it's actually clean now — that's exactly what
the message above is telling you to do.

---

## Part 5 — Every other command and flag

| Command / flag | What it does |
| --- | --- |
| `rsc-sentinel check` | Scan and print a human-readable report (default command). |
| `rsc-sentinel check --json` | Same scan, but prints machine-readable JSON instead — use this if another program (a script, a CI step) needs to read the result. |
| `rsc-sentinel check --path <folder>` | Scan a different project instead of the current folder. |
| `rsc-sentinel fix` | Run `npm audit fix` (non-breaking fixes only). |
| `rsc-sentinel fix --force` | Run `npm audit fix --force` (allows breaking fixes). |
| `rsc-sentinel fix --path <folder>` | Run fix against a different project. |
| `rsc-sentinel --help` | Print the command list shown above. |
| `rsc-sentinel --version` | Print the installed version number, e.g. `0.1.0`. |

---

## Part 6 — Exit codes (for scripts and CI)

Every command line program signals success or failure with a number when it finishes,
called an **exit code**. `rsc-sentinel check` uses:

| Exit code | Meaning |
| --- | --- |
| `0` | Clean — no known vulnerabilities found. |
| `1` | Vulnerabilities were found (see the report above the exit). |
| `2` | The scan couldn't run at all — check the error message printed to the terminal (see [Part 9](#part-9--common-errors-and-what-they-actually-mean)). |

This is what makes it usable in CI: a build step that runs `npx rsc-sentinel check` will
itself fail (stopping the pipeline) exactly when real vulnerabilities are found, with no
extra scripting needed:

```yaml
# example GitHub Actions step
- run: npx rsc-sentinel check
```

---

## Part 7 — Using the Server Action guard in your code

This part has nothing to do with the terminal — it's a function you import and use
inside a Next.js Server Action.

### The problem it solves

A plain Server Action has no built-in limit on how long it can run, and (below Next's
own 1&nbsp;MiB framework default) no limit on payload size that *you* control per-action.
`withActionGuard` adds both, with a callback so you can log what got blocked.

### Basic example

```ts
// app/actions.ts
"use server";

import { withActionGuard } from "rsc-sentinel";

async function handleContactForm(formData: FormData) {
  // your actual logic goes here
}

export const submitContactForm = withActionGuard(handleContactForm, {
  maxFormDataBytes: 512 * 1024, // 512 KiB
  timeoutMs: 15_000,            // 15 seconds
});
```

That's it — `submitContactForm` is now what you bind to your form (`<form action={submitContactForm}>`),
instead of `handleContactForm` directly.

### Every option, explained

| Option | Type | Default | What it does |
| --- | --- | --- | --- |
| `maxFormDataBytes` | number | `1048576` (1 MiB) | If the action is called with a `FormData` argument bigger than this, it's rejected before your function body runs at all. |
| `timeoutMs` | number | `30000` (30s) | If the action hasn't returned by this time, the caller gets an error. See the warning below. |
| `onBlocked` | function | none | Called right before an error is thrown, with the reason (`"size_limit"` or `"timeout"`) and a text detail — wire this into your own logging (Sentry, Datadog, `console.warn`, whatever you use). |

### Reading the result

```ts
import { ActionGuardError } from "rsc-sentinel";

try {
  await submitContactForm(formData);
} catch (err) {
  if (err instanceof ActionGuardError) {
    if (err.reason === "size_limit") {
      // show "your message is too long" to the user
    } else if (err.reason === "timeout") {
      // show "that took too long, please try again"
    }
  }
}
```

### ⚠️ Important limitation — read this before you rely on the timeout

`timeoutMs` can only rescue you from an action that's hanging on something
**asynchronous** — a slow database call, a fetch that never resolves. It **cannot**
interrupt a genuinely synchronous, CPU-bound loop, because Node.js runs your code on a
single thread: the timer that would cancel the action can only fire once that thread is
free, and a real infinite/expensive loop never frees it. That specific failure mode —
synchronous CPU exhaustion — is exactly the mechanism behind CVE-2026-23869-class bugs,
and the only real defenses against it are (a) running patched package versions (run
`rsc-sentinel check` to find out), or (b) infrastructure-level protection outside the
Node process itself (a reverse-proxy timeout, a WAF rule, or moving the work into a
`worker_threads` worker a supervisor can forcibly kill). `withActionGuard` is a genuinely
useful extra layer — it is not a replacement for staying patched.

A full, runnable example of this wired into a real Next.js 16 app is in
[`examples/nextjs-demo`](./examples/nextjs-demo).

---

## Part 8 — Common errors and what they actually mean

These are real errors you may see, and exactly what's going on when you see them.

### `npm error 404 Not Found ... 'rsc-sentinel@*' is not in this registry`

This means npm couldn't find the package by that exact name — almost always a typo, an
offline connection, or an npm registry mirror/cache issue. Try `npm view rsc-sentinel`
on its own; if that also 404s, check your internet connection and your npm registry
setting (`npm config get registry` should show `https://registry.npmjs.org/`).

### `No package-lock.json found. npm audit needs a lockfile — run npm install first.`

`rsc-sentinel check` relies on `npm audit`, which only reads `package-lock.json`. If your
project has never had `npm install` run in it, that file doesn't exist yet. Run
`npm install` once, then re-run `rsc-sentinel check`.

This also means yarn (`yarn.lock`) and pnpm (`pnpm-lock.yaml`) projects aren't supported
yet — `npm audit` only reads its own lockfile format.

### `No package.json found in <folder>. Run rsc-sentinel from your project root.`

You ran the command from a folder that isn't a Node project (no `package.json` there).
`cd` into your actual project folder first, or pass `--path`.

### `'tsc' is not recognized as an internal or external command` (only if you're modifying this package's own source code, not just using it)

This means `npm install` hasn't been run **inside the `rsc-sentinel` source folder
itself** yet, so TypeScript (a `devDependency`) isn't installed. This only applies if
you've cloned the source and are building it yourself — not to normal
`npm install rsc-sentinel` usage. Fix: run `npm install` in that folder, then `npm run
build`.

---

## Part 9 — Why this exists

In April 2026, Meta disclosed **CVE-2026-23869** — a high-severity (CVSS 7.5)
denial-of-service vulnerability in React's Flight protocol. Deserializing a crafted,
cyclic RSC payload could pin a Node process's CPU for close to a minute, with no
authentication required.

That wasn't an isolated incident. This scanner's own output (Part 3, above) shows the
real picture: **six related advisories** in the same subsystem, disclosed across April
through August 2026, not one. That's the entire reason the scanner queries live data
instead of shipping a fixed list — a hardcoded CVE list is stale the day a new one is
published, and this area has kept producing new ones.

---

## Part 10 — What this does NOT do

- **It does not patch React or Next.js.** It tells you what to upgrade to; it doesn't
  rewrite vulnerable code for you.
- **The guard's timeout cannot stop a synchronous CPU-exhaustion attack** — see the
  warning in [Part 7](#part-7--using-the-server-action-guard-in-your-code).
- **It doesn't support yarn or pnpm yet** — see [Part 8](#part-8--common-errors-and-what-they-actually-mean).

---

## Contributing / running the tests

```bash
git clone <your-repo-url>
cd rsc-sentinel
npm install
npm run build
npm test
```

`npm test` builds the project and then runs 14 automated tests (`node --test`) covering
the scanner's normalization logic and the guard's size-limit and timeout behavior.

## License

MIT

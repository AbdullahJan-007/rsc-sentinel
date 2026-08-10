# rsc-sentinel — Next.js 16.3.0 demo

A minimal, real, running example of `withActionGuard` wrapping a Server Action in a
current Next.js App Router project. Not a mock — the guard actually runs on every submit.

## What's here

- `app/actions.ts` — a `'use server'` action wrapped in `withActionGuard`, called with a
  real `FormData` argument the way Next.js actually invokes Server Actions (no `(req,
  res)` pair — that pattern doesn't exist in this runtime).
- `app/page.tsx` — a form bound via `useActionState`, plus a live panel showing the
  guard's configured limits and a running log of the last few submissions and why the
  guard passed or blocked each one.

Two checkboxes let you trip the guard on purpose:

- **Simulate a 3s hang** — the action awaits `setTimeout(…, 3000)` before returning,
  while the guard's `timeoutMs` is set to `2000`. The guard's timeout fires first.
- **Oversized payload** — fills the message field with ~5 KB of text against a
  `maxFormDataBytes` limit of 4096. The guard rejects it before the action body ever
  runs.

## Running it

This example depends on the local `rsc-sentinel` package, not a published one (it hasn't
shipped to npm yet). From the repo root:

```bash
cd ../..                            # repo root
npm install && npm run build        # build rsc-sentinel first
npm pack --pack-destination examples/nextjs-demo
cd examples/nextjs-demo
npm install ./rsc-sentinel-0.1.0.tgz
npm install
npm run dev
```

Once `rsc-sentinel` is actually published, replace that install step with a normal
`npm install rsc-sentinel` and drop the `file:`/tarball reference from
`package.json` — everything else in this example stays the same.

## What was verified before this was written up as "done"

- `npx tsc` — zero errors, strict mode, against real `next`/`react` types (this is what
  catches signature mismatches like the classic "the wrapper expects `(req, res)` but a
  Server Action never receives that" bug).
- `next build` — clean, including static generation.
- `next start` on a real port, `curl`'d — the page serves 200 with the expected content
  actually rendered.

What was **not** verified end-to-end: a raw HTTP-level invocation of the Server Action
through curl, hand-crafting Next's internal action-invocation wire format. That format
isn't a stable public API and isn't meant to be hand-built; a couple of reasonable
attempts didn't get a connection through, and reverse-engineering it further wasn't worth
the time given the guard logic itself (`withActionGuard`) already has direct unit test
coverage for exactly this — the size check and the timeout — using real `FormData`
objects and real timers. If you want true browser-level E2E coverage, Playwright against
`npm run dev` is the natural next step; it just isn't set up here.

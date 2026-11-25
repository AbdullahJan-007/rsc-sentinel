# Next.js App Router Demo — `rsc-sentinel`

A minimal Next.js App Router application demonstrating `createActionGuard` and `safeRun` from `rsc-sentinel/guard` with React's `useActionState`.

## Files

- `app/actions.ts` — A `"use server"` module exporting `submitAction`, guarded by `createActionGuard` with `maxFormDataBytes: 4096`, `maxFormDataEntries: 20`, and `timeoutMs: 2000`. Uses `safeRun` so blocked calls return an RSC-serializable error object and passes the cooperative `AbortSignal` to cancel simulated async work.
- `app/page.tsx` — A Client Component form bound via `useActionState`, with controls to trigger both the payload-size guard and the timeout guard on demand.

## Running Locally

```bash
npm install
npm run dev
```

Open [http://localhost:3000](http://localhost:3000) and test:
- **Normal submission:** Completes within limits and returns the server response.
- **Oversized payload:** Exceeds `4096` bytes and is rejected with `reason: "size_limit"` before the action body executes.
- **Simulated 3s delay:** Exceeds `timeoutMs: 2000`, triggers `AbortSignal`, and returns `reason: "timeout"`.

"use client";

import { useActionState, useEffect, useRef, useState } from "react";
import { submitAction, type SubmitResult } from "./actions";

interface LogEntry {
  id: number;
  time: string;
  ok: boolean;
  message: string;
}

const initialState: SubmitResult | null = null;

export default function Home() {
  const [state, formAction, isPending] = useActionState(submitAction, initialState);
  const [log, setLog] = useState<LogEntry[]>([]);
  const [simulateDelay, setSimulateDelay] = useState(false);
  const [oversized, setOversized] = useState(false);
  const nextId = useRef(1);
  const lastLoggedState = useRef<SubmitResult | null>(null);

  useEffect(() => {
    if (state && state !== lastLoggedState.current) {
      lastLoggedState.current = state;
      setLog((prev) =>
        [
          {
            id: nextId.current++,
            time: new Date().toLocaleTimeString(),
            ok: state.ok,
            message: state.message,
          },
          ...prev,
        ].slice(0, 8),
      );
    }
  }, [state]);

  return (
    <main className="mx-auto flex w-full max-w-5xl flex-1 flex-col gap-10 px-6 py-16">
      <header className="flex flex-col gap-2">
        <div className="flex items-center gap-2 font-mono text-sm text-accent">
          <span className="inline-block h-2 w-2 rounded-full bg-accent" />
          rsc-sentinel
        </div>
        <h1 className="text-2xl font-semibold tracking-tight text-foreground sm:text-3xl">
          Server Action guard — live demo
        </h1>
        <p className="max-w-2xl text-sm text-muted">
          This form calls a real Next.js 16 Server Action wrapped in{" "}
          <code className="rounded bg-surface-2 px-1.5 py-0.5 font-mono text-xs text-foreground">
            withActionGuard
          </code>
          . Trip the size cap or the timeout below to see it actually reject the call, in real
          time — not a mocked response.
        </p>
      </header>

      <div className="grid gap-8 lg:grid-cols-[1fr_320px]">
        <form action={formAction} className="flex flex-col gap-5 rounded-lg border border-border bg-surface p-6">
          <div className="flex flex-col gap-1.5">
            <label htmlFor="name" className="font-mono text-xs uppercase tracking-wide text-muted">
              Name
            </label>
            <input
              id="name"
              name="name"
              required
              placeholder="Abdullah"
              className="rounded-md border border-border bg-surface-2 px-3 py-2 text-sm text-foreground placeholder:text-muted/60 outline-none focus:border-accent"
            />
          </div>

          <div className="flex flex-col gap-1.5">
            <label htmlFor="message" className="font-mono text-xs uppercase tracking-wide text-muted">
              Message
            </label>
            <textarea
              id="message"
              name="message"
              required
              rows={4}
              defaultValue={oversized ? "x".repeat(5000) : ""}
              placeholder="Type a short message…"
              className="resize-none rounded-md border border-border bg-surface-2 px-3 py-2 text-sm text-foreground placeholder:text-muted/60 outline-none focus:border-accent"
            />
            <p className="font-mono text-xs text-muted">Guard limit: 4096 bytes total per submission.</p>
          </div>

          <input type="hidden" name="simulateDelayMs" value={simulateDelay ? 3000 : 0} />

          <div className="flex flex-col gap-2 border-t border-border pt-4">
            <label className="flex items-center gap-2 text-sm text-foreground">
              <input
                type="checkbox"
                checked={simulateDelay}
                onChange={(e) => setSimulateDelay(e.target.checked)}
                className="h-4 w-4 accent-[var(--accent)]"
              />
              Simulate a 3s hang (guard timeout is 2s)
            </label>
            <label className="flex items-center gap-2 text-sm text-foreground">
              <input
                type="checkbox"
                checked={oversized}
                onChange={(e) => setOversized(e.target.checked)}
                className="h-4 w-4 accent-[var(--accent)]"
              />
              Fill message with an oversized payload (~5&nbsp;KB)
            </label>
          </div>

          <button
            type="submit"
            disabled={isPending}
            className="mt-1 rounded-md bg-accent px-4 py-2 text-sm font-medium text-accent-foreground transition-opacity disabled:opacity-60"
          >
            {isPending ? "Submitting…" : "Send through the guard"}
          </button>

          {state && (
            <p
              className={`font-mono text-xs ${state.ok ? "text-success" : "text-danger"}`}
              role="status"
            >
              {state.ok ? "OK" : "BLOCKED"} — {state.message}
            </p>
          )}
        </form>

        <aside className="flex flex-col gap-4 rounded-lg border border-border bg-surface p-5">
          <div>
            <h2 className="font-mono text-xs uppercase tracking-wide text-muted">Guard config</h2>
            <dl className="mt-2 space-y-1 font-mono text-xs text-foreground">
              <div className="flex justify-between gap-4">
                <dt className="text-muted">maxFormDataBytes</dt>
                <dd>4096</dd>
              </div>
              <div className="flex justify-between gap-4">
                <dt className="text-muted">timeoutMs</dt>
                <dd>2000</dd>
              </div>
            </dl>
          </div>

          <div className="border-t border-border pt-4">
            <h2 className="font-mono text-xs uppercase tracking-wide text-muted">Recent calls</h2>
            {log.length === 0 ? (
              <p className="mt-2 text-xs text-muted">Nothing submitted yet.</p>
            ) : (
              <ul className="mt-2 flex flex-col gap-2">
                {log.map((entry) => (
                  <li key={entry.id} className="rounded-md border border-border bg-surface-2 p-2">
                    <div className="flex items-center justify-between font-mono text-[10px] text-muted">
                      <span>{entry.time}</span>
                      <span className={entry.ok ? "text-success" : "text-danger"}>
                        {entry.ok ? "PASS" : "BLOCKED"}
                      </span>
                    </div>
                    <p className="mt-1 text-xs text-foreground">{entry.message}</p>
                  </li>
                ))}
              </ul>
            )}
          </div>
        </aside>
      </div>
    </main>
  );
}

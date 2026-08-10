/**
 * Server Action hardening.
 *
 * IMPORTANT — read this before you rely on it:
 *
 * A Next.js `'use server'` function is called directly with whatever
 * arguments the call site passes (a FormData object from a <form action={}>,
 * or plain arguments from a direct call, or (prevState, formData) under
 * useActionState). There is no (req, res) pair — Next.js doesn't hand your
 * action an Express-style request object. This wrapper matches that real
 * calling convention: it wraps the action function itself and forwards
 * whatever arguments it's called with, unchanged.
 *
 * The timeout below only helps when your action HANGS on something
 * asynchronous — a slow database query, a downstream fetch that never
 * resolves, etc. It cannot stop a genuinely synchronous, CPU-bound loop
 * (the actual mechanism behind CVE-2026-23869-class RSC deserialization
 * bugs). Node.js runs your code on a single thread; a setTimeout callback
 * can only fire once that thread is free. If the thread is stuck spinning
 * inside a synchronous loop, the timeout callback queues up but never gets
 * a chance to run, so `AbortController`/`Promise.race` style timeouts
 * cannot preempt it. The request will keep the process pinned until the
 * loop finishes on its own.
 *
 * What this DOES give you:
 *   - A real, enforced cap on FormData payload size.
 *   - A real timeout for actions that hang on unresolved async work,
 *     so at least the caller gets an error back instead of hanging forever
 *     (the underlying work may still be running in the background until it
 *     naturally settles — this frees the caller, not the server resources).
 *
 * What it does NOT give you:
 *   - Protection against the synchronous CPU-exhaustion vector in
 *     CVE-2026-23869 and related RSC/Flight-protocol DoS advisories. The
 *     only real fixes for that are (a) running patched package versions —
 *     run `rsc-sentinel check` to see if you're on one — or (b) an
 *     out-of-process defense (a WAF/reverse-proxy timeout, or moving the
 *     action's work into a `worker_threads` worker that a supervisor can
 *     forcibly terminate).
 */

export type ActionGuardReason = "size_limit" | "timeout";

export class ActionGuardError extends Error {
  constructor(
    message: string,
    public readonly reason: ActionGuardReason,
  ) {
    super(message);
    this.name = "ActionGuardError";
  }
}

export interface ActionGuardOptions {
  /**
   * Maximum allowed size, in bytes, for FormData arguments. Only applies to
   * arguments that are actual FormData instances; other argument types are
   * not size-checked here (JSON bodies for direct calls are already capped
   * by Next.js's own `serverActions.bodySizeLimit` config).
   * Default: 1 MiB (1048576 bytes).
   */
  maxFormDataBytes?: number;
  /**
   * Milliseconds to wait before treating the action as hung. See the module
   * doc comment above for exactly what this can and can't catch.
   * Default: 30000.
   */
  timeoutMs?: number;
  /** Fires when a call is rejected, before the error is thrown — wire this into your own logging/metrics. */
  onBlocked?: (reason: ActionGuardReason, detail: string) => void;
}

const DEFAULT_MAX_FORM_DATA_BYTES = 1024 * 1024;
const DEFAULT_TIMEOUT_MS = 30_000;

function estimateFormDataBytes(formData: FormData): number {
  const encoder = new TextEncoder();
  let total = 0;
  for (const [key, value] of formData.entries()) {
    total += encoder.encode(key).length;
    total += value instanceof Blob ? value.size : encoder.encode(value).length;
  }
  return total;
}

/**
 * Wraps a Server Action with a FormData size cap and a hang timeout.
 * Forwards arguments unchanged — safe to use with <form action={}>,
 * useActionState, and direct calls alike.
 *
 * @example
 * 'use server';
 * export const submitContactForm = withActionGuard(
 *   async (formData: FormData) => {
 *     // ...
 *   },
 *   { maxFormDataBytes: 512 * 1024, timeoutMs: 15_000 },
 * );
 */
export function withActionGuard<Args extends unknown[], Return>(
  action: (...args: Args) => Promise<Return>,
  options: ActionGuardOptions = {},
): (...args: Args) => Promise<Return> {
  const maxFormDataBytes = options.maxFormDataBytes ?? DEFAULT_MAX_FORM_DATA_BYTES;
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;

  return async (...args: Args): Promise<Return> => {
    for (const arg of args) {
      if (arg instanceof FormData) {
        const size = estimateFormDataBytes(arg);
        if (size > maxFormDataBytes) {
          const detail = `FormData payload was ~${size} bytes; limit is ${maxFormDataBytes}.`;
          options.onBlocked?.("size_limit", detail);
          throw new ActionGuardError(`Rejected: ${detail}`, "size_limit");
        }
      }
    }

    let timeoutHandle: ReturnType<typeof setTimeout> | undefined;
    const timeoutPromise = new Promise<never>((_resolve, reject) => {
      timeoutHandle = setTimeout(() => {
        const detail = `Action exceeded ${timeoutMs}ms.`;
        options.onBlocked?.("timeout", detail);
        reject(new ActionGuardError(`Timed out: ${detail}`, "timeout"));
      }, timeoutMs);
    });

    try {
      return await Promise.race([action(...args), timeoutPromise]);
    } finally {
      clearTimeout(timeoutHandle);
    }
  };
}

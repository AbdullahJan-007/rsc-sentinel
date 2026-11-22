/**
 * Production-hardened Next.js Server Action guard.
 *
 * Zero Node.js builtin dependencies — uses only Web-standard APIs (`FormData`,
 * `Blob`, `TextEncoder`, `AbortController`, `setTimeout`), so it is safe to
 * import from `rsc-sentinel/guard` in Next.js App Router Server Actions,
 * Edge Runtime, and Client Components without triggering Node-builtin bundler
 * errors.
 *
 * IMPORTANT — Next.js `'use server'` export rule:
 * Next.js requires every export of a `'use server'` file to be a direct
 * `export async function ...` declaration (not `export const x = withActionGuard(...)`).
 * Use `createActionGuard()` inside your exported `async function`:
 *
 * @example
 * "use server";
 * import { createActionGuard } from "rsc-sentinel/guard";
 *
 * const guard = createActionGuard({ maxFormDataBytes: 512 * 1024, timeoutMs: 15_000 });
 *
 * export async function submitContact(formData: FormData) {
 *   return guard.safeRun([formData], async (signal) => {
 *     // `signal` is aborted automatically if `timeoutMs` is exceeded.
 *     return { received: true };
 *   });
 * }
 *
 * Honest scope of `timeoutMs`:
 * JavaScript runs on a single event loop. `timeoutMs` rescues callers from
 * hung asynchronous work (slow DB queries, stalled fetches) and signals
 * cooperative cancellation via `AbortSignal`. It cannot preempt a synchronous,
 * CPU-bound infinite loop (CVE-2026-23869-class deserialization bugs). For
 * synchronous CPU exhaustion, always stay on patched React/Next.js versions
 * (`npx rsc-sentinel check`) and enforce reverse-proxy / WAF timeouts.
 */

export type ActionGuardReason =
  | "size_limit"
  | "entry_limit"
  | "depth_limit"
  | "timeout";

export class ActionGuardError extends Error {
  public readonly isActionGuardError = true;

  constructor(
    message: string,
    public readonly reason: ActionGuardReason,
  ) {
    super(message);
    this.name = "ActionGuardError";
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/**
 * Cross-realm safe type guard for `ActionGuardError`.
 */
export function isActionGuardError(err: unknown): err is ActionGuardError {
  if (err instanceof ActionGuardError) return true;
  if (!err || typeof err !== "object") return false;
  const candidate = err as {
    name?: unknown;
    reason?: unknown;
    isActionGuardError?: unknown;
  };
  return (
    candidate.isActionGuardError === true &&
    candidate.name === "ActionGuardError" &&
    (candidate.reason === "size_limit" ||
      candidate.reason === "entry_limit" ||
      candidate.reason === "depth_limit" ||
      candidate.reason === "timeout")
  );
}

/**
 * RSC-serializable discriminated union returned by `guard.safeRun()` and
 * `guard.wrapSafe()`. Safe to pass across the Next.js Server/Client boundary
 * in production (where Next.js strips thrown `Error` subclasses).
 */
export type ActionGuardResult<T> =
  | { ok: true; data: T }
  | {
      ok: false;
      error: {
        reason: ActionGuardReason;
        message: string;
      };
    };

export interface ActionGuardOptions {
  /**
   * Maximum allowed total size, in bytes, for any `FormData` argument
   * (keys + string values + Blob sizes + File names).
   * Default: 1 MiB (1048576 bytes).
   */
  maxFormDataBytes?: number;
  /**
   * Maximum allowed number of entries in a single `FormData` argument.
   * Stops field-flood DoS attacks (e.g., 100,000 tiny fields under 1 MiB).
   * Default: 1000.
   */
  maxFormDataEntries?: number;
  /**
   * Maximum allowed estimated byte size for non-`FormData` arguments
   * (strings, plain objects, arrays, TypedArrays, Blobs).
   * Default: 1 MiB (1048576 bytes).
   */
  maxPayloadBytes?: number;
  /**
   * Maximum allowed nesting depth for non-`FormData` objects and arrays.
   * Prevents stack-exhaustion and deeply-nested payload DoS.
   * Default: 32.
   */
  maxObjectDepth?: number;
  /**
   * Milliseconds to wait before treating the action as hung and aborting
   * the cooperative `AbortSignal`.
   * Default: 30000 (30s).
   */
  timeoutMs?: number;
  /**
   * Fires right before a call is rejected by the guard. Wrapped in try/catch
   * internally so a failing logger can never bypass or mask the guard.
   */
  onBlocked?: (reason: ActionGuardReason, detail: string) => void;
  /**
   * Fires if an action rejects *after* a timeout has already settled the call.
   * Prevents Node.js `UnhandledPromiseRejection` crashes.
   */
  onLateError?: (error: unknown) => void;
}

interface ResolvedGuardOptions {
  maxFormDataBytes: number;
  maxFormDataEntries: number;
  maxPayloadBytes: number;
  maxObjectDepth: number;
  timeoutMs: number;
  onBlocked: ((reason: ActionGuardReason, detail: string) => void) | undefined;
  onLateError: ((error: unknown) => void) | undefined;
}

const DEFAULT_MAX_FORM_DATA_BYTES = 1024 * 1024;
const DEFAULT_MAX_FORM_DATA_ENTRIES = 1000;
const DEFAULT_MAX_PAYLOAD_BYTES = 1024 * 1024;
const DEFAULT_MAX_OBJECT_DEPTH = 32;
const DEFAULT_TIMEOUT_MS = 30_000;

const SHARED_ENCODER = new TextEncoder();

function assertPositiveFiniteNumber(name: string, value: number): number {
  if (typeof value !== "number" || !Number.isFinite(value) || value <= 0) {
    throw new RangeError(
      `ActionGuardOptions.${name} must be a positive finite number, received ${String(value)}.`,
    );
  }
  return value;
}

function resolveOptions(options: ActionGuardOptions): ResolvedGuardOptions {
  return {
    maxFormDataBytes: assertPositiveFiniteNumber(
      "maxFormDataBytes",
      options.maxFormDataBytes ?? DEFAULT_MAX_FORM_DATA_BYTES,
    ),
    maxFormDataEntries: assertPositiveFiniteNumber(
      "maxFormDataEntries",
      options.maxFormDataEntries ?? DEFAULT_MAX_FORM_DATA_ENTRIES,
    ),
    maxPayloadBytes: assertPositiveFiniteNumber(
      "maxPayloadBytes",
      options.maxPayloadBytes ?? DEFAULT_MAX_PAYLOAD_BYTES,
    ),
    maxObjectDepth: assertPositiveFiniteNumber(
      "maxObjectDepth",
      options.maxObjectDepth ?? DEFAULT_MAX_OBJECT_DEPTH,
    ),
    timeoutMs: assertPositiveFiniteNumber(
      "timeoutMs",
      options.timeoutMs ?? DEFAULT_TIMEOUT_MS,
    ),
    onBlocked: options.onBlocked,
    onLateError: options.onLateError,
  };
}

function safeOnBlocked(
  opts: ResolvedGuardOptions,
  reason: ActionGuardReason,
  detail: string,
): void {
  if (!opts.onBlocked) return;
  try {
    opts.onBlocked(reason, detail);
  } catch {
    // A failing metrics/logging hook must never bypass or mask the security guard.
  }
}

function safeOnLateError(opts: ResolvedGuardOptions, error: unknown): void {
  if (!opts.onLateError) return;
  try {
    opts.onLateError(error);
  } catch {
    // Never let a late-error callback trigger an unhandled rejection.
  }
}

function rejectGuard(
  opts: ResolvedGuardOptions,
  reason: ActionGuardReason,
  prefix: string,
  detail: string,
): never {
  safeOnBlocked(opts, reason, detail);
  throw new ActionGuardError(`${prefix}: ${detail}`, reason);
}

/**
 * Detects Next.js App Router internal control-flow errors (`redirect()`,
 * `permanentRedirect()`, `notFound()`, `forbidden()`, `unauthorized()`).
 * These must always be re-thrown untouched so Next.js can process them.
 */
export function isNextControlFlowError(err: unknown): boolean {
  if (!err || typeof err !== "object") return false;
  const digest = (err as { digest?: unknown }).digest;
  if (typeof digest !== "string") return false;
  return (
    digest.startsWith("NEXT_REDIRECT") ||
    digest === "NEXT_NOT_FOUND" ||
    digest.startsWith("NEXT_HTTP_ERROR_FALLBACK;")
  );
}

function inspectFormData(formData: FormData, opts: ResolvedGuardOptions): void {
  let totalBytes = 0;
  let entryCount = 0;

  for (const [key, value] of formData.entries()) {
    entryCount++;
    if (entryCount > opts.maxFormDataEntries) {
      rejectGuard(
        opts,
        "entry_limit",
        "Rejected",
        `FormData exceeded ${opts.maxFormDataEntries} entries.`,
      );
    }

    totalBytes += SHARED_ENCODER.encode(key).byteLength;
    if (value instanceof Blob) {
      totalBytes += value.size;
      const maybeName = (value as { name?: unknown }).name;
      if (typeof maybeName === "string" && maybeName.length > 0) {
        totalBytes += SHARED_ENCODER.encode(maybeName).byteLength;
      }
    } else {
      totalBytes += SHARED_ENCODER.encode(String(value)).byteLength;
    }

    // Short-circuit immediately so huge payloads don't consume CPU/RAM before failing.
    if (totalBytes > opts.maxFormDataBytes) {
      rejectGuard(
        opts,
        "size_limit",
        "Rejected",
        `FormData payload exceeded limit of ${opts.maxFormDataBytes} bytes (reached >=${totalBytes} bytes).`,
      );
    }
  }
}

interface PayloadState {
  totalBytes: number;
  seen: WeakSet<object>;
}

function inspectValue(
  value: unknown,
  depth: number,
  state: PayloadState,
  opts: ResolvedGuardOptions,
): void {
  if (value === null || value === undefined) {
    state.totalBytes += 4;
    return;
  }

  const kind = typeof value;
  if (kind === "string") {
    state.totalBytes += SHARED_ENCODER.encode(value as string).byteLength;
    if (state.totalBytes > opts.maxPayloadBytes) {
      rejectGuard(
        opts,
        "size_limit",
        "Rejected",
        `Action arguments exceeded limit of ${opts.maxPayloadBytes} bytes.`,
      );
    }
    return;
  }

  if (kind === "number" || kind === "boolean" || kind === "bigint" || kind === "symbol") {
    state.totalBytes += 8;
    if (state.totalBytes > opts.maxPayloadBytes) {
      rejectGuard(
        opts,
        "size_limit",
        "Rejected",
        `Action arguments exceeded limit of ${opts.maxPayloadBytes} bytes.`,
      );
    }
    return;
  }

  if (kind !== "object") {
    return;
  }

  const obj = value as object;

  if (obj instanceof Blob) {
    state.totalBytes += obj.size;
    if (state.totalBytes > opts.maxPayloadBytes) {
      rejectGuard(
        opts,
        "size_limit",
        "Rejected",
        `Action arguments exceeded limit of ${opts.maxPayloadBytes} bytes.`,
      );
    }
    return;
  }

  if (obj instanceof ArrayBuffer) {
    state.totalBytes += obj.byteLength;
    if (state.totalBytes > opts.maxPayloadBytes) {
      rejectGuard(
        opts,
        "size_limit",
        "Rejected",
        `Action arguments exceeded limit of ${opts.maxPayloadBytes} bytes.`,
      );
    }
    return;
  }

  if (ArrayBuffer.isView(obj)) {
    state.totalBytes += obj.byteLength;
    if (state.totalBytes > opts.maxPayloadBytes) {
      rejectGuard(
        opts,
        "size_limit",
        "Rejected",
        `Action arguments exceeded limit of ${opts.maxPayloadBytes} bytes.`,
      );
    }
    return;
  }

  if (obj instanceof Date) {
    state.totalBytes += 24;
    return;
  }

  if (depth > opts.maxObjectDepth) {
    rejectGuard(
      opts,
      "depth_limit",
      "Rejected",
      `Action argument exceeded maximum nesting depth of ${opts.maxObjectDepth}.`,
    );
  }

  // Prevent infinite recursion on circular references.
  if (state.seen.has(obj)) {
    state.totalBytes += 8;
    return;
  }
  state.seen.add(obj);

  if (Array.isArray(obj)) {
    for (let i = 0; i < obj.length; i++) {
      inspectValue(obj[i], depth + 1, state, opts);
    }
    return;
  }

  if (obj instanceof Map) {
    for (const [k, v] of obj.entries()) {
      inspectValue(k, depth + 1, state, opts);
      inspectValue(v, depth + 1, state, opts);
    }
    return;
  }

  if (obj instanceof Set) {
    for (const v of obj.values()) {
      inspectValue(v, depth + 1, state, opts);
    }
    return;
  }

  const keys = Object.keys(obj);
  for (let i = 0; i < keys.length; i++) {
    const key = keys[i]!;
    state.totalBytes += SHARED_ENCODER.encode(key).byteLength;
    if (state.totalBytes > opts.maxPayloadBytes) {
      rejectGuard(
        opts,
        "size_limit",
        "Rejected",
        `Action arguments exceeded limit of ${opts.maxPayloadBytes} bytes.`,
      );
    }
    inspectValue(
      (obj as Record<string, unknown>)[key],
      depth + 1,
      state,
      opts,
    );
  }
}

function inspectArguments(
  args: readonly unknown[],
  opts: ResolvedGuardOptions,
): void {
  const payloadState: PayloadState = {
    totalBytes: 0,
    seen: new WeakSet<object>(),
  };

  for (const arg of args) {
    if (typeof FormData !== "undefined" && arg instanceof FormData) {
      inspectFormData(arg, opts);
    } else {
      inspectValue(arg, 0, payloadState, opts);
    }
  }
}

async function executeGuarded<Return>(
  args: readonly unknown[],
  executor: (signal: AbortSignal) => Promise<Return>,
  opts: ResolvedGuardOptions,
): Promise<Return> {
  inspectArguments(args, opts);

  const controller = new AbortController();
  let timedOut = false;
  let timeoutHandle: ReturnType<typeof setTimeout> | undefined;

  const timeoutPromise = new Promise<never>((_resolve, reject) => {
    timeoutHandle = setTimeout(() => {
      timedOut = true;
      const detail = `Action exceeded ${opts.timeoutMs}ms.`;
      const err = new ActionGuardError(`Timed out: ${detail}`, "timeout");
      controller.abort(err);
      safeOnBlocked(opts, "timeout", detail);
      reject(err);
    }, opts.timeoutMs);
  });

  // Start the action and attach a late-rejection handler so a post-timeout
  // rejection never crashes Node.js with UnhandledPromiseRejection.
  const actionPromise = Promise.resolve().then(() => executor(controller.signal));
  actionPromise.catch((lateErr: unknown) => {
    if (timedOut) {
      safeOnLateError(opts, lateErr);
    }
  });

  try {
    return await Promise.race([actionPromise, timeoutPromise]);
  } finally {
    if (timeoutHandle !== undefined) {
      clearTimeout(timeoutHandle);
    }
  }
}

/**
 * Wraps a Server Action with payload size/entry/depth guards and a hang timeout.
 *
 * NOTE for Next.js `'use server'` files: do NOT `export const myAction = withActionGuard(...)`
 * directly from a `'use server'` file (Next.js requires `export async function`).
 * Either keep the wrapped function private and call it from `export async function`,
 * or use `createActionGuard()` with `guard.run()` / `guard.safeRun()`.
 */
export function withActionGuard<Args extends unknown[], Return>(
  action: (...args: Args) => Promise<Return>,
  options: ActionGuardOptions = {},
): (...args: Args) => Promise<Return> {
  const resolved = resolveOptions(options);

  return async (...args: Args): Promise<Return> => {
    return executeGuarded(args, () => action(...args), resolved);
  };
}

export interface ActionGuard {
  /**
   * Executes `fn` with input inspection, timeout enforcement, and an
   * `AbortSignal` that aborts automatically if `timeoutMs` is exceeded.
   * Throws `ActionGuardError` when blocked.
   */
  run<Return>(
    args: readonly unknown[],
    fn: (signal: AbortSignal) => Promise<Return>,
  ): Promise<Return>;

  /**
   * Same as `run()`, but converts `ActionGuardError` into an RSC-serializable
   * `{ ok: false, error: { reason, message } }` result. Next.js control-flow
   * errors (`redirect()`, `notFound()`) and unexpected errors are still re-thrown.
   */
  safeRun<Return>(
    args: readonly unknown[],
    fn: (signal: AbortSignal) => Promise<Return>,
  ): Promise<ActionGuardResult<Return>>;

  /**
   * Wraps an action function (throws `ActionGuardError` when blocked).
   */
  wrap<Args extends unknown[], Return>(
    action: (...args: Args) => Promise<Return>,
  ): (...args: Args) => Promise<Return>;

  /**
   * Wraps an action function and returns an RSC-serializable `ActionGuardResult`.
   */
  wrapSafe<Args extends unknown[], Return>(
    action: (...args: Args) => Promise<Return>,
  ): (...args: Args) => Promise<ActionGuardResult<Return>>;
}

/**
 * Creates a reusable, Next.js-idiomatic Server Action guard with eager option
 * validation, cooperative `AbortSignal` cancellation, and RSC-serializable results.
 */
export function createActionGuard(options: ActionGuardOptions = {}): ActionGuard {
  const resolved = resolveOptions(options);

  const run: ActionGuard["run"] = async (args, fn) => {
    return executeGuarded(args, fn, resolved);
  };

  const safeRun: ActionGuard["safeRun"] = async (args, fn) => {
    try {
      const data = await executeGuarded(args, fn, resolved);
      return { ok: true, data };
    } catch (err) {
      if (isNextControlFlowError(err)) {
        throw err;
      }
      if (isActionGuardError(err)) {
        return {
          ok: false,
          error: {
            reason: err.reason,
            message: err.message,
          },
        };
      }
      throw err;
    }
  };

  const wrap: ActionGuard["wrap"] = (action) => {
    return async (...args) => executeGuarded(args, () => action(...args), resolved);
  };

  const wrapSafe: ActionGuard["wrapSafe"] = (action) => {
    return async (...args) => safeRun(args, () => action(...args));
  };

  return { run, safeRun, wrap, wrapSafe };
}

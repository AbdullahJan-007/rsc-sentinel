"use server";

import { createActionGuard } from "rsc-sentinel/guard";

export interface SubmitResult {
  ok: boolean;
  message: string;
}

/**
 * Reusable guard instance (NOT exported — Next.js `'use server'` files may
 * only export `async function` declarations).
 */
const contactGuard = createActionGuard({
  maxFormDataBytes: 4 * 1024, // deliberately small so the demo can trip it
  maxFormDataEntries: 20,
  timeoutMs: 2000, // deliberately short so the demo can trip it
  onBlocked: (reason, detail) => {
    console.warn(`[rsc-sentinel] blocked (${reason}): ${detail}`);
  },
});

/**
 * Server Action adapter for `useActionState`: `(previousState, formData) -> newState`.
 * Uses `safeRun` so guard rejections return an RSC-serializable result object
 * instead of throwing an error that Next.js sanitizes in production.
 */
export async function submitAction(
  _prevState: SubmitResult | null,
  formData: FormData,
): Promise<SubmitResult> {
  const guarded = await contactGuard.safeRun([formData], async (signal) => {
    const name = String(formData.get("name") ?? "").trim();
    const message = String(formData.get("message") ?? "").trim();

    if (!name || !message) {
      return { ok: false, message: "Name and message are required." };
    }

    // Simulate async work that honors cooperative AbortSignal cancellation.
    const artificialDelayMs = Number(formData.get("simulateDelayMs") ?? 0);
    if (artificialDelayMs > 0) {
      await new Promise<void>((resolve, reject) => {
        const timer = setTimeout(resolve, artificialDelayMs);
        signal.addEventListener(
          "abort",
          () => {
            clearTimeout(timer);
            reject(signal.reason);
          },
          { once: true },
        );
      });
    }

    return {
      ok: true,
      message: `Received ${message.length} characters from ${name}.`,
    };
  });

  if (!guarded.ok) {
    if (guarded.error.reason === "size_limit") {
      return { ok: false, message: "Blocked by rsc-sentinel: payload too large." };
    }
    if (guarded.error.reason === "entry_limit") {
      return { ok: false, message: "Blocked by rsc-sentinel: too many form fields." };
    }
    if (guarded.error.reason === "timeout") {
      return {
        ok: false,
        message: "Blocked by rsc-sentinel: the action took too long and was cut off.",
      };
    }
    return { ok: false, message: "Blocked by rsc-sentinel: invalid input structure." };
  }

  return guarded.data;
}

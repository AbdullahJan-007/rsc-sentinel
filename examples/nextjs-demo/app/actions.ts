"use server";

import { withActionGuard, ActionGuardError } from "rsc-sentinel";

export interface SubmitResult {
  ok: boolean;
  message: string;
}

/**
 * The real business logic. Notice it takes exactly one argument — the
 * FormData Next.js hands a Server Action bound to a <form action={}> — and
 * nothing else. No (req, res) pair exists here; Next.js never constructs one
 * for Server Actions.
 */
async function handleSubmit(formData: FormData): Promise<SubmitResult> {
  const name = String(formData.get("name") ?? "").trim();
  const message = String(formData.get("message") ?? "").trim();

  if (!name || !message) {
    return { ok: false, message: "Name and message are required." };
  }

  // Simulate real work (e.g. a DB write) so the timeout path is demonstrable.
  const artificialDelayMs = Number(formData.get("simulateDelayMs") ?? 0);
  if (artificialDelayMs > 0) {
    await new Promise((resolve) => setTimeout(resolve, artificialDelayMs));
  }

  return { ok: true, message: `Received ${message.length} characters from ${name}.` };
}

export const submitGuarded = withActionGuard(handleSubmit, {
  maxFormDataBytes: 4 * 1024, // deliberately small so the demo can trip it
  timeoutMs: 2000, // deliberately short so the demo can trip it
  onBlocked: (reason, detail) => {
    console.warn(`[rsc-sentinel] blocked (${reason}): ${detail}`);
  },
});

/**
 * Server Action adapter for useActionState: (previousState, formData) -> newState.
 * This is the shape the form on the page actually binds to.
 */
export async function submitAction(
  _prevState: SubmitResult | null,
  formData: FormData,
): Promise<SubmitResult> {
  try {
    return await submitGuarded(formData);
  } catch (err) {
    if (err instanceof ActionGuardError) {
      return {
        ok: false,
        message:
          err.reason === "size_limit"
            ? "Blocked by rsc-sentinel: payload too large."
            : "Blocked by rsc-sentinel: the action took too long and was cut off.",
      };
    }
    throw err;
  }
}

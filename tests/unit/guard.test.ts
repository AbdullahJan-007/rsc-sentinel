import { test, describe } from "node:test";
import assert from "node:assert/strict";
import {
  withActionGuard,
  createActionGuard,
  ActionGuardError,
  isActionGuardError,
  isNextControlFlowError,
} from "../../src/guard.js";

describe("withActionGuard & createActionGuard (unit)", () => {
  test("forwards arguments and return value unchanged on success", async () => {
    const action = async (name: string, count: number) => `${name}:${count}`;
    const guarded = withActionGuard(action);
    assert.equal(await guarded("hello", 42), "hello:42");
  });

  test("passes FormData under size and entry limits", async () => {
    const fd = new FormData();
    fd.set("field", "small value");
    const guarded = withActionGuard(async (formData: FormData) => formData.get("field"), {
      maxFormDataBytes: 1024,
      maxFormDataEntries: 10,
    });
    assert.equal(await guarded(fd), "small value");
  });

  test("rejects FormData over maxFormDataBytes without invoking action", async () => {
    const fd = new FormData();
    fd.set("field", "x".repeat(2000));
    let called = false;
    const guarded = withActionGuard(
      async (_fd: FormData) => {
        called = true;
        return "nope";
      },
      { maxFormDataBytes: 100 },
    );

    await assert.rejects(
      () => guarded(fd),
      (err: unknown) => isActionGuardError(err) && err.reason === "size_limit",
    );
    assert.equal(called, false);
  });

  test("counts File.name bytes in FormData size calculation", async () => {
    const fd = new FormData();
    const file = new File(["a"], "x".repeat(200), { type: "text/plain" });
    fd.set("upload", file);
    const guarded = withActionGuard(async (_fd: FormData) => "ok", {
      maxFormDataBytes: 100,
    });

    await assert.rejects(
      () => guarded(fd),
      (err: unknown) => isActionGuardError(err) && err.reason === "size_limit",
    );
  });

  test("rejects FormData exceeding maxFormDataEntries", async () => {
    const fd = new FormData();
    for (let i = 0; i < 15; i++) fd.append(`k${i}`, "v");
    const guarded = withActionGuard(async (_fd: FormData) => "ok", {
      maxFormDataEntries: 10,
    });

    await assert.rejects(
      () => guarded(fd),
      (err: unknown) => isActionGuardError(err) && err.reason === "entry_limit",
    );
  });

  test("aborts cooperative AbortSignal when timeoutMs is exceeded", async () => {
    let aborted = false;
    const guard = createActionGuard({ timeoutMs: 25 });

    await assert.rejects(
      () =>
        guard.run([], async (signal) => {
          return await new Promise<string>((_resolve, reject) => {
            signal.addEventListener("abort", () => {
              aborted = true;
              reject(signal.reason);
            });
          });
        }),
      (err: unknown) => isActionGuardError(err) && err.reason === "timeout",
    );
    assert.equal(aborted, true);
  });

  test("safeRun returns RSC-serializable ok/error union on guard rejection", async () => {
    const guard = createActionGuard({ maxPayloadBytes: 20 });

    const okRes = await guard.safeRun(["hi"], async () => ({ saved: true }));
    assert.deepEqual(okRes, { ok: true, data: { saved: true } });

    const blockedRes = await guard.safeRun(["x".repeat(100)], async () => ({
      saved: true,
    }));
    assert.equal(blockedRes.ok, false);
    if (!blockedRes.ok) {
      assert.equal(blockedRes.error.reason, "size_limit");
      assert.ok(blockedRes.error.message.includes("limit of 20"));
    }
  });

  test("safeRun re-throws Next.js NEXT_REDIRECT and NEXT_NOT_FOUND control-flow errors", async () => {
    const guard = createActionGuard({ timeoutMs: 1000 });

    const redirectErr = Object.assign(new Error("NEXT_REDIRECT"), {
      digest: "NEXT_REDIRECT;replace;/dashboard;307;",
    });
    assert.equal(isNextControlFlowError(redirectErr), true);

    await assert.rejects(
      () =>
        guard.safeRun([], async () => {
          throw redirectErr;
        }),
      (err: unknown) => err === redirectErr,
    );

    const notFoundErr = Object.assign(new Error("NEXT_HTTP_ERROR_FALLBACK"), {
      digest: "NEXT_HTTP_ERROR_FALLBACK;404",
    });
    assert.equal(isNextControlFlowError(notFoundErr), true);

    await assert.rejects(
      () =>
        guard.safeRun([], async () => {
          throw notFoundErr;
        }),
      (err: unknown) => err === notFoundErr,
    );
  });

  test("isActionGuardError identifies real and cross-realm guard errors", () => {
    const real = new ActionGuardError("boom", "timeout");
    assert.equal(isActionGuardError(real), true);
    assert.equal(
      isActionGuardError({
        name: "ActionGuardError",
        reason: "size_limit",
        isActionGuardError: true,
      }),
      true,
    );
    assert.equal(isActionGuardError(new Error("plain")), false);
    assert.equal(isActionGuardError(null), false);
  });
});

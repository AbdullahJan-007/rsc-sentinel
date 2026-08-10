import { test } from "node:test";
import assert from "node:assert/strict";
import { withActionGuard, ActionGuardError } from "../dist/middleware/protect-action.js";

test("forwards arguments and return value unchanged on success", async () => {
  const action = async (name: string, count: number) => `${name}:${count}`;
  const guarded = withActionGuard(action);
  const result = await guarded("hello", 42);
  assert.equal(result, "hello:42");
});

test("passes a FormData argument through when under the size limit", async () => {
  const fd = new FormData();
  fd.set("field", "small value");
  const action = async (formData: FormData) => formData.get("field");
  const guarded = withActionGuard(action, { maxFormDataBytes: 1024 });
  const result = await guarded(fd);
  assert.equal(result, "small value");
});

test("rejects FormData over the configured size limit without calling the action", async () => {
  const fd = new FormData();
  fd.set("field", "x".repeat(2000));
  let actionWasCalled = false;
  const action = async (_formData: FormData) => {
    actionWasCalled = true;
    return "should not reach here";
  };
  const guarded = withActionGuard(action, { maxFormDataBytes: 100 });

  await assert.rejects(
    () => guarded(fd),
    (err: unknown) => err instanceof ActionGuardError && err.reason === "size_limit",
  );
  assert.equal(actionWasCalled, false);
});

test("rejects with a timeout error when the action hangs past timeoutMs", async () => {
  const hangingAction = () => new Promise<string>(() => {}); // never resolves
  const guarded = withActionGuard(hangingAction, { timeoutMs: 20 });

  await assert.rejects(
    () => guarded(),
    (err: unknown) => err instanceof ActionGuardError && err.reason === "timeout",
  );
});

test("does not time out an action that resolves comfortably within timeoutMs", async () => {
  const fastAction = async () => {
    await new Promise((r) => setTimeout(r, 5));
    return "done";
  };
  const guarded = withActionGuard(fastAction, { timeoutMs: 200 });
  assert.equal(await guarded(), "done");
});

test("calls onBlocked with the reason and a detail string before throwing", async () => {
  const calls: Array<{ reason: string; detail: string }> = [];
  const fd = new FormData();
  fd.set("field", "x".repeat(500));
  const action = async (_formData: FormData) => "unused";
  const guarded = withActionGuard(action, {
    maxFormDataBytes: 10,
    onBlocked: (reason, detail) => calls.push({ reason, detail }),
  });

  await assert.rejects(() => guarded(fd));
  assert.equal(calls.length, 1);
  assert.equal(calls[0]?.reason, "size_limit");
  assert.ok(calls[0]?.detail.includes("limit is 10"));
});

test("propagates the action's own error unchanged when it rejects on its own", async () => {
  const action = async () => {
    throw new Error("business logic failed");
  };
  const guarded = withActionGuard(action, { timeoutMs: 1000 });

  await assert.rejects(() => guarded(), /business logic failed/);
});

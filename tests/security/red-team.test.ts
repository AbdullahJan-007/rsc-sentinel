import { test, describe } from "node:test";
import assert from "node:assert/strict";
import {
  withActionGuard,
  createActionGuard,
  isActionGuardError,
} from "../../src/guard.js";
import { analyzeAuditReport } from "../../src/scanner/analyze.js";
import type { NpmAuditReport } from "../../src/scanner/types.js";

describe("Security Red-Team & Adversarial Bypass Tests", () => {
  test("ATTACK: NaN / Infinity / zero / negative options cannot silently disable the guard", () => {
    assert.throws(() => createActionGuard({ maxFormDataBytes: Number.NaN }), RangeError);
    assert.throws(() => createActionGuard({ maxFormDataBytes: 0 }), RangeError);
    assert.throws(() => createActionGuard({ maxFormDataBytes: -100 }), RangeError);
    assert.throws(
      () => createActionGuard({ maxFormDataBytes: Number.POSITIVE_INFINITY }),
      RangeError,
    );
    assert.throws(() => createActionGuard({ timeoutMs: Number.NaN }), RangeError);
    assert.throws(() => createActionGuard({ timeoutMs: -1 }), RangeError);
    assert.throws(() => createActionGuard({ maxFormDataEntries: 0 }), RangeError);
    assert.throws(() => createActionGuard({ maxObjectDepth: 0 }), RangeError);
    assert.throws(() => createActionGuard({ maxPayloadBytes: -5 }), RangeError);
  });

  test("ATTACK: FormData field-flood DoS (many 1-byte fields under byte cap) is blocked by maxFormDataEntries", async () => {
    const fd = new FormData();
    for (let i = 0; i < 1200; i++) {
      fd.append(`f${i}`, "1");
    }
    const guarded = withActionGuard(async (_fd: FormData) => "should not run", {
      maxFormDataBytes: 1024 * 1024, // 1 MiB — total bytes here is tiny (~6KB)
      maxFormDataEntries: 1000,
    });

    await assert.rejects(
      () => guarded(fd),
      (err: unknown) => isActionGuardError(err) && err.reason === "entry_limit",
    );
  });

  test("ATTACK: Direct call with massive non-FormData string/Uint8Array bypass is blocked", async () => {
    const guarded = withActionGuard(
      async (_payload: unknown) => "should not run",
      { maxPayloadBytes: 512 },
    );

    await assert.rejects(
      () => guarded("A".repeat(1000)),
      (err: unknown) => isActionGuardError(err) && err.reason === "size_limit",
    );

    await assert.rejects(
      () => guarded(new Uint8Array(1024)),
      (err: unknown) => isActionGuardError(err) && err.reason === "size_limit",
    );
  });

  test("ATTACK: Deeply nested object stack-exhaustion payload is blocked by maxObjectDepth", async () => {
    let nested: Record<string, unknown> = { leaf: true };
    for (let i = 0; i < 50; i++) {
      nested = { child: nested };
    }

    const guarded = withActionGuard(async (_obj: unknown) => "should not run", {
      maxObjectDepth: 16,
    });

    await assert.rejects(
      () => guarded(nested),
      (err: unknown) => isActionGuardError(err) && err.reason === "depth_limit",
    );
  });

  test("ATTACK: Circular object reference does not crash inspector with stack overflow", async () => {
    const cyclic: Record<string, unknown> = { name: "loop" };
    cyclic.self = cyclic;

    const guarded = withActionGuard(async (obj: Record<string, unknown>) => obj.name, {
      maxObjectDepth: 32,
      maxPayloadBytes: 1024,
    });

    assert.equal(await guarded(cyclic), "loop");
  });

  test("ATTACK: Late rejection after timeout MUST NOT trigger Node.js unhandledRejection", async () => {
    let unhandledTriggered = false;
    const onUnhandled = () => {
      unhandledTriggered = true;
    };
    process.on("unhandledRejection", onUnhandled);

    let lateCaptured: unknown = null;
    try {
      const guarded = withActionGuard(
        async () => {
          await new Promise((r) => setTimeout(r, 40));
          throw new Error("late db connection error");
        },
        {
          timeoutMs: 10,
          onLateError: (err) => {
            lateCaptured = err;
          },
        },
      );

      await assert.rejects(
        () => guarded(),
        (err: unknown) => isActionGuardError(err) && err.reason === "timeout",
      );

      // Wait past the late rejection to prove it is handled cleanly
      await new Promise((r) => setTimeout(r, 70));
      assert.equal(unhandledTriggered, false);
      assert.ok(lateCaptured instanceof Error);
      assert.match((lateCaptured as Error).message, /late db connection error/);
    } finally {
      process.off("unhandledRejection", onUnhandled);
    }
  });

  test("ATTACK: Throwing onBlocked callback cannot bypass or mask ActionGuardError", async () => {
    const guarded = withActionGuard(async (_s: string) => "nope", {
      maxPayloadBytes: 5,
      onBlocked: () => {
        throw new Error("sentry crashed");
      },
    });

    await assert.rejects(
      () => guarded("0123456789"),
      (err: unknown) => isActionGuardError(err) && err.reason === "size_limit",
    );
  });

  test("ATTACK: Malformed npm audit report with null/corrupt entries does not crash analyzer", () => {
    const hostileReport = {
      vulnerabilities: {
        "../../etc/passwd": null,
        "broken-pkg": {
          name: "broken-pkg",
          severity: "unknown-sev",
          isDirect: true,
          via: [null, 42, "transitive", { title: "Weird", url: "https://example.com", severity: "bogus", cwe: null, range: null }],
          effects: [],
          range: "*",
          nodes: ["../../../etc/passwd"],
          fixAvailable: false,
        },
      },
    } as unknown as NpmAuditReport;

    const result = analyzeAuditReport(hostileReport, process.cwd());
    assert.equal(result.findings.length, 1);
    assert.equal(result.findings[0]?.severity, "info");
    assert.equal(result.findings[0]?.installedVersion, null);
  });
});

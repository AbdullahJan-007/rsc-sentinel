import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { mkdtempSync, writeFileSync, rmSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const execFileAsync = promisify(execFile);

const REPO_ROOT = resolve(import.meta.dirname, "..", "..", "..");
const BIN_PATH = join(REPO_ROOT, "bin", "rsc-sentinel.js");
const PKG_VERSION = (
  JSON.parse(readFileSync(join(REPO_ROOT, "package.json"), "utf-8")) as {
    version: string;
  }
).version;

async function runCli(args: string[]): Promise<{
  stdout: string;
  stderr: string;
  exitCode: number;
}> {
  try {
    const { stdout, stderr } = await execFileAsync(process.execPath, [
      BIN_PATH,
      ...args,
    ]);
    return { stdout, stderr, exitCode: 0 };
  } catch (err) {
    const e = err as { stdout?: string; stderr?: string; code?: number };
    return {
      stdout: String(e.stdout ?? ""),
      stderr: String(e.stderr ?? ""),
      exitCode: typeof e.code === "number" ? e.code : 1,
    };
  }
}

describe("CLI Integration Tests (real subprocess)", () => {
  test("--version prints exact package.json version and exits 0", async () => {
    const res = await runCli(["--version"]);
    assert.equal(res.exitCode, 0);
    assert.equal(res.stdout.trim(), PKG_VERSION);
  });

  test("--help prints usage and exits 0", async () => {
    const res = await runCli(["--help"]);
    assert.equal(res.exitCode, 0);
    assert.match(res.stdout, /Usage:/);
    assert.match(res.stdout, /--rsc-only/);
    assert.match(res.stdout, /--fail-on/);
  });

  test("unknown command exits with code 2 (not 0)", async () => {
    const res = await runCli(["bogus-cmd"]);
    assert.equal(res.exitCode, 2);
    assert.match(res.stderr, /Unknown command/);
  });

  test("unknown flag exits cleanly with code 2 (no uncaught stack trace)", async () => {
    const res = await runCli(["--nonexistent-flag"]);
    assert.equal(res.exitCode, 2);
    assert.match(res.stderr, /rsc-sentinel:/);
    assert.doesNotMatch(res.stderr, /at parseArgs/);
  });

  test("invalid --fail-on value exits with code 2", async () => {
    const res = await runCli(["check", "--fail-on", "extreme"]);
    assert.equal(res.exitCode, 2);
    assert.match(res.stderr, /Invalid --fail-on/);
  });

  test("missing package.json exits with code 2 and emits valid JSON when --json is passed", async () => {
    const emptyDir = mkdtempSync(join(tmpdir(), "rsc-sentinel-empty-"));
    try {
      const res = await runCli(["check", "--path", emptyDir, "--json"]);
      assert.equal(res.exitCode, 2);
      const parsed = JSON.parse(res.stdout) as {
        error?: { code?: string; message?: string };
      };
      assert.equal(parsed.error?.code, "NO_PACKAGE_JSON");
      assert.ok(parsed.error?.message?.includes("No package.json"));
    } finally {
      rmSync(emptyDir, { recursive: true, force: true });
    }
  });

  test("missing package-lock.json exits with code 2 and NO_LOCKFILE code", async () => {
    const dir = mkdtempSync(join(tmpdir(), "rsc-sentinel-nolock-"));
    try {
      writeFileSync(
        join(dir, "package.json"),
        JSON.stringify({ name: "fixture", version: "1.0.0" }),
      );
      const res = await runCli(["check", "--path", dir, "--json"]);
      assert.equal(res.exitCode, 2);
      const parsed = JSON.parse(res.stdout) as {
        error?: { code?: string };
      };
      assert.equal(parsed.error?.code, "NO_LOCKFILE");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("check --json against current repo returns valid ScanResult and exits 0", async () => {
    const res = await runCli(["check", "--path", REPO_ROOT, "--json"]);
    assert.equal(res.exitCode, 0);
    const parsed = JSON.parse(res.stdout) as {
      clean: boolean;
      findings: unknown[];
      rscFindings: unknown[];
      totalsBySeverity: Record<string, number>;
    };
    assert.equal(parsed.clean, true);
    assert.ok(Array.isArray(parsed.findings));
    assert.ok(Array.isArray(parsed.rscFindings));
    assert.equal(parsed.totalsBySeverity.critical, 0);
  });
});

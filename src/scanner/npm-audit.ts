import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { existsSync } from "node:fs";
import { join } from "node:path";
import type { NpmAuditReport } from "./types.js";

const execFileAsync = promisify(execFile);

export class NpmAuditError extends Error {
  constructor(
    message: string,
    public readonly code?: string,
  ) {
    super(message);
    this.name = "NpmAuditError";
  }
}

/**
 * Runs `npm audit --json` in the given project directory and returns the
 * parsed report.
 *
 * Important: npm audit exits with a non-zero code whenever it *finds*
 * vulnerabilities — that's expected behavior, not a failed command. We only
 * treat it as a real error when stdout doesn't parse into a report shape
 * (e.g. npm returns an `{ "error": ... }` payload, which happens for things
 * like a missing lockfile).
 */
export async function runNpmAudit(
  projectPath: string,
): Promise<NpmAuditReport> {
  if (!existsSync(join(projectPath, "package.json"))) {
    throw new NpmAuditError(
      `No package.json found in ${projectPath}. Run rsc-sentinel from your project root.`,
    );
  }
  if (!existsSync(join(projectPath, "package-lock.json"))) {
    throw new NpmAuditError(
      "No package-lock.json found. npm audit needs a lockfile — run `npm install` first. " +
        "(yarn.lock / pnpm-lock.yaml projects aren't supported yet: npm audit only reads its own lockfile format.)",
      "NO_LOCKFILE",
    );
  }

  let stdout: string;
  try {
    const result = await execFileAsync("npm", ["audit", "--json"], {
      cwd: projectPath,
      maxBuffer: 1024 * 1024 * 32,
    });
    stdout = result.stdout;
  } catch (err) {
    // execFile rejects on non-zero exit codes. npm audit uses a non-zero
    // exit specifically to signal "vulnerabilities were found" — the JSON
    // report is still on stdout and is what we actually want.
    const execErr = err as { stdout?: unknown; stderr?: unknown };
    if (typeof execErr.stdout === "string" && execErr.stdout.length > 0) {
      stdout = execErr.stdout;
    } else {
      throw new NpmAuditError(
        `npm audit produced no output. stderr: ${String(execErr.stderr ?? "(none)")}`,
      );
    }
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(stdout);
  } catch {
    throw new NpmAuditError("npm audit did not return valid JSON output.");
  }

  if (isErrorPayload(parsed)) {
    throw new NpmAuditError(
      parsed.error.summary ?? "npm audit reported an error.",
      parsed.error.code,
    );
  }

  if (!isAuditReport(parsed)) {
    throw new NpmAuditError(
      "npm audit returned an unexpected shape. Your npm version may format audit output differently — this package was verified against npm 10.x.",
    );
  }

  return parsed;
}

function isErrorPayload(
  value: unknown,
): value is { error: { code?: string; summary?: string } } {
  return (
    !!value &&
    typeof value === "object" &&
    "error" in value &&
    !!(value as { error: unknown }).error
  );
}

function isAuditReport(value: unknown): value is NpmAuditReport {
  return (
    !!value &&
    typeof value === "object" &&
    "vulnerabilities" in value &&
    typeof (value as { vulnerabilities: unknown }).vulnerabilities === "object"
  );
}

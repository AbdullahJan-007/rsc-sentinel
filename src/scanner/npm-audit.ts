import { existsSync } from "node:fs";
import { join, resolve } from "node:path";
import { execNpm } from "../utils/npm-runner.js";
import type { NpmAuditReport } from "./types.js";

export type NpmAuditErrorCode =
  | "NO_PACKAGE_JSON"
  | "NO_LOCKFILE"
  | "NPM_NOT_FOUND"
  | "TIMEOUT"
  | "NO_OUTPUT"
  | "INVALID_JSON"
  | "UNEXPECTED_SHAPE"
  | (string & {});

export class NpmAuditError extends Error {
  constructor(
    message: string,
    public readonly code?: NpmAuditErrorCode,
  ) {
    super(message);
    this.name = "NpmAuditError";
  }
}

export interface RunNpmAuditOptions {
  /** Timeout in milliseconds for `npm audit --json`. Default: 60000 (60s). */
  timeoutMs?: number;
}

/**
 * Runs `npm audit --json` in the given project directory and returns the
 * parsed report.
 *
 * Important: `npm audit` exits with a non-zero code whenever it finds
 * vulnerabilities — that's expected behavior, not a failed command. We only
 * throw when `npm` cannot run, times out, returns an `{ "error": ... }` payload,
 * or returns invalid/unexpected JSON.
 */
export async function runNpmAudit(
  projectPath: string,
  options: RunNpmAuditOptions = {},
): Promise<NpmAuditReport> {
  const resolvedPath = resolve(projectPath);

  if (!existsSync(join(resolvedPath, "package.json"))) {
    throw new NpmAuditError(
      `No package.json found in ${resolvedPath}. Run rsc-sentinel from your project root or pass --path <dir>.`,
      "NO_PACKAGE_JSON",
    );
  }
  if (!existsSync(join(resolvedPath, "package-lock.json"))) {
    throw new NpmAuditError(
      "No package-lock.json found. npm audit needs a lockfile — run `npm install` first. " +
        "(yarn.lock / pnpm-lock.yaml projects aren't supported yet: npm audit only reads its own lockfile format.)",
      "NO_LOCKFILE",
    );
  }

  const execOpts =
    options.timeoutMs !== undefined
      ? { cwd: resolvedPath, timeoutMs: options.timeoutMs }
      : { cwd: resolvedPath };

  const execResult = await execNpm(["audit", "--json"], execOpts);

  if (execResult.timedOut) {
    throw new NpmAuditError(
      `npm audit timed out after ${options.timeoutMs ?? 60_000}ms. Check your network connection to the npm registry.`,
      "TIMEOUT",
    );
  }

  if (execResult.spawnErrorCode === "ENOENT") {
    throw new NpmAuditError(
      "Could not find `npm` on PATH. Ensure Node.js and npm are installed and accessible.",
      "NPM_NOT_FOUND",
    );
  }

  const stdout = execResult.stdout.trim();
  if (stdout.length === 0) {
    const detail = execResult.stderr.trim() || execResult.spawnErrorCode || "(none)";
    throw new NpmAuditError(
      `npm audit produced no output. Details: ${detail}`,
      "NO_OUTPUT",
    );
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(stdout);
  } catch {
    throw new NpmAuditError(
      "npm audit did not return valid JSON output.",
      "INVALID_JSON",
    );
  }

  if (isErrorPayload(parsed)) {
    throw new NpmAuditError(
      parsed.error.summary ?? parsed.error.detail ?? "npm audit reported an error.",
      parsed.error.code,
    );
  }

  if (!isAuditReport(parsed)) {
    throw new NpmAuditError(
      "npm audit returned an unexpected shape. Ensure you are running npm 7+ (verified against npm 10.x and 11.x).",
      "UNEXPECTED_SHAPE",
    );
  }

  return parsed;
}

function isErrorPayload(
  value: unknown,
): value is { error: { code?: string; summary?: string; detail?: string } } {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  if (!("error" in value)) return false;
  const errVal = (value as { error: unknown }).error;
  return Boolean(errVal && typeof errVal === "object" && !Array.isArray(errVal));
}

function isAuditReport(value: unknown): value is NpmAuditReport {
  if (!value || typeof value !== "object" || Array.isArray(value)) return false;
  if (!("vulnerabilities" in value)) return false;
  const vulns = (value as { vulnerabilities: unknown }).vulnerabilities;
  return Boolean(vulns && typeof vulns === "object" && !Array.isArray(vulns));
}

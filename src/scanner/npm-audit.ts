import { existsSync } from "node:fs";
import { join, resolve } from "node:path";
import {
  detectPackageManager,
  execPackageManager,
  type PackageManager,
} from "../utils/pm-runner.js";
import {
  normalizePnpmAuditReport,
  normalizeYarnAuditOutput,
} from "./adapters.js";
import type { NpmAuditReport } from "./types.js";

export type NpmAuditErrorCode =
  | "NO_PACKAGE_JSON"
  | "NO_LOCKFILE"
  | "NPM_NOT_FOUND"
  | "PM_NOT_FOUND"
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
  /** Timeout in milliseconds for the audit command. Default: 60000 (60s). */
  timeoutMs?: number;
  /** Package manager to use. Defaults to `"auto"` (lockfile detection). */
  packageManager?: "auto" | PackageManager;
}

export interface AuditExecutionResult {
  packageManager: PackageManager;
  report: NpmAuditReport;
}

/**
 * Runs the appropriate package manager's live audit command (`npm audit --json`,
 * `pnpm audit --json`, or `yarn npm audit --json` / `yarn audit --json`) and
 * returns a normalized `NpmAuditReport`.
 */
export async function runAudit(
  projectPath: string,
  options: RunNpmAuditOptions = {},
): Promise<AuditExecutionResult> {
  const resolvedPath = resolve(projectPath);

  if (!existsSync(join(resolvedPath, "package.json"))) {
    throw new NpmAuditError(
      `No package.json found in ${resolvedPath}. Run rsc-sentinel from your project root or pass --path <dir>.`,
      "NO_PACKAGE_JSON",
    );
  }

  const requestedPm = options.packageManager ?? "auto";
  const pm: PackageManager | null =
    requestedPm === "auto" ? detectPackageManager(resolvedPath) : requestedPm;

  if (!pm) {
    throw new NpmAuditError(
      "No lockfile found (package-lock.json, pnpm-lock.yaml, or yarn.lock). Run your package manager's install command first.",
      "NO_LOCKFILE",
    );
  }

  const execOpts =
    options.timeoutMs !== undefined
      ? { cwd: resolvedPath, timeoutMs: options.timeoutMs }
      : { cwd: resolvedPath };

  if (pm === "pnpm") {
    return {
      packageManager: "pnpm",
      report: await runPnpmAudit(execOpts, options.timeoutMs),
    };
  }

  if (pm === "yarn") {
    return {
      packageManager: "yarn",
      report: await runYarnAudit(execOpts, options.timeoutMs),
    };
  }

  return {
    packageManager: "npm",
    report: await runNpmAuditInternal(resolvedPath, execOpts, options.timeoutMs),
  };
}

/**
 * Backwards-compatible helper that runs `npm audit --json` (or auto-detected PM
 * when `options.packageManager` is provided) and returns `NpmAuditReport`.
 */
export async function runNpmAudit(
  projectPath: string,
  options: RunNpmAuditOptions = {},
): Promise<NpmAuditReport> {
  const { report } = await runAudit(projectPath, {
    ...options,
    packageManager: options.packageManager ?? "npm",
  });
  return report;
}

async function runNpmAuditInternal(
  resolvedPath: string,
  execOpts: { cwd: string; timeoutMs?: number },
  timeoutMs?: number,
): Promise<NpmAuditReport> {
  if (
    !existsSync(join(resolvedPath, "package-lock.json")) &&
    !existsSync(join(resolvedPath, "npm-shrinkwrap.json"))
  ) {
    throw new NpmAuditError(
      "No package-lock.json found. npm audit needs a lockfile — run `npm install` first.",
      "NO_LOCKFILE",
    );
  }

  const execResult = await execPackageManager("npm", ["audit", "--json"], execOpts);

  if (execResult.timedOut) {
    throw new NpmAuditError(
      `npm audit timed out after ${timeoutMs ?? 60_000}ms. Check your network connection to the npm registry.`,
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

async function runPnpmAudit(
  execOpts: { cwd: string; timeoutMs?: number },
  timeoutMs?: number,
): Promise<NpmAuditReport> {
  const execResult = await execPackageManager("pnpm", ["audit", "--json"], execOpts);

  if (execResult.timedOut) {
    throw new NpmAuditError(
      `pnpm audit timed out after ${timeoutMs ?? 60_000}ms.`,
      "TIMEOUT",
    );
  }

  if (execResult.spawnErrorCode === "ENOENT") {
    throw new NpmAuditError(
      "Could not find `pnpm` on PATH. Install pnpm or run with `--pm npm`.",
      "PM_NOT_FOUND",
    );
  }

  const stdout = execResult.stdout.trim();
  if (stdout.length === 0) {
    const detail = execResult.stderr.trim() || execResult.spawnErrorCode || "(none)";
    throw new NpmAuditError(
      `pnpm audit produced no output. Details: ${detail}`,
      "NO_OUTPUT",
    );
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(stdout);
  } catch {
    throw new NpmAuditError(
      "pnpm audit did not return valid JSON output.",
      "INVALID_JSON",
    );
  }

  if (isErrorPayload(parsed)) {
    throw new NpmAuditError(
      parsed.error.summary ?? parsed.error.detail ?? "pnpm audit reported an error.",
      parsed.error.code,
    );
  }

  const normalized = normalizePnpmAuditReport(parsed);
  if (!normalized) {
    throw new NpmAuditError(
      "pnpm audit returned an unexpected JSON shape.",
      "UNEXPECTED_SHAPE",
    );
  }
  return normalized;
}

async function runYarnAudit(
  execOpts: { cwd: string; timeoutMs?: number },
  timeoutMs?: number,
): Promise<NpmAuditReport> {
  // Try Yarn Berry (`yarn npm audit --json`) first; fall back to Yarn Classic v1 (`yarn audit --json`).
  let execResult = await execPackageManager(
    "yarn",
    ["npm", "audit", "--json"],
    execOpts,
  );

  if (execResult.spawnErrorCode === "ENOENT") {
    throw new NpmAuditError(
      "Could not find `yarn` on PATH. Install yarn or run with `--pm npm`.",
      "PM_NOT_FOUND",
    );
  }

  if (execResult.timedOut) {
    throw new NpmAuditError(
      `yarn audit timed out after ${timeoutMs ?? 60_000}ms.`,
      "TIMEOUT",
    );
  }

  let normalized =
    execResult.stdout.trim().length > 0
      ? normalizeYarnAuditOutput(execResult.stdout)
      : null;

  if (!normalized) {
    execResult = await execPackageManager("yarn", ["audit", "--json"], execOpts);
    if (execResult.timedOut) {
      throw new NpmAuditError(
        `yarn audit timed out after ${timeoutMs ?? 60_000}ms.`,
        "TIMEOUT",
      );
    }
    normalized =
      execResult.stdout.trim().length > 0
        ? normalizeYarnAuditOutput(execResult.stdout)
        : null;
  }

  if (!normalized) {
    const detail = execResult.stderr.trim() || "(none)";
    throw new NpmAuditError(
      `yarn audit did not return parseable JSON output. Details: ${detail}`,
      "UNEXPECTED_SHAPE",
    );
  }

  return normalized;
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

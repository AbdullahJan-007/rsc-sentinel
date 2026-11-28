import { execFile } from "node:child_process";
import { existsSync } from "node:fs";
import { join } from "node:path";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

const DEFAULT_MAX_BUFFER_BYTES = 32 * 1024 * 1024;
const DEFAULT_TIMEOUT_MS = 60_000;

export type PackageManager = "npm" | "pnpm" | "yarn";

export interface PmExecOptions {
  cwd: string;
  timeoutMs?: number;
  maxBufferBytes?: number;
}

export interface PmExecResult {
  stdout: string;
  stderr: string;
  exitCode: number;
  timedOut: boolean;
  spawnErrorCode?: string;
}

/**
 * Auto-detects the package manager for a project directory by inspecting lockfiles.
 * Priority: pnpm-lock.yaml > yarn.lock > package-lock.json / npm-shrinkwrap.json.
 */
export function detectPackageManager(projectPath: string): PackageManager | null {
  if (existsSync(join(projectPath, "pnpm-lock.yaml"))) return "pnpm";
  if (existsSync(join(projectPath, "yarn.lock"))) return "yarn";
  if (
    existsSync(join(projectPath, "package-lock.json")) ||
    existsSync(join(projectPath, "npm-shrinkwrap.json"))
  ) {
    return "npm";
  }
  return null;
}

/**
 * Executes a package manager CLI (`npm`, `pnpm`, or `yarn`) with fixed,
 * non-user-controlled arguments in a cross-platform way.
 *
 * On Windows, `npm`, `pnpm`, and `yarn` are `.cmd` batch shims. Routing
 * through `cmd.exe /d /s /c <pm> ...` with `windowsHide: true` works reliably
 * across Node.js 20/22/24 (after CVE-2024-27980) while keeping arguments explicit.
 */
export async function execPackageManager(
  pm: PackageManager,
  args: readonly string[],
  options: PmExecOptions,
): Promise<PmExecResult> {
  const timeout = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const maxBuffer = options.maxBufferBytes ?? DEFAULT_MAX_BUFFER_BYTES;

  const isWin = process.platform === "win32";
  const command = isWin ? (process.env.ComSpec ?? "cmd.exe") : pm;
  const finalArgs = isWin ? ["/d", "/s", "/c", pm, ...args] : [...args];

  try {
    const { stdout, stderr } = await execFileAsync(command, finalArgs, {
      cwd: options.cwd,
      maxBuffer,
      timeout,
      windowsHide: true,
    });
    return {
      stdout: String(stdout),
      stderr: String(stderr),
      exitCode: 0,
      timedOut: false,
    };
  } catch (err) {
    const execErr = err as {
      stdout?: unknown;
      stderr?: unknown;
      code?: unknown;
      killed?: boolean;
      signal?: string | null;
    };

    const timedOut = Boolean(execErr.killed && execErr.signal === "SIGTERM");
    const numericCode = typeof execErr.code === "number" ? execErr.code : 1;
    const result: PmExecResult = {
      stdout: typeof execErr.stdout === "string" ? execErr.stdout : "",
      stderr: typeof execErr.stderr === "string" ? execErr.stderr : "",
      exitCode: numericCode,
      timedOut,
    };
    if (typeof execErr.code === "string") {
      result.spawnErrorCode = execErr.code;
    }
    return result;
  }
}

/**
 * Backwards-compatible alias for `execPackageManager("npm", ...)`.
 */
export async function execNpm(
  args: readonly string[],
  options: PmExecOptions,
): Promise<PmExecResult> {
  return execPackageManager("npm", args, options);
}

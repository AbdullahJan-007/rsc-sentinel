import { execFile } from "node:child_process";
import { promisify } from "node:util";

const execFileAsync = promisify(execFile);

const DEFAULT_MAX_BUFFER_BYTES = 32 * 1024 * 1024;
const DEFAULT_TIMEOUT_MS = 60_000;

export interface NpmExecOptions {
  cwd: string;
  timeoutMs?: number;
  maxBufferBytes?: number;
}

export interface NpmExecResult {
  stdout: string;
  stderr: string;
  exitCode: number;
  timedOut: boolean;
  spawnErrorCode?: string;
}

/**
 * Executes `npm` with fixed, non-user-controlled arguments in a cross-platform way.
 *
 * On Windows, `npm` is a `.cmd` batch shim (`npm.cmd`). Since Node.js 20.12+
 * (CVE-2024-27980), invoking `.cmd` directly with `execFile` without a shell
 * fails with `ENOENT` or `EINVAL`. Routing through `cmd.exe /d /s /c npm ...`
 * with `windowsHide: true` works reliably across Node 20/22/24 while keeping
 * argument handling explicit.
 */
export async function execNpm(
  args: readonly string[],
  options: NpmExecOptions,
): Promise<NpmExecResult> {
  const timeout = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const maxBuffer = options.maxBufferBytes ?? DEFAULT_MAX_BUFFER_BYTES;

  const isWin = process.platform === "win32";
  const command = isWin ? (process.env.ComSpec ?? "cmd.exe") : "npm";
  const finalArgs = isWin ? ["/d", "/s", "/c", "npm", ...args] : [...args];

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
    const numericCode =
      typeof execErr.code === "number" ? execErr.code : 1;
    const result: NpmExecResult = {
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

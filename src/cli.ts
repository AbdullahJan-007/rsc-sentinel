#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { parseArgs } from "node:util";
import { scan } from "./scanner/scan.js";
import { NpmAuditError } from "./scanner/npm-audit.js";
import {
  VALID_SEVERITIES,
  isSeverity,
  type Finding,
  type ScanResult,
  type Severity,
} from "./scanner/types.js";
import { execNpm } from "./utils/npm-runner.js";

function loadPackageVersion(): string {
  try {
    const pkgPath = new URL("../package.json", import.meta.url);
    const parsed = JSON.parse(readFileSync(pkgPath, "utf-8")) as {
      version?: unknown;
    };
    return typeof parsed.version === "string" ? parsed.version : "0.0.0";
  } catch {
    return "0.0.0";
  }
}

const VERSION = loadPackageVersion();

const SEVERITY_LABEL: Record<Severity, string> = {
  critical: "CRITICAL",
  high: "HIGH",
  moderate: "MODERATE",
  low: "LOW",
  info: "INFO",
};

function printHelp(stream: "stdout" | "stderr" = "stdout"): void {
  const text = `rsc-sentinel v${VERSION}

Live vulnerability scanning for React Server Components / Next.js projects.
Queries npm's live advisory database at run time — never a stale hardcoded list.

Usage:
  rsc-sentinel check [options]
  rsc-sentinel fix [--force] [--path <dir>]
  rsc-sentinel --help
  rsc-sentinel --version

Commands:
  check   Scan the project and report known vulnerabilities (default).
  fix     Run npm's own audit fix. Without --force, only applies non-breaking
          fixes. With --force, allows semver-major upgrades (review & test first).

Options:
  --json                 Print machine-readable JSON output (including errors).
  --path <dir>           Project directory to scan. Defaults to current directory.
  --rsc-only             Only report and fail on RSC / Flight-protocol findings.
  --fail-on <severity>   Minimum severity to report/fail on:
                         info | low | moderate | high | critical (default: info).
  --timeout <ms>         Timeout for npm audit in milliseconds (default: 60000).
  --force                (fix only) Allow npm to apply semver-major fixes.
  -h, --help             Show this help message.
  -v, --version          Print version number.

Exit Codes:
  0  Clean (no findings meeting the filter threshold).
  1  Vulnerabilities found (or fix left unresolved issues).
  2  Configuration, CLI usage, or scanner execution error.
`;
  if (stream === "stderr") {
    console.error(text);
  } else {
    console.log(text);
  }
}

function formatFixLine(f: Finding): string {
  const breakingTag = f.fixIsBreaking ? " (semver-major)" : "";
  if (f.fixPackage && f.fixedIn) {
    return `fix: upgrade ${f.fixPackage} to ${f.fixedIn}${breakingTag}`;
  }
  if (f.fixedIn) {
    return `fix: upgrade to ${f.fixedIn}${breakingTag}`;
  }
  if (f.fixAvailable) {
    return `fix: available via \`rsc-sentinel fix\`${breakingTag}`;
  }
  return "fix: none published yet";
}

function formatFinding(f: Finding): string {
  const tag = f.isRscRelated ? " [RSC]" : "";
  const installed = f.installedVersion ? `@${f.installedVersion}` : "";
  const cvss = f.cvssScore !== null ? ` (CVSS ${f.cvssScore})` : "";
  return [
    `  [${SEVERITY_LABEL[f.severity]}]${tag} ${f.packageName}${installed}`,
    `    ${f.title}${cvss}`,
    `    vulnerable range: ${f.vulnerableRange}`,
    `    ${formatFixLine(f)}`,
    `    ${f.url}`,
  ].join("\n");
}

function printReport(result: ScanResult): void {
  if (result.clean) {
    console.log("No known vulnerabilities found matching the scan criteria.");
    return;
  }

  const t = result.totalsBySeverity;
  console.log(
    `Found ${result.findings.length} finding(s): ` +
      `${t.critical} critical, ${t.high} high, ${t.moderate} moderate, ${t.low} low, ${t.info} info.`,
  );

  if (result.rscFindings.length > 0) {
    console.log(
      `\n${result.rscFindings.length} of these are React Server Components / Flight-protocol related:\n`,
    );
    for (const f of result.rscFindings) console.log(formatFinding(f), "\n");
  }

  const others = result.findings.filter((f) => !f.isRscRelated);
  if (others.length > 0) {
    console.log(`\nOther findings (not RSC-specific):\n`);
    for (const f of others) console.log(formatFinding(f), "\n");
  }

  console.log("Run `rsc-sentinel fix` to apply available non-breaking fixes.");
}

function emitError(message: string, code: string, json: boolean): void {
  if (json) {
    console.log(JSON.stringify({ error: { code, message } }, null, 2));
  } else {
    console.error(`rsc-sentinel: ${message}`);
  }
}

async function runCheck(opts: {
  projectPath: string;
  json: boolean;
  rscOnly: boolean;
  minSeverity: Severity;
  timeoutMs: number | undefined;
}): Promise<number> {
  try {
    const scanOpts: {
      projectPath: string;
      rscOnly: boolean;
      minSeverity: Severity;
      timeoutMs?: number;
    } = {
      projectPath: opts.projectPath,
      rscOnly: opts.rscOnly,
      minSeverity: opts.minSeverity,
    };
    if (opts.timeoutMs !== undefined) {
      scanOpts.timeoutMs = opts.timeoutMs;
    }

    const result = await scan(scanOpts);
    if (opts.json) {
      console.log(JSON.stringify(result, null, 2));
    } else {
      printReport(result);
    }
    return result.clean ? 0 : 1;
  } catch (err) {
    if (err instanceof NpmAuditError) {
      emitError(err.message, err.code ?? "AUDIT_ERROR", opts.json);
      return 2;
    }
    throw err;
  }
}

async function runFix(projectPath: string, force: boolean): Promise<number> {
  const resolvedPath = resolve(projectPath);
  const args = force ? ["audit", "fix", "--force"] : ["audit", "fix"];
  console.log(`Running: npm ${args.join(" ")}`);

  const res = await execNpm(args, { cwd: resolvedPath });

  if (res.spawnErrorCode === "ENOENT") {
    console.error(
      "rsc-sentinel: Could not find `npm` on PATH. Ensure Node.js and npm are installed.",
    );
    return 2;
  }

  if (res.timedOut) {
    console.error("rsc-sentinel: npm audit fix timed out.");
    return 2;
  }

  if (res.stdout) console.log(res.stdout);
  if (res.stderr) console.error(res.stderr);

  if (res.exitCode === 0) {
    return 0;
  }

  console.log(
    "\nSome fixes may require a semver-major upgrade. Re-run with --force to allow those, " +
      "then re-run `rsc-sentinel check` and your own test suite before committing.",
  );
  return 1;
}

export async function main(argv: string[] = process.argv.slice(2)): Promise<number> {
  const wantsJson = argv.includes("--json");

  let parsed: ReturnType<typeof parseArgs>;
  try {
    parsed = parseArgs({
      args: argv,
      allowPositionals: true,
      options: {
        json: { type: "boolean", default: false },
        path: { type: "string" },
        force: { type: "boolean", default: false },
        "rsc-only": { type: "boolean", default: false },
        "fail-on": { type: "string" },
        timeout: { type: "string" },
        help: { type: "boolean", short: "h", default: false },
        version: { type: "boolean", short: "v", default: false },
      },
    });
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    emitError(message, "INVALID_ARGS", wantsJson);
    return 2;
  }

  const { positionals, values } = parsed;
  const json = Boolean(values.json);

  if (values.version) {
    console.log(VERSION);
    return 0;
  }

  if (values.help) {
    printHelp("stdout");
    return 0;
  }

  const rawCommand = positionals[0];
  if (rawCommand !== undefined && rawCommand !== "check" && rawCommand !== "fix") {
    emitError(
      `Unknown command "${rawCommand}". Expected "check" or "fix". Run \`rsc-sentinel --help\` for usage.`,
      "UNKNOWN_COMMAND",
      json,
    );
    return 2;
  }

  const command = rawCommand ?? "check";
  const projectPath = typeof values.path === "string" ? values.path : process.cwd();

  let minSeverity: Severity = "info";
  if (typeof values["fail-on"] === "string") {
    const candidate = values["fail-on"].toLowerCase();
    if (!isSeverity(candidate)) {
      emitError(
        `Invalid --fail-on value "${values["fail-on"]}". Expected one of: ${VALID_SEVERITIES.join(", ")}.`,
        "INVALID_SEVERITY",
        json,
      );
      return 2;
    }
    minSeverity = candidate;
  }

  let timeoutMs: number | undefined;
  if (typeof values.timeout === "string") {
    const num = Number(values.timeout);
    if (!Number.isFinite(num) || num <= 0) {
      emitError(
        `Invalid --timeout value "${values.timeout}". Expected a positive number of milliseconds.`,
        "INVALID_TIMEOUT",
        json,
      );
      return 2;
    }
    timeoutMs = num;
  }

  if (command === "fix") {
    return runFix(projectPath, Boolean(values.force));
  }

  return runCheck({
    projectPath,
    json,
    rscOnly: Boolean(values["rsc-only"]),
    minSeverity,
    timeoutMs,
  });
}

#!/usr/bin/env node
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { parseArgs } from "node:util";
import { scan, toSarif } from "./scanner/scan.js";
import { NpmAuditError } from "./scanner/npm-audit.js";
import {
  VALID_SEVERITIES,
  isSeverity,
  type Finding,
  type ScanResult,
  type Severity,
} from "./scanner/types.js";
import {
  detectPackageManager,
  execPackageManager,
  type PackageManager,
} from "./utils/pm-runner.js";

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
const VALID_PMS = ["auto", "npm", "pnpm", "yarn"] as const;
type PmOption = (typeof VALID_PMS)[number];

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
Queries live advisory data via npm, pnpm, or yarn — never a stale hardcoded list.

Usage:
  rsc-sentinel check [options]
  rsc-sentinel fix [--force] [--path <dir>] [--pm <auto|npm|pnpm|yarn>]
  rsc-sentinel --help
  rsc-sentinel --version

Commands:
  check   Scan the project and report known vulnerabilities (default).
  fix     Run your package manager's audit fix (npm/pnpm). Without --force,
          only applies non-breaking fixes.

Options:
  --json                 Print machine-readable JSON output (including errors).
  --sarif                Print SARIF 2.1.0 output for GitHub Code Scanning.
  --path <dir>           Project directory to scan. Defaults to current directory.
  --pm <manager>         Package manager: auto | npm | pnpm | yarn (default: auto).
  --rsc-only             Only report and fail on RSC / Flight-protocol findings.
  --fail-on <severity>   Minimum severity to report/fail on:
                         info | low | moderate | high | critical (default: info).
  --timeout <ms>         Timeout for the audit command in milliseconds (default: 60000).
  --force                (fix only) Allow semver-major fixes (npm).
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
  const pmTag = result.packageManager ? ` via ${result.packageManager}` : "";
  console.log(
    `Found ${result.findings.length} finding(s)${pmTag}: ` +
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
  sarif: boolean;
  packageManager: PmOption;
  rscOnly: boolean;
  minSeverity: Severity;
  timeoutMs: number | undefined;
}): Promise<number> {
  try {
    const scanOpts: {
      projectPath: string;
      packageManager: PmOption;
      rscOnly: boolean;
      minSeverity: Severity;
      timeoutMs?: number;
    } = {
      projectPath: opts.projectPath,
      packageManager: opts.packageManager,
      rscOnly: opts.rscOnly,
      minSeverity: opts.minSeverity,
    };
    if (opts.timeoutMs !== undefined) {
      scanOpts.timeoutMs = opts.timeoutMs;
    }

    const result = await scan(scanOpts);
    if (opts.sarif) {
      console.log(JSON.stringify(toSarif(result, VERSION), null, 2));
    } else if (opts.json) {
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

async function runFix(
  projectPath: string,
  force: boolean,
  pmOption: PmOption,
): Promise<number> {
  const resolvedPath = resolve(projectPath);
  const pm: PackageManager =
    pmOption === "auto"
      ? (detectPackageManager(resolvedPath) ?? "npm")
      : pmOption;

  if (pm === "yarn") {
    console.error(
      "rsc-sentinel: Yarn does not provide an automated `audit fix` command. " +
        "Upgrade affected packages with `yarn up <pkg>` or add `resolutions` in package.json.",
    );
    return 2;
  }

  const args =
    pm === "pnpm"
      ? ["audit", "--fix"]
      : force
        ? ["audit", "fix", "--force"]
        : ["audit", "fix"];

  console.log(`Running: ${pm} ${args.join(" ")}`);
  const res = await execPackageManager(pm, args, { cwd: resolvedPath });

  if (res.spawnErrorCode === "ENOENT") {
    console.error(
      `rsc-sentinel: Could not find \`${pm}\` on PATH. Ensure it is installed and accessible.`,
    );
    return 2;
  }

  if (res.timedOut) {
    console.error(`rsc-sentinel: ${pm} audit fix timed out.`);
    return 2;
  }

  if (res.stdout) console.log(res.stdout);
  if (res.stderr) console.error(res.stderr);

  if (res.exitCode === 0) {
    return 0;
  }

  console.log(
    "\nSome fixes may require a semver-major upgrade. Review affected packages, " +
      "then re-run `rsc-sentinel check` and your test suite before committing.",
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
        sarif: { type: "boolean", default: false },
        path: { type: "string" },
        pm: { type: "string" },
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
  const sarif = Boolean(values.sarif);

  if (values.version) {
    console.log(VERSION);
    return 0;
  }

  if (values.help) {
    printHelp("stdout");
    return 0;
  }

  if (json && sarif) {
    emitError(
      "Options --json and --sarif cannot be combined. Choose one output format.",
      "CONFLICTING_FLAGS",
      false,
    );
    return 2;
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

  let pmOption: PmOption = "auto";
  if (typeof values.pm === "string") {
    const candidate = values.pm.toLowerCase();
    if (!(VALID_PMS as readonly string[]).includes(candidate)) {
      emitError(
        `Invalid --pm value "${values.pm}". Expected one of: ${VALID_PMS.join(", ")}.`,
        "INVALID_PM",
        json,
      );
      return 2;
    }
    pmOption = candidate as PmOption;
  }

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
    return runFix(projectPath, Boolean(values.force), pmOption);
  }

  return runCheck({
    projectPath,
    json,
    sarif,
    packageManager: pmOption,
    rscOnly: Boolean(values["rsc-only"]),
    minSeverity,
    timeoutMs,
  });
}

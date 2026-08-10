#!/usr/bin/env node
import { parseArgs } from "node:util";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { scan } from "./scanner/scan.js";
import { NpmAuditError } from "./scanner/npm-audit.js";
import type { Finding, ScanResult, Severity } from "./scanner/types.js";

const execFileAsync = promisify(execFile);

const VERSION = "0.1.0";

const SEVERITY_LABEL: Record<Severity, string> = {
  critical: "CRITICAL",
  high: "HIGH",
  moderate: "MODERATE",
  low: "LOW",
  info: "INFO",
};

function printHelp(): void {
  console.log(`rsc-sentinel v${VERSION}

Live vulnerability scanning for React Server Components / Next.js projects.
Queries npm's audit data at run time — findings reflect whatever advisories
are published right now, not a hardcoded list.

Usage:
  rsc-sentinel check [--json] [--path <dir>]
  rsc-sentinel fix [--force] [--path <dir>]
  rsc-sentinel --help
  rsc-sentinel --version

Commands:
  check   Scan the project and report known vulnerabilities (default).
  fix     Run npm's own audit fix. Without --force, only applies fixes that
          don't require a semver-major bump. --force allows breaking fixes —
          review what it changes before committing.

Options:
  --json         Print machine-readable JSON instead of a formatted report.
  --path <dir>   Project directory to scan. Defaults to the current directory.
  --force        (fix only) Allow npm to apply semver-major fixes.
`);
}

function formatFinding(f: Finding): string {
  const tag = f.isRscRelated ? " [RSC]" : "";
  const installed = f.installedVersion ? `@${f.installedVersion}` : "";
  const cvss = f.cvssScore !== null ? ` (CVSS ${f.cvssScore})` : "";
  const fix = f.fixedIn
    ? `fix: upgrade to ${f.fixedIn}${f.fixIsBreaking ? " (semver-major)" : ""}`
    : "fix: none published yet";
  return [
    `  [${SEVERITY_LABEL[f.severity]}]${tag} ${f.packageName}${installed}`,
    `    ${f.title}${cvss}`,
    `    vulnerable range: ${f.vulnerableRange}`,
    `    ${fix}`,
    `    ${f.url}`,
  ].join("\n");
}

function printReport(result: ScanResult): void {
  if (result.clean) {
    console.log("No known vulnerabilities found by npm audit.");
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

async function runCheck(projectPath: string, json: boolean): Promise<number> {
  try {
    const result = await scan({ projectPath });
    if (json) {
      console.log(JSON.stringify(result, null, 2));
    } else {
      printReport(result);
    }
    return result.clean ? 0 : 1;
  } catch (err) {
    if (err instanceof NpmAuditError) {
      console.error(`rsc-sentinel: ${err.message}`);
      return 2;
    }
    throw err;
  }
}

async function runFix(projectPath: string, force: boolean): Promise<number> {
  const args = force ? ["audit", "fix", "--force"] : ["audit", "fix"];
  console.log(`Running: npm ${args.join(" ")}`);
  try {
    const { stdout } = await execFileAsync("npm", args, { cwd: projectPath });
    console.log(stdout);
    return 0;
  } catch (err) {
    const execErr = err as { stdout?: string; stderr?: string };
    if (execErr.stdout) console.log(execErr.stdout);
    if (execErr.stderr) console.error(execErr.stderr);
    console.log(
      "\nSome fixes may require a semver-major upgrade. Re-run with --force to allow those, " +
        "then re-run `rsc-sentinel check` and your own test suite before committing.",
    );
    return 1;
  }
}

async function main(): Promise<void> {
  const { positionals, values } = parseArgs({
    args: process.argv.slice(2),
    allowPositionals: true,
    options: {
      json: { type: "boolean", default: false },
      path: { type: "string" },
      force: { type: "boolean", default: false },
      help: { type: "boolean", default: false },
      version: { type: "boolean", default: false },
    },
  });

  if (values.version) {
    console.log(VERSION);
    return;
  }
  if (values.help || (positionals[0] !== "check" && positionals[0] !== "fix" && positionals[0])) {
    printHelp();
    return;
  }

  const command = positionals[0] ?? "check";
  const projectPath = values.path ?? process.cwd();

  const exitCode =
    command === "fix"
      ? await runFix(projectPath, values.force)
      : await runCheck(projectPath, values.json);

  process.exitCode = exitCode;
}

main().catch((err: unknown) => {
  console.error("rsc-sentinel: unexpected error");
  console.error(err);
  process.exitCode = 2;
});

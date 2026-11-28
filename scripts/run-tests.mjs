import { readdirSync, existsSync } from "node:fs";
import { join, resolve } from "node:path";
import { spawnSync } from "node:child_process";

const suites = process.argv.slice(2);
const targetDirs =
  suites.length > 0
    ? suites.map((s) => resolve("dist-test", "tests", s))
    : [
        resolve("dist-test", "tests", "unit"),
        resolve("dist-test", "tests", "security"),
        resolve("dist-test", "tests", "integration"),
      ];

const testFiles = [];
for (const dir of targetDirs) {
  if (!existsSync(dir)) continue;
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (entry.isFile() && entry.name.endsWith(".test.js")) {
      testFiles.push(join(dir, entry.name));
    }
  }
}

testFiles.sort();

if (testFiles.length === 0) {
  console.error("No compiled *.test.js files found. Run `npm run build:test` first.");
  process.exit(1);
}

const result = spawnSync(process.execPath, ["--test", ...testFiles], {
  stdio: "inherit",
});

process.exit(result.status ?? 1);

import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";

/**
 * Reads the version actually resolved into node_modules for a package,
 * straight from that package's own package.json.
 *
 * This deliberately does NOT read the version range declared in the
 * project's root package.json. A range like "^19.1.0" only tells you what
 * versions npm is *allowed* to install — it says nothing about which one
 * is actually sitting in node_modules right now. Checking the range instead
 * of the resolved copy is exactly the kind of check that silently passes
 * on a vulnerable install and fails to catch it.
 */
export function getInstalledVersion(
  projectPath: string,
  packageName: string,
): string | null {
  const pkgJsonPath = join(projectPath, "node_modules", packageName, "package.json");
  if (!existsSync(pkgJsonPath)) {
    return null;
  }
  try {
    const raw = readFileSync(pkgJsonPath, "utf-8");
    const parsed = JSON.parse(raw) as { version?: unknown };
    return typeof parsed.version === "string" ? parsed.version : null;
  } catch {
    return null;
  }
}

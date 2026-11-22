import { readFileSync, existsSync } from "node:fs";
import { dirname, relative, resolve, sep } from "node:path";

/**
 * Valid npm package name pattern (unscoped or `@scope/name`).
 * Rejects path traversal segments (`..`, leading slashes, null bytes, backslashes).
 */
const VALID_PACKAGE_NAME_RE = /^(?:@[a-z0-9-~][a-z0-9-._~]*\/)?[a-z0-9-~][a-z0-9-._~]*$/i;

const MAX_HOIST_WALK_DEPTH = 10;

function isPathInside(parentDir: string, candidatePath: string): boolean {
  const rel = relative(parentDir, candidatePath);
  return rel.length > 0 && !rel.startsWith("..") && !rel.startsWith(sep) && !rel.includes(`..${sep}`);
}

function readPackageVersionFromFile(pkgJsonPath: string): string | null {
  if (!existsSync(pkgJsonPath)) {
    return null;
  }
  try {
    const raw = readFileSync(pkgJsonPath, "utf-8");
    const parsed = JSON.parse(raw) as { version?: unknown };
    return typeof parsed.version === "string" && parsed.version.length > 0
      ? parsed.version
      : null;
  } catch {
    return null;
  }
}

/**
 * Reads the version actually resolved into `node_modules` for a package,
 * straight from that package's own `package.json`.
 *
 * Resolution order:
 * 1. Exact `nodes` paths reported by `npm audit` (catches nested dependencies
 *    like `node_modules/next/node_modules/react-server-dom-webpack`).
 * 2. Direct `<projectPath>/node_modules/<packageName>/package.json`.
 * 3. Ancestor `node_modules` directories up to 10 levels (supports npm
 *    workspaces / monorepo hoisting).
 *
 * All candidate paths are validated to stay inside their expected root to
 * prevent path traversal from untrusted audit reports.
 */
export function getInstalledVersion(
  projectPath: string,
  packageName: string,
  auditNodes?: readonly string[],
): string | null {
  if (!packageName || !VALID_PACKAGE_NAME_RE.test(packageName)) {
    return null;
  }

  const rootDir = resolve(projectPath);

  // 1. Check exact node paths reported by npm audit (handles nested deps)
  if (auditNodes && auditNodes.length > 0) {
    for (const nodePath of auditNodes) {
      if (typeof nodePath !== "string" || nodePath.length === 0) continue;
      if (nodePath.includes("\0")) continue;
      const candidatePkgJson = resolve(rootDir, nodePath, "package.json");
      if (!isPathInside(rootDir, candidatePkgJson)) continue;
      const version = readPackageVersionFromFile(candidatePkgJson);
      if (version !== null) return version;
    }
  }

  // 2 & 3. Check project node_modules, then walk up for hoisted monorepo installs
  let currentDir = rootDir;
  for (let depth = 0; depth <= MAX_HOIST_WALK_DEPTH; depth++) {
    const nodeModulesDir = resolve(currentDir, "node_modules");
    const candidatePkgJson = resolve(nodeModulesDir, packageName, "package.json");
    if (isPathInside(nodeModulesDir, candidatePkgJson)) {
      const version = readPackageVersionFromFile(candidatePkgJson);
      if (version !== null) return version;
    }

    const parentDir = dirname(currentDir);
    if (parentDir === currentDir) break;
    currentDir = parentDir;
  }

  return null;
}

/**
 * Helper exported for testing path validation directly.
 */
export function isValidPackageName(name: string): boolean {
  return VALID_PACKAGE_NAME_RE.test(name);
}

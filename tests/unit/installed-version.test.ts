import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  getInstalledVersion,
  isValidPackageName,
} from "../../src/utils/installed-version.js";

describe("getInstalledVersion", () => {
  test("reads direct node_modules package version", () => {
    const dir = mkdtempSync(join(tmpdir(), "rsc-sentinel-ver-"));
    try {
      mkdirSync(join(dir, "node_modules", "next"), { recursive: true });
      writeFileSync(
        join(dir, "node_modules", "next", "package.json"),
        JSON.stringify({ name: "next", version: "15.2.3" }),
      );
      assert.equal(getInstalledVersion(dir, "next"), "15.2.3");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("reads scoped package version (@scope/name)", () => {
    const dir = mkdtempSync(join(tmpdir(), "rsc-sentinel-scoped-"));
    try {
      mkdirSync(join(dir, "node_modules", "@next", "env"), { recursive: true });
      writeFileSync(
        join(dir, "node_modules", "@next", "env", "package.json"),
        JSON.stringify({ name: "@next/env", version: "15.2.3" }),
      );
      assert.equal(getInstalledVersion(dir, "@next/env"), "15.2.3");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("resolves nested dependency via npm audit nodes array", () => {
    const dir = mkdtempSync(join(tmpdir(), "rsc-sentinel-nested-"));
    try {
      const nestedPath = join(
        dir,
        "node_modules",
        "next",
        "node_modules",
        "react-server-dom-webpack",
      );
      mkdirSync(nestedPath, { recursive: true });
      writeFileSync(
        join(nestedPath, "package.json"),
        JSON.stringify({ name: "react-server-dom-webpack", version: "19.1.4" }),
      );
      assert.equal(
        getInstalledVersion(dir, "react-server-dom-webpack", [
          "node_modules/next/node_modules/react-server-dom-webpack",
        ]),
        "19.1.4",
      );
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  test("walks up parent node_modules for monorepo hoisted dependencies", () => {
    const root = mkdtempSync(join(tmpdir(), "rsc-sentinel-mono-"));
    try {
      const appDir = join(root, "apps", "web");
      mkdirSync(appDir, { recursive: true });
      mkdirSync(join(root, "node_modules", "react"), { recursive: true });
      writeFileSync(
        join(root, "node_modules", "react", "package.json"),
        JSON.stringify({ name: "react", version: "19.2.8" }),
      );
      assert.equal(getInstalledVersion(appDir, "react"), "19.2.8");
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  test("rejects path traversal package names and malicious audit node paths", () => {
    const root = mkdtempSync(join(tmpdir(), "rsc-sentinel-trav-"));
    try {
      const subDir = join(root, "project");
      mkdirSync(subDir, { recursive: true });
      writeFileSync(
        join(root, "package.json"),
        JSON.stringify({ name: "secret-parent", version: "9.9.9" }),
      );

      assert.equal(isValidPackageName("../../secret"), false);
      assert.equal(isValidPackageName("../package.json"), false);
      assert.equal(isValidPackageName("/etc/passwd"), false);
      assert.equal(getInstalledVersion(subDir, "../.."), null);
      assert.equal(
        getInstalledVersion(subDir, "legit-pkg", ["../", "../../etc"]),
        null,
      );
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });
});

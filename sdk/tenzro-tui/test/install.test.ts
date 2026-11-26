import test from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

// dist/test/install.test.js -> the package directory.
const pkgDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const sdkDir = path.resolve(pkgDir, "..", "tenzro-ts-sdk");
const npm = process.platform === "win32" ? "npm.cmd" : "npm";

/**
 * The package as a user gets it: packed to a tarball, installed into an empty
 * project, and run through the command the install puts on the path. A bin
 * entry that names a file the build does not write fails here.
 */
test("the packed package installs and its tenzro-tui command runs", { timeout: 300_000 }, () => {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "tz-tui-install-"));
  try {
    const packed = JSON.parse(
      execFileSync(npm, ["pack", "--json", "--pack-destination", tmp], { cwd: pkgDir, encoding: "utf8", shell: process.platform === "win32" }),
    ) as { filename: string; files: { path: string }[] }[];
    const tarball = path.join(tmp, packed[0]!.filename);
    const bin = (JSON.parse(fs.readFileSync(path.join(pkgDir, "package.json"), "utf8")) as { bin: Record<string, string> }).bin["tenzro-tui"]!;
    assert.ok(
      packed[0]!.files.some((f) => f.path === bin),
      `the tarball holds ${bin}, the file the command runs`,
    );

    // The SDK is a sibling directory, not a published package: point the
    // install at it, as the package's own file: dependency does.
    const app = path.join(tmp, "app");
    fs.mkdirSync(app);
    fs.writeFileSync(
      path.join(app, "package.json"),
      JSON.stringify({
        name: "install-check",
        private: true,
        dependencies: { "tenzro-tui": `file:${tarball}` },
        overrides: { "tenzro-sdk": `file:${sdkDir}` },
      }),
    );
    execFileSync(npm, ["install", "--prefer-offline", "--no-audit", "--no-fund", "--ignore-scripts"], {
      cwd: app,
      stdio: "pipe",
      shell: process.platform === "win32",
    });

    const command = path.join(app, "node_modules", ".bin", process.platform === "win32" ? "tenzro-tui.cmd" : "tenzro-tui");
    assert.ok(fs.existsSync(command), "the install put the tenzro-tui command in place");
    const run = (arg: string) => execFileSync(command, [arg], { cwd: app, encoding: "utf8", shell: process.platform === "win32" });
    assert.match(run("--version"), /^tenzro-tui \d+\.\d+\.\d+\n$/);
    assert.match(run("--help"), /Usage: tenzro-tui \[options\]/);
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
});

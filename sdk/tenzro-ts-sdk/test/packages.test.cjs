// The package split: a thin core every capability builds on, each capability
// importing only the packages it declares, and the umbrella re-exporting them.
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const PACKAGES = path.join(__dirname, "..", "packages");
const names = fs.readdirSync(PACKAGES).filter((n) => fs.existsSync(path.join(PACKAGES, n, "package.json")));
const manifest = (n) => JSON.parse(fs.readFileSync(path.join(PACKAGES, n, "package.json"), "utf8"));

function sources(dir) {
  return fs.readdirSync(dir, { withFileTypes: true }).flatMap((e) =>
    e.isDirectory() ? sources(path.join(dir, e.name)) : e.name.endsWith(".ts") ? [path.join(dir, e.name)] : [],
  );
}

test("the core depends on no capability", () => {
  assert.deepEqual(Object.keys(manifest("core").dependencies ?? {}), []);
});

test("every package imports only the packages it declares, and none imports the umbrella", () => {
  for (const n of names) {
    const declared = new Set(Object.keys(manifest(n).dependencies ?? {}));
    for (const file of sources(path.join(PACKAGES, n, "src"))) {
      const text = fs
        .readFileSync(file, "utf8")
        .split("\n")
        .filter((l) => !/^\s*(\*|\/\/)/.test(l))
        .join("\n");
      for (const [, spec] of text.matchAll(/(?:from\s+|import\(\s*|require\(\s*)["']([^"'.][^"']*)["']/g)) {
        assert.notEqual(spec, "tenzro-sdk", file);
        if (!spec.startsWith("@tenzro/") || spec === "@tenzro/device-key") continue;
        assert.ok(declared.has(spec), `${file} imports ${spec}, which @tenzro/${n} does not declare`);
      }
    }
  }
});

test("the core loads without any capability", () => {
  const core = require(path.join(PACKAGES, "core"));
  assert.equal(typeof core.RpcClient, "function");
  assert.equal(typeof core.TypedTxClient, "function");
  const loaded = Object.keys(require.cache).filter((f) => f.startsWith(PACKAGES + path.sep));
  for (const f of loaded) assert.ok(f.startsWith(path.join(PACKAGES, "core") + path.sep), `the core loaded ${f}`);
});

test("the umbrella re-exports every package", () => {
  const sdk = require("../dist/index.js");
  for (const n of names) {
    const pkg = require(path.join(PACKAGES, n));
    for (const key of Object.keys(pkg)) assert.equal(sdk[key], pkg[key], `@tenzro/${n} ${key}`);
  }
  assert.equal(typeof sdk.TenzroClient, "function");
});

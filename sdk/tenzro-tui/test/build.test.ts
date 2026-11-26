import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { digestOf, ownDir, sameDigest } from "../src/build.js";

function tree(files: Record<string, string>): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "tz-build-"));
  for (const [rel, text] of Object.entries(files)) {
    fs.mkdirSync(path.dirname(path.join(dir, rel)), { recursive: true });
    fs.writeFileSync(path.join(dir, rel), text);
  }
  return dir;
}

test("the digest is the release notice's bundle digest", () => {
  // The value the release lane's definition gives for this tree.
  assert.equal(digestOf(tree({ "app.js": "a", "cli.js": "b", "sub/x.js": "c" })), "5f4dc4c8db1c691f6092b7e622c9d778e9ed987c7cf94570ac2e8ceb0c2fefe7");
  assert.throws(() => digestOf(tree({})), /no file/);
});

test("the digest is the same for the same files and changes with any of them", () => {
  const base = { "app.js": "a", "cli.js": "b", "sub/x.js": "c" };
  const d = digestOf(tree(base));
  assert.match(d, /^[0-9a-f]{64}$/);
  assert.equal(digestOf(tree({ "sub/x.js": "c", "cli.js": "b", "app.js": "a" })), d, "order written does not matter");
  const variants: Record<string, Record<string, string>> = {
    changed: { ...base, "cli.js": "B" },
    added: { ...base, "extra.js": "" },
    removed: { "app.js": "a", "cli.js": "b" },
    renamed: { "app.js": "a", "cli.js": "b", "sub/y.js": "c" },
    moved: { "app.js": "ab", "cli.js": "", "sub/x.js": "c" },
  };
  for (const [what, other] of Object.entries(variants)) {
    assert.notEqual(digestOf(tree(other)), d, what);
  }
});

test("the running console can digest itself, and an expected digest must match exactly", () => {
  const own = digestOf(ownDir());
  assert.equal(digestOf(ownDir()), own);
  assert.ok(sameDigest(own, own));
  assert.ok(sameDigest(` ${own.toUpperCase()} `, own));
  assert.ok(!sameDigest(own.slice(0, 63) + (own.endsWith("0") ? "1" : "0"), own));
  assert.ok(!sameDigest(own.slice(0, 32), own));
  assert.ok(!sameDigest("", own));
});

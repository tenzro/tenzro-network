// Run manifests of docs/standards/run-manifest.md against the published
// vectors, and the registry put that anchors one.
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const sdk = require("../dist/index.js");

// Read exactly: one output is 2^64 - 1 bytes, past what a double holds.
const all = sdk.parseExact(
  fs.readFileSync(path.join(__dirname, "../../../docs/standards/vectors/run-manifest.json"), "utf8"),
);
const text = (manifest) => sdk.stringifyExact(manifest);

test("every published manifest has its digest and every refused one its reason", async () => {
  assert.ok(all.vectors.length >= 3);
  for (const v of all.vectors) {
    assert.equal(await sdk.runManifestDigest(text(v.manifest)), v.digest, v.label);
  }
  for (const v of all.refused) {
    await assert.rejects(
      sdk.runManifestDigest(text(v.manifest)),
      (err) => err instanceof sdk.RunManifestError && err.reason === v.reason,
      v.label,
    );
  }
  for (const reason of ["no_output", "too_large", "malformed"]) {
    assert.ok(all.refused.some((v) => v.reason === reason), reason);
  }
});

test("an output size past 2^53 is read exactly, and a rounded one refused", async () => {
  const big = all.vectors.find((v) => v.manifest.outputs[0].bytes === 2n ** 64n - 1n);
  assert.ok(big);
  assert.equal(await sdk.runManifestDigest(big.manifest), big.digest);
  // JSON.parse rounds 2^64 - 1 up to 2^64, which no output can be.
  await assert.rejects(sdk.runManifestDigest(JSON.parse(text(big.manifest))), (err) => err.reason === "malformed");
});

test("a string with a lone surrogate is refused, not written as U+FFFD", async () => {
  const raw = text(all.vectors[0].manifest).replace("run-2026-11-17-001", "run-\\ud800");
  await assert.rejects(sdk.runManifestDigest(raw), (err) => err.reason === "malformed");
});

test("a run is anchored as a version of the account's runs entry", async () => {
  const account = "ab".repeat(32);
  const worked = all.vectors[0];
  const tx = await sdk.runManifestPutTx(`0x${account.toUpperCase()}`, worked.manifest);
  assert.deepEqual(tx, {
    Registry: { op: { put: { id: `${account}/runs`, kind: "run-manifest", anchor: worked.digest, data: "" } } },
  });
  assert.throws(() => sdk.runsRegistryId("abc"), sdk.RunManifestError);
});

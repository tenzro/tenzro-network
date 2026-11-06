// The digest a machine root signs for its validator's governance ballot,
// pinned to the same vector as the chain's types and the Rust SDK.
const test = require("node:test");
const assert = require("node:assert/strict");
const sdk = require("../dist/index.js");

test("the ballot digest matches the chain's", () => {
  const digest = sdk.governanceBallotDigest(
    13380,
    new Uint8Array(32).fill(0x11),
    new Uint8Array(32).fill(0xab),
    true,
    new Uint8Array(32).fill(0x22),
    new Uint8Array(16).fill(5),
  );
  assert.equal(Buffer.from(digest).toString("hex"), "cb7ff4bed1bbc009122add80adb1a59663fa621e7234251e9017c53f8bbb0192");
});

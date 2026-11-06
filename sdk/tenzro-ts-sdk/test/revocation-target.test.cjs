// The target a root signs to revoke an identity, pinned to the same vector
// as the chain's types and the Rust and Python SDKs.
const test = require("node:test");
const assert = require("node:assert/strict");
const sdk = require("../dist/index.js");

test("the revocation target matches the chain's", () => {
  assert.equal(
    sdk.revocationTarget("did:tenzro:human:aa", "passkey lost").toString("hex"),
    "9fae58244604f04767ff22e0809efecc7f459c45eccc23b9e61499488acb170a",
  );
});

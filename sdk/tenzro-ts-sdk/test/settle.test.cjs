// The shared vectors under sdk/fixtures/split: this SDK divides a gross
// exactly as the chain does and hashes a rule to the same digest.
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const sdk = require("../dist/index.js");

const vectors = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "..", "fixtures", "split", "vectors.json"), "utf8"));

test("every split vector divides and hashes as the chain does", async () => {
  assert.ok(vectors.length > 0);
  for (const v of vectors) {
    const got = sdk.previewSplit(BigInt(v.gross), v.rule, v.params, BigInt(v.network_fees));
    assert.deepEqual(got, v.expect, v.name);
    assert.equal(await sdk.splitRuleHash(v.rule), v.rule_hash, v.name);
  }
});

test("facilitator and relayer lines are held to an agent's Terms as the chain holds them", () => {
  const addr = (b) => ({ address: b.repeat(64) });
  const rule = (lines) => ({ version: 1, lines: [{ role: "payee", recipient: addr("1"), basis: "remainder" }, ...lines] });
  const fees = rule([
    { role: "facilitator", recipient: addr("2"), basis: { bps: 100 } },
    { role: "relayer", recipient: addr("3"), basis: { bps: 50 } },
  ]);
  sdk.checkIntermediaryShare(fees, 1_000_000n, 150);
  assert.throws(() => sdk.checkIntermediaryShare(fees, 1_000_000n, 149), /more than 149 bps/);
  const fixed = rule([{ role: "facilitator", recipient: addr("2"), basis: { fixed: "200" } }]);
  sdk.checkIntermediaryShare(fixed, 10_000n, 200);
  assert.throws(() => sdk.checkIntermediaryShare(fixed, 10_000n, 199));
  const capped = rule([{ role: "facilitator", recipient: addr("2"), basis: { bps: 5000 }, cap: "10" }]);
  sdk.checkIntermediaryShare(capped, 10_000n, 10);
  sdk.checkIntermediaryShare(rule([{ role: "referrer", recipient: addr("4"), basis: { bps: 3000 } }]), 10_000n, 0);
});

test("a passkey assertion is the WebAuthn form of the P-256 leg", async () => {
  const sig = sdk.compositeSignatureJson(
    { authenticatorData: new Uint8Array([1, 2]), clientDataJson: new Uint8Array([3]), signature: new Uint8Array([4, 5]) },
    null,
  );
  assert.deepEqual(sig, { classical: { form: "web_authn", authenticator_data: "0102", client_data_json: "03", signature: "0405" } });
  assert.deepEqual(sdk.compositeSignatureJson(new Uint8Array([9]), new Uint8Array([7])), {
    classical: { form: "raw", signature: "09" },
    pq: "07",
  });
  // base64url(SHA-256("abc")), unpadded.
  assert.equal(await sdk.webauthnChallengeOf(new TextEncoder().encode("abc")), "ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0");
});

// web.HybridPayer signs the authorization message the facilitator rebuilds
// for a tenzro-hybrid requirement (vector pinned by the node's tests).
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const sdk = require("../dist/index.js");

const vector = JSON.parse(
  fs.readFileSync(path.join(__dirname, "../../fixtures/payments/x402_hybrid_authorization.json"), "utf8"),
);
const publicKey = Uint8Array.from(Buffer.from(vector.public_key, "hex"));

test("the payer derives the account the facilitator debits", async () => {
  const payer = await sdk.accountAddress(publicKey);
  assert.equal(Buffer.from(payer).toString("hex"), vector.payer_address);
});

test("the authorization message matches the node's", async () => {
  const message = await sdk.web.hybridAuthorizationMessage(
    vector.requirement,
    vector.resource.url,
    Buffer.from(vector.payer_address, "hex"),
    BigInt(vector.max_amount),
  );
  assert.equal(Buffer.from(message).toString("hex"), vector.message);
});

test("pay signs the composite representative of that message and names the key", async () => {
  const signed = [];
  const signer = {
    p256PublicKey: () => publicKey,
    signComposite: async (m) => {
      signed.push(m);
      return [new Uint8Array(64).fill(1), new Uint8Array(3309).fill(2)];
    },
  };
  const payer = new sdk.web.HybridPayer(signer, "did:tenzro:human:p");
  assert.ok(payer.supports(vector.requirement));
  assert.ok(!payer.supports({ ...vector.requirement, scheme: "batch-settlement" }));
  const credential = await payer.pay(vector.requirement, vector.resource);
  const expected = await sdk.compositeMessageRepresentative(
    sdk.web.PAYMENT_AUTHORIZATION_CONTEXT,
    Buffer.from(vector.message, "hex"),
  );
  assert.deepEqual(Buffer.from(signed[0]), Buffer.from(expected));
  assert.equal(credential.challenge_id, vector.requirement.extra.challengeId);
  assert.equal(credential.payer_address, vector.payer_address);
  assert.equal(credential.extra.public_key, vector.public_key);
  assert.equal(credential.amount, BigInt(vector.requirement.amount));
  assert.equal(credential.payer_did, "did:tenzro:human:p");
});

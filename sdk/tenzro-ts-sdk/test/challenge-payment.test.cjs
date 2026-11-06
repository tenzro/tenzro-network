// Paying a node-issued challenge: the authorization message against the
// shared vector the node verifies, the signed credential, and the request
// shape the pay endpoints parse.
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const sdk = require("../dist/index.js");

const vector = JSON.parse(
  fs.readFileSync(path.join(__dirname, "../../fixtures/payments/challenge_authorization.json"), "utf8"),
);
const publicKey = Uint8Array.from(Buffer.from(vector.public_key, "hex"));

function signer(signed) {
  return {
    p256PublicKey: () => publicKey,
    signComposite: async (m) => {
      signed.push(m);
      return [new Uint8Array(64).fill(1), null];
    },
  };
}

test("the authorization message matches the node's", async () => {
  const message = await sdk.web.challengeAuthorizationMessage(
    vector.challenge,
    Buffer.from(vector.payer_address, "hex"),
    BigInt(vector.max_amount),
  );
  assert.equal(Buffer.from(message).toString("hex"), vector.message);
});

test("a challenge without a chain id is refused", async () => {
  const { chain_id, ...extra } = vector.challenge.extra;
  await assert.rejects(() =>
    sdk.web.challengeAuthorizationMessage({ ...vector.challenge, extra }, new Uint8Array(32), 1n),
  );
});

test("a credential may pay from a named account the key acts for", async () => {
  const signed = [];
  const shared = "ab".repeat(20);
  const credential = await sdk.web.signChallengeCredential(vector.challenge, signer(signed), "", undefined, shared);
  assert.equal(credential.payer_address, shared + "00".repeat(12));
  assert.equal(credential.extra.public_key, Buffer.from(publicKey).toString("hex"));
});

test("the credential signs that message and names the key's account", async () => {
  const signed = [];
  const credential = await sdk.web.signChallengeCredential(
    vector.challenge,
    signer(signed),
    "did:tenzro:human:p",
    BigInt(vector.max_amount),
  );
  const expected = await sdk.compositeMessageRepresentative(
    sdk.web.PAYMENT_AUTHORIZATION_CONTEXT,
    Buffer.from(vector.message, "hex"),
  );
  assert.deepEqual(Buffer.from(signed[0]), Buffer.from(expected));
  assert.equal(credential.challenge_id, vector.challenge.challenge_id);
  assert.equal(credential.protocol, "mpp");
  assert.equal(credential.payer_address, vector.payer_address);
  assert.equal(credential.amount, BigInt(vector.challenge.amount));
  assert.equal(credential.extra.public_key, vector.public_key);
  assert.equal(credential.extra.upto_max, vector.max_amount);
  assert.equal(credential.signature.pq, undefined);
});

test("a ceiling below the charge is refused; an exact credential has no ceiling", async () => {
  await assert.rejects(sdk.web.signChallengeCredential(vector.challenge, signer([]), "", 999n));
  const exact = await sdk.web.signChallengeCredential(vector.challenge, signer([]), "");
  assert.equal(exact.extra.upto_max, undefined);
});

test("amounts above 2^53 stay exact on the wire", () => {
  const wire = sdk.web.stringifyExact({ credential: { amount: 2n ** 100n } });
  assert.equal(wire, `{"credential":{"amount":${(2n ** 100n).toString()}}}`);
});

test("createChallenge sends the object the node reads", async () => {
  const calls = [];
  const rpc = new sdk.RpcClient("http://unused", undefined, 30000, {
    call: async (method, params) => (calls.push([method, params]), {}),
  });
  await new sdk.PaymentClient(rpc).createChallenge("/r", 2n ** 100n, "TNZO", "x402", "0909");
  assert.equal(calls[0][0], "tenzro_createPaymentChallenge");
  assert.deepEqual(calls[0][1], {
    resource: "/r",
    amount: (2n ** 100n).toString(),
    asset: "TNZO",
    protocol: "x402",
    recipient: "0909",
  });
});

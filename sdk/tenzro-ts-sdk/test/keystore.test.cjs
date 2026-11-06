// The keystore change digest every SDK computes, from the shared vector.
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const sdk = require("../dist");

const vector = JSON.parse(
  fs.readFileSync(path.join(__dirname, "../../fixtures/keystore/digest.json"), "utf8"),
);

test("the keystore digest matches the network's for every change", async () => {
  assert.equal(vector.cases.length, 11);
  for (const c of vector.cases) {
    const digest = await sdk.keystoreDigest(vector.chain_id, vector.account, vector.previous_commitment, c.op);
    assert.equal(Buffer.from(digest).toString("hex"), c.digest, JSON.stringify(c.op));
  }
});

test("the keystore digest names the chain the change is for", async () => {
  const op = vector.cases[2].op;
  const here = await sdk.keystoreDigest(vector.chain_id, vector.account, vector.previous_commitment, op);
  const there = await sdk.keystoreDigest(vector.chain_id + 1, vector.account, vector.previous_commitment, op);
  assert.notDeepEqual(Buffer.from(here), Buffer.from(there));
  await assert.rejects(() => sdk.keystoreDigest(-1, vector.account, vector.previous_commitment, op));
});

test("a change is sent as the network encodes it", () => {
  const enc = JSON.parse(fs.readFileSync(path.join(__dirname, "../../fixtures/keystore/encoding.json"), "utf8"));
  for (const c of enc.cases) {
    assert.deepEqual(sdk.txType({ kind: "KeystoreUpdate", fields: { update: c.update } }), {
      KeystoreUpdate: { update: c.encoded },
    });
  }
});

test("a change is approved by a passkey over that digest", async () => {
  const signed = [];
  const signer = {
    p256PublicKey: () => new Uint8Array(64).fill(9),
    signComposite: async (m) => {
      signed.push(m);
      return [new Uint8Array(64).fill(1), null];
    },
  };
  const client = new sdk.KeystoreClient(new sdk.RpcClient("http://node.invalid"));
  const update = {
    chain_id: vector.chain_id,
    account: vector.account,
    anchor: null,
    previous_commitment: vector.previous_commitment,
    op: vector.cases[2].op,
    approvals: [],
    possession: null,
  };
  const approved = await client.approve(update, signer);
  assert.equal(approved.approvals.length, 1);
  assert.equal(approved.approvals[0].public_key, "09".repeat(64));
  const digest = Buffer.from(vector.cases[2].digest, "hex");
  const expected = await sdk.compositeMessageRepresentative(sdk.ACCOUNT_OWNER_SIGNATURE_CONTEXT, digest);
  assert.deepEqual(Buffer.from(signed[0]), Buffer.from(expected));
});

test("the recovery code helpers agree with the network's", async () => {
  const code = "77".repeat(32);
  const credential = vector.cases[10].op.recover_with_code.credential;
  assert.equal(
    await sdk.recoveryCodeCommitment(vector.chain_id, vector.account, code),
    vector.cases[8].op.set_recovery_code.commitment,
  );
  assert.equal(
    await sdk.recoveryCodeClaim(vector.chain_id, vector.account, code, credential),
    vector.cases[9].op.claim_recovery_code.claim,
  );
  const fresh = sdk.generateRecoveryCode();
  assert.match(fresh, /^[0-9a-f]{64}$/);
  assert.notEqual(fresh, sdk.generateRecoveryCode());
});

test("a registration's model and sync flags, and a key in the keystore's form", () => {
  const authData = new Uint8Array(37 + 16 + 2);
  authData[32] = 0x40 | 0x08 | 0x10;
  authData.set(new Uint8Array(16).fill(0xab), 37);
  assert.deepEqual(sdk.registrationFacts(authData), {
    aaguid: "ab".repeat(16),
    backupEligible: true,
    backupState: true,
  });
  const sec1 = new Uint8Array(65);
  sec1[0] = 4;
  sec1.fill(7, 1);
  assert.equal(sdk.rawP256(sec1), "07".repeat(64));
  assert.throws(() => sdk.rawP256(new Uint8Array(10)));
});

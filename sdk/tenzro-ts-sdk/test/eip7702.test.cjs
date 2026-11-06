// The EIP-7702 reference vector under sdk/fixtures/eip7702 was signed by an
// independent wallet library; the builders reproduce its digests and bytes.
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const sdk = require("../dist/index.js");

const v = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "..", "fixtures", "eip7702", "vectors.json"), "utf8"));
const a = v.authorization;
const t = v.transaction;

const tx = {
  chainId: t.chain_id,
  nonce: t.nonce,
  maxPriorityFeePerGas: BigInt(t.max_priority_fee_per_gas),
  maxFeePerGas: BigInt(t.max_fee_per_gas),
  gasLimit: t.gas_limit,
  to: t.to,
  value: BigInt(t.value),
  data: t.data,
  accessList: t.access_list.map((i) => ({ address: i.address, storageKeys: i.storage_keys })),
  authorizationList: [
    { chainId: a.chain_id, address: a.address, nonce: a.nonce, signature: { yParity: a.y_parity, r: a.r, s: a.s } },
  ],
};

test("the authorization digest matches the wallet's", () => {
  assert.equal(sdk.authorizationSigningHash({ chainId: a.chain_id, address: a.address, nonce: a.nonce }), a.signing_hash);
});

test("the transaction digest, raw bytes and hash match the wallet's", () => {
  assert.equal(sdk.setCodeTransactionSigningHash(tx), t.signing_hash);
  const raw = sdk.encodeSignedSetCodeTransaction(tx, { yParity: t.y_parity, r: t.r, s: t.s });
  assert.equal(raw, t.raw);
  assert.equal(sdk.rawTransactionHash(raw), t.hash);
});

test("a transaction without authorizations is refused", () => {
  assert.throws(() => sdk.setCodeTransactionSigningHash({ ...tx, authorizationList: [] }));
});

test("the designator is the magic and the address", () => {
  assert.equal(sdk.delegationDesignator(a.address), "0xef0100" + a.address.slice(2));
});

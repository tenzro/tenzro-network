// The shared vectors under sdk/fixtures/remote_grant: every account this SDK
// derives is the one Tenzro derives, and the digests match.
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const sdk = require("../dist/index.js");

const v = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "..", "fixtures", "remote_grant", "vectors.json"), "utf8"));
const hex = (b) => Buffer.from(b).toString("hex");

test("keccak-256 and blake2b-256 match their reference vectors", () => {
  assert.equal(hex(sdk.keccak256(new Uint8Array(0))), "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");
  assert.equal(hex(sdk.blake2b256(new TextEncoder().encode("abc"))), "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319");
});

test("every account and digest matches the vectors", () => {
  for (const c of v.chains) {
    const a = sdk.omniAccount(v.did).address(c.chain, c.deployment);
    assert.equal(a.address, c.account, c.chain);
    assert.equal(hex(a.raw), c.account_raw, c.chain);
    assert.equal(sdk.toCaip10(a), c.caip10, c.chain);
    const erc = sdk.toErc7930(a);
    assert.equal(erc ? hex(erc) : null, c.erc7930, c.chain);
    assert.equal(hex(sdk.omniSalt(v.did)), c.salt);
    assert.equal(hex(sdk.grantTreeKey(v.did, c.chain)), c.tree_key);
    const action = sdk.encodeAction(c.action);
    assert.equal(hex(action), c.action.encoded);
    assert.equal(hex(sdk.actDigest(c.chain, Buffer.from(c.account_word, "hex"), 1, 0, action)), c.action_digest);
  }
});

test("a deployment of another family is refused", () => {
  assert.throws(() => sdk.omniAddress("did:x", "eip155:1", { family: "solana", program_id: Array(32).fill(7) }));
});

test("the settle transaction carries the delivery", () => {
  const tx = sdk.AgentAccountsClient.relay("did:x", "eip155:1", Uint8Array.of(1, 2));
  assert.deepEqual(tx, { RemoteGrantSettle: { agent_did: "did:x", chain: "eip155:1", delivery: "0102" } });
});

test("a channel voucher digest and pay data match the account layout", () => {
  const account = new Uint8Array(32);
  account.fill(0x11, 12);
  assert.equal(hex(sdk.channelVoucherDigest("eip155:8453", account, 7, 1000n)), "046c669c72b5951a78639fc0849f070e8a5c2a8d0ddc0760d631aac95a2523d9");
  const d = sdk.payData(new Uint8Array(32).fill(1), new Uint8Array(32).fill(2), new Uint8Array(32).fill(3), 30);
  assert.equal(d.length, 104);
  assert.equal(hex(d.slice(96)), "000000000000001e");
  assert.throws(() => sdk.payData(new Uint8Array(31), new Uint8Array(32), new Uint8Array(32), 1));
});

test("the proven payment transaction carries the account's report", () => {
  assert.deepEqual(sdk.AgentAccountsClient.prove("did:x", "eip155:1", Uint8Array.of(1, 2)), {
    Payment: { op: { proven: { agent_did: "did:x", chain: "eip155:1", delivery: "0102" } } },
  });
});

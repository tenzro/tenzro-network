// A transaction is signed only with the nonce and chain id the node reports:
// a failed or malformed read is an error, never a default.
const test = require("node:test");
const assert = require("node:assert/strict");
const sdk = require("../dist");

const ENDPOINT = "http://node.test";

/**
 * A node answering each method from `answers`: a value, or an Error thrown.
 * The recipient check asks for the account's history before anything is
 * signed; unless a test gives one, the account has paid `TO` before.
 */
function node(answers) {
  const sent = [];
  return {
    sent,
    getEndpoint: () => ENDPOINT,
    call: async (method, params) => {
      sent.push({ method, params });
      if (method === "tenzro_getTransactionHistory" && !(method in answers)) {
        return { transactions: [{ from: params.address, to: TO }] };
      }
      const a = answers[method];
      if (a instanceof Error) throw a;
      return a;
    },
  };
}

function signer() {
  const s = {
    signed: 0,
    p256PublicKey: () => new Uint8Array(64).fill(7),
    mlDsaPublicKey: () => null,
    signComposite: async () => {
      s.signed += 1;
      return [new Uint8Array(64).fill(9), null];
    },
  };
  return s;
}

const TO = "0x" + "03".repeat(32);

test("self custody signs with the nonce and chain id the node reports", async () => {
  const rpc = node({ tenzro_getNonce: "0x5", eth_chainId: "0x3444", tenzro_sendRawTransaction: "0xabc" });
  const s = signer();
  const out = await new sdk.WalletClient(rpc).sendSelfCustody({ signer: s, to: TO, value: 5n });
  assert.equal(out, "0xabc");
  assert.equal(s.signed, 1);
  const sent = rpc.sent.find((r) => r.method === "tenzro_sendRawTransaction").params;
  assert.equal(sent.nonce, 5);
  assert.equal(sent.chain_id, 13380);
});

test("self custody uses a nonce and chain id the caller passes", async () => {
  const rpc = node({ tenzro_sendRawTransaction: "0xabc" });
  const s = signer();
  await new sdk.WalletClient(rpc).sendSelfCustody({ signer: s, to: TO, value: 5n, nonce: 2, chainId: 13380 });
  const RECIPIENT_CHECK = ["tenzro_getNetworkParams", "tenzro_getTransactionHistory"];
  assert.deepEqual(
    rpc.sent.map((r) => r.method).filter((m) => !RECIPIENT_CHECK.includes(m)),
    ["tenzro_sendRawTransaction"],
  );
  const sent = rpc.sent.find((r) => r.method === "tenzro_sendRawTransaction").params;
  assert.equal(sent.nonce, 2);
  assert.equal(sent.chain_id, 13380);
});

for (const [name, answers, what] of [
  ["the chain id read fails", { tenzro_getNonce: "0x5", eth_chainId: new Error("unavailable") }, "chain id"],
  ["the nonce read fails", { tenzro_getNonce: new Error("unavailable"), eth_chainId: "0x3444" }, "nonce"],
  ["the chain id is malformed", { tenzro_getNonce: "0x5", eth_chainId: "0xzz" }, "chain id"],
  ["the nonce is malformed", { tenzro_getNonce: "12zz", eth_chainId: "0x3444" }, "nonce"],
  ["the chain id is missing", { tenzro_getNonce: "0x5", eth_chainId: null }, "chain id"],
]) {
  test(`self custody does not sign when ${name}`, async () => {
    const rpc = node({ ...answers, tenzro_sendRawTransaction: "0xabc" });
    const s = signer();
    await assert.rejects(
      () => new sdk.WalletClient(rpc).sendSelfCustody({ signer: s, to: TO, value: 5n }),
      (e) => e.message.startsWith(`could not read the ${what} from ${ENDPOINT}: `),
    );
    assert.equal(s.signed, 0);
    assert.ok(!rpc.sent.some((r) => r.method === "tenzro_sendRawTransaction"));
  });

  test(`a typed transaction is not signed when ${name}`, async () => {
    const rpc = node({ ...answers, eth_gasPrice: "0x3b9aca00" });
    const s = signer();
    await assert.rejects(
      () => new sdk.TypedTxClient(rpc).send(s, { kind: "Transfer", fields: { amount: 1 } }),
      (e) => e.message.startsWith(`could not read the ${what} from ${ENDPOINT}: `),
    );
    assert.equal(s.signed, 0);
    assert.ok(!rpc.sent.some((r) => r.method === "tenzro_getSigningPayload"));
  });
}

test("a keystore change does not name a chain the node did not report", async () => {
  const rpc = node({
    tenzro_getKeystore: { account: "0x01", keystore: {}, commitment: "0x02", on_chain: true },
    eth_chainId: new Error("unavailable"),
  });
  await assert.rejects(
    () => new sdk.KeystoreClient(rpc).prepare("0x01", { Freeze: {} }),
    /could not read the chain id from http:\/\/node\.test: unavailable/,
  );
});

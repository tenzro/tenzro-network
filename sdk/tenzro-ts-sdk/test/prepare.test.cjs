// A typed transaction dry run: the node encodes the signing payload, the SDK
// checks it, and nothing is signed or submitted.
const test = require("node:test");
const assert = require("node:assert/strict");
const { createHash } = require("node:crypto");
const sdk = require("../dist");

const SENDER = "0x" + "11".repeat(32);
const TO = "0x" + "22".repeat(32);

function node(skewNonce = 0) {
  const sent = [];
  return {
    sent,
    getEndpoint: () => "http://node.test",
    call: async (method, params) => {
      sent.push(method);
      if (method === "tenzro_getNonce") return "0x7";
      if (method === "eth_chainId") return "0x539";
      if (method === "eth_gasPrice") return "0x1";
      if (method === "tenzro_getSigningPayload") {
        const preimage = JSON.stringify({
          chain_id: params.chain_id,
          from: params.from.slice(2),
          to: params.to.slice(2),
          nonce: params.nonce + skewNonce,
          gas_limit: params.gas_limit,
          gas_price: params.gas_price,
          timestamp: params.timestamp,
          valid_until: params.valid_until,
          action: params.tx_type,
        });
        return { kind: "typed_action", preimage, digest: createHash("sha256").update(preimage).digest("hex") };
      }
      throw new Error(`unexpected ${method}`);
    },
  };
}

test("prepare checks the node's encoding and sends nothing", async () => {
  const rpc = node();
  const out = await new sdk.TypedTxClient(rpc).prepare(SENDER, { kind: "Transfer", fields: { amount: 5 }, to: TO });
  assert.equal(out.request.from, SENDER);
  assert.equal(out.request.nonce, 7);
  assert.equal(out.request.chain_id, 1337);
  assert.equal(out.request.signature, undefined);
  assert.match(out.digest, /^[0-9a-f]{64}$/);
  assert.deepEqual(rpc.sent, ["tenzro_getNonce", "eth_chainId", "eth_gasPrice", "tenzro_getSigningPayload"]);
});

test("prepare refuses a payload that is not the transaction", async () => {
  const rpc = node(1);
  await assert.rejects(
    new sdk.TypedTxClient(rpc).prepare(SENDER, { kind: "Transfer", fields: { amount: 5 }, to: TO }),
    /nonce/,
  );
  assert.ok(!rpc.sent.includes("tenzro_sendRawTransaction"));
});

// Bridge-send and payee payment operations: the SDK builds the operations
// in sdk/fixtures/payment-ops/vectors.json, which the network decodes.
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const sdk = require("../dist/index.js");

const vectors = JSON.parse(
  fs.readFileSync(path.join(__dirname, "../../fixtures/payment-ops/vectors.json"), "utf8"),
);

test("outboundFields matches the shared vectors", () => {
  for (const v of vectors.bridge_outbound) {
    const a = v.args;
    assert.deepEqual(
      sdk.outboundFields(a.target_chain, a.recipient, BigInt(a.amount), a.asset ?? undefined),
      v.fields,
    );
  }
  assert.throws(() => sdk.outboundFields("base", "zz", 1n));
  assert.throws(() => sdk.outboundFields("base", "01", 0n));
});

test("refundOp matches the shared vectors", () => {
  for (const v of vectors.payment_refund) {
    assert.deepEqual(sdk.refundOp(v.args.pay_ref, BigInt(v.args.amount)), v.op);
  }
  assert.throws(() => sdk.refundOp("abcd", 1n));
  assert.throws(() => sdk.refundOp("ab".repeat(32), 0n));
});

test("send, refund and split submit signed Bridge and Payment transactions", async () => {
  const sent = [];
  const rpc = {
    call: async (method, params) => {
      sent.push({ method, params });
      if (method === "tenzro_getNonce") return "0x0";
      if (method === "eth_chainId") return "0x539";
      if (method === "eth_gasPrice") return "0x3b9aca00";
      if (method === "tenzro_getSigningPayload") throw new Error("stop before signing");
      return null;
    },
  };
  const signer = { p256PublicKey: () => new Uint8Array(64).fill(7), signComposite: async () => { throw new Error("unreachable"); } };
  await assert.rejects(new sdk.BridgeClient(rpc).send(signer, "base", "0xabcd", 5n, "usdc"), /stop before signing/);
  await assert.rejects(new sdk.SettlementClient(rpc).refundPayment(signer, "ab".repeat(32), 5n), /stop before signing/);
  await assert.rejects(new sdk.SettlementClient(rpc).setPayeeSplit(signer, null), /stop before signing/);
  const types = sent.filter((c) => c.method === "tenzro_getSigningPayload").map((c) => c.params.tx_type);
  assert.deepEqual(types, [
    { Bridge: { op: { outbound: { target_chain: "base", recipient: "abcd", amount: "5", asset: "USDC" } } } },
    { Payment: { op: { refund: { pay_ref: "ab".repeat(32), amount: "5" } } } },
    { Payment: { op: { set_split: { rule: null } } } },
  ]);
});

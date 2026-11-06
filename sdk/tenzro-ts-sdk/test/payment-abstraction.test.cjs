// Ledger payments in any permitted asset: the shared vectors in
// sdk/fixtures/payments/payment_abstraction.json, pinned by tenzro-types.
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const sdk = require("../dist/index.js");

const v = JSON.parse(fs.readFileSync(path.join(__dirname, "../../fixtures/payments/payment_abstraction.json"), "utf8"));
const b = (h) => Uint8Array.from(Buffer.from(h, "hex"));

test("prices parse to micro-units exactly", () => {
  for (const [s, e6] of v.prices) assert.equal(sdk.parsePriceE6(s), BigInt(e6));
  for (const s of v.bad_prices) assert.throws(() => sdk.parsePriceE6(s), (e) => e.code === "invalid_price");
});

test("the payment id derives from the idempotency key", async () => {
  const p = v.payment_id;
  assert.equal(await sdk.paymentId(p.idempotency_key, b(p.payer), b(p.payee), b(p.request_digest)), p.payment_id);
  assert.equal(Buffer.from(await sdk.requestDigest("https://api.example/v1/infer")).toString("hex"), p.request_digest);
});

test("the authorization preimage is the chain's", () => {
  const a = v.authorization;
  const m = sdk.ledgerAuthorizationMessage({
    chainId: BigInt(a.chain_id),
    paymentId: a.payment_id,
    payer: b(a.payer),
    payee: b(a.payee),
    maxAmount: BigInt(a.max_amount),
    asset: a.asset,
    requestDigest: b(a.request_digest),
    quoteDigest: b(a.quote_digest),
    usdE6: BigInt(a.usd_e6),
  });
  assert.equal(Buffer.from(m).toString("hex"), a.preimage);
});

test("the first accepted asset that can settle is chosen; none refuses with its code", () => {
  const assets = sdk.readQuoteAssets(v.quote.response);
  assert.equal(sdk.chooseAsset(assets, v.quote.accept).asset, v.quote.chosen);
  assert.throws(() => sdk.chooseAsset(assets, v.quote.accept_none), (e) => e.code === v.quote.none_code);
});

test("a suspended asset is passed over for the next accepted asset; alone it refuses with its code", () => {
  const q = v.quote_suspended;
  const assets = sdk.readQuoteAssets(q.response);
  assert.equal(sdk.chooseAsset(assets, q.accept).asset, q.chosen);
  assert.throws(() => sdk.chooseAsset(assets, q.accept_none), (e) => e.code === "asset_suspended");
});

test("an asset with a full inflow cap is passed over for the next accepted asset; alone it refuses with its code", () => {
  const q = v.quote_inflow_full;
  const assets = sdk.readQuoteAssets(q.response);
  assert.equal(sdk.chooseAsset(assets, q.accept).asset, q.chosen);
  assert.throws(() => sdk.chooseAsset(assets, q.accept_none), (e) => e.code === "asset_inflow_full");
});

test("a receipt checks against two identical records with every field", async () => {
  const e = v.receipt.expected;
  const expected = { paymentId: e.payment_id, payee: e.payee, asset: e.asset, amount: BigInt(e.amount), request: e.request };
  const r = await sdk.checkReceipt(expected, v.receipt.record, structuredClone(v.receipt.record));
  // A receipt for one request never verifies for another.
  await assert.rejects(
    async () => sdk.checkReceipt({ ...expected, request: v.receipt.other_request }, v.receipt.record, v.receipt.record),
    (x) => x.code === "receipt_mismatch" && /request/.test(x.message),
  );
  assert.equal(r.record.fee_asset, e.asset);
  await assert.rejects(async () => sdk.checkReceipt(expected, null, v.receipt.record), (x) => x.code === "receipt_missing");
  await assert.rejects(
    async () => sdk.checkReceipt(expected, v.receipt.record, { ...v.receipt.record, amount: "1" }),
    (x) => x.code === "receipt_mismatch",
  );
  const noUnit = { ...v.receipt.record, value_units: "" };
  await assert.rejects(async () => sdk.checkReceipt(expected, noUnit, noUnit), (x) => x.code === "receipt_mismatch");
});

function fakeNode(record) {
  const calls = [];
  let stored = record;
  const node = {
    calls,
    settle: (r) => (stored = r),
    call: async (method, params) => {
      calls.push([method, params]);
      if (method === "tenzro_quotePayment") return node.quote ?? v.quote.response;
      if (method === "tenzro_getPayment") return stored;
      if (method === "eth_chainId") return "0x539";
      if (method === "tenzro_settle") {
        stored = v.receipt.record;
        return { status: "settled" };
      }
      throw new Error(method);
    },
  };
  return node;
}

const signer = {
  p256PublicKey: () => new Uint8Array(64).fill(3),
  signComposite: async () => [new Uint8Array(64).fill(1), undefined],
};

test("pay signs the chosen asset and amount, relays it, and returns the record", async () => {
  const node = fakeNode(null);
  const pay = new sdk.LedgerPayments([node, node]);
  const q = await pay.quote({
    payee: v.payment_id.payee,
    price: { amount: "1", unit: "USD" },
    request: "https://api.example/v1/infer",
    accept: v.quote.accept,
  });
  assert.equal(q.chosen.asset, v.quote.chosen);
  assert.deepEqual(node.calls[0], ["tenzro_quotePayment", { usd_e6: 1000000, accept: v.quote.accept }]);
  const r = await pay.pay(q, { signer, idempotencyKey: "order-7f3a", account: v.payment_id.payer, backoffMs: 1 });
  const settle = node.calls.find(([m]) => m === "tenzro_settle")[1];
  assert.equal(settle.amount, v.authorization.max_amount);
  assert.equal(settle.payment.payment_id, v.payment_id.payment_id);
  assert.equal(settle.payment.authorization.asset, v.quote.chosen);
  assert.equal(settle.payment.authorization.binding.usd_e6, 1000000);
  assert.equal(r.paymentId, v.payment_id.payment_id);
  await pay.verifyReceipt(r);
});

test("a retry with the same idempotency key finds the payment and never pays twice", async () => {
  const node = fakeNode(v.receipt.record);
  const pay = new sdk.LedgerPayments([node, node]);
  const q = await pay.quote({ payee: v.payment_id.payee, price: { amount: "1", unit: "USD" }, request: "https://api.example/v1/infer", accept: v.quote.accept });
  await pay.pay(q, { signer, idempotencyKey: "order-7f3a", account: v.payment_id.payer });
  assert.equal(node.calls.filter(([m]) => m === "tenzro_settle").length, 0);
});

test("charge serves only a paid request and answers 402 otherwise", async () => {
  const node = fakeNode(v.receipt.record);
  const pay = new sdk.LedgerPayments([node, node]);
  const served = pay.charge(async () => "ok", { payee: v.payment_id.payee, price: { amount: "1", unit: "USD" }, accept: v.quote.accept });
  assert.equal((await served({ request: "https://api.example/v1/infer" })).status, 402);
  assert.equal((await served({ request: "https://other.example", paymentId: v.payment_id.payment_id })).status, 402);
  assert.equal(await served({ request: "https://api.example/v1/infer", paymentId: v.payment_id.payment_id }), "ok");
  // The same payment presented again unlocks nothing.
  const again = await served({ request: "https://api.example/v1/infer", paymentId: v.payment_id.payment_id });
  assert.equal(again.status, 402);
  assert.equal(again.reason, "payment_consumed");
  const dear = new sdk.LedgerPayments([node, node]).charge(async () => "ok", { payee: v.payment_id.payee, price: { amount: "2", unit: "USD" }, accept: v.quote.accept });
  assert.equal((await dear({ request: "https://api.example/v1/infer", paymentId: v.payment_id.payment_id })).status, 402);
});

test("a resold payment signs each commission and its receipt shows every leg", async () => {
  const a = v.authorization_resold;
  const m = sdk.ledgerAuthorizationMessage({
    chainId: BigInt(a.chain_id),
    paymentId: a.payment_id,
    payer: b(a.payer),
    payee: b(a.payee),
    maxAmount: BigInt(a.max_amount),
    asset: a.asset,
    requestDigest: b(a.request_digest),
    quoteDigest: b(a.quote_digest),
    usdE6: BigInt(a.usd_e6),
    resellers: a.resellers.map((r) => ({ reseller: r.reseller, commission_bps: r.commission_bps })),
  });
  assert.equal(Buffer.from(m).toString("hex"), a.preimage);
  // The quote discloses the operator price and the commission.
  const [q] = sdk.readQuoteAssets(v.quote_resold.response);
  assert.equal(q.operator_amount, BigInt(v.quote_resold.operator_amount));
  assert.equal(q.legs[0].amount, BigInt(v.quote_resold.commission));
  // The receipt verifies with its legs, and not without the commission.
  const e = v.receipt_resold.expected;
  const expected = { paymentId: e.payment_id, payee: e.payee, asset: e.asset, amount: BigInt(e.amount), request: e.request, resellers: e.resellers };
  const r = await sdk.checkReceipt(expected, v.receipt_resold.record, v.receipt_resold.record);
  assert.equal(r.record.legs.length, 2);
  const undisclosed = { ...v.receipt_resold.record, legs: [v.receipt_resold.record.legs[0]] };
  await assert.rejects(async () => sdk.checkReceipt(expected, undisclosed, undisclosed), (x) => x.code === "receipt_mismatch");
  const noLegs = { ...v.receipt.record, legs: [] };
  const direct = v.receipt.expected;
  await assert.rejects(
    async () => sdk.checkReceipt({ paymentId: direct.payment_id, payee: direct.payee, asset: direct.asset, amount: BigInt(direct.amount), request: direct.request }, noLegs, noLegs),
    (x) => x.code === "receipt_mismatch",
  );
});

test("pay signs the quoted commission", async () => {
  const node = fakeNode(null);
  node.quote = v.quote_resold.response;
  const pay = new sdk.LedgerPayments([node, node]);
  const q = await pay.quote({
    payee: v.payment_id.payee,
    price: { amount: "1", unit: "USD" },
    request: "https://api.example/v1/infer",
    accept: v.quote_resold.accept,
    resellers: v.quote_resold.resellers,
  });
  const asked = node.calls.find(([m]) => m === "tenzro_quotePayment")[1];
  assert.deepEqual(asked.resellers, [{ reseller: Array.from(Buffer.from("33".repeat(32), "hex")), commission_bps: 1000 }]);
  await pay.pay(q, { signer, idempotencyKey: "order-7f3a", account: v.payment_id.payer, backoffMs: 1 });
  const settle = node.calls.find(([m]) => m === "tenzro_settle")[1];
  assert.equal(settle.amount, "1101103");
  assert.deepEqual(settle.payment.authorization.resellers, asked.resellers);
});

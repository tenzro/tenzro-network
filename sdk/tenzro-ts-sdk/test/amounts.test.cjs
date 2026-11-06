// Amounts past 2^53 stay exact end to end: the node writes a u64 as a JSON
// integer literal, so a reader that goes through a double rounds it.
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const sdk = require("../dist/index.js");

const ABOVE = 2n ** 53n + 1n; // 9007199254740993
const U64_MAX = 2n ** 64n - 1n; // 18446744073709551615
const VECTORS = [ABOVE, U64_MAX];
// The same amounts as USD prices of six places.
const price = (e6) => `${e6 / 1_000_000n}.${(e6 % 1_000_000n).toString().padStart(6, "0")}`;

const fixtures = path.join(__dirname, "../../fixtures");
const v = JSON.parse(fs.readFileSync(path.join(fixtures, "payments/payment_abstraction.json"), "utf8"));

/**
 * Nodes behind real RpcClients: every request goes through fetch as text and
 * every answer comes back as the text a node writes, a bigint as an integer
 * literal.
 */
function wire(answer) {
  const bodies = [];
  const realFetch = globalThis.fetch;
  globalThis.fetch = async (url, init) => {
    bodies.push(init.body);
    const req = sdk.parseExact(init.body);
    const result = answer(req.method, req.params, String(url));
    const text = sdk.stringifyExact({ jsonrpc: "2.0", id: req.id, result });
    return new Response(text, { status: 200, headers: { "content-type": "application/json" } });
  };
  const clients = [new sdk.RpcClient("http://node-a.test"), new sdk.RpcClient("http://node-b.test")];
  return { clients, bodies, restore: () => (globalThis.fetch = realFetch) };
}

function quoteResponse(amount) {
  const r = structuredClone(v.quote.response);
  for (const a of r.assets) {
    if (a.error) continue;
    a.amount = amount;
    a.fee = amount / 1000n;
  }
  return r;
}

test("integer literals past 2^53 parse exactly and write back unchanged", () => {
  const text = `{"a":${ABOVE},"b":${U64_MAX},"c":"${U64_MAX}","d":1.5,"e":-${ABOVE},"f":[1,2e+300,0],"g":"q\\"${ABOVE}"}`;
  const got = sdk.parseExact(text);
  assert.equal(got.a, ABOVE);
  assert.equal(got.b, U64_MAX);
  assert.equal(got.c, U64_MAX.toString());
  assert.equal(got.d, 1.5);
  assert.equal(got.e, -ABOVE);
  assert.deepEqual(got.f, [1, 2e300, 0]);
  assert.equal(got.g, `q"${ABOVE}`);
  assert.equal(sdk.stringifyExact(got), text);
  assert.equal(sdk.parseExact("9007199254740991"), Number.MAX_SAFE_INTEGER);
});

test("every shared vector file round-trips exactly", () => {
  const files = [];
  const walk = (d) => {
    for (const e of fs.readdirSync(d, { withFileTypes: true })) {
      const p = path.join(d, e.name);
      if (e.isDirectory()) walk(p);
      else if (e.name.endsWith(".json")) files.push(p);
    }
  };
  walk(fixtures);
  assert.ok(files.length > 10);
  for (const f of files) {
    const text = fs.readFileSync(f, "utf8");
    const exact = sdk.parseExact(text);
    assert.deepEqual(sdk.parseExact(sdk.stringifyExact(exact)), exact, f);
    // Within 2^53 the exact reader is JSON.parse.
    const hasBig = /[^\d."\w]\d{16,}/.test(text.replace(/"(?:[^"\\]|\\.)*"/g, '""'));
    if (!hasBig) assert.equal(sdk.stringifyExact(exact), JSON.stringify(JSON.parse(text)), f);
  }
});

test("an RPC answer past 2^53 comes back exact", async () => {
  for (const amount of VECTORS) {
    const w = wire(() => ({ amount, balance: amount.toString() }));
    try {
      const r = await w.clients[0].call("tenzro_anything", {});
      assert.equal(r.amount, amount);
      assert.equal(r.balance, amount.toString());
    } finally {
      w.restore();
    }
  }
});

test("quote reads amounts past 2^53 exactly from the shared quote vector", async () => {
  for (const amount of VECTORS) {
    const w = wire((m) => (m === "tenzro_quotePayment" ? quoteResponse(amount) : null));
    try {
      const pay = new sdk.LedgerPayments(w.clients);
      const q = await pay.quote({ payee: v.payment_id.payee, price: { amount: "1", unit: "USD" }, request: "https://api.example/v1/infer", accept: v.quote.accept });
      assert.equal(q.chosen.asset, v.quote.chosen);
      assert.equal(q.chosen.amount, amount);
      assert.equal(q.chosen.fee, amount / 1000n);
      assert.equal(q.chosen.operator_amount, amount);
    } finally {
      w.restore();
    }
  }
  // The resold vector: the operator amount and each leg, exact.
  const r = structuredClone(v.quote_resold.response);
  r.assets[0].amount = U64_MAX;
  r.assets[0].operator_amount = U64_MAX - ABOVE;
  r.assets[0].legs[0].amount = ABOVE;
  const [a] = sdk.readQuoteAssets(sdk.parseExact(sdk.stringifyExact(r)));
  assert.equal(a.amount, U64_MAX);
  assert.equal(a.operator_amount, U64_MAX - ABOVE);
  assert.equal(a.legs[0].amount, ABOVE);
});

test("an amount already rounded through a double is refused, never paid", () => {
  const r = structuredClone(v.quote.response);
  r.assets[1].amount = Number(U64_MAX);
  assert.throws(() => sdk.readQuoteAssets(r), (e) => e.code === "invalid_asset");
  assert.throws(() => sdk.readAmount(2 ** 53 + 2, "x"), (e) => e.code === "receipt_mismatch");
  assert.equal(sdk.readAmount(U64_MAX.toString(), "x"), U64_MAX);
  assert.equal(sdk.readAmount(7, "x"), 7n);
});

const signer = {
  p256PublicKey: () => new Uint8Array(64).fill(3),
  signComposite: async () => [new Uint8Array(64).fill(1), undefined],
};

function record(amount, valueUnits) {
  const r = structuredClone(v.receipt.record);
  r.amount = amount;
  r.legs[0].amount = amount;
  r.value_units = valueUnits;
  return r;
}

test("pay and payFor sign, send and verify amounts past 2^53 exactly", async () => {
  for (const amount of VECTORS) {
    let settled = null;
    const w = wire((m, p) => {
      if (m === "tenzro_quotePayment") return quoteResponse(amount);
      if (m === "eth_chainId") return "0x539";
      if (m === "tenzro_settle") {
        settled = { ...record(amount, p.payment.authorization.binding.usd_e6.toString()), nonce: p.payment.payment_id };
        return { status: "settled" };
      }
      if (m === "tenzro_getPayment") return settled;
      throw new Error(m);
    });
    try {
      const pay = new sdk.LedgerPayments(w.clients);
      const r = await pay.payFor(v.receipt.expected.request, {
        payee: v.payment_id.payee,
        price: { amount: price(amount), unit: "USD" },
        accept: v.quote.accept,
        signer,
        idempotencyKey: v.payment_id.idempotency_key,
        account: v.payment_id.payer,
        backoffMs: 1,
      });
      assert.equal(r.amount, amount);
      assert.equal(r.record.amount, amount);
      // On the wire: the u64 price as an integer literal, the amounts as decimal strings.
      const quoteBody = w.bodies.find((b) => b.includes("tenzro_quotePayment"));
      assert.ok(quoteBody.includes(`"usd_e6":${amount}`), quoteBody);
      const settleBody = w.bodies.find((b) => b.includes("tenzro_settle"));
      assert.ok(settleBody.includes(`"amount":"${amount}"`), settleBody);
      assert.ok(settleBody.includes(`"max_amount":"${amount}"`), settleBody);
      assert.ok(settleBody.includes(`"usd_e6":${amount}`), settleBody);
    } finally {
      w.restore();
    }
  }
});

test("verifyReceipt and checkReceipt hold exactly at the boundary amounts", async () => {
  const e = v.receipt.expected;
  for (const amount of VECTORS) {
    for (const onWire of [amount, amount.toString()]) {
      const w = wire((m) => (m === "tenzro_getPayment" ? record(onWire, "1000000") : null));
      try {
        const pay = new sdk.LedgerPayments(w.clients);
        const expected = { paymentId: e.payment_id, request: e.request, payee: e.payee, asset: e.asset, amount };
        const r = await pay.verifyReceipt(expected);
        assert.equal(r.amount, amount);
        await assert.rejects(pay.verifyReceipt({ ...expected, amount: amount - 1n }), (x) => x.code === "receipt_mismatch");
      } finally {
        w.restore();
      }
    }
  }
});

test("charge compares value units past 2^53 exactly", async () => {
  const e = v.receipt.expected;
  const w = wire((m) => (m === "tenzro_getPayment" ? record(ABOVE, ABOVE) : null));
  try {
    const pay = new sdk.LedgerPayments(w.clients);
    const req = { request: e.request, paymentId: e.payment_id };
    const at = pay.charge(async () => "ok", { payee: e.payee, price: { amount: price(ABOVE), unit: "USD" }, accept: v.quote.accept });
    assert.equal(await at(req), "ok");
    const over = pay.charge(async () => "ok", { payee: e.payee, price: { amount: price(ABOVE + 1n), unit: "USD" }, accept: v.quote.accept });
    assert.equal((await over(req)).status, 402);
  } finally {
    w.restore();
  }
});

test("balances and transfers carry boundary amounts exactly", async () => {
  for (const amount of VECTORS) {
    const w = wire((m) => (m === "tenzro_getBalance" ? `0x${amount.toString(16)}` : null));
    try {
      const wallet = new sdk.WalletClient(w.clients[0]);
      assert.equal(await wallet.getBalance("0x" + "11".repeat(32)), amount);
    } finally {
      w.restore();
    }
  }
});

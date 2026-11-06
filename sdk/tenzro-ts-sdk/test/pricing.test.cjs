// The pricing rule, the voucher preimage and the registry wrappers, against
// the vectors the node's own tests assert.
const test = require("node:test");
const assert = require("node:assert/strict");
const sdk = require("../dist/index.js");

const card = (denom, lines, min = 0) => ({
  denom,
  lines: Object.fromEntries(lines.map(([k, p, e]) => [k, { price: String(p), per_exp: e }])),
  min_charge: String(min),
});
const A = card("nano_usd", [["input_tokens", 200000000, 6], ["output_tokens", 1000000000, 6]]);

test("the charge vectors hold", () => {
  assert.equal(sdk.chargeInDenom(A, { input_tokens: 1000, output_tokens: 500 }), 700000n);
  assert.equal(sdk.chargeWei(A, { input_tokens: 1000000 }, 500000000n), 400000000000000000n);
  const B = card("wei", [["pixel_steps", 2000000, 0]]);
  assert.equal(sdk.chargeWei(B, { pixel_steps: 31719424 }, 0n), 63438848000000n);
  const C = card("nano_usd", [["bandwidth_bytes", 10000000, 9]]);
  assert.equal(sdk.chargeInDenom(C, { bandwidth_bytes: 1000000006 }), 10000001n);
  assert.throws(() => sdk.chargeInDenom(A, { "output_tokens@priority": 1 }), /prices none/);
  assert.equal(sdk.chargeInDenom(A, { input_tokens: 1000, ttft_ms: 250 }), 200000n);
  assert.throws(() => sdk.chargeWei(A, { input_tokens: 1 }, 0n), /rate/);
});

test("the voucher preimage binds the receipt chain", () => {
  const z = new Uint8Array(32);
  const e = new Uint8Array(32).fill(1);
  const a = sdk.escrowVoucherPreimage(1337n, e, 5n, z);
  assert.equal(a.length, "tenzro/escrow-voucher".length + 8 + 32 + 16 + 32);
  const b = sdk.escrowVoucherPreimage(1337n, e, 5n, new Uint8Array(32).fill(2));
  assert.notDeepEqual(a, b);
  // Layout: domain, chain id LE, escrow, cumulative LE, binding.
  assert.equal(Buffer.from(a.slice(21, 29)).toString("hex"), "3905000000000000");
  assert.equal(a[61], 5);
  const h1 = sdk.receiptChainNext(z, e);
  assert.equal(h1.length, 32);
  assert.notDeepEqual(
    sdk.receiptChainNext(h1, new Uint8Array(32).fill(2)),
    sdk.receiptChainNext(sdk.receiptChainNext(z, new Uint8Array(32).fill(2)), e),
  );
});

test("the registry client calls the node's registry methods", async () => {
  const calls = [];
  const rpc = { call: async (m, p) => { calls.push([m, p]); return m === "tenzro_getFeeRate" ? { rate_nano_usd: "500000000" } : m === "tenzro_getPriceCard" ? { id: "x", card: { model_id: "m", model_hash: "h", rates: A } } : null; } };
  const r = new sdk.RegistryClient(rpc);
  await r.list("unit", "a", 5);
  await r.get("bandwidth_bytes", 2);
  assert.equal(await r.quote("ab", "m", { input_tokens: 1000000 }), 400000000000000000n);
  assert.deepEqual(calls.map((c) => c[0]), ["tenzro_listRegistry", "tenzro_getRegistryEntry", "tenzro_getPriceCard", "tenzro_getFeeRate"]);
  assert.deepEqual(calls[0][1], { kind: "unit", after: "a", limit: 5 });
  assert.equal(sdk.cardEntryId("0xab", "m"), "ab/card/m");
  assert.deepEqual(sdk.registryRetireTx("x"), { Registry: { op: { retire: { id: "x" } } } });
  assert.deepEqual([...sdk.RESERVED_REGISTRY_KINDS], ["standard", "conformance", "name"]);
});

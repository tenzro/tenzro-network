// Runs against the compiled package in dist/ (npm test builds first).
// The AP2 mandate-to-Terms vectors shared with the Rust and Python SDKs: each
// case decides after the mandate's constraints and the Terms per-payment limit.
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const sdk = require("../dist/index.js");

const file = JSON.parse(fs.readFileSync(path.join(__dirname, "../../fixtures/ap2_terms/vectors.json"), "utf8"));

test("every AP2 mandate-to-Terms vector decides as stated", () => {
  const txid = "checkout-digest";
  const instrument = { id: "tenzro-wallet", type: "tenzro" };
  const now = Math.floor(Date.now() / 1000);
  assert.ok(file.cases.length >= 15);
  for (const c of file.cases) {
    const constraints = JSON.parse(JSON.stringify(c.constraints).replaceAll("$PAYEE", file.payee));
    const all = c.omit_reference ? constraints : [{ type: "payment.reference", conditional_transaction_id: txid }, ...constraints];
    const payment = { payee: file.payee, amount: BigInt(c.amount), currency: file.currency };
    let accepted = true;
    try {
      sdk.checkMandateConstraints(all, payment, txid, instrument, now);
      if (BigInt(c.amount) > BigInt(c.terms_max)) accepted = false;
    } catch (e) {
      assert.ok(e instanceof sdk.MandateRefusal, `${c.name}: ${e}`);
      accepted = false;
    }
    assert.equal(accepted ? "accept" : "refuse", c.expect, c.name);
  }
});

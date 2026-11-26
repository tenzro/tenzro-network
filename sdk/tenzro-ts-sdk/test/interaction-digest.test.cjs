// The interaction record digest of docs/standards/interaction-receipt.md,
// computed without a node, against the published vectors.
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const sdk = require("../dist/index.js");

const all = JSON.parse(
  fs.readFileSync(path.join(__dirname, "../../../docs/standards/vectors/interaction-receipt.json"), "utf8"),
);

test("every published vector has its digest and every refused one its reason", async () => {
  assert.ok(all.vectors.length >= 4);
  for (const v of all.vectors) {
    assert.equal(await sdk.interactionDigest(JSON.stringify(v.record)), v.digest, v.label);
  }
  for (const v of all.refused) {
    await assert.rejects(
      sdk.interactionDigest(JSON.stringify(v.record)),
      (err) => err instanceof sdk.InteractionError && err.reason === v.reason,
      v.label,
    );
  }
});

test("an amount written as a number past 2^53 stays exact", async () => {
  const record = { ...all.vectors[0].record, amount_charged: "18446744073709551615" };
  const asString = JSON.stringify(record);
  const asNumber = asString.replace('"18446744073709551615"', "18446744073709551615");
  assert.notEqual(asNumber, asString);
  assert.equal(await sdk.interactionDigest(asNumber), await sdk.interactionDigest(asString));
  // A value JSON.parse already rounded is refused, never digested as another amount.
  await assert.rejects(sdk.interactionDigest(JSON.parse(asNumber)), (err) => err.reason === "malformed");
});

test("the preimage starts with the domain and ends with the time as eight bytes", () => {
  const preimage = sdk.interactionPreimage(JSON.stringify(all.vectors[0].record));
  const domain = new TextEncoder().encode(sdk.INTERACTION_DOMAIN);
  assert.deepEqual(preimage.slice(0, domain.length), domain);
  const tail = new DataView(preimage.buffer, preimage.length - 12);
  assert.equal(tail.getUint32(0, true), 8);
  assert.equal(tail.getBigInt64(4, true), BigInt(all.vectors[0].record.occurred_at));
});

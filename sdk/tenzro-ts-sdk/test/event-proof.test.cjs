// Event proofs from the shared fixture under sdk/fixtures/event-proof, which
// the Rust SDK pins to what the chain's own types serve.
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const sdk = require("../dist/index.js");

const fixture = JSON.parse(
  fs.readFileSync(path.join(__dirname, "..", "..", "fixtures", "event-proof", "fixture.json"), "utf8"),
);
const anchor = Buffer.from(fixture.anchor_digest, "hex");

test("blake3 matches the reference vectors", () => {
  const hex = (b) => Buffer.from(b).toString("hex");
  assert.equal(hex(sdk.blake3(new Uint8Array(0))), "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262");
  const input = Uint8Array.from({ length: 3000 }, (_, i) => i % 251);
  assert.equal(hex(sdk.blake3(input)), fixture.blake3_3000);
});

test("a served proof verifies against the certified checkpoint", () => {
  sdk.verifyEventProof(fixture.proof, anchor);
});

test("a tampered proof does not verify", () => {
  const tampered = structuredClone(fixture.proof);
  tampered.event.data[0] ^= 1;
  assert.throws(() => sdk.verifyEventProof(tampered, anchor));
  const header = structuredClone(fixture.proof);
  header.header.metadata.gas_used += 1;
  assert.throws(() => sdk.verifyEventProof(header, anchor));
  assert.throws(() => sdk.verifyEventProof(fixture.proof, new Uint8Array(32)));
});

test("an index answer verifies only as the projection of its proofs", () => {
  sdk.verifyIndexAnswer(fixture.answer, anchor);
  const lie = structuredClone(fixture.answer);
  lie.result = {};
  assert.throws(() => sdk.verifyIndexAnswer(lie, anchor));
});

test("a complete page verifies and an omission does not", () => {
  const c = fixture.completeness;
  const keys = sdk.filterIndexKeys(c.filter);
  const selects = sdk.filterSelects(c.filter);
  sdk.verifyCompleteness(c.proof, anchor, keys, c.answer, selects);
  for (let skip = 0; skip < c.answer.length; skip++) {
    const short = c.answer.filter((_, i) => i !== skip);
    assert.throws(() => sdk.verifyCompleteness(c.proof, anchor, keys, short, selects));
  }
  const tampered = structuredClone(c.proof);
  tampered.blocks[1].entries[0].entry.cursors = [];
  assert.throws(() => sdk.verifyCompleteness(tampered, anchor, keys, c.answer, selects));
});

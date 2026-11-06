// Governance receipts from the shared fixture under sdk/fixtures/governance_receipt,
// certified from genesis by the chain's own types (the CLI checks the same
// receipt from the genesis anchor).
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const sdk = require("../dist/index.js");

const dir = path.join(__dirname, "..", "..", "fixtures", "governance_receipt");
const fixture = JSON.parse(fs.readFileSync(path.join(dir, "receipt_from_genesis.json"), "utf8"));
const root = Buffer.from(fixture.certified_state_root, "hex");
const clone = () => JSON.parse(JSON.stringify(fixture.receipt));
const at = (r, kind) => r.records.findIndex((x) => x.kind === kind);

test("a certified receipt verifies offline", () => {
  const report = sdk.verifyGovernanceReceipt(fixture.receipt, root);
  assert.equal(report.executedHeight, BigInt(fixture.executed_height));
  assert.equal(report.proposal.status, "executed");
  assert.equal(report.tally.yes, "3");
  assert.equal(report.vetoLocked, 0n);
});

test("every tampering is refused", () => {
  assert.throws(() => sdk.verifyGovernanceReceipt(fixture.receipt, Buffer.alloc(32, 9)), /another state root/);
  let r = clone();
  r.records[at(r, "tally")].value = Buffer.from('{"yes":"4","no":"0","total_eligible":"4"}').toString("hex");
  assert.throws(() => sdk.verifyGovernanceReceipt(r, root), /not proven/);
  r = clone();
  r.records[at(r, "veto_total")].value = "01" + "00".repeat(15);
  assert.throws(() => sdk.verifyGovernanceReceipt(r, root), /not proven/);
  r = clone();
  r.records.splice(at(r, "decision"), 1);
  assert.throws(() => sdk.verifyGovernanceReceipt(r, root), /decision/);
  r = clone();
  r.records[0].subject = "cd".repeat(32);
  assert.throws(() => sdk.verifyGovernanceReceipt(r, root), /another proposal/);
  r = clone();
  r.records[at(r, "proposal")].proof.siblings[0][0] ^= 1;
  assert.throws(() => sdk.verifyGovernanceReceipt(r, root), /not proven/);
});

// The binary proof form the finality verifier reads, as the JSON the node serves.
function proofJson(h) {
  const b = Buffer.from(h, "hex");
  const depth = b.readUInt16BE(0);
  const word = (i) => b.subarray(i, i + 32).toString("hex");
  const siblings = Array.from({ length: depth }, (_, d) => word(2 + 32 * d));
  const t = 2 + 32 * depth;
  const terminal =
    b[t] === 0
      ? "Empty"
      : b[t] === 1
        ? { OtherStem: { stem: b.subarray(t + 1, t + 32).toString("hex"), slots_root: word(t + 32) } }
        : { Stem: { slot_siblings: Array.from({ length: 8 }, (_, i) => word(t + 1 + 32 * i)) } };
  return { siblings, terminal };
}

test("the finality verifier vectors verify here", () => {
  const v = JSON.parse(fs.readFileSync(path.join(dir, "vectors.json"), "utf8"));
  const id = v.proposal_id;
  const record = (kind, prefix, value, proof) => ({ kind, subject: id, slot: prefix + id, value, proof: proofJson(v[proof]) });
  const receipt = {
    state_root: v.state_root,
    proposal_id: id,
    records: [
      record("proposal", "proposal:", v.proposal_record, "proposal_proof"),
      record("decision", "governance_decision:", v.decision, "decision_proof"),
    ],
  };
  const vroot = Buffer.from(v.state_root, "hex");
  assert.throws(() => sdk.verifyGovernanceReceipt(receipt, vroot), /tally/);
  receipt.records[1].value = v.decision.slice(0, 78) + "00";
  assert.throws(() => sdk.verifyGovernanceReceipt(receipt, vroot), /not proven/);
});

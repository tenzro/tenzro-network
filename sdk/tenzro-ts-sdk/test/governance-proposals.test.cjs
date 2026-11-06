// Governance proposal builders: the proposal bytes are the action the node reads.
const test = require("node:test");
const assert = require("node:assert/strict");
const sdk = require("../dist/index.js");

const action = (tx) => {
  assert.equal(tx.kind, "GovernancePropose");
  return JSON.parse(Buffer.from(tx.fields.proposal).toString("utf8"));
};

test("reinstateValidatorProposal carries the account as 32 bytes", () => {
  const a = action(sdk.reinstateValidatorProposal("0x" + "ab".repeat(32), "wrongly jailed"));
  assert.deepEqual(a, { action: "reinstate_validator", validator: Array(32).fill(0xab), memo: "wrongly jailed" });
});

test("reinstateValidatorProposal refuses a malformed account", () => {
  for (const bad of ["ab".repeat(31), "zz".repeat(32), ""]) {
    assert.throws(() => sdk.reinstateValidatorProposal(bad, "memo"), /32 bytes/);
  }
});

test("pausing a lever is an ordinary parameter change", () => {
  const a = action(sdk.parameterChangeProposal("bridge.status", 1, "fault"));
  assert.equal(a.action, "parameter_change");
  assert.equal(a.value, 1);
});

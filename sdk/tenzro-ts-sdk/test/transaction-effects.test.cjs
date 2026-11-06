// What an approval shows: the effects a node derives for an unsigned
// transaction, and, given a second operator's node, only effects both derived
// at the same block.
const test = require("node:test");
const assert = require("node:assert/strict");
const sdk = require("../dist/index.js");

const effects = (digest, block = "0xb1") => ({ outcome: "success", balance_changes: [], logs: [], digest, block_hash: block });

function node(answer) {
  const calls = [];
  return {
    calls,
    async call(method, params) {
      calls.push({ method, params });
      return { effects: answer(params[0]) };
    },
  };
}

const tx = { tx_type: { Transfer: { to: "0x01", amount: "5" } } };

test("one node: its effects, for exactly the transaction asked about", async () => {
  const a = node(() => effects("0xd1"));
  const got = await new sdk.GovernanceClient(a).transactionEffects(tx);
  assert.equal(got.digest, "0xd1");
  assert.deepEqual(a.calls, [{ method: "tenzro_decodeAction", params: [{ transaction: tx }] }]);
});

test("two nodes: the second executes at the first's block, and agreeing effects are returned", async () => {
  const a = node(() => effects("0xd1", "0xb7"));
  const b = node((p) => effects("0xd1", p.block.blockHash));
  const got = await new sdk.GovernanceClient(a).transactionEffects(tx, b);
  assert.equal(got.block_hash, "0xb7");
  assert.deepEqual(b.calls[0].params, [{ transaction: tx, block: { blockHash: "0xb7" } }]);
});

test("two nodes that derive different effects stop the approval", async () => {
  const a = node(() => effects("0xd1"));
  await assert.rejects(new sdk.GovernanceClient(a).transactionEffects(tx, node(() => effects("0xd2"))), /must not be approved/);
  await assert.rejects(new sdk.GovernanceClient(a).transactionEffects(tx, node(() => effects("0xd1", "0xb2"))), /must not be approved/);
});

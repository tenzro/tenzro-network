// AccountKeysClient.sendEnrolling: an account with no ML-DSA-65 key enrolled
// sends its first transaction by enrolling the hardware's key and sending again.
const test = require("node:test");
const assert = require("node:assert/strict");
const sdk = require("../dist/index.js");

const NOT_ENROLLED = "invalid signature: ML-DSA-65 leg present for a key with no ML-DSA-65 key enrolled";

function signer() {
  return {
    p256PublicKey: () => new Uint8Array(64).fill(7),
    mlDsaPublicKey: () => new Uint8Array(1952).fill(3),
    signComposite: async () => [new Uint8Array(64).fill(1), new Uint8Array(3309).fill(2)],
  };
}

// Replaces TypedTxClient.send with one that answers from `answers` in turn and
// records the kind of each transaction it was given.
function stubSend(answers) {
  const original = sdk.TypedTxClient.prototype.send;
  const sent = [];
  sdk.TypedTxClient.prototype.send = async function (_signer, tx) {
    sent.push(tx.kind);
    const a = answers.shift();
    if (a instanceof Error) throw a;
    return a;
  };
  return { sent, restore: () => (sdk.TypedTxClient.prototype.send = original) };
}

const transfer = { kind: "Transfer", fields: { amount: 1 } };

test("a transaction the node accepts is sent once", async () => {
  const stub = stubSend(["0xabc"]);
  try {
    const out = await new sdk.AccountKeysClient({}).sendEnrolling(signer(), transfer);
    assert.equal(out, "0xabc");
    assert.deepEqual(stub.sent, ["Transfer"]);
  } finally {
    stub.restore();
  }
});

test("a node that has no key enrolled gets the enrolment, then the transaction again", async () => {
  const stub = stubSend([new Error(NOT_ENROLLED), "0xenrol", "0xabc"]);
  try {
    const out = await new sdk.AccountKeysClient({}).sendEnrolling(signer(), transfer);
    assert.equal(out, "0xabc");
    assert.deepEqual(stub.sent, ["Transfer", "AccountKeys", "Transfer"]);
  } finally {
    stub.restore();
  }
});

test("any other refusal is raised without enrolling", async () => {
  const stub = stubSend([new Error("insufficient balance")]);
  try {
    await assert.rejects(new sdk.AccountKeysClient({}).sendEnrolling(signer(), transfer), /insufficient balance/);
    assert.deepEqual(stub.sent, ["Transfer"]);
  } finally {
    stub.restore();
  }
});

test("an enrolment that is itself refused is not retried by enrolling", async () => {
  const stub = stubSend([new Error(NOT_ENROLLED)]);
  try {
    const enrol = { kind: "AccountKeys", fields: { op: {} } };
    await assert.rejects(new sdk.AccountKeysClient({}).sendEnrolling(signer(), enrol), /no ML-DSA-65 key enrolled/);
    assert.deepEqual(stub.sent, ["AccountKeys"]);
  } finally {
    stub.restore();
  }
});

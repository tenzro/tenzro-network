// SettleClient.signPlanPayment: signs the plan's open transaction locally,
// checks the node's signing digest before signing, and submits nothing.
const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const sdk = require("../dist/index.js");

const P256_PK = new Uint8Array(64).fill(7);
const P256_SIG = new Uint8Array(64).fill(1);
const PQ_SIG = new Uint8Array(3309).fill(2);

// A hardware signer stand-in: the P-256 key names the account, and both
// composite legs come back from one call.
function fakeSigner() {
  const calls = [];
  return {
    calls,
    p256PublicKey: () => P256_PK,
    signComposite: async (m) => {
      calls.push(m);
      return [P256_SIG, PQ_SIG];
    },
  };
}

const u = (v, n, signed = false) => {
  const b = Buffer.alloc(n);
  if (n === 4) b.writeUInt32LE(v);
  else if (signed) b.writeBigInt64LE(BigInt(v));
  else b.writeBigUInt64LE(BigInt(v));
  return b;
};
const unhex = (h) => Buffer.from(h.replace(/^0x/, ""), "hex");

// The node's `plain` signing payload, computed the way the chain does.
function plainPayload(r, tamper) {
  const encoded = JSON.stringify(r.tx_type);
  const digest = crypto
    .createHash("sha256")
    .update(
      Buffer.concat([
        u(r.chain_id, 8),
        unhex(r.from),
        unhex(r.to),
        u(r.nonce, 8),
        u(r.gas_limit, 8),
        u(r.gas_price, 8),
        u(r.timestamp, 8, true),
        u(r.valid_until, 8, true),
        Buffer.from(encoded),
      ]),
    )
    .digest();
  if (tamper) digest[0] ^= 0xff;
  return { kind: "plain", digest: digest.toString("hex"), tx_type_json: encoded };
}

function fakeRpc({ tamper = false } = {}) {
  const methods = [];
  return {
    methods,
    call: async (method, params) => {
      methods.push(method);
      if (method === "tenzro_getNonce") return "0x3";
      if (method === "eth_chainId") return "0x539";
      if (method === "eth_gasPrice") return "0xee6b2800";
      if (method === "tenzro_getSigningPayload") return plainPayload(params, tamper);
      if (method === "tenzro_sendRawTransaction") return { params };
      throw new Error(`unexpected rpc ${method}`);
    },
  };
}

const plan = { legs: [{ to: "0x" + "ab".repeat(32), amount: "1000" }], nonce: 1 };
const accepted = {
  scheme: "plan",
  network: "tenzro:1337",
  amount: "1000",
  asset: "TNZO",
  payTo: "0x" + "ab".repeat(32),
  maxTimeoutSeconds: 60,
};

test("signPlanPayment wraps the signed open transaction and submits nothing", async () => {
  const rpc = fakeRpc();
  const signer = fakeSigner();
  const resource = { url: "https://example.org/r" };
  const { payload, header } = await new sdk.SettleClient(rpc).signPlanPayment(signer, plan, accepted, resource);

  assert.equal(payload.x402Version, sdk.X402_VERSION);
  assert.deepEqual(payload.accepted, accepted);
  assert.deepEqual(payload.resource, resource);
  const tx = payload.payload.signed_tx;
  assert.deepEqual(tx.transaction.tx_type, { SettlementPlan: { op: { open: plan } } });
  assert.equal(tx.transaction.chain_id, 0x539);
  assert.equal(tx.transaction.nonce, 3);
  assert.equal(tx.public_key, Buffer.from(P256_PK).toString("hex"));
  assert.deepEqual(tx.signature, {
    classical: { form: "raw", signature: Buffer.from(P256_SIG).toString("hex") },
    pq: Buffer.from(PQ_SIG).toString("hex"),
  });
  assert.equal(signer.calls.length, 1);

  assert.deepEqual(JSON.parse(Buffer.from(header, "base64").toString("utf8")), payload);
  assert.deepEqual(rpc.methods.sort(), ["eth_chainId", "eth_gasPrice", "tenzro_getNonce", "tenzro_getSigningPayload"]);
});

test("signPlanPayment refuses a digest the node altered, before signing", async () => {
  const signer = fakeSigner();
  await assert.rejects(new sdk.SettleClient(fakeRpc({ tamper: true })).signPlanPayment(signer, plan, accepted));
  assert.equal(signer.calls.length, 0);
});

test("signPlanPayment refuses a requirement that is not a plan", async () => {
  await assert.rejects(
    new sdk.SettleClient(fakeRpc()).signPlanPayment(fakeSigner(), plan, { ...accepted, scheme: "exact" }),
    /not plan/,
  );
});

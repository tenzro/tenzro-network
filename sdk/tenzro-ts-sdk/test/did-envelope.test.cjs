// The controller's DID envelope over a machine registration, pinned to the
// shared vector the node's envelope code is checked against
// (sdk/fixtures/did_envelope/machine_registration.json).
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const sdk = require("../dist/index.js");

const vector = JSON.parse(
  fs.readFileSync(path.join(__dirname, "../../fixtures/did_envelope/machine_registration.json"), "utf8"),
);
const hex = (s) => Uint8Array.from(Buffer.from(s, "hex"));
const toHex = (b) => Buffer.from(b).toString("hex");

// A signer that answers only for the vector's message representative, with
// the vector's signature, so the envelope the SDK builds is byte-checked.
function vectorSigner() {
  return {
    p256PublicKey: () => hex(vector.controller_public_key),
    signComposite: async (mPrime) => {
      assert.equal(toHex(mPrime), vector.m_prime, "the SDK asked to sign the vector's message");
      return [hex(vector.signature.classical.signature), null];
    },
  };
}

test("the request binding and params hash match the node's", async () => {
  const binding = sdk.requestBinding(vector.request);
  assert.equal(Buffer.from(binding).toString("utf8"), vector.request_binding);
  assert.deepEqual(sdk.requestBinding({ ...vector.request, did_envelope: "ff", extra: undefined }), binding);
  const hash = new Uint8Array(await crypto.subtle.digest("SHA-256", binding));
  assert.equal(toHex(hash), vector.params_hash);
});

test("the preimage, message representative and header match the node's", async () => {
  const fields = {
    did: vector.did,
    method: vector.method,
    paramsHash: hex(vector.params_hash),
    timestampMs: vector.timestamp_ms,
    nonce: hex(vector.nonce),
  };
  const preimage = sdk.didEnvelopePreimage(fields);
  assert.equal(toHex(preimage), vector.preimage);
  const mPrime = await sdk.compositeMessageRepresentative(sdk.DID_ENVELOPE_CONTEXT, preimage);
  assert.equal(toHex(mPrime), vector.m_prime);
  assert.equal(sdk.didEnvelopeHeader(fields, vector.signature), vector.did_envelope);
});

test("the vector's signature is the controller's over the message representative", async () => {
  const xy = hex(vector.controller_public_key);
  const raw = new Uint8Array(65);
  raw[0] = 4;
  raw.set(xy, 1);
  const key = await crypto.subtle.importKey("raw", raw, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
  const sig = hex(vector.signature.classical.signature);
  const ecdsa = { name: "ECDSA", hash: "SHA-256" };
  assert.ok(await crypto.subtle.verify(ecdsa, key, sig, hex(vector.m_prime)));
  const other = hex(vector.m_prime);
  other[other.length - 1] ^= 1;
  assert.equal(await crypto.subtle.verify(ecdsa, key, sig, other), false);
});

test("withRequestEnvelope signs every field with the controller's signer", async () => {
  const signed = await sdk.withRequestEnvelope(vectorSigner(), vector.did, vector.method, vector.request, {
    timestampMs: vector.timestamp_ms,
    nonce: hex(vector.nonce),
  });
  assert.equal(signed.did_envelope, vector.did_envelope);
  for (const [k, v] of Object.entries(vector.request)) assert.deepEqual(signed[k], v);
});

test("registerMachine sends tenzro_registerMachineIdentity with the controller's envelope", async () => {
  const calls = [];
  const rpc = { call: async (method, params) => (calls.push({ method, params }), { did: "did:tenzro:machine:x" }) };
  const identity = new sdk.IdentityClient(rpc);
  const controller = {
    p256PublicKey: () => hex(vector.controller_public_key),
    signComposite: async () => [hex(vector.signature.classical.signature), null],
  };
  const params = {
    controllerDid: vector.did,
    publicKey: vector.request.public_key,
    capabilities: vector.request.capabilities,
  };
  await identity.registerMachine(params, controller);
  assert.equal(calls.length, 1);
  const { method, params: sent } = calls[0];
  assert.equal(method, "tenzro_registerMachineIdentity");
  assert.deepEqual(Object.keys(sent).sort(), ["capabilities", "controller_did", "did_envelope", "public_key"]);
  assert.equal(sent.controller_did, vector.did);

  // The header names the controller and the method, and binds exactly the
  // fields sent beside it.
  const header = Buffer.from(sent.did_envelope, "hex");
  let o = 0;
  const take = (n) => header.subarray(o, (o += n));
  const u32 = () => take(4).readUInt32BE(0);
  assert.equal(take(u32()).toString("utf8"), vector.did);
  assert.equal(take(u32()).toString("utf8"), "tenzro_registerMachineIdentity");
  const binding = sdk.requestBinding(sent);
  const hash = Buffer.from(await crypto.subtle.digest("SHA-256", binding));
  assert.equal(take(32).toString("hex"), hash.toString("hex"));
  const ts = Number(take(8).readBigUInt64BE(0));
  assert.ok(Math.abs(ts - Date.now()) < 60_000, "a fresh timestamp");
  take(16);
  assert.deepEqual(JSON.parse(take(u32()).toString("utf8")), {
    classical: { form: "raw", signature: vector.signature.classical.signature },
  });
  assert.equal(o, header.length);
});

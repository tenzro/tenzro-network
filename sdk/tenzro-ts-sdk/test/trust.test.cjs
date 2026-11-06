// Runs against the compiled package in dist/ (npm test builds first).
const test = require("node:test");
const assert = require("node:assert/strict");
const sdk = require("../dist/index.js");

// Headers the Rust signer (tenzro_payments::rfc9421::agent) produces for
// this request; both implementations must agree on the signature base.
const VECTOR = {
  public_key:
    "0217e617f0b6443928278f96999e69a23a4f2c152bdf6d6cdf66e5b80282d4ed194a7debcb97712d2dda3ca85aa8765a56f45fc758599652f2897c65306e5794",
  headers: {
    "Signature-Agent":
      '"https://node.example/.well-known/http-message-signatures-directory?agent=did:tenzro:machine:alice:shopper"',
    "Tenzro-Agent": "did:tenzro:machine:alice:shopper",
    "Tenzro-Mandate": "beef",
    "Content-Digest": "sha-256=:kkON3UJmsycfzr/0kafbfwmVMyut6CTHBPg1lrfzb3Q=:",
    "Signature-Input":
      'tenzro=("@method" "@authority" "@path" "@query" "signature-agent" "tenzro-agent" "tenzro-mandate" "content-digest");created=1700000000;expires=1700000300;nonce="n1";keyid="jkt-vector";alg="ecdsa-p256-sha256";tag="web-bot-auth"',
    Signature:
      "tenzro=:4QIEap6tQ39GNiJ6idvGjehPECBALHDkmZxn9+PsBiVumLqx5ZLOrHaUoLv/4wyZbNOgiWF5mkNgU1J/uLcrRQ==:",
  },
};

function request(overrides = {}) {
  return {
    method: "POST",
    url: "https://shop.example/buy?sku=1",
    headers: { ...VECTOR.headers },
    body: '{"qty":1}',
    ...overrides,
  };
}

function resolution(overrides = {}) {
  return {
    agent_did: "did:tenzro:machine:alice:shopper",
    root: "did:tenzro:human:alice",
    keyid: "jkt-vector",
    public_key: VECTOR.public_key,
    machine_did: "did:tenzro:machine:m1",
    key_certification: "",
    mandate: "beef",
    terms_version: 1,
    expires_at_ms: null,
    revoked: false,
    quarantined: false,
    ...overrides,
  };
}

const NOW = 1_700_000_010;

test("a request the Rust signer produced verifies, and forgeries are refused", async () => {
  assert.deepEqual(sdk.agentKeyOf(request()), {
    keyid: "jkt-vector",
    agent_did: "did:tenzro:machine:alice:shopper",
  });
  const ok = await sdk.verifyAgentRequest(request(), resolution(), NOW);
  assert.equal(ok.root, "did:tenzro:human:alice");

  const refused = [
    [request({ body: '{"qty":9}' }), resolution()],
    [request({ url: "https://shop.example/refund?sku=1" }), resolution()],
    [request(), resolution({ revoked: true })],
    [request(), resolution({ quarantined: true })],
    [request(), resolution({ mandate: "cafe" })],
    [request(), resolution({ expires_at_ms: NOW * 1000 - 1 })],
    [request(), resolution({ agent_did: "did:tenzro:machine:alice:other" })],
  ];
  for (const [req, res] of refused) {
    await assert.rejects(sdk.verifyAgentRequest(req, res, NOW));
  }
  await assert.rejects(sdk.verifyAgentRequest(request(), resolution(), NOW + 3600));
});

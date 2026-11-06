// The hardware DPoP prover: an ES256 proof whose signing input's SHA-256 the
// hardware key signs. The key here stands in for the TPM or Secure Enclave.
const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const { HardwareDpopProver, jwkThumbprint } = require("../dist/index.js");

function standIn() {
  const { publicKey } = crypto.generateKeyPairSync("ec", { namedCurve: "P-256" });
  const jwk = publicKey.export({ format: "jwk" });
  const key = {
    digests: [],
    publicKeyJwk: () => ({ kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y }),
    // The hardware key signs the 32-byte digest it is given (raw r || s).
    async sign(digest) {
      key.digests.push(Buffer.from(digest));
      return { bytes: new Uint8Array(64).fill(7), aux: new Uint8Array(0) };
    },
  };
  return key;
}

test("a proof is ES256 over its signing input, bound to the token and the request", async () => {
  const key = standIn();
  const prover = new HardwareDpopProver(key);
  const jwk = key.publicKeyJwk();
  const want = crypto
    .createHash("sha256")
    .update(`{"crv":"P-256","kty":"EC","x":"${jwk.x}","y":"${jwk.y}"}`)
    .digest("base64url");
  assert.equal(await prover.jkt(), want);
  assert.equal(jwkThumbprint(jwk), want);

  const proof = await prover.proof("POST", "https://node.example/", "tok");
  const [h, p, s] = proof.split(".");
  const header = JSON.parse(Buffer.from(h, "base64url"));
  const payload = JSON.parse(Buffer.from(p, "base64url"));
  assert.deepEqual(header, { typ: "dpop+jwt", alg: "ES256", jwk });
  assert.equal(payload.htm, "POST");
  assert.equal(payload.htu, "https://node.example/");
  assert.equal(payload.ath, crypto.createHash("sha256").update("tok").digest("base64url"));
  assert.ok(Math.abs(payload.iat - Date.now() / 1000) < 5);
  assert.deepEqual(key.digests, [crypto.createHash("sha256").update(`${h}.${p}`).digest()]);
  assert.deepEqual(Buffer.from(s, "base64url"), Buffer.alloc(64, 7));
});

test("a request's proof names the endpoint as the node checks it: no query, and an empty path is /", async () => {
  const { RpcClient } = require("../dist/index.js");
  const seen = [];
  const realFetch = globalThis.fetch;
  globalThis.fetch = async (_url, init) => {
    const proof = init.headers.DPoP ?? init.headers.dpop;
    seen.push(JSON.parse(Buffer.from(proof.split(".")[1], "base64url").toString()).htu);
    return new Response(JSON.stringify({ jsonrpc: "2.0", id: 1, result: "0x1" }), { headers: { "content-type": "application/json" } });
  };
  try {
    const prover = new HardwareDpopProver(standIn());
    for (const endpoint of ["http://127.0.0.1:29840", "http://127.0.0.1:29840/", "http://127.0.0.1:29840/?x=1#f"]) {
      await new RpcClient(endpoint, undefined, 5_000, undefined, { token: "t", prover }).call("eth_blockNumber", []);
    }
  } finally {
    globalThis.fetch = realFetch;
  }
  assert.deepEqual(seen, ["http://127.0.0.1:29840/", "http://127.0.0.1:29840/", "http://127.0.0.1:29840/"]);
});

test("a refresh proves its key and presents no access token", async () => {
  const sdk = require("../dist/index.js");
  const seen = [];
  const realFetch = globalThis.fetch;
  globalThis.fetch = async (url, init) => {
    seen.push({ url, headers: init.headers, body: JSON.parse(init.body) });
    return new Response(JSON.stringify({ jsonrpc: "2.0", id: 1, result: { refresh_token: "next" } }));
  };
  try {
    const prover = { jkt: async () => "jkt", proof: async (htm, htu, token) => `${htm} ${htu} ${token}` };
    const credential = { token: "signed-in", prover };
    const rpc = new sdk.RpcClient("http://node.invalid", "http://api.invalid", 1000, undefined, credential);
    const out = await rpc.callWithProof("tenzro_refreshToken", { refresh_token: "r1" }, prover);
    assert.deepEqual(out, { refresh_token: "next" });
    assert.equal(seen[0].headers.Authorization, undefined);
    assert.equal(seen[0].headers.DPoP, "POST http://node.invalid/ ");
    assert.equal(seen[0].body.method, "tenzro_refreshToken");
  } finally {
    globalThis.fetch = realFetch;
  }
});

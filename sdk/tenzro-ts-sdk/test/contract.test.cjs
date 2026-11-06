// The shared contract fixtures under sdk/fixtures, which the Rust SDK runs
// too: recorded chat streams decoded at every chunk boundary. Runs against the
// compiled package in dist/ (npm test builds first).
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const sdk = require("../dist/index.js");

const FIXTURES = path.join(__dirname, "..", "..", "fixtures");
const STREAMS = ["content", "reasoning", "tool-calls", "usage", "error"];

// Decode `chunks` as one stream: the events up to the end or the first
// error, the completion, and the error.
function run(chunks) {
  const decoder = new sdk.SseDecoder();
  const assembler = new sdk.ChatStreamAssembler();
  const frames = [];
  for (const c of chunks) frames.push(...decoder.push(c));
  frames.push(...decoder.finish());
  const events = [];
  for (const frame of frames) {
    try {
      events.push(...assembler.push(frame.data));
    } catch (e) {
      assert.ok(e instanceof sdk.ApiError, `unexpected ${e}`);
      return { events, completion: null, error: e.toJSON() };
    }
    if (assembler.done) break;
  }
  assert.ok(assembler.done, "stream ended without [DONE]");
  return { events, completion: assembler.completion(), error: null };
}

test("chat streams decode identically at every chunk boundary", () => {
  const dir = path.join(FIXTURES, "chat-stream");
  const expected = JSON.parse(fs.readFileSync(path.join(dir, "expected.json"), "utf8"));
  for (const name of STREAMS) {
    const bytes = new Uint8Array(fs.readFileSync(path.join(dir, `${name}.sse`)));
    const want = expected[name];
    assert.deepEqual(run([bytes]), want, `${name}: whole stream`);
    for (let cut = 0; cut <= bytes.length; cut++) {
      assert.deepEqual(run([bytes.subarray(0, cut), bytes.subarray(cut)]), want, `${name}: split at byte ${cut}`);
    }
    const singles = Array.from(bytes, (_, i) => bytes.subarray(i, i + 1));
    assert.deepEqual(run(singles), want, `${name}: one byte per read`);
  }
});

test("reasoning arrives before the answer", () => {
  const bytes = new Uint8Array(fs.readFileSync(path.join(FIXTURES, "chat-stream", "reasoning.sse")));
  const kinds = run([bytes]).events.map((e) => e.type);
  const firstContent = kinds.indexOf("content");
  assert.ok(kinds.slice(0, firstContent).includes("reasoning"));
  assert.ok(!kinds.slice(firstContent).includes("reasoning"));
});

test("every request of a client carries that client's own token and a proof for it", async () => {
  const seen = [];
  const realFetch = globalThis.fetch;
  globalThis.fetch = async (url, init) => {
    seen.push({ url: String(url), auth: init.headers["Authorization"], dpop: init.headers["DPoP"] });
    const body = String(url).endsWith("/v1/chat/completions")
      ? fs.readFileSync(path.join(FIXTURES, "chat-stream", "content.sse"))
      : JSON.stringify({ jsonrpc: "2.0", id: 1, result: "0x1" });
    return new Response(body, { status: 200 });
  };
  try {
    for (const token of ["tok_a", "tok_b"]) {
      const credential = { token, prover: { jkt: async () => "jkt", proof: async (htm, htu, t) => `${htm} ${htu} ${t}` } };
      const rpc = new sdk.RpcClient("http://node.invalid", "http://api.invalid", 1000, undefined, credential);
      await rpc.call("eth_chainId");
      const completion = await new sdk.StreamingClient(rpc).chat({
        model: "qwen3.5-4b",
        messages: [{ role: "user", content: "hi" }],
      });
      assert.equal(completion.content, "Hello, wörld 世界");
    }
  } finally {
    globalThis.fetch = realFetch;
  }
  // The proof names the endpoint as the node checks it: an origin given
  // without a path proves the root path.
  const row = (url, htu, t) => ({ url, auth: `DPoP ${t}`, dpop: `POST ${htu} ${t}` });
  assert.deepEqual(seen, [
    row("http://node.invalid", "http://node.invalid/", "tok_a"),
    row("http://node.invalid/v1/chat/completions", "http://node.invalid/v1/chat/completions", "tok_a"),
    row("http://node.invalid", "http://node.invalid/", "tok_b"),
    row("http://node.invalid/v1/chat/completions", "http://node.invalid/v1/chat/completions", "tok_b"),
  ]);
});

test("an error body before the stream is a typed ApiError", async () => {
  const realFetch = globalThis.fetch;
  globalThis.fetch = async () =>
    new Response(
      JSON.stringify({ error: { message: "No provider serves any of: x", type: "invalid_request_error", code: "model_not_found" } }),
      { status: 404 },
    );
  try {
    const rpc = new sdk.RpcClient("http://node.invalid", undefined, 1000);
    await assert.rejects(
      new sdk.StreamingClient(rpc).chat({ model: "x", messages: [] }),
      (e) => e instanceof sdk.ApiError && e.code === "model_not_found" && e.type === "invalid_request_error",
    );
  } finally {
    globalThis.fetch = realFetch;
  }
});

test("a typed transaction is signed only over the transaction it was built as", async () => {
  const env = {
    chainId: 1337,
    from: new Uint8Array(32).fill(1),
    to: new Uint8Array(32).fill(2),
    nonce: 7,
    gasLimit: 500000,
    gasPrice: 1,
    timestamp: 1000,
    validUntil: 2000,
  };
  const type = sdk.txType({ kind: "Transfer", fields: { amount: 5 } });
  const encoded = '{"Transfer":{"amount":5}}';
  const le = (v, n, signed) => {
    const b = Buffer.alloc(n);
    if (n === 4) b.writeUInt32LE(v);
    else if (signed) b.writeBigInt64LE(BigInt(v));
    else b.writeBigUInt64LE(BigInt(v));
    return b;
  };
  const digest = require("node:crypto")
    .createHash("sha256")
    .update(Buffer.concat([
      le(env.chainId, 8), env.from, env.to, le(env.nonce, 8), le(env.gasLimit, 8), le(env.gasPrice, 8),
      le(env.timestamp, 8, true), le(env.validUntil, 8, true), Buffer.from(encoded),
    ]))
    .digest("hex");
  const got = await sdk.checkSigningPayload(env, type, { kind: "plain", tx_type_json: encoded, digest });
  assert.equal(Buffer.from(got).toString("hex"), digest);
  await assert.rejects(
    sdk.checkSigningPayload(env, type, { kind: "plain", tx_type_json: '{"Transfer":{"amount":6}}', digest }),
    /tx_type/,
  );
  assert.equal(sdk.TX_KINDS.includes("ExitValidator"), true);
  assert.equal(sdk.txType({ kind: "ExitValidator", fields: null }), "ExitValidator");
});

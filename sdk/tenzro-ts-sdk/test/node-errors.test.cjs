// A JSON-RPC error the node answers with reaches the caller as RpcCallError,
// with its code and data, and the light build's refusal is recognised.
const test = require("node:test");
const assert = require("node:assert/strict");
const sdk = require("../dist");

async function callAgainst(error) {
  const realFetch = globalThis.fetch;
  const sent = [];
  globalThis.fetch = async (_url, init) => {
    const body = JSON.parse(init.body);
    sent.push(body);
    return new Response(JSON.stringify({ jsonrpc: "2.0", id: body.id, error }), { status: 200 });
  };
  try {
    const rpc = new sdk.RpcClient("http://node.invalid", undefined, 1000);
    await rpc.call("tenzro_chat", { model_id: "m" });
    assert.fail("the call should fail");
  } catch (e) {
    return { e, sent };
  } finally {
    globalThis.fetch = realFetch;
  }
}

test("the light build refusal is an RpcCallError the caller can recognise", async () => {
  const { e, sent } = await callAgainst({
    code: -32004,
    message: "tenzro_chat needs a model on this node, and this is the light build of tenzro-node, which runs none",
    data: { build: "light" },
  });
  assert.equal(sent[0].method, "tenzro_chat");
  assert.ok(e instanceof sdk.RpcCallError);
  assert.equal(e.code, -32004);
  assert.equal(e.isLightBuild, true);
});

test("other node errors keep their code and data and are not the light build", async () => {
  const { e } = await callAgainst({ code: -32602, message: "missing model_id", data: { field: "model_id" } });
  assert.ok(e instanceof sdk.RpcCallError);
  assert.equal(e.code, -32602);
  assert.deepEqual(e.data, { field: "model_id" });
  assert.equal(e.isLightBuild, false);
  const { e: notFound } = await callAgainst({ code: -32004, message: "no escrow 0x01" });
  assert.equal(notFound.isLightBuild, false);
});

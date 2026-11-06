// Runs against the compiled package in dist/ (npm test builds first).
const test = require("node:test");
const assert = require("node:assert/strict");
const sdk = require("../dist/index.js");

const CHAIN = 1337;

function node({ digest, latest = 9, listed = [], chain = CHAIN }) {
  return (method, params) => {
    if (method === "tenzro_listRoleEndpoints") return { role: "rpc", endpoints: listed };
    if (method === "eth_chainId") return `0x${chain.toString(16)}`;
    if (method === "tenzro_getCheckpointCertificate") {
      const index = params.index ?? latest;
      return { index, digest: `${digest}-${index}` };
    }
    return null;
  };
}

function withNodes(nodes, fn) {
  const real = globalThis.fetch;
  globalThis.fetch = async (url, init) => {
    const handler = nodes[url];
    if (!handler) throw new TypeError(`fetch failed: ${url}`);
    const body = JSON.parse(init.body);
    const result = handler(body.method, body.params);
    return new Response(JSON.stringify({ jsonrpc: "2.0", id: body.id, result }), { status: 200 });
  };
  return fn().finally(() => {
    globalThis.fetch = real;
  });
}

test("discovery keeps the staked endpoints that agree on the chain's history", () =>
  withNodes(
    {
      "https://seed.example": node({
        digest: "good",
        listed: [
          { account: "0x01", url: "https://a.example", bonded: "2" },
          { account: "0x02", url: "https://liar.example", bonded: "1" },
          { account: "0x03", url: "https://other.example", bonded: "1" },
          { account: "0x04", url: "https://down.example", bonded: "1" },
        ],
      }),
      "https://a.example": node({ digest: "good", latest: 12 }),
      "https://liar.example": node({ digest: "forged" }),
      "https://other.example": node({ digest: "good", chain: 1 }),
    },
    async () => {
      const found = await sdk.discoverEndpoints({ seeds: ["https://seed.example"], chainId: CHAIN });
      assert.deepEqual(
        found.map((e) => e.url),
        ["https://a.example", "https://seed.example"],
      );
      assert.equal(found[0].checkpointIndex, 9);
    },
  ));

test("with the first seed down, discovery succeeds through the next", () =>
  withNodes(
    {
      "https://live.example": node({ digest: "good" }),
    },
    async () => {
      const found = await sdk.discoverEndpoints({ seeds: ["https://down.example", "https://live.example"], chainId: CHAIN });
      assert.deepEqual(
        found.map((e) => e.url),
        ["https://live.example"],
      );
      await assert.rejects(sdk.discoverEndpoints({ seeds: ["https://down.example"], chainId: CHAIN }));
      assert.deepEqual(sdk.DEFAULT_NETWORK.seeds, [...sdk.NETWORK_SEEDS]);
    },
  ));

test("the failover transport moves past an endpoint it cannot reach", () =>
  withNodes({ "https://b.example": node({ digest: "good" }) }, async () => {
    const transport = new sdk.FailoverTransport(["https://down.example", "https://b.example"], 1000);
    assert.equal(await transport.call("eth_chainId", []), "0x539");
    assert.equal(transport.endpoint, "https://b.example");
  }));

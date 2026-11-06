// The publisher gate and the paying fetch against a facilitator that keeps
// voucher accounting the way the ledger does: a voucher only moves forward
// and must cover everything served on its channel.
const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const { web } = require("../dist/index.js");

const PAY_TO = "09".repeat(32);
const CHANNEL = "ab".repeat(32);
const FACILITATOR = "https://facilitator.example";
const policy = (extra = {}) => ({
  chainId: 1337,
  payTo: PAY_TO,
  facilitator: FACILITATOR,
  routes: [
    { path: "/articles/*", usdE6: 2_000, permits: ["ai-input", "search"], prohibits: ["ai-train"], contentUsage: "train-ai=n" },
    { path: "/free-preview", usdE6: 0, amount: "0" },
  ],
  ...extra,
});

/** A facilitator with ledger-style voucher accounting per channel. */
function facilitator() {
  const channels = new Map();
  const f = {
    settles: 0,
    channels,
    async settle(body) {
      f.settles++;
      const req = JSON.parse(body);
      const cred = req.paymentPayload.payload;
      const id = cred.extra.escrow_id;
      const cumulative = BigInt(cred.extra.cumulative_amount);
      const charge = BigInt(req.paymentRequirements.amount);
      const c = channels.get(id) ?? { highest: 0n, spent: 0n };
      if (cumulative < c.highest || c.spent + charge > cumulative) {
        return { success: false, errorReason: "invalid_payload", transaction: "", network: req.paymentRequirements.network };
      }
      channels.set(id, { highest: cumulative, spent: c.spent + charge });
      return { success: true, transaction: `escrow:${id}:${cumulative}`, network: req.paymentRequirements.network, amount: String(charge) };
    },
  };
  return f;
}

function harness(opts = {}) {
  const fac = facilitator();
  let served = 0;
  const handler = async () => {
    served++;
    return new Response("the article", { status: 200 });
  };
  const gate = new web.PublisherGate({
    policy: policy(opts.policy),
    quote: async (usdE6) => String(usdE6 * 1000),
    fetch: async (url, init) => new Response(JSON.stringify(await fac.settle(init.body)), { status: 200 }),
  });
  const transport = async (url, init) => gate.handle(new Request(String(url), init), handler);
  return { fac, gate, transport, served: () => served };
}

const signed = { headers: { "signature-input": 'sig1=("@authority");tag="web-bot-auth"', signature: "sig1=:AAAA:" } };

function agentRpc() {
  const calls = [];
  return {
    calls,
    async call(method, params) {
      calls.push({ method, params });
      assert.equal(method, "tenzro_agentVoucher");
      return {
        voucher: {
          escrow_id: params.channel_id,
          cumulative_amount: params.cumulative_amount,
          signature: "11".repeat(64),
          agent: { agent_did: "did:tenzro:agent:a", machine_did: "did:tenzro:machine:m", as_of_ms: 1_800_000_000_000 },
        },
      };
    },
  };
}

test("a person browses free; the licence terms ride along", async () => {
  const h = harness();
  const res = await h.transport("https://pub.example/articles/1", {});
  assert.equal(res.status, 200);
  assert.equal(res.headers.get("content-usage"), "train-ai=n");
  assert.equal(h.served(), 1);
});

test("an agent is asked to pay and nothing runs before it does", async () => {
  const h = harness();
  const res = await h.transport("https://pub.example/articles/1", signed);
  assert.equal(res.status, 402);
  assert.equal(h.served(), 0);
  const required = JSON.parse(web.decodeHeaderText(res.headers.get("PAYMENT-REQUIRED")));
  assert.equal(required.x402Version, 2);
  assert.deepEqual(required.accepts.map((r) => r.scheme), ["batch-settlement", "tenzro-hybrid"]);
  for (const r of required.accepts) {
    assert.equal(r.amount, "2000000");
    assert.equal(r.network, "tenzro:1337");
    assert.equal(r.payTo, PAY_TO);
    assert.equal(r.extra.usd_e6, 2000);
  }
  // A forged requirement (another payee, a lower price) is refused before the facilitator.
  const cheap = { ...required.accepts[0], amount: "1" };
  const header = web.encodeHeaderText(JSON.stringify({ x402Version: 2, resource: required.resource, accepted: cheap, payload: {} }));
  const refused = await h.transport("https://pub.example/articles/1", { headers: { ...signed.headers, "PAYMENT-SIGNATURE": header } });
  assert.equal(refused.status, 402);
  assert.equal(h.fac.settles, 0);
  assert.equal(h.served(), 0);
});

test("ten thousand sub-cent requests ride one channel and leave one voucher to claim", async () => {
  const h = harness();
  const rpc = agentRpc();
  const payer = new web.AgentChannelPayer(rpc, 1337, CHANNEL, PAY_TO);
  const get = web.payingFetch(payer, { maxAmount: 10_000_000n, fetch: h.transport });
  for (let i = 0; i < 10_000; i++) {
    const res = await get(`https://pub.example/articles/${i % 7}`, signed);
    assert.equal(res.status, 200, `request ${i}`);
    assert.ok(res.headers.get("PAYMENT-RESPONSE"));
  }
  assert.equal(h.served(), 10_000);
  assert.equal(h.fac.settles, 10_000);
  const c = h.fac.channels.get(CHANNEL);
  assert.equal(c.highest, 10_000n * 2_000_000n);
  assert.equal(c.spent, c.highest);
  assert.equal(h.fac.channels.size, 1);
});

test("a replayed payment serves nothing", async () => {
  const h = harness();
  const payer = new web.AgentChannelPayer(agentRpc(), 1337, CHANNEL, PAY_TO);
  const first = await h.transport("https://pub.example/articles/1", signed);
  const required = JSON.parse(web.decodeHeaderText(first.headers.get("PAYMENT-REQUIRED")));
  const header = await web.paymentHeader(payer, required, required.accepts[0]);
  const init = { headers: { ...signed.headers, "PAYMENT-SIGNATURE": header } };
  assert.equal((await h.transport("https://pub.example/articles/1", init)).status, 200);
  assert.equal((await h.transport("https://pub.example/articles/1", init)).status, 402);
  assert.equal(h.served(), 1);
});

test("the licence document, robots line and route matching", () => {
  const xml = web.rslXml(policy(), "https://pub.example/");
  assert.match(xml, /<content url="https:\/\/pub.example\/articles\/\*">/);
  assert.match(xml, /<permits type="usage">ai-input search<\/permits>/);
  assert.match(xml, /<prohibits type="usage">ai-train<\/prohibits>/);
  assert.match(xml, /<amount currency="USD">0.002<\/amount>/);
  assert.equal(web.robotsLicenseLine("https://pub.example/"), "License: https://pub.example/license.xml");
  assert.equal(web.matchRoute(policy().routes, "/articles/x").path, "/articles/*");
  assert.equal(web.matchRoute(policy().routes, "/about"), undefined);
});

test("the agent voucher payload matches the shared vector the node decodes", async () => {
  const v = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "..", "fixtures", "payments", "x402_agent_voucher.json"), "utf8"));
  const cred = web.agentVoucherCredential(v.requirement, v.channel_id, BigInt(v.cumulative_amount), BigInt(v.requirement.amount), v.voucher, v.credential_id);
  const text = web.stringifyExact({ x402Version: 2, resource: v.resource, accepted: v.requirement, payload: cred });
  assert.equal(web.encodeHeaderText(text), v.payment_signature);
});

// The shared gate vectors (sdk/fixtures/payments/x402_gate.json), which the
// Rust and Python gates decide identically.
const G = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "..", "fixtures", "payments", "x402_gate.json"), "utf8"));
const normalized = (body) => body.replace(/"challengeId":"[^"]*"/g, '"challengeId":"CHALLENGE"');

test("the gate decides every shared case", async () => {
  for (const c of G.cases) {
    const bodies = [];
    let served = false;
    const gate = new web.PublisherGate({
      policy: G.policy,
      ...(c.quote === false ? {} : { quote: async (usdE6) => String(usdE6 * G.quote_rate) }),
      fetch: async (url, init) => {
        assert.equal(url, `${G.policy.facilitator}/settle`);
        bodies.push(init.body);
        if (c.facilitator.unreachable) throw new TypeError("fetch failed");
        return new Response(JSON.stringify(c.facilitator.respond), { status: 200 });
      },
    });
    const headers = { ...c.headers };
    if (c.payment_text !== undefined) headers["PAYMENT-SIGNATURE"] = web.encodeHeaderText(c.payment_text);
    const origin = G.origin.replace(/\/$/, "");
    const res = await gate.handle(new Request(origin + c.path, { headers }), async () => {
      served = true;
      return new Response("the article", { status: 200 });
    });
    const e = c.expect;
    assert.equal(res.status, e.status, c.name);
    assert.equal(served, e.served, c.name);
    if ("content_usage" in e) assert.equal(res.headers.get("content-usage"), e.content_usage, c.name);
    assert.ok(bodies.length <= 1, c.name);
    assert.equal(bodies[0] ?? null, e.settled, c.name);
    if (e.payment_response) assert.equal(web.decodeHeaderText(res.headers.get("PAYMENT-RESPONSE")), e.payment_response, c.name);
    if (res.status === 402) {
      const required = web.decodeHeaderText(res.headers.get("PAYMENT-REQUIRED"));
      assert.equal(JSON.parse(required).error ?? null, e.error, c.name);
      assert.equal(res.headers.get("content-type"), "application/json");
      if (e.error === null) assert.equal(normalized(required), G.required_body, c.name);
    }
  }
});

test("the licence document and route matching match the shared vectors", () => {
  assert.equal(web.rslXml(G.policy, G.origin), G.rsl_xml);
  assert.equal(web.robotsLicenseLine(G.origin), G.robots_line);
  for (const [p, want] of G.matches) assert.equal(web.matchRoute(G.policy.routes, p)?.path ?? null, want, p);
});

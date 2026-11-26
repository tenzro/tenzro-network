import test from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import type { AddressInfo } from "node:net";
import React from "react";
import { render } from "ink-testing-library";
import { App } from "../src/app.js";
import type { Source } from "../src/data.js";
import type { Helper } from "../src/helper.js";
import { makeTheme } from "../src/theme.js";
import { MAX_WITNESSES, WITNESS_MAX_BYTES, chooseWitnesses, fetchAsk, witnessCheck, type Ask } from "../src/witness.js";
import { healthy, PAYEE, sourceOf } from "./fixtures.js";

const listed = (n: number) => Array.from({ length: n }, (_, i) => ({ account: `0x0${i}`, url: `https://op${i}.example/` }));

/** Answers per host: what each read returns, or "silent". */
function fakeAsk(views: Record<string, { syncing?: unknown; peers?: string; finalized?: string } | "silent">, asked: [string, string][] = []): Ask {
  return async (url, method) => {
    asked.push([url, method]);
    const v = views[new URL(url).hostname];
    if (!v || v === "silent") throw new Error("timeout");
    if (method === "eth_syncing") return v.syncing ?? false;
    if (method === "net_peerCount") return v.peers ?? "0x5";
    return v.finalized ?? "0x12d680";
  };
}

test("only endpoints the chain lists are asked: no credentials, no other schemes, not this node, at most three", () => {
  const urls = chooseWitnesses(
    [
      { account: "0x09", url: "https://late.example" },
      { account: PAYEE.toUpperCase().replace("0X", "0x"), url: "https://self.example" },
      { account: "0x01", url: "https://user:secret@creds.example" },
      { account: "0x02", url: "ftp://files.example" },
      { account: "0x03", url: "not a url" },
      { account: "0x04", url: "https://a.example/rpc" },
      { account: "0x05", url: "https://a.example/other" },
      { account: "0x06", url: "http://b.example:8545" },
      { account: "0x07", url: "https://c.example" },
    ],
    PAYEE,
  );
  assert.deepEqual(urls, ["https://a.example/rpc", "http://b.example:8545/", "https://c.example/"]);
  assert.equal(urls.length, MAX_WITNESSES);
});

test("the reads are the open ones any client makes, and nothing else is sent", async () => {
  const asked: [string, string][] = [];
  await witnessCheck(listed(2), healthy(), fakeAsk({ "op0.example": {}, "op1.example": {} }, asked));
  assert.deepEqual([...new Set(asked.map(([, m]) => m))].sort(), ["eth_syncing", "net_peerCount", "tenzro_getFinalizedBlock"]);
  assert.equal(asked.length, 6);
});

test("a majority of the operators that answer must see a healthy network at this node's tip", async () => {
  const snap = healthy(); // finalized 1234560 = 0x12d680
  const tip = {};
  const far = { finalized: "0x100000" };
  const run = async (views: Parameters<typeof fakeAsk>[0]) => (await witnessCheck(listed(3), snap, fakeAsk(views))).check;

  const all = await run({ "op0.example": tip, "op1.example": tip, "op2.example": tip });
  assert.equal(all.ok, true);
  assert.match(all.text, /3 of the 3 other operators that answered \(3 asked\)/);

  assert.equal((await run({ "op0.example": tip, "op1.example": tip, "op2.example": far })).ok, true);
  assert.equal((await run({ "op0.example": tip, "op1.example": far, "op2.example": far })).ok, false);
  assert.equal((await run({ "op0.example": tip, "op1.example": { syncing: { currentBlock: "0x1" } }, "op2.example": "silent" })).ok, false, "one of two is not a majority");
  assert.equal((await run({ "op0.example": tip, "op1.example": "silent", "op2.example": "silent" })).ok, true, "the one that answered agrees");
  assert.equal((await run({ "op0.example": { peers: "0x0" }, "op1.example": "silent", "op2.example": "silent" })).ok, false);

  const none = await run({});
  assert.equal(none.ok, false);
  assert.match(none.text, /None of the 3 other operators asked answered/);

  const alone = await witnessCheck([{ account: PAYEE, url: "https://self.example" }], snap, fakeAsk({}));
  assert.equal(alone.check.ok, true);
  assert.match(alone.check.text, /nobody to ask/);
});

test("an answer is held to a size, and a redirect is not followed", async () => {
  const server = http.createServer((req, res) => {
    if (req.url === "/big") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ jsonrpc: "2.0", id: 1, result: "x".repeat(WITNESS_MAX_BYTES * 4) }));
    } else if (req.url === "/away") {
      res.writeHead(302, { Location: "/ok" });
      res.end();
    } else {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ jsonrpc: "2.0", id: 1, result: "0x10" }));
    }
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
  try {
    assert.equal(await fetchAsk(`${base}/ok`, "net_peerCount"), "0x10");
    await assert.rejects(fetchAsk(`${base}/big`, "net_peerCount"));
    await assert.rejects(fetchAsk(`${base}/away`, "net_peerCount"));
  } finally {
    await new Promise<void>((r) => server.close(() => r()));
  }
});

test("a stop the other operators do not support is blocked, and they are not asked when this node's own checks fail", async () => {
  const tick = (ms = 80) => new Promise((res) => setTimeout(res, ms));
  const provider = () => {
    const s = healthy();
    if (s.status.state !== "ok") throw new Error("fixture");
    return { ...s, status: { ...s.status, value: { ...s.status.value, roles: ["Provider"] } } };
  };
  let asked = 0;
  const calls: string[] = [];
  const helper: Helper = { path: "x", call: async (m) => (calls.push(m), {} as never) };
  const withWitnesses = (snap: () => ReturnType<typeof healthy>): Source => ({
    ...sourceOf(snap),
    witnesses: async () => {
      asked++;
      return { id: "peers", ok: false, text: "1 of the 3 other operators that answered (3 asked) see a healthy network at this node's tip." };
    },
  });
  const show = (src: Source) => render(<App source={src} helper={helper} theme={makeTheme(false)} initialAccount={null} refreshMs={60000} size={{ columns: 120, rows: 30 }} />);
  const txt = (r: ReturnType<typeof show>) => (r.lastFrame() ?? "").replace(/\u001b\[[0-9;]*m/g, "");

  const r = show(withWitnesses(provider));
  await tick();
  r.stdin.write("S");
  await tick(150);
  assert.match(txt(r), /NO\s+1 of the 3 other operators/);
  assert.match(txt(r), /The stop is blocked/);
  assert.equal(asked, 1);
  r.unmount();

  // A validator the set cannot spare: blocked on its own count, and nobody else is asked.
  const v = show(withWitnesses(healthy));
  await tick();
  v.stdin.write("S");
  await tick(150);
  assert.match(txt(v), /The stop is blocked/);
  assert.equal(asked, 1);
  assert.deepEqual(calls, []);
  v.unmount();
});

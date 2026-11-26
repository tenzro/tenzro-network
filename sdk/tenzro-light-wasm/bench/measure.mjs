// Measures both certificate paths of the WebAssembly light client against a
// node: following the handovers from a trusted committee, then accepting one
// checkpoint by its compact certificate (the first of an epoch builds the
// proof set-up) and by its quorum certificate.
//
//   node bench/measure.mjs --rpc https://rpc.tenzro.com --chain 13380 \
//     --genesis <hex> --epoch <n> --committee-root <hex> [--max-age-secs 3600]
import { createRequire } from "node:module";
import { performance } from "node:perf_hooks";

const require = createRequire(import.meta.url);
const { LightClient } = require("../pkg/tenzro_light_wasm.js");

const arg = (name, fallback) => {
  const i = process.argv.indexOf(`--${name}`);
  if (i < 0 && fallback === undefined) throw new Error(`--${name} is required`);
  return i < 0 ? fallback : process.argv[i + 1];
};
const rpc = arg("rpc");
let id = 0;
async function call(method, paramsJson) {
  const res = await fetch(rpc, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ jsonrpc: "2.0", id: ++id, method, params: JSON.parse(paramsJson) }),
  });
  const body = await res.json();
  if (body.error) throw new Error(`${method}: ${body.error.message}`);
  return JSON.stringify(body.result);
}

const epoch = BigInt(arg("epoch"));
const clock = () => [BigInt(Date.now()), BigInt(arg("max-age-secs", "3600")) * 1000n, 30_000n];
const time = async (label, f) => {
  const t = performance.now();
  const out = await f();
  console.log(`${label}: ${(performance.now() - t).toFixed(1)} ms`);
  return out;
};

const committee = await call("tenzro_getCommittee", JSON.stringify([Number(epoch)]));
const lc = await time("committee held to its root", () =>
  new LightClient(call, BigInt(arg("chain")), arg("genesis"), epoch, arg("committee-root"), committee),
);
const newest = JSON.parse(await call("tenzro_getCheckpointCertificate", "{}"));
await time(`follow the handovers to epoch ${newest.epoch}`, () => lc.follow(BigInt(newest.epoch)));

// Both paths on one checkpoint: the newest compact certificate, and the
// quorum certificate of the same index, each on a client at the same epoch.
const compactReply = await call("tenzro_getCompactCertificate", "[]");
const twin = LightClient.restore(call, lc.save(), BigInt(arg("chain")), arg("genesis"), 0n);
const compact = JSON.parse(
  await time("compact certificate, first of the epoch (builds the set-up)", () =>
    twin.advance_compact(compactReply, ...clock()),
  ),
);
const quorumReply = await call("tenzro_getCheckpointCertificate", JSON.stringify([compact.index]));
await time(`quorum certificate of the same checkpoint ${compact.index}`, () => lc.advance(quorumReply, ...clock()));

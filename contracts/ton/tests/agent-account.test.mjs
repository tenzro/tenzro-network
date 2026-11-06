// SPDX-License-Identifier: Apache-2.0
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { createChain } from './chain.mjs';
import { beginCell, Cell, contractAddress, toNano } from '@ton/core';
import { compileFunc } from '@ton-community/func-js';
import { p256 } from '@noble/curves/p256';
import { sha256 } from '@noble/hashes/sha256';

const dir = path.dirname(new URL(import.meta.url).pathname);
const read = (f) => fs.readFileSync(path.join(dir, '../contracts', f), 'utf8');
const vectors = JSON.parse(fs.readFileSync(path.join(dir, '../../../sdk/fixtures/remote_grant/vectors.json'), 'utf8'));
const finalityCode = Cell.fromBase64(fs.readFileSync(path.join(dir, '../build/finality.code.boc.b64'), 'utf8'));
const wrapped = JSON.parse(fs.readFileSync(path.join(dir, 'fixtures/bls_wrap_proof.json'), 'utf8'));

const DID = Buffer.from('did:tenzro:machine:vectors:agent');
const CAIP2 = Buffer.from('tvm:-239');
const ASSET = Buffer.from('tvm:-239/slip44:607');
const OP_STATE_ROOT = 0x2b7f4c93;
const OP_SYNC = 0x5c3e1a77;
const OP_ACT = 0x3a6d0b21;
const OP_ACT_EXACT = 0x7e19c4d5;
const OP_REPORT = 0x6a2d9e15;
const OPS = ['did:tenzro:human:operator-a', 'did:tenzro:human:operator-b', 'did:tenzro:human:operator-a'];
const KEYS = [0x11, 0x22, 0x33].map((b) => new Uint8Array(32).fill(b));
const H = (...parts) => Buffer.from(sha256(Buffer.concat(parts.map((p) => Buffer.from(p)))));
const big = (b) => BigInt('0x' + Buffer.from(b).toString('hex'));
const be = (v, n) => {
  const out = Buffer.alloc(n);
  let x = BigInt(v);
  for (let i = n - 1; i >= 0; i--) { out[i] = Number(x & 0xffn); x >>= 8n; }
  return out;
};

/** The grant's state tree key: VM system storage keyed by the hex of `agent_grant:did:caip2`. */
function treeKey() {
  const key = Buffer.concat([Buffer.from('agent_grant:'), DID, Buffer.from(':'), CAIP2]).toString('hex');
  return H('tenzro.state-trie.key', Buffer.from([5, 0]), 'state', 'storage:' + 'f'.repeat(40) + ':', key);
}

const pair = (a, b) => (Buffer.compare(a, b) <= 0 ? H([1], a, b) : H([1], b, a));
const leaves = KEYS.map((k, i) => H([0], p256.getPublicKey(k, false), OPS[i]));
const n01 = pair(leaves[0], leaves[1]);
const KEYS_ROOT = pair(n01, leaves[2]);
const KEY_PROOFS = [[leaves[1], leaves[2]], [leaves[0], leaves[2]], [n01]];

async function compileAccount(finalityId) {
  const config = `const int FINALITY = 0x${finalityId.toString(16)};\nconst int CHAIN = 0x${H(CAIP2).toString('hex')};\nconst int ASSET = 0x${H(ASSET).toString('hex')};\n`;
  const targets = ['prelude.fc', 'state-proof.fc', 'config.fc', 'agent-account.fc'];
  const sources = { 'prelude.fc': read('prelude.fc'), 'state-proof.fc': read('state-proof.fc'), 'config.fc': config, 'agent-account.fc': read('agent-account.fc') };
  const r = await compileFunc({ targets, sources });
  if (r.status === 'error') throw new Error(r.message);
  return Cell.fromBase64(r.codeBoc);
}

/** A stand-in finality client: forwards whatever root it is told to the account, as the real one reports. */
async function compileReporter() {
  const src = `
() recv_internal(int balance, int value, cell in_msg, slice body) impure {
  if (body.slice_empty?()) { return (); }
  slice to = body~load_msg_addr();
  int index = body~load_uint(64);
  int root = body~load_uint(256);
  cell payload = body~load_ref();
  send_raw_message(begin_cell().store_uint(0x10, 6).store_slice(to).store_coins(0).store_uint(0, 1 + 4 + 4 + 64 + 32 + 1).store_uint(1, 1)
    .store_ref(begin_cell().store_uint(${OP_STATE_ROOT}, 32).store_uint(0, 64).store_uint(index, 64).store_uint(root, 256).store_uint(0, 64).store_ref(payload).end_cell())
    .end_cell(), 64);
}`;
  const r = await compileFunc({ targets: ['prelude.fc', 'r.fc'], sources: { 'prelude.fc': read('prelude.fc'), 'r.fc': src } });
  if (r.status === 'error') throw new Error(r.message);
  return Cell.fromBase64(r.codeBoc);
}

function grantBytes(t, { seq = 1, voided = false, payload = Buffer.alloc(32), targetsRoot = Buffer.alloc(32) } = {}) {
  return Buffer.concat([
    Buffer.from([1]), H(CAIP2), t.accountId, H(DID), be(1, 8), be(seq, 8), be(t.now - 1000, 8), be(t.now + 600000, 8),
    H(ASSET), be(toNano('10'), 16), be(toNano('4'), 16), be(toNano('3'), 16), KEYS_ROOT, targetsRoot, payload,
    be(toNano('0.1'), 16), Buffer.from([voided ? 1 : 0]),
  ]);
}

/** The grant as cells at its field boundaries (97, 112 and 113 bytes). */
function grantCell(g) {
  const c = beginCell().storeBuffer(g.subarray(209)).endCell();
  return beginCell().storeBuffer(g.subarray(0, 97)).storeRef(beginCell().storeBuffer(g.subarray(97, 209)).storeRef(c).endCell()).endCell();
}

function chain(words, per = 3) {
  let next = null;
  for (let i = Math.ceil(words.length / per) - 1; i >= 0; i--) {
    const b = beginCell();
    for (const w of words.slice(i * per, i * per + per)) b.storeBuffer(w);
    if (next) b.storeRef(next);
    next = b.endCell();
  }
  return next ?? beginCell().endCell();
}

/** The root of a tree whose only entry is `value` at `tk`, and its proof as cells. */
function single(tk, value) {
  let s = H([0], value);
  for (let i = 0; i < 8; i++) {
    s = ((tk[31] >> i) & 1) === 0 ? H([3], s, Buffer.alloc(32)) : H([3], Buffer.alloc(32), s);
  }
  const root = H([2], tk.subarray(0, 31), s);
  const proof = beginCell().storeUint(0, 16).storeRef(beginCell().endCell()).storeRef(chain(Array(8).fill(Buffer.alloc(32)))).endCell();
  return { root, proof };
}

async function setup() {
  const chainSim = await createChain();
  const now = 1_800_000_001_000;
  chainSim.now = Math.floor(now / 1000);
  const reporterCode = await compileReporter();
  const reporterInit = { code: reporterCode, data: beginCell().endCell() };
  const reporter = contractAddress(0, reporterInit);
  const relayer = await chainSim.treasury('relayer');
  await relayer.send({ to: reporter, value: toNano('1'), init: reporterInit });
  const code = await compileAccount(big(reporter.hash));
  const data = beginCell().storeBuffer(H(DID)).storeBuffer(treeKey()).endCell();
  const init = { code, data };
  const account = contractAddress(0, init);
  await relayer.send({ to: account, value: toNano('100'), init, body: beginCell().endCell() });
  return { chainSim, relayer, reporter, account, accountId: Buffer.from(account.hash), code, now };
}

async function install(t, g, index = 1) {
  const { root, proof } = single(treeKey(), g);
  const payload = beginCell().storeUint(OP_SYNC, 32).storeBuffer(Buffer.alloc(32, 7)).storeRef(grantCell(g)).storeRef(proof).endCell();
  const r = await t.relayer.send({
    to: t.reporter, value: toNano('0.5'),
    body: beginCell().storeAddress(t.account).storeUint(index, 64).storeBuffer(root).storeRef(payload).endCell(),
  });
  return r.transactions.find((x) => x.inMessage?.info.dest?.equals?.(t.account));
}

function actionBytes(targetId, amount, refund, selector = Buffer.alloc(0)) {
  return Buffer.concat([be(32, 2), targetId, be(selector.length, 2), selector, be(amount, 16), be(refund, 16), be(0, 4)]);
}

function digestOf(t, action, seq, nonce) {
  return H('tenzro/agent-act/v1', H(CAIP2), t.accountId, be(seq, 8), be(nonce, 8), action);
}

function signer(i, digest, highS = false) {
  // TVM checks a P-256 signature over the SHA-256 of the 32-byte digest.
  let sig = p256.sign(digest, KEYS[i], { prehash: true, lowS: true });
  if (highS) sig = new p256.Signature(sig.r, p256.CURVE.n - sig.s);
  const pub = p256.getPublicKey(KEYS[i], false);
  return beginCell().storeUint(sig.r, 256).storeUint(sig.s, 256)
    .storeRef(beginCell().storeBuffer(Buffer.from(pub.subarray(1))).endCell())
    .storeRef(beginCell().storeBuffer(Buffer.from(OPS[i])).endCell())
    .storeRef(chain(KEY_PROOFS[i]))
    .endCell();
}

async function act(t, action, signers, targetProof = null) {
  const list = signers.reduceRight((acc, s) => beginCell().storeRef(s).storeSlice(acc.beginParse()).endCell(), beginCell().endCell());
  const body = beginCell().storeUint(OP_ACT, 32).storeRef(beginCell().storeBuffer(action).endCell());
  if (targetProof) body.storeRef(targetProof);
  body.storeRef(list);
  const r = await t.relayer.send({ to: t.account, value: toNano('0.5'), body: body.endCell() });
  return r.transactions.find((x) => x.inMessage?.info.dest?.equals?.(t.account));
}

const exitCode = (tx) => tx.description.computePhase.exitCode;
const target = Buffer.alloc(32, 0xaa);

test('the account is where Tenzro derives it', async () => {
  const t = await setup();
  // Tenzro's derivation: the StateInit hash from the code's hash and depth.
  const dataHash = H([0, 128], H(DID), treeKey());
  const code = t.code;
  const expected = H([2, 1, 0x34], be(code.depth(), 2), be(0, 2), code.hash(), dataHash);
  assert.deepEqual(expected, t.accountId);
  const c = vectors.chains.find((c) => c.chain === 'tvm:-239');
  assert.equal(c.tree_key, treeKey().toString('hex'));
  const vh = H([2, 1, 0x34], be(1, 2), be(0, 2), Buffer.alloc(32, 0x99), H([0, 128], H(DID), treeKey()));
  assert.equal(c.account_raw, vh.toString('hex'));
});

test('a synced grant lets a signed action send TON, once', async () => {
  const t = await setup();
  const tx = await install(t, grantBytes(t));
  assert.equal(exitCode(tx), 0);
  console.log(`sync gas: ${tx.description.computePhase.gasUsed}`);
  const a = actionBytes(target, toNano('1'), toNano('0.05'));
  const d = digestOf(t, a, 1, 0);
  const onChain = (await t.chainSim.runGetMethod(t.account, 'get_action_digest', [{ type: 'cell', cell: beginCell().storeBuffer(a).endCell() }])).stackReader.readBigNumber();
  assert.equal(onChain, big(d));
  const r = await act(t, a, [signer(0, d)]);
  assert.equal(exitCode(r), 0);
  console.log(`act gas: ${r.description.computePhase.gasUsed}`);
  assert.equal((await t.chainSim.runGetMethod(t.account, 'get_nonce')).stackReader.readBigNumber(), 1n);
  assert.equal((await t.chainSim.runGetMethod(t.account, 'get_spent')).stackReader.readBigNumber(), toNano('1'));
  assert.notEqual(exitCode(await act(t, a, [signer(0, d)])), 0, 'a replay');
});

test('every rule of the grant holds', async () => {
  const t = await setup();
  await install(t, grantBytes(t));
  const a = actionBytes(target, toNano('1'), 0n);
  const d = digestOf(t, a, 1, 0);
  assert.equal(exitCode(await act(t, a, [signer(0, d, true)])), 413);
  assert.equal(exitCode(await act(t, a, [signer(1, digestOf(t, a, 1, 5))])), 414);
  const over = actionBytes(target, toNano('4.1'), 0n);
  assert.equal(exitCode(await act(t, over, [signer(0, digestOf(t, over, 1, 0))])), 418);
  const refund = actionBytes(target, toNano('1'), toNano('0.2'));
  assert.equal(exitCode(await act(t, refund, [signer(0, digestOf(t, refund, 1, 0))])), 420);
  const bigA = actionBytes(target, toNano('3.5'), 0n);
  const bd = (n) => digestOf(t, bigA, 1, n);
  assert.equal(exitCode(await act(t, bigA, [signer(0, bd(0))])), 416);
  assert.equal(exitCode(await act(t, bigA, [signer(0, bd(0)), signer(2, bd(0))])), 416);
  assert.equal(exitCode(await act(t, bigA, [signer(0, bd(0)), signer(1, bd(0))])), 0);
  assert.equal(exitCode(await act(t, bigA, [signer(0, bd(1)), signer(1, bd(1))])), 0);
  assert.equal(exitCode(await act(t, bigA, [signer(0, bd(2)), signer(1, bd(2))])), 419);
});

test('a void stops actions, a stale grant is refused, only the finality client reports', async () => {
  const t = await setup();
  await install(t, grantBytes(t));
  assert.equal(exitCode(await install(t, grantBytes(t, { voided: true }), 2)), 0);
  const a = actionBytes(target, toNano('1'), 0n);
  assert.equal(exitCode(await act(t, a, [signer(0, digestOf(t, a, 1, 0))])), 407);
  assert.equal(exitCode(await install(t, grantBytes(t), 3)), 404);
  // A report from anyone else.
  const r = await t.relayer.send({
    to: t.account, value: toNano('0.2'),
    body: beginCell().storeUint(OP_STATE_ROOT, 32).storeUint(0, 64).storeUint(1, 64).storeUint(0, 256).storeUint(0, 64).storeRef(beginCell().endCell()).endCell(),
  });
  assert.equal(exitCode(r.transactions.find((x) => x.inMessage?.info.dest?.equals?.(t.account))), 400);
});

test('targets and time hold', async () => {
  const t = await setup();
  const leaf = H([0], be(32, 2), target, be(0, 2));
  const other = H([0], be(32, 2), Buffer.alloc(32, 0xbb), be(0, 2));
  await install(t, grantBytes(t, { targetsRoot: pair(leaf, other) }));
  const a = actionBytes(target, toNano('1'), 0n);
  const d = digestOf(t, a, 1, 0);
  assert.equal(exitCode(await act(t, a, [signer(0, d)], chain([Buffer.alloc(32, 1)]))), 417);
  assert.equal(exitCode(await act(t, a, [signer(0, d)], chain([other]))), 0);
  t.chainSim.now = Math.floor((t.now + 600_001) / 1000) + 1;
  const a2 = actionBytes(target, toNano('1'), 0n);
  assert.equal(exitCode(await act(t, a2, [signer(0, digestOf(t, a2, 1, 1))], chain([other]))), 408);
});

test('an exact grant runs its action once', async () => {
  const t = await setup();
  const a = actionBytes(target, toNano('1'), 0n);
  await install(t, grantBytes(t, { payload: H(a) }));
  const send = () => t.relayer.send({ to: t.account, value: toNano('0.3'), body: beginCell().storeUint(OP_ACT_EXACT, 32).storeRef(beginCell().storeBuffer(a).endCell()).endCell() });
  const before = (await t.chainSim.getContract(t.account)).balance;
  const first = (await send()).transactions.find((x) => x.inMessage?.info.dest?.equals?.(t.account));
  assert.equal(exitCode(first), 0);
  const after = (await t.chainSim.getContract(t.account)).balance;
  assert.ok(before - after >= toNano('1') - toNano('0.3'), 'the account paid the target');
  const second = (await send()).transactions.find((x) => x.inMessage?.info.dest?.equals?.(t.account));
  assert.equal(exitCode(second), 411);
});

test('the real finality client reports to the account', async () => {
  const chainSim = await createChain();
  const g = (s) => beginCell().storeBuffer(Buffer.from(s, 'hex')).endCell();
  const vk = wrapped.vk;
  const vkCell = beginCell().storeBuffer(Buffer.from(vk.alpha, 'hex')).storeBuffer(Buffer.from(vk.ic[0], 'hex'))
    .storeRef(g(vk.beta)).storeRef(g(vk.gamma)).storeRef(g(vk.delta))
    .storeRef(beginCell().storeBuffer(Buffer.from(vk.ic[1], 'hex')).storeBuffer(Buffer.from(vk.ic[2], 'hex'))
      .storeRef(g(vk.ic[3])).storeRef(g(vk.commitment_g)).storeRef(g(vk.commitment_g_sigma_neg)).endCell())
    .endCell();
  const { Dictionary } = await import('@ton/core');
  const committees = Dictionary.empty(Dictionary.Keys.BigUint(64), Dictionary.Values.BigUint(256));
  committees.set(0n, BigInt('0xf17b383633cfd64f3bf43b34394ee538096a722322bb16144d845acd28e6e481'));
  const fdata = beginCell().storeUint(BigInt('0x' + wrapped.proof.image_id), 256).storeUint(1337, 64).storeUint(BigInt('0x' + '6e'.repeat(32)), 256)
    .storeUint(0, 64).storeRef(vkCell).storeDict(committees).storeDict(null).endCell();
  const finit = { code: finalityCode, data: fdata };
  const finality = contractAddress(0, finit);
  const relayer = await chainSim.treasury('relayer');
  await relayer.send({ to: finality, value: toNano('1'), init: finit });
  const j = Buffer.from(wrapped.proof.journal, 'hex');
  const words = [0, 3, 6, 9, 12, 13].map((w) => w * 32);
  let jc = null;
  for (let i = 4; i >= 0; i--) {
    const b = beginCell().storeBuffer(j.subarray(words[i], words[i + 1]));
    if (jc) b.storeRef(jc);
    jc = b.endCell();
  }
  const p = wrapped.proof;
  const seal = beginCell().storeBuffer(Buffer.from(p.a, 'hex')).storeBuffer(Buffer.from(p.c, 'hex'))
    .storeRef(beginCell().storeBuffer(Buffer.from(p.b, 'hex')).endCell())
    .storeRef(beginCell().storeBuffer(Buffer.from(p.commitment, 'hex')).storeBuffer(Buffer.from(p.commitment_pok, 'hex')).endCell()).endCell();
  await relayer.send({ to: finality, value: toNano('1'), body: beginCell().storeUint(0x4f1c3b7a, 32).storeUint(0, 64).storeRef(jc).storeRef(seal).endCell() });
  const code = await compileAccount(big(finality.hash));
  const init = { code, data: beginCell().storeBuffer(H(DID)).storeBuffer(treeKey()).endCell() };
  const account = contractAddress(0, init);
  await relayer.send({ to: account, value: toNano('1'), init, body: beginCell().endCell() });
  // The checkpoint's root holds no grant of this agent: the report arrives
  // from the client and the proof is what refuses it.
  const { proof } = single(treeKey(), Buffer.alloc(322));
  const payload = beginCell().storeUint(OP_SYNC, 32).storeBuffer(Buffer.alloc(32)).storeRef(grantCell(Buffer.concat([Buffer.from([1]), Buffer.alloc(321)]))).storeRef(proof).endCell();
  const r = await relayer.send({ to: finality, value: toNano('0.5'), body: beginCell().storeUint(OP_REPORT, 32).storeUint(1, 64).storeUint(7, 64).storeAddress(account).storeRef(payload).endCell() });
  const tx = r.transactions.find((x) => x.inMessage?.info.dest?.equals?.(account));
  assert.equal(exitCode(tx), 402);
});

test('a call action locks a settlement leg with exactly its amount, the account as payer', async () => {
  const t = await setup();
  await install(t, grantBytes(t));
  const lockCode = Cell.fromBase64(fs.readFileSync(path.join(dir, '../build/settlement-lock.code.boc.b64'), 'utf8'));
  const lockData = beginCell().storeBuffer(Buffer.from(t.reporter.hash)).storeUint(3600, 64)
    .storeUint(0, 256).storeUint(0, 256).storeDict(null).storeRef(beginCell().storeUint(0, 64).storeUint(0, 256).endCell()).endCell();
  const lockInit = { code: lockCode, data: lockData };
  const lock = contractAddress(0, lockInit);
  await t.relayer.send({ to: lock, value: toNano('1'), init: lockInit });
  const plan = 0x0707n;
  const recipient = Buffer.alloc(32, 0xcc);
  const callBody = beginCell().storeUint(0x1e7c9a52, 32).storeUint(0, 64).storeUint(plan, 256).storeUint(0, 8)
    .storeCoins(toNano('1')).storeBuffer(recipient).endCell();
  const amount = toNano('1.1');
  const sel = Buffer.from('call');
  const a = Buffer.concat([be(32, 2), Buffer.from(lock.hash), be(sel.length, 2), sel, be(amount, 16), be(0, 16), be(32, 4), callBody.hash()]);
  const sendCall = async (nonce, body) => {
    const list = beginCell().storeRef(signer(0, digestOf(t, a, 1, nonce))).endCell();
    return t.relayer.send({
      to: t.account, value: toNano('0.5'),
      body: beginCell().storeUint(OP_ACT, 32).storeRef(beginCell().storeBuffer(a).endCell()).storeRef(list).storeRef(body).endCell(),
    });
  };
  // Another body than the signed one: refused.
  const other = beginCell().storeUint(0x1e7c9a52, 32).storeUint(0, 64).storeUint(plan, 256).storeUint(0, 8)
    .storeCoins(toNano('1')).storeBuffer(Buffer.alloc(32, 0xdd)).endCell();
  let r = await sendCall(0, other);
  assert.equal(exitCode(r.transactions.find((x) => x.inMessage?.info.dest?.equals?.(t.account))), 412);
  r = await sendCall(0, callBody);
  assert.equal(exitCode(r.transactions.find((x) => x.inMessage?.info.dest?.equals?.(t.account))), 0);
  const toLock = r.transactions.find((x) => x.inMessage?.info.dest?.equals?.(lock));
  assert.equal(toLock.inMessage.info.value.coins, amount);
  assert.equal(exitCode(toLock), 0);
  const leg = (await t.chainSim.runGetMethod(lock, 'get_leg', [{ type: 'int', value: plan }, { type: 'int', value: 0n }])).stackReader;
  assert.equal(leg.readBigNumber(), 1n);
  assert.equal(leg.readBigNumber(), big(t.accountId));
  assert.equal(leg.readBigNumber(), big(recipient));
  assert.equal(leg.readBigNumber(), toNano('1'));
  assert.equal((await t.chainSim.runGetMethod(t.account, 'get_spent')).stackReader.readBigNumber(), amount);
});

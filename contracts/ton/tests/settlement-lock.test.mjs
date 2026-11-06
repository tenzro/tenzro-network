// SPDX-License-Identifier: Apache-2.0
// The settlement lock on the shared vectors (sdk/fixtures/settlement_lock):
// TON and jetton legs, settled on decisions a finality client reports.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { createChain } from './chain.mjs';
import { beginCell, Cell, contractAddress, toNano } from '@ton/core';
import { compileFunc } from '@ton-community/func-js';

const dir = path.dirname(new URL(import.meta.url).pathname);
const read = (f) => fs.readFileSync(path.join(dir, '../contracts', f), 'utf8');
const v = JSON.parse(fs.readFileSync(path.join(dir, '../../../sdk/fixtures/settlement_lock/vectors.json'), 'utf8'));
const walletCode = Cell.fromBase64(fs.readFileSync(path.join(dir, '../build/jetton-wallet.code.boc.b64'), 'utf8'));
const lockCode = Cell.fromBase64(fs.readFileSync(path.join(dir, '../build/settlement-lock.code.boc.b64'), 'utf8'));

const OP_STATE_ROOT = 0x2b7f4c93;
const OP_LOCK = 0x1e7c9a52;
const OP_LEARN_WALLET = 0x3d5f8b11;
const OP_ESCAPE = 0x6b2e0f47;
const OP_TRANSFER = 0x0f8a7ea5;
const OP_INTERNAL_TRANSFER = 0x178d4519;
const OP_TAKE_WALLET_ADDRESS = 0xd1735400;
const HORIZON = 14 * 24 * 3600;
const NOW = 1_800_000_000;
const CHECKPOINT = 7n;

const raw = (h) => Buffer.from(h.replace(/^0x/, ''), 'hex');
const big = (b) => BigInt('0x' + Buffer.from(b).toString('hex'));
const exitCode = (tx) => tx.description.computePhase.exitCode;
const plan = (which) => big(raw(v[which].plan_id));

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

/** A binary state proof as the cells the lock reads. */
function proofCell(hex) {
  const p = raw(hex);
  const depth = p.readUInt16BE(0);
  const words = (from, n) => Array.from({ length: n }, (_, i) => p.subarray(from + 32 * i, from + 32 * i + 32));
  const t = 2 + 32 * depth;
  assert.equal(p[t], 2);
  return beginCell().storeUint(depth, 16).storeRef(chain(words(2, depth))).storeRef(chain(words(t + 1, 8))).endCell();
}

/** A stand-in finality client: forwards whatever root it is told, as the real one reports. */
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

function walletInit(owner, master) {
  return { code: walletCode, data: beginCell().storeCoins(0).storeAddress(owner).storeAddress(master).storeRef(walletCode).endCell() };
}

async function setup({ jetton = false } = {}) {
  const sim = await createChain();
  sim.now = NOW;
  const relayer = await sim.treasury('relayer');
  const payer = await sim.treasury('payer');
  const recipient = await sim.treasury('recipient');
  const master = await sim.treasury('master');
  const reporterInit = { code: await compileReporter(), data: beginCell().endCell() };
  const reporter = contractAddress(0, reporterInit);
  await relayer.send({ to: reporter, value: toNano('1'), init: reporterInit });
  const data = beginCell().storeBuffer(Buffer.from(reporter.hash)).storeUint(HORIZON, 64)
    .storeUint(jetton ? big(master.address.hash) : 0n, 256).storeUint(0, 256).storeDict(null).storeRef(beginCell().storeUint(0, 64).storeUint(0, 256).endCell()).endCell();
  const init = { code: lockCode, data };
  const lock = contractAddress(0, init);
  await relayer.send({ to: lock, value: toNano('10'), init });
  return { sim, relayer, payer, recipient, master, reporter, lock };
}

async function lockTon(t, which, index, amount, value = amount + toNano('0.1')) {
  const r = await t.payer.send({
    to: t.lock, value,
    body: beginCell().storeUint(OP_LOCK, 32).storeUint(0, 64).storeUint(plan(which), 256).storeUint(index, 8)
      .storeCoins(amount).storeBuffer(Buffer.from(t.recipient.address.hash)).endCell(),
  });
  return r.transactions.find((x) => x.inMessage?.info.dest?.equals?.(t.lock));
}

/** Ask the reporter to deliver `root` with the decision and proof of `proofOf` for leg `index` of `which`. */
async function settle(t, which, index, proofOf, { root = raw(v.root), decision = raw(v[proofOf].decision), via = t.reporter } = {}) {
  const payload = beginCell().storeUint(plan(which), 256).storeUint(index, 8)
    .storeRef(beginCell().storeBuffer(decision).endCell()).storeRef(proofCell(v[proofOf].proof)).endCell();
  const body = via === t.reporter
    ? beginCell().storeAddress(t.lock).storeUint(CHECKPOINT, 64).storeBuffer(root).storeRef(payload).endCell()
    : beginCell().storeUint(OP_STATE_ROOT, 32).storeUint(0, 64).storeUint(CHECKPOINT, 64).storeBuffer(root).storeUint(0, 64).storeRef(payload).endCell();
  const r = await t.relayer.send({ to: via, value: toNano('0.5'), body });
  return r;
}

const lockTx = (t, r) => r.transactions.find((x) => x.inMessage?.info.dest?.equals?.(t.lock));

async function leg(t, which, index) {
  const r = await t.sim.provider(t.lock).get('get_leg', [{ type: 'int', value: plan(which) }, { type: 'int', value: BigInt(index) }]);
  return { stage: r.stack.readNumber(), payer: r.stack.readBigNumber(), recipient: r.stack.readBigNumber(), amount: r.stack.readBigNumber(), escapeAt: r.stack.readNumber() };
}

function payoutTo(t, r, to) {
  return r.transactions.find((x) => x.inMessage?.info.dest?.equals?.(to) && x.inMessage.info.src?.equals?.(t.lock))?.inMessage.info.value.coins;
}

test('leg ids and the decision key are Tenzro\'s', async () => {
  const t = await setup();
  const get = async (name, args) => (await t.sim.provider(t.lock).get(name, args.map((value) => ({ type: 'int', value })))).stack.readBigNumber();
  for (const which of ['committed', 'aborted', 'undecided']) {
    for (let i = 0; i < 3; i++) assert.equal(await get('get_leg_id', [plan(which), BigInt(i)]), big(raw(v[which].leg_ids[i])));
    assert.equal(await get('get_decision_tree_key', [plan(which)]), big(raw(v[which].tree_key)));
  }
});

test('the Locked log carries what Tenzro proves', async () => {
  const t = await setup();
  const tx = await lockTon(t, 'committed', 1, toNano('3'));
  assert.equal(exitCode(tx), 0);
  const out = [...tx.outMessages.values()].find((m) => m.info.type === 'external-out');
  const s = out.body.beginParse();
  assert.equal(s.loadUint(8), 0x61);
  assert.equal(s.loadUintBig(256), plan('committed'));
  assert.equal(s.loadUintBig(256), big(raw(v.committed.leg_ids[1])));
  assert.equal(s.loadUint(8), 1);
  assert.equal(s.loadUintBig(256), big(t.payer.address.hash));
  const tail = s.loadRef().beginParse();
  assert.equal(tail.loadUintBig(256), big(t.recipient.address.hash));
  assert.equal(tail.loadCoins(), toNano('3'));
  assert.equal(tail.loadUint(64), NOW + HORIZON);
  assert.equal(tail.loadUintBig(256), 0n);
});

test('a commit pays the recipient once', async () => {
  const t = await setup();
  assert.equal(exitCode(await lockTon(t, 'committed', 2, toNano('3'))), 0);
  const l = await leg(t, 'committed', 2);
  assert.deepEqual([l.stage, l.amount, l.escapeAt], [1, toNano('3'), NOW + HORIZON]);
  assert.equal(l.recipient, big(t.recipient.address.hash));
  const r = await settle(t, 'committed', 2, 'committed');
  assert.equal(exitCode(lockTx(t, r)), 0);
  assert.equal(payoutTo(t, r, t.recipient.address), toNano('3'));
  assert.equal((await leg(t, 'committed', 2)).stage, 2);
  assert.equal(exitCode(lockTx(t, await settle(t, 'committed', 2, 'committed'))), 503);
});

test('an abort refunds the payer', async () => {
  const t = await setup();
  await lockTon(t, 'aborted', 0, toNano('2'));
  const r = await settle(t, 'aborted', 0, 'aborted');
  assert.equal(exitCode(lockTx(t, r)), 0);
  assert.equal(payoutTo(t, r, t.payer.address), toNano('2'));
  assert.equal(payoutTo(t, r, t.recipient.address), undefined);
  assert.equal((await leg(t, 'aborted', 0)).stage, 3);
});

test('a foreign, forged, unanchored or unreported decision moves nothing', async () => {
  const t = await setup();
  await lockTon(t, 'undecided', 1, toNano('1'));
  await lockTon(t, 'committed', 0, toNano('1'));
  assert.equal(exitCode(lockTx(t, await settle(t, 'undecided', 1, 'committed'))), 505);
  const forged = raw(v.committed.decision);
  raw(v.undecided.plan_id).copy(forged, 10);
  assert.equal(exitCode(lockTx(t, await settle(t, 'undecided', 1, 'committed', { decision: forged }))), 505);
  assert.equal(exitCode(lockTx(t, await settle(t, 'committed', 0, 'committed', { root: Buffer.alloc(32, 7) }))), 505);
  // The same report sent by anyone but the finality client.
  assert.equal(exitCode(lockTx(t, await settle(t, 'committed', 0, 'committed', { via: t.lock }))), 500);
  assert.equal((await leg(t, 'undecided', 1)).stage, 1);
  assert.equal((await leg(t, 'committed', 0)).stage, 1);
});

test('an undecided leg escapes only after the horizon', async () => {
  const t = await setup();
  await lockTon(t, 'undecided', 0, toNano('5'));
  const escape = async () => {
    const r = await t.relayer.send({
      to: t.lock, value: toNano('0.2'),
      body: beginCell().storeUint(OP_ESCAPE, 32).storeUint(0, 64).storeUint(plan('undecided'), 256).storeUint(0, 8).endCell(),
    });
    return r;
  };
  t.sim.now = NOW + HORIZON - 1;
  assert.equal(exitCode(lockTx(t, await escape())), 506);
  t.sim.now = NOW + HORIZON;
  const r = await escape();
  assert.equal(exitCode(lockTx(t, r)), 0);
  assert.equal(payoutTo(t, r, t.payer.address), toNano('5'));
  assert.equal(exitCode(lockTx(t, await escape())), 503);
});

test('a leg locks once and brings its payout reserve', async () => {
  const t = await setup();
  assert.equal(exitCode(await lockTon(t, 'committed', 1, toNano('1'), toNano('1'))), 504);
  assert.equal(exitCode(await lockTon(t, 'committed', 1, 0n)), 504);
  assert.equal(exitCode(await lockTon(t, 'committed', 1, toNano('1'))), 0);
  assert.equal(exitCode(await lockTon(t, 'committed', 1, toNano('1'))), 502);
});

test('a jetton leg is held by the lock\'s wallet and paid out of it', async () => {
  const t = await setup({ jetton: true });
  const walletOf = (owner) => contractAddress(0, walletInit(owner, t.master.address));
  const lockWallet = walletOf(t.lock);
  // The lock learns its wallet from its master.
  const learn = await t.relayer.send({ to: t.lock, value: toNano('0.2'), body: beginCell().storeUint(OP_LEARN_WALLET, 32).storeUint(0, 64).endCell() });
  assert.equal(exitCode(lockTx(t, learn)), 0);
  const stranger = await t.sim.treasury('stranger');
  const take = (from) => from.send({
    to: t.lock, value: toNano('0.1'),
    body: beginCell().storeUint(OP_TAKE_WALLET_ADDRESS, 32).storeUint(0, 64).storeAddress(lockWallet).storeUint(0, 1).endCell(),
  });
  assert.equal(exitCode(lockTx(t, await take(stranger))), 507);
  assert.equal(exitCode(lockTx(t, await take(t.master))), 0);
  assert.equal((await t.sim.provider(t.lock).get('get_wallet', [])).stack.readBigNumber(), big(lockWallet.hash));

  // The master mints 1000 to the payer's wallet.
  const payerWallet = walletOf(t.payer.address);
  await t.master.send({
    to: payerWallet, value: toNano('0.5'), init: walletInit(t.payer.address, t.master.address),
    body: beginCell().storeUint(OP_INTERNAL_TRANSFER, 32).storeUint(0, 64).storeCoins(1000).storeAddress(t.master.address)
      .storeAddress(t.master.address).storeCoins(0).storeUint(0, 1).endCell(),
  });
  const transfer = (amount, payload) => t.payer.send({
    to: payerWallet, value: toNano('0.5'),
    body: beginCell().storeUint(OP_TRANSFER, 32).storeUint(0, 64).storeCoins(amount).storeAddress(t.lock).storeAddress(t.payer.address)
      .storeUint(0, 1).storeCoins(toNano('0.1')).storeUint(1, 1).storeRef(payload).endCell(),
  });
  const balance = async (owner) => (await t.sim.provider(walletOf(owner)).get('get_wallet_data', [])).stack.readBigNumber();
  const legPayload = (which, index) => beginCell().storeUint(plan(which), 256).storeUint(index, 8).storeBuffer(Buffer.from(t.recipient.address.hash)).endCell();

  await transfer(400, legPayload('committed', 1));
  assert.equal(await balance(t.lock), 400n);
  assert.equal((await leg(t, 'committed', 1)).amount, 400n);
  // A transfer that is not a leg goes back.
  await transfer(50, beginCell().storeUint(1, 8).endCell());
  await transfer(70, legPayload('committed', 1));
  assert.equal(await balance(t.lock), 400n);
  assert.equal(await balance(t.payer.address), 600n);

  const r = await settle(t, 'committed', 1, 'committed');
  assert.equal(exitCode(lockTx(t, r)), 0);
  assert.equal(await balance(t.recipient.address), 400n);
  assert.equal(await balance(t.lock), 0n);
});

test('the reconciliation hash matches the shared vector', async () => {
  const rv = JSON.parse(fs.readFileSync(path.join(dir, '../../../sdk/fixtures/settlement_lock/recon.json'), 'utf8'));
  const t = await setup();
  t.payer = await t.sim.treasury('whale', { balance: toNano('3000000000') });
  const recon = async () => {
    const r = await t.sim.provider(t.lock).get('get_reconciliation', []);
    return [r.stack.readNumber(), r.stack.readBigNumber()];
  };
  assert.equal(exitCode(await lockTon(t, 'committed', 0, 400n)), 0);
  assert.deepEqual(await recon(), [1, big(raw(rv.entries[0].acc))]);
  assert.equal(exitCode(await lockTon(t, 'aborted', 2, 1_000_000_000_000_000_000n)), 0);
  assert.equal(exitCode(lockTx(t, await settle(t, 'committed', 0, 'committed'))), 0);
  assert.equal(exitCode(lockTx(t, await settle(t, 'aborted', 2, 'aborted'))), 0);
  assert.equal(exitCode(await lockTon(t, 'undecided', 1, 250n)), 0);
  t.sim.now = NOW + HORIZON;
  const escaped = await t.relayer.send({
    to: t.lock, value: toNano('0.2'),
    body: beginCell().storeUint(OP_ESCAPE, 32).storeUint(0, 64).storeUint(plan('undecided'), 256).storeUint(1, 8).endCell(),
  });
  assert.equal(exitCode(lockTx(t, escaped)), 0);
  assert.deepEqual(await recon(), [rv.count, big(raw(rv.acc))]);

  const r = await t.relayer.send({ to: t.lock, value: toNano('0.05'), body: beginCell().storeUint(0x5c1a3e29, 32).storeUint(0, 64).endCell() });
  const tx = lockTx(t, r);
  assert.equal(exitCode(tx), 0);
  const out = [...tx.outMessages.values()].find((m) => m.info.type === 'external-out');
  const s = out.body.beginParse();
  assert.equal(s.remainingBits, 8 + 64 + 256);
  const got = s.loadBuffer(41).toString('hex');
  const file = path.join(dir, '../../../sdk/fixtures/settlement_lock/ton_accumulator_log.hex');
  if (process.env.TENZRO_WRITE_FIXTURES) fs.writeFileSync(file, got + '\n');
  assert.equal(fs.readFileSync(file, 'utf8').trim(), got);
  assert.equal(got, '64' + '0000000000000006' + rv.acc.replace(/^0x/, ''));
});

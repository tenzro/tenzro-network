// SPDX-License-Identifier: Apache-2.0
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { createChain } from './chain.mjs';
import { beginCell, Cell, contractAddress, Dictionary, toNano } from '@ton/core';

const dir = path.dirname(new URL(import.meta.url).pathname);
const code = Cell.fromBase64(fs.readFileSync(path.join(dir, '../build/finality.code.boc.b64'), 'utf8'));
/** A real finality proof of a test build of the finality program, wrapped over BLS12-381 with a one-party test key. */
const fixture = JSON.parse(fs.readFileSync(path.join(dir, 'fixtures/bls_wrap_proof.json'), 'utf8'));

const OP_SUBMIT = 0x4f1c3b7a;
const OP_REPORT = 0x6a2d9e15;
const OP_STATE_ROOT = 0x2b7f4c93;
const COMMITTEE = BigInt('0xf17b383633cfd64f3bf43b34394ee538096a722322bb16144d845acd28e6e481');
const GENESIS = BigInt('0x' + '6e'.repeat(32));
const hex = (s) => Buffer.from(s, 'hex');

function vkCell(vk) {
  const g2 = (s) => beginCell().storeBuffer(hex(s)).endCell();
  return beginCell()
    .storeBuffer(hex(vk.alpha)).storeBuffer(hex(vk.ic[0]))
    .storeRef(g2(vk.beta)).storeRef(g2(vk.gamma)).storeRef(g2(vk.delta))
    .storeRef(beginCell().storeBuffer(hex(vk.ic[1])).storeBuffer(hex(vk.ic[2]))
      .storeRef(beginCell().storeBuffer(hex(vk.ic[3])).endCell())
      .storeRef(g2(vk.commitment_g)).storeRef(g2(vk.commitment_g_sigma_neg)).endCell())
    .endCell();
}

function journalCell(journal) {
  const words = [0, 3, 6, 9, 12, 13].map((w) => w * 32);
  let cell = null;
  for (let i = 4; i >= 0; i--) {
    const b = beginCell().storeBuffer(journal.subarray(words[i], words[i + 1]));
    if (cell) b.storeRef(cell);
    cell = b.endCell();
  }
  return cell;
}

function sealCell(p) {
  return beginCell().storeBuffer(hex(p.a)).storeBuffer(hex(p.c))
    .storeRef(beginCell().storeBuffer(hex(p.b)).endCell())
    .storeRef(beginCell().storeBuffer(hex(p.commitment)).storeBuffer(hex(p.commitment_pok)).endCell())
    .endCell();
}

async function setup(chainId = 1337n, committee = COMMITTEE) {
  const chain = await createChain();
  const committees = Dictionary.empty(Dictionary.Keys.BigUint(64), Dictionary.Values.BigUint(256));
  committees.set(0n, committee);
  const data = beginCell()
    .storeUint(BigInt('0x' + fixture.proof.image_id), 256).storeUint(chainId, 64).storeUint(GENESIS, 256).storeUint(0, 64)
    .storeRef(vkCell(fixture.vk)).storeDict(committees).storeDict(null)
    .endCell();
  const init = { code, data };
  const address = contractAddress(0, init);
  const client = chain.openContract({ address, init });
  const sender = await chain.treasury('relayer');
  await sender.send({ to: address, value: toNano('1'), init, body: beginCell().endCell() });
  return { chain, address, sender };
}

async function submit(ctx, journal = hex(fixture.proof.journal), proof = fixture.proof) {
  const body = beginCell().storeUint(OP_SUBMIT, 32).storeUint(0, 64).storeRef(journalCell(journal)).storeRef(sealCell(proof)).endCell();
  const r = await ctx.sender.send({ to: ctx.address, value: toNano('1'), body });
  return r.transactions.find((t) => t.inMessage?.info.dest?.equals?.(ctx.address));
}

const exitCode = (tx) => tx.description.computePhase.exitCode;
const get = async (ctx, method, args = []) =>
  (await ctx.chain.runGetMethod(ctx.address, method, args.map((v) => ({ type: 'int', value: BigInt(v) })))).stackReader.readBigNumber();

test('a wrapped real proof finalizes its checkpoint and hands over', async () => {
  const ctx = await setup();
  const tx = await submit(ctx);
  assert.equal(exitCode(tx), 0);
  console.log(`submit gas: ${tx.description.computePhase.gasUsed}`);
  assert.equal(await get(ctx, 'get_state_root', [7]), BigInt('0x' + '5e'.repeat(32)));
  assert.equal(await get(ctx, 'get_checkpoint_timestamp', [7]), 1790000000000n);
  assert.equal(await get(ctx, 'get_latest_index'), 7n);
  assert.equal(await get(ctx, 'get_committee_root', [1]), BigInt('0x' + 'c2'.repeat(32)));
});

test('a checkpoint is final once', async () => {
  const ctx = await setup();
  await submit(ctx);
  assert.equal(exitCode(await submit(ctx)), 303);
});

test('a journal the proof does not commit is refused', async () => {
  const ctx = await setup();
  const journal = hex(fixture.proof.journal);
  journal[8 * 32] = 0x5f;
  assert.equal(exitCode(await submit(ctx, journal)), 304);
  assert.equal(await get(ctx, 'get_latest_index'), 0n);
});

test('a proof with its points swapped is refused', async () => {
  const ctx = await setup();
  const tx = await submit(ctx, undefined, { ...fixture.proof, a: fixture.proof.c, c: fixture.proof.a });
  assert.notEqual(exitCode(tx), 0);
});

test('a proof with another commitment is refused', async () => {
  const ctx = await setup();
  const tx = await submit(ctx, undefined, { ...fixture.proof, commitment: fixture.proof.commitment_pok });
  assert.equal(exitCode(tx), 304);
});

test('proofs of another chain or committee are refused', async () => {
  assert.equal(exitCode(await submit(await setup(1n))), 301);
  assert.equal(exitCode(await submit(await setup(1337n, BigInt('0x' + 'c2'.repeat(32))))), 302);
});

test('the client reports a final state root to whoever asks, and nothing it has not finalized', async () => {
  const ctx = await setup();
  await submit(ctx);
  const asker = await ctx.chain.treasury('account');
  const ask = (index) =>
    ctx.sender.send({
      to: ctx.address,
      value: toNano('0.2'),
      body: beginCell().storeUint(OP_REPORT, 32).storeUint(9, 64).storeUint(index, 64).storeAddress(asker.address)
        .storeRef(beginCell().storeUint(42, 8).endCell()).endCell(),
    });
  const r = await ask(7);
  const reply = r.transactions.find((t) => t.inMessage?.info.dest?.equals?.(asker.address));
  const s = reply.inMessage.body.beginParse();
  assert.equal(s.loadUint(32), OP_STATE_ROOT);
  assert.equal(s.loadUintBig(64), 9n);
  assert.equal(s.loadUintBig(64), 7n);
  assert.equal(s.loadUintBig(256), BigInt('0x' + '5e'.repeat(32)));
  assert.equal(s.loadUintBig(64), 1790000000000n);
  assert.equal(s.loadRef().beginParse().loadUint(8), 42);
  const missing = await ask(8);
  assert.equal(exitCode(missing.transactions.find((t) => t.inMessage?.info.dest?.equals?.(ctx.address))), 305);
});

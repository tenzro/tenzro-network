// SPDX-License-Identifier: Apache-2.0
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { createChain } from './chain.mjs';
import { Address, beginCell, Cell, contractAddress, Dictionary, toNano } from '@ton/core';
import { secp256k1 } from '@noble/curves/secp256k1';
import { keccak_256 } from '@noble/hashes/sha3';

const dir = path.dirname(new URL(import.meta.url).pathname);
const load = (name) => Cell.fromBase64(fs.readFileSync(path.join(dir, `../build/${name}.code.boc.b64`), 'utf8'));
const code = load('bridge');
const walletCode = load('jetton-wallet');

const CHAIN_ID = 1337n;
const TON_SELECTOR = 101n;
const TENZRO_SELECTOR = 7777n;
const ROUTE_KEY = Buffer.from('bridge_route:contract:ton');
const TOKEN = BigInt('0x' + '22'.repeat(32));
const ENDPOINT = BigInt('0x' + '44'.repeat(32));
const OP_SEND = 0x54e0a5d1;
const OP_EXECUTE = 0x8f2c6b3a;
const OP_ROTATE = 0x6b1d2e47;
const EXPIRES = 4_000_000_000n;
const OP_TRANSFER = 0x0f8a7ea5;
const OP_TRANSFER_NOTIFICATION = 0x7362d09c;
const OP_BURN = 0x595f07bc;
const TNZO = 10n ** 18n;

/** Tenzro's outbound record for the contract at `0x33..33` and the digest its committee signs (Tenzro's route tests read both). */
const OUTBOUND = '00000000000000070000000000001e610000000000000065111111111111111111111111111111111111111111111111111111111111111122222222222222222222222222222222222222222222222222222222222222223333333333333333333333333333333333333333333333333333333333333333000000000000000000000000000000000000000000000000000000000000000b00000000000000004563918244f40000';
const OUTBOUND_DIGEST = '3e09d98ef914c6e888c3bc1a8ee350a07980649d6754e88caf7cc44e3babc95b';

/** The digest that hands this contract over to set 2 of members [0x41; 20], [0x42; 20], [0x43; 20], threshold 2, expiring at Unix second 2,000,000,000 (Tenzro's route tests read it). */
const HANDOVER_DIGEST = 'd15e037d726e5047cb01944e5f80b6d9dc9ef110ede1b30787583ced39d41b25';

const keys = [1, 2, 3, 4, 5, 6, 8, 9].reduce((m, i) => ((m[i] = new Uint8Array(32).fill(i)), m), {});
const ethAddress = (sk) => {
  const pub = secp256k1.getPublicKey(sk, false).slice(1);
  return BigInt('0x' + Buffer.from(keccak_256(pub).slice(12)).toString('hex'));
};

function be(v, bytes) {
  const out = Buffer.alloc(bytes);
  let x = BigInt(v);
  for (let i = bytes - 1; i >= 0; i--) { out[i] = Number(x & 0xffn); x >>= 8n; }
  return out;
}

function recordCell(r) {
  const tail = beginCell().storeUint(r.recipient, 256).storeUint(r.amount, 128).endCell();
  return beginCell()
    .storeUint(r.sequence, 64).storeUint(r.source, 64).storeUint(r.dest, 64)
    .storeUint(r.sender, 256).storeUint(r.token, 256).storeUint(r.endpoint, 256)
    .storeRef(tail).endCell();
}

function recordBytes(r) {
  return Buffer.concat([be(r.sequence, 8), be(r.source, 8), be(r.dest, 8), be(r.sender, 32), be(r.token, 32), be(r.endpoint, 32), be(r.recipient, 32), be(r.amount, 16)]);
}

function digestOf(record) {
  return Buffer.from(keccak_256(Buffer.concat([Buffer.from('tenzro/bridge/route-outbound'), be(CHAIN_ID, 8), be(ROUTE_KEY.length, 8), ROUTE_KEY, record])));
}

function signatures(seeds, digest) {
  // Chained cells of 65-byte signatures (r || s || v).
  let next = null;
  for (const s of [...seeds].reverse()) {
    const sig = secp256k1.sign(digest, keys[s], { lowS: true });
    const b = beginCell().storeUint(sig.r, 256).storeUint(sig.s, 256).storeUint(sig.recovery, 8);
    if (next) b.storeRef(next);
    next = b.endCell();
  }
  return next;
}

async function setup(expires = EXPIRES) {
  const chain = await createChain();
  const committee = Dictionary.empty(Dictionary.Keys.BigUint(160), Dictionary.Values.Cell());
  for (const s of [1, 2, 3]) committee.set(ethAddress(keys[s]), beginCell().endCell());
  const route = beginCell()
    .storeUint(TOKEN, 256).storeUint(ENDPOINT, 256).storeUint(1, 32).storeUint(expires, 64)
    .storeDict(committee).storeDict(null).endCell();
  // TEP-64 off-chain content.
  const content = beginCell().storeUint(1, 8).storeStringTail('https://tenzro.com/tnzo.json').endCell();
  const data = beginCell()
    .storeUint(0, 64).storeUint(CHAIN_ID, 64).storeUint(TON_SELECTOR, 64).storeUint(TENZRO_SELECTOR, 64).storeUint(2, 8)
    .storeCoins(0)
    .storeRef(beginCell().storeBuffer(ROUTE_KEY).endCell())
    .storeRef(route)
    .storeRef(content)
    .storeRef(walletCode)
    .endCell();
  const address = contractAddress(0, { code, data });
  const user = await chain.treasury('user');
  await user.send({ to: address, value: toNano('1'), init: { code, data }, body: beginCell().endCell() });
  const ramp = BigInt('0x' + address.hash.toString('hex'));
  return { chain, address, user, ramp };
}

const get = async (t, at, method, args) => (await t.chain.runGetMethod(at, method, args)).stackReader;
const walletOf = async (t, owner) =>
  (await get(t, t.address, 'get_wallet_address', [{ type: 'slice', cell: beginCell().storeAddress(owner).endCell() }])).readAddress();
const jettons = async (t, owner) => {
  const w = await walletOf(t, owner);
  const acc = await t.chain.getContract(w);
  if (acc.accountState?.type !== 'active') return 0n;
  return (await get(t, w, 'get_wallet_data', [])).readBigNumber();
};
const supply = async (t) => (await get(t, t.address, 'get_jetton_data', [])).readBigNumber();

async function execute(t, record, seeds) {
  const body = beginCell().storeUint(OP_EXECUTE, 32).storeRef(recordCell(record)).storeRef(signatures(seeds, digestOf(recordBytes(record)))).endCell();
  return t.user.send({ to: t.address, value: toNano('0.5'), body });
}

const userId = (t) => BigInt('0x' + t.user.address.hash.toString('hex'));

function outbound(t) {
  return { sequence: 7n, source: TENZRO_SELECTOR, dest: TON_SELECTOR, sender: BigInt('0x' + '11'.repeat(32)), token: TOKEN, endpoint: t.ramp, recipient: userId(t), amount: 5n * TNZO };
}

/** A standard TEP-74 transfer from the user's jetton wallet. */
async function jettonTransfer(t, to, amount, forwardTon, payload) {
  const body = beginCell()
    .storeUint(OP_TRANSFER, 32).storeUint(9, 64).storeCoins(amount)
    .storeAddress(to).storeAddress(t.user.address).storeMaybeRef(null)
    .storeCoins(forwardTon);
  if (payload) body.storeBit(1).storeRef(payload); else body.storeBit(0);
  return t.user.send({ to: await walletOf(t, t.user.address), value: forwardTon + toNano('0.2'), body: body.endCell() });
}

const toTenzro = (recipient) => beginCell().storeUint(OP_SEND, 32).storeUint(recipient, 256).endCell();
const failed = (res) => res.transactions.some((tx) => tx.description.type === 'generic' && tx.description.computePhase.type === 'vm' && !tx.description.computePhase.success);
const externals = (res, from) =>
  res.transactions.flatMap((tx) => tx.outMessages.values()).filter((m) => m.info.type === 'external-out' && m.info.src.equals(from));

test('a record the committee signed mints jettons to the recipient once', async () => {
  const t = await setup();
  const record = outbound(t);
  const cell = recordCell(record);
  assert.equal((await get(t, t.address, 'get_outbound_digest', [{ type: 'cell', cell }])).readBigNumber(), BigInt('0x' + digestOf(recordBytes(record)).toString('hex')));
  assert.equal(failed(await execute(t, record, [1, 3])), false);
  assert.equal(await jettons(t, t.user.address), 5n * TNZO);
  assert.equal(await supply(t), 5n * TNZO);
  assert.equal((await get(t, t.address, 'is_executed', [{ type: 'int', value: 7n }])).readBigNumber(), -1n);
  assert.equal(failed(await execute(t, record, [2, 3])), true);
  assert.equal(await supply(t), 5n * TNZO);
});

test('fewer than the threshold, strangers, a tampered record or an amount past jetton range mint nothing', async () => {
  const t = await setup();
  const record = outbound(t);
  assert.equal(failed(await execute(t, record, [2, 2])), true);
  assert.equal(failed(await execute(t, record, [1, 9])), true);
  const body = beginCell().storeUint(OP_EXECUTE, 32).storeRef(recordCell({ ...record, amount: record.amount + 1n })).storeRef(signatures([1, 2], digestOf(recordBytes(record)))).endCell();
  assert.equal(failed(await t.user.send({ to: t.address, value: toNano('0.5'), body })), true);
  assert.equal(failed(await execute(t, { ...record, amount: 1n << 120n }, [1, 2])), true);
  assert.equal(await jettons(t, t.user.address), 0n);
  assert.equal(await supply(t), 0n);
});

test('the jetton data and wallets follow TEP-74', async () => {
  const t = await setup();
  await execute(t, outbound(t), [1, 2]);
  const s = await get(t, t.address, 'get_jetton_data', []);
  assert.equal(s.readBigNumber(), 5n * TNZO);
  assert.equal(s.readBigNumber(), -1n);
  assert.equal(s.readAddressOpt(), null);
  s.readCell();
  assert.equal(s.readCell().hash().toString('hex'), walletCode.hash().toString('hex'));
  const w = await get(t, await walletOf(t, t.user.address), 'get_wallet_data', []);
  assert.equal(w.readBigNumber(), 5n * TNZO);
  assert.ok(w.readAddress().equals(t.user.address));
  assert.ok(w.readAddress().equals(t.address));
  // A plain jetton transfer between holders.
  const other = await t.chain.treasury('other');
  assert.equal(failed(await jettonTransfer(t, other.address, 2n * TNZO, 0n, null)), false);
  assert.equal(await jettons(t, other.address), 2n * TNZO);
  assert.equal(await jettons(t, t.user.address), 3n * TNZO);
});

test('a jetton transfer to the bridge burns it and emits the record the light client reads', async () => {
  const t = await setup();
  await execute(t, outbound(t), [1, 2]);
  const res = await jettonTransfer(t, t.address, 3n * TNZO, toNano('0.1'), toTenzro(BigInt('0x' + '55'.repeat(32))));
  assert.equal(failed(res), false);
  const ext = externals(res, t.address);
  assert.equal(ext.length, 1);
  const record = { sequence: 1n, source: TON_SELECTOR, dest: TENZRO_SELECTOR, sender: userId(t), token: TOKEN, endpoint: ENDPOINT, recipient: BigInt('0x' + '55'.repeat(32)), amount: 3n * TNZO };
  assert.equal(ext[0].body.hash().toString('hex'), recordCell(record).hash().toString('hex'));
  assert.equal(await jettons(t, t.user.address), 2n * TNZO);
  assert.equal(await jettons(t, t.address), 0n);
  assert.equal(await supply(t), 2n * TNZO);
  assert.equal((await get(t, t.address, 'get_sequence', [])).readBigNumber(), 1n);
});

test('a transfer without the Tenzro payload is returned, with no record', async () => {
  const t = await setup();
  await execute(t, outbound(t), [1, 2]);
  const wrong = beginCell().storeUint(0x12345678, 32).storeUint(1, 256).endCell();
  const res = await jettonTransfer(t, t.address, 1n * TNZO, toNano('0.1'), wrong);
  assert.equal(externals(res, t.address).length, 0);
  assert.equal(await jettons(t, t.user.address), 5n * TNZO);
  assert.equal(await jettons(t, t.address), 0n);
  assert.equal(await supply(t), 5n * TNZO);
  assert.equal((await get(t, t.address, 'get_sequence', [])).readBigNumber(), 0n);
});

test('a transfer to Tenzro with too little TON for the burn still leaves the supply and is recorded', async () => {
  const t = await setup();
  await execute(t, outbound(t), [1, 2]);
  const res = await jettonTransfer(t, t.address, 1n * TNZO, toNano('0.01'), toTenzro(1n));
  assert.equal(externals(res, t.address).length, 1);
  assert.equal(await jettons(t, t.user.address), 4n * TNZO);
  assert.equal(await jettons(t, t.address), 1n * TNZO);
  assert.equal(await supply(t), 4n * TNZO);
});

test('a forged transfer notification emits nothing, and a plain burn lowers the supply', async () => {
  const t = await setup();
  await execute(t, outbound(t), [1, 2]);
  const forged = beginCell().storeUint(OP_TRANSFER_NOTIFICATION, 32).storeUint(0, 64).storeCoins(100n * TNZO)
    .storeAddress(t.user.address).storeBit(1).storeRef(toTenzro(1n)).endCell();
  const res = await t.user.send({ to: t.address, value: toNano('0.5'), body: forged });
  assert.equal(failed(res), true);
  assert.equal(externals(res, t.address).length, 0);
  const burn = beginCell().storeUint(OP_BURN, 32).storeUint(0, 64).storeCoins(1n * TNZO).storeAddress(t.user.address).storeMaybeRef(null).endCell();
  const b = await t.user.send({ to: await walletOf(t, t.user.address), value: toNano('0.2'), body: burn });
  assert.equal(failed(b), false);
  assert.equal(externals(b, t.address).length, 0);
  assert.equal(await supply(t), 4n * TNZO);
  assert.equal(await jettons(t, t.user.address), 4n * TNZO);
});

test('the committee digest is the one Tenzro computes', () => {
  // Tenzro's outbound digest for a fixed record on this route (see the
  // Tenzro route tests, which read this constant).
  const record = { sequence: 7n, source: TENZRO_SELECTOR, dest: TON_SELECTOR, sender: BigInt('0x' + '11'.repeat(32)), token: TOKEN, endpoint: BigInt('0x' + '33'.repeat(32)), recipient: 11n, amount: 5n * TNZO };
  assert.equal(recordBytes(record).toString('hex'), OUTBOUND);
  assert.equal(digestOf(recordBytes(record)).toString('hex'), OUTBOUND_DIGEST);
});

/** Members as 20-byte addresses, six per cell, chained through one reference. */
function membersCell(addresses) {
  let next = null;
  for (let i = Math.floor((addresses.length - 1) / 6) * 6; i >= 0; i -= 6) {
    const b = beginCell();
    for (const a of addresses.slice(i, i + 6)) b.storeUint(a, 160);
    if (next) b.storeRef(next);
    next = b.endCell();
  }
  return next;
}

function handoverDigest(setIndex, addresses, threshold, expires) {
  return Buffer.from(keccak_256(Buffer.concat([
    Buffer.from('tenzro/bridge/route-committee'), be(CHAIN_ID, 8), be(ROUTE_KEY.length, 8), ROUTE_KEY,
    be(setIndex, 4), be(addresses.length, 4), ...addresses.map((a) => be(a, 20)), be(threshold, 4), be(expires, 8),
  ])));
}

async function rotate(t, setIndex, addresses, threshold, expires, seeds) {
  const body = beginCell()
    .storeUint(OP_ROTATE, 32).storeUint(setIndex, 32).storeUint(threshold, 8).storeUint(expires, 64)
    .storeRef(membersCell(addresses))
    .storeRef(signatures(seeds, handoverDigest(setIndex, addresses, threshold, expires)))
    .endCell();
  return t.user.send({ to: t.address, value: toNano('0.5'), body });
}

const fixed = [0x41, 0x42, 0x43].map((b) => BigInt('0x' + b.toString(16).repeat(20)));

test('the handover digest is the one Tenzro computes', async () => {
  const t = await setup();
  assert.equal(handoverDigest(2n, fixed, 2n, 2_000_000_000n).toString('hex'), HANDOVER_DIGEST);
  const args = [
    { type: 'int', value: 2n },
    { type: 'cell', cell: membersCell(fixed) },
    { type: 'int', value: 2n },
    { type: 'int', value: 2_000_000_000n },
  ];
  assert.equal((await get(t, t.address, 'get_handover_digest', args)).readBigNumber(), BigInt('0x' + HANDOVER_DIGEST));
  // Members spanning several cells hash as one sequence.
  const many = Array.from({ length: 13 }, (_, i) => BigInt(i + 1) << 100n);
  const manyArgs = [{ type: 'int', value: 3n }, { type: 'cell', cell: membersCell(many) }, { type: 'int', value: 9n }, { type: 'int', value: 7n }];
  assert.equal((await get(t, t.address, 'get_handover_digest', manyArgs)).readBigNumber(), BigInt('0x' + handoverDigest(3n, many, 9n, 7n).toString('hex')));
});

test('the committee hands over only with its own quorum, to a higher set, once', async () => {
  const t = await setup();
  const next = [4, 5, 6].map((s) => ethAddress(keys[s]));
  assert.equal(failed(await rotate(t, 2n, next, 2n, EXPIRES, [4, 5])), true, 'the next committee cannot hand itself in');
  assert.equal(failed(await rotate(t, 1n, next, 2n, EXPIRES, [1, 2])), true, 'the set index held is refused');
  assert.equal(failed(await rotate(t, 2n, next, 2n, EXPIRES, [1, 2])), false);
  const set = await get(t, t.address, 'get_committee_set', []);
  assert.equal(set.readBigNumber(), 2n);
  assert.equal(set.readBigNumber(), EXPIRES);
  assert.equal(failed(await rotate(t, 2n, next, 2n, EXPIRES, [4, 5])), true, 'a replay is stale');
  assert.equal(failed(await execute(t, outbound(t), [1, 2])), true, 'the old committee no longer mints');
  assert.equal(failed(await execute(t, outbound(t), [4, 6])), false);
  assert.equal(await jettons(t, t.user.address), 5n * TNZO);
});

test('an expired committee neither mints nor hands over', async () => {
  // The emulated chain's clock is past Unix second 1,000,000.
  const t = await setup(1_000_000n);
  assert.equal(failed(await execute(t, outbound(t), [1, 2])), true);
  const next = [4, 5, 6].map((s) => ethAddress(keys[s]));
  assert.equal(failed(await rotate(t, 2n, next, 2n, EXPIRES, [1, 2])), true);
});

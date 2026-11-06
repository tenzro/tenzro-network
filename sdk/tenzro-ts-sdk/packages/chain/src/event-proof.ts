/**
 * Verifies the chain's event proofs against a certified checkpoint.
 *
 * Every block header commits the events its execution emitted, and every
 * checkpoint certificate commits the block headers it covers. An event's
 * proof links its leaf to the header's event root, the header to the
 * covering checkpoint's blocks root, and that checkpoint through the
 * following checkpoint bodies to a certified one. `verifyEventProof` checks
 * all of it against the digest of a checkpoint the caller already holds as
 * certified (from a light client); it trusts nothing the node says.
 */

import { createHash } from 'node:crypto';

// ── BLAKE3 (hash mode) ──

const IV = new Uint32Array([
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
]);
const PERM = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];
const CHUNK_START = 1;
const CHUNK_END = 2;
const PARENT = 4;
const ROOT = 8;
const CHUNK_LEN = 1024;

function rotr(x: number, n: number): number {
  return ((x >>> n) | (x << (32 - n))) >>> 0;
}

function g(s: Uint32Array, a: number, b: number, c: number, d: number, x: number, y: number): void {
  s[a] = (s[a] + s[b] + x) >>> 0;
  s[d] = rotr(s[d] ^ s[a], 16);
  s[c] = (s[c] + s[d]) >>> 0;
  s[b] = rotr(s[b] ^ s[c], 12);
  s[a] = (s[a] + s[b] + y) >>> 0;
  s[d] = rotr(s[d] ^ s[a], 8);
  s[c] = (s[c] + s[d]) >>> 0;
  s[b] = rotr(s[b] ^ s[c], 7);
}

function compress(cv: Uint32Array, block: Uint32Array, counter: number, len: number, flags: number): Uint32Array {
  const s = new Uint32Array([
    cv[0], cv[1], cv[2], cv[3], cv[4], cv[5], cv[6], cv[7],
    IV[0], IV[1], IV[2], IV[3],
    counter >>> 0, Math.floor(counter / 0x100000000) >>> 0, len, flags,
  ]);
  let m: Uint32Array = Uint32Array.from(block);
  for (let r = 0; r < 7; r++) {
    g(s, 0, 4, 8, 12, m[0], m[1]);
    g(s, 1, 5, 9, 13, m[2], m[3]);
    g(s, 2, 6, 10, 14, m[4], m[5]);
    g(s, 3, 7, 11, 15, m[6], m[7]);
    g(s, 0, 5, 10, 15, m[8], m[9]);
    g(s, 1, 6, 11, 12, m[10], m[11]);
    g(s, 2, 7, 8, 13, m[12], m[13]);
    g(s, 3, 4, 9, 14, m[14], m[15]);
    if (r < 6) m = Uint32Array.from(PERM, (i) => m[i]);
  }
  for (let i = 0; i < 8; i++) {
    s[i] ^= s[i + 8];
    s[i + 8] ^= cv[i];
  }
  return s;
}

function words(bytes: Uint8Array): Uint32Array {
  const padded = new Uint8Array(64);
  padded.set(bytes);
  const out = new Uint32Array(16);
  for (let i = 0; i < 16; i++) {
    out[i] = padded[4 * i] | (padded[4 * i + 1] << 8) | (padded[4 * i + 2] << 16) | (padded[4 * i + 3] << 24);
  }
  return out;
}

function chunkCv(chunk: Uint8Array, index: number, root: boolean): Uint32Array {
  let cv: Uint32Array = Uint32Array.from(IV);
  const blocks = Math.max(1, Math.ceil(chunk.length / 64));
  for (let b = 0; b < blocks; b++) {
    const block = chunk.subarray(64 * b, 64 * b + 64);
    let flags = b === 0 ? CHUNK_START : 0;
    if (b === blocks - 1) flags |= CHUNK_END | (root ? ROOT : 0);
    cv = compress(cv, words(block), index, block.length, flags).subarray(0, 8);
  }
  return cv;
}

function parentCv(left: Uint32Array, right: Uint32Array, root: boolean): Uint32Array {
  const block = new Uint32Array(16);
  block.set(left, 0);
  block.set(right, 8);
  return compress(IV, block, 0, 64, PARENT | (root ? ROOT : 0)).subarray(0, 8);
}

function subtree(input: Uint8Array, first: number, chunks: number, root: boolean): Uint32Array {
  if (chunks === 1) {
    return chunkCv(input.subarray(first * CHUNK_LEN, (first + 1) * CHUNK_LEN), first, root);
  }
  let left = 1;
  while (left * 2 < chunks) left *= 2;
  return parentCv(subtree(input, first, left, false), subtree(input, first + left, chunks - left, false), root);
}

/** BLAKE3 of `input`, 32 bytes. */
export function blake3(input: Uint8Array): Uint8Array {
  const chunks = Math.max(1, Math.ceil(input.length / CHUNK_LEN));
  const cv = subtree(input, 0, chunks, true);
  const out = new Uint8Array(32);
  for (let i = 0; i < 8; i++) {
    out[4 * i] = cv[i] & 0xff;
    out[4 * i + 1] = (cv[i] >>> 8) & 0xff;
    out[4 * i + 2] = (cv[i] >>> 16) & 0xff;
    out[4 * i + 3] = (cv[i] >>> 24) & 0xff;
  }
  return out;
}

// ── Encoding helpers ──

class Bytes {
  private parts: number[] = [];
  push(...b: number[]): this {
    this.parts.push(...b);
    return this;
  }
  raw(b: ArrayLike<number>): this {
    for (let i = 0; i < b.length; i++) this.parts.push(b[i]);
    return this;
  }
  u32(n: number): this {
    return this.uint(BigInt(n), 4);
  }
  u64(n: number | bigint): this {
    return this.uint(BigInt(n), 8);
  }
  u128(n: number | bigint): this {
    return this.uint(BigInt(n), 16);
  }
  i64(n: number): this {
    return this.uint(BigInt.asUintN(64, BigInt(n)), 8);
  }
  lenBytes(b: ArrayLike<number>): this {
    return this.u32(b.length).raw(b);
  }
  private uint(n: bigint, width: number): this {
    for (let i = 0; i < width; i++) this.parts.push(Number((n >> BigInt(8 * i)) & 0xffn));
    return this;
  }
  done(): Uint8Array {
    return Uint8Array.from(this.parts);
  }
}

function fail(msg: string): never {
  throw new Error(`event proof: ${msg}`);
}

function bytes32(v: unknown, what: string): number[] {
  if (!Array.isArray(v) || v.length !== 32) fail(`${what} is not 32 bytes`);
  return v as number[];
}

function eq(a: ArrayLike<number>, b: ArrayLike<number>): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

function hashLeaf(leaf: ArrayLike<number>): Uint8Array {
  return blake3(new Bytes().push(0).raw(leaf).done());
}

function hashPair(l: ArrayLike<number>, r: ArrayLike<number>): Uint8Array {
  return blake3(new Bytes().push(1).raw(l).raw(r).done());
}

interface PathStep {
  sibling: number[];
  left: boolean;
}

function rootFromPath(leaf: ArrayLike<number>, path: PathStep[]): Uint8Array {
  let acc = hashLeaf(leaf);
  for (const step of path) {
    acc = step.left ? hashPair(bytes32(step.sibling, 'a path sibling'), acc) : hashPair(acc, bytes32(step.sibling, 'a path sibling'));
  }
  return acc;
}

/** One event the chain emitted, as the node serves it. */
export interface ChainEvent {
  cursor: { height: number; tx_index: number; event_index: number };
  tx_hash: number[];
  kind: 'tx_outcome' | 'log';
  success?: boolean;
  gas_used?: number;
  contract_address?: number[] | null;
  address?: number[];
  topics?: number[][];
  data?: number[];
}

/** An event's proof, as `tenzro_getEventProof` and `tenzro_queryEvents` return it. */
export interface EventProof {
  event: ChainEvent;
  event_path: PathStep[];
  header: Record<string, any>;
  block_path: PathStep[];
  checkpoints: Record<string, any>[];
}

function eventLeaf(e: ChainEvent): Uint8Array {
  const out = new Bytes()
    .raw(new TextEncoder().encode('tenzro/chain-event/leaf'))
    .u64(e.cursor.height)
    .u32(e.cursor.tx_index)
    .u32(e.cursor.event_index)
    .raw(bytes32(e.tx_hash, 'tx_hash'));
  if (e.kind === 'tx_outcome') {
    out.push(0, e.success ? 1 : 0).u64(e.gas_used ?? fail('gas_used is missing'));
    if (e.contract_address == null) out.push(0);
    else out.push(1).lenBytes(e.contract_address);
  } else if (e.kind === 'log') {
    out.push(1).lenBytes(e.address ?? fail('address is missing'));
    const topics = e.topics ?? fail('topics are missing');
    out.u32(topics.length);
    for (const t of topics) out.lenBytes(t);
    out.lenBytes(e.data ?? fail('data is missing'));
  } else {
    fail('unknown event kind');
  }
  return blake3(out.done());
}

function logsBloom(v: unknown): number[] {
  if (typeof v !== 'string' || !/^[0-9a-f]{512}$/.test(v)) fail('logs_bloom is not 256 hex bytes');
  const out: number[] = [];
  for (let i = 0; i < 512; i += 2) out.push(parseInt((v as string).slice(i, i + 2), 16));
  return out;
}

function headerHash(h: Record<string, any>): Uint8Array {
  const m = h.metadata;
  const out = new Bytes().u64(h.height).u64(h.epoch).u64(h.round);
  for (const f of ['anchor', 'prev_hash', 'tx_root', 'state_root', 'event_root', 'receipts_root']) out.raw(bytes32(h[f], f));
  out.raw(logsBloom(h.logs_bloom));
  out.i64(h.timestamp).raw(bytes32(h.proposer, 'proposer'));
  out.u64(m.gas_used).u64(m.gas_limit).u64(m.tx_count).u64(m.protocol_version);
  if (m.base_fee_per_gas == null) out.push(0);
  else out.push(1).u128(m.base_fee_per_gas);
  return new Uint8Array(createHash('sha256').update(out.done()).digest());
}

/** The digest a checkpoint certificate signs, from the checkpoint's JSON. */
export function checkpointDigest(cp: Record<string, any>): Uint8Array {
  const body = new Bytes()
    .u64(cp.chain_id)
    .raw(bytes32(cp.genesis_hash, 'genesis_hash'))
    .u64(cp.epoch)
    .u64(cp.index)
    .raw(bytes32(cp.prev, 'prev'))
    .u64(cp.first_height)
    .u64(cp.last_height)
    .raw(bytes32(cp.blocks_root, 'blocks_root'))
    .u64(cp.state_height)
    .raw(bytes32(cp.state_root, 'state_root'))
    .raw(bytes32(cp.statement_root, 'statement_root'));
  if (cp.next_committee_root == null) body.push(0);
  else body.push(1).raw(bytes32(cp.next_committee_root, 'next_committee_root'));
  body.u64(cp.anchor_round).u64(cp.timestamp_ms).raw(bytes32(cp.ordering_root, 'ordering_root'));
  return blake3(new Bytes().raw(new TextEncoder().encode('tenzro/consensus/checkpoint/body')).raw(body.done()).done());
}

/**
 * Checks `proof` against the digest of a checkpoint the caller holds as
 * certified. Throws on any broken link.
 */
export function verifyEventProof(proof: EventProof, certifiedCheckpointDigest: ArrayLike<number>): void {
  const { event, header, checkpoints } = proof;
  if (event.cursor.height !== header.height) fail('the event and the header are at different heights');
  if (!eq(rootFromPath(eventLeaf(event), proof.event_path), bytes32(header.event_root, 'event_root'))) {
    fail("the event is not under the header's event root");
  }
  if (!checkpoints || checkpoints.length === 0) fail('no checkpoint');
  const covering = checkpoints[0];
  if (header.height < covering.first_height || header.height > covering.last_height) {
    fail('the first checkpoint does not cover the block');
  }
  if (!eq(rootFromPath(headerHash(header), proof.block_path), bytes32(covering.blocks_root, 'blocks_root'))) {
    fail("the header is not under the checkpoint's blocks root");
  }
  let digest = checkpointDigest(covering);
  for (let i = 1; i < checkpoints.length; i++) {
    if (!eq(bytes32(checkpoints[i].prev, 'prev'), digest) || checkpoints[i].index !== checkpoints[i - 1].index + 1) {
      fail('a checkpoint does not follow its predecessor');
    }
    digest = checkpointDigest(checkpoints[i]);
  }
  if (!eq(digest, certifiedCheckpointDigest)) fail('the proof does not end at the certified checkpoint');
}

/** An answer computed from proven events: its projection, result and proofs. */
export interface ProvenAnswer {
  projection: 'events' | 'count' | 'latest_per_address';
  result: unknown;
  proofs: EventProof[];
}

function hex(b: ArrayLike<number>): string {
  return Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
}

/**
 * Checks an index answer: every proof against the certified
 * checkpoint, and the answer as the projection of exactly the proven events.
 */
export function verifyIndexAnswer(answer: ProvenAnswer, certifiedCheckpointDigest: ArrayLike<number>): void {
  const events = answer.proofs.map((p) => {
    verifyEventProof(p, certifiedCheckpointDigest);
    return p.event;
  });
  const key = (e: ChainEvent) => [e.cursor.height, e.cursor.tx_index, e.cursor.event_index];
  for (let i = 1; i < events.length; i++) {
    const [a, b] = [key(events[i - 1]), key(events[i])];
    const before = a[0] < b[0] || (a[0] === b[0] && (a[1] < b[1] || (a[1] === b[1] && a[2] < b[2])));
    if (!before) fail("the answer's events are not in cursor order");
  }
  let expected: unknown;
  if (answer.projection === 'events') expected = events;
  else if (answer.projection === 'count') expected = events.length;
  else if (answer.projection === 'latest_per_address') {
    const latest: Record<string, ChainEvent> = {};
    for (const e of events) if (e.kind === 'log') latest[hex(e.address ?? [])] = e;
    expected = latest;
  } else fail('unknown projection');
  if (!deepEqual(expected, answer.result)) fail('the answer is not the projection of its proven events');
}

function deepEqual(a: unknown, b: unknown): boolean {
  if (a === b) return true;
  if (typeof a !== 'object' || typeof b !== 'object' || a === null || b === null) return false;
  if (Array.isArray(a) !== Array.isArray(b)) return false;
  const ka = Object.keys(a as object).filter((k) => (a as any)[k] !== undefined);
  const kb = Object.keys(b as object).filter((k) => (b as any)[k] !== undefined);
  if (ka.length !== kb.length) return false;
  return ka.every((k) => deepEqual((a as any)[k], (b as any)[k]));
}

// ── Completeness ──

type Cursor = { height: number; tx_index: number; event_index: number };

/** One entry of a block's index: every event under `key`, and the next key. */
export interface IndexEntry {
  /** The key, hex. The chain starts at the empty key. */
  key: string;
  /** The next key, hex, or null for the last entry. */
  next: string | null;
  cursors: Cursor[];
}

/** The proof that a page of events left out nothing its filter selects. */
export interface CompletenessProof {
  keys: string[];
  first_height: number;
  after: Cursor | null;
  through: Cursor;
  blocks: { header: Record<string, any>; block_path: PathStep[]; entries: { entry: IndexEntry; path: PathStep[] }[] }[];
  checkpoints: Record<string, any>[];
  excluded: EventProof[];
}

function unhex(h: string): number[] {
  if (h.length % 2 !== 0 || !/^[0-9a-f]*$/.test(h)) fail(`not lowercase hex: ${h}`);
  const out: number[] = [];
  for (let i = 0; i < h.length; i += 2) out.push(parseInt(h.slice(i, i + 2), 16));
  return out;
}

function cursorCmp(a: Cursor, b: Cursor): number {
  return a.height - b.height || a.tx_index - b.tx_index || a.event_index - b.event_index;
}

function cursorKey(c: Cursor): string {
  return `${c.height}:${c.tx_index}:${c.event_index}`;
}

function indexLeaf(e: IndexEntry): Uint8Array {
  const out = new Bytes().raw(new TextEncoder().encode('tenzro/chain-event/index')).lenBytes(unhex(e.key));
  if (e.next == null) out.push(0);
  else out.push(1).lenBytes(unhex(e.next));
  out.u32(e.cursors.length);
  for (const c of e.cursors) {
    // Big-endian, as the node's storage key.
    const be = new Bytes().u64(c.height).done().reverse();
    out.raw(be).raw(new Bytes().u32(c.tx_index).done().reverse()).raw(new Bytes().u32(c.event_index).done().reverse());
  }
  return blake3(out.done());
}

/** The cursors `entry` proves for `key` (empty when the key falls between it and the next), or null. */
function covers(entry: IndexEntry, key: string): Cursor[] | null {
  if (entry.key === key) return entry.cursors;
  // Lowercase hex orders as its bytes do.
  return entry.key < key && (entry.next == null || key < entry.next) ? [] : null;
}

function hex20(v: string): string {
  const h = v.replace(/^0x/, '').toLowerCase();
  if (h.length !== 40) fail(`an address must be 20 bytes: ${v}`);
  return h;
}

function hex32(v: string): string {
  const h = v.replace(/^0x/, '').toLowerCase();
  if (h.length !== 64) fail(`a topic must be 32 bytes: ${v}`);
  return h;
}

function topicSlots(filter: Record<string, any>): (string[] | null)[] {
  return ((filter.topics as unknown[]) ?? []).map((slot) =>
    slot == null ? null : Array.isArray(slot) ? slot.map((t) => hex32(String(t))) : [hex32(String(slot))],
  );
}

/** The block-index keys (hex) a filter's completeness proof covers, as the node derives them. */
export function filterIndexKeys(filter: Record<string, any>): string[] {
  if (((filter.vm_types as unknown[]) ?? []).length > 0) return [];
  const types = (filter.event_types as string[]) ?? [];
  const addresses = ((filter.addresses as string[]) ?? []).map(hex20);
  const topics = topicSlots(filter);
  const keys: string[] = [];
  if ((types.length === 0 || types.includes('transaction_included')) && addresses.length === 0 && topics.length === 0) {
    keys.push('6b00');
  }
  if (types.length === 0 || types.includes('log')) {
    const position = topics.findIndex((s) => s !== null);
    if (addresses.length > 0) keys.push(...addresses.map((a) => `61${a}`));
    else if (position >= 0) keys.push(...topics[position]!.map((t) => `74${position.toString(16).padStart(2, '0')}${t}`));
    else keys.push('6b01');
  }
  return [...new Set(keys)].sort();
}

/** Whether `filter` selects `event`, as the node decides it. */
export function filterSelects(filter: Record<string, any>): (event: ChainEvent) => boolean {
  const types = (filter.event_types as string[]) ?? [];
  const addresses = ((filter.addresses as string[]) ?? []).map(hex20);
  const topics = topicSlots(filter);
  const vmTypes = (filter.vm_types as unknown[]) ?? [];
  return (e) => {
    const h = e.cursor.height;
    if ((filter.from_block != null && h < filter.from_block) || (filter.to_block != null && h > filter.to_block)) return false;
    if (vmTypes.length > 0) return false;
    const type = e.kind === 'tx_outcome' ? 'transaction_included' : 'log';
    if (types.length > 0 && !types.includes(type)) return false;
    if (e.kind === 'tx_outcome') return addresses.length === 0 && topics.length === 0;
    const addr = e.address ?? [];
    const tail = hex(addr.length === 32 ? addr.slice(12) : addr);
    if (addresses.length > 0 && !addresses.includes(tail)) return false;
    if (topics.length === 0) return true;
    const t = (e.topics ?? []).map((x) => hex(x));
    if (t.some((x) => x.length !== 64)) return false;
    return topics.every((slot, i) => slot === null || (t[i] !== undefined && slot.includes(t[i])));
  };
}

/**
 * Checks that `answer`, a page of events whose own proofs the caller checked,
 * is every event the filter selects in the proof's range: the block-index
 * entries of every covered block are under certified headers, and every
 * candidate they list is answered or proven rejected. Throws when anything
 * was left out.
 */
export function verifyCompleteness(
  proof: CompletenessProof,
  certifiedCheckpointDigest: ArrayLike<number>,
  keys: string[],
  answer: ChainEvent[],
  selects: (e: ChainEvent) => boolean,
): void {
  if (proof.keys.length !== keys.length || proof.keys.some((k, i) => k !== keys[i])) fail('the proof covers other index keys');
  const span = proof.through.height >= proof.first_height ? proof.through.height - proof.first_height + 1 : 0;
  if (proof.blocks.length !== span) fail(`${proof.blocks.length} block proofs for ${span} heights`);
  if (span > 0) {
    let digest = checkpointDigest(proof.checkpoints[0] ?? fail('no checkpoint'));
    for (let i = 1; i < proof.checkpoints.length; i++) {
      if (!eq(bytes32(proof.checkpoints[i].prev, 'prev'), digest) || proof.checkpoints[i].index !== proof.checkpoints[i - 1].index + 1) {
        fail('a checkpoint does not follow its predecessor');
      }
      digest = checkpointDigest(proof.checkpoints[i]);
    }
    if (!eq(digest, certifiedCheckpointDigest)) fail('the proof does not end at the certified checkpoint');
  }
  const inRange = (c: Cursor) => (proof.after == null || cursorCmp(c, proof.after) > 0) && cursorCmp(c, proof.through) <= 0;
  const candidates = new Set<string>();
  proof.blocks.forEach((block, i) => {
    const height = proof.first_height + i;
    if (block.header.height !== height) fail(`block proof ${i} is not for height ${height}`);
    const covering = proof.checkpoints.find((c) => c.first_height <= height && height <= c.last_height) ?? fail(`no checkpoint covers ${height}`);
    if (!eq(rootFromPath(headerHash(block.header), block.block_path), bytes32(covering.blocks_root, 'blocks_root'))) {
      fail(`the header of block ${height} is not under its checkpoint`);
    }
    if (block.entries.length !== keys.length) fail(`block ${height} proves the wrong number of entries`);
    block.entries.forEach(({ entry, path }, k) => {
      if (!eq(rootFromPath(indexLeaf(entry), path), bytes32(block.header.event_root, 'event_root'))) {
        fail(`an index entry is not under block ${height}'s event root`);
      }
      const listed = covers(entry, keys[k]) ?? fail(`block ${height}'s entry does not speak for key ${keys[k]}`);
      for (const c of listed) {
        if (c.height !== height) fail(`block ${height}'s index lists another height`);
        if (inRange(c)) candidates.add(cursorKey(c));
      }
    });
  });
  const seen = new Set<string>();
  for (const e of answer) {
    if (!candidates.has(cursorKey(e.cursor))) fail(`event ${cursorKey(e.cursor)} is not a candidate`);
    if (!selects(e)) fail(`event ${cursorKey(e.cursor)} does not match the filter`);
    seen.add(cursorKey(e.cursor));
  }
  for (const p of proof.excluded) {
    verifyEventProof(p, certifiedCheckpointDigest);
    if (!candidates.has(cursorKey(p.event.cursor)) || selects(p.event)) fail(`event ${cursorKey(p.event.cursor)} is not a rejected candidate`);
    seen.add(cursorKey(p.event.cursor));
  }
  for (const c of candidates) if (!seen.has(c)) fail(`event ${c} was left out`);
}

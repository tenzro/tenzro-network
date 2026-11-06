/**
 * Agents' accounts on other chains, and the grants that bound them.
 *
 * `omniAccount(did).address(caip2, deployment)` derives an agent's account
 * on a chain from its DID and the chain's deployment of the agent account
 * code, as every Tenzro node does. `AgentAccountsClient` reads accounts,
 * grants and their proofs from a node, asks the agent's serving node for
 * grants and action signatures, and builds the transaction that settles an
 * account's report.
 */
import { createHash } from "node:crypto";
import { keccak256, type RpcClient } from "@tenzro/core";

/** Where the agent account code is deployed on one chain. Byte fields are arrays of numbers, as the node serves them. */
export type AccountDeployment =
  | { family: "eip155"; factory: number[]; init_code_hash: number[] }
  | { family: "solana"; program_id: number[] }
  | { family: "sui"; registry: number[] }
  | { family: "aptos"; creator: number[] }
  | { family: "stellar"; network_passphrase: string; factory: number[] }
  | { family: "cosmos"; hrp: string; factory: number[]; code_checksum: number[] }
  | { family: "tvm"; workchain: number; code_hash: number[]; code_depth: number };

/** An agent's account on one chain. */
export interface OmniAddress {
  caip2: string;
  address: string;
  raw: Uint8Array;
}

const enc = new TextEncoder();
const cat = (...parts: Uint8Array[]): Uint8Array => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
};
const hex = (b: Uint8Array): string => Buffer.from(b).toString("hex");
const sha256 = (...parts: Uint8Array[]): Uint8Array => new Uint8Array(createHash("sha256").update(cat(...parts)).digest());
const sha3_256 = (...parts: Uint8Array[]): Uint8Array => new Uint8Array(createHash("sha3-256").update(cat(...parts)).digest());

const MASK64 = (1n << 64n) - 1n;
const B2_IV = [
  0x6a09e667f3bcc908n, 0xbb67ae8584caa73bn, 0x3c6ef372fe94f82bn, 0xa54ff53a5f1d36f1n,
  0x510e527fade682d1n, 0x9b05688c2b3e6c1fn, 0x1f83d9abfb41bd6bn, 0x5be0cd19137e2179n,
];
const SIGMA = [
  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15], [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
  [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4], [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
  [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13], [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
  [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11], [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
  [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5], [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
];
const rotr = (x: bigint, n: bigint): bigint => ((x >> n) | (x << (64n - n))) & MASK64;

/** BLAKE2b with a 32-byte digest and no key. */
export function blake2b256(data: Uint8Array): Uint8Array {
  const h = B2_IV.slice();
  h[0] ^= 0x01010000n ^ 32n;
  const blocks = Math.max(1, Math.ceil(data.length / 128));
  for (let bi = 0; bi < blocks; bi++) {
    const block = new Uint8Array(128);
    block.set(data.subarray(bi * 128, bi * 128 + 128));
    const m = new Array<bigint>(16);
    for (let i = 0; i < 16; i++) {
      let w = 0n;
      for (let j = 7; j >= 0; j--) w = (w << 8n) | BigInt(block[i * 8 + j]);
      m[i] = w;
    }
    const last = bi === blocks - 1;
    const t = BigInt(last ? data.length : (bi + 1) * 128);
    const v = [...h, ...B2_IV];
    v[12] ^= t & MASK64;
    if (last) v[14] ^= MASK64;
    const g = (a: number, b: number, c: number, d: number, x: bigint, y: bigint) => {
      v[a] = (v[a] + v[b] + x) & MASK64;
      v[d] = rotr(v[d] ^ v[a], 32n);
      v[c] = (v[c] + v[d]) & MASK64;
      v[b] = rotr(v[b] ^ v[c], 24n);
      v[a] = (v[a] + v[b] + y) & MASK64;
      v[d] = rotr(v[d] ^ v[a], 16n);
      v[c] = (v[c] + v[d]) & MASK64;
      v[b] = rotr(v[b] ^ v[c], 63n);
    };
    for (let r = 0; r < 12; r++) {
      const s = SIGMA[r % 10];
      g(0, 4, 8, 12, m[s[0]], m[s[1]]);
      g(1, 5, 9, 13, m[s[2]], m[s[3]]);
      g(2, 6, 10, 14, m[s[4]], m[s[5]]);
      g(3, 7, 11, 15, m[s[6]], m[s[7]]);
      g(0, 5, 10, 15, m[s[8]], m[s[9]]);
      g(1, 6, 11, 12, m[s[10]], m[s[11]]);
      g(2, 7, 8, 13, m[s[12]], m[s[13]]);
      g(3, 4, 9, 14, m[s[14]], m[s[15]]);
    }
    for (let i = 0; i < 8; i++) h[i] ^= v[i] ^ v[i + 8];
  }
  const out = new Uint8Array(32);
  for (let i = 0; i < 4; i++) for (let j = 0; j < 8; j++) out[i * 8 + j] = Number((h[i] >> BigInt(8 * j)) & 0xffn);
  return out;
}

const P25519 = (1n << 255n) - 19n;
const modp = (x: bigint): bigint => ((x % P25519) + P25519) % P25519;
const powp = (b: bigint, e: bigint): bigint => {
  let r = 1n;
  b = modp(b);
  while (e > 0n) {
    if (e & 1n) r = (r * b) % P25519;
    b = (b * b) % P25519;
    e >>= 1n;
  }
  return r;
};
const D25519 = modp(-121665n * powp(121666n, P25519 - 2n));
const SQRT_M1 = powp(2n, (P25519 - 1n) / 4n);

/** Whether 32 bytes decompress to a point of the Ed25519 curve. */
function onEd25519(b: Uint8Array): boolean {
  let y = 0n;
  for (let i = 31; i >= 0; i--) y = (y << 8n) | BigInt(i === 31 ? b[i] & 0x7f : b[i]);
  if (y >= P25519) return false;
  const y2 = (y * y) % P25519;
  const u = modp(y2 - 1n);
  const v = modp(D25519 * y2 + 1n);
  const v3 = (v * v * v) % P25519;
  let x = (u * v3 % P25519) * powp(u * v3 * v3 * v % P25519, (P25519 - 5n) / 8n) % P25519;
  const vx2 = (v * x * x) % P25519;
  if (vx2 === u) return true;
  if (vx2 === modp(-u)) {
    x = (x * SQRT_M1) % P25519;
    return true;
  }
  return false;
}

const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
function base58(b: Uint8Array): string {
  let n = 0n;
  for (const x of b) n = (n << 8n) | BigInt(x);
  let out = "";
  while (n > 0n) {
    out = B58[Number(n % 58n)] + out;
    n /= 58n;
  }
  for (const x of b) {
    if (x !== 0) break;
    out = "1" + out;
  }
  return out;
}
function unbase58(s: string): Uint8Array {
  let n = 0n;
  for (const c of s) {
    const i = B58.indexOf(c);
    if (i < 0) throw new Error("not base58");
    n = n * 58n + BigInt(i);
  }
  const bytes: number[] = [];
  while (n > 0n) {
    bytes.unshift(Number(n & 0xffn));
    n >>= 8n;
  }
  for (const c of s) {
    if (c !== "1") break;
    bytes.unshift(0);
  }
  return new Uint8Array(bytes);
}

function bech32(hrp: string, data: Uint8Array): string {
  const CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
  const words: number[] = [];
  let acc = 0;
  let bits = 0;
  for (const x of data) {
    acc = (acc << 8) | x;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      words.push((acc >> bits) & 31);
    }
  }
  if (bits > 0) words.push((acc << (5 - bits)) & 31);
  const polymod = (values: number[]) => {
    const G = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
    let chk = 1;
    for (const v of values) {
      const b = chk >> 25;
      chk = ((chk & 0x1ffffff) << 5) ^ v;
      for (let i = 0; i < 5; i++) if ((b >> i) & 1) chk ^= G[i];
    }
    return chk;
  };
  const expand = [...hrp].map((c) => c.charCodeAt(0) >> 5).concat([0], [...hrp].map((c) => c.charCodeAt(0) & 31));
  const mod = polymod(expand.concat(words, [0, 0, 0, 0, 0, 0])) ^ 1;
  const check = [0, 1, 2, 3, 4, 5].map((i) => (mod >> (5 * (5 - i))) & 31);
  return hrp + "1" + words.concat(check).map((w) => CHARSET[w]).join("");
}

/** A Stellar StrKey: base32 of the version byte, the payload and its CRC16-XModem (little-endian). */
export function stellarStrkey(version: number, payload: Uint8Array): string {
  const b = cat(Uint8Array.of(version), payload);
  let crc = 0;
  for (const x of b) {
    crc ^= x << 8;
    for (let i = 0; i < 8; i++) crc = crc & 0x8000 ? ((crc << 1) ^ 0x1021) & 0xffff : (crc << 1) & 0xffff;
  }
  const all = cat(b, Uint8Array.of(crc & 0xff, crc >> 8));
  const A = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let out = "";
  let acc = 0;
  let bits = 0;
  for (const x of all) {
    acc = (acc << 8) | x;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out += A[(acc >> bits) & 31];
    }
    acc &= (1 << bits) - 1;
  }
  if (bits > 0) out += A[(acc << (5 - bits)) & 31];
  return out;
}

function eip55(raw: Uint8Array): string {
  const lower = hex(raw);
  const h = keccak256(enc.encode(lower));
  let out = "0x";
  for (let i = 0; i < lower.length; i++) {
    const nibble = (h[i >> 1] >> (i % 2 === 0 ? 4 : 0)) & 0xf;
    out += /[a-f]/.test(lower[i]) && nibble >= 8 ? lower[i].toUpperCase() : lower[i];
  }
  return out;
}

const be = (v: bigint | number, n: number): Uint8Array => {
  const out = new Uint8Array(n);
  let x = BigInt(v);
  for (let i = n - 1; i >= 0; i--) {
    out[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  return out;
};
const le = (v: bigint | number, n: number): Uint8Array => be(v, n).reverse();
const bytes = (a: number[]): Uint8Array => Uint8Array.from(a);

/** The per-DID salt. */
export function omniSalt(did: string): Uint8Array {
  return sha256(enc.encode("tenzro/omni-account/v1"), enc.encode(did));
}

/** The state tree key of the grant of `did` on `caip2`. */
export function grantTreeKey(did: string, caip2: string): Uint8Array {
  const key = "storage:" + "f".repeat(40) + ":" + hex(enc.encode(`agent_grant:${did}:${caip2}`));
  return sha256(enc.encode("tenzro.state-trie.key"), le(5, 2), enc.encode("state"), enc.encode(key));
}

/** The account of `did` on `caip2` under `deployment`. */
export function omniAddress(did: string, caip2: string, d: AccountDeployment): OmniAddress {
  const ns = caip2.split(":")[0];
  if (ns !== d.family) throw new Error(`the deployment is for ${d.family}, the chain is ${caip2}`);
  const s = omniSalt(did);
  switch (d.family) {
    case "eip155": {
      const raw = keccak256(cat(Uint8Array.of(0xff), bytes(d.factory), s, bytes(d.init_code_hash))).subarray(12);
      return { caip2, address: eip55(raw), raw };
    }
    case "solana": {
      const seed = sha256(enc.encode(did));
      for (let bump = 255; bump >= 0; bump--) {
        const c = sha256(enc.encode("agent"), seed, Uint8Array.of(bump), bytes(d.program_id), enc.encode("ProgramDerivedAddress"));
        if (!onEd25519(c)) return { caip2, address: base58(c), raw: c };
      }
      throw new Error("no program address");
    }
    case "sui": {
      const keyBcs = cat(Uint8Array.of(32), s);
      const tag = cat(Uint8Array.of(7), be(2, 32), Uint8Array.of(14), enc.encode("derived_object"), Uint8Array.of(16), enc.encode("DerivedObjectKey"), Uint8Array.of(1, 6, 1));
      const raw = blake2b256(cat(Uint8Array.of(0xf0), bytes(d.registry), le(keyBcs.length, 8), keyBcs, tag));
      return { caip2, address: "0x" + hex(raw), raw };
    }
    case "aptos": {
      const raw = sha3_256(bytes(d.creator), s, Uint8Array.of(0xfe));
      return { caip2, address: "0x" + hex(raw), raw };
    }
    case "stellar": {
      const raw = sha256(be(8, 4), sha256(enc.encode(d.network_passphrase)), be(0, 4), be(1, 4), bytes(d.factory), s);
      return { caip2, address: stellarStrkey(0x10, raw), raw };
    }
    case "cosmos": {
      const part = (p: Uint8Array) => cat(be(p.length, 8), p);
      const key = cat(enc.encode("wasm\0"), part(bytes(d.code_checksum)), part(bytes(d.factory)), part(s), part(new Uint8Array(0)));
      const raw = sha256(sha256(enc.encode("module")), key);
      return { caip2, address: bech32(d.hrp, raw), raw };
    }
    case "tvm": {
      const dataHash = sha256(Uint8Array.of(0, 128), sha256(enc.encode(did)), grantTreeKey(did, caip2));
      const raw = sha256(Uint8Array.of(2, 1, 0x34), be(d.code_depth, 2), be(0, 2), bytes(d.code_hash), dataHash);
      return { caip2, address: `${d.workchain}:${hex(raw)}`, raw };
    }
  }
}

/** CAIP-10 of an account. */
export const toCaip10 = (a: OmniAddress): string => `${a.caip2}:${a.address}`;

/** The ERC-7930 interoperable address of an EVM or Solana account; undefined for other families. */
export function toErc7930(a: OmniAddress): Uint8Array | undefined {
  const [ns, ref] = a.caip2.split(":");
  let chainType: number[];
  let chainRef: Uint8Array;
  if (ns === "eip155") {
    chainType = [0, 0];
    let n = BigInt(ref);
    const b: number[] = [];
    while (n > 0n) {
      b.unshift(Number(n & 0xffn));
      n >>= 8n;
    }
    chainRef = Uint8Array.from(b.length ? b : [0]);
  } else if (ns === "solana") {
    chainType = [0, 2];
    chainRef = unbase58(ref);
  } else {
    return undefined;
  }
  return cat(Uint8Array.of(0, 1, ...chainType, chainRef.length), chainRef, Uint8Array.of(a.raw.length), a.raw);
}

/** An agent's accounts, by DID. */
export function omniAccount(did: string) {
  return {
    address: (caip2: string, deployment: AccountDeployment) => omniAddress(did, caip2, deployment),
  };
}

/** An action as the grant's digest covers it. */
export interface RemoteAction {
  target: string;
  selector: string;
  amount: string;
  relay_refund: string;
  data: string;
}

/** The encoded action: target and selector (u16-prefixed), amount and refund (u128), data (u32-prefixed), big-endian. */
export function encodeAction(a: RemoteAction): Uint8Array {
  const t = Buffer.from(a.target.replace(/^0x/, ""), "hex");
  const sel = Buffer.from(a.selector.replace(/^0x/, ""), "hex");
  const data = Buffer.from(a.data.replace(/^0x/, ""), "hex");
  return cat(be(t.length, 2), t, be(sel.length, 2), sel, be(BigInt(a.amount), 16), be(BigInt(a.relay_refund), 16), be(data.length, 4), data);
}

/** The digest serving nodes sign for action `nonce` under grant `seq` of `account` (32 bytes, left-padded) on `caip2`. */
export function actDigest(caip2: string, account: Uint8Array, seq: bigint | number, nonce: bigint | number, action: Uint8Array): Uint8Array {
  return sha256(enc.encode("tenzro/agent-act/v1"), sha256(enc.encode(caip2)), account, be(seq, 8), be(nonce, 8), action);
}

/** The digest a serving node signs for a voucher paying `cumulative` on channel `channelId` of `account` (32 bytes, left-padded) on `caip2`. */
export function channelVoucherDigest(caip2: string, account: Uint8Array, channelId: bigint | number, cumulative: bigint | number): Uint8Array {
  return sha256(enc.encode("tenzro/agent-channel/v1"), sha256(enc.encode(caip2)), account, be(channelId, 8), be(cumulative, 16));
}

/** The 104 bytes a paying action carries: the Tenzro payee, the request and quote digests it bought, and the USD price (micro-units). */
export function payData(payee: Uint8Array, requestDigest: Uint8Array, quoteDigest: Uint8Array, usdE6: bigint | number): Uint8Array {
  for (const [name, b] of [["payee", payee], ["requestDigest", requestDigest], ["quoteDigest", quoteDigest]] as const) {
    if (b.length !== 32) throw new Error(`${name} must be 32 bytes`);
  }
  return cat(payee, requestDigest, quoteDigest, be(usdE6, 8));
}

/** Reads agents' accounts and grants, and asks serving nodes for grants and action signatures (with the agent's access token on the transport). */
export class AgentAccountsClient {
  constructor(private rpc: RpcClient) {}

  /** The agent's account on every configured chain. */
  accounts(did: string): Promise<unknown> {
    return this.rpc.call("tenzro_agentAccounts", { did });
  }

  /** Issue a grant on `chain` as the agent. */
  requestGrant(chain: string, grant: Record<string, unknown>, stepUp?: Record<string, unknown>): Promise<unknown> {
    return this.rpc.call("tenzro_requestRemoteGrant", stepUp ? { chain, grant, step_up: stepUp } : { chain, grant });
  }

  /** The agent's grant on `chain` and its state proof. */
  grantProof(did: string, chain: string, checkpoint?: number): Promise<unknown> {
    return this.rpc.call("tenzro_getAgentGrantProof", { did, chain, checkpoint });
  }

  /** The digest of an action and the proofs the account checks. */
  buildAction(did: string, chain: string, nonce: number, action: RemoteAction): Promise<unknown> {
    return this.rpc.call("tenzro_buildRemoteAction", { did, chain, nonce, action });
  }

  /**
   * The consent that makes the agent's account on an EVM `chain` the agentWallet of ERC-8004 entry `agentId` owned by
   * `owner`: the registry's EIP-712 digest, the approveHash action approving it (sign it with `signAction`) and the
   * setAgentWallet calldata the owner sends. The canonical registry when `registry` is absent.
   */
  walletConsent(
    did: string,
    chain: string,
    agentId: number,
    owner: string,
    deadline: number,
    registry?: string,
  ): Promise<unknown> {
    return this.rpc.call("tenzro_agentWalletConsent", {
      did,
      chain,
      agent_id: agentId,
      owner,
      deadline,
      ...(registry ? { registry } : {}),
    });
  }

  /** The serving node's signature over an action, as the agent. */
  signAction(chain: string, nonce: number, action: RemoteAction): Promise<unknown> {
    return this.rpc.call("tenzro_signRemoteAction", { chain, nonce, action });
  }

  /** The serving node's signature over a voucher on a channel the agent's account holds on `chain`, as the agent. */
  signChannelVoucher(chain: string, channelId: number, cumulative: bigint | string): Promise<unknown> {
    return this.rpc.call("tenzro_signRemoteChannelVoucher", { chain, channel_id: channelId, cumulative_amount: cumulative.toString() });
  }

  /** The `Payment` transaction type that records one payment the agent's account on `chain` reported, for any signer to submit. */
  static prove(agentDid: string, chain: string, delivery: Uint8Array): Record<string, unknown> {
    return { Payment: { op: { proven: { agent_did: agentDid, chain, delivery: hex(delivery) } } } };
  }

  /** The `RemoteGrantSettle` transaction type that settles one report of the agent's account on `chain`, for any signer to submit. */
  static relay(agentDid: string, chain: string, delivery: Uint8Array): Record<string, unknown> {
    return { RemoteGrantSettle: { agent_did: agentDid, chain, delivery: hex(delivery) } };
  }
}

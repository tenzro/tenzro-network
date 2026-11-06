// Standard EIP-7702 set-code transactions (type 0x04), built for an external
// secp256k1 signer.
//
// The SDK holds no signing key. It produces the two digests a wallet or
// hardware signer signs (the authorization digest and the transaction digest)
// and assembles the signed bytes from the signatures it is handed. The raw
// bytes go to `eth_sendRawTransaction`; the node recovers the sender and every
// authority from their signatures and installs the delegation designator in
// the authority's code.
//
//   authorization digest = keccak256(0x05 || rlp([chain_id, address, nonce]))
//   transaction digest   = keccak256(0x04 || rlp([chain_id, nonce, max_priority_fee_per_gas,
//                            max_fee_per_gas, gas_limit, to, value, data, access_list,
//                            authorization_list]))
//   raw transaction      = 0x04 || rlp([...same fields..., y_parity, r, s])

import { keccak256 } from "@tenzro/core";

export const SET_CODE_TX_TYPE = 0x04;
export const AUTHORIZATION_MAGIC = 0x05;

/** A secp256k1 signature as a wallet returns it; `r` and `s` are 0x-hex. */
export interface EcdsaSignature {
  yParity: 0 | 1;
  r: string;
  s: string;
}

/** The authority lets `address`'s code run as its own. */
export interface Authorization {
  /** The chain the authorization is valid on (0 = every chain). */
  chainId: bigint | number;
  /** The delegate contract, 0x-hex. */
  address: string;
  /** The authority's account nonce at the time the transaction executes. */
  nonce: bigint | number;
}

export interface SignedAuthorization extends Authorization {
  signature: EcdsaSignature;
}

export interface AccessListItem {
  address: string;
  storageKeys: string[];
}

/** A set-code transaction before the sender signs it. */
export interface SetCodeTransaction {
  chainId: bigint | number;
  nonce: bigint | number;
  maxPriorityFeePerGas: bigint;
  maxFeePerGas: bigint;
  gasLimit: bigint | number;
  /** A set-code transaction always has a destination. */
  to: string;
  value: bigint;
  data: string;
  accessList: AccessListItem[];
  /** At least one signed authorization. */
  authorizationList: SignedAuthorization[];
}

function fromHex(s: string, len?: number): Uint8Array {
  const h = s.startsWith("0x") ? s.slice(2) : s;
  if (h.length % 2 !== 0 || /[^0-9a-fA-F]/.test(h)) throw new Error(`not hex: ${s}`);
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.slice(2 * i, 2 * i + 2), 16);
  if (len !== undefined && out.length !== len) throw new Error(`expected ${len} bytes: ${s}`);
  return out;
}

function toHex(b: Uint8Array): string {
  return "0x" + Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}

function concat(parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const p of parts) {
    out.set(p, at);
    at += p.length;
  }
  return out;
}

function lengthPrefix(len: number, short: number, long: number): Uint8Array {
  if (len < 56) return Uint8Array.of(short + len);
  const be: number[] = [];
  for (let n = len; n > 0; n = Math.floor(n / 256)) be.unshift(n % 256);
  return Uint8Array.of(long + be.length, ...be);
}

function rlpBytes(b: Uint8Array): Uint8Array {
  if (b.length === 1 && b[0] < 0x80) return b;
  return concat([lengthPrefix(b.length, 0x80, 0xb7), b]);
}

function rlpUint(v: bigint | number): Uint8Array {
  let n = BigInt(v);
  if (n < 0n) throw new Error("negative integer");
  const be: number[] = [];
  while (n > 0n) {
    be.unshift(Number(n & 0xffn));
    n >>= 8n;
  }
  return rlpBytes(Uint8Array.from(be));
}

/** A signature scalar is an integer: leading zero bytes are dropped. */
function rlpWord(s: string): Uint8Array {
  return rlpUint(BigInt(toHex(fromHex(s, 32))));
}

function rlpList(items: Uint8Array[]): Uint8Array {
  const body = concat(items);
  return concat([lengthPrefix(body.length, 0xc0, 0xf7), body]);
}

/** The digest the authority signs. */
export function authorizationSigningHash(a: Authorization): string {
  const body = rlpList([rlpUint(a.chainId), rlpBytes(fromHex(a.address, 20)), rlpUint(a.nonce)]);
  return toHex(keccak256(concat([Uint8Array.of(AUTHORIZATION_MAGIC), body])));
}

function authorizationRlp(a: SignedAuthorization): Uint8Array {
  return rlpList([
    rlpUint(a.chainId),
    rlpBytes(fromHex(a.address, 20)),
    rlpUint(a.nonce),
    rlpUint(a.signature.yParity),
    rlpWord(a.signature.r),
    rlpWord(a.signature.s),
  ]);
}

function fields(tx: SetCodeTransaction): Uint8Array[] {
  if (tx.authorizationList.length === 0) {
    throw new Error("a set-code transaction needs at least one authorization");
  }
  const access = tx.accessList.map((i) =>
    rlpList([rlpBytes(fromHex(i.address, 20)), rlpList(i.storageKeys.map((k) => rlpBytes(fromHex(k, 32))))]),
  );
  return [
    rlpUint(tx.chainId),
    rlpUint(tx.nonce),
    rlpUint(tx.maxPriorityFeePerGas),
    rlpUint(tx.maxFeePerGas),
    rlpUint(tx.gasLimit),
    rlpBytes(fromHex(tx.to, 20)),
    rlpUint(tx.value),
    rlpBytes(fromHex(tx.data)),
    rlpList(access),
    rlpList(tx.authorizationList.map(authorizationRlp)),
  ];
}

/** The digest the sender signs. */
export function setCodeTransactionSigningHash(tx: SetCodeTransaction): string {
  return toHex(keccak256(concat([Uint8Array.of(SET_CODE_TX_TYPE), rlpList(fields(tx))])));
}

/** The raw signed transaction (0x-hex) for `eth_sendRawTransaction`. */
export function encodeSignedSetCodeTransaction(tx: SetCodeTransaction, signature: EcdsaSignature): string {
  const all = [...fields(tx), rlpUint(signature.yParity), rlpWord(signature.r), rlpWord(signature.s)];
  return toHex(concat([Uint8Array.of(SET_CODE_TX_TYPE), rlpList(all)]));
}

/** The hash a wallet and the node record a raw transaction under. */
export function rawTransactionHash(raw: string): string {
  return toHex(keccak256(fromHex(raw)));
}

/** The code an authority carries once its delegation is installed. */
export function delegationDesignator(address: string): string {
  return "0xef0100" + toHex(fromHex(address, 20)).slice(2);
}

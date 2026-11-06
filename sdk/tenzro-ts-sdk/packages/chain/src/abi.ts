/**
 * Solidity ABI encoding and decoding, offline: calldata for any EVM contract
 * or Tenzro precompile, and the values its return data and logs carry.
 *
 * Types: `uint<M>`, `int<M>`, `address`, `bool`, `bytes<M>`, `bytes`,
 * `string`, arrays `T[]` and `T[k]`, and tuples `(T1,T2,...)`.
 *
 * Values in: integers as `bigint`, `number` or a decimal or `0x` string;
 * addresses as `0x` hex; byte strings as `Uint8Array` or `0x` hex; arrays
 * and tuples as arrays. Values out: integers as `bigint`, addresses and byte
 * strings as lowercase `0x` hex, arrays and tuples as arrays.
 */
import { keccak256 } from "@tenzro/core";

type AbiType =
  | { kind: "uint" | "int"; bits: number }
  | { kind: "address" | "bool" | "bytes" | "string" }
  | { kind: "fixedBytes"; size: number }
  | { kind: "array"; of: AbiType; length?: number }
  | { kind: "tuple"; of: AbiType[] };

/** A value of an ABI type, as taken by `abiEncode` and returned by `abiDecode`. */
export type AbiValue = bigint | number | string | boolean | Uint8Array | AbiValue[];

const enc = new TextEncoder();
const dec = new TextDecoder("utf-8", { fatal: true });

const toHex = (b: Uint8Array): string => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
function fromHex(h: string): Uint8Array {
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.slice(2 * i, 2 * i + 2), 16);
  return out;
}

function splitTop(s: string): string[] {
  if (s === "") return [];
  const out: string[] = [];
  let depth = 0;
  let start = 0;
  for (let i = 0; i < s.length; i++) {
    if (s[i] === "(") depth++;
    else if (s[i] === ")") depth--;
    else if (s[i] === "," && depth === 0) {
      out.push(s.slice(start, i));
      start = i + 1;
    }
    if (depth < 0) throw new Error(`unbalanced parentheses in ${s}`);
  }
  if (depth !== 0) throw new Error(`unbalanced parentheses in ${s}`);
  out.push(s.slice(start));
  return out;
}

function parseType(raw: string): AbiType {
  const t = raw.trim();
  const arr = /^(.*)\[(\d*)\]$/.exec(t);
  if (arr) {
    const of = parseType(arr[1]);
    if (arr[2] === "") return { kind: "array", of };
    const length = Number(arr[2]);
    if (!Number.isSafeInteger(length) || length <= 0) throw new Error(`bad array length in ${t}`);
    return { kind: "array", of, length };
  }
  if (t.startsWith("(") && t.endsWith(")")) return { kind: "tuple", of: splitTop(t.slice(1, -1)).map(parseType) };
  if (t === "address" || t === "bool" || t === "bytes" || t === "string") return { kind: t };
  const int = /^(u?int)(\d*)$/.exec(t);
  if (int) {
    const bits = int[2] === "" ? 256 : Number(int[2]);
    if (bits < 8 || bits > 256 || bits % 8 !== 0) throw new Error(`bad integer width in ${t}`);
    return { kind: int[1] === "uint" ? "uint" : "int", bits };
  }
  const fb = /^bytes(\d+)$/.exec(t);
  if (fb) {
    const size = Number(fb[1]);
    if (size < 1 || size > 32) throw new Error(`bad byte width in ${t}`);
    return { kind: "fixedBytes", size };
  }
  throw new Error(`unsupported ABI type: ${t}`);
}

function canonical(t: AbiType): string {
  switch (t.kind) {
    case "uint":
    case "int":
      return `${t.kind}${t.bits}`;
    case "fixedBytes":
      return `bytes${t.size}`;
    case "array":
      return `${canonical(t.of)}[${t.length ?? ""}]`;
    case "tuple":
      return `(${t.of.map(canonical).join(",")})`;
    default:
      return t.kind;
  }
}

function dynamic(t: AbiType): boolean {
  if (t.kind === "bytes" || t.kind === "string") return true;
  if (t.kind === "array") return t.length === undefined || dynamic(t.of);
  if (t.kind === "tuple") return t.of.some(dynamic);
  return false;
}

/** Bytes a static type takes in the head. */
function headSize(t: AbiType): number {
  if (dynamic(t)) return 32;
  if (t.kind === "array") return t.length! * headSize(t.of);
  if (t.kind === "tuple") return t.of.reduce((n, x) => n + headSize(x), 0);
  return 32;
}

function hexBytes(v: AbiValue, what: string): Uint8Array {
  if (v instanceof Uint8Array) return v;
  if (typeof v === "string" && /^0x([0-9a-fA-F]{2})*$/.test(v)) return fromHex(v.slice(2));
  throw new Error(`${what} must be bytes or 0x hex`);
}

function toBigInt(v: AbiValue, what: string): bigint {
  if (typeof v === "bigint") return v;
  if (typeof v === "number") {
    if (!Number.isSafeInteger(v)) throw new Error(`${what}: ${v} is not a safe integer; pass a bigint`);
    return BigInt(v);
  }
  if (typeof v === "string" && /^(-?\d+|0x[0-9a-fA-F]+)$/.test(v)) return BigInt(v);
  throw new Error(`${what} must be an integer`);
}

function word(n: bigint): Uint8Array {
  const w = new Uint8Array(32);
  let x = n < 0n ? (1n << 256n) + n : n;
  for (let i = 31; i >= 0; i--) {
    w[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  return w;
}

function padRight(b: Uint8Array): Uint8Array {
  const out = new Uint8Array(Math.ceil(b.length / 32) * 32);
  out.set(b);
  return out;
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

function encodeSequence(types: AbiType[], values: AbiValue[]): Uint8Array {
  if (types.length !== values.length) throw new Error(`expected ${types.length} values, got ${values.length}`);
  const heads: Uint8Array[] = [];
  const tails: Uint8Array[] = [];
  let offset = types.reduce((n, t) => n + headSize(t), 0);
  types.forEach((t, i) => {
    const e = encodeOne(t, values[i]);
    if (dynamic(t)) {
      heads.push(word(BigInt(offset)));
      tails.push(e);
      offset += e.length;
    } else {
      heads.push(e);
    }
  });
  return concat([...heads, ...tails]);
}

function encodeOne(t: AbiType, v: AbiValue): Uint8Array {
  const what = canonical(t);
  switch (t.kind) {
    case "uint": {
      const n = toBigInt(v, what);
      if (n < 0n || n >= 1n << BigInt(t.bits)) throw new Error(`${what}: ${n} out of range`);
      return word(n);
    }
    case "int": {
      const n = toBigInt(v, what);
      const lim = 1n << BigInt(t.bits - 1);
      if (n < -lim || n >= lim) throw new Error(`${what}: ${n} out of range`);
      return word(n);
    }
    case "address": {
      const b = hexBytes(v, what);
      if (b.length !== 20) throw new Error("address must be 20 bytes");
      const w = new Uint8Array(32);
      w.set(b, 12);
      return w;
    }
    case "bool":
      if (typeof v !== "boolean") throw new Error("bool must be true or false");
      return word(v ? 1n : 0n);
    case "fixedBytes": {
      const b = hexBytes(v, what);
      if (b.length !== t.size) throw new Error(`${what} must be ${t.size} bytes`);
      return padRight(b);
    }
    case "bytes": {
      const b = hexBytes(v, what);
      return concat([word(BigInt(b.length)), padRight(b)]);
    }
    case "string": {
      if (typeof v !== "string") throw new Error("string must be a string");
      const b = enc.encode(v);
      return concat([word(BigInt(b.length)), padRight(b)]);
    }
    case "array": {
      if (!Array.isArray(v)) throw new Error(`${what} must be an array`);
      if (t.length !== undefined && v.length !== t.length) throw new Error(`${what} must hold ${t.length} values`);
      const body = encodeSequence(v.map(() => t.of), v);
      return t.length === undefined ? concat([word(BigInt(v.length)), body]) : body;
    }
    case "tuple":
      if (!Array.isArray(v)) throw new Error(`${what} must be an array of its fields`);
      return encodeSequence(t.of, v);
  }
}

class Reader {
  constructor(readonly data: Uint8Array) {}
  word(at: number): Uint8Array {
    if (at < 0 || at + 32 > this.data.length) throw new Error(`ABI data ends before byte ${at + 32}`);
    return this.data.subarray(at, at + 32);
  }
  uint(at: number): bigint {
    return BigInt("0x" + toHex(this.word(at)));
  }
  /** A length or offset: must fit the data. */
  size(at: number): number {
    const n = this.uint(at);
    if (n > BigInt(this.data.length)) throw new Error(`ABI length or offset ${n} beyond the data`);
    return Number(n);
  }
}

function decodeSequence(r: Reader, types: AbiType[], base: number): AbiValue[] {
  let at = base;
  return types.map((t) => {
    const v = dynamic(t) ? decodeOne(r, t, base + r.size(at)) : decodeOne(r, t, at);
    at += headSize(t);
    return v;
  });
}

const hex = (b: Uint8Array) => "0x" + toHex(b);

function decodeOne(r: Reader, t: AbiType, at: number): AbiValue {
  const what = canonical(t);
  switch (t.kind) {
    case "uint": {
      const n = r.uint(at);
      if (n >= 1n << BigInt(t.bits)) throw new Error(`${what} out of range`);
      return n;
    }
    case "int": {
      let n = r.uint(at);
      if (n >= 1n << 255n) n -= 1n << 256n;
      const lim = 1n << BigInt(t.bits - 1);
      if (n < -lim || n >= lim) throw new Error(`${what} out of range`);
      return n;
    }
    case "address": {
      const w = r.word(at);
      if (w.subarray(0, 12).some((b) => b !== 0)) throw new Error("address has non-zero high bytes");
      return hex(w.subarray(12));
    }
    case "bool": {
      const n = r.uint(at);
      if (n > 1n) throw new Error("bool is neither 0 nor 1");
      return n === 1n;
    }
    case "fixedBytes": {
      const w = r.word(at);
      if (w.subarray(t.size).some((b) => b !== 0)) throw new Error(`${what} has non-zero padding`);
      return hex(w.subarray(0, t.size));
    }
    case "bytes":
    case "string": {
      const len = r.size(at);
      if (at + 32 + len > r.data.length) throw new Error(`${what} runs past the data`);
      const b = r.data.subarray(at + 32, at + 32 + len);
      return t.kind === "bytes" ? hex(b) : dec.decode(b);
    }
    case "array": {
      if (t.length !== undefined) return decodeSequence(r, Array(t.length).fill(t.of), at);
      const len = r.size(at);
      if (len * headSize(t.of) > r.data.length) throw new Error(`${what} length beyond the data`);
      return decodeSequence(r, Array(len).fill(t.of), at + 32);
    }
    case "tuple":
      return decodeSequence(r, t.of, at);
  }
}

/** Encode `values` as the ABI encodes a function's arguments of `types`. */
export function abiEncode(types: string[], values: AbiValue[]): Uint8Array {
  return encodeSequence(types.map(parseType), values);
}

/** Decode `data` (return data, log data, or calldata after its selector) as values of `types`. */
export function abiDecode(types: string[], data: Uint8Array | string): AbiValue[] {
  const bytes = typeof data === "string" ? hexBytes(data, "data") : data;
  return decodeSequence(new Reader(bytes), types.map(parseType), 0);
}

/** `name(type1,type2)` split into its name and argument types, normalized (`uint` is `uint256`). */
export function parseSignature(signature: string): { name: string; types: string[]; canonical: string } {
  const m = /^\s*([A-Za-z_$][A-Za-z0-9_$]*)\s*\((.*)\)\s*$/.exec(signature);
  if (!m) throw new Error(`not a function signature: ${signature}`);
  const parsed = splitTop(m[2].replace(/\s+/g, "")).map(parseType);
  const types = parsed.map(canonical);
  return { name: m[1], types, canonical: `${m[1]}(${types.join(",")})` };
}

/** The 4-byte selector of a function signature: the first bytes of its keccak-256. */
export function functionSelector(signature: string): Uint8Array {
  return keccak256(enc.encode(parseSignature(signature).canonical)).slice(0, 4);
}

/** An event signature's topic 0. */
export function eventTopic(signature: string): string {
  return hex(keccak256(enc.encode(parseSignature(signature).canonical)));
}

/** Calldata for `signature` called with `values`: selector, then the encoded arguments. */
export function encodeFunctionCall(signature: string, values: AbiValue[]): Uint8Array {
  return concat([functionSelector(signature), abiEncode(parseSignature(signature).types, values)]);
}

/** Calldata for a fixed 4-byte selector with arguments of `types` (for selectors that are not a signature's hash). */
export function encodeWithSelector(selector: Uint8Array | string, types: string[], values: AbiValue[]): Uint8Array {
  const sel = typeof selector === "string" ? hexBytes(selector, "selector") : selector;
  if (sel.length !== 4) throw new Error("a selector is 4 bytes");
  return concat([sel, abiEncode(types, values)]);
}

/** Split calldata into its selector and decoded arguments of `types`. */
export function decodeFunctionCall(types: string[], calldata: Uint8Array | string): { selector: string; args: AbiValue[] } {
  const bytes = typeof calldata === "string" ? hexBytes(calldata, "calldata") : calldata;
  if (bytes.length < 4) throw new Error("calldata is shorter than a selector");
  return { selector: hex(bytes.subarray(0, 4)), args: abiDecode(types, bytes.subarray(4)) };
}

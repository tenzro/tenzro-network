/**
 * DID envelopes over whole JSON-RPC requests.
 *
 * Some methods change something that belongs to a DID (registering a machine
 * under a controller is one), so the request carries `did_envelope`: the
 * DID's signature over the method name and a hash of every other parameter.
 * The node rebuilds the same bytes (`tenzro_identity::envelope`) and checks
 * the signature against the key the DID resolves to. The signature comes
 * from a {@link HybridSigner}: a passkey, TPM or Secure Enclave key. The SDK
 * never holds a private key.
 */

import { stringifyExact } from "./exact-json";
import { type HybridSigner, compositeMessageRepresentative, compositeSignatureJson } from "./wallet";

/** Signature context of a DID envelope. */
export const DID_ENVELOPE_CONTEXT = new TextEncoder().encode("tenzro/did-envelope");

/** Domain tag at the start of every envelope preimage. */
const ENVELOPE_DOMAIN = new TextEncoder().encode("tenzro-did-envelope:v1");

/**
 * The bytes a request envelope binds: the params object without its
 * `did_envelope` field, as JSON with object keys sorted at every level and no
 * whitespace. Fields left `undefined` are left out, as they are on the wire.
 */
export function requestBinding(params: Record<string, unknown>): Uint8Array {
  return new TextEncoder().encode(canonical(params, true));
}

function canonical(value: unknown, skipEnvelope: boolean): string {
  if (Array.isArray(value)) {
    return `[${value.map((v) => (v === undefined ? "null" : canonical(v, false))).join(",")}]`;
  }
  if (value !== null && typeof value === "object" && !(value instanceof Uint8Array)) {
    const entries = Object.entries(value as Record<string, unknown>)
      .filter(([k, v]) => v !== undefined && !(skipEnvelope && k === "did_envelope"))
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
    return `{${entries.map(([k, v]) => `${JSON.stringify(k)}:${canonical(v, false)}`).join(",")}}`;
  }
  if (value instanceof Uint8Array) {
    throw new Error("requestBinding: encode byte fields as hex strings before signing");
  }
  return stringifyExact(value);
}

/** SHA-256 of `bytes`. */
async function sha256(bytes: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await globalThis.crypto.subtle.digest("SHA-256", bytes as BufferSource));
}

function u32be(n: number): Uint8Array {
  const out = new Uint8Array(4);
  new DataView(out.buffer).setUint32(0, n, false);
  return out;
}

function u64be(n: number): Uint8Array {
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, BigInt(n), false);
  return out;
}

function concat(parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

function hex(bytes: Uint8Array): string {
  let out = "";
  for (const b of bytes) out += b.toString(16).padStart(2, "0");
  return out;
}

/** The fields of an envelope before its signature. */
export interface DidEnvelopeFields {
  /** The signing DID. */
  did: string;
  /** The method the envelope authorizes. */
  method: string;
  /** SHA-256 of the bound bytes (32 bytes). */
  paramsHash: Uint8Array;
  /** Unix milliseconds at signing; the node accepts 60 s either side of its clock. */
  timestampMs: number;
  /** 16 random bytes; the node refuses a nonce it has seen. */
  nonce: Uint8Array;
}

/**
 * The preimage the DID signs: the domain tag, then `did` and `method` each
 * prefixed with its length (u32 big-endian), `paramsHash`, `timestampMs`
 * (u64 big-endian) and `nonce`.
 */
export function didEnvelopePreimage(fields: DidEnvelopeFields): Uint8Array {
  const did = new TextEncoder().encode(fields.did);
  const method = new TextEncoder().encode(fields.method);
  return concat([
    ENVELOPE_DOMAIN,
    u32be(did.length),
    did,
    u32be(method.length),
    method,
    fields.paramsHash,
    u64be(fields.timestampMs),
    fields.nonce,
  ]);
}

/**
 * The hex header value the node takes as `did_envelope`: `did` and `method`
 * length-prefixed, `paramsHash`, `timestampMs`, `nonce`, then the JSON of
 * the composite `signature`, length-prefixed.
 */
export function didEnvelopeHeader(fields: DidEnvelopeFields, signature: unknown): string {
  const did = new TextEncoder().encode(fields.did);
  const method = new TextEncoder().encode(fields.method);
  const sig = new TextEncoder().encode(JSON.stringify(signature));
  return hex(
    concat([
      u32be(did.length),
      did,
      u32be(method.length),
      method,
      fields.paramsHash,
      u64be(fields.timestampMs),
      fields.nonce,
      u32be(sig.length),
      sig,
    ]),
  );
}

/** Fixed timestamp and nonce, for reproducing a vector. Leave unset otherwise. */
export interface DidEnvelopeOptions {
  timestampMs?: number;
  nonce?: Uint8Array;
}

/**
 * `params` with `did_envelope` set: `did`'s envelope, signed by `signer`,
 * authorizing `method` over every other field of `params`. `signer` must
 * hold the key `did` resolves to on the node.
 */
export async function withRequestEnvelope<T extends Record<string, unknown>>(
  signer: HybridSigner,
  did: string,
  method: string,
  params: T,
  options: DidEnvelopeOptions = {},
): Promise<T & { did_envelope: string }> {
  const nonce = options.nonce ?? globalThis.crypto.getRandomValues(new Uint8Array(16));
  if (nonce.length !== 16) throw new Error("envelope nonce must be 16 bytes");
  const fields: DidEnvelopeFields = {
    did,
    method,
    paramsHash: await sha256(requestBinding(params)),
    timestampMs: options.timestampMs ?? Date.now(),
    nonce,
  };
  const mPrime = await compositeMessageRepresentative(DID_ENVELOPE_CONTEXT, didEnvelopePreimage(fields));
  const [classical, pq] = await signer.signComposite(mPrime);
  return { ...params, did_envelope: didEnvelopeHeader(fields, compositeSignatureJson(classical, pq)) };
}

/**
 * The Tenzro DID envelope extension for A2A 1.0.
 *
 * A node's agent card declares the extension URI as required. Every call
 * that opens, changes or reads a task (`SendMessage`, `SendStreamingMessage`,
 * `CancelTask`, `GetTask`, `ListTasks`) carries five metadata keys: in
 * `params.message.metadata` for the message methods, in `params.metadata`
 * for the others. The signature is over `envelopePreimage(...)`, which binds
 * the node addressed (its machine DID, as its signed card names it), the
 * method, the task, the sender, a single-use nonce, the time, and the
 * SHA-256 of the RFC 8785 canonical params with the envelope keys removed.
 * The node shows a task only to the DID that opened it.
 *
 * An account that enrolled an ML-DSA-65 key also signs the preimage with
 * it, as the ML-DSA-65 leg of a composite under `A2A_ENVELOPE_CONTEXT`, sent
 * in a sixth key (`ENVELOPE_PQ_SIGNATURE_KEY`). The node requires that leg
 * from such an account and refuses it from any other.
 *
 * A passkey cannot sign an envelope: it signs WebAuthn client data, never a
 * message of the caller's choosing. An identity whose only key is a passkey
 * makes these calls from a device bound to it whose key is in a TPM or
 * Secure Enclave, with that device's account as the sender.
 */

import { compositeMessageRepresentative } from '@tenzro/core';

/** Extension URI the agent card lists as required. */
export const TENZRO_DID_ENVELOPE_EXTENSION_URI = 'https://tenzro.com/a2a/extensions/did-envelope';

/** Metadata key carrying the sender's `did:tenzro:` DID. */
export const ENVELOPE_SENDER_KEY = 'tenzro.a2a.envelope.sender';

/** Metadata key carrying the signing public key (hex; 32 bytes Ed25519, 33 bytes secp256k1). */
export const ENVELOPE_PUBLIC_KEY_KEY = 'tenzro.a2a.envelope.public_key';

/** Metadata key carrying the signature (hex). */
export const ENVELOPE_SIGNATURE_KEY = 'tenzro.a2a.envelope.signature';

/** Metadata key carrying the single-use nonce (hex, 16 bytes). */
export const ENVELOPE_NONCE_KEY = 'tenzro.a2a.envelope.nonce';

/** Metadata key carrying the signing time in unix milliseconds. */
export const ENVELOPE_TIMESTAMP_KEY = 'tenzro.a2a.envelope.timestamp';

/** Metadata key carrying the ML-DSA-65 leg, hex. */
export const ENVELOPE_PQ_SIGNATURE_KEY = 'tenzro.a2a.envelope.pq_signature';

/** Signature context of the ML-DSA-65 leg. */
export const A2A_ENVELOPE_CONTEXT = new TextEncoder().encode('tenzro/a2a/envelope');

/** The envelope fields read from a message's metadata. */
export interface TenzroDidEnvelope {
  readonly sender: string;
  readonly publicKey: string;
  readonly signature: string;
  readonly nonce: string;
  readonly timestampMs: number;
}

/** The text the sender signs (UTF-8) for the node whose machine DID is `audienceDid`. */
export function envelopePreimage(
  audienceDid: string,
  method: string,
  taskId: string,
  senderDid: string,
  nonceHex: string,
  timestampMs: number,
  paramsSha256Hex: string,
): string {
  return `tenzro:a2a:${audienceDid}:${method}:${taskId}:${senderDid}:${nonceHex}:${timestampMs}:${paramsSha256Hex}`;
}

/**
 * Read the envelope from an A2A metadata object. Returns `null` when any of
 * the five fields is missing or has the wrong type.
 */
export function extractTenzroDidEnvelope(
  metadata: Readonly<Record<string, unknown>>,
): TenzroDidEnvelope | null {
  const sender = metadata[ENVELOPE_SENDER_KEY];
  const publicKey = metadata[ENVELOPE_PUBLIC_KEY_KEY];
  const signature = metadata[ENVELOPE_SIGNATURE_KEY];
  const nonce = metadata[ENVELOPE_NONCE_KEY];
  const timestampMs = metadata[ENVELOPE_TIMESTAMP_KEY];
  if (
    typeof sender !== 'string' ||
    typeof publicKey !== 'string' ||
    typeof signature !== 'string' ||
    typeof nonce !== 'string' ||
    typeof timestampMs !== 'number'
  ) {
    return null;
  }
  return { sender, publicKey, signature, nonce, timestampMs };
}

/** The hardware P-256 key of the account a task call is made as. */
export interface EnvelopeSigner {
  /** The public key, `x || y` (64 bytes). */
  publicKey(): Uint8Array;
  /** `r || s` (64 bytes) over SHA-256 of `message`. */
  sign(message: Uint8Array): Promise<Uint8Array>;
  /**
   * For an account that enrolled an ML-DSA-65 key: the ML-DSA-65 leg over
   * `mPrime` (built by `compositeMessageRepresentative`) with the FIPS 204
   * context string `COMPOSITE_LABEL_MLDSA65_P256`.
   */
  mlDsaLeg?(mPrime: Uint8Array): Promise<Uint8Array>;
}

/** Who a task call is made as: the DID and the key that signs for it. */
export interface EnvelopeSender {
  did: string;
  signer: EnvelopeSigner;
}

const ENVELOPE_KEYS = [
  ENVELOPE_SENDER_KEY,
  ENVELOPE_PUBLIC_KEY_KEY,
  ENVELOPE_SIGNATURE_KEY,
  ENVELOPE_NONCE_KEY,
  ENVELOPE_TIMESTAMP_KEY,
  ENVELOPE_PQ_SIGNATURE_KEY,
];

type Json = null | boolean | number | string | Json[] | { [key: string]: Json };
type JsonObject = { [key: string]: Json };

const isMessageMethod = (method: string): boolean => method === 'SendMessage' || method === 'SendStreamingMessage';
const isObject = (v: unknown): v is JsonObject => typeof v === 'object' && v !== null && !Array.isArray(v);
const toHex = (bytes: Uint8Array): string => Array.from(bytes, (b) => b.toString(16).padStart(2, '0')).join('');

/** RFC 8785 canonical text of `value`: member names in UTF-16 code unit order, numbers and strings as ECMAScript writes them. */
export function canonicalJson(value: unknown): string {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') return JSON.stringify(value);
  if (typeof value === 'number') {
    if (!Number.isFinite(value)) throw new Error('an A2A envelope cannot sign a number that is not finite');
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (isObject(value)) {
    const names = Object.keys(value).filter((k) => value[k] !== undefined).sort();
    return `{${names.map((k) => `${JSON.stringify(k)}:${canonicalJson(value[k])}`).join(',')}}`;
  }
  throw new Error(`an A2A envelope cannot sign a value of type ${typeof value}`);
}

/** The task id an envelope binds to: `params.message.taskId` for the message methods, `params.id` for the others, empty when there is none. */
export function envelopeTaskId(method: string, params: Readonly<Record<string, unknown>>): string {
  const holder = isMessageMethod(method) ? params.message : params;
  const found = isObject(holder) ? (isMessageMethod(method) ? holder.taskId : holder.id) : undefined;
  return typeof found === 'string' ? found : '';
}

/** Lowercase hex SHA-256 of the canonical `params` with the envelope keys removed, and their metadata object dropped when nothing else is left in it. */
export async function paramsDigestHex(method: string, params: Readonly<Record<string, unknown>>): Promise<string> {
  const body = JSON.parse(JSON.stringify(params)) as JsonObject;
  const holder = isMessageMethod(method) ? body.message : body;
  if (isObject(holder) && isObject(holder.metadata)) {
    for (const key of ENVELOPE_KEYS) delete holder.metadata[key];
    if (Object.keys(holder.metadata).length === 0) delete holder.metadata;
  }
  const bytes = new TextEncoder().encode(canonicalJson(body));
  return toHex(new Uint8Array(await globalThis.crypto.subtle.digest('SHA-256', bytes as BufferSource)));
}

/**
 * `params` with the envelope for `method` to the node whose machine DID is
 * `audienceDid` attached, signed now by `sender`. The input is not changed.
 */
export async function signEnvelope<P extends Record<string, unknown>>(
  audienceDid: string,
  method: string,
  params: P,
  sender: EnvelopeSender,
): Promise<P> {
  const publicKey = sender.signer.publicKey();
  if (publicKey.length !== 64) throw new Error(`the envelope key must be a P-256 key x || y (64 bytes), got ${publicKey.length}`);
  const nonce = toHex(globalThis.crypto.getRandomValues(new Uint8Array(16)));
  const timestampMs = Date.now();
  const digest = await paramsDigestHex(method, params);
  const preimage = envelopePreimage(audienceDid, method, envelopeTaskId(method, params), sender.did, nonce, timestampMs, digest);
  const signature = await sender.signer.sign(new TextEncoder().encode(preimage));
  if (signature.length !== 64) throw new Error(`the envelope signature must be r || s (64 bytes), got ${signature.length}`);
  const out = JSON.parse(JSON.stringify(params)) as JsonObject;
  const holder = isMessageMethod(method) ? out.message : out;
  if (!isObject(holder)) throw new Error(`${method} params have no object to carry the envelope`);
  const metadata = isObject(holder.metadata) ? holder.metadata : {};
  metadata[ENVELOPE_SENDER_KEY] = sender.did;
  metadata[ENVELOPE_PUBLIC_KEY_KEY] = toHex(publicKey);
  metadata[ENVELOPE_SIGNATURE_KEY] = toHex(signature);
  metadata[ENVELOPE_NONCE_KEY] = nonce;
  metadata[ENVELOPE_TIMESTAMP_KEY] = timestampMs;
  if (sender.signer.mlDsaLeg) {
    const mPrime = await compositeMessageRepresentative(A2A_ENVELOPE_CONTEXT, new TextEncoder().encode(preimage));
    metadata[ENVELOPE_PQ_SIGNATURE_KEY] = toHex(await sender.signer.mlDsaLeg(mPrime));
  }
  holder.metadata = metadata;
  return out as unknown as P;
}

/**
 * The Tenzro DID envelope extension for A2A 1.0.
 *
 * A node's agent card declares the extension URI as required. Every state
 * change (`SendMessage`, `SendStreamingMessage`, `CancelTask`) carries five
 * metadata keys: in `params.message.metadata` for the message methods, in
 * `params.metadata` for `CancelTask`. The signature is over
 * `envelopePreimage(...)`, which binds the method, the task, the sender, a
 * single-use nonce, the time, and the SHA-256 of the RFC 8785 canonical
 * params with the envelope keys removed.
 */

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

/** The envelope fields read from a message's metadata. */
export interface TenzroDidEnvelope {
  readonly sender: string;
  readonly publicKey: string;
  readonly signature: string;
  readonly nonce: string;
  readonly timestampMs: number;
}

/** The text the sender signs (UTF-8). */
export function envelopePreimage(
  method: string,
  taskId: string,
  senderDid: string,
  nonceHex: string,
  timestampMs: number,
  paramsSha256Hex: string,
): string {
  return `tenzro:a2a:${method}:${taskId}:${senderDid}:${nonceHex}:${timestampMs}:${paramsSha256Hex}`;
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

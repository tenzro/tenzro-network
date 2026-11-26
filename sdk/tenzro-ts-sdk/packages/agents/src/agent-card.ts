/**
 * Checking a node's A2A agent card before trusting the node with a task.
 *
 * A card is served with detached signatures: each is a JWS whose payload is
 * the RFC 8785 canonical form of the card without its `signatures`, signed
 * with ES256 by the key in the signature's protected header. That alone proves
 * only that the card matches a key the card itself names. The key is a
 * machine's hardware identity key, and a machine DID is derived from exactly
 * that key, so the check that matters is the last one here: the DID the
 * signing key derives must be the DID the caller meant to reach.
 *
 * A card that does not pass is refused. There is no unverified fallback.
 */

import { canonicalJson } from "./a2a-extension";

const MACHINE_DEVICE_DOMAIN = "tenzro/machine-did/device-key";

/** A card that could not be shown to come from the machine the caller named. */
export class AgentCardRefused extends Error {
  constructor(why: string) {
    super(`agent card refused: ${why}`);
    this.name = "AgentCardRefused";
  }
}

const toHex = (bytes: Uint8Array): string => Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");

function fromBase64Url(text: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]*$/.test(text)) throw new AgentCardRefused("a field is not base64url");
  const b64 = text.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - (text.length % 4)) % 4);
  const bin = atob(b64);
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

function toBase64Url(bytes: Uint8Array): string {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function sha256(bytes: Uint8Array): Promise<Uint8Array> {
  return new Uint8Array(await globalThis.crypto.subtle.digest("SHA-256", bytes as BufferSource));
}

/**
 * The machine DID of a hardware P-256 key `x || y` (64 bytes): the key's
 * uncompressed SEC1 form, length-prefixed, hashed under the machine DID domain.
 */
export async function machineDid(p256PublicKey: Uint8Array): Promise<string> {
  if (p256PublicKey.length !== 64) throw new Error(`P-256 public key must be 64 bytes (x || y), got ${p256PublicKey.length}`);
  const domain = new TextEncoder().encode(MACHINE_DEVICE_DOMAIN);
  const preimage = new Uint8Array(domain.length + 4 + 65);
  preimage.set(domain, 0);
  preimage.set([0, 0, 0, 65, 0x04], domain.length);
  preimage.set(p256PublicKey, domain.length + 5);
  return `did:tenzro:machine:${toHex(await sha256(preimage))}`;
}

/** The DID of the machine whose key made one signature, after that signature verified over `card`. */
async function signerOf(card: Record<string, unknown>, signature: unknown): Promise<string> {
  const sig = signature as { protected?: unknown; signature?: unknown } | null;
  if (!sig || typeof sig.protected !== "string" || typeof sig.signature !== "string") {
    throw new AgentCardRefused("a signature has no protected header or no value");
  }
  let header: { alg?: unknown; kid?: unknown; jwk?: { kty?: unknown; crv?: unknown; x?: unknown; y?: unknown } };
  try {
    header = JSON.parse(new TextDecoder().decode(fromBase64Url(sig.protected)));
  } catch {
    throw new AgentCardRefused("a signature's protected header cannot be read");
  }
  if (header.alg !== "ES256") throw new AgentCardRefused("a signature is not ES256");
  const jwk = header.jwk;
  if (!jwk || jwk.kty !== "EC" || jwk.crv !== "P-256" || typeof jwk.x !== "string" || typeof jwk.y !== "string") {
    throw new AgentCardRefused("the signing key is not a P-256 key");
  }
  const x = fromBase64Url(jwk.x);
  const y = fromBase64Url(jwk.y);
  if (x.length !== 32 || y.length !== 32) throw new AgentCardRefused("the signing key's coordinates are not 32 bytes");
  const raw = fromBase64Url(sig.signature);
  if (raw.length !== 64) throw new AgentCardRefused("a signature is not 64 bytes r || s");

  let key: CryptoKey;
  try {
    key = await globalThis.crypto.subtle.importKey("jwk", { kty: "EC", crv: "P-256", x: jwk.x, y: jwk.y }, { name: "ECDSA", namedCurve: "P-256" }, false, ["verify"]);
  } catch {
    throw new AgentCardRefused("the signing key is not a point on P-256");
  }
  const { signatures: _dropped, ...unsigned } = card;
  const payload = new TextEncoder().encode(canonicalJson(unsigned));
  const input = new TextEncoder().encode(`${sig.protected}.${toBase64Url(payload)}`);
  const ok = await globalThis.crypto.subtle.verify({ name: "ECDSA", hash: "SHA-256" }, key, raw as BufferSource, input as BufferSource);
  if (!ok) throw new AgentCardRefused("a signature does not verify over the card");

  const xy = new Uint8Array(64);
  xy.set(x, 0);
  xy.set(y, 32);
  const did = await machineDid(xy);
  // The header's own name for the key must be the DID the key derives.
  if (typeof header.kid !== "string" || (header.kid !== did && !header.kid.startsWith(`${did}#`))) {
    throw new AgentCardRefused(`a signature claims the key of ${String(header.kid)}, but its key is ${did}'s`);
  }
  return did;
}

/**
 * Check that `card` is signed, that every signature on it verifies, and that
 * one of them is by the hardware key `expectedMachineDid` derives from.
 * @throws AgentCardRefused naming what failed
 */
export async function verifyAgentCard(card: Record<string, unknown>, expectedMachineDid: string): Promise<void> {
  const signatures = card.signatures;
  if (!Array.isArray(signatures) || signatures.length === 0) throw new AgentCardRefused("it carries no signature");
  const signers: string[] = [];
  for (const signature of signatures) signers.push(await signerOf(card, signature));
  if (!signers.includes(expectedMachineDid)) {
    throw new AgentCardRefused(`it is signed by ${signers.join(", ")}, not by ${expectedMachineDid}`);
  }
}

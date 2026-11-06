import type { RpcClient } from './rpc';

// ── Types ──

/** Result of a signature verification. */
export interface VerifyResult {
  /** Whether the signature is valid */
  valid: boolean;
  /** Whether the ML-DSA leg was present and verified. */
  pq_leg_verified: boolean;
  /** Whether the account has an ML-DSA key enrolled. */
  pq_enrolled: boolean;
}

/** Result of a VRF proof verification. */
export interface VrfVerifyResult {
  valid: boolean;
  /** The VRF output, 0x-prefixed hex, when the proof verifies. */
  output?: string;
  output_len?: number;
  /** Why the proof does not verify. */
  error?: string;
}

// ── Client ──

/**
 * Client for cryptographic operations.
 *
 * Provides signing with the caller's bound wallet, signature verification
 * and hashing. No method sends or returns private key material.
 */
export class CryptoClient {
  constructor(private readonly rpc: RpcClient) {}

  /**
   * Verify a composite signature over a message against an account's P-256
   * key, in the signed-message context. The node also checks the ML-DSA leg
   * when the account has enrolled one.
   * @param publicKey - Hex-encoded P-256 public key
   * @param messageHex - The message bytes, hex
   * @param signature - The composite signature in the network's JSON form (as `compositeSignatureJson` builds it)
   */
  async verifySignature(
    publicKey: string,
    messageHex: string,
    signature: Record<string, unknown>,
  ): Promise<VerifyResult> {
    return this.rpc.call<VerifyResult>("tenzro_verifySignature", {
      public_key: publicKey,
      message_hex: messageHex,
      signature,
    });
  }

  /** Verify a VRF proof; `pubkey`, `proof` and the input `alpha` are hex. */
  async verifyVrfProof(pubkey: string, proof: string, alpha: string): Promise<VrfVerifyResult> {
    return this.rpc.call<VrfVerifyResult>("tenzro_verifyVrfProof", { pubkey, proof, alpha });
  }
}

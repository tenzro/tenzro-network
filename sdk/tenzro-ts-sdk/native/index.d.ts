/** `"tpm"`, `"secure-enclave"`, or `null` when this machine has neither. */
export declare function platformBackend(): 'tpm' | 'secure-enclave' | null;

/**
 * Provision this machine's TPM once: the storage root, attestation key and
 * identity key every device key hangs from. Idempotent; returns one line per
 * slot. Throws on a machine without a TPM (a Secure Enclave needs none).
 * Needs access to the TPM device. Also available as `npx @tenzro/device-key provision`.
 */
export declare function provisionTpm(): string[];

export interface Attestation {
  /** Backend that produced the evidence. */
  backend: string;
  /** Backend-specific evidence (TPM quote, enclave binding). */
  evidence: Buffer;
  /** Uncompressed SEC1 public key (65 bytes). */
  publicKey: Buffer;
}

/** A P-256 key held by this machine's TPM or Secure Enclave. */
export declare class DeviceKey {
  /** Open the labelled key, creating it on first use. Throws without hardware. */
  static open(label: string): DeviceKey;
  readonly backend: 'tpm' | 'secure-enclave';
  readonly label: string;
  /** Uncompressed SEC1 public key (65 bytes). */
  publicKey(): Buffer;
  /** ECDSA-P256 over a 32-byte digest; raw low-S `r || s` (64 bytes). */
  signDigest(digest: Uint8Array): Promise<Buffer>;
  attest(): Promise<Attestation>;
}

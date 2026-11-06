/**
 * Pluggable signing surface for custom wallet developers: a {@link Signer}
 * signs a 32-byte digest with a passkey or a hardware key.
 *
 * Why interfaces, not classes:
 *   - Custom HSM integrations, air-gapped flows,
 *     and social-recovery topologies need to extend the surface without
 *     forking the SDK.
 *   - The SDK's own signers consume the same surface, so a third-party
 *     wallet gets every feature they do.
 */

/** What the {@link Signer} is. */
export type SignerKind =
  | { kind: "webauthn"; credentialId: Uint8Array }
  | { kind: "ed25519" }
  | { kind: "tee"; backend: TeeBackend }
  | { kind: "hsm"; vendor: string }
  | { kind: "custom"; name: string };

/** Which TEE attests a `tee` signer. */
export type TeeBackend =
  | "intel-tdx"
  | "amd-sev-snp"
  | "aws-nitro"
  | "nvidia-cc"
  | "apple-secure-enclave"
  | "android-strongbox"
  | "windows-tpm"
  | "linux-tpm";

/** Per-call signing context. */
export interface SignContext {
  /** User-facing reason shown in the biometric prompt. */
  promptReason?: string;
  /**
   * Domain tag the signer scopes the hash with. Implementations MUST
   * refuse to sign when this is set and the tag does not match.
   */
  domainTag?: Uint8Array;
  /** Wall-clock deadline (ms since epoch). */
  deadlineMs?: number;
}

/** Opaque signature. Format is signer-specific. */
export interface SignerSignature {
  /** Raw signature bytes. */
  bytes: Uint8Array;
  /**
   * Ancillary data the validator needs alongside `bytes`. WebAuthn:
   * `clientDataJSON || authenticatorData`. TEE-bound: attestation report.
   */
  aux: Uint8Array;
}

export class SignerError extends Error {
  constructor(public readonly kind: SignerErrorKind, message: string) {
    super(message);
    this.name = "SignerError";
  }
}

export type SignerErrorKind =
  | "user-cancelled"
  | "authentication-failed"
  | "timeout"
  | "domain-tag-mismatch"
  | "backend-unavailable"
  | "transport";

/**
 * Produces a {@link SignerSignature} over a 32-byte hash. Implementations
 * are stateless wrt the hash — per-call state lives in
 * {@link SignContext}.
 */
export interface Signer {
  /** Self-describes the signer kind. */
  describe(): SignerKind;
  /** Signs `hash`. */
  sign(hash: Uint8Array, context: SignContext): Promise<SignerSignature>;
}


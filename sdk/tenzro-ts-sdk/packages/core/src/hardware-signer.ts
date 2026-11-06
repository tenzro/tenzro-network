/**
 * The one way this SDK gets a machine or user signing key.
 *
 * - Node.js: the optional native module `@tenzro/device-key` drives the TPM
 *   2.0 (Linux `/dev/tpmrm0`, Windows TBS) or the Apple Secure Enclave. It can
 *   read the public key, sign a digest, and attest. It cannot export a key.
 * - Browsers: a passkey (WebAuthn) signs.
 * - Neither: {@link openHardwareSigner} throws. There is no software key.
 */

import {
  BrowserWebAuthnAuthenticator,
  WebAuthnSigner,
  type PasskeyCredential,
  type ResolvedPasskeyConfig,
} from "./passkey";
import {
  SignerError,
  type Signer,
  type SignerKind,
  type SignerSignature,
  type SignContext,
} from "./signer";
import type { HybridSigner } from "./wallet";

/** Attestation evidence from the key's hardware. */
export interface HardwareAttestation {
  backend: string;
  evidence: Uint8Array;
  /** Uncompressed SEC1 public key (65 bytes). */
  publicKey: Uint8Array;
}

/** Shape of the native `DeviceKey` class (see `native/index.d.ts`). */
interface NativeDeviceKey {
  readonly backend: "tpm" | "secure-enclave";
  readonly label: string;
  publicKey(): Uint8Array;
  signDigest(digest: Uint8Array): Promise<Uint8Array>;
  attest(): Promise<HardwareAttestation>;
}

interface NativeModule {
  platformBackend(): "tpm" | "secure-enclave" | null;
  DeviceKey: { open(label: string): NativeDeviceKey };
}

const NO_HARDWARE =
  "no hardware signer is available: Node.js needs the optional @tenzro/device-key " +
  "module (npm install @tenzro/device-key) and a TPM 2.0 or Secure Enclave, a browser needs a passkey; " +
  "there is no software-key fallback";

function loadNative(): NativeModule | undefined {
  if (typeof process === "undefined" || !process.versions?.node) return undefined;
  try {
    // Plain require so bundlers for the browser leave it alone.
    // eslint-disable-next-line @typescript-eslint/no-require-imports
    return require("@tenzro/device-key") as NativeModule;
  } catch {
    return undefined;
  }
}

/** A {@link Signer} whose key lives in this machine's TPM or Secure Enclave. */
export class HardwareKeySigner implements Signer, HybridSigner {
  private constructor(private readonly key: NativeDeviceKey) {}

  /** @internal Only {@link openHardwareSigner} constructs one. */
  static fromNative(key: NativeDeviceKey): HardwareKeySigner {
    return new HardwareKeySigner(key);
  }

  describe(): SignerKind {
    if (this.key.backend === "secure-enclave") {
      return { kind: "tee", backend: "apple-secure-enclave" };
    }
    const tpm = typeof process !== "undefined" && process.platform === "win32" ? "windows-tpm" : "linux-tpm";
    return { kind: "tee", backend: tpm };
  }

  get label(): string {
    return this.key.label;
  }

  /** Uncompressed SEC1 P-256 public key (65 bytes). */
  publicKey(): Uint8Array {
    return new Uint8Array(this.key.publicKey());
  }

  /** P-256 public key as a JWK, for DPoP and DID documents. */
  publicKeyJwk(): { kty: "EC"; crv: "P-256"; x: string; y: string } {
    const pk = this.publicKey();
    return { kty: "EC", crv: "P-256", x: b64url(pk.subarray(1, 33)), y: b64url(pk.subarray(33, 65)) };
  }

  /** The P-256 public key as `x || y` (64 bytes); it names the account. */
  p256PublicKey(): Uint8Array {
    return this.publicKey().subarray(1, 65);
  }

  /**
   * The composite signature over `mPrime`: the P-256 leg over
   * `SHA-256(mPrime)`. The native binding exposes no ML-DSA-65 key, so the
   * post-quantum leg is absent; the node refuses the signature for an account
   * that enrolled one.
   */
  async signComposite(mPrime: Uint8Array): Promise<[Uint8Array, Uint8Array | null]> {
    const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", mPrime as BufferSource));
    return [new Uint8Array(await this.key.signDigest(digest)), null];
  }

  /** ECDSA-P256 over a 32-byte digest; `bytes` is raw low-S `r || s`. */
  async sign(hash: Uint8Array, _context?: SignContext): Promise<SignerSignature> {
    if (hash.length !== 32) {
      throw new SignerError("authentication-failed", `expected 32-byte hash, got ${hash.length}`);
    }
    const sig = await this.key.signDigest(hash);
    return { bytes: new Uint8Array(sig), aux: new Uint8Array(0) };
  }

  async attest(): Promise<HardwareAttestation> {
    const a = await this.key.attest();
    return { backend: a.backend, evidence: new Uint8Array(a.evidence), publicKey: new Uint8Array(a.publicKey) };
  }
}

export interface OpenHardwareSignerOptions {
  /** Key label in the TPM or Secure Enclave (Node.js). */
  label: string;
  /** Passkey to sign with in a browser. */
  passkey?: { credential: PasskeyCredential; config: ResolvedPasskeyConfig };
}

/**
 * Open the hardware signer for this host, or throw `backend-unavailable`.
 * Node.js uses the TPM or Secure Enclave; a browser uses the given passkey.
 */
export function openHardwareSigner(
  options: OpenHardwareSignerOptions
): HardwareKeySigner | WebAuthnSigner {
  const native = loadNative();
  if (native && native.platformBackend() !== null) {
    try {
      return HardwareKeySigner.fromNative(native.DeviceKey.open(options.label));
    } catch (e) {
      throw new SignerError("backend-unavailable", (e as Error).message);
    }
  }
  const browser =
    typeof navigator !== "undefined" && typeof (navigator as Navigator).credentials !== "undefined";
  if (browser && options.passkey) {
    return new WebAuthnSigner(
      new BrowserWebAuthnAuthenticator(),
      options.passkey.credential,
      options.passkey.config
    );
  }
  throw new SignerError("backend-unavailable", NO_HARDWARE);
}

function b64url(bytes: Uint8Array): string {
  let s = "";
  for (const b of bytes) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

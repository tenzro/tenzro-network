/**
 * Passkey signing: a {@link PlatformAuthenticator} drives the WebAuthn
 * ceremony and {@link WebAuthnSigner} signs a 32-byte digest with it. An
 * account acts through transactions its keystore authorizes, signed this
 * way.
 *
 * # Where the actual ceremony runs
 *
 * - **Browser:** `navigator.credentials.create/get`. The SDK detects
 *   the browser environment automatically.
 * - **Tauri desktop:** Tenzro Control's commands `device_create_passkey` /
 *   `device_sign_with_passkey`. Pass a {@link PlatformAuthenticator}
 *   adapter that invokes those commands via `@tauri-apps/api/core`.
 * - **Other hosts:** pass a {@link PlatformAuthenticator} that drives the
 *   host's own authenticator. There is no software fallback: a passkey's
 *   private key exists only inside an authenticator.
 *
 * # Cross-device QR (FIDO hybrid / caBLE)
 *
 * When `isPlatformAuthenticatorAvailable()` returns false and the
 * caller used a production config, the host's authenticator offers the
 * cross-device link, which returns a QR payload + a promise that resolves
 * once the remote authenticator completes.
 * The actual caBLE wire is implemented by the host adapter; the SDK
 * ships only the surface.
 */

import type { Signer, SignerKind, SignerSignature } from "./signer";
import { SignerError } from "./signer";

/** Bytes of a registered passkey credential. */
export interface PasskeyCredential {
  /** Authenticator-assigned credential ID (opaque blob). */
  credentialId: Uint8Array;
  /** 64-byte uncompressed P-256 public key (`x || y`, no SEC1 0x04 prefix). */
  publicKey: Uint8Array;
}

/** WebAuthn ceremony configuration. */
export interface PasskeyConfig {
  /** Relying-party ID (registrable domain only — no scheme/path). */
  rpId: string;
  /** Human-readable RP name shown in OS prompts. Defaults to "Tenzro Network". */
  rpName?: string;
  /** Require user verification (biometric/PIN). MUST be `true` in production. */
  requireUserVerification?: boolean;
  /** Require platform authenticator (Touch ID / Face ID / Windows Hello). */
  requirePlatformAuthenticator?: boolean;
}

/** Per-ceremony output from `create`. */
export interface AuthenticatorRegistration {
  credential: PasskeyCredential;
  /** Raw `attestationObject` bytes (CBOR). Empty for `none` attestation. */
  attestationObject: Uint8Array;
}

/** Per-ceremony output from `get` (assertion). */
export interface AuthenticatorAssertion {
  /** 64-byte raw P-256 signature (`r || s`). */
  signature: Uint8Array;
  /** WebAuthn `authenticatorData` blob. */
  authenticatorData: Uint8Array;
  /** Raw `clientDataJSON` bytes. */
  clientDataJson: Uint8Array;
}

/** QR + channel for the FIDO hybrid (caBLE) cross-device flow. */
export interface CrossDeviceLink {
  /** `FIDO:/...` URI — render as QR code. */
  qrUri: string;
  /** Channel ID used to await remote completion. */
  channelId: string;
}

/**
 * Trait every host implements once. Not a class — implementations
 * vary radically (browser vs Tauri vs headless), so we pin only the
 * shape.
 */
export interface PlatformAuthenticator {
  isPlatformAuthenticatorAvailable(): Promise<boolean>;
  createCredential(
    config: ResolvedPasskeyConfig,
    challenge: Uint8Array
  ): Promise<AuthenticatorRegistration>;
  signAssertion(
    config: ResolvedPasskeyConfig,
    credentialId: Uint8Array,
    challenge: Uint8Array
  ): Promise<AuthenticatorAssertion>;
  startCrossDeviceLink(
    config: ResolvedPasskeyConfig
  ): Promise<CrossDeviceLink>;
}

/** {@link PasskeyConfig} after defaults applied. */
export interface ResolvedPasskeyConfig {
  rpId: string;
  rpName: string;
  requireUserVerification: boolean;
  requirePlatformAuthenticator: boolean;
}

/** Production preset: strict UV, platform attachment required. */
export function productionConfig(rpId: string): ResolvedPasskeyConfig {
  return {
    rpId,
    rpName: "Tenzro Network",
    requireUserVerification: true,
    requirePlatformAuthenticator: true,
  };
}

/** Development preset: strict UV, allows cross-platform (YubiKey on Linux). */
export function developmentConfig(rpId: string): ResolvedPasskeyConfig {
  return {
    rpId,
    rpName: "Tenzro Network (dev)",
    requireUserVerification: true,
    requirePlatformAuthenticator: false,
  };
}

function resolveConfig(cfg: PasskeyConfig): ResolvedPasskeyConfig {
  const base =
    cfg.requirePlatformAuthenticator === false
      ? developmentConfig(cfg.rpId)
      : productionConfig(cfg.rpId);
  return {
    rpId: cfg.rpId,
    rpName: cfg.rpName ?? base.rpName,
    requireUserVerification:
      cfg.requireUserVerification ?? base.requireUserVerification,
    requirePlatformAuthenticator:
      cfg.requirePlatformAuthenticator ?? base.requirePlatformAuthenticator,
  };
}

/** {@link Signer} impl that delegates to a {@link PlatformAuthenticator}. */
export class WebAuthnSigner implements Signer {
  constructor(
    private readonly authenticator: PlatformAuthenticator,
    private readonly credentialBytes: PasskeyCredential,
    private readonly config: ResolvedPasskeyConfig
  ) {}

  describe(): SignerKind {
    return { kind: "webauthn", credentialId: this.credentialBytes.credentialId };
  }

  credential(): PasskeyCredential {
    return this.credentialBytes;
  }

  async sign(hash: Uint8Array): Promise<SignerSignature> {
    if (hash.length !== 32) {
      throw new SignerError(
        "authentication-failed",
        `expected 32-byte hash, got ${hash.length}`
      );
    }
    const assertion = await this.authenticator.signAssertion(
      this.config,
      this.credentialBytes.credentialId,
      hash
    );
    // Pack authenticatorData + clientDataJSON into `aux` with 4-byte
    // LE length prefixes.
    const aux = packAux(assertion.authenticatorData, assertion.clientDataJson);
    return { bytes: assertion.signature, aux };
  }
}

/**
 * Pick the right {@link PlatformAuthenticator} for the current host.
 * Browsers use `navigator.credentials`. Any other host has no
 * authenticator the SDK can reach on its own, so this throws and the
 * caller passes its own authenticator.
 */
export function defaultAuthenticator(): PlatformAuthenticator {
  if (
    typeof navigator !== "undefined" &&
    typeof (navigator as Navigator).credentials !== "undefined"
  ) {
    return new BrowserWebAuthnAuthenticator();
  }
  throw new SignerError(
    "backend-unavailable",
    "no WebAuthn authenticator on this host; pass the host's own authenticator"
  );
}

// --- Browser WebAuthn implementation ---------------------------------

/**
 * Browser-native authenticator using `navigator.credentials`. This is
 * the production path on the web.
 */
export class BrowserWebAuthnAuthenticator implements PlatformAuthenticator {
  async isPlatformAuthenticatorAvailable(): Promise<boolean> {
    if (typeof PublicKeyCredential === "undefined") return false;
    const fn = (
      PublicKeyCredential as unknown as {
        isUserVerifyingPlatformAuthenticatorAvailable?: () => Promise<boolean>;
      }
    ).isUserVerifyingPlatformAuthenticatorAvailable;
    if (!fn) return false;
    try {
      return await fn.call(PublicKeyCredential);
    } catch {
      return false;
    }
  }

  async createCredential(
    config: ResolvedPasskeyConfig,
    challenge: Uint8Array
  ): Promise<AuthenticatorRegistration> {
    const userId = new Uint8Array(new ArrayBuffer(16));
    crypto.getRandomValues(userId);
    const cred = (await navigator.credentials.create({
      publicKey: {
        challenge: bufferOf(challenge),
        rp: { id: config.rpId, name: config.rpName },
        user: {
          id: bufferOf(userId),
          name: "tenzro-user",
          displayName: "Tenzro User",
        },
        pubKeyCredParams: [{ type: "public-key", alg: -7 }], // ES256 / P-256
        authenticatorSelection: {
          authenticatorAttachment: config.requirePlatformAuthenticator
            ? "platform"
            : undefined,
          userVerification: config.requireUserVerification
            ? "required"
            : "preferred",
          residentKey: "preferred",
        },
        attestation: "none",
      },
    })) as PublicKeyCredential | null;

    if (!cred) {
      throw new SignerError("user-cancelled", "credential creation returned null");
    }

    const response = cred.response as AuthenticatorAttestationResponse;
    const credentialId = new Uint8Array(cred.rawId);
    const publicKey = extractCosePublicKey(
      new Uint8Array(response.attestationObject)
    );
    return {
      credential: { credentialId, publicKey },
      attestationObject: new Uint8Array(response.attestationObject),
    };
  }

  async signAssertion(
    config: ResolvedPasskeyConfig,
    credentialId: Uint8Array,
    challenge: Uint8Array
  ): Promise<AuthenticatorAssertion> {
    const cred = (await navigator.credentials.get({
      publicKey: {
        challenge: bufferOf(challenge),
        rpId: config.rpId,
        allowCredentials: [
          {
            type: "public-key",
            id: bufferOf(credentialId),
            transports: ["internal", "hybrid", "usb", "nfc", "ble"],
          },
        ],
        userVerification: config.requireUserVerification
          ? "required"
          : "preferred",
      },
    })) as PublicKeyCredential | null;

    if (!cred) {
      throw new SignerError("user-cancelled", "assertion returned null");
    }

    const response = cred.response as AuthenticatorAssertionResponse;
    return {
      signature: derToRawP256(new Uint8Array(response.signature)),
      authenticatorData: new Uint8Array(response.authenticatorData),
      clientDataJson: new Uint8Array(response.clientDataJSON),
    };
  }

  async startCrossDeviceLink(
    _config: ResolvedPasskeyConfig
  ): Promise<CrossDeviceLink> {
    // The browser doesn't expose caBLE QR generation directly — it
    // ships inside `navigator.credentials.get` when the platform
    // detects no local authenticator. Custom hosts (Tauri) implement
    // this directly. Surface a clear error here.
    throw new SignerError(
      "backend-unavailable",
      "browser does not expose caBLE QR; the OS handles cross-device transparently inside navigator.credentials.get"
    );
  }
}

// --- helpers ---------------------------------------------------------

function packAux(authData: Uint8Array, clientData: Uint8Array): Uint8Array {
  const out = new Uint8Array(8 + authData.length + clientData.length);
  const view = new DataView(out.buffer);
  view.setUint32(0, authData.length, true);
  out.set(authData, 4);
  view.setUint32(4 + authData.length, clientData.length, true);
  out.set(clientData, 8 + authData.length);
  return out;
}

function randomChallenge(): Uint8Array {
  const buf = new Uint8Array(new ArrayBuffer(32));
  crypto.getRandomValues(buf);
  return buf;
}

/** Lowercase hex, no `0x` prefix — matches the node's `*_hex` param decoders. */
function hexEncode(bytes: Uint8Array): string {
  let hex = "";
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i].toString(16).padStart(2, "0");
  }
  return hex;
}

function bufferOf(arr: Uint8Array): ArrayBuffer {
  // Strip any subarray-offset by copying into a fresh buffer — most
  // WebAuthn implementations are picky about this.
  const out = new ArrayBuffer(arr.byteLength);
  new Uint8Array(out).set(arr);
  return out;
}

/**
 * Browser WebAuthn returns DER-encoded ECDSA signatures from
 * `navigator.credentials.get`. The on-chain validator wants the raw
 * `r || s` 64-byte form. Decode minimal DER:
 *
 *   30 LL 02 RL <r> 02 SL <s>
 */
function derToRawP256(der: Uint8Array): Uint8Array {
  let i = 0;
  if (der[i++] !== 0x30) throw new SignerError("transport", "DER: missing SEQUENCE");
  // Length (could be short-form for typical 70-72 byte sigs).
  if (der[i] & 0x80) {
    const lenBytes = der[i++] & 0x7f;
    i += lenBytes;
  } else {
    i++;
  }
  if (der[i++] !== 0x02) throw new SignerError("transport", "DER: missing r INTEGER");
  const rLen = der[i++];
  const rRaw = der.slice(i, i + rLen);
  i += rLen;
  if (der[i++] !== 0x02) throw new SignerError("transport", "DER: missing s INTEGER");
  const sLen = der[i++];
  const sRaw = der.slice(i, i + sLen);

  // Strip leading 0x00 padding (DER encodes positive ints with a
  // leading zero if MSB set), then left-pad to 32 bytes.
  const r = stripLeadingZero(rRaw);
  const s = stripLeadingZero(sRaw);
  const out = new Uint8Array(64);
  out.set(r, 32 - r.length);
  out.set(s, 64 - s.length);
  return out;
}

function stripLeadingZero(b: Uint8Array): Uint8Array {
  // Copy into a fresh ArrayBuffer-backed Uint8Array so callers can
  // assign without TS narrowing the buffer type to ArrayBufferLike.
  const start = b.length > 1 && b[0] === 0x00 ? 1 : 0;
  const out = new Uint8Array(b.length - start);
  out.set(b.subarray(start));
  return out;
}

/**
 * Extract the raw 64-byte P-256 public key (`x || y`) from the COSE
 * key embedded in a WebAuthn `attestationObject`.
 *
 * The attestationObject is CBOR; its `authData` field embeds an
 * "attested credential data" record that ends with a COSE_Key. For
 * ES256/P-256 (alg=-7, kty=2, crv=1) the key has a fixed structure:
 *
 *   A5            ; map(5)
 *     01 02       ; kty: 2 (EC2)
 *     03 26       ; alg: -7 (ES256)
 *     20 01       ; crv: 1 (P-256)
 *     21 58 20 <x32>  ; x coord
 *     22 58 20 <y32>  ; y coord
 *
 * We scan for `21 58 20` + 32 bytes + `22 58 20` + 32 bytes — a
 * minimal CBOR-aware parse that avoids pulling in a full CBOR lib.
 */
function extractCosePublicKey(attestationObject: Uint8Array): Uint8Array {
  for (let i = 0; i + 70 < attestationObject.length; i++) {
    if (
      attestationObject[i] === 0x21 &&
      attestationObject[i + 1] === 0x58 &&
      attestationObject[i + 2] === 0x20 &&
      attestationObject[i + 35] === 0x22 &&
      attestationObject[i + 36] === 0x58 &&
      attestationObject[i + 37] === 0x20
    ) {
      const out = new Uint8Array(64);
      out.set(attestationObject.slice(i + 3, i + 35), 0);
      out.set(attestationObject.slice(i + 38, i + 70), 32);
      return out;
    }
  }
  throw new SignerError(
    "transport",
    "could not locate COSE P-256 public key in attestationObject"
  );
}

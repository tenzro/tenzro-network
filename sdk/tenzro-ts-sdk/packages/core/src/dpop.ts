/**
 * DPoP proofs (RFC 9449) minted with the hardware P-256 key: ES256 over the
 * proof's signing input, the key's JWK in the header, `ath` binding the
 * access token. The node's verifier checks the thumbprint against the token's
 * `cnf.jkt`, the signature, `htm`/`htu`, `iat` within its window and `jti`
 * against replays.
 */
import { createHash, randomUUID } from "node:crypto";
import type { DpopProver } from "./access";
import type { HardwareKeySigner } from "./hardware-signer";

const b64url = (bytes: Uint8Array | Buffer): string => Buffer.from(bytes).toString("base64url");

/** RFC 7638 thumbprint of a P-256 JWK. */
export function jwkThumbprint(jwk: { crv: string; kty: string; x: string; y: string }): string {
  const canonical = `{"crv":"${jwk.crv}","kty":"${jwk.kty}","x":"${jwk.x}","y":"${jwk.y}"}`;
  return b64url(createHash("sha256").update(canonical).digest());
}

/** Mints ES256 DPoP proofs with a hardware P-256 key. */
export class HardwareDpopProver implements DpopProver {
  private readonly jwk: { kty: "EC"; crv: "P-256"; x: string; y: string };

  constructor(private readonly signer: HardwareKeySigner) {
    this.jwk = signer.publicKeyJwk();
  }

  async jkt(): Promise<string> {
    return jwkThumbprint(this.jwk);
  }

  async proof(htm: string, htu: string, accessToken: string): Promise<string> {
    const header = { typ: "dpop+jwt", alg: "ES256", jwk: this.jwk };
    const payload = {
      jti: randomUUID(),
      htm,
      htu,
      iat: Math.floor(Date.now() / 1000),
      ath: b64url(createHash("sha256").update(accessToken).digest()),
    };
    const input = `${b64url(Buffer.from(JSON.stringify(header)))}.${b64url(Buffer.from(JSON.stringify(payload)))}`;
    const digest = new Uint8Array(createHash("sha256").update(input).digest());
    const signature = await this.signer.sign(digest);
    return `${input}.${b64url(signature.bytes)}`;
  }
}

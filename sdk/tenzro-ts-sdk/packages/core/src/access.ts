import type { RpcClient } from "./rpc";

/**
 * Node access: sign in for a DPoP-bound access token, and administer who may
 * use a node.
 *
 * A caller proves who it is once, with a passkey or a hardware key, and
 * receives a short-lived ES256 access token bound to its DPoP key. Every
 * later request carries the token and a fresh DPoP proof; the node
 * re-evaluates its access policy for the token's DID on each one.
 *
 * The policy and token methods are for the node's operator and the
 * administrators its policy names; the node refuses anyone else.
 */

/** Mints DPoP proofs (RFC 9449) with a key the caller holds in hardware. */
export interface DpopProver {
  /** RFC 7638 thumbprint of the DPoP public key. */
  jkt(): Promise<string>;
  /** A proof for one request, bound to the access token it accompanies. */
  proof(htm: string, htu: string, accessToken: string): Promise<string>;
}

/** An access token and the DPoP key it is bound to. */
export interface AccessCredential {
  token: string;
  prover: DpopProver;
}

/** A sign-in challenge. */
export interface AccessChallenge {
  challenge_id: string;
  /** The challenge a passkey signs (`webauthn.get`), base64url. */
  challenge: string;
  /** The digest a hardware key signs, hex. */
  device_digest: string;
  expires_in: number;
}

/** The answer to a sign-in challenge. */
export type SignInProof =
  | {
      kind: "passkey";
      account_address: string;
      credential_id: string;
      authenticator_data: string;
      client_data_json: string;
      signature: string;
    }
  | {
      kind: "device";
      /** Hex: the key the DID derives from, or one registered on it. */
      public_key: string;
      /** Hex: ECDSA P-256 `r || s` over SHA-256 of the digest, or Ed25519. */
      signature: string;
    };

/** An issued access token. */
export interface IssuedAccessToken {
  access_token: string;
  token_type: "DPoP";
  expires_in: number;
  did: string;
  /** The method classes the policy admits the DID to. */
  classes: string[];
  /** The node's token-signing key. */
  jwk: Record<string, unknown>;
}

/** What the policy decides for one caller. */
export type AccessDecision =
  | { decision: "allow"; tier: string | null; named: boolean }
  | { decision: "pay"; via: string; price: string; asset: string }
  | { decision: "refuse"; reason: string };

/** Node access RPCs. */
export class AccessClient {
  constructor(private rpc: RpcClient) {}

  /** `tenzro_accessChallenge`: a single-use challenge for `did`, bound to the DPoP key `dpopJkt`. */
  async challenge(did: string, dpopJkt: string): Promise<AccessChallenge> {
    return this.rpc.call<AccessChallenge>("tenzro_accessChallenge", { did, dpop_jkt: dpopJkt });
  }

  /** `tenzro_issueAccessToken`: answer a challenge. `credentials` are KYA credentials about the DID. */
  async issue(challengeId: string, proof: SignInProof, credentials?: unknown[]): Promise<IssuedAccessToken> {
    const params: Record<string, unknown> = { challenge_id: challengeId, proof };
    if (credentials) params.credentials = credentials;
    return this.rpc.call<IssuedAccessToken>("tenzro_issueAccessToken", params);
  }

  /** `tenzro_getAccessPolicy`: the policy in force, as data and as TOML. */
  async getPolicy(): Promise<{ policy: Record<string, unknown>; toml: string }> {
    return this.rpc.call("tenzro_getAccessPolicy", {});
  }

  /** `tenzro_setAccessPolicy`: replace the policy with `toml`. Returns the new version. */
  async setPolicy(toml: string): Promise<number> {
    const r = await this.rpc.call<{ version: number }>("tenzro_setAccessPolicy", { toml });
    return r.version;
  }

  /** `tenzro_previewAccess`: what the policy decides for `did` (anonymous when omitted) calling `method` on `surface`. */
  async preview(
    surface: string,
    method: string,
    did?: string,
  ): Promise<{ surface: string; class: string; caller: string | null; result: AccessDecision }> {
    const params: Record<string, unknown> = { surface, method };
    if (did) params.did = did;
    return this.rpc.call("tenzro_previewAccess", params);
  }

  /** `tenzro_listAccessTokens`: the live tokens the node issued. */
  async listTokens(): Promise<{ tokens: Array<{ jti: string; bearer_did: string; issued_at_ms: number; expires_at: number }> }> {
    return this.rpc.call("tenzro_listAccessTokens", {});
  }

  /** `tenzro_revokeAccessToken`: withdraw one token by `jti`. */
  async revokeToken(jti: string): Promise<{ revoked: string[] }> {
    return this.rpc.call("tenzro_revokeAccessToken", { jti });
  }

  /** `tenzro_revokeAccessToken`: withdraw every live token of `did`. */
  async revokeDid(did: string): Promise<{ revoked: string[] }> {
    return this.rpc.call("tenzro_revokeAccessToken", { did });
  }

  /**
   * `tenzro_listAdminAudit`: the node's administrative audit log, the most
   * recent records the filter selects, oldest first. Times are RFC 3339 or
   * Unix milliseconds; `limit` defaults to 100, at most 1000.
   */
  async auditLog(filter: {
    method?: string;
    principal?: string;
    since?: string | number;
    until?: string | number;
    limit?: number;
  } = {}): Promise<{ count: number; records: Array<{ record: Record<string, unknown>; hash: string }> }> {
    return this.rpc.call("tenzro_listAdminAudit", filter);
  }

  /** `tenzro_verifyAdminAudit`: check the audit log's chain and signed checkpoints. */
  async verifyAuditLog(): Promise<{
    ok: boolean;
    records: number;
    segments: string[];
    first_seq: number | null;
    last_seq: number | null;
    head_hash: string | null;
    checkpoints: number;
    signed_checkpoints: number;
    unsigned_checkpoints: number;
    problems: string[];
  }> {
    return this.rpc.call("tenzro_verifyAdminAudit", {});
  }
}

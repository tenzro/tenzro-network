import type { RpcClient } from "@tenzro/core";
import type { CompositeSignature } from "@tenzro/core";

/**
 * Origin of a reserve attestation — who is asserting the backing.
 * Wire form is snake_case (`issuer` / `tee` / `chainlink_por` / `oracle`).
 */
export type ReserveSource = 'issuer' | 'tee' | 'chainlink_por' | 'oracle';

/**
 * reserve attestation a reserve-backed token's mint carries (`TokenClient.mint`). Mirrors the
 * canonical on-chain `ReserveAttestation`: the attestor signs the canonical
 * payload (`signing_payload`) with the P-256 assertion key of their registered
 * identity (TPM, Secure Enclave or passkey; context `ReserveAttestation`), plus
 * the ML-DSA-65 leg once that key has one enrolled. The node rejects any
 * submission whose signature is missing or does not verify.
 */
export interface ReserveAttestation {
  /** Human-readable asset label the reserve backs (e.g. ISIN, symbol). */
  asset_id: string;
  /** Attested reserve, base units. */
  reserves: number;
  /** Who is attesting the backing. */
  source: ReserveSource;
  /** Attestor DID: must be registered and hold a P-256 assertion key. */
  attestor_did: string;
  /** Unix seconds the attestation was made. */
  attested_at: number;
  /**
   * Composite signature over `signing_payload()`:
   * `{classical: {form: "raw", signature} | {form: "web_authn", authenticator_data,
   * client_data_json, signature}, pq?}`, all bytes hex. The node is fail-closed:
   * a missing signature is rejected before any persist.
   */
  signature?: CompositeSignature;
}

/**
 * Proof-of-Reserve client: submit and read the reserve attestation backing a
 * tokenized asset. A reserve-backed token mints with its attestor's
 * attestation inside a signed Token transaction (`TokenClient.mint`).
 */
export class ReserveClient {
  constructor(private readonly rpc: RpcClient) {}

  /** Submit a 1:1-backed reserve attestation for a tokenized asset. */
  async submitReserveAttestation(attestation: ReserveAttestation): Promise<unknown> {
    return this.rpc.call('tenzro_submitReserveAttestation', { attestation });
  }

  /** Read the latest reserve attestation for a tokenized asset. */
  async getReserve(assetId: string): Promise<unknown> {
    return this.rpc.call('tenzro_getReserve', { asset_id: assetId });
  }

  /** `tenzro_buildReserveAttestationFromPor`. */
  buildReserveAttestationFromPor<T = unknown>(params: { asset_id?: unknown; attestor_did?: unknown } = {}): Promise<T> {
    return this.rpc.call<T>("tenzro_buildReserveAttestationFromPor", params);
  }

  /** `tenzro_readPorReserve`. */
  readPorReserve<T = unknown>(params: { asset_id?: unknown } = {}): Promise<T> {
    return this.rpc.call<T>("tenzro_readPorReserve", params);
  }

  /** `tenzro_getReserveFeed`: the Proof-of-Reserve feed governance installed for an asset (`feed` is null when none is). */
  getReserveFeed<T = unknown>(params: { asset_id: string }): Promise<T> {
    return this.rpc.call<T>("tenzro_getReserveFeed", params);
  }
}


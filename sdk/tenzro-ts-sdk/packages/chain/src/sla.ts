import type { RpcClient } from "@tenzro/core";

// ── Types ──

/**
 * Probe issued by `tenzro_slaIssueProbe`. The `challenge_nonce` is the
 * 32-byte VRF output used to address the probe through its lifecycle.
 */
export interface SlaProbeIssued {
  /** 0x-prefixed hex of the issuing validator's address (32 bytes). */
  issuer: string;
  /** DID of the provider being probed. */
  provider_did: string;
  /** Validator epoch the probe was issued in. */
  epoch: number;
  /** Probe round within the epoch. */
  round: number;
  /** 0x-prefixed hex of the 32-byte VRF output addressing this probe. */
  challenge_nonce: string;
  /** Unix-millisecond deadline by which the provider must respond. */
  deadline_ms: number;
  /** 0x-prefixed hex of the issuing validator's VRF public key. */
  vrf_pubkey: string;
}

/** A single entry in the outstanding-probes reflector. */
export interface SlaOutstandingProbe {
  challenge_nonce: string;
  provider_did: string;
  epoch: number;
  round: number;
  deadline_ms: number;
  /** 0x-prefixed hex of the issuing validator's address. */
  issuer: string;
}

/** Result of `tenzro_slaListOutstandingProbes`. */
export interface SlaOutstandingProbes {
  count: number;
  probes: SlaOutstandingProbe[];
}

/** Result of `tenzro_slaGetParams`. */
export interface SlaParams {
  /** What a frozen unavailable verdict takes from the provider's compute bond into the insurance pool, wei, decimal string. */
  unavailable_penalty_wei: string;
  /** 0x-prefixed hex of this validator's VRF public key. */
  vrf_pubkey: string;
}

// ── Client ──

/**
 * Validator-side SLA fault-detector inspection client.
 *
 * Wraps:
 * - `tenzro_slaIssueProbe` — issue a VRF-bound liveness probe to a
 *   ModelProvider / TeeProvider DID and broadcast it on the
 *   `tenzro/sla` gossipsub topic. **Validator-only** — non-validator
 *   nodes return `-32000 SlaManager not initialized`.
 * - `tenzro_slaListOutstandingProbes` — list every in-flight probe
 *   awaiting a response, regardless of who issued it. Used by
 *   operators to spot stuck probes whose deadline has already
 *   elapsed without a response.
 * - `tenzro_slaGetParams` — the penalty a frozen unavailable verdict
 *   takes from a compute bond (`unavailable_penalty_wei`) and this
 *   validator's VRF public key.
 */
export class SlaClient {
  constructor(private readonly rpc: RpcClient) {}

  /**
   * Issue a VRF-bound liveness probe to `providerDid`. Validator-only.
   *
   * The issuing node computes the VRF output over
   * `(provider_did, epoch, round)`, registers the probe in its
   * in-memory outstanding-probe map (so a fast response cannot race
   * the insertion), and broadcasts it on the `tenzro/sla` gossipsub
   * topic.
   *
   * @param providerDid - DID of the provider being probed
   * @param epoch - Validator epoch the probe is issued in
   * @param round - Probe round within the epoch
   * @param deadlineMs - Unix-millisecond timestamp by which the
   *   provider must respond before the probe is considered missed
   */
  async issueProbe(
    providerDid: string,
    epoch: number,
    round: number,
    deadlineMs: number
  ): Promise<SlaProbeIssued> {
    return this.rpc.call<SlaProbeIssued>('tenzro_slaIssueProbe', [
      {
        provider_did: providerDid,
        epoch,
        round,
        deadline_ms: deadlineMs,
      },
    ]);
  }

  /**
   * List every in-flight probe awaiting a response from any provider,
   * regardless of issuer. Used by operators to spot probes whose
   * `deadline_ms` has already elapsed without a matching response.
   */
  async listOutstandingProbes(): Promise<SlaOutstandingProbes> {
    return this.rpc.call<SlaOutstandingProbes>(
      'tenzro_slaListOutstandingProbes',
      []
    );
  }

  /**
   * Read the fault-detector parameters this validator is using.
   * Returns the slash threshold (missed probes before slashing
   * fires), the per-crossing slash amount in wei, and this
   * validator's VRF public key.
   */
  async getParams(): Promise<SlaParams> {
    return this.rpc.call<SlaParams>('tenzro_slaGetParams', []);
  }

  /** `tenzro_slaVerdict`. */
  slaVerdict<T = unknown>(params: { epoch?: unknown; provider_did?: unknown } = {}): Promise<T> {
    return this.rpc.call<T>("tenzro_slaVerdict", params);
  }
}

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

/** One readiness tier's row of an {@link SlaEnergyReport}. */
export interface SlaTierEnergy {
  /** The declared readiness tier. */
  tier: 'Cold' | 'Cool' | 'Warm';
  /** Eligible compute bonds whose provider declared this tier. */
  units: number;
  /** Probe rounds between this tier's burst challenges. */
  burst_rounds_between: number;
  /** Challenge energy one unit of this tier spends per day, joules, decimal string. */
  challenge_joules_per_unit_per_day: string;
  /** One unit of this tier's own energy per day, joules, decimal string. */
  idle_joules_per_unit_per_day: string;
  /** These units' own energy over a day, joules, decimal string. */
  fleet_joules_per_day: string;
  /** Challenge energy these units spend over a day, joules, decimal string. */
  challenge_joules_per_day: string;
}

/** Result of `tenzro_slaGetEnergy`. */
export interface SlaEnergyReport {
  /** The governed probe interval in force, ms. */
  probe_interval_ms: number;
  /** Probes one bonded unit answers per day at that interval. */
  probes_per_unit_per_day: number;
  /** Whether the wake-cost rule prices these figures; before it every probe is charged a cool-tier wake. */
  wake_rule_live: boolean;
  /** Challenge energy as a share of the fleet's own energy, basis points. */
  challenge_share_bps: number;
  /** The governed challenge energy budget, basis points; zero is disabled. */
  budget_bps: number;
  /** Whether the cadence in force holds within that budget. */
  within_budget: boolean;
  /** Eligible compute bonds. */
  units: number;
  /** The whole fleet's own energy over a day, joules, decimal string. */
  fleet_joules_per_day: string;
  /** The whole fleet's challenge energy over a day, joules, decimal string. */
  challenge_joules_per_day: string;
  /** The fleet by declared readiness tier, cold first. */
  tiers: SlaTierEnergy[];
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
   * What SLA challenges cost the bonded compute fleet in energy at the
   * probe cadence in force (`tenzro_slaGetEnergy`).
   */
  async energyReport(): Promise<SlaEnergyReport> {
    return this.rpc.call<SlaEnergyReport>('tenzro_slaGetEnergy', []);
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

import { RpcClient } from "@tenzro/core";

/**
 * Evidence chain state already holds of a loss a bonded party caused: a
 * reconciliation mismatch of an attested route's settlement lock that cost
 * the claimant a leg's value. (A stream never pays a provider for an hour
 * judged unavailable, so an SLA miss leaves nothing to claim.)
 */
export type InsuranceEvidence = {
  recon_mismatch: { adapter: string; chain: string; position: number };
};

/** The insurance pool as chain state records it. */
export interface InsurancePool {
  /** Vault address holding the pool. */
  vault: string;
  /** Balance, wei. */
  balance_wei: string;
  /** Claims paid to date. */
  claims_paid: number;
  /** Total paid out, wei. */
  total_paid_wei: string;
  /** Credited from fee revenue, wei. */
  from_fees_wei: string;
  /** Credited from slashed bonds, wei. */
  from_slashes_wei: string;
  /** The most one claim may take now, wei. */
  max_claim_wei: string;
}

/** A claim the pool paid. */
export interface InsuranceClaim {
  claim_id: string;
  claimant: string;
  evidence: InsuranceEvidence;
  loss: string;
  paid: string;
  paid_at_ms: number;
}

/** Paid claims, oldest first. */
export interface ClaimList {
  count: number;
  claims: InsuranceClaim[];
}

/**
 * The network insurance pool. It is funded by a governed share of fee revenue
 * and by slashed agent bonds, and pays the party a piece of evidence names,
 * once, capped by governance.
 */
export class InsuranceClient {
  constructor(private rpc: RpcClient) {}

  /** Every paid claim. */
  async listClaims(): Promise<ClaimList> {
    return this.rpc.call<ClaimList>("tenzro_listInsuranceClaims", {});
  }

  /** One paid claim, or null. */
  async getClaim(claimId: string): Promise<InsuranceClaim | null> {
    return this.rpc.call<InsuranceClaim | null>("tenzro_getInsuranceClaim", { claim_id: claimId });
  }

  /** The pool's balance, history and claim cap. */
  async pool(): Promise<InsurancePool> {
    return this.rpc.call<InsurancePool>("tenzro_getInsurancePoolBalance", {});
  }
}

import { RpcClient } from "@tenzro/core";

/** The work a network duty pays for. */
export type DutyKind =
  | { reconciliation: { route: string; epoch: number } }
  | { grant_relay: { agent_did: string; chain: string; seq: number } };

/** A network duty: work the chain pays the first prover for. */
export interface Duty {
  /** Duty id, hex. */
  id: string;
  kind: DutyKind;
  /** The keyless vault holding the reward, hex. */
  vault: string;
  /** Where an unpaid reward returns, hex. */
  funder: string;
  /** Reward, wei. */
  reward: string;
  opened_at_ms: number;
  expires_at_ms: number | null;
  state: "open" | "paid" | "expired";
  /** Who it paid, once paid. */
  paid_to?: string | null;
}

/** Open duties, oldest first. */
export interface DutyList {
  count: number;
  duties: Duty[];
}

/** One evidence item in the node's JSON form. */
export type Evidence =
  | { audit: Record<string, unknown> }
  | { terms: { agent_did: string } }
  | { settlement: { payment_id: string } }
  | {
      sensor_data: {
        device_did: string;
        payload_digest: string;
        measured_at_ms: number;
        signature: Record<string, unknown>;
      };
    }
  | { finality_proof: { journal: string; seal: string } }
  | { document: { kind: "mandate" | "receipt" | "evidence_pack" | "delivery"; digest: string } };

/** What one evidence item checked to. */
export interface CheckedEvidence {
  kind: string;
  digest: string;
  /** The chain checked it against its own records; a document never is. */
  verified_on_chain: boolean;
}

/** Network duties and evidence checks against chain state. */
export class DutyClient {
  constructor(private rpc: RpcClient) {}

  /** Every open duty. */
  async list(): Promise<DutyList> {
    return this.rpc.call<DutyList>("tenzro_listDuties", {});
  }

  /** One duty by id, or null. */
  async get(dutyId: string): Promise<Duty | null> {
    return this.rpc.call<Duty | null>("tenzro_getDuty", { duty_id: dutyId });
  }

  /** What each evidence item proves against chain state (1 to 16 items). */
  async verifyEvidence(items: Evidence[]): Promise<{ items: CheckedEvidence[] }> {
    return this.rpc.call<{ items: CheckedEvidence[] }>("tenzro_verifyEvidence", { items });
  }
}

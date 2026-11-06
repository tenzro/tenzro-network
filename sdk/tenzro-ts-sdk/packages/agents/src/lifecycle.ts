import { RpcClient } from "@tenzro/core";

/**
 * Client for agent lifecycle and kill-switch queries.
 *
 * The kill-switch records every `TerminateAgent` event — including
 * cascaded terminations from a parent agent — with the canonical reason
 * code, the slash applied to the bond, and the controller that
 * authorised it. These endpoints are read-only inspections of that
 * audit trail; mutations flow through `TerminateAgent` typed
 * transactions.
 */
export class LifecycleClient {
  constructor(private rpc: RpcClient) {}

  /**
   * List every kill-switch receipt whose target is the given agent.
   * @param agentDid - Agent DID
   * @param fromCursor - `cursor` of the previous page, to continue
   * @returns `{agent_did, receipts, cursor}` in chain order
   */
  async listKillSwitchByAgent(agentDid: string, fromCursor?: string): Promise<KillSwitchPage> {
    return this.rpc.call<KillSwitchPage>("tenzro_listKillSwitchByAgent", {
      agent_did: agentDid,
      ...(fromCursor === undefined ? {} : { from_cursor: fromCursor }),
    });
  }

  /**
   * List every kill-switch receipt authored by the given controller DID.
   * @param controllerDid - Controller DID
   * @param fromCursor - `cursor` of the previous page, to continue
   * @returns `{controller_did, receipts, cursor}` in chain order
   */
  async listKillSwitchByController(controllerDid: string, fromCursor?: string): Promise<KillSwitchPage> {
    return this.rpc.call<KillSwitchPage>("tenzro_listKillSwitchByController", {
      controller_did: controllerDid,
      ...(fromCursor === undefined ? {} : { from_cursor: fromCursor }),
    });
  }

  /**
   * Fetch a single kill-switch receipt by its 32-byte id.
   * @param receiptId - Receipt identifier (hex)
   * @returns Kill-switch receipt or null if unknown
   */
  async getKillSwitchReceipt(receiptId: string): Promise<KillSwitchReceipt | null> {
    return this.rpc.call<KillSwitchReceipt | null>("tenzro_getKillSwitchReceipt", { receipt_id: receiptId });
  }
}

/** A kill-switch receipt from consensus state. */
export interface KillSwitchReceipt {
  receipt_id: string;
  action: "pause" | "quarantine" | "terminate";
  agent_did: string;
  controller_did: string;
  reason_code: number;
  reason_text: string | null;
  /** The hash of the evidence, hex. */
  evidence_hash: string | null;
  /** The share of the agent's bond slashed, basis points. */
  slash_bps: number | null;
  /** Whether the action cascades to the agent's sub-agents. */
  cascade: boolean | null;
  /** When a pause ends of itself, Unix seconds; null for a pause that lasts until resumed, and for every other action. */
  pause_until?: number | null;
  frozen_at_block: number;
  /** Unix milliseconds. */
  timestamp: number;
  /** The receipt's event cursor, on a listed receipt. */
  cursor?: string;
}

/** A page of kill-switch receipts; pass `cursor` back to continue, `null` at the end. */
export interface KillSwitchPage {
  agent_did?: string;
  controller_did?: string;
  receipts: KillSwitchReceipt[];
  cursor: string | null;
}

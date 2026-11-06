import { RpcClient } from "@tenzro/core";

/** Wrapped bond list for a controller as returned by the node. */
/** An agent bond as chain state holds it. */
export interface AgentBond {
  agent_did: string;
  controller_did: string;
  /** Wei the bond holds (string-encoded). */
  amount: string;
  state: "Active" | "Cooldown" | "Slashed" | "Returned" | "Burned";
  /** When a withdrawal's cooldown ends, ms. */
  cooldown_until_ms: number | null;
  /** The bond vault, hex. */
  vault: string;
}

export interface ControllerBonds {
  /** The controller DID the list belongs to. */
  controller_did: string;
  /** Number of bonds the controller has posted. */
  count: number;
  /** Sum of the Active bond amounts in wei (string-encoded). */
  aggregate_bond: string;
  /** The bond records. */
  bonds: AgentBond[];
}

/**
 * Client for AgentBond operations.
 *
 * Bonds are TNZO-denominated stakes posted by a controller against a
 * specific agent DID. While Active and ≥ `bond_min_for_promotion`, the
 * bonded agent is promoted to the Delegated admission lane. Bonds are
 * locked at a deterministic vault address derived from the agent DID:
 * `Address(SHA-256("tenzro/agent-bond/vault" || agent_did))`.
 *
 * Read methods query node state directly. Write methods build typed
 * `PostAgentBond` / `IncreaseAgentBond` / `WithdrawAgentBond`
 * transactions and submit them through `tenzro_sendRawTransaction`,
 * matching the {@link SettlementClient.createEscrow} pattern.
 */
export class BondClient {
  constructor(private rpc: RpcClient) {}

  /**
   * Fetch an agent's bond record from chain state.
   * @param agentDid - The agent DID the bond was posted for
   * @returns Bond record or null if none was posted
   */
  async getAgentBond(agentDid: string): Promise<AgentBond | null> {
    return this.rpc.call<AgentBond | null>("tenzro_getAgentBond", { agent_did: agentDid });
  }

  /**
   * List all AgentBonds posted by a given controller DID. The node requires
   * the `controller_did` param by name.
   * @param controllerDid - The controller DID (e.g. `did:tenzro:human:...`)
   * @returns Wrapped bond list: `{controller_did, count, aggregate_bond, bonds}`
   */
  async listAgentBondsByController(
    controllerDid: string,
  ): Promise<ControllerBonds> {
    return this.rpc.call<ControllerBonds>(
      "tenzro_listAgentBondsByController",
      { controller_did: controllerDid },
    );
  }
}

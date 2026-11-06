import type { RpcClient } from "@tenzro/core";
import type { AgentTermsView } from "@tenzro/core";

/**
 * Reads a delegated agent's spend against its consensus Terms. What an agent
 * may pay is its Terms; what it has spent is consensus state.
 */
export class AgentPaymentClient {
  constructor(private readonly rpc: RpcClient) {}

  /**
   * The agent's full Terms, root kind, status and spend so far against each
   * limit.
   * @param agentDid - The agent's DID
   * @returns `null` when the DID has no Terms on chain
   */
  async getTerms(agentDid: string): Promise<AgentTermsView | null> {
    return this.rpc.call<AgentTermsView | null>('tenzro_getAgentTerms', {
      agent_did: agentDid,
    });
  }
}

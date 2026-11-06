import { RpcClient } from "@tenzro/core";

/**
 * Network funding: grant requests and tranche releases.
 *
 * Every write is a signed `Funding` transaction whose gas the treasury pays,
 * so an identity with a zero balance can take part. Requests go to the
 * governance vote.
 */
export class FundingClient {
  constructor(private rpc: RpcClient) {}

  private static address32(hex: string): number[] {
    const clean = hex.replace(/^0x/, "");
    const out = new Array(32).fill(0);
    for (let i = 0; i < clean.length / 2 && i < 32; i++) {
      out[i] = parseInt(clean.substr(i * 2, 2), 16);
    }
    return out;
  }

  /** A tranched grant, or null. */
  async getGrant(grantId: string): Promise<unknown> {
    return this.rpc.call("tenzro_getGrant", [{ grant_id: grantId.replace(/^0x/, "") }]);
  }
}

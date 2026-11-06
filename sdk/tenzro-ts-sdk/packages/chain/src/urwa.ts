import type { RpcClient } from "@tenzro/core";

export interface UrwaKillSwitchState {
  token_id_hex: string;
  active: boolean;
}

export interface UrwaFrozenAmount {
  token_id_hex: string;
  account_hex: string;
  frozen_amount: string;
}

/**
 * ERC-7943 (uRWA) reads from chain state: whether a token's issuer halted
 * holder transfers, and how much of a holder's balance it froze. The issuer's
 * controls (freezing, halting, forced transfers) are `Token` transactions it
 * signs ({@link TokenClient.operation}).
 */
export class UrwaClient {
  constructor(private readonly rpc: RpcClient) {}

  async isKillSwitched(tokenIdHex: string): Promise<UrwaKillSwitchState> {
    return this.rpc.call<UrwaKillSwitchState>('tenzro_urwaIsKillSwitched', [
      { token_id_hex: tokenIdHex },
    ]);
  }

  async getFrozenTokens(tokenIdHex: string, accountHex: string): Promise<UrwaFrozenAmount> {
    return this.rpc.call<UrwaFrozenAmount>('tenzro_urwaGetFrozenTokens', [
      { token_id_hex: tokenIdHex, account_hex: accountHex },
    ]);
  }
}

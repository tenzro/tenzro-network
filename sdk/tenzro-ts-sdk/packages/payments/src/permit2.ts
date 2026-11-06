import type { RpcClient } from "@tenzro/core";

export interface Permit2DigestRequest {
  chain_id: number;
  owner: string;
  token: string;
  amount: string;
  spender: string;
  nonce: string;
  deadline: number;
  /** The witness, 32 bytes hex; the node checks a witness transfer only with all three witness fields. */
  witness?: string;
  /** The witness struct's type name, as in the EIP-712 type string. */
  witness_type_name?: string;
  witness_type_string?: string;
}

export interface Permit2VerifyAndConsumeRequest extends Permit2DigestRequest {
  signature: string;
}

export interface Permit2VerifyAndConsumeResult {
  consumed: boolean;
  word_pos: string;
  bit_pos: number;
}

export interface Permit2NonceUsed {
  used: boolean;
  owner: string;
  nonce: string;
}

/**
 * Permit2 `SignatureTransfer` client. Wraps the canonical Tenzro
 * Permit2 contract at `0x0000…00001023` with optional witness binding.
 */
export class Permit2Client {
  constructor(private readonly rpc: RpcClient) {}

  async verifyAndConsume(
    req: Permit2VerifyAndConsumeRequest
  ): Promise<Permit2VerifyAndConsumeResult> {
    return this.rpc.call<Permit2VerifyAndConsumeResult>(
      'tenzro_permit2VerifyAndConsume',
      [req]
    );
  }

  async nonceUsed(owner: string, nonce: string): Promise<Permit2NonceUsed> {
    return this.rpc.call<Permit2NonceUsed>('tenzro_permit2NonceUsed', [
      { owner, nonce },
    ]);
  }
}

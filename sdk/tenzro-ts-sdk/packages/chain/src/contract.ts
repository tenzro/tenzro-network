import { TypedTxClient } from "@tenzro/core";
import type { HybridSigner, RpcClient } from "@tenzro/core";

// ── Parameter types ──

/** A contract deployment: EVM creation code and its constructor arguments. */
export interface DeployContractParams {
  /** EVM creation code. */
  code: Uint8Array;
  /** ABI-encoded constructor arguments, appended to the code. */
  constructorArgs?: Uint8Array;
  /**
   * Hex deployer account; by default the account the signer's P-256 key
   * names.
   */
  from?: string;
  /** Gas limit; 3,000,000 when unset. */
  gasLimit?: number;
  /** Gas price, smallest TNZO unit; the node's current price when unset. */
  gasPrice?: number;
}

/** One call of a contract-call transaction. */
export interface VmCall {
  /** The VM the call executes in. */
  vm: 'evm' | 'svm';
  /**
   * The code called: an EVM contract (20 bytes) or an SVM program (32 bytes).
   */
  to: Uint8Array;
  /** Native TNZO the call carries, wei. Only EVM calls carry value. */
  value?: bigint;
  /** Calldata in the VM's own format. */
  data: Uint8Array;
}

// ── Return types ──

/** Result of a read-only contract call. */
export interface CallResult {
  /** Hex-encoded return data */
  data: string;
}

/**
 * A deployment admitted to the mempool. The contract exists once a block
 * executes the transaction; its receipt reports the address.
 */
export interface DeployResult {
  /** Hash of the ContractDeploy transaction. */
  tx_hash: string;
  /** `"admitted"`. */
  status: string;
}

// ── Client ──

/** Client for deploying EVM contracts and reading them. */
export class ContractClient {
  constructor(private readonly rpc: RpcClient) {}

  /**
   * Sign a ContractDeploy transaction with `signer` and submit it. The
   * signature covers the code, the arguments, the nonce, the chain and the
   * sender; the contract is created when a block executes it.
   */
  async deploy(signer: HybridSigner, params: DeployContractParams): Promise<DeployResult> {
    return (await new TypedTxClient(this.rpc).sendVia('tenzro_deployContract', signer, {
      kind: 'ContractDeploy',
      fields: {
        code: Array.from(params.code),
        args: Array.from(params.constructorArgs ?? new Uint8Array()),
      },
      to: `0x${'00'.repeat(32)}`,
      from: params.from,
      gasLimit: params.gasLimit ?? 3_000_000,
      gasPrice: params.gasPrice,
    })) as DeployResult;
  }

  /**
   * Perform a read-only contract call (eth_call).
   * @param to - Contract address (hex)
   * @param data - ABI-encoded call data (hex)
   * @param block - Block number or "latest" (default: "latest")
   */
  async callContract(to: string, data: string, block?: string): Promise<CallResult> {
    const result = await this.rpc.call<string>('eth_call', [
      { to, data },
      block ?? 'latest',
    ]);
    return { data: result };
  }

}

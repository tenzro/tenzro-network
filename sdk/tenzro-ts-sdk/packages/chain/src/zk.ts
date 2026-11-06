import type { RpcClient } from "@tenzro/core";

// ── Types ──

/** One proof system's proof of a statement, hex. */
export interface ZkProofLeg {
  /** Proof system, as the node names it (see `listCircuits`). */
  system: string;
  /** The proof bytes, 0x-prefixed hex. */
  proof: string;
  /** Size of the proof in bytes (present on proofs the node made). */
  proof_size_bytes?: number;
}

/** A statement proven in every proof system the node runs (`tenzro_createZkProof`). */
export interface ZkProof {
  /** The circuit: `settlement` (a node never proves `identity`). */
  circuit_id: string;
  /** Public inputs, 0x-prefixed hex: the digest and the binding. */
  public_inputs: string[];
  /** Commitment to the circuit and its public inputs. */
  statement_commitment: string;
  /** One proof per proof system. */
  proofs: ZkProofLeg[];
}

/** The verdict on a statement's proofs (`tenzro_verifyZkProof`). */
export interface ZkVerifyResult {
  /** Whether every given proof verifies. */
  valid: boolean;
  circuit_id: string;
  statement_commitment: string;
  /** Number of proofs given. */
  legs: number;
  /** Proof systems whose proofs verified. */
  verified_systems: string[];
  /** Proof systems a statement needs before it is attested. */
  diverse_threshold: number;
  /** Whether the proofs span enough systems for the statement to be attested. */
  meets_diverse_threshold: boolean;
  /** The AttestZkProof transactions submitted, one per proof, when attested. */
  attestations: Array<{ system: string; commitment_hex: string; attest_tx: string | { error: string } }>;
  /** Why verification failed, when it did. */
  error: string | null;
  note: string;
}

/** A circuit the node proves and verifies (`tenzro_listCircuits`). */
export interface CircuitInfo {
  /** Circuit id: `identity` or `settlement`. */
  type: string;
  /** The AIR the circuit is built on. */
  name: string;
  /** What a proof shows. */
  statement: string;
  public_inputs: string[];
  in_circuit_hash: string;
  /** Whether a node may prove it (an identity proof is made by the key holder). */
  node_provable: boolean;
  /** Each proof system with its parameters and security level. */
  proof_systems: Array<Record<string, unknown> & { system: string; implementation: string }>;
  diverse_threshold: number;
}

/** A ZK proof bound to a TEE attestation (`tenzro_createTeeZkProof`). */
export interface TeeZkProofResult {
  /** The bundle to pass to `verifyTeeZkProof`. */
  tee_zk_proof: Record<string, unknown>;
  binding_digest: string;
  circuit_id: string;
  vendor: string;
}

/** The verdict on a TEE-bound ZK proof (`tenzro_verifyTeeZkProof`). */
export interface TeeZkVerifyResult {
  admitted: boolean;
  circuit_id: string;
  system: string;
  proof_and_binding_valid: boolean;
  proof_and_binding_error: string | null;
  attestation_valid: boolean;
  attestation_error: string | null;
  vendor: string;
  binding_digest: string;
}

/** A finality proof bound to the node's TEE (`tenzro_attestFinalityProof`). */
export interface AttestedFinalityProof {
  vendor: string;
  binding_digest: string;
  measurements: Record<string, unknown>;
  /** The bundle to pass to `verifyTeeFinalityProof`. */
  tee_finality_proof: Record<string, unknown>;
}

/** Whether a proof commitment is attested on chain (`tenzro_getZkAttestation`). */
export interface ZkAttestation {
  commitment_hex: string;
  attested: boolean;
}

// ── Client ──

/**
 * Client for zero-knowledge proofs: the node proves a settlement statement in
 * every proof system it runs, verifies proofs of a statement, and binds proofs
 * to an attestation of its TEE.
 */
export class ZkClient {
  constructor(private readonly rpc: RpcClient) {}

  /**
   * Prove a statement in every proof system the node runs (`tenzro_createZkProof`).
   * @param circuitId - `settlement` (identity statements are proven by the key holder, never a node)
   * @param witness - The 32-byte witness, hex
   * @param binding - The 32-byte request binding, hex
   */
  async createProof(circuitId: string, witness: string, binding: string): Promise<ZkProof> {
    return this.rpc.call<ZkProof>("tenzro_createZkProof", { circuit_id: circuitId, witness, binding });
  }

  /**
   * Verify proofs of one statement (`tenzro_verifyZkProof`). When they span
   * enough proof systems, the node submits each as an AttestZkProof transaction.
   * @param circuitId - `identity` or `settlement`
   * @param publicInputs - The digest and the binding, hex
   * @param proofs - One proof per proof system
   */
  async verifyProof(
    circuitId: string,
    publicInputs: string[],
    proofs: Array<{ system: string; proof: string }>,
  ): Promise<ZkVerifyResult> {
    return this.rpc.call<ZkVerifyResult>("tenzro_verifyZkProof", {
      circuit_id: circuitId,
      public_inputs: publicInputs,
      proofs: proofs.map(({ system, proof }) => ({ system, proof })),
    });
  }

  /** The circuits the node proves and verifies, with their proof systems. */
  async listCircuits(): Promise<CircuitInfo[]> {
    const out = await this.rpc.call<{ circuits: CircuitInfo[]; total: number }>("tenzro_listCircuits", {});
    return out.circuits;
  }

  /**
   * `tenzro_attestFinalityProof`: bind a wrapped finality proof made on the
   * node's machine to an attestation of its TEE. Hex fields as
   * `tenzro-finality-prover wrap` writes them.
   */
  attestFinalityProof(params: { image_id: string; journal: string; seal: string }): Promise<AttestedFinalityProof> {
    return this.rpc.call<AttestedFinalityProof>("tenzro_attestFinalityProof", params);
  }

  /**
   * `tenzro_verifyTeeFinalityProof`: verify a bundle from
   * `attestFinalityProof`; returns the verified measurement registers.
   */
  verifyTeeFinalityProof<T = Record<string, unknown>>(params: { tee_finality_proof: unknown }): Promise<T> {
    return this.rpc.call<T>("tenzro_verifyTeeFinalityProof", params);
  }

  /**
   * `tenzro_createTeeZkProof`: prove a statement and bind the proof to an
   * attestation of the node's TEE.
   * @param params.vendor - `intel-tdx`, `amd-sev-snp`, `aws-nitro` or `intel-sgx`; must be the node's TEE
   */
  createTeeZkProof(params: { circuit_id: string; vendor: string; witness: string; binding: string }): Promise<TeeZkProofResult> {
    return this.rpc.call<TeeZkProofResult>("tenzro_createTeeZkProof", params);
  }

  /** `tenzro_getZkAttestation`: whether a proof commitment (32-byte hex) is attested on chain. */
  getZkAttestation(params: { commitment: string }): Promise<ZkAttestation> {
    return this.rpc.call<ZkAttestation>("tenzro_getZkAttestation", params);
  }

  /** `tenzro_listZkCircuits`: the circuit catalogue as a bare list. */
  listZkCircuits(): Promise<CircuitInfo[]> {
    return this.rpc.call<CircuitInfo[]>("tenzro_listZkCircuits", {});
  }

  /** `tenzro_verifyTeeZkProof`: verify a bundle from `createTeeZkProof`. */
  verifyTeeZkProof(params: { tee_zk_proof: unknown }): Promise<TeeZkVerifyResult> {
    return this.rpc.call<TeeZkVerifyResult>("tenzro_verifyTeeZkProof", params);
  }
}

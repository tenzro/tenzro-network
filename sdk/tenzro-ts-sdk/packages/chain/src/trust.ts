import { RpcClient } from "@tenzro/core";

/** What kind of statement an issuer makes about a subject. */
export type ClaimKind =
  | "certification"
  | "rating"
  | "evaluation"
  | "safety-scan"
  | "policy-conformance";

/** Where a credential stands right now. */
export type CredentialState =
  | "valid"
  | "not-yet-valid"
  | "expired"
  | "revoked"
  | "issuer-revoked";

/** The result of submitting a record. */
export interface SubmitResult {
  kind: string;
  /** The record's digest; a manifest's root; a violation's id. */
  key: string;
  /** False when the ledger already held this record. */
  new: boolean;
  violation: unknown | null;
  slash: unknown | null;
}

/**
 * Certifications, ratings, operator policies and model provenance.
 *
 * Every record is signed by its author on their own TPM, Secure Enclave or
 * passkey before it reaches this client, and the node re-verifies each one, so
 * submitting a record grants it nothing it cannot prove. Records are JSON
 * documents (W3C Verifiable Credential 2.0 shapes with an `ecdsa-jcs-2019`
 * proof) and are passed through unchanged.
 */
export class TrustClient {
  constructor(private rpc: RpcClient) {}

  /**
   * Submits a signed credential, revocation, issuer revocation,
   * operator policy, origin attestation, model manifest or policy violation
   * evidence. A violation proven for the first time slashes the operator's
   * compute bond; the result reports it.
   */
  async submit(record: unknown): Promise<SubmitResult> {
    return this.rpc.call<SubmitResult>("tenzro_submitTrustRecord", { record });
  }

  /**
   * Verifies a credential: its proof, its validity window, the issuer's status
   * list and whether the issuer's key was revoked.
   */
  async verifyCredential(credential: unknown): Promise<{
    valid: boolean;
    state?: CredentialState;
    anchored?: boolean;
    error?: string;
  }> {
    return this.rpc.call("tenzro_verifyTrustCredential", { credential });
  }

  /**
   * Credentials about a subject: `tenzro:model:<root>`, an operator DID, or a
   * model name with a verified manifest.
   */
  async credentials(subject: string): Promise<unknown> {
    return this.rpc.call("tenzro_getTrustCredentials", { subject });
  }

  /** An issuer's Bitstring Status List and the revocations it was built from. */
  async statusList(issuer: string): Promise<unknown> {
    return this.rpc.call("tenzro_getStatusList", { issuer });
  }

  /** An operator's policy in force, its history and its proven violations. */
  async operatorPolicy(operator: string): Promise<unknown> {
    return this.rpc.call("tenzro_getOperatorPolicy", { operator });
  }

  /**
   * A model's manifests, origin observations and verification status, by
   * manifest root or by name. Naming `file` also returns that file's manifest
   * entry and Merkle inclusion proof.
   */
  async modelProvenance(rootOrName: string, file?: string): Promise<unknown> {
    const isRoot = rootOrName.length === 64 && /^[0-9a-f]+$/.test(rootOrName);
    const params: Record<string, unknown> = isRoot
      ? { root: rootOrName }
      : { name: rootOrName };
    if (file !== undefined) {
      params.file = file;
    }
    return this.rpc.call("tenzro_getModelProvenance", params);
  }

  /** `tenzro_auditInferenceChallenge`. */
  auditInferenceChallenge<T = unknown>(params: { challenge?: unknown; challenge_id?: unknown } = {}): Promise<T> {
    return this.rpc.call<T>("tenzro_auditInferenceChallenge", params);
  }

  /** `tenzro_buildModelManifest` (operator only). */
  buildModelManifest<T = unknown>(params: { name?: unknown } = {}): Promise<T> {
    return this.rpc.call<T>("tenzro_buildModelManifest", params);
  }

  /** `tenzro_commitChallengeVote` (operator only). */
  commitChallengeVote<T = unknown>(params: { challenge_id?: unknown; commit_hash?: unknown; signature?: unknown; voter?: unknown } = {}): Promise<T> {
    return this.rpc.call<T>("tenzro_commitChallengeVote", params);
  }

  /** `tenzro_fileInferenceChallenge`. */
  fileInferenceChallenge<T = unknown>(params: { challenger?: unknown; commitment_hash?: unknown; reason?: unknown } = {}): Promise<T> {
    return this.rpc.call<T>("tenzro_fileInferenceChallenge", params);
  }

  /** `tenzro_finalizeChallenge`. */
  finalizeChallenge<T = unknown>(params: { challenge_id?: unknown } = {}): Promise<T> {
    return this.rpc.call<T>("tenzro_finalizeChallenge", params);
  }

  /** `tenzro_registerKeyRelease`: register a model's key-release policy: a KeyRelease transaction signed by the account that owns the policy. */
  registerKeyRelease<T = unknown>(params: Record<string, unknown> = {}): Promise<T> {
    return this.rpc.call<T>("tenzro_registerKeyRelease", params);
  }

  /** `tenzro_revokeKeyRelease`: revoke a model's key-release policy: a KeyRelease transaction signed by the account that owns the policy. */
  revokeKeyRelease<T = unknown>(params: Record<string, unknown> = {}): Promise<T> {
    return this.rpc.call<T>("tenzro_revokeKeyRelease", params);
  }

  /** `tenzro_requestKeyRelease`: submit an attested environment's release request (`request`), which the provider node verifies and records. */
  requestKeyRelease<T = unknown>(params: Record<string, unknown> = {}): Promise<T> {
    return this.rpc.call<T>("tenzro_requestKeyRelease", params);
  }

  /** `tenzro_getKeyRelease`: a model's release policy and releases (`model_id`), or for a recorded `request` the content key sealed to the environment. */
  getKeyRelease<T = unknown>(params: Record<string, unknown> = {}): Promise<T> {
    return this.rpc.call<T>("tenzro_getKeyRelease", params);
  }

  /** `tenzro_commitTrainingRound`: commit a training round's signed receipt against its milestone escrow. */
  commitTrainingRound<T = unknown>(params: Record<string, unknown> = {}): Promise<T> {
    return this.rpc.call<T>("tenzro_commitTrainingRound", params);
  }

  /** `tenzro_settleTrainingRound`: settle a committed training round (`receipt_id`) once its challenge window has closed. */
  settleTrainingRound<T = unknown>(params: Record<string, unknown> = {}): Promise<T> {
    return this.rpc.call<T>("tenzro_settleTrainingRound", params);
  }

  /** `tenzro_trainedModelProvenance`: the provenance of a trained model (`model_id`) from its committed training rounds (`rounds`). */
  trainedModelProvenance<T = unknown>(params: Record<string, unknown> = {}): Promise<T> {
    return this.rpc.call<T>("tenzro_trainedModelProvenance", params);
  }

  /** `tenzro_getToolCallRecords`: the tool-call records this node signed for an agent (`agent_did`, `limit`), and whether it records. */
  getToolCallRecords<T = unknown>(params: Record<string, unknown> = {}): Promise<T> {
    return this.rpc.call<T>("tenzro_getToolCallRecords", params);
  }

  /** `tenzro_agentNodePqKey`: this node's ML-DSA-65 key for an agent (`agent_did`) and its proof of possession. */
  agentNodePqKey<T = unknown>(params: Record<string, unknown> = {}): Promise<T> {
    return this.rpc.call<T>("tenzro_agentNodePqKey", params);
  }

  /** `tenzro_getAttestationLog`: the node's attestation log, `{ head, entries }`. */
  getAttestationLog<T = { head: string; entries: unknown[] }>(): Promise<T> {
    return this.rpc.call<T>("tenzro_getAttestationLog", {});
  }

  /** `tenzro_getInferenceChallenge`. */
  getInferenceChallenge<T = unknown>(params: { challenge_id?: unknown } = {}): Promise<T> {
    return this.rpc.call<T>("tenzro_getInferenceChallenge", params);
  }

  /** `tenzro_getInferenceCommitment`. */
  getInferenceCommitment<T = unknown>(params: { commitment_hash?: unknown } = {}): Promise<T> {
    return this.rpc.call<T>("tenzro_getInferenceCommitment", params);
  }

  /** `tenzro_hostModel` (operator only): Host a model's files in this node's blob store, by manifest `root`, model `name` or local `path`. */
  hostModel<T = unknown>(params: { name?: string; root?: string; path?: string }): Promise<T> {
    return this.rpc.call<T>("tenzro_hostModel", params);
  }

  /** `tenzro_listInferenceChallenges`. */
  listInferenceChallenges<T = unknown>(params: { provider?: unknown; status?: unknown } = {}): Promise<T> {
    return this.rpc.call<T>("tenzro_listInferenceChallenges", params);
  }

  /**
   * `tenzro_publishTeeMeasurement` (operator only): publish the measurement
   * of an attestation `report` answering the challenge `nonce` (32 bytes,
   * hex), signed by the publisher's hardware key.
   */
  publishTeeMeasurement<T = unknown>(params: {
    report: unknown;
    nonce: string;
    publisher_key_hex: string;
    signature_hex: string;
  }): Promise<T> {
    return this.rpc.call<T>("tenzro_publishTeeMeasurement", params);
  }

  /** `tenzro_revealChallengeVote` (operator only). */
  revealChallengeVote<T = unknown>(params: { challenge_id?: unknown; salt?: unknown; signature?: unknown; verdict?: unknown; voter?: unknown } = {}): Promise<T> {
    return this.rpc.call<T>("tenzro_revealChallengeVote", params);
  }

  /** `tenzro_scanModelFiles` (operator only): Scan a model's files for unsafe formats and record the result as a safety-scan claim. */
  scanModelFiles<T = unknown>(params: { name?: string; root?: string; path?: string }): Promise<T> {
    return this.rpc.call<T>("tenzro_scanModelFiles", params);
  }

  /** `tenzro_signChallengeVote` (operator only). */
  signChallengeVote<T = unknown>(params: { challenge_id?: unknown; commit_hash?: unknown; salt?: unknown; verdict?: unknown } = {}): Promise<T> {
    return this.rpc.call<T>("tenzro_signChallengeVote", params);
  }

  /** `tenzro_verifyInferenceCommitment`. */
  verifyInferenceCommitment<T = unknown>(params: { commitment_hash?: unknown; prompt?: unknown; receipt?: unknown } = {}): Promise<T> {
    return this.rpc.call<T>("tenzro_verifyInferenceCommitment", params);
  }

  /** `tenzro_verifyInferenceReceipt`. */
  verifyInferenceReceipt<T = unknown>(params: { level?: unknown; receipt?: unknown } = {}): Promise<T> {
    return this.rpc.call<T>("tenzro_verifyInferenceReceipt", params);
  }

  /** `tenzro_verifyModelFiles` (operator only): Check a model's files against its verified manifest. */
  verifyModelFiles<T = unknown>(params: { name?: string; root?: string; path?: string }): Promise<T> {
    return this.rpc.call<T>("tenzro_verifyModelFiles", params);
  }
}

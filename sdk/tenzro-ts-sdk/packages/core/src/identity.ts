import { RpcClient } from "./rpc";
import { withRequestEnvelope } from "./did-envelope";
import type { HybridSigner } from "./wallet";
import { IdentityInfo, IdentityType, DidDocument, JoinAsMicroNodeResponse } from "./types";

/** One identity in a `tenzro_listIdentities` listing. */
export interface IdentityListEntry {
  did: string;
  /** `human`, `machine` or `institution`. */
  type: string;
  status: string;
  created_at: string;
  [field: string]: unknown;
}

/** `tenzro_listIdentities`. */
export interface IdentityList {
  human_count: number;
  machine_count: number;
  total_count: number;
  identities: IdentityListEntry[];
  /** Whether the node held more than it listed. */
  truncated: boolean;
}

/** Result of `tenzro_registerIdentity`. */
export interface RegisterIdentityResult {
  did: string;
  identity_type: string;
  status: string;
  /** Hash of the `RegisterIdentity` transaction that replicates the identity. */
  tx_hash: string;
}

/** A DID-signed envelope over a payload. */
export interface DidEnvelope {
  payload: unknown;
  signature: string;
  signer_did: string;
  alg: string;
  [extra: string]: unknown;
}

/**
 * Client for Tenzro Decentralized Identity Protocol (TDIP) operations.
 * Supports both human and machine identities with W3C DID documents.
 */
export class IdentityClient {
  constructor(private rpc: RpcClient) {}

  /**
   * Register a human identity bound to a passkey (`tenzro_registerIdentity`
   * with `identity_type` `human`). `publicKey` is the passkey's P-256 key and
   * `credentialId` its credential id (both hex); `proof` is the passkey's
   * composite signature over the registration statement under the
   * `IdentityRegistration` context, which the node requires. Applications
   * enrolling a passkey from a browser use `PasskeyRpcClient.enroll` instead,
   * which takes the WebAuthn registration as it comes.
   * @returns The DID and the hash of the `RegisterIdentity` transaction that
   *   replicates it. The node records nothing when it cannot submit that
   *   transaction, and the call fails instead.
   */
  async registerHuman(params: {
    displayName: string;
    publicKey: string;
    credentialId: string;
    proof: Record<string, unknown>;
  }): Promise<RegisterIdentityResult> {
    return this.rpc.call("tenzro_registerIdentity", {
      identity_type: "human",
      display_name: params.displayName,
      public_key: params.publicKey,
      credential_id: params.credentialId,
      proof: params.proof,
    });
  }

  /**
   * Register a machine identity under a controller
   * (`tenzro_registerMachineIdentity`).
   *
   * The machine acts for its controller, carries its delegation scope and
   * draws on its admission quota, so the controller signs the request:
   * `controller` is the controller's own passkey, TPM or Secure Enclave
   * signer, and the request carries its DID envelope over every field. The
   * node refuses a request without one, or with one from any other DID.
   *
   * @param params.controllerDid - DID of the controlling identity
   * @param params.publicKey - The machine's P-256 public key (hex, `x || y`), from its TPM or Secure Enclave
   * @param params.capabilities - Capabilities of the machine
   * @param controller - Signer holding the key `controllerDid` resolves to
   * @returns The machine's DID, its controller, status and capabilities
   */
  async registerMachine(
    params: { controllerDid: string; publicKey: string; capabilities: string[] },
    controller: HybridSigner
  ): Promise<IdentityInfo> {
    const request = await withRequestEnvelope(controller, params.controllerDid, "tenzro_registerMachineIdentity", {
      controller_did: params.controllerDid,
      public_key: params.publicKey,
      capabilities: params.capabilities,
    });
    return this.rpc.call("tenzro_registerMachineIdentity", request);
  }

  /**
   * Resolve a DID to get identity information.
   * @param did - The DID to resolve (e.g., "did:tenzro:human:..." or "did:tenzro:machine:...")
   * @returns Identity information
   */
  async resolve(did: string): Promise<IdentityInfo> {
    return this.rpc.call<IdentityInfo>("tenzro_resolveIdentity", [{ did }]);
  }

  /**
   * Resolve a DID to get the full W3C DID Document.
   * @param did - The DID to resolve
   * @returns W3C DID Document
   */
  async resolveDidDocument(did: string): Promise<DidDocument> {
    return this.rpc.call<DidDocument>("tenzro_resolveDidDocument", [{ did }]);
  }

  /**
   * The service entries of a DID's document and the version of the list,
   * from consensus state. A change is an `IdentityServices` transaction the
   * DID's root approves for this version.
   */
  async didServices(did: string): Promise<DidServices> {
    return this.rpc.call<DidServices>("tenzro_getDidServices", { did });
  }

  /**
   * The identities this node's registry holds, with counts by kind. The node
   * returns at most its listing cap and says so in `truncated`. With
   * `identityType`, only identities of that kind are kept.
   */
  async listIdentities(identityType?: IdentityType): Promise<IdentityList> {
    const list = await this.rpc.call<IdentityList>("tenzro_listIdentities", {});
    if (identityType === undefined) return list;
    const kind = identityType.toLowerCase();
    return { ...list, identities: list.identities.filter((i) => i.type === kind) };
  }

  /**
   * Join the Tenzro Network as a MicroNode participant.
   * Zero-install — no P2P binary required.
   * Provisions a TDIP DID and a wallet bound to the caller's identity key:
   * the P-256 public key (x || y, hex) with the passkey `credential_id` of a
   * human, or the `machine_id` of a secure-element key. The node never mints
   * a key.
   * @param params - The identity key, and an optional display name, origin hint and participant type
   * @returns Full MicroNode identity, wallet, capabilities, and network endpoints
   */
  async joinAsMicroNode(params: {
    public_key: string;
    credential_id?: string;
    machine_id?: string;
    display_name?: string;
    origin?: string;
    participant_type?: string;
  }): Promise<JoinAsMicroNodeResponse> {
    return this.rpc.call<JoinAsMicroNodeResponse>("tenzro_joinAsMicroNode", { ...params });
  }

  /** Verify a DID-signed envelope (for example an off-chain signed result). */
  async verifyDidEnvelope(envelope: DidEnvelope): Promise<unknown> {
    return this.rpc.call('tenzro_verifyDidEnvelope', { envelope });
  }

  /** `tenzro_get7702Delegation`. */
  get7702Delegation<T = unknown>(params: { authority?: unknown } = {}): Promise<T> {
    return this.rpc.call<T>("tenzro_get7702Delegation", params);
  }

  /**
   * `tenzro_issueKyaCredential` (operator only): a know-your-agent credential
   * about `did`, signed by this node, valid for `validity_secs`.
   */
  issueKyaCredential<T = unknown>(params: { did: string; validity_secs?: number }): Promise<T> {
    return this.rpc.call<T>("tenzro_issueKyaCredential", params);
  }

  /** `tenzro_mirrorSettlement` (operator only). */
  mirrorSettlement<T = unknown>(params: { interaction?: unknown; targets?: unknown; primary_committed?: unknown } = {}): Promise<T> {
    return this.rpc.call<T>("tenzro_mirrorSettlement", params);
  }

  /** `tenzro_nodeDidDocument`. */
  nodeDidDocument<T = unknown>(): Promise<T> {
    return this.rpc.call<T>("tenzro_nodeDidDocument");
  }

  /**
   * `tenzro_rotateIdentityToPq`: hand the authority of `did` to the hardware
   * ML-DSA-65 key `new_pq_key` (hex). The key the DID derives from signs the
   * rotation (`authority_signature`) and the new key signs it
   * (`new_key_signature`); `sequence` is the next rotation number.
   */
  rotateIdentityToPq<T = unknown>(params: {
    did: string;
    new_pq_key: string;
    backend: string;
    sequence: number;
    authority_signature: string;
    new_key_signature: string;
  }): Promise<T> {
    return this.rpc.call<T>("tenzro_rotateIdentityToPq", params);
  }

  /** `tenzro_updateIdentity`. */
  updateIdentity<T = unknown>(params: { did?: unknown; kind?: unknown; update?: unknown } = {}): Promise<T> {
    return this.rpc.call<T>("tenzro_updateIdentity", params);
  }

  /** `tenzro_verifyKyaCredential`. */
  verifyKyaCredential<T = unknown>(params: { credential?: unknown } = {}): Promise<T> {
    return this.rpc.call<T>("tenzro_verifyKyaCredential", params);
  }

  /** `tenzro_verifyNodeDidDocument`. */
  verifyNodeDidDocument<T = unknown>(params: { document?: unknown; id?: unknown } = {}): Promise<T> {
    return this.rpc.call<T>("tenzro_verifyNodeDidDocument", params);
  }
}

/** One service entry of a DID's document, as consensus state holds it. */
export interface DidServiceEntry {
  /** The fragment of its id: the document lists it as `<did>#<id>`. */
  id: string;
  service_type: string;
  endpoint: string;
}

/** Result of `tenzro_getDidServices`. */
export interface DidServices {
  did: string;
  /** One more per change; a change names the version it applies to. */
  version: number;
  services: DidServiceEntry[];
}

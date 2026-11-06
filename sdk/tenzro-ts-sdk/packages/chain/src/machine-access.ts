import { RpcClient } from "@tenzro/core";

/** A part of the machine a grant reaches. */
export type MachineResource =
  | { kind: "network"; cidr: string; port?: number | null }
  | { kind: "folder"; path: string };

/** What the machine owner signs to add a grant. */
export interface MachineAccessTerms {
  /** The node's machine DID for any sandboxed job on it, or an agent or tool DID. */
  grantee_did: string;
  resources: MachineResource[];
  /** `connect` for networks, `read` and/or `write` for folders. */
  operations: string[];
  /** When the grant ends, in milliseconds since the Unix epoch. */
  expires_at_ms: number;
  max_uses_per_minute?: number | null;
  /** Most bytes moved through the grant. */
  max_bytes?: number | null;
}

/** The change a custody challenge is issued for. */
export type MachineAccessChange =
  | ({ action: "add" } & MachineAccessTerms)
  | { action: "list" }
  | { action: "revoke"; grant_id: string };

/**
 * Machine access: what a machine's owner lets agents, tools and models on a
 * node reach.
 *
 * Nothing on a node can reach its loopback services, its LAN, cloud metadata
 * endpoints or host folders unless the machine's owner signed a grant for it.
 * Every change is signed by the owner in two steps: `challenge` returns a
 * custody challenge bound to exactly the change; the owner approves it in
 * their wallet (a passkey assertion and an ML-DSA-65 signature over the
 * digest); the approval, with `challenge_id` set, goes to `add`, `list` or
 * `revoke` as `authorization`.
 */
export class MachineAccessClient {
  private rpc: RpcClient;

  constructor(rpc: RpcClient) {
    this.rpc = rpc;
  }

  /**
   * Issue the custody challenge for `change`. Returns `challenge_id`,
   * `webauthn_challenge` (what the owner's passkey signs) and the owner's
   * `account_address`.
   * Terms the node would refuse are refused here, before anyone signs them.
   */
  async challenge(change: MachineAccessChange): Promise<any> {
    return this.rpc.call("tenzro_createCustodyChallenge", {
      operation: "machine_access",
      machine_access: change,
    });
  }

  /** Add a grant with exactly the terms the challenge was issued for. */
  async add(terms: MachineAccessTerms, authorization: unknown): Promise<any> {
    return this.rpc.call("tenzro_addMachineAccess", { ...terms, authorization });
  }

  /** The grants on the node, with their use, refusal and byte counts. */
  async list(authorization: unknown): Promise<any> {
    return this.rpc.call("tenzro_listMachineAccess", { authorization });
  }

  /** Revoke a grant. It stops applying at once. */
  async revoke(grantId: string, authorization: unknown): Promise<any> {
    return this.rpc.call("tenzro_revokeMachineAccess", {
      grant_id: grantId,
      authorization,
    });
  }
}

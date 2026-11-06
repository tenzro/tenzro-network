/**
 * `TenzroAgentWallet` — the composite agent-wallet surface.
 *
 * Composes `passkeyRpc.*`, `bond.*`, and delegation-scope
 * helpers into one class so a developer can do:
 *
 *   const aw = client.agentWallet;
 *   const { smart_account_address, did } = await aw.spawn({
 *     displayName: "Trader-7",
 *     passkeyPublicKeyHex,
 *     credentialIdHex,
 *     authorization,
 *   });
 *
 * Substrates composed:
 *   - `tenzro_enrollPasskey`       → the account the passkey derives,
 *     with its keystore (the passkey alone until its first change).
 *   - `PostAgentBond` typed tx via `tenzro_sendRawTransaction` /
 *     `tenzro_getAgentBond` /
 *     `tenzro_listAgentBondsByController`
 *                                  → AgentBond economic substrate
 *     (Active/Cooldown/Frozen/Slashed/Returned, governance-gated
 *     insurance claims).
 *
 * Three-class TDIP identity model:
 *   spawn()       — autonomous-agent class (TEE-attested).
 *   delegateTo()  — delegated-agent class (controller-signed scope).
 *   getRisk()     — composite risk score combining bond status
 *                   and delegation scope — for explorer + counterparty surfaces.
 *
 * What this class does NOT do (deliberately):
 *   - Does not hold or transit the device passkey private key — that
 *     stays in the platform secure enclave; the caller passes raw
 *     SEC1 / COSE_Key public bytes and the credential id only.
 *   - Does not run the WebAuthn ceremony — `navigator.credentials.*`
 *     is host-side glue (Tauri commands `device_create_passkey` /
 *     `device_sign_with_passkey` in Studio; browser API elsewhere).
 *   - Does not handle PIN — PIN is a device-local session-re-auth
 *     accelerator, never sent over RPC.
 */

import type { KeystoreAnchor, KeystoreRecord, RpcClient } from "@tenzro/core";
import {
  PasskeyRpcClient,
  type EnrollPasskeyParams,
  type EnrollPasskeyResponse,
} from "@tenzro/core";
import { BondClient, type ControllerBonds } from "./bond";


/** Result of `spawn()` — the autonomous-agent identity + the smart
 *  account that holds its keys. The address is CREATE2-deterministic
 *  from `sha256(passkey ‖ credential ‖ did)`, so the same passkey
 *  always yields the same account regardless of restarts. */
export interface SpawnAgentResult {
  /** TDIP DID of the new agent (`did:tenzro:agent:...`). */
  did: string;
  /** The account address the passkey derives (20 bytes hex). */
  smartAccountAddress: string;
  /** The passkey's credential id, which its authenticator locates it by. */
  credentialIdHex: string;
  /** The account's keystore: the passkey alone until its first keystore change. */
  keystore: KeystoreRecord;
  /** What the account's first keystore change carries; null once it has one on chain. */
  anchor: KeystoreAnchor | null;
}

/** Composite risk profile — what an explorer page or a counterparty
 *  RPC consumer should look at before transacting with an agent.
 *  Substrate already exists on the node; this just packages it. */
export interface AgentRiskSnapshot {
  did: string;
  /** Aggregate active bond across all controllers, in TNZO base units. */
  aggregateBondTnzo: string;
  /** Count of currently-Active bonds (`Active`/`Cooldown`/`Frozen`/`Slashed`/`Returned`). */
  activeBondCount: number;
  /** Most recent slashing event timestamp (unix secs), or null. */
  lastSlashSecs: number | null;
  /** Most recent insurance claim against this agent, or null. */
  lastInsuranceClaimSecs: number | null;
}

export class TenzroAgentWallet {
  /** Underlying clients are public so power users can drop down when
   *  the composite surface doesn't cover their case. The composite
   *  is opinionated — these aren't. */
  public readonly passkey: PasskeyRpcClient;
  public readonly bond: BondClient;

  constructor(rpc: RpcClient) {
    this.passkey = new PasskeyRpcClient(rpc);
    this.bond = new BondClient(rpc);
  }

  /**
   * Spawn a new autonomous-agent identity backed by a passkey-rooted
   * smart account. The caller is responsible for producing the
   * WebAuthn credential externally (Studio: `device_create_passkey`;
   * browser: `navigator.credentials.create`).
   *
   * The node registers the identity the passkey derives and returns the
   * account it derives. Nothing about the account is stored by the node:
   * its keystore is the passkey alone until its first `KeystoreUpdate`.
   * Re-calling with the same passkey, credential and salt yields the same
   * address.
   */
  async spawn(params: EnrollPasskeyParams): Promise<SpawnAgentResult> {
    const resp: EnrollPasskeyResponse = await this.passkey.enroll(params);
    return {
      did: resp.did,
      smartAccountAddress: resp.smart_account_address,
      credentialIdHex: resp.credential_id_hex,
      keystore: resp.keystore,
      anchor: resp.anchor,
    };
  }

  /** List every bond posted by a controller — the explorer / app
   *  surface uses this to render the controller's full agent fleet. */
  async listBondsFor(controllerDid: string): Promise<ControllerBonds> {
    return this.bond.listAgentBondsByController(controllerDid);
  }

  /**
   * Composite risk snapshot for a given agent DID. Pulls bond state
   * via `tenzro_listAgentBondsByController`: active bond total, last
   * slashing and last insurance claim.
   *
   * The shape is stable across composition — clients can render an
   * explorer card without knowing which RPCs were called.
   */
  async getRisk(args: {
    agentDid: string;
    controllerDid: string;
  }): Promise<AgentRiskSnapshot> {
    const bonds = await this.bond.listAgentBondsByController(args.controllerDid);
    const own = (bonds.bonds ?? []).filter((b) => b.agent_did === args.agentDid) as unknown as Record<
      string,
      unknown
    >[];
    const active = own.filter(
      (b: Record<string, unknown>) =>
        (b as { state?: string }).state === "Active" ||
        (b as { state?: string }).state === "Cooldown",
    );
    const aggregate = active.reduce<bigint>((acc, b) => {
      const amt = (b as { amount?: string }).amount;
      try {
        return acc + BigInt(amt ?? "0");
      } catch {
        return acc;
      }
    }, 0n);
    const lastSlashSecs = pickMostRecentEvent(own, "slashed_at");
    const lastInsuranceClaimSecs = pickMostRecentEvent(own, "insurance_claimed_at");

    return {
      did: args.agentDid,
      aggregateBondTnzo: aggregate.toString(),
      activeBondCount: active.length,
      lastSlashSecs,
      lastInsuranceClaimSecs,
    };
  }
}

function pickMostRecentEvent(
  bonds: ReadonlyArray<Record<string, unknown>>,
  key: string,
): number | null {
  let max: number | null = null;
  for (const b of bonds) {
    const v = (b as Record<string, unknown>)[key];
    if (typeof v === "number" && (max === null || v > max)) max = v;
  }
  return max;
}

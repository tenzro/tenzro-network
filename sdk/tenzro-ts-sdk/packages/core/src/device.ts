import { RpcClient } from "./rpc";
import type { CustodyChallengeResponse } from "./passkey-rpc";

/** A WebAuthn assertion from a bound device over a custody challenge's `webauthn_challenge`, base64 fields. */
export interface DeviceAssertion {
  credential_id: string;
  authenticator_data_b64: string;
  client_data_json_b64: string;
  signature_b64: string;
}

/** A `tenzro_bindDevice` request: a WebAuthn registration over a `bind_device` challenge. */
export interface BindDeviceRequest {
  identity_did: string;
  /** The device's label; the challenge's target. */
  label: string;
  /** The attestation object from `navigator.credentials.create()`, base64. */
  attestation_object_b64: string;
  /** The registration's `clientDataJSON`, base64. */
  client_data_json_b64: string;
  challenge_id: string;
  /** An assertion from a device already bound; required for every device after the first. */
  authorization?: DeviceAssertion;
}

/** One bound device, as the node graded its attestation. */
export interface BoundDevice {
  credential_id: string;
  label?: string;
  aaguid?: string;
  hardware_bound?: boolean;
  attestation_format: string;
  key_protection: string;
  chain_verified: boolean;
  backup_eligible: boolean;
  backed_up?: boolean;
  sign_count?: number;
  sign_count_meaningful?: boolean;
  bound_at_ms?: number;
}

/** `tenzro_listBoundDevices`. */
export interface BoundDevices {
  identity_did: string;
  count: number;
  independent_roots: number;
  hardware_bound_count: number;
  wallet_ready: boolean;
  wallet_blocker: string | null;
  devices: BoundDevice[];
}

/** `tenzro_revokeBoundDevice`. */
export interface DeviceRevocation {
  identity_did: string;
  credential_id: string;
  removed: boolean;
  sessions_ended: number;
  devices_remaining: number;
  independent_roots: number;
  wallet_ready: boolean;
}

/** `tenzro_walletReadiness`. */
export interface WalletReadiness {
  identity_did: string;
  ready: boolean;
  blocker: string | null;
  /** `bind_second_device` or `bind_independent_device`. */
  remedy: string | null;
  bound_devices: number;
  independent_roots: number;
  hardware_bound_devices: number;
}

/** Who authorises a machine transfer. */
export type TransferAuthority =
  | { kind: "controller"; controllerDid: string; authorization: DeviceAssertion }
  | { kind: "machine_key"; machineSignatureHex: string };

function utf8Hex(s: string): string {
  return Array.from(new TextEncoder().encode(s), (b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * Devices bound to a Tenzro identity, and machine ownership.
 *
 * A Tenzro identity links devices the way a platform account does, except the
 * link is not a platform account. No Apple, Google or Microsoft sign-in is an
 * identity authority here: what the node trusts is a WebAuthn attestation it
 * verifies to a vendor root it pins, so "hardware-bound" is a fact the device
 * proved rather than a claim its cloud account made.
 *
 * A wallet cannot sit behind one device. `walletReadiness` reports whether a
 * second bound device exists yet, and names the remedy when it does not.
 */
export class DeviceClient {
  private rpc: RpcClient;

  constructor(rpc: RpcClient) {
    this.rpc = rpc;
  }

  /**
   * The single-use custody challenge a device change answers: `bind_device`
   * for `(identityDid, label)`, `revoke_device` for `(identityDid,
   * credentialId)`, `transfer_machine_ownership` for `(machineDid,
   * newOwnerDid)`. A registration signs `challenge_hex` as its WebAuthn
   * challenge; an assertion from a bound device signs `webauthn_challenge`.
   */
  async challenge(
    operation: "bind_device" | "revoke_device" | "transfer_machine_ownership",
    accountDid: string,
    target: string,
  ): Promise<CustodyChallengeResponse> {
    return this.rpc.call<CustodyChallengeResponse>("tenzro_createCustodyChallenge", {
      account_address: utf8Hex(accountDid),
      operation,
      target_hex: utf8Hex(target),
    });
  }

  /**
   * Bind a device to an identity from a WebAuthn registration made over a
   * `bind_device` challenge for `(identity_did, label)`. The node grades the
   * attestation against the vendor roots it pins: a device whose key is not in
   * hardware, or whose credential can sync to a cloud account, is refused with
   * the reason. The first device must be the identity's own passkey; another
   * needs `authorization`, an assertion from a device already bound.
   */
  async bindDevice(request: BindDeviceRequest): Promise<BoundDevice> {
    return this.rpc.call<BoundDevice>("tenzro_bindDevice", { ...request });
  }

  /** The devices that can authenticate as an identity, and what each proved. */
  async listBoundDevices(identityDid: string): Promise<BoundDevices> {
    return this.rpc.call<BoundDevices>("tenzro_listBoundDevices", {
      identity_did: identityDid,
    });
  }

  /**
   * Unbind a device and end every session it authorised, in one action.
   * `authorization` is an assertion from a bound device over a
   * `revoke_device` challenge for `(identityDid, credentialId)`.
   */
  async revokeBoundDevice(
    identityDid: string,
    credentialId: string,
    challengeId: string,
    authorization: DeviceAssertion,
  ): Promise<DeviceRevocation> {
    return this.rpc.call<DeviceRevocation>("tenzro_revokeBoundDevice", {
      identity_did: identityDid,
      credential_id: credentialId,
      challenge_id: challengeId,
      authorization,
    });
  }

  /**
   * Whether a wallet may be created for this identity, and if not, why.
   *
   * Read before offering wallet creation so the user is told what to do,
   * "scan the pairing QR with your phone", rather than shown a button that
   * fails. A wallet cannot sit behind a single device.
   */
  async walletReadiness(
    identityDid: string,
    thisDeviceCredentialId?: string,
  ): Promise<WalletReadiness> {
    return this.rpc.call<WalletReadiness>("tenzro_walletReadiness", {
      identity_did: identityDid,
      this_device_credential_id: thisDeviceCredentialId ?? null,
    });
  }

  /**
   * Move a machine to another identity, answering a
   * `transfer_machine_ownership` challenge for `(machineDid, newOwnerDid)`.
   * A `controller` authority carries an assertion from a device bound to the
   * controller of a machine a party delegated; a `machine_key` authority the
   * machine's own signature over the challenge, for a machine nobody
   * delegated. The two are not interchangeable.
   */
  async transferMachineOwnership(
    machineDid: string,
    newOwnerDid: string,
    challengeId: string,
    authority: TransferAuthority,
  ): Promise<Record<string, unknown>> {
    const params: Record<string, unknown> = {
      machine_did: machineDid,
      new_owner_did: newOwnerDid,
      challenge_id: challengeId,
    };
    if (authority.kind === "controller") {
      params.authority = "controller";
      params.controller_did = authority.controllerDid;
      params.authorization = authority.authorization;
    } else {
      params.authority = "machine_key";
      params.machine_signature_hex = authority.machineSignatureHex;
    }
    return this.rpc.call("tenzro_transferMachineOwnership", params);
  }

  /**
   * The rails a payment can settle on, and the smallest worthwhile payment on
   * each. Supporting x402 and being able to carry a micropayment are different
   * properties — Base speaks x402 and still cannot carry a one-cent charge
   * without ~10% overhead.
   */
  async settlementNetworks(): Promise<any> {
    return this.rpc.call("tenzro_settlementNetworks", {});
  }

  /**
   * Where a specific charge would settle: accumulate below the
   * micro-settlement floor, the Tenzro Ledger, a secondary rail, or no viable
   * rail for the payee's asset. Omit `tnzoMicroUsd` and the node settles on the
   * home chain rather than routing on a guessed rate.
   */
  async routePayment(
    amountWei: string,
    asset?: string,
    tnzoMicroUsd?: number,
  ): Promise<any> {
    return this.rpc.call("tenzro_settlementNetworks", {
      amount_wei: amountWei,
      asset: asset ?? null,
      tnzo_micro_usd: tnzoMicroUsd ?? null,
    });
  }
}

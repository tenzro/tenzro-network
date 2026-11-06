import type { RpcClient } from "@tenzro/core";
import type { RoleStakes, StakeCapacity, StakingRole, WalletProviderStatus } from "@tenzro/core";

/**
 * Role stakes. An account bonds stake per role with a `Stake` transaction it
 * signs itself; a node serves a bonded role only while its operator account
 * holds that role's bond. The validator role is bonded by RegisterValidator.
 */
/** One staked operator of a role and the URL it published on chain. */
export interface RoleEndpoint {
  account: string;
  url: string;
  bonded: string;
}

/** Result of `tenzro_listRoleEndpoints`. */
export interface RoleEndpoints {
  role: string;
  endpoints: RoleEndpoint[];
}

/** One relay check, as a node ran it. */
export interface RelayCheck {
  url: string;
  operator: string | null;
  healthy: boolean;
  latency_ms: number | null;
  checked_ms: number;
  error: string | null;
}

/** A staked edge operator's relay and the answering node's latest check. */
export interface StakedRelay {
  account: string;
  url: string;
  bonded: string;
  used: boolean;
  check: RelayCheck | null;
  /** The SLA verdict validators froze for the last closed epoch, if any. */
  sla: { epoch: number; available: boolean; attesters: number } | null;
}

/** Result of `tenzro_listRelays`. */
export interface StakedRelays {
  relays: StakedRelay[];
}

/** Result of `tenzro_getConnectivity`: how a node is reached, without its addresses. */
export interface Connectivity {
  reachability: 'public' | 'port_mapped' | 'hole_punch' | 'peer_relay' | 'relay' | 'unreachable';
  nat: 'unknown' | 'none' | 'endpoint_independent' | 'endpoint_dependent';
  observers: number;
  port_mapped: boolean;
  external_addresses: number;
  ipv4: boolean;
  ipv6: boolean;
  relays: { url: string; connected: boolean }[];
  /** Peers reached on a birthday-punched direct path. */
  punched_paths: number;
  /** Peer relays (forwarders) the node offers paths through. */
  peer_relays: { endpoint: string; rtt_ms: number; direct: boolean }[];
}

export class StakingClient {
  constructor(private readonly rpc: RpcClient) {}

  /** An account's stake per role and every role's network total; omit `address` for the node's operator payee. */
  async roleStakes(address?: string): Promise<RoleStakes> {
    return this.rpc.call<RoleStakes>('tenzro_getRoleStakes', address ? { address } : {});
  }

  /**
   * Whether a staked wallet provider serves the passkey relying-party domain
   * `rpId`. A wallet linking a credential from that domain shows it as coming
   * from a staked provider only when `staked` is true; credentials from other
   * domains still work.
   */
  async walletProvider(rpId: string): Promise<WalletProviderStatus> {
    return this.rpc.call<WalletProviderStatus>('tenzro_getWalletProvider', { rp_id: rpId });
  }

  /**
   * A role's staked operators and the public URLs they published on chain,
   * most bonded first (default role `rpc`). See `connectToNetwork` for a
   * client that uses them.
   */
  async roleEndpoints(role: string = 'rpc'): Promise<RoleEndpoints> {
    return this.rpc.call<RoleEndpoints>('tenzro_listRoleEndpoints', { role });
  }

  /**
   * The relays staked edge operators serve, most bonded first, with the
   * SLA verdict validators froze for the last closed epoch and the
   * answering node's latest check of each.
   */
  async relays(): Promise<StakedRelays> {
    return this.rpc.call<StakedRelays>('tenzro_listRelays', {});
  }

  /** How the answering node is reached: directly, after hole punching, or through relays. */
  async connectivity(): Promise<Connectivity> {
    return this.rpc.call<Connectivity>('tenzro_getConnectivity', {});
  }
}

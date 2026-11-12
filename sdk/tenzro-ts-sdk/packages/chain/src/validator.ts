import { RpcClient } from "@tenzro/core";

/**
 * Validator registry status. Mirrors the Rust
 * `tenzro_token::validator_registry::ValidatorStatus` enum, projected
 * to its `Debug`-formatted string on the wire.
 */
export type ValidatorStatus =
  | "Active"
  | "Candidate"
  | "PendingActive"
  | "PendingExit"
  | "Exited"
  | "Jailed";

/**
 * A single entry in the on-chain validator registry. `address` and
 * `withdrawal_address` are base58-encoded (Solana-style, matching
 * Tenzro's `Address::Display` impl). Pubkeys are plain lowercase hex
 * without `0x` prefix. `self_stake` is a u128 encoded as a decimal
 * string. `tee_attestation_hash` is `null` when the validator has
 * no recorded TEE attestation; `metadata_uri` defaults to `""`.
 */
export interface ValidatorRegistryEntry {
  /** Base58-encoded 32-byte address. */
  address: string;
  /** Hardware validator key, ML-DSA-65 leg (1952 bytes), hex-encoded. */
  ml_dsa_pubkey: string;
  /** Hardware validator key, P-256 leg, hex-encoded. */
  p256_pubkey: string;
  /** The node's Ed25519 network key (32 bytes), hex-encoded. */
  node_key: string;
  /** Base58-encoded 32-byte withdrawal address. */
  withdrawal_address: string;
  /** u128 decimal string. */
  self_stake: string;
  status: ValidatorStatus;
  registered_at_epoch: number;
  activated_at_epoch: number | null;
  exited_at_epoch: number | null;
  jailed_until_epoch: number | null;
  tee_attestation_hash: string | null;
  metadata_uri: string;
  /** Unix ms timestamp of last registry mutation. */
  updated_at: number;
}

export interface ListValidatorsResult {
  count: number;
  validators: ValidatorRegistryEntry[];
}

/** The node's answer to `tenzro_getUpdateNotice`. */
export interface UpdateNoticeReply {
  /** True when `if_none_match` named the notice the node holds; no notice is sent then. */
  unchanged?: boolean;
  /** The signed notice envelope. The caller checks its signature. */
  notice?: unknown | null;
  /** Value to send back as `if_none_match` on the next ask. */
  etag: string | null;
  latest_version?: string | null;
  severity?: string | null;
  /** Seconds the answer may be kept. */
  cache_ttl_secs: number;
  /** The node's epoch position, when it runs consensus. */
  epoch: { epoch: number; blocks_to_boundary: number | null } | null;
}

/** The node's finality (`tenzro_getFinality`). */
export interface Finality {
  /** Highest height ordered by consensus. */
  ordered: number;
  /** Highest height a certified checkpoint covers. */
  certified: number;
  /** The checkpoint the latest certificate covers, when one is kept. */
  certificate: {
    epoch: number;
    index: number;
    first_height: number;
    last_height: number;
    state_height: number;
    state_root: string;
    signers: number;
  } | null;
}

/** A checkpoint certificate and the sessions that verify it, bincode as hex. */
export interface CheckpointCertificate {
  epoch: number;
  index: number;
  last_height: number;
  /** The checkpoint digest (full certificates only). */
  digest?: string;
  certificate: string;
  sessions: string;
}

/** An epoch's committee (`tenzro_getCommittee`); `members` is bincode as hex. */
export interface Committee {
  epoch: number;
  root: string;
  members: string;
}

/** The certificate that hands an epoch to the next committee, bincode as hex. */
export interface EpochHandover {
  epoch: number;
  index: number;
  certificate: string;
  sessions: string;
  next_members: string;
}

/** The node's head and its age (`tenzro_currentHeader`). */
export interface CurrentHeader {
  height: number;
  /** Empty when the store holds no block at the head. */
  hash: string;
  timestamp_secs: number;
  now_secs: number;
  age_secs: number;
  /** `live`, `stale_yellow`, `stale_red`, `invalid` or `unknown`. */
  tier: string;
}

/** The committed state root (`tenzro_getStateRoot`). */
export interface StateRoot {
  height: number;
  state_root: string;
  /** The checkpoint that certifies this height, when one does. */
  certified_by_checkpoint: number | null;
}

/** A value in committed state and its proof (`tenzro_getStateProof`). */
export interface StateProof extends StateRoot {
  namespace: string;
  /** The key, hex. */
  key: string;
  /** The value, hex, or null when the proof shows absence. */
  value: string | null;
  proof: unknown;
}

/**
 * Client for the on-chain validator registry — used by operator
 * dashboards, SREs, validator-fleet tooling, and any client that needs
 * to enumerate the active set, inspect a single validator's stake,
 * activation epoch, or TEE-attestation status.
 *
 * Backed by the `tenzro_getValidatorState` / `tenzro_listValidators` /
 * `tenzro_listActiveValidators` RPCs. Validator registration happens
 * through the staking transaction path.
 */
export class ValidatorClient {
  constructor(private rpc: RpcClient) {}

  /**
   * Fetch a single validator's registry entry by 32-byte address
   * (hex form, with or without `0x` prefix — the node decodes hex,
   * not base58, on the request path even though responses are
   * base58-encoded). Returns `null` if the address is not registered.
   */
  async getState(address: string): Promise<ValidatorRegistryEntry | null> {
    return this.rpc.call("tenzro_getValidatorState", [{ address }]);
  }

  /**
   * List validators in the registry, optionally filtered by status.
   * Omit `status` to return every entry regardless of state.
   */
  async list(status?: ValidatorStatus): Promise<ListValidatorsResult> {
    const params = status ? [{ status }] : [{}];
    return this.rpc.call("tenzro_listValidators", params);
  }

  /**
   * Convenience over `list("Active")` — returns only the validators
   * currently producing blocks. The node returns the same shape, so
   * the result type is identical to `list()`.
   */
  async listActive(): Promise<ListValidatorsResult> {
    return this.rpc.call("tenzro_listActiveValidators", []);
  }

  /** `tenzro_currentHeader`: the node's head and how old it is. */
  currentHeader<T = CurrentHeader>(): Promise<T> {
    return this.rpc.call<T>("tenzro_currentHeader");
  }

  /** `tenzro_getCheckpointCertificate`: the certificate at `index`, or the latest. */
  getCheckpointCertificate<T = CheckpointCertificate>(params: { index?: number } = {}): Promise<T> {
    return this.rpc.call<T>("tenzro_getCheckpointCertificate", params);
  }

  /** `tenzro_getCommittee`: the committee of `epoch`. */
  getCommittee<T = Committee>(params: { epoch: number }): Promise<T> {
    return this.rpc.call<T>("tenzro_getCommittee", params);
  }

  /** `tenzro_getCompactCertificate`: the compact certificate at `index`, or the latest. */
  getCompactCertificate<T = CheckpointCertificate>(params: { index?: number } = {}): Promise<T> {
    return this.rpc.call<T>("tenzro_getCompactCertificate", params);
  }

  /** `tenzro_getConsensusMetrics`. */
  getConsensusMetrics<T = unknown>(): Promise<T> {
    return this.rpc.call<T>("tenzro_getConsensusMetrics");
  }

  /** `tenzro_getEpochHandover`: the certificate that hands `epoch` to the next committee. */
  getEpochHandover<T = EpochHandover>(params: { epoch: number }): Promise<T> {
    return this.rpc.call<T>("tenzro_getEpochHandover", params);
  }

  /** `tenzro_getFinality`: ordered and certified heights and the latest certificate. */
  getFinality<T = Finality>(): Promise<T> {
    return this.rpc.call<T>("tenzro_getFinality");
  }

  /** `tenzro_getUpdateNotice`: the newest signed release notice the node holds and its epoch position. */
  getUpdateNotice<T = UpdateNoticeReply>(params?: { if_none_match?: string }): Promise<T> {
    return this.rpc.call<T>("tenzro_getUpdateNotice", params);
  }

  /** `tenzro_getRewardEpoch`: a closed reward epoch's summary. */
  getRewardEpoch<T = unknown>(params: { epoch: number }): Promise<T> {
    return this.rpc.call<T>("tenzro_getRewardEpoch", params);
  }

  /** `tenzro_getRewardSchedule`. */
  getRewardSchedule<T = unknown>(): Promise<T> {
    return this.rpc.call<T>("tenzro_getRewardSchedule");
  }

  /** `tenzro_getStateProof`: a value in committed state and its proof; `key` is hex. */
  getStateProof<T = StateProof>(params: { namespace: string; key: string }): Promise<T> {
    return this.rpc.call<T>("tenzro_getStateProof", params);
  }

  /** `tenzro_getStateRoot`: the committed state root. */
  getStateRoot<T = StateRoot>(): Promise<T> {
    return this.rpc.call<T>("tenzro_getStateRoot");
  }

  /**
   * `tenzro_getHardwareLevel`: an address's hardware security level and
   * hardware type, derived on chain from verified attestation.
   */
  getHardwareLevel<T = unknown>(params: { address?: unknown } = {}): Promise<T> {
    return this.rpc.call<T>("tenzro_getHardwareLevel", params);
  }

  /** `tenzro_getVesting`. */
  getVesting<T = unknown>(params: { address?: unknown } = {}): Promise<T> {
    return this.rpc.call<T>("tenzro_getVesting", params);
  }

  /** `tenzro_listRewardCoupons`. */
  listRewardCoupons<T = unknown>(params: { address?: unknown } = {}): Promise<T> {
    return this.rpc.call<T>("tenzro_listRewardCoupons", params);
  }

  /**
   * `tenzro_signalUpgradeReady` (operator only): signal from this validator
   * that the binary staged on the node hashes to `code_hash` and is ready to
   * run.
   */
  signalUpgradeReady<T = unknown>(params: { code_hash: string }): Promise<T> {
    return this.rpc.call<T>("tenzro_signalUpgradeReady", params);
  }


  /** `tenzro_validatorPublicKeys` (operator only). */
  validatorPublicKeys<T = unknown>(): Promise<T> {
    return this.rpc.call<T>("tenzro_validatorPublicKeys");
  }

  /** `tenzro_validatorSelfStake` (operator only). */
  validatorSelfStake<T = unknown>(params: { additional?: unknown } = {}): Promise<T> {
    return this.rpc.call<T>("tenzro_validatorSelfStake", params);
  }

  /** `tenzro_verifyVrfProof`. */
  verifyVrfProof<T = unknown>(params: { alpha?: unknown; proof?: unknown; pubkey?: unknown } = {}): Promise<T> {
    return this.rpc.call<T>("tenzro_verifyVrfProof", params);
  }
}

import { createHash } from "node:crypto";
import { RpcClient } from "@tenzro/core";
import { DecodedAction, Levers, NetworkParam, TransactionEffects, NetworkParams, ProposalPage, ProposalView, UpgradeReadiness, VotingPower } from "@tenzro/core";
import type { TypedTransaction } from "@tenzro/core";

const PROPOSE_GAS = 100_000;
const VOTE_GAS = 30_000;
const EXECUTE_GAS = 120_000;

const id = (proposalId: string) => proposalId.replace(/^0x/, "");

/**
 * On-chain governance. Proposals, votes, enactment and vetoes are signed
 * transactions decided in consensus, and voting weight is bonded stake. A
 * proposal carries one action tagged by `action`: `policy_update` (economic
 * policy, burn dial, supply targets, protocol upgrade), `parameter_change`, `treasury_grant`, `revoke_identity`, and the
 * rest the node documents.
 */
export class GovernanceClient {
  constructor(private rpc: RpcClient) {}

  /** Proposals newest first, optionally only one action `kind`. */
  async listProposals(opts: { limit?: number; before?: number; kind?: string } = {}): Promise<ProposalPage> {
    return this.rpc.call<ProposalPage>("tenzro_listProposals", [opts]);
  }

  /** One proposal and its tally, or null. */
  async getProposal(proposalId: string): Promise<ProposalView | null> {
    return this.rpc.call<ProposalView | null>("tenzro_getProposal", [{ proposal_id: id(proposalId) }]);
  }

  /** The treasury's keyless accounts on other chains and their last grants. */
  async getTreasuryAccounts(): Promise<TreasuryAccounts> {
    return this.rpc.call<TreasuryAccounts>("tenzro_getTreasuryAccounts", [{}]);
  }

  /**
   * Every guardian and Foundation steward seat, the enactment pause, the
   * steward treasury hold, the guardian threshold, the steward sunset and seat
   * cap and, with an address, the seat it holds and whether it is live.
   */
  async getGuardianState(address?: string): Promise<Record<string, unknown>> {
    return this.rpc.call<Record<string, unknown>>("tenzro_getGuardianState", [address ? { address } : {}]);
  }

  /** The bonded stake `address` votes with. */
  async getVotingPower(address: string): Promise<VotingPower> {
    return this.rpc.call<VotingPower>("tenzro_getVotingPower", [{ address }]);
  }

  /**
   * The governance-sponsored part of a validator's stake: bonded, unbonding,
   * the part the validator put up itself, and the governed caps (whole TNZO,
   * 0 disables sponsorship). Amounts are decimal strings.
   */
  async getSponsoredBond(address: string): Promise<Record<string, unknown>> {
    return this.rpc.call<Record<string, unknown>>("tenzro_getSponsoredBond", [{ address }]);
  }

  /**
   * Every sponsorship and grant disbursement, oldest first, each with its
   * recipient, amount, class and proposal; the total per class; the governed
   * caps; and with an address its approvals and the total it has been paid.
   */
  async getTreasuryPayouts(
    address?: string,
    offset = 0,
    limit = 100,
  ): Promise<Record<string, unknown>> {
    return this.rpc.call<Record<string, unknown>>("tenzro_getTreasuryPayouts", [
      { address, offset, limit },
    ]);
  }

  /**
   * The last enacted change of a network policy `kind` (economic_policy,
   * adaptive_burn_config, supply_targets, protocol_upgrade), or null while
   * the genesis setting stands.
   */
  async getPolicy(kind: string): Promise<unknown> {
    return this.rpc.call("tenzro_getPolicy", [{ kind }]);
  }

  /**
   * A proposal's governance receipt: its records with state proofs under a
   * certified checkpoint and that checkpoint's proof from genesis, for
   * offline verification ({@link verifyGovernanceReceipt} under a certified
   * state root, or `tenzro governance receipt --verify` from genesis).
   */
  async getGovernanceReceipt(proposalId: string): Promise<Record<string, unknown>> {
    return this.rpc.call<Record<string, unknown>>("tenzro_getGovernanceReceipt", [{ proposal_id: proposalId }]);
  }

  /**
   * The typed preimage a privileged transaction (an unsigned transaction
   * object) is signed over, its digest and what it does in words. The digest
   * is recomputed here from the returned preimage bytes and the preimage's
   * action is checked against the transaction given, so what a wallet shows
   * is what is signed.
   */
  async decodeAction(transaction: { tx_type: unknown }): Promise<DecodedAction> {
    const decoded = await this.rpc.call<DecodedAction>("tenzro_decodeAction", [{ transaction }]);
    const hex = decoded.preimage_hex;
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < bytes.length; i++) bytes[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
    const digestHex = Array.from(digest, (b) => b.toString(16).padStart(2, "0")).join("");
    if (digestHex !== decoded.digest) {
      throw new Error("decodeAction returned a digest that is not the preimage's");
    }
    const parsed = JSON.parse(new TextDecoder().decode(bytes)) as { action: unknown };
    if (JSON.stringify(parsed.action) !== JSON.stringify(transaction.tx_type)) {
      throw new Error("decodeAction described another action than the one given");
    }
    return decoded;
  }

  /**
   * What `transaction` (unsigned) would do, executed by the node on a copy
   * of its state: outcome, balance changes and logs, with a digest. Given
   * `second`, a node run by another operator, the transaction is executed
   * there too at the same block, and the effects are returned only when both
   * digests agree, so an approval shows what two nodes derived rather than
   * what a front end drew.
   */
  async transactionEffects(transaction: { tx_type: unknown }, second?: RpcClient): Promise<TransactionEffects> {
    const first = await this.rpc.call<{ effects: TransactionEffects }>("tenzro_decodeAction", [{ transaction }]);
    if (!second) return first.effects;
    const other = await second.call<{ effects: TransactionEffects }>("tenzro_decodeAction", [
      { transaction, block: { blockHash: first.effects.block_hash } },
    ]);
    if (other.effects.digest !== first.effects.digest || other.effects.block_hash !== first.effects.block_hash) {
      throw new Error("two nodes derived different effects for this transaction; it must not be approved");
    }
    return first.effects;
  }

  /**
   * Which validators' machines have quoted the binary `codeHash` (hex
   * SHA-256), their share of bonded stake against the share a protocol
   * upgrade needs, and the activation consensus scheduled last.
   */
  async getUpgradeReadiness(codeHash: string): Promise<UpgradeReadiness> {
    return this.rpc.call<UpgradeReadiness>("tenzro_getUpgradeReadiness", [{ code_hash: codeHash }]);
  }

  /**
   * Every governed network parameter from chain state (fees, slashing
   * rates, bonds, windows, caps): value, bounds, genesis value, the
   * direction that tightens it, and any enacted change still waiting for
   * its epoch.
   */
  async getNetworkParams(): Promise<NetworkParams> {
    return this.rpc.call<NetworkParams>("tenzro_getNetworkParams", {});
  }

  /** One governed network parameter. */
  async getNetworkParam(key: string): Promise<NetworkParam> {
    return this.rpc.call<NetworkParam>("tenzro_getNetworkParams", { key });
  }

  /**
   * Every governance lever, optionally only those of one `area` (fees,
   * bridge, roles, keystore, zk, consensus...): its kind, value, status,
   * bounds and any enacted change waiting with the epoch it activates in,
   * plus each bridge route's mode after its transport's lever.
   */
  async listLevers(area?: string): Promise<Levers> {
    return this.rpc.call<Levers>("tenzro_listLevers", area ? { area } : {});
  }
}

/**
 * A proposal to change one governed network parameter, ready to sign and
 * send. The node refuses it at submission when `value` is outside the
 * parameter's bounds; once enacted the value applies from the next epoch,
 * or after the tightening grace window when it asks more of those the rule
 * binds.
 */
export function parameterChangeProposal(key: string, value: number | bigint | string, memo: string): TypedTransaction {
  const v = BigInt(value);
  if (v < 0n || v > 18446744073709551615n) throw new Error("a parameter value is an unsigned 64-bit integer");
  const action = `{"action":"parameter_change","key":${JSON.stringify(key)},"value":${v.toString()},"memo":${JSON.stringify(memo)}}`;
  return {
    kind: "GovernancePropose",
    fields: { proposal: Array.from(Buffer.from(action, "utf8")) },
    gasLimit: PROPOSE_GAS,
  };
}

/**
 * A proposal to return a jailed validator to candidacy at the next epoch
 * boundary, ahead of the end of its jail term. It is admitted again like any
 * candidate; slashing is not undone. For a validator that is not jailed it
 * does nothing. `validator` is the 32 byte account, hex.
 */
export function reinstateValidatorProposal(validator: string, memo: string): TypedTransaction {
  const hex = validator.replace(/^0x/, "");
  if (!/^[0-9a-fA-F]{64}$/.test(hex)) throw new Error("validator must be 32 bytes of hex");
  const action = `{"action":"reinstate_validator","validator":${JSON.stringify(Array.from(Buffer.from(hex, "hex")))},"memo":${JSON.stringify(memo)}}`;
  return {
    kind: "GovernancePropose",
    fields: { proposal: Array.from(Buffer.from(action, "utf8")) },
    gasLimit: PROPOSE_GAS,
  };
}

/** What a verified governance receipt establishes, read from its proven records only. */
export interface GovernanceReceiptReport {
  /** The proposal record, as consensus stores it. */
  proposal: Record<string, any>;
  /** The tally record, if a vote was cast. */
  tally: Record<string, any> | null;
  /** TNZO locked in the veto escrow, base units. */
  vetoLocked: bigint;
  /** Height the proposal was enacted at, if it was. */
  executedHeight: bigint | null;
  /** The scheduled activation, for an enacted protocol upgrade. */
  activation: Record<string, any> | null;
}

const STEM_LEN = 31;
const EMPTY = new Uint8Array(32);
const SYSTEM_ADDRESS_HEX = "ff".repeat(20);

function bad(msg: string): Error {
  return new Error(`governance receipt: ${msg}`);
}

function sha(...parts: Uint8Array[]): Uint8Array {
  const h = createHash("sha256");
  for (const p of parts) h.update(p);
  return new Uint8Array(h.digest());
}

function eq(a: Uint8Array, b: Uint8Array): boolean {
  return a.length === b.length && a.every((x, i) => x === b[i]);
}

function fromHex(h: unknown, what: string): Uint8Array {
  if (typeof h !== "string" || h.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(h)) throw bad(`${what} is not hex`);
  return new Uint8Array(Buffer.from(h, "hex"));
}

/** Bytes as the node serves them: hex, or an array of byte values. */
function fixed(v: unknown, n: number, what: string): Uint8Array {
  let out: Uint8Array | null = null;
  if (typeof v === "string") out = fromHex(v, what);
  else if (Array.isArray(v) && v.every((b) => Number.isInteger(b) && b >= 0 && b < 256)) out = Uint8Array.from(v);
  if (!out || out.length !== n) throw bad(`${what} is not ${n} bytes`);
  return out;
}

/** The tree key of system storage slot `slot` in namespace `state`. */
function systemSlotTreeKey(slot: string): Uint8Array {
  const key = `storage:${SYSTEM_ADDRESS_HEX}:${Buffer.from(slot, "utf8").toString("hex")}`;
  const ns = new Uint8Array([5, 0]);
  return sha(new TextEncoder().encode("tenzro.state-trie.key"), ns, new TextEncoder().encode("state"), new TextEncoder().encode(key));
}

function bit(stem: Uint8Array, depth: number): number {
  return (stem[depth >> 3] >> (7 - (depth & 7))) & 1;
}

function slotPair(l: Uint8Array, r: Uint8Array): Uint8Array {
  if (eq(l, EMPTY) && eq(r, EMPTY)) return EMPTY;
  return sha(Uint8Array.of(3), l, r);
}

/** Whether, under `root`, the entry with tree key `tk` holds `value` (or is absent, for null), by `proof`. */
function verifyStateProof(root: Uint8Array, tk: Uint8Array, value: Uint8Array | null, proof: any): boolean {
  if (!proof || !Array.isArray(proof.siblings)) throw bad("a proof has no siblings");
  const siblings = proof.siblings.map((s: unknown) => fixed(s, 32, "a sibling"));
  if (siblings.length > STEM_LEN * 8) return false;
  const depth = siblings.length;
  const stem = tk.subarray(0, STEM_LEN);
  const terminal = proof.terminal;
  let acc: Uint8Array;
  if (terminal === "Empty") {
    if (value) return false;
    acc = EMPTY;
  } else if (terminal && terminal.OtherStem) {
    const other = fixed(terminal.OtherStem.stem, STEM_LEN, "a stem");
    const slotsRoot = fixed(terminal.OtherStem.slots_root, 32, "a slots root");
    if (value || eq(other, stem)) return false;
    for (let d = 0; d < depth; d++) if (bit(other, d) !== bit(stem, d)) return false;
    acc = sha(Uint8Array.of(2), other, slotsRoot);
  } else if (terminal && terminal.Stem) {
    const sibs = terminal.Stem.slot_siblings;
    if (!Array.isArray(sibs) || sibs.length !== 8) throw bad("a stem proof needs 8 slot siblings");
    let s = value ? sha(Uint8Array.of(0), value) : EMPTY;
    let index = tk[STEM_LEN];
    for (const raw of sibs) {
      const sib = fixed(raw, 32, "a slot sibling");
      s = (index & 1) === 0 ? slotPair(s, sib) : slotPair(sib, s);
      index >>= 1;
    }
    if (eq(s, EMPTY)) return false;
    acc = sha(Uint8Array.of(2), stem, s);
  } else {
    throw bad("a proof has an unknown terminal");
  }
  for (let d = depth - 1; d >= 0; d--) {
    acc = bit(stem, d) === 0 ? sha(Uint8Array.of(1), acc, siblings[d]) : sha(Uint8Array.of(1), siblings[d], acc);
  }
  return eq(acc, root);
}

/**
 * Checks a governance receipt (as `getGovernanceReceipt` returns it) offline,
 * against the state root of a checkpoint the caller holds as certified (from
 * a light client, the finality verifier, or `tenzro governance receipt
 * --verify`, which proves the receipt's checkpoint from the genesis anchor).
 * Every record must be proven under that root and be about the receipt's
 * proposal; the proposal, tally, veto and decision records must all be
 * proven (present or absent); and a decision must be of exactly the proven
 * proposal record. Nothing the node says is trusted. Throws on any failure.
 */
export function verifyGovernanceReceipt(receipt: any, certifiedStateRoot: ArrayLike<number>): GovernanceReceiptReport {
  const root = fixed(receipt?.state_root, 32, "state_root");
  if (!eq(root, Uint8Array.from(certifiedStateRoot))) throw bad("the receipt names another state root than the certified one");
  const id = receipt.proposal_id;
  if (typeof id !== "string") throw bad("no proposal_id");
  if (!Array.isArray(receipt.records)) throw bad("no records");
  const values = new Map<string, Uint8Array | null>();
  for (const r of receipt.records) {
    const kind = r?.kind;
    if (typeof kind !== "string") throw bad("a record has no kind");
    if (r.subject !== id) throw bad(`a ${kind} record is about another proposal`);
    if (typeof r.slot !== "string") throw bad("a record has no slot");
    const value = r.value === null || r.value === undefined ? null : fromHex(r.value, `the ${kind} value`);
    if (!verifyStateProof(root, systemSlotTreeKey(r.slot), value, r.proof)) {
      throw bad(`the ${kind} record is not proven under the certified root`);
    }
    if (values.has(kind)) throw bad(`the receipt carries two ${kind} records`);
    values.set(kind, value);
  }
  const proposalBytes = values.get("proposal");
  if (!proposalBytes) throw bad("the receipt proves no proposal record");
  const json = (b: Uint8Array | null | undefined): any => {
    if (!b) return null;
    try {
      return JSON.parse(Buffer.from(b).toString("utf8"));
    } catch {
      return null;
    }
  };
  const proposal = json(proposalBytes);
  if (!proposal) throw bad("the proposal record is not JSON");
  if (proposal.id !== id) throw bad("the proposal record is of another proposal");
  for (const kind of ["tally", "veto_total", "decision"]) {
    if (!values.has(kind)) throw bad(`the receipt does not prove the ${kind} record`);
  }
  let executedHeight: bigint | null = null;
  const decision = values.get("decision");
  if (decision) {
    if (decision.length !== 40) throw bad("the decision record is malformed");
    if (!eq(decision.subarray(0, 32), sha(proposalBytes))) throw bad("the decision record is not of the proven proposal record");
    if (proposal.status !== "executed") throw bad("a decision is recorded for a proposal that is not executed");
    executedHeight = Buffer.from(decision.subarray(32)).readBigUInt64BE(0);
  }
  const veto = values.get("veto_total");
  const vetoLocked = veto && veto.length === 16 ? Buffer.from(veto).reverse().reduce((a, b) => (a << 8n) | BigInt(b), 0n) : 0n;
  return { proposal, tally: json(values.get("tally")), vetoLocked, executedHeight, activation: json(values.get("activation")) };
}

/** `tenzro_getTreasuryAccounts`: the network treasury and its keyless accounts on other chains. */
export interface TreasuryAccounts {
  did: string;
  /** The treasury's account on Tenzro, hex. */
  tenzro: string;
  accounts: Array<{
    caip2: string;
    address?: string;
    caip10?: string;
    /** The last remote grant an enacted proposal wrote for the account. */
    grant?: { seq: number; payload_hash: string; amount: string; not_after_ms: number; void: boolean } | null;
    /** Why the account could not be derived. */
    error?: string;
  }>;
  bitcoin?: string;
}

import { RpcClient, A2A_AGENT_CARD_PATH } from "@tenzro/core";
import {
  A2aSendMessageResponse,
  A2aTask,
  a2aTextMessage,
  AgentAuditProof,
  AgentAuditCommitResponse,
  AgentAuditVerification,
  AgentAuditAttestation,
  AgentQuarantineStatus,
} from "@tenzro/core";

import type { AgentKeyResolution } from "@tenzro/core";
import { signEnvelope, type EnvelopeSender } from "./a2a-extension";
import { verifyAgentCard } from "./agent-card";

/** Which of the sender's tasks `ListTasks` returns, and how much of each. */
export interface A2aTaskFilter {
  /** Only tasks of this context. */
  contextId?: string;
  /** Only tasks in this state, e.g. `TASK_STATE_COMPLETED`. */
  status?: string;
  /** Tasks per page (the node returns at most 100). */
  pageSize?: number;
  /** The `nextPageToken` of the page before. */
  pageToken?: string;
  /** Most recent messages to return with each task. */
  historyLength?: number;
  /** Whether each task carries its artifacts. */
  includeArtifacts?: boolean;
}

/** One page of `ListTasks`. */
export interface A2aTaskList {
  /** The tasks on this page, ordered by id. */
  tasks: A2aTask[];
  /** Token of the next page; empty on the last one. */
  nextPageToken: string;
  /** Tasks per page the node used. */
  pageSize: number;
  /** How many of the sender's tasks match the filter. */
  totalSize: number;
}

// Simple UUID v4 generator for browser/node compatibility
function generateUUID(): string {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
    const r = Math.random() * 16 | 0;
    const v = c === 'x' ? r : (r & 0x3 | 0x8);
    return v.toString(16);
  });
}

/**
 * Client for AI agent operations.
 * Supports agent registration, messaging, and task delegation.
 */
export class AgentClient {
  constructor(private rpc: RpcClient) {}

  /**
   * One A2A task call as `sender` to the node whose machine DID is
   * `agentDid`, carrying the DID envelope its key signs. The node answers no
   * task call without one, and none addressed to another node.
   */
  private async signedA2aCall<T>(
    method: string,
    params: Record<string, unknown>,
    sender: EnvelopeSender,
    agentDid: string,
  ): Promise<T> {
    return this.rpc.a2aCall<T>(method, await signEnvelope(agentDid, method, params, sender));
  }

  /**
   * Delegate a task to the A2A agent of the node whose machine identity is
   * `agentDid`, with an A2A v1.0 `SendMessage`. The task belongs to the
   * sender: only it can read, continue or cancel it. The node's card is
   * fetched and checked first (`getAgentCard`); when it does not prove
   * the endpoint is `agentDid`'s, nothing is sent.
   * @param sender - The DID the call is made as and the key that signs for it
   * @param agentDid - Machine DID of the node the task is meant for
   * @param taskDescription - Description of the task to delegate
   * @returns Exactly one of `task` (created or updated) or `message`
   * @throws AgentCardRefused when the card is unsigned, altered or another machine's
   */
  async delegateTask(sender: EnvelopeSender, agentDid: string, taskDescription: string): Promise<A2aSendMessageResponse> {
    await this.getAgentCard(agentDid);
    return this.signedA2aCall<A2aSendMessageResponse>(
      "SendMessage",
      a2aTextMessage(taskDescription, generateUUID()) as unknown as Record<string, unknown>,
      sender,
      agentDid,
    );
  }

  /**
   * Fetch the current state of one of the sender's own A2A tasks (`GetTask`).
   * A task another DID opened is reported as not found.
   * @param sender - The DID the call is made as and the key that signs for it
   * @param agentDid - Machine DID of the node that holds the task
   * @param taskId - Task identifier
   */
  async getA2aTask(sender: EnvelopeSender, agentDid: string, taskId: string): Promise<A2aTask> {
    return this.signedA2aCall<A2aTask>("GetTask", { id: taskId }, sender, agentDid);
  }

  /**
   * List the A2A tasks the sender opened (`ListTasks`), and no others.
   * @param sender - The DID the call is made as and the key that signs for it
   * @param agentDid - Machine DID of the node that holds the tasks
   * @param filter - Which of them, and how much of each
   */
  async listA2aTasks(sender: EnvelopeSender, agentDid: string, filter: A2aTaskFilter = {}): Promise<A2aTaskList> {
    return this.signedA2aCall<A2aTaskList>("ListTasks", { ...filter }, sender, agentDid);
  }

  /**
   * Cancel one of the sender's own A2A tasks (`CancelTask`).
   * @param sender - The DID the call is made as and the key that signs for it
   * @param agentDid - Machine DID of the node that holds the task
   * @param taskId - Task identifier
   */
  async cancelA2aTask(sender: EnvelopeSender, agentDid: string, taskId: string): Promise<A2aTask> {
    return this.signedA2aCall<A2aTask>("CancelTask", { id: taskId }, sender, agentDid);
  }

  /**
   * Fetch the node's A2A agent card from `/.well-known/agent-card.json` and
   * check it was signed by the hardware key `agentDid` derives from. No card
   * is returned unchecked.
   * @param agentDid - Machine DID of the node the caller means to reach
   * @throws AgentCardRefused when the card is unsigned, altered or another machine's
   */
  async getAgentCard(agentDid: string): Promise<Record<string, unknown>> {
    const card = await this.rpc.get<Record<string, unknown>>(A2A_AGENT_CARD_PATH);
    await verifyAgentCard(card, agentDid);
    return card;
  }

  // ─── Discovery & Lifecycle ──────────────────────────────────────────────────

  /**
   * Discover available models with optional filters.
   * @param options - Optional filters: modality, servingOnly, query
   * @returns Array of discovered models
   */
  async discoverModels(options?: {
    modality?: string;
    servingOnly?: boolean;
    query?: string;
  }): Promise<any> {
    return this.rpc.call("tenzro_discoverModels", [
      {
        modality: options?.modality,
        serving_only: options?.servingOnly,
        query: options?.query,
      },
    ]);
  }

  /**
   * The audit root `committer` recorded on chain for `epoch` (the latest
   * when omitted). Served from chain state, so any node answers it.
   */
  async getAuditCommit(committer: string, epoch?: number): Promise<AgentAuditCommitResponse> {
    return this.rpc.call<AgentAuditCommitResponse>("tenzro_getAgentAuditCommit", {
      committer,
      ...(epoch === undefined ? {} : { epoch }),
    });
  }

  /**
   * Check the hardware attestation a node committed with its audit and
   * telemetry root for `epoch`: the TPM quote binding the root to the
   * machine's measured boot state and identity. Served from chain state.
   */
  async verifyAuditAttestation(committer: string, epoch: number): Promise<AgentAuditAttestation> {
    return this.rpc.call<AgentAuditAttestation>("tenzro_verifyAgentAuditAttestation", {
      committer,
      epoch,
    });
  }

  /**
   * Whether an agent is quarantined: the quarantine chain state records
   * (which every node enforces) and any this node holds ahead of it.
   */
  async getQuarantine(agentDid: string): Promise<AgentQuarantineStatus> {
    return this.rpc.call<AgentQuarantineStatus>("tenzro_getAgentQuarantine", {
      agent_did: agentDid,
    });
  }

  /**
   * Resolve the key an agent's HTTP request signature names, from chain
   * state: the key, the agent's root, the terms in force and whether it is
   * revoked or quarantined. Pass the result to `verifyAgentRequest`.
   */
  async resolveAgentKey(agentDid: string, keyid: string): Promise<AgentKeyResolution> {
    return this.rpc.call<AgentKeyResolution>("tenzro_resolveAgentKey", {
      agent_did: agentDid,
      keyid,
    });
  }

  /**
   * The circuit-breaker records that disable or pause the bridge routes to
   * and from `sourceChain`, for one adapter or every adapter.
   */
  async getBridgeCircuit(
    sourceChain: string,
    adapter?: string,
  ): Promise<{
    source_chain: string;
    paused: boolean;
    disabled: boolean;
    stops: Array<{
      adapter: string;
      source_chain: string;
      mode: "disabled" | "paused";
      by: "validators" | "governance";
      reason: string;
      evidence_hash: string | null;
      epoch: number;
      at_ms: number;
    }>;
  }> {
    return this.rpc.call("tenzro_getBridgeCircuit", {
      source_chain: sourceChain,
      ...(adapter ? { adapter } : {}),
    });
  }

  /**
   * Check an audit entry's proof, as the agent's recorder exported it, and
   * check the epoch root it reaches against the root recorded on chain,
   * read through this client's node. Throws when any step fails.
   */
  async verifyAuditEntry(proof: AgentAuditProof): Promise<AgentAuditVerification> {
    const epochRoot = await verifyAgentAuditProof(proof);
    const commit = await this.getAuditCommit(proof.committer, proof.epoch);
    const onchainRoot = commit.record?.root;
    if (!onchainRoot) {
      throw new Error("no audit root is recorded on chain for this committer and epoch");
    }
    if (strip0x(onchainRoot).toLowerCase() !== epochRoot) {
      throw new Error(`the entry reaches ${epochRoot}, but chain state records ${onchainRoot}`);
    }
    return {
      entry: JSON.parse(new TextDecoder().decode(fromHex(proof.entry.body))),
      epochRoot,
      onchainRoot,
      epoch: proof.epoch,
      committer: proof.committer,
    };
  }

  /** `tenzro_exportEvidencePack`. */
  exportEvidencePack<T = unknown>(params: { agent_did?: unknown; agents?: unknown; audit?: unknown; payments?: unknown; receipts?: unknown; root_did?: unknown } = {}): Promise<T> {
    return this.rpc.call<T>("tenzro_exportEvidencePack", params);
  }

  /** `tenzro_flagAgentAudit` (operator only). */
  flagAgentAudit<T = unknown>(params: { epoch?: unknown; findings?: unknown } = {}): Promise<T> {
    return this.rpc.call<T>("tenzro_flagAgentAudit", params);
  }

  /**
   * `tenzro_recordAgentAuditSession` (operator only): report an audit
   * session's latest line (its MMR root over `count` entries) to the serving
   * node, which commits each ended epoch's lines on chain.
   */
  recordAgentAuditSession(params: { session_id: string; mmr_root: string; count: number }): Promise<{ epoch: number; sessions: number }> {
    return this.rpc.call("tenzro_recordAgentAuditSession", params);
  }

  /** `tenzro_getAgentTermsCredential`: a delegated agent's Terms as an unsigned W3C VC 2.0 credential its controller signs; null when the agent has no Terms. */
  getAgentTermsCredential<T = unknown>(agentDid: string): Promise<T> {
    return this.rpc.call<T>("tenzro_getAgentTermsCredential", { agent_did: agentDid });
  }

  /** `tenzro_recordExecutionReceipt` (owner proof): record, once, a receipt an outside platform gave an agent for work it ran there; the receipt's SHA-256 enters the agent's signed audit log. */
  recordExecutionReceipt<T = unknown>(params: {
    agent_did: string;
    platform: string;
    receipt: string;
    units?: number;
    did_envelope: unknown;
  }): Promise<T> {
    return this.rpc.call<T>("tenzro_recordExecutionReceipt", params);
  }
}

export function strip0x(s: string): string {
  return s.startsWith("0x") ? s.slice(2) : s;
}

export function fromHex(s: string): Uint8Array {
  const h = strip0x(s);
  const out = new Uint8Array(h.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(h.slice(2 * i, 2 * i + 2), 16);
  return out;
}

export function toHex(b: Uint8Array): string {
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
}

export function u64le(n: number): Uint8Array {
  const out = new Uint8Array(8);
  new DataView(out.buffer).setBigUint64(0, BigInt(n), true);
  return out;
}

export async function sha256(...parts: Uint8Array[]): Promise<Uint8Array> {
  const len = parts.reduce((a, p) => a + p.length, 0);
  const buf = new Uint8Array(len);
  let off = 0;
  for (const p of parts) {
    buf.set(p, off);
    off += p.length;
  }
  return new Uint8Array(await crypto.subtle.digest("SHA-256", buf));
}

export function nodeHash(l: Uint8Array, r: Uint8Array): Promise<Uint8Array> {
  return sha256(Uint8Array.of(0x01), l, r);
}

function mountainSizes(n: number): number[] {
  const out: number[] = [];
  for (let b = 52; b >= 0; b--) {
    const size = 2 ** b;
    if (Math.floor(n / size) % 2 === 1) out.push(size);
  }
  return out;
}

export async function bagPeaks(peaks: Uint8Array[]): Promise<Uint8Array> {
  if (peaks.length === 0) return new Uint8Array(32);
  let acc = peaks[peaks.length - 1];
  for (let i = peaks.length - 2; i >= 0; i--) acc = await nodeHash(peaks[i], acc);
  return acc;
}

/**
 * The `tx_type` of a transaction lifting an agent's quarantine, for
 * `tenzro_sendRawTransaction`. Only the owner or controller the
 * quarantine names may send it.
 */
export function liftAgentQuarantineTx(agentDid: string, reasonText?: string): Record<string, unknown> {
  return { LiftAgentQuarantine: { agent_did: agentDid, reason_text: reasonText ?? null } };
}

/**
 * Check an audit proof end to end: the entry's leaf hash, its path to the
 * session's MMR root, and the session line's path to the epoch root.
 * Returns the epoch root (hex) for comparison with the root on chain.
 */
export async function verifyAgentAuditProof(proof: AgentAuditProof): Promise<string> {
  const body = fromHex(proof.entry.body);
  const entry = JSON.parse(new TextDecoder().decode(body)) as { seq: number; session_id: string };
  const { mmr, epoch_proof: ep } = proof;
  if (entry.seq !== mmr.index) throw new Error("entry sequence number and proof position differ");
  if (strip0x(entry.session_id) !== strip0x(ep.leaf.session_id)) {
    throw new Error("entry and epoch line name different sessions");
  }
  if (mmr.size !== ep.leaf.count) throw new Error("MMR size and committed entry count differ");

  const leaf = await sha256(Uint8Array.of(0x00), u64le(body.length), body, fromHex(proof.entry.signature));
  const sizes = mountainSizes(mmr.size);
  if (sizes.length !== mmr.peaks.length) throw new Error("peak count does not match the range size");
  const peaks = mmr.peaks.map(fromHex);
  let start = 0;
  let found = false;
  for (let t = 0; t < sizes.length; t++) {
    const m = sizes[t];
    if (mmr.index < start + m) {
      if (2 ** mmr.siblings.length !== m) throw new Error("path length does not match the peak height");
      let pos = mmr.index - start;
      let hash = leaf;
      for (const s of mmr.siblings.map(fromHex)) {
        hash = pos % 2 === 0 ? await nodeHash(hash, s) : await nodeHash(s, hash);
        pos = Math.floor(pos / 2);
      }
      if (toHex(hash) !== toHex(peaks[t])) throw new Error("entry does not reach its peak");
      found = true;
      break;
    }
    start += m;
  }
  if (!found) throw new Error("leaf index is past the range");
  const sessionRoot = await bagPeaks(peaks);
  if (toHex(sessionRoot) !== strip0x(ep.leaf.mmr_root).toLowerCase()) {
    throw new Error("entry does not reach the committed session root");
  }

  let hash = await sha256(
    Uint8Array.of(0x02),
    fromHex(ep.leaf.session_id),
    fromHex(ep.leaf.mmr_root),
    u64le(ep.leaf.count),
  );
  let pos = ep.index;
  let width = ep.count;
  const sibs = ep.siblings.map(fromHex);
  let next = 0;
  if (pos >= width) throw new Error("session index is past the tree");
  while (width > 1) {
    const sib = pos ^ 1;
    if (sib < width) {
      const s = sibs[next++];
      if (!s) throw new Error("proof is short a sibling");
      hash = pos % 2 === 0 ? await nodeHash(hash, s) : await nodeHash(s, hash);
    }
    pos = Math.floor(pos / 2);
    width = Math.ceil(width / 2);
  }
  if (next !== sibs.length) throw new Error("proof has extra siblings");
  return toHex(hash);
}


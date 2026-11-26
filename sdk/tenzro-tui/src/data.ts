import {
  GovernanceClient,
  RpcCallError,
  RpcClient,
  TenzroClient,
  ValidatorClient,
  type LoadedModel,
  type NodeStatusReport,
  type ProposalView,
  type ValidatorRegistryEntry,
} from "tenzro-sdk";
import type { Condition } from "./alerts.js";
import { plainError } from "./format.js";
import { redact, type Shown } from "./redact.js";
import type { StopCheck } from "./stop.js";
import { fetchAsk, witnessCheck, type ListedEndpoint } from "./witness.js";

/** One section of the screen: what the node said, when, or why it could not. */
export type Reading<T> =
  | { state: "pending" }
  | { state: "ok"; value: T; at: number }
  | { state: "error"; error: Shown; at: number; last?: { value: T; at: number } };

export const pending = { state: "pending" } as const;

/** One row of `tenzro_listPeers`: this node, or a peer whose signed announcement it holds. */
export interface Peer {
  peer_id: string;
  self: boolean;
  account: string | null;
  machine_did: string | null;
  roles: string[];
  hardware_tier: string | null;
  identity_anchor: string | null;
  region: string | null;
  version: string | null;
  age_ms?: number;
}

export interface Snapshot {
  at: number;
  status: Reading<NodeStatusReport>;
  health: Reading<{ status: string; version: string }>;
  syncing: Reading<boolean>;
  chainId: Reading<number>;
  finalized: Reading<number>;
  models: Reading<LoadedModel[]>;
  validators: Reading<ValidatorRegistryEntry[]>;
  proposals: Reading<{ items: ProposalView[]; total: number }>;
  balance: Reading<{ address: string; wei: bigint; nonce: number | null }>;
  peers: Reading<Peer[]>;
  /** The node's conditions list; null when the node does not serve one. */
  conditions: Reading<Condition[] | null>;
}

export const emptySnapshot: Snapshot = {
  at: 0,
  status: pending,
  health: pending,
  syncing: pending,
  chainId: pending,
  finalized: pending,
  models: pending,
  validators: pending,
  proposals: pending,
  balance: pending,
  peers: pending,
  conditions: pending,
};

/** What a source can say about a planned stop beyond the node's own view. */
export type Witnesses = (snap: Snapshot) => Promise<StopCheck>;

export interface Source {
  /** The node URL as it may be shown: credentials in it are masked. */
  url: Shown;
  collect(address: string | null, prev: Snapshot): Promise<Snapshot>;
  /** Ask other operators how the network looks to them; absent when the source has nobody to ask. */
  witnesses?: Witnesses;
}

const CALL_TIMEOUT_MS = 4000;

function within<T>(p: Promise<T>, ms: number): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const t = setTimeout(() => reject(new Error("timed out")), ms);
    p.then(
      (v) => {
        clearTimeout(t);
        resolve(v);
      },
      (e) => {
        clearTimeout(t);
        reject(e);
      },
    );
  });
}

async function read<T>(url: Shown, prev: Reading<T>, f: () => Promise<T>): Promise<Reading<T>> {
  try {
    const value = await within(f(), CALL_TIMEOUT_MS);
    return { state: "ok", value, at: Date.now() };
  } catch (e) {
    const last = prev.state === "ok" ? { value: prev.value, at: prev.at } : prev.state === "error" ? prev.last : undefined;
    return { state: "error", error: plainError(e, url), at: Date.now(), ...(last ? { last } : {}) };
  }
}

/** A source backed by the TypeScript SDK, one node URL. */
export function sdkSource(url: string, apiUrl?: string): Source {
  const client = new TenzroClient({ endpoint: url, ...(apiUrl ? { apiEndpoint: apiUrl } : {}), timeout: CALL_TIMEOUT_MS });
  const rpc = new RpcClient(url, apiUrl, CALL_TIMEOUT_MS);
  const validators = new ValidatorClient(rpc);
  const governance = new GovernanceClient(rpc);
  const shown = redact(url);
  return {
    url: shown,
    async collect(address, prev) {
      const [status, health, syncing, chainId, finalized, models, vals, props, balance, peers, conditions] = await Promise.all([
        read(shown, prev.status, () => client.nodeInfo()),
        read(shown, prev.health, async () => {
          const h = await client.health();
          return { status: h.status, version: h.version };
        }),
        read(shown, prev.syncing, () => client.isSyncing()),
        read(shown, prev.chainId, () => client.getChainId()),
        read(shown, prev.finalized, () => client.getFinalizedBlock()),
        read(shown, prev.models, async () => (await client.inference.listLoadedModels()).models),
        read(shown, prev.validators, async () => (await validators.list()).validators),
        read(shown, prev.proposals, async () => {
          const page = await governance.listProposals({ limit: 25 });
          return { items: page.proposals, total: page.total };
        }),
        address
          ? read(shown, prev.balance, async () => {
              const wei = await client.getBalance(address);
              let nonce: number | null = null;
              try {
                nonce = await client.wallet.getNonce(address as never);
              } catch {
                nonce = null;
              }
              return { address, wei, nonce };
            })
          : Promise.resolve(pending as Reading<Snapshot["balance"] extends Reading<infer V> ? V : never>),
        read(shown, prev.peers, async () => ((await client.listPeers()) as { peers: Peer[] }).peers),
        read(shown, prev.conditions, async () => {
          try {
            return await rpc.call<Condition[]>("tenzro_listConditions");
          } catch (e) {
            // A node that does not serve the list is not a failed read.
            if (e instanceof RpcCallError && e.code === -32601) return null;
            throw e;
          }
        }),
      ]);
      return { at: Date.now(), status, health, syncing, chainId, finalized, models, validators: vals, proposals: props, balance, peers, conditions };
    },
    async witnesses(snap) {
      let listed: ListedEndpoint[];
      try {
        listed = (await within(rpc.call<{ endpoints: ListedEndpoint[] }>("tenzro_listRoleEndpoints", { role: "rpc" }), CALL_TIMEOUT_MS)).endpoints;
      } catch (e) {
        return { id: "peers", ok: false, text: `The chain's operator list could not be read: ${plainError(e, shown)}` };
      }
      return (await witnessCheck(listed, snap, fetchAsk)).check;
    },
  };
}

/** The one-word state the header shows. UNKNOWN is a state, never green. */
export type Headline = "OK" | "WATCH" | "DOWN" | "UNKNOWN";

export function headline(s: Snapshot): { word: Headline; reason: Shown } {
  const h = judge(s);
  return { word: h.word, reason: redact(h.reason) };
}

function judge(s: Snapshot): { word: Headline; reason: string } {
  if (s.status.state === "pending") return { word: "UNKNOWN", reason: "waiting for the first answer" };
  if (s.status.state === "error") {
    return { word: "DOWN", reason: s.status.error };
  }
  const st = s.status.value;
  if (st.state !== "Running") return { word: "WATCH", reason: `node state is ${st.state}` };
  if (st.health_status !== "Healthy") return { word: "WATCH", reason: `node health is ${st.health_status}` };
  if (s.syncing.state === "ok" && s.syncing.value) return { word: "WATCH", reason: "node is catching up with the network" };
  if (st.disk && (st.disk as { pressure?: string }).pressure && (st.disk as { pressure?: string }).pressure !== "normal") {
    return { word: "WATCH", reason: `disk pressure is ${(st.disk as { pressure?: string }).pressure}` };
  }
  return { word: "OK", reason: "node is running and healthy" };
}

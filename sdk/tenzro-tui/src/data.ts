import {
  GovernanceClient,
  RpcClient,
  TenzroClient,
  ValidatorClient,
  type LoadedModel,
  type NodeStatusReport,
  type ProposalView,
  type ValidatorRegistryEntry,
} from "tenzro-sdk";
import { plainError } from "./format.js";

/** One section of the screen: what the node said, when, or why it could not. */
export type Reading<T> =
  | { state: "pending" }
  | { state: "ok"; value: T; at: number }
  | { state: "error"; error: string; at: number; last?: { value: T; at: number } };

export const pending = { state: "pending" } as const;

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
};

export interface Source {
  url: string;
  collect(address: string | null, prev: Snapshot): Promise<Snapshot>;
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

async function read<T>(url: string, prev: Reading<T>, f: () => Promise<T>): Promise<Reading<T>> {
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
  return {
    url,
    async collect(address, prev) {
      const [status, health, syncing, chainId, finalized, models, vals, props, balance] = await Promise.all([
        read(url, prev.status, () => client.nodeInfo()),
        read(url, prev.health, async () => {
          const h = await client.health();
          return { status: h.status, version: h.version };
        }),
        read(url, prev.syncing, () => client.isSyncing()),
        read(url, prev.chainId, () => client.getChainId()),
        read(url, prev.finalized, () => client.getFinalizedBlock()),
        read(url, prev.models, async () => (await client.inference.listLoadedModels()).models),
        read(url, prev.validators, async () => (await validators.list()).validators),
        read(url, prev.proposals, async () => {
          const page = await governance.listProposals({ limit: 25 });
          return { items: page.proposals, total: page.total };
        }),
        address
          ? read(url, prev.balance, async () => {
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
      ]);
      return { at: Date.now(), status, health, syncing, chainId, finalized, models, validators: vals, proposals: props, balance };
    },
  };
}

/** The one-word state the header shows. UNKNOWN is a state, never green. */
export type Headline = "OK" | "WATCH" | "DOWN" | "UNKNOWN";

export function headline(s: Snapshot): { word: Headline; reason: string } {
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

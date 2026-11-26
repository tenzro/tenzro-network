// Rehearsal: the whole console against a scripted node and a helper that
// does nothing, so a person can practise reading an alert, acknowledging it
// and walking a planned stop without a node being touched. Nothing here
// opens a connection.

import type { Condition } from "./alerts.js";
import type { Peer, Snapshot, Source } from "./data.js";
import type { Helper } from "./helper.js";
import { redact } from "./redact.js";

/** Snapshots in one pass of the script; it then starts again. */
export const SCRIPT_LENGTH = 12;

const ACCOUNT = "0x" + "5e".repeat(20) + "00".repeat(12);
const ENDPOINT = "7e".repeat(32);

/** Seven active validators, so the set can lose one. Typed loosely: the SDK's entry has fields the script does not need. */
function validators(): never {
  return Array.from({ length: 7 }, (_, i) => ({
    address: `rehearsal-validator-${i + 1}`,
    ml_dsa_pubkey: "",
    p256_pubkey: "",
    node_key: "",
    withdrawal_address: "",
    self_stake: "1000000000000000000000000",
    status: "Active",
    registered_at_epoch: 0,
    activated_at_epoch: 0,
    exited_at_epoch: null,
    jailed_until_epoch: null,
    tee_attestation_hash: null,
    metadata_uri: "",
    updated_at: 0,
  })) as never;
}

function peers(): Peer[] {
  const peer = (n: number): Peer => ({ peer_id: n.toString(16).padStart(2, "0").repeat(32), self: false, account: null, machine_did: `did:tenzro:machine:rehearsal-${n}`, roles: ["Validator"], hardware_tier: "server", identity_anchor: "tpm", region: null, version: null, age_ms: 4000 * n });
  return [{ peer_id: ENDPOINT, self: true, account: ACCOUNT, machine_did: "did:tenzro:machine:rehearsal-0", roles: ["Validator"], hardware_tier: "server", identity_anchor: "tpm", region: null, version: "rehearsal" }, peer(1), peer(2), peer(3)];
}

/**
 * The scripted node at step `n`: healthy and advancing, then for four steps
 * it stops following the network (its own condition, height frozen), then it
 * recovers.
 */
export function scripted(n: number, at: number): Snapshot {
  const step = ((n % SCRIPT_LENGTH) + SCRIPT_LENGTH) % SCRIPT_LENGTH;
  const stalled = step >= 3 && step <= 6;
  const pass = Math.floor(n / SCRIPT_LENGTH);
  const height = 500_000 + pass * SCRIPT_LENGTH * 10 + (stalled ? 30 : step * 10);
  const ok = <T,>(value: T) => ({ state: "ok" as const, value, at });
  const follow: Condition = {
    id: "follow",
    kind: "follow",
    title: "This node has stopped following the network",
    detail: "no new block has arrived (rehearsal)",
    since: new Date(Date.UTC(2027, 0, 15, 8, pass % 60, 0)).toISOString(),
    code: "no_progress",
    severity: "critical",
  };
  return {
    at,
    status: ok({
      state: "Running",
      roles: ["Validator"],
      health_status: "Healthy",
      uptime_secs: 86_400 + n * 5,
      block_height: height,
      peer_count: stalled ? 0 : 3,
      data_dir: "(rehearsal)",
      tee_capable: true,
      tee_vendor: "tpm",
      iroh_enabled: true,
      iroh_endpoint_id: ENDPOINT,
      iroh_alpns: [],
      hidden_gpus: [],
      disk: { pressure: "normal", used_pct: 37 },
      machine_did: "did:tenzro:machine:rehearsal-0",
      operator_did: null,
      payee: ACCOUNT,
    } as never),
    health: ok({ status: "healthy", version: "rehearsal" }),
    syncing: ok(false),
    chainId: ok(13380),
    finalized: ok(height - 2),
    models: ok([]),
    validators: ok(validators()),
    proposals: ok({ items: [], total: 0 }),
    balance: ok({ address: ACCOUNT, wei: 250n * 10n ** 18n, nonce: 3 }),
    peers: ok(stalled ? peers().slice(0, 1) : peers()),
    conditions: ok(stalled ? [follow] : []),
  };
}

/** A source that plays the script, one step per collection. */
export function rehearsalSource(): Source {
  let n = 0;
  return {
    url: redact("rehearsal (no node is contacted)"),
    collect: async () => scripted(n++, Date.now()),
    witnesses: async () => ({ id: "peers", ok: true, text: "3 of the 3 other operators that answered (3 asked) see a healthy network at this node's tip. (rehearsal)" }),
  };
}

/** A helper that records what it was asked and changes nothing. */
export function rehearsalHelper(asked: { method: string; params: unknown }[] = []): Helper {
  return {
    path: "(rehearsal)",
    call: async <T,>(method: string, params: Record<string, unknown> = {}) => {
      asked.push({ method, params });
      return { service: "running", reason: "rehearsal: nothing was stopped" } as T;
    },
  };
}

import type { Snapshot, Source } from "../src/data.js";

const now = Date.now();
const ok = <T,>(value: T) => ({ state: "ok" as const, value, at: now });

export const PAYEE = "0x3e233163a86f398a7867b7d942c0552ecf6080e3000000000000000000000000";

export function healthy(): Snapshot {
  return {
    at: now,
    status: ok({
      state: "Running",
      roles: ["Validator", "Provider"],
      health_status: "Healthy",
      uptime_secs: 3700,
      block_height: 1234567,
      peer_count: 12,
      data_dir: "/var/lib/tenzro",
      tee_capable: true,
      tee_vendor: "tpm",
      iroh_enabled: true,
      iroh_endpoint_id: "3d480675a69f1f52f11deb3acc2adfb5ab94c37e6f8bffd0b19dfab64c56583e",
      iroh_alpns: [],
      hidden_gpus: [],
      disk: { pressure: "normal", used_pct: 41 },
      machine_did: "did:tenzro:machine:265ad18ed76da11bfaa3015b316beb6c6d46de50a286f538866182cbc957b33f",
      operator_did: null,
      payee: PAYEE,
    }),
    health: ok({ status: "healthy", version: "0.2.0" }),
    syncing: ok(false),
    chainId: ok(13380),
    finalized: ok(1234560),
    models: ok(
      Array.from({ length: 30 }, (_, i) => ({
        model_id: `org/model-${String(i).padStart(2, "0")}-instruct-q4`,
        type: i % 3 === 0 ? "embedding" : "chat",
        engine: i % 4 === 0 ? null : "llamacpp",
        visibility: "public" as const,
        visibility_source: "node" as const,
        access: { mode: "public" as const, price_per_request: "1000" },
        loaded: i % 2 === 0,
        serving: true,
      })),
    ),
    validators: ok([
      {
        address: "5BZQKYYVG7TC43oWX2ktBktWCkzp8M5KYqNRXvXPefLs",
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
      },
    ] as never),
    proposals: ok({
      total: 2,
      items: [
        {
          proposal: { id: "9f3c1a77d2e84b10aa55", proposer: "x", track: "standard", eta_ms: null, action: { action: "x" }, created_ms: 0, voting_ends_ms: 0, status: "Voting", queued_ms: null, veto_extension_ms: 0, concerns: 0, concern_doubled: false },
          kind: "policy_update",
          tally: { yes: "5000000000000000000000", no: "100000000000000000000", total_eligible: "1000000000000000000000000" },
          veto_locked: "0",
        },
        {
          proposal: { id: "11aa22bb33cc44dd55ee", proposer: "x", track: "fast", eta_ms: null, action: { action: "x" }, created_ms: 0, voting_ends_ms: 0, status: "Executed", queued_ms: null, veto_extension_ms: 0, concerns: 0, concern_doubled: false },
          kind: "param_change",
          tally: { yes: "9000000000000000000000", no: "0", total_eligible: "1000000000000000000000000" },
          veto_locked: "0",
        },
      ] as never,
    }),
    balance: ok({ address: PAYEE, wei: 1234567890123456789012n, nonce: 7 }),
  };
}

export function down(url: string): Snapshot {
  const e = { state: "error" as const, error: `Cannot reach a node at ${url}. Start one, or pass --rpc <url>.`, at: now };
  return { at: now, status: e, health: e, syncing: e, chainId: e, finalized: e, models: e, validators: e, proposals: e, balance: { state: "pending" } };
}

export function sourceOf(snap: () => Snapshot, url = "http://127.0.0.1:8545"): Source {
  return { url, collect: async () => snap() };
}

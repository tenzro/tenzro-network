import { vi } from "vitest";
import type {
  CapabilityReadout,
  ControlConfig,
  RoleStakeGate,
  WalletStatusView,
} from "@/lib/api";

/** Every command the UI sent over the IPC bridge, in order. */
export const calls: { cmd: string; args?: Record<string, unknown> }[] = [];

/** Answers by command name; a command with no answer rejects. */
export const answers: Record<string, (args?: Record<string, unknown>) => unknown> = {};

export const invoke = vi.fn(async (cmd: string, args?: Record<string, unknown>) => {
  calls.push({ cmd, args });
  const answer = answers[cmd];
  if (!answer) throw new Error(`no answer for ${cmd}`);
  return answer(args);
});

export function resetIpc() {
  calls.length = 0;
  for (const k of Object.keys(answers)) delete answers[k];
  invoke.mockClear();
}

export function gate(role: string, over: Partial<RoleStakeGate> = {}): RoleStakeGate {
  return {
    role,
    label: role,
    required_wei: "1000",
    required_display: "1,000 TNZO",
    met: false,
    staked_wei: "0",
    staked_display: "0 TNZO",
    can_stake: true,
    shortfall_wei: "0",
    shortfall_display: "0 TNZO",
    ...over,
  };
}

export function wallet(over: Partial<WalletStatusView> = {}): WalletStatusView {
  return {
    exists: true,
    address: "0x" + "ab".repeat(32),
    display_address: "0xabab...abab",
    did: "did:tenzro:machine:abc",
    custody: "hardware",
    balance_wei: "0",
    balance_display: "0 TNZO",
    staked_wei: "0",
    staked_display: "0 TNZO",
    staked_role: "",
    unbonding_at_ms: null,
    unbonding_roles: [],
    stake_account: { address: "0x" + "ab".repeat(32), signer: "tpm" },
    stake_balance_wei: "0",
    stake_balance_display: "0 TNZO",
    node_ready: true,
    gates: [gate("validator")],
    ...over,
  };
}

export function config(over: Partial<ControlConfig> = {}): ControlConfig {
  return {
    identity: { did: "", address: "", custody: "none", display_name: "" },
    roles: [],
    models: [],
    availability: { always_on: true, windows: [] },
    ai_pricing: { input_price_per_token_wei: 0, output_price_per_token_wei: 0 },
    storage_pricing: { capacity_gb: 0, min_rate_wei: 0, max_rate_wei: 0 },
    compute_pricing: { rate_per_hour_wei: 0 },
    memory: { reserve_gb: null, resident_ceiling_gb: null, on_demand_ceiling_gb: null },
    onboarded: false,
    ...over,
  };
}

export function hardware(): CapabilityReadout {
  return {
    ram_gb: 32,
    physical_cores: 8,
    gpu: "None",
    gpu_class: "None",
    free_disk_gb: 500,
    offerable_storage_gb: 400,
    roles: [
      { role: "validator", available: true, detail: "Any machine can validate." },
      { role: "compute", available: false, detail: "No rentable accelerator." },
    ],
  };
}

export function budget() {
  return {
    ram_total_gb: 32,
    ram_reserved_gb: 8,
    ram_selected_gb: 0,
    ram_available_gb: 24,
    disk_total_gb: 500,
    disk_reserved_gb: 100,
    disk_downloads_gb: 0,
    disk_storage_gb: 0,
    disk_available_gb: 400,
    models: [],
  };
}

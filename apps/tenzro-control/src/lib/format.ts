import type { RoleStakeGate } from "./api";

const WEI_PER_TNZO = 1_000_000_000_000_000_000n;

/// Wei arrives as a decimal string from the wallet commands and as a JSON
/// number from the persisted config. Both go through BigInt so the
/// fractional part is exact rather than whatever a double rounded to.
export function formatTnzo(value: string | number, maxDecimals = 6): string {
  let wei: bigint;
  try {
    wei = typeof value === "number" ? BigInt(Math.round(value)) : BigInt(value.trim() || "0");
  } catch {
    return "0 TNZO";
  }

  const whole = wei / WEI_PER_TNZO;
  const rest = wei % WEI_PER_TNZO;

  if (rest === 0n) return `${whole.toLocaleString("en-US")} TNZO`;

  const frac = rest.toString().padStart(18, "0").slice(0, maxDecimals).replace(/0+$/, "");
  if (frac === "") {
    // Non-zero but smaller than the precision we show.
    return `<0.${"0".repeat(maxDecimals - 1)}1 TNZO`;
  }
  return `${whole.toLocaleString("en-US")}.${frac} TNZO`;
}

/// Decimal TNZO to a wei string, without ever touching a double. Returns
/// null for anything that is not a plain non-negative decimal.
export function tnzoToWei(input: string): string | null {
  const text = input.trim();
  if (!/^\d*\.?\d*$/.test(text) || text === "" || text === ".") return null;

  const [whole, frac = ""] = text.split(".");
  if (frac.length > 18) return null;

  const padded = frac.padEnd(18, "0");
  return (BigInt(whole || "0") * WEI_PER_TNZO + BigInt(padded || "0")).toString();
}

/// Wei to a plain decimal string with no unit suffix, for text inputs.
export function weiToTnzoInput(value: string | number): string {
  let wei: bigint;
  try {
    wei = typeof value === "number" ? BigInt(Math.round(value)) : BigInt(value.trim() || "0");
  } catch {
    return "0";
  }
  const whole = wei / WEI_PER_TNZO;
  const frac = (wei % WEI_PER_TNZO).toString().padStart(18, "0").replace(/0+$/, "");
  return frac === "" ? whole.toString() : `${whole}.${frac}`;
}

export function formatBytes(bytes: number): string {
  if (!Number.isFinite(bytes) || bytes <= 0) return "0 B";
  const units = ["B", "KB", "MB", "GB", "TB"];
  let i = 0;
  let n = bytes;
  while (n >= 1024 && i < units.length - 1) {
    n /= 1024;
    i += 1;
  }
  const decimals = i === 0 ? 0 : n < 10 ? 1 : 0;
  return `${n.toFixed(decimals)} ${units[i]}`;
}

export function formatUptime(seconds: number): string {
  if (!Number.isFinite(seconds) || seconds < 0) return "—";
  const s = Math.floor(seconds);
  const days = Math.floor(s / 86400);
  const hours = Math.floor((s % 86400) / 3600);
  const minutes = Math.floor((s % 3600) / 60);

  if (days > 0) return `${days}d ${hours}h`;
  if (hours > 0) return `${hours}h ${minutes}m`;
  if (minutes > 0) return `${minutes}m`;
  return `${s}s`;
}

export function hourLabel(hour: number): string {
  const h = ((hour % 24) + 24) % 24;
  return `${h.toString().padStart(2, "0")}:00`;
}

export const DAY_NAMES = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"] as const;

export function formatPercent(value: number, decimals = 0): string {
  if (!Number.isFinite(value)) return "0%";
  return `${value.toFixed(decimals)}%`;
}

export type GateStatus = "active" | "ready" | "short" | "blocked";

export interface GateReadout {
  status: GateStatus;
  tone: "good" | "warn";
  label: string;
  /// One line of explanation, or null when the label says everything.
  detail: string | null;
}

/// Read one role's stake gate into something a badge can render.
///
/// Holding enough TNZO is not the same as having staked it, and the four
/// states here are all distinguishable and all reachable:
///
/// - **active** — a bond is posted against this role and covers it.
/// - **ready** — the balance covers the minimum and nothing is in the way,
///   so a stake call would be accepted.
/// - **short** — the balance is below the minimum.
/// - **blocked** — the balance would cover it, but another role already
///   holds this account's one permitted stake.
///
/// A missing gate means the role carries no stake minimum, which reads as
/// active rather than as a problem.
export function describeGate(gate: RoleStakeGate | undefined): GateReadout {
  if (!gate) {
    return { status: "active", tone: "good", label: "Active", detail: null };
  }
  if (gate.met) {
    return {
      status: "active",
      tone: "good",
      label: "Active",
      detail: `${gate.staked_display} staked`,
    };
  }
  if (gate.can_stake) {
    return {
      status: "ready",
      tone: "warn",
      label: "Stake required",
      detail: `Balance covers the ${gate.required_display} minimum. Post the stake to activate.`,
    };
  }
  if (gate.shortfall_wei !== "0") {
    return {
      status: "short",
      tone: "warn",
      label: "Waiting on stake",
      detail: `${gate.shortfall_display} short of ${gate.required_display}`,
    };
  }
  return {
    status: "blocked",
    tone: "warn",
    label: "Blocked by another stake",
    detail: "Only one stake can be live at a time.",
  };
}

/// Random 32-byte value as lowercase hex, for the device-key and caBLE
/// possession checks. Uses the WebCrypto CSPRNG the WebView already has.
export function randomPrehashHex(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

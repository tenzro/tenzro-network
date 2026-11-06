import type { CapabilityReadout } from "./api";

/// One rung of the stake ladder, as Control offers it.
///
/// The `id` is the wire token stored in `ControlConfig::roles` and read
/// back by the node's `NetworkRole` parser, so it may only ever be a
/// string that parser accepts.
export interface RoleDef {
  id: string;
  title: string;
  blurb: string;
  earns: string;
  /// The bond scales with pledged capacity, so the figure the gate
  /// reports is a floor rather than the whole cost. Rendered as a
  /// trailing `+` next to the amount.
  scaled?: boolean;
  /// What the bond scales with. Shown under the amount for scaled rungs.
  stakeNote?: string;
  /// The rung cannot be held alongside any other. Picking it clears the
  /// rest of the selection, and picking anything else clears it.
  exclusive?: boolean;
}

/// The roles Control can offer, in ascending order of what they ask of
/// the machine.
///
/// Seven of the ladder's rungs. An RPC operator is not a separate node
/// role: it is a validator that additionally serves public RPC.
export const ROLES: RoleDef[] = [
  {
    id: "light",
    title: "Local only",
    blurb:
      "Run models from the catalogue on this machine for your own use. Nothing is offered to the network.",
    earns: "Nothing to earn — and nothing to stake.",
    exclusive: true,
  },
  {
    id: "validator",
    title: "Validator",
    blurb: "Vote on blocks and finalise them. Runs whenever the machine is awake.",
    earns: "Earns network rewards for the blocks it proposes and the checkpoints it signs.",
  },
  {
    id: "ai",
    title: "AI inference",
    blurb: "Serve models from the catalogue to callers on the network.",
    earns: "Earns per input and output token, at rates you set.",
  },
  {
    id: "storage",
    title: "Storage",
    blurb: "Hold content-addressed data for the network on spare disk.",
    earns: "Earns per gigabyte-month, at rates you set.",
    scaled: true,
    stakeNote: "Rises with every terabyte you pledge.",
  },
  {
    id: "compute",
    title: "Compute",
    blurb: "Rent this machine's accelerator out by the hour. The renter brings their own work.",
    earns: "Earns per card-hour, at rates you set.",
    scaled: true,
    stakeNote: "Rises with the class and count of the cards you pledge.",
  },
  {
    id: "cloud",
    title: "Cloud",
    blurb: "Host static sites and functions for the network on this machine.",
    earns: "Earns per deployment-hour, at rates you set.",
    scaled: true,
    stakeNote: "More for databases, more again for full machines.",
  },
  {
    id: "tee",
    title: "Confidential compute",
    blurb: "Run work inside a hardware enclave and attest the result.",
    earns: "Earns a premium over plain inference.",
  },
];

/// Operator-facing name for a wire token, falling back to the token so a
/// role the node knows about but Control does not still reads sensibly.
export function roleLabel(id: string): string {
  return ROLES.find((r) => r.id === id)?.title ?? id;
}

/// Whether the selection loads models onto this machine at all, which is
/// what decides if the operator is asked to pick any.
export function runsModels(roles: string[]): boolean {
  return sellsModels(roles) || roles.includes("light");
}

/// Whether models loaded on this machine are offered to callers on the
/// network. Local-only operators run the same models but sell nothing, so
/// they are never asked for a rate and their models are served privately.
export function sellsModels(roles: string[]): boolean {
  return roles.includes("ai") || roles.includes("tee");
}

/// Why this machine cannot carry a role, or null when it can.
///
/// The verdict is decided by the Rust probe; this only reads it back, so
/// the role picker and the scan screen cannot disagree. The stake is a
/// separate axis: it is shown alongside as a requirement and checked
/// again once the wallet exists.
export function hardwareBlock(role: string, hw: CapabilityReadout | null): string | null {
  const verdict = hw?.roles.find((c) => c.role === role);
  return verdict && !verdict.available ? verdict.detail : null;
}

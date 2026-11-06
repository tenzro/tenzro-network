/** A governance lever as `tenzro_listLevers` reports it; only what this screen reads. */
export interface LeverRead {
  key: string;
  kind: "status" | "switch" | "value";
  status: "enabled" | "paused" | "retired" | null;
  /** Set while a protocol guardian pause holds the lever; `status` then reads paused. */
  guardian_pause_until_epoch?: number | null;
  pending?: { value: string; status: "enabled" | "paused" | "retired" | null; activates_epoch: number } | null;
}

export interface LeversRead {
  epoch: number;
  levers: LeverRead[];
}

export interface HeldLever {
  key: string;
  state: "paused" | "retired";
  /** Why it is held: a guardian pause that lifts at an epoch, or a vote. */
  cause: "guardian" | "vote";
  /** The epoch a guardian pause lifts at. */
  untilEpoch: number | null;
  /** An enacted change that will change the state, and when. */
  next: { status: string; epoch: number } | null;
}

/** The levers that are not running: paused by a vote or a guardian, or retired. */
export function heldLevers(read: LeversRead): HeldLever[] {
  const out: HeldLever[] = [];
  for (const l of read.levers) {
    if (l.status !== "paused" && l.status !== "retired") continue;
    const guardian = typeof l.guardian_pause_until_epoch === "number" && l.guardian_pause_until_epoch > read.epoch;
    out.push({
      key: l.key,
      state: l.status,
      cause: guardian ? "guardian" : "vote",
      untilEpoch: guardian ? (l.guardian_pause_until_epoch as number) : null,
      next:
        l.pending && l.pending.status
          ? { status: l.pending.status, epoch: l.pending.activates_epoch }
          : null,
    });
  }
  return out.sort((a, b) => a.key.localeCompare(b.key));
}

/** One line a person can read for a held lever. */
export function describeHeld(h: HeldLever): string {
  if (h.cause === "guardian") return `Paused by the protocol guardians until epoch ${h.untilEpoch}.`;
  const base = h.state === "retired" ? "Retired by a vote; it does not come back." : "Paused by a vote.";
  return h.next ? `${base} ${h.next.status} from epoch ${h.next.epoch}.` : base;
}

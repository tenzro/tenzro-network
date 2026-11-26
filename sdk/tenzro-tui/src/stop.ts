// What must hold before this node is stopped on purpose. A check that fails
// blocks the stop and says why; the console never stops a node past one.

import type { Alert } from "./alerts.js";
import type { Snapshot } from "./data.js";

export interface StopCheck {
  id: "fresh" | "alerts" | "syncing" | "quorum" | "peers";
  ok: boolean;
  text: string;
}

/** Validators that must sign for the set to make progress, equal-stake form: n - floor((n - 1) / 3). */
export function quorum(n: number): number {
  return n - Math.floor((n - 1) / 3);
}

function isValidator(roles: unknown): boolean {
  return Array.isArray(roles) ? roles.some((r) => String(r).toLowerCase() === "validator") : String(roles ?? "").toLowerCase().includes("validator");
}

/**
 * The checks, in the order shown. The validator count is the number of
 * `Active` entries in the node's validator list (`tenzro_listValidators`
 * through the SDK): it counts registrations, not which of them are up, and
 * not their stake, so it can only ever be too generous. One spare is kept on
 * top of the quorum for that reason.
 */
export function stopChecks(snap: Snapshot, alerts: Alert[]): StopCheck[] {
  const out: StopCheck[] = [];
  const fresh = snap.status.state === "ok" && snap.validators.state === "ok" && snap.syncing.state === "ok";
  out.push({ id: "fresh", ok: fresh, text: fresh ? "The node is answering." : "The node's state, validator list or sync state could not be read just now." });

  const paging = alerts.filter((a) => a.level === "page" && !a.ack);
  out.push({
    id: "alerts",
    ok: paging.length === 0,
    text: paging.length === 0 ? "No page-level alert is open." : `A page-level alert is open and not acknowledged: ${paging[0]!.title}`,
  });

  const syncing = snap.syncing.state === "ok" && snap.syncing.value;
  out.push({ id: "syncing", ok: !syncing, text: syncing ? "The node is still catching up with the network." : "The node is at the tip." });

  if (snap.status.state === "ok" && snap.validators.state === "ok") {
    if (!isValidator(snap.status.value.roles)) {
      out.push({ id: "quorum", ok: true, text: "This node does not validate; stopping it takes nothing from the validator set." });
    } else {
      const active = snap.validators.value.filter((v) => String(v.status) === "Active").length;
      const need = quorum(active) + 1;
      const left = active - 1;
      out.push({
        id: "quorum",
        ok: left >= need,
        text:
          left >= need
            ? `${active} validators are active; without this one ${left} remain, and ${need} (quorum plus one) are needed.`
            : `${active} validators are active; without this one only ${left} would remain, and ${need} (quorum plus one) are needed.`,
      });
    }
  } else {
    out.push({ id: "quorum", ok: false, text: "The validator set could not be read, so its headroom is unknown." });
  }
  return out;
}

export function stopAllowed(checks: StopCheck[]): boolean {
  return checks.every((c) => c.ok);
}

/**
 * What a stop does, in one sentence, said before the person is asked to
 * confirm. For a validator: what the set is left with, and that the node
 * itself waits until it leads none of the coming rounds before it shuts down
 * (`tenzro_gracefulExit` does that waiting, up to a minute by default).
 */
export function stopConsequence(snap: Snapshot): string {
  if (snap.status.state !== "ok" || snap.validators.state !== "ok") return "If you go on: the node shuts down. What that leaves the network with could not be read.";
  if (!isValidator(snap.status.value.roles)) {
    return "If you go on: this node stops answering its callers (RPC, models it serves). The validator set is not affected. It stays stopped until it is started again.";
  }
  const active = snap.validators.value.filter((v) => String(v.status) === "Active").length;
  const left = active - 1;
  const spare = left - quorum(active);
  return `If you go on: this validator stops signing, leaving ${left} of ${active}, ${spare} over quorum. The node first waits until it leads none of the coming rounds (up to a minute), then shuts down. It stays stopped until it is started again.`;
}

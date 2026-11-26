// What is wrong with the node, as alerts a person can act on and acknowledge.
//
// The node's own conditions list (`tenzro_listConditions`) is the source when
// the node serves it. The rules in `ownFindings` read from the snapshot what
// the list does not carry, and everything else too for a node that serves no
// list. Either way the findings pass through one engine: one alert per key, raised only after it
// holds for two snapshots running and dropped only after it is clear for
// two, so a value flapping around a threshold does not flicker. An
// acknowledgement needs a reason and stays with the alert until it clears.

import type { Snapshot } from "./data.js";
import { ageText } from "./format.js";
import { redact, type Shown } from "./redact.js";
import type { SharedAcks } from "./shared.js";

export type Level = "page" | "warn" | "info";

const ORDER: Record<Level, number> = { page: 0, warn: 1, info: 2 };

export function isLevel(v: unknown): v is Level {
  return typeof v === "string" && Object.hasOwn(ORDER, v);
}

/**
 * One entry of the node's conditions list. `id` names the thing (`follow`,
 * `requirement:disk`) and stays the same each time it opens; `since` (RFC
 * 3339) restarts on each opening, so the two together are one occurrence.
 */
export interface Condition {
  id: string;
  kind: string;
  title: string;
  detail: string;
  since: string;
  code: string;
  severity: string;
  needs?: "passkey" | "confirm";
}

/** Something found wrong in one snapshot. */
export interface Finding {
  key: string;
  level: Level;
  title: Shown;
  detail: Shown;
}

export interface Acknowledgement {
  reason: Shown;
  at: number;
}

/** A finding that has held long enough to be shown. */
export interface Alert extends Finding {
  since: number;
  ack: Acknowledgement | null;
}

interface Track {
  finding: Finding;
  since: number;
  present: number;
  absent: number;
  raised: boolean;
  ack: Acknowledgement | null;
}

export interface AlertState {
  tracks: Record<string, Track>;
  /** The finalized height last seen to change, and when. */
  progress: { finalized: number; since: number } | null;
}

export const noAlerts: AlertState = { tracks: {}, progress: null };

export interface AlertEvent {
  at: number;
  what: "raised" | "cleared" | "acknowledged";
  key: string;
  level: Level;
  title: Shown;
}

/** Snapshots a finding must hold for before it is raised, and be gone for before it clears. */
export const RAISE_AFTER = 2;
export const CLEAR_AFTER = 2;

/**
 * The node's severity word (`critical`, `warning`, `info`) as one of the
 * three levels. A word this console does not know is shown as a warning
 * rather than filed away as information.
 */
export function levelOf(severity: string): Level {
  const s = severity.toLowerCase();
  if (s === "critical") return "page";
  if (s === "info") return "info";
  return "warn";
}

export function findingsFromConditions(conditions: Condition[]): Finding[] {
  return conditions.map((c) => ({
    key: `condition:${c.id}@${c.since}`,
    level: levelOf(c.severity),
    title: redact(c.title),
    detail: redact(c.detail),
  }));
}

const UNREACHABLE = "node-unreachable";

/** The one finding only the console can make: the node did not answer it. */
function unreachable(snap: Snapshot): Finding[] {
  if (snap.status.state !== "error") return [];
  return [{ key: UNREACHABLE, level: "page", title: redact("The node does not answer"), detail: snap.status.error }];
}

/**
 * The console's own rules. The conditions list carries disk pressure and a
 * node that has stopped following the network, so with `listed` those rules
 * are left to the node; whether the node is running, healthy or catching up
 * is on no list and is always read here.
 */
export function ownFindings(snap: Snapshot, progress: AlertState["progress"], now: number, staleAfter: number, listed: boolean): Finding[] {
  const out = unreachable(snap);
  const add = (key: string, level: Level, title: string, detail: string) => out.push({ key, level, title: redact(title), detail: redact(detail) });
  const syncing = snap.syncing.state === "ok" && snap.syncing.value;
  if (snap.status.state === "ok") {
    const st = snap.status.value;
    if (st.state !== "Running") add("node-state", "warn", "The node is not running normally", `node state is ${st.state}`);
    if (st.health_status !== "Healthy") add("node-health", "warn", "The node reports it is not healthy", `node health is ${st.health_status}`);
    const pressure = (st.disk as { pressure?: string } | undefined)?.pressure;
    if (!listed && pressure && pressure !== "normal") add("disk-pressure", "warn", "The disk is filling up", `disk pressure is ${pressure}`);
    if (!listed && st.peer_count === 0) add("no-peers", "warn", "The node has no peers", "it cannot follow the network alone");
  }
  if (syncing) add("syncing", "info", "The node is catching up with the network", "it is behind the tip");
  if (!listed && progress && !syncing && snap.finalized.state === "ok" && now - progress.since > staleAfter) {
    add("finality-stalled", "page", "Finality has stopped advancing", `finalized height has been ${progress.finalized} for ${ageText(now - progress.since).replace(" ago", "")}`);
  }
  return out;
}

/** Everything found in `snap`: the node's conditions when it serves them, and the console's rules for the rest. */
export function findings(snap: Snapshot, state: AlertState, now: number, staleAfter: number): Finding[] {
  const listed = snap.conditions.state === "ok" && snap.conditions.value !== null ? snap.conditions.value : null;
  const own = ownFindings(snap, state.progress, now, staleAfter, listed !== null);
  return listed ? [...own, ...findingsFromConditions(listed)] : own;
}

/** Whether the alerts come from the node's conditions list or from the console's own rules. */
export function alertSource(snap: Snapshot): "conditions" | "rules" | "unknown" {
  if (snap.conditions.state === "pending") return "unknown";
  return snap.conditions.state === "ok" && snap.conditions.value !== null ? "conditions" : "rules";
}

function advance(progress: AlertState["progress"], snap: Snapshot, now: number): AlertState["progress"] {
  if (snap.finalized.state !== "ok") return progress;
  const finalized = snap.finalized.value;
  return progress && progress.finalized === finalized ? progress : { finalized, since: now };
}

/** Feed one snapshot's findings through the engine. */
export function step(state: AlertState, snap: Snapshot, now: number, staleAfter: number): { state: AlertState; events: AlertEvent[] } {
  const progress = advance(state.progress, snap, now);
  const found = findings(snap, { ...state, progress }, now, staleAfter);
  const events: AlertEvent[] = [];
  const tracks: Record<string, Track> = {};
  const event = (what: AlertEvent["what"], f: Finding) => events.push({ at: now, what, key: f.key, level: f.level, title: f.title });
  for (const f of found) {
    const prior = state.tracks[f.key];
    const present = (prior?.present ?? 0) + 1;
    const raised = (prior?.raised ?? false) || present >= RAISE_AFTER;
    if (raised && !prior?.raised) event("raised", f);
    // An acknowledgement covers the level it was given at, not a worse one.
    const ack = prior?.ack && ORDER[f.level] >= ORDER[prior.finding.level] ? prior.ack : null;
    tracks[f.key] = { finding: f, since: prior?.since ?? now, present, absent: 0, raised, ack };
  }
  for (const [key, prior] of Object.entries(state.tracks)) {
    if (tracks[key] || !prior.raised) continue;
    const absent = prior.absent + 1;
    if (absent >= CLEAR_AFTER) event("cleared", prior.finding);
    else tracks[key] = { ...prior, present: 0, absent };
  }
  return { state: { tracks, progress }, events };
}

/** Acknowledge an open alert with a reason; the error text when it cannot be. */
export function acknowledge(state: AlertState, key: string, reason: string, now: number): { state: AlertState; event: AlertEvent } | string {
  const track = state.tracks[key];
  if (!track || !track.raised) return "That alert is no longer open.";
  const why = reason.trim();
  if (why === "") return "An acknowledgement needs a reason: say why this is known and accepted.";
  const ack = { reason: redact(why), at: now };
  return {
    state: { ...state, tracks: { ...state.tracks, [key]: { ...track, ack } } },
    event: { at: now, what: "acknowledged", key, level: track.finding.level, title: track.finding.title },
  };
}

/**
 * `state` with the acknowledgements other consoles shared taken onto the open
 * alerts nobody here has acknowledged. One counts only for the alert as it
 * stands now: given since the alert was raised, at its level or a worse one.
 */
export function adopt(state: AlertState, shared: SharedAcks): AlertState {
  let tracks = state.tracks;
  for (const [key, track] of Object.entries(state.tracks)) {
    const s = shared[key];
    if (!s || !track.raised || track.ack || s.at < track.since || ORDER[track.finding.level] < ORDER[s.level]) continue;
    tracks = { ...tracks, [key]: { ...track, ack: { reason: redact(s.reason), at: s.at } } };
  }
  return tracks === state.tracks ? state : { ...state, tracks };
}

const BLIND = "console-blind";

/**
 * The open alerts, worst first then oldest first. When nothing fresh has
 * arrived for `staleAfter` the console cannot vouch for any of it and says so
 * with an alert of its own, which needs no snapshot to appear.
 */
export function openAlerts(state: AlertState, lastAnswerAt: number, now: number, staleAfter: number): Alert[] {
  const out: Alert[] = Object.values(state.tracks)
    .filter((t) => t.raised)
    .map((t) => ({ ...t.finding, since: t.since, ack: t.ack }));
  if (now - lastAnswerAt > staleAfter) {
    out.push({
      key: BLIND,
      level: "page",
      title: redact("The console has no fresh answer from the node"),
      detail: redact(`nothing new for ${ageText(now - lastAnswerAt).replace(" ago", "")}; what is shown may no longer be true`),
      since: lastAnswerAt + staleAfter,
      ack: null,
    });
  }
  return out.sort((a, b) => ORDER[a.level] - ORDER[b.level] || a.since - b.since || a.key.localeCompare(b.key));
}

/** The worst level among alerts nobody has acknowledged, or null when there is none. */
export function worstUnacknowledged(alerts: Alert[]): Level | null {
  const open = alerts.filter((a) => !a.ack);
  return open.length === 0 ? null : open.reduce<Level>((w, a) => (ORDER[a.level] < ORDER[w] ? a.level : w), "info");
}

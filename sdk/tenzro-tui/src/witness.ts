// Before a planned stop the console asks a few other operators how the
// network looks from where they stand, because a node is the worst judge of
// its own surroundings. It asks only endpoints the chain's operator list
// names, makes only the open reads any client makes (nothing in them says a
// stop is being considered), and holds each answer to a size and a time.

import type { Snapshot } from "./data.js";
import { redact, type Shown } from "./redact.js";
import type { StopCheck } from "./stop.js";

/** One operator of the `rpc` role as the chain lists it. */
export interface ListedEndpoint {
  account: string;
  url: string;
}

/** Other operators asked for one stop. */
export const MAX_WITNESSES = 3;
/** Time one operator has to answer one read, ms. */
export const WITNESS_TIMEOUT_MS = 3000;
/** Largest answer read from an operator, bytes. */
export const WITNESS_MAX_BYTES = 4096;
/** How far apart two nodes' finalized heights may be and still be at the same tip. */
export const TIP_TOLERANCE = 50;

/** One JSON-RPC read against another operator's endpoint. */
export type Ask = (url: string, method: string) => Promise<unknown>;

export interface Witness {
  url: Shown;
  answered: boolean;
  agrees: boolean;
  says: Shown;
}

/** The endpoints to ask: listed on chain, plain http(s) URLs without credentials, not this node's own account. */
export function chooseWitnesses(listed: ListedEndpoint[], ownAccount: string | null): string[] {
  const own = ownAccount?.toLowerCase() ?? null;
  const seen = new Set<string>();
  const out: string[] = [];
  for (const e of [...listed].sort((a, b) => a.account.localeCompare(b.account))) {
    if (own !== null && e.account.toLowerCase() === own) continue;
    let u: URL;
    try {
      u = new URL(e.url);
    } catch {
      continue;
    }
    if ((u.protocol !== "https:" && u.protocol !== "http:") || u.username || u.password) continue;
    if (seen.has(u.origin)) continue;
    seen.add(u.origin);
    out.push(u.toString());
    if (out.length === MAX_WITNESSES) break;
  }
  return out;
}

/** A count or height as the node answers it: a number, or a hex or decimal string. */
function asCount(v: unknown): number | null {
  const n = typeof v === "number" ? v : typeof v === "string" && v !== "" ? Number(v) : NaN;
  return Number.isInteger(n) && n >= 0 ? n : null;
}

/** Ask one operator; a failure of any read is "did not answer". */
async function askOne(url: string, ownFinalized: number, ask: Ask): Promise<Witness> {
  const shown = redact(url);
  try {
    const [syncing, peers, finalized] = await Promise.all([ask(url, "eth_syncing"), ask(url, "net_peerCount"), ask(url, "tenzro_getFinalizedBlock")]);
    const height = asCount(finalized);
    const peerCount = asCount(peers);
    if (height === null || peerCount === null) return { url: shown, answered: false, agrees: false, says: redact("answered with something that could not be read") };
    const behind = syncing !== false;
    const apart = Math.abs(height - ownFinalized);
    const agrees = !behind && peerCount > 0 && apart <= TIP_TOLERANCE;
    const says = behind ? "is itself catching up" : peerCount === 0 ? "has no peers" : apart > TIP_TOLERANCE ? `has finalized height ${height}, ${apart} away from this node's ${ownFinalized}` : `is at the same tip (finalized ${height}) with ${peerCount} peers`;
    return { url: shown, answered: true, agrees, says: redact(says) };
  } catch {
    return { url: shown, answered: false, agrees: false, says: redact("did not answer in time") };
  }
}

/**
 * The stop check the other operators give: passes when a majority of those
 * that answered see a healthy network at the same tip as this node. With
 * nobody else on the list there is nothing to compare and it passes; when
 * operators are listed and none answers it fails, because then this node's
 * own view is all there is.
 */
export async function witnessCheck(listed: ListedEndpoint[], snap: Snapshot, ask: Ask): Promise<{ check: StopCheck; witnesses: Witness[] }> {
  const own = snap.status.state === "ok" ? snap.status.value.payee : null;
  const urls = chooseWitnesses(listed, own ?? null);
  if (urls.length === 0) {
    return { check: { id: "peers", ok: true, text: "No other operator is listed on chain, so there is nobody to ask." }, witnesses: [] };
  }
  if (snap.finalized.state !== "ok") {
    return { check: { id: "peers", ok: false, text: "This node's finalized height could not be read, so other operators' answers cannot be compared." }, witnesses: [] };
  }
  const witnesses = await Promise.all(urls.map((u) => askOne(u, snap.finalized.state === "ok" ? snap.finalized.value : 0, ask)));
  const answered = witnesses.filter((w) => w.answered);
  const agree = answered.filter((w) => w.agrees).length;
  const ok = answered.length > 0 && agree * 2 > answered.length;
  const text =
    answered.length === 0
      ? `None of the ${urls.length} other operators asked answered; this node's own view is all there is.`
      : `${agree} of the ${answered.length} other operators that answered (${urls.length} asked) see a healthy network at this node's tip.`;
  return { check: { id: "peers", ok, text }, witnesses };
}

/** An `Ask` over fetch: one POST, no redirects followed, a time limit, and at most `WITNESS_MAX_BYTES` read. */
export const fetchAsk: Ask = async (url, method) => {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), WITNESS_TIMEOUT_MS);
  try {
    const res = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ jsonrpc: "2.0", id: 1, method, params: [] }),
      redirect: "error",
      signal: controller.signal,
    });
    if (!res.ok || !res.body) throw new Error("no answer");
    const reader = res.body.getReader();
    const chunks: Uint8Array[] = [];
    let size = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > WITNESS_MAX_BYTES) {
        controller.abort();
        throw new Error("answer too large");
      }
      chunks.push(value);
    }
    const msg = JSON.parse(Buffer.concat(chunks).toString("utf8")) as { result?: unknown; error?: unknown };
    if (msg.error !== undefined || msg.result === undefined) throw new Error("refused");
    return msg.result;
  } finally {
    clearTimeout(timer);
  }
};

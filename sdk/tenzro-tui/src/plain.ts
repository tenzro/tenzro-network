import type { Reading, Snapshot } from "./data.js";
import { headline } from "./data.js";
import { formatDuration, formatTnzo } from "./format.js";

function val<T>(r: Reading<T>): T | null {
  return r.state === "ok" ? r.value : r.state === "error" && r.last ? r.last.value : null;
}

function why<T>(r: Reading<T>): string {
  return r.state === "ok" ? "" : " (no data)";
}

/** The same answers as the screens, as plain lines: for pipes, scripts and screen readers. */
export function plainReport(url: string, s: Snapshot): string {
  const h = headline(s);
  const st = val(s.status);
  const lines: string[] = [];
  lines.push(`Tenzro node ${url}`);
  lines.push(`Status: ${h.word} - ${h.reason}`);
  if (st) {
    lines.push(`State: ${st.state}, ${st.health_status}`);
    lines.push(`Uptime: ${formatDuration(st.uptime_secs)}`);
    lines.push(`Height: ${st.block_height}`);
    lines.push(`Peers: ${st.peer_count}`);
    lines.push(`Roles: ${Array.isArray(st.roles) ? st.roles.join(", ") : String(st.roles)}`);
    if (st.payee) lines.push(`Pays out to: ${st.payee}`);
  }
  const ver = val(s.health);
  if (ver) lines.push(`Version: ${ver.version}`);
  const cid = val(s.chainId);
  if (cid !== null) lines.push(`Chain id: ${cid}`);
  const fin = val(s.finalized);
  if (fin !== null) lines.push(`Finalized: ${fin}`);
  const sync = val(s.syncing);
  if (sync !== null) lines.push(`Syncing: ${sync ? "yes" : "no"}`);
  const m = val(s.models);
  lines.push(`Models: ${m ? m.length : 0}${why(s.models)}`);
  for (const x of m ?? []) lines.push(`  ${x.model_id}  ${x.type}  ${x.visibility}  loaded=${x.loaded ? "yes" : "no"}  serving=${x.serving ? "yes" : "no"}`);
  const v = val(s.validators);
  lines.push(`Validators: ${v ? v.length : 0}${why(s.validators)}`);
  for (const x of v ?? []) lines.push(`  ${x.address}  ${x.status}  self stake ${formatTnzo(x.self_stake, 2)} TNZO`);
  const p = val(s.proposals);
  lines.push(`Proposals: ${p ? p.total : 0}${why(s.proposals)}`);
  const b = val(s.balance);
  if (b) lines.push(`Balance of ${b.address}: ${formatTnzo(b.wei)} TNZO`);
  return lines.join("\n") + "\n";
}

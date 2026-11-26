// Acknowledgements kept in one file that every console watching a node can
// name (`--shared <file>`), so an alert one operator has acknowledged shows as
// acknowledged, with the same reason, in every other console that names the
// file. The file holds nothing but acknowledgements. It is read whole on
// every refresh and rewritten whole by a rename, so a reader never sees half
// of a write. Anything malformed or oversized in it reads as no
// acknowledgements at all, and a reason read from it is redacted again before
// it is drawn.

import fs from "node:fs";
import path from "node:path";
import { isLevel, type Level } from "./alerts.js";

/** One acknowledgement as the file keeps it. */
export interface SharedAck {
  /** The level the alert had when it was acknowledged. */
  level: Level;
  reason: string;
  at: number;
}

/** Acknowledgements by alert key. */
export type SharedAcks = Record<string, SharedAck>;

/** Largest file read, bytes. */
export const MAX_SHARED_BYTES = 64 * 1024;
const MAX_KEY = 128;
const MAX_REASON = 500;

function wellFormed(key: string, v: unknown): v is SharedAck {
  if (key.length === 0 || key.length > MAX_KEY || typeof v !== "object" || v === null) return false;
  const a = v as Record<string, unknown>;
  return isLevel(a.level) && typeof a.reason === "string" && a.reason.length <= MAX_REASON && typeof a.at === "number" && Number.isFinite(a.at);
}

/** The acknowledgements in `file`; none when it is missing, too large or malformed. */
export function readShared(file: string): SharedAcks {
  let text: string;
  try {
    if (fs.statSync(file).size > MAX_SHARED_BYTES) return {};
    text = fs.readFileSync(file, "utf8");
  } catch {
    return {};
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return {};
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) return {};
  const out: SharedAcks = {};
  for (const [key, v] of Object.entries(parsed)) if (wellFormed(key, v)) out[key] = { level: v.level, reason: v.reason, at: v.at };
  return out;
}

/** Records `ack` for `key` in `file`, keeping every other acknowledgement; the error text when it cannot. */
export function writeShared(file: string, key: string, ack: SharedAck): string | null {
  if (!wellFormed(key, ack)) return "That acknowledgement cannot be shared: its reason is too long.";
  const next = { ...readShared(file), [key]: ack };
  const tmp = path.join(path.dirname(file), `.${path.basename(file)}.${process.pid}.tmp`);
  try {
    fs.writeFileSync(tmp, JSON.stringify(next), { mode: 0o600 });
    fs.renameSync(tmp, file);
    return null;
  } catch (e) {
    fs.rmSync(tmp, { force: true });
    return `The acknowledgement could not be shared: ${(e as NodeJS.ErrnoException).code ?? "write failed"}.`;
  }
}

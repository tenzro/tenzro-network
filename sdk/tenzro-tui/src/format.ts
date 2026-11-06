const WEI = 10n ** 18n;

/** Whole-token display of a wei amount, up to `places` decimals, grouped by thousands. */
export function formatTnzo(wei: bigint | string, places = 4): string {
  const v = typeof wei === "bigint" ? wei : BigInt(wei);
  const neg = v < 0n;
  const a = neg ? -v : v;
  const whole = a / WEI;
  let frac = (a % WEI).toString().padStart(18, "0").slice(0, places).replace(/0+$/, "");
  const w = whole.toString().replace(/\B(?=(\d{3})+(?!\d))/g, ",");
  return `${neg ? "-" : ""}${w}${frac ? "." + frac : ""}`;
}

export function shortId(id: string, head = 8, tail = 6): string {
  if (id.length <= head + tail + 1) return id;
  return `${id.slice(0, head)}...${id.slice(-tail)}`;
}

export function formatDuration(secs: number): string {
  if (!Number.isFinite(secs) || secs < 0) return "unknown";
  const d = Math.floor(secs / 86400);
  const h = Math.floor((secs % 86400) / 3600);
  const m = Math.floor((secs % 3600) / 60);
  const s = Math.floor(secs % 60);
  if (d > 0) return `${d}d ${h}h`;
  if (h > 0) return `${h}h ${m}m`;
  if (m > 0) return `${m}m ${s}s`;
  return `${s}s`;
}

export function ageText(ms: number): string {
  if (ms < 1500) return "now";
  return `${formatDuration(Math.round(ms / 1000))} ago`;
}

/** Pad or cut to exactly `n` cells (ASCII output only; the console prints no wide glyphs). */
export function fit(s: string, n: number): string {
  if (n <= 0) return "";
  if (s.length > n) return n > 3 ? s.slice(0, n - 3) + "..." : s.slice(0, n);
  return s.padEnd(n);
}

/** A 20-byte (40 hex) or 32-byte (64 hex) account, with the 0x prefix. */
export function isAddress(s: string): boolean {
  return /^0x([0-9a-fA-F]{40}|[0-9a-fA-F]{64})$/.test(s.trim());
}

/** Turn a transport failure into one plain sentence that says what to do. */
export function plainError(e: unknown, url: string): string {
  const raw = e instanceof Error ? `${e.message} ${(e as { cause?: { code?: string; message?: string } }).cause?.code ?? ""} ${(e as { cause?: { message?: string } }).cause?.message ?? ""}` : String(e);
  if (/ECONNREFUSED|fetch failed|ENOTFOUND|EHOSTUNREACH|ECONNRESET/i.test(raw)) {
    return `Cannot reach a node at ${url}. Start one, or pass --rpc <url>.`;
  }
  if (/abort|timeout|timed out/i.test(raw)) return `The node at ${url} did not answer in time.`;
  if (/401|403|unauthor|forbidden|access/i.test(raw)) return "The node refused this request (access required).";
  return raw.replace(/\s+/g, " ").trim().slice(0, 160);
}

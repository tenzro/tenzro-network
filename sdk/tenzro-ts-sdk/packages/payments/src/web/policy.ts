/**
 * A publisher's policy: which paths are paid, at what USD price, in which
 * assets and schemes, and under which licence and content-usage terms. The
 * same policy renders the machine-readable licence (RSL), the robots.txt
 * `License:` line and each response's `Content-Usage` (AIPREF) header.
 */

/** One paid path. */
export interface PaidRoute {
  /** An exact path, or a prefix ending in `*` (`/articles/*`). */
  path: string;
  /** Price per request in USD micro-units (1 USD = 1_000_000). */
  usdE6: number;
  /** Accepted schemes, most preferred first. Default: a channel voucher, then a signed payment. */
  schemes?: string[];
  /** The asset paid. Default `TNZO`, priced at the consensus rate. */
  asset?: string;
  /** A fixed amount in the asset's smallest unit, instead of quoting `usdE6`. */
  amount?: string;
  /** Uses the licence permits for this path (RSL usage tokens, e.g. `ai-input`, `search`). */
  permits?: string[];
  /** Uses it prohibits (e.g. `ai-train`). */
  prohibits?: string[];
  /** What a payment licenses (RSL payment type). Default `use`. */
  licenceType?: "use" | "crawl" | "training" | "purchase";
  /** The `Content-Usage` header value served with the path. */
  contentUsage?: string;
  /** Shown to payers with the requirement. */
  description?: string;
}

/** A publisher's whole policy. */
export interface PublisherPolicy {
  /** The Tenzro chain payments settle on. */
  chainId: number;
  /** The Tenzro account paid (hex). Payouts reach whatever the account's passkey controls. */
  payTo: string;
  /** Base URL of the x402 facilitator that verifies and settles. */
  facilitator: string;
  /** Paid paths. Unlisted paths are free. */
  routes: PaidRoute[];
  /** Charge requests that carry no agent signature too. Default false: people browse free. */
  chargeUnsigned?: boolean;
  /** Seconds a payer has to answer a requirement. Default 300. */
  maxTimeoutSeconds?: number;
}

/** The default scheme order: a voucher on a channel, then a signed one-off payment. */
export const DEFAULT_SCHEMES = ["batch-settlement", "tenzro-hybrid"];

/** The route `pathname` falls under: an exact path wins, then the longest prefix. */
export function matchRoute(routes: PaidRoute[], pathname: string): PaidRoute | undefined {
  const exact = routes.find((r) => !r.path.endsWith("*") && r.path === pathname);
  if (exact) return exact;
  return routes
    .filter((r) => r.path.endsWith("*") && pathname.startsWith(r.path.slice(0, -1)))
    .sort((a, b) => b.path.length - a.path.length)[0];
}

const xml = (s: string): string =>
  s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");

const usd = (usdE6: number): string => {
  const whole = Math.floor(usdE6 / 1_000_000);
  const frac = String(usdE6 % 1_000_000).padStart(6, "0").replace(/0+$/, "");
  return frac ? `${whole}.${frac}` : String(whole);
};

/** The policy as an RSL licence document, its content URLs on `origin`. */
export function rslXml(policy: PublisherPolicy, origin: string): string {
  const base = origin.replace(/\/$/, "");
  const lines = ['<?xml version="1.0" encoding="UTF-8"?>', '<rsl xmlns="https://rslstandard.org/rsl">'];
  for (const r of policy.routes) {
    lines.push(`  <content url="${xml(base + r.path)}">`, "    <license>");
    if (r.permits?.length) lines.push(`      <permits type="usage">${xml(r.permits.join(" "))}</permits>`);
    if (r.prohibits?.length) lines.push(`      <prohibits type="usage">${xml(r.prohibits.join(" "))}</prohibits>`);
    lines.push(
      `      <payment type="${r.licenceType ?? "use"}">`,
      `        <amount currency="USD">${usd(r.usdE6)}</amount>`,
      "      </payment>",
      "    </license>",
      "  </content>",
    );
  }
  lines.push("</rsl>");
  return lines.join("\n") + "\n";
}

/** The robots.txt line pointing crawlers at the licence. */
export function robotsLicenseLine(origin: string, licencePath = "/license.xml"): string {
  return `License: ${origin.replace(/\/$/, "")}${licencePath}`;
}

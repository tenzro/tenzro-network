/**
 * The publisher gate: answers a paid path with 402 and the requirements,
 * and serves it only after a facilitator has settled the payment. The
 * handler never runs for an unpaid request, so nothing it does can be had
 * for free. Framework-neutral: it takes a fetch `Request` and a handler
 * returning a `Response`.
 */
import { DEFAULT_SCHEMES, matchRoute, type PaidRoute, type PublisherPolicy } from "./policy";
import {
  PAYMENT_REQUIRED_HEADER,
  PAYMENT_RESPONSE_HEADER,
  PAYMENT_SIGNATURE_HEADER,
  X402_VERSION,
  challengeIdOf,
  decodeHeaderText,
  encodeHeaderText,
  tenzroNetwork,
  type PaymentRequired,
  type PaymentRequirement,
  type SettlementResponse,
} from "./x402";

/** Prices a USD amount in TNZO base units at the consensus rate (`tenzro_quotePayment`). */
export type Quote = (usdE6: number) => Promise<string>;

export interface GateOptions {
  policy: PublisherPolicy;
  /** Required for routes priced in USD without a fixed amount. */
  quote?: Quote;
  /** Seconds a quote is reused. Default 60. */
  quoteTtlSeconds?: number;
  /** The transport to the facilitator. Default the global fetch. */
  fetch?: typeof fetch;
}

interface Priced {
  amount: bigint;
  at: number;
}

/** Whether a request carries an agent's HTTP message signature. */
export function isSignedRequest(headers: Headers): boolean {
  return headers.has("signature-input") && headers.has("signature");
}

export class PublisherGate {
  private readonly prices = new Map<string, Priced[]>();
  private readonly send: typeof fetch;

  constructor(private readonly opts: GateOptions) {
    this.send = opts.fetch ?? fetch;
  }

  /** Serve `request` through `handler` once it is paid, or answer 402. */
  async handle(request: Request, handler: (r: Request) => Promise<Response>): Promise<Response> {
    const { policy } = this.opts;
    const url = new URL(request.url);
    const route = matchRoute(policy.routes, url.pathname);
    if (!route) return handler(request);
    const header = request.headers.get(PAYMENT_SIGNATURE_HEADER);
    if (!header && !policy.chargeUnsigned && !isSignedRequest(request.headers)) {
      return this.usage(await handler(request), route);
    }
    if (!header) return this.required(url, route);

    let text: string;
    let accepted: PaymentRequirement;
    try {
      text = decodeHeaderText(header);
      accepted = JSON.parse(text).accepted;
    } catch {
      return this.required(url, route, "invalid_payload");
    }
    if (!(await this.offers(route, accepted))) return this.required(url, route, "requirement_not_offered");

    // Settle before the handler runs; the payload is forwarded as sent.
    const body = `{"x402Version":${X402_VERSION},"paymentPayload":${text},"paymentRequirements":${JSON.stringify(accepted)}}`;
    let settled: SettlementResponse;
    try {
      const res = await this.send(`${policy.facilitator.replace(/\/$/, "")}/settle`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body,
      });
      settled = (await res.json()) as SettlementResponse;
    } catch {
      return this.required(url, route, "facilitator_unreachable");
    }
    if (!settled.success) return this.required(url, route, settled.errorReason ?? "settlement_failed");

    const served = this.usage(await handler(request), route);
    const headers = new Headers(served.headers);
    headers.set(PAYMENT_RESPONSE_HEADER, encodeHeaderText(JSON.stringify(settled)));
    return new Response(served.body, { status: served.status, statusText: served.statusText, headers });
  }

  /** The requirements `route` offers now, one per accepted scheme. */
  async requirements(route: PaidRoute): Promise<PaymentRequirement[]> {
    const { policy } = this.opts;
    const amount = (await this.price(route)).toString();
    const challengeId = globalThis.crypto.randomUUID();
    return (route.schemes ?? DEFAULT_SCHEMES).map((scheme) => ({
      scheme,
      network: tenzroNetwork(policy.chainId),
      amount,
      asset: route.asset ?? "TNZO",
      payTo: policy.payTo,
      maxTimeoutSeconds: policy.maxTimeoutSeconds ?? 300,
      extra: { challengeId, chain_id: policy.chainId, usd_e6: route.usdE6 },
    }));
  }

  private async required(url: URL, route: PaidRoute, error?: string): Promise<Response> {
    let accepts: PaymentRequirement[];
    try {
      accepts = await this.requirements(route);
    } catch {
      return new Response("payment required, but no price is available", { status: 503 });
    }
    const required: PaymentRequired = {
      x402Version: X402_VERSION,
      ...(error ? { error } : {}),
      resource: { url: url.toString(), ...(route.description ? { description: route.description } : {}) },
      accepts,
    };
    const json = JSON.stringify(required);
    return this.usage(
      new Response(json, {
        status: 402,
        headers: { "content-type": "application/json", [PAYMENT_REQUIRED_HEADER]: encodeHeaderText(json) },
      }),
      route,
    );
  }

  /** Whether `r` is what `route` offers: scheme, network, payee and asset, at no less than a price quoted recently. */
  private async offers(route: PaidRoute, r: PaymentRequirement | undefined): Promise<boolean> {
    const { policy } = this.opts;
    if (!r || !challengeIdOf(r)) return false;
    if (!(route.schemes ?? DEFAULT_SCHEMES).some((s) => s.toLowerCase() === String(r.scheme).toLowerCase())) return false;
    if (r.network !== tenzroNetwork(policy.chainId)) return false;
    if (String(r.payTo).replace(/^0x/, "").toLowerCase() !== policy.payTo.replace(/^0x/, "").toLowerCase()) return false;
    if (String(r.asset).toLowerCase() !== (route.asset ?? "TNZO").toLowerCase()) return false;
    let paid: bigint;
    try {
      paid = BigInt(r.amount);
    } catch {
      return false;
    }
    const current = await this.price(route);
    if (route.amount) return paid >= current;
    const recent = this.prices.get(route.path) ?? [];
    return recent.some((p) => paid >= p.amount);
  }

  /** The route's current price, quoted at most once per TTL; the last two quotes stay acceptable. */
  private async price(route: PaidRoute): Promise<bigint> {
    if (route.amount) return BigInt(route.amount);
    const ttl = (this.opts.quoteTtlSeconds ?? 60) * 1000;
    const now = Date.now();
    const seen = this.prices.get(route.path) ?? [];
    const fresh = seen.find((p) => now - p.at < ttl);
    if (fresh) return fresh.amount;
    if (!this.opts.quote) throw new Error(`route ${route.path} is priced in USD and the gate has no quote`);
    const amount = BigInt(await this.opts.quote(route.usdE6));
    this.prices.set(route.path, [{ amount, at: now }, ...seen].slice(0, 2));
    return amount;
  }

  private usage(res: Response, route: PaidRoute): Response {
    if (!route.contentUsage) return res;
    const headers = new Headers(res.headers);
    headers.set("Content-Usage", route.contentUsage);
    return new Response(res.body, { status: res.status, statusText: res.statusText, headers });
  }
}

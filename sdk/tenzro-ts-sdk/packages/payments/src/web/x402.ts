/**
 * The x402 wire as Tenzro serves it: base64 JSON headers on a 402 and on the
 * paid retry, and the bodies a facilitator takes. Amounts that may exceed
 * 2^53 stay exact: a payload is forwarded as the text the payer sent, and
 * credentials are written with integer literals from bigints.
 */

/** Header carrying the requirements on a 402. */
export const PAYMENT_REQUIRED_HEADER = "PAYMENT-REQUIRED";
/** Header carrying the payer's payload on the retried request. */
export const PAYMENT_SIGNATURE_HEADER = "PAYMENT-SIGNATURE";
/** Header carrying the settlement on a paid response. */
export const PAYMENT_RESPONSE_HEADER = "PAYMENT-RESPONSE";
/** The protocol version every Tenzro facilitator speaks. */
export const X402_VERSION = 2;

/** One way to pay, as a resource server offers it. */
export interface PaymentRequirement {
  scheme: string;
  network: string;
  amount: string;
  asset: string;
  payTo: string;
  maxTimeoutSeconds: number;
  extra?: Record<string, unknown>;
}

/** The resource a requirement set is for. */
export interface ResourceInfo {
  url: string;
  description?: string;
  mimeType?: string;
}

/** The body of `PAYMENT-REQUIRED`. */
export interface PaymentRequired {
  x402Version: number;
  error?: string;
  resource: ResourceInfo;
  accepts: PaymentRequirement[];
}

/** A settlement as a facilitator reports it, and as `PAYMENT-RESPONSE` carries it. */
export interface SettlementResponse {
  success: boolean;
  errorReason?: string;
  payer?: string;
  transaction: string;
  network: string;
  amount?: string;
}

/** Base64 (standard, padded) of `text`. */
export function encodeHeaderText(text: string): string {
  const bytes = new TextEncoder().encode(text);
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary);
}

/** The JSON text a base64 header carries. */
export function decodeHeaderText(value: string): string {
  const binary = atob(value.trim());
  return new TextDecoder().decode(Uint8Array.from(binary, (c) => c.charCodeAt(0)));
}

export { stringifyExact } from "@tenzro/core";

/** The challenge id a requirement names. */
export function challengeIdOf(r: PaymentRequirement): string | undefined {
  const id = r.extra?.["challengeId"];
  return typeof id === "string" ? id : undefined;
}

/** The Tenzro network name of chain `chainId`. */
export const tenzroNetwork = (chainId: number | bigint): string => `tenzro:${chainId}`;

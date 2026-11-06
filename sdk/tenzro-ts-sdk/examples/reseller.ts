/**
 * A reseller app over the public payment surface: it sells an operator's
 * model to its own customers at the operator's price plus its commission.
 *
 * Buyer side: quote the call with the reseller's commission declared, check
 * the commission against the buyer's own cap before signing, pay, and verify
 * the receipt shows the operator's leg and the reseller's leg apart.
 * Reseller side: serve a call only once a payment on chain carries the
 * reseller's own leg for exactly that request.
 *
 * Nothing here is privileged: any registered identity resells on the same
 * terms, the buyer can always pay the operator directly at its own price,
 * and the chain refuses a commission past a delegated agent's Terms cap
 * (`max_commission_bps`) whatever an app does.
 *
 * Run with: `npx tsx examples/reseller.ts`
 *   TENZRO_RPC_URL, TENZRO_RPC_URL_2   two nodes; receipts are checked on both
 *   OPERATOR                           the operator's account (0x + 64 hex)
 *   RESELLER                           the reseller's account (0x + 64 hex)
 *   COMMISSION_BPS                     the reseller's commission, bps (default 1000)
 *   BUYER_MAX_COMMISSION_BPS           the buyer's own cap, bps (default 1500)
 *   ACCEPT                             assets the buyer pays in, comma separated (default TNZO)
 */

import {
  HardwareKeySigner,
  LedgerPayments,
  MemoryChargeStore,
  PaymentError,
  RpcClient,
  openHardwareSigner,
} from "../src/index";
import type { LedgerQuote, ResellerCommission } from "../src/index";

const REQUEST = "https://reseller.example/v1/chat?model=operator-model";
const PRICE = { amount: "0.25", unit: "USD" as const };

function need(name: string): string {
  const v = process.env[name];
  if (!v) throw new Error(`set ${name}`);
  return v;
}

/** The buyer refuses, before signing, a quote whose commissions pass its own cap. */
function withinBuyerCap(q: LedgerQuote, capBps: number): void {
  const total = q.chosen.legs.reduce((sum, l) => sum + l.commission_bps, 0);
  if (total > capBps) {
    throw new Error(`the quote carries ${total} bps of commission; this buyer pays at most ${capBps}`);
  }
}

async function main(): Promise<void> {
  const nodes = [new RpcClient(need("TENZRO_RPC_URL")), new RpcClient(need("TENZRO_RPC_URL_2"))];
  const pay = new LedgerPayments(nodes);
  const operator = need("OPERATOR");
  const reseller: ResellerCommission = {
    reseller: need("RESELLER"),
    commission_bps: Number(process.env.COMMISSION_BPS ?? 1_000),
  };
  const accept = (process.env.ACCEPT ?? "TNZO").split(",");

  // Buyer: the quote discloses the operator's price and the commission apart.
  const q = await pay.quote({ payee: operator, price: PRICE, request: REQUEST, accept, resellers: [reseller] });
  console.log(
    `in ${q.chosen.asset}: operator ${q.chosen.operator_amount}, commission ${q.chosen.legs[0]?.amount}, total ${q.chosen.amount}, fees ${q.chosen.fee}`,
  );
  withinBuyerCap(q, Number(process.env.BUYER_MAX_COMMISSION_BPS ?? 1_500));

  const signer = openHardwareSigner({ label: "tenzro/wallet" });
  if (!(signer instanceof HardwareKeySigner)) throw new Error("no TPM or Secure Enclave on this machine");
  const paid = await pay.pay(q, { signer, idempotencyKey: `reseller-demo-${Date.now()}` });
  const receipt = await pay.verifyReceipt(paid);
  for (const leg of receipt.record.legs as { role: string; account: string; amount: string; fee: string }[]) {
    console.log(`${leg.role} ${leg.account}: ${leg.amount} (fee ${leg.fee})`);
  }

  // Reseller: serve the call only for a payment carrying its own leg, once.
  const serve = pay.charge(async (req) => `served ${req.request}`, {
    payee: operator,
    price: PRICE,
    accept,
    reseller,
    store: new MemoryChargeStore(),
  });
  console.log(await serve({ request: REQUEST, paymentId: paid.paymentId }));
  const again = await serve({ request: REQUEST, paymentId: paid.paymentId });
  console.log(`presented again: ${"status" in (again as object) ? JSON.stringify(again) : again}`);
}

main().catch((e) => {
  console.error(e instanceof PaymentError ? `${e.code}: ${e.message}` : e);
  process.exit(1);
});

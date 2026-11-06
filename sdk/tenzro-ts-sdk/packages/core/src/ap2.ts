/**
 * AP2 v0.2 open Payment Mandate constraints, checked the way the node checks
 * them before it holds the payment to the paying agent's Terms. An agent uses
 * this to know, before it presents a mandate, whether a payment is one the
 * mandate allows. Every constraint is checked or refused; none is skipped.
 */

/** The payment a mandate is checked against. */
export interface MandatePayment {
  /** The payee DID. */
  payee: string;
  /** Minor units of `currency`. */
  amount: bigint;
  currency: string;
}

/** Why a mandate does not allow a payment. */
export class MandateRefusal extends Error {
  constructor(message: string) {
    super(message);
    this.name = "MandateRefusal";
  }
}

function amountOf(v: unknown): bigint | undefined {
  if (typeof v === "number" && Number.isSafeInteger(v) && v >= 0) return BigInt(v);
  if (typeof v === "string" && /^[0-9]+$/.test(v)) return BigInt(v);
  return undefined;
}

function sameJson(a: unknown, b: unknown): boolean {
  return JSON.stringify(a) === JSON.stringify(b);
}

/**
 * Checks the open mandate's `constraints` against `payment`, made under the
 * checkout `transactionId` with `instrument`, at `nowSecs`. Throws
 * {@link MandateRefusal} naming the first constraint that refuses.
 * `payment.budget` and `payment.agent_recurrence` are refused: they need a
 * record of earlier payments and are expressed as a period limit in the
 * agent's Terms instead.
 */
export function checkMandateConstraints(
  constraints: unknown,
  payment: MandatePayment,
  transactionId: string,
  instrument: Record<string, unknown> | undefined,
  nowSecs: number,
): void {
  if (!Array.isArray(constraints)) throw new MandateRefusal("constraints is not a list");
  let referenced = false;
  for (const c of constraints as Record<string, unknown>[]) {
    const type = typeof c?.type === "string" ? c.type : "";
    switch (type) {
      case "payment.reference":
        if (c.conditional_transaction_id !== transactionId) {
          throw new MandateRefusal("the open mandate references another checkout");
        }
        referenced = true;
        break;
      case "payment.amount_range": {
        const cur = typeof c.currency === "string" ? c.currency : "";
        if (cur.toLowerCase() !== payment.currency.toLowerCase()) {
          throw new MandateRefusal("the amount range is in another currency");
        }
        const max = amountOf(c.max);
        if (max === undefined) throw new MandateRefusal("amount_range.max");
        const min = amountOf(c.min) ?? 0n;
        if (payment.amount < min || payment.amount > max) {
          throw new MandateRefusal("the amount is outside the mandate's range");
        }
        break;
      }
      case "payment.allowed_payees": {
        const list = Array.isArray(c.allowed) ? (c.allowed as unknown[]) : [];
        const ok = list.some(
          (p) => p === payment.payee || (typeof p === "object" && p !== null && (p as { id?: unknown }).id === payment.payee),
        );
        if (!ok) throw new MandateRefusal("the payee is not one the mandate allows");
        break;
      }
      case "payment.allowed_payment_instruments": {
        const list = Array.isArray(c.allowed) ? (c.allowed as unknown[]) : undefined;
        const ok =
          list !== undefined &&
          instrument !== undefined &&
          list.some(
            (a) =>
              sameJson(a, instrument) ||
              (typeof a === "object" && a !== null && (a as { id?: unknown }).id !== undefined && (a as { id?: unknown }).id === instrument.id) ||
              (typeof a === "string" && a === instrument.type),
          );
        if (!ok) throw new MandateRefusal("the payment instrument is not one the mandate allows");
        break;
      }
      case "payment.allowed_pisps":
        // A payment on this network is initiated by no PISP; the constraint
        // only narrows card and bank initiation.
        break;
      case "payment.execution_date": {
        const at = (k: string): number | undefined => {
          const v = c[k];
          if (typeof v !== "string") return undefined;
          const t = Date.parse(v);
          return Number.isNaN(t) ? undefined : Math.floor(t / 1000);
        };
        const notBefore = at("not_before");
        const notAfter = at("not_after");
        if ((notBefore !== undefined && nowSecs < notBefore) || (notAfter !== undefined && nowSecs > notAfter)) {
          throw new MandateRefusal("the payment is outside the mandate's execution dates");
        }
        break;
      }
      case "payment.budget":
      case "payment.agent_recurrence":
        throw new MandateRefusal(
          `${type} needs a record of earlier payments; express it as a period limit in the agent's Terms`,
        );
      default:
        throw new MandateRefusal(`unknown constraint ${type}`);
    }
  }
  if (!referenced) throw new MandateRefusal("an open Payment Mandate must contain payment.reference");
}

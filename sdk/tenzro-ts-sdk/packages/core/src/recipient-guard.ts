/**
 * Recipient checks before a transfer is signed: first-time recipient friction
 * and look-alike (address poisoning) detection. The same rules as
 * `tenzro_types::recipient_guard`. The byte counts are the governed
 * parameters `wallet.recipient_lookalike_prefix_bytes` and
 * `wallet.recipient_lookalike_suffix_bytes`, read from `tenzro_getNetworkParams`.
 */

export const PREFIX_BYTES_PARAM = "wallet.recipient_lookalike_prefix_bytes";
export const SUFFIX_BYTES_PARAM = "wallet.recipient_lookalike_suffix_bytes";
export const DEFAULT_PREFIX_BYTES = 3;
export const DEFAULT_SUFFIX_BYTES = 3;

export interface LookalikeParams {
  prefixBytes: number;
  suffixBytes: number;
}

export type RecipientFlag =
  | { kind: "first_time_recipient" }
  | { kind: "looks_like"; trusted: string }
  | { kind: "seen_only_as_inbound_sender" };

export interface RecipientAssessment {
  /** The recipient as 64 lowercase hex characters, never shortened. */
  fullAddress: string;
  flags: RecipientFlag[];
  /** Whether the user must type the full address before signing. */
  requiresFullAddressConfirmation: boolean;
  /** Plain-language lines for the confirmation screen. */
  describe: string[];
}

const norm = (a: string): string => a.trim().replace(/^0x/i, "").toLowerCase();

function alike(a: string, b: string, p: LookalikeParams): boolean {
  if (a === b || a.length !== b.length) return false;
  const pre = Math.min(p.prefixBytes * 2, a.length);
  const suf = Math.min(p.suffixBytes * 2, a.length);
  if (pre + suf === 0) return false;
  return a.slice(0, pre) === b.slice(0, pre) && a.slice(a.length - suf) === b.slice(b.length - suf);
}

export function lookalikeParamsFromGoverned(prefix?: number, suffix?: number): LookalikeParams {
  return {
    prefixBytes: prefix ?? DEFAULT_PREFIX_BYTES,
    suffixBytes: suffix ?? DEFAULT_SUFFIX_BYTES,
  };
}

/** Check `recipient` against trusted addresses and ones that only sent to this account. */
export function assessRecipient(
  recipient: string,
  trusted: string[],
  inboundOnly: string[],
  params: LookalikeParams = lookalikeParamsFromGoverned(),
): RecipientAssessment {
  const to = norm(recipient);
  const tr = trusted.map(norm);
  const flags: RecipientFlag[] = [];
  if (!tr.includes(to)) {
    flags.push({ kind: "first_time_recipient" });
    const t = tr.find((x) => alike(to, x, params));
    if (t !== undefined) flags.push({ kind: "looks_like", trusted: t });
    if (inboundOnly.map(norm).includes(to)) flags.push({ kind: "seen_only_as_inbound_sender" });
  }
  const describe = [`Recipient: 0x${to}`];
  for (const f of flags) {
    if (f.kind === "first_time_recipient") {
      describe.push("First payment to this address from this account: compare every character.");
    } else if (f.kind === "looks_like") {
      describe.push(
        `This address looks like a trusted one (0x${f.trusted}) but is a different address. ` +
          "This is how address poisoning works: do not send unless you meant this one.",
      );
    } else {
      describe.push(
        "This address has only ever sent to you. Copying an address from your history is how address poisoning works.",
      );
    }
  }
  return { fullAddress: to, flags, requiresFullAddressConfirmation: flags.length > 0, describe };
}

/** Whether `typed` is the assessed recipient's full address; a shortened form never matches. */
export function confirmationMatches(a: RecipientAssessment, typed: string): boolean {
  return norm(typed) === a.fullAddress;
}

interface RpcLike {
  call<T>(method: string, params: unknown[] | Record<string, unknown>): Promise<T>;
}

/** Assess `to` for `fromHex` from the node's history and the governed thresholds. */
export async function assessRecipientFromNode(
  rpc: RpcLike,
  fromHex: string,
  to: string,
): Promise<RecipientAssessment> {
  const governed = async (key: string): Promise<number | undefined> => {
    try {
      const v = await rpc.call<{ value?: string }>("tenzro_getNetworkParams", { key });
      const n = Number(v?.value);
      return Number.isFinite(n) ? n : undefined;
    } catch {
      return undefined;
    }
  };
  const params = lookalikeParamsFromGoverned(
    await governed(PREFIX_BYTES_PARAM),
    await governed(SUFFIX_BYTES_PARAM),
  );
  const history = await rpc.call<{ transactions?: Array<{ from?: string; to?: string }> }>(
    "tenzro_getTransactionHistory",
    { address: fromHex, limit: 500 },
  );
  const me = norm(fromHex);
  const trusted: string[] = [];
  const senders: string[] = [];
  for (const tx of history.transactions ?? []) {
    if (!tx.from || !tx.to) continue;
    if (norm(tx.from) === me) trusted.push(tx.to);
    else if (norm(tx.to) === me) senders.push(tx.from);
  }
  const trustedSet = new Set(trusted.map(norm));
  return assessRecipient(
    to,
    trusted,
    senders.filter((s) => !trustedSet.has(norm(s))),
    params,
  );
}

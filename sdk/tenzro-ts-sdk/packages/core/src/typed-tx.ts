import type { RpcClient } from "./rpc";
import { readQuantity } from "./rpc";
import {
  HybridSigner,
  TRANSACTION_SIGNATURE_CONTEXT,
  accountAddress,
  compositeMessageRepresentative,
  compositeSignatureJson,
} from "./wallet";

/**
 * Typed transactions for every consensus transaction type, signed
 * client-side.
 *
 * A {@link TypedTransaction} names its kind and carries the variant's
 * fields as JSON. {@link TypedTxClient.send} fills in the envelope, asks the
 * node for the signing payload, checks that the payload is the transaction it
 * asked for, signs the digest with the caller's hybrid key and submits it.
 * The node never signs: it only encodes, and an encoding that does not match
 * what the caller built is refused before anything is signed.
 */

/** Every consensus transaction type, in the order the network declares them. */
export const TX_KINDS = [
  "Transfer",
  "ContractDeploy",
  "ContractCall",
  "AgentRegister",
  "AgentExecute",
  "ModelInference",
  "TeeProviderRegister",
  "GovernancePropose",
  "GovernanceVote",
  "GovernanceVeto",
  "GovernancePause",
  "GovernanceExecute",
  "Funding",
  "CreateEscrow",
  "ReleaseEscrow",
  "RefundEscrow",
  "PauseAgent",
  "QuarantineAgent",
  "TerminateAgent",
  "PostAgentBond",
  "IncreaseAgentBond",
  "WithdrawAgentBond",
  "PostComputeBond",
  "IncreaseComputeBond",
  "WithdrawComputeBond",
  "FinalizeComputeBondWithdrawal",
  "PayInsuranceClaim",
  "PayerSettle",
  "ClaimEscrow",
  "ClaimEscrowPreimage",
  "ClaimEscrowStream",
  "PostMeterBond",
  "WithdrawMeterBond",
  "DisputeMeteredCharge",
  "TreasuryDeposit",
  "IncreaseValidatorStake",
  "RegisterValidator",
  "ReportCheckpointEquivocation",
  "ExitValidator",
  "UpdateValidatorMetadata",
  "RegisterIdentity",
  "AttestZkProof",
  "SlaAttest",
  "ComputeClaim",
  "RecordCheckpointSigners",
  "AgentAuditCommit",
  "LiftAgentQuarantine",
  "AgentAuditFlag",
  "RevokeDelegatedAgent",
  "SetAgentTerms",
  "AgentAct",
  "FeeRateSubmit",
  "InferenceFault",
  "Bridge",
  "Token",
  "Stake",
  "RemoteGrantSettle",
  "Payment",
  "GovernanceVetoSignal",
  "GovernanceVetoWithdraw",
  "GovernanceConcern",
  "UpgradeReady",
  "GovernanceSecurityDisclosure",
  "SettlementPlan",
  "BeaconContribute",
  "DaRetention",
  "AccountKeys",
  "KeystoreUpdate",
  "IdentityServices",
  "ExternalEvm",
  "ExternalSvm",
  "RevokeIdentity",
  "Registry",
  "SetAgentTopUp",
  "TopUpAgent",
  "ReclaimAgentFunds",
  "RotateValidatorKey",
  "HardwareProof",
  "RegisterValidatorMachine",
  "KeyRelease",
  "TrainingProof",
  "AttachMachineAttestation",
  "SponsoredBond",
  "AccountOutflow",
] as const;

/** One consensus transaction type. */
export type TxKind = (typeof TX_KINDS)[number];

/** A transaction of one kind, before its envelope and signature. */
export interface TypedTransaction {
  kind: TxKind;
  /** The kind's fields; `null` for `ExitValidator`, the one kind without fields. */
  fields: Record<string, unknown> | null;
  /** Hex recipient field of the envelope; the system address when unset. */
  to?: string;
  /**
   * Hex sender account (20 or 32 bytes): a passkey account whose keystore on
   * chain links the signer's passkey, such as the account every device of a
   * wallet acts for. By default the account the signer's P-256 key names.
   */
  from?: string;
  gasLimit?: number;
  /** Gas price, smallest TNZO unit. The node's current price (`eth_gasPrice`) when unset. */
  gasPrice?: number;
}

/** The `tx_type` the network decodes. */
export function txType(tx: TypedTransaction): unknown {
  if (tx.kind === "ExitValidator") {
    if (tx.fields !== null) throw new Error("ExitValidator takes no fields");
    return "ExitValidator";
  }
  if (tx.fields === null || typeof tx.fields !== "object" || Array.isArray(tx.fields)) {
    throw new Error(`${tx.kind} takes a JSON object of fields`);
  }
  if (tx.kind === "KeystoreUpdate") return { KeystoreUpdate: keystoreUpdateFields(tx.fields) };
  return { [tx.kind]: tx.fields };
}

/**
 * A keystore change as the network encodes it: a credential the change adds
 * carries `added_at_ms` (zero; the chain sets it), as the node's signing
 * payload does.
 */
function keystoreUpdateFields(fields: Record<string, unknown>): Record<string, unknown> {
  const update = fields.update as { op?: unknown } | undefined;
  const op = update?.op;
  if (!op || typeof op !== "object") return fields;
  const [name, body] = Object.entries(op as Record<string, unknown>)[0] ?? [];
  if ((name !== "add_credential" && name !== "start_recovery") || !body || typeof body !== "object") return fields;
  const credential = (body as { credential?: Record<string, unknown> }).credential;
  if (!credential) return fields;
  return {
    ...fields,
    update: {
      ...update,
      op: { [name]: { ...body, credential: { ...credential, added_at_ms: credential.added_at_ms ?? 0 } } },
    },
  };
}

const VALIDITY_MS = 300_000;

/**
 * A signed transaction as the network's JSON encodes it: byte fields are
 * arrays of numbers, the type is `tx_type` exactly as it was signed.
 */
export interface SignedTransactionJson {
  transaction: {
    chain_id: number;
    from: number[];
    to: number[];
    nonce: number;
    tx_type: unknown;
    gas_limit: number;
    gas_price: number;
    timestamp: number;
    valid_until: number;
    memo: null;
  };
  /** The signer's P-256 key `x || y`, hex. */
  public_key: string;
  /** The composite signature: the P-256 leg (raw or a passkey's WebAuthn form), plus the ML-DSA-65 leg when enrolled. */
  signature: ReturnType<typeof compositeSignatureJson>;
}

/** The envelope fields of one signing. */
export interface Envelope {
  chainId: number;
  from: Uint8Array;
  to: Uint8Array;
  nonce: number;
  gasLimit: number;
  gasPrice: number;
  timestamp: number;
  validUntil: number;
}

const hex = (b: Uint8Array): string => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
const unhex = (s: string): Uint8Array => {
  const c = s.startsWith("0x") ? s.slice(2) : s;
  if (c.length % 2 !== 0 || /[^0-9a-fA-F]/.test(c)) throw new Error("not hex");
  return Uint8Array.from(c.match(/../g) ?? [], (h) => parseInt(h, 16));
};
const le = (v: number, bytes: 4 | 8, signed = false): Uint8Array => {
  const buf = new ArrayBuffer(bytes);
  const view = new DataView(buf);
  if (bytes === 4) view.setUint32(0, v, true);
  else if (signed) view.setBigInt64(0, BigInt(v), true);
  else view.setBigUint64(0, BigInt(v), true);
  return new Uint8Array(buf);
};
const sha256 = async (data: Uint8Array): Promise<Uint8Array> =>
  new Uint8Array(await crypto.subtle.digest("SHA-256", new Uint8Array(data)));
const concat = (parts: Uint8Array[]): Uint8Array => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
};

/** Deep equality of two JSON values, ignoring object key order. */
function sameJson(a: unknown, b: unknown): boolean {
  if (a === b) return true;
  if (typeof a !== typeof b || a === null || b === null || typeof a !== "object") return false;
  if (Array.isArray(a) !== Array.isArray(b)) return false;
  const ka = Object.keys(a as object);
  const kb = Object.keys(b as object);
  return ka.length === kb.length && ka.every((k) => sameJson((a as Record<string, unknown>)[k], (b as Record<string, unknown>)[k]));
}

function mismatch(what: string): Error {
  return new Error(`the node's signing payload does not match the transaction: ${what}`);
}

/**
 * The digest to sign, once the node's payload is shown to be the transaction
 * `env` and `type` describe. Exported for tests.
 */
export async function checkSigningPayload(
  env: Envelope,
  type: unknown,
  payload: { kind?: string; digest?: string; tx_type_json?: string; preimage?: string },
): Promise<Uint8Array> {
  if (typeof payload.digest !== "string") throw mismatch("no digest");
  const claimed = unhex(payload.digest);
  let digest: Uint8Array;
  if (payload.kind === "plain") {
    const encoded = payload.tx_type_json;
    if (typeof encoded !== "string") throw mismatch("no tx_type encoding");
    if (!sameJson(JSON.parse(encoded), type)) throw mismatch("tx_type");
    digest = await sha256(
      concat([
        le(env.chainId, 8),
        env.from,
        env.to,
        le(env.nonce, 8),
        le(env.gasLimit, 8),
        le(env.gasPrice, 8),
        le(env.timestamp, 8, true),
        le(env.validUntil, 8, true),
        new TextEncoder().encode(encoded),
      ]),
    );
  } else if (payload.kind === "typed_action") {
    const bytes = payload.preimage;
    if (typeof bytes !== "string") throw mismatch("no preimage");
    const p = JSON.parse(bytes) as Record<string, unknown>;
    const want: Record<string, unknown> = {
      chain_id: env.chainId,
      from: hex(env.from),
      to: hex(env.to),
      nonce: env.nonce,
      gas_limit: env.gasLimit,
      gas_price: env.gasPrice,
      timestamp: env.timestamp,
      valid_until: env.validUntil,
      action: type,
    };
    for (const [field, value] of Object.entries(want)) {
      if (!sameJson(p[field], value)) throw mismatch(field);
    }
    digest = await sha256(new TextEncoder().encode(bytes));
  } else {
    throw mismatch("unknown payload kind");
  }
  if (hex(digest) !== hex(claimed)) throw mismatch("digest");
  return digest;
}

/** Signs and submits typed transactions. */
export class TypedTxClient {
  constructor(private rpc: RpcClient) {}

  /** Sign `tx` with `signer` and submit it; returns `tenzro_sendRawTransaction`'s answer. */
  async send(signer: HybridSigner, tx: TypedTransaction): Promise<unknown> {
    return this.sendVia("tenzro_sendRawTransaction", signer, tx);
  }

  /**
   * Sign `tx` with `signer` and submit it through `method`, which takes the
   * params `tenzro_sendRawTransaction` takes (`tenzro_revokeIdentity` for a
   * `RevokeIdentity` transaction).
   */
  async sendVia(method: string, signer: HybridSigner, tx: TypedTransaction): Promise<unknown> {
    const { request, publicKey, signature, pqSignature } = await this.signParts(signer, tx);
    return this.rpc.call(method, {
      ...request,
      public_key: hex(publicKey),
      signature: compositeSignatureJson(signature, pqSignature),
    });
  }

  /**
   * Sign `tx` with `signer` without submitting it. Returns the signed
   * transaction in the network's JSON form, for a party that submits it
   * later (an x402 `plan` payment carries one; see `planPaymentPayload`).
   */
  async sign(signer: HybridSigner, tx: TypedTransaction): Promise<SignedTransactionJson> {
    const { env, type, publicKey, signature, pqSignature } = await this.signParts(signer, tx);
    return {
      transaction: {
        chain_id: env.chainId,
        from: Array.from(env.from),
        to: Array.from(env.to),
        nonce: env.nonce,
        tx_type: type,
        gas_limit: env.gasLimit,
        gas_price: env.gasPrice,
        timestamp: env.timestamp,
        valid_until: env.validUntil,
        memo: null,
      },
      public_key: hex(publicKey),
      signature: compositeSignatureJson(signature, pqSignature),
    };
  }

  /**
   * A dry run of `tx` sent from the account `from` (32-byte hex; `tx.from`
   * wins when set): reads the nonce, chain id and gas price the node reports,
   * asks the node to encode the signing payload and checks that the encoding
   * is the transaction built here. Returns the request and the digest a
   * signer would sign; nothing is signed or submitted.
   */
  async prepare(from: string, tx: TypedTransaction): Promise<PreparedTransaction> {
    const { request, digest } = await this.prepareParts(tx.from === undefined ? { ...tx, from } : tx, undefined);
    return { request, digest: hex(digest) };
  }

  private async signParts(signer: HybridSigner, tx: TypedTransaction) {
    const publicKey = signer.p256PublicKey();
    const { env, type, request, digest } = await this.prepareParts(tx, publicKey);
    const mPrime = await compositeMessageRepresentative(TRANSACTION_SIGNATURE_CONTEXT, digest);
    const [signature, pqSignature] = await signer.signComposite(mPrime);
    return { env, type, request, publicKey, signature, pqSignature };
  }

  private async prepareParts(tx: TypedTransaction, publicKey: Uint8Array | undefined) {
    const type = txType(tx);
    let from: Uint8Array;
    if (tx.from === undefined) {
      if (publicKey === undefined) throw new Error("a sender account is needed");
      from = await accountAddress(publicKey);
    } else {
      const named = unhex(tx.from);
      if (named.length === 20) from = concat([named, new Uint8Array(12)]);
      else if (named.length === 32) from = named;
      else throw new Error(`sender must be 20 or 32 bytes, got ${named.length}`);
    }
    const fromHex = "0x" + hex(from);
    const to = tx.to ? unhex(tx.to) : new Uint8Array(32);
    if (to.length !== 32) throw new Error(`recipient must be 32 bytes, got ${to.length}`);
    const nonce = await readQuantity(this.rpc, "tenzro_getNonce", [fromHex], "nonce");
    const chainId = await readQuantity(this.rpc, "eth_chainId", [], "chain id");
    const gasPrice = tx.gasPrice ?? (await readQuantity(this.rpc, "eth_gasPrice", [], "gas price"));
    const timestamp = Date.now();
    const env: Envelope = {
      chainId,
      from,
      to,
      nonce,
      gasLimit: tx.gasLimit ?? 500_000,
      gasPrice,
      timestamp,
      validUntil: timestamp + VALIDITY_MS,
    };
    const request: Record<string, unknown> = {
      from: fromHex,
      to: "0x" + hex(to),
      nonce,
      chain_id: chainId,
      gas_limit: env.gasLimit,
      gas_price: env.gasPrice,
      timestamp,
      valid_until: env.validUntil,
      tx_type: type,
    };
    const payload = await this.rpc.call<{ kind?: string; digest?: string; tx_type_json?: string; preimage?: string }>(
      "tenzro_getSigningPayload",
      request,
    );
    const digest = await checkSigningPayload(env, type, payload);
    return { env, type, request, digest };
  }
}

/** A typed transaction checked against the node's encoding and not signed. */
export interface PreparedTransaction {
  /** The `tenzro_sendRawTransaction` params, without `public_key` and `signature`. */
  request: Record<string, unknown>;
  /** The SHA-256 digest a signer would sign, hex. */
  digest: string;
}

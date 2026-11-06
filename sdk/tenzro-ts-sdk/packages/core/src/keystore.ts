/**
 * Passkey account keystores, held in consensus state.
 *
 * A passkey account is its devices plus its keystore on the ledger: the
 * passkeys that may act for it, its policy, its recovery signers and any
 * recovery in progress. Every node answers from the same record, so any
 * linked device works through any node, and the account outlives every site
 * and node that served it.
 *
 * Changes are `KeystoreUpdate` transactions. Each is approved by passkeys of
 * the account (or, to start a recovery, by its recovery signers) over
 * {@link keystoreDigest}, which every SDK computes the same way and which
 * names the chain the change is for (a chain refuses a change approved for
 * another); any account
 * may send and pay for it, and a transaction the account itself sends,
 * signed by one of its passkeys, counts as that passkey's approval.
 */

import type { RpcClient } from "./rpc";
import { readQuantity } from "./rpc";
import { TypedTxClient } from "./typed-tx";
import { type HybridSigner, compositeMessageRepresentative, compositeSignatureJson, webauthnChallengeOf } from "./wallet";

/** A signature in the network's JSON form. */
export type CompositeSignatureJson = ReturnType<typeof compositeSignatureJson>;

/** One passkey a keystore links. Byte fields are hex. */
export interface KeystoreCredential {
  /** The relying party the passkey is registered on: any wallet provider's domain. */
  rp_id: string;
  credential_id: string;
  /** P-256 key, `x || y`. */
  public_key: string;
  aaguid: string;
  backup_eligible: boolean;
  backup_state: boolean;
  /** Block time (ms) from which it counts as a root; set by the chain. */
  counts_as_root_from_ms: number;
  /** Block time (ms) the passkey joined the keystore on chain; set by the chain, zero until then. */
  added_at_ms?: number;
  label: string;
}

export type SecondFactorPolicy = "single_credential" | "two_credentials";
export type RecoveryRole = "recovery_key" | "email_verifier" | "device";

/** A key that may approve the account's recovery. */
export interface RecoverySigner {
  /** A passkey's relying party; empty for a TPM or Secure Enclave key. */
  rp_id: string;
  public_key: string;
  aaguid: string;
  backup_eligible: boolean;
  backup_state: boolean;
  role: RecoveryRole;
  label: string;
}

export interface PendingRecovery {
  credential: KeystoreCredential;
  approvers: number[];
  started_at_ms: number;
  ready_at_ms: number;
}

export interface KeystoreRecord {
  account: string;
  owner_did: string;
  salt: number;
  version: number;
  credentials: KeystoreCredential[];
  policy: SecondFactorPolicy;
  recovery_signers: RecoverySigner[];
  recovery_threshold: number;
  pending_recovery: PendingRecovery | null;
  /** Commitment to the one-time recovery code, when the account set one. */
  recovery_code: { commitment: string } | null;
}

/** The first passkey of an account, which derives its address. */
export interface KeystoreAnchor {
  rp_id: string;
  credential_id: string;
  public_key: string;
  aaguid: string;
  backup_eligible: boolean;
  backup_state: boolean;
  salt: number;
}

export type KeystoreOp =
  | { add_credential: { credential: KeystoreCredential } }
  | { remove_credential: { credential_id: string } }
  | { set_policy: { policy: SecondFactorPolicy } }
  | { set_recovery: { signers: RecoverySigner[]; threshold: number } }
  | { start_recovery: { credential: KeystoreCredential } }
  | "cancel_recovery"
  | "finish_recovery"
  | { set_recovery_code: { commitment: string | null } }
  | { claim_recovery_code: { claim: string } }
  | { recover_with_code: { code: string; credential: KeystoreCredential } };

export interface KeystoreApproval {
  public_key: string;
  signature: CompositeSignatureJson;
}

export interface KeystoreUpdate {
  /** The chain the change is for; a chain refuses a change approved for another. */
  chain_id: number;
  account: string;
  anchor: KeystoreAnchor | null;
  previous_commitment: string;
  op: KeystoreOp;
  approvals: KeystoreApproval[];
  possession: CompositeSignatureJson | null;
}

/** `tenzro_getKeystore`. */
export interface KeystoreView {
  account: string;
  /** Whether the record is on chain; otherwise it is the genesis record of the anchor asked about. */
  on_chain: boolean;
  keystore: KeystoreRecord | null;
  /** The `previous_commitment` the account's next update names. */
  commitment?: string;
  independent_roots?: number;
  may_spend?: boolean;
}

/** Context passkeys approve keystore changes under. */
export const ACCOUNT_OWNER_SIGNATURE_CONTEXT = new TextEncoder().encode("tenzro/rpc/account-owner");
/** Context recovery signers approve a recovery under. */
export const RECOVERY_APPROVAL_SIGNATURE_CONTEXT = new TextEncoder().encode("tenzro/identity/recovery-approval");

const UPDATE_DOMAIN = new TextEncoder().encode("tenzro/keystore-update/v1");
const ROLE: Record<RecoveryRole, number> = { recovery_key: 1, email_verifier: 2, device: 3 };
const POLICY: Record<SecondFactorPolicy, number> = { single_credential: 1, two_credentials: 2 };

function bytes(hex: string): Uint8Array {
  const c = hex.startsWith("0x") ? hex.slice(2) : hex;
  if (c.length % 2 !== 0 || /[^0-9a-fA-F]/.test(c)) throw new Error(`${hex} is not hex`);
  return Uint8Array.from(c.match(/../g) ?? [], (h) => parseInt(h, 16));
}

const hexOf = (b: Uint8Array): string => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");

/** `n` as 8 bytes little-endian, the way a transaction encodes its chain id. */
function u64le(n: number): Uint8Array {
  if (!Number.isSafeInteger(n) || n < 0) throw new Error(`${n} is not a chain id`);
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, BigInt(n), true);
  return b;
}

function u32be(n: number): Uint8Array {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n, false);
  return b;
}

function field(b: Uint8Array): Uint8Array[] {
  return [u32be(b.length), b];
}

function concat(parts: Uint8Array[]): Uint8Array {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let offset = 0;
  for (const p of parts) {
    out.set(p, offset);
    offset += p.length;
  }
  return out;
}

function credentialBytes(c: KeystoreCredential): Uint8Array[] {
  return [
    ...field(new TextEncoder().encode(c.rp_id)),
    ...field(bytes(c.credential_id)),
    ...field(bytes(c.public_key)),
    ...field(bytes(c.aaguid)),
    Uint8Array.of(c.backup_eligible ? 1 : 0, c.backup_state ? 1 : 0),
    ...field(new TextEncoder().encode(c.label)),
  ];
}

/** The canonical bytes of `op` an approval covers. */
export function encodeKeystoreOp(op: KeystoreOp): Uint8Array {
  if (op === "cancel_recovery") return Uint8Array.of(5);
  if (op === "finish_recovery") return Uint8Array.of(6);
  if ("add_credential" in op) return concat([Uint8Array.of(1), ...credentialBytes(op.add_credential.credential)]);
  if ("remove_credential" in op) return concat([Uint8Array.of(2), ...field(bytes(op.remove_credential.credential_id))]);
  if ("set_recovery" in op) {
    const { signers, threshold } = op.set_recovery;
    const parts: Uint8Array[] = [Uint8Array.of(3), u32be(threshold), u32be(signers.length)];
    for (const s of signers) {
      parts.push(
        ...field(new TextEncoder().encode(s.rp_id)),
        ...field(bytes(s.public_key)),
        ...field(bytes(s.aaguid)),
        Uint8Array.of(s.backup_eligible ? 1 : 0, s.backup_state ? 1 : 0, ROLE[s.role]),
        ...field(new TextEncoder().encode(s.label)),
      );
    }
    return concat(parts);
  }
  if ("start_recovery" in op) return concat([Uint8Array.of(4), ...credentialBytes(op.start_recovery.credential)]);
  if ("set_policy" in op) return Uint8Array.of(7, POLICY[op.set_policy.policy]);
  if ("set_recovery_code" in op) {
    const c = op.set_recovery_code.commitment;
    return concat([Uint8Array.of(8), ...field(c ? bytes(c) : new Uint8Array(0))]);
  }
  if ("claim_recovery_code" in op) return concat([Uint8Array.of(9), ...field(bytes(op.claim_recovery_code.claim))]);
  if ("recover_with_code" in op) {
    return concat([
      Uint8Array.of(10),
      ...field(bytes(op.recover_with_code.code)),
      ...credentialBytes(op.recover_with_code.credential),
    ]);
  }
  throw new Error("unknown keystore change");
}

const RECOVERY_CODE_DOMAIN = new TextEncoder().encode("tenzro/keystore/recovery-code/v1");
const RECOVERY_CLAIM_DOMAIN = new TextEncoder().encode("tenzro/keystore/recovery-claim/v1");

const sha256 = async (b: Uint8Array): Promise<Uint8Array> =>
  new Uint8Array(await globalThis.crypto.subtle.digest("SHA-256", b as BufferSource));

/**
 * A new one-time recovery code: 32 random bytes, hex, from the platform's
 * secure random source. Its holder keeps it (downloaded or written down);
 * the account holds only {@link recoveryCodeCommitment}. It is no key and
 * signs nothing: it starts a recovery any linked passkey can cancel.
 */
export function generateRecoveryCode(): string {
  return hexOf(globalThis.crypto.getRandomValues(new Uint8Array(32)));
}

/** The commitment `set_recovery_code` puts on the account on chain `chainId` for `code`. */
export async function recoveryCodeCommitment(chainId: number, account: string, code: string): Promise<string> {
  return hexOf(await sha256(concat([RECOVERY_CODE_DOMAIN, u64le(chainId), bytes(account), bytes(code)])));
}

/**
 * The claim on chain `chainId` binding `code` to the passkey `credential`
 * that will join: sent first, by another account, as `claim_recovery_code`;
 * the code is revealed with `recover_with_code` once the claim has aged.
 */
export async function recoveryCodeClaim(
  chainId: number,
  account: string,
  code: string,
  credential: KeystoreCredential,
): Promise<string> {
  return hexOf(
    await sha256(concat([RECOVERY_CLAIM_DOMAIN, u64le(chainId), bytes(account), bytes(code), ...credentialBytes(credential)])),
  );
}

/**
 * What a passkey's registration says about it, from its authenticator data:
 * its authenticator model (AAGUID) and whether it is backup eligible and
 * backed up, which the keystore records and the chain checks.
 */
export function registrationFacts(authenticatorData: Uint8Array): {
  aaguid: string;
  backupEligible: boolean;
  backupState: boolean;
} {
  if (authenticatorData.length < 37 + 16 || (authenticatorData[32] & 0x40) === 0) {
    throw new Error("the registration carries no attested credential");
  }
  const flags = authenticatorData[32];
  return {
    aaguid: hexOf(authenticatorData.subarray(37, 53)),
    backupEligible: (flags & 0x08) !== 0,
    backupState: (flags & 0x10) !== 0,
  };
}

/** A P-256 key as the keystore holds it (`x || y`, hex), from SPKI DER, SEC1 or raw form. */
export function rawP256(key: Uint8Array): string {
  const xy =
    key.length === 64 ? key : key.length === 65 && key[0] === 0x04 ? key.subarray(1) : key.length === 91 ? key.subarray(27) : null;
  if (!xy || xy.length !== 64) throw new Error("not a P-256 public key");
  return hexOf(xy);
}

/**
 * The WebAuthn challenge (base64url) a passkey signs to approve, or prove
 * possession for, `digest` under `context` (the account-owner context by
 * default).
 */
export async function passkeyChallenge(digest: Uint8Array, context: Uint8Array = ACCOUNT_OWNER_SIGNATURE_CONTEXT): Promise<string> {
  return webauthnChallengeOf(await compositeMessageRepresentative(context, digest));
}

/**
 * What every approval of `op` on `account` on chain `chainId` signs, given
 * the commitment of the record it changes:
 * `SHA-256(domain ‖ chain id ‖ account ‖ commitment ‖ op)`, the chain id as
 * 8 bytes little-endian.
 */
export async function keystoreDigest(
  chainId: number,
  account: string,
  previousCommitment: string,
  op: KeystoreOp,
): Promise<Uint8Array> {
  const preimage = concat([
    UPDATE_DOMAIN,
    u64le(chainId),
    ...field(bytes(account)),
    ...field(bytes(previousCommitment)),
    encodeKeystoreOp(op),
  ]);
  return new Uint8Array(await globalThis.crypto.subtle.digest("SHA-256", preimage as BufferSource));
}

const updateDigest = (u: KeystoreUpdate): Promise<Uint8Array> =>
  keystoreDigest(u.chain_id, u.account, u.previous_commitment, u.op);

/** `signer`'s signature over `digest` under `context`, in the network's JSON form. */
async function signDigest(signer: HybridSigner, context: Uint8Array, digest: Uint8Array): Promise<CompositeSignatureJson> {
  const mPrime = await compositeMessageRepresentative(context, digest);
  const [signature, pq] = await signer.signComposite(mPrime);
  return compositeSignatureJson(signature, pq);
}

/** Reads keystores and builds, approves and sends their changes. */
export class KeystoreClient {
  private readonly txs: TypedTxClient;

  constructor(private readonly rpc: RpcClient) {
    this.txs = new TypedTxClient(rpc);
  }

  /** The keystore of `account`; with `anchor`, the genesis record of an account that has none on chain. */
  getKeystore(account: string, anchor?: KeystoreAnchor): Promise<KeystoreView> {
    return this.rpc.call("tenzro_getKeystore", anchor ? { account, anchor } : { account });
  }

  /** The accounts whose keystore links the passkey with this credential id, registered on `rpId`. */
  resolveCredential(credentialId: string, rpId: string): Promise<{ accounts: string[] }> {
    return this.rpc.call("tenzro_resolveCredential", { credential_id: credentialId, rp_id: rpId });
  }

  /**
   * An unapproved change of `account`'s keystore, naming the node's chain
   * and the keystore's current commitment. `anchor` is required while the
   * account has no keystore on chain, and then carried by the change.
   */
  async prepare(account: string, op: KeystoreOp, anchor?: KeystoreAnchor): Promise<KeystoreUpdate> {
    const view = await this.getKeystore(account, anchor);
    if (!view.keystore || !view.commitment) {
      throw new Error(`account ${account} has no keystore on chain; pass its anchor`);
    }
    const chainId = await readQuantity(this.rpc, "eth_chainId", [], "chain id");
    return {
      chain_id: chainId,
      account: view.account,
      anchor: view.on_chain ? null : (anchor ?? null),
      previous_commitment: view.commitment,
      op,
      approvals: [],
      possession: null,
    };
  }

  /** Add `signer`'s approval, as a passkey of the account. */
  async approve(update: KeystoreUpdate, signer: HybridSigner): Promise<KeystoreUpdate> {
    const digest = await updateDigest(update);
    const signature = await signDigest(signer, ACCOUNT_OWNER_SIGNATURE_CONTEXT, digest);
    return { ...update, approvals: [...update.approvals, { public_key: hexOf(signer.p256PublicKey()), signature }] };
  }

  /** Add `signer`'s approval, as a recovery signer of the account. */
  async approveRecovery(update: KeystoreUpdate, signer: HybridSigner): Promise<KeystoreUpdate> {
    const digest = await updateDigest(update);
    const signature = await signDigest(signer, RECOVERY_APPROVAL_SIGNATURE_CONTEXT, digest);
    return { ...update, approvals: [...update.approvals, { public_key: hexOf(signer.p256PublicKey()), signature }] };
  }

  /** Add the proof of possession of the passkey the change adds, signed by that passkey. */
  async prove(update: KeystoreUpdate, newPasskey: HybridSigner): Promise<KeystoreUpdate> {
    const digest = await updateDigest(update);
    return { ...update, possession: await signDigest(newPasskey, ACCOUNT_OWNER_SIGNATURE_CONTEXT, digest) };
  }

  /**
   * Send `update`, signed and paid for by `sender`. With `fromAccount`, the
   * transaction is sent from that account (the passkey account itself, so
   * the sender's passkey also approves); otherwise from the account the
   * sender's key names: a sponsor (a wallet provider, or a friend) that pays
   * the fee of an account with no balance and authorizes nothing, the
   * change carrying the passkeys' approvals.
   * The fee is paid at `gasPrice`, or at the node's current price
   * (`eth_gasPrice`).
   */
  send(sender: HybridSigner, update: KeystoreUpdate, fromAccount?: string, gasPrice?: number): Promise<unknown> {
    return this.txs.send(sender, { kind: "KeystoreUpdate", fields: { update }, from: fromAccount, gasPrice });
  }
}

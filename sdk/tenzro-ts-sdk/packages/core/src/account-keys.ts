import type { RpcClient } from './rpc';
import { TypedTxClient, type TypedTransaction } from './typed-tx';
import { accountAddress, compositeMessageRepresentative, type HybridSigner } from './wallet';

/** Length of an ML-DSA-65 verifying key. */
export const ML_DSA_65_PUBLIC_KEY_LEN = 1952;

/** Signature context of the proof that the hardware holds the ML-DSA-65 key being enrolled. */
export const PQ_KEY_ENROLLMENT_SIGNATURE_CONTEXT = new TextEncoder().encode('tenzro/account/pq-key-enrollment');

/**
 * What the new key signs to prove possession: the account slot of the
 * sender's P-256 key followed by the new key, so the proof enrolls that key
 * for that account and nothing else.
 */
export function pqEnrollmentMessage(accountSlot: Uint8Array, mlDsaPublicKey: Uint8Array): Uint8Array {
  if (accountSlot.length !== 32) throw new Error(`an account slot is 32 bytes, got ${accountSlot.length}`);
  const m = new Uint8Array(32 + mlDsaPublicKey.length);
  m.set(accountSlot, 0);
  m.set(mlDsaPublicKey, 32);
  return m;
}

const hex = (b: Uint8Array): string => Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');

/** The `op` of an `AccountKeys` transaction that enrolls (or replaces) the account's ML-DSA-65 key. */
export function enrollPqKeyOp(mlDsaPublicKey: Uint8Array, possession: Uint8Array): Record<string, unknown> {
  if (mlDsaPublicKey.length !== ML_DSA_65_PUBLIC_KEY_LEN) {
    throw new Error(`an ML-DSA-65 key is ${ML_DSA_65_PUBLIC_KEY_LEN} bytes, got ${mlDsaPublicKey.length}`);
  }
  if (possession.length === 0) throw new Error('the proof of possession is empty');
  return { enroll_pq_key: { ml_dsa_public_key: hex(mlDsaPublicKey), possession: hex(possession) } };
}

/** What a node answers when an account that has not enrolled an ML-DSA-65 key sends a transaction carrying that leg. */
export const NOT_ENROLLED = 'no ML-DSA-65 key enrolled';

/** Operations on the keys of the signer's own account. */
export class AccountKeysClient {
  constructor(private readonly rpc: RpcClient) {}

  /**
   * Enroll the hardware's ML-DSA-65 key as the account's post-quantum key, or
   * replace the enrolled one. The hardware signs the proof of possession and
   * the transaction; no key leaves it.
   */
  async enrollPqKey(signer: HybridSigner): Promise<unknown> {
    const key = signer.mlDsaPublicKey?.() ?? null;
    if (!key) throw new Error('the hardware holds no ML-DSA-65 key to enroll');
    const slot = await accountAddress(signer.p256PublicKey());
    const mPrime = await compositeMessageRepresentative(PQ_KEY_ENROLLMENT_SIGNATURE_CONTEXT, pqEnrollmentMessage(slot, key));
    const [, possession] = await signer.signComposite(mPrime);
    if (!possession) throw new Error('the hardware did not sign with its ML-DSA-65 key');
    return new TypedTxClient(this.rpc).send(signer, { kind: 'AccountKeys', fields: { op: enrollPqKeyOp(key, possession) } });
  }

  /**
   * Send `tx`; if the node answers that the account has no ML-DSA-65 key
   * enrolled, enroll the hardware's key and send it again. An account signs
   * nothing until it has enrolled one, so this is how a new account sends its
   * first transaction.
   */
  async sendEnrolling(signer: HybridSigner, tx: TypedTransaction): Promise<unknown> {
    const client = new TypedTxClient(this.rpc);
    try {
      return await client.send(signer, tx);
    } catch (e) {
      const message = e instanceof Error ? e.message : String(e);
      if (tx.kind === 'AccountKeys' || !message.includes(NOT_ENROLLED)) throw e;
    }
    await this.enrollPqKey(signer);
    return client.send(signer, tx);
  }
}

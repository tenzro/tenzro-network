import { RpcClient, readQuantity } from "./rpc";
import { assessRecipientFromNode, confirmationMatches } from "./recipient-guard";
import {
  Address,
} from "./types";

/**
 * A hardware signer for a Tenzro account. The P-256 key of a TPM, Secure
 * Enclave or other hardware module names the account; where the same
 * hardware holds an ML-DSA-65 key and the account enrolled it in state, that
 * key signs the post-quantum leg. The SDK never holds a private key: this
 * interface is implemented over the hardware (see `HardwareKeySigner`), and
 * it is what lets `WalletClient.sendSelfCustody` and `TypedTxClient.send`
 * build the canonical transaction hash, obtain the composite signature and
 * submit it via `tenzro_sendRawTransaction`.
 */
export interface HybridSigner {
  /** The hardware P-256 public key, `x ‖ y` (64 bytes). It derives the account address (`accountAddress`). */
  p256PublicKey(): Uint8Array;

  /**
   * The hardware ML-DSA-65 verifying key (1952 bytes), when the hardware
   * holds one: the account's enrolled key, or the key an `AccountKeys`
   * transaction enrolls (`AccountKeysClient`).
   */
  mlDsaPublicKey?(): Uint8Array | null;

  /**
   * Sign the composite message representative `mPrime` (built by
   * `compositeMessageRepresentative`): the P-256 leg over `SHA-256(mPrime)`,
   * and, when the hardware holds an ML-DSA-65 key (`mlDsaPublicKey`), the
   * ML-DSA-65 leg over `mPrime` with the FIPS 204 context string
   * `COMPOSITE_LABEL_MLDSA65_P256` (`null` otherwise). A TPM or Secure
   * Enclave returns the P-256 leg as a prehash signature `r ‖ s` (64 bytes);
   * a passkey returns its WebAuthn assertion over the challenge
   * `base64url(SHA-256(mPrime))` (`webauthnChallengeOf`).
   */
  signComposite(mPrime: Uint8Array): Promise<[ClassicalLeg, Uint8Array | null]>;
}

/** A passkey's assertion, the WebAuthn form of the P-256 leg. */
export interface WebAuthnAssertion {
  authenticatorData: Uint8Array;
  /** `clientDataJSON`, byte-exact. */
  clientDataJson: Uint8Array;
  /** The assertion signature, DER or `r ‖ s`. */
  signature: Uint8Array;
}

/** The P-256 leg: raw `r ‖ s` from a TPM or Secure Enclave, or a passkey assertion. */
export type ClassicalLeg = Uint8Array | WebAuthnAssertion;

/** The WebAuthn challenge a passkey signs for `mPrime`: `base64url(SHA-256(mPrime))`, unpadded. */
export async function webauthnChallengeOf(mPrime: Uint8Array): Promise<string> {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", mPrime as BufferSource));
  let bin = "";
  for (const b of digest) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** Fixed prefix of every composite message representative. */
export const COMPOSITE_PREFIX = new TextEncoder().encode("CompositeAlgorithmSignatures2025");

/**
 * Composite label for ML-DSA-65 paired with ECDSA P-256. Also the FIPS 204
 * context string the ML-DSA-65 component signs under.
 */
export const COMPOSITE_LABEL_MLDSA65_P256 = new TextEncoder().encode(
  "COMPSIG-MLDSA65-ECDSA-P256-SHA512"
);

/**
 * The 32-byte ledger account slot of a hardware P-256 key, identical to
 * `tenzro_crypto::account_slot`:
 * `SHA-256("tenzro/account" ‖ 0x02 ‖ 0x40 ‖ x ‖ y)[..20]` followed by 12 zero
 * bytes. The address commits to the P-256 key only, so enrolling or rotating
 * the ML-DSA-65 key never moves an account.
 */
export async function accountAddress(p256PublicKey: Uint8Array): Promise<Uint8Array> {
  if (p256PublicKey.length !== 64) {
    throw new Error(`P-256 public key must be 64 bytes (x || y), got ${p256PublicKey.length}`);
  }
  const domain = new TextEncoder().encode("tenzro/account");
  const preimage = new Uint8Array(domain.length + 2 + 64);
  preimage.set(domain, 0);
  preimage[domain.length] = 2;
  preimage[domain.length + 1] = 64;
  preimage.set(p256PublicKey, domain.length + 2);
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", preimage));
  const slot = new Uint8Array(32);
  slot.set(digest.subarray(0, 20), 0);
  return slot;
}

/** Signature context of a ledger transaction. */
export const TRANSACTION_SIGNATURE_CONTEXT = new TextEncoder().encode("tenzro/tx");

/**
 * The composite message representative both components sign, identical to
 * `tenzro_crypto::composite::message_representative`:
 * `Prefix ‖ Label ‖ len(ctx) ‖ ctx ‖ SHA-512(message)`.
 */
export async function compositeMessageRepresentative(
  context: Uint8Array,
  message: Uint8Array
): Promise<Uint8Array> {
  const ph = new Uint8Array(await crypto.subtle.digest("SHA-512", message as BufferSource));
  const out = new Uint8Array(
    COMPOSITE_PREFIX.length + COMPOSITE_LABEL_MLDSA65_P256.length + 1 + context.length + ph.length
  );
  let off = 0;
  out.set(COMPOSITE_PREFIX, off);
  off += COMPOSITE_PREFIX.length;
  out.set(COMPOSITE_LABEL_MLDSA65_P256, off);
  off += COMPOSITE_LABEL_MLDSA65_P256.length;
  out[off] = context.length;
  off += 1;
  out.set(context, off);
  off += context.length;
  out.set(ph, off);
  return out;
}

/**
 * The JSON form of a composite signature, as `tenzro_sendRawTransaction`
 * takes it: the P-256 leg in raw or WebAuthn form, and the ML-DSA-65 leg when
 * present.
 */
export function compositeSignatureJson(
  classical: ClassicalLeg,
  mlDsa: Uint8Array | null
): {
  classical:
    | { form: "raw"; signature: string }
    | { form: "web_authn"; authenticator_data: string; client_data_json: string; signature: string };
  pq?: string;
} {
  const sig: ReturnType<typeof compositeSignatureJson> = {
    classical:
      classical instanceof Uint8Array
        ? { form: "raw", signature: hexEncode(classical) }
        : {
            form: "web_authn",
            authenticator_data: hexEncode(classical.authenticatorData),
            client_data_json: hexEncode(classical.clientDataJson),
            signature: hexEncode(classical.signature),
          },
  };
  if (mlDsa) sig.pq = hexEncode(mlDsa);
  return sig;
}

function hexEncode(bytes: Uint8Array): string {
  let out = "";
  for (const b of bytes) out += b.toString(16).padStart(2, "0");
  return out;
}

function hexDecode(input: string): Uint8Array {
  const clean = input.startsWith("0x") ? input.slice(2) : input;
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  }
  return out;
}

/**
 * Builds the canonical `Transaction::hash()` preimage for a native TNZO
 * transfer, byte-identical to
 * `tenzro_types::transaction::Transaction::hash`.
 *
 * Preimage order (all integers little-endian):
 * `chain_id ‖ from(32) ‖ to(32) ‖ nonce ‖ gas_limit ‖ gas_price ‖
 * timestamp ‖ valid_until ‖ tx_type_json ‖ (no memo)`.
 *
 * `tx_type_json` reproduces serde's externally-tagged
 * `{"Transfer":{"amount":<N>}}` — no whitespace, bare integer.
 */
/** Validity window a transaction is signed with: five minutes, inside the
 * network's validity caps for every transaction class. */
const TX_VALIDITY_MS = 300_000;

async function transferTxHash(args: {
  chainId: number;
  from: Uint8Array;
  to: Uint8Array;
  nonce: number;
  gasLimit: number;
  gasPrice: number;
  timestampMs: number;
  validUntilMs: number;
  amountWei: bigint;
}): Promise<Uint8Array> {
  const txTypeJson = new TextEncoder().encode(
    `{"Transfer":{"amount":${args.amountWei.toString()}}}`
  );

  const u64le = (v: number): Uint8Array => {
    const buf = new ArrayBuffer(8);
    new DataView(buf).setBigUint64(0, BigInt(v), true);
    return new Uint8Array(buf);
  };
  const i64le = (v: number): Uint8Array => {
    const buf = new ArrayBuffer(8);
    new DataView(buf).setBigInt64(0, BigInt(v), true);
    return new Uint8Array(buf);
  };

  const parts: Uint8Array[] = [
    u64le(args.chainId),
    args.from,
    args.to,
    u64le(args.nonce),
    u64le(args.gasLimit),
    u64le(args.gasPrice),
    i64le(args.timestampMs),
    i64le(args.validUntilMs),
    txTypeJson,
    // memo is None on native transfers — nothing appended.
  ];
  const total = parts.reduce((n, p) => n + p.length, 0);
  const preimage = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    preimage.set(p, off);
    off += p.length;
  }
  const digest = await crypto.subtle.digest("SHA-256", preimage);
  return new Uint8Array(digest);
}

/**
 * Client for wallet operations.
 * Supports permissionless hardware-key wallets and standard accounts.
 */
export class WalletClient {
  constructor(private rpc: RpcClient) {}

  /**
   * Get the native token balance (TNZO) for an address.
   * Returns balance as bigint (in smallest unit).
   */
  async getBalance(address: Address): Promise<bigint> {
    const hex = await this.rpc.call<string>("tenzro_getBalance", [address]);
    return BigInt(hex);
  }

  /**
   * The TNZO token balance of an address, in the smallest unit, as a decimal
   * string.
   */
  async getTokenBalance(address: Address): Promise<string> {
    return this.rpc.call<string>("tenzro_tokenBalance", { address });
  }

  /**
   * Get the nonce for an address (for transaction ordering).
   */
  async getNonce(address: Address): Promise<number> {
    const hex = await this.rpc.call<string>("tenzro_getNonce", [address]);
    return parseInt(hex, 16);
  }

  /**
   * Sign a TNZO transfer with a hardware {@link HybridSigner} and submit it
   * via `tenzro_sendRawTransaction`; the node never holds the key.
   *
   * The account of the signer's P-256 key is the `from` account. This method
   * fetches the nonce and chain id, builds the canonical `Transaction::hash()`
   * preimage, has the hardware sign its composite representative, and
   * submits the pre-signed transaction. The node requires the ML-DSA-65 leg
   * when the account enrolled an ML-DSA-65 key.
   *
   * @param value - amount in wei (smallest TNZO unit).
   * @returns The submitted transaction hash (64-char lowercase hex).
   */
  async sendSelfCustody(args: {
    signer: HybridSigner;
    to: Address;
    value: bigint;
    /**
     * The account sent from, 20 or 32 bytes of hex: a passkey account whose
     * keystore on chain links the signer's passkey. By default the account
     * the signer's P-256 key names.
     */
    from?: Address;
    gasLimit?: number;
    gasPrice?: number;
    nonce?: number;
    chainId?: number;
    /**
     * The full recipient address as the user typed it back. Required when
     * the recipient is new to this account or resembles one it trusts;
     * without it nothing is signed.
     */
    acknowledgeRecipient?: string;
  }): Promise<string> {
    const publicKey = args.signer.p256PublicKey();
    let fromBytes = args.from === undefined ? await accountAddress(publicKey) : hexDecode(args.from);
    if (fromBytes.length === 20) {
      const slot = new Uint8Array(32);
      slot.set(fromBytes);
      fromBytes = slot;
    }
    if (fromBytes.length !== 32) {
      throw new Error(`sender address must be 20 or 32 bytes, got ${fromBytes.length}`);
    }
    const toBytes = hexDecode(args.to);
    if (toBytes.length !== 32) {
      throw new Error(
        `recipient address must be 32 bytes, got ${toBytes.length}`
      );
    }
    const fromHex = "0x" + hexEncode(fromBytes);

    const assessment = await assessRecipientFromNode(this.rpc, fromHex, args.to);
    if (
      assessment.requiresFullAddressConfirmation &&
      !(args.acknowledgeRecipient !== undefined && confirmationMatches(assessment, args.acknowledgeRecipient))
    ) {
      throw new Error(
        "recipient needs the full address confirmed before signing: " + assessment.describe.join(" "),
      );
    }

    let { nonce, chainId } = args;
    if (nonce === undefined) {
      nonce = await readQuantity(this.rpc, "tenzro_getNonce", [fromHex], "nonce");
    }
    if (chainId === undefined) {
      chainId = await readQuantity(this.rpc, "eth_chainId", [], "chain id");
    }

    const gasLimit = args.gasLimit ?? 21000;
    const gasPrice = args.gasPrice ?? 1_000_000_000;
    const timestampMs = Date.now();
    const validUntilMs = timestampMs + TX_VALIDITY_MS;

    const hash = await transferTxHash({
      chainId,
      from: fromBytes,
      to: toBytes,
      nonce,
      gasLimit,
      gasPrice,
      timestampMs,
      validUntilMs,
      amountWei: args.value,
    });
    const mPrime = await compositeMessageRepresentative(TRANSACTION_SIGNATURE_CONTEXT, hash);
    const [p256Sig, mlDsaSig] = await args.signer.signComposite(mPrime);

    return this.rpc.call<string>("tenzro_sendRawTransaction", {
      from: fromHex,
      to: "0x" + hexEncode(toBytes),
      value: args.value.toString(),
      gas_limit: gasLimit,
      gas_price: gasPrice,
      nonce,
      chain_id: chainId,
      timestamp: timestampMs,
      valid_until: validUntilMs,
      public_key: hexEncode(publicKey),
      signature: compositeSignatureJson(p256Sig, mlDsaSig),
    });
  }
}

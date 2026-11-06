/**
 * Passkey-first wallet RPC client.
 *
 * Mirrors `crates/tenzro-node/src/passkey_rpc.rs` 1:1. Use this when you
 * need to talk to a Tenzro node from a browser, Tauri desktop, or Node.js
 * environment. The local-signing side (acquiring a WebAuthn assertion,
 * holding the platform authenticator handle) is covered by
 * [`PasskeyWallet`](./passkey.ts).
 */

import type { KeystoreAnchor, KeystoreRecord } from "./keystore";
import type { RpcClient } from "./rpc";

/**
 * A hardware signature: the P-256 leg (a TPM / Secure Enclave `r || s`, or a
 * passkey assertion) and, when the hardware has one, the ML-DSA-65 leg. All
 * bytes hex.
 */
export interface CompositeSignature {
	classical:
		| { form: "raw"; signature: string }
		| { form: "web_authn"; authenticator_data: string; client_data_json: string; signature: string };
	pq?: string;
}

export interface EnrollPasskeyParams {
	display_name?: string;
	passkey_public_key_hex: string;
	credential_id_hex: string;
	/**
	 * The ML-DSA-65 verifying key of the hardware that holds the passkey, hex.
	 * The authorization's `ml_dsa_signature_hex` signs the same challenge with
	 * it, and passkey sign-in checks it.
	 */
	ml_dsa_public_key_hex: string;
	/**
	 * Proof the caller holds this passkey: its assertion over the
	 * `webauthn_challenge` of an `enroll_passkey` custody challenge issued for
	 * the passkey's P-256 key with the credential id as target.
	 */
	authorization: CustodyAuthorization;
	salt?: number;
	/**
	 * The registration's `authenticatorData`, hex: what
	 * `navigator.credentials.create()` returned as
	 * `response.getAuthenticatorData()`. The node reads the credential's
	 * backup flags from it after checking it names the passkey's relying
	 * party, this credential and this key. Required, except for a further
	 * wallet (salt > 0) under an existing identity.
	 */
	registration_authenticator_data_hex?: string;
	/**
	 * The relying party the passkey is registered on: the wallet provider's
	 * domain. Defaults to the node's own.
	 */
	rp_id?: string;
}

export interface EnrollPasskeyResponse {
	did: string;
	smart_account_address: string;
	credential_id_hex: string;
	/** The account's keystore: on chain, or its genesis record before its first change. */
	keystore: KeystoreRecord;
	/** The `previous_commitment` the account's next keystore change names. */
	keystore_commitment: string;
	/** What the account's first keystore change carries; null once it has a keystore on chain. */
	anchor: KeystoreAnchor | null;
}

export interface WebAuthnAssertionJson {
	authenticator_data: number[] | Uint8Array;
	client_data_json: number[] | Uint8Array;
	signature: number[] | Uint8Array;
	user_handle?: number[] | Uint8Array | null;
}

/**
 * Which custody change a challenge authorizes.
 *
 * Changing who can sign for a wallet takes two ceremonies: proof of control
 * from a device already on the account, then the change itself. The account
 * address alone is not proof — it is returned by `enrollPasskey` and visible
 * on-chain.
 */
export type CustodyOperation =
	| "set_cluster_membership"
	/**
	 * Prove possession of a passkey before it is enrolled. The account is the
	 * passkey's 64-byte P-256 public key (`x || y`) and the target its
	 * credential id.
	 */
	| "enroll_passkey"
	/**
	 * Delegate an agent. The account is the controller's smart account; the
	 * node computes the target from the terms sent as `delegation`.
	 */
	| "delegate_agent"
	/** Replace a delegated agent's terms, computed from the new terms. */
	| "update_agent_terms"
	/**
	 * Revoke an identity on its root's authority: a root itself, or a
	 * delegated agent by its controller. The account is the approving root's
	 * and the target `revocationTarget(did, reason)`.
	 */
	| "revoke_identity"
	/** Bind a device. The account is the identity DID's bytes, the target the label's. */
	| "bind_device"
	/** Unbind a device. The account is the identity DID's bytes, the target the credential id's. */
	| "revoke_device"
	/** Move a machine. The account is the machine DID's bytes, the target the new owner DID's. */
	| "transfer_machine_ownership"
	/** Add, list or revoke a machine-access grant, derived from the change sent as `machine_access`. */
	| "machine_access";

/** Request a custody challenge. */
export interface CustodyChallengeParams {
	/** The smart account being changed. */
	account_address: string;
	/** Which change the challenge should authorize. */
	operation: CustodyOperation;
	/**
	 * The operation's subject, hex-encoded — the credential being revoked, the
	 * session key being withdrawn.
	 *
	 * Omitted for `add_passkey`: the device being added does not exist yet at
	 * challenge time, so that challenge authorizes "add one device to this
	 * account, once, now" rather than naming a specific credential.
	 */
	target_hex?: string;
}

/** The challenge to sign. */
export interface CustodyChallengeResponse {
	/** Present this back with the signed assertion. */
	challenge_id: string;
	/** The 32-byte challenge digest, `0x`-prefixed. */
	challenge_hex: string;
	/**
	 * The WebAuthn challenge the passkey signs: the composite digest of
	 * `challenge_hex` under the account-owner context, base64url.
	 */
	webauthn_challenge: string;
	/** The account it was issued for. */
	account_address: string;
	/** The target the challenge is bound to, `0x`-prefixed. */
	target_hex: string;
	/**
	 * The 16-byte challenge nonce, `0x`-prefixed. With the chain id, account,
	 * operation and target it lets the caller recompute `challenge_hex` before
	 * signing.
	 */
	nonce_hex: string;
	/** The chain id the challenge is bound to. */
	chain_id?: number;
	/** How long it stays valid. */
	expires_in_secs: number;
	/** For agent delegation: the agent's DID. */
	agent_did?: string;
	/** For agent delegation: the completed terms. Send them back unchanged. */
	delegation?: Record<string, unknown>;
	/** For a terms update: whether the approval also withdraws the agent's live access tokens. */
	rotate_tokens?: boolean;
}

/** Proof of control accompanying a custody change. */
export interface CustodyAuthorization {
	/** From {@link CustodyChallengeResponse.challenge_id}. */
	challenge_id: string;
	/** A credential **already enrolled** on this account. */
	credential_id_hex: string;
	/** That credential's assertion over {@link CustodyChallengeResponse.webauthn_challenge}. */
	assertion: Record<string, unknown>;
	/**
	 * The hardware ML-DSA-65 leg, required when the account has one enrolled:
	 * a signature over the composite representative of the challenge digest
	 * under the account-owner context.
	 */
	ml_dsa_signature_hex?: string;
	/** For an account with no keystore on chain yet: its first passkey, which must derive the account. */
	anchor?: KeystoreAnchor;
}

export type PasskeySessionKind = "enroll";

export type PasskeySessionStatus =
	| "pending"
	| "in_flight"
	| "completed"
	| "failed"
	| "expired";

export interface CreatePasskeySessionParams {
	kind: PasskeySessionKind;
	/** Enroll: display name for the new identity. */
	display_name?: string;
	/** Enroll: CREATE2 salt (defaults to 0). */
	salt?: number;
	/** Display label shown in the browser ceremony. */
	label?: string;
}

export interface CreatePasskeySessionResponse {
	session_id: string;
	/** Path on the node's web API, e.g. `/auth/passkey?session=<id>`. */
	verification_path: string;
	status: PasskeySessionStatus;
	challenge_b64: string;
	expires_at_ms: number;
}

export interface PasskeySessionState {
	session_id: string;
	kind: PasskeySessionKind;
	status: PasskeySessionStatus;
	/** Handler result once `status === "completed"`. */
	result?: Record<string, unknown> | null;
	/** Failure detail once `status === "failed"`. */
	error?: string | null;
	expires_at_ms: number;
}

// ---- Identity / credential lifecycle --------------------------------------

export interface RevokeJwtParams {
	jti: string;
	/**
	 * Hex DID envelope proving control of the token's bearer DID or of the
	 * controller DID that authorized it. Bound to method `tenzro_revokeJwt`
	 * with the `jti` bytes as the params hash.
	 */
	did_envelope: string;
	reason?: string;
}

export interface RevokeJwtResponse {
	jti: string;
	status: string;
	cascade: string;
}

/**
 * RPC binding for the passkey-first custody surface on a Tenzro node.
 */
export class PasskeyRpcClient {
	private rpc: RpcClient;

	constructor(rpc: RpcClient) {
		this.rpc = rpc;
	}

	enroll(params: EnrollPasskeyParams): Promise<EnrollPasskeyResponse> {
		return this.rpc.call(
			"tenzro_enrollPasskey",
			params as unknown as Record<string, unknown>,
		);
	}

	/**
	 * Ask the node for the challenge an already-enrolled passkey must sign to
	 * authorize one custody change.
	 *
	 * Single-use and time-bounded, bound to this account and this operation.
	 * Issuing is unauthenticated by design: a challenge is worthless without an
	 * enrolled credential to sign it, and gating issuance would only stop a
	 * legitimate owner from starting.
	 */
	createCustodyChallenge(
		params: CustodyChallengeParams,
	): Promise<CustodyChallengeResponse> {
		return this.rpc.call(
			"tenzro_createCustodyChallenge",
			params as unknown as Record<string, unknown>,
		);
	}

	/**
	 * Create a pending browser-ceremony session (device-login flow). Open
	 * `<web base>` + `verification_path` in a browser, then poll
	 * {@link getSession} until the session is terminal.
	 */
	createSession(
		params: CreatePasskeySessionParams,
	): Promise<CreatePasskeySessionResponse> {
		return this.rpc.call(
			"tenzro_createPasskeySession",
			params as unknown as Record<string, unknown>,
		);
	}

	getSession(session_id: string): Promise<PasskeySessionState> {
		return this.rpc.call("tenzro_getPasskeySession", { session_id });
	}

	// ---- Identity / credential lifecycle ------------------------------

	/**
	 * Revoke a single JWT by its `jti`, cascading to the act-chain transitive
	 * closure. Admin-token-gated.
	 */
	revokeJwt(params: RevokeJwtParams): Promise<RevokeJwtResponse> {
		return this.rpc.call(
			"tenzro_revokeJwt",
			params as unknown as Record<string, unknown>,
		);
	}

}

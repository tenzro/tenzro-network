import type {
	CustodyAuthorization,
	CustodyChallengeParams,
	CustodyChallengeResponse,
} from "./passkey-rpc";
import { createHash, randomBytes } from "node:crypto";
import type { DpopProver } from "./access";
import { RpcClient } from "./rpc";
import { TypedTxClient } from "./typed-tx";
import {
	compositeMessageRepresentative,
	compositeSignatureJson,
	type HybridSigner,
} from "./wallet";

/** Signature context of a custody approval: the account-owner context. */
const ACCOUNT_OWNER_CONTEXT = new TextEncoder().encode("tenzro/rpc/account-owner");

/**
 * A machine root's approval of a custody challenge: its TPM or Secure
 * Enclave composite signature over `challenge_hex` under the account-owner
 * context.
 */
export interface MachineRootAuthorization {
	challenge_id: string;
	signature: ReturnType<typeof compositeSignatureJson>;
}

/**
 * The root's approval an `authorize` callback returns: a passkey's custody
 * assertion for a human root, a hardware signature for a machine root.
 */
export type RootAuthorization = CustodyAuthorization | MachineRootAuthorization;

function hexBytes(field: string, value: string): Uint8Array {
	const hex = hexField(field, value);
	const out = new Uint8Array(hex.length / 2);
	for (let i = 0; i < out.length; i++) out[i] = Number.parseInt(hex.slice(2 * i, 2 * i + 2), 16);
	return out;
}

async function signRootDigest(signer: HybridSigner, digestHex: string) {
	const mPrime = await compositeMessageRepresentative(
		ACCOUNT_OWNER_CONTEXT,
		hexBytes("challenge_hex", digestHex),
	);
	const [p256, pq] = await signer.signComposite(mPrime);
	return compositeSignatureJson(p256, pq);
}

/**
 * A root's signature over a `revoke_identity` challenge, as the approval in
 * a `RevokeIdentity` transaction carries it.
 */
export interface RootApproval {
	/** The root's P-256 key, `x || y` (64 bytes). */
	root_public_key: number[];
	/** The composite signature over the challenge, in its JSON form. */
	signature: Record<string, unknown>;
}

/** Gas a `RevokeIdentity` transaction is sent with. */
export const REVOCATION_GAS_LIMIT = 1_000_000;

function hexOf(bytes: Uint8Array): string {
	return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}

/** A machine root's approval of `challenge` with its hardware `signer`. */
export async function machineRootApproval(
	challenge: CustodyChallengeResponse,
	signer: HybridSigner,
): Promise<RootApproval> {
	return {
		root_public_key: Array.from(signer.p256PublicKey()),
		signature: (await signRootDigest(signer, challenge.challenge_hex)) as Record<string, unknown>,
	};
}

/**
 * A passkey root's approval: its P-256 key (`x || y`) and its WebAuthn
 * assertion over the challenge's `webauthn_challenge`, as the authenticator
 * returned it.
 */
export function passkeyRootApproval(
	publicKey: Uint8Array,
	assertion: { authenticatorData: Uint8Array; clientDataJSON: Uint8Array; signature: Uint8Array },
): RootApproval {
	return {
		root_public_key: Array.from(publicKey),
		signature: {
			classical: {
				form: "web_authn",
				authenticator_data: hexOf(assertion.authenticatorData),
				client_data_json: hexOf(assertion.clientDataJSON),
				signature: hexOf(assertion.signature),
			},
		},
	};
}

/** Approve `challenge` as a machine root with its hardware `signer`. */
export async function machineRootAuthorization(
	challenge: CustodyChallengeResponse,
	signer: HybridSigner,
): Promise<MachineRootAuthorization> {
	return {
		challenge_id: challenge.challenge_id,
		signature: await signRootDigest(signer, challenge.challenge_hex),
	};
}

/**
 * The `step_up` a machine root gives a held action, from the error data
 * `tenzro_agentAct` returned. Send the same action again with the result as
 * its `step_up`.
 */
export async function machineRootStepUp(
	stepUp: Record<string, unknown>,
	signer: HybridSigner,
): Promise<AgentStepUp> {
	const s = (stepUp.step_up ?? stepUp) as Record<string, unknown>;
	const field = (name: string): string => {
		const v = s[name];
		if (typeof v !== "string") throw new Error(`step_up.${name} is missing`);
		return v;
	};
	const key = signer.p256PublicKey();
	return {
		account: field("account"),
		nonce: field("nonce"),
		root_public_key: Array.from(key, (b) => b.toString(16).padStart(2, "0")).join(""),
		signature: await signRootDigest(signer, field("challenge_hex")),
	};
}

/**
 * The custody digest a machine root signs to cast its validator's governance
 * ballot on the network `chainId`: the validator account, the operation
 * `governance_ballot` and the target `proposal_id || vote || len || validator`,
 * under `nonce`.
 */
export function governanceBallotDigest(
	chainId: number | bigint,
	account: Uint8Array,
	proposalId: Uint8Array,
	vote: boolean,
	validator: Uint8Array,
	nonce: Uint8Array,
): Uint8Array {
	const enc = new TextEncoder();
	const target = new Uint8Array([...proposalId, vote ? 1 : 0, validator.length, ...validator]);
	const h = createHash("sha256");
	h.update(enc.encode("tenzro/custody-challenge/v2"));
	const chain = Buffer.alloc(8);
	chain.writeBigUInt64BE(BigInt(chainId));
	h.update(chain);
	for (const part of [account, enc.encode("governance_ballot"), target]) {
		const len = Buffer.alloc(4);
		len.writeUInt32BE(part.length);
		h.update(len);
		h.update(part);
	}
	h.update(nonce);
	return new Uint8Array(h.digest());
}

/**
 * The `root_approval` of a `GovernanceVote` for a validator whose identity is
 * the autonomous machine holding `signer`: the hardware key its machine DID
 * derives from approves exactly this ballot on the network `chainId`. Any
 * account may submit it.
 */
export async function machineRootBallot(
	signer: HybridSigner,
	chainId: number | bigint,
	proposalIdHex: string,
	vote: boolean,
	validatorHex: string,
): Promise<Record<string, unknown>> {
	const proposalId = hexBytes("proposal_id", proposalIdHex);
	const validator = hexBytes("validator", validatorHex);
	if (proposalId.length !== 32) throw new Error("proposal_id is 32 bytes");
	if (validator.length !== 32) throw new Error("validator is a 32-byte account");
	const nonce = new Uint8Array(randomBytes(16));
	const digest = governanceBallotDigest(chainId, validator, proposalId, vote, validator, nonce);
	const mPrime = await compositeMessageRepresentative(ACCOUNT_OWNER_CONTEXT, digest);
	const [p256, pq] = await signer.signComposite(mPrime);
	return {
		account: Array.from(validator),
		nonce: Array.from(nonce),
		root_public_key: Array.from(signer.p256PublicKey()),
		signature: compositeSignatureJson(p256, pq),
	};
}

function hexField(field: string, value: string): string {
	const hex = value.replace(/^0x/, "").toLowerCase();
	if (hex.length % 2 !== 0 || !/^[0-9a-f]*$/.test(hex)) {
		throw new Error(`${field} is not hex`);
	}
	return hex;
}

/**
 * Client for OAuth 2.1 + DPoP onboarding RPCs.
 *
 * Onboarding uses OAuth 2.1 (RFC 6749 successor) + DPoP-bound JWTs
 * (RFC 9449) + Rich Authorization Requests (RFC 9396). Participants —
 * humans, delegated agents under a human controller, and fully autonomous
 * agents — onboard via the three RPCs exposed here. Each call provisions
 * a TDIP identity (+ permissionless wallet) and returns a JWT bound to a
 * holder-supplied DPoP `jkt` (RFC 7638 thumbprint of the holder's
 * Ed25519 public key).
 *
 * Subsequent privileged calls (sign + send transaction, escrow create,
 * release/refund, etc.) authenticate by sending the JWT in the
 * `Authorization: DPoP <jwt>` header alongside a per-request DPoP proof
 * in the `DPoP` header. The SDK forwards both headers automatically when
 * the `TENZRO_BEARER_JWT` and `TENZRO_DPOP_PROOF` environment variables
 * are set in Node — see {@link RpcClient} for the transport-level wiring.
 */
export class AuthClient {
	constructor(private rpc: RpcClient) {}

	/**
	 * Onboard a new **human** participant — provisions a TDIP `did:tenzro:human:*`
	 * identity rooted in the caller's passkey, a permissionless wallet, and
	 * returns an OAuth 2.1 access token.
	 *
	 * The node only onboards a caller that proves it holds the passkey. This
	 * method requests the `enroll_passkey` custody challenge for exactly that
	 * passkey and hands it to `authorize`, which has the authenticator sign
	 * its `webauthn_challenge`. The SDK never sees the private key.
	 *
	 * @param displayName - human-readable label surfaced in approver UIs
	 * @param credentialIdHex - the passkey's credential id
	 * @param publicKeyHex - the passkey's P-256 public key, raw `x || y` or
	 *   SEC1 uncompressed (`04 || x || y`)
	 * @param authorize - signs the issued challenge on the caller's
	 *   authenticator; its `credential_id_hex` must be `credentialIdHex`
	 * @param dpopJkt - optional RFC 7638 JWK thumbprint of the holder's
	 *   Ed25519 public key. If supplied, the issued JWT is DPoP-bound to
	 *   that key and every subsequent privileged call must accompany the
	 *   bearer with a fresh DPoP proof signed by the same key. Strongly
	 *   recommended.
	 */
	async onboardHuman(
		displayName: string,
		credentialIdHex: string,
		publicKeyHex: string,
		authorize: (
			challenge: CustodyChallengeResponse,
		) => Promise<CustodyAuthorization>,
		dpopJkt?: string,
	): Promise<OnboardSession> {
		const credentialId = hexField("credentialIdHex", credentialIdHex);
		const publicKey = hexField("publicKeyHex", publicKeyHex);
		let passkeyXy: string;
		if (publicKey.length === 128) {
			passkeyXy = publicKey;
		} else if (publicKey.length === 130 && publicKey.startsWith("04")) {
			passkeyXy = publicKey.slice(2);
		} else {
			throw new Error(
				`publicKeyHex must be a raw 64-byte or SEC1 65-byte P-256 key, got ${publicKey.length / 2} bytes`,
			);
		}

		// The challenge names the passkey being enrolled and binds its
		// credential id, so it cannot enrol another credential.
		const challengeParams: CustodyChallengeParams = {
			account_address: passkeyXy,
			operation: "enroll_passkey",
			target_hex: credentialId,
		};
		const challenge = await this.rpc.call<CustodyChallengeResponse>(
			"tenzro_createCustodyChallenge",
			challengeParams as unknown as Record<string, unknown>,
		);
		const authorization = await authorize(challenge);

		const params: Record<string, unknown> = {
			display_name: displayName,
			credential_id: credentialId,
			public_key: passkeyXy,
			authorization,
		};
		if (dpopJkt) params.dpop_jkt = dpopJkt;
		return this.rpc.call<OnboardSession>("tenzro_onboardHuman", params);
	}

	/**
	 * Onboard a **machine** as a delegated agent of an existing
	 * `controllerDid` (a human). The machine's key lives in its TPM or
	 * Secure Enclave; `devicePublicKeyHex` is its public half. The controller
	 * approves the machine's terms, with its hardware key as the single
	 * serving node, through a `delegate_agent` custody challenge on their
	 * smart account; `authorize` signs it with a passkey enrolled there.
	 */
	async onboardDelegatedAgent(
		accountAddress: string,
		controllerDid: string,
		devicePublicKeyHex: string,
		machineId: string,
		capabilities: string[],
		delegationScope: unknown,
		authorize: (
			challenge: CustodyChallengeResponse,
		) => Promise<RootAuthorization>,
		dpopJkt?: string,
	): Promise<OnboardSession> {
		const challenge = await this.rpc.call<CustodyChallengeResponse>(
			"tenzro_createCustodyChallenge",
			{
				account_address: accountAddress,
				operation: "delegate_agent",
				device_public_key: devicePublicKeyHex,
				machine_id: machineId,
				delegation: {
					controller_did: controllerDid,
					agent_name: machineId,
					delegation_scope: delegationScope,
					capabilities,
				},
			},
		);
		const authorization = await authorize(challenge);
		const params: Record<string, unknown> = {
			controller_did: controllerDid,
			device_public_key: devicePublicKeyHex,
			machine_id: machineId,
			capabilities,
			delegation_scope: delegationScope,
			authorization,
		};
		if (dpopJkt) params.dpop_jkt = dpopJkt;
		return this.rpc.call<OnboardSession>(
			"tenzro_onboardDelegatedAgent",
			params,
		);
	}

	/**
	 * Take one action as a delegated agent, with the agent's access token on the
	 * transport. The serving node checks it against the agent's approved
	 * terms, signs it with its hardware key only when it is within them, and
	 * submits it; the chain checks it again at execution.
	 */
	async agentAct(action: AgentActRequest): Promise<AgentActResult> {
		return this.rpc.call<AgentActResult>(
			"tenzro_agentAct",
			action as unknown as Record<string, unknown>,
		);
	}

	/**
	 * The agent's next cumulative voucher on a channel its wallet funded,
	 * signed by the serving node with its hardware key for the agent. The
	 * node signs only a voucher the ledger would honor now.
	 */
	async agentVoucher(channelId: string, cumulativeAmount: string): Promise<AgentVoucherResult> {
		return this.rpc.call<AgentVoucherResult>("tenzro_agentVoucher", {
			channel_id: channelId,
			cumulative_amount: cumulativeAmount,
		});
	}

	/**
	 * Delegate an agent with its root's approval: a human's passkey, or a machine's hardware key (machineRootAuthorization).
	 *
	 * `terms` names the controller, the agent, its scope and limits, its
	 * capabilities, its serving nodes as `[{machine_did, operator_did}]`,
	 * `min_distinct_operators` and `expires_at_ms`. The node completes each
	 * serving node's key and returns a challenge over the completed terms;
	 * `authorize` signs it with a passkey enrolled on the controller's
	 * smart account. The serving nodes deliver the agent's access tokens; the
	 * result says how each delivery went.
	 */
	async delegateAgent(
		accountAddress: string,
		terms: AgentTerms,
		authorize: (
			challenge: CustodyChallengeResponse,
		) => Promise<RootAuthorization>,
	): Promise<DelegatedAgent> {
		const challenge = await this.rpc.call<CustodyChallengeResponse>(
			"tenzro_createCustodyChallenge",
			{
				account_address: accountAddress,
				operation: "delegate_agent",
				delegation: terms,
			},
		);
		const delegation = completedTerms(challenge);
		const authorization = await authorize(challenge);
		return this.rpc.call<DelegatedAgent>("tenzro_onboardDelegatedAgent", {
			delegation,
			authorization,
		});
	}

	/**
	 * Replace a delegated agent's terms with the controller's passkey. The
	 * agent's DID stays the same; with `rotateTokens` set, its live access
	 * tokens are withdrawn and the result counts them.
	 */
	async updateAgentTerms(
		accountAddress: string,
		agentDid: string,
		terms: AgentTerms,
		rotateTokens: boolean,
		authorize: (
			challenge: CustodyChallengeResponse,
		) => Promise<RootAuthorization>,
	): Promise<AgentTermsUpdate> {
		const challenge = await this.rpc.call<CustodyChallengeResponse>(
			"tenzro_createCustodyChallenge",
			{
				account_address: accountAddress,
				operation: "update_agent_terms",
				agent_did: agentDid,
				delegation: terms,
				rotate_tokens: rotateTokens,
			},
		);
		const delegation = completedTerms(challenge);
		const authorization = await authorize(challenge);
		return this.rpc.call<AgentTermsUpdate>("tenzro_updateAgentTerms", {
			agent_did: agentDid,
			delegation,
			rotate_tokens: rotateTokens,
			authorization,
		});
	}

	/**
	 * Revoke an identity with its root's approval (a passkey, or a machine's
	 * hardware key): a root revokes itself, a delegated agent is revoked by
	 * the controller its terms name, and a machine a root registered by that
	 * root. `accountAddress` is the approving root's account and
	 * `approverDid` the root (`did` itself by default).
	 *
	 * `approve` signs the `revoke_identity` challenge, which covers `did` and
	 * `reason`, and returns the root's key and signature
	 * ({@link passkeyRootApproval}, {@link machineRootApproval}). The SDK puts
	 * the approval into a `RevokeIdentity` transaction, signs it with
	 * `signer` (any account may send it; the approval authorises it) and
	 * submits it with `tenzro_revokeIdentity`. Every validator re-verifies the
	 * approval; once the transaction is in a block every node treats the
	 * identity as revoked and revokes its tokens, and revoking a root also
	 * revokes every agent it delegated.
	 */
	async revokeIdentity(
		signer: HybridSigner,
		accountAddress: string,
		did: string,
		approve: (challenge: CustodyChallengeResponse) => Promise<RootApproval>,
		options: { approverDid?: string; reason?: string } = {},
	): Promise<RevokeResponse> {
		const reason = options.reason ?? DEFAULT_REVOCATION_REASON;
		const challengeParams: CustodyChallengeParams = {
			account_address: accountAddress,
			operation: "revoke_identity",
			target_hex: revocationTarget(did, reason).toString("hex"),
		};
		const challenge = await this.rpc.call<CustodyChallengeResponse>(
			"tenzro_createCustodyChallenge",
			challengeParams as unknown as Record<string, unknown>,
		);
		const root = await approve(challenge);
		const op = {
			did,
			reason,
			approver_did: options.approverDid ?? did,
			approval: {
				account: Array.from(hexBytes("account_address", challenge.account_address)),
				nonce: Array.from(hexBytes("nonce_hex", challenge.nonce_hex)),
				root_public_key: root.root_public_key,
				signature: root.signature,
			},
		};
		return (await new TypedTxClient(this.rpc).sendVia("tenzro_revokeIdentity", signer, {
			kind: "RevokeIdentity",
			fields: { op },
			gasLimit: REVOCATION_GAS_LIMIT,
		})) as RevokeResponse;
	}

	/**
	 * Onboard a **fully autonomous agent**, rooted in its own secure
	 * element: `devicePublicKey` (hex) and the `machineId` of the element
	 * holding it. It has no human controller; instead its bond must already
	 * be locked on chain: an active `PostAgentBond` of at least 1 TNZO for
	 * the DID the device key derives.
	 */
	async onboardAutonomousAgent(
		devicePublicKey: string,
		machineId: string,
		dpopJkt?: string,
	): Promise<OnboardSession> {
		const params: Record<string, unknown> = {
			device_public_key: devicePublicKey,
			machine_id: machineId,
		};
		if (dpopJkt) params.dpop_jkt = dpopJkt;
		return this.rpc.call<OnboardSession>(
			"tenzro_onboardAutonomousAgent",
			params,
		);
	}

	/**
	 * Exchange a long-lived refresh token for a fresh access token. Mirrors
	 * OAuth 2.1 `grant_type=refresh_token`. Refresh tokens are opaque UUIDs
	 * with a 30-day TTL; access tokens are ES256 JWTs with a 1-hour TTL.
	 *
	 * `prover` holds the key the refresh token is bound to and proves it for
	 * this request; a refresh token issued without a key is bound to it from
	 * now on. Each refresh token is good for one exchange: keep the
	 * `refresh_token` the answer carries for the next one.
	 */
	async refreshToken(
		refreshToken: string,
		prover: DpopProver,
	): Promise<RefreshedToken> {
		return this.rpc.callWithProof<RefreshedToken>(
			"tenzro_refreshToken",
			{ refresh_token: refreshToken },
			prover,
		);
	}

	/**
	 * Revoke a single JWT by its `jti` claim. The token is added to the
	 * engine's revocation set and any subsequent validation fails.
	 *
	 * `didEnvelope` is the hex envelope proving control of the token's bearer
	 * DID **or** of the controller DID that authorized it, bound to method
	 * `tenzro_revokeJwt` with the `jti` bytes as the params hash. A `jti`
	 * travels in every audit row, so it is an identifier, not a credential.
	 */
	async revokeJwt(
		jti: string,
		didEnvelope: string,
		reason?: string,
	): Promise<RevokeResponse> {
		return this.rpc.call<RevokeResponse>("tenzro_revokeJwt", {
			jti,
			did_envelope: didEnvelope,
			reason: reason ?? "revoked via SDK",
		});
	}

	/**
	 * TDIP/GDPR Article 17 right-to-erasure. Hard-deletes a previously
	 * revoked identity from the registry and persistent storage.
	 *
	 * The identity MUST already be `Revoked` — call {@link revokeIdentity}
	 * first, wait for its transaction to land, and then call this. Distinct
	 * from `revokeIdentity`, which is a logical delete.
	 */
	async forgetIdentity(
		did: string,
	): Promise<{ did: string; status: string; note: string }> {
		return this.rpc.call("tenzro_forgetIdentity", { did });
	}

	/**
	 * **RFC 8693 OAuth 2.0 Token Exchange.** Exchange a parent JWT for a
	 * narrower child JWT bound to a different DPoP key, with a strictly
	 * subset of the parent's RAR grants and AAP capabilities. The child
	 * token's `controller_did` is set to the parent's `sub`, extending the
	 * act-chain by one hop.
	 *
	 * Subset enforcement is performed by the AS — `requestedRar` and
	 * `requestedAapCapabilities` must be a strict subset of what the parent
	 * already holds. Anything outside the parent's authority is rejected
	 * with JSON-RPC error code `-32002`.
	 *
	 * @param subjectToken - the parent JWT (validated for signature, exp,
	 *   and revocation by the AS)
	 * @param childBearerDid - DID that will be the `sub` of the child JWT
	 * @param childDpopJkt - RFC 7638 JWK thumbprint of the child holder's
	 *   Ed25519 public key. The child token will be DPoP-bound to it.
	 * @param requestedRar - typed scope envelope (RFC 9396) the child should
	 *   carry. Must be a subset of the parent's `authorization_details`.
	 * @param requestedAapCapabilities - AAP `aap_capabilities` claim list.
	 *   Must be a subset of the parent's capabilities.
	 * @param requestedTtlSecs - optional override; clamped to the engine's
	 *   `max_ttl_secs` and parent's remaining lifetime.
	 */
	async exchangeToken(
		subjectToken: string,
		childBearerDid: string,
		childDpopJkt: string,
		requestedRar: unknown,
		requestedAapCapabilities: unknown[],
		requestedTtlSecs?: number,
	): Promise<TokenExchangeResult> {
		const params: Record<string, unknown> = {
			subject_token: subjectToken,
			child_bearer_did: childBearerDid,
			child_dpop_jkt: childDpopJkt,
			requested_rar: requestedRar,
			requested_aap_capabilities: requestedAapCapabilities,
		};
		if (requestedTtlSecs !== undefined) {
			params.requested_ttl_secs = requestedTtlSecs;
		}
		return this.rpc.call<TokenExchangeResult>("tenzro_exchangeToken", params);
	}

	/**
	 * **RFC 7662 OAuth 2.0 Token Introspection.** Ask the AS whether a
	 * token is currently active and, if so, return its full claim set
	 * (RAR, AAP, cnf, controller_did, etc.). Per RFC 7662 §2.2 a failed
	 * validation returns `{ active: false }` with no other fields — the AS
	 * deliberately does not leak why the token is inactive.
	 *
	 * Use this from a downstream resource server that wants to validate a
	 * bearer token without re-implementing JWT signature checking.
	 */
	async introspectToken(token: string): Promise<IntrospectionResult> {
		return this.rpc.call<IntrospectionResult>("tenzro_introspectToken", {
			token,
		});
	}

	/**
	 * **RFC 8414 / RFC 9728 OAuth Authorization Server / Protected Resource
	 * Metadata.** Returns the same metadata document the AS publishes at
	 * `GET /.well-known/openid-configuration`. Useful for JSON-RPC-only
	 * clients (CLI, agents) that don't want to also speak HTTP discovery.
	 */
	async oauthDiscovery(): Promise<OAuthDiscovery> {
		return this.rpc.call<OAuthDiscovery>("tenzro_oauthDiscovery", []);
	}
}

/**
 * One of the three onboarding RPCs (or `linkWalletForAuth`) returns this
 * session bundle.
 */
export interface OnboardSession {
	/** Provisioned TDIP identity record. */
	identity: unknown;
	/** Provisioned permissionless wallet record (id + address). */
	wallet: unknown;
	/**
	 * OAuth 2.1 access token (ES256 JWT, optionally DPoP-bound). Send as
	 * `Authorization: Bearer <token>` on subsequent privileged calls. When
	 * DPoP-bound, also send a fresh `DPoP: <proof>` header.
	 */
	access_token: string;
	/** Always `"Bearer"` (RFC 6750 token type, even though DPoP-bound). */
	token_type?: string;
	/** Access-token lifetime in seconds (default 3600). */
	expires_in?: number;
	/**
	 * Long-lived refresh token (opaque UUID, 30-day TTL). Exchange via
	 * {@link AuthClient.refreshToken} when the access token expires. Treat
	 * as a secret — leakage allows minting access tokens until revocation.
	 */
	refresh_token?: string;
	/** Refresh-token lifetime in seconds (default 30 days). */
	refresh_token_expires_in?: number;
	/** `true` iff the access token requires a DPoP proof on every call. */
	dpop_bound?: boolean;
	/**
	 * RFC 9396 Rich Authorization Request payload echoed back, describing
	 * the act-chain and capabilities the token is authorized for.
	 */
	authorization_details?: unknown;
}

/**
 * Result of {@link AuthClient.refreshToken}. The refresh token is **not**
 * rotated in V1 — only the access token changes.
 */
export interface RefreshedToken {
	/** New access-token JWT. */
	access_token: string;
	/** `"DPoP"` for a key-bound token, else `"Bearer"`. */
	token_type?: string;
	/** Access-token lifetime in seconds. */
	expires_in?: number;
	/** `true` iff the new access token carries a `cnf.jkt` claim. */
	dpop_bound?: boolean;
	/** The refresh token for the next exchange; the one presented is spent. */
	refresh_token: string;
	/** Seconds until `refresh_token` expires. */
	refresh_token_expires_in: number;
}

/** The completed terms a delegation challenge carries. */
function completedTerms(
	challenge: CustodyChallengeResponse,
): Record<string, unknown> {
	if (!challenge.delegation) {
		throw new Error("the node returned no completed delegation terms");
	}
	return challenge.delegation;
}

/** A serving node assigned to a delegated agent. */
export interface ServingNodeRef {
	/** The node's machine identity. */
	machine_did: string;
	/** The identity operating the node. */
	operator_did: string;
	/** Thumbprint of the node's key for this agent. */
	dpop_jkt?: string;
}

/** What a controller approves for a delegated agent. */
export interface AgentTerms {
	controller_did: string;
	agent_name: string;
	delegation_scope?: {
		/** Wei, canonical decimal. */
		max_transaction_value?: string;
		/** Wei, canonical decimal. */
		max_daily_spend?: string;
		allowed_operations?: string[];
		allowed_payment_protocols?: string[];
		allowed_chains?: string[];
		allowed_models?: string[];
		/** Addresses (hex) the agent may pay. */
		allowed_counterparties?: string[];
		/**
		 * The KYC tier (1 basic, 2 enhanced, 3 full) every counterparty the
		 * agent pays must hold: a live `kyc` claim under `registry`, a token
		 * id, from an issuer that token names.
		 */
		counterparty_kyc?: { min_tier: number; registry: string };
		/**
		 * The most the facilitator and relayer lines of a settlement the
		 * agent opens may take together, basis points of the value divided.
		 */
		max_split_fee_bps?: number;
	};
	capabilities?: string[];
	serving_nodes: ServingNodeRef[];
	min_distinct_operators?: number;
	expires_at_ms?: number;
}

/** Result of `delegateAgent`. */
export interface DelegatedAgent {
	identity: {
		did: string;
		identity_type: string;
		controller_did: string;
		capabilities: string[];
		status: string;
	};
	/** Watch-only wallet whose address derives from the agent's DID. */
	wallet: { wallet_id: string; address: string };
	serving_nodes: ServingNodeRef[];
	min_distinct_operators: number;
	expires_at_ms?: number | null;
	/** How delivering the agent's access tokens to its serving nodes went. */
	token_delivery?: unknown;
}

/** One action a delegated agent asks its serving node to take. */
export interface AgentActRequest {
	operation: string;
	/** Recipient address, hex, when the action moves value. */
	counterparty?: string;
	/** Value moved, wei, decimal. */
	amount?: string;
	/** Chain; `tenzro` when omitted. */
	chain?: string;
	payment_protocol?: string;
	model?: string;
	/** Asset moved other than TNZO: a token id, `0x` hex. */
	asset?: string;
	/** USD price of the value moved, micro-units; required with `asset`. */
	usd_e6?: number | bigint;
	/** For `pay`: what the payment pays for. */
	payment?: AgentPayment;
	/**
	 * The controller's step-up of this exact action, when its terms hold it:
	 * the root signs the challenge a refused attempt returns in
	 * `error.data.step_up`, and the same action is sent again with it.
	 */
	step_up?: AgentStepUp;
}

/**
 * The root's approval of one held action (`agent_step_up`): `account`,
 * `nonce` and the root's P-256 key `root_public_key` (x||y) hex, and its
 * composite `signature` over the challenge digest under the account-owner
 * context: a passkey assertion (`web_authn` form) for a human root, or the
 * TPM or Secure Enclave signature (`raw` form, with `pq` when the machine
 * has an ML-DSA-65 key enrolled) for a machine root ({@link machineRootStepUp}).
 */
export interface AgentStepUp {
	account: string;
	nonce: string;
	root_public_key: string;
	signature: {
		classical:
			| { form: "raw"; signature: string }
			| { form: "web_authn"; authenticator_data: string; client_data_json: string; signature: string };
		pq?: string;
	};
}

/** The payment an agent's `pay` action makes. */
export interface AgentPayment {
	/** The payment id the record is keyed by. */
	payment_id: string;
	/** SHA-256 of the request paid for, hex. */
	request_digest: string;
	/** The payee's quote digest, hex, or 64 zeros for none. */
	quote_digest: string;
}

/** Result of `agentAct`. */
export interface AgentActResult {
	agent_did: string;
	machine_did: string;
	nonce: number;
	escrow_id?: string | null;
	/** The payment record's reference, for `pay`. */
	pay_ref?: string | null;
	tx_hash: unknown;
}

/** Result of `agentVoucher`. */
export interface AgentVoucherResult {
	/** The voucher, signed by the serving node for the agent. */
	voucher: Record<string, unknown>;
	/** What the ledger would pay on it now, decimal. */
	payout: string;
}

/** Result of `updateAgentTerms`. */
export interface AgentTermsUpdate {
	agent_did: string;
	/** The full updated terms, serving nodes included. */
	delegation: Record<string, unknown>;
	/** How delivering the agent's access tokens went. */
	token_delivery?: unknown;
	/** Access tokens withdrawn, when the update rotated them. */
	tokens_revoked?: number;
}

/** Result of `revokeJwt` / `revokeIdentity`. */
export interface RevokeResponse {
	/** `"revoked"` for a token; `"admitted"` for an identity. */
	status?: string;
	/**
	 * For a token: the JTIs invalidated by this call (>1 indicates cascade).
	 * An identity's tokens are revoked by every node once its revocation is
	 * in a block.
	 */
	affected_jti_count?: number;
	/** For an identity: the root whose approval the chain verifies. */
	approver_did?: string;
	/** For an identity: the `RevokeIdentity` transaction. */
	tx_hash?: string;
}

/** The reason a revocation records when none is given. */
export const DEFAULT_REVOCATION_REASON = "revoked by its root";

/**
 * What a root signs to revoke `did` for `reason`: the `target` of a
 * `revoke_identity` custody challenge,
 * SHA-256("tenzro/identity-revocation/v1" ‖ len ‖ did ‖ len ‖ reason) with
 * 4-byte big-endian lengths.
 */
export function revocationTarget(did: string, reason: string): Buffer {
	const h = createHash("sha256");
	h.update(Buffer.from("tenzro/identity-revocation/v1", "utf8"));
	for (const f of [Buffer.from(did, "utf8"), Buffer.from(reason, "utf8")]) {
		const len = Buffer.alloc(4);
		len.writeUInt32BE(f.length, 0);
		h.update(len);
		h.update(f);
	}
	return h.digest();
}

/**
 * Result of {@link AuthClient.exchangeToken} — the issued child JWT and
 * its delegation envelope per RFC 8693 §2.2.
 */
export interface TokenExchangeResult {
	/** The newly-issued child JWT (ES256, DPoP-bound to `child_dpop_jkt`). */
	access_token: string;
	/** Lifetime of the child token in seconds. */
	expires_in: number;
	/** Always `"DPoP"` — child tokens are always DPoP-bound (RFC 9449). */
	token_type: string;
	/**
	 * Always `"urn:ietf:params:oauth:token-type:jwt"` — the format of the
	 * issued token (RFC 8693 §2.2).
	 */
	issued_token_type: string;
	/**
	 * Echo of the delegation envelope: `{ controller_did, depth, … }`. The
	 * exact shape is defined by `tenzro_auth::TokenExchangeOutcome` — kept
	 * as opaque JSON in the SDK to avoid recapitulating every AAP claim
	 * type.
	 */
	delegation: unknown;
}

/**
 * Result of {@link AuthClient.introspectToken} — the RFC 7662 §2.2
 * introspection response. When `active` is `false`, all other fields are
 * absent (the AS does not leak why the token is inactive).
 *
 * The full claim set (RAR `authorization_details`, AAP `aap_*` claims,
 * `cnf`, `controller_did`, etc.) is returned as flat JSON properties to
 * keep the SDK decoupled from `tenzro-auth` internals — callers that
 * need typed access can narrow the fields themselves.
 */
export interface IntrospectionResult {
	/**
	 * `true` iff the token validates and its controller chain is not
	 * revoked.
	 */
	active: boolean;
	/** Subject — bearer DID. Present iff `active`. */
	sub?: string;
	/** Issuer — node DID. Present iff `active`. */
	iss?: string;
	/** Audience — typically the resource server URL. Present iff `active`. */
	aud?: string;
	/** Issued-at, Unix seconds. Present iff `active`. */
	iat?: number;
	/** Not-before, Unix seconds. Present iff `active`. */
	nbf?: number;
	/** Expires-at, Unix seconds. Present iff `active`. */
	exp?: number;
	/** JWT id. Present iff `active`. */
	jti?: string;
	/** `"DPoP"` for tokens with a `cnf.jkt`; absent otherwise. */
	token_type?: string;
	/**
	 * RFC 7800 confirmation claim — `{ jkt: "<thumbprint>" }` for
	 * DPoP-bound tokens.
	 */
	cnf?: { jkt: string };
	/** The authorizing DID (parent of `sub` in the act-chain). */
	controller_did?: string;
	/** RFC 9396 typed scope envelope. */
	authorization_details?: unknown;
	/** AAP claims — present only when set on the token. */
	aap_agent?: unknown;
	aap_task?: unknown;
	aap_capabilities?: unknown;
	aap_delegation?: unknown;
	aap_context?: unknown;
	aap_audit?: unknown;
}

/**
 * Result of {@link AuthClient.oauthDiscovery} — the OAuth 2.0
 * authorization-server metadata document (RFC 8414) augmented with the
 * AAP-specific extensions.
 *
 * Mirrors the document published at
 * `GET /.well-known/openid-configuration` on the AS.
 */
export interface OAuthDiscovery {
	/** Issuer DID — typically `did:tenzro:node:<node_id>`. */
	issuer: string;
	/**
	 * `POST` endpoint for authorization-code, refresh-token, and
	 * token-exchange grants.
	 */
	token_endpoint: string;
	/** `POST` endpoint for RFC 7662 token introspection. */
	introspection_endpoint: string;
	/** `POST` endpoint for RFC 7009 token revocation. */
	revocation_endpoint: string;
	/**
	 * All grant types the AS accepts. Includes
	 * `urn:ietf:params:oauth:grant-type:token-exchange`,
	 * `authorization_code`, and `refresh_token`.
	 */
	grant_types_supported: string[];
	/**
	 * Authentication methods at the token endpoint (`"none"` for public
	 * clients, `"private_key_jwt"`).
	 */
	token_endpoint_auth_methods_supported: string[];
	/** Authorization-code response types — currently `["code"]`. */
	response_types_supported: string[];
	/**
	 * DPoP signing algorithms accepted on proofs — currently `["EdDSA"]`
	 * (Ed25519 per RFC 8037).
	 */
	dpop_signing_alg_values_supported: string[];
	/**
	 * RFC 9396 RAR `type` values the AS recognizes: `transfer`,
	 * `create_escrow`, `discharge_escrow`, `inference`, `stake`, `vote`,
	 * `contract`, `register_identity`, `resource_invocation`.
	 */
	authorization_details_types_supported: string[];
	/**
	 * AAP claim names the AS issues — `aap_agent`, `aap_task`,
	 * `aap_capabilities`, `aap_delegation`, `aap_context`,
	 * `aap_audit`.
	 */
	aap_claims_supported: string[];
}

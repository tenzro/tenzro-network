import { TypedTxClient } from "@tenzro/core";
import type { HybridSigner, RpcClient, TypedTransaction } from "@tenzro/core";

/**
 * Compute rental: provider bonds, compute claims, the observed price feed and
 * renting capacity.
 *
 * A provider posts a compute bond for its machine DID. Validators probe every
 * bonded provider and freeze one SLA verdict per provider and hour; those
 * availability verdicts are what every payment here settles on.
 *
 * - Renting capacity now is a stream escrow: a signed `CreateEscrow` whose
 *   release is `Stream { rate_per_epoch, epoch_ms }` and whose payee is the
 *   provider's bonded address ({@link ComputeClient.rent}). It accrues one
 *   epoch at a time; an hour the validators judged the provider unavailable is
 *   never paid out of it and returns to the renter when the stream is stopped.
 * - Buying capacity ahead is a compute claim, written and bought with the
 *   `ComputeClaim` transaction and read here ({@link ComputeClient.getClaim}).
 *   A storage claim is the same record with `storage_descriptor` set.
 */

/** The hour validators freeze one SLA verdict for, in ms: the epoch a rental streams over by default. */
export const SLA_EPOCH_MS = 3_600_000;

/** A provider's compute bond, as chain state records it. */
export interface ComputeBond {
	provider_did: string;
	/** The account that posted the bond: the payee of a rental, and where a returned bond goes. */
	provider_address: string;
	/** Bonded amount in wei, decimal. */
	amount: string;
	/** "Active", "Cooldown", "Returned" or "Slashed". */
	status: string;
	/** Unix ms at which a withdrawal may be finalized; set only in Cooldown. */
	cooldown_until: number | null;
	/** The bond vault address, hex. */
	vault: string;
	/** Whether the bond backs its provider: active and at least the governed minimum. */
	is_eligible: boolean;
	/** Wei that counts toward admission: zero once the bond leaves Active. */
	effective_amount: string;
}

/** The governed dials a provider needs before it posts a compute bond. */
export interface ComputeBondParams {
	/** The governed compute bond minimum in wei, decimal. */
	min_bond_wei: string;
	/** Milliseconds a withdrawal sits in Cooldown before it can be finalized. */
	cooldown_ms: number;
}

/** Where a compute claim is in its life. */
export type ClaimState =
	| "offered"
	| "held"
	| "delivered"
	| "cancelled"
	| "lapsed";

/**
 * A u128 the node writes as a JSON number up to `u64::MAX` and as a decimal
 * string above it; the RPC client reads integers past 2^53 as bigints.
 */
export type WireU128 = number | bigint | string;

/** A compute claim: capacity a bonded provider promised for hour-aligned terms, settled each hour on the SLA verdict for its bond. */
export interface ComputeClaim {
	claim_id: string;
	/** Hex of the writer's address. */
	writer: string;
	/** Hex of the holder's address, once bought. */
	holder: string | null;
	/** 1 cpu, 2 consumer GPU, 3 datacenter GPU, 4 multi-accelerator: the writer's statement. */
	hardware_class: number;
	/** ISO 3166-1 alpha-2 region, or empty. */
	region: string;
	/** First hour of delivery, Unix ms. */
	delivery_start_ms: number;
	/** Hours delivered. */
	epochs: number;
	/** Price per hour, wei. */
	strike_per_epoch: WireU128;
	/** The compute bond (or storage stake) delivering the claim. */
	provider_did: string;
	/** For a storage claim: hex SHA-256 of the object descriptor the bond keeps retrievable. */
	storage_descriptor: string | null;
	/** The registered unit reserved capacity is stated in, for a claim on metered capacity. */
	unit: string | null;
	/** Units of `unit` reserved per hour. */
	units_per_epoch: WireU128;
	/** Hours settled so far. */
	epochs_settled: number;
	/** Writer collateral still in the vault, wei. */
	collateral: WireU128;
	/** Holder payment still in the vault, wei. */
	payment: WireU128;
	/** Where the claim is in its life. */
	state: { state: ClaimState };
	/** What a buyer pays: `strike_per_epoch * epochs`, decimal. */
	total_strike: string;
	/** End of delivery, Unix ms. */
	delivery_end_ms: number;
	/** The claim's vault address, hex. */
	vault: string;
}

/** The claims one party is a side of. */
export interface ComputeClaimList {
	/** Every claim of the party, beyond the page returned. */
	total: number;
	/** The claims returned, oldest first. */
	claims: ComputeClaim[];
}

/** A filter on the observed price feed. Every field is optional. */
export interface PriceFeedQuery {
	model_id?: string;
	/** An announced hardware class: "cpu", "consumer_gpu", "datacenter_gpu" or "multi_accelerator". */
	hardware_class?: string;
	/** An announced region. */
	region?: string;
	/** Only entries at least two distinct validators observed. */
	attested_only?: boolean;
	/** Most entries to return (node default 100, at most 1000). */
	limit?: number;
}

/** One provider and model in the price feed. */
export interface PriceFeedEntry {
	/** The provider's address, hex. */
	provider: string;
	model_id: string;
	/** The provider's announced hardware class (a claim). */
	hardware_class: string;
	/** The provider's announced region (a claim). */
	region: string;
	observations: number;
	distinct_observers: number;
	/** Whether enough distinct validators observed it to enter the index. */
	attested: boolean;
	success_rate_bps: number;
	latency_p50_ms: number | null;
	latency_p90_ms: number | null;
	/** Observed price per 1000 output tokens, wei, decimal. */
	price_per_1k_output_tokens_wei: string | null;
	/** Observed price per second of served compute, wei, decimal. */
	price_per_compute_second_wei: string | null;
	last_observed_ms: number;
}

/** The observed price feed: prices, latencies and success rates are validator observations; hardware class and region are claims. */
export interface PriceFeed {
	window_ms: number;
	min_distinct_observers: number;
	/** Entries matching the query, beyond the page returned. */
	total: number;
	entries: PriceFeedEntry[];
	claims_note: string;
}

/** The terms of a rental. */
export interface RentRequest {
	/** The provider's bonded address (32-byte hex): the account that posted its compute bond. */
	providerAddress: string;
	/** Paid per elapsed epoch, smallest unit of `assetId`. */
	ratePerEpoch: bigint;
	/** Epochs rented; the escrow locks `ratePerEpoch * epochs`. */
	epochs: number;
	/** Epoch length in ms; {@link SLA_EPOCH_MS} by default. */
	epochMs?: number;
	/** "TNZO" (default) or a token id, `0x`-prefixed hex. */
	assetId?: string;
	/** USD price of the amount in micro-units; required for an asset other than TNZO. */
	usdE6?: number;
	/** An opaque 32-byte hex reference, so the application can find the rental again with `tenzro_listEscrowsByPayer`. */
	reference?: string;
}

const U64_MAX = 0xffffffffffffffffn;

/** A u128 the way the node encodes it, so the signing payload it returns decodes to exactly what was built. */
function wireU128(v: bigint): WireU128 {
	if (v <= BigInt(Number.MAX_SAFE_INTEGER)) return Number(v);
	return v <= U64_MAX ? v : v.toString();
}

/** `hex` as 32 bytes of lowercase hex without a prefix. */
function hex32(hex: string, what: string): string {
	const h = (hex.startsWith("0x") ? hex.slice(2) : hex).toLowerCase();
	if (!/^[0-9a-f]{64}$/.test(h)) throw new Error(`${what} must be 32 bytes of hex`);
	return h;
}

/**
 * The `CreateEscrow` transaction for a rental signed at `nowMs`.
 *
 * The stream accrues from the block that funds it, not from `nowMs`, so the
 * escrow expires one epoch after the term would end if it were funded now:
 * the funding block has that long to land and the whole term still accrues.
 * Accrual never exceeds the locked amount, so the extra epoch pays nothing more.
 */
export function rentTransaction(
	request: RentRequest,
	nowMs: number,
): TypedTransaction {
	const epochMs = request.epochMs ?? SLA_EPOCH_MS;
	const { ratePerEpoch, epochs } = request;
	if (
		ratePerEpoch <= 0n ||
		!Number.isSafeInteger(epochs) ||
		epochs <= 0 ||
		!Number.isSafeInteger(epochMs) ||
		epochMs <= 0
	) {
		throw new Error(
			"a rental pays a positive rate over a positive number of positive epochs",
		);
	}
	const amount = ratePerEpoch * BigInt(epochs);
	if (amount > (1n << 128n) - 1n)
		throw new Error("ratePerEpoch * epochs overflows");
	const expiresAt = nowMs + (epochs + 1) * epochMs;
	if (!Number.isSafeInteger(expiresAt))
		throw new Error("the rental term overflows");
	return {
		kind: "CreateEscrow",
		fields: {
			payee: hex32(request.providerAddress, "providerAddress").match(/../g)!.map((b) => parseInt(b, 16)),
			amount: wireU128(amount),
			asset_id: request.assetId ?? "TNZO",
			usd_e6: request.usdE6 ?? 0,
			expires_at: expiresAt,
			release_conditions: {
				Stream: { rate_per_epoch: wireU128(ratePerEpoch), epoch_ms: epochMs },
			},
			reference: request.reference === undefined ? null : hex32(request.reference, "reference"),
		},
	};
}

/** Compute rental client: bonds, claims, the price feed and renting. */
export class ComputeClient {
	constructor(private rpc: RpcClient) {}

	/** The governed compute bond minimum and withdrawal cooldown (`tenzro_computeBondParams`). */
	bondParams(): Promise<ComputeBondParams> {
		return this.rpc.call<ComputeBondParams>("tenzro_computeBondParams", []);
	}

	/** The compute bond posted for `providerDid`, or null when it has never posted one (`tenzro_getComputeBond`). */
	getBond(providerDid: string): Promise<ComputeBond | null> {
		return this.rpc.call<ComputeBond | null>("tenzro_getComputeBond", [
			{ provider_did: providerDid },
		]);
	}

	/** Every compute bond on chain (`tenzro_listComputeBonds`). */
	async listBonds(): Promise<ComputeBond[]> {
		const result = await this.rpc.call<{ count: number; bonds: ComputeBond[] }>(
			"tenzro_listComputeBonds",
			[],
		);
		return result.bonds;
	}

	/** One compute claim from chain state (`tenzro_computeGetClaim`); the node answers an error when there is none. */
	getClaim(claimId: string): Promise<ComputeClaim> {
		return this.rpc.call<ComputeClaim>("tenzro_computeGetClaim", {
			claim_id: claimId,
		});
	}

	/** The claims `party` (hex address) has written, held or been pledged, oldest first (`tenzro_computeListClaims`). */
	listClaims(party: string, limit?: number): Promise<ComputeClaimList> {
		return this.rpc.call<ComputeClaimList>(
			"tenzro_computeListClaims",
			limit === undefined ? { party } : { party, limit },
		);
	}

	/** What validators observed each provider charge, how fast it served and how often it failed (`tenzro_computePriceFeed`). */
	priceFeed(query: PriceFeedQuery = {}): Promise<PriceFeed> {
		const params = Object.fromEntries(
			Object.entries(query).filter(([, v]) => v !== undefined),
		);
		return this.rpc.call<PriceFeed>("tenzro_computePriceFeed", params);
	}

	/**
	 * Rent capacity from a bonded provider: sign and submit the stream escrow
	 * {@link rentTransaction} builds, returning `tenzro_sendRawTransaction`'s
	 * answer. The provider draws each accrued epoch with `ClaimEscrowStream`;
	 * the renter stops the rental with `RefundEscrow`.
	 */
	rent(signer: HybridSigner, request: RentRequest): Promise<unknown> {
		return new TypedTxClient(this.rpc).send(
			signer,
			rentTransaction(request, Date.now()),
		);
	}
}

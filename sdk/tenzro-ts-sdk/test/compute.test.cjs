// Compute rental and data availability against a recording node: the reads
// send the params the node's handlers read and return their answers; renting
// signs a CreateEscrow with stream release, checked against the node's
// signing payload before anything is signed.
const test = require("node:test");
const assert = require("node:assert/strict");
const crypto = require("node:crypto");
const sdk = require("../dist/index.js");

const PROVIDER = "0x" + "ab".repeat(32);
const BOND = {
	provider_did: "did:tenzro:machine:a",
	provider_address: PROVIDER,
	amount: "5",
	status: "Active",
	cooldown_until: null,
	vault: "0xcd",
	is_eligible: true,
	effective_amount: "5",
};

/** A node answering each method from `answers` and recording each call. */
function node(answers) {
	const sent = [];
	return {
		sent,
		call: async (method, params) => {
			sent.push({ method, params });
			const a = answers[method];
			return typeof a === "function" ? a(params) : a;
		},
	};
}

const u = (v, n, signed = false) => {
	const b = Buffer.alloc(n);
	if (signed) b.writeBigInt64LE(BigInt(v));
	else b.writeBigUInt64LE(BigInt(v));
	return b;
};
const unhex = (h) => Buffer.from(h.replace(/^0x/, ""), "hex");

/** The node's `plain` signing payload: its own JSON encoding of the type, integers exact. */
function plainPayload(r) {
	const encoded = sdk.stringifyExact(r.tx_type);
	const digest = crypto
		.createHash("sha256")
		.update(
			Buffer.concat([
				u(r.chain_id, 8),
				unhex(r.from),
				unhex(r.to),
				u(r.nonce, 8),
				u(r.gas_limit, 8),
				u(r.gas_price, 8),
				u(r.timestamp, 8, true),
				u(r.valid_until, 8, true),
				Buffer.from(encoded),
			]),
		)
		.digest();
	return {
		kind: "plain",
		digest: digest.toString("hex"),
		tx_type_json: encoded,
	};
}

const signer = {
	p256PublicKey: () => new Uint8Array(64).fill(7),
	mlDsaPublicKey: () => null,
	signComposite: async () => [new Uint8Array(64).fill(1), null],
};

test("a rental is a stream escrow to the bonded address, expiring a term and one epoch on", () => {
	const tx = sdk.rentTransaction(
		{
			providerAddress: PROVIDER,
			ratePerEpoch: 7n,
			epochs: 3,
			reference: "0x" + "09".repeat(32),
		},
		1000,
	);
	assert.equal(tx.kind, "CreateEscrow");
	assert.deepEqual(tx.fields, {
		payee: new Array(32).fill(0xab),
		amount: 21,
		asset_id: "TNZO",
		usd_e6: 0,
		expires_at: 1000 + 4 * sdk.SLA_EPOCH_MS,
		release_conditions: {
			Stream: { rate_per_epoch: 7, epoch_ms: sdk.SLA_EPOCH_MS },
		},
		reference: "09".repeat(32),
	});
});

test("rental amounts are encoded as the node encodes a u128", () => {
	const big = sdk.rentTransaction(
		{
			providerAddress: PROVIDER,
			ratePerEpoch: 5_000_000_000_000_000_123n,
			epochs: 1,
		},
		0,
	);
	assert.equal(big.fields.amount, 5_000_000_000_000_000_123n);
	const huge = sdk.rentTransaction(
		{ providerAddress: PROVIDER, ratePerEpoch: 1n << 64n, epochs: 2 },
		0,
	);
	assert.equal(huge.fields.amount, (2n << 64n).toString());
	assert.equal(
		huge.fields.release_conditions.Stream.rate_per_epoch,
		(1n << 64n).toString(),
	);
	assert.equal(huge.fields.reference, null);
});

test("a rental of nothing, or to a malformed address, is refused", () => {
	for (const r of [
		{ providerAddress: PROVIDER, ratePerEpoch: 0n, epochs: 3 },
		{ providerAddress: PROVIDER, ratePerEpoch: 7n, epochs: 0 },
		{ providerAddress: PROVIDER, ratePerEpoch: 7n, epochs: 3, epochMs: 0 },
		{ providerAddress: "0xab", ratePerEpoch: 7n, epochs: 3 },
		{ providerAddress: PROVIDER, ratePerEpoch: 1n << 127n, epochs: 4 },
	]) {
		assert.throws(() => sdk.rentTransaction(r, 0));
	}
});

test("rent signs the escrow the node encodes, amounts beyond 2^53 included, and submits it", async () => {
	const n = node({
		tenzro_getNonce: "0x2",
		tenzro_estimateGas: "0x7a120",
		eth_chainId: "0x539",
		eth_gasPrice: "0x1",
		tenzro_getSigningPayload: plainPayload,
		tenzro_sendRawTransaction: { hash: "0x01" },
	});
	const rate = 1_234_567_890_123_456_789n;
	const out = await new sdk.ComputeClient(n).rent(signer, {
		providerAddress: BOND.provider_address,
		ratePerEpoch: rate,
		epochs: 2,
	});
	assert.deepEqual(out, { hash: "0x01" });
	const sent = n.sent.find(
		(s) => s.method === "tenzro_sendRawTransaction",
	).params;
	const escrow = sent.tx_type.CreateEscrow;
	assert.equal(escrow.amount, 2n * rate);
	assert.deepEqual(escrow.release_conditions, {
		Stream: { rate_per_epoch: rate, epoch_ms: sdk.SLA_EPOCH_MS },
	});
	const room = escrow.expires_at - sent.timestamp;
	assert.ok(
		room > 3 * sdk.SLA_EPOCH_MS - 5000 && room <= 3 * sdk.SLA_EPOCH_MS,
		`${room}`,
	);
});

test("rent submits nothing when the node's payload names another escrow", async () => {
	const n = node({
		tenzro_getNonce: "0x2",
		tenzro_estimateGas: "0x7a120",
		eth_chainId: "0x539",
		eth_gasPrice: "0x1",
		tenzro_getSigningPayload: (r) =>
			plainPayload({
				...r,
				tx_type: {
					CreateEscrow: {
						...r.tx_type.CreateEscrow,
						payee: new Array(32).fill(1),
					},
				},
			}),
	});
	await assert.rejects(
		new sdk.ComputeClient(n).rent(signer, {
			providerAddress: PROVIDER,
			ratePerEpoch: 7n,
			epochs: 1,
		}),
		/signing payload/,
	);
	assert.ok(!n.sent.some((s) => s.method === "tenzro_sendRawTransaction"));
});

test("compute reads send what the node reads and return its answer", async () => {
	const claim = {
		claim_id: "c1",
		state: { state: "held" },
		storage_descriptor: "ee",
		total_strike: "14",
	};
	const feed = {
		window_ms: 86_400_000,
		min_distinct_observers: 2,
		total: 0,
		entries: [],
		claims_note: "n",
	};
	const n = node({
		tenzro_computeBondParams: { min_bond_wei: "1000", cooldown_ms: 60000 },
		tenzro_getComputeBond: BOND,
		tenzro_listComputeBonds: { count: 1, bonds: [BOND] },
		tenzro_computeGetClaim: claim,
		tenzro_computeListClaims: { total: 3, claims: [claim] },
		tenzro_computePriceFeed: feed,
	});
	const c = new sdk.TenzroClient({ endpoint: "http://node.test" }, n).compute;
	const cases = [
		[
			() => c.bondParams(),
			"tenzro_computeBondParams",
			[],
			{ min_bond_wei: "1000", cooldown_ms: 60000 },
		],
		[
			() => c.getBond("did:tenzro:machine:a"),
			"tenzro_getComputeBond",
			[{ provider_did: "did:tenzro:machine:a" }],
			BOND,
		],
		[() => c.listBonds(), "tenzro_listComputeBonds", [], [BOND]],
		[
			() => c.getClaim("c1"),
			"tenzro_computeGetClaim",
			{ claim_id: "c1" },
			claim,
		],
		[
			() => c.listClaims(PROVIDER),
			"tenzro_computeListClaims",
			{ party: PROVIDER },
			{ total: 3, claims: [claim] },
		],
		[
			() => c.listClaims(PROVIDER, 1),
			"tenzro_computeListClaims",
			{ party: PROVIDER, limit: 1 },
			{ total: 3, claims: [claim] },
		],
		[
			() =>
				c.priceFeed({
					hardware_class: "cpu",
					attested_only: true,
					region: undefined,
				}),
			"tenzro_computePriceFeed",
			{ hardware_class: "cpu", attested_only: true },
			feed,
		],
		[() => c.priceFeed(), "tenzro_computePriceFeed", {}, feed],
	];
	for (const [call, method, params, want] of cases) {
		n.sent.length = 0;
		assert.deepEqual(await call(), want, method);
		assert.equal(n.sent.length, 1);
		assert.equal(n.sent[0].method, method);
		assert.deepEqual(n.sent[0].params, params, method);
	}
});

test("data-availability reads send what the node reads", async () => {
	const n = node({});
	const da = new sdk.TenzroClient({ endpoint: "http://node.test" }, n).da;
	const cases = [
		[() => da.availability(), "tenzro_daAvailability", {}],
		[
			() => da.availabilityOf(PROVIDER),
			"tenzro_daAvailability",
			{ address: PROVIDER },
		],
		[
			() => da.challenge("0xcc", 3),
			"tenzro_daChallenge",
			{ commitment: "0xcc", target_index: 3 },
		],
		[() => da.committee(), "tenzro_daCommittee", []],
		[() => da.listBlobs(), "tenzro_daListBlobs", []],
		[() => da.listChallenges(), "tenzro_daListChallenges", {}],
		[() => da.listChallenges(4), "tenzro_daListChallenges", { limit: 4 }],
	];
	for (const [call, method, params] of cases) {
		n.sent.length = 0;
		await call();
		assert.equal(n.sent[0].method, method);
		assert.deepEqual(n.sent[0].params, params, method);
	}
});

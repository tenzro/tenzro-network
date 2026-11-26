import type { RpcClient } from "@tenzro/core";

/** How a possession challenge against a data-availability committee member resolved. */
export type DaChallengeOutcome =
	| "passed"
	| "failed_no_response"
	| "failed_not_held"
	| "failed_bad_proof";

/** A resolved possession challenge. Hashes and addresses are `0x` hex. */
export interface DaChallengeRecord {
	id: string;
	commitment: string;
	target_index: number;
	target_address: string;
	nonce: string;
	issued_at_ms: number;
	resolved_at_ms: number;
	outcome: DaChallengeOutcome;
}

/** Resolved challenges, most recently resolved first. */
export interface DaChallengeList {
	count: number;
	challenges: DaChallengeRecord[];
}

/** A committee member's rolling availability score. */
export interface DaAvailabilityScore {
	address: string;
	score: number;
	max_score: number;
	passes: number;
	failures: number;
	last_outcome: DaChallengeOutcome;
	last_challenge_ms: number;
}

/** Every scored member, lowest score first. */
export interface DaAvailabilityList {
	count: number;
	scores: DaAvailabilityScore[];
}

/** One member of the current committee. */
export interface DaCommitteeMember {
	index: number;
	address: string;
	/** Whether the member is the node answering. */
	is_local: boolean;
	/** Its score, once it has been challenged. */
	availability: DaAvailabilityScore | null;
}

/** The current data-availability committee. */
export interface DaCommittee {
	local_address: string;
	count: number;
	members: DaCommitteeMember[];
}

/** The availability certificate of a blob this node wrote. */
export interface DaBlobCertificate {
	attesting_indices: number[];
	quorum: number;
	certified_at_ms: number;
	root: string;
}

/** A blob commitment this node knows about. */
export interface DaBlob {
	commitment: string;
	/** The index of the sliver this node holds, if any. */
	held_sliver_index: number | null;
	blob_len: number | null;
	certificate: DaBlobCertificate | null;
}

/** The blob commitments this node knows about. */
export interface DaBlobList {
	count: number;
	blobs: DaBlob[];
}

/**
 * The data-availability committee: members, the blobs they hold slivers of,
 * and the possession challenges that score their availability.
 */
export class DaClient {
	constructor(private rpc: RpcClient) {}

	/** Every scored member, lowest score first (`tenzro_daAvailability`). */
	availability(): Promise<DaAvailabilityList> {
		return this.rpc.call<DaAvailabilityList>("tenzro_daAvailability", {});
	}

	/** One member's score; the node answers an error for a member never challenged. */
	availabilityOf(address: string): Promise<DaAvailabilityScore> {
		return this.rpc.call<DaAvailabilityScore>("tenzro_daAvailability", {
			address,
		});
	}

	/** Challenge member `targetIndex` to prove possession of `commitment` (`tenzro_daChallenge`, operator only). */
	challenge(
		commitment: string,
		targetIndex: number,
	): Promise<DaChallengeRecord> {
		return this.rpc.call<DaChallengeRecord>("tenzro_daChallenge", {
			commitment,
			target_index: targetIndex,
		});
	}

	/** The current committee (`tenzro_daCommittee`). */
	committee(): Promise<DaCommittee> {
		return this.rpc.call<DaCommittee>("tenzro_daCommittee");
	}

	/** The blob commitments this node knows about (`tenzro_daListBlobs`). */
	listBlobs(): Promise<DaBlobList> {
		return this.rpc.call<DaBlobList>("tenzro_daListBlobs");
	}

	/** Resolved challenges, most recent first (`tenzro_daListChallenges`); the node defaults `limit` to 100. */
	listChallenges(limit?: number): Promise<DaChallengeList> {
		return this.rpc.call<DaChallengeList>(
			"tenzro_daListChallenges",
			limit === undefined ? {} : { limit },
		);
	}
}

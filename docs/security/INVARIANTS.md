# Security invariants

Statements the implementation must uphold, with the code that enforces
each one. An auditor should be able to falsify an invariant by pointing
at a code path that violates it; a fuzz target listed against an
invariant exercises it mechanically (see `fuzz/README.md`).

## Consensus

| # | Invariant | Enforced at | Fuzz |
|---|---|---|---|
| C1 | A vote counts toward a quorum certificate only if its composite signature (Ed25519 + ML-DSA-65) and BLS signature verify against a current validator-set member | `crates/tenzro-consensus/src/voter.rs:534 VoteCollector::add_vote` | `consensus_vote` |
| C2 | Votes carrying `vote_format_version != 4` are rejected before signature work | `voter.rs:53 VOTE_FORMAT_VERSION`, checked in `add_vote` | `consensus_vote` |
| C3 | `high_qc_view < view` for every accepted vote | `add_vote` pre-registry validation | `consensus_vote` |
| C4 | Two votes from the same validator for the same view but different blocks produce slashing evidence, persisted across restarts | `validator.rs:654 EquivocationDetector`; evidence in `CF_AUDIT / equivocation/*`; 10% slash via `StakingSlashingCallback` | — |
| C5 | A validator set is never empty | `validator.rs ValidatorSet::new` returns `Err` on empty input | — |
| C6 | Capability weighting in leader selection never exceeds 1.5× | `leader_reputation.rs:135 CAPABILITY_MAX_BPS = 15000` | — |
| C7 | Arbitrary bytes on the vote wire (bincode or JSON) can never panic the collector | decode + `add_vote` are total | `consensus_vote` |

## Bridges

| # | Invariant | Enforced at | Fuzz |
|---|---|---|---|
| B1 | An inbound message mutates state only after decode → validate → verify_hash → verify_signature → nonce replay check all pass | `crates/tenzro-bridge/src/message_format.rs:449 verify_inner_message` | `bridge_inner_message` |
| B2 | A Wormhole VAA is accepted only with ≥ quorum valid guardian signatures from the active, unexpired set, with no duplicate guardian indices | `wormhole.rs:329 Vaa::verify_quorum` | `wormhole_vaa` |
| B3 | Malformed (r,s,v) signature bytes never panic secp256k1 recovery | `verify_quorum` signature loop | `wormhole_vaa` |
| B4 | A processed inbound nonce is never accepted twice, including across restarts | `NonceTracker::with_storage` → `CF_SETTLEMENTS / bridge_nonce:*` | — |
| B5 | When a Hyperlane/Axelar validator set is installed, verification is fail-closed: unverifiable ISM metadata rejects the message | `hyperlane.rs receive_message` (inline trailer parse), `axelar.rs` | — |
| B6 | The threshold-signing path never exposes key shares to the bridge crate | `mpc::sign::ThresholdSigner` trait boundary — bridge sees only `sign_prehash(msg_hash) -> SignOutput` | — |

## Settlement

| # | Invariant | Enforced at | Fuzz |
|---|---|---|---|
| S1 | A channel state update is applied only with a valid Ed25519 signature by the payer key over the canonical 40-byte preimage (`nonce ‖ payer_balance ‖ payee_balance`, LE) of the *next* state | `crates/tenzro-settlement/src/micropayments.rs:505 canonical_message`, `:489 verify_signature_with_key` | `settlement_channel_state` |
| S2 | Signature/key material of any length is rejected without panicking | `verify_signature_with_key` | `settlement_channel_state` |
| S3 | Escrow release/refund is payer-authorized only, with state and expiry checks; vault addresses have no private key (derived: `SHA-256("tenzro/escrow/vault" ‖ escrow_id)`) | `EscrowManager` + Native VM dispatch of `CreateEscrow`/`ReleaseEscrow`/`RefundEscrow` | — |
| S4 | Batch settlement is atomic: any failure rolls back the whole batch | `BatchProcessor` | — |

## Staking and token economics

| # | Invariant | Enforced at | Fuzz |
|---|---|---|---|
| T1 | `stake`, `slash`, `unstake` return typed errors on overflow/underflow — never panic, never wrap | `crates/tenzro-token/src/staking.rs:394/:564/:438` (checked_add / checked_sub) | `staking_arithmetic` |
| T2 | No multiplication of two 10^18-scaled u128 values overflows: quotient/remainder decomposition throughout the liquid-staking pool | `liquid_staking.rs:493 exchange_rate`, `:521 deposit`, `:602 request_withdrawal`, `:769 distribute_rewards` | `staking_arithmetic` |
| T3 | Slashing amount never exceeds the target's stake | `staking.rs slash` clamp | `staking_arithmetic` |
| T4 | Secure-mint: `circulating + amount ≤ attested reserve` at every mint | `crates/tenzro-vm/src/secure_mint.rs check_and_mint` | — |
| T5 | Reserve attestations from unregistered attestors or with empty signatures are rejected before persist | `tenzro_submitReserveAttestation` handler in `crates/tenzro-node/src/rpc.rs` | — |

## Transactions

| # | Invariant | Enforced at | Fuzz |
|---|---|---|---|
| X1 | The canonical signing preimage covers `chain_id ‖ from ‖ to ‖ nonce ‖ gas ‖ timestamp ‖ tx_type ‖ memo ‖ pq_public_key` — no signed field is outside the hash | `crates/tenzro-types/src/transaction.rs:102 Transaction::hash` | `transaction_decode` |
| X2 | Arbitrary JSON never panics decode, hash, or validate | `transaction.rs:501 SignedTransaction::validate` | `transaction_decode` |
| X3 | ML-DSA-65 fields are length-gated (signature 3309, verifying key 1952) | `SignedTransaction::validate` | `transaction_decode` |
| X4 | Every submission path verifies the signature synchronously before acceptance; failures return JSON-RPC `-32003` | `eth_sendRawTransaction` / `tenzro_signAndSendTransaction` handlers in `rpc.rs` | — |

## Cross-chain intents (ERC-7683)

| # | Invariant | Enforced at | Fuzz |
|---|---|---|---|
| I1 | `uint256_be_to_u128` rejects any word with non-zero high 128 bits — no silent truncation of amounts | `crates/tenzro-types/src/intent_7683.rs:350` | `intent_7683` |
| I2 | `u128_to_uint256_be` / `uint256_be_to_u128` round-trip exactly | `intent_7683.rs` | `intent_7683` |
| I3 | `compute_order_id` is deterministic and total over all field contents (domain-tagged SHA-256) | `intent_7683.rs:324` | `intent_7683` |
| I4 | Origin-side opens and destination-side fills are idempotent per order id | `CF_SETTLEMENTS / 7683_origin:` and `7683_dest:` keyspaces | — |

## Identity and custody

| # | Invariant | Enforced at |
|---|---|---|
| D1 | A machine DID cannot exceed its `DelegationScope` (value, daily spend, operations, contracts, time bound, protocols, chains) | `IdentityRegistry::enforce_operation` → typed `DelegationViolation` |
| D2 | Payment settlement requires both the protocol `DelegationScope` and the runtime `SpendingPolicy` to pass | `IdentityPaymentBinder` two-axis check |
| D3 | Every installed ERC-7579 validator module must approve a `UserOperation` (AND-combination); `valid_after = max`, `valid_until = min_nonzero` | `crates/tenzro-vm ValidatorRegistry::validate_user_op` |
| D4 | Revoking an identity cascades to everything it controls | `IdentityRegistry` cascading revocation |
| D5 | KYC tier changes require a verifying credential | `update_kyc_tier_with_credential` |

## TEE attestation

| # | Invariant | Enforced at |
|---|---|---|
| E1 | An attestation is valid only with a full X.509 chain to the pinned vendor root plus a valid ECDSA signature over the quote/report body (TDX QE P-256 over Quote[0..632]; Nitro COSE_Sign1 ES384) | `crates/tenzro-tee/src/attestation.rs`, per-provider verify paths |
| E2 | Confidential-tier trainer enrollment requires attestation ↔ `enclave_pubkey` ↔ measurement parity | `tenzro-training::confidential validate_confidential_enrollment` |
| E3 | Off-hardware key sealing fails closed (no simulation on live nodes) | `TeeKeyshareSealer::derive_auto` |

## Generative media

| # | Invariant | Enforced at |
|---|---|---|
| G1 | A job id is a domain-tagged SHA-256 over the whole posted spec, including any conditioning-image hash, so the terms a receipt is checked against cannot be swapped after posting | `crates/tenzro-media-gen/src/commitments.rs compute_job_id` / `expected_job_id`, checked in `post_job` |
| G2 | The three signed stages use distinct domain tags (`tenzro/media-gen/job-id`, `/handoff`, `/receipt`), so a signature from one stage is not replayable as another | `commitments.rs` tag constants + preimage builders |
| G3 | A charge above the requester's posted ceiling is rejected; the ceiling is checked at admission, not after a claim | `crates/tenzro-media-gen/src/pricing.rs enforce_ceiling` |
| G4 | Image kinds are priced as one frame regardless of any stray `num_frames` — a still is never billed as a clip | `pricing.rs pixel_steps` |
| G5 | Fetched bytes are accepted only at the exact size and content hash the receipt (or handoff, for the intermediate latent) committed to | `crates/tenzro-media-gen/src/output_store.rs verify_output` / `verify_latent` / `verify_input` |
| G6 | A split job's payment division reads `steps_completed` from the signed handoff, never from a worker's claim; the two shares always sum to 10000 bps with rounding to the low-noise half | `crates/tenzro-media-gen/src/runtime.rs apply_shares` |
| G7 | A handoff whose `steps_completed` exceeds the job's total steps is rejected, and a second handoff for the same job cannot replace the first | `runtime.rs` `HandoffStepsOutOfRange` / `HandoffAlreadyRecorded` |
| G8 | A completed job cannot be re-completed with a different output hash, and a receipt whose spec differs from the posted spec is rejected | `runtime.rs` `ReceiptSpecMismatch` |
| G9 | Only an enrolled worker can claim, each expert role is claimable once, and a split job cannot be claimed whole (nor a whole job claimed by role) | `runtime.rs` `WorkerNotEnrolled` / `RoleAlreadyClaimed` / `RoleRequired` / `RoleNotRequired` |
| G10 | Worker enrollment refuses any model outside the curated catalog, or one whose license terms the operator did not accept at startup | `handle_media_gen_enroll_worker` in `crates/tenzro-node/src/rpc.rs` → `check_model_license` |

## RPC authorization

| # | Invariant | Enforced at |
|---|---|---|
| R1 | Cross-chain mint/burn, bridge authorization, compliance (freeze/whitelist/recover), secure-mint policy mutation, delegation-scope mutation, and Canton operator surfaces require the operator admin token | `crates/tenzro-node/src/rpc.rs:641 requires_admin_token` |
| R2 | Canton-scoped API keys without a bound Canton user cannot submit DAML commands (fail-closed `-32004`); `act_as` overrides must match the key's primary party or its `can_act_as_parties` whitelist | `handle_submit_daml_command` in `rpc.rs` |
| R3 | Tenant OAuth client secrets are never returned over RPC | `tenzro_createApiKey` response shaping |
| R4 | Validator-only gossip topics reject messages from non-validators | `crates/tenzro-network/src/peer_manager.rs:386 authorize_peer_for_topic` |

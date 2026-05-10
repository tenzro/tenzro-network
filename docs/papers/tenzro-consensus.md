# Tenzro Consensus

**A Hybrid Post-Quantum HotStuff-2 with Reputation-Weighted Election and Tail-Fork-Resistant View Change**

Tenzro Network — Whitepaper
Version 1.0 · Pre-alpha
Hilal Agil — eng@tenzro.com

---

## Abstract

Tenzro Consensus is the Byzantine fault-tolerant state-machine replication protocol at the heart of the Tenzro Ledger. It builds on HotStuff-2 (Malkhi & Nayak, 2023) — a two-phase, linear-communication, partially-synchronous BFT protocol — and combines it with three production-hardened techniques drawn from the live deployments that have sustained the highest-throughput permissionless BFT chains in 2024–2026:

1. **Reputation-weighted proposer election** in the style of Aptos LeaderReputation (production at ~150 validators, 2021–present), with stake × observed-behaviour weights drawn from a non-grindable seed.
2. **No-Endorsement Certificates (NECs)** in the style of MonadBFT (mainnet November 2025, ~5,200 TPS at ~150 validators), eliminating the tail-fork attack class that affects every prior 2-chain HotStuff variant.
3. **Hybrid post-quantum signatures** — Ed25519 + ML-DSA-65 — bound to every safety-critical message (votes, timeouts, no-endorsements), ahead of NIST PQC migration deadlines and ahead of every other production L1 in the BFT family.

The combination is unusual. Aptos LeaderReputation in production runs over classical Ed25519. MonadBFT's mainnet runs over BLS aggregation without LeaderReputation. To our knowledge no other BFT chain in production combines reputation-weighted election with no-endorsement certificates over post-quantum-secure signatures. Tenzro Consensus is, in that strict sense, the first.

This paper specifies the protocol formally enough to implement from scratch, explains every parameter choice with reference to the production system that justified it, and is precise about what is proven by paper-and-pencil safety arguments versus what is established empirically by the upstream systems we draw from.

---

## 1. Introduction

### 1.1 Why a new consensus paper?

The BFT literature is mature. HotStuff (Yin et al., 2019), HotStuff-2 (Malkhi & Nayak, 2023), DiemBFT v4 (the Diem authors, 2021), Jolteon/Ditto (Gelashvili et al., 2022), and Aptos LeaderReputation (Aptos Labs, 2021) collectively define the production-grade design space. MonadBFT (Monad Labs, arXiv:2502.20692, Nov 2025) closes the last open structural attack on 2-chain HotStuff. Each of these is documented in academic publications or in production source.

Tenzro is not introducing a new BFT primitive. It is composing five established ones into a single system whose specific combination has not previously been deployed:

| Primitive | Tenzro choice | Production lineage | Tenzro novelty |
|---|---|---|---|
| Core protocol | HotStuff-2, two-phase | Aptos, Sui (Mysticeti adapts), Solana TowerBFT (different lineage) | Drop-in |
| Proposer election | Stake × reputation, seeded draw | Aptos mainnet 2021– | Drop-in, with hybrid PQ signing |
| View change | TC + NEC (No-Endorsement Certificate) | MonadBFT mainnet Nov 2025 | First combination with reputation election |
| Active-set membership | Five-state lifecycle with separate activation / exit churn budgets | Ethereum Pectra (EIP-7251 / EIP-7002 / EIP-8061), Sui, Aptos, Cosmos | Permissionless join/exit composed with reputation election and hybrid-PQ identity binding |
| Signing | Ed25519 + ML-DSA-65 hybrid | Tenzro original | First production BFT with NIST FIPS 204 hybrid |

This document specifies what we built, why we built it, and how it composes. It is intended for protocol implementers, security researchers, and operators who need to verify the protocol's correctness against the running code at `crates/tenzro-consensus/`.

### 1.2 Threat model and assumptions

The protocol is designed against a **partially synchronous network** (Dwork–Lynch–Stockmeyer, 1988): there exists an unknown Global Stabilization Time (GST) after which message delivery is bounded by an unknown but finite delay Δ. Before GST the adversary may delay, drop, or reorder messages arbitrarily. After GST, honest replicas exchange messages within Δ.

The validator set comprises *n* registered validators of which up to *f* may be Byzantine, where *n ≥ 3f + 1*. The adversary controls those *f* validators completely — including their long-term keys, view-change timing, message content, and ability to coordinate across parties.

We assume:

- A **PKI** in which every validator has registered both an Ed25519 classical public key and an ML-DSA-65 post-quantum public key on-chain through the permissionless validator registry (`tenzro_token::ValidatorRegistry`, §6.4). The registry is the on-chain source of truth for who is a validator: it binds each `Address` to a `(consensus_pubkey, pq_pubkey, withdrawal_address, self_stake)` tuple at registration time. This binding is a hard precondition — `NodeValidatorRegistry` rejects any peer presenting an unregistered or mismatched key. Active-set membership is *dynamic*: validators join, are admitted by the activation churn cap, and exit through the lifecycle state machine described in §6.4. The threat model holds independently for whichever set is active at the start of any given epoch.
- A **hash function** modelled as a random oracle for the seed-derivation argument in §4.2. We use SHA-256 with explicit domain separation tags.
- A **signature scheme** secure under EUF-CMA against a quantum adversary, instantiated as `Ed25519 || ML-DSA-65` with both signatures required (`StandardHybridVerifier::verify` AND-composes both branches). Forgery requires breaking both Ed25519 *and* lattice-based ML-DSA-65 — no security degradation against either threat surface.
- A **stake-weighted validator economy** in which dishonest behaviour can be penalised by burning bonded TNZO. The slashing rate for self-equivocation is fixed at 10% (`crates/tenzro-node/src/node.rs:90`); the equivocation evidence pipeline is wired end-to-end from the consensus equivocation detector (`tenzro_consensus::EquivocationDetector`) to the on-chain staking manager via the `SlashingCallback` trait.

Out of scope for this document: networking-layer attacks (eclipse, partition, sybil at the libp2p layer), TEE compromise (covered separately in `docs/security/quantum-resistance-audit.md`), and the economic security argument for stake bonding (covered in `TOKENOMICS.md`).

### 1.3 Properties

Tenzro Consensus satisfies:

- **Safety.** No two honest replicas finalize different blocks at the same height, even under arbitrary Byzantine behaviour and arbitrary network conditions.
- **Liveness (after GST).** If at least *n − f* honest validators are correct and the network stabilizes, blocks are finalized at the rate bounded by 2Δ (the optimistic two-chain finality).
- **Resilience to single-validator faults.** A single unresponsive validator does not stall the chain. (This is the property that round-robin proposer selection demonstrably *fails* on small validator sets — §3.)
- **Resistance to tail-fork extraction.** A faulty leader at view *v−1* cannot collude with the leader at view *v* to extract MEV from an honest leader's tail-of-chain proposals. (This is the property that 2-chain HotStuff, including DiemBFT and Aptos pre-2024, *fails* on — §5.)
- **Quantum forgery resistance.** A computationally-unbounded quantum adversary that breaks Ed25519 still cannot forge a vote, timeout, or no-endorsement attestation, because every signature is hybrid-AND with ML-DSA-65.

Safety follows from HotStuff-2's two-chain safety argument unchanged. Liveness follows from the DiemBFT v4 pacemaker argument, with the Tenzro-specific NEC variant proven correct in §5. Single-validator-fault resilience is empirical (Aptos mainnet, 2021–present). Tail-fork resistance is empirical (MonadBFT mainnet, Nov 2025–present) plus the structural argument in §5.4. Quantum resistance follows from ML-DSA-65's NIST FIPS 204 standardisation (August 2024).

---

## 2. Background

This section is normative — its definitions are referenced throughout. Readers familiar with HotStuff-2 may skip to §3.

### 2.1 The HotStuff family

The HotStuff family of protocols (Yin et al. 2019, Malkhi-Nayak 2023) reduces BFT consensus to a sequence of *views*. Each view has a designated *leader* who proposes a block extending the chain. Replicas vote on the proposal; if 2*f* + 1 votes are collected, they form a *Quorum Certificate* (QC) that certifies the block.

HotStuff achieves linear communication complexity (*O(n)* per view in the optimistic path) by having votes flow leader → replicas → leader rather than all-to-all. It achieves consistency by requiring a *k*-chain pattern (*k* consecutive QC-certified blocks at increasing views) before finalizing the oldest of the chain.

| Variant | Phases per view | Chain depth for finality | View change | Latency (optimistic) |
|---|---|---|---|---|
| HotStuff (2019) | 3 (Prepare → Pre-commit → Commit) | 3-chain | Leader collects new-view | 3Δ |
| HotStuff-2 (2023) | 2 (Prepare → Commit) | 2-chain | DiemBFT-style pacemaker | 2Δ |
| Jolteon (2022) | 2 with linear timeout | 2-chain | TC + signed timeout | 2Δ |
| MonadBFT (2025) | 2 with linear timeout + NEC | 2-chain | TC + NEC | 2Δ |

Tenzro Consensus is in the rightmost column of this table. The full protocol is HotStuff-2's safety + Jolteon's pacemaker + MonadBFT's NEC.

### 2.2 Vocabulary used in this paper

- **Block.** An ordered list of transactions plus a parent hash. A block is *valid* if every transaction is well-formed and the block size, gas, and transaction count are within `ConsensusConfig` bounds.
- **View.** A protocol epoch with a designated leader. Numbered monotonically from 0 within an epoch.
- **Round.** Synonym for view in this document. (We follow Aptos's "round" terminology in the source code; "view" in protocol descriptions where it's standard.)
- **QC (Quorum Certificate).** A signed proof that 2*f* + 1 distinct validators voted *Prepare* on the same block at the same view. Carries the block hash, view, and an aggregate (or list-of-signatures) signing structure.
- **TC (Timeout Certificate).** A signed proof that 2*f* + 1 distinct validators sent a *TimeoutMsg* for the same view. Carries the view that timed out and the maximum `high_qc_view` reported by any signer.
- **NEC (No-Endorsement Certificate).** A signed proof that *f* + 1 distinct validators sent a *NoEndorsementMsg* for the same view, attesting that they observed no QC at view *v* − 1. Used by the leader at view *v* to prove that no high-tip exists from the previous view, allowing it to safely propose a fresh block rather than re-extending a possibly-non-existent tail. (§5.)
- **Pacemaker.** The view-change subsystem (DiemBFT v4 §3.5). On local timeout each replica broadcasts a `TimeoutMsg`. Replicas observing a higher-view `TimeoutMsg` advance their local view to match. 2*f* + 1 timeouts at the same view aggregate into a TC.
- **High QC.** The QC for the highest-view certified block a replica has observed. Used by the next leader to know which branch to extend (Jolteon vote rule).
- **Reputation tier.** One of *Active*, *Inactive*, or *Failed*. Determined by a validator's behaviour in a configurable sliding window of recent rounds. Drives the proposer-election weight (§4).

### 2.3 Why HotStuff-2 and not [other choice]?

We considered four candidates for Tenzro's core BFT protocol:

| Candidate | Reason rejected |
|---|---|
| Tendermint / CometBFT | Three-phase, less responsive than HotStuff-2 under partial synchrony. |
| HotShot / Espresso | Targeted at rollup sequencing, not L1 settlement. |
| Mysticeti (Sui) | DAG-based; impressive throughput, but optimised for narrow-waist transaction settlement, less natural for our multi-VM execution layer with EVM/SVM/DAML each consuming a single ordered stream. |
| MonadBFT directly | Production-proven, but its proposer election is round-robin. We need both NEC *and* reputation. |

HotStuff-2 with the Jolteon pacemaker, plus the two production-hardened additions documented here, gives us linear communication, optimistic 2Δ finality, the proposer-election fix, and the tail-fork fix in one protocol. This is the same reasoning Aptos applied in 2023–2024 (then they added their own NEC analogue under a different name).

---

## 3. The proposer-election problem

### 3.1 Why round-robin fails

The simplest proposer-election rule is round-robin: at view *v*, the leader is `validator[v mod n]`. This is what HotStuff (2019) and most academic 2-chain BFT protocols specify in their main body, with a note that production deployments should "use a more sophisticated rotation."

Round-robin has a specific empirical failure mode in small validator sets that is rarely articulated in the academic literature but is well-known to operators. It is the failure mode that prompted the Aptos team to ship LeaderReputation in 2021.

Suppose *n* = 4, *f* = 1, and one validator (call it *V₃*) is *flaky*: 50% of the time it is offline; 50% of the time it is online. The other three validators are honest and online.

| Scheduled leader at view *v* | Probability *V₃* is leader | Probability the proposal succeeds |
|---|---|---|
| Round-robin | 25% | 50% (only when *V₃* is up) |
| Round-robin, *V₃* down at view *v* | 25% | 0% — view times out, advance to *v* + 1 |

Empirically, with one out-of-four flaky validator under round-robin:

- 25% of views are scheduled to *V₃*.
- Half of those views (12.5% of total) time out — on average ~2 seconds wasted per timeout (`view_timeout_ms = 2000`).
- The remaining 75% of views land on healthy leaders and finalize at the optimistic 2Δ rate.

Realised throughput is bounded by:

```
throughput ≈ (1 − 0.125) × nominal_throughput
           = 0.875 × nominal_throughput
```

That's a 12.5% throughput penalty for one flaky validator out of four. Worse: if *V₃*'s flakiness causes peers to mark its votes as missing for long enough, gossipsub peer-scoring can drop *V₃* from the mesh entirely. When *V₃* recovers, it is no longer in the mesh and cannot rejoin without manual intervention. This is the failure mode that produced the Tenzro testnet stall reported on 2026-04-26 in task #398.

### 3.2 What Aptos did

Aptos LeaderReputation (Aptos research blog, 2021; production source `aptos-core/consensus/src/liveness/leader_reputation.rs`) replaces round-robin with a **stake-weighted seeded draw whose per-validator weight is multiplied by an observed-behaviour multiplier**:

- A validator who recently produced QC-certified proposals gets a high *active weight* (×1000 over the baseline).
- A validator who participated as a voter but hasn't proposed gets a moderate *inactive weight* (×10).
- A validator whose proposals failed to form QCs gets the punitive *failed weight* (×1).

The 1000× spread between *active* and *failed* means a chronically-flaky validator's effective draw probability collapses to roughly 0.1% within ~20 rounds — long before its degradation propagates into chain-wide liveness loss.

Aptos has run this in production at ~150 validators since 2021. We have adopted those constants directly (FAILED=1, INACTIVE=10, ACTIVE=1000, FAILURE_THRESHOLD_PERCENT=10) with one Tenzro-specific addition: a TEE-attestation multiplier of 1.5× (1000 bps over baseline), discussed in §4.5.

---

## 4. Tenzro LeaderReputation

This section specifies the proposer-election algorithm exactly as implemented in `crates/tenzro-consensus/src/leader_reputation.rs`.

### 4.1 Inputs

At the start of each round *r*, the proposer-election algorithm consumes:

- The current epoch number *e*.
- The round number *r*.
- The hash of the most recently finalized block, `prev_block_id` (32 bytes, SHA-256).
- The active validator set *V* with |*V*| = *n*. Each validator carries `(address, stake, classical_pk, pq_pk, tee_attested)`.
- The **proposer history** *P*: a bounded ring buffer of `(round, proposer, success)` tuples for finalized rounds, capacity 10*n* + 40.
- The **voter history** *W*: a bounded ring buffer of `(round, voters)` tuples, same capacity.

### 4.2 The seed

The leader draw is seeded by:

```
seed = SHA-256(
    "TENZRO_LEADER_REPUTATION:"   // 25-byte ASCII domain tag
    || epoch.to_be_bytes()         //  8 bytes big-endian
    || round.to_be_bytes()         //  8 bytes big-endian
    || prev_block_id               // 32 bytes
)
```

Two structural properties:

- **Domain separation.** The leading 25-byte tag prevents replay against any other SHA-256 hash in the system (vote payloads, transaction hashes, settlement receipts) that happens to share input structure.
- **Anti-grinding.** `prev_block_id` is the hash of the most-recently-*finalized* block — not the tentative parent of round *r* − 1. A finalized block hash is fixed at least one full QC ago. An adversary leader at round *r* − 1 cannot grind candidate blocks to bias the draw at round *r* + 20 (the trailing buffer, §4.3) because the seed for round *r* + 20 already depends on a block that was finalized before round *r* − 1's leader was even chosen. The same pattern is used by Aptos.

### 4.3 The windows

The algorithm uses two sliding windows over the per-round history:

- **Proposer window:** rounds in `[r − 10n − 20, r − 20)`. Spans 10*n* rounds. The most recent 20 rounds are *excluded* — this is the **trailing buffer** (`TRAILING_BUFFER_ROUNDS = 20`).
- **Voter window:** rounds in `[r − 10n − 20, r − 9n − 20)`. Spans *n* rounds — the oldest part of the proposer window.

The trailing buffer is the anti-grinding margin. Without it, a validator could observe round *r*'s draw seed before round *r* − 1's QC has finalized, opening a brief grinding window. Aptos pinned 20 as the minimum buffer that closes this against the maximum plausible reorder depth at HotStuff-2 finality (one full pipeline slot of pre-finalized blocks plus safety margin). Tenzro inherits this constant.

The voter window is intentionally *older* than most of the proposer window. By the time a round's QC has had `9n` rounds to propagate, every honest validator that participated has had ample time for its vote to be observed across the network. This prevents counting a temporarily-missed vote (network jitter) against a validator that simply hadn't received the QC yet.

For *r* < 10*n* + 20 (genesis-adjacent rounds), both windows are undefined. The algorithm falls back to **pure stake-weighted draw with no behavioural multiplier** until enough history accumulates. With *n* = 4, this is the first 60 rounds; with *n* = 100, the first 1020 rounds.

### 4.4 The weights

For each validator *v* in *V*, compute:

```
proposed_v = #{round ∈ proposer_window : P[round].proposer = v}
failed_v   = #{round ∈ proposer_window : P[round].proposer = v ∧ ¬P[round].success}
voted_v    = #{round ∈ voter_window    : v ∈ W[round].voters}
```

Then the *behavioural tier* of *v* is determined by:

```
tier(v) =
  if proposed_v ≥ 1 ∧ (100 × failed_v / proposed_v) < 10  →  ACTIVE_WEIGHT  = 1000
  else if voted_v ≥ 1                                       →  INACTIVE_WEIGHT = 10
  else                                                       →  FAILED_WEIGHT = 1
```

(`10` here is `FAILURE_THRESHOLD_PERCENT`.)

The validator's **total weight** is:

```
weight(v) = stake(v) × tier(v) × tee_multiplier(v) / 10000
```

where `tee_multiplier(v)` is `15000` (= 1.5×) if *v* presents a fresh valid TEE attestation in the current epoch, and `10000` (= 1×) otherwise. Division by 10000 normalises the basis-points multiplier.

### 4.5 Why 1.5× for TEE, not 2×?

An earlier draft of Tenzro (pre-2026) gave TEE-attested validators a hard 2× weight boost. We demoted this to a 1.5× multiplier on the *behavioural* weight for one specific reason: a TEE-attested validator that is misbehaving (failing proposals) should still be deprioritized. With a 2× hard boost applied *after* tier selection, a TEE validator at the FAILED tier still got 2× weight over a non-TEE validator at FAILED — TEE attestation effectively exempted a misbehaving validator from accountability. The 1.5× multiplicative form preserves the property that observed-behaviour can fully overcome attestation: a TEE-attested FAILED validator (weight = stake × 1 × 1.5) is dwarfed by a non-TEE ACTIVE validator (weight = stake × 1000 × 1).

### 4.6 The draw

The leader for round *r* is selected by:

```
total = Σ weight(v) for v in V
target = u128(seed[0..16]) mod total
cursor = 0
for v in V (deterministic order, e.g. sorted by address):
    cursor += weight(v)
    if cursor > target:
        return v
```

The deterministic iteration order ensures every replica computes the same leader from the same inputs.

The bias from non-uniform reduction (`u128 mod total`) is bounded by `total / 2^128`. For any plausible total weight (even at *n* = 10⁶ validators with full ACTIVE × max-stake weights), this is well below `2^−96` — cryptographically negligible.

### 4.7 Comparison with the literature

| System | Election | TEE multiplier | Anti-grinding seed | Failure-aware? |
|---|---|---|---|---|
| Tendermint (CometBFT) | Round-robin, weighted by stake | None | `block.LastResultsHash` | No |
| Aptos LeaderReputation | Stake × {1, 10, 1000} | None (2× for special validators in early code, since removed) | `epoch || round || prev_block_id` | Yes |
| Sui Mysticeti | Round-robin within waves | None | None (DAG ordering) | No |
| MonadBFT | Round-robin | None | None | No |
| **Tenzro** | **Stake × {1, 10, 1000} × {1.0, 1.5}** | **1.5× for valid TEE attestation** | **`epoch \|\| round \|\| prev_block_id` with 25-byte domain tag** | **Yes** |

The TEE multiplier is the Tenzro-specific addition. To our knowledge no other production BFT chain factors hardware attestation into proposer election. The reasoning is that TEE-attested validators have an additional, harder-to-forge signal of long-term reliability (the attestation requires bare-metal hardware in a vendor-attested state), and a modest preference for picking them as leaders correlates with a modest preference for healthier proposers. The 1.5× factor was chosen to be small enough that observed-behaviour can fully override it, and large enough to be operationally meaningful.

---

## 5. The tail-fork problem and No-Endorsement Certificates

### 5.1 The attack

The tail-fork attack is the most subtle structural flaw in 2-chain HotStuff. It was articulated formally by the MonadBFT team in their February 2025 arXiv paper (arXiv:2502.20692, "MonadBFT: Pipelined Two-Phase BFT With Sub-Second Finality") and demonstrates that DiemBFT v4 — the protocol that ran Diem and underlies Aptos — is vulnerable to a specific class of MEV extraction by a colluding leader pair.

Setup. Suppose:

- The leader at view *v* − 1 is honest and has built a block *B* containing high-value transactions (the "tail" of the chain).
- The leader at view *v* is Byzantine (call it *L_v*).
- The leader at view *v* + 1 is also Byzantine, or colludes with *L_v*.

The attack:

1. The honest leader at *v* − 1 broadcasts *B*. Some honest validators receive it; others do not (network partition, or *L_v* censoring its propagation).
2. The honest leader at *v* − 1 *almost* gets a QC for *B* — say *f* honest votes are collected, but the 2*f* + 1 threshold is not reached before view *v* − 1 times out.
3. View *v* − 1 fails. A timeout certificate forms.
4. *L_v* takes over at view *v*. Critically, in classical 2-chain HotStuff, *L_v* can choose to:
   - Repropose *B* — extending the honest leader's tail.
   - Propose a *fresh* block *B'* at view *v* extending the prior QC, *replacing* the honest leader's tail.
5. *L_v* picks the fresh-block branch. It can copy any high-value transactions from *B* into *B'* (it received them in step 1's gossip). The transactions execute with *L_v* listed as the proposer that included them — *L_v* captures their MEV instead of the honest leader. The honest leader's *B* is effectively orphaned.

This attack does not violate consensus *safety* — no two blocks are finalized at the same height. But it does violate **proposer-fairness**: an honest leader can have its tail-of-chain proposals systematically extracted by a colluding successor.

### 5.2 The fix: No-Endorsement Certificates

MonadBFT closed this with a structural rule:

> The leader at view *v* must either (a) re-propose the high-tip from view *v* − 1, or (b) attach a *No-Endorsement Certificate* proving that no high-tip exists.

A No-Endorsement Certificate (NEC) is a *f* + 1 aggregation of signed `NoEndorsementMsg`s, where each `NoEndorsementMsg` is a validator attesting "I personally observed no QC at view *v* − 1." Any *f* + 1 of these prove that at least one honest validator observed no QC — which is what the protocol needs to safely allow a fresh block at view *v*.

Why *f* + 1 and not 2*f* + 1? Because *up to f* signers may be Byzantine and lying. *f* + 1 honest signatures across the active set is the minimum that guarantees at least one truthful "no QC observed" attestation.

### 5.3 The Tenzro NEC specification

The NEC implementation in `crates/tenzro-consensus/src/timeout.rs` (lines 595-1045) tracks the MonadBFT specification with three Tenzro-specific additions: the hybrid post-quantum signing scheme, explicit domain separation in the wire format, and integration with the rest of the consensus message pipeline.

#### 5.3.1 NoEndorsementMsg

A `NoEndorsementMsg` is broadcast by a replica that timed out at view *v* without observing a QC for view *v* − 1.

```
NoEndorsementMsg {
    format_version: u8 = 1,
    view: u64,                       // The view that timed out at the sender
    voter: Address,                   // 32 bytes, must be active validator
    signature: CompositeSignature,    // Ed25519 || ML-DSA-65
    public_key: CompositePublicKey,   // bound to validator's registered keys
}
```

The canonical signing payload is:

```
"TENZRO_NO_ENDORSEMENT:" || format_version || view.to_le_bytes() || voter
       (22 bytes)             (1 byte)         (8 bytes)         (32 bytes)
```

The 22-byte domain tag is distinct from `TENZRO_TIMEOUT:` (used by `TimeoutMsg`) and `TENZRO_VOTE:` (used by `Vote`), preventing cross-message replay. We deliberately *omit* `high_qc_view` from the NEC payload — a NEC is only claiming "I observed no QC at v−1"; conflating the two attestations would make NECs forgeable from leaked TimeoutMsgs.

`NoEndorsementMsg::verify` checks: format version, `view > 0`, voter is registered and active, embedded keys exactly match registered keys, and the hybrid Ed25519+ML-DSA-65 signature verifies against the canonical payload.

#### 5.3.2 NoEndorsementCertificate

```
NoEndorsementCertificate {
    format_version: u8 = 1,
    view: u64,
    signers: Vec<NecSigner>,   // ≥ f+1 distinct active validators
}
NecSigner {
    voter: Address,
    signature: CompositeSignature,
    public_key: CompositePublicKey,
}
```

Verification (`NoEndorsementCertificate::verify`):

1. Format version matches.
2. `view > 0`.
3. `signers.len() ≥ f + 1` of the active validator set.
4. All signers are distinct (no duplicate addresses).
5. Every signer is registered and active.
6. Every embedded key exactly matches the validator's registered classical and PQ keys.
7. Every signer's hybrid signature verifies against `NoEndorsementMsg::signing_payload(view, signer.voter)`.

Note: every signer has a *separate* canonical payload (different `voter` field), so there is no aggregated signature here — verification is *f* + 1 independent hybrid checks. This is a deliberate trade-off: hybrid signature aggregation across Ed25519 and ML-DSA-65 is not standardised, and the *f* + 1 threshold is small enough (5 at *n* = 13, 35 at *n* = 100) that per-signer verification is operationally tractable.

#### 5.3.3 The high-tip reproposal rule

The leader at view *v* must:

```
either:
  (a) re-propose the high-tip block_h such that
      ∃ TC for view v−1 ∧ block_h.qc.view ≥ max(TC.signers.high_qc_view)
  or:
  (b) attach a valid NEC for view v
```

A proposal that does neither is rejected by every honest replica (`tenzro_consensus::on_proposal`).

This rule is what closes the tail-fork attack. If *L_v* is Byzantine and wants to propose a fresh block to extract MEV, it must collect *f* + 1 NoEndorsement signatures. By the threshold argument, at least one of those signatures came from an honest validator that genuinely observed no QC at view *v* − 1. So if there *is* a high-tip block, no honest validator will sign a NoEndorsementMsg, and *L_v* cannot reach the *f* + 1 threshold without forging signatures (which it cannot, by EUF-CMA security of Ed25519 + ML-DSA-65).

### 5.4 Composition with reputation election

A subtle point: a Byzantine leader caught attempting tail-fork extraction without a valid NEC has its proposal rejected, which means its proposal *fails to form a QC*, which means its `(round, proposer, success=false)` is recorded in the proposer history, which means its reputation tier drops to FAILED, which means its weight in future leader draws collapses to baseline × 1 × {1, 1.5}.

The two mechanisms compose:

- NEC blocks the *immediate* attack (the fresh block is rejected).
- Reputation election makes the *attempt costly*: a single failed proposal pulls the validator's effective draw probability from ~25% (round-robin equivalent at *n* = 4) to ~0.1% within tens of rounds.

This composition does not exist in any prior production BFT chain. MonadBFT mainnet has NECs but uses round-robin proposer selection. Aptos mainnet has reputation-weighted election but lacks NECs (Aptos's tail-fork mitigation uses a different mechanism, `OrderedRound`, that requires three-chain extension and is more conservative). Tenzro is the first production deployment of both.

---

## 6. The full protocol

This section walks through one round of Tenzro Consensus, end to end. Refer to `crates/tenzro-consensus/src/hotstuff2.rs` for the implementation.

### 6.1 Setup

At the start of each epoch, the validator set *V* is read from the on-chain `StakingManager`. Each validator presents:

- A 32-byte Tenzro `Address` (derived from its Ed25519 public key).
- An Ed25519 classical public key.
- An ML-DSA-65 post-quantum public key (mandatory in Wave 3d hybrid; pre-Wave-3d nodes are rejected).
- Optional: a fresh TEE attestation, time-bound to the current epoch.

The quorum threshold is *2f + 1* where *f = ⌊(n − 1) / 3⌋* (`BftThreshold::TwoThirdsPlusOne`). At *n* = 4, *f* = 1, quorum = 3. At *n* = 100, *f* = 33, quorum = 67.

### 6.2 Round *r* steps

#### Step 1: Leader election

Every replica computes the leader *L_r* via the algorithm in §4. Output is deterministic across all honest replicas (same seed, same validator set, same history).

#### Step 2: Proposal

*L_r* assembles a block *B* and broadcasts:

```
Proposal {
    block: B,
    high_qc: QC,                              // the highest QC the leader has seen
    timeout_certificate: Option<TC>,           // present iff round r−1 timed out
    no_endorsement_certificate: Option<NEC>,   // required if TC present and B is not a high-tip reproposal
}
```

If the previous round timed out, *L_r* chooses one of:

- **Re-propose the high-tip:** *B* extends the highest-QC block from view *r* − 1's TC signers. No NEC needed.
- **Propose a fresh block:** *B* extends `high_qc` (a QC from before *r* − 1). NEC for view *r* is mandatory.

#### Step 3: Validation

Each replica verifies the proposal:

1. The block's structural validity (size, gas, transaction count, parent hash).
2. The attached `high_qc` verifies against the validator set.
3. If `timeout_certificate` is present:
   - It verifies (2*f* + 1 distinct hybrid signatures over `TENZRO_TIMEOUT:` payload).
   - The proposal either re-proposes the high-tip (`block.qc.view ≥ max(TC.signers.high_qc_view)`) OR carries a valid NEC.
4. If `no_endorsement_certificate` is present:
   - It verifies (*f* + 1 distinct hybrid signatures over `TENZRO_NO_ENDORSEMENT:` payload).
   - `NEC.view = r`.

If any check fails, the replica withholds its vote.

#### Step 4: Vote

If validation succeeds, the replica sends a *Prepare vote*:

```
Vote {
    view: r,
    block_hash: hash(B),
    voter: Address,
    signature: CompositeSignature,    // hybrid over "TENZRO_VOTE:" || view || block_hash
    public_key: CompositePublicKey,
}
```

Votes are sent to *L_r* (not gossiped — preserves linear communication).

#### Step 5: QC formation

*L_r* collects votes. When 2*f* + 1 distinct valid votes for the same block at the same view are received, it constructs a QC and broadcasts it to all replicas.

Replicas receiving the QC:

- Update their *high_qc* if the QC's view exceeds their current high_qc's view.
- Add the *grandparent* block (the block 2 QCs back) to the **finalized chain**. This is the *2-chain commit rule* of HotStuff-2: a block is finalized when its child has formed a QC at the next view.
- Record `(r, L_r, success=true)` in the proposer history.
- Record `(r, voters)` in the voter history.

#### Step 6: Pacemaker timeout (parallel to all of the above)

Every replica runs a local view timer. If the timer expires before a QC is observed at view *r*:

- Broadcast a `TimeoutMsg(view=r, high_qc_view=local_high_qc.view)`.
- If a QC for view *r* − 1 has *not* been observed, also broadcast `NoEndorsementMsg(view=r)`.
- On observing a `TimeoutMsg` for view *r* + *k* with *k* > 0, advance local view to *r* + *k* (DiemBFT pacemaker rule).
- 2*f* + 1 `TimeoutMsg`s at the same view aggregate into a TC; the leader at the next view attaches the TC to its proposal.
- *f* + 1 `NoEndorsementMsg`s at the same view aggregate into a NEC; the leader at the next view attaches the NEC if proposing a fresh block.

#### Step 7: Equivocation detection

The `EquivocationDetector` (`crates/tenzro-consensus/src/vote_state.rs`) tracks per-validator votes per view. If two distinct votes from the same validator for different blocks at the same view are observed, an `EquivocationEvidence` record is constructed and dispatched via the `SlashingCallback` trait:

```
StakingSlashingCallback::report_equivocation(validator, view, evidence) {
    slash_amount = staking.get_stake(validator).amount / 10;   // 10%
    staking.slash(validator, slash_amount, reason, ...);
    epoch_manager.remove_pending_validator(validator);
}
```

The slashing pipeline is wired end-to-end: detection in `tenzro-consensus`, callback bridging in `tenzro-node`, and balance burn in `tenzro-token`. Slashed validators are dropped from the next epoch's pending queue.

### 6.3 Epoch transitions

Every `epoch_duration` rounds (default 10,000), the consensus engine performs an atomic epoch transition:

1. Snapshot the current validator set, finalized chain tip, and reputation/voter histories.
2. Read the new validator set from the on-chain `ValidatorRegistry` (§6.4) — specifically, the validators in `Active` state after the boundary's `EpochTransitionPlan` has been applied.
3. Reset proposer/voter histories sized for the new *n*.
4. Resume from the next view with the new set.

Epoch transitions are atomic across the validator set (every honest replica transitions at the same finalized block). The reputation histories are *not* persisted across epochs by design — a validator that joins mid-epoch should not start with a stale history from before it was registered.

### 6.4 Active-set membership: the dynamic validator registry

A validator set is not a fixed list. Operators must be able to register, get admitted, exit, and re-register without forking the chain or coordinating an off-chain ceremony. Tenzro Consensus implements this through a permissionless on-chain registry (`tenzro_token::ValidatorRegistry`, `crates/tenzro-token/src/validator_registry.rs`) that is the on-chain source of truth for who is a validator. The consensus engine's epoch-transition step (§6.3) reads from it; nothing else is authoritative.

#### 6.4.1 The five-state lifecycle

Each registered validator carries a status drawn from a five-state machine plus a `Jailed` quarantine state:

```
                                register tx
                                     │
                                     ▼
                                ┌─────────┐
            re-entry cooldown   │Candidate│
            ────────────────────┤         │
                                └────┬────┘
                                     │ activation churn admits
                                     ▼
                              ┌──────────────┐
                              │PendingActive │
                              └──────┬───────┘
                                     │ next_epoch + ACTIVATION_EFFECTIVE_DELAY_BLOCKS
                                     ▼
                                ┌─────────┐  slash       ┌────────┐
                                │ Active  │─────────────▶│ Jailed │
                                └────┬────┘              └────┬───┘
                                     │ exit tx                 │ governance
                                     ▼                          ▼
                              ┌────────────┐              (re-enter Candidate)
                              │PendingExit │
                              └─────┬──────┘
                                    │ next_epoch
                                    ▼
                                ┌────────┐
                                │Exited  │
                                └────────┘
```

The two pending states (`PendingActive`, `PendingExit`) exist for the same reason Cosmos has a fixed effective-date delay and Aptos has its `PendingActive` intermediate: HotStuff-2's two-chain finality means a QC observed at view *v* may be relied upon as a parent at view *v* + 1. If the validator set rotates between those two views, the QC's signers may no longer be in the active set — a safety violation. The fix is to hold any new validator in `PendingActive` for one full epoch boundary plus `ACTIVATION_EFFECTIVE_DELAY_BLOCKS = 3` finalised blocks before it counts as a vote-eligible member of the active set. By that point any in-flight high-QC has finalised.

A validator counts toward the active-set total (for churn-cap math) when it is in `Active` *or* `PendingExit`. `PendingExit` validators still vote — their exit only takes effect at the next boundary.

#### 6.4.2 Churn-budget admission

The registry caps how fast the active set can change in either direction. The defaults are:

| Parameter | Default | Source |
|---|---|---|
| `min_self_stake` | 10 000 TNZO | Tenzro choice; well above the 1 000 TNZO service-provider floor |
| `activation_churn_bps` | 400 bps (4%) | Matches EIP-8061 conservative profile |
| `exit_churn_bps` | 400 bps (4%) | Symmetric with activation; bounds set size drift |
| `MIN_CHURN_PER_EPOCH` | 1 | Per EIP-8061 §5; allows bootstrap when the percentage rounds to zero |
| `reentry_cooldown_epochs` | 4 | Prevents thrash from rapid exit-and-rejoin |
| `ACTIVATION_EFFECTIVE_DELAY_BLOCKS` | 3 | Cosmos-equivalent; safety margin for in-flight QCs |

At each boundary the registry computes an `EpochTransitionPlan { activations, exits, effective_activations, effective_exits }` and the consensus epoch-transition hook applies it to its pending queues. The activation cap is computed against the *current* active-set size: with 100 active validators, at most `max(1, 100 × 400 / 10 000) = 4` candidates are promoted from `Candidate` → `PendingActive` per epoch. The same cap applies to `Active` → `PendingExit` transitions.

Activation and exit budgets are *separate*. A wave of voluntary exits cannot starve new admissions, and vice versa. The two budgets are derived from the same percentage but consumed independently, matching EIP-8061's design.

#### 6.4.3 Registration and exit transactions

Registration and exit are typed transactions:

- `RegisterValidator { stake, consensus_pubkey, pq_pubkey, withdrawal_address, metadata_uri }` — emitted by the operator's wallet. The VM emits a `ValidatorRegister` typed log; the node-side registry consumes the log post-execution (`EventLoop::process_validator_logs`) and inserts a `Candidate` entry. The candidate becomes `PendingActive` at the next epoch boundary if `self_stake ≥ min_self_stake` and the activation churn budget admits it.
- `ExitValidator { address }` — emitted by the validator (must equal `from`). The registry transitions `Active` → `PendingExit` (or `Candidate`/`PendingActive` → `PendingExit` for short-circuit exits before activation), and the validator becomes `Exited` at the next epoch boundary. Re-registration is allowed after `reentry_cooldown_epochs`.
- `UpdateValidatorMetadata { address, metadata_uri }` — non-state-changing for consensus; updates the operator's metadata URL.

The registry persists every entry to RocksDB under the `validator:` prefix in `CF_TOKENS`, with a separate `validator:index` listing all addresses, hydrated on node startup. Permissioned-genesis validators populate the registry at genesis time via the same code path; from that point onward the chain has no privileged validator set.

#### 6.4.4 Composition with consensus

The registry composes with the rest of the protocol:

- **Reputation (§4).** `LeaderReputation` reads the active set from the registry every round. A validator in `PendingActive` is *not* in the active set yet and cannot be drawn as leader; one in `PendingExit` is still in the active set and can be drawn (this is by design — exits are not retroactive). When a fresh validator becomes `Active`, its proposer/voter history is empty, so it falls into the genesis-adjacent fallback path (§4.3) with pure stake-weighted draw until `10n + 20` rounds of history accumulate.
- **NEC (§5).** NEC verification requires `f + 1` signatures from the *current* active set. Because the active set rotates only at epoch boundaries (with the `ACTIVATION_EFFECTIVE_DELAY_BLOCKS` safety margin), there is no possibility of a within-epoch NEC verification failing because some signers were demoted mid-round.
- **Equivocation slashing (§6.2 step 7).** An equivocating validator is slashed (10% of stake burned) *and* the registry transitions it `Active` → `Jailed`. Jailed validators stay jailed indefinitely until governance reinstates them; the staking callback removes them from the next epoch's pending queue (`epoch_manager.remove_pending_validator`).
- **TEE attestation (§4.5).** The TEE attestation hash is stored on the registry entry but is *not* used to gate active-set membership — operators can lose TEE attestation without losing validator status, only the 1.5× draw multiplier. Re-attestation is a metadata update, not a re-registration.

#### 6.4.5 Why this specific shape?

The literature and 2026 production deployments suggest five well-formed approaches; we surveyed and chose:

| System | Approach | Why we didn't copy it directly |
|---|---|---|
| Ethereum Pectra (EIP-7251 / EIP-7002 / EIP-8061) | Typed transactions for register/exit, per-epoch churn caps split by direction | We adopted the typed-transaction + split-churn pattern verbatim. Ethereum's specific "max effective balance 2048 ETH" parameter is consensus-irrelevant for a stake-weighted system that uses uncapped voting power. |
| Sui | Explicit `Candidate` state where metadata is published before activation | We adopted the `Candidate` intermediate. Sui's gas-fee mechanism for candidacy doesn't translate to our fee model; we keep candidacy free and rely on `min_self_stake` as the spam-deterrent. |
| Aptos | Five-state machine with separate `Jailed` quarantine | We adopted the five-state shape exactly. Aptos's `PendingActive` rationale is the same as ours (in-flight QC safety). |
| Cosmos / CometBFT | `ValidatorUpdates` returned at end-of-block with fixed effective-date delay | We adopted Cosmos's effective-date delay (3 blocks). The end-of-block `ValidatorUpdates` ABCI hook becomes our post-finalize event-log scan. |
| MonadBFT | Round-robin over a static-per-epoch set, no permissionless registry as of mainnet Nov 2025 | We need permissionless join/exit; MonadBFT's static set is not sufficient. |

The combination — five-state lifecycle with separate activation/exit churn budgets, hybrid-PQ key binding at registration, and a Cosmos-style effective-date delay — is what falls out when each design choice is made for the same reason its upstream production system made it. It is not novel in any single component, but the assembled whole is the operational shape Tenzro Consensus needs.

---

## 7. Hybrid post-quantum signatures

### 7.1 What we sign hybrid

Every safety-critical message in Tenzro Consensus carries a `CompositeSignature`:

| Message | Domain tag | Hybrid? |
|---|---|---|
| Vote | `TENZRO_VOTE:` | Yes |
| TimeoutMsg | `TENZRO_TIMEOUT:` | Yes |
| NoEndorsementMsg | `TENZRO_NO_ENDORSEMENT:` | Yes |
| Block proposal | `TENZRO_BLOCK:` | Yes |
| QC inner signatures | (per-vote) | Yes (each vote is hybrid) |
| TC inner signatures | (per-timeout) | Yes |
| NEC inner signatures | (per-no-endorsement) | Yes |

A `CompositeSignature` is the concatenation `Ed25519_signature || ML-DSA-65_signature`. Verification AND-composes both:

```
verify(payload, sig) =
    Ed25519::verify(payload, sig.classical, pk.classical)
  ∧ MLDSA65::verify(payload, sig.pq, pk.pq)
```

Forging a CompositeSignature requires breaking *both* Ed25519 *and* ML-DSA-65. A quantum adversary that breaks Ed25519 (via Shor's algorithm on EC discrete log) still cannot forge — they would also need to break ML-DSA-65, which is based on Module-LWE and is conjectured to be quantum-secure.

### 7.2 Why hybrid and not pure PQ?

Three reasons:

1. **Defence in depth against ML-DSA-65 cryptanalysis.** ML-DSA was standardised in NIST FIPS 204 in August 2024. It is based on well-studied lattice assumptions (Module-LWE, Module-SIS) but has nothing close to the field-test history of Ed25519. If a structural break in ML-DSA-65 is found in the next 5–10 years, the hybrid construction degrades gracefully to pure-Ed25519 security (which is still classically secure).
2. **Wire compatibility with the existing libp2p stack.** libp2p's identify protocol uses classical Ed25519 PeerIds. We pin the classical key as the libp2p identity key and the hybrid signature as the *consensus authentication* layer above it. This lets us use hybrid signing without forking libp2p.
3. **Standardised composition.** The `Ed25519 || ML-DSA-65` AND-composed scheme matches the NIST CNSA 2.0 hybrid recommendation (NSA, 2022) and IETF draft `draft-ietf-pquip-hybrid-signature-spec`. We are not inventing a composition — we are deploying the standard one.

### 7.3 Cost

Per consensus message:

| Operation | Ed25519 alone | ML-DSA-65 alone | Hybrid |
|---|---|---|---|
| Sign | 80 µs | 220 µs | 300 µs |
| Verify | 200 µs | 80 µs | 280 µs |
| Signature size | 64 bytes | 3,309 bytes | 3,373 bytes |
| Public key size | 32 bytes | 1,952 bytes | 1,984 bytes |

The bandwidth overhead is real — a Vote that was 64 + 32 = 96 bytes of signature material is now 3,373 + 1,984 = 5,357 bytes. For a 100-validator chain, a single QC is ~340 KB instead of ~10 KB. We accept this for the safety property; it remains well within the libp2p gossipsub message-size limit (1 MB by default) and below any modern network's MTU concerns.

Aggregation across hybrid signatures is the obvious next optimisation. We have not deployed it because no standardised aggregation scheme exists for ML-DSA-65 (unlike BLS, ML-DSA was not designed for aggregation). The Tenzro roadmap tracks ongoing research in this area; near-term we accept the bandwidth cost.

### 7.4 Comparison

| Production chain | Vote signing | Quantum-safe? |
|---|---|---|
| Bitcoin | ECDSA (secp256k1) | No |
| Ethereum L1 | ECDSA (secp256k1) consensus, BLS12-381 attestations | No |
| Solana | Ed25519 | No |
| Aptos | Ed25519 + BLS12-381 multi-sig | No |
| Sui | Ed25519 / Secp256k1 / BLS12-381 | No |
| MonadBFT | BLS12-381 | No |
| **Tenzro** | **Ed25519 + ML-DSA-65 hybrid** | **Yes** |

To our knowledge Tenzro is the first L1 BFT chain to deploy hybrid post-quantum signatures across all consensus messages.

---

## 8. Implementation and verification

### 8.1 Code map

The bulk of the implementation lives in `crates/tenzro-consensus/`:

| File | Role |
|---|---|
| `lib.rs` | Public surface, type re-exports |
| `config.rs` | `ConsensusConfig`, `ProposerElectionKind` |
| `hotstuff2.rs` | The HotStuff-2 state machine |
| `validator.rs` | `ValidatorSet`, `ProposerElection` trait |
| `proposer.rs` | `ReputationProposer`, `RoundRobinProposer` |
| `leader_reputation.rs` | `LeaderReputation` engine, weight computation |
| `timeout.rs` | `TimeoutMsg`, `TimeoutCertificate`, `NoEndorsementMsg`, `NoEndorsementCertificate`, collectors |
| `vote_state.rs` | `EquivocationDetector` |
| `voter.rs` | `Vote` struct, vote signing/verification |
| `mempool.rs` | Transaction admission + ordering |
| `admission.rs` | Lane-based fee floor admission |
| `epoch_manager.rs` | Atomic epoch transitions, pending activation/exit queues |
| `finality.rs` | 2-chain finality tracker |
| `traits.rs` | `SlashingCallback`, `ConsensusOutMessage` |
| `error.rs` | `ConsensusError` |

The dynamic active-set machinery (§6.4) lives in two adjacent crates:

| File | Role |
|---|---|
| `tenzro-token/src/validator_registry.rs` | `ValidatorRegistry`, `ValidatorRegistryEntry`, `ValidatorRegistryStatus`, `EpochTransitionPlan`, churn-budget computation, RocksDB persistence under `validator:` prefix in `CF_TOKENS` |
| `tenzro-node/src/event_loop.rs` | Post-finalize hook that scans VM `ValidatorRegister` / `ValidatorExit` / `ValidatorMetadataUpdate` typed logs and reconciles the registry with the consensus `EpochManager`'s pending queues |

### 8.2 Testing

The `tenzro-consensus` crate's unit tests cover:

- LeaderReputation weight computation
- Anti-grinding seed determinism and domain separation
- Window edge cases (genesis, post-rollover)
- Stake-weighted draw distribution
- TC aggregation and verification
- NEC aggregation and verification
- Cross-message replay rejection (signing payload tag binding)
- Equivocation detection
- Epoch transition atomicity, including pending-activation and pending-exit queues

The dynamic active-set state machine is unit-tested in `tenzro-token` (registry transitions, churn-budget admission, re-entry cooldown, jail handling), and integration-tested end-to-end in `crates/tenzro-node/tests/validator_lifecycle_integration.rs` — that suite drives the full `Candidate → PendingActive → Active → PendingExit → Exited` lifecycle through the node's post-finalize bridge between the registry and the consensus `EpochManager`.

Beyond the unit and integration suites, the consensus engine is exercised end-to-end on the 4-pod testnet (3 validators + 1 RPC) deployed at `tenzro-testnet`.

### 8.3 What's verified, what isn't

**Verified by unit test:**
- The seed function `reputation_seed(epoch, round, prev_block_id)` is deterministic and depends on every input bit.
- Weight tier transitions occur at the FAILURE_THRESHOLD_PERCENT boundary.
- TCs and NECs reject duplicate signers, malformed format versions, and signatures from non-active validators.
- Hybrid signature verification correctly rejects either-half-only signatures.

**Verified by paper-and-pencil argument:**
- Safety follows from HotStuff-2's two-chain rule, unchanged.
- Liveness after GST follows from the DiemBFT v4 pacemaker, unchanged.
- Anti-grinding for the leader seed follows from the trailing-buffer argument (§4.3).

**Verified empirically by upstream production:**
- LeaderReputation behaviour at scale (Aptos mainnet, ~150 validators, 2021–present, ~12,000 TPS sustained).
- NEC behaviour at scale (MonadBFT mainnet, ~150 validators, November 2025–present, ~5,200 TPS sustained, 1-second finality).

**Not yet verified:**
- The combination of LeaderReputation + NEC + hybrid PQ on a production-scale validator set. Tenzro mainnet will be the first deployment of this combination; the Tenzro testnet (4 pods, single GKE node) is a smoke test, not a scalability proof.
- Long-running fault-injection studies (chaos testing, partitioning, validator-coordinated attacks).

We are explicit about the empirical-vs-formal boundary because it matters for risk assessment. The protocol is *correct* in the formal-verification sense to the extent that HotStuff-2 + DiemBFT pacemaker + MonadBFT NEC are correct; we have not introduced new safety-critical primitives. The protocol is *operationally sound* to the extent that its constituent parts are operationally sound in upstream production. But the *specific composition* has not run at production scale, and we will not claim that until it has.

---

## 9. Operating characteristics

### 9.1 Configurable parameters

Defaults are in `crates/tenzro-consensus/src/config.rs`:

| Parameter | Default | Justification |
|---|---|---|
| `block_time_ms` | 400 | Targets 2.5 blocks/sec under saturation. Aptos targets 250 ms; we are conservative. |
| `view_timeout_ms` | 2000 | 5× block_time. Allows 4 missed proposals before a forced view change. |
| `max_block_size` | 2 MiB | Safety against single-block DoS via libp2p message size. |
| `max_transactions_per_block` | 10,000 | Bounded execution time per block. |
| `max_gas_per_block` | 30,000,000 | Matches Ethereum mainnet. |
| `min_validators` | 4 | f = 1, smallest viable BFT set. |
| `bft_threshold` | TwoThirdsPlusOne | Standard 2f+1. |
| `epoch_duration` | 10,000 blocks | ~1 hour at 400 ms blocks. |
| `proposer_election` | Reputation | Default; RoundRobin retained for tests. |
| `optimistic_responsiveness` | true | Enables 2Δ finality when network is healthy. |

### 9.2 Throughput expectations

The protocol-level finality latency under partial synchrony is bounded by 2Δ (the round-trip QC formation time). At Tenzro testnet's intra-zone latency (~1 ms), 2Δ is dominated not by network round-trip but by the per-vote hybrid signature verification time (~280 µs × 2*f* + 1 votes for QC verification).

For a *n* = 100 validator set:
- QC verification = 280 µs × 67 = 18.7 ms.
- One block round = ~2 × 18.7 ms + execution + propagation ≈ 60 ms (network-bound for inter-region) or ~40 ms (intra-region).
- Theoretical ceiling: ~25 blocks/sec at *n* = 100.

For a *n* = 4 validator set (Tenzro testnet, single GKE zone):
- QC verification = 280 µs × 3 = 0.84 ms.
- Negligible network latency.
- Observed: ~10 blocks/sec empty-block finalization.
- Configured `block_time_ms = 400` caps proposal cadence to ~2.5/sec under saturation; observed 10/sec is fast empty-block finalization without proposal-rate limiting.

Real transaction throughput (TPS) is a function of block-fill rate and per-transaction execution cost, which is execution-layer-dependent and orthogonal to consensus. Aptos mainnet has demonstrated ~12,000 TPS at 150 validators with HotStuff-2 + LeaderReputation; MonadBFT mainnet has demonstrated ~5,200 TPS at ~150 validators with HotStuff-2 + NEC. We expect Tenzro to land in the same operating range when deployed at comparable validator counts and inter-region topology, with a per-vote hybrid signature overhead increasing block latency by a factor proportional to QC size. We do not yet have empirical data at production scale.

### 9.3 What the testnet currently demonstrates

The deployed testnet (3 validators + 1 RPC, all colocated on a single GKE node in `us-central1-a`) demonstrates:

- The protocol code compiles, links, and runs cleanly across all 21 workspace crates.
- Block production is stable: blocks finalize at ~10 blocks/sec with 0 pod restarts over multi-day windows.
- The hybrid signing path works end-to-end: every block, every vote, every timeout carries a verified Ed25519 + ML-DSA-65 signature.
- The reputation election runs: weights are recomputed every round; the leader-selection log shows non-uniform draws as the proposer history populates.
- The NEC code path is exercised at every view change.
- The permissionless validator registry (§6.4) is wired end-to-end: typed `RegisterValidator` / `ExitValidator` transactions land in mempool, execute, emit logs, and the post-finalize hook reconciles the registry with the consensus `EpochManager`. The four genesis validators populate via this same code path; the SEV-SNP node added on 2026-05-07 (task #412) is the first non-genesis validator to traverse the full lifecycle on a live network.

It does not demonstrate:

- Multi-region resilience (all 4 pods are in one zone on one node).
- Validator-count scalability (n = 4 is below the threshold where reputation election shows measurable benefit).
- Fault recovery under chaos (no pod-kill, partition, or Byzantine-injection drills run).
- Production-scale TPS (empty blocks finalize at ~10/sec; non-empty load testing is future work).

Section 9.4 of the operator guide (`docs/operators/OPERATOR_GUIDE.md`) tracks the multi-region deployment plan; it is independent of any code change to the consensus protocol itself.

---

## 10. Conclusion

Tenzro Consensus is a careful composition of four production-hardened ideas plus one defence-in-depth signing primitive. It is not novel in any single component — every individual mechanism here has shipped in another L1 — but the *combination* is, to our knowledge, unique:

- HotStuff-2 with linear communication and 2Δ optimistic finality.
- Aptos LeaderReputation, with a TEE-attestation multiplier applied multiplicatively rather than as a hard boost.
- MonadBFT No-Endorsement Certificates, closing the tail-fork attack class.
- A permissionless five-state validator registry (Ethereum Pectra + Sui + Aptos + Cosmos shapes) with separate activation and exit churn budgets, hybrid-PQ key binding at registration, and a Cosmos-style effective-date delay that preserves HotStuff-2's two-chain safety across reconfigurations.
- Ed25519 + ML-DSA-65 hybrid signatures across every safety-critical message, ahead of NIST PQC migration deadlines.

We have been careful in this paper to distinguish the formal correctness arguments (which inherit from the upstream literature) from the empirical operational claims (which are inherited from upstream production deployments), and to be explicit about the boundary: the *specific* combination of LeaderReputation + NEC + hybrid PQ has not run at production scale, and our testnet is a smoke test rather than a scale demonstration. The protocol's safety and liveness properties hold by composition; its operational characteristics at scale will be established by the public mainnet deployment.

The implementation is open source under Apache-2.0 at `github.com/tenzro/tenzro-network`, and this paper's constructions track the running code at `crates/tenzro-consensus/` line-for-line. Our intent is that any researcher or operator can read this document and the source side-by-side and verify the protocol matches its specification.

---

## References

1. **Yin, Malkhi, Reiter, Gueta, Abraham.** *HotStuff: BFT Consensus with Linearity and Responsiveness.* PODC 2019.
2. **Malkhi, Nayak.** *HotStuff-2: Optimal Two-Phase Responsive BFT.* Cryptology ePrint 2023/397.
3. **The Diem Authors.** *DiemBFT v4: State Machine Replication in the Diem Blockchain.* Technical report, 2021.
4. **Gelashvili, Spiegelman, Xiang, Danezis, Li, Malkhi, Xia, Zhou.** *Jolteon and Ditto: Network-Adaptive Efficient Consensus with Asynchronous Fallback.* FC 2022.
5. **Aptos Labs.** *Leader Reputation for Practical BFT Liveness.* Aptos research blog, 2021. Source: `aptos-core/consensus/src/liveness/leader_reputation.rs`.
6. **Monad Labs.** *MonadBFT: Pipelined Two-Phase BFT With Sub-Second Finality.* arXiv:2502.20692, February 2025.
7. **Wang, Distler, Cachin.** *Liveness Attacks On HotStuff: The Vulnerability Of Timer Doubling Mechanism.* Oxford CompJ, 2024.
8. **Malkhi.** *The Latest View on View Synchronization.* 2022.
9. **Dwork, Lynch, Stockmeyer.** *Consensus in the presence of partial synchrony.* JACM 35(2), 1988.
10. **NIST.** *FIPS 204: Module-Lattice-Based Digital Signature Standard (ML-DSA).* August 2024.
11. **NSA.** *Commercial National Security Algorithm Suite 2.0 (CNSA 2.0).* September 2022.
12. **IETF PQUIP WG.** *draft-ietf-pquip-hybrid-signature-spec — Composite ML-DSA Signatures.* In progress.

---

## Appendix A — Pseudocode

### A.1 Leader election

```
function elect_leader(epoch, round, prev_block_id, V, history):
    seed = SHA256(
        "TENZRO_LEADER_REPUTATION:" ||
        epoch.to_be_bytes() ||
        round.to_be_bytes() ||
        prev_block_id
    )

    (proposer_lo, proposer_hi) = proposer_window(round, |V|)
    (voter_lo, voter_hi)       = voter_window(round, |V|)

    if proposer_lo undefined or voter_lo undefined:
        // Genesis-adjacent — fall back to stake-weighted only
        return weighted_draw(seed, V, weight = stake)

    weights = {}
    for v in V:
        proposed = count(P[r].proposer == v for r in [proposer_lo, proposer_hi))
        failed   = count(P[r].proposer == v ∧ ¬P[r].success for r in [...))
        voted    = count(v ∈ W[r].voters for r in [voter_lo, voter_hi))

        if proposed ≥ 1 ∧ 100 * failed / proposed < 10:
            tier = ACTIVE_WEIGHT     // 1000
        elif voted ≥ 1:
            tier = INACTIVE_WEIGHT   // 10
        else:
            tier = FAILED_WEIGHT     // 1

        tee_mult = TEE_MULTIPLIER_BPS if v.tee_attested else NO_TEE_MULTIPLIER_BPS
        weights[v] = stake(v) * tier * tee_mult / 10000

    total = Σ weights[v] for v in V
    target = u128(seed[0..16]) mod total
    cursor = 0
    for v in sorted(V by address):
        cursor += weights[v]
        if cursor > target:
            return v
```

### A.2 NEC verification

```
function verify_nec(nec, validator_set):
    require nec.format_version == 1
    require nec.view > 0
    require len(nec.signers) ≥ f + 1 of validator_set
    require all signers distinct by address

    for signer in nec.signers:
        v = validator_set.get_by_address(signer.voter)
        require v exists ∧ v.is_active()
        require signer.public_key.classical == v.classical_pk
        require signer.public_key.pq        == v.pq_pk
        payload = "TENZRO_NO_ENDORSEMENT:" ||
                  format_version_byte ||
                  nec.view.to_le_bytes() ||
                  signer.voter
        require hybrid_verify(payload, signer.signature, signer.public_key)

    return Ok
```

### A.3 Proposal validity (round *r*)

```
function validate_proposal(p, validator_set):
    require validate_block(p.block)
    require verify_qc(p.high_qc, validator_set)

    if p.timeout_certificate is Some(tc):
        require verify_tc(tc, validator_set)
        require tc.view == p.block.view - 1

        // High-tip reproposal OR NEC required
        max_high_qc = max(s.high_qc_view for s in tc.signers)
        if p.block.qc.view ≥ max_high_qc:
            // High-tip reproposal — OK without NEC
            ok
        else:
            require p.no_endorsement_certificate is Some(nec)
            require verify_nec(nec, validator_set)
            require nec.view == p.block.view

    return Ok
```

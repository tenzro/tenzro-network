# tenzro-consensus

HotStuff-2 BFT consensus engine with reputation-weighted proposer election, no-endorsement certificates, and hybrid post-quantum signatures. Powers the Tenzro Ledger settlement layer.

## Overview

The crate composes these BFT mechanisms:

1. **Two-phase HotStuff-2** — linear-communication, partially-synchronous BFT with 2Δ optimistic finality.
2. **Reputation-weighted proposer election** — stake × observed-behaviour leader draw. Closes the small-validator-set stall mode that round-robin suffers when one validator is flaky.
3. **No-endorsement certificates (NECs)** — closes the tail-fork attack class on 2-chain HotStuff.
4. **Ed25519 + ML-DSA-65 hybrid signatures** — every safety-critical message (vote, timeout, no-endorsement) is hybrid-signed. NIST FIPS 204 compliant.
5. **Batch certificates** — a proposal references transaction batches by ID plus an erasure-availability threshold, so the leader's egress bandwidth no longer caps throughput when serving large payloads.
6. **Quorum-gated ZK commitment attestation** — a ZK proof commitment is recorded on-chain only after a validator quorum independently co-signs it, so no single validator can attest a proof that was never verified.

## Modules

| File | Lines | Role |
|---|---:|---|
| `lib.rs` | 231 | Public surface, type re-exports |
| `config.rs` | 211 | `ConsensusConfig`, `BftThreshold`, `ProposerElectionKind` |
| `hotstuff2.rs` | 3,562 | The HotStuff-2 state machine |
| `validator.rs` | 736 | `ValidatorSet`, `ProposerElection` trait |
| `proposer.rs` | 400 | `ReputationProposer`, `RoundRobinProposer` |
| `leader_reputation.rs` | 855 | `LeaderReputation` engine, weight computation, anti-grinding seed |
| `timeout.rs` | 1,710 | `TimeoutMsg` / `TimeoutCertificate` (TC) and `NoEndorsementMsg` / `NoEndorsementCertificate` (NEC) |
| `vote_state.rs` | 570 | `EquivocationDetector` |
| `voter.rs` | 724 | `Vote`, `QuorumCertificate`, `VoteCollector` |
| `batch_cert.rs` | 983 | `Batch` / batch certificates — decouple ordering bandwidth from data bandwidth so a proposal carries batch IDs plus an erasure-availability threshold instead of full transaction bodies |
| `zk_quorum.rs` | 897 | `ZkCommitmentClaim` / `ZkCosign` / `ZkQuorumCertificate` — a ZK commitment is accepted only after a quorum of validators independently co-sign it off-EVM, not a single validator's run |
| `mempool.rs` | 875 | Transaction admission + ordering |
| `admission.rs` | 622 | Lane-based fee floor admission |
| `epoch_manager.rs` | 574 | Atomic epoch transitions |
| `finality.rs` | 502 | 2-chain finality tracker |
| `traits.rs` | 123 | `ConsensusEngine`, `SlashingCallback`, `ConsensusOutMessage` |
| `error.rs` | 140 | `ConsensusError` |

11,835 LOC total.

## Protocol

### Two-phase HotStuff-2

Each view runs Prepare → Commit. A block is finalized once its child has formed a Commit QC at the next view (the 2-chain rule). Leader → replicas → leader vote flow keeps communication linear in the optimistic path.

### Reputation-weighted proposer election

Each round draws the leader from a stake-weighted seeded distribution where per-validator weight is multiplied by an observed-behaviour tier:

```
weight(v) = stake(v) × tier(v) × tee_multiplier(v) / 10000

tier(v):
  ACTIVE_WEIGHT   = 1000   if v proposed ≥1 QC-certified block recently
                            and failed <10% of its proposer-window rounds
  INACTIVE_WEIGHT = 10     if v voted but didn't propose
  FAILED_WEIGHT   = 1      otherwise

tee_multiplier(v):
  15000 (1.5×) if v has a fresh valid TEE attestation in the current epoch
  10000 (1.0×) otherwise
```

The 1000× spread between ACTIVE and FAILED collapses a chronically-flaky validator's effective draw probability to ~0.1% within ~20 rounds, long before its degradation propagates into chain-wide liveness loss.

The leader-draw seed is anti-grinding:

```
seed = SHA-256(
    "TENZRO_LEADER_REPUTATION:"
    || epoch.to_be_bytes()
    || round.to_be_bytes()
    || prev_finalized_block_id
)
```

`prev_finalized_block_id` is fixed at least one full QC ago, and the proposer-history window excludes the most recent 20 rounds (`TRAILING_BUFFER_ROUNDS = 20`), so an adversary leader cannot grind candidate blocks to bias future draws.

### TEE multiplier (1.5×, multiplicative)

A validator with a fresh, valid TEE attestation receives a 1.5× multiplier on its reputation-adjusted weight. The multiplicative form (rather than a hard 2× boost) preserves the property that observed behaviour can fully overcome attestation: a TEE-attested FAILED validator (weight = stake × 1 × 1.5) is still dwarfed by a non-TEE ACTIVE validator (weight = stake × 1000 × 1).

### No-Endorsement Certificates (NEC)

Closes the tail-fork attack on 2-chain HotStuff. The leader at view *v* must either:

- **Re-propose the high-tip from view v−1**, or
- **Attach a valid NEC for view v**

A NEC is a *f+1* aggregation of `NoEndorsementMsg`s, each attesting "I observed no QC at view v−1". *f+1* (not 2f+1) is the correct threshold: with at most *f* Byzantine signers, *f+1* suffices to guarantee at least one truthful "no QC observed" attestation. Domain tag `TENZRO_NO_ENDORSEMENT:` distinct from the timeout and vote tags prevents cross-message replay.

### Hybrid post-quantum signatures

Every safety-critical message carries a `CompositeSignature = Ed25519 || ML-DSA-65`. Verification is AND-composed — forging requires breaking both schemes. A quantum adversary that breaks Ed25519 (Shor's algorithm on EC discrete log) still cannot forge, because ML-DSA-65 is conjectured quantum-secure.

| Message | Domain tag |
|---|---|
| Vote | `TENZRO_VOTE:` |
| TimeoutMsg | `TENZRO_TIMEOUT:` |
| NoEndorsementMsg | `TENZRO_NO_ENDORSEMENT:` |
| Block proposal | `TENZRO_BLOCK:` |
| Reputation seed | `TENZRO_LEADER_REPUTATION:` |

### Byzantine fault tolerance

Tolerates up to *f* faulty validators where *f = ⌊(n−1)/3⌋*. Quorum is *2f+1*. With *n* = 4: *f* = 1, quorum = 3. With *n* = 100: *f* = 33, quorum = 67.

### Equivocation detection and slashing

The `EquivocationDetector` (in `vote_state.rs`) tracks per-validator votes per view. Two distinct votes from the same validator at the same view trigger:

```
StakingSlashingCallback::report_equivocation(validator, view, evidence) {
    slash_amount = stake.amount / 10;     // 10%
    staking.slash(validator, slash_amount, reason, ...);
    epoch_manager.remove_pending_validator(validator);
}
```

Pipeline: `EquivocationDetector` → `SlashingCallback` trait → `tenzro-node::StakingSlashingCallback` → `tenzro-token::StakingManager::slash` → on-chain TNZO burn. Slashed validators are dropped from the next epoch's pending queue.

### View change (pacemaker)

On local view timeout, replicas broadcast a signed `TimeoutMsg(view, high_qc_view)`. Receivers observing a higher-view timeout advance their local view. *2f+1* timeouts at the same view aggregate into a Timeout Certificate (TC). The next leader attaches the TC to its proposal.

If `view v−1` produced no QC, replicas additionally broadcast `NoEndorsementMsg(view=v)`. *f+1* of these aggregate into a NEC.

## Configuration

```rust
use tenzro_consensus::{ConsensusConfig, ProposerElectionKind};

let config = ConsensusConfig::default()
    .with_block_time(400)           // 400ms block time
    .with_view_timeout(2000)        // 2s view timeout
    .with_max_block_size(2_097_152) // 2MB
    .with_proposer_election(ProposerElectionKind::Reputation); // default
```

Defaults:

| Parameter | Default |
|---|---|
| `block_time_ms` | 400 |
| `view_timeout_ms` | 2000 |
| `max_block_size` | 2 MiB |
| `max_transactions_per_block` | 10,000 |
| `max_gas_per_block` | 30,000,000 |
| `min_validators` | 4 |
| `bft_threshold` | TwoThirdsPlusOne |
| `epoch_duration` | 10,000 blocks |
| `proposer_election` | Reputation |
| `optimistic_responsiveness` | true |

`ProposerElectionKind::RoundRobin` is retained for tests and replay benchmarks.

## Usage

```rust
use tenzro_consensus::{
    HotStuff2Engine, ConsensusConfig, ConsensusEngine,
    EpochManager, ValidatorInfo,
};
use tenzro_crypto::{KeyPair, KeyType};
use tenzro_crypto::pq::MlDsaSigningKey;
use tenzro_crypto::bls::BlsKeyPair;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let keypair = KeyPair::generate(KeyType::Ed25519)?;
    let pq_key = MlDsaSigningKey::generate()?;
    let bls_key = BlsKeyPair::generate()?;
    let address = keypair.address_32();

    let validators = vec![
        ValidatorInfo::new(
            address,
            keypair.public_key().clone(),
            pq_key.verifying_key_bytes().to_vec(),
            bls_key.public_key().to_bytes().to_vec(),
            1000,
        ),
    ];

    let epoch_manager = EpochManager::new(validators, 10000)?;
    let config = ConsensusConfig::default();
    let mut engine = HotStuff2Engine::new(keypair, pq_key, bls_key, config, epoch_manager);

    engine.start().await?;

    let mut finality_rx = engine.finality_tracker.subscribe();
    tokio::spawn(async move {
        while let Ok(notification) = finality_rx.recv().await {
            println!("Block finalized: height={} hash={}",
                notification.height, notification.hash);
        }
    });

    Ok(())
}
```

## Performance

Per consensus message, hybrid signing cost:

| Operation | Time |
|---|---|
| Sign (Ed25519 + ML-DSA-65) | ~300 µs |
| Verify | ~280 µs |
| Signature size | 3,373 bytes |
| Public key size | 1,984 bytes |

For *n* = 100 validators:

- QC verification (2f+1 = 67 hybrid checks): ~18.7 ms
- One block round (intra-region): ~40 ms
- Theoretical ceiling: ~25 blocks/sec

For *n* = 4 (current testnet, single-zone):

- QC verification (3 hybrid checks): ~0.84 ms
- Observed: ~10 blocks/sec empty-block finalization

Real TPS is execution-layer-dependent and orthogonal to consensus throughput. Production HotStuff-2 deployments at *n* ≈ 150 sustain in the range of 5,000–12,000 TPS depending on execution layer and block size; Tenzro is expected to fall in the same operating range when deployed at comparable validator counts.

## Safety and liveness

- **Safety.** No two honest replicas finalize different blocks at the same height. Follows from HotStuff-2's two-chain rule.
- **Liveness (after GST).** Progress guaranteed once *2f+1* honest validators exchange messages within bounded delay. Follows from the standard pacemaker liveness argument.
- **Single-validator-fault resilience.** Reputation election deprioritizes flaky validators within ~20 rounds.
- **Tail-fork resistance.** NEC blocks fresh-block proposals after a timeout unless f+1 validators attest no QC was observed.
- **Quantum forgery resistance.** Hybrid Ed25519 + ML-DSA-65 over every safety-critical signature.

## Test coverage

Unit tests cover:

- Reputation weight computation
- Anti-grinding seed determinism and domain separation
- Window edge cases (genesis, post-rollover)
- Stake-weighted draw distribution
- TC aggregation and verification
- NEC aggregation and verification
- Cross-message replay rejection (signing payload tag binding)
- Equivocation detection
- Epoch transition atomicity
- Hybrid signature verification (rejecting either-half-only signatures)

## Dependencies

- `tenzro-types`, `tenzro-crypto` — primitives, hybrid signing
- `tokio`, `async-trait` — async runtime
- `dashmap`, `parking_lot` — concurrent state
- `serde`, `serde_json`, `bincode` — serialization
- `tracing` — logging

## License

Apache License 2.0 — see [LICENSE](../../LICENSE).

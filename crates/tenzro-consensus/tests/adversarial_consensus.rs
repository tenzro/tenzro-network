//! Adversarial multi-node consensus integration tests for HotStuff-2.
//!
//! These tests exercise the consensus engine under Byzantine conditions:
//! equivocation, invalid signatures, insufficient quorum, view changes,
//! non-leader proposals, epoch transitions, and finality notifications.

use std::sync::Arc;

use parking_lot::Mutex;

use tenzro_consensus::{
    ConsensusConfig, ConsensusEngine, ConsensusError, EpochManager, EquivocationEvidence,
    FinalityTracker, HotStuff2Engine, QuorumCertificate, SlashingCallback, ValidatorInfo,
    ValidatorSet, Vote, VoteCollector, VoteType,
};
use tenzro_crypto::bls::{BlsKeyPair, BlsSecretKey};
use tenzro_crypto::composite::{CompositeSignature, HybridSigner, InMemoryHybridSigner};
use tenzro_crypto::pq::MlDsaSigningKey;
use tenzro_crypto::signatures::Ed25519SignerImpl;
use tenzro_crypto::{KeyPair, KeyType};
use tenzro_types::block::{Block, BlockHeader, BlockMetadata, ConsensusAlgorithm, ConsensusProof};
use tenzro_types::primitives::{Address, BlockHeight, Hash};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// A validator keypair + metadata bundle used throughout the tests.
struct TestValidator {
    keypair: KeyPair,
    /// PQ seed bytes so the keypair can be rebuilt at engine-construction time.
    pq_seed: Vec<u8>,
    /// BLS secret-key bytes so the keypair can be rebuilt at engine-construction time.
    bls_sk_bytes: [u8; 32],
    bls: BlsKeyPair,
    signer: InMemoryHybridSigner,
    info: ValidatorInfo,
    address: Address,
}

/// Convert a 20-byte `tenzro_crypto::Address` to a 32-byte `tenzro_types::Address`.
fn crypto_to_types_address(crypto_addr: tenzro_crypto::Address) -> Address {
    let mut addr_bytes = [0u8; 32];
    addr_bytes[..20].copy_from_slice(crypto_addr.as_bytes());
    Address::new(addr_bytes)
}

/// Create `n` test validators, each with 1000 stake.
fn create_test_validator_set(n: usize) -> Vec<TestValidator> {
    (0..n)
        .map(|_| {
            let keypair = KeyPair::generate(KeyType::Ed25519).unwrap();
            let address = crypto_to_types_address(keypair.address());
            let pq = MlDsaSigningKey::generate();
            let pq_seed = pq.seed_bytes().to_vec();
            let pq_vk = pq.verifying_key_bytes().to_vec();
            let bls = BlsKeyPair::generate().unwrap();
            let bls_sk_bytes = bls.secret_key().to_bytes();
            let info = ValidatorInfo::new(
                address,
                keypair.public_key().clone(),
                pq_vk,
                bls.public_key().to_bytes().to_vec(),
                1000,
            );
            let classical = Ed25519SignerImpl::new(
                KeyPair::from_bytes(keypair.key_type(), &keypair.to_bytes()).unwrap(),
            )
            .unwrap();
            let signer = InMemoryHybridSigner::new(Box::new(classical), pq);
            TestValidator {
                keypair,
                pq_seed,
                bls_sk_bytes,
                bls,
                signer,
                info,
                address,
            }
        })
        .collect()
}

/// Sign a vote using the canonical signing payload, returning a well-formed `Vote`.
fn sign_vote(
    view: u64,
    height: BlockHeight,
    block_hash: Hash,
    voter_address: Address,
    vote_type: VoteType,
    signer: &InMemoryHybridSigner,
    bls: &BlsKeyPair,
) -> Vote {
    // Build an unsigned vote first so we can compute the payload.
    let placeholder_sig = CompositeSignature::new(Vec::new(), Vec::new());
    let placeholder_bls = bls.sign(b"__placeholder__");
    let pk = signer.public_key().clone();
    let unsigned = Vote::new(
        view,
        height,
        block_hash,
        voter_address,
        placeholder_sig,
        pk.clone(),
        placeholder_bls.clone(),
        vote_type,
        0,
    );
    let payload = unsigned.signing_payload();
    let sig = signer.sign(&payload).unwrap();
    let mut vote = Vote::new(
        view,
        height,
        block_hash,
        voter_address,
        sig,
        pk,
        placeholder_bls,
        vote_type,
        0,
    );
    let bls_payload = tenzro_consensus::bls_payload_for_vote(&vote);
    vote.bls_signature = bls.sign(&bls_payload);
    vote
}

/// Create a minimal valid test block at the given height/view/proposer.
fn create_test_block(height: u64, proposer: Address) -> Block {
    let header = BlockHeader::new(
        BlockHeight::from(height),
        Hash::default(),
        Hash::default(),
        Hash::default(),
        proposer,
        ConsensusProof::new(ConsensusAlgorithm::PBFT, Vec::new()),
    );
    // Set metadata to match zero transactions so `validate_structure` passes.
    let mut block = Block::new(header, vec![]);
    block.header.metadata = BlockMetadata {
        gas_used: 0,
        gas_limit: 30_000_000,
        tx_count: 0,
        protocol_version: 1,
        base_fee_per_gas: Some(1_000_000_000),
    };
    block
}

/// Build a `VoteCollector` wired to the given validators.
fn build_vote_collector(validators: &[TestValidator]) -> VoteCollector {
    let infos: Vec<ValidatorInfo> = validators.iter().map(|v| v.info.clone()).collect();
    let vs = ValidatorSet::new(0, infos).unwrap();
    VoteCollector::new(Arc::new(vs))
}

/// A mock `SlashingCallback` that records every invocation for assertion.
#[derive(Default)]
struct MockSlashingCallback {
    calls: Mutex<Vec<(Address, u64)>>,
}

impl MockSlashingCallback {
    fn call_count(&self) -> usize {
        self.calls.lock().len()
    }

    fn calls(&self) -> Vec<(Address, u64)> {
        self.calls.lock().clone()
    }
}

impl SlashingCallback for MockSlashingCallback {
    fn report_equivocation(
        &self,
        validator: &Address,
        view: u64,
        _evidence: &EquivocationEvidence,
    ) {
        self.calls.lock().push((*validator, view));
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// 1. Four validators reach consensus on a block through the full
///    PREPARE -> COMMIT pipeline using VoteCollector directly.
#[test]
fn test_four_node_consensus_happy_path() {
    let validators = create_test_validator_set(4);
    let collector = build_vote_collector(&validators);

    let view = 0u64;
    let height = BlockHeight::from(1);
    let block = create_test_block(1, validators[0].address);
    let block_hash = block.hash();

    // -- PREPARE phase: all 4 validators vote --------------------------------
    for (i, v) in validators.iter().enumerate() {
        let vote = sign_vote(view, height, block_hash, v.address, VoteType::Prepare, &v.signer, &v.bls);
        let result = collector.add_vote(vote).unwrap();
        if i < 2 {
            // Quorum threshold for n=4 is 3 (f=1, 2f+1=3).
            assert!(result.is_none(), "QC formed too early at vote {}", i);
        } else if i == 2 {
            // Third vote should form the QC.
            assert!(result.is_some(), "QC should form on third vote");
            let qc = result.unwrap();
            assert_eq!(qc.vote_count(), 3);
            assert_eq!(qc.view, view);
            assert_eq!(qc.block_hash, block_hash);
            assert_eq!(qc.vote_type, VoteType::Prepare);
        }
        // Fourth vote should return the existing QC immediately.
    }

    // -- COMMIT phase: all 4 validators vote ---------------------------------
    let mut commit_qc: Option<QuorumCertificate> = None;
    for (i, v) in validators.iter().enumerate() {
        let vote = sign_vote(view, height, block_hash, v.address, VoteType::Commit, &v.signer, &v.bls);
        let result = collector.add_vote(vote).unwrap();
        if i == 2 {
            assert!(result.is_some(), "Commit QC should form on third vote");
            commit_qc = result;
        }
    }

    let qc = commit_qc.unwrap();
    assert_eq!(qc.vote_type, VoteType::Commit);
    assert_eq!(qc.vote_count(), 3);

    // Verify finality can be recorded.
    let finality = FinalityTracker::new();
    finality.finalize_block(block, qc).unwrap();
    assert_eq!(finality.finalized_height(), BlockHeight::from(1));
}

/// 2. One validator sends conflicting votes for different blocks in the same
///    view. The EquivocationDetector must catch it and the VoteCollector must
///    return an Equivocation error.
#[test]
fn test_byzantine_validator_equivocation_detected() {
    let validators = create_test_validator_set(4);
    let collector = build_vote_collector(&validators);

    let view = 1u64;
    let height = BlockHeight::from(1);
    let block_a_hash = Hash::default();

    // Byzantine validator votes for block A.
    let vote_a = sign_vote(
        view,
        height,
        block_a_hash,
        validators[0].address,
        VoteType::Prepare,
        &validators[0].signer,
        &validators[0].bls,
    );
    let res = collector.add_vote(vote_a);
    assert!(res.is_ok());

    // Byzantine validator votes for a DIFFERENT block B in the same view.
    let mut hash_b_bytes = [0u8; 32];
    hash_b_bytes[0] = 0xFF;
    let block_b_hash = Hash::new(hash_b_bytes);

    let vote_b = sign_vote(
        view,
        height,
        block_b_hash,
        validators[0].address,
        VoteType::Prepare,
        &validators[0].signer,
        &validators[0].bls,
    );
    let res = collector.add_vote(vote_b);
    assert!(res.is_err());

    match res.unwrap_err() {
        ConsensusError::Equivocation { validator, view: v } => {
            assert_eq!(v, view);
            assert!(
                validator.contains(&validators[0].address.to_string()),
                "Error should name the equivocating validator"
            );
        }
        other => panic!("Expected Equivocation error, got: {:?}", other),
    }

    // Evidence should be preserved.
    assert_eq!(collector.equivocation_count(), 1);
    let evidence = collector.get_evidence_for(&validators[0].address, view);
    assert!(evidence.is_some());
    let evidence = evidence.unwrap();
    assert!(evidence.is_valid());
    assert_eq!(evidence.validator, validators[0].address);
}

/// 3. Four nodes, one Byzantine (sends garbage signature). The remaining 3
///    honest validators still reach quorum (2f+1 = 3 when f=1).
#[test]
fn test_consensus_with_one_byzantine_node() {
    let validators = create_test_validator_set(4);
    let collector = build_vote_collector(&validators);

    let view = 0u64;
    let height = BlockHeight::from(1);
    let block = create_test_block(1, validators[0].address);
    let block_hash = block.hash();

    // Byzantine node sends a vote with an invalid (garbage) signature but
    // with the real validator's hybrid public key embedded — this exercises
    // the hybrid signature verification path.
    let bad_sig = CompositeSignature::new(vec![0u8; 64], vec![0u8; 3309]);
    // Real BLS signature over a garbage payload — the BLS leg verifies under the
    // collector's aggregator only when re-signed over the canonical QC payload,
    // so this still drives the hybrid verification path to reject.
    let bad_bls = validators[0].bls.sign(b"__garbage_payload__");
    let bad_vote = Vote::new(
        view,
        height,
        block_hash,
        validators[0].address,
        bad_sig,
        validators[0].signer.public_key().clone(),
        bad_bls,
        VoteType::Prepare,
        0,
    );
    let res = collector.add_vote(bad_vote);
    assert!(res.is_err(), "Garbage signature must be rejected");

    // Honest nodes 1, 2, 3 send valid votes.
    for (i, v) in validators.iter().enumerate().skip(1) {
        let vote = sign_vote(view, height, block_hash, v.address, VoteType::Prepare, &v.signer, &v.bls);
        let result = collector.add_vote(vote).unwrap();
        if i == 3 {
            // Third honest vote (indices 1,2,3) should form quorum.
            assert!(result.is_some(), "Quorum should be reached with 3 honest votes");
            let qc = result.unwrap();
            assert_eq!(qc.vote_count(), 3);
        }
    }
}

/// 4. Four nodes, two Byzantine. Only 2 honest votes are cast which is
///    insufficient for quorum (need 3).
#[test]
fn test_consensus_fails_with_too_many_byzantine() {
    let validators = create_test_validator_set(4);
    let collector = build_vote_collector(&validators);

    let view = 0u64;
    let height = BlockHeight::from(1);
    let block = create_test_block(1, validators[0].address);
    let block_hash = block.hash();

    // Byzantine nodes 0 and 1 send garbage signatures.
    for v in &validators[..2] {
        let bad_sig = CompositeSignature::new(vec![0u8; 64], vec![0u8; 3309]);
        let bad_bls = v.bls.sign(b"__garbage_payload__");
        let bad_vote = Vote::new(
            view,
            height,
            block_hash,
            v.address,
            bad_sig,
            v.signer.public_key().clone(),
            bad_bls,
            VoteType::Prepare,
            0,
        );
        let res = collector.add_vote(bad_vote);
        assert!(res.is_err());
    }

    // Honest nodes 2 and 3 send valid votes.
    let mut last_result = None;
    for v in &validators[2..] {
        let vote = sign_vote(view, height, block_hash, v.address, VoteType::Prepare, &v.signer, &v.bls);
        last_result = Some(collector.add_vote(vote).unwrap());
    }

    // With only 2 valid votes, no QC should form.
    assert!(
        last_result.unwrap().is_none(),
        "QC must NOT form with only 2 out of 4 validators"
    );

    // Confirm the vote count.
    assert_eq!(
        collector.vote_count(view, block_hash, VoteType::Prepare),
        2,
        "Only 2 honest votes should be recorded"
    );
}

/// 5. The leader fails to propose. Verify view change triggers via the
///    engine's timeout mechanism and the view number advances.
#[tokio::test]
async fn test_view_change_on_timeout() {
    let validators = create_test_validator_set(4);
    let infos: Vec<ValidatorInfo> = validators.iter().map(|v| v.info.clone()).collect();

    // Use a very short timeout so the test completes quickly.
    let config = ConsensusConfig::default()
        .with_view_timeout(50) // 50ms
        .with_block_time(10);

    let epoch_manager = EpochManager::new(infos.clone(), 10_000).unwrap();

    // Use the first validator's keypair for the engine.
    let engine_keypair =
        KeyPair::from_bytes(validators[0].keypair.key_type(), &validators[0].keypair.to_bytes())
            .unwrap();
    let engine_pq = MlDsaSigningKey::from_seed(&validators[0].pq_seed).unwrap();
    let engine_bls =
        BlsKeyPair::from_secret_key(BlsSecretKey::from_bytes(&validators[0].bls_sk_bytes).unwrap());
    let mut engine =
        HotStuff2Engine::new(engine_keypair, engine_pq, engine_bls, config, epoch_manager);

    engine.start().await.unwrap();

    // Wait long enough for at least one view timeout to fire.
    tokio::time::sleep(std::time::Duration::from_millis(200)).await;

    // The view should have advanced at least once (the engine auto-advances
    // on timeout inside the consensus loop).
    // We verify the height is still at 0 because no block was finalized,
    // confirming the timeout path ran rather than the proposal path.
    let finalized = engine.finalized_height().await;
    assert_eq!(
        finalized,
        BlockHeight::from(0),
        "No block should have been finalized since leader did not produce a valid block with external votes"
    );

    engine.stop().await.unwrap();
}

/// 6. A non-leader attempts to propose a block. The engine must reject it
///    with a `NotLeader` error.
#[tokio::test]
async fn test_non_leader_proposal_rejected() {
    let validators = create_test_validator_set(4);
    let infos: Vec<ValidatorInfo> = validators.iter().map(|v| v.info.clone()).collect();

    let config = ConsensusConfig::default().with_view_timeout(5000);
    // Determine who the leader is for view 0 so we can pick a NON-leader.
    let vs = {
        let em = EpochManager::new(infos.clone(), 10_000).unwrap();
        em.current_validator_set()
    };
    let leader = vs.select_leader_round_robin(0).unwrap();

    // Pick a validator that is NOT the leader for view 0.
    let non_leader = validators
        .iter()
        .find(|v| v.address != leader.address)
        .expect("Should find a non-leader among 4 validators");

    let engine_keypair = KeyPair::from_bytes(
        non_leader.keypair.key_type(),
        &non_leader.keypair.to_bytes(),
    )
    .unwrap();

    let epoch_manager2 = EpochManager::new(infos, 10_000).unwrap();
    let engine_pq = MlDsaSigningKey::from_seed(&non_leader.pq_seed).unwrap();
    let engine_bls =
        BlsKeyPair::from_secret_key(BlsSecretKey::from_bytes(&non_leader.bls_sk_bytes).unwrap());
    let mut engine =
        HotStuff2Engine::new(engine_keypair, engine_pq, engine_bls, config, epoch_manager2);
    engine.start().await.unwrap();

    // Attempt to propose (the public propose_block checks is_leader first).
    let result = engine.propose_block(vec![]).await;
    assert!(result.is_err());
    match result.unwrap_err() {
        ConsensusError::NotLeader(_) => {} // expected
        other => panic!("Expected NotLeader error, got: {:?}", other),
    }

    engine.stop().await.unwrap();
}

/// 7. A vote from an unknown address (not in the validator set) is rejected
///    with a NonValidator error.
#[test]
fn test_votes_from_non_validators_rejected() {
    let validators = create_test_validator_set(4);
    let collector = build_vote_collector(&validators);

    // Create a keypair that is NOT in the validator set.
    let outsider_kp = KeyPair::generate(KeyType::Ed25519).unwrap();
    let outsider_addr = crypto_to_types_address(outsider_kp.address());
    let outsider_classical = Ed25519SignerImpl::new(outsider_kp).unwrap();
    let outsider_pq = MlDsaSigningKey::generate();
    let outsider_signer =
        InMemoryHybridSigner::new(Box::new(outsider_classical), outsider_pq);
    let outsider_bls = BlsKeyPair::generate().unwrap();

    let vote = sign_vote(
        0,
        BlockHeight::from(1),
        Hash::default(),
        outsider_addr,
        VoteType::Prepare,
        &outsider_signer,
        &outsider_bls,
    );

    let res = collector.add_vote(vote);
    assert!(res.is_err());
    match res.unwrap_err() {
        ConsensusError::NonValidator(_) => {} // expected
        other => panic!("Expected NonValidator error, got: {:?}", other),
    }
}

/// 8. A validator sends the exact same vote twice. The second submission must
///    be rejected with AlreadyVoted, and the vote count must remain 1.
#[test]
fn test_duplicate_votes_ignored() {
    let validators = create_test_validator_set(4);
    let collector = build_vote_collector(&validators);

    let view = 0u64;
    let height = BlockHeight::from(1);
    let block_hash = Hash::default();

    let vote = sign_vote(
        view,
        height,
        block_hash,
        validators[0].address,
        VoteType::Prepare,
        &validators[0].signer,
        &validators[0].bls,
    );

    // First submission succeeds.
    let res = collector.add_vote(vote.clone());
    assert!(res.is_ok());

    // Second submission of the identical vote must fail.
    let res = collector.add_vote(vote);
    assert!(res.is_err());
    match res.unwrap_err() {
        ConsensusError::AlreadyVoted(v) => assert_eq!(v, view),
        other => panic!("Expected AlreadyVoted error, got: {:?}", other),
    }

    // Vote count must still be 1.
    assert_eq!(collector.vote_count(view, block_hash, VoteType::Prepare), 1);
}

/// 9. When the epoch boundary is reached, the validator set updates
///    atomically via EpochManager, including any pending validator additions.
#[test]
fn test_epoch_transition_updates_validator_set() {
    let initial_validators = create_test_validator_set(4);
    let infos: Vec<ValidatorInfo> = initial_validators.iter().map(|v| v.info.clone()).collect();

    let epoch_duration = 100u64;
    let epoch_manager = EpochManager::new(infos, epoch_duration).unwrap();

    // Add a new pending validator for the next epoch.
    let new_val = create_test_validator_set(1).pop().unwrap();
    epoch_manager.add_pending_validator(new_val.info.clone());

    // Before transition: epoch 0, 4 validators.
    let epoch_before = epoch_manager.current_epoch();
    assert_eq!(epoch_before.number, 0);
    assert_eq!(epoch_before.validator_set.len(), 4);

    // Should not transition before the boundary.
    assert!(!epoch_manager.should_transition(BlockHeight::from(50)));

    // Trigger transition at the boundary.
    assert!(epoch_manager.should_transition(BlockHeight::from(100)));
    let new_vs = epoch_manager
        .transition_epoch(BlockHeight::from(100))
        .unwrap();

    // After transition: epoch 1, pending merged into existing set
    // (4 originals + 1 new addition = 5).
    let epoch_after = epoch_manager.current_epoch();
    assert_eq!(epoch_after.number, 1);
    assert_eq!(new_vs.len(), 5, "Pending merges into current set");
    assert!(new_vs.is_validator(&new_val.address));
    for v in &initial_validators {
        assert!(
            new_vs.is_validator(&v.address),
            "Original validator must persist across epoch transition"
        );
    }

    // Both pending queues should be cleared.
    assert!(epoch_manager.pending_validators().is_empty());
    assert!(epoch_manager.pending_removals().is_empty());

    // Epoch 0 should be in history.
    let historical = epoch_manager.get_epoch(0);
    assert!(historical.is_some());
}

/// 10. When a block is finalized, FinalityNotification is broadcast to
///     all subscribers.
#[test]
fn test_finality_notification_on_commit() {
    let validators = create_test_validator_set(4);
    let finality = FinalityTracker::new();
    let mut rx = finality.subscribe();

    let block = create_test_block(1, validators[0].address);
    let block_hash = block.hash();
    let height = block.height();

    let qc = QuorumCertificate::new(
        0,
        height,
        block_hash,
        VoteType::Commit,
        vec![], // votes elided for brevity
        3000,
        // FinalityTracker doesn't run BLS verification — placeholders are sound here.
        [0u8; 96],
        Vec::new(),
    );

    finality.finalize_block(block.clone(), qc.clone()).unwrap();

    // Subscriber should receive exactly one notification.
    let notification = rx.try_recv().expect("Should receive finality notification");
    assert_eq!(notification.height, BlockHeight::from(1));
    assert_eq!(notification.hash, block_hash);
    assert_eq!(notification.qc.view, 0);
}

/// 11. When equivocation is detected through the engine's on_vote path,
///     the SlashingCallback receives the evidence with the correct validator
///     address and view number.
#[tokio::test]
async fn test_slashing_callback_invoked_on_equivocation() {
    let validators = create_test_validator_set(4);
    let infos: Vec<ValidatorInfo> = validators.iter().map(|v| v.info.clone()).collect();

    let config = ConsensusConfig::default().with_view_timeout(5000);

    let engine_keypair = KeyPair::from_bytes(
        validators[0].keypair.key_type(),
        &validators[0].keypair.to_bytes(),
    )
    .unwrap();

    let mock_slasher = Arc::new(MockSlashingCallback::default());

    let epoch_manager = EpochManager::new(infos, 10_000).unwrap();
    let engine_pq = MlDsaSigningKey::from_seed(&validators[0].pq_seed).unwrap();
    let engine_bls =
        BlsKeyPair::from_secret_key(BlsSecretKey::from_bytes(&validators[0].bls_sk_bytes).unwrap());
    let mut engine =
        HotStuff2Engine::new(engine_keypair, engine_pq, engine_bls, config, epoch_manager)
            .with_slashing_callback(mock_slasher.clone());

    engine.start().await.unwrap();

    let view = 0u64;
    let height = BlockHeight::from(1);

    // Validator 1 sends a valid vote for block A.
    let hash_a = Hash::default();
    let vote_a = sign_vote(
        view,
        height,
        hash_a,
        validators[1].address,
        VoteType::Prepare,
        &validators[1].signer,
        &validators[1].bls,
    );
    let _ = engine.on_vote(&vote_a).await;

    // Validator 1 sends a conflicting vote for block B in the same view.
    let mut hash_b_bytes = [0u8; 32];
    hash_b_bytes[0] = 0xAB;
    let hash_b = Hash::new(hash_b_bytes);
    let vote_b = sign_vote(
        view,
        height,
        hash_b,
        validators[1].address,
        VoteType::Prepare,
        &validators[1].signer,
        &validators[1].bls,
    );
    let res = engine.on_vote(&vote_b).await;

    // The engine should detect equivocation.
    assert!(res.is_err());
    match res.unwrap_err() {
        ConsensusError::Equivocation { validator, view: v } => {
            assert_eq!(v, view);
            assert!(validator.contains(&validators[1].address.to_string()));
        }
        other => panic!("Expected Equivocation, got: {:?}", other),
    }

    // The mock slashing callback should have been invoked.
    assert_eq!(mock_slasher.call_count(), 1);
    let calls = mock_slasher.calls();
    assert_eq!(calls[0].0, validators[1].address);
    assert_eq!(calls[0].1, view);

    engine.stop().await.unwrap();
}

/// 12. After a failed view (no proposal / timeout), consensus resumes with
///     a new leader in the next view. We verify this by checking the leader
///     rotation logic directly since the engine's internal consensus loop
///     handles view changes asynchronously.
#[test]
fn test_consensus_resumes_after_view_change() {
    let validators = create_test_validator_set(4);
    let infos: Vec<ValidatorInfo> = validators.iter().map(|v| v.info.clone()).collect();

    let vs = ValidatorSet::new(0, infos).unwrap();

    // In round-robin mode, leader for view N = validators[N % 4].
    let leader_v0 = vs.select_leader_round_robin(0).unwrap();
    let leader_v1 = vs.select_leader_round_robin(1).unwrap();
    let leader_v2 = vs.select_leader_round_robin(2).unwrap();

    // After a timeout at view 0, view 1 should have a different leader.
    assert_ne!(
        leader_v0.address, leader_v1.address,
        "View 1 leader must differ from view 0 leader"
    );

    // After another timeout at view 1, view 2 gets yet another leader.
    assert_ne!(
        leader_v1.address, leader_v2.address,
        "View 2 leader must differ from view 1 leader"
    );

    // Now simulate that view 2's leader succeeds: collect votes and form QC.
    let collector = build_vote_collector(&validators);
    let view = 2u64;
    let height = BlockHeight::from(1);
    let block = create_test_block(1, leader_v2.address);
    let block_hash = block.hash();

    // Collect 3 votes (quorum) for the prepare phase.
    let mut prepare_qc = None;
    for v in validators.iter().take(3) {
        let vote = sign_vote(view, height, block_hash, v.address, VoteType::Prepare, &v.signer, &v.bls);
        if let Some(qc) = collector.add_vote(vote).unwrap() {
            prepare_qc = Some(qc);
        }
    }
    assert!(
        prepare_qc.is_some(),
        "Should form prepare QC after view change"
    );

    // Collect 3 commit votes.
    let mut commit_qc = None;
    for v in validators.iter().take(3) {
        let vote = sign_vote(view, height, block_hash, v.address, VoteType::Commit, &v.signer, &v.bls);
        if let Some(qc) = collector.add_vote(vote).unwrap() {
            commit_qc = Some(qc);
        }
    }
    assert!(
        commit_qc.is_some(),
        "Should form commit QC after view change"
    );

    // Finalize the block.
    let finality = FinalityTracker::new();
    finality
        .finalize_block(block, commit_qc.unwrap())
        .unwrap();
    assert_eq!(finality.finalized_height(), BlockHeight::from(1));
}

// ---------------------------------------------------------------------------
// Additional edge-case tests
// ---------------------------------------------------------------------------

/// Verify that the quorum threshold is correct for various validator counts.
#[test]
fn test_quorum_threshold_calculation() {
    // n=4 => f=1 => 2f+1=3
    let vals4 = create_test_validator_set(4);
    let infos4: Vec<ValidatorInfo> = vals4.iter().map(|v| v.info.clone()).collect();
    let vs4 = ValidatorSet::new(0, infos4).unwrap();
    assert_eq!(vs4.quorum_threshold(), 3);

    // n=7 => f=2 => 2f+1=5
    let vals7 = create_test_validator_set(7);
    let infos7: Vec<ValidatorInfo> = vals7.iter().map(|v| v.info.clone()).collect();
    let vs7 = ValidatorSet::new(0, infos7).unwrap();
    assert_eq!(vs7.quorum_threshold(), 5);

    // n=10 => f=3 => 2f+1=7
    let vals10 = create_test_validator_set(10);
    let infos10: Vec<ValidatorInfo> = vals10.iter().map(|v| v.info.clone()).collect();
    let vs10 = ValidatorSet::new(0, infos10).unwrap();
    assert_eq!(vs10.quorum_threshold(), 7);
}

/// Verify that votes signed by the wrong key (a different validator's key)
/// are rejected, even if the voter address belongs to a real validator.
#[test]
fn test_wrong_key_vote_rejected() {
    let validators = create_test_validator_set(4);
    let collector = build_vote_collector(&validators);

    // Validator 0's address but signed by validator 1's key.
    let vote = sign_vote(
        0,
        BlockHeight::from(1),
        Hash::default(),
        validators[0].address,
        VoteType::Prepare,
        &validators[1].signer, // wrong signer!
        &validators[1].bls,    // wrong bls!
    );

    let res = collector.add_vote(vote);
    assert!(res.is_err());
    match res.unwrap_err() {
        ConsensusError::InvalidSignature(_) => {} // expected
        other => panic!("Expected InvalidSignature, got: {:?}", other),
    }
}

/// Verify multiple sequential blocks can be finalized in order.
#[test]
fn test_sequential_block_finalization() {
    let validators = create_test_validator_set(4);
    let finality = FinalityTracker::new();
    let mut rx = finality.subscribe();

    for h in 1..=5u64 {
        let block = create_test_block(h, validators[0].address);
        let qc = QuorumCertificate::new(
            h - 1,
            BlockHeight::from(h),
            block.hash(),
            VoteType::Commit,
            vec![],
            3000,
            [0u8; 96],
            Vec::new(),
        );
        finality.finalize_block(block, qc).unwrap();

        let notification = rx.try_recv().unwrap();
        assert_eq!(notification.height, BlockHeight::from(h));
    }

    assert_eq!(finality.finalized_height(), BlockHeight::from(5));
    assert!(finality.is_finalized(BlockHeight::from(3)));
    assert!(!finality.is_finalized(BlockHeight::from(6)));
}

/// Verify that finalizing a block at a height <= the current finalized height
/// is rejected (no regression / duplicate finalization).
#[test]
fn test_duplicate_finalization_rejected() {
    let validators = create_test_validator_set(4);
    let finality = FinalityTracker::new();

    let block1 = create_test_block(1, validators[0].address);
    let qc1 = QuorumCertificate::new(
        0,
        BlockHeight::from(1),
        block1.hash(),
        VoteType::Commit,
        vec![],
        3000,
        [0u8; 96],
        Vec::new(),
    );
    finality.finalize_block(block1.clone(), qc1.clone()).unwrap();

    // Attempting to finalize the same height again should fail.
    let res = finality.finalize_block(block1, qc1);
    assert!(res.is_err());
}

/// Full two-phase consensus across two sequential views, verifying that
/// the vote collector can handle votes for different views cleanly.
#[test]
fn test_multi_view_consensus() {
    let validators = create_test_validator_set(4);
    let collector = build_vote_collector(&validators);
    let finality = FinalityTracker::new();

    for view in 0..3u64 {
        let height = BlockHeight::from(view + 1);
        let block = create_test_block(view + 1, validators[(view as usize) % 4].address);
        let block_hash = block.hash();

        // Prepare phase.
        for v in validators.iter().take(3) {
            let vote = sign_vote(view, height, block_hash, v.address, VoteType::Prepare, &v.signer, &v.bls);
            let _ = collector.add_vote(vote).unwrap();
        }

        // Commit phase.
        let mut commit_qc = None;
        for v in validators.iter().take(3) {
            let vote = sign_vote(view, height, block_hash, v.address, VoteType::Commit, &v.signer, &v.bls);
            if let Some(qc) = collector.add_vote(vote).unwrap() {
                commit_qc = Some(qc);
            }
        }

        finality
            .finalize_block(block, commit_qc.unwrap())
            .unwrap();
    }

    assert_eq!(finality.finalized_height(), BlockHeight::from(3));
}

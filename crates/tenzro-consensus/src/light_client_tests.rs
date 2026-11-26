//! The light client and the compact certificate verifier, against certificates
//! made by this crate's vote collector and software test keys.

use tenzro_light::TrustAnchor;
use tenzro_light::light_client::*;

use crate::checkpoint::test_support::{MemoryHighWater, checkpoint, sign_as};
use crate::checkpoint::{Certificate, Checkpoint, VoteCollector, VoteOutcome};
use crate::committee::test_support::committee;
use crate::committee::{Committee, ValidatorIndex};
use crate::session::{SessionBook, SessionCertificate};
use crate::validator_key::test_signer::SoftwareTestSigner;
use crate::vertex::Digest;

fn certify<S: std::borrow::Borrow<SoftwareTestSigner>>(
    c: &Committee,
    s: &[S],
    who: &[ValidatorIndex],
    cp: &Checkpoint,
) -> (Certificate, Vec<SessionCertificate>) {
    let mut book = SessionBook::new(cp.chain_id, cp.genesis_hash, cp.epoch);
    let mut col = VoteCollector::new();
    let mut out = None;
    for i in who {
        let v = sign_as(s[*i as usize].borrow(), &MemoryHighWater::default(), *i, cp).unwrap();
        book.admit(c, v.signature.session.clone()).unwrap();
        if let VoteOutcome::Certified(cert) = col.add(c, v) {
            out = Some(*cert);
        }
    }
    let cert = out.expect("quorum");
    let sessions = book.bundle(&cert.sessions);
    (cert, sessions)
}

/// A checkpoint of epoch 1, proved from the genesis committee through
/// the handover that ends epoch 0.
/// A clock under which every test checkpoint is current: these tests are
/// about certificates, not freshness.
fn any_time() -> tenzro_light::Clock {
    tenzro_light::Clock {
        now_ms: 0,
        max_age_ms: u64::MAX,
        max_ahead_ms: u64::MAX,
    }
}

fn proof() -> (CheckpointProof, TrustAnchor) {
    let (c0, s) = committee(4);
    let c1 = Committee::from_members(1, c0.members().to_vec()).unwrap();
    let end = Checkpoint {
        next_committee_root: Some(c1.root()),
        ..checkpoint(5, 1)
    };
    let (handover, handover_sessions) = certify(&c0, &s, &[0, 1, 2], &end);
    let cp = Checkpoint {
        epoch: 1,
        ..checkpoint(9, 2)
    };
    let (certificate, sessions) = certify(&c1, &s, &[1, 2, 3], &cp);
    let anchor = TrustAnchor {
        epoch: 0,
        chain_id: 7,
        genesis_hash: [1; 32],
        committee_root: c0.root(),
    };
    let proof = CheckpointProof {
        genesis_members: c0.members().to_vec(),
        handovers: vec![EpochHandover {
            certificate: handover,
            sessions: handover_sessions,
            next_members: c1.members().to_vec(),
        }],
        certificate,
        sessions,
    };
    (proof, anchor)
}

/// A session certificate that fails admission is dropped from a checkpoint
/// proof, not fatal to it, as it always was: old and new nodes reach the
/// same verdict on the same proof.
#[test]
fn a_session_certificate_that_fails_admission_is_dropped_from_a_checkpoint_proof() {
    let (mut proof, anchor) = proof();
    let mut foreign = proof.sessions[0].clone();
    foreign.chain_id += 1;
    proof.sessions.insert(0, foreign.clone());
    proof.handovers[0].sessions.push(foreign);
    assert_eq!(proof.verify(&anchor).unwrap().index, 9);
}

#[test]
fn a_checkpoint_proof_verifies_from_genesis_and_refuses_what_is_not_certified() {
    let (proof, anchor) = proof();
    assert_eq!(proof.verify(&anchor).unwrap().index, 9);

    let mut m = proof.clone();
    m.certificate.checkpoint.state_root[0] ^= 1;
    assert!(
        m.verify(&anchor).is_err(),
        "a state root the committee did not sign"
    );

    let mut m = proof.clone();
    m.certificate.signers.truncate(2);
    m.certificate.sessions.truncate(2);
    m.certificate.signatures.truncate(2);
    assert!(m.verify(&anchor).is_err(), "less than a quorum");

    let mut m = proof.clone();
    m.handovers.clear();
    assert!(
        m.verify(&anchor).is_err(),
        "no way from genesis to the checkpoint's epoch"
    );

    let mut m = proof.clone();
    m.handovers[0].next_members[0].stake += 1;
    assert!(
        m.verify(&anchor).is_err(),
        "a committee the handover does not commit"
    );

    assert!(
        proof
            .verify(&TrustAnchor {
                committee_root: [0; 32],
                ..anchor
            })
            .is_err(),
        "another genesis committee"
    );
    assert!(
        proof
            .verify(&TrustAnchor {
                chain_id: 8,
                ..anchor
            })
            .is_err(),
        "another chain"
    );
    let later = proof
        .verify(&TrustAnchor { epoch: 1, ..anchor })
        .unwrap_err();
    assert!(
        later.to_string().contains("genesis anchor"),
        "an anchor of a later epoch: {later}"
    );

    // Signed by a committee that is not the chain's: its own members,
    // presented as genesis, do not match the anchor.
    let (outsiders, _) = committee(5);
    let mut m = proof.clone();
    m.genesis_members = outsiders.members().to_vec();
    assert!(m.verify(&anchor).is_err(), "a committee outside the anchor");
}

/// A checkpoint proven from the newest handover chain proof alone: the
/// receipt stands for every handover before the epoch it reaches, so the
/// proof carries that epoch's committee and no handover. Checking the
/// receipt itself is the zkVM verifier's part; here it hands the journal.
#[test]
fn a_chained_proof_verifies_from_the_chain_proof_alone() {
    let (proof, a) = proof();
    let program = [0x42; 32];
    let anchor = ChainAnchor {
        chain_id: a.chain_id,
        genesis_hash: a.genesis_hash,
        genesis_root: a.committee_root,
        program,
    };
    let c1 = proof.handovers[0].next_members.clone();
    let c1_root = Committee::from_members(1, c1.clone()).unwrap().root();
    let journal = HandoverChainJournal {
        program,
        chain_id: 7,
        genesis_hash: [1; 32],
        genesis_root: a.committee_root,
        epoch: 1,
        committee_root: c1_root,
    };
    let proves = |j: HandoverChainJournal| {
        move |p: &Digest, r: &[u8]| -> std::result::Result<Vec<u8>, String> {
            if r == b"receipt" && *p == j.program {
                Ok(j.encode())
            } else {
                Err("not a receipt of the program".into())
            }
        }
    };
    let chained = ChainedCheckpointProof {
        chain: b"receipt".to_vec(),
        members: c1.clone(),
        handovers: Vec::new(),
        certificate: proof.certificate.clone(),
        sessions: proof.sessions.clone(),
    };
    assert_eq!(chained.verify(&anchor, proves(journal)).unwrap().index, 9);

    // With no chain proof yet, the same proof walks from genesis.
    let walked = ChainedCheckpointProof {
        chain: Vec::new(),
        members: proof.genesis_members.clone(),
        handovers: proof.handovers.clone(),
        certificate: proof.certificate.clone(),
        sessions: proof.sessions.clone(),
    };
    assert_eq!(walked.verify(&anchor, proves(journal)).unwrap().index, 9);

    let other = HandoverChainJournal {
        program: [7; 32],
        ..journal
    };
    assert!(
        chained
            .verify(
                &ChainAnchor {
                    program: [7; 32],
                    ..anchor
                },
                proves(journal)
            )
            .is_err(),
        "a receipt of another program"
    );
    assert!(
        chained
            .verify(&anchor, |_: &Digest, _: &[u8]| Ok(other.encode()))
            .is_err(),
        "a journal naming another program"
    );
    assert!(
        chained
            .verify(&anchor, |_: &Digest, _: &[u8]| Err("forged".to_string()))
            .is_err(),
        "a receipt that does not verify"
    );
    let elsewhere = HandoverChainJournal {
        genesis_root: [9; 32],
        ..journal
    };
    assert!(
        chained.verify(&anchor, proves(elsewhere)).is_err(),
        "a chain from another genesis committee"
    );
    let mut m = chained.clone();
    m.members[0].stake += 1;
    assert!(
        m.verify(&anchor, proves(journal)).is_err(),
        "members that are not the committee the chain reaches"
    );
    let behind = HandoverChainJournal {
        epoch: 0,
        committee_root: a.committee_root,
        ..journal
    };
    let mut m = chained.clone();
    m.members = proof.genesis_members.clone();
    assert!(
        m.verify(&anchor, proves(behind)).is_err(),
        "a chain that stops short of the checkpoint's epoch"
    );
    let mut m = chained.clone();
    m.certificate.checkpoint.state_root[0] ^= 1;
    assert!(
        m.verify(&anchor, proves(journal)).is_err(),
        "a state root the committee did not sign"
    );
}

/// Either form of certification verifies through the one call, a chained
/// one only against a named handover program, and the JSON of each comes
/// back as the same form.
#[test]
fn a_certification_takes_either_form() {
    let (proof, a) = proof();
    let program = [0x42; 32];
    let no_receipt =
        |_: &Digest, _: &[u8]| -> std::result::Result<Vec<u8>, String> { Err("no receipt".into()) };
    let walked = ChainedCheckpointProof {
        chain: Vec::new(),
        members: proof.genesis_members.clone(),
        handovers: proof.handovers.clone(),
        certificate: proof.certificate.clone(),
        sessions: proof.sessions.clone(),
    };
    for c in [
        Certification::FromGenesis(proof.clone()),
        Certification::Chained(walked),
    ] {
        assert_eq!(c.checkpoint().index, 9);
        assert_eq!(c.verify(&a, Some(program), no_receipt).unwrap().index, 9);
        let json = serde_json::to_value(&c).unwrap();
        assert_eq!(serde_json::from_value::<Certification>(json).unwrap(), c);
    }
    let chained = Certification::Chained(ChainedCheckpointProof {
        chain: b"receipt".to_vec(),
        members: proof.genesis_members.clone(),
        handovers: Vec::new(),
        certificate: proof.certificate.clone(),
        sessions: proof.sessions.clone(),
    });
    assert!(
        chained.verify(&a, None, no_receipt).is_err(),
        "a chained certification is checked against a named program"
    );
    assert!(
        chained.verify(&a, Some(program), no_receipt).is_err(),
        "a receipt that does not verify"
    );
}

/// A light client follows a served segment: from genesis through its
/// handovers, or from the committee its chain proof reaches with none,
/// and then accepts the checkpoint; members that are not that committee,
/// another genesis or an unnamed program are refused.
#[test]
fn a_light_client_follows_a_served_segment() {
    let (proof, a) = proof();
    let program = [0x42; 32];
    let c1 = proof.handovers[0].next_members.clone();
    let journal = HandoverChainJournal {
        program,
        chain_id: a.chain_id,
        genesis_hash: a.genesis_hash,
        genesis_root: a.committee_root,
        epoch: 1,
        committee_root: Committee::from_members(1, c1.clone()).unwrap().root(),
    };
    let proves = move |p: &Digest, r: &[u8]| -> std::result::Result<Vec<u8>, String> {
        if r == b"receipt" && *p == program {
            Ok(journal.encode())
        } else {
            Err("not a receipt of the program".into())
        }
    };
    let walked = ChainSegment {
        journal: None,
        receipt: Vec::new(),
        members: proof.genesis_members.clone(),
        handovers: proof.handovers.clone(),
    };
    let chained = ChainSegment {
        journal: Some(journal),
        receipt: b"receipt".to_vec(),
        members: c1,
        handovers: Vec::new(),
    };
    for (segment, program) in [(&walked, None), (&chained, Some(program))] {
        let mut client = segment.light_client(&a, program, proves).unwrap();
        client
            .advance(&proof.certificate, proof.sessions.clone(), &any_time())
            .unwrap();
        assert_eq!(client.latest().unwrap().index, 9);
    }
    assert!(
        chained.light_client(&a, None, proves).is_err(),
        "a chain proof names its program"
    );
    let mut wrong = chained.clone();
    wrong.members[0].stake += 1;
    assert!(
        wrong.light_client(&a, Some(program), proves).is_err(),
        "members that are not the committee the chain reaches"
    );
    let elsewhere = TrustAnchor {
        committee_root: [9; 32],
        ..a
    };
    assert!(
        chained
            .light_client(&elsewhere, Some(program), proves)
            .is_err(),
        "another genesis"
    );
    assert!(
        walked.light_client(&elsewhere, None, proves).is_err(),
        "another genesis committee"
    );
}

/// A governance receipt certified from genesis: an executed proposal's
/// records, proven under a state root that an epoch-1 checkpoint commits,
/// with that checkpoint's proof from the genesis committee. It is the
/// shared fixture under `sdk/fixtures/governance_receipt/`, which the CLI
/// checks from the genesis anchor and the SDKs check under the certified
/// root. Session keys are fresh per run, so the stored fixture is not
/// regenerated byte for byte; this test checks that it still verifies,
/// and `TENZRO_WRITE_FIXTURES=1` rewrites it after a deliberate change.
#[test]
fn the_governance_receipt_fixture_is_certified_from_genesis() {
    use sha2::Digest as _;
    use std::sync::Arc;
    use tenzro_storage::state_trie::capture::Writes;
    use tenzro_storage::{MemoryStore, StateTrie};
    use tenzro_types::evidence_pack::{
        GovernanceReceipt, ProvenRecord, STATE_NAMESPACE, vm_storage_key,
    };

    const SYSTEM_ADDRESS: [u8; 20] = [0xFF; 20];
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../sdk/fixtures/governance_receipt/receipt_from_genesis.json");

    if std::env::var_os("TENZRO_WRITE_FIXTURES").is_some() {
        let id = "ab".repeat(32);
        let proposal = serde_json::to_vec(
            &serde_json::json!({ "id": id, "status": "executed", "track": "standard" }),
        )
        .unwrap();
        let mut decision = sha2::Sha256::digest(&proposal).to_vec();
        decision.extend_from_slice(&7u64.to_be_bytes());
        let slots = [
            ("proposal", format!("proposal:{id}"), Some(proposal)),
            (
                "tally",
                format!("proposal_tally:{id}"),
                Some(br#"{"yes":"3","no":"1","total_eligible":"4"}"#.to_vec()),
            ),
            ("veto_total", format!("veto_total:{id}"), None),
            (
                "decision",
                format!("governance_decision:{id}"),
                Some(decision),
            ),
        ];
        let trie = StateTrie::new(Arc::new(MemoryStore::new()));
        let mut writes = Writes::new();
        for (_, slot, value) in &slots {
            if value.is_some() {
                writes.insert(
                    (
                        STATE_NAMESPACE.to_string(),
                        vm_storage_key(&SYSTEM_ADDRESS, slot.as_bytes()),
                    ),
                    value.clone(),
                );
            }
        }
        let root: [u8; 32] = trie
            .commit(1, &writes)
            .unwrap()
            .as_bytes()
            .try_into()
            .unwrap();
        let records = slots
            .iter()
            .map(|(kind, slot, _)| {
                let (value, proof) = trie
                    .prove(
                        1,
                        STATE_NAMESPACE,
                        &vm_storage_key(&SYSTEM_ADDRESS, slot.as_bytes()),
                    )
                    .unwrap();
                ProvenRecord {
                    kind: (*kind).into(),
                    subject: id.clone(),
                    slot: slot.clone(),
                    value: value.map(hex::encode),
                    proof: serde_json::to_value(proof).unwrap(),
                }
            })
            .collect();

        let (c0, s) = committee(4);
        let c1 = Committee::from_members(1, c0.members().to_vec()).unwrap();
        let end = Checkpoint {
            next_committee_root: Some(c1.root()),
            ..checkpoint(5, 1)
        };
        let (handover, handover_sessions) = certify(&c0, &s, &[0, 1, 2], &end);
        let cp = Checkpoint {
            epoch: 1,
            state_root: root,
            ..checkpoint(9, 2)
        };
        let (certificate, sessions) = certify(&c1, &s, &[1, 2, 3], &cp);
        let anchor = TrustAnchor {
            epoch: 0,
            chain_id: 7,
            genesis_hash: [1; 32],
            committee_root: c0.root(),
        };
        let proof = CheckpointProof {
            genesis_members: c0.members().to_vec(),
            handovers: vec![EpochHandover {
                certificate: handover,
                sessions: handover_sessions,
                next_members: c1.members().to_vec(),
            }],
            certificate,
            sessions,
        };
        let receipt = GovernanceReceipt {
            proposal_id: id,
            state_height: cp.state_height,
            state_root: hex::encode(root),
            state_trie_hash: Default::default(),
            checkpoint: serde_json::to_value(&proof).unwrap(),
            records,
        };
        let fixture = serde_json::json!({
            "anchor": {
                "chain_id": anchor.chain_id,
                "genesis_hash": hex::encode(anchor.genesis_hash),
                "committee_root": hex::encode(anchor.committee_root),
            },
            "certified_checkpoint": cp.index,
            "certified_state_root": hex::encode(root),
            "executed_height": 7,
            "receipt": receipt,
        });
        std::fs::write(&path, serde_json::to_string(&fixture).unwrap() + "\n").unwrap();
    }

    let fixture: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).expect("the shared fixture")).unwrap();
    let b32 = |v: &serde_json::Value| -> [u8; 32] {
        hex::decode(v.as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap()
    };
    let anchor = TrustAnchor {
        epoch: 0,
        chain_id: fixture["anchor"]["chain_id"].as_u64().unwrap(),
        genesis_hash: b32(&fixture["anchor"]["genesis_hash"]),
        committee_root: b32(&fixture["anchor"]["committee_root"]),
    };
    let proof: CheckpointProof =
        serde_json::from_value(fixture["receipt"]["checkpoint"].clone()).unwrap();
    let cp = proof.verify(&anchor).unwrap();
    assert_eq!(cp.index, fixture["certified_checkpoint"].as_u64().unwrap());
    assert_eq!(cp.state_root, b32(&fixture["certified_state_root"]));
    assert_eq!(cp.state_root, b32(&fixture["receipt"]["state_root"]));
    assert_eq!(
        cp.state_height,
        fixture["receipt"]["state_height"].as_u64().unwrap()
    );
    assert!(
        proof
            .verify(&TrustAnchor {
                committee_root: [0; 32],
                ..anchor
            })
            .is_err()
    );
}

/// An evidence pack with node-signed tool-call records and its EU AI Act
/// profile, certified from genesis: the shared fixture under
/// `sdk/fixtures/eu_ai_act/`, which the CLI verifies from the genesis
/// anchor alone. `TENZRO_WRITE_FIXTURES=1` rewrites it.
#[test]
fn the_eu_ai_act_pack_fixture_is_certified_from_genesis() {
    use crate::eu_ai_act::{Profile, build_profile, verify_profile};
    use tenzro_types::evidence_pack::EvidencePack;

    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../sdk/fixtures/eu_ai_act/pack_from_genesis.json");
    let no_receipt = |_: &[u8; 32], _: &[u8]| -> std::result::Result<Vec<u8>, String> {
        Err("no handover program".into())
    };
    if std::env::var_os("TENZRO_WRITE_FIXTURES").is_some() {
        let (mut pack, root) = crate::eu_ai_act::fixture::pack();
        let (c0, s) = committee(4);
        let c1 = Committee::from_members(1, c0.members().to_vec()).unwrap();
        let end = Checkpoint {
            next_committee_root: Some(c1.root()),
            ..checkpoint(5, 1)
        };
        let (handover, handover_sessions) = certify(&c0, &s, &[0, 1, 2], &end);
        let cp = Checkpoint {
            epoch: 1,
            state_root: root,
            ..checkpoint(9, 2)
        };
        let (certificate, sessions) = certify(&c1, &s, &[1, 2, 3], &cp);
        let anchor = TrustAnchor {
            epoch: 0,
            chain_id: 7,
            genesis_hash: [1; 32],
            committee_root: c0.root(),
        };
        let proof = CheckpointProof {
            genesis_members: c0.members().to_vec(),
            handovers: vec![EpochHandover {
                certificate: handover,
                sessions: handover_sessions,
                next_members: c1.members().to_vec(),
            }],
            certificate,
            sessions,
        };
        pack.state_height = cp.state_height;
        pack.checkpoint = serde_json::to_value(&proof).unwrap();
        let profile = build_profile(&pack);
        let fixture = serde_json::json!({
            "anchor": {
                "chain_id": anchor.chain_id,
                "genesis_hash": hex::encode(anchor.genesis_hash),
                "committee_root": hex::encode(anchor.committee_root),
            },
            "pack": pack,
            "profile": profile,
        });
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(
            &path,
            serde_json::to_string_pretty(&fixture).unwrap() + "\n",
        )
        .unwrap();
    }

    let fixture: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&path).expect("the shared fixture")).unwrap();
    let b32 = |v: &serde_json::Value| -> [u8; 32] {
        hex::decode(v.as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap()
    };
    let anchor = TrustAnchor {
        epoch: 0,
        chain_id: fixture["anchor"]["chain_id"].as_u64().unwrap(),
        genesis_hash: b32(&fixture["anchor"]["genesis_hash"]),
        committee_root: b32(&fixture["anchor"]["committee_root"]),
    };
    let pack: EvidencePack = serde_json::from_value(fixture["pack"].clone()).unwrap();
    let profile: Profile = serde_json::from_value(fixture["profile"].clone()).unwrap();
    let report = verify_profile(&pack, &profile, &anchor, None, no_receipt).unwrap();
    assert_eq!(report.signed_tool_calls, 2);
    assert_eq!(report.pack.entries, 3);
    assert!(
        verify_profile(
            &pack,
            &profile,
            &TrustAnchor {
                committee_root: [0; 32],
                ..anchor
            },
            None,
            no_receipt
        )
        .is_err()
    );
}
/// A validator replaces its hardware key at an epoch boundary on the
/// running chain: the committee of epoch 1 carries its new key, which the
/// last checkpoint of epoch 0 commits. A client from genesis still
/// verifies the epoch 0 checkpoint signed with the old key, verifies the
/// epoch 1 checkpoint signed with the new one, and from epoch 1 refuses a
/// session certified by the retired key.
#[test]
fn a_validator_rekeys_at_an_epoch_boundary_and_earlier_checkpoints_still_verify() {
    use crate::validator_key::ValidatorSigner;
    let (c0, s) = committee(4);
    let replacement = SoftwareTestSigner::from_seed(4_242);
    let mut members = c0.members().to_vec();
    assert_ne!(&members[0].public_key, replacement.public_key());
    members[0].public_key = replacement.public_key().clone();
    let c1 = Committee::from_members(1, members).unwrap();
    let end = Checkpoint {
        next_committee_root: Some(c1.root()),
        ..checkpoint(5, 1)
    };
    let (handover, handover_sessions) = certify(&c0, &s, &[0, 1, 2], &end);
    let s1 = [&replacement, &s[1], &s[2], &s[3]];
    let cp = Checkpoint {
        epoch: 1,
        ..checkpoint(9, 2)
    };
    let (certificate, sessions) = certify(&c1, &s1, &[0, 1, 2], &cp);
    let anchor = TrustAnchor {
        epoch: 0,
        chain_id: 7,
        genesis_hash: [1; 32],
        committee_root: c0.root(),
    };

    // The epoch 0 checkpoint, signed by the old key, from genesis.
    let old = CheckpointProof {
        genesis_members: c0.members().to_vec(),
        handovers: vec![],
        certificate: handover.clone(),
        sessions: handover_sessions.clone(),
    };
    assert_eq!(old.verify(&anchor).unwrap().index, 5);

    // The epoch 1 checkpoint, signed with the new key, through the
    // handover.
    let new = CheckpointProof {
        genesis_members: c0.members().to_vec(),
        handovers: vec![EpochHandover {
            certificate: handover,
            sessions: handover_sessions,
            next_members: c1.members().to_vec(),
        }],
        certificate,
        sessions,
    };
    assert_eq!(new.verify(&anchor).unwrap().index, 9);

    // The retired key no longer certifies a session in epoch 1; the new
    // one does.
    let stale = sign_as(&s[0], &MemoryHighWater::default(), 0, &cp).unwrap();
    let mut book = SessionBook::new(cp.chain_id, cp.genesis_hash, 1);
    assert!(book.admit(&c1, stale.signature.session.clone()).is_err());
    let fresh = sign_as(&replacement, &MemoryHighWater::default(), 0, &cp).unwrap();
    assert!(book.admit(&c1, fresh.signature.session.clone()).is_ok());
}
/// The whole committee moves to ML-DSA-87 hardware keys at an epoch
/// boundary on the running chain. A client from genesis verifies the
/// epoch 0 checkpoint certified under the ML-DSA-65 keys and the epoch 1
/// checkpoint certified under the ML-DSA-87 keys; a signature of one
/// scheme never verifies under a key of the other.
#[test]
fn a_committee_migrates_to_a_second_signature_scheme_and_earlier_checkpoints_still_verify() {
    use crate::validator_key::{SignatureScheme, ValidatorSigner};
    let (c0, s) = committee(4);
    let next: Vec<SoftwareTestSigner> = (0..4)
        .map(|i| SoftwareTestSigner::from_seed_with_scheme(9_000 + i, SignatureScheme::MlDsa87P384))
        .collect();
    let mut members = c0.members().to_vec();
    for (m, k) in members.iter_mut().zip(&next) {
        assert_eq!(k.public_key().scheme(), SignatureScheme::MlDsa87P384);
        m.public_key = k.public_key().clone();
    }
    let c1 = Committee::from_members(1, members).unwrap();
    let end = Checkpoint {
        next_committee_root: Some(c1.root()),
        ..checkpoint(5, 1)
    };
    let (handover, handover_sessions) = certify(&c0, &s, &[0, 1, 2], &end);
    let cp = Checkpoint {
        epoch: 1,
        ..checkpoint(9, 2)
    };
    let (certificate, sessions) = certify(&c1, &next, &[0, 1, 3], &cp);
    let anchor = TrustAnchor {
        epoch: 0,
        chain_id: 7,
        genesis_hash: [1; 32],
        committee_root: c0.root(),
    };
    let old = CheckpointProof {
        genesis_members: c0.members().to_vec(),
        handovers: vec![],
        certificate: handover.clone(),
        sessions: handover_sessions.clone(),
    };
    assert_eq!(old.verify(&anchor).unwrap().index, 5);
    let new = CheckpointProof {
        genesis_members: c0.members().to_vec(),
        handovers: vec![EpochHandover {
            certificate: handover,
            sessions: handover_sessions,
            next_members: c1.members().to_vec(),
        }],
        certificate,
        sessions,
    };
    assert_eq!(new.verify(&anchor).unwrap().index, 9);

    // No cross-scheme verification, in either direction.
    let by_old = s[0].sign(b"tenzro/test", b"m").unwrap();
    let by_new = next[0].sign(b"tenzro/test", b"m").unwrap();
    assert!(next[0].public_key().verify(b"tenzro/test", b"m", &by_new));
    assert!(!next[0].public_key().verify(b"tenzro/test", b"m", &by_old));
    assert!(!s[0].public_key().verify(b"tenzro/test", b"m", &by_new));
}

/// Members that do not hash to the committed root are an invalid
/// certificate to consensus, as they were before the light client moved.
#[test]
fn a_committee_mismatch_is_an_invalid_certificate() {
    assert!(matches!(
        crate::error::ConsensusError::from(tenzro_light::LightError::CommitteeMismatch),
        crate::error::ConsensusError::InvalidCertificate(_)
    ));
}

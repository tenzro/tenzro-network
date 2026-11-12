//! Upgrade readiness and the security-fix track, end to end through the
//! executor.

use super::*;
use crate::VmType;
use crate::config::VmConfig;
use crate::governance::{
    DEFAULT_SECURITY_REVEAL_WINDOW_MS, DEFAULT_UPGRADE_ACTIVATION_DELAY_BLOCKS, PolicyTrack,
    Proposal, ProposalAction, ProposalStatus, SecurityBasis, upgrade_ready_digest,
};
use crate::state_adapter::StateAdapter;
use sha2::Digest;
use tenzro_tee::tpm_attest::tests::{SoftTpm, evidence};
use tenzro_tee::tpm_attest::{
    MachineAttestation, admission_challenge, attestation_key_sec1, machine_did_for_attestation_key,
};
use tenzro_types::token::PolicyUpdate;

const GAS: u128 = 10_000_000_000_000_000_000;
const GAS_PRICE: u128 = 1_000_000_000;
pub(super) const CODE: [u8; 32] = [0xc0; 32];
pub(super) const HEIGHT: u64 = 5_000;

pub(super) fn tx(from: &[u8], data: Vec<u8>, at_ms: i64) -> VmTransaction {
    let mut tx = VmTransaction::new(
        from.to_vec(),
        None,
        0,
        data,
        400_000,
        GAS_PRICE,
        0,
        VmType::Evm,
        1337,
    );
    tx.block_timestamp_ms = Some(at_ms);
    tx.block_height = Some(HEIGHT);
    tx
}

pub(super) struct Validator {
    pub(super) addr: Vec<u8>,
    pub(super) tpm: SoftTpm,
}

/// A bonded validator whose account is a machine identity admitted with
/// `tpm`'s attestation key.
fn validator(state: &mut StateAdapter, seed: u8, stake: u128) -> Validator {
    let addr = vec![seed; 32];
    let tpm = SoftTpm::new(seed);
    let (probe, _) = evidence(&tpm, &[0; 32]);
    let ak = attestation_key_sec1(&probe).unwrap();
    let did = machine_did_for_attestation_key(&ak);
    let controller = vec![seed; 33];
    let nonce = [seed; 32];
    let (ev, _) = evidence(&tpm, &admission_challenge(&did, &controller, &nonce));
    let att = MachineAttestation {
        evidence: ev,
        nonce: nonce.to_vec(),
        activated: true,
    };
    let mut metadata = std::collections::BTreeMap::new();
    metadata.insert(
        tenzro_tee::identity_evidence::TPM_ATTESTATION_KEY.to_string(),
        serde_json::to_string(&att).unwrap(),
    );
    let record = tenzro_types::identity::RegisterIdentityPayload {
        did: did.clone(),
        identity_type: "machine".into(),
        display_name: String::new(),
        controller_pubkey: controller,
        key_type: "p256".into(),
        wallet_id: String::new(),
        wallet_address: Address::new([seed; 32]),
        pq_verifying_key: Vec::new(),
        metadata,
        proof: tenzro_types::identity::RegistrationProof::Hardware {
            signature: tenzro_types::account_signature::CompositeSignature::classical(
                tenzro_types::account_signature::ClassicalProof::Raw {
                    signature: Vec::new(),
                },
            ),
        },
    };
    state.set_storage(
        &SYSTEM_ADDRESS,
        &identity_storage_key(&did),
        serde_json::to_vec(&record).unwrap(),
    );
    state.set_storage(
        &SYSTEM_ADDRESS,
        identity_wallet_index_key(&addr).as_bytes(),
        did.into_bytes(),
    );
    staking::add_bond(state, &addr, stake, -crate::governance::MIN_BOND_AGE_MS).unwrap();
    let vault = state.get_balance(&STAKING_VAULT_ADDRESS);
    state.set_balance(&STAKING_VAULT_ADDRESS, vault + stake);
    state.set_balance(&addr, GAS);
    Validator { addr, tpm }
}

pub(super) fn ready_data(v: &Validator, code: &[u8; 32], quoted_for: &[u8; 32]) -> Vec<u8> {
    let (ev, _) = evidence(&v.tpm, &upgrade_ready_digest(quoted_for, &v.addr));
    let mut data = SELECTOR_UPGRADE_READY.to_vec();
    data.extend_from_slice(code);
    data.extend_from_slice(&serde_json::to_vec(&ev).unwrap());
    data
}

pub(super) fn upgrade(track: PolicyTrack) -> ProposalAction {
    ProposalAction::PolicyUpdate {
        update: PolicyUpdate::ProtocolUpgrade {
            version: "2".into(),
            code_hash: CODE.to_vec(),
        },
        memo: "ship 2".into(),
        track,
    }
}

/// A protocol upgrade already through its vote and timelock.
pub(super) fn queued(state: &mut StateAdapter, id: [u8; 32], action: ProposalAction) {
    let mut p = Proposal::open(
        hex::encode(id),
        Address::new([0x77; 32]),
        action,
        0,
        crate::governance::GovernanceRules::GENESIS,
    );
    p.status = ProposalStatus::Queued;
    p.queued_ms = Some(0);
    p.eta_ms = Some(0);
    store_proposal(state, &p).unwrap();
}

pub(super) fn execute_data(id: &[u8; 32]) -> Vec<u8> {
    let mut data = SELECTOR_GOVERNANCE_EXECUTE.to_vec();
    data.extend_from_slice(id);
    data
}

/// Three validators: 66%, 1% and 33% of bonded stake.
pub(super) fn network() -> (NativeExecutor, StateAdapter, Vec<Validator>) {
    let mut state = StateAdapter::new();
    let vs = vec![
        validator(&mut state, 1, 66),
        validator(&mut state, 2, 1),
        validator(&mut state, 3, 33),
    ];
    (NativeExecutor::new(VmConfig::default()).unwrap(), state, vs)
}

#[tokio::test]
async fn sixty_six_percent_does_not_enact_and_sixty_seven_does() {
    let (ex, mut state, vs) = network();
    let id = [0xcd; 32];
    queued(&mut state, id, upgrade(PolicyTrack::Standard));

    ex.execute_transaction(
        &tx(&vs[0].addr, ready_data(&vs[0], &CODE, &CODE), 1),
        &mut state,
    )
    .await
    .expect("a validator's machine signals readiness");
    assert_eq!(readiness(&state, &CODE).ready_bps(), 6_600);
    let err = ex
        .execute_transaction(&tx(&vs[2].addr, execute_data(&id), 2), &mut state)
        .await
        .expect_err("66% must not enact");
    assert!(err.to_string().contains("6700 bps must"), "{err}");

    ex.execute_transaction(
        &tx(&vs[1].addr, ready_data(&vs[1], &CODE, &CODE), 3),
        &mut state,
    )
    .await
    .unwrap();
    assert!(readiness(&state, &CODE).met());
    let r = ex
        .execute_transaction(&tx(&vs[2].addr, execute_data(&id), 4), &mut state)
        .await
        .unwrap();
    assert!(
        r.logs
            .iter()
            .any(|l| l.topics[0] == UPGRADE_SCHEDULED_TOPIC)
    );
    let a = read_upgrade_activation(&state).unwrap();
    assert_eq!(
        a.activation_height,
        HEIGHT + DEFAULT_UPGRADE_ACTIVATION_DELAY_BLOCKS
    );
    assert_eq!(a.code_hash, hex::encode(CODE));

    // The decision record binds the executed proposal record and its height.
    let id_hex = hex::encode(id);
    let record = state
        .get_storage(&SYSTEM_ADDRESS, governance_proposal_key(&id_hex).as_bytes())
        .unwrap();
    let decision = state
        .get_storage(
            &SYSTEM_ADDRESS,
            governance_decision_slot(&id_hex).as_bytes(),
        )
        .unwrap();
    let (digest, height) = tenzro_types::evidence_pack::decode_decision(&decision).unwrap();
    assert_eq!(digest.as_slice(), sha2::Sha256::digest(&record).as_slice());
    assert_eq!(height, HEIGHT);
    let kinds: Vec<_> = governance_receipt_slots(&state, &id_hex)
        .into_iter()
        .map(|(k, _)| k)
        .collect();
    assert_eq!(
        kinds,
        [
            "proposal",
            "tally",
            "readiness",
            "activation",
            "veto_total",
            "decision"
        ]
    );
}

#[tokio::test]
async fn the_activation_height_is_the_same_on_every_replica() {
    let mut seen = Vec::new();
    for _ in 0..2 {
        let (ex, mut state, vs) = network();
        let id = [0xcd; 32];
        queued(&mut state, id, upgrade(PolicyTrack::Standard));
        for v in &vs {
            ex.execute_transaction(&tx(&v.addr, ready_data(v, &CODE, &CODE), 1), &mut state)
                .await
                .unwrap();
        }
        ex.execute_transaction(&tx(&vs[0].addr, execute_data(&id), 2), &mut state)
            .await
            .unwrap();
        seen.push(read_upgrade_activation(&state).unwrap());
    }
    assert_eq!(seen[0], seen[1]);
}

#[tokio::test]
async fn a_forged_quote_is_refused() {
    let (ex, mut state, vs) = network();
    // A quote over another binary.
    let err = ex
        .execute_transaction(
            &tx(&vs[0].addr, ready_data(&vs[0], &CODE, &[0xee; 32]), 1),
            &mut state,
        )
        .await
        .expect_err("the quote answers another digest");
    assert!(err.to_string().contains("quote refused"), "{err}");
    // A quote by a TPM other than the one the validator was admitted with.
    let other = Validator {
        addr: vs[0].addr.clone(),
        tpm: SoftTpm::new(9),
    };
    let err = ex
        .execute_transaction(
            &tx(&vs[0].addr, ready_data(&other, &CODE, &CODE), 1),
            &mut state,
        )
        .await
        .expect_err("another machine's quote");
    assert!(
        err.to_string().contains("admitted attestation key"),
        "{err}"
    );
    // A tampered signature.
    let (mut ev, _) = evidence(&vs[0].tpm, &upgrade_ready_digest(&CODE, &vs[0].addr));
    ev.quote_signature[10] ^= 1;
    let mut data = SELECTOR_UPGRADE_READY.to_vec();
    data.extend_from_slice(&CODE);
    data.extend_from_slice(&serde_json::to_vec(&ev).unwrap());
    assert!(
        ex.execute_transaction(&tx(&vs[0].addr, data, 1), &mut state)
            .await
            .is_err()
    );
    assert!(upgrade::ready_signals(&state, &CODE).is_empty());
}

#[tokio::test]
async fn a_security_fix_without_a_record_is_refused() {
    let (ex, mut state, vs) = network();
    let fix = upgrade(PolicyTrack::SecurityFix {
        basis: SecurityBasis::Fault {
            fault_id: "missing".into(),
        },
    });
    let mut data = SELECTOR_GOVERNANCE_PROPOSE.to_vec();
    data.extend_from_slice(&serde_json::to_vec(&fix).unwrap());
    let err = ex
        .execute_transaction(&tx(&vs[0].addr, data, 1), &mut state)
        .await
        .expect_err("no upheld fault");
    assert!(err.to_string().contains("upheld fault"), "{err}");

    let not_upgrade = ProposalAction::PolicyUpdate {
        update: PolicyUpdate::TpmEndorsementRootsSet {
            roots_pem: Vec::new(),
        },
        memo: "x".into(),
        track: PolicyTrack::SecurityFix {
            basis: SecurityBasis::Vulnerability {
                commitment: "ab".repeat(32),
            },
        },
    };
    assert!(
        not_upgrade.validate().is_err(),
        "only a protocol upgrade is a security fix"
    );
}

/// Propose a security fix on a commitment, carry it, ready every machine and
/// enact it at `at`. Returns the proposal id.
async fn enacted_fix(
    ex: &NativeExecutor,
    state: &mut StateAdapter,
    vs: &[Validator],
    commitment: &str,
    at: i64,
) -> [u8; 32] {
    let fix = upgrade(PolicyTrack::SecurityFix {
        basis: SecurityBasis::Vulnerability {
            commitment: commitment.into(),
        },
    });
    let mut data = SELECTOR_GOVERNANCE_PROPOSE.to_vec();
    data.extend_from_slice(&serde_json::to_vec(&fix).unwrap());
    let out = ex
        .execute_transaction(&tx(&vs[0].addr, data, 1), state)
        .await
        .expect("propose")
        .output;
    let id: [u8; 32] = out.as_slice().try_into().unwrap();
    let mut p = load_proposal(state, &hex::encode(id)).unwrap();
    assert_eq!(p.track, crate::governance::ProposalTrack::SecurityFix);
    p.status = ProposalStatus::Queued;
    p.queued_ms = Some(0);
    p.eta_ms = Some(0);
    store_proposal(state, &p).unwrap();
    for v in vs {
        ex.execute_transaction(&tx(&v.addr, ready_data(v, &CODE, &CODE), 2), state)
            .await
            .unwrap();
    }
    ex.execute_transaction(&tx(&vs[2].addr, execute_data(&id), at), state)
        .await
        .expect("enacts");
    id
}

fn disclosure_data(id: &[u8; 32], disclosure: &[u8]) -> Vec<u8> {
    let mut data = SELECTOR_SECURITY_DISCLOSURE.to_vec();
    data.extend_from_slice(id);
    data.extend_from_slice(disclosure);
    data
}

#[tokio::test]
async fn a_missing_reveal_slashes_the_proposer() {
    let (ex, mut state, vs) = network();
    let report = b"overflow in the fee path";
    let commitment = hex::encode(sha2::Sha256::digest(report));
    let id = enacted_fix(&ex, &mut state, &vs, &commitment, 10).await;
    let window = DEFAULT_SECURITY_REVEAL_WINDOW_MS as i64;

    let early = ex
        .execute_transaction(
            &tx(&vs[1].addr, disclosure_data(&id, &[]), 10 + window),
            &mut state,
        )
        .await;
    assert!(early.is_err(), "the reveal window is still open");

    let before = bonded_stake_of(&state, &vs[0].addr);
    ex.execute_transaction(
        &tx(&vs[1].addr, disclosure_data(&id, &[]), 11 + window),
        &mut state,
    )
    .await
    .expect("anyone settles a lapse");
    assert!(
        bonded_stake_of(&state, &vs[0].addr) < before,
        "the proposer is slashed"
    );
    assert_eq!(
        read_security_commitment(&state, &hex::encode(id))
            .unwrap()
            .settled
            .as_deref(),
        Some("slashed")
    );
    assert!(
        ex.execute_transaction(
            &tx(&vs[0].addr, disclosure_data(&id, report), 12 + window),
            &mut state
        )
        .await
        .is_err(),
        "settled once"
    );
}

#[tokio::test]
async fn a_reveal_settles_without_a_slash() {
    let (ex, mut state, vs) = network();
    let report = b"overflow in the fee path";
    let commitment = hex::encode(sha2::Sha256::digest(report));
    let id = enacted_fix(&ex, &mut state, &vs, &commitment, 10).await;
    assert!(
        ex.execute_transaction(
            &tx(&vs[0].addr, disclosure_data(&id, b"something else"), 20),
            &mut state
        )
        .await
        .is_err()
    );
    let before = bonded_stake_of(&state, &vs[0].addr);
    ex.execute_transaction(
        &tx(&vs[0].addr, disclosure_data(&id, report), 20),
        &mut state,
    )
    .await
    .unwrap();
    let window = DEFAULT_SECURITY_REVEAL_WINDOW_MS as i64;
    assert!(
        ex.execute_transaction(
            &tx(&vs[1].addr, disclosure_data(&id, &[]), window * 2),
            &mut state
        )
        .await
        .is_err()
    );
    assert_eq!(bonded_stake_of(&state, &vs[0].addr), before);
}

/// The governance receipt vectors contracts on other chains are tested
/// against: a protocol upgrade enacted by the executor, its proposal and
/// decision records committed to a state trie, and their state proofs. Run
/// with `TENZRO_WRITE_FIXTURES=1` to rewrite `sdk/fixtures/governance_receipt`.
#[tokio::test]
async fn the_governance_receipt_vectors_are_current() {
    use tenzro_storage::state_trie::capture::Writes;
    use tenzro_storage::{MemoryStore, StateTrie};
    use tenzro_types::evidence_pack::{STATE_NAMESPACE, vm_storage_key};
    use tenzro_types::remote_grant::system_slot_tree_key;

    let (ex, mut state, vs) = network();
    let id = [0xcd; 32];
    queued(&mut state, id, upgrade(PolicyTrack::Standard));
    for v in &vs {
        ex.execute_transaction(&tx(&v.addr, ready_data(v, &CODE, &CODE), 1), &mut state)
            .await
            .unwrap();
    }
    ex.execute_transaction(&tx(&vs[0].addr, execute_data(&id), 2), &mut state)
        .await
        .unwrap();

    let id_hex = hex::encode(id);
    let other = hex::encode([0xce; 32]);
    let trie = StateTrie::new(std::sync::Arc::new(MemoryStore::new()));
    let mut writes = Writes::new();
    for slot in [
        governance_proposal_key(&id_hex),
        governance_decision_slot(&id_hex),
    ] {
        writes.insert(
            (
                STATE_NAMESPACE.to_string(),
                vm_storage_key(&SYSTEM_ADDRESS, slot.as_bytes()),
            ),
            state.get_storage(&SYSTEM_ADDRESS, slot.as_bytes()),
        );
    }
    let root = trie.commit(1, &writes).unwrap();
    let prove = |slot: &str| {
        let (value, proof) = trie
            .prove(
                1,
                STATE_NAMESPACE,
                &vm_storage_key(&SYSTEM_ADDRESS, slot.as_bytes()),
            )
            .unwrap();
        (value, hex::encode(proof.encode()))
    };
    let (record, record_proof) = prove(&governance_proposal_key(&id_hex));
    let (decision, decision_proof) = prove(&governance_decision_slot(&id_hex));
    let (absent, absent_proof) = prove(&governance_decision_slot(&other));
    let (record, decision) = (record.unwrap(), decision.unwrap());
    assert!(absent.is_none());
    let (record_hash, height) = tenzro_types::evidence_pack::decode_decision(&decision).unwrap();
    let vectors = serde_json::json!({
        "state_root": root.to_string(),
        "proposal_id": id_hex,
        "proposal_record": hex::encode(&record),
        "proposal_record_hash": hex::encode(record_hash),
        "executed_height": height,
        "decision_tree_key": hex::encode(system_slot_tree_key(governance_decision_slot(&id_hex).as_bytes())),
        "decision": hex::encode(&decision),
        "decision_proof": decision_proof,
        "proposal_tree_key": hex::encode(system_slot_tree_key(governance_proposal_key(&id_hex).as_bytes())),
        "proposal_proof": record_proof,
        "absent_proposal_id": other,
        "absent_decision_tree_key": hex::encode(system_slot_tree_key(governance_decision_slot(&other).as_bytes())),
        "absent_decision_proof": absent_proof,
    });
    let full = format!(
        "{}/../../sdk/fixtures/governance_receipt/vectors.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let text = serde_json::to_string_pretty(&vectors).unwrap() + "\n";
    if std::env::var("TENZRO_WRITE_FIXTURES").is_ok() {
        std::fs::create_dir_all(std::path::Path::new(&full).parent().unwrap()).unwrap();
        std::fs::write(&full, text).unwrap();
        return;
    }
    assert_eq!(
        std::fs::read_to_string(&full).unwrap_or_default(),
        text,
        "rerun with TENZRO_WRITE_FIXTURES=1"
    );
}

/// A manufacturer root as governance records it: one PEM certificate.
fn root_pem(seed: u8, name: &str) -> String {
    use base64::Engine;
    use tenzro_tee::x509::testca;
    let k = testca::key(seed);
    let der = testca::issue(name, &k, name, &k, true, 1);
    format!(
        "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
        base64::engine::general_purpose::STANDARD.encode(der)
    )
}

fn machine_did(v: &Validator) -> String {
    let (probe, _) = evidence(&v.tpm, &[0; 32]);
    machine_did_for_attestation_key(&attestation_key_sec1(&probe).unwrap())
}

/// Re-records `v`'s admission with an endorsement certificate issued by the
/// root `seed` / `name`, as a machine from another manufacturer would carry.
fn endorse_under(state: &mut StateAdapter, v: &Validator, seed: u8, name: &str) {
    use p256::pkcs8::EncodePublicKey;
    use tenzro_tee::x509::testca;
    let did = machine_did(v);
    let key = identity_storage_key(&did);
    let mut record: tenzro_types::identity::RegisterIdentityPayload =
        serde_json::from_slice(&state.get_storage(&SYSTEM_ADDRESS, &key).unwrap()).unwrap();
    let slot = tenzro_tee::identity_evidence::TPM_ATTESTATION_KEY.to_string();
    let mut att: MachineAttestation = serde_json::from_str(&record.metadata[&slot]).unwrap();
    let spki = v.tpm.ek.public_key().to_public_key_der().unwrap();
    att.evidence.ek_certificate = testca::issue_with_spki(
        "EK",
        spki.as_bytes(),
        name,
        &testca::key(seed),
        false,
        2,
        (1_000_000_000, 4_000_000_000),
        &[],
    );
    record
        .metadata
        .insert(slot, serde_json::to_string(&att).unwrap());
    state.set_storage(&SYSTEM_ADDRESS, &key, serde_json::to_vec(&record).unwrap());
}

/// Enacts `roots` as the recognised endorsement roots through a queued
/// governance proposal, on the running executor.
async fn enact_roots(
    ex: &NativeExecutor,
    state: &mut StateAdapter,
    by: &Validator,
    id: [u8; 32],
    roots: Vec<String>,
    at: i64,
) {
    queued(
        state,
        id,
        ProposalAction::PolicyUpdate {
            update: PolicyUpdate::TpmEndorsementRootsSet { roots_pem: roots },
            memo: "manufacturer root rotation".into(),
            track: PolicyTrack::Standard,
        },
    );
    ex.execute_transaction(&tx(&by.addr, execute_data(&id), at), state)
        .await
        .expect("the root rotation enacts");
}

/// A TPM manufacturer root is added alongside the one in force and the old
/// one retired, each by a governance decision on the running chain. While
/// both are recognised, machines under either are endorsed; once the old
/// one is retired, only machines under the new one are. Admission records,
/// bonds and balances are untouched throughout.
#[tokio::test]
async fn a_tpm_root_is_added_then_the_old_one_retired_by_governance_without_a_restart() {
    const AT: i64 = 2_000_000_000_000;
    let (ex, mut state, vs) = network();
    let (old, new) = (root_pem(40, "TPM Root"), root_pem(41, "TPM Root 2"));
    endorse_under(&mut state, &vs[2], 41, "TPM Root 2");
    let mut changes = Vec::new();
    funding::set_endorsement_roots(&mut state, std::slice::from_ref(&old), &mut changes).unwrap();
    let (a, b) = (machine_did(&vs[0]), machine_did(&vs[2]));
    let records = |s: &StateAdapter| {
        [&a, &b].map(|d| s.get_storage(&SYSTEM_ADDRESS, &identity_storage_key(d)))
    };
    let held = |s: &StateAdapter| {
        vs.iter()
            .map(|v| (s.get_balance(&v.addr), staking::bonded_stake_of(s, &v.addr)))
            .collect::<Vec<_>>()
    };
    let (records_before, held_before) = (records(&state), held(&state));

    assert!(machine_endorsed(&state, &a, AT).is_ok());
    assert!(machine_endorsed(&state, &b, AT).is_err());

    enact_roots(
        &ex,
        &mut state,
        &vs[0],
        [0xa1; 32],
        vec![old.clone(), new.clone()],
        1,
    )
    .await;
    assert_eq!(
        read_endorsement_roots(&state),
        vec![old.clone(), new.clone()]
    );
    assert!(machine_endorsed(&state, &a, AT).is_ok());
    assert!(machine_endorsed(&state, &b, AT).is_ok());

    enact_roots(&ex, &mut state, &vs[0], [0xa2; 32], vec![new.clone()], 2).await;
    assert_eq!(read_endorsement_roots(&state), vec![new]);
    assert!(machine_endorsed(&state, &a, AT).is_err());
    assert!(machine_endorsed(&state, &b, AT).is_ok());

    assert_eq!(records(&state), records_before);
    let after = held(&state);
    for (i, ((bal, bond), (bal0, bond0))) in after.iter().zip(&held_before).enumerate() {
        assert_eq!(bond, bond0, "validator {i}'s bond");
        if i != 0 {
            assert_eq!(bal, bal0, "validator {i}'s balance");
        }
    }
}

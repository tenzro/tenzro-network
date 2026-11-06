//! Attaching a TPM attestation to a machine root registered without one.

use super::*;
use crate::state_adapter::StateAdapter;
use tenzro_crypto::composite::testing::TestHybridSigner;
use tenzro_crypto::composite::{HybridSigner as _, SignatureContext};
use tenzro_tee::tpm_attest::tests::{SoftTpm, evidence};
use tenzro_tee::tpm_attest::{
    MachineAttestation, admission_challenge, attestation_key_sec1, machine_did_for_attestation_key,
};
use tenzro_types::identity::{AttachMachineAttestationOp, attach_attestation_nonce};

/// A machine root registered without a TPM attestation.
struct Root {
    signer: TestHybridSigner,
    key: Vec<u8>,
    did: String,
    wallet: Vec<u8>,
}

/// Registers machine root `seed` (identity key and wallet from the seed) with
/// `metadata`.
fn root_with(
    state: &mut StateAdapter,
    seed: u8,
    metadata: std::collections::BTreeMap<String, String>,
) -> Root {
    let signer = TestHybridSigner::p256_only(seed);
    let key = [&[0x04u8][..], &signer.public_key().p256].concat();
    let did = tenzro_types::did_derivation::machine_did(&key);
    let wallet = Address::new([seed; 32]);
    let record = tenzro_types::identity::RegisterIdentityPayload {
        did: did.clone(),
        identity_type: "machine".into(),
        display_name: "machine root".into(),
        controller_pubkey: key.clone(),
        key_type: "P-256".into(),
        wallet_id: format!("0x{}", hex::encode(wallet.as_bytes())),
        wallet_address: wallet,
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
    Root {
        signer,
        key,
        did,
        wallet: wallet.as_bytes().to_vec(),
    }
}

fn root(state: &mut StateAdapter, seed: u8) -> Root {
    root_with(state, seed, Default::default())
}

/// `tpm`'s attestation for `root`, answering the attach challenge at the
/// wallet's current nonce.
fn attestation(state: &StateAdapter, root: &Root, tpm: &SoftTpm) -> MachineAttestation {
    let nonce = attach_attestation_nonce(&root.did, &root.wallet, state.get_nonce(&root.wallet));
    let (ev, _) = evidence(tpm, &admission_challenge(&root.did, &root.key, &nonce));
    MachineAttestation {
        evidence: ev,
        nonce: nonce.to_vec(),
        activated: true,
    }
}

/// The attach of `att` to `root`, signed by `signer`.
fn op(root: &Root, att: &MachineAttestation, signer: &TestHybridSigner) -> Vec<u8> {
    let attestation = serde_json::to_string(att).unwrap();
    let statement = tenzro_types::identity::attach_attestation_statement(&root.did, &attestation);
    let op = AttachMachineAttestationOp {
        did: root.did.clone(),
        attestation,
        signature: signer
            .sign(SignatureContext::IdentityRegistration, &statement)
            .unwrap(),
    };
    serde_json::to_vec(&op).unwrap()
}

fn attach_as(state: &mut StateAdapter, root: &Root, att: &MachineAttestation) -> Result<()> {
    machine_attestation::attach(state, &root.wallet, &op(root, att, &root.signer)).map(|_| ())
}

fn refused(r: Result<()>) -> String {
    match r {
        Err(VmError::InvalidTransaction(msg)) => msg,
        other => panic!("expected a refusal, got {other:?}"),
    }
}

#[test]
fn an_attestation_attaches_once() {
    let mut state = StateAdapter::new();
    let root = root(&mut state, 1);
    let tpm = SoftTpm::new(50);
    let att = attestation(&state, &root, &tpm);
    attach_as(&mut state, &root, &att).unwrap();

    let held = funding::machine_attestation(&state, &root.did).unwrap();
    assert_eq!(held, att);
    let record = funding::identity_record(&state, &root.did).unwrap();
    assert_eq!(
        record.metadata.get("machine_anchor").map(String::as_str),
        Some("tpm_attested")
    );
    let device = tenzro_types::hardware_level::device_id(&att.evidence.ek_public);
    assert_eq!(
        machine_attestation::admitted_tpm_holder(&state, &device),
        Some(root.did.clone())
    );
}

#[test]
fn a_second_attach_is_refused() {
    let mut state = StateAdapter::new();
    let root = root(&mut state, 2);
    let tpm = SoftTpm::new(51);
    let att = attestation(&state, &root, &tpm);
    attach_as(&mut state, &root, &att).unwrap();
    state.set_nonce(&root.wallet, 1);
    let again = attestation(&state, &root, &tpm);
    let msg = refused(attach_as(&mut state, &root, &again));
    assert!(msg.contains("already carries a TPM attestation"), "{msg}");
}

#[test]
fn a_root_registered_with_its_attestation_attaches_nothing() {
    let mut state = StateAdapter::new();
    let mut metadata = std::collections::BTreeMap::new();
    metadata.insert(
        tenzro_tee::identity_evidence::TPM_ATTESTATION_KEY.to_string(),
        "{}".to_string(),
    );
    let root = root_with(&mut state, 3, metadata);
    let att = attestation(&state, &root, &SoftTpm::new(52));
    let msg = refused(attach_as(&mut state, &root, &att));
    assert!(msg.contains("already carries a TPM attestation"), "{msg}");
}

#[test]
fn a_bad_quote_is_refused() {
    let mut state = StateAdapter::new();
    let root = root(&mut state, 4);
    let tpm = SoftTpm::new(53);
    let mut att = attestation(&state, &root, &tpm);
    let last = att.evidence.quote_signature.len() - 1;
    att.evidence.quote_signature[last] ^= 1;
    let msg = refused(attach_as(&mut state, &root, &att));
    assert!(msg.contains("the TPM quote does not verify"), "{msg}");
    assert!(funding::machine_attestation(&state, &root.did).is_err());
}

#[test]
fn a_quote_over_another_challenge_is_refused() {
    let mut state = StateAdapter::new();
    let root = root(&mut state, 5);
    let tpm = SoftTpm::new(54);
    // Answers the challenge of the wallet's next nonce, not its current one.
    state.set_nonce(&root.wallet, 1);
    let stale = attestation(&state, &root, &tpm);
    state.set_nonce(&root.wallet, 0);
    let msg = refused(attach_as(&mut state, &root, &stale));
    assert!(msg.contains("chain challenge"), "{msg}");
    // The challenge's nonce, but a quote over another root's challenge.
    let mut forged = attestation(&state, &root, &tpm);
    let (other, _) = evidence(
        &tpm,
        &admission_challenge("did:tenzro:machine:x", &root.key, &[0; 32]),
    );
    forged.evidence.quote = other.quote;
    forged.evidence.quote_signature = other.quote_signature;
    let msg = refused(attach_as(&mut state, &root, &forged));
    assert!(msg.contains("the TPM quote does not verify"), "{msg}");
}

#[test]
fn an_attach_without_credential_activation_is_refused() {
    let mut state = StateAdapter::new();
    let root = root(&mut state, 6);
    let mut att = attestation(&state, &root, &SoftTpm::new(55));
    att.activated = false;
    let msg = refused(attach_as(&mut state, &root, &att));
    assert!(msg.contains("credential activation"), "{msg}");
}

#[test]
fn a_tpm_admitted_under_another_root_is_refused() {
    let mut state = StateAdapter::new();
    let first = root(&mut state, 7);
    let second = root(&mut state, 8);
    let tpm = SoftTpm::new(56);
    let att = attestation(&state, &first, &tpm);
    attach_as(&mut state, &first, &att).unwrap();
    let again = attestation(&state, &second, &tpm);
    let msg = refused(attach_as(&mut state, &second, &again));
    assert!(
        msg.contains(&format!("already admitted under {}", first.did)),
        "{msg}"
    );
    assert!(funding::machine_attestation(&state, &second.did).is_err());
}

#[test]
fn a_tpm_admitted_as_an_autonomous_machine_is_refused() {
    let mut state = StateAdapter::new();
    let root = root(&mut state, 9);
    let tpm = SoftTpm::new(57);
    let (probe, _) = evidence(&tpm, &[0; 32]);
    let autonomous = machine_did_for_attestation_key(&attestation_key_sec1(&probe).unwrap());
    let record = tenzro_types::identity::RegisterIdentityPayload {
        did: autonomous.clone(),
        identity_type: "machine".into(),
        display_name: String::new(),
        controller_pubkey: vec![1; 65],
        key_type: "P-256".into(),
        wallet_id: String::new(),
        wallet_address: Address::new([99; 32]),
        pq_verifying_key: Vec::new(),
        metadata: Default::default(),
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
        &identity_storage_key(&autonomous),
        serde_json::to_vec(&record).unwrap(),
    );
    let att = attestation(&state, &root, &tpm);
    let msg = refused(attach_as(&mut state, &root, &att));
    assert!(
        msg.contains(&format!("already admitted under {autonomous}")),
        "{msg}"
    );
}

#[test]
fn an_attach_signed_by_another_key_is_refused() {
    let mut state = StateAdapter::new();
    let root = root(&mut state, 10);
    let att = attestation(&state, &root, &SoftTpm::new(58));
    let data = op(&root, &att, &TestHybridSigner::p256_only(11));
    let msg = refused(machine_attestation::attach(&mut state, &root.wallet, &data).map(|_| ()));
    assert!(msg.contains("not signed by"), "{msg}");
}

#[test]
fn an_attach_sent_by_another_account_is_refused() {
    let mut state = StateAdapter::new();
    let root = root(&mut state, 12);
    let att = attestation(&state, &root, &SoftTpm::new(59));
    let data = op(&root, &att, &root.signer);
    let msg = refused(machine_attestation::attach(&mut state, &[13; 32], &data).map(|_| ()));
    assert!(msg.contains("sent by its wallet"), "{msg}");
}

/// The transaction, end to end through the executor and its selector.
#[tokio::test]
async fn the_attach_transaction_executes_under_its_selector() {
    let executor = NativeExecutor::new(VmConfig::default()).unwrap();
    let mut state = StateAdapter::new();
    let root = root(&mut state, 14);
    state.set_balance(&root.wallet, 10_000_000_000_000_000_000);
    let att = attestation(&state, &root, &SoftTpm::new(60));
    let mut data = SELECTOR_ATTACH_MACHINE_ATTESTATION.to_vec();
    data.extend_from_slice(&op(&root, &att, &root.signer));
    let tx = VmTransaction::new(
        root.wallet.clone(),
        None,
        0,
        data,
        1_000_000,
        1_000_000_000,
        0,
        VmType::Tenzro,
        1337,
    );
    let result = executor.execute_transaction(&tx, &mut state).await.unwrap();
    assert!(result.success, "{result:?}");
    assert!(
        result
            .logs
            .iter()
            .any(|l| l.topics.first().map(Vec::as_slice)
                == Some(machine_attestation::MACHINE_ATTESTATION_ATTACHED_TOPIC)),
        "the attach emits its log"
    );
    assert_eq!(
        funding::machine_attestation(&state, &root.did).unwrap(),
        att
    );
    assert_eq!(state.get_nonce(&root.wallet), 1);
}

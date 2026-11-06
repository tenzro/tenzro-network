//! The handover chain proven link by link, and a light client that verifies
//! a later checkpoint from the newest receipt alone.
//!
//! A one-member committee certifies the end of epochs 0 and 1 and then a
//! checkpoint of epoch 2. Epoch 0's handover is proven under the genesis
//! committee; epoch 1's is proven with the first receipt as its assumption,
//! which the zkVM verifies, so the second receipt stands for both. Proving
//! runs on an NVIDIA GPU, so the test is ignored by default:
//!
//! ```text
//! cargo test --release --features cuda --test handover_chain -- --ignored --nocapture
//! ```
//!
//! With `HANDOVER_CHAIN_FIXTURE` set, the chained proof of the epoch-2
//! checkpoint is written there (bincode: the proof, the genesis committee's
//! root and the program), for the node's own check of a real receipt.

use ml_dsa::{ExpandedSigningKey, MlDsa65};
use p256::ecdsa::signature::hazmat::PrehashSigner;
use sha2::Digest as _;
use tenzro_finality::chain::{ChainAnchor, ChainedCheckpointProof, HandoverChainJournal, HandoverLink};
use tenzro_finality::checkpoint::{CHECKPOINT_VOTE_DOMAIN, Certificate, Checkpoint, checkpoint_state_height};
use tenzro_finality::committee::{Committee, Member};
use tenzro_finality::key::{CompositeSignature, ValidatorPublicKey, message_representative, ml_dsa_context};
use tenzro_finality::session::{SESSION_CERTIFICATE_DOMAIN, SessionCertificate, certificate_message};
use tenzro_finality::step::FinalityStep;
use tenzro_finality_prover::{HANDOVER_GUEST_ID, handover_program, prove_handover, read_receipt, write_receipt};
use tenzro_types::primitives::Address as TenzroAddress;

const CHAIN_ID: u64 = 1337;
const GENESIS: [u8; 32] = [0x6e; 32];

/// A composite ML-DSA-65 + P-256 key held in memory, for the test only.
struct Key {
    ml: ExpandedSigningKey<MlDsa65>,
    ec: p256::ecdsa::SigningKey,
    public: ValidatorPublicKey,
}

impl Key {
    fn new(seed: u8) -> Self {
        let ml = ExpandedSigningKey::<MlDsa65>::from_seed(&[seed; 32].into());
        let ec = p256::ecdsa::SigningKey::from_slice(&[seed.wrapping_add(1); 32]).unwrap();
        let public = ValidatorPublicKey::new(
            ml.verifying_key().encode().to_vec(),
            ec.verifying_key().to_sec1_point(false).as_bytes().to_vec(),
        )
        .unwrap();
        Self { ml, ec, public }
    }

    fn sign(&self, domain: &[u8], message: &[u8]) -> CompositeSignature {
        let rep = message_representative(domain, message).unwrap();
        let ml = self.ml.sign_deterministic(&rep, ml_dsa_context()).unwrap().encode().to_vec();
        let digest: [u8; 32] = sha2::Sha256::digest(&rep).into();
        let ec: p256::ecdsa::Signature = self.ec.sign_prehash(&digest).unwrap();
        CompositeSignature { ml_dsa: ml, p256: ec.to_bytes().to_vec() }
    }
}

struct Chain {
    hardware: Key,
    session: Key,
    members: Vec<Member>,
}

impl Chain {
    fn new() -> Self {
        let hardware = Key::new(1);
        let members = vec![Member {
            address: TenzroAddress([0x11; 32]),
            public_key: hardware.public.clone(),
            stake: 1,
            seats: 1,
        }];
        Self { hardware, session: Key::new(9), members }
    }

    fn root(&self, epoch: u64) -> [u8; 32] {
        Committee::from_members(epoch, self.members.clone()).unwrap().root()
    }

    /// The certified checkpoint `index` of `epoch`; it ends the epoch when
    /// `ends` is set, committing the next epoch's committee.
    fn certify(&self, epoch: u64, index: u64, ends: bool) -> FinalityStep {
        let mut session = SessionCertificate {
            chain_id: CHAIN_ID,
            genesis_hash: GENESIS,
            epoch,
            validator: self.hardware.public.fingerprint(),
            session_key: self.session.public.clone(),
            signature: CompositeSignature { ml_dsa: Vec::new(), p256: Vec::new() },
        };
        session.signature = self.hardware.sign(SESSION_CERTIFICATE_DOMAIN, &certificate_message(&session));
        let first = index * 40 + 1;
        let checkpoint = Checkpoint {
            chain_id: CHAIN_ID,
            genesis_hash: GENESIS,
            epoch,
            index,
            prev: [index as u8; 32],
            first_height: first,
            last_height: first + 39,
            blocks_root: [0xb1; 32],
            state_height: checkpoint_state_height(first, first + 39),
            state_root: [0x5e; 32],
            statement_root: [0x57; 32],
            next_committee_root: ends.then(|| self.root(epoch + 1)),
            anchor_round: index * 3,
            timestamp_ms: 1_790_000_000_000 + index,
            ordering_root: [0; 32],
        };
        let signature = self.session.sign(CHECKPOINT_VOTE_DOMAIN, &checkpoint.digest());
        let certificate = Certificate {
            checkpoint,
            signers: vec![0],
            sessions: vec![session.digest()],
            signatures: vec![signature],
        };
        FinalityStep {
            chain_id: CHAIN_ID,
            genesis_hash: GENESIS,
            members: self.members.clone(),
            sessions: vec![session],
            certificate,
        }
    }
}

fn verify_receipt(program: &[u8; 32], bytes: &[u8]) -> Result<Vec<u8>, String> {
    let receipt = read_receipt(bytes).map_err(|e| e.to_string())?;
    receipt
        .verify(risc0_zkvm::sha::Digest::from(*program))
        .map_err(|e| e.to_string())?;
    Ok(receipt.journal.bytes)
}

#[test]
#[ignore]
fn a_light_client_verifies_a_checkpoint_from_the_newest_chain_receipt_alone() {
    let chain = Chain::new();
    let program = handover_program();
    let genesis_root = chain.root(0);

    let start = std::time::Instant::now();
    let link0 = HandoverLink { program, genesis_root, prev: None, step: chain.certify(0, 4, true) };
    let r0 = prove_handover(&link0, None).expect("epoch 0's handover proves");
    eprintln!("LINK 0 PROVED in {:.1} s", start.elapsed().as_secs_f64());
    let j0 = HandoverChainJournal::decode(&r0.journal.bytes).expect("a chain journal");
    assert_eq!((j0.epoch, j0.committee_root), (1, chain.root(1)));

    let start = std::time::Instant::now();
    let link1 = HandoverLink { program, genesis_root, prev: Some(j0), step: chain.certify(1, 9, true) };
    let r1 = prove_handover(&link1, Some(&r0)).expect("epoch 1's handover proves on the first receipt");
    eprintln!("LINK 1 PROVED in {:.1} s", start.elapsed().as_secs_f64());
    r1.verify(HANDOVER_GUEST_ID).expect("the second receipt verifies alone");
    let receipt = write_receipt(&r1).unwrap();
    eprintln!("RECEIPT {} bytes", receipt.len());

    let anchor = ChainAnchor { chain_id: CHAIN_ID, genesis_hash: GENESIS, genesis_root, program };
    let latest = chain.certify(2, 12, false);
    let proof = ChainedCheckpointProof {
        chain: receipt.clone(),
        members: chain.members.clone(),
        handovers: Vec::new(),
        certificate: latest.certificate.clone(),
        sessions: latest.sessions.clone(),
    };
    assert_eq!(proof.verify(&anchor, verify_receipt).expect("the checkpoint is certified").index, 12);

    // The first receipt alone reaches only epoch 1: the epoch-2 checkpoint
    // is not certified by it.
    let short = ChainedCheckpointProof { chain: write_receipt(&r0).unwrap(), ..proof.clone() };
    assert!(short.verify(&anchor, verify_receipt).is_err(), "a receipt that stops short");
    // Under another program id the receipt does not verify.
    let other = ChainAnchor { program: [0x77; 32], ..anchor };
    assert!(proof.verify(&other, verify_receipt).is_err(), "another program");
    // Against another genesis committee the chain is not the client's.
    let elsewhere = ChainAnchor { genesis_root: [0x01; 32], ..anchor };
    assert!(proof.verify(&elsewhere, verify_receipt).is_err(), "another genesis");
    // The second link cannot be proven on a receipt of another chain.
    let forged = HandoverLink { prev: Some(HandoverChainJournal { epoch: 1, committee_root: [0xee; 32], ..j0 }), ..link1 };
    assert!(prove_handover(&forged, Some(&r0)).is_err(), "a link on a receipt it does not name");

    if let Some(path) = std::env::var_os("HANDOVER_CHAIN_FIXTURE") {
        std::fs::write(path, bincode::serialize(&(proof, genesis_root, program)).unwrap()).unwrap();
    }
}

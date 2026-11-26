//! The largest message each gossip topic can legally carry, measured against
//! the gossip frame.
//!
//! A node publishes and accepts at most
//! [`tenzro_iroh::gossip::MAX_GOSSIP_MESSAGE`] bytes of content on every
//! topic. A message the protocol accepts as valid but that does not fit is
//! never delivered: it is valid and stuck. Each case below builds the largest
//! message its topic's own rules allow, encodes it through the gossip
//! envelope, prints its size against the frame and fails if it exceeds it.
//!
//! Covered here are the topics whose content has a bound of its own short of
//! the frame: transactions, bounded per variant by transaction validation,
//! and checkpoint certificates, bounded by the committee. Every other topic's
//! content is bounded only by the frame itself, which
//! `NetworkMessage::from_bytes` enforces, so its largest legal message fits by
//! construction.

use tenzro_consensus::checkpoint::PublishedCertificate;
use tenzro_finality::checkpoint::{Certificate, Checkpoint};
use tenzro_finality::key::{
    CompositeSignature, ML_DSA_65_PUBLIC_KEY_LEN, ML_DSA_65_SIGNATURE_LEN, P256_PUBLIC_KEY_LEN,
    P256_SIGNATURE_LEN, ValidatorPublicKey,
};
use tenzro_finality::session::SessionCertificate;
use tenzro_iroh::gossip::MAX_GOSSIP_MESSAGE;
use tenzro_network::message::{MessagePayload, NetworkMessage};
use tenzro_types::transaction::{
    MAX_CHECKPOINT_RECORD_BYTES, MAX_TX_DATA_SIZE, SignedTransaction, Transaction, TransactionType,
};

/// Encoded size of `payload` as gossip carries it.
fn gossip_size(payload: MessagePayload) -> usize {
    NetworkMessage::new(payload)
        .to_bytes()
        .expect("the message encodes")
        .len()
}

/// `tx_type` in a transaction signed with a full-size composite signature.
fn signed(tx_type: TransactionType) -> SignedTransaction {
    use tenzro_types::account_signature::{ClassicalProof, CompositeSignature};
    use tenzro_types::primitives::{Address, ChainId, Nonce};
    let tx = Transaction::new(
        ChainId::from(1337u64),
        Address::new([0u8; 32]),
        Address::new([0u8; 32]),
        Nonce::from(0u64),
        tx_type,
        0,
        0,
    );
    SignedTransaction::new(
        tx,
        vec![0u8; 64],
        CompositeSignature {
            classical: ClassicalProof::Raw {
                signature: vec![0u8; 64],
            },
            pq: Some(vec![0u8; ML_DSA_65_SIGNATURE_LEN]),
        },
    )
}

/// A composite signature at its fixed size.
fn composite_signature() -> CompositeSignature {
    CompositeSignature {
        ml_dsa: vec![0u8; ML_DSA_65_SIGNATURE_LEN],
        p256: vec![0u8; P256_SIGNATURE_LEN],
    }
}

/// The certificate a publisher sends on a full-bundle checkpoint, signed by
/// `signers` validators: each signature with the signer's session
/// certificate.
fn full_bundle_certificate(signers: usize) -> MessagePayload {
    let checkpoint = Checkpoint {
        chain_id: 0,
        genesis_hash: [0; 32],
        epoch: 0,
        index: 0,
        prev: [0; 32],
        first_height: 0,
        last_height: 0,
        blocks_root: [0; 32],
        state_height: 0,
        state_root: [0; 32],
        statement_root: [0; 32],
        next_committee_root: Some([0; 32]),
        anchor_round: 0,
        timestamp_ms: 0,
        ordering_root: [0; 32],
    };
    let published = PublishedCertificate {
        certificate: Certificate {
            checkpoint,
            signers: (0..signers as u16).collect(),
            sessions: vec![[0; 32]; signers],
            signatures: vec![composite_signature(); signers],
        },
        sessions: vec![
            SessionCertificate {
                chain_id: 0,
                genesis_hash: [0; 32],
                epoch: 0,
                validator: [0; 32],
                session_key: ValidatorPublicKey {
                    ml_dsa: vec![0u8; ML_DSA_65_PUBLIC_KEY_LEN],
                    p256: vec![0u8; P256_PUBLIC_KEY_LEN],
                },
                signature: composite_signature(),
            };
            signers
        ],
    };
    MessagePayload::Certificate(bincode::serialize(&published).expect("the certificate encodes"))
}

/// Each case's largest legal message against the frame; every case is
/// printed, and the ones over the frame are listed in the failure.
#[test]
fn the_largest_legal_message_of_each_topic_fits_the_gossip_frame() {
    let data = vec![0u8; MAX_TX_DATA_SIZE];
    // The most members a committee may hold: the upper bound of the governed
    // `consensus.max_committee_members`. A quorum is `n - f` seats,
    // `f = (n - 1) / 3`; with one seat each, that many signers. A member that
    // holds several seats signs once, so one seat each is the worst case.
    const MAX_COMMITTEE_MEMBERS: usize = 110;
    let quorum_of = |seats: usize| seats - (seats - 1) / 3;
    // An AttestZkProof at its 4 MiB cap is not here: it is never gossiped. The
    // node refuses a signed transaction whose gossip message exceeds the frame
    // at submission (`too_large_to_carry`), and proofs reach validators by the
    // out-of-gossip proof path.
    let cases: Vec<(&str, MessagePayload)> = vec![
        (
            "tenzro/transactions: ContractDeploy, code and args at the data limit",
            MessagePayload::Transaction(signed(TransactionType::ContractDeploy {
                code: data.clone(),
                args: data.clone(),
            })),
        ),
        (
            "tenzro/transactions: TeeProviderRegister, attestation and info at the data limit",
            MessagePayload::Transaction(signed(TransactionType::TeeProviderRegister {
                attestation: data.clone(),
                info: data,
            })),
        ),
        (
            "tenzro/transactions: RecordCheckpointSigners, a certificate at its cap",
            MessagePayload::Transaction(signed(TransactionType::RecordCheckpointSigners {
                certificate: vec![0u8; MAX_CHECKPOINT_RECORD_BYTES],
            })),
        ),
        (
            "tenzro/certificates: full bundle, a quorum of the largest committee",
            full_bundle_certificate(quorum_of(MAX_COMMITTEE_MEMBERS)),
        ),
    ];

    // The most signers a full-bundle certificate can carry within the frame.
    let per_signer =
        gossip_size(full_bundle_certificate(2)) - gossip_size(full_bundle_certificate(1));
    let fixed = gossip_size(full_bundle_certificate(1)) - per_signer;
    eprintln!(
        "tenzro/certificates: {per_signer} bytes per signer; at most {} signers fit",
        (MAX_GOSSIP_MESSAGE - fixed) / per_signer
    );

    let mut over = Vec::new();
    for (what, payload) in cases {
        let size = gossip_size(payload);
        eprintln!("{what}: {size} of {MAX_GOSSIP_MESSAGE} bytes");
        if size > MAX_GOSSIP_MESSAGE {
            over.push(format!("{what}: {size} bytes"));
        }
    }
    assert!(
        over.is_empty(),
        "legal messages larger than the {MAX_GOSSIP_MESSAGE}-byte gossip frame:\n{}",
        over.join("\n")
    );
}

//! Whether a DID provably belongs to the key registered with it.
//!
//! The consensus rule for identity registration and every node mirroring a
//! replicated identity ask the same question, so it is answered once, here:
//!
//! - a key-rooted DID (human passkey, machine device key, delegated machine,
//!   institution) must be the DID its controller key derives
//!   ([`tenzro_types::did_derivation`]);
//! - a TPM-attested machine's DID is derived from its attestation key, and
//!   the record carries a quote by that key answering the admission challenge
//!   over the DID and exactly the registered key. Nobody can claim the DID
//!   without the attestation key, and the quote shows the key vouched for the
//!   registered controller key.
//!
//! A passkey public key is not a secret, so derivation alone would let anyone
//! register a victim's DID bound to the victim's own key. That is harmless to
//! the victim (the record names only their key), and it is why the controller
//! key itself must be the key the DID derives from rather than any key the
//! submitter chooses.

use std::collections::BTreeMap;

use crate::tpm_attest::{self, MachineAttestation};

/// Metadata key the TPM admission evidence travels under.
pub const TPM_ATTESTATION_KEY: &str = "tpm_attestation";

/// Metadata key of the endorsement grade recorded at admission (a
/// reputation signal; see [`crate::tpm_attest::EndorsementGrade`]).
pub const TPM_ENDORSEMENT_KEY: &str = "tpm_endorsement";

/// The endorsement grade of `att` against the TPM manufacturer roots the
/// network recognises (PEM), now, as its metadata label.
pub fn endorsement_label(att: &MachineAttestation, roots_pem: &[String]) -> &'static str {
    let now = chrono::Utc::now().timestamp().max(0) as u64;
    match tpm_attest::parse_roots(roots_pem) {
        Ok(roots) => tpm_attest::endorsement_grade(att, &roots, now).as_str(),
        Err(_) => "uncertified",
    }
}

/// Whether the registration is signed by the key it binds, and the DID belongs
/// to that key.
///
/// Three separate questions, all of which must hold:
///
/// 1. the DID derives from `controller_pubkey`, or a TPM quote roots it there
///    ([`registration_binding_holds`]);
/// 2. the submitter holds `controller_pubkey`, shown by a signature over
///    [`registration_statement`];
/// 3. the controller's hardware holds an ML-DSA-65 key, enrolled in state or
///    named by the registration, and the proof's ML-DSA-65 leg verifies
///    against it. An identity whose hardware holds none is not registered.
///
/// Without (2) a public key is enough to register: a passkey's public half is
/// published to every relying party, so an attacker reads one and claims that
/// person's DID first, choosing its wallet address and its post-quantum key.
/// The record would name the victim's key and pay to the attacker's wallet.
pub fn registration_is_authorized(
    payload: &tenzro_types::identity::RegisterIdentityPayload,
    enrolled_pq: Option<&[u8]>,
) -> bool {
    if !registration_binding_holds(&payload.did, &payload.controller_pubkey, &payload.metadata) {
        return false;
    }
    if !identity_type_matches_did(&payload.identity_type, &payload.did) {
        return false;
    }
    let statement = tenzro_types::identity::registration_statement(payload);
    possession_holds(payload, &statement, enrolled_pq)
}

/// The ML-DSA-65 key a registration enrols for its controller, for a
/// registration [`registration_is_authorized`] accepted: the key the
/// registration names, when the controller has none enrolled in state and the
/// proof carries the ML-DSA-65 leg, which was then verified against that key.
/// A key already enrolled moves only by a signed rotation, so `None` then.
pub fn registration_enrolled_pq_key<'a>(
    payload: &'a tenzro_types::identity::RegisterIdentityPayload,
    enrolled_pq: Option<&[u8]>,
) -> Option<&'a [u8]> {
    use tenzro_types::identity::RegistrationProof as P;
    if enrolled_pq.is_some() || payload.pq_verifying_key.is_empty() {
        return None;
    }
    let (P::Hardware { signature } | P::TpmQuote { signature }) = &payload.proof;
    signature
        .pq
        .is_some()
        .then_some(payload.pq_verifying_key.as_slice())
}

/// Whether `identity_type` is the class the DID's own prefix names. A machine
/// record under a human DID would resolve under rules meant for the other
/// class.
fn identity_type_matches_did(identity_type: &str, did: &str) -> bool {
    let Some(rest) = did.strip_prefix("did:tenzro:") else {
        return false;
    };
    match identity_type {
        "human" => rest.starts_with("human:"),
        "machine" => rest.starts_with("machine:"),
        "institution" => rest.starts_with("institution:"),
        _ => false,
    }
}
/// Whether the proof shows possession of the controller key. The ML-DSA-65
/// leg is checked against `enrolled_pq`, the key the controller has enrolled
/// in state. With none enrolled, a leg the proof carries is checked against
/// the key the registration names, which the statement commits to.
fn possession_holds(
    payload: &tenzro_types::identity::RegisterIdentityPayload,
    statement: &[u8; 32],
    enrolled_pq: Option<&[u8]>,
) -> bool {
    use tenzro_types::identity::RegistrationProof as P;
    match &payload.proof {
        P::Hardware { signature } => signature_holds(payload, statement, signature, enrolled_pq),
        // The quote answers a challenge over the DID and the controller key
        // only, so it says nothing about the wallet, the post-quantum key or
        // the metadata. The controller key's signature over the statement
        // covers those; the quote shows the DID is this TPM's.
        P::TpmQuote { signature } => {
            signature_holds(payload, statement, signature, enrolled_pq)
                && payload
                    .metadata
                    .get(TPM_ATTESTATION_KEY)
                    .and_then(|json| serde_json::from_str::<MachineAttestation>(json).ok())
                    .is_some_and(|att| {
                        tpm_evidence_binds(&payload.did, &payload.controller_pubkey, &att)
                    })
        }
    }
}

/// Whether `signature` is the controller key's composite signature over
/// `statement`, with the ML-DSA-65 leg checked against `enrolled_pq`, or
/// with none enrolled against the key the registration names.
fn signature_holds(
    payload: &tenzro_types::identity::RegisterIdentityPayload,
    statement: &[u8; 32],
    signature: &tenzro_types::account_signature::CompositeSignature,
    enrolled_pq: Option<&[u8]>,
) -> bool {
    // A key enrolled in state always decides. Without one, a carried leg
    // proves the submitter also holds the ML-DSA-65 key being registered.
    let pq = match enrolled_pq {
        Some(enrolled) => Some(enrolled),
        None if signature.pq.is_some() && !payload.pq_verifying_key.is_empty() => {
            Some(payload.pq_verifying_key.as_slice())
        }
        None => None,
    };
    // A registration is refused unless its hardware holds an ML-DSA-65 key
    // and the proof's ML-DSA-65 leg verifies against it.
    let Some(pq) = pq else {
        return false;
    };
    composite_signature_holds(
        &payload.controller_pubkey,
        statement,
        signature,
        Some(pq),
        tenzro_crypto::composite::PqPolicy::Required,
    )
}

/// Whether `signature` is the composite signature of the identity whose
/// controller key is `controller_key` over `statement` (a statement the
/// identity makes about itself, under its own domain), with the ML-DSA-65
/// leg checked against `enrolled_pq`.
pub fn controller_signature_holds(
    controller_key: &[u8],
    statement: &[u8; 32],
    signature: &tenzro_types::account_signature::CompositeSignature,
    enrolled_pq: Option<&[u8]>,
) -> bool {
    composite_signature_holds(
        controller_key,
        statement,
        signature,
        enrolled_pq,
        tenzro_crypto::composite::PqPolicy::WhenPresent,
    )
}

fn composite_signature_holds(
    controller_key: &[u8],
    statement: &[u8; 32],
    signature: &tenzro_types::account_signature::CompositeSignature,
    enrolled_pq: Option<&[u8]>,
    policy: tenzro_crypto::composite::PqPolicy,
) -> bool {
    use tenzro_crypto::composite::{CompositePublicKey, SignatureContext, verify_composite};
    let Some(p256_xy) = p256_xy(controller_key) else {
        return false;
    };
    let Ok(key) = CompositePublicKey::new(p256_xy, enrolled_pq.map(<[u8]>::to_vec)) else {
        return false;
    };
    verify_composite(
        &key,
        SignatureContext::IdentityRegistration,
        statement,
        signature,
        policy,
    )
    .is_ok()
}

/// The uncompressed P-256 point `x || y` of a controller key given as `x || y`
/// or SEC1 uncompressed (`0x04 || x || y`).
fn p256_xy(key: &[u8]) -> Option<Vec<u8>> {
    match key.len() {
        64 => Some(key.to_vec()),
        65 if key[0] == 0x04 => Some(key[1..].to_vec()),
        _ => None,
    }
}

/// Whether `did` provably belongs to `controller_key`.
pub fn registration_binding_holds(
    did: &str,
    controller_key: &[u8],
    metadata: &BTreeMap<String, String>,
) -> bool {
    if tenzro_types::did_derivation::did_derives_from_key(did, controller_key) {
        return true;
    }
    metadata
        .get(TPM_ATTESTATION_KEY)
        .and_then(|json| serde_json::from_str::<MachineAttestation>(json).ok())
        .is_some_and(|att| tpm_evidence_binds(did, controller_key, &att))
}

/// Whether `att` is a quote by the attestation key `did` derives from,
/// vouching for `controller_key`.
pub fn tpm_evidence_binds(did: &str, controller_key: &[u8], att: &MachineAttestation) -> bool {
    let Ok(ak) = tpm_attest::attestation_key_sec1(&att.evidence) else {
        return false;
    };
    // The attested identity is the autonomous machine the attestation key
    // derives, or a machine root whose DID derives from the controller key
    // the quote's challenge names.
    if tpm_attest::machine_did_for_attestation_key(&ak) != did
        && !tenzro_types::did_derivation::did_derives_from_key(did, controller_key)
    {
        return false;
    }
    let Ok(nonce) = <[u8; 32]>::try_from(att.nonce.as_slice()) else {
        return false;
    };
    let challenge = tpm_attest::admission_challenge(did, controller_key, &nonce);
    tpm_attest::verify_quote(&att.evidence, &challenge).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tpm_attest::tests::{SoftTpm, evidence};

    #[test]
    fn a_machine_root_binds_the_tpm_it_attests() {
        let tpm = SoftTpm::new(30);
        // SoftTpm::new(30)'s attestation key is [31; 32]: the root's identity
        // key is another, so the DID is not the autonomous one.
        let root = p256::SecretKey::from_slice(&[33u8; 32]).unwrap();
        let key = root.public_key().to_sec1_bytes().to_vec();
        let did = tenzro_types::did_derivation::machine_did(&key);
        let nonce = [5u8; 32];
        let (ev, _) = evidence(&tpm, &tpm_attest::admission_challenge(&did, &key, &nonce));
        let att = MachineAttestation {
            evidence: ev,
            nonce: nonce.to_vec(),
            activated: true,
        };
        assert!(tpm_evidence_binds(&did, &key, &att));
        let other = p256::SecretKey::from_slice(&[34u8; 32]).unwrap();
        let other_key = other.public_key().to_sec1_bytes().to_vec();
        let other_did = tenzro_types::did_derivation::machine_did(&other_key);
        assert!(
            !tpm_evidence_binds(&other_did, &other_key, &att),
            "a quote for another root"
        );
        assert!(
            !tpm_evidence_binds(&did, &other_key, &att),
            "a root under another key"
        );
    }

    fn attested(tpm: &SoftTpm, did_key: &[u8]) -> (String, MachineAttestation) {
        let ak = tenzro_device_key::tpm_wire::parse_public(&tpm.ak_public())
            .unwrap()
            .p256_sec1()
            .unwrap();
        let did = tpm_attest::machine_did_for_attestation_key(&ak);
        let nonce = [4u8; 32];
        let challenge = tpm_attest::admission_challenge(&did, did_key, &nonce);
        let (ev, _) = evidence(tpm, &challenge);
        (
            did,
            MachineAttestation {
                evidence: ev,
                nonce: nonce.to_vec(),
                activated: true,
            },
        )
    }

    fn md(att: &MachineAttestation) -> BTreeMap<String, String> {
        BTreeMap::from([(
            TPM_ATTESTATION_KEY.to_string(),
            serde_json::to_string(att).unwrap(),
        )])
    }

    #[test]
    fn attested_machine_binds_only_its_quoted_key() {
        let key = [9u8; 32];
        let (did, att) = attested(&SoftTpm::new(3), &key);
        assert!(registration_binding_holds(&did, &key, &md(&att)));
        assert!(
            !registration_binding_holds(&did, &[8u8; 32], &md(&att)),
            "another key must not bind"
        );
        let (other_did, _) = attested(&SoftTpm::new(4), &key);
        assert!(
            !registration_binding_holds(&other_did, &key, &md(&att)),
            "evidence roots one DID only"
        );
    }

    /// Pairing a real TPM's public endorsement key with one's own attestation
    /// key does not yield that TPM's DID: the DID follows the attestation key.
    #[test]
    fn a_borrowed_endorsement_key_does_not_claim_the_victims_did() {
        let key = [9u8; 32];
        let victim = SoftTpm::new(3);
        let attacker = SoftTpm::new(5);
        let (victim_did, _) = attested(&victim, &key);
        let (_, mut forged) = attested(&attacker, &key);
        forged.evidence.ek_public = victim.ek_public();
        assert!(!registration_binding_holds(&victim_did, &key, &md(&forged)));
    }

    /// A machine registration whose quote someone captured: the same DID,
    /// key and quote, but the attacker's wallet. Only the registration the
    /// machine's controller key signed is authorized.
    #[test]
    fn a_captured_quote_does_not_authorize_another_wallet() {
        use tenzro_crypto::composite::{HybridSigner, SignatureContext};
        use tenzro_types::identity::{
            RegisterIdentityPayload, RegistrationProof, registration_statement,
        };
        let machine = tenzro_crypto::composite::testing::TestHybridSigner::hybrid(6);
        let key = machine.public_key().p256.clone();
        let (did, att) = attested(&SoftTpm::new(3), &key);
        let signed = |wallet: u8, by: &tenzro_crypto::composite::testing::TestHybridSigner| {
            let mut payload = RegisterIdentityPayload {
                did: did.clone(),
                identity_type: "machine".into(),
                display_name: String::new(),
                controller_pubkey: key.clone(),
                key_type: "P-256".into(),
                wallet_id: format!("wallet-{wallet}"),
                wallet_address: tenzro_types::primitives::Address::new([wallet; 32]),
                pq_verifying_key: machine.public_key().pq.clone().unwrap(),
                metadata: md(&att),
                proof: RegistrationProof::Hardware {
                    signature: tenzro_types::account_signature::CompositeSignature::classical(
                        tenzro_types::account_signature::ClassicalProof::Raw {
                            signature: Vec::new(),
                        },
                    ),
                },
            };
            let signature = by
                .sign(
                    SignatureContext::IdentityRegistration,
                    &registration_statement(&payload),
                )
                .unwrap();
            payload.proof = RegistrationProof::TpmQuote { signature };
            payload
        };
        let theirs = signed(1, &machine);
        assert!(registration_is_authorized(&theirs, None));

        // Hardware with no ML-DSA-65 key registers nothing.
        let mut no_pq = signed(1, &machine);
        no_pq.pq_verifying_key = Vec::new();
        assert!(!registration_is_authorized(&no_pq, None));
        let mut stripped = signed(1, &machine);
        if let tenzro_types::identity::RegistrationProof::TpmQuote { signature } =
            &mut stripped.proof
        {
            signature.pq = None;
        }
        assert!(
            !registration_is_authorized(&stripped, None),
            "a proof without its ML-DSA-65 leg"
        );

        let mut forged = signed(2, &machine);
        forged.proof = theirs.proof.clone();
        assert!(
            !registration_is_authorized(&forged, None),
            "the machine's signature covers only its own wallet"
        );
        let attacker = tenzro_crypto::composite::testing::TestHybridSigner::hybrid(7);
        assert!(
            !registration_is_authorized(&signed(2, &attacker), None),
            "signed by a key other than the quoted one"
        );
        // A DID the key derives on its own still needs the quote to claim
        // TPM admission.
        let mut no_quote = signed(1, &machine);
        no_quote.did = tenzro_types::did_derivation::machine_did(&key);
        no_quote.metadata.clear();
        let statement = registration_statement(&no_quote);
        no_quote.proof = RegistrationProof::TpmQuote {
            signature: machine
                .sign(SignatureContext::IdentityRegistration, &statement)
                .unwrap(),
        };
        assert!(
            !registration_is_authorized(&no_quote, None),
            "TPM admission claimed without a quote"
        );
    }

    #[test]
    fn a_random_did_with_no_evidence_binds_nothing() {
        let did = format!("did:tenzro:human:{}", uuid::Uuid::new_v4());
        assert!(!registration_binding_holds(
            &did,
            &[7u8; 65],
            &BTreeMap::new()
        ));
    }
}

//! A registration's key must be shown to live in hardware.
//!
//! A registration proves its submitter holds the controller key: the key
//! signed the record. It does not prove the key is in hardware: a key made in
//! software signs just as well. Once [`GATE`] is in force a root registers
//! only with evidence the chain can check itself:
//!
//! - an autonomous machine (`did:tenzro:machine:{id}`) carries, under its
//!   `tpm_attestation` metadata, a TPM quote by the attestation key its DID
//!   derives from, vouching for the controller key;
//! - a human (`did:tenzro:human:{id}`) carries the WebAuthn registration of
//!   its passkey (`webauthn_attestation_object` and
//!   `webauthn_client_data_json`, base64): an attestation that chains to a
//!   root governance put in [`ROOTS_KEY`], for a credential that cannot be
//!   synced to other devices, whose key is in a trusted environment or a
//!   secure element and is the controller key, made with user verification,
//!   over a challenge that names the DID and the key.
//!
//! Delegated identities answer to the root they are derived under, which is
//! itself held to this rule. Institutions are not changed by it.

use base64::Engine;
use sha2::{Digest, Sha256};
use tenzro_types::agent_terms::RootKind;
use tenzro_types::identity::RegisterIdentityPayload;

use super::funding::{read_json, refuse, write_json};
use super::*;

/// The gate of the rule.
pub const GATE: &str = "feature.registration_attestation.activation_epoch";

/// Where the governed WebAuthn attestation roots (PEM) are kept.
pub const ROOTS_KEY: &str = "webauthn_attestation_roots";

/// Metadata key of a human registration's attestation object, base64.
pub const ATTESTATION_OBJECT_KEY: &str = "webauthn_attestation_object";

/// Metadata key of a human registration's `clientDataJSON`, base64.
pub const CLIENT_DATA_KEY: &str = "webauthn_client_data_json";

const CHALLENGE_DOMAIN: &[u8] = b"tenzro/registration-attestation/v1";

/// The challenge a human's passkey registration answers for `did` with
/// controller key `key`: `SHA-256(domain ‖ len(did) ‖ did ‖ len(key) ‖ key)`,
/// lengths 4 bytes big-endian.
pub fn registration_challenge(did: &str, key: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(CHALLENGE_DOMAIN);
    h.update((did.len() as u32).to_be_bytes());
    h.update(did.as_bytes());
    h.update((key.len() as u32).to_be_bytes());
    h.update(key);
    h.finalize().into()
}

/// The WebAuthn attestation roots governance put in force.
pub fn attestation_roots(state: &dyn VmState) -> Vec<String> {
    read_json(state, ROOTS_KEY).unwrap_or_default()
}

/// The WebAuthn attestation roots governance put in force, as DER.
///
/// A root that does not parse is dropped, which fails closed: fewer chains
/// verify.
pub fn attestation_root_ders(state: &dyn VmState) -> Vec<Vec<u8>> {
    attestation_roots(state)
        .iter()
        .filter_map(|pem| tenzro_tee::x509::parse_pem_chain(pem).ok())
        .flatten()
        .map(|c| c.der)
        .collect()
}

/// Replace the WebAuthn attestation roots with `roots_pem`.
pub(super) fn set_roots(
    state: &mut dyn VmState,
    roots_pem: &[String],
    changes: &mut Vec<StateChange>,
) -> Result<()> {
    for pem in roots_pem {
        tenzro_tee::x509::parse_pem_chain(pem)
            .map_err(|e| refuse(format!("a WebAuthn attestation root does not parse: {e}")))?;
    }
    write_json(state, ROOTS_KEY, &roots_pem.to_vec(), changes).map(|_| ())
}

fn decode(payload: &RegisterIdentityPayload, key: &str) -> Result<Vec<u8>> {
    let text = payload
        .metadata
        .get(key)
        .ok_or_else(|| refuse(format!("a human registration carries {key}")))?;
    base64::engine::general_purpose::STANDARD
        .decode(text)
        .map_err(|_| refuse(format!("{key} is not base64")))
}

/// The client data's hash, once it is a registration ceremony over the
/// registration's challenge on an https origin; and the origin's host.
fn client_data(payload: &RegisterIdentityPayload, controller: &[u8]) -> Result<([u8; 32], String)> {
    let raw = decode(payload, CLIENT_DATA_KEY)?;
    let client: serde_json::Value = serde_json::from_slice(&raw)
        .map_err(|_| refuse("the passkey's clientDataJSON is not JSON"))?;
    if client.get("type").and_then(|t| t.as_str()) != Some("webauthn.create") {
        return Err(refuse(
            "the passkey's clientDataJSON is not from a registration",
        ));
    }
    if client.get("crossOrigin").and_then(|c| c.as_bool()) == Some(true) {
        return Err(refuse(
            "a registration made inside a cross-origin frame is refused",
        ));
    }
    let challenge = client
        .get("challenge")
        .and_then(|c| c.as_str())
        .and_then(|c| {
            base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(c)
                .ok()
        })
        .ok_or_else(|| refuse("the passkey's clientDataJSON names no challenge"))?;
    if challenge != registration_challenge(&payload.did, controller) {
        return Err(refuse(
            "the passkey was registered over another challenge than this registration's",
        ));
    }
    let host = client
        .get("origin")
        .and_then(|o| o.as_str())
        .and_then(|o| o.strip_prefix("https://"))
        .map(|h| h.split(':').next().unwrap_or(h).to_string())
        .filter(|h| !h.is_empty())
        .ok_or_else(|| refuse("the passkey was registered on an origin that is not https"))?;
    Ok((Sha256::digest(&raw).into(), host))
}

fn require_human(state: &dyn VmState, payload: &RegisterIdentityPayload, now_s: u64) -> Result<()> {
    let controller = match payload.controller_pubkey.as_slice() {
        [0x04, xy @ ..] if xy.len() == 64 => xy,
        other => other,
    };
    let (client_hash, host) = client_data(payload, controller)?;
    let roots = attestation_root_ders(state);
    let facts = tenzro_auth::parse_attestation(
        &decode(payload, ATTESTATION_OBJECT_KEY)?,
        &client_hash,
        &roots,
        now_s,
    )
    .map_err(|e| refuse(format!("the passkey's attestation: {e}")))?;
    if facts.rp_id_hash != <[u8; 32]>::from(Sha256::digest(host.as_bytes())) {
        return Err(refuse(
            "the passkey was registered for another relying party than its origin",
        ));
    }
    let tenzro_auth::CredentialKey::P256(key) = &facts.credential_key else {
        return Err(refuse("a human's passkey is a P-256 key"));
    };
    if key[1..] != *controller {
        return Err(refuse(
            "the attested passkey is not this registration's controller key",
        ));
    }
    if !facts.user_verified {
        return Err(refuse(
            "the passkey was registered without user verification",
        ));
    }
    if facts.backup_eligible {
        return Err(refuse(
            "the passkey can be synced to other devices; a root's key must stay on one",
        ));
    }
    if !facts.evidence.chain_verified {
        return Err(refuse(
            "the passkey's attestation does not chain to a root governance recognises",
        ));
    }
    if !facts.evidence.proves_hardware() {
        return Err(refuse("the passkey's key is not held in hardware"));
    }
    Ok(())
}

/// Refuse a root's registration whose key is not shown to be in hardware,
/// once [`GATE`] is in force. `now_ms` yields the block time and runs only
/// when the gate is in force and the registration is a passkey's, so a
/// transaction without a block timestamp registers as before while dormant.
pub(super) fn require(
    state: &dyn VmState,
    payload: &RegisterIdentityPayload,
    now_ms: impl FnOnce() -> Result<i64>,
) -> Result<()> {
    if !crate::feature_gate::is_live_now(state, GATE) {
        return Ok(());
    }
    match RootKind::of(&payload.did) {
        Some(RootKind::Machine) => {
            let attested = payload
                .metadata
                .get(tenzro_tee::identity_evidence::TPM_ATTESTATION_KEY)
                .and_then(|json| {
                    serde_json::from_str::<tenzro_tee::tpm_attest::MachineAttestation>(json).ok()
                })
                .is_some_and(|att| {
                    tenzro_tee::identity_evidence::tpm_evidence_binds(
                        &payload.did,
                        &payload.controller_pubkey,
                        &att,
                    )
                });
            if attested {
                Ok(())
            } else {
                Err(refuse(format!(
                    "{} registers with a TPM quote by the attestation key its DID derives from",
                    payload.did
                )))
            }
        }
        Some(RootKind::Passkey) => require_human(state, payload, now_ms()?.max(0) as u64 / 1000),
        None => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::StateAdapter;
    use tenzro_tee::tpm_attest::tests::{SoftTpm, evidence};
    use tenzro_tee::tpm_attest::{
        MachineAttestation, admission_challenge, attestation_key_sec1,
        machine_did_for_attestation_key,
    };
    use tenzro_types::identity::RegistrationProof;

    fn payload(did: &str, identity_type: &str, controller: Vec<u8>) -> RegisterIdentityPayload {
        RegisterIdentityPayload {
            did: did.to_string(),
            identity_type: identity_type.into(),
            display_name: String::new(),
            controller_pubkey: controller,
            key_type: "P-256".into(),
            wallet_id: String::new(),
            wallet_address: tenzro_types::primitives::Address::new([1; 32]),
            pq_verifying_key: Vec::new(),
            metadata: Default::default(),
            proof: RegistrationProof::Hardware {
                signature: tenzro_types::account_signature::CompositeSignature::classical(
                    tenzro_types::account_signature::ClassicalProof::Raw {
                        signature: Vec::new(),
                    },
                ),
            },
        }
    }

    /// An autonomous machine's record, with its TPM's quote over the
    /// admission challenge for `quoted_controller` in its metadata.
    fn machine(seed: u8, quoted_controller: &[u8]) -> RegisterIdentityPayload {
        let tpm = SoftTpm::new(seed);
        let (probe, _) = evidence(&tpm, &[0; 32]);
        let did = machine_did_for_attestation_key(&attestation_key_sec1(&probe).unwrap());
        let nonce = [seed; 32];
        let (ev, _) = evidence(&tpm, &admission_challenge(&did, quoted_controller, &nonce));
        let att = MachineAttestation {
            evidence: ev,
            nonce: nonce.to_vec(),
            activated: true,
        };
        let mut p = payload(&did, "machine", vec![seed; 33]);
        p.metadata.insert(
            tenzro_tee::identity_evidence::TPM_ATTESTATION_KEY.to_string(),
            serde_json::to_string(&att).unwrap(),
        );
        p
    }

    fn live() -> StateAdapter {
        let mut state = StateAdapter::new();
        set_governed_param_for_test(&mut state, GATE, 0);
        state
    }

    #[test]
    fn dormant_a_registration_needs_no_hardware_evidence() {
        let state = StateAdapter::new();
        // The block time is not read while the gate is dormant.
        let no_clock = || {
            Err(crate::error::VmError::InvalidTransaction(
                "no block timestamp".to_string(),
            ))
        };
        require(
            &state,
            &payload("did:tenzro:machine:aa", "machine", vec![2; 33]),
            no_clock,
        )
        .unwrap();
        require(
            &state,
            &payload("did:tenzro:human:aa", "human", vec![2; 64]),
            no_clock,
        )
        .unwrap();
    }

    #[test]
    fn live_a_machine_registers_only_with_its_tpm_quote_for_its_controller_key() {
        let state = live();
        require(&state, &machine(5, &[5; 33]), || Ok(1)).unwrap();
        // No quote at all.
        let mut bare = machine(5, &[5; 33]);
        bare.metadata.clear();
        assert!(require(&state, &bare, || Ok(1)).is_err());
        // A quote vouching for another key than the record's controller.
        assert!(require(&state, &machine(5, &[6; 33]), || Ok(1)).is_err());
        // Delegated identities answer to their root and are not held here.
        require(
            &state,
            &payload("did:tenzro:machine:root:agent", "machine", vec![2; 33]),
            || Ok(1),
        )
        .unwrap();
    }

    #[test]
    fn live_a_human_needs_its_passkeys_attested_registration_over_this_challenge() {
        let state = live();
        let did = "did:tenzro:human:aa";
        let key = vec![7u8; 64];
        let mut p = payload(did, "human", key.clone());
        let err = require(&state, &p, || Ok(1)).unwrap_err();
        assert!(err.to_string().contains(CLIENT_DATA_KEY), "{err}");

        let client = |challenge: &[u8; 32], origin: &str| {
            base64::engine::general_purpose::STANDARD.encode(
                serde_json::to_vec(&serde_json::json!({
                    "type": "webauthn.create",
                    "challenge": base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(challenge),
                    "origin": origin,
                }))
                .unwrap(),
            )
        };
        p.metadata.insert(
            ATTESTATION_OBJECT_KEY.to_string(),
            base64::engine::general_purpose::STANDARD.encode(b"not cbor"),
        );
        // A registration ceremony over another identity's challenge.
        p.metadata.insert(
            CLIENT_DATA_KEY.to_string(),
            client(
                &registration_challenge("did:tenzro:human:bb", &key),
                "https://wallet.example",
            ),
        );
        let err = require(&state, &p, || Ok(1)).unwrap_err();
        assert!(err.to_string().contains("another challenge"), "{err}");
        // The right challenge on a plain-http origin.
        p.metadata.insert(
            CLIENT_DATA_KEY.to_string(),
            client(&registration_challenge(did, &key), "http://wallet.example"),
        );
        assert!(
            require(&state, &p, || Ok(1))
                .unwrap_err()
                .to_string()
                .contains("https")
        );
        // The right challenge, but no attestation the chain can verify.
        p.metadata.insert(
            CLIENT_DATA_KEY.to_string(),
            client(&registration_challenge(did, &key), "https://wallet.example"),
        );
        let err = require(&state, &p, || Ok(1)).unwrap_err();
        assert!(err.to_string().contains("attestation"), "{err}");
    }

    /// A security key's `packed` registration for the passkey `cred`, over
    /// `client_data`, signed by `att_key`, with flags `flags`.
    fn packed(
        cred: &p256::ecdsa::SigningKey,
        att_key: &p256::ecdsa::SigningKey,
        leaf: Vec<u8>,
        client_data: &[u8],
        flags: u8,
    ) -> Vec<u8> {
        use ciborium::value::Value;
        use p256::ecdsa::signature::Signer as _;
        let point = cred.verifying_key().to_sec1_point(false);
        let xy = point.as_bytes();
        let cose = Value::Map(vec![
            (Value::Integer(1.into()), Value::Integer(2.into())),
            (Value::Integer(3.into()), Value::Integer((-7).into())),
            (Value::Integer((-1).into()), Value::Integer(1.into())),
            (
                Value::Integer((-2).into()),
                Value::Bytes(xy[1..33].to_vec()),
            ),
            (
                Value::Integer((-3).into()),
                Value::Bytes(xy[33..65].to_vec()),
            ),
        ]);
        let mut auth = Sha256::digest(b"wallet.example").to_vec();
        auth.push(flags | 0x40);
        auth.extend_from_slice(&1u32.to_be_bytes());
        auth.extend_from_slice(&[7u8; 16]);
        auth.extend_from_slice(&3u16.to_be_bytes());
        auth.extend_from_slice(b"cid");
        ciborium::into_writer(&cose, &mut auth).unwrap();
        let mut signed = auth.clone();
        signed.extend_from_slice(&Sha256::digest(client_data));
        let sig: p256::ecdsa::Signature = att_key.sign(&signed);
        let object = Value::Map(vec![
            (Value::Text("fmt".into()), Value::Text("packed".into())),
            (Value::Text("authData".into()), Value::Bytes(auth)),
            (
                Value::Text("attStmt".into()),
                Value::Map(vec![
                    (Value::Text("alg".into()), Value::Integer((-7).into())),
                    (
                        Value::Text("sig".into()),
                        Value::Bytes(sig.to_der().as_bytes().to_vec()),
                    ),
                    (
                        Value::Text("x5c".into()),
                        Value::Array(vec![Value::Bytes(leaf)]),
                    ),
                ]),
            ),
        ]);
        let mut out = Vec::new();
        ciborium::into_writer(&object, &mut out).unwrap();
        out
    }

    fn pem(der: &[u8]) -> String {
        format!(
            "-----BEGIN CERTIFICATE-----\n{}\n-----END CERTIFICATE-----\n",
            base64::engine::general_purpose::STANDARD.encode(der)
        )
    }

    #[test]
    fn the_roots_in_force_are_read_back_as_der_and_a_bad_one_is_dropped() {
        use tenzro_tee::x509::testca;
        let k = testca::key(72);
        let root = testca::issue("FIDO Root", &k, "FIDO Root", &k, true, 1);
        let mut state = live();
        assert!(attestation_root_ders(&state).is_empty());
        write_json(
            &mut state,
            ROOTS_KEY,
            &vec!["not a certificate".to_string()],
            &mut Vec::new(),
        )
        .unwrap();
        assert!(attestation_root_ders(&state).is_empty());
        set_roots(&mut state, &[pem(&root)], &mut Vec::new()).unwrap();
        assert_eq!(attestation_root_ders(&state), vec![root]);
    }

    /// A human root whose security key registered its passkey over this
    /// registration's challenge, attested by a vendor chain governance
    /// recognises: accepted. The same registration is refused when the
    /// credential may sync, when user verification is missing, when the
    /// roots in force do not include the vendor's, and when the attested
    /// key is another than the controller key.
    #[test]
    fn live_a_human_with_a_device_bound_attested_passkey_registers() {
        use tenzro_tee::x509::testca;
        const UP: u8 = 0x01;
        const UV: u8 = 0x04;
        const BE: u8 = 0x08;
        let root_k = testca::key(70);
        let att_k = testca::key(71);
        let root = testca::issue("FIDO Root", &root_k, "FIDO Root", &root_k, true, 1);
        let leaf = testca::issue("Attestation", &att_k, "FIDO Root", &root_k, false, 2);
        let cred = p256::ecdsa::SigningKey::from_slice(&[0x21; 32]).unwrap();
        let point = cred.verifying_key().to_sec1_point(false);
        let controller = point.as_bytes()[1..].to_vec();
        let did = format!(
            "did:tenzro:human:{}",
            tenzro_types::did_derivation::human_id(&controller)
        );

        let mut state = live();
        set_roots(&mut state, &[pem(&root)], &mut Vec::new()).unwrap();
        let client = serde_json::to_vec(&serde_json::json!({
            "type": "webauthn.create",
            "challenge": base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(registration_challenge(&did, &controller)),
            "origin": "https://wallet.example",
        }))
        .unwrap();
        let registration = |flags: u8, key: &p256::ecdsa::SigningKey| {
            let mut p = payload(&did, "human", controller.clone());
            p.metadata.insert(
                ATTESTATION_OBJECT_KEY.to_string(),
                base64::engine::general_purpose::STANDARD.encode(packed(
                    key,
                    &att_k,
                    leaf.clone(),
                    &client,
                    flags,
                )),
            );
            p.metadata.insert(
                CLIENT_DATA_KEY.to_string(),
                base64::engine::general_purpose::STANDARD.encode(&client),
            );
            p
        };
        // 1_800_000_000 s: inside the test certificates' validity.
        let at = || Ok(1_800_000_000_000_i64);
        require(&state, &registration(UP | UV, &cred), at).unwrap();

        let synced = require(&state, &registration(UP | UV | BE, &cred), at).unwrap_err();
        assert!(synced.to_string().contains("synced"), "{synced}");
        assert!(require(&state, &registration(UP, &cred), at).is_err());
        let other = p256::ecdsa::SigningKey::from_slice(&[0x22; 32]).unwrap();
        let err = require(&state, &registration(UP | UV, &other), at).unwrap_err();
        assert!(err.to_string().contains("controller key"), "{err}");
        set_roots(&mut state, &[], &mut Vec::new()).unwrap();
        let unrooted = require(&state, &registration(UP | UV, &cred), at).unwrap_err();
        assert!(unrooted.to_string().contains("root"), "{unrooted}");
    }

    #[test]
    fn the_roots_cannot_be_proposed_while_the_rule_is_dormant() {
        let action = crate::governance::ProposalAction::PolicyUpdate {
            update: tenzro_types::token::PolicyUpdate::WebauthnRootsSet {
                roots_pem: Vec::new(),
            },
            memo: "roots".into(),
            track: crate::governance::PolicyTrack::Standard,
        };
        let crate::governance::ProposalAction::PolicyUpdate { update, .. } = &action else {
            unreachable!("a policy change")
        };
        assert!(crate::feature_gate::refuse_dormant_policy(&StateAdapter::new(), update).is_err());
        crate::feature_gate::refuse_dormant_policy(&live(), update).unwrap();
    }

    #[test]
    fn the_challenge_binds_the_did_and_the_key() {
        let a = registration_challenge("did:tenzro:human:aa", &[1; 64]);
        assert_ne!(a, registration_challenge("did:tenzro:human:ab", &[1; 64]));
        assert_ne!(a, registration_challenge("did:tenzro:human:aa", &[2; 64]));
    }
}

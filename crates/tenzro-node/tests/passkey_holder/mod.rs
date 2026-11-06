//! A person onboarding a human identity: a device-bound P-256 passkey and its
//! assertion over the `enroll_passkey` custody challenge that
//! `tenzro_onboardHuman` requires.
//!
//! The helpers build params only, so each harness sends them through its own
//! RPC path: `tenzro_createCustodyChallenge` with [`PasskeyHolder::challenge_params`],
//! then `tenzro_onboardHuman` with [`PasskeyHolder::onboard_params`] carrying
//! [`PasskeyHolder::authorize`] over that challenge.

// Each test binary that declares this module uses a different part of it.
#![allow(dead_code)]

use serde_json::{Value, json};
use sha2::Digest as _;

pub struct PasskeyHolder {
    passkey: tenzro_crypto::p256::P256KeyPair,
    credential_id: Vec<u8>,
    /// The ML-DSA-65 key the holder's hardware enrols with the passkey.
    pq: tenzro_crypto::pq::MlDsaSigningKey,
}

impl PasskeyHolder {
    pub fn generate() -> Self {
        let mut credential_id = vec![0u8; 16];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut credential_id);
        Self {
            passkey: tenzro_crypto::p256::P256KeyPair::generate(),
            credential_id,
            pq: tenzro_crypto::pq::MlDsaSigningKey::generate(),
        }
    }

    /// The passkey's public key, `x || y`.
    #[allow(dead_code)]
    pub fn public_xy(&self) -> Vec<u8> {
        self.passkey.public_key_bytes().to_vec()
    }

    /// `tenzro_createCustodyChallenge` params: an `enroll_passkey` challenge
    /// on this passkey, bound to its credential id.
    pub fn challenge_params(&self) -> Value {
        json!({
            "account_address": hex::encode(self.passkey.public_key_bytes()),
            "operation": "enroll_passkey",
            "target_hex": hex::encode(&self.credential_id),
        })
    }

    /// The ML-DSA-65 verifying key enrolled with the passkey, hex.
    pub fn ml_dsa_public_key_hex(&self) -> String {
        hex::encode(self.pq.verifying_key_bytes())
    }

    /// A user-verified, device-bound assertion over the `webauthn_challenge`
    /// of a `tenzro_createCustodyChallenge` result; for an `enroll_passkey`
    /// challenge, with the ML-DSA-65 leg over the same digest.
    pub fn authorize(&self, issued: &Value) -> Value {
        let challenge_id = issued["challenge_id"]
            .as_str()
            .unwrap_or_else(|| panic!("no challenge in {issued}"));
        let challenge = issued["webauthn_challenge"]
            .as_str()
            .unwrap_or_else(|| panic!("no webauthn_challenge in {issued}"));
        // The node's default RP ID is the network's.
        let rp_id = tenzro_node::config::DEFAULT_WEBAUTHN_RP_ID;
        let cdj = format!(
            r#"{{"type":"webauthn.get","challenge":"{}","origin":"https://{}","crossOrigin":false}}"#,
            challenge,
            rp_id
        )
        .into_bytes();
        let mut authenticator_data = sha2::Sha256::digest(rp_id.as_bytes()).to_vec();
        authenticator_data.push(0x01 | tenzro_crypto::webauthn::AUTH_DATA_FLAG_UV);
        authenticator_data.extend_from_slice(&1u32.to_be_bytes());
        let signer = tenzro_crypto::p256::P256Signer::from_keypair(&self.passkey);
        let signature = signer.sign_prehash(&tenzro_crypto::webauthn::webauthn_signed_hash(
            &authenticator_data,
            &cdj,
        ));
        let ml_dsa_signature_hex = (issued["operation"] == "enroll_passkey").then(|| {
            let digest = hex::decode(
                issued["challenge_hex"]
                    .as_str()
                    .expect("challenge_hex")
                    .trim_start_matches("0x"),
            )
            .expect("challenge_hex is hex");
            hex::encode(self.pq.sign(
                tenzro_crypto::composite::LABEL_MLDSA65_P256,
                &tenzro_crypto::composite::message_representative(
                    tenzro_crypto::composite::SignatureContext::AccountOwner,
                    &digest,
                ),
            ))
        });
        json!({
            "challenge_id": challenge_id,
            "credential_id_hex": hex::encode(&self.credential_id),
            "ml_dsa_signature_hex": ml_dsa_signature_hex,
            "assertion": {
                "authenticator_data": authenticator_data,
                "client_data_json": cdj,
                "signature": signature.as_bytes().to_vec(),
                "user_handle": null,
            },
            // Until the account has a keystore on chain, its keystore is this
            // passkey alone, as the registration describes it: the anchor the
            // account's first keystore change carries.
            "anchor": {
                "rp_id": rp_id,
                "credential_id": hex::encode(&self.credential_id),
                "public_key": hex::encode(self.passkey.public_key_bytes()),
                "aaguid": hex::encode([0xcbu8; 16]),
                "backup_eligible": false,
                "backup_state": false,
                "salt": 0,
            },
        })
    }

    /// This passkey's approval of a custody challenge as chain state carries
    /// it: the challenge's account and nonce, the passkey's key and its
    /// assertion over the `webauthn_challenge`, as a wallet assembles it.
    #[allow(dead_code)]
    pub fn approval(&self, issued: &Value) -> tenzro_types::agent_terms::AgentTermsApproval {
        let unhex = |field: &str| {
            let s = issued[field]
                .as_str()
                .unwrap_or_else(|| panic!("no {field} in {issued}"));
            hex::decode(s.trim_start_matches("0x")).expect("hex")
        };
        let nonce: [u8; 16] = unhex("nonce_hex").try_into().expect("16-byte nonce");
        let assertion = &self.authorize(issued)["assertion"];
        let bytes = |field: &str| -> Vec<u8> {
            serde_json::from_value(assertion[field].clone()).expect("assertion bytes")
        };
        tenzro_types::agent_terms::AgentTermsApproval {
            account: unhex("account_address"),
            nonce,
            root_public_key: self.passkey.public_key_bytes().to_vec(),
            signature: tenzro_types::account_signature::CompositeSignature {
                classical: tenzro_types::account_signature::ClassicalProof::WebAuthn {
                    authenticator_data: bytes("authenticator_data"),
                    client_data_json: bytes("client_data_json"),
                    signature: bytes("signature"),
                },
                pq: None,
            },
        }
    }

    /// `tenzro_enrollPasskey` params: this holder's passkey, credential id and
    /// `authorization` over its `enroll_passkey` challenge.
    pub fn enroll_params(&self, authorization: Value) -> Value {
        json!({
            "passkey_public_key_hex": hex::encode(self.passkey.public_key_bytes()),
            "credential_id_hex": hex::encode(&self.credential_id),
            "registration_authenticator_data_hex": hex::encode(self.registration_authenticator_data()),
            "ml_dsa_public_key_hex": self.ml_dsa_public_key_hex(),
            "authorization": authorization,
        })
    }

    /// The authenticatorData `navigator.credentials.create()` returns for this
    /// passkey on the node's RP ID: user-verified, with the attested
    /// credential (AAGUID, credential id, COSE ES256 key).
    fn registration_authenticator_data(&self) -> Vec<u8> {
        let rp_id = tenzro_node::config::DEFAULT_WEBAUTHN_RP_ID;
        let xy = self.passkey.public_key_bytes();
        let mut data = sha2::Sha256::digest(rp_id.as_bytes()).to_vec();
        data.push(0x01 | tenzro_crypto::webauthn::AUTH_DATA_FLAG_UV | 0x40);
        data.extend_from_slice(&0u32.to_be_bytes());
        data.extend_from_slice(&[0xcb; 16]);
        data.extend_from_slice(&(self.credential_id.len() as u16).to_be_bytes());
        data.extend_from_slice(&self.credential_id);
        data.extend_from_slice(&[0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20]);
        data.extend_from_slice(&xy[..32]);
        data.extend_from_slice(&[0x22, 0x58, 0x20]);
        data.extend_from_slice(&xy[32..]);
        data
    }

    /// `tenzro_onboardHuman` params: `fields` plus this holder's credential
    /// id, passkey public key and `authorization`.
    /// The passkey's public key as a P-256 verifying key.
    #[allow(dead_code)]
    pub fn verifying_key(&self) -> p256::ecdsa::VerifyingKey {
        let mut sec1 = vec![0x04];
        sec1.extend_from_slice(&self.passkey.public_key_bytes());
        p256::ecdsa::VerifyingKey::from_sec1_bytes(&sec1).expect("a P-256 key")
    }

    /// An ES256 signature by the passkey over `message`, as a JWS carries it.
    #[allow(dead_code)]
    pub fn sign_es256(&self, message: &[u8]) -> p256::ecdsa::Signature {
        let sig = tenzro_crypto::p256::P256Signer::from_keypair(&self.passkey).sign_sha256(message);
        p256::ecdsa::Signature::from_slice(sig.as_bytes()).expect("a P-256 signature")
    }

    pub fn onboard_params(&self, fields: Value, authorization: Value) -> Value {
        let mut params = fields;
        params["credential_id"] = json!(hex::encode(&self.credential_id));
        params["public_key"] = json!(format!(
            "04{}",
            hex::encode(self.passkey.public_key_bytes())
        ));
        params["ml_dsa_public_key_hex"] = json!(self.ml_dsa_public_key_hex());
        params["authorization"] = authorization;
        params
    }
}

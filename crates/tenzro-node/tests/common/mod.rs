//! A machine owner for integration tests: a passkey account enrolled on the
//! node, the node's machine identity under it, and the owner's signature on
//! machine-access calls.
//!
//! The node must be booted with `operator_did` set to [`MachineOwner::machine_did`].

// Each test crate that includes this module uses only part of it.
#![allow(dead_code)]

use serde_json::{Value, json};
use sha2::Digest as _;
use tenzro_node::TenzroNode;

/// The hardware key the node's machine identity is registered with.
/// A valid P-256 point (`x || y`, the curve's generator): the registry
/// accepts only P-256 hardware keys.
const DEVICE_KEY: [u8; 64] = [
    0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40, 0xf2,
    0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2, 0x96,
    0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e, 0x16,
    0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e, 0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5,
];

pub struct MachineOwner {
    passkey: tenzro_crypto::p256::P256KeyPair,
    credential_id: Vec<u8>,
    sign_count: u32,
    /// The ML-DSA-65 key the owner's hardware enrols with the passkey.
    pq: tenzro_crypto::pq::MlDsaSigningKey,
}

pub async fn rpc(client: &reqwest::Client, base_url: &str, method: &str, params: Value) -> Value {
    client
        .post(base_url)
        .json(&json!({"jsonrpc": "2.0", "id": 1, "method": method, "params": params}))
        .send()
        .await
        .expect("HTTP request")
        .json::<Value>()
        .await
        .expect("JSON parse")
}

impl MachineOwner {
    pub fn generate(credential: u8) -> Self {
        Self {
            passkey: tenzro_crypto::p256::P256KeyPair::generate(),
            credential_id: vec![credential; 16],
            sign_count: 0,
            pq: tenzro_crypto::pq::MlDsaSigningKey::generate(),
        }
    }

    pub fn did(&self) -> String {
        tenzro_identity::TenzroDid::from_passkey(&self.passkey.public_key_bytes()).to_string()
    }

    /// The machine DID the node's identity will have once
    /// [`register_machine`](Self::register_machine) runs.
    pub fn machine_did(&self) -> String {
        let owner = tenzro_identity::TenzroDid::from_passkey(&self.passkey.public_key_bytes());
        tenzro_identity::TenzroDid::delegated_machine(&owner.id, &DEVICE_KEY)
            .expect("machine did")
            .to_string()
    }

    /// A user-verified, device-bound assertion over a custody challenge
    /// digest: the passkey signs its account-owner WebAuthn challenge.
    pub fn authorize(&mut self, challenge_id: &str, digest: &[u8]) -> Value {
        self.sign_count += 1;
        // The node's default RP ID is the network's.
        let rp_id = tenzro_node::config::DEFAULT_WEBAUTHN_RP_ID;
        let cdj = format!(
            r#"{{"type":"webauthn.get","challenge":"{}","origin":"https://{}","crossOrigin":false}}"#,
            tenzro_crypto::composite::webauthn_challenge(
                tenzro_crypto::composite::SignatureContext::AccountOwner,
                digest
            ),
            rp_id
        )
        .into_bytes();
        let mut authenticator_data = sha2::Sha256::digest(rp_id.as_bytes()).to_vec();
        authenticator_data.push(0x01 | tenzro_crypto::webauthn::AUTH_DATA_FLAG_UV);
        authenticator_data.extend_from_slice(&self.sign_count.to_be_bytes());
        let signer = tenzro_crypto::p256::P256Signer::from_keypair(&self.passkey);
        let signature = signer.sign_prehash(&tenzro_crypto::webauthn::webauthn_signed_hash(
            &authenticator_data,
            &cdj,
        ));
        // The owner's hardware ML-DSA-65 key is enrolled, so every approval
        // carries its leg over the same digest.
        let ml_dsa_signature = self.pq.sign(
            tenzro_crypto::composite::LABEL_MLDSA65_P256,
            &tenzro_crypto::composite::message_representative(
                tenzro_crypto::composite::SignatureContext::AccountOwner,
                digest,
            ),
        );
        json!({
            "challenge_id": challenge_id,
            "credential_id_hex": hex::encode(&self.credential_id),
            "ml_dsa_signature_hex": hex::encode(ml_dsa_signature),
            "assertion": {
                "authenticator_data": authenticator_data,
                "client_data_json": cdj,
                "signature": signature.as_bytes().to_vec(),
                "user_handle": null,
            },
            // The account has no keystore on chain yet: its first passkey,
            // as the registration below describes it.
            "anchor": {
                "rp_id": tenzro_node::config::DEFAULT_WEBAUTHN_RP_ID,
                "credential_id": hex::encode(&self.credential_id),
                "public_key": hex::encode(self.passkey.public_key_bytes()),
                "aaguid": hex::encode([0xcbu8; 16]),
                "backup_eligible": false,
                "backup_state": false,
                "salt": 0,
            },
        })
    }

    async fn challenge(
        client: &reqwest::Client,
        base_url: &str,
        account: &str,
        operation: &str,
        target_hex: &str,
    ) -> (String, Vec<u8>) {
        let issued = rpc(
            client,
            base_url,
            "tenzro_createCustodyChallenge",
            json!({
                "account_address": account,
                "operation": operation,
                "target_hex": target_hex,
            }),
        )
        .await;
        let id = issued["result"]["challenge_id"]
            .as_str()
            .unwrap_or_else(|| panic!("no challenge: {issued}"))
            .to_string();
        let digest = hex::decode(
            issued["result"]["challenge_hex"]
                .as_str()
                .expect("challenge_hex")
                .trim_start_matches("0x"),
        )
        .expect("challenge is hex");
        (id, digest)
    }

    /// Enroll the owner's passkey account. Returns the account address.
    pub async fn enroll(
        &mut self,
        client: &reqwest::Client,
        base_url: &str,
        node: &TenzroNode,
    ) -> String {
        let xy = self.passkey.public_key_bytes().to_vec();
        let (challenge_id, digest) = Self::challenge(
            client,
            base_url,
            &hex::encode(&xy),
            "enroll_passkey",
            &hex::encode(&self.credential_id),
        )
        .await;
        let authorization = self.authorize(&challenge_id, &digest);
        let resp = rpc(
            client,
            base_url,
            "tenzro_enrollPasskey",
            json!({
                "display_name": "Machine owner",
                "passkey_public_key_hex": format!("04{}", hex::encode(&xy)),
                "credential_id_hex": hex::encode(&self.credential_id),
                "registration_authenticator_data_hex": hex::encode(self.registration_authenticator_data()),
                "ml_dsa_public_key_hex": hex::encode(self.pq.verifying_key_bytes()),
                "authorization": authorization,
            }),
        )
        .await;
        let account = resp["result"]["smart_account_address"]
            .as_str()
            .unwrap_or_else(|| panic!("enroll failed: {resp}"))
            .to_string();
        // The identity registration an enrolment submits is a transaction no
        // block carries in these harnesses, so the enrolled ML-DSA-65 key is
        // recorded in chain state as that transaction would.
        let mut state =
            tenzro_vm::StateAdapter::with_storage(node.storage().expect("node storage").clone());
        tenzro_vm::account_keys::set_enrolled_pq_key(
            &mut state,
            &xy,
            self.pq.verifying_key_bytes().to_vec(),
            &mut Vec::new(),
        );
        state.commit().expect("commit enrolled key");
        account
    }

    /// The authenticatorData `navigator.credentials.create()` returns for the
    /// owner's passkey on the node's RP ID: user-verified, with the attested
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

    /// Register the node's machine identity under this owner.
    pub async fn register_machine(&self, node: &TenzroNode) {
        let registered = node
            .identity_registry()
            .expect("identity registry")
            .register_machine_with_fee(&self.did(), DEVICE_KEY.to_vec(), Vec::new())
            .await
            .expect("register machine");
        assert_eq!(registered.identity.did.to_string(), self.machine_did());
    }

    /// Call a machine-access method signed by this key pair: ask the node
    /// what to sign, request the challenge, sign it, and send the call again.
    pub async fn signed(
        &mut self,
        client: &reqwest::Client,
        base_url: &str,
        method: &str,
        params: Value,
    ) -> Value {
        let (challenge_id, digest) = self.challenge_for(client, base_url, method, &params).await;
        let mut params = params;
        params["authorization"] = self.authorize(&challenge_id, &digest);
        rpc(client, base_url, method, params).await
    }

    /// The custody challenge the node asks for before `method` with `params`.
    pub async fn challenge_for(
        &self,
        client: &reqwest::Client,
        base_url: &str,
        method: &str,
        params: &Value,
    ) -> (String, Vec<u8>) {
        let unsigned = rpc(client, base_url, method, params.clone()).await;
        let data = &unsigned["error"]["data"];
        let account = data["account_address"]
            .as_str()
            .unwrap_or_else(|| panic!("no signing request in {unsigned}"));
        let target_hex = data["target_hex"].as_str().expect("target_hex");
        Self::challenge(client, base_url, account, "machine_access", target_hex).await
    }
}

/// Terms for a grant to every job on the node for `cidr` on `port`.
pub fn network_terms(grantee: &str, cidr: &str, port: Option<u16>) -> Value {
    json!({
        "grantee_did": grantee,
        "resources": [{ "kind": "network", "cidr": cidr, "port": port }],
        "operations": ["connect"],
        "expires_at_ms": chrono::Utc::now().timestamp_millis() + 3_600_000,
    })
}

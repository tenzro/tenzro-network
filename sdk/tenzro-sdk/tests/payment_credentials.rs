//! Paying a node-issued challenge: the authorization message against the
//! shared vector the node verifies, the signed credential, and the request
//! shape the pay endpoints parse.

use async_trait::async_trait;
use p256::ecdsa::signature::hazmat::{PrehashSigner, PrehashVerifier};
use p256::ecdsa::{Signature, SigningKey, VerifyingKey};
use sha2::{Digest, Sha256};
use tenzro_sdk::error::SdkResult;
use tenzro_sdk::payment::{
    PAYMENT_AUTHORIZATION_CONTEXT, PaymentChallenge, authorization_message, challenge_request,
    credential_params, sign_credential,
};
use tenzro_sdk::wallet::{HybridSigner, account_address, composite_message_representative};

fn vector() -> serde_json::Value {
    serde_json::from_str(include_str!(
        "../../fixtures/payments/challenge_authorization.json"
    ))
    .unwrap()
}

fn challenge() -> PaymentChallenge {
    serde_json::from_value(vector()["challenge"].clone()).unwrap()
}

struct P256Only(SigningKey);

impl P256Only {
    fn new() -> Self {
        Self(SigningKey::from_bytes(&[7u8; 32].into()).unwrap())
    }
    fn verifying_key(&self) -> VerifyingKey {
        *self.0.verifying_key()
    }
}

#[async_trait]
impl HybridSigner for P256Only {
    fn p256_public_key(&self) -> [u8; 64] {
        let point = self.verifying_key().to_encoded_point(false);
        point.as_bytes()[1..].try_into().unwrap()
    }
    fn ml_dsa_public_key(&self) -> Option<Vec<u8>> {
        None
    }
    async fn sign_composite(&self, m_prime: &[u8]) -> SdkResult<([u8; 64], Option<Vec<u8>>)> {
        let sig: Signature = self.0.sign_prehash(&Sha256::digest(m_prime)).unwrap();
        Ok((sig.to_bytes().into(), None))
    }
    async fn sign_p256(&self, _message: &[u8]) -> SdkResult<[u8; 64]> {
        unreachable!("a payment authorization is a composite signature")
    }
}

#[test]
fn the_authorization_message_matches_the_shared_vector() {
    let v = vector();
    let public_key: [u8; 64] = hex::decode(v["public_key"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let payer = account_address(&public_key);
    assert_eq!(hex::encode(payer), v["payer_address"].as_str().unwrap());
    let max_amount: u128 = v["max_amount"].as_str().unwrap().parse().unwrap();
    let message = authorization_message(&challenge(), &payer, max_amount).unwrap();
    assert_eq!(hex::encode(message), v["message"].as_str().unwrap());
}

#[test]
fn a_challenge_without_a_chain_id_is_refused() {
    let mut c = challenge();
    c.extra.remove("chain_id");
    assert!(authorization_message(&c, &[0u8; 32], 1).is_err());
}

#[tokio::test]
async fn the_credential_is_signed_by_the_hardware_key_and_names_its_account() {
    let signer = P256Only::new();
    let c = challenge();
    let credential = sign_credential(&c, &signer, "did:tenzro:human:payer", Some(2500), None)
        .await
        .unwrap();

    let public_key = signer.p256_public_key();
    let payer = account_address(&public_key);
    assert_eq!(credential.challenge_id, c.challenge_id);
    assert_eq!(credential.protocol, "mpp");
    assert_eq!(credential.amount, 1000);
    assert_eq!(credential.payer_address, hex::encode(payer));
    assert_eq!(credential.extra["public_key"], hex::encode(public_key));
    assert_eq!(credential.extra["upto_max"], "2500");
    assert_eq!(credential.signature["classical"]["form"], "raw");
    assert!(credential.signature.get("pq").is_none());

    let m_prime = composite_message_representative(
        PAYMENT_AUTHORIZATION_CONTEXT,
        &authorization_message(&c, &payer, 2500).unwrap(),
    );
    let sig_bytes = hex::decode(
        credential.signature["classical"]["signature"]
            .as_str()
            .unwrap(),
    )
    .unwrap();
    let sig = Signature::from_slice(&sig_bytes).unwrap();
    signer
        .verifying_key()
        .verify_prehash(&Sha256::digest(&m_prime), &sig)
        .unwrap();
}

#[tokio::test]
async fn an_exact_credential_carries_no_ceiling_and_a_ceiling_below_the_charge_is_refused() {
    let signer = P256Only::new();
    let exact = sign_credential(&challenge(), &signer, "", None, None)
        .await
        .unwrap();
    assert!(exact.extra.get("upto_max").is_none());
    assert!(
        sign_credential(&challenge(), &signer, "", Some(999), None)
            .await
            .is_err()
    );
}

#[tokio::test]
async fn the_credential_params_are_the_credential_object() {
    let signer = P256Only::new();
    let c = challenge();
    let credential = sign_credential(&c, &signer, "", None, None).await.unwrap();
    let params = credential_params(&credential).unwrap();
    let obj = params.as_object().unwrap();
    assert_eq!(obj.len(), 1);
    assert_eq!(obj["credential"]["challenge_id"], c.challenge_id.as_str());
    assert_eq!(obj["credential"]["amount"], 1000);
}

#[test]
fn the_challenge_request_is_the_object_the_node_reads() {
    let p = challenge_request("/r", u128::MAX, "TNZO", "x402", Some("0909"));
    assert_eq!(p["amount"], u128::MAX.to_string());
    assert_eq!(p["resource"], "/r");
    assert_eq!(p["protocol"], "x402");
    assert_eq!(p["recipient"], "0909");
    assert!(
        challenge_request("/r", 1, "TNZO", "mpp", None)
            .get("recipient")
            .is_none()
    );
}

/// A credential may pay from a named account the signer's passkey acts for:
/// the shared account of a wallet, not the account its own key derives.
#[tokio::test]
async fn a_credential_pays_from_the_account_the_caller_names() {
    let signer = P256Only::new();
    let mut shared = [0u8; 32];
    shared[..20].copy_from_slice(&[0xab; 20]);
    let credential = sign_credential(&challenge(), &signer, "", None, Some(shared))
        .await
        .unwrap();
    assert_eq!(credential.payer_address, hex::encode(shared));
}

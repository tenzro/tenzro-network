//! The AP2 mandate-to-Terms vectors in `sdk/fixtures/ap2_terms/vectors.json`:
//! each open Payment Mandate constraint narrows a payment the agent's Terms
//! already decide, and the outcome after both checks is the vector's.

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{SigningKey, VerifyingKey};
use serde_json::{Map, Value, json};
use tenzro_payments::ap2::{
    Ap2Presentation, MandateKeys, ProposedPayment, VCT_PAYMENT, VCT_PAYMENT_OPEN, b64_sha256,
    jwk_of, sign_jws, verify,
};
use tenzro_payments::terms_gate::{PaymentIntent, TermsGate};
use tenzro_payments::{PaymentError, Result};

const AGENT: &str = "did:tenzro:machine:agent";
const ROOT: &str = "did:tenzro:human:root";

fn key() -> SigningKey {
    use getrandom_0_4::{SysRng, rand_core::UnwrapErr};
    use p256::elliptic_curve::Generate;
    SigningKey::generate_from_rng(&mut UnwrapErr(SysRng))
}

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

fn jws(k: &SigningKey, claims: &Value) -> String {
    let mut h = Map::new();
    h.insert("alg".into(), "ES256".into());
    h.insert("jwk".into(), jwk_of(k.verifying_key()));
    sign_jws(&h, claims, |m| k.sign(m))
}

/// An SD-JWT disclosing every claim but `vct` and `cnf`.
fn sd_jwt(k: &SigningKey, claims: Value) -> String {
    let mut body = Map::new();
    let mut digests = Vec::new();
    let mut discs = Vec::new();
    for (name, v) in claims.as_object().unwrap() {
        if name == "vct" || name == "cnf" {
            body.insert(name.clone(), v.clone());
            continue;
        }
        let d = B64.encode(serde_json::to_vec(&json!(["s", name, v])).unwrap());
        digests.push(Value::String(b64_sha256(d.as_bytes())));
        discs.push(d);
    }
    body.insert("_sd".into(), Value::Array(digests));
    body.insert("_sd_alg".into(), "sha-256".into());
    let mut out = jws(k, &Value::Object(body));
    for d in discs {
        out.push('~');
        out.push_str(&d);
    }
    out.push('~');
    out
}

struct Keys {
    root: VerifyingKey,
    agent: VerifyingKey,
}

impl MandateKeys for Keys {
    fn controller_of(&self, agent_did: &str) -> Option<String> {
        (agent_did == AGENT).then(|| ROOT.to_string())
    }
    fn did_lists_key(&self, did: &str, key: &VerifyingKey) -> Result<bool> {
        Ok((did == ROOT && *key == self.root) || (did == AGENT && *key == self.agent))
    }
}

struct PerTx(u128);

impl TermsGate for PerTx {
    fn authorize(&self, i: &PaymentIntent<'_>) -> Result<()> {
        if i.amount > self.0 {
            return Err(PaymentError::VerificationFailed(
                "over the Terms limit".into(),
            ));
        }
        Ok(())
    }
}

#[test]
fn every_vector_decides_as_stated() {
    let path = format!(
        "{}/../../sdk/fixtures/ap2_terms/vectors.json",
        env!("CARGO_MANIFEST_DIR")
    );
    let file: Value = serde_json::from_str(&std::fs::read_to_string(path).unwrap()).unwrap();
    let payee = file["payee"].as_str().unwrap();
    let currency = file["currency"].as_str().unwrap();
    let (root, agent, merchant) = (key(), key(), key());
    let keys = Keys {
        root: *root.verifying_key(),
        agent: *agent.verifying_key(),
    };
    let checkout = jws(&merchant, &json!({"id": "chk", "exp": now() + 600}));
    let txid = b64_sha256(checkout.as_bytes());

    let cases = file["cases"].as_array().unwrap();
    assert!(cases.len() >= 15);
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let amount = case["amount"].as_u64().unwrap();
        let constraints: Vec<Value> =
            serde_json::from_str(&case["constraints"].to_string().replace("$PAYEE", payee))
                .unwrap();
        let mut all = Vec::new();
        if case["omit_reference"] != true {
            all.push(json!({"type": "payment.reference", "conditional_transaction_id": txid}));
        }
        all.extend(constraints);
        let open = sd_jwt(
            &root,
            json!({"vct": VCT_PAYMENT_OPEN, "cnf": {"jwk": jwk_of(agent.verifying_key())},
                   "constraints": all, "exp": now() + 600}),
        );
        let closed = sd_jwt(
            &agent,
            json!({"vct": VCT_PAYMENT, "transaction_id": txid,
                   "payee": {"id": payee, "name": "seller"},
                   "payment_amount": {"amount": amount, "currency": currency},
                   "payment_instrument": {"id": "tenzro-wallet", "type": "tenzro"},
                   "exp": now() + 600}),
        );
        let presented = Ap2Presentation {
            checkout_jwt: checkout.clone(),
            payment_mandate: closed,
            open_payment_mandate: Some(open),
        };
        let pay = ProposedPayment {
            agent_did: AGENT,
            payee,
            amount: u128::from(amount),
            currency,
            chain: "tenzro:1337",
        };
        let terms = PerTx(u128::from(case["terms_max"].as_u64().unwrap()));
        let got = verify(
            &presented,
            &pay,
            Some(merchant.verifying_key()),
            &keys,
            &terms,
        );
        match case["expect"].as_str().unwrap() {
            "accept" => assert!(got.is_ok(), "{name}: {got:?}"),
            _ => assert!(got.is_err(), "{name} was accepted"),
        }
    }
}

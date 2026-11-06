//! Paying any service a sandbox calls.
//!
//! When an outbound request is answered `402 Payment Required` with an x402
//! (`PAYMENT-REQUIRED`) or MPP (`WWW-Authenticate: Payment`) challenge, the
//! [`Payer`] decides it for the agent: the agent and its root must be
//! unrevoked, and the payment must pass the agent's Terms as a `pay` action
//! (per-payment and period caps, payment protocols, payees). A challenge that
//! carries an AP2 checkout is paid only with a Payment Mandate the controller
//! signed, verified by `tenzro-payments`' AP2 verifier, and the presentation
//! travels with the credential. The credential is signed by the serving
//! node's hardware key for the agent's DID; the agent never holds it. It is
//! kept against the request's target and written into the retried request
//! by the supervisor middleware, after the request has left the agent.
//! Every decision is a signed record linked to the action that met the 402.

use std::collections::HashMap;
use std::sync::Arc;

use base64::Engine as _;
use parking_lot::Mutex;
use serde_json::Value as Json;
use tenzro_crypto::composite::HybridSigner;
use tenzro_payments::ap2::{self, Ap2Presentation, MandateKeys, ProposedPayment};
use tenzro_payments::terms_gate::TermsGate;
use tenzro_payments::types::{PaymentChallenge, PaymentCredential};
use tenzro_types::agent_audit::{ActionKind, ActionOutcome};

use crate::authority::{Authority, Proposed};
use crate::records::{Decision, RecordLog};

/// The request a payment is for.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Target {
    /// The sandbox that made the request.
    pub sandbox: String,
    /// HTTP method.
    pub method: String,
    /// Host.
    pub host: String,
    /// Port.
    pub port: u32,
    /// Path.
    pub path: String,
}

impl Target {
    /// The digest a payment names as the request it pays for.
    pub fn digest(&self) -> [u8; 32] {
        crate::digest(
            b"tenzro/openshell/request/v1",
            &[
                self.method.as_bytes(),
                self.host.as_bytes(),
                &self.port.to_le_bytes(),
                self.path.as_bytes(),
            ],
        )
    }

    /// The URL the request went to.
    pub fn url(&self) -> String {
        format!("http://{}:{}{}", self.host, self.port, self.path)
    }

    /// The target as a record names it.
    pub fn label(&self) -> String {
        format!("{} {}:{}{}", self.method, self.host, self.port, self.path)
    }
}

/// An authorized payment, waiting for the request to be retried.
#[derive(Debug, Clone)]
pub struct Pending {
    /// The agent paying.
    pub agent: String,
    /// The challenge paid.
    pub challenge_id: String,
    /// The header the retried request carries.
    pub header: (String, String),
    /// Amount authorized.
    pub amount: u128,
}

/// What the payer decided about a response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Paid {
    /// Not a payment challenge.
    NotAChallenge,
    /// Paid: the credential waits for the retried request.
    Authorized {
        /// The challenge paid.
        challenge_id: String,
    },
    /// Refused, and why.
    Refused(String),
}

/// Where controller-signed AP2 Payment Mandates are found.
pub trait Mandates: Send + Sync {
    /// The closed Payment Mandate (SD-JWT) the agent's controller signed for
    /// the checkout whose `transaction_id` is `transaction_id`.
    fn payment_mandate(&self, agent_did: &str, transaction_id: &str) -> Option<String>;
}

/// Decides and signs payments for agents in sandboxes.
pub struct Payer {
    authority: Arc<dyn Authority>,
    terms: Arc<dyn TermsGate>,
    mandate_keys: Arc<dyn MandateKeys>,
    mandates: Arc<dyn Mandates>,
    signer: Arc<dyn HybridSigner>,
    records: Arc<RecordLog>,
    pending: Mutex<HashMap<Target, Pending>>,
    rail: Mutex<HashMap<Target, String>>,
}

/// The wire a challenge arrived on, and so the header its answer goes in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Wire {
    X402,
    Mpp,
}

fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(n, _)| n.eq_ignore_ascii_case(name))
        .map(|(_, v)| v.as_str())
}

/// The `request` parameter of a `Payment` challenge.
fn payment_request_param(value: &str) -> Option<&str> {
    let rest = value.trim().strip_prefix("Payment")?;
    rest.split(',').find_map(|p| {
        let (k, v) = p.trim().split_once('=')?;
        (k.trim() == "request").then(|| v.trim().trim_matches('"'))
    })
}

/// The challenge a 402 response carries, if any.
fn challenge_of(headers: &[(String, String)]) -> Option<Result<(PaymentChallenge, Wire), String>> {
    if let Some(v) = header(headers, "www-authenticate").and_then(payment_request_param) {
        let parsed = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(v)
            .map_err(|e| format!("payment challenge is not base64url: {e}"))
            .and_then(|json| {
                serde_json::from_slice::<PaymentChallenge>(&json)
                    .map_err(|e| format!("payment challenge: {e}"))
            })
            .map(|c| {
                let wire = if c.protocol.eq_ignore_ascii_case("x402") {
                    Wire::X402
                } else {
                    Wire::Mpp
                };
                (c, wire)
            });
        return Some(parsed);
    }
    let required = header(headers, tenzro_payments::x402::PAYMENT_REQUIRED_HEADER)?;
    Some((|| {
        let r = tenzro_payments::x402::X402PaymentRequired::from_base64(required)
            .map_err(|e| format!("PAYMENT-REQUIRED: {e}"))?;
        let accepted = r
            .accepts
            .first()
            .ok_or_else(|| "PAYMENT-REQUIRED offers nothing".to_string())?;
        let c = tenzro_payments::x402::wire::challenge_from_requirement(accepted, &r.resource.url)
            .map_err(|e| format!("PAYMENT-REQUIRED: {e}"))?;
        Ok((c, Wire::X402))
    })())
}

impl Payer {
    /// A payer signing with the serving node's hardware key `signer`.
    pub fn new(
        authority: Arc<dyn Authority>,
        terms: Arc<dyn TermsGate>,
        mandate_keys: Arc<dyn MandateKeys>,
        mandates: Arc<dyn Mandates>,
        signer: Arc<dyn HybridSigner>,
        records: Arc<RecordLog>,
    ) -> Self {
        Self {
            authority,
            terms,
            mandate_keys,
            mandates,
            signer,
            records,
            pending: Mutex::new(HashMap::new()),
            rail: Mutex::new(HashMap::new()),
        }
    }

    fn record(&self, target: &Target, agent: &str, outcome: ActionOutcome, linked: Option<String>) {
        let kind = match &outcome {
            ActionOutcome::Refused(r) if r == crate::authority::REVOKED => ActionKind::GrantUse,
            _ => ActionKind::Spend,
        };
        let action = format!(
            "{} {}",
            self.rail
                .lock()
                .get(target)
                .cloned()
                .unwrap_or_else(|| "x402".into()),
            target.url()
        );
        if let Err(e) = self.records.record(Decision {
            session: &target.sandbox,
            agent,
            kind,
            action: &action,
            outcome,
            detail: &target.digest(),
            linked_tx: linked,
        }) {
            tracing::error!("payment record not written: {e}");
        }
    }

    /// The AP2 presentation a challenge demands, verified; `None` when it
    /// demands none.
    fn mandate(
        &self,
        agent: &str,
        c: &PaymentChallenge,
    ) -> Result<Option<Ap2Presentation>, String> {
        let Some(ap2) = c.extra.get(ap2::AP2_EXTENSION_KEY) else {
            return Ok(None);
        };
        let checkout = ap2
            .get("checkout_jwt")
            .and_then(Json::as_str)
            .ok_or("the AP2 checkout names no checkout_jwt")?;
        let payee = ap2
            .get("payee")
            .and_then(Json::as_str)
            .ok_or("the AP2 checkout names no payee")?;
        let transaction_id = ap2::b64_sha256(checkout.as_bytes());
        let mandate = self
            .mandates
            .payment_mandate(agent, &transaction_id)
            .ok_or("no Payment Mandate from the controller covers this checkout")?;
        let p = Ap2Presentation {
            checkout_jwt: checkout.to_string(),
            payment_mandate: mandate,
            open_payment_mandate: None,
        };
        let merchant = ap2
            .get("merchant_jwk")
            .map(ap2::key_from_jwk)
            .transpose()
            .map_err(|e| e.to_string())?;
        ap2::verify(
            &p,
            &ProposedPayment {
                agent_did: agent,
                payee,
                amount: c.amount,
                currency: &c.asset,
                chain: &c.chain,
            },
            merchant.as_ref(),
            self.mandate_keys.as_ref(),
            self.terms.as_ref(),
        )
        .map_err(|e| format!("AP2: {e}"))?;
        Ok(Some(p))
    }

    fn credential(
        &self,
        agent: &str,
        c: &PaymentChallenge,
        mandate: Option<&Ap2Presentation>,
    ) -> Result<PaymentCredential, String> {
        let mut cred = tenzro_payments::payer_auth::sign_credential(
            c,
            &c.protocol,
            agent,
            self.signer.as_ref(),
            c.amount,
            c.amount,
        )
        .map_err(|e| e.to_string())?;
        if let Some(p) = mandate {
            cred.extra.insert(
                ap2::AP2_EXTENSION_KEY.to_string(),
                serde_json::to_value(p).map_err(|e| e.to_string())?,
            );
        }
        Ok(cred)
    }

    fn header_for(
        c: &PaymentChallenge,
        cred: &PaymentCredential,
        wire: Wire,
    ) -> Result<(String, String), String> {
        match wire {
            Wire::X402 => {
                let payload = tenzro_payments::x402::wire::payload_for_credential(c, cred)
                    .and_then(|p| p.to_base64())
                    .map_err(|e| e.to_string())?;
                Ok((
                    tenzro_payments::x402::PAYMENT_SIGNATURE_HEADER.to_string(),
                    payload,
                ))
            }
            Wire::Mpp => {
                let v = tenzro_payments::mpp::IetfPaymentBody::for_credential(cred)
                    .and_then(|b| b.to_header())
                    .map_err(|e| e.to_string())?;
                Ok(("Authorization".to_string(), v))
            }
        }
    }

    /// Decide a response with status `status` and `headers` to `target`,
    /// made by `agent`. `action` is the leaf of the record of the request
    /// that met the challenge, which the payment's records link to.
    pub fn answer(
        &self,
        target: &Target,
        agent: &str,
        status: u32,
        headers: &[(String, String)],
        action: &str,
    ) -> Paid {
        if status != 402 {
            return Paid::NotAChallenge;
        }
        let Some(parsed) = challenge_of(headers) else {
            return Paid::NotAChallenge;
        };
        let linked = Some(action.to_string());
        let refuse = |why: String| {
            self.record(
                target,
                agent,
                ActionOutcome::Refused(why.clone()),
                linked.clone(),
            );
            Paid::Refused(why)
        };
        let (c, wire) = match parsed {
            Ok(p) => p,
            Err(e) => return refuse(e),
        };
        self.rail
            .lock()
            .insert(target.clone(), c.protocol.to_ascii_lowercase());
        let mandate = match self.mandate(agent, &c) {
            Ok(m) => m,
            Err(e) => return refuse(e),
        };
        let proposed = Proposed {
            operation: tenzro_types::agent_terms::OP_PAY.to_string(),
            counterparty: c.recipient.clone(),
            amount: c.amount,
            payment_protocol: Some(c.protocol.to_ascii_lowercase()),
            chain: String::new(),
            model: None,
            payment: Some((c.challenge_id.clone(), target.digest())),
        };
        if let Err(r) = self.authority.authorize(agent, &proposed, crate::now_ms()) {
            return refuse(r.0);
        }
        let header = match self
            .credential(agent, &c, mandate.as_ref())
            .and_then(|cred| Self::header_for(&c, &cred, wire))
        {
            Ok(h) => h,
            Err(e) => return refuse(e),
        };
        self.pending.lock().insert(
            target.clone(),
            Pending {
                agent: agent.to_string(),
                challenge_id: c.challenge_id.clone(),
                header,
                amount: c.amount,
            },
        );
        self.record(
            target,
            agent,
            ActionOutcome::Pending(format!("payment {} authorized", c.challenge_id)),
            Some(c.challenge_id.clone()),
        );
        Paid::Authorized {
            challenge_id: c.challenge_id,
        }
    }

    /// The payment waiting for a retried request to `target`, if any. It is
    /// kept until the payee answers, and refused once the agent is revoked.
    pub fn presented(&self, target: &Target) -> Option<Result<Pending, String>> {
        let pending = self.pending.lock().get(target).cloned()?;
        if let Some(why) = self.authority.revoked(&pending.agent, crate::now_ms()) {
            self.pending.lock().remove(target);
            self.record(
                target,
                &pending.agent,
                ActionOutcome::Refused(why.clone()),
                Some(pending.challenge_id.clone()),
            );
            return Some(Err(why));
        }
        Some(Ok(pending))
    }

    /// The payee answered the retried request with `status`: a 2xx settles
    /// the payment, anything else leaves it unsettled.
    pub fn settled(
        &self,
        target: &Target,
        status: u32,
        headers: &[(String, String)],
    ) -> Option<bool> {
        let pending = self.pending.lock().remove(target)?;
        let receipt = header(headers, tenzro_payments::x402::PAYMENT_RESPONSE_HEADER)
            .or_else(|| header(headers, "payment-receipt"));
        let ok = (200..300).contains(&status) && receipt.is_some();
        let outcome = if ok {
            ActionOutcome::Allowed
        } else {
            ActionOutcome::Refused(format!("payee answered {status} without a receipt"))
        };
        let linked = receipt
            .map(|r| {
                format!(
                    "{}:{}",
                    pending.challenge_id,
                    hex::encode(crate::digest(
                        b"tenzro/openshell/receipt/v1",
                        &[r.as_bytes()]
                    ))
                )
            })
            .unwrap_or(pending.challenge_id.clone());
        self.record(target, &pending.agent, outcome, Some(linked));
        Some(ok)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::authority::StateAuthority;
    use crate::credential_driver::tests::{MACHINE, ROOT, agent, terms};
    use tenzro_crypto::composite::testing::TestHybridSigner;
    use tenzro_payments::traits::PaymentGateway;
    use tenzro_payments::x402::X402PaymentServer;

    const PAYEE: &str = "0909090909090909090909090909090909090909";

    pub(crate) fn payer_fixture(
        cap: &str,
    ) -> (
        Payer,
        Arc<StateAuthority>,
        Arc<RecordLog>,
        Arc<TestHybridSigner>,
    ) {
        let id = Arc::new(TestHybridSigner::p256_only(21));
        let authority = StateAuthority::new(MACHINE, id.public_key().p256.clone(), 1337);
        let mut t = terms(&["pay", "fetch"]);
        t.delegation_scope.max_transaction_value = Some(cap.to_string());
        // AP2 mandate payments are checked as the `ap2` protocol too.
        t.delegation_scope.allowed_payment_protocols =
            vec!["x402".into(), "mpp".into(), "ap2".into()];
        authority.install_terms(&agent(), t);
        authority.fund(StateAuthority::wallet(&agent()), 1_000_000);
        let session = Arc::new(tenzro_crypto::batch::ImmediateRecordSigner::new(id.clone()));
        let records = Arc::new(RecordLog::new(session, Some("tee:tpm:00".into())));
        let payer = Payer::new(
            authority.clone(),
            authority.clone(),
            authority.clone(),
            authority.clone(),
            id.clone(),
            records.clone(),
        );
        (payer, authority, records, id)
    }

    pub(crate) async fn gateway(
        authority: &Arc<StateAuthority>,
    ) -> Arc<tenzro_payments::gateway::TenzroPaymentGateway> {
        let gw = tenzro_payments::gateway::TenzroPaymentGateway::new(1337, authority.clone())
            .with_rail(authority.clone())
            .with_payer_resolver(authority.clone());
        gw.set_terms_gate(authority.clone());
        gw.register_protocol(Arc::new(X402PaymentServer::new(
            1337,
            vec!["tenzro".to_string()],
            authority.clone(),
        )));
        Arc::new(gw)
    }

    fn target() -> Target {
        Target {
            sandbox: "sb1".into(),
            method: "GET".into(),
            host: "data.example".into(),
            port: 80,
            path: "/report".into(),
        }
    }

    async fn challenge_headers(
        gw: &tenzro_payments::gateway::TenzroPaymentGateway,
        amount: u128,
    ) -> (PaymentChallenge, Vec<(String, String)>) {
        let c = gw
            .create_challenge("x402", "/report", amount, "TNZO", PAYEE)
            .await
            .unwrap();
        let h = tenzro_payments::middleware::payment_required_header(&c).unwrap();
        (
            c,
            vec![(
                tenzro_payments::x402::PAYMENT_REQUIRED_HEADER.to_string(),
                h.to_str().unwrap().to_string(),
            )],
        )
    }

    #[tokio::test]
    async fn a_402_inside_the_terms_is_paid_and_settles_from_the_agents_wallet() {
        let (payer, authority, records, _) = payer_fixture("500");
        let gw = gateway(&authority).await;
        let (c, headers) = challenge_headers(&gw, 400).await;
        let t = target();
        assert_eq!(
            payer.answer(&t, &agent(), 402, &headers, "leaf"),
            Paid::Authorized {
                challenge_id: c.challenge_id.clone()
            }
        );
        let pending = payer.presented(&t).unwrap().unwrap();
        assert_eq!(
            pending.header.0,
            tenzro_payments::x402::PAYMENT_SIGNATURE_HEADER
        );
        // The payee verifies the credential the retried request carries.
        let cred = tenzro_payments::x402::credential_from_header(&pending.header.1).unwrap();
        let receipt = gw
            .verify_and_settle(
                &cred,
                tenzro_payments::gateway::PaymentExpectation::Resource {
                    resource: "/report",
                    payee: PAYEE,
                    min_amount: 400,
                    asset: "TNZO",
                },
            )
            .await
            .unwrap();
        assert_eq!(receipt.amount, 400);
        assert_eq!(
            authority.balance(&StateAuthority::wallet(&agent())),
            999_600
        );
        let response = vec![(
            tenzro_payments::x402::PAYMENT_RESPONSE_HEADER.to_string(),
            "r".to_string(),
        )];
        assert_eq!(payer.settled(&t, 200, &response), Some(true));
        let entries =
            crate::records::verify_session(records.identity(), &records.entries("sb1")).unwrap();
        assert!(matches!(entries[0].outcome, ActionOutcome::Pending(_)));
        assert_eq!(
            entries[0].linked_tx.as_deref(),
            Some(c.challenge_id.as_str())
        );
        assert_eq!(entries[1].outcome, ActionOutcome::Allowed);
    }

    #[tokio::test]
    async fn a_402_over_the_per_payment_cap_is_refused_and_recorded() {
        let (payer, authority, records, _) = payer_fixture("500");
        let gw = gateway(&authority).await;
        let (_, headers) = challenge_headers(&gw, 501).await;
        let t = target();
        let Paid::Refused(why) = payer.answer(&t, &agent(), 402, &headers, "leaf") else {
            panic!("paid over the cap");
        };
        assert!(why.contains("per-transaction"), "{why}");
        assert!(payer.presented(&t).is_none());
        let entries =
            crate::records::verify_session(records.identity(), &records.entries("sb1")).unwrap();
        assert!(
            matches!(&entries[0].outcome, ActionOutcome::Refused(r) if r.contains("per-transaction"))
        );
        assert_eq!(entries[0].linked_tx.as_deref(), Some("leaf"));
    }

    #[tokio::test]
    async fn the_daily_cap_counts_every_payment() {
        let (payer, authority, _, _) = payer_fixture("500");
        let mut t = terms(&["pay"]);
        t.delegation_scope.max_daily_spend = Some("700".into());
        authority.install_terms(&agent(), t);
        let gw = gateway(&authority).await;
        let (_, h1) = challenge_headers(&gw, 400).await;
        assert!(matches!(
            payer.answer(&target(), &agent(), 402, &h1, "a"),
            Paid::Authorized { .. }
        ));
        let (_, h2) = challenge_headers(&gw, 400).await;
        let Paid::Refused(why) = payer.answer(&target(), &agent(), 402, &h2, "b") else {
            panic!("paid past the daily cap");
        };
        assert!(why.contains("daily"), "{why}");
    }

    #[tokio::test]
    async fn a_payee_outside_the_terms_is_refused() {
        let (payer, authority, _, _) = payer_fixture("500");
        let mut t = terms(&["pay"]);
        t.delegation_scope.allowed_counterparties =
            vec!["0x0101010101010101010101010101010101010101".into()];
        authority.install_terms(&agent(), t);
        let gw = gateway(&authority).await;
        let (_, headers) = challenge_headers(&gw, 10).await;
        let Paid::Refused(why) = payer.answer(&target(), &agent(), 402, &headers, "a") else {
            panic!("paid a payee outside the terms");
        };
        assert!(why.contains("counterparty"), "{why}");
    }

    #[tokio::test]
    async fn revocation_refuses_new_payments_and_withdraws_pending_ones() {
        let (payer, authority, _, _) = payer_fixture("500");
        let gw = gateway(&authority).await;
        let (_, headers) = challenge_headers(&gw, 100).await;
        let t = target();
        assert!(matches!(
            payer.answer(&t, &agent(), 402, &headers, "a"),
            Paid::Authorized { .. }
        ));
        authority.revoke(ROOT, "kill switch");
        assert!(matches!(payer.presented(&t), Some(Err(_))));
        let (_, headers) = challenge_headers(&gw, 100).await;
        let Paid::Refused(why) = payer.answer(&t, &agent(), 402, &headers, "b") else {
            panic!("paid after revocation");
        };
        assert!(why.contains("revoked"), "{why}");
    }

    #[tokio::test]
    async fn an_mpp_challenge_is_answered_in_the_authorization_header() {
        let (payer, authority, _, _) = payer_fixture("500");
        let gw = gateway(&authority).await;
        let (mut c, _) = challenge_headers(&gw, 100).await;
        c.protocol = "mpp".into();
        let request = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&c).unwrap());
        let headers = vec![(
            "WWW-Authenticate".to_string(),
            format!(
                "Payment id=\"{}\", realm=\"/report\", method=\"tenzro\", intent=\"charge\", request=\"{request}\"",
                c.challenge_id
            ),
        )];
        assert!(matches!(
            payer.answer(&target(), &agent(), 402, &headers, "a"),
            Paid::Authorized { .. }
        ));
        let p = payer.presented(&target()).unwrap().unwrap();
        assert_eq!(p.header.0, "Authorization");
        assert!(p.header.1.starts_with("Payment "));
    }

    mod ap2_mandates {
        use super::*;
        use p256::ecdsa::SigningKey;
        use p256::ecdsa::signature::Signer;
        use serde_json::{Map, json};
        const B64: base64::engine::general_purpose::GeneralPurpose =
            base64::engine::general_purpose::URL_SAFE_NO_PAD;
        const SELLER: &str = "did:tenzro:machine:seller";

        fn key(seed: u8) -> SigningKey {
            SigningKey::from_slice(&[seed; 32]).unwrap()
        }

        fn jws(k: &SigningKey, claims: Json) -> String {
            let mut h = Map::new();
            h.insert("alg".into(), "ES256".into());
            h.insert("jwk".into(), ap2::jwk_of(k.verifying_key()));
            ap2::sign_jws(&h, &claims, |m| k.sign(m))
        }

        /// A closed Payment Mandate as an SD-JWT, every claim but `vct`
        /// disclosed.
        fn mandate(k: &SigningKey, checkout: &str, amount: u64) -> String {
            let now = chrono::Utc::now().timestamp();
            let claims = json!({
                "vct": "mandate.payment.1",
                "transaction_id": ap2::b64_sha256(checkout.as_bytes()),
                "payee": {"id": SELLER, "name": "seller"},
                "payment_amount": {"amount": amount, "currency": "TNZO"},
                "payment_instrument": {"id": "tenzro-wallet", "type": "tenzro"},
                "exp": now + 600,
            });
            let mut digests = Vec::new();
            let mut discs = Vec::new();
            let mut body = Map::new();
            for (name, v) in claims.as_object().unwrap() {
                if name == "vct" {
                    body.insert(name.clone(), v.clone());
                    continue;
                }
                let d = B64.encode(serde_json::to_vec(&json!(["salt", name, v])).unwrap());
                digests.push(Json::String(ap2::b64_sha256(d.as_bytes())));
                discs.push(d);
            }
            body.insert("_sd".into(), Json::Array(digests));
            body.insert("_sd_alg".into(), "sha-256".into());
            let mut out = jws(k, Json::Object(body));
            for d in discs {
                out.push('~');
                out.push_str(&d);
            }
            out.push('~');
            out
        }

        async fn checkout_challenge(
            authority: &Arc<StateAuthority>,
            amount: u128,
        ) -> (String, Vec<(String, String)>) {
            let merchant = key(9);
            let now = chrono::Utc::now().timestamp();
            let checkout = jws(&merchant, json!({"id": "chk_1", "exp": now + 600}));
            let gw = gateway(authority).await;
            let mut c = gw
                .create_challenge("x402", "/report", amount, "TNZO", PAYEE)
                .await
                .unwrap();
            c.extra.insert(
                ap2::AP2_EXTENSION_KEY.to_string(),
                json!({"checkout_jwt": checkout, "payee": SELLER,
                       "merchant_jwk": ap2::jwk_of(merchant.verifying_key())}),
            );
            let request = B64.encode(serde_json::to_vec(&c).unwrap());
            (
                checkout,
                vec![(
                    "WWW-Authenticate".to_string(),
                    format!("Payment request=\"{request}\""),
                )],
            )
        }

        #[tokio::test]
        async fn a_checkout_is_paid_only_under_the_controllers_mandate() {
            let (payer, authority, _, _) = payer_fixture("500");
            let root = key(5);
            authority.register_did_key(ROOT, *root.verifying_key());
            let (checkout, headers) = checkout_challenge(&authority, 300).await;
            // No mandate lodged: refused.
            let Paid::Refused(why) = payer.answer(&target(), &agent(), 402, &headers, "a") else {
                panic!("paid a checkout without a mandate");
            };
            assert!(why.contains("Mandate"), "{why}");
            // A mandate signed by someone other than the controller: refused.
            let tx = ap2::b64_sha256(checkout.as_bytes());
            authority.lodge_mandate(&agent(), &tx, mandate(&key(6), &checkout, 300));
            assert!(matches!(
                payer.answer(&target(), &agent(), 402, &headers, "a"),
                Paid::Refused(_)
            ));
            // The controller's mandate for less than the checkout: refused.
            authority.lodge_mandate(&agent(), &tx, mandate(&root, &checkout, 200));
            assert!(matches!(
                payer.answer(&target(), &agent(), 402, &headers, "a"),
                Paid::Refused(_)
            ));
            // The controller's mandate for the amount: paid, and presented.
            authority.lodge_mandate(&agent(), &tx, mandate(&root, &checkout, 300));
            let paid = payer.answer(&target(), &agent(), 402, &headers, "a");
            assert!(matches!(paid, Paid::Authorized { .. }), "{paid:?}");
            let p = payer.presented(&target()).unwrap().unwrap();
            let cred = tenzro_payments::x402::credential_from_header(&p.header.1).unwrap();
            assert!(cred.extra.contains_key(ap2::AP2_EXTENSION_KEY));
        }

        #[tokio::test]
        async fn a_mandate_never_lifts_the_terms() {
            let (payer, authority, _, _) = payer_fixture("100");
            let root = key(5);
            authority.register_did_key(ROOT, *root.verifying_key());
            let (checkout, headers) = checkout_challenge(&authority, 300).await;
            let tx = ap2::b64_sha256(checkout.as_bytes());
            authority.lodge_mandate(&agent(), &tx, mandate(&root, &checkout, 300));
            assert!(matches!(
                payer.answer(&target(), &agent(), 402, &headers, "a"),
                Paid::Refused(_)
            ));
        }
    }

    #[tokio::test]
    async fn a_non_402_or_a_402_without_a_challenge_is_not_a_payment() {
        let (payer, _, _, _) = payer_fixture("500");
        assert_eq!(
            payer.answer(&target(), &agent(), 200, &[], "a"),
            Paid::NotAChallenge
        );
        assert_eq!(
            payer.answer(&target(), &agent(), 402, &[], "a"),
            Paid::NotAChallenge
        );
    }
}

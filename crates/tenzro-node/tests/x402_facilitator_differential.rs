//! The x402 facilitator and consensus decide a Tenzro-scheme payment alike.
//!
//! A resource server asks the facilitator whether a payload pays its
//! requirement; the ledger then settles it with an `X402Settle` that the VM
//! checks again. The two checks are written separately, so this test feeds
//! both the same inputs (the requirement and the buyer's payload, honest and
//! tampered) and asserts:
//!
//! - whatever the facilitator accepts, consensus accepts, for the same payer,
//!   payee, payment id and amount, and the instruction the facilitator hands
//!   its ledger rail is exactly that transaction;
//! - every tampering of a signed field is refused by both;
//! - the only place the facilitator is stricter is the requirement's price,
//!   which consensus does not know: a ceiling signed above the price, or a
//!   price rewritten after signing, is refused at the facilitator and would
//!   still verify on the ledger.

use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use tenzro_crypto::composite::testing::TestHybridSigner;
use tenzro_crypto::composite::{ClassicalProof, HybridSigner};
use tenzro_payments::PaymentProtocol;
use tenzro_payments::gateway::{RailOutcome, SettlementInstruction, SettlementRail};
use tenzro_payments::payer_auth::{
    CHAIN_ID_KEY, authorized_ceiling, challenge_binding, parse_tenzro_address, payer_account,
    sign_credential,
};
use tenzro_payments::types::{PaymentChallenge, PaymentCredential};
use tenzro_payments::x402::wire::{self, CHALLENGE_ID_KEY};
use tenzro_payments::x402::{
    X402Facilitator, X402PaymentPayload, X402PaymentRequirement, X402PaymentServer,
};
use tenzro_types::payment_authorization::PaymentAuthorization;
use tenzro_types::primitives::Address;

const CHAIN_ID: u64 = 1337;
const PAYEE: &str = "0909090909090909090909090909090909090909";
const PRICE: u128 = 900;

fn signer(seed: u8) -> TestHybridSigner {
    TestHybridSigner::hybrid(seed)
}

/// The facilitator reads enrolled keys the way the node does; consensus reads
/// the same state. Every test payer enrolled the ML-DSA-65 key it signs with.
struct EnrolledPayers;

impl tenzro_payments::EnrolledKeys for EnrolledPayers {
    fn enrolled_pq_key(&self, p256_xy: &[u8]) -> tenzro_payments::Result<Option<Vec<u8>>> {
        Ok(TestHybridSigner::hybrid_pq_key(p256_xy))
    }
}

fn keys() -> Arc<dyn tenzro_payments::EnrolledKeys> {
    Arc::new(EnrolledPayers)
}

/// Chain state holding each payer's enrolled ML-DSA-65 key.
fn chain_state(payers: &[&TestHybridSigner]) -> tenzro_vm::StateAdapter {
    let mut state = tenzro_vm::StateAdapter::new();
    let mut changes = Vec::new();
    for p in payers {
        let pk = p.public_key();
        tenzro_vm::account_keys::set_enrolled_pq_key(
            &mut state,
            &pk.p256,
            pk.pq.clone().expect("hybrid"),
            &mut changes,
        );
    }
    state
}

/// The instructions the facilitator hands its ledger rail.
#[derive(Default)]
struct Recorder(Mutex<Vec<SettlementInstruction>>);

#[async_trait]
impl SettlementRail for Recorder {
    fn name(&self) -> &'static str {
        "recorder"
    }
    fn carries(&self, asset: &str) -> bool {
        asset.eq_ignore_ascii_case("TNZO")
    }
    async fn settle(&self, i: &SettlementInstruction) -> tenzro_payments::Result<RailOutcome> {
        self.0.lock().unwrap().push(i.clone());
        Ok(RailOutcome::Settled {
            reference: "0xledger".into(),
        })
    }
    async fn status(&self, _: &str) -> tenzro_payments::Result<RailOutcome> {
        Ok(RailOutcome::Pending {
            reference: String::new(),
        })
    }
}

async fn challenge() -> PaymentChallenge {
    let server = X402PaymentServer::new(CHAIN_ID, vec!["tenzro".to_string()], keys());
    let mut ch = server
        .create_challenge("/paid", PRICE, "TNZO", PAYEE)
        .await
        .expect("challenge");
    ch.extra
        .insert(CHAIN_ID_KEY.to_string(), serde_json::json!(CHAIN_ID));
    ch
}

/// The `X402Settle` fields a payload maps to, as consensus would receive
/// them: payer from the credential, payee, payment id and chain from the
/// requirement.
struct Settle {
    chain_id: u64,
    payment_id: String,
    payer: Address,
    payee: Address,
    amount: u128,
    authorization: PaymentAuthorization,
}

fn settle_tx(req: &X402PaymentRequirement, payload: &X402PaymentPayload) -> Option<Settle> {
    let credential = wire::credential_from_payload(payload).ok()?;
    let resource = payload
        .resource
        .as_ref()
        .map(|r| r.url.as_str())
        .unwrap_or_default();
    let challenge = wire::challenge_from_requirement(req, resource).ok()?;
    let public_key = hex::decode(
        credential
            .extra
            .get("public_key")?
            .as_str()?
            .trim_start_matches("0x"),
    )
    .ok()?;
    let payer = if credential.payer_address.is_empty() {
        payer_account(&public_key)
    } else {
        parse_tenzro_address(&credential.payer_address).ok()?
    };
    Some(Settle {
        chain_id: wire::tenzro_chain_id(&req.network)?,
        payment_id: challenge.challenge_id.clone(),
        payer,
        payee: parse_tenzro_address(&req.pay_to).ok()?,
        amount: credential.amount,
        authorization: PaymentAuthorization {
            resellers: Vec::new(),
            public_key,
            signature: credential.signature.clone()?,
            max_amount: authorized_ceiling(&credential).ok()?,
            asset: credential.asset.clone(),
            binding: challenge_binding(&challenge).ok()?,
        },
    })
}

fn consensus_accepts(state: &tenzro_vm::StateAdapter, tx: &Settle) -> bool {
    tenzro_vm::native::verify_payment_authorization(
        state,
        tx.chain_id,
        &tx.payment_id,
        &tx.payer,
        &tx.payee,
        tx.amount,
        &tx.authorization,
        0,
    )
    .is_ok()
}

#[derive(Debug, PartialEq)]
enum Verdict {
    Both,
    Neither,
    ConsensusOnly,
}

/// Runs one case through both and checks the invariant; returns the verdict.
async fn decide(
    state: &tenzro_vm::StateAdapter,
    name: &str,
    req: &X402PaymentRequirement,
    payload: &X402PaymentPayload,
) -> Verdict {
    let rail = Arc::new(Recorder::default());
    let facilitator =
        X402Facilitator::new(CHAIN_ID, Vec::new(), keys()).with_ledger_rail(rail.clone());
    let verified = facilitator.verify(req, payload).await;
    let tx = settle_tx(req, payload);
    let consensus = tx.as_ref().is_some_and(|tx| consensus_accepts(state, tx));
    match verified {
        Ok(v) => {
            let tx = tx.unwrap_or_else(|| {
                panic!("{name}: the facilitator accepted a payload with no settlement")
            });
            assert!(
                consensus,
                "{name}: the facilitator accepted what consensus refuses"
            );
            assert_eq!(v.payer, hex::encode(tx.payer.as_bytes()), "{name}: payer");
            let settled = facilitator.settle(req, payload).await;
            assert!(settled.success, "{name}: {settled:?}");
            let seen = rail.0.lock().unwrap().clone();
            assert_eq!(seen.len(), 1, "{name}");
            let i = &seen[0];
            assert_eq!(
                (i.payer.address, i.payee, i.amount, i.payment_id.as_str()),
                (tx.payer, tx.payee, tx.amount, tx.payment_id.as_str()),
                "{name}: the rail settles another transaction than consensus checked"
            );
            assert_eq!(
                i.payer.authorization, tx.authorization,
                "{name}: authorization"
            );
            Verdict::Both
        }
        Err(_) if consensus => Verdict::ConsensusOnly,
        Err(_) => Verdict::Neither,
    }
}

async fn signed(
    by: &TestHybridSigner,
    amount: u128,
    ceiling: u128,
) -> (PaymentChallenge, PaymentCredential) {
    let ch = challenge().await;
    let cred = sign_credential(&ch, "x402", "", by, amount, ceiling).expect("credential");
    (ch, cred)
}

fn encode(
    ch: &PaymentChallenge,
    cred: &PaymentCredential,
) -> (X402PaymentRequirement, X402PaymentPayload) {
    (
        wire::requirement_for(ch),
        wire::payload_for_credential(ch, cred).expect("payload"),
    )
}

#[tokio::test]
async fn the_facilitator_never_accepts_what_consensus_refuses() {
    let payer = signer(0x51);
    let other = signer(0x52);
    let state = chain_state(&[&payer, &other]);

    let (ch, cred) = signed(&payer, PRICE, PRICE).await;
    let (req, payload) = encode(&ch, &cred);
    assert_eq!(
        decide(&state, "honest", &req, &payload).await,
        Verdict::Both
    );

    // Requirement rewritten after signing: payee, challenge id, chain.
    // The payload names the rewritten requirement as the one it accepts, so
    // only the signature stands between it and settlement.
    // A rewritten price is the facilitator's alone to catch.
    let rewritten: Vec<(&str, Verdict, Box<dyn Fn(&mut X402PaymentRequirement)>)> = vec![
        (
            "payee rewritten",
            Verdict::Neither,
            Box::new(|r| r.pay_to = "0808080808080808080808080808080808080808".into()),
        ),
        (
            "challenge rewritten",
            Verdict::Neither,
            Box::new(|r| r.set_extra(CHALLENGE_ID_KEY, serde_json::json!("another"))),
        ),
        (
            "chain rewritten",
            Verdict::Neither,
            Box::new(|r| r.network = "tenzro:1".into()),
        ),
        (
            "price rewritten",
            Verdict::ConsensusOnly,
            Box::new(|r| r.amount = (PRICE * 2).to_string()),
        ),
    ];
    for (name, expected, rewrite) in rewritten {
        let mut r = req.clone();
        rewrite(&mut r);
        let mut p = payload.clone();
        p.accepted = r.clone();
        assert_eq!(decide(&state, name, &r, &p).await, expected, "{name}");
    }

    // Credential tampered after signing.
    let tampered: Vec<(&str, Box<dyn Fn(&mut PaymentCredential)>)> = vec![
        (
            "charge above the ceiling",
            Box::new(|c| c.amount = PRICE + 1),
        ),
        (
            "classical signature",
            Box::new(|c| {
                if let Some(sig) = c.signature.as_mut()
                    && let ClassicalProof::Raw { signature } = &mut sig.classical
                {
                    signature[0] ^= 1;
                }
            }),
        ),
        (
            "post-quantum signature",
            Box::new(|c| {
                if let Some(pq) = c.signature.as_mut().and_then(|s| s.pq.as_mut()) {
                    pq[0] ^= 1;
                }
            }),
        ),
        (
            "post-quantum leg stripped",
            Box::new(|c| {
                if let Some(sig) = c.signature.as_mut() {
                    sig.pq = None;
                }
            }),
        ),
        ("asset", Box::new(|c| c.asset = "USDC".into())),
        (
            "another payer named",
            Box::new(|c| c.payer_address = PAYEE.into()),
        ),
    ];
    for (name, tamper) in tampered {
        let mut c = cred.clone();
        tamper(&mut c);
        let (req, payload) = encode(&ch, &c);
        assert_eq!(
            decide(&state, name, &req, &payload).await,
            Verdict::Neither,
            "{name}"
        );
    }

    // Another key presenting this payer's signature.
    let (_, theirs) = signed(&other, PRICE, PRICE).await;
    let mut c = cred.clone();
    c.extra
        .insert("public_key".into(), theirs.extra["public_key"].clone());
    let (req, payload) = encode(&ch, &c);
    assert_eq!(
        decide(&state, "another key", &req, &payload).await,
        Verdict::Neither
    );

    // A charge below the signed ceiling: whatever the facilitator decides,
    // the invariant holds.
    let (ch2, below) = signed(&payer, PRICE - 100, PRICE).await;
    let (req, payload) = encode(&ch2, &below);
    let _ = decide(&state, "charge below the ceiling", &req, &payload).await;

    // The requirement's price is the facilitator's alone to enforce.
    let (ch3, over) = signed(&payer, PRICE, PRICE + 1).await;
    let (req, payload) = encode(&ch3, &over);
    assert_eq!(
        decide(&state, "ceiling above the price", &req, &payload).await,
        Verdict::ConsensusOnly
    );
}

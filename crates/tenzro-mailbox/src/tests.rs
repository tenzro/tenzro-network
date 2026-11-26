use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use parking_lot::Mutex;
use sha2::{Digest, Sha256};
use tenzro_crypto::testing::TestHybridSigner;
use tenzro_crypto::{CompositeSignature, HybridSigner, SignatureContext};
use tenzro_types::payment_authorization::{EscrowVoucher, escrow_voucher_preimage};

use crate::service::entry_id;
use crate::store::faults::fail_writes;
use crate::{
    Action, Auth, Capability, Deposit, DepositPolicy, EscrowView, Ledger, Mailbox, MailboxConfig,
    MailboxError, SenderProof, SigningKey, auth_preimage, deposit_binding, sender_preimage,
};

const CHAIN: u64 = 13380;
const NOW: u64 = 1_800_000_000_000;
const RATE: u128 = 10;
const LIFETIME_S: u64 = 7200;
const ESCROW: [u8; 32] = [7; 32];
const BOB: &str = "did:tenzro:human:bob";
const CAROL: &str = "did:tenzro:human:carol";

#[derive(Default)]
struct FakeLedger {
    /// The keys that act for each DID.
    dids: Mutex<HashMap<String, Vec<SigningKey>>>,
    /// The keys that act for each account.
    accounts: Mutex<HashMap<[u8; 32], Vec<SigningKey>>>,
    escrows: Mutex<HashMap<[u8; 32], EscrowView>>,
}

fn key_among(keys: Option<&Vec<SigningKey>>, public_key: &[u8]) -> Option<SigningKey> {
    keys?.iter().find(|k| k.key.p256 == public_key).cloned()
}

#[async_trait]
impl Ledger for FakeLedger {
    async fn account_key(
        &self,
        public_key: &[u8],
        account: &[u8; 32],
    ) -> Result<Option<SigningKey>, MailboxError> {
        Ok(key_among(self.accounts.lock().get(account), public_key))
    }

    async fn did_key(
        &self,
        did: &str,
        public_key: &[u8],
    ) -> Result<Option<SigningKey>, MailboxError> {
        Ok(key_among(self.dids.lock().get(did), public_key))
    }

    async fn escrow(&self, escrow_id: &[u8; 32]) -> Result<Option<EscrowView>, MailboxError> {
        Ok(self.escrows.lock().get(escrow_id).cloned())
    }
}

/// An operator, a payer with an escrow for the operator and a passkey its
/// keystore links, a recipient with a root key and two more devices, and a
/// third party.
struct World {
    ledger: Arc<FakeLedger>,
    operator: Arc<TestHybridSigner>,
    payer: TestHybridSigner,
    payer_passkey: TestHybridSigner,
    bob_root: TestHybridSigner,
    bob_phone: TestHybridSigner,
    bob_passkey: TestHybridSigner,
    carol: TestHybridSigner,
    dir: tempfile::TempDir,
}

fn signing_key(signer: &TestHybridSigner) -> SigningKey {
    SigningKey {
        key: signer.public_key().clone(),
        rp_id: None,
    }
}

impl World {
    fn new() -> Self {
        let world = Self {
            ledger: Arc::new(FakeLedger::default()),
            operator: Arc::new(TestHybridSigner::hybrid(1)),
            payer: TestHybridSigner::hybrid(2),
            payer_passkey: TestHybridSigner::hybrid(7),
            bob_root: TestHybridSigner::hybrid(3),
            bob_phone: TestHybridSigner::p256_only(4),
            bob_passkey: TestHybridSigner::p256_only(5),
            carol: TestHybridSigner::hybrid(6),
            dir: tempfile::tempdir().expect("tempdir"),
        };
        world.ledger.dids.lock().insert(
            BOB.to_string(),
            vec![
                signing_key(&world.bob_root),
                signing_key(&world.bob_phone),
                signing_key(&world.bob_passkey),
            ],
        );
        world
            .ledger
            .dids
            .lock()
            .insert(CAROL.to_string(), vec![signing_key(&world.carol)]);
        world.ledger.accounts.lock().insert(
            world.payer.public_key().account_slot(),
            vec![
                signing_key(&world.payer),
                SigningKey {
                    key: world.payer_passkey.public_key().clone(),
                    rp_id: Some("tenzro.com".to_string()),
                },
            ],
        );
        world.ledger.escrows.lock().insert(
            ESCROW,
            EscrowView {
                payer: world.payer.public_key().account_slot(),
                payee: world.operator.public_key().account_slot(),
                amount: 1_000_000,
                claimed: 0,
                expires_at_ms: NOW + 86_400_000,
            },
        );
        world
    }

    fn mailbox_with(&self, config: MailboxConfig) -> Mailbox {
        Mailbox::open(
            config,
            self.dir.path(),
            self.ledger.clone(),
            self.operator.clone(),
            NOW,
        )
        .expect("open")
    }

    fn mailbox(&self) -> Mailbox {
        self.mailbox_with(config())
    }

    fn voucher_by(
        &self,
        signer: &TestHybridSigner,
        cumulative_amount: u128,
        binding: [u8; 32],
    ) -> EscrowVoucher {
        let message = escrow_voucher_preimage(CHAIN, &ESCROW, cumulative_amount, &binding);
        EscrowVoucher {
            escrow_id: ESCROW,
            cumulative_amount,
            binding,
            public_key: signer.public_key().p256.clone(),
            signature: signer
                .sign(SignatureContext::EscrowVoucher, &message)
                .expect("sign"),
            agent: None,
            attribution: None,
        }
    }

    /// A deposit of `sealed` for Bob whose voucher is bound to it and
    /// promises `cumulative_amount` in total.
    fn deposit(&self, sealed: &[u8], cumulative_amount: u128) -> Deposit {
        let sha: [u8; 32] = Sha256::digest(sealed).into();
        Deposit {
            recipient_did: BOB.to_string(),
            sealed: sealed.to_vec(),
            lifetime_s: LIFETIME_S,
            voucher: self.voucher_by(
                &self.payer,
                cumulative_amount,
                deposit_binding(BOB, &sha, LIFETIME_S),
            ),
            sender: None,
            capability: None,
        }
    }

    /// `deposit` with a proof that `signer` is `did`.
    fn sent_by(&self, mut deposit: Deposit, signer: &TestHybridSigner, did: &str) -> Deposit {
        let message = sender_preimage(
            &operator_p256(),
            did,
            &deposit.voucher.escrow_id,
            &deposit.voucher.binding,
        );
        deposit.sender = Some(SenderProof {
            did: did.to_string(),
            public_key: signer.public_key().p256.clone(),
            signature: signer
                .sign(SignatureContext::Mailbox, &message)
                .expect("sign"),
        });
        deposit
    }
}

/// The operator's P-256 key: `World::operator`'s.
fn operator_p256() -> Vec<u8> {
    TestHybridSigner::hybrid(1).public_key().p256.clone()
}

/// A capability for `recipient` at this mailbox under `epoch`, signed by
/// `signer`.
fn capability(
    signer: &TestHybridSigner,
    recipient: &str,
    depositor: Option<&str>,
    epoch: u64,
    expires_at_ms: u64,
) -> Capability {
    let mut capability = Capability {
        operator_key: operator_p256(),
        recipient_did: recipient.to_string(),
        policy_epoch: epoch,
        depositor_did: depositor.map(str::to_string),
        expires_at_ms,
        public_key: signer.public_key().p256.clone(),
        signature: CompositeSignature::default(),
    };
    capability.signature = signer
        .sign(SignatureContext::Mailbox, &capability.preimage())
        .expect("sign");
    capability
}

fn auth(signer: &TestHybridSigner, action: Action, did: &str, id: &str, nonce: u8) -> Auth {
    auth_at(signer, action, did, id, nonce, NOW)
}

fn auth_at(
    signer: &TestHybridSigner,
    action: Action,
    did: &str,
    id: &str,
    nonce: u8,
    timestamp_ms: u64,
) -> Auth {
    let nonce = [nonce; 16];
    Auth {
        did: did.to_string(),
        timestamp_ms,
        nonce,
        public_key: signer.public_key().p256.clone(),
        signature: signer
            .sign(
                SignatureContext::Mailbox,
                &auth_preimage(&operator_p256(), action, did, id, timestamp_ms, &nonce),
            )
            .expect("sign"),
    }
}

/// The operator's defaults with size classes small enough to read in a test.
fn config() -> MailboxConfig {
    let mut config = MailboxConfig::new(CHAIN, RATE);
    config.size_classes = vec![1, 50, 100];
    config
}

/// What the test payer pays at most: the operator's own prices.
fn terms() -> crate::Terms {
    crate::Terms {
        chain_id: CHAIN,
        max_rate_per_byte_hour: RATE,
        max_prekey_price: config().prekey_price,
    }
}

fn sealed() -> Vec<u8> {
    vec![0xAB; 100]
}

/// What `sealed()` costs for `LIFETIME_S`: 100 bytes, two hours.
const CHARGE: u128 = 100 * 2 * RATE;

fn unpaid(result: Result<crate::Receipt, MailboxError>) -> bool {
    matches!(result, Err(MailboxError::Unpaid(_)))
}

fn unauthorized<T>(result: Result<T, MailboxError>) -> bool {
    matches!(result, Err(MailboxError::Unauthorized(_)))
}

#[tokio::test]
async fn a_deposit_is_collected_from_another_device_and_the_operator_is_paid() {
    let w = World::new();
    let mailbox = w.mailbox();
    let receipt = mailbox
        .deposit(&w.deposit(&sealed(), CHARGE), NOW)
        .await
        .expect("deposit");
    assert_eq!(receipt.charge, CHARGE);
    assert_eq!(receipt.expires_at_ms, NOW + LIFETIME_S * 1000);
    receipt
        .verify(w.operator.public_key())
        .expect("operator receipt");

    let listed = mailbox
        .list(&auth(&w.bob_phone, Action::List, BOB, "", 1), NOW)
        .await
        .expect("list");
    assert_eq!(listed, vec![receipt.clone()]);

    let (got, bytes) = mailbox
        .collect(
            &auth(&w.bob_phone, Action::Collect, BOB, &receipt.id, 2),
            &receipt.id,
            NOW,
        )
        .await
        .expect("collect");
    assert_eq!((got, bytes), (receipt.clone(), sealed()));

    let due = mailbox.due().expect("due");
    assert_eq!(due.len(), 1);
    assert_eq!(due[0].charged, CHARGE);
    assert_eq!(due[0].voucher.escrow_id, ESCROW);
    assert_eq!(due[0].voucher.cumulative_amount, CHARGE);
}

#[tokio::test]
async fn a_bound_passkey_collects() {
    let w = World::new();
    let mailbox = w.mailbox();
    let receipt = mailbox
        .deposit(&w.deposit(&sealed(), CHARGE), NOW)
        .await
        .expect("deposit");
    let nonce = [9u8; 16];
    let message = auth_preimage(
        &operator_p256(),
        Action::Collect,
        BOB,
        &receipt.id,
        NOW,
        &nonce,
    );
    let assertion = Auth {
        did: BOB.to_string(),
        timestamp_ms: NOW,
        nonce,
        public_key: w.bob_passkey.public_key().p256.clone(),
        signature: CompositeSignature {
            classical: w
                .bob_passkey
                .sign_passkey(0x05, SignatureContext::Mailbox, &message),
            pq: None,
        },
    };
    let (_, bytes) = mailbox
        .collect(&assertion, &receipt.id, NOW)
        .await
        .expect("collect with a passkey");
    assert_eq!(bytes, sealed());
}

#[tokio::test]
async fn a_message_stays_until_the_recipient_acknowledges_it() {
    let w = World::new();
    let mailbox = w.mailbox();
    let id = mailbox
        .deposit(&w.deposit(&sealed(), CHARGE), NOW)
        .await
        .expect("deposit")
        .id;
    for nonce in 1..=3 {
        mailbox
            .collect(
                &auth(&w.bob_root, Action::Collect, BOB, &id, nonce),
                &id,
                NOW,
            )
            .await
            .expect("collect again");
    }
    mailbox
        .ack(&auth(&w.bob_root, Action::Ack, BOB, &id, 4), &id, NOW)
        .await
        .expect("ack");
    assert!(matches!(
        mailbox
            .collect(&auth(&w.bob_root, Action::Collect, BOB, &id, 5), &id, NOW)
            .await,
        Err(MailboxError::NotFound)
    ));
    assert!(
        mailbox
            .list(&auth(&w.bob_root, Action::List, BOB, "", 6), NOW)
            .await
            .expect("list")
            .is_empty()
    );
    // Nothing of the message is left, its recipient's directory included.
    assert_eq!(
        w.dir.path().join("mail").read_dir().expect("mail").count(),
        0
    );
}

#[tokio::test]
async fn a_third_party_cannot_list_collect_or_acknowledge() {
    let w = World::new();
    let mailbox = w.mailbox();
    let id = mailbox
        .deposit(&w.deposit(&sealed(), CHARGE), NOW)
        .await
        .expect("deposit")
        .id;

    // Carol's key signing as Bob.
    assert!(unauthorized(
        mailbox
            .list(&auth(&w.carol, Action::List, BOB, "", 1), NOW)
            .await
    ));
    assert!(unauthorized(
        mailbox
            .collect(&auth(&w.carol, Action::Collect, BOB, &id, 2), &id, NOW)
            .await
    ));
    assert!(unauthorized(
        mailbox
            .ack(&auth(&w.carol, Action::Ack, BOB, &id, 3), &id, NOW)
            .await
    ));

    // Carol signing as herself reaches only her own, empty, mailbox.
    assert!(
        mailbox
            .list(&auth(&w.carol, Action::List, CAROL, "", 4), NOW)
            .await
            .expect("list")
            .is_empty()
    );
    assert!(matches!(
        mailbox
            .collect(&auth(&w.carol, Action::Collect, CAROL, &id, 5), &id, NOW)
            .await,
        Err(MailboxError::NotFound)
    ));
    assert!(matches!(
        mailbox
            .ack(&auth(&w.carol, Action::Ack, CAROL, &id, 6), &id, NOW)
            .await,
        Err(MailboxError::NotFound)
    ));

    // Bob's signature for one action or message does not serve another.
    assert!(unauthorized(
        mailbox
            .ack(&auth(&w.bob_root, Action::Collect, BOB, &id, 7), &id, NOW)
            .await
    ));
    let other = "0".repeat(32);
    assert!(unauthorized(
        mailbox
            .collect(
                &auth(&w.bob_root, Action::Collect, BOB, &other, 8),
                &id,
                NOW
            )
            .await
    ));

    mailbox
        .collect(&auth(&w.bob_root, Action::Collect, BOB, &id, 9), &id, NOW)
        .await
        .expect("the message is still Bob's to collect");
}

#[tokio::test]
async fn a_deposit_that_is_not_paid_is_refused() {
    let w = World::new();
    let mailbox = w.mailbox();
    let sha: [u8; 32] = Sha256::digest(sealed()).into();
    let binding = deposit_binding(BOB, &sha, LIFETIME_S);

    // One wei short.
    assert!(unpaid(
        mailbox
            .deposit(&w.deposit(&sealed(), CHARGE - 1), NOW)
            .await
    ));
    // More than the escrow holds.
    assert!(unpaid(
        mailbox.deposit(&w.deposit(&sealed(), 1_000_001), NOW).await
    ));
    // Signed by someone other than the payer.
    let mut forged = w.deposit(&sealed(), CHARGE);
    forged.voucher = w.voucher_by(&w.carol, CHARGE, binding);
    assert!(unpaid(mailbox.deposit(&forged, NOW).await));
    // The payer's voucher with its amount raised after signing.
    let mut raised = w.deposit(&sealed(), CHARGE - 1);
    raised.voucher.cumulative_amount = CHARGE;
    assert!(unpaid(mailbox.deposit(&raised, NOW).await));
    // A voucher bound to no deposit.
    let mut unbound = w.deposit(&sealed(), CHARGE);
    unbound.voucher = w.voucher_by(&w.payer, CHARGE, [0; 32]);
    assert!(unpaid(mailbox.deposit(&unbound, NOW).await));
    // A voucher bound to another message.
    let mut rebound = w.deposit(&sealed(), CHARGE);
    rebound.sealed = vec![0xCD; 100];
    assert!(unpaid(mailbox.deposit(&rebound, NOW).await));
    // A voucher bound to another recipient.
    let mut redirected = w.deposit(&sealed(), CHARGE);
    redirected.recipient_did = CAROL.to_string();
    assert!(unpaid(mailbox.deposit(&redirected, NOW).await));
    // A voucher bound to a shorter lifetime.
    let mut extended = w.deposit(&sealed(), CHARGE * 2);
    extended.lifetime_s = LIFETIME_S * 2;
    assert!(unpaid(mailbox.deposit(&extended, NOW).await));

    // An escrow that pays someone else.
    w.ledger
        .escrows
        .lock()
        .get_mut(&ESCROW)
        .expect("escrow")
        .payee = w.carol.public_key().account_slot();
    assert!(unpaid(
        mailbox.deposit(&w.deposit(&sealed(), CHARGE), NOW).await
    ));
    // An escrow the payer can refund before the mailbox could claim.
    {
        let mut escrows = w.ledger.escrows.lock();
        let escrow = escrows.get_mut(&ESCROW).expect("escrow");
        escrow.payee = w.operator.public_key().account_slot();
        escrow.expires_at_ms = NOW + 60_000;
    }
    assert!(unpaid(
        mailbox.deposit(&w.deposit(&sealed(), CHARGE), NOW).await
    ));
    // No escrow at all.
    w.ledger.escrows.lock().clear();
    assert!(unpaid(
        mailbox.deposit(&w.deposit(&sealed(), CHARGE), NOW).await
    ));

    assert!(mailbox.due().expect("due").is_empty());
    assert!(
        mailbox
            .list(&auth(&w.bob_root, Action::List, BOB, "", 1), NOW)
            .await
            .expect("list")
            .is_empty()
    );
}

#[tokio::test]
async fn each_deposit_needs_the_voucher_to_cover_the_running_total() {
    let w = World::new();
    let mailbox = w.mailbox();
    mailbox
        .deposit(&w.deposit(&[1; 100], CHARGE), NOW)
        .await
        .expect("first");
    assert!(unpaid(
        mailbox
            .deposit(&w.deposit(&[2; 100], CHARGE * 2 - 1), NOW)
            .await
    ));
    let second = mailbox
        .deposit(&w.deposit(&[2; 100], CHARGE * 2), NOW)
        .await
        .expect("second");

    // The same deposit again returns its receipt and charges nothing.
    assert_eq!(
        mailbox
            .deposit(&w.deposit(&[2; 100], CHARGE * 2), NOW + 5)
            .await
            .expect("again"),
        second
    );
    let due = mailbox.due().expect("due");
    assert_eq!(due[0].charged, CHARGE * 2);
    assert_eq!(due[0].voucher.cumulative_amount, CHARGE * 2);

    // What the mailbox already claimed on the ledger counts against a
    // voucher too.
    w.ledger
        .escrows
        .lock()
        .get_mut(&ESCROW)
        .expect("escrow")
        .claimed = CHARGE * 5;
    assert!(unpaid(
        mailbox
            .deposit(&w.deposit(&[4; 100], CHARGE * 6 - 1), NOW)
            .await
    ));
    mailbox
        .deposit(&w.deposit(&[4; 100], CHARGE * 6), NOW)
        .await
        .expect("covers the claimed total and this deposit");
}

#[tokio::test]
async fn a_passkey_the_payers_keystore_links_pays() {
    let w = World::new();
    let mailbox = w.mailbox();
    let sha: [u8; 32] = Sha256::digest(sealed()).into();
    let binding = deposit_binding(BOB, &sha, LIFETIME_S);
    let message = escrow_voucher_preimage(CHAIN, &ESCROW, CHARGE, &binding);
    let mut deposit = w.deposit(&sealed(), CHARGE);
    deposit.voucher.public_key = w.payer_passkey.public_key().p256.clone();
    deposit.voucher.signature =
        w.payer_passkey
            .sign_passkey_composite(0x05, SignatureContext::EscrowVoucher, &message);
    mailbox.deposit(&deposit, NOW).await.expect("deposit");

    // The same passkey without its ML-DSA-65 leg does not.
    let other: [u8; 32] = Sha256::digest([9u8; 100]).into();
    let binding = deposit_binding(BOB, &other, LIFETIME_S);
    let message = escrow_voucher_preimage(CHAIN, &ESCROW, CHARGE * 2, &binding);
    let mut deposit = w.deposit(&[9; 100], CHARGE * 2);
    deposit.voucher.public_key = w.payer_passkey.public_key().p256.clone();
    deposit.voucher.signature = CompositeSignature {
        classical: w
            .payer_passkey
            .sign_passkey(0x05, SignatureContext::EscrowVoucher, &message),
        pq: None,
    };
    assert!(unpaid(mailbox.deposit(&deposit, NOW).await));
}

/// Where the mailbox keeps the receipt of Bob's message `id`.
fn receipt_path(w: &World, id: &str) -> std::path::PathBuf {
    w.dir
        .path()
        .join("mail")
        .join(hex::encode(Sha256::digest(BOB)))
        .join(format!("{id}.json"))
}

fn account_path(w: &World) -> std::path::PathBuf {
    w.dir
        .path()
        .join("escrows")
        .join(format!("{}.json", hex::encode(ESCROW)))
}

#[tokio::test]
async fn a_deposit_that_fails_between_its_writes_is_not_charged() {
    let w = World::new();
    let mailbox = w.mailbox();
    mailbox
        .deposit(&w.deposit(&[1; 100], CHARGE), NOW)
        .await
        .expect("first");

    // The second deposit's receipt cannot be written: a directory is in its
    // place. Its charge and its sealed bytes are already on disk by then.
    let second = w.deposit(&[2; 100], CHARGE * 2);
    let sha: [u8; 32] = Sha256::digest(&second.sealed).into();
    let receipt = receipt_path(&w, &entry_id(BOB, &sha, &second.voucher));
    let blocked = receipt.with_extension("json.tmp");
    std::fs::create_dir(&blocked).expect("block the receipt");
    assert!(matches!(
        mailbox.deposit(&second, NOW).await,
        Err(MailboxError::Store(_))
    ));
    let due = mailbox.due().expect("due");
    assert_eq!(due[0].charged, CHARGE);
    assert_eq!(due[0].voucher.cumulative_amount, CHARGE);
    assert!(!receipt.with_extension("bin").exists());
    assert!(!receipt.exists());

    // The same deposit, retried once the fault is gone, is charged once.
    std::fs::remove_dir(&blocked).expect("unblock");
    mailbox.deposit(&second, NOW).await.expect("retry");
    assert_eq!(mailbox.due().expect("due")[0].charged, CHARGE * 2);
    assert!(unpaid(
        mailbox
            .deposit(&w.deposit(&[3; 100], CHARGE * 2), NOW)
            .await
    ));
}

#[tokio::test]
async fn a_charge_whose_message_was_never_written_is_undone_at_open() {
    let w = World::new();
    let first = w
        .mailbox()
        .deposit(&w.deposit(&[1; 100], CHARGE), NOW)
        .await
        .expect("first");

    // The process died after charging a second deposit and before writing
    // its message: the escrow record names it as pending, its sealed bytes
    // are half there, and a temporary file is left beside the record.
    let lost = "ab".repeat(16);
    let mut account: serde_json::Value =
        serde_json::from_slice(&std::fs::read(account_path(&w)).expect("account")).expect("json");
    account["charged"] = serde_json::json!(CHARGE as u64 * 2);
    account["pending"] =
        serde_json::json!({ "id": lost, "recipient_did": BOB, "charge": CHARGE as u64 });
    std::fs::write(account_path(&w), account.to_string()).expect("write account");
    std::fs::write(receipt_path(&w, &lost).with_extension("bin"), [2u8; 100]).expect("bytes");
    let stray = account_path(&w).with_extension("json.tmp");
    std::fs::write(&stray, b"{").expect("stray");

    let mailbox = w.mailbox();
    assert!(!stray.exists());
    assert!(!receipt_path(&w, &lost).with_extension("bin").exists());
    assert_eq!(mailbox.due().expect("due")[0].charged, CHARGE);
    // The voucher advance that paid for the lost message pays for one
    // message, not two.
    mailbox
        .deposit(&w.deposit(&[2; 100], CHARGE * 2), NOW)
        .await
        .expect("the retried deposit");
    assert!(unpaid(
        mailbox
            .deposit(&w.deposit(&[3; 100], CHARGE * 2), NOW)
            .await
    ));

    // A pending mark left on a message that was written is cleared before
    // the message is dropped, so dropping it does not undo its charge.
    let mut account: serde_json::Value =
        serde_json::from_slice(&std::fs::read(account_path(&w)).expect("account")).expect("json");
    account["pending"] = serde_json::json!({
        "id": first.id, "recipient_did": BOB, "charge": CHARGE as u64
    });
    std::fs::write(account_path(&w), account.to_string()).expect("write account");
    mailbox
        .ack(
            &auth(&w.bob_root, Action::Ack, BOB, &first.id, 1),
            &first.id,
            NOW,
        )
        .await
        .expect("ack");
    drop(mailbox);
    assert_eq!(w.mailbox().due().expect("due")[0].charged, CHARGE * 2);
}

#[tokio::test]
async fn a_damaged_receipt_does_not_hide_the_recipients_other_mail() {
    let w = World::new();
    let mailbox = w.mailbox();
    let kept = mailbox
        .deposit(&w.deposit(&[1; 100], CHARGE), NOW)
        .await
        .expect("first");
    let damaged = receipt_path(&w, &"cd".repeat(16));
    std::fs::write(&damaged, b"not a receipt").expect("damage");
    std::fs::write(damaged.with_extension("bin"), [0u8; 100]).expect("its bytes");

    let listed = mailbox
        .list(&auth(&w.bob_root, Action::List, BOB, "", 1), NOW)
        .await
        .expect("list");
    assert_eq!(listed, vec![kept.clone()]);
    // A sweep drops the damaged receipt with its bytes and nothing else.
    assert_eq!(mailbox.sweep(NOW).expect("sweep"), 1);
    assert!(!damaged.exists() && !damaged.with_extension("bin").exists());
    let listed = mailbox
        .list(&auth(&w.bob_root, Action::List, BOB, "", 2), NOW)
        .await
        .expect("list");
    assert_eq!(listed, vec![kept]);
}

#[tokio::test]
async fn a_failed_write_never_leaves_a_charge_without_its_message() {
    let w = World::new();
    let mailbox = w.mailbox();
    mailbox
        .deposit(&w.deposit(&[1; 100], CHARGE), NOW)
        .await
        .expect("first");
    let charged = |mailbox: &Mailbox| mailbox.due().expect("due")[0].charged;

    // The escrow record itself cannot be written: nothing changes.
    let second = w.deposit(&[2; 100], CHARGE * 2);
    fail_writes(&[0]);
    assert!(matches!(
        mailbox.deposit(&second, NOW).await,
        Err(MailboxError::Store(_))
    ));
    assert_eq!(charged(&mailbox), CHARGE);

    // The receipt cannot be written, and putting the escrow record back
    // fails too: writes are the record, the sealed bytes, the receipt, then
    // the record again. The charge stays marked as pending.
    fail_writes(&[2, 3]);
    assert!(matches!(
        mailbox.deposit(&second, NOW).await,
        Err(MailboxError::Store(_))
    ));
    let record: serde_json::Value =
        serde_json::from_slice(&std::fs::read(account_path(&w)).expect("account")).expect("json");
    assert_eq!(record["charged"], CHARGE as u64 * 2);
    assert!(record["pending"].is_object());

    // The mark is settled before the escrow is used again: another deposit
    // is charged on top of what is held, not on top of the lost charge.
    let third = w.deposit(&[3; 100], CHARGE * 2);
    mailbox.deposit(&third, NOW).await.expect("third");
    assert_eq!(charged(&mailbox), CHARGE * 2);
    // And the deposit that failed is taken when it is offered again.
    let mut again = w.deposit(&[2; 100], CHARGE * 3);
    assert!(unpaid(mailbox.deposit(&second, NOW).await));
    mailbox
        .deposit(&again, NOW)
        .await
        .expect("the failed deposit, retried");
    assert_eq!(charged(&mailbox), CHARGE * 3);
    again.lifetime_s += 1;
    assert!(unpaid(mailbox.deposit(&again, NOW).await));
}

#[tokio::test]
async fn a_deposit_is_not_taken_twice_after_it_was_delivered_or_expired() {
    let w = World::new();
    let mailbox = w.mailbox();
    // Each voucher promises more than its deposit costs, so only the
    // escrow's record of what it paid for stands in the way of a replay.
    let delivered = w.deposit(&[1; 100], CHARGE * 10);
    let expired = w.deposit(&[2; 100], CHARGE * 10);
    let id = mailbox.deposit(&delivered, NOW).await.expect("first").id;
    mailbox.deposit(&expired, NOW).await.expect("second");

    mailbox
        .ack(&auth(&w.bob_root, Action::Ack, BOB, &id, 1), &id, NOW)
        .await
        .expect("ack");
    assert!(matches!(
        mailbox.deposit(&delivered, NOW + 1).await,
        Err(MailboxError::Spent)
    ));

    let end = NOW + LIFETIME_S * 1000;
    assert_eq!(mailbox.sweep(end).expect("sweep"), 1);
    assert!(matches!(
        mailbox.deposit(&expired, end - 3_600_000).await,
        Err(MailboxError::Spent)
    ));
    assert_eq!(mailbox.due().expect("due")[0].charged, CHARGE * 2);

    // The record of what was paid for outlives a restart.
    drop(mailbox);
    assert!(matches!(
        w.mailbox().deposit(&delivered, NOW + 2).await,
        Err(MailboxError::Spent)
    ));
}

#[tokio::test]
async fn deposits_over_the_operators_limits_are_refused() {
    let w = World::new();
    let mut config = config();
    config.max_deposits_per_payer_per_hour = 3;
    config.max_messages_per_recipient = 3;
    let mailbox = w.mailbox_with(config);

    // Over the largest class, between two classes, and empty.
    for size in [101, 99, 0] {
        assert!(matches!(
            mailbox
                .deposit(&w.deposit(&vec![1; size], 1_000_000), NOW)
                .await,
            Err(MailboxError::SizeClass { .. })
        ));
    }
    for lifetime_s in [0, 30 * 24 * 3600 + 1] {
        let mut deposit = w.deposit(&sealed(), 1_000_000);
        deposit.lifetime_s = lifetime_s;
        assert!(matches!(
            mailbox.deposit(&deposit, NOW).await,
            Err(MailboxError::Lifetime { .. })
        ));
    }
    for recipient_did in [
        String::new(),
        format!("did:tenzro:human:{}", "a".repeat(240)),
    ] {
        let mut deposit = w.deposit(&sealed(), 1_000_000);
        deposit.recipient_did = recipient_did;
        assert!(matches!(
            mailbox.deposit(&deposit, NOW).await,
            Err(MailboxError::Recipient { max: 256 })
        ));
    }

    for (n, total) in [(1u8, CHARGE), (2, CHARGE * 2), (3, CHARGE * 3)] {
        mailbox
            .deposit(&w.deposit(&[n; 100], total), NOW)
            .await
            .expect("within the limits");
    }
    // Three deposits this hour.
    assert!(matches!(
        mailbox
            .deposit(&w.deposit(&[4; 100], CHARGE * 4), NOW)
            .await,
        Err(MailboxError::RateLimited)
    ));
    // An hour later the payer may deposit again, and the recipient has
    // three messages waiting.
    let later = NOW + 3_600_000;
    assert!(matches!(
        mailbox
            .deposit(&w.deposit(&[4; 100], CHARGE * 4), later)
            .await,
        Err(MailboxError::RecipientFull)
    ));
    let first_sha: [u8; 32] = Sha256::digest([1u8; 100]).into();
    let first = entry_id(BOB, &first_sha, &w.deposit(&[1; 100], CHARGE).voucher);
    mailbox
        .ack(
            &auth_at(&w.bob_root, Action::Ack, BOB, &first, 1, later),
            &first,
            later,
        )
        .await
        .expect("ack");
    mailbox
        .deposit(&w.deposit(&[4; 100], CHARGE * 4), later)
        .await
        .expect("room again");
}

#[test]
fn a_mailbox_that_charges_nothing_must_be_meant() {
    let w = World::new();
    let open = |config: MailboxConfig| {
        Mailbox::open(
            config,
            w.dir.path(),
            w.ledger.clone(),
            w.operator.clone(),
            NOW,
        )
    };
    let mut free = MailboxConfig::new(CHAIN, 0);
    assert!(matches!(open(free.clone()), Err(MailboxError::Config(_))));
    free.allow_free = true;
    assert!(open(free).is_ok());
}

#[tokio::test]
async fn the_default_size_classes_take_only_padded_messages() {
    let w = World::new();
    let mailbox = w.mailbox_with(MailboxConfig::new(CHAIN, RATE));
    for size in [100, 1023, 1025, 64 * 1024 + 1] {
        assert!(matches!(
            mailbox
                .deposit(&w.deposit(&vec![1; size], 1_000_000), NOW)
                .await,
            Err(MailboxError::SizeClass { .. })
        ));
    }
    for (n, size) in [1024u128, 4 * 1024, 16 * 1024].into_iter().enumerate() {
        let total = (1024 + 4 * 1024 + 16 * 1024) * 2 * RATE;
        let receipt = mailbox
            .deposit(&w.deposit(&vec![n as u8; size as usize], total), NOW)
            .await
            .expect("a padded message");
        assert_eq!(receipt.charge, size * 2 * RATE);
    }
}

#[tokio::test]
async fn a_replayed_or_stale_request_is_refused() {
    let w = World::new();
    let mailbox = w.mailbox();
    let request = auth(&w.bob_root, Action::List, BOB, "", 1);
    mailbox.list(&request, NOW).await.expect("first use");
    assert!(unauthorized(mailbox.list(&request, NOW + 1).await));

    for timestamp_ms in [NOW - 60_001, NOW + 60_001] {
        let stale = auth_at(&w.bob_root, Action::List, BOB, "", 2, timestamp_ms);
        assert!(unauthorized(mailbox.list(&stale, NOW).await));
    }
    let edge = auth_at(&w.bob_root, Action::List, BOB, "", 3, NOW - 60_000);
    mailbox.list(&edge, NOW).await.expect("inside the window");

    // A request altered after signing.
    let mut moved = auth(&w.bob_root, Action::List, BOB, "", 4);
    moved.timestamp_ms += 1;
    assert!(unauthorized(mailbox.list(&moved, NOW).await));
}

/// Bytes of mail on disk: sealed bytes and receipts.
fn held_bytes(w: &World) -> u64 {
    let mut total = 0;
    for dir in w.dir.path().join("mail").read_dir().expect("mail") {
        for file in dir.expect("dir").path().read_dir().expect("recipient") {
            total += file.expect("file").metadata().expect("metadata").len();
        }
    }
    total
}

#[tokio::test]
async fn the_mailbox_survives_a_restart() {
    let w = World::new();
    let receipt = w
        .mailbox()
        .deposit(&w.deposit(&sealed(), CHARGE), NOW)
        .await
        .expect("deposit");

    // Sealed bytes whose receipt was never written, a stray file beside the
    // recipients' directories, and what an interrupted rewrite of the log
    // of recent requests leaves.
    let recipient_dir = w
        .dir
        .path()
        .join("mail")
        .read_dir()
        .expect("mail")
        .next()
        .expect("recipient")
        .expect("dir")
        .path();
    let one_message = held_bytes(&w);
    let orphan = recipient_dir.join(format!("{}.bin", "f".repeat(32)));
    std::fs::write(&orphan, [0u8; 40]).expect("orphan");
    std::fs::write(w.dir.path().join("mail").join("stray"), b"x").expect("stray");
    let log_tmp = w.dir.path().join("recent.log.tmp");
    std::fs::write(&log_tmp, b"n 00").expect("log tmp");

    // Room for one message and half of another.
    let mut config = config();
    config.max_total_bytes = one_message * 3 / 2;
    let mailbox = w.mailbox_with(config);
    assert!(!orphan.exists());
    assert!(!log_tmp.exists());
    let (got, bytes) = mailbox
        .collect(
            &auth(&w.bob_phone, Action::Collect, BOB, &receipt.id, 1),
            &receipt.id,
            NOW,
        )
        .await
        .expect("collect after restart");
    assert_eq!((got, bytes), (receipt, sealed()));
    assert_eq!(mailbox.due().expect("due")[0].charged, CHARGE);
    // The reopened mailbox still counts the mail it holds, receipts
    // included, and still knows what the escrow was charged.
    assert!(matches!(
        mailbox
            .deposit(&w.deposit(&[2; 100], CHARGE * 2), NOW)
            .await,
        Err(MailboxError::Full)
    ));
    assert!(unpaid(
        mailbox.deposit(&w.deposit(&[2; 50], CHARGE), NOW).await
    ));
    assert_eq!(mailbox.sweep(NOW).expect("sweep with a stray file"), 0);
}

#[tokio::test]
async fn a_damaged_line_in_the_log_of_recent_requests_closes_its_windows() {
    let w = World::new();
    {
        let mailbox = w.mailbox();
        mailbox
            .list(&auth(&w.bob_root, Action::List, BOB, "", 1), NOW)
            .await
            .expect("list");
    }
    let log = w.dir.path().join("recent.log");
    let mut text = std::fs::read_to_string(&log).expect("log");
    text.push_str("n 0011\n");
    std::fs::write(&log, text).expect("damage");

    // Which nonce or deposit time was lost is unknown. A request may be
    // dated a window ahead of the clock, so recipients' requests wait out two
    // windows, and deposits wait out the hour.
    let mailbox = w.mailbox();
    assert!(matches!(
        mailbox
            .list(&auth(&w.bob_root, Action::List, BOB, "", 9), NOW)
            .await,
        Err(MailboxError::Recovering)
    ));
    // The closure itself outlives a restart.
    drop(mailbox);
    let mailbox = w.mailbox();
    let list = |nonce: u8, at: u64| {
        let request = auth_at(&w.bob_root, Action::List, BOB, "", nonce, at);
        let mailbox = &mailbox;
        async move { mailbox.list(&request, at).await }
    };
    // A nonce signed for a window after the crash, as a lost one may have
    // been: refused while it could still be inside its window.
    let ahead = auth_at(&w.bob_root, Action::List, BOB, "", 2, NOW + 60_000);
    for at in [NOW, NOW + 60_000, NOW + 119_999] {
        assert!(matches!(
            mailbox.list(&ahead, at).await,
            Err(MailboxError::Recovering)
        ));
    }
    // Once the closure ends, that request is outside its window.
    assert!(unauthorized(mailbox.list(&ahead, NOW + 120_001).await));
    list(3, NOW + 120_000)
        .await
        .expect("after two signing windows");
    assert!(matches!(
        mailbox
            .deposit(&w.deposit(&sealed(), CHARGE), NOW + 3_599_999)
            .await,
        Err(MailboxError::Recovering)
    ));
    mailbox
        .deposit(&w.deposit(&sealed(), CHARGE), NOW + 3_600_000)
        .await
        .expect("after the hour");
}

#[tokio::test]
async fn a_restart_does_not_reopen_the_replay_window_or_reset_the_hourly_count() {
    let w = World::new();
    let mut config = config();
    config.max_deposits_per_payer_per_hour = 1;
    let request = auth(&w.bob_root, Action::List, BOB, "", 1);
    {
        let mailbox = w.mailbox_with(config.clone());
        mailbox
            .deposit(&w.deposit(&[1; 100], CHARGE), NOW)
            .await
            .expect("deposit");
        mailbox.list(&request, NOW).await.expect("first use");
    }
    let mailbox = w.mailbox_with(config.clone());
    assert!(unauthorized(mailbox.list(&request, NOW + 1).await));
    assert!(matches!(
        mailbox
            .deposit(&w.deposit(&[2; 100], CHARGE * 2), NOW + 1)
            .await,
        Err(MailboxError::RateLimited)
    ));
    drop(mailbox);

    // Records that left their windows are not carried into the next run.
    let later = NOW + 3_600_000;
    let mailbox = Mailbox::open(
        config,
        w.dir.path(),
        w.ledger.clone(),
        w.operator.clone(),
        later,
    )
    .expect("open");
    mailbox
        .deposit(&w.deposit(&[2; 100], CHARGE * 2), later)
        .await
        .expect("an hour later");
    let log = std::fs::read_to_string(w.dir.path().join("recent.log")).expect("log");
    assert_eq!(log.lines().filter(|l| !l.starts_with("c ")).count(), 1);
}

#[tokio::test]
async fn an_expired_message_is_not_served_and_is_swept() {
    let w = World::new();
    let mailbox = w.mailbox();
    let id = mailbox
        .deposit(&w.deposit(&sealed(), CHARGE), NOW)
        .await
        .expect("deposit")
        .id;
    let end = NOW + LIFETIME_S * 1000;

    assert_eq!(mailbox.sweep(end - 1).expect("sweep"), 0);
    mailbox
        .collect(
            &auth_at(&w.bob_root, Action::Collect, BOB, &id, 1, end - 1),
            &id,
            end - 1,
        )
        .await
        .expect("served until its lifetime ends");

    assert!(matches!(
        mailbox
            .collect(
                &auth_at(&w.bob_root, Action::Collect, BOB, &id, 2, end),
                &id,
                end
            )
            .await,
        Err(MailboxError::NotFound)
    ));
    assert!(
        mailbox
            .list(&auth_at(&w.bob_root, Action::List, BOB, "", 3, end), end)
            .await
            .expect("list")
            .is_empty()
    );
    assert_eq!(mailbox.sweep(end).expect("sweep"), 1);
    assert_eq!(mailbox.sweep(end).expect("sweep"), 0);
    // The payment for the time it was kept still stands.
    assert_eq!(mailbox.due().expect("due")[0].charged, CHARGE);
}

#[tokio::test]
async fn a_receipt_with_any_field_changed_does_not_verify() {
    let w = World::new();
    let receipt = w
        .mailbox()
        .deposit(&w.deposit(&sealed(), CHARGE), NOW)
        .await
        .expect("deposit");
    let operator = w.operator.public_key();
    receipt.verify(operator).expect("as issued");
    assert!(receipt.verify(w.carol.public_key()).is_err());

    let mut changed = Vec::new();
    for field in 0..8 {
        let mut r = receipt.clone();
        match field {
            0 => r.id = "0".repeat(32),
            1 => r.recipient_did = CAROL.to_string(),
            2 => r.sealed_sha256 = "0".repeat(64),
            3 => r.size += 1,
            4 => r.deposited_at_ms += 1,
            5 => r.expires_at_ms += 1,
            6 => r.escrow_id = "0".repeat(64),
            _ => r.charge += 1,
        }
        changed.push(r);
    }
    for r in changed {
        assert!(r.verify(operator).is_err(), "{r:?}");
    }
}

#[tokio::test]
async fn the_record_of_an_escrow_that_ended_is_dropped() {
    let w = World::new();
    let mailbox = w.mailbox();
    let deposit = w.deposit(&sealed(), CHARGE * 10);
    let id = mailbox.deposit(&deposit, NOW).await.expect("deposit").id;
    mailbox
        .ack(&auth(&w.bob_root, Action::Ack, BOB, &id, 1), &id, NOW)
        .await
        .expect("ack");
    let ends = NOW + 86_400_000;

    // Until the escrow ends, its record stays and the deposit is not taken
    // again.
    mailbox.sweep(ends - 1).expect("sweep");
    assert_eq!(mailbox.due().expect("due").len(), 1);
    assert!(account_path(&w).exists());
    // Once it ended, its record goes; the voucher pays for nothing any more,
    // so the deposit is still refused.
    mailbox.sweep(ends).expect("sweep");
    assert!(mailbox.due().expect("due").is_empty());
    assert!(!account_path(&w).exists());
    assert!(unpaid(mailbox.deposit(&deposit, ends).await));
}

#[tokio::test]
async fn a_sweep_keeps_the_charge_of_a_damaged_message_that_was_held() {
    let w = World::new();
    let mailbox = w.mailbox();
    let receipt = mailbox
        .deposit(&w.deposit(&sealed(), CHARGE), NOW)
        .await
        .expect("deposit");
    // The deposit's pending mark was left set, and its receipt is damaged.
    let mut account: serde_json::Value =
        serde_json::from_slice(&std::fs::read(account_path(&w)).expect("account")).expect("json");
    account["pending"] = serde_json::json!({
        "id": receipt.id, "recipient_did": BOB, "charge": CHARGE as u64
    });
    std::fs::write(account_path(&w), account.to_string()).expect("write account");
    std::fs::write(receipt_path(&w, &receipt.id), b"damaged").expect("damage");

    assert_eq!(mailbox.sweep(NOW).expect("sweep"), 1);
    // The message was held when its mark was settled, so it stays paid for.
    assert_eq!(mailbox.due().expect("due")[0].charged, CHARGE);
}

// --- Over HTTP ----------------------------------------------------------

/// Serves `mailbox` on a loopback port and returns its base URL.
async fn serve(mailbox: Mailbox) -> String {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let url = format!("http://{}/mailbox/v1", listener.local_addr().expect("addr"));
    let limits = crate::HttpLimits::default();
    let router = crate::router(std::sync::Arc::new(mailbox), &limits);
    tokio::spawn(async move { crate::serve(listener, router, &limits).await });
    url
}

/// The mailbox's clock: the HTTP routes read the system time.
fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock")
        .as_millis() as u64
}

#[tokio::test]
async fn a_message_goes_through_the_mailbox_over_http() {
    let w = World::new();
    w.ledger
        .escrows
        .lock()
        .get_mut(&ESCROW)
        .expect("escrow")
        .expires_at_ms = now() + 86_400_000;
    let url = serve(w.mailbox()).await;
    let http = reqwest::Client::new();

    let info: serde_json::Value = http
        .get(format!("{url}/info"))
        .send()
        .await
        .expect("info")
        .json()
        .await
        .expect("json");
    assert_eq!(
        info["payee"],
        hex::encode(w.operator.public_key().account_slot())
    );
    assert_eq!(info["size_classes"], serde_json::json!([1, 50, 100]));

    let receipt: crate::Receipt = http
        .post(format!("{url}/deposit"))
        .json(&w.deposit(&sealed(), CHARGE))
        .send()
        .await
        .expect("deposit")
        .json()
        .await
        .expect("receipt");
    receipt.verify(w.operator.public_key()).expect("receipt");

    let at = now();
    let list = serde_json::json!({ "auth": auth_at(&w.bob_phone, Action::List, BOB, "", 1, at) });
    let listed: serde_json::Value = http
        .post(format!("{url}/list"))
        .json(&list)
        .send()
        .await
        .expect("list")
        .json()
        .await
        .expect("json");
    assert_eq!(listed["messages"][0]["id"], receipt.id);

    let collect = serde_json::json!({
        "auth": auth_at(&w.bob_phone, Action::Collect, BOB, &receipt.id, 2, at),
        "id": receipt.id,
    });
    let collected: serde_json::Value = http
        .post(format!("{url}/collect"))
        .json(&collect)
        .send()
        .await
        .expect("collect")
        .json()
        .await
        .expect("json");
    use base64::Engine as _;
    assert_eq!(
        base64::engine::general_purpose::STANDARD
            .decode(collected["sealed"].as_str().expect("sealed"))
            .expect("base64"),
        sealed()
    );

    let ack = serde_json::json!({
        "auth": auth_at(&w.bob_phone, Action::Ack, BOB, &receipt.id, 3, at),
        "id": receipt.id,
    });
    let status = http
        .post(format!("{url}/ack"))
        .json(&ack)
        .send()
        .await
        .expect("ack")
        .status();
    assert_eq!(status, reqwest::StatusCode::OK);
}

#[tokio::test]
async fn refusals_over_http_carry_their_status() {
    let w = World::new();
    w.ledger
        .escrows
        .lock()
        .get_mut(&ESCROW)
        .expect("escrow")
        .expires_at_ms = now() + 86_400_000;
    let url = serve(w.mailbox()).await;
    let http = reqwest::Client::new();
    let post = |path: &str, body: serde_json::Value| {
        let request = http.post(format!("{url}/{path}")).json(&body);
        async move { request.send().await.expect("send") }
    };

    let short = serde_json::to_value(w.deposit(&sealed(), CHARGE - 1)).expect("json");
    let answer = post("deposit", short).await;
    assert_eq!(answer.status(), reqwest::StatusCode::PAYMENT_REQUIRED);
    let why: serde_json::Value = answer.json().await.expect("json");
    assert!(
        why["error"]
            .as_str()
            .expect("error")
            .starts_with("payment refused")
    );

    let unpadded = serde_json::to_value(w.deposit(&[1; 99], CHARGE)).expect("json");
    assert_eq!(
        post("deposit", unpadded).await.status(),
        reqwest::StatusCode::PAYLOAD_TOO_LARGE
    );

    let stranger =
        serde_json::json!({ "auth": auth_at(&w.carol, Action::List, BOB, "", 1, now()) });
    assert_eq!(
        post("list", stranger).await.status(),
        reqwest::StatusCode::UNAUTHORIZED
    );

    // A body past what the largest message or the largest key package
    // upload needs is refused before it is read whole.
    let takes = config();
    let upload = (takes.max_prekeys_per_recipient + 1) * takes.max_prekey_bytes;
    let huge = serde_json::json!({ "pad": "x".repeat(2 * upload) });
    assert_eq!(
        post("deposit", huge).await.status(),
        reqwest::StatusCode::PAYLOAD_TOO_LARGE
    );
}

// --- The ledger over JSON-RPC ---------------------------------------------

/// A node's JSON-RPC answers, as canned values keyed by method.
#[derive(Clone, Default)]
struct FakeNode {
    escrow: Option<serde_json::Value>,
    document: Option<serde_json::Value>,
    /// The keys `tenzro_getAccountSigningKey` answers for, by (public key
    /// hex, account hex).
    keys: HashMap<(String, String), serde_json::Value>,
}

async fn answer(
    axum::extract::State(node): axum::extract::State<std::sync::Arc<FakeNode>>,
    axum::Json(request): axum::Json<serde_json::Value>,
) -> axum::Json<serde_json::Value> {
    let params = &request["params"];
    let result = match request["method"].as_str().unwrap_or_default() {
        "tenzro_getEscrow" => node.escrow.clone(),
        "tenzro_resolveDidDocument" => node.document.clone(),
        "tenzro_getAccountSigningKey" => node
            .keys
            .get(&(
                params["public_key"]
                    .as_str()
                    .unwrap_or_default()
                    .to_string(),
                params["account"].as_str().unwrap_or_default().to_string(),
            ))
            .cloned(),
        _ => None,
    };
    axum::Json(match result {
        Some(result) => serde_json::json!({ "jsonrpc": "2.0", "id": 1, "result": result }),
        None => serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "error": { "code": -32004, "message": "no such record" }
        }),
    })
}

async fn serve_node(node: FakeNode) -> crate::RpcLedger {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let url = format!("http://{}/", listener.local_addr().expect("addr"));
    let router = axum::Router::new()
        .route("/", axum::routing::post(answer))
        .with_state(std::sync::Arc::new(node));
    tokio::spawn(async move { axum::serve(listener, router).await.expect("serve") });
    crate::RpcLedger::new(url)
}

fn key_answer(signer: &TestHybridSigner, rp_id: Option<&str>) -> serde_json::Value {
    serde_json::json!({
        "p256": hex::encode(&signer.public_key().p256),
        "ml_dsa": signer.public_key().pq.as_ref().map(hex::encode),
        "rp_id": rp_id,
    })
}

#[tokio::test]
async fn the_ledger_is_read_through_a_nodes_open_methods() {
    let w = World::new();
    let payer = w.payer.public_key();
    let root_account = hex::encode(tenzro_crypto::account_slot(&w.bob_root.public_key().p256));
    let mut node = FakeNode {
        escrow: Some(serde_json::json!({
            "escrow_id": format!("0x{}", hex::encode(ESCROW)),
            "payer": format!("0x{}", hex::encode(&payer.account_slot()[..20])),
            "payee": format!("0x{}", hex::encode(&w.operator.public_key().account_slot()[..20])),
            "amount": "1000000",
            "claimed": "250",
            "status": "Funded",
            "expires_at": NOW,
        })),
        document: Some(serde_json::json!({
            "id": BOB,
            "verificationMethod": [{
                "id": format!("{BOB}#key-1"),
                "type": "EcdsaSecp256r1VerificationKey2019",
                "controller": BOB,
                "publicKeyMultibase": format!(
                    "z{}",
                    bs58::encode([&[4u8][..], &w.bob_root.public_key().p256].concat()).into_string()
                ),
            }],
        })),
        keys: HashMap::new(),
    };
    node.keys.insert(
        (hex::encode(&payer.p256), hex::encode(payer.account_slot())),
        key_answer(&w.payer, None),
    );
    node.keys.insert(
        (
            hex::encode(&w.bob_phone.public_key().p256),
            root_account.clone(),
        ),
        key_answer(&w.bob_phone, Some("tenzro.com")),
    );
    let ledger = serve_node(node.clone()).await;

    let escrow = ledger.escrow(&ESCROW).await.expect("read").expect("escrow");
    assert_eq!(escrow.payer, payer.account_slot());
    assert_eq!(escrow.payee, w.operator.public_key().account_slot());
    assert_eq!((escrow.amount, escrow.claimed), (1_000_000, 250));
    assert_eq!(escrow.expires_at_ms, NOW);

    let key = ledger
        .account_key(&payer.p256, &payer.account_slot())
        .await
        .expect("read")
        .expect("key");
    assert_eq!(key.key, *payer);
    assert!(key.rp_id.is_none());
    // A key the account does not know: the node answers with an error.
    assert!(
        ledger
            .account_key(&w.carol.public_key().p256, &payer.account_slot())
            .await
            .expect("read")
            .is_none()
    );

    // A device acts for the DID through the account the DID's own key names.
    let device = ledger
        .did_key(BOB, &w.bob_phone.public_key().p256)
        .await
        .expect("read")
        .expect("device key");
    assert_eq!(device.key, *w.bob_phone.public_key());
    assert_eq!(device.rp_id.as_deref(), Some("tenzro.com"));
    assert!(
        ledger
            .did_key(BOB, &w.carol.public_key().p256)
            .await
            .expect("read")
            .is_none()
    );

    // An escrow that is no longer funded pays for nothing.
    let mut released = node.clone();
    released.escrow.as_mut().expect("escrow")["status"] = serde_json::json!("Released");
    released.document = None;
    let ledger = serve_node(released).await;
    assert!(ledger.escrow(&ESCROW).await.expect("read").is_none());
    assert!(
        ledger
            .did_key(BOB, &w.bob_phone.public_key().p256)
            .await
            .expect("read")
            .is_none()
    );

    // A node that answers with a key other than the one asked about is
    // refused, not believed.
    let mut lying = node;
    lying.keys.insert(
        (hex::encode(&payer.p256), hex::encode(payer.account_slot())),
        key_answer(&w.carol, None),
    );
    let ledger = serve_node(lying).await;
    assert!(matches!(
        ledger.account_key(&payer.p256, &payer.account_slot()).await,
        Err(MailboxError::Ledger(_))
    ));
    // A node that cannot be reached is a failure, not an absent record.
    assert!(matches!(
        crate::RpcLedger::new("http://127.0.0.1:1/")
            .escrow(&ESCROW)
            .await,
        Err(MailboxError::Ledger(_))
    ));
}

// --- Who may deposit ------------------------------------------------------

const DAVE: &str = "did:tenzro:human:dave";

fn not_allowed(result: Result<crate::Receipt, MailboxError>) -> bool {
    matches!(result, Err(MailboxError::NotAllowed(_)))
}

/// Sets Bob's depositors to `dids`, signed by Bob's phone, and returns the
/// policy epoch.
async fn only(w: &World, mailbox: &Mailbox, dids: &[&str], nonce: u8) -> u64 {
    let policy = DepositPolicy::Only(dids.iter().map(|d| d.to_string()).collect());
    mailbox
        .set_policy(
            &auth(&w.bob_phone, Action::Policy, BOB, &policy.digest(), nonce),
            &policy,
            NOW,
        )
        .await
        .expect("policy")
}

#[tokio::test]
async fn a_recipient_that_names_its_depositors_takes_mail_only_from_them() {
    let w = World::new();
    let dave = TestHybridSigner::hybrid(8);
    w.ledger
        .dids
        .lock()
        .insert(DAVE.to_string(), vec![signing_key(&dave)]);
    let mailbox = w.mailbox();
    only(&w, &mailbox, &[CAROL], 1).await;

    // Payment alone is not enough any more.
    assert!(not_allowed(
        mailbox.deposit(&w.deposit(&[1; 100], CHARGE), NOW).await
    ));
    // Neither is a proof from a DID Bob did not name, or one Carol did not
    // sign.
    let from_dave = w.sent_by(w.deposit(&[1; 100], CHARGE), &dave, DAVE);
    assert!(not_allowed(mailbox.deposit(&from_dave, NOW).await));
    let posing = w.sent_by(w.deposit(&[1; 100], CHARGE), &dave, CAROL);
    assert!(not_allowed(mailbox.deposit(&posing, NOW).await));
    // A proof for one deposit does not carry over to another.
    let mut moved = w.sent_by(w.deposit(&[1; 100], CHARGE), &w.carol, CAROL);
    moved.sender = w
        .sent_by(w.deposit(&[2; 100], CHARGE), &w.carol, CAROL)
        .sender;
    assert!(not_allowed(mailbox.deposit(&moved, NOW).await));

    let from_carol = w.sent_by(w.deposit(&[1; 100], CHARGE), &w.carol, CAROL);
    mailbox.deposit(&from_carol, NOW).await.expect("from Carol");

    // The policy is kept, and only Bob may change it.
    drop(mailbox);
    let mailbox = w.mailbox();
    assert!(not_allowed(
        mailbox
            .deposit(&w.deposit(&[2; 100], CHARGE * 2), NOW)
            .await
    ));
    let anyone = DepositPolicy::Anyone;
    assert!(unauthorized(
        mailbox
            .set_policy(
                &auth(&w.carol, Action::Policy, BOB, &anyone.digest(), 2),
                &anyone,
                NOW
            )
            .await
    ));
    // Bob's signature over one policy does not set another.
    assert!(unauthorized(
        mailbox
            .set_policy(
                &auth(&w.bob_root, Action::Policy, BOB, &anyone.digest(), 3),
                &DepositPolicy::Only([DAVE.to_string()].into()),
                NOW
            )
            .await
    ));
    mailbox
        .set_policy(
            &auth(&w.bob_root, Action::Policy, BOB, &anyone.digest(), 4),
            &anyone,
            NOW,
        )
        .await
        .expect("anyone again");
    mailbox
        .deposit(&w.deposit(&[2; 100], CHARGE * 2), NOW)
        .await
        .expect("anyone who pays");
}

#[tokio::test]
async fn a_capability_the_recipient_signed_lets_its_holder_deposit() {
    let w = World::new();
    let dave = TestHybridSigner::hybrid(8);
    w.ledger
        .dids
        .lock()
        .insert(DAVE.to_string(), vec![signing_key(&dave)]);
    let mailbox = w.mailbox();
    let epoch = only(&w, &mailbox, &[CAROL], 1).await;
    let with = |fill: u8, total: u128, cap: Capability| {
        let mut deposit = w.deposit(&[fill; 100], total);
        deposit.capability = Some(cap);
        deposit
    };
    let later = NOW + 60_000;

    // A bearer capability: whoever holds it deposits until it expires.
    let bearer = capability(&w.bob_phone, BOB, None, epoch, later);
    mailbox
        .deposit(&with(1, CHARGE, bearer.clone()), NOW)
        .await
        .expect("bearer");
    assert!(not_allowed(
        mailbox.deposit(&with(2, CHARGE * 2, bearer), later).await
    ));
    // Signed by someone else than Bob, or for another recipient.
    assert!(not_allowed(
        mailbox
            .deposit(
                &with(2, CHARGE * 2, capability(&w.carol, BOB, None, epoch, later)),
                NOW
            )
            .await
    ));
    assert!(not_allowed(
        mailbox
            .deposit(
                &with(
                    2,
                    CHARGE * 2,
                    capability(&w.carol, CAROL, None, epoch, later)
                ),
                NOW
            )
            .await
    ));
    // Its expiry moved after Bob signed it.
    let mut stretched = capability(&w.bob_phone, BOB, None, epoch, later);
    stretched.expires_at_ms += 1;
    assert!(not_allowed(
        mailbox.deposit(&with(2, CHARGE * 2, stretched), NOW).await
    ));

    // A capability for Dave: only a deposit Dave proves is his.
    let for_dave = capability(&w.bob_root, BOB, Some(DAVE), epoch, later);
    assert!(not_allowed(
        mailbox
            .deposit(&with(2, CHARGE * 2, for_dave.clone()), NOW)
            .await
    ));
    let carol_with_it = w.sent_by(with(2, CHARGE * 2, for_dave.clone()), &w.carol, CAROL);
    assert!(not_allowed(mailbox.deposit(&carol_with_it, NOW).await));
    let dave_with_it = w.sent_by(with(2, CHARGE * 2, for_dave), &dave, DAVE);
    mailbox
        .deposit(&dave_with_it, NOW)
        .await
        .expect("Dave with his capability");
}

#[tokio::test]
async fn a_policy_past_its_bounds_is_refused() {
    let w = World::new();
    let mailbox = w.mailbox();
    let too_many =
        DepositPolicy::Only((0..1025).map(|i| format!("did:tenzro:human:{i}")).collect());
    assert!(matches!(
        mailbox
            .set_policy(
                &auth(&w.bob_root, Action::Policy, BOB, &too_many.digest(), 1),
                &too_many,
                NOW
            )
            .await,
        Err(MailboxError::Policy(_))
    ));
}

// --- Hardening ------------------------------------------------------------

#[tokio::test]
async fn a_capability_counts_only_at_its_mailbox_under_its_policy_and_within_its_lifetime() {
    let w = World::new();
    let mailbox = w.mailbox();
    let epoch = only(&w, &mailbox, &[CAROL], 1).await;
    let with = |fill: u8, total: u128, cap: Capability| {
        let mut deposit = w.deposit(&[fill; 100], total);
        deposit.capability = Some(cap);
        deposit
    };
    let later = NOW + 60_000;

    // For another mailbox: the same capability signed over another
    // operator's key.
    let mut elsewhere = capability(&w.bob_phone, BOB, None, epoch, later);
    elsewhere.operator_key = w.carol.public_key().p256.clone();
    elsewhere.signature = w
        .bob_phone
        .sign(SignatureContext::Mailbox, &elsewhere.preimage())
        .expect("sign");
    assert!(not_allowed(
        mailbox.deposit(&with(1, CHARGE, elsewhere), NOW).await
    ));
    // Longer than the mailbox takes, or naming an empty depositor.
    let too_long = capability(
        &w.bob_phone,
        BOB,
        None,
        epoch,
        NOW + 30 * 24 * 3_600_000 + 1,
    );
    assert!(not_allowed(
        mailbox.deposit(&with(1, CHARGE, too_long), NOW).await
    ));
    let empty = capability(&w.bob_phone, BOB, Some(""), epoch, later);
    assert!(not_allowed(
        mailbox.deposit(&with(1, CHARGE, empty), NOW).await
    ));
    // Signed over the generic message context, as a wallet's "sign this
    // message" would.
    let mut generic = capability(&w.bob_phone, BOB, None, epoch, later);
    generic.signature = w
        .bob_phone
        .sign(SignatureContext::SignedMessage, &generic.preimage())
        .expect("sign");
    assert!(not_allowed(
        mailbox.deposit(&with(1, CHARGE, generic), NOW).await
    ));

    let good = capability(&w.bob_phone, BOB, None, epoch, later);
    mailbox
        .deposit(&with(1, CHARGE, good.clone()), NOW)
        .await
        .expect("the capability as given");
    // Setting the policy again ends every capability given before.
    let next = only(&w, &mailbox, &[CAROL], 2).await;
    assert_eq!(next, epoch + 1);
    assert!(not_allowed(
        mailbox.deposit(&with(2, CHARGE * 2, good), NOW).await
    ));
}

#[tokio::test]
async fn a_sender_proof_counts_only_at_its_mailbox() {
    let w = World::new();
    let mailbox = w.mailbox();
    only(&w, &mailbox, &[CAROL], 1).await;
    let mut deposit = w.deposit(&[1; 100], CHARGE);
    let elsewhere = sender_preimage(
        &w.carol.public_key().p256,
        CAROL,
        &deposit.voucher.escrow_id,
        &deposit.voucher.binding,
    );
    deposit.sender = Some(SenderProof {
        did: CAROL.to_string(),
        public_key: w.carol.public_key().p256.clone(),
        signature: w
            .carol
            .sign(SignatureContext::Mailbox, &elsewhere)
            .expect("sign"),
    });
    assert!(not_allowed(mailbox.deposit(&deposit, NOW).await));
}

#[tokio::test]
async fn a_refused_deposit_sent_again_and_again_uses_up_its_payers_allowance() {
    let w = World::new();
    let mut config = config();
    config.max_deposits_per_payer_per_hour = 3;
    let mailbox = w.mailbox_with(config);
    only(&w, &mailbox, &[CAROL], 1).await;
    let refused = w.deposit(&[1; 100], CHARGE);
    for _ in 0..3 {
        assert!(not_allowed(mailbox.deposit(&refused, NOW).await));
    }
    // The fourth attempt is stopped before the depositor is checked, and so
    // is an allowed deposit from the same payer.
    assert!(matches!(
        mailbox.deposit(&refused, NOW).await,
        Err(MailboxError::RateLimited)
    ));
    let allowed = w.sent_by(w.deposit(&[2; 100], CHARGE), &w.carol, CAROL);
    assert!(matches!(
        mailbox.deposit(&allowed, NOW).await,
        Err(MailboxError::RateLimited)
    ));
}

#[test]
fn a_sender_proof_names_the_escrow_that_pays() {
    let operator = operator_p256();
    let binding = [7u8; 32];
    assert_ne!(
        sender_preimage(&operator, CAROL, &[1; 32], &binding),
        sender_preimage(&operator, CAROL, &[2; 32], &binding)
    );
}

#[test]
fn the_claim_gas_covers_what_the_ledger_charges() {
    const { assert!(crate::CLAIM_GAS_PER_VOUCHER >= tenzro_vm::native::GAS_ESCROW_CLAIM_PER_VOUCHER) };
    for vouchers in 1..=tenzro_types::payment_authorization::MAX_VOUCHERS_PER_CLAIM {
        let charged = tenzro_vm::native::GAS_ESCROW_CLAIM_PER_VOUCHER * vouchers as u64;
        let given = crate::claim_gas(vouchers);
        assert!(given > charged, "{vouchers} vouchers");
        // Inside the ledger's ceiling for a transaction.
        assert!(given <= 30_000_000, "{vouchers} vouchers");
    }
}

/// Serves `mailbox` with `limits` on a loopback port and returns its
/// address.
async fn serve_with(mailbox: Mailbox, limits: crate::HttpLimits) -> std::net::SocketAddr {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    let router = crate::router(std::sync::Arc::new(mailbox), &limits);
    tokio::spawn(async move { crate::serve(listener, router, &limits).await });
    addr
}

#[tokio::test]
async fn a_client_that_holds_a_connection_without_sending_is_cut_off() {
    use tokio::io::AsyncReadExt as _;
    let w = World::new();
    let addr = serve_with(
        w.mailbox(),
        crate::HttpLimits {
            max_connections: 1,
            header_read_timeout: std::time::Duration::from_millis(300),
            ..crate::HttpLimits::default()
        },
    )
    .await;
    // A connection that sends nothing is closed once the header time passes.
    let mut silent = tokio::net::TcpStream::connect(addr).await.expect("connect");
    let mut rest = Vec::new();
    let closed = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        silent.read_to_end(&mut rest),
    )
    .await;
    assert!(closed.is_ok(), "the silent connection was not closed");

    // One connection at a time: a second one is closed while the first is
    // held.
    let _held = tokio::net::TcpStream::connect(addr).await.expect("connect");
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let mut second = tokio::net::TcpStream::connect(addr).await.expect("connect");
    let mut buf = [0u8; 1];
    let read = tokio::time::timeout(std::time::Duration::from_secs(2), second.read(&mut buf))
        .await
        .expect("closed at once");
    assert!(matches!(read, Ok(0) | Err(_)));
}

#[tokio::test]
async fn a_mailbox_at_its_limit_of_requests_answers_busy() {
    let w = World::new();
    let addr = serve_with(
        w.mailbox(),
        crate::HttpLimits {
            max_in_flight: 0,
            ..crate::HttpLimits::default()
        },
    )
    .await;
    let answer = reqwest::Client::new()
        .post(format!("http://{addr}/mailbox/v1/deposit"))
        .json(&w.deposit(&sealed(), CHARGE))
        .send()
        .await
        .expect("send");
    assert_eq!(answer.status(), reqwest::StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn a_failure_reading_the_ledger_does_not_tell_the_caller_where_the_node_is() {
    let w = World::new();
    let mailbox = Mailbox::open(
        config(),
        w.dir.path(),
        std::sync::Arc::new(crate::RpcLedger::new("http://127.0.0.1:1/secret-path")),
        w.operator.clone(),
        NOW,
    )
    .expect("open");
    let addr = serve_with(mailbox, crate::HttpLimits::default()).await;
    let answer = reqwest::Client::new()
        .post(format!("http://{addr}/mailbox/v1/deposit"))
        .json(&w.deposit(&sealed(), CHARGE))
        .send()
        .await
        .expect("send");
    assert_eq!(answer.status(), reqwest::StatusCode::BAD_GATEWAY);
    let text = answer.text().await.expect("text");
    assert!(
        !text.contains("127.0.0.1") && !text.contains("secret-path"),
        "{text}"
    );
}

#[tokio::test]
async fn a_node_that_answers_with_another_escrow_or_too_much_is_refused() {
    let w = World::new();
    let other = FakeNode {
        escrow: Some(serde_json::json!({
            "escrow_id": format!("0x{}", hex::encode([9u8; 32])),
            "payer": "0x00", "payee": "0x00", "amount": "1", "claimed": "0",
            "status": "Funded", "expires_at": NOW,
        })),
        ..FakeNode::default()
    };
    assert!(matches!(
        serve_node(other).await.escrow(&ESCROW).await,
        Err(MailboxError::Ledger(_))
    ));
    let huge = FakeNode {
        document: Some(serde_json::json!({ "pad": "x".repeat(300 * 1024) })),
        ..FakeNode::default()
    };
    assert!(matches!(
        serve_node(huge)
            .await
            .did_key(BOB, &w.bob_root.public_key().p256)
            .await,
        Err(MailboxError::Ledger(_))
    ));
}

// --- Key packages -----------------------------------------------------------

/// A fetch of one of Bob's key packages whose voucher promises `total`.
fn fetch(w: &World, nonce: u8, total: u128) -> crate::PrekeyFetch {
    let nonce = [nonce; 16];
    crate::PrekeyFetch {
        recipient_did: BOB.to_string(),
        nonce,
        voucher: w.voucher_by(
            &w.payer,
            total,
            crate::fetch_binding(&operator_p256(), BOB, &nonce),
        ),
    }
}

/// Bob uploads `packages` and `last`, signed by his phone.
async fn upload(
    w: &World,
    mailbox: &Mailbox,
    packages: &[Vec<u8>],
    last: Option<&[u8]>,
    nonce: u8,
) -> Result<usize, MailboxError> {
    let digest = crate::prekeys_digest(packages, last);
    mailbox
        .upload_prekeys(
            &auth(&w.bob_phone, Action::Prekeys, BOB, &digest, nonce),
            packages,
            last,
            NOW,
        )
        .await
}

const PRICE: u128 = RATE * 16 * 1024;

#[tokio::test]
async fn each_paid_fetch_gets_its_own_package_then_the_last_resort_one() {
    let w = World::new();
    let mailbox = w.mailbox();
    let packages = vec![vec![1u8; 1500], vec![2u8; 1500]];
    assert_eq!(
        upload(&w, &mailbox, &packages, Some(&[9u8; 1500]), 1)
            .await
            .expect("upload"),
        2
    );

    let first = mailbox
        .fetch_prekey(&fetch(&w, 1, PRICE), NOW)
        .await
        .expect("first");
    assert_eq!((first.package, first.last_resort), (vec![1u8; 1500], false));
    let second = mailbox
        .fetch_prekey(&fetch(&w, 2, PRICE * 2), NOW)
        .await
        .expect("second");
    assert_eq!(second.package, vec![2u8; 1500]);
    // None left: the last-resort package, which stays.
    for (nonce, total) in [(3u8, PRICE * 3), (4, PRICE * 4)] {
        let last = mailbox
            .fetch_prekey(&fetch(&w, nonce, total), NOW)
            .await
            .expect("last resort");
        assert_eq!((last.package, last.last_resort), (vec![9u8; 1500], true));
    }
    assert_eq!(mailbox.due().expect("due")[0].charged, PRICE * 4);

    // The same request again: the same package, nothing more charged.
    let again = mailbox
        .fetch_prekey(&fetch(&w, 1, PRICE), NOW + 10)
        .await
        .expect("again");
    assert_eq!(again.package, vec![1u8; 1500]);
    assert_eq!(mailbox.due().expect("due")[0].charged, PRICE * 4);
}

#[tokio::test]
async fn a_fetch_that_is_not_paid_or_not_bound_to_it_is_refused() {
    let w = World::new();
    let mailbox = w.mailbox();
    upload(&w, &mailbox, &[vec![1u8; 100]], None, 1)
        .await
        .expect("upload");
    assert!(unpaid_prekey(
        mailbox.fetch_prekey(&fetch(&w, 1, PRICE - 1), NOW).await
    ));
    // A voucher for another request, recipient or mailbox.
    let mut other_nonce = fetch(&w, 1, PRICE);
    other_nonce.nonce = [2; 16];
    assert!(unpaid_prekey(mailbox.fetch_prekey(&other_nonce, NOW).await));
    let mut other_recipient = fetch(&w, 1, PRICE);
    other_recipient.recipient_did = CAROL.to_string();
    assert!(unpaid_prekey(
        mailbox.fetch_prekey(&other_recipient, NOW).await
    ));
    let elsewhere = crate::PrekeyFetch {
        recipient_did: BOB.to_string(),
        nonce: [1; 16],
        voucher: w.voucher_by(
            &w.payer,
            PRICE,
            crate::fetch_binding(&w.carol.public_key().p256, BOB, &[1; 16]),
        ),
    };
    assert!(unpaid_prekey(mailbox.fetch_prekey(&elsewhere, NOW).await));
    // Nothing was handed out.
    assert_eq!(
        mailbox
            .fetch_prekey(&fetch(&w, 1, PRICE), NOW)
            .await
            .expect("paid")
            .package,
        vec![1u8; 100]
    );
    // A recipient with no packages at all: nothing to hand out, nothing
    // charged.
    let mut nobody = fetch(&w, 5, PRICE * 2);
    nobody.recipient_did = CAROL.to_string();
    nobody.voucher = w.voucher_by(
        &w.payer,
        PRICE * 2,
        crate::fetch_binding(&operator_p256(), CAROL, &[5; 16]),
    );
    assert!(matches!(
        mailbox.fetch_prekey(&nobody, NOW).await,
        Err(MailboxError::NotFound)
    ));
    assert_eq!(mailbox.due().expect("due")[0].charged, PRICE);
}

fn unpaid_prekey(result: Result<crate::Prekey, MailboxError>) -> bool {
    matches!(result, Err(MailboxError::Unpaid(_)))
}

#[tokio::test]
async fn a_recipients_packages_cannot_be_drained_to_its_last_resort_one() {
    let w = World::new();
    let mut limited = config();
    limited.max_fetches_per_recipient_per_hour = 2;
    let mailbox = w.mailbox_with(limited);
    let packages: Vec<Vec<u8>> = (1..=5u8).map(|n| vec![n; 100]).collect();
    upload(&w, &mailbox, &packages, Some(&[9u8; 100]), 1)
        .await
        .expect("upload");

    // Whoever pays, two packages an hour.
    for (nonce, total) in [(1u8, PRICE), (2, PRICE * 2)] {
        assert!(
            !mailbox
                .fetch_prekey(&fetch(&w, nonce, total), NOW)
                .await
                .expect("within the hour's share")
                .last_resort
        );
    }
    for (nonce, total) in [(3u8, PRICE * 3), (4, PRICE * 3)] {
        assert!(matches!(
            mailbox.fetch_prekey(&fetch(&w, nonce, total), NOW).await,
            Err(MailboxError::RateLimited)
        ));
    }
    // The rest is still there an hour later, oldest first.
    let later = NOW + 3_600_000;
    assert_eq!(
        mailbox
            .fetch_prekey(&fetch(&w, 3, PRICE * 3), later)
            .await
            .expect("an hour later")
            .package,
        vec![3u8; 100]
    );
    // The hourly share outlives a restart.
    drop(mailbox);
    let mut limited = config();
    limited.max_fetches_per_recipient_per_hour = 2;
    let mailbox = Mailbox::open(
        limited,
        w.dir.path(),
        w.ledger.clone(),
        w.operator.clone(),
        later,
    )
    .expect("open");
    mailbox
        .fetch_prekey(&fetch(&w, 4, PRICE * 4), later)
        .await
        .expect("the second of this hour");
    assert!(matches!(
        mailbox.fetch_prekey(&fetch(&w, 5, PRICE * 5), later).await,
        Err(MailboxError::RateLimited)
    ));
}

#[tokio::test]
async fn only_the_recipient_uploads_its_packages_within_the_bounds() {
    let w = World::new();
    let mut limited = config();
    limited.max_prekeys_per_recipient = 3;
    let mailbox = w.mailbox_with(limited);
    let packages = vec![vec![1u8; 10], vec![2u8; 10]];
    let digest = crate::prekeys_digest(&packages, None);
    assert!(unauthorized(
        mailbox
            .upload_prekeys(
                &auth(&w.carol, Action::Prekeys, BOB, &digest, 1),
                &packages,
                None,
                NOW
            )
            .await
    ));
    // Bob's signature over other packages.
    assert!(unauthorized(
        mailbox
            .upload_prekeys(
                &auth(&w.bob_root, Action::Prekeys, BOB, &digest, 2),
                &[vec![3u8; 10]],
                None,
                NOW
            )
            .await
    ));
    for bad in [vec![], vec![0u8; config().max_prekey_bytes + 1]] {
        assert!(matches!(
            upload(&w, &mailbox, &[bad], None, 3).await,
            Err(MailboxError::Prekeys(_))
        ));
    }
    assert_eq!(
        upload(&w, &mailbox, &packages, None, 4)
            .await
            .expect("upload"),
        2
    );
    assert!(matches!(
        upload(&w, &mailbox, &packages, None, 5).await,
        Err(MailboxError::Prekeys(_))
    ));
}

#[tokio::test]
async fn key_packages_go_over_http() {
    let w = World::new();
    w.ledger
        .escrows
        .lock()
        .get_mut(&ESCROW)
        .expect("escrow")
        .expires_at_ms = now() + 86_400_000;
    let url = serve(w.mailbox()).await;
    let http = reqwest::Client::new();
    use base64::Engine as _;
    let b64 = |b: &[u8]| base64::engine::general_purpose::STANDARD.encode(b);
    let packages = vec![vec![1u8; 100]];
    let at = now();
    let upload = serde_json::json!({
        "auth": auth_at(&w.bob_phone, Action::Prekeys, BOB, &crate::prekeys_digest(&packages, Some(&[9u8; 100])), 1, at),
        "packages": [b64(&packages[0])],
        "last_resort": b64(&[9u8; 100]),
    });
    let held: serde_json::Value = http
        .post(format!("{url}/prekeys/upload"))
        .json(&upload)
        .send()
        .await
        .expect("upload")
        .json()
        .await
        .expect("json");
    assert_eq!(held["held"], 1);
    let got: serde_json::Value = http
        .post(format!("{url}/prekeys/fetch"))
        .json(&fetch(&w, 1, PRICE))
        .send()
        .await
        .expect("fetch")
        .json()
        .await
        .expect("json");
    assert_eq!(got["package"], b64(&packages[0]));
    assert_eq!(got["last_resort"], false);
}

#[tokio::test]
async fn ledger_reads_for_unchecked_vouchers_are_bounded() {
    let w = World::new();
    let mut config = config();
    config.max_voucher_lookups_per_escrow_per_minute = 2;
    config.max_voucher_lookups_per_minute = 3;
    let mailbox = w.mailbox_with(config);
    let forged = |escrow: u8| {
        let mut deposit = w.deposit(&sealed(), CHARGE);
        deposit.voucher.escrow_id = [escrow; 32];
        deposit
    };
    for _ in 0..2 {
        assert!(unpaid(mailbox.deposit(&forged(1), NOW).await));
    }
    assert!(matches!(
        mailbox.deposit(&forged(1), NOW).await,
        Err(MailboxError::RateLimited)
    ));
    assert!(unpaid(mailbox.deposit(&forged(2), NOW).await));
    // Three reads in the minute are spent, whatever escrow asks.
    assert!(matches!(
        mailbox.deposit(&forged(3), NOW + 1).await,
        Err(MailboxError::RateLimited)
    ));
    // A minute later the reads are counted afresh.
    assert!(unpaid(mailbox.deposit(&forged(3), NOW + 60_001).await));
}

#[tokio::test]
async fn the_keys_and_policies_kept_for_all_recipients_are_bounded_across_a_restart() {
    let w = World::new();
    let mut limited = config();
    limited.max_key_bytes_total = 25;
    let packages = vec![vec![1u8; 10], vec![2u8; 10]];
    {
        let mailbox = w.mailbox_with(limited.clone());
        assert_eq!(
            upload(&w, &mailbox, &packages, None, 1)
                .await
                .expect("upload"),
            2
        );
    }
    let mailbox = w.mailbox_with(limited);
    assert!(matches!(
        upload(&w, &mailbox, &[vec![3u8; 10]], None, 2).await,
        Err(MailboxError::Full)
    ));
    assert_eq!(
        upload(&w, &mailbox, &[vec![3u8; 5]], None, 3)
            .await
            .expect("fits"),
        3
    );
}

// --- The client ---------------------------------------------------------------

#[tokio::test]
async fn a_sender_and_a_recipient_go_through_the_client() {
    let w = World::new();
    w.ledger
        .escrows
        .lock()
        .get_mut(&ESCROW)
        .expect("escrow")
        .expires_at_ms = now() + 86_400_000;
    let url = serve(w.mailbox()).await;
    let base = url.trim_end_matches("/mailbox/v1").to_string();
    let client =
        crate::MailboxClient::new(&base, w.operator.public_key().clone(), terms()).expect("client");
    let info = client.info().await.expect("info");
    assert_eq!(crate::size_class_for(70, &info.size_classes), Some(100));

    // Bob takes mail only from Carol, and gives Dave-less bearers nothing.
    let epoch = client
        .set_policy(
            &w.bob_phone,
            BOB,
            &DepositPolicy::Only([CAROL.to_string()].into()),
        )
        .await
        .expect("policy");
    let refused = client
        .deposit(
            &w.payer,
            crate::DepositRequest {
                escrow_id: ESCROW,
                cumulative_amount: CHARGE,
                recipient_did: BOB,
                sealed: sealed(),
                lifetime_s: LIFETIME_S,
                sender: None,
                capability: None,
            },
        )
        .await;
    assert!(
        matches!(refused, Err(MailboxError::NotAllowed(_))),
        "{refused:?}"
    );
    let receipt = client
        .deposit(
            &w.payer,
            crate::DepositRequest {
                escrow_id: ESCROW,
                cumulative_amount: CHARGE,
                recipient_did: BOB,
                sealed: sealed(),
                lifetime_s: LIFETIME_S,
                sender: Some((CAROL, &w.carol)),
                capability: None,
            },
        )
        .await
        .expect("from Carol");
    let bearer = client
        .capability(&w.bob_phone, BOB, None, epoch, now() + 60_000)
        .expect("capability");
    client
        .deposit(
            &w.payer,
            crate::DepositRequest {
                escrow_id: ESCROW,
                cumulative_amount: CHARGE * 2,
                recipient_did: BOB,
                sealed: vec![7; 100],
                lifetime_s: LIFETIME_S,
                sender: None,
                capability: Some(bearer),
            },
        )
        .await
        .expect("with Bob's leave");

    let listed = client.list(&w.bob_root, BOB).await.expect("list");
    assert_eq!(listed.len(), 2);
    let collected = client
        .collect(&w.bob_phone, BOB, &receipt.id)
        .await
        .expect("collect");
    assert_eq!(collected.sealed, sealed());
    client
        .ack(&w.bob_phone, BOB, &receipt.id)
        .await
        .expect("ack");
    assert_eq!(client.list(&w.bob_root, BOB).await.expect("list").len(), 1);

    // Key packages: one for the payer, then the last-resort one.
    client
        .upload_prekeys(&w.bob_phone, BOB, &[vec![1u8; 50]], Some(&[9u8; 50]))
        .await
        .expect("upload");
    let first = client
        .fetch_prekey(&w.payer, ESCROW, CHARGE * 2 + PRICE, BOB)
        .await
        .expect("fetch");
    assert_eq!((first.package, first.last_resort), (vec![1u8; 50], false));
    let last = client
        .fetch_prekey(&w.payer, ESCROW, CHARGE * 2 + PRICE * 2, BOB)
        .await
        .expect("fetch");
    assert!(last.last_resort);

    // A client that pins another key refuses this mailbox.
    let wrong =
        crate::MailboxClient::new(&base, w.carol.public_key().clone(), terms()).expect("client");
    assert!(matches!(
        wrong.info().await,
        Err(MailboxError::Unauthorized(_))
    ));
}

#[tokio::test]
async fn a_client_signs_nothing_for_a_mailbox_outside_its_terms() {
    let w = World::new();
    let url = serve(w.mailbox()).await;
    let base = url.trim_end_matches("/mailbox/v1").to_string();
    let key = w.operator.public_key().clone();
    let client = |terms| crate::MailboxClient::new(&base, key.clone(), terms).expect("client");
    let request = |sealed: Vec<u8>, lifetime_s| crate::DepositRequest {
        escrow_id: ESCROW,
        cumulative_amount: CHARGE,
        recipient_did: BOB,
        sealed,
        lifetime_s,
        sender: None,
        capability: None,
    };
    fn refused<T>(result: Result<T, MailboxError>) -> bool {
        matches!(result, Err(MailboxError::Unauthorized(_)))
    }
    let other_chain = crate::Terms {
        chain_id: CHAIN + 1,
        ..terms()
    };
    assert!(refused(
        client(other_chain)
            .deposit(&w.payer, request(sealed(), LIFETIME_S))
            .await
    ));
    let cheap = crate::Terms {
        max_rate_per_byte_hour: RATE - 1,
        ..terms()
    };
    assert!(refused(
        client(cheap)
            .deposit(&w.payer, request(sealed(), LIFETIME_S))
            .await
    ));
    let stingy = crate::Terms {
        max_prekey_price: config().prekey_price - 1,
        ..terms()
    };
    assert!(refused(
        client(stingy)
            .fetch_prekey(&w.payer, ESCROW, PRICE, BOB)
            .await
    ));
    let within = client(terms());
    assert!(refused(
        within
            .deposit(&w.payer, request(vec![0; 70], LIFETIME_S))
            .await
    ));
    assert!(refused(
        within.deposit(&w.payer, request(sealed(), u64::MAX)).await
    ));
}

#[tokio::test]
async fn a_client_reads_no_more_than_it_expects_and_follows_no_redirect() {
    let w = World::new();
    let good = serve(w.mailbox()).await;
    let target = format!("{good}/info");
    let router = axum::Router::new()
        .route(
            "/big/mailbox/v1/info",
            axum::routing::get(|| async { vec![b'a'; 3 << 20] }),
        )
        .route(
            "/hop/mailbox/v1/info",
            axum::routing::get(move || {
                let target = target.clone();
                async move { axum::response::Redirect::temporary(&target) }
            }),
        );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind");
    let addr = listener.local_addr().expect("addr");
    tokio::spawn(async move { axum::serve(listener, router).await.expect("serve") });
    let key = w.operator.public_key().clone();
    for path in ["big", "hop"] {
        let client =
            crate::MailboxClient::new(format!("http://{addr}/{path}"), key.clone(), terms())
                .expect("client");
        assert!(
            matches!(client.info().await, Err(MailboxError::Remote(_))),
            "{path}"
        );
    }
    let base = good.trim_end_matches("/mailbox/v1");
    crate::MailboxClient::new(base, key, terms())
        .expect("client")
        .info()
        .await
        .expect("the mailbox itself answers");
}

#[test]
fn a_client_reaches_only_https_or_this_machine() {
    let key = World::new().operator.public_key().clone();
    for base in [
        "https://mbx.example.org",
        "https://203.0.113.9.example.org:8443/path",
        "https://8.8.8.8",
        "http://127.0.0.1:8095",
        "http://localhost:8095",
        "http://[::1]:8095",
    ] {
        assert!(
            crate::MailboxClient::new(base, key.clone(), terms()).is_ok(),
            "{base}"
        );
    }
    for base in [
        "http://mbx.example.org",
        "http://10.0.0.1",
        "https://10.0.0.1",
        "https://192.168.1.1",
        "https://169.254.169.254",
        "https://100.64.0.1",
        "https://0.0.0.0",
        "https://[::1]",
        "https://[fd00::1]",
        "https://[fe80::1]",
        "https://[::ffff:10.0.0.1]",
        "https://localhost",
        "ftp://mbx.example.org",
        "mbx.example.org",
    ] {
        assert!(
            crate::MailboxClient::new(base, key.clone(), terms()).is_err(),
            "{base}"
        );
        let endpoint = format!("{base}{}{}", "#key=", "00".repeat(32));
        assert!(
            crate::MailboxEntry::parse("did:tenzro:human:b#m", &endpoint).is_none(),
            "{base}"
        );
    }
}

// --- Finding a mailbox in a DID document -----------------------------------------

#[test]
fn a_published_endpoint_is_a_valid_did_service_and_reads_back() {
    let w = World::new();
    let key = w.operator.public_key().clone();
    let endpoint = crate::mailbox_endpoint("https://mbx.example.org/", &key);
    tenzro_types::validation::validate_service_endpoint_url(&endpoint).expect("valid endpoint");
    let entry = crate::MailboxEntry::parse("did:tenzro:human:b#mailbox", &endpoint).expect("entry");
    assert_eq!(entry.base, "https://mbx.example.org");
    assert_eq!(entry.key_digest, crate::operator_key_digest(&key));
    assert_ne!(
        crate::operator_key_digest(w.carol.public_key()),
        entry.key_digest
    );
}

#[test]
fn only_well_formed_mailbox_services_are_read_from_a_document() {
    let w = World::new();
    let endpoint = crate::mailbox_endpoint("https://mbx.example.org", w.operator.public_key());
    let doc = serde_json::json!({
        "id": BOB,
        "service": [
            { "id": "did:x#inbox", "type": "MessagingService", "serviceEndpoint": endpoint },
            { "id": "did:x#short", "type": crate::MAILBOX_SERVICE_TYPE, "serviceEndpoint": "https://a#key=00" },
            { "id": "did:x#nokey", "type": crate::MAILBOX_SERVICE_TYPE, "serviceEndpoint": "https://a" },
            { "id": "did:x#ws", "type": crate::MAILBOX_SERVICE_TYPE, "serviceEndpoint": endpoint.replacen("https", "wss", 1) },
            { "id": "did:x#mailbox", "type": crate::MAILBOX_SERVICE_TYPE, "serviceEndpoint": endpoint },
        ]
    });
    let found = crate::mailboxes_in(&doc);
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].id, "did:x#mailbox");
    assert!(crate::mailboxes_in(&serde_json::json!({ "id": BOB })).is_empty());
}

#[tokio::test]
async fn a_client_connects_only_to_the_key_the_document_pins() {
    let w = World::new();
    let url = serve(w.mailbox()).await;
    let base = url.trim_end_matches("/mailbox/v1").to_string();

    let pinned = crate::MailboxEntry::parse(
        "did:x#mailbox",
        &crate::mailbox_endpoint(&base, w.operator.public_key()),
    )
    .expect("entry");
    let client = crate::MailboxClient::connect(&pinned, terms())
        .await
        .expect("connect");
    assert_eq!(
        client.info().await.expect("info").operator_key,
        *w.operator.public_key()
    );

    let other = crate::MailboxEntry::parse(
        "did:x#mailbox",
        &crate::mailbox_endpoint(&base, w.carol.public_key()),
    )
    .expect("entry");
    assert!(matches!(
        crate::MailboxClient::connect(&other, terms()).await,
        Err(MailboxError::Unauthorized(_))
    ));
}

// --- Group sessions ----------------------------------------------------------------

#[cfg(feature = "mls")]
mod group {
    use super::*;
    use crate::{GroupMember, MemberPackage, Opened, VerifiedPackage};

    /// Bob, Carol and Dave, each with the key its DID document names.
    struct Three {
        w: World,
        dave: TestHybridSigner,
        bob: GroupMember,
        carol: GroupMember,
        dave_member: GroupMember,
    }

    impl Three {
        fn new() -> Self {
            let w = World::new();
            let dave = TestHybridSigner::hybrid(9);
            w.ledger
                .dids
                .lock()
                .insert(DAVE.to_string(), vec![signing_key(&dave)]);
            Self {
                w,
                dave,
                bob: GroupMember::new(BOB).expect("bob"),
                carol: GroupMember::new(CAROL).expect("carol"),
                dave_member: GroupMember::new(DAVE).expect("dave"),
            }
        }

        async fn vouched(&self, member: &GroupMember, key: &TestHybridSigner) -> VerifiedPackage {
            let bytes = member
                .package(key)
                .expect("package")
                .to_bytes()
                .expect("bytes");
            MemberPackage::from_bytes(&bytes)
                .expect("read back")
                .verify(self.w.ledger.as_ref())
                .await
                .expect("verified")
        }

        /// Bob's group with Carol and Dave in it.
        async fn group(&mut self) -> Vec<u8> {
            let id = self.bob.create().expect("create");
            let carol = self.vouched(&self.carol, &self.w.carol).await;
            let dave = self.vouched(&self.dave_member, &self.dave).await;
            let added = self.bob.add(&id, &[carol, dave]).expect("add");
            let welcome = added.welcome.expect("welcome");
            assert_eq!(self.carol.join(&welcome).expect("carol joins"), id);
            assert_eq!(self.dave_member.join(&welcome).expect("dave joins"), id);
            id
        }
    }

    #[tokio::test]
    async fn added_members_read_each_other() {
        let mut t = Three::new();
        let id = t.group().await;
        let mut members = t.bob.members(&id).expect("members");
        members.sort();
        assert_eq!(members, vec![BOB, CAROL, DAVE]);

        let sealed = t.bob.seal(&id, b"hello group").expect("seal");
        for reader in [&mut t.carol, &mut t.dave_member] {
            assert_eq!(
                reader.open(&sealed).expect("open"),
                Opened::Message {
                    group: id.clone(),
                    sender: BOB.to_string(),
                    bytes: b"hello group".to_vec(),
                }
            );
        }
        let back = t.carol.seal(&id, b"hi bob").expect("seal");
        assert!(matches!(
            t.bob.open(&back).expect("open"),
            Opened::Message { sender, .. } if sender == CAROL
        ));
    }

    /// What post-quantum keys cost on the wire: a vouched key package fits
    /// what a mailbox takes by default, and a welcome and a commit of a
    /// three-member group fit its size classes.
    #[tokio::test]
    async fn post_quantum_group_messages_fit_the_mailbox() {
        let mut t = Three::new();
        let takes = crate::MailboxConfig::new(CHAIN, RATE);
        let package = t
            .carol
            .package(&t.w.carol)
            .expect("package")
            .to_bytes()
            .expect("bytes");
        assert!(
            package.len() <= takes.max_prekey_bytes,
            "a vouched key package is {} bytes; the mailbox takes {}",
            package.len(),
            takes.max_prekey_bytes
        );

        let id = t.bob.create().expect("create");
        let carol = t.vouched(&t.carol, &t.w.carol).await;
        let dave = t.vouched(&t.dave_member, &t.dave).await;
        let added = t.bob.add(&id, &[carol, dave]).expect("add");
        let welcome = added.welcome.expect("welcome");
        let largest = *takes.size_classes.iter().max().expect("a size class") as usize;
        for (what, bytes) in [("welcome", welcome.len()), ("commit", added.commit.len())] {
            assert!(
                crate::size_class_for(bytes, &takes.size_classes).is_some(),
                "a {what} is {bytes} bytes; the largest size class is {largest}"
            );
        }
    }

    #[tokio::test]
    async fn a_key_package_must_be_vouched_for_by_its_own_did() {
        let t = Three::new();
        let package = t.carol.package(&t.w.carol).expect("package");

        // Signed by another DID's key.
        let mut stolen = package.clone();
        stolen.public_key = t.w.bob_root.public_key().p256.clone();
        assert!(matches!(
            stolen.verify(t.w.ledger.as_ref()).await,
            Err(MailboxError::Unauthorized(_))
        ));

        // Bob vouches, under his own DID, for a package naming Carol.
        let forged = MemberPackage {
            did: BOB.to_string(),
            public_key: t.w.bob_root.public_key().p256.clone(),
            signature: t
                .w
                .bob_root
                .sign(
                    SignatureContext::Mailbox,
                    &crate::member_package_preimage(BOB, &package.key_package),
                )
                .expect("sign"),
            key_package: package.key_package.clone(),
        };
        assert!(matches!(
            forged.verify(t.w.ledger.as_ref()).await,
            Err(MailboxError::Group(_))
        ));

        // A changed key package breaks the DID signature.
        let mut changed = package;
        let last = changed.key_package.len() - 1;
        changed.key_package[last] ^= 1;
        assert!(changed.verify(t.w.ledger.as_ref()).await.is_err());
    }

    #[tokio::test]
    async fn a_removed_member_reads_nothing_after() {
        let mut t = Three::new();
        let id = t.group().await;
        let removal = t.bob.remove(&id, &[DAVE]).expect("remove");
        assert!(removal.welcome.is_none());
        assert!(matches!(
            t.carol.open(&removal.commit).expect("carol applies"),
            Opened::Changed { .. }
        ));
        assert_eq!(
            t.dave_member.open(&removal.commit).expect("dave applies"),
            Opened::Removed { group: id.clone() }
        );

        let sealed = t.bob.seal(&id, b"without dave").expect("seal");
        assert!(matches!(
            t.carol.open(&sealed).expect("carol reads"),
            Opened::Message { .. }
        ));
        assert!(matches!(
            t.dave_member.open(&sealed),
            Err(MailboxError::Group(_))
        ));
        let mut members = t.carol.members(&id).expect("members");
        members.sort();
        assert_eq!(members, vec![BOB, CAROL]);
        assert!(matches!(
            t.bob.remove(&id, &[DAVE]),
            Err(MailboxError::Group(_))
        ));
    }

    #[tokio::test]
    async fn a_key_update_moves_every_member_to_the_next_epoch() {
        let mut t = Three::new();
        let id = t.group().await;
        let before = t.bob.epoch(&id).expect("epoch");

        let update = t.carol.update(&id).expect("update");
        assert_eq!(t.carol.epoch(&id).expect("epoch"), before + 1);
        for member in [&mut t.bob, &mut t.dave_member] {
            assert_eq!(
                member.open(&update.commit).expect("apply"),
                Opened::Changed {
                    group: id.clone(),
                    epoch: before + 1,
                }
            );
        }
        // The same commit again is refused.
        assert!(t.bob.open(&update.commit).is_err());

        let after = t.carol.seal(&id, b"after the update").expect("seal");
        for reader in [&mut t.bob, &mut t.dave_member] {
            assert!(matches!(
                reader.open(&after).expect("open"),
                Opened::Message { bytes, .. } if bytes == b"after the update"
            ));
        }
    }
}

// --- Shared files --------------------------------------------------------------------

#[cfg(feature = "files")]
mod files {
    use super::*;
    use crate::{RecipientCard, VerifiedRecipient};
    use tenzro_crypto::hybrid_seal::HybridSecretKey;

    /// Bob shares with Carol and Dave, each with a file key and the DID key
    /// its document names.
    struct Sharing {
        w: World,
        dave: TestHybridSigner,
        carol_key: HybridSecretKey,
        dave_key: HybridSecretKey,
    }

    impl Sharing {
        fn new() -> Self {
            let w = World::new();
            let dave = TestHybridSigner::hybrid(9);
            w.ledger
                .dids
                .lock()
                .insert(DAVE.to_string(), vec![signing_key(&dave)]);
            Self {
                w,
                dave,
                carol_key: HybridSecretKey::generate(),
                dave_key: HybridSecretKey::generate(),
            }
        }

        async fn recipients(&self) -> Vec<VerifiedRecipient> {
            let mut out = Vec::new();
            for card in [
                RecipientCard::new(CAROL, self.carol_key.public(), &self.w.carol).expect("card"),
                RecipientCard::new(DAVE, self.dave_key.public(), &self.dave).expect("card"),
            ] {
                let json = serde_json::to_vec(&card).expect("json");
                let card: RecipientCard = serde_json::from_slice(&json).expect("read back");
                out.push(card.verify(self.w.ledger.as_ref()).await.expect("verified"));
            }
            out
        }
    }

    #[tokio::test]
    async fn every_recipient_opens_a_shared_file_and_checks_its_manifest() {
        let t = Sharing::new();
        let content = b"the quarterly figures".repeat(200);
        let shared =
            crate::share(&content, &t.recipients().await, BOB, &t.w.bob_root).expect("share");
        assert_eq!(shared.manifest.recipients, vec![CAROL, DAVE]);

        // Padded to a size class on its way through a mailbox.
        let mut padded = shared.sealed.clone();
        padded.resize(16 * 1024, 0);
        for key in [&t.carol_key, &t.dave_key] {
            assert_eq!(
                *crate::open_file(&padded, &shared.manifest, key, t.w.ledger.as_ref())
                    .await
                    .expect("open"),
                content
            );
        }

        // An outsider opens nothing; a changed file fails its manifest.
        assert!(
            crate::open_file(
                &padded,
                &shared.manifest,
                &HybridSecretKey::generate(),
                t.w.ledger.as_ref()
            )
            .await
            .is_err()
        );
        let mut changed = shared.sealed.clone();
        let last = changed.len() - 1;
        changed[last] ^= 1;
        assert!(
            shared
                .manifest
                .verify(&changed, t.w.ledger.as_ref())
                .await
                .is_err()
        );
        assert!(
            crate::open_file(
                &changed,
                &shared.manifest,
                &t.carol_key,
                t.w.ledger.as_ref()
            )
            .await
            .is_err()
        );
    }

    #[tokio::test]
    async fn a_file_key_must_be_vouched_for_by_its_own_did() {
        let t = Sharing::new();
        let mut stolen = RecipientCard::new(CAROL, t.dave_key.public(), &t.dave).expect("card");
        assert!(matches!(
            stolen.verify(t.w.ledger.as_ref()).await,
            Err(MailboxError::Unauthorized(_))
        ));
        stolen.key.truncate(10);
        assert!(stolen.verify(t.w.ledger.as_ref()).await.is_err());

        // A manifest signed by a key that is not the sharer's.
        let mut shared =
            crate::share(b"x", &t.recipients().await, BOB, &t.w.bob_root).expect("share");
        shared.manifest.sharer = CAROL.to_string();
        assert!(matches!(
            shared
                .manifest
                .verify(&shared.sealed, t.w.ledger.as_ref())
                .await,
            Err(MailboxError::Unauthorized(_))
        ));
    }

    #[tokio::test]
    async fn a_recipient_taken_off_cannot_open_the_file_shared_again() {
        let t = Sharing::new();
        let recipients = t.recipients().await;
        let first = crate::share(b"plans", &recipients, BOB, &t.w.bob_root).expect("share");
        let carol_only: Vec<VerifiedRecipient> = recipients
            .into_iter()
            .filter(|r| r.did() == CAROL)
            .collect();
        let again = crate::reshare(
            &first,
            &t.carol_key,
            &carol_only,
            BOB,
            &t.w.bob_root,
            t.w.ledger.as_ref(),
        )
        .await
        .expect("reshare");
        assert_eq!(again.manifest.recipients, vec![CAROL]);
        assert_eq!(
            *crate::open_file(
                &again.sealed,
                &again.manifest,
                &t.carol_key,
                t.w.ledger.as_ref()
            )
            .await
            .expect("open"),
            b"plans"
        );
        assert!(
            crate::open_file(
                &again.sealed,
                &again.manifest,
                &t.dave_key,
                t.w.ledger.as_ref()
            )
            .await
            .is_err()
        );
        // A manifest the sharer did not sign for this file opens nothing.
        let mut forged = again.manifest.clone();
        forged.file_sha256[0] ^= 1;
        assert!(
            crate::open_file(&again.sealed, &forged, &t.carol_key, t.w.ledger.as_ref())
                .await
                .is_err()
        );
        assert!(crate::share(b"x", &[], BOB, &t.w.bob_root).is_err());
    }
}

// --- Recipients addressed by tag -------------------------------------------------------

#[tokio::test]
async fn a_recipient_addressed_by_tag_collects_with_the_tag_key_alone() {
    let w = World::new();
    w.ledger
        .escrows
        .lock()
        .get_mut(&ESCROW)
        .expect("escrow")
        .expires_at_ms = now() + 86_400_000;
    let url = serve(w.mailbox()).await;
    let base = url.trim_end_matches("/mailbox/v1").to_string();
    let client =
        crate::MailboxClient::new(&base, w.operator.public_key().clone(), terms()).expect("client");

    // This epoch's tag key: no DID document names it.
    let tag_key = TestHybridSigner::hybrid(21);
    let tag = crate::recipient_tag(tag_key.public_key()).expect("a hybrid key has a tag");
    assert!(tag.starts_with(crate::TAG_PREFIX));
    assert_ne!(
        crate::recipient_tag(TestHybridSigner::hybrid(22).public_key()),
        Some(tag.clone())
    );
    assert_eq!(crate::recipient_tag(w.bob_phone.public_key()), None);

    let receipt = client
        .deposit(
            &w.payer,
            crate::DepositRequest {
                escrow_id: ESCROW,
                cumulative_amount: CHARGE,
                recipient_did: &tag,
                sealed: sealed(),
                lifetime_s: LIFETIME_S,
                sender: None,
                capability: None,
            },
        )
        .await
        .expect("deposit for the tag");
    assert_eq!(receipt.recipient_did, tag);

    // Another key, even a DID's own, does not act for the tag.
    for other in [&w.bob_root, &TestHybridSigner::hybrid(22)] {
        assert!(matches!(
            client.list(other, &tag).await,
            Err(MailboxError::Unauthorized(_))
        ));
    }
    let listed = client.list(&tag_key, &tag).await.expect("list");
    assert_eq!(listed.len(), 1);
    let got = client
        .collect(&tag_key, &tag, &receipt.id)
        .await
        .expect("collect");
    assert_eq!(got.sealed, sealed());
    client.ack(&tag_key, &tag, &receipt.id).await.expect("ack");
    assert!(client.list(&tag_key, &tag).await.expect("list").is_empty());

    // The tag's own policy and capabilities work as a DID's do.
    let epoch = client
        .set_policy(
            &tag_key,
            &tag,
            &DepositPolicy::Only([CAROL.to_string()].into()),
        )
        .await
        .expect("policy");
    let bearer = client
        .capability(&tag_key, &tag, None, epoch, now() + 60_000)
        .expect("capability");
    client
        .deposit(
            &w.payer,
            crate::DepositRequest {
                escrow_id: ESCROW,
                cumulative_amount: CHARGE * 2,
                recipient_did: &tag,
                sealed: vec![7; 100],
                lifetime_s: LIFETIME_S,
                sender: None,
                capability: Some(bearer),
            },
        )
        .await
        .expect("a bearer of the tag's capability deposits");
}

#[test]
fn only_the_key_a_tag_names_acts_for_it() {
    let key = TestHybridSigner::hybrid(21);
    let tag = crate::recipient_tag(key.public_key()).expect("tag");
    let bytes = crate::tag_key_bytes(key.public_key());
    assert_eq!(
        crate::wire::tag_key(&tag, &bytes).as_ref(),
        Some(key.public_key())
    );
    // The P-256 half alone, another key's bytes, or a DID instead of a tag.
    assert!(crate::wire::tag_key(&tag, &key.public_key().p256).is_none());
    let other = crate::tag_key_bytes(TestHybridSigner::hybrid(22).public_key());
    assert!(crate::wire::tag_key(&tag, &other).is_none());
    assert!(crate::wire::tag_key(BOB, &bytes).is_none());
}

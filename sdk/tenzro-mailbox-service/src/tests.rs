use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use sha2::{Digest, Sha256};
use tenzro_crypto::testing::TestHybridSigner;
use tenzro_crypto::{HybridSigner, SignatureContext};
use tenzro_mailbox::{
    Deposit, EscrowView, Ledger, Mailbox, MailboxConfig, MailboxError, SigningKey, deposit_binding,
};
use tenzro_types::payment_authorization::{EscrowVoucher, escrow_voucher_preimage};

use tenzro_sdk::typed_tx::TypedTransaction;

use crate::{Claimer, Submit, due_claims};

const CHAIN: u64 = 13380;
const NOW: u64 = 1_800_000_000_000;
const RECIPIENT: &str = "did:tenzro:human:bob";

/// Escrows by id; the payer's key acts for its own account.
struct FakeLedger {
    payer: TestHybridSigner,
    escrows: Mutex<HashMap<[u8; 32], EscrowView>>,
}

#[async_trait]
impl Ledger for FakeLedger {
    async fn account_key(
        &self,
        public_key: &[u8],
        account: &[u8; 32],
    ) -> Result<Option<SigningKey>, MailboxError> {
        let key = self.payer.public_key();
        Ok(
            (key.p256 == public_key && key.account_slot() == *account).then(|| SigningKey {
                key: key.clone(),
                rp_id: None,
            }),
        )
    }

    async fn did_key(&self, _: &str, _: &[u8]) -> Result<Option<SigningKey>, MailboxError> {
        Ok(None)
    }

    async fn escrow(&self, escrow_id: &[u8; 32]) -> Result<Option<EscrowView>, MailboxError> {
        Ok(self.escrows.lock().expect("lock").get(escrow_id).cloned())
    }
}

/// A deposit of a 1 KiB message for one hour under escrow `escrow_id`,
/// whose voucher promises `total`.
fn deposit(payer: &TestHybridSigner, escrow_id: [u8; 32], fill: u8, total: u128) -> Deposit {
    let sealed = vec![fill; 1024];
    let sha: [u8; 32] = Sha256::digest(&sealed).into();
    let binding = deposit_binding(RECIPIENT, &sha, 3600);
    let message = escrow_voucher_preimage(CHAIN, &escrow_id, total, &binding);
    Deposit {
        recipient_did: RECIPIENT.to_string(),
        sealed,
        lifetime_s: 3600,
        voucher: EscrowVoucher {
            escrow_id,
            cumulative_amount: total,
            binding,
            public_key: payer.public_key().p256.clone(),
            signature: payer
                .sign(SignatureContext::EscrowVoucher, &message)
                .expect("sign"),
            agent: None,
            attribution: None,
        },
        sender: None,
        capability: None,
    }
}

/// Refuses any claim transaction that names one of `refused`, and records
/// how many claims each accepted transaction carried.
#[derive(Default)]
struct FakeSubmit {
    refused: Vec<[u8; 32]>,
    accepted: Mutex<Vec<usize>>,
}

impl Submit for FakeSubmit {
    async fn submit(&self, tx: &TypedTransaction) -> anyhow::Result<()> {
        let claims = tx.fields["claims"].as_array().expect("claims");
        let names_refused = claims.iter().any(|c| {
            let id = c["voucher"]["escrow_id"].as_str().expect("escrow id");
            self.refused
                .iter()
                .any(|r| hex::encode(r) == id.trim_start_matches("0x"))
        });
        if names_refused {
            anyhow::bail!("the ledger refused the claim");
        }
        assert_eq!(tx.gas_limit, tenzro_mailbox::claim_gas(claims.len()));
        self.accepted.lock().expect("lock").push(claims.len());
        Ok(())
    }
}

/// An operator's mailbox holding one 1 KiB message for each of the escrows
/// 1..=`escrows`, each charged 1024 wei.
async fn charged_mailbox(
    escrows: u8,
) -> (
    Arc<FakeLedger>,
    Mailbox,
    tempfile::TempDir,
    TestHybridSigner,
) {
    let operator = Arc::new(TestHybridSigner::hybrid(1));
    let payer = TestHybridSigner::hybrid(2);
    let escrow = || EscrowView {
        payer: payer.public_key().account_slot(),
        payee: operator.public_key().account_slot(),
        amount: 1_000_000_000,
        claimed: 0,
        expires_at_ms: NOW + 86_400_000,
    };
    let ledger = Arc::new(FakeLedger {
        payer: TestHybridSigner::hybrid(2),
        escrows: Mutex::new((1..=escrows).map(|id| ([id; 32], escrow())).collect()),
    });
    let dir = tempfile::tempdir().expect("dir");
    let mut config = MailboxConfig::new(CHAIN, 1);
    config.max_deposits_per_payer_per_hour = 100;
    let mailbox = Mailbox::open(config, dir.path(), ledger.clone(), operator, NOW).expect("open");
    for id in 1..=escrows {
        mailbox
            .deposit(&deposit(&payer, [id; 32], id, 1024), NOW)
            .await
            .expect("deposit");
    }
    (ledger, mailbox, dir, payer)
}

#[tokio::test]
async fn only_open_escrows_that_still_owe_and_do_not_end_soon_are_claimed() {
    let (ledger, mailbox, _dir, _) = charged_mailbox(4).await;
    {
        let mut escrows = ledger.escrows.lock().expect("lock");
        // Escrow 1 was claimed in full, escrow 2 is closed, escrow 3 ends
        // inside the margin.
        escrows.get_mut(&[1; 32]).expect("1").claimed = 1024;
        escrows.remove(&[2; 32]);
        escrows.get_mut(&[3; 32]).expect("3").expires_at_ms = NOW + 3_600_000;
    }
    let claims = due_claims(mailbox.due().expect("due"), ledger.as_ref(), NOW, 3_600_000)
        .await
        .expect("claims");
    assert_eq!(claims.len(), 1);
    assert_eq!(claims[0].voucher.escrow_id, [4; 32]);
    assert_eq!(
        (claims[0].amount, claims[0].voucher.cumulative_amount),
        (1024, 1024)
    );
}

#[tokio::test]
async fn one_claim_the_ledger_refuses_does_not_hold_back_the_others() {
    let (ledger, mailbox, _dir, _) = charged_mailbox(34).await;
    let claims = || async {
        due_claims(mailbox.due().expect("due"), ledger.as_ref(), NOW, 3_600_000)
            .await
            .expect("claims")
    };
    let submit = FakeSubmit {
        refused: vec![[5; 32]],
        ..FakeSubmit::default()
    };
    let mut claimer = Claimer::default();

    // 34 claims: a batch of 32 with the refused one, then a batch of 2. The
    // first batch is refused, and its claims go one by one.
    assert_eq!(claimer.claim(claims().await, &submit, NOW).await, 33);
    let mut accepted = submit.accepted.lock().expect("lock").clone();
    accepted.sort();
    assert_eq!(accepted, [vec![1; 31], vec![2]].concat());

    // The refused claim waits ten minutes, then twice as long after each
    // refusal.
    submit.accepted.lock().expect("lock").clear();
    let refused = vec![
        claims()
            .await
            .into_iter()
            .find(|c| c.voucher.escrow_id == [5; 32])
            .expect("5"),
    ];
    assert_eq!(
        claimer.claim(refused.clone(), &submit, NOW + 599_999).await,
        0
    );
    assert_eq!(
        claimer.claim(refused.clone(), &submit, NOW + 600_000).await,
        0
    );
    assert_eq!(
        claimer
            .claim(refused.clone(), &submit, NOW + 600_000 + 1_199_999)
            .await,
        0
    );
    assert!(submit.accepted.lock().expect("lock").is_empty());
    // Once the ledger takes it, it is claimed.
    let taking = FakeSubmit::default();
    assert_eq!(
        claimer
            .claim(refused, &taking, NOW + 600_000 + 1_200_000)
            .await,
        1
    );
}

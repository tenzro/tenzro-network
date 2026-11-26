//! A fee payer's consent to pay one transaction's fee, carried in the
//! transaction's memo.
//!
//! A transaction names the account that pays its fee by carrying that
//! account's consent in its memo: the fixed prefix [`MEMO_PREFIX`], then the
//! payer's account, its P-256 public key and its signature, hex, separated by
//! `:`. The memo is part of the transaction hash, so the sender's signature
//! covers the payer and its consent. The payer signs first, over
//! [`consent_digest`]: the whole transaction body (chain id, sender,
//! recipient, nonce, gas limit, gas price, timestamp, expiry and action) and
//! its own account, under [`SignatureContext::FeePayer`]. Its signature
//! therefore pays for that one transaction of that sender on that chain,
//! until it expires, up to `gas_limit * gas_price`, and for nothing else.
//!
//! Nothing here changes how a transaction is encoded: a node that does not
//! apply the fee payer rule reads the memo as a memo and charges the sender.

use sha2::{Digest, Sha256};
use tenzro_types::account_signature::{ClassicalProof, CompositeSignature};
use tenzro_types::primitives::Address;
use tenzro_types::transaction::Transaction;

use crate::composite::{PqPolicy, SignatureContext, verify_classical_component};

/// What a memo that carries a fee payer's consent starts with. The trailing
/// number is the version of the layout after it.
pub const MEMO_PREFIX: &str = "tenzro-fee-payer-1:";

/// Domain tag of [`consent_digest`].
const CONSENT_DOMAIN: &[u8] = b"tenzro/fee-payer/consent/1";

/// A fee payer's consent as a memo carries it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FeePayerConsent {
    /// The account that pays the fee.
    pub fee_payer: Address,
    /// The payer's P-256 public key, `x || y`; it names the payer's account.
    pub public_key: Vec<u8>,
    /// The payer's signature over [`consent_digest`]: a raw P-256 leg and
    /// the ML-DSA-65 leg. The ledger requires both, as it does of a
    /// transaction signature of the payer's account.
    pub signature: CompositeSignature,
}

/// Why a transaction's fee payer is refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum FeePayerError {
    /// The memo starts with [`MEMO_PREFIX`] and is not a consent.
    #[error("the memo names a fee payer but is not a well-formed consent: {0}")]
    Malformed(&'static str),
    /// The payer is the sender.
    #[error("the fee payer is the sender")]
    IsSender,
    /// The key does not name the payer's account.
    #[error("the fee payer's key does not name its account")]
    WrongKey,
    /// The signature does not verify.
    #[error("the fee payer's signature does not verify: {0}")]
    BadSignature(String),
}

impl FeePayerConsent {
    /// The memo that carries this consent.
    pub fn to_memo(&self) -> Result<String, FeePayerError> {
        let ClassicalProof::Raw { signature } = &self.signature.classical else {
            return Err(FeePayerError::Malformed(
                "a fee payer signs with its P-256 key directly",
            ));
        };
        let mut memo = format!(
            "{MEMO_PREFIX}{}:{}:{}",
            hex::encode(self.fee_payer.as_bytes()),
            hex::encode(&self.public_key),
            hex::encode(signature),
        );
        if let Some(pq) = &self.signature.pq {
            memo.push(':');
            memo.push_str(&hex::encode(pq));
        }
        Ok(memo)
    }

    /// The consent `memo` carries: `None` for a memo that does not start
    /// with [`MEMO_PREFIX`], an error for one that does and is not a
    /// well-formed consent.
    pub fn from_memo(memo: &str) -> Option<Result<Self, FeePayerError>> {
        let rest = memo.strip_prefix(MEMO_PREFIX)?;
        Some(Self::parse(rest))
    }

    fn parse(rest: &str) -> Result<Self, FeePayerError> {
        let mut parts = rest.split(':');
        let mut field = |what: &'static str| {
            parts
                .next()
                .and_then(|h| hex::decode(h).ok())
                .ok_or(FeePayerError::Malformed(what))
        };
        let fee_payer: [u8; 32] = field("the payer account is not hex")?
            .try_into()
            .map_err(|_| FeePayerError::Malformed("the payer account is not 32 bytes"))?;
        let public_key = field("the payer key is not hex")?;
        if public_key.len() != 64 {
            return Err(FeePayerError::Malformed(
                "the payer key is not a 64-byte P-256 point",
            ));
        }
        let signature = field("the payer signature is not hex")?;
        if signature.len() != 64 {
            return Err(FeePayerError::Malformed(
                "the payer signature is not a 64-byte P-256 signature",
            ));
        }
        let pq = match parts.next() {
            None => None,
            Some(h) => Some(hex::decode(h).map_err(|_| {
                FeePayerError::Malformed("the payer ML-DSA-65 signature is not hex")
            })?),
        };
        if parts.next().is_some() {
            return Err(FeePayerError::Malformed("the consent has too many fields"));
        }
        Ok(Self {
            fee_payer: Address::new(fee_payer),
            public_key,
            signature: CompositeSignature {
                classical: ClassicalProof::Raw { signature },
                pq,
            },
        })
    }
}

/// The fee payer consent `tx` carries in its memo, if its memo names one and
/// its type may name one ([`may_name_fee_payer`]). The memo of any other
/// transaction is not read: its sender did not sign it.
pub fn named_in(tx: &Transaction) -> Option<Result<FeePayerConsent, FeePayerError>> {
    if !may_name_fee_payer(tx) {
        return None;
    }
    FeePayerConsent::from_memo(tx.memo.as_deref()?)
}

/// Whether a transaction of this type may name a fee payer: a native
/// transaction that owes a fee and is not a privileged action. A privileged
/// action is signed over its typed preimage, which carries no memo, and an
/// external wallet's transaction over its raw bytes, so neither sender's
/// signature covers a memo, and anyone could attach one.
pub fn may_name_fee_payer(tx: &Transaction) -> bool {
    !tx.tx_type.is_external()
        && !tx.tx_type.pays_no_fee()
        && tenzro_types::typed_action::action_class(&tx.tx_type).is_none()
}

/// What a fee payer signs to pay the fee of `tx`: SHA-256 over a domain tag,
/// the chain id, the sender, the recipient, the nonce, the gas limit, the gas
/// price, the timestamp, the expiry, the payer's account and the canonical
/// encoding of the action. Everything of the transaction but its memo, which
/// is where the signature goes.
pub fn consent_digest(tx: &Transaction, fee_payer: &Address) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(CONSENT_DOMAIN);
    h.update(tx.chain_id.0.to_le_bytes());
    h.update(tx.from.as_bytes());
    h.update(tx.to.as_bytes());
    h.update(tx.nonce.0.to_le_bytes());
    h.update(tx.gas_limit.to_le_bytes());
    h.update(tx.gas_price.to_le_bytes());
    h.update(tx.timestamp.0.to_le_bytes());
    h.update(tx.valid_until.0.to_le_bytes());
    h.update(fee_payer.as_bytes());
    if let Ok(tx_type_json) = serde_json::to_vec(&tx.tx_type) {
        h.update(&tx_type_json);
    }
    h.finalize().into()
}

/// Checks everything about the consent `tx` carries that needs no chain
/// state: the payer is another account, its key names its account, and the P-256 leg of its signature
/// verifies over [`consent_digest`] under [`SignatureContext::FeePayer`].
/// Returns the consent; the caller owes the ML-DSA-65 leg against the key the
/// payer enrolled ([`verify_pq_leg`]). `None` for a transaction whose memo
/// names no payer.
pub fn verify_classical(tx: &Transaction) -> Option<Result<FeePayerConsent, FeePayerError>> {
    let consent = match named_in(tx)? {
        Ok(consent) => consent,
        Err(e) => return Some(Err(e)),
    };
    Some(check_classical(tx, consent))
}

fn check_classical(
    tx: &Transaction,
    consent: FeePayerConsent,
) -> Result<FeePayerConsent, FeePayerError> {
    if consent.fee_payer == tx.from {
        return Err(FeePayerError::IsSender);
    }
    if !crate::controls_account(&consent.public_key, consent.fee_payer.as_bytes()) {
        return Err(FeePayerError::WrongKey);
    }
    verify_classical_component(
        &consent.public_key,
        SignatureContext::FeePayer,
        &consent_digest(tx, &consent.fee_payer),
        &consent.signature.classical,
    )
    .map_err(|e| FeePayerError::BadSignature(e.to_string()))?;
    Ok(consent)
}

/// The ML-DSA-65 leg of a consent over `digest`, against `enrolled`, the key
/// the payer's account enrolled in chain state, under `policy`.
pub fn verify_pq_leg(
    enrolled: Option<&[u8]>,
    digest: &[u8],
    signature: &CompositeSignature,
    policy: PqPolicy,
) -> Result<(), FeePayerError> {
    crate::composite::verify_pq_component(
        enrolled,
        SignatureContext::FeePayer,
        digest,
        signature.pq.as_deref(),
        policy,
    )
    .map(|_| ())
    .map_err(|e| FeePayerError::BadSignature(e.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::composite::HybridSigner;
    use crate::composite::testing::TestHybridSigner;
    use tenzro_types::primitives::{ChainId, Nonce, Timestamp};
    use tenzro_types::transaction::TransactionType;

    fn body(sender: &TestHybridSigner) -> Transaction {
        let mut tx = Transaction::new(
            ChainId::from(9u64),
            sender.address(),
            Address::new([2; 32]),
            Nonce::from(4),
            TransactionType::Transfer { amount: 5 },
            21_000,
            7,
        );
        tx.timestamp = Timestamp::new(1_700_000_000_000);
        tx.valid_until = Timestamp::new(1_700_000_300_000);
        tx
    }

    fn consent(payer: &TestHybridSigner, context: SignatureContext, tx: &Transaction) -> String {
        FeePayerConsent {
            fee_payer: payer.address(),
            public_key: payer.public_key().p256.clone(),
            signature: payer
                .sign(context, &consent_digest(tx, &payer.address()))
                .unwrap(),
        }
        .to_memo()
        .unwrap()
    }

    /// A consent round-trips through the memo, and its size is what the
    /// two signature legs cost in hex.
    #[test]
    fn a_consent_travels_in_the_memo() {
        let (sender, payer) = (TestHybridSigner::hybrid(1), TestHybridSigner::hybrid(2));
        let mut tx = body(&sender);
        assert!(named_in(&tx).is_none());
        tx.memo = Some("thanks".into());
        assert!(named_in(&tx).is_none());
        let memo = consent(&payer, SignatureContext::FeePayer, &tx);
        assert!(memo.starts_with(MEMO_PREFIX));
        // Prefix, 32-byte account, 64-byte key, 64-byte P-256 signature and
        // the ML-DSA-65 leg, in hex with separators: about 7 KB.
        assert!(memo.len() > 6_000 && memo.len() < 8_000, "{}", memo.len());
        tx.memo = Some(memo);
        let read = verify_classical(&tx).unwrap().unwrap();
        assert_eq!(read.fee_payer, payer.address());
        verify_pq_leg(
            payer.public_key().pq.as_deref(),
            &consent_digest(&tx, &read.fee_payer),
            &read.signature,
            PqPolicy::Required,
        )
        .unwrap();

        // The ledger requires the ML-DSA-65 leg of a payer as it does of a
        // sender: a consent without it does not pass.
        let mut classical = read.clone();
        classical.signature.pq = None;
        assert!(
            verify_pq_leg(
                payer.public_key().pq.as_deref(),
                &consent_digest(&tx, &read.fee_payer),
                &classical.signature,
                PqPolicy::default(),
            )
            .is_err()
        );
        // An account with no ML-DSA-65 key enrolled pays for nobody.
        assert!(
            verify_pq_leg(
                None,
                &consent_digest(&tx, &read.fee_payer),
                &read.signature,
                PqPolicy::default(),
            )
            .is_err()
        );
    }

    /// A memo that starts with the prefix and is not a consent is an error,
    /// never a plain memo.
    #[test]
    fn a_memo_with_the_prefix_must_be_a_consent() {
        for bad in [
            "",
            "zz",
            "00:11:22",
            &format!("{}:{}:{}", "0".repeat(64), "0".repeat(128), "0".repeat(126)),
            &format!(
                "{}:{}:{}:00:00",
                "0".repeat(64),
                "0".repeat(128),
                "0".repeat(128)
            ),
        ] {
            let memo = format!("{MEMO_PREFIX}{bad}");
            assert!(
                matches!(
                    FeePayerConsent::from_memo(&memo),
                    Some(Err(FeePayerError::Malformed(_)))
                ),
                "{bad}"
            );
        }
        assert!(FeePayerConsent::from_memo("tenzro-fee-payer-2:00").is_none());
    }

    /// The payer's signature is bound to the chain, the sender, the nonce,
    /// the expiry, the gas terms and the action, and to its own context: it
    /// pays for no other transaction.
    #[test]
    fn a_consent_pays_for_one_transaction_only() {
        let (sender, payer) = (TestHybridSigner::hybrid(1), TestHybridSigner::hybrid(2));
        let signed = body(&sender);
        let memo = consent(&payer, SignatureContext::FeePayer, &signed);
        let with_memo = |mut tx: Transaction| {
            tx.memo = Some(memo.clone());
            tx
        };
        assert!(
            verify_classical(&with_memo(signed.clone()))
                .unwrap()
                .is_ok()
        );

        let other_sender = TestHybridSigner::hybrid(5);
        let changes: [(&str, Box<dyn Fn(&mut Transaction)>); 8] = [
            ("chain id", Box::new(|t| t.chain_id = ChainId::from(10u64))),
            ("sender", Box::new(move |t| t.from = other_sender.address())),
            ("nonce", Box::new(|t| t.nonce = Nonce::from(5))),
            (
                "expiry",
                Box::new(|t| t.valid_until = Timestamp::new(t.valid_until.0 + 1)),
            ),
            ("gas limit", Box::new(|t| t.gas_limit += 1)),
            ("gas price", Box::new(|t| t.gas_price += 1)),
            ("recipient", Box::new(|t| t.to = Address::new([3; 32]))),
            (
                "action",
                Box::new(|t| t.tx_type = TransactionType::Transfer { amount: 6 }),
            ),
        ];
        for (what, change) in &changes {
            let mut tx = signed.clone();
            change(&mut tx);
            assert!(
                matches!(
                    verify_classical(&with_memo(tx)),
                    Some(Err(FeePayerError::BadSignature(_)))
                ),
                "{what}"
            );
        }

        // The payer's signature under its ordinary transaction context.
        let mut tx = signed.clone();
        tx.memo = Some(consent(&payer, SignatureContext::Transaction, &signed));
        assert!(matches!(
            verify_classical(&tx),
            Some(Err(FeePayerError::BadSignature(_)))
        ));
        // Another account's key under the payer's name.
        let stranger = TestHybridSigner::hybrid(6);
        let mut forged =
            FeePayerConsent::from_memo(&consent(&stranger, SignatureContext::FeePayer, &signed))
                .unwrap()
                .unwrap();

        forged.fee_payer = payer.address();
        let mut tx = signed.clone();
        tx.memo = Some(forged.to_memo().unwrap());
        assert_eq!(verify_classical(&tx), Some(Err(FeePayerError::WrongKey)));
        // The sender naming itself.
        let mut tx = signed.clone();
        tx.memo = Some(consent(&sender, SignatureContext::FeePayer, &signed));
        assert_eq!(verify_classical(&tx), Some(Err(FeePayerError::IsSender)));
        // The P-256 leg alone, for a payer with an ML-DSA-65 key enrolled.
        let mut classical = FeePayerConsent::from_memo(&memo).unwrap().unwrap();
        classical.signature.pq = None;
        assert!(
            verify_pq_leg(
                payer.public_key().pq.as_deref(),
                &consent_digest(&signed, &payer.address()),
                &classical.signature,
                PqPolicy::Required,
            )
            .is_err()
        );
    }

    /// A transaction whose sender's signature does not cover its memo (an
    /// external wallet's, a privileged action) names no payer: its memo is
    /// not read at all, so a memo someone attaches to it changes nothing.
    #[test]
    fn a_memo_the_sender_did_not_sign_names_no_fee_payer() {
        let (sender, payer) = (TestHybridSigner::hybrid(1), TestHybridSigner::hybrid(2));
        let mut tx = body(&sender);
        tx.tx_type = TransactionType::ExternalEvm { raw: vec![1] };
        assert!(!may_name_fee_payer(&tx));
        tx.memo = Some(consent(&payer, SignatureContext::FeePayer, &tx));
        assert!(named_in(&tx).is_none());
        assert!(verify_classical(&tx).is_none());
        tx.memo = Some(format!("{MEMO_PREFIX}garbage"));
        assert!(named_in(&tx).is_none());
        assert!(may_name_fee_payer(&body(&sender)));
    }
}

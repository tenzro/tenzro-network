//! What crosses the mailbox boundary and the exact bytes each party signs.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tenzro_crypto::{
    CompositePublicKey, CompositeSignature, PqPolicy, SignatureContext, verify_composite,
};
use tenzro_types::payment_authorization::EscrowVoucher;

use crate::error::MailboxError;

/// Domain tag at the start of every mailbox preimage.
const DOMAIN: &[u8] = b"tenzro/mailbox/v1";

pub(crate) fn tagged(part: &[u8]) -> Vec<u8> {
    let mut m = DOMAIN.to_vec();
    m.extend_from_slice(part);
    m
}

pub(crate) fn push_prefixed(m: &mut Vec<u8>, bytes: &[u8]) {
    m.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
    m.extend_from_slice(bytes);
}

/// Prefix of a recipient addressed by tag rather than by DID: `tag:` and the
/// hex SHA-256 of a composite key the recipient made for it ([`recipient_tag`]).
///
/// A recipient that wants its mailbox unlinked from its DID makes a new tag
/// key each epoch and tells its contacts the tag inside their sealed
/// conversation; the operator sees tags, not the DID. Requests for a tag are
/// signed by its key, P-256 and ML-DSA-65 both.
pub const TAG_PREFIX: &str = "tag:";

const TAG_DOMAIN: &[u8] = b"tenzro/mailbox/v1/recipient-tag";

/// The recipient tag of `key`, which must carry an ML-DSA-65 key.
pub fn recipient_tag(key: &CompositePublicKey) -> Option<String> {
    let pq = key.pq.as_ref()?;
    let mut h = Sha256::new();
    h.update(TAG_DOMAIN);
    h.update(&key.p256);
    h.update(pq);
    Some(format!("{TAG_PREFIX}{}", hex::encode(h.finalize())))
}

/// What a request for a tag carries as its `public_key`: the P-256 key
/// (`x || y`) then the ML-DSA-65 key.
pub fn tag_key_bytes(key: &CompositePublicKey) -> Vec<u8> {
    let mut out = key.p256.clone();
    out.extend_from_slice(key.pq.as_deref().unwrap_or_default());
    out
}

/// The key a request for the tag `recipient` names, when it is that tag's.
pub(crate) fn tag_key(recipient: &str, public_key: &[u8]) -> Option<CompositePublicKey> {
    if !recipient.starts_with(TAG_PREFIX) || public_key.len() <= 64 {
        return None;
    }
    let (p256, pq) = public_key.split_at(64);
    let key = CompositePublicKey::new(p256.to_vec(), Some(pq.to_vec())).ok()?;
    (recipient_tag(&key).as_deref() == Some(recipient)).then_some(key)
}

/// Bytes as base64 in JSON.
pub(crate) mod base64_bytes {
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&STANDARD.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        STANDARD
            .decode(String::deserialize(d)?)
            .map_err(serde::de::Error::custom)
    }
}

/// Bytes as hex in JSON.
pub(crate) mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        hex::decode(String::deserialize(d)?).map_err(serde::de::Error::custom)
    }
}

/// A 16-byte nonce as hex in JSON.
mod hex_nonce {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(nonce: &[u8; 16], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(nonce))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 16], D::Error> {
        hex::decode(String::deserialize(d)?)
            .ok()
            .and_then(|b| b.try_into().ok())
            .ok_or_else(|| serde::de::Error::custom("a nonce is 16 bytes of hex"))
    }
}

/// A sealed message offered for an offline recipient.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Deposit {
    /// The DID the message is held for.
    pub recipient_did: String,
    /// The message, sealed by the sender to the recipient. The mailbox never
    /// opens it. Base64 in JSON.
    #[serde(with = "base64_bytes")]
    pub sealed: Vec<u8>,
    /// How long the mailbox keeps it, in seconds.
    pub lifetime_s: u64,
    /// The payer's voucher on an escrow whose payee is the mailbox. Its
    /// `binding` is [`deposit_binding`] of this deposit, so the payer's
    /// signature authorizes this deposit and no other.
    pub voucher: EscrowVoucher,
    /// Who deposits, for a recipient that takes mail only from named DIDs.
    pub sender: Option<SenderProof>,
    /// The recipient's leave to deposit, for a recipient that takes mail
    /// only from named DIDs.
    pub capability: Option<Capability>,
}

/// Who may deposit for a recipient. The recipient sets it.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DepositPolicy {
    /// Anyone whose voucher pays.
    #[default]
    Anyone,
    /// Only these DIDs, or a depositor holding the recipient's
    /// [`Capability`].
    Only(std::collections::BTreeSet<String>),
}

impl DepositPolicy {
    /// The digest a recipient signs when it sets the policy: SHA-256 of the
    /// domain tag and of every DID it names, each prefixed with its length,
    /// hex.
    pub fn digest(&self) -> String {
        let mut m = tagged(b"/policy");
        match self {
            Self::Anyone => m.push(0),
            Self::Only(dids) => {
                m.push(1);
                for did in dids {
                    push_prefixed(&mut m, did.as_bytes());
                }
            }
        }
        hex::encode(Sha256::digest(m))
    }
}

/// What a recipient signs when it uploads key packages: SHA-256 of the
/// domain tag, the number of packages, each package prefixed with its
/// length, and the last-resort package (a zero length when none), hex.
pub fn prekeys_digest(packages: &[Vec<u8>], last_resort: Option<&[u8]>) -> String {
    let mut m = tagged(b"/prekeys");
    m.extend_from_slice(&(packages.len() as u32).to_be_bytes());
    for package in packages {
        push_prefixed(&mut m, package);
    }
    push_prefixed(&mut m, last_resort.unwrap_or_default());
    hex::encode(Sha256::digest(m))
}

/// A request for one of a recipient's key packages, paid by its voucher.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrekeyFetch {
    /// The recipient whose package is asked for.
    pub recipient_did: String,
    /// 16 random bytes the payer chose for this request, hex in JSON.
    #[serde(with = "hex_nonce")]
    pub nonce: [u8; 16],
    /// The payer's voucher; its `binding` is [`fetch_binding`] of this
    /// request.
    pub voucher: EscrowVoucher,
}

/// What a voucher's `binding` carries when it pays for one key package: the
/// mailbox's operator key, the recipient and the request's nonce.
pub fn fetch_binding(operator: &[u8], recipient_did: &str, nonce: &[u8; 16]) -> [u8; 32] {
    let mut m = tagged(b"/fetch");
    push_prefixed(&mut m, operator);
    push_prefixed(&mut m, recipient_did.as_bytes());
    m.extend_from_slice(nonce);
    Sha256::digest(m).into()
}

/// A depositor's proof that it is the DID it names: its signature over the
/// deposit's binding.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SenderProof {
    /// The depositor's DID.
    pub did: String,
    /// The P-256 key that signed (`x || y`), hex in JSON: the key the DID
    /// resolves to, or one its account's keystore links.
    #[serde(with = "hex_bytes")]
    pub public_key: Vec<u8>,
    /// Signature over [`sender_preimage`] under
    /// [`SignatureContext::Mailbox`].
    pub signature: CompositeSignature,
}

/// The bytes a depositor signs for a deposit at the mailbox whose operator
/// key is `operator`: the domain tag, the operator key and its DID each
/// prefixed with its length, the escrow that pays, and the voucher's binding
/// of the deposit. The escrow is in it so that nobody else can pay to deliver
/// the same message again under the depositor's name.
pub fn sender_preimage(
    operator: &[u8],
    did: &str,
    escrow_id: &[u8; 32],
    binding: &[u8; 32],
) -> Vec<u8> {
    let mut m = tagged(b"/sender");
    push_prefixed(&mut m, operator);
    push_prefixed(&mut m, did.as_bytes());
    m.extend_from_slice(escrow_id);
    m.extend_from_slice(binding);
    m
}

/// A recipient's signed leave to deposit for it at one mailbox: for one
/// depositor DID, or for whoever holds it, until it expires or the
/// recipient next sets its depositor policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Capability {
    /// The mailbox it is for: its operator's P-256 key (`x || y`), hex in
    /// JSON.
    #[serde(with = "hex_bytes")]
    pub operator_key: Vec<u8>,
    /// The recipient that gives it.
    pub recipient_did: String,
    /// The recipient's policy epoch it was given under: setting the policy
    /// again ends it.
    pub policy_epoch: u64,
    /// The depositor it is for, who must then prove it is that DID; any
    /// holder when absent.
    pub depositor_did: Option<String>,
    /// Unix milliseconds after which it is refused.
    pub expires_at_ms: u64,
    /// The recipient's P-256 key that signed (`x || y`), hex in JSON.
    #[serde(with = "hex_bytes")]
    pub public_key: Vec<u8>,
    /// Signature over [`Capability::preimage`] under
    /// [`SignatureContext::Mailbox`].
    pub signature: CompositeSignature,
}

impl Capability {
    /// The bytes the recipient signs: the domain tag, the operator key, the
    /// recipient and the depositor (empty for a bearer capability) each
    /// prefixed with its length, then the policy epoch and the expiry (u64
    /// big-endian each).
    pub fn preimage(&self) -> Vec<u8> {
        let mut m = tagged(b"/capability");
        push_prefixed(&mut m, &self.operator_key);
        push_prefixed(&mut m, self.recipient_did.as_bytes());
        push_prefixed(
            &mut m,
            self.depositor_did.as_deref().unwrap_or_default().as_bytes(),
        );
        m.extend_from_slice(&self.policy_epoch.to_be_bytes());
        m.extend_from_slice(&self.expires_at_ms.to_be_bytes());
        m
    }
}

/// What a voucher's `binding` carries when it pays for one deposit: the
/// recipient, the SHA-256 of the sealed bytes and the lifetime.
pub fn deposit_binding(recipient_did: &str, sealed_sha256: &[u8; 32], lifetime_s: u64) -> [u8; 32] {
    let mut m = tagged(b"/deposit");
    push_prefixed(&mut m, recipient_did.as_bytes());
    m.extend_from_slice(sealed_sha256);
    m.extend_from_slice(&lifetime_s.to_be_bytes());
    Sha256::digest(m).into()
}

/// What a recipient asks of its mailbox.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// List the messages held.
    List,
    /// Read one message.
    Collect,
    /// Confirm one message was read, which drops it.
    Ack,
    /// Set who may deposit.
    Policy,
    /// Upload key packages.
    Prekeys,
}

impl Action {
    fn as_bytes(self) -> &'static [u8] {
        match self {
            Self::List => b"list",
            Self::Collect => b"collect",
            Self::Ack => b"ack",
            Self::Policy => b"policy",
            Self::Prekeys => b"prekeys",
        }
    }
}

/// A recipient's proof that a request is its own.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Auth {
    /// The recipient DID.
    pub did: String,
    /// Unix milliseconds at signing.
    pub timestamp_ms: u64,
    /// 16 random bytes, accepted once. Hex in JSON.
    #[serde(with = "hex_nonce")]
    pub nonce: [u8; 16],
    /// The P-256 key (`x || y`) that signed: the key the DID resolves to, or
    /// one its account's keystore links. Hex in JSON.
    #[serde(with = "hex_bytes")]
    pub public_key: Vec<u8>,
    /// Signature over [`auth_preimage`] under
    /// [`SignatureContext::Mailbox`] by `public_key`.
    pub signature: CompositeSignature,
}

/// The bytes a recipient signs for `action` at the mailbox whose operator
/// key is `operator` (its P-256 key, `x || y`): the domain tag, then the
/// operator key, the action, the DID and the subject (the message id, the
/// policy digest, or empty for a list) each prefixed with its length (u32
/// big-endian), `timestamp_ms` (u64 big-endian) and `nonce`.
pub fn auth_preimage(
    operator: &[u8],
    action: Action,
    did: &str,
    entry_id: &str,
    timestamp_ms: u64,
    nonce: &[u8; 16],
) -> Vec<u8> {
    let mut m = tagged(b"/auth");
    push_prefixed(&mut m, operator);
    push_prefixed(&mut m, action.as_bytes());
    push_prefixed(&mut m, did.as_bytes());
    push_prefixed(&mut m, entry_id.as_bytes());
    m.extend_from_slice(&timestamp_ms.to_be_bytes());
    m.extend_from_slice(nonce);
    m
}

/// The mailbox operator's signed statement that it holds a message. It is
/// also the record the mailbox keeps of the message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Receipt {
    /// The message id: 32 hex characters.
    pub id: String,
    /// The DID the message is held for.
    pub recipient_did: String,
    /// SHA-256 of the sealed bytes, hex.
    pub sealed_sha256: String,
    /// Size of the sealed bytes.
    pub size: u64,
    /// Unix milliseconds the mailbox took the message.
    pub deposited_at_ms: u64,
    /// Unix milliseconds after which the mailbox no longer serves it.
    pub expires_at_ms: u64,
    /// The escrow that paid, hex.
    pub escrow_id: String,
    /// What the deposit cost, in wei.
    #[serde(with = "tenzro_types::primitives::u128_serde")]
    pub charge: u128,
    /// The operator's signature over [`Receipt::preimage`] under
    /// [`SignatureContext::Mailbox`].
    pub signature: CompositeSignature,
}

impl Receipt {
    /// The bytes the operator signs: every field but the signature.
    pub fn preimage(&self) -> Vec<u8> {
        let mut m = tagged(b"/receipt");
        push_prefixed(&mut m, self.id.as_bytes());
        push_prefixed(&mut m, self.recipient_did.as_bytes());
        push_prefixed(&mut m, self.sealed_sha256.as_bytes());
        m.extend_from_slice(&self.size.to_be_bytes());
        m.extend_from_slice(&self.deposited_at_ms.to_be_bytes());
        m.extend_from_slice(&self.expires_at_ms.to_be_bytes());
        push_prefixed(&mut m, self.escrow_id.as_bytes());
        m.extend_from_slice(&self.charge.to_be_bytes());
        m
    }

    /// Checks the receipt against the operator key the recipient's DID
    /// document pins for this mailbox.
    pub fn verify(&self, operator: &CompositePublicKey) -> Result<(), MailboxError> {
        verify_composite(
            operator,
            SignatureContext::Mailbox,
            &self.preimage(),
            &self.signature,
            PqPolicy::WhenPresent,
        )
        .map(|_| ())
        .map_err(|e| MailboxError::Unauthorized(format!("receipt signature: {e}")))
    }
}

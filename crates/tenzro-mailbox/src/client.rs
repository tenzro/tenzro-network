//! A client of a mailbox: what a sender and a recipient run.
//!
//! The client pins the mailbox's operator key, as the recipient's DID
//! document names it beside the mailbox's address, and checks every receipt
//! and every collected message against it. Signatures come from a
//! [`HybridSigner`] over the caller's hardware or passkey; the client holds
//! no key.
//!
//! A sealed message must already be padded to one of the mailbox's size
//! classes ([`MailboxInfo::size_classes`], [`size_class_for`]); the sealing
//! format carries the message's own length, so the padding is the sealer's
//! and the mailbox never reads either.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use serde::de::DeserializeOwned;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tenzro_crypto::{CompositePublicKey, HybridSigner, SignatureContext};
use tenzro_types::payment_authorization::{EscrowVoucher, escrow_voucher_preimage};

use crate::discovery::{MailboxEntry, acceptable_base, operator_key_digest};
use crate::error::MailboxError;
use crate::prekeys::Prekey;
use crate::service::MailboxInfo;
use crate::wire::{
    Action, Auth, Capability, Deposit, DepositPolicy, PrekeyFetch, Receipt, SenderProof,
    TAG_PREFIX, auth_preimage, deposit_binding, fetch_binding, prekeys_digest, sender_preimage,
    tag_key_bytes,
};

/// The smallest of `classes` that holds `len` bytes.
pub fn size_class_for(len: usize, classes: &[u64]) -> Option<u64> {
    classes.iter().copied().filter(|c| *c >= len as u64).min()
}

/// A payer's signed voucher on `escrow_id` for `cumulative_amount` in total,
/// bound to `binding`.
pub fn sign_voucher(
    payer: &dyn HybridSigner,
    chain_id: u64,
    escrow_id: [u8; 32],
    cumulative_amount: u128,
    binding: [u8; 32],
) -> Result<EscrowVoucher, MailboxError> {
    let message = escrow_voucher_preimage(chain_id, &escrow_id, cumulative_amount, &binding);
    Ok(EscrowVoucher {
        escrow_id,
        cumulative_amount,
        binding,
        public_key: payer.public_key().p256.clone(),
        signature: payer
            .sign(SignatureContext::EscrowVoucher, &message)
            .map_err(|e| MailboxError::Signing(e.to_string()))?,
        agent: None,
        attribution: None,
    })
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

/// Longest a request, connecting included, may take.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// Longest a connection may take to open.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Most bytes of one answer the client reads: the largest message in its
/// base64 form with its receipt, and a full list of receipts, fit well
/// within it.
const MAX_ANSWER_BYTES: usize = 2 << 20;

/// What a payer will pay at a mailbox. A deposit or a key package fetch is
/// signed only when the mailbox's terms are within these.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Terms {
    /// The chain the payer's escrows are on.
    pub chain_id: u64,
    /// The most the payer pays for keeping one byte for one hour, in wei.
    pub max_rate_per_byte_hour: u128,
    /// The most the payer pays for one key package, in wei.
    pub max_prekey_price: u128,
}

/// A mailbox, as a sender or a recipient reaches it.
pub struct MailboxClient {
    http: reqwest::Client,
    base: String,
    operator: CompositePublicKey,
    terms: Terms,
}

/// One message to deposit: what is sent, for whom, and how it is paid for.
pub struct DepositRequest<'a> {
    /// The escrow that pays, whose payee is the mailbox's.
    pub escrow_id: [u8; 32],
    /// What the escrow's vouchers add up to with this deposit.
    pub cumulative_amount: u128,
    /// The recipient's DID, or its tag.
    pub recipient_did: &'a str,
    /// The sealed message, padded to one of the mailbox's size classes.
    pub sealed: Vec<u8>,
    /// How long the mailbox keeps it, in seconds.
    pub lifetime_s: u64,
    /// The depositor's DID and the key that proves it.
    pub sender: Option<(&'a str, &'a dyn HybridSigner)>,
    /// The recipient's leave to deposit.
    pub capability: Option<Capability>,
}

/// What a recipient collected.
#[derive(Debug, Clone)]
pub struct Collected {
    /// The operator's receipt for the message.
    pub receipt: Receipt,
    /// The sealed message.
    pub sealed: Vec<u8>,
}

/// The key a request for `recipient` names: for a tag, the whole composite
/// key its tag is the digest of; for a DID, the P-256 key.
fn request_key(signer: &dyn HybridSigner, recipient: &str) -> Vec<u8> {
    if recipient.starts_with(TAG_PREFIX) {
        tag_key_bytes(signer.public_key())
    } else {
        signer.public_key().p256.clone()
    }
}

fn http_client() -> Result<reqwest::Client, MailboxError> {
    reqwest::Client::builder()
        .timeout(REQUEST_TIMEOUT)
        .connect_timeout(CONNECT_TIMEOUT)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|e| MailboxError::Remote(e.to_string()))
}

fn check_base(base: &str) -> Result<(), MailboxError> {
    if acceptable_base(base) {
        Ok(())
    } else {
        Err(MailboxError::Unauthorized(
            "a mailbox is reached over https, or over http on this machine".to_string(),
        ))
    }
}

/// The body of `answer`, refused when it is longer than the client reads.
async fn read_body(mut answer: reqwest::Response) -> Result<Vec<u8>, MailboxError> {
    let too_long = || MailboxError::Remote("the answer is too long".to_string());
    if answer
        .content_length()
        .is_some_and(|n| n > MAX_ANSWER_BYTES as u64)
    {
        return Err(too_long());
    }
    let mut body = Vec::new();
    while let Some(chunk) = answer
        .chunk()
        .await
        .map_err(|e| MailboxError::Remote(e.to_string()))?
    {
        if body.len() + chunk.len() > MAX_ANSWER_BYTES {
            return Err(too_long());
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

async fn read_info(http: &reqwest::Client, base: &str) -> Result<MailboxInfo, MailboxError> {
    let answer = http
        .get(format!("{base}/mailbox/v1/info"))
        .send()
        .await
        .map_err(|e| MailboxError::Remote(e.to_string()))?;
    serde_json::from_slice(&read_body(answer).await?)
        .map_err(|e| MailboxError::Remote(e.to_string()))
}

impl MailboxClient {
    /// Reach the mailbox a DID document's `entry` names, paying within
    /// `terms`: its key is read from the mailbox and refused unless it
    /// hashes to the digest the document pins.
    pub async fn connect(entry: &MailboxEntry, terms: Terms) -> Result<Self, MailboxError> {
        check_base(&entry.base)?;
        let http = http_client()?;
        let operator = read_info(&http, &entry.base).await?.operator_key;
        if operator_key_digest(&operator) != entry.key_digest {
            return Err(MailboxError::Unauthorized(
                "the mailbox's key is not the one its DID document pins".to_string(),
            ));
        }
        Ok(Self {
            http,
            base: entry.base.clone(),
            operator,
            terms,
        })
    }

    /// The mailbox served at `base` (its address, ending before
    /// `/mailbox/v1`), whose receipts `operator` signs, paid within `terms`.
    pub fn new(
        base: impl Into<String>,
        operator: CompositePublicKey,
        terms: Terms,
    ) -> Result<Self, MailboxError> {
        let base = base.into().trim_end_matches('/').to_string();
        check_base(&base)?;
        Ok(Self {
            http: http_client()?,
            base,
            operator,
            terms,
        })
    }

    /// The mailbox's price list, refused when its chain is not the payer's
    /// or its prices exceed the payer's terms.
    async fn quote(&self) -> Result<MailboxInfo, MailboxError> {
        let info = self.info().await?;
        if info.chain_id != self.terms.chain_id {
            return Err(MailboxError::Unauthorized(
                "the mailbox is paid on another chain".to_string(),
            ));
        }
        Ok(info)
    }

    async fn post<T: DeserializeOwned>(&self, path: &str, body: &Value) -> Result<T, MailboxError> {
        let answer = self
            .http
            .post(format!("{}/mailbox/v1/{path}", self.base))
            .json(body)
            .send()
            .await
            .map_err(|e| MailboxError::Remote(e.to_string()))?;
        let status = answer.status();
        let value: Value = serde_json::from_slice(&read_body(answer).await?)
            .map_err(|e| MailboxError::Remote(e.to_string()))?;
        if !status.is_success() {
            let why = value["error"].as_str().unwrap_or_default().to_string();
            return Err(match status.as_u16() {
                401 => MailboxError::Unauthorized(why),
                402 => MailboxError::Unpaid(why),
                403 => MailboxError::NotAllowed(why),
                404 => MailboxError::NotFound,
                409 => MailboxError::Spent,
                429 => MailboxError::RateLimited,
                503 => MailboxError::Busy,
                _ => MailboxError::Remote(format!("{status}: {why}")),
            });
        }
        serde_json::from_value(value).map_err(|e| MailboxError::Remote(e.to_string()))
    }

    /// What the mailbox charges and takes. Refused when the mailbox's key is
    /// not the one pinned.
    pub async fn info(&self) -> Result<MailboxInfo, MailboxError> {
        let info = read_info(&self.http, &self.base).await?;
        if info.operator_key != self.operator {
            return Err(MailboxError::Unauthorized(
                "the mailbox's key is not the one the recipient names".to_string(),
            ));
        }
        Ok(info)
    }

    /// A recipient's proof for `action` on `subject`, signed now by
    /// `signer`.
    pub fn auth(
        &self,
        signer: &dyn HybridSigner,
        action: Action,
        did: &str,
        subject: &str,
    ) -> Result<Auth, MailboxError> {
        let timestamp_ms = now_ms();
        let nonce: [u8; 16] = rand::random();
        let message = auth_preimage(
            &self.operator.p256,
            action,
            did,
            subject,
            timestamp_ms,
            &nonce,
        );
        Ok(Auth {
            did: did.to_string(),
            timestamp_ms,
            nonce,
            public_key: request_key(signer, did),
            signature: signer
                .sign(SignatureContext::Mailbox, &message)
                .map_err(|e| MailboxError::Signing(e.to_string()))?,
        })
    }

    /// Deposits `request.sealed` for the recipient, paid by `payer` with a
    /// voucher on the request's escrow, and returns the operator's receipt
    /// once it verifies. Nothing is signed unless the mailbox's chain,
    /// prices, size classes and lifetime are within the client's terms.
    pub async fn deposit(
        &self,
        payer: &dyn HybridSigner,
        request: DepositRequest<'_>,
    ) -> Result<Receipt, MailboxError> {
        let DepositRequest {
            escrow_id,
            cumulative_amount,
            recipient_did,
            sealed,
            lifetime_s,
            sender,
            capability,
        } = request;
        let info = self.quote().await?;
        if info.rate_per_byte_hour > self.terms.max_rate_per_byte_hour {
            return Err(MailboxError::Unauthorized(
                "the mailbox charges more than the payer's terms".to_string(),
            ));
        }
        if !info.size_classes.contains(&(sealed.len() as u64)) || lifetime_s > info.max_lifetime_s {
            return Err(MailboxError::Unauthorized(
                "the message is outside the sizes or lifetime the mailbox takes".to_string(),
            ));
        }
        let chain_id = self.terms.chain_id;
        let sha: [u8; 32] = Sha256::digest(&sealed).into();
        let binding = deposit_binding(recipient_did, &sha, lifetime_s);
        let voucher = sign_voucher(payer, chain_id, escrow_id, cumulative_amount, binding)?;
        let sender = match sender {
            Some((did, signer)) => Some(SenderProof {
                did: did.to_string(),
                public_key: signer.public_key().p256.clone(),
                signature: signer
                    .sign(
                        SignatureContext::Mailbox,
                        &sender_preimage(&self.operator.p256, did, &escrow_id, &binding),
                    )
                    .map_err(|e| MailboxError::Signing(e.to_string()))?,
            }),
            None => None,
        };
        let deposit = Deposit {
            recipient_did: recipient_did.to_string(),
            sealed,
            lifetime_s,
            voucher,
            sender,
            capability,
        };
        let body =
            serde_json::to_value(&deposit).map_err(|e| MailboxError::Store(e.to_string()))?;
        let receipt: Receipt = self.post("deposit", &body).await?;
        receipt.verify(&self.operator)?;
        if receipt.recipient_did != recipient_did || receipt.sealed_sha256 != hex::encode(sha) {
            return Err(MailboxError::Unauthorized(
                "the receipt is for another message".to_string(),
            ));
        }
        Ok(receipt)
    }

    /// The receipts of the messages held for `did`, each verified.
    pub async fn list(
        &self,
        signer: &dyn HybridSigner,
        did: &str,
    ) -> Result<Vec<Receipt>, MailboxError> {
        let body = json!({ "auth": self.auth(signer, Action::List, did, "")? });
        let answer: Value = self.post("list", &body).await?;
        let receipts: Vec<Receipt> = serde_json::from_value(answer["messages"].clone())
            .map_err(|e| MailboxError::Remote(e.to_string()))?;
        for receipt in &receipts {
            receipt.verify(&self.operator)?;
        }
        Ok(receipts)
    }

    /// The message `id` held for `did`, checked against its receipt.
    pub async fn collect(
        &self,
        signer: &dyn HybridSigner,
        did: &str,
        id: &str,
    ) -> Result<Collected, MailboxError> {
        let body = json!({ "auth": self.auth(signer, Action::Collect, did, id)?, "id": id });
        let answer: Value = self.post("collect", &body).await?;
        let receipt: Receipt = serde_json::from_value(answer["receipt"].clone())
            .map_err(|e| MailboxError::Remote(e.to_string()))?;
        receipt.verify(&self.operator)?;
        let sealed = base64::engine::general_purpose::STANDARD
            .decode(answer["sealed"].as_str().unwrap_or_default())
            .map_err(|e| MailboxError::Remote(e.to_string()))?;
        if receipt.id != id || receipt.sealed_sha256 != hex::encode(Sha256::digest(&sealed)) {
            return Err(MailboxError::Unauthorized(
                "the message does not match its receipt".to_string(),
            ));
        }
        Ok(Collected { receipt, sealed })
    }

    /// Confirms `did` read the message `id`, which drops it.
    pub async fn ack(
        &self,
        signer: &dyn HybridSigner,
        did: &str,
        id: &str,
    ) -> Result<(), MailboxError> {
        let body = json!({ "auth": self.auth(signer, Action::Ack, did, id)?, "id": id });
        self.post::<Value>("ack", &body).await.map(|_| ())
    }

    /// Sets who may deposit for `did`, and returns the policy epoch it
    /// starts.
    pub async fn set_policy(
        &self,
        signer: &dyn HybridSigner,
        did: &str,
        policy: &DepositPolicy,
    ) -> Result<u64, MailboxError> {
        let body = json!({
            "auth": self.auth(signer, Action::Policy, did, &policy.digest())?,
            "policy": policy,
        });
        let answer: Value = self.post("policy", &body).await?;
        answer["epoch"]
            .as_u64()
            .ok_or_else(|| MailboxError::Remote("no epoch in the answer".to_string()))
    }

    /// The recipient `did`'s leave to deposit at this mailbox under policy
    /// `epoch`, for `depositor_did` or any holder, until `expires_at_ms`.
    pub fn capability(
        &self,
        signer: &dyn HybridSigner,
        did: &str,
        depositor_did: Option<&str>,
        epoch: u64,
        expires_at_ms: u64,
    ) -> Result<Capability, MailboxError> {
        let mut capability = Capability {
            operator_key: self.operator.p256.clone(),
            recipient_did: did.to_string(),
            policy_epoch: epoch,
            depositor_did: depositor_did.map(str::to_string),
            expires_at_ms,
            public_key: request_key(signer, did),
            signature: Default::default(),
        };
        capability.signature = signer
            .sign(SignatureContext::Mailbox, &capability.preimage())
            .map_err(|e| MailboxError::Signing(e.to_string()))?;
        Ok(capability)
    }

    /// Uploads `did`'s key packages, and returns how many the mailbox holds.
    pub async fn upload_prekeys(
        &self,
        signer: &dyn HybridSigner,
        did: &str,
        packages: &[Vec<u8>],
        last_resort: Option<&[u8]>,
    ) -> Result<usize, MailboxError> {
        let b64 = |b: &[u8]| base64::engine::general_purpose::STANDARD.encode(b);
        let body = json!({
            "auth": self.auth(signer, Action::Prekeys, did, &prekeys_digest(packages, last_resort))?,
            "packages": packages.iter().map(|p| b64(p)).collect::<Vec<_>>(),
            "last_resort": last_resort.map(b64),
        });
        let answer: Value = self.post("prekeys/upload", &body).await?;
        answer["held"]
            .as_u64()
            .map(|n| n as usize)
            .ok_or_else(|| MailboxError::Remote("no count in the answer".to_string()))
    }

    /// One of `recipient_did`'s key packages, paid by `payer` on `escrow_id`
    /// with a voucher for `cumulative_amount` in total; refused when the
    /// mailbox's chain or price is not within the client's terms.
    pub async fn fetch_prekey(
        &self,
        payer: &dyn HybridSigner,
        escrow_id: [u8; 32],
        cumulative_amount: u128,
        recipient_did: &str,
    ) -> Result<Prekey, MailboxError> {
        if self.quote().await?.prekey_price > self.terms.max_prekey_price {
            return Err(MailboxError::Unauthorized(
                "the mailbox charges more than the payer's terms".to_string(),
            ));
        }
        let chain_id = self.terms.chain_id;
        let nonce: [u8; 16] = rand::random();
        let binding = fetch_binding(&self.operator.p256, recipient_did, &nonce);
        let fetch = PrekeyFetch {
            recipient_did: recipient_did.to_string(),
            nonce,
            voucher: sign_voucher(payer, chain_id, escrow_id, cumulative_amount, binding)?,
        };
        let body = serde_json::to_value(&fetch).map_err(|e| MailboxError::Store(e.to_string()))?;
        let answer: Value = self.post("prekeys/fetch", &body).await?;
        Ok(Prekey {
            package: base64::engine::general_purpose::STANDARD
                .decode(answer["package"].as_str().unwrap_or_default())
                .map_err(|e| MailboxError::Remote(e.to_string()))?,
            last_resort: answer["last_resort"].as_bool().unwrap_or_default(),
        })
    }
}

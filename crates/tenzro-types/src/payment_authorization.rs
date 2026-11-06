//! A payer's own authorization of a payment, verifiable by every validator.
//!
//! A payer-authorized payment is settled
//! on the Tenzro Ledger by a `PayerSettle` transaction. That transaction can be
//! submitted by anyone, so it carries the payer's signature over the canonical
//! preimage defined here, and the VM re-verifies it before any balance moves:
//! the debited account is the one whose key signed, never an address a caller
//! typed in.
//!
//! The preimage binds everything that decides where money goes and how much,
//! and what it pays for: the chain, the payment id (the payer's nonce), payer,
//! payee, the asset, the ceiling the payer agreed to, and the
//! [`PaymentBinding`]: the digest of the request, the digest of the payee's
//! quote (price, licence and content usage), the USD price and the
//! developer margin the payer agrees to pay an application. An exact
//! payment signs `max_amount == amount`; a metered (`upto`) payment signs a
//! ceiling and the settled amount may be anything up to it.
//!
//! Every settled payment leaves one consensus record keyed by its
//! [`pay_ref`], which hashes the payee and the binding with the nonce, so the
//! request, the quote, the payment and the delivery receipts form one chain.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::account_signature::CompositeSignature;
use crate::primitives::Address;

/// Domain tag prefixed to every payment-authorization preimage, so the
/// signature can never be replayed as any other Tenzro signature.
pub const PAYMENT_AUTHORIZATION_DOMAIN: &[u8] = b"tenzro/payment-authorization";

/// Length of a payer's P-256 public key (`x || y`).
pub const P256_PUBLIC_KEY_LEN: usize = 64;

/// The payer's signature over [`payment_authorization_preimage`], carried on
/// the settlement transaction.
///
/// The payer account is the one the P-256 key derives
/// (`tenzro_crypto::account_address`); an enrolled ML-DSA-65 key never moves it. The signature is a composite
/// signature under the payment-authorization context. The ML-DSA-65 leg is
/// checked against the key the payer account has enrolled in chain state
/// ([`crate::account_signature::enrolled_pq_key_storage_key`]), never a key
/// the record carries; an account with one enrolled must sign the hybrid.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaymentAuthorization {
    /// The payer's P-256 public key (`x || y`).
    #[serde(with = "hex_bytes")]
    pub public_key: Vec<u8>,
    /// Composite signature over the preimage.
    pub signature: CompositeSignature,
    /// The ceiling the payer signed. The settled amount must not exceed it.
    #[serde(with = "crate::primitives::u128_serde")]
    pub max_amount: u128,
    /// The asset the payer signed for: `TNZO`, or a token's 32-byte id as
    /// `0x`-prefixed hex.
    pub asset: String,
    /// What the payment pays for.
    pub binding: PaymentBinding,
    /// The reseller commissions the payer agrees to, each its own leg paid
    /// on top of the operator's price; empty for a direct payment.
    #[serde(default)]
    pub resellers: Vec<ResellerLeg>,
}

/// A reseller's commission on a payment: its own leg, paid by the payer to
/// the reseller on top of the operator's price, never out of it. Any
/// registered identity may resell on the same terms.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ResellerLeg {
    /// The reseller's account.
    pub reseller: Address,
    /// The commission, basis points of the operator's price.
    pub commission_bps: u32,
}

/// What a payment pays for, as the payer signs it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PaymentBinding {
    /// SHA-256 of the canonical request (method, target and body digest).
    /// Never zero: a payment always names what it buys.
    #[serde(with = "hex_array32")]
    pub request_digest: [u8; 32],
    /// [`Quote::digest`] of the payee's signed quote, or zero for a payment
    /// made without one.
    #[serde(with = "hex_array32")]
    pub quote_digest: [u8; 32],
    /// The price in USD micro-units, or zero for a payment not priced in
    /// USD. Limits and the settlement fee value the payment at this price.
    pub usd_e6: u64,
    /// The developer margin the payer agrees to pay out of the amount, or
    /// `None` for a payment that pays no application margin. A settlement
    /// pays exactly this margin to exactly this wallet, never one a
    /// submitter names.
    #[serde(default)]
    pub app_margin: Option<AppMargin>,
}

/// An application's margin on a payment, as the payer signs it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AppMargin {
    /// The wallet the margin is paid to.
    pub app_wallet: Address,
    /// The margin in basis points, included in the settled amount: the
    /// application receives `amount * margin_bps / (10_000 + margin_bps)`.
    /// Bounded by the governed `fees.max_developer_margin_bps`.
    pub margin_bps: u32,
}

impl PaymentBinding {
    fn put(&self, m: &mut Vec<u8>) {
        m.extend_from_slice(&self.request_digest);
        m.extend_from_slice(&self.quote_digest);
        m.extend_from_slice(&self.usd_e6.to_le_bytes());
        put_app_margin(&self.app_margin, m);
    }
}

/// `0x00` for no margin, or `0x01 || app_wallet(32) || margin_bps(u32 LE)`.
fn put_app_margin(margin: &Option<AppMargin>, m: &mut Vec<u8>) {
    match margin {
        None => m.push(0),
        Some(a) => {
            m.push(1);
            m.extend_from_slice(a.app_wallet.as_bytes());
            m.extend_from_slice(&a.margin_bps.to_le_bytes());
        }
    }
}

/// The asset string naming native TNZO.
pub const TNZO_ASSET: &str = "TNZO";

/// The token id an asset string names: `None` for TNZO, the 32-byte id for
/// a `0x`-prefixed hex token id. An asset string of any other form is
/// refused.
pub fn asset_token_id(asset: &str) -> Result<Option<[u8; 32]>, &'static str> {
    if asset == TNZO_ASSET {
        return Ok(None);
    }
    let hex_id = asset
        .strip_prefix("0x")
        .ok_or("an asset is TNZO or a 0x-prefixed 32-byte token id")?;
    let bytes = hex::decode(hex_id).map_err(|_| "the token id is not hex")?;
    let id: [u8; 32] = bytes.try_into().map_err(|_| "a token id is 32 bytes")?;
    Ok(Some(id))
}

/// Domain tag of a payment reference.
pub const PAY_REF_DOMAIN: &[u8] = b"tenzro/pay-ref";

/// Domain of [`idempotent_payment_id`].
pub const PAYMENT_ID_DOMAIN: &[u8] = b"tenzro/payment-id";

/// The payment id a payer derives from its idempotency key, so every retry
/// of one payment settles under one id and the chain's replay marker
/// refuses the second: SHA-256 over the domain, the key (u32 LE length
/// prefixed), payer, payee and request digest, as lowercase hex.
pub fn idempotent_payment_id(
    idempotency_key: &str,
    payer: &Address,
    payee: &Address,
    request_digest: &[u8; 32],
) -> String {
    let mut h = Sha256::new();
    h.update(PAYMENT_ID_DOMAIN);
    h.update((idempotency_key.len() as u32).to_le_bytes());
    h.update(idempotency_key.as_bytes());
    h.update(payer.as_bytes());
    h.update(payee.as_bytes());
    h.update(request_digest);
    hex::encode(h.finalize())
}

/// The reference of the payment record a settlement writes:
/// `SHA-256(domain, chain_id, payee, request_digest, quote_digest,
/// app_margin, nonce)`, the margin encoded as in the authorization preimage.
/// The nonce is the payment id; a reference is settled at most once.
pub fn pay_ref(chain_id: u64, payee: &Address, binding: &PaymentBinding, nonce: &str) -> [u8; 32] {
    let mut margin = Vec::with_capacity(37);
    put_app_margin(&binding.app_margin, &mut margin);
    let mut h = Sha256::new();
    h.update(PAY_REF_DOMAIN);
    h.update(chain_id.to_le_bytes());
    h.update(payee.as_bytes());
    h.update(binding.request_digest);
    h.update(binding.quote_digest);
    h.update(&margin);
    h.update((nonce.len() as u32).to_le_bytes());
    h.update(nonce.as_bytes());
    h.finalize().into()
}

/// One asset a quote accepts, with the most of it the payer pays.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuotedAsset {
    /// `TNZO` or a token id, as [`asset_token_id`] reads it.
    pub asset: String,
    /// Most of the asset the quoted price settles for.
    #[serde(with = "crate::primitives::u128_serde")]
    pub max_amount: u128,
}

/// A payee's offer for one request: the price, the assets it accepts, and
/// the licence and content-usage terms the payment buys. The payee signs
/// [`Quote::digest`]; the payer's authorization carries the digest, so the
/// price, the licence and the request are bound into the payment record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Quote {
    /// The payee.
    pub payee: Address,
    /// The request quoted for.
    #[serde(with = "hex_array32")]
    pub request_digest: [u8; 32],
    /// The price in USD micro-units.
    pub usd_e6: u64,
    /// The assets the payee accepts.
    pub accepts: Vec<QuotedAsset>,
    /// The licence the payment buys: an identifier or the licence text's
    /// SHA-256, hex.
    pub licence: String,
    /// The content-usage expression the licence grants (for example
    /// `train-ai=n, search=y`).
    #[serde(default)]
    pub content_usage: String,
    /// SHA-256 of each line item the quote covers (a cart's lines). A
    /// mandate or checkout may only pay for lines listed here.
    #[serde(default, with = "hex_array32_list")]
    pub lines: Vec<[u8; 32]>,
    /// The quote is void after this time, unix ms.
    pub expires_at_ms: u64,
    /// The payee's hardware level and type as the chain derives them, so the
    /// buyer sees what will serve it. A quote may omit it; one that carries
    /// it must match the chain.
    #[serde(default)]
    pub hardware: Option<crate::hardware_level::HardwareStamp>,
}

/// Domain tag of a quote digest.
pub const QUOTE_DOMAIN: &[u8] = b"tenzro/quote";

impl Quote {
    /// The digest the payee signs and the payer's binding carries.
    pub fn digest(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(QUOTE_DOMAIN);
        h.update(self.payee.as_bytes());
        h.update(self.request_digest);
        h.update(self.usd_e6.to_le_bytes());
        h.update((self.accepts.len() as u32).to_le_bytes());
        for a in &self.accepts {
            h.update((a.asset.len() as u32).to_le_bytes());
            h.update(a.asset.as_bytes());
            h.update(a.max_amount.to_le_bytes());
        }
        for s in [&self.licence, &self.content_usage] {
            h.update((s.len() as u32).to_le_bytes());
            h.update(s.as_bytes());
        }
        h.update((self.lines.len() as u32).to_le_bytes());
        for l in &self.lines {
            h.update(l);
        }
        h.update(self.expires_at_ms.to_le_bytes());
        // A quote without a stamp keeps the digest it always had.
        if let Some(stamp) = &self.hardware {
            h.update([1]);
            stamp.digest_into(&mut h);
        }
        h.finalize().into()
    }

    /// The binding a payer signs to pay this quote.
    pub fn binding(&self) -> PaymentBinding {
        PaymentBinding {
            request_digest: self.request_digest,
            quote_digest: self.digest(),
            usd_e6: self.usd_e6,
            app_margin: None,
        }
    }

    /// Whether the quote lists line `line`.
    pub fn covers_line(&self, line: &[u8; 32]) -> bool {
        self.lines.contains(line)
    }
}

/// The payee's statement of what it delivered for a payment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeliveryReceipt {
    /// The payment record it answers.
    #[serde(with = "hex_array32")]
    pub pay_ref: [u8; 32],
    /// SHA-256 of the delivered body.
    #[serde(with = "hex_array32")]
    pub body_digest: [u8; 32],
    /// The inference receipt's digest, when the delivery was an inference.
    #[serde(default, with = "hex_array32_opt")]
    pub inference_receipt: Option<[u8; 32]>,
    /// When it was delivered, unix ms.
    pub delivered_at_ms: u64,
    /// The payee's hardware level and type that served the payment. The
    /// chain refuses a receipt whose stamp differs from what it derives for
    /// the payee.
    #[serde(default)]
    pub hardware: Option<crate::hardware_level::HardwareStamp>,
}

/// Domain tag of a delivery receipt digest.
pub const DELIVERY_RECEIPT_DOMAIN: &[u8] = b"tenzro/delivery-receipt";

impl DeliveryReceipt {
    /// The digest the payment record lists.
    pub fn digest(&self) -> [u8; 32] {
        let mut h = Sha256::new();
        h.update(DELIVERY_RECEIPT_DOMAIN);
        h.update(self.pay_ref);
        h.update(self.body_digest);
        match &self.inference_receipt {
            Some(r) => {
                h.update([1]);
                h.update(r);
            }
            None => h.update([0]),
        }
        h.update(self.delivered_at_ms.to_le_bytes());
        if let Some(stamp) = &self.hardware {
            h.update([1]);
            stamp.digest_into(&mut h);
        }
        h.finalize().into()
    }
}

/// The exact bytes a payer signs to authorize a payment.
///
/// Every variable-length field is length-prefixed so no two distinct field
/// tuples can produce the same preimage.
pub fn payment_authorization_preimage(
    chain_id: u64,
    payment_id: &str,
    payer: &Address,
    payee: &Address,
    max_amount: u128,
    asset: &str,
    binding: &PaymentBinding,
) -> Vec<u8> {
    let mut m = Vec::with_capacity(
        PAYMENT_AUTHORIZATION_DOMAIN.len()
            + 8
            + 4
            + payment_id.len()
            + 64
            + 16
            + 4
            + asset.len()
            + 72
            + 37,
    );
    m.extend_from_slice(PAYMENT_AUTHORIZATION_DOMAIN);
    m.extend_from_slice(&chain_id.to_le_bytes());
    m.extend_from_slice(&(payment_id.len() as u32).to_le_bytes());
    m.extend_from_slice(payment_id.as_bytes());
    m.extend_from_slice(payer.as_bytes());
    m.extend_from_slice(payee.as_bytes());
    m.extend_from_slice(&max_amount.to_le_bytes());
    m.extend_from_slice(&(asset.len() as u32).to_le_bytes());
    m.extend_from_slice(asset.as_bytes());
    binding.put(&mut m);
    m
}

/// [`payment_authorization_preimage`] with the reseller legs the payer
/// agrees to: when there are any, a `0x02` tag, their count (u32 LE) and
/// each reseller's account and commission (u32 LE) follow, so a commission
/// cannot be added, dropped, raised or redirected after the payer signed.
/// With none, the preimage is the direct payment's.
#[allow(clippy::too_many_arguments)]
pub fn payment_authorization_preimage_with_resellers(
    chain_id: u64,
    payment_id: &str,
    payer: &Address,
    payee: &Address,
    max_amount: u128,
    asset: &str,
    binding: &PaymentBinding,
    resellers: &[ResellerLeg],
) -> Vec<u8> {
    let mut m = payment_authorization_preimage(
        chain_id, payment_id, payer, payee, max_amount, asset, binding,
    );
    if !resellers.is_empty() {
        m.push(2);
        m.extend_from_slice(&(resellers.len() as u32).to_le_bytes());
        for r in resellers {
            m.extend_from_slice(r.reseller.as_bytes());
            m.extend_from_slice(&r.commission_bps.to_le_bytes());
        }
    }
    m
}

/// Upper bound on vouchers in one `ClaimEscrow` transaction, so one
/// transaction's work stays bounded.
pub const MAX_VOUCHERS_PER_CLAIM: usize = 32;

/// One leg of a `ClaimEscrow`: the payer's voucher, which caps what may be
/// claimed, and `amount`, the cumulative total the payee claims under it,
/// which is what its metering charged. A voucher signed ahead of a call
/// covers that call's ceiling; the payee claims only what the calls cost,
/// and what is not claimed goes back to the payer when the escrow ends.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EscrowClaim {
    /// The payer's voucher.
    pub voucher: EscrowVoucher,
    /// Cumulative total claimed, at most `voucher.cumulative_amount`.
    #[serde(with = "crate::primitives::u128_serde")]
    pub amount: u128,
}

/// Domain tag prefixed to every escrow-voucher preimage.
pub const ESCROW_VOUCHER_DOMAIN: &[u8] = b"tenzro/escrow-voucher";

/// A payer's signed promise that the payee of an on-chain escrow may claim
/// up to `cumulative_amount` of it in total.
///
/// Vouchers are cumulative, not incremental: each new voucher supersedes the
/// last, and a claim pays out only the difference between the voucher and
/// what was already claimed. That is what lets one escrow back a stream of
/// payments (a channel, a metered session, a batch of HTTP-402 requests) with
/// a single claim at the end.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EscrowVoucher {
    /// The escrow the voucher draws on.
    #[serde(with = "hex_array32")]
    pub escrow_id: [u8; 32],
    /// Total the payee may have claimed once this voucher is honoured.
    #[serde(with = "crate::primitives::u128_serde")]
    pub cumulative_amount: u128,
    /// What the payer is paying for: the head of the hash chain of the
    /// receipts it received on this escrow, so the voucher proves which
    /// delivery it paid. All zero for a voucher signed ahead of delivery,
    /// covering a ceiling.
    #[serde(default, with = "hex_array32")]
    pub binding: [u8; 32],
    /// The payer's P-256 public key (`x || y`); it must derive the escrow's
    /// payer account.
    #[serde(with = "hex_bytes")]
    pub public_key: Vec<u8>,
    /// Composite signature over [`escrow_voucher_preimage`].
    pub signature: CompositeSignature,
    /// For an escrow a delegated agent's wallet funded: the agent and the
    /// serving node that signed. The keys are then empty and `signature` is
    /// that node's raw P-256 signature (`r || s`, no ML-DSA leg) over
    /// [`agent_voucher_digest`], made with its hardware key for the agent.
    #[serde(default)]
    pub agent: Option<AgentVoucherSigner>,
    /// The call chain the payer attributes what the voucher pays to, if
    /// any. The signature covers it: see [`attributed_voucher_preimage`] and
    /// [`attributed_agent_voucher_digest`].
    #[serde(default)]
    pub attribution: Option<crate::settlement::CallAttribution>,
}

/// Who signed an agent's voucher, and when.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentVoucherSigner {
    /// The paying agent; the escrow's payer is its wallet.
    pub agent_did: String,
    /// The serving node whose key for the agent signed. It must be assigned
    /// in the agent's current terms.
    pub machine_did: String,
    /// When the node signed, unix ms. A voucher signed at or after the
    /// agent's revocation or quarantine is void.
    pub as_of_ms: u64,
}

/// Domain tag of an agent voucher digest.
pub const AGENT_VOUCHER_DOMAIN: &[u8] = b"tenzro/agent-voucher";

/// The digest a serving node signs for an agent's voucher.
pub fn agent_voucher_digest(
    chain_id: u64,
    escrow_id: &[u8; 32],
    cumulative: u128,
    binding: &[u8; 32],
    signer: &AgentVoucherSigner,
) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(AGENT_VOUCHER_DOMAIN);
    h.update(chain_id.to_le_bytes());
    h.update(escrow_id);
    h.update(cumulative.to_le_bytes());
    h.update(binding);
    for s in [&signer.agent_did, &signer.machine_did] {
        h.update((s.len() as u32).to_le_bytes());
        h.update(s.as_bytes());
    }
    h.update(signer.as_of_ms.to_le_bytes());
    h.finalize().into()
}

/// The exact bytes a payer signs for an [`EscrowVoucher`].
pub fn escrow_voucher_preimage(
    chain_id: u64,
    escrow_id: &[u8; 32],
    cumulative: u128,
    binding: &[u8; 32],
) -> Vec<u8> {
    let mut m = Vec::with_capacity(ESCROW_VOUCHER_DOMAIN.len() + 8 + 32 + 16 + 32);
    m.extend_from_slice(ESCROW_VOUCHER_DOMAIN);
    m.extend_from_slice(&chain_id.to_le_bytes());
    m.extend_from_slice(escrow_id);
    m.extend_from_slice(&cumulative.to_le_bytes());
    m.extend_from_slice(binding);
    m
}

/// What a payer signs for a voucher: [`escrow_voucher_preimage`], followed
/// by the attribution's [`signing_bytes`] when the voucher carries one, so a
/// voucher without one signs exactly what it always did.
///
/// [`signing_bytes`]: crate::settlement::CallAttribution::signing_bytes
pub fn attributed_voucher_preimage(
    preimage: Vec<u8>,
    attribution: Option<&crate::settlement::CallAttribution>,
) -> Vec<u8> {
    let mut m = preimage;
    if let Some(a) = attribution {
        m.extend_from_slice(&a.signing_bytes());
    }
    m
}

/// What a serving node signs for an agent's voucher: the
/// [`agent_voucher_digest`] itself, or, when the voucher carries an
/// attribution, SHA-256 over that digest and the attribution's signing
/// bytes.
pub fn attributed_agent_voucher_digest(
    digest: [u8; 32],
    attribution: Option<&crate::settlement::CallAttribution>,
) -> [u8; 32] {
    match attribution {
        None => digest,
        Some(a) => {
            let mut h = Sha256::new();
            h.update(digest);
            h.update(a.signing_bytes());
            h.finalize().into()
        }
    }
}

/// Domain tag of [`receipt_chain_next`].
pub const RECEIPT_CHAIN_DOMAIN: &[u8] = b"tenzro/receipt-chain";

/// The next head of a voucher's receipt chain: the previous head (all zero
/// for the first receipt on an escrow) extended by one receipt's digest.
pub fn receipt_chain_next(previous: &[u8; 32], receipt_digest: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(RECEIPT_CHAIN_DOMAIN);
    h.update(previous);
    h.update(receipt_digest);
    h.finalize().into()
}

pub(crate) mod hex_bytes {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        hex::decode(s.trim_start_matches("0x")).map_err(serde::de::Error::custom)
    }
}

mod hex_array32_list {
    use serde::{Deserialize, Deserializer, Serializer, ser::SerializeSeq};

    pub fn serialize<S: Serializer>(items: &[[u8; 32]], s: S) -> Result<S::Ok, S::Error> {
        let mut seq = s.serialize_seq(Some(items.len()))?;
        for i in items {
            seq.serialize_element(&hex::encode(i))?;
        }
        seq.end()
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<[u8; 32]>, D::Error> {
        Vec::<String>::deserialize(d)?
            .iter()
            .map(|s| {
                hex::decode(s.trim_start_matches("0x"))
                    .map_err(serde::de::Error::custom)?
                    .try_into()
                    .map_err(|_| serde::de::Error::custom("expected 32 bytes"))
            })
            .collect()
    }
}

pub(crate) mod hex_array32_opt {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &Option<[u8; 32]>, s: S) -> Result<S::Ok, S::Error> {
        match v {
            Some(b) => s.serialize_some(&hex::encode(b)),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<[u8; 32]>, D::Error> {
        Option::<String>::deserialize(d)?
            .map(|s| {
                hex::decode(s.trim_start_matches("0x"))
                    .map_err(serde::de::Error::custom)?
                    .try_into()
                    .map_err(|_| serde::de::Error::custom("expected 32 bytes"))
            })
            .transpose()
    }
}

pub(crate) mod hex_array32 {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(bytes: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let s = String::deserialize(d)?;
        let v = hex::decode(s.trim_start_matches("0x")).map_err(serde::de::Error::custom)?;
        v.try_into()
            .map_err(|_| serde::de::Error::custom("expected 32 bytes"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn voucher_preimage_binds_chain_escrow_amount_and_delivery() {
        let z = [0u8; 32];
        let a = escrow_voucher_preimage(1, &[1u8; 32], 5, &z);
        assert_ne!(a, escrow_voucher_preimage(2, &[1u8; 32], 5, &z));
        assert_ne!(a, escrow_voucher_preimage(1, &[2u8; 32], 5, &z));
        assert_ne!(a, escrow_voucher_preimage(1, &[1u8; 32], 6, &z));
        assert_ne!(a, escrow_voucher_preimage(1, &[1u8; 32], 5, &[3u8; 32]));
        // Never collides with a payment authorization.
        assert!(!a.starts_with(PAYMENT_AUTHORIZATION_DOMAIN));
    }

    /// A voucher without an attribution signs what it always did; one with
    /// an attribution signs every hop, in its place, so moving a DID to
    /// another hop or naming another one changes what was signed.
    #[test]
    fn an_attribution_is_covered_by_the_voucher_signature() {
        use crate::settlement::CallAttribution;
        let z = [0u8; 32];
        let base = escrow_voucher_preimage(1, &[1u8; 32], 5, &z);
        assert_eq!(attributed_voucher_preimage(base.clone(), None), base);
        let app = CallAttribution {
            app_did: Some("did:tenzro:human:app".into()),
            ..Default::default()
        };
        let as_tool = CallAttribution {
            tool_did: Some("did:tenzro:human:app".into()),
            ..Default::default()
        };
        let other = CallAttribution {
            app_did: Some("did:tenzro:human:other".into()),
            ..Default::default()
        };
        let signed = attributed_voucher_preimage(base.clone(), Some(&app));
        assert!(signed.starts_with(&base) && signed.len() > base.len());
        assert_ne!(
            signed,
            attributed_voucher_preimage(base.clone(), Some(&as_tool))
        );
        assert_ne!(signed, attributed_voucher_preimage(base, Some(&other)));
        let d = [7u8; 32];
        assert_eq!(attributed_agent_voucher_digest(d, None), d);
        assert_ne!(attributed_agent_voucher_digest(d, Some(&app)), d);
        assert_ne!(
            attributed_agent_voucher_digest(d, Some(&app)),
            attributed_agent_voucher_digest(d, Some(&as_tool))
        );
    }

    /// An attribution names one to three registered-looking DIDs, each once.
    #[test]
    fn an_attribution_names_distinct_dids() {
        use crate::settlement::CallAttribution;
        assert!(CallAttribution::default().check().is_err());
        let a = |app: &str, agent: Option<&str>| CallAttribution {
            app_did: Some(app.into()),
            agent_did: agent.map(str::to_string),
            tool_did: None,
        };
        assert!(
            a("did:tenzro:human:a", Some("did:tenzro:human:b"))
                .check()
                .is_ok()
        );
        assert!(
            a("did:tenzro:human:a", Some("did:tenzro:human:a"))
                .check()
                .is_err()
        );
        assert!(a("app", None).check().is_err());
        assert!(
            a(&format!("did:{}", "x".repeat(300)), None)
                .check()
                .is_err()
        );
        let full = CallAttribution {
            app_did: Some("did:a".into()),
            agent_did: Some("did:b".into()),
            tool_did: Some("did:c".into()),
        };
        assert_eq!(full.dids(), vec!["did:a", "did:b", "did:c"]);
        let json = serde_json::to_value(a("did:a", None)).unwrap();
        // Every hop is encoded, absent ones as null: transactions travel in
        // an encoding that cannot skip a field.
        assert_eq!(
            json,
            serde_json::json!({ "app_did": "did:a", "agent_did": null, "tool_did": null })
        );
    }

    #[test]
    fn preimage_changes_with_every_field() {
        let payer = Address::new([1u8; 32]);
        let payee = Address::new([2u8; 32]);
        let base = payment_authorization_preimage(
            1,
            "p",
            &payer,
            &payee,
            10,
            "TNZO",
            &PaymentBinding::default(),
        );
        assert_ne!(
            base,
            payment_authorization_preimage(
                2,
                "p",
                &payer,
                &payee,
                10,
                "TNZO",
                &PaymentBinding::default()
            )
        );
        assert_ne!(
            base,
            payment_authorization_preimage(
                1,
                "q",
                &payer,
                &payee,
                10,
                "TNZO",
                &PaymentBinding::default()
            )
        );
        assert_ne!(
            base,
            payment_authorization_preimage(
                1,
                "p",
                &payee,
                &payer,
                10,
                "TNZO",
                &PaymentBinding::default()
            )
        );
        assert_ne!(
            base,
            payment_authorization_preimage(
                1,
                "p",
                &payer,
                &payee,
                11,
                "TNZO",
                &PaymentBinding::default()
            )
        );
        assert_ne!(
            base,
            payment_authorization_preimage(
                1,
                "p",
                &payer,
                &payee,
                10,
                "USDC",
                &PaymentBinding::default()
            )
        );
    }

    #[test]
    fn preimage_binds_request_quote_and_price() {
        let payer = Address::new([1u8; 32]);
        let payee = Address::new([2u8; 32]);
        let b = PaymentBinding {
            request_digest: [3; 32],
            quote_digest: [4; 32],
            usd_e6: 5,
            app_margin: None,
        };
        let base = payment_authorization_preimage(1, "p", &payer, &payee, 10, "TNZO", &b);
        let margin = AppMargin {
            app_wallet: Address::new([7; 32]),
            margin_bps: 100,
        };
        for other in [
            PaymentBinding {
                request_digest: [9; 32],
                ..b
            },
            PaymentBinding {
                quote_digest: [9; 32],
                ..b
            },
            PaymentBinding { usd_e6: 6, ..b },
            PaymentBinding {
                app_margin: Some(margin),
                ..b
            },
            PaymentBinding {
                app_margin: Some(AppMargin {
                    app_wallet: Address::new([8; 32]),
                    ..margin
                }),
                ..b
            },
            PaymentBinding {
                app_margin: Some(AppMargin {
                    margin_bps: 101,
                    ..margin
                }),
                ..b
            },
        ] {
            assert_ne!(
                base,
                payment_authorization_preimage(1, "p", &payer, &payee, 10, "TNZO", &other)
            );
        }
    }

    #[test]
    fn app_margin_is_encoded_after_the_price() {
        let payer = Address::new([1u8; 32]);
        let payee = Address::new([2u8; 32]);
        let none = payment_authorization_preimage(
            1,
            "p",
            &payer,
            &payee,
            10,
            "TNZO",
            &PaymentBinding::default(),
        );
        assert_eq!(none.last(), Some(&0));
        let some = payment_authorization_preimage(
            1,
            "p",
            &payer,
            &payee,
            10,
            "TNZO",
            &PaymentBinding {
                app_margin: Some(AppMargin {
                    app_wallet: Address::new([7; 32]),
                    margin_bps: 0x0102,
                }),
                ..PaymentBinding::default()
            },
        );
        assert_eq!(some.len(), none.len() + 36);
        assert_eq!(some[..none.len() - 1], none[..none.len() - 1]);
        let tail = &some[none.len() - 1..];
        assert_eq!(tail[0], 1);
        assert_eq!(&tail[1..33], &[7u8; 32]);
        assert_eq!(&tail[33..], &[2, 1, 0, 0]);
    }

    #[test]
    fn pay_ref_names_payee_binding_and_nonce() {
        let payee = Address::new([2u8; 32]);
        let b = PaymentBinding {
            request_digest: [3; 32],
            quote_digest: [4; 32],
            usd_e6: 1,
            app_margin: None,
        };
        let r = pay_ref(1, &payee, &b, "n");
        assert_ne!(
            r,
            pay_ref(
                1,
                &payee,
                &PaymentBinding {
                    app_margin: Some(AppMargin {
                        app_wallet: Address::new([7; 32]),
                        margin_bps: 1,
                    }),
                    ..b
                },
                "n"
            )
        );
        assert_ne!(r, pay_ref(2, &payee, &b, "n"));
        assert_ne!(r, pay_ref(1, &Address::new([5; 32]), &b, "n"));
        assert_ne!(
            r,
            pay_ref(
                1,
                &payee,
                &PaymentBinding {
                    request_digest: [6; 32],
                    ..b
                },
                "n"
            )
        );
        assert_ne!(
            r,
            pay_ref(
                1,
                &payee,
                &PaymentBinding {
                    quote_digest: [6; 32],
                    ..b
                },
                "n"
            )
        );
        assert_ne!(r, pay_ref(1, &payee, &b, "m"));
    }

    fn quote() -> Quote {
        Quote {
            payee: Address::new([2u8; 32]),
            request_digest: [3; 32],
            usd_e6: 1_500,
            accepts: vec![QuotedAsset {
                asset: TNZO_ASSET.into(),
                max_amount: 10,
            }],
            licence: "licence-1".into(),
            content_usage: "train-ai=n".into(),
            lines: vec![[7; 32]],
            expires_at_ms: 99,
            hardware: None,
        }
    }

    #[test]
    fn quote_digest_covers_price_licence_usage_and_lines() {
        let q = quote();
        let d = q.digest();
        let mut o = q.clone();
        o.usd_e6 += 1;
        assert_ne!(d, o.digest());
        let mut o = q.clone();
        o.licence.push('x');
        assert_ne!(d, o.digest());
        let mut o = q.clone();
        o.content_usage = "train-ai=y".into();
        assert_ne!(d, o.digest());
        let mut o = q.clone();
        o.lines.push([8; 32]);
        assert_ne!(d, o.digest());
        let mut o = q.clone();
        o.accepts[0].max_amount = 11;
        assert_ne!(d, o.digest());
        assert_eq!(q.binding().quote_digest, d);
        assert!(q.covers_line(&[7; 32]) && !q.covers_line(&[8; 32]));
        // Round-trips through JSON unchanged.
        let back: Quote = serde_json::from_str(&serde_json::to_string(&q).unwrap()).unwrap();
        assert_eq!(back.digest(), d);
    }

    #[test]
    fn receipt_digest_covers_body_and_inference_receipt() {
        let r = DeliveryReceipt {
            pay_ref: [1; 32],
            body_digest: [2; 32],
            inference_receipt: None,
            delivered_at_ms: 3,
            hardware: None,
        };
        let d = r.digest();
        // A stamp is inside the digest, so a served level cannot be swapped.
        let stamped = DeliveryReceipt {
            hardware: Some(crate::hardware_level::HardwareStamp::default()),
            ..r.clone()
        };
        assert_ne!(d, stamped.digest());
        let mut l1 = stamped.clone();
        l1.hardware.as_mut().unwrap().level = crate::hardware_level::HardwareLevel::L1;
        assert_ne!(stamped.digest(), l1.digest());
        assert_ne!(
            d,
            DeliveryReceipt {
                body_digest: [9; 32],
                ..r.clone()
            }
            .digest()
        );
        assert_ne!(
            d,
            DeliveryReceipt {
                inference_receipt: Some([0; 32]),
                ..r.clone()
            }
            .digest()
        );
        let back: DeliveryReceipt =
            serde_json::from_str(&serde_json::to_string(&r).unwrap()).unwrap();
        assert_eq!(back, r);
    }

    #[test]
    fn asset_strings_are_tnzo_or_a_token_id() {
        assert_eq!(asset_token_id("TNZO"), Ok(None));
        let id = format!("0x{}", "ab".repeat(32));
        assert_eq!(asset_token_id(&id), Ok(Some([0xab; 32])));
        assert!(asset_token_id("USDC").is_err());
        assert!(asset_token_id("0xabcd").is_err());
    }

    #[test]
    fn agent_voucher_digest_covers_signer_and_time() {
        let s = AgentVoucherSigner {
            agent_did: "a".into(),
            machine_did: "m".into(),
            as_of_ms: 1,
        };
        let z = [0u8; 32];
        let d = agent_voucher_digest(1, &[1; 32], 5, &z, &s);
        assert_ne!(d, agent_voucher_digest(1, &[1; 32], 6, &z, &s));
        assert_ne!(d, agent_voucher_digest(1, &[1; 32], 5, &[4; 32], &s));
        assert_ne!(
            d,
            agent_voucher_digest(
                1,
                &[1; 32],
                5,
                &z,
                &AgentVoucherSigner {
                    as_of_ms: 2,
                    ..s.clone()
                }
            )
        );
        assert_ne!(
            d,
            agent_voucher_digest(
                1,
                &[1; 32],
                5,
                &z,
                &AgentVoucherSigner {
                    machine_did: "n".into(),
                    ..s.clone()
                }
            )
        );
    }

    #[test]
    fn the_receipt_chain_is_ordered_and_binds_each_receipt() {
        let z = [0u8; 32];
        let a = receipt_chain_next(&z, &[1; 32]);
        let ab = receipt_chain_next(&a, &[2; 32]);
        let b = receipt_chain_next(&z, &[2; 32]);
        let ba = receipt_chain_next(&b, &[1; 32]);
        assert_ne!(ab, ba);
        assert_ne!(a, z);
        assert_eq!(
            ab,
            receipt_chain_next(&receipt_chain_next(&z, &[1; 32]), &[2; 32])
        );
    }

    #[test]
    fn length_prefixing_prevents_field_shifting() {
        let payer = Address::new([1u8; 32]);
        let payee = Address::new([2u8; 32]);
        assert_ne!(
            payment_authorization_preimage(
                1,
                "ab",
                &payer,
                &payee,
                1,
                "c",
                &PaymentBinding::default()
            ),
            payment_authorization_preimage(
                1,
                "a",
                &payer,
                &payee,
                1,
                "bc",
                &PaymentBinding::default()
            )
        );
    }

    #[test]
    fn reseller_legs_extend_the_preimage_only_when_present() {
        let (payer, payee) = (Address::new([1; 32]), Address::new([2; 32]));
        let b = PaymentBinding {
            request_digest: [3; 32],
            ..Default::default()
        };
        let plain = payment_authorization_preimage(1, "p", &payer, &payee, 10, "TNZO", &b);
        assert_eq!(
            payment_authorization_preimage_with_resellers(
                1,
                "p",
                &payer,
                &payee,
                10,
                "TNZO",
                &b,
                &[]
            ),
            plain
        );
        let leg = ResellerLeg {
            reseller: Address::new([4; 32]),
            commission_bps: 700,
        };
        let one = payment_authorization_preimage_with_resellers(
            1,
            "p",
            &payer,
            &payee,
            10,
            "TNZO",
            &b,
            &[leg],
        );
        let mut expect = plain.clone();
        expect.push(2);
        expect.extend_from_slice(&1u32.to_le_bytes());
        expect.extend_from_slice(&[4; 32]);
        expect.extend_from_slice(&700u32.to_le_bytes());
        assert_eq!(one, expect);
    }
}

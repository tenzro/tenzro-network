//! Hash-locked delivery at the node's HTTP-402 gates.
//!
//! A buyer that asks for `PAYMENT-DELIVERY: sealed` on a priced resource is
//! answered 402 with the response itself, encrypted under a fresh content key,
//! and the seller's signed [`SealedDelivery`] statement of it. The buyer funds
//! two escrows locked by the SHA-256 of that key: one to this node's payee for
//! the price less the network share, and one to the network treasury for the
//! share. It then asks the node to redeem them with
//! `tenzro_redeemSealedDelivery`. The node checks both escrows on chain and
//! claims the seller's with `ClaimEscrowPreimage`, which publishes the key in
//! the same transaction that pays; it then claims the treasury's escrow with
//! the published key. The buyer decrypts with the key from the claim.
//!
//! Neither side is exposed: the node never reveals the key without being paid
//! in the same transaction, and the buyer's funds leave only when the key they
//! were locked against is published.

use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use tenzro_payments::dvp::SealedDelivery;
use tenzro_payments::mpp::EscrowView;
use tenzro_settlement::escrow::EscrowAccount;
use tenzro_types::primitives::Address;
use tenzro_types::transaction::TransactionType;

use crate::node::TenzroNode;
use crate::payment_rails::Inclusion;

/// Request header a buyer sets to be answered with a sealed delivery.
pub const PAYMENT_DELIVERY_HEADER: &str = "payment-delivery";

/// The `PAYMENT-DELIVERY` value that asks for one.
pub const SEALED: &str = "sealed";

/// Largest response the node seals.
pub const MAX_SEALED_BODY: usize = 8 * 1024 * 1024;

/// How long a sealed offer stays redeemable.
pub const OFFER_TTL: Duration = Duration::from_secs(15 * 60);

/// How long before an escrow expires the node stops claiming it, so its claim
/// lands before the buyer could refund.
const EXPIRY_MARGIN_MS: i64 = 120_000;

/// How long a claim is waited for.
const CLAIM_WAIT: Duration = Duration::from_secs(20);

/// Whether the request asks for a sealed delivery.
pub fn wants_sealed(headers: &axum::http::HeaderMap) -> bool {
    headers
        .get(PAYMENT_DELIVERY_HEADER)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.trim().eq_ignore_ascii_case(SEALED))
}

/// An offer the node made and has not been paid for.
struct Offer {
    key: [u8; 32],
    delivery: SealedDelivery,
    payee: Address,
    made: Instant,
}

/// The node's open sealed offers, by lock. The content keys are the seller's
/// own secrets until it is paid; nothing here is anyone's balance.
#[derive(Default)]
pub struct SealedOffers {
    offers: DashMap<[u8; 32], Offer>,
}

impl std::fmt::Debug for SealedOffers {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SealedOffers")
            .field("open", &self.offers.len())
            .finish()
    }
}

impl SealedOffers {
    /// Seal `body` as `resource` for `price`, paid to `payee`, and keep the
    /// key until the offer is redeemed or lapses.
    pub fn offer(
        &self,
        resource: &str,
        body: &[u8],
        price: u128,
        asset: &str,
        payee: Address,
        network_share_bps: u64,
        signer: &dyn tenzro_crypto::batch::RecordSigner,
    ) -> tenzro_payments::Result<SealedDelivery> {
        self.offers.retain(|_, o| o.made.elapsed() < OFFER_TTL);
        let (delivery, key) = SealedDelivery::seal(
            resource,
            body,
            price,
            asset,
            &hex::encode(payee.as_bytes()),
            network_share_bps,
            signer,
        )?;
        self.offers.insert(
            delivery.lock()?,
            Offer {
                key,
                delivery: delivery.clone(),
                payee,
                made: Instant::now(),
            },
        );
        Ok(delivery)
    }

    /// Check that `seller` and `network` pay the open offer they are locked
    /// by, at `now_ms`. Returns the lock, the content key, and whether the
    /// network is owed a share.
    pub fn check(
        &self,
        seller: &EscrowAccount,
        network: Option<&EscrowAccount>,
        now_ms: i64,
    ) -> Result<([u8; 32], [u8; 32], bool), String> {
        let seller = EscrowView::from_account(seller);
        let network = network.map(EscrowView::from_account);
        let lock = seller.hash_lock().ok_or("the escrow is not hash-locked")?;
        let offer = self
            .offers
            .get(&lock)
            .filter(|o| o.made.elapsed() < OFFER_TTL)
            .ok_or("no open offer is locked by this escrow's hash")?;
        let d = &offer.delivery;
        d.check_locked(
            &offer.payee,
            &seller,
            network.as_ref(),
            now_ms,
            EXPIRY_MARGIN_MS,
        )?;
        Ok((lock, offer.key, d.network_share > 0))
    }

    /// Forget a redeemed offer.
    pub fn close(&self, lock: &[u8; 32]) {
        self.offers.remove(lock);
    }
}

/// Answer a sealed-delivery request for `resource` at `price` with `body`
/// sealed: a 402 carrying the ciphertext and the node's signed statement.
pub fn sealed_response(
    node: &Arc<TenzroNode>,
    resource: &str,
    body: &[u8],
    price: u128,
) -> axum::response::Response {
    use axum::http::StatusCode;
    use axum::response::IntoResponse;
    let refuse = |status: StatusCode, message: String| {
        (
            status,
            axum::Json(
                serde_json::json!({ "error": "sealed_delivery_unavailable", "message": message }),
            ),
        )
            .into_response()
    };
    if body.len() > MAX_SEALED_BODY {
        return refuse(
            StatusCode::PAYLOAD_TOO_LARGE,
            format!("responses over {MAX_SEALED_BODY} bytes are not sealed; pay for it directly"),
        );
    }
    let Some(signer) = node.records() else {
        return refuse(
            StatusCode::SERVICE_UNAVAILABLE,
            "this node has no key to sign a delivery with".to_string(),
        );
    };
    let payments = &node.config().payments;
    let payee = match tenzro_payments::payer_auth::parse_tenzro_address(&payments.recipient) {
        Ok(a) => a,
        Err(e) => {
            return refuse(
                StatusCode::SERVICE_UNAVAILABLE,
                format!("this node names no payee to be paid at: {e}"),
            );
        }
    };
    match node.sealed_offers().offer(
        resource,
        body,
        price,
        &payments.default_asset,
        payee,
        crate::rpc::chain_state_of(node)
            .map(|chain| tenzro_vm::native::network_param(&chain, tenzro_vm::native::economy::HTTP402_NETWORK_SHARE_PARAM))
            .unwrap_or_else(|| tenzro_vm::governance::genesis_param(tenzro_vm::native::economy::HTTP402_NETWORK_SHARE_PARAM)),
        signer.as_ref(),
    ) {
        Ok(delivery) => (
            StatusCode::PAYMENT_REQUIRED,
            axum::Json(serde_json::json!({
                "error": "payment_required",
                "message": "Sealed delivery: fund one HashLock escrow for seller_amount to payee and one \
                            for network_share to network_payee, both locked by key_hash, then call \
                            tenzro_redeemSealedDelivery. The claim that pays publishes the key.",
                "delivery": delivery,
                "seller_amount": delivery.seller_amount().to_string(),
            })),
        )
            .into_response(),
        Err(e) => refuse(StatusCode::INTERNAL_SERVER_ERROR, format!("sealing failed: {e}")),
    }
}

/// What a redemption did.
#[derive(Debug, Clone, serde::Serialize)]
pub struct Redemption {
    /// The claim that paid the seller and published the key.
    pub seller_claim_tx: String,
    /// The claim that paid the network its share, if one was owed.
    pub network_claim_tx: Option<String>,
    /// The content key (hex), as the seller's claim published it.
    pub key: String,
}

/// Redeem the offer `seller_escrow` (and `network_escrow`) pay for: check
/// both on chain, claim the seller's with the key, then the network's.
pub async fn redeem(
    node: &Arc<TenzroNode>,
    seller_escrow: [u8; 32],
    network_escrow: Option<[u8; 32]>,
) -> Result<Redemption, String> {
    let storage = node
        .storage()
        .cloned()
        .ok_or("this node has no chain state to read escrows from")?;
    let submitter = node
        .ledger_submitter()
        .cloned()
        .ok_or("this node cannot submit transactions")?;
    let state = tenzro_vm::StateAdapter::with_storage(storage as Arc<dyn tenzro_storage::KvStore>);
    let read = |id: &[u8; 32]| {
        tenzro_vm::native::read_escrow(&state, id)
            .ok_or_else(|| format!("no escrow {} on chain", hex::encode(id)))
    };
    let seller = read(&seller_escrow)?;
    let network = network_escrow.map(|id| read(&id)).transpose()?;
    let now = chrono::Utc::now().timestamp_millis();
    let offers = node.sealed_offers();
    let (lock, key, owes_share) = offers.check(&seller, network.as_ref(), now)?;

    let claim = |escrow_id: [u8; 32]| {
        let submitter = submitter.clone();
        async move {
            let hash = submitter
                .submit(
                    Address::zero(),
                    TransactionType::ClaimEscrowPreimage {
                        escrow_id,
                        preimage: key.to_vec(),
                    },
                )
                .await?;
            match submitter.await_inclusion(&hash, CLAIM_WAIT).await {
                Inclusion::Executed(r) if r.success => Ok(hash),
                Inclusion::Executed(r) => Err(format!(
                    "claim {hash} reverted: {}",
                    r.revert_reason.unwrap_or_default()
                )),
                Inclusion::Waiting => Err(format!("claim {hash} has not executed yet")),
            }
        }
    };
    let seller_claim_tx = claim(seller_escrow).await?;
    offers.close(&lock);
    // The key is public from here; the network's escrow is claimable by
    // anyone, and this node claims it at once.
    let network_claim_tx = match network_escrow {
        Some(id) if owes_share => Some(claim(id).await?),
        _ => None,
    };
    Ok(Redemption {
        seller_claim_tx,
        network_claim_tx,
        key: hex::encode(key),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tenzro_settlement::escrow::EscrowStatus;
    use tenzro_types::asset::AssetId;
    use tenzro_types::primitives::Timestamp;
    use tenzro_types::settlement::ReleaseConditions;

    const NOW: i64 = 1_800_000_000_000;

    fn signer() -> tenzro_crypto::batch::ImmediateRecordSigner {
        tenzro_crypto::batch::ImmediateRecordSigner::new(Arc::new(tenzro_crypto::composite::testing::TestHybridSigner::random()))
    }

    fn escrow(payee: Address, amount: u128, lock: [u8; 32]) -> EscrowAccount {
        EscrowAccount {
            escrow_id: "e".into(),
            payer: Address::new([1u8; 32]),
            payee,
            amount,
            asset_id: AssetId::tnzo(),
            usd_e6: 0,
            created_at: Timestamp::new(NOW),
            expires_at: Timestamp::new(NOW + 3_600_000),
            status: EscrowStatus::Funded,
            release_conditions: ReleaseConditions::HashLock { hash: lock },
            claimed: 0,
            approved_by: None,
            reference: None,
        }
    }

    #[test]
    fn an_offer_is_redeemable_only_when_both_legs_pay_it_in_full() {
        let offers = SealedOffers::default();
        let seller = Address::new([2u8; 32]);
        let treasury = tenzro_types::network_treasury_address();
        let d = offers
            .offer(
                "/sites/s/paid",
                b"the page",
                1_000,
                "TNZO",
                seller,
                1_000,
                &signer(),
            )
            .unwrap();
        let lock = d.lock().unwrap();
        assert_eq!((d.seller_amount(), d.network_share), (900, 100));

        let good_seller = escrow(seller, 900, lock);
        let good_network = escrow(treasury, 100, lock);
        let (got_lock, key, owes) = offers
            .check(&good_seller, Some(&good_network), NOW)
            .unwrap();
        assert_eq!(got_lock, lock);
        assert!(owes);
        assert_eq!(d.open(&key).unwrap(), b"the page");

        // Short, misdirected, other-lock, missing and late legs are refused.
        assert!(
            offers
                .check(&escrow(seller, 899, lock), Some(&good_network), NOW)
                .is_err()
        );
        assert!(
            offers
                .check(&escrow(treasury, 900, lock), Some(&good_network), NOW)
                .is_err()
        );
        assert!(
            offers
                .check(&good_seller, Some(&escrow(treasury, 99, lock)), NOW)
                .is_err()
        );
        assert!(
            offers
                .check(&good_seller, Some(&escrow(seller, 100, lock)), NOW)
                .is_err()
        );
        assert!(
            offers
                .check(&good_seller, Some(&escrow(treasury, 100, [9u8; 32])), NOW)
                .is_err()
        );
        assert!(offers.check(&good_seller, None, NOW).is_err());
        assert!(
            offers
                .check(&escrow(seller, 900, [9u8; 32]), Some(&good_network), NOW)
                .is_err()
        );
        assert!(
            offers
                .check(&good_seller, Some(&good_network), NOW + 3_590_000)
                .is_err()
        );
        let mut refunded = good_seller.clone();
        refunded.status = EscrowStatus::Refunded;
        assert!(offers.check(&refunded, Some(&good_network), NOW).is_err());

        // Redeemed once.
        offers.close(&lock);
        assert!(
            offers
                .check(&good_seller, Some(&good_network), NOW)
                .is_err()
        );
    }

    #[test]
    fn the_sealed_header_is_recognised() {
        let mut h = axum::http::HeaderMap::new();
        assert!(!wants_sealed(&h));
        h.insert(PAYMENT_DELIVERY_HEADER, "Sealed".parse().unwrap());
        assert!(wants_sealed(&h));
    }
}

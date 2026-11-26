//! Compute rental: provider bonds, compute claims, the observed price feed and
//! renting capacity.
//!
//! A provider posts a compute bond for its machine DID. Validators probe every
//! bonded provider and freeze one SLA verdict per provider and hour; those
//! availability verdicts are what every payment here settles on.
//!
//! - Renting capacity now is a stream escrow: a signed `CreateEscrow` whose
//!   release is `Stream { rate_per_epoch, epoch_ms }` and whose payee is the
//!   provider's bonded address ([`ComputeClient::rent`]). It accrues one epoch
//!   at a time; an hour the validators judged the provider unavailable is never
//!   paid out of it and returns to the renter when the stream is stopped.
//! - Buying capacity ahead is a compute claim, written and bought with the
//!   `ComputeClaim` transaction and read here ([`ComputeClient::get_claim`]).
//!   A storage claim is the same record with `storage_descriptor` set.

use std::sync::Arc;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::error::{SdkError, SdkResult};
use crate::rpc::RpcClient;
use crate::typed_tx::{TxKind, TypedTransaction, TypedTxClient};
use crate::types::Address;
use crate::wallet::HybridSigner;

/// The hour validators freeze one SLA verdict for, in milliseconds: the epoch
/// length a rental streams over unless the parties choose another.
pub const SLA_EPOCH_MS: u64 = 3_600_000;

/// Compute rental client: bonds, claims, the price feed and renting.
#[derive(Clone)]
pub struct ComputeClient {
    rpc: Arc<RpcClient>,
}

impl ComputeClient {
    /// Creates a new compute client.
    pub fn new(rpc: Arc<RpcClient>) -> Self {
        Self { rpc }
    }

    async fn call<T: serde::de::DeserializeOwned>(
        &self,
        method: &str,
        params: Value,
    ) -> SdkResult<T> {
        let value = self.rpc.call(method, params).await?;
        serde_json::from_value(value).map_err(|e| SdkError::RpcError(format!("{method}: {e}")))
    }

    /// The governed compute bond minimum and withdrawal cooldown
    /// (`tenzro_computeBondParams`).
    ///
    /// # Example
    ///
    /// ```no_run
    /// # async fn run() -> Result<(), Box<dyn std::error::Error>> {
    /// # let client = tenzro_sdk::network::connect_to_network(&tenzro_sdk::network::NetworkOptions::default()).await?;
    /// let params = client.compute().bond_params().await?;
    /// println!("minimum bond: {} wei", params.min_bond_wei);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn bond_params(&self) -> SdkResult<ComputeBondParams> {
        self.call("tenzro_computeBondParams", json!([])).await
    }

    /// The compute bond posted for `provider_did`, or `None` when that
    /// provider has never posted one (`tenzro_getComputeBond`).
    pub async fn get_bond(&self, provider_did: &str) -> SdkResult<Option<ComputeBond>> {
        self.call(
            "tenzro_getComputeBond",
            json!([{ "provider_did": provider_did }]),
        )
        .await
    }

    /// Every compute bond on chain (`tenzro_listComputeBonds`).
    pub async fn list_bonds(&self) -> SdkResult<Vec<ComputeBond>> {
        let list: ComputeBondList = self.call("tenzro_listComputeBonds", json!([])).await?;
        Ok(list.bonds)
    }

    /// One compute claim from chain state (`tenzro_computeGetClaim`). The node
    /// answers an error when there is no claim with this id.
    pub async fn get_claim(&self, claim_id: &str) -> SdkResult<ComputeClaim> {
        self.call("tenzro_computeGetClaim", json!({ "claim_id": claim_id }))
            .await
    }

    /// The claims `party` (hex address) has written, held or been pledged,
    /// oldest first (`tenzro_computeListClaims`); `limit` defaults to 100 on
    /// the node, at most 1000.
    pub async fn list_claims(
        &self,
        party: &str,
        limit: Option<u64>,
    ) -> SdkResult<ComputeClaimList> {
        let mut params = json!({ "party": party });
        if let Some(limit) = limit {
            params["limit"] = json!(limit);
        }
        self.call("tenzro_computeListClaims", params).await
    }

    /// What validators observed each provider charge, how fast it served and
    /// how often it failed (`tenzro_computePriceFeed`). Hardware class and
    /// region are the providers' announced claims; the prices, latencies and
    /// success rates are validator observations.
    pub async fn price_feed(&self, query: &PriceFeedQuery) -> SdkResult<PriceFeed> {
        self.call("tenzro_computePriceFeed", query.params()).await
    }

    /// Rent capacity from a bonded provider: sign and submit the stream
    /// escrow [`RentRequest::transaction`] builds. Returns the node's answer to
    /// `tenzro_sendRawTransaction`. The provider draws each accrued epoch
    /// with `ClaimEscrowStream`; the renter stops the rental with
    /// `RefundEscrow`.
    pub async fn rent(&self, signer: &dyn HybridSigner, request: &RentRequest) -> SdkResult<Value> {
        let tx = request.transaction(now_ms()?)?;
        TypedTxClient::new(self.rpc.clone()).send(signer, &tx).await
    }

    /// Moves a rental off an operator that is down: refunds what the stream
    /// escrow `down_escrow_id` still holds, then opens the stream `next`
    /// describes with another operator. What the first operator drew for
    /// epochs it served stays its own; the next operator is paid only for the
    /// epochs it then draws. Returns the node's answer to the rental.
    pub async fn fail_over_rental(
        &self,
        signer: &dyn HybridSigner,
        down_escrow_id: &str,
        next: &RentRequest,
    ) -> SdkResult<Value> {
        let (refund, rent) = failover_transactions(down_escrow_id, next, now_ms()?)?;
        let client = TypedTxClient::new(self.rpc.clone());
        client.send(signer, &refund).await?;
        client.send(signer, &rent).await
    }
}

fn now_ms() -> SdkResult<u64> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .map_err(|e| SdkError::InvalidParameter(e.to_string()))
}

/// The two transactions that move a rental: the refund of the stream escrow
/// of the operator that is down, then the stream to the next operator.
pub fn failover_transactions(
    down_escrow_id: &str,
    next: &RentRequest,
    now_ms: u64,
) -> SdkResult<(TypedTransaction, TypedTransaction)> {
    let id: [u8; 32] = hex::decode(down_escrow_id.trim_start_matches("0x"))
        .ok()
        .and_then(|b| b.try_into().ok())
        .ok_or_else(|| SdkError::InvalidParameter("an escrow id is 32 bytes of hex".into()))?;
    let refund = TypedTransaction::new(TxKind::RefundEscrow, json!({ "escrow_id": id.to_vec() }))?;
    Ok((refund, next.transaction(now_ms)?))
}

/// A u128 the way the node encodes it: a JSON number up to `u64::MAX`, a
/// decimal string above it. The signing payload the node returns must decode
/// to exactly what was built.
fn u128_json(v: u128) -> Value {
    match u64::try_from(v) {
        Ok(n) => json!(n),
        Err(_) => json!(v.to_string()),
    }
}

/// The terms of a rental: who is paid, at what rate per epoch, for how many
/// epochs.
#[derive(Debug, Clone, PartialEq)]
pub struct RentRequest {
    /// The provider's bonded address: the account that posted its compute
    /// bond. Only a stream to that address is judged by its SLA verdicts.
    pub provider_address: Address,
    /// Paid per elapsed epoch, smallest unit of `asset_id`.
    pub rate_per_epoch: u128,
    /// Epochs rented; the escrow locks `rate_per_epoch * epochs`.
    pub epochs: u64,
    /// Epoch length in milliseconds; [`SLA_EPOCH_MS`] by default.
    pub epoch_ms: u64,
    /// `TNZO` or a token id (`0x`-prefixed hex).
    pub asset_id: String,
    /// USD price of the amount in micro-units; required for an asset other
    /// than TNZO.
    pub usd_e6: u64,
    /// An opaque 32-byte reference the application chose, so it can find the
    /// rental again with `tenzro_listEscrowsByPayer`.
    pub reference: Option<[u8; 32]>,
}

impl RentRequest {
    /// A TNZO rental of `epochs` hours at `rate_per_epoch` wei per hour.
    pub fn new(provider_address: Address, rate_per_epoch: u128, epochs: u64) -> Self {
        Self {
            provider_address,
            rate_per_epoch,
            epochs,
            epoch_ms: SLA_EPOCH_MS,
            asset_id: "TNZO".to_string(),
            usd_e6: 0,
            reference: None,
        }
    }

    /// A TNZO rental from the provider that posted `bond`.
    pub fn for_bond(bond: &ComputeBond, rate_per_epoch: u128, epochs: u64) -> SdkResult<Self> {
        let address = Address::from_hex(&bond.provider_address).ok_or_else(|| {
            SdkError::InvalidParameter(format!(
                "the bond's provider address {} is not an address",
                bond.provider_address
            ))
        })?;
        Ok(Self::new(address, rate_per_epoch, epochs))
    }

    /// Stream over epochs of `epoch_ms` milliseconds instead of an hour.
    pub fn epoch_ms(mut self, epoch_ms: u64) -> Self {
        self.epoch_ms = epoch_ms;
        self
    }

    /// Pay in `asset_id`, priced at `usd_e6` micro-USD for the whole amount.
    pub fn asset(mut self, asset_id: impl Into<String>, usd_e6: u64) -> Self {
        self.asset_id = asset_id.into();
        self.usd_e6 = usd_e6;
        self
    }

    /// Carry `reference` on the escrow.
    pub fn reference(mut self, reference: [u8; 32]) -> Self {
        self.reference = Some(reference);
        self
    }

    /// The amount the escrow locks: `rate_per_epoch * epochs`.
    pub fn amount(&self) -> SdkResult<u128> {
        self.rate_per_epoch
            .checked_mul(u128::from(self.epochs))
            .ok_or_else(|| SdkError::InvalidParameter("rate_per_epoch * epochs overflows".into()))
    }

    /// The `CreateEscrow` transaction for this rental, signed at `now_ms`.
    ///
    /// The stream accrues from the block that funds it, not from `now_ms`,
    /// so the escrow expires one epoch after the term would end if it were
    /// funded now: the funding block has that long to land and the whole term
    /// still accrues. Accrual never exceeds the locked amount, so the extra
    /// epoch pays nothing more.
    pub fn transaction(&self, now_ms: u64) -> SdkResult<TypedTransaction> {
        if self.rate_per_epoch == 0 || self.epochs == 0 || self.epoch_ms == 0 {
            return Err(SdkError::InvalidParameter(
                "a rental pays a positive rate over a positive number of positive epochs".into(),
            ));
        }
        let amount = self.amount()?;
        let expires_at = self
            .epochs
            .checked_add(1)
            .and_then(|e| e.checked_mul(self.epoch_ms))
            .and_then(|t| t.checked_add(now_ms))
            .ok_or_else(|| SdkError::InvalidParameter("the rental term overflows".into()))?;
        TypedTransaction::new(
            TxKind::CreateEscrow,
            json!({
                "payee": self.provider_address.0,
                "amount": u128_json(amount),
                "asset_id": self.asset_id,
                "usd_e6": self.usd_e6,
                "expires_at": expires_at,
                "release_conditions": {
                    "Stream": {
                        "rate_per_epoch": u128_json(self.rate_per_epoch),
                        "epoch_ms": self.epoch_ms,
                    }
                },
                "reference": self.reference.map(hex::encode),
            }),
        )
    }
}

/// A provider's compute bond, as chain state records it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ComputeBond {
    /// DID of the provider the bond is posted for.
    pub provider_did: String,
    /// The account that posted the bond: the payee of a rental, and where a
    /// returned bond goes.
    pub provider_address: String,
    /// Bonded amount in wei, decimal.
    pub amount: String,
    /// `Active`, `Cooldown`, `Returned` or `Slashed`.
    pub status: String,
    /// Unix milliseconds at which a withdrawal may be finalized; set only in
    /// `Cooldown`.
    pub cooldown_until: Option<i64>,
    /// The bond vault address, hex.
    pub vault: String,
    /// Whether the bond backs its provider: active and at least the governed
    /// minimum.
    pub is_eligible: bool,
    /// Wei that counts toward admission: zero once the bond leaves `Active`.
    pub effective_amount: String,
}

#[derive(Deserialize)]
struct ComputeBondList {
    bonds: Vec<ComputeBond>,
}

/// The governed dials a provider needs before it posts a compute bond.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ComputeBondParams {
    /// The governed compute bond minimum in wei, decimal.
    pub min_bond_wei: String,
    /// Milliseconds a withdrawal sits in `Cooldown` before it can be
    /// finalized.
    pub cooldown_ms: i64,
}

/// Where a compute claim is in its life.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "state")]
pub enum ClaimState {
    /// Written, awaiting a buyer.
    Offered,
    /// Bought; settling hour by hour.
    Held,
    /// Every hour settled.
    Delivered,
    /// Withdrawn before anyone bought it.
    Cancelled,
    /// Nobody bought it before delivery; the collateral returned.
    Lapsed,
}

/// A compute claim: capacity a bonded provider promised for hour-aligned
/// terms, settled each hour on the SLA verdict for its bond.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ComputeClaim {
    /// The claim id.
    pub claim_id: String,
    /// Hex of the writer's address.
    pub writer: String,
    /// Hex of the holder's address, once bought.
    pub holder: Option<String>,
    /// `1` cpu, `2` consumer GPU, `3` datacenter GPU, `4` multi-accelerator:
    /// the writer's statement.
    pub hardware_class: u8,
    /// ISO 3166-1 alpha-2 region, or empty.
    pub region: String,
    /// First hour of delivery, Unix milliseconds.
    pub delivery_start_ms: i64,
    /// Hours delivered.
    pub epochs: u64,
    /// Price per hour, wei.
    #[serde(with = "crate::types::u128_wire")]
    pub strike_per_epoch: u128,
    /// The compute bond (or storage stake) delivering the claim.
    pub provider_did: String,
    /// For a storage claim: hex SHA-256 of the object descriptor the bond
    /// keeps retrievable.
    #[serde(default)]
    pub storage_descriptor: Option<String>,
    /// The registered unit reserved capacity is stated in, for a claim on
    /// metered capacity.
    #[serde(default)]
    pub unit: Option<String>,
    /// Units of `unit` reserved per hour.
    #[serde(default, with = "crate::types::u128_wire")]
    pub units_per_epoch: u128,
    /// Hours settled so far.
    pub epochs_settled: u64,
    /// Writer collateral still in the vault, wei.
    #[serde(with = "crate::types::u128_wire")]
    pub collateral: u128,
    /// Holder payment still in the vault, wei.
    #[serde(with = "crate::types::u128_wire")]
    pub payment: u128,
    /// Where the claim is in its life.
    pub state: ClaimState,
    /// What a buyer pays: `strike_per_epoch * epochs`, decimal.
    pub total_strike: String,
    /// End of delivery, Unix milliseconds.
    pub delivery_end_ms: i64,
    /// The claim's vault address, hex.
    pub vault: String,
}

/// The claims one party is a side of.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ComputeClaimList {
    /// Every claim of the party, beyond the page returned.
    pub total: u64,
    /// The claims returned, oldest first.
    pub claims: Vec<ComputeClaim>,
}

/// A filter on the observed price feed. Every field is optional.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct PriceFeedQuery {
    /// Only this model.
    pub model_id: Option<String>,
    /// Only this announced hardware class: `cpu`, `consumer_gpu`,
    /// `datacenter_gpu` or `multi_accelerator`.
    pub hardware_class: Option<String>,
    /// Only this announced region.
    pub region: Option<String>,
    /// Only entries at least two distinct validators observed.
    pub attested_only: bool,
    /// Most entries to return (node default 100, at most 1000).
    pub limit: Option<u64>,
}

impl PriceFeedQuery {
    fn params(&self) -> Value {
        let mut params = serde_json::Map::new();
        for (key, value) in [
            ("model_id", &self.model_id),
            ("hardware_class", &self.hardware_class),
            ("region", &self.region),
        ] {
            if let Some(v) = value {
                params.insert(key.to_string(), json!(v));
            }
        }
        if self.attested_only {
            params.insert("attested_only".to_string(), json!(true));
        }
        if let Some(limit) = self.limit {
            params.insert("limit".to_string(), json!(limit));
        }
        Value::Object(params)
    }
}

/// One provider and model in the price feed.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PriceFeedEntry {
    /// The provider's address, hex.
    pub provider: String,
    /// The model served.
    pub model_id: String,
    /// The provider's announced hardware class (a claim).
    pub hardware_class: String,
    /// The provider's announced region (a claim).
    pub region: String,
    /// Observations in the window.
    pub observations: u64,
    /// Distinct validators that observed it.
    pub distinct_observers: u64,
    /// Whether enough distinct validators observed it to enter the index.
    pub attested: bool,
    /// Observed success rate, basis points.
    pub success_rate_bps: u32,
    /// Observed median latency, ms.
    pub latency_p50_ms: Option<u64>,
    /// Observed 90th-percentile latency, ms.
    pub latency_p90_ms: Option<u64>,
    /// Observed price per 1000 output tokens, wei, decimal.
    pub price_per_1k_output_tokens_wei: Option<String>,
    /// Observed price per second of served compute, wei, decimal.
    pub price_per_compute_second_wei: Option<String>,
    /// Latest observation, Unix milliseconds.
    pub last_observed_ms: i64,
}

/// The observed price feed.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PriceFeed {
    /// The rolling observation window, ms.
    pub window_ms: i64,
    /// Distinct validators an entry needs to be attested.
    pub min_distinct_observers: u64,
    /// Entries matching the query, beyond the page returned.
    pub total: u64,
    /// The entries returned.
    pub entries: Vec<PriceFeedEntry>,
    /// Which fields are claims and which are observations.
    pub claims_note: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_rental_is_a_stream_escrow_to_the_bonded_address() {
        let tx = RentRequest::new(Address([5; 32]), 7, 3)
            .reference([9; 32])
            .transaction(1_000)
            .unwrap();
        assert_eq!(tx.kind, TxKind::CreateEscrow);
        assert_eq!(
            tx.tx_type(),
            json!({ "CreateEscrow": {
                "payee": ([5u8; 32]),
                "amount": 21,
                "asset_id": "TNZO",
                "usd_e6": 0,
                "expires_at": 1_000 + 4 * SLA_EPOCH_MS,
                "release_conditions": { "Stream": { "rate_per_epoch": 7, "epoch_ms": SLA_EPOCH_MS } },
                "reference": hex::encode([9u8; 32]),
            }})
        );
    }

    #[test]
    fn amounts_are_encoded_as_the_node_encodes_them() {
        let rate = u128::from(u64::MAX);
        let tx = RentRequest::new(Address([5; 32]), rate, 2)
            .transaction(0)
            .unwrap();
        let fields = &tx.fields;
        assert_eq!(fields["amount"], json!((rate * 2).to_string()));
        assert_eq!(
            fields["release_conditions"]["Stream"]["rate_per_epoch"],
            json!(u64::MAX)
        );
        assert_eq!(fields["reference"], Value::Null);
    }

    #[test]
    fn a_rental_of_nothing_is_refused() {
        for r in [
            RentRequest::new(Address([5; 32]), 0, 3),
            RentRequest::new(Address([5; 32]), 7, 0),
            RentRequest::new(Address([5; 32]), 7, 3).epoch_ms(0),
        ] {
            assert!(r.transaction(0).is_err());
        }
        assert!(
            RentRequest::new(Address([5; 32]), u128::MAX, 2)
                .transaction(0)
                .is_err()
        );
    }

    #[test]
    fn a_rental_from_a_bond_pays_its_provider_address() {
        let bond = ComputeBond {
            provider_did: "did:tenzro:machine:a".into(),
            provider_address: format!("0x{}", "ab".repeat(32)),
            amount: "1".into(),
            status: "Active".into(),
            cooldown_until: None,
            vault: "0x00".into(),
            is_eligible: true,
            effective_amount: "1".into(),
        };
        let r = RentRequest::for_bond(&bond, 1, 1).unwrap();
        assert_eq!(r.provider_address, Address([0xab; 32]));
        let bad = ComputeBond {
            provider_address: "nope".into(),
            ..bond
        };
        assert!(RentRequest::for_bond(&bad, 1, 1).is_err());
    }

    #[test]
    fn the_price_feed_query_sends_only_what_is_set() {
        assert_eq!(PriceFeedQuery::default().params(), json!({}));
        let q = PriceFeedQuery {
            model_id: Some("m".into()),
            hardware_class: Some("cpu".into()),
            region: None,
            attested_only: true,
            limit: Some(5),
        };
        assert_eq!(
            q.params(),
            json!({ "model_id": "m", "hardware_class": "cpu", "attested_only": true, "limit": 5 })
        );
    }
}

#[cfg(test)]
mod failover_tests {
    use super::*;

    #[test]
    fn a_rental_moves_by_refunding_the_down_operator_then_streaming_to_the_next() {
        let down = hex::encode([5u8; 32]);
        let next = RentRequest::new(Address([4; 32]), 7, 3);
        let (refund, rent) = failover_transactions(&down, &next, 1_000).unwrap();
        assert_eq!(refund.kind, TxKind::RefundEscrow);
        assert_eq!(refund.fields["escrow_id"], json!([5u8; 32].to_vec()));
        assert_eq!(rent.kind, TxKind::CreateEscrow);
        assert_eq!(rent.fields["payee"], json!([4u8; 32].to_vec()));
        assert_eq!(rent.fields["amount"], json!(21));
        assert!(failover_transactions("12", &next, 1_000).is_err());
    }
}

//! Metered work, price cards and the generic registry.
//!
//! - [`BillableUnits`]: what a call consumed, as a map of meter key (a unit
//!   id, optionally `@tier`) to quantity.
//! - [`RateCard`]: a price per meter key, and [`RateCard::charge_wei`], the
//!   same pricing rule the node applies to the calls it serves, so a caller
//!   can quote and check a charge itself.
//! - [`RegistryClient`]: the generic registry, where units, service types,
//!   price cards and applications are published as entries, listed by kind.
//! - [`receipt_chain_next`]: the head of the receipt chain a voucher binds.

use crate::error::{SdkError, SdkResult};
use crate::rpc::RpcClient;
use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::sync::Arc;

/// What one call consumed: quantities under meter keys. A zero quantity is
/// never stored, so an absent key and a zero one are the same meter.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BillableUnits(BTreeMap<String, u128>);

/// Whether `key` is a meter key: a unit id of 1..=40 `[a-z0-9_]` starting
/// with a letter, optionally `@` and a tier of 1..=24 `[a-z0-9_]`.
pub fn valid_meter_key(key: &str) -> bool {
    let word = |s: &str, max: usize| {
        !s.is_empty()
            && s.len() <= max
            && s.bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
    };
    let (unit, tier) = match key.split_once('@') {
        Some((u, t)) => (u, Some(t)),
        None => (key, None),
    };
    word(unit, 40) && unit.as_bytes()[0].is_ascii_lowercase() && tier.is_none_or(|t| word(t, 24))
}

impl BillableUnits {
    /// An empty meter.
    pub fn new() -> Self {
        Self::default()
    }

    /// The quantity under `key`, zero when absent.
    pub fn get(&self, key: &str) -> u128 {
        self.0.get(key).copied().unwrap_or(0)
    }

    /// Record `quantity` under `key`; zero removes it.
    pub fn set(&mut self, key: &str, quantity: u128) -> SdkResult<()> {
        if !valid_meter_key(key) {
            return Err(SdkError::InvalidParameter(format!(
                "'{key}' is not a meter key"
            )));
        }
        if quantity == 0 {
            self.0.remove(key);
        } else {
            self.0.insert(key.to_string(), quantity);
        }
        Ok(())
    }

    /// Every key with its quantity, in key order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, u128)> {
        self.0.iter().map(|(k, v)| (k.as_str(), *v))
    }

    /// The quantity of `unit` across all its tiers.
    pub fn unit_total(&self, unit: &str) -> u128 {
        self.iter()
            .filter(|(k, _)| k.split('@').next() == Some(unit))
            .fold(0u128, |a, (_, v)| a.saturating_add(v))
    }

    /// Prompt tokens fresh plus served from cache.
    pub fn prompt_tokens(&self) -> u128 {
        self.unit_total("input_tokens") + self.unit_total("cached_read_tokens")
    }

    /// Tokens generated.
    pub fn output_tokens(&self) -> u128 {
        self.unit_total("output_tokens")
    }
}

impl Serialize for BillableUnits {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let m: BTreeMap<&str, Value> = self
            .iter()
            .map(|(k, v)| {
                let n = if v <= u64::MAX as u128 {
                    json!(v as u64)
                } else {
                    json!(v.to_string())
                };
                (k, n)
            })
            .collect();
        m.serialize(s)
    }
}

impl<'de> Deserialize<'de> for BillableUnits {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let raw = BTreeMap::<String, Value>::deserialize(d)?;
        let mut out = BillableUnits::new();
        for (k, v) in raw {
            let q = match &v {
                Value::Number(n) => n.as_u64().map(u128::from),
                Value::String(s) => s.parse().ok(),
                _ => None,
            }
            .ok_or_else(|| D::Error::custom(format!("'{k}' is not a whole quantity")))?;
            out.set(&k, q).map_err(D::Error::custom)?;
        }
        Ok(out)
    }
}

/// What a card's prices are denominated in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Denom {
    /// Billionths of a US dollar, settled in TNZO at the chain's rate.
    #[default]
    NanoUsd,
    /// TNZO base units.
    Wei,
}

/// The price of one meter key: `price` per `10^per_exp` units.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rate {
    #[serde(with = "crate::types::u128_wire")]
    pub price: u128,
    #[serde(default)]
    pub per_exp: u8,
}

/// A price list: a price per meter key and a per-call minimum.
#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct RateCard {
    #[serde(default)]
    pub denom: Denom,
    #[serde(default)]
    pub lines: BTreeMap<String, Rate>,
    #[serde(default, with = "crate::types::u128_wire")]
    pub min_charge: u128,
}

/// A provider's card for one model, as its registry entry carries it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PriceCard {
    pub model_id: String,
    pub model_hash: String,
    pub rates: RateCard,
}

/// Units the network records but never charges.
pub const RECORDED_ONLY_UNITS: &[&str] = &["ttft_ms", "decode_ms"];

/// Whether a unit is billable by default: everything but the recorded-only
/// units. Pass your own lookup to [`RateCard::charge_wei`] to consult
/// registered units.
pub fn default_billable(unit: &str) -> Option<bool> {
    Some(!RECORDED_ONLY_UNITS.contains(&unit))
}

impl RateCard {
    /// The charge for `units` in the card's denomination: each priced key
    /// `ceil(q × price / 10^per_exp)`, an unpriced key nothing, at least the
    /// minimum. Refused when billable work exists and the card prices none
    /// of it, or a unit is unknown to `billable`.
    pub fn charge_in_denom(
        &self,
        units: &BillableUnits,
        billable: impl Fn(&str) -> Option<bool>,
    ) -> SdkResult<u128> {
        let mut total = 0u128;
        let (mut priced, mut unpriced) = (false, Vec::new());
        for (k, q) in units.iter() {
            let unit = k.split('@').next().unwrap_or(k);
            match billable(unit) {
                None => {
                    return Err(SdkError::InvalidParameter(format!(
                        "unit '{unit}' is not registered"
                    )));
                }
                Some(false) => continue,
                Some(true) => {}
            }
            let Some(r) = self.lines.get(k) else {
                unpriced.push(k.to_string());
                continue;
            };
            priced = true;
            let den = 10u128
                .checked_pow(r.per_exp as u32)
                .ok_or_else(|| SdkError::InvalidParameter("per_exp too large".into()))?;
            let cost = q
                .checked_mul(r.price)
                .ok_or_else(|| SdkError::InvalidParameter("the charge overflows".into()))?
                .div_ceil(den);
            total = total
                .checked_add(cost)
                .ok_or_else(|| SdkError::InvalidParameter("the charge overflows".into()))?;
        }
        if !priced && !unpriced.is_empty() {
            return Err(SdkError::InvalidParameter(format!(
                "the card prices none of the billable work metered ({})",
                unpriced.join(", ")
            )));
        }
        Ok(total.max(self.min_charge))
    }

    /// The charge in TNZO base units; a USD card converts at
    /// `tnzo_usd_nano` (billionths of a dollar per TNZO, from
    /// `tenzro_getFeeRate`), rounding up.
    pub fn charge_wei(
        &self,
        units: &BillableUnits,
        billable: impl Fn(&str) -> Option<bool>,
        tnzo_usd_nano: u128,
    ) -> SdkResult<u128> {
        let amount = self.charge_in_denom(units, billable)?;
        match self.denom {
            _ if amount == 0 => Ok(0),
            Denom::Wei => Ok(amount),
            Denom::NanoUsd => {
                if tnzo_usd_nano == 0 {
                    return Err(SdkError::InvalidParameter("no TNZO/USD rate".into()));
                }
                amount
                    .checked_mul(1_000_000_000_000_000_000)
                    .map(|v| v.div_ceil(tnzo_usd_nano))
                    .ok_or_else(|| SdkError::InvalidParameter("the charge overflows".into()))
            }
        }
    }
}

/// The next head of a voucher's receipt chain: SHA-256 over
/// `tenzro/receipt-chain`, the previous head (all zero for the first) and
/// one receipt's digest.
pub fn receipt_chain_next(previous: &[u8; 32], receipt_digest: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"tenzro/receipt-chain");
    h.update(previous);
    h.update(receipt_digest);
    h.finalize().into()
}

/// The bytes a payer signs for an escrow voucher: the domain, the chain, the
/// escrow, the cumulative amount and the receipt-chain binding (all zero for
/// a voucher signed ahead of delivery).
pub fn escrow_voucher_preimage(
    chain_id: u64,
    escrow_id: &[u8; 32],
    cumulative: u128,
    binding: &[u8; 32],
) -> Vec<u8> {
    let mut m = b"tenzro/escrow-voucher".to_vec();
    m.extend_from_slice(&chain_id.to_le_bytes());
    m.extend_from_slice(escrow_id);
    m.extend_from_slice(&cumulative.to_le_bytes());
    m.extend_from_slice(binding);
    m
}

/// Registry kind of a standard: the anchor is the digest of its bundle.
pub const REGISTRY_KIND_STANDARD: &str = "standard";
/// Registry kind of a conformance claim: the anchor is the implementation's
/// digest, the data the 32-byte bundle digests of the standards it passes.
pub const REGISTRY_KIND_CONFORMANCE: &str = "conformance";
/// Registry kind of a name: first come, bonded, retired by governance only.
pub const REGISTRY_KIND_NAME: &str = "name";
/// The registry kinds whose rules the chain enforces.
pub const RESERVED_REGISTRY_KINDS: [&str; 3] = [
    REGISTRY_KIND_STANDARD,
    REGISTRY_KIND_CONFORMANCE,
    REGISTRY_KIND_NAME,
];

/// One registry entry, as the node returns it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegistryEntry {
    pub id: String,
    pub kind: String,
    pub owner: String,
    pub version: u64,
    pub anchor: String,
    /// The entry's data, hex.
    pub data: String,
    pub digest: String,
    pub put_at_ms: i64,
    #[serde(default)]
    pub retired_at_ms: Option<i64>,
    pub standing: bool,
}

impl RegistryEntry {
    /// The data, decoded from hex.
    pub fn data_bytes(&self) -> SdkResult<Vec<u8>> {
        hex::decode(&self.data).map_err(|e| SdkError::InvalidParameter(format!("data: {e}")))
    }
}

/// A page of entries of one kind.
#[derive(Debug, Clone, Deserialize)]
pub struct RegistryPage {
    pub kind: String,
    pub entries: Vec<RegistryEntry>,
    /// Pass back as `after` for the next page.
    pub next: Option<String>,
}

/// The registry id of `provider`'s card for `model_id`.
pub fn card_entry_id(provider_hex: &str, model_id: &str) -> String {
    format!("{}/card/{model_id}", provider_hex.trim_start_matches("0x"))
}

/// The registry transaction payloads a signer sends as a transaction type.
pub fn registry_put_tx(id: &str, kind: &str, anchor_hex: &str, data: &[u8]) -> Value {
    json!({ "Registry": { "op": { "put": {
        "id": id, "kind": kind, "anchor": anchor_hex, "data": hex::encode(data)
    } } } })
}

/// The registry transaction that retires an entry.
pub fn registry_retire_tx(id: &str) -> Value {
    json!({ "Registry": { "op": { "retire": { "id": id } } } })
}

/// Client for the generic registry and price cards.
#[derive(Clone)]
pub struct RegistryClient {
    rpc: Arc<RpcClient>,
}

impl RegistryClient {
    /// A registry client over `rpc`.
    pub fn new(rpc: Arc<RpcClient>) -> Self {
        Self { rpc }
    }

    /// Standing entries of `kind`, in id order, after `after`.
    pub async fn list(
        &self,
        kind: &str,
        after: Option<&str>,
        limit: Option<u32>,
    ) -> SdkResult<RegistryPage> {
        let v = self
            .rpc
            .call(
                "tenzro_listRegistry",
                json!({ "kind": kind, "after": after, "limit": limit }),
            )
            .await?;
        serde_json::from_value(v).map_err(|e| SdkError::InvalidParameter(e.to_string()))
    }

    /// An entry, the latest version or `version`.
    pub async fn get(&self, id: &str, version: Option<u64>) -> SdkResult<Option<RegistryEntry>> {
        let v = self
            .rpc
            .call(
                "tenzro_getRegistryEntry",
                json!({ "id": id, "version": version }),
            )
            .await?;
        serde_json::from_value(v).map_err(|e| SdkError::InvalidParameter(e.to_string()))
    }

    /// The card `provider` publishes for `model_id`, decoded, with its entry.
    pub async fn price_card(
        &self,
        provider: &str,
        model_id: &str,
    ) -> SdkResult<Option<(RegistryEntry, PriceCard)>> {
        let v: Value = self
            .rpc
            .call(
                "tenzro_getPriceCard",
                json!({ "provider": provider, "model_id": model_id }),
            )
            .await?;
        if v.is_null() {
            return Ok(None);
        }
        let card: PriceCard = serde_json::from_value(v["card"].clone())
            .map_err(|e| SdkError::InvalidParameter(e.to_string()))?;
        let entry: RegistryEntry =
            serde_json::from_value(v).map_err(|e| SdkError::InvalidParameter(e.to_string()))?;
        Ok(Some((entry, card)))
    }

    /// The entry `provider` would put to publish the node's card for a model.
    pub async fn price_card_to_publish(&self, provider: &str, model_id: &str) -> SdkResult<Value> {
        self.rpc
            .call(
                "tenzro_priceCardToPublish",
                json!({ "provider": provider, "model_id": model_id }),
            )
            .await
    }

    /// The TNZO/USD rate, billionths of a dollar per TNZO.
    pub async fn tnzo_usd_nano(&self) -> SdkResult<u128> {
        let v: Value = self.rpc.call("tenzro_getFeeRate", json!({})).await?;
        v["rate_nano_usd"]
            .as_str()
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| SdkError::InvalidParameter("no rate_nano_usd".into()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn card(denom: Denom, lines: &[(&str, u128, u8)], min: u128) -> RateCard {
        RateCard {
            denom,
            lines: lines
                .iter()
                .map(|(k, p, e)| {
                    (
                        k.to_string(),
                        Rate {
                            price: *p,
                            per_exp: *e,
                        },
                    )
                })
                .collect(),
            min_charge: min,
        }
    }

    fn units(kv: &[(&str, u128)]) -> BillableUnits {
        let mut u = BillableUnits::new();
        for (k, v) in kv {
            u.set(k, *v).unwrap();
        }
        u
    }

    #[test]
    fn the_charge_vectors_hold() {
        let a = card(
            Denom::NanoUsd,
            &[
                ("input_tokens", 200_000_000, 6),
                ("output_tokens", 1_000_000_000, 6),
            ],
            0,
        );
        assert_eq!(
            a.charge_in_denom(
                &units(&[("input_tokens", 1000), ("output_tokens", 500)]),
                default_billable
            )
            .unwrap(),
            700_000
        );
        assert_eq!(
            a.charge_wei(
                &units(&[("input_tokens", 1_000_000)]),
                default_billable,
                500_000_000
            )
            .unwrap(),
            400_000_000_000_000_000
        );
        let b = card(Denom::Wei, &[("pixel_steps", 2_000_000, 0)], 0);
        assert_eq!(
            b.charge_wei(&units(&[("pixel_steps", 31_719_424)]), default_billable, 0)
                .unwrap(),
            63_438_848_000_000
        );
        let c = card(Denom::NanoUsd, &[("bandwidth_bytes", 10_000_000, 9)], 0);
        assert_eq!(
            c.charge_in_denom(
                &units(&[("bandwidth_bytes", 1_000_000_006)]),
                default_billable
            )
            .unwrap(),
            10_000_001
        );
        assert!(
            a.charge_in_denom(&units(&[("output_tokens@priority", 1)]), default_billable)
                .is_err()
        );
        assert_eq!(
            a.charge_in_denom(
                &units(&[("input_tokens", 1000), ("ttft_ms", 250)]),
                default_billable
            )
            .unwrap(),
            200_000
        );
    }

    #[test]
    fn a_meter_round_trips_and_refuses_bad_keys() {
        let u = units(&[
            ("input_tokens", 812),
            ("control_steps@hz50", 9),
            ("pixel_steps", u128::MAX - 1),
        ]);
        let j = serde_json::to_string(&u).unwrap();
        assert!(j.contains("\"control_steps@hz50\":9"));
        assert_eq!(serde_json::from_str::<BillableUnits>(&j).unwrap(), u);
        assert!(serde_json::from_str::<BillableUnits>(r#"{"Output":1}"#).is_err());
        assert_eq!(
            serde_json::from_str::<BillableUnits>(r#"{"output_tokens":0}"#).unwrap(),
            BillableUnits::new()
        );
    }

    #[test]
    fn the_voucher_preimage_binds_the_receipt_chain() {
        let z = [0u8; 32];
        let a = escrow_voucher_preimage(1337, &[1; 32], 5, &z);
        assert_eq!(a.len(), b"tenzro/escrow-voucher".len() + 8 + 32 + 16 + 32);
        assert_ne!(a, escrow_voucher_preimage(1337, &[1; 32], 5, &[2; 32]));
        let h1 = receipt_chain_next(&z, &[1; 32]);
        assert_ne!(
            receipt_chain_next(&h1, &[2; 32]),
            receipt_chain_next(&receipt_chain_next(&z, &[2; 32]), &[1; 32])
        );
    }

    #[test]
    fn the_reserved_registry_kinds_are_listed() {
        assert_eq!(RESERVED_REGISTRY_KINDS, ["standard", "conformance", "name"]);
    }
}

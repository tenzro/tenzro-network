//! The permitted settlement asset registry in chain state.
//!
//! Governance installs one [`SettlementAsset`] per token at
//! `settlement_asset:<token id hex>` (a `SetSettlementAsset` vote). A payment
//! in any token other than TNZO settles only in an enabled entry whose
//! validator rate sits inside its par band around the rate of the currency
//! it is pegged to; anything else is refused with the reason named.
//!
//! Each entry also carries a peg breaker, stepped once per frozen epoch rate
//! of its symbol: `settlement_asset.breaker_suspend_epochs` consecutive
//! epochs off the par band suspend the asset, and only
//! `settlement_asset.breaker_resume_epochs` consecutive epochs inside the
//! tighter `settlement_asset.breaker_resume_band_bps` re-enable it, so a rate
//! sitting at the band edge cannot switch it on and off. A suspended asset
//! settles nothing and pays out nothing; what the treasury holds of it is
//! kept, never sold.

use tenzro_types::settlement_asset::{NUMERAIRE, SettlementAsset};

use super::funding::read_json;
use super::*;

/// Nano-units of the numeraire per whole unit of the numeraire itself.
pub const NUMERAIRE_NANO: u128 = 1_000_000_000;

const INDEX_KEY: &str = "settlement_assets";

/// The token ids that have a registry entry, enabled or not, ascending.
pub fn listed_ids(state: &dyn VmState) -> Vec<[u8; 32]> {
    read_json::<Vec<String>>(state, INDEX_KEY)
        .unwrap_or_default()
        .iter()
        .filter_map(|h| hex::decode(h).ok()?.try_into().ok())
        .collect()
}

fn index(state: &mut dyn VmState, id: &[u8; 32], changes: &mut Vec<StateChange>) -> Result<()> {
    let mut ids: Vec<String> = read_json(state, INDEX_KEY).unwrap_or_default();
    let h = hex::encode(id);
    if let Err(at) = ids.binary_search(&h) {
        ids.insert(at, h);
        super::funding::write_json(state, INDEX_KEY, &ids, changes)?;
    }
    Ok(())
}

/// What `account` holds in registered settlement assets, in TNZO base
/// units at the validator rates in force, rounded down. An asset that is
/// unpriced or off its peg counts for nothing.
pub fn holdings_tnzo_eq(state: &dyn VmState, account: &[u8]) -> u128 {
    let tnzo_rate = super::economy::read_fee_rate(state).rate_nano_usd;
    listed_ids(state)
        .iter()
        .filter_map(|id| {
            let held = crate::token_ledger::balance(state, id, account);
            if held == 0 {
                return None;
            }
            let rate = priced_on_peg(state, id).ok()?;
            Some(tnzo_eq(held, rate.0, rate.1, tnzo_rate, false))
        })
        .fold(0u128, u128::saturating_add)
}

/// What `account` holds in registered settlement assets, micro-units of
/// account at the validator rates in force, rounded down. An asset that is
/// unpriced or off its peg counts for nothing.
pub fn holdings_value_e6(state: &dyn VmState, account: &[u8]) -> u128 {
    listed_ids(state)
        .iter()
        .filter_map(|id| {
            let held = crate::token_ledger::balance(state, id, account);
            if held == 0 {
                return None;
            }
            let (rate, decimals) = priced_on_peg(state, id).ok()?;
            Some(value_e6(held, rate, decimals))
        })
        .fold(0u128, u128::saturating_add)
}

/// Refuses adding `intake` of `p`'s asset to the treasury when the asset
/// would then make up more of the treasury's whole value (its TNZO and its
/// settlement-asset holdings, at the rates in force) than the entry's
/// `max_exposure_bps`.
pub(super) fn check_exposure(
    state: &dyn VmState,
    token: &[u8; 32],
    p: &Permitted,
    intake: u128,
) -> Result<()> {
    let treasury = derive_treasury_address();
    let tnzo_rate = super::economy::read_fee_rate(state).rate_nano_usd;
    let eq = |x: u128| tnzo_eq(x, p.rate_nano_usd, p.asset.decimals, tnzo_rate, false);
    let held =
        crate::token_ledger::balance(state, token, treasury.as_bytes()).saturating_add(intake);
    let after = eq(held);
    let total = state
        .get_balance(treasury.as_bytes())
        .saturating_add(holdings_tnzo_eq(state, treasury.as_bytes()))
        .saturating_add(eq(intake));
    let ceiling = p.asset.max_exposure_bps;
    if after.saturating_mul(10_000) > total.saturating_mul(u128::from(ceiling)) {
        return Err(VmError::InvalidTransaction(format!(
            "settlement asset {} would make up {} bps of the treasury, over its exposure ceiling of {ceiling} bps",
            p.asset.symbol,
            after.saturating_mul(10_000) / total.max(1)
        )));
    }
    Ok(())
}

/// The validator rate and decimals of a registered asset whose rate sits on
/// its peg, whether or not payments may settle in it now.
fn priced_on_peg(state: &dyn VmState, token: &[u8; 32]) -> Result<(u128, u8)> {
    let mut asset = read_settlement_asset(state, token).ok_or_else(|| {
        VmError::InvalidTransaction("not a registered settlement asset".to_string())
    })?;
    let decimals = asset.decimals;
    asset.enabled = true;
    let p = check_entry(state, asset)?;
    Ok((p.rate_nano_usd, decimals))
}

/// The entry governance installed for `token`, if any.
pub fn read_settlement_asset(state: &dyn VmState, token: &[u8; 32]) -> Option<SettlementAsset> {
    read_json(state, &SettlementAsset::storage_key(token))
}

/// Refuses an entry whose token is not on the ledger or whose decimals
/// differ from the token's own.
pub(super) fn check_against_ledger(state: &dyn VmState, asset: &SettlementAsset) -> Result<()> {
    let id = asset.token_bytes().ok_or_else(|| {
        VmError::InvalidTransaction(format!(
            "settlement asset token id {:?} is not 0x and 64 hex digits",
            asset.token_id
        ))
    })?;
    let token = crate::token_ledger::read_token(state, &id).ok_or_else(|| {
        VmError::InvalidTransaction(format!(
            "settlement asset {} names token {} which is not on this ledger",
            asset.symbol, asset.token_id
        ))
    })?;
    if token.decimals != asset.decimals {
        return Err(VmError::InvalidTransaction(format!(
            "settlement asset {} declares {} decimals; the token has {}",
            asset.symbol, asset.decimals, token.decimals
        )));
    }
    Ok(())
}

/// Stores `asset` at its key, replacing any entry for the same token.
pub(super) fn write_settlement_asset(
    state: &mut dyn VmState,
    asset: &SettlementAsset,
    changes: &mut Vec<StateChange>,
) -> Result<()> {
    let id = asset.token_bytes().ok_or_else(|| {
        VmError::InvalidTransaction("a settlement asset names a 32-byte token".to_string())
    })?;
    let mut stored = asset.clone();
    stored.token_id = format!("0x{}", hex::encode(id));
    super::funding::write_json(state, &SettlementAsset::storage_key(&id), &stored, changes)?;
    index(state, &id, changes)
}

/// A permitted asset with the rates it settles at.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Permitted {
    /// The registry entry.
    pub asset: SettlementAsset,
    /// The asset's validator rate, nano-USD per whole token.
    pub rate_nano_usd: u128,
    /// The epoch whose median set the asset's rate.
    pub rate_epoch: Option<u64>,
}

/// Nano-USD per whole unit of `currency`: exact for the numeraire, the
/// validator rate otherwise.
fn currency_rate(state: &dyn VmState, currency: &str) -> Result<u128> {
    if currency == NUMERAIRE {
        return Ok(NUMERAIRE_NANO);
    }
    super::economy::read_symbol_rate(state, currency)
        .map(|(r, _)| r)
        .filter(|r| *r > 0)
        .ok_or_else(|| {
            VmError::InvalidTransaction(format!(
                "validators have not priced the currency {currency}; settlement in it is refused"
            ))
        })
}

/// Governed key: consecutive epochs off its par band that suspend an asset.
pub const BREAKER_SUSPEND_PARAM: &str = "settlement_asset.breaker_suspend_epochs";
/// Genesis value of [`BREAKER_SUSPEND_PARAM`].
pub const DEFAULT_BREAKER_SUSPEND_EPOCHS: u64 = 3;
/// Greatest value of [`BREAKER_SUSPEND_PARAM`].
pub const MAX_BREAKER_SUSPEND_EPOCHS: u64 = 168;
/// Governed key: consecutive epochs inside the resume band that re-enable a
/// suspended asset.
pub const BREAKER_RESUME_PARAM: &str = "settlement_asset.breaker_resume_epochs";
/// Genesis value of [`BREAKER_RESUME_PARAM`].
pub const DEFAULT_BREAKER_RESUME_EPOCHS: u64 = 24;
/// Greatest value of [`BREAKER_RESUME_PARAM`].
pub const MAX_BREAKER_RESUME_EPOCHS: u64 = 720;
/// Governed key: band around par a suspended asset's rate must hold inside
/// to count toward re-enabling, bps; never wider than the entry's own par
/// band.
pub const BREAKER_RESUME_BAND_PARAM: &str = "settlement_asset.breaker_resume_band_bps";
/// Genesis value of [`BREAKER_RESUME_BAND_PARAM`].
pub const DEFAULT_BREAKER_RESUME_BAND_BPS: u64 = 50;
/// Least value of [`BREAKER_RESUME_BAND_PARAM`].
pub const MIN_BREAKER_RESUME_BAND_BPS: u64 = 10;
/// Topic of the log a breaker suspending an asset emits.
pub const ASSET_SUSPENDED_TOPIC: &[u8] = b"SettlementAssetSuspended";
/// Topic of the log a breaker re-enabling an asset emits.
pub const ASSET_RESUMED_TOPIC: &[u8] = b"SettlementAssetResumed";

/// A settlement asset's peg breaker, as stored.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct Breaker {
    /// Whether the asset is suspended.
    pub suspended: bool,
    /// Consecutive epochs off the par band, while not suspended.
    pub off_run: u64,
    /// Consecutive epochs inside the resume band, while suspended.
    pub on_run: u64,
    /// The last epoch whose rate stepped the breaker.
    pub last_epoch: Option<u64>,
    /// The epoch the current suspension began.
    pub since_epoch: Option<u64>,
    /// Suspensions since the entry was installed.
    pub suspensions: u64,
}

/// The governed values a breaker steps by.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BreakerRules {
    /// Consecutive off-peg epochs that suspend.
    pub suspend_epochs: u64,
    /// Consecutive epochs inside the resume band that re-enable.
    pub resume_epochs: u64,
    /// The resume band, bps.
    pub resume_band_bps: u64,
}

impl BreakerRules {
    /// The values in force, within their bounds.
    pub fn read(state: &dyn VmState) -> Self {
        use tenzro_types::settlement_asset::MAX_PAR_BAND_BPS;
        Self {
            suspend_epochs: network_param(state, BREAKER_SUSPEND_PARAM)
                .clamp(1, MAX_BREAKER_SUSPEND_EPOCHS),
            resume_epochs: network_param(state, BREAKER_RESUME_PARAM)
                .clamp(1, MAX_BREAKER_RESUME_EPOCHS),
            resume_band_bps: network_param(state, BREAKER_RESUME_BAND_PARAM)
                .clamp(MIN_BREAKER_RESUME_BAND_BPS, MAX_PAR_BAND_BPS),
        }
    }
}

fn breaker_key(token: &[u8; 32]) -> String {
    format!("settlement_breaker:{}", hex::encode(token))
}

/// The breaker of `token`; a never-stepped one is closed.
pub fn read_breaker(state: &dyn VmState, token: &[u8; 32]) -> Breaker {
    read_json(state, &breaker_key(token)).unwrap_or_default()
}

/// One epoch's step of a breaker: `rate` frozen for `epoch` against `par`.
/// An epoch at or before the last one stepped changes nothing.
pub fn step_breaker(
    b: &Breaker,
    epoch: u64,
    rate: u128,
    par: u128,
    par_band_bps: u64,
    rules: &BreakerRules,
) -> Breaker {
    if b.last_epoch.is_some_and(|l| epoch <= l) {
        return b.clone();
    }
    let mut n = b.clone();
    n.last_epoch = Some(epoch);
    if n.suspended {
        let band = rules.resume_band_bps.min(par_band_bps);
        n.on_run = if on_peg(rate, par, band) {
            n.on_run + 1
        } else {
            0
        };
        if n.on_run >= rules.resume_epochs {
            n.suspended = false;
            n.on_run = 0;
            n.off_run = 0;
            n.since_epoch = None;
        }
    } else {
        n.off_run = if on_peg(rate, par, par_band_bps) {
            0
        } else {
            n.off_run + 1
        };
        if n.off_run >= rules.suspend_epochs {
            n.suspended = true;
            n.off_run = 0;
            n.on_run = 0;
            n.since_epoch = Some(epoch);
            n.suspensions = n.suspensions.saturating_add(1);
        }
    }
    n
}

/// Steps the breaker of every entry priced under `symbol` with the rate
/// validators froze for `epoch`, logging each suspension and re-enabling.
pub(super) fn observe_rate(
    state: &mut dyn VmState,
    symbol: &str,
    epoch: u64,
    rate: u128,
    changes: &mut Vec<StateChange>,
    logs: &mut Vec<Log>,
) -> Result<()> {
    let rules = BreakerRules::read(state);
    for id in listed_ids(state) {
        let Some(asset) = read_settlement_asset(state, &id) else {
            continue;
        };
        if asset.symbol != symbol {
            continue;
        }
        let Ok(par) = currency_rate(state, &asset.currency) else {
            continue;
        };
        let before = read_breaker(state, &id);
        let after = step_breaker(&before, epoch, rate, par, asset.par_band_bps, &rules);
        if after == before {
            continue;
        }
        super::funding::write_json(state, &breaker_key(&id), &after, changes)?;
        if after.suspended != before.suspended {
            let topic = if after.suspended {
                ASSET_SUSPENDED_TOPIC
            } else {
                ASSET_RESUMED_TOPIC
            };
            logs.push(Log::new(
                SYSTEM_ADDRESS.to_vec(),
                vec![topic.to_vec()],
                serde_json::to_vec(&serde_json::json!({
                    "token": format!("0x{}", hex::encode(id)),
                    "symbol": asset.symbol,
                    "epoch": epoch,
                    "rate_nano_usd": rate.to_string(),
                    "par_nano_usd": par.to_string(),
                }))
                .map_err(|e| VmError::Internal(format!("encode breaker log: {e}")))?,
            ));
        }
    }
    Ok(())
}

fn check_breaker(state: &dyn VmState, token: &[u8; 32], asset: &SettlementAsset) -> Result<()> {
    let b = read_breaker(state, token);
    if !b.suspended {
        return Ok(());
    }
    let rules = BreakerRules::read(state);
    Err(VmError::InvalidTransaction(format!(
        "settlement asset {} is suspended by its peg breaker since epoch {}; it settles again after {} epochs on its peg within {} bps",
        asset.symbol,
        b.since_epoch.unwrap_or_default(),
        rules.resume_epochs,
        rules.resume_band_bps.min(asset.par_band_bps)
    )))
}

/// Whether `rate` sits within `band_bps` of `par`.
pub fn on_peg(rate: u128, par: u128, band_bps: u64) -> bool {
    let gap = rate.abs_diff(par);
    gap.saturating_mul(10_000) <= par.saturating_mul(u128::from(band_bps))
}

/// The entry for `token` and its rate, when payments may settle in it now:
/// installed, enabled, priced by validators, on its peg, and not suspended
/// by its peg breaker.
pub fn permitted(state: &dyn VmState, token: &[u8; 32]) -> Result<Permitted> {
    let asset = read_settlement_asset(state, token).ok_or_else(|| {
        VmError::InvalidTransaction(format!(
            "token 0x{} is not a permitted settlement asset",
            hex::encode(token)
        ))
    })?;
    check_breaker(state, token, &asset)?;
    check_entry(state, asset)
}

fn check_entry(state: &dyn VmState, asset: SettlementAsset) -> Result<Permitted> {
    if !asset.enabled {
        return Err(VmError::InvalidTransaction(format!(
            "settlement asset {} is disabled",
            asset.symbol
        )));
    }
    let (rate, rate_epoch) = super::economy::read_symbol_rate(state, &asset.symbol)
        .filter(|(r, _)| *r > 0)
        .ok_or_else(|| {
            VmError::InvalidTransaction(format!(
                "validators have not priced settlement asset {}; settlement in it is refused",
                asset.symbol
            ))
        })?;
    let par = currency_rate(state, &asset.currency)?;
    if !on_peg(rate, par, asset.par_band_bps) {
        return Err(VmError::InvalidTransaction(format!(
            "settlement asset {} is off its {} peg: {rate} nano-USD against {par}, band {} bps",
            asset.symbol, asset.currency, asset.par_band_bps
        )));
    }
    Ok(Permitted {
        asset,
        rate_nano_usd: rate,
        rate_epoch,
    })
}

/// The unit of account payments are valued in: the dollar alone.
pub fn unit_of_account() -> tenzro_types::settlement::UnitOfAccount {
    tenzro_types::settlement::UnitOfAccount {
        basket: NUMERAIRE.to_string(),
        version: 1,
    }
}

fn pow10(decimals: u8) -> revm::primitives::U256 {
    revm::primitives::U256::from(10u8).pow(revm::primitives::U256::from(decimals))
}

fn narrow(v: revm::primitives::U256) -> u128 {
    u128::try_from(v).unwrap_or(u128::MAX)
}

/// Micro-units of account `amount` smallest units of a token with
/// `decimals` decimals are worth at `rate_nano_usd` per whole token,
/// rounded down.
pub fn value_e6(amount: u128, rate_nano_usd: u128, decimals: u8) -> u128 {
    use revm::primitives::U256;
    let num = U256::from(amount) * U256::from(rate_nano_usd);
    narrow(num / (pow10(decimals) * U256::from(1_000u32)))
}

/// [`value_e6`] rounded up: what a spend limit counts, so a payment is
/// never counted at less than it is worth.
pub fn value_e6_up(amount: u128, rate_nano_usd: u128, decimals: u8) -> u128 {
    use revm::primitives::U256;
    let num = U256::from(amount) * U256::from(rate_nano_usd);
    narrow(num.div_ceil(pow10(decimals) * U256::from(1_000u32)))
}

/// Smallest units of a token with `decimals` decimals that cover `e6`
/// micro-units of account at `rate_nano_usd` per whole token, rounded up.
pub fn units_for_e6(e6: u128, rate_nano_usd: u128, decimals: u8) -> u128 {
    use revm::primitives::U256;
    if e6 == 0 {
        return 0;
    }
    let num = U256::from(e6) * U256::from(1_000u32) * pow10(decimals);
    narrow(num.div_ceil(U256::from(rate_nano_usd.max(1))))
}

/// TNZO base units `amount` smallest units of a token are worth, the token
/// at `rate_nano_usd` and TNZO at `tnzo_nano_usd` per whole unit, rounded
/// up when `up`, down otherwise.
pub fn tnzo_eq(
    amount: u128,
    rate_nano_usd: u128,
    decimals: u8,
    tnzo_nano_usd: u128,
    up: bool,
) -> u128 {
    use revm::primitives::U256;
    let Some(num) = U256::from(amount)
        .checked_mul(U256::from(rate_nano_usd))
        .and_then(|v| v.checked_mul(pow10(18)))
    else {
        return u128::MAX;
    };
    let den = pow10(decimals) * U256::from(tnzo_nano_usd.max(1));
    narrow(if up { num.div_ceil(den) } else { num / den })
}

/// Micro-units of account `wei` TNZO base units are worth at
/// `tnzo_nano_usd` per TNZO, rounded down.
pub fn tnzo_value_e6(wei: u128, tnzo_nano_usd: u128) -> u128 {
    value_e6(wei, tnzo_nano_usd, 18)
}

/// Value settled in one asset in one epoch, micro-units.
#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
struct Inflow {
    epoch: u64,
    #[serde(with = "tenzro_types::primitives::u128_serde")]
    value_e6: u128,
}

fn inflow_key(token: &[u8; 32]) -> String {
    format!("settlement_inflow:{}", hex::encode(token))
}

/// What has settled in `token` in the current epoch, micro-units.
pub fn read_epoch_inflow(state: &dyn VmState, token: &[u8; 32]) -> u128 {
    let epoch = super::economy::read_current_epoch(state);
    read_json::<Inflow>(state, &inflow_key(token))
        .filter(|i| i.epoch == epoch)
        .map_or(0, |i| i.value_e6)
}

/// Counts `value_e6` against the asset's epoch inflow cap, refusing a
/// payment that would pass it.
pub(super) fn admit_inflow(
    state: &mut dyn VmState,
    token: &[u8; 32],
    permitted: &Permitted,
    value_e6: u128,
    changes: &mut Vec<StateChange>,
) -> Result<()> {
    let epoch = super::economy::read_current_epoch(state);
    let used = read_epoch_inflow(state, token);
    let cap = u128::from(permitted.asset.epoch_inflow_cap_units).saturating_mul(1_000_000);
    let total = used.saturating_add(value_e6);
    if total > cap {
        return Err(VmError::InvalidTransaction(format!(
            "settlement asset {} has {} micro-units of its epoch inflow cap left; the payment is worth {value_e6}",
            permitted.asset.symbol,
            cap.saturating_sub(used)
        )));
    }
    super::funding::write_json(
        state,
        &inflow_key(token),
        &Inflow {
            epoch,
            value_e6: total,
        },
        changes,
    )
    .map(|_| ())
}

/// What a payment worth a given value costs in one asset now.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct AssetQuote {
    /// The asset as the payment names it: `TNZO` or a `0x` token id.
    pub asset: String,
    /// The amount to authorize, smallest units, rounded up; a decimal
    /// string, exact in every reader.
    #[serde(with = "decimal")]
    pub amount: u128,
    /// The settlement fee taken out of it, in `fee_asset`; a decimal string.
    #[serde(with = "decimal")]
    pub fee: u128,
    /// The asset the fee is collected in: the payment's own.
    pub fee_asset: String,
    /// The epoch whose median set the TNZO rate used.
    pub rate_epoch: Option<u64>,
    /// The operator's price inside `amount`, a decimal string.
    #[serde(with = "decimal")]
    pub operator_amount: u128,
    /// Each reseller commission inside `amount`, as the chain carves it.
    #[serde(default)]
    pub legs: Vec<QuotedLeg>,
}

/// One reseller commission a quote discloses.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct QuotedLeg {
    /// The reseller's account, hex.
    pub reseller: String,
    /// Its commission, bps of the operator's price.
    pub commission_bps: u32,
    /// What the leg carries, smallest units; a decimal string.
    #[serde(with = "decimal")]
    pub amount: u128,
    /// The settlement fee the leg pays, in the same asset; a decimal string.
    #[serde(with = "decimal")]
    pub fee: u128,
}

mod decimal {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(v: &u128, s: S) -> std::result::Result<S::Ok, S::Error> {
        s.serialize_str(&v.to_string())
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> std::result::Result<u128, D::Error> {
        String::deserialize(d)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

/// Why an asset cannot be quoted now, with a stable code.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct QuoteRefusal {
    /// `asset_unpermitted`, `asset_disabled`, `rate_held`,
    /// `asset_suspended`, `asset_off_peg`, `asset_inflow_full` or
    /// `invalid_asset`.
    pub code: String,
    /// What the chain said.
    pub reason: String,
}

fn refusal(code: &str, reason: impl Into<String>) -> QuoteRefusal {
    QuoteRefusal {
        code: code.to_string(),
        reason: reason.into(),
    }
}

/// What a payment worth `usd_e6` micro-units costs in `asset` now, and the
/// settlement fee it pays in the same asset; or why it cannot settle in it.
pub fn quote_asset(
    state: &dyn VmState,
    asset: &str,
    usd_e6: u64,
) -> std::result::Result<AssetQuote, QuoteRefusal> {
    let rate_epoch = super::economy::read_fee_rate(state).epoch;
    let token = tenzro_types::payment_authorization::asset_token_id(asset)
        .map_err(|e| refusal("invalid_asset", e.to_string()))?;
    let Some(token) = token else {
        let amount = super::payment_settlement::usd_e6_to_wei(state, usd_e6);
        return Ok(AssetQuote {
            asset: asset.to_string(),
            amount,
            fee: super::economy::settlement_fee(state, amount),
            fee_asset: asset.to_string(),
            rate_epoch,
            operator_amount: amount,
            legs: Vec::new(),
        });
    };
    let entry = read_settlement_asset(state, &token).ok_or_else(|| {
        refusal(
            "asset_unpermitted",
            format!("{asset} is not a permitted settlement asset"),
        )
    })?;
    if !entry.enabled {
        return Err(refusal(
            "asset_disabled",
            format!("settlement asset {} is disabled", entry.symbol),
        ));
    }
    if super::economy::read_symbol_rate(state, &entry.symbol).is_none_or(|(r, _)| r == 0) {
        return Err(refusal(
            "rate_held",
            format!("validators have not priced {}", entry.symbol),
        ));
    }
    check_breaker(state, &token, &entry).map_err(|e| refusal("asset_suspended", e.to_string()))?;
    let p = permitted(state, &token).map_err(|e| {
        let e = e.to_string();
        if e.contains("off its") {
            refusal("asset_off_peg", e)
        } else {
            refusal("rate_held", e)
        }
    })?;
    // The inflow cap is first-come and the payment settles at once; a quote
    // names an asset whose cap this payment would pass, so the payer moves
    // to its next accepted asset instead of being refused at settlement.
    let cap = u128::from(p.asset.epoch_inflow_cap_units).saturating_mul(1_000_000);
    let used = read_epoch_inflow(state, &token);
    if used.saturating_add(u128::from(usd_e6)) > cap {
        return Err(refusal(
            "asset_inflow_full",
            format!(
                "settlement asset {} has {} micro-units of its epoch inflow cap left; the payment is worth {usd_e6}",
                p.asset.symbol,
                cap.saturating_sub(used)
            ),
        ));
    }
    let amount = units_for_e6(u128::from(usd_e6), p.rate_nano_usd, p.asset.decimals);
    let params = super::payment_settlement::in_kind_fee_params(state, &p);
    Ok(AssetQuote {
        asset: format!("0x{}", hex::encode(token)),
        amount,
        fee: tenzro_types::split::fee_allocation(amount, &params).fee,
        fee_asset: format!("0x{}", hex::encode(token)),
        rate_epoch,
        operator_amount: amount,
        legs: Vec::new(),
    })
}

/// [`quote_asset`] for a payment resold through `resellers`: the operator's
/// price, each commission on top of it as the chain carves it from the
/// amount the payer signs, the whole amount, and the settlement fee every
/// leg pays at the same governed rate. The operator is always paid its
/// whole price.
pub fn quote_asset_resold(
    state: &dyn VmState,
    asset: &str,
    usd_e6: u64,
    resellers: &[tenzro_types::payment_authorization::ResellerLeg],
) -> std::result::Result<AssetQuote, QuoteRefusal> {
    let direct = quote_asset(state, asset, usd_e6)?;
    if resellers.is_empty() {
        return Ok(direct);
    }
    let overflow = || refusal("invalid_asset", "the commissions overflow the amount");
    let bps: Vec<u32> = std::iter::once(0)
        .chain(resellers.iter().map(|r| r.commission_bps))
        .collect();
    let total_bps = bps
        .iter()
        .try_fold(0u32, |a, b| a.checked_add(*b))
        .ok_or_else(overflow)?;
    let mut amount = super::payment_settlement::amount_with_leg(direct.amount, total_bps)
        .ok_or_else(overflow)?;
    // The least amount whose carved operator part is at least the price.
    let carve = |amount: u128| super::payment_settlement::declared_legs(amount, &bps);
    loop {
        let parts = carve(amount).ok_or_else(overflow)?;
        if amount - parts.iter().sum::<u128>() >= direct.amount {
            break;
        }
        amount = amount.checked_add(1).ok_or_else(overflow)?;
    }
    let parts = carve(amount).ok_or_else(overflow)?;
    let leg_fee = |x: u128| -> u128 {
        match tenzro_types::payment_authorization::asset_token_id(asset)
            .ok()
            .flatten()
        {
            None => super::economy::settlement_fee(state, x),
            Some(token) => permitted(state, &token).map_or(0, |p| {
                let params = super::payment_settlement::in_kind_fee_params(state, &p);
                tenzro_types::split::fee_allocation(x, &params).fee
            }),
        }
    };
    let operator_amount = amount - parts.iter().sum::<u128>();
    let legs: Vec<QuotedLeg> = resellers
        .iter()
        .zip(&parts[1..])
        .map(|(r, a)| QuotedLeg {
            reseller: hex::encode(r.reseller.as_bytes()),
            commission_bps: r.commission_bps,
            amount: *a,
            fee: leg_fee(*a),
        })
        .collect();
    Ok(AssetQuote {
        fee: leg_fee(operator_amount) + legs.iter().map(|l| l.fee).sum::<u128>(),
        amount,
        operator_amount,
        legs,
        ..direct
    })
}

/// Test seam: installs `asset` the way an enacted vote stores it.
#[cfg(test)]
pub(crate) fn install_for_test(state: &mut dyn VmState, asset: &SettlementAsset) {
    let id = asset.token_bytes().expect("a 32-byte token id");
    state.set_storage(
        &SYSTEM_ADDRESS,
        SettlementAsset::storage_key(&id).as_bytes(),
        serde_json::to_vec(asset).unwrap(),
    );
    index(state, &id, &mut Vec::new()).unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state_adapter::StateAdapter;

    const ID: [u8; 32] = [0x5c; 32];

    fn usdc() -> SettlementAsset {
        SettlementAsset::new(&format!("0x{}", hex::encode(ID)), "USDC", "USD", 6)
    }

    fn priced(rate: u128) -> StateAdapter {
        let mut state = StateAdapter::new();
        install_for_test(&mut state, &usdc());
        super::super::economy::write_symbol_rate_for_tests(&mut state, "USDC", 3, rate);
        state
    }

    fn token_held_by(
        state: &mut StateAdapter,
        holder: &[u8],
        symbol: &str,
        supply: u128,
    ) -> [u8; 32] {
        let spec = crate::token_ledger::TokenRecord {
            name: symbol.into(),
            symbol: symbol.into(),
            decimals: 6,
            total_supply: supply,
            creator: Vec::new(),
            max_supply: None,
            powers: tenzro_types::token_policy::PowerManifest::NONE,
            policy: tenzro_types::token_policy::TokenPolicy::default(),
            council: None,
            reserve_backing: None,
            pending: None,
        };
        crate::token_ledger::create(state, holder, &spec, &mut Vec::new()).unwrap()
    }

    #[test]
    fn stable_holdings_count_at_the_validator_rate_and_off_peg_holdings_count_nothing() {
        let mut state = StateAdapter::new();
        let pool = super::super::insurance::pool_address();
        let usdc = token_held_by(&mut state, pool.as_bytes(), "USDC", 2_000_000);
        let eurc = token_held_by(&mut state, pool.as_bytes(), "EURC", 5_000_000);
        for (id, sym, cur) in [(usdc, "USDC", "USD"), (eurc, "EURC", "EUR")] {
            install_for_test(
                &mut state,
                &SettlementAsset::new(&format!("0x{}", hex::encode(id)), sym, cur, 6),
            );
        }
        super::super::economy::write_symbol_rate_for_tests(&mut state, "USDC", 1, NUMERAIRE_NANO);
        // EURC with no EUR rate cannot be checked against its peg: it counts
        // for nothing rather than at a guessed value.
        super::super::economy::write_symbol_rate_for_tests(&mut state, "EURC", 1, 1_080_000_000);
        // 2 USDC at 0.10 USD per TNZO: 20 TNZO.
        let twenty = 20 * 10u128.pow(18);
        assert_eq!(holdings_tnzo_eq(&state, pool.as_bytes()), twenty);
        super::super::economy::write_symbol_rate_for_tests(&mut state, "EUR", 1, 1_080_000_000);
        // 5 EURC at 1.08 USD: 54 TNZO more.
        assert_eq!(
            holdings_tnzo_eq(&state, pool.as_bytes()),
            twenty + 54 * 10u128.pow(18)
        );
        state.set_balance(pool.as_bytes(), 7);
        assert_eq!(
            super::super::insurance::pool_value(&state),
            7 + twenty + 54 * 10u128.pow(18)
        );
        assert_eq!(listed_ids(&state), {
            let mut v = vec![usdc, eurc];
            v.sort();
            v
        });
    }

    #[test]
    fn a_quote_prices_each_accepted_asset_with_its_fee_in_kind_or_names_why_not() {
        let mut state = StateAdapter::new();
        // Amounts are decimal strings, exact past 2^53 in every reader.
        let q = quote_asset(&state, "TNZO", 1_000_000).unwrap();
        let v = serde_json::to_value(&q).unwrap();
        assert_eq!(v["amount"], q.amount.to_string());
        assert_eq!(v["fee"], q.fee.to_string());
        let usdc = token_held_by(&mut state, &[9; 32], "USDC", 1);
        let usdc_hex = format!("0x{}", hex::encode(usdc));
        // TNZO: 2.5 USD at 0.10 is 25 TNZO, its fee in TNZO.
        let q = quote_asset(&state, "TNZO", 2_500_000).unwrap();
        assert_eq!(q.amount, 25 * 10u128.pow(18));
        assert_eq!(
            q.fee,
            super::super::economy::settlement_fee(&state, q.amount)
        );
        assert_eq!(q.fee_asset, "TNZO");
        // Not in the registry.
        let e = quote_asset(&state, &usdc_hex, 2_500_000).unwrap_err();
        assert_eq!(e.code, "asset_unpermitted");
        let mut entry = SettlementAsset::new(&usdc_hex, "USDC", "USD", 6);
        entry.enabled = false;
        install_for_test(&mut state, &entry);
        assert_eq!(
            quote_asset(&state, &usdc_hex, 2_500_000).unwrap_err().code,
            "asset_disabled"
        );
        entry.enabled = true;
        entry.epoch_inflow_cap_units = 2;
        install_for_test(&mut state, &entry);
        assert_eq!(
            quote_asset(&state, &usdc_hex, 2_500_000).unwrap_err().code,
            "rate_held"
        );
        super::super::economy::write_symbol_rate_for_tests(&mut state, "USDC", 4, 950_000_000);
        assert_eq!(
            quote_asset(&state, &usdc_hex, 1_000_000).unwrap_err().code,
            "asset_off_peg"
        );
        super::super::economy::write_symbol_rate_for_tests(&mut state, "USDC", 5, 999_000_000);
        assert_eq!(
            quote_asset(&state, &usdc_hex, 2_500_000).unwrap_err().code,
            "asset_inflow_full"
        );
        // 1 USD at 0.999: 1001002 smallest units, rounded up; fee in USDC.
        let q = quote_asset(&state, &usdc_hex, 1_000_000).unwrap();
        assert_eq!(q.amount, 1_001_002);
        assert_eq!(q.fee_asset, usdc_hex);
        assert_eq!(
            q.rate_epoch,
            super::super::economy::read_fee_rate(&state).epoch
        );
        assert!(q.fee > 0 && q.fee < q.amount);
    }

    #[test]
    fn a_resold_quote_discloses_the_operator_price_and_each_commission() {
        let mut state = StateAdapter::new();
        let usdc = token_held_by(&mut state, &[9; 32], "USDC", 1);
        let usdc_hex = format!("0x{}", hex::encode(usdc));
        install_for_test(
            &mut state,
            &SettlementAsset::new(&usdc_hex, "USDC", "USD", 6),
        );
        super::super::economy::write_symbol_rate_for_tests(&mut state, "USDC", 5, NUMERAIRE_NANO);
        let direct = quote_asset(&state, &usdc_hex, 10_000_000).unwrap();
        let legs = [
            tenzro_types::payment_authorization::ResellerLeg {
                reseller: Address::new([0x51; 32]),
                commission_bps: 1_000,
            },
            tenzro_types::payment_authorization::ResellerLeg {
                reseller: Address::new([0x52; 32]),
                commission_bps: 500,
            },
        ];
        let q = quote_asset_resold(&state, &usdc_hex, 10_000_000, &legs).unwrap();
        assert_eq!(q.operator_amount, direct.amount);
        assert_eq!(
            q.amount,
            super::super::payment_settlement::amount_with_leg(direct.amount, 1_500).unwrap()
        );
        // Each leg as the chain will carve it from the signed amount.
        let carved =
            super::super::payment_settlement::declared_legs(q.amount, &[0, 1_000, 500]).unwrap();
        assert_eq!(q.legs.len(), 2);
        assert_eq!(
            (q.legs[0].commission_bps, q.legs[0].amount),
            (1_000, carved[1])
        );
        assert_eq!(
            (q.legs[1].commission_bps, q.legs[1].amount),
            (500, carved[2])
        );
        assert_eq!(q.legs[0].reseller, hex::encode([0x51; 32]));
        assert!(
            q.amount - carved[1] - carved[2] >= direct.amount,
            "the operator is paid its whole price"
        );
        assert!(q.fee > direct.fee, "each leg pays the fee at the same rate");
        // A direct quote discloses no legs.
        assert!(direct.legs.is_empty());
        assert_eq!(direct.operator_amount, direct.amount);
    }

    #[test]
    fn valuations_round_toward_the_network() {
        // 1.5 USDC at 0.999 USD: 1.4985 USD.
        assert_eq!(value_e6(1_500_000, 999_000_000, 6), 1_498_500);
        // One smallest unit at 0.999 is worth 0.999 micro-units: rounds to 0.
        assert_eq!(value_e6(1, 999_000_000, 6), 0);
        // Covering one micro-unit at 0.999 takes two smallest units.
        assert_eq!(units_for_e6(1, 999_000_000, 6), 2);
        assert_eq!(units_for_e6(1_000_000, NUMERAIRE_NANO, 6), 1_000_000);
        assert_eq!(units_for_e6(0, NUMERAIRE_NANO, 6), 0);
        // 1 USDC at par with TNZO at 0.10 USD is 10 TNZO.
        let ten = 10 * 10u128.pow(18);
        assert_eq!(
            tnzo_eq(1_000_000, NUMERAIRE_NANO, 6, 100_000_000, false),
            ten
        );
        assert_eq!(
            tnzo_eq(1_000_000, NUMERAIRE_NANO, 6, 100_000_000, true),
            ten
        );
        // A third of a TNZO base unit rounds down or up as asked.
        assert_eq!(tnzo_eq(1, 1, 18, 3, false), 0);
        assert_eq!(tnzo_eq(1, 1, 18, 3, true), 1);
        assert_eq!(tnzo_value_e6(ten, 100_000_000), 1_000_000);
        // Overflow saturates rather than wraps.
        assert_eq!(tnzo_eq(u128::MAX, u128::MAX, 0, 1, false), u128::MAX);
    }

    #[test]
    fn an_enabled_asset_on_its_peg_is_permitted_at_its_rate() {
        let state = priced(999_000_000);
        let p = permitted(&state, &ID).unwrap();
        assert_eq!(p.asset.symbol, "USDC");
        assert_eq!(p.rate_nano_usd, 999_000_000);
        assert_eq!(p.rate_epoch, Some(3));
    }

    #[test]
    fn a_token_with_no_entry_is_refused() {
        let state = StateAdapter::new();
        let err = permitted(&state, &ID).unwrap_err().to_string();
        assert!(err.contains("not a permitted settlement asset"), "{err}");
    }

    #[test]
    fn a_disabled_asset_is_refused() {
        let mut state = priced(NUMERAIRE_NANO);
        let mut a = usdc();
        a.enabled = false;
        install_for_test(&mut state, &a);
        let err = permitted(&state, &ID).unwrap_err().to_string();
        assert!(err.contains("disabled"), "{err}");
    }

    #[test]
    fn an_unpriced_asset_is_refused() {
        let mut state = StateAdapter::new();
        install_for_test(&mut state, &usdc());
        let err = permitted(&state, &ID).unwrap_err().to_string();
        assert!(err.contains("have not priced"), "{err}");
    }

    #[test]
    fn an_asset_off_its_peg_is_refused_either_side_of_the_band() {
        // Band 100 bps around 1 USD: 0.99 and 1.01 pass, beyond them fail.
        assert!(permitted(&priced(990_000_000), &ID).is_ok());
        assert!(permitted(&priced(1_010_000_000), &ID).is_ok());
        for rate in [989_999_999, 1_010_000_001, 500_000_000] {
            let err = permitted(&priced(rate), &ID).unwrap_err().to_string();
            assert!(err.contains("off its USD peg"), "{rate}: {err}");
        }
    }

    #[test]
    fn a_euro_asset_is_checked_against_the_euro_rate_not_the_dollar() {
        let mut state = StateAdapter::new();
        let eurc = SettlementAsset::new(&format!("0x{}", hex::encode(ID)), "EURC", "EUR", 6);
        install_for_test(&mut state, &eurc);
        super::super::economy::write_symbol_rate_for_tests(&mut state, "EURC", 3, 1_080_000_000);
        // No EUR rate: refused by name rather than checked against USD.
        let err = permitted(&state, &ID).unwrap_err().to_string();
        assert!(err.contains("currency EUR"), "{err}");
        super::super::economy::write_symbol_rate_for_tests(&mut state, "EUR", 3, 1_085_000_000);
        assert_eq!(permitted(&state, &ID).unwrap().rate_nano_usd, 1_080_000_000);
        super::super::economy::write_symbol_rate_for_tests(&mut state, "EUR", 4, 1_200_000_000);
        let err = permitted(&state, &ID).unwrap_err().to_string();
        assert!(err.contains("off its EUR peg"), "{err}");
    }

    /// Once settlements fill an asset's epoch inflow cap, a quote refuses it
    /// as `asset_inflow_full`, naming what is left; the next epoch it quotes
    /// again.
    #[test]
    fn an_asset_whose_epoch_inflow_is_full_is_refused_by_quote_as_asset_inflow_full() {
        let mut state = StateAdapter::new();
        super::super::economy::write_symbol_rate_for_tests(&mut state, "USDC", 0, 1_000_000_000);
        let held = token_held_by(&mut state, &[9; 32], "USDC", 10_000_000);
        let hex_id = format!("0x{}", hex::encode(held));
        let mut entry = SettlementAsset::new(&hex_id, "USDC", "USD", 6);
        entry.epoch_inflow_cap_units = 3;
        install_for_test(&mut state, &entry);
        assert!(quote_asset(&state, &hex_id, 1_000_000).is_ok());
        let p = permitted(&state, &held).unwrap();
        admit_inflow(&mut state, &held, &p, 2_500_000, &mut Vec::new()).unwrap();
        let e = quote_asset(&state, &hex_id, 1_000_000).unwrap_err();
        assert_eq!(e.code, "asset_inflow_full");
        assert!(
            e.reason
                .contains("500000 micro-units of its epoch inflow cap left"),
            "{}",
            e.reason
        );
        assert!(quote_asset(&state, &hex_id, 500_000).is_ok());
        admit_inflow(&mut state, &held, &p, 500_000, &mut Vec::new()).unwrap();
        assert_eq!(
            quote_asset(&state, &hex_id, 1).unwrap_err().code,
            "asset_inflow_full"
        );
        // The settlement path refuses past the cap too: first-come, at once.
        assert!(admit_inflow(&mut state, &held, &p, 1, &mut Vec::new()).is_err());
    }

    fn rules(suspend: u64, resume: u64, band: u64) -> BreakerRules {
        BreakerRules {
            suspend_epochs: suspend,
            resume_epochs: resume,
            resume_band_bps: band,
        }
    }

    /// Runs `rates` through a breaker from epoch 1 against par 1.0 in a 100
    /// bps band; returns it and how many times it changed state.
    fn run(rates: &[u128], r: &BreakerRules) -> (Breaker, u64) {
        let mut b = Breaker::default();
        let mut flips = 0;
        for (i, rate) in rates.iter().enumerate() {
            let n = step_breaker(&b, i as u64 + 1, *rate, 1_000_000_000, 100, r);
            flips += u64::from(n.suspended != b.suspended);
            b = n;
        }
        (b, flips)
    }

    #[test]
    fn the_breaker_suspends_after_k_off_peg_epochs_and_resumes_only_after_m_inside_the_tighter_band()
     {
        let r = rules(3, 4, 50);
        // Two epochs off, one back on: the run restarts.
        let (b, _) = run(
            &[
                980_000_000,
                980_000_000,
                1_000_000_000,
                980_000_000,
                980_000_000,
            ],
            &r,
        );
        assert!(!b.suspended);
        assert_eq!(b.off_run, 2);
        // Three in a row suspend.
        let (b, flips) = run(&[980_000_000; 3], &r);
        assert!(b.suspended);
        assert_eq!((b.since_epoch, b.suspensions, flips), (Some(3), 1, 1));
        // Back inside the par band but outside the 50 bps resume band: still
        // suspended however long it stays there.
        let mut rates = vec![980_000_000; 3];
        rates.extend([993_000_000; 30]);
        assert!(run(&rates, &r).0.suspended);
        // Four epochs inside 50 bps re-enable it.
        rates.extend([999_000_000; 3]);
        assert!(run(&rates, &r).0.suspended);
        rates.push(1_001_000_000);
        let (b, flips) = run(&rates, &r);
        assert!(!b.suspended);
        assert_eq!((b.suspensions, flips), (1, 2));
        // An epoch already stepped steps nothing.
        let again = step_breaker(
            &b,
            b.last_epoch.unwrap(),
            500_000_000,
            1_000_000_000,
            100,
            &r,
        );
        assert_eq!(again, b);
    }

    #[test]
    fn a_rate_oscillating_at_the_band_edge_suspends_at_most_once_per_event() {
        let r = rules(3, 6, 50);
        // Alternating just inside and just outside the par band never
        // completes an off run.
        let edge: Vec<u128> = (0..200)
            .map(|i| if i % 2 == 0 { 989_900_000 } else { 990_100_000 })
            .collect();
        let (b, flips) = run(&edge, &r);
        assert_eq!((b.suspended, flips), (false, 0));
        // A real depeg, then a recovery that oscillates around the par band
        // edge: one suspension, no re-enabling until the rate settles near
        // par, then exactly one re-enabling.
        let mut path = vec![950_000_000; 5];
        path.extend((0..100).map(|i| if i % 2 == 0 { 989_000_000 } else { 991_000_000 }));
        let (b, flips) = run(&path, &r);
        assert_eq!((b.suspended, flips), (true, 1));
        path.extend([1_000_000_000; 6]);
        let (b, flips) = run(&path, &r);
        assert_eq!((b.suspended, b.suspensions, flips), (false, 1, 2));
    }

    #[test]
    fn a_suspended_asset_is_refused_by_its_own_code_until_it_resumes_and_its_holdings_still_count()
    {
        let mut state = StateAdapter::new();
        super::super::economy::write_symbol_rate_for_tests(&mut state, "USDC", 0, 1_000_000_000);
        let treasury = derive_treasury_address();
        let held = token_held_by(&mut state, treasury.as_bytes(), "USDC", 5_000_000);
        let mut entry = usdc();
        entry.token_id = format!("0x{}", hex::encode(held));
        install_for_test(&mut state, &entry);
        let value = holdings_tnzo_eq(&state, treasury.as_bytes());
        assert!(value > 0);
        let r = BreakerRules::read(&state);
        assert_eq!(
            r,
            rules(
                DEFAULT_BREAKER_SUSPEND_EPOCHS,
                DEFAULT_BREAKER_RESUME_EPOCHS,
                DEFAULT_BREAKER_RESUME_BAND_BPS
            )
        );
        let mut logs = Vec::new();
        for e in 1..=DEFAULT_BREAKER_SUSPEND_EPOCHS {
            observe_rate(
                &mut state,
                "USDC",
                e,
                900_000_000,
                &mut Vec::new(),
                &mut logs,
            )
            .unwrap();
        }
        assert_eq!(logs.len(), 1);
        assert_eq!(logs[0].topics[0], ASSET_SUSPENDED_TOPIC.to_vec());
        // The rate is back at par, but the asset stays suspended.
        super::super::economy::write_symbol_rate_for_tests(&mut state, "USDC", 4, 1_000_000_000);
        let err = permitted(&state, &held).unwrap_err().to_string();
        assert!(
            err.contains("suspended by its peg breaker since epoch 3"),
            "{err}"
        );
        let hex_id = format!("0x{}", hex::encode(held));
        assert_eq!(
            quote_asset(&state, &hex_id, 1_000_000).unwrap_err().code,
            "asset_suspended"
        );
        // Nothing is sold: the treasury still holds it, valued at its rate.
        assert_eq!(
            crate::token_ledger::balance(&state, &held, treasury.as_bytes()),
            5_000_000
        );
        assert_eq!(holdings_tnzo_eq(&state, treasury.as_bytes()), value);
        // The resume run re-enables it.
        let first = DEFAULT_BREAKER_SUSPEND_EPOCHS + 1;
        for e in first..first + DEFAULT_BREAKER_RESUME_EPOCHS {
            observe_rate(
                &mut state,
                "USDC",
                e,
                1_000_000_000,
                &mut Vec::new(),
                &mut logs,
            )
            .unwrap();
        }
        assert_eq!(logs.last().unwrap().topics[0], ASSET_RESUMED_TOPIC.to_vec());
        assert!(permitted(&state, &held).is_ok());
        assert!(quote_asset(&state, &hex_id, 1_000_000).is_ok());
    }
}

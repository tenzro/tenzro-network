//! How a settlement's value is divided.
//!
//! One pure function, [`apply`], computes the division of a gross amount: the
//! protocol fee first (charged once, on the gross, divided into burn,
//! treasury and insurance), then the network fees the payee side bears, then
//! the [`SplitRule`] lines over what is left. The VM calls it inside the
//! decision transaction; the RPC preview and every SDK call the same function
//! (or a port checked against the shared vectors in `sdk/fixtures/split`),
//! so a payer sees exactly the division the chain will make.
//!
//! All arithmetic is on `u128` with no floats. Fixed lines are paid first in
//! index order, each capped by what remains. Basis-point lines then share the
//! remaining pool by largest remainder: each takes the floor of its exact
//! share, and the units left over by flooring go one each to the lines with
//! the largest fractional parts (ties to the lower index). The single
//! `Remainder` line takes everything else, so the division conserves the gross
//! exactly.

use crate::primitives::Address;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// The rule encoding this module produces.
pub const SPLIT_RULE_VERSION: u16 = 1;

/// Most lines one rule carries.
pub const MAX_SPLIT_LINES: usize = 16;

/// Most bytes a DID-derived recipient names.
pub const MAX_SPLIT_DID_LEN: usize = 256;

/// Basis points in one whole.
pub const BPS: u128 = 10_000;

const RULE_DOMAIN: &[u8] = b"tenzro/split-rule/v1";

/// What a line is paid for. Informational for receipts and Terms limits; it
/// does not change the arithmetic.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SplitRole {
    /// The seller of the good or service.
    Payee,
    /// The publisher the sale happened on.
    Publisher,
    /// The holder of a licence the good carries.
    Licensor,
    /// Whoever referred the payer.
    Referrer,
    /// The facilitator that verified and submitted the payment.
    Facilitator,
    /// The relayer that carried a leg's proof.
    Relayer,
    /// The solver that filled an intent.
    Solver,
    /// The prover that produced a leg's proof.
    Prover,
    /// Value returned to the payer.
    Refund,
}

impl SplitRole {
    /// Whether the line pays an intermediary of the payment (a facilitator
    /// or a relayer), the share an agent's Terms bound.
    pub fn is_intermediary(self) -> bool {
        matches!(self, Self::Facilitator | Self::Relayer)
    }

    fn tag(self) -> u8 {
        match self {
            Self::Payee => 0,
            Self::Publisher => 1,
            Self::Licensor => 2,
            Self::Referrer => 3,
            Self::Facilitator => 4,
            Self::Relayer => 5,
            Self::Solver => 6,
            Self::Prover => 7,
            Self::Refund => 8,
        }
    }
}

/// Who a line pays.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SplitRecipient {
    /// A fixed account, 32-byte hex.
    Address(#[serde(with = "address_hex")] Address),
    /// The account derived from this DID's root key, resolved when paid.
    DidDerived(String),
    /// Whoever submitted the proof that completed the settlement.
    LegSubmitter,
}

/// How much a line takes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SplitBasis {
    /// A share of the pool left after fixed lines, basis points.
    Bps(u16),
    /// A fixed amount, base units, capped by what remains.
    Fixed(#[serde(with = "crate::primitives::u128_serde")] u128),
    /// Everything the other lines leave. Exactly one line per rule.
    Remainder,
}

/// One recipient's part of a [`SplitRule`].
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SplitLine {
    /// What the line is paid for.
    pub role: SplitRole,
    /// Who it pays.
    pub recipient: SplitRecipient,
    /// How much it takes.
    pub basis: SplitBasis,
    /// The most it takes, base units; the excess goes to the remainder line.
    #[serde(default, with = "crate::primitives::u128_serde_opt")]
    pub cap: Option<u128>,
}

/// The division of a settlement's net value, fixed by the quote (or the
/// payee's standing rule) before any value moves.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SplitRule {
    /// Encoding version, [`SPLIT_RULE_VERSION`].
    pub version: u16,
    /// 1 to [`MAX_SPLIT_LINES`] lines, exactly one of them `Remainder`.
    pub lines: Vec<SplitLine>,
}

/// Why a rule or a division was refused.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SplitError {
    /// The rule is malformed.
    #[error("split rule refused: {0}")]
    Rule(&'static str),
    /// The fee and network fees exceed the gross.
    #[error("fees of {fees} exceed the gross of {gross}")]
    FeesExceedGross {
        /// The protocol fee plus payee-borne network fees.
        fees: u128,
        /// The gross being divided.
        gross: u128,
    },
    /// Facilitator and relayer lines can take more than an agent's Terms allow.
    #[error("facilitator and relayer lines can take more than {max_bps} bps of the gross")]
    IntermediaryShare {
        /// The most the Terms allow, basis points of the gross.
        max_bps: u16,
    },
}

impl SplitRule {
    /// A rule that pays everything to one account.
    pub fn sole(role: SplitRole, recipient: Address) -> Self {
        Self {
            version: SPLIT_RULE_VERSION,
            lines: vec![SplitLine {
                role,
                recipient: SplitRecipient::Address(recipient),
                basis: SplitBasis::Remainder,
                cap: None,
            }],
        }
    }

    /// Check the rule's shape: version, line count, exactly one uncapped
    /// remainder line, basis points summing to at most a whole, bounded DIDs.
    pub fn validate(&self) -> Result<(), SplitError> {
        if self.version != SPLIT_RULE_VERSION {
            return Err(SplitError::Rule("unknown split rule version"));
        }
        if self.lines.is_empty() || self.lines.len() > MAX_SPLIT_LINES {
            return Err(SplitError::Rule("a split rule has 1 to 16 lines"));
        }
        let mut remainders = 0usize;
        let mut bps_sum = 0u128;
        for line in &self.lines {
            match line.basis {
                SplitBasis::Remainder => {
                    remainders += 1;
                    if line.cap.is_some() {
                        return Err(SplitError::Rule("the remainder line has no cap"));
                    }
                }
                SplitBasis::Bps(b) => {
                    if b == 0 {
                        return Err(SplitError::Rule(
                            "a basis-point line takes a positive share",
                        ));
                    }
                    bps_sum += u128::from(b);
                }
                SplitBasis::Fixed(0) => {
                    return Err(SplitError::Rule("a fixed line takes a positive amount"));
                }
                SplitBasis::Fixed(_) => {}
            }
            if let SplitRecipient::DidDerived(did) = &line.recipient
                && (did.is_empty() || did.len() > MAX_SPLIT_DID_LEN)
            {
                return Err(SplitError::Rule("a DID recipient is 1 to 256 bytes"));
            }
        }
        if remainders != 1 {
            return Err(SplitError::Rule(
                "a split rule has exactly one remainder line",
            ));
        }
        if bps_sum > BPS {
            return Err(SplitError::Rule("basis-point lines sum to at most 10000"));
        }
        Ok(())
    }

    /// The canonical byte encoding the rule hash commits to. Big-endian
    /// integers, one tag byte per variant.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(RULE_DOMAIN.len() + 3 + self.lines.len() * 52);
        out.extend_from_slice(RULE_DOMAIN);
        out.extend_from_slice(&self.version.to_be_bytes());
        out.push(self.lines.len().min(255) as u8);
        for line in &self.lines {
            out.push(line.role.tag());
            match &line.recipient {
                SplitRecipient::Address(a) => {
                    out.push(0);
                    out.extend_from_slice(&a.0);
                }
                SplitRecipient::DidDerived(did) => {
                    out.push(1);
                    out.extend_from_slice(&(did.len().min(u16::MAX as usize) as u16).to_be_bytes());
                    out.extend_from_slice(did.as_bytes());
                }
                SplitRecipient::LegSubmitter => out.push(2),
            }
            match line.basis {
                SplitBasis::Bps(b) => {
                    out.push(0);
                    out.extend_from_slice(&b.to_be_bytes());
                }
                SplitBasis::Fixed(v) => {
                    out.push(1);
                    out.extend_from_slice(&v.to_be_bytes());
                }
                SplitBasis::Remainder => out.push(2),
            }
            match line.cap {
                Some(c) => {
                    out.push(1);
                    out.extend_from_slice(&c.to_be_bytes());
                }
                None => out.push(0),
            }
        }
        out
    }

    /// SHA-256 of [`Self::canonical_bytes`]: what a quote signs and what a
    /// plan or escrow binds.
    pub fn hash(&self) -> [u8; 32] {
        Sha256::digest(self.canonical_bytes()).into()
    }

    /// Refuse a rule whose facilitator and relayer lines can take more than
    /// `max_bps` of `gross`. Each line counts at the most it can take: a
    /// basis-point line its exact share, a fixed line its amount, the
    /// remainder line the whole gross, each bounded by its cap and the gross.
    /// The bound holds whatever fee the division later charges, since a fee
    /// only shrinks what the lines share.
    pub fn check_intermediary_share(&self, gross: u128, max_bps: u16) -> Result<(), SplitError> {
        let mut most = 0u128;
        for line in &self.lines {
            if !line.role.is_intermediary() {
                continue;
            }
            // Shares in units of 1/BPS of a base unit, so no division rounds.
            let share = match line.basis {
                SplitBasis::Bps(b) => gross.saturating_mul(u128::from(b)),
                SplitBasis::Fixed(a) => a.min(gross).saturating_mul(BPS),
                SplitBasis::Remainder => gross.saturating_mul(BPS),
            };
            let share = line
                .cap
                .map_or(share, |c| share.min(c.min(gross).saturating_mul(BPS)));
            most = most.saturating_add(share);
        }
        if most > gross.saturating_mul(u128::from(max_bps)) {
            return Err(SplitError::IntermediaryShare { max_bps });
        }
        Ok(())
    }
}

/// The governed fee parameters [`apply`] reads, captured by the caller.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeParams {
    /// Protocol fee on the gross, basis points.
    pub fee_bps: u16,
    /// The least fee one settlement pays, base units (never above the gross).
    #[serde(with = "crate::primitives::u128_serde")]
    pub min_fee: u128,
    /// Share of the fee burned, basis points.
    pub burn_bps: u16,
    /// Share of the unburned fee paid to the insurance pool, basis points.
    pub insurance_bps: u16,
}

/// How the protocol fee divides.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FeeAllocation {
    /// The whole fee.
    #[serde(with = "crate::primitives::u128_serde")]
    pub fee: u128,
    /// Burned.
    #[serde(with = "crate::primitives::u128_serde")]
    pub burn: u128,
    /// To the treasury.
    #[serde(with = "crate::primitives::u128_serde")]
    pub treasury: u128,
    /// To the insurance pool.
    #[serde(with = "crate::primitives::u128_serde")]
    pub insurance: u128,
}

/// The full division of one gross amount.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Allocation {
    /// What was divided.
    #[serde(with = "crate::primitives::u128_serde")]
    pub gross: u128,
    /// The protocol fee and its parts.
    pub fee: FeeAllocation,
    /// Network fees the payee side bore.
    #[serde(with = "crate::primitives::u128_serde")]
    pub network_fees: u128,
    /// What the lines divided: `gross - fee - network_fees`.
    #[serde(with = "crate::primitives::u128_serde")]
    pub net: u128,
    /// Each line's credit, by line index.
    #[serde(with = "u128_vec")]
    pub credits: Vec<u128>,
}

impl Allocation {
    /// Whether the parts sum to the gross exactly.
    pub fn conserves(&self) -> bool {
        let fee_parts = self
            .fee
            .burn
            .checked_add(self.fee.treasury)
            .and_then(|v| v.checked_add(self.fee.insurance));
        let credits = self
            .credits
            .iter()
            .try_fold(0u128, |a, c| a.checked_add(*c));
        match (fee_parts, credits) {
            (Some(parts), Some(credits)) => {
                parts == self.fee.fee
                    && credits == self.net
                    && self
                        .fee
                        .fee
                        .checked_add(self.network_fees)
                        .and_then(|v| v.checked_add(self.net))
                        == Some(self.gross)
            }
            _ => false,
        }
    }
}

/// `value` divided across `claims` in proportion to them, by largest
/// remainder (each takes the floor of its exact share, then the units left
/// go one each to the largest fractional parts, ties to the lower index).
/// Shares sum to `value` exactly when `value <= sum(claims)`, and no share
/// exceeds its claim. Used where a shortfall is shared among creditors.
pub fn pro_rata(value: u128, claims: &[u128]) -> Vec<u128> {
    let total = claims.iter().fold(0u128, |t, c| t.saturating_add(*c));
    if total == 0 {
        return vec![0; claims.len()];
    }
    let value = value.min(total);
    let mut shares = Vec::with_capacity(claims.len());
    let mut fractions = Vec::with_capacity(claims.len());
    let mut given = 0u128;
    for (i, c) in claims.iter().enumerate() {
        let (q, r) = mul_div_rem(value, *c, total);
        shares.push(q);
        fractions.push((r, i));
        given += q;
    }
    fractions.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
    for &(_, i) in fractions.iter().take((value - given) as usize) {
        shares[i] += 1;
    }
    shares
}

/// `(a * b / d, a * b % d)` over the full 256-bit product, for `a <= d`.
fn mul_div_rem(a: u128, b: u128, d: u128) -> (u128, u128) {
    const M: u128 = u64::MAX as u128;
    let (a1, a0, b1, b0) = (a >> 64, a & M, b >> 64, b & M);
    let lo = a0 * b0;
    let mid1 = a1 * b0;
    let mid2 = a0 * b1;
    let (mid, carry) = mid1.overflowing_add(mid2);
    let (low, c2) = lo.overflowing_add(mid << 64);
    let high = a1 * b1 + (mid >> 64) + if carry { 1u128 << 64 } else { 0 } + u128::from(c2);
    let (mut q, mut r) = (0u128, 0u128);
    for bit in (0..256).rev() {
        let next = if bit >= 128 {
            (high >> (bit - 128)) & 1
        } else {
            (low >> bit) & 1
        };
        let over = r >> 127 == 1;
        r = (r << 1) | next;
        if over || r >= d {
            r = r.wrapping_sub(d);
            if bit < 128 {
                q |= 1 << bit;
            }
        }
    }
    (q, r)
}

/// `floor(value * bps / 10_000)` without overflow, for `bps <= 10_000`.
pub fn bps_of(value: u128, bps: u128) -> u128 {
    value / BPS * bps + value % BPS * bps / BPS
}

/// The protocol fee on `gross`: `max(floor(gross * fee_bps / 10_000),
/// min_fee)`, never above the gross, divided into burn, treasury and
/// insurance.
pub fn fee_allocation(gross: u128, params: &FeeParams) -> FeeAllocation {
    let fee = bps_of(gross, u128::from(params.fee_bps.min(10_000)))
        .max(params.min_fee)
        .min(gross);
    let burn = bps_of(fee, u128::from(params.burn_bps.min(10_000)));
    let unburned = fee - burn;
    let insurance = bps_of(unburned, u128::from(params.insurance_bps.min(10_000)));
    FeeAllocation {
        fee,
        burn,
        treasury: unburned - insurance,
        insurance,
    }
}

/// Divide `gross`: the protocol fee once, then `network_fees` (borne by the
/// payee side), then `rule` over what is left. Conserves the gross exactly.
pub fn apply(
    gross: u128,
    rule: &SplitRule,
    params: &FeeParams,
    network_fees: u128,
) -> Result<Allocation, SplitError> {
    rule.validate()?;
    let fee = fee_allocation(gross, params);
    let fees = fee
        .fee
        .checked_add(network_fees)
        .ok_or(SplitError::FeesExceedGross {
            fees: u128::MAX,
            gross,
        })?;
    if fees > gross {
        return Err(SplitError::FeesExceedGross { fees, gross });
    }
    let net = gross - fees;
    let credits = divide(net, rule);
    let allocation = Allocation {
        gross,
        fee,
        network_fees,
        net,
        credits,
    };
    debug_assert!(allocation.conserves());
    Ok(allocation)
}

/// Divide `net` over a validated rule's lines.
fn divide(net: u128, rule: &SplitRule) -> Vec<u128> {
    let mut credits = vec![0u128; rule.lines.len()];
    let mut left = net;
    for (i, line) in rule.lines.iter().enumerate() {
        if let SplitBasis::Fixed(v) = line.basis {
            let take = v.min(line.cap.unwrap_or(u128::MAX)).min(left);
            credits[i] = take;
            left -= take;
        }
    }
    let pool = left;
    // Largest remainder over the basis-point lines: the exact share of line
    // i is pool * bps_i / 10_000; its fractional part, scaled by 10_000, is
    // (pool % 10_000) * bps_i % 10_000 (the whole multiples of 10_000 in the
    // pool contribute no fraction).
    let bps_lines: Vec<(usize, u128)> = rule
        .lines
        .iter()
        .enumerate()
        .filter_map(|(i, l)| match l.basis {
            SplitBasis::Bps(b) => Some((i, u128::from(b))),
            _ => None,
        })
        .collect();
    let bps_sum: u128 = bps_lines.iter().map(|(_, b)| b).sum();
    let target = bps_of(pool, bps_sum);
    let mut floors_sum = 0u128;
    let mut fractions = Vec::with_capacity(bps_lines.len());
    for &(i, b) in &bps_lines {
        let share = bps_of(pool, b);
        credits[i] = share;
        floors_sum += share;
        fractions.push((pool % BPS * b % BPS, i));
    }
    // Descending fraction, ties to the lower index.
    fractions.sort_by(|a, b| b.0.cmp(&a.0).then(a.1.cmp(&b.1)));
    let mut extra = target - floors_sum;
    for &(_, i) in &fractions {
        if extra == 0 {
            break;
        }
        credits[i] += 1;
        extra -= 1;
    }
    // Caps on basis-point lines: the excess flows to the remainder line.
    for (i, line) in rule.lines.iter().enumerate() {
        if let (SplitBasis::Bps(_), Some(cap)) = (line.basis, line.cap)
            && credits[i] > cap
        {
            credits[i] = cap;
        }
    }
    let paid: u128 = credits.iter().sum();
    if let Some(r) = rule
        .lines
        .iter()
        .position(|l| l.basis == SplitBasis::Remainder)
    {
        credits[r] = net - paid;
    }
    credits
}

mod address_hex {
    use crate::primitives::Address;
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(a: &Address, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&hex::encode(a.0))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Address, D::Error> {
        let s = String::deserialize(d)?;
        hex::decode(s.trim_start_matches("0x"))
            .ok()
            .and_then(|b| <[u8; 32]>::try_from(b).ok())
            .map(Address)
            .ok_or_else(|| serde::de::Error::custom("an address is 32 bytes of hex"))
    }
}

mod u128_vec {
    use serde::{Deserialize, Deserializer, Serializer, ser::SerializeSeq};

    pub fn serialize<S: Serializer>(v: &[u128], s: S) -> Result<S::Ok, S::Error> {
        let mut seq = s.serialize_seq(Some(v.len()))?;
        for x in v {
            seq.serialize_element(&x.to_string())?;
        }
        seq.end()
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u128>, D::Error> {
        Vec::<String>::deserialize(d)?
            .into_iter()
            .map(|s| s.parse().map_err(serde::de::Error::custom))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(b: u8) -> SplitRecipient {
        SplitRecipient::Address(Address([b; 32]))
    }

    fn line(role: SplitRole, b: u8, basis: SplitBasis, cap: Option<u128>) -> SplitLine {
        SplitLine {
            role,
            recipient: addr(b),
            basis,
            cap,
        }
    }

    const PARAMS: FeeParams = FeeParams {
        fee_bps: 10,
        min_fee: 1,
        burn_bps: 5_000,
        insurance_bps: 1_000,
    };

    /// A small deterministic generator, so the property runs need no extra
    /// dependency and every failure reproduces from its seed.
    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
        fn below(&mut self, n: u64) -> u64 {
            self.next() % n.max(1)
        }
        fn amount(&mut self) -> u128 {
            match self.below(4) {
                0 => u128::from(self.below(1_000)),
                1 => u128::from(self.next()),
                2 => (u128::from(self.next()) << 64) | u128::from(self.next()),
                _ => u128::MAX - u128::from(self.below(1_000)),
            }
        }
    }

    fn random_rule(rng: &mut Rng) -> SplitRule {
        let n = 1 + rng.below(MAX_SPLIT_LINES as u64) as usize;
        let remainder_at = rng.below(n as u64) as usize;
        let mut bps_left = 10_000u64;
        let lines = (0..n)
            .map(|i| {
                let basis = if i == remainder_at {
                    SplitBasis::Remainder
                } else if rng.below(3) == 0 {
                    SplitBasis::Fixed(1 + u128::from(rng.below(1 << 40)))
                } else if bps_left > 0 {
                    let b = 1 + rng.below(bps_left);
                    bps_left -= b;
                    SplitBasis::Bps(b as u16)
                } else {
                    SplitBasis::Fixed(1 + u128::from(rng.below(1 << 20)))
                };
                let cap = (basis != SplitBasis::Remainder && rng.below(4) == 0)
                    .then(|| u128::from(rng.below(1 << 30)));
                line(SplitRole::Payee, i as u8, basis, cap)
            })
            .collect();
        SplitRule {
            version: SPLIT_RULE_VERSION,
            lines,
        }
    }

    #[test]
    fn every_division_conserves_the_gross_exactly() {
        let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
        for case in 0..20_000 {
            let rule = random_rule(&mut rng);
            rule.validate()
                .unwrap_or_else(|e| panic!("case {case}: {e}"));
            let gross = rng.amount();
            let params = FeeParams {
                fee_bps: rng.below(10_001) as u16,
                min_fee: u128::from(rng.below(1_000)),
                burn_bps: rng.below(10_001) as u16,
                insurance_bps: rng.below(10_001) as u16,
            };
            let fee = fee_allocation(gross, &params).fee;
            let network = u128::from(rng.below(1_000)).min(gross - fee);
            let a = apply(gross, &rule, &params, network).unwrap();
            assert!(a.conserves(), "case {case}: {a:?}");
            for (i, l) in rule.lines.iter().enumerate() {
                if let Some(cap) = l.cap {
                    assert!(a.credits[i] <= cap, "case {case}: line {i} over its cap");
                }
            }
        }
    }

    #[test]
    fn the_fee_is_charged_once_on_the_gross_however_many_lines() {
        let one = SplitRule::sole(SplitRole::Payee, Address([1; 32]));
        let sixteen = SplitRule {
            version: SPLIT_RULE_VERSION,
            lines: (0..16)
                .map(|i| {
                    let basis = if i == 15 {
                        SplitBasis::Remainder
                    } else {
                        SplitBasis::Bps(600)
                    };
                    line(SplitRole::Payee, i, basis, None)
                })
                .collect(),
        };
        // 16 legs of 999 each floor to a zero fee per leg; once on the gross
        // the fee is 15.
        let gross = 16 * 999;
        let a = apply(gross, &one, &PARAMS, 0).unwrap();
        let b = apply(gross, &sixteen, &PARAMS, 0).unwrap();
        assert_eq!(a.fee, b.fee);
        assert_eq!(a.fee.fee, 15);
    }

    #[test]
    fn largest_remainder_breaks_ties_by_line_index() {
        // 10 split 3334/3333/3333: floors 3,3,3, one unit left over; it goes
        // to the largest fraction (line 0), and the two tied lines stay at 3.
        let rule = SplitRule {
            version: SPLIT_RULE_VERSION,
            lines: vec![
                line(SplitRole::Payee, 1, SplitBasis::Bps(3_334), None),
                line(SplitRole::Publisher, 2, SplitBasis::Bps(3_333), None),
                line(SplitRole::Referrer, 3, SplitBasis::Bps(3_333), None),
                line(SplitRole::Refund, 4, SplitBasis::Remainder, None),
            ],
        };
        let zero = FeeParams {
            fee_bps: 0,
            min_fee: 0,
            burn_bps: 0,
            insurance_bps: 0,
        };
        let a = apply(10, &rule, &zero, 0).unwrap();
        assert_eq!(a.credits, vec![4, 3, 3, 0]);
        let again = apply(10, &rule, &zero, 0).unwrap();
        assert_eq!(a, again);
    }

    #[test]
    fn malformed_rules_are_refused() {
        let mut r = SplitRule::sole(SplitRole::Payee, Address([1; 32]));
        r.lines
            .push(line(SplitRole::Payee, 2, SplitBasis::Remainder, None));
        assert!(r.validate().is_err());
        let r = SplitRule {
            version: SPLIT_RULE_VERSION,
            lines: vec![
                line(SplitRole::Payee, 1, SplitBasis::Bps(9_000), None),
                line(SplitRole::Payee, 2, SplitBasis::Bps(2_000), None),
                line(SplitRole::Payee, 3, SplitBasis::Remainder, None),
            ],
        };
        assert!(r.validate().is_err());
        let r = SplitRule {
            version: 2,
            ..SplitRule::sole(SplitRole::Payee, Address([1; 32]))
        };
        assert!(r.validate().is_err());
    }

    #[test]
    fn fees_above_the_gross_are_refused() {
        let r = SplitRule::sole(SplitRole::Payee, Address([1; 32]));
        assert!(matches!(
            apply(100, &r, &PARAMS, 100),
            Err(SplitError::FeesExceedGross { .. })
        ));
    }

    #[test]
    fn the_rule_hash_commits_to_every_field() {
        let a = SplitRule::sole(SplitRole::Payee, Address([1; 32]));
        let mut b = a.clone();
        b.lines[0].role = SplitRole::Solver;
        let mut c = a.clone();
        c.lines[0].recipient = addr(2);
        assert_ne!(a.hash(), b.hash());
        assert_ne!(a.hash(), c.hash());
        assert_eq!(a.hash(), a.clone().hash());
    }

    /// The shared vectors every SDK port is checked against.
    #[test]
    fn the_shared_vectors_hold() {
        #[derive(Deserialize)]
        struct Vector {
            name: String,
            #[serde(with = "crate::primitives::u128_serde")]
            gross: u128,
            rule: SplitRule,
            params: FeeParams,
            #[serde(with = "crate::primitives::u128_serde")]
            network_fees: u128,
            rule_hash: String,
            expect: Allocation,
        }
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../sdk/fixtures/split");
        let mut seen = 0;
        for entry in std::fs::read_dir(&dir).expect("sdk/fixtures/split exists") {
            let path = entry.unwrap().path();
            if path.extension().and_then(|e| e.to_str()) != Some("json") {
                continue;
            }
            let vectors: Vec<Vector> =
                serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
            for v in vectors {
                let got = apply(v.gross, &v.rule, &v.params, v.network_fees).unwrap();
                assert_eq!(got, v.expect, "{}: {}", path.display(), v.name);
                assert_eq!(
                    hex::encode(v.rule.hash()),
                    v.rule_hash,
                    "{}: {}",
                    path.display(),
                    v.name
                );
                seen += 1;
            }
        }
        assert!(seen > 0, "no split vectors found");
    }

    #[test]
    fn pro_rata_conserves_and_caps_each_claim() {
        assert_eq!(pro_rata(10, &[5, 5, 10]), vec![3, 2, 5]);
        assert_eq!(pro_rata(0, &[5, 5]), vec![0, 0]);
        assert_eq!(pro_rata(99, &[10, 20]), vec![10, 20]);
        let big = u128::MAX / 3;
        let s = pro_rata(big, &[big, big, big]);
        assert_eq!(s.iter().sum::<u128>(), big);
        assert!(s.iter().all(|x| *x <= big));
        let s = pro_rata(7, &[u128::MAX / 2, 1, u128::MAX / 2]);
        assert_eq!(s.iter().sum::<u128>(), 7);
    }

    #[test]
    fn intermediary_share_is_bounded_by_the_most_each_line_can_take() {
        let rule = |lines: Vec<SplitLine>| SplitRule {
            version: SPLIT_RULE_VERSION,
            lines,
        };
        let payee = line(SplitRole::Payee, 1, SplitBasis::Remainder, None);
        let fac = |basis, cap| line(SplitRole::Facilitator, 2, basis, cap);
        let relay = |basis| line(SplitRole::Relayer, 3, basis, None);

        // 100 bps facilitator + 50 bps relayer: within 150, above 149.
        let r = rule(vec![
            payee.clone(),
            fac(SplitBasis::Bps(100), None),
            relay(SplitBasis::Bps(50)),
        ]);
        assert_eq!(r.check_intermediary_share(1_000_000, 150), Ok(()));
        assert_eq!(
            r.check_intermediary_share(1_000_000, 149),
            Err(SplitError::IntermediaryShare { max_bps: 149 })
        );
        // A fixed line counts at its amount against the gross.
        let r = rule(vec![payee.clone(), fac(SplitBasis::Fixed(200), None)]);
        assert_eq!(r.check_intermediary_share(10_000, 200), Ok(()));
        assert!(r.check_intermediary_share(10_000, 199).is_err());
        // A cap bounds a line; a remainder facilitator can take everything.
        let r = rule(vec![
            line(SplitRole::Payee, 1, SplitBasis::Bps(9_000), None),
            fac(SplitBasis::Remainder, None),
        ]);
        assert!(r.check_intermediary_share(10_000, 9_999).is_err());
        assert_eq!(r.check_intermediary_share(10_000, 10_000), Ok(()));
        let r = rule(vec![payee.clone(), fac(SplitBasis::Bps(5_000), Some(10))]);
        assert_eq!(r.check_intermediary_share(10_000, 10), Ok(()));
        // Other roles are not intermediaries.
        let r = rule(vec![
            payee,
            line(SplitRole::Referrer, 4, SplitBasis::Bps(3_000), None),
        ]);
        assert_eq!(r.check_intermediary_share(10_000, 0), Ok(()));
    }
}

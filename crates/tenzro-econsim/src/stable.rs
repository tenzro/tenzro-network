//! A stable settlement asset on the simulated ledger.
//!
//! When payments settle in a stable unit ([`Assumptions::stable_asset`]),
//! escrows to providers hold a token the ledger's token factory issues. The
//! account that stands for everyone outside the simulation who holds the
//! stable unit ([`ids::STABLE_OUTSIDE`]) creates it with a fixed supply and
//! no issuer powers, so the supply never changes: agents are funded from
//! that account and providers redeem to it. The VM charges the settlement
//! fee of a token payment in TNZO, from the payee, on the payment's USD
//! price, and the treasury leg beside it; gas and bonds stay in TNZO.
//!
//! With the stable leg ([`Assumptions::stable_leg`]) the leg is taken in
//! the token instead: the chain's leg is set to zero and each provider pays
//! the leg of what it was paid to the treasury in the token, at the rate
//! and on the base the VM uses (the class's bps of the payment less the
//! settlement fee).
//!
//! [`Assumptions::stable_asset`]: crate::economy::Assumptions::stable_asset
//! [`Assumptions::stable_leg`]: crate::economy::Assumptions::stable_leg
//! [`ids::STABLE_OUTSIDE`]: crate::economy::ids::STABLE_OUTSIDE

use std::collections::BTreeMap;

use sha2::{Digest, Sha256};
use tenzro_types::primitives::Address;
use tenzro_types::token_op::TokenOp;
use tenzro_types::token_policy::{PowerManifest, TokenPolicy};
use tenzro_vm::native as n;
use tenzro_vm::traits::VmState;

/// Decimals of the stable token: one base unit is a micro-USD, so an
/// amount is also its USD price in `usd_e6`.
pub const DECIMALS: u8 = 6;
/// Base units in one USD.
pub const UNIT: u128 = 1_000_000;
/// The fixed supply, USD: everything outside holders could pay with.
pub const SUPPLY_USD: u128 = 1_000_000_000_000;

/// The fixed supply, base units.
pub fn supply() -> u128 {
    SUPPLY_USD * UNIT
}

/// Base units as USD.
pub fn usd(x: u128) -> f64 {
    x as f64 / UNIT as f64
}

/// USD as base units.
pub fn units(usd: f64) -> u128 {
    (usd.max(0.0) * UNIT as f64) as u128
}

/// The vault an escrow's funds sit in, derived as the VM derives it.
pub fn vault_address(escrow_id: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"tenzro/escrow/vault");
    h.update(escrow_id);
    h.finalize().into()
}

/// Call data of the token's creation: fixed supply, no issuer powers, an
/// open policy with the shortest policy timelock the chain allows.
pub fn create_call(policy_timelock_ms: u64) -> Vec<u8> {
    op_call(&TokenOp::Create {
        name: "USD stable".into(),
        symbol: "USDS".into(),
        decimals: DECIMALS,
        initial_supply: supply(),
        max_supply: Some(supply()),
        powers: PowerManifest::NONE,
        policy: TokenPolicy {
            eligibility: Vec::new(),
            policy_timelock_ms,
        },
        council: None,
        reserve_backing: None,
    })
}

/// The symbol validators report the stable token's rate under.
pub const SYMBOL: &str = "USDS";

/// The proposal that installs the stable token as a settlement asset
/// pegged to the dollar, with the registry's genesis limits: until it is
/// enacted, a payment in the token is refused.
pub fn install_action(token: [u8; 32]) -> Vec<u8> {
    let asset = tenzro_types::settlement_asset::SettlementAsset::new(
        &format!("0x{}", hex::encode(token)),
        SYMBOL,
        "USD",
        DECIMALS,
    );
    serde_json::to_vec(&tenzro_vm::governance::ProposalAction::SetSettlementAsset {
        asset,
        memo: "simulated".into(),
    })
    .expect("action encodes")
}

/// Call data of a holder transfer of `amount` of `token` to `to`.
pub fn transfer_call(token: [u8; 32], to: [u8; 32], amount: u128) -> Vec<u8> {
    op_call(&TokenOp::Transfer {
        token_id: token,
        to: to.to_vec(),
        amount,
    })
}

fn op_call(op: &TokenOp) -> Vec<u8> {
    let mut data = n::SELECTOR_TOKEN.to_vec();
    data.extend_from_slice(&serde_json::to_vec(op).expect("token op encodes"));
    data
}

/// Payload of an escrow of `amount` of the token at `asset` to `payee`.
pub fn escrow_payload(
    payee: [u8; 32],
    amount: u128,
    asset: &str,
    expires_at: i64,
    release_conditions: tenzro_types::settlement::ReleaseConditions,
) -> Vec<u8> {
    #[derive(serde::Serialize)]
    struct P {
        payee: Address,
        amount: u128,
        asset_id: tenzro_types::AssetId,
        usd_e6: u64,
        expires_at: i64,
        release_conditions: tenzro_types::settlement::ReleaseConditions,
    }
    serde_json::to_vec(&P {
        payee: Address::new(payee),
        amount,
        asset_id: tenzro_types::AssetId::new(asset),
        usd_e6: u64::try_from(amount).unwrap_or(u64::MAX),
        expires_at,
        release_conditions,
    })
    .expect("escrow payload encodes")
}

/// The work a payment buys, which sets its treasury leg.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Work {
    /// A compute stream: a compute lease.
    Compute,
    /// An agent session: inference served.
    Inference,
}

/// An escrow of the token the run follows until it closes.
#[derive(Debug, Clone)]
pub struct Escrow {
    /// Index of the provider it pays.
    pub provider: usize,
    /// The account that funded it.
    pub payer: u32,
    /// What it pays for.
    pub work: Work,
    /// Paid out of it so far, as last read.
    pub claimed: u128,
    /// When it expires, calendar ms.
    pub expires_ms: i64,
    /// When its payer last asked for it to be closed, calendar ms.
    pub close_sent_ms: i64,
}

/// What one block paid a provider out of the token escrows.
#[derive(Debug, Clone, Copy)]
pub struct Paid {
    /// Index of the provider.
    pub provider: usize,
    /// What it pays for.
    pub work: Work,
    /// Base units paid.
    pub amount: u128,
}

/// The stable asset of a run.
#[derive(Debug, Clone)]
pub struct Stable {
    /// Token id.
    pub token: [u8; 32],
    /// Asset string escrows name it by.
    pub asset: String,
    /// Open escrows of the token.
    pub escrows: BTreeMap<[u8; 32], Escrow>,
    /// Treasury leg of inference taken in the token, bps; zero unless the
    /// leg is taken in the token.
    pub leg_inference_bps: u64,
    /// Treasury leg of compute leases taken in the token, bps.
    pub leg_compute_bps: u64,
    /// Whether the leg is taken in the token.
    pub leg_in_token: bool,
    /// Legs providers have sent to the treasury, base units.
    pub legs_sent: u128,
}

impl Stable {
    /// The stable asset of token `token`.
    pub fn new(
        token: [u8; 32],
        leg_in_token: bool,
        leg_inference_bps: u64,
        leg_compute_bps: u64,
    ) -> Self {
        Self {
            token,
            asset: format!("0x{}", hex::encode(token)),
            escrows: BTreeMap::new(),
            leg_inference_bps,
            leg_compute_bps,
            leg_in_token,
            legs_sent: 0,
        }
    }

    /// `owner`'s balance of the token.
    pub fn balance(&self, state: &dyn VmState, owner: &[u8]) -> u128 {
        tenzro_vm::token_ledger::balance(state, &self.token, owner)
    }

    /// The treasury leg the provider owes on `amount` of `work` paid with a
    /// settlement fee of `fee_bps`, base units: zero unless the leg is
    /// taken in the token.
    pub fn leg_of(&self, work: Work, amount: u128, fee_bps: u64) -> u128 {
        if !self.leg_in_token {
            return 0;
        }
        let bps = match work {
            Work::Compute => self.leg_compute_bps,
            Work::Inference => self.leg_inference_bps,
        };
        let after_fee = amount - amount * u128::from(fee_bps.min(10_000)) / 10_000;
        after_fee * u128::from(bps.min(n::economy::MAX_TREASURY_LEG_BPS)) / 10_000
    }

    /// Reads every open escrow after a block: what each paid out since the
    /// last read, and the escrows that closed, which leave the book. An
    /// escrow that was never created leaves it too. Returns the payments,
    /// and any closed escrow whose vault still holds the token.
    pub fn after_block(&mut self, state: &dyn VmState) -> (Vec<Paid>, Vec<String>) {
        let mut paid = Vec::new();
        let mut breaks = Vec::new();
        let mut closed = Vec::new();
        for (id, e) in self.escrows.iter_mut() {
            let Some(rec) = n::read_escrow(state, id) else {
                closed.push(*id);
                continue;
            };
            if rec.claimed > e.claimed {
                paid.push(Paid {
                    provider: e.provider,
                    work: e.work,
                    amount: rec.claimed - e.claimed,
                });
                e.claimed = rec.claimed;
            }
            let funded = serde_json::to_value(rec.status)
                .ok()
                .is_some_and(|v| v.as_str() == Some("Funded"));
            if !funded {
                let left = tenzro_vm::token_ledger::balance(state, &self.token, &vault_address(id));
                if left > 0 {
                    breaks.push(format!(
                        "escrow {} closed with {left} of the stable token in its vault",
                        hex::encode(id)
                    ));
                }
                closed.push(*id);
            }
        }
        for id in closed {
            self.escrows.remove(&id);
        }
        (paid, breaks)
    }

    /// Escrows past their expiry by an hour that their payer should close,
    /// at most once a day each: (payer, escrow id).
    pub fn to_close(&mut self, now_ms: i64) -> Vec<(u32, [u8; 32])> {
        let mut out = Vec::new();
        for (id, e) in self.escrows.iter_mut() {
            if now_ms > e.expires_ms + crate::chain::HOUR_MS
                && now_ms >= e.close_sent_ms + crate::chain::DAY_MS
            {
                e.close_sent_ms = now_ms;
                out.push((e.payer, *id));
            }
        }
        out
    }

    /// The conservation rule of the token: its recorded supply is the fixed
    /// supply, and `holders` (every account of the run) and the vaults of
    /// the open escrows hold exactly that between them. Returns what broke.
    pub fn check(&self, state: &dyn VmState, holders: &[[u8; 32]]) -> Option<String> {
        let recorded = tenzro_vm::token_ledger::read_token(state, &self.token)
            .map(|r| r.total_supply)
            .unwrap_or(0);
        if recorded != supply() {
            return Some(format!(
                "the stable token records a supply of {recorded}, not {}",
                supply()
            ));
        }
        let accounts: u128 = holders.iter().map(|a| self.balance(state, a)).sum();
        let vaults: u128 = self
            .escrows
            .keys()
            .map(|id| self.balance(state, &vault_address(id)))
            .sum();
        let held = accounts + vaults;
        (held != supply()).then(|| {
            format!(
                "the run's accounts and open escrows hold {held} of the stable token; the supply is {}",
                supply()
            )
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_leg_is_taken_on_the_payment_less_the_fee() {
        let s = Stable::new([1; 32], true, 800, 500);
        // $100 of inference at a 0.1% fee: 8% of $99.90.
        assert_eq!(s.leg_of(Work::Inference, 100 * UNIT, 10), 7_992_000);
        assert_eq!(s.leg_of(Work::Compute, 100 * UNIT, 10), 4_995_000);
        let tnzo_leg = Stable::new([1; 32], false, 800, 500);
        assert_eq!(tnzo_leg.leg_of(Work::Inference, 100 * UNIT, 10), 0);
    }

    #[test]
    fn an_amount_is_its_own_usd_price() {
        assert_eq!(units(12.5), 12_500_000);
        assert_eq!(usd(12_500_000), 12.5);
    }
}

//! A payment stated without a rail, resolved to the plan leg that carries it.
//!
//! A payee says which rails it accepts, in the order it prefers them; a payer
//! says which it can fund. [`resolve`] picks the payee's first accepted rail
//! the payer can fund and that has a price, converts the USD value into that
//! rail's units, and builds the settlement plan leg that moves it: a TNZO
//! transfer or a netted stablecoin obligation on Tenzro, a lock on another
//! chain reached by a governed route, or an instruction on a bank or card
//! rail. The intent names no rail of its own, so one intent pays whoever
//! accepts whatever the payer holds.
//!
//! Prices are the caller's: a rail with no price is passed over rather than
//! routed on a guessed number. Nothing here reads state or moves value; the
//! payer opens the plan holding the leg, and the plan's rules decide it.

use tenzro_types::bridge_route::BridgeRouteAdapter;
use tenzro_types::primitives::Address;
use tenzro_types::settlement::{Leg, LegClass, LegKind, RailKind};

/// A rail a payee accepts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AcceptedRail {
    /// TNZO on Tenzro (`asset` `None`) or a Tenzro token, by id.
    Tenzro { asset: Option<[u8; 32]> },
    /// An asset on another chain a governed route reaches, paid to
    /// `recipient` there.
    Remote {
        adapter: BridgeRouteAdapter,
        chain: String,
        asset: [u8; 32],
        recipient: [u8; 32],
    },
    /// A bank or card rail in `currency`, confirmed by the payee or by its
    /// bonded `attestor`.
    Instruction {
        rail: RailKind,
        currency: String,
        attestor: Option<Address>,
    },
}

/// What a payer can fund.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PayerMeans {
    /// Tenzro assets it holds: `None` for TNZO, a token id otherwise.
    pub tenzro: Vec<Option<[u8; 32]>>,
    /// Assets it holds on other chains, as `(chain, asset)`.
    pub remote: Vec<(String, [u8; 32])>,
    /// Bank and card rails it can instruct, with the currency.
    pub instruction: Vec<(RailKind, String)>,
}

/// A payment without a rail.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RailIntent {
    /// Value, USD micro-units.
    pub usd_e6: u64,
    /// The payee's Tenzro account: it confirms and is compensated on a rail
    /// leg.
    pub payee: Address,
    /// The rails the payee accepts, preferred first.
    pub accepts: Vec<AcceptedRail>,
}

/// A rail leg's parts known only once the payer has made its instruction.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct InstructionParts {
    /// SHA-256 of the instruction sent on the rail.
    pub instruction_digest: [u8; 32],
    /// TNZO, wei, escrowed to compensate the payee if the leg fails.
    pub reserve: u128,
}

/// Why an intent resolved to no leg.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RailIntentError {
    /// The payee accepts no rail the payer can fund.
    #[error("the payee accepts no rail the payer can fund")]
    NoCommonRail,
    /// The payer can fund an accepted rail, but none has a price.
    #[error("no rail the payer and payee share has a price")]
    Unpriced,
}

impl AcceptedRail {
    fn funded_by(&self, means: &PayerMeans) -> bool {
        match self {
            Self::Tenzro { asset } => means.tenzro.contains(asset),
            Self::Remote { chain, asset, .. } => {
                means.remote.iter().any(|(c, a)| c == chain && a == asset)
            }
            Self::Instruction { rail, currency, .. } => means
                .instruction
                .iter()
                .any(|(r, c)| r == rail && c.eq_ignore_ascii_case(currency)),
        }
    }
}

/// The leg carrying `intent` on the payee's first accepted rail that the
/// payer can fund and `amount_for` prices: `amount_for(rail, usd_e6)` is the
/// rail's units for that value, `None` when the caller has no price.
pub fn resolve(
    intent: &RailIntent,
    means: &PayerMeans,
    amount_for: &dyn Fn(&AcceptedRail, u64) -> Option<u128>,
    instruction: InstructionParts,
) -> Result<Leg, RailIntentError> {
    let mut shared = false;
    for rail in intent.accepts.iter().filter(|r| r.funded_by(means)) {
        shared = true;
        let Some(amount) = amount_for(rail, intent.usd_e6) else {
            continue;
        };
        let (kind, class_required) = match rail {
            AcceptedRail::Tenzro { asset: None } => (
                LegKind::NativeTransfer {
                    amount,
                    escrow_id: None,
                },
                LegClass::Native,
            ),
            AcceptedRail::Tenzro { asset: Some(asset) } => (
                LegKind::Netted {
                    asset: *asset,
                    amount,
                },
                LegClass::Native,
            ),
            AcceptedRail::Remote {
                adapter,
                chain,
                asset,
                recipient,
            } => (
                LegKind::RemoteLock {
                    adapter: *adapter,
                    chain: chain.clone(),
                    asset: *asset,
                    amount,
                    recipient: *recipient,
                },
                LegClass::Proven,
            ),
            AcceptedRail::Instruction {
                rail,
                currency,
                attestor,
            } => (
                LegKind::RailInstruction {
                    rail: *rail,
                    instruction_digest: instruction.instruction_digest,
                    currency: currency.clone(),
                    amount_minor: amount,
                    payee: intent.payee,
                    attestor: *attestor,
                    reserve: instruction.reserve,
                },
                LegClass::Attested,
            ),
        };
        return Ok(Leg {
            kind,
            class_required,
            usd_e6: intent.usd_e6,
            max_network_fee: 0,
        });
    }
    Err(if shared {
        RailIntentError::Unpriced
    } else {
        RailIntentError::NoCommonRail
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const USDC: [u8; 32] = [0x0c; 32];

    fn intent() -> RailIntent {
        RailIntent {
            usd_e6: 2_500_000,
            payee: Address::new([9; 32]),
            accepts: vec![
                AcceptedRail::Tenzro { asset: Some(USDC) },
                AcceptedRail::Remote {
                    adapter: BridgeRouteAdapter::Ccip,
                    chain: "eip155:8453".into(),
                    asset: USDC,
                    recipient: [7; 32],
                },
                AcceptedRail::Instruction {
                    rail: RailKind::Iso20022,
                    currency: "EUR".into(),
                    attestor: None,
                },
                AcceptedRail::Tenzro { asset: None },
            ],
        }
    }

    /// One USD value per unit for stablecoins and cents for fiat; TNZO has
    /// no price unless the test gives one.
    fn prices(tnzo: Option<u128>) -> impl Fn(&AcceptedRail, u64) -> Option<u128> {
        move |rail, usd_e6| match rail {
            AcceptedRail::Tenzro { asset: None } => tnzo.map(|p| u128::from(usd_e6) * p),
            AcceptedRail::Instruction { .. } => Some(u128::from(usd_e6) / 10_000),
            _ => Some(u128::from(usd_e6)),
        }
    }

    /// The same intent resolves to whatever the payer can fund, in the
    /// payee's order, with the value carried into the leg.
    #[test]
    fn one_intent_resolves_to_the_payees_first_rail_the_payer_can_fund() {
        let i = intent();
        let none = InstructionParts::default();

        let holds_usdc = PayerMeans {
            tenzro: vec![Some(USDC)],
            ..Default::default()
        };
        let leg = resolve(&i, &holds_usdc, &prices(None), none).unwrap();
        assert_eq!(
            leg.kind,
            LegKind::Netted {
                asset: USDC,
                amount: 2_500_000
            }
        );
        assert_eq!(leg.class_required, LegClass::Native);
        assert_eq!(leg.usd_e6, 2_500_000);

        let on_base = PayerMeans {
            remote: vec![("eip155:8453".into(), USDC)],
            ..Default::default()
        };
        let leg = resolve(&i, &on_base, &prices(None), none).unwrap();
        assert!(matches!(
            leg.kind,
            LegKind::RemoteLock { amount: 2_500_000, recipient, .. } if recipient == [7; 32]
        ));
        assert_eq!(leg.class_required, LegClass::Proven);

        let bank = PayerMeans {
            instruction: vec![(RailKind::Iso20022, "eur".into())],
            ..Default::default()
        };
        let parts = InstructionParts {
            instruction_digest: [3; 32],
            reserve: 11,
        };
        let leg = resolve(&i, &bank, &prices(None), parts).unwrap();
        assert!(matches!(
            leg.kind,
            LegKind::RailInstruction { amount_minor: 250, reserve: 11, instruction_digest, .. }
                if instruction_digest == [3; 32]
        ));
        assert_eq!(leg.class_required, LegClass::Attested);

        // TNZO is accepted but unpriced: the rail is passed over, not guessed.
        let tnzo = PayerMeans {
            tenzro: vec![None],
            ..Default::default()
        };
        assert_eq!(
            resolve(&i, &tnzo, &prices(None), none),
            Err(RailIntentError::Unpriced)
        );
        let leg = resolve(&i, &tnzo, &prices(Some(4)), none).unwrap();
        assert_eq!(
            leg.kind,
            LegKind::NativeTransfer {
                amount: 10_000_000,
                escrow_id: None
            }
        );

        let nothing = PayerMeans {
            remote: vec![("solana".into(), USDC)],
            ..Default::default()
        };
        assert_eq!(
            resolve(&i, &nothing, &prices(None), none),
            Err(RailIntentError::NoCommonRail)
        );
    }
}

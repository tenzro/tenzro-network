//! Generators for settlement plan operations.
//!
//! The tests in `tests/` drive these through the native executor and check
//! that no input panics it, that a refused operation changes nothing, that
//! no sequence of operations creates value, and that a decided plan stays
//! decided. The number of cases is bounded by `PROPTEST_CASES`, so a CI run
//! is time-boxed by its setting.

use proptest::collection::vec;
use proptest::prelude::*;
use tenzro_types::primitives::Address;
use tenzro_types::settlement::{Leg, LegClass, LegKind, PlanOp};
use tenzro_types::split::{
    SPLIT_RULE_VERSION, SplitBasis, SplitLine, SplitRecipient, SplitRole, SplitRule,
};

/// The account every generated plan is opened by.
pub const PAYER: [u8; 32] = [7; 32];
/// What the payer holds before the first operation.
pub const PAYER_FUNDS: u128 = 1_000 * 1_000_000_000_000_000_000;

/// A few fixed recipients, so splits pay accounts the tests can watch.
pub const RECIPIENTS: [[u8; 32]; 3] = [[1; 32], [2; 32], [3; 32]];

fn amount() -> impl Strategy<Value = u128> {
    prop_oneof![
        Just(0u128),
        1u128..1_000u128,
        1u128..=PAYER_FUNDS,
        Just(PAYER_FUNDS),
        Just(PAYER_FUNDS + 1),
        Just(u128::MAX),
    ]
}

fn class() -> impl Strategy<Value = LegClass> {
    prop_oneof![
        Just(LegClass::Native),
        Just(LegClass::Proven),
        Just(LegClass::Attested)
    ]
}

fn kind() -> impl Strategy<Value = LegKind> {
    prop_oneof![
        4 => (amount(), proptest::option::of(any::<[u8; 32]>()))
            .prop_map(|(amount, escrow_id)| LegKind::NativeTransfer { amount, escrow_id }),
        1 => (any::<[u8; 32]>(), amount()).prop_map(|(asset, amount)| LegKind::Netted { asset, amount }),
        1 => (prop_oneof![Just("cosmoshub-4".to_string()), "[a-z0-9-]{0,12}"], any::<u64>())
            .prop_map(|(chain, sequence)| LegKind::IbcTransfer { chain, sequence }),
    ]
}

/// One leg of any kind and class.
pub fn leg() -> impl Strategy<Value = Leg> {
    (kind(), class(), any::<u64>(), amount()).prop_map(
        |(kind, class_required, usd_e6, max_network_fee)| Leg {
            kind,
            class_required,
            usd_e6,
            max_network_fee,
        },
    )
}

fn role() -> impl Strategy<Value = SplitRole> {
    prop_oneof![
        Just(SplitRole::Payee),
        Just(SplitRole::Publisher),
        Just(SplitRole::Licensor),
        Just(SplitRole::Referrer),
        Just(SplitRole::Facilitator),
        Just(SplitRole::Relayer),
        Just(SplitRole::Solver),
        Just(SplitRole::Prover),
        Just(SplitRole::Refund),
    ]
}

fn line() -> impl Strategy<Value = SplitLine> {
    (
        role(),
        prop_oneof![
            4 => proptest::sample::select(RECIPIENTS.to_vec()).prop_map(|a| SplitRecipient::Address(Address::new(a))),
            1 => Just(SplitRecipient::LegSubmitter),
            1 => "did:tenzro:[a-z]{1,8}:[a-z0-9]{0,8}".prop_map(SplitRecipient::DidDerived),
        ],
        prop_oneof![
            3 => (0u16..=10_000).prop_map(SplitBasis::Bps),
            1 => any::<u16>().prop_map(SplitBasis::Bps),
            1 => amount().prop_map(SplitBasis::Fixed),
            2 => Just(SplitBasis::Remainder),
        ],
        proptest::option::of(amount()),
    )
        .prop_map(|(role, recipient, basis, cap)| SplitLine { role, recipient, basis, cap })
}

/// A split rule: usually well formed, sometimes not.
pub fn split() -> impl Strategy<Value = SplitRule> {
    (
        prop_oneof![9 => Just(SPLIT_RULE_VERSION), 1 => any::<u16>()],
        vec(line(), 0..18),
    )
        .prop_map(|(version, lines)| SplitRule { version, lines })
}

/// An `Open` whose deadline lies within a day of `now_ms`, with a split hash
/// that usually matches its split.
pub fn open(now_ms: i64) -> impl Strategy<Value = PlanOp> {
    (
        any::<u64>(),
        any::<[u8; 32]>(),
        split(),
        prop::bool::weighted(0.9),
        vec(leg(), 0..20),
        -60_000i64..86_400_000,
    )
        .prop_map(
            move |(nonce, quote_digest, split, hash_matches, legs, offset)| PlanOp::Open {
                nonce,
                quote_digest,
                split_hash: if hash_matches {
                    split.hash()
                } else {
                    quote_digest
                },
                split,
                legs,
                decide_deadline_ms: (now_ms + offset).max(0) as u64,
                agent: None,
                attribution: None,
            },
        )
}

/// A `ProveLeg` or `DisputeRail` on `plan_id`, or on a random plan when
/// `plan_id` is `None`.
pub fn prove(plan_id: Option<[u8; 32]>) -> impl Strategy<Value = PlanOp> {
    let id = match plan_id {
        Some(id) => Just(id).boxed(),
        None => any::<[u8; 32]>().boxed(),
    };
    (
        id,
        any::<u8>(),
        vec(any::<u8>(), 0..256),
        amount(),
        prop::bool::weighted(0.8),
    )
        .prop_map(|(plan_id, index, evidence, network_fee, prove)| {
            if prove {
                PlanOp::ProveLeg {
                    plan_id,
                    index: index % 24,
                    evidence,
                    network_fee,
                }
            } else {
                PlanOp::DisputeRail {
                    plan_id,
                    index: index % 24,
                    evidence,
                }
            }
        })
}

/// One step of a session: an operation, a block boundary, or raw bytes sent
/// as the operation payload.
#[derive(Debug, Clone)]
pub enum Step {
    /// Open a plan.
    Open(PlanOp),
    /// Prove or dispute a leg of the `n`th plan opened so far (modulo), or
    /// of an unknown plan when none is open.
    Prove(usize, PlanOp),
    /// Advance the clock by this many milliseconds and run the block hook.
    Block(i64),
    /// Send these bytes as the payload.
    Raw(Vec<u8>),
}

/// A session of steps starting at `now_ms`.
pub fn session(now_ms: i64) -> impl Strategy<Value = Vec<Step>> {
    vec(
        prop_oneof![
            4 => open(now_ms).prop_map(Step::Open),
            3 => (any::<usize>(), prove(None)).prop_map(|(n, op)| Step::Prove(n, op)),
            2 => (0i64..7_200_000).prop_map(Step::Block),
            1 => vec(any::<u8>(), 0..512).prop_map(Step::Raw),
        ],
        1..24,
    )
}

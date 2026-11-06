//! Adversaries that run beside the honest populations, and their books.
//!
//! An adversary is a parameterised strategy. Its profit is measured on the
//! ledger: what its accounts hold at the end against what they held at the
//! start, plus bonds still held for it, minus its off-chain costs. A
//! strategy is reported as profitable only when that figure is positive in
//! the run that executed it.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use tenzro_sim::ledger::{self, SimTx, TNZO, TxResult};
use tenzro_types::primitives::Address;
use tenzro_vm::native as n;

use crate::chain::{DAY_MS, HOUR_MS, tnzo};
use crate::economy::{Economy, NATIVE_GAS, ids};

/// A strategy and its parameters.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Adversary {
    /// One party is both renter and provider. The provider bonds the
    /// minimum and stays unreachable; the renter streams to it and claims
    /// each unavailable hour back from the insurance pool, while the
    /// provider still collects the stream.
    SelfDealingSla {
        /// Day the strategy starts.
        start_day: u32,
        /// Days it runs.
        run_days: u32,
        /// Streams opened per hour.
        streams_per_hour: u32,
        /// Stream rate, whole TNZO per hour.
        rate_tnzo: f64,
        /// Hours each stream lasts.
        stream_hours: u32,
        /// Compute bond posted, whole TNZO.
        bond_tnzo: f64,
    },
    /// Validators holding a stake share attest an honest provider
    /// unavailable while their own renters stream to it and claim the
    /// insurance.
    CartelFalseDown {
        /// Day the strategy starts.
        start_day: u32,
        /// Days it runs.
        run_days: u32,
        /// Validators in the cartel (the lowest ids).
        cartel: u32,
        /// Share of honest validators that attest each hour.
        honest_attest: f64,
        /// Streams the cartel's renters open per hour.
        streams_per_hour: u32,
        /// Stream rate, whole TNZO per hour.
        rate_tnzo: f64,
    },
    /// Validators propose a treasury grant to themselves; the rest vote
    /// against at the given turnout or stay away.
    GovernanceCapture {
        /// Day of the proposal.
        start_day: u32,
        /// Validators in the attacking group (the lowest ids), unless
        /// `stake_share` sets the group.
        attackers: u32,
        /// Share of the other validators that vote at all (against).
        honest_turnout: f64,
        /// Grant asked for, whole TNZO.
        grant_tnzo: f64,
        /// When above zero, the attacking group is instead the lowest-id
        /// validators bonded on the start day that together hold this
        /// share of bonded stake.
        #[serde(default)]
        stake_share: f64,
    },
    /// A share of validators never votes; measures whether routine grants
    /// and fee-rate updates still pass.
    GovernanceHoldout {
        /// Share of bonded validators that never vote.
        abstain_share: f64,
    },
    /// Validators holding a stake share report the TNZO/USD rate a fixed
    /// step below the rate in force every epoch, so a clamped move
    /// compounds; or, withholding, stop reporting so that fewer reports
    /// than the quorum open.
    RateWalk {
        /// Day the strategy starts.
        start_day: u32,
        /// Days it runs.
        run_days: u32,
        /// Validators in the coalition (the lowest ids).
        cartel: u32,
        /// Step below the rate in force, basis points.
        step_bps: u32,
        /// Report nothing instead of the stepped rate.
        withhold: bool,
    },
    /// Validators holding a stake share open many treasury grants to
    /// themselves at once and enact them in two batches, the second just
    /// before or just after the treasury's outflow period rolls over, so
    /// together they would pay more than one period allows.
    SalamiGrants {
        /// Day the grants are proposed.
        open_day: u32,
        /// Validators that vote for them (the lowest ids).
        attackers: u32,
        /// Grants proposed.
        grants: u32,
        /// Each grant, whole TNZO.
        grant_tnzo: f64,
        /// Day the first half is enacted.
        enact_day: f64,
        /// Day the second half is enacted.
        second_enact_day: f64,
    },
    /// Colluding root identities pay each other in a cycle through
    /// settlement plans to earn the activity and provider rewards their
    /// settlements carry. Every member is its own registered root, so each
    /// settlement counts as organic activity.
    WashRing {
        /// Day the strategy starts.
        start_day: u32,
        /// Days it runs.
        run_days: u32,
        /// Root identities in the ring.
        ring: u32,
        /// Plans each member opens per hour.
        plans_per_hour: u32,
        /// Each plan, whole TNZO.
        value_tnzo: f64,
        /// Payees report each plan as settled work, for provider rewards.
        report_work: bool,
    },
    /// Validators holding a stake share report the TNZO/USD rate a fixed
    /// share off the market, small enough to sit inside the challenge band.
    /// Their gain is measured against the same run with every validator
    /// reporting the market.
    OracleSkew {
        /// Day the strategy starts.
        start_day: u32,
        /// Days it runs.
        run_days: u32,
        /// Validators in the cartel (the lowest ids).
        cartel: u32,
        /// Reported rate over the market rate, less one, basis points.
        skew_bps: i32,
    },
    /// The lowest-index providers raise their price together while a
    /// validator cartel attests their competitors unavailable. Buyers route
    /// by price and away from providers judged unavailable in the last
    /// closed epoch. The providers' and validators' gain is measured against
    /// the same run without collusion.
    ProviderCollusion {
        /// Day the strategy starts.
        start_day: u32,
        /// Days it runs.
        run_days: u32,
        /// Colluding providers (the lowest provider indices).
        providers: u32,
        /// Price the colluding providers charge over the market price.
        markup: f64,
        /// Validators that attest the competitors unavailable (the lowest ids).
        cartel: u32,
        /// Share of honest validators that attest each hour.
        honest_attest: f64,
    },
    /// A validator cartel reports the rate far off the market, so that the
    /// chain rate leaves the challenge band and governance's rate hold
    /// fires; it keeps or drops its skew while the rate is held. Measured
    /// against the same run with every validator reporting the market.
    PlaybookTrigger {
        /// Day the strategy starts.
        start_day: u32,
        /// Days it runs.
        run_days: u32,
        /// Validators in the cartel (the lowest ids).
        cartel: u32,
        /// Reported rate over the market rate, less one, basis points.
        skew_bps: i32,
        /// Keep reporting the skewed rate once the rate is held.
        keep_skew: bool,
    },
}

impl Adversary {
    /// Short name.
    pub fn name(&self) -> &'static str {
        match self {
            Adversary::SelfDealingSla { .. } => "self-dealing SLA insurance claims",
            Adversary::CartelFalseDown { .. } => "validator cartel false SLA verdicts",
            Adversary::GovernanceCapture { .. } => "governance capture at low turnout",
            Adversary::GovernanceHoldout { .. } => "governance holdout",
            Adversary::RateWalk { .. } => "rate report walk",
            Adversary::SalamiGrants { .. } => "many grants across a treasury outflow period",
            Adversary::WashRing { .. } => "wash ring across colluding roots",
            Adversary::OracleSkew { .. } => "validator cartel rate skew inside the band",
            Adversary::ProviderCollusion { .. } => {
                "provider price collusion with false SLA verdicts"
            }
            Adversary::PlaybookTrigger { .. } => "rate hold forced by a skewed rate",
        }
    }

    /// Whether the strategy's profit is measured against a baseline run
    /// ([`Adversary::baseline`]) rather than on its own accounts.
    pub fn paired(&self) -> bool {
        matches!(
            self,
            Adversary::OracleSkew { .. }
                | Adversary::ProviderCollusion { .. }
                | Adversary::PlaybookTrigger { .. }
        )
    }

    /// The same strategy with nobody deviating: the run a paired strategy's
    /// gain is measured against.
    pub fn baseline(&self) -> Option<Adversary> {
        match *self {
            Adversary::OracleSkew {
                start_day,
                run_days,
                ..
            } => Some(Adversary::OracleSkew {
                start_day,
                run_days,
                cartel: 0,
                skew_bps: 0,
            }),
            Adversary::ProviderCollusion {
                start_day,
                run_days,
                ..
            } => Some(Adversary::ProviderCollusion {
                start_day,
                run_days,
                providers: 0,
                markup: 1.0,
                cartel: 0,
                honest_attest: 1.0,
            }),
            Adversary::PlaybookTrigger {
                start_day,
                run_days,
                ..
            } => Some(Adversary::PlaybookTrigger {
                start_day,
                run_days,
                cartel: 0,
                skew_bps: 0,
                keep_skew: false,
            }),
            _ => None,
        }
    }

    fn window(&self) -> Option<(u32, u32)> {
        match *self {
            Adversary::WashRing {
                start_day,
                run_days,
                ..
            }
            | Adversary::OracleSkew {
                start_day,
                run_days,
                ..
            }
            | Adversary::ProviderCollusion {
                start_day,
                run_days,
                ..
            }
            | Adversary::PlaybookTrigger {
                start_day,
                run_days,
                ..
            } => Some((start_day, run_days)),
            _ => None,
        }
    }
}

/// What an adversary achieved.
#[derive(Debug, Clone, Default, Serialize)]
pub struct AttackOutcome {
    /// Strategy name.
    pub name: String,
    /// Parameters.
    pub params: serde_json::Value,
    /// Net gain on the ledger, whole TNZO.
    pub profit_tnzo: f64,
    /// Net gain at the final price, USD.
    pub profit_usd: f64,
    /// Whether the strategy turned a profit (or, for holdout, blocked governance).
    pub succeeded: bool,
    /// Insurance pool drained by the strategy, whole TNZO.
    pub pool_drained_tnzo: f64,
    /// Other measured figures.
    pub detail: BTreeMap<String, f64>,
}

/// Running state of an adversary.
#[derive(Debug, Clone)]
pub struct AdversaryState {
    /// The strategy.
    pub spec: Adversary,
    start_balance: u128,
    started: bool,
    bond_posted: u128,
    penalties: u128,
    streams: Vec<([u8; 32], i64, i64)>,
    insurance_received: u128,
    proposal: Option<Vec<u8>>,
    proposed_action: Vec<u8>,
    proposal_ms: i64,
    proposal_stage: u8,
    detail: BTreeMap<String, f64>,
    pool_at_start: f64,
    /// Open proposals with their stage: 1 voting, 2 closing sent, 3 closed,
    /// 4 enactment sent, 5 enacted, 6 refused.
    grants: Vec<(Vec<u8>, u8)>,
    /// Treasury balance when the hour's block was built.
    treasury_before: u128,
    /// Grants paid: when, how much, and the treasury balance before the
    /// block that paid them.
    payments: Vec<(i64, u128, u128)>,
    /// Plan nonce of the wash ring.
    plan_nonce: u64,
    /// Wash plans committed and not yet reported: (payee, plan id).
    pending_reports: Vec<(u32, [u8; 32])>,
    /// Reward coupons the wash ring was issued: (account, epoch, bucket) to amount.
    coupons: BTreeMap<(u32, u64, String), u128>,
    /// Identities of the colluding providers.
    cartel_dids: Vec<String>,
    /// Validators of a governance-capture group.
    capture_ids: Vec<u32>,
}

const ADV_RENTER: u32 = ids::ADVERSARY;
const ADV_PROVIDER: u32 = ids::ADVERSARY + 1;

fn adv_did() -> String {
    format!("did:tenzro:machine:econsim-{ADV_PROVIDER}")
}

fn accounts() -> std::ops::Range<u32> {
    ids::ADVERSARY..ids::ADVERSARY + ids::ADVERSARY_COUNT
}

impl AdversaryState {
    /// Fresh state.
    pub fn new(spec: Adversary) -> Self {
        Self {
            spec,
            start_balance: 0,
            started: false,
            bond_posted: 0,
            penalties: 0,
            streams: Vec::new(),
            insurance_received: 0,
            proposal: None,
            proposed_action: Vec::new(),
            proposal_ms: 0,
            proposal_stage: 0,
            detail: BTreeMap::new(),
            pool_at_start: 0.0,
            grants: Vec::new(),
            treasury_before: 0,
            payments: Vec::new(),
            plan_nonce: 0,
            pending_reports: Vec::new(),
            coupons: BTreeMap::new(),
            cartel_dids: Vec::new(),
            capture_ids: Vec::new(),
        }
    }

    fn active(&self, day: f64) -> bool {
        self.spec
            .window()
            .is_some_and(|(s, r)| day >= s as f64 && day < (s + r) as f64)
    }
}

/// First account of the wash ring.
const RING0: u32 = ids::ADVERSARY + 2;

fn ring_value(e: &Economy, st: &AdversaryState, ring: u32) -> u128 {
    let mut t = holdings(e, &[]);
    for id in RING0..RING0 + ring {
        let addr = ledger::account(id);
        t += crate::economy::vesting_total(e.chain.state(), &addr);
        t += n::rewards::read_coupons(e.chain.state(), &Address::new(addr))
            .unwrap_or_default()
            .iter()
            .filter(|c| matches!(c.status, tenzro_token::rewards::CouponStatus::Issued))
            .map(|c| c.amount)
            .sum::<u128>();
    }
    let _ = st;
    t
}

/// A validator's liquid, vesting and bonded TNZO.
fn validator_value(e: &Economy, v: u32) -> f64 {
    let addr = ledger::account(v);
    tnzo(e.chain.ledger.balance(v))
        + tnzo(crate::economy::vesting_total(e.chain.state(), &addr))
        + tnzo(
            e.chain
                .ledger
                .bonds_now()
                .get(v as usize)
                .copied()
                .unwrap_or(0),
        )
}

fn holdings(e: &Economy, vals: &[u32]) -> u128 {
    let mut t: u128 = accounts().map(|a| e.chain.ledger.balance(a)).sum();
    for v in vals {
        t += e.chain.ledger.balance(*v);
    }
    t
}

fn day(e: &Economy) -> f64 {
    e.chain.now_ms() as f64 / DAY_MS as f64
}

fn pool(e: &Economy) -> f64 {
    tnzo(e.chain.balance_of(n::insurance::pool_address().as_bytes()))
}

/// Called every hour before the block is built.
pub fn hour(e: &mut Economy) {
    let Some(mut st) = e.adv.take() else { return };
    let d = day(e);
    let now = e.chain.now_ms();
    match st.spec.clone() {
        Adversary::SelfDealingSla {
            start_day,
            run_days,
            streams_per_hour,
            rate_tnzo,
            stream_hours,
            bond_tnzo,
        } => {
            let active = d >= start_day as f64 && d < (start_day + run_days) as f64;
            if d >= start_day as f64 && !st.started {
                st.started = true;
                st.start_balance = holdings(e, &[]);
                st.pool_at_start = pool(e);
                let bond = (bond_tnzo * TNZO as f64) as u128;
                let payload = crate::chain::compute_bond_payload(&adv_did(), bond);
                if e.chain.call(
                    ADV_PROVIDER,
                    None,
                    0,
                    n::SELECTOR_POST_COMPUTE_BOND,
                    &payload,
                    NATIVE_GAS,
                    None,
                ) {
                    st.bond_posted = bond;
                }
            }
            if active && st.bond_posted > 0 {
                let rate = (rate_tnzo * TNZO as f64) as u128;
                for _ in 0..streams_per_hour {
                    if let Some(id) =
                        open_stream(e, ADV_RENTER, ADV_PROVIDER, rate, stream_hours as i64)
                    {
                        st.streams.push((
                            id,
                            now + HOUR_MS,
                            crate::chain::stream_expiry(now, stream_hours as i64),
                        ));
                    }
                }
            }
            collect_streams_and_claims(e, &mut st, ADV_PROVIDER, ADV_RENTER);
        }
        Adversary::CartelFalseDown {
            start_day,
            run_days,
            streams_per_hour,
            rate_tnzo,
            ..
        } => {
            let active = d >= start_day as f64 && d < (start_day + run_days) as f64;
            if d >= start_day as f64 && !st.started {
                st.started = true;
                st.start_balance = holdings(e, &[]);
                st.pool_at_start = pool(e);
            }
            // The victim is the first honest provider that has bonded.
            let victim = (ids::PROVIDERS..ids::PROVIDERS + ids::PROVIDER_COUNT).find(|p| {
                tenzro_vm::native::read_sla_verdict(
                    e.chain.state(),
                    &format!("did:tenzro:machine:econsim-{p}"),
                    0,
                )
                .is_some()
                    || e.provider_bonded(*p)
            });
            if let (true, Some(victim)) = (active, victim) {
                st.detail.insert("victim".into(), victim as f64);
                let rate = (rate_tnzo * TNZO as f64) as u128;
                for _ in 0..streams_per_hour {
                    if let Some(id) = open_stream(e, ADV_RENTER, victim, rate, 2) {
                        st.streams
                            .push((id, now + HOUR_MS, crate::chain::stream_expiry(now, 2)));
                    }
                }
            }
        }
        Adversary::GovernanceCapture {
            start_day,
            grant_tnzo,
            attackers,
            stake_share,
            ..
        } => {
            if d >= start_day as f64 && !st.started {
                st.started = true;
                st.start_balance = holdings(e, &[]);
                let bonds: Vec<u128> = e.chain.ledger.bonds_now().to_vec();
                let total: u128 = bonds.iter().sum();
                st.capture_ids = if stake_share > 0.0 {
                    let mut ids = Vec::new();
                    let mut held = 0u128;
                    for (v, b) in bonds.iter().enumerate().filter(|(_, b)| **b > 0) {
                        if held as f64 >= stake_share * total as f64 {
                            break;
                        }
                        ids.push(v as u32);
                        held += *b;
                    }
                    ids
                } else {
                    (0..attackers).collect()
                };
                let from = st.capture_ids.first().copied().unwrap_or(0);
                let amount = (grant_tnzo * TNZO as f64) as u128;
                let action = ledger::treasury_grant(ADV_RENTER, amount);
                st.proposed_action = action.clone();
                let _ = e.chain.submit(from, NATIVE_GAS, |nonce| SimTx::Propose {
                    from,
                    action,
                    nonce,
                });
                st.proposal_ms = now;
                st.detail.insert(
                    "treasury_at_proposal_tnzo".into(),
                    tnzo(e.chain.balance_of(n::derive_treasury_address().as_bytes())),
                );
                let mine: u128 = st
                    .capture_ids
                    .iter()
                    .map(|v| bonds.get(*v as usize).copied().unwrap_or(0))
                    .sum();
                st.detail.insert(
                    "attacker_stake_share".into(),
                    mine as f64 / total.max(1) as f64,
                );
                st.detail.insert("attacker_stake_tnzo".into(), tnzo(mine));
            }
            if let Some(id) = st.proposal.clone() {
                let from = st.capture_ids.first().copied().unwrap_or(0);
                let rules = tenzro_vm::governance::GovernanceRules::GENESIS;
                if st.proposal_stage == 1
                    && now >= st.proposal_ms + rules.voting_period_ms + rules.voting_period_ms / 10
                {
                    let _ = e.chain.submit(from, NATIVE_GAS, |nonce| SimTx::Execute {
                        from,
                        proposal: id.clone(),
                        nonce,
                    });
                    st.proposal_stage = 2;
                } else if st.proposal_stage == 3
                    && now >= st.proposal_ms + rules.voting_period_ms * 2 + rules.timelock_ms * 2
                {
                    let _ = e.chain.submit(from, NATIVE_GAS, |nonce| SimTx::Execute {
                        from,
                        proposal: id,
                        nonce,
                    });
                    st.proposal_stage = 4;
                }
            }
        }
        Adversary::GovernanceHoldout { .. } => {}
        Adversary::SalamiGrants {
            open_day,
            grants,
            grant_tnzo,
            enact_day,
            second_enact_day,
            ..
        } => {
            st.treasury_before = e.chain.balance_of(n::derive_treasury_address().as_bytes());
            if d >= open_day as f64 && !st.started {
                st.started = true;
                st.start_balance = holdings(e, &[]);
                let amount = (grant_tnzo * TNZO as f64) as u128;
                let action = ledger::treasury_grant(ADV_RENTER, amount);
                st.proposed_action = action.clone();
                st.proposal_ms = now;
                for _ in 0..grants {
                    let action = action.clone();
                    let _ = e.chain.submit(0, NATIVE_GAS, |nonce| SimTx::Propose {
                        from: 0,
                        action,
                        nonce,
                    });
                }
            }
            let rules = tenzro_vm::governance::GovernanceRules::GENESIS;
            if now >= st.proposal_ms + rules.voting_period_ms + rules.voting_period_ms / 10 {
                for g in st.grants.iter_mut().filter(|g| g.1 == 1) {
                    let id = g.0.clone();
                    let _ = e.chain.submit(0, NATIVE_GAS, |nonce| SimTx::Execute {
                        from: 0,
                        proposal: id,
                        nonce,
                    });
                    g.1 = 2;
                }
            }
            let half = (grants as usize).div_ceil(2);
            let batch = if d >= second_enact_day {
                Some(half..usize::MAX)
            } else if d >= enact_day {
                Some(0..half)
            } else {
                None
            };
            if let Some(r) = batch {
                for (k, g) in st.grants.iter_mut().enumerate() {
                    if g.1 == 3 && r.contains(&k) {
                        let id = g.0.clone();
                        let _ = e.chain.submit(0, NATIVE_GAS, |nonce| SimTx::Execute {
                            from: 0,
                            proposal: id,
                            nonce,
                        });
                        g.1 = 4;
                    }
                }
            }
        }
        Adversary::WashRing {
            start_day,
            ring,
            plans_per_hour,
            value_tnzo,
            report_work,
            ..
        } => {
            if d >= start_day as f64 && !st.started {
                st.started = true;
                st.start_balance = ring_value(e, &st, ring);
            }
            // Payees report the plans committed in the last block.
            let mut by_payee: BTreeMap<u32, Vec<[u8; 32]>> = BTreeMap::new();
            for (payee, plan) in st.pending_reports.drain(..) {
                by_payee
                    .entry(payee)
                    .or_default()
                    .push(tenzro_types::settlement::leg_id(&plan, 0));
            }
            if report_work {
                for (payee, legs) in by_payee {
                    let _ = e.chain.call(
                        payee,
                        None,
                        0,
                        n::SELECTOR_FUNDING,
                        &crate::settlement_rewards::report(&legs),
                        NATIVE_GAS,
                        None,
                    );
                }
            }
            if st.active(d) {
                // Plans are decided against calendar time: one block's worth
                // past the next block, so each commits in the block carrying it.
                let deadline = (now.max(0) as u64) + 2 * e.chain.clock.block_calendar_ms() as u64;
                let amount = (value_tnzo * TNZO as f64) as u128;
                for i in 0..ring {
                    for _ in 0..plans_per_hour {
                        st.plan_nonce += 1;
                        let to = RING0 + (i + 1) % ring;
                        let body = crate::settlement_rewards::open_plan(
                            st.plan_nonce,
                            to,
                            None,
                            amount,
                            deadline,
                        );
                        let _ = e.chain.call(
                            RING0 + i,
                            None,
                            0,
                            n::SELECTOR_SETTLEMENT_PLAN,
                            &body,
                            NATIVE_GAS,
                            None,
                        );
                    }
                }
            }
            // Once a day each member notes its new coupons and claims them;
            // once a week it releases what has vested.
            if st.started && (now / HOUR_MS) % 24 == 1 {
                let claim = serde_json::json!({ "op": "claim_rewards" }).to_string();
                let release = serde_json::json!({ "op": "release_vesting" }).to_string();
                for id in RING0..RING0 + ring {
                    let addr = Address::new(ledger::account(id));
                    for c in n::rewards::read_coupons(e.chain.state(), &addr).unwrap_or_default() {
                        st.coupons
                            .insert((id, c.epoch, format!("{:?}", c.bucket)), c.amount);
                    }
                    let _ = e.chain.call(
                        id,
                        None,
                        0,
                        n::SELECTOR_FUNDING,
                        claim.as_bytes(),
                        NATIVE_GAS,
                        None,
                    );
                    if (now / DAY_MS) % 7 == 0 {
                        let _ = e.chain.call(
                            id,
                            None,
                            0,
                            n::SELECTOR_FUNDING,
                            release.as_bytes(),
                            NATIVE_GAS,
                            None,
                        );
                    }
                }
            }
        }
        Adversary::OracleSkew {
            start_day, cartel, ..
        }
        | Adversary::PlaybookTrigger {
            start_day, cartel, ..
        } => {
            if d >= start_day as f64 && !st.started {
                st.started = true;
                let bonds = e.chain.ledger.bonds_now();
                let total: u128 = bonds.iter().sum();
                let mine: u128 = bonds.iter().take(cartel as usize).sum();
                st.detail.insert(
                    "cartel_stake_share".into(),
                    mine as f64 / total.max(1) as f64,
                );
            }
            if st.active(d) && e.chain.param("fees.usd_rate_frozen") == 1 {
                *st.detail.entry("hours_rate_held".into()).or_default() += 1.0;
            }
        }
        Adversary::ProviderCollusion {
            start_day,
            providers,
            cartel,
            ..
        } => {
            if d >= start_day as f64 && !st.started {
                st.started = true;
                st.cartel_dids = e
                    .provider_books()
                    .into_iter()
                    .take(providers as usize)
                    .map(|(_, did, _, _)| did)
                    .collect();
                let books = e.provider_books();
                st.detail.insert(
                    "providers_live_at_start".into(),
                    books.iter().filter(|b| b.2).count() as f64,
                );
                let bonds = e.chain.ledger.bonds_now();
                let total: u128 = bonds.iter().sum();
                let mine: u128 = bonds.iter().take(cartel as usize).sum();
                st.detail.insert(
                    "cartel_stake_share".into(),
                    mine as f64 / total.max(1) as f64,
                );
            }
        }
        Adversary::RateWalk { start_day, .. } => {
            if d >= start_day as f64 && !st.started {
                st.started = true;
                st.start_balance = holdings(e, &[]);
                let bonds = e.chain.ledger.bonds_now();
                let total: u128 = bonds.iter().sum();
                let cartel = match st.spec {
                    Adversary::RateWalk { cartel, .. } => cartel,
                    _ => 0,
                };
                let mine: u128 = bonds.iter().take(cartel as usize).sum();
                st.detail.insert(
                    "cartel_stake_share".into(),
                    mine as f64 / total.max(1) as f64,
                );
            }
        }
    }
    e.adv = Some(st);
}

/// The rate the walking coalition reports this epoch, nano-USD, or that it
/// withholds: `(coalition size, rate, withholds)` while the strategy runs.
pub fn rate_walk(e: &Economy) -> Option<(u32, u128, bool)> {
    let st = e.adv.as_ref()?;
    let Adversary::RateWalk {
        start_day,
        run_days,
        cartel,
        step_bps,
        withhold,
    } = st.spec
    else {
        return None;
    };
    let d = day(e);
    if d < start_day as f64 || d >= (start_day + run_days) as f64 {
        return None;
    }
    let now = n::read_fee_rate(e.chain.state()).rate_nano_usd;
    let rate = (now * u128::from(10_000u32.saturating_sub(step_bps)) / 10_000).max(1);
    Some((cartel, rate, withhold))
}

/// The validators skewing their rate report and the factor they report
/// the market rate at: `(cartel size, factor)` while a skew runs.
pub fn rate_skew(e: &Economy) -> Option<(u32, f64)> {
    let st = e.adv.as_ref()?;
    if !st.active(day(e)) {
        return None;
    }
    match st.spec {
        Adversary::OracleSkew {
            cartel, skew_bps, ..
        } => Some((cartel, 1.0 + skew_bps as f64 / 10_000.0)),
        Adversary::PlaybookTrigger {
            cartel,
            skew_bps,
            keep_skew,
            ..
        } if keep_skew || e.chain.param("fees.usd_rate_frozen") != 1 => {
            Some((cartel, 1.0 + skew_bps as f64 / 10_000.0))
        }
        _ => None,
    }
}

/// Price provider `i` charges over the market price under collusion.
pub fn collusion_markup(e: &Economy, i: usize) -> f64 {
    match e.adv.as_ref() {
        Some(st) if st.active(day(e)) => match st.spec {
            Adversary::ProviderCollusion {
                providers, markup, ..
            } if (i as u32) < providers => markup,
            _ => 1.0,
        },
        _ => 1.0,
    }
}

/// How strongly buyers route by price while the provider collusion
/// strategy is in the run (in its baseline too); `None` otherwise, and
/// buyers pick providers uniformly.
pub fn routing_elasticity(e: &Economy) -> Option<f64> {
    match e.adv.as_ref().map(|a| &a.spec) {
        Some(Adversary::ProviderCollusion { .. }) => Some(e.cfg.assumptions.buyer_price_elasticity),
        _ => None,
    }
}

fn open_stream(
    e: &mut Economy,
    payer: u32,
    payee: u32,
    rate: u128,
    hours: i64,
) -> Option<[u8; 32]> {
    let now = e.chain.now_ms();
    let payload = crate::chain::stream_escrow_payload(payee, rate, hours, now);
    if !e.chain.call(
        payer,
        None,
        0,
        n::SELECTOR_ESCROW_CREATE,
        &payload,
        NATIVE_GAS,
        None,
    ) {
        return None;
    }
    let nonce = e.chain.last_nonce(payer);
    Some(n::derive_escrow_id(
        &Address::new(ledger::account(payer)),
        nonce,
    ))
}

fn collect_streams_and_claims(
    e: &mut Economy,
    st: &mut AdversaryState,
    provider: u32,
    _renter: u32,
) {
    let now = e.chain.now_ms();
    for (id, created, expires) in st.streams.clone() {
        if now - created >= HOUR_MS && now + HOUR_MS <= expires {
            let payload = serde_json::json!({ "escrow_id": id });
            let _ = e.chain.call(
                provider,
                None,
                0,
                n::SELECTOR_ESCROW_STREAM_CLAIM,
                payload.to_string().as_bytes(),
                NATIVE_GAS,
                None,
            );
        }
    }
    st.streams.retain(|(_, _, exp)| *exp + 2 * HOUR_MS > now);
}

/// Extra SLA outcomes the adversary's own providers produce this hour, and
/// what an honest validator attests about them.
pub fn adversary_outcomes(e: &Economy) -> Vec<(String, bool)> {
    match e.adv.as_ref().map(|a| &a.spec) {
        Some(Adversary::SelfDealingSla { .. })
            if e.adv.as_ref().is_some_and(|a| a.bond_posted > 0) =>
        {
            vec![(adv_did(), false)]
        }
        _ => Vec::new(),
    }
}

/// What validator-side behaviour reports for provider `id` whose true
/// availability was `up`. Honest validators report the truth.
pub fn attested_availability(e: &Economy, _id: u32, up: bool) -> bool {
    let _ = e;
    up
}

/// Availability validator `v` attests for provider `did` with truth `up`.
pub fn attest_for(e: &Economy, v: u32, did: &str, up: bool) -> bool {
    if let Some(st) = e.adv.as_ref()
        && let Adversary::CartelFalseDown {
            cartel,
            start_day,
            run_days,
            ..
        } = st.spec
        && v < cartel
        && st
            .detail
            .get("victim")
            .is_some_and(|x| format!("did:tenzro:machine:econsim-{}", *x as u32) == did)
    {
        let d = day(e);
        if d >= start_day as f64 && d < (start_day + run_days) as f64 {
            return false;
        }
    }
    if let Some(st) = e.adv.as_ref()
        && let Adversary::ProviderCollusion { cartel, .. } = st.spec
        && v < cartel
        && st.active(day(e))
        && !st.cartel_dids.iter().any(|c| c == did)
    {
        return false;
    }
    up
}

/// Whether validator `v` skips attesting this hour.
pub fn validator_withholds_attestation(e: &mut Economy, v: u32) -> bool {
    if let Some(st) = e.adv.as_ref()
        && let Adversary::CartelFalseDown {
            cartel,
            honest_attest,
            ..
        } = st.spec
        && v >= cartel
    {
        return rand::Rng::gen_range(&mut e.rng, 0.0..1.0) >= honest_attest;
    }
    // Every validator draws, so the baseline and the collusion run use the
    // random source alike.
    if let Some(st) = e.adv.as_ref()
        && let Adversary::ProviderCollusion {
            cartel,
            honest_attest,
            ..
        } = st.spec
    {
        let active = st.active(day(e));
        let draw = rand::Rng::gen_range(&mut e.rng, 0.0..1.0);
        return active && v >= cartel && draw >= honest_attest;
    }
    false
}

/// Whether validator `v` votes on routine proposals.
pub fn validator_votes(e: &Economy, v: u32) -> bool {
    match e.adv.as_ref().map(|a| &a.spec) {
        Some(Adversary::GovernanceHoldout { abstain_share }) => {
            let total = e.cfg.assumptions.validators as f64;
            (v as f64) >= (abstain_share * total).ceil()
        }
        _ => true,
    }
}

/// Sees every result, before the honest bookkeeping.
pub fn on_result(e: &mut Economy, r: &TxResult) {
    let Some(mut st) = e.adv.take() else { return };
    let spec = st.spec.clone();
    // A wash plan committed: its payee reports it in the next block.
    if let (Adversary::WashRing { ring, .. }, SimTx::Call { from, data, .. }) = (&spec, &r.tx)
        && r.applied
        && (RING0..RING0 + ring).contains(from)
        && data.starts_with(&n::SELECTOR_SETTLEMENT_PLAN)
    {
        let out: serde_json::Value = serde_json::from_slice(&r.output).unwrap_or_default();
        if let Some(id) = out["plan_id"]
            .as_str()
            .and_then(|s| hex::decode(s).ok())
            .and_then(|b| <[u8; 32]>::try_from(b).ok())
        {
            let payee = RING0 + (from - RING0 + 1) % ring;
            st.pending_reports.push((payee, id));
        }
    }
    match (&spec, &r.tx) {
        (Adversary::GovernanceCapture { honest_turnout, .. }, SimTx::Propose { action, .. })
            if r.applied && st.proposal.is_none() && *action == st.proposed_action =>
        {
            let id = r.output.clone();
            st.proposal = Some(id.clone());
            st.proposal_stage = 1;
            let bonded: Vec<u32> = e
                .chain
                .ledger
                .bonds_now()
                .iter()
                .enumerate()
                .filter(|(_, b)| **b > 0)
                .map(|(i, _)| i as u32)
                .collect();
            let turnout = *honest_turnout;
            for v in bonded {
                if st.capture_ids.contains(&v) {
                    let id = id.clone();
                    let _ = e.chain.submit(v, NATIVE_GAS, |nonce| SimTx::Vote {
                        from: v,
                        proposal: id,
                        nonce,
                    });
                } else if rand::Rng::gen_range(&mut e.rng, 0.0..1.0) < turnout {
                    let mut payload = id.clone();
                    payload.push(0);
                    let me = ledger::account(v);
                    payload.push(me.len() as u8);
                    payload.extend_from_slice(&me);
                    let _ = e.chain.call(
                        v,
                        None,
                        0,
                        n::SELECTOR_GOVERNANCE_VOTE,
                        &payload,
                        NATIVE_GAS,
                        None,
                    );
                }
            }
        }
        (Adversary::SalamiGrants { attackers, .. }, SimTx::Propose { action, .. })
            if r.applied && *action == st.proposed_action =>
        {
            let id = r.output.clone();
            st.grants.push((id.clone(), 1));
            for v in 0..*attackers {
                let id = id.clone();
                let _ = e.chain.submit(v, NATIVE_GAS, |nonce| SimTx::Vote {
                    from: v,
                    proposal: id,
                    nonce,
                });
            }
        }
        (Adversary::SalamiGrants { grant_tnzo, .. }, SimTx::Execute { proposal, .. }) => {
            let amount = (grant_tnzo * TNZO as f64) as u128;
            let now = e.chain.now_ms();
            let before = st.treasury_before;
            if let Some(g) = st.grants.iter_mut().find(|g| &g.0 == proposal) {
                match (g.1, r.applied) {
                    (2, true) => g.1 = 3,
                    (2, false) => {
                        g.1 = 6;
                        *st.detail.entry("close refused".into()).or_default() += 1.0;
                    }
                    (4, true) => {
                        g.1 = 5;
                        st.payments.push((now, amount, before));
                    }
                    (4, false) => {
                        g.1 = 6;
                        *st.detail
                            .entry(format!(
                                "enact refused: {}",
                                crate::economy::strip_ids(&r.error)
                                    .chars()
                                    .take(100)
                                    .collect::<String>()
                            ))
                            .or_default() += 1.0;
                    }
                    _ => {}
                }
            }
        }
        (Adversary::GovernanceCapture { .. }, SimTx::Execute { proposal, .. })
            if st.proposal.as_ref() == Some(proposal) =>
        {
            if st.proposal_stage == 2 {
                st.proposal_stage = if r.applied { 3 } else { 5 };
                st.detail
                    .insert("closed_ok".into(), if r.applied { 1.0 } else { 0.0 });
                if !r.applied {
                    st.detail.insert(
                        format!(
                            "close refused: {}",
                            r.error.chars().take(160).collect::<String>()
                        ),
                        1.0,
                    );
                }
            } else if st.proposal_stage == 4 {
                st.detail
                    .insert("enacted".into(), if r.applied { 1.0 } else { 0.0 });
                st.proposal_stage = 5;
            }
        }
        (
            _,
            SimTx::Call {
                from, data, nonce, ..
            },
        ) if data.len() >= 4 && accounts().contains(from) => {
            if !r.applied && data.starts_with(&n::SELECTOR_ESCROW_CREATE) {
                let id = n::derive_escrow_id(&Address::new(ledger::account(*from)), *nonce);
                st.streams.retain(|s| s.0 != id);
            }
            let sel: [u8; 4] = data[..4].try_into().expect("selector");
            let key = format!(
                "{} {}",
                crate::economy::selector_name(sel),
                if r.applied { "applied" } else { "refused" }
            );
            *st.detail.entry(key).or_default() += 1.0;
            if !r.applied {
                *st.detail
                    .entry(format!(
                        "refusal: {}",
                        crate::economy::strip_ids(&r.error)
                            .chars()
                            .take(120)
                            .collect::<String>()
                    ))
                    .or_default() += 1.0;
            }
            if r.applied && sel == n::SELECTOR_PAY_INSURANCE_CLAIM {
                st.insurance_received += 1;
            }
        }
        _ => {}
    }
    e.adv = Some(st);
}

/// Closes the books at the end of a run.
pub fn finish(e: &mut Economy) {
    let Some(st) = e.adv.take() else { return };
    let price = e.price;
    let mut out = AttackOutcome {
        name: st.spec.name().into(),
        params: serde_json::to_value(&st.spec).unwrap_or_default(),
        detail: st.detail.clone(),
        ..AttackOutcome::default()
    };
    match &st.spec {
        Adversary::SelfDealingSla { .. } => {
            // The bond still held counts as the adversary's: what was posted
            // less every penalty its unavailable verdicts took.
            let penalty = e.chain.param("sla.unavailable.penalty_gwei") as u128 * 1_000_000_000;
            let mut taken: u128 = 0;
            let first =
                (st.streams.first().map(|s| s.1).unwrap_or(0).max(0) / n::MARKET_EPOCH_MS) as u64;
            let last = (e.chain.now_ms().max(0) / n::MARKET_EPOCH_MS) as u64;
            if st.bond_posted > 0 {
                for ep in first.saturating_sub(48)..=last {
                    if let Some(v) = n::read_sla_verdict(e.chain.state(), &adv_did(), ep)
                        && !v.available
                    {
                        taken = (taken + penalty).min(st.bond_posted);
                    }
                }
            }
            let held = holdings(e, &[]) + st.bond_posted - taken;
            let profit = held as f64 / TNZO as f64 - st.start_balance as f64 / TNZO as f64;
            out.profit_tnzo = profit;
            out.detail
                .insert("bond_posted_tnzo".into(), tnzo(st.bond_posted));
            out.detail.insert("penalties_tnzo".into(), tnzo(taken));
            out.detail
                .insert("claims_paid".into(), st.insurance_received as f64);
            out.pool_drained_tnzo = (st.pool_at_start - pool(e)).max(0.0);
            out.detail
                .insert("pool_at_start_tnzo".into(), st.pool_at_start);
            out.detail.insert("pool_at_end_tnzo".into(), pool(e));
            let _ = st.penalties;
        }
        Adversary::CartelFalseDown { .. } => {
            let held = holdings(e, &[]);
            out.profit_tnzo = held as f64 / TNZO as f64 - st.start_balance as f64 / TNZO as f64;
            out.pool_drained_tnzo = (st.pool_at_start - pool(e)).max(0.0);
            out.detail
                .insert("claims_paid".into(), st.insurance_received as f64);
        }
        // An attempt that never reached its start day gained nothing.
        Adversary::GovernanceCapture { .. } => {
            if st.started {
                let held = holdings(e, &[]);
                out.profit_tnzo = held as f64 / TNZO as f64 - st.start_balance as f64 / TNZO as f64;
            }
        }
        Adversary::SalamiGrants { .. } => {
            // The treasury's own rule, replayed over what was paid: a period
            // opens at the first payment after the last one ended, with the
            // treasury balance then, and may pay that balance times the cap.
            let length = e.chain.param("treasury.outflow_period_ms") as i64;
            let bps = e.chain.param("treasury.max_period_outflow_bps") as u128;
            let mut pays = st.payments.clone();
            pays.sort_by_key(|p| p.0);
            let (mut start, mut cap, mut paid) = (i64::MIN, 0u128, 0u128);
            let mut worst: f64 = 0.0;
            let mut periods = 0.0;
            for (at, amount, before) in pays {
                if start == i64::MIN || at >= start.saturating_add(length) {
                    start = at;
                    cap = before / 10_000 * bps;
                    paid = 0;
                    periods += 1.0;
                }
                paid += amount;
                worst = worst.max(paid as f64 / cap.max(1) as f64);
            }
            out.detail.insert("periods".into(), periods);
            out.detail
                .insert("worst_period_paid_over_cap".into(), worst);
            out.detail
                .insert("grants_paid".into(), st.payments.len() as f64);
            out.detail.insert(
                "grants_closed".into(),
                st.grants.iter().filter(|g| g.1 >= 3 && g.1 != 6).count() as f64,
            );
            let held = holdings(e, &[]);
            out.profit_tnzo = held as f64 / TNZO as f64 - st.start_balance as f64 / TNZO as f64;
        }
        Adversary::RateWalk { start_day, .. } => {
            // How far the rate in force stood from the market while the
            // coalition ran, against the share of stake it held.
            let mut worst: f64 = 0.0;
            for dd in e
                .out
                .days
                .iter()
                .filter(|x| x.snap.day >= *start_day as f64)
            {
                if dd.fair_price_usd > 0.0 && dd.chain_rate_usd > 0.0 {
                    worst = worst.max((dd.chain_rate_usd / dd.fair_price_usd - 1.0).abs());
                }
            }
            out.detail.insert("rate_max_deviation".into(), worst);
            let held = holdings(e, &[]);
            out.profit_tnzo = held as f64 / TNZO as f64 - st.start_balance as f64 / TNZO as f64;
        }
        Adversary::GovernanceHoldout { .. } => {
            out.detail
                .insert("routine_enacted".into(), e.enacted as f64);
            out.detail.insert("routine_failed".into(), e.failed as f64);
        }
        Adversary::WashRing {
            ring, value_tnzo, ..
        } => {
            let end = ring_value(e, &st, *ring);
            out.profit_tnzo = end as f64 / TNZO as f64 - st.start_balance as f64 / TNZO as f64;
            let rewards: u128 = st.coupons.values().sum();
            out.detail
                .insert("rewards_issued_tnzo".into(), tnzo(rewards));
            for bucket in ["Ecosystem", "Provider"] {
                let b: u128 = st
                    .coupons
                    .iter()
                    .filter(|(k, _)| k.2 == bucket)
                    .map(|(_, v)| *v)
                    .sum();
                out.detail
                    .insert(format!("rewards_{}_tnzo", bucket.to_lowercase()), tnzo(b));
            }
            let plans = st
                .detail
                .get("settlement plan applied")
                .copied()
                .unwrap_or(0.0);
            out.detail.insert("settled_tnzo".into(), plans * value_tnzo);
            out.detail.insert(
                "settlement_fee_bps".into(),
                e.chain.param("fees.settlement_fee_bps") as f64,
            );
            out.detail.insert(
                "activity_reward_fee_bps".into(),
                e.chain.param("fees.activity_reward_fee_bps") as f64,
            );
            // Fees and gas are what the ring paid beyond the rewards.
            out.detail
                .insert("fees_and_gas_tnzo".into(), tnzo(rewards) - out.profit_tnzo);
        }
        Adversary::OracleSkew { .. }
        | Adversary::PlaybookTrigger { .. }
        | Adversary::ProviderCollusion { .. } => {
            // Each account's holdings, for the comparison with the baseline
            // run ([`pair`]).
            let validators = e.cfg.assumptions.validators + e.cfg.assumptions.standby;
            for v in 0..validators {
                out.detail.insert(format!("val:{v}"), validator_value(e, v));
            }
            if matches!(st.spec, Adversary::ProviderCollusion { .. }) {
                for (i, b) in e.provider_books().iter().enumerate() {
                    out.detail.insert(format!("prov:{i}"), b.3);
                }
            }
            if let Some((start_day, _)) = st.spec.window() {
                let mut worst: f64 = 0.0;
                let mut held = 0.0;
                for dd in e.out.days.iter().filter(|x| x.snap.day >= start_day as f64) {
                    if dd.fair_price_usd > 0.0 && dd.chain_rate_usd > 0.0 {
                        worst = worst.max((dd.chain_rate_usd / dd.fair_price_usd - 1.0).abs());
                    }
                    if dd.rate_frozen {
                        held += 1.0;
                    }
                }
                out.detail.insert("rate_max_deviation".into(), worst);
                out.detail.insert("days_rate_held".into(), held);
            }
            out.detail.insert("final_price_usd".into(), price);
        }
    }
    // Profit is what the adversary's own accounts gained; validators'
    // ordinary rewards are not counted. A strategy counts as profitable
    // above one TNZO of net gain.
    out.profit_usd = out.profit_tnzo * price;
    out.succeeded = match &st.spec {
        Adversary::GovernanceHoldout { .. } => e.enacted == 0 && e.failed > 0,
        // A coalition below half the stake moved the rate in force more
        // than 5% away from the market.
        // A period paid out more than its cap (a thousandth of slack for
        // fees credited to the treasury in the same block).
        Adversary::SalamiGrants { .. } => {
            out.detail
                .get("worst_period_paid_over_cap")
                .copied()
                .unwrap_or(0.0)
                > 1.001
        }
        Adversary::RateWalk { .. } => {
            out.detail.get("cartel_stake_share").copied().unwrap_or(1.0) < 0.5
                && out.detail.get("rate_max_deviation").copied().unwrap_or(0.0) > 0.05
        }
        // Judged once compared with the baseline run.
        s if s.paired() => false,
        _ => out.profit_tnzo > 1.0,
    };
    e.out.adversary = Some(out);
}

/// Measures a paired strategy's gain against its baseline run (the same
/// seed and configuration with nobody deviating): what the cartel's
/// validators hold more, in TNZO, plus what the colluding providers earned
/// more, in USD at the final price. Profitable above one TNZO. The
/// per-account figures are dropped afterwards.
pub fn pair(out: &mut AttackOutcome, base: &AttackOutcome) {
    let Ok(spec) = serde_json::from_value::<Adversary>(out.params.clone()) else {
        return;
    };
    let (cartel, providers) = match spec {
        Adversary::OracleSkew { cartel, .. } | Adversary::PlaybookTrigger { cartel, .. } => {
            (cartel, 0)
        }
        Adversary::ProviderCollusion {
            cartel, providers, ..
        } => (cartel, providers),
        _ => return,
    };
    let get = |o: &AttackOutcome, k: String| o.detail.get(&k).copied().unwrap_or(0.0);
    let validators: f64 = (0..cartel)
        .map(|v| get(out, format!("val:{v}")) - get(base, format!("val:{v}")))
        .sum();
    let providers_usd: f64 = (0..providers)
        .map(|i| get(out, format!("prov:{i}")) - get(base, format!("prov:{i}")))
        .sum();
    let price = get(out, "final_price_usd".into()).max(1e-12);
    out.profit_tnzo = validators + providers_usd / price;
    out.profit_usd = out.profit_tnzo * price;
    out.succeeded = out.profit_tnzo > 1.0;
    out.detail
        .insert("cartel_validators_gain_tnzo".into(), validators);
    out.detail
        .insert("colluding_providers_gain_usd".into(), providers_usd);
    out.detail.insert(
        "baseline_final_price_usd".into(),
        get(base, "final_price_usd".into()),
    );
    out.detail
        .retain(|k, _| !k.starts_with("val:") && !k.starts_with("prov:"));
}

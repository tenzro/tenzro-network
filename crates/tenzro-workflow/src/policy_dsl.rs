//! Composite policy DSL evaluated above the flat `DelegationScope`.
//!
//! `DelegationScope` is a structural ceiling (max value, allowed ops). The DSL
//! lets a controller express richer predicates: amount-tier × counterparty ×
//! time-window × asset-class × risk-tier, with `RequiresApprovalFrom(...)`
//! escalation available as a verdict in its own right.
//!
//! The evaluator is **pure**: no async, no I/O beyond the `IdentityLookup`
//! trait. Same context → same verdict, every time. This is what makes it safe
//! to embed in transaction-validation paths.

use serde::{Deserialize, Serialize};

/// A composite policy expression.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum PolicyExpr {
    // -- Boolean combinators --
    And(Vec<PolicyExpr>),
    Or(Vec<PolicyExpr>),
    Not(Box<PolicyExpr>),

    // -- Constants --
    Allow,
    Deny,

    // -- Amount predicates (wei) --
    AmountLte(u128),
    AmountGte(u128),
    DailyAmountLte(u128),

    // -- Counterparty --
    CounterpartyIn(Vec<String>),
    CounterpartyDomain(String),
    CounterpartyKycTierGte(u8),
    CounterpartyBondGte(u128),

    // -- Time --
    TimeWindow {
        start_hour: u8,
        end_hour: u8,
        tz_offset_minutes: i16,
    },
    DayOfWeekIn(Vec<u8>),
    BeforeBlock(u64),
    AfterBlock(u64),

    // -- Risk / classification --
    RiskTierLte(u8),
    AssetIn(Vec<String>),
    ChainIn(Vec<String>),
    PaymentProtocolIn(Vec<String>),

    // -- Workflow-scoped --
    InWorkflowStatus(Vec<String>),
    ParticipantHasRole(String),

    // -- Escalation --
    RequiresApprovalFrom(String),
    RequiresApprovalThreshold {
        dids: Vec<String>,
        m: u8,
        n: u8,
    },
}

/// Read-only lookup callback for counterparty KYC tier and bond.
///
/// The evaluator never calls into RocksDB or the network directly; the host
/// supplies a snapshot lookup so evaluation stays pure.
pub trait IdentityLookup {
    fn kyc_tier(&self, did: &str) -> Option<u8>;
    fn bond_wei(&self, did: &str) -> Option<u128>;
    fn risk_tier(&self, did: &str) -> Option<u8>;
}

/// A no-op lookup for tests / contexts where counterparty data is not needed.
pub struct NullLookup;
impl IdentityLookup for NullLookup {
    fn kyc_tier(&self, _did: &str) -> Option<u8> { None }
    fn bond_wei(&self, _did: &str) -> Option<u128> { None }
    fn risk_tier(&self, _did: &str) -> Option<u8> { None }
}

/// Inputs to policy evaluation.
pub struct PolicyContext<'a> {
    pub amount_wei: u128,
    pub counterparty_did: Option<&'a str>,
    pub asset: &'a str,
    pub chain: &'a str,
    pub payment_protocol: &'a str,
    pub current_block: u64,
    /// Unix seconds.
    pub current_ts: i64,
    pub workflow_status: Option<&'a str>,
    pub workflow_roles_held_by_actor: &'a [String],
    pub identity_lookup: &'a dyn IdentityLookup,
    pub daily_spent_wei: u128,
}

/// Verdict returned by the evaluator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyVerdict {
    Allow,
    Deny { reason: String },
    RequireApproval {
        approvers: ApproverSpec,
        reason: String,
    },
}

/// Resolved approver specification surfaced by `RequiresApproval*` clauses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ApproverSpec {
    Single(String),
    Threshold { dids: Vec<String>, m: u8, n: u8 },
}

/// Evaluates a `PolicyExpr` against a `PolicyContext` and returns a verdict.
///
/// Semantics:
/// - `Allow` short-circuits to `Allow`.
/// - `Deny` short-circuits to `Deny`.
/// - `And([..])` returns the strictest verdict found: any `Deny` wins; else
///   any `RequireApproval` wins; else `Allow`.
/// - `Or([..])` returns the most permissive verdict: any `Allow` wins; else
///   any `RequireApproval` wins; else `Deny`.
/// - `Not(p)` flips Allow ↔ Deny; `RequireApproval` becomes `Deny` (you can't
///   negate "needs approval" coherently).
/// - Atomic predicates evaluate to `Allow` if satisfied, `Deny` otherwise.
/// - `RequiresApprovalFrom` / `RequiresApprovalThreshold` always return
///   `RequireApproval`.
pub fn evaluate(expr: &PolicyExpr, ctx: &PolicyContext) -> PolicyVerdict {
    use PolicyExpr::*;
    match expr {
        Allow => PolicyVerdict::Allow,
        Deny => PolicyVerdict::Deny { reason: "explicit Deny".into() },

        And(parts) => {
            let mut accumulated = PolicyVerdict::Allow;
            for p in parts {
                match evaluate(p, ctx) {
                    PolicyVerdict::Deny { reason } => {
                        return PolicyVerdict::Deny { reason };
                    }
                    PolicyVerdict::RequireApproval { approvers, reason } => {
                        accumulated = PolicyVerdict::RequireApproval { approvers, reason };
                    }
                    PolicyVerdict::Allow => {}
                }
            }
            accumulated
        }

        Or(parts) => {
            let mut last_deny: Option<String> = None;
            let mut pending_approval: Option<(ApproverSpec, String)> = None;
            for p in parts {
                match evaluate(p, ctx) {
                    PolicyVerdict::Allow => return PolicyVerdict::Allow,
                    PolicyVerdict::RequireApproval { approvers, reason } => {
                        pending_approval = Some((approvers, reason));
                    }
                    PolicyVerdict::Deny { reason } => {
                        last_deny = Some(reason);
                    }
                }
            }
            if let Some((approvers, reason)) = pending_approval {
                PolicyVerdict::RequireApproval { approvers, reason }
            } else {
                PolicyVerdict::Deny {
                    reason: last_deny.unwrap_or_else(|| "Or had no allow path".into()),
                }
            }
        }

        Not(inner) => match evaluate(inner, ctx) {
            PolicyVerdict::Allow => PolicyVerdict::Deny { reason: "Not(Allow)".into() },
            PolicyVerdict::Deny { .. } => PolicyVerdict::Allow,
            PolicyVerdict::RequireApproval { .. } => PolicyVerdict::Deny {
                reason: "Not(RequireApproval) collapses to Deny".into(),
            },
        },

        AmountLte(cap) => bool_to_verdict(ctx.amount_wei <= *cap, || {
            format!("amount {} > cap {}", ctx.amount_wei, cap)
        }),
        AmountGte(floor) => bool_to_verdict(ctx.amount_wei >= *floor, || {
            format!("amount {} < floor {}", ctx.amount_wei, floor)
        }),
        DailyAmountLte(cap) => {
            let projected = ctx.daily_spent_wei.saturating_add(ctx.amount_wei);
            bool_to_verdict(projected <= *cap, || {
                format!("projected daily spend {} > cap {}", projected, cap)
            })
        }

        CounterpartyIn(allowed) => {
            let cp = match ctx.counterparty_did {
                Some(c) => c,
                None => return PolicyVerdict::Deny { reason: "no counterparty".into() },
            };
            bool_to_verdict(allowed.iter().any(|a| a == cp), || {
                format!("counterparty {} not in allowlist", cp)
            })
        }
        CounterpartyDomain(domain) => {
            let cp = match ctx.counterparty_did {
                Some(c) => c,
                None => return PolicyVerdict::Deny { reason: "no counterparty".into() },
            };
            bool_to_verdict(cp.ends_with(domain.as_str()), || {
                format!("counterparty {} not in domain {}", cp, domain)
            })
        }
        CounterpartyKycTierGte(min) => {
            let cp = match ctx.counterparty_did {
                Some(c) => c,
                None => return PolicyVerdict::Deny { reason: "no counterparty".into() },
            };
            match ctx.identity_lookup.kyc_tier(cp) {
                Some(tier) => bool_to_verdict(tier >= *min, || {
                    format!("counterparty kyc tier {} < min {}", tier, min)
                }),
                None => PolicyVerdict::Deny { reason: format!("kyc tier unknown for {}", cp) },
            }
        }
        CounterpartyBondGte(min_wei) => {
            let cp = match ctx.counterparty_did {
                Some(c) => c,
                None => return PolicyVerdict::Deny { reason: "no counterparty".into() },
            };
            match ctx.identity_lookup.bond_wei(cp) {
                Some(b) => bool_to_verdict(b >= *min_wei, || {
                    format!("counterparty bond {} < min {}", b, min_wei)
                }),
                None => PolicyVerdict::Deny { reason: format!("bond unknown for {}", cp) },
            }
        }

        TimeWindow { start_hour, end_hour, tz_offset_minutes } => {
            let local_seconds = ctx.current_ts + (*tz_offset_minutes as i64) * 60;
            // Unix epoch / 86400 = days since epoch (Thu 1970-01-01).
            // Hour-of-day = (local_seconds mod 86400) / 3600.
            let hour = ((local_seconds.rem_euclid(86_400)) / 3_600) as u8;
            let in_window = if start_hour <= end_hour {
                hour >= *start_hour && hour < *end_hour
            } else {
                // Wrap window (e.g. 22-06).
                hour >= *start_hour || hour < *end_hour
            };
            bool_to_verdict(in_window, || {
                format!("hour {} outside window {}..{}", hour, start_hour, end_hour)
            })
        }
        DayOfWeekIn(days) => {
            // 1970-01-01 was a Thursday (=3 with Mon=0).
            let day_of_week = (((ctx.current_ts / 86_400) + 3).rem_euclid(7)) as u8;
            bool_to_verdict(days.contains(&day_of_week), || {
                format!("day of week {} not in allowlist", day_of_week)
            })
        }
        BeforeBlock(b) => bool_to_verdict(ctx.current_block < *b, || {
            format!("block {} >= deadline {}", ctx.current_block, b)
        }),
        AfterBlock(b) => bool_to_verdict(ctx.current_block > *b, || {
            format!("block {} <= floor {}", ctx.current_block, b)
        }),

        RiskTierLte(max) => {
            let cp = match ctx.counterparty_did {
                Some(c) => c,
                None => return PolicyVerdict::Allow, // no counterparty = no risk
            };
            match ctx.identity_lookup.risk_tier(cp) {
                Some(t) => bool_to_verdict(t <= *max, || {
                    format!("risk tier {} > max {}", t, max)
                }),
                None => PolicyVerdict::Deny { reason: format!("risk unknown for {}", cp) },
            }
        }
        AssetIn(allowed) => bool_to_verdict(allowed.iter().any(|a| a == ctx.asset), || {
            format!("asset {} not in allowlist", ctx.asset)
        }),
        ChainIn(allowed) => bool_to_verdict(allowed.iter().any(|a| a == ctx.chain), || {
            format!("chain {} not in allowlist", ctx.chain)
        }),
        PaymentProtocolIn(allowed) => bool_to_verdict(
            allowed.iter().any(|a| a == ctx.payment_protocol),
            || format!("payment protocol {} not in allowlist", ctx.payment_protocol),
        ),

        InWorkflowStatus(allowed) => match ctx.workflow_status {
            Some(s) => bool_to_verdict(allowed.iter().any(|a| a == s), || {
                format!("workflow status {} not in allowlist", s)
            }),
            None => PolicyVerdict::Deny { reason: "workflow not in scope".into() },
        },
        ParticipantHasRole(role) => bool_to_verdict(
            ctx.workflow_roles_held_by_actor.iter().any(|r| r == role),
            || format!("actor does not hold role {}", role),
        ),

        RequiresApprovalFrom(did) => PolicyVerdict::RequireApproval {
            approvers: ApproverSpec::Single(did.clone()),
            reason: format!("RequiresApprovalFrom({})", did),
        },
        RequiresApprovalThreshold { dids, m, n } => PolicyVerdict::RequireApproval {
            approvers: ApproverSpec::Threshold {
                dids: dids.clone(),
                m: *m,
                n: *n,
            },
            reason: format!("RequiresApprovalThreshold({} of {})", m, n),
        },
    }
}

#[inline]
fn bool_to_verdict<F: FnOnce() -> String>(ok: bool, reason: F) -> PolicyVerdict {
    if ok { PolicyVerdict::Allow } else { PolicyVerdict::Deny { reason: reason() } }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx<'a>(amount: u128, daily: u128, lookup: &'a dyn IdentityLookup) -> PolicyContext<'a> {
        PolicyContext {
            amount_wei: amount,
            counterparty_did: Some("did:tenzro:machine:bob:1"),
            asset: "TNZO",
            chain: "tenzro",
            payment_protocol: "MPP",
            current_block: 100,
            current_ts: 0, // Thursday 00:00 UTC
            workflow_status: Some("Active"),
            workflow_roles_held_by_actor: &[],
            identity_lookup: lookup,
            daily_spent_wei: daily,
        }
    }

    struct FixedLookup {
        kyc: Option<u8>,
        bond: Option<u128>,
        risk: Option<u8>,
    }
    impl IdentityLookup for FixedLookup {
        fn kyc_tier(&self, _did: &str) -> Option<u8> { self.kyc }
        fn bond_wei(&self, _did: &str) -> Option<u128> { self.bond }
        fn risk_tier(&self, _did: &str) -> Option<u8> { self.risk }
    }

    #[test]
    fn allow_and_deny() {
        let lookup = NullLookup;
        let c = ctx(0, 0, &lookup);
        assert_eq!(evaluate(&PolicyExpr::Allow, &c), PolicyVerdict::Allow);
        assert!(matches!(evaluate(&PolicyExpr::Deny, &c), PolicyVerdict::Deny { .. }));
    }

    #[test]
    fn amount_lte() {
        let lookup = NullLookup;
        let c1 = ctx(100, 0, &lookup);
        assert_eq!(evaluate(&PolicyExpr::AmountLte(200), &c1), PolicyVerdict::Allow);
        let c2 = ctx(300, 0, &lookup);
        assert!(matches!(evaluate(&PolicyExpr::AmountLte(200), &c2), PolicyVerdict::Deny { .. }));
    }

    #[test]
    fn daily_amount_lte_uses_projected_total() {
        let lookup = NullLookup;
        let c = ctx(50, 100, &lookup);
        assert_eq!(evaluate(&PolicyExpr::DailyAmountLte(200), &c), PolicyVerdict::Allow);
        assert!(matches!(
            evaluate(&PolicyExpr::DailyAmountLte(120), &c),
            PolicyVerdict::Deny { .. }
        ));
    }

    #[test]
    fn and_short_circuits_on_deny() {
        let lookup = NullLookup;
        let c = ctx(500, 0, &lookup);
        let expr = PolicyExpr::And(vec![
            PolicyExpr::AmountLte(1000),
            PolicyExpr::AmountLte(100),
        ]);
        assert!(matches!(evaluate(&expr, &c), PolicyVerdict::Deny { .. }));
    }

    #[test]
    fn or_returns_allow_if_any_branch_allows() {
        let lookup = NullLookup;
        let c = ctx(500, 0, &lookup);
        let expr = PolicyExpr::Or(vec![
            PolicyExpr::AmountLte(100),
            PolicyExpr::AmountLte(1000),
        ]);
        assert_eq!(evaluate(&expr, &c), PolicyVerdict::Allow);
    }

    #[test]
    fn or_collapses_to_require_approval_when_no_allow() {
        let lookup = NullLookup;
        let c = ctx(500, 0, &lookup);
        let expr = PolicyExpr::Or(vec![
            PolicyExpr::AmountLte(100),
            PolicyExpr::RequiresApprovalFrom("did:tenzro:human:treasurer:1".into()),
        ]);
        match evaluate(&expr, &c) {
            PolicyVerdict::RequireApproval { approvers, .. } => {
                assert_eq!(approvers, ApproverSpec::Single("did:tenzro:human:treasurer:1".into()));
            }
            v => panic!("expected RequireApproval, got {:?}", v),
        }
    }

    #[test]
    fn and_with_require_approval_returns_approval() {
        let lookup = NullLookup;
        let c = ctx(500, 0, &lookup);
        let expr = PolicyExpr::And(vec![
            PolicyExpr::AmountLte(1000),
            PolicyExpr::RequiresApprovalFrom("did:tenzro:human:treasurer:1".into()),
        ]);
        assert!(matches!(evaluate(&expr, &c), PolicyVerdict::RequireApproval { .. }));
    }

    #[test]
    fn not_flips_allow_and_deny() {
        let lookup = NullLookup;
        let c = ctx(50, 0, &lookup);
        assert!(matches!(
            evaluate(&PolicyExpr::Not(Box::new(PolicyExpr::AmountLte(100))), &c),
            PolicyVerdict::Deny { .. }
        ));
        assert_eq!(
            evaluate(&PolicyExpr::Not(Box::new(PolicyExpr::AmountLte(10))), &c),
            PolicyVerdict::Allow
        );
    }

    #[test]
    fn counterparty_kyc_tier_check() {
        let lookup = FixedLookup { kyc: Some(2), bond: None, risk: None };
        let c = ctx(0, 0, &lookup);
        assert_eq!(
            evaluate(&PolicyExpr::CounterpartyKycTierGte(2), &c),
            PolicyVerdict::Allow
        );
        assert!(matches!(
            evaluate(&PolicyExpr::CounterpartyKycTierGte(3), &c),
            PolicyVerdict::Deny { .. }
        ));
    }

    #[test]
    fn time_window_business_hours() {
        let lookup = NullLookup;
        // 2026-05-09 14:00 UTC -> hour 14
        let mut c = ctx(0, 0, &lookup);
        c.current_ts = 1_778_421_600;
        let expr = PolicyExpr::TimeWindow { start_hour: 9, end_hour: 17, tz_offset_minutes: 0 };
        assert_eq!(evaluate(&expr, &c), PolicyVerdict::Allow);
        // 2026-05-09 22:00 UTC -> hour 22
        c.current_ts = 1_778_450_400;
        assert!(matches!(evaluate(&expr, &c), PolicyVerdict::Deny { .. }));
    }

    #[test]
    fn time_window_wrap_around() {
        let lookup = NullLookup;
        let mut c = ctx(0, 0, &lookup);
        // overnight window 22..06
        let expr = PolicyExpr::TimeWindow { start_hour: 22, end_hour: 6, tz_offset_minutes: 0 };
        // 23:00 UTC
        c.current_ts = 23 * 3600;
        assert_eq!(evaluate(&expr, &c), PolicyVerdict::Allow);
        // 03:00 UTC
        c.current_ts = 3 * 3600;
        assert_eq!(evaluate(&expr, &c), PolicyVerdict::Allow);
        // 12:00 UTC
        c.current_ts = 12 * 3600;
        assert!(matches!(evaluate(&expr, &c), PolicyVerdict::Deny { .. }));
    }
}

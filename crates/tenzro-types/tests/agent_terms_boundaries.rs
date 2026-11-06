//! Boundary cases of the delegated-agent terms checks: spellings of the
//! same operation, model or counterparty that a steered agent might send,
//! the hour window across midnight, and value split into many small
//! actions across clock-hour and day edges. Seeded and exhaustive where
//! the domain is small, so every run checks the same cases.

use tenzro_types::agent_terms::{
    ActionHistory, AgentAction, AgentTerms, HOUR_MS, ServingNode, TermsScope, check_action,
    check_scope, hour_in_window,
};

const MACHINE: &str = "did:tenzro:machine:m";
const DAY_MS: u64 = 24 * HOUR_MS;

fn terms(scope: TermsScope) -> AgentTerms {
    AgentTerms {
        controller_did: "did:tenzro:human:abc".into(),
        agent_name: "buyer".into(),
        delegation_scope: scope,
        capabilities: vec![],
        serving_nodes: vec![ServingNode {
            machine_did: MACHINE.into(),
            operator_did: "did:tenzro:human:op".into(),
            ..Default::default()
        }],
        min_distinct_operators: 1,
        expires_at_ms: None,
        trifecta_exception: false,
        auto_approve: None,
        credentials: Vec::new(),
    }
}

fn action(operation: &str, amount: u128, counterparty: &str) -> AgentAction {
    AgentAction {
        asset: None,
        usd_e6: 0,
        payment: None,
        agent_did: "a".into(),
        machine_did: MACHINE.into(),
        operation: operation.into(),
        counterparty: counterparty.into(),
        amount,
        chain: "tenzro".into(),
        payment_protocol: None,
        model: None,
        calls: Vec::new(),
        escrow: None,
        remote_grant: None,
        ballot: None,
        veto_signal: None,
        nonce: 0,
        tainted: false,
        step_up: None,
    }
}

/// A small deterministic generator, so the cases do not depend on a crate
/// the package does not already use.
struct Gen(u64);

impl Gen {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n.max(1)
    }
}

/// Other spellings of `name` an injected instruction could produce: case,
/// look-alike letters from other scripts, full-width forms, invisible and
/// combining characters, surrounding space and a trailing NUL.
fn spellings(name: &str) -> Vec<String> {
    let mut out = vec![
        name.to_ascii_uppercase(),
        format!(" {name}"),
        format!("{name} "),
        format!("{name}\u{0}"),
        format!("{name}\u{200b}"),
        format!("\u{feff}{name}"),
        format!("{name}\u{0301}"),
        name.chars()
            .map(|c| {
                char::from_u32(c as u32 + 0xfee0)
                    .filter(|_| c.is_ascii_graphic())
                    .unwrap_or(c)
            })
            .collect(),
    ];
    // Cyrillic and Greek look-alikes of Latin letters.
    let look = [
        ('a', 'а'),
        ('e', 'е'),
        ('o', 'о'),
        ('p', 'р'),
        ('c', 'с'),
        ('y', 'у'),
        ('x', 'х'),
        ('i', 'і'),
        ('v', 'ν'),
    ];
    for (latin, other) in look {
        if name.contains(latin) {
            out.push(name.replacen(latin, &other.to_string(), 1));
        }
    }
    let mut first_upper = name.to_string();
    if let Some(c) = first_upper.get(0..1) {
        first_upper.replace_range(0..1, &c.to_ascii_uppercase());
    }
    out.push(first_upper);
    out
}

#[test]
fn only_the_exact_lower_case_name_of_an_allowed_operation_passes_the_scope() {
    for op in [
        "pay",
        "transfer",
        "governance.vote",
        "create_escrow",
        "inference",
    ] {
        let t = terms(TermsScope {
            allowed_operations: vec![op.into()],
            ..Default::default()
        });
        assert!(
            check_scope(&t, &action(op, 0, ""), 0).is_ok(),
            "{op} itself"
        );
        for s in spellings(op) {
            assert!(
                check_scope(&t, &action(&s, 0, ""), 0).is_err(),
                "{op:?} spelled {s:?} passed the scope"
            );
        }
    }
}

#[test]
fn an_allowed_entry_in_another_case_never_admits_a_non_lower_case_operation() {
    let t = terms(TermsScope {
        allowed_operations: vec!["PAY".into(), "Transfer".into()],
        ..Default::default()
    });
    for (op, ok) in [
        ("pay", true),
        ("transfer", true),
        ("PAY", false),
        ("Transfer", false),
        ("pAy", false),
    ] {
        assert_eq!(check_scope(&t, &action(op, 0, ""), 0).is_ok(), ok, "{op}");
    }
}

#[test]
fn only_the_listed_model_passes_the_scope() {
    let model = "did:tenzro:model:qwen3-0.6b";
    let t = terms(TermsScope {
        allowed_operations: vec!["inference".into()],
        allowed_models: vec![model.into()],
        ..Default::default()
    });
    let mut a = action("inference", 0, "");
    a.model = Some(model.into());
    assert!(check_scope(&t, &a, 0).is_ok());
    for s in spellings(model).into_iter().chain([
        format!("{model}:latest"),
        format!("{model}-instruct"),
        model.replace("0.6b", "06b"),
    ]) {
        // An ASCII case difference names the same model; anything else does not.
        if s.eq_ignore_ascii_case(model) {
            continue;
        }
        a.model = Some(s.clone());
        assert!(
            check_scope(&t, &a, 0).is_err(),
            "model spelled {s:?} passed the scope"
        );
    }
}

/// Bytes a counterparty string names, as the payment path decodes it.
fn named_bytes(s: &str) -> Option<Vec<u8>> {
    let h = s.trim_start_matches("0x");
    if !h.len().is_multiple_of(2) || !h.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    (0..h.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&h[i..i + 2], 16).ok())
        .collect()
}

#[test]
fn a_counterparty_passes_only_when_it_names_the_bytes_of_an_allowed_one() {
    let allowed = "81".repeat(32);
    let t = terms(TermsScope {
        allowed_operations: vec!["transfer".into()],
        allowed_counterparties: vec![format!("0x{allowed}")],
        ..Default::default()
    });
    let want = named_bytes(&allowed).unwrap();
    let mut g = Gen(0x9e37_79b9_7f4a_7c15);
    let mut forms = vec![
        allowed.clone(),
        allowed.to_ascii_uppercase(),
        format!("0x{allowed}"),
        format!("0X{allowed}"),
        format!("0x0x{allowed}"),
        format!("{allowed}00"),
        allowed[..40].to_string(),
        format!("000000000000000000000000{}", &allowed[..40]),
        format!("did:tenzro:human:{allowed}"),
        format!("{allowed}\u{200b}"),
        format!(" {allowed}"),
    ];
    for _ in 0..2_000 {
        let mut b = want.clone();
        let i = g.below(32) as usize;
        b[i] ^= 1 << g.below(8);
        forms.push(b.iter().map(|x| format!("{x:02x}")).collect());
    }
    for f in forms {
        let passed = check_scope(&t, &action("transfer", 1, &f), 0).is_ok();
        if passed {
            assert_eq!(
                named_bytes(&f).as_deref(),
                Some(want.as_slice()),
                "{f:?} passed the counterparty list but names other bytes"
            );
        }
    }
}

/// The hours of the window `[start, end)`, walking forward from `start`
/// around the clock; an empty window when they are equal.
fn reference_hours(start: u8, end: u8) -> Vec<u8> {
    let mut out = Vec::new();
    let mut h = start;
    while h != end {
        out.push(h);
        h = (h + 1) % 24;
    }
    out
}

#[test]
fn the_hour_window_matches_walking_the_clock_for_every_start_end_and_hour() {
    for start in 0..24u8 {
        for end in 0..24u8 {
            let want = reference_hours(start, end);
            for hour in 0..24u8 {
                assert_eq!(
                    hour_in_window([start, end], hour),
                    want.contains(&hour),
                    "window [{start}, {end}) at hour {hour}"
                );
            }
        }
    }
}

#[test]
fn the_hour_window_is_judged_on_the_hour_the_action_lands_in_at_its_edges() {
    // 22:00 to 02:00 UTC.
    let t = terms(TermsScope {
        allowed_operations: vec!["transfer".into()],
        allowed_hours_utc: Some([22, 2]),
        ..Default::default()
    });
    let day = 20_000 * DAY_MS;
    for (ms, ok) in [
        (day + 22 * HOUR_MS - 1, false),
        (day + 22 * HOUR_MS, true),
        (day + DAY_MS - 1, true),
        (day + DAY_MS, true),
        (day + DAY_MS + 2 * HOUR_MS - 1, true),
        (day + DAY_MS + 2 * HOUR_MS, false),
    ] {
        assert_eq!(
            check_scope(&t, &action("transfer", 1, &"00".repeat(32)), ms).is_ok(),
            ok,
            "at {ms}"
        );
    }
}

/// History as a node keeps it: totals of the accepted actions in the
/// current clock hour and UTC day.
#[derive(Default)]
struct Ledger {
    accepted: Vec<(u64, u128)>,
}

impl Ledger {
    fn history(&self, now: u64) -> ActionHistory {
        let (hour, day) = (now / HOUR_MS, now / DAY_MS);
        let mut h = ActionHistory {
            known_counterparty: true,
            ..Default::default()
        };
        for (at, amount) in &self.accepted {
            if at / DAY_MS == day {
                h.spent_today += amount;
                h.actions_today += 1;
            }
            if at / HOUR_MS == hour {
                h.spent_this_hour += amount;
                h.actions_this_hour += 1;
            }
        }
        h
    }
}

#[test]
fn value_split_across_actions_and_clock_edges_never_passes_the_hour_or_day_caps() {
    let (per_tx, hourly, daily, step_up) = (1_000u128, 2_500u128, 9_000u128, 400u128);
    let t = terms(TermsScope {
        allowed_operations: vec!["transfer".into()],
        max_transaction_value: Some(per_tx.to_string()),
        max_hourly_spend: Some(hourly.to_string()),
        max_daily_spend: Some(daily.to_string()),
        step_up_above: Some(step_up.to_string()),
        ..Default::default()
    });
    let cp = "00".repeat(32);
    let mut g = Gen(0x2545_f491_4f6c_dd1d);
    for run in 0..300 {
        let mut l = Ledger::default();
        // Start just before a day boundary so hours and days roll over.
        let mut now = 19_000 * DAY_MS + DAY_MS - 3 * HOUR_MS + g.below(HOUR_MS);
        for _ in 0..400 {
            now += match g.below(4) {
                0 => 1,
                1 => g.below(60_000),
                2 => g.below(HOUR_MS / 2),
                _ => HOUR_MS - now % HOUR_MS - 1 + g.below(3),
            };
            // Mostly just under the step-up threshold, sometimes at a cap.
            let amount = match g.below(5) {
                0 => step_up,
                1 => step_up + 1,
                2 => per_tx,
                _ => 1 + g.below(step_up as u64) as u128,
            };
            let h = l.history(now);
            let stepped = g.below(4) == 0;
            if check_action(&t, &action("transfer", amount, &cp), &h, stepped, now).is_ok() {
                assert!(amount <= per_tx, "run {run}: one action moved {amount}");
                assert!(
                    stepped || amount <= step_up,
                    "run {run}: {amount} passed without step-up"
                );
                l.accepted.push((now, amount));
                let after = l.history(now);
                assert!(
                    after.spent_this_hour <= hourly,
                    "run {run}: hour total {}",
                    after.spent_this_hour
                );
                assert!(
                    after.spent_today <= daily,
                    "run {run}: day total {}",
                    after.spent_today
                );
            }
        }
    }
}

#[test]
fn a_tainted_action_needs_step_up_for_any_value_to_a_new_counterparty_and_above_its_limit() {
    let t = terms(TermsScope {
        allowed_operations: vec!["transfer".into()],
        tainted_value_limit: Some("50".into()),
        ..Default::default()
    });
    let cp = "00".repeat(32);
    for (amount, known, ok) in [
        (0u128, false, true),
        (1, false, false),
        (50, true, true),
        (51, true, false),
    ] {
        let mut a = action("transfer", amount, &cp);
        a.tainted = true;
        let h = ActionHistory {
            known_counterparty: known,
            ..Default::default()
        };
        assert_eq!(
            check_action(&t, &a, &h, false, 0).is_ok(),
            ok,
            "amount {amount} known {known}"
        );
        assert!(
            check_action(&t, &a, &h, true, 0).is_ok(),
            "amount {amount} with step-up"
        );
    }
}

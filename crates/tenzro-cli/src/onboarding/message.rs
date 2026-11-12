//! The one place the initial-phase "you need stake, here is how to get it"
//! wording is built. `tenzro join`, `tenzro setup`, `tenzro validator
//! register`, `tenzro stake bond` and `tenzro doctor` all render from
//! [`stake_gap`]; none of them has its own copy.
//!
//! User-facing wording rule: the initial phase is run by "the Tenzro founders
//! and core developers" / "the Tenzro team". Never an individual, never "I".

use super::foundation_config;
use super::phase::Phase;
use super::state::{ApplicationState, ladder_line};
use crate::rpc::format_tnzo;

/// How a rendered line should be drawn.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LineKind {
    Heading,
    Text,
    Command,
}

pub type Lines = Vec<(LineKind, String)>;

/// Who funds approved applicants. Today the Tenzro team sends the stake from
/// its own validator accounts. A later phase adds an on-chain sponsor account;
/// it slots in as another variant here (changing only the sentences below),
/// because the state machine never asks HOW funds arrived: `funded` is read
/// from the wallet balance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FundingRoute {
    TeamDirect,
}

/// What the ambient settings say. Built once by [`MsgEnv::current`], passed
/// explicitly everywhere else so the builders stay pure.
#[derive(Debug, Clone)]
pub struct MsgEnv {
    pub phase: Phase,
    pub join_link: String,
    pub contacts: Vec<String>,
    pub reply_time: String,
    pub route: FundingRoute,
}

impl MsgEnv {
    /// From `TENZRO_PHASE`, `TENZRO_JOIN_LINK` and the CLI config, falling
    /// back to `foundation_config`.
    pub fn current() -> MsgEnv {
        let cfg = crate::config::load_config();
        let join_link = std::env::var("TENZRO_JOIN_LINK")
            .ok()
            .filter(|s| !s.trim().is_empty())
            .or(cfg.onboarding_join_link)
            .unwrap_or_else(|| foundation_config::join_link().to_string());
        MsgEnv {
            phase: Phase::resolve(
                std::env::var("TENZRO_PHASE").ok().as_deref(),
                cfg.onboarding_phase.as_deref(),
            ),
            join_link,
            ..MsgEnv::with_phase(Phase::Foundation)
        }
    }

    /// Defaults from `foundation_config` for a given phase (tests, doctor).
    pub fn with_phase(phase: Phase) -> MsgEnv {
        MsgEnv {
            phase,
            join_link: foundation_config::join_link().to_string(),
            contacts: foundation_config::contact_lines(),
            reply_time: foundation_config::expected_reply_time().to_string(),
            route: FundingRoute::TeamDirect,
        }
    }
}

/// A role's stake need against a wallet.
#[derive(Debug, Clone)]
pub struct GapInput<'a> {
    /// How the role reads in a sentence, e.g. `validator`.
    pub role_label: &'a str,
    pub required_wei: u128,
    /// `None` when the balance could not be read. Never carries the reason:
    /// an RPC failure must not reach the person.
    pub balance_wei: Option<u128>,
    /// The wallet, ready to copy.
    pub account: &'a str,
    pub state: ApplicationState,
}

impl GapInput<'_> {
    pub fn is_met(&self) -> bool {
        self.balance_wei.is_some_and(|b| b >= self.required_wei)
    }
}

fn held(balance: Option<u128>) -> String {
    match balance {
        Some(b) => format!("This wallet holds {}.", format_tnzo(b)),
        None => "The balance could not be checked just now.".to_string(),
    }
}

fn contacts(env: &MsgEnv, out: &mut Lines) {
    out.push((LineKind::Text, "Questions? Contact the Tenzro team:".into()));
    for c in &env.contacts {
        out.push((LineKind::Command, c.clone()));
    }
}

/// The initial-phase message, or `None` when none applies: the phase is not
/// the initial one, the wallet already holds the stake, or the stake is
/// already bonded (liquid balance is expected to be low then).
pub fn stake_gap(input: &GapInput<'_>, env: &MsgEnv) -> Option<Lines> {
    if env.phase != Phase::Foundation || input.is_met() || input.state.stake_in_place() {
        return None;
    }
    let need = format_tnzo(input.required_wei);
    let role = input.role_label;
    let mut out: Lines = vec![(
        LineKind::Heading,
        format!(
            "You need {need} to run the {role} role. {}",
            held(input.balance_wei)
        ),
    )];
    out.push((LineKind::Text, ladder_line(input.state)));
    use ApplicationState::*;
    match input.state {
        NotApplied => {
            out.push((
                LineKind::Text,
                format!(
                    "Why: the {role} role bonds {need} as its stake. In the initial phase of Tenzro Network the \
                     Tenzro founders and core developers run the network, review each application, decide \
                     eligibility, and send the stake to approved applicants. There is nothing to buy first, and \
                     applying does not guarantee approval."
                ),
            ));
            out.push((
                LineKind::Text,
                format!(
                    "How to apply: fill in the form at {} and give this wallet address:",
                    env.join_link
                ),
            ));
            out.push((LineKind::Command, input.account.to_string()));
            contacts(env, &mut out);
            out.push((
                LineKind::Text,
                format!("Expected reply: {}", env.reply_time),
            ));
            out.push((
                LineKind::Text,
                "Run the same command again at any time. It carries on from wherever your application is."
                    .into(),
            ));
        }
        Applied | UnderReview => {
            let what = if input.state == Applied {
                "The Tenzro team has received your application"
            } else {
                "The Tenzro team is reviewing your application"
            };
            out.push((
                LineKind::Text,
                format!(
                    "{what} for the {role} role. Nothing more is needed from you right now. If approved, the \
                     team sends {need} to this wallet:"
                ),
            ));
            out.push((LineKind::Command, input.account.to_string()));
            out.push((
                LineKind::Text,
                format!("Expected reply: {}", env.reply_time),
            ));
            contacts(env, &mut out);
            out.push((
                LineKind::Text,
                "Run the same command again to check; it continues from here.".into(),
            ));
        }
        Approved => {
            out.push((
                LineKind::Text,
                format!(
                    "Approved. The Tenzro team sends {need} to this wallet after approval. Nothing more is needed \
                     from you; once it arrives, run the same command again and it carries on to staking:"
                ),
            ));
            out.push((LineKind::Command, input.account.to_string()));
            out.push((
                LineKind::Text,
                format!("If it has not arrived and the expected time has passed ({}), contact the team:", env.reply_time),
            ));
            for c in &env.contacts {
                out.push((LineKind::Command, c.clone()));
            }
        }
        Funded => {
            out.push((
                LineKind::Text,
                "The Tenzro team has recorded this wallet as funded, but the balance does not show it yet. \
                 Run the same command again in a few minutes. If it still does not show, contact the team:"
                    .into(),
            ));
            for c in &env.contacts {
                out.push((LineKind::Command, c.clone()));
            }
        }
        Declined => {
            out.push((
                LineKind::Text,
                "The Tenzro team did not approve this application, so no stake will be sent for it.".into(),
            ));
            contacts(env, &mut out);
        }
        Staked | Serving => unreachable!("stake_in_place returned above"),
    }
    Some(out)
}

/// What to do next once the stake is in place or the wallet holds it. Pure;
/// used by `tenzro join --role` when [`stake_gap`] has nothing to say.
pub fn next_step(
    role_label: &str,
    bond_flag: Option<&str>,
    required_wei: u128,
    state: ApplicationState,
) -> Lines {
    use ApplicationState::*;
    let need_tnzo = required_wei / tenzro_types::constants::ONE_TNZO.max(1);
    let mut out: Lines = vec![(LineKind::Text, ladder_line(state))];
    match state {
        Staked => out.push((
            LineKind::Text,
            format!("The {role_label} stake is bonded. Start the node to begin serving: tenzro setup --apply"),
        )),
        Serving => out.push((LineKind::Text, format!("The {role_label} role is live. Nothing to do."))),
        _ => match bond_flag {
            Some(flag) => {
                out.push((
                    LineKind::Text,
                    format!("This wallet holds the {role_label} stake. Bond it:"),
                ));
                out.push((LineKind::Command, format!("tenzro stake bond --role {flag} --amount {need_tnzo}")));
            }
            None => {
                out.push((
                    LineKind::Text,
                    format!("This wallet holds the {role_label} stake. Set up the validator node, which registers itself:"),
                ));
                out.push((LineKind::Command, "tenzro setup".into()));
            }
        },
    }
    out
}

/// True when an error text is the node refusing a spend for lack of funds.
/// Used to swap such an error for [`stake_gap`] in the initial phase, so no
/// raw chain error reaches the person.
pub fn looks_like_insufficient_funds(raw: &str) -> bool {
    let r = raw.to_ascii_lowercase();
    [
        "insufficient",
        "not enough",
        "exceeds balance",
        "balance too low",
        "below minimum",
        "below the minimum",
        "underfunded",
    ]
    .iter()
    .any(|k| r.contains(k))
}

/// Render lines as plain text, one per line, commands indented.
pub fn to_text(lines: &Lines) -> String {
    lines
        .iter()
        .map(|(k, t)| match k {
            LineKind::Command => format!("      {t}"),
            _ => t.clone(),
        })
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;

    const ONE: u128 = 1_000_000_000_000_000_000;
    const ADDR: &str = "0xabababababababababababababababababababababababababababababababab";

    fn input(state: ApplicationState, balance: Option<u128>) -> GapInput<'static> {
        GapInput {
            role_label: "validator",
            required_wei: 10_000 * ONE,
            balance_wei: balance,
            account: ADDR,
            state,
        }
    }
    fn text(l: &Lines) -> String {
        to_text(l)
    }

    #[test]
    fn below_minimum_names_exact_amount_address_link_and_contacts() {
        let env = MsgEnv::with_phase(Phase::Foundation);
        let t = text(&stake_gap(&input(ApplicationState::NotApplied, Some(0)), &env).unwrap());
        assert!(
            t.contains("You need 10000 TNZO to run the validator role. This wallet holds 0 TNZO."),
            "{t}"
        );
        assert!(t.contains(&env.join_link), "{t}");
        assert!(t.contains(ADDR), "{t}");
        for (_, v) in foundation_config::FOUNDATION_CONTACT_CHANNELS.iter() {
            assert!(t.contains(v), "{t}");
        }
        assert!(
            t.contains("Why:") && t.contains("Tenzro founders and core developers"),
            "{t}"
        );
    }

    #[test]
    fn exact_amount_for_each_role_minimum() {
        let env = MsgEnv::with_phase(Phase::Foundation);
        for (req, shown) in [
            (100_000 * ONE, "100000 TNZO"),
            (500 * ONE, "500 TNZO"),
            (100 * ONE, "100 TNZO"),
        ] {
            let i = GapInput {
                required_wei: req,
                ..input(ApplicationState::NotApplied, Some(0))
            };
            assert!(text(&stake_gap(&i, &env).unwrap()).contains(&format!("You need {shown} ")));
        }
    }

    #[test]
    fn an_unreadable_balance_says_so_plainly_and_leaks_no_error() {
        let env = MsgEnv::with_phase(Phase::Foundation);
        let t = text(&stake_gap(&input(ApplicationState::NotApplied, None), &env).unwrap());
        assert!(t.contains("could not be checked just now"), "{t}");
        for leak in [
            "error", "Error", "RPC", "rpc", "-32", "jsonrpc", "HTTP", "eth_",
        ] {
            assert!(!t.contains(leak), "leaked `{leak}`: {t}");
        }
    }

    #[test]
    fn no_message_in_open_stake_phase() {
        let env = MsgEnv::with_phase(Phase::OpenStake);
        assert!(stake_gap(&input(ApplicationState::NotApplied, Some(0)), &env).is_none());
    }

    #[test]
    fn no_message_when_funded_enough_or_already_staked() {
        let env = MsgEnv::with_phase(Phase::Foundation);
        assert!(
            stake_gap(
                &input(ApplicationState::NotApplied, Some(10_000 * ONE)),
                &env
            )
            .is_none()
        );
        assert!(stake_gap(&input(ApplicationState::Staked, Some(0)), &env).is_none());
        assert!(stake_gap(&input(ApplicationState::Serving, Some(0)), &env).is_none());
    }

    #[test]
    fn resuming_from_a_later_state_does_not_reshow_apply_instructions() {
        let env = MsgEnv::with_phase(Phase::Foundation);
        for s in [
            ApplicationState::Applied,
            ApplicationState::UnderReview,
            ApplicationState::Approved,
            ApplicationState::Funded,
        ] {
            let t = text(&stake_gap(&input(s, Some(0)), &env).unwrap());
            assert!(!t.contains("How to apply"), "{s:?}: {t}");
            assert!(
                !t.contains(&env.join_link),
                "{s:?} re-shows the join link: {t}"
            );
        }
        let t = text(&stake_gap(&input(ApplicationState::Approved, Some(0)), &env).unwrap());
        assert!(t.contains("Approved.") && t.contains(ADDR), "{t}");
        let t = text(&stake_gap(&input(ApplicationState::UnderReview, Some(0)), &env).unwrap());
        assert!(t.contains("reviewing your application"), "{t}");
    }

    #[test]
    fn declined_is_told_plainly_with_contacts() {
        let env = MsgEnv::with_phase(Phase::Foundation);
        let t = text(&stake_gap(&input(ApplicationState::Declined, Some(0)), &env).unwrap());
        assert!(
            t.contains("did not approve") && t.contains("Contact the Tenzro team"),
            "{t}"
        );
    }

    #[test]
    fn public_wording_names_no_individual() {
        let env = MsgEnv::with_phase(Phase::Foundation);
        for s in [
            ApplicationState::NotApplied,
            ApplicationState::Applied,
            ApplicationState::UnderReview,
            ApplicationState::Approved,
            ApplicationState::Funded,
            ApplicationState::Declined,
        ] {
            let t = text(&stake_gap(&input(s, Some(0)), &env).unwrap());
            for w in [" I ", "I'm", "my ", "the owner", "The owner"] {
                assert!(!t.contains(w), "{s:?} contains `{w}`: {t}");
            }
        }
    }

    #[test]
    fn next_step_after_funding_is_the_right_command() {
        let t = text(&next_step(
            "model provider",
            Some("ai"),
            1_000 * ONE,
            ApplicationState::Funded,
        ));
        assert!(
            t.contains("tenzro stake bond --role ai --amount 1000"),
            "{t}"
        );
        let t = text(&next_step(
            "validator",
            None,
            10_000 * ONE,
            ApplicationState::Funded,
        ));
        assert!(t.contains("tenzro setup"), "{t}");
        assert!(
            text(&next_step("validator", None, 0, ApplicationState::Serving))
                .contains("Nothing to do")
        );
    }

    #[test]
    fn insufficient_funds_errors_are_recognised() {
        assert!(looks_like_insufficient_funds(
            "RPC error -32000: insufficient funds for transfer"
        ));
        assert!(!looks_like_insufficient_funds("connection refused"));
    }

    /// The cases use a fixed test environment, not foundation_config.json, so filling in
    /// the real channels never makes the file stale. The wallet app
    /// (apps/tenzro-control/src/lib/onboarding.ts) re-implements
    /// this builder in TypeScript. Both must produce these exact lines, so the
    /// cases and their expected output are written to one JSON file that the
    /// wallet's own tests replay. This test fails when the file is stale;
    /// regenerate it with `UPDATE_ONBOARDING_FIXTURES=1 cargo test -p tenzro-cli
    /// onboarding::message`.
    #[test]
    fn wallet_fixture_is_current() {
        use ApplicationState::*;
        let states = [
            NotApplied,
            Applied,
            UnderReview,
            Approved,
            Funded,
            Staked,
            Serving,
            Declined,
        ];
        let mut cases = Vec::new();
        for phase in [Phase::Foundation, Phase::OpenStake] {
            for (label, req_tnzo) in [("validator", 10_000u128), ("compute provider", 500)] {
                for bal in [Some(0u128), None, Some(250 * ONE), Some(req_tnzo * ONE)] {
                    for st in states {
                        let i = GapInput {
                            role_label: label,
                            required_wei: req_tnzo * ONE,
                            balance_wei: bal,
                            account: ADDR,
                            state: st,
                        };
                        let env = MsgEnv {
                            phase,
                            join_link: "https://join.example.test/apply".into(),
                            contacts: vec![
                                "Email: team@example.invalid".into(),
                                "Discord: example-invite".into(),
                            ],
                            reply_time: "within the fixture window".into(),
                            route: FundingRoute::TeamDirect,
                        };
                        let out = stake_gap(&i, &env).map(|l| {
                            l.into_iter()
                                .map(|(k, t)| {
                                    serde_json::json!([format!("{k:?}").to_lowercase(), t])
                                })
                                .collect::<Vec<_>>()
                        });
                        cases.push(serde_json::json!({
                            "phase": phase.as_str(),
                            "role_label": label,
                            "required_wei": i.required_wei.to_string(),
                            "balance_wei": bal.map(|b| b.to_string()),
                            "account": ADDR,
                            "state": st.as_str(),
                            "lines": out,
                        }));
                    }
                }
            }
        }
        let env = serde_json::json!({
            "join_link": "https://join.example.test/apply",
            "contacts": ["Email: team@example.invalid", "Discord: example-invite"],
            "reply_time": "within the fixture window",
        });
        let fixture = serde_json::json!({ "env": env, "cases": cases });
        let mut text = serde_json::to_string_pretty(&fixture).unwrap();
        text.push('\n');
        let path = concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../apps/tenzro-control/src/lib/onboarding-fixtures.json"
        );
        if std::env::var_os("UPDATE_ONBOARDING_FIXTURES").is_some() {
            std::fs::write(path, &text).unwrap();
        }
        // Compared as data: the order a JSON object's keys are written in
        // depends on which features the build gives the JSON library.
        let on_disk: serde_json::Value = std::fs::read_to_string(path)
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();
        assert!(
            on_disk == fixture,
            "{path} is stale: run with UPDATE_ONBOARDING_FIXTURES=1"
        );
    }
}

//! The screen shown when a role needs stake the account does not hold.
//!
//! A new operator arrives with zero TNZO and a role that needs thousands.
//! Instead of an error, they get the options in the order worth trying: apply for a sponsorship grant first, then receive TNZO
//! at the account, then carry on without a staked role. The need is also
//! written to `~/.tenzro/config.json` (`pending_stake`) so `tenzro status`
//! and `tenzro sponsor status` keep naming it until it is met.

use anyhow::Result;

use crate::config;
use crate::rpc::format_tnzo;

pub use crate::onboarding::message::LineKind;
use crate::onboarding::message::{GapInput, MsgEnv, stake_gap};
use crate::onboarding::role::JoinRole;
use crate::onboarding::state::ApplicationState;

/// A role's stake requirement against the account that must hold it.
#[derive(Debug, Clone)]
pub struct StakeNeed {
    /// What the stake is for, e.g. `validator` or `compute bond`.
    pub role: String,
    pub required_wei: u128,
    /// `None` when the balance could not be read.
    pub balance_wei: Option<u128>,
    /// The account that must hold the stake, `0x` and 64 hex.
    pub account: String,
}

impl StakeNeed {
    /// Whether the account already holds what the role needs.
    pub fn is_met(&self) -> bool {
        self.balance_wei.is_some_and(|b| b >= self.required_wei)
    }

    /// TNZO still missing, in wei. An unreadable balance counts as zero held.
    pub fn shortfall_wei(&self) -> u128 {
        self.required_wei
            .saturating_sub(self.balance_wei.unwrap_or(0))
    }

    /// The record key for this role: its application slug when it is one.
    pub fn role_key(&self) -> String {
        JoinRole::parse(&self.role).map_or_else(|| self.role.clone(), |r| r.slug().to_string())
    }

    /// The screen, as lines, from the ambient phase and the application
    /// status this machine last kept.
    pub fn lines(&self) -> Vec<(LineKind, String)> {
        let state = crate::onboarding::flow::cached_state(&self.account, &self.role_key())
            .unwrap_or(ApplicationState::NotApplied);
        self.lines_with(&MsgEnv::current(), state)
    }

    /// The screen. Pure. In the initial phase it is the one shared
    /// application message (`onboarding::message`, which `tenzro doctor`
    /// renders too); in any other phase, the general options below.
    pub fn lines_with(&self, env: &MsgEnv, state: ApplicationState) -> Vec<(LineKind, String)> {
        let input = GapInput {
            role_label: &self.role,
            required_wei: self.required_wei,
            balance_wei: self.balance_wei,
            account: &self.account,
            state,
        };
        stake_gap(&input, env).unwrap_or_else(|| self.general_lines())
    }

    fn general_lines(&self) -> Vec<(LineKind, String)> {
        let held = match self.balance_wei {
            Some(b) => format!("This account holds {}.", format_tnzo(b)),
            None => "The account's balance could not be read.".to_string(),
        };
        vec![
            (
                LineKind::Heading,
                format!(
                    "You need {} to run the {} role. {held}",
                    format_tnzo(self.required_wei),
                    self.role
                ),
            ),
            (
                LineKind::Text,
                "Your options, in the order to try them:".into(),
            ),
            (
                LineKind::Text,
                "1. Apply for a sponsorship grant. Governance can approve an operator whose \
                 hardware attests and who has run available, then fund its running cost and \
                 validator bond, so you need no TNZO up front. See whether you qualify, then apply:"
                    .into(),
            ),
            (LineKind::Command, "tenzro sponsor check".into()),
            (LineKind::Command, "tenzro sponsor apply".into()),
            (
                LineKind::Text,
                "2. Receive TNZO at this account, from an exchange, another wallet or a sponsor. \
                 Run the same command again afterwards and it carries on from here:"
                    .into(),
            ),
            (LineKind::Command, self.account.clone()),
            (
                LineKind::Text,
                "3. Continue without a staked role. The machine joins as a participant, and you \
                 can stake later:"
                    .into(),
            ),
            (LineKind::Command, "tenzro setup --mode consume".into()),
        ]
    }

    /// Render the screen through `emit`.
    pub fn render(&self, mut emit: impl FnMut(LineKind, String)) {
        for (kind, text) in self.lines() {
            emit(kind, text);
        }
    }

    /// Record the need in the CLI config so later commands keep naming it.
    pub fn remember(&self) -> Result<()> {
        let mut cfg = config::load_config();
        cfg.pending_stake = Some(config::PendingStake {
            role: self.role.clone(),
            required_wei: self.required_wei.to_string(),
            account: self.account.clone(),
        });
        config::save_config(&cfg)
    }
}

/// Clear the recorded need once the account holds the stake.
pub fn forget() -> Result<()> {
    let mut cfg = config::load_config();
    if cfg.pending_stake.is_some() {
        cfg.pending_stake = None;
        config::save_config(&cfg)?;
    }
    Ok(())
}

impl StakeNeed {
    /// Print the screen as plain output, for commands that are not the setup
    /// wizard.
    pub fn print_plain(&self) {
        println!();
        self.render(|kind, text| match kind {
            LineKind::Heading => crate::output::print_warning(&text),
            LineKind::Text => crate::output::print_info(&text),
            LineKind::Command => println!("      {text}"),
        });
        println!();
    }
}

/// The `tenzro ...` commands the screen prints.
pub fn printed_tenzro_commands(need: &StakeNeed) -> Vec<String> {
    use crate::onboarding::phase::Phase;
    let mut lines = need.lines_with(
        &MsgEnv::with_phase(Phase::OpenStake),
        ApplicationState::NotApplied,
    );
    lines.extend(crate::onboarding::message::next_step(
        &need.role,
        Some("ai"),
        need.required_wei,
        ApplicationState::Funded,
    ));
    lines
        .into_iter()
        .filter(|(k, t)| *k == LineKind::Command && t.starts_with("tenzro "))
        .map(|(_, t)| t)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn open() -> MsgEnv {
        MsgEnv::with_phase(crate::onboarding::phase::Phase::OpenStake)
    }

    #[test]
    fn the_initial_phase_screen_is_the_shared_application_message() {
        use crate::onboarding::phase::Phase;
        let lines = need(Some(0)).lines_with(
            &MsgEnv::with_phase(Phase::Foundation),
            ApplicationState::NotApplied,
        );
        let t = crate::onboarding::message::to_text(&lines);
        assert!(
            t.contains("How to apply") && t.contains("10000 TNZO"),
            "{t}"
        );
        assert!(!t.contains("sponsorship grant"), "{t}");
        // the same text doctor renders: both come from stake_gap
        let direct = crate::onboarding::message::stake_gap(
            &GapInput {
                role_label: "validator",
                required_wei: need(Some(0)).required_wei,
                balance_wei: Some(0),
                account: &need(Some(0)).account,
                state: ApplicationState::NotApplied,
            },
            &MsgEnv::with_phase(Phase::Foundation),
        )
        .unwrap();
        assert_eq!(lines, direct);
    }

    fn need(balance: Option<u128>) -> StakeNeed {
        StakeNeed {
            role: "validator".into(),
            required_wei: 10_000 * 1_000_000_000_000_000_000,
            balance_wei: balance,
            account: format!("0x{}", "ab".repeat(32)),
        }
    }

    #[test]
    fn sponsorship_is_the_first_option() {
        let lines = need(Some(0)).lines_with(&open(), ApplicationState::NotApplied);
        let texts: Vec<&str> = lines.iter().map(|(_, t)| t.as_str()).collect();
        let sponsor = texts
            .iter()
            .position(|t| t.starts_with("1. Apply for a sponsorship grant"))
            .unwrap();
        let receive = texts
            .iter()
            .position(|t| t.starts_with("2. Receive TNZO"))
            .unwrap();
        let without = texts
            .iter()
            .position(|t| t.starts_with("3. Continue without"))
            .unwrap();
        assert!(sponsor < receive && receive < without);
    }

    #[test]
    fn the_screen_names_the_amount_the_account_and_the_balance() {
        let lines = need(Some(0)).lines_with(&open(), ApplicationState::NotApplied);
        assert!(lines[0].1.contains("10000 TNZO"), "{}", lines[0].1);
        assert!(
            lines
                .iter()
                .any(|(_, t)| t == &format!("0x{}", "ab".repeat(32)))
        );
        assert!(
            need(None).lines_with(&open(), ApplicationState::NotApplied)[0]
                .1
                .contains("could not be read")
        );
    }

    #[test]
    fn shortfall_and_met() {
        let one = 1_000_000_000_000_000_000;
        assert_eq!(need(Some(4_000 * one)).shortfall_wei(), 6_000 * one);
        assert!(!need(Some(4_000 * one)).is_met());
        assert!(need(Some(10_000 * one)).is_met());
        assert_eq!(need(None).shortfall_wei(), 10_000 * one);
        assert!(!need(None).is_met());
    }
}

//! The one table every key comes from: dispatch, the footer and the help
//! overlay all read it, so the three can never disagree. One key, one action;
//! a test fails the build if a key is bound twice or two actions share a label.

use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyModifiers};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Act {
    // Console
    Screen(usize),
    Next,
    Prev,
    Down,
    Up,
    Refresh,
    Edit,
    More,
    // Setup
    Go,
    Back,
    Skip,
    Pick(usize),
    // Both
    Help,
    Close,
    Quit,
}

#[derive(Debug, Clone, Copy)]
pub struct Binding {
    pub act: Act,
    pub keys: &'static [&'static str],
    pub label: &'static str,
    /// Short form for the footer; empty when the help overlay is enough.
    pub hint: &'static str,
}

const fn b(act: Act, keys: &'static [&'static str], label: &'static str, hint: &'static str) -> Binding {
    Binding { act, keys, label, hint }
}

/// The console screens, in order, with their keys.
pub const SCREENS: [(&str, &str); 6] = [
    ("1", "Overview"),
    ("2", "Wallet"),
    ("3", "Models"),
    ("4", "Validators"),
    ("5", "Governance"),
    ("6", "Health"),
];

pub const CONSOLE: &[Binding] = &[
    b(Act::Screen(0), &["1"], "Overview: node, chain, peers", ""),
    b(Act::Screen(1), &["2"], "Wallet: balance of one account", ""),
    b(Act::Screen(2), &["3"], "Models: what this node holds and serves", ""),
    b(Act::Screen(3), &["4"], "Validators: the registered set", ""),
    b(Act::Screen(4), &["5"], "Governance: proposals and tallies", ""),
    b(Act::Screen(5), &["6"], "Health: peers, sync, roles, key grant", ""),
    b(Act::Next, &["Tab", "Right"], "Next screen", "Tab next"),
    b(Act::Prev, &["Shift-Tab", "Left"], "Previous screen", ""),
    b(Act::Down, &["Down", "j"], "Move down in a list", "Up/Down move"),
    b(Act::Up, &["Up", "k"], "Move up in a list", ""),
    b(Act::Refresh, &["r"], "Refresh now (it also refreshes every 5 s)", "r refresh"),
    b(Act::Edit, &["e"], "Wallet: choose the account to show", "e account"),
    b(Act::More, &["m"], "More commands: the full command menu", "m more"),
    b(Act::Help, &["?"], "Show or hide this help", "? help"),
    b(Act::Close, &["Esc"], "Close help or cancel an edit", ""),
    b(Act::Quit, &["q", "Ctrl-C"], "Quit and restore the terminal", "q quit"),
];

pub const SETUP: &[Binding] = &[
    b(Act::Go, &["Enter"], "Do this step, or continue", "Enter go"),
    b(Act::Back, &["b", "Backspace"], "Back one step", "b back"),
    b(Act::Skip, &["s"], "Skip this step (only where it is safe)", "s skip"),
    b(Act::Down, &["Down", "j"], "Move down in a list", ""),
    b(Act::Up, &["Up", "k"], "Move up in a list", ""),
    b(Act::Pick(0), &["1"], "Choose the first answer", ""),
    b(Act::Pick(1), &["2"], "Choose the second answer", ""),
    b(Act::Pick(2), &["3"], "Choose the third answer", ""),
    b(Act::Pick(3), &["4"], "Choose the fourth answer", ""),
    b(Act::Help, &["?"], "Show or hide this help", "? help"),
    b(Act::Close, &["Esc"], "Close help, or cancel a typed confirmation", ""),
    b(Act::Quit, &["q", "Ctrl-C"], "Quit and restore the terminal", "q quit"),
];

/// Normalised name of a key press, `None` for releases and repeats.
pub fn key_name(k: &KeyEvent) -> Option<String> {
    if k.kind != KeyEventKind::Press {
        return None;
    }
    let ctrl = k.modifiers.contains(KeyModifiers::CONTROL);
    Some(match k.code {
        KeyCode::Char('c') if ctrl => "Ctrl-C".into(),
        KeyCode::Char(c) => c.to_string(),
        KeyCode::Tab => "Tab".into(),
        KeyCode::BackTab => "Shift-Tab".into(),
        KeyCode::Left => "Left".into(),
        KeyCode::Right => "Right".into(),
        KeyCode::Up => "Up".into(),
        KeyCode::Down => "Down".into(),
        KeyCode::Esc => "Esc".into(),
        KeyCode::Enter => "Enter".into(),
        KeyCode::Backspace => "Backspace".into(),
        _ => return None,
    })
}

pub fn act_for(table: &[Binding], name: &str) -> Option<Act> {
    table.iter().find(|x| x.keys.contains(&name)).map(|x| x.act)
}

/// Problems with a table itself: a key bound twice, or two actions with one label.
pub fn problems(table: &[Binding]) -> Vec<String> {
    let mut out = Vec::new();
    let mut seen: Vec<(&str, Act)> = Vec::new();
    let mut labels: Vec<(&str, Act)> = Vec::new();
    for x in table {
        for k in x.keys {
            if let Some((_, prior)) = seen.iter().find(|(s, _)| s == k)
                && *prior != x.act
            {
                out.push(format!("key {k} is bound to {prior:?} and {:?}", x.act));
            }
            seen.push((k, x.act));
        }
        if let Some((_, prior)) = labels.iter().find(|(l, _)| *l == x.label)
            && *prior != x.act
        {
            out.push(format!("label {:?} is used by {prior:?} and {:?}", x.label, x.act));
        }
        labels.push((x.label, x.act));
    }
    out
}

/// The footer text for a table: the hints, in order.
pub fn footer(table: &[Binding]) -> String {
    table
        .iter()
        .filter(|x| !x.hint.is_empty())
        .map(|x| x.hint)
        .collect::<Vec<_>>()
        .join("  ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_key_is_bound_twice_and_no_label_repeats() {
        assert_eq!(problems(CONSOLE), Vec::<String>::new());
        assert_eq!(problems(SETUP), Vec::<String>::new());
    }

    #[test]
    fn every_console_screen_has_exactly_one_key() {
        for (i, (key, _)) in SCREENS.iter().enumerate() {
            assert_eq!(act_for(CONSOLE, key), Some(Act::Screen(i)));
        }
    }

    #[test]
    fn a_duplicate_is_caught() {
        let bad = [
            b(Act::Next, &["x"], "a", ""),
            b(Act::Prev, &["x"], "b", ""),
        ];
        assert_eq!(problems(&bad).len(), 1);
    }

    #[test]
    fn ctrl_c_is_a_quit() {
        let k = KeyEvent::new(KeyCode::Char('c'), KeyModifiers::CONTROL);
        assert_eq!(act_for(CONSOLE, &key_name(&k).unwrap()), Some(Act::Quit));
        assert_eq!(act_for(SETUP, &key_name(&k).unwrap()), Some(Act::Quit));
    }
}

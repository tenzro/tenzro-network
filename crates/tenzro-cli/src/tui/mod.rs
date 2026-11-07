//! The full-screen interface: a first-run setup that walks a new person
//! from nothing to a working install, and the console that follows it.
//!
//! Both are built with ratatui on crossterm, so they work in a native
//! terminal on Linux, macOS and Windows, over ssh and inside tmux, with no
//! Node.js. The state of each screen is a plain value (`firstrun::App`,
//! `console::Console`) that takes keys and draws into any frame, which is how
//! the tests drive them. The drivers below own the terminal and put it back
//! however they end.

pub mod console;
pub mod detect;
pub mod firstrun;
pub mod journey;
pub mod keys;
pub mod runner;
pub mod term;
pub mod theme;
pub mod ui;

use std::sync::atomic::Ordering;
use std::time::Duration;

use anyhow::Result;
use ratatui::crossterm::event::{self, Event};

pub use console::Leave;
pub use firstrun::Outcome;

/// Whether this machine has been set up: the settings file exists.
pub fn is_first_run() -> bool {
    !crate::config::config_path().exists()
}

/// Whether a full-screen interface can be shown here.
pub fn available() -> bool {
    term::interactive_terminal()
}

/// The endpoint the first run checks and saves: what the person asked for,
/// else the public network.
pub fn first_run_rpc() -> String {
    let (url, source) = crate::endpoint::resolve();
    if source == crate::endpoint::Source::Default {
        crate::endpoint::PUBLIC_RPC.to_string()
    } else {
        url
    }
}

/// Run the first-run screens.
pub async fn first_run(rpc: String) -> Result<Outcome> {
    let handle = tokio::runtime::Handle::current();
    let stop = term::stop_flag();
    tokio::task::spawn_blocking(move || -> Result<Outcome> {
        let mut session = term::Session::enter()?;
        let mut app = firstrun::App::new(&rpc, theme::Theme::detect(), Some(handle));
        app.start_probes();
        loop {
            app.tick();
            session.terminal.draw(|f| app.view(f))?;
            if let Some(o) = app.outcome.take() {
                return Ok(o);
            }
            if stop.load(Ordering::SeqCst) {
                return Ok(Outcome::Quit);
            }
            if event::poll(Duration::from_millis(100))? {
                match event::read()? {
                    Event::Key(k) => {
                        if let Some(n) = keys::key_name(&k) {
                            app.on_key(&n);
                        }
                    }
                    Event::Resize(..) => session.terminal.clear()?,
                    _ => {}
                }
            }
        }
    })
    .await?
}

/// Run the console against `url`.
pub async fn console(url: String) -> Result<Leave> {
    let handle = tokio::runtime::Handle::current();
    let stop = term::stop_flag();
    tokio::task::spawn_blocking(move || -> Result<Leave> {
        let mut session = term::Session::enter()?;
        let mut c = console::Console::start(&url, theme::Theme::detect(), &handle);
        loop {
            c.tick();
            session.terminal.draw(|f| c.view(f))?;
            if let Some(l) = c.leave.take() {
                return Ok(l);
            }
            if stop.load(Ordering::SeqCst) {
                return Ok(Leave::Quit);
            }
            if event::poll(Duration::from_millis(100))? {
                match event::read()? {
                    Event::Key(k) => {
                        if let Some(n) = keys::key_name(&k) {
                            c.on_key(&n);
                        }
                    }
                    Event::Resize(..) => session.terminal.clear()?,
                    _ => {}
                }
            }
        }
    })
    .await?
}

/// The text printed after the screens close, so the one next command stays
/// in the terminal's scrollback.
pub fn farewell(o: &Outcome) -> Option<String> {
    match o {
        Outcome::Quit => None,
        Outcome::Finished { next } if next == "tenzro" => None,
        Outcome::Finished { next } => Some(format!("Next, run: {next}")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_farewell_names_exactly_one_command() {
        assert_eq!(farewell(&Outcome::Quit), None);
        assert_eq!(
            farewell(&Outcome::Finished { next: "tenzro dev".into() }).as_deref(),
            Some("Next, run: tenzro dev")
        );
        assert_eq!(farewell(&Outcome::Finished { next: "tenzro".into() }), None);
    }
}

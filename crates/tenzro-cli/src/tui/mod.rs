//! The full-screen interface: a first-run setup that walks a new person
//! from nothing to a working install, and the console that follows it.
//!
//! Both are built with ratatui on crossterm, so they work in a native
//! terminal on Linux, macOS and Windows, over ssh and inside tmux, with no
//! Node.js. The state of each screen is a plain value (`firstrun::App`,
//! `console::Console`) that takes keys and draws into any frame, which is how
//! the tests drive them. The drivers below own the terminal and put it back
//! however they end.

pub mod assistant;
pub mod console;
pub mod detect;
pub mod firstrun;
pub mod journey;
pub mod keys;
pub mod runner;
pub mod term;
pub mod theme;
pub mod ui;

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
    let stop = term::Stop::watch();
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
            if stop.asked() {
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
    let stop = term::Stop::watch();
    tokio::task::spawn_blocking(move || -> Result<Leave> {
        let mut session = term::Session::enter()?;
        let mut c = console::Console::start(&url, theme::Theme::detect(), &handle);
        loop {
            c.tick();
            session.terminal.draw(|f| c.view(f))?;
            if let Some(l) = c.leave.take() {
                return Ok(l);
            }
            if stop.asked() {
                return Ok(Leave::Quit);
            }
            if let Some(argv) = c.assistant.handover.take() {
                // The person said yes: the command gets their terminal, Ctrl-C
                // there is the command's, and the console comes back when it
                // has ended.
                drop(session);
                let result = {
                    let _lent = stop.lend();
                    assistant::run_attached(&argv)
                };
                if stop.asked() {
                    return Ok(Leave::Quit);
                }
                session = term::Session::enter()?;
                c.assistant.handed_back(result);
                continue;
            }
            match next_event(&mut c.assistant, &mut Crossterm)? {
                Some(Event::Key(k)) => {
                    if let Some(n) = keys::key_name(&k) {
                        c.on_key(&n);
                    }
                }
                Some(Event::Paste(text)) => c.on_paste(&text),
                Some(Event::Resize(..)) => session.terminal.clear()?,
                _ => {}
            }
        }
    })
    .await?
}

/// Where the console's keys and pastes come from.
trait Input {
    fn poll(&mut self, timeout: Duration) -> Result<bool>;
    fn read(&mut self) -> Result<Event>;
}

/// The terminal.
struct Crossterm;

impl Input for Crossterm {
    fn poll(&mut self, timeout: Duration) -> Result<bool> {
        Ok(event::poll(timeout)?)
    }

    fn read(&mut self) -> Result<Event> {
        Ok(event::read()?)
    }
}

/// The next event for the console, if one comes within a tick. A question
/// raised since the last read, by a reply that arrived in tick() or by the key
/// just handled, is never answered or armed by a key or paste that was already
/// waiting: those are dropped first.
fn next_event(panel: &mut assistant::Panel, input: &mut impl Input) -> Result<Option<Event>> {
    if panel.question_appeared() {
        while input.poll(Duration::ZERO)? {
            let _ = input.read()?;
        }
    }
    if input.poll(Duration::from_millis(100))? {
        Ok(Some(input.read()?))
    } else {
        Ok(None)
    }
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
    use std::collections::VecDeque;

    use ratatui::crossterm::event::{KeyCode, KeyEvent, KeyModifiers};

    use super::*;

    struct Queue(VecDeque<Event>);

    impl Input for Queue {
        fn poll(&mut self, _: Duration) -> Result<bool> {
            Ok(!self.0.is_empty())
        }

        fn read(&mut self) -> Result<Event> {
            Ok(self.0.pop_front().expect("polled first"))
        }
    }

    fn key(c: char) -> Event {
        Event::Key(KeyEvent::new(KeyCode::Char(c), KeyModifiers::NONE))
    }

    fn enter() -> Event {
        Event::Key(KeyEvent::new(KeyCode::Enter, KeyModifiers::NONE))
    }

    const QUESTION: &str = "y then Enter run it  n leave it  Ctrl-C quit";

    #[test]
    fn keys_typed_ahead_of_a_question_neither_arm_nor_answer_it() {
        let mut p = assistant::Panel::new(None);
        for c in "/serve qwen".chars() {
            p.on_key(&c.to_string());
        }
        // The person typed y, Enter and a paste before the question was shown.
        let mut input = Queue(VecDeque::from([
            key('y'),
            enter(),
            Event::Paste("y".into()),
        ]));
        p.on_key("Enter");
        assert_eq!(p.footer(), QUESTION);

        assert!(next_event(&mut p, &mut input).unwrap().is_none());
        assert!(input.0.is_empty());
        assert_eq!(p.footer(), QUESTION, "nothing armed the question");
        assert_eq!(p.handover, None);

        // Keys typed once the question is shown answer it.
        input.0.extend([key('y'), enter()]);
        for _ in 0..2 {
            let Some(Event::Key(k)) = next_event(&mut p, &mut input).unwrap() else {
                panic!("a key typed after the question reaches it");
            };
            p.on_key(&keys::key_name(&k).unwrap());
        }
        assert!(p.handover.is_some());
    }

    #[test]
    fn without_a_new_question_a_waiting_key_is_read() {
        let mut p = assistant::Panel::new(None);
        let mut input = Queue(VecDeque::from([key('a'), key('b')]));
        assert!(matches!(
            next_event(&mut p, &mut input).unwrap(),
            Some(Event::Key(k)) if k.code == KeyCode::Char('a')
        ));
        assert_eq!(input.0.len(), 1);
    }

    #[test]
    fn the_farewell_names_exactly_one_command() {
        assert_eq!(farewell(&Outcome::Quit), None);
        assert_eq!(
            farewell(&Outcome::Finished {
                next: "tenzro dev".into()
            })
            .as_deref(),
            Some("Next, run: tenzro dev")
        );
        assert_eq!(
            farewell(&Outcome::Finished {
                next: "tenzro".into()
            }),
            None
        );
    }
}

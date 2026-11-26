//! Owning the terminal: raw mode and the alternate screen, put back however
//! the program ends (normal return, Ctrl-C, a signal, or a panic).

use std::io::{self, Stdout};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::Result;
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::crossterm::cursor::Show;
use ratatui::crossterm::event::{DisableBracketedPaste, EnableBracketedPaste};
use ratatui::crossterm::execute;
use ratatui::crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};

pub type Term = Terminal<CrosstermBackend<Stdout>>;

/// Whether a full-screen interface can be shown: both ends are a terminal and
/// the terminal is not `dumb`.
pub fn interactive_terminal() -> bool {
    use std::io::IsTerminal as _;
    io::stdin().is_terminal()
        && io::stdout().is_terminal()
        && std::env::var("TERM").map(|t| t != "dumb").unwrap_or(true)
}

/// Put the terminal back: leave the alternate screen, show the cursor, leave
/// raw mode. Safe to call twice.
pub fn restore() {
    let _ = disable_raw_mode();
    let mut out = io::stdout();
    let _ = execute!(out, DisableBracketedPaste, LeaveAlternateScreen, Show);
}

/// Restore the terminal first when the program panics, then let the normal
/// panic message print on a sane screen.
pub fn install_panic_hook() {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        restore();
        previous(info);
    }));
}

/// Whether the process has been asked to stop (SIGINT, SIGTERM, SIGHUP). In
/// raw mode Ctrl-C at the keyboard arrives as a key; this catches the signal
/// sent from outside.
#[derive(Clone)]
pub struct Stop {
    asked: Arc<AtomicBool>,
    lent: Arc<AtomicBool>,
}

impl Stop {
    /// Starts watching for the signals. Call it inside the runtime.
    pub fn watch() -> Self {
        let stop = Self {
            asked: Arc::new(AtomicBool::new(false)),
            lent: Arc::new(AtomicBool::new(false)),
        };
        let seen = stop.clone();
        #[cfg(unix)]
        {
            use tokio::signal::unix::{SignalKind, signal};
            let mut int = signal(SignalKind::interrupt()).ok();
            let mut term = signal(SignalKind::terminate()).ok();
            let mut hup = signal(SignalKind::hangup()).ok();
            tokio::spawn(async move {
                loop {
                    let interrupt = tokio::select! {
                        _ = arrival(&mut int) => true,
                        _ = arrival(&mut term) => false,
                        _ = arrival(&mut hup) => false,
                    };
                    if !(interrupt && seen.lent.load(Ordering::SeqCst)) {
                        break;
                    }
                }
                seen.asked.store(true, Ordering::SeqCst);
            });
        }
        #[cfg(not(unix))]
        tokio::spawn(async move {
            loop {
                let interrupt = tokio::signal::ctrl_c().await.is_ok();
                if !(interrupt && seen.lent.load(Ordering::SeqCst)) {
                    break;
                }
            }
            seen.asked.store(true, Ordering::SeqCst);
        });
        stop
    }

    pub fn asked(&self) -> bool {
        self.asked.load(Ordering::SeqCst)
    }

    /// While the terminal is lent to a command, Ctrl-C at the keyboard is
    /// sent to that command and to this process. It is the command's to
    /// answer, so it does not count here; SIGTERM and SIGHUP still do. The
    /// terminal is lent until the returned guard drops, however the command
    /// ends.
    pub fn lend(&self) -> Lent<'_> {
        self.lent.store(true, Ordering::SeqCst);
        Lent(self)
    }
}

/// The terminal lent to a command, until this drops.
pub struct Lent<'a>(&'a Stop);

impl Drop for Lent<'_> {
    fn drop(&mut self) {
        self.0.lent.store(false, Ordering::SeqCst);
    }
}

#[cfg(unix)]
async fn arrival(signal: &mut Option<tokio::signal::unix::Signal>) {
    match signal {
        Some(signal) => {
            signal.recv().await;
        }
        None => std::future::pending().await,
    }
}

/// Raw mode plus the alternate screen, for as long as the value lives.
pub struct Session {
    pub terminal: Term,
}

impl Session {
    pub fn enter() -> Result<Self> {
        install_panic_hook();
        enable_raw_mode()?;
        let mut out = io::stdout();
        // With bracketed paste on, pasted text arrives as one paste rather
        // than as keys, so a paste can never answer a question.
        if let Err(e) = execute!(out, EnterAlternateScreen, EnableBracketedPaste) {
            let _ = disable_raw_mode();
            return Err(e.into());
        }
        let backend = CrosstermBackend::new(out);
        let mut terminal = Terminal::new(backend)?;
        terminal.hide_cursor()?;
        terminal.clear()?;
        Ok(Self { terminal })
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        restore();
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::time::Duration;

    fn interrupt_this_process() {
        let sent = std::process::Command::new("kill")
            .args(["-INT", &std::process::id().to_string()])
            .status()
            .unwrap();
        assert!(sent.success());
    }

    #[tokio::test]
    async fn an_interrupt_counts_unless_the_terminal_is_lent_to_a_command() {
        let stop = Stop::watch();
        {
            let _lent = stop.lend();
            interrupt_this_process();
            tokio::time::sleep(Duration::from_millis(500)).await;
            assert!(!stop.asked());
        }

        interrupt_this_process();
        for _ in 0..500 {
            if stop.asked() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(stop.asked());
    }
}

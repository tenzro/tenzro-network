//! Owning the terminal: raw mode and the alternate screen, put back however
//! the program ends (normal return, Ctrl-C, a signal, or a panic).

use std::io::{self, Stdout};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use anyhow::Result;
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::crossterm::cursor::Show;
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
    let _ = execute!(out, LeaveAlternateScreen, Show);
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

/// A flag set when the process is asked to stop (SIGINT, SIGTERM, SIGHUP).
/// In raw mode Ctrl-C at the keyboard arrives as a key; this catches the
/// signal sent from outside.
pub fn stop_flag() -> Arc<AtomicBool> {
    let flag = Arc::new(AtomicBool::new(false));
    let f = flag.clone();
    tokio::spawn(async move {
        #[cfg(unix)]
        {
            use tokio::signal::unix::{SignalKind, signal};
            let mut term = signal(SignalKind::terminate()).ok();
            let mut hup = signal(SignalKind::hangup()).ok();
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = async { match term.as_mut() { Some(s) => { s.recv().await; } None => std::future::pending().await } } => {}
                _ = async { match hup.as_mut() { Some(s) => { s.recv().await; } None => std::future::pending().await } } => {}
            }
        }
        #[cfg(not(unix))]
        {
            let _ = tokio::signal::ctrl_c().await;
        }
        f.store(true, Ordering::SeqCst);
    });
    flag
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
        if let Err(e) = execute!(out, EnterAlternateScreen) {
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

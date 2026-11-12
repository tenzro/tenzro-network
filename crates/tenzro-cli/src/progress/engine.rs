//! Draws a [`Board`] on a terminal, writes it as calm lines, or writes it as
//! one JSON line per event, depending on where the output is going.

use std::collections::HashMap;
use std::io::Write;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use serde_json::json;

use super::fmt;
use super::model::{Board, Kind, StepState, Task};
use super::rows::{self, Opts, Row, Tone};

/// How progress is shown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// A terminal: a live checklist, bars and spinners that redraw in place.
    Tty,
    /// Not a terminal, or colour is off: plain lines, at a calm rate.
    Plain,
    /// One JSON object per line, for programs.
    Json,
}

/// The environment variable that picks a mode by hand: `json` or `plain`.
pub const MODE_ENV: &str = "TENZRO_PROGRESS";

/// Pick the mode from the facts about this run. Pure, so it can be tested.
pub fn mode_from(
    json_flag: bool,
    env_mode: Option<&str>,
    no_color_flag: bool,
    no_color_env: Option<&str>,
    term: Option<&str>,
    stdout_tty: bool,
    stderr_tty: bool,
) -> Mode {
    if json_flag || env_mode == Some("json") {
        return Mode::Json;
    }
    if env_mode == Some("plain")
        || no_color_flag
        || no_color_env.is_some_and(|v| !v.is_empty())
        || term == Some("dumb")
        || !stdout_tty
        || !stderr_tty
    {
        return Mode::Plain;
    }
    Mode::Tty
}

impl Mode {
    /// The mode for this process, from its arguments, environment and streams.
    pub fn detect() -> Mode {
        use std::io::IsTerminal as _;
        let args: Vec<String> = std::env::args().collect();
        let json = args.iter().any(|a| a == "--json" || a == "--format=json")
            || args
                .windows(2)
                .any(|w| w[0] == "--format" && w[1] == "json");
        mode_from(
            json,
            std::env::var(MODE_ENV).ok().as_deref(),
            args.iter().any(|a| a == "--no-color"),
            std::env::var("NO_COLOR").ok().as_deref(),
            std::env::var("TERM").ok().as_deref(),
            std::io::stdout().is_terminal(),
            std::io::stderr().is_terminal(),
        )
    }
}

/// In plain and JSON modes a running task speaks at most this often.
pub const CALM_EVERY: Duration = Duration::from_secs(5);
/// Progress events in JSON mode are spaced at least this far apart.
const JSON_EVERY: Duration = Duration::from_millis(250);

const SHOW_CURSOR: &str = "\x1b[?25h";
const HIDE_CURSOR: &str = "\x1b[?25l";

/// How many rows the live region has drawn, so Ctrl-C can wipe them.
static DRAWN: AtomicUsize = AtomicUsize::new(0);
static HANDLER: AtomicBool = AtomicBool::new(false);

fn up_and_clear(rows: usize) -> String {
    if rows == 0 {
        String::new()
    } else {
        format!("\x1b[{rows}A\r\x1b[J")
    }
}

/// Wipe the live region and give the cursor back.
fn restore_terminal() {
    let n = DRAWN.swap(0, Ordering::SeqCst);
    let mut s = up_and_clear(n);
    s.push_str(SHOW_CURSOR);
    let mut err = std::io::stderr();
    let _ = err.write_all(s.as_bytes());
    let _ = err.flush();
}

/// On Ctrl-C, stop the animation, wipe the half-drawn rows, restore the
/// cursor and leave with the usual status for an interrupt. Returns whether
/// the handler is in place; without one the cursor is never hidden.
fn install_interrupt_handler() -> bool {
    if HANDLER.load(Ordering::SeqCst) {
        return true;
    }
    let Ok(handle) = tokio::runtime::Handle::try_current() else {
        return false;
    };
    if HANDLER.swap(true, Ordering::SeqCst) {
        return true;
    }
    handle.spawn(async {
        if tokio::signal::ctrl_c().await.is_ok() {
            restore_terminal();
            std::process::exit(130);
        }
    });
    true
}

fn locale_is_utf8() -> bool {
    if std::env::var("TERM").is_ok_and(|t| t == "linux") {
        return false;
    }
    ["LC_ALL", "LC_CTYPE", "LANG"]
        .iter()
        .filter_map(|k| std::env::var(k).ok())
        .find(|v| !v.is_empty())
        .is_some_and(|v| {
            let v = v.to_ascii_lowercase();
            v.contains("utf-8") || v.contains("utf8")
        })
}

/// Whether to draw with ASCII only: a console that cannot show more.
pub fn ascii_only() -> bool {
    !locale_is_utf8()
}

fn terminal_size() -> (usize, usize) {
    if let Some((rows, cols)) = console::Term::stderr().size_checked() {
        return (cols as usize, rows as usize);
    }
    let cols = std::env::var("COLUMNS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(80);
    (cols, 24)
}

fn tone_code(t: Tone) -> &'static str {
    use crate::output::colors;
    match t {
        Tone::Ok => colors::ok(),
        Tone::Bad => colors::bad(),
        Tone::Accent => colors::accent(),
        Tone::Muted => "\x1b[38;5;247m",
        Tone::Plain => "",
    }
}

/// The state of what is shown and where it is written. Every call takes the
/// time as the length of time since the run began, which keeps the rates, the
/// calm lines and the tests free of the clock.
pub struct Engine {
    mode: Mode,
    out: Box<dyn Write + Send>,
    pub(crate) board: Board,
    size: Option<(usize, usize)>,
    color: bool,
    ascii: bool,
    frame: usize,
    drawn: usize,
    hidden: bool,
    hide_cursor: bool,
    paused: bool,
    real: bool,
    last_emit: HashMap<u64, Duration>,
    pub(crate) ticker: bool,
    live_checked: bool,
}

/// Steps share the key space of tasks in the calm-rate table.
const STEP_KEY: u64 = 1 << 40;

impl Engine {
    /// An engine writing to `out`, with no colour and ASCII only.
    pub fn new(mode: Mode, out: Box<dyn Write + Send>) -> Self {
        Self {
            mode,
            out,
            board: Board::new(),
            size: None,
            color: false,
            ascii: true,
            frame: 0,
            drawn: 0,
            hidden: false,
            hide_cursor: true,
            paused: false,
            real: false,
            last_emit: HashMap::new(),
            ticker: false,
            live_checked: false,
        }
    }

    /// The engine for this process: standard error, with the terminal's own size and colour.
    pub fn terminal(mode: Mode) -> Self {
        let mut e = Self::new(mode, Box::new(std::io::stderr()));
        e.real = true;
        e.color = mode == Mode::Tty && crate::output::colors::enabled_stderr();
        e.ascii = !locale_is_utf8();
        e
    }

    /// Fix the terminal size (columns, rows) instead of asking the terminal.
    pub fn with_size(mut self, cols: usize, rows: usize) -> Self {
        self.size = Some((cols, rows));
        self
    }

    #[cfg(test)]
    pub(crate) fn with_size_for_test(self) -> Self {
        self.with_size(80, 24)
    }

    pub fn mode(&self) -> Mode {
        self.mode
    }

    /// Whether this engine writes to the real terminal stream.
    pub(crate) fn is_real(&self) -> bool {
        self.real
    }

    /// Whether nothing is shown, so a ticker has nothing to do.
    pub fn is_idle(&self) -> bool {
        self.board.is_empty()
    }

    /// Called once when something first becomes visible: puts the Ctrl-C
    /// handler in place before the cursor is hidden.
    pub(crate) fn go_live(&mut self) {
        if self.live_checked {
            return;
        }
        self.live_checked = true;
        if self.real && self.mode == Mode::Tty {
            self.hide_cursor = install_interrupt_handler();
        }
    }

    fn write(&mut self, s: &str) {
        if s.is_empty() {
            return;
        }
        let _ = self.out.write_all(s.as_bytes());
        let _ = self.out.flush();
    }

    fn line(&mut self, text: &str) {
        let mut s = String::with_capacity(text.len() + 1);
        s.push_str(text);
        s.push('\n');
        self.write(&s);
    }

    fn set_drawn(&mut self, n: usize) {
        self.drawn = n;
        if self.real {
            DRAWN.store(n, Ordering::SeqCst);
        }
    }

    fn json(
        &mut self,
        task: &str,
        state: &str,
        done: Option<u64>,
        total: Option<u64>,
        unit: Option<&str>,
        message: &str,
        elapsed: Duration,
    ) {
        let v = json!({
            "task": task,
            "state": state,
            "done": done,
            "total": total,
            "unit": unit,
            "message": message,
            "elapsed_ms": elapsed.as_millis() as u64,
        });
        self.line(&v.to_string());
    }

    fn json_task(&mut self, t: &Task, state: &str, message: &str) {
        let unit = t.kind.unit().map(str::to_string);
        self.json(
            &t.name.clone(),
            state,
            Some(t.done),
            t.total,
            unit.as_deref(),
            message,
            t.elapsed,
        );
    }

    // ---- drawing -----------------------------------------------------

    fn paint(&self, r: &Row) -> String {
        if self.color && r.tone != Tone::Plain {
            let reset = crate::output::colors::reset();
            format!("{}{}{}", tone_code(r.tone), r.text, reset)
        } else {
            r.text.clone()
        }
    }

    fn draw(&mut self, now: Duration) {
        if self.mode != Mode::Tty || self.paused {
            return;
        }
        let (cols, height) = self.size.unwrap_or_else(terminal_size);
        let width = cols.saturating_sub(1).max(10);
        self.board.touch(now);
        let mut rows = rows::render(
            &self.board,
            &Opts {
                width,
                frame: self.frame,
                ascii: self.ascii,
                now,
            },
        );
        let fit = height.saturating_sub(2).max(1);
        if rows.len() > fit {
            let extra = rows.len() - fit;
            rows.drain(0..extra);
        }
        let mut buf = up_and_clear(self.drawn);
        if !rows.is_empty() && self.hide_cursor && !self.hidden {
            buf.push_str(HIDE_CURSOR);
            self.hidden = true;
        }
        for r in &rows {
            buf.push_str(&self.paint(r));
            buf.push('\n');
        }
        if rows.is_empty() && self.hidden {
            buf.push_str(SHOW_CURSOR);
            self.hidden = false;
        }
        let n = rows.len();
        self.write(&buf);
        self.set_drawn(n);
    }

    /// Wipe the live region, and give the cursor back when nothing is left.
    fn wipe(&mut self) -> String {
        let s = up_and_clear(self.drawn);
        self.set_drawn(0);
        s
    }

    /// Print a line that stays, above the live region.
    pub fn print_above(&mut self, text: &str, now: Duration) {
        match self.mode {
            Mode::Tty => {
                let mut buf = self.wipe();
                buf.push_str(text);
                buf.push('\n');
                self.write(&buf);
                self.draw(now);
            }
            Mode::Plain => self.line(text),
            Mode::Json => {}
        }
    }

    /// Hide the live region while something else uses the terminal.
    pub fn pause(&mut self) {
        if self.mode == Mode::Tty {
            let mut buf = self.wipe();
            if self.hidden {
                buf.push_str(SHOW_CURSOR);
                self.hidden = false;
            }
            self.write(&buf);
        }
        self.paused = true;
    }

    pub fn resume(&mut self, now: Duration) {
        self.paused = false;
        self.draw(now);
    }

    // ---- steps -------------------------------------------------------

    /// Show a checklist. One that is still showing is finished first.
    pub fn start_steps(&mut self, labels: &[&str], now: Duration) {
        if !self.board.steps.is_empty() {
            self.finish_steps(now);
        }
        self.board.set_steps(labels);
        self.draw(now);
    }

    fn step_opts(&self, now: Duration) -> Opts {
        Opts {
            width: usize::MAX,
            frame: self.frame,
            ascii: self.ascii,
            now,
        }
    }

    /// Move a step along. A move the step's state does not allow is ignored.
    /// `via_task` says a task is reporting the move itself.
    pub fn step(
        &mut self,
        i: usize,
        next: StepState,
        detail: Option<String>,
        now: Duration,
        via_task: bool,
    ) -> bool {
        // A step that is over in an instant need not announce that it began.
        if next == StepState::Done
            && self
                .board
                .steps
                .get(i)
                .is_some_and(|s| s.state == StepState::Pending)
        {
            self.board.step_to(i, StepState::Running, None, now);
        }
        if !self.board.step_to(i, next, detail.clone(), now) {
            return false;
        }
        if !via_task {
            let step = self.board.steps[i].clone();
            match self.mode {
                Mode::Plain => {
                    // No spinner in a log: a running step is just announced.
                    let text = rows::step_text(&step, true, &self.step_opts(now));
                    self.line(text.trim_start());
                    self.last_emit.insert(STEP_KEY + i as u64, now);
                }
                Mode::Json => {
                    let elapsed = step.elapsed(now).unwrap_or_default();
                    self.json(
                        &step.label,
                        next.as_str(),
                        None,
                        None,
                        None,
                        detail.as_deref().unwrap_or(""),
                        elapsed,
                    );
                    self.last_emit.insert(STEP_KEY + i as u64, now);
                }
                Mode::Tty => {
                    if next == StepState::Failed {
                        let why = detail
                            .as_deref()
                            .map(|d| format!(": {d}"))
                            .unwrap_or_default();
                        self.print_above(&format!("[!] {}: failed{why}", step.label), now);
                        return true;
                    }
                }
            }
        }
        self.draw(now);
        true
    }

    /// Take the checklist off the screen. In a terminal the finished list
    /// stays as it stands; a step still running is marked as stopped.
    pub fn finish_steps(&mut self, now: Duration) {
        for i in 0..self.board.steps.len() {
            if self.board.steps[i].state == StepState::Running {
                self.step(
                    i,
                    StepState::Failed,
                    Some("stopped before it finished".into()),
                    now,
                    false,
                );
            }
        }
        if self.mode == Mode::Tty && !self.paused && !self.board.steps.is_empty() {
            let o = Opts {
                width: self
                    .size
                    .unwrap_or_else(terminal_size)
                    .0
                    .saturating_sub(1)
                    .max(10),
                frame: self.frame,
                ascii: self.ascii,
                now,
            };
            let mut keep = Board::new();
            keep.steps = self.board.steps.clone();
            let rows = rows::render(&keep, &o);
            let mut buf = self.wipe();
            for r in &rows {
                buf.push_str(&self.paint(r));
                buf.push('\n');
            }
            self.write(&buf);
        }
        self.board.steps.clear();
        self.board.tasks.retain(|t| t.step.is_none());
        self.draw(now);
    }

    // ---- tasks -------------------------------------------------------

    pub fn start_task(
        &mut self,
        name: &str,
        kind: Kind,
        total: Option<u64>,
        step: Option<usize>,
        now: Duration,
    ) -> u64 {
        let step = step.filter(|i| *i < self.board.steps.len());
        if let Some(i) = step {
            self.step(i, StepState::Running, None, now, true);
        }
        let id = self.board.add_task(name, kind, total, step, now);
        self.last_emit.insert(id, now);
        match self.mode {
            Mode::Plain => {
                let size = match (&self.board.tasks.last().map(|t| t.kind.clone()), total) {
                    (Some(Kind::Bytes), Some(t)) => format!(", {}", fmt::bytes(t)),
                    (Some(Kind::Count(u)), Some(t)) => format!(", {} {u}", fmt::count(t)),
                    _ => String::new(),
                };
                self.line(&format!("{name}: started{size}"));
            }
            Mode::Json => {
                if let Some(t) = self.board.tasks.last().cloned() {
                    self.json_task(&t, "running", "");
                }
            }
            Mode::Tty => {}
        }
        self.draw(now);
        id
    }

    pub fn update_task(&mut self, id: u64, done: u64, now: Duration) {
        let Some(t) = self.board.task_mut(id) else {
            return;
        };
        t.update(done, now);
        if self.mode == Mode::Json {
            let due = self
                .last_emit
                .get(&id)
                .is_none_or(|at| now.saturating_sub(*at) >= JSON_EVERY);
            if due {
                self.emit_json_running(id, now);
            }
        }
    }

    pub fn set_total(&mut self, id: u64, total: Option<u64>) {
        if let Some(t) = self.board.task_mut(id) {
            t.total = total;
        }
    }

    pub fn set_message(&mut self, id: u64, message: &str) {
        if let Some(t) = self.board.task_mut(id) {
            t.message = message.to_string();
        }
    }

    pub fn task_done(&self, id: u64) -> u64 {
        self.board
            .tasks
            .iter()
            .find(|t| t.id == id)
            .map_or(0, |t| t.done)
    }

    fn emit_json_running(&mut self, id: u64, now: Duration) {
        if let Some(t) = self.board.tasks.iter().find(|t| t.id == id).cloned() {
            let msg = t.message.clone();
            self.json_task(&t, "running", &msg);
            self.last_emit.insert(id, now);
        }
    }

    /// End a task well. `text` replaces the default result in the summary.
    pub fn finish_task(&mut self, id: u64, text: Option<&str>, now: Duration) {
        let Some(mut t) = self.board.remove_task(id) else {
            return;
        };
        t.touch(now);
        t.state = super::model::TaskState::Done;
        self.last_emit.remove(&id);
        let took = fmt::duration(t.elapsed);
        let summary = match text {
            Some(x) => format!("{}: {x} ({took})", t.name),
            None => t.summary(),
        };
        let detail = text.map(str::to_string).unwrap_or_else(|| t.detail());
        if let Some(i) = t.step {
            self.board.step_to(
                i,
                StepState::Done,
                Some(detail.clone()).filter(|d| !d.is_empty()),
                now,
            );
        }
        match self.mode {
            Mode::Plain => {
                let driven = t.step.and_then(|i| self.board.steps.get(i).cloned());
                match driven {
                    Some(st) => {
                        let line = rows::step_text(&st, true, &self.step_opts(now));
                        self.line(line.trim_start());
                    }
                    None => self.line(&summary),
                }
            }
            Mode::Json => self.json_task(&t, "done", text.unwrap_or("")),
            Mode::Tty => {
                if t.step.is_none() {
                    self.print_above(&format!("[x] {summary}"), now);
                    return;
                }
            }
        }
        self.draw(now);
    }

    /// End a task with no closing line, for a wait the surrounding text already
    /// reports. Programs reading JSON still get the event.
    pub fn dismiss_task(&mut self, id: u64, now: Duration) {
        let Some(mut t) = self.board.remove_task(id) else {
            return;
        };
        t.touch(now);
        self.last_emit.remove(&id);
        if let Some(i) = t.step {
            self.board.step_to(i, StepState::Done, None, now);
        }
        if self.mode == Mode::Json {
            self.json_task(&t, "done", "");
        }
        self.draw(now);
    }

    /// End a task badly. The error is printed whole on a line of its own.
    pub fn fail_task(&mut self, id: u64, error: &str, now: Duration) {
        let Some(mut t) = self.board.remove_task(id) else {
            return;
        };
        t.touch(now);
        t.state = super::model::TaskState::Failed;
        t.error = Some(error.to_string());
        self.last_emit.remove(&id);
        if let Some(i) = t.step {
            self.board
                .step_to(i, StepState::Failed, Some(error.to_string()), now);
        }
        let text = format!(
            "{}: failed after {}: {error}",
            t.name,
            fmt::duration(t.elapsed)
        );
        match self.mode {
            Mode::Plain => self.line(&text),
            Mode::Json => self.json_task(&t, "failed", error),
            Mode::Tty => {
                self.print_above(&format!("[!] {text}"), now);
                return;
            }
        }
        self.draw(now);
    }

    // ---- time --------------------------------------------------------

    /// Advance the clock: redraw a terminal, and let a quiet log say once in a
    /// while that work is still going on.
    pub fn tick(&mut self, now: Duration) {
        self.frame = self.frame.wrapping_add(1);
        self.board.touch(now);
        match self.mode {
            Mode::Tty => self.draw(now),
            Mode::Plain | Mode::Json => self.calm(now),
        }
    }

    fn calm(&mut self, now: Duration) {
        let due = |last: &HashMap<u64, Duration>, key: u64| {
            last.get(&key)
                .is_none_or(|at| now.saturating_sub(*at) >= CALM_EVERY)
        };
        let ids: Vec<u64> = self.board.tasks.iter().map(|t| t.id).collect();
        for id in ids {
            if !due(&self.last_emit, id) {
                continue;
            }
            self.last_emit.insert(id, now);
            let Some(t) = self.board.tasks.iter().find(|t| t.id == id).cloned() else {
                continue;
            };
            if self.mode == Mode::Plain {
                self.line(&t.status_line());
            } else {
                let msg = t.message.clone();
                self.json_task(&t, "running", &msg);
            }
        }
        for i in 0..self.board.steps.len() {
            let s = self.board.steps[i].clone();
            let driven = self.board.tasks.iter().any(|t| t.step == Some(i));
            if s.state != StepState::Running || driven || !due(&self.last_emit, STEP_KEY + i as u64)
            {
                continue;
            }
            self.last_emit.insert(STEP_KEY + i as u64, now);
            let took = s.elapsed(now).unwrap_or_default();
            if self.mode == Mode::Plain {
                self.line(&format!(
                    "{}: still working, {} elapsed",
                    s.label,
                    fmt::duration(took)
                ));
            } else {
                self.json(&s.label, "running", None, None, None, "", took);
            }
        }
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        if self.mode == Mode::Tty {
            let mut buf = self.wipe();
            if self.hidden {
                buf.push_str(SHOW_CURSOR);
            }
            self.write(&buf);
        }
    }
}

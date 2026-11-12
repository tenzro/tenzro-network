//! Progress and activity indicators for the command line and the full-screen
//! screens.
//!
//! One task model ([`model`]) feeds every surface. In a terminal it draws a
//! live checklist, a byte bar with speed and time left, a count bar and a
//! spinner with a clock. Where output is not a terminal (a pipe, CI, a serial
//! console, `--no-color`, `NO_COLOR`, `TERM=dumb`) it writes plain lines, at
//! most one per task every five seconds plus a start and a finish line. With
//! `--json`, or `TENZRO_PROGRESS=json`, it writes one JSON object per line.
//! Progress goes to standard error so a command's own output stays clean.
//!
//! ```ignore
//! let p = progress::global();
//! let steps = p.steps(&["Download the model", "Start the node"]);
//! let dl = steps.bytes(0, "Model download", Some(total));
//! dl.set(bytes_so_far);
//! dl.finish();
//! let wait = steps.wait(1, "Starting the node", "waiting for the first block");
//! wait.finish_with("Node is running");
//! ```

pub mod engine;
pub mod fmt;
pub mod model;
pub mod rows;
pub mod widget;

use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant};

pub use engine::{Engine, MODE_ENV, Mode, mode_from};
pub use model::{Board, Kind, StepState};

struct Shared {
    engine: Mutex<Engine>,
    clock: Instant,
}

/// A handle on the run's progress display. Cheap to clone.
#[derive(Clone)]
pub struct Progress {
    sh: Arc<Shared>,
}

/// The progress display for this process, chosen from where output goes.
pub fn global() -> &'static Progress {
    static GLOBAL: OnceLock<Progress> = OnceLock::new();
    GLOBAL.get_or_init(Progress::auto)
}

impl Progress {
    pub fn new(engine: Engine) -> Self {
        Self {
            sh: Arc::new(Shared {
                engine: Mutex::new(engine),
                clock: Instant::now(),
            }),
        }
    }

    /// A display that picks its mode from the arguments, environment and streams.
    pub fn auto() -> Self {
        Self::new(Engine::terminal(Mode::detect()))
    }

    /// A display that never redraws: lines at a calm rate, or JSON. For a
    /// command that shares the terminal with another program's output.
    pub fn calm() -> &'static Progress {
        static CALM: OnceLock<Progress> = OnceLock::new();
        CALM.get_or_init(|| {
            let mode = if Mode::detect() == Mode::Json {
                Mode::Json
            } else {
                Mode::Plain
            };
            Progress::new(Engine::terminal(mode))
        })
    }

    pub fn mode(&self) -> Mode {
        self.lock().mode()
    }

    fn lock(&self) -> MutexGuard<'_, Engine> {
        self.sh.engine.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn with<R>(&self, f: impl FnOnce(&mut Engine, Duration) -> R) -> R {
        let mut g = self.lock();
        f(&mut g, self.sh.clock.elapsed())
    }

    /// Redraw, or write a calm line if one is due. The background ticker calls
    /// this; call it directly only when no ticker runs.
    pub fn tick(&self) {
        self.with(|e, now| e.tick(now));
    }

    fn start_ticker(&self) {
        let mut g = self.lock();
        g.go_live();
        if !g.is_real() || g.ticker {
            return;
        }
        let every = if g.mode() == Mode::Tty {
            Duration::from_millis(100)
        } else {
            Duration::from_secs(1)
        };
        g.ticker = true;
        let weak = Arc::downgrade(&self.sh);
        let spawned = std::thread::Builder::new()
            .name("progress".into())
            .spawn(move || {
                loop {
                    std::thread::sleep(every);
                    let Some(sh) = weak.upgrade() else { break };
                    let mut e = sh.engine.lock().unwrap_or_else(|e| e.into_inner());
                    e.tick(sh.clock.elapsed());
                    if e.is_idle() {
                        e.ticker = false;
                        break;
                    }
                }
            });
        if spawned.is_err() {
            g.ticker = false;
        }
    }

    /// Show a checklist of `labels`, all pending.
    pub fn steps(&self, labels: &[&str]) -> Steps {
        self.with(|e, now| e.start_steps(labels, now));
        self.start_ticker();
        Steps {
            p: self.clone(),
            ended: false,
        }
    }

    /// A byte transfer. `total` is the size when it is known.
    pub fn bytes(&self, name: &str, total: Option<u64>) -> Task {
        self.begin(name, Kind::Bytes, total, None)
    }

    /// A count of items such as `blocks` or `files`.
    pub fn count(&self, name: &str, total: Option<u64>, unit: &str) -> Task {
        self.begin(name, Kind::Count(unit.to_string()), total, None)
    }

    /// A wait with a spinner, a clock and a short status line.
    pub fn wait(&self, name: &str, message: &str) -> Task {
        let t = self.begin(name, Kind::Wait, None, None);
        t.message(message);
        t
    }

    fn begin(&self, name: &str, kind: Kind, total: Option<u64>, step: Option<usize>) -> Task {
        let id = self.with(|e, now| e.start_task(name, kind, total, step, now));
        self.start_ticker();
        Task {
            p: self.clone(),
            id,
            ended: false,
        }
    }

    /// Print a line that stays, above anything drawn.
    pub fn println(&self, text: &str) {
        self.with(|e, now| e.print_above(text, now));
    }

    /// Clear what is drawn while `f` uses the terminal (a prompt, say), and
    /// draw it again afterwards.
    pub fn suspend<R>(&self, f: impl FnOnce() -> R) -> R {
        self.lock().pause();
        let out = f();
        self.with(|e, now| e.resume(now));
        out
    }
}

/// A checklist on screen. It ends when [`Steps::finish`] is called or it is
/// dropped; a step still running then shows as stopped.
pub struct Steps {
    p: Progress,
    ended: bool,
}

impl Steps {
    fn go(&self, i: usize, next: StepState, detail: Option<String>) {
        self.p.with(|e, now| {
            e.step(i, next, detail, now, false);
        });
    }

    pub fn start(&self, i: usize) {
        self.go(i, StepState::Running, None);
    }

    pub fn done(&self, i: usize) {
        self.go(i, StepState::Done, None);
    }

    /// End a step well, with a few words on the result.
    pub fn done_with(&self, i: usize, detail: &str) {
        self.go(i, StepState::Done, Some(detail.to_string()));
    }

    pub fn skip(&self, i: usize, why: &str) {
        self.go(i, StepState::Skipped, Some(why.to_string()));
    }

    pub fn fail(&self, i: usize, why: &str) {
        self.go(i, StepState::Failed, Some(why.to_string()));
    }

    /// A byte transfer that is step `i`; the step runs and ends with it.
    pub fn bytes(&self, i: usize, name: &str, total: Option<u64>) -> Task {
        self.p.begin(name, Kind::Bytes, total, Some(i))
    }

    pub fn count(&self, i: usize, name: &str, total: Option<u64>, unit: &str) -> Task {
        self.p
            .begin(name, Kind::Count(unit.to_string()), total, Some(i))
    }

    pub fn wait(&self, i: usize, name: &str, message: &str) -> Task {
        let t = self.p.begin(name, Kind::Wait, None, Some(i));
        t.message(message);
        t
    }

    fn end(&mut self) {
        if !self.ended {
            self.ended = true;
            self.p.with(|e, now| e.finish_steps(now));
        }
    }

    /// Take the checklist off the screen, leaving it as it stands.
    pub fn finish(mut self) {
        self.end();
    }
}

impl Drop for Steps {
    fn drop(&mut self) {
        self.end();
    }
}

/// One running activity. End it with [`Task::finish`], [`Task::finish_with`]
/// or [`Task::fail`]; dropped without either, it ends as failed, so an early
/// return with `?` still leaves a clean line.
pub struct Task {
    p: Progress,
    id: u64,
    ended: bool,
}

/// A copy of a task's update calls, for a thread that reports progress while
/// the owner waits.
#[derive(Clone)]
pub struct Reporter {
    p: Progress,
    id: u64,
}

impl Reporter {
    /// Set how much is done.
    pub fn set(&self, done: u64) {
        self.p.with(|e, now| e.update_task(self.id, done, now));
    }

    /// Add to how much is done.
    pub fn inc(&self, by: u64) {
        self.p.with(|e, now| {
            let done = e.task_done(self.id).saturating_add(by);
            e.update_task(self.id, done, now);
        });
    }

    pub fn set_total(&self, total: u64) {
        self.p.with(|e, _| e.set_total(self.id, Some(total)));
    }

    /// Change the short status line.
    pub fn message(&self, text: &str) {
        self.p.with(|e, _| e.set_message(self.id, text));
    }
}

impl Task {
    pub fn reporter(&self) -> Reporter {
        Reporter {
            p: self.p.clone(),
            id: self.id,
        }
    }

    pub fn set(&self, done: u64) {
        self.reporter().set(done);
    }

    pub fn inc(&self, by: u64) {
        self.reporter().inc(by);
    }

    pub fn set_total(&self, total: u64) {
        self.reporter().set_total(total);
    }

    pub fn message(&self, text: &str) {
        self.reporter().message(text);
    }

    /// End well, with the standard summary of size and time.
    pub fn finish(mut self) {
        self.ended = true;
        self.p.with(|e, now| e.finish_task(self.id, None, now));
    }

    /// End well, with `text` in place of the standard result.
    pub fn finish_with(mut self, text: &str) {
        self.ended = true;
        self.p
            .with(|e, now| e.finish_task(self.id, Some(text), now));
    }

    /// End well with no closing line, for a wait that the text around it
    /// already reports.
    pub fn dismiss(mut self) {
        self.ended = true;
        self.p.with(|e, now| e.dismiss_task(self.id, now));
    }

    /// End badly. The error is shown whole on its own line.
    pub fn fail(mut self, error: &str) {
        self.ended = true;
        self.p.with(|e, now| e.fail_task(self.id, error, now));
    }
}

impl Drop for Task {
    fn drop(&mut self) {
        if !self.ended {
            self.p
                .with(|e, now| e.fail_task(self.id, "stopped before it finished", now));
        }
    }
}

#[cfg(test)]
mod tests;

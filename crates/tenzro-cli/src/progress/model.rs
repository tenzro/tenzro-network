//! The task model: plain data and no input or output. The terminal renderer
//! and the full-screen panel both draw from a [`Board`], so the setup wizard
//! and the interactive screens show the same states.

use std::time::Duration;

use super::fmt;

/// Where one step of a multi-step flow stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StepState {
    Pending,
    Running,
    Done,
    Failed,
    Skipped,
}

impl StepState {
    /// The word used in machine output.
    pub fn as_str(self) -> &'static str {
        match self {
            StepState::Pending => "pending",
            StepState::Running => "running",
            StepState::Done => "done",
            StepState::Failed => "failed",
            StepState::Skipped => "skipped",
        }
    }

    /// Whether the step has reached an end state that needs nothing more.
    pub fn is_final(self) -> bool {
        matches!(self, StepState::Done | StepState::Skipped)
    }

    /// Whether a step in this state may move to `next`. A failed step may be
    /// tried again; a finished or skipped one stays as it is.
    pub fn can_become(self, next: StepState) -> bool {
        use StepState::*;
        matches!(
            (self, next),
            (Pending, Running)
                | (Pending, Skipped)
                | (Pending, Failed)
                | (Running, Done)
                | (Running, Failed)
                | (Running, Skipped)
                | (Failed, Running)
        )
    }
}

/// One line of the checklist.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Step {
    pub label: String,
    pub state: StepState,
    /// What to show beside the label once it has ended: a result or a reason.
    pub detail: Option<String>,
    started: Option<Duration>,
    /// How long it ran, once it has ended.
    pub took: Option<Duration>,
}

impl Step {
    fn new(label: &str) -> Self {
        Self {
            label: label.to_string(),
            state: StepState::Pending,
            detail: None,
            started: None,
            took: None,
        }
    }

    /// How long the step has been running, or ran.
    pub fn elapsed(&self, now: Duration) -> Option<Duration> {
        self.took
            .or_else(|| self.started.map(|s| now.saturating_sub(s)))
    }
}

/// What a task counts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Kind {
    /// A byte transfer.
    Bytes,
    /// A number of items, named by the unit (`blocks`, `files`).
    Count(String),
    /// A wait with no measure of progress.
    Wait,
}

impl Kind {
    /// The unit word used in machine output.
    pub fn unit(&self) -> Option<&str> {
        match self {
            Kind::Bytes => Some("bytes"),
            Kind::Count(u) => Some(u),
            Kind::Wait => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskState {
    Running,
    Done,
    Failed,
}

impl TaskState {
    pub fn as_str(self) -> &'static str {
        match self {
            TaskState::Running => "running",
            TaskState::Done => "done",
            TaskState::Failed => "failed",
        }
    }
}

/// One activity: a transfer, a count or a wait.
#[derive(Debug, Clone)]
pub struct Task {
    pub id: u64,
    pub name: String,
    pub kind: Kind,
    pub done: u64,
    pub total: Option<u64>,
    /// The short live status line.
    pub message: String,
    pub state: TaskState,
    pub error: Option<String>,
    /// The checklist step this task drives, if any.
    pub step: Option<usize>,
    pub started: Duration,
    pub elapsed: Duration,
    rate: f64,
    sampled_at: Duration,
    sampled_done: u64,
}

/// A rate is measured over windows at least this long, so one burst does not
/// swing the speed or the time left.
const RATE_WINDOW: Duration = Duration::from_millis(500);

impl Task {
    pub fn new(id: u64, name: &str, kind: Kind, total: Option<u64>, now: Duration) -> Self {
        Self {
            id,
            name: name.to_string(),
            kind,
            done: 0,
            total,
            message: String::new(),
            state: TaskState::Running,
            error: None,
            step: None,
            started: now,
            elapsed: Duration::ZERO,
            rate: 0.0,
            sampled_at: now,
            sampled_done: 0,
        }
    }

    /// Move the clock on without changing the amount done.
    pub fn touch(&mut self, now: Duration) {
        self.elapsed = now.saturating_sub(self.started);
    }

    /// Record the amount done so far.
    pub fn update(&mut self, done: u64, now: Duration) {
        self.done = done;
        self.touch(now);
        let window = now.saturating_sub(self.sampled_at);
        if window >= RATE_WINDOW {
            let moved = done.saturating_sub(self.sampled_done) as f64;
            let instant = moved / window.as_secs_f64();
            self.rate = if self.rate > 0.0 {
                0.7 * self.rate + 0.3 * instant
            } else {
                instant
            };
            self.sampled_at = now;
            self.sampled_done = done;
        }
    }

    /// Items or bytes per second: the recent speed, or the average so far
    /// before one has been measured.
    pub fn rate(&self) -> f64 {
        if self.rate > 0.0 {
            return self.rate;
        }
        let secs = self.elapsed.as_secs_f64();
        if secs >= 1.0 {
            self.done as f64 / secs
        } else {
            0.0
        }
    }

    /// How far along, from 0 to 1, when the total is known.
    pub fn fraction(&self) -> Option<f64> {
        let total = self.total.filter(|t| *t > 0)?;
        Some((self.done as f64 / total as f64).clamp(0.0, 1.0))
    }

    /// The time left at the current speed.
    pub fn eta(&self) -> Option<Duration> {
        let total = self.total?;
        fmt::eta(total.saturating_sub(self.done), self.rate())
    }

    /// The text beside a count: `12,345 / 90,000 blocks`, `1.2 GB / 3.0 GB`.
    pub fn amount(&self) -> String {
        match (&self.kind, self.total) {
            (Kind::Bytes, Some(t)) => format!("{} / {}", fmt::bytes(self.done), fmt::bytes(t)),
            (Kind::Bytes, None) => fmt::bytes(self.done),
            (Kind::Count(u), Some(t)) => {
                format!("{} / {} {u}", fmt::count(self.done), fmt::count(t))
            }
            (Kind::Count(u), None) => format!("{} {u}", fmt::count(self.done)),
            (Kind::Wait, _) => String::new(),
        }
    }

    /// The speed as text, or `None` for a wait.
    pub fn rate_text(&self) -> Option<String> {
        match &self.kind {
            Kind::Bytes => Some(fmt::byte_rate(self.rate())),
            Kind::Count(u) => Some(fmt::item_rate(self.rate(), u)),
            Kind::Wait => None,
        }
    }

    /// What was done, in a few words, without the time.
    pub fn detail(&self) -> String {
        match &self.kind {
            Kind::Bytes => {
                let avg = if self.elapsed.as_secs_f64() >= 1.0 {
                    format!(
                        ", {}",
                        fmt::byte_rate(self.done as f64 / self.elapsed.as_secs_f64())
                    )
                } else {
                    String::new()
                };
                format!("{}{avg}", fmt::bytes(self.done))
            }
            Kind::Count(u) => format!("{} {u}", fmt::count(self.done)),
            Kind::Wait => String::new(),
        }
    }

    /// The closing line: what was done, how much, and how long it took.
    pub fn summary(&self) -> String {
        let took = fmt::duration(self.elapsed);
        match &self.kind {
            Kind::Bytes => {
                let avg = if self.elapsed.as_secs_f64() >= 1.0 {
                    format!(
                        ", {}",
                        fmt::byte_rate(self.done as f64 / self.elapsed.as_secs_f64())
                    )
                } else {
                    String::new()
                };
                format!("{}: {} in {took}{avg}", self.name, fmt::bytes(self.done))
            }
            Kind::Count(u) => format!("{}: {} {u} in {took}", self.name, fmt::count(self.done)),
            Kind::Wait => format!("{}: done in {took}", self.name),
        }
    }

    /// One calm line for a log that cannot redraw.
    pub fn status_line(&self) -> String {
        let mut parts: Vec<String> = Vec::new();
        match (&self.kind, self.fraction()) {
            (Kind::Wait, _) => {}
            (_, Some(_)) => {
                let pct = fmt::percent(self.done, self.total.unwrap_or(0));
                parts.push(format!("{pct}% ({})", self.amount()));
            }
            (_, None) => parts.push(self.amount()),
        }
        if let Some(r) = self.rate_text().filter(|r| r != "-") {
            parts.push(r);
        }
        parts.push(format!("{} elapsed", fmt::duration(self.elapsed)));
        if let Some(e) = self.eta() {
            parts.push(format!("about {} left", fmt::duration(e)));
        }
        if !self.message.is_empty() {
            parts.push(self.message.clone());
        }
        format!("{}: {}", self.name, parts.join(", "))
    }
}

/// Everything in flight: the checklist and the running tasks.
#[derive(Debug, Clone, Default)]
pub struct Board {
    pub steps: Vec<Step>,
    pub tasks: Vec<Task>,
    next_id: u64,
}

impl Board {
    pub fn new() -> Self {
        Self::default()
    }

    /// Replace the checklist with `labels`, all pending.
    pub fn set_steps(&mut self, labels: &[&str]) {
        self.steps = labels.iter().map(|l| Step::new(l)).collect();
    }

    /// Move step `i` to `next`. Returns whether the move was allowed; a move
    /// that is not allowed changes nothing.
    pub fn step_to(
        &mut self,
        i: usize,
        next: StepState,
        detail: Option<String>,
        now: Duration,
    ) -> bool {
        let Some(step) = self.steps.get_mut(i) else {
            return false;
        };
        if !step.state.can_become(next) {
            return false;
        }
        match next {
            StepState::Running => {
                step.started = Some(now);
                step.took = None;
                step.detail = None;
            }
            StepState::Done | StepState::Failed | StepState::Skipped => {
                step.took = step.started.map(|s| now.saturating_sub(s));
                step.detail = detail;
            }
            StepState::Pending => {}
        }
        step.state = next;
        true
    }

    /// Whether every step has ended well or been skipped.
    pub fn steps_complete(&self) -> bool {
        !self.steps.is_empty() && self.steps.iter().all(|s| s.state.is_final())
    }

    pub fn add_task(
        &mut self,
        name: &str,
        kind: Kind,
        total: Option<u64>,
        step: Option<usize>,
        now: Duration,
    ) -> u64 {
        self.next_id += 1;
        let mut t = Task::new(self.next_id, name, kind, total, now);
        t.step = step;
        self.tasks.push(t);
        self.next_id
    }

    pub fn task_mut(&mut self, id: u64) -> Option<&mut Task> {
        self.tasks.iter_mut().find(|t| t.id == id)
    }

    pub fn remove_task(&mut self, id: u64) -> Option<Task> {
        let at = self.tasks.iter().position(|t| t.id == id)?;
        Some(self.tasks.remove(at))
    }

    /// Whether nothing is shown.
    pub fn is_empty(&self) -> bool {
        self.steps.is_empty() && self.tasks.is_empty()
    }

    /// Move every running task's clock on.
    pub fn touch(&mut self, now: Duration) {
        for t in &mut self.tasks {
            t.touch(now);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    #[test]
    fn a_step_runs_then_ends_and_stays_ended() {
        let mut b = Board::new();
        b.set_steps(&["one", "two"]);
        assert!(b.step_to(0, StepState::Running, None, secs(1)));
        assert!(b.step_to(0, StepState::Done, Some("ok".into()), secs(4)));
        assert_eq!(b.steps[0].took, Some(secs(3)));
        assert_eq!(b.steps[0].detail.as_deref(), Some("ok"));
        assert!(!b.step_to(0, StepState::Running, None, secs(5)));
        assert!(!b.step_to(0, StepState::Failed, None, secs(5)));
        assert_eq!(b.steps[0].state, StepState::Done);
    }

    #[test]
    fn a_step_cannot_finish_without_starting() {
        let mut b = Board::new();
        b.set_steps(&["one"]);
        assert!(!b.step_to(0, StepState::Done, None, secs(1)));
        assert_eq!(b.steps[0].state, StepState::Pending);
        assert!(!b.step_to(9, StepState::Running, None, secs(1)));
    }

    #[test]
    fn a_step_can_be_skipped_or_failed_and_retried() {
        let mut b = Board::new();
        b.set_steps(&["a", "b"]);
        assert!(b.step_to(0, StepState::Skipped, Some("not needed".into()), secs(0)));
        assert!(b.step_to(1, StepState::Running, None, secs(0)));
        assert!(b.step_to(1, StepState::Failed, Some("no route".into()), secs(2)));
        assert!(!b.steps_complete());
        assert!(b.step_to(1, StepState::Running, None, secs(3)));
        assert!(b.step_to(1, StepState::Done, None, secs(5)));
        assert!(b.steps_complete());
    }

    #[test]
    fn every_state_has_a_word() {
        let all = [
            StepState::Pending,
            StepState::Running,
            StepState::Done,
            StepState::Failed,
            StepState::Skipped,
        ];
        let words: Vec<_> = all.iter().map(|s| s.as_str()).collect();
        assert_eq!(words, ["pending", "running", "done", "failed", "skipped"]);
    }

    #[test]
    fn the_speed_is_smoothed_and_drives_the_time_left() {
        let mut t = Task::new(1, "Model", Kind::Bytes, Some(1000), secs(0));
        t.update(100, secs(1));
        assert!((t.rate() - 100.0).abs() < 1e-6);
        assert_eq!(t.eta(), Some(secs(9)));
        t.update(900, secs(2));
        assert!(t.rate() > 100.0 && t.rate() < 800.0);
    }

    #[test]
    fn before_a_window_there_is_no_speed() {
        let mut t = Task::new(1, "Model", Kind::Bytes, Some(100), secs(0));
        t.update(10, Duration::from_millis(200));
        assert_eq!(t.rate(), 0.0);
        assert_eq!(t.eta(), None);
    }

    #[test]
    fn fraction_is_clamped_and_needs_a_total() {
        let mut t = Task::new(1, "Blocks", Kind::Count("blocks".into()), None, secs(0));
        assert_eq!(t.fraction(), None);
        t.total = Some(10);
        t.done = 20;
        assert_eq!(t.fraction(), Some(1.0));
    }

    #[test]
    fn the_summary_names_the_size_and_the_time() {
        let mut t = Task::new(1, "Model download", Kind::Bytes, Some(3 << 30), secs(0));
        t.update(3 << 30, secs(72));
        assert_eq!(t.summary(), "Model download: 3.00 GB in 1m 12s, 42.7 MB/s");
        let mut c = Task::new(
            2,
            "Chain sync",
            Kind::Count("blocks".into()),
            Some(5000),
            secs(0),
        );
        c.update(5000, secs(40));
        assert_eq!(c.summary(), "Chain sync: 5,000 blocks in 40s");
        let mut w = Task::new(3, "Node start", Kind::Wait, None, secs(0));
        w.touch(secs(12));
        assert_eq!(w.summary(), "Node start: done in 12s");
    }

    #[test]
    fn the_calm_line_carries_amount_speed_and_time_left() {
        let mut t = Task::new(1, "Model", Kind::Bytes, Some(1 << 20), secs(0));
        t.update(1 << 19, secs(10));
        let l = t.status_line();
        assert!(l.starts_with("Model: 50% (512 KB / 1.00 MB)"), "{l}");
        assert!(l.contains("10s elapsed"), "{l}");
        assert!(l.contains("left"), "{l}");
    }
}

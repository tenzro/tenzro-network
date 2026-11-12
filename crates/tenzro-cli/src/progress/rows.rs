//! Turns a [`Board`] into rows of text. The terminal renderer and the
//! full-screen panel both use these rows, so a step or a transfer reads the
//! same in the setup wizard and in the interactive screens.

use std::time::Duration;

use super::fmt;
use super::model::{Board, Kind, Step, StepState, Task};

/// How a row should be coloured. The renderer decides what each tone looks
/// like, or ignores them when colour is off.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Tone {
    Plain,
    Ok,
    Bad,
    Accent,
    Muted,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    pub text: String,
    pub tone: Tone,
}

/// What a draw needs besides the board.
#[derive(Debug, Clone, Copy)]
pub struct Opts {
    /// The most characters a row may use.
    pub width: usize,
    /// Which frame of the spinner to show.
    pub frame: usize,
    /// Use only ASCII characters.
    pub ascii: bool,
    /// The clock the running steps are measured against.
    pub now: Duration,
}

const SPIN_UNICODE: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
const SPIN_ASCII: [&str; 4] = ["|", "/", "-", "\\"];

/// One frame of the spinner.
pub fn spinner(frame: usize, ascii: bool) -> &'static str {
    if ascii {
        SPIN_ASCII[frame % SPIN_ASCII.len()]
    } else {
        SPIN_UNICODE[frame % SPIN_UNICODE.len()]
    }
}

/// The checklist mark for a state.
pub fn mark(state: StepState) -> &'static str {
    match state {
        StepState::Pending => "[ ]",
        StepState::Running => "[>]",
        StepState::Done => "[x]",
        StepState::Failed => "[!]",
        StepState::Skipped => "[-]",
    }
}

/// The widest bar drawn, and the narrowest worth drawing.
const BAR_MAX: usize = 30;
const BAR_MIN: usize = 10;

fn len(s: &str) -> usize {
    s.chars().count()
}

/// The row for one running task, `indent` columns in. Parts drop out from the
/// right as the width shrinks, so the row never wraps.
pub fn task_row(t: &Task, width: usize, frame: usize, ascii: bool, indent: usize) -> String {
    let spin = spinner(frame, ascii);
    let mut head = format!("{}{spin} {}", " ".repeat(indent), t.name);
    if !t.message.is_empty() {
        head.push_str(" - ");
        head.push_str(&t.message);
    }
    if matches!(t.kind, Kind::Wait) {
        let tail = fmt::duration(t.elapsed);
        let room = width.saturating_sub(len(&tail) + 2);
        let line = format!("{}  {tail}", fmt::clip(&head, room.max(4)));
        return fmt::clip(&line, width);
    }

    let pct = t
        .fraction()
        .map(|_| format!("{}%", fmt::percent(t.done, t.total.unwrap_or(0))));
    let amount = t.amount();
    let rate = t.rate_text().filter(|r| r != "-");
    let elapsed = fmt::duration(t.elapsed);
    let eta = t.eta().map(|e| format!("ETA {}", fmt::duration(e)));
    let pick = |parts: &[Option<&String>]| -> String {
        parts
            .iter()
            .flatten()
            .map(|s| s.as_str())
            .collect::<Vec<_>>()
            .join("  ")
    };
    let (p, r, e) = (pct.as_ref(), rate.as_ref(), eta.as_ref());
    let a = Some(&amount);
    let el = Some(&elapsed);
    let tails = [
        pick(&[p, a, r, el, e]),
        pick(&[p, a, r, e]),
        pick(&[p, a, r]),
        pick(&[p, a]),
        pick(&[p]),
    ];

    // A head longer than a third of a narrow row is cut so the figures stay.
    let head_cap = if width < 70 {
        (width * 2 / 5).max(12)
    } else {
        width
    };
    let head = fmt::clip(&head, head_cap);

    if t.fraction().is_some() {
        for tail in &tails {
            let fixed = len(&head) + 2 + 2 + len(tail);
            if width >= fixed + BAR_MIN {
                let bar_w = (width - fixed).min(BAR_MAX);
                let bar = fmt::bar(bar_w, t.done, t.total.unwrap_or(0));
                return format!("{head}  {bar}  {tail}");
            }
        }
    }
    for tail in &tails {
        if tail.is_empty() {
            continue;
        }
        let line = format!("{head}  {tail}");
        if len(&line) <= width {
            return line;
        }
    }
    fmt::clip(&head, width)
}

/// The text of one checklist line. `driven` says a task under the step shows
/// the live detail, so the step itself needs no spinner.
pub fn step_text(s: &Step, driven: bool, o: &Opts) -> String {
    let mut line = format!(" {} {}", mark(s.state), s.label);
    let took = s
        .elapsed(o.now)
        .filter(|d| d.as_secs() >= 1)
        .map(fmt::duration);
    match s.state {
        StepState::Pending => {}
        StepState::Running => {
            if !driven {
                line.push_str(&format!(
                    "  {} {}",
                    spinner(o.frame, o.ascii),
                    took.unwrap_or_else(|| "0s".into())
                ));
            }
        }
        StepState::Done => {
            if let Some(d) = &s.detail {
                line.push_str(&format!("  {d}"));
            }
            if let Some(t) = took {
                line.push_str(&format!("  ({t})"));
            }
        }
        StepState::Failed => {
            line.push_str("  failed");
            if let Some(d) = &s.detail {
                line.push_str(&format!(": {d}"));
            }
        }
        StepState::Skipped => {
            line.push_str("  skipped");
            if let Some(d) = &s.detail {
                line.push_str(&format!(": {d}"));
            }
        }
    }
    line
}

/// The rows for the whole board: the checklist, each running task under the
/// step it drives, then tasks that belong to no step.
pub fn render(board: &Board, o: &Opts) -> Vec<Row> {
    let mut rows = Vec::new();
    for (i, s) in board.steps.iter().enumerate() {
        let tone = match s.state {
            StepState::Pending | StepState::Skipped => Tone::Muted,
            StepState::Running => Tone::Accent,
            StepState::Done => Tone::Ok,
            StepState::Failed => Tone::Bad,
        };
        let driven = board.tasks.iter().any(|t| t.step == Some(i));
        rows.push(Row {
            text: fmt::clip(&step_text(s, driven, o), o.width),
            tone,
        });
        for t in board.tasks.iter().filter(|t| t.step == Some(i)) {
            rows.push(Row {
                text: task_row(t, o.width, o.frame, o.ascii, 6),
                tone: Tone::Plain,
            });
        }
    }
    for t in board
        .tasks
        .iter()
        .filter(|t| t.step.is_none_or(|i| i >= board.steps.len()))
    {
        rows.push(Row {
            text: task_row(t, o.width, o.frame, o.ascii, 0),
            tone: Tone::Accent,
        });
    }
    rows
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::progress::model::{Board, Kind};

    fn secs(n: u64) -> Duration {
        Duration::from_secs(n)
    }

    fn opts(width: usize) -> Opts {
        Opts {
            width,
            frame: 0,
            ascii: true,
            now: secs(30),
        }
    }

    fn download(done: u64) -> Task {
        let mut t = Task::new(1, "Downloading model", Kind::Bytes, Some(3 << 30), secs(0));
        t.update(done, secs(20));
        t
    }

    #[test]
    fn a_transfer_row_shows_bar_sizes_speed_time_and_eta() {
        let row = task_row(&download(1 << 30), 120, 0, true, 0);
        assert!(row.contains("33%"), "{row}");
        assert!(row.contains("1.00 GB / 3.00 GB"), "{row}");
        assert!(row.contains("/s"), "{row}");
        assert!(row.contains("20s"), "{row}");
        assert!(row.contains("ETA"), "{row}");
        assert!(row.contains("[="), "{row}");
    }

    #[test]
    fn no_row_is_wider_than_the_width_at_any_width() {
        for w in [10usize, 20, 30, 40, 60, 80, 120] {
            let rows = [
                task_row(&download(1 << 30), w, 3, true, 0),
                task_row(&download(1 << 30), w, 3, true, 6),
                {
                    let mut t = Task::new(
                        2,
                        "Waiting for the first block from the network",
                        Kind::Wait,
                        None,
                        secs(0),
                    );
                    t.message = "3 peers found, still looking".into();
                    t.touch(secs(75));
                    task_row(&t, w, 0, true, 0)
                },
            ];
            for r in rows {
                assert!(len(&r) <= w, "{w}: {r:?}");
            }
        }
    }

    #[test]
    fn narrow_rows_keep_the_percent_before_the_detail() {
        let row = task_row(&download(1 << 30), 40, 0, true, 0);
        assert!(row.contains("33%"), "{row}");
        assert!(!row.contains("ETA"), "{row}");
    }

    #[test]
    fn a_wait_shows_the_elapsed_time_and_the_live_status() {
        let mut t = Task::new(1, "Starting the node", Kind::Wait, None, secs(0));
        t.message = "waiting for the first block".into();
        t.touch(secs(65));
        let row = task_row(&t, 80, 1, true, 0);
        assert_eq!(
            row,
            "/ Starting the node - waiting for the first block  1m 05s"
        );
    }

    #[test]
    fn a_count_without_a_total_has_no_bar() {
        let mut t = Task::new(
            1,
            "Verifying files",
            Kind::Count("files".into()),
            None,
            secs(0),
        );
        t.update(1200, secs(10));
        let row = task_row(&t, 80, 0, true, 0);
        assert!(row.contains("1,200 files"), "{row}");
        assert!(!row.contains('['), "{row}");
    }

    #[test]
    fn the_checklist_marks_each_state_and_nests_the_running_task() {
        let mut b = Board::new();
        b.set_steps(&[
            "Create the wallet",
            "Download the model",
            "Start the node",
            "Register",
        ]);
        b.step_to(0, StepState::Running, None, secs(0));
        b.step_to(0, StepState::Done, Some("0xab12".into()), secs(4));
        b.step_to(1, StepState::Running, None, secs(4));
        b.step_to(
            3,
            StepState::Skipped,
            Some("not needed here".into()),
            secs(4),
        );
        let id = b.add_task("Model download", Kind::Bytes, Some(100), Some(1), secs(4));
        b.task_mut(id).unwrap().update(40, secs(8));
        let rows = render(&b, &opts(100));
        let text: Vec<&str> = rows.iter().map(|r| r.text.as_str()).collect();
        assert_eq!(text[0], " [x] Create the wallet  0xab12  (4s)");
        assert_eq!(text[1], " [>] Download the model");
        assert!(text[2].starts_with("      | Model download"), "{}", text[2]);
        assert_eq!(text[3], " [ ] Start the node");
        assert_eq!(text[4], " [-] Register  skipped: not needed here");
        assert_eq!(rows[0].tone, Tone::Ok);
        assert_eq!(rows[3].tone, Tone::Muted);
    }

    #[test]
    fn a_failed_step_shows_why() {
        let mut b = Board::new();
        b.set_steps(&["Start the node"]);
        b.step_to(0, StepState::Running, None, secs(0));
        b.step_to(
            0,
            StepState::Failed,
            Some("the node did not answer".into()),
            secs(9),
        );
        let rows = render(&b, &opts(100));
        assert_eq!(
            rows[0].text,
            " [!] Start the node  failed: the node did not answer"
        );
        assert_eq!(rows[0].tone, Tone::Bad);
    }

    #[test]
    fn a_running_step_with_no_task_shows_a_spinner_and_a_clock() {
        let mut b = Board::new();
        b.set_steps(&["Wait for the passkey"]);
        b.step_to(0, StepState::Running, None, secs(10));
        let rows = render(&b, &opts(100));
        assert_eq!(rows[0].text, " [>] Wait for the passkey  | 20s");
    }
}

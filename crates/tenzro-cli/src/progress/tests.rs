use std::io::Write;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::Progress;
use super::engine::{Engine, Mode, mode_from};
use super::model::Kind;

#[derive(Clone, Default)]
struct Sink(Arc<Mutex<Vec<u8>>>);

impl Write for Sink {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl Sink {
    fn text(&self) -> String {
        String::from_utf8(self.0.lock().unwrap().clone()).unwrap()
    }
}

fn secs(n: u64) -> Duration {
    Duration::from_secs(n)
}

fn ms(n: u64) -> Duration {
    Duration::from_millis(n)
}

fn engine(mode: Mode, cols: usize) -> (Engine, Sink) {
    let s = Sink::default();
    (
        Engine::new(mode, Box::new(s.clone())).with_size(cols, 24),
        s,
    )
}

/// What a terminal would show after these bytes, and whether the cursor is hidden.
fn screen(bytes: &str) -> (Vec<String>, bool) {
    let mut lines: Vec<String> = Vec::new();
    let mut row = 0usize;
    let mut hidden = false;
    let cs: Vec<char> = bytes.chars().collect();
    let mut i = 0;
    while i < cs.len() {
        match cs[i] {
            '\x1b' => {
                let mut j = i + 1;
                if cs.get(j) == Some(&'[') {
                    j += 1;
                }
                let start = j;
                while j < cs.len() && !cs[j].is_ascii_alphabetic() {
                    j += 1;
                }
                let params: String = cs[start..j].iter().collect();
                match cs.get(j) {
                    Some('A') => row = row.saturating_sub(params.parse().unwrap_or(1)),
                    Some('J') => lines.truncate(row),
                    Some('h') if params == "?25" => hidden = false,
                    Some('l') if params == "?25" => hidden = true,
                    _ => {}
                }
                i = j;
            }
            '\r' => {}
            '\n' => row += 1,
            c => {
                while lines.len() <= row {
                    lines.push(String::new());
                }
                lines[row].push(c);
            }
        }
        i += 1;
    }
    while lines.last().is_some_and(|l| l.is_empty()) {
        lines.pop();
    }
    (lines, hidden)
}

#[test]
fn the_mode_follows_where_the_output_goes() {
    // json flag, env, then plain fallbacks, then a real terminal.
    assert_eq!(
        mode_from(true, None, false, None, Some("xterm"), true, true),
        Mode::Json
    );
    assert_eq!(
        mode_from(false, Some("json"), false, None, None, false, false),
        Mode::Json
    );
    assert_eq!(
        mode_from(false, Some("plain"), false, None, Some("xterm"), true, true),
        Mode::Plain
    );
    assert_eq!(
        mode_from(false, None, true, None, Some("xterm"), true, true),
        Mode::Plain
    );
    assert_eq!(
        mode_from(false, None, false, Some("1"), Some("xterm"), true, true),
        Mode::Plain
    );
    assert_eq!(
        mode_from(false, None, false, Some(""), Some("xterm"), true, true),
        Mode::Tty
    );
    assert_eq!(
        mode_from(false, None, false, None, Some("dumb"), true, true),
        Mode::Plain
    );
    assert_eq!(
        mode_from(false, None, false, None, Some("xterm"), false, true),
        Mode::Plain
    );
    assert_eq!(
        mode_from(false, None, false, None, Some("xterm"), true, false),
        Mode::Plain
    );
    assert_eq!(
        mode_from(false, None, false, None, Some("xterm-256color"), true, true),
        Mode::Tty
    );
}

#[test]
fn plain_mode_has_no_escape_codes_and_speaks_every_five_seconds() {
    let (mut e, s) = engine(Mode::Plain, 80);
    let id = e.start_task("Model download", Kind::Bytes, Some(1000), None, secs(0));
    for t in 1..=12u64 {
        e.update_task(id, t * 10, secs(t));
        e.tick(secs(t));
    }
    e.finish_task(id, None, secs(12));
    let out = s.text();
    assert!(!out.contains('\x1b'), "{out:?}");
    assert!(!out.contains('\r'), "{out:?}");
    let lines: Vec<&str> = out.lines().collect();
    // start, one at 5s, one at 10s, finish.
    assert_eq!(lines.len(), 4, "{out}");
    assert_eq!(lines[0], "Model download: started, 1000 B");
    assert!(lines[1].starts_with("Model download: 5%"), "{}", lines[1]);
    assert!(lines[2].starts_with("Model download: 10%"), "{}", lines[2]);
    assert_eq!(lines[3], "Model download: 120 B in 12s, 10 B/s");
}

#[test]
fn plain_mode_stays_quiet_between_updates_however_many_there_are() {
    let (mut e, s) = engine(Mode::Plain, 80);
    let id = e.start_task(
        "Chain sync",
        Kind::Count("blocks".into()),
        Some(100_000),
        None,
        secs(0),
    );
    for k in 0..4000u64 {
        e.update_task(id, k, ms(k));
        e.tick(ms(k));
    }
    // 4 seconds of ticks: nothing past the start line.
    assert_eq!(s.text().lines().count(), 1, "{}", s.text());
}

#[test]
fn plain_mode_says_a_step_without_a_task_is_still_working() {
    let (mut e, s) = engine(Mode::Plain, 80);
    e.start_steps(&["Wait for the passkey"], secs(0));
    e.step(0, super::StepState::Running, None, secs(0), false);
    for t in 1..=11u64 {
        e.tick(secs(t));
    }
    let out = s.text();
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines[0], "[>] Wait for the passkey");
    assert_eq!(lines[1], "Wait for the passkey: still working, 5s elapsed");
    assert_eq!(lines[2], "Wait for the passkey: still working, 10s elapsed");
    assert_eq!(lines.len(), 3);
}

#[test]
fn json_mode_writes_one_well_formed_object_per_event() {
    let (mut e, s) = engine(Mode::Json, 80);
    let id = e.start_task("Model download", Kind::Bytes, Some(1000), None, ms(0));
    for k in 1..=10u64 {
        e.update_task(id, k * 100, ms(k * 100));
    }
    e.finish_task(id, None, ms(1000));
    let w = e.start_task("Starting the node", Kind::Wait, None, None, ms(1000));
    e.fail_task(w, "the node did not answer", ms(2500));
    let out = s.text();
    let events: Vec<serde_json::Value> = out
        .lines()
        .map(|l| serde_json::from_str(l).expect(l))
        .collect();
    for ev in &events {
        for key in [
            "task",
            "state",
            "done",
            "total",
            "unit",
            "message",
            "elapsed_ms",
        ] {
            assert!(ev.get(key).is_some(), "{key} missing in {ev}");
        }
    }
    assert_eq!(events[0]["state"], "running");
    assert_eq!(events[0]["task"], "Model download");
    assert_eq!(events[0]["unit"], "bytes");
    assert_eq!(events[0]["total"], 1000);
    // Updates are spaced out: far fewer events than updates.
    let running = events
        .iter()
        .filter(|e| e["task"] == "Model download" && e["state"] == "running")
        .count();
    assert!((2..=6).contains(&running), "{running}");
    let done = events.iter().find(|e| e["state"] == "done").unwrap();
    assert_eq!(done["done"], 1000);
    assert_eq!(done["elapsed_ms"], 1000);
    let failed = events.last().unwrap();
    assert_eq!(failed["state"], "failed");
    assert_eq!(failed["message"], "the node did not answer");
    assert_eq!(failed["unit"], serde_json::Value::Null);
    assert!(!out.contains('\x1b'));
}

#[test]
fn json_mode_reports_steps_by_label() {
    let (mut e, s) = engine(Mode::Json, 80);
    e.start_steps(&["Create the wallet"], ms(0));
    e.step(0, super::StepState::Running, None, ms(0), false);
    e.step(
        0,
        super::StepState::Done,
        Some("0xab".into()),
        ms(1500),
        false,
    );
    let evs: Vec<serde_json::Value> = s
        .text()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect();
    assert_eq!(evs.len(), 2);
    assert_eq!(evs[1]["task"], "Create the wallet");
    assert_eq!(evs[1]["state"], "done");
    assert_eq!(evs[1]["message"], "0xab");
    assert_eq!(evs[1]["elapsed_ms"], 1500);
}

#[test]
fn a_terminal_redraws_in_place_and_ends_clean() {
    let (mut e, s) = engine(Mode::Tty, 80);
    e.start_steps(&["Download the model", "Start the node"], secs(0));
    let id = e.start_task("Model download", Kind::Bytes, Some(1000), Some(0), secs(0));
    e.update_task(id, 500, secs(2));
    e.tick(secs(2));
    e.tick(secs(3));
    let (mid, hidden) = screen(&s.text());
    assert!(hidden);
    assert_eq!(mid.len(), 3, "{mid:?}");
    assert!(mid[0].starts_with(" [>] Download the model"), "{mid:?}");
    assert!(
        mid[1].contains("50%") && mid[1].contains("500 B / 1000 B"),
        "{mid:?}"
    );
    assert_eq!(mid[2], " [ ] Start the node");

    e.finish_task(id, None, secs(4));
    e.step(
        1,
        super::StepState::Skipped,
        Some("already running".into()),
        secs(4),
        false,
    );
    e.finish_steps(secs(4));
    let (end, hidden) = screen(&s.text());
    assert!(!hidden, "the cursor must be back");
    assert_eq!(
        end,
        vec![
            " [x] Download the model  500 B, 125 B/s  (4s)".to_string(),
            " [-] Start the node  skipped: already running".to_string(),
        ]
    );
}

#[test]
fn a_failure_shows_the_whole_error_and_leaves_a_clean_line() {
    let (mut e, s) = engine(Mode::Tty, 40);
    let id = e.start_task("Model download", Kind::Bytes, Some(1000), None, secs(0));
    e.update_task(id, 100, secs(2));
    e.tick(secs(2));
    let why = "there is no room on the disk for a file this large, free some space and try again";
    e.fail_task(id, why, secs(3));
    let (lines, hidden) = screen(&s.text());
    assert!(!hidden);
    assert_eq!(
        lines,
        vec![format!("[!] Model download: failed after 3s: {why}")]
    );
}

#[test]
fn no_row_wraps_at_any_terminal_width() {
    for cols in [12usize, 16, 20, 24, 30, 40, 60, 80, 120] {
        let (mut e, s) = engine(Mode::Tty, cols);
        e.start_steps(
            &[
                "Create the identity and the wallet",
                "Download the model",
                "Start the node and wait for it",
            ],
            secs(0),
        );
        e.step(0, super::StepState::Running, None, secs(0), false);
        e.step(
            0,
            super::StepState::Done,
            Some("0x1234567890abcdef1234567890abcdef".into()),
            secs(3),
            false,
        );
        let d = e.start_task(
            "Model download and checksum",
            Kind::Bytes,
            Some(5 << 30),
            Some(1),
            secs(3),
        );
        e.update_task(d, 2 << 30, secs(40));
        let c = e.start_task(
            "Blocks synced from the network",
            Kind::Count("blocks".into()),
            Some(900_000),
            None,
            secs(3),
        );
        e.update_task(c, 123_456, secs(30));
        let w = e.start_task("Waiting for peers", Kind::Wait, None, None, secs(3));
        e.board.task_mut(w).unwrap().message = "found 2, looking for more".into();
        e.tick(secs(41));
        e.tick(secs(42));
        let (lines, _) = screen(&s.text());
        assert!(!lines.is_empty());
        for l in &lines {
            assert!(l.chars().count() < cols, "{cols}: {l:?}");
        }
    }
}

#[test]
fn a_tall_checklist_is_cut_to_the_screen_height() {
    let s = Sink::default();
    let mut e = Engine::new(Mode::Tty, Box::new(s.clone())).with_size(80, 8);
    let labels: Vec<String> = (0..20).map(|i| format!("step {i}")).collect();
    let refs: Vec<&str> = labels.iter().map(|l| l.as_str()).collect();
    e.start_steps(&refs, secs(0));
    e.tick(secs(1));
    let (lines, _) = screen(&s.text());
    assert!(lines.len() <= 6, "{}", lines.len());
}

#[test]
fn a_task_dropped_without_an_end_is_reported_as_stopped() {
    let s = Sink::default();
    let p = Progress::new(Engine::new(Mode::Plain, Box::new(s.clone())));
    {
        let _t = p.bytes("Model download", Some(10));
    }
    assert!(
        s.text()
            .contains("Model download: failed after 0s: stopped before it finished"),
        "{}",
        s.text()
    );
}

#[test]
fn a_checklist_dropped_early_marks_the_running_step_as_stopped() {
    let s = Sink::default();
    let p = Progress::new(Engine::new(Mode::Plain, Box::new(s.clone())));
    {
        let steps = p.steps(&["Create the wallet", "Start the node"]);
        steps.start(0);
    }
    let out = s.text();
    assert!(out.contains("[>] Create the wallet"), "{out}");
    assert!(
        out.contains("[!] Create the wallet  failed: stopped before it finished"),
        "{out}"
    );
    assert!(
        !out.contains("Start the node"),
        "a pending step is not announced: {out}"
    );
}

#[test]
fn a_task_that_is_a_step_reports_once_and_closes_the_step() {
    let s = Sink::default();
    let p = Progress::new(Engine::new(Mode::Plain, Box::new(s.clone())));
    let steps = p.steps(&["Download the model", "Start the node"]);
    let t = steps.bytes(0, "Model download", Some(100));
    t.reporter().set(100);
    t.finish();
    steps.done(1);
    let out = s.text();
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines[0], "Model download: started, 100 B");
    assert_eq!(lines[1], "[x] Download the model  100 B");
    assert_eq!(lines[2], "[x] Start the node");
    assert_eq!(lines.len(), 3, "{out}");
}

#[test]
fn a_reporter_can_be_used_from_another_thread() {
    let s = Sink::default();
    let p = Progress::new(Engine::new(Mode::Json, Box::new(s.clone())));
    let t = p.count("Verifying files", Some(50), "files");
    let r = t.reporter();
    std::thread::spawn(move || {
        for _ in 0..50 {
            r.inc(1);
        }
    })
    .join()
    .unwrap();
    t.finish();
    let last: serde_json::Value = serde_json::from_str(s.text().lines().last().unwrap()).unwrap();
    assert_eq!(last["state"], "done");
    assert_eq!(last["done"], 50);
    assert_eq!(last["unit"], "files");
}

#[test]
fn suspending_clears_the_terminal_for_a_prompt_and_draws_again() {
    let s = Sink::default();
    let p = Progress::new(Engine::new(Mode::Tty, Box::new(s.clone())).with_size_for_test());
    let _t = p.wait("Waiting for the node", "starting");
    let mark = s.text().len();
    p.suspend(|| {});
    let after = &s.text()[mark..];
    // It wiped the rows, showed the cursor, and then drew again.
    assert!(after.starts_with("\x1b[1A\r\x1b[J"), "{after:?}");
    assert!(after.contains("\x1b[?25h"), "{after:?}");
    assert!(after.contains("Waiting for the node"), "{after:?}");
}

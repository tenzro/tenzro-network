//! The progress panel for the full-screen screens. It draws the same rows as
//! the terminal renderer, from the same task model.

use std::time::{Duration, Instant};

use ratatui::buffer::Buffer;
use ratatui::layout::Rect;
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Widget};

use super::engine::ascii_only;
use super::model::{Board, Kind, StepState};
use super::rows::{self, Opts, Tone};
use crate::tui::theme::{Theme, Word};

/// A board, a clock and a spinner frame: what a screen keeps to show progress.
pub struct Panel {
    pub board: Board,
    clock: Instant,
    frame: usize,
}

impl Default for Panel {
    fn default() -> Self {
        Self::new()
    }
}

impl Panel {
    pub fn new() -> Self {
        Self {
            board: Board::new(),
            clock: Instant::now(),
            frame: 0,
        }
    }

    pub fn now(&self) -> Duration {
        self.clock.elapsed()
    }

    /// Whether anything is showing.
    pub fn is_empty(&self) -> bool {
        self.board.is_empty()
    }

    /// Advance the spinner. Call it on every screen tick.
    pub fn tick(&mut self) {
        self.frame = self.frame.wrapping_add(1);
        let now = self.now();
        self.board.touch(now);
    }

    /// Show a checklist.
    pub fn set_steps(&mut self, labels: &[&str]) {
        self.board.set_steps(labels);
    }

    pub fn step(&mut self, i: usize, next: StepState, detail: Option<&str>) -> bool {
        let now = self.now();
        self.board.step_to(i, next, detail.map(str::to_string), now)
    }

    /// Start an activity; returns its id.
    pub fn start(&mut self, name: &str, kind: Kind, total: Option<u64>) -> u64 {
        let now = self.now();
        self.board.add_task(name, kind, total, None, now)
    }

    /// A wait with a short status line.
    pub fn start_wait(&mut self, name: &str, message: &str) -> u64 {
        let id = self.start(name, Kind::Wait, None);
        self.message(id, message);
        id
    }

    pub fn message(&mut self, id: u64, text: &str) {
        if let Some(t) = self.board.task_mut(id) {
            t.message = text.to_string();
        }
    }

    pub fn update(&mut self, id: u64, done: u64) {
        let now = self.now();
        if let Some(t) = self.board.task_mut(id) {
            t.update(done, now);
        }
    }

    pub fn set_total(&mut self, id: u64, total: Option<u64>) {
        if let Some(t) = self.board.task_mut(id) {
            t.total = total;
        }
    }

    /// End an activity and take it off the panel.
    pub fn end(&mut self, id: u64) {
        self.board.remove_task(id);
    }

    /// Take everything off the panel.
    pub fn clear(&mut self) {
        self.board = Board::new();
    }

    /// The widget, drawn with the screen's theme.
    pub fn widget<'a>(&'a self, theme: &'a Theme, title: &'a str) -> ProgressPanel<'a> {
        ProgressPanel {
            board: &self.board,
            theme,
            frame: self.frame,
            now: self.now(),
            title,
        }
    }

    /// Rows the panel needs at `width`, border included.
    pub fn height(&self, width: u16) -> u16 {
        let rows = rows::render(
            &self.board,
            &Opts {
                width: width.max(1) as usize,
                frame: 0,
                ascii: true,
                now: self.now(),
            },
        );
        if rows.is_empty() {
            0
        } else {
            rows.len() as u16 + 1
        }
    }
}

/// The panel as a ratatui widget.
pub struct ProgressPanel<'a> {
    board: &'a Board,
    theme: &'a Theme,
    frame: usize,
    now: Duration,
    title: &'a str,
}

fn style_of(theme: &Theme, tone: Tone) -> Style {
    match tone {
        Tone::Plain => Style::default(),
        Tone::Ok => theme.status(Word::Ok),
        Tone::Bad => theme.status(Word::Down),
        Tone::Accent => theme.accent(),
        Tone::Muted => theme.muted(),
    }
}

impl Widget for ProgressPanel<'_> {
    fn render(self, area: Rect, buf: &mut Buffer) {
        if area.width < 8 || area.height < 2 {
            return;
        }
        let block = Block::default().borders(Borders::TOP).title(Span::styled(
            format!(" {} ", self.title),
            self.theme.muted(),
        ));
        let inner = block.inner(area);
        block.render(area, buf);
        let o = Opts {
            width: inner.width as usize,
            frame: self.frame,
            ascii: ascii_only(),
            now: self.now,
        };
        let mut rows = rows::render(self.board, &o);
        let fit = inner.height as usize;
        if rows.len() > fit {
            let extra = rows.len() - fit;
            rows.drain(0..extra);
        }
        let lines: Vec<Line> = rows
            .into_iter()
            .map(|r| Line::from(Span::styled(r.text, style_of(self.theme, r.tone))))
            .collect();
        Paragraph::new(lines).render(inner, buf);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::theme::Depth;

    fn draw(p: &Panel, w: u16, h: u16) -> Vec<String> {
        let theme = Theme::with_depth(Depth::None);
        let area = Rect::new(0, 0, w, h);
        let mut buf = Buffer::empty(area);
        p.widget(&theme, "progress").render(area, &mut buf);
        (0..h)
            .map(|y| {
                (0..w)
                    .map(|x| buf[(x, y)].symbol().to_string())
                    .collect::<String>()
                    .trim_end()
                    .to_string()
            })
            .collect()
    }

    #[test]
    fn the_panel_shows_a_wait_with_its_status_line() {
        let mut p = Panel::new();
        p.start_wait("Starting the node", "waiting for the first block");
        let screen = draw(&p, 70, 4);
        assert!(screen[0].contains("progress"), "{screen:?}");
        assert!(
            screen[1].contains("Starting the node - waiting for the first block"),
            "{screen:?}"
        );
    }

    #[test]
    fn the_panel_shows_a_transfer_bar_and_a_checklist() {
        let mut p = Panel::new();
        p.set_steps(&["Download", "Start"]);
        p.step(0, StepState::Running, None);
        let id = p.start("Model download", Kind::Bytes, Some(1000));
        p.update(id, 250);
        let screen = draw(&p, 90, 6);
        assert!(
            screen.iter().any(|l| l.contains("[>] Download")),
            "{screen:?}"
        );
        assert!(screen.iter().any(|l| l.contains("[ ] Start")), "{screen:?}");
        assert!(
            screen
                .iter()
                .any(|l| l.contains("25%") && l.contains("250 B / 1000 B")),
            "{screen:?}"
        );
    }

    #[test]
    fn a_small_area_draws_nothing_and_does_not_panic() {
        let mut p = Panel::new();
        p.start_wait("Waiting", "");
        assert!(draw(&p, 5, 1).iter().all(|l| l.is_empty()));
    }

    #[test]
    fn height_is_zero_when_empty_and_grows_with_rows() {
        let mut p = Panel::new();
        assert_eq!(p.height(80), 0);
        p.start_wait("One", "");
        assert_eq!(p.height(80), 2);
        p.start_wait("Two", "");
        assert_eq!(p.height(80), 3);
    }
}

//! Pieces every screen shares: the minimum size, header, footer, help
//! overlay and a centred box.

use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Wrap};

use super::keys::Binding;
use super::theme::Theme;

pub const MIN_W: u16 = 80;
pub const MIN_H: u16 = 24;

/// When the window is smaller than 80x24, say so and draw nothing else.
/// Returns true when the caller should stop drawing.
pub fn too_small(f: &mut Frame, theme: &Theme) -> bool {
    let a = f.area();
    if a.width >= MIN_W && a.height >= MIN_H {
        return false;
    }
    let text = vec![
        Line::from(Span::styled("Terminal too small", theme.title())),
        Line::from(format!(
            "Need at least {MIN_W}x{MIN_H}, this window is {}x{}.",
            a.width, a.height
        )),
        Line::from("Make the window bigger, or press q to quit."),
    ];
    f.render_widget(Clear, a);
    f.render_widget(Paragraph::new(text).wrap(Wrap { trim: true }), a);
    true
}

/// The three bands of every screen: header (1 row), body, footer (1 row).
pub fn bands(area: Rect) -> (Rect, Rect, Rect) {
    let [h, b, ft] = Layout::vertical([
        Constraint::Length(1),
        Constraint::Min(1),
        Constraint::Length(1),
    ])
    .areas(area);
    (h, b, ft)
}

pub fn header(f: &mut Frame, area: Rect, theme: &Theme, left: &str, right: Vec<Span<'static>>) {
    let [l, r] = Layout::horizontal([
        Constraint::Min(10),
        Constraint::Length(
            right
                .iter()
                .map(|s| s.width() as u16)
                .sum::<u16>()
                .min(area.width / 2),
        ),
    ])
    .areas(area);
    f.render_widget(
        Paragraph::new(Line::from(vec![
            Span::styled(" tenzro ", theme.title()),
            Span::styled(format!(" {left}"), theme.muted()),
        ])),
        l,
    );
    f.render_widget(
        Paragraph::new(Line::from(right)).alignment(Alignment::Right),
        r,
    );
}

pub fn footer(f: &mut Frame, area: Rect, theme: &Theme, text: &str) {
    f.render_widget(
        Paragraph::new(Line::from(Span::styled(format!(" {text}"), theme.muted()))),
        area,
    );
}

/// A box of `w` by `h` (clamped) in the middle of `area`.
pub fn centered(area: Rect, w: u16, h: u16) -> Rect {
    let w = w.min(area.width);
    let h = h.min(area.height);
    Rect::new(
        area.x + (area.width - w) / 2,
        area.y + (area.height - h) / 2,
        w,
        h,
    )
}

/// The help overlay, generated from the same table the keys come from.
pub fn help(f: &mut Frame, theme: &Theme, table: &[Binding], title: &str) {
    let area = centered(f.area(), 72, (table.len() as u16 + 4).min(f.area().height));
    f.render_widget(Clear, area);
    let mut lines = Vec::new();
    for b in table {
        lines.push(Line::from(vec![
            Span::styled(format!("{:<16}", b.keys.join(" / ")), theme.command()),
            Span::raw(b.label),
        ]));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(Span::styled(
        "Esc or ? closes this help",
        theme.muted(),
    )));
    let block = Block::default()
        .borders(Borders::ALL)
        .title(Span::styled(format!(" {title} "), theme.title()));
    f.render_widget(
        Paragraph::new(lines)
            .block(block)
            .wrap(Wrap { trim: false }),
        area,
    );
}

/// Word-wrap `text` to `width` columns after a label of `label_w` columns:
/// the label is on the first line and the following lines are indented under
/// the text, so wrapped paragraphs keep their hanging indent. A word longer
/// than the line is broken.
pub fn hang(
    label: Span<'static>,
    label_w: usize,
    text: &str,
    width: u16,
    style: ratatui::style::Style,
) -> Vec<Line<'static>> {
    let avail = (width as usize).saturating_sub(label_w + 1).max(8);
    let mut rows: Vec<String> = Vec::new();
    let mut cur = String::new();
    for word in text.split_whitespace() {
        let mut word = word.to_string();
        while word.chars().count() > avail {
            if !cur.is_empty() {
                rows.push(std::mem::take(&mut cur));
            }
            let head: String = word.chars().take(avail).collect();
            rows.push(head);
            word = word.chars().skip(avail).collect();
        }
        let need = if cur.is_empty() {
            word.chars().count()
        } else {
            cur.chars().count() + 1 + word.chars().count()
        };
        if need > avail {
            rows.push(std::mem::take(&mut cur));
        }
        if !cur.is_empty() {
            cur.push(' ');
        }
        cur.push_str(&word);
    }
    if !cur.is_empty() || rows.is_empty() {
        rows.push(cur);
    }
    rows.into_iter()
        .enumerate()
        .map(|(i, r)| {
            let lead = if i == 0 {
                label.clone()
            } else {
                Span::raw(" ".repeat(label_w))
            };
            Line::from(vec![lead, Span::styled(r, style)])
        })
        .collect()
}

/// Cut `s` to at most `n` characters, ending in `..` when cut.
pub fn clip(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else if n <= 2 {
        s.chars().take(n).collect()
    } else {
        let mut t: String = s.chars().take(n - 2).collect();
        t.push_str("..");
        t
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clip_ends_with_dots_and_never_exceeds() {
        assert_eq!(clip("abcdef", 4), "ab..");
        assert_eq!(clip("abc", 4), "abc");
        assert_eq!(clip("abcdef", 2), "ab");
    }

    #[test]
    fn hang_wraps_under_the_text_and_breaks_long_words() {
        let l = hang(
            Span::raw(" Why   "),
            7,
            "one two three four five six",
            20,
            ratatui::style::Style::default(),
        );
        assert!(l.len() >= 2);
        for row in &l[1..] {
            assert!(row.spans[0].content.starts_with("       "));
        }
        let l = hang(
            Span::raw("> "),
            2,
            &"x".repeat(50),
            20,
            ratatui::style::Style::default(),
        );
        assert!(l.len() >= 3 && l.iter().all(|r| r.width() <= 20));
    }

    #[test]
    fn centered_stays_inside() {
        let r = centered(Rect::new(0, 0, 80, 24), 100, 100);
        assert_eq!((r.width, r.height), (80, 24));
        let r = centered(Rect::new(0, 0, 80, 24), 40, 10);
        assert_eq!((r.x, r.y), (20, 7));
    }
}

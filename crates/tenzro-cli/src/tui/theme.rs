//! The look of the terminal screens: the site's near-black ground (the
//! terminal's own background) and a single periwinkle accent. Status is a word
//! first and a colour second, so a terminal without colour, or `NO_COLOR`,
//! loses nothing: bold, reverse video and the words carry the meaning.

use ratatui::style::{Color, Modifier, Style};

/// The fixed status vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Word {
    Ok,
    Watch,
    Action,
    Down,
    Unknown,
}

impl Word {
    pub fn text(self) -> &'static str {
        match self {
            Word::Ok => "OK",
            Word::Watch => "WATCH",
            Word::Action => "ACTION",
            Word::Down => "DOWN",
            Word::Unknown => "UNKNOWN",
        }
    }
}

/// How many colours the terminal is given.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Depth {
    None,
    Ansi256,
    True,
}

/// Pure choice of colour depth from the environment.
pub fn depth_from(no_color: Option<&str>, term: Option<&str>, colorterm: Option<&str>) -> Depth {
    if no_color.is_some_and(|v| !v.is_empty()) || term == Some("dumb") {
        return Depth::None;
    }
    if matches!(colorterm, Some("truecolor") | Some("24bit")) {
        Depth::True
    } else {
        Depth::Ansi256
    }
}

#[derive(Debug, Clone, Copy)]
pub struct Theme {
    pub depth: Depth,
}

impl Theme {
    pub fn detect() -> Self {
        Self {
            depth: depth_from(
                std::env::var("NO_COLOR").ok().as_deref(),
                std::env::var("TERM").ok().as_deref(),
                std::env::var("COLORTERM").ok().as_deref(),
            ),
        }
    }

    pub fn with_depth(depth: Depth) -> Self {
        Self { depth }
    }

    fn pick(&self, rgb: (u8, u8, u8), ansi: u8) -> Option<Color> {
        match self.depth {
            Depth::None => None,
            Depth::Ansi256 => Some(Color::Indexed(ansi)),
            Depth::True => Some(Color::Rgb(rgb.0, rgb.1, rgb.2)),
        }
    }

    fn fg(&self, rgb: (u8, u8, u8), ansi: u8) -> Style {
        match self.pick(rgb, ansi) {
            Some(c) => Style::default().fg(c),
            None => Style::default(),
        }
    }

    /// The one accent, `#8a9bc7`.
    pub fn accent(&self) -> Style {
        self.fg((138, 155, 199), 110)
    }

    /// Accent on selected rows; reverse video when there is no colour.
    pub fn selected(&self) -> Style {
        match self.depth {
            Depth::None => Style::default().add_modifier(Modifier::REVERSED | Modifier::BOLD),
            _ => self.accent().add_modifier(Modifier::BOLD),
        }
    }

    pub fn title(&self) -> Style {
        self.accent().add_modifier(Modifier::BOLD)
    }

    pub fn bold(&self) -> Style {
        Style::default().add_modifier(Modifier::BOLD)
    }

    /// Secondary text: a light grey, not "dim" (which can vanish on black).
    pub fn muted(&self) -> Style {
        self.fg((154, 160, 173), 247)
    }

    pub fn command(&self) -> Style {
        match self.depth {
            Depth::None => Style::default().add_modifier(Modifier::BOLD),
            _ => self.accent(),
        }
    }

    pub fn status(&self, w: Word) -> Style {
        let base = match w {
            Word::Ok => self.fg((124, 196, 164), 115),
            Word::Watch => self.fg((224, 181, 103), 179),
            Word::Action => self.fg((224, 181, 103), 179),
            Word::Down => self.fg((228, 138, 138), 174),
            Word::Unknown => self.muted(),
        };
        let m = match w {
            Word::Down | Word::Action => Modifier::BOLD | Modifier::UNDERLINED,
            _ => Modifier::BOLD,
        };
        base.add_modifier(m)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_color_and_dumb_terminals_get_no_colour() {
        assert_eq!(depth_from(Some("1"), None, Some("truecolor")), Depth::None);
        assert_eq!(depth_from(None, Some("dumb"), None), Depth::None);
        assert_eq!(depth_from(Some(""), Some("xterm"), None), Depth::Ansi256);
        assert_eq!(
            depth_from(None, Some("xterm"), Some("truecolor")),
            Depth::True
        );
    }

    #[test]
    fn without_colour_status_is_still_distinguishable() {
        let t = Theme::with_depth(Depth::None);
        assert_eq!(t.status(Word::Down).fg, None);
        assert!(
            t.status(Word::Down)
                .add_modifier
                .contains(Modifier::UNDERLINED)
        );
        assert!(t.selected().add_modifier.contains(Modifier::REVERSED));
    }

    #[test]
    fn the_accent_is_the_site_periwinkle() {
        let t = Theme::with_depth(Depth::True);
        assert_eq!(t.accent().fg, Some(Color::Rgb(0x8a, 0x9b, 0xc7)));
    }
}

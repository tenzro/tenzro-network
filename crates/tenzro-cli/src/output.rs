//! Output formatting utilities for the Tenzro CLI
//!
//! This module provides helpers for formatted console output including
//! tables, progress bars, colored status messages, and banners.

use indicatif::{ProgressBar, ProgressStyle};
use std::time::Duration;

/// Whether escape codes may be written at all. Pure, so it is testable: colour
/// is off when `NO_COLOR` is set and non-empty (https://no-color.org), when
/// `TERM` is `dumb`, or when the stream is not a terminal.
pub fn color_allowed(no_color: Option<&str>, term: Option<&str>, is_tty: bool) -> bool {
    if no_color.is_some_and(|v| !v.is_empty()) {
        return false;
    }
    if term == Some("dumb") {
        return false;
    }
    is_tty
}

/// Whether the terminal advertises 24-bit colour.
pub fn truecolor_allowed(colorterm: Option<&str>) -> bool {
    matches!(colorterm, Some("truecolor") | Some("24bit"))
}

/// Colour palette: one periwinkle accent (the site's `#8a9bc7`), and three
/// status colours. Every function returns an empty string when colour is not
/// allowed, so the text reads the same without it.
pub mod colors {
    use std::io::IsTerminal as _;
    use std::sync::OnceLock;

    static STDOUT_ON: OnceLock<bool> = OnceLock::new();
    static STDERR_ON: OnceLock<bool> = OnceLock::new();
    static TRUECOLOR: OnceLock<bool> = OnceLock::new();

    fn decide(tty: bool) -> bool {
        super::color_allowed(
            std::env::var("NO_COLOR").ok().as_deref(),
            std::env::var("TERM").ok().as_deref(),
            tty,
        )
    }

    /// Colour on stdout.
    pub fn enabled() -> bool {
        *STDOUT_ON.get_or_init(|| decide(std::io::stdout().is_terminal()))
    }

    /// Colour on stderr.
    pub fn enabled_stderr() -> bool {
        *STDERR_ON.get_or_init(|| decide(std::io::stderr().is_terminal()))
    }

    fn truecolor() -> bool {
        *TRUECOLOR
            .get_or_init(|| super::truecolor_allowed(std::env::var("COLORTERM").ok().as_deref()))
    }

    fn pick(on: bool, truecolor_code: &'static str, ansi256: &'static str) -> &'static str {
        if !on {
            ""
        } else if truecolor() {
            truecolor_code
        } else {
            ansi256
        }
    }

    pub fn accent() -> &'static str {
        pick(enabled(), "\x1b[38;2;138;155;199m", "\x1b[38;5;110m")
    }
    pub fn ok() -> &'static str {
        pick(enabled(), "\x1b[38;2;124;196;164m", "\x1b[38;5;115m")
    }
    pub fn warn() -> &'static str {
        pick(enabled(), "\x1b[38;2;224;181;103m", "\x1b[38;5;179m")
    }
    pub fn bad() -> &'static str {
        pick(enabled(), "\x1b[38;2;228;138;138m", "\x1b[38;5;174m")
    }
    /// Red for the error stream, which may be a terminal when stdout is not.
    pub fn bad_stderr() -> &'static str {
        if enabled_stderr() { "\x1b[38;5;174m" } else { "" }
    }
    pub fn bold() -> &'static str {
        if enabled() { "\x1b[1m" } else { "" }
    }
    pub fn reset() -> &'static str {
        if enabled() { "\x1b[0m" } else { "" }
    }
    pub fn reset_stderr() -> &'static str {
        if enabled_stderr() { "\x1b[0m" } else { "" }
    }
}

/// The prompt theme for the plain wizard: coloured on a colour terminal, plain
/// text otherwise.
pub fn prompt_theme() -> &'static dyn dialoguer::theme::Theme {
    use std::sync::OnceLock;
    static COLORFUL: OnceLock<dialoguer::theme::ColorfulTheme> = OnceLock::new();
    static SIMPLE: dialoguer::theme::SimpleTheme = dialoguer::theme::SimpleTheme;
    if colors::enabled() {
        COLORFUL.get_or_init(dialoguer::theme::ColorfulTheme::default)
    } else {
        &SIMPLE
    }
}

/// Apply the colour decision to the `console` crate too, which styles the
/// wizard rail and spinners.
pub fn apply_color_policy() {
    console::set_colors_enabled(colors::enabled());
    console::set_colors_enabled_stderr(colors::enabled_stderr());
}

/// Print the Tenzro CLI banner
pub fn print_banner() {
    let title = format!("Tenzro Network CLI v{}", env!("CARGO_PKG_VERSION"));
    let width = 59usize;
    let left = width.saturating_sub(title.chars().count()) / 2;
    let right = width.saturating_sub(title.chars().count() + left);
    println!("{}", colors::bold());
    println!("╔{}╗", "═".repeat(width));
    println!("║{}║", " ".repeat(width));
    println!(
        "║{}{}{}{}{}║",
        " ".repeat(left),
        colors::accent(),
        title,
        colors::bold(),
        " ".repeat(right)
    );
    println!("║{}║", " ".repeat(width));
    println!("║      AI-Native, Agentic, Tokenized Settlement Layer      ║");
    println!("║{}║", " ".repeat(width));
    println!("╚{}╝", "═".repeat(width));
    println!("{}", colors::reset());
}

/// Print a section header
pub fn print_header(title: &str) {
    println!(
        "\n{}{}{}{}:",
        colors::bold(),
        colors::accent(),
        title,
        colors::reset()
    );
    println!("{}", "─".repeat(60));
}

/// Print a success message
pub fn print_success(message: &str) {
    println!("{}✓{} {}", colors::ok(), colors::reset(), message);
}

/// Print an error message
pub fn print_error(message: &str) {
    eprintln!("{}✗{} {}", colors::bad_stderr(), colors::reset_stderr(), message);
}

/// Print a warning message
pub fn print_warning(message: &str) {
    println!("{}!{} {}", colors::warn(), colors::reset(), message);
}

/// Print an info message
pub fn print_info(message: &str) {
    println!("{}ℹ{} {}", colors::accent(), colors::reset(), message);
}

/// Print a key-value pair
pub fn print_field(key: &str, value: &str) {
    println!("  {}{:20}{} {}", colors::bold(), key, colors::reset(), value);
}

/// Print a status with color coding
pub fn print_status(label: &str, status: &str, active: bool) {
    let (color, symbol) = if active {
        (colors::ok(), "●")
    } else {
        (colors::bad(), "○")
    };
    println!(
        "  {}{:20}{} {}{}{}",
        colors::bold(),
        label,
        colors::reset(),
        color,
        symbol,
        colors::reset()
    );
    println!("  {:20}   {}", "", status);
}

/// Format load info from JSON for display
pub fn format_load_info(load: &serde_json::Value) -> String {
    let active = load
        .get("active_requests")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let max = load
        .get("max_concurrent")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let util = load
        .get("utilization_percent")
        .and_then(|v| v.as_u64())
        .unwrap_or(0);
    let level = load
        .get("load_level")
        .and_then(|v| v.as_str())
        .unwrap_or("unknown");

    let color = match level {
        "idle" => colors::accent(),
        "available" => colors::ok(),
        "busy" => colors::warn(),
        "near_capacity" => colors::warn(),
        "at_capacity" => colors::bad(),
        _ => colors::reset(),
    };

    format!(
        "{}{} ({}/{}  {}%){}",
        color,
        level,
        active,
        max,
        util,
        colors::reset()
    )
}

/// Create a progress bar for downloads or long operations
pub fn create_progress_bar(total: u64, message: &str) -> ProgressBar {
    let pb = ProgressBar::new(total);
    pb.set_style(
        ProgressStyle::default_bar()
            .template("{msg}\n{spinner:.green} [{elapsed_precise}] [{wide_bar:.cyan/blue}] {bytes}/{total_bytes} ({eta})")
            .unwrap()
            .progress_chars("#>-"),
    );
    pb.set_message(message.to_string());
    pb
}

/// Create a spinner for indefinite operations
pub fn create_spinner(message: &str) -> ProgressBar {
    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.green} {msg}")
            .unwrap()
            .tick_strings(&["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]),
    );
    pb.set_message(message.to_string());
    pb.enable_steady_tick(Duration::from_millis(100));
    pb
}

/// Print a table with headers and rows
pub fn print_table(headers: &[&str], rows: &[Vec<String>]) {
    // Calculate column widths
    let mut widths: Vec<usize> = headers.iter().map(|h| h.len()).collect();

    for row in rows {
        for (i, cell) in row.iter().enumerate() {
            if i < widths.len() && cell.len() > widths[i] {
                widths[i] = cell.len();
            }
        }
    }

    // Print header
    print!("  {}", colors::bold());
    for (i, header) in headers.iter().enumerate() {
        print!(
            "{:width$}",
            header,
            width = widths.get(i).copied().unwrap_or(15) + 2
        );
    }
    println!("{}", colors::reset());

    // Print separator
    print!("  ");
    for width in &widths {
        print!("{}", "─".repeat(width + 2));
    }
    println!();

    // Print rows
    for row in rows {
        print!("  ");
        for (i, cell) in row.iter().enumerate() {
            print!(
                "{:width$}",
                cell,
                width = widths.get(i).copied().unwrap_or(15) + 2
            );
        }
        println!();
    }
    println!();
}

/// Print JSON with pretty formatting
pub fn print_json<T: serde::Serialize>(value: &T) -> anyhow::Result<()> {
    let json = serde_json::to_string_pretty(value)?;
    println!("{}", json);
    Ok(())
}

/// Format a balance amount with decimals
pub fn format_balance(amount: u128, decimals: u8) -> String {
    let divisor = 10u128.pow(decimals as u32);
    let whole = amount / divisor;
    let fraction = amount % divisor;

    if fraction == 0 {
        format!("{}", whole)
    } else {
        let fraction_str = format!("{:0width$}", fraction, width = decimals as usize);
        let trimmed = fraction_str.trim_end_matches('0');
        format!("{}.{}", whole, trimmed)
    }
}

/// Format a hash for display (shortened)
pub fn format_hash(hash: &str) -> String {
    if hash.len() > 16 {
        format!("{}...{}", &hash[..8], &hash[hash.len() - 8..])
    } else {
        hash.to_string()
    }
}

/// Format an address for display (shortened)
pub fn format_address(address: &str) -> String {
    if address.len() > 16 {
        format!("{}...{}", &address[..8], &address[address.len() - 8..])
    } else {
        address.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_balance() {
        assert_eq!(format_balance(1_000_000_000_000_000_000, 18), "1");
        assert_eq!(format_balance(1_500_000_000_000_000_000, 18), "1.5");
        assert_eq!(format_balance(123_456_789_000_000_000, 18), "0.123456789");
        assert_eq!(format_balance(0, 18), "0");
    }

    #[test]
    fn test_format_hash() {
        let hash = "1234567890abcdef1234567890abcdef";
        assert_eq!(format_hash(hash), "12345678...90abcdef");
        assert_eq!(format_hash("short"), "short");
    }

    #[test]
    fn test_format_address() {
        let addr = "tenzro1234567890abcdef1234567890abcdef";
        assert_eq!(format_address(addr), "tenzro12...90abcdef");
    }
}

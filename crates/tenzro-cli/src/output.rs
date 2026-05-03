//! Output formatting utilities for the Tenzro CLI
//!
//! This module provides helpers for formatted console output including
//! tables, progress bars, colored status messages, and banners.

use indicatif::{ProgressBar, ProgressStyle};
use std::time::Duration;

/// Color codes for terminal output
pub mod colors {
    pub const GREEN: &str = "\x1b[32m";
    pub const RED: &str = "\x1b[31m";
    pub const YELLOW: &str = "\x1b[33m";
    pub const BLUE: &str = "\x1b[34m";
    pub const CYAN: &str = "\x1b[36m";
    pub const BOLD: &str = "\x1b[1m";
    pub const RESET: &str = "\x1b[0m";
}

/// Print the Tenzro CLI banner
pub fn print_banner() {
    println!("{}", colors::BOLD);
    println!("╔═══════════════════════════════════════════════════════════╗");
    println!("║                                                           ║");
    println!("║              {}Tenzro Network CLI v0.1.0{}               ║", colors::CYAN, colors::BOLD);
    println!("║                                                           ║");
    println!("║      AI-Native, Agentic, Tokenized Settlement Layer      ║");
    println!("║                                                           ║");
    println!("╚═══════════════════════════════════════════════════════════╝");
    println!("{}", colors::RESET);
}

/// Print a section header
pub fn print_header(title: &str) {
    println!("\n{}{}{}{}:", colors::BOLD, colors::CYAN, title, colors::RESET);
    println!("{}", "─".repeat(60));
}

/// Print a success message
pub fn print_success(message: &str) {
    println!("{}✓{} {}", colors::GREEN, colors::RESET, message);
}

/// Print an error message
pub fn print_error(message: &str) {
    eprintln!("{}✗{} {}", colors::RED, colors::RESET, message);
}

/// Print a warning message
pub fn print_warning(message: &str) {
    println!("{}⚠{} {}", colors::YELLOW, colors::RESET, message);
}

/// Print an info message
pub fn print_info(message: &str) {
    println!("{}ℹ{} {}", colors::BLUE, colors::RESET, message);
}

/// Print a key-value pair
pub fn print_field(key: &str, value: &str) {
    println!("  {}{:20}{} {}", colors::BOLD, key, colors::RESET, value);
}

/// Print a status with color coding
pub fn print_status(label: &str, status: &str, active: bool) {
    let (color, symbol) = if active {
        (colors::GREEN, "●")
    } else {
        (colors::RED, "○")
    };
    println!("  {}{:20}{} {}{}{}", colors::BOLD, label, colors::RESET, color, symbol, colors::RESET);
    println!("  {:20}   {}", "", status);
}

/// Format load info from JSON for display
pub fn format_load_info(load: &serde_json::Value) -> String {
    let active = load.get("active_requests").and_then(|v| v.as_u64()).unwrap_or(0);
    let max = load.get("max_concurrent").and_then(|v| v.as_u64()).unwrap_or(0);
    let util = load.get("utilization_percent").and_then(|v| v.as_u64()).unwrap_or(0);
    let level = load.get("load_level").and_then(|v| v.as_str()).unwrap_or("unknown");

    let color = match level {
        "idle" => colors::CYAN,
        "available" => colors::GREEN,
        "busy" => colors::YELLOW,
        "near_capacity" => colors::YELLOW,
        "at_capacity" => colors::RED,
        _ => colors::RESET,
    };

    format!("{}{} ({}/{}  {}%){}", color, level, active, max, util, colors::RESET)
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
    print!("  {}", colors::BOLD);
    for (i, header) in headers.iter().enumerate() {
        print!("{:width$}", header, width = widths.get(i).copied().unwrap_or(15) + 2);
    }
    println!("{}", colors::RESET);

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
            print!("{:width$}", cell, width = widths.get(i).copied().unwrap_or(15) + 2);
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
        format!("{}...{}", &hash[..8], &hash[hash.len()-8..])
    } else {
        hash.to_string()
    }
}

/// Format an address for display (shortened)
pub fn format_address(address: &str) -> String {
    if address.len() > 16 {
        format!("{}...{}", &address[..8], &address[address.len()-8..])
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

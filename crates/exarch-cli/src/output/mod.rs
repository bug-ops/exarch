//! Output formatting module.

mod formatter;
mod human;
mod json;

pub use formatter::OutputFormatter;

use human::HumanFormatter;
use json::JsonFormatter;

/// Creates an output formatter based on CLI flags
pub fn create_formatter(json: bool, verbose: bool, quiet: bool) -> Box<dyn OutputFormatter> {
    if json {
        Box::new(JsonFormatter::stdout())
    } else {
        Box::new(HumanFormatter::new(verbose, quiet))
    }
}

/// Converts a byte count into a human-readable string using binary
/// (1024-based) units, tiered from bytes up to terabytes.
pub fn humanize_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;
    const TB: u64 = GB * 1024;

    if bytes >= TB {
        format!("{:.1} TB", bytes as f64 / TB as f64)
    } else if bytes >= GB {
        format!("{:.1} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} KB", bytes as f64 / KB as f64)
    } else {
        format!("{bytes} B")
    }
}

#[cfg(test)]
mod tests {
    use super::humanize_bytes;

    #[test]
    fn test_humanize_bytes_bytes() {
        assert_eq!(humanize_bytes(0), "0 B");
        assert_eq!(humanize_bytes(512), "512 B");
        assert_eq!(humanize_bytes(1023), "1023 B");
    }

    #[test]
    fn test_humanize_bytes_kilobytes() {
        assert_eq!(humanize_bytes(1024), "1.0 KB");
        assert_eq!(humanize_bytes(1536), "1.5 KB");
        assert_eq!(humanize_bytes(2048), "2.0 KB");
    }

    #[test]
    fn test_humanize_bytes_megabytes() {
        assert_eq!(humanize_bytes(1024 * 1024), "1.0 MB");
        assert_eq!(humanize_bytes(1536 * 1024), "1.5 MB");
        assert_eq!(humanize_bytes(2 * 1024 * 1024), "2.0 MB");
    }

    #[test]
    fn test_humanize_bytes_gigabytes() {
        assert_eq!(humanize_bytes(1024 * 1024 * 1024), "1.0 GB");
        assert_eq!(humanize_bytes(1536 * 1024 * 1024), "1.5 GB");
        assert_eq!(humanize_bytes(2 * 1024 * 1024 * 1024), "2.0 GB");
    }

    #[test]
    fn test_humanize_bytes_terabytes() {
        assert_eq!(humanize_bytes(1024_u64.pow(4)), "1.0 TB");
    }

    #[test]
    fn test_humanize_bytes_edge_cases() {
        // u64::MAX = 18446744073709551615 bytes = 16777216.0 TB (TB = 1024^4)
        assert_eq!(humanize_bytes(u64::MAX), "16777216.0 TB");
    }
}

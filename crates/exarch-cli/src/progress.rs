//! Progress bar implementation for CLI operations.

use console::Term;
use exarch_core::ProgressCallback;
use indicatif::ProgressBar;
use indicatif::ProgressStyle;
use std::path::Path;

/// CLI progress bar wrapper implementing `ProgressCallback`.
///
/// Displays a progress bar driven by entry count (`{pos}/{len} files`).
/// Bytes written are shown in the message suffix and updated independently so
/// that byte accumulation does not corrupt the entry counter. Automatically
/// cleans up on drop.
pub struct CliProgress {
    bar: ProgressBar,
    label: String,
    bytes_written: u64,
}

impl CliProgress {
    /// Creates a new CLI progress bar.
    ///
    /// # Arguments
    ///
    /// * `total` - Total number of entries to process
    /// * `message` - Label displayed before the bar (e.g., "Extracting")
    #[must_use]
    pub fn new(total: usize, message: &str) -> Self {
        let bar = ProgressBar::new(total as u64);

        // Template: "Extracting [████████░░░░] 42/100 files"
        // Bytes are appended via set_message to keep pos/len as entry counts.
        bar.set_style(
            ProgressStyle::default_bar()
                .template("{msg} [{bar:40.cyan/blue}] {pos}/{len} files")
                .unwrap_or_else(|_| ProgressStyle::default_bar())
                .progress_chars("█▓░"),
        );

        bar.set_message(message.to_string());

        Self {
            bar,
            label: message.to_string(),
            bytes_written: 0,
        }
    }

    /// Checks if we should show progress (TTY detection).
    #[must_use]
    pub fn should_show() -> bool {
        Term::stdout().is_term()
    }
}

impl Drop for CliProgress {
    fn drop(&mut self) {
        self.bar.finish_and_clear();
    }
}

impl ProgressCallback for CliProgress {
    fn on_entry_start(&mut self, _path: &Path, _total: usize, _current: usize) {}

    fn on_bytes_written(&mut self, bytes: u64) {
        self.bytes_written += bytes;
        self.bar.set_message(format!(
            "{} ({})",
            self.label,
            humanize_bytes(self.bytes_written)
        ));
    }

    fn on_entry_complete(&mut self, _path: &Path) {
        self.bar.inc(1);
    }

    fn on_complete(&mut self) {
        self.bar.finish_and_clear();
    }
}

/// Per-entry verbose progress that prints one line per archive entry to stderr.
///
/// Activated when `--verbose` is set and `--quiet` is not. Prints each entry
/// name as it starts processing. No TTY detection is required — output is
/// always plain text.
///
/// # Examples
///
/// ```no_run
/// use exarch_core::ProgressCallback;
/// use std::path::Path;
///
/// let mut p = VerboseProgress::new();
/// p.on_entry_start(Path::new("data/file.txt"), 10, 0);
/// p.on_entry_complete(Path::new("data/file.txt"));
/// p.on_complete();
/// ```
#[derive(Debug, Default)]
pub struct VerboseProgress;

impl VerboseProgress {
    /// Creates a new `VerboseProgress` instance.
    #[must_use]
    pub fn new() -> Self {
        Self
    }
}

impl ProgressCallback for VerboseProgress {
    fn on_entry_start(&mut self, path: &Path, _total: usize, _current: usize) {
        eprintln!("  extract  {}", path.display());
    }

    fn on_bytes_written(&mut self, _bytes: u64) {}

    fn on_entry_complete(&mut self, _path: &Path) {}

    fn on_complete(&mut self) {}
}

/// Converts bytes to human-readable format (KB, MB, GB, TB).
fn humanize_bytes(bytes: u64) -> String {
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
    use super::*;

    #[test]
    fn test_humanize_bytes() {
        assert_eq!(humanize_bytes(0), "0 B");
        assert_eq!(humanize_bytes(512), "512 B");
        assert_eq!(humanize_bytes(1024), "1.0 KB");
        assert_eq!(humanize_bytes(1536), "1.5 KB");
        assert_eq!(humanize_bytes(1024 * 1024), "1.0 MB");
        assert_eq!(humanize_bytes(1024 * 1024 * 1024), "1.0 GB");
        assert_eq!(humanize_bytes(1024_u64.pow(4)), "1.0 TB");
    }

    #[test]
    fn test_verbose_progress_no_panic() {
        let mut p = VerboseProgress::new();
        p.on_entry_start(Path::new("data/file.txt"), 10, 0);
        p.on_bytes_written(512);
        p.on_entry_complete(Path::new("data/file.txt"));
        p.on_complete();
    }

    #[test]
    fn test_progress_callback() {
        let mut progress = CliProgress::new(100, "Testing");

        // Simulate processing entries
        progress.on_entry_start(Path::new("test.txt"), 100, 1);
        progress.on_bytes_written(1024);
        progress.on_entry_complete(Path::new("test.txt"));

        assert_eq!(progress.bytes_written, 1024);
    }
}

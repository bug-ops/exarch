//! Progress bar implementation for CLI operations.

use console::Term;
use exarch_core::ProgressCallback;
use indicatif::ProgressBar;
use indicatif::ProgressState;
use indicatif::ProgressStyle;
use std::fmt::Write;
use std::path::Path;

/// CLI progress bar wrapper implementing `ProgressCallback`.
///
/// Displays a progress bar with file count, bytes processed, speed, and ETA
/// when running in a TTY. Automatically cleans up on drop.
pub struct CliProgress {
    bar: ProgressBar,
    bytes_written: u64,
}

impl CliProgress {
    /// Creates a new CLI progress bar.
    ///
    /// # Arguments
    ///
    /// * `total` - Total number of entries to process
    /// * `message` - Message to display (e.g., "Extracting", "Creating")
    #[must_use]
    pub fn new(total: usize, message: &str) -> Self {
        let bar = ProgressBar::new(total as u64);

        // Template: "Extracting [████████░░░░] 42/100 files (15.2 MB, 5.1 MB/s, 12s)"
        bar.set_style(
            ProgressStyle::default_bar()
                .template(
                    "{msg} [{bar:40.cyan/blue}] {pos}/{len} files ({bytes}, {bytes_per_sec}, {eta})",
                )
                .unwrap_or_else(|_| ProgressStyle::default_bar())
                .with_key("bytes", |state: &ProgressState, w: &mut dyn Write| {
                    write!(w, "{}", humanize_bytes(state.pos())).unwrap_or(());
                })
                .with_key("bytes_per_sec", |state: &ProgressState, w: &mut dyn Write| {
                    let per_sec = state.per_sec();
                    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
                    let bytes_per_sec = per_sec as u64;
                    write!(w, "{}/s", humanize_bytes(bytes_per_sec)).unwrap_or(());
                })
                .with_key("eta", |state: &ProgressState, w: &mut dyn Write| {
                    let eta = state.eta();
                    write!(w, "{}", humanize_duration(eta)).unwrap_or(());
                })
                .progress_chars("█▓░"),
        );

        bar.set_message(message.to_string());

        Self {
            bar,
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
    fn on_entry_start(&mut self, _path: &Path, _total: usize, _current: usize) {
        // Entry start is handled by on_entry_complete incrementing the counter
    }

    fn on_bytes_written(&mut self, bytes: u64) {
        self.bytes_written += bytes;
        self.bar.set_position(self.bytes_written);
    }

    fn on_entry_complete(&mut self, _path: &Path) {
        self.bar.inc(1);
    }

    fn on_complete(&mut self) {
        self.bar.finish_and_clear();
    }
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

/// Converts duration to human-readable format.
fn humanize_duration(duration: std::time::Duration) -> String {
    let secs = duration.as_secs();
    if secs >= 3600 {
        format!("{}h{}m", secs / 3600, (secs % 3600) / 60)
    } else if secs >= 60 {
        format!("{}m{}s", secs / 60, secs % 60)
    } else {
        format!("{secs}s")
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
    fn test_humanize_duration() {
        assert_eq!(humanize_duration(std::time::Duration::from_secs(0)), "0s");
        assert_eq!(humanize_duration(std::time::Duration::from_secs(30)), "30s");
        assert_eq!(
            humanize_duration(std::time::Duration::from_secs(90)),
            "1m30s"
        );
        assert_eq!(
            humanize_duration(std::time::Duration::from_secs(3661)),
            "1h1m"
        );
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

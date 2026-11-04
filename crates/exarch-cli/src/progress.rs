//! Progress bar implementation for CLI operations.

use crate::output::humanize_bytes;
use crate::output::terminal::TerminalPath;
use console::Term;
use exarch_core::EntryPosition;
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
    sized: bool,
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
        bar.set_style(Self::sized_style());
        bar.set_message(message.to_string());

        Self {
            bar,
            label: message.to_string(),
            bytes_written: 0,
            sized: true,
        }
    }

    /// Creates a progress bar for a run whose entry total is not known up
    /// front.
    ///
    /// It shows a plain entry count until `on_entry_start` reports a non-zero
    /// total (ZIP and 7z know theirs; a TAR stream does not), then becomes a
    /// regular bar.
    ///
    /// # Arguments
    ///
    /// * `message` - Label displayed before the count (e.g., "Extracting")
    #[must_use]
    pub fn counting(message: &str) -> Self {
        let bar = ProgressBar::new_spinner();
        bar.set_style(
            ProgressStyle::default_spinner()
                .template("{msg} {pos} files")
                .unwrap_or_else(|_| ProgressStyle::default_spinner()),
        );
        bar.set_message(message.to_string());

        Self {
            bar,
            label: message.to_string(),
            bytes_written: 0,
            sized: false,
        }
    }

    // Template: "Extracting [████████░░░░] 42/100 files". Bytes are appended
    // via set_message to keep pos/len as entry counts.
    fn sized_style() -> ProgressStyle {
        ProgressStyle::default_bar()
            .template("{msg} [{bar:40.cyan/blue}] {pos}/{len} files")
            .unwrap_or_else(|_| ProgressStyle::default_bar())
            .progress_chars("█▓░")
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
    fn on_entry_start(&mut self, _path: &Path, position: EntryPosition) {
        if !self.sized
            && let Some(total) = position.total.known().filter(|total| *total > 0)
        {
            self.sized = true;
            self.bar.set_length(total as u64);
            self.bar.set_style(Self::sized_style());
        }
    }

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
/// p.on_entry_start(
///     Path::new("data/file.txt"),
///     EntryPosition::at_index(0, EntryTotal::Known(10)),
/// );
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
    fn on_entry_start(&mut self, path: &Path, _position: EntryPosition) {
        eprintln!("  extract  {}", TerminalPath::new(path));
    }

    fn on_bytes_written(&mut self, _bytes: u64) {}

    fn on_entry_complete(&mut self, _path: &Path) {}

    fn on_complete(&mut self) {}
}

#[cfg(test)]
mod tests {
    use super::*;
    use exarch_core::EntryTotal;

    #[test]
    fn test_verbose_progress_no_panic() {
        let mut p = VerboseProgress::new();
        p.on_entry_start(
            Path::new("data/file.txt"),
            EntryPosition::at_index(0, EntryTotal::Known(10)),
        );
        p.on_bytes_written(512);
        p.on_entry_complete(Path::new("data/file.txt"));
        p.on_complete();
    }

    #[test]
    fn test_progress_callback() {
        let mut progress = CliProgress::new(100, "Testing");

        // Simulate processing entries
        progress.on_entry_start(
            Path::new("test.txt"),
            EntryPosition::at_index(0, EntryTotal::Known(100)),
        );
        progress.on_bytes_written(1024);
        progress.on_entry_complete(Path::new("test.txt"));

        assert_eq!(progress.bytes_written, 1024);
    }

    #[test]
    fn test_counting_progress_becomes_sized_once_total_is_known() {
        let mut progress = CliProgress::counting("Testing");
        assert!(!progress.sized);

        progress.on_entry_start(
            Path::new("a"),
            EntryPosition::at_index(0, EntryTotal::Unknown),
        );
        assert!(!progress.sized);

        progress.on_entry_start(
            Path::new("b"),
            EntryPosition::at_index(1, EntryTotal::Known(7)),
        );
        assert!(progress.sized);
        assert_eq!(progress.bar.length(), Some(7));
    }
}

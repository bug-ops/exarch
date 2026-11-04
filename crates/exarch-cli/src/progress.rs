//! Progress bar implementation for CLI operations.

use crate::operation::Operation;
use crate::output::OutputMode;
use crate::output::Verbosity;
use crate::output::humanize_bytes;
use crate::output::terminal::TerminalPath;
use console::Term;
use exarch_core::EntryPosition;
use exarch_core::EntryTotal;
use exarch_core::NoopProgress;
use exarch_core::ProgressCallback;
use indicatif::ProgressBar;
use indicatif::ProgressStyle;
use std::path::Path;

/// How many entries a progress bar counts to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BarLength {
    /// The total is known before the run starts.
    Known(usize),
    /// The total is not known up front: the bar counts entries until core
    /// reports one.
    Discover,
}

/// The progress reporter `operation` runs with under `mode`: per-entry lines
/// when verbose, a bar on a terminal, and nothing when quiet, in `--json`
/// mode or when stdout is not a terminal.
pub fn progress_for(
    mode: OutputMode,
    length: BarLength,
    operation: Operation,
) -> Box<dyn ProgressCallback> {
    match mode {
        OutputMode::Json | OutputMode::Human(Verbosity::Quiet) => Box::new(NoopProgress),
        OutputMode::Human(Verbosity::Verbose) => Box::new(VerboseProgress::new(operation)),
        OutputMode::Human(Verbosity::Normal) => {
            if CliProgress::should_show() {
                Box::new(CliProgress::new(length, operation_label(operation)))
            } else {
                Box::new(NoopProgress)
            }
        }
    }
}

const fn operation_label(operation: Operation) -> &'static str {
    match operation {
        Operation::Extract => "Extracting",
        Operation::Create => "Creating",
        Operation::List => "Listing",
        Operation::Verify => "Verifying",
    }
}

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
    /// Creates a CLI progress bar.
    ///
    /// # Arguments
    ///
    /// * `length` - How many entries the bar counts to
    /// * `message` - Label displayed before the bar (e.g., "Extracting")
    #[must_use]
    pub fn new(length: BarLength, message: &str) -> Self {
        match length {
            BarLength::Known(total) => Self::sized(total, message),
            BarLength::Discover => Self::counting(message),
        }
    }

    fn sized(total: usize, message: &str) -> Self {
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
    fn counting(message: &str) -> Self {
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
    fn should_show() -> bool {
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
        if self.sized {
            return;
        }
        if let EntryTotal::Known(total) = position.total
            && total > 0
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
/// let mut p = VerboseProgress::new(Operation::Extract);
/// p.on_entry_start(
///     Path::new("data/file.txt"),
///     position(1, EntryTotal::Known(10)),
/// );
/// p.on_entry_complete(Path::new("data/file.txt"));
/// p.on_complete();
/// ```
#[derive(Debug)]
pub struct VerboseProgress {
    operation: Operation,
}

impl VerboseProgress {
    /// Creates a reporter that prefixes each entry line with the operation.
    #[must_use]
    pub const fn new(operation: Operation) -> Self {
        Self { operation }
    }
}

impl ProgressCallback for VerboseProgress {
    fn on_entry_start(&mut self, path: &Path, _position: EntryPosition) {
        eprintln!("  {}  {}", self.operation.name(), TerminalPath::new(path));
    }

    fn on_bytes_written(&mut self, _bytes: u64) {}

    fn on_entry_complete(&mut self, _path: &Path) {}

    fn on_complete(&mut self) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    fn position(current: usize, total: EntryTotal) -> EntryPosition {
        EntryPosition::at_index(current - 1, total)
    }

    #[test]
    fn test_verbose_progress_no_panic() {
        let mut p = VerboseProgress::new(Operation::Extract);
        p.on_entry_start(
            Path::new("data/file.txt"),
            position(1, EntryTotal::Known(10)),
        );
        p.on_bytes_written(512);
        p.on_entry_complete(Path::new("data/file.txt"));
        p.on_complete();
    }

    #[test]
    fn test_progress_callback() {
        let mut progress = CliProgress::new(BarLength::Known(100), "Testing");

        // Simulate processing entries
        progress.on_entry_start(Path::new("test.txt"), position(1, EntryTotal::Known(100)));
        progress.on_bytes_written(1024);
        progress.on_entry_complete(Path::new("test.txt"));

        assert_eq!(progress.bytes_written, 1024);
    }

    #[test]
    fn test_counting_progress_becomes_sized_once_total_is_known() {
        let mut progress = CliProgress::new(BarLength::Discover, "Testing");
        assert!(!progress.sized);

        progress.on_entry_start(Path::new("a"), position(1, EntryTotal::Unknown));
        assert!(!progress.sized);

        progress.on_entry_start(Path::new("b"), position(2, EntryTotal::Known(7)));
        assert!(progress.sized);
        assert_eq!(progress.bar.length(), Some(7));
    }
}

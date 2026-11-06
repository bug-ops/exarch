//! Turns SIGINT and SIGTERM into a cancelled run.
//!
//! Only `extract` and `create` install the handler: they stage their output,
//! and core removes the staging entry when [`ProgressCallback::is_cancelled`]
//! reports a stop. The commands that write nothing keep the default signal
//! action, so Ctrl-C ends them at once.
//!
//! Cancellation takes effect at entry boundaries; one very large entry is
//! finished first, and for `extract` the pre-extraction listing pass runs to
//! its end before the first poll. A second signal gives up waiting and exits
//! at once with [`FORCED_EXIT_CODE`].
//!
//! WASI has no signals, so the handler is not installed there.

use exarch_core::EntryPosition;
use exarch_core::ProgressCallback;
use std::path::Path;
#[cfg(not(target_os = "wasi"))]
use std::path::PathBuf;
#[cfg(not(target_os = "wasi"))]
use std::sync::OnceLock;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;

/// The exit status of an interrupted run.
pub const FORCED_EXIT_CODE: u8 = 130;

/// What a received signal means for the run.
#[cfg(not(target_os = "wasi"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Signal {
    /// The first signal: stop at the next entry boundary.
    First,
    /// A later signal: stop waiting.
    Repeated,
}

/// Whether a stop was asked for.
#[derive(Debug, Default)]
pub struct Interrupt(AtomicBool);

impl Interrupt {
    /// An interrupt that was not requested.
    #[must_use]
    pub const fn new() -> Self {
        Self(AtomicBool::new(false))
    }

    /// Records a signal and says whether it is the first.
    #[cfg(not(target_os = "wasi"))]
    pub fn request(&self) -> Signal {
        if self.0.swap(true, Ordering::SeqCst) {
            Signal::Repeated
        } else {
            Signal::First
        }
    }

    /// Whether a signal arrived.
    pub fn requested(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
}

static INTERRUPT: Interrupt = Interrupt::new();
#[cfg(not(target_os = "wasi"))]
static OUTPUT: OnceLock<PathBuf> = OnceLock::new();

/// Whether the process was asked to stop.
pub fn requested() -> bool {
    INTERRUPT.requested()
}

/// What the forced exit tells the user to look for.
///
/// `.exarch-backup-*` holds the only copy of the original destination between
/// the moment an atomic replace moves it aside and the moment the new content
/// takes its place, so it is named apart from the staging entries that are safe
/// to delete.
#[cfg(not(target_os = "wasi"))]
fn forced_exit_hint(output: &Path) -> String {
    let place = match output.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.display().to_string(),
        _ => "the current directory".to_owned(),
    };
    format!(
        "interrupted again, stopping at once; unfinished staging entries named .exarch-* may \
         remain in {place}: remove them, but if {output} is missing, rename the \
         .exarch-backup-* entry there back to {output} first, since it holds the original",
        output = output.display(),
    )
}

#[cfg(not(target_os = "wasi"))]
fn on_signal() {
    if INTERRUPT.request() == Signal::Repeated {
        if let Some(output) = OUTPUT.get() {
            eprintln!("{}", forced_exit_hint(output));
        }
        std::process::exit(i32::from(FORCED_EXIT_CODE));
    }
}

/// Starts turning SIGINT and SIGTERM into a cancelled run of the command that
/// writes `output`. A handler that cannot be installed is reported and the
/// default signal action stays.
#[cfg(not(target_os = "wasi"))]
pub fn install(output: &Path) {
    OUTPUT.get_or_init(|| output.to_path_buf());
    if let Err(error) = ctrlc::set_handler(on_signal) {
        eprintln!("warning: cannot install the interrupt handler: {error}");
    }
}

/// WASI has no signals; there is nothing to install.
#[cfg(target_os = "wasi")]
pub const fn install(_output: &Path) {}

/// Wraps a reporter so that a requested stop cancels the run.
pub struct Interruptible {
    inner: Box<dyn ProgressCallback>,
    interrupt: &'static Interrupt,
}

impl Interruptible {
    /// `inner` reporting, stopping when the process is asked to.
    pub fn new(inner: Box<dyn ProgressCallback>) -> Self {
        Self::watching(inner, &INTERRUPT)
    }

    const fn watching(inner: Box<dyn ProgressCallback>, interrupt: &'static Interrupt) -> Self {
        Self { inner, interrupt }
    }
}

impl ProgressCallback for Interruptible {
    fn on_entry_start(&mut self, path: &Path, position: EntryPosition) {
        self.inner.on_entry_start(path, position);
    }

    fn on_bytes_written(&mut self, bytes: u64) {
        self.inner.on_bytes_written(bytes);
    }

    fn on_entry_complete(&mut self, path: &Path) {
        self.inner.on_entry_complete(path);
    }

    fn on_complete(&mut self) {
        self.inner.on_complete();
    }

    fn is_cancelled(&mut self) -> bool {
        self.interrupt.requested() || self.inner.is_cancelled()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use exarch_core::NoopProgress;

    #[cfg(not(target_os = "wasi"))]
    #[test]
    fn the_first_signal_is_first_and_the_next_are_repeated() {
        let interrupt = Interrupt::new();
        assert!(!interrupt.requested());
        assert_eq!(interrupt.request(), Signal::First);
        assert!(interrupt.requested());
        assert_eq!(interrupt.request(), Signal::Repeated);
    }

    #[test]
    fn a_requested_stop_cancels_the_wrapped_reporter() {
        static WATCHED: Interrupt = Interrupt::new();
        let mut progress = Interruptible::watching(Box::new(NoopProgress), &WATCHED);
        assert!(!progress.is_cancelled());
        WATCHED.request();
        assert!(progress.is_cancelled());
    }

    #[cfg(not(target_os = "wasi"))]
    #[test]
    fn the_forced_exit_hint_names_the_backup_apart_from_the_staging_entries() {
        let hint = forced_exit_hint(Path::new("work/out"));
        assert!(hint.contains("in work:"), "{hint}");
        assert!(hint.contains("rename the .exarch-backup-* entry"), "{hint}");
        assert!(hint.contains("work/out"), "{hint}");
        assert!(forced_exit_hint(Path::new("out")).contains("in the current directory:"));
    }
}

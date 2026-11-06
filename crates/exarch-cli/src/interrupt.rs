//! Turns SIGINT into a cancelled run.
//!
//! Only SIGINT is handled: SIGTERM and SIGHUP keep their default action, so a
//! `nohup`-ed run still ignores SIGHUP and `kill` still ends the process at
//! once.
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
#[cfg(not(target_os = "wasi"))]
use std::io::Write as _;
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
static OUTPUT: OnceLock<(PathBuf, Run)> = OnceLock::new();

/// Whether the process was asked to stop.
pub fn requested() -> bool {
    INTERRUPT.requested()
}

/// What the interrupted command leaves on disk, which decides what the forced
/// exit tells the user to look for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Run {
    /// `create`: stages the archive in a temporary file next to the output.
    Create,
    /// `extract` without `--atomic`: writes into the destination, or, for a
    /// TAR into a fresh destination, stages like `--atomic`.
    ExtractInPlace,
    /// `extract --atomic`: stages in a directory next to the destination.
    ExtractAtomic,
    /// `extract --atomic --force`: also moves an existing destination aside.
    ExtractReplace,
}

/// What the forced exit tells the user to look for.
///
/// `.exarch-backup-*` holds the only copy of the original destination between
/// the moment an atomic replace moves it aside and the moment the new content
/// takes its place, so it is named apart from the staging entries that are safe
/// to delete, and only for the run that makes one.
#[cfg(not(target_os = "wasi"))]
fn forced_exit_hint(output: &Path, run: Run) -> String {
    let place = match output.parent() {
        Some(parent) if !parent.as_os_str().is_empty() => parent.display().to_string(),
        _ => "the current directory".to_owned(),
    };
    let output = output.display();
    match run {
        Run::Create => format!(
            "interrupted again, stopping at once; an unfinished temporary file named .exarch-* \
             may remain in {place}: remove it"
        ),
        Run::ExtractInPlace => format!(
            "interrupted again, stopping at once; entries already extracted into {output} \
             remain, or, for a destination that did not exist, an unfinished staging directory \
             named .exarch-* may remain in {place}: remove it"
        ),
        Run::ExtractAtomic => format!(
            "interrupted again, stopping at once; an unfinished staging directory named \
             .exarch-* may remain in {place}: remove it"
        ),
        Run::ExtractReplace => format!(
            "interrupted again, stopping at once; unfinished staging entries named .exarch-* may \
             remain in {place}: remove them, but if {output} is missing, rename the \
             .exarch-backup-* entry there back to {output} first, since it holds the original"
        ),
    }
}

#[cfg(not(target_os = "wasi"))]
fn on_signal() {
    if INTERRUPT.request() == Signal::Repeated {
        if let Some((output, run)) = OUTPUT.get() {
            // A closed stderr must not stop the exit below.
            let _ = writeln!(std::io::stderr(), "{}", forced_exit_hint(output, *run));
        }
        std::process::exit(i32::from(FORCED_EXIT_CODE));
    }
}

/// Starts turning SIGINT into a cancelled run of the command that
/// writes `output`. A handler that cannot be installed is reported and the
/// default signal action stays.
#[cfg(not(target_os = "wasi"))]
pub fn install(output: &Path, run: Run) {
    OUTPUT.get_or_init(|| (output.to_path_buf(), run));
    if let Err(error) = ctrlc::set_handler(on_signal) {
        eprintln!("warning: cannot install the interrupt handler: {error}");
    }
}

/// WASI has no signals; there is nothing to install.
#[cfg(target_os = "wasi")]
pub const fn install(_output: &Path, _run: Run) {}

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
    #[cfg(not(target_os = "wasi"))]
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

    #[cfg(not(target_os = "wasi"))]
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
    fn only_a_replace_names_the_backup() {
        let replace = forced_exit_hint(Path::new("work/out"), Run::ExtractReplace);
        assert!(replace.contains("in work:"), "{replace}");
        assert!(
            replace.contains("rename the .exarch-backup-* entry"),
            "{replace}"
        );
        for run in [Run::Create, Run::ExtractInPlace, Run::ExtractAtomic] {
            let hint = forced_exit_hint(Path::new("work/out"), run);
            assert!(!hint.contains("backup"), "{run:?}: {hint}");
        }
    }

    #[cfg(not(target_os = "wasi"))]
    #[test]
    fn each_run_names_what_it_leaves() {
        let create = forced_exit_hint(Path::new("o.tar"), Run::Create);
        assert!(
            create.contains("temporary file named .exarch-*"),
            "{create}"
        );
        assert!(create.contains("in the current directory"), "{create}");
        let atomic = forced_exit_hint(Path::new("work/out"), Run::ExtractAtomic);
        assert!(
            atomic.contains("staging directory named .exarch-*"),
            "{atomic}"
        );
        let in_place = forced_exit_hint(Path::new("work/out"), Run::ExtractInPlace);
        assert!(in_place.contains("work/out"), "{in_place}");
        assert!(
            in_place.contains("staging directory named .exarch-*"),
            "{in_place}"
        );
        assert!(!in_place.contains("backup"), "{in_place}");
    }
}

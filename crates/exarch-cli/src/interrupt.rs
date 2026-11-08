//! Turns SIGINT and SIGTERM into a cancelled run, for exactly as long as the
//! run can honour it.
//!
//! Only `extract` and `create` arm the handler, through [`install`]: they stage
//! their output, and core removes the staging entry when
//! [`ProgressCallback::is_cancelled`] reports a stop. The returned
//! [`InterruptGuard`] is the armed window. Dropping it, which the commands do
//! before they print results, disarms the handler: a signal that arrives later
//! gets the default action at once, so Ctrl-C during output ends the process
//! instead of being swallowed. The commands that write nothing (`list`,
//! `verify`, `completion`) never install it and keep the default action
//! throughout.
//!
//! A first signal while armed stops the run at the next poll and the process
//! exits with [`ExitStatus::Interrupted`] (SIGINT) or
//! [`ExitStatus::Terminated`] (SIGTERM). A second signal gives up waiting and
//! exits at once with the same status; under `--json` it writes a minimal
//! `Cancelled` error document to stdout first, so the one-document contract
//! holds, and otherwise a hint on stderr naming what the run left behind.
//!
//! SIGHUP is deliberately not handled: a `nohup`-ed run ignores it, and
//! handling it here would override that. A disposition inherited as ignored
//! cannot be detected without `unsafe`, so SIGINT or SIGTERM that the parent
//! ignored is still turned into a cancel.
//!
//! Core polls at entry boundaries and every few MiB inside one entry's copy,
//! and the `extract` pre-extraction listing polls per entry, so the first
//! signal is effective without the forced path except inside one decoder call.
//!
//! On Unix the signals are read on a helper thread through `signal-hook`; on
//! Windows `ctrlc` reports Ctrl-C and Ctrl-Break as an interrupt. WASI has no
//! signals, so nothing is installed there.

#[cfg(not(target_os = "wasi"))]
use crate::exit::ExitStatus;
#[cfg(not(target_os = "wasi"))]
use crate::operation::Operation;
use crate::output::OutputMode;
use exarch_core::EntryPosition;
use exarch_core::NoopProgress;
use exarch_core::ProgressCallback;
#[cfg(not(target_os = "wasi"))]
use exarch_core::path_text;
use std::path::Path;
#[cfg(not(target_os = "wasi"))]
use std::path::PathBuf;
use std::sync::atomic::AtomicU8;
use std::sync::atomic::Ordering;

/// Why the process was asked to stop; decides its exit status.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stop {
    /// SIGINT, or Ctrl-C and Ctrl-Break on Windows.
    Interrupt,
    /// SIGTERM.
    Terminate,
}

impl Stop {
    #[cfg(not(target_os = "wasi"))]
    const fn encode(self) -> u8 {
        match self {
            Self::Interrupt => 1,
            Self::Terminate => 2,
        }
    }

    const fn decode(code: u8) -> Option<Self> {
        match code {
            1 => Some(Self::Interrupt),
            2 => Some(Self::Terminate),
            _ => None,
        }
    }

    #[cfg(unix)]
    const fn raw_signal(self) -> std::ffi::c_int {
        match self {
            Self::Interrupt => signal_hook::consts::SIGINT,
            Self::Terminate => signal_hook::consts::SIGTERM,
        }
    }
}

/// What a received stop request means for the run.
#[cfg(not(target_os = "wasi"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Signal {
    /// The first request: stop at the next poll.
    First,
    /// A later request: stop waiting.
    Repeated,
}

/// Whether a stop was asked for, and by what: the first request decides.
#[derive(Debug, Default)]
pub struct Interrupt(AtomicU8);

impl Interrupt {
    /// An interrupt that was not requested.
    #[must_use]
    pub const fn new() -> Self {
        Self(AtomicU8::new(0))
    }

    /// Records a request and says whether it is the first.
    #[cfg(not(target_os = "wasi"))]
    pub fn request(&self, stop: Stop) -> Signal {
        match self
            .0
            .compare_exchange(0, stop.encode(), Ordering::SeqCst, Ordering::SeqCst)
        {
            Ok(_) => Signal::First,
            Err(_) => Signal::Repeated,
        }
    }

    /// What the first request was, if there was one.
    pub fn requested(&self) -> Option<Stop> {
        Stop::decode(self.0.load(Ordering::SeqCst))
    }
}

static INTERRUPT: Interrupt = Interrupt::new();

/// What the process was asked to stop by, if it was.
pub fn requested() -> Option<Stop> {
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

impl Run {
    /// The command that makes this run, as the JSON envelope names it.
    #[cfg(not(target_os = "wasi"))]
    const fn operation(self) -> Operation {
        match self {
            Self::Create => Operation::Create,
            Self::ExtractInPlace | Self::ExtractAtomic | Self::ExtractReplace => Operation::Extract,
        }
    }
}

/// What the forced exit tells the user to look for.
///
/// `.exarch-backup-*` holds the only copy of the original destination between
/// the moment an atomic replace moves it aside and the moment the new content
/// takes its place, so it is named apart from the staging entries that are safe
/// to delete, and only for the run that makes one. `place` is the directory
/// the staging entries are created in.
#[cfg(not(target_os = "wasi"))]
fn forced_exit_hint(output: &Path, place: &Path, run: Run) -> String {
    let place = path_text(place);
    let output = path_text(output);
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

/// The directory core stages `output`'s run in: the parent of the absolute
/// path, so a destination spelled `.` names the directory above the working
/// directory, where its staging entry really is.
#[cfg(not(target_os = "wasi"))]
fn staging_place(output: &Path) -> PathBuf {
    let absolute = std::path::absolute(output).unwrap_or_else(|_| output.to_path_buf());
    absolute
        .parent()
        .map_or_else(|| absolute.clone(), Path::to_path_buf)
}

/// What a forced exit does once the armed window has seen a second request.
#[cfg(not(target_os = "wasi"))]
#[derive(Debug)]
struct Armed {
    hint: String,
    operation: Operation,
    mode: OutputMode,
}

#[cfg(not(target_os = "wasi"))]
static ARMED: std::sync::Mutex<Option<Armed>> = std::sync::Mutex::new(None);

#[cfg(not(target_os = "wasi"))]
fn armed() -> std::sync::MutexGuard<'static, Option<Armed>> {
    ARMED
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// The armed window of a staged run: while it lives, a stop request cancels
/// the run; once it is dropped, the default action applies again.
///
/// Only one window can be open at a time; installing again replaces the
/// previous one. It is created by [`install`], and the progress reporter of a
/// staged run is built from it ([`InterruptGuard::watch`]), so a command cannot
/// arm the handler without polling it.
#[must_use = "dropping the guard disarms the interrupt handler at once"]
#[derive(Debug)]
pub struct InterruptGuard {
    interrupt: &'static Interrupt,
}

impl InterruptGuard {
    const fn armed() -> Self {
        Self {
            interrupt: &INTERRUPT,
        }
    }

    /// Wraps `inner` so that a requested stop cancels the run it reports on.
    pub fn watch(&self, inner: Box<dyn ProgressCallback>) -> Interruptible {
        Interruptible::watching(inner, self.interrupt)
    }

    /// A reporter that only watches for a stop, for a pass with nothing to
    /// show.
    pub fn watcher(&self) -> Interruptible {
        self.watch(Box::new(NoopProgress))
    }
}

impl Drop for InterruptGuard {
    fn drop(&mut self) {
        #[cfg(not(target_os = "wasi"))]
        {
            *armed() = None;
        }
    }
}

/// What a stop request does outside an armed window: the default action, so
/// the process ends as it would have without this module.
#[cfg(not(target_os = "wasi"))]
fn terminate_by_default(stop: Stop) -> ! {
    #[cfg(unix)]
    {
        // A terminating signal ends the process here, or aborts when the
        // default action cannot be restored; the exit below only runs when
        // this returns, for a signal it does not know or whose default does
        // not terminate.
        let _ = signal_hook::low_level::emulate_default_handler(stop.raw_signal());
    }
    std::process::exit(i32::from(ExitStatus::from(stop) as u8))
}

/// Ends the process of a run that stopped on a request the way the request
/// would have: by the signal itself, so a shell loop sees a signal death and
/// stops too. `$?` still reads 130 or 143. When the signal's default action
/// does not terminate, or the signal is unknown, this returns and the caller
/// exits with the status; a failure to restore the default action aborts the
/// process.
pub fn finish_by_signal() {
    #[cfg(unix)]
    if let Some(stop) = requested() {
        let _ = signal_hook::low_level::emulate_default_handler(stop.raw_signal());
    }
}

/// Gives up waiting for the run: reports what it leaves and exits with the
/// status of the stop.
#[cfg(not(target_os = "wasi"))]
fn forced_exit(armed: &Armed, stop: Stop) -> ! {
    use crate::output::emit_line;
    use std::io::Write as _;

    // A closed stdout or stderr must not stop the exit below.
    match armed.mode {
        OutputMode::Json => {
            if let Ok(document) = crate::output::forced_exit_envelope(armed.operation, &armed.hint)
            {
                let _ = emit_line(&mut std::io::stdout(), format_args!("{document}"));
            }
        }
        OutputMode::Human(_) => {
            let _ = writeln!(std::io::stderr(), "{}", armed.hint);
        }
    }
    std::process::exit(i32::from(ExitStatus::from(stop) as u8))
}

/// The stop that decides the exit status: the first request, not the latest.
#[cfg(not(target_os = "wasi"))]
fn decided(interrupt: &Interrupt, latest: Stop) -> Stop {
    interrupt.requested().unwrap_or(latest)
}

#[cfg(not(target_os = "wasi"))]
fn on_stop(stop: Stop) {
    let window = armed();
    let Some(armed) = window.as_ref() else {
        drop(window);
        terminate_by_default(stop);
    };
    if INTERRUPT.request(stop) == Signal::Repeated {
        forced_exit(armed, decided(&INTERRUPT, stop));
    }
}

#[cfg(unix)]
fn register(handler: fn(Stop)) -> std::io::Result<()> {
    use signal_hook::consts::SIGINT;
    use signal_hook::consts::SIGTERM;

    let mut signals = signal_hook::iterator::Signals::new([SIGINT, SIGTERM])?;
    std::thread::Builder::new()
        .name("exarch-signals".to_owned())
        .spawn(move || {
            for signal in signals.forever() {
                handler(if signal == SIGTERM {
                    Stop::Terminate
                } else {
                    Stop::Interrupt
                });
            }
        })
        .map(drop)
}

#[cfg(windows)]
fn register(handler: fn(Stop)) -> std::io::Result<()> {
    ctrlc::set_handler(move || handler(Stop::Interrupt)).map_err(std::io::Error::other)
}

/// Arms the handler for the command that writes `output` and returns the
/// window it stays armed for. A handler that cannot be installed is reported
/// and the default signal action stays.
#[cfg(not(target_os = "wasi"))]
pub fn install(output: &Path, run: Run, mode: OutputMode) -> InterruptGuard {
    static REGISTERED: std::sync::Once = std::sync::Once::new();

    let guard = arm(output, run, mode);
    REGISTERED.call_once(|| {
        if let Err(error) = register(on_stop) {
            eprintln!("warning: cannot install the interrupt handler: {error}");
        }
    });
    guard
}

/// Opens the armed window without touching the process's signal handlers.
#[cfg(not(target_os = "wasi"))]
fn arm(output: &Path, run: Run, mode: OutputMode) -> InterruptGuard {
    *armed() = Some(Armed {
        hint: forced_exit_hint(output, &staging_place(output), run),
        operation: run.operation(),
        mode,
    });
    InterruptGuard::armed()
}

/// WASI has no signals; there is nothing to arm.
#[cfg(target_os = "wasi")]
pub const fn install(_output: &Path, _run: Run, _mode: OutputMode) -> InterruptGuard {
    InterruptGuard::armed()
}

/// Wraps a reporter so that a requested stop cancels the run.
pub struct Interruptible {
    inner: Box<dyn ProgressCallback>,
    interrupt: &'static Interrupt,
}

impl Interruptible {
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
        self.interrupt.requested().is_some() || self.inner.is_cancelled()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(not(target_os = "wasi"))]
    use crate::output::Verbosity;

    #[cfg(not(target_os = "wasi"))]
    #[test]
    fn the_first_request_is_first_and_decides_the_stop() {
        let interrupt = Interrupt::new();
        assert_eq!(interrupt.requested(), None);
        assert_eq!(interrupt.request(Stop::Terminate), Signal::First);
        assert_eq!(interrupt.requested(), Some(Stop::Terminate));
        assert_eq!(interrupt.request(Stop::Interrupt), Signal::Repeated);
        assert_eq!(interrupt.requested(), Some(Stop::Terminate));
    }

    #[cfg(not(target_os = "wasi"))]
    #[test]
    fn a_forced_exit_takes_the_status_of_the_first_request() {
        let interrupt = Interrupt::new();
        interrupt.request(Stop::Terminate);
        assert_eq!(interrupt.request(Stop::Interrupt), Signal::Repeated);
        assert_eq!(decided(&interrupt, Stop::Interrupt), Stop::Terminate);
    }

    #[cfg(not(target_os = "wasi"))]
    #[test]
    fn every_stop_survives_the_atomic_encoding() {
        for stop in [Stop::Interrupt, Stop::Terminate] {
            assert_eq!(Stop::decode(stop.encode()), Some(stop));
        }
        assert_eq!(Stop::decode(0), None);
    }

    #[cfg(not(target_os = "wasi"))]
    #[test]
    fn a_requested_stop_cancels_the_wrapped_reporter() {
        static WATCHED: Interrupt = Interrupt::new();
        let mut progress = Interruptible::watching(Box::new(NoopProgress), &WATCHED);
        assert!(!progress.is_cancelled());
        WATCHED.request(Stop::Interrupt);
        assert!(progress.is_cancelled());
    }

    #[cfg(not(target_os = "wasi"))]
    #[test]
    fn only_a_replace_names_the_backup() {
        let place = Path::new("/work");
        let replace = forced_exit_hint(Path::new("/work/out"), place, Run::ExtractReplace);
        assert!(replace.contains("in /work:"), "{replace}");
        assert!(
            replace.contains("rename the .exarch-backup-* entry"),
            "{replace}"
        );
        for run in [Run::Create, Run::ExtractInPlace, Run::ExtractAtomic] {
            let hint = forced_exit_hint(Path::new("/work/out"), place, run);
            assert!(!hint.contains("backup"), "{run:?}: {hint}");
        }
    }

    #[cfg(not(target_os = "wasi"))]
    #[test]
    fn each_run_names_what_it_leaves() {
        let place = Path::new("/work");
        let create = forced_exit_hint(Path::new("/work/o.tar"), place, Run::Create);
        assert!(
            create.contains("temporary file named .exarch-*"),
            "{create}"
        );
        assert!(create.contains("in /work:"), "{create}");
        let atomic = forced_exit_hint(Path::new("/work/out"), place, Run::ExtractAtomic);
        assert!(
            atomic.contains("staging directory named .exarch-*"),
            "{atomic}"
        );
        let in_place = forced_exit_hint(Path::new("/work/out"), place, Run::ExtractInPlace);
        assert!(in_place.contains("/work/out"), "{in_place}");
        assert!(
            in_place.contains("staging directory named .exarch-*"),
            "{in_place}"
        );
        assert!(!in_place.contains("backup"), "{in_place}");
    }

    #[cfg(not(target_os = "wasi"))]
    #[test]
    #[allow(clippy::expect_used)]
    fn a_destination_spelled_dot_stages_above_the_working_directory() {
        let cwd = std::env::current_dir().expect("working directory");
        let above = cwd.parent().map_or_else(|| cwd.clone(), Path::to_path_buf);
        assert_eq!(staging_place(Path::new(".")), above);
        assert_eq!(staging_place(Path::new("out")), cwd);
        assert_eq!(staging_place(&cwd.join("work/out")), cwd.join("work"));
    }

    #[cfg(not(target_os = "wasi"))]
    #[test]
    fn the_window_is_armed_only_while_the_guard_lives() {
        let guard = arm(
            Path::new("out"),
            Run::ExtractAtomic,
            OutputMode::Human(Verbosity::Normal),
        );
        assert!(armed().is_some());
        drop(guard);
        assert!(armed().is_none());
    }
}

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
//! [`ExitStatus::Terminated`] (SIGTERM); a stop that lands after the last poll
//! lets the run finish, report its result, and then end the same way. A second
//! signal gives up waiting; under `--json` it writes a minimal `Cancelled`
//! error document to stdout first, so the one-document contract holds, and
//! otherwise a hint on stderr naming what the run left behind. Both stops end
//! the process by the signal itself on Unix, so a parent sees a signal death
//! (`$?` reads 130 or 143); Windows has no such death and exits 130.
//!
//! SIGHUP is deliberately not handled: a `nohup`-ed run ignores it, and
//! handling it here would override that. SIGINT or SIGTERM that the parent
//! ignored (a background job under `trap "" INT`) is left alone on Unix: no
//! handler is installed for it, so it stays ignored for the whole run, inside
//! the armed window and after it.
//!
//! Core polls at entry boundaries and every few MiB inside one entry's copy,
//! and the `extract` pre-extraction listing polls per entry, so the first
//! signal is effective without the forced path except inside one decoder call.
//!
//! On Unix the signals are read on a helper thread through `signal-hook`; on
//! Windows `ctrlc` reports Ctrl-C and Ctrl-Break as an interrupt. WASI has no
//! signals, so nothing is installed there.

#[cfg(not(target_os = "wasi"))]
use crate::error::Part;
#[cfg(not(target_os = "wasi"))]
use crate::exit::ExitStatus;
#[cfg(not(target_os = "wasi"))]
use crate::operation::Operation;
use crate::output::OutputMode;
use exarch_core::EntryPosition;
use exarch_core::NoopProgress;
use exarch_core::ProgressCallback;
#[cfg(not(target_os = "wasi"))]
use exarch_core::StagedOutputKind;
#[cfg(not(target_os = "wasi"))]
use exarch_core::StagingPlace;
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
    /// Every stop, in the order of the signals that cause them.
    #[cfg(unix)]
    const ALL: [Self; 2] = [Self::Interrupt, Self::Terminate];

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

    #[cfg(unix)]
    fn from_raw_signal(signal: std::ffi::c_int) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|stop| stop.raw_signal() == signal)
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

    /// Whether the run moves the existing destination aside, so that the
    /// forced exit must say where the original is.
    #[cfg(not(target_os = "wasi"))]
    const fn makes_backup(self) -> bool {
        match self {
            Self::ExtractReplace => true,
            Self::Create | Self::ExtractInPlace | Self::ExtractAtomic => false,
        }
    }

    /// What core stages for this run, which decides how its place resolves.
    #[cfg(not(target_os = "wasi"))]
    const fn staged_kind(self) -> StagedOutputKind {
        match self {
            Self::Create => StagedOutputKind::File,
            Self::ExtractInPlace | Self::ExtractAtomic | Self::ExtractReplace => {
                StagedOutputKind::Directory
            }
        }
    }
}

/// What the forced exit tells the user to look for.
///
/// The backup entry holds the only copy of the original destination between
/// the moment an atomic replace moves it aside and the moment the new content
/// takes its place, so it is named apart from the staging entries that are safe
/// to delete, and only for the run that makes one. `place` is where core
/// created the entries, when it could be resolved: the hint then names that
/// directory and the path the backup is renamed back to; otherwise it names
/// only `output`.
#[cfg(not(target_os = "wasi"))]
fn forced_exit_hint(output: &Path, place: Option<&StagingPlace>, run: Run) -> Vec<Part> {
    let staged = Part::Text(format!("{}*", exarch_core::STAGING_PREFIX));
    let location = place.map_or_else(
        || [Part::Lit(" next to "), Part::Path(output.to_path_buf())],
        |place| [Part::Lit(" in "), Part::Path(place.parent().to_path_buf())],
    );
    let mut parts = vec![Part::Lit("interrupted again, stopping at once; ")];
    match run {
        Run::Create => parts.extend([
            Part::Lit("an unfinished temporary file named "),
            staged,
            Part::Lit(" may remain"),
        ]),
        Run::ExtractInPlace => parts.extend([
            Part::Lit("entries already extracted into "),
            Part::Path(output.to_path_buf()),
            Part::Lit(
                " remain, or, for a destination that did not exist, an unfinished staging \
                 directory named ",
            ),
            staged,
            Part::Lit(" may remain"),
        ]),
        Run::ExtractAtomic => parts.extend([
            Part::Lit("an unfinished staging directory named "),
            staged,
            Part::Lit(" may remain"),
        ]),
        Run::ExtractReplace => parts.extend([
            Part::Lit("unfinished staging entries named "),
            staged,
            Part::Lit(" may remain"),
        ]),
    }
    parts.extend(location);
    if run.makes_backup() {
        let target = place.map_or_else(|| output.to_path_buf(), StagingPlace::target);
        parts.extend([
            Part::Lit(": remove them, but if "),
            Part::Path(target.clone()),
            Part::Lit(" is missing, rename the "),
            Part::Text(format!("{}*", exarch_core::BACKUP_PREFIX)),
            Part::Lit(" entry there back to "),
            Part::Path(target),
            Part::Lit(" first, since it holds the original"),
        ]);
    } else {
        parts.push(Part::Lit(": remove it"));
    }
    parts
}

/// What a forced exit does once the armed window has seen a second request.
///
/// `place` is resolved when the window opens, before core renames anything: a
/// destination spelled `a/b/..` stops resolving once a replace moves `a`
/// aside.
#[cfg(not(target_os = "wasi"))]
#[derive(Clone, Debug)]
struct Armed {
    output: PathBuf,
    run: Run,
    mode: OutputMode,
    place: Option<StagingPlace>,
}

/// The armed state of one window, shared between the guard that opens it and
/// the signal thread that reads it.
#[cfg(not(target_os = "wasi"))]
#[derive(Debug)]
struct Window(std::sync::Mutex<Option<Armed>>);

#[cfg(not(target_os = "wasi"))]
impl Window {
    const fn new() -> Self {
        Self(std::sync::Mutex::new(None))
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Option<Armed>> {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

#[cfg(not(target_os = "wasi"))]
static WINDOW: Window = Window::new();

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
    #[cfg(not(target_os = "wasi"))]
    window: &'static Window,
}

impl InterruptGuard {
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
            *self.window.lock() = None;
        }
    }
}

/// What a stop request does outside an armed window: the default action, so
/// the process ends as it would have without this module.
///
/// A signal inherited as ignored never reaches here on Unix, since `register`
/// does not handle it.
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
    std::process::exit(ExitStatus::from(stop).code())
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

/// How long a forced exit waits for its report to be written before it exits
/// without it.
#[cfg(not(target_os = "wasi"))]
const FORCED_EXIT_WRITE_BUDGET: std::time::Duration = std::time::Duration::from_millis(500);

/// Runs `write` on a detached thread and waits at most `budget` for it to
/// return, so a write blocked on a full pipe cannot keep the process alive.
/// The thread is left behind when the budget runs out; the caller ends the
/// process next, which ends it.
#[cfg(not(target_os = "wasi"))]
fn deliver_within(budget: std::time::Duration, write: impl FnOnce() + Send + 'static) {
    let (done, finished) = std::sync::mpsc::channel();
    let spawned = std::thread::Builder::new()
        .name("exarch-forced-exit".to_owned())
        .spawn(move || {
            write();
            let _ = done.send(());
        });
    if spawned.is_ok() {
        let _ = finished.recv_timeout(budget);
    }
}

/// The hint of a forced exit. A place that could not be resolved when the
/// window opened, because core had not created the parent yet, is resolved
/// again here.
#[cfg(not(target_os = "wasi"))]
fn resolved_hint(armed: &Armed) -> Vec<Part> {
    let place = armed
        .place
        .clone()
        .or_else(|| exarch_core::staging_place(&armed.output, armed.run.staged_kind()).ok());
    forced_exit_hint(&armed.output, place.as_ref(), armed.run)
}

/// Writes the report of a forced exit and flushes both streams: the one
/// `--json` document on stdout, or the hint on stderr.
#[cfg(not(target_os = "wasi"))]
fn write_forced_report(armed: &Armed) {
    use crate::output::emit_line;
    use std::io::Write as _;

    let hint = resolved_hint(armed);
    // A closed stdout or stderr must not stop the exit.
    match armed.mode {
        OutputMode::Json => {
            let hint = crate::error::raw(&hint);
            if let Ok(document) = crate::output::forced_exit_envelope(armed.run.operation(), &hint)
            {
                let _ = emit_line(&mut std::io::stdout(), format_args!("{document}"));
            }
        }
        OutputMode::Human(_) => {
            let _ = writeln!(std::io::stderr(), "{}", crate::error::terminal(&hint));
        }
    }
    let _ = std::io::stdout().flush();
    let _ = std::io::stderr().flush();
}

/// Gives up waiting for the run: reports what it leaves and ends the process
/// by the signal, like the graceful stop.
///
/// The report is written on a detached thread and abandoned after
/// [`FORCED_EXIT_WRITE_BUDGET`], so a full stdout or stderr pipe cannot hang
/// the exit. Consequences for the reader: if the interrupted thread holds the
/// stdout lock, no `--json` envelope is written; a write that times out above
/// `PIPE_BUF` (512 bytes on macOS, 4096 on Linux) can leave a partial line.
/// The exit status is the contract; the report is best effort.
///
/// Both streams are flushed before the process ends, since a signal death
/// skips std's exit cleanup. Where there is no signal death (Windows), the exit
/// goes through `process::exit`, whose stdout cleanup flushes a line the
/// interrupted thread left buffered and can block on a full pipe; the path is
/// narrow because the CLI writes whole lines, and a lock held by an abandoned
/// writer makes the cleanup skip the flush.
#[cfg(not(target_os = "wasi"))]
fn forced_exit(armed: Armed, stop: Stop) -> ! {
    deliver_within(FORCED_EXIT_WRITE_BUDGET, move || {
        write_forced_report(&armed);
    });
    terminate_by_default(stop)
}

/// The stop that decides the exit status: the first request, not the latest.
#[cfg(not(target_os = "wasi"))]
fn decided(interrupt: &Interrupt, latest: Stop) -> Stop {
    interrupt.requested().unwrap_or(latest)
}

/// What a stop request found when it looked at the window.
#[cfg(not(target_os = "wasi"))]
#[derive(Debug)]
enum Claim<'w> {
    /// No window is open: the default action applies.
    Disarmed,
    /// The first request: the run stops at its next poll.
    First,
    /// A later request: the forced exit reports `report` while `held` keeps the
    /// window locked, so the guard of the interrupted command cannot drop and
    /// let its thread write a second result.
    Forced {
        report: Armed,
        held: std::sync::MutexGuard<'w, Option<Armed>>,
    },
}

/// Records the request `stop` against `interrupt` while `window` is open, and
/// says what the handler must do about it.
#[cfg(not(target_os = "wasi"))]
fn claim<'w>(window: &'w Window, interrupt: &Interrupt, stop: Stop) -> Claim<'w> {
    let held = window.lock();
    let Some(armed) = held.as_ref() else {
        return Claim::Disarmed;
    };
    match interrupt.request(stop) {
        Signal::First => Claim::First,
        Signal::Repeated => Claim::Forced {
            report: armed.clone(),
            held,
        },
    }
}

#[cfg(not(target_os = "wasi"))]
fn on_stop(stop: Stop) {
    handle_stop(&WINDOW, &INTERRUPT, stop, |report, stop| {
        forced_exit(report, stop)
    });
}

/// Acts on a stop request found by [`claim`]: the forced exit runs with the
/// window still locked, which `exit` is given no way to release.
#[cfg(not(target_os = "wasi"))]
fn handle_stop(window: &Window, interrupt: &Interrupt, stop: Stop, exit: impl FnOnce(Armed, Stop)) {
    match claim(window, interrupt, stop) {
        Claim::Disarmed => terminate_by_default(stop),
        Claim::First => {}
        Claim::Forced { report, held } => {
            exit(report, decided(interrupt, stop));
            drop(held);
        }
    }
}

/// Whether the process inherited `signal` as ignored, read with a `sigaction`
/// query that installs nothing. This is the CLI's only `unsafe`: neither std
/// nor `signal-hook` can read a disposition.
#[cfg(unix)]
#[allow(unsafe_code)]
fn ignored_on_entry(signal: std::ffi::c_int) -> bool {
    // SAFETY: a null new action only queries; an all-zero C `sigaction` is
    // valid and is read only after success.
    unsafe {
        let mut current: libc::sigaction = std::mem::zeroed();
        libc::sigaction(signal, std::ptr::null(), &raw mut current) == 0
            && current.sa_sigaction == libc::SIG_IGN
    }
}

#[cfg(unix)]
fn register(handler: fn(Stop)) -> std::io::Result<()> {
    let kept: Vec<_> = Stop::ALL
        .into_iter()
        .map(Stop::raw_signal)
        .filter(|&signal| !ignored_on_entry(signal))
        .collect();
    if kept.is_empty() {
        return Ok(());
    }
    let mut signals = signal_hook::iterator::Signals::new(kept)?;
    std::thread::Builder::new()
        .name("exarch-signals".to_owned())
        .spawn(move || {
            for stop in signals.forever().filter_map(Stop::from_raw_signal) {
                handler(stop);
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
    use std::io::Write as _;

    static REGISTERED: std::sync::Once = std::sync::Once::new();

    let guard = arm(&WINDOW, output, run, mode);
    REGISTERED.call_once(|| {
        if let Err(error) = register(on_stop) {
            let _ = writeln!(
                std::io::stderr(),
                "warning: cannot install the interrupt handler: {error}"
            );
        }
    });
    guard
}

/// Opens `window` without touching the process's signal handlers.
#[cfg(not(target_os = "wasi"))]
fn arm(window: &'static Window, output: &Path, run: Run, mode: OutputMode) -> InterruptGuard {
    *window.lock() = Some(Armed {
        output: output.to_path_buf(),
        run,
        mode,
        place: exarch_core::staging_place(output, run.staged_kind()).ok(),
    });
    InterruptGuard {
        interrupt: &INTERRUPT,
        window,
    }
}

/// WASI has no signals; there is nothing to arm.
#[cfg(target_os = "wasi")]
pub const fn install(_output: &Path, _run: Run, _mode: OutputMode) -> InterruptGuard {
    InterruptGuard {
        interrupt: &INTERRUPT,
    }
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
    use std::assert_matches;

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
    fn flag() -> std::sync::Arc<std::sync::atomic::AtomicBool> {
        std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false))
    }

    #[cfg(not(target_os = "wasi"))]
    #[test]
    fn a_write_that_returns_has_happened_when_delivery_returns() {
        let written = flag();
        let seen = std::sync::Arc::clone(&written);
        deliver_within(std::time::Duration::from_secs(5), move || {
            seen.store(true, Ordering::SeqCst);
        });
        assert!(written.load(Ordering::SeqCst));
    }

    #[cfg(not(target_os = "wasi"))]
    #[test]
    fn a_write_that_never_returns_is_abandoned_after_the_budget() {
        let written = flag();
        let seen = std::sync::Arc::clone(&written);
        let started = std::time::Instant::now();
        deliver_within(std::time::Duration::from_millis(50), move || {
            let (_keep, never) = std::sync::mpsc::channel::<()>();
            let _ = never.recv();
            seen.store(true, Ordering::SeqCst);
        });
        assert!(!written.load(Ordering::SeqCst));
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
    }

    #[cfg(not(target_os = "wasi"))]
    #[test]
    fn a_writer_that_panics_does_not_hold_up_delivery() {
        let started = std::time::Instant::now();
        deliver_within(std::time::Duration::from_secs(30), || {
            panic!("write failed")
        });
        assert!(started.elapsed() < std::time::Duration::from_secs(5));
    }

    #[cfg(unix)]
    #[test]
    #[allow(clippy::expect_used)]
    fn a_write_blocked_on_a_full_pipe_is_abandoned_within_the_budget() {
        use std::io::Write as _;
        use std::sync::Arc;
        use std::sync::atomic::AtomicUsize;

        const CHUNK: usize = 512;
        let (reader, mut filler) = std::io::pipe().expect("create pipe");
        let mut blocked = filler.try_clone().expect("clone writer");
        let written = Arc::new(AtomicUsize::new(0));
        let progress = Arc::clone(&written);
        std::thread::spawn(move || {
            while filler.write_all(&[0; CHUNK]).is_ok() {
                progress.fetch_add(CHUNK, Ordering::SeqCst);
            }
        });

        // The filler is stuck in a write once its byte count stops moving.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        loop {
            let before = written.load(Ordering::SeqCst);
            std::thread::sleep(std::time::Duration::from_millis(100));
            if before > 0 && before == written.load(Ordering::SeqCst) {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the pipe never filled"
            );
        }

        let finished = flag();
        let seen = Arc::clone(&finished);
        let started = std::time::Instant::now();
        deliver_within(std::time::Duration::from_millis(100), move || {
            let _ = blocked.write_all(&[0; 4096]);
            seen.store(true, Ordering::SeqCst);
        });
        assert!(!finished.load(Ordering::SeqCst));
        assert!(started.elapsed() < std::time::Duration::from_secs(2));
        drop(reader);
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
    fn hint_text(output: &str, place: Option<&StagingPlace>, run: Run) -> String {
        crate::error::raw(&forced_exit_hint(Path::new(output), place, run))
    }

    #[cfg(not(target_os = "wasi"))]
    #[allow(clippy::expect_used)]
    fn place_of(output: &Path, run: Run) -> StagingPlace {
        exarch_core::staging_place(output, run.staged_kind()).expect("resolve the place")
    }

    #[cfg(not(target_os = "wasi"))]
    #[test]
    #[allow(clippy::expect_used)]
    fn only_a_replace_names_the_backup() {
        let dir = tempfile::tempdir().expect("tempdir");
        let output = dir.path().join("out");
        let place = place_of(&output, Run::ExtractReplace);
        let backup = format!("{}*", exarch_core::BACKUP_PREFIX);
        let target = place.target().display().to_string();
        let replace = crate::error::raw(&forced_exit_hint(
            &output,
            Some(&place),
            Run::ExtractReplace,
        ));
        assert!(
            replace.contains(&format!("rename the {backup} entry")),
            "{replace}"
        );
        assert!(
            replace.contains(&format!("back to {target} first")),
            "{replace}"
        );
        assert!(
            replace.contains(&format!("in {}:", place.parent().display())),
            "{replace}"
        );
        for run in [Run::Create, Run::ExtractInPlace, Run::ExtractAtomic] {
            let hint = crate::error::raw(&forced_exit_hint(&output, Some(&place), run));
            assert!(!hint.contains("backup"), "{run:?}: {hint}");
        }
    }

    #[cfg(not(target_os = "wasi"))]
    #[test]
    #[allow(clippy::expect_used)]
    fn each_run_names_what_it_leaves() {
        let dir = tempfile::tempdir().expect("tempdir");
        let output = dir.path().join("out");
        let staged = format!("{}*", exarch_core::STAGING_PREFIX);
        let place = place_of(&output, Run::ExtractAtomic);
        let parent = place.parent().display().to_string();
        let output = output.display().to_string();

        let create = hint_text(&output, Some(&place), Run::Create);
        assert!(
            create.contains(&format!("temporary file named {staged}")),
            "{create}"
        );
        assert!(create.contains(&format!("in {parent}:")), "{create}");
        let atomic = hint_text(&output, Some(&place), Run::ExtractAtomic);
        assert!(
            atomic.contains(&format!("staging directory named {staged}")),
            "{atomic}"
        );
        let in_place = hint_text(&output, Some(&place), Run::ExtractInPlace);
        assert!(in_place.contains(&output), "{in_place}");
        assert!(
            in_place.contains(&format!("staging directory named {staged}")),
            "{in_place}"
        );
        assert!(!in_place.contains("backup"), "{in_place}");
    }

    #[cfg(not(target_os = "wasi"))]
    #[test]
    fn an_unresolved_place_names_only_the_output() {
        let hint = hint_text("out", None, Run::ExtractReplace);
        assert!(hint.contains("next to out"), "{hint}");
        assert!(hint.contains("back to out first"), "{hint}");
    }

    #[cfg(unix)]
    #[test]
    fn the_hint_spells_a_host_path_exactly_in_json() {
        let place = hint_text("a\\b", None, Run::Create);
        assert!(place.contains("next to a\\b:"), "{place}");
    }

    #[cfg(not(target_os = "wasi"))]
    #[test]
    #[allow(clippy::expect_used)]
    fn the_place_is_resolved_when_the_window_opens() {
        static OPENING: Window = Window::new();
        let dir = tempfile::tempdir().expect("tempdir");
        let canonical = dir.path().canonicalize().expect("canonicalize");
        std::fs::create_dir_all(dir.path().join("a/b")).expect("create");
        let output = dir.path().join("a/b/..");
        let guard = arm(
            &OPENING,
            &output,
            Run::ExtractReplace,
            OutputMode::Human(Verbosity::Normal),
        );
        let target = OPENING
            .lock()
            .as_ref()
            .and_then(|armed| armed.place.as_ref().map(StagingPlace::target))
            .expect("a resolved place");
        assert_eq!(target, canonical.join("a"));
        drop(guard);
    }

    #[cfg(not(target_os = "wasi"))]
    #[test]
    #[allow(clippy::expect_used)]
    fn a_place_unresolved_at_arm_time_is_resolved_when_the_exit_is_forced() {
        let dir = tempfile::tempdir().expect("tempdir");
        let canonical = dir.path().canonicalize().expect("canonicalize");
        let armed = |output: PathBuf| Armed {
            output,
            run: Run::ExtractAtomic,
            mode: OutputMode::Human(Verbosity::Normal),
            place: None,
        };

        let resolved = crate::error::raw(&resolved_hint(&armed(dir.path().join("out"))));
        assert!(
            resolved.contains(&format!("in {}:", canonical.display())),
            "{resolved}"
        );

        let missing_parent = dir.path().join("absent/out");
        let unresolved = crate::error::raw(&resolved_hint(&armed(missing_parent.clone())));
        assert!(
            unresolved.contains(&format!("next to {}:", missing_parent.display())),
            "{unresolved}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn every_stop_round_trips_through_its_signal() {
        for stop in Stop::ALL {
            assert_eq!(Stop::from_raw_signal(stop.raw_signal()), Some(stop));
        }
        assert_eq!(Stop::from_raw_signal(signal_hook::consts::SIGHUP), None);
    }

    #[cfg(not(target_os = "wasi"))]
    #[test]
    fn a_stop_without_a_window_leaves_the_request_unrecorded() {
        static CLOSED: Window = Window::new();
        static STOPS: Interrupt = Interrupt::new();
        assert_matches!(claim(&CLOSED, &STOPS, Stop::Interrupt), Claim::Disarmed);
        assert_eq!(STOPS.requested(), None);
    }

    #[cfg(not(target_os = "wasi"))]
    #[test]
    #[allow(clippy::expect_used)]
    fn a_repeated_stop_keeps_the_guard_from_dropping_until_the_exit_ends() {
        use std::sync::mpsc;
        use std::time::Duration;

        static HELD: Window = Window::new();
        static STOPS: Interrupt = Interrupt::new();
        let guard = arm(
            &HELD,
            Path::new("out"),
            Run::ExtractAtomic,
            OutputMode::Human(Verbosity::Normal),
        );
        assert_matches!(claim(&HELD, &STOPS, Stop::Interrupt), Claim::First);
        let Claim::Forced { report, held } = claim(&HELD, &STOPS, Stop::Interrupt) else {
            panic!("a repeated stop must force the exit");
        };
        assert_eq!(report.output, Path::new("out"));

        let (started_tx, started) = mpsc::channel();
        let (done_tx, done) = mpsc::channel();
        let dropper = std::thread::spawn(move || {
            started_tx.send(()).expect("report the start");
            drop(guard);
            done_tx.send(()).expect("report the drop");
        });
        started
            .recv_timeout(Duration::from_secs(5))
            .expect("the dropping thread starts");
        assert!(
            done.recv_timeout(Duration::from_millis(100)).is_err(),
            "the guard dropped while the forced exit held the window"
        );

        drop(held);
        done.recv_timeout(Duration::from_secs(5))
            .expect("the guard drops once the window is free");
        dropper.join().expect("the dropping thread ends");
        assert!(HELD.lock().is_none());
    }

    #[cfg(not(target_os = "wasi"))]
    #[test]
    fn the_window_stays_locked_while_the_forced_exit_runs() {
        static LOCKED: Window = Window::new();
        static STOPS: Interrupt = Interrupt::new();
        let _guard = arm(
            &LOCKED,
            Path::new("out"),
            Run::ExtractAtomic,
            OutputMode::Human(Verbosity::Normal),
        );
        handle_stop(&LOCKED, &STOPS, Stop::Interrupt, |_, _| {
            panic!("a first stop must not force the exit")
        });

        let mut was_locked = false;
        handle_stop(&LOCKED, &STOPS, Stop::Interrupt, |_, _| {
            was_locked = LOCKED.0.try_lock().is_err();
        });

        assert!(was_locked, "the window was free while the exit ran");
        assert!(LOCKED.0.try_lock().is_ok());
    }

    #[cfg(not(target_os = "wasi"))]
    #[test]
    fn the_window_is_armed_only_while_the_guard_lives() {
        static ARMED_WINDOW: Window = Window::new();
        let guard = arm(
            &ARMED_WINDOW,
            Path::new("out"),
            Run::ExtractAtomic,
            OutputMode::Human(Verbosity::Normal),
        );
        assert!(ARMED_WINDOW.lock().is_some());
        drop(guard);
        assert!(ARMED_WINDOW.lock().is_none());
    }
}

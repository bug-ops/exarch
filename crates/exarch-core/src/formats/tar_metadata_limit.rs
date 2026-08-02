//! Bounds bytes the `tar` crate may read while searching for the next entry.
//!
//! # Background
//!
//! GNU long-name (`L`), GNU long-link (`K`), and PAX extended header (`x`/`g`)
//! records are read fully into memory by the `tar` crate's `Entries::next()`
//! (via `EntryFields::read_all()`) *before* any entry reaches the entry
//! validator or quota tracker. A crafted record declaring a multi-gigabyte
//! length backed by a tiny compressed stream causes unbounded allocation with
//! no quota enforcement (issue #414).
//!
//! An earlier fix re-parsed TAR headers in a shadow parser to reject an
//! oversized metadata record before the `tar` crate could buffer it. That
//! approach was abandoned after three rounds of adversarial review each found
//! a fresh case where the shadow parser's belief about entry framing
//! diverged from the `tar` crate's own (untracked PAX `size=` overrides,
//! typeflag-without-magic-gate framing, and a PAX global header draining
//! `tar`'s override state without draining the mirror's). Three independent
//! divergences in three rounds is a structural problem with maintaining a
//! second parser, not a fixable oversight.
//!
//! # Design: a read budget, not a second parser
//!
//! [`BudgetedReader`] never looks at a header, a typeflag, magic bytes, or a
//! PAX record. It only counts bytes, and it is told when to start/stop
//! counting by the `tar` crate's own iterator boundary — via [`TarReadBudget`]
//! ([`arm`](TarReadBudget::arm)/[`disarm`](TarReadBudget::disarm)), driven by
//! [`BudgetedEntries::next_entry`]. The invariant enforced:
//!
//! > Between the moment iteration asks for the next entry and the moment
//! > `tar` yields one, `tar` may read at most `limit` bytes from the
//! > underlying reader.
//!
//! That window contains exactly: sub-block padding, the `L`/`K`/`x` metadata
//! headers and bodies `tar` buffers via `read_all`, GNU sparse extension
//! blocks, and the final entry header. It contains *no* entry data, because
//! every yielded entry is fully drained — via [`TarEntryGuard`]'s `Drop` —
//! before the next iteration step. So the budget is a pure constant: no
//! declared size, from any header, ever feeds it. There is exactly one
//! parser (the `tar` crate's own), so there is nothing for a shadow parser to
//! disagree with.
//!
//! The drain must run to true completion for a *legitimate* unread entry —
//! `list`/`verify` never read entry content at all, so the drain is the
//! *only* thing that consumes a legitimate entry's real bytes to reach the
//! next header, no matter how large that entry is (`verify` in particular
//! sets `max_file_size` to `u64::MAX` precisely so a metadata-only listing
//! does not reject large files). A fixed cap on *total drained output* —
//! however generous — therefore either (a) truncates real bytes of some
//! legitimate large entry, misaligning the next header read and rejecting an
//! ordinary archive with a scary `SecurityViolation`, or (b) is raised high
//! enough to avoid that and stops bounding anything, since a GNU sparse
//! entry's synthesized zero-padding (`tar` allocates no backing bytes for
//! sparse gaps) can be driven past any fixed number via a `realsize` field up
//! to `u64::MAX`. An earlier version of this fix picked option (a) at
//! different fixed caps and was broken both ways in succession (issue #414's
//! C2/C3 findings) before this module was corrected to the design below.
//!
//! **The drain is bounded by *synthesized* bytes, not total output.** A
//! legitimate regular entry's drain consumes real bytes from the underlying
//! reader 1:1 with what it outputs — reading further only produces more
//! output if the reader actually had more to give. GNU sparse padding is the
//! opposite: `tar` yields it from `io::repeat(0)`, producing output with
//! **zero** corresponding reads from the underlying reader. [`BudgetedReader`]
//! tracks a monotonic, never-reset `total_read` count of bytes actually
//! delivered from `inner`, armed or disarmed; [`TarEntryGuard::drop`] drains
//! in a loop tracking `synthetic = output_so_far -
//! bytes_actually_read_during_this_drain` and stops once `synthetic` exceeds
//! [`SYNTHETIC_PAD_CAP_BYTES`]. A legitimate entry's `synthetic` stays at (or
//! within a chunk-size rounding of) zero regardless of how large the entry is,
//! so it always drains fully; a sparse bomb's `synthetic` grows by a full
//! read-chunk on every iteration once padding starts, tripping the cap almost
//! immediately regardless of how large the declared `realsize` is. This
//! distinguishes the two purely by *where the bytes came from*, never by
//! inspecting a header field.
//!
//! One known residual limitation, accepted (P3, tracked as a follow-up
//! issue) rather than fixed here: a *legitimate* GNU sparse file with real
//! holes larger than [`SYNTHETIC_PAD_CAP_BYTES`] (e.g. a multi-gigabyte
//! sparse disk image, mostly zero-filled) looks identical to an attack from
//! this module's perspective when such a file is skipped unread — both
//! produce output with no corresponding read. This affects `list_archive`,
//! `verify_archive`, and, via those, the `exarch` CLI's `extract` command
//! too (its `extract` runs a `list_archive` pre-flight ahead of the actual
//! extraction, the same pre-flight `list`/`verify` use). Only a *direct*
//! `TarArchive::extract` library call bypassing that pre-flight is
//! unaffected, since it reads the entry itself and the guard's drain finds
//! nothing left to do.
//!
//! # Invariant: this module must never peek at archive content
//!
//! Nothing in this file reads a typeflag, checks magic bytes, or tracks a PAX
//! record — not even for a read-only "sanity check" or a diagnostic message.
//! That absence is not an implementation gap; it is the entire reason the
//! S1/S2/S3 bug class (three independent shadow-parser/`tar`-parser framing
//! disagreements, found in three separate rounds of adversarial review)
//! cannot recur here. **If a future change to this module adds any code path
//! that inspects header bytes to make a decision — even something as
//! innocuous-looking as "skip the budget check for typeflag `'g'`" or "trust
//! the declared size when it looks sane" — it reintroduces a second parser,
//! and with it the exact vulnerability class this redesign replaced.** Any
//! change that appears to need header awareness should be treated as a sign
//! the change belongs somewhere else (e.g. `EntryValidator`, which runs after
//! an entry is already fully framed by `tar` itself), not as a reason to add
//! a peek here.

use std::io;
use std::io::Read;
use std::marker::PhantomData;
use std::sync::Arc;
use std::sync::atomic::AtomicU64;
use std::sync::atomic::Ordering;

/// Hard, non-configurable ceiling on how many *synthesized* bytes (drained
/// output with no corresponding read from the underlying reader)
/// [`TarEntryGuard::drop`] will tolerate before giving up on a drain.
///
/// This is **not** a cap on total drained output — a legitimate entry drains
/// fully regardless of size, since its output tracks real reads 1:1 and never
/// accumulates synthetic bytes. Only a run of GNU sparse zero-padding (or
/// anything else that yields output without a corresponding read) can push
/// `synthetic` past this. A few MiB is ample: real padding-heavy input trips
/// it within a handful of read-chunk iterations, while it is never reached at
/// all by 1:1 content.
const SYNTHETIC_PAD_CAP_BYTES: u64 = 8 * 1024 * 1024;

/// Chunk size for the drain loop in [`TarEntryGuard::drop`]. Not a security
/// boundary — just an I/O granularity choice, small enough to keep the
/// worst-case overshoot past [`SYNTHETIC_PAD_CAP_BYTES`] negligible.
const DRAIN_CHUNK_BYTES: usize = 8192;

/// Sentinel `allowance` value meaning "disarmed" (no cap on reads).
const DISARMED: u64 = u64::MAX;

/// Shared, atomics-only state behind [`TarReadBudget`] and [`BudgetedReader`].
///
/// `Send + Sync` by construction (no `Rc`/`Cell`), so the read wrapper can
/// cross thread boundaries the same way the reader it wraps already can —
/// required by the Node.js binding's blocking-thread-pool usage.
struct BudgetState {
    /// The configured per-window byte limit; re-applied on every `arm()`.
    limit: u64,
    /// Bytes delivered through this reader since the most recent `arm()`.
    consumed: AtomicU64,
    /// `DISARMED`, or the number of bytes still allowed before the next
    /// `read()` must fail. Armed **from construction** (fail-closed): a call
    /// site that forgets to pair a `BudgetedReader` with `BudgetedEntries`
    /// trips on the very first read of real entry content instead of running
    /// unprotected.
    allowance: AtomicU64,
    /// Monotonic count of bytes actually read from the underlying reader,
    /// armed or disarmed alike — never reset by `arm()`/`disarm()`. Lets
    /// [`TarEntryGuard::drop`] distinguish real archive bytes from
    /// synthesized padding during its drain, regardless of the metered
    /// window's own state at the time.
    total_read: AtomicU64,
}

/// Cheap, cloneable handle used to arm/disarm the budget around the gap
/// between two yielded TAR entries.
///
/// Obtained together with a [`BudgetedReader`] from [`budgeted_reader`]; both
/// must wrap the *same* underlying reader passed to the *same*
/// [`BudgetedEntries`] for the invariant to hold.
#[derive(Clone)]
pub struct TarReadBudget(Arc<BudgetState>);

impl TarReadBudget {
    /// Starts (or restarts) counting: `consumed = 0`, `allowance = limit`.
    fn arm(&self) {
        self.0.consumed.store(0, Ordering::Relaxed);
        self.0.allowance.store(self.0.limit, Ordering::Relaxed);
    }

    /// Stops counting: subsequent reads pass through unmetered until the next
    /// `arm()`. Called once `tar` has yielded an entry — reading that
    /// entry's *own* data must never count against the metadata budget.
    fn disarm(&self) {
        self.0.allowance.store(DISARMED, Ordering::Relaxed);
    }

    /// Total bytes read from the underlying reader so far — monotonic,
    /// never reset by `arm()`/`disarm()`.
    fn total_read(&self) -> u64 {
        self.0.total_read.load(Ordering::Relaxed)
    }
}

/// Marker error surfaced when more than the configured limit is read from a
/// [`BudgetedReader`] while armed. Recovered via [`budget_violation`] and
/// converted into an `ArchiveError::SecurityViolation`.
#[derive(Debug)]
struct TarReadBudgetExceeded {
    limit: u64,
}

impl std::fmt::Display for TarReadBudgetExceeded {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "TAR metadata read budget exceeded: more than {} bytes read while searching for the \
             next archive entry (long-name/long-link/PAX headers, or a run of GNU sparse \
             extension blocks)",
            self.limit
        )
    }
}

impl std::error::Error for TarReadBudgetExceeded {}

/// Recovers a `TarReadBudgetExceeded` violation from an `io::Error` surfaced
/// by the `tar` crate, converting it into an `ArchiveError::SecurityViolation`.
///
/// Returns `None` for any other I/O error, so callers can fall back to their
/// usual generic error mapping.
pub fn budget_violation(e: &io::Error) -> Option<crate::ArchiveError> {
    let inner = e.get_ref()?;
    let exceeded = inner.downcast_ref::<TarReadBudgetExceeded>()?;
    Some(crate::ArchiveError::SecurityViolation {
        reason: exceeded.to_string(),
    })
}

/// Read wrapper that meters bytes against a [`TarReadBudget`] while armed and
/// passes them through unmetered while disarmed.
///
/// Never buffers, drops, reorders, or fabricates bytes: every byte returned
/// came from `inner`, in the same order. The only behavior beyond plain
/// passthrough is refusing to deliver more than `limit` bytes per armed
/// window, and it refuses by returning `Err`, never `Ok(0)` — a clamp to a
/// zero-length read would masquerade as clean end-of-archive to callers like
/// `tar`'s own `try_read_all`, turning a budget trip into a silently
/// truncated (but "successful") listing.
pub struct BudgetedReader<R> {
    inner: R,
    state: Arc<BudgetState>,
}

impl<R: Read> Read for BudgetedReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let allowance = self.state.allowance.load(Ordering::Relaxed);
        if allowance == DISARMED {
            let n = self.inner.read(buf)?;
            self.state.total_read.fetch_add(n as u64, Ordering::Relaxed);
            return Ok(n);
        }

        let consumed = self.state.consumed.load(Ordering::Relaxed);
        if consumed >= allowance {
            // The budget is exhausted, but a well-formed archive whose
            // metadata happens to end exactly at the configured limit must
            // not be rejected: distinguish "the underlying stream also ends
            // here" (safe — nothing was hidden) from "there is more real
            // data beyond the budget" (a genuine violation) with a minimal
            // probe read, rather than assuming a violation outright.
            let mut probe = [0u8; 1];
            return match self.inner.read(&mut probe) {
                Ok(0) => Ok(0),
                Ok(n) => {
                    self.state.total_read.fetch_add(n as u64, Ordering::Relaxed);
                    Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        TarReadBudgetExceeded { limit: allowance },
                    ))
                }
                Err(e) => Err(e),
            };
        }

        let remaining = allowance - consumed;
        let want = usize::try_from(remaining)
            .unwrap_or(usize::MAX)
            .min(buf.len());
        let n = self.inner.read(&mut buf[..want])?;
        self.state.consumed.fetch_add(n as u64, Ordering::Relaxed);
        self.state.total_read.fetch_add(n as u64, Ordering::Relaxed);
        Ok(n)
    }
}

/// Wraps `inner` in a [`BudgetedReader`] and returns it alongside the
/// [`TarReadBudget`] handle used to arm/disarm it.
///
/// The budget starts **armed** with `limit` (fail-closed): any read before
/// the first explicit `arm()`/`disarm()` cycle — e.g. a call site that never
/// wires up [`BudgetedEntries`] — is metered, not silently unlimited.
// No runnable `# Examples` here: this module is `pub(crate)` (an
// implementation detail of the `tar`/`inspection::list` wiring, not public
// API), so a doctest importing it via `exarch_core::formats::...` would not
// link — doctests only see the crate's public surface.
#[must_use]
pub fn budgeted_reader<R: Read>(inner: R, limit: u64) -> (BudgetedReader<R>, TarReadBudget) {
    let state = Arc::new(BudgetState {
        limit,
        consumed: AtomicU64::new(0),
        allowance: AtomicU64::new(limit),
        total_read: AtomicU64::new(0),
    });
    let reader = BudgetedReader {
        inner,
        state: Arc::clone(&state),
    };
    (reader, TarReadBudget(state))
}

/// A `tar::Entry` on loan from [`BudgetedEntries::next_entry`], guaranteed
/// fully drained (up to a bound) when dropped.
///
/// The `'s` lifetime ties this guard to the `&mut BudgetedEntries` borrow
/// that produced it, making it a compile error to call `next_entry()` again
/// (or to hold two guards at once) while a guard is alive — the "every entry
/// is drained before the next iteration step" invariant the whole module
/// depends on is therefore enforced by the borrow checker, not by review
/// convention.
pub struct TarEntryGuard<'a, 's, R: Read> {
    entry: tar::Entry<'a, BudgetedReader<R>>,
    budget: TarReadBudget,
    abandoned: bool,
    _borrow: PhantomData<&'s mut ()>,
}

impl<R: Read> TarEntryGuard<'_, '_, R> {
    /// Suppresses the bounded drain this guard would otherwise perform on
    /// drop.
    ///
    /// Call this only when abandoning the whole operation (returning an
    /// error and never calling `next_entry()` again) — draining is then
    /// pointless I/O, not a correctness requirement, since the bounded drain
    /// is safe to skip precisely because no further reads will happen.
    pub fn abandon(&mut self) {
        self.abandoned = true;
    }
}

impl<'a, R: Read> std::ops::Deref for TarEntryGuard<'a, '_, R> {
    type Target = tar::Entry<'a, BudgetedReader<R>>;

    fn deref(&self) -> &Self::Target {
        &self.entry
    }
}

impl<R: Read> std::ops::DerefMut for TarEntryGuard<'_, '_, R> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.entry
    }
}

impl<R: Read> Drop for TarEntryGuard<'_, '_, R> {
    fn drop(&mut self) {
        if self.abandoned {
            return;
        }
        // Bounded by *synthesized* bytes, not total output (see module
        // docs): a legitimate entry's `synthetic` stays ~0 regardless of
        // size, so it always drains to completion here, while a run of GNU
        // sparse zero-padding pushes `synthetic` up by a full chunk on every
        // iteration and trips `SYNTHETIC_PAD_CAP_BYTES` almost immediately.
        // A partial drain (the loop bails before true EOF) still leaves the
        // stream in a well-defined position — the shortfall is read on the
        // *next* header search, either misaligning into a checksum error or
        // exceeding the metadata budget, both loud failures, never silent.
        let total_read_at_start = self.budget.total_read();
        let mut output_so_far: u64 = 0;
        let mut buf = [0u8; DRAIN_CHUNK_BYTES];
        loop {
            let n = match self.entry.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            output_so_far += n as u64;
            let read_since_start = self.budget.total_read() - total_read_at_start;
            let synthetic = output_so_far.saturating_sub(read_since_start);
            if synthetic > SYNTHETIC_PAD_CAP_BYTES {
                break;
            }
        }
    }
}

/// Lending iterator over `tar` entries with a read budget armed for every gap
/// between entries.
///
/// Deliberately does **not** implement `std::iter::Iterator`: `Iterator::next`
/// cannot return a value borrowing `&mut self`, so an `Iterator` impl would
/// let a caller hold two [`TarEntryGuard`]s (or collect them into a `Vec`)
/// simultaneously — compiling, but silently defeating the "always drained
/// before the next entry" guarantee this type exists to enforce. Use
/// `while let Some(entry) = entries.next_entry() { ... }`.
pub struct BudgetedEntries<'a, R: Read> {
    entries: tar::Entries<'a, BudgetedReader<R>>,
    budget: TarReadBudget,
}

impl<'a, R: Read> BudgetedEntries<'a, R> {
    fn new(entries: tar::Entries<'a, BudgetedReader<R>>, budget: TarReadBudget) -> Self {
        Self { entries, budget }
    }

    /// Arms the budget, asks `tar` for the next entry, disarms the budget,
    /// and (on success) wraps the result in a draining guard.
    ///
    /// Arming happens *before* asking `tar`, so the metered window covers the
    /// entire gap: sub-block padding, any `L`/`K`/`x` metadata records, GNU
    /// sparse extension blocks, and the final header — including the
    /// trailing gap after the last real entry, which is exactly where an
    /// archive consisting of nothing but oversized metadata records would
    /// otherwise buffer unbounded before `tar` gives up with "members found
    /// describing a future member but no future member found".
    pub fn next_entry(&mut self) -> Option<io::Result<TarEntryGuard<'a, '_, R>>> {
        self.budget.arm();
        let result = self.entries.next();
        self.budget.disarm();

        match result {
            None => None,
            Some(Err(e)) => Some(Err(e)),
            Some(Ok(entry)) => Some(Ok(TarEntryGuard {
                entry,
                budget: self.budget.clone(),
                abandoned: false,
                _borrow: PhantomData,
            })),
        }
    }
}

/// Builds a [`BudgetedEntries`] iterator from an already budget-wrapped
/// archive, using the *same* [`TarReadBudget`] handle that reader was created
/// with.
///
/// Keeping construction to this one function (rather than callers manually
/// pairing `archive.entries()` with a `TarReadBudget` obtained separately) is
/// what makes it hard to accidentally iterate the raw `tar::Entries` and
/// bypass arming entirely.
///
/// # Errors
///
/// Returns an error if `tar` cannot begin reading entries (e.g. the archive
/// was already fully consumed).
pub fn budgeted_tar_entries<R: Read>(
    archive: &mut tar::Archive<BudgetedReader<R>>,
    budget: TarReadBudget,
) -> io::Result<BudgetedEntries<'_, R>> {
    let entries = archive.entries()?;
    Ok(BudgetedEntries::new(entries, budget))
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn disarmed_reader_passes_bytes_through_unchanged() {
        let (mut reader, budget) = budgeted_reader(Cursor::new(b"hello world".to_vec()), 4);
        budget.disarm();
        let mut out = Vec::new();
        reader.read_to_end(&mut out).unwrap();
        assert_eq!(out, b"hello world");
    }

    #[test]
    fn armed_reader_allows_exactly_the_limit() {
        let (mut reader, budget) = budgeted_reader(Cursor::new(vec![b'a'; 10]), 10);
        budget.arm();
        let mut out = Vec::new();
        reader.read_to_end(&mut out).unwrap();
        assert_eq!(out.len(), 10);
    }

    #[test]
    fn armed_reader_trips_at_limit_plus_one_with_err_not_ok_zero() {
        // Regression for critic finding S4: a naive clamp-to-empty-slice at
        // exhaustion returns `Ok(0)`, which `tar`'s own `try_read_all` (and
        // any other EOF-sensing consumer) treats as clean end-of-archive —
        // silently truncating output instead of failing loudly.
        let (mut reader, budget) = budgeted_reader(Cursor::new(vec![b'a'; 11]), 10);
        budget.arm();
        let mut out = Vec::new();
        let err = reader
            .read_to_end(&mut out)
            .expect_err("must error, not silently truncate");
        assert!(
            budget_violation(&err).is_some(),
            "must be recognizable as a budget violation, got: {err:?}"
        );
    }

    #[test]
    fn new_reader_is_armed_from_construction() {
        // Regression for critic finding S3: if the budget started disarmed,
        // a call site that forgets to pair the reader with `BudgetedEntries`
        // (never calling `arm()`/`disarm()` itself) would run unprotected —
        // exactly the regression this whole redesign exists to prevent.
        let (mut reader, _budget) = budgeted_reader(Cursor::new(vec![b'a'; 11]), 10);
        let mut out = Vec::new();
        let err = reader
            .read_to_end(&mut out)
            .expect_err("a freshly constructed reader must already be armed");
        assert!(budget_violation(&err).is_some());
    }

    #[test]
    fn rearming_resets_consumed_bytes() {
        let (mut reader, budget) = budgeted_reader(Cursor::new(vec![b'a'; 20]), 10);
        budget.arm();
        let mut buf = [0u8; 10];
        reader.read_exact(&mut buf).unwrap();
        // Disarm, do something unmetered, then arm again: the fresh window
        // must not inherit the previous window's consumed count.
        budget.disarm();
        budget.arm();
        let mut out = Vec::new();
        reader.read_to_end(&mut out).unwrap();
        assert_eq!(
            out.len(),
            10,
            "re-armed window must allow a fresh `limit` bytes"
        );
    }

    /// Builds a minimal one-entry TAR archive (ustar) around `content`.
    fn one_entry_tar(name: &str, content: &[u8]) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_size(content.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder.append_data(&mut header, name, content).unwrap();
        builder.into_inner().unwrap()
    }

    #[test]
    fn budgeted_entries_yields_a_well_formed_archive_normally() {
        let data = one_entry_tar("file.txt", b"hello");
        let (reader, budget) = budgeted_reader(Cursor::new(data), 4096);
        let mut archive = tar::Archive::new(reader);
        let mut entries = budgeted_tar_entries(&mut archive, budget).unwrap();

        let mut guard = entries
            .next_entry()
            .expect("one entry")
            .expect("no io error");
        let mut content = Vec::new();
        guard.read_to_end(&mut content).unwrap();
        assert_eq!(content, b"hello");
        drop(guard);

        assert!(entries.next_entry().is_none(), "exactly one entry");
    }

    #[test]
    fn drop_drains_unread_entry_so_the_next_header_is_found() {
        let mut data = one_entry_tar("skipped.txt", b"unread content");
        // Append a second entry after the first.
        let mut builder = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_size(5);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, "after.txt", &b"hello"[..])
            .unwrap();
        let second = builder.into_inner().unwrap();
        // Splice: first entry's header+data (without its own EOF markers)
        // followed by the second archive's single entry and its EOF markers.
        data.truncate(data.len() - 1024); // drop first archive's EOF markers
        data.extend_from_slice(&second);

        let (reader, budget) = budgeted_reader(Cursor::new(data), 4096);
        let mut archive = tar::Archive::new(reader);
        let mut entries = budgeted_tar_entries(&mut archive, budget).unwrap();

        let guard = entries.next_entry().unwrap().unwrap();
        // Deliberately never read `guard`'s content — the Drop below must
        // still leave the stream correctly positioned for the next header.
        drop(guard);

        let mut second_guard = entries
            .next_entry()
            .expect("second entry must still be reachable")
            .expect("no io error");
        let mut content = Vec::new();
        second_guard.read_to_end(&mut content).unwrap();
        assert_eq!(content, b"hello");
    }

    #[test]
    fn abandon_suppresses_the_drain() {
        let data = one_entry_tar("file.txt", b"hello");
        let (reader, budget) = budgeted_reader(Cursor::new(data), 4096);
        let mut archive = tar::Archive::new(reader);
        let mut entries = budgeted_tar_entries(&mut archive, budget).unwrap();

        let mut guard = entries.next_entry().unwrap().unwrap();
        guard.abandon();
        // No assertion beyond "does not panic and drops cleanly": abandon()
        // only affects whether Drop performs I/O, which has no externally
        // observable effect once the whole `BudgetedEntries` is discarded.
        drop(guard);
    }

    #[test]
    fn oversized_metadata_record_trips_the_budget() {
        // A GNU long-name record whose real (delivered) bytes exceed the
        // configured budget must trip before `tar` finishes buffering it.
        let long_name = "x".repeat(2048);
        let mut builder = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_size(5);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, long_name.as_str(), &b"hello"[..])
            .unwrap();
        let data = builder.into_inner().unwrap();

        let (reader, budget) = budgeted_reader(Cursor::new(data), 512);
        let mut archive = tar::Archive::new(reader);
        let mut entries = budgeted_tar_entries(&mut archive, budget).unwrap();

        // `.err()` first: `TarEntryGuard` (the `Ok` side) does not implement
        // `Debug` (it holds a `tar::Entry`, which does not either), so
        // `Result::expect_err` (which requires `T: Debug`) does not apply —
        // `Option::expect` on the converted `Option<io::Error>` does not
        // need the discarded `Ok` value to implement anything.
        let result = entries.next_entry().expect("an entry attempt");
        let err = result
            .err()
            .expect("the long-name record exceeds the 512-byte budget");
        assert!(budget_violation(&err).is_some(), "got: {err:?}");
    }

    /// Reader that counts total bytes yielded by `inner`, used below to
    /// observe how much `TarEntryGuard::drop` actually drains without relying
    /// on heap-allocation measurement (which a `Take`-limited `io::sink` drain
    /// would not show regardless of how large the drain is).
    struct CountingReader<R> {
        inner: R,
        count: Arc<AtomicU64>,
    }

    impl<R: Read> Read for CountingReader<R> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            let n = self.inner.read(buf)?;
            self.count.fetch_add(n as u64, Ordering::Relaxed);
            Ok(n)
        }
    }

    #[test]
    fn drop_fully_drains_a_legitimate_large_entry_regardless_of_size() {
        // Regression for critic findings C2/C3: a fixed cap on *total*
        // drained output (the earlier, broken designs) rejects any ordinary
        // archive whose unread entry exceeds that cap — worse than the
        // original bug, since no crafting is needed to trip it. A
        // legitimate entry's drain consumes real bytes 1:1 with its output,
        // so `synthetic` never grows and this must drain to completion no
        // matter how large the entry is (here: comfortably larger than
        // `SYNTHETIC_PAD_CAP_BYTES`).
        let content_len = usize::try_from(SYNTHETIC_PAD_CAP_BYTES).unwrap() * 3;
        let data = one_entry_tar("legit_large.bin", &vec![b'A'; content_len]);

        let read_count = Arc::new(AtomicU64::new(0));
        let counting = CountingReader {
            inner: Cursor::new(data),
            count: Arc::clone(&read_count),
        };

        let (reader, budget) = budgeted_reader(counting, 4096);
        let mut archive = tar::Archive::new(reader);
        let mut entries = budgeted_tar_entries(&mut archive, budget).unwrap();

        let guard = entries.next_entry().unwrap().unwrap();
        // Deliberately never read `guard`'s content — the drop must still
        // fully drain it, exactly like the "skip an unread entry" case on
        // `list`/`verify`/extension-filtered `extract`.
        drop(guard);

        let drained = read_count.load(Ordering::Relaxed);
        // The one-entry archive is: 512-byte header + content (block-padded)
        // + two 512-byte zero blocks (end-of-archive trailer). The drain
        // must consume at least the full content, proving it was not cut
        // short by any fixed output cap.
        assert!(
            drained >= 512 + u64::try_from(content_len).unwrap(),
            "drop must fully drain a legitimate large entry, drained only {drained} bytes of a \
             {content_len}-byte entry"
        );
    }

    /// Builds a raw one-entry TAR archive with a GNU old-format sparse
    /// header (typeflag `'S'`) whose `realsize` vastly exceeds its one-block
    /// physical backing — the same on-disk shape as issue #414's C1 `PoC`,
    /// used here to unit-test the synthetic-byte cap directly rather than
    /// relying only on the integration-level regression test.
    fn gnu_sparse_bomb_tar(realsize: u64) -> Vec<u8> {
        const HDR_BLOCK: usize = 512;
        fn octal_field(n: u64, width: usize) -> Option<Vec<u8>> {
            let digits = format!("{n:o}").into_bytes();
            if digits.len() > width - 1 {
                return None;
            }
            let mut out = vec![b'0'; width - 1 - digits.len()];
            out.extend_from_slice(&digits);
            out.push(0);
            Some(out)
        }
        fn base256_field(n: u64, width: usize) -> Vec<u8> {
            let mut out = vec![0u8; width];
            let bytes = n.to_be_bytes();
            out[width - bytes.len()..].copy_from_slice(&bytes);
            out[0] |= 0x80;
            out
        }
        fn num_field(n: u64, width: usize) -> Vec<u8> {
            octal_field(n, width).unwrap_or_else(|| base256_field(n, width))
        }

        let gap = realsize - HDR_BLOCK as u64;
        let mut h = vec![0u8; HDR_BLOCK];
        let name = b"sparsebomb.bin";
        h[..name.len()].copy_from_slice(name);
        h[100..108].copy_from_slice(&num_field(0o644, 8));
        h[108..116].copy_from_slice(&num_field(0, 8));
        h[116..124].copy_from_slice(&num_field(0, 8));
        h[124..136].copy_from_slice(&num_field(HDR_BLOCK as u64, 12));
        h[136..148].copy_from_slice(&num_field(0, 12));
        h[156] = b'S';
        h[257..263].copy_from_slice(b"ustar ");
        h[263..265].copy_from_slice(b" \0");
        h[386..398].copy_from_slice(&num_field(gap, 12));
        h[398..410].copy_from_slice(&num_field(HDR_BLOCK as u64, 12));
        h[482] = 0;
        h[483..495].copy_from_slice(&num_field(realsize, 12));
        h[148..156].copy_from_slice(b"        ");
        let sum: u32 = h.iter().map(|b| u32::from(*b)).sum();
        h[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());

        let mut out = h;
        out.extend(std::iter::repeat_n(0u8, HDR_BLOCK)); // one real backing block
        out.extend(std::iter::repeat_n(0u8, HDR_BLOCK * 2)); // end-of-archive trailer
        out
    }

    #[test]
    fn drop_drain_stops_quickly_on_gnu_sparse_synthesized_padding() {
        // Regression for critic finding C1 (and confirms C2's fix did not
        // reopen it): a GNU sparse entry's zero-padding produces output with
        // no corresponding read, so `synthetic` grows immediately and the
        // drain must stop within a small, bounded number of bytes actually
        // read from the underlying reader — regardless of how large
        // `realsize` claims to be.
        let data = gnu_sparse_bomb_tar(1u64 << 50);

        let read_count = Arc::new(AtomicU64::new(0));
        let counting = CountingReader {
            inner: Cursor::new(data),
            count: Arc::clone(&read_count),
        };

        let (reader, budget) = budgeted_reader(counting, 4096);
        let mut archive = tar::Archive::new(reader);
        let mut entries = budgeted_tar_entries(&mut archive, budget).unwrap();

        let guard = entries.next_entry().unwrap().unwrap();
        drop(guard);

        let drained = read_count.load(Ordering::Relaxed);
        // The header (512 B) plus the one real backing block (512 B) plus a
        // generous margin for the synthetic cap's own chunking — nowhere
        // near the exabyte `realsize` the entry claims.
        assert!(
            drained
                <= 512 + 512 + SYNTHETIC_PAD_CAP_BYTES + u64::try_from(DRAIN_CHUNK_BYTES).unwrap(),
            "drop must stop draining almost immediately on synthesized padding, drained {drained} \
             bytes"
        );
    }
}

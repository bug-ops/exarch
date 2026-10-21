//! Bounded parallel decoding of one LZMA2 stream.
//!
//! An LZMA2 stream is a sequence of chunks. A chunk that resets the dictionary
//! (control byte `0x01` or `>= 0xE0`) starts an independent run, so the runs
//! between two resets can be decoded on different threads. The planner finds
//! those runs by reading chunk headers only, a worker decodes one run into an
//! owned buffer, and the consumer reads the runs back in order.
//!
//! Memory is bounded by a lookahead budget: every run handed to a worker is
//! charged for its packed bytes, its output and a pessimistic window, and the
//! charge is released as the run is joined and consumed. A run that does not
//! fit the budget is decoded inline as a stream by the consumer's thread, which
//! costs only the window. Anything the planner cannot prove well formed (a bad
//! control byte, truncation, a chunk that crosses the requested output) ends
//! the plan with a [`PlannedUnit::Tail`] that is decoded inline from the last
//! run start, exactly like a sequential reader, so the result never depends on
//! the number of cores.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;
use std::io::{self};
use std::num::NonZeroUsize;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;
use std::thread::Scope;
use std::thread::ScopedJoinHandle;
use std::thread::{self};

use lzma_rust2::Lzma2Reader;

/// Output bytes a worker decodes between two checks of the cancel flag.
const DECODE_STEP: usize = 1 << 20;
/// Fixed per-run allowance for the range decoder buffer and thread bookkeeping.
const UNIT_OVERHEAD: u64 = 128 * 1024;
/// Header bytes the planner reads from the source in one go.
const PLAN_WINDOW: u64 = 64 * 1024;
/// Smallest window a run is charged for.
const MIN_WINDOW: u64 = 64 * 1024;
/// Read size of the inline stream input.
const INPUT_BUFFER: usize = 128 * 1024;
/// Most worker threads in flight.
#[cfg(not(fuzzing))]
const MAX_THREADS: usize = 16;

/// Tuning knobs of the parallel decoder, passed explicitly so tests and fuzz
/// targets can force the parallel path on small inputs.
#[derive(Debug, Clone, Copy)]
pub struct DecodeKnobs {
    /// Output a run accumulates before the planner ends it at the next reset.
    pub min_unit: u64,
    /// Most runs decoded by workers at the same time.
    pub threads: NonZeroUsize,
    #[cfg(test)]
    pub fault: Option<WorkerFault>,
}

/// A failure injected into the worker with the given spawn index.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkerFault {
    PanicOn(usize),
    SpawnFailsOn(usize),
}

impl DecodeKnobs {
    /// Production values: 1 MiB runs and one worker per core, capped at 16.
    ///
    /// Under `cfg(fuzzing)` runs shrink to 1 KiB on two workers so small fuzz
    /// inputs reach the parallel path.
    pub fn production() -> Self {
        #[cfg(fuzzing)]
        return Self::new(1 << 10, 2);
        #[cfg(not(fuzzing))]
        {
            let cores = thread::available_parallelism().map_or(1, NonZeroUsize::get);
            Self::new(1 << 20, cores.min(MAX_THREADS))
        }
    }

    pub fn new(min_unit: u64, threads: usize) -> Self {
        Self {
            min_unit,
            threads: NonZeroUsize::new(threads).unwrap_or(NonZeroUsize::MIN),
            #[cfg(test)]
            fault: None,
        }
    }
}

/// One LZMA2 stream inside a source.
#[derive(Debug, Clone, Copy)]
pub struct Lzma2Stream {
    /// Absolute offset of the stream in the source.
    pub offset: u64,
    /// Packed length of the stream.
    pub len: u64,
    /// Output bytes the consumer may read; the plan never goes past it.
    pub output_len: u64,
    /// Dictionary size declared by the coder properties.
    pub dict_size: u32,
}

/// A run of chunks that starts at a dictionary reset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct Lzma2Unit {
    offset: u64,
    packed: u64,
    output: u64,
}

/// Memory a run holds while it is in flight, split by when it is released.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct UnitCharge {
    /// Packed input, window and overhead; released when the worker is joined.
    transient: u64,
    /// The output buffer; released when the consumer has read it.
    retained: u64,
}

impl Lzma2Unit {
    /// Pessimistic memory of a worker for this run.
    ///
    /// The decoder grows its window geometrically and a reallocation briefly
    /// holds both copies: up to 3/2 of the window when the output caps it, and
    /// up to twice the window when the dictionary does (the last growth step
    /// is clamped, so the old copy can be almost as large as the new one).
    fn charge(&self, dict_size: u32) -> Option<UnitCharge> {
        let wanted = self.output.saturating_mul(2).max(MIN_WINDOW);
        let dict = u64::from(dict_size);
        let window = if dict < wanted {
            dict.checked_mul(2)?
        } else {
            wanted.checked_add(wanted / 2)?
        };
        let transient = self
            .packed
            .checked_add(window)?
            .checked_add(UNIT_OVERHEAD)?;
        transient.checked_add(self.output)?;
        Some(UnitCharge {
            transient,
            retained: self.output,
        })
    }
}

/// What the planner hands out next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PlannedUnit {
    /// A well formed run: fits in a buffer and can be decoded by a worker.
    Buffered(Lzma2Unit),
    /// The rest of the stream from `offset` is decoded inline, unplanned.
    Tail { offset: u64 },
}

/// Positioned reads of the stream out of a shared source.
struct PackSource<'a, S> {
    source: &'a RefCell<S>,
    stream: Lzma2Stream,
}

impl<S> Clone for PackSource<'_, S> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<S> Copy for PackSource<'_, S> {}

impl<S: Read + Seek> PackSource<'_, S> {
    fn read_at(&self, offset: u64, buf: &mut [u8]) -> io::Result<()> {
        offset
            .checked_add(buf.len() as u64)
            .filter(|&end| end <= self.stream.len)
            .ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))?;
        let absolute = self
            .stream
            .offset
            .checked_add(offset)
            .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
        let mut source = self
            .source
            .try_borrow_mut()
            .map_err(|_| io::Error::other("LZMA2 source is already in use"))?;
        source.seek(SeekFrom::Start(absolute))?;
        source.read_exact(buf)
    }
}

/// A chunk header, reduced to what planning needs.
#[derive(Debug, Clone, Copy)]
enum Chunk {
    End,
    Data {
        resets: bool,
        header: u64,
        packed: u64,
        output: u64,
    },
}

/// Walks chunk headers lazily, holding O(1) state.
struct Lzma2Planner<'a, S> {
    pack: PackSource<'a, S>,
    /// Stream bytes from `window_start`, so headers a few bytes apart cost one
    /// read between them instead of one each.
    window: Vec<u8>,
    window_start: u64,
    offset: u64,
    produced: u64,
    min_unit: u64,
    finished: bool,
}

impl<'a, S: Read + Seek> Lzma2Planner<'a, S> {
    fn new(pack: PackSource<'a, S>, min_unit: u64) -> Self {
        Self {
            pack,
            window: Vec::new(),
            window_start: 0,
            offset: 0,
            produced: 0,
            min_unit,
            finished: false,
        }
    }

    /// Up to six bytes of the stream at `offset`, refilling the window when
    /// they are not all in it.
    fn head_at(&mut self, offset: u64) -> io::Result<[u8; 6]> {
        const HEAD: u64 = 6;
        let available = self.pack.stream.len.saturating_sub(offset);
        let wanted = available.min(HEAD);
        let in_window = |planner: &Self| {
            offset >= planner.window_start
                && offset - planner.window_start + wanted <= planner.window.len() as u64
        };
        if !in_window(self) {
            let fill = available.min(PLAN_WINDOW);
            self.window.clear();
            self.window
                .resize(usize::try_from(fill).unwrap_or_default(), 0);
            self.pack.read_at(offset, &mut self.window)?;
            self.window_start = offset;
        }
        let mut head = [0u8; 6];
        let at = usize::try_from(offset - self.window_start).unwrap_or_default();
        let len = usize::try_from(wanted).unwrap_or_default();
        head[..len].copy_from_slice(&self.window[at..at + len]);
        Ok(head)
    }

    /// Reads the header at `offset`; `None` for a malformed or truncated one.
    fn chunk_at(&mut self, offset: u64) -> io::Result<Option<Chunk>> {
        let available = self.pack.stream.len.saturating_sub(offset);
        if available == 0 {
            return Ok(None);
        }
        let head = self.head_at(offset)?;
        let first = usize::try_from(available.min(head.len() as u64)).unwrap_or(head.len());
        let control = head[0];
        let be16 = |at: usize| u64::from(u16::from_be_bytes([head[at], head[at + 1]]));
        let chunk = match control {
            0x00 => Some(Chunk::End),
            0x01 | 0x02 if first >= 3 => Some(Chunk::Data {
                resets: control == 0x01,
                header: 3,
                packed: be16(1) + 1,
                output: be16(1) + 1,
            }),
            0x80..=0xFF => {
                let header = if control >= 0xC0 { 6 } else { 5 };
                (first as u64 >= header).then(|| Chunk::Data {
                    resets: control >= 0xE0,
                    header,
                    packed: be16(3) + 1,
                    output: ((u64::from(control & 0x1F) << 16) | be16(1)) + 1,
                })
            }
            _ => None,
        };
        Ok(chunk)
    }

    /// Plans the next run, or `None` once the requested output is covered.
    fn next_unit(&mut self, needed: u64) -> io::Result<Option<PlannedUnit>> {
        if self.finished || self.produced >= needed {
            self.finished = true;
            return Ok(None);
        }
        let start = self.offset;
        let mut cursor = start;
        let mut output = 0u64;
        loop {
            if self.produced + output == needed {
                break;
            }
            let Some(Chunk::Data {
                resets,
                header,
                packed,
                output: chunk_output,
            }) = self.chunk_at(cursor)?
            else {
                return Ok(Some(self.tail(start)));
            };
            if cursor == start {
                if !resets {
                    return Ok(Some(self.tail(start)));
                }
            } else if resets && output >= self.min_unit {
                break;
            }
            let next_cursor = cursor
                .checked_add(header)
                .and_then(|c| c.checked_add(packed))
                .filter(|&c| c <= self.pack.stream.len);
            let next_output = output
                .checked_add(chunk_output)
                .filter(|&o| self.produced.saturating_add(o) <= needed);
            let (Some(next_cursor), Some(next_output)) = (next_cursor, next_output) else {
                return Ok(Some(self.tail(start)));
            };
            cursor = next_cursor;
            output = next_output;
        }
        self.offset = cursor;
        self.produced += output;
        Ok(Some(PlannedUnit::Buffered(Lzma2Unit {
            offset: start,
            packed: cursor - start,
            output,
        })))
    }

    fn tail(&mut self, offset: u64) -> PlannedUnit {
        self.finished = true;
        PlannedUnit::Tail { offset }
    }
}

/// Bytes of lookahead memory still available.
#[derive(Debug)]
struct Lookahead {
    free: u64,
}

impl Lookahead {
    fn acquire(&mut self, charge: UnitCharge) -> bool {
        let Some(total) = charge.transient.checked_add(charge.retained) else {
            return false;
        };
        if total > self.free {
            return false;
        }
        self.free -= total;
        true
    }

    fn release(&mut self, bytes: u64) {
        self.free = self.free.saturating_add(bytes);
    }
}

/// What a worker decoded: the bytes before the first failure, and the failure.
struct RunOutput {
    data: Vec<u8>,
    error: Option<io::Error>,
}

/// Decodes one run into an exactly sized buffer; `data` carries the run
/// followed by an end marker.
///
/// A failing run still hands back every byte decoded before the failure, so
/// the consumer sees the same files, and blames the same one, as a sequential
/// decode would.
fn decode_unit(data: &[u8], output: usize, dict_size: u32, cancel: &AtomicBool) -> RunOutput {
    let mut reader = Lzma2Reader::new(data, dict_size, None);
    let mut out = vec![0u8; output];
    let mut done = 0;
    while done < output {
        if cancel.load(Ordering::Relaxed) {
            return RunOutput {
                data: Vec::new(),
                error: Some(io::Error::other("LZMA2 decode cancelled")),
            };
        }
        let end = output.min(done + DECODE_STEP);
        if let Err(error) = reader.read_exact(&mut out[done..end]) {
            let valid = failing_prefix(data, dict_size, &mut out[..end], done);
            out.truncate(valid);
            return RunOutput {
                data: out,
                error: Some(error),
            };
        }
        done = end;
    }
    let error = expect_end(&mut reader).err();
    RunOutput { data: out, error }
}

/// Bytes of `out[..end]` that decode before the failure, given that the first
/// `done` bytes are known good.
///
/// A failed read loses the bytes of its own call, so the failing step is
/// decoded again one byte at a time. Only runs that fail pay for it.
fn failing_prefix(data: &[u8], dict_size: u32, out: &mut [u8], done: usize) -> usize {
    let mut reader = Lzma2Reader::new(data, dict_size, None);
    if reader.read_exact(&mut out[..done]).is_err() {
        return done;
    }
    let mut valid = done;
    while valid < out.len() && matches!(reader.read(&mut out[valid..=valid]), Ok(1)) {
        valid += 1;
    }
    valid
}

/// Requires the decoder to be at its end marker.
fn expect_end(reader: &mut impl Read) -> io::Result<()> {
    let mut probe = [0u8; 1];
    if reader.read(&mut probe)? == 0 {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "LZMA2 run is longer than planned",
        ))
    }
}

/// Packed input of an inline stream, with an optional end marker appended.
struct UnitInput<'a, S> {
    pack: PackSource<'a, S>,
    pos: u64,
    end: u64,
    buf: Vec<u8>,
    buf_pos: usize,
    terminator: Option<u8>,
}

impl<'a, S: Read + Seek> UnitInput<'a, S> {
    fn new(pack: PackSource<'a, S>, pos: u64, end: u64, terminator: Option<u8>) -> Self {
        Self {
            pack,
            pos,
            end,
            buf: Vec::new(),
            buf_pos: 0,
            terminator,
        }
    }
}

impl<S: Read + Seek> Read for UnitInput<'_, S> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        if self.buf_pos == self.buf.len() {
            let remaining = self.end - self.pos;
            if remaining == 0 {
                return Ok(self.terminator.take().map_or(0, |byte| {
                    out[0] = byte;
                    1
                }));
            }
            let take = usize::try_from(remaining).map_or(INPUT_BUFFER, |r| r.min(INPUT_BUFFER));
            self.buf.clear();
            self.buf.resize(take, 0);
            self.pack.read_at(self.pos, &mut self.buf)?;
            self.pos += take as u64;
            self.buf_pos = 0;
        }
        let n = out.len().min(self.buf.len() - self.buf_pos);
        out[..n].copy_from_slice(&self.buf[self.buf_pos..self.buf_pos + n]);
        self.buf_pos += n;
        Ok(n)
    }
}

/// A run decoded on the consumer's thread as a stream.
struct InlineStream<'a, S> {
    reader: Lzma2Reader<UnitInput<'a, S>>,
    /// Output still owed by a planned run; `None` for the unplanned tail.
    remaining: Option<u64>,
}

enum Pending<'scope> {
    Running {
        handle: ScopedJoinHandle<'scope, RunOutput>,
        charge: UnitCharge,
    },
    Inline(Lzma2Unit),
}

enum Current<'a, S> {
    Idle,
    Buffered {
        data: Vec<u8>,
        pos: usize,
        retained: u64,
        /// Delivered once `data` is read.
        error: Option<io::Error>,
    },
    Stream(Box<InlineStream<'a, S>>),
}

/// Reads the decoded stream in order while workers decode ahead.
pub struct ParallelLzma2<'scope, 'env, S> {
    scope: &'scope Scope<'scope, 'env>,
    cancel: &'env AtomicBool,
    pack: PackSource<'env, S>,
    knobs: DecodeKnobs,
    planner: Lzma2Planner<'env, S>,
    needed: u64,
    stash: Option<PlannedUnit>,
    lookahead: Lookahead,
    queue: VecDeque<Pending<'scope>>,
    running: usize,
    spawned: usize,
    spawn_failed: bool,
    poisoned: bool,
    deferred: Option<io::Error>,
    current: Current<'env, S>,
}

impl<'scope, 'env, S: Read + Seek> ParallelLzma2<'scope, 'env, S> {
    fn new(
        scope: &'scope Scope<'scope, 'env>,
        cancel: &'env AtomicBool,
        source: &'env RefCell<S>,
        stream: Lzma2Stream,
        knobs: DecodeKnobs,
        lookahead_bytes: u64,
    ) -> Self {
        let pack = PackSource { source, stream };
        Self {
            scope,
            cancel,
            pack,
            knobs,
            planner: Lzma2Planner::new(pack, knobs.min_unit),
            needed: stream.output_len,
            stash: None,
            lookahead: Lookahead {
                free: lookahead_bytes,
            },
            queue: VecDeque::new(),
            running: 0,
            spawned: 0,
            spawn_failed: false,
            poisoned: false,
            deferred: None,
            current: Current::Idle,
        }
    }

    fn next_planned(&mut self) -> io::Result<Option<PlannedUnit>> {
        match self.stash.take() {
            Some(planned) => Ok(Some(planned)),
            None => self.planner.next_unit(self.needed),
        }
    }

    /// [`fill`](Self::fill), keeping an error for the point where the consumer
    /// reaches the runs it concerns, after the runs already queued.
    fn fill_deferring(&mut self) {
        if let Err(error) = self.fill() {
            self.deferred = Some(error);
        }
    }

    /// Starts workers for the runs after the head while the budget allows.
    ///
    /// Stops for good at the first thread that cannot be spawned: the
    /// remaining runs decode inline as they become the head.
    fn fill(&mut self) -> io::Result<()> {
        if self.spawn_failed || self.deferred.is_some() {
            return Ok(());
        }
        while self.running < self.knobs.threads.get() {
            let Some(planned) = self.next_planned()? else {
                break;
            };
            let PlannedUnit::Buffered(unit) = planned else {
                self.stash = Some(planned);
                break;
            };
            let dict = self.pack.stream.dict_size;
            let charge = unit.charge(dict).filter(|&c| self.lookahead.acquire(c));
            let Some(charge) = charge else {
                self.stash = Some(planned);
                break;
            };
            match self.spawn(unit, dict) {
                Ok(handle) => {
                    self.running += 1;
                    self.queue.push_back(Pending::Running { handle, charge });
                }
                Err(SpawnFailure::Source(e)) => return Err(e),
                Err(SpawnFailure::Thread) => {
                    self.lookahead.release(charge.transient + charge.retained);
                    self.queue.push_back(Pending::Inline(unit));
                    self.spawn_failed = true;
                    break;
                }
            }
        }
        Ok(())
    }

    fn spawn(
        &mut self,
        unit: Lzma2Unit,
        dict: u32,
    ) -> Result<ScopedJoinHandle<'scope, RunOutput>, SpawnFailure> {
        let packed = usize::try_from(unit.packed)
            .ok()
            .filter(|&p| p < isize::MAX as usize)
            .ok_or(SpawnFailure::Thread)?;
        let output = usize::try_from(unit.output).map_err(|_| SpawnFailure::Thread)?;
        let mut data = vec![0u8; packed + 1];
        self.pack
            .read_at(unit.offset, &mut data[..packed])
            .map_err(SpawnFailure::Source)?;
        let cancel = self.cancel;
        let index = self.spawned;
        self.spawned += 1;
        #[cfg(test)]
        let fault = self.knobs.fault;
        #[cfg(test)]
        if fault == Some(WorkerFault::SpawnFailsOn(index)) {
            return Err(SpawnFailure::Thread);
        }
        thread::Builder::new()
            .name(format!("exarch-lzma2-{index}"))
            .spawn_scoped(self.scope, move || {
                #[cfg(test)]
                assert!(
                    fault != Some(WorkerFault::PanicOn(index)),
                    "injected LZMA2 worker panic"
                );
                decode_unit(&data, output, dict, cancel)
            })
            .map_err(|_| SpawnFailure::Thread)
    }

    fn inline_stream(&self, planned: PlannedUnit) -> InlineStream<'env, S> {
        let dict = self.pack.stream.dict_size;
        let (pos, end, terminator, remaining) = match planned {
            PlannedUnit::Buffered(unit) => (
                unit.offset,
                unit.offset + unit.packed,
                Some(0u8),
                Some(unit.output),
            ),
            PlannedUnit::Tail { offset } => (offset, self.pack.stream.len, None, None),
        };
        InlineStream {
            reader: Lzma2Reader::new(UnitInput::new(self.pack, pos, end, terminator), dict, None),
            remaining,
        }
    }

    /// Moves to the next run; `false` at the end of the stream.
    fn advance(&mut self) -> io::Result<bool> {
        match self.queue.pop_front() {
            Some(Pending::Running { handle, charge }) => {
                self.running -= 1;
                let joined = handle.join();
                self.lookahead.release(charge.transient);
                let run = joined.map_err(|_| io::Error::other("LZMA2 worker panicked"))?;
                self.fill_deferring();
                self.current = Current::Buffered {
                    data: run.data,
                    pos: 0,
                    retained: charge.retained,
                    error: run.error,
                };
                Ok(true)
            }
            Some(Pending::Inline(unit)) => {
                self.fill_deferring();
                self.current =
                    Current::Stream(Box::new(self.inline_stream(PlannedUnit::Buffered(unit))));
                Ok(true)
            }
            None => {
                if let Some(error) = self.deferred.take() {
                    return Err(error);
                }
                let Some(planned) = self.next_planned()? else {
                    return Ok(false);
                };
                self.fill_deferring();
                self.current = Current::Stream(Box::new(self.inline_stream(planned)));
                Ok(true)
            }
        }
    }
}

enum SpawnFailure {
    Source(io::Error),
    Thread,
}

impl<S: Read + Seek> Read for ParallelLzma2<'_, '_, S> {
    /// After an error every further read fails: the stream cannot resume.
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.poisoned {
            return Err(io::Error::other("LZMA2 stream failed earlier"));
        }
        let result = self.read_run(buf);
        self.poisoned = result.is_err();
        result
    }
}

impl<S: Read + Seek> ParallelLzma2<'_, '_, S> {
    fn read_run(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        loop {
            match &mut self.current {
                Current::Buffered {
                    data,
                    pos,
                    retained,
                    error,
                } => {
                    if *pos < data.len() {
                        let n = buf.len().min(data.len() - *pos);
                        buf[..n].copy_from_slice(&data[*pos..*pos + n]);
                        *pos += n;
                        return Ok(n);
                    }
                    let (retained, error) = (*retained, error.take());
                    self.lookahead.release(retained);
                    self.current = Current::Idle;
                    if let Some(error) = error {
                        return Err(error);
                    }
                }
                Current::Stream(stream) => {
                    let want = stream.remaining.map_or(buf.len(), |r| {
                        buf.len().min(usize::try_from(r).unwrap_or(usize::MAX))
                    });
                    let n = stream.reader.read(&mut buf[..want])?;
                    match (&mut stream.remaining, n) {
                        (None, 0) => self.current = Current::Idle,
                        (Some(_), 0) => return Err(io::ErrorKind::UnexpectedEof.into()),
                        (remaining, n) => {
                            if let Some(left) = remaining {
                                *left -= n as u64;
                                if *left == 0 {
                                    expect_end(&mut stream.reader)?;
                                    self.current = Current::Idle;
                                }
                            }
                            return Ok(n);
                        }
                    }
                }
                Current::Idle => {
                    if !self.advance()? {
                        return Ok(0);
                    }
                }
            }
        }
    }
}

impl<S> Drop for ParallelLzma2<'_, '_, S> {
    fn drop(&mut self) {
        self.cancel.store(true, Ordering::Relaxed);
        for pending in self.queue.drain(..) {
            if let Pending::Running { handle, .. } = pending {
                drop(handle.join());
            }
        }
    }
}

/// Runs `consume` over the decoded stream, decoding ahead on worker threads
/// within `lookahead_bytes` of extra memory.
///
/// Every worker is joined before this returns, on success, error and panic
/// alike. Decode and source errors surface as read errors of the reader
/// `consume` receives.
pub fn with_parallel_reader<S: Read + Seek, T>(
    source: S,
    stream: Lzma2Stream,
    knobs: DecodeKnobs,
    lookahead_bytes: u64,
    consume: impl FnOnce(&mut dyn Read) -> T,
) -> T {
    let source = RefCell::new(source);
    let cancel = AtomicBool::new(false);
    thread::scope(|scope| {
        let mut reader =
            ParallelLzma2::new(scope, &cancel, &source, stream, knobs, lookahead_bytes);
        consume(&mut reader)
    })
}

#[cfg(test)]
mod tests;

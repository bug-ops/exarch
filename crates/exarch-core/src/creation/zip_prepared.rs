//! Prepared ZIP entries: compression that may run off the calling thread.
//!
//! Every regular file of at most [`PREPARED_ENTRY_LIMIT`] bytes is compressed
//! into memory by a [`PreparedJob`] and appended with `add_prepared_file`, in
//! every mode. [`Workers`] only decides which thread runs a job, so the bytes
//! of an archive never depend on [`Parallelism`](crate::Parallelism).
//!
//! This is the only module that names the `zip` prepared-entry API.

use std::any::Any;
use std::collections::BTreeMap;
use std::fs::File;
use std::io::Read;
use std::io::Write;
use std::num::NonZeroUsize;
use std::panic::AssertUnwindSafe;
use std::panic::catch_unwind;
use std::panic::resume_unwind;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::mpsc;
use std::thread::Builder;
use std::thread::Scope;

use zip::PreparedZipFile;
use zip::write::SimpleFileOptions;
use zip::write::ZipFileBuilder;

use crate::ArchiveError;
use crate::IoContext;
use crate::Parallelism;
use crate::Result;
use crate::creation::open::ExactReader;
use crate::creation::source::source_error;

/// Largest source, by the size of the opened handle, that is compressed into
/// memory; larger files stream through the archive writer.
pub(crate) const PREPARED_ENTRY_LIMIT: u64 = 8 * 1024 * 1024;

const COPY_BUFFER: usize = 64 * 1024;

/// A verified, open source awaiting compression into a prepared entry.
#[derive(Debug)]
pub(crate) struct PreparedJob {
    pub(crate) path: PathBuf,
    pub(crate) name: String,
    pub(crate) options: SimpleFileOptions,
    pub(crate) reader: ExactReader<File>,
}

impl PreparedJob {
    /// Compresses the whole source.
    ///
    /// # Errors
    ///
    /// A source failure (including [`ArchiveError::SourceChanged`]) for a read
    /// that fails; an I/O error when the entry cannot be built.
    pub(crate) fn compress(mut self) -> Result<PreparedZipFile> {
        #[cfg(test)]
        assert!(self.name != tests::PANIC_NAME, "injected compression panic");
        let mut builder = ZipFileBuilder::new(&self.name, self.options)
            .map_err(|e| zip_error("failed to start prepared zip entry", &e))?;
        let mut buffer = vec![0u8; COPY_BUFFER];
        loop {
            let read = match self.reader.read(&mut buffer) {
                Ok(0) => break,
                Ok(read) => read,
                Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(e) => return Err(source_error(&self.path, e)),
            };
            let chunk = buffer.get(..read).ok_or_else(|| {
                source_error(
                    &self.path,
                    std::io::Error::from(std::io::ErrorKind::InvalidData),
                )
            })?;
            builder.write_all(chunk)?;
        }
        builder
            .finish()
            .map_err(|e| zip_error("failed to finish prepared zip entry", &e))
    }
}

pub(crate) fn zip_error(context: &'static str, error: &zip::result::ZipError) -> ArchiveError {
    ArchiveError::Io(std::io::Error::other(IoContext::new(
        context,
        error.to_string(),
    )))
}

/// Worker threads for the current scope, or `None` when jobs run on the calling
/// thread: [`Parallelism::Sequential`], a single worker, and targets that
/// cannot spawn threads.
pub(crate) fn worker_count(parallelism: Parallelism) -> Option<NonZeroUsize> {
    if cfg!(target_os = "wasi") {
        return None;
    }
    match parallelism {
        Parallelism::Threads(requested) => {
            let available = std::thread::available_parallelism().map_or(1, NonZeroUsize::get);
            NonZeroUsize::new(requested.get().min(available)).filter(|n| n.get() > 1)
        }
        _ => None,
    }
}

/// Where a staged [`PreparedJob`] is compressed, and what is held for it until
/// its turn in archive order.
///
/// The pending value is the job itself when the calling thread compresses it,
/// and a marker when a worker already has it, so a handle to a worker never
/// exists without workers.
pub(crate) trait Executor {
    /// What the staging area keeps for a dispatched job.
    type Pending;

    /// Takes `job` as the entry at archive position `index`.
    ///
    /// # Errors
    ///
    /// An I/O error when no worker can take it.
    fn dispatch(&self, index: usize, job: PreparedJob) -> Result<Self::Pending>;

    /// Produces the prepared entry for `pending` at `index`, waiting for it if
    /// needed.
    ///
    /// # Errors
    ///
    /// The error of the job, or an I/O error when every worker has stopped.
    fn collect(&mut self, index: usize, pending: Self::Pending) -> Result<PreparedZipFile>;

    /// Entries that may be dispatched ahead of the write position.
    fn capacity(&self) -> usize;
}

/// Compresses on the calling thread, at the entry's turn.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Inline;

impl Executor for Inline {
    type Pending = PreparedJob;

    fn dispatch(&self, _index: usize, job: PreparedJob) -> Result<PreparedJob> {
        Ok(job)
    }

    fn collect(&mut self, _index: usize, pending: PreparedJob) -> Result<PreparedZipFile> {
        pending.compress()
    }

    fn capacity(&self) -> usize {
        0
    }
}

/// A job a worker holds; only [`Workers`] hands one out.
#[derive(Debug)]
pub(crate) struct Submitted(());

impl Executor for Workers {
    type Pending = Submitted;

    fn dispatch(&self, index: usize, job: PreparedJob) -> Result<Submitted> {
        self.submit(index, job)?;
        Ok(Submitted(()))
    }

    fn collect(&mut self, index: usize, _pending: Submitted) -> Result<PreparedZipFile> {
        self.take(index)
    }

    fn capacity(&self) -> usize {
        self.capacity
    }
}

/// What a worker reports for one job; a panic is carried to the thread that
/// waits for the entry instead of being lost with the worker.
enum Finished {
    Compressed(Result<PreparedZipFile>),
    Panicked(Box<dyn Any + Send>),
}

type Outcome = (usize, Finished);

/// A pool of scoped threads compressing jobs, with an archive-order reorder
/// buffer on the receiving side.
pub(crate) struct Workers {
    jobs: mpsc::SyncSender<(usize, PreparedJob)>,
    results: mpsc::Receiver<Outcome>,
    ready: BTreeMap<usize, Finished>,
    capacity: usize,
}

impl Workers {
    /// Starts `count` threads in `scope`. They stop when the pool is dropped.
    ///
    /// # Errors
    ///
    /// An I/O error when a thread cannot be spawned.
    pub(crate) fn spawn<'scope>(
        scope: &'scope Scope<'scope, '_>,
        count: NonZeroUsize,
    ) -> Result<Self> {
        let capacity = count.get().saturating_mul(2);
        let (jobs, job_rx) = mpsc::sync_channel::<(usize, PreparedJob)>(capacity);
        let (result_tx, results) = mpsc::channel::<Outcome>();
        let job_rx = Arc::new(Mutex::new(job_rx));
        for _ in 0..count.get() {
            let job_rx = Arc::clone(&job_rx);
            let result_tx = result_tx.clone();
            Builder::new().spawn_scoped(scope, move || {
                loop {
                    let Ok(queue) = job_rx.lock() else { break };
                    let next = queue.recv();
                    drop(queue);
                    let Ok((index, job)) = next else { break };
                    let finished = match catch_unwind(AssertUnwindSafe(|| job.compress())) {
                        Ok(compressed) => Finished::Compressed(compressed),
                        Err(payload) => Finished::Panicked(payload),
                    };
                    if result_tx.send((index, finished)).is_err() {
                        break;
                    }
                }
            })?;
        }
        Ok(Self {
            jobs,
            results,
            ready: BTreeMap::new(),
            capacity,
        })
    }

    /// Queues `job` as the entry at archive position `index`.
    ///
    /// The caller keeps at most [`Executor::capacity`] jobs outstanding, so
    /// this never blocks.
    ///
    /// # Errors
    ///
    /// An I/O error when every worker has stopped.
    fn submit(&self, index: usize, job: PreparedJob) -> Result<()> {
        self.jobs.send((index, job)).map_err(|_| worker_lost())
    }

    /// Waits for the entry at `index`, holding later finished entries back.
    ///
    /// # Errors
    ///
    /// The error of that entry's job, or an I/O error when every worker has
    /// stopped.
    ///
    /// # Panics
    ///
    /// Resumes the panic of that entry's job on the calling thread.
    fn take(&mut self, index: usize) -> Result<PreparedZipFile> {
        loop {
            match self.ready.remove(&index) {
                Some(Finished::Compressed(outcome)) => return outcome,
                Some(Finished::Panicked(payload)) => resume_unwind(payload),
                None => {}
            }
            let (done, outcome) = self.results.recv().map_err(|_| worker_lost())?;
            self.ready.insert(done, outcome);
        }
    }
}

fn worker_lost() -> ArchiveError {
    ArchiveError::Io(std::io::Error::other(IoContext::new(
        "zip compression worker stopped",
        String::new(),
    )))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::assert_matches;

    pub(super) const PANIC_NAME: &str = "panic-on-compress";

    fn named(name: &str, content: &[u8]) -> (tempfile::TempDir, PreparedJob) {
        let (dir, mut job) = job_over(content, content.len() as u64);
        job.name = name.to_string();
        (dir, job)
    }

    #[test]
    fn a_worker_panic_surfaces_on_the_waiting_thread_instead_of_hanging() {
        let (_a, fine) = named("fine", b"data");
        let (_b, boom) = named(PANIC_NAME, b"data");
        let (_c, later) = named("later", b"data");

        std::thread::scope(|scope| {
            let mut pool = Workers::spawn(scope, NonZeroUsize::new(2).unwrap()).unwrap();
            pool.submit(0, fine).unwrap();
            pool.submit(1, boom).unwrap();
            pool.submit(2, later).unwrap();

            assert!(pool.take(0).is_ok());
            let panicked = catch_unwind(AssertUnwindSafe(|| pool.take(1)));
            assert!(panicked.is_err());
            assert!(pool.take(2).is_ok());
        });
    }

    fn job_over(content: &[u8], claimed: u64) -> (tempfile::TempDir, PreparedJob) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("f.bin");
        std::fs::File::create(&path)
            .unwrap()
            .write_all(content)
            .unwrap();
        let job = PreparedJob {
            path: path.clone(),
            name: "f.bin".to_string(),
            options: SimpleFileOptions::default(),
            reader: ExactReader::new(File::open(&path).unwrap(), claimed),
        };
        (dir, job)
    }

    #[test]
    fn a_source_shorter_than_its_stat_is_source_changed() {
        let (_dir, job) = job_over(b"0123456789", 20);

        assert_matches!(job.compress(), Err(ArchiveError::SourceChanged { .. }));
    }

    #[test]
    fn a_source_longer_than_its_stat_is_source_changed() {
        let (_dir, job) = job_over(b"0123456789", 4);

        assert_matches!(job.compress(), Err(ArchiveError::SourceChanged { .. }));
    }

    #[test]
    fn an_exact_source_compresses() {
        let (_dir, job) = job_over(b"0123456789", 10);

        assert!(job.compress().is_ok());
    }

    #[test]
    fn sequential_and_one_thread_run_inline() {
        assert_eq!(worker_count(Parallelism::Sequential), None);
        assert_eq!(worker_count(Parallelism::Threads(NonZeroUsize::MIN)), None);
    }

    #[test]
    fn threads_are_clamped_to_the_available_cores() {
        let available = std::thread::available_parallelism().map_or(1, NonZeroUsize::get);
        let many = NonZeroUsize::new(available.saturating_mul(64)).unwrap();

        let workers = worker_count(Parallelism::Threads(many));

        assert_eq!(workers.map_or(1, NonZeroUsize::get), available);
    }
}

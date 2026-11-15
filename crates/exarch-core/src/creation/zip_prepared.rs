//! Prepared ZIP entries: compression that may run off the calling thread.
//!
//! Every regular file of at most [`PREPARED_ENTRY_LIMIT`] bytes is compressed
//! into memory by a [`PreparedJob`] and appended with `add_prepared_file`, in
//! every mode. [`Workers`] only decides which thread runs a job, so the bytes
//! of an archive never depend on [`Parallelism`](crate::Parallelism).
//!
//! This is the only module that names the `zip` prepared-entry API.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::Read;
use std::io::Write;
use std::num::NonZeroUsize;
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

type Outcome = (usize, Result<PreparedZipFile>);

/// A pool of scoped threads compressing jobs, with an archive-order reorder
/// buffer on the receiving side.
pub(crate) struct Workers {
    jobs: mpsc::SyncSender<(usize, PreparedJob)>,
    results: mpsc::Receiver<Outcome>,
    ready: BTreeMap<usize, Result<PreparedZipFile>>,
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
                    if result_tx.send((index, job.compress())).is_err() {
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

    /// Entries that may be submitted and not yet taken.
    pub(crate) const fn capacity(&self) -> usize {
        self.capacity
    }

    /// Queues `job` as the entry at archive position `index`.
    ///
    /// The caller keeps at most [`Workers::capacity`] jobs outstanding, so this
    /// never blocks.
    ///
    /// # Errors
    ///
    /// An I/O error when every worker has stopped.
    pub(crate) fn submit(&self, index: usize, job: PreparedJob) -> Result<()> {
        self.jobs.send((index, job)).map_err(|_| worker_lost())
    }

    /// Waits for the entry at `index`, holding later finished entries back.
    ///
    /// # Errors
    ///
    /// The error of that entry's job, or an I/O error when every worker has
    /// stopped.
    pub(crate) fn take(&mut self, index: usize) -> Result<PreparedZipFile> {
        loop {
            if let Some(outcome) = self.ready.remove(&index) {
                return outcome;
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
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::assert_matches;

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

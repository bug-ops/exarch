//! Progress tracking utilities for archive creation.
//!
//! This module provides reusable progress tracking components that work
//! with the `ProgressCallback` trait. These utilities consolidate progress
//! reporting logic to avoid duplication across TAR and ZIP creation.
//!
//! # Components
//!
//! - **`ProgressTracker`**: Manages progress callbacks with automatic entry
//!   counting
//! - **`ProgressReader`**: Wrapper reader that reports bytes read to progress
//!   callback

use crate::EntryPosition;
use crate::EntryTotal;
use crate::ProgressCallback;
use crate::copy::CancelClock;
use crate::formats::common::EntryCompleteGuard;
use crate::formats::io_marker::IoMarker;
use std::io;
use std::io::Read;
use std::path::Path;

/// Marks the [`io::Error`] a [`ProgressReader`] raises when the callback asks
/// to stop in the middle of an entry, so the writer that consumed the reader
/// can tell it from a source or sink fault.
#[derive(Debug, thiserror::Error)]
#[error("operation cancelled")]
pub(crate) struct CancelledMidEntry;

impl IoMarker for CancelledMidEntry {
    const KIND: io::ErrorKind = io::ErrorKind::Other;
}

/// Manages progress callbacks with automatic entry counting.
///
/// This struct consolidates progress-related state to reduce argument count
/// in helper functions. It automatically tracks the current entry number
/// and provides convenient methods for common progress reporting patterns.
///
/// # Batching
///
/// Progress callbacks are invoked at specific lifecycle points:
///
/// - `on_entry_start`: Called by `begin` before processing each entry
/// - `on_entry_complete`: Called when the guard from `begin` completes or
///   drops, so it follows every start even if the entry fails
/// - `on_complete`: Called once when the entire operation finishes
pub(crate) struct ProgressTracker<'a> {
    /// Reference to the progress callback implementation
    progress: &'a mut dyn ProgressCallback,
    /// Current entry number (1-indexed for user display)
    current_entry: usize,
    /// Total number of entries to process
    total_entries: usize,
}

impl<'a> ProgressTracker<'a> {
    /// Creates a new progress tracker.
    ///
    /// # Parameters
    ///
    /// - `progress`: Mutable reference to the progress callback
    /// - `total_entries`: Total number of entries that will be processed
    #[must_use]
    pub(crate) fn new(progress: &'a mut dyn ProgressCallback, total_entries: usize) -> Self {
        Self {
            progress,
            current_entry: 0,
            total_entries,
        }
    }

    /// Announces the entry at `path` and returns the guard that reports its
    /// completion when completed or dropped, including on an early `?` return.
    ///
    /// Automatically increments the current entry counter.
    ///
    /// # Errors
    ///
    /// Returns [`ArchiveError::Cancelled`](crate::ArchiveError::Cancelled)
    /// without announcing the entry when the callback asks to stop.
    pub(crate) fn begin<'p>(&'p mut self, path: &'p Path) -> crate::Result<EntryCompleteGuard<'p>> {
        let position =
            EntryPosition::at_index(self.current_entry, EntryTotal::Known(self.total_entries));
        self.current_entry = self.current_entry.saturating_add(1);
        EntryCompleteGuard::try_start(&mut *self.progress, path, position)
    }

    /// Reports that the entire operation completed.
    ///
    /// This should be called exactly once after all entries have been
    /// processed.
    pub(crate) fn on_complete(&mut self) {
        self.progress.on_complete();
    }

    /// Stops creation when the callback asks for it; see
    /// [`ProgressCallback::is_cancelled`].
    ///
    /// # Errors
    ///
    /// Returns [`ArchiveError::Cancelled`](crate::ArchiveError::Cancelled) when
    /// cancelled.
    pub(crate) fn check_cancelled(&mut self) -> crate::Result<()> {
        check_cancelled(&mut *self.progress)
    }
}

/// Wrapper reader that tracks bytes read and reports progress.
///
/// This reader wraps any `Read` implementation and reports bytes read
/// to a progress callback. To reduce callback overhead, it uses batching
/// with a configurable threshold (default: 1 MB).
///
/// # Batching Behavior
///
/// The reader accumulates bytes read and only invokes the progress callback
/// when:
///
/// 1. The accumulated bytes reach the batch threshold (default: 1 MB)
/// 2. The reader is dropped (flushes remaining bytes)
///
/// This reduces callback overhead for large files while still providing
/// responsive progress updates.
pub(crate) struct ProgressReader<'a, R> {
    /// Inner reader being wrapped
    inner: R,
    /// Reference to the progress callback
    progress: &'a mut dyn ProgressCallback,
    /// Bytes read since last progress update
    bytes_since_last_update: u64,
    /// Batch threshold in bytes (default: 1 MB)
    batch_threshold: u64,
    /// Bytes read so far, for the cancellation clock
    total_read: u64,
    /// Decides when the callback is asked about cancellation
    clock: CancelClock,
}

impl<'a, R> ProgressReader<'a, R> {
    /// Creates a new progress-tracking reader with default batch threshold.
    ///
    /// The default batch threshold is 1 MB (1,048,576 bytes).
    ///
    /// # Parameters
    ///
    /// - `inner`: The reader to wrap
    /// - `progress`: Mutable reference to the progress callback
    #[must_use]
    pub(crate) fn new(inner: R, progress: &'a mut dyn ProgressCallback) -> Self {
        Self {
            inner,
            progress,
            bytes_since_last_update: 0,
            batch_threshold: 1024 * 1024, // 1 MB batching threshold
            total_read: 0,
            clock: CancelClock::standard(),
        }
    }

    /// Replaces the cancellation poll interval, in bytes.
    #[cfg(test)]
    fn with_cancel_interval(mut self, interval: u64) -> Self {
        self.clock = CancelClock::new(interval);
        self
    }

    /// Creates a new progress-tracking reader with custom batch threshold.
    ///
    /// # Parameters
    ///
    /// - `inner`: The reader to wrap
    /// - `progress`: Mutable reference to the progress callback
    /// - `batch_threshold`: Number of bytes to accumulate before reporting
    #[must_use]
    #[allow(dead_code)]
    pub(crate) fn with_batch_threshold(
        inner: R,
        progress: &'a mut dyn ProgressCallback,
        batch_threshold: u64,
    ) -> Self {
        Self {
            inner,
            progress,
            bytes_since_last_update: 0,
            batch_threshold,
            total_read: 0,
            clock: CancelClock::standard(),
        }
    }

    /// Flushes any accumulated bytes to the progress callback.
    ///
    /// This is called automatically when the reader is dropped, but can
    /// be called manually if needed.
    pub(crate) fn flush_progress(&mut self) {
        if self.bytes_since_last_update > 0 {
            self.progress.on_bytes_written(self.bytes_since_last_update);
            self.bytes_since_last_update = 0;
        }
    }
}

impl<R: Read> Read for ProgressReader<'_, R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if self.clock.due(self.total_read) && self.progress.is_cancelled() {
            return Err(CancelledMidEntry.into_io());
        }
        let bytes_read = self.inner.read(buf)?;
        if bytes_read > 0 {
            self.total_read = self.total_read.saturating_add(bytes_read as u64);
            self.bytes_since_last_update = self
                .bytes_since_last_update
                .saturating_add(bytes_read as u64);
            if self.bytes_since_last_update >= self.batch_threshold {
                self.progress.on_bytes_written(self.bytes_since_last_update);
                self.bytes_since_last_update = 0;
            }
        }
        Ok(bytes_read)
    }
}

impl<R> Drop for ProgressReader<'_, R> {
    fn drop(&mut self) {
        self.flush_progress();
    }
}

/// Polls `progress` for a cancellation.
///
/// # Errors
///
/// Returns [`ArchiveError::Cancelled`](crate::ArchiveError::Cancelled) when
/// `progress` is cancelled.
pub(crate) fn check_cancelled(progress: &mut dyn ProgressCallback) -> crate::Result<()> {
    if progress.is_cancelled() {
        return Err(crate::ArchiveError::Cancelled);
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::unused_io_amount)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[derive(Debug, Default)]
    struct TestProgress {
        entries_started: Vec<String>,
        entries_completed: Vec<String>,
        bytes_written: u64,
        completed: bool,
    }

    impl ProgressCallback for TestProgress {
        fn on_entry_start(&mut self, path: &Path, _position: crate::EntryPosition) {
            self.entries_started
                .push(path.to_string_lossy().to_string());
        }

        fn on_bytes_written(&mut self, bytes: u64) {
            self.bytes_written += bytes;
        }

        fn on_entry_complete(&mut self, path: &Path) {
            self.entries_completed
                .push(path.to_string_lossy().to_string());
        }

        fn on_complete(&mut self) {
            self.completed = true;
        }
    }

    #[test]
    fn test_progress_tracker_entry_counting() {
        let mut progress = TestProgress::default();
        let mut tracker = ProgressTracker::new(&mut progress, 3);

        tracker.begin(Path::new("file1.txt")).unwrap().complete();
        drop(tracker.begin(Path::new("file2.txt")).unwrap());

        tracker.on_complete();

        assert_eq!(progress.entries_started.len(), 2);
        assert_eq!(progress.entries_completed.len(), 2);
        assert_eq!(progress.entries_started[0], "file1.txt");
        assert_eq!(progress.entries_started[1], "file2.txt");
        assert!(progress.completed);
    }

    #[test]
    fn test_progress_reader_reports_bytes() {
        let data = b"Hello, World!";
        let reader = Cursor::new(data);
        let mut progress = TestProgress::default();
        let mut tracking_reader = ProgressReader::new(reader, &mut progress);

        let mut buffer = vec![0u8; 5];
        let bytes_read = tracking_reader.read(&mut buffer).unwrap();

        drop(tracking_reader);

        assert_eq!(bytes_read, 5);
        assert_eq!(progress.bytes_written, 5);
        assert_eq!(&buffer[..bytes_read], b"Hello");
    }

    #[test]
    fn test_progress_reader_batching() {
        // Create data larger than batch threshold
        let data = vec![0u8; 2 * 1024 * 1024]; // 2 MB
        let reader = Cursor::new(data);
        let mut progress = TestProgress::default();

        // Use small batch threshold for testing
        let batch_threshold = 64 * 1024; // 64 KB
        let mut tracking_reader =
            ProgressReader::with_batch_threshold(reader, &mut progress, batch_threshold);

        let mut buffer = vec![0u8; 32 * 1024]; // 32 KB reads

        // Read multiple times
        for _ in 0..4 {
            tracking_reader.read(&mut buffer).unwrap();
        }

        // Drop reader to flush remaining bytes
        drop(tracking_reader);

        // Should have reported bytes (batched)
        assert!(progress.bytes_written > 0);
    }

    #[derive(Default)]
    struct CancelOnPoll;

    impl ProgressCallback for CancelOnPoll {
        fn on_entry_start(&mut self, _: &Path, _: crate::EntryPosition) {}

        fn on_bytes_written(&mut self, _: u64) {}

        fn on_entry_complete(&mut self, _: &Path) {}

        fn on_complete(&mut self) {}

        fn is_cancelled(&mut self) -> bool {
            true
        }
    }

    #[test]
    fn test_progress_reader_cancels_mid_entry_with_a_marker() {
        let mut progress = CancelOnPoll;
        let mut reader = ProgressReader::new(Cursor::new(vec![0u8; 100]), &mut progress)
            .with_cancel_interval(10);
        let mut buffer = [0u8; 4];

        let error = (0..10)
            .find_map(|_| reader.read(&mut buffer).err())
            .unwrap();
        assert!(CancelledMidEntry::find(&error).is_some());
    }

    #[test]
    fn test_progress_reader_handles_eof() {
        let data = b"";
        let reader = Cursor::new(data);
        let mut progress = TestProgress::default();
        let mut tracking_reader = ProgressReader::new(reader, &mut progress);

        let mut buffer = vec![0u8; 10];
        let bytes_read = tracking_reader.read(&mut buffer).unwrap();

        // Drop tracking reader before accessing progress
        drop(tracking_reader);

        assert_eq!(bytes_read, 0);
        assert_eq!(progress.bytes_written, 0);
    }

    #[test]
    fn test_progress_reader_manual_flush() {
        let data = b"test data";
        let reader = Cursor::new(data);
        let mut progress = TestProgress::default();

        let mut buffer = vec![0u8; 4];
        {
            let mut tracking_reader = ProgressReader::new(reader, &mut progress);

            tracking_reader.read(&mut buffer).unwrap();

            // Manually flush progress
            tracking_reader.flush_progress();

            // Reading more shouldn't add to previous bytes
            tracking_reader.read(&mut buffer).unwrap();
            tracking_reader.flush_progress();
        } // Drop tracking_reader here

        // Now we can access progress without borrowing issues
        assert_eq!(progress.bytes_written, 8); // 4 + 4 = 8
    }
}

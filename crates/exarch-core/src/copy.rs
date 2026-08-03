//! Optimized file copy implementation with reusable buffers.
//!
//! OPT-C002: Provides a stack-allocated copy buffer for efficient file
//! extraction without heap allocations on every copy operation. This reduces
//! memory pressure and improves throughput by 5-10% compared to
//! `std::io::copy`.
//!
//! # Security Guarantees
//!
//! - Preserves quota overflow detection via checked arithmetic
//! - No unsafe code
//! - Buffer size is constant and stack-allocated
//! - When called with a declared `expected_size` (GHSA-5j8q-wxg5-hj4r),
//!   enforces it as a hard streaming ceiling rather than trusting it: the copy
//!   aborts the instant more bytes have been decompressed than the archive
//!   declared, and a short read (fewer bytes than declared) is rejected once
//!   the source reaches EOF. This closes the gap where a forged
//!   `uncompressed_size` header let compression-ratio and quota checks (which
//!   only see the declared size) pass while the real decompressed stream was
//!   unbounded.

use std::io::Read;
use std::io::Write;
use std::io::{self};

use crate::ArchiveError;

/// Optimal buffer size for I/O operations (64KB).
///
/// This matches typical filesystem block sizes and provides good balance
/// between memory usage and I/O performance.
const COPY_BUFFER_SIZE: usize = 64 * 1024;

/// Stack-allocated reusable buffer used internally by [`copy_with_buffer`].
#[derive(Debug)]
pub struct CopyBuffer {
    // Stack allocation is intentional for performance (avoids heap overhead)
    #[allow(clippy::large_stack_arrays)]
    buf: [u8; COPY_BUFFER_SIZE],
}

impl CopyBuffer {
    /// Creates a new copy buffer.
    ///
    /// The buffer is allocated on the stack and zero-initialized.
    #[inline]
    #[must_use]
    #[allow(clippy::large_stack_arrays)]
    pub fn new() -> Self {
        Self {
            buf: [0u8; COPY_BUFFER_SIZE],
        }
    }

    /// Returns the buffer size in bytes.
    #[inline]
    #[must_use]
    #[allow(dead_code, clippy::unused_self)]
    pub fn size(&self) -> usize {
        COPY_BUFFER_SIZE
    }
}

impl Default for CopyBuffer {
    fn default() -> Self {
        Self::new()
    }
}

/// Copies data from reader to writer using the provided reusable buffer.
///
/// This is an optimized version of `std::io::copy` that:
/// - Uses a caller-provided buffer (avoiding heap allocation)
/// - Uses checked arithmetic to detect quota overflows
/// - Enforces `expected_size`, if given, as a hard ceiling on the stream rather
///   than trusting it as pre-validated metadata
/// - Returns the total number of bytes copied
///
/// # Security - Streaming Size Ceiling (GHSA-5j8q-wxg5-hj4r)
///
/// `expected_size` is the declared uncompressed size a caller already used
/// to pass compression-ratio and quota checks (both of which only see
/// archive-supplied metadata, never actual decompressed bytes). Trusting
/// that declared size for those checks but not for the copy itself let a
/// forged small `uncompressed_size` sail through validation while the
/// decompressing `reader` produced an unbounded number of real bytes on
/// disk. When `expected_size` is `Some`, this function closes that gap in
/// two ways:
///
/// - **Streaming ceiling**: `total` is checked against `expected_size` after
///   every buffer-sized read, so the copy aborts with
///   [`ArchiveError::SecurityViolation`] the moment more bytes have been
///   decompressed than declared, not after the fact.
/// - **Post-copy exact match**: once the reader reaches EOF, `total` must equal
///   `expected_size` exactly. A legitimate encoder never lies about this; any
///   mismatch (necessarily `total < expected_size`, since a larger `total`
///   already aborted above) is rejected the same way, with
///   [`ArchiveError::SecurityViolation`].
///
/// Both directions use `SecurityViolation` rather than
/// [`ArchiveError::QuotaExceeded`]: `expected_size` here is the archive's own
/// (possibly forged) declared size, not the configured
/// `max_file_size`/`max_total_size` limit, so a `QuotaExceeded`-shaped error
/// would surface a "raise the configured limit" remedy hint that makes no sense
/// for a metadata mismatch the caller cannot fix by reconfiguring anything.
///
/// Callers that do not yet know a size (`expected_size: None`) get no
/// additional enforcement beyond the pre-existing overflow guard.
///
/// # Errors
///
/// Returns an error if:
/// - Reading from the source fails
/// - Writing to the destination fails
/// - Total bytes written would overflow u64 (quota protection)
/// - `expected_size` is `Some` and the actual byte count exceeds or falls short
///   of it
#[inline]
pub fn copy_with_buffer<R: Read + ?Sized, W: Write + ?Sized>(
    reader: &mut R,
    writer: &mut W,
    buffer: &mut CopyBuffer,
    expected_size: Option<u64>,
) -> Result<u64, ArchiveError> {
    let mut total: u64 = 0;

    loop {
        let bytes_read = match reader.read(&mut buffer.buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(ArchiveError::Io(e)),
        };

        // SECURITY: Detect overflow to prevent quota bypass
        total = total
            .checked_add(bytes_read as u64)
            .ok_or(ArchiveError::QuotaExceeded {
                resource: crate::QuotaResource::IntegerOverflow,
            })?;

        // SECURITY: Enforce the declared size as a hard streaming ceiling
        // (GHSA-5j8q-wxg5-hj4r) instead of only checking it once at the end.
        // Checked before the write, so the chunk that would push `total` over
        // the ceiling is never written at all — not "at most one buffer's
        // worth of excess on disk", but zero.
        //
        // Uses SecurityViolation, not QuotaExceeded: `expected` is the
        // archive's own declared size, not `config.max_file_size`, so a
        // QuotaExceeded-shaped error would carry the CLI's "raise
        // --max-file-size" hint — actively wrong advice for a forged-metadata
        // mismatch the caller cannot fix by reconfiguring anything.
        if let Some(expected) = expected_size
            && total > expected
        {
            return Err(ArchiveError::SecurityViolation {
                reason: format!(
                    "decompressed size exceeded the declared uncompressed size of \
                     {expected} bytes"
                ),
            });
        }

        writer
            .write_all(&buffer.buf[..bytes_read])
            .map_err(ArchiveError::Io)?;
    }

    // SECURITY: A short stream (fewer bytes than declared) is just as much a
    // forged-metadata signal as an overlong one; the streaming ceiling above
    // only catches the "too many bytes" direction.
    if let Some(expected) = expected_size
        && total != expected
    {
        return Err(ArchiveError::SecurityViolation {
            reason: format!(
                "decompressed size ({total} bytes) does not match the declared \
                 uncompressed size ({expected} bytes)"
            ),
        });
    }

    Ok(total)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::io::Cursor;

    #[test]
    fn test_copy_buffer_new() {
        let buffer = CopyBuffer::new();
        assert_eq!(buffer.size(), 64 * 1024);
    }

    #[test]
    fn test_copy_buffer_default() {
        let buffer = CopyBuffer::default();
        assert_eq!(buffer.size(), 64 * 1024);
    }

    #[test]
    fn test_copy_empty_source() {
        let mut buffer = CopyBuffer::new();
        let mut input = Cursor::new(Vec::<u8>::new());
        let mut output = Vec::new();

        let result = copy_with_buffer(&mut input, &mut output, &mut buffer, None);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 0);
        assert_eq!(output.len(), 0);
    }

    #[test]
    fn test_copy_small_data() {
        let mut buffer = CopyBuffer::new();
        let input_data = b"Hello, World!";
        let mut input = Cursor::new(input_data);
        let mut output = Vec::new();

        let result = copy_with_buffer(&mut input, &mut output, &mut buffer, None);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), input_data.len() as u64);
        assert_eq!(output, input_data);
    }

    #[test]
    fn test_copy_large_data() {
        let mut buffer = CopyBuffer::new();
        // Create 1MB of data
        let input_data = vec![0x42u8; 1024 * 1024];
        let mut input = Cursor::new(&input_data);
        let mut output = Vec::new();

        let result = copy_with_buffer(&mut input, &mut output, &mut buffer, None);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), input_data.len() as u64);
        assert_eq!(output, input_data);
    }

    #[test]
    fn test_copy_exact_buffer_size() {
        let mut buffer = CopyBuffer::new();
        let input_data = vec![0xAAu8; COPY_BUFFER_SIZE];
        let mut input = Cursor::new(&input_data);
        let mut output = Vec::new();

        let result = copy_with_buffer(&mut input, &mut output, &mut buffer, None);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), COPY_BUFFER_SIZE as u64);
        assert_eq!(output, input_data);
    }

    #[test]
    fn test_copy_multiple_chunks() {
        let mut buffer = CopyBuffer::new();
        // Create data larger than buffer size
        let input_data = vec![0x55u8; COPY_BUFFER_SIZE * 3 + 1000];
        let mut input = Cursor::new(&input_data);
        let mut output = Vec::new();

        let result = copy_with_buffer(&mut input, &mut output, &mut buffer, None);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), input_data.len() as u64);
        assert_eq!(output, input_data);
    }

    #[test]
    fn test_copy_reusable_buffer() {
        let mut buffer = CopyBuffer::new();

        // First copy
        let data1 = b"First copy";
        let mut input1 = Cursor::new(data1);
        let mut output1 = Vec::new();
        let result1 = copy_with_buffer(&mut input1, &mut output1, &mut buffer, None);
        assert!(result1.is_ok());
        assert_eq!(output1, data1);

        // Second copy with same buffer
        let data2 = b"Second copy with different data";
        let mut input2 = Cursor::new(data2);
        let mut output2 = Vec::new();
        let result2 = copy_with_buffer(&mut input2, &mut output2, &mut buffer, None);
        assert!(result2.is_ok());
        assert_eq!(output2, data2);
    }

    #[test]
    fn test_copy_byte_for_byte_correctness() {
        let mut buffer = CopyBuffer::new();
        // Test with diverse byte patterns
        let mut input_data = Vec::new();
        for i in 0..=255u8 {
            input_data.extend_from_slice(&[i; 256]);
        }

        let mut input = Cursor::new(&input_data);
        let mut output = Vec::new();

        let result = copy_with_buffer(&mut input, &mut output, &mut buffer, None);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), input_data.len() as u64);
        assert_eq!(output, input_data);
    }

    // Edge case: Test interrupted reads handling
    #[test]
    fn test_copy_with_interrupted_reads() {
        use std::io::Error;
        use std::io::ErrorKind;

        // Mock reader that simulates interrupted reads
        struct InterruptedReader {
            data: Vec<u8>,
            position: usize,
            interrupt_count: usize,
        }

        impl Read for InterruptedReader {
            fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
                if self.interrupt_count.is_multiple_of(3) && self.position < self.data.len() {
                    self.interrupt_count += 1;
                    return Err(Error::new(ErrorKind::Interrupted, "interrupted"));
                }

                self.interrupt_count += 1;

                if self.position >= self.data.len() {
                    return Ok(0); // EOF
                }

                let remaining = self.data.len() - self.position;
                let to_read = remaining.min(buf.len());
                buf[..to_read].copy_from_slice(&self.data[self.position..self.position + to_read]);
                self.position += to_read;
                Ok(to_read)
            }
        }

        let test_data = vec![0x42u8; 1000];
        let mut reader = InterruptedReader {
            data: test_data.clone(),
            position: 0,
            interrupt_count: 0,
        };

        let mut buffer = CopyBuffer::new();
        let mut output = Vec::new();

        let result = copy_with_buffer(&mut reader, &mut output, &mut buffer, None);
        assert!(result.is_ok(), "copy should handle interrupted reads");
        assert_eq!(
            output, test_data,
            "data should be copied correctly despite interruptions"
        );
    }

    // Edge case: Test write failure propagation
    #[test]
    fn test_copy_with_write_failure() {
        use std::io::Error;
        use std::io::ErrorKind;

        // Mock writer that fails after a certain number of bytes
        struct FailingWriter {
            written: usize,
            fail_after: usize,
        }

        impl Write for FailingWriter {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                if self.written >= self.fail_after {
                    return Err(Error::other("write failed"));
                }
                let to_write = (self.fail_after - self.written).min(buf.len());
                self.written += to_write;
                Ok(to_write)
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let test_data = vec![0x42u8; 1000];
        let mut input = Cursor::new(test_data);
        let mut writer = FailingWriter {
            written: 0,
            fail_after: 500,
        };

        let mut buffer = CopyBuffer::new();
        let result = copy_with_buffer(&mut input, &mut writer, &mut buffer, None);

        assert!(result.is_err(), "copy should propagate write errors");
        match result {
            Err(ArchiveError::Io(e)) => {
                assert_eq!(e.kind(), ErrorKind::Other);
            }
            _ => panic!("expected IO error"),
        }
    }

    // Regression test for GHSA-5j8q-wxg5-hj4r: a forged small
    // `expected_size` must not let the real decompressed stream grow
    // unbounded. Reproduces the PoC shape (declared size far smaller than
    // actual content) directly against `copy_with_buffer`, independent of
    // any specific archive format's decompressor.
    #[test]
    fn test_copy_forged_expected_size_aborts_streaming() {
        let mut buffer = CopyBuffer::new();
        // Declares 50 bytes but the source actually produces ~1MB, mirroring
        // a ZIP entry with a forged uncompressed_size header.
        let real_data = vec![0x42u8; 1024 * 1024];
        let mut input = Cursor::new(&real_data);
        let mut output = Vec::new();

        let result = copy_with_buffer(&mut input, &mut output, &mut buffer, Some(50));

        assert!(
            result.is_err(),
            "streaming past the declared size must abort, got: {result:?}"
        );
        match result {
            Err(ArchiveError::SecurityViolation { reason }) => {
                assert!(
                    reason.contains("50 bytes"),
                    "error must name the declared ceiling (50), got: {reason:?}"
                );
            }
            other => {
                panic!("expected SecurityViolation naming the 50-byte ceiling, got: {other:?}")
            }
        }
        // The excess must never fully land in the destination.
        assert!(
            output.len() < real_data.len(),
            "aborted copy must not have written the full oversized payload"
        );
    }

    /// A stream that ends short of its declared size (undersized) is just as
    /// much a forged-metadata signal as an oversized one and must be
    /// rejected once EOF is reached, even though it never trips the
    /// streaming ceiling.
    #[test]
    fn test_copy_undersized_stream_rejected_after_eof() {
        let mut buffer = CopyBuffer::new();
        let data = b"short";
        let mut input = Cursor::new(data);
        let mut output = Vec::new();

        let result = copy_with_buffer(&mut input, &mut output, &mut buffer, Some(1000));

        assert!(
            result.is_err(),
            "actual size short of declared size must be rejected, got: {result:?}"
        );
        assert!(matches!(
            result,
            Err(ArchiveError::SecurityViolation { .. })
        ));
    }

    /// A stream matching its declared size exactly must succeed, exercising
    /// the boundary between the streaming ceiling and the post-copy check.
    #[test]
    fn test_copy_exact_expected_size_succeeds() {
        let mut buffer = CopyBuffer::new();
        let data = vec![0x99u8; 4096];
        let mut input = Cursor::new(&data);
        let mut output = Vec::new();

        let result = copy_with_buffer(&mut input, &mut output, &mut buffer, Some(4096));

        assert_eq!(result.unwrap(), 4096);
        assert_eq!(output, data);
    }

    /// One byte over the declared size must abort even though the excess is
    /// well within a single buffer read, pinning the "checked every
    /// iteration, not just at the end" requirement at the smallest possible
    /// margin.
    #[test]
    fn test_copy_one_byte_over_expected_size_aborts() {
        let mut buffer = CopyBuffer::new();
        let data = vec![0x77u8; 101];
        let mut input = Cursor::new(&data);
        let mut output = Vec::new();

        let result = copy_with_buffer(&mut input, &mut output, &mut buffer, Some(100));

        match result {
            Err(ArchiveError::SecurityViolation { reason }) => {
                assert!(
                    reason.contains("100 bytes"),
                    "error must name the declared ceiling (100), got: {reason:?}"
                );
            }
            other => {
                panic!("expected SecurityViolation naming the 100-byte ceiling, got: {other:?}")
            }
        }
    }

    proptest! {
        #[test]
        fn prop_copy_preserves_data(
            data in prop::collection::vec(any::<u8>(), 0..100_000)
        ) {
            let mut buffer = CopyBuffer::new();
            let mut input = Cursor::new(&data);
            let mut output = Vec::new();
            let result = copy_with_buffer(&mut input, &mut output, &mut buffer, None);
            prop_assert!(result.is_ok(), "copy should succeed");
            prop_assert_eq!(result.unwrap(), data.len() as u64, "should report correct size");
            prop_assert_eq!(output, data, "output must match input exactly");
        }

        #[test]
        fn prop_copy_handles_various_sizes(
            size in 0usize..500_000
        ) {
            let mut buffer = CopyBuffer::new();
            let data = vec![0x42u8; size];
            let mut input = Cursor::new(&data);
            let mut output = Vec::new();
            let result = copy_with_buffer(&mut input, &mut output, &mut buffer, None);
            prop_assert!(result.is_ok(), "copy should succeed for size {}", size);
            prop_assert_eq!(output.len(), size, "output size must match input");
            prop_assert!(output.iter().all(|&b| b == 0x42), "all bytes must be preserved");
        }

        #[test]
        fn prop_copy_buffer_reusable(
            data1 in prop::collection::vec(any::<u8>(), 0..10_000),
            data2 in prop::collection::vec(any::<u8>(), 0..10_000)
        ) {
            let mut buffer = CopyBuffer::new();
            let mut input1 = Cursor::new(&data1);
            let mut output1 = Vec::new();
            let result1 = copy_with_buffer(&mut input1, &mut output1, &mut buffer, None);
            prop_assert!(result1.is_ok());
            prop_assert_eq!(output1, data1);
            let mut input2 = Cursor::new(&data2);
            let mut output2 = Vec::new();
            let result2 = copy_with_buffer(&mut input2, &mut output2, &mut buffer, None);
            prop_assert!(result2.is_ok());
            prop_assert_eq!(output2, data2);
        }
    }
}

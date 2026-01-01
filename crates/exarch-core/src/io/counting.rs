//! Counting writer for tracking bytes written.
//!
//! This module provides a `CountingWriter` that wraps any `Write`
//! implementation and tracks the total number of bytes written.

use std::io::Write;

/// Wrapper writer that tracks total bytes written.
///
/// This writer wraps any `Write` implementation and maintains a counter
/// of the total bytes successfully written. This is useful for:
///
/// - Tracking compressed archive size for reports
/// - Monitoring write progress
/// - Validating expected output sizes
///
/// # Implementation Notes
///
/// The counter only increments on successful writes. If a write operation
/// fails partway through, only the successfully written bytes are counted.
///
/// # Examples
///
/// ```
/// use exarch_core::io::CountingWriter;
/// use std::io::Write;
///
/// let mut buffer = Vec::new();
/// let mut writer = CountingWriter::new(&mut buffer);
///
/// writer.write_all(b"Hello, ")?;
/// writer.write_all(b"World!")?;
/// writer.flush()?;
///
/// assert_eq!(writer.total_bytes(), 13);
/// assert_eq!(buffer, b"Hello, World!");
/// # Ok::<(), std::io::Error>(())
/// ```
pub struct CountingWriter<W> {
    /// Inner writer being wrapped
    inner: W,
    /// Total bytes successfully written
    bytes_written: u64,
}

impl<W> CountingWriter<W> {
    /// Creates a new counting writer.
    ///
    /// # Parameters
    ///
    /// - `inner`: The writer to wrap
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::io::CountingWriter;
    /// use std::io::Write;
    ///
    /// let buffer: Vec<u8> = Vec::new();
    /// let writer = CountingWriter::new(buffer);
    /// ```
    #[must_use]
    pub fn new(inner: W) -> Self {
        Self {
            inner,
            bytes_written: 0,
        }
    }

    /// Returns the total number of bytes successfully written.
    ///
    /// This count includes all bytes from successful write operations,
    /// including those from `write`, `write_all`, and `write_fmt`.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::io::CountingWriter;
    /// use std::io::Write;
    ///
    /// let mut buffer = Vec::new();
    /// let mut writer = CountingWriter::new(&mut buffer);
    ///
    /// writer.write_all(b"test")?;
    /// assert_eq!(writer.total_bytes(), 4);
    ///
    /// writer.write_all(b"data")?;
    /// assert_eq!(writer.total_bytes(), 8);
    /// # Ok::<(), std::io::Error>(())
    /// ```
    #[must_use]
    pub fn total_bytes(&self) -> u64 {
        self.bytes_written
    }

    /// Consumes the counting writer and returns the inner writer.
    ///
    /// This is useful when you need to retrieve the underlying writer
    /// after all writing is complete.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::io::CountingWriter;
    /// use std::io::Write;
    ///
    /// let buffer = Vec::new();
    /// let mut writer = CountingWriter::new(buffer);
    ///
    /// writer.write_all(b"test")?;
    ///
    /// let buffer = writer.into_inner();
    /// assert_eq!(buffer, b"test");
    /// # Ok::<(), std::io::Error>(())
    /// ```
    #[must_use]
    pub fn into_inner(self) -> W {
        self.inner
    }

    /// Returns a reference to the inner writer.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::io::CountingWriter;
    ///
    /// let buffer = Vec::new();
    /// let writer = CountingWriter::new(buffer);
    ///
    /// let inner_ref: &Vec<u8> = writer.get_ref();
    /// ```
    #[must_use]
    pub fn get_ref(&self) -> &W {
        &self.inner
    }

    /// Returns a mutable reference to the inner writer.
    ///
    /// # Safety
    ///
    /// If you write to the inner writer directly (bypassing the
    /// `CountingWriter`), the byte count will not be updated.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::io::CountingWriter;
    ///
    /// let buffer = Vec::new();
    /// let mut writer = CountingWriter::new(buffer);
    ///
    /// let inner_mut: &mut Vec<u8> = writer.get_mut();
    /// ```
    pub fn get_mut(&mut self) -> &mut W {
        &mut self.inner
    }
}

impl<W: Write> Write for CountingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let bytes = self.inner.write(buf)?;
        self.bytes_written += bytes as u64;
        Ok(bytes)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }

    fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()> {
        self.inner.write_all(buf)?;
        self.bytes_written += buf.len() as u64;
        Ok(())
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_counting_writer_basic() {
        let mut buffer = Vec::new();
        let mut writer = CountingWriter::new(&mut buffer);

        writer.write_all(b"Hello").unwrap();
        assert_eq!(writer.total_bytes(), 5);

        writer.write_all(b", World!").unwrap();
        assert_eq!(writer.total_bytes(), 13);

        assert_eq!(buffer, b"Hello, World!");
    }

    #[test]
    fn test_counting_writer_write() {
        let mut buffer = Vec::new();
        let mut writer = CountingWriter::new(&mut buffer);

        let bytes_written = writer.write(b"test").unwrap();
        assert_eq!(bytes_written, 4);
        assert_eq!(writer.total_bytes(), 4);
    }

    #[test]
    fn test_counting_writer_write_fmt() {
        let mut buffer = Vec::new();
        let mut writer = CountingWriter::new(&mut buffer);

        write!(writer, "test {}", 42).unwrap();
        assert_eq!(writer.total_bytes(), 7);
        assert_eq!(buffer, b"test 42");
    }

    #[test]
    fn test_counting_writer_flush() {
        let mut buffer = Vec::new();
        let mut writer = CountingWriter::new(&mut buffer);

        writer.write_all(b"data").unwrap();
        writer.flush().unwrap();

        assert_eq!(writer.total_bytes(), 4);
    }

    #[test]
    fn test_counting_writer_into_inner() {
        let buffer = Vec::new();
        let mut writer = CountingWriter::new(buffer);

        writer.write_all(b"test").unwrap();
        assert_eq!(writer.total_bytes(), 4);

        let buffer = writer.into_inner();
        assert_eq!(buffer, b"test");
    }

    #[test]
    fn test_counting_writer_get_ref() {
        let buffer = Vec::new();
        let mut writer = CountingWriter::new(buffer);

        writer.write_all(b"test").unwrap();

        let inner_ref = writer.get_ref();
        assert_eq!(inner_ref, &b"test"[..]);
    }

    #[test]
    fn test_counting_writer_get_mut() {
        let buffer = Vec::new();
        let mut writer = CountingWriter::new(buffer);

        writer.write_all(b"test").unwrap();

        let inner_mut = writer.get_mut();
        inner_mut.push(b'!');

        // Note: Direct modification doesn't update counter
        assert_eq!(writer.total_bytes(), 4);
        assert_eq!(writer.get_ref(), &b"test!"[..]);
    }

    #[test]
    fn test_counting_writer_empty() {
        let buffer: Vec<u8> = Vec::new();
        let writer = CountingWriter::new(buffer);

        assert_eq!(writer.total_bytes(), 0);
    }

    #[test]
    fn test_counting_writer_multiple_writes() {
        let mut buffer = Vec::new();
        let mut writer = CountingWriter::new(&mut buffer);

        for i in 0..10 {
            write!(writer, "{i}").unwrap();
        }

        assert_eq!(writer.total_bytes(), 10);
        assert_eq!(buffer, b"0123456789");
    }

    #[test]
    fn test_counting_writer_with_cursor() {
        let buffer: Vec<u8> = vec![0u8; 100];
        let cursor = Cursor::new(buffer);
        let mut writer = CountingWriter::new(cursor);

        writer.write_all(b"test data").unwrap();
        assert_eq!(writer.total_bytes(), 9);
    }

    #[test]
    fn test_counting_writer_partial_write() {
        // Use a limited buffer that can only write partial data
        struct LimitedWriter {
            inner: Vec<u8>,
            max_write: usize,
        }

        impl Write for LimitedWriter {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                let to_write = buf.len().min(self.max_write);
                self.inner.extend_from_slice(&buf[..to_write]);
                Ok(to_write)
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        let limited = LimitedWriter {
            inner: Vec::new(),
            max_write: 3,
        };
        let mut writer = CountingWriter::new(limited);

        // Try to write 5 bytes but only 3 will be written
        let written = writer.write(b"hello").unwrap();
        assert_eq!(written, 3);
        assert_eq!(writer.total_bytes(), 3);

        // Verify only 3 bytes were written
        assert_eq!(writer.get_ref().inner, b"hel");
    }
}

//! Panic-free read helpers for decoders that hand a caller-sized buffer to an
//! untrusted `Read` implementation.
//!
//! A `Read::read` that reports more bytes than the buffer holds would make
//! `&buf[..n]` panic. These helpers turn that contract violation into an
//! `InvalidData` error instead.

use std::io::Read;
use std::io::{self};

/// An `InvalidData` error for a length or index that breaks an invariant.
pub(crate) fn invalid_data() -> io::Error {
    io::Error::from(io::ErrorKind::InvalidData)
}

/// Copies as many leading bytes of `src` as fit into `dst` and returns how
/// many.
///
/// # Errors
///
/// Returns `InvalidData` when a prefix of the computed length cannot be taken,
/// which the length computation rules out.
pub(crate) fn copy_prefix(dst: &mut [u8], src: &[u8]) -> io::Result<usize> {
    let n = dst.len().min(src.len());
    let (head, _) = dst.split_at_mut_checked(n).ok_or_else(invalid_data)?;
    let (from, _) = src.split_at_checked(n).ok_or_else(invalid_data)?;
    head.copy_from_slice(from);
    Ok(n)
}

/// Reads once into `buf` and returns the filled prefix.
///
/// # Errors
///
/// Returns the read error, or `InvalidData` when the reader claims to have
/// read more bytes than `buf` holds.
pub(crate) fn read_prefix<'b, R: Read + ?Sized>(
    reader: &mut R,
    buf: &'b mut [u8],
) -> io::Result<&'b mut [u8]> {
    let n = reader.read(buf)?;
    buf.get_mut(..n).ok_or_else(invalid_data)
}

/// Reads until `buf` is full or the reader is at its end, retrying
/// `Interrupted`, and returns the number of bytes read.
///
/// # Errors
///
/// Returns the first read error other than `Interrupted`, or `InvalidData`
/// when the reader claims to have read more bytes than `buf` has room for.
pub(crate) fn read_up_to<R: Read + ?Sized>(reader: &mut R, buf: &mut [u8]) -> io::Result<usize> {
    let mut filled = 0usize;
    loop {
        let Some(rest) = buf.get_mut(filled..).filter(|rest| !rest.is_empty()) else {
            return Ok(filled);
        };
        match read_prefix(reader, rest) {
            Ok([]) => return Ok(filled),
            Ok(read) => filled = filled.saturating_add(read.len()),
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    struct Overclaiming;

    impl Read for Overclaiming {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            Ok(buf.len() + 1)
        }
    }

    struct InterruptedOnce<'a>(bool, &'a [u8]);

    impl Read for InterruptedOnce<'_> {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if !self.0 {
                self.0 = true;
                return Err(io::ErrorKind::Interrupted.into());
            }
            self.1.read(buf)
        }
    }

    #[test]
    fn copy_prefix_copies_the_shorter_length() {
        let mut dst = [0u8; 3];
        assert_eq!(copy_prefix(&mut dst, b"abcdef").unwrap(), 3);
        assert_eq!(&dst, b"abc");
        let mut dst = [0u8; 4];
        assert_eq!(copy_prefix(&mut dst, b"ab").unwrap(), 2);
        assert_eq!(&dst, b"ab\0\0");
    }

    struct MustNotRead;

    impl Read for MustNotRead {
        fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
            panic!("read called");
        }
    }

    struct TwoBytesThenError(bool);

    impl Read for TwoBytesThenError {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.0 {
                return Err(io::Error::other("hard"));
            }
            self.0 = true;
            buf[..2].fill(7);
            Ok(2)
        }
    }

    struct ExactFill;

    impl Read for ExactFill {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            Ok(buf.len())
        }
    }

    #[test]
    fn copy_prefix_handles_empty_sides() {
        let mut empty: [u8; 0] = [];
        assert_eq!(copy_prefix(&mut empty, b"ab").unwrap(), 0);
        let mut dst = [9u8; 4];
        assert_eq!(copy_prefix(&mut dst, b"").unwrap(), 0);
        assert_eq!(dst, [9; 4]);
    }

    #[test]
    fn read_up_to_returns_zero_for_an_empty_buffer_without_reading() {
        assert_eq!(read_up_to(&mut MustNotRead, &mut []).unwrap(), 0);
    }

    #[test]
    fn read_up_to_propagates_a_hard_error_after_a_partial_fill() {
        let err = read_up_to(&mut TwoBytesThenError(false), &mut [0u8; 8]).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Other);
    }

    #[test]
    fn read_prefix_accepts_an_exact_fill() {
        let mut buf = [0u8; 4];
        assert_eq!(read_prefix(&mut ExactFill, &mut buf).unwrap().len(), 4);
    }

    #[test]
    fn read_prefix_returns_the_filled_part() {
        let mut buf = [0u8; 8];
        let mut src: &[u8] = b"abc";
        assert_eq!(read_prefix(&mut src, &mut buf).unwrap(), b"abc");
    }

    #[test]
    fn read_prefix_rejects_an_overlong_read() {
        let err = read_prefix(&mut Overclaiming, &mut [0u8; 4]).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }

    #[test]
    fn read_up_to_fills_across_interruption_and_stops_at_eof() {
        let mut buf = [0u8; 8];
        let mut src = InterruptedOnce(false, b"abcde");
        assert_eq!(read_up_to(&mut src, &mut buf).unwrap(), 5);
        assert_eq!(&buf[..5], b"abcde");
    }

    #[test]
    fn read_up_to_stops_when_the_buffer_is_full() {
        let mut buf = [0u8; 2];
        let mut src: &[u8] = b"abcde";
        assert_eq!(read_up_to(&mut src, &mut buf).unwrap(), 2);
    }

    #[test]
    fn read_up_to_rejects_an_overlong_read() {
        let err = read_up_to(&mut Overclaiming, &mut [0u8; 4]).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }
}

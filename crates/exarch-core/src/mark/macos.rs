//! The macOS mark: the `com.apple.quarantine` extended attribute, read and
//! written through open descriptors only.

use std::fs::File;
use std::io;
use std::os::fd::AsFd;

use rustix::fs::XattrFlags;
use rustix::io::Errno;

use super::quarantine::MAX_LEN;
use super::quarantine::Quarantine;

pub(super) type Mark = Quarantine;

pub(super) const SUPPORTED: bool = true;

const NAME: &str = "com.apple.quarantine";

/// Reads the quarantine value of the open archive `file`.
///
/// `Ok(None)` when the file has none or its filesystem has no attributes. A
/// value that exists but is longer than the bound or malformed still is a
/// mark, so it reads as the conservative one; only a real I/O error is an
/// error.
pub(super) fn read(file: &File) -> io::Result<Option<Mark>> {
    let mut buffer = [0_u8; MAX_LEN];
    match rustix::fs::fgetxattr(file, NAME, &mut buffer[..]) {
        Ok(len) => Ok(Some(Quarantine::of_value(
            buffer.get(..len).unwrap_or_default(),
        ))),
        Err(Errno::RANGE) => Ok(Some(Quarantine::fallback())),
        Err(Errno::NOATTR | Errno::NOTSUP) => Ok(None),
        Err(error) => Err(error.into()),
    }
}

/// Sets a fresh quarantine value on the file `file` is open on.
pub(super) fn write_file(mark: Mark, file: &File) -> io::Result<()> {
    write(mark, file)
}

/// Sets a fresh quarantine value on the directory `dir` is open on.
pub(super) fn write_dir(mark: Mark, dir: &impl AsFd) -> io::Result<()> {
    write(mark, dir)
}

fn write(mark: Mark, fd: &impl AsFd) -> io::Result<()> {
    Ok(rustix::fs::fsetxattr(
        fd,
        NAME,
        mark.render().as_bytes(),
        XattrFlags::empty(),
    )?)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::io::Write;

    fn set(file: &File, value: &[u8]) {
        rustix::fs::fsetxattr(file, NAME, value, XattrFlags::empty()).unwrap();
    }

    #[test]
    fn an_unmarked_file_reads_as_none() {
        let temp = tempfile::tempfile().unwrap();
        assert_eq!(read(&temp).unwrap(), None);
    }

    #[test]
    fn a_marked_file_round_trips_through_a_fresh_value() {
        let source = tempfile::tempfile().unwrap();
        set(
            &source,
            b"0083;5f3c8d11;Safari;3F2D5A10-1111-4222-8333-444455556666",
        );
        let mark = read(&source).unwrap().unwrap();

        let mut target = tempfile::tempfile().unwrap();
        target.write_all(b"x").unwrap();
        write_file(mark, &target).unwrap();
        assert_eq!(read(&target).unwrap(), Some(mark));
    }

    #[test]
    fn a_malformed_or_oversized_value_reads_as_the_conservative_mark() {
        for value in [&b"not a quarantine value"[..], &[b'0'; 1024]] {
            let source = tempfile::tempfile().unwrap();
            set(&source, value);
            let mark = read(&source).unwrap().unwrap();
            assert_eq!(mark.render().split(';').next(), Some("0001"));
        }
    }
}

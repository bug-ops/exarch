//! The bytes sevenz-rust2 reads to open an archive with an encrypted header,
//! held in memory so that the open runs no caller `Read`/`Seek` code.

use std::io;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;

/// One byte range of the archive, as far as the source delivered it.
#[derive(Debug)]
struct Part {
    start: u64,
    declared_end: u64,
    bytes: Vec<u8>,
}

/// A `Read + Seek` view of an archive that holds only the byte ranges the
/// open of an encrypted header reads: the signature header, the next-header
/// record and the packed header.
///
/// A read at a position inside a range but past what the source delivered ends
/// like the source would (a truncated archive); a read anywhere else short of
/// the archive's length is an error, so a layout that needs more than the
/// ranges fails instead of reading zeros.
#[derive(Debug)]
pub(super) struct PrefetchedHeader {
    length: u64,
    position: u64,
    parts: Vec<Part>,
}

impl PrefetchedHeader {
    /// An archive of `length` bytes with no range yet.
    pub(super) const fn new(length: u64) -> Self {
        Self {
            length,
            position: 0,
            parts: Vec::new(),
        }
    }

    /// Adds the range of `declared` bytes at `start`, of which the source
    /// delivered `bytes`.
    pub(super) fn with_part(mut self, start: u64, declared: u64, bytes: Vec<u8>) -> Self {
        self.parts.push(Part {
            start,
            declared_end: start.saturating_add(declared),
            bytes,
        });
        self
    }

    /// The `len` bytes held at `start`, or `None` when no range holds them
    /// all.
    pub(super) fn bytes_at(&self, start: u64, len: u64) -> Option<&[u8]> {
        let part = self.part_at(start)?;
        let from = usize::try_from(start.checked_sub(part.start)?).ok()?;
        let to = from.checked_add(usize::try_from(len).ok()?)?;
        part.bytes.get(from..to)
    }

    /// Overwrites the bytes held at `start` with `data`; `None` when no range
    /// holds all of them.
    pub(super) fn write_at(&mut self, start: u64, data: &[u8]) -> Option<()> {
        let index = self
            .parts
            .iter()
            .position(|part| (part.start..part.declared_end).contains(&start))?;
        let part = self.parts.get_mut(index)?;
        let from = usize::try_from(start.checked_sub(part.start)?).ok()?;
        let to = from.checked_add(data.len())?;
        part.bytes.get_mut(from..to)?.copy_from_slice(data);
        Some(())
    }

    fn part_at(&self, position: u64) -> Option<&Part> {
        self.parts
            .iter()
            .find(|part| (part.start..part.declared_end).contains(&position))
    }
}

impl Read for PrefetchedHeader {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let position = self.position;
        let Some(part) = self.part_at(position) else {
            return if position >= self.length {
                Ok(0)
            } else {
                Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "read outside the prefetched header bytes",
                ))
            };
        };
        let offset = usize::try_from(position.saturating_sub(part.start)).unwrap_or(usize::MAX);
        let available = part.bytes.get(offset..).unwrap_or_default();
        let count = available.len().min(buf.len());
        if let (Some(from), Some(to)) = (available.get(..count), buf.get_mut(..count)) {
            to.copy_from_slice(from);
        }
        self.position = position.saturating_add(count as u64);
        Ok(count)
    }
}

impl Seek for PrefetchedHeader {
    fn seek(&mut self, to: SeekFrom) -> io::Result<u64> {
        let target = match to {
            SeekFrom::Start(position) => Some(position),
            SeekFrom::End(delta) => self.length.checked_add_signed(delta),
            SeekFrom::Current(delta) => self.position.checked_add_signed(delta),
        }
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "seek before the start"))?;
        self.position = target;
        Ok(target)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn archive() -> PrefetchedHeader {
        PrefetchedHeader::new(100)
            .with_part(0, 4, vec![1, 2, 3, 4])
            .with_part(50, 10, vec![9, 9])
    }

    #[test]
    fn a_range_reads_back_and_seeks_from_the_start_end_and_current() {
        let mut view = archive();
        let mut buf = [0u8; 4];
        view.read_exact(&mut buf).unwrap();
        assert_eq!(buf, [1, 2, 3, 4]);
        assert_eq!(view.seek(SeekFrom::End(-50)).unwrap(), 50);
        assert_eq!(view.seek(SeekFrom::Current(1)).unwrap(), 51);
        view.seek(SeekFrom::Start(50)).unwrap();
        let mut two = [0u8; 2];
        view.read_exact(&mut two).unwrap();
        assert_eq!(two, [9, 9]);
        assert!(view.seek(SeekFrom::Current(-1000)).is_err());
    }

    #[test]
    fn bytes_are_read_and_overwritten_where_a_range_holds_them() {
        let mut view = archive();
        assert_eq!(view.bytes_at(1, 2), Some(&[2, 3][..]));
        assert_eq!(view.bytes_at(2, 3), None, "past the delivered bytes");
        assert_eq!(view.bytes_at(20, 1), None, "outside every range");
        assert_eq!(view.write_at(1, &[7, 8]), Some(()));
        assert_eq!(view.bytes_at(0, 4), Some(&[1, 7, 8, 4][..]));
        assert_eq!(view.write_at(3, &[0, 0]), None);
        assert_eq!(view.bytes_at(0, 4), Some(&[1, 7, 8, 4][..]));
        let mut buf = [0u8; 4];
        view.read_exact(&mut buf).unwrap();
        assert_eq!(buf, [1, 7, 8, 4]);
    }

    #[test]
    fn a_range_the_source_cut_short_ends_like_the_source() {
        let mut view = archive();
        view.seek(SeekFrom::Start(52)).unwrap();
        assert_eq!(view.read(&mut [0u8; 8]).unwrap(), 0);
    }

    #[test]
    fn a_read_outside_every_range_fails_until_the_archive_ends() {
        let mut view = archive();
        view.seek(SeekFrom::Start(20)).unwrap();
        let error = view.read(&mut [0u8; 1]).unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
        view.seek(SeekFrom::Start(100)).unwrap();
        assert_eq!(view.read(&mut [0u8; 1]).unwrap(), 0);
    }
}

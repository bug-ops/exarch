//! The Windows mark: the `Zone.Identifier` alternate data stream, opened
//! relative to the handle of the file it belongs to and never through a
//! `file:stream` path string.

use std::fs::File;
use std::io;

use super::zone::MAX_LEN;
use super::zone::Zone;
use crate::formats::pinned_dir::read_zone_stream;
use crate::formats::pinned_dir::write_zone_stream;

pub(super) type Mark = Zone;

pub(super) const SUPPORTED: bool = true;

/// Reads the zone of the open archive `file`.
///
/// `Ok(None)` when the file has no stream. A stream that exists is a mark
/// even when it cannot be read as one, and then reads as the internet zone;
/// only an I/O error, or a volume that cannot be asked, is an error.
pub(super) fn read(file: &File) -> io::Result<Option<Mark>> {
    Ok(read_zone_stream(file, MAX_LEN)?.map(|content| Zone::of_stream(&content)))
}

/// Creates the stream on the file `file` is open on.
pub(super) fn write_file(mark: Mark, file: &File) -> io::Result<()> {
    write_zone_stream(file, mark.render().as_bytes())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn an_unmarked_file_reads_as_none() {
        let file = tempfile::tempfile().unwrap();
        assert_eq!(read(&file).unwrap(), None);
    }

    #[test]
    fn a_mark_written_through_a_handle_reads_back() {
        let file = tempfile::tempfile().unwrap();
        write_zone_stream(&file, b"[ZoneTransfer]\r\nZoneId=3\r\n").unwrap();
        let mark = read(&file).unwrap().unwrap();

        let target = tempfile::tempfile().unwrap();
        write_file(mark, &target).unwrap();
        assert_eq!(read(&target).unwrap(), Some(mark));
    }
}

//! Parser for the records `NtQueryDirectoryFile` returns for
//! `FileFullDirectoryInformation`.
//!
//! The buffer comes from the kernel but a filesystem driver wrote it, so it is
//! parsed as untrusted: every offset and length is checked, and a record that
//! does not parse refuses the whole buffer. The function is pure and
//! platform-neutral so its tests run on every host; `nt` pins the layout
//! constants to the real struct with a compile-time assertion.

/// Offset of `NextEntryOffset` in a record.
pub(super) const NEXT_ENTRY_OFFSET: usize = 0;
/// Offset of `FileNameLength` in a record.
pub(super) const FILE_NAME_LENGTH: usize = 60;
/// Offset of the first name unit in a record, which is also the header size.
pub(super) const FILE_NAME: usize = 68;

/// Records start on 8-byte boundaries.
const RECORD_ALIGN: usize = 8;

/// Why a buffer of directory records was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Refusal {
    /// No record, or a header or name that runs past the buffer.
    Truncated,
    /// A link to the next record that is misaligned, overlaps the current
    /// record or leaves the buffer.
    BadOffset,
    /// A name length that is not a whole number of UTF-16 units, or is zero.
    BadNameLength,
    /// An offset sum that overflows.
    Overflow,
}

fn read_u32(buffer: &[u8], at: usize) -> Result<u32, Refusal> {
    let end = after(at, size_of::<u32>())?;
    let bytes = buffer.get(at..end).ok_or(Refusal::Truncated)?;
    let mut raw = [0_u8; size_of::<u32>()];
    raw.copy_from_slice(bytes);
    Ok(u32::from_le_bytes(raw))
}

fn after(offset: usize, delta: usize) -> Result<usize, Refusal> {
    offset.checked_add(delta).ok_or(Refusal::Overflow)
}

fn to_usize(value: u32) -> Result<usize, Refusal> {
    usize::try_from(value).map_err(|_| Refusal::Overflow)
}

/// The names in `buffer`, as UTF-16 code units, without `.` and `..`.
///
/// # Errors
///
/// A [`Refusal`] for any record that does not parse; nothing partial is
/// returned.
pub(super) fn names(buffer: &[u8]) -> Result<Vec<Vec<u16>>, Refusal> {
    const DOT: [u16; 1] = [0x2e];
    const DOT_DOT: [u16; 2] = [0x2e, 0x2e];

    let mut names = Vec::new();
    let mut offset = 0_usize;
    loop {
        let name_bytes = to_usize(read_u32(buffer, after(offset, FILE_NAME_LENGTH)?)?)?;
        if name_bytes == 0 || !name_bytes.is_multiple_of(size_of::<u16>()) {
            return Err(Refusal::BadNameLength);
        }
        let record_len = after(FILE_NAME, name_bytes)?;
        let record_end = after(offset, record_len)?;
        let raw = buffer
            .get(after(offset, FILE_NAME)?..record_end)
            .ok_or(Refusal::Truncated)?;
        let units: Vec<u16> = raw
            .as_chunks::<{ size_of::<u16>() }>()
            .0
            .iter()
            .map(|&pair| u16::from_le_bytes(pair))
            .collect();
        if units != DOT && units != DOT_DOT {
            names.push(units);
        }
        let next = to_usize(read_u32(buffer, after(offset, NEXT_ENTRY_OFFSET)?)?)?;
        if next == 0 {
            return Ok(names);
        }
        if next < record_len || !next.is_multiple_of(RECORD_ALIGN) {
            return Err(Refusal::BadOffset);
        }
        offset = after(offset, next)?;
        if offset >= buffer.len() {
            return Err(Refusal::BadOffset);
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn record(name: &str, next: u32) -> Vec<u8> {
        let units: Vec<u16> = name.encode_utf16().collect();
        let mut bytes = vec![0_u8; FILE_NAME + units.len() * 2];
        bytes[NEXT_ENTRY_OFFSET..NEXT_ENTRY_OFFSET + 4].copy_from_slice(&next.to_le_bytes());
        let length = u32::try_from(units.len() * 2).unwrap();
        bytes[FILE_NAME_LENGTH..FILE_NAME_LENGTH + 4].copy_from_slice(&length.to_le_bytes());
        for (index, unit) in units.iter().enumerate() {
            let at = FILE_NAME + index * 2;
            bytes[at..at + 2].copy_from_slice(&unit.to_le_bytes());
        }
        bytes
    }

    fn padded(mut bytes: Vec<u8>) -> Vec<u8> {
        bytes.resize(bytes.len().next_multiple_of(RECORD_ALIGN), 0);
        bytes
    }

    fn chain(names: &[&str]) -> Vec<u8> {
        let mut records: Vec<Vec<u8>> = names.iter().map(|name| padded(record(name, 0))).collect();
        let last = records.len() - 1;
        for (index, bytes) in records.iter_mut().enumerate() {
            if index != last {
                let next = u32::try_from(bytes.len()).unwrap();
                bytes[..4].copy_from_slice(&next.to_le_bytes());
            }
        }
        records.concat()
    }

    fn units(name: &str) -> Vec<u16> {
        name.encode_utf16().collect()
    }

    #[test]
    fn a_chain_of_records_gives_its_names_without_the_dot_entries() {
        let buffer = chain(&[".", "..", "a.txt", "dir"]);

        assert_eq!(names(&buffer), Ok(vec![units("a.txt"), units("dir")]));
    }

    #[test]
    fn a_name_that_merely_starts_with_dots_is_kept() {
        let buffer = chain(&["...", ".hidden"]);

        assert_eq!(names(&buffer), Ok(vec![units("..."), units(".hidden")]));
    }

    #[test]
    fn an_empty_buffer_is_refused() {
        assert_eq!(names(&[]), Err(Refusal::Truncated));
    }

    #[test]
    fn a_truncated_header_is_refused() {
        let buffer = chain(&["a"]);

        assert_eq!(names(&buffer[..FILE_NAME - 1]), Err(Refusal::Truncated));
    }

    #[test]
    fn a_name_running_past_the_buffer_is_refused() {
        let buffer = record("abcd", 0);

        assert_eq!(names(&buffer[..buffer.len() - 2]), Err(Refusal::Truncated));
    }

    #[test]
    fn an_odd_name_length_is_refused() {
        let mut buffer = record("ab", 0);
        buffer[FILE_NAME_LENGTH..FILE_NAME_LENGTH + 4].copy_from_slice(&3_u32.to_le_bytes());

        assert_eq!(names(&buffer), Err(Refusal::BadNameLength));
    }

    #[test]
    fn an_empty_name_is_refused() {
        let buffer = record("", 0);

        assert_eq!(names(&buffer), Err(Refusal::BadNameLength));
    }

    #[test]
    fn a_name_length_that_overflows_the_offsets_is_refused() {
        let mut buffer = record("a", 0);
        buffer[FILE_NAME_LENGTH..FILE_NAME_LENGTH + 4]
            .copy_from_slice(&u32::MAX.wrapping_sub(1).to_le_bytes());

        assert!(matches!(
            names(&buffer),
            Err(Refusal::Truncated | Refusal::Overflow)
        ));
    }

    #[test]
    fn a_link_below_the_header_size_is_refused() {
        let mut buffer = chain(&["a", "b"]);
        buffer[..4].copy_from_slice(&8_u32.to_le_bytes());

        assert_eq!(names(&buffer), Err(Refusal::BadOffset));
    }

    #[test]
    fn a_link_that_overlaps_its_own_record_is_refused() {
        let mut buffer = chain(&["abcdef", "b"]);
        buffer[..4].copy_from_slice(&72_u32.to_le_bytes());

        assert_eq!(names(&buffer), Err(Refusal::BadOffset));
    }

    #[test]
    fn a_misaligned_link_is_refused() {
        let mut buffer = chain(&["abcdef", "b"]);
        let misaligned = u32::try_from(FILE_NAME + 12 + 1).unwrap();
        buffer[..4].copy_from_slice(&misaligned.to_le_bytes());

        assert_eq!(names(&buffer), Err(Refusal::BadOffset));
    }

    #[test]
    fn a_link_past_the_buffer_is_refused() {
        let mut buffer = chain(&["a", "b"]);
        buffer[..4].copy_from_slice(&4096_u32.to_le_bytes());

        assert_eq!(names(&buffer), Err(Refusal::BadOffset));
    }
}

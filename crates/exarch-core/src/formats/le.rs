//! Bounds-checked little-endian field readers for untrusted binary headers.
//!
//! The ZIP structure walker, the Windows reparse-buffer parser and the 7z
//! signature-header probe all read fixed-width fields at attacker-chosen or
//! fixed offsets. Keeping one audited implementation here means no parser can
//! panic on an out-of-range offset or fall back to a made-up value.

/// Little-endian `u16` at `at`, or `None` when `bytes` is too short.
pub(crate) fn u16_at(bytes: &[u8], at: usize) -> Option<u16> {
    bytes
        .get(at..)?
        .first_chunk()
        .copied()
        .map(u16::from_le_bytes)
}

/// Little-endian `u32` at `at`, or `None` when `bytes` is too short.
pub(crate) fn u32_at(bytes: &[u8], at: usize) -> Option<u32> {
    bytes
        .get(at..)?
        .first_chunk()
        .copied()
        .map(u32::from_le_bytes)
}

/// Little-endian `u64` at `at`, or `None` when `bytes` is too short.
pub(crate) fn u64_at(bytes: &[u8], at: usize) -> Option<u64> {
    bytes
        .get(at..)?
        .first_chunk()
        .copied()
        .map(u64::from_le_bytes)
}

/// Little-endian `u16` at the constant offset `AT` of a fixed-size header; an
/// offset past the end does not compile.
#[expect(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "AT + width <= N is asserted at compile time"
)]
pub(crate) const fn le16<const AT: usize, const N: usize>(bytes: &[u8; N]) -> u16 {
    const { assert!(AT + 2 <= N) };
    u16::from_le_bytes([bytes[AT], bytes[AT + 1]])
}

/// Little-endian `u32` at the constant offset `AT` of a fixed-size header; an
/// offset past the end does not compile.
#[expect(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "AT + width <= N is asserted at compile time"
)]
pub(crate) const fn le32<const AT: usize, const N: usize>(bytes: &[u8; N]) -> u32 {
    const { assert!(AT + 4 <= N) };
    u32::from_le_bytes([bytes[AT], bytes[AT + 1], bytes[AT + 2], bytes[AT + 3]])
}

/// Little-endian `u64` at the constant offset `AT` of a fixed-size header; an
/// offset past the end does not compile.
#[expect(
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "AT + width <= N is asserted at compile time"
)]
pub(crate) const fn le64<const AT: usize, const N: usize>(bytes: &[u8; N]) -> u64 {
    const { assert!(AT + 8 <= N) };
    u64::from_le_bytes([
        bytes[AT],
        bytes[AT + 1],
        bytes[AT + 2],
        bytes[AT + 3],
        bytes[AT + 4],
        bytes[AT + 5],
        bytes[AT + 6],
        bytes[AT + 7],
    ])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slice_readers_read_little_endian() {
        let bytes = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09];
        assert_eq!(u16_at(&bytes, 1), Some(0x0302));
        assert_eq!(u32_at(&bytes, 1), Some(0x0504_0302));
        assert_eq!(u64_at(&bytes, 1), Some(0x0908_0706_0504_0302));
    }

    #[test]
    fn slice_readers_fail_past_the_end_without_panicking() {
        let bytes = [0u8; 4];
        assert_eq!(u16_at(&bytes, 3), None);
        assert_eq!(u32_at(&bytes, 1), None);
        assert_eq!(u64_at(&bytes, 0), None);
        assert_eq!(u16_at(&bytes, usize::MAX), None);
    }

    #[test]
    fn const_readers_read_little_endian() {
        let bytes = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09];
        assert_eq!(le16::<1, 9>(&bytes), 0x0302);
        assert_eq!(le32::<1, 9>(&bytes), 0x0504_0302);
        assert_eq!(le64::<1, 9>(&bytes), 0x0908_0706_0504_0302);
    }
}

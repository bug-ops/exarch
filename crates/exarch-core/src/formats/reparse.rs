//! Parsing of the `REPARSE_DATA_BUFFER` that `FSCTL_GET_REPARSE_POINT` returns.
//!
//! The buffer comes from the file system and is treated as untrusted: every
//! offset and length is bounds-checked against the buffer and against the
//! declared data length before it is used. Only the two name-surrogate tags
//! that stand for a directory link are understood: symbolic links and mount
//! points (junctions). The parser is plain safe Rust with no Windows
//! dependency, so its unit tests run on every host.

use std::io;

const SYMLINK_TAG: u32 = 0xA000_000C;
const MOUNT_POINT_TAG: u32 = 0xA000_0003;
const SYMLINK_FLAG_RELATIVE: u32 = 1;

const HEADER_LEN: usize = 8;
const SYMLINK_FIELDS_LEN: usize = 12;
const MOUNT_POINT_FIELDS_LEN: usize = 8;

const NT_PREFIX: [u16; 4] = [0x5C, 0x3F, 0x3F, 0x5C];
const VERBATIM_PREFIX: [u16; 4] = [0x5C, 0x5C, 0x3F, 0x5C];

/// The target a reparse point names, as UTF-16 code units.
///
/// Code units rather than a path so this module needs no Windows type; the
/// caller converts with `OsString::from_wide`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ReparseTarget {
    /// A symbolic link target to resolve against the directory holding the
    /// link.
    Relative(Vec<u16>),
    /// An absolute target, already rewritten from the NT form (`\??\C:\x`) to
    /// the verbatim Win32 form (`\\?\C:\x`) that a canonical destination uses.
    Absolute(Vec<u16>),
}

/// Why a reparse buffer was refused.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub(crate) enum ReparseError {
    /// The buffer ends before a header, a field or a name it declares.
    #[error("reparse buffer is truncated or declares a name outside itself")]
    Truncated,
    /// A name offset or length is not a whole number of UTF-16 code units.
    #[error("reparse name offset or length is odd")]
    OddLength,
    /// The reparse tag is not a symbolic link or a mount point.
    #[error("unsupported reparse tag {0:#010x}")]
    UnsupportedTag(u32),
    /// The substitute name is empty.
    #[error("reparse substitute name is empty")]
    Empty,
    /// An absolute substitute name does not start with the NT prefix `\??\`.
    #[error("absolute reparse target is not an NT path")]
    NotNtPath,
}

impl From<ReparseError> for io::Error {
    fn from(error: ReparseError) -> Self {
        Self::new(io::ErrorKind::InvalidData, error)
    }
}

fn array_at<const N: usize>(bytes: &[u8], at: usize) -> Result<[u8; N], ReparseError> {
    let end = at.checked_add(N).ok_or(ReparseError::Truncated)?;
    bytes
        .get(at..end)
        .and_then(|raw| raw.try_into().ok())
        .ok_or(ReparseError::Truncated)
}

fn u16_at(bytes: &[u8], at: usize) -> Result<u16, ReparseError> {
    array_at(bytes, at).map(u16::from_le_bytes)
}

fn u32_at(bytes: &[u8], at: usize) -> Result<u32, ReparseError> {
    array_at(bytes, at).map(u32::from_le_bytes)
}

fn units(bytes: &[u8]) -> Vec<u16> {
    bytes
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u16::from_le_bytes(*pair))
        .collect()
}

/// Parses `buf`, a `REPARSE_DATA_BUFFER`, into the target its substitute name
/// gives.
///
/// The print name is display-only and is never used. Junctions are always
/// absolute. A symbolic link is relative when `SYMLINK_FLAG_RELATIVE` is set.
///
/// # Errors
///
/// Returns a [`ReparseError`] for a buffer that is truncated, declares a name
/// outside itself or with an odd offset or length, carries another tag, names
/// nothing, or holds an absolute target that is not an NT path.
pub(crate) fn parse(buf: &[u8]) -> Result<ReparseTarget, ReparseError> {
    let tag = u32_at(buf, 0)?;
    let data_len = usize::from(u16_at(buf, 4)?);
    let data = buf
        .get(HEADER_LEN..HEADER_LEN.saturating_add(data_len))
        .ok_or(ReparseError::Truncated)?;
    let (fields_len, relative) = match tag {
        SYMLINK_TAG => (
            SYMLINK_FIELDS_LEN,
            u32_at(data, 8)? & SYMLINK_FLAG_RELATIVE != 0,
        ),
        MOUNT_POINT_TAG => (MOUNT_POINT_FIELDS_LEN, false),
        other => return Err(ReparseError::UnsupportedTag(other)),
    };
    let offset = usize::from(u16_at(data, 0)?);
    let len = usize::from(u16_at(data, 2)?);
    if offset % 2 != 0 || len % 2 != 0 {
        return Err(ReparseError::OddLength);
    }
    let paths = data.get(fields_len..).ok_or(ReparseError::Truncated)?;
    let name = paths
        .get(offset..offset.saturating_add(len))
        .ok_or(ReparseError::Truncated)?;
    let mut name = units(name);
    if name.is_empty() {
        return Err(ReparseError::Empty);
    }
    if relative {
        return Ok(ReparseTarget::Relative(name));
    }
    if !name.starts_with(&NT_PREFIX) {
        return Err(ReparseError::NotNtPath);
    }
    name[..VERBATIM_PREFIX.len()].copy_from_slice(&VERBATIM_PREFIX);
    Ok(ReparseTarget::Absolute(name))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::assert_matches;

    fn wide(text: &str) -> Vec<u8> {
        text.encode_utf16().flat_map(u16::to_le_bytes).collect()
    }

    fn buffer(tag: u32, flags: Option<u32>, substitute: &str, print: &str) -> Vec<u8> {
        let sub = wide(substitute);
        let print = wide(print);
        let mut fields = Vec::new();
        fields.extend(0_u16.to_le_bytes());
        fields.extend(u16::try_from(sub.len()).unwrap().to_le_bytes());
        fields.extend(u16::try_from(sub.len()).unwrap().to_le_bytes());
        fields.extend(u16::try_from(print.len()).unwrap().to_le_bytes());
        if let Some(flags) = flags {
            fields.extend(flags.to_le_bytes());
        }
        fields.extend(&sub);
        fields.extend(&print);
        let mut buf = Vec::new();
        buf.extend(tag.to_le_bytes());
        buf.extend(u16::try_from(fields.len()).unwrap().to_le_bytes());
        buf.extend(0_u16.to_le_bytes());
        buf.extend(fields);
        buf
    }

    fn symlink(flags: u32, substitute: &str) -> Vec<u8> {
        buffer(SYMLINK_TAG, Some(flags), substitute, substitute)
    }

    fn junction(substitute: &str) -> Vec<u8> {
        buffer(MOUNT_POINT_TAG, None, substitute, substitute)
    }

    fn set_u16(buf: &mut [u8], at: usize, value: u16) {
        buf[at..at + 2].copy_from_slice(&value.to_le_bytes());
    }

    fn units_of(text: &str) -> Vec<u16> {
        text.encode_utf16().collect()
    }

    #[test]
    fn a_relative_symlink_keeps_its_substitute_name() {
        let parsed = parse(&symlink(1, r"..\sibling\dir")).unwrap();

        assert_eq!(parsed, ReparseTarget::Relative(units_of(r"..\sibling\dir")));
    }

    #[test]
    fn an_absolute_symlink_is_rewritten_to_the_verbatim_form() {
        let parsed = parse(&symlink(0, r"\??\C:\dest\sub")).unwrap();

        assert_eq!(
            parsed,
            ReparseTarget::Absolute(units_of(r"\\?\C:\dest\sub"))
        );
    }

    #[test]
    fn a_junction_is_always_absolute() {
        let parsed = parse(&junction(r"\??\C:\dest\sub")).unwrap();

        assert_eq!(
            parsed,
            ReparseTarget::Absolute(units_of(r"\\?\C:\dest\sub"))
        );
    }

    #[test]
    fn a_unc_target_becomes_a_verbatim_unc_path() {
        let parsed = parse(&junction(r"\??\UNC\host\share\x")).unwrap();

        assert_eq!(
            parsed,
            ReparseTarget::Absolute(units_of(r"\\?\UNC\host\share\x"))
        );
    }

    #[test]
    fn the_print_name_is_never_used() {
        let buf = buffer(SYMLINK_TAG, Some(0), r"\??\C:\inside", r"C:\outside");

        assert_eq!(
            parse(&buf).unwrap(),
            ReparseTarget::Absolute(units_of(r"\\?\C:\inside"))
        );
    }

    #[test]
    fn a_device_path_is_not_an_nt_path() {
        assert_matches!(
            parse(&junction(r"\Device\HarddiskVolume1\x")),
            Err(ReparseError::NotNtPath)
        );
        assert_matches!(parse(&symlink(0, r"C:\x")), Err(ReparseError::NotNtPath));
    }

    #[test]
    fn an_empty_substitute_name_is_refused() {
        assert_matches!(parse(&symlink(1, "")), Err(ReparseError::Empty));
    }

    #[test]
    fn a_short_header_is_truncated() {
        let full = symlink(1, "x");

        for len in 0..HEADER_LEN {
            assert_matches!(parse(&full[..len]), Err(ReparseError::Truncated));
        }
    }

    #[test]
    fn a_declared_data_length_past_the_buffer_is_truncated() {
        let full = symlink(1, "name");

        for len in HEADER_LEN..full.len() {
            assert_matches!(parse(&full[..len]), Err(ReparseError::Truncated));
        }
    }

    #[test]
    fn a_data_length_too_short_for_the_fixed_fields_is_truncated() {
        let mut buf = symlink(1, "name");
        set_u16(&mut buf, 4, 6);
        assert_matches!(parse(&buf), Err(ReparseError::Truncated));

        let mut buf = junction("name");
        set_u16(&mut buf, 4, 4);
        assert_matches!(parse(&buf), Err(ReparseError::Truncated));
    }

    #[test]
    fn a_name_past_the_declared_data_is_truncated() {
        let mut buf = symlink(1, "name");
        set_u16(&mut buf, 8, 0xFFFE);
        assert_matches!(parse(&buf), Err(ReparseError::Truncated));

        let mut buf = symlink(1, "name");
        set_u16(&mut buf, 10, 0xFFFE);
        assert_matches!(parse(&buf), Err(ReparseError::Truncated));

        let mut buf = symlink(1, "name");
        set_u16(&mut buf, 4, 18);
        assert_matches!(parse(&buf), Err(ReparseError::Truncated));
    }

    #[test]
    fn data_beyond_the_declared_length_is_ignored() {
        let mut buf = symlink(1, "name");
        buf.extend([0xFF; 8]);

        assert_eq!(
            parse(&buf).unwrap(),
            ReparseTarget::Relative(units_of("name"))
        );
    }

    #[test]
    fn an_odd_offset_or_length_is_refused() {
        let mut buf = symlink(1, "name");
        set_u16(&mut buf, 8, 1);
        assert_matches!(parse(&buf), Err(ReparseError::OddLength));

        let mut buf = symlink(1, "name");
        set_u16(&mut buf, 10, 7);
        assert_matches!(parse(&buf), Err(ReparseError::OddLength));
    }

    #[test]
    fn another_tag_is_unsupported() {
        for tag in [0x9000_001A_u32, 0x8000_0017, 0xA000_001D, 0] {
            let buf = buffer(tag, Some(0), "x", "x");
            assert_matches!(parse(&buf), Err(ReparseError::UnsupportedTag(found)) if found == tag);
        }
    }

    #[test]
    fn a_refusal_is_invalid_data() {
        let error = io::Error::from(ReparseError::Truncated);

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
    }
}

#[cfg(all(test, windows))]
mod windows_constants {
    use super::*;
    use windows_sys::Wdk::Storage::FileSystem::SYMLINK_FLAG_RELATIVE as WINDOWS_RELATIVE;
    use windows_sys::Win32::System::SystemServices::IO_REPARSE_TAG_MOUNT_POINT;
    use windows_sys::Win32::System::SystemServices::IO_REPARSE_TAG_SYMLINK;

    #[test]
    fn the_local_constants_match_the_system_headers() {
        assert_eq!(SYMLINK_TAG, IO_REPARSE_TAG_SYMLINK);
        assert_eq!(MOUNT_POINT_TAG, IO_REPARSE_TAG_MOUNT_POINT);
        assert_eq!(SYMLINK_FLAG_RELATIVE, WINDOWS_RELATIVE);
    }
}

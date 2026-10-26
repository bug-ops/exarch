//! File type a ZIP reader takes from an `xl` extra field.
//!
//! The `zip` crate reads an entry's type from the central attributes only.
//! libarchive 3.7, which this check is written against, also honours the
//! experimental `xl` (`0x6c78`) extra field that repeats them: a streaming
//! reader (a real pipe) reads it from the local header, a seekable one (a file,
//! or a redirected `-f - < file`) from the central record and then the local
//! header. A field that disagrees with the central attributes makes the two
//! readers extract different kinds of entry under one name.
//!
//! Entries without an `xl` attribute field are not compared: a streaming reader
//! reads them as regular files or directories whatever the central directory
//! says, which every symlink written by common producers relies on. Of the
//! conditions that make the reader reject a header only an extra field that
//! overruns its block is modelled; any other header is still compared, which
//! can only add a finding.

use flate2::Crc;

use super::extra_fields;
use super::le32;
use crate::formats::common::SpecialFile;
use crate::formats::common::UnixFileType;
use crate::formats::zip::ZipEntryKind;
use crate::formats::zip::zip_entry_kind;

const XL_EXTRA_ID: u16 = 0x6c78;
const UNICODE_PATH_EXTRA_ID: u16 = 0x7075;
const UNICODE_PATH_HEAD_LEN: usize = 5;
const XL_VERSION_MADE_BY: u8 = 1;
const XL_INTERNAL_ATTRIBUTES: u8 = 2;
const XL_EXTERNAL_ATTRIBUTES: u8 = 4;
const XL_BITMAP_CONTINUES: u8 = 0x80;

const HOST_DOS: u8 = 0;
const HOST_UNIX: u8 = 3;
const DOS_DIRECTORY: u32 = 0x10;
const DOS_READ_ONLY: u32 = 0x01;

/// Host system a header names, which decides how its attributes are read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum HostSystem {
    Dos,
    Unix,
    /// Any other host: the reader takes no type from its attributes.
    Other,
}

impl HostSystem {
    pub(super) const fn from_byte(byte: u8) -> Self {
        match byte {
            HOST_DOS => Self::Dos,
            HOST_UNIX => Self::Unix,
            _ => Self::Other,
        }
    }
}

/// What an entry is extracted as.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum EntryKind {
    Regular,
    Directory,
    Symlink,
    /// Device node or socket, which no ZIP handler of this crate extracts.
    Special,
}

impl EntryKind {
    /// The type the extraction here gives an entry, from its central record.
    pub(super) fn of_central(is_dir: bool, mode: Option<u32>) -> Self {
        match zip_entry_kind(is_dir, mode) {
            ZipEntryKind::Directory => Self::Directory,
            ZipEntryKind::Symlink => Self::Symlink,
            ZipEntryKind::Regular => Self::Regular,
        }
    }
}

/// What the `xl` fields of one header's extra block say.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct XlScan {
    /// Host system after any version-made-by of an `xl` field.
    pub(super) host: HostSystem,
    pub(super) file_type: Option<XlFileType>,
}

impl XlScan {
    /// A block without `xl` fields, which also stands for a central record the
    /// reader does not use: a streaming reader never reads it, so it must not
    /// decide whether the local header is compared.
    pub(super) const ABSENT: Self = Self {
        host: HostSystem::Dos,
        file_type: None,
    };

    /// Scans `extra`, a header's extra block, for `xl` fields. `host` is the
    /// one the header's version field names.
    ///
    /// Follows the reader's order: a later field's version-made-by replaces the
    /// host, a field that is cut short ends its own parsing only, and the last
    /// field with attributes wins. An extra field whose declared length
    /// overruns the block makes the reader reject the header, so `None` is
    /// returned.
    pub(super) fn parse(host: HostSystem, extra: &[u8]) -> Option<Self> {
        let mut scan = Self {
            host,
            file_type: None,
        };
        for field in extra_fields(extra) {
            let (id, body) = field.ok()?;
            if id == XL_EXTRA_ID {
                apply_xl(body, &mut scan.host, &mut scan.file_type);
            }
        }
        Some(scan)
    }
}

/// The type a reader extracts an entry as when an `xl` field gives one: the
/// local header's field overrides the central record's.
///
/// `name` and `local_extra` are the local header's; the directory decision
/// follows the reader's final name (see [`is_directory_name`]).
pub(super) fn reader_kind(
    local: XlScan,
    central: XlScan,
    name: &[u8],
    local_extra: &[u8],
) -> Option<EntryKind> {
    let file_type = local.file_type.or(central.file_type)?;
    Some(file_type.kind(is_directory_name(name, local_extra, local.host)))
}

/// Whether the reader's final name for an entry marks a directory.
///
/// The reader replaces the name by a Unicode Path extra field whose CRC-32
/// matches the name it replaces, and on a DOS host turns backslashes into
/// slashes when the name has no slash. The CRC is taken over the raw bytes,
/// which is the reader's name on POSIX but may differ from the converted name
/// of a libarchive that converts names to a locale.
fn is_directory_name(name: &[u8], extra: &[u8], host: HostSystem) -> bool {
    let mut name = name;
    // An overrun is unreachable here: `XlScan::parse` rejects the same bytes
    // first.
    for (id, body) in extra_fields(extra).map_while(std::result::Result::ok) {
        let Some((head, replacement)) = body.split_first_chunk::<UNICODE_PATH_HEAD_LEN>() else {
            continue;
        };
        if id != UNICODE_PATH_EXTRA_ID {
            continue;
        }
        let mut crc = Crc::new();
        crc.update(name);
        if crc.sum() == le32::<1, UNICODE_PATH_HEAD_LEN>(head) {
            name = replacement;
        }
    }
    match name.last() {
        Some(b'/') => true,
        Some(b'\\') => host == HostSystem::Dos && !name.contains(&b'/'),
        _ => false,
    }
}

/// File type bits an `xl` extra field gives an entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct XlFileType(Option<UnixFileType>);

impl XlFileType {
    /// The type the reader extracts the entry as; a trailing slash in the name
    /// makes anything but a directory one.
    pub(super) fn kind(self, trailing_slash: bool) -> EntryKind {
        match (self.0, trailing_slash) {
            (Some(UnixFileType::Directory), _) | (_, true) => EntryKind::Directory,
            (Some(UnixFileType::Symlink), false) => EntryKind::Symlink,
            (
                None | Some(UnixFileType::Regular | UnixFileType::Special(SpecialFile::Fifo)),
                false,
            ) => EntryKind::Regular,
            _ => EntryKind::Special,
        }
    }

    fn of_attributes(host: HostSystem, attributes: u32) -> Self {
        Self(match host {
            HostSystem::Unix => UnixFileType::from_mode(attributes >> 16),
            // The reader strips the write bits of a read-only entry with a mask
            // that also clears the type, so such a directory reads as a file.
            HostSystem::Dos if attributes & (DOS_DIRECTORY | DOS_READ_ONLY) == DOS_DIRECTORY => {
                Some(UnixFileType::Directory)
            }
            HostSystem::Dos => Some(UnixFileType::Regular),
            HostSystem::Other => None,
        })
    }
}

fn apply_xl(body: &[u8], host: &mut HostSystem, file_type: &mut Option<XlFileType>) {
    let Some((&bitmap, mut rest)) = body.split_first() else {
        return;
    };
    let mut last = bitmap;
    while last & XL_BITMAP_CONTINUES != 0 {
        let Some((&next, tail)) = rest.split_first() else {
            break;
        };
        last = next;
        rest = tail;
    }
    if bitmap & XL_VERSION_MADE_BY != 0 {
        let Some((version, tail)) = rest.split_first_chunk::<2>() else {
            return;
        };
        *host = HostSystem::from_byte(version[1]);
        rest = tail;
    }
    if bitmap & XL_INTERNAL_ATTRIBUTES != 0 {
        let Some((_, tail)) = rest.split_first_chunk::<2>() else {
            return;
        };
        rest = tail;
    }
    if bitmap & XL_EXTERNAL_ATTRIBUTES != 0 {
        let Some((attributes, _)) = rest.split_first_chunk::<4>() else {
            return;
        };
        *file_type = Some(XlFileType::of_attributes(
            *host,
            u32::from_le_bytes(*attributes),
        ));
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::raw_zip::SYMLINK_MODE as LINK;

    const S_IFDIR: u32 = 0o040_000;
    const S_IFREG: u32 = 0o100_000;
    const S_IFIFO: u32 = 0o010_000;
    use crate::raw_zip::extra_field;
    use crate::raw_zip::unicode_path_field;
    use crate::raw_zip::xl_unix_attributes as attributes;

    fn xl(body: &[u8]) -> Vec<u8> {
        extra_field(XL_EXTRA_ID, body)
    }

    fn dos_attributes(bits: u32) -> Vec<u8> {
        let mut body = vec![XL_EXTERNAL_ATTRIBUTES];
        body.extend_from_slice(&bits.to_le_bytes());
        xl(&body)
    }

    fn kind_of(host: HostSystem, extra: &[u8], slash: bool) -> Option<EntryKind> {
        XlScan::parse(host, extra)
            .and_then(|scan| scan.file_type)
            .map(|t| t.kind(slash))
    }

    #[test]
    fn unix_attributes_give_the_type_bits() {
        let cases = [
            (LINK, EntryKind::Symlink),
            (S_IFDIR | 0o755, EntryKind::Directory),
            (S_IFREG | 0o644, EntryKind::Regular),
            (S_IFIFO | 0o644, EntryKind::Regular),
            (0, EntryKind::Regular),
            (0o020_666, EntryKind::Special),
            (0o140_755, EntryKind::Special),
        ];
        for (mode, kind) in cases {
            assert_eq!(
                kind_of(HostSystem::Unix, &xl(&attributes(mode)), false),
                Some(kind),
                "{mode:o}"
            );
        }
    }

    #[test]
    fn every_type_nibble_maps_to_a_kind() {
        use EntryKind::Directory;
        use EntryKind::Regular;
        use EntryKind::Special;
        use EntryKind::Symlink;
        // Index = the four S_IFMT bits; 0 records no type.
        let plain = [
            Regular, Regular, Special, Special, Directory, Special, Special, Special, Regular,
            Special, Symlink, Special, Special, Special, Special, Special,
        ];
        for (nibble, expected) in plain.into_iter().enumerate() {
            let mode = u32::try_from(nibble).unwrap() << 12;
            let file_type = XlFileType::of_attributes(HostSystem::Unix, mode << 16);
            assert_eq!(file_type.kind(false), expected, "{mode:o}");
            assert_eq!(file_type.kind(true), Directory, "{mode:o} with slash");
        }
    }

    #[test]
    fn host_comes_from_the_header_unless_the_field_overrides_it() {
        let link = xl(&attributes(LINK));
        for host in [HostSystem::Dos, HostSystem::Other] {
            assert_eq!(kind_of(host, &link, false), Some(EntryKind::Regular));
        }

        let mut body = vec![XL_VERSION_MADE_BY | XL_EXTERNAL_ATTRIBUTES];
        body.extend_from_slice(&0x031eu16.to_le_bytes());
        body.extend_from_slice(&(LINK << 16).to_le_bytes());
        assert_eq!(
            kind_of(HostSystem::Dos, &xl(&body), false),
            Some(EntryKind::Symlink)
        );
    }

    #[test]
    fn dos_attributes_know_only_writable_directories_and_files() {
        let cases = [
            (DOS_DIRECTORY, EntryKind::Directory),
            (0, EntryKind::Regular),
            (DOS_DIRECTORY | DOS_READ_ONLY, EntryKind::Regular),
        ];
        for (bits, kind) in cases {
            assert_eq!(
                kind_of(HostSystem::Dos, &dos_attributes(bits), false),
                Some(kind),
                "{bits:#x}"
            );
        }
        assert_eq!(
            kind_of(
                HostSystem::Dos,
                &dos_attributes(DOS_DIRECTORY | DOS_READ_ONLY),
                true
            ),
            Some(EntryKind::Directory)
        );
    }

    #[test]
    fn a_trailing_slash_makes_any_type_a_directory() {
        let link = xl(&attributes(LINK));
        assert_eq!(
            kind_of(HostSystem::Unix, &link, true),
            Some(EntryKind::Directory)
        );
    }

    #[test]
    fn optional_fields_and_bitmap_continuation_are_skipped() {
        let mut body = vec![
            XL_VERSION_MADE_BY | XL_INTERNAL_ATTRIBUTES | XL_EXTERNAL_ATTRIBUTES | 0x80,
            0x01,
        ];
        body.extend_from_slice(&0x031eu16.to_le_bytes());
        body.extend_from_slice(&[0xaa, 0xbb]);
        body.extend_from_slice(&(LINK << 16).to_le_bytes());
        assert_eq!(
            kind_of(HostSystem::Dos, &xl(&body), false),
            Some(EntryKind::Symlink)
        );
    }

    #[test]
    fn a_field_without_external_attributes_or_cut_short_gives_no_type() {
        assert_eq!(kind_of(HostSystem::Unix, &[], false), None);
        assert_eq!(kind_of(HostSystem::Unix, &xl(&[]), false), None);
        assert_eq!(
            kind_of(HostSystem::Unix, &xl(&[XL_VERSION_MADE_BY]), false),
            None
        );
        let cut = [XL_EXTERNAL_ATTRIBUTES, 0, 0, 0];
        assert_eq!(kind_of(HostSystem::Unix, &xl(&cut), false), None);
    }

    #[test]
    fn an_overrunning_extra_field_rejects_the_header() {
        let mut extra = xl(&attributes(LINK));
        extra.extend_from_slice(&[0x55, 0x54, 99, 0, 1]);
        assert_eq!(XlScan::parse(HostSystem::Unix, &extra), None);
    }

    #[test]
    fn the_last_field_with_attributes_wins() {
        let mut extra = xl(&attributes(LINK));
        extra.extend(xl(&attributes(S_IFREG | 0o644)));
        assert_eq!(
            kind_of(HostSystem::Unix, &extra, false),
            Some(EntryKind::Regular)
        );
    }

    proptest::proptest! {
        #[test]
        fn parsing_arbitrary_extra_bytes_never_panics(
            host in 0u8..=255,
            extra in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..64),
        ) {
            let _ = XlScan::parse(HostSystem::from_byte(host), &extra);
        }
    }

    #[test]
    fn directory_name_follows_the_readers_final_name() {
        assert!(is_directory_name(b"d/", &[], HostSystem::Unix));
        assert!(!is_directory_name(b"d", &[], HostSystem::Unix));
        assert!(!is_directory_name(b"", &[], HostSystem::Unix));
        assert!(is_directory_name(b"d\\", &[], HostSystem::Dos));
        assert!(!is_directory_name(b"d\\", &[], HostSystem::Unix));
        assert!(!is_directory_name(b"a/d\\", &[], HostSystem::Dos));

        let upath = unicode_path_field(b"d", b"d/");
        assert!(is_directory_name(b"d", &upath, HostSystem::Unix));
        let stale = unicode_path_field(b"other", b"d/");
        assert!(!is_directory_name(b"d", &stale, HostSystem::Unix));
        let to_file = unicode_path_field(b"d/", b"d");
        assert!(!is_directory_name(b"d/", &to_file, HostSystem::Unix));
    }

    #[test]
    fn an_absent_central_scan_does_not_hide_a_local_field() {
        let local = XlScan::parse(HostSystem::Unix, &xl(&attributes(LINK))).unwrap();
        assert_eq!(
            reader_kind(local, XlScan::ABSENT, b"a", &[]),
            Some(EntryKind::Symlink)
        );
        assert_eq!(reader_kind(XlScan::ABSENT, XlScan::ABSENT, b"a", &[]), None);
    }

    #[test]
    fn the_local_field_overrides_the_central_one() {
        let scan = |mode| XlScan::parse(HostSystem::Unix, &xl(&attributes(mode))).unwrap();
        let (link, regular) = (scan(LINK), scan(S_IFREG));
        assert_eq!(
            reader_kind(link, regular, b"a", &[]),
            Some(EntryKind::Symlink)
        );
        assert_eq!(
            reader_kind(XlScan::ABSENT, link, b"a", &[]),
            Some(EntryKind::Symlink)
        );
    }

    #[test]
    fn central_type_follows_the_extraction() {
        assert_eq!(
            EntryKind::of_central(true, Some(LINK)),
            EntryKind::Directory
        );
        assert_eq!(EntryKind::of_central(false, Some(LINK)), EntryKind::Symlink);
        assert_eq!(
            EntryKind::of_central(false, Some(S_IFREG | 0o644)),
            EntryKind::Regular
        );
        assert_eq!(EntryKind::of_central(false, None), EntryKind::Regular);
    }
}

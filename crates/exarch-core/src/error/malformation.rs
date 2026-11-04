//! Typed malformed-archive refusals.
//!
//! [`Malformation`] is the payload of [`ArchiveError::InvalidArchive`]. Each
//! kind fixes its own message and its [`InvalidArchiveSubCode`], so the two
//! cannot disagree. Kinds that carry no family of their own are
//! [`Malformation::Unclassified`], which only this crate can construct.
//!
//! [`ArchiveError::InvalidArchive`]: super::ArchiveError::InvalidArchive

use std::fmt;
use std::path::PathBuf;

use super::messages::InvalidArchiveSubCode;
use crate::security::fs_view::LinkKind;

/// A malformed-archive refusal that has no family of its own.
///
/// Only this crate constructs it, so a refusal with a family cannot be raised
/// untyped from outside. Callers meet it only inside a received
/// [`Malformation::Unclassified`], whose [`Malformation::sub_code`] is `None`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unclassified(Box<str>);

impl Unclassified {
    pub(crate) fn new(reason: impl Into<Box<str>>) -> Self {
        Self(reason.into())
    }
}

/// Why an archive, or one of its entries, is malformed.
///
/// # Examples
///
/// ```
/// use exarch_core::InvalidArchiveSubCode;
/// use exarch_core::Malformation;
///
/// let m = Malformation::DeclaredCompressedExceedsArchive;
/// assert_eq!(
///     m.to_string(),
///     "declared compressed size exceeds archive length"
/// );
/// assert_eq!(m.sub_code(), Some(InvalidArchiveSubCode::DeclaredSize));
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Malformation {
    /// A link entry has no target.
    LinkTargetMissing(LinkKind),
    /// The name of a link entry cannot be read.
    LinkNameUnreadable {
        /// The kind of link.
        kind: LinkKind,
        /// The reader's description of the failure.
        detail: Box<str>,
    },
    /// The target of a link entry cannot be read.
    LinkTargetUnreadable {
        /// The reader's description of the failure.
        detail: Box<str>,
    },
    /// The target of a ZIP symlink cannot be read.
    SymlinkTargetUnreadable {
        /// The reader's description of the failure.
        detail: Box<str>,
    },
    /// The target of a 7z symlink cannot be read.
    SevenZipSymlinkTargetUnreadable {
        /// The entry name.
        name: Box<str>,
        /// Why the target cannot be read.
        detail: Box<str>,
    },
    /// A symlink target is not valid UTF-8.
    SymlinkTargetNotUtf8,
    /// A link target is longer than the host allows.
    LinkTargetTooLong {
        /// The kind of link.
        kind: LinkKind,
        /// The length of the target in bytes.
        bytes: usize,
    },
    /// A hardlink target does not exist when the link is created.
    HardlinkTargetAbsent {
        /// The target path.
        target: PathBuf,
    },
    /// A hardlink target is a directory.
    HardlinkTargetDirectory {
        /// The target path.
        target: PathBuf,
    },
    /// A hardlink target is not a regular file.
    HardlinkTargetNotRegular {
        /// The target path.
        target: PathBuf,
    },
    /// An entry path is already taken.
    DuplicateEntry {
        /// The path of the second entry.
        path: PathBuf,
    },
    /// The path of a TAR entry cannot be read.
    EntryPathUnreadable {
        /// The reader's description of the failure.
        detail: Box<str>,
    },
    /// The name of a ZIP entry cannot be read.
    EntryNameUnreadable {
        /// The central-directory index of the entry, when known.
        index: Option<usize>,
        /// The reader's description of the failure.
        detail: Box<str>,
    },
    /// An entry path is not valid UTF-8, so a binding cannot name it.
    EntryPathNotUtf8 {
        /// The path, lossily rendered.
        path: PathBuf,
    },
    /// A declared compressed size is larger than the archive.
    DeclaredCompressedExceedsArchive,
    /// The pack sizes of a 7z archive overflow.
    PackSizesOverflow,
    /// A 7z block's files do not add up to its decoded size.
    BlockSizeUnaccounted,
    /// The entry sizes of an archive overflow `u64`.
    TotalSizeOverflow,
    /// The integrity decode of an entry failed.
    IntegrityCheckFailed {
        /// Where the failure was found.
        location: Box<str>,
        /// What failed.
        detail: Box<str>,
    },
    /// The `zip` crate cannot open the archive.
    ZipArchiveUnreadable {
        /// The reader's description of the failure.
        detail: Box<str>,
    },
    /// The `zip` crate cannot read an entry while the archive is checked.
    ZipEntryUnreadable {
        /// The central-directory index of the entry.
        index: usize,
        /// The reader's description of the failure.
        detail: Box<str>,
    },
    /// The `zip` crate cannot open an entry for extraction.
    ZipEntryOpenFailed {
        /// The central-directory index of the entry.
        index: usize,
        /// The reader's description of the failure.
        detail: Box<str>,
    },
    /// The `zip` crate cannot open an entry a second time.
    ZipEntryRereadFailed {
        /// The central-directory index of the entry.
        index: usize,
        /// The reader's description of the failure.
        detail: Box<str>,
    },
    /// The `zip` crate cannot read an entry while the archive is listed.
    ZipListedEntryUnreadable {
        /// The reader's description of the failure.
        detail: Box<str>,
    },
    /// The central directory the census read is not the one the reader read.
    ZipCensusDisagreement,
    /// An entry's data range does not fit in 64 bits.
    ZipDataRangeUnrepresentable,
    /// The zstd entries could not be walked within the archive extent.
    ZipZstdWalkIncomplete,
    /// The `tar` crate cannot read a PAX header of an entry.
    TarPaxHeaderUnreadable {
        /// The reader's description of the failure.
        detail: Box<str>,
    },
    /// The `tar` crate cannot start reading the entries while an archive is
    /// extracted.
    TarEntriesUnreadable {
        /// The reader's description of the failure.
        detail: Box<str>,
    },
    /// The `tar` crate cannot start reading the entries while an archive is
    /// listed.
    TarListEntriesUnreadable {
        /// The reader's description of the failure.
        detail: Box<str>,
    },
    /// The `tar` crate fails while reading toward the next entry.
    TarEntryUnreadable {
        /// The reader's description of the failure.
        detail: Box<str>,
    },
    /// The TAR reader was asked for an entry after one was abandoned.
    TarReadAfterAbandonedEntry,
    /// A 7z block uses a coder exarch does not decode or malformed coder
    /// properties.
    SevenZUnsupportedCoder,
    /// The 7z header lists pack streams without a stream-map offset for each.
    SevenZPackStreamOffsetMismatch {
        /// Number of stream-map offsets.
        offsets: usize,
        /// Number of pack streams.
        pack_streams: usize,
    },
    /// `sevenz-rust2` cannot parse the 7z header.
    SevenZHeaderUnreadable {
        /// The reader's description of the failure.
        detail: Box<str>,
    },
    /// The link entries of a 7z archive are not in ascending file order.
    SevenZLinkEntriesOutOfOrder,
    /// `sevenz-rust2` fails in a way that has no kind of its own.
    SevenZLibraryError {
        /// The reader's description of the failure.
        detail: Box<str>,
    },
    /// A refusal with no family of its own.
    Unclassified(Unclassified),
}

impl Malformation {
    pub(crate) fn unclassified(reason: impl Into<Box<str>>) -> Self {
        Self::Unclassified(Unclassified::new(reason))
    }

    /// The family this kind belongs to, `None` for an unclassified refusal.
    #[must_use]
    pub const fn sub_code(&self) -> Option<InvalidArchiveSubCode> {
        use InvalidArchiveSubCode as C;
        match self {
            Self::LinkTargetMissing(_)
            | Self::LinkNameUnreadable { .. }
            | Self::LinkTargetUnreadable { .. }
            | Self::SymlinkTargetUnreadable { .. }
            | Self::SevenZipSymlinkTargetUnreadable { .. }
            | Self::SymlinkTargetNotUtf8
            | Self::LinkTargetTooLong { .. }
            | Self::HardlinkTargetAbsent { .. }
            | Self::HardlinkTargetDirectory { .. }
            | Self::HardlinkTargetNotRegular { .. } => Some(C::LinkTarget),
            Self::DuplicateEntry { .. } => Some(C::DuplicateEntry),
            Self::EntryPathUnreadable { .. }
            | Self::EntryNameUnreadable { .. }
            | Self::EntryPathNotUtf8 { .. } => Some(C::EntryName),
            Self::DeclaredCompressedExceedsArchive
            | Self::PackSizesOverflow
            | Self::BlockSizeUnaccounted
            | Self::TotalSizeOverflow => Some(C::DeclaredSize),
            Self::IntegrityCheckFailed { .. } => Some(C::Integrity),
            Self::ZipArchiveUnreadable { .. }
            | Self::ZipEntryUnreadable { .. }
            | Self::ZipEntryOpenFailed { .. }
            | Self::ZipEntryRereadFailed { .. }
            | Self::ZipListedEntryUnreadable { .. }
            | Self::ZipCensusDisagreement
            | Self::ZipDataRangeUnrepresentable
            | Self::ZipZstdWalkIncomplete => Some(C::ZipReader),
            Self::TarPaxHeaderUnreadable { .. }
            | Self::TarEntriesUnreadable { .. }
            | Self::TarListEntriesUnreadable { .. }
            | Self::TarEntryUnreadable { .. }
            | Self::TarReadAfterAbandonedEntry => Some(C::TarReader),
            Self::SevenZUnsupportedCoder
            | Self::SevenZPackStreamOffsetMismatch { .. }
            | Self::SevenZHeaderUnreadable { .. }
            | Self::SevenZLinkEntriesOutOfOrder
            | Self::SevenZLibraryError { .. } => Some(C::SevenZReader),
            Self::Unclassified(_) => None,
        }
    }
}

impl fmt::Display for Malformation {
    #[expect(clippy::too_many_lines, reason = "one arm per kind")]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LinkTargetMissing(kind) => write!(f, "{kind} missing target"),
            Self::LinkNameUnreadable { kind, detail } => {
                write!(f, "failed to read {kind} name: {detail}")
            }
            Self::LinkTargetUnreadable { detail } => write!(f, "invalid link target: {detail}"),
            Self::SymlinkTargetUnreadable { detail } => {
                write!(f, "failed to read symlink target: {detail}")
            }
            Self::SevenZipSymlinkTargetUnreadable { name, detail } => {
                write!(f, "failed to read 7z symlink target {name}: {detail}")
            }
            Self::SymlinkTargetNotUtf8 => f.write_str("symlink target is not valid UTF-8"),
            Self::LinkTargetTooLong { kind, bytes } => {
                write!(f, "{kind} target too long: {bytes} bytes")
            }
            Self::HardlinkTargetAbsent { target } => {
                write!(
                    f,
                    "hardlink target does not exist: {}",
                    crate::path_text(target)
                )
            }
            Self::HardlinkTargetDirectory { target } => {
                write!(
                    f,
                    "hardlink target is a directory: {}",
                    crate::path_text(target)
                )
            }
            Self::HardlinkTargetNotRegular { target } => write!(
                f,
                "hardlink target is not a regular file: {}",
                crate::path_text(target)
            ),
            Self::DuplicateEntry { path } => {
                write!(f, "duplicate entry: {}", crate::path_text(path))
            }
            Self::EntryPathUnreadable { detail } => write!(f, "invalid path: {detail}"),
            Self::EntryNameUnreadable {
                index: Some(index),
                detail,
            } => write!(f, "invalid entry name at {index}: {detail}"),
            Self::EntryNameUnreadable {
                index: None,
                detail,
            } => write!(f, "invalid entry name: {detail}"),
            Self::EntryPathNotUtf8 { path } => {
                write!(
                    f,
                    "entry path is not valid UTF-8: {}",
                    crate::path_text(path)
                )
            }
            Self::DeclaredCompressedExceedsArchive => {
                f.write_str("declared compressed size exceeds archive length")
            }
            Self::PackSizesOverflow => f.write_str("7z pack sizes overflow"),
            Self::BlockSizeUnaccounted => {
                f.write_str("7z block's files do not account for its decoded size")
            }
            Self::TotalSizeOverflow => f.write_str("archive total size overflows u64"),
            Self::IntegrityCheckFailed { location, detail } => {
                write!(f, "integrity check failed {location}: {detail}")
            }
            Self::ZipArchiveUnreadable { detail } => {
                write!(f, "failed to open ZIP archive: {detail}")
            }
            Self::ZipEntryUnreadable { index, detail } => {
                write!(f, "failed to read entry {index}: {detail}")
            }
            Self::ZipEntryOpenFailed { index, detail } => {
                write!(f, "failed to open zip entry {index}: {detail}")
            }
            Self::ZipEntryRereadFailed { index, detail } => {
                write!(f, "failed to re-read ZIP entry {index}: {detail}")
            }
            Self::ZipListedEntryUnreadable { detail } => {
                write!(f, "failed to read ZIP entry: {detail}")
            }
            Self::ZipCensusDisagreement => {
                f.write_str("ZIP central directory census disagrees with reader")
            }
            Self::ZipDataRangeUnrepresentable => {
                f.write_str("ZIP entry data range is not representable")
            }
            Self::ZipZstdWalkIncomplete => {
                f.write_str("ZIP zstd entries could not be walked within the archive extent")
            }
            Self::TarPaxHeaderUnreadable { detail } => {
                write!(f, "failed to read PAX header: {detail}")
            }
            Self::TarEntriesUnreadable { detail } => write!(f, "failed to read entries: {detail}"),
            Self::TarListEntriesUnreadable { detail } => {
                write!(f, "failed to read TAR entries: {detail}")
            }
            Self::TarEntryUnreadable { detail } => write!(f, "failed to read TAR entry: {detail}"),
            Self::TarReadAfterAbandonedEntry => {
                f.write_str("TAR read continued after an abandoned entry")
            }
            Self::SevenZUnsupportedCoder => {
                f.write_str("7z block uses an unsupported coder or malformed coder properties")
            }
            Self::SevenZPackStreamOffsetMismatch {
                offsets,
                pack_streams,
            } => write!(
                f,
                "failed to open 7z archive: the pack stream offsets have {offsets} entries for \
                 {pack_streams} pack streams"
            ),
            Self::SevenZHeaderUnreadable { detail } => {
                write!(f, "failed to open 7z archive: {detail}")
            }
            Self::SevenZLinkEntriesOutOfOrder => f.write_str("7z link entries are out of order"),
            Self::SevenZLibraryError { detail } => write!(f, "7z error: {detail}"),
            Self::Unclassified(Unclassified(reason)) => f.write_str(reason),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    #[expect(clippy::too_many_lines, reason = "one row per kind")]
    fn one_of_each() -> Vec<(Malformation, &'static str, Option<InvalidArchiveSubCode>)> {
        use InvalidArchiveSubCode as C;
        let path = || PathBuf::from("a/b");
        vec![
            (
                Malformation::LinkTargetMissing(LinkKind::Symlink),
                "symlink missing target",
                Some(C::LinkTarget),
            ),
            (
                Malformation::LinkNameUnreadable {
                    kind: LinkKind::Hardlink,
                    detail: "bad".into(),
                },
                "failed to read hardlink name: bad",
                Some(C::LinkTarget),
            ),
            (
                Malformation::LinkTargetUnreadable {
                    detail: "bad".into(),
                },
                "invalid link target: bad",
                Some(C::LinkTarget),
            ),
            (
                Malformation::SymlinkTargetUnreadable {
                    detail: "bad".into(),
                },
                "failed to read symlink target: bad",
                Some(C::LinkTarget),
            ),
            (
                Malformation::SevenZipSymlinkTargetUnreadable {
                    name: "l".into(),
                    detail: "bad".into(),
                },
                "failed to read 7z symlink target l: bad",
                Some(C::LinkTarget),
            ),
            (
                Malformation::SymlinkTargetNotUtf8,
                "symlink target is not valid UTF-8",
                Some(C::LinkTarget),
            ),
            (
                Malformation::LinkTargetTooLong {
                    kind: LinkKind::Hardlink,
                    bytes: 100_000,
                },
                "hardlink target too long: 100000 bytes",
                Some(C::LinkTarget),
            ),
            (
                Malformation::HardlinkTargetAbsent { target: path() },
                "hardlink target does not exist: a/b",
                Some(C::LinkTarget),
            ),
            (
                Malformation::HardlinkTargetDirectory { target: path() },
                "hardlink target is a directory: a/b",
                Some(C::LinkTarget),
            ),
            (
                Malformation::HardlinkTargetNotRegular { target: path() },
                "hardlink target is not a regular file: a/b",
                Some(C::LinkTarget),
            ),
            (
                Malformation::DuplicateEntry { path: path() },
                "duplicate entry: a/b",
                Some(C::DuplicateEntry),
            ),
            (
                Malformation::EntryPathUnreadable {
                    detail: "bad".into(),
                },
                "invalid path: bad",
                Some(C::EntryName),
            ),
            (
                Malformation::EntryNameUnreadable {
                    index: Some(3),
                    detail: "bad".into(),
                },
                "invalid entry name at 3: bad",
                Some(C::EntryName),
            ),
            (
                Malformation::EntryNameUnreadable {
                    index: None,
                    detail: "bad".into(),
                },
                "invalid entry name: bad",
                Some(C::EntryName),
            ),
            (
                Malformation::EntryPathNotUtf8 { path: path() },
                "entry path is not valid UTF-8: a/b",
                Some(C::EntryName),
            ),
            (
                Malformation::DeclaredCompressedExceedsArchive,
                "declared compressed size exceeds archive length",
                Some(C::DeclaredSize),
            ),
            (
                Malformation::PackSizesOverflow,
                "7z pack sizes overflow",
                Some(C::DeclaredSize),
            ),
            (
                Malformation::BlockSizeUnaccounted,
                "7z block's files do not account for its decoded size",
                Some(C::DeclaredSize),
            ),
            (
                Malformation::TotalSizeOverflow,
                "archive total size overflows u64",
                Some(C::DeclaredSize),
            ),
            (
                Malformation::IntegrityCheckFailed {
                    location: "at f".into(),
                    detail: "crc".into(),
                },
                "integrity check failed at f: crc",
                Some(C::Integrity),
            ),
            (
                Malformation::ZipArchiveUnreadable {
                    detail: "bad".into(),
                },
                "failed to open ZIP archive: bad",
                Some(C::ZipReader),
            ),
            (
                Malformation::ZipEntryUnreadable {
                    index: 2,
                    detail: "bad".into(),
                },
                "failed to read entry 2: bad",
                Some(C::ZipReader),
            ),
            (
                Malformation::ZipEntryOpenFailed {
                    index: 2,
                    detail: "bad".into(),
                },
                "failed to open zip entry 2: bad",
                Some(C::ZipReader),
            ),
            (
                Malformation::ZipEntryRereadFailed {
                    index: 2,
                    detail: "bad".into(),
                },
                "failed to re-read ZIP entry 2: bad",
                Some(C::ZipReader),
            ),
            (
                Malformation::ZipListedEntryUnreadable {
                    detail: "bad".into(),
                },
                "failed to read ZIP entry: bad",
                Some(C::ZipReader),
            ),
            (
                Malformation::ZipCensusDisagreement,
                "ZIP central directory census disagrees with reader",
                Some(C::ZipReader),
            ),
            (
                Malformation::ZipDataRangeUnrepresentable,
                "ZIP entry data range is not representable",
                Some(C::ZipReader),
            ),
            (
                Malformation::ZipZstdWalkIncomplete,
                "ZIP zstd entries could not be walked within the archive extent",
                Some(C::ZipReader),
            ),
            (
                Malformation::TarPaxHeaderUnreadable {
                    detail: "bad".into(),
                },
                "failed to read PAX header: bad",
                Some(C::TarReader),
            ),
            (
                Malformation::TarEntriesUnreadable {
                    detail: "bad".into(),
                },
                "failed to read entries: bad",
                Some(C::TarReader),
            ),
            (
                Malformation::TarListEntriesUnreadable {
                    detail: "bad".into(),
                },
                "failed to read TAR entries: bad",
                Some(C::TarReader),
            ),
            (
                Malformation::TarEntryUnreadable {
                    detail: "bad".into(),
                },
                "failed to read TAR entry: bad",
                Some(C::TarReader),
            ),
            (
                Malformation::TarReadAfterAbandonedEntry,
                "TAR read continued after an abandoned entry",
                Some(C::TarReader),
            ),
            (
                Malformation::SevenZUnsupportedCoder,
                "7z block uses an unsupported coder or malformed coder properties",
                Some(C::SevenZReader),
            ),
            (
                Malformation::SevenZPackStreamOffsetMismatch {
                    offsets: 1,
                    pack_streams: 2,
                },
                "failed to open 7z archive: the pack stream offsets have 1 entries for 2 pack \
                 streams",
                Some(C::SevenZReader),
            ),
            (
                Malformation::SevenZHeaderUnreadable {
                    detail: "bad".into(),
                },
                "failed to open 7z archive: bad",
                Some(C::SevenZReader),
            ),
            (
                Malformation::SevenZLinkEntriesOutOfOrder,
                "7z link entries are out of order",
                Some(C::SevenZReader),
            ),
            (
                Malformation::SevenZLibraryError {
                    detail: "bad".into(),
                },
                "7z error: bad",
                Some(C::SevenZReader),
            ),
            (Malformation::unclassified("anything"), "anything", None),
        ]
    }

    #[test]
    fn every_kind_has_its_message_and_family() {
        for (malformation, message, sub_code) in one_of_each() {
            assert_eq!(malformation.to_string(), message);
            assert_eq!(malformation.sub_code(), sub_code, "{message}");
        }
    }

    #[test]
    fn every_new_family_is_produced_by_some_kind() {
        use InvalidArchiveSubCode as C;
        let produced: Vec<_> = one_of_each()
            .into_iter()
            .filter_map(|(m, ..)| m.sub_code())
            .collect();
        for code in [
            C::LinkTarget,
            C::DuplicateEntry,
            C::EntryName,
            C::DeclaredSize,
            C::Integrity,
            C::ZipReader,
            C::TarReader,
            C::SevenZReader,
        ] {
            assert!(produced.contains(&code), "{code:?}");
        }
    }
}

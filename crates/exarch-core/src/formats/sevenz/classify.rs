//! Classification of 7z entries by their attributes: file, directory, symlink,
//! reparse point and anti item.

use crate::ArchiveError;
use crate::Result;
use crate::formats::common;
use crate::inspection::manifest::ManifestEntryType;
use crate::security::validator::NodeKind;

/// How a 7z archive entry is treated, decided once for `extract`, `list` and
/// `verify` so they cannot disagree.
///
/// # Known Limitations (sevenz-rust2 0.24)
///
/// - **Unix mode**: p7zip and libarchive store the mode in the high 16 bits of
///   the attributes (flagged by `0x8000`). `S_IFLNK` is classified as
///   [`SevenZKind::UnixSymlink`]; a FIFO, socket, device node, undefined type,
///   or a type that contradicts the entry's native kind is
///   [`SevenZClass::Unsupported`].
/// - **Symlinks (Windows)**: detected through `FILE_ATTRIBUTE_REPARSE_POINT`
///   and refused on extraction.
/// - **Hardlinks**: not detectable; extracted as separate files.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SevenZClass {
    /// A "delete this path" marker of an incremental update. Never extracted,
    /// validated, counted against quota or listed. Unlike `7z x`, which applies
    /// it as a deletion, exarch deliberately skips it: it applies no
    /// deletions, and materializing one would truncate an existing file.
    AntiItem,
    /// An entry that stands for something on disk.
    Present(SevenZKind),
    /// An entry exarch refuses in `extract`, `list` and `verify`.
    Unsupported(UnsupportedEntry),
}

/// What a present 7z entry stands for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SevenZKind {
    /// A regular file.
    File,
    /// A directory.
    Directory,
    /// A Windows reparse point (symlink or junction), file or directory.
    ReparsePoint,
    /// A symlink recorded through the Unix mode p7zip stores in the attributes.
    UnixSymlink,
}

/// What the 7z header itself says an entry is: a directory has no stream and
/// is not flagged as an empty file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NativeKind {
    /// Holds data or is an empty file.
    File,
    /// Has no stream and is not an empty file.
    Directory,
}

impl NativeKind {
    const fn noun(self) -> &'static str {
        match self {
            Self::File => "file",
            Self::Directory => "directory",
        }
    }

    const fn opposite(self) -> &'static str {
        match self {
            Self::File => "directory",
            Self::Directory => "regular file",
        }
    }
}

/// Where a claim about an entry's kind was recorded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KindSource {
    /// The Unix mode in the high 16 bits of the attributes.
    UnixMode,
    /// The Windows `FILE_ATTRIBUTE_DIRECTORY` bit.
    WindowsAttribute,
}

impl KindSource {
    const fn noun(self) -> &'static str {
        match self {
            Self::UnixMode => "Unix mode",
            Self::WindowsAttribute => "Windows attributes",
        }
    }
}

/// Why a 7z entry is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnsupportedEntry {
    /// A FIFO, device node or socket.
    Special(common::SpecialFile),
    /// A Unix mode whose type bits name no defined file type.
    UndefinedType(u8),
    /// A recorded kind that the entry's native kind contradicts: the claim is
    /// the opposite of `native`.
    KindContradiction {
        /// What the 7z header says.
        native: NativeKind,
        /// Where the contradicting claim was recorded.
        claimed_by: KindSource,
    },
}

impl UnsupportedEntry {
    /// The refusal for the entry named `name`.
    fn refusal(self, name: &str) -> ArchiveError {
        let reason = match self {
            Self::Special(special) => {
                format!("{} entries not supported: {name}", special.noun())
            }
            Self::UndefinedType(bits) => {
                format!("7z entry has an undefined Unix file type ({bits:#x}): {name}")
            }
            Self::KindContradiction { native, claimed_by } => format!(
                "7z entry is a {} but its {} says {}: {name}",
                native.noun(),
                claimed_by.noun(),
                native.opposite()
            ),
        };
        ArchiveError::violation(reason)
    }
}

impl SevenZClass {
    /// Classifies an entry. An anti item wins over every other attribute, and
    /// a link wins over the directory flag because junctions are directories.
    pub(crate) fn of(entry: &sevenz_rust2::ArchiveEntry) -> Self {
        use common::UnixFileType;

        if entry.is_anti_item {
            return Self::AntiItem;
        }
        if is_windows_reparse_point(entry) {
            return Self::Present(SevenZKind::ReparsePoint);
        }
        let mode_type = unix_file_type(entry);
        if mode_type == Some(UnixFileType::Symlink) {
            return Self::Present(SevenZKind::UnixSymlink);
        }
        let native = if entry.is_directory() {
            NativeKind::Directory
        } else {
            NativeKind::File
        };
        let contradiction = |claimed_by| {
            Self::Unsupported(UnsupportedEntry::KindContradiction { native, claimed_by })
        };
        match (mode_type, native) {
            (Some(UnixFileType::Special(special)), _) => {
                return Self::Unsupported(UnsupportedEntry::Special(special));
            }
            (Some(UnixFileType::Undefined(bits)), _) => {
                return Self::Unsupported(UnsupportedEntry::UndefinedType(bits));
            }
            (Some(UnixFileType::Regular), NativeKind::Directory)
            | (Some(UnixFileType::Directory), NativeKind::File) => {
                return contradiction(KindSource::UnixMode);
            }
            _ => {}
        }
        if native == NativeKind::File && claims_windows_directory(entry) {
            return contradiction(KindSource::WindowsAttribute);
        }
        Self::Present(match native {
            NativeKind::Directory => SevenZKind::Directory,
            NativeKind::File => SevenZKind::File,
        })
    }

    /// The kind of an entry to extract or list, `None` for an anti item.
    ///
    /// # Errors
    ///
    /// Returns `SecurityViolation` naming `name` for an unsupported entry.
    pub(crate) fn present(self, name: &str) -> Result<Option<SevenZKind>> {
        match self {
            Self::AntiItem => Ok(None),
            Self::Present(kind) => Ok(Some(kind)),
            Self::Unsupported(unsupported) => Err(unsupported.refusal(name)),
        }
    }
}

impl SevenZKind {
    /// How the root-entry rule sees this entry.
    pub(crate) const fn node_kind(self) -> NodeKind {
        match self {
            Self::Directory => NodeKind::Directory,
            Self::File | Self::ReparsePoint | Self::UnixSymlink => NodeKind::NonDirectory,
        }
    }

    /// The entry type `list` and `verify` report.
    pub(crate) const fn manifest_type(self) -> ManifestEntryType {
        match self {
            Self::File => ManifestEntryType::File,
            Self::Directory => ManifestEntryType::Directory,
            Self::ReparsePoint | Self::UnixSymlink => ManifestEntryType::Symlink,
        }
    }
}

/// The refusal for a Windows reparse point, which has no readable target.
pub(super) fn reparse_point_refusal(name: &str) -> ArchiveError {
    ArchiveError::violation(format!(
        "symlink detected in 7z archive: {name} (Windows reparse point attribute set). \
             Its target cannot be read due to sevenz-rust2 API limitations."
    ))
}

/// Stashes `error` for the caller to return as is and gives the error that ends
/// the sevenz-rust2 entry loop, which would otherwise reclassify it from its
/// message text.
pub(super) fn abort_with(
    pending_error: &mut Option<ArchiveError>,
    error: ArchiveError,
) -> sevenz_rust2::Error {
    *pending_error = Some(error);
    sevenz_rust2::Error::Other("extraction aborted by security policy".into())
}

/// Checks if Windows attributes indicate a reparse point (symlink/junction).
///
/// Only detects links recorded through the Windows attribute; Unix-mode
/// symlinks are detected by [`unix_file_type`].
///
/// Reference: <https://learn.microsoft.com/en-us/windows/win32/fileio/file-attribute-constants>
pub(super) fn is_windows_reparse_point(entry: &sevenz_rust2::ArchiveEntry) -> bool {
    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;

    entry.has_windows_attributes && (entry.windows_attributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0
}

/// Reads the file type of the Unix mode p7zip keeps in the high 16 bits of the
/// attributes, `None` when the entry carries no Unix mode or no type bits.
pub(super) fn unix_file_type(entry: &sevenz_rust2::ArchiveEntry) -> Option<common::UnixFileType> {
    const UNIX_EXTENSION: u32 = 0x8000;

    (entry.has_windows_attributes && entry.windows_attributes & UNIX_EXTENSION != 0)
        .then(|| common::UnixFileType::from_mode(entry.windows_attributes >> 16))
        .flatten()
}

/// Checks whether the Windows attributes claim a directory.
pub(super) fn claims_windows_directory(entry: &sevenz_rust2::ArchiveEntry) -> bool {
    const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0000_0010;

    entry.has_windows_attributes && entry.windows_attributes & FILE_ATTRIBUTE_DIRECTORY != 0
}

//! Typed refusals for TAR headers that different TAR readers resolve
//! differently.

use crate::closed_enum::closed_enum;
use crate::formats::tar_extension_headers::MAX_PAX_RECORD_BYTES;

closed_enum! {
    /// A numeric header field that must be plain.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::TarHeaderField;
    ///
    /// assert_eq!(TarHeaderField::Checksum.to_string(), "checksum");
    /// ```
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    #[non_exhaustive]
    pub enum TarHeaderField {
        /// The `size` field.
        Size => "size",
        /// The `chksum` field.
        Checksum => "checksum",
    }
}

closed_enum! {
    /// A TAR entry type that has no data and must not declare a payload.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::TarNonRegularKind;
    ///
    /// assert_eq!(TarNonRegularKind::Hardlink.to_string(), "Hardlink");
    /// ```
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    #[non_exhaustive]
    pub enum TarNonRegularKind {
        /// A directory entry (`5`).
        Directory => "Directory",
        /// A symbolic link entry (`2`).
        Symlink => "Symlink",
        /// A hard link entry (`1`).
        Hardlink => "Hardlink",
    }
}

impl TarNonRegularKind {
    /// The kind of `entry_type`, or `None` for a type that may carry data.
    pub(crate) const fn of(entry_type: tar::EntryType) -> Option<Self> {
        match entry_type {
            tar::EntryType::Directory => Some(Self::Directory),
            tar::EntryType::Symlink => Some(Self::Symlink),
            tar::EntryType::Link => Some(Self::Hardlink),
            _ => None,
        }
    }
}

/// An extension header whose body the `tar` crate merges into the next entry.
///
/// # Examples
///
/// ```
/// use exarch_core::TarExtensionKind;
///
/// assert_eq!(TarExtensionKind::Pax.typeflag(), b'x');
/// assert_eq!(TarExtensionKind::LongName.to_string(), "GNU long name");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TarExtensionKind {
    /// A local PAX header (`x`).
    Pax,
    /// A GNU long name record (`L`).
    LongName,
    /// A GNU long link record (`K`).
    LongLink,
}

impl TarExtensionKind {
    /// The typeflag byte that introduces this kind of header.
    #[must_use]
    pub const fn typeflag(self) -> u8 {
        match self {
            Self::Pax => b'x',
            Self::LongName => b'L',
            Self::LongLink => b'K',
        }
    }

    const fn name(self) -> &'static str {
        match self {
            Self::Pax => "PAX",
            Self::LongName => "GNU long name",
            Self::LongLink => "GNU long link",
        }
    }

    const fn entry_type_name(self) -> &'static str {
        match self {
            Self::Pax => "XHeader",
            Self::LongName => "GNULongName",
            Self::LongLink => "GNULongLink",
        }
    }
}

impl std::fmt::Display for TarExtensionKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.name())
    }
}

/// The path-like PAX key that a GNU long record duplicates.
///
/// # Examples
///
/// ```
/// use exarch_core::TarPathKey;
///
/// assert_eq!(TarPathKey::LinkPath.to_string(), "linkpath");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum TarPathKey {
    /// The `path` key, which a GNU long name record also describes.
    Path,
    /// The `linkpath` key, which a GNU long link record also describes.
    LinkPath,
}

impl TarPathKey {
    /// The key as a PAX record spells it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Path => "path",
            Self::LinkPath => "linkpath",
        }
    }

    const fn long_record(self) -> &'static str {
        match self {
            Self::Path => "name",
            Self::LinkPath => "link",
        }
    }
}

impl std::fmt::Display for TarPathKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A TAR header or extension-header construct that readers such as `bsdtar`
/// and Python `tarfile` resolve differently from the `tar` crate.
///
/// The `String` payloads named `key` are the record key decoded lossily and
/// truncated to 256 bytes. The `path` payloads are the entry path decoded
/// lossily and not truncated. Both exist for display only: never compare them
/// with a real key or path.
///
/// # Examples
///
/// ```
/// use exarch_core::ArchiveError;
/// use exarch_core::TarAmbiguity;
///
/// let err = ArchiveError::TarAmbiguity(TarAmbiguity::ChecksumMismatch);
/// assert_eq!(
///     err.to_string(),
///     "invalid archive: ambiguous TAR header: header checksum does not match the header bytes"
/// );
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum TarAmbiguity {
    /// A PAX record is not a well-formed `"<len> <key>=<value>\n"` record.
    MalformedRecord,

    /// A PAX record has an empty key.
    EmptyKey,

    /// A PAX record is longer than the 999999 bytes `libarchive` accepts.
    OversizedRecord {
        /// Lossy, truncated key; for display only.
        key: String,
    },

    /// A PAX header repeats a key, so readers disagree on which value wins.
    DuplicateRecord {
        /// Lossy, truncated key; for display only.
        key: String,
    },

    /// A PAX record (`GNU.sparse.*`, `SCHILY.realsize`) changes how the entry
    /// data is read, which not every reader supports.
    UnsupportedRecord {
        /// Lossy, truncated key; for display only.
        key: String,
    },

    /// A PAX `size` record is not a decimal number.
    InvalidSize,

    /// A global PAX header carries `path`, `linkpath` or `size`, which some
    /// readers apply to every later entry.
    GlobalOverride {
        /// Lossy, truncated key; for display only.
        key: String,
    },

    /// A global PAX header is larger than the metadata limit.
    GlobalTooLarge {
        /// Declared size of the header body.
        size: u64,
        /// Configured metadata limit.
        limit: u64,
    },

    /// A global PAX header follows a local PAX header.
    LocalBeforeGlobal,

    /// A global PAX header follows a GNU long name or link record.
    LongRecordBeforeGlobal,

    /// A PAX record and a GNU long record both describe the same entry.
    StackedLongRecord {
        /// The PAX key that the GNU long record duplicates.
        key: TarPathKey,
    },

    /// An `x`, `L` or `K` header without a ustar or GNU magic.
    UnrecognizedHeader {
        /// The kind of extension header.
        kind: TarExtensionKind,
    },

    /// A GNU sparse entry.
    SparseEntry,

    /// A header field is not a plain octal or base-256 number.
    NonCanonicalNumber {
        /// The offending field.
        field: TarHeaderField,
    },

    /// A header has a `prefix` field but no ustar magic.
    PrefixWithoutUstar,

    /// The header checksum does not match the header bytes.
    ChecksumMismatch,

    /// An entry is preceded by two extension headers of the same kind.
    DuplicateExtensionHeader {
        /// The repeated kind.
        kind: TarExtensionKind,
    },

    /// The bytes read before an entry do not end at the position of its
    /// header.
    WindowMismatch,

    /// The padding after an extension header body holds non-zero bytes, which
    /// some readers parse as further records.
    NonZeroPadding,

    /// A GNU long name or link body is not a single NUL-terminated string.
    MalformedLongRecord {
        /// The kind of extension header.
        kind: TarExtensionKind,
    },

    /// A directory, symbolic link or hard link entry declares a payload, which
    /// some readers skip as data and others parse as further headers.
    NonRegularPayload {
        /// The entry type.
        kind: TarNonRegularKind,
        /// Declared payload size in bytes.
        size: u64,
        /// Lossy entry path; for display only.
        path: String,
    },

    /// A regular entry whose name ends in `/` declares a payload, so it is a
    /// directory to some readers and a file to others.
    DirectoryNamedPayload {
        /// Declared payload size in bytes.
        size: u64,
        /// Lossy entry path; for display only.
        path: String,
    },
}

impl std::fmt::Display for TarAmbiguity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MalformedRecord => f.write_str("malformed PAX record"),
            Self::EmptyKey => f.write_str("PAX record with an empty key"),
            Self::OversizedRecord { key } => write!(
                f,
                "PAX record {key:?} is longer than {MAX_PAX_RECORD_BYTES} bytes"
            ),
            Self::DuplicateRecord { key } => write!(f, "duplicate PAX record {key:?}"),
            Self::UnsupportedRecord { key } => write!(f, "PAX record {key:?} is not supported"),
            Self::InvalidSize => f.write_str("PAX `size` record is not a decimal number"),
            Self::GlobalOverride { key } => {
                write!(f, "global PAX record {key:?} would apply to later entries")
            }
            Self::GlobalTooLarge { size, limit } => write!(
                f,
                "global PAX header ({size} bytes) exceeds the metadata limit of {limit} bytes"
            ),
            Self::LocalBeforeGlobal => f.write_str("global PAX header follows a local PAX header"),
            Self::LongRecordBeforeGlobal => {
                f.write_str("global PAX header follows a GNU long name or link record")
            }
            Self::StackedLongRecord { key } => write!(
                f,
                "PAX `{key}` record and a GNU long {} record both describe the same entry",
                key.long_record()
            ),
            Self::UnrecognizedHeader { kind } => write!(
                f,
                "extension header {} lacks a ustar or GNU magic",
                kind.entry_type_name()
            ),
            Self::SparseEntry => f.write_str("GNU sparse entries are not supported"),
            Self::NonCanonicalNumber { field } => write!(
                f,
                "header {field} field is not a plain octal or base-256 number"
            ),
            Self::PrefixWithoutUstar => {
                f.write_str("header carries a prefix field without a ustar magic")
            }
            Self::ChecksumMismatch => {
                f.write_str("header checksum does not match the header bytes")
            }
            Self::DuplicateExtensionHeader { kind } => {
                write!(f, "duplicate {kind} extension header")
            }
            Self::NonZeroPadding => {
                f.write_str("extension header body is followed by non-zero padding")
            }
            Self::MalformedLongRecord { kind } => {
                write!(
                    f,
                    "{kind} extension header is not a single NUL-terminated string"
                )
            }
            Self::WindowMismatch => {
                f.write_str("bytes read before the entry do not match the position of its header")
            }
            Self::NonRegularPayload { kind, size, path } => {
                write!(f, "{kind} entry declares a {size} byte payload: {path}")
            }
            Self::DirectoryNamedPayload { size, path } => {
                write!(
                    f,
                    "file entry with a directory name carries {size} bytes: {path}"
                )
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn payload_messages_are_pinned() {
        let directory = TarAmbiguity::NonRegularPayload {
            kind: TarNonRegularKind::Directory,
            size: 1024,
            path: "x/".into(),
        };
        assert_eq!(
            directory.to_string(),
            "Directory entry declares a 1024 byte payload: x/"
        );
        let named = TarAmbiguity::DirectoryNamedPayload {
            size: 3,
            path: "d/".into(),
        };
        let hardlink = TarAmbiguity::NonRegularPayload {
            kind: TarNonRegularKind::Hardlink,
            size: 2,
            path: "l".into(),
        };
        assert_eq!(
            hardlink.to_string(),
            "Hardlink entry declares a 2 byte payload: l"
        );
        assert_eq!(
            named.to_string(),
            "file entry with a directory name carries 3 bytes: d/"
        );
    }

    #[test]
    fn extension_kind_messages_are_pinned() {
        let cases = [
            (TarExtensionKind::Pax, "PAX", "XHeader"),
            (TarExtensionKind::LongName, "GNU long name", "GNULongName"),
            (TarExtensionKind::LongLink, "GNU long link", "GNULongLink"),
        ];
        for (kind, name, entry_type) in cases {
            assert_eq!(kind.to_string(), name);
            assert_eq!(
                TarAmbiguity::DuplicateExtensionHeader { kind }.to_string(),
                format!("duplicate {name} extension header")
            );
            assert_eq!(
                TarAmbiguity::MalformedLongRecord { kind }.to_string(),
                format!("{name} extension header is not a single NUL-terminated string")
            );
            assert_eq!(
                TarAmbiguity::UnrecognizedHeader { kind }.to_string(),
                format!("extension header {entry_type} lacks a ustar or GNU magic")
            );
        }
    }
}

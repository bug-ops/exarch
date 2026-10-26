//! Typed findings for ZIP archives whose structure is read differently by
//! different ZIP readers.

use crate::closed_enum::closed_enum;

macro_rules! index_newtype {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(usize);

        impl $name {
            /// Wraps a raw index.
            #[must_use]
            pub const fn new(index: usize) -> Self {
                Self(index)
            }

            /// Returns the raw index.
            #[must_use]
            pub const fn get(self) -> usize {
                self.0
            }
        }

        impl ::std::fmt::Display for $name {
            fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                ::std::fmt::Display::fmt(&self.0, f)
            }
        }
    };
}

index_newtype! {
    /// Index of an entry in the `zip` crate's entry map, which equals its
    /// position in the manifest listing.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::ZipEntryIndex;
    ///
    /// assert_eq!(ZipEntryIndex::new(3).get(), 3);
    /// ```
    ZipEntryIndex
}

index_newtype! {
    /// Position of a record in the raw central directory, counting records
    /// that the `zip` crate collapsed because they share a name.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::CentralRecordOrdinal;
    ///
    /// assert_eq!(CentralRecordOrdinal::new(1).to_string(), "1");
    /// ```
    CentralRecordOrdinal
}

closed_enum! {
    /// Header field in which a ZIP local header disagrees with its central
    /// directory record.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::ZipHeaderField;
    ///
    /// assert_eq!(ZipHeaderField::FileName.to_string(), "file name");
    /// ```
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    #[non_exhaustive]
    pub enum ZipHeaderField {
        /// File name
        FileName => "file name",

        /// Unicode Path extra field
        UnicodePath => "unicode path",

        /// Compression method
        CompressionMethod => "compression method",

        /// Encryption flag
        EncryptionFlag => "encryption flag",

        /// Data descriptor flag
        DataDescriptorFlag => "data descriptor flag",

        /// Modification time
        ModifiedTime => "modification time",

        /// CRC-32
        Crc32 => "crc32",

        /// Compressed size
        CompressedSize => "compressed size",

        /// Uncompressed size
        UncompressedSize => "uncompressed size",
    }
}

closed_enum! {
    /// Why a ZIP local header could not be compared with its central
    /// directory record.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::ZipUncomparable;
    ///
    /// assert_eq!(ZipUncomparable::Unparseable.to_string(), "unparseable local header");
    /// ```
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    #[non_exhaustive]
    pub enum ZipUncomparable {
        /// The `zip` crate reported a failed check this version does not know
        Unrecognized => "unrecognized field",

        /// The local header could not be parsed
        Unparseable => "unparseable local header",
    }
}

closed_enum! {
    /// Part of a ZIP file in which an unmapped local header was found.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::HiddenRegion;
    ///
    /// assert_eq!(HiddenRegion::Prefix.to_string(), "before the archive start");
    /// ```
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    #[non_exhaustive]
    pub enum HiddenRegion {
        /// Bytes before the archive start, such as a self-extractor stub
        Prefix => "before the archive start",

        /// Bytes between entries or before the central directory
        Gap => "between entries",

        /// Bytes behind the end of the compressed stream of a data-descriptor
        /// entry, inside the range its central directory record declares
        DescriptorTail => "inside the range of a data-descriptor entry",
    }
}

closed_enum! {
    /// Kind of end record found before an entry.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::EndRecordKind;
    ///
    /// assert_eq!(
    ///     EndRecordKind::Zip64.to_string(),
    ///     "ZIP64 end of central directory record"
    /// );
    /// ```
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    #[non_exhaustive]
    pub enum EndRecordKind {
        /// End of central directory record
        Classic => "end of central directory record",

        /// ZIP64 end of central directory record
        Zip64 => "ZIP64 end of central directory record",
    }
}

/// A structural finding that makes a ZIP archive ambiguous between readers.
///
/// Names are the raw central directory bytes decoded lossily; the `zip`
/// crate's own key can differ after Unicode Path substitution.
///
/// # Examples
///
/// ```
/// use exarch_core::CentralRecordOrdinal;
/// use exarch_core::ZipInconsistency;
///
/// let finding = ZipInconsistency::DuplicateName {
///     record: CentralRecordOrdinal::new(1),
///     name: "a.txt".to_string(),
/// };
/// assert_eq!(
///     finding.to_string(),
///     "duplicate entry name \"a.txt\" (record 1)"
/// );
/// ```
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ZipInconsistency {
    /// A local header disagrees with its central directory record.
    HeaderMismatch {
        /// Entry in the crate's entry map.
        entry: ZipEntryIndex,
        /// Field that differs.
        field: ZipHeaderField,
        /// Central directory name of the entry.
        name: String,
    },

    /// A local header could not be compared with its central directory
    /// record, so a disagreement between them cannot be ruled out.
    HeaderUncomparable {
        /// Entry in the crate's entry map.
        entry: ZipEntryIndex,
        /// Central directory name of the entry.
        name: String,
        /// Why the comparison was not possible.
        reason: ZipUncomparable,
    },

    /// Two or more central directory records share a name.
    DuplicateName {
        /// Position in the raw central directory of a record that the `zip`
        /// crate collapsed into a later record with the same name.
        record: CentralRecordOrdinal,
        /// Shared name.
        name: String,
    },

    /// Entry data ranges intersect.
    OverlappingEntries,

    /// A local header exists that no central directory record maps.
    HiddenLocalHeader {
        /// Absolute offset of the unmapped header.
        offset: u64,
        /// Part of the file the header was found in.
        region: HiddenRegion,
    },

    /// An end of central directory record other than the one the reader used
    /// follows it, so a reader that picks another candidate sees another
    /// directory.
    IgnoredEndRecord {
        /// Absolute offset of the ignored record.
        offset: u64,
    },

    /// A central directory record sits outside the central directory, in the
    /// bytes before the first entry or between entries, so a streaming reader
    /// that stops listing at the first central record never sees the entries
    /// after it.
    StrayCentralRecord {
        /// Absolute offset of the stray record.
        offset: u64,
    },

    /// An end record signature sits in the bytes before the first entry or
    /// between entries, so a streaming reader that stops listing at it never
    /// sees the entries after it.
    StrayEndRecord {
        /// Absolute offset of the stray record.
        offset: u64,
        /// Kind of end record the signature starts.
        kind: EndRecordKind,
    },

    /// A data descriptor makes a streaming reader resume past the next entry
    /// header, so it skips or misreads that entry.
    DescriptorOverrun {
        /// Entry whose descriptor is misread.
        entry: ZipEntryIndex,
        /// Absolute offset where the entry's data ends and the descriptor
        /// starts.
        offset: u64,
    },

    /// An `xl` extra field, in the local header or the central record, gives
    /// an entry a file type that differs from the one its central attributes
    /// give, so a reader that honours the field extracts another kind of entry
    /// than one that follows the attributes.
    XlTypeDivergence {
        /// Entry whose types differ.
        entry: ZipEntryIndex,
        /// Absolute offset of the entry's local header.
        offset: u64,
    },

    /// The central directory holds more records than its end record counts.
    UncountedCentralRecords {
        /// Count claimed by the end of central directory record.
        counted: usize,
        /// Records actually present.
        found: usize,
    },
}

impl std::fmt::Display for ZipInconsistency {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::HeaderMismatch { entry, field, name } => write!(
                f,
                "local header disagrees with central directory on {field} for entry {entry} \
                 ({name:?})"
            ),
            Self::HeaderUncomparable {
                entry,
                name,
                reason,
            } => match reason {
                ZipUncomparable::Unparseable => write!(
                    f,
                    "local header of entry {entry} ({name:?}) cannot be parsed, so it cannot be \
                     compared with the central directory"
                ),
                ZipUncomparable::Unrecognized => write!(
                    f,
                    "local header of entry {entry} ({name:?}) fails the header consistency check \
                     in a way this version does not recognize"
                ),
            },
            Self::DuplicateName { record, name } => {
                write!(f, "duplicate entry name {name:?} (record {record})")
            }
            Self::OverlappingEntries => f.write_str("entry data ranges overlap"),
            Self::HiddenLocalHeader { offset, region } => write!(
                f,
                "local header at offset {offset} ({region}) is not in the central directory"
            ),
            Self::IgnoredEndRecord { offset } => write!(
                f,
                "end of central directory record at offset {offset} is ignored by the reader"
            ),
            Self::StrayCentralRecord { offset } => write!(
                f,
                "central directory record outside the central directory at offset {offset}"
            ),
            Self::StrayEndRecord { offset, kind } => {
                write!(f, "{kind} before an entry, at offset {offset}")
            }
            Self::DescriptorOverrun { entry, offset } => write!(
                f,
                "data descriptor of entry {entry} at offset {offset} makes a streaming reader \
                 resume past the next entry"
            ),
            Self::XlTypeDivergence { entry, offset } => write!(
                f,
                "an xl extra field of entry {entry} (local header at offset {offset}) gives it a \
                 file type that the central directory attributes do not"
            ),
            Self::UncountedCentralRecords { counted, found } => write!(
                f,
                "central directory holds {found} records but the end record counts {counted}"
            ),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mismatch(field: ZipHeaderField) -> String {
        ZipInconsistency::HeaderMismatch {
            entry: ZipEntryIndex::new(2),
            field,
            name: "a.txt".into(),
        }
        .to_string()
    }

    #[test]
    fn mismatch_message_names_the_field() {
        assert_eq!(
            mismatch(ZipHeaderField::Crc32),
            "local header disagrees with central directory on crc32 for entry 2 (\"a.txt\")"
        );
    }

    #[test]
    fn unparseable_and_unrecognized_get_their_own_wording() {
        let uncomparable = |reason| {
            ZipInconsistency::HeaderUncomparable {
                entry: ZipEntryIndex::new(2),
                name: "a.txt".into(),
                reason,
            }
            .to_string()
        };
        assert_eq!(
            uncomparable(ZipUncomparable::Unparseable),
            "local header of entry 2 (\"a.txt\") cannot be parsed, so it cannot be compared \
             with the central directory"
        );
        assert_eq!(
            uncomparable(ZipUncomparable::Unrecognized),
            "local header of entry 2 (\"a.txt\") fails the header consistency check in a way \
             this version does not recognize"
        );
    }

    #[test]
    fn findings_render_their_positions() {
        assert_eq!(
            ZipInconsistency::HiddenLocalHeader {
                offset: 45,
                region: HiddenRegion::Gap
            }
            .to_string(),
            "local header at offset 45 (between entries) is not in the central directory"
        );
        assert_eq!(
            ZipInconsistency::IgnoredEndRecord { offset: 7 }.to_string(),
            "end of central directory record at offset 7 is ignored by the reader"
        );
        assert_eq!(
            ZipInconsistency::StrayCentralRecord { offset: 9 }.to_string(),
            "central directory record outside the central directory at offset 9"
        );
        assert_eq!(
            ZipInconsistency::StrayEndRecord {
                offset: 11,
                kind: EndRecordKind::Zip64
            }
            .to_string(),
            "ZIP64 end of central directory record before an entry, at offset 11"
        );
        assert_eq!(
            ZipInconsistency::DescriptorOverrun {
                entry: ZipEntryIndex::new(2),
                offset: 70
            }
            .to_string(),
            "data descriptor of entry 2 at offset 70 makes a streaming reader resume past the \
             next entry"
        );
        assert_eq!(
            ZipInconsistency::XlTypeDivergence {
                entry: ZipEntryIndex::new(2),
                offset: 70
            }
            .to_string(),
            "an xl extra field of entry 2 (local header at offset 70) gives it a file type \
             that the central directory attributes do not"
        );
        assert_eq!(
            ZipInconsistency::UncountedCentralRecords {
                counted: 1,
                found: 2
            }
            .to_string(),
            "central directory holds 2 records but the end record counts 1"
        );
    }
}

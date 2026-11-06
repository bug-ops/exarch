//! Archive format detection.

use std::path::Path;
use std::str::FromStr;

use crate::ArchiveError;
use crate::ConfigProblem;
use crate::ConfigSetting;
use crate::Result;
use crate::closed_enum::ClosedEnum;
use crate::closed_enum::closed_enum;
use crate::formats::compression::CompressionCodec;
use crate::formats::sevenz::SEVENZ_MAGIC;

/// Number of bytes to read for magic-byte detection: one full TAR header block,
/// so the USTAR signature at offset 257 and the checksum field at 148 are both
/// available. All other signatures fit within the first 6 bytes.
const MAGIC_READ_LEN: usize = 512;

const TAR_BLOCK_LEN: usize = 512;
const USTAR_MAGIC_OFFSET: usize = 257;
const TAR_CKSUM_FIELD: std::ops::Range<usize> = 148..156;

/// Magic byte signatures for each supported archive format.
///
/// Each entry is `(offset, signature, ArchiveType)`.
///
/// ZIP has three recognized openers: local-file header (`PK\x03\x04`), EOCD
/// (`PK\x05\x06` — valid empty ZIP), and split-archive marker (`PK\x07\x08`).
const MAGIC_SIGNATURES: &[(usize, &[u8], ArchiveType)] = &[
    (0, b"\x1f\x8b", ArchiveType::TarGz),
    (0, b"\x28\xb5\x2f\xfd", ArchiveType::TarZst),
    (0, b"\x42\x5a\x68", ArchiveType::TarBz2),
    (0, b"\x50\x4b\x03\x04", ArchiveType::Zip),
    (0, b"\x50\x4b\x05\x06", ArchiveType::Zip),
    (0, b"\x50\x4b\x07\x08", ArchiveType::Zip),
    (0, &SEVENZ_MAGIC, ArchiveType::SevenZ),
    (0, b"\xfd\x37\x7a\x58\x5a\x00", ArchiveType::TarXz),
    (257, b"ustar", ArchiveType::Tar),
];

/// File extensions that wrap a ZIP container with extra structure.
///
/// Signing, manifests, and ordering rules sit on top of the ZIP bytes
/// for these formats. Extraction treats them as ZIP; creation is
/// rejected separately in `api::reject_zip_family_creation`. Kept as a
/// single source of truth so the two call sites don't drift.
pub const ZIP_FAMILY_ALIASES: &[&str] = &[
    "jar", "war", "ear", "nar", "nbm", "apk", "aab", "ipa", "appx", "msix", "whl", "vsix", "xpi",
    "epub",
];

/// Returns true if `ext` (case-insensitive) names a ZIP-family alias.
/// Plain `.zip` is deliberately *not* included - callers can test it
/// separately when they need to distinguish "bare ZIP" from "ZIP under
/// another name".
pub(crate) fn is_zip_family_alias(ext: &str) -> bool {
    ZIP_FAMILY_ALIASES
        .iter()
        .any(|alias| ext.eq_ignore_ascii_case(alias))
}

closed_enum! {
    /// Supported archive formats.
    ///
    /// `#[non_exhaustive]` so support for a new archive format is not a
    /// breaking change for downstream matches.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    #[non_exhaustive]
    pub enum ArchiveType {
        /// Tar archive (uncompressed).
        Tar => "Tar",
        /// Gzip-compressed tar archive.
        TarGz => "TarGz",
        /// Bzip2-compressed tar archive.
        TarBz2 => "TarBz2",
        /// XZ-compressed tar archive.
        TarXz => "TarXz",
        /// Zstd-compressed tar archive.
        TarZst => "TarZst",
        /// ZIP archive.
        Zip => "Zip",
        /// 7z archive.
        SevenZ => "SevenZ",
    }
}

closed_enum! {
    /// Archive formats exarch can create.
    ///
    /// The subset of [`ArchiveType`] with a writer: 7z can be read but not
    /// created, so it is absent here and a creation API cannot be asked for it.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::ArchiveType;
    /// use exarch_core::CreatableFormat;
    ///
    /// assert_eq!(ArchiveType::from(CreatableFormat::TarGz), ArchiveType::TarGz);
    /// assert_eq!(
    ///     CreatableFormat::try_from(ArchiveType::Zip).unwrap(),
    ///     CreatableFormat::Zip
    /// );
    /// assert!(CreatableFormat::try_from(ArchiveType::SevenZ).is_err());
    /// ```
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    #[non_exhaustive]
    pub enum CreatableFormat {
        /// Tar archive (uncompressed).
        Tar => "Tar",
        /// Gzip-compressed tar archive.
        TarGz => "TarGz",
        /// Bzip2-compressed tar archive.
        TarBz2 => "TarBz2",
        /// XZ-compressed tar archive.
        TarXz => "TarXz",
        /// Zstd-compressed tar archive.
        TarZst => "TarZst",
        /// ZIP archive.
        Zip => "Zip",
    }
}

closed_enum! {
    /// Archive formats exarch can read but not create.
    ///
    /// Together with [`CreatableFormat`] it partitions [`ArchiveType`], so a
    /// refusal to create a format names a value that cannot be a creatable one.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::formats::detect::ExtractOnlyFormat;
    ///
    /// assert_eq!(ExtractOnlyFormat::SevenZ.extension(), "7z");
    /// ```
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    #[non_exhaustive]
    pub enum ExtractOnlyFormat {
        /// 7z archive.
        SevenZ => "SevenZ",
    }
}

impl ExtractOnlyFormat {
    /// The canonical file extension, without a leading dot.
    #[must_use]
    pub const fn extension(self) -> &'static str {
        match self {
            Self::SevenZ => "7z",
        }
    }

    fn not_creatable(self) -> ArchiveError {
        ArchiveError::InvalidConfiguration {
            setting: ConfigSetting::CreationFormat,
            problem: ConfigProblem::NotCreatable { format: self },
        }
    }
}

/// How a [`CreatableFormat`] is written: a TAR stream with an optional codec,
/// or a ZIP container.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CreationFamily {
    Tar(Option<CompressionCodec>),
    Zip,
}

impl CreatableFormat {
    /// The TAR format for a stream compressed with `codec`, or plain TAR.
    pub(crate) const fn tar_with(codec: Option<CompressionCodec>) -> Self {
        match codec {
            None => Self::Tar,
            Some(CompressionCodec::Gzip) => Self::TarGz,
            Some(CompressionCodec::Bzip2) => Self::TarBz2,
            Some(CompressionCodec::Xz) => Self::TarXz,
            Some(CompressionCodec::Zstd) => Self::TarZst,
        }
    }

    /// Groups this format by the writer that handles it.
    pub(crate) const fn family(self) -> CreationFamily {
        match self {
            Self::Tar => CreationFamily::Tar(None),
            Self::TarGz => CreationFamily::Tar(Some(CompressionCodec::Gzip)),
            Self::TarBz2 => CreationFamily::Tar(Some(CompressionCodec::Bzip2)),
            Self::TarXz => CreationFamily::Tar(Some(CompressionCodec::Xz)),
            Self::TarZst => CreationFamily::Tar(Some(CompressionCodec::Zstd)),
            Self::Zip => CreationFamily::Zip,
        }
    }
}

impl From<CreatableFormat> for ArchiveType {
    fn from(format: CreatableFormat) -> Self {
        match format {
            CreatableFormat::Tar => Self::Tar,
            CreatableFormat::TarGz => Self::TarGz,
            CreatableFormat::TarBz2 => Self::TarBz2,
            CreatableFormat::TarXz => Self::TarXz,
            CreatableFormat::TarZst => Self::TarZst,
            CreatableFormat::Zip => Self::Zip,
        }
    }
}

impl TryFrom<ArchiveType> for CreatableFormat {
    type Error = ArchiveError;

    /// # Errors
    ///
    /// Returns [`ArchiveError::InvalidConfiguration`] with
    /// [`ConfigProblem::NotCreatable`] for 7z, which cannot be created.
    fn try_from(format: ArchiveType) -> Result<Self> {
        match format {
            ArchiveType::Tar => Ok(Self::Tar),
            ArchiveType::TarGz => Ok(Self::TarGz),
            ArchiveType::TarBz2 => Ok(Self::TarBz2),
            ArchiveType::TarXz => Ok(Self::TarXz),
            ArchiveType::TarZst => Ok(Self::TarZst),
            ArchiveType::Zip => Ok(Self::Zip),
            ArchiveType::SevenZ => Err(ExtractOnlyFormat::SevenZ.not_creatable()),
        }
    }
}

impl FromStr for CreatableFormat {
    type Err = ArchiveError;

    /// Parses the string form shared with [`ArchiveType::as_str`].
    ///
    /// # Errors
    ///
    /// [`ArchiveError::InvalidConfiguration`] naming
    /// [`ConfigSetting::CreationFormat`]: [`ConfigProblem::NotCreatable`] for
    /// the spelling of a format that can only be read, and
    /// [`ConfigProblem::NotOneOf`] listing the creatable formats for any other
    /// string.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::CreatableFormat;
    ///
    /// assert_eq!(
    ///     "Zip".parse::<CreatableFormat>().unwrap(),
    ///     CreatableFormat::Zip
    /// );
    /// let err = "SevenZ".parse::<CreatableFormat>().unwrap_err();
    /// assert_eq!(
    ///     err.to_string(),
    ///     "invalid configuration: 7z archive creation is not supported"
    /// );
    /// ```
    fn from_str(value: &str) -> Result<Self> {
        if let Some(format) = ExtractOnlyFormat::ALL
            .iter()
            .find(|format| format.as_str() == value)
        {
            return Err(format.not_creatable());
        }
        <Self as ClosedEnum>::parse_for(ConfigSetting::CreationFormat, value)
    }
}

/// How an [`ArchiveType`] is read: a TAR stream with an optional codec, or a
/// container format with its own handler.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum FormatFamily {
    Tar(Option<CompressionCodec>),
    Seekable(crate::SeekableFormat),
}

impl ArchiveType {
    /// The TAR type for a stream compressed with `codec`, or plain TAR.
    pub(crate) const fn tar_with(codec: Option<CompressionCodec>) -> Self {
        match codec {
            None => Self::Tar,
            Some(CompressionCodec::Gzip) => Self::TarGz,
            Some(CompressionCodec::Bzip2) => Self::TarBz2,
            Some(CompressionCodec::Xz) => Self::TarXz,
            Some(CompressionCodec::Zstd) => Self::TarZst,
        }
    }

    /// The canonical file extension for this type, without a leading dot.
    ///
    /// Extension detection maps the result back to the same type.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::ArchiveType;
    ///
    /// assert_eq!(ArchiveType::TarGz.extension(), "tar.gz");
    /// assert_eq!(ArchiveType::SevenZ.extension(), "7z");
    /// ```
    #[must_use]
    pub const fn extension(self) -> &'static str {
        match self {
            Self::Tar => "tar",
            Self::TarGz => "tar.gz",
            Self::TarBz2 => "tar.bz2",
            Self::TarXz => "tar.xz",
            Self::TarZst => "tar.zst",
            Self::Zip => "zip",
            Self::SevenZ => "7z",
        }
    }

    /// Whether this type is a TAR stream, with or without a compression codec.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::ArchiveType;
    ///
    /// assert!(ArchiveType::TarZst.is_tar());
    /// assert!(!ArchiveType::Zip.is_tar());
    /// ```
    #[must_use]
    pub const fn is_tar(self) -> bool {
        match self.family() {
            FormatFamily::Tar(_) => true,
            FormatFamily::Seekable(_) => false,
        }
    }

    /// Groups this type by the reader that handles it.
    pub(crate) const fn family(self) -> FormatFamily {
        match self {
            Self::Tar => FormatFamily::Tar(None),
            Self::TarGz => FormatFamily::Tar(Some(CompressionCodec::Gzip)),
            Self::TarBz2 => FormatFamily::Tar(Some(CompressionCodec::Bzip2)),
            Self::TarXz => FormatFamily::Tar(Some(CompressionCodec::Xz)),
            Self::TarZst => FormatFamily::Tar(Some(CompressionCodec::Zstd)),
            Self::Zip => FormatFamily::Seekable(crate::SeekableFormat::Zip),
            Self::SevenZ => FormatFamily::Seekable(crate::SeekableFormat::SevenZ),
        }
    }
}

/// Detects the archive type from a file path using two-phase detection.
///
/// This function is for **reading** existing archives. For creating archives,
/// use `detect_format_from_extension` directly so that stale on-disk bytes
/// do not override the user's intended output format.
///
/// **Phase 1 — extension:** maps the file extension to an [`ArchiveType`] using
/// the same rules as before. `.gz` is only accepted when the stem ends with
/// `.tar`, compared case-insensitively (e.g. `archive.tar.gz`,
/// `ARCHIVE.TAR.GZ`); a bare `archive.gz` is not a recognised extension.
///
/// **Phase 2 — magic bytes:** when extension detection fails (unrecognised or
/// missing extension), the function reads up to the first 512 bytes of the file
/// and matches against known magic-byte signatures. If the file is not readable
/// (does not exist, is a directory, I/O error), phase 2 is silently skipped and
/// [`ArchiveError::UnknownFormat`] is returned.
///
/// Additionally, if extension detection succeeds but magic-byte inspection
/// identifies a *different* known format, the magic-byte result takes
/// precedence. This covers the common case where a file was renamed or given
/// the wrong extension.
///
/// **Precedence between signatures:** a ZIP or 7z magic at offset 0 always
/// wins, and so do gzip, xz and zstd magics: no valid UTF-8 member name starts
/// with them, while a gzip header can carry a whole ustar block in its extra
/// field. Only `BZh` can open a member name, so a checksum-valid ustar header
/// whose leading bytes are not a complete bzip2 stream header (`BZh`, a level
/// digit, then the block or end-of-stream marker) is read as a plain TAR. An
/// input that is valid under both readings keeps its compression view, as in
/// bsdtar and `CPython`.
///
/// **Note on compression signatures:** magic-byte detection maps GZ, BZ2, XZ,
/// and Zstd signatures to their `Tar*` variants because those are the only
/// archive-level formats this library handles for those compression schemes.
/// A bare single-file gzip/bz2/xz/zstd stream (not wrapping a tar) will
/// succeed detection but fail at extraction with a tar-parse error. When the
/// file has an unrelated extension (e.g. `.dat`), magic-byte fallback still
/// returns the `Tar*` guess — callers should be aware that
/// compressed-but-not-tar streams will surface errors at decode time rather
/// than at detection.
///
/// # Errors
///
/// Returns [`ArchiveError::UnknownFormat`] when neither phase can determine the
/// format.
pub fn detect_format(path: &Path) -> Result<ArchiveType> {
    let ext_result = detect_format_from_extension(path);

    match ext_result {
        Ok(ext_type) => {
            // Extension matched. Read magic bytes to verify; if they point to
            // a different known format, trust the bytes over the name.
            if let Some(magic_type) = detect_format_from_magic(path)
                && magic_type != ext_type
            {
                return Ok(magic_type);
            }
            Ok(ext_type)
        }
        Err(_) => {
            // Extension gave no conclusive result — fall back to magic bytes.
            detect_format_from_magic(path).ok_or_else(|| ArchiveError::UnknownFormat {
                path: path.to_path_buf(),
            })
        }
    }
}

/// Extension-only detection used for archive **creation**.
///
/// Magic-byte inspection is intentionally skipped here: the output file may not
/// exist yet, or it may contain stale bytes from a previous run that must not
/// override the caller's chosen format.
pub(crate) fn detect_format_from_extension(path: &Path) -> Result<ArchiveType> {
    let extension =
        path.extension()
            .and_then(|e| e.to_str())
            .ok_or_else(|| ArchiveError::UnknownFormat {
                path: path.to_path_buf(),
            })?;

    let ext_lower = extension.to_ascii_lowercase();
    match ext_lower.as_str() {
        "tar" => Ok(ArchiveType::Tar),
        "tgz" => Ok(ArchiveType::TarGz),
        "gz" => {
            if let Some(stem) = path.file_stem()
                && stem
                    .as_encoded_bytes()
                    .last_chunk::<4>()
                    .is_some_and(|tail| tail.eq_ignore_ascii_case(b".tar"))
            {
                Ok(ArchiveType::TarGz)
            } else {
                Err(ArchiveError::UnknownFormat {
                    path: path.to_path_buf(),
                })
            }
        }
        "bz2" | "tbz" | "tbz2" => Ok(ArchiveType::TarBz2),
        "xz" | "txz" => Ok(ArchiveType::TarXz),
        "zst" | "tzst" => Ok(ArchiveType::TarZst),
        "zip" => Ok(ArchiveType::Zip),
        "7z" => Ok(ArchiveType::SevenZ),
        // JVM artifacts, app bundles, Python wheels, IDE/browser
        // extensions, EPUBs - all ZIP under the hood, so they extract
        // through the same path. See `ZIP_FAMILY_ALIASES` for the list.
        ext if is_zip_family_alias(ext) => Ok(ArchiveType::Zip),
        _ => Err(ArchiveError::UnknownFormat {
            path: path.to_path_buf(),
        }),
    }
}

/// Reads up to [`MAGIC_READ_LEN`] bytes from the beginning of `path` and
/// matches them against [`MAGIC_SIGNATURES`].
///
/// Uses a read loop to handle short reads (interrupted syscalls, FUSE mounts,
/// network filesystems) so the USTAR check at offset 257 is always reliable.
///
/// Returns `None` if the file cannot be read or no signature matches.
fn detect_format_from_magic(path: &Path) -> Option<ArchiveType> {
    let mut file = std::fs::File::open(path).ok()?;
    let header = peek_header(&mut file).ok()?;
    match_signature(header.as_slice())
}

/// The leading bytes of a source, as many as [`MAGIC_READ_LEN`] allows.
pub(crate) struct Header {
    buf: [u8; MAGIC_READ_LEN],
    filled: usize,
}

impl Header {
    /// The bytes that were actually read.
    pub(crate) fn as_slice(&self) -> &[u8] {
        &self.buf[..self.filled]
    }
}

/// Reads up to [`MAGIC_READ_LEN`] bytes from `reader`, looping over short
/// reads and `Interrupted` until the buffer is full or the source ends.
///
/// # Errors
///
/// Returns the first read error other than `Interrupted`.
pub(crate) fn peek_header<R: std::io::Read + ?Sized>(reader: &mut R) -> std::io::Result<Header> {
    let mut header = Header {
        buf: [0; MAGIC_READ_LEN],
        filled: 0,
    };
    while header.filled < MAGIC_READ_LEN {
        match reader.read(&mut header.buf[header.filled..]) {
            Ok(0) => break,
            Ok(n) => header.filled += n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e),
        }
    }
    Ok(header)
}

/// Whether `header` opens with a TAR header block: `ustar` at offset 257 and a
/// checksum field that matches the tar reader's own rule (unsigned byte sum
/// with the checksum field counted as spaces).
fn is_ustar_header(header: &[u8]) -> bool {
    let Some(block) = header.first_chunk::<TAR_BLOCK_LEN>() else {
        return false;
    };
    if !block[USTAR_MAGIC_OFFSET..].starts_with(b"ustar") {
        return false;
    }
    let sum: u32 = block
        .iter()
        .enumerate()
        .map(|(i, &b)| {
            if TAR_CKSUM_FIELD.contains(&i) {
                u32::from(b' ')
            } else {
                u32::from(b)
            }
        })
        .sum();
    tar::Header::from_byte_slice(block)
        .cksum()
        .is_ok_and(|stored| stored == sum)
}

/// Whether `header` opens with a complete bzip2 stream header: `BZh`, a level
/// digit, then the first block magic or the end-of-stream marker.
fn is_bzip2_stream_start(header: &[u8]) -> bool {
    const BLOCK_MAGIC: &[u8; 6] = b"1AY&SY";
    const END_MAGIC: &[u8; 6] = &[0x17, 0x72, 0x45, 0x38, 0x50, 0x90];
    header.starts_with(b"BZh")
        && header
            .get(3)
            .is_some_and(|level| (b'1'..=b'9').contains(level))
        && header
            .get(4..10)
            .is_some_and(|marker| marker == BLOCK_MAGIC || marker == END_MAGIC)
}

/// Matches `header` against [`MAGIC_SIGNATURES`]; the first entry in table
/// order wins, so an offset-0 magic beats the `ustar` signature at 257.
///
/// The one exception is a bzip2 magic that is not a complete bzip2 stream
/// header: a checksum-valid ustar header outranks it, because a TAR member name
/// can start with `BZh`. Input valid under both readings, and every other
/// magic, keeps the offset-0 view.
///
/// The one signature table behind path, seekable and streaming detection.
pub(crate) fn match_signature(header: &[u8]) -> Option<ArchiveType> {
    let table_match = MAGIC_SIGNATURES
        .iter()
        .find(|&&(offset, sig, _)| {
            offset
                .checked_add(sig.len())
                .and_then(|end| header.get(offset..end))
                .is_some_and(|window| window == sig)
        })
        .map(|&(_, _, archive_type)| archive_type);
    match table_match {
        Some(ArchiveType::TarBz2) if !is_bzip2_stream_start(header) && is_ustar_header(header) => {
            Some(ArchiveType::Tar)
        }
        _ => table_match,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::assert_matches;
    use std::path::PathBuf;

    #[test]
    fn a_creatable_format_parses_from_its_name() {
        for &format in CreatableFormat::ALL {
            assert_eq!(format.as_str().parse::<CreatableFormat>().unwrap(), format);
        }
    }

    #[test]
    fn an_unknown_creation_format_lists_the_creatable_formats_only() {
        for text in ["zip", "ZIP", "tar.gz", "bogus", "", "7z"] {
            let err = text.parse::<CreatableFormat>().unwrap_err();
            assert_eq!(
                err.to_string(),
                "invalid configuration: creation format is not one of the allowed values: \
                 Tar, TarGz, TarBz2, TarXz, TarZst, Zip",
                "{text:?}"
            );
        }
    }

    #[test]
    fn an_extract_only_format_is_not_creatable() {
        let from_name = "SevenZ".parse::<CreatableFormat>().unwrap_err();
        let from_type = CreatableFormat::try_from(ArchiveType::SevenZ).unwrap_err();
        for err in [from_name, from_type] {
            assert_matches!(
                err,
                ArchiveError::InvalidConfiguration {
                    setting: ConfigSetting::CreationFormat,
                    problem: ConfigProblem::NotCreatable {
                        format: ExtractOnlyFormat::SevenZ
                    },
                }
            );
        }
    }

    #[test]
    fn creatable_and_extract_only_formats_partition_the_archive_types() {
        let mut names: Vec<&str> = CreatableFormat::NAMES
            .iter()
            .chain(ExtractOnlyFormat::NAMES)
            .copied()
            .collect();
        names.sort_unstable();
        let mut all: Vec<&str> = ArchiveType::NAMES.to_vec();
        all.sort_unstable();
        assert_eq!(names, all);
    }

    #[test]
    fn test_archive_type_as_str_matches_display_and_is_unique() {
        let names: Vec<&str> = ArchiveType::ALL.iter().map(|t| t.as_str()).collect();
        assert_eq!(
            names,
            ["Tar", "TarGz", "TarBz2", "TarXz", "TarZst", "Zip", "SevenZ"]
        );
        for t in ArchiveType::ALL {
            assert_eq!(t.to_string(), t.as_str());
        }
    }

    #[test]
    fn test_archive_type_extension_round_trips_through_detection() {
        for &t in ArchiveType::ALL {
            let name = format!("archive.{}", t.extension());
            assert_eq!(detect_format_from_extension(Path::new(&name)).unwrap(), t);
        }
    }

    #[test]
    fn test_creatable_format_round_trips_through_archive_type() {
        for &format in CreatableFormat::ALL {
            let archive_type = ArchiveType::from(format);
            assert_eq!(CreatableFormat::try_from(archive_type).unwrap(), format);
            assert_eq!(archive_type.as_str(), format.as_str());
        }
        assert_eq!(CreatableFormat::ALL.len(), ArchiveType::ALL.len() - 1);
        assert_matches!(
            CreatableFormat::try_from(ArchiveType::SevenZ),
            Err(ArchiveError::InvalidConfiguration { .. })
        );
    }

    #[test]
    fn test_family_maps_tar_codecs() {
        assert_eq!(ArchiveType::Tar.family(), FormatFamily::Tar(None));
        assert_eq!(
            ArchiveType::TarGz.family(),
            FormatFamily::Tar(Some(CompressionCodec::Gzip))
        );
        assert_eq!(
            ArchiveType::TarBz2.family(),
            FormatFamily::Tar(Some(CompressionCodec::Bzip2))
        );
        assert_eq!(
            ArchiveType::TarXz.family(),
            FormatFamily::Tar(Some(CompressionCodec::Xz))
        );
        assert_eq!(
            ArchiveType::TarZst.family(),
            FormatFamily::Tar(Some(CompressionCodec::Zstd))
        );
        assert_eq!(
            ArchiveType::Zip.family(),
            FormatFamily::Seekable(crate::SeekableFormat::Zip)
        );
        assert_eq!(
            ArchiveType::SevenZ.family(),
            FormatFamily::Seekable(crate::SeekableFormat::SevenZ)
        );
    }

    #[test]
    fn test_detect_tar() {
        let path = PathBuf::from("archive.tar");
        assert_eq!(detect_format(&path).unwrap(), ArchiveType::Tar);
    }

    #[test]
    fn test_detect_tar_gz_still_works() {
        let path = PathBuf::from("archive.tar.gz");
        assert_eq!(detect_format(&path).unwrap(), ArchiveType::TarGz);

        let path2 = PathBuf::from("archive.tgz");
        assert_eq!(detect_format(&path2).unwrap(), ArchiveType::TarGz);
    }

    #[test]
    fn test_detect_tar_gz_stem_is_case_insensitive() {
        for name in ["a.TAR.gz", "a.Tar.GZ", "A.TAR.GZ"] {
            assert_eq!(
                detect_format(&PathBuf::from(name)).unwrap(),
                ArchiveType::TarGz,
                "{name}"
            );
        }
    }

    #[test]
    fn test_detect_bare_dot_tar_gz_still_matches() {
        assert_eq!(
            detect_format_from_extension(Path::new(".tar.gz")).unwrap(),
            ArchiveType::TarGz
        );
    }

    #[test]
    fn test_detect_bare_gz_returns_unknown_format() {
        let path = PathBuf::from("archive.gz");
        assert_matches!(
            detect_format(&path),
            Err(ArchiveError::UnknownFormat { .. })
        );
    }

    #[test]
    fn test_detect_bare_gz_error_carries_path() {
        let path = PathBuf::from("archive.gz");
        let err = detect_format(&path).unwrap_err();
        assert_matches!(
            err,
            ArchiveError::UnknownFormat { path: ref p } if p == &PathBuf::from("archive.gz")
        );
    }

    #[test]
    fn test_detect_tar_bz2() {
        let path = PathBuf::from("archive.tar.bz2");
        assert_eq!(detect_format(&path).unwrap(), ArchiveType::TarBz2);

        let path2 = PathBuf::from("archive.tbz");
        assert_eq!(detect_format(&path2).unwrap(), ArchiveType::TarBz2);

        let path3 = PathBuf::from("archive.tbz2");
        assert_eq!(detect_format(&path3).unwrap(), ArchiveType::TarBz2);
    }

    #[test]
    fn test_detect_tar_xz() {
        let path = PathBuf::from("archive.tar.xz");
        assert_eq!(detect_format(&path).unwrap(), ArchiveType::TarXz);

        let path2 = PathBuf::from("archive.txz");
        assert_eq!(detect_format(&path2).unwrap(), ArchiveType::TarXz);
    }

    #[test]
    fn test_detect_tar_zst() {
        let path = PathBuf::from("archive.tar.zst");
        assert_eq!(detect_format(&path).unwrap(), ArchiveType::TarZst);

        let path2 = PathBuf::from("archive.tzst");
        assert_eq!(detect_format(&path2).unwrap(), ArchiveType::TarZst);
    }

    #[test]
    fn test_detect_zip() {
        let path = PathBuf::from("archive.zip");
        assert_eq!(detect_format(&path).unwrap(), ArchiveType::Zip);
    }

    #[test]
    fn test_detect_zip_family_extensions() {
        // Each of these is a ZIP underneath and should resolve to
        // ArchiveType::Zip so the existing extractor picks it up. Upper-case
        // variants cover Windows-authored filenames. Driving off
        // ZIP_FAMILY_ALIASES keeps the test from drifting if the list changes.
        for ext in ZIP_FAMILY_ALIASES {
            let path = PathBuf::from(format!("archive.{ext}"));
            assert_eq!(
                detect_format(&path).unwrap(),
                ArchiveType::Zip,
                "{ext} should detect as ZIP",
            );

            let upper = PathBuf::from(format!("archive.{}", ext.to_ascii_uppercase()));
            assert_eq!(
                detect_format(&upper).unwrap(),
                ArchiveType::Zip,
                "{ext} uppercase should detect as ZIP",
            );
        }
    }

    #[test]
    fn test_detect_7z() {
        let path = PathBuf::from("archive.7z");
        assert_eq!(detect_format(&path).unwrap(), ArchiveType::SevenZ);
    }

    #[test]
    fn test_detect_7z_case_insensitive() {
        let path = PathBuf::from("ARCHIVE.7Z");
        assert_eq!(detect_format(&path).unwrap(), ArchiveType::SevenZ);

        let path2 = PathBuf::from("Archive.7Z");
        assert_eq!(detect_format(&path2).unwrap(), ArchiveType::SevenZ);
    }

    #[test]
    fn test_detect_unknown_format() {
        let path = PathBuf::from("archive.rar");
        assert_matches!(
            detect_format(&path),
            Err(ArchiveError::UnknownFormat { .. })
        );
    }

    #[test]
    fn test_detect_unknown_format_error_carries_path() {
        let path = PathBuf::from("archive.rar");
        let err = detect_format(&path).unwrap_err();
        assert_matches!(
            err,
            ArchiveError::UnknownFormat { path: ref p } if p == &PathBuf::from("archive.rar")
        );
    }

    #[test]
    fn test_archive_type_sevenz_equality() {
        assert_eq!(ArchiveType::SevenZ, ArchiveType::SevenZ);
        assert_ne!(ArchiveType::SevenZ, ArchiveType::Zip);
    }

    #[test]
    fn test_archive_type_sevenz_debug() {
        let format = ArchiveType::SevenZ;
        let debug_str = format!("{format:?}");
        assert_eq!(debug_str, "SevenZ");
    }

    // --- magic-bytes tests ---

    fn write_magic_file(dir: &tempfile::TempDir, name: &str, header: &[u8]) -> PathBuf {
        let path = dir.path().join(name);
        // Pad to MAGIC_READ_LEN so TAR USTAR offset tests work.
        let mut data = vec![0u8; MAGIC_READ_LEN];
        let n = header.len().min(data.len());
        data[..n].copy_from_slice(&header[..n]);
        std::fs::write(&path, &data).unwrap();
        path
    }

    fn write_magic_file_at_offset(
        dir: &tempfile::TempDir,
        name: &str,
        offset: usize,
        sig: &[u8],
    ) -> PathBuf {
        let path = dir.path().join(name);
        let mut data = vec![0u8; MAGIC_READ_LEN];
        let end = offset + sig.len();
        if end <= data.len() {
            data[offset..end].copy_from_slice(sig);
        }
        std::fs::write(&path, &data).unwrap();
        path
    }

    #[test]
    fn test_magic_zip_no_extension() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_magic_file(&dir, "data", b"\x50\x4b\x03\x04");
        assert_eq!(detect_format(&path).unwrap(), ArchiveType::Zip);
    }

    #[test]
    fn test_magic_gzip_no_extension() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_magic_file(&dir, "data", b"\x1f\x8b\x00");
        assert_eq!(detect_format(&path).unwrap(), ArchiveType::TarGz);
    }

    #[test]
    fn test_magic_bz2_no_extension() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_magic_file(&dir, "data", b"\x42\x5a\x68");
        assert_eq!(detect_format(&path).unwrap(), ArchiveType::TarBz2);
    }

    #[test]
    fn test_magic_xz_no_extension() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_magic_file(&dir, "data", b"\xfd\x37\x7a\x58\x5a\x00");
        assert_eq!(detect_format(&path).unwrap(), ArchiveType::TarXz);
    }

    #[test]
    fn test_magic_zstd_no_extension() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_magic_file(&dir, "data", b"\x28\xb5\x2f\xfd");
        assert_eq!(detect_format(&path).unwrap(), ArchiveType::TarZst);
    }

    #[test]
    fn test_magic_sevenz_no_extension() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_magic_file(&dir, "data", b"\x37\x7a\xbc\xaf\x27\x1c");
        assert_eq!(detect_format(&path).unwrap(), ArchiveType::SevenZ);
    }

    #[test]
    fn test_magic_tar_ustar_no_extension() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_magic_file_at_offset(&dir, "data", 257, b"ustar");
        assert_eq!(detect_format(&path).unwrap(), ArchiveType::Tar);
    }

    #[test]
    fn test_magic_wins_over_wrong_extension() {
        // File named .zip but contains gzip magic bytes.
        let dir = tempfile::tempdir().unwrap();
        let path = write_magic_file(&dir, "archive.zip", b"\x1f\x8b\x00");
        assert_eq!(detect_format(&path).unwrap(), ArchiveType::TarGz);
    }

    #[test]
    fn test_extension_wins_when_no_magic_mismatch() {
        // File named .zip whose first bytes are not a recognised signature —
        // extension result stands.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("archive.zip");
        std::fs::write(&path, b"\x00\x00\x00\x00").unwrap();
        assert_eq!(detect_format(&path).unwrap(), ArchiveType::Zip);
    }

    #[test]
    fn test_nonexistent_file_without_extension_returns_unknown() {
        let path = PathBuf::from("/nonexistent/path/to/archive");
        assert_matches!(
            detect_format(&path),
            Err(ArchiveError::UnknownFormat { .. })
        );
    }

    #[test]
    fn test_nonexistent_file_with_known_extension_uses_extension() {
        // For a nonexistent file the magic-read silently fails, so extension
        // wins.
        let path = PathBuf::from("/nonexistent/archive.zip");
        assert_eq!(detect_format(&path).unwrap(), ArchiveType::Zip);
    }

    // S1: empty ZIP (EOCD magic) and split-archive marker must be detected.
    #[test]
    fn test_magic_empty_zip_eocd_no_extension() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_magic_file(&dir, "empty", b"\x50\x4b\x05\x06");
        assert_eq!(detect_format(&path).unwrap(), ArchiveType::Zip);
    }

    #[test]
    fn test_magic_split_zip_no_extension() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_magic_file(&dir, "split", b"\x50\x4b\x07\x08");
        assert_eq!(detect_format(&path).unwrap(), ArchiveType::Zip);
    }

    // S3: USTAR detection must work even when the file is exactly 262 bytes
    // with no extra padding — exercises the read loop for a file that is
    // exactly at the boundary and has no trailing zero padding beyond
    // offset 262.
    #[test]
    fn test_magic_tar_ustar_exact_boundary_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("minimal.tar");
        // Write exactly 262 bytes: zeros everywhere except "ustar" at offset
        // 257.
        let mut data = vec![0u8; MAGIC_READ_LEN];
        data[257..262].copy_from_slice(b"ustar");
        std::fs::write(&path, &data).unwrap();
        // Extension matches too — verify magic agrees.
        assert_eq!(detect_format(&path).unwrap(), ArchiveType::Tar);
    }

    // S3: a file shorter than 262 bytes but with USTAR at offset 257 must still
    // be detected (file is 262 bytes minimum by construction, but 263 bytes
    // with one extra zero also works; test a file that is exactly the USTAR
    // minimum).
    #[test]
    fn test_magic_tar_ustar_minimal_263_byte_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("data");
        let mut data = vec![0u8; 263];
        data[257..262].copy_from_slice(b"ustar");
        std::fs::write(&path, &data).unwrap();
        assert_eq!(detect_format(&path).unwrap(), ArchiveType::Tar);
    }

    #[test]
    fn match_signature_prefers_offset_zero_magic_over_ustar() {
        let mut header = [0u8; MAGIC_READ_LEN];
        header[257..262].copy_from_slice(b"ustar");
        assert_eq!(match_signature(&header), Some(ArchiveType::Tar));
        header[..4].copy_from_slice(b"PK\x03\x04");
        assert_eq!(match_signature(&header), Some(ArchiveType::Zip));
    }

    fn sealed_block(name: &[u8]) -> [u8; TAR_BLOCK_LEN] {
        let mut header = tar::Header::new_ustar();
        header.as_old_mut().name[..name.len()].copy_from_slice(name);
        header.set_size(0);
        header.set_cksum();
        *header.as_bytes()
    }

    #[test]
    fn is_ustar_header_accepts_only_a_sealed_block() {
        let block = sealed_block(b"a.txt");
        assert!(is_ustar_header(&block));

        let mut off_by_one = block;
        off_by_one[0] ^= 1;
        assert!(!is_ustar_header(&off_by_one));

        let mut non_numeric = block;
        non_numeric[TAR_CKSUM_FIELD].copy_from_slice(b"xxxxxxx\0");
        assert!(!is_ustar_header(&non_numeric));

        assert!(!is_ustar_header(&block[..TAR_BLOCK_LEN - 1]));
        assert!(!is_ustar_header(&[]));

        let mut v7 = sealed_block(b"a.txt");
        v7[USTAR_MAGIC_OFFSET..USTAR_MAGIC_OFFSET + 5].fill(0);
        assert!(!is_ustar_header(&v7));
    }

    #[test]
    fn only_a_bzip2_looking_name_loses_to_a_sealed_ustar_block() {
        let cases: [(&[u8], Option<ArchiveType>); 8] = [
            (b"BZhfoo.txt", Some(ArchiveType::Tar)),
            (b"BZh91AY&SYfoo", Some(ArchiveType::TarBz2)),
            (b"\x1f\x8bfoo", Some(ArchiveType::TarGz)),
            (b"\x28\xb5\x2f\xfdfoo", Some(ArchiveType::TarZst)),
            (b"\xfd7zXZ\0foo", Some(ArchiveType::TarXz)),
            (b"PK\x03\x04foo", Some(ArchiveType::Zip)),
            (b"7z\xbc\xaf\x27\x1cfoo", Some(ArchiveType::SevenZ)),
            (b"plain.txt", Some(ArchiveType::Tar)),
        ];
        for (name, expected) in cases {
            assert_eq!(match_signature(&sealed_block(name)), expected, "{name:?}");
        }
    }

    #[test]
    fn a_v7_tar_with_a_gzip_magic_name_stays_gzip() {
        let mut block = sealed_block(b"\x1f\x8bfoo");
        block[USTAR_MAGIC_OFFSET..USTAR_MAGIC_OFFSET + 5].fill(0);
        assert_eq!(match_signature(&block), Some(ArchiveType::TarGz));
    }

    #[test]
    fn match_signature_handles_short_and_empty_headers() {
        assert_eq!(match_signature(&[]), None);
        assert_eq!(match_signature(b"\x1f"), None);
        assert_eq!(match_signature(b"\x1f\x8b"), Some(ArchiveType::TarGz));
        assert_eq!(match_signature(&[0; 261]), None);
    }
}

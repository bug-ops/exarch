//! Archives read from a caller-supplied reader instead of a path.
//!
//! [`ArchiveReader`] is the input of
//! [`ListRequest::list_reader`](crate::ListRequest::list_reader),
//! [`VerifyRequest::verify_reader`](crate::VerifyRequest::verify_reader) and
//! [`SinkExtractRequest::extract`](crate::SinkExtractRequest::extract). The
//! constructors encode what each format needs: a TAR stream is forward-only, so
//! any `Read` will do, while ZIP and 7z read a directory at the end of the
//! archive and need `Seek`. The caller states the format with
//! [`ArchiveReader::tar`], [`ArchiveReader::seekable`] or
//! [`ArchiveReader::of_type`], or has it sniffed from the leading bytes by
//! [`ArchiveReader::detect`] and [`ArchiveReader::detect_stream`].

use std::io::BufReader;
use std::io::Cursor;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;

use crate::ArchiveError;
use crate::ProgressCallback;
use crate::ReaderFormatError;
use crate::Result;
use crate::SecurityConfig;
use crate::VerificationOptions;
use crate::formats::SevenZArchive;
use crate::formats::TarArchive;
use crate::formats::ZipArchive;
use crate::formats::compression::CompressionCodec;
use crate::formats::compression::DecoderLimits;
use crate::formats::detect::ArchiveType;
use crate::formats::detect::FormatFamily;
use crate::formats::detect::match_signature;
use crate::formats::detect::peek_header;
use crate::formats::source_fault::SourceRead;
use crate::formats::source_fault::SourceTap;
use crate::formats::source_fault::TapSource;
use crate::inspection::ArchiveManifest;
use crate::inspection::VerificationReport;
use crate::inspection::integrity::TarTrailer;
use crate::inspection::list::ListPass;
use crate::inspection::list::list_tar_stream;
use crate::inspection::verify::verify_with;

/// A seekable byte source.
pub(crate) trait ReadSeek: Read + Seek + Send {}

impl<T: Read + Seek + Send> ReadSeek for T {}

/// A format that is read through a directory at the end of the archive, and
/// so needs a seekable source.
///
/// # Examples
///
/// ```
/// use exarch_core::SeekableFormat;
///
/// assert_eq!(SeekableFormat::Zip.as_str(), "zip");
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SeekableFormat {
    /// A ZIP archive.
    Zip,
    /// A 7z archive.
    SevenZ,
}

impl SeekableFormat {
    /// The format's lower-case name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Zip => "zip",
            Self::SevenZ => "7z",
        }
    }
}

pub(crate) enum Source<'a> {
    Tar {
        stream: Box<dyn Read + Send + 'a>,
        codec: Option<CompressionCodec>,
    },
    Seekable {
        reader: Box<dyn ReadSeek + 'a>,
        format: SeekableFormat,
    },
}

/// An archive supplied as a reader.
///
/// # Examples
///
/// ```
/// use exarch_core::ArchiveReader;
/// use exarch_core::SeekableFormat;
/// use exarch_core::formats::detect::ArchiveType;
/// use std::io::Cursor;
///
/// let tar = ArchiveReader::tar(Cursor::new(Vec::<u8>::new()), None);
/// assert_eq!(tar.format(), ArchiveType::Tar);
///
/// let zip = ArchiveReader::seekable(Cursor::new(Vec::<u8>::new()), SeekableFormat::Zip);
/// assert_eq!(zip.format(), ArchiveType::Zip);
/// ```
pub struct ArchiveReader<'a> {
    source: Source<'a>,
}

impl std::fmt::Debug for ArchiveReader<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ArchiveReader")
            .field("format", &self.format())
            .finish_non_exhaustive()
    }
}

impl<'a> ArchiveReader<'a> {
    /// A TAR archive in `reader`, compressed with `codec` when given.
    ///
    /// The reader holds the raw bytes. The decoder is applied when the
    /// operation runs, with the decoder memory limit of its config.
    #[must_use]
    pub fn tar<R: Read + Send + 'a>(reader: R, codec: Option<CompressionCodec>) -> Self {
        Self {
            source: Source::Tar {
                stream: Box::new(reader),
                codec,
            },
        }
    }

    /// A ZIP or 7z archive in `reader`.
    ///
    /// The archive must start at offset 0 of the reader: 7z addresses its
    /// blocks by absolute offsets, so an archive embedded in a larger stream
    /// needs a reader that maps offset 0 to the start of the archive.
    #[must_use]
    pub fn seekable<R: Read + Seek + Send + 'a>(reader: R, format: SeekableFormat) -> Self {
        Self {
            source: Source::Seekable {
                reader: Box::new(reader),
                format,
            },
        }
    }

    /// An archive of the stated `format` in `reader`, whichever way it is read.
    ///
    /// The reader must start at the archive, as for [`Self::tar`] and
    /// [`Self::seekable`].
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::ArchiveReader;
    /// use exarch_core::formats::detect::ArchiveType;
    /// use std::io::Cursor;
    ///
    /// let reader = ArchiveReader::of_type(Cursor::new(Vec::<u8>::new()), ArchiveType::TarGz);
    /// assert_eq!(reader.format(), ArchiveType::TarGz);
    /// ```
    #[must_use]
    pub fn of_type<R: Read + Seek + Send + 'a>(reader: R, format: ArchiveType) -> Self {
        match format.family() {
            FormatFamily::Tar(codec) => Self::tar(reader, codec),
            FormatFamily::Seekable(container) => Self::seekable(reader, container),
        }
    }

    /// An archive of the stated `format` in a forward-only `reader`.
    ///
    /// # Errors
    ///
    /// Returns [`ArchiveError::ReaderFormat`] with `NeedsSeek` if `format` is
    /// ZIP or 7z, which cannot be read without seeking.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::ArchiveReader;
    /// use exarch_core::formats::detect::ArchiveType;
    ///
    /// let tar = ArchiveReader::of_stream(&b""[..], ArchiveType::TarGz)?;
    /// assert_eq!(tar.format(), ArchiveType::TarGz);
    /// assert!(ArchiveReader::of_stream(&b""[..], ArchiveType::Zip).is_err());
    /// # Ok::<(), exarch_core::ArchiveError>(())
    /// ```
    pub fn of_stream<R: Read + Send + 'a>(reader: R, format: ArchiveType) -> Result<Self> {
        match format.family() {
            FormatFamily::Tar(codec) => Ok(Self::tar(reader, codec)),
            FormatFamily::Seekable(container) => Err(ArchiveError::ReaderFormat(
                ReaderFormatError::NeedsSeek(container),
            )),
        }
    }

    /// An archive held in memory: of the stated `format`, or detected from its
    /// leading bytes when `format` is `None`.
    ///
    /// # Errors
    ///
    /// With `format` of `None`, the errors of [`Self::detect`].
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::ArchiveReader;
    /// use exarch_core::formats::detect::ArchiveType;
    ///
    /// let bytes = b"PK\x05\x06\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0".to_vec();
    /// let detected = ArchiveReader::from_bytes(bytes.clone(), None)?;
    /// assert_eq!(detected.format(), ArchiveType::Zip);
    ///
    /// let stated = ArchiveReader::from_bytes(bytes, Some(ArchiveType::Tar))?;
    /// assert_eq!(stated.format(), ArchiveType::Tar);
    /// # Ok::<(), exarch_core::ArchiveError>(())
    /// ```
    pub fn from_bytes<B: AsRef<[u8]> + Send + 'a>(
        bytes: B,
        format: Option<ArchiveType>,
    ) -> Result<Self> {
        let cursor = Cursor::new(bytes);
        match format {
            Some(format) => Ok(Self::of_type(cursor, format)),
            None => Self::detect(cursor),
        }
    }

    /// Detects the format of the archive at the current position of a
    /// seekable `reader` from its leading bytes.
    ///
    /// The reader is left at the position it was in. A TAR archive may start
    /// anywhere; a ZIP or 7z archive must start at offset 0, because both
    /// address their records by absolute offsets. Where several signatures
    /// match, the first in table order wins: a container magic at the start
    /// beats the `ustar` marker at offset 257, and so do gzip, xz and zstd
    /// magics. Only `BZh` can open a member name, so a checksum-valid ustar
    /// header that does not start with a complete bzip2 stream header is read
    /// as a plain TAR; input valid under both readings stays bzip2. A v7 TAR
    /// (no `ustar` marker)
    /// and a ZIP with data prepended are not recognized; use [`Self::tar`]
    /// for the former.
    ///
    /// # Errors
    ///
    /// Returns [`ArchiveError::ReaderFormat`] with `Unrecognized` if no
    /// signature matches, or with `NotAtStart` if a ZIP or 7z signature is
    /// found at a position other than 0. Returns [`ArchiveError::Io`] if the
    /// reader cannot be read or repositioned.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::ArchiveReader;
    /// use exarch_core::formats::detect::ArchiveType;
    /// use std::io::Cursor;
    ///
    /// let empty_zip = b"PK\x05\x06\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
    /// let reader = ArchiveReader::detect(Cursor::new(empty_zip.to_vec()))?;
    /// assert_eq!(reader.format(), ArchiveType::Zip);
    /// # Ok::<(), exarch_core::ArchiveError>(())
    /// ```
    pub fn detect<R: Read + Seek + Send + 'a>(mut reader: R) -> Result<Self> {
        let start = reader.stream_position().map_err(ArchiveError::Io)?;
        let header = peek_header(&mut reader).map_err(ArchiveError::Io)?;
        reader
            .seek(SeekFrom::Start(start))
            .map_err(ArchiveError::Io)?;
        let format = match_signature(header.as_slice())
            .ok_or(ArchiveError::ReaderFormat(ReaderFormatError::Unrecognized))?;
        match format.family() {
            FormatFamily::Seekable(container) if start != 0 => Err(ArchiveError::ReaderFormat(
                ReaderFormatError::NotAtStart(container),
            )),
            _ => Ok(Self::of_type(reader, format)),
        }
    }

    /// Detects the format of a forward-only `reader` from its leading bytes.
    ///
    /// Only TAR streams can be read without seeking. The bytes consumed for
    /// detection are replayed in front of the rest of the stream, so nothing
    /// is lost. The signature rules are those of [`Self::detect`]. Up to 512
    /// bytes are peeked, or the stream is read to its end if it is shorter.
    ///
    /// # Errors
    ///
    /// Returns [`ArchiveError::ReaderFormat`] with `NeedsSeek` if the bytes
    /// are a ZIP or 7z signature, or with `Unrecognized` if no signature
    /// matches. Returns [`ArchiveError::Io`] if the reader cannot be read.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::assert_matches;
    ///
    /// use exarch_core::ArchiveError;
    /// use exarch_core::ArchiveReader;
    /// use exarch_core::ReaderFormatError;
    /// use exarch_core::SeekableFormat;
    ///
    /// let zip: &[u8] = b"PK\x03\x04 and the rest";
    /// assert_matches!(
    ///     ArchiveReader::detect_stream(zip),
    ///     Err(ArchiveError::ReaderFormat(ReaderFormatError::NeedsSeek(
    ///         SeekableFormat::Zip
    ///     )))
    /// );
    /// ```
    pub fn detect_stream<R: Read + Send + 'a>(mut reader: R) -> Result<Self> {
        let header = peek_header(&mut reader).map_err(ArchiveError::Io)?;
        let format = match_signature(header.as_slice())
            .ok_or(ArchiveError::ReaderFormat(ReaderFormatError::Unrecognized))?;
        match format.family() {
            FormatFamily::Tar(codec) => {
                let replay = Cursor::new(header.as_slice().to_vec());
                Ok(Self::tar(replay.chain(reader), codec))
            }
            FormatFamily::Seekable(container) => Err(ArchiveError::ReaderFormat(
                ReaderFormatError::NeedsSeek(container),
            )),
        }
    }

    /// The format the reader was declared to hold.
    #[must_use]
    pub const fn format(&self) -> ArchiveType {
        match self.source {
            Source::Tar { codec, .. } => ArchiveType::tar_with(codec),
            Source::Seekable {
                format: SeekableFormat::Zip,
                ..
            } => ArchiveType::Zip,
            Source::Seekable {
                format: SeekableFormat::SevenZ,
                ..
            } => ArchiveType::SevenZ,
        }
    }

    pub(crate) fn into_source(self) -> Source<'a> {
        self.source
    }

    pub(crate) fn list(
        self,
        config: &SecurityConfig,
        listing: &mut ListPass<'_, '_>,
    ) -> Result<ArchiveManifest> {
        let format = self.format();
        match self.source {
            Source::Tar { stream, codec } => {
                let decoded = decode_tar_stream(stream, codec, DecoderLimits::of(config))?;
                let source = decoded.source();
                list_tar_stream(decoded.stream, source, codec, format, config, listing)
            }
            Source::Seekable {
                reader,
                format: SeekableFormat::Zip,
            } => ZipArchive::new(reader, config)?.list_with(config, listing),
            Source::Seekable {
                reader,
                format: SeekableFormat::SevenZ,
            } => crate::inspection::list::list_sevenz_reader(reader, config, listing),
        }
    }

    pub(crate) fn verify(
        self,
        config: &SecurityConfig,
        options: VerificationOptions,
        progress: &mut dyn ProgressCallback,
    ) -> Result<VerificationReport> {
        let format = self.format();
        match self.source {
            Source::Tar { stream, codec } => {
                let decoded = decode_tar_stream(stream, codec, DecoderLimits::of(config))?;
                let source = decoded.source();
                verify_with(config, options, progress, |listing| {
                    list_tar_stream(decoded.stream, source, codec, format, config, listing)
                })
            }
            Source::Seekable {
                reader,
                format: SeekableFormat::Zip,
            } => ZipArchive::new(reader, config)?.verify_with_progress(config, options, progress),
            Source::Seekable {
                reader,
                format: SeekableFormat::SevenZ,
            } => {
                SevenZArchive::new(reader, config)?.verify_with_progress(config, options, progress)
            }
        }
    }
}

/// A decoded TAR byte stream together with the meter on its raw input.
pub(crate) struct TarStream<'r> {
    pub(crate) stream: Box<dyn Read + Send + 'r>,
    tap: SourceTap,
}

impl TarStream<'_> {
    /// The metered source behind the stream.
    pub(crate) fn source(&self) -> TapSource {
        TapSource::Tapped(self.tap.clone())
    }
}

/// Wraps a TAR byte stream in its decoder, metering the raw input.
///
/// # Errors
///
/// Returns an error if the decoder cannot be initialised.
pub(crate) fn decode_tar_stream<'r, R: Read + Send + 'r>(
    reader: R,
    codec: Option<CompressionCodec>,
    limits: DecoderLimits,
) -> Result<TarStream<'r>> {
    let tap = SourceTap::default();
    let buffered = BufReader::new(SourceRead::new(reader, tap.clone()));
    let stream = match codec {
        Some(codec) => codec.decoder(buffered, limits)?,
        None => Box::new(buffered),
    };
    Ok(TarStream { stream, tap })
}

/// Opens a TAR stream on `reader`; the owner of the stream reads archive
/// entries from it.
pub(crate) fn tar_archive<'r, R: Read + Send + 'r>(
    reader: R,
    codec: Option<CompressionCodec>,
    config: &SecurityConfig,
) -> Result<TarArchive<Box<dyn Read + Send + 'r>>> {
    let trailer = TarTrailer::for_codec(codec);
    decode_tar_stream(reader, codec, DecoderLimits::of(config))
        .map(|decoded| TarArchive::from_stream(decoded, trailer, config))
}

#[cfg(test)]
mod tests {
    use std::assert_matches;

    use super::*;
    use crate::SeekableFormat;

    #[test]
    fn test_of_stream_keeps_every_tar_codec() -> Result<()> {
        for format in [
            ArchiveType::Tar,
            ArchiveType::TarBz2,
            ArchiveType::TarXz,
            ArchiveType::TarZst,
        ] {
            let reader = ArchiveReader::of_stream(&b""[..], format)?;
            assert_eq!(reader.format(), format);
        }
        Ok(())
    }

    #[test]
    fn test_of_stream_refuses_seekable_formats() {
        for (format, container) in [
            (ArchiveType::Zip, SeekableFormat::Zip),
            (ArchiveType::SevenZ, SeekableFormat::SevenZ),
        ] {
            assert_matches!(
                ArchiveReader::of_stream(&b""[..], format),
                Err(ArchiveError::ReaderFormat(ReaderFormatError::NeedsSeek(c))) if c == container
            );
        }
    }
}

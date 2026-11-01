//! Archives read from a caller-supplied reader instead of a path.
//!
//! [`ArchiveReader`] is the input of [`list_reader`](crate::list_reader),
//! [`verify_reader`](crate::verify_reader) and
//! [`extract_to_sink`](crate::extract_to_sink). The constructors encode what
//! each format needs: a TAR stream is forward-only, so any `Read` will do,
//! while ZIP and 7z read a directory at the end of the archive and need `Seek`.
//! The format is stated by the caller; nothing is sniffed from the bytes.

use std::io::BufReader;
use std::io::Read;
use std::io::Seek;

use crate::Result;
use crate::SecurityConfig;
use crate::VerificationOptions;
use crate::config::Validated;
use crate::formats::SevenZArchive;
use crate::formats::TarArchive;
use crate::formats::ZipArchive;
use crate::formats::compression::CompressionCodec;
use crate::formats::detect::ArchiveType;
use crate::formats::traits::ArchiveFormat;
use crate::inspection::ArchiveManifest;
use crate::inspection::VerificationReport;
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
        config: &SecurityConfig<Validated>,
        listing: &mut ListPass<'_, '_>,
    ) -> Result<ArchiveManifest> {
        let format = self.format();
        match self.source {
            Source::Tar { stream, codec } => {
                let decoded = decode_tar_stream(stream, codec, config.max_decoder_memory)?;
                list_tar_stream(decoded, codec, format, config, listing)
            }
            Source::Seekable {
                reader,
                format: SeekableFormat::Zip,
            } => ZipArchive::new(reader)?.list_with(config, listing),
            Source::Seekable {
                reader,
                format: SeekableFormat::SevenZ,
            } => crate::inspection::list::list_sevenz_reader(reader, config, listing),
        }
    }

    pub(crate) fn verify(
        self,
        config: &SecurityConfig<Validated>,
        options: VerificationOptions,
    ) -> Result<VerificationReport> {
        let format = self.format();
        match self.source {
            Source::Tar { stream, codec } => {
                let decoded = decode_tar_stream(stream, codec, config.max_decoder_memory)?;
                verify_with(config, options, |listing| {
                    list_tar_stream(decoded, codec, format, config, listing)
                })
            }
            Source::Seekable {
                reader,
                format: SeekableFormat::Zip,
            } => ZipArchive::new(reader)?.verify(config, &options),
            Source::Seekable {
                reader,
                format: SeekableFormat::SevenZ,
            } => SevenZArchive::new(reader)?.verify(config, &options),
        }
    }
}

/// Wraps a TAR byte stream in its decoder.
///
/// # Errors
///
/// Returns an error if the decoder cannot be initialised.
pub(crate) fn decode_tar_stream<'r, R: Read + Send + 'r>(
    reader: R,
    codec: Option<CompressionCodec>,
    max_decoder_memory: u64,
) -> Result<Box<dyn Read + Send + 'r>> {
    let buffered = BufReader::new(reader);
    match codec {
        Some(codec) => codec.decoder(buffered, max_decoder_memory),
        None => Ok(Box::new(buffered)),
    }
}

/// Opens a TAR stream on `reader`; the owner of the stream reads archive
/// entries from it.
pub(crate) fn tar_archive<'r, R: Read + Send + 'r>(
    reader: R,
    codec: Option<CompressionCodec>,
    max_decoder_memory: u64,
) -> Result<TarArchive<Box<dyn Read + Send + 'r>>> {
    decode_tar_stream(reader, codec, max_decoder_memory).map(TarArchive::new)
}

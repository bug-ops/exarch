//! Archive creation into a caller-supplied writer instead of a path.
//!
//! [`ArchiveWriter`] is the destination of [`create_to_writer`]. The
//! constructors encode what each format needs: a TAR stream is forward-only, so
//! any `Write` will do, while ZIP patches earlier records and needs `Seek`. The
//! format is stated by the caller; nothing is derived from a file name.
//!
//! On error the writer may already hold a partial archive; the caller owns it
//! and decides whether to discard it.

use std::io::Cursor;
use std::io::Seek;
use std::io::Write;
use std::path::Path;

use crate::ArchiveError;
use crate::CreationConfig;
use crate::CreationReport;
use crate::NoopProgress;
use crate::ProgressCallback;
use crate::Result;
use crate::creation::tar::write_tar;
use crate::creation::zip::warn_on_extraction_ratio;
use crate::creation::zip::write_zip;
use crate::formats::compression::CompressionCodec;
use crate::formats::detect::CreatableFormat;
use crate::formats::detect::CreationFamily;

/// A seekable byte destination.
pub(crate) trait WriteSeek: Write + Seek + Send {}

impl<T: Write + Seek + Send> WriteSeek for T {}

/// Counts the bytes that pass through to the inner writer.
#[derive(Debug)]
pub(crate) struct CountingWriter<W> {
    inner: W,
    bytes: u64,
}

impl<W> CountingWriter<W> {
    pub(crate) const fn new(inner: W) -> Self {
        Self { inner, bytes: 0 }
    }

    pub(crate) const fn bytes(&self) -> u64 {
        self.bytes
    }
}

impl<W: Write> Write for CountingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let written = self.inner.write(buf)?;
        self.bytes = self.bytes.saturating_add(written as u64);
        Ok(written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

pub(crate) fn sevenz_creation_unsupported() -> ArchiveError {
    ArchiveError::InvalidConfiguration {
        reason: "7z archive creation is not supported".into(),
    }
}

enum Destination<'a> {
    Tar {
        stream: Box<dyn Write + Send + 'a>,
        codec: Option<CompressionCodec>,
    },
    Zip {
        stream: Box<dyn WriteSeek + 'a>,
    },
}

/// An archive destination supplied as a writer.
///
/// Pass `&mut writer` to keep the writer after the call.
///
/// # Examples
///
/// ```
/// use exarch_core::ArchiveWriter;
/// use exarch_core::formats::CompressionCodec;
/// use exarch_core::formats::detect::CreatableFormat;
/// use std::io::Cursor;
///
/// let tar = ArchiveWriter::tar(Vec::<u8>::new(), Some(CompressionCodec::Gzip));
/// assert_eq!(tar.format(), CreatableFormat::TarGz);
///
/// let zip = ArchiveWriter::zip(Cursor::new(Vec::<u8>::new()));
/// assert_eq!(zip.format(), CreatableFormat::Zip);
/// ```
pub struct ArchiveWriter<'a> {
    destination: Destination<'a>,
}

impl std::fmt::Debug for ArchiveWriter<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ArchiveWriter")
            .field("format", &self.format())
            .finish_non_exhaustive()
    }
}

impl<'a> ArchiveWriter<'a> {
    /// A TAR archive written to `writer`, compressed with `codec` when given.
    ///
    /// The compression level comes from `CreationConfig::compression_level`.
    #[must_use]
    pub fn tar<W: Write + Send + 'a>(writer: W, codec: Option<CompressionCodec>) -> Self {
        Self {
            destination: Destination::Tar {
                stream: Box::new(writer),
                codec,
            },
        }
    }

    /// A ZIP archive written to `writer`.
    ///
    /// The writer must be positioned at offset 0 when the archive is created,
    /// otherwise creation fails with
    /// [`InvalidConfiguration`](ArchiveError::InvalidConfiguration).
    #[must_use]
    pub fn zip<W: Write + Seek + Send + 'a>(writer: W) -> Self {
        Self {
            destination: Destination::Zip {
                stream: Box::new(writer),
            },
        }
    }

    /// An archive of the given `format` written to `writer`.
    ///
    /// Picks [`tar`](Self::tar) or [`zip`](Self::zip) from `format`, for
    /// callers that hold the format as a value. `Seek` is required because
    /// the format is only known at run time.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::ArchiveWriter;
    /// use exarch_core::formats::detect::CreatableFormat;
    /// use std::io::Cursor;
    ///
    /// let writer = ArchiveWriter::of_type(Cursor::new(Vec::<u8>::new()), CreatableFormat::TarZst);
    /// assert_eq!(writer.format(), CreatableFormat::TarZst);
    /// ```
    pub fn of_type<W: Write + Seek + Send + 'a>(writer: W, format: CreatableFormat) -> Self {
        match format.family() {
            CreationFamily::Tar(codec) => Self::tar(writer, codec),
            CreationFamily::Zip => Self::zip(writer),
        }
    }

    /// The format the writer was declared to receive.
    #[must_use]
    pub const fn format(&self) -> CreatableFormat {
        match self.destination {
            Destination::Tar { codec, .. } => CreatableFormat::tar_with(codec),
            Destination::Zip { .. } => CreatableFormat::Zip,
        }
    }
}

/// Creates an archive from `sources` into `writer`.
///
/// Same as [`create_archive`](crate::create_archive) with the output in a
/// writer. The writer fixes the format, so `config.format` is ignored.
/// `CreationReport::bytes_compressed` is the number of bytes written to it.
///
/// # Errors
///
/// Returns an error if:
/// - the configuration is invalid
/// - a source does not exist or cannot be read
/// - writing to the writer fails
///
/// # Examples
///
/// ```
/// use exarch_core::ArchiveWriter;
/// use exarch_core::CreationConfig;
/// use exarch_core::create_to_writer;
/// use exarch_core::formats::CompressionCodec;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let src = tempfile::tempdir()?;
/// std::fs::write(src.path().join("a.txt"), b"hello")?;
///
/// let mut buf = Vec::new();
/// let report = create_to_writer(
///     ArchiveWriter::tar(&mut buf, Some(CompressionCodec::Gzip)),
///     &[src.path()],
///     &CreationConfig::default(),
/// )?;
/// assert_eq!(report.bytes_compressed, buf.len() as u64);
/// # Ok(())
/// # }
/// ```
pub fn create_to_writer<P: AsRef<Path>>(
    writer: ArchiveWriter<'_>,
    sources: &[P],
    config: &CreationConfig,
) -> Result<CreationReport> {
    create_to_writer_with_progress(writer, sources, config, &mut NoopProgress)
}

/// Creates an archive from `sources` into `writer`, reporting progress.
///
/// Same as [`create_to_writer`] with a [`ProgressCallback`].
///
/// # Errors
///
/// Same as [`create_to_writer`].
///
/// # Examples
///
/// ```
/// use exarch_core::ArchiveWriter;
/// use exarch_core::CreationConfig;
/// use exarch_core::NoopProgress;
/// use exarch_core::create_to_writer_with_progress;
/// use std::io::Cursor;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let src = tempfile::tempdir()?;
/// std::fs::write(src.path().join("a.txt"), b"hello")?;
///
/// let mut out = Cursor::new(Vec::new());
/// let report = create_to_writer_with_progress(
///     ArchiveWriter::zip(&mut out),
///     &[src.path()],
///     &CreationConfig::default(),
///     &mut NoopProgress,
/// )?;
/// assert_eq!(report.files_added, 1);
/// # Ok(())
/// # }
/// ```
pub fn create_to_writer_with_progress<P: AsRef<Path>>(
    writer: ArchiveWriter<'_>,
    sources: &[P],
    config: &CreationConfig,
    progress: &mut dyn ProgressCallback,
) -> Result<CreationReport> {
    let config = config.clone().validate()?;

    match writer.destination {
        Destination::Tar { stream, codec } => write_tar(stream, codec, sources, &config, progress),
        Destination::Zip { stream } => {
            write_zip(stream, sources, &config, progress).map(|(report, _)| report)
        }
    }
}

/// Creates an archive of `format` from `sources` and returns its bytes.
///
/// The whole archive is held in memory, so use
/// [`create_archive`](crate::create_archive) for large ones. Because the
/// finished ZIP can be read back, a ZIP result carries the same warning as
/// [`create_archive`](crate::create_archive) when default extraction would
/// refuse an entry as a zip bomb.
///
/// # Errors
///
/// Returns the errors of [`create_to_writer`].
///
/// # Examples
///
/// ```
/// use exarch_core::CreationConfig;
/// use exarch_core::create_to_bytes;
/// use exarch_core::formats::detect::CreatableFormat;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let src = tempfile::tempdir()?;
/// std::fs::write(src.path().join("a.txt"), b"hello")?;
///
/// let (bytes, report) = create_to_bytes(
///     &[src.path()],
///     CreatableFormat::TarGz,
///     &CreationConfig::default(),
/// )?;
/// assert_eq!(report.bytes_compressed, bytes.len() as u64);
/// # Ok(())
/// # }
/// ```
pub fn create_to_bytes<P: AsRef<Path>>(
    sources: &[P],
    format: CreatableFormat,
    config: &CreationConfig,
) -> Result<(Vec<u8>, CreationReport)> {
    let mut out = Cursor::new(Vec::new());
    let writer = ArchiveWriter::of_type(&mut out, format);
    let mut report = create_to_writer(writer, sources, config)?;
    if format == CreatableFormat::Zip {
        warn_on_extraction_ratio(&mut out, &mut report);
    }
    Ok((out.into_inner(), report))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::SecurityConfig;
    use crate::api::create_archive;
    use crate::api::extract_archive;
    use std::assert_matches;
    use std::fs;
    use std::io::Cursor;
    use tempfile::TempDir;

    fn source_tree() -> TempDir {
        let src = TempDir::new().unwrap();
        fs::write(src.path().join("a.txt"), "alpha").unwrap();
        fs::create_dir(src.path().join("sub")).unwrap();
        fs::write(src.path().join("sub/b.txt"), "bravo".repeat(500)).unwrap();
        src
    }

    fn config() -> CreationConfig {
        CreationConfig::default()
            .with_exclude_patterns(vec![])
            .with_include_hidden(true)
    }

    const TAR_FORMATS: [(Option<CompressionCodec>, &str); 5] = [
        (None, "tar"),
        (Some(CompressionCodec::Gzip), "tar.gz"),
        (Some(CompressionCodec::Bzip2), "tar.bz2"),
        (Some(CompressionCodec::Xz), "tar.xz"),
        (Some(CompressionCodec::Zstd), "tar.zst"),
    ];

    fn assert_extracts_equal(archive: &Path, src: &Path) {
        let dest = TempDir::new().unwrap();
        extract_archive(archive, dest.path(), &SecurityConfig::default()).unwrap();
        let root = dest.path();
        assert_eq!(fs::read_to_string(root.join("a.txt")).unwrap(), "alpha");
        assert_eq!(
            fs::read(root.join("sub/b.txt")).unwrap(),
            fs::read(src.join("sub/b.txt")).unwrap()
        );
    }

    #[test]
    fn test_tar_round_trip_every_codec() {
        let src = source_tree();
        for (codec, ext) in TAR_FORMATS {
            let mut buf = Vec::new();
            let report = create_to_writer(
                ArchiveWriter::tar(&mut buf, codec),
                &[src.path()],
                &config(),
            )
            .unwrap();
            assert_eq!(report.bytes_compressed, buf.len() as u64, "{ext}");
            assert_eq!(report.files_added, 2, "{ext}");

            let out = TempDir::new().unwrap();
            let archive = out.path().join(format!("out.{ext}"));
            fs::write(&archive, &buf).unwrap();
            assert_extracts_equal(&archive, src.path());
        }
    }

    #[test]
    fn test_zip_round_trip() {
        let src = source_tree();
        let mut out = Cursor::new(Vec::new());
        let report =
            create_to_writer(ArchiveWriter::zip(&mut out), &[src.path()], &config()).unwrap();
        let buf = out.into_inner();
        assert_eq!(report.bytes_compressed, buf.len() as u64);

        let dir = TempDir::new().unwrap();
        let archive = dir.path().join("out.zip");
        fs::write(&archive, &buf).unwrap();
        assert_extracts_equal(&archive, src.path());
    }

    #[test]
    fn test_writer_output_equals_path_output() {
        let src = source_tree();
        let dir = TempDir::new().unwrap();
        for (codec, ext) in TAR_FORMATS {
            let path = dir.path().join(format!("p.{ext}"));
            let path_report = create_archive(&path, &[src.path()], &config()).unwrap();
            let mut buf = Vec::new();
            let report = create_to_writer(
                ArchiveWriter::tar(&mut buf, codec),
                &[src.path()],
                &config(),
            )
            .unwrap();
            assert_eq!(fs::read(&path).unwrap(), buf, "{ext}");
            assert_eq!(
                path_report.bytes_compressed,
                fs::metadata(&path).unwrap().len()
            );
            assert_eq!(
                report.bytes_compressed, path_report.bytes_compressed,
                "{ext}"
            );
        }
    }

    #[test]
    fn test_path_zip_bytes_compressed_equals_file_length() {
        let src = source_tree();
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("p.zip");
        let report = create_archive(&path, &[src.path()], &config()).unwrap();
        assert_eq!(report.bytes_compressed, fs::metadata(&path).unwrap().len());
    }

    #[test]
    fn test_create_to_bytes_round_trips_every_creatable_format() {
        let src = source_tree();
        for &format in CreatableFormat::ALL {
            let (bytes, report) = create_to_bytes(&[src.path()], format, &config()).unwrap();
            assert_eq!(report.bytes_compressed, bytes.len() as u64, "{format}");
            let reader = crate::ArchiveReader::from_bytes(bytes, None).unwrap();
            assert_eq!(
                crate::formats::detect::ArchiveType::from(format),
                reader.format()
            );
        }
    }

    #[test]
    fn test_create_to_bytes_zip_warns_about_extraction_ratio() {
        let src = TempDir::new().unwrap();
        fs::write(src.path().join("zeros"), vec![0u8; 100_000]).unwrap();
        let (_, report) = create_to_bytes(&[src.path()], CreatableFormat::Zip, &config()).unwrap();
        assert!(
            report
                .warnings
                .iter()
                .any(|warning| warning.contains("extraction ratio limit")),
            "{:?}",
            report.warnings
        );
        let (_, report) =
            create_to_bytes(&[src.path()], CreatableFormat::TarGz, &config()).unwrap();
        assert!(report.warnings.is_empty(), "{:?}", report.warnings);
    }

    #[test]
    fn test_of_type_round_trips_every_creatable_format() {
        let src = source_tree();
        for &format in CreatableFormat::ALL {
            let mut out = Cursor::new(Vec::new());
            let writer = ArchiveWriter::of_type(&mut out, format);
            assert_eq!(writer.format(), format);
            create_to_writer(writer, &[src.path()], &config()).unwrap();
            assert!(!out.get_ref().is_empty());
        }
    }

    #[test]
    fn test_writer_format_wins_over_config_format() {
        let src = source_tree();
        let cfg = config().with_format(Some(CreatableFormat::Zip));
        let mut out = Cursor::new(Vec::new());
        create_to_writer(
            ArchiveWriter::tar(&mut out, Some(CompressionCodec::Gzip)),
            &[src.path()],
            &cfg,
        )
        .unwrap();
        assert_eq!(&out.get_ref()[..2], b"\x1f\x8b");
    }

    #[test]
    fn test_zip_writer_not_at_start_is_rejected() {
        let src = source_tree();
        let mut out = Cursor::new(vec![0u8; 4]);
        out.set_position(4);
        let result = create_to_writer(ArchiveWriter::zip(out), &[src.path()], &config());
        assert_matches!(result, Err(ArchiveError::InvalidConfiguration { .. }));
    }

    #[test]
    fn test_missing_source_is_an_error() {
        let result = create_to_writer(
            ArchiveWriter::tar(Vec::new(), None),
            &[Path::new("/nonexistent/exarch-source")],
            &config(),
        );
        assert!(result.is_err());
    }

    #[test]
    fn test_progress_events_match_path_creation() {
        #[derive(Default)]
        struct Recorder {
            starts: Vec<std::path::PathBuf>,
            completes: usize,
            done: usize,
        }
        impl ProgressCallback for Recorder {
            fn on_entry_start(&mut self, path: &Path, _total: usize, _current: usize) {
                self.starts.push(path.to_path_buf());
            }

            fn on_bytes_written(&mut self, _bytes: u64) {}

            fn on_entry_complete(&mut self, _path: &Path) {
                self.completes += 1;
            }

            fn on_complete(&mut self) {
                self.done += 1;
            }
        }

        let src = source_tree();
        let dir = TempDir::new().unwrap();
        let mut by_path = Recorder::default();
        crate::create_archive_with_progress(
            dir.path().join("p.tar"),
            &[src.path()],
            &config(),
            &mut by_path,
        )
        .unwrap();
        let mut by_writer = Recorder::default();
        create_to_writer_with_progress(
            ArchiveWriter::tar(Vec::new(), None),
            &[src.path()],
            &config(),
            &mut by_writer,
        )
        .unwrap();
        assert_eq!(by_path.starts, by_writer.starts);
        assert_eq!(by_path.completes, by_writer.completes);
        assert_eq!((by_path.done, by_writer.done), (1, 1));
    }

    #[test]
    fn test_created_archive_lists_through_reader() {
        let src = source_tree();
        let mut buf = Vec::new();
        create_to_writer(
            ArchiveWriter::tar(&mut buf, Some(CompressionCodec::Zstd)),
            &[src.path()],
            &config(),
        )
        .unwrap();
        let manifest = crate::list_reader(
            crate::ArchiveReader::tar(Cursor::new(buf), Some(CompressionCodec::Zstd)),
            &SecurityConfig::default(),
            &crate::ListOptions::default(),
        )
        .unwrap();
        assert!(manifest.total_entries() >= 2);
    }
}

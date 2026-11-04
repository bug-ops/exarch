//! Listing that keeps what extraction can reuse.
//!
//! A caller that must look at an archive before extracting it (to refuse
//! conflicts with an existing destination, or to size a progress bar) pays a
//! second decode of a compressed TAR when it lists and then extracts. A
//! [`ListedArchive`] spools the decoder output of the list pass to an unnamed
//! temporary file, so the extraction reads the spool instead of decoding the
//! archive again.
//!
//! A ZIP archive is kept open instead: the list pass runs the structural check
//! that decodes the deflate entries, and extraction reuses its output and the
//! parsed archive (see [`DecodeReuse`](crate::DecodeReuse)) rather than opening
//! and checking the file a second time.
//!
//! The spool is an optimisation only. Whenever it cannot be trusted to equal
//! what a fresh decode yields, extraction decodes the archive again, exactly as
//! it would without it:
//!
//! - the decoder failed, or did not reach its end, while the list pass and the
//!   drain behind it read the stream;
//! - the decoded stream is larger than [`REPLAY_LIMIT`], or a spool write
//!   failed;
//! - the codec decodes faster than a disk round trip (zstd) or is absent (plain
//!   TAR);
//! - the extraction's `max_decoder_memory` is below the one the list pass
//!   decoded under, so the decode must be redone under the stricter bound.
//!
//! A fallback is chosen by the archive's size and contents, so it is never a
//! security property: the replay holds the bytes the same decoder produced,
//! and extraction validates every entry again.

use std::fs::File;
use std::io;
use std::io::BufReader;
use std::io::BufWriter;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;

use crate::DecodeReuse;
use crate::ExtractionReport;
use crate::ListOptions;
use crate::ProgressCallback;
use crate::Result;
use crate::SecurityConfig;
use crate::api::extract_staged;
use crate::api::extract_tar_stream;
use crate::api::extract_validated;
use crate::config::ExtractionOptions;
use crate::config::Validated;
use crate::formats::compression::CompressionCodec;
use crate::formats::compression::DecoderLimits;
use crate::formats::detect::FormatFamily;
use crate::formats::detect::detect_format;
use crate::formats::source_fault::SourceRead;
use crate::formats::source_fault::SourceTap;
use crate::formats::source_fault::TapSource;
use crate::formats::tar::open_tar_stream;
use crate::formats::traits::ArchiveFormat;
use crate::formats::zip::ZipArchive;
use crate::inspection::ArchiveManifest;
use crate::inspection::integrity::TarTrailer;
use crate::inspection::list::ListPass;
use crate::inspection::list::list_detected;
use crate::inspection::list::list_tar_stream;
use crate::reader::SeekableFormat;

/// The most decoded TAR bytes a list pass keeps for extraction (256 MiB).
///
/// Beyond it the spool is dropped and extraction decodes again. Data after the
/// TAR end marker is decoded into the spool before the listing returns, without
/// progress output. The list pass refuses a tail longer than the trailer cap
/// (`max_tar_metadata_bytes`, at least 1 MiB), so the tail is bounded by that
/// cap and by this limit, whichever is smaller.
///
/// Decoded streams over the limit decode twice. That cost is accepted: a larger
/// spool would be an unbounded temporary file (RAM on a tmpfs). A caller that
/// extracts atomically can skip the list pass and decode once.
const REPLAY_LIMIT: u64 = 256 * 1024 * 1024;

const SPOOL_BUFFER: usize = 64 * 1024;

/// Whether decoding `codec` costs more than reading its output back from disk.
const fn replays(codec: CompressionCodec) -> bool {
    match codec {
        CompressionCodec::Gzip | CompressionCodec::Bzip2 | CompressionCodec::Xz => true,
        CompressionCodec::Zstd => false,
    }
}

/// What a list pass kept for extraction.
enum Kept {
    Nothing,
    TarSpool(Spool),
    Zip(Box<ZipArchive<File>>),
}

/// The decoder output of a list pass and the decoder memory it was produced
/// under.
#[derive(Debug)]
struct Spool {
    file: File,
    decoded_with: DecoderLimits,
}

/// An archive that was listed and is ready to extract without decoding it
/// again where that is possible.
///
/// Created by [`list_archive_for_extraction`]. Extracting from it gives the
/// same result as
/// [`extract_archive_with_options_and_progress`](crate::api::extract_archive_with_options_and_progress)
/// on the archive; only the cost differs.
///
/// # Examples
///
/// ```
/// use exarch_core::DecodeReuse;
/// use exarch_core::ExtractionOptions;
/// use exarch_core::ListOptions;
/// use exarch_core::NoopProgress;
/// use exarch_core::SecurityConfig;
/// use exarch_core::list_archive_for_extraction;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// # let dir = tempfile::tempdir()?;
/// # let archive = dir.path().join("a.tar.gz");
/// # let mut tar = tar::Builder::new(Vec::new());
/// # let mut header = tar::Header::new_gnu();
/// # header.set_size(2);
/// # header.set_mode(0o644);
/// # tar.append_data(&mut header, "a.txt", &b"hi"[..])?;
/// # let mut gz = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
/// # std::io::Write::write_all(&mut gz, &tar.into_inner()?)?;
/// # std::fs::write(&archive, gz.finish()?)?;
/// let config = SecurityConfig::default();
/// let listed = list_archive_for_extraction(
///     &archive,
///     &config,
///     &ListOptions::default(),
///     DecodeReuse::default(),
/// )?;
/// assert_eq!(listed.manifest().total_entries(), 1);
///
/// let out = dir.path().join("out");
/// let report = listed.extract(
///     &out,
///     &config,
///     &ExtractionOptions::default(),
///     &mut NoopProgress,
/// )?;
/// assert_eq!(report.files_extracted, 1);
/// # Ok(())
/// # }
/// ```
pub struct ListedArchive {
    manifest: ArchiveManifest,
    archive: PathBuf,
    kept: Kept,
}

impl std::fmt::Debug for ListedArchive {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let kept = match self.kept {
            Kept::Nothing => "nothing",
            Kept::TarSpool(_) => "tar spool",
            Kept::Zip(_) => "zip archive",
        };
        f.debug_struct("ListedArchive")
            .field("archive", &self.archive)
            .field("kept", &kept)
            .finish_non_exhaustive()
    }
}

const _: () = {
    const fn send_sync<T: Send + Sync>() {}
    send_sync::<ListedArchive>();
};

impl ListedArchive {
    #[cfg(test)]
    const fn has_spool(&self) -> bool {
        matches!(self.kept, Kept::TarSpool(_))
    }

    /// What the list pass found in the archive.
    #[must_use]
    pub const fn manifest(&self) -> &ArchiveManifest {
        &self.manifest
    }

    /// Extracts the archive into `output_dir`.
    ///
    /// Behaves as
    /// [`extract_archive_with_options_and_progress`](crate::api::extract_archive_with_options_and_progress)
    /// does for the listed archive, reading the decoded stream kept by the list
    /// pass when it is available and `config.max_decoder_memory` is at least
    /// the limit the list pass decoded under (which also fixes the zstd window
    /// limit). A ZIP archive is extracted from the archive the list pass
    /// opened, with the decoded output it kept; `options.decode_reuse` does not
    /// apply, the mode given to [`list_archive_for_extraction`] does.
    ///
    /// # Errors
    ///
    /// Same as [`extract_archive_with_options_and_progress`](crate::api::extract_archive_with_options_and_progress).
    pub fn extract<P: AsRef<Path>>(
        self,
        output_dir: P,
        config: &SecurityConfig,
        options: &ExtractionOptions,
        progress: &mut dyn ProgressCallback,
    ) -> Result<ExtractionReport> {
        let Self { archive, kept, .. } = self;
        let validated = config.clone().validate()?;
        let spool = match kept {
            Kept::Zip(zip) if zip.serves(&validated) => {
                return extract_staged(output_dir.as_ref(), options, |dir| {
                    zip.extract(dir, &validated, options, progress)
                });
            }
            Kept::TarSpool(spool) if DecoderLimits::of(&validated).covers(spool.decoded_with) => {
                spool
            }
            Kept::Nothing | Kept::TarSpool(_) | Kept::Zip(_) => {
                return extract_staged(output_dir.as_ref(), options, |dir| {
                    extract_validated(&archive, dir, &validated, options, progress)
                });
            }
        };
        let config = validated;
        extract_staged(output_dir.as_ref(), options, |dir| {
            replay_spool(spool.file, dir, &config, options, progress)
        })
    }
}

/// Extracts the decoded TAR stream `spool`, reporting a fault of the spool as
/// the I/O error it raised rather than as a corrupt archive.
fn replay_spool<R: Read>(
    spool: R,
    dir: &Path,
    config: &SecurityConfig<Validated>,
    options: &ExtractionOptions,
    progress: &mut dyn ProgressCallback,
) -> Result<ExtractionReport> {
    let tap = SourceTap::default();
    let stream = BufReader::with_capacity(SPOOL_BUFFER, SourceRead::new(spool, tap.clone()));
    extract_tar_stream(
        stream,
        TapSource::Replay(tap),
        TarTrailer::DrainToDecoderEof,
        dir,
        config,
        options,
        progress,
    )
}

/// Lists an archive and keeps what extraction can reuse.
///
/// The listing is the same as
/// [`list_archive_with_options`](crate::list_archive_with_options) gives. For a
/// gzip, bzip2 or xz compressed TAR whose decoded stream fits in 256 MiB, the
/// decoder output is also written to an unnamed temporary file
/// (in the platform's temporary directory, which on Linux is often memory
/// backed) so that [`ListedArchive::extract`] does not decode the archive a
/// second time. Trailing members after the TAR data are decoded before the
/// listing returns; a tail longer than `max_tar_metadata_bytes` (at least
/// 1 MiB) is refused.
///
/// A ZIP archive is listed from an archive handle that is kept for the
/// extraction, together with the deflate output the structural check decoded,
/// as `reuse` says. Use [`DecodeReuse::Off`] to keep none.
///
/// # Errors
///
/// Same as [`list_archive_with_options`](crate::list_archive_with_options).
///
/// # Examples
///
/// ```
/// use exarch_core::DecodeReuse;
/// use exarch_core::ListOptions;
/// use exarch_core::SecurityConfig;
/// use exarch_core::list_archive_for_extraction;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// # let dir = tempfile::tempdir()?;
/// # let archive = dir.path().join("a.tar");
/// # let mut tar = tar::Builder::new(Vec::new());
/// # let mut header = tar::Header::new_gnu();
/// # header.set_size(2);
/// # header.set_mode(0o644);
/// # tar.append_data(&mut header, "a.txt", &b"hi"[..])?;
/// # std::fs::write(&archive, tar.into_inner()?)?;
/// let listed = list_archive_for_extraction(
///     &archive,
///     &SecurityConfig::default(),
///     &ListOptions::default(),
///     DecodeReuse::default(),
/// )?;
/// assert_eq!(listed.manifest().total_entries(), 1);
/// # Ok(())
/// # }
/// ```
pub fn list_archive_for_extraction<P: AsRef<Path>>(
    archive_path: P,
    config: &SecurityConfig,
    options: &ListOptions,
    reuse: DecodeReuse,
) -> Result<ListedArchive> {
    list_with_limit(archive_path.as_ref(), config, *options, REPLAY_LIMIT, reuse)
}

fn list_with_limit(
    archive: &Path,
    config: &SecurityConfig,
    options: ListOptions,
    limit: u64,
    reuse: DecodeReuse,
) -> Result<ListedArchive> {
    let config = config.clone().validate()?;
    let format = detect_format(archive)?;
    let mut pass = ListPass::strict_with(options.stored_targets);
    let (manifest, kept) = match format.family() {
        FormatFamily::Tar(Some(codec)) if replays(codec) && fits(archive, codec, limit) => {
            let decoded = open_tar_stream(archive, Some(codec), DecoderLimits::of(&config))?;
            let source = decoded.source();
            let mut tee = SpoolTee::new(decoded.stream, limit);
            let manifest =
                list_tar_stream(&mut tee, source, Some(codec), format, &config, &mut pass)?;
            let kept = tee
                .finish_spool(&config)
                .map_or(Kept::Nothing, Kept::TarSpool);
            (manifest, kept)
        }
        FormatFamily::Seekable(SeekableFormat::Zip) => {
            let mut zip = ZipArchive::for_extraction(File::open(archive)?, &config, reuse)?;
            let manifest = zip.list_with(&config, &mut pass)?;
            (manifest, Kept::Zip(Box::new(zip)))
        }
        _ => (
            list_detected(archive, format, &config, &mut pass)?,
            Kept::Nothing,
        ),
    };
    Ok(ListedArchive {
        manifest,
        archive: archive.to_path_buf(),
        kept,
    })
}

/// Whether the decoded stream can fit the limit, judged from the file alone;
/// a larger one would pay for a spool that is then thrown away. Only a hint:
/// a wrong guess costs the optimisation or a wasted spool, never correctness.
///
/// A gzip trailer that cannot describe the file (a decoded size under half the
/// compressed length, as a tiny last member after a large one gives) says
/// nothing about the whole stream and counts as too large. A missing trailer is
/// not a reason to skip the spool.
fn fits(archive: &Path, codec: CompressionCodec, limit: u64) -> bool {
    let Ok(compressed_len) = std::fs::metadata(archive).map(|m| m.len()) else {
        return false;
    };
    compressed_len <= limit
        && (codec != CompressionCodec::Gzip
            || gzip_decoded_size(archive)
                .is_none_or(|size| size.saturating_mul(2) >= compressed_len && size <= limit))
}

/// The decoded size a gzip file declares in its trailer (modulo 2^32, and of
/// its last member only).
fn gzip_decoded_size(archive: &Path) -> Option<u64> {
    let mut file = File::open(archive).ok()?;
    file.seek(SeekFrom::End(-4)).ok()?;
    let mut isize = [0; 4];
    file.read_exact(&mut isize).ok()?;
    Some(u64::from(u32::from_le_bytes(isize)))
}

/// Where the decoder stands, as seen by a [`SpoolTee`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Decoding {
    Reading,
    Finished,
    Failed,
}

/// A reader that copies what its inner decoder yields into a spool.
///
/// Any decoder error latches [`Decoding::Failed`] for good, and a spool that
/// ran over the limit or failed a write is dropped; neither disturbs the
/// bytes handed to the reader's consumer.
struct SpoolTee<R> {
    inner: R,
    spool: Option<BufWriter<File>>,
    written: u64,
    limit: u64,
    decoding: Decoding,
}

impl<R: Read> SpoolTee<R> {
    fn new(inner: R, limit: u64) -> Self {
        // Without a temporary file the only loss is the optimisation.
        let spool = crate::formats::common::open_spool()
            .map(|file| BufWriter::with_capacity(SPOOL_BUFFER, file));
        Self {
            inner,
            spool,
            written: 0,
            limit,
            decoding: Decoding::Reading,
        }
    }

    fn spool_chunk(&mut self, chunk: &[u8]) {
        let Some(spool) = self.spool.as_mut() else {
            return;
        };
        self.written += chunk.len() as u64;
        if self.written > self.limit || spool.write_all(chunk).is_err() {
            self.spool = None;
        }
    }

    /// Reads the decoder to its end, stopping at the first error, the first
    /// spool failure or the limit.
    fn drain(&mut self) {
        let mut chunk = vec![0; SPOOL_BUFFER];
        while self.spool.is_some() && self.decoding == Decoding::Reading {
            if self.read(&mut chunk).is_err() {
                break;
            }
        }
    }

    /// Drains the decoder and returns the spool, rewound, if it holds the
    /// complete decoder output.
    fn finish_spool(mut self, config: &SecurityConfig<Validated>) -> Option<Spool> {
        self.drain();
        if self.decoding != Decoding::Finished {
            return None;
        }
        let mut file = self.spool?.into_inner().ok()?;
        file.rewind().ok()?;
        Some(Spool {
            file,
            decoded_with: DecoderLimits::of(config),
        })
    }
}

impl<R: Read> Read for SpoolTee<R> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        match self.inner.read(buf) {
            Ok(0) => {
                if self.decoding == Decoding::Reading {
                    self.decoding = Decoding::Finished;
                }
                Ok(0)
            }
            Ok(n) => {
                self.spool_chunk(&buf[..n]);
                Ok(n)
            }
            Err(e) => {
                self.decoding = Decoding::Failed;
                self.spool = None;
                Err(e)
            }
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use std::assert_matches;

    use super::*;
    use crate::ErrorCode;
    use crate::NoopProgress;
    use crate::api::extract_archive_with_options_and_progress;
    use crate::test_utils::create_test_tar;
    use tempfile::TempDir;

    const CONTENT: &[u8] = b"hello replay";

    fn encoded(codec: CompressionCodec, tar: &[u8]) -> Vec<u8> {
        let mut encoder = codec
            .encoder(Vec::new(), crate::creation::CompressionLevel::default())
            .unwrap();
        encoder.write_all(tar).unwrap();
        encoder.finish().unwrap()
    }

    fn write_archive(dir: &TempDir, codec: CompressionCodec, bytes: &[u8]) -> PathBuf {
        let path = dir.path().join(format!("a.{}", codec.extension()));
        std::fs::write(&path, bytes).unwrap();
        path
    }

    fn small_tar() -> Vec<u8> {
        create_test_tar(vec![("a.txt", CONTENT)])
    }

    fn list(archive: &Path, limit: u64) -> ListedArchive {
        list_with_limit(
            archive,
            &SecurityConfig::default(),
            ListOptions::default(),
            limit,
            DecodeReuse::default(),
        )
        .unwrap()
    }

    fn extract_into(listed: ListedArchive, dir: &TempDir, config: &SecurityConfig) -> Result<()> {
        let out = dir.path().join("out");
        listed
            .extract(
                &out,
                config,
                &ExtractionOptions::default(),
                &mut NoopProgress,
            )
            .map(drop)
    }

    #[test]
    fn replays_the_decoded_stream_without_the_archive() {
        for codec in [
            CompressionCodec::Gzip,
            CompressionCodec::Bzip2,
            CompressionCodec::Xz,
        ] {
            let dir = TempDir::new().unwrap();
            let archive = write_archive(&dir, codec, &encoded(codec, &small_tar()));
            let listed = list(&archive, REPLAY_LIMIT);
            assert!(listed.has_spool(), "{codec:?}");
            std::fs::remove_file(&archive).unwrap();

            extract_into(listed, &dir, &SecurityConfig::default()).unwrap();

            let extracted = std::fs::read(dir.path().join("out/a.txt")).unwrap();
            assert_eq!(extracted, CONTENT, "{codec:?}");
        }
    }

    #[test]
    fn replay_honours_atomic_extraction() {
        let dir = TempDir::new().unwrap();
        let archive = write_archive(
            &dir,
            CompressionCodec::Gzip,
            &encoded(CompressionCodec::Gzip, &small_tar()),
        );
        let listed = list(&archive, REPLAY_LIMIT);
        std::fs::remove_file(&archive).unwrap();
        let out = dir.path().join("out");
        let options = ExtractionOptions::default().with_atomic(true);

        listed
            .extract(
                &out,
                &SecurityConfig::default(),
                &options,
                &mut NoopProgress,
            )
            .unwrap();

        assert_eq!(std::fs::read(out.join("a.txt")).unwrap(), CONTENT);
    }

    #[test]
    fn zstd_and_plain_tar_keep_no_spool() {
        let dir = TempDir::new().unwrap();
        let zst = write_archive(
            &dir,
            CompressionCodec::Zstd,
            &encoded(CompressionCodec::Zstd, &small_tar()),
        );
        let plain = dir.path().join("a.tar");
        std::fs::write(&plain, small_tar()).unwrap();

        assert!(!list(&zst, REPLAY_LIMIT).has_spool());
        assert!(!list(&plain, REPLAY_LIMIT).has_spool());
    }

    #[test]
    fn a_decoded_stream_over_the_limit_keeps_no_spool_but_still_extracts() {
        let dir = TempDir::new().unwrap();
        let tar = create_test_tar(vec![("a.txt", &vec![b'z'; 100 * 1024])]);
        let bytes = encoded(CompressionCodec::Bzip2, &tar);
        let archive = write_archive(&dir, CompressionCodec::Bzip2, &bytes);
        let limit = 4096;
        assert!(bytes.len() as u64 <= limit);

        let listed = list(&archive, limit);

        assert!(!listed.has_spool());
        extract_into(listed, &dir, &SecurityConfig::default()).unwrap();
        assert_eq!(
            std::fs::read(dir.path().join("out/a.txt")).unwrap().len(),
            100 * 1024
        );
    }

    #[test]
    fn a_gzip_file_declaring_a_decoded_size_over_the_limit_is_not_spooled() {
        let dir = TempDir::new().unwrap();
        let tar = create_test_tar(vec![("a.txt", &vec![b'z'; 100 * 1024])]);
        let bytes = encoded(CompressionCodec::Gzip, &tar);
        let archive = write_archive(&dir, CompressionCodec::Gzip, &bytes);

        assert_eq!(gzip_decoded_size(&archive), Some(tar.len() as u64));
        assert!(!fits(&archive, CompressionCodec::Gzip, 4096));
        assert!(fits(&archive, CompressionCodec::Gzip, REPLAY_LIMIT));
        assert!(fits(&archive, CompressionCodec::Bzip2, 4096));
    }

    #[test]
    fn a_gzip_trailer_of_a_tiny_last_member_does_not_vouch_for_the_stream() {
        let dir = TempDir::new().unwrap();
        // High-entropy content keeps the first member's compressed size near
        // its decoded size, far above twice the tiny member's trailer size.
        let mut state = 0x9e37_79b9_7f4a_7c15_u64;
        let noise: Vec<u8> = (0..256 * 1024)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state.to_le_bytes()[0]
            })
            .collect();
        let large = encoded(
            CompressionCodec::Gzip,
            &create_test_tar(vec![("big.bin", &noise)]),
        );
        let tiny = encoded(CompressionCodec::Gzip, b"x");
        let archive = write_archive(&dir, CompressionCodec::Gzip, &[large, tiny].concat());

        assert_eq!(gzip_decoded_size(&archive), Some(1));
        assert!(!fits(&archive, CompressionCodec::Gzip, REPLAY_LIMIT));
        assert!(!list(&archive, REPLAY_LIMIT).has_spool());
    }

    #[test]
    fn a_compressed_file_over_the_limit_is_not_spooled() {
        let dir = TempDir::new().unwrap();
        let bytes = encoded(CompressionCodec::Gzip, &small_tar());
        let archive = write_archive(&dir, CompressionCodec::Gzip, &bytes);

        assert!(!list(&archive, bytes.len() as u64 - 1).has_spool());
    }

    #[test]
    fn a_trailer_failure_fails_the_list_pass_like_a_fresh_extraction() {
        let dir = TempDir::new().unwrap();
        let mut bytes = encoded(CompressionCodec::Gzip, &small_tar());
        let crc_at = bytes.len() - 8;
        bytes[crc_at] ^= 0xff;
        let archive = write_archive(&dir, CompressionCodec::Gzip, &bytes);
        let config = SecurityConfig::default();
        let fresh = TempDir::new().unwrap();
        let fresh_result = extract_archive_with_options_and_progress(
            &archive,
            fresh.path().join("out"),
            &config,
            &ExtractionOptions::default(),
            &mut NoopProgress,
        );

        let listed = list_with_limit(
            &archive,
            &config,
            ListOptions::default(),
            REPLAY_LIMIT,
            DecodeReuse::default(),
        );

        assert!(listed.is_err());
        assert!(fresh_result.is_err());
    }

    #[test]
    fn a_stricter_decoder_memory_decodes_again() {
        let dir = TempDir::new().unwrap();
        let archive = write_archive(
            &dir,
            CompressionCodec::Xz,
            &encoded(CompressionCodec::Xz, &small_tar()),
        );
        let listed = list(&archive, REPLAY_LIMIT);
        assert!(listed.has_spool());
        std::fs::remove_file(&archive).unwrap();
        let stricter = SecurityConfig::default().with_max_decoder_memory(1024 * 1024);

        assert!(extract_into(listed, &dir, &stricter).is_err());
    }

    #[test]
    fn a_smaller_member_allowance_decodes_again() {
        let dir = TempDir::new().unwrap();
        let tar = small_tar();
        let bytes: Vec<u8> = tar
            .chunks(512)
            .flat_map(|chunk| encoded(CompressionCodec::Gzip, chunk))
            .collect();
        let archive = write_archive(&dir, CompressionCodec::Gzip, &bytes);
        let listed = list(&archive, REPLAY_LIMIT);
        assert!(listed.has_spool());
        let stricter = SecurityConfig::default()
            .with_compressed_member_allowance(std::num::NonZeroU64::MIN.saturating_add(1));

        let error = match extract_into(listed, &dir, &stricter).unwrap_err() {
            crate::ArchiveError::PartialExtraction { source, .. } => *source,
            other => other,
        };

        assert_matches!(
            error,
            crate::ArchiveError::QuotaExceeded {
                resource: crate::QuotaResource::CompressedMembers { .. }
            }
        );
    }

    #[test]
    fn a_looser_decoder_memory_still_replays() {
        let dir = TempDir::new().unwrap();
        let archive = write_archive(
            &dir,
            CompressionCodec::Xz,
            &encoded(CompressionCodec::Xz, &small_tar()),
        );
        let listed = list(&archive, REPLAY_LIMIT);
        std::fs::remove_file(&archive).unwrap();
        let looser = SecurityConfig::default().with_max_decoder_memory(512 * 1024 * 1024);

        extract_into(listed, &dir, &looser).unwrap();
    }

    #[test]
    fn replay_enforces_the_extract_configs_quotas() {
        let dir = TempDir::new().unwrap();
        let tar = create_test_tar(vec![("a.txt", b"0123456789"), ("b.txt", b"0123456789")]);
        let archive = write_archive(
            &dir,
            CompressionCodec::Gzip,
            &encoded(CompressionCodec::Gzip, &tar),
        );
        for strict in [
            SecurityConfig::default().with_max_file_count(1),
            SecurityConfig::default().with_max_file_size(5),
        ] {
            let listed = list(&archive, REPLAY_LIMIT);
            assert!(listed.has_spool());
            let out = TempDir::new().unwrap();

            let result = listed.extract(
                out.path().join("out"),
                &strict,
                &ExtractionOptions::default(),
                &mut NoopProgress,
            );

            assert_eq!(result.unwrap_err().error_code(), ErrorCode::QuotaExceeded);
        }
    }

    #[test]
    fn replay_enforces_the_extract_configs_tar_metadata_limit() {
        let dir = TempDir::new().unwrap();
        let long_name = format!("{}/f.txt", crate::test_utils::path_of_len(900));
        let tar = create_test_tar(vec![(long_name.as_str(), b"x")]);
        let archive = write_archive(
            &dir,
            CompressionCodec::Gzip,
            &encoded(CompressionCodec::Gzip, &tar),
        );
        let listed = list(&archive, REPLAY_LIMIT);
        assert!(listed.has_spool());
        let strict = SecurityConfig::default().with_max_tar_metadata_bytes(512);

        let error = extract_into(listed, &dir, &strict).unwrap_err();

        assert_eq!(
            error.relaxable_by(),
            Some(crate::PolicySetting::MaxTarMetadataBytes),
            "{error:?}"
        );
    }

    #[test]
    fn bzip2_and_xz_files_over_the_compressed_limit_are_not_spooled() {
        for codec in [CompressionCodec::Bzip2, CompressionCodec::Xz] {
            let dir = TempDir::new().unwrap();
            let bytes = encoded(codec, &small_tar());
            let archive = write_archive(&dir, codec, &bytes);

            assert!(
                !list(&archive, bytes.len() as u64 - 1).has_spool(),
                "{codec:?}"
            );
            assert!(fits(&archive, codec, bytes.len() as u64), "{codec:?}");
        }
    }

    #[test]
    fn corrupt_payload_fails_the_list_pass() {
        let dir = TempDir::new().unwrap();
        let tar = create_test_tar(vec![("a.txt", &vec![b'q'; 64 * 1024])]);
        let mut bytes = encoded(CompressionCodec::Gzip, &tar);
        let middle = bytes.len() / 2;
        bytes[middle] ^= 0xff;
        let archive = write_archive(&dir, CompressionCodec::Gzip, &bytes);

        let result = list_archive_for_extraction(
            &archive,
            &SecurityConfig::default(),
            &ListOptions::default(),
            DecodeReuse::default(),
        );

        assert!(result.is_err());
    }

    struct Scripted(Vec<io::Result<&'static [u8]>>);

    impl Read for Scripted {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.0.is_empty() {
                return Ok(0);
            }
            self.0.remove(0).map(|chunk| {
                buf[..chunk.len()].copy_from_slice(chunk);
                chunk.len()
            })
        }
    }

    fn finish_scripted(script: Vec<io::Result<&'static [u8]>>, limit: u64) -> Option<Spool> {
        let mut tee = SpoolTee::new(Scripted(script), limit);
        let mut sink = [0; 8];
        while tee.read(&mut sink).is_ok_and(|n| n > 0) {}
        tee.finish_spool(&SecurityConfig::default().validate().unwrap())
    }

    const EIO: i32 = 5;

    /// Serves `inner` until `remaining` bytes were read, then fails every read.
    struct FailAfter {
        inner: io::Cursor<Vec<u8>>,
        remaining: usize,
    }

    impl Read for FailAfter {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.remaining == 0 {
                return Err(io::Error::from_raw_os_error(EIO));
            }
            let want = buf.len().min(self.remaining);
            let n = self.inner.read(&mut buf[..want])?;
            self.remaining -= n;
            Ok(n)
        }
    }

    fn replay_failing_after(bytes: &[u8], budget: usize) -> Result<ExtractionReport> {
        let dir = TempDir::new().unwrap();
        let spool = FailAfter {
            inner: io::Cursor::new(bytes.to_vec()),
            remaining: budget,
        };
        let config = SecurityConfig::default().validate().unwrap();
        replay_spool(
            spool,
            dir.path(),
            &config,
            &ExtractionOptions::default(),
            &mut NoopProgress,
        )
    }

    fn io_root(error: &crate::ArchiveError) -> &crate::ArchiveError {
        match error {
            crate::ArchiveError::PartialExtraction { source, .. } => io_root(source),
            other => other,
        }
    }

    #[test]
    fn a_spool_read_fault_is_io_with_its_errno_at_every_position() {
        let tar = create_test_tar(vec![
            ("a.txt", &[1u8; 3000][..]),
            ("dir/b.bin", &[2u8; 5000][..]),
            ("c.txt", CONTENT),
        ]);

        for budget in (0..tar.len()).step_by(11) {
            let error = replay_failing_after(&tar, budget).unwrap_err();
            assert_matches!(
                io_root(&error),
                crate::ArchiveError::Io(e) if e.raw_os_error() == Some(EIO),
                "budget {budget}: {error:?}"
            );
        }
        replay_failing_after(&tar, tar.len() + 1).unwrap();
    }

    #[test]
    fn tee_spools_a_clean_stream_and_rewinds_it() {
        let spool = finish_scripted(vec![Ok(b"abc"), Ok(b"def")], 100).unwrap();

        let mut copy = Vec::new();
        let mut file = spool.file;
        file.read_to_end(&mut copy).unwrap();
        assert_eq!(copy, b"abcdef");
    }

    #[test]
    fn tee_latches_a_decoder_error_even_when_the_decoder_then_reports_the_end() {
        let script = vec![Ok(&b"abc"[..]), Err(io::Error::other("bad")), Ok(&b""[..])];

        assert!(finish_scripted(script, 100).is_none());
    }

    #[test]
    fn tee_drops_the_spool_at_the_limit() {
        assert!(finish_scripted(vec![Ok(b"abcd"), Ok(b"efgh")], 7).is_none());
    }
}

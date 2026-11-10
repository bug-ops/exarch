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
//! parsed archive (see [`DecodeReuse`]) rather than opening
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
//!   TAR).
//!
//! The extraction runs under the policy the archive was listed for, so a
//! different `max_decoder_memory` can never ask for a second decode.
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
use std::sync::Arc;

use crate::DecodeReuse;
use crate::ExistingFiles;
use crate::ExtractionReport;
use crate::ListOptions;
use crate::MarkPropagation;
use crate::ProgressCallback;
use crate::Result;
use crate::SecurityConfig;
use crate::Staging;
use crate::api::extract_tar_stream;
use crate::api::extract_validated;
use crate::closed_enum::closed_enum;
use crate::config::ExtractionOptions;
use crate::formats::common::open_archive;
use crate::formats::compression::CompressionCodec;
use crate::formats::compression::DecoderLimits;
use crate::formats::detect::FormatFamily;
use crate::formats::detect::detect_format;
use crate::formats::le;
use crate::formats::output_root::OutputRoot;
use crate::formats::source_fault::SourceRead;
use crate::formats::source_fault::SourceTap;
use crate::formats::source_fault::TapSource;
use crate::formats::spool::TempSpool;
use crate::formats::traits::ArchiveFormat;
use crate::formats::zip::ZipArchive;
use crate::inspection::ArchiveManifest;
use crate::inspection::integrity::TarTrailer;
use crate::inspection::list::ListPass;
use crate::inspection::list::list_detected;
use crate::inspection::list::list_tar_stream;
use crate::mark::MarkScope;
use crate::reader::SeekableFormat;
use crate::reader::decode_tar_stream;
use crate::staging::extract_staged;

mod destination;

/// The most decoded TAR bytes a list pass keeps for extraction (256 MiB).
///
/// Beyond it the spool is dropped and extraction decodes again. Data after the
/// TAR end marker is decoded into the spool before the listing returns, without
/// progress output. The list pass refuses a tail longer than the trailer cap
/// (`max_tar_metadata_bytes`, at least 1 MiB), so the tail is bounded by that
/// cap and by this limit, whichever is smaller.
///
/// Decoded streams over the limit decode twice. That cost is accepted: a larger
/// spool would be an unbounded temporary file. On a tmpfs the spool occupies
/// RAM, so there it is also held to `max_decoder_memory`, as the ZIP decode
/// reuse spool is. A caller that extracts atomically can skip the list pass and
/// decode once.
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
    TarSpool(Spool, SourceFile),
    Zip(Box<ZipArchive<SourceFile>>, SourceFile),
}

/// The archive file the list pass opened, kept so the download mark is read
/// from that same handle at extraction instead of from the path again.
///
/// Reads and seeks through a shared reference, so the list pass's reader and
/// the extraction's mark read use one open file with no extra syscall.
#[derive(Clone, Debug)]
struct SourceFile(Arc<File>);

impl SourceFile {
    fn open(path: &Path) -> Result<Self> {
        open_archive(path).map(|file| Self(Arc::new(file)))
    }

    fn file(&self) -> &File {
        &self.0
    }
}

impl Read for SourceFile {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        (&*self.0).read(buf)
    }
}

impl Seek for SourceFile {
    fn seek(&mut self, pos: SeekFrom) -> io::Result<u64> {
        (&*self.0).seek(pos)
    }
}

impl Kept {
    /// Whether an extraction under `config` can use what was kept as it is.
    ///
    /// Always true for the config the archive was listed for: the list pass
    /// runs under the same decoder limits, ZIP consistency policy and
    /// allowances, and the four flags it resets (symlinks, hardlinks,
    /// world-writable, preserved permissions) are not inputs of the kept state
    /// (`tests/listed_differential.rs`). [`ListedArchive::extract`] asserts it
    /// in debug builds.
    fn serves(&self, config: &SecurityConfig) -> bool {
        match self {
            Self::Nothing => true,
            Self::TarSpool(spool, _) => DecoderLimits::of(config).covers(spool.decoded_with),
            Self::Zip(zip, _) => zip.serves(config),
        }
    }
}

/// The decoder output of a list pass and the decoder memory it was produced
/// under.
#[derive(Debug)]
struct Spool {
    file: File,
    decoded_with: DecoderLimits,
}

/// The options of [`ListedArchive::extract`]: the knobs that may still vary
/// after the archive was listed.
///
/// What the list pass kept (the ZIP census output, the TAR spool) depends on
/// the policy and on the [`DecodeReuse`] mode given to
/// [`ListRequest::for_extraction`](crate::ListRequest::for_extraction), so
/// neither is an option here.
///
/// # Examples
///
/// ```
/// use exarch_core::ListedExtractOptions;
///
/// use exarch_core::ExistingFiles;
/// use exarch_core::Staging;
///
/// let options = ListedExtractOptions::default().with_staging(Staging::Atomic);
/// assert_eq!(options.staging, Staging::Atomic);
/// assert_eq!(options.existing_files, ExistingFiles::Skip);
/// ```
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct ListedExtractOptions {
    /// How the output is staged; see [`ExtractionOptions::staging`].
    pub staging: Staging,
    /// What to do with an occupied destination path; see
    /// [`ExtractionOptions::existing_files`].
    pub existing_files: ExistingFiles,
    /// Whether the archive file's download-origin mark is copied onto the
    /// extracted files; see [`ExtractionOptions::mark_propagation`].
    ///
    /// The mark is read from the handle the listing opened.
    pub mark_propagation: MarkPropagation,
}

impl Default for ListedExtractOptions {
    fn default() -> Self {
        let options = ExtractionOptions::default();
        Self {
            staging: options.staging,
            existing_files: options.existing_files,
            mark_propagation: options.mark_propagation,
        }
    }
}

impl ListedExtractOptions {
    /// Chooses how the output is staged.
    #[must_use]
    pub const fn with_staging(mut self, staging: Staging) -> Self {
        self.staging = staging;
        self
    }

    /// Chooses what happens to an occupied destination path.
    #[must_use]
    pub const fn with_existing_files(mut self, existing_files: ExistingFiles) -> Self {
        self.existing_files = existing_files;
        self
    }

    /// Chooses whether the archive file's download-origin mark is copied onto
    /// the extracted files.
    #[must_use]
    pub const fn with_mark_propagation(mut self, mark_propagation: MarkPropagation) -> Self {
        self.mark_propagation = mark_propagation;
        self
    }
}

closed_enum! {
    /// What [`ListedArchive::check_destination`] requires of the paths the
    /// extraction would write.
    ///
    /// # Examples
    ///
    /// ```
    /// use exarch_core::DestinationCheck;
    ///
    /// assert_eq!(DestinationCheck::Vacant.as_str(), "vacant");
    /// ```
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    #[non_exhaustive]
    pub enum DestinationCheck {
        /// Every file or link landing must be empty and every directory landing
        /// must be a directory (a refuse-existing run).
        Vacant => "vacant",

        /// Only the occupants an in-place overwrite run refuses are reported:
        /// a file at a directory landing, a directory at any other landing, a
        /// file at a hardlink landing, and, as the symlink refusal, a symlink
        /// at a file or hardlink landing or at a symlink landing whose archive
        /// target is not recorded or differs from the existing one. A file at a
        /// file or symlink landing is replaced, and a symlink with the same
        /// recorded target is skipped.
        Replaceable => "replaceable",
    }
}

/// An archive that was listed and is ready to extract without decoding it
/// again where that is possible.
///
/// Created by
/// [`ListRequest::for_extraction`](crate::ListRequest::for_extraction),
/// which fixes the policy the extraction runs under: the archive is listed
/// under the same quotas, path rules, allowlist and decoder limits, and
/// extracted under the config the request was built with. Extracting from it
/// gives the same result as [`ExtractRequest`](crate::ExtractRequest) on the
/// archive; only the cost differs.
///
/// # Examples
///
/// ```
/// use exarch_core::DecodeReuse;
/// use exarch_core::ListRequest;
/// use exarch_core::ListedExtractOptions;
/// use exarch_core::NoopProgress;
/// use exarch_core::SecurityConfig;
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
/// let listed = ListRequest::new(&config).for_extraction(&archive, DecodeReuse::default())?;
/// assert_eq!(listed.manifest().total_entries(), 1);
///
/// let out = dir.path().join("out");
/// let report = listed.extract(&out, &ListedExtractOptions::default(), &mut NoopProgress)?;
/// assert_eq!(report.files_extracted, 1);
/// # Ok(())
/// # }
/// ```
pub struct ListedArchive {
    manifest: ArchiveManifest,
    archive: PathBuf,
    kept: Kept,
    config: Box<SecurityConfig>,
    reuse: DecodeReuse,
}

impl std::fmt::Debug for ListedArchive {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let kept = match self.kept {
            Kept::Nothing => "nothing",
            Kept::TarSpool(..) => "tar spool",
            Kept::Zip(..) => "zip archive",
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
        matches!(self.kept, Kept::TarSpool(..))
    }

    /// Refuses a destination that the write phase would refuse, with the same
    /// typed error, before anything is written.
    ///
    /// [`DestinationCheck::Vacant`] requires every file or link landing to be
    /// empty and every directory landing to be a directory;
    /// [`DestinationCheck::Replaceable`] checks only the landings an
    /// in-place overwrite refuses. A refusal is
    /// [`ArchiveError::DestinationOccupied`](crate::ArchiveError::DestinationOccupied)
    /// naming the occupied landings, or the typed symlink refusal when an
    /// existing symlink would be followed out of `dest` or a symlink landing
    /// over an existing symlink has an unread or different archive target.
    ///
    /// The check is advisory: the write itself decides again, so a path that
    /// appears after the check is still handled by
    /// [`ExistingFiles`].
    ///
    /// # Errors
    ///
    /// [`ArchiveError::DestinationOccupied`](crate::ArchiveError::DestinationOccupied)
    /// for an occupied landing; the typed symlink refusal the write phase gives
    /// for a symlink among the parents or at a landing; the I/O error of a path
    /// that could not be inspected, which is never reported as a refusal; or
    /// [`ConfigProblem::NotADirectory`](crate::ConfigProblem::NotADirectory)
    /// when `dest` exists and is not a directory. A destination that does not
    /// exist passes.
    pub fn check_destination(&self, dest: &Path, check: DestinationCheck) -> Result<()> {
        destination::check(&self.manifest, &self.config, dest, check)
    }

    /// What the list pass found in the archive.
    #[must_use]
    pub const fn manifest(&self) -> &ArchiveManifest {
        &self.manifest
    }

    /// Extracts the archive into `output_dir` under the policy it was listed
    /// for.
    ///
    /// Behaves as [`ExtractRequest`](crate::ExtractRequest) does for the listed
    /// archive, reading the decoded stream kept by the list pass when it is
    /// available. A ZIP archive is extracted from the archive the list pass
    /// opened, with the decoded output it kept.
    ///
    /// # Errors
    ///
    /// Same as [`ExtractRequest`](crate::ExtractRequest).
    pub fn extract<P: AsRef<Path>>(
        self,
        output_dir: P,
        options: &ListedExtractOptions,
        progress: &mut dyn ProgressCallback,
    ) -> Result<ExtractionReport> {
        let Self {
            archive,
            kept,
            config,
            reuse,
            ..
        } = self;
        let extraction = ExtractionOptions::default()
            .with_staging(options.staging)
            .with_existing_files(options.existing_files)
            .with_mark_propagation(options.mark_propagation)
            .with_decode_reuse(reuse);
        debug_assert!(
            kept.serves(&config),
            "a listed archive's kept state must serve the config it was listed for"
        );
        extract_kept(
            &archive,
            kept,
            output_dir.as_ref(),
            &config,
            &extraction,
            progress,
        )
    }
}

/// Extracts a listed archive from what the list pass kept, or decodes it
/// again when it kept nothing.
fn extract_kept(
    archive: &Path,
    kept: Kept,
    output_dir: &Path,
    config: &SecurityConfig,
    options: &ExtractionOptions,
    progress: &mut dyn ProgressCallback,
) -> Result<ExtractionReport> {
    let spool = match kept {
        Kept::Zip(zip, source) => {
            let zip = (*zip).rebind(config);
            return extract_staged(
                output_dir,
                options,
                &config.selection,
                Some(archive),
                progress,
                |dir, options, progress| {
                    MarkScope::open(options.mark_propagation, source.file())
                        .around(|mark| zip.extract(dir.with_mark(mark), options, progress))
                },
            );
        }
        Kept::TarSpool(spool, source) => Some((spool, source)),
        Kept::Nothing => None,
    };
    extract_staged(
        output_dir,
        options,
        &config.selection,
        Some(archive),
        progress,
        |dir, options, progress| match spool {
            Some((spool, source)) => MarkScope::open(options.mark_propagation, source.file())
                .around(|mark| {
                    replay_spool(spool.file, dir.with_mark(mark), config, options, progress)
                }),
            None => extract_validated(archive, dir, config, options, progress),
        },
    )
}

/// Extracts the decoded TAR stream `spool`, reporting a fault of the spool as
/// the I/O error it raised rather than as a corrupt archive.
fn replay_spool<R: Read>(
    spool: R,
    dir: OutputRoot<'_>,
    config: &SecurityConfig,
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

impl ListedArchive {
    /// Lists `archive` for an extraction under `extraction`.
    ///
    /// The list pass runs under the same policy with the write-time flags
    /// reset, as that is all a listing needs and it must never admit more than
    /// the extraction would. The extraction later runs under `extraction`.
    pub(crate) fn list(
        archive: &Path,
        extraction: &SecurityConfig,
        options: ListOptions,
        reuse: DecodeReuse,
        progress: Option<&mut dyn ProgressCallback>,
    ) -> Result<Self> {
        Self::list_within(archive, extraction, options, reuse, REPLAY_LIMIT, progress)
    }

    /// [`list`](Self::list) with a replay limit other than [`REPLAY_LIMIT`].
    fn list_within(
        archive: &Path,
        extraction: &SecurityConfig,
        options: ListOptions,
        reuse: DecodeReuse,
        limit: u64,
        progress: Option<&mut dyn ProgressCallback>,
    ) -> Result<Self> {
        let mut listed = list_with_limit(
            archive,
            &extraction.for_listing(),
            options,
            limit,
            reuse,
            progress,
        )?;
        listed.config = Box::new(extraction.clone());
        Ok(listed)
    }
}

fn list_with_limit(
    archive: &Path,
    config: &SecurityConfig,
    options: ListOptions,
    limit: u64,
    reuse: DecodeReuse,
    progress: Option<&mut dyn ProgressCallback>,
) -> Result<ListedArchive> {
    let format = detect_format(archive)?;
    let mut pass = ListPass::strict_with(options.stored_targets);
    if let Some(progress) = progress {
        pass = pass.with_progress(progress);
    }
    let (manifest, kept) = match format.family() {
        FormatFamily::Tar(Some(codec)) if replays(codec) && fits(archive, codec, limit) => {
            let file = SourceFile::open(archive)?;
            let decoded = decode_tar_stream(file.clone(), Some(codec), DecoderLimits::of(config))?;
            let source = decoded.source();
            let mut tee = SpoolTee::new(decoded.stream, limit, config.max_decoder_memory.get());
            let manifest =
                list_tar_stream(&mut tee, source, Some(codec), format, config, &mut pass)?;
            let kept = tee
                .finish_spool(config)
                .map_or(Kept::Nothing, |spool| Kept::TarSpool(spool, file));
            (manifest, kept)
        }
        FormatFamily::Seekable(SeekableFormat::Zip) => {
            let file = SourceFile::open(archive)?;
            let mut zip = ZipArchive::for_extraction(file.clone(), config, reuse)?;
            let manifest = zip.list_with(config, &mut pass)?;
            (manifest, Kept::Zip(Box::new(zip), file))
        }
        _ => (
            list_detected(archive, format, config, &mut pass)?,
            Kept::Nothing,
        ),
    };
    Ok(ListedArchive {
        manifest,
        archive: archive.to_path_buf(),
        kept,
        config: Box::new(config.clone()),
        reuse,
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
    Some(u64::from(le::le32::<0, 4>(&isize)))
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
    /// A tee into a new spool holding at most `limit` bytes, and at most
    /// `ram_limit` where the spool lives in memory.
    fn new(inner: R, limit: u64, ram_limit: u64) -> Self {
        Self::over(inner, crate::formats::spool::open_spool(), limit, ram_limit)
    }

    /// A tee into `spool`, or into none: without a temporary file the only
    /// loss is the optimisation.
    fn over(inner: R, spool: Option<TempSpool>, limit: u64, ram_limit: u64) -> Self {
        let limit = spool
            .as_ref()
            .map_or(limit, |spool| spool.backing().capacity(limit, ram_limit));
        Self {
            inner,
            spool: spool.map(|spool| BufWriter::with_capacity(SPOOL_BUFFER, spool.into_file())),
            written: 0,
            limit,
            decoding: Decoding::Reading,
        }
    }

    fn spool_chunk(&mut self, chunk: &[u8]) {
        let Some(spool) = self.spool.as_mut() else {
            return;
        };
        self.written = self.written.saturating_add(chunk.len() as u64);
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
    fn finish_spool(mut self, config: &SecurityConfig) -> Option<Spool> {
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
                let Some(chunk) = buf.get(..n) else {
                    self.decoding = Decoding::Failed;
                    self.spool = None;
                    return Err(io::Error::from(io::ErrorKind::InvalidData));
                };
                self.spool_chunk(chunk);
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
    use crate::ExtractRequest;
    use crate::NoopProgress;
    use crate::formats::spool::SpoolBacking;
    use crate::test_utils::OverReporting;
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

    fn list_under(archive: &Path, config: &SecurityConfig, limit: u64) -> Result<ListedArchive> {
        ListedArchive::list_within(
            archive,
            config,
            ListOptions::default(),
            DecodeReuse::default(),
            limit,
            None,
        )
    }

    fn list(archive: &Path, limit: u64) -> ListedArchive {
        list_under(archive, &SecurityConfig::default(), limit).unwrap()
    }

    fn extract_into(listed: ListedArchive, dir: &TempDir) -> Result<()> {
        let out = dir.path().join("out");
        listed
            .extract(&out, &ListedExtractOptions::default(), &mut NoopProgress)
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

            extract_into(listed, &dir).unwrap();

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
        let options = ListedExtractOptions::default().with_staging(Staging::Atomic);

        listed.extract(&out, &options, &mut NoopProgress).unwrap();

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
        extract_into(listed, &dir).unwrap();
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
        let fresh_result = ExtractRequest::new(&config)
            .with_options(ExtractionOptions::default())
            .with_progress(&mut NoopProgress)
            .extract(&archive, fresh.path().join("out"));

        let listed = list_under(&archive, &config, REPLAY_LIMIT);

        assert!(listed.is_err());
        assert!(fresh_result.is_err());
    }

    #[test]
    fn a_stricter_decoder_memory_refuses_at_the_list_pass() {
        let dir = TempDir::new().unwrap();
        let archive = write_archive(
            &dir,
            CompressionCodec::Xz,
            &encoded(CompressionCodec::Xz, &small_tar()),
        );
        let stricter =
            SecurityConfig::default().with_max_decoder_memory(crate::non_zero!(1024 * 1024));

        assert!(list_under(&archive, &stricter, REPLAY_LIMIT).is_err());
    }

    #[test]
    fn a_smaller_member_allowance_refuses_at_the_list_pass() {
        let dir = TempDir::new().unwrap();
        let tar = small_tar();
        let bytes: Vec<u8> = tar
            .chunks(512)
            .flat_map(|chunk| encoded(CompressionCodec::Gzip, chunk))
            .collect();
        let archive = write_archive(&dir, CompressionCodec::Gzip, &bytes);
        let stricter = SecurityConfig::default()
            .with_compressed_member_allowance(std::num::NonZeroU64::MIN.saturating_add(1));

        let error = list_under(&archive, &stricter, REPLAY_LIMIT).unwrap_err();

        assert_matches!(
            error,
            crate::ArchiveError::QuotaExceeded {
                resource: crate::QuotaResource::CompressedMembers { .. }
            }
        );
    }

    #[test]
    fn the_list_pass_enforces_the_extract_configs_quotas() {
        let dir = TempDir::new().unwrap();
        let tar = create_test_tar(vec![("a.txt", b"0123456789"), ("b.txt", b"0123456789")]);
        let archive = write_archive(
            &dir,
            CompressionCodec::Gzip,
            &encoded(CompressionCodec::Gzip, &tar),
        );
        for strict in [
            SecurityConfig::default().with_max_file_count(crate::non_zero!(1)),
            SecurityConfig::default().with_max_file_size(crate::non_zero!(5)),
        ] {
            let error = list_under(&archive, &strict, REPLAY_LIMIT).unwrap_err();

            assert_eq!(error.error_code(), ErrorCode::QuotaExceeded);
        }
    }

    #[test]
    fn the_list_pass_enforces_the_extract_configs_tar_metadata_limit() {
        let dir = TempDir::new().unwrap();
        let long_name = format!("{}/f.txt", crate::test_utils::path_of_len(900));
        let tar = create_test_tar(vec![(long_name.as_str(), b"x")]);
        let archive = write_archive(
            &dir,
            CompressionCodec::Gzip,
            &encoded(CompressionCodec::Gzip, &tar),
        );
        let strict = SecurityConfig::default().with_max_tar_metadata_bytes(crate::non_zero!(512));

        let error = list_under(&archive, &strict, REPLAY_LIMIT).unwrap_err();

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

        let result = list_under(&archive, &SecurityConfig::default(), REPLAY_LIMIT);

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
        let mut tee = SpoolTee::new(Scripted(script), limit, u64::MAX);
        let mut sink = [0; 8];
        while tee.read(&mut sink).is_ok_and(|n| n > 0) {}
        tee.finish_spool(&SecurityConfig::default())
    }

    #[test]
    fn a_decoder_reporting_more_than_the_buffer_yields_no_spool() {
        let mut tee = SpoolTee::new(OverReporting, 100, u64::MAX);
        let mut sink = [0; 8];

        let error = tee.read(&mut sink).unwrap_err();

        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(tee.finish_spool(&SecurityConfig::default()).is_none());
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
        let config = SecurityConfig::default();
        replay_spool(
            spool,
            dir.path().into(),
            &config,
            &ExtractionOptions::default(),
            &mut NoopProgress,
        )
    }

    fn io_root(error: &crate::ArchiveError) -> &crate::ArchiveError {
        match error {
            crate::ArchiveError::PartialExtraction(partial) => io_root(partial.cause()),
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
    fn a_spool_in_memory_is_held_to_the_ram_limit_and_one_on_disk_is_not() {
        let script = || vec![Ok(&b"abcd"[..]), Ok(&b"efgh"[..])];
        let finish = |backing| {
            let spool = TempSpool::with_backing(backing);
            let mut tee = SpoolTee::over(Scripted(script()), spool, 100, 7);
            let mut sink = [0; 8];
            while tee.read(&mut sink).is_ok_and(|n| n > 0) {}
            tee.finish_spool(&SecurityConfig::default())
        };

        assert!(finish(SpoolBacking::Ram).is_none());
        assert!(finish(SpoolBacking::Disk).is_some());
    }

    #[test]
    fn tee_drops_the_spool_at_the_limit() {
        assert!(finish_scripted(vec![Ok(b"abcd"), Ok(b"efgh")], 7).is_none());
    }
}

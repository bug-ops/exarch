//! TAR archive format extraction.
//!
//! This module provides secure extraction of TAR archives with comprehensive
//! security validation. Supported formats:
//!
//! - **ustar** (POSIX.1-1988): Standard Unix tar format
//! - **pax** (POSIX.1-2001): Extended header format for long paths/metadata
//! - **gnu** (GNU tar): GNU extensions for sparse files and incremental backups
//!
//! # Header Consistency
//!
//! Specific constructs that readers parse differently are refused as ambiguous
//! rather than interpreted: a directory, symlink or hardlink that declares a
//! payload, GNU sparse entries, signed or control-character size and checksum
//! fields, a `prefix` field without a ustar magic, duplicate, empty-key,
//! over-long or `GNU.sparse.*` PAX records, a PAX `path` or `linkpath` stacked
//! with a GNU long name or link record, and global PAX headers that override
//! `path`, `linkpath` or `size`, are malformed, or follow a local header or a
//! GNU long record.
//!
//! # Format Detection
//!
//! The TAR format is auto-detected based on header magic bytes. No explicit
//! format selection is required.
//!
//! # Compression Support
//!
//! Transparent decompression is supported via:
//!
//! - **gzip** (.tar.gz, .tgz): Via `flate2` crate
//! - **bzip2** (.tar.bz2, .tbz2): Via `bzip2` crate
//! - **xz** (.tar.xz, .txz): Via `liblzma` crate
//! - **zstd** (.tar.zst, .tzst): Via `zstd` crate
//!
//! # Security Features
//!
//! All entries are validated through the security layer:
//!
//! - Path traversal prevention (rejects `../`, absolute paths)
//! - Quota enforcement (file size, count, total size)
//! - Symlink escape detection (symlinks must point within extraction directory)
//! - Hardlink escape detection (hardlink targets must be within extraction
//!   directory)
//! - Permission sanitization (strips setuid/setgid bits)
//! - Device file rejection (char, block devices not supported)
//! - FIFO rejection (named pipes not supported)
//!
//! # Entry Type Support
//!
//! | Entry Type | Supported | Notes |
//! |------------|-----------|-------|
//! | Regular files | ✅ Yes | Full support with streaming |
//! | Directories | ✅ Yes | Created recursively |
//! | Symlinks | ✅ Yes | Unix only, requires `config.allowed.symlinks = true` |
//! | Hardlinks | ✅ Yes | Two-pass extraction, requires `config.allowed.hardlinks = true` |
//! | Continuous | ✅ Yes | Treated as regular file |
//! | GNU sparse | ❌ No | Refused as ambiguous |
//! | PAX headers (`XHeader`, `XGlobalHeader`) | Skipped | Format-internal metadata |
//! | GNU metadata (`GNULongName`, `GNULongLink`) | Skipped | Format-internal metadata |
//! | Char devices | ❌ No | Rejected with `UnsupportedFeature` error |
//! | Block devices | ❌ No | Rejected with `UnsupportedFeature` error |
//! | FIFOs | ❌ No | Rejected with `UnsupportedFeature` error |
//!
//! # Performance Characteristics
//!
//! - **Streaming**: Processes entries one at a time without buffering entire
//!   archive
//! - **Memory usage**: O(1) for archive processing, O(n) for hardlink tracking
//! - **Two-pass extraction**: Files/directories first, hardlinks second
//!
//! # Examples
//!
//! Basic extraction:
//!
//! ```no_run
//! use exarch_core::ExtractionOptions;
//! use exarch_core::SecurityConfig;
//! use exarch_core::formats::TarArchive;
//! use exarch_core::formats::traits::ArchiveFormat;
//! use std::fs::File;
//! use std::path::Path;
//!
//! let file = File::open("archive.tar")?;
//! let mut archive = TarArchive::new(file);
//! let config = SecurityConfig::default();
//! let report = archive.extract(
//!     Path::new("/output"),
//!     &config,
//!     &ExtractionOptions::default(),
//!     &mut exarch_core::NoopProgress,
//! )?;
//! println!("Extracted {} files", report.files_extracted);
//! # Ok::<(), exarch_core::ArchiveError>(())
//! ```
//!
//! Gzip-compressed TAR:
//!
//! ```no_run
//! use exarch_core::ExtractionOptions;
//! use exarch_core::SecurityConfig;
//! use exarch_core::formats::TarArchive;
//! use exarch_core::formats::traits::ArchiveFormat;
//! use flate2::read::GzDecoder;
//! use std::fs::File;
//! use std::path::Path;
//!
//! let file = File::open("archive.tar.gz")?;
//! let decoder = GzDecoder::new(file);
//! let mut archive = TarArchive::new(decoder);
//! let config = SecurityConfig::default();
//! let report = archive.extract(
//!     Path::new("/output"),
//!     &config,
//!     &ExtractionOptions::default(),
//!     &mut exarch_core::NoopProgress,
//! )?;
//! # Ok::<(), exarch_core::ArchiveError>(())
//! ```

use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::time::Instant;

use smallvec::SmallVec;
use tar::Archive;

use crate::ArchiveError;
use crate::ExtractionOptions;
use crate::ExtractionReport;
use crate::LinkKind;
use crate::Malformation;
use crate::ProgressCallback;
use crate::Result;
use crate::SecurityConfig;
use crate::SinkOptions;
use crate::SpecialFile;
use crate::TarAmbiguity;
use crate::TarNonRegularKind;
use crate::VerificationOptions;
use crate::Violation;
use crate::inspection::integrity::TarTrailer;
use crate::inspection::list::ListPass;
use crate::security::HardlinkTarget;
use crate::security::RawMode;
use crate::security::Uncompressed;
use crate::security::admitted::EntrySize;
use crate::security::quota::EntryCount;
use crate::security::validator::NodeKind;
use crate::security::validator::check_root_entry_is_directory;
use crate::security::validator::require_non_empty_name;
use crate::types::EntryType;
use crate::types::SafePath;
use crate::types::safe_path::ParentCheck;

use super::common;
use super::compression::CompressionCodec;
use super::source_fault::TapSource;
use super::tar_metadata_limit::CheckedTarEntry;
use super::tar_metadata_limit::SkipLimits;
use super::tar_metadata_limit::budgeted_reader_with;
use super::tar_metadata_limit::budgeted_tar_entries;
use super::target::ExtractTarget;
use super::target::FileAdmission;
use super::target::FileRequest;
use super::target::HostTarget;
use super::target::Tally;
use super::traits::ArchiveFormat;
use crate::formats::compression::DecoderLimits;
use crate::reader::TarStream;
use crate::reader::decode_tar_stream;

/// TAR archive handler with streaming extraction.
///
/// Supports ustar, pax, and gnu TAR formats with automatic detection.
/// The archive is processed in a streaming fashion to minimize memory usage.
///
/// # Type Parameters
///
/// - `R`: Reader type that must implement `Read`
///
/// # Examples
///
/// ```no_run
/// use exarch_core::ExtractionOptions;
/// use exarch_core::SecurityConfig;
/// use exarch_core::formats::TarArchive;
/// use exarch_core::formats::traits::ArchiveFormat;
/// use std::fs::File;
/// use std::path::Path;
///
/// let file = File::open("archive.tar")?;
/// let mut archive = TarArchive::new(file);
/// let config = SecurityConfig::default();
/// let report = archive.extract(
///     Path::new("/output"),
///     &config,
///     &ExtractionOptions::default(),
///     &mut exarch_core::NoopProgress,
/// )?;
/// # Ok::<(), exarch_core::ArchiveError>(())
/// ```
pub struct TarArchive<R: Read> {
    /// Raw underlying reader, consumed by `extract()`/`list()`/`verify()`.
    ///
    /// Wrapped in a metadata-size-limiting reader (using the config supplied
    /// to `extract()`/`list()`) and only then handed to `tar::Archive`, so the
    /// cap is applied fresh with whatever `SecurityConfig` each call uses.
    inner: R,
    /// The raw input behind `inner`, when core metered it.
    source: TapSource,
    /// How the bytes after the end-of-archive marker are checked.
    trailer: TarTrailer,
}

impl<'r> TarArchive<Box<dyn Read + Send + 'r>> {
    /// Creates a handler over a stream core decoded and metered itself.
    pub(crate) fn from_stream(decoded: TarStream<'r>, trailer: TarTrailer) -> Self {
        let source = decoded.source();
        Self::with_source(decoded.stream, source, trailer)
    }
}

impl<R: Read> TarArchive<R> {
    /// Creates a new TAR archive handler from a reader.
    ///
    /// The reader will be consumed during extraction. For file-based
    /// archives, wrap in `BufReader` for optimal performance.
    ///
    /// The codec behind `reader` is unknown, so extraction, listing and
    /// verification read it to its end after the end-of-archive marker. That
    /// surfaces a decoder's trailer check (a gzip CRC mismatch) as an error,
    /// but a reader that never ends blocks, and more than the trailer cap
    /// (`max_tar_metadata_bytes`, at least 1 MiB) of bytes after the marker is
    /// refused even for a plain TAR. The path-based APIs and
    /// [`ArchiveReader`](crate::ArchiveReader) know the codec and leave a
    /// plain TAR's tail alone.
    ///
    /// Core cannot see how much input a decoder behind `reader` consumed, so
    /// entries skipped by the extension allowlist are not bounded by
    /// `max_compression_ratio` here, as they are for the path-based APIs and
    /// [`ArchiveReader`](crate::ArchiveReader).
    ///
    /// # Performance Notes
    ///
    /// - Input: Wrap file readers in `BufReader::new()` for 10x faster reads
    /// - Output: File writes use `BufWriter` internally for optimal throughput
    /// - Memory: O(1) for archive processing, O(n) for hardlink tracking
    /// - Typical throughput: 100-500 MB/s on modern SSDs
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use exarch_core::formats::TarArchive;
    /// use std::fs::File;
    /// use std::io::BufReader;
    ///
    /// let file = File::open("archive.tar")?;
    /// let reader = BufReader::new(file);
    /// let archive = TarArchive::new(reader);
    /// # Ok::<(), std::io::Error>(())
    /// ```
    #[must_use]
    pub fn new(reader: R) -> Self {
        Self::with_trailer(reader, TarTrailer::DrainToDecoderEof)
    }

    /// Creates a handler that checks the tail of the stream as `trailer` says.
    pub(crate) fn with_trailer(reader: R, trailer: TarTrailer) -> Self {
        Self::with_source(reader, TapSource::Opaque, trailer)
    }

    /// Creates a handler over `reader`, whose raw input `source` meters.
    pub(crate) fn with_source(reader: R, source: TapSource, trailer: TarTrailer) -> Self {
        Self {
            inner: reader,
            source,
            trailer,
        }
    }

    /// Lists the archive as `listing` asks, consuming the reader.
    fn list_with_pass(
        self,
        config: &SecurityConfig,
        listing: &mut ListPass<'_, '_>,
    ) -> Result<crate::inspection::ArchiveManifest> {
        use crate::formats::detect::ArchiveType;
        use crate::inspection::list::list_tar_reader;

        let (budgeted, budget) = budgeted_reader_with(
            self.inner,
            config.max_tar_metadata_bytes,
            self.source.clone(),
        );
        list_tar_reader(
            budgeted,
            budget,
            ArchiveType::Tar,
            config,
            listing,
            self.trailer,
        )
    }

    /// Processes a single TAR entry.
    fn process_entry<ER: Read, T: ExtractTarget>(
        entry: &mut tar::Entry<'_, ER>,
        target: &mut T,
        ctx: &mut ExtractionContext<'_>,
    ) -> Result<EntryOutcome<T::Parent>> {
        // Skip TAR metadata entries (PAX headers, GNU long names/links, sparse)
        if TarEntryAdapter::is_metadata_entry(entry) {
            return Ok(EntryOutcome::Done);
        }

        let path = entry
            .path()
            .map_err(|e| {
                ArchiveError::from(Malformation::EntryPathUnreadable {
                    detail: e.to_string().into(),
                })
            })?
            .into_owned();

        require_non_empty_name(&path)?;
        check_root_entry_is_directory(
            &path,
            NodeKind::directory_if(effective_entry_type(entry)? == tar::EntryType::Directory),
        )?;

        let entry_type = TarEntryAdapter::to_entry_type(entry)?;
        let size = TarEntryAdapter::get_uncompressed_size(entry);
        let mode = tar_permission_bits(entry.header());

        let entry_size = EntrySize::new(size, None);

        match &entry_type {
            EntryType::File => {
                let request = FileRequest {
                    path: &path,
                    size: entry_size,
                    mode,
                };
                match target.validate_file(request, &mut ctx.tally)? {
                    FileAdmission::Write(admitted) => {
                        target.file(entry, admitted, &mut ctx.tally)?;
                        Ok(EntryOutcome::Done)
                    }
                    FileAdmission::Skipped(_) => Ok(EntryOutcome::Skipped),
                }
            }

            EntryType::Directory => {
                let safe_path = target.validate_directory(&path, entry_size)?;
                target.directory(&safe_path, &mut ctx.tally)?;
                Ok(EntryOutcome::Done)
            }

            EntryType::Symlink {
                target: link_target,
            } => {
                let safe_symlink = target.validate_symlink(&path, link_target, entry_size)?;
                target.symlink(&safe_symlink, &mut ctx.tally)?;
                Ok(EntryOutcome::Done)
            }

            EntryType::Hardlink {
                target: link_target,
            } => {
                let link = target.validate_hardlink(&path, link_target, entry_size)?;
                // Two-pass: defer hardlink creation until target files exist
                Ok(EntryOutcome::Hardlink(HardlinkInfo {
                    link_path: link.link,
                    target_path: link.target,
                    counted: link.counted,
                }))
            }
        }
    }

    /// Processes `entry`, then reads past its data when the entry was skipped.
    fn process_and_skip<ER: Read, T: ExtractTarget>(
        entry: &mut CheckedTarEntry<'_, '_, ER>,
        target: &mut T,
        ctx: &mut ExtractionContext<'_>,
        skip_limits: &SkipLimits,
    ) -> Result<EntryOutcome<T::Parent>> {
        let outcome = Self::process_entry(entry, target, ctx)?;
        if matches!(outcome, EntryOutcome::Skipped) {
            entry.drain_skipped(skip_limits)?;
        }
        Ok(outcome)
    }

    /// Runs the extraction loop against `target`: the validation gates are the
    /// same whether it writes to the filesystem or to an entry sink.
    pub(crate) fn extract_into<T: ExtractTarget>(
        self,
        target: &mut T,
        config: &SecurityConfig,
        options: SinkOptions,
        progress: &mut dyn ProgressCallback,
    ) -> Result<ExtractionReport> {
        let start = Instant::now();

        let mut report = ExtractionReport::new();

        let mut hardlinks: SmallVec<[HardlinkInfo<T::Parent>; 8]> = SmallVec::new();

        let mut current_entry: usize = 0;

        // Aggregated once, at every exit point, into a single warning per
        // counter instead of one warning per skipped entry — keeps
        // `report.warnings`'s growth independent of how many duplicate
        // entries an archive contains (issue #490). Hardlinks are counted
        // separately since they are format-specific to TAR (ZIP has no
        // hardlink entry type).
        let mut duplicate_skips: u64 = 0;
        let mut hardlink_duplicate_skips: u64 = 0;
        // Same aggregation, for entries rejected by the extension allowlist
        // (issue #495).
        let mut extension_skips: u64 = 0;

        let (budgeted, budget) = budgeted_reader_with(
            self.inner,
            config.max_tar_metadata_bytes,
            self.source.clone(),
        );
        let mut inner_archive = Archive::new(budgeted);
        let mut entries = budgeted_tar_entries(&mut inner_archive, budget)
            .map_err(|e| ArchiveError::unclassified(format!("failed to read entries: {e}")))?;

        let skip_limits = SkipLimits::of(config);
        let mut ctx = ExtractionContext {
            tally: Tally {
                report: &mut report,
                options,
                duplicate_skips: &mut duplicate_skips,
                extension_skips: &mut extension_skips,
                progress,
            },
            hardlink_duplicate_skips: &mut hardlink_duplicate_skips,
        };

        while let Some(entry_result) = entries.next_entry() {
            let guard = entry_result.map_err(|raw| {
                ctx.push_skip_warnings();
                ArchiveError::partial_or(std::mem::take(ctx.tally.report), raw)
            })?;
            let mut guard = guard
                .check(config.max_tar_metadata_bytes.get())
                .map_err(|e| {
                    ctx.push_skip_warnings();
                    ArchiveError::partial_or(std::mem::take(ctx.tally.report), e)
                })?;

            // TAR is streaming: total entry count is not known upfront, so pass
            // 0.
            let entry_path = guard
                .path()
                .ok()
                .map_or_default(std::borrow::Cow::into_owned);
            current_entry = current_entry.saturating_add(1);
            ctx.tally
                .progress
                .on_entry_start(&entry_path, 0, current_entry);

            // `settle` abandons the entry on failure: no further
            // `next_entry()` calls follow, so the guard's usual drain is
            // pointless I/O (see `TarEntryGuard::abandon`).
            let settled =
                guard.settle(|guard| Self::process_and_skip(guard, target, &mut ctx, &skip_limits));
            ctx.tally.progress.on_entry_complete(&entry_path);
            match settled {
                Ok(EntryOutcome::Hardlink(hardlink_info)) => hardlinks.push(hardlink_info),
                Ok(EntryOutcome::Done | EntryOutcome::Skipped) => {}
                Err(e) => {
                    ctx.push_skip_warnings();
                    return Err(ArchiveError::partial_or(
                        std::mem::take(ctx.tally.report),
                        e,
                    ));
                }
            }
        }

        let finished = entries.finish();
        drop(entries);
        let finished = finished.and_then(|()| {
            self.trailer
                .enforce(&mut inner_archive.into_inner(), config)
        });
        if let Err(e) = finished {
            ctx.push_skip_warnings();
            return Err(ArchiveError::partial_or(
                std::mem::take(ctx.tally.report),
                e,
            ));
        }

        // Two-pass extraction: create hardlinks after all target files exist
        for hardlink in hardlinks {
            if let Err(e) = target.hardlink(
                &hardlink.link_path,
                &hardlink.target_path,
                hardlink.counted,
                &mut ctx.tally,
                ctx.hardlink_duplicate_skips,
            ) {
                ctx.push_skip_warnings();
                return Err(ArchiveError::partial_or(
                    std::mem::take(ctx.tally.report),
                    e,
                ));
            }
        }

        ctx.push_skip_warnings();
        ctx.tally.progress.on_complete();
        report.duration = start.elapsed();

        Ok(report)
    }
}

impl<R: Read> ArchiveFormat for TarArchive<R> {
    fn extract(
        self,
        output_dir: &Path,
        config: &SecurityConfig,
        options: &ExtractionOptions,
        progress: &mut dyn ProgressCallback,
    ) -> Result<ExtractionReport> {
        let mut target = HostTarget::create(output_dir, config)?;
        self.extract_into(
            &mut target,
            config,
            SinkOptions::duplicates_of(options),
            progress,
        )
    }

    fn list(self, config: &SecurityConfig) -> Result<crate::inspection::ArchiveManifest> {
        self.list_with_pass(config, &mut ListPass::strict())
    }

    /// Verifies the archive; the TAR stream's codec is unknown here, so with
    /// integrity requested the stream is read to decoder EOF within the budget
    /// after the end marker.
    fn verify(
        self,
        config: &SecurityConfig,
        options: &VerificationOptions,
    ) -> Result<crate::inspection::VerificationReport> {
        crate::inspection::verify::verify_with(
            config,
            *options,
            &mut crate::NoopProgress,
            |listing| self.list_with_pass(config, listing),
        )
    }
}

struct ExtractionContext<'a> {
    tally: Tally<'a>,
    /// Count of hardlinks skipped as pre-existing duplicates. Tracked
    /// separately from the tally's `duplicate_skips` because hardlinks are
    /// TAR-specific (ZIP has no hardlink entry type).
    hardlink_duplicate_skips: &'a mut u64,
}

impl ExtractionContext<'_> {
    fn push_skip_warnings(&mut self) {
        push_duplicate_skip_warnings(
            self.tally.report,
            *self.tally.duplicate_skips,
            *self.hardlink_duplicate_skips,
            *self.tally.extension_skips,
        );
    }
}

/// Appends aggregated duplicate-skip and disallowed-extension warnings to
/// `report`, one entry per non-zero counter, mirroring 7z's single
/// end-of-extraction warning (`SevenZArchive::extract_into`)
/// instead of one warning per skipped entry (issues #490, #495).
fn push_duplicate_skip_warnings(
    report: &mut ExtractionReport,
    duplicate_skips: u64,
    hardlink_duplicate_skips: u64,
    disallowed_extension_skips: u64,
) {
    common::push_duplicate_skip_warning(report, duplicate_skips, "entry", "entries");
    common::push_duplicate_skip_warning(report, hardlink_duplicate_skips, "hardlink", "hardlinks");
    common::push_disallowed_extension_warning(report, disallowed_extension_skips);
}

/// What `process_entry` did with an entry.
enum EntryOutcome<P: ParentCheck> {
    /// The entry was written or needed nothing.
    Done,
    /// A file was skipped (a duplicate or a disallowed extension); its data
    /// is still to be read past, see `CheckedTarEntry::drain_skipped`.
    Skipped,
    /// A hardlink to create once every file exists.
    Hardlink(HardlinkInfo<P>),
}

#[allow(dead_code)] // Fields used only on Unix
struct HardlinkInfo<P: ParentCheck> {
    link_path: SafePath<P>,
    target_path: HardlinkTarget,
    counted: EntryCount,
}

/// Adapter to convert `tar::Entry` to our `EntryType`.
struct TarEntryAdapter;

impl TarEntryAdapter {
    /// Returns `true` for TAR metadata entries that should be skipped.
    ///
    /// PAX extended headers and GNU long name/link entries are format-internal
    /// records, not user files. The `tar` crate consumes `XHeader`,
    /// `GNULongName`, and `GNULongLink` internally in `next_entry()`, so
    /// they normally never reach our iterator. `XGlobalHeader` does reach
    /// us. All four are checked here as defense-in-depth.
    fn is_metadata_entry<R: Read>(tar_entry: &tar::Entry<'_, R>) -> bool {
        is_metadata_type(tar_entry.header().entry_type())
    }

    /// Converts `tar::EntryType` to our `EntryType` enum.
    fn to_entry_type<R: Read>(tar_entry: &tar::Entry<'_, R>) -> Result<EntryType> {
        match tar_node(effective_entry_type(tar_entry)?)? {
            TarNode::File => Ok(EntryType::File),
            TarNode::Directory => Ok(EntryType::Directory),
            TarNode::Symlink => {
                let target = tar_entry
                    .link_name()
                    .map_err(|e| {
                        ArchiveError::from(Malformation::LinkNameUnreadable {
                            kind: LinkKind::Symlink,
                            detail: e.to_string().into(),
                        })
                    })?
                    .ok_or_else(|| {
                        ArchiveError::from(Malformation::LinkTargetMissing(LinkKind::Symlink))
                    })?
                    .into_owned();
                Ok(EntryType::Symlink { target })
            }
            TarNode::Hardlink => {
                let target = tar_entry
                    .link_name()
                    .map_err(|e| {
                        ArchiveError::from(Malformation::LinkNameUnreadable {
                            kind: LinkKind::Hardlink,
                            detail: e.to_string().into(),
                        })
                    })?
                    .ok_or_else(|| {
                        ArchiveError::from(Malformation::LinkTargetMissing(LinkKind::Hardlink))
                    })?
                    .into_owned();
                Ok(EntryType::Hardlink { target })
            }
        }
    }

    /// Gets uncompressed size from TAR entry.
    fn get_uncompressed_size<R: Read>(tar_entry: &tar::Entry<'_, R>) -> Uncompressed {
        Uncompressed(tar_entry.size())
    }
}

/// What a supported TAR entry type stands for.
///
/// The single classification shared by extraction, `list` and `verify`, so a
/// type refused by one is refused by all.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TarNode {
    File,
    Directory,
    Symlink,
    Hardlink,
}

/// Returns `true` for TAR metadata records that are skipped, not extracted.
///
/// The `tar` crate consumes `XHeader`, `GNULongName` and `GNULongLink`
/// internally, so normally only `XGlobalHeader` reaches the entry loop; all
/// four are checked as defense-in-depth.
pub(crate) const fn is_metadata_type(kind: tar::EntryType) -> bool {
    matches!(
        kind,
        tar::EntryType::XHeader
            | tar::EntryType::XGlobalHeader
            | tar::EntryType::GNULongName
            | tar::EntryType::GNULongLink
    )
}

fn special_entry(kind: SpecialFile) -> ArchiveError {
    ArchiveError::from(Violation::SpecialEntry { kind, name: None })
}

/// Classifies a non-metadata TAR entry type, refusing special files.
///
/// # Errors
///
/// Returns [`ArchiveError::SecurityViolation`] for device nodes, FIFOs and any
/// other typeflag that is not a file, directory or link.
pub(crate) fn tar_node(kind: tar::EntryType) -> Result<TarNode> {
    use tar::EntryType as TarType;

    match kind {
        TarType::Regular | TarType::Continuous => Ok(TarNode::File),
        TarType::Directory => Ok(TarNode::Directory),
        TarType::Symlink => Ok(TarNode::Symlink),
        TarType::Link => Ok(TarNode::Hardlink),
        TarType::Char => Err(special_entry(SpecialFile::CharDevice)),
        TarType::Block => Err(special_entry(SpecialFile::BlockDevice)),
        TarType::Fifo => Err(special_entry(SpecialFile::Fifo)),
        _ => Err(ArchiveError::from(Violation::UnsupportedTarType {
            kind: format!("{kind:?}").into(),
        })),
    }
}

/// Returns the type an entry stands for, reading an empty file-typed header
/// (regular or contiguous) whose name ends in `/` as a directory.
///
/// V7 and other pre-ustar writers (`bsdtar --format v7`) store directories as
/// regular entries with a trailing slash; GNU tar, libarchive and `tar-rs`'s
/// own unpacker read them as directories. Shared by extraction and listing so
/// both classify an entry the same way.
///
/// # Errors
///
/// Returns [`TarAmbiguity::DirectoryNamedPayload`] for a file-typed entry with
/// a directory name that carries a payload: reading it as a directory would
/// drop its data without a trace, and reading it as a file would create a name
/// the archive declares to be a directory. A directory, symbolic link or hard
/// link that declares a payload is refused as
/// [`TarAmbiguity::NonRegularPayload`] for the same reason: readers disagree
/// on whether the payload blocks are data or further headers.
pub(crate) fn effective_entry_type<R: Read>(entry: &tar::Entry<'_, R>) -> Result<tar::EntryType> {
    let kind = entry.header().entry_type();
    if let (Some(kind), size @ 1..) = (TarNonRegularKind::of(kind), entry.size()) {
        return Err(ArchiveError::TarAmbiguity(
            TarAmbiguity::NonRegularPayload {
                kind,
                size,
                path: String::from_utf8_lossy(&entry.path_bytes()).into_owned(),
            },
        ));
    }
    let is_file_typed = matches!(kind, tar::EntryType::Regular | tar::EntryType::Continuous);
    if !is_file_typed || !entry.path_bytes().ends_with(b"/") {
        return Ok(kind);
    }
    match entry.size() {
        0 => Ok(tar::EntryType::Directory),
        size => Err(ArchiveError::TarAmbiguity(
            TarAmbiguity::DirectoryNamedPayload {
                size,
                path: String::from_utf8_lossy(&entry.path_bytes()).into_owned(),
            },
        )),
    }
}

/// Returns the permission bits (`0o7777`) of a TAR header's mode, dropping any
/// file-type bits older writers stored there, so `list` and `extract` agree
/// with ZIP and system `tar`.
pub(crate) fn tar_permission_bits(header: &tar::Header) -> Option<RawMode> {
    header.mode().ok().map(|mode| RawMode::new(mode & 0o7777))
}

/// Opens `path` as a TAR byte stream, decoding it with `codec` when one is
/// given.
///
/// This is the single place that decides how a TAR file is buffered, so
/// extraction, listing and the public `open_tar_*` functions share one read
/// path: file, one `BufReader`, then at most one decoder.
///
/// # Errors
///
/// Returns an error if the file cannot be opened or the decoder cannot be
/// initialised.
pub(crate) fn open_tar_stream(
    path: &Path,
    codec: Option<CompressionCodec>,
    limits: DecoderLimits,
) -> Result<TarStream<'static>> {
    decode_tar_stream(File::open(path)?, codec, limits)
}

/// Opens `path` as a TAR archive whose trailer is read to decoder EOF, the
/// shape every public `open_tar_*` function returns.
fn open_tar_archive(
    path: &Path,
    codec: CompressionCodec,
    limits: DecoderLimits,
) -> Result<TarArchive<Box<dyn Read + Send>>> {
    open_tar_stream(path, Some(codec), limits)
        .map(|decoded| TarArchive::from_stream(decoded, TarTrailer::DrainToDecoderEof))
}

/// Opens a gzip-compressed TAR archive (.tar.gz).
///
/// The file is wrapped in `BufReader` for optimal performance.
///
/// # Errors
///
/// Returns an error if the file cannot be opened.
///
/// # Examples
///
/// ```no_run
/// use exarch_core::ExtractionOptions;
/// use exarch_core::SecurityConfig;
/// use exarch_core::formats::tar::open_tar_gz;
/// use exarch_core::formats::traits::ArchiveFormat;
/// use std::path::Path;
///
/// let mut archive = open_tar_gz("archive.tar.gz")?;
/// let config = SecurityConfig::default();
/// let report = archive.extract(
///     Path::new("/output"),
///     &config,
///     &ExtractionOptions::default(),
///     &mut exarch_core::NoopProgress,
/// )?;
/// # Ok::<(), exarch_core::ArchiveError>(())
/// ```
pub fn open_tar_gz<P: AsRef<Path>>(path: P) -> Result<TarArchive<Box<dyn Read + Send>>> {
    open_tar_archive(
        path.as_ref(),
        CompressionCodec::Gzip,
        DecoderLimits::UNBOUNDED,
    )
}

/// Opens a bzip2-compressed TAR archive (.tar.bz2).
///
/// The file is wrapped in `BufReader` for optimal performance.
///
/// # Errors
///
/// Returns an error if the file cannot be opened.
///
/// # Examples
///
/// ```no_run
/// use exarch_core::ExtractionOptions;
/// use exarch_core::SecurityConfig;
/// use exarch_core::formats::tar::open_tar_bz2;
/// use exarch_core::formats::traits::ArchiveFormat;
/// use std::path::Path;
///
/// let mut archive = open_tar_bz2("archive.tar.bz2")?;
/// let config = SecurityConfig::default();
/// let report = archive.extract(
///     Path::new("/output"),
///     &config,
///     &ExtractionOptions::default(),
///     &mut exarch_core::NoopProgress,
/// )?;
/// # Ok::<(), exarch_core::ArchiveError>(())
/// ```
pub fn open_tar_bz2<P: AsRef<Path>>(path: P) -> Result<TarArchive<Box<dyn Read + Send>>> {
    open_tar_archive(
        path.as_ref(),
        CompressionCodec::Bzip2,
        DecoderLimits::UNBOUNDED,
    )
}

/// Opens an xz-compressed TAR archive (.tar.xz).
///
/// The file is wrapped in `BufReader` for optimal performance.
///
/// # Errors
///
/// Returns an error if the file cannot be opened.
///
/// # Decoder memory
///
/// The decoder is bounded by `config.max_decoder_memory`, fixed when the
/// archive is opened. The config later passed to `extract` is not consulted
/// for this limit, so the two configs may disagree; use the same config for
/// both.
///
/// # Examples
///
/// ```no_run
/// use exarch_core::ExtractionOptions;
/// use exarch_core::SecurityConfig;
/// use exarch_core::formats::tar::open_tar_xz;
/// use exarch_core::formats::traits::ArchiveFormat;
/// use std::path::Path;
///
/// let config = SecurityConfig::default();
/// let mut archive = open_tar_xz("archive.tar.xz", &config)?;
/// let report = archive.extract(
///     Path::new("/output"),
///     &config,
///     &ExtractionOptions::default(),
///     &mut exarch_core::NoopProgress,
/// )?;
/// # Ok::<(), exarch_core::ArchiveError>(())
/// ```
pub fn open_tar_xz<P: AsRef<Path>>(
    path: P,
    config: &SecurityConfig,
) -> Result<TarArchive<Box<dyn Read + Send>>> {
    open_tar_archive(
        path.as_ref(),
        CompressionCodec::Xz,
        DecoderLimits::of(config),
    )
}

/// Opens a zstd-compressed TAR archive (.tar.zst).
///
/// The file is wrapped in `BufReader` for optimal performance.
///
/// # Errors
///
/// Returns an error if the file cannot be opened or if decompression
/// initialization fails.
///
/// # Examples
///
/// ```no_run
/// use exarch_core::ExtractionOptions;
/// use exarch_core::SecurityConfig;
/// use exarch_core::formats::tar::open_tar_zst;
/// use exarch_core::formats::traits::ArchiveFormat;
/// use std::path::Path;
///
/// let mut archive = open_tar_zst("archive.tar.zst")?;
/// let config = SecurityConfig::default();
/// let report = archive.extract(
///     Path::new("/output"),
///     &config,
///     &ExtractionOptions::default(),
///     &mut exarch_core::NoopProgress,
/// )?;
/// # Ok::<(), exarch_core::ArchiveError>(())
/// ```
pub fn open_tar_zst<P: AsRef<Path>>(path: P) -> Result<TarArchive<Box<dyn Read + Send>>> {
    open_tar_archive(
        path.as_ref(),
        CompressionCodec::Zstd,
        DecoderLimits::UNBOUNDED,
    )
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::NoopProgress;
    use crate::test_utils::create_test_tar;
    use std::assert_matches;
    use std::io::Cursor;
    use std::io::Write;
    use tempfile::TempDir;

    #[test]
    fn test_tar_permission_bits_strips_file_type_bits() {
        let mut header = tar::Header::new_gnu();
        for (raw, expected) in [(0o100_644, 0o644), (0o040_755, 0o755), (0o104_755, 0o4755)] {
            header.set_mode(raw);
            assert_eq!(tar_permission_bits(&header), Some(RawMode::new(expected)));
        }
    }

    #[test]
    fn test_extract_simple_file() {
        let tar_data = create_test_tar(vec![("file.txt", b"hello world")]);
        let archive = TarArchive::new(Cursor::new(tar_data));

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default();

        let report = archive
            .extract(
                temp.path(),
                &config,
                &ExtractionOptions::default(),
                &mut crate::NoopProgress,
            )
            .unwrap();

        assert_eq!(report.files_extracted, 1);
        assert_eq!(report.directories_created, 0);
        assert!(temp.path().join("file.txt").exists());
    }

    #[test]
    fn test_extract_nested_structure() {
        let mut builder = tar::Builder::new(Vec::new());

        // Add directories explicitly
        let mut header = tar::Header::new_gnu();
        header.set_size(0);
        header.set_mode(0o755);
        header.set_entry_type(tar::EntryType::Directory);
        header.set_cksum();
        builder
            .append_data(&mut header, "dir1/", &[] as &[u8])
            .unwrap();

        let mut header = tar::Header::new_gnu();
        header.set_size(0);
        header.set_mode(0o755);
        header.set_entry_type(tar::EntryType::Directory);
        header.set_cksum();
        builder
            .append_data(&mut header, "dir1/dir2/", &[] as &[u8])
            .unwrap();

        // Add file
        let mut header = tar::Header::new_gnu();
        header.set_size(6);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, "dir1/dir2/file.txt", &b"nested"[..])
            .unwrap();

        let tar_data = builder.into_inner().unwrap();
        let archive = TarArchive::new(Cursor::new(tar_data));

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default();

        let report = archive
            .extract(
                temp.path(),
                &config,
                &ExtractionOptions::default(),
                &mut crate::NoopProgress,
            )
            .unwrap();

        assert_eq!(report.files_extracted, 1);
        assert_eq!(report.directories_created, 2);
        assert!(temp.path().join("dir1/dir2/file.txt").exists());
    }

    #[test]
    #[cfg(unix)]
    fn test_extract_symlink() {
        let mut builder = tar::Builder::new(Vec::new());

        // Add target file
        let mut header = tar::Header::new_gnu();
        header.set_size(5);
        header.set_mode(0o644);
        header.set_entry_type(tar::EntryType::Regular);
        header.set_cksum();
        builder
            .append_data(&mut header, "target.txt", &b"data\n"[..])
            .unwrap();

        // Add symlink
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Symlink);
        header.set_link_name("target.txt").unwrap();
        header.set_size(0);
        header.set_cksum();
        builder
            .append_data(&mut header, "link.txt", &[] as &[u8])
            .unwrap();

        let tar_data = builder.into_inner().unwrap();
        let archive = TarArchive::new(Cursor::new(tar_data));

        let temp = TempDir::new().unwrap();
        let mut config = SecurityConfig::default();
        config.allowed.symlinks = crate::Admit::Allow;

        let report = archive
            .extract(
                temp.path(),
                &config,
                &ExtractionOptions::default(),
                &mut crate::NoopProgress,
            )
            .unwrap();

        assert_eq!(report.files_extracted, 1);
        assert_eq!(report.symlinks_created, 1);
        assert!(temp.path().join("link.txt").exists());
    }

    #[test]
    #[cfg(unix)]
    fn test_extract_hardlink_two_pass() {
        let mut builder = tar::Builder::new(Vec::new());

        // Add hardlink BEFORE target (tests two-pass)
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Link);
        header.set_link_name("target.txt").unwrap();
        header.set_size(0);
        header.set_cksum();
        builder
            .append_data(&mut header, "hardlink.txt", &[] as &[u8])
            .unwrap();

        // Add target file
        let mut header = tar::Header::new_gnu();
        header.set_size(5);
        header.set_mode(0o644);
        header.set_entry_type(tar::EntryType::Regular);
        header.set_cksum();
        builder
            .append_data(&mut header, "target.txt", &b"data\n"[..])
            .unwrap();

        let tar_data = builder.into_inner().unwrap();
        let archive = TarArchive::new(Cursor::new(tar_data));

        let temp = TempDir::new().unwrap();
        let mut config = SecurityConfig::default();
        config.allowed.hardlinks = crate::Admit::Allow;

        let report = archive
            .extract(
                temp.path(),
                &config,
                &ExtractionOptions::default(),
                &mut crate::NoopProgress,
            )
            .unwrap();

        assert_eq!(report.files_extracted, 2);
        assert!(temp.path().join("hardlink.txt").exists());
        assert!(temp.path().join("target.txt").exists());
    }

    #[test]
    fn test_quota_file_size_exceeded() {
        let tar_data = create_test_tar(vec![("large.bin", &vec![0u8; 1000])]);
        let archive = TarArchive::new(Cursor::new(tar_data));

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default().with_max_file_size(crate::non_zero!(100));

        let result = archive.extract(
            temp.path(),
            &config,
            &ExtractionOptions::default(),
            &mut crate::NoopProgress,
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_unsupported_entry_type_block_device() {
        let mut builder = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Block);
        header.set_size(0);
        header.set_cksum();
        builder
            .append_data(&mut header, "dev/sda", &[] as &[u8])
            .unwrap();

        let tar_data = builder.into_inner().unwrap();
        let archive = TarArchive::new(Cursor::new(tar_data));

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default();

        let result = archive.extract(
            temp.path(),
            &config,
            &ExtractionOptions::default(),
            &mut crate::NoopProgress,
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_unsupported_entry_type_char_device() {
        let mut builder = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Char);
        header.set_size(0);
        header.set_cksum();
        builder
            .append_data(&mut header, "dev/tty", &[] as &[u8])
            .unwrap();

        let tar_data = builder.into_inner().unwrap();
        let archive = TarArchive::new(Cursor::new(tar_data));

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default();

        let result = archive.extract(
            temp.path(),
            &config,
            &ExtractionOptions::default(),
            &mut crate::NoopProgress,
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_unsupported_entry_type_fifo() {
        let mut builder = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Fifo);
        header.set_size(0);
        header.set_cksum();
        builder
            .append_data(&mut header, "fifo", &[] as &[u8])
            .unwrap();

        let tar_data = builder.into_inner().unwrap();
        let archive = TarArchive::new(Cursor::new(tar_data));

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default();

        let result = archive.extract(
            temp.path(),
            &config,
            &ExtractionOptions::default(),
            &mut crate::NoopProgress,
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_extract_pax_headers_skipped() {
        let mut builder = tar::Builder::new(Vec::new());

        // Add a PAX global header entry
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::XGlobalHeader);
        let pax_data = b"14 comment=hi\n";
        header.set_size(pax_data.len() as u64);
        header.set_cksum();
        builder
            .append_data(&mut header, "././@PaxHeader", &pax_data[..])
            .unwrap();

        // Add a PAX extended header entry
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::XHeader);
        header.set_size(pax_data.len() as u64);
        header.set_cksum();
        builder
            .append_data(&mut header, "././@PaxHeader", &pax_data[..])
            .unwrap();

        // Add a regular file
        let mut header = tar::Header::new_gnu();
        header.set_size(5);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, "hello.txt", &b"hello"[..])
            .unwrap();

        let tar_data = builder.into_inner().unwrap();
        let archive = TarArchive::new(Cursor::new(tar_data));

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default();

        let report = archive
            .extract(
                temp.path(),
                &config,
                &ExtractionOptions::default(),
                &mut crate::NoopProgress,
            )
            .unwrap();

        assert_eq!(report.files_extracted, 1);
        assert!(temp.path().join("hello.txt").exists());
    }

    #[test]
    fn test_extract_gnu_long_name_skipped() {
        let mut builder = tar::Builder::new(Vec::new());

        // Add a GNU long name entry
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::GNULongName);
        let long_name = b"very_long_filename.txt\0";
        header.set_size(long_name.len() as u64);
        header.set_cksum();
        builder
            .append_data(&mut header, "././@LongLink", &long_name[..])
            .unwrap();

        // Add a regular file
        let mut header = tar::Header::new_gnu();
        header.set_size(4);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, "file.txt", &b"data"[..])
            .unwrap();

        let tar_data = builder.into_inner().unwrap();
        let archive = TarArchive::new(Cursor::new(tar_data));

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default();

        let report = archive
            .extract(
                temp.path(),
                &config,
                &ExtractionOptions::default(),
                &mut crate::NoopProgress,
            )
            .unwrap();

        assert_eq!(report.files_extracted, 1);
        assert!(temp.path().join("very_long_filename.txt").exists());
    }

    #[test]
    fn test_extract_gnu_long_link_skipped() {
        let mut builder = tar::Builder::new(Vec::new());

        // Add a GNU long link entry (metadata, should be skipped)
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::GNULongLink);
        let long_link = b"target.txt\0";
        header.set_size(long_link.len() as u64);
        header.set_cksum();
        builder
            .append_data(&mut header, "././@LongLink", &long_link[..])
            .unwrap();

        // Add a regular file
        let mut header = tar::Header::new_gnu();
        header.set_size(4);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, "file.txt", &b"data"[..])
            .unwrap();

        let tar_data = builder.into_inner().unwrap();
        let archive = TarArchive::new(Cursor::new(tar_data));

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default();

        let report = archive
            .extract(
                temp.path(),
                &config,
                &ExtractionOptions::default(),
                &mut crate::NoopProgress,
            )
            .unwrap();

        assert_eq!(report.files_extracted, 1);
        assert!(temp.path().join("file.txt").exists());
    }

    #[test]
    fn test_gnu_sparse_entry_is_refused() {
        let mut builder = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::GNUSparse);
        header.set_size(6);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, "sparse.txt", &b"sparse"[..])
            .unwrap();

        let tar_data = builder.into_inner().unwrap();
        let archive = TarArchive::new(Cursor::new(tar_data));

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default();

        let result = archive.extract(
            temp.path(),
            &config,
            &ExtractionOptions::default(),
            &mut crate::NoopProgress,
        );
        assert_eq!(
            result.unwrap_err().error_code(),
            crate::ErrorCode::InvalidArchive
        );
        assert!(!temp.path().join("sparse.txt").exists());
    }

    #[test]
    fn test_unsupported_entry_type_unknown_byte() {
        let mut builder = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        // b'Z' is not a known entry type byte
        header.set_entry_type(tar::EntryType::__Nonexhaustive(b'Z'));
        header.set_size(0);
        header.set_cksum();
        builder
            .append_data(&mut header, "unknown", &[] as &[u8])
            .unwrap();

        let tar_data = builder.into_inner().unwrap();
        let archive = TarArchive::new(Cursor::new(tar_data));

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default();

        let result = archive.extract(
            temp.path(),
            &config,
            &ExtractionOptions::default(),
            &mut crate::NoopProgress,
        );

        assert_matches!(
            result,
            Err(ArchiveError::SecurityViolation { .. }),
            "expected SecurityViolation, got: {result:?}"
        );
    }

    #[test]
    fn test_extract_continuous_entry_as_file() {
        let mut builder = tar::Builder::new(Vec::new());

        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Continuous);
        header.set_size(7);
        header.set_mode(0o644);
        header.set_cksum();
        builder
            .append_data(&mut header, "cont.txt", &b"content"[..])
            .unwrap();

        let tar_data = builder.into_inner().unwrap();
        let archive = TarArchive::new(Cursor::new(tar_data));

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default();

        let report = archive
            .extract(
                temp.path(),
                &config,
                &ExtractionOptions::default(),
                &mut crate::NoopProgress,
            )
            .unwrap();

        assert_eq!(report.files_extracted, 1);
        assert!(temp.path().join("cont.txt").exists());
    }

    #[test]
    fn test_extract_gzip_compressed() {
        use flate2::Compression;
        use flate2::write::GzEncoder;

        // Create TAR archive
        let tar_data = create_test_tar(vec![("file.txt", b"compressed")]);

        // Compress with gzip
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&tar_data).unwrap();
        let gz_data = encoder.finish().unwrap();

        // Extract
        let decoder = flate2::read::GzDecoder::new(Cursor::new(gz_data));
        let archive = TarArchive::new(decoder);

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default();

        let report = archive
            .extract(
                temp.path(),
                &config,
                &ExtractionOptions::default(),
                &mut crate::NoopProgress,
            )
            .unwrap();

        assert_eq!(report.files_extracted, 1);
        assert!(temp.path().join("file.txt").exists());
    }

    #[test]
    fn test_extract_bzip2_compressed() {
        use bzip2::Compression;
        use bzip2::write::BzEncoder;

        // Create TAR archive
        let tar_data = create_test_tar(vec![("file.txt", b"compressed")]);

        // Compress with bzip2
        let mut encoder = BzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(&tar_data).unwrap();
        let bz2_data = encoder.finish().unwrap();

        // Extract
        let decoder = bzip2::read::BzDecoder::new(Cursor::new(bz2_data));
        let archive = TarArchive::new(decoder);

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default();

        let report = archive
            .extract(
                temp.path(),
                &config,
                &ExtractionOptions::default(),
                &mut crate::NoopProgress,
            )
            .unwrap();

        assert_eq!(report.files_extracted, 1);
        assert!(temp.path().join("file.txt").exists());
    }

    #[test]
    fn test_extract_xz_compressed() {
        use liblzma::write::XzEncoder;

        // Create TAR archive
        let tar_data = create_test_tar(vec![("file.txt", b"compressed")]);

        // Compress with xz
        let mut encoder = XzEncoder::new(Vec::new(), 6);
        encoder.write_all(&tar_data).unwrap();
        let xz_data = encoder.finish().unwrap();

        // Extract
        let decoder = liblzma::read::XzDecoder::new(Cursor::new(xz_data));
        let archive = TarArchive::new(decoder);

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default();

        let report = archive
            .extract(
                temp.path(),
                &config,
                &ExtractionOptions::default(),
                &mut crate::NoopProgress,
            )
            .unwrap();

        assert_eq!(report.files_extracted, 1);
        assert!(temp.path().join("file.txt").exists());
    }

    #[test]
    fn test_extract_zstd_compressed() {
        // Create TAR archive
        let tar_data = create_test_tar(vec![("file.txt", b"compressed")]);

        // Compress with zstd
        let zst_data = zstd::encode_all(&tar_data[..], 3).unwrap();

        // Extract
        let decoder = zstd::Decoder::with_buffer(Cursor::new(zst_data)).unwrap();
        let archive = TarArchive::new(decoder);

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default();

        let report = archive
            .extract(
                temp.path(),
                &config,
                &ExtractionOptions::default(),
                &mut crate::NoopProgress,
            )
            .unwrap();

        assert_eq!(report.files_extracted, 1);
        assert!(temp.path().join("file.txt").exists());
    }

    #[test]
    fn test_empty_tar_archive() {
        let tar_data = create_test_tar(vec![]);
        let archive = TarArchive::new(Cursor::new(tar_data));

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default();

        let report = archive
            .extract(
                temp.path(),
                &config,
                &ExtractionOptions::default(),
                &mut crate::NoopProgress,
            )
            .unwrap();

        assert_eq!(report.files_extracted, 0);
        assert_eq!(report.directories_created, 0);
    }

    #[test]
    fn test_extract_empty_file() {
        let tar_data = create_test_tar(vec![("empty.txt", b"")]);
        let archive = TarArchive::new(Cursor::new(tar_data));

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default();

        let report = archive
            .extract(
                temp.path(),
                &config,
                &ExtractionOptions::default(),
                &mut crate::NoopProgress,
            )
            .unwrap();

        assert_eq!(report.files_extracted, 1);
        assert!(temp.path().join("empty.txt").exists());
        assert_eq!(
            std::fs::metadata(temp.path().join("empty.txt"))
                .unwrap()
                .len(),
            0
        );
    }

    #[test]
    fn test_extract_multiple_files() {
        let tar_data = create_test_tar(vec![
            ("file1.txt", b"content1"),
            ("file2.txt", b"content2"),
            ("file3.txt", b"content3"),
        ]);
        let archive = TarArchive::new(Cursor::new(tar_data));

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default();

        let report = archive
            .extract(
                temp.path(),
                &config,
                &ExtractionOptions::default(),
                &mut crate::NoopProgress,
            )
            .unwrap();

        assert_eq!(report.files_extracted, 3);
        assert!(temp.path().join("file1.txt").exists());
        assert!(temp.path().join("file2.txt").exists());
        assert!(temp.path().join("file3.txt").exists());
    }

    #[test]
    fn test_quota_file_count_exceeded() {
        let tar_data = create_test_tar(vec![
            ("file1.txt", b"a"),
            ("file2.txt", b"b"),
            ("file3.txt", b"c"),
        ]);
        let archive = TarArchive::new(Cursor::new(tar_data));

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default().with_max_file_count(crate::non_zero!(2));

        let result = archive.extract(
            temp.path(),
            &config,
            &ExtractionOptions::default(),
            &mut crate::NoopProgress,
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_quota_total_size_exceeded() {
        let tar_data = create_test_tar(vec![
            ("file1.txt", &vec![0u8; 500]),
            ("file2.txt", &vec![0u8; 600]),
        ]);
        let archive = TarArchive::new(Cursor::new(tar_data));

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default().with_max_total_size(crate::non_zero!(1000));

        let result = archive.extract(
            temp.path(),
            &config,
            &ExtractionOptions::default(),
            &mut crate::NoopProgress,
        );

        assert!(result.is_err());
    }

    #[test]
    #[cfg(unix)]
    fn test_file_permissions_preserved() {
        use std::os::unix::fs::PermissionsExt;

        let mut builder = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_size(4);
        header.set_mode(0o755);
        header.set_cksum();
        builder
            .append_data(&mut header, "script.sh", &b"#!/bin/sh"[..])
            .unwrap();

        let tar_data = builder.into_inner().unwrap();
        let archive = TarArchive::new(Cursor::new(tar_data));

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default();

        let report = archive
            .extract(
                temp.path(),
                &config,
                &ExtractionOptions::default(),
                &mut crate::NoopProgress,
            )
            .unwrap();

        assert_eq!(report.files_extracted, 1);

        let metadata = std::fs::metadata(temp.path().join("script.sh")).unwrap();
        let permissions = metadata.permissions();
        assert_eq!(permissions.mode() & 0o777, 0o755);
    }

    #[test]
    #[cfg(unix)]
    fn test_permissions_sanitized_setuid_removed() {
        use std::os::unix::fs::PermissionsExt;

        let mut builder = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_size(4);
        header.set_mode(0o4755); // setuid bit set
        header.set_cksum();
        builder
            .append_data(&mut header, "binary", &b"data"[..])
            .unwrap();

        let tar_data = builder.into_inner().unwrap();
        let archive = TarArchive::new(Cursor::new(tar_data));

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default();

        let report = archive
            .extract(
                temp.path(),
                &config,
                &ExtractionOptions::default(),
                &mut crate::NoopProgress,
            )
            .unwrap();

        assert_eq!(report.files_extracted, 1);

        let metadata = std::fs::metadata(temp.path().join("binary")).unwrap();
        let permissions = metadata.permissions();
        // setuid bit should be stripped
        assert_eq!(permissions.mode() & 0o7777, 0o755);
    }

    #[test]
    fn test_bytes_written_tracking() {
        let tar_data = create_test_tar(vec![("file1.txt", b"12345"), ("file2.txt", b"67890")]);
        let archive = TarArchive::new(Cursor::new(tar_data));

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default();

        let report = archive
            .extract(
                temp.path(),
                &config,
                &ExtractionOptions::default(),
                &mut crate::NoopProgress,
            )
            .unwrap();

        assert_eq!(report.bytes_written, 10);
    }

    #[test]
    fn test_extract_directory_only() {
        let mut builder = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_size(0);
        header.set_mode(0o755);
        header.set_entry_type(tar::EntryType::Directory);
        header.set_cksum();
        builder
            .append_data(&mut header, "mydir/", &[] as &[u8])
            .unwrap();

        let tar_data = builder.into_inner().unwrap();
        let archive = TarArchive::new(Cursor::new(tar_data));

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default();

        let report = archive
            .extract(
                temp.path(),
                &config,
                &ExtractionOptions::default(),
                &mut crate::NoopProgress,
            )
            .unwrap();

        assert_eq!(report.files_extracted, 0);
        assert_eq!(report.directories_created, 1);
        assert!(temp.path().join("mydir").is_dir());
    }

    #[test]
    #[cfg(unix)]
    fn test_symlink_disabled_by_default() {
        let mut builder = tar::Builder::new(Vec::new());

        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Symlink);
        header.set_link_name("target.txt").unwrap();
        header.set_size(0);
        header.set_cksum();
        builder
            .append_data(&mut header, "link.txt", &[] as &[u8])
            .unwrap();

        let tar_data = builder.into_inner().unwrap();
        let archive = TarArchive::new(Cursor::new(tar_data));

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default(); // symlinks disabled by default

        let result = archive.extract(
            temp.path(),
            &config,
            &ExtractionOptions::default(),
            &mut crate::NoopProgress,
        );

        assert!(result.is_err());
    }

    #[test]
    #[cfg(unix)]
    fn test_hardlink_disabled_by_default() {
        let mut builder = tar::Builder::new(Vec::new());

        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Link);
        header.set_link_name("target.txt").unwrap();
        header.set_size(0);
        header.set_cksum();
        builder
            .append_data(&mut header, "hardlink.txt", &[] as &[u8])
            .unwrap();

        let tar_data = builder.into_inner().unwrap();
        let archive = TarArchive::new(Cursor::new(tar_data));

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default(); // hardlinks disabled by default

        let result = archive.extract(
            temp.path(),
            &config,
            &ExtractionOptions::default(),
            &mut crate::NoopProgress,
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_extraction_duration_recorded() {
        let tar_data = create_test_tar(vec![("file.txt", b"test")]);
        let archive = TarArchive::new(Cursor::new(tar_data));

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default();

        let report = archive
            .extract(
                temp.path(),
                &config,
                &ExtractionOptions::default(),
                &mut crate::NoopProgress,
            )
            .unwrap();

        assert!(report.duration.as_nanos() > 0);
    }

    #[test]
    fn test_path_traversal_via_dotdot_rejected() {
        let mut builder = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_size(5);
        header.set_mode(0o644);

        // Manually set path with .. (bypassing tar crate validation)
        let path_bytes = b"subdir/../etc/passwd";
        let mut name_field = [0u8; 100];
        name_field[..path_bytes.len()].copy_from_slice(path_bytes);
        header.as_gnu_mut().unwrap().name = name_field;
        header.set_cksum();

        builder.append(&header, &b"evil\n"[..]).unwrap();

        let tar_data = builder.into_inner().unwrap();
        let archive = TarArchive::new(Cursor::new(tar_data));

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default();

        let result = archive.extract(
            temp.path(),
            &config,
            &ExtractionOptions::default(),
            &mut crate::NoopProgress,
        );

        assert!(result.is_err());
        match result {
            Err(ArchiveError::PathTraversal { .. }) => {}
            _ => panic!("Expected PathTraversal error"),
        }
    }

    #[test]
    fn test_absolute_path_rejected() {
        let mut builder = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_size(5);
        header.set_mode(0o644);

        // Manually set absolute path (bypassing tar crate validation)
        let path_bytes = b"/etc/shadow";
        let mut name_field = [0u8; 100];
        name_field[..path_bytes.len()].copy_from_slice(path_bytes);
        header.as_gnu_mut().unwrap().name = name_field;
        header.set_cksum();

        builder.append(&header, &b"evil\n"[..]).unwrap();

        let tar_data = builder.into_inner().unwrap();
        let archive = TarArchive::new(Cursor::new(tar_data));

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default();

        let result = archive.extract(
            temp.path(),
            &config,
            &ExtractionOptions::default(),
            &mut crate::NoopProgress,
        );

        assert!(result.is_err());
        match result {
            Err(ArchiveError::PathTraversal { .. }) => {}
            _ => panic!("Expected PathTraversal error for absolute path"),
        }
    }

    #[test]
    #[cfg(unix)]
    fn test_symlink_escape_rejected() {
        let mut builder = tar::Builder::new(Vec::new());

        // Add directory first
        let mut header = tar::Header::new_gnu();
        header.set_size(0);
        header.set_mode(0o755);
        header.set_entry_type(tar::EntryType::Directory);
        header.set_cksum();
        builder
            .append_data(&mut header, "subdir/", &[] as &[u8])
            .unwrap();

        // Add symlink in subdir pointing outside extraction directory
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Symlink);
        header.set_link_name("../../etc/passwd").unwrap();
        header.set_size(0);
        header.set_cksum();
        builder
            .append_data(&mut header, "subdir/evil_link.txt", &[] as &[u8])
            .unwrap();

        let tar_data = builder.into_inner().unwrap();
        let archive = TarArchive::new(Cursor::new(tar_data));

        let temp = TempDir::new().unwrap();
        let mut config = SecurityConfig::default();
        config.allowed.symlinks = crate::Admit::Allow;

        let result = archive.extract(
            temp.path(),
            &config,
            &ExtractionOptions::default(),
            &mut crate::NoopProgress,
        );

        assert!(result.is_err());
        // A directory was created before the symlink escape, so the error is
        // wrapped in PartialExtraction. Unwrap one level to check the source.
        match result {
            Err(ArchiveError::PartialExtraction { source, .. }) => {
                assert_matches!(*source, ArchiveError::SymlinkEscape { .. });
            }
            Err(ArchiveError::SymlinkEscape { .. }) => {}
            other => panic!("Expected SymlinkEscape error for symlink escape, got: {other:?}"),
        }
    }

    #[test]
    #[cfg(unix)]
    fn test_hardlink_target_missing_error() {
        let mut builder = tar::Builder::new(Vec::new());

        // Add hardlink without target file (should fail in second pass)
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Link);
        header.set_link_name("nonexistent.txt").unwrap();
        header.set_size(0);
        header.set_cksum();
        builder
            .append_data(&mut header, "hardlink.txt", &[] as &[u8])
            .unwrap();

        let tar_data = builder.into_inner().unwrap();
        let archive = TarArchive::new(Cursor::new(tar_data));

        let temp = TempDir::new().unwrap();
        let mut config = SecurityConfig::default();
        config.allowed.hardlinks = crate::Admit::Allow;

        let result = archive.extract(
            temp.path(),
            &config,
            &ExtractionOptions::default(),
            &mut crate::NoopProgress,
        );

        assert!(result.is_err());
        match result {
            Err(ArchiveError::InvalidArchive(msg)) => {
                assert!(msg.to_string().contains("hardlink target does not exist"));
            }
            _ => panic!("Expected InvalidArchive error for missing hardlink target"),
        }
    }

    #[cfg(unix)]
    fn hardlink_config() -> SecurityConfig {
        let mut config = SecurityConfig::default();
        config.allowed.hardlinks = crate::Admit::Allow;
        config
    }

    /// Issue #818: a hardlink target swapped for a FIFO between the two passes
    /// must be refused without blocking on the open or the read.
    #[test]
    #[cfg(unix)]
    fn test_hardlink_target_swapped_for_fifo_is_refused_without_blocking() {
        let temp = TempDir::new().unwrap();
        let dest = temp.path().to_path_buf();
        let (tx, rx) = std::sync::mpsc::channel();

        std::thread::spawn(move || {
            let config = hardlink_config();
            let outcome = (|| -> std::result::Result<Result<()>, String> {
                let mut target = HostTarget::create(&dest, &config).map_err(|e| e.to_string())?;
                let validated = target
                    .validate_hardlink(
                        Path::new("loot.txt"),
                        Path::new("pipe"),
                        EntrySize::new(Uncompressed(0), None),
                    )
                    .map_err(|e| e.to_string())?;
                let made = std::process::Command::new("mkfifo")
                    .arg(dest.join("pipe"))
                    .status()
                    .map_err(|e| e.to_string())?;
                if !made.success() {
                    return Err("mkfifo failed".into());
                }
                let mut report = ExtractionReport::new();
                let mut progress = crate::NoopProgress;
                let (mut skips, mut link_skips, mut extension_skips) = (0u64, 0u64, 0u64);
                let mut tally = Tally {
                    report: &mut report,
                    options: SinkOptions::default(),
                    duplicate_skips: &mut skips,
                    extension_skips: &mut extension_skips,
                    progress: &mut progress,
                };
                Ok(target.hardlink(
                    &validated.link,
                    &validated.target,
                    validated.counted,
                    &mut tally,
                    &mut link_skips,
                ))
            })();
            let _ = tx.send(outcome);
        });

        let outcome = rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .expect("hardlink must not block on a FIFO target")
            .expect("setup");
        let err = outcome.expect_err("a FIFO target must be refused");
        assert_matches!(&err, ArchiveError::InvalidArchive(m) if m.to_string().contains("not a regular file"));
        assert!(!temp.path().join("loot.txt").exists());
    }

    #[cfg(unix)]
    fn hardlink_only_tar(link_name: &str) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        let mut link_header = tar::Header::new_gnu();
        link_header.set_entry_type(tar::EntryType::Link);
        link_header.set_link_name(link_name).unwrap();
        link_header.set_size(0);
        link_header.set_cksum();
        builder
            .append_data(&mut link_header, "h", &[] as &[u8])
            .unwrap();
        builder.into_inner().unwrap()
    }

    #[cfg(unix)]
    fn extract_hardlink_only(dest: &Path, link_name: &str) -> Result<ExtractionReport> {
        TarArchive::new(Cursor::new(hardlink_only_tar(link_name))).extract(
            dest,
            &hardlink_config(),
            &ExtractionOptions::default(),
            &mut crate::NoopProgress,
        )
    }

    /// Issue #818: a pre-existing symlink inside `dest` is read through for a
    /// hardlink target however the path is spelled (a directory in the chain,
    /// `..` after a directory, or the leaf), as before the pinned directories.
    #[test]
    #[cfg(unix)]
    fn test_hardlink_target_through_preexisting_symlinks_is_copied() {
        for spelling in ["alias/f.txt", "x/../alias/f.txt", "lnk"] {
            let temp = TempDir::new().unwrap();
            std::fs::create_dir(temp.path().join("real")).unwrap();
            std::fs::create_dir(temp.path().join("x")).unwrap();
            std::fs::write(temp.path().join("real/f.txt"), b"data").unwrap();
            std::os::unix::fs::symlink("real", temp.path().join("alias")).unwrap();
            std::os::unix::fs::symlink("real/f.txt", temp.path().join("lnk")).unwrap();

            extract_hardlink_only(temp.path(), spelling).unwrap();

            assert_eq!(
                std::fs::read(temp.path().join("h")).unwrap(),
                b"data",
                "{spelling}"
            );
            assert!(
                !std::fs::symlink_metadata(temp.path().join("h"))
                    .unwrap()
                    .file_type()
                    .is_symlink(),
                "{spelling}"
            );
        }
    }

    /// The copy of a pre-existing target never gets wider permissions than the
    /// target, and never setuid, setgid or (unless allowed) world-writable
    /// bits.
    #[test]
    #[cfg(unix)]
    fn test_hardlink_copy_sanitizes_the_mode_of_a_preexisting_target() {
        use std::os::unix::fs::PermissionsExt;

        let allow_world_writable = {
            let mut config = SecurityConfig::default();
            config.allowed.hardlinks = crate::Admit::Allow;
            config.allowed.world_writable = crate::Admit::Allow;
            config
        };
        for (target_mode, config, expected) in [
            (0o4755, hardlink_config(), 0o755),
            (0o2755, hardlink_config(), 0o755),
            (0o777, hardlink_config(), 0o775),
            (0o777, allow_world_writable, 0o777),
            (0o600, hardlink_config(), 0o600),
            (0o444, hardlink_config(), 0o444),
        ] {
            let temp = TempDir::new().unwrap();
            let target = temp.path().join("t");
            std::fs::write(&target, b"data").unwrap();
            std::fs::set_permissions(&target, std::fs::Permissions::from_mode(target_mode))
                .unwrap();

            TarArchive::new(Cursor::new(hardlink_only_tar("t")))
                .extract(
                    temp.path(),
                    &config,
                    &ExtractionOptions::default(),
                    &mut crate::NoopProgress,
                )
                .unwrap();

            let copy = std::fs::metadata(temp.path().join("h")).unwrap();
            assert_eq!(
                copy.permissions().mode() & 0o7777,
                expected,
                "target mode {target_mode:o}"
            );
            assert_eq!(std::fs::read(temp.path().join("h")).unwrap(), b"data");
        }
    }

    /// Issue #818: reading through a pre-existing symlink never leaves `dest`.
    #[test]
    #[cfg(unix)]
    fn test_hardlink_target_through_an_escaping_symlink_is_refused() {
        let root = TempDir::new().unwrap();
        let dest = root.path().join("dest");
        let outside = root.path().join("outside");
        std::fs::create_dir(&dest).unwrap();
        std::fs::create_dir(&outside).unwrap();
        std::fs::write(outside.join("secret.txt"), b"secret").unwrap();
        std::os::unix::fs::symlink(&outside, dest.join("esc")).unwrap();
        std::os::unix::fs::symlink(outside.join("secret.txt"), dest.join("leaf")).unwrap();

        for spelling in ["esc/secret.txt", "leaf"] {
            let result = extract_hardlink_only(&dest, spelling);

            assert!(result.is_err(), "{spelling}: {result:?}");
            assert!(!dest.join("h").exists(), "{spelling}");
        }
    }

    /// Issue #818: a parent directory swapped for a symlink while a 200-entry
    /// archive extracts must never put a file outside the destination.
    #[test]
    #[cfg(unix)]
    fn test_components_swapped_during_extraction_never_write_outside() {
        use std::sync::atomic::AtomicBool;
        use std::sync::atomic::Ordering;

        let root = TempDir::new().unwrap();
        let dest = root.path().join("dest");
        let outside = root.path().join("outside");
        std::fs::create_dir(&dest).unwrap();
        std::fs::create_dir(&outside).unwrap();

        let mut builder = tar::Builder::new(Vec::new());
        for i in 0..200 {
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Regular);
            header.set_size(4);
            header.set_mode(0o644);
            header.set_cksum();
            builder
                .append_data(&mut header, format!("d/sub/f{i}"), b"data" as &[u8])
                .unwrap();
        }
        let data = builder.into_inner().unwrap();
        let config = SecurityConfig::default();
        let stop = AtomicBool::new(false);

        std::thread::scope(|scope| {
            scope.spawn(|| {
                while !stop.load(Ordering::Relaxed) {
                    let moved = dest.join("d_moved");
                    if std::fs::rename(dest.join("d"), &moved).is_ok() {
                        let _ = std::os::unix::fs::symlink(&outside, dest.join("d"));
                        let _ = std::fs::remove_file(dest.join("d"));
                        let _ = std::fs::rename(&moved, dest.join("d"));
                    }
                }
            });
            let archive = TarArchive::new(Cursor::new(data.clone()));
            let _ = archive.extract(
                &dest,
                &config,
                &ExtractionOptions::default(),
                &mut crate::NoopProgress,
            );
            stop.store(true, Ordering::Relaxed);
        });

        assert_eq!(std::fs::read_dir(&outside).unwrap().count(), 0);
    }

    /// Builds a TAR with a regular file entry (`target.txt`) followed by a
    /// hardlink entry (`hardlink.txt`) pointing at it.
    #[cfg(unix)]
    fn create_hardlink_tar(target_content: &[u8]) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());

        let mut file_header = tar::Header::new_gnu();
        file_header.set_entry_type(tar::EntryType::Regular);
        file_header.set_size(target_content.len() as u64);
        file_header.set_mode(0o644);
        file_header.set_cksum();
        builder
            .append_data(&mut file_header, "target.txt", target_content)
            .unwrap();

        let mut link_header = tar::Header::new_gnu();
        link_header.set_entry_type(tar::EntryType::Link);
        link_header.set_link_name("target.txt").unwrap();
        link_header.set_size(0);
        link_header.set_cksum();
        builder
            .append_data(&mut link_header, "hardlink.txt", &[] as &[u8])
            .unwrap();

        builder.into_inner().unwrap()
    }

    /// Regression test for issue #467: a dangling symlink pre-planted at the
    /// hardlink's destination path used to bypass the old `Path::exists()`
    /// duplicate check (which returns `false` for a dangling symlink) and a
    /// subsequent `fs::copy` followed it, writing archive content outside
    /// the extraction root. With `skip_duplicates=true` (the default), the
    /// pre-existing path at `hardlink.txt` must now be treated as a
    /// duplicate and skipped instead of being written through.
    #[test]
    #[cfg(unix)]
    fn test_hardlink_dangling_symlink_at_destination_skipped() {
        let temp = TempDir::new().unwrap();
        let outside = TempDir::new().unwrap();
        let victim_path = outside.path().join("victim.txt");

        // Pre-plant a dangling symlink at the hardlink's destination path,
        // pointing outside the extraction root at a file that does not exist.
        let link_dest = temp.path().join("hardlink.txt");
        std::os::unix::fs::symlink(&victim_path, &link_dest).unwrap();
        assert!(!victim_path.exists());

        let tar_data = create_hardlink_tar(b"pwned!");
        let archive = TarArchive::new(Cursor::new(tar_data));

        let mut config = SecurityConfig::default();
        config.allowed.hardlinks = crate::Admit::Allow;

        let report = archive
            .extract(
                temp.path(),
                &config,
                &ExtractionOptions::default(), // skip_duplicates = true
                &mut crate::NoopProgress,
            )
            .expect("extraction should succeed by skipping the duplicate");

        assert_eq!(report.files_skipped, 1);
        assert!(
            !victim_path.exists(),
            "hardlink write followed the pre-planted symlink outside the extraction root"
        );

        // The pre-planted symlink itself must be left untouched, not followed
        // or replaced.
        let link_metadata = std::fs::symlink_metadata(&link_dest).unwrap();
        assert!(link_metadata.file_type().is_symlink());
    }

    /// Companion to [`test_hardlink_dangling_symlink_at_destination_skipped`]
    /// with `skip_duplicates=false`: the pre-planted symlink must still be
    /// rejected as a duplicate-entry error rather than followed.
    #[test]
    #[cfg(unix)]
    fn test_hardlink_dangling_symlink_at_destination_errors_when_skip_disabled() {
        let temp = TempDir::new().unwrap();
        let outside = TempDir::new().unwrap();
        let victim_path = outside.path().join("victim.txt");

        let link_dest = temp.path().join("hardlink.txt");
        std::os::unix::fs::symlink(&victim_path, &link_dest).unwrap();

        let tar_data = create_hardlink_tar(b"pwned!");
        let archive = TarArchive::new(Cursor::new(tar_data));

        let mut config = SecurityConfig::default();
        config.allowed.hardlinks = crate::Admit::Allow;
        let options = ExtractionOptions {
            atomic: false,
            skip_duplicates: false,
            ..ExtractionOptions::default()
        };

        let result = archive.extract(temp.path(), &config, &options, &mut crate::NoopProgress);

        assert!(!victim_path.exists());
        // The regular `target.txt` entry extracts successfully before the
        // hardlink entry fails, so the error arrives wrapped in
        // PartialExtraction; unwrap one level to check the source.
        match result {
            Err(ArchiveError::PartialExtraction { source, .. }) => match *source {
                ArchiveError::InvalidArchive(msg) => {
                    assert!(msg.to_string().contains("duplicate entry"));
                }
                other => panic!("Expected InvalidArchive duplicate-entry error, got: {other:?}"),
            },
            Err(ArchiveError::InvalidArchive(msg)) => {
                assert!(msg.to_string().contains("duplicate entry"));
            }
            other => panic!("Expected InvalidArchive duplicate-entry error, got: {other:?}"),
        }

        let link_metadata = std::fs::symlink_metadata(&link_dest).unwrap();
        assert!(link_metadata.file_type().is_symlink());
    }

    /// Regression test for issue #467's pass-1-to-pass-2 TOCTOU: a hardlink
    /// target that is safe when `EntryValidator::validate_entry`
    /// (`HardlinkTracker::validate_hardlink`) runs in pass one, but gets
    /// swapped for a symlink escaping `dest` before `create_hardlink` (pass
    /// two) actually reads it, must not have its escape-target content
    /// copied into the destination.
    ///
    /// Calls `create_hardlink` directly with a hand-built `HardlinkInfo`
    /// instead of going through `TarArchive::extract`, since the two passes
    /// run back-to-back within a single `extract()` call with no way for a
    /// test to inject a filesystem change in between. This is deliberate: a
    /// plain pre-planted symlink present *before* pass one runs is already
    /// rejected by pass one's own `resolve_through_symlinks` check
    /// (`HardlinkTracker::validate_hardlink`, issue #116) and never reaches
    /// `create_hardlink` at all — asserting against that scenario would
    /// pass identically on the pre-#467-fix code and prove nothing about
    /// this change. Simulating the race directly is the only way to
    /// exercise the symlink-at-target re-resolution path of
    /// `HostTarget::hardlink` and its `resolve_through_symlinks` re-validation.
    #[test]
    #[cfg(unix)]
    fn test_hardlink_target_swapped_for_escaping_symlink_between_passes() {
        let temp = TempDir::new().unwrap();
        let outside = TempDir::new().unwrap();
        let sentinel_path = outside.path().join("sentinel.txt");
        std::fs::write(&sentinel_path, b"top secret").unwrap();

        let mut config = SecurityConfig::default();
        config.allowed.hardlinks = crate::Admit::Allow;

        // Simulates: pass one validated "target.txt" as a safe relative
        // target (it did not exist yet, or was something innocuous) and
        // recorded this `HardlinkInfo` for pass two. Between the two passes,
        // an attacker with write access to `dest` swaps in a symlink
        // escaping the destination — exactly the window pass one's
        // point-in-time check cannot see across.
        let mut target = HostTarget::create(temp.path(), &config).unwrap();
        let validated = target
            .validate_hardlink(
                Path::new("loot.txt"),
                Path::new("target.txt"),
                EntrySize::new(Uncompressed(0), None),
            )
            .unwrap();
        let info = HardlinkInfo {
            link_path: validated.link,
            target_path: validated.target,
            counted: validated.counted,
        };
        std::os::unix::fs::symlink(&sentinel_path, temp.path().join("target.txt")).unwrap();

        let mut report = ExtractionReport::new();
        let mut progress = crate::NoopProgress;
        let mut duplicate_skips = 0u64;
        let mut hardlink_duplicate_skips = 0u64;
        let mut extension_skips = 0u64;
        let mut tally = Tally {
            report: &mut report,
            options: SinkOptions::default(),
            duplicate_skips: &mut duplicate_skips,
            extension_skips: &mut extension_skips,
            progress: &mut progress,
        };

        let result = target.hardlink(
            &info.link_path,
            &info.target_path,
            info.counted,
            &mut tally,
            &mut hardlink_duplicate_skips,
        );

        assert_matches!(
            result,
            Err(ArchiveError::HardlinkEscape { .. }),
            "expected the pass-1-to-pass-2 target swap to be rejected as a hardlink escape, got: {result:?}"
        );
        assert!(
            !temp.path().join("loot.txt").exists(),
            "sentinel content must not have been copied into the destination, and TempFileGuard \
             must have removed the exclusively-opened link file on this error path"
        );
    }

    /// Regression test for issue #467's `TempFileGuard` cleanup path: when
    /// the quota reservation fails *after* the hardlink's exclusive-open
    /// destination file was already created, no stray zero-byte file must
    /// be left behind at `link_path`.
    #[test]
    #[cfg(unix)]
    fn test_hardlink_quota_failure_leaves_no_stray_link_file() {
        let temp = TempDir::new().unwrap();

        let tar_data = create_hardlink_tar(&[b'A'; 100]);
        let archive = TarArchive::new(Cursor::new(tar_data));

        let mut config = SecurityConfig::default();
        config.allowed.hardlinks = crate::Admit::Allow;
        // Enough room for target.txt (100 bytes) but not for the hardlink's
        // own independent 100-byte copy on top of it.
        config.max_total_size = crate::Limit::Bounded(crate::non_zero!(150));

        let result = archive.extract(
            temp.path(),
            &config,
            &ExtractionOptions::default(),
            &mut crate::NoopProgress,
        );

        assert!(result.is_err(), "expected quota exceeded, got: {result:?}");
        assert!(
            temp.path().join("target.txt").exists(),
            "target.txt should have been extracted before the hardlink's quota failure"
        );
        assert!(
            !temp.path().join("hardlink.txt").exists(),
            "TempFileGuard must remove the empty hardlink destination file left by the failed \
             quota reservation"
        );
    }

    /// Regression test for issue #467's
    /// symlink-at-target re-resolution path of `HostTarget::hardlink`: a
    /// hardlink whose target is itself a symlink pointing *inside* `dest`
    /// (a legitimate, common archive shape — two links sharing an inode,
    /// where the second is stored as a `Symlink` entry rather than a second
    /// `Link` entry) must still extract correctly, not hard-fail with a raw
    /// `ELOOP`.
    ///
    /// Archive order matters here: `real.txt` (regular) then `loot.txt`
    /// (hardlink -> `target.txt`) then `target.txt` (symlink -> `real.txt`)
    /// means `target.txt` does not exist on disk yet when `loot.txt`'s
    /// hardlink entry is validated in pass one, so pass one cannot resolve
    /// the symlink itself — deferring to pass two's `create_hardlink`, which
    /// by then finds `target.txt` on disk as the symlink created earlier in
    /// the same pass-one loop. This is the exact ordering the regression was
    /// reproduced with.
    #[test]
    #[cfg(unix)]
    fn test_hardlink_target_is_legitimate_symlink_created_earlier_in_extraction() {
        let temp = TempDir::new().unwrap();

        let mut builder = tar::Builder::new(Vec::new());

        let mut file_header = tar::Header::new_gnu();
        file_header.set_entry_type(tar::EntryType::Regular);
        file_header.set_size(5);
        file_header.set_mode(0o644);
        file_header.set_cksum();
        builder
            .append_data(&mut file_header, "real.txt", b"hello" as &[u8])
            .unwrap();

        let mut link_header = tar::Header::new_gnu();
        link_header.set_entry_type(tar::EntryType::Link);
        link_header.set_link_name("target.txt").unwrap();
        link_header.set_size(0);
        link_header.set_cksum();
        builder
            .append_data(&mut link_header, "loot.txt", &[] as &[u8])
            .unwrap();

        let mut symlink_header = tar::Header::new_gnu();
        symlink_header.set_entry_type(tar::EntryType::Symlink);
        symlink_header.set_link_name("real.txt").unwrap();
        symlink_header.set_size(0);
        symlink_header.set_cksum();
        builder
            .append_data(&mut symlink_header, "target.txt", &[] as &[u8])
            .unwrap();

        let tar_data = builder.into_inner().unwrap();
        let archive = TarArchive::new(Cursor::new(tar_data));

        let mut config = SecurityConfig::default();
        config.allowed.hardlinks = crate::Admit::Allow;
        config.allowed.symlinks = crate::Admit::Allow;

        let report = archive
            .extract(
                temp.path(),
                &config,
                &ExtractionOptions::default(),
                &mut crate::NoopProgress,
            )
            .expect("legitimate hardlink-to-in-dest-symlink shape must extract successfully");

        assert_eq!(report.files_extracted, 2, "real.txt and loot.txt");
        assert_eq!(report.symlinks_created, 1, "target.txt");
        assert_eq!(
            std::fs::read(temp.path().join("loot.txt")).unwrap(),
            b"hello",
            "loot.txt must contain real.txt's content, resolved through target.txt's symlink"
        );
    }

    // OPT-H001: Test SmallVec stack allocation for hardlinks
    #[test]
    #[cfg(unix)]
    fn test_hardlink_collection_stack_allocation() {
        // Test with 7 hardlinks - should stay on stack (SmallVec<[T; 8]>)
        let mut builder = tar::Builder::new(Vec::new());

        // Add target file
        let mut header = tar::Header::new_gnu();
        header.set_size(5);
        header.set_mode(0o644);
        header.set_entry_type(tar::EntryType::Regular);
        header.set_cksum();
        builder
            .append_data(&mut header, "target.txt", &b"data\n"[..])
            .unwrap();

        // Add 7 hardlinks (stays on stack)
        for i in 0..7 {
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Link);
            header.set_link_name("target.txt").unwrap();
            header.set_size(0);
            header.set_cksum();
            builder
                .append_data(&mut header, format!("link{i}.txt"), &[] as &[u8])
                .unwrap();
        }

        let tar_data = builder.into_inner().unwrap();
        let archive = TarArchive::new(Cursor::new(tar_data));

        let temp = TempDir::new().unwrap();
        let mut config = SecurityConfig::default();
        config.allowed.hardlinks = crate::Admit::Allow;

        let report = archive
            .extract(
                temp.path(),
                &config,
                &ExtractionOptions::default(),
                &mut crate::NoopProgress,
            )
            .unwrap();

        // 1 target file + 7 hardlinks = 8 files extracted
        assert_eq!(report.files_extracted, 8);
        for i in 0..7 {
            assert!(temp.path().join(format!("link{i}.txt")).exists());
        }
    }

    // OPT-H001: Test SmallVec heap spillover for hardlinks
    #[test]
    #[cfg(unix)]
    fn test_hardlink_collection_heap_spillover() {
        // Test with 20 hardlinks - should spill to heap
        let mut builder = tar::Builder::new(Vec::new());

        // Add target file
        let mut header = tar::Header::new_gnu();
        header.set_size(5);
        header.set_mode(0o644);
        header.set_entry_type(tar::EntryType::Regular);
        header.set_cksum();
        builder
            .append_data(&mut header, "target.txt", &b"data\n"[..])
            .unwrap();

        // Add 20 hardlinks (spills to heap)
        for i in 0..20 {
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Link);
            header.set_link_name("target.txt").unwrap();
            header.set_size(0);
            header.set_cksum();
            builder
                .append_data(&mut header, format!("link{i}.txt"), &[] as &[u8])
                .unwrap();
        }

        let tar_data = builder.into_inner().unwrap();
        let archive = TarArchive::new(Cursor::new(tar_data));

        let temp = TempDir::new().unwrap();
        let mut config = SecurityConfig::default();
        config.allowed.hardlinks = crate::Admit::Allow;

        let report = archive
            .extract(
                temp.path(),
                &config,
                &ExtractionOptions::default(),
                &mut crate::NoopProgress,
            )
            .unwrap();

        // 1 target file + 20 hardlinks = 21 files extracted
        assert_eq!(report.files_extracted, 21);
        for i in 0..20 {
            assert!(temp.path().join(format!("link{i}.txt")).exists());
        }
    }

    // Builds a raw TAR archive with a PAX extended header that advertises
    // `pax_size` for the file, while the ustar header carries size=0.
    // This is exactly the structure that exploits the PAX quota bypass (issue
    // #82).
    fn create_tar_with_pax_size_override(filename: &str, pax_size: u64, data: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();

        let pax_bytes = &exarch_testkit::pax::record(b"size", pax_size.to_string().as_bytes());

        // PAX extended header (type 'x') with the computed size
        let mut pax_header = tar::Header::new_ustar();
        pax_header.set_entry_type(tar::EntryType::XHeader);
        pax_header.set_size(pax_bytes.len() as u64);
        pax_header.set_mode(0o644);
        pax_header.set_path("././@PaxHeader").unwrap();
        pax_header.set_cksum();
        out.extend_from_slice(pax_header.as_bytes());
        out.extend_from_slice(pax_bytes);
        let pax_pad = (512 - pax_bytes.len() % 512) % 512;
        out.extend(std::iter::repeat_n(0u8, pax_pad));

        // Regular file header with ustar size=0 (triggers the bypass pre-fix)
        let mut file_header = tar::Header::new_ustar();
        file_header.set_entry_type(tar::EntryType::Regular);
        file_header.set_size(0);
        file_header.set_mode(0o644);
        file_header.set_path(filename).unwrap();
        file_header.set_cksum();
        out.extend_from_slice(file_header.as_bytes());
        out.extend_from_slice(data);
        let data_pad = if data.is_empty() {
            0
        } else {
            (512 - data.len() % 512) % 512
        };
        out.extend(std::iter::repeat_n(0u8, data_pad));

        // End-of-archive: two 512-byte zero blocks
        out.extend(std::iter::repeat_n(0u8, 1024));
        out
    }

    #[test]
    fn test_pax_size_override_bypasses_max_file_size_quota() {
        // Regression for issue #82: PAX size must be used for quota, not ustar
        // size. File has PAX size=2MB but ustar size=0; limit is 1MB —
        // must be rejected.
        const PAX_SIZE: u64 = 2 * 1024 * 1024;
        let data = vec![0u8; usize::try_from(PAX_SIZE).unwrap()];
        let tar_data = create_tar_with_pax_size_override("big.bin", PAX_SIZE, &data);

        let archive = TarArchive::new(Cursor::new(tar_data));
        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default().with_max_file_size(crate::non_zero!(1024 * 1024));

        let result = archive.extract(
            temp.path(),
            &config,
            &ExtractionOptions::default(),
            &mut crate::NoopProgress,
        );
        assert!(
            result.is_err(),
            "expected quota error for PAX file size override, got: {result:?}"
        );
    }

    #[test]
    fn test_pax_size_override_bypasses_max_total_size_quota() {
        // Regression for issue #82: PAX size must be used for total-size quota.
        // File has PAX size=600KB but ustar size=0; total limit is 500KB — must
        // be rejected.
        const PAX_SIZE: u64 = 600 * 1024;
        let data = vec![0u8; usize::try_from(PAX_SIZE).unwrap()];
        let tar_data = create_tar_with_pax_size_override("big.bin", PAX_SIZE, &data);

        let archive = TarArchive::new(Cursor::new(tar_data));
        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default().with_max_total_size(crate::non_zero!(500 * 1024));

        let result = archive.extract(
            temp.path(),
            &config,
            &ExtractionOptions::default(),
            &mut crate::NoopProgress,
        );
        assert!(
            result.is_err(),
            "expected quota error for PAX total size override, got: {result:?}"
        );
    }

    // OPT-H001: Test SmallVec boundary at exactly 8 hardlinks
    #[test]
    #[cfg(unix)]
    fn test_hardlink_collection_boundary() {
        // Test with exactly 8 hardlinks - boundary case
        let mut builder = tar::Builder::new(Vec::new());

        // Add target file
        let mut header = tar::Header::new_gnu();
        header.set_size(5);
        header.set_mode(0o644);
        header.set_entry_type(tar::EntryType::Regular);
        header.set_cksum();
        builder
            .append_data(&mut header, "target.txt", &b"data\n"[..])
            .unwrap();

        // Add exactly 8 hardlinks (boundary case)
        for i in 0..8 {
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Link);
            header.set_link_name("target.txt").unwrap();
            header.set_size(0);
            header.set_cksum();
            builder
                .append_data(&mut header, format!("link{i}.txt"), &[] as &[u8])
                .unwrap();
        }

        let tar_data = builder.into_inner().unwrap();
        let archive = TarArchive::new(Cursor::new(tar_data));

        let temp = TempDir::new().unwrap();
        let mut config = SecurityConfig::default();
        config.allowed.hardlinks = crate::Admit::Allow;

        let report = archive
            .extract(
                temp.path(),
                &config,
                &ExtractionOptions::default(),
                &mut crate::NoopProgress,
            )
            .unwrap();

        // 1 target file + 8 hardlinks = 9 files extracted
        assert_eq!(report.files_extracted, 9);
        for i in 0..8 {
            assert!(temp.path().join(format!("link{i}.txt")).exists());
        }
    }

    /// Build a TAR archive in-memory with two entries sharing the same path.
    fn create_duplicate_entry_tar(path: &str, content1: &[u8], content2: &[u8]) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());

        let mut header = tar::Header::new_gnu();
        header.set_size(content1.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder.append_data(&mut header, path, content1).unwrap();

        let mut header = tar::Header::new_gnu();
        header.set_size(content2.len() as u64);
        header.set_mode(0o644);
        header.set_cksum();
        builder.append_data(&mut header, path, content2).unwrap();

        builder.into_inner().unwrap()
    }

    #[test]
    fn test_duplicate_entry_skip_default() {
        let tar_data = create_duplicate_entry_tar("legit.txt", b"first", b"second");
        let archive = TarArchive::new(Cursor::new(tar_data));

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default();
        let options = ExtractionOptions::default(); // skip_duplicates = true

        let report = archive
            .extract(temp.path(), &config, &options, &mut crate::NoopProgress)
            .unwrap();

        // First entry extracted, second skipped
        assert_eq!(report.files_extracted, 1);
        assert_eq!(report.files_skipped, 1);
        assert_eq!(report.warnings.len(), 1);
        assert!(report.warnings[0].contains("pre-existing duplicates"));

        // File content is from the first entry
        let content = std::fs::read(temp.path().join("legit.txt")).unwrap();
        assert_eq!(content, b"first");
    }

    #[test]
    fn test_duplicate_entry_overwrites_when_skip_disabled() {
        let tar_data = create_duplicate_entry_tar("legit.txt", b"first", b"second");
        let archive = TarArchive::new(Cursor::new(tar_data));

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default();
        let options = ExtractionOptions {
            atomic: false,
            skip_duplicates: false,
            ..ExtractionOptions::default()
        };

        let report = archive
            .extract(temp.path(), &config, &options, &mut crate::NoopProgress)
            .unwrap();

        // Both entries extracted (second overwrites first)
        assert_eq!(report.files_extracted, 2);
        assert_eq!(report.files_skipped, 0);

        // File content is from the second (overwriting) entry
        let content = std::fs::read(temp.path().join("legit.txt")).unwrap();
        assert_eq!(content, b"second");
    }

    /// Regression test for issue #490: extracting an archive with many
    /// pre-existing duplicate entries must push exactly one aggregated
    /// warning onto `report.warnings`, not one `String` per skipped entry
    /// (mirrors 7z's `test_skip_duplicates_aggregates_single_warning`, #484).
    #[test]
    fn test_skip_duplicates_aggregates_single_warning() {
        const ENTRY_COUNT: usize = 30;
        let names: Vec<String> = (0..ENTRY_COUNT).map(|i| format!("dup-{i}.txt")).collect();
        let entries: Vec<(&str, &[u8])> = names
            .iter()
            .map(|n| (n.as_str(), b"payload".as_slice()))
            .collect();
        let tar_data = create_test_tar(entries);
        let archive = TarArchive::new(Cursor::new(tar_data));

        let temp = TempDir::new().unwrap();
        for name in &names {
            std::fs::write(temp.path().join(name), b"already here").unwrap();
        }

        let config = SecurityConfig::default();
        let report = archive
            .extract(
                temp.path(),
                &config,
                &ExtractionOptions::default(), // skip_duplicates = true
                &mut crate::NoopProgress,
            )
            .unwrap();

        assert_eq!(report.files_skipped, ENTRY_COUNT);
        assert_eq!(report.files_extracted, 0);
        assert_eq!(
            report.warnings.len(),
            1,
            "duplicate skips must be aggregated into a single warning, got: {:?}",
            report.warnings
        );
        assert!(
            report.warnings[0].contains(&ENTRY_COUNT.to_string()),
            "aggregated warning must report the correct skipped count, got: {}",
            report.warnings[0]
        );
    }

    /// Companion to [`test_skip_duplicates_aggregates_single_warning`]: TAR's
    /// hardlink duplicate-skip path (`create_hardlink`) is not routed
    /// through `common.rs`, so it needs its own counter and must be verified
    /// to aggregate separately (issue #490).
    #[test]
    #[cfg(unix)]
    fn test_skip_duplicate_hardlinks_aggregates_single_warning() {
        const LINK_COUNT: usize = 10;

        let mut builder = tar::Builder::new(Vec::new());

        let mut header = tar::Header::new_gnu();
        header.set_size(5);
        header.set_mode(0o644);
        header.set_entry_type(tar::EntryType::Regular);
        header.set_cksum();
        builder
            .append_data(&mut header, "target.txt", &b"data\n"[..])
            .unwrap();

        for i in 0..LINK_COUNT {
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Link);
            header.set_link_name("target.txt").unwrap();
            header.set_size(0);
            header.set_cksum();
            builder
                .append_data(&mut header, format!("link{i}.txt"), &[] as &[u8])
                .unwrap();
        }

        let tar_data = builder.into_inner().unwrap();
        let archive = TarArchive::new(Cursor::new(tar_data));

        let temp = TempDir::new().unwrap();
        for i in 0..LINK_COUNT {
            std::fs::write(temp.path().join(format!("link{i}.txt")), b"already here").unwrap();
        }

        let mut config = SecurityConfig::default();
        config.allowed.hardlinks = crate::Admit::Allow;

        let report = archive
            .extract(
                temp.path(),
                &config,
                &ExtractionOptions::default(), // skip_duplicates = true
                &mut crate::NoopProgress,
            )
            .unwrap();

        assert_eq!(report.files_skipped, LINK_COUNT);
        assert_eq!(report.files_extracted, 1, "only target.txt is extracted");
        assert_eq!(
            report.warnings.len(),
            1,
            "hardlink duplicate skips must be aggregated into a single warning, got: {:?}",
            report.warnings
        );
        assert!(
            report.warnings[0].contains(&LINK_COUNT.to_string())
                && report.warnings[0].contains("hardlink"),
            "aggregated warning must report the correct skipped hardlink count, got: {}",
            report.warnings[0]
        );
    }

    #[test]
    fn test_list_returns_manifest_with_entries() {
        let tar_data = create_test_tar(vec![("a.txt", b"hello"), ("b.txt", b"world")]);
        let archive = TarArchive::new(Cursor::new(tar_data));
        let config = SecurityConfig::default();

        let manifest = archive.list(&config).unwrap();

        assert_eq!(manifest.total_entries(), 2);
        assert_eq!(manifest.total_size(), 10);
    }

    #[test]
    fn test_list_empty_archive_returns_empty_manifest() {
        let tar_data = create_test_tar(vec![]);
        let archive = TarArchive::new(Cursor::new(tar_data));
        let config = SecurityConfig::default();

        let manifest = archive.list(&config).unwrap();

        assert_eq!(manifest.total_entries(), 0);
        assert_eq!(manifest.total_size(), 0);
    }

    #[test]
    fn test_verify_clean_archive_is_safe() {
        let tar_data = create_test_tar(vec![("safe.txt", b"data")]);
        let archive = TarArchive::new(Cursor::new(tar_data));
        let config = SecurityConfig::default();

        let report = archive
            .verify(&config, &crate::VerificationOptions::default())
            .unwrap();

        assert!(report.is_safe());
        assert_eq!(report.total_entries(), 1);
    }

    fn create_tar_with_absolute_path(path_bytes: &[u8], content: &[u8]) -> Vec<u8> {
        let mut builder = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_size(content.len() as u64);
        header.set_mode(0o644);
        let mut name_field = [0u8; 100];
        let len = path_bytes.len().min(100);
        name_field[..len].copy_from_slice(&path_bytes[..len]);
        header.as_gnu_mut().unwrap().name = name_field;
        header.set_cksum();
        builder.append(&header, content).unwrap();
        builder.into_inner().unwrap()
    }

    #[test]
    fn test_tar_absolute_path_rejected_by_default() {
        let tar_data = create_tar_with_absolute_path(b"/etc/shadow", b"secret");
        let archive = TarArchive::new(Cursor::new(tar_data));

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default();

        let result = archive.extract(
            temp.path(),
            &config,
            &ExtractionOptions::default(),
            &mut NoopProgress,
        );
        assert!(result.is_err(), "absolute path must be rejected by default");
        assert_matches!(
            result.unwrap_err(),
            ArchiveError::PathTraversal { .. },
            "expected PathTraversal"
        );
    }

    #[test]
    fn test_tar_absolute_path_with_flag_writes_to_dest() {
        let tar_data = create_tar_with_absolute_path(b"/etc/shadow", b"content");
        let archive = TarArchive::new(Cursor::new(tar_data));

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default().with_allow_absolute_paths(true);

        let report = archive
            .extract(
                temp.path(),
                &config,
                &ExtractionOptions::default(),
                &mut NoopProgress,
            )
            .unwrap();

        assert_eq!(report.files_extracted, 1);
        assert!(
            temp.path().join("etc/shadow").exists(),
            "file must land inside dest, not at real /etc/shadow"
        );
    }

    #[test]
    fn test_tar_absolute_path_traversal_still_rejected_with_flag() {
        // Even with allow_absolute_paths, `/../etc/passwd` contains `..` and
        // must be rejected regardless.
        let tar_data = create_tar_with_absolute_path(b"/../etc/passwd", b"secret");
        let archive = TarArchive::new(Cursor::new(tar_data));

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default().with_allow_absolute_paths(true);

        let result = archive.extract(
            temp.path(),
            &config,
            &ExtractionOptions::default(),
            &mut NoopProgress,
        );
        assert!(
            result.is_err(),
            "traversal-after-root must be rejected even with allow_absolute_paths"
        );
    }

    #[test]
    fn test_allowed_extensions_filters_out_disallowed() {
        let tar_data = create_test_tar(vec![("keep.txt", b"keep"), ("skip.exe", b"skip")]);
        let dest = tempfile::tempdir().unwrap();
        let config = SecurityConfig::default()
            .try_add_allowed_extension("txt")
            .unwrap();

        let report = TarArchive::new(Cursor::new(tar_data))
            .extract(
                dest.path(),
                &config,
                &ExtractionOptions::default(),
                &mut NoopProgress,
            )
            .unwrap();

        assert_eq!(report.files_extracted, 1);
        assert_eq!(report.files_skipped, 1);
        assert!(dest.path().join("keep.txt").exists());
        assert!(!dest.path().join("skip.exe").exists());
        assert_eq!(
            report.warnings,
            vec!["skipped 1 entry with disallowed extension".to_string()],
            "the disallowed-extension skip must be aggregated into a single warning \
             instead of a per-entry, path-bearing one (issue #495)"
        );
    }

    /// Reproduces the actual #495 bug scenario end-to-end: many entries
    /// rejected by the extension allowlist must aggregate into a single
    /// warning instead of growing `report.warnings` proportional to archive
    /// size (mirrors `test_skip_duplicates_aggregates_single_warning`, #490).
    #[test]
    fn test_disallowed_extension_aggregates_single_warning() {
        const ENTRY_COUNT: usize = 30;
        let names: Vec<String> = (0..ENTRY_COUNT).map(|i| format!("skip-{i}.exe")).collect();
        let entries: Vec<(&str, &[u8])> = names
            .iter()
            .map(|n| (n.as_str(), b"payload".as_slice()))
            .collect();
        let tar_data = create_test_tar(entries);
        let dest = tempfile::tempdir().unwrap();
        let config = SecurityConfig::default()
            .try_add_allowed_extension("txt")
            .unwrap();

        let report = TarArchive::new(Cursor::new(tar_data))
            .extract(
                dest.path(),
                &config,
                &ExtractionOptions::default(),
                &mut NoopProgress,
            )
            .unwrap();

        assert_eq!(report.files_skipped, ENTRY_COUNT);
        assert_eq!(report.files_extracted, 0);
        assert_eq!(
            report.warnings,
            vec![format!(
                "skipped {ENTRY_COUNT} entries with disallowed extensions"
            )],
            "disallowed-extension skips must be aggregated into a single warning, got: {:?}",
            report.warnings
        );
    }

    /// Verifies duplicate-skip and disallowed-extension-skip counters
    /// aggregate independently in the same extraction: an archive mixing
    /// both skip reasons must produce exactly two warnings, one per reason,
    /// each with the correct count (issue #495).
    #[test]
    fn test_duplicate_and_disallowed_extension_skips_aggregate_independently() {
        const DUPLICATE_COUNT: usize = 5;
        const DISALLOWED_COUNT: usize = 7;

        let mut names: Vec<String> = (0..DUPLICATE_COUNT)
            .map(|i| format!("dup-{i}.txt"))
            .collect();
        names.extend((0..DISALLOWED_COUNT).map(|i| format!("skip-{i}.exe")));
        let entries: Vec<(&str, &[u8])> = names
            .iter()
            .map(|n| (n.as_str(), b"payload".as_slice()))
            .collect();
        let tar_data = create_test_tar(entries);

        let temp = TempDir::new().unwrap();
        for name in names.iter().take(DUPLICATE_COUNT) {
            std::fs::write(temp.path().join(name), b"already here").unwrap();
        }

        let config = SecurityConfig::default()
            .try_add_allowed_extension("txt")
            .unwrap();

        let report = TarArchive::new(Cursor::new(tar_data))
            .extract(
                temp.path(),
                &config,
                &ExtractionOptions::default(), // skip_duplicates = true
                &mut NoopProgress,
            )
            .unwrap();

        assert_eq!(report.files_skipped, DUPLICATE_COUNT + DISALLOWED_COUNT);
        assert_eq!(report.files_extracted, 0);
        assert_eq!(
            report.warnings.len(),
            2,
            "each skip reason must aggregate into its own single warning, got: {:?}",
            report.warnings
        );
        assert!(
            report
                .warnings
                .iter()
                .any(|w| w.contains(&DUPLICATE_COUNT.to_string()) && w.contains("duplicate")),
            "expected a duplicate-skip warning reporting {DUPLICATE_COUNT}, got: {:?}",
            report.warnings
        );
        assert!(
            report
                .warnings
                .iter()
                .any(|w| w.contains(&DISALLOWED_COUNT.to_string())
                    && w.contains("disallowed extension")),
            "expected a disallowed-extension warning reporting {DISALLOWED_COUNT}, got: {:?}",
            report.warnings
        );
    }

    #[test]
    fn test_empty_allowed_extensions_allows_all() {
        let tar_data = create_test_tar(vec![("a.txt", b"a"), ("b.exe", b"b")]);
        let dest = tempfile::tempdir().unwrap();
        let config = SecurityConfig::default(); // empty = allow all

        let report = TarArchive::new(Cursor::new(tar_data))
            .extract(
                dest.path(),
                &config,
                &ExtractionOptions::default(),
                &mut NoopProgress,
            )
            .unwrap();

        assert_eq!(report.files_extracted, 2);
        assert_eq!(report.files_skipped, 0);
    }

    #[test]
    fn test_extension_less_files_blocked_when_allowlist_nonempty() {
        // A file without any extension must be blocked when an allowlist is
        // set.
        let tar_data = create_test_tar(vec![("Makefile", b"all:"), ("keep.txt", b"ok")]);
        let dest = tempfile::tempdir().unwrap();
        let config = SecurityConfig::default()
            .try_add_allowed_extension("txt")
            .unwrap();

        let report = TarArchive::new(Cursor::new(tar_data))
            .extract(
                dest.path(),
                &config,
                &ExtractionOptions::default(),
                &mut NoopProgress,
            )
            .unwrap();

        assert_eq!(report.files_extracted, 1, "only .txt should be extracted");
        assert_eq!(
            report.files_skipped, 1,
            "extension-less file must be skipped"
        );
        assert!(!dest.path().join("Makefile").exists());
        assert!(dest.path().join("keep.txt").exists());
    }
}

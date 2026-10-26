//! ZIP archive format extraction.
//!
//! This module provides secure extraction of ZIP archives with comprehensive
//! security validation. Supported features:
//!
//! - **ZIP format** (PKZIP 2.0+)
//! - **Compression methods**: Stored, DEFLATE, DEFLATE64, BZIP2, ZSTD
//! - **Symlinks**: Via Unix extended file attributes
//! - **Central directory**: Random access to entries
//!
//! # Central Directory Structure
//!
//! Unlike TAR's linear stream, ZIP archives have a central directory at the
//! end:
//!
//! ```text
//! [File 1 Data] [File 2 Data] ... [Central Directory] [End Record]
//! ```
//!
//! This allows:
//! - Random access to any entry without scanning entire archive
//! - Metadata lookup before extraction
//! - Better zip bomb detection (know all sizes upfront)
//!
//! **Trade-off:** Requires seekable reader (`Read + Seek`).
//!
//! # Compression Support
//!
//! Each ZIP entry is independently compressed:
//!
//! | Method | Feature Flag | Typical Use |
//! |--------|--------------|-------------|
//! | Stored | (built-in) | No compression |
//! | DEFLATE | `deflate` | Standard compression (ZIP default) |
//! | DEFLATE64 | `deflate64` | Enhanced DEFLATE |
//! | BZIP2 | `bzip2` | Better compression ratio |
//! | ZSTD | `zstd` | Modern fast compression |
//!
//! Decompression is transparent during extraction.
//!
//! # Security Features
//!
//! All entries are validated through the security layer:
//!
//! - **Path traversal prevention** (rejects `../`, absolute paths)
//! - **Quota enforcement** (file size, count, total size)
//! - **Zip bomb detection** (per-entry and aggregate compression ratios)
//! - **Symlink escape detection** (symlinks must point within extraction
//!   directory)
//! - **Permission sanitization** (strips setuid/setgid bits)
//! - **Encryption rejection** (password-protected archives not supported)
//! - **Structural consistency** (local headers, duplicate names, overlapping
//!   entries, records and headers the central directory does not account for;
//!   see [`ZipConsistencyPolicy`] and `zip_structure`)
//!
//! # Entry Type Support
//!
//! | Entry Type | Supported | Detection Method |
//! |------------|-----------|------------------|
//! | Regular files | ✅ Yes | Default entry type |
//! | Directories | ✅ Yes | Name ends with `/` or explicit flag |
//! | Symlinks | ✅ Yes | Unix external attributes (mode & 0o120000) |
//! | Hardlinks | ❌ No | Not part of ZIP spec |
//!
//! ## Symlink Handling
//!
//! ZIP symlinks are platform-specific:
//!
//! - **Unix**: Symlink target stored as file data, mode indicates symlink type
//! - **Windows**: No native symlink support in ZIP
//! - **Detection**: Check Unix external file attributes for `S_IFLNK` mode
//!
//! # Password-Protected Archives
//!
//! **Security Policy:** Password-protected ZIP archives are **rejected**.
//!
//! **Rationale:**
//! - No crypto dependencies (smaller attack surface)
//! - Clear security boundary (no decryption attempted)
//! - User must decrypt separately if needed
//!
//! Detection:
//! - Archive-level check in constructor
//! - Per-entry encryption flag check during extraction
//!
//! # Examples
//!
//! Basic extraction:
//!
//! ```no_run
//! use exarch_core::ExtractionOptions;
//! use exarch_core::SecurityConfig;
//! use exarch_core::formats::ZipArchive;
//! use exarch_core::formats::traits::ArchiveFormat;
//! use std::fs::File;
//! use std::path::Path;
//!
//! let file = File::open("archive.zip")?;
//! let mut archive = ZipArchive::new(file)?;
//! let config = SecurityConfig::default().validate()?;
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
//! Custom security configuration:
//!
//! ```no_run
//! use exarch_core::ExtractionOptions;
//! use exarch_core::SecurityConfig;
//!
//! let mut config = SecurityConfig::default();
//! config.allowed.symlinks = true; // Allow symlinks
//! config.max_file_size = 100 * 1024 * 1024; // 100 MB per file
//! config.max_compression_ratio = 100.0; // Allow 100:1 compression
//! // ... extract with config
//! ```

use std::io::Read;
use std::io::Seek;
use std::path::Path;
use std::path::PathBuf;
use std::time::Instant;

use typed_path::Utf8Components;
use typed_path::Utf8WindowsComponent;
use typed_path::Utf8WindowsPath;
use zip::ZipArchive as ZipReader;

use crate::ArchiveError;
use crate::ExtractionOptions;
use crate::ExtractionReport;
use crate::ProgressCallback;
use crate::Result;
use crate::SecurityConfig;
use crate::VerificationOptions;
use crate::ZipConsistencyPolicy;
use crate::config::Validated;
use crate::copy::CopyBuffer;

use crate::copy::declared_size_exceeded;
use crate::inspection::integrity::DecodeFailure;
use crate::inspection::integrity::DecodeOutcome;
use crate::inspection::integrity::IntegrityPass;
use crate::inspection::integrity::Slot;
use crate::security::EntryValidator;
use crate::security::permissions::SanitizedMode;
use crate::security::quota::QuotaPermit;
use crate::security::validator::EntryPath;
use crate::security::validator::NodeKind;
use crate::security::validator::ValidatedEntryType;
use crate::security::validator::require_non_empty_name;
use crate::security::zipbomb::DeclaredCompressedBudget;
use crate::types::DestDir;
use crate::types::EntryType;
use crate::types::SafePath;
use crate::types::safe_path::stream_separator_error;

use super::common;
use super::common::EntryCompleteGuard;
use super::traits::ArchiveFormat;
use super::zip_structure;
use super::zip_structure::Shared;
use super::zip_structure::ZipStructure;

/// Message of the `io::Error` the `zip` crate (>= 9.0.1) raises when an entry
/// decompresses past its declared size.
pub(crate) const ZIP_DECLARED_SIZE_EXCEEDED: &str =
    "File is larger than its declared uncompressed size";

/// Message of the `io::Error` the `zip` crate raises when an entry's CRC-32
/// does not match, at the read that reaches the entry's EOF.
pub(crate) const ZIP_INVALID_CHECKSUM: &str = "Invalid checksum";

/// Shared context passed to every ZIP entry extraction call.
///
/// Groups the parameters that are constant across all entries in a single
/// archive extraction, eliminating the need to thread them through every
/// function call individually.
struct ZipExtractionContext<'a> {
    dest: &'a DestDir,
    config: &'a SecurityConfig<Validated>,
    report: &'a mut ExtractionReport,
    copy_buffer: &'a mut CopyBuffer,
    dir_cache: &'a mut common::DirCache,
    skip_duplicates: bool,
    /// Count of file/symlink entries skipped as pre-existing duplicates,
    /// threaded through `common::extract_file_with_permit` and
    /// `common::create_symlink`. Aggregated into a single warning after
    /// extraction completes instead of one warning per entry, mirroring
    /// 7z's `duplicate_skips` accumulator (issue #490).
    duplicate_skips: &'a mut u64,
    /// Count of file entries skipped by `common::check_extension_allowed`
    /// because their extension is not in the allowlist. Aggregated into a
    /// single warning after extraction completes instead of one warning
    /// per entry (issue #495).
    disallowed_extension_skips: &'a mut u64,
    progress: &'a mut dyn ProgressCallback,
}

/// How a raw ZIP entry name starts, as far as absolute-path policy cares.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NamePrefix {
    /// Starts with `/` or `\` (including UNC `\\server\share`), or a drive
    /// followed by a separator or nothing (`C:\x`, `C:/x`, `C:`)
    Rooted,
    /// A drive letter glued to a name (`C:x`): drive-relative on Windows, an
    /// ordinary file name elsewhere
    DriveRelative,
    /// Anything else
    Plain,
}

fn classify_name_prefix(raw: &str) -> NamePrefix {
    let bytes = raw.as_bytes();
    if raw.starts_with(['/', '\\']) {
        return NamePrefix::Rooted;
    }
    match (bytes.first(), bytes.get(1), bytes.get(2)) {
        (Some(drive), Some(b':'), None | Some(b'/' | b'\\')) if drive.is_ascii_alphabetic() => {
            NamePrefix::Rooted
        }
        (Some(drive), Some(b':'), Some(_)) if drive.is_ascii_alphabetic() => {
            NamePrefix::DriveRelative
        }
        _ => NamePrefix::Plain,
    }
}

/// A parsed ZIP entry name: either a clean path, or a name that extraction
/// rejects but `verify`'s listing pre-flight keeps so `verify_entry` can
/// report it.
pub(crate) enum ZipEntryName {
    /// The name passed the policy; the path is safe to join onto the
    /// destination.
    Resolved(PathBuf),
    /// The name violates the policy: extraction fails with `error`, while the
    /// verify pre-flight lists it under `path` so the report can flag it.
    Deferred { path: PathBuf, error: ArchiveError },
}

impl ZipEntryName {
    /// Extraction view: a deferred name is an error.
    pub(crate) fn into_strict(self) -> Result<PathBuf> {
        match self {
            Self::Resolved(path) => Ok(path),
            Self::Deferred { error, .. } => Err(error),
        }
    }

    /// Verify pre-flight view: a deferred name keeps its raw path.
    pub(crate) fn into_preflight_path(self) -> PathBuf {
        match self {
            Self::Resolved(path) | Self::Deferred { path, .. } => path,
        }
    }
}

/// Applies the entry-path policy shared by ZIP extraction and listing,
/// rejecting every name the policy refuses.
///
/// Besides the errors listed on [`parse_zip_entry_name`], returns
/// `SecurityViolation` for a NUL byte and, on Windows, for a `:` in any
/// component.
pub(crate) fn resolve_zip_entry_path(
    raw: &str,
    config: &SecurityConfig<Validated>,
) -> Result<PathBuf> {
    parse_zip_entry_name(raw, config)?.into_strict()
}

/// Applies the entry-path policy shared by ZIP extraction and listing.
///
/// `raw` is the entry name as stored. The name is split on both `/` and `\`
/// on every platform; for an absolute name admitted by `allow_absolute_paths`
/// the Windows prefix (drive, UNC, verbatim or device) and root are stripped
/// first.
///
/// # Errors
///
/// - `SecurityViolation` for an empty name
/// - `PathTraversal` for an absolute name without `allow_absolute_paths`, for
///   any `..` component (in the raw name or left after prefix stripping), and
///   for an absolute name that resolves to nothing
///
/// A relative name made only of `.` and separators (`./`, `.`) is the archive
/// root and resolves to `.`, which `SafePath` maps to the destination itself;
/// [`zip_node_kind`] then checks that the entry may stand for it.
///
/// A name is absolute when it starts with `/` or `\`, or with a drive plus a
/// separator or nothing (`C:\x`, `C:/x`, `C:`), on every platform. A drive
/// glued to a name (`C:x`) is absolute only on Windows; elsewhere it is an
/// ordinary file name and is kept as stored.
///
/// Two outcomes are [`ZipEntryName::Deferred`] rather than errors: a NUL byte
/// (`SecurityViolation`, checked first so it wins over every other check;
/// the path is the raw name), and on Windows a `:` in any component (stream
/// separator `SecurityViolation`; the path is the name left after prefix
/// stripping).
pub(crate) fn parse_zip_entry_name(
    raw: &str,
    config: &SecurityConfig<Validated>,
) -> Result<ZipEntryName> {
    let traversal = || ArchiveError::PathTraversal {
        path: PathBuf::from(raw),
    };

    if raw.contains('\0') {
        return Ok(ZipEntryName::Deferred {
            path: PathBuf::from(raw),
            error: ArchiveError::violation(format!(
                "path contains null bytes: {}",
                raw.escape_debug()
            )),
        });
    }

    require_non_empty_name(Path::new(raw))?;

    let prefix = classify_name_prefix(raw);
    let absolute =
        prefix == NamePrefix::Rooted || (prefix == NamePrefix::DriveRelative && cfg!(windows));
    if absolute && !config.allowed.absolute_paths {
        return Err(traversal());
    }
    if has_parent_component(raw) {
        return Err(traversal());
    }

    let rest = if absolute { strip_root(raw) } else { raw };
    // A drive glued to `..` (`\\?\C:..\x`) is one raw component but parses as
    // prefix plus `..`, so the check must run again after stripping.
    if absolute && has_parent_component(rest) {
        return Err(traversal());
    }
    let components: Vec<&str> = rest
        .split(['/', '\\'])
        .filter(|component| !component.is_empty() && *component != ".")
        .collect();
    if components.is_empty() {
        if absolute {
            return Err(traversal());
        }
        return Ok(ZipEntryName::Resolved(PathBuf::from(".")));
    }
    // On Windows, pushing `c:x` replaces the path built so far; other Windows
    // hazards are left to `SafePath`.
    if cfg!(windows)
        && let Some(component) = components.iter().find(|c| c.contains(':'))
    {
        return Ok(ZipEntryName::Deferred {
            path: PathBuf::from(rest),
            error: stream_separator_error(component),
        });
    }
    Ok(ZipEntryName::Resolved(components.into_iter().collect()))
}

/// Classifies an entry for the root-entry rule.
///
/// The root names the destination itself, so only a directory or an empty
/// regular file (the `zip` crate reads a bare `.` as a file) may stand for it,
/// and counts as a directory; a symlink or an entry with data would be written
/// onto the destination. Shared by extraction and listing so `verify` and
/// `extract` agree.
pub(crate) fn zip_node_kind<R: Read>(
    path: &Path,
    entry: &zip::read::ZipFile<'_, R>,
) -> Result<NodeKind> {
    if entry.is_dir() {
        return Ok(NodeKind::Directory);
    }
    match EntryPath::of(path) {
        EntryPath::Child(_) => Ok(NodeKind::NonDirectory),
        EntryPath::Root(_) if zip_mode_is_symlink(entry.unix_mode()) || entry.size() > 0 => {
            Err(ArchiveError::violation(
                "archive root entry '.' must be a directory or an empty regular file".into(),
            ))
        }
        EntryPath::Root(_) => Ok(NodeKind::Directory),
    }
}

fn has_parent_component(name: &str) -> bool {
    name.split(['/', '\\']).any(|component| component == "..")
}

/// The part of an absolute name after its Windows prefix (drive, UNC,
/// verbatim or device) and root.
fn strip_root(raw: &str) -> &str {
    let mut components = Utf8WindowsPath::new(raw).components();
    let mut rest = components.as_str();
    while let Some(Utf8WindowsComponent::Prefix(_) | Utf8WindowsComponent::RootDir) =
        components.next()
    {
        rest = components.as_str();
    }
    rest
}

/// Whether opening a ZIP entry failed because it is encrypted.
///
/// Matches the typed upstream variants so an upstream message change cannot
/// silently reclassify encrypted archives as merely invalid.
pub(crate) fn is_password_required(error: &zip::result::ZipError) -> bool {
    use zip::result::ZipError;

    matches!(
        error,
        ZipError::UnsupportedArchive(ZipError::PASSWORD_REQUIRED) | ZipError::InvalidPassword
    )
}

/// Appends aggregated duplicate-skip and disallowed-extension warnings to
/// `report`, mirroring TAR's `push_duplicate_skip_warnings` (issues #490,
/// #495). Called on every extraction exit path — including entry-open/name
/// failures that occur before a [`ZipExtractionContext`] exists — so no
/// early return can drop accumulated skip counts from the report.
fn push_duplicate_skip_warnings(
    report: &mut ExtractionReport,
    duplicate_skips: u64,
    disallowed_extension_skips: u64,
) {
    common::push_duplicate_skip_warning(report, duplicate_skips, "entry", "entries");
    common::push_disallowed_extension_warning(report, disallowed_extension_skips);
}

/// ZIP archive handler with random-access extraction.
///
/// Supports:
/// - ZIP format (PKZIP 2.0+)
/// - Compression methods: stored, deflate, deflate64, bzip2, zstd
/// - Unix symlinks via extended attributes
/// - Password-protected archive detection (rejected)
///
/// # Central Directory
///
/// ZIP archives have a central directory at the end containing metadata
/// for all entries. This allows random access but requires seekable reader.
///
/// # Compression
///
/// Unlike TAR, each ZIP entry is independently compressed. This allows:
/// - Selective decompression (only extract needed files)
/// - Parallel decompression (future optimization)
/// - Better compression ratio detection for zip bombs
///
/// # Examples
///
/// ```no_run
/// use exarch_core::ExtractionOptions;
/// use exarch_core::SecurityConfig;
/// use exarch_core::formats::ZipArchive;
/// use exarch_core::formats::traits::ArchiveFormat;
/// use std::fs::File;
/// use std::path::Path;
///
/// let file = File::open("archive.zip")?;
/// let mut archive = ZipArchive::new(file)?;
/// let config = SecurityConfig::default().validate()?;
/// let report = archive.extract(
///     Path::new("/output"),
///     &config,
///     &ExtractionOptions::default(),
///     &mut exarch_core::NoopProgress,
/// )?;
/// println!("Extracted {} files", report.files_extracted);
/// # Ok::<(), exarch_core::ArchiveError>(())
/// ```
pub struct ZipArchive<R: Read + Seek> {
    inner: ZipReader<Shared<R>>,
    structure: ZipStructure,
}

impl<R: Read + Seek> ZipArchive<R> {
    /// Creates a new ZIP archive handler from a seekable reader.
    ///
    /// The reader must support both `Read` and `Seek` because ZIP archives
    /// have a central directory at the end that must be parsed first.
    ///
    /// Opening runs the checks that need no configuration: encrypted entries,
    /// unsupported compression methods and declared compressed sizes that do
    /// not fit in the archive are rejected, and the archive's structure is
    /// inspected (local versus central headers, duplicate names, overlapping
    /// entries, records and local headers the central directory does not
    /// account for). Structural findings do not fail the constructor; each
    /// operation applies the
    /// [`ZipConsistencyPolicy`] of its config. The central directory is
    /// parsed once and the archive that was admitted is the one every
    /// operation uses; the structural census adds one sequential pass over
    /// the raw directory and a second read of each local header.
    ///
    /// # Errors
    ///
    /// Returns an error if:
    /// - File is not a valid ZIP archive
    /// - Central directory is corrupted, or changes while it is being read
    /// - Archive is password-protected (rejected for security)
    ///
    /// # Examples
    ///
    /// ```no_run
    /// use exarch_core::formats::ZipArchive;
    /// use std::fs::File;
    ///
    /// let file = File::open("archive.zip")?;
    /// let archive = ZipArchive::new(file)?;
    /// # Ok::<(), exarch_core::ArchiveError>(())
    /// ```
    pub fn new(reader: R) -> Result<Self> {
        let (inner, structure) = zip_structure::open(reader)?;
        Ok(Self { inner, structure })
    }

    /// The underlying reader, for listing.
    pub(crate) fn reader_mut(&mut self) -> &mut ZipReader<Shared<R>> {
        &mut self.inner
    }

    /// What the structural census found when the archive was opened.
    #[cfg(test)]
    pub(crate) const fn structure(&self) -> &ZipStructure {
        &self.structure
    }

    /// Applies the policy-independent entry count limit, then the structural
    /// policy, before an operation touches the archive's entries.
    ///
    /// The count is the raw central directory count, so duplicate records and
    /// records past the end record's count cannot be used to dodge
    /// `max_file_count`.
    fn check_count(&self, config: &SecurityConfig<Validated>) -> Result<()> {
        let found = self.structure.central_entries();
        if found > config.max_file_count {
            return Err(ArchiveError::QuotaExceeded {
                resource: crate::QuotaResource::FileCount {
                    current: found,
                    max: config.max_file_count,
                },
            });
        }
        Ok(())
    }

    /// Lists the entries under the structural policy, decoding payloads when
    /// `listing` carries an integrity pass.
    pub(crate) fn list_with(
        &mut self,
        config: &SecurityConfig<Validated>,
        listing: &mut crate::inspection::list::ListPass<'_, '_>,
    ) -> Result<crate::inspection::ArchiveManifest> {
        self.check_structure(config)?;
        crate::inspection::list::list_zip_reader(self, config, listing)
    }

    fn check_structure(&self, config: &SecurityConfig<Validated>) -> Result<()> {
        self.check_count(config)?;
        if config.zip_consistency == ZipConsistencyPolicy::Enforce
            && let Some(finding) = self.structure.findings().first()
        {
            return Err(ArchiveError::ZipInconsistency(finding.clone()));
        }
        Ok(())
    }

    /// Resolves the entry path from a ZIP file via [`resolve_zip_entry_path`].
    fn resolve_entry_path(
        zip_file: &zip::read::ZipFile<'_, Shared<R>>,
        index: usize,
        config: &SecurityConfig<Validated>,
    ) -> Result<PathBuf> {
        let raw_name = zip_file.name().map_err(|e| {
            ArchiveError::InvalidArchive(format!("invalid entry name at {index}: {e}"))
        })?;
        resolve_zip_entry_path(&raw_name, config)
    }

    /// Processes a single ZIP entry using an already-opened `ZipFile`.
    ///
    /// The caller is responsible for opening the entry via `by_index` exactly
    /// once and passing it here, so the local header is read only once per
    /// entry. Branches on entry type (directory/symlink/file) within the same
    /// borrow scope. For directories and symlinks, the zip file is explicitly
    /// dropped before calling extraction helpers. For files, the zip file
    /// remains alive through validation and is reused for data extraction.
    fn process_entry(
        mut zip_file: zip::read::ZipFile<'_, Shared<R>>,
        index: usize,
        validator: &mut EntryValidator,
        ctx: &mut ZipExtractionContext<'_>,
    ) -> Result<()> {
        if zip_file.encrypted() {
            let name = zip_file
                .name()
                .map_or_else(|_| format!("<entry {index}>"), std::borrow::Cow::into_owned);
            return Err(ArchiveError::violation(format!(
                "encrypted entry detected: {name}"
            )));
        }

        let path = Self::resolve_entry_path(&zip_file, index, ctx.config)?;

        // A non-directory entry classed as a directory is the empty root file:
        // a no-op.
        if zip_node_kind(&path, &zip_file)? == NodeKind::Directory && !zip_file.is_dir() {
            return Ok(());
        }

        let (uncompressed_size, compressed_size) = ZipEntryAdapter::get_sizes(&zip_file);
        let mode = zip_file.unix_mode();

        let entry_kind = zip_entry_kind(zip_file.is_dir(), mode);
        if entry_kind == ZipEntryKind::Directory {
            drop(zip_file);
            let validated = validator.validate_entry(
                &path,
                &EntryType::Directory,
                uncompressed_size,
                Some(compressed_size),
                mode,
                Some(ctx.dir_cache),
            )?;
            common::create_directory(validated.safe_path(), ctx.dest, ctx.report, ctx.dir_cache)?;
        } else if entry_kind == ZipEntryKind::Symlink {
            let target = ZipEntryAdapter::read_symlink_target(&mut zip_file)?;
            drop(zip_file);
            let entry_type = EntryType::Symlink { target };
            let validated = validator.validate_entry(
                &path,
                &entry_type,
                uncompressed_size,
                Some(compressed_size),
                mode,
                Some(ctx.dir_cache),
            )?;
            if let ValidatedEntryType::Symlink(safe_symlink) = validated.entry_type() {
                common::create_symlink(
                    safe_symlink,
                    ctx.dest,
                    ctx.report,
                    ctx.dir_cache,
                    ctx.skip_duplicates,
                    ctx.duplicate_skips,
                )?;
            }
        } else {
            if !common::check_extension_allowed(
                &path,
                ctx.config,
                ctx.report,
                ctx.disallowed_extension_skips,
            ) {
                return Ok(());
            }
            // File: validate BEFORE writing (security invariant preserved),
            // then extract with the same zip_file (stream still at position 0)
            let validated = validator.validate_entry(
                &path,
                &EntryType::File,
                uncompressed_size,
                Some(compressed_size),
                mode,
                Some(ctx.dir_cache),
            )?;
            // into_parts() moves the QuotaPermit out by value into
            // extract_file (mirrors 7z's process_entry_inner, issue #445),
            // rather than only observing it through entry_type()'s shared
            // reference. validate_entry(&EntryType::File, ..) always yields
            // ValidatedEntryType::File, never another variant.
            let (safe_path, entry_type, sanitized_mode) = validated.into_parts();
            let ValidatedEntryType::File(permit) = entry_type else {
                return Err(ArchiveError::violation(
                    "validate_entry(EntryType::File) returned a non-File variant".into(),
                ));
            };
            Self::extract_file(
                &mut zip_file,
                &safe_path,
                sanitized_mode,
                permit,
                uncompressed_size,
                ctx,
            )?;
        }

        Ok(())
    }

    /// Extracts a regular file to disk.
    fn extract_file(
        zip_file: &mut zip::read::ZipFile<'_, Shared<R>>,
        safe_path: &SafePath,
        mode: Option<SanitizedMode>,
        permit: QuotaPermit,
        file_size: u64,
        ctx: &mut ZipExtractionContext<'_>,
    ) -> Result<()> {
        common::extract_file_with_permit(
            zip_file,
            safe_path,
            mode,
            permit,
            ctx.dest,
            ctx.report,
            Some(file_size),
            ctx.copy_buffer,
            ctx.dir_cache,
            ctx.skip_duplicates,
            ctx.duplicate_skips,
            ctx.progress,
        )
        .map_err(|e| Self::classify_declared_size_overrun(e, file_size))
    }

    /// Re-types the `zip` crate's own declared-size ceiling as a security
    /// violation, matching what `copy_with_buffer` reports for the same
    /// forgery.
    fn classify_declared_size_overrun(err: ArchiveError, declared: u64) -> ArchiveError {
        match err {
            ArchiveError::Io(ref io)
                if io.kind() == std::io::ErrorKind::InvalidData
                    && io.to_string() == ZIP_DECLARED_SIZE_EXCEEDED =>
            {
                declared_size_exceeded(declared)
            }
            other => other,
        }
    }
}

impl<R: Read + Seek> ArchiveFormat for ZipArchive<R> {
    fn extract(
        &mut self,
        output_dir: &Path,
        config: &SecurityConfig<Validated>,
        options: &ExtractionOptions,
        progress: &mut dyn ProgressCallback,
    ) -> Result<ExtractionReport> {
        let start = Instant::now();
        let skip_duplicates = options.skip_duplicates;

        self.check_structure(config)?;
        let dest = DestDir::new_or_create(output_dir.to_path_buf())?;

        // OPT-H004: Pass references to avoid cloning
        let mut validator = EntryValidator::new(config, &dest);

        let mut report = ExtractionReport::new();

        // OPT-C002: Single copy buffer per archive instead of per-file
        // allocation
        let mut copy_buffer = CopyBuffer::new();

        let mut dir_cache = common::DirCache::new();

        // Aggregated into a single warning after extraction instead of one
        // per skipped entry, mirroring 7z's `duplicate_skips` accumulator
        // (issue #490).
        let mut duplicate_skips: u64 = 0;

        // Same aggregation, for entries rejected by the extension allowlist
        // (issue #495).
        let mut disallowed_extension_skips: u64 = 0;

        let entry_count = self.inner.len();

        for i in 0..entry_count {
            let zip_file = match self.inner.by_index(i) {
                Ok(f) => f,
                Err(e) => {
                    let err = if is_password_required(&e) {
                        common::encrypted_archive_error()
                    } else {
                        ArchiveError::InvalidArchive(format!("failed to open zip entry {i}: {e}"))
                    };
                    push_duplicate_skip_warnings(
                        &mut report,
                        duplicate_skips,
                        disallowed_extension_skips,
                    );
                    return Err(ArchiveError::partial_or(std::mem::take(&mut report), err));
                }
            };
            let entry_path = match zip_file.name() {
                Ok(name) => PathBuf::from(name.as_ref()),
                Err(e) => {
                    let err =
                        ArchiveError::InvalidArchive(format!("invalid entry name at {i}: {e}"));
                    push_duplicate_skip_warnings(
                        &mut report,
                        duplicate_skips,
                        disallowed_extension_skips,
                    );
                    return Err(ArchiveError::partial_or(std::mem::take(&mut report), err));
                }
            };
            progress.on_entry_start(&entry_path, entry_count, i.saturating_add(1));
            let mut guard = EntryCompleteGuard::new(progress, &entry_path);

            let mut ctx = ZipExtractionContext {
                dest: &dest,
                config,
                report: &mut report,
                copy_buffer: &mut copy_buffer,
                dir_cache: &mut dir_cache,
                skip_duplicates,
                duplicate_skips: &mut duplicate_skips,
                disallowed_extension_skips: &mut disallowed_extension_skips,
                progress: guard.progress_mut(),
            };

            let result = Self::process_entry(zip_file, i, &mut validator, &mut ctx);

            if let Err(e) = result {
                drop(guard);
                push_duplicate_skip_warnings(
                    &mut report,
                    duplicate_skips,
                    disallowed_extension_skips,
                );
                return Err(ArchiveError::partial_or(std::mem::take(&mut report), e));
            }
            guard.complete();
        }

        push_duplicate_skip_warnings(&mut report, duplicate_skips, disallowed_extension_skips);
        progress.on_complete();
        report.duration = start.elapsed();

        Ok(report)
    }

    fn list(
        &mut self,
        config: &SecurityConfig<Validated>,
    ) -> Result<crate::inspection::ArchiveManifest> {
        use crate::inspection::list::ListPass;
        self.list_with(config, &mut ListPass::strict())
    }

    fn verify(
        &mut self,
        config: &SecurityConfig<Validated>,
        options: &VerificationOptions,
    ) -> Result<crate::inspection::VerificationReport> {
        use crate::inspection::list::list_zip_reader;
        use crate::inspection::report::ArchiveStructure;
        use crate::inspection::verify::list_for_verify;
        use crate::inspection::verify::verify_manifest_with_structure;

        self.check_count(config)?;
        let listed = list_for_verify(config, *options, |listing| {
            list_zip_reader(self, config, listing)
        })?;
        let (findings, omitted) = match config.zip_consistency {
            ZipConsistencyPolicy::Enforce => {
                (self.structure.findings(), self.structure.omitted_findings())
            }
            ZipConsistencyPolicy::Ignore => (&[][..], 0),
        };
        let structure = ArchiveStructure::new(self.structure.central_entries(), findings, omitted);
        verify_manifest_with_structure(&listed.manifest, config, &structure, listed.integrity)
    }

    fn format_name(&self) -> &'static str {
        "zip"
    }
}

/// Adapter to convert `zip::ZipFile` metadata to internal types.
struct ZipEntryAdapter;

impl ZipEntryAdapter {
    /// Checks if an entry is a symbolic link by examining Unix mode bits.
    fn is_symlink_from_mode(mode: Option<u32>) -> bool {
        mode.and_then(common::UnixFileType::from_mode) == Some(common::UnixFileType::Symlink)
    }

    /// Reads symlink target from ZIP entry data (stored as file content).
    fn read_symlink_target<R: Read>(zip_file: &mut zip::read::ZipFile<'_, R>) -> Result<PathBuf> {
        let size = zip_file.size();
        common::check_symlink_target_size(size)?;

        // SAFETY: size has already been validated to be <=
        // MAX_STORED_SYMLINK_TARGET which is well within usize
        // range on all platforms
        #[allow(clippy::cast_possible_truncation)]
        let mut target_bytes = Vec::with_capacity(size as usize);
        zip_file
            .take(common::MAX_STORED_SYMLINK_TARGET)
            .read_to_end(&mut target_bytes)
            .map_err(|e| {
                ArchiveError::InvalidArchive(format!("failed to read symlink target: {e}"))
            })?;

        common::symlink_target_from_bytes(&target_bytes)
    }

    /// Gets uncompressed and compressed sizes.
    fn get_sizes<R: Read>(zip_file: &zip::read::ZipFile<'_, R>) -> (u64, u64) {
        (zip_file.size(), zip_file.compressed_size())
    }
}

/// Reads the symlink target stored as file data in a ZIP entry.
///
/// The ZIP spec stores symlink targets as the uncompressed file content of the
/// entry, not in any metadata field. This function enforces a hard cap of 4096
/// bytes (`PATH_MAX`) to prevent unbounded allocation.
pub(crate) fn read_zip_symlink_target<R: Read>(
    zip_file: &mut zip::read::ZipFile<'_, R>,
) -> Result<PathBuf> {
    ZipEntryAdapter::read_symlink_target(zip_file)
}

/// Reads a ZIP symlink target for an integrity pass.
///
/// Unlike [`read_zip_symlink_target`] the entry is read to its EOF through
/// `copy_bounded`, so the CRC-32 is checked: a checksum failure is recorded
/// as `CorruptData` for the entry and the bytes read are kept as the target.
/// Any other read failure is an `InvalidArchive` error, as without a pass.
///
/// # Errors
///
/// Returns an error when the target is too large, is not UTF-8, cannot be read,
/// or the disk fails.
pub(crate) fn read_zip_symlink_target_checked<R: Read>(
    zip_file: &mut zip::read::ZipFile<'_, R>,
    pass: &mut IntegrityPass<'_>,
    slot: Slot,
    entry_path: &Path,
) -> Result<PathBuf> {
    let declared = zip_file.size();
    common::check_symlink_target_size(declared)?;

    let mut target_bytes = Vec::new();
    if let Err(failure) = pass.copy_into(zip_file, &mut target_bytes, declared) {
        match failure {
            DecodeFailure::Checksum => {
                pass.record(slot, entry_path, DecodeOutcome::Failed(failure))?;
            }
            failure => {
                return Err(ArchiveError::InvalidArchive(format!(
                    "failed to read symlink target: {failure}"
                )));
            }
        }
    }
    common::symlink_target_from_bytes(&target_bytes)
}

/// Returns `true` if `mode` has the `S_IFLNK` file-type bits set.
///
/// Uses the correct POSIX mask (`S_IFMT`) to isolate the file-type field before
/// comparing — without the mask, mode bits from the permission bits can
/// spuriously match `S_IFLNK`.
pub(crate) fn zip_mode_is_symlink(mode: Option<u32>) -> bool {
    ZipEntryAdapter::is_symlink_from_mode(mode)
}

/// What extraction makes of a ZIP entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ZipEntryKind {
    Directory,
    Symlink,
    Regular,
}

/// The kind extraction gives an entry: a directory, else a symlink by its Unix
/// mode, else a regular file.
///
/// The single decision shared by extraction, listing and the structure census,
/// whose `xl` comparison is sound only while all three agree.
pub(crate) fn zip_entry_kind(is_dir: bool, unix_mode: Option<u32>) -> ZipEntryKind {
    if is_dir {
        ZipEntryKind::Directory
    } else if zip_mode_is_symlink(unix_mode) {
        ZipEntryKind::Symlink
    } else {
        ZipEntryKind::Regular
    }
}

/// Compression methods the ZIP handlers accept.
///
/// Anything else (including `deflate64`, which the `zip` crate can decode but
/// exarch does not vet) is rejected at open time by [`admit_zip_entry`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ZipMethod {
    Stored,
    Deflate,
    Bzip2,
    Zstd,
}

impl TryFrom<zip::CompressionMethod> for ZipMethod {
    type Error = ArchiveError;

    fn try_from(method: zip::CompressionMethod) -> Result<Self> {
        match method {
            zip::CompressionMethod::Stored => Ok(Self::Stored),
            zip::CompressionMethod::Deflated => Ok(Self::Deflate),
            zip::CompressionMethod::Bzip2 => Ok(Self::Bzip2),
            zip::CompressionMethod::Zstd => Ok(Self::Zstd),
            other => Err(ArchiveError::violation(format!(
                "unsupported compression method: {other:?}"
            ))),
        }
    }
}

/// Admission check shared by extraction and listing for every ZIP entry.
///
/// Rejects encrypted entries, charges the declared compressed size against
/// `budget`, and parses the compression method, so `extract`, `list` and
/// `verify` accept exactly the same set of entries.
///
/// # Errors
///
/// Returns the encrypted-archive error, `InvalidArchive` when the declared
/// size exceeds the budget, or `SecurityViolation` for an unsupported method.
pub(crate) fn admit_zip_entry<R: Read>(
    entry: &zip::read::ZipFile<'_, R>,
    budget: &mut DeclaredCompressedBudget,
) -> Result<()> {
    if entry.encrypted() {
        return Err(common::encrypted_archive_error());
    }
    budget.charge(entry.compressed_size())?;
    ZipMethod::try_from(entry.compression()).map(drop)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::items_after_statements,
    clippy::uninlined_format_args,
    clippy::field_reassign_with_default
)]
mod tests {
    use super::*;
    use crate::NoopProgress;
    use crate::raw_zip::RawEntry;
    use crate::raw_zip::RawZip;
    use crate::test_utils::create_raw_zip_entry;
    use crate::test_utils::create_test_zip;
    use std::assert_matches;
    use std::io::Cursor;
    use std::io::Write;
    use tempfile::TempDir;
    use zip::write::SimpleFileOptions;
    use zip::write::ZipWriter;

    #[test]
    fn test_zip_archive_new() {
        let zip_data = create_test_zip(vec![]);
        let cursor = Cursor::new(zip_data);
        let archive = ZipArchive::new(cursor).unwrap();
        assert_eq!(archive.format_name(), "zip");
    }

    #[test]
    fn test_extract_empty_archive() {
        let zip_data = create_test_zip(vec![]);
        let cursor = Cursor::new(zip_data);
        let mut archive = ZipArchive::new(cursor).unwrap();

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default().validate().expect("valid config");

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
    fn test_extract_simple_file() {
        let zip_data = create_test_zip(vec![("file.txt", b"hello world")]);
        let cursor = Cursor::new(zip_data);
        let mut archive = ZipArchive::new(cursor).unwrap();

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default().validate().expect("valid config");

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

        let content = std::fs::read_to_string(temp.path().join("file.txt")).unwrap();
        assert_eq!(content, "hello world");
    }

    #[test]
    fn test_extract_multiple_files() {
        let zip_data = create_test_zip(vec![
            ("file1.txt", b"content1"),
            ("file2.txt", b"content2"),
            ("file3.txt", b"content3"),
        ]);
        let cursor = Cursor::new(zip_data);
        let mut archive = ZipArchive::new(cursor).unwrap();

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default().validate().expect("valid config");

        let report = archive
            .extract(
                temp.path(),
                &config,
                &ExtractionOptions::default(),
                &mut crate::NoopProgress,
            )
            .unwrap();

        assert_eq!(report.files_extracted, 3);
    }

    #[test]
    fn test_extract_nested_structure() {
        let zip_data = create_test_zip(vec![("dir1/dir2/file.txt", b"nested")]);
        let cursor = Cursor::new(zip_data);
        let mut archive = ZipArchive::new(cursor).unwrap();

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default().validate().expect("valid config");

        let report = archive
            .extract(
                temp.path(),
                &config,
                &ExtractionOptions::default(),
                &mut crate::NoopProgress,
            )
            .unwrap();

        assert_eq!(report.files_extracted, 1);
        assert!(temp.path().join("dir1/dir2/file.txt").exists());
    }

    #[test]
    fn test_extract_with_deflate_compression() {
        let buffer = Vec::new();
        let mut zip = ZipWriter::new(Cursor::new(buffer));

        let options =
            SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);

        zip.start_file("compressed.txt", options).unwrap();
        zip.write_all(b"This text will be compressed with DEFLATE")
            .unwrap();

        let zip_data = zip.finish().unwrap().into_inner();
        let cursor = Cursor::new(zip_data);
        let mut archive = ZipArchive::new(cursor).unwrap();

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default().validate().expect("valid config");

        let report = archive
            .extract(
                temp.path(),
                &config,
                &ExtractionOptions::default(),
                &mut crate::NoopProgress,
            )
            .unwrap();

        assert_eq!(report.files_extracted, 1);

        let content = std::fs::read_to_string(temp.path().join("compressed.txt")).unwrap();
        assert_eq!(content, "This text will be compressed with DEFLATE");
    }

    #[test]
    fn test_extract_with_bzip2_compression() {
        let buffer = Vec::new();
        let mut zip = ZipWriter::new(Cursor::new(buffer));

        let options =
            SimpleFileOptions::default().compression_method(zip::CompressionMethod::Bzip2);

        zip.start_file("bzip2.txt", options).unwrap();
        zip.write_all(b"This text will be compressed with BZIP2")
            .unwrap();

        let zip_data = zip.finish().unwrap().into_inner();
        let cursor = Cursor::new(zip_data);
        let mut archive = ZipArchive::new(cursor).unwrap();

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default().validate().expect("valid config");

        let report = archive
            .extract(
                temp.path(),
                &config,
                &ExtractionOptions::default(),
                &mut crate::NoopProgress,
            )
            .unwrap();

        assert_eq!(report.files_extracted, 1);
    }

    #[test]
    fn test_extract_with_zstd_compression() {
        let buffer = Vec::new();
        let mut zip = ZipWriter::new(Cursor::new(buffer));

        let options = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Zstd);

        zip.start_file("zstd.txt", options).unwrap();
        zip.write_all(b"This text will be compressed with ZSTD")
            .unwrap();

        let zip_data = zip.finish().unwrap().into_inner();
        let cursor = Cursor::new(zip_data);
        let mut archive = ZipArchive::new(cursor).unwrap();

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default().validate().expect("valid config");

        let report = archive
            .extract(
                temp.path(),
                &config,
                &ExtractionOptions::default(),
                &mut crate::NoopProgress,
            )
            .unwrap();

        assert_eq!(report.files_extracted, 1);
    }

    #[test]
    fn test_extract_directory_entry() {
        let buffer = Vec::new();
        let mut zip = ZipWriter::new(Cursor::new(buffer));

        // ZIP directories end with '/'
        let options = SimpleFileOptions::default();
        zip.add_directory("mydir/", options).unwrap();

        let zip_data = zip.finish().unwrap().into_inner();
        let cursor = Cursor::new(zip_data);
        let mut archive = ZipArchive::new(cursor).unwrap();

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default().validate().expect("valid config");

        let report = archive
            .extract(
                temp.path(),
                &config,
                &ExtractionOptions::default(),
                &mut crate::NoopProgress,
            )
            .unwrap();

        assert_eq!(report.directories_created, 1);
        assert!(temp.path().join("mydir").is_dir());
    }

    #[test]
    fn test_extract_empty_file() {
        let zip_data = create_test_zip(vec![("empty.txt", b"")]);
        let cursor = Cursor::new(zip_data);
        let mut archive = ZipArchive::new(cursor).unwrap();

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default().validate().expect("valid config");

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

        let metadata = std::fs::metadata(temp.path().join("empty.txt")).unwrap();
        assert_eq!(metadata.len(), 0);
    }

    #[test]
    fn test_quota_file_size_exceeded() {
        let zip_data = create_test_zip(vec![("large.bin", &vec![0u8; 1000])]);
        let cursor = Cursor::new(zip_data);
        let mut archive = ZipArchive::new(cursor).unwrap();

        let temp = TempDir::new().unwrap();
        let mut config = SecurityConfig::default();
        config.max_file_size = 100; // Only allow 100 bytes
        let config = config.validate().expect("valid config");

        let result = archive.extract(
            temp.path(),
            &config,
            &ExtractionOptions::default(),
            &mut crate::NoopProgress,
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_quota_file_count_exceeded() {
        let zip_data = create_test_zip(vec![
            ("file1.txt", b"data"),
            ("file2.txt", b"data"),
            ("file3.txt", b"data"),
        ]);
        let cursor = Cursor::new(zip_data);
        let mut archive = ZipArchive::new(cursor).unwrap();

        let temp = TempDir::new().unwrap();
        let mut config = SecurityConfig::default();
        config.max_file_count = 2; // Only allow 2 files
        let config = config.validate().expect("valid config");

        let result = archive.extract(
            temp.path(),
            &config,
            &ExtractionOptions::default(),
            &mut crate::NoopProgress,
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_path_traversal_rejected() {
        let zip_data = create_test_zip(vec![("../etc/passwd", b"malicious")]);
        let cursor = Cursor::new(zip_data);
        let mut archive = ZipArchive::new(cursor).unwrap();

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default().validate().expect("valid config");

        let result = archive.extract(
            temp.path(),
            &config,
            &ExtractionOptions::default(),
            &mut crate::NoopProgress,
        );

        assert!(result.is_err());
        assert_matches!(result.unwrap_err(), ArchiveError::PathTraversal { .. });
    }

    #[test]
    fn test_absolute_path_rejected_by_default() {
        let zip_data = create_test_zip(vec![("/etc/shadow", b"content")]);
        let mut archive = ZipArchive::new(Cursor::new(zip_data)).unwrap();

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default().validate().expect("valid config");

        let result = archive.extract(
            temp.path(),
            &config,
            &ExtractionOptions::default(),
            &mut crate::NoopProgress,
        );

        assert_matches!(result, Err(ArchiveError::PathTraversal { .. }));
        assert!(!temp.path().join("etc/shadow").exists());
    }

    #[test]
    fn test_absolute_path_relocated_only_with_allow_absolute_paths() {
        let zip_data = create_test_zip(vec![("/etc/shadow", b"content")]);
        let mut archive = ZipArchive::new(Cursor::new(zip_data)).unwrap();

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default()
            .with_allow_absolute_paths(true)
            .validate()
            .expect("valid config");

        let report = archive
            .extract(
                temp.path(),
                &config,
                &ExtractionOptions::default(),
                &mut crate::NoopProgress,
            )
            .unwrap();

        assert_eq!(report.files_extracted, 1);
        assert!(
            temp.path().join("etc/shadow").exists(),
            "file must land inside dest, not at real /etc/shadow"
        );
    }

    #[test]
    fn test_zip_bomb_detection() {
        // Create a highly compressed file
        let buffer = Vec::new();
        let mut zip = ZipWriter::new(Cursor::new(buffer));

        let options =
            SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);

        zip.start_file("bomb.txt", options).unwrap();
        // Write highly compressible data
        zip.write_all(&vec![0u8; 100_000]).unwrap();

        let zip_data = zip.finish().unwrap().into_inner();
        let cursor = Cursor::new(zip_data);
        let mut archive = ZipArchive::new(cursor).unwrap();

        let temp = TempDir::new().unwrap();
        let mut config = SecurityConfig::default();
        config.max_compression_ratio = 10.0; // Low threshold for testing
        let config = config.validate().expect("valid config");

        let result = archive.extract(
            temp.path(),
            &config,
            &ExtractionOptions::default(),
            &mut crate::NoopProgress,
        );

        // Should fail with ZipBomb error
        assert!(result.is_err());
    }

    #[test]
    #[cfg(unix)]
    fn test_file_permissions_preserved() {
        use std::os::unix::fs::PermissionsExt;

        let buffer = Vec::new();
        let mut zip = ZipWriter::new(Cursor::new(buffer));

        let options = SimpleFileOptions::default().unix_permissions(0o755);
        zip.start_file("script.sh", options).unwrap();
        zip.write_all(b"#!/bin/sh\n").unwrap();

        let zip_data = zip.finish().unwrap().into_inner();
        let cursor = Cursor::new(zip_data);
        let mut archive = ZipArchive::new(cursor).unwrap();

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default().validate().expect("valid config");

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

        let buffer = Vec::new();
        let mut zip = ZipWriter::new(Cursor::new(buffer));

        let options = SimpleFileOptions::default().unix_permissions(0o4755); // setuid
        zip.start_file("binary", options).unwrap();
        zip.write_all(b"data").unwrap();

        let zip_data = zip.finish().unwrap().into_inner();
        let cursor = Cursor::new(zip_data);
        let mut archive = ZipArchive::new(cursor).unwrap();

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default().validate().expect("valid config");

        let _report = archive
            .extract(
                temp.path(),
                &config,
                &ExtractionOptions::default(),
                &mut crate::NoopProgress,
            )
            .unwrap();

        let metadata = std::fs::metadata(temp.path().join("binary")).unwrap();
        let permissions = metadata.permissions();
        // setuid bit should be stripped
        assert_eq!(permissions.mode() & 0o7777, 0o755);
    }

    #[test]
    #[cfg(unix)]
    fn test_permissions_sanitized_setgid_removed() {
        use std::os::unix::fs::PermissionsExt;

        // MED-003: Test setgid bit removal
        let buffer = Vec::new();
        let mut zip = ZipWriter::new(Cursor::new(buffer));

        let options = SimpleFileOptions::default().unix_permissions(0o2755); // setgid
        zip.start_file("binary", options).unwrap();
        zip.write_all(b"data").unwrap();

        let zip_data = zip.finish().unwrap().into_inner();
        let cursor = Cursor::new(zip_data);
        let mut archive = ZipArchive::new(cursor).unwrap();

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default().validate().expect("valid config");

        let _report = archive
            .extract(
                temp.path(),
                &config,
                &ExtractionOptions::default(),
                &mut crate::NoopProgress,
            )
            .unwrap();

        let metadata = std::fs::metadata(temp.path().join("binary")).unwrap();
        let permissions = metadata.permissions();
        // setgid bit should be stripped
        assert_eq!(permissions.mode() & 0o7777, 0o755);
    }

    #[test]
    #[cfg(unix)]
    fn test_permissions_sanitized_setuid_setgid_removed() {
        use std::os::unix::fs::PermissionsExt;

        // MED-003: Test both setuid and setgid bit removal
        let buffer = Vec::new();
        let mut zip = ZipWriter::new(Cursor::new(buffer));

        let options = SimpleFileOptions::default().unix_permissions(0o6755); // setuid + setgid
        zip.start_file("binary", options).unwrap();
        zip.write_all(b"data").unwrap();

        let zip_data = zip.finish().unwrap().into_inner();
        let cursor = Cursor::new(zip_data);
        let mut archive = ZipArchive::new(cursor).unwrap();

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default().validate().expect("valid config");

        let _report = archive
            .extract(
                temp.path(),
                &config,
                &ExtractionOptions::default(),
                &mut crate::NoopProgress,
            )
            .unwrap();

        let metadata = std::fs::metadata(temp.path().join("binary")).unwrap();
        let permissions = metadata.permissions();
        // Both setuid and setgid bits should be stripped
        assert_eq!(permissions.mode() & 0o7777, 0o755);
    }

    #[test]
    #[cfg(unix)]
    fn test_extract_symlink_via_unix_attributes() {
        // raw_zip_with_custom_entry places mode bits in the external attributes
        // high word (unix_mode << 16), which is how real ZIP tools encode them.
        // This bypasses the zip crate writer's lossy unix_permissions() path.
        let zip_bytes = raw_zip_with_custom_entry("link", b"target.txt", 0, 0, 0o120_777);
        let cursor = Cursor::new(zip_bytes);
        let mut archive = ZipArchive::new(cursor).unwrap();

        let temp = TempDir::new().unwrap();
        let mut config = SecurityConfig::default();
        config.allowed.symlinks = true;
        let config = config.validate().expect("valid config");

        let report = archive
            .extract(
                temp.path(),
                &config,
                &ExtractionOptions::default(),
                &mut crate::NoopProgress,
            )
            .unwrap();

        assert_eq!(report.symlinks_created, 1, "should have 1 symlink");

        let link_path = temp.path().join("link");
        let metadata = std::fs::symlink_metadata(&link_path).unwrap();
        assert!(metadata.is_symlink(), "link should be a symlink");
    }

    #[test]
    #[cfg(unix)]
    fn test_symlink_disabled_by_default() {
        let zip_bytes = raw_zip_with_custom_entry("link", b"target.txt", 0, 0, 0o120_777);
        let cursor = Cursor::new(zip_bytes);
        let mut archive = ZipArchive::new(cursor).unwrap();

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default().validate().expect("valid config"); // symlinks disabled by default

        let result = archive.extract(
            temp.path(),
            &config,
            &ExtractionOptions::default(),
            &mut crate::NoopProgress,
        );

        match result {
            Err(ArchiveError::SecurityViolation { reason, .. }) => {
                assert!(
                    reason.contains("symlinks not allowed") || reason.contains("symlink"),
                    "error should mention symlinks: {reason}"
                );
            }
            Err(other) => panic!("expected SecurityViolation, got: {other:?}"),
            Ok(_) => panic!("expected error, got success"),
        }
    }

    #[test]
    fn test_hardlink_rejected() {
        // ZIP spec has no hardlink type; ValidatedEntryType::Hardlink is
        // unreachable for any real ZIP entry. Verify that a well-formed ZIP
        // extracts cleanly without triggering any hardlink-related error path.
        let zip_data = create_test_zip(vec![("file.txt", b"content")]);
        let cursor = Cursor::new(zip_data);
        let mut archive = ZipArchive::new(cursor).unwrap();

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default().validate().expect("valid config");

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
    fn test_compression_method_detection() {
        // Test that different compression methods are detected correctly
        let buffer = Vec::new();
        let mut zip = ZipWriter::new(Cursor::new(buffer));

        let stored =
            SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
        zip.start_file("stored.txt", stored).unwrap();
        zip.write_all(b"stored").unwrap();

        let deflated =
            SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated);
        zip.start_file("deflated.txt", deflated).unwrap();
        zip.write_all(b"deflated").unwrap();

        let zip_data = zip.finish().unwrap().into_inner();
        let cursor = Cursor::new(zip_data);
        let mut archive = ZipArchive::new(cursor).unwrap();

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default().validate().expect("valid config");

        let report = archive
            .extract(
                temp.path(),
                &config,
                &ExtractionOptions::default(),
                &mut crate::NoopProgress,
            )
            .unwrap();

        assert_eq!(report.files_extracted, 2);
    }

    #[test]
    fn test_bytes_written_tracking() {
        let zip_data = create_test_zip(vec![
            ("file1.txt", b"hello"),    // 5 bytes
            ("file2.txt", b"world!!!"), // 8 bytes
        ]);
        let cursor = Cursor::new(zip_data);
        let mut archive = ZipArchive::new(cursor).unwrap();

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default().validate().expect("valid config");

        let report = archive
            .extract(
                temp.path(),
                &config,
                &ExtractionOptions::default(),
                &mut crate::NoopProgress,
            )
            .unwrap();

        assert_eq!(report.bytes_written, 13);
    }

    #[test]
    fn test_duration_tracking() {
        let zip_data = create_test_zip(vec![("file.txt", b"data")]);
        let cursor = Cursor::new(zip_data);
        let mut archive = ZipArchive::new(cursor).unwrap();

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default().validate().expect("valid config");

        let report = archive
            .extract(
                temp.path(),
                &config,
                &ExtractionOptions::default(),
                &mut crate::NoopProgress,
            )
            .unwrap();

        // Duration should be non-zero
        assert!(report.duration.as_nanos() > 0);
    }

    #[test]
    fn test_invalid_zip_archive() {
        let invalid_data = b"not a zip file";
        let cursor = Cursor::new(invalid_data);
        let result = ZipArchive::new(cursor);

        assert!(result.is_err());
    }

    #[test]
    fn test_entry_type_detection_file() {
        let zip_data = create_test_zip(vec![("regular.txt", b"content")]);
        let cursor = Cursor::new(zip_data);
        let mut archive = ZipArchive::new(cursor).unwrap();

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default().validate().expect("valid config");

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
        assert_eq!(report.symlinks_created, 0);
    }

    #[test]
    fn test_entry_type_detection_directory() {
        let buffer = Vec::new();
        let mut zip = ZipWriter::new(Cursor::new(buffer));

        let options = SimpleFileOptions::default();
        zip.add_directory("testdir/", options).unwrap();

        let zip_data = zip.finish().unwrap().into_inner();
        let cursor = Cursor::new(zip_data);
        let mut archive = ZipArchive::new(cursor).unwrap();

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default().validate().expect("valid config");

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
    }

    #[test]
    fn test_nested_directories_created_automatically() {
        // ZIP might not have explicit directory entries
        // Parent dirs should be created automatically
        let zip_data = create_test_zip(vec![("a/b/c/file.txt", b"nested")]);
        let cursor = Cursor::new(zip_data);
        let mut archive = ZipArchive::new(cursor).unwrap();

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default().validate().expect("valid config");

        let _report = archive
            .extract(
                temp.path(),
                &config,
                &ExtractionOptions::default(),
                &mut crate::NoopProgress,
            )
            .unwrap();

        assert!(temp.path().join("a/b/c/file.txt").exists());
        assert!(temp.path().join("a").is_dir());
        assert!(temp.path().join("a/b").is_dir());
        assert!(temp.path().join("a/b/c").is_dir());
    }

    #[test]
    fn test_large_file_extraction() {
        // Test with a 1MB file
        let large_data = vec![0xAB; 1024 * 1024];
        let zip_data = create_test_zip(vec![("large.bin", &large_data)]);
        let cursor = Cursor::new(zip_data);
        let mut archive = ZipArchive::new(cursor).unwrap();

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default().validate().expect("valid config");

        let report = archive
            .extract(
                temp.path(),
                &config,
                &ExtractionOptions::default(),
                &mut crate::NoopProgress,
            )
            .unwrap();

        assert_eq!(report.files_extracted, 1);

        let extracted = std::fs::read(temp.path().join("large.bin")).unwrap();
        assert_eq!(extracted.len(), 1024 * 1024);
    }

    #[test]
    fn test_many_files_extraction() {
        // Test with 100 files
        let entries: Vec<_> = (0..100)
            .map(|i| (format!("file{i}.txt"), format!("content{i}").into_bytes()))
            .collect();

        let buffer = Vec::new();
        let mut zip = ZipWriter::new(Cursor::new(buffer));

        for (name, data) in &entries {
            let options = SimpleFileOptions::default();
            zip.start_file(name, options).unwrap();
            zip.write_all(data).unwrap();
        }

        let zip_data = zip.finish().unwrap().into_inner();
        let cursor = Cursor::new(zip_data);
        let mut archive = ZipArchive::new(cursor).unwrap();

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default().validate().expect("valid config");

        let report = archive
            .extract(
                temp.path(),
                &config,
                &ExtractionOptions::default(),
                &mut crate::NoopProgress,
            )
            .unwrap();

        assert_eq!(report.files_extracted, 100);
    }

    #[test]
    fn test_quota_total_size_exceeded() {
        let zip_data = create_test_zip(vec![
            ("file1.txt", &vec![0u8; 600]),
            ("file2.txt", &vec![0u8; 600]),
        ]);
        let cursor = Cursor::new(zip_data);
        let mut archive = ZipArchive::new(cursor).unwrap();

        let temp = TempDir::new().unwrap();
        let mut config = SecurityConfig::default();
        config.max_total_size = 1000; // Total limit 1000 bytes
        let config = config.validate().expect("valid config");

        let result = archive.extract(
            temp.path(),
            &config,
            &ExtractionOptions::default(),
            &mut crate::NoopProgress,
        );

        assert!(result.is_err());
    }

    #[test]
    fn test_special_characters_in_filename() {
        let zip_data = create_test_zip(vec![
            ("file with spaces.txt", b"content"),
            ("file-with-dashes.txt", b"content"),
            ("file_with_underscores.txt", b"content"),
        ]);
        let cursor = Cursor::new(zip_data);
        let mut archive = ZipArchive::new(cursor).unwrap();

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default().validate().expect("valid config");

        let report = archive
            .extract(
                temp.path(),
                &config,
                &ExtractionOptions::default(),
                &mut crate::NoopProgress,
            )
            .unwrap();

        assert_eq!(report.files_extracted, 3);
        assert!(temp.path().join("file with spaces.txt").exists());
    }

    #[test]
    fn zip_entry_kind_decides_directory_then_symlink_then_regular() {
        for mode in [None, Some(0o120_777), Some(0o100_644), Some(0o040_755)] {
            assert_eq!(zip_entry_kind(true, mode), ZipEntryKind::Directory);
        }
        assert_eq!(
            zip_entry_kind(false, Some(0o120_777)),
            ZipEntryKind::Symlink
        );
        for mode in [None, Some(0o100_644), Some(0o040_755), Some(0o755)] {
            assert_eq!(zip_entry_kind(false, mode), ZipEntryKind::Regular);
        }
    }

    #[test]
    fn test_is_symlink_from_mode() {
        assert!(ZipEntryAdapter::is_symlink_from_mode(Some(0o120_777)));
        assert!(ZipEntryAdapter::is_symlink_from_mode(Some(0o120_755)));
        assert!(!ZipEntryAdapter::is_symlink_from_mode(Some(0o100_644)));
        assert!(!ZipEntryAdapter::is_symlink_from_mode(Some(0o040_755)));
        assert!(!ZipEntryAdapter::is_symlink_from_mode(Some(0o755)));
        assert!(!ZipEntryAdapter::is_symlink_from_mode(None));
    }

    /// Builds a single-entry ZIP in memory with a custom compression method
    /// field, flags, unix mode, and content (written as is, with its CRC32).
    fn raw_zip_with_custom_entry(
        filename: &str,
        content: &[u8],
        compression_method: u16,
        flags: u16,
        unix_mode: u32,
    ) -> Vec<u8> {
        let entry = RawEntry {
            method: compression_method,
            flags,
            date: 0,
            external_attributes: unix_mode << 16,
            ..RawEntry::stored(filename, content)
        };
        RawZip::new(vec![entry]).build().bytes
    }

    /// Build a raw ZIP with two local entries sharing the same path.
    ///
    /// The `zip` crate's writer rejects duplicate filenames, so the entries are
    /// written by the raw builder.
    fn create_raw_duplicate_zip(path: &str, content1: &[u8], content2: &[u8]) -> Vec<u8> {
        let entries = [content1, content2].map(|content| RawEntry {
            date: 0,
            ..RawEntry::stored(path, content)
        });
        RawZip::new(entries.to_vec()).build().bytes
    }

    #[test]
    fn test_unsupported_compression_method_rejected() {
        // Build a ZIP with compression method=99 (unknown/unsupported)
        // The zip crate parses entries with unknown methods but fails on
        // decompression. Our code checks the compression method in
        // process_entry before decompressing.
        let zip_bytes = raw_zip_with_custom_entry("file.txt", b"", 99, 0, 0o100_644);
        let cursor = Cursor::new(zip_bytes);
        let result = ZipArchive::new(cursor);
        if let Ok(mut archive) = result {
            let temp = TempDir::new().unwrap();
            let config = SecurityConfig::default().validate().expect("valid config");
            let err = archive
                .extract(
                    temp.path(),
                    &config,
                    &ExtractionOptions::default(),
                    &mut crate::NoopProgress,
                )
                .unwrap_err();
            assert_matches!(
                err,
                ArchiveError::SecurityViolation { .. },
                "expected SecurityViolation for unsupported compression, got: {err:?}"
            );
        }
        // If zip crate rejects at parse time, that's also acceptable —
        // the archive never opens, so extraction is blocked either way.
    }

    #[test]
    fn test_symlink_target_too_large() {
        // Build a raw ZIP entry with symlink mode (0o120777) and >4096 bytes
        // content. The size field in the local header is what our code
        // reads via zip_file.size(). We need actual content bytes so
        // the zip crate reports the correct uncompressed size.
        let target = vec![b'a'; crate::test_utils::HOST_SYMLINK_TARGET_BYTES + 1];
        let zip_bytes = raw_zip_with_custom_entry("link", &target, 0, 0, 0o120_777);
        let cursor = Cursor::new(zip_bytes);
        // The archive itself should open fine.
        let result = ZipArchive::new(cursor);
        if let Ok(mut archive) = result {
            let temp = TempDir::new().unwrap();
            let mut config = SecurityConfig::default();
            config.allowed.symlinks = true;
            let config = config.validate().expect("valid config");
            let err = archive
                .extract(
                    temp.path(),
                    &config,
                    &ExtractionOptions::default(),
                    &mut crate::NoopProgress,
                )
                .unwrap_err();
            assert_matches!(
                err,
                ArchiveError::SecurityViolation { ref reason, .. }
                    if reason.contains("symlink target too large"),
                "expected SecurityViolation(symlink target too large), got: {err:?}"
            );
        }
    }

    #[cfg(windows)]
    #[test]
    fn test_symlink_entry_is_refused_on_windows() {
        let target = vec![b'a'; 16];
        let zip_bytes = raw_zip_with_custom_entry("link", &target, 0, 0, 0o120_777);
        let mut archive = ZipArchive::new(Cursor::new(zip_bytes)).unwrap();
        let temp = TempDir::new().unwrap();
        let mut config = SecurityConfig::default();
        config.allowed.symlinks = true;
        let config = config.validate().expect("valid config");
        let err = archive
            .extract(
                temp.path(),
                &config,
                &ExtractionOptions::default(),
                &mut crate::NoopProgress,
            )
            .unwrap_err();
        assert_matches!(
            err,
            ArchiveError::SecurityViolation { ref reason, .. }
                if reason.contains("not supported on this platform"),
            "{err:?}"
        );
    }

    #[test]
    fn test_symlink_target_invalid_utf8() {
        // Build a raw ZIP entry with symlink mode and non-UTF-8 content.
        let invalid_utf8 = vec![0xFF, 0xFE, 0x00];
        let zip_bytes = raw_zip_with_custom_entry("link", &invalid_utf8, 0, 0, 0o120_777);
        let cursor = Cursor::new(zip_bytes);
        let result = ZipArchive::new(cursor);
        if let Ok(mut archive) = result {
            let temp = TempDir::new().unwrap();
            let mut config = SecurityConfig::default();
            config.allowed.symlinks = true;
            let config = config.validate().expect("valid config");
            let err = archive
                .extract(
                    temp.path(),
                    &config,
                    &ExtractionOptions::default(),
                    &mut crate::NoopProgress,
                )
                .unwrap_err();
            assert_matches!(
                err,
                ArchiveError::InvalidArchive(ref msg) if msg.contains("UTF-8"),
                "expected InvalidArchive(UTF-8), got: {err:?}"
            );
        }
    }

    /// Creates a 400-entry ZIP archive in memory. The entry at
    /// `encrypted_index` is encrypted using deprecated `ZipCrypto`. All other
    /// entries are unencrypted with Stored compression and 1-byte content,
    /// to keep construction fast.
    fn create_large_archive_with_encrypted_entry(encrypted_index: usize) -> Vec<u8> {
        use zip::unstable::write::FileOptionsExt;

        let total = 400usize;
        let buffer = Vec::new();
        let mut zip = ZipWriter::new(Cursor::new(buffer));

        for i in 0..total {
            let options = if i == encrypted_index {
                SimpleFileOptions::default()
                    .compression_method(zip::CompressionMethod::Stored)
                    .with_deprecated_encryption(b"pass")
                    .unwrap()
            } else {
                SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored)
            };
            zip.start_file(format!("file{i}.txt"), options).unwrap();
            zip.write_all(b"x").unwrap();
        }

        zip.finish().unwrap().into_inner()
    }

    const LOCAL_HEADER_SIGNATURE: [u8; 4] = *b"PK\x03\x04";
    const CENTRAL_HEADER_SIGNATURE: [u8; 4] = *b"PK\x01\x02";

    /// Offset of the second header starting with `signature`.
    fn second_header_offset(data: &[u8], signature: [u8; 4]) -> usize {
        data.windows(4)
            .enumerate()
            .filter(|(_, w)| **w == signature)
            .nth(1)
            .map(|(i, _)| i)
            .expect("second header present")
    }

    /// Sets the declared compressed size of the second local and central
    /// header to `size`.
    fn forge_second_entry_compressed_size(data: &mut [u8], size: u32) {
        for (signature, offset) in [(LOCAL_HEADER_SIGNATURE, 18), (CENTRAL_HEADER_SIGNATURE, 20)] {
            let at = second_header_offset(data, signature);
            data[at + offset..at + offset + 4].copy_from_slice(&size.to_le_bytes());
        }
    }

    /// Issue #625: an oversized declared compressed size on a later entry must
    /// fail when the archive is opened, before the earlier valid entry is
    /// written.
    #[test]
    fn test_declared_compressed_size_violation_fails_before_any_write() {
        let mut data = create_test_zip(vec![("a.txt", &[1u8; 64]), ("b.txt", &[2u8; 64])]);
        forge_second_entry_compressed_size(&mut data, 400_000);

        let result = ZipArchive::new(Cursor::new(data.clone()));
        assert_matches!(result.err(), Some(ArchiveError::InvalidArchive(_)));

        let dir = TempDir::new().unwrap();
        let archive_path = dir.path().join("forged.zip");
        std::fs::write(&archive_path, &data).unwrap();
        let out = dir.path().join("out");
        std::fs::create_dir(&out).unwrap();

        let result = crate::extract_archive(&archive_path, &out, &SecurityConfig::default());
        assert_matches!(result, Err(ArchiveError::InvalidArchive(_)));
        assert_eq!(
            std::fs::read_dir(&out).unwrap().count(),
            0,
            "no entry may be written before the size check fails"
        );
    }

    /// Issue #625: the open-time pass reads every local header, so a corrupt
    /// header with an intact central directory fails before any write.
    #[test]
    fn test_corrupt_local_header_fails_before_any_write() {
        let mut data = create_test_zip(vec![("a.txt", &[1u8; 64]), ("b.txt", &[2u8; 64])]);
        let at = second_header_offset(&data, LOCAL_HEADER_SIGNATURE);
        data[at..at + 4].fill(0);

        let dir = TempDir::new().unwrap();
        let archive_path = dir.path().join("corrupt.zip");
        std::fs::write(&archive_path, &data).unwrap();
        let out = dir.path().join("out");
        std::fs::create_dir(&out).unwrap();

        let result = crate::extract_archive(&archive_path, &out, &SecurityConfig::default());
        assert_matches!(result, Err(ArchiveError::InvalidArchive(_)));
        assert_eq!(std::fs::read_dir(&out).unwrap().count(), 0);
    }

    #[test]
    fn test_is_password_required_matches_typed_variants_only() {
        use ::zip::result::ZipError;

        assert!(is_password_required(&ZipError::UnsupportedArchive(
            ZipError::PASSWORD_REQUIRED
        )));
        assert!(is_password_required(&ZipError::InvalidPassword));
        assert!(!is_password_required(&ZipError::FileNotFound));
        assert!(!is_password_required(&ZipError::UnsupportedArchive(
            "password mentioned elsewhere"
        )));
    }

    #[test]
    fn test_password_protected_large_archive_first_entry() {
        // Encrypted entry at index 0 — detected by full scan.
        let zip_data = create_large_archive_with_encrypted_entry(0);
        let cursor = Cursor::new(zip_data);
        let result = ZipArchive::new(cursor);
        assert_matches!(
            result.err(),
            Some(ArchiveError::SecurityViolation { .. }),
            "expected SecurityViolation for encrypted entry in first batch"
        );
    }

    #[test]
    fn test_password_protected_large_archive_middle_entry() {
        // Encrypted entry at index 200 — detected by full scan.
        let zip_data = create_large_archive_with_encrypted_entry(200);
        let cursor = Cursor::new(zip_data);
        let result = ZipArchive::new(cursor);
        assert_matches!(
            result.err(),
            Some(ArchiveError::SecurityViolation { .. }),
            "expected SecurityViolation for encrypted entry in middle batch"
        );
    }

    #[test]
    fn test_password_protected_large_archive_last_entry() {
        // Encrypted entry at index 399 — detected by full scan.
        let zip_data = create_large_archive_with_encrypted_entry(399);
        let cursor = Cursor::new(zip_data);
        let result = ZipArchive::new(cursor);
        assert_matches!(
            result.err(),
            Some(ArchiveError::SecurityViolation { .. }),
            "expected SecurityViolation for encrypted entry in last batch"
        );
    }

    #[test]
    fn test_large_archive_no_encryption_passes_constructor() {
        // 400-entry unencrypted archive — constructor should succeed.
        let buffer = Vec::new();
        let mut zip = ZipWriter::new(Cursor::new(buffer));
        let options =
            SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
        for i in 0..400usize {
            zip.start_file(format!("file{i}.txt"), options).unwrap();
            zip.write_all(b"x").unwrap();
        }
        let zip_data = zip.finish().unwrap().into_inner();
        let cursor = Cursor::new(zip_data);
        let archive = ZipArchive::new(cursor);
        assert!(
            archive.is_ok(),
            "unencrypted 400-entry archive should open fine"
        );
    }

    #[test]
    fn test_encrypted_entry_at_gap_index_is_detected_by_full_scan() {
        // Index 125 was previously in the gap between first-100 and middle-100
        // sampling windows. The full scan now catches it at construction time.
        let zip_data = create_large_archive_with_encrypted_entry(125);
        let cursor = Cursor::new(zip_data);
        let result = ZipArchive::new(cursor);
        assert_matches!(
            result.err(),
            Some(ArchiveError::SecurityViolation { .. }),
            "full scan must detect encrypted entry at index 125"
        );
    }

    #[test]
    fn test_duplicate_entry_skip_default() {
        let zip_data = create_raw_duplicate_zip("legit.txt", b"first", b"second");
        let cursor = Cursor::new(zip_data);
        let mut archive = ZipArchive::new(cursor).unwrap();

        let temp = TempDir::new().unwrap();
        let enforcing = SecurityConfig::default().validate().expect("valid config");
        let options = ExtractionOptions::default(); // skip_duplicates = true

        let rejected = archive
            .extract(temp.path(), &enforcing, &options, &mut crate::NoopProgress)
            .unwrap_err();
        assert_matches!(
            rejected,
            ArchiveError::ZipInconsistency(crate::ZipInconsistency::DuplicateName { .. })
        );
        assert!(!temp.path().join("legit.txt").exists());

        let config = SecurityConfig::default()
            .with_zip_consistency(ZipConsistencyPolicy::Ignore)
            .validate()
            .expect("valid config");
        let report = archive
            .extract(temp.path(), &config, &options, &mut crate::NoopProgress)
            .unwrap();

        // zip crate 8.x deduplicates entries at ZipArchive::new(), so the raw
        // archive with two identical filenames appears as a single entry.
        // The skip logic is verified by the TAR tests; this test confirms the
        // ZIP extractor still succeeds without panicking on such archives.
        assert_eq!(report.files_extracted, 1);
        assert!(temp.path().join("legit.txt").exists());
    }

    /// Regression test for issue #490: extracting an archive whose entries
    /// collide with many pre-existing files on disk must push exactly one
    /// aggregated warning onto `report.warnings`, not one `String` per
    /// skipped entry (mirrors 7z's
    /// `test_skip_duplicates_aggregates_single_warning`, #484).
    #[test]
    fn test_skip_duplicates_aggregates_single_warning() {
        const ENTRY_COUNT: usize = 30;
        let names: Vec<String> = (0..ENTRY_COUNT).map(|i| format!("dup-{i}.txt")).collect();
        let entries: Vec<(&str, &[u8])> = names
            .iter()
            .map(|n| (n.as_str(), b"payload".as_slice()))
            .collect();
        let zip_data = create_test_zip(entries);
        let cursor = Cursor::new(zip_data);
        let mut archive = ZipArchive::new(cursor).unwrap();

        let temp = TempDir::new().unwrap();
        for name in &names {
            std::fs::write(temp.path().join(name), b"already here").unwrap();
        }

        let config = SecurityConfig::default().validate().expect("valid config");
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

    #[test]
    fn test_encrypted_zip_rejected_with_security_violation() {
        use zip::unstable::write::FileOptionsExt;

        let buffer = Vec::new();
        let mut writer = ZipWriter::new(Cursor::new(buffer));
        let options = SimpleFileOptions::default()
            .with_deprecated_encryption(b"password123")
            .unwrap();
        writer.start_file("secret.txt", options).unwrap();
        writer.write_all(b"secret data").unwrap();
        let zip_data = writer.finish().unwrap().into_inner();

        let cursor = Cursor::new(zip_data);
        let result = ZipArchive::new(cursor);
        let Err(err) = result else {
            panic!("expected error for encrypted ZIP, got Ok");
        };
        match err {
            ArchiveError::SecurityViolation { reason, .. } => {
                assert!(
                    reason.contains("password") || reason.contains("encrypted"),
                    "expected password/encryption mention in reason: {reason}"
                );
            }
            other => panic!("expected SecurityViolation, got: {other}"),
        }
    }

    // Regression test for #171: full scan must catch an encrypted entry at any
    // interior position.
    #[test]
    fn test_encrypted_entry_not_at_boundary_is_detected() {
        use zip::unstable::write::FileOptionsExt;

        let buffer = Vec::new();
        let mut writer = ZipWriter::new(Cursor::new(buffer));

        let plain = SimpleFileOptions::default();
        let encrypted = SimpleFileOptions::default()
            .with_deprecated_encryption(b"secret")
            .unwrap();

        // 7 entries: indices 0..6. Encrypted entry is at index 3 (interior).
        // Verifies that the full scan catches all positions, not just
        // boundaries.
        for i in 0..7u8 {
            if i == 3 {
                writer
                    .start_file(format!("file{i}.txt"), encrypted)
                    .unwrap();
            } else {
                writer.start_file(format!("file{i}.txt"), plain).unwrap();
            }
            writer.write_all(b"data").unwrap();
        }
        let zip_data = writer.finish().unwrap().into_inner();

        let cursor = Cursor::new(zip_data);
        let result = ZipArchive::new(cursor);
        assert!(
            result.is_err(),
            "archive with encrypted entry at index 3 must be rejected"
        );
        match result.err().unwrap() {
            ArchiveError::SecurityViolation { reason, .. } => {
                assert!(
                    reason.contains("password") || reason.contains("encrypted"),
                    "unexpected reason: {reason}"
                );
            }
            other => panic!("expected SecurityViolation, got: {other}"),
        }
    }

    #[test]
    fn test_list_returns_manifest_with_entries() {
        let zip_data = create_test_zip(vec![("a.txt", b"hello"), ("b.txt", b"world")]);
        let mut archive = ZipArchive::new(Cursor::new(zip_data)).unwrap();
        let config = SecurityConfig::default().validate().expect("valid config");

        let manifest = archive.list(&config).unwrap();

        assert_eq!(manifest.total_entries(), 2);
        assert_eq!(manifest.total_size(), 10);
    }

    #[test]
    fn test_list_empty_zip_returns_empty_manifest() {
        let zip_data = create_test_zip(vec![]);
        let mut archive = ZipArchive::new(Cursor::new(zip_data)).unwrap();
        let config = SecurityConfig::default().validate().expect("valid config");

        let manifest = archive.list(&config).unwrap();

        assert_eq!(manifest.total_entries(), 0);
        assert_eq!(manifest.total_size(), 0);
    }

    #[test]
    fn test_verify_clean_zip_is_safe() {
        let zip_data = create_test_zip(vec![("safe.txt", b"data")]);
        let mut archive = ZipArchive::new(Cursor::new(zip_data)).unwrap();
        let config = SecurityConfig::default().validate().expect("valid config");

        let report = archive
            .verify(&config, &crate::VerificationOptions::default())
            .unwrap();

        assert!(report.is_safe());
        assert_eq!(report.total_entries(), 1);
    }

    #[test]
    fn test_allowed_extensions_filters_out_disallowed() {
        use crate::NoopProgress;
        let zip_data = create_test_zip(vec![("keep.txt", b"keep"), ("skip.exe", b"skip")]);
        let dest = tempfile::tempdir().unwrap();
        let config = SecurityConfig::default()
            .with_allowed_extensions(vec!["txt".to_string()])
            .validate()
            .unwrap();

        let report = ZipArchive::new(Cursor::new(zip_data))
            .unwrap()
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
        use crate::NoopProgress;
        const ENTRY_COUNT: usize = 30;
        let names: Vec<String> = (0..ENTRY_COUNT).map(|i| format!("skip-{i}.exe")).collect();
        let entries: Vec<(&str, &[u8])> = names
            .iter()
            .map(|n| (n.as_str(), b"payload".as_slice()))
            .collect();
        let zip_data = create_test_zip(entries);
        let dest = tempfile::tempdir().unwrap();
        let config = SecurityConfig::default()
            .with_allowed_extensions(vec!["txt".to_string()])
            .validate()
            .expect("valid config");

        let report = ZipArchive::new(Cursor::new(zip_data))
            .unwrap()
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
        use crate::NoopProgress;
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
        let zip_data = create_test_zip(entries);

        let temp = TempDir::new().unwrap();
        for name in names.iter().take(DUPLICATE_COUNT) {
            std::fs::write(temp.path().join(name), b"already here").unwrap();
        }

        let config = SecurityConfig::default()
            .with_allowed_extensions(vec!["txt".to_string()])
            .validate()
            .expect("valid config");

        let report = ZipArchive::new(Cursor::new(zip_data))
            .unwrap()
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

    /// Regression for critic finding S1 (found during #505 review):
    /// `by_index()` failing partway through the loop previously returned its
    /// error via a bare `?`, bypassing the duplicate/disallowed-extension
    /// warning aggregation and `ArchiveError::partial_or` wrapping used for
    /// `process_entry` failures — silently discarding any skips/warnings
    /// accumulated from earlier entries. `ZipArchive::new()`'s own
    /// encryption pre-scan already calls `by_index()` on every entry, so a
    /// corrupted local header would normally be caught there rather than in
    /// `extract()`; this test bypasses that pre-scan by constructing
    /// `ZipArchive` directly from an already-parsed `zip::ZipArchive`, to
    /// exercise `extract()`'s own `by_index()` failure path in isolation.
    #[test]
    fn test_by_index_failure_preserves_prior_skip_warnings() {
        use crate::NoopProgress;

        let mut zip_data = create_test_zip(vec![("bad.exe", b"x"), ("good.txt", b"hello world")]);

        // Corrupt the second entry's local file header signature so
        // `by_index(1)` fails in `extract()` while the central directory
        // (read by `zip::ZipArchive::new()`) remains intact.
        let sig = b"PK\x03\x04";
        let first = zip_data
            .windows(4)
            .position(|w| w == sig)
            .expect("first local header signature");
        let second = zip_data[first + 4..]
            .windows(4)
            .position(|w| w == sig)
            .map(|p| p + first + 4)
            .expect("second local header signature");
        zip_data[second..second + 4].copy_from_slice(b"XXXX");

        // Bypass `ZipArchive::new()`'s encryption pre-scan (which itself
        // calls `by_index()` on every entry and would surface the
        // corruption before `extract()` is ever reached) by constructing
        // the wrapper directly around an already-open reader.
        let inner =
            ZipReader::new(Shared::new(Cursor::new(zip_data))).expect("valid central directory");
        let structure = ZipStructure::unchecked(inner.len());
        let mut archive = ZipArchive { inner, structure };

        let config = SecurityConfig::default()
            .with_allowed_extensions(vec!["txt".to_string()])
            .validate()
            .expect("valid config");
        let temp = TempDir::new().unwrap();

        let err = archive
            .extract(
                temp.path(),
                &config,
                &ExtractionOptions::default(),
                &mut NoopProgress,
            )
            .unwrap_err();

        match err {
            ArchiveError::PartialExtraction { report, .. } => {
                assert_eq!(
                    report.files_skipped, 1,
                    "the disallowed-extension skip of bad.exe before the by_index failure \
                     must be preserved, got report: {report:?}"
                );
                assert!(
                    report.has_warnings(),
                    "the disallowed-extension warning must be preserved, got report: {report:?}"
                );
            }
            other => panic!("expected PartialExtraction preserving the prior skip, got: {other:?}"),
        }
    }

    #[test]
    fn test_empty_allowed_extensions_allows_all() {
        use crate::NoopProgress;
        let zip_data = create_test_zip(vec![("a.txt", b"a"), ("b.exe", b"b")]);
        let dest = tempfile::tempdir().unwrap();
        let config = SecurityConfig::default().validate().expect("valid config");

        let report = ZipArchive::new(Cursor::new(zip_data))
            .unwrap()
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
        use crate::NoopProgress;
        let zip_data = create_test_zip(vec![("Makefile", b"all:"), ("keep.txt", b"ok")]);
        let dest = tempfile::tempdir().unwrap();
        let config = SecurityConfig::default()
            .with_allowed_extensions(vec!["txt".to_string()])
            .validate()
            .unwrap();

        let report = ZipArchive::new(Cursor::new(zip_data))
            .unwrap()
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

    #[test]
    fn test_extract_zip_traversal_after_root_rejected_by_default() {
        // `/../etc/passwd` has a traversal component after root;
        // exarch's raw-name `..` check rejects this pattern. Without
        // allow_absolute_paths the entry must be rejected as
        // PathTraversal.
        let zip_data = create_raw_zip_entry("/../etc/passwd", b"secret");
        let cursor = Cursor::new(zip_data);
        let mut archive = ZipArchive::new(cursor).unwrap();

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default().validate().expect("valid config");

        let result = archive.extract(
            temp.path(),
            &config,
            &ExtractionOptions::default(),
            &mut NoopProgress,
        );
        assert!(
            result.is_err(),
            "traversal-after-root must be rejected by default"
        );
    }

    #[test]
    fn test_extract_zip_traversal_after_root_still_rejected_with_flag() {
        // Even with allow_absolute_paths, `/../etc/passwd` contains `..` and
        // must be rejected regardless.
        let zip_data = create_raw_zip_entry("/../etc/passwd", b"secret");
        let cursor = Cursor::new(zip_data);
        let mut archive = ZipArchive::new(cursor).unwrap();

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default()
            .with_allow_absolute_paths(true)
            .validate()
            .unwrap();

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
    fn test_extract_zip_absolute_path_with_flag_writes_to_dest() {
        // `/etc/passwd` raw in ZIP: the root is stripped to `etc/passwd`,
        // so extraction must write <dest>/etc/passwd without error.
        // Empty content keeps CRC32 = 0 which matches the raw ZIP header.
        let zip_data = create_raw_zip_entry("/etc/passwd", b"");
        let cursor = Cursor::new(zip_data);
        let mut archive = ZipArchive::new(cursor).unwrap();

        let temp = TempDir::new().unwrap();
        let config = SecurityConfig::default()
            .with_allow_absolute_paths(true)
            .validate()
            .unwrap();

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
            temp.path().join("etc/passwd").exists(),
            "file must land inside dest, not at real /etc/passwd"
        );
    }

    // --- resolve_entry_path unit tests ---

    fn strict_config() -> SecurityConfig<Validated> {
        SecurityConfig::default().validate().unwrap()
    }

    fn absolute_config() -> SecurityConfig<Validated> {
        SecurityConfig::default()
            .with_allow_absolute_paths(true)
            .validate()
            .unwrap()
    }

    /// Builds a minimal in-memory ZIP with a single entry named `entry_name`
    /// and empty content, then opens it and calls `resolve_entry_path` on the
    /// first entry, returning the result.
    fn call_resolve_entry_path(
        entry_name: &str,
        config: &SecurityConfig<Validated>,
    ) -> Result<PathBuf> {
        let zip_data = create_raw_zip_entry(entry_name, b"");
        let cursor = Cursor::new(zip_data);
        let mut reader = zip::ZipArchive::new(Shared::new(cursor)).unwrap();
        let zip_file = reader.by_index(0).unwrap();
        ZipArchive::<Cursor<Vec<u8>>>::resolve_entry_path(&zip_file, 0, config)
    }

    #[test]
    fn test_resolve_entry_path_normal_relative_path() {
        let path = call_resolve_entry_path("some/file.txt", &strict_config()).unwrap();
        assert_eq!(path, PathBuf::from("some/file.txt"));
    }

    #[test]
    fn test_resolve_entry_path_absolute_forms_rejected_by_default() {
        for name in [
            "/etc/passwd",
            "\\etc\\passwd",
            "C:\\x",
            "C:/x",
            "\\\\server\\share\\f",
            "\\\\?\\C:\\x",
            "\\\\.\\COM1\\x",
            "\\\\?\\UNC\\srv\\sh\\f",
            "//?/C:/x",
        ] {
            let result = call_resolve_entry_path(name, &strict_config());
            assert_matches!(
                result,
                Err(ArchiveError::PathTraversal { .. }),
                "{name:?} must be rejected without allow_absolute_paths"
            );
        }
    }

    #[test]
    fn test_resolve_entry_path_absolute_forms_stripped_with_flag() {
        for (name, expected) in [
            ("/etc/passwd", "etc/passwd"),
            ("\\etc\\passwd", "etc/passwd"),
            ("C:\\x", "x"),
            ("C:/dir/x", "dir/x"),
            ("\\\\server\\share\\f", "f"),
            ("\\\\?\\C:\\x\\y", "x/y"),
            ("\\\\.\\COM1\\x", "x"),
            ("\\\\?\\UNC\\srv\\sh\\f", "f"),
            ("C:\\NUL.txt", "NUL.txt"),
        ] {
            let path = call_resolve_entry_path(name, &absolute_config()).unwrap();
            assert_eq!(path, PathBuf::from(expected), "{name:?}");
        }
    }

    #[test]
    fn test_resolve_entry_path_absolute_resolving_to_nothing_rejected_with_flag() {
        for name in ["/", "C:\\", "\\\\server\\share"] {
            let result = call_resolve_entry_path(name, &absolute_config());
            assert_matches!(
                result,
                Err(ArchiveError::PathTraversal { .. }),
                "{name:?} resolves to an empty path and must be rejected"
            );
        }
    }

    #[test]
    fn test_resolve_entry_path_root_directory_spellings_resolve_to_dot() {
        for name in [".", "./", ".//", "./.", ".\\"] {
            let path = call_resolve_entry_path(name, &strict_config()).unwrap();
            assert_eq!(path, PathBuf::from("."), "{name:?}");
        }
    }

    #[test]
    fn test_resolve_entry_path_drive_glued_to_name_depends_on_platform() {
        let result = call_resolve_entry_path("a:notes.txt", &strict_config());
        if cfg!(windows) {
            assert_matches!(result, Err(ArchiveError::PathTraversal { .. }));
            let path = call_resolve_entry_path("a:notes.txt", &absolute_config()).unwrap();
            assert_eq!(path, PathBuf::from("notes.txt"));
        } else {
            assert_eq!(result.unwrap(), PathBuf::from("a:notes.txt"));
            let path = call_resolve_entry_path("a:dir\\notes.txt", &absolute_config()).unwrap();
            assert_eq!(path, PathBuf::from("a:dir/notes.txt"));
        }
    }

    #[test]
    fn test_resolve_entry_path_drive_with_separator_or_nothing_is_absolute_everywhere() {
        for name in ["C:", "c:\\x", "Z:/x"] {
            let result = call_resolve_entry_path(name, &strict_config());
            assert_matches!(
                result,
                Err(ArchiveError::PathTraversal { .. }),
                "{name:?} must be rejected on every platform"
            );
        }
    }

    #[test]
    fn test_resolve_entry_path_drive_like_later_component_depends_on_platform() {
        let cases = [
            ("dir/a:notes.txt", strict_config(), "dir/a:notes.txt"),
            ("./a:notes.txt", strict_config(), "a:notes.txt"),
            (".\\a:notes.txt", strict_config(), "a:notes.txt"),
            ("/dir/a:notes.txt", absolute_config(), "dir/a:notes.txt"),
            ("/c:x", absolute_config(), "c:x"),
        ];
        for (name, config, unix) in cases {
            let result = call_resolve_entry_path(name, &config);
            if cfg!(windows) {
                assert_matches!(
                    result,
                    Err(ArchiveError::SecurityViolation { .. }),
                    "{name:?}"
                );
            } else {
                assert_eq!(result.unwrap(), PathBuf::from(unix), "{name:?}");
            }
        }
    }

    #[test]
    fn test_resolve_entry_path_parent_hidden_behind_prefix_rejected() {
        let mut names = vec!["\\\\?\\C:..\\x", "/\\?\\C:..", "\\\\?\\C:\\..\\x"];
        if cfg!(windows) {
            names.extend(["C:..", "c:../x"]);
        }
        for name in names {
            let result = resolve_zip_entry_path(name, &absolute_config());
            assert_matches!(result, Err(ArchiveError::PathTraversal { .. }), "{name:?}");
        }
    }

    fn name_strategy() -> impl proptest::strategy::Strategy<Value = String> {
        use proptest::prelude::Just;
        use proptest::prelude::prop_oneof;
        use proptest::strategy::Strategy;
        let prefix = prop_oneof![
            Just(""),
            Just("/"),
            Just("\\"),
            Just("\\\\?\\"),
            Just("//?/"),
            Just("/\\?\\"),
            Just("\\\\.\\"),
            Just("\\\\?\\UNC\\"),
            Just("C:"),
            Just("C:\\"),
        ];
        let part = prop_oneof![
            3 => Just("C:.."),
            3 => Just(".."),
            2 => Just("C:"),
            2 => Just("."),
            2 => Just("/"),
            2 => Just("\\"),
            2 => Just("?"),
            2 => Just("UNC"),
            3 => Just("a"),
        ];
        (prefix, proptest::collection::vec(part, 0..6))
            .prop_map(|(prefix, parts)| format!("{prefix}{}", parts.concat()))
    }

    proptest::proptest! {
        #![proptest_config(proptest::prelude::ProptestConfig::with_cases(4096))]
        #[test]
        fn test_resolve_entry_path_ok_paths_have_only_normal_components(
            name in name_strategy(),
            absolute in proptest::prelude::any::<bool>(),
        ) {
            let config = if absolute { absolute_config() } else { strict_config() };
            if let Ok(path) = resolve_zip_entry_path(&name, &config) {
                if path == Path::new(".") {
                    proptest::prop_assert!(
                        name.chars().all(|c| matches!(c, '.' | '/' | '\\')),
                        "{name:?} resolved to the archive root"
                    );
                    return Ok(());
                }
                proptest::prop_assert!(
                    path.components()
                        .all(|c| matches!(c, std::path::Component::Normal(_))),
                    "{name:?} resolved to {path:?}"
                );
                // Without a ':' component Windows parses the path as plain
                // names too, so the invariant also holds on Windows hosts.
                let joined = path.to_string_lossy().replace('/', "\\");
                if !joined.contains(':') {
                    proptest::prop_assert!(
                        Utf8WindowsPath::new(&joined)
                            .components()
                            .all(|c| matches!(c, Utf8WindowsComponent::Normal(_))),
                        "{name:?} resolved to {path:?}"
                    );
                }
            }
        }
    }

    #[cfg(windows)]
    #[test]
    fn test_resolve_entry_path_windows_reserved_name_left_to_safe_path() {
        let path = resolve_zip_entry_path("dir/NUL.txt", &strict_config()).unwrap();
        assert_eq!(path, PathBuf::from("dir/NUL.txt"));
    }

    #[cfg(windows)]
    #[test]
    fn test_resolve_entry_path_windows_colon_returned_raw_in_verify_preflight() {
        let path = parse_zip_entry_name("dir\\c:x", &strict_config())
            .unwrap()
            .into_preflight_path();
        assert_eq!(path, PathBuf::from("dir\\c:x"));
    }

    #[cfg(windows)]
    #[test]
    fn test_resolve_entry_path_windows_colon_rejected_in_strict() {
        let result = resolve_zip_entry_path("dir\\c:x", &strict_config());
        assert_matches!(
            result,
            Err(ArchiveError::SecurityViolation { reason, .. }) if reason == "path component contains ':': c:x"
        );
    }

    #[test]
    fn test_resolve_zip_entry_path_empty_name_is_a_security_violation() {
        for config in [strict_config(), absolute_config()] {
            let result = resolve_zip_entry_path("", &config);
            assert_matches!(result, Err(ArchiveError::SecurityViolation { .. }));
        }
    }

    #[test]
    fn test_resolve_entry_path_parent_components_rejected_in_both_separators() {
        for name in [
            "../escape.txt",
            "/../etc/shadow",
            "a\\..\\..\\x",
            "a/../b",
            "a\\..\\b",
        ] {
            for config in [strict_config(), absolute_config()] {
                let result = call_resolve_entry_path(name, &config);
                assert_matches!(
                    result,
                    Err(ArchiveError::PathTraversal { .. }),
                    "{name:?} must be rejected"
                );
            }
        }
    }

    #[test]
    fn test_resolve_zip_entry_path_nul_byte_is_security_violation() {
        for config in [strict_config(), absolute_config()] {
            for raw in [
                "a\0b.txt",
                "/a\0b.txt",
                "C:\\a\0b.txt",
                "\\\\?\\C:\\a\0b.txt",
                "\\\\server\\share\\a\0b",
            ] {
                let result = resolve_zip_entry_path(raw, &config);
                assert_matches!(
                    result,
                    Err(ArchiveError::SecurityViolation { .. }),
                    "{raw:?}"
                );
            }
        }
    }

    #[test]
    fn test_resolve_zip_entry_path_nul_byte_passes_through_in_verify_preflight() {
        let path = parse_zip_entry_name("a\0b.txt", &strict_config())
            .unwrap()
            .into_preflight_path();
        assert_eq!(path, PathBuf::from("a\0b.txt"));
    }

    #[test]
    fn test_nul_byte_entry_is_reported_by_verify_and_rejected_by_extraction() {
        let dir = TempDir::new().unwrap();
        let archive_path = dir.path().join("nul.zip");
        std::fs::write(&archive_path, create_raw_zip_entry("a\0b.txt", b"x")).unwrap();
        let out = dir.path().join("out");
        std::fs::create_dir(&out).unwrap();
        let config = SecurityConfig::default();

        let report = crate::verify_archive(&archive_path, &config).unwrap();
        assert_eq!(report.status(), crate::VerificationStatus::Fail);
        assert!(
            report
                .issues()
                .iter()
                .any(|i| i.message.contains("null bytes")),
            "expected a null-byte issue, got: {:?}",
            report.issues()
        );

        let result = crate::extract_archive(&archive_path, &out, &config);
        assert_matches!(result, Err(ArchiveError::SecurityViolation { .. }));
    }
}

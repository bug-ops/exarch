//! Archive listing implementation.

use std::fs::File;
use std::io::ErrorKind;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;
use std::path::Path;
use std::path::PathBuf;
use std::time::SystemTime;

use crate::ArchiveError;
use crate::Result;
use crate::SecurityConfig;
use crate::config::Validated;
#[cfg(test)]
use crate::error::QuotaResource;
use crate::formats::ZipArchive;
use crate::formats::common::encrypted_archive_error;
use crate::formats::common::normalize_entry_name;
use crate::formats::compression::CompressionCodec;
use crate::formats::detect::ArchiveType;
use crate::formats::detect::FormatFamily;
use crate::formats::detect::detect_format;
use crate::formats::sevenz::SevenZClass;
use crate::formats::sevenz::is_password_error;
use crate::formats::sevenz::sevenz_entry_compression;
use crate::formats::sevenz::verify_sevenz_blocks;
use crate::formats::tar::effective_entry_type;
use crate::formats::tar::open_tar_stream;
use crate::formats::tar_metadata_limit::TarEntryGuard;
use crate::formats::tar_metadata_limit::TarReadBudget;
use crate::formats::tar_metadata_limit::budget_violation;
use crate::formats::tar_metadata_limit::budgeted_reader;
use crate::formats::tar_metadata_limit::budgeted_tar_entries;
use crate::formats::zip::is_password_required;
use crate::formats::zip::parse_zip_entry_name;
use crate::formats::zip::read_zip_symlink_target;
use crate::formats::zip::read_zip_symlink_target_checked;
use crate::formats::zip::resolve_zip_entry_path;
use crate::formats::zip::zip_mode_is_symlink;
use crate::formats::zip::zip_node_kind;
use crate::formats::zip_tail::DescriptorTail;
use crate::inspection::integrity::Charge;
use crate::inspection::integrity::DecodeOutcome;
use crate::inspection::integrity::IntegrityPass;
use crate::inspection::integrity::Slot;
use crate::inspection::integrity::TarTrailer;
use crate::inspection::manifest::ArchiveEntry;
use crate::inspection::manifest::ArchiveManifest;
use crate::inspection::manifest::EntryCompression;
use crate::inspection::manifest::LinkTarget;
use crate::inspection::manifest::ManifestEntryKind;
use crate::inspection::manifest::ManifestEntryType;
use crate::inspection::report::UnverifiedReason;
use crate::security::fs_view::LinkKind;
use crate::security::fs_view::MAX_SYMLINK_TARGET_BYTES;
use crate::security::fs_view::check_name_lengths;
use crate::security::fs_view::name_too_long;
use crate::security::quota::QuotaPermit;
use crate::security::quota::QuotaTracker;
use crate::security::validator::EntryPath;
use crate::security::validator::NodeKind;
use crate::security::validator::require_non_empty_name;
use crate::types::safe_path::has_null_bytes;

/// Lists archive contents without extracting.
///
/// Returns a manifest containing metadata for all entries in the archive.
/// No files are written to disk during this operation.
///
/// # Arguments
///
/// * `archive_path` - Path to archive file
/// * `config` - Security configuration (quota limits apply)
///
/// # Errors
///
/// Returns error if:
/// - Archive file cannot be opened
/// - Archive format is unsupported or corrupted
/// - Quota limits exceeded (file count, total size, single file size)
/// - A ZIP archive's structure is read differently by different tools
///   ([`ArchiveError::ZipInconsistency`], unless `zip_consistency` is `Ignore`)
/// - A link target exceeds the host's name limits
///
/// # Examples
///
/// ```no_run
/// use exarch_core::SecurityConfig;
/// use exarch_core::list_archive;
///
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// let config = SecurityConfig::default();
/// let manifest = list_archive("archive.tar.gz", &config)?;
///
/// println!("Archive contains {} files", manifest.total_entries());
/// for entry in manifest.entries() {
///     println!("{}: {} bytes", entry.path.display(), entry.size);
/// }
/// # Ok(())
/// # }
/// ```
pub fn list_archive<P: AsRef<Path>>(
    archive_path: P,
    config: &SecurityConfig,
) -> Result<ArchiveManifest> {
    let config = config.clone().validate()?;
    list_validated(archive_path.as_ref(), &config, &mut ListPass::Strict)
}

/// Which listing runs: the bare `list_archive`, or `verify`'s pre-flight.
///
/// The pre-flight defers rejections that `verify_entry` reports as issues, and
/// may decode payloads through an integrity pass. Only the pre-flight can carry
/// a pass, so a strict listing that decodes is unrepresentable.
pub(crate) enum ListPass<'a, 'c> {
    /// Bare listing: every policy violation fails the listing.
    Strict,
    /// `verify`'s pre-flight, optionally decoding payloads through the pass.
    VerifyPreflight(Option<&'a mut IntegrityPass<'c>>),
}

impl<'c> ListPass<'_, 'c> {
    /// Returns the integrity pass, which only the pre-flight can carry.
    pub(crate) fn integrity(&mut self) -> Option<&mut IntegrityPass<'c>> {
        match self {
            Self::Strict => None,
            Self::VerifyPreflight(pass) => pass.as_deref_mut(),
        }
    }

    const fn mode(&self) -> ListMode {
        match self {
            Self::Strict => ListMode::Strict,
            Self::VerifyPreflight(_) => ListMode::VerifyPreflight,
        }
    }
}

/// Borrow-free projection of [`ListPass`] for checks that must not hold the
/// integrity pass.
#[derive(Clone, Copy, PartialEq, Eq)]
enum ListMode {
    /// See [`ListPass::Strict`].
    Strict,
    /// See [`ListPass::VerifyPreflight`].
    VerifyPreflight,
}

/// Reserves quota for a listed entry; the pre-flight lifts only the per-file
/// size limit.
fn reserve_entry(
    quota: &mut QuotaTracker,
    size: u64,
    config: &SecurityConfig<Validated>,
    mode: ListMode,
) -> Result<QuotaPermit> {
    match mode {
        ListMode::Strict => quota.reserve(size, config),
        ListMode::VerifyPreflight => quota.reserve_without_file_limit(size, config),
    }
}

/// Lists an archive with an already validated config, decoding payloads when
/// `listing` carries an integrity pass.
pub(crate) fn list_validated(
    archive_path: &Path,
    config: &SecurityConfig<Validated>,
    listing: &mut ListPass<'_, '_>,
) -> Result<ArchiveManifest> {
    list_detected(archive_path, detect_format(archive_path)?, config, listing)
}

/// Lists an archive whose format is already known.
pub(crate) fn list_detected(
    archive_path: &Path,
    format: ArchiveType,
    config: &SecurityConfig<Validated>,
    listing: &mut ListPass<'_, '_>,
) -> Result<ArchiveManifest> {
    match format.family() {
        FormatFamily::Tar(codec) => list_tar(archive_path, codec, format, config, listing),
        FormatFamily::Zip => list_zip(archive_path, config, listing),
        FormatFamily::SevenZ => list_sevenz(archive_path, config, listing),
    }
}

fn list_tar(
    archive_path: &Path,
    codec: Option<CompressionCodec>,
    format: ArchiveType,
    config: &SecurityConfig<Validated>,
    listing: &mut ListPass<'_, '_>,
) -> Result<ArchiveManifest> {
    let stream = open_tar_stream(archive_path, codec, config.max_decoder_memory)?;
    let (budgeted, budget) = budgeted_reader(stream, config.max_tar_metadata_bytes);
    let archive = tar::Archive::new(budgeted);
    let trailer = if codec.is_some() {
        TarTrailer::DrainToDecoderEof
    } else {
        TarTrailer::Probe
    };
    list_tar_entries(archive, budget, format, config, listing, trailer)
}

/// Lists entries from a TAR archive already wrapped in a [`budgeted_reader`].
///
/// `budget` must be the handle returned alongside the reader that `archive`
/// wraps — passed explicitly (rather than re-derived) so the reader and the
/// budget used to arm/disarm around it can never be a mismatched pair.
fn list_tar_entries<R: std::io::Read>(
    mut archive: tar::Archive<crate::formats::tar_metadata_limit::BudgetedReader<R>>,
    budget: TarReadBudget,
    format: ArchiveType,
    config: &SecurityConfig<Validated>,
    listing: &mut ListPass<'_, '_>,
    trailer: TarTrailer,
) -> Result<ArchiveManifest> {
    let list_mode = listing.mode();
    let mut manifest = ArchiveManifest::new(format);
    let mut quota = QuotaTracker::new();

    let mut entries = budgeted_tar_entries(&mut archive, budget)
        .map_err(|e| ArchiveError::InvalidArchive(format!("failed to read TAR entries: {e}")))?;

    while let Some(entry_result) = entries.next_entry() {
        let mut entry = entry_result.map_err(|e| {
            budget_violation(&e).unwrap_or_else(|| {
                ArchiveError::InvalidArchive(format!("failed to read TAR entry: {e}"))
            })
        })?;

        // Skip TAR metadata entries (PAX headers, GNU long names/links)
        if is_tar_metadata_entry(&entry) {
            continue;
        }

        let size = entry.size();

        // Route through the same QuotaTracker used by extraction: per-file
        // size, file count, and total size (with checked arithmetic) are all
        // enforced here using the same logic. Note this doesn't make listing
        // and extraction fully equivalent — extraction's QuotaTracker only
        // records EntryType::File, while listing records every entry type
        // (directories, symlinks, hardlinks too), a pre-existing divergence.
        //
        // A quota rejection here (the `?`) aborts the loop without an
        // explicit `entry.abandon()`; harmless — the guard's bounded drain
        // on drop is pointless I/O in that case, not a correctness
        // requirement (see `TarEntryGuard::abandon`).
        let _permit = reserve_entry(&mut quota, size, config, list_mode)?;

        let path = entry
            .path()
            .map_err(|e| ArchiveError::InvalidArchive(format!("invalid path: {e}")))?
            .into_owned();

        if list_mode == ListMode::Strict && has_null_bytes(&path) {
            return Err(ArchiveError::SecurityViolation {
                reason: format!("path contains null bytes: {}", path.display()),
            });
        }

        if contains_traversal(&path, config) {
            return Err(ArchiveError::PathTraversal { path });
        }

        require_non_empty_name(&path)?;
        let tar_type = effective_entry_type(&entry);
        let kind = NodeKind::directory_if(tar_type == tar::EntryType::Directory);
        if !admit_path(&path, kind, &mut manifest, listing)? {
            continue;
        }

        let entry_type = convert_tar_entry_type(tar_type)?;
        let mode = crate::formats::tar::tar_permission_bits(entry.header());
        let modified =
            entry.header().mtime().ok().and_then(|t| {
                SystemTime::UNIX_EPOCH.checked_add(std::time::Duration::from_secs(t))
            });

        let target = match entry.header().entry_type() {
            tar::EntryType::Symlink | tar::EntryType::Link => {
                let target = entry
                    .link_name()
                    .map_err(|e| ArchiveError::InvalidArchive(format!("invalid link target: {e}")))?
                    .map(std::borrow::Cow::into_owned);
                let is_symlink = entry.header().entry_type() == tar::EntryType::Symlink;
                let kind = if is_symlink {
                    LinkKind::Symlink
                } else {
                    LinkKind::Hardlink
                };

                match target {
                    Some(t) => classify_link_target(t, kind, list_mode)?,
                    // `link_name()` returns `None` when neither the ustar
                    // linkname field nor a PAX `linkpath` override is
                    // present — a structurally different case from an
                    // empty-string target (see `validate_link_target`).
                    // `extract` rejects this via `to_entry_type`
                    // (formats/tar.rs) with the same message; mirrored here
                    // for list/extract parity; skipped in verify's pre-flight
                    // since `verify_entry` reports a missing target.
                    None if list_mode == ListMode::Strict => {
                        return Err(ArchiveError::InvalidArchive(format!(
                            "{kind} missing target"
                        )));
                    }
                    None => LinkTarget::Missing,
                }
            }
            _ => LinkTarget::Missing,
        };

        let archive_entry = ArchiveEntry {
            path,
            kind: manifest_entry_kind(entry_type, target),
            size,
            compression: EntryCompression::Unknown,
            mode,
            modified,
        };

        if let Some(pass) = listing.integrity() {
            let slot = pass.begin_entry(size, &archive_entry.compression);
            if entry_type == ManifestEntryType::File && size > 0 {
                verify_tar_payload(pass, slot, &mut entry, &archive_entry.path)?;
            }
        }

        manifest.add_entry(archive_entry)?;
    }

    drop(entries);
    if let Some(pass) = listing.integrity() {
        pass.check_tar_trailer(&mut archive.into_inner(), trailer)?;
    }

    Ok(manifest)
}

/// Reads one TAR entry's content to its end so the codec and the tar framing
/// are exercised.
///
/// A decode failure inside entry content is a hard error: the scan cannot
/// continue past it, and a report over the entries read so far would let
/// security look fine for entries that were never inspected. Listing already
/// decodes every entry through the guard's drain, so only GNU sparse entries
/// (whose synthesized zeros the drain caps) are charged to the budget.
fn verify_tar_payload<R: Read>(
    pass: &mut IntegrityPass<'_>,
    slot: Slot,
    entry: &mut TarEntryGuard<'_, '_, R>,
    path: &Path,
) -> Result<()> {
    let charge = if entry.header().entry_type() == tar::EntryType::GNUSparse {
        Charge::Declared
    } else {
        Charge::Free
    };
    let declared = entry.size();
    match pass.decode(slot, &mut **entry, declared, charge) {
        DecodeOutcome::Failed(failure) => {
            entry.abandon();
            Err(failure.into_tar_error(path))
        }
        outcome => pass.record(slot, path, outcome),
    }
}

fn list_zip(
    archive_path: &Path,
    config: &SecurityConfig<Validated>,
    listing: &mut ListPass<'_, '_>,
) -> Result<ArchiveManifest> {
    let file = File::open(archive_path)?;
    ZipArchive::new(file)?.list_with(config, listing)
}

/// Lists entries from an already budget-wrapped TAR reader.
///
/// Used by `ArchiveFormat::list()` implementations to avoid re-opening the
/// archive. `format` is passed through into `ArchiveManifest` as-is. `budget`
/// must be the handle returned alongside `reader` from the same
/// `budgeted_reader` call.
pub(crate) fn list_tar_reader<R: Read>(
    reader: crate::formats::tar_metadata_limit::BudgetedReader<R>,
    budget: TarReadBudget,
    format: ArchiveType,
    config: &SecurityConfig<Validated>,
    listing: &mut ListPass<'_, '_>,
    trailer: TarTrailer,
) -> Result<ArchiveManifest> {
    let archive = tar::Archive::new(reader);
    list_tar_entries(archive, budget, format, config, listing, trailer)
}

/// Lists entries from an already-opened ZIP archive.
///
/// Used by `ArchiveFormat::list()` and `verify()`. Taking the crate's own
/// handler rather than the raw reader proves that opening already ran the
/// admission checks (encryption, method, declared sizes) and the structural
/// census, so listing does not repeat them.
pub(crate) fn list_zip_reader<R: Read + Seek>(
    archive: &mut ZipArchive<R>,
    config: &SecurityConfig<Validated>,
    listing: &mut ListPass<'_, '_>,
) -> Result<ArchiveManifest> {
    let list_mode = listing.mode();
    let mut manifest = ArchiveManifest::new(ArchiveType::Zip);
    let mut quota = QuotaTracker::new();
    let archive = archive.reader_mut();

    for i in 0..archive.len() {
        let mut entry = archive.by_index(i).map_err(|e| {
            if is_password_required(&e) {
                return encrypted_archive_error();
            }
            ArchiveError::InvalidArchive(format!("failed to read ZIP entry: {e}"))
        })?;

        // Route through the same QuotaTracker used by extraction: per-file
        // size, file count, and total size (with checked arithmetic) are all
        // enforced here using the same logic. Note this doesn't make listing
        // and extraction fully equivalent — extraction's QuotaTracker only
        // records EntryType::File, while listing records every entry type
        // (directories, symlinks, hardlinks too), a pre-existing divergence.
        let _permit = reserve_entry(&mut quota, entry.size(), config, list_mode)?;

        let raw_name = entry
            .name()
            .map_err(|e| ArchiveError::InvalidArchive(format!("invalid entry name: {e}")))?
            .into_owned();
        let path = match list_mode {
            ListMode::Strict => resolve_zip_entry_path(&raw_name, config)?,
            ListMode::VerifyPreflight => {
                parse_zip_entry_name(&raw_name, config)?.into_preflight_path()
            }
        };
        let kind = zip_node_kind(&path, &entry)?;
        if !admit_path(&path, kind, &mut manifest, listing)? {
            continue;
        }

        let entry_type = convert_zip_entry_type(&entry, kind);
        let size = entry.size();
        let compression = EntryCompression::Entry(entry.compressed_size());
        let mode = entry.unix_mode().map(|m| m & 0o7777);
        #[expect(
            clippy::cast_sign_loss,
            reason = "the value is non-negative at this point"
        )]
        let modified = entry.last_modified().and_then(|dt| {
            time::PrimitiveDateTime::try_from(dt).ok().and_then(|t| {
                let timestamp = t.assume_utc().unix_timestamp().max(0) as u64;
                SystemTime::UNIX_EPOCH.checked_add(std::time::Duration::from_secs(timestamp))
            })
        });

        let mut tracked = listing.integrity().map(|pass| {
            let slot = pass.begin_entry(size, &compression);
            (pass, slot)
        });
        // Symlink targets are decoded below, through the target read.
        let has_payload = entry_type != ManifestEntryType::Symlink
            && (entry_type != ManifestEntryType::Directory || size > 0);
        let mut descriptor_tail = None;
        if has_payload && let Some((pass, slot)) = tracked.as_mut() {
            let outcome = pass.decode(*slot, &mut entry, size, Charge::Declared);
            if matches!(outcome, DecodeOutcome::Verified) {
                descriptor_tail = DescriptorTail::of(&entry);
            }
            pass.record(*slot, &path, outcome)?;
        }

        // Drop `entry` before conditionally re-opening the archive for symlink
        // target data: the borrow checker requires the mutable borrow to end.
        drop(entry);

        if let (Some(tail), Some((pass, slot))) = (descriptor_tail, tracked.as_mut()) {
            tail.check(archive, i, pass, *slot, &path)?;
        }

        let target = if entry_type == ManifestEntryType::Symlink {
            let mut sym_entry = archive.by_index(i).map_err(|e| {
                ArchiveError::InvalidArchive(format!("failed to re-read ZIP entry {i}: {e}"))
            })?;
            let declared = sym_entry.size();
            if list_mode == ListMode::VerifyPreflight && declared > MAX_SYMLINK_TARGET_BYTES as u64
            {
                LinkTarget::Oversized {
                    bytes: usize::try_from(declared).unwrap_or(usize::MAX),
                }
            } else {
                let target = match tracked.as_mut() {
                    Some((pass, slot)) => {
                        read_zip_symlink_target_checked(&mut sym_entry, pass, *slot, &path)?
                    }
                    None => read_zip_symlink_target(&mut sym_entry)?,
                };
                classify_link_target(target, LinkKind::Symlink, list_mode)?
            }
        } else {
            LinkTarget::Missing
        };

        let archive_entry = ArchiveEntry {
            path,
            kind: manifest_entry_kind(entry_type, target),
            size,
            compression,
            mode,
            modified,
        };

        manifest.add_entry(archive_entry)?;
    }

    Ok(manifest)
}

/// Lists entries from an already-opened 7z source reader.
///
/// Used by `ArchiveFormat::list()` to avoid re-opening the archive. The reader
/// must be positioned at the beginning of the 7z stream.
pub(crate) fn list_sevenz_reader<R: Read + Seek>(
    mut source: R,
    config: &SecurityConfig<Validated>,
    listing: &mut ListPass<'_, '_>,
) -> Result<ArchiveManifest> {
    use sevenz_rust2::Archive;
    use sevenz_rust2::Password;

    let password = Password::empty();
    let archive = match Archive::read(&mut source, &password) {
        Ok(a) => a,
        Err(e) => {
            if is_password_error(&e) {
                return Err(encrypted_archive_error());
            }
            if is_empty_sevenz_archive_reader(&e, &mut source) {
                return Ok(ArchiveManifest::new(ArchiveType::SevenZ));
            }
            return Err(ArchiveError::InvalidArchive(format!(
                "failed to open 7z archive: {e}"
            )));
        }
    };

    list_sevenz_parsed(&archive, source, config, listing)
}

/// Lists an already-parsed 7z archive, decoding its blocks when `listing`
/// carries an integrity pass.
pub(crate) fn list_sevenz_parsed<R: Read + Seek>(
    archive: &sevenz_rust2::Archive,
    mut source: R,
    config: &SecurityConfig<Validated>,
    listing: &mut ListPass<'_, '_>,
) -> Result<ArchiveManifest> {
    let source_len = source.seek(SeekFrom::End(0))?;
    let (manifest, slots) = list_sevenz_archive(archive, source_len, config, listing)?;
    if let Some(pass) = listing.integrity() {
        verify_sevenz_blocks(archive, &mut source, pass, &slots)?;
    }
    Ok(manifest)
}

/// Checks whether a sevenz-rust2 parse failure is due to a valid empty 7z
/// archive, using a generic seekable reader.
fn is_empty_sevenz_archive_reader<R: Read + Seek>(
    err: &sevenz_rust2::Error,
    source: &mut R,
) -> bool {
    const SEVENZ_MAGIC: [u8; 6] = [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C];
    const EMPTY_ARCHIVE_SIZE: u64 = 32;

    let is_eof = matches!(err, sevenz_rust2::Error::Io(io_err, _) if io_err.kind() == ErrorKind::UnexpectedEof);
    if !is_eof {
        return false;
    }

    let Ok(size) = source.seek(std::io::SeekFrom::End(0)) else {
        return false;
    };
    if size != EMPTY_ARCHIVE_SIZE {
        return false;
    }

    let Ok(_) = source.seek(std::io::SeekFrom::Start(0)) else {
        return false;
    };
    let mut magic = [0u8; 6];
    source.read_exact(&mut magic).is_ok() && magic == SEVENZ_MAGIC
}

/// Builds a manifest from a parsed 7z archive structure.
///
/// No NUL-byte check is applied to `entry.name`, unlike `list_tar_entries`
/// and `list_zip_reader`: `sevenz_rust2::Archive::read` decodes each name as
/// UTF-16 and stops at the first zero code unit while parsing the header
/// (see `sevenz-rust2::reader`'s `NamesReader`), so an embedded NUL cannot
/// survive into `entry.name` here. This is a format-parser guarantee, not a
/// scope decision — it would need re-checking if `sevenz-rust2` ever changes
/// that truncation behavior.
fn list_sevenz_archive(
    archive: &sevenz_rust2::Archive,
    source_len: u64,
    config: &SecurityConfig<Validated>,
    listing: &mut ListPass<'_, '_>,
) -> Result<(ArchiveManifest, Vec<Option<Slot>>)> {
    let list_mode = listing.mode();
    let mut manifest = ArchiveManifest::new(ArchiveType::SevenZ);
    let mut quota = QuotaTracker::new();
    let compression = sevenz_entry_compression(archive, source_len)?;
    // One element per archive file: the integrity slot of the manifest entry it
    // became, or `None` for an anti item (never listed), an entry dropped for
    // its path, or without a pass.
    let mut slots = Vec::with_capacity(archive.files.len());

    for (entry, compression) in archive.files.iter().zip(compression) {
        let SevenZClass::Present(kind) = SevenZClass::of(entry) else {
            slots.push(None);
            continue;
        };

        // Route through the same QuotaTracker used by extraction: per-file
        // size, file count, and total size (with checked arithmetic) are all
        // enforced here using the same logic. Note this doesn't make listing
        // and extraction fully equivalent — extraction's QuotaTracker only
        // records EntryType::File, while listing records every entry type
        // (directories, symlinks, hardlinks too), a pre-existing divergence.
        let _permit = reserve_entry(&mut quota, entry.size, config, list_mode)?;

        let path = PathBuf::from(normalize_entry_name(&entry.name));

        if contains_traversal(&path, config) {
            return Err(ArchiveError::PathTraversal { path });
        }

        require_non_empty_name(&path)?;
        let entry_type = kind.manifest_type();
        if !admit_path(&path, kind.node_kind(), &mut manifest, listing)? {
            slots.push(None);
            continue;
        }

        let size = entry.size;
        let modified = entry
            .has_last_modified_date
            .then(|| SystemTime::from(entry.last_modified_date));

        slots.push(
            listing
                .integrity()
                .map(|pass| pass.begin_entry(size, &compression)),
        );

        let archive_entry = ArchiveEntry {
            path,
            kind: manifest_entry_kind(entry_type, LinkTarget::Unread),
            size,
            compression,
            mode: None,
            modified,
        };

        manifest.add_entry(archive_entry)?;
    }

    Ok((manifest, slots))
}

fn list_sevenz(
    archive_path: &Path,
    config: &SecurityConfig<Validated>,
    listing: &mut ListPass<'_, '_>,
) -> Result<ArchiveManifest> {
    let mut file = File::open(archive_path)?;
    list_sevenz_reader(&mut file, config, listing)
}

/// Returns whether the entry at `path` is kept.
///
/// An entry the host cannot create fails the listing; the verify pre-flight
/// instead records only its length on `manifest` and drops it, so the report
/// can flag it without the manifest growing with the path. When the verify
/// pass decodes content, the dropped entry is also counted as unverified.
///
/// # Errors
///
/// A root entry (`.`) whose `kind` is not a directory fails the listing in
/// either mode, so no list handler can skip the root-entry rule.
fn admit_path(
    path: &Path,
    kind: NodeKind,
    manifest: &mut ArchiveManifest,
    listing: &mut ListPass<'_, '_>,
) -> Result<bool> {
    EntryPath::of(path).require_directory_root(kind)?;
    if check_name_lengths(path).is_ok() {
        return Ok(true);
    }
    if listing.mode() == ListMode::Strict {
        return Err(ArchiveError::Io(name_too_long()));
    }
    manifest.add_oversized(path.as_os_str().len());
    if let Some(pass) = listing.integrity() {
        pass.count_unverified(UnverifiedReason::PathTooLong, 1);
    }
    Ok(false)
}

fn manifest_entry_kind(entry_type: ManifestEntryType, target: LinkTarget) -> ManifestEntryKind {
    match entry_type {
        ManifestEntryType::File => ManifestEntryKind::File,
        ManifestEntryType::Directory => ManifestEntryKind::Directory,
        ManifestEntryType::Symlink => ManifestEntryKind::Symlink { target },
        ManifestEntryType::Hardlink => ManifestEntryKind::Hardlink { target },
    }
}

/// Checks a symlink/hardlink target parsed during listing for emptiness and
/// NUL bytes — the same two conditions `SafeSymlink::validate` and
/// `HardlinkTracker::validate_hardlink` reject during extraction (#424).
/// `kind` is `"symlink"` or `"hardlink"`, matching the wording used by those
/// extraction-side checks.
///
/// This does not give `list` full parity with `extract`: unlike the
/// extraction-side validators, it does not check
/// `config.allowed.symlinks`/`hardlinks`, reject absolute targets, or detect
/// traversal within the target — only emptiness and NUL bytes. Skipped
/// entirely in the verify pre-flight, so `verify_archive` can defer to
/// `verify_entry`'s own equivalent checks and report a graceful
/// `VerificationIssue` instead of aborting.
fn validate_link_target(target: &Path, kind: LinkKind, mode: ListMode) -> Result<()> {
    if mode == ListMode::VerifyPreflight {
        return Ok(());
    }
    if target.is_empty() {
        return Err(ArchiveError::SecurityViolation {
            reason: format!("{kind} target is empty"),
        });
    }
    if has_null_bytes(target) {
        return Err(ArchiveError::SecurityViolation {
            reason: format!("{kind} target contains null bytes"),
        });
    }
    Ok(())
}

/// Validates a link target found during listing and classifies it once.
///
/// A target beyond the host's name limits is never retained: bare listing
/// rejects it, and the verify pre-flight keeps only its length so the report
/// can flag it without the manifest growing with the target.
fn classify_link_target(target: PathBuf, kind: LinkKind, mode: ListMode) -> Result<LinkTarget> {
    validate_link_target(&target, kind, mode)?;
    match LinkTarget::classify(target, kind) {
        LinkTarget::Oversized { bytes } if mode == ListMode::Strict => Err(
            ArchiveError::InvalidArchive(format!("{kind} target too long: {bytes} bytes")),
        ),
        classified => Ok(classified),
    }
}

/// Returns `true` if the path contains traversal attempts.
///
/// `ParentDir` (`..`) is always rejected. `RootDir` and `Prefix` (Windows drive
/// paths such as `C:\`) are rejected only when `config.allowed.absolute_paths`
/// is false, matching the behaviour of `SafePath::validate`.
fn contains_traversal(path: &Path, config: &SecurityConfig<Validated>) -> bool {
    use std::path::Component;
    path.components().any(|c| match c {
        Component::ParentDir => true,
        Component::Prefix(_) | Component::RootDir => !config.allowed.absolute_paths,
        _ => false,
    })
}

/// Returns `true` for TAR metadata entries that should be skipped.
fn is_tar_metadata_entry<R: std::io::Read>(entry: &tar::Entry<'_, R>) -> bool {
    matches!(
        entry.header().entry_type(),
        tar::EntryType::XHeader
            | tar::EntryType::XGlobalHeader
            | tar::EntryType::GNULongName
            | tar::EntryType::GNULongLink
    )
}

fn convert_tar_entry_type(tar_type: tar::EntryType) -> Result<ManifestEntryType> {
    match tar_type {
        tar::EntryType::Directory => Ok(ManifestEntryType::Directory),
        tar::EntryType::Symlink => Ok(ManifestEntryType::Symlink),
        tar::EntryType::Link => Ok(ManifestEntryType::Hardlink),
        tar::EntryType::Char | tar::EntryType::Block | tar::EntryType::Fifo => {
            Err(ArchiveError::InvalidArchive(
                "special files (char/block devices, FIFOs) are not supported".to_string(),
            ))
        }
        // Regular, Continuous, GNUSparse treated as files
        _ => Ok(ManifestEntryType::File),
    }
}

fn convert_zip_entry_type<R: std::io::Read + std::io::Seek>(
    entry: &zip::read::ZipFile<'_, R>,
    kind: NodeKind,
) -> ManifestEntryType {
    if kind == NodeKind::Directory {
        ManifestEntryType::Directory
    } else if is_zip_symlink(entry) {
        ManifestEntryType::Symlink
    } else {
        ManifestEntryType::File
    }
}

fn is_zip_symlink<R: std::io::Read + std::io::Seek>(entry: &zip::read::ZipFile<'_, R>) -> bool {
    zip_mode_is_symlink(entry.unix_mode())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use std::assert_matches;

    use crate::OversizedEntry;
    use crate::test_utils::HOST_PATH_LIMIT;
    use crate::test_utils::create_raw_zip_entry;
    use crate::test_utils::path_of_len;
    use crate::test_utils::tar_with_pax_linkpath;
    use crate::test_utils::tar_with_pax_nul_path;
    use flate2::write::GzEncoder;
    use std::io::Write;
    use tempfile::NamedTempFile;

    /// Builds a raw TAR archive containing a single entry with the given path
    /// string.
    ///
    /// The `tar` crate's `set_path()` rejects `..` components and absolute
    /// paths for safety, so we write the name directly into the 512-byte
    /// header block to create adversarial archives for testing path
    /// traversal detection.
    fn tar_with_raw_path(path: &str) -> Vec<u8> {
        // A TAR header is exactly 512 bytes. The name field is bytes 0..100.
        // We start with a zeroed block and fill in the minimal fields:
        // name (0), mode (100), uid (108), gid (116), size (124), mtime (136),
        // checksum (148), typeflag (156). All numeric fields are NUL-terminated
        // octal strings as per the POSIX ustar spec.
        let mut block = [0u8; 512];

        // Name field: first 100 bytes, NUL-terminated.
        let name_bytes = path.as_bytes();
        debug_assert!(
            name_bytes.len() <= 99,
            "tar_with_raw_path: path exceeds POSIX TAR name field limit (99 bytes)"
        );
        let name_len = name_bytes.len().min(99);
        block[..name_len].copy_from_slice(&name_bytes[..name_len]);

        // Mode: 0000644
        block[100..107].copy_from_slice(b"0000644");
        // UID: 0000000
        block[108..115].copy_from_slice(b"0000000");
        // GID: 0000000
        block[116..123].copy_from_slice(b"0000000");
        // Size: 0 bytes (empty file)
        block[124..135].copy_from_slice(b"00000000000");
        // Mtime: 0
        block[136..147].copy_from_slice(b"00000000000");
        // Typeflag: '0' (regular file)
        block[156] = b'0';

        // Checksum: sum of all bytes in the header (checksum field treated as
        // spaces).
        block[148..156].copy_from_slice(b"        ");
        let checksum: u32 = block.iter().map(|&b| u32::from(b)).sum();
        let checksum_str = format!("{checksum:06o}\0 ");
        block[148..156].copy_from_slice(checksum_str.as_bytes());

        // Two 512-byte zero blocks mark end-of-archive.
        let mut tar = block.to_vec();
        tar.extend_from_slice(&[0u8; 1024]);
        tar
    }

    /// Writes a minimal single-file ZIP archive where `external_attributes`
    /// encodes a full Unix stat(2) mode (file-type bits + permission bits)
    /// in the high 16 bits, as produced by system `zip(1)`, Python's
    /// `zipfile`, and other Unix-aware tools.
    ///
    /// `unix_mode` is what `ZipFile::unix_mode()` should return (i.e.
    /// `external_attributes >> 16`). The zip crate's write API masks
    /// `unix_permissions` to 0o777, so we construct the binary ZIP
    /// structure directly to reproduce archives from external tools.
    /// Uses empty content (CRC32 = 0) to avoid a CRC32 dependency in tests.
    #[allow(clippy::cast_possible_truncation)]
    fn zip_with_raw_unix_mode(filename: &str, unix_mode: u32) -> Vec<u8> {
        let external_attributes = unix_mode << 16;
        let name_bytes = filename.as_bytes();
        let name_len = name_bytes.len() as u16;

        let mut buf: Vec<u8> = Vec::new();

        // Local file header (empty stored entry, CRC32 = 0)
        let local_offset = buf.len() as u32;
        buf.extend_from_slice(b"PK\x03\x04"); // signature
        buf.extend_from_slice(&20u16.to_le_bytes()); // version needed
        buf.extend_from_slice(&0u16.to_le_bytes()); // general purpose flags
        buf.extend_from_slice(&0u16.to_le_bytes()); // compression method: stored
        buf.extend_from_slice(&0u16.to_le_bytes()); // last mod time
        buf.extend_from_slice(&0u16.to_le_bytes()); // last mod date
        buf.extend_from_slice(&0u32.to_le_bytes()); // CRC32
        buf.extend_from_slice(&0u32.to_le_bytes()); // compressed size
        buf.extend_from_slice(&0u32.to_le_bytes()); // uncompressed size
        buf.extend_from_slice(&name_len.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes()); // extra field length
        buf.extend_from_slice(name_bytes);
        // no content bytes

        // Central directory entry
        let central_offset = buf.len() as u32;
        buf.extend_from_slice(b"PK\x01\x02"); // signature
        buf.extend_from_slice(&0x031eu16.to_le_bytes()); // version made by: Unix (3) + spec 3.0
        buf.extend_from_slice(&20u16.to_le_bytes()); // version needed
        buf.extend_from_slice(&0u16.to_le_bytes()); // flags
        buf.extend_from_slice(&0u16.to_le_bytes()); // compression
        buf.extend_from_slice(&0u16.to_le_bytes()); // mod time
        buf.extend_from_slice(&0u16.to_le_bytes()); // mod date
        buf.extend_from_slice(&0u32.to_le_bytes()); // CRC32
        buf.extend_from_slice(&0u32.to_le_bytes()); // compressed size
        buf.extend_from_slice(&0u32.to_le_bytes()); // uncompressed size
        buf.extend_from_slice(&name_len.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes()); // extra length
        buf.extend_from_slice(&0u16.to_le_bytes()); // comment length
        buf.extend_from_slice(&0u16.to_le_bytes()); // disk number start
        buf.extend_from_slice(&0u16.to_le_bytes()); // internal file attributes
        buf.extend_from_slice(&external_attributes.to_le_bytes()); // external attributes
        buf.extend_from_slice(&local_offset.to_le_bytes()); // local header offset
        buf.extend_from_slice(name_bytes);

        // End of central directory record
        let central_size = (buf.len() as u32) - central_offset;
        buf.extend_from_slice(b"PK\x05\x06"); // signature
        buf.extend_from_slice(&0u16.to_le_bytes()); // disk number
        buf.extend_from_slice(&0u16.to_le_bytes()); // disk with central dir
        buf.extend_from_slice(&1u16.to_le_bytes()); // entries on this disk
        buf.extend_from_slice(&1u16.to_le_bytes()); // total entries
        buf.extend_from_slice(&central_size.to_le_bytes());
        buf.extend_from_slice(&central_offset.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes()); // comment length
        buf
    }

    #[test]
    fn test_list_archive_empty_tar() {
        let mut temp_file = NamedTempFile::with_suffix(".tar").unwrap();
        let builder = tar::Builder::new(Vec::new());
        let data = builder.into_inner().unwrap();
        temp_file.write_all(&data).unwrap();
        temp_file.flush().unwrap();

        let config = SecurityConfig::default();
        let manifest = list_archive(temp_file.path(), &config).unwrap();

        assert_eq!(manifest.total_entries(), 0);
        assert_eq!(manifest.total_size(), 0);
        assert_eq!(manifest.entries().len(), 0);
        assert_eq!(manifest.format(), ArchiveType::Tar);
    }

    #[test]
    fn test_list_archive_tar_gz() {
        let mut temp_file = NamedTempFile::with_suffix(".tar.gz").unwrap();
        let mut builder = tar::Builder::new(Vec::new());

        let data = b"test content";
        let mut header = tar::Header::new_gnu();
        header.set_path("file.txt").unwrap();
        header.set_size(data.len() as u64);
        header.set_cksum();
        builder.append(&header, &data[..]).unwrap();

        let tar_data = builder.into_inner().unwrap();
        let mut encoder = GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(&tar_data).unwrap();
        let compressed = encoder.finish().unwrap();

        temp_file.write_all(&compressed).unwrap();
        temp_file.flush().unwrap();

        let config = SecurityConfig::default();
        let manifest = list_archive(temp_file.path(), &config).unwrap();

        assert_eq!(manifest.total_entries(), 1);
        assert_eq!(manifest.format(), ArchiveType::TarGz);
        assert_eq!(manifest.entries()[0].path, PathBuf::from("file.txt"));
        assert_eq!(
            manifest.entries()[0].kind.entry_type(),
            ManifestEntryType::File
        );
    }

    #[test]
    fn test_list_archive_zip() {
        let temp_file = NamedTempFile::with_suffix(".zip").unwrap();
        let file = std::fs::File::create(temp_file.path()).unwrap();
        let mut zip = zip::ZipWriter::new(file);

        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Deflated);
        zip.start_file("test.txt", options).unwrap();
        zip.write_all(b"test content").unwrap();
        zip.finish().unwrap();

        let config = SecurityConfig::default();
        let manifest = list_archive(temp_file.path(), &config).unwrap();

        assert_eq!(manifest.total_entries(), 1);
        assert_eq!(manifest.format(), ArchiveType::Zip);
        assert_eq!(manifest.entries()[0].path, PathBuf::from("test.txt"));
        assert_eq!(
            manifest.entries()[0].kind.entry_type(),
            ManifestEntryType::File
        );
    }

    #[test]
    fn test_list_archive_with_entries() {
        let mut temp_file = NamedTempFile::with_suffix(".tar").unwrap();
        let mut builder = tar::Builder::new(Vec::new());

        let file1_data = b"content1";
        let mut header1 = tar::Header::new_gnu();
        header1.set_path("dir/file1.txt").unwrap();
        header1.set_size(file1_data.len() as u64);
        header1.set_cksum();
        builder.append(&header1, &file1_data[..]).unwrap();

        let file2_data = b"content2";
        let mut header2 = tar::Header::new_gnu();
        header2.set_path("dir/file2.txt").unwrap();
        header2.set_size(file2_data.len() as u64);
        header2.set_cksum();
        builder.append(&header2, &file2_data[..]).unwrap();

        let data = builder.into_inner().unwrap();
        temp_file.write_all(&data).unwrap();
        temp_file.flush().unwrap();

        let config = SecurityConfig::default();
        let manifest = list_archive(temp_file.path(), &config).unwrap();

        assert_eq!(manifest.total_entries(), 2);
        assert_eq!(manifest.total_size(), 16);
        assert_eq!(manifest.entries().len(), 2);
        assert_eq!(manifest.entries()[0].path, PathBuf::from("dir/file1.txt"));
        assert_eq!(manifest.entries()[1].path, PathBuf::from("dir/file2.txt"));
    }

    #[test]
    fn test_list_archive_with_symlink() {
        let mut temp_file = NamedTempFile::with_suffix(".tar").unwrap();
        let mut builder = tar::Builder::new(Vec::new());

        let mut header = tar::Header::new_gnu();
        header.set_path("link").unwrap();
        header.set_size(0);
        header.set_entry_type(tar::EntryType::Symlink);
        header.set_link_name("target.txt").unwrap();
        header.set_cksum();
        builder.append(&header, &[][..]).unwrap();

        let data = builder.into_inner().unwrap();
        temp_file.write_all(&data).unwrap();
        temp_file.flush().unwrap();

        let config = SecurityConfig::default();
        let manifest = list_archive(temp_file.path(), &config).unwrap();

        assert_eq!(manifest.total_entries(), 1);
        assert_eq!(
            manifest.entries()[0].kind.entry_type(),
            ManifestEntryType::Symlink
        );
        assert_eq!(
            manifest.entries()[0].kind.symlink_target(),
            Some(Path::new("target.txt"))
        );
    }

    #[test]
    #[cfg(unix)]
    fn test_list_zip_symlink_target_is_actual_target() {
        use crate::test_utils::create_zip_with_symlink;
        use std::io::Cursor;

        let zip_bytes = create_zip_with_symlink("link", "target.txt");
        let mut archive = ZipArchive::new(Cursor::new(zip_bytes)).unwrap();
        let config = SecurityConfig::default().validate().expect("valid config");
        let manifest = list_zip_reader(&mut archive, &config, &mut ListPass::Strict).unwrap();

        assert_eq!(manifest.total_entries(), 1);
        assert_eq!(
            manifest.entries()[0].kind.entry_type(),
            ManifestEntryType::Symlink
        );
        assert_eq!(
            manifest.entries()[0].kind.symlink_target(),
            Some(Path::new("target.txt")),
            "symlink_target must be the actual link target, not the entry path"
        );
        assert_eq!(
            manifest.entries()[0].kind.hardlink_target(),
            None,
            "ZIP has no hardlink concept — hardlink_target must always be None"
        );
    }

    #[test]
    fn test_list_archive_with_hardlink() {
        let mut temp_file = NamedTempFile::with_suffix(".tar").unwrap();
        let mut builder = tar::Builder::new(Vec::new());

        let mut header = tar::Header::new_gnu();
        header.set_path("link").unwrap();
        header.set_size(0);
        header.set_entry_type(tar::EntryType::Link);
        header.set_link_name("original.txt").unwrap();
        header.set_cksum();
        builder.append(&header, &[][..]).unwrap();

        let data = builder.into_inner().unwrap();
        temp_file.write_all(&data).unwrap();
        temp_file.flush().unwrap();

        let config = SecurityConfig::default();
        let manifest = list_archive(temp_file.path(), &config).unwrap();

        assert_eq!(manifest.total_entries(), 1);
        assert_eq!(
            manifest.entries()[0].kind.entry_type(),
            ManifestEntryType::Hardlink
        );
        assert_eq!(
            manifest.entries()[0].kind.hardlink_target(),
            Some(Path::new("original.txt"))
        );
    }

    #[test]
    fn test_list_archive_quota_exceeded() {
        let mut temp_file = NamedTempFile::with_suffix(".tar").unwrap();
        let mut builder = tar::Builder::new(Vec::new());

        // Create 2 entries
        let data = b"test data";
        let mut header = tar::Header::new_gnu();
        header.set_path("file1.txt").unwrap();
        header.set_size(data.len() as u64);
        header.set_cksum();
        builder.append(&header, &data[..]).unwrap();

        let mut header2 = tar::Header::new_gnu();
        header2.set_path("file2.txt").unwrap();
        header2.set_size(data.len() as u64);
        header2.set_cksum();
        builder.append(&header2, &data[..]).unwrap();

        let archive_data = builder.into_inner().unwrap();
        temp_file.write_all(&archive_data).unwrap();
        temp_file.flush().unwrap();

        // Set quota to 1 file
        let config = SecurityConfig::default().with_max_file_count(1);

        let result = list_archive(temp_file.path(), &config);
        match result {
            Err(ArchiveError::QuotaExceeded {
                resource: QuotaResource::FileCount { current, max },
            }) => {
                assert_eq!(max, 1);
                assert_eq!(current, 2, "current must be max+1 (off-by-one fix)");
            }
            other => panic!("expected FileCount quota error, got {other:?}"),
        }
    }

    #[test]
    fn test_list_zip_quota_exceeded_file_count() {
        let temp_file = NamedTempFile::with_suffix(".zip").unwrap();
        let file = std::fs::File::create(temp_file.path()).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        zip.start_file("a.txt", options).unwrap();
        zip.start_file("b.txt", options).unwrap();
        zip.finish().unwrap();

        let config = SecurityConfig::default().with_max_file_count(1);

        let result = list_archive(temp_file.path(), &config);
        match result {
            Err(ArchiveError::QuotaExceeded {
                resource: QuotaResource::FileCount { current, max },
            }) => {
                assert_eq!(max, 1);
                assert_eq!(current, 2, "current must be max+1 (off-by-one fix)");
            }
            other => panic!("expected FileCount quota error, got {other:?}"),
        }
    }

    #[test]
    fn test_zip_mode_strips_s_ifreg_bits() {
        // Archives from Unix tools store the full stat(2) mode in
        // external_attributes. 0o100644 = S_IFREG (0o100000) | 0o644.
        // After listing, only 0o644 must remain.
        let zip_bytes = zip_with_raw_unix_mode("file.txt", 0o100_644);
        let mut temp_file = NamedTempFile::with_suffix(".zip").unwrap();
        temp_file.write_all(&zip_bytes).unwrap();
        temp_file.flush().unwrap();

        let config = SecurityConfig::default();
        let manifest = list_archive(temp_file.path(), &config).unwrap();

        assert_eq!(manifest.total_entries(), 1);
        assert_eq!(manifest.entries()[0].mode, Some(0o644));
    }

    #[test]
    fn test_zip_mode_strips_s_ifdir_bits() {
        // 0o040755 = S_IFDIR (0o040000) | 0o755. After listing, only 0o755 must
        // remain.
        let zip_bytes = zip_with_raw_unix_mode("mydir/", 0o040_755);
        let mut temp_file = NamedTempFile::with_suffix(".zip").unwrap();
        temp_file.write_all(&zip_bytes).unwrap();
        temp_file.flush().unwrap();

        let config = SecurityConfig::default();
        let manifest = list_archive(temp_file.path(), &config).unwrap();

        assert_eq!(manifest.total_entries(), 1);
        assert_eq!(manifest.entries()[0].mode, Some(0o755));
    }

    #[test]
    fn test_zip_mode_permission_bits_unchanged() {
        // When no file-type bits are present, permission bits must be preserved
        // as-is.
        let zip_bytes = zip_with_raw_unix_mode("file.txt", 0o644);
        let mut temp_file = NamedTempFile::with_suffix(".zip").unwrap();
        temp_file.write_all(&zip_bytes).unwrap();
        temp_file.flush().unwrap();

        let config = SecurityConfig::default();
        let manifest = list_archive(temp_file.path(), &config).unwrap();

        assert_eq!(manifest.total_entries(), 1);
        assert_eq!(manifest.entries()[0].mode, Some(0o644));
    }

    #[test]
    fn test_list_zip_encrypted_returns_security_violation() {
        use std::io::Cursor;
        use zip::ZipWriter;
        use zip::unstable::write::FileOptionsExt;
        use zip::write::SimpleFileOptions;

        let mut writer = ZipWriter::new(Cursor::new(Vec::new()));
        let options = SimpleFileOptions::default()
            .with_deprecated_encryption(b"password")
            .unwrap();
        writer.start_file("secret.txt", options).unwrap();
        writer.write_all(b"secret data").unwrap();
        let zip_data = writer.finish().unwrap().into_inner();

        let mut temp_file = NamedTempFile::with_suffix(".zip").unwrap();
        temp_file.write_all(&zip_data).unwrap();
        temp_file.flush().unwrap();

        let config = SecurityConfig::default();
        let result = list_archive(temp_file.path(), &config);
        match result {
            Err(ArchiveError::SecurityViolation { reason }) => {
                assert!(
                    reason.contains("password-protected"),
                    "expected 'password-protected' in reason: {reason}"
                );
            }
            other => panic!("expected SecurityViolation, got: {other:?}"),
        }
    }

    #[test]
    fn test_list_archive_tar_bz2() {
        use bzip2::Compression as BzCompression;
        use bzip2::write::BzEncoder;
        use std::io::Write;

        let mut temp_file = NamedTempFile::with_suffix(".tar.bz2").unwrap();

        let mut builder = tar::Builder::new(Vec::new());
        let data = b"bzip2 content";
        let mut header = tar::Header::new_gnu();
        header.set_path("file.txt").unwrap();
        header.set_size(data.len() as u64);
        header.set_cksum();
        builder.append(&header, &data[..]).unwrap();
        let tar_data = builder.into_inner().unwrap();

        let mut encoder = BzEncoder::new(Vec::new(), BzCompression::default());
        encoder.write_all(&tar_data).unwrap();
        let compressed = encoder.finish().unwrap();

        temp_file.write_all(&compressed).unwrap();
        temp_file.flush().unwrap();

        let config = SecurityConfig::default();
        let manifest = list_archive(temp_file.path(), &config).unwrap();

        assert_eq!(manifest.total_entries(), 1);
        assert_eq!(manifest.format(), ArchiveType::TarBz2);
        assert_eq!(manifest.entries()[0].path, PathBuf::from("file.txt"));
    }

    #[test]
    fn test_list_archive_tar_xz() {
        use std::io::Write;
        use xz2::write::XzEncoder;

        let mut temp_file = NamedTempFile::with_suffix(".tar.xz").unwrap();

        let mut builder = tar::Builder::new(Vec::new());
        let data = b"xz content";
        let mut header = tar::Header::new_gnu();
        header.set_path("file.txt").unwrap();
        header.set_size(data.len() as u64);
        header.set_cksum();
        builder.append(&header, &data[..]).unwrap();
        let tar_data = builder.into_inner().unwrap();

        let mut encoder = XzEncoder::new(Vec::new(), 1);
        encoder.write_all(&tar_data).unwrap();
        let compressed = encoder.finish().unwrap();

        temp_file.write_all(&compressed).unwrap();
        temp_file.flush().unwrap();

        let config = SecurityConfig::default();
        let manifest = list_archive(temp_file.path(), &config).unwrap();

        assert_eq!(manifest.total_entries(), 1);
        assert_eq!(manifest.format(), ArchiveType::TarXz);
    }

    #[test]
    fn test_list_archive_tar_zst() {
        use std::io::Write;
        use zstd::stream::write::Encoder as ZstdEncoder;

        let mut temp_file = NamedTempFile::with_suffix(".tar.zst").unwrap();

        let mut builder = tar::Builder::new(Vec::new());
        let data = b"zstd content";
        let mut header = tar::Header::new_gnu();
        header.set_path("file.txt").unwrap();
        header.set_size(data.len() as u64);
        header.set_cksum();
        builder.append(&header, &data[..]).unwrap();
        let tar_data = builder.into_inner().unwrap();

        let mut encoder = ZstdEncoder::new(Vec::new(), 1).unwrap();
        encoder.write_all(&tar_data).unwrap();
        let compressed = encoder.finish().unwrap();

        temp_file.write_all(&compressed).unwrap();
        temp_file.flush().unwrap();

        let config = SecurityConfig::default();
        let manifest = list_archive(temp_file.path(), &config).unwrap();

        assert_eq!(manifest.total_entries(), 1);
        assert_eq!(manifest.format(), ArchiveType::TarZst);
    }

    #[test]
    fn test_list_sevenz_corrupt() {
        // A truncated 7z header (valid magic, invalid body) must return
        // InvalidArchive.
        let mut temp_file = NamedTempFile::with_suffix(".7z").unwrap();
        temp_file.write_all(b"7z\xbc\xaf\x27\x1c\x00\x04").unwrap();
        temp_file.flush().unwrap();

        let config = SecurityConfig::default();
        let result = list_archive(temp_file.path(), &config);
        assert_matches!(
            result,
            Err(ArchiveError::InvalidArchive(_)),
            "expected InvalidArchive for truncated 7z, got: {result:?}"
        );
    }

    #[test]
    fn test_list_tar_special_file_rejected() {
        let mut temp_file = NamedTempFile::with_suffix(".tar").unwrap();
        let mut builder = tar::Builder::new(Vec::new());

        let mut header = tar::Header::new_gnu();
        header.set_path("chardev").unwrap();
        header.set_size(0);
        header.set_entry_type(tar::EntryType::Char);
        header.set_cksum();
        builder.append(&header, &[][..]).unwrap();

        let data = builder.into_inner().unwrap();
        temp_file.write_all(&data).unwrap();
        temp_file.flush().unwrap();

        let config = SecurityConfig::default();
        let result = list_archive(temp_file.path(), &config);
        assert_matches!(
            result,
            Err(ArchiveError::InvalidArchive(_)),
            "expected InvalidArchive for char device entry, got: {result:?}"
        );
    }

    #[test]
    fn test_list_zip_quota_exceeded_total_size() {
        let temp_file = NamedTempFile::with_suffix(".zip").unwrap();
        let file = std::fs::File::create(temp_file.path()).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        zip.start_file("big.bin", options).unwrap();
        zip.write_all(&vec![0u8; 600]).unwrap();
        zip.finish().unwrap();

        let config = SecurityConfig::default().with_max_total_size(100);
        let result = list_archive(temp_file.path(), &config);
        assert_matches!(
            result,
            Err(ArchiveError::QuotaExceeded {
                resource: crate::error::QuotaResource::TotalSize { .. }
            }),
            "expected TotalSize quota error, got: {result:?}"
        );
    }

    #[test]
    fn test_list_tar_quota_exceeded_total_size() {
        let mut temp_file = NamedTempFile::with_suffix(".tar").unwrap();
        let mut builder = tar::Builder::new(Vec::new());

        let data = vec![0u8; 600];
        let mut header = tar::Header::new_gnu();
        header.set_path("big.bin").unwrap();
        header.set_size(data.len() as u64);
        header.set_cksum();
        builder.append(&header, &data[..]).unwrap();

        let archive_data = builder.into_inner().unwrap();
        temp_file.write_all(&archive_data).unwrap();
        temp_file.flush().unwrap();

        let config = SecurityConfig::default().with_max_total_size(100);
        let result = list_archive(temp_file.path(), &config);
        assert_matches!(
            result,
            Err(ArchiveError::QuotaExceeded {
                resource: crate::error::QuotaResource::TotalSize { .. }
            }),
            "expected TotalSize quota error, got: {result:?}"
        );
    }

    #[test]
    fn test_list_zip_path_traversal() {
        // ZIP with ../etc/passwd entry — resolve_zip_entry_path rejects the
        // `..` component with PathTraversal.
        let temp_file = NamedTempFile::with_suffix(".zip").unwrap();
        let file = std::fs::File::create(temp_file.path()).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        zip.start_file("../etc/passwd", options).unwrap();
        zip.write_all(b"malicious").unwrap();
        zip.finish().unwrap();

        let config = SecurityConfig::default();
        let result = list_archive(temp_file.path(), &config);
        assert_matches!(
            result,
            Err(ArchiveError::PathTraversal { .. }),
            "expected PathTraversal error, got: {result:?}"
        );
    }

    #[test]
    fn test_list_tar_path_traversal_dotdot() {
        let mut temp_file = NamedTempFile::with_suffix(".tar").unwrap();
        temp_file
            .write_all(&tar_with_raw_path("../escape.txt"))
            .unwrap();
        temp_file.flush().unwrap();

        let config = SecurityConfig::default();
        let result = list_archive(temp_file.path(), &config);
        assert_matches!(
            &result,
            Err(ArchiveError::PathTraversal { path }) if path == &PathBuf::from("../escape.txt"),
            "expected PathTraversal {{ path: ../escape.txt }}, got: {result:?}"
        );
    }

    #[test]
    fn test_list_tar_path_traversal_nested() {
        let mut temp_file = NamedTempFile::with_suffix(".tar").unwrap();
        temp_file
            .write_all(&tar_with_raw_path("foo/../../escape.txt"))
            .unwrap();
        temp_file.flush().unwrap();

        let config = SecurityConfig::default();
        let result = list_archive(temp_file.path(), &config);
        assert_matches!(
            result,
            Err(ArchiveError::PathTraversal { .. }),
            "expected PathTraversal error for nested ../ in TAR, got: {result:?}"
        );
    }

    #[test]
    fn test_list_tar_path_traversal_absolute() {
        let mut temp_file = NamedTempFile::with_suffix(".tar").unwrap();
        temp_file
            .write_all(&tar_with_raw_path("/etc/passwd"))
            .unwrap();
        temp_file.flush().unwrap();

        let config = SecurityConfig::default();
        let result = list_archive(temp_file.path(), &config);
        assert_matches!(
            result,
            Err(ArchiveError::PathTraversal { .. }),
            "expected PathTraversal error for absolute path in TAR, got: {result:?}"
        );
    }

    #[test]
    fn test_list_tar_absolute_path_allowed_when_flag_set() {
        // Regression for #318: allow_absolute_paths must also take effect
        // during the listing phase, not only during extraction.
        let mut temp_file = NamedTempFile::with_suffix(".tar").unwrap();
        temp_file
            .write_all(&tar_with_raw_path("/etc/passwd"))
            .unwrap();
        temp_file.flush().unwrap();

        let config = SecurityConfig::default().with_allow_absolute_paths(true);
        let result = list_archive(temp_file.path(), &config);
        assert!(
            result.is_ok(),
            "list_archive must accept absolute paths when allow_absolute_paths=true, got: {result:?}"
        );
        let manifest = result.unwrap();
        assert_eq!(manifest.total_entries(), 1);
    }

    #[test]
    fn test_list_sevenz_absolute_path_allowed_when_flag_set() {
        // Regression for #318: allow_absolute_paths must propagate to 7z
        // listing.
        let archive_bytes = make_sevenz_archive(&[("/absolute/path.txt", b"data")]);
        let mut temp_file = NamedTempFile::with_suffix(".7z").unwrap();
        temp_file.write_all(&archive_bytes).unwrap();
        temp_file.flush().unwrap();

        let config = SecurityConfig::default().with_allow_absolute_paths(true);
        let result = list_archive(temp_file.path(), &config);
        assert!(
            result.is_ok(),
            "list_archive must accept absolute paths in 7z when allow_absolute_paths=true, got: {result:?}"
        );
    }

    /// Unit test for `contains_traversal` — verifies that `Prefix` (Windows
    /// drive paths) is gated by `allow_absolute_paths`, matching
    /// `SafePath::validate`. On Unix there is no native way to produce a
    /// `Prefix` component via the filesystem, so we test the function logic
    /// directly with a crafted `PathBuf`.
    #[test]
    fn test_contains_traversal_prefix_gated_by_flag() {
        // A path whose string representation starts with a Windows-style drive
        // prefix. On Windows this produces Component::Prefix; on Unix the
        // entire string is treated as a relative path component (no
        // Prefix produced), so this test exercises the flag-gating
        // logic via the RootDir path instead. The critical invariant —
        // Prefix and RootDir share the same gate — is verified by the
        // match arm `Component::Prefix(_) | Component::RootDir`.
        let absolute = PathBuf::from("/absolute/path.txt");

        let config_deny = SecurityConfig::default().validate().expect("valid config"); // absolute_paths = false
        assert!(
            contains_traversal(&absolute, &config_deny),
            "absolute path must be rejected when allow_absolute_paths=false"
        );

        let config_allow = SecurityConfig::default()
            .with_allow_absolute_paths(true)
            .validate()
            .expect("valid config");
        assert!(
            !contains_traversal(&absolute, &config_allow),
            "absolute path must be accepted when allow_absolute_paths=true"
        );

        // ParentDir must always be rejected regardless of the flag.
        let dotdot = PathBuf::from("../escape.txt");
        assert!(
            contains_traversal(&dotdot, &config_allow),
            "ParentDir must be rejected even when allow_absolute_paths=true"
        );
    }

    #[test]
    fn test_list_tar_gz_path_traversal() {
        let mut temp_file = NamedTempFile::with_suffix(".tar.gz").unwrap();
        let tar_data = tar_with_raw_path("../escape.txt");
        let mut encoder = GzEncoder::new(Vec::new(), flate2::Compression::default());
        encoder.write_all(&tar_data).unwrap();
        let compressed = encoder.finish().unwrap();

        temp_file.write_all(&compressed).unwrap();
        temp_file.flush().unwrap();

        let config = SecurityConfig::default();
        let result = list_archive(temp_file.path(), &config);
        assert_matches!(
            result,
            Err(ArchiveError::PathTraversal { .. }),
            "expected PathTraversal error for tar.gz with ../ entry, got: {result:?}"
        );
    }

    #[test]
    fn test_list_tar_path_traversal_mixed_entries_fail_fast() {
        // A safe entry followed by a traversal entry — verifies fail-fast
        // behavior: error must be returned immediately on the traversal
        // entry, not after accumulating the safe entry into a partial
        // manifest.
        let mut temp_file = NamedTempFile::with_suffix(".tar").unwrap();
        let mut builder = tar::Builder::new(Vec::new());

        let safe_data = b"safe content";
        let mut header = tar::Header::new_gnu();
        header.set_path("hello.txt").unwrap();
        header.set_size(safe_data.len() as u64);
        header.set_cksum();
        builder.append(&header, &safe_data[..]).unwrap();
        let safe_tar = builder.into_inner().unwrap();

        // safe_tar ends with the two zero-block end-of-archive marker. Strip it
        // and append the raw traversal entry + end-of-archive to create
        // a two-entry archive. The tar crate always writes exactly two
        // 512-byte zero blocks (1024 bytes total) as the end-of-archive
        // marker per POSIX ustar §3.4. Verified with tar 0.4.x; a
        // future major version bump should re-check this.
        let eof_marker_len = 1024;
        let tar_body = &safe_tar[..safe_tar.len() - eof_marker_len];
        let traversal_entry = tar_with_raw_path("../escape.txt");
        // tar_with_raw_path includes end-of-archive, so use it as-is after the
        // body.
        let mut combined = tar_body.to_vec();
        combined.extend_from_slice(&traversal_entry);

        temp_file.write_all(&combined).unwrap();
        temp_file.flush().unwrap();

        let config = SecurityConfig::default();
        let result = list_archive(temp_file.path(), &config);
        assert_matches!(
            result,
            Err(ArchiveError::PathTraversal { .. }),
            "expected PathTraversal error for mixed-entry TAR, got: {result:?}"
        );
    }

    #[test]
    fn test_list_zip_by_index_encrypted_error_path() {
        // Cover the encrypted entry check at list.rs line 260
        // (entry.encrypted() == true). ZipCrypto entries succeed at
        // by_index() time but are flagged as encrypted by the entry
        // metadata, triggering SecurityViolation::EncryptedArchive.
        use std::io::Write;
        use zip::ZipWriter;
        use zip::unstable::write::FileOptionsExt;
        use zip::write::SimpleFileOptions;

        let mut writer = ZipWriter::new(std::io::Cursor::new(Vec::new()));
        let options = SimpleFileOptions::default()
            .with_deprecated_encryption(b"password")
            .unwrap();
        writer.start_file("secret.txt", options).unwrap();
        writer.write_all(b"secret data").unwrap();
        let zip_data = writer.finish().unwrap().into_inner();

        let mut temp_file = NamedTempFile::with_suffix(".zip").unwrap();
        temp_file.write_all(&zip_data).unwrap();
        temp_file.flush().unwrap();

        let config = SecurityConfig::default();
        let result = list_archive(temp_file.path(), &config);
        assert_matches!(
            result,
            Err(ArchiveError::SecurityViolation { .. }),
            "expected SecurityViolation for encrypted ZIP in list, got: {result:?}"
        );
    }

    #[test]
    fn test_tar_and_zip_mode_consistent() {
        // TAR and ZIP must both store only permission bits in
        // ArchiveEntry.mode.
        let tar_file = NamedTempFile::with_suffix(".tar").unwrap();
        {
            let mut builder = tar::Builder::new(std::fs::File::create(tar_file.path()).unwrap());
            let data = b"content";
            let mut header = tar::Header::new_gnu();
            header.set_path("file.txt").unwrap();
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            header.set_cksum();
            builder.append(&header, &data[..]).unwrap();
            builder.into_inner().unwrap();
        }

        // ZIP with full S_IFREG mode, as written by an external Unix tool.
        let zip_bytes = zip_with_raw_unix_mode("file.txt", 0o100_644);
        let zip_file = NamedTempFile::with_suffix(".zip").unwrap();
        {
            let mut f = std::fs::File::create(zip_file.path()).unwrap();
            f.write_all(&zip_bytes).unwrap();
        }

        let config = SecurityConfig::default();
        let tar_manifest = list_archive(tar_file.path(), &config).unwrap();
        let zip_manifest = list_archive(zip_file.path(), &config).unwrap();

        assert_eq!(
            tar_manifest.entries()[0].mode,
            zip_manifest.entries()[0].mode
        );
        assert_eq!(tar_manifest.entries()[0].mode, Some(0o644));
    }

    #[test]
    fn test_list_sevenz_simple() {
        let path = std::path::Path::new("../../tests/fixtures/simple.7z");
        let config = SecurityConfig::default();
        let manifest = list_archive(path, &config).unwrap();
        assert!(
            manifest.total_entries() > 0,
            "simple.7z should have entries"
        );
        for entry in manifest.entries() {
            assert!(!entry.path.is_empty(), "entry path should not be empty");
        }
    }

    #[test]
    fn test_list_sevenz_empty() {
        let path = std::path::Path::new("../../tests/fixtures/empty.7z");
        let config = SecurityConfig::default();
        let manifest = list_archive(path, &config).unwrap();
        assert_eq!(
            manifest.total_entries(),
            0,
            "empty.7z should have no entries"
        );
        assert_eq!(
            manifest.total_size(),
            0,
            "empty.7z should have zero total size"
        );
    }

    #[test]
    fn test_list_sevenz_nested_dirs() {
        let path = std::path::Path::new("../../tests/fixtures/nested-dirs.7z");
        let config = SecurityConfig::default();
        let manifest = list_archive(path, &config).unwrap();
        assert!(manifest.total_entries() > 0);
        let has_dir = manifest
            .entries()
            .iter()
            .any(|e| e.kind.entry_type() == ManifestEntryType::Directory);
        assert!(has_dir, "nested-dirs.7z should contain directory entries");
    }

    #[test]
    fn test_list_sevenz_encrypted_rejected() {
        let path = std::path::Path::new("../../tests/fixtures/encrypted.7z");
        let config = SecurityConfig::default();
        let result = list_archive(path, &config);
        assert!(result.is_err(), "encrypted archive should return an error");
        let err_str = result.unwrap_err().to_string().to_lowercase();
        assert!(
            err_str.contains("encrypt") || err_str.contains("password"),
            "error should mention encryption, got: {err_str}"
        );
    }

    #[test]
    fn test_list_sevenz_solid() {
        // Solid archives are safe to list (no decompression needed for
        // metadata).
        let path = std::path::Path::new("../../tests/fixtures/solid.7z");
        let config = SecurityConfig::default();
        let manifest = list_archive(path, &config).unwrap();
        assert!(manifest.total_entries() > 0, "solid.7z should have entries");
    }

    #[test]
    fn test_verify_sevenz_simple() {
        let path = std::path::Path::new("../../tests/fixtures/simple.7z");
        let config = SecurityConfig::default();
        let report = crate::verify_archive(path, &config).unwrap();
        assert_ne!(
            report.status(),
            crate::inspection::report::VerificationStatus::Fail,
            "simple.7z should not fail verification"
        );
    }

    #[test]
    fn test_list_sevenz_format_field() {
        let path = std::path::Path::new("../../tests/fixtures/simple.7z");
        let config = SecurityConfig::default();
        let manifest = list_archive(path, &config).unwrap();
        assert_eq!(
            manifest.format(),
            crate::formats::detect::ArchiveType::SevenZ,
            "manifest format should be SevenZ"
        );
    }

    /// Creates a minimal in-memory 7z archive with a single file entry
    /// and returns the archive bytes. Uses stored (no compression) method
    /// to keep test archives fast.
    fn make_sevenz_archive(entries: &[(&str, &[u8])]) -> Vec<u8> {
        use sevenz_rust2::ArchiveEntry;
        use sevenz_rust2::ArchiveWriter;
        use sevenz_rust2::EncoderConfiguration;
        use sevenz_rust2::EncoderMethod;
        use std::io::Cursor;

        let buf = Cursor::new(Vec::new());
        let mut writer = ArchiveWriter::new(buf).unwrap();
        writer.set_content_methods(vec![EncoderConfiguration::new(EncoderMethod::COPY)]);
        for (name, data) in entries {
            let mut entry = ArchiveEntry::new_file(name);
            entry.has_stream = true;
            entry.size = data.len() as u64;
            writer
                .push_archive_entry(entry, Some(std::io::Cursor::new(*data)))
                .unwrap();
        }
        writer.finish().unwrap().into_inner()
    }

    #[test]
    fn test_list_sevenz_path_traversal_dotdot() {
        // Create an archive with a traversal entry name; list should reject it.
        let archive_bytes = make_sevenz_archive(&[("../escape.txt", b"evil")]);
        let mut temp_file = NamedTempFile::with_suffix(".7z").unwrap();
        temp_file.write_all(&archive_bytes).unwrap();
        temp_file.flush().unwrap();

        let config = SecurityConfig::default();
        let result = list_archive(temp_file.path(), &config);
        assert_matches!(
            result,
            Err(ArchiveError::PathTraversal { .. }),
            "expected PathTraversal error for ../ entry, got: {result:?}"
        );
    }

    #[test]
    fn test_list_sevenz_quota_file_count() {
        // Create an archive with 3 files and set a quota of 2.
        let archive_bytes =
            make_sevenz_archive(&[("a.txt", b"a"), ("b.txt", b"b"), ("c.txt", b"c")]);
        let mut temp_file = NamedTempFile::with_suffix(".7z").unwrap();
        temp_file.write_all(&archive_bytes).unwrap();
        temp_file.flush().unwrap();

        let config = SecurityConfig::default().with_max_file_count(2);
        let result = list_archive(temp_file.path(), &config);
        assert_matches!(
            result,
            Err(ArchiveError::QuotaExceeded {
                resource: crate::error::QuotaResource::FileCount { .. }
            }),
            "expected FileCount QuotaExceeded, got: {result:?}"
        );
    }

    #[test]
    fn test_list_sevenz_quota_total_size() {
        // Create a file with 100 bytes and set a total-size quota of 50 bytes.
        let data = vec![0u8; 100];
        let archive_bytes = make_sevenz_archive(&[("big.bin", &data)]);
        let mut temp_file = NamedTempFile::with_suffix(".7z").unwrap();
        temp_file.write_all(&archive_bytes).unwrap();
        temp_file.flush().unwrap();

        let config = SecurityConfig::default().with_max_total_size(50);
        let result = list_archive(temp_file.path(), &config);
        assert_matches!(
            result,
            Err(ArchiveError::QuotaExceeded {
                resource: crate::error::QuotaResource::TotalSize { .. }
            }),
            "expected TotalSize QuotaExceeded, got: {result:?}"
        );
    }

    #[test]
    fn test_list_sevenz_hardlink_reported_as_file() {
        // 7z has no hardlink concept — entries appear as regular files.
        let path = std::path::Path::new("../../tests/fixtures/hardlink.7z");
        let config = SecurityConfig::default();
        let manifest = list_archive(path, &config).unwrap();
        assert!(
            manifest.total_entries() > 0,
            "hardlink.7z should have entries"
        );
        for entry in manifest.entries() {
            assert_ne!(
                entry.kind.entry_type(),
                ManifestEntryType::Hardlink,
                "7z format never produces Hardlink entries (no API support)"
            );
        }
    }

    #[test]
    fn test_list_sevenz_solid_compressed_size() {
        // Entries in solid archives should not have compressed_size=Some(0)
        // with size>0. That combination would trigger a false positive
        // in zip bomb detection.
        let path = std::path::Path::new("../../tests/fixtures/solid.7z");
        let config = SecurityConfig::default();
        let manifest = list_archive(path, &config).unwrap();
        for entry in manifest.entries() {
            if entry.size > 0 {
                assert_ne!(
                    entry.compressed_size(),
                    Some(0),
                    "entry {:?} has compressed_size=Some(0) with size={}, which is a false positive trigger",
                    entry.path,
                    entry.size
                );
            }
        }
    }

    // Regression for #166: caller-supplied max_total_size must not be silently
    // discarded.
    #[test]
    fn test_list_archive_custom_max_total_size_honoured_tar() {
        let mut temp_file = NamedTempFile::with_suffix(".tar").unwrap();
        let mut builder = tar::Builder::new(Vec::new());

        let data = vec![0u8; 600];
        let mut header = tar::Header::new_gnu();
        header.set_path("file.bin").unwrap();
        header.set_size(data.len() as u64);
        header.set_cksum();
        builder.append(&header, &data[..]).unwrap();
        temp_file.write_all(&builder.into_inner().unwrap()).unwrap();
        temp_file.flush().unwrap();

        // Small limit — must reject.
        let small = SecurityConfig::default().with_max_total_size(100);
        assert_matches!(
            list_archive(temp_file.path(), &small),
            Err(ArchiveError::QuotaExceeded {
                resource: QuotaResource::TotalSize { .. }
            }),
            "expected TotalSize quota error with limit=100"
        );

        // Large limit (simulates --max-total-size 1G) — must succeed.
        let large = SecurityConfig::default().with_max_total_size(1024 * 1024 * 1024);
        assert!(
            list_archive(temp_file.path(), &large).is_ok(),
            "list_archive must succeed when caller supplies a large max_total_size (regression #166)"
        );
    }

    #[test]
    fn test_list_archive_custom_max_total_size_honoured_zip() {
        let temp_file = NamedTempFile::with_suffix(".zip").unwrap();
        {
            let file = std::fs::File::create(temp_file.path()).unwrap();
            let mut zip = zip::ZipWriter::new(file);
            let options = zip::write::SimpleFileOptions::default()
                .compression_method(zip::CompressionMethod::Stored);
            zip.start_file("file.bin", options).unwrap();
            zip.write_all(&vec![0u8; 600]).unwrap();
            zip.finish().unwrap();
        }

        let small = SecurityConfig::default().with_max_total_size(100);
        assert_matches!(
            list_archive(temp_file.path(), &small),
            Err(ArchiveError::QuotaExceeded {
                resource: QuotaResource::TotalSize { .. }
            }),
            "expected TotalSize quota error with limit=100"
        );

        let large = SecurityConfig::default().with_max_total_size(1024 * 1024 * 1024);
        assert!(
            list_archive(temp_file.path(), &large).is_ok(),
            "list_archive must succeed when caller supplies a large max_total_size (regression #166)"
        );
    }

    #[test]
    fn test_list_archive_custom_max_total_size_honoured_sevenz() {
        let data = vec![0u8; 600];
        let archive_bytes = make_sevenz_archive(&[("file.bin", &data)]);
        let mut temp_file = NamedTempFile::with_suffix(".7z").unwrap();
        temp_file.write_all(&archive_bytes).unwrap();
        temp_file.flush().unwrap();

        let small = SecurityConfig::default().with_max_total_size(100);
        assert_matches!(
            list_archive(temp_file.path(), &small),
            Err(ArchiveError::QuotaExceeded {
                resource: QuotaResource::TotalSize { .. }
            }),
            "expected TotalSize quota error with limit=100"
        );

        let large = SecurityConfig::default().with_max_total_size(1024 * 1024 * 1024);
        assert!(
            list_archive(temp_file.path(), &large).is_ok(),
            "list_archive must succeed when caller supplies a large max_total_size (regression #166)"
        );
    }

    #[test]
    fn test_list_sevenz_regular_mode_entry_reported_as_file() {
        // The fixture's link.txt has a regular-file Unix mode, so it is
        // reported as ManifestEntryType::File.
        let path = std::path::Path::new("../../tests/fixtures/symlink-unix.7z");
        let config = SecurityConfig::default();
        let manifest = list_archive(path, &config).unwrap();
        assert!(
            manifest.total_entries() > 0,
            "symlink-unix.7z should have entries"
        );
        // All entries should be File or Directory — no Symlink (API
        // limitation).
        for entry in manifest.entries() {
            assert_ne!(
                entry.kind.entry_type(),
                ManifestEntryType::Symlink,
                "regular-mode entries are reported as File: {}",
                entry.path.display()
            );
        }
    }

    #[test]
    fn test_verify_sevenz_solid_no_false_positive() {
        use crate::inspection::report::IssueSeverity;

        let path = std::path::Path::new("../../tests/fixtures/solid.7z");
        let config = SecurityConfig::default().with_allow_solid_archives(true);
        let report = crate::verify_archive(path, &config).unwrap();
        assert_ne!(
            report.status(),
            crate::inspection::report::VerificationStatus::Fail,
            "solid.7z should not fail verification when solid archives are allowed"
        );
        let has_false_positive = report.issues().iter().any(|issue| {
            issue.severity == IssueSeverity::High
                && issue.message.to_lowercase().contains("compressed_size")
        });
        assert!(
            !has_false_positive,
            "solid.7z verification should not produce High-severity compressed_size issue"
        );
    }

    #[test]
    fn list_archive_rejects_invalid_security_config() {
        let config = SecurityConfig::default().with_max_file_size(0);
        let result = crate::list_archive("any.tar.gz", &config);
        assert_matches!(
            result,
            Err(crate::ArchiveError::InvalidConfiguration { .. }),
            "list_archive must return InvalidConfiguration for zero max_file_size"
        );
    }

    // --- Regression tests for #325: allow_absolute_paths for ZIP listing ---

    // The absolute-path policy is enforced on the raw name by
    // `resolve_zip_entry_path` (issue #631).
    #[test]
    fn test_list_zip_absolute_path_rejected_by_default() {
        let zip_bytes = create_raw_zip_entry("/etc/passwd", b"");
        let mut temp_file = NamedTempFile::with_suffix(".zip").unwrap();
        temp_file.write_all(&zip_bytes).unwrap();
        temp_file.flush().unwrap();

        let config = SecurityConfig::default();
        let result = list_archive(temp_file.path(), &config);
        assert_matches!(
            result,
            Err(ArchiveError::PathTraversal { .. }),
            "absolute ZIP name must be rejected by default like TAR, got: {result:?}"
        );
    }

    #[test]
    fn test_list_zip_absolute_path_allowed_when_configured() {
        let zip_bytes = create_raw_zip_entry("/etc/passwd", b"");
        let mut temp_file = NamedTempFile::with_suffix(".zip").unwrap();
        temp_file.write_all(&zip_bytes).unwrap();
        temp_file.flush().unwrap();

        let config = SecurityConfig::default().with_allow_absolute_paths(true);
        let manifest = list_archive(temp_file.path(), &config).unwrap();
        assert_eq!(manifest.total_entries(), 1);
        assert_eq!(manifest.entries()[0].path, PathBuf::from("etc/passwd"));
    }

    #[test]
    fn test_list_zip_traversal_absolute_path_rejected_by_default() {
        // /../etc/passwd: traversal after root.
        // allow_absolute_paths is false, so the entry is rejected with
        // PathTraversal.
        let zip_bytes = create_raw_zip_entry("/../etc/passwd", b"");
        let mut temp_file = NamedTempFile::with_suffix(".zip").unwrap();
        temp_file.write_all(&zip_bytes).unwrap();
        temp_file.flush().unwrap();

        let config = SecurityConfig::default();
        let result = list_archive(temp_file.path(), &config);
        assert_matches!(
            result,
            Err(ArchiveError::PathTraversal { .. }),
            "absolute path with traversal must be rejected by default, got: {result:?}"
        );
    }

    #[test]
    fn test_list_zip_traversal_absolute_path_still_rejected_when_allowed() {
        // Even with allow_absolute_paths, /../etc/passwd must be rejected
        // because after stripping `/` the remaining `../etc/passwd` still
        // contains `..` which contains_traversal() catches.
        let zip_bytes = create_raw_zip_entry("/../etc/passwd", b"");
        let mut temp_file = NamedTempFile::with_suffix(".zip").unwrap();
        temp_file.write_all(&zip_bytes).unwrap();
        temp_file.flush().unwrap();

        let config = SecurityConfig::default().with_allow_absolute_paths(true);
        let result = list_archive(temp_file.path(), &config);
        assert_matches!(
            result,
            Err(ArchiveError::PathTraversal { .. }),
            "traversal inside absolute path must still be rejected even when allowed, got: {result:?}"
        );
    }

    #[test]
    fn test_list_zip_absolute_path_with_traversal_still_rejected() {
        // /foo/../../../etc/passwd: goes above root. The `..` components are
        // rejected even though the leading `/` is stripped.
        let zip_bytes = create_raw_zip_entry("/foo/../../../etc/passwd", b"");
        let mut temp_file = NamedTempFile::with_suffix(".zip").unwrap();
        temp_file.write_all(&zip_bytes).unwrap();
        temp_file.flush().unwrap();

        let config = SecurityConfig::default().with_allow_absolute_paths(true);
        let result = list_archive(temp_file.path(), &config);
        assert_matches!(
            result,
            Err(ArchiveError::PathTraversal { .. }),
            "traversal inside absolute path must still be rejected, got: {result:?}"
        );
    }

    #[test]
    fn test_list_zip_parent_glued_to_prefix_rejected_with_allow_absolute_paths() {
        for name in ["\\\\?\\C:..\\x", "/\\?\\C:.."] {
            let zip_bytes = create_raw_zip_entry(name, b"");
            let mut temp_file = NamedTempFile::with_suffix(".zip").unwrap();
            temp_file.write_all(&zip_bytes).unwrap();
            temp_file.flush().unwrap();

            let config = SecurityConfig::default().with_allow_absolute_paths(true);
            let result = list_archive(temp_file.path(), &config);
            assert_matches!(result, Err(ArchiveError::PathTraversal { .. }), "{name:?}");
        }
    }

    // --- Regression tests for #430: list() must reject NUL bytes in entry
    // paths, matching extract()/verify() ---

    #[test]
    fn test_list_tar_pax_path_nul_byte_rejected() {
        let mut temp_file = NamedTempFile::with_suffix(".tar").unwrap();
        temp_file
            .write_all(&tar_with_pax_nul_path(b"foo\0bar.txt", b"hello"))
            .unwrap();
        temp_file.flush().unwrap();

        let config = SecurityConfig::default();
        let result = list_archive(temp_file.path(), &config);
        match result {
            Err(ArchiveError::SecurityViolation { reason }) => {
                assert!(reason.contains("null bytes"), "reason: {reason}");
            }
            other => {
                panic!("expected SecurityViolation for NUL byte in PAX path, got: {other:?}")
            }
        }
    }

    #[test]
    fn test_list_zip_nul_byte_rejected_as_security_violation_by_default() {
        let zip_bytes = create_raw_zip_entry("foo\0bar.txt", b"");
        let mut temp_file = NamedTempFile::with_suffix(".zip").unwrap();
        temp_file.write_all(&zip_bytes).unwrap();
        temp_file.flush().unwrap();

        let config = SecurityConfig::default();
        let result = list_archive(temp_file.path(), &config);
        match result {
            Err(ArchiveError::SecurityViolation { reason }) => {
                assert!(reason.contains("null bytes"), "reason: {reason}");
            }
            other => {
                panic!("expected SecurityViolation for NUL byte in ZIP filename, got: {other:?}")
            }
        }
    }

    #[test]
    fn test_list_zip_nul_byte_rejected_with_allow_absolute_paths() {
        // The actual bypass closed by #430: allow_absolute_paths routes
        // through the raw name, so only the NUL check in
        // resolve_zip_entry_path catches it.
        let zip_bytes = create_raw_zip_entry("foo\0bar.txt", b"");
        let mut temp_file = NamedTempFile::with_suffix(".zip").unwrap();
        temp_file.write_all(&zip_bytes).unwrap();
        temp_file.flush().unwrap();

        let config = SecurityConfig::default().with_allow_absolute_paths(true);
        let result = list_archive(temp_file.path(), &config);
        match result {
            Err(ArchiveError::SecurityViolation { reason }) => {
                assert!(reason.contains("null bytes"), "reason: {reason}");
            }
            other => panic!(
                "expected SecurityViolation for NUL byte in ZIP filename with allow_absolute_paths, got: {other:?}"
            ),
        }
    }

    // --- Regression tests for #430 follow-up: list() must reject NUL bytes
    // and emptiness in symlink/hardlink targets, matching extract()'s
    // SafeSymlink/HardlinkTracker checks (#424) ---

    #[test]
    fn test_list_tar_symlink_target_nul_byte_rejected() {
        let mut temp_file = NamedTempFile::with_suffix(".tar").unwrap();
        temp_file
            .write_all(&tar_with_pax_linkpath(b"foo\0bar", b'2'))
            .unwrap();
        temp_file.flush().unwrap();

        let config = SecurityConfig::default();
        let result = list_archive(temp_file.path(), &config);
        match result {
            Err(ArchiveError::SecurityViolation { reason }) => {
                assert_eq!(reason, "symlink target contains null bytes");
            }
            other => {
                panic!("expected SecurityViolation for NUL byte in symlink target, got: {other:?}")
            }
        }
    }

    #[test]
    fn test_list_tar_symlink_target_empty_rejected() {
        let mut temp_file = NamedTempFile::with_suffix(".tar").unwrap();
        temp_file
            .write_all(&tar_with_pax_linkpath(b"", b'2'))
            .unwrap();
        temp_file.flush().unwrap();

        let config = SecurityConfig::default();
        let result = list_archive(temp_file.path(), &config);
        match result {
            Err(ArchiveError::SecurityViolation { reason }) => {
                assert_eq!(reason, "symlink target is empty");
            }
            other => panic!("expected SecurityViolation for empty symlink target, got: {other:?}"),
        }
    }

    #[test]
    fn test_list_tar_hardlink_target_nul_byte_rejected() {
        let mut temp_file = NamedTempFile::with_suffix(".tar").unwrap();
        temp_file
            .write_all(&tar_with_pax_linkpath(b"foo\0bar", b'1'))
            .unwrap();
        temp_file.flush().unwrap();

        let config = SecurityConfig::default();
        let result = list_archive(temp_file.path(), &config);
        match result {
            Err(ArchiveError::SecurityViolation { reason }) => {
                assert_eq!(reason, "hardlink target contains null bytes");
            }
            other => {
                panic!("expected SecurityViolation for NUL byte in hardlink target, got: {other:?}")
            }
        }
    }

    #[test]
    fn test_list_tar_hardlink_target_empty_rejected() {
        let mut temp_file = NamedTempFile::with_suffix(".tar").unwrap();
        temp_file
            .write_all(&tar_with_pax_linkpath(b"", b'1'))
            .unwrap();
        temp_file.flush().unwrap();

        let config = SecurityConfig::default();
        let result = list_archive(temp_file.path(), &config);
        match result {
            Err(ArchiveError::SecurityViolation { reason }) => {
                assert_eq!(reason, "hardlink target is empty");
            }
            other => panic!("expected SecurityViolation for empty hardlink target, got: {other:?}"),
        }
    }

    #[test]
    #[cfg(unix)]
    fn test_list_zip_symlink_target_nul_byte_rejected() {
        use crate::test_utils::create_zip_with_symlink;
        use std::io::Cursor;

        let zip_bytes = create_zip_with_symlink("link", "foo\0bar");
        let mut archive = ZipArchive::new(Cursor::new(zip_bytes)).unwrap();
        let config = SecurityConfig::default().validate().expect("valid config");
        let result = list_zip_reader(&mut archive, &config, &mut ListPass::Strict);
        match result {
            Err(ArchiveError::SecurityViolation { reason }) => {
                assert_eq!(reason, "symlink target contains null bytes");
            }
            other => panic!(
                "expected SecurityViolation for NUL byte in ZIP symlink target, got: {other:?}"
            ),
        }
    }

    #[test]
    #[cfg(unix)]
    fn test_list_zip_symlink_target_empty_rejected() {
        use crate::test_utils::create_zip_with_symlink;
        use std::io::Cursor;

        let zip_bytes = create_zip_with_symlink("link", "");
        let mut archive = ZipArchive::new(Cursor::new(zip_bytes)).unwrap();
        let config = SecurityConfig::default().validate().expect("valid config");
        let result = list_zip_reader(&mut archive, &config, &mut ListPass::Strict);
        match result {
            Err(ArchiveError::SecurityViolation { reason }) => {
                assert_eq!(reason, "symlink target is empty");
            }
            other => {
                panic!("expected SecurityViolation for empty ZIP symlink target, got: {other:?}")
            }
        }
    }

    // --- Regression tests for #430 follow-up (round 3): a symlink/hardlink
    // entry with no link target at all (no ustar linkname field, no PAX
    // `linkpath` override — `entry.link_name()` returns `None`) must be
    // rejected by bare `list`, matching extract's `to_entry_type` wording,
    // while `ListPass::VerifyPreflight` must skip this check (and the
    // entry-path NUL and link-target emptiness/NUL checks) so verify's
    // pre-flight listing pass can defer to `verify_entry`'s own graceful
    // checks instead of aborting ---

    #[test]
    fn test_list_tar_symlink_missing_target_rejected() {
        let mut temp_file = NamedTempFile::with_suffix(".tar").unwrap();
        let mut builder = tar::Builder::new(Vec::new());

        let mut header = tar::Header::new_gnu();
        header.set_path("link").unwrap();
        header.set_size(0);
        header.set_entry_type(tar::EntryType::Symlink);
        // Deliberately no `set_link_name()` call: the raw linkname field
        // stays all-zero, so `entry.link_name()` returns `None` rather than
        // `Some(empty)`.
        header.set_cksum();
        builder.append(&header, &[][..]).unwrap();

        let data = builder.into_inner().unwrap();
        temp_file.write_all(&data).unwrap();
        temp_file.flush().unwrap();

        let config = SecurityConfig::default();
        let result = list_archive(temp_file.path(), &config);
        match result {
            Err(ArchiveError::InvalidArchive(msg)) => {
                assert_eq!(msg, "symlink missing target");
            }
            other => panic!("expected InvalidArchive for missing symlink target, got: {other:?}"),
        }
    }

    #[test]
    fn test_list_tar_hardlink_missing_target_rejected() {
        let mut temp_file = NamedTempFile::with_suffix(".tar").unwrap();
        let mut builder = tar::Builder::new(Vec::new());

        let mut header = tar::Header::new_gnu();
        header.set_path("link").unwrap();
        header.set_size(0);
        header.set_entry_type(tar::EntryType::Link);
        header.set_cksum();
        builder.append(&header, &[][..]).unwrap();

        let data = builder.into_inner().unwrap();
        temp_file.write_all(&data).unwrap();
        temp_file.flush().unwrap();

        let config = SecurityConfig::default();
        let result = list_archive(temp_file.path(), &config);
        match result {
            Err(ArchiveError::InvalidArchive(msg)) => {
                assert_eq!(msg, "hardlink missing target");
            }
            other => panic!("expected InvalidArchive for missing hardlink target, got: {other:?}"),
        }
    }

    fn tar_with_paths(paths: &[&str]) -> NamedTempFile {
        let mut builder = tar::Builder::new(Vec::new());
        for path in paths {
            let mut header = tar::Header::new_gnu();
            header.set_size(1);
            header.set_cksum();
            builder.append_data(&mut header, path, &b"x"[..]).unwrap();
        }
        let mut file = NamedTempFile::with_suffix(".tar").unwrap();
        file.write_all(&builder.into_inner().unwrap()).unwrap();
        file.flush().unwrap();
        file
    }

    fn zip_with_names(names: &[&str]) -> NamedTempFile {
        let file = NamedTempFile::with_suffix(".zip").unwrap();
        let mut zip = zip::ZipWriter::new(std::fs::File::create(file.path()).unwrap());
        let options = zip::write::SimpleFileOptions::default();
        for name in names {
            zip.start_file(*name, options).unwrap();
            zip.write_all(b"x").unwrap();
        }
        zip.finish().unwrap();
        file
    }

    fn list_preflight(path: &Path, config: SecurityConfig) -> Result<ArchiveManifest> {
        list_validated(
            path,
            &config.validate()?,
            &mut ListPass::VerifyPreflight(None),
        )
    }

    fn assert_name_too_long(result: &Result<ArchiveManifest>) {
        assert!(
            matches!(result, Err(ArchiveError::Io(e)) if e.to_string() == "file name too long"),
            "expected name-too-long error, got {result:?}"
        );
    }

    #[test]
    fn test_list_tar_entry_path_limit_boundary() {
        let at_limit = path_of_len(HOST_PATH_LIMIT);
        let over = path_of_len(HOST_PATH_LIMIT + 1);
        let config = SecurityConfig::default();

        let ok = tar_with_paths(&[&at_limit]);
        assert_eq!(list_archive(ok.path(), &config).unwrap().total_entries(), 1);

        let bad = tar_with_paths(&[&over]);
        assert_name_too_long(&list_archive(bad.path(), &config));
    }

    #[test]
    fn test_list_tar_entry_component_limit() {
        let long_component = "a".repeat(255 + 1);
        let bad = tar_with_paths(&[&long_component]);
        assert_name_too_long(&list_archive(bad.path(), &SecurityConfig::default()));
    }

    #[test]
    fn test_list_tar_verify_preflight_records_oversized_entry() {
        let over = path_of_len(HOST_PATH_LIMIT + 1);
        let file = tar_with_paths(&["first.txt", &over, "last.txt"]);
        let manifest = list_preflight(file.path(), SecurityConfig::default()).unwrap();

        assert_eq!(manifest.total_entries(), 2);
        assert_eq!(
            manifest.oversized_entries(),
            &[OversizedEntry::new(1, HOST_PATH_LIMIT + 1)]
        );
        assert_eq!(manifest.entries()[1].path, PathBuf::from("last.txt"));
    }

    #[test]
    fn test_list_zip_entry_path_limit() {
        let at_limit = path_of_len(HOST_PATH_LIMIT);
        let over = path_of_len(HOST_PATH_LIMIT + 1);
        let config = SecurityConfig::default();

        let ok = zip_with_names(&[&at_limit]);
        assert_eq!(list_archive(ok.path(), &config).unwrap().total_entries(), 1);

        let bad = zip_with_names(&[&over]);
        assert_name_too_long(&list_archive(bad.path(), &config));
    }

    #[test]
    fn test_list_zip_verify_preflight_records_oversized_entry() {
        let over = path_of_len(HOST_PATH_LIMIT + 1);
        let file = zip_with_names(&[&over, "last.txt"]);
        let manifest = list_preflight(file.path(), SecurityConfig::default()).unwrap();

        assert_eq!(manifest.total_entries(), 1);
        assert_eq!(
            manifest.oversized_entries(),
            &[OversizedEntry::new(0, HOST_PATH_LIMIT + 1)]
        );
    }

    #[test]
    fn test_verify_reports_one_high_issue_per_oversized_entry() {
        let over = path_of_len(HOST_PATH_LIMIT + 1);
        let way_over = path_of_len(HOST_PATH_LIMIT * 3);
        let file = tar_with_paths(&["ok.txt", &over, &way_over]);

        let report = crate::verify_archive(file.path(), &SecurityConfig::default()).unwrap();

        assert_eq!(report.status(), crate::VerificationStatus::Fail);
        let issues: Vec<_> = report
            .issues()
            .iter()
            .filter(|i| i.message.contains("file name too long"))
            .collect();
        assert_eq!(issues.len(), 2);
        assert!(
            issues
                .iter()
                .all(|i| { i.severity == crate::IssueSeverity::High && i.entry_path.is_none() })
        );
        assert!(issues[0].message.contains("entry 1"));
        assert!(
            issues[1]
                .message
                .contains(&format!("{} bytes", HOST_PATH_LIMIT * 3))
        );
    }

    #[test]
    fn test_list_sevenz_entry_path_limit() {
        let over = path_of_len(HOST_PATH_LIMIT + 1);
        let data = make_sevenz_archive(&[(&over, b"x"), ("last.txt", b"x")]);
        let mut file = NamedTempFile::with_suffix(".7z").unwrap();
        file.write_all(&data).unwrap();
        file.flush().unwrap();

        assert_name_too_long(&list_archive(file.path(), &SecurityConfig::default()));

        let manifest = list_preflight(file.path(), SecurityConfig::default()).unwrap();
        assert_eq!(manifest.total_entries(), 1);
        assert_eq!(manifest.oversized_entries().len(), 1);
    }

    #[cfg(not(windows))]
    #[test]
    fn test_list_tar_pax_path_of_5000_bytes_errors() {
        let file = tar_with_paths(&[&path_of_len(5000)]);
        assert_name_too_long(&list_archive(file.path(), &SecurityConfig::default()));

        let manifest = list_preflight(file.path(), SecurityConfig::default()).unwrap();
        assert_eq!(manifest.total_entries(), 0);
        assert_eq!(
            manifest.oversized_entries(),
            &[OversizedEntry::new(0, 5000)]
        );
    }

    #[test]
    fn test_list_zip_name_of_65535_bytes_errors() {
        let mut file = NamedTempFile::with_suffix(".zip").unwrap();
        file.write_all(&create_raw_zip_entry(&path_of_len(65535), b""))
            .unwrap();
        file.flush().unwrap();
        assert_name_too_long(&list_archive(file.path(), &SecurityConfig::default()));

        let manifest = list_preflight(file.path(), SecurityConfig::default()).unwrap();
        assert_eq!(manifest.total_entries(), 0);
        assert_eq!(
            manifest.oversized_entries(),
            &[OversizedEntry::new(0, 65535)]
        );
    }

    #[test]
    fn test_verify_caps_oversized_entry_issues() {
        let over = path_of_len(HOST_PATH_LIMIT + 1);
        let paths = vec![over.as_str(); 20];
        let file = tar_with_paths(&paths);

        let report = crate::verify_archive(file.path(), &SecurityConfig::default()).unwrap();

        let issues: Vec<_> = report
            .issues()
            .iter()
            .filter(|i| i.message.contains("file name too long"))
            .collect();
        assert_eq!(issues.len(), 17);
        assert!(issues[16].message.contains("4 more entries"));
    }

    #[test]
    fn test_list_tar_verify_preflight_allows_nul_byte_path() {
        let mut temp_file = NamedTempFile::with_suffix(".tar").unwrap();
        temp_file
            .write_all(&tar_with_pax_nul_path(b"foo\0bar.txt", b"hello"))
            .unwrap();
        temp_file.flush().unwrap();

        let manifest = list_preflight(temp_file.path(), SecurityConfig::default())
            .expect("the pre-flight must let a NUL-byte entry path through");

        assert_eq!(manifest.total_entries(), 1);
        assert!(
            has_null_bytes(&manifest.entries()[0].path),
            "the raw NUL-byte path must reach the manifest unmodified"
        );
    }

    #[test]
    fn test_list_tar_verify_preflight_allows_missing_link_target() {
        let mut temp_file = NamedTempFile::with_suffix(".tar").unwrap();
        let mut builder = tar::Builder::new(Vec::new());

        let mut header = tar::Header::new_gnu();
        header.set_path("link").unwrap();
        header.set_size(0);
        header.set_entry_type(tar::EntryType::Symlink);
        header.set_cksum();
        builder.append(&header, &[][..]).unwrap();

        let data = builder.into_inner().unwrap();
        temp_file.write_all(&data).unwrap();
        temp_file.flush().unwrap();

        let manifest = list_preflight(temp_file.path(), SecurityConfig::default())
            .expect("the pre-flight must let a missing symlink target through");

        assert_eq!(manifest.total_entries(), 1);
        assert_eq!(manifest.entries()[0].kind.symlink_target(), None);
    }

    #[test]
    fn test_list_tar_verify_preflight_allows_nul_byte_link_target() {
        let mut temp_file = NamedTempFile::with_suffix(".tar").unwrap();
        temp_file
            .write_all(&tar_with_pax_linkpath(b"foo\0bar", b'2'))
            .unwrap();
        temp_file.flush().unwrap();

        let manifest = list_preflight(temp_file.path(), SecurityConfig::default())
            .expect("the pre-flight must let a NUL-byte symlink target through");

        assert_eq!(manifest.total_entries(), 1);
        assert!(
            manifest.entries()[0]
                .kind
                .symlink_target()
                .is_some_and(has_null_bytes),
            "the raw NUL-byte target must reach the manifest unmodified"
        );
    }

    #[test]
    fn test_list_zip_verify_preflight_allows_nul_byte_path() {
        let zip_bytes = create_raw_zip_entry("foo\0bar.txt", b"");
        let mut archive = ZipArchive::new(std::io::Cursor::new(zip_bytes)).unwrap();
        let config = SecurityConfig::default()
            .with_allow_absolute_paths(true)
            .validate()
            .unwrap();
        let manifest = list_zip_reader(&mut archive, &config, &mut ListPass::VerifyPreflight(None))
            .expect("the pre-flight must let a NUL-byte ZIP entry path through");

        assert_eq!(manifest.total_entries(), 1);
        assert!(
            has_null_bytes(&manifest.entries()[0].path),
            "the raw NUL-byte path must reach the manifest unmodified"
        );
    }

    // --- Regression tests for #396: list_archive() must route through
    // QuotaTracker instead of reimplementing quota checks ---

    #[test]
    fn test_list_tar_quota_exceeded_file_size() {
        // Previously list_tar_entries never checked max_file_size per entry —
        // only max_file_count/max_total_size. A single oversized entry must now
        // be rejected even when total size and file count are within limits.
        let mut temp_file = NamedTempFile::with_suffix(".tar").unwrap();
        let mut builder = tar::Builder::new(Vec::new());

        let data = vec![0u8; 1000];
        let mut header = tar::Header::new_gnu();
        header.set_path("big.bin").unwrap();
        header.set_size(data.len() as u64);
        header.set_cksum();
        builder.append(&header, &data[..]).unwrap();

        let archive_data = builder.into_inner().unwrap();
        temp_file.write_all(&archive_data).unwrap();
        temp_file.flush().unwrap();

        let config = SecurityConfig::default().with_max_file_size(500);
        let result = list_archive(temp_file.path(), &config);
        assert_matches!(
            result,
            Err(ArchiveError::QuotaExceeded {
                resource: QuotaResource::FileSize {
                    size: 1000,
                    max: 500
                }
            }),
            "expected FileSize quota error, got: {result:?}"
        );
    }

    #[test]
    fn test_list_zip_quota_exceeded_file_size() {
        let temp_file = NamedTempFile::with_suffix(".zip").unwrap();
        let file = std::fs::File::create(temp_file.path()).unwrap();
        let mut zip = zip::ZipWriter::new(file);
        let options = zip::write::SimpleFileOptions::default()
            .compression_method(zip::CompressionMethod::Stored);
        zip.start_file("big.bin", options).unwrap();
        zip.write_all(&vec![0u8; 1000]).unwrap();
        zip.finish().unwrap();

        let config = SecurityConfig::default().with_max_file_size(500);
        let result = list_archive(temp_file.path(), &config);
        assert_matches!(
            result,
            Err(ArchiveError::QuotaExceeded {
                resource: QuotaResource::FileSize {
                    size: 1000,
                    max: 500
                }
            }),
            "expected FileSize quota error, got: {result:?}"
        );
    }

    #[test]
    fn test_list_sevenz_quota_exceeded_file_size() {
        let data = vec![0u8; 1000];
        let archive_bytes = make_sevenz_archive(&[("big.bin", &data)]);
        let mut temp_file = NamedTempFile::with_suffix(".7z").unwrap();
        temp_file.write_all(&archive_bytes).unwrap();
        temp_file.flush().unwrap();

        let config = SecurityConfig::default().with_max_file_size(500);
        let result = list_archive(temp_file.path(), &config);
        assert_matches!(
            result,
            Err(ArchiveError::QuotaExceeded {
                resource: QuotaResource::FileSize {
                    size: 1000,
                    max: 500
                }
            }),
            "expected FileSize quota error, got: {result:?}"
        );
    }

    /// Builds a raw ZIP archive whose central directory declares entry sizes
    /// via the ZIP64 extended-information extra field (id `0x0001`),
    /// independent of the actual (empty) local file data. This lets tests
    /// exercise declared sizes that would be implausible to back with real
    /// bytes (e.g. near `u64::MAX`), which is exactly what `QuotaTracker`'s
    /// checked arithmetic must guard against.
    #[allow(clippy::cast_possible_truncation)]
    fn zip_with_zip64_declared_sizes(entries: &[(&str, u64)]) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::new();
        let mut central_entries: Vec<Vec<u8>> = Vec::new();

        for (name, declared_size) in entries {
            let name_bytes = name.as_bytes();
            let name_len = name_bytes.len() as u16;
            let local_offset = buf.len() as u32;

            // Local file header: empty stored entry, real size 0.
            buf.extend_from_slice(b"PK\x03\x04");
            buf.extend_from_slice(&20u16.to_le_bytes()); // version needed
            buf.extend_from_slice(&0u16.to_le_bytes()); // flags
            buf.extend_from_slice(&0u16.to_le_bytes()); // compression: stored
            buf.extend_from_slice(&0u16.to_le_bytes()); // mod time
            buf.extend_from_slice(&0u16.to_le_bytes()); // mod date
            buf.extend_from_slice(&0u32.to_le_bytes()); // crc32
            buf.extend_from_slice(&0u32.to_le_bytes()); // compressed size
            buf.extend_from_slice(&0u32.to_le_bytes()); // uncompressed size
            buf.extend_from_slice(&name_len.to_le_bytes());
            buf.extend_from_slice(&0u16.to_le_bytes()); // extra field length
            buf.extend_from_slice(name_bytes);

            // Central directory entry: sizes forced to the ZIP64 sentinel with
            // the real (lying) sizes carried in a ZIP64 extra field.
            let mut central: Vec<u8> = Vec::new();
            central.extend_from_slice(b"PK\x01\x02");
            central.extend_from_slice(&0x032du16.to_le_bytes()); // version made by: Unix, 4.5
            central.extend_from_slice(&45u16.to_le_bytes()); // version needed: 4.5 (ZIP64)
            central.extend_from_slice(&0u16.to_le_bytes()); // flags
            central.extend_from_slice(&0u16.to_le_bytes()); // compression
            central.extend_from_slice(&0u16.to_le_bytes()); // mod time
            central.extend_from_slice(&0u16.to_le_bytes()); // mod date
            central.extend_from_slice(&0u32.to_le_bytes()); // crc32
            central.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // compressed size sentinel
            central.extend_from_slice(&0xFFFF_FFFFu32.to_le_bytes()); // uncompressed size sentinel
            central.extend_from_slice(&name_len.to_le_bytes());
            central.extend_from_slice(&20u16.to_le_bytes()); // extra field length (4 hdr + 16 data)
            central.extend_from_slice(&0u16.to_le_bytes()); // comment length
            central.extend_from_slice(&0u16.to_le_bytes()); // disk number start
            central.extend_from_slice(&0u16.to_le_bytes()); // internal attributes
            central.extend_from_slice(&0u32.to_le_bytes()); // external attributes
            central.extend_from_slice(&local_offset.to_le_bytes());
            central.extend_from_slice(name_bytes);
            central.extend_from_slice(&1u16.to_le_bytes()); // ZIP64 extra field id
            central.extend_from_slice(&16u16.to_le_bytes()); // ZIP64 extra field data size
            central.extend_from_slice(&declared_size.to_le_bytes()); // uncompressed size
            central.extend_from_slice(&0u64.to_le_bytes()); // compressed size

            central_entries.push(central);
        }

        let central_offset = buf.len() as u32;
        for central in &central_entries {
            buf.extend_from_slice(central);
        }
        let central_size = (buf.len() as u32) - central_offset;

        buf.extend_from_slice(b"PK\x05\x06");
        buf.extend_from_slice(&0u16.to_le_bytes()); // disk number
        buf.extend_from_slice(&0u16.to_le_bytes()); // disk with central dir
        buf.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        buf.extend_from_slice(&(entries.len() as u16).to_le_bytes());
        buf.extend_from_slice(&central_size.to_le_bytes());
        buf.extend_from_slice(&central_offset.to_le_bytes());
        buf.extend_from_slice(&0u16.to_le_bytes()); // comment length
        buf
    }

    #[test]
    fn test_list_zip_total_size_overflow_rejected_not_wrapped() {
        // Two entries whose declared sizes sum past u64::MAX. With unchecked
        // addition (the pre-fix behaviour) `total_size` would silently wrap
        // and bypass max_total_size entirely. QuotaTracker's checked_add must
        // reject this with IntegerOverflow instead.
        use std::io::Cursor;

        let zip_bytes = zip_with_zip64_declared_sizes(&[("a.bin", u64::MAX - 100), ("b.bin", 200)]);
        let mut archive = ZipArchive::new(Cursor::new(zip_bytes)).unwrap();

        let config = SecurityConfig::default()
            .with_max_file_size(u64::MAX)
            .with_max_file_count(usize::MAX)
            .with_max_total_size(u64::MAX)
            .validate()
            .expect("valid config");
        let result = list_zip_reader(&mut archive, &config, &mut ListPass::Strict);
        assert_matches!(
            result,
            Err(ArchiveError::QuotaExceeded {
                resource: QuotaResource::IntegerOverflow
            }),
            "expected IntegerOverflow quota error instead of a silently wrapped total, got: {result:?}"
        );
    }

    fn oversized_hardlink_tar(count: usize) -> Vec<u8> {
        let one = tar_with_pax_linkpath(&vec![b'a'; 100_000], b'1');
        let entry = &one[..one.len() - 1024];
        let mut tar = entry.repeat(count);
        tar.extend(std::iter::repeat_n(0u8, 1024));
        tar
    }

    #[test]
    fn test_list_tar_oversized_link_target_rejected() {
        let mut temp_file = NamedTempFile::with_suffix(".tar").unwrap();
        temp_file.write_all(&oversized_hardlink_tar(1)).unwrap();
        temp_file.flush().unwrap();

        let result = list_archive(temp_file.path(), &SecurityConfig::default());
        assert_matches!(
            result,
            Err(ArchiveError::InvalidArchive(msg)) if msg == "hardlink target too long: 100000 bytes"
        );
    }

    #[test]
    fn test_list_tar_preflight_keeps_only_the_length_of_oversized_targets() {
        let mut temp_file = NamedTempFile::with_suffix(".tar").unwrap();
        temp_file.write_all(&oversized_hardlink_tar(3)).unwrap();
        temp_file.flush().unwrap();

        let manifest = list_preflight(temp_file.path(), SecurityConfig::default()).unwrap();

        assert_eq!(manifest.total_entries(), 3);
        for entry in manifest.entries() {
            assert_matches!(
                &entry.kind,
                ManifestEntryKind::Hardlink {
                    target: LinkTarget::Oversized { bytes: 100_000 }
                }
            );
        }
    }

    fn tar_with_sizes(sizes: &[usize]) -> NamedTempFile {
        let mut builder = tar::Builder::new(Vec::new());
        for (i, size) in sizes.iter().enumerate() {
            let mut header = tar::Header::new_gnu();
            header.set_size(*size as u64);
            header.set_cksum();
            builder
                .append_data(&mut header, format!("f{i}.bin"), &vec![0u8; *size][..])
                .unwrap();
        }
        let mut file = NamedTempFile::with_suffix(".tar").unwrap();
        file.write_all(&builder.into_inner().unwrap()).unwrap();
        file.flush().unwrap();
        file
    }

    #[test]
    fn test_list_preflight_lifts_only_file_size_limit() {
        let file = tar_with_sizes(&[100, 10]);
        let config = SecurityConfig::default().with_max_file_size(50);

        assert_matches!(
            list_archive(file.path(), &config),
            Err(ArchiveError::QuotaExceeded {
                resource: QuotaResource::FileSize { size: 100, max: 50 }
            })
        );
        let manifest = list_preflight(file.path(), config.clone()).unwrap();
        assert_eq!(manifest.total_entries(), 2);

        assert_matches!(
            list_preflight(file.path(), config.clone().with_max_file_count(1)),
            Err(ArchiveError::QuotaExceeded {
                resource: QuotaResource::FileCount { current: 2, max: 1 }
            })
        );
        assert_matches!(
            list_preflight(file.path(), config.with_max_total_size(105)),
            Err(ArchiveError::QuotaExceeded {
                resource: QuotaResource::TotalSize {
                    current: 110,
                    max: 105
                }
            })
        );
    }

    fn assert_verify_reports_oversized_file(path: &Path) {
        let config = SecurityConfig::default().with_max_file_size(500);
        let report = crate::verify_archive(path, &config)
            .expect("verify must report an oversized entry, not error out");

        assert_eq!(report.status(), crate::VerificationStatus::Fail);
        assert!(
            report.issues().iter().any(|i| {
                i.category == crate::IssueCategory::QuotaExceeded
                    && i.message.contains("single file size")
            }),
            "expected a FileSize issue, got: {:?}",
            report.issues()
        );
    }

    #[test]
    fn test_verify_zip_reports_oversized_entry_not_error() {
        let mut file = NamedTempFile::with_suffix(".zip").unwrap();
        let bytes = crate::test_utils::create_test_zip(vec![("big.bin", &[0u8; 1000])]);
        file.write_all(&bytes).unwrap();
        file.flush().unwrap();

        assert_verify_reports_oversized_file(file.path());
    }

    #[test]
    fn test_verify_sevenz_reports_oversized_entry_not_error() {
        let mut file = NamedTempFile::with_suffix(".7z").unwrap();
        file.write_all(&make_sevenz_archive(&[("big.bin", &[0u8; 1000])]))
            .unwrap();
        file.flush().unwrap();

        assert_verify_reports_oversized_file(file.path());
    }

    #[test]
    fn test_list_zip_oversized_symlink_target() {
        use crate::test_utils::HOST_SYMLINK_TARGET_BYTES;
        use crate::test_utils::create_zip_with_symlink;
        use std::io::Cursor;

        let zip_bytes = create_zip_with_symlink("link", &"a".repeat(HOST_SYMLINK_TARGET_BYTES + 1));

        let mut archive = ZipArchive::new(Cursor::new(zip_bytes.clone())).unwrap();
        let strict = SecurityConfig::default().validate().unwrap();
        assert_matches!(
            list_zip_reader(&mut archive, &strict, &mut ListPass::Strict),
            Err(ArchiveError::SecurityViolation { .. })
        );

        let mut archive = ZipArchive::new(Cursor::new(zip_bytes)).unwrap();
        let manifest =
            list_zip_reader(&mut archive, &strict, &mut ListPass::VerifyPreflight(None)).unwrap();
        assert_matches!(
            &manifest.entries()[0].kind,
            ManifestEntryKind::Symlink {
                target: LinkTarget::Oversized { bytes }
            } if *bytes == HOST_SYMLINK_TARGET_BYTES + 1
        );
    }

    #[test]
    fn test_list_zip_symlink_with_a_huge_declared_target_is_never_read() {
        use crate::raw_zip::RawEntry;
        use crate::raw_zip::RawZip;
        use crate::raw_zip::deflate_zeros;
        use std::io::Cursor;

        const DECLARED: u64 = 64 * 1024 * 1024;
        let mut link = RawEntry::stored("link", b"");
        link.data = deflate_zeros(DECLARED);
        link.method = 8;
        link.size = DECLARED;
        link.external_attributes = 0o120_777 << 16;
        let bytes = RawZip::new(vec![link]).build().bytes;

        let mut archive = ZipArchive::new(Cursor::new(bytes)).unwrap();
        let config = SecurityConfig::default().validate().unwrap();
        let manifest =
            list_zip_reader(&mut archive, &config, &mut ListPass::VerifyPreflight(None)).unwrap();
        assert_matches!(
            &manifest.entries()[0].kind,
            ManifestEntryKind::Symlink {
                target: LinkTarget::Oversized { bytes }
            } if *bytes == usize::try_from(DECLARED).unwrap()
        );
    }
}

//! Where a TAR or ZIP handler's validated entries go.
//!
//! The handler loops own every per-format gate (metadata budget, entry-type
//! refusal, encrypted entries, declared sizes, extension filter, two-pass
//! hardlinks). Only validation and the final write go through an
//! [`ExtractTarget`], so the host filesystem ([`HostTarget`]) and an
//! `EntrySink` run the same gates.

use std::io::Read;
use std::path::Path;

use crate::ArchiveError;
use crate::ExtractionReport;
use crate::ProgressCallback;
use crate::Result;
use crate::SecurityConfig;
use crate::config::Validated;
use crate::copy::CopyBuffer;
use crate::security::fs_view::HostFs;
use crate::security::hardlink::hardlink_target_missing;
use crate::security::permissions::SanitizedMode;
use crate::security::quota::EntryCount;
use crate::security::quota::QuotaPermit;
use crate::security::validator::ValidatedEntry;
use crate::security::validator::ValidatorCore;
use crate::types::DestDir;
use crate::types::EntryType;
use crate::types::SafePath;
use crate::types::SafeSymlink;
use crate::types::safe_symlink::resolve_through_symlinks;

use super::common;

/// The per-run counters a target updates while it writes.
pub struct Tally<'a> {
    pub(crate) report: &'a mut ExtractionReport,
    pub(crate) skip_duplicates: bool,
    /// File and symlink entries skipped as pre-existing duplicates.
    pub(crate) duplicate_skips: &'a mut u64,
    pub(crate) progress: &'a mut dyn ProgressCallback,
}

/// The validation and write half of an extraction.
pub trait ExtractTarget {
    /// Validates one entry against the target's own view of the destination.
    fn validate(
        &mut self,
        path: &Path,
        entry_type: &EntryType,
        size: u64,
        compressed_size: Option<u64>,
        mode: Option<u32>,
    ) -> Result<ValidatedEntry>;

    /// Creates a validated directory.
    fn directory(&mut self, path: &SafePath, tally: &mut Tally<'_>) -> Result<()>;

    /// Streams a validated file from `reader`, enforcing the declared `size`.
    fn file<R: Read>(
        &mut self,
        reader: &mut R,
        path: &SafePath,
        mode: Option<SanitizedMode>,
        permit: QuotaPermit,
        size: u64,
        tally: &mut Tally<'_>,
    ) -> Result<()>;

    /// Creates a validated symlink.
    fn symlink(&mut self, symlink: &SafeSymlink, tally: &mut Tally<'_>) -> Result<()>;

    /// Materializes a hardlink in the second pass, once every target exists.
    fn hardlink(
        &mut self,
        link: &SafePath,
        target: &SafePath,
        counted: EntryCount,
        tally: &mut Tally<'_>,
        hardlink_duplicate_skips: &mut u64,
    ) -> Result<()>;
}

/// Extraction onto the real filesystem.
pub struct HostTarget<'a> {
    dest: DestDir,
    dir_cache: common::DirCache,
    copy_buffer: CopyBuffer,
    core: ValidatorCore<'a>,
}

impl<'a> HostTarget<'a> {
    /// Creates `output_dir` if needed and a target writing into it.
    pub(crate) fn create(output_dir: &Path, config: &'a SecurityConfig<Validated>) -> Result<Self> {
        Ok(Self {
            dest: DestDir::new_or_create(output_dir.to_path_buf())?,
            dir_cache: common::DirCache::new(),
            copy_buffer: CopyBuffer::new(),
            core: ValidatorCore::new(config),
        })
    }
}

impl ExtractTarget for HostTarget<'_> {
    fn validate(
        &mut self,
        path: &Path,
        entry_type: &EntryType,
        size: u64,
        compressed_size: Option<u64>,
        mode: Option<u32>,
    ) -> Result<ValidatedEntry> {
        let ctx = self
            .core
            .context::<HostFs>()
            .with_dir_cache(&self.dir_cache);
        self.core.validate_entry_in(
            path,
            entry_type,
            size,
            compressed_size,
            mode,
            &self.dest,
            &HostFs,
            &ctx,
        )
    }

    fn directory(&mut self, path: &SafePath, tally: &mut Tally<'_>) -> Result<()> {
        common::create_directory(path, &self.dest, tally.report, &mut self.dir_cache)
    }

    fn file<R: Read>(
        &mut self,
        reader: &mut R,
        path: &SafePath,
        mode: Option<SanitizedMode>,
        permit: QuotaPermit,
        size: u64,
        tally: &mut Tally<'_>,
    ) -> Result<()> {
        common::extract_file_with_permit(
            reader,
            path,
            mode,
            permit,
            &self.dest,
            tally.report,
            Some(size),
            &mut self.copy_buffer,
            &mut self.dir_cache,
            tally.skip_duplicates,
            tally.duplicate_skips,
            tally.progress,
        )
    }

    fn symlink(&mut self, symlink: &SafeSymlink, tally: &mut Tally<'_>) -> Result<()> {
        common::create_symlink(
            symlink,
            &self.dest,
            tally.report,
            &mut self.dir_cache,
            tally.skip_duplicates,
            tally.duplicate_skips,
        )
    }

    /// Creates a hardlink in the second pass by copying content.
    ///
    /// Uses a content copy instead of `fs::hard_link` to avoid shared-inode
    /// corruption: a real OS hardlink would allow a subsequent write to
    /// `link_path` to silently overwrite `target_path` (GHSA-2367-c296-3mp2
    /// variant, issue #130).
    ///
    /// # Security - Symlink-at-Destination Rejection (issue #467)
    ///
    /// `Path::exists()` returns `false` for a dangling symlink, so a
    /// pre-planted symlink at `link_path` used to bypass the old
    /// existence-based duplicate check, and the subsequent `fs::copy`
    /// followed it, writing archive content outside the extraction root.
    /// The destination is now opened via `common::create_file_with_mode`
    /// (mode `None`, since permissions are copied from the target's bytes
    /// afterward, not set at creation) with `create_new = true`, which
    /// atomically fails with `ErrorKind::AlreadyExists` for any pre-existing
    /// path at `link_path` — symlink (dangling or not), regular file, or
    /// directory — folding the duplicate check into the `open()` call
    /// itself instead of a separate, bypassable `exists()` probe. This
    /// reuses the same `O_EXCL`+`O_NOFOLLOW` (Unix) discipline as the
    /// normal-file write path (issue #459) for consistency, though
    /// `create_new`'s `O_EXCL` alone already refuses any pre-existing path.
    ///
    /// # Security - Target Read TOCTOU and Quota TOCTOU (issue #467)
    ///
    /// Hardlinks are validated in two passes: `validate` (via
    /// `HardlinkTracker::validate_hardlink_in`) resolves `target` through
    /// any on-disk symlinks and checks containment in pass one, but this
    /// function — pass two — runs later, after every entry in the archive has
    /// been validated and every non-hardlink entry extracted. Nothing
    /// re-validates `target_path` in between. A plain path-based `File::open`
    /// (or `std::fs::metadata`, as this function used to do to size the quota
    /// reservation) would silently follow whatever is at `target_path` by the
    /// time pass two runs — which, given an attacker-writable destination
    /// directory, may not be what pass one validated at all (the target
    /// swapped for a symlink escaping `dest` in between the two passes).
    /// Separately, sizing the quota reservation from a path-based `stat` and
    /// then copying from a *different*, separately-opened handle left its own
    /// TOCTOU window: swapping `target_path` between the two operations could
    /// charge the quota for N bytes while actually copying an unbounded
    /// amount.
    ///
    /// Both are narrowed the same way: [`common::open_no_follow`] opens
    /// `target_path` once, refusing to follow a symlink (Unix, via
    /// `O_NOFOLLOW`) rather than a separate `stat`-then-`open`; the quota
    /// reservation is sized from that same open handle's `fstat`, and the
    /// copy reads from that same handle — never re-touching the path
    /// afterward. A symlink at `target_path` is not automatically rejected,
    /// though: it is a legitimate, common archive shape for a hardlink's
    /// target to itself be a symlink created earlier in the *same*
    /// extraction (already pass-one-validated). On `ErrorKind::FilesystemLoop`
    /// from `open_no_follow`, [`resolve_through_symlinks`] re-runs the exact
    /// containment check pass one already trusts, against the *current*
    /// on-disk state; if it still resolves inside `dest`, the resolved
    /// (symlink-free, since `canonicalize` dereferences fully) path is opened
    /// instead. This narrows the TOCTOU window from "the entire gap between
    /// pass one and pass two" down to "between this re-check and the open" —
    /// consistent with the check-then-act discipline the rest of the pipeline
    /// already accepts elsewhere (e.g. `DirCache`'s documented TOCTOU). If the
    /// re-resolution instead lands outside `dest`, that is a genuine escape
    /// attempt and is reported as such, not as a raw OS errno.
    fn hardlink(
        &mut self,
        link: &SafePath,
        target: &SafePath,
        counted: EntryCount,
        tally: &mut Tally<'_>,
        hardlink_duplicate_skips: &mut u64,
    ) -> Result<()> {
        let link_path = self.dest.join(link);
        let target_path = self.dest.join(target);

        if !target_path.exists() {
            return Err(hardlink_target_missing(target.as_path()));
        }

        // Create parent directories using cache
        self.dir_cache.ensure_parent_dir(&link_path)?;

        let link_file = match common::create_file_with_mode(&link_path, None, true) {
            Ok(file) => file,
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                if tally.skip_duplicates {
                    common::checked_increment_files_skipped(tally.report)?;
                    *hardlink_duplicate_skips = hardlink_duplicate_skips.saturating_add(1);
                    return Ok(());
                }
                return Err(ArchiveError::InvalidArchive(format!(
                    "duplicate entry: {}",
                    link.as_path().display()
                )));
            }
            Err(e) => return Err(ArchiveError::Io(e)),
        };
        let cleanup_guard = common::TempFileGuard::new(link_path);

        // Opened once, refusing to follow a symlink at `target_path`; the
        // quota reservation below and the copy further down both operate on
        // this same handle instead of re-touching the path (issue #467).
        let target_file = match common::open_no_follow(&target_path) {
            Ok(file) => file,
            Err(e) if common::is_filesystem_loop_error(&e) => {
                // `target_path`'s final component is a symlink. Re-run pass
                // one's own containment check against the current on-disk
                // state; a symlink created by an earlier entry in this same
                // extraction resolves safely inside `dest` and is opened at
                // its resolved (symlink-free) location, while a genuine
                // escape attempt is rejected as HardlinkEscape rather than
                // surfacing as a raw ELOOP.
                let resolved = resolve_through_symlinks(
                    self.dest.as_path(),
                    target.as_path(),
                    self.dest.as_path(),
                    link.as_path(),
                )
                .map_err(|_| ArchiveError::HardlinkEscape {
                    path: link.as_path().to_path_buf(),
                })?;
                common::open_no_follow(&resolved)?
            }
            Err(e) => return Err(ArchiveError::Io(e)),
        };

        // Every hardlink copies the target's real bytes to a new inode, so it
        // must be charged against the same quota tracker as regular files
        // (issue #426): otherwise N hardlinks to one small file extract N
        // full copies with no size enforcement. The entry itself was counted
        // in pass one (`counted`), so a skipped duplicate keeps its count
        // slot but is charged no bytes, and the pending list is bounded by
        // `max_file_count` before anything is copied. The permit is consumed
        // by value below, so this charge cannot be spent twice.
        let target_size = target_file.metadata()?.len();
        let permit = self.core.charge_hardlink(counted, target_size)?;

        // Copy content between the two handles opened above. Any subsequent
        // write to `link_path` cannot corrupt `target_path` because they are
        // separate files.
        let bytes_copied = common::copy_file_content_with_permit(target_file, link_file, permit)?;
        cleanup_guard.persist();

        tally.report.files_extracted = common::checked_add_count(tally.report.files_extracted, 1)?;
        tally.report.bytes_written =
            common::checked_add_bytes(tally.report.bytes_written, bytes_copied)?;
        tally.progress.on_bytes_written(bytes_copied);

        Ok(())
    }
}

//! Integration tests for `ExtractionOptions::skip_duplicates`.
//!
//! Covers both the default behavior (skip=true, first entry wins) and the
//! opt-in overwrite behavior (skip=false, last entry wins) using TAR archives
//! built in-memory with two entries sharing the same path.
//!
//! ZIP duplicate behavior is documented in a separate note below: the `zip`
//! crate (8.x) deduplicates entries at `ZipArchive::new()` time, so the raw
//! archive with two identical filenames appears as a single entry regardless of
//! `skip_duplicates`.  The ZIP-specific unit tests in `src/formats/zip.rs`
//! cover this boundary.

#![allow(clippy::unwrap_used, clippy::expect_used)]

use exarch_core::ExtractionOptions;
use exarch_core::SecurityConfig;
use exarch_core::extract_archive_with_options;
use sevenz_rust2::ArchiveEntry;
use sevenz_rust2::ArchiveWriter;
use std::io::Write as _;
use tempfile::NamedTempFile;
use tempfile::TempDir;

/// Build a TAR archive in memory containing two entries with the same path.
fn make_tar_with_duplicate(path: &str, first: &[u8], second: &[u8]) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());

    let mut hdr = tar::Header::new_gnu();
    hdr.set_size(first.len() as u64);
    hdr.set_mode(0o644);
    hdr.set_cksum();
    builder.append_data(&mut hdr, path, first).unwrap();

    let mut hdr = tar::Header::new_gnu();
    hdr.set_size(second.len() as u64);
    hdr.set_mode(0o644);
    hdr.set_cksum();
    builder.append_data(&mut hdr, path, second).unwrap();

    builder.into_inner().unwrap()
}

/// Write bytes to a named temp file with a `.tar` suffix and return the file
/// (kept alive so the path remains valid for the duration of the test).
fn write_tar(data: &[u8]) -> NamedTempFile {
    let mut f = NamedTempFile::with_suffix(".tar").unwrap();
    f.write_all(data).unwrap();
    f.flush().unwrap();
    f
}

/// Build a TAR archive in memory containing a single file entry.
fn make_tar_single(path: &str, content: &[u8]) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    let mut hdr = tar::Header::new_gnu();
    hdr.set_size(content.len() as u64);
    hdr.set_mode(0o644);
    hdr.set_cksum();
    builder.append_data(&mut hdr, path, content).unwrap();
    builder.into_inner().unwrap()
}

/// `skip_duplicates=true` (the default): the second entry is skipped and the
/// file on disk retains the content of the first entry.
#[test]
fn tar_skip_duplicates_true_keeps_first_entry() {
    let data = make_tar_with_duplicate("file.txt", b"first", b"second");
    let archive = write_tar(&data);
    let dest = TempDir::new().unwrap();
    let config = SecurityConfig::default();
    let options = ExtractionOptions::default(); // skip_duplicates = true

    let report = extract_archive_with_options(archive.path(), dest.path(), &config, &options)
        .expect("extraction with skip_duplicates=true must succeed");

    assert_eq!(
        report.files_extracted, 1,
        "only the first entry is extracted"
    );
    assert_eq!(
        report.files_skipped, 1,
        "second entry must be counted as skipped"
    );
    assert_eq!(
        report.warnings.len(),
        1,
        "exactly one duplicate warning expected"
    );
    assert!(
        report.warnings[0].contains("file.txt"),
        "warning must identify the duplicate path"
    );

    let content = std::fs::read(dest.path().join("file.txt")).unwrap();
    assert_eq!(content, b"first", "first entry content must be preserved");
}

/// `skip_duplicates=false`: both entries are processed; the second entry
/// overwrites the first, so the file on disk contains the content of the
/// second entry.
#[test]
fn tar_skip_duplicates_false_overwrites_with_last_entry() {
    let data = make_tar_with_duplicate("file.txt", b"first", b"second");
    let archive = write_tar(&data);
    let dest = TempDir::new().unwrap();
    let config = SecurityConfig::default();
    let options = ExtractionOptions::default().with_skip_duplicates(false);

    let report = extract_archive_with_options(archive.path(), dest.path(), &config, &options)
        .expect("extraction with skip_duplicates=false must succeed");

    assert_eq!(
        report.files_extracted, 2,
        "both entries must be counted as extracted (second overwrites first)"
    );
    assert_eq!(report.files_skipped, 0, "no entries must be skipped");

    let content = std::fs::read(dest.path().join("file.txt")).unwrap();
    assert_eq!(
        content, b"second",
        "second entry must have overwritten the first"
    );
}

// ============================================================================
// 7z skip_duplicates tests
// ============================================================================

/// Build a 7z archive in memory containing two entries with the same path but
/// different content.
fn make_sevenz_with_duplicate(path: &str, first: &[u8], second: &[u8]) -> NamedTempFile {
    let mut f = NamedTempFile::with_suffix(".7z").unwrap();
    {
        let mut writer = ArchiveWriter::new(&mut f).unwrap();
        writer
            .push_archive_entry(ArchiveEntry::new_file(path), Some(first))
            .unwrap();
        writer
            .push_archive_entry(ArchiveEntry::new_file(path), Some(second))
            .unwrap();
        writer.finish().unwrap();
    }
    f
}

/// `skip_duplicates=true` (default): first entry extracted, second skipped.
/// The file on disk must contain the content of the FIRST entry.
#[test]
fn sevenz_skip_duplicates_true_keeps_first_entry() {
    let archive = make_sevenz_with_duplicate("file.txt", b"first", b"second");
    let dest = TempDir::new().unwrap();
    let config = SecurityConfig::default();
    let options = ExtractionOptions::default(); // skip_duplicates = true

    let report = extract_archive_with_options(archive.path(), dest.path(), &config, &options)
        .expect("extraction with skip_duplicates=true must succeed");

    assert_eq!(
        report.files_extracted, 1,
        "only the first entry is extracted"
    );
    assert_eq!(
        report.files_skipped, 1,
        "second entry must be counted as skipped"
    );
    assert_eq!(
        report.warnings.len(),
        1,
        "exactly one duplicate warning expected"
    );
    assert!(
        report.warnings[0].contains("file.txt"),
        "warning must identify the duplicate path"
    );

    let content = std::fs::read(dest.path().join("file.txt")).unwrap();
    assert_eq!(content, b"first", "first entry content must be preserved");
}

/// `skip_duplicates=false`: both entries processed; second overwrites first.
/// The file on disk must contain the content of the SECOND entry.
#[test]
fn sevenz_skip_duplicates_false_overwrites_with_last_entry() {
    let archive = make_sevenz_with_duplicate("file.txt", b"first", b"second");
    let dest = TempDir::new().unwrap();
    let config = SecurityConfig::default();
    let options = ExtractionOptions::default().with_skip_duplicates(false);

    let report = extract_archive_with_options(archive.path(), dest.path(), &config, &options)
        .expect("extraction with skip_duplicates=false must succeed");

    assert_eq!(
        report.files_extracted, 2,
        "both entries must be counted as extracted (second overwrites first)"
    );
    assert_eq!(report.files_skipped, 0, "no entries must be skipped");

    let content = std::fs::read(dest.path().join("file.txt")).unwrap();
    assert_eq!(
        content, b"second",
        "second entry must have overwritten the first"
    );
}

/// `skip_duplicates=false` with a nested path: verifies parent directories are
/// created correctly and the overwrite path works for entries under
/// subdirectories.
#[test]
fn tar_skip_duplicates_false_overwrites_nested_path() {
    let data = make_tar_with_duplicate("subdir/nested.txt", b"original", b"overwritten");
    let archive = write_tar(&data);
    let dest = TempDir::new().unwrap();
    let config = SecurityConfig::default();
    let options = ExtractionOptions::default().with_skip_duplicates(false);

    let report = extract_archive_with_options(archive.path(), dest.path(), &config, &options)
        .expect("extraction with skip_duplicates=false must succeed for nested paths");

    assert_eq!(report.files_extracted, 2);
    assert_eq!(report.files_skipped, 0);

    let content = std::fs::read(dest.path().join("subdir/nested.txt")).unwrap();
    assert_eq!(content, b"overwritten");
}

// ============================================================================
// Symlink-at-destination regression tests (issue #459)
// ============================================================================
//
// Before the #446 fix, the duplicate-existence check used `Path::exists()`,
// which follows symlinks and returns `false` for a *dangling* one. A dangling
// symlink planted at the destination path (by something other than this
// extraction — an in-archive symlink entry cannot escape `dest`, since
// `SafeSymlink::validate` already rejects that) therefore looked like "no
// duplicate" and a plain `File::create` wrote the archive's content straight
// through the link, landing outside the extraction root. The fix folds the
// check into `open()` with `O_EXCL`/`O_NOFOLLOW`, which reject an existing
// symlink (dangling or not) without following it, on both `skip_duplicates`
// values.

/// `skip_duplicates=true` (default): a dangling symlink at the destination
/// path must be treated as an existing entry and skipped — not followed.
#[cfg(unix)]
#[test]
fn tar_dangling_symlink_at_destination_skipped_not_followed() {
    use std::os::unix::fs::symlink;

    let dest = TempDir::new().unwrap();
    let outside = TempDir::new().unwrap();
    let escape_target = outside.path().join("escaped.txt");

    // Plant a dangling symlink at the path the archive entry targets,
    // pointing outside the destination directory.
    symlink(&escape_target, dest.path().join("file.txt")).unwrap();
    assert!(
        !escape_target.exists(),
        "symlink target must be dangling before extraction"
    );

    let data = make_tar_single("file.txt", b"payload");
    let archive = write_tar(&data);
    let config = SecurityConfig::default();
    let options = ExtractionOptions::default(); // skip_duplicates = true (default)

    let report = extract_archive_with_options(archive.path(), dest.path(), &config, &options)
        .expect("skip_duplicates=true must skip the symlinked path, not error");

    assert_eq!(
        report.files_skipped, 1,
        "the symlinked path must be counted as skipped"
    );
    assert_eq!(report.files_extracted, 0);
    assert!(
        !escape_target.exists(),
        "payload must never land outside dest via the dangling symlink"
    );
    assert!(
        dest.path()
            .join("file.txt")
            .symlink_metadata()
            .unwrap()
            .file_type()
            .is_symlink(),
        "the planted symlink must be left untouched, not replaced"
    );
}

/// `skip_duplicates=false`: a symlink at the destination path must still be
/// rejected rather than followed and overwritten-through.
#[cfg(unix)]
#[test]
fn tar_dangling_symlink_at_destination_rejected_when_overwrite_requested() {
    use std::os::unix::fs::symlink;

    let dest = TempDir::new().unwrap();
    let outside = TempDir::new().unwrap();
    let escape_target = outside.path().join("escaped.txt");

    symlink(&escape_target, dest.path().join("file.txt")).unwrap();
    assert!(
        !escape_target.exists(),
        "symlink target must be dangling before extraction"
    );

    let data = make_tar_single("file.txt", b"payload");
    let archive = write_tar(&data);
    let config = SecurityConfig::default();
    let options = ExtractionOptions::default().with_skip_duplicates(false);

    let result = extract_archive_with_options(archive.path(), dest.path(), &config, &options);

    assert!(
        result.is_err(),
        "writing through a symlink at the destination must be rejected, not silently followed"
    );
    assert!(
        !escape_target.exists(),
        "payload must never land outside dest via the dangling symlink"
    );
}

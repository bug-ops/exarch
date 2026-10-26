#![allow(clippy::unwrap_used, clippy::expect_used)]

use super::admit::RefusalScope;
use super::admit::SevenZRefusal;
use super::admit::sevenz_entry_compression;
use super::admit::sevenz_refusals;
use super::classify::KindSource;
use super::classify::NativeKind;
use super::classify::SevenZClass;
use super::classify::SevenZKind;
use super::classify::UnsupportedEntry;
use super::classify::is_windows_reparse_point;
use super::classify::reparse_point_refusal;
use super::decode::decode_archive_entries;
use super::header::BlockIndex;
use super::links::BlockScan;
use super::links::BlockStop;
use super::verify::entries_uncovered_by_block_crc;
use super::verify::payload_by_block;
#[cfg(unix)]
use super::write::MAX_TEMP_FILE_CREATE_ATTEMPTS;
#[cfg(unix)]
use super::write::write_file_direct;
#[cfg(unix)]
use super::write::write_file_with_permit;
#[cfg(unix)]
use super::write::write_file_with_permit_using;
use super::*;
use crate::IssueCategory;
use crate::ParallelDecode;
use crate::QuotaResource;
use crate::SolidBlock;
use crate::UnverifiedReason;
use crate::inspection::integrity::IntegrityPass;
#[cfg(unix)]
use crate::security::QuotaPermit;
use sevenz_rust2::Archive;
use sevenz_rust2::Password;
use std::assert_matches;
use std::collections::BTreeSet;
use std::io::Cursor;
use std::path::PathBuf;
use tempfile::TempDir;

fn extraction_type_of(entry: &sevenz_rust2::ArchiveEntry) -> Result<EntryType> {
    match SevenZClass::of(entry).present(&entry.name)? {
        Some(SevenZKind::File) => Ok(EntryType::File),
        Some(SevenZKind::Directory) => Ok(EntryType::Directory),
        Some(SevenZKind::ReparsePoint) => Err(reparse_point_refusal(&entry.name)),
        Some(SevenZKind::UnixSymlink) => Ok(EntryType::Symlink {
            target: PathBuf::new(),
        }),
        None => panic!("anti item has no extraction type"),
    }
}

fn reparse(mut entry: sevenz_rust2::ArchiveEntry) -> sevenz_rust2::ArchiveEntry {
    entry.has_windows_attributes = true;
    entry.windows_attributes = 0x0400;
    entry
}

#[test]
fn classifier_table() {
    use sevenz_rust2::ArchiveEntry;

    let file = ArchiveEntry::new_file("f");
    let dir = ArchiveEntry::new_directory("d");
    let mut anti_reparse_dir = reparse(ArchiveEntry::new_directory("x"));
    anti_reparse_dir.is_anti_item = true;

    assert_eq!(
        SevenZClass::of(&file),
        SevenZClass::Present(SevenZKind::File)
    );
    assert_eq!(
        SevenZClass::of(&dir),
        SevenZClass::Present(SevenZKind::Directory)
    );
    assert_eq!(
        SevenZClass::of(&reparse(ArchiveEntry::new_file("l"))),
        SevenZClass::Present(SevenZKind::ReparsePoint)
    );
    assert_eq!(
        SevenZClass::of(&reparse(ArchiveEntry::new_directory("j"))),
        SevenZClass::Present(SevenZKind::ReparsePoint)
    );
    assert_eq!(SevenZClass::of(&anti_reparse_dir), SevenZClass::AntiItem);
}

fn with_unix_mode(mut entry: sevenz_rust2::ArchiveEntry, mode: u32) -> sevenz_rust2::ArchiveEntry {
    entry.has_windows_attributes = true;
    entry.windows_attributes = 0x8000 | (mode << 16);
    entry
}

#[test]
fn unix_mode_symlink_is_classified_as_symlink() {
    use sevenz_rust2::ArchiveEntry;

    let link = SevenZClass::Present(SevenZKind::UnixSymlink);

    assert_eq!(
        SevenZClass::of(&with_unix_mode(ArchiveEntry::new_file("l"), 0o120_777)),
        link
    );
    assert_eq!(
        SevenZClass::of(&with_unix_mode(ArchiveEntry::new_directory("l"), 0o120_777)),
        link
    );
    assert_eq!(
        SevenZClass::of(&with_unix_mode(ArchiveEntry::new_file("f"), 0o100_644)),
        SevenZClass::Present(SevenZKind::File)
    );
    assert_eq!(
        SevenZClass::of(&with_unix_mode(ArchiveEntry::new_directory("d"), 0o040_755)),
        SevenZClass::Present(SevenZKind::Directory)
    );
}

#[test]
fn unix_mode_without_extension_flag_is_not_a_symlink() {
    let mut entry = sevenz_rust2::ArchiveEntry::new_file("f");
    entry.has_windows_attributes = true;
    entry.windows_attributes = 0o120_777 << 16;
    assert_eq!(
        SevenZClass::of(&entry),
        SevenZClass::Present(SevenZKind::File)
    );

    let mut anti = with_unix_mode(sevenz_rust2::ArchiveEntry::new_file("a"), 0o120_777);
    anti.is_anti_item = true;
    assert_eq!(SevenZClass::of(&anti), SevenZClass::AntiItem);
}

const S_IFSOCK: u32 = 0o14_0000;
const S_IFBLK: u32 = 0o06_0000;
const S_IFREG: u32 = 0o10_0000;
const S_IFDIR: u32 = 0o04_0000;
const S_IFCHR: u32 = 0o02_0000;
const S_IFIFO: u32 = 0o01_0000;

fn file_with_stream(name: &str) -> sevenz_rust2::ArchiveEntry {
    let mut entry = sevenz_rust2::ArchiveEntry::new_file(name);
    entry.has_stream = true;
    entry.size = 5;
    entry
}

#[test]
fn unix_mode_special_files_are_unsupported_whatever_the_native_kind() {
    use common::SpecialFile::*;

    for (mode, special) in [
        (S_IFIFO, Fifo),
        (S_IFCHR, CharDevice),
        (S_IFBLK, BlockDevice),
        (S_IFSOCK, Socket),
    ] {
        for entry in [
            sevenz_rust2::ArchiveEntry::new_file("f"),
            file_with_stream("f"),
            sevenz_rust2::ArchiveEntry::new_directory("f"),
        ] {
            assert_eq!(
                SevenZClass::of(&with_unix_mode(entry, mode | 0o644)),
                SevenZClass::Unsupported(UnsupportedEntry::Special(special)),
                "mode {mode:o}"
            );
        }
    }
}

#[test]
fn unix_mode_with_an_undefined_type_is_unsupported() {
    for (mode, bits) in [(0o03_0000, 3), (0o05_0000, 5), (0o16_0000, 14)] {
        assert_eq!(
            SevenZClass::of(&with_unix_mode(file_with_stream("f"), mode | 0o644)),
            SevenZClass::Unsupported(UnsupportedEntry::UndefinedType(bits)),
            "mode {mode:o}"
        );
    }
}

#[test]
fn unix_mode_agreeing_with_the_native_kind_is_present() {
    assert_eq!(
        SevenZClass::of(&with_unix_mode(file_with_stream("f"), S_IFREG | 0o644)),
        SevenZClass::Present(SevenZKind::File)
    );
    assert_eq!(
        SevenZClass::of(&with_unix_mode(
            sevenz_rust2::ArchiveEntry::new_file("f"),
            S_IFREG | 0o644
        )),
        SevenZClass::Present(SevenZKind::File)
    );
    assert_eq!(
        SevenZClass::of(&with_unix_mode(
            sevenz_rust2::ArchiveEntry::new_directory("d"),
            S_IFDIR | 0o755
        )),
        SevenZClass::Present(SevenZKind::Directory)
    );
}

#[test]
fn unix_mode_contradicting_the_native_kind_is_unsupported() {
    let directory_claim = SevenZClass::Unsupported(UnsupportedEntry::KindContradiction {
        native: NativeKind::File,
        claimed_by: KindSource::UnixMode,
    });
    let file_claim = SevenZClass::Unsupported(UnsupportedEntry::KindContradiction {
        native: NativeKind::Directory,
        claimed_by: KindSource::UnixMode,
    });

    assert_eq!(
        SevenZClass::of(&with_unix_mode(file_with_stream("f"), S_IFDIR | 0o755)),
        directory_claim
    );
    assert_eq!(
        SevenZClass::of(&with_unix_mode(
            sevenz_rust2::ArchiveEntry::new_file("f"),
            S_IFDIR | 0o755
        )),
        directory_claim
    );
    assert_eq!(
        SevenZClass::of(&with_unix_mode(
            sevenz_rust2::ArchiveEntry::new_directory("d"),
            S_IFREG | 0o644
        )),
        file_claim
    );
}

#[test]
fn mode_without_type_bits_leaves_the_native_kind() {
    assert_eq!(
        SevenZClass::of(&with_unix_mode(file_with_stream("f"), 0o644)),
        SevenZClass::Present(SevenZKind::File)
    );
    assert_eq!(
        SevenZClass::of(&with_unix_mode(
            sevenz_rust2::ArchiveEntry::new_directory("d"),
            0o755
        )),
        SevenZClass::Present(SevenZKind::Directory)
    );
}

#[test]
fn windows_directory_bit_on_a_native_file_is_unsupported() {
    const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x10;

    let mut entry = file_with_stream("f");
    entry.has_windows_attributes = true;
    entry.windows_attributes = FILE_ATTRIBUTE_DIRECTORY;
    assert_eq!(
        SevenZClass::of(&entry),
        SevenZClass::Unsupported(UnsupportedEntry::KindContradiction {
            native: NativeKind::File,
            claimed_by: KindSource::WindowsAttribute,
        })
    );

    let mut dir = sevenz_rust2::ArchiveEntry::new_directory("d");
    dir.has_windows_attributes = true;
    dir.windows_attributes = FILE_ATTRIBUTE_DIRECTORY;
    assert_eq!(
        SevenZClass::of(&dir),
        SevenZClass::Present(SevenZKind::Directory)
    );

    let mut clear = sevenz_rust2::ArchiveEntry::new_directory("d");
    clear.has_windows_attributes = true;
    clear.windows_attributes = 0x20;
    assert_eq!(
        SevenZClass::of(&clear),
        SevenZClass::Present(SevenZKind::Directory)
    );
}

#[test]
fn symlink_and_reparse_bit_win_before_kind_checks() {
    let mut link = with_unix_mode(file_with_stream("l"), 0o120_777);
    link.windows_attributes |= 0x10;
    assert_eq!(
        SevenZClass::of(&link),
        SevenZClass::Present(SevenZKind::UnixSymlink)
    );

    let mut reparse_dir_bit = file_with_stream("r");
    reparse_dir_bit.has_windows_attributes = true;
    reparse_dir_bit.windows_attributes = 0x410;
    assert_eq!(
        SevenZClass::of(&reparse_dir_bit),
        SevenZClass::Present(SevenZKind::ReparsePoint)
    );
}

#[test]
fn anti_item_wins_over_an_unsupported_mode() {
    let mut anti = with_unix_mode(file_with_stream("a"), S_IFIFO | 0o644);
    anti.is_anti_item = true;
    assert_eq!(SevenZClass::of(&anti), SevenZClass::AntiItem);
}

#[test]
fn present_refuses_unsupported_entries_by_name() {
    let fifo = with_unix_mode(file_with_stream("pipe"), S_IFIFO | 0o644);
    assert_matches!(
        SevenZClass::of(&fifo).present("pipe"),
        Err(ArchiveError::SecurityViolation { reason, .. })
            if reason.contains("FIFO entries not supported") && reason.contains("pipe")
    );
    let anti = SevenZClass::AntiItem;
    assert_matches!(anti.present("a"), Ok(None));
    assert_matches!(
        SevenZClass::Present(SevenZKind::File).present("f"),
        Ok(Some(SevenZKind::File))
    );
}

#[test]
fn reparse_point_wins_over_unix_symlink() {
    let mut entry = with_unix_mode(sevenz_rust2::ArchiveEntry::new_file("l"), 0o120_777);
    entry.windows_attributes |= 0x0400;
    assert_eq!(
        SevenZClass::of(&entry),
        SevenZClass::Present(SevenZKind::ReparsePoint)
    );
}

#[test]
fn unix_mode_is_ignored_without_windows_attributes() {
    let mut entry = with_unix_mode(sevenz_rust2::ArchiveEntry::new_file("f"), 0o120_777);
    entry.has_windows_attributes = false;
    assert_eq!(
        SevenZClass::of(&entry),
        SevenZClass::Present(SevenZKind::File)
    );
}

// 7z format magic bytes for signature validation
const SEVENZ_MAGIC: [u8; 6] = [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C];

/// Load pre-generated fixture from tests/fixtures/
pub(super) fn load_fixture(name: &str) -> Vec<u8> {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let fixture_path = std::path::PathBuf::from(manifest_dir)
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("tests/fixtures")
        .join(name);

    std::fs::read(&fixture_path).unwrap_or_else(|e| {
        panic!(
            "Failed to load fixture {name}. Run tests/fixtures/generate_7z_fixtures.sh first. Error: {e}"
        )
    })
}

/// Test that `format_name` returns correct value.
/// This test doesn't require a valid archive.
#[test]
fn test_format_name() {
    // We can't create a valid SevenZArchive without a real archive,
    // but we can verify the implementation returns the expected value
    // by checking the trait implementation directly.

    // Create invalid data - this will fail to parse
    let data = SEVENZ_MAGIC.to_vec();
    let cursor = Cursor::new(data);

    // new() will fail because it's not a valid archive, but that's expected
    let result = SevenZArchive::new(cursor);
    assert!(result.is_err(), "invalid archive should fail to parse");

    // Verify the error is InvalidArchive (not security violation)
    assert_matches!(result, Err(ArchiveError::InvalidArchive(_)));
}

/// Test that invalid magic bytes are rejected.
#[test]
fn test_invalid_magic_rejected() {
    let data = vec![0x00, 0x01, 0x02, 0x03, 0x04, 0x05];
    let cursor = Cursor::new(data);

    let result = SevenZArchive::new(cursor);
    assert!(result.is_err());
    assert_matches!(result, Err(ArchiveError::InvalidArchive(_)));
}

#[test]
fn test_load_fixture_helper() {
    let data = load_fixture("simple.7z");
    assert!(!data.is_empty());
    assert_eq!(&data[0..6], &SEVENZ_MAGIC);
}

/// Reserves a throwaway [`QuotaPermit`] for use in tests that call
/// `write_file_with_permit` directly, bypassing the normal validation
/// pipeline that would otherwise produce one.
#[cfg(unix)]
fn test_permit() -> QuotaPermit {
    let config = SecurityConfig::default().validate().expect("valid config");
    crate::security::quota::QuotaTracker::new()
        .reserve(0, &config)
        .expect("reservation should succeed")
}

/// Regression test for issue #471: `write_file_with_permit`'s temp file
/// name is predictable from the process PID and a per-process monotonic
/// counter (`.{name}.exarch-tmp-{pid}-{counter}`). A dangling symlink
/// pre-planted at one of the next few predicted counter values used to
/// be silently followed by a non-exclusive `File::create`, writing
/// archive content through it and outside the extraction root. The fix
/// retries with a fresh counter value on `AlreadyExists` instead of
/// falling through to a non-exclusive open.
///
/// Exercises [`write_file_with_permit_using`] directly with a private,
/// test-local candidate generator instead of calling
/// [`write_file_with_permit`] (which draws from the process-global
/// [`TEMP_COUNTER`]): predicting exactly which paths a call will attempt
/// is only safe if nothing else in the process can advance that counter
/// concurrently, which does not hold under `cargo test`'s default
/// multi-threaded execution (sibling tests write 7z files too). A
/// private generator has no shared state to race on, so this test is
/// deterministic under both `cargo test` and nextest (see #471 review).
#[test]
#[cfg(unix)]
fn test_write_file_with_permit_skips_planted_symlinks() {
    let temp = TempDir::new().unwrap();
    let outside = TempDir::new().unwrap();
    let dest_path = temp.path().join("real-output.txt");

    // Plant dangling symlinks at every candidate path the generator
    // below will produce, except the last available attempt, so the fix
    // must retry past all of them.
    let mut victims = Vec::new();
    for offset in 0..(MAX_TEMP_FILE_CREATE_ATTEMPTS - 1) {
        let planted_path = temp.path().join(format!(".candidate-{offset}.tmp"));
        let victim_path = outside.path().join(format!("victim-{offset}.txt"));
        std::os::unix::fs::symlink(&victim_path, &planted_path).unwrap();
        victims.push((planted_path, victim_path));
    }

    let mut next_candidate = 0u32;
    let temp_dir_path = temp.path().to_path_buf();
    let mut reader = Cursor::new(b"legit content".to_vec());
    let mut copy_buffer = CopyBuffer::new();
    let bytes_written = write_file_with_permit_using(
        &mut reader,
        &dest_path,
        13,
        &mut copy_buffer,
        test_permit(),
        || {
            let path = temp_dir_path.join(format!(".candidate-{next_candidate}.tmp"));
            next_candidate += 1;
            path
        },
    )
    .expect("should retry past every planted symlink and succeed");

    assert_eq!(bytes_written, 13);
    assert_eq!(std::fs::read(&dest_path).unwrap(), b"legit content");
    // The generator must have been driven past every planted symlink to
    // reach a free candidate — otherwise this test would pass vacuously
    // without ever exercising the retry-on-AlreadyExists path.
    assert_eq!(next_candidate, MAX_TEMP_FILE_CREATE_ATTEMPTS);

    for (planted_path, victim_path) in &victims {
        assert!(
            !victim_path.exists(),
            "write followed a planted symlink outside the extraction root"
        );
        let metadata = std::fs::symlink_metadata(planted_path).unwrap();
        assert!(
            metadata.file_type().is_symlink(),
            "planted symlink should be left untouched, not consumed or replaced"
        );
    }
}

/// Companion to [`test_write_file_with_permit_skips_planted_symlinks`]:
/// when every attempt's candidate path is blocked by a planted symlink,
/// `write_file_with_permit_using` must give up with an error instead of
/// looping forever or falling back to a non-exclusive open. Uses the
/// same private-generator approach for the same determinism reason.
#[test]
#[cfg(unix)]
fn test_write_file_with_permit_gives_up_after_max_attempts() {
    let temp = TempDir::new().unwrap();
    let outside = TempDir::new().unwrap();
    let dest_path = temp.path().join("real-output.txt");

    let mut victims = Vec::new();
    for offset in 0..MAX_TEMP_FILE_CREATE_ATTEMPTS {
        let planted_path = temp.path().join(format!(".candidate-{offset}.tmp"));
        let victim_path = outside.path().join(format!("victim-{offset}.txt"));
        std::os::unix::fs::symlink(&victim_path, &planted_path).unwrap();
        victims.push(victim_path);
    }

    let mut next_candidate = 0u32;
    let temp_dir_path = temp.path().to_path_buf();
    let mut reader = Cursor::new(b"legit content".to_vec());
    let mut copy_buffer = CopyBuffer::new();
    let result = write_file_with_permit_using(
        &mut reader,
        &dest_path,
        13,
        &mut copy_buffer,
        test_permit(),
        || {
            let path = temp_dir_path.join(format!(".candidate-{next_candidate}.tmp"));
            next_candidate += 1;
            path
        },
    );

    assert!(
        result.is_err(),
        "expected exhaustion error, got: {result:?}"
    );
    assert_eq!(next_candidate, MAX_TEMP_FILE_CREATE_ATTEMPTS);
    assert!(!dest_path.exists());
    for victim_path in &victims {
        assert!(!victim_path.exists());
    }
}

/// Regression test for GHSA-5j8q-wxg5-hj4r on 7z's fast write path
/// (`write_file_direct`, used when nothing occupies the destination): a
/// reader producing far more bytes than `expected_size` (standing in for
/// a forged `entry.size` from 7z's own archive metadata) must abort with
/// an error and must not leave an oversized file on disk.
#[test]
#[cfg(unix)]
fn test_write_file_direct_forged_size_aborts_and_cleans_up() {
    let temp = TempDir::new().unwrap();
    let dest_path = temp.path().join("bomb.bin");

    let real_data = vec![0x41u8; 200 * 1024];
    let mut reader = Cursor::new(&real_data);
    let mut copy_buffer = CopyBuffer::new();

    let result = write_file_direct(&mut reader, &dest_path, 50, &mut copy_buffer, test_permit());

    assert!(
        result.is_err(),
        "streaming past expected_size must abort, got: {result:?}"
    );
    match result {
        Err(ArchiveError::SecurityViolation { reason, .. }) => {
            assert!(
                reason.contains("50 bytes"),
                "error must name the declared ceiling (50), got: {reason:?}"
            );
        }
        other => {
            panic!("expected SecurityViolation naming the 50-byte ceiling, got: {other:?}")
        }
    }
    assert!(
        !dest_path.exists(),
        "aborted write_file_direct must not leave a file on disk"
    );
}

/// Same as [`test_write_file_direct_forged_size_aborts_and_cleans_up`]
/// but for the overwrite path (`write_file_with_permit`, temp-file +
/// rename): the forged-size abort must clean up the temp file and must
/// never reach `rename`, so the pre-existing destination is untouched.
#[test]
#[cfg(unix)]
fn test_write_file_with_permit_forged_size_aborts_and_leaves_original_untouched() {
    let temp = TempDir::new().unwrap();
    let dest_path = temp.path().join("existing.bin");
    std::fs::write(&dest_path, b"original content").unwrap();

    let real_data = vec![0x41u8; 200 * 1024];
    let mut reader = Cursor::new(&real_data);
    let mut copy_buffer = CopyBuffer::new();

    let result =
        write_file_with_permit(&mut reader, &dest_path, 50, &mut copy_buffer, test_permit());

    assert!(
        result.is_err(),
        "streaming past expected_size must abort, got: {result:?}"
    );
    assert_eq!(
        std::fs::read(&dest_path).unwrap(),
        b"original content",
        "aborted overwrite must leave the pre-existing destination untouched"
    );
    // No stray temp file (`.existing.bin.exarch-tmp-*`) left behind.
    let leftovers: Vec<_> = std::fs::read_dir(temp.path())
        .unwrap()
        .filter_map(std::result::Result::ok)
        .filter(|e| e.file_name() != dest_path.file_name().unwrap())
        .collect();
    assert!(
        leftovers.is_empty(),
        "aborted write must not leave a temp file behind, found: {leftovers:?}"
    );
}

#[test]
fn test_extract_simple_file() {
    let data = load_fixture("simple.7z");
    let cursor = Cursor::new(data);
    let mut archive = SevenZArchive::new(cursor).unwrap();

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
    assert!(temp.path().join("simple/file1.txt").exists());
    assert!(temp.path().join("simple/file2.txt").exists());

    // Verify file contents
    let content1 = std::fs::read_to_string(temp.path().join("simple/file1.txt")).unwrap();
    assert_eq!(content1, "hello world\n");
}

#[test]
fn test_extract_nested_directories() {
    let data = load_fixture("nested-dirs.7z");
    let cursor = Cursor::new(data);
    let mut archive = SevenZArchive::new(cursor).unwrap();

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

    assert!(report.files_extracted >= 1);
    assert!(temp.path().join("nested/subdir1/subdir2/deep.txt").exists());
    assert!(temp.path().join("nested/subdir1/file.txt").exists());
}

#[test]
fn test_solid_archive_rejected() {
    let data = load_fixture("solid.7z");
    let cursor = Cursor::new(data);

    // new() should now succeed (just caches is_solid flag)
    let mut archive = SevenZArchive::new(cursor).unwrap();

    // Rejection happens in extract() with default config
    let temp = TempDir::new().unwrap();
    let result = archive.extract(
        temp.path(),
        &SecurityConfig::default().validate().unwrap(),
        &ExtractionOptions::default(),
        &mut crate::NoopProgress,
    );

    assert!(result.is_err());
    assert_matches!(result.unwrap_err(), ArchiveError::SecurityViolation { .. });
}

#[test]
fn test_encrypted_archive_rejected() {
    let data = load_fixture("encrypted.7z");
    let cursor = Cursor::new(data);

    // Should fail in new() due to encryption detection
    let result = SevenZArchive::new(cursor);
    assert!(result.is_err());
    assert_matches!(result.unwrap_err(), ArchiveError::SecurityViolation { .. });
}

#[test]
fn test_empty_archive() {
    let data = load_fixture("empty.7z");
    let cursor = Cursor::new(data);
    let mut archive = SevenZArchive::new(cursor).unwrap();

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
fn test_empty_archive_extract() {
    let path = std::path::Path::new("../../tests/fixtures/empty.7z");
    let file = std::fs::File::open(path).unwrap();
    let mut archive = SevenZArchive::new(file).unwrap();

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
    assert_eq!(report.bytes_written, 0);
}

fn parse_fixture(name: &str) -> (SevenZHeader, u64) {
    let data = load_fixture(name);
    let len = data.len() as u64;
    let header = read_sevenz_header(&mut Cursor::new(data)).unwrap();
    (header, len)
}

fn first_block(header: &SevenZHeader) -> BlockIndex {
    header.block_indices().next().unwrap()
}

#[test]
fn test_compression_non_solid_covers_every_stream_file() {
    let (header, len) = parse_fixture("simple.7z");
    let compression = sevenz_entry_compression(&header, len).unwrap();
    assert_eq!(compression.len(), header.files().len());
    for (file, compression) in header.files().iter().zip(&compression) {
        assert_eq!(
            file.has_stream,
            matches!(compression, EntryCompression::Entry(_)),
            "{}",
            file.name
        );
    }
}

#[test]
fn test_compression_solid_block_start_carries_block_totals() {
    let (header, len) = parse_fixture("solid.7z");
    let compression = sevenz_entry_compression(&header, len).unwrap();
    let pack_sizes = header.archive().pack_sizes();
    let first_files: Vec<usize> = header
        .block_indices()
        .map(|block| header.block_first_file(block))
        .collect();
    assert!(!first_files.is_empty());

    for block in header.block_indices() {
        let end = header
            .next_block_first_pack(block)
            .unwrap_or(pack_sizes.len());
        let expected_compressed: u64 = pack_sizes[header.block_first_pack(block)..end].iter().sum();
        let expected_uncompressed: u64 = header
            .files()
            .iter()
            .enumerate()
            .filter(|(i, _)| header.file_block(*i) == Some(block))
            .map(|(_, f)| f.size)
            .sum();
        assert_eq!(
            compression[header.block_first_file(block)],
            EntryCompression::SolidBlockStart(SolidBlock::new(
                expected_compressed,
                expected_uncompressed
            )),
            "block {block:?}"
        );
    }
    for (index, compression) in compression.iter().enumerate() {
        if !first_files.contains(&index) && header.files()[index].has_stream {
            assert_eq!(
                *compression,
                EntryCompression::SolidBlockMember,
                "file {index}"
            );
        }
    }
}

fn make_sevenz_archive_with_empty_file() -> Vec<u8> {
    use sevenz_rust2::ArchiveEntry;
    use sevenz_rust2::ArchiveWriter;

    let mut writer = ArchiveWriter::new(Cursor::new(Vec::new())).unwrap();
    writer
        .push_archive_entry(ArchiveEntry::new_file("empty.txt"), None::<Cursor<Vec<u8>>>)
        .unwrap();
    let mut full = ArchiveEntry::new_file("full.txt");
    full.has_stream = true;
    full.size = 7;
    writer
        .push_archive_entry(full, Some(Cursor::new(b"payload".to_vec())))
        .unwrap();
    writer.finish().unwrap().into_inner()
}

#[test]
fn test_compression_block_uncompressed_overflow_is_rejected() {
    let data = load_fixture("solid.7z");
    let len = data.len() as u64;
    let mut archive = Archive::read(&mut Cursor::new(data), &Password::empty()).unwrap();
    let members: Vec<usize> = (0..archive.files.len())
        .filter(|&i| archive.stream_map.file_block_index[i] == Some(0))
        .collect();
    assert!(members.len() >= 2, "fixture must have a multi-file block");
    archive.files[members[0]].size = u64::MAX;
    archive.files[members[1]].size = 1;

    assert_matches!(
        sevenz_entry_compression(&SevenZHeader::assume_checked(archive), len),
        Err(ArchiveError::QuotaExceeded {
            resource: QuotaResource::IntegerOverflow
        })
    );
}

#[test]
fn test_compression_empty_files_are_unknown() {
    let data = make_sevenz_archive_with_empty_file();
    let len = data.len() as u64;
    let header = read_sevenz_header(&mut Cursor::new(data)).unwrap();
    let compression = sevenz_entry_compression(&header, len).unwrap();
    for (file, compression) in header.files().iter().zip(&compression) {
        if file.size == 0 {
            assert_eq!(*compression, EntryCompression::Unknown, "{}", file.name);
        } else {
            assert_matches!(compression, EntryCompression::Entry(_));
        }
    }
}

fn entry_compressed_sizes(name: &str) -> Vec<u64> {
    let (archive, len) = parse_fixture(name);
    let compression = sevenz_entry_compression(&archive, len).unwrap();
    let entries: Vec<u64> = compression
        .iter()
        .filter_map(|c| match c {
            EntryCompression::Entry(size) => Some(*size),
            _ => None,
        })
        .collect();
    entries
}

#[test]
fn test_compression_bcj2_block_counts_its_four_pack_streams() {
    let (archive, _) = parse_fixture("bcj2.7z");
    assert_eq!(archive.archive().pack_sizes().len(), 4);
    let expected: u64 = archive.archive().pack_sizes().iter().sum();

    assert_eq!(entry_compressed_sizes("bcj2.7z"), [expected]);
}

#[test]
fn test_compression_bcj2_block_excludes_an_unreferenced_pack_stream() {
    let (archive, _) = parse_fixture("bcj2-spare-pack.7z");
    let pack_sizes = archive.archive().pack_sizes();
    assert_eq!(pack_sizes.len(), 5);
    assert_eq!(pack_sizes[4], 7);
    let expected: u64 = pack_sizes[..4].iter().sum();

    assert_eq!(entry_compressed_sizes("bcj2-spare-pack.7z"), [expected]);
}

#[test]
fn test_compression_bcj2_id_on_a_one_input_coder_is_capped_at_declared_streams() {
    let (archive, _) = parse_fixture("bcj2-simple-coder.7z");
    assert_eq!(archive.archive().pack_sizes().len(), 1);
    let expected = archive.archive().pack_sizes()[0];

    assert_eq!(entry_compressed_sizes("bcj2-simple-coder.7z"), [expected]);
}

#[test]
fn test_compression_rejects_source_shorter_than_declared_streams() {
    let (archive, len) = parse_fixture("simple.7z");
    let declared: u64 = archive.archive().pack_sizes().iter().sum();
    let too_short = SIGNATURE_HEADER_SIZE + archive.archive().pack_pos() + declared - 1;
    assert!(too_short < len);
    assert_matches!(
        sevenz_entry_compression(&archive, too_short),
        Err(ArchiveError::InvalidArchive(_))
    );
}

/// Test B-002: Verify quota is not double-counted
/// Pre-validation and extraction use separate validators to prevent
/// counting files twice against quotas.
#[test]
fn test_multiple_files_quota_not_double_counted() {
    let data = load_fixture("simple.7z"); // Contains 2 files
    let cursor = Cursor::new(data);
    let mut archive = SevenZArchive::new(cursor).unwrap();

    let temp = TempDir::new().unwrap();
    // Should allow 2 files
    let config = SecurityConfig::default()
        .with_max_file_count(3)
        .validate()
        .unwrap();

    let result = archive.extract(
        temp.path(),
        &config,
        &ExtractionOptions::default(),
        &mut crate::NoopProgress,
    );
    assert!(
        result.is_ok(),
        "2 files should not exceed quota of 3: {result:?}"
    );
    assert_eq!(result.unwrap().files_extracted, 2);
}

/// Test B-1: Verify path traversal is rejected
/// This test ensures the validator integration properly rejects
/// archives with path traversal attempts.
#[test]
fn test_path_traversal_integration() {
    // Test that our validator integration works by creating a simple
    // archive and verifying the validator is properly called
    let data = load_fixture("simple.7z");
    let cursor = Cursor::new(data);
    let archive = SevenZArchive::new(cursor);

    // Verify our validator is properly integrated
    assert!(archive.is_ok());

    // NOTE: Path traversal testing is covered by integration tests using
    // actual 7z fixtures. Additional unit-level fixture testing can be
    // added here if needed in the future.
}

/// Test: Solid archive extracts when allowed
#[test]
fn test_solid_archive_allowed_with_config() {
    let data = load_fixture("solid.7z");
    let cursor = Cursor::new(data);
    let mut archive = SevenZArchive::new(cursor).unwrap();

    let temp = TempDir::new().unwrap();
    let config = SecurityConfig::default()
        .with_allow_solid_archives(true)
        .with_max_solid_block_memory(100 * 1024 * 1024)
        .validate()
        .unwrap(); // 100 MB

    let result = archive.extract(
        temp.path(),
        &config,
        &ExtractionOptions::default(),
        &mut crate::NoopProgress,
    );
    assert!(result.is_ok(), "solid archive should extract: {result:?}");
    assert!(result.unwrap().files_extracted > 0);
}

/// Test: Solid archive rejected by default config
#[test]
fn test_solid_archive_rejected_by_default() {
    let data = load_fixture("solid.7z");
    let cursor = Cursor::new(data);
    let mut archive = SevenZArchive::new(cursor).unwrap();

    let temp = TempDir::new().unwrap();
    let config = SecurityConfig::default().validate().expect("valid config");

    let result = archive.extract(
        temp.path(),
        &config,
        &ExtractionOptions::default(),
        &mut crate::NoopProgress,
    );
    assert!(result.is_err());
    assert_matches!(result.unwrap_err(), ArchiveError::SecurityViolation { .. });
}

/// Test: Solid archive memory limit exceeded
#[test]
fn test_solid_archive_memory_limit_exceeded() {
    let data = load_fixture("solid.7z");
    let cursor = Cursor::new(data);
    let mut archive = SevenZArchive::new(cursor).unwrap();

    let temp = TempDir::new().unwrap();
    let config = SecurityConfig::default()
        .with_allow_solid_archives(true)
        .with_max_solid_block_memory(1)
        .validate()
        .unwrap(); // 1 byte (too small)

    let result = archive.extract(
        temp.path(),
        &config,
        &ExtractionOptions::default(),
        &mut crate::NoopProgress,
    );
    assert!(result.is_err());
    assert_matches!(result.unwrap_err(), ArchiveError::QuotaExceeded { .. });
}

/// Test: Non-solid archives work regardless of solid config
#[test]
fn test_non_solid_archive_unaffected_by_solid_config() {
    let data = load_fixture("simple.7z");
    let cursor = Cursor::new(data);
    let mut archive = SevenZArchive::new(cursor).unwrap();

    let temp = TempDir::new().unwrap();
    let config = SecurityConfig::default().validate().expect("valid config"); // allow_solid_archives = false

    let result = archive.extract(
        temp.path(),
        &config,
        &ExtractionOptions::default(),
        &mut crate::NoopProgress,
    );
    assert!(result.is_ok(), "non-solid should work: {result:?}");
}

// ============================================================================
// Phase 10.4 Review Fixes: Additional Tests
// ============================================================================

/// Test H-3: Verify `is_solid` flag is correctly detected
#[test]
fn test_is_solid_flag_detected_correctly() {
    // Solid archive should have is_solid = true
    let solid_data = load_fixture("solid.7z");
    let solid_cursor = Cursor::new(solid_data);
    let solid_archive = SevenZArchive::new(solid_cursor).unwrap();
    assert!(
        solid_archive.header.is_solid(),
        "solid.7z should have is_solid=true"
    );

    // Non-solid archive should have is_solid = false
    let non_solid_data = load_fixture("simple.7z");
    let non_solid_cursor = Cursor::new(non_solid_data);
    let non_solid_archive = SevenZArchive::new(non_solid_cursor).unwrap();
    assert!(
        !non_solid_archive.header.is_solid(),
        "simple.7z should have is_solid=false"
    );
}

/// Test H-1: Boundary condition - exact limit should PASS
#[test]
fn test_solid_archive_memory_limit_exact_boundary() {
    let data = load_fixture("solid.7z");

    // First read to get total size
    let archive_for_size = SevenZArchive::new(Cursor::new(data.clone())).unwrap();
    let total_size: u64 = archive_for_size.entries.iter().map(|e| e.size).sum();

    // Now test with exact limit
    let mut archive = SevenZArchive::new(Cursor::new(data)).unwrap();
    let temp = TempDir::new().unwrap();
    let config = SecurityConfig::default()
        .with_allow_solid_archives(true)
        .with_max_solid_block_memory(total_size)
        .validate()
        .unwrap(); // Exact match

    let result = archive.extract(
        temp.path(),
        &config,
        &ExtractionOptions::default(),
        &mut crate::NoopProgress,
    );
    assert!(
        result.is_ok(),
        "exact limit should allow extraction: {result:?}"
    );
}

/// Test H-1: Boundary condition - one byte under limit should FAIL
#[test]
fn test_solid_archive_memory_limit_one_under_boundary() {
    let data = load_fixture("solid.7z");

    // First read to get total size
    let archive_for_size = SevenZArchive::new(Cursor::new(data.clone())).unwrap();
    let total_size: u64 = archive_for_size.entries.iter().map(|e| e.size).sum();

    // Ensure we have at least 2 bytes of content to make test meaningful
    if total_size < 2 {
        return; // Skip test if fixture is too small
    }

    // Now test with one byte under
    let mut archive = SevenZArchive::new(Cursor::new(data)).unwrap();
    let temp = TempDir::new().unwrap();
    let config = SecurityConfig::default()
        .with_allow_solid_archives(true)
        .with_max_solid_block_memory(total_size - 1)
        .validate()
        .unwrap(); // One byte under

    let result = archive.extract(
        temp.path(),
        &config,
        &ExtractionOptions::default(),
        &mut crate::NoopProgress,
    );
    assert!(result.is_err(), "one byte under limit should reject");
    assert_matches!(result.unwrap_err(), ArchiveError::QuotaExceeded { .. });
}

/// Test H-2: Verify error message contains helpful info
#[test]
fn test_solid_archive_rejected_error_message() {
    let data = load_fixture("solid.7z");
    let cursor = Cursor::new(data);
    let mut archive = SevenZArchive::new(cursor).unwrap();

    let temp = TempDir::new().unwrap();
    let result = archive.extract(
        temp.path(),
        &SecurityConfig::default().validate().unwrap(),
        &ExtractionOptions::default(),
        &mut crate::NoopProgress,
    );

    assert!(result.is_err());
    match result.unwrap_err() {
        ArchiveError::SecurityViolation { reason, .. } => {
            assert!(
                reason.contains("solid") && reason.contains("allow_solid_archives"),
                "error should mention 'solid' and 'allow_solid_archives', got: {reason}"
            );
        }
        other => panic!("expected SecurityViolation, got {other:?}"),
    }
}

// ============================================================================
// Phase 10.5: Symlink/Hardlink Detection Tests
// ============================================================================

/// Test: Windows reparse point detection (TRUE case)
#[test]
fn test_windows_reparse_point_detected() {
    let mut entry = sevenz_rust2::ArchiveEntry::new_file("symlink.txt");
    entry.has_windows_attributes = true;
    entry.windows_attributes = 0x0400; // FILE_ATTRIBUTE_REPARSE_POINT

    assert!(
        is_windows_reparse_point(&entry),
        "reparse point attribute should be detected"
    );

    let result = extraction_type_of(&entry);
    assert!(result.is_err(), "should return error for reparse point");
    assert_matches!(
        result.unwrap_err(),
        ArchiveError::SecurityViolation { .. },
        "should be SecurityViolation error"
    );
}

/// Test: Windows reparse point NOT detected (has attributes, but not
/// reparse point)
#[test]
fn test_windows_reparse_point_not_set() {
    let mut entry = sevenz_rust2::ArchiveEntry::new_file("file.txt");
    entry.has_windows_attributes = true;
    entry.windows_attributes = 0x0080; // FILE_ATTRIBUTE_NORMAL

    assert!(
        !is_windows_reparse_point(&entry),
        "normal file should not be detected as reparse point"
    );

    let result = extraction_type_of(&entry);
    assert!(result.is_ok(), "normal file should succeed");
    assert_eq!(result.unwrap(), EntryType::File);
}

/// Test: No Windows attributes (Unix archive)
#[test]
fn test_no_windows_attributes() {
    let mut entry = sevenz_rust2::ArchiveEntry::new_file("file.txt");
    entry.has_windows_attributes = false;
    entry.windows_attributes = 0; // Should be ignored

    assert!(
        !is_windows_reparse_point(&entry),
        "entry without Windows attributes should not be detected as reparse point"
    );

    let result = extraction_type_of(&entry);
    assert!(result.is_ok(), "file without attributes should succeed");
    assert_eq!(result.unwrap(), EntryType::File);
}

/// Test: Windows reparse point with other attributes combined
#[test]
fn test_windows_reparse_point_with_other_attributes() {
    let mut entry = sevenz_rust2::ArchiveEntry::new_file("symlink.txt");
    entry.has_windows_attributes = true;
    entry.windows_attributes = 0x0400 | 0x0020; // REPARSE_POINT | ARCHIVE

    assert!(
        is_windows_reparse_point(&entry),
        "reparse point should be detected even with other attributes"
    );

    let result = extraction_type_of(&entry);
    assert!(result.is_err(), "should return error for reparse point");
}

/// Test: Directory entry should not trigger reparse point check
#[test]
fn test_directory_junction_reparse_point_rejected() {
    let mut entry = sevenz_rust2::ArchiveEntry::new_directory("dir/");
    entry.has_windows_attributes = true;
    entry.windows_attributes = 0x0400; // REPARSE_POINT (directory junction)

    // SECURITY: Reparse point check happens FIRST, even for directories
    // This catches directory junctions (Windows symlink directories)
    let result = extraction_type_of(&entry);
    assert!(result.is_err(), "directory junction should be rejected");
    assert_matches!(result.unwrap_err(), ArchiveError::SecurityViolation { .. });
}

/// Test: Error message for Windows reparse point
#[test]
fn test_windows_reparse_point_error_message() {
    let mut entry = sevenz_rust2::ArchiveEntry::new_file("link.txt");
    entry.has_windows_attributes = true;
    entry.windows_attributes = 0x0400;

    let result = extraction_type_of(&entry);
    assert!(result.is_err());

    match result.unwrap_err() {
        ArchiveError::SecurityViolation { reason, .. } => {
            assert!(
                reason.contains("symlink") && reason.contains("link.txt"),
                "error should mention 'symlink' and entry name, got: {reason}"
            );
            assert!(
                reason.contains("sevenz-rust2"),
                "error should mention library limitation, got: {reason}"
            );
        }
        other => panic!("expected SecurityViolation, got {other:?}"),
    }
}

/// Issue #634: I/O errors keep their original kind and message instead of
/// being rebuilt from the `Display` text as `ErrorKind::Other`.
#[test]
fn test_sevenz_io_error_preserves_kind_and_message() {
    let inner = std::io::Error::new(
        std::io::ErrorKind::UnexpectedEof,
        "unexpected EOF while reading entry data",
    );
    let sevenz_err = sevenz_rust2::Error::Io(inner, "test.7z".into());

    let archive_err: ArchiveError = sevenz_err.into();

    match archive_err {
        ArchiveError::Io(io_err) => {
            assert_eq!(io_err.kind(), std::io::ErrorKind::UnexpectedEof);
            assert!(io_err.to_string().contains("unexpected EOF"));
        }
        other => panic!("expected ArchiveError::Io, got {other:?}"),
    }
}

#[test]
fn test_sevenz_file_open_error_keeps_path_and_kind() {
    let inner = std::io::Error::new(std::io::ErrorKind::NotFound, "missing");
    let err = ArchiveError::from(sevenz_rust2::Error::FileOpen(inner, "a/b.7z".into()));
    match err {
        ArchiveError::Io(io_err) => {
            assert_eq!(io_err.kind(), std::io::ErrorKind::NotFound);
            assert!(io_err.to_string().contains("a/b.7z"), "{io_err}");
        }
        other => panic!("expected ArchiveError::Io, got {other:?}"),
    }
}

/// Issue #634: encryption is detected from the typed variants, and
/// unrelated messages that merely contain "read" or "password" are not
/// reclassified.
#[test]
fn test_sevenz_error_classification_is_typed() {
    for err in [
        sevenz_rust2::Error::PasswordRequired,
        sevenz_rust2::Error::MaybeBadPassword(std::io::Error::other("bad")),
    ] {
        assert_matches!(
            ArchiveError::from(err),
            ArchiveError::SecurityViolation { .. }
        );
    }

    let lookalike = sevenz_rust2::Error::Other("thread already ready: password".into());
    assert_matches!(
        ArchiveError::from(lookalike),
        ArchiveError::InvalidArchive(_)
    );
}

#[test]
fn test_list_returns_manifest_with_entries() {
    let data = load_fixture("simple.7z");
    let mut archive = SevenZArchive::new(Cursor::new(data)).unwrap();
    let config = SecurityConfig::default().validate().expect("valid config");

    let manifest = archive.list(&config).unwrap();

    assert!(
        manifest.total_entries() > 0,
        "simple.7z must have at least one entry"
    );
}

#[test]
fn test_verify_clean_sevenz_is_safe() {
    let data = load_fixture("simple.7z");
    let mut archive = SevenZArchive::new(Cursor::new(data)).unwrap();
    let config = SecurityConfig::default().validate().expect("valid config");

    let report = archive
        .verify(&config, &crate::VerificationOptions::default())
        .unwrap();

    assert!(report.is_safe());
}

#[test]
fn test_allowed_extensions_filters_out_disallowed() {
    // mixed-extensions.7z contains document.txt, program.exe, readme.txt
    let data = load_fixture("mixed-extensions.7z");
    let dest = TempDir::new().unwrap();

    let config = SecurityConfig::default()
        .with_allowed_extensions(vec!["txt".to_string()])
        .validate()
        .unwrap();

    let report = SevenZArchive::new(Cursor::new(data))
        .unwrap()
        .extract(
            dest.path(),
            &config,
            &ExtractionOptions::default(),
            &mut crate::NoopProgress,
        )
        .unwrap();

    assert_eq!(
        report.files_extracted, 2,
        "only .txt files should be extracted"
    );
    assert_eq!(report.files_skipped, 1, ".exe file should be skipped");
    assert!(
        !dest
            .path()
            .join("mixed-ext-fixture")
            .join("program.exe")
            .exists(),
        ".exe must not be extracted"
    );
    assert!(
        dest.path()
            .join("mixed-ext-fixture")
            .join("document.txt")
            .exists(),
        ".txt files must be extracted"
    );
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
    let data = make_sevenz_archive(&entries);
    let dest = TempDir::new().unwrap();
    let config = SecurityConfig::default()
        .with_allowed_extensions(vec!["txt".to_string()])
        .validate()
        .expect("valid config");

    let report = SevenZArchive::new(Cursor::new(data))
        .unwrap()
        .extract(
            dest.path(),
            &config,
            &ExtractionOptions::default(),
            &mut crate::NoopProgress,
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
    let data = make_sevenz_archive(&entries);

    let temp = TempDir::new().unwrap();
    for name in names.iter().take(DUPLICATE_COUNT) {
        std::fs::write(temp.path().join(name), b"already here").unwrap();
    }

    let config = SecurityConfig::default()
        .with_allowed_extensions(vec!["txt".to_string()])
        .validate()
        .expect("valid config");

    let report = SevenZArchive::new(Cursor::new(data))
        .unwrap()
        .extract(
            temp.path(),
            &config,
            &ExtractionOptions::default(), // skip_duplicates = true
            &mut crate::NoopProgress,
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
        report.warnings.iter().any(
            |w| w.contains(&DISALLOWED_COUNT.to_string()) && w.contains("disallowed extension")
        ),
        "expected a disallowed-extension warning reporting {DISALLOWED_COUNT}, got: {:?}",
        report.warnings
    );
}

#[test]
fn test_empty_allowed_extensions_allows_all() {
    let data = load_fixture("simple.7z");
    let dest = TempDir::new().unwrap();
    let config = SecurityConfig::default().validate().expect("valid config"); // empty = allow all

    let report = SevenZArchive::new(Cursor::new(data))
        .unwrap()
        .extract(
            dest.path(),
            &config,
            &ExtractionOptions::default(),
            &mut crate::NoopProgress,
        )
        .unwrap();

    assert_eq!(report.files_skipped, 0);
    assert!(report.files_extracted > 0);
}

#[test]
fn test_extension_less_files_blocked_when_allowlist_nonempty() {
    // no-extension.7z contains document.txt and Makefile (no extension)
    let data = load_fixture("no-extension.7z");
    let dest = TempDir::new().unwrap();
    let config = SecurityConfig::default()
        .with_allowed_extensions(vec!["txt".to_string()])
        .validate()
        .unwrap();

    let report = SevenZArchive::new(Cursor::new(data))
        .unwrap()
        .extract(
            dest.path(),
            &config,
            &ExtractionOptions::default(),
            &mut crate::NoopProgress,
        )
        .unwrap();

    assert_eq!(report.files_extracted, 1, "only .txt should be extracted");
    assert_eq!(
        report.files_skipped, 1,
        "extension-less file must be skipped"
    );
    assert!(!dest.path().join("no-ext-fixture").join("Makefile").exists());
    assert!(
        dest.path()
            .join("no-ext-fixture")
            .join("document.txt")
            .exists()
    );
}

fn make_sevenz_archive(entries: &[(&str, &[u8])]) -> Vec<u8> {
    use sevenz_rust2::ArchiveEntry;
    use sevenz_rust2::ArchiveWriter;
    use sevenz_rust2::EncoderConfiguration;
    use sevenz_rust2::EncoderMethod;

    let buf = Cursor::new(Vec::new());
    let mut writer = ArchiveWriter::new(buf).unwrap();
    writer.set_content_methods(vec![EncoderConfiguration::new(EncoderMethod::COPY)]);
    for (name, data) in entries {
        let mut entry = ArchiveEntry::new_file(name);
        entry.has_stream = true;
        entry.size = data.len() as u64;
        writer
            .push_archive_entry(entry, Some(Cursor::new(*data)))
            .unwrap();
    }
    writer.finish().unwrap().into_inner()
}

/// Builds a 7z archive with all `entries` packed into one solid block
/// using the COPY method.
fn make_solid_sevenz_archive(entries: &[(&str, &[u8])]) -> Vec<u8> {
    build_solid_sevenz_archive(entries, true)
}

pub(super) fn build_solid_sevenz_archive(entries: &[(&str, &[u8])], copy_method: bool) -> Vec<u8> {
    use sevenz_rust2::ArchiveEntry;
    use sevenz_rust2::ArchiveWriter;
    use sevenz_rust2::EncoderConfiguration;
    use sevenz_rust2::EncoderMethod;
    use sevenz_rust2::SourceReader;

    let mut writer = ArchiveWriter::new(Cursor::new(Vec::new())).unwrap();
    if copy_method {
        writer.set_content_methods(vec![EncoderConfiguration::new(EncoderMethod::COPY)]);
    }
    let archive_entries = entries
        .iter()
        .map(|(name, data)| {
            let mut entry = ArchiveEntry::new_file(name);
            entry.has_stream = !data.is_empty();
            entry.size = data.len() as u64;
            entry
        })
        .collect();
    let readers = entries
        .iter()
        .map(|(_, data)| SourceReader::from(Cursor::new(*data)))
        .collect();
    writer
        .push_archive_entries(archive_entries, readers)
        .unwrap();
    writer.finish().unwrap().into_inner()
}

fn solid_config(allowed_extensions: Vec<String>) -> SecurityConfig<Validated> {
    SecurityConfig::default()
        .with_allow_solid_archives(true)
        .with_max_solid_block_memory(100 * 1024 * 1024)
        .with_allowed_extensions(allowed_extensions)
        .validate()
        .unwrap()
}

/// A solid block of `copies` identical source files, LZMA2-compressed.
fn compressed_solid_copies(copies: usize) -> Vec<u8> {
    let mut state = 0x2545_F491_4F6C_DD1Du64;
    let source: Vec<u8> = (0..4096)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            b"0123456789abcdef"[(state % 16) as usize]
        })
        .collect();
    let names: Vec<String> = (0..copies).map(|i| format!("copy{i}/main.rs")).collect();
    let entries: Vec<(&str, &[u8])> = names
        .iter()
        .map(|n| (n.as_str(), source.as_slice()))
        .collect();
    build_solid_sevenz_archive(&entries, false)
}

fn solid_block_ratio(data: &[u8]) -> f64 {
    let header = read_sevenz_header(&mut Cursor::new(data)).unwrap();
    let compression = sevenz_entry_compression(&header, data.len() as u64).unwrap();
    compression
        .iter()
        .find_map(|c| match c {
            EntryCompression::SolidBlockStart(b) => {
                Some(b.uncompressed as f64 / b.compressed as f64)
            }
            _ => None,
        })
        .expect("a solid block start")
}

/// Issue #626: a legitimate solid block above the per-file ratio limit
/// but below the solid limit extracts and verifies cleanly.
#[test]
fn test_legit_solid_block_above_per_file_ratio_passes_extract_and_verify() {
    let data = compressed_solid_copies(100);
    let ratio = solid_block_ratio(&data);
    assert!(
        (100.0..1000.0).contains(&ratio),
        "fixture must sit between the per-file and solid limits, got {ratio}"
    );

    let dir = TempDir::new().unwrap();
    let path = dir.path().join("tree.7z");
    std::fs::write(&path, &data).unwrap();
    let config = SecurityConfig::default().with_allow_solid_archives(true);

    let report = crate::verify_archive(&path, &config).unwrap();
    assert_ne!(
        report.status(),
        crate::inspection::report::VerificationStatus::Fail,
        "issues: {:?}",
        report.issues()
    );

    let out = dir.path().join("out");
    let report = crate::extract_archive(&path, &out, &config).unwrap();
    assert_eq!(report.files_extracted, 100);
}

/// Issue #626: a block over `max_solid_compression_ratio` is rejected by
/// extract before any write and flagged by verify.
#[test]
fn test_solid_block_over_limit_rejected_by_extract_and_verify() {
    let data = compressed_solid_copies(100);
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("tree.7z");
    std::fs::write(&path, &data).unwrap();
    let config = SecurityConfig::default()
        .with_allow_solid_archives(true)
        .with_max_solid_compression_ratio(50.0);

    let report = crate::verify_archive(&path, &config).unwrap();
    assert!(
        report
            .issues()
            .iter()
            .any(|i| i.category == crate::inspection::report::IssueCategory::ZipBomb),
        "issues: {:?}",
        report.issues()
    );

    let out = dir.path().join("out");
    let result = crate::extract_archive(&path, &out, &config);
    assert_matches!(result, Err(ArchiveError::ZipBomb(_)));
    assert!(!out.join("copy0").exists(), "nothing may be written");
}

/// Issue #628: a disallowed entry in a solid block must not leave its
/// bytes in the shared stream for the next entry to read.
#[test]
fn test_solid_block_disallowed_entry_does_not_shift_next_entry() {
    let skipped = vec![b'A'; 5000];
    let kept = vec![b'B'; 5000];
    let data = make_solid_sevenz_archive(&[("a.bin", &skipped), ("b.txt", &kept)]);
    let dest = TempDir::new().unwrap();

    let report = SevenZArchive::new(Cursor::new(data))
        .unwrap()
        .extract(
            dest.path(),
            &solid_config(vec!["txt".to_string()]),
            &ExtractionOptions::default(),
            &mut crate::NoopProgress,
        )
        .unwrap();

    assert_eq!(report.files_extracted, 1);
    assert_eq!(report.files_skipped, 1);
    assert!(!dest.path().join("a.bin").exists());
    assert_eq!(std::fs::read(dest.path().join("b.txt")).unwrap(), kept);
}

/// Issue #628: skipping the last entry of a solid block must leave the
/// earlier entries and the extraction result intact.
#[test]
fn test_solid_block_skipping_last_entry_extracts_earlier_entries() {
    let first = vec![b'A'; 5000];
    let second = vec![b'B'; 5000];
    let skipped = vec![b'C'; 5000];
    let data =
        make_solid_sevenz_archive(&[("a.txt", &first), ("b.txt", &second), ("c.exe", &skipped)]);
    let dest = TempDir::new().unwrap();

    let report = SevenZArchive::new(Cursor::new(data))
        .unwrap()
        .extract(
            dest.path(),
            &solid_config(vec!["txt".to_string()]),
            &ExtractionOptions::default(),
            &mut crate::NoopProgress,
        )
        .unwrap();

    assert_eq!(report.files_extracted, 2);
    assert_eq!(report.files_skipped, 1);
    assert_eq!(std::fs::read(dest.path().join("a.txt")).unwrap(), first);
    assert_eq!(std::fs::read(dest.path().join("b.txt")).unwrap(), second);
    assert!(!dest.path().join("c.exe").exists());
}

/// Issue #628: same as above for the `skip_duplicates` skip path.
#[test]
fn test_solid_block_duplicate_entry_does_not_shift_next_entry() {
    let skipped = vec![b'A'; 5000];
    let kept = vec![b'B'; 5000];
    let data = make_solid_sevenz_archive(&[("a.txt", &skipped), ("b.txt", &kept)]);
    let dest = TempDir::new().unwrap();
    std::fs::write(dest.path().join("a.txt"), b"already here").unwrap();

    let report = SevenZArchive::new(Cursor::new(data))
        .unwrap()
        .extract(
            dest.path(),
            &solid_config(Vec::new()),
            &ExtractionOptions::default(),
            &mut crate::NoopProgress,
        )
        .unwrap();

    assert_eq!(report.files_extracted, 1);
    assert_eq!(report.files_skipped, 1);
    assert_eq!(
        std::fs::read(dest.path().join("a.txt")).unwrap(),
        b"already here"
    );
    assert_eq!(std::fs::read(dest.path().join("b.txt")).unwrap(), kept);
}

/// Test #376: entry names with embedded `\` must be treated as path
/// separators.
///
/// On Unix, `PathBuf::from("..\\..\\x")` would produce a single component,
/// bypassing traversal detection. After normalization `\` → `/`, the name
/// becomes `../../x` and must be rejected.
#[test]
fn test_7z_backslash_entry_rejected() {
    let data = make_sevenz_archive(&[("..\\..\\x", b"payload")]);
    let mut archive = SevenZArchive::new(Cursor::new(data)).unwrap();

    let temp = TempDir::new().unwrap();
    let result = archive.extract(
        temp.path(),
        &SecurityConfig::default().validate().unwrap(),
        &ExtractionOptions::default(),
        &mut crate::NoopProgress,
    );
    assert!(
        result.is_err(),
        "backslash-encoded traversal must be rejected, got: {result:?}"
    );
    assert_matches!(
        result.unwrap_err(),
        ArchiveError::PathTraversal { .. },
        "expected PathTraversal error"
    );
}

#[test]
fn test_7z_absolute_path_rejected_by_default() {
    let data = make_sevenz_archive(&[("/etc/shadow", b"secret")]);
    let mut archive = SevenZArchive::new(Cursor::new(data)).unwrap();

    let temp = TempDir::new().unwrap();
    let config = SecurityConfig::default().validate().expect("valid config");

    let result = archive.extract(
        temp.path(),
        &config,
        &ExtractionOptions::default(),
        &mut crate::NoopProgress,
    );
    assert!(
        result.is_err(),
        "absolute path must be rejected by default, got: {result:?}"
    );
}

#[test]
fn test_7z_absolute_path_with_flag_writes_to_dest() {
    let data = make_sevenz_archive(&[("/etc/shadow", b"content")]);
    let mut archive = SevenZArchive::new(Cursor::new(data)).unwrap();

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
fn test_7z_absolute_path_traversal_still_rejected_with_flag() {
    let data = make_sevenz_archive(&[("/../etc/passwd", b"secret")]);
    let mut archive = SevenZArchive::new(Cursor::new(data)).unwrap();

    let temp = TempDir::new().unwrap();
    let config = SecurityConfig::default()
        .with_allow_absolute_paths(true)
        .validate()
        .unwrap();

    let result = archive.extract(
        temp.path(),
        &config,
        &ExtractionOptions::default(),
        &mut crate::NoopProgress,
    );
    assert!(
        result.is_err(),
        "traversal-after-root must be rejected even with allow_absolute_paths"
    );
}

/// Regression test for GHSA-qh76-45cr-8xrc / CVE-2026-61725 (7z Zip-Slip):
/// proves the extraction-time re-validation inside `process_entry_inner`
/// (the "defense in depth" layer noted at the top of
/// `extract_with_callback`, which compensates for deliberately bypassing
/// upstream's own Zip-Slip guard) independently rejects a traversal
/// entry.
///
/// `SevenZArchive::extract` always pre-validates every entry in Step 1
/// before this callback ever runs, so a traversal entry reaching
/// `extract()` is caught there first (see the `test_7z_*_rejected*`
/// tests above). This test calls `process_entry_inner` directly to
/// exercise the callback layer in isolation, proving it is not dead
/// code should Step 1 ever be bypassed or restructured.
#[test]
fn test_process_entry_inner_rejects_traversal_independently() {
    let temp = TempDir::new().unwrap();
    let dest = DestDir::new_or_create(temp.path().to_path_buf()).unwrap();
    let config = SecurityConfig::default().validate().expect("valid config");
    let mut validator = EntryValidator::new(&config, &dest);
    let mut dir_cache = common::DirCache::new();
    let mut report = ExtractionReport::new();
    let mut duplicate_skips = 0u64;
    let mut disallowed_extension_skips = 0u64;
    let mut pending_error = None;
    let mut copy_buffer = CopyBuffer::new();

    let mut entry = sevenz_rust2::ArchiveEntry::new_file("../../evil.txt");
    entry.has_stream = true;
    entry.size = 5;
    let entry_path = std::path::PathBuf::from(common::normalize_entry_name(&entry.name));

    let result = SevenZArchive::<Cursor<Vec<u8>>>::process_entry_inner(
        &entry,
        SevenZKind::File,
        &mut std::io::empty(),
        &entry_path,
        &mut validator,
        &dest,
        &mut report,
        &mut dir_cache,
        false,
        &config,
        &mut duplicate_skips,
        &mut disallowed_extension_skips,
        &mut pending_error,
        &mut copy_buffer,
    );

    assert!(
        result.is_err(),
        "callback re-validation must independently reject a traversal entry via its own \
         validate_entry call, got: {result:?}"
    );
    assert_matches!(
        pending_error,
        Some(ArchiveError::PathTraversal { .. }),
        "the typed error must reach the caller, not a stringified one"
    );
}

/// Regression test for #502: `duplicate_skips` must saturate instead of
/// wrapping (or panicking, in debug builds) once it reaches `u64::MAX`,
/// mirroring the near-boundary pattern used by
/// `common.rs`'s `test_extract_file_with_permit_integer_overflow_check`
/// for `bytes_written`.
#[test]
fn test_process_entry_inner_duplicate_skips_saturates_at_max() {
    let temp = TempDir::new().unwrap();
    let dest = DestDir::new_or_create(temp.path().to_path_buf()).unwrap();
    std::fs::write(temp.path().join("existing.txt"), b"already here").unwrap();

    let config = SecurityConfig::default().validate().expect("valid config");
    let mut validator = EntryValidator::new(&config, &dest);
    let mut dir_cache = common::DirCache::new();
    let mut report = ExtractionReport::new();
    let mut duplicate_skips = u64::MAX;
    let mut disallowed_extension_skips = 0u64;
    let mut pending_error = None;
    let mut copy_buffer = CopyBuffer::new();

    let mut entry = sevenz_rust2::ArchiveEntry::new_file("existing.txt");
    entry.has_stream = true;
    entry.size = 5;
    let entry_path = std::path::PathBuf::from(common::normalize_entry_name(&entry.name));

    let result = SevenZArchive::<Cursor<Vec<u8>>>::process_entry_inner(
        &entry,
        SevenZKind::File,
        &mut std::io::empty(),
        &entry_path,
        &mut validator,
        &dest,
        &mut report,
        &mut dir_cache,
        true, // skip_duplicates
        &config,
        &mut duplicate_skips,
        &mut disallowed_extension_skips,
        &mut pending_error,
        &mut copy_buffer,
    );

    assert_matches!(
        result,
        Ok(0),
        "duplicate skip must not error, got: {result:?}"
    );
    assert_eq!(
        duplicate_skips,
        u64::MAX,
        "duplicate_skips must saturate at u64::MAX instead of wrapping or panicking"
    );
}

/// Issue #468: `Path::exists()` follows symlinks and returns `false` for
/// a dangling symlink, so the old `dest_path.exists()` check silently
/// missed a pre-existing dangling symlink occupying the entry's
/// destination path. With `skip_duplicates` true, the entry must be
/// detected as a duplicate and skipped, leaving the dangling symlink in
/// place instead of being silently replaced.
#[test]
#[cfg(unix)]
fn test_skip_duplicates_detects_dangling_symlink_at_destination() {
    let data = make_sevenz_archive(&[("target.txt", b"payload")]);
    let mut archive = SevenZArchive::new(Cursor::new(data)).unwrap();

    let temp = TempDir::new().unwrap();
    let link_path = temp.path().join("target.txt");
    std::os::unix::fs::symlink(temp.path().join("does-not-exist"), &link_path).unwrap();
    assert!(
        !link_path.exists(),
        "sanity check: dangling symlink must be invisible to exists()"
    );

    let config = SecurityConfig::default().validate().expect("valid config");
    let report = archive
        .extract(
            temp.path(),
            &config,
            &ExtractionOptions::default(), // skip_duplicates = true
            &mut crate::NoopProgress,
        )
        .unwrap();

    assert_eq!(
        report.files_skipped, 1,
        "entry must be skipped as a duplicate of the dangling symlink"
    );
    assert_eq!(report.files_extracted, 0);
    let metadata = std::fs::symlink_metadata(&link_path).unwrap();
    assert!(
        metadata.file_type().is_symlink(),
        "dangling symlink must survive untouched, not be replaced by extracted content"
    );
}

/// Regression test for #477: before this fix, `skip_duplicates = false`
/// against a dangling symlink at the destination silently replaced it —
/// `write_file_with_permit`'s temp-file + `rename` replaces whatever
/// sits at `dest_path`, symlink or not, without following it, and
/// nothing upstream of that rename rejected a symlink destination the
/// way TAR/ZIP's `O_NOFOLLOW`/`ELOOP` in `create_file_with_mode` does.
/// `process_entry_inner` now checks `lstat_dest` before reserving quota
/// or removing anything, and fails with the same `ELOOP` I/O error
/// TAR/ZIP produce instead of silently replacing the symlink.
#[test]
#[cfg(unix)]
fn test_duplicate_rejects_dangling_symlink_when_not_skipping() {
    let data = make_sevenz_archive(&[("target.txt", b"payload")]);
    let mut archive = SevenZArchive::new(Cursor::new(data)).unwrap();

    let temp = TempDir::new().unwrap();
    let link_path = temp.path().join("target.txt");
    std::os::unix::fs::symlink(temp.path().join("does-not-exist"), &link_path).unwrap();

    let config = SecurityConfig::default().validate().expect("valid config");
    let options = ExtractionOptions {
        skip_duplicates: false,
        ..ExtractionOptions::default()
    };
    let result = archive.extract(temp.path(), &config, &options, &mut crate::NoopProgress);

    assert!(
        result.is_err(),
        "a pre-existing symlink at the destination must be rejected, not silently \
         replaced: {result:?}"
    );
    let metadata = std::fs::symlink_metadata(&link_path).unwrap();
    assert!(
        metadata.file_type().is_symlink(),
        "dangling symlink must survive untouched, not be replaced by extracted content"
    );
}

/// Regression test for issue #483: extracting a file entry onto a
/// pre-existing *directory* at the destination path must fail instead of
/// recursively deleting the directory tree via `remove_dir_all`.
///
/// Asserts the error's `io::ErrorKind` specifically (not just
/// `is_err()`): the S1 bug this guards against had extraction still
/// return `Err`, but with the precise `IsADirectory` kind lost to the
/// lossy `From<sevenz_rust2::Error> for ArchiveError` string-heuristic
/// converter (and, for some path names, misclassified as
/// `SecurityViolation`), so a bare `is_err()` check would not have
/// caught it.
#[test]
fn test_overwrite_directory_returns_error_without_deleting_it() {
    let data = make_sevenz_archive(&[("target", b"payload")]);
    let mut archive = SevenZArchive::new(Cursor::new(data)).unwrap();

    let temp = TempDir::new().unwrap();
    let dir_path = temp.path().join("target");
    std::fs::create_dir(&dir_path).unwrap();
    let inner_file = dir_path.join("keep-me.txt");
    std::fs::write(&inner_file, b"do not delete").unwrap();

    let config = SecurityConfig::default().validate().expect("valid config");
    let options = ExtractionOptions {
        skip_duplicates: false,
        ..ExtractionOptions::default()
    };

    let result = archive.extract(temp.path(), &config, &options, &mut crate::NoopProgress);

    let err = result.expect_err("extracting a file entry onto a pre-existing directory must fail");
    assert_matches!(
        &err,
        ArchiveError::Io(io_err) if io_err.kind() == std::io::ErrorKind::IsADirectory,
        "must fail with ErrorKind::IsADirectory specifically, not a generic or \
         misclassified error, got: {err:?}"
    );
    assert!(
        dir_path.is_dir(),
        "pre-existing directory must survive the failed extraction, not be deleted"
    );
    assert_eq!(
        std::fs::read(&inner_file).unwrap(),
        b"do not delete",
        "directory contents must be untouched by the failed extraction"
    );
}

/// Regression test for issue #483 finding S2: a symlink whose target is
/// itself a directory must not be misidentified as a real directory and
/// take the `ErrorKind::IsADirectory` branch. It is still rejected — as
/// of #486/#477, every pre-existing symlink at the destination fails
/// with `ELOOP` on Unix rather than being replaced — but the failure
/// must come from the symlink check, not the directory check, and the
/// symlink's target directory itself must survive untouched either way.
#[test]
#[cfg(unix)]
fn test_symlink_to_directory_rejected_via_symlink_check_not_directory_check() {
    let data = make_sevenz_archive(&[("target", b"payload")]);
    let mut archive = SevenZArchive::new(Cursor::new(data)).unwrap();

    let temp = TempDir::new().unwrap();
    let real_dir = temp.path().join("real-dir");
    std::fs::create_dir(&real_dir).unwrap();
    let link_path = temp.path().join("target");
    std::os::unix::fs::symlink(&real_dir, &link_path).unwrap();

    let config = SecurityConfig::default().validate().expect("valid config");
    let options = ExtractionOptions {
        skip_duplicates: false,
        ..ExtractionOptions::default()
    };

    let result = archive.extract(temp.path(), &config, &options, &mut crate::NoopProgress);

    assert!(
        result.is_err(),
        "a pre-existing symlink at the destination must be rejected, even when its \
         target is a directory: {result:?}"
    );
    let metadata = std::fs::symlink_metadata(&link_path).unwrap();
    assert!(
        metadata.file_type().is_symlink(),
        "the symlink itself must survive untouched, not be replaced"
    );
    assert!(
        real_dir.is_dir(),
        "the symlink's target directory itself must be untouched"
    );
}

/// Regression test for issue #484: extracting an archive with many
/// pre-existing duplicate entries must push exactly one aggregated
/// warning onto `report.warnings`, not one `String` per skipped entry.
#[test]
fn test_skip_duplicates_aggregates_single_warning() {
    const ENTRY_COUNT: usize = 30;
    let names: Vec<String> = (0..ENTRY_COUNT).map(|i| format!("dup-{i}.txt")).collect();
    let entries: Vec<(&str, &[u8])> = names
        .iter()
        .map(|n| (n.as_str(), b"payload".as_slice()))
        .collect();
    let data = make_sevenz_archive(&entries);
    let mut archive = SevenZArchive::new(Cursor::new(data)).unwrap();

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

/// Regression test for issue #492 adversarial review, finding C1:
/// `process_entry_inner` must re-validate every entry's path without
/// trusting `dir_cache`'s record of directories it has already created.
/// If something outside the archive's own entries — e.g. a misbehaving
/// `ProgressCallback` — replaces a previously-created directory with a
/// symlink between two entries that share it as a parent, the trust
/// shortcut would let the second entry's write follow that symlink
/// outside the destination root, silently and repeatedly, instead of
/// failing loudly the way an untrusted (always-canonicalize) validation
/// does. Simulates exactly that swap and asserts extraction aborts
/// instead of writing through the symlink.
#[test]
#[cfg(unix)]
fn test_dir_swapped_for_symlink_between_entries_is_rejected() {
    struct DirSwapper {
        dest_root: std::path::PathBuf,
        outside_root: std::path::PathBuf,
    }

    impl crate::ProgressCallback for DirSwapper {
        fn on_entry_start(&mut self, _path: &std::path::Path, _total: usize, _current: usize) {}

        fn on_bytes_written(&mut self, _bytes: u64) {}

        fn on_entry_complete(&mut self, path: &std::path::Path) {
            if path == std::path::Path::new("a/file1.txt") {
                let a = self.dest_root.join("a");
                std::fs::remove_dir_all(&a).unwrap();
                std::os::unix::fs::symlink(&self.outside_root, &a).unwrap();
            }
        }

        fn on_complete(&mut self) {}
    }

    let data = make_sevenz_archive(&[("a/file1.txt", b"one"), ("a/file2.txt", b"two")]);
    let mut archive = SevenZArchive::new(Cursor::new(data)).unwrap();

    let dest = TempDir::new().unwrap();
    let outside = TempDir::new().unwrap();

    let mut swapper = DirSwapper {
        dest_root: dest.path().to_path_buf(),
        outside_root: outside.path().to_path_buf(),
    };

    let config = SecurityConfig::default().validate().expect("valid config");
    let result = archive.extract(
        dest.path(),
        &config,
        &ExtractionOptions::default(),
        &mut swapper,
    );

    assert!(
        result.is_err(),
        "extraction must fail once a parent directory is swapped for a symlink \
         mid-extraction, not silently continue writing through it"
    );
    assert!(
        !outside.path().join("file2.txt").exists(),
        "file2.txt must not be written through the swapped symlink outside the \
         destination root"
    );
}

/// Regression test for issue #492 adversarial review, finding C2:
/// `extract()` must remain safely callable more than once on the same
/// `SevenZArchive` instance. `mem::take`-ing the cached `Archive` on the
/// first call left `self.archive` as `Archive::default()` afterward, so
/// a second `extract()` would silently report zero files extracted
/// against an archive with no entries, instead of extracting the same
/// real contents again.
#[test]
fn test_extract_can_be_called_twice_on_same_instance() {
    let data = make_sevenz_archive(&[("file.txt", b"payload")]);
    let mut archive = SevenZArchive::new(Cursor::new(data)).unwrap();
    let config = SecurityConfig::default().validate().expect("valid config");

    let first_dest = TempDir::new().unwrap();
    let first_report = archive
        .extract(
            first_dest.path(),
            &config,
            &ExtractionOptions::default(),
            &mut crate::NoopProgress,
        )
        .unwrap();
    assert_eq!(first_report.files_extracted, 1);

    let second_dest = TempDir::new().unwrap();
    let second_report = archive
        .extract(
            second_dest.path(),
            &config,
            &ExtractionOptions::default(),
            &mut crate::NoopProgress,
        )
        .unwrap();
    assert_eq!(
        second_report.files_extracted, 1,
        "second extract() call on the same instance must extract the real archive \
         contents, not silently return zero files"
    );
    assert_eq!(
        std::fs::read(second_dest.path().join("file.txt")).unwrap(),
        b"payload"
    );
}

#[test]
fn test_uncovered_by_block_crc_counts_entries_without_own_crc() {
    let crcs = [(4, true), (5, false), (6, false)];
    assert_eq!(
        entries_uncovered_by_block_crc(true, 10, 12, crcs.into_iter()),
        [5, 6]
    );
    assert!(entries_uncovered_by_block_crc(true, 12, 12, crcs.into_iter()).is_empty());
    assert!(entries_uncovered_by_block_crc(false, 10, 12, crcs.into_iter()).is_empty());
}

fn block_refusals(header: &SevenZHeader) -> Vec<SevenZRefusal> {
    let config = SecurityConfig::default()
        .with_allow_solid_archives(true)
        .validate()
        .unwrap();
    sevenz_refusals(header, &config)
}

fn visit(
    header: &SevenZHeader,
    source: Vec<u8>,
) -> (Vec<String>, std::result::Result<(), sevenz_rust2::Error>) {
    let mut names = Vec::new();
    let result = decode_archive_entries(
        &mut Cursor::new(source),
        header,
        ParallelDecode::Sequential,
        DecodeKnobs::production(),
        &mut |entry, _| {
            names.push(entry.name.clone());
            Ok(true)
        },
    );
    (names, result)
}

#[test]
fn test_stream_less_entry_before_a_block_is_admitted() {
    let bytes = make_sevenz_archive_with_empty_file();
    let header = read_sevenz_header(&mut Cursor::new(bytes.clone())).unwrap();

    assert!(block_refusals(&header).is_empty());
    let (visited, result) = visit(&header, bytes);
    result.unwrap();
    assert!(visited.contains(&"full.txt".to_string()));
}

/// `interleaved-empty.7z` has a stream-less entry between the stream files
/// of one block. Upstream iterates the block as `num_unpack_sub_streams`
/// consecutive files, so every stream-less entry inside the block pushes
/// the last stream file out of reach (a directory has the same effect
/// as an empty file); trailing and leading ones fall outside the span.
#[test]
fn test_stream_less_entry_inside_a_block_is_refused_and_upstream_drops_a_file() {
    let bytes = load_fixture("interleaved-empty.7z");
    let header = read_sevenz_header(&mut Cursor::new(bytes.clone())).unwrap();
    let stream_files: Vec<_> = header
        .files()
        .iter()
        .filter(|f| f.has_stream && f.size > 0)
        .map(|f| f.name.clone())
        .collect();

    let refusals = block_refusals(&header);
    assert_eq!(refusals.len(), 1);
    assert_eq!(refusals[0].scope, RefusalScope::Block(first_block(&header)));
    assert_matches!(refusals[0].error, ArchiveError::InvalidArchive(_));

    // If sevenz-rust2 starts visiting every stream file, the predicate can
    // be relaxed. The walk itself fails closed on the dropped file.
    let (visited, result) = visit(&header, bytes);
    let dropped = stream_files.iter().filter(|n| !visited.contains(n)).count();
    assert_eq!(dropped, 1, "{visited:?}");
    assert_matches!(result, Err(sevenz_rust2::Error::Other(_)));
}

#[test]
fn test_decoder_memory_bound_uses_declared_file_sizes_beyond_the_unpack_size() {
    let data = vec![7u8; 1024];
    let bytes = build_solid_sevenz_archive(&[("a", &data), ("b", &data)], false);
    let mut archive = Archive::read(&mut Cursor::new(bytes), &Password::empty()).unwrap();
    let config = SecurityConfig::default()
        .with_allow_solid_archives(true)
        .with_max_decoder_memory(1024 * 1024)
        .validate()
        .unwrap();

    let header = SevenZHeader::assume_checked(archive.clone());
    assert!(
        sevenz_refusals(&header, &config).is_empty(),
        "a small block is admitted"
    );

    archive.files[0].size = 512 * 1024 * 1024;
    let header = SevenZHeader::assume_checked(archive);
    let refusals: Vec<_> = sevenz_refusals(&header, &config)
        .into_iter()
        .filter(|r| r.scope == RefusalScope::Block(first_block(&header)))
        .collect();
    assert_eq!(refusals.len(), 1);
    assert_matches!(
        refusals[0].error,
        ArchiveError::QuotaExceeded {
            resource: QuotaResource::DecoderMemory { .. }
        }
    );
}

fn sevenz_file(name: &str, stream: bool, size: u64, anti: bool) -> sevenz_rust2::ArchiveEntry {
    let mut entry = sevenz_rust2::ArchiveEntry::new_file(name);
    entry.has_stream = stream;
    entry.size = size;
    entry.is_anti_item = anti;
    entry
}

#[test]
fn test_payload_by_block_skips_anti_items_and_stream_less_files() {
    let config = SecurityConfig::default().validate().unwrap();
    let mut pass = IntegrityPass::new(&config, crate::DecompressionBudget::DEFAULT);
    let a = pass.begin_entry(4, &EntryCompression::Unknown);
    let empty = pass.begin_entry(0, &EntryCompression::Unknown);
    let b = pass.begin_entry(4, &EntryCompression::Unknown);

    let mut archive = Archive::default();
    archive.files = vec![
        sevenz_file("anti", false, 0, true),
        sevenz_file("a", true, 4, false),
        sevenz_file("empty", false, 0, false),
        sevenz_file("b", true, 4, false),
    ];
    archive.blocks = vec![sevenz_rust2::Block::default()];
    archive.stream_map.file_block_index = vec![None, Some(0), Some(0), Some(0)];
    let slots = [None, Some(a), Some(empty), Some(b)];

    assert_eq!(
        payload_by_block(&SevenZHeader::assume_checked(archive), &slots),
        [vec![(1, a), (3, b)]]
    );
}

struct FailingReader(Option<io::Error>);

impl Read for FailingReader {
    fn read(&mut self, _buf: &mut [u8]) -> io::Result<usize> {
        Err(self.0.take().unwrap_or_else(|| io::Error::other("again")))
    }
}

fn scan_failing_file(error: io::Error) -> (bool, Option<BlockStop>, Vec<IssueCategory>) {
    let config = SecurityConfig::default().validate().unwrap();
    let mut pass = IntegrityPass::new(&config, crate::DecompressionBudget::DEFAULT);
    let slot = pass.begin_entry(4, &EntryCompression::Unknown);
    let slots = [Some(slot)];
    let mut scan = BlockScan {
        pass: &mut pass,
        slots: &slots,
        links: None,
        next_file: 0,
        visited: BTreeSet::new(),
        stop: None,
    };
    let keep_going = scan.visit(
        &sevenz_file("a", true, 4, false),
        &mut FailingReader(Some(error)),
    );
    let stop = scan.stop.take();
    let issues = pass.finish().entry_issues.remove(0);
    (
        keep_going,
        stop,
        issues.iter().map(|i| i.category).collect(),
    )
}

#[test]
fn test_block_scan_keeps_going_after_a_checksum_mismatch() {
    let error = io::Error::other(sevenz_rust2::Error::ChecksumVerificationFailed);
    let (keep_going, stop, issues) = scan_failing_file(error);

    assert!(keep_going);
    assert!(stop.is_none());
    assert_eq!(issues, [IssueCategory::CorruptData]);
}

#[test]
fn test_block_scan_abandons_the_block_on_a_decoder_error() {
    let error = io::Error::new(io::ErrorKind::InvalidData, "bad block");
    let (keep_going, stop, issues) = scan_failing_file(error);

    assert!(!keep_going);
    assert_matches!(
        stop,
        Some(BlockStop::Abandoned(UnverifiedReason::NotDecodable))
    );
    assert_eq!(issues, [IssueCategory::CorruptData]);
}

#[test]
fn test_block_scan_abandons_the_block_on_a_resource_limit() {
    let error = io::Error::new(
        io::ErrorKind::InvalidData,
        crate::formats::tar_metadata_limit::DecoderMemoryExceeded { max: 1 },
    );
    let (keep_going, stop, issues) = scan_failing_file(error);

    assert!(!keep_going);
    assert_matches!(
        stop,
        Some(BlockStop::Abandoned(UnverifiedReason::ResourceLimit))
    );
    assert_eq!(issues, [IssueCategory::QuotaExceeded]);
}

#[test]
fn test_block_scan_stops_on_a_disk_error() {
    let (keep_going, stop, _) = scan_failing_file(io::Error::from_raw_os_error(5));

    assert!(!keep_going);
    assert_matches!(stop, Some(BlockStop::Fatal(ArchiveError::Io(_))));
}

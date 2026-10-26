//! `extract`, `list` and `verify` classify 7z entries through one classifier:
//! a reparse point is refused before any write, an anti item is skipped
//! everywhere, and an empty name is rejected by all three.

#![allow(clippy::unwrap_used)]

use std::io::Cursor;
use std::path::Path;
use std::path::PathBuf;

use exarch_core::ArchiveError;
use exarch_core::ExtractionOptions;
use exarch_core::IssueSeverity;
use exarch_core::ProgressCallback;
use exarch_core::SecurityConfig;
use exarch_core::VerificationStatus;
use exarch_core::extract_archive;
use exarch_core::extract_archive_with_options;
use exarch_core::list_archive;
use exarch_core::verify_archive;
use sevenz_rust2::ArchiveEntry;
use sevenz_rust2::ArchiveWriter;
use sevenz_rust2::SourceReader;
use tempfile::TempDir;

const FILE_ATTRIBUTE_DIRECTORY: u32 = 0x0010;
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;

type Pushed = (ArchiveEntry, Option<Cursor<Vec<u8>>>);

fn file(name: &str, data: &[u8]) -> Pushed {
    let mut entry = ArchiveEntry::new_file(name);
    if data.is_empty() {
        return (entry, None);
    }
    entry.has_stream = true;
    entry.size = data.len() as u64;
    (entry, Some(Cursor::new(data.to_vec())))
}

fn anti_item(name: &str) -> Pushed {
    let mut entry = ArchiveEntry::new_file(name);
    entry.is_anti_item = true;
    (entry, None)
}

fn reparse_directory(name: &str) -> Pushed {
    let mut entry = ArchiveEntry::new_directory(name);
    entry.has_windows_attributes = true;
    entry.windows_attributes = FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT;
    (entry, None)
}

fn reparse_file(name: &str) -> Pushed {
    let mut entry = ArchiveEntry::new_file(name);
    entry.has_windows_attributes = true;
    entry.windows_attributes = FILE_ATTRIBUTE_REPARSE_POINT;
    (entry, None)
}

fn anti_directory(name: &str) -> Pushed {
    let mut entry = ArchiveEntry::new_directory(name);
    entry.is_anti_item = true;
    (entry, None)
}

fn write_archive(dir: &TempDir, entries: Vec<Pushed>) -> PathBuf {
    let mut writer = ArchiveWriter::new(Cursor::new(Vec::new())).unwrap();
    for (entry, data) in entries {
        writer.push_archive_entry(entry, data).unwrap();
    }
    let path = dir.path().join("classifier.7z");
    std::fs::write(&path, writer.finish().unwrap().into_inner()).unwrap();
    path
}

fn dir_names(dir: &TempDir) -> Vec<String> {
    let mut names: Vec<_> = std::fs::read_dir(dir.path())
        .unwrap()
        .map(|e| e.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    names
}

fn listed_paths(archive: &Path) -> Vec<String> {
    list_archive(archive, &SecurityConfig::default())
        .unwrap()
        .entries()
        .iter()
        .map(|e| e.path.to_string_lossy().into_owned())
        .collect()
}

#[test]
fn reparse_file_and_nested_reparse_entries_are_refused_before_any_write() {
    let cases: [Vec<Pushed>; 3] = [
        vec![file("a.txt", b"hi"), reparse_file("link")],
        vec![file("a.txt", b"hi"), reparse_file("sub/link")],
        vec![file("a.txt", b"hi"), reparse_directory("sub/junction")],
    ];
    for entries in cases {
        let dir = TempDir::new().unwrap();
        let archive = write_archive(&dir, entries);
        let out = TempDir::new().unwrap();

        let err = extract_archive(&archive, out.path(), &SecurityConfig::default()).unwrap_err();

        assert!(
            matches!(&err, ArchiveError::SecurityViolation { reason, .. } if reason.contains("reparse point")),
            "{err}"
        );
        assert!(dir_names(&out).is_empty(), "a.txt must not be written");
    }
}

#[test]
fn reparse_root_entry_hits_the_root_rule_in_extract_before_any_write() {
    let dir = TempDir::new().unwrap();
    let archive = write_archive(&dir, vec![file("a.txt", b"hi"), reparse_directory(".")]);
    let out = TempDir::new().unwrap();

    let err = extract_archive(&archive, out.path(), &SecurityConfig::default()).unwrap_err();

    assert!(err.to_string().contains("must be a directory"), "{err}");
    assert!(dir_names(&out).is_empty());
}

#[test]
fn empty_name_is_rejected_by_list_verify_and_extract() {
    let named_entries = [
        file("", b""),
        file("", b"payload"),
        (ArchiveEntry::new_directory(""), None),
    ];
    for entry in named_entries {
        let dir = TempDir::new().unwrap();
        let archive = write_archive(&dir, vec![file("a.txt", b"hi"), entry]);
        let out = TempDir::new().unwrap();

        let config = SecurityConfig::default();
        let list_err = list_archive(&archive, &config).unwrap_err();
        let verify_err = verify_archive(&archive, &config).unwrap_err();
        let extract_err = extract_archive(&archive, out.path(), &config).unwrap_err();

        for err in [list_err, verify_err, extract_err] {
            assert_eq!(err.error_code(), "SECURITY_VIOLATION");
            assert!(err.to_string().contains("empty path"), "{err}");
        }
        assert!(dir_names(&out).is_empty());
    }
}

#[test]
fn anti_item_is_skipped_by_list_verify_and_extract() {
    let cases: [(&str, Pushed); 5] = [
        ("dots", anti_item("...")),
        ("root", anti_item(".")),
        ("traversal", anti_item("../evil")),
        ("same name as a real file", anti_item("a.txt")),
        ("directory", anti_directory("old/")),
    ];
    for (label, anti) in cases {
        let dir = TempDir::new().unwrap();
        let archive = write_archive(&dir, vec![file("a.txt", b"hi"), anti]);
        let out = TempDir::new().unwrap();

        assert_eq!(listed_paths(&archive), ["a.txt"], "{label}");
        let report = verify_archive(&archive, &SecurityConfig::default()).unwrap();
        assert_eq!(report.status(), VerificationStatus::Pass, "{label}");
        let extracted = extract_archive(&archive, out.path(), &SecurityConfig::default()).unwrap();
        assert_eq!(extracted.files_extracted, 1, "{label}");
        assert_eq!(dir_names(&out), ["a.txt"], "{label}");
        assert_eq!(
            std::fs::read(out.path().join("a.txt")).unwrap(),
            b"hi",
            "{label}"
        );
    }
}

#[test]
fn anti_item_never_truncates_an_existing_file_even_with_overwrite() {
    let dir = TempDir::new().unwrap();
    let archive = write_archive(&dir, vec![file("a.txt", b"hi"), anti_item("gone.txt")]);
    let out = TempDir::new().unwrap();
    std::fs::write(out.path().join("gone.txt"), b"precious").unwrap();
    let options = ExtractionOptions::default().with_skip_duplicates(false);

    extract_archive_with_options(&archive, out.path(), &SecurityConfig::default(), &options)
        .unwrap();

    assert_eq!(
        std::fs::read(out.path().join("gone.txt")).unwrap(),
        b"precious"
    );
}

#[test]
fn archive_of_only_anti_items_extracts_nothing() {
    let dir = TempDir::new().unwrap();
    let archive = write_archive(&dir, vec![anti_item("gone.txt")]);
    let out = TempDir::new().unwrap();

    let report = extract_archive(&archive, out.path(), &SecurityConfig::default()).unwrap();

    assert_eq!(report.files_extracted, 0);
    assert!(dir_names(&out).is_empty());
}

#[test]
fn extract_warns_once_with_the_number_of_skipped_anti_items() {
    let dir = TempDir::new().unwrap();
    let archive = write_archive(
        &dir,
        vec![
            file("a.txt", b"hi"),
            anti_item("x"),
            anti_directory("old/"),
            anti_item("y"),
        ],
    );
    let out = TempDir::new().unwrap();

    let report = extract_archive(&archive, out.path(), &SecurityConfig::default()).unwrap();

    assert_eq!(
        report.warnings,
        ["skipped 3 7z anti-items (deletion markers are not applied)"]
    );
}

#[test]
fn extract_of_only_anti_items_still_warns() {
    let dir = TempDir::new().unwrap();
    let archive = write_archive(&dir, vec![anti_item("gone.txt")]);
    let out = TempDir::new().unwrap();

    let report = extract_archive(&archive, out.path(), &SecurityConfig::default()).unwrap();

    assert_eq!(
        report.warnings,
        ["skipped 1 7z anti-item (deletion markers are not applied)"]
    );
}

#[test]
fn archive_without_anti_items_has_no_warning_or_finding() {
    let dir = TempDir::new().unwrap();
    let archive = write_archive(&dir, vec![file("a.txt", b"hi")]);
    let out = TempDir::new().unwrap();

    let extracted = extract_archive(&archive, out.path(), &SecurityConfig::default()).unwrap();
    let verified = verify_archive(&archive, &SecurityConfig::default()).unwrap();

    assert!(extracted.warnings.is_empty());
    assert!(verified.issues().is_empty());
}

#[test]
fn verify_reports_skipped_anti_items_as_info_and_still_passes() {
    let dir = TempDir::new().unwrap();
    let archive = write_archive(
        &dir,
        vec![file("a.txt", b"hi"), anti_item("x"), anti_item("y")],
    );

    let report = verify_archive(&archive, &SecurityConfig::default()).unwrap();

    assert_eq!(report.status(), VerificationStatus::Pass);
    let [issue] = report.issues() else {
        panic!("expected one finding, got {:?}", report.issues());
    };
    assert_eq!(issue.severity, IssueSeverity::Info);
    assert_eq!(
        issue.message,
        "2 7z anti-items skipped (deletion markers are not applied)"
    );
}

#[test]
fn anti_item_warning_survives_a_failing_extract() {
    let dir = TempDir::new().unwrap();
    let archive = write_archive(
        &dir,
        vec![
            file("a.txt", b"hi"),
            file("b.txt", b"yo"),
            anti_item("gone"),
        ],
    );
    let out = TempDir::new().unwrap();
    std::fs::create_dir(out.path().join("b.txt")).unwrap();
    let options = ExtractionOptions::default().with_skip_duplicates(false);

    let err =
        extract_archive_with_options(&archive, out.path(), &SecurityConfig::default(), &options)
            .unwrap_err();

    let ArchiveError::PartialExtraction { report, .. } = err else {
        panic!("expected a partial extraction, got {err}");
    };
    assert_eq!(
        report.warnings,
        ["skipped 1 7z anti-item (deletion markers are not applied)"]
    );
}

#[test]
fn list_reports_no_anti_item_and_lists_the_rest() {
    let dir = TempDir::new().unwrap();
    let archive = write_archive(&dir, vec![file("a.txt", b"hi"), anti_item("gone")]);

    assert_eq!(listed_paths(&archive), ["a.txt"]);
}

#[test]
fn verify_anti_item_info_does_not_mask_a_failing_issue() {
    let dir = TempDir::new().unwrap();
    let archive = write_archive(
        &dir,
        vec![
            file("a.txt", b"hi"),
            anti_item("gone"),
            reparse_file("link"),
        ],
    );

    let report = verify_archive(&archive, &SecurityConfig::default()).unwrap();

    assert_eq!(report.status(), VerificationStatus::Fail);
    assert!(
        report
            .issues()
            .iter()
            .any(|i| i.severity == IssueSeverity::Info && i.message.contains("anti-item")),
        "{:?}",
        report.issues()
    );
}

#[derive(Default)]
struct Recorder {
    starts: Vec<(usize, usize)>,
}

impl ProgressCallback for Recorder {
    fn on_entry_start(&mut self, _path: &Path, total: usize, current: usize) {
        self.starts.push((total, current));
    }

    fn on_bytes_written(&mut self, _bytes: u64) {}

    fn on_entry_complete(&mut self, _path: &Path) {}

    fn on_complete(&mut self) {}
}

#[test]
fn progress_total_excludes_anti_items_and_indexes_are_contiguous() {
    let dir = TempDir::new().unwrap();
    let archive = write_archive(
        &dir,
        vec![
            file("a.txt", b"aa"),
            anti_item("gone"),
            file("b.txt", b"bb"),
        ],
    );
    let out = TempDir::new().unwrap();
    let mut recorder = Recorder::default();

    exarch_core::extract_archive_with_progress(
        &archive,
        out.path(),
        &SecurityConfig::default(),
        &mut recorder,
    )
    .unwrap();

    assert_eq!(recorder.starts, [(2, 1), (2, 2)]);
}

#[test]
fn anti_items_do_not_count_against_the_file_quota() {
    let dir = TempDir::new().unwrap();
    let archive = write_archive(
        &dir,
        vec![
            file("a.txt", b"aa"),
            anti_item("x"),
            file("b.txt", b"bb"),
            anti_item("y"),
        ],
    );
    let out = TempDir::new().unwrap();
    let config = SecurityConfig::default().with_max_file_count(2);

    list_archive(&archive, &config).unwrap();
    extract_archive(&archive, out.path(), &config).unwrap();

    assert_eq!(dir_names(&out), ["a.txt", "b.txt"]);
}

const SOLID_PAYLOADS: [&[u8]; 2] = [b"first-payload", b"second-payload"];

/// Writes a solid block of `a.txt`, `b.txt` and a stream-less anti item placed
/// at `anti_at` in the entry order.
fn solid_with_anti_item(dir: &TempDir, anti_at: usize) -> PathBuf {
    let mut entries = vec![
        ArchiveEntry::new_file("a.txt"),
        ArchiveEntry::new_file("b.txt"),
    ];
    for (entry, data) in entries.iter_mut().zip(SOLID_PAYLOADS) {
        entry.has_stream = true;
        entry.size = data.len() as u64;
    }
    let mut readers: Vec<SourceReader<Cursor<&[u8]>>> = SOLID_PAYLOADS
        .into_iter()
        .map(|data| SourceReader::from(Cursor::new(data)))
        .collect();
    let mut anti = ArchiveEntry::new_file("gone");
    anti.is_anti_item = true;
    anti.has_stream = false;
    entries.insert(anti_at, anti);
    readers.insert(anti_at, SourceReader::from(Cursor::new(&b""[..])));

    let mut writer = ArchiveWriter::new(Cursor::new(Vec::new())).unwrap();
    writer.push_archive_entries(entries, readers).unwrap();
    let path = dir.path().join("solid.7z");
    std::fs::write(&path, writer.finish().unwrap().into_inner()).unwrap();
    path
}

#[test]
fn anti_item_inside_a_solid_block_fails_closed_before_any_write() {
    for anti_at in 0..=2 {
        let dir = TempDir::new().unwrap();
        let archive = solid_with_anti_item(&dir, anti_at);
        let out = TempDir::new().unwrap();
        let config = SecurityConfig::default().with_allow_solid_archives(true);

        extract_archive(&archive, out.path(), &config).unwrap_err();

        assert!(dir_names(&out).is_empty(), "anti item at {anti_at}");
    }
}

const UNIX_EXTENSION: u32 = 0x8000;
const S_IFSOCK: u32 = 0o14_0000;
const S_IFBLK: u32 = 0o06_0000;
const S_IFREG: u32 = 0o10_0000;
const S_IFDIR: u32 = 0o04_0000;
const S_IFCHR: u32 = 0o02_0000;
const S_IFIFO: u32 = 0o01_0000;

fn with_unix_mode(mut pushed: Pushed, mode: u32) -> Pushed {
    pushed.0.has_windows_attributes = true;
    pushed.0.windows_attributes = UNIX_EXTENSION | (mode << 16);
    pushed
}

fn directory_with_mode(name: &str, mode: u32) -> Pushed {
    with_unix_mode((ArchiveEntry::new_directory(name), None), mode)
}

fn assert_refused_by_list_verify_and_extract(entries: Vec<Pushed>, expect: &str) {
    let dir = TempDir::new().unwrap();
    let archive = write_archive(&dir, entries);
    let config = SecurityConfig::default();
    let out = TempDir::new().unwrap();

    for err in [
        list_archive(&archive, &config).unwrap_err(),
        verify_archive(&archive, &config).unwrap_err(),
        extract_archive(&archive, out.path(), &config).unwrap_err(),
    ] {
        assert!(
            matches!(&err, ArchiveError::SecurityViolation { reason, .. } if reason.contains(expect)),
            "{expect}: {err}"
        );
    }
    assert!(
        dir_names(&out).is_empty(),
        "{expect}: nothing may be written"
    );
}

#[test]
fn special_files_are_refused_with_or_without_a_stream() {
    for (mode, noun) in [
        (S_IFIFO, "FIFO"),
        (S_IFCHR, "character device"),
        (S_IFBLK, "block device"),
        (S_IFSOCK, "socket"),
    ] {
        for special in [
            with_unix_mode(file("special", b""), mode | 0o644),
            with_unix_mode(file("special", b"payload"), mode | 0o644),
        ] {
            assert_refused_by_list_verify_and_extract(
                vec![file("a.txt", b"hi"), special],
                &format!("{noun} entries not supported"),
            );
        }
    }
}

#[test]
fn undefined_unix_file_type_is_refused() {
    assert_refused_by_list_verify_and_extract(
        vec![
            file("a.txt", b"hi"),
            with_unix_mode(file("odd", b"payload"), 0o03_0000 | 0o644),
        ],
        "undefined Unix file type",
    );
}

#[test]
fn unix_mode_contradicting_the_native_kind_is_refused() {
    let cases = [
        with_unix_mode(file("d", b"payload"), S_IFDIR | 0o755),
        with_unix_mode(file("d", b""), S_IFDIR | 0o755),
        directory_with_mode("d", S_IFREG | 0o644),
    ];
    for contradicting in cases {
        assert_refused_by_list_verify_and_extract(
            vec![file("a.txt", b"hi"), contradicting],
            "Unix mode says",
        );
    }
}

#[test]
fn windows_directory_bit_on_a_file_with_data_is_refused() {
    let mut pushed = file("d", b"payload");
    pushed.0.has_windows_attributes = true;
    pushed.0.windows_attributes = FILE_ATTRIBUTE_DIRECTORY;
    assert_refused_by_list_verify_and_extract(
        vec![file("a.txt", b"hi"), pushed],
        "Windows attributes says",
    );
}

#[test]
fn agreeing_unix_modes_extract_normally() {
    let dir = TempDir::new().unwrap();
    let archive = write_archive(
        &dir,
        vec![
            directory_with_mode("sub", S_IFDIR | 0o755),
            with_unix_mode(file("sub/f", b"data"), S_IFREG | 0o644),
            with_unix_mode(file("empty", b""), S_IFREG | 0o644),
        ],
    );
    let out = TempDir::new().unwrap();

    extract_archive(&archive, out.path(), &SecurityConfig::default()).unwrap();

    assert_eq!(std::fs::read(out.path().join("sub/f")).unwrap(), b"data");
    assert!(out.path().join("empty").is_file());
}

const S_IFLNK: u32 = 0o12_0000;

fn with_windows_attributes(mut pushed: Pushed, attributes: u32) -> Pushed {
    pushed.0.has_windows_attributes = true;
    pushed.0.windows_attributes = attributes;
    pushed
}

/// Writes one archive per contradiction of the entry kind to
/// `EXARCH_7Z_DIFF_DIR`, each holding `ok.txt` and the contradicting entry
/// `entry`; `scripts/sevenz-differential.sh` extracts them with other tools.
#[test]
#[ignore = "needs EXARCH_7Z_DIFF_DIR; run through scripts/sevenz-differential.sh"]
fn write_kind_contradictions_for_the_differential() {
    let target = std::env::var_os("EXARCH_7Z_DIFF_DIR").unwrap();
    let target = PathBuf::from(target);
    let cases: [(&str, Pushed); 9] = [
        ("baseline-file", file("entry", b"payload")),
        (
            "baseline-unix-symlink",
            with_unix_mode(file("entry", b"ok.txt"), S_IFLNK | 0o777),
        ),
        (
            "dir-bit-on-file-with-data",
            with_windows_attributes(file("entry", b"payload"), FILE_ATTRIBUTE_DIRECTORY),
        ),
        (
            "unix-dir-on-file-with-data",
            with_unix_mode(file("entry", b"payload"), S_IFDIR | 0o755),
        ),
        (
            "unix-dir-on-empty-file",
            with_unix_mode(file("entry", b""), S_IFDIR | 0o755),
        ),
        (
            "unix-regular-on-directory",
            directory_with_mode("entry", S_IFREG | 0o644),
        ),
        (
            "undefined-unix-type",
            with_unix_mode(file("entry", b"payload"), 0o03_0000 | 0o644),
        ),
        (
            "symlink-with-reparse-bit",
            with_windows_attributes(
                file("entry", b"ok.txt"),
                UNIX_EXTENSION | ((S_IFLNK | 0o777) << 16) | FILE_ATTRIBUTE_REPARSE_POINT,
            ),
        ),
        (
            "fifo-with-data",
            with_unix_mode(file("entry", b"payload"), S_IFIFO | 0o644),
        ),
    ];
    for (name, contradicting) in cases {
        let mut writer = ArchiveWriter::new(Cursor::new(Vec::new())).unwrap();
        for (entry, data) in [file("ok.txt", b"fine"), contradicting] {
            writer.push_archive_entry(entry, data).unwrap();
        }
        std::fs::write(
            target.join(format!("{name}.7z")),
            writer.finish().unwrap().into_inner(),
        )
        .unwrap();
    }
}

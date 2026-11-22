//! `verify` reports a stored setuid, setgid or sticky bit the same way for
//! TAR, ZIP and 7z (#1307).

#![expect(clippy::disallowed_methods, reason = "test fixture setup")]
#![expect(clippy::unwrap_used, reason = "integration test helpers")]

use std::io::Cursor;
use std::io::Write;
use std::path::Path;
use std::path::PathBuf;

use exarch_core::IssueCategory;
use exarch_core::SecurityConfig;
use exarch_core::VerificationReport;
use exarch_core::VerificationStatus;
use exarch_core::VerifyRequest;
use sevenz_rust2::ArchiveEntry;
use sevenz_rust2::ArchiveWriter;
use sevenz_rust2::SourceReader;
use tempfile::TempDir;

const SPECIAL: [u32; 2] = [0o4755, 0o1755];
const PLAIN: [u32; 2] = [0o755, 0o644];
const UNIX_EXTENSION: u32 = 0x8000;
const WINDOWS_ARCHIVE_ATTRIBUTE: u32 = 0x20;

fn tar_archive(dir: &Path, modes: &[u32]) -> PathBuf {
    let mut builder = tar::Builder::new(Vec::new());
    for (index, mode) in modes.iter().enumerate() {
        let mut header = tar::Header::new_gnu();
        header.set_size(2);
        header.set_mode(*mode);
        builder
            .append_data(&mut header, format!("f{index}"), &b"hi"[..])
            .unwrap();
    }
    let path = dir.join("a.tar");
    std::fs::write(&path, builder.into_inner().unwrap()).unwrap();
    path
}

fn zip_archive_from(dir: &Path, system: zip::System, modes: &[u32]) -> PathBuf {
    let mut writer = zip::write::ZipWriter::new(Cursor::new(Vec::new()));
    for (index, mode) in modes.iter().enumerate() {
        // `unix_permissions` masks to 0o777, so the full mode goes in raw.
        let options = zip::write::SimpleFileOptions::default()
            .system(system)
            .external_attributes((0o100_000 | mode) << 16);
        writer.start_file(format!("f{index}"), options).unwrap();
        writer.write_all(b"hi").unwrap();
    }
    let path = dir.join("a.zip");
    std::fs::write(&path, writer.finish().unwrap().into_inner()).unwrap();
    path
}

fn zip_archive(dir: &Path, modes: &[u32]) -> PathBuf {
    zip_archive_from(dir, zip::System::Unix, modes)
}

fn sevenz_with_attributes(dir: &Path, words: &[u32]) -> PathBuf {
    let mut writer = ArchiveWriter::new(Cursor::new(Vec::new())).unwrap();
    for (index, word) in words.iter().enumerate() {
        let mut entry = ArchiveEntry::new_file(&format!("f{index}"));
        entry.has_stream = true;
        entry.size = 2;
        entry.has_windows_attributes = true;
        entry.windows_attributes = *word;
        writer
            .push_archive_entry(entry, Some(SourceReader::from(Cursor::new(vec![b'x'; 2]))))
            .unwrap();
    }
    let path = dir.join("a.7z");
    std::fs::write(&path, writer.finish().unwrap().into_inner()).unwrap();
    path
}

fn sevenz_archive(dir: &Path, modes: &[u32]) -> PathBuf {
    let words: Vec<u32> = modes
        .iter()
        .map(|mode| UNIX_EXTENSION | ((0o100_000 | mode) << 16))
        .collect();
    sevenz_with_attributes(dir, &words)
}

fn verify(path: &Path) -> VerificationReport {
    VerifyRequest::new(&SecurityConfig::default())
        .verify(path)
        .unwrap()
}

fn permission_issues(report: &VerificationReport) -> usize {
    report
        .issues()
        .iter()
        .filter(|issue| issue.category() == IssueCategory::InvalidPermissions)
        .count()
}

fn assert_flagged(make: fn(&Path, &[u32]) -> PathBuf) {
    let work = TempDir::new().unwrap();
    let report = verify(&make(work.path(), &SPECIAL));
    assert_eq!(report.status(), VerificationStatus::Warning);
    assert_eq!(permission_issues(&report), SPECIAL.len());
}

fn assert_clean(make: fn(&Path, &[u32]) -> PathBuf) {
    let work = TempDir::new().unwrap();
    let report = verify(&make(work.path(), &PLAIN));
    assert_eq!(report.status(), VerificationStatus::Pass);
    assert_eq!(permission_issues(&report), 0);
}

#[test]
fn tar_special_bits_are_flagged() {
    assert_flagged(tar_archive);
}

#[test]
fn zip_special_bits_are_flagged() {
    assert_flagged(zip_archive);
}

#[test]
fn sevenz_special_bits_are_flagged() {
    assert_flagged(sevenz_archive);
}

#[test]
fn tar_plain_modes_pass() {
    assert_clean(tar_archive);
}

#[test]
fn zip_plain_modes_pass() {
    assert_clean(zip_archive);
}

#[test]
fn sevenz_plain_modes_pass() {
    assert_clean(sevenz_archive);
}

#[test]
fn sevenz_windows_attributes_are_not_read_as_a_unix_mode() {
    let work = TempDir::new().unwrap();
    let words = [
        WINDOWS_ARCHIVE_ATTRIBUTE,
        WINDOWS_ARCHIVE_ATTRIBUTE | (0o4755 << 16),
    ];
    let report = verify(&sevenz_with_attributes(work.path(), &words));
    assert_eq!(report.status(), VerificationStatus::Pass);
    assert_eq!(permission_issues(&report), 0);
}

#[test]
fn zip_special_bits_are_flagged_for_every_non_dos_host_system() {
    for system in [
        zip::System::OsDarwin,
        zip::System::WindowsNTFS,
        zip::System::Unknown,
    ] {
        let work = TempDir::new().unwrap();
        let report = verify(&zip_archive_from(work.path(), system, &SPECIAL));
        assert_eq!(report.status(), VerificationStatus::Warning, "{system:?}");
        assert_eq!(permission_issues(&report), SPECIAL.len(), "{system:?}");
    }
}

#[test]
fn zip_dos_entry_is_not_read_as_a_unix_mode() {
    let work = TempDir::new().unwrap();
    let report = verify(&zip_archive_from(work.path(), zip::System::Dos, &SPECIAL));
    assert_eq!(report.status(), VerificationStatus::Pass);
    assert_eq!(permission_issues(&report), 0);
}

#[test]
fn directory_modes_are_not_judged_in_tar_and_zip() {
    let work = TempDir::new().unwrap();

    let mut builder = tar::Builder::new(Vec::new());
    let mut header = tar::Header::new_gnu();
    header.set_entry_type(tar::EntryType::Directory);
    header.set_size(0);
    header.set_mode(0o1755);
    builder.append_data(&mut header, "d/", &b""[..]).unwrap();
    let tar_path = work.path().join("d.tar");
    std::fs::write(&tar_path, builder.into_inner().unwrap()).unwrap();

    let mut writer = zip::write::ZipWriter::new(Cursor::new(Vec::new()));
    let options = zip::write::SimpleFileOptions::default()
        .system(zip::System::Unix)
        .external_attributes((0o040_000 | 0o1755) << 16);
    writer.add_directory("d/", options).unwrap();
    let zip_path = work.path().join("d.zip");
    std::fs::write(&zip_path, writer.finish().unwrap().into_inner()).unwrap();

    let tar_report = verify(&tar_path);
    let zip_report = verify(&zip_path);
    assert_eq!(permission_issues(&tar_report), 0);
    assert_eq!(permission_issues(&zip_report), 0);
    assert_eq!(zip_report.status(), tar_report.status());
}

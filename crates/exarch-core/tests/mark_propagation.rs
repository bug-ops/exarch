//! Download-origin mark propagation: files an extraction creates carry the
//! mark of the archive file (macOS quarantine attribute, Windows
//! `Zone.Identifier` stream), and nothing else ever does.
//!
//! Linux has no mark, so this file has no tests there.

#![cfg(any(target_os = "macos", windows))]
#![allow(clippy::unwrap_used)]
#![allow(clippy::disallowed_methods)]

use std::collections::BTreeSet;
use std::io::Write;
use std::path::Path;

use exarch_core::DecodeReuse;
use exarch_core::ExistingFiles;
use exarch_core::ExtractRequest;
use exarch_core::ExtractionOptions;
use exarch_core::ExtractionReport;
use exarch_core::ListRequest;
use exarch_core::ListedExtractOptions;
use exarch_core::MarkOutcome;
use exarch_core::MarkPropagation;
use exarch_core::NoopProgress;
use exarch_core::SecurityConfig;
use exarch_core::Staging;
use tempfile::TempDir;

mod common;

use common::sevenz_fixture;
use common::tar_fixture;
use common::tar_header;
use common::zip_fixture;

#[cfg(target_os = "macos")]
mod platform {
    use std::path::Path;

    use rustix::fs::XattrFlags;
    use rustix::io::Errno;

    const NAME: &str = "com.apple.quarantine";
    const SOURCE: &[u8] = b"0083;5f3c8d11;Safari;3F2D5A10-1111-4222-8333-444455556666";

    pub const DIRECTORIES_ARE_MARKED: bool = true;

    pub fn mark_archive(path: &Path) {
        rustix::fs::setxattr(path, NAME, SOURCE, XattrFlags::empty()).unwrap();
    }

    pub fn mark_of(path: &Path) -> Option<String> {
        let mut buffer = [0_u8; 256];
        match rustix::fs::getxattr(path, NAME, &mut buffer[..]) {
            Ok(len) => Some(String::from_utf8(buffer[..len].to_vec()).unwrap()),
            Err(Errno::NOATTR) => None,
            Err(error) => panic!("{}: {error}", path.display()),
        }
    }

    pub fn assert_mark_derives_from_source(value: &str) {
        let fields: Vec<_> = value.split(';').collect();
        assert_eq!(&fields[..2], ["0003", "5f3c8d11"], "{value}");
        assert_ne!(fields[3], "3F2D5A10-1111-4222-8333-444455556666", "{value}");
    }
}

#[cfg(windows)]
mod platform {
    use std::path::Path;

    pub const DIRECTORIES_ARE_MARKED: bool = false;

    fn stream(path: &Path) -> String {
        format!("{}:Zone.Identifier", path.display())
    }

    pub fn mark_archive(path: &Path) {
        std::fs::write(stream(path), "[ZoneTransfer]\r\nZoneId=3\r\n").unwrap();
    }

    pub fn mark_of(path: &Path) -> Option<String> {
        std::fs::read_to_string(stream(path)).ok()
    }

    pub fn assert_mark_derives_from_source(value: &str) {
        assert!(value.contains("ZoneId=3"), "{value}");
    }
}

use platform::DIRECTORIES_ARE_MARKED;
use platform::mark_archive;
use platform::mark_of;

const FILES: [&str; 4] = ["App.app/Contents/MacOS/run", "ro.txt", "exec", "link.txt"];
const DIRECTORIES: [&str; 3] = ["App.app", "App.app/Contents", "App.app/Contents/MacOS"];

fn config() -> SecurityConfig {
    SecurityConfig::default().with_allow_hardlinks(true)
}

fn when_marked() -> ExtractionOptions {
    ExtractionOptions::default().with_mark_propagation(MarkPropagation::WhenMarked)
}

fn extract(archive: &Path, out: &Path, options: ExtractionOptions) -> ExtractionReport {
    ExtractRequest::new(&config())
        .with_options(options)
        .extract(archive, out)
        .unwrap()
}

fn expected_marked(files: usize, directories: usize) -> MarkOutcome {
    let directories = if DIRECTORIES_ARE_MARKED {
        directories
    } else {
        0
    };
    MarkOutcome::Propagated {
        marked: files + directories,
        failed: 0,
    }
}

#[test]
fn tar_files_and_run_created_directories_carry_a_fresh_mark() {
    let work = TempDir::new().unwrap();
    let archive = tar_fixture(work.path());
    mark_archive(&archive);
    let out = TempDir::new().unwrap();

    let report = extract(&archive, out.path(), when_marked());

    assert_eq!(report.mark, expected_marked(FILES.len(), DIRECTORIES.len()));
    let mut values = BTreeSet::new();
    for name in FILES {
        let value = mark_of(&out.path().join(name)).unwrap_or_else(|| panic!("{name} unmarked"));
        platform::assert_mark_derives_from_source(&value);
        values.insert(value);
    }
    assert_eq!(values.len(), FILES.len(), "every file gets its own value");
    for name in DIRECTORIES {
        assert_eq!(
            mark_of(&out.path().join(name)).is_some(),
            DIRECTORIES_ARE_MARKED,
            "{name}"
        );
    }
    assert!(
        mark_of(out.path()).is_none(),
        "the destination root is never marked"
    );
}

#[test]
fn never_marks_nothing_and_reports_not_requested() {
    let work = TempDir::new().unwrap();
    let archive = tar_fixture(work.path());
    mark_archive(&archive);
    let out = TempDir::new().unwrap();

    let report = extract(&archive, out.path(), ExtractionOptions::default());

    assert_eq!(report.mark, MarkOutcome::NotRequested);
    for name in FILES.iter().chain(&DIRECTORIES) {
        assert!(mark_of(&out.path().join(name)).is_none(), "{name}");
    }
}

#[test]
fn an_unmarked_archive_marks_nothing() {
    let work = TempDir::new().unwrap();
    let archive = tar_fixture(work.path());
    let out = TempDir::new().unwrap();

    let report = extract(&archive, out.path(), when_marked());

    assert_eq!(report.mark, MarkOutcome::Unmarked);
    for name in FILES {
        assert!(mark_of(&out.path().join(name)).is_none(), "{name}");
    }
}

#[cfg(unix)]
#[test]
fn read_only_entries_are_marked_before_their_mode_applies() {
    use std::os::unix::fs::PermissionsExt;

    let work = TempDir::new().unwrap();
    let archive = tar_fixture(work.path());
    mark_archive(&archive);
    let out = TempDir::new().unwrap();

    extract(&archive, out.path(), when_marked());

    for (name, mode) in [("ro.txt", 0o444), ("exec", 0o555), ("link.txt", 0o444)] {
        let path = out.path().join(name);
        assert!(mark_of(&path).is_some(), "{name} unmarked");
        let actual = std::fs::metadata(&path).unwrap().permissions().mode() & 0o7777;
        assert_eq!(actual, mode, "{name}");
    }
}

#[test]
fn pre_existing_directories_are_not_marked() {
    let work = TempDir::new().unwrap();
    let archive = tar_fixture(work.path());
    mark_archive(&archive);
    let out = TempDir::new().unwrap();
    std::fs::create_dir(out.path().join("App.app")).unwrap();

    extract(&archive, out.path(), when_marked());

    assert!(mark_of(&out.path().join("App.app")).is_none());
    assert_eq!(
        mark_of(&out.path().join("App.app/Contents")).is_some(),
        DIRECTORIES_ARE_MARKED
    );
    assert!(mark_of(&out.path().join("ro.txt")).is_some());
}

#[test]
fn an_overwritten_entry_is_marked_with_its_exact_mode() {
    let work = TempDir::new().unwrap();
    let archive = tar_fixture(work.path());
    mark_archive(&archive);
    let out = TempDir::new().unwrap();
    std::fs::write(out.path().join("ro.txt"), b"old").unwrap();

    let options = when_marked().with_existing_files(ExistingFiles::Overwrite);
    extract(&archive, out.path(), options);

    let path = out.path().join("ro.txt");
    assert_eq!(std::fs::read(&path).unwrap(), b"data");
    assert!(mark_of(&path).is_some());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o7777,
            0o444
        );
    }
}

#[test]
fn an_atomic_extraction_keeps_the_marks_after_it_publishes() {
    let work = TempDir::new().unwrap();
    let archive = tar_fixture(work.path());
    mark_archive(&archive);
    let out = work.path().join("published");

    let report = extract(&archive, &out, when_marked().with_staging(Staging::Atomic));

    assert_eq!(report.mark, expected_marked(FILES.len(), DIRECTORIES.len()));
    for name in FILES {
        assert!(mark_of(&out.join(name)).is_some(), "{name}");
    }
    assert!(mark_of(&out).is_none(), "the published root is not marked");
}

#[test]
fn zip_and_7z_files_are_marked() {
    let work = TempDir::new().unwrap();
    for archive in [zip_fixture(work.path()), sevenz_fixture(work.path())] {
        mark_archive(&archive);
        let out = TempDir::new().unwrap();

        let report = extract(&archive, out.path(), when_marked());

        assert_eq!(report.mark, expected_marked(2, 1), "{}", archive.display());
        for name in ["ro.txt", "nested/inner.txt"] {
            assert!(mark_of(&out.path().join(name)).is_some(), "{name}");
        }
    }
}

#[test]
fn a_listed_extraction_marks_zip_and_a_tar_spool() {
    let work = TempDir::new().unwrap();
    let zip = zip_fixture(work.path());
    let tar_gz = work.path().join("fixture.tar.gz");
    let mut encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
    encoder
        .write_all(&std::fs::read(tar_fixture(work.path())).unwrap())
        .unwrap();
    std::fs::write(&tar_gz, encoder.finish().unwrap()).unwrap();

    for (archive, name) in [(zip, "ro.txt"), (tar_gz, "ro.txt")] {
        mark_archive(&archive);
        let config = config();
        let listed = ListRequest::new(&config)
            .for_extraction(&archive, DecodeReuse::default())
            .unwrap();
        let out = TempDir::new().unwrap();

        let options =
            ListedExtractOptions::default().with_mark_propagation(MarkPropagation::WhenMarked);
        let report = listed
            .extract(out.path(), &options, &mut NoopProgress)
            .unwrap();

        assert!(matches!(
            report.mark,
            MarkOutcome::Propagated { failed: 0, .. }
        ));
        assert!(
            mark_of(&out.path().join(name)).is_some(),
            "{}",
            archive.display()
        );
    }
}

#[test]
fn an_entry_named_like_a_mark_stream_is_still_refused() {
    let work = TempDir::new().unwrap();
    let mut builder = tar::Builder::new(Vec::new());
    for name in ["x:Zone.Identifier", "x::$DATA"] {
        let mut header = tar_header(tar::EntryType::Regular, 0o644, 4);
        header.set_path("placeholder").unwrap();
        let mut raw = [0_u8; 100];
        raw[..name.len()].copy_from_slice(name.as_bytes());
        header.as_old_mut().name = raw;
        header.set_cksum();
        builder.append(&header, &b"data"[..]).unwrap();
    }
    let archive = work.path().join("streams.tar");
    std::fs::write(&archive, builder.into_inner().unwrap()).unwrap();
    mark_archive(&archive);
    let out = TempDir::new().unwrap();

    let result = ExtractRequest::new(&config())
        .with_options(when_marked())
        .extract(&archive, out.path());

    if cfg!(windows) {
        assert!(result.is_err());
        assert_eq!(std::fs::read_dir(out.path()).unwrap().count(), 0);
    } else {
        // The macOS host model accepts ':' in a name: the entries are plain
        // files with those literal names and get the mark any file gets.
        result.unwrap();
        for name in ["x:Zone.Identifier", "x::$DATA"] {
            let value = mark_of(&out.path().join(name)).unwrap();
            platform::assert_mark_derives_from_source(&value);
        }
    }
}

#[cfg(target_os = "macos")]
fn set_raw_mark(path: &Path, value: &[u8]) {
    rustix::fs::setxattr(
        path,
        "com.apple.quarantine",
        value,
        rustix::fs::XattrFlags::empty(),
    )
    .unwrap();
}

/// A mark that is present but cannot be read is still a mark: files get the
/// most conservative one instead of none.
#[cfg(target_os = "macos")]
#[test]
fn a_malformed_or_oversized_source_mark_propagates_the_conservative_mark() {
    for value in [&b"garbage"[..], &[b'x'; 1024], b"\xff\xfe;;"] {
        let work = TempDir::new().unwrap();
        let archive = tar_fixture(work.path());
        set_raw_mark(&archive, value);
        let out = TempDir::new().unwrap();

        let report = extract(&archive, out.path(), when_marked());

        assert_eq!(report.mark, expected_marked(FILES.len(), DIRECTORIES.len()));
        let mark = mark_of(&out.path().join("ro.txt")).unwrap();
        assert!(mark.starts_with("0001;"), "{mark}");
    }
}

/// The listed route reads the mark from the handle it listed, so replacing the
/// archive afterwards neither drops nor changes the mark.
#[cfg(target_os = "macos")]
#[test]
fn a_listed_extraction_marks_from_the_listed_handle_not_the_path() {
    for name in ["zip", "tar.gz"] {
        let work = TempDir::new().unwrap();
        let archive = if name == "zip" {
            zip_fixture(work.path())
        } else {
            let tar_gz = work.path().join("fixture.tar.gz");
            let mut encoder =
                flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::fast());
            encoder
                .write_all(&std::fs::read(tar_fixture(work.path())).unwrap())
                .unwrap();
            std::fs::write(&tar_gz, encoder.finish().unwrap()).unwrap();
            tar_gz
        };
        mark_archive(&archive);
        let config = config();
        let listed = ListRequest::new(&config)
            .for_extraction(&archive, DecodeReuse::default())
            .unwrap();

        let unmarked_copy = work.path().join("unmarked");
        std::fs::copy(&archive, &unmarked_copy).unwrap();
        rustix::fs::removexattr(&unmarked_copy, "com.apple.quarantine").unwrap();
        std::fs::rename(&unmarked_copy, &archive).unwrap();
        assert!(mark_of(&archive).is_none());

        let out = TempDir::new().unwrap();
        let options =
            ListedExtractOptions::default().with_mark_propagation(MarkPropagation::WhenMarked);
        let report = listed
            .extract(out.path(), &options, &mut NoopProgress)
            .unwrap();

        assert!(
            matches!(report.mark, MarkOutcome::Propagated { failed: 0, .. }),
            "{name}"
        );
        assert!(mark_of(&out.path().join("ro.txt")).is_some(), "{name}");
    }
}

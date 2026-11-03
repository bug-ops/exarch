//! The extension allowlist applies the same way in TAR, ZIP and 7z: path
//! validation first, then the allowlist, then quota. A skipped file charges
//! no bytes, creates nothing, and `list` counts it toward the file limit only.

#![allow(clippy::unwrap_used)]
#![allow(clippy::disallowed_methods)]

mod common;
mod sink_support;

use std::assert_matches;
use std::io::Cursor;
use std::io::Write as _;
use std::path::Path;

use exarch_core::ArchiveError;
use exarch_core::QuotaResource;
use exarch_core::SecurityConfig;
use exarch_core::extract_archive;
use exarch_core::list_archive;
use sevenz_rust2::ArchiveEntry;
use sevenz_rust2::ArchiveWriter;
use tempfile::TempDir;
use zip::CompressionMethod;
use zip::write::SimpleFileOptions;

const BIG: usize = 2_000;
const LIMIT: u64 = 1_000;

#[derive(Debug, Clone, Copy)]
enum Format {
    Tar,
    Zip,
    SevenZ,
}

const FORMATS: [Format; 3] = [Format::Tar, Format::Zip, Format::SevenZ];

impl Format {
    const fn file_name(self) -> &'static str {
        match self {
            Self::Tar => "a.tar",
            Self::Zip => "a.zip",
            Self::SevenZ => "a.7z",
        }
    }

    /// Builds an archive of stored files, keeping names as given (`..` too).
    fn build(self, files: &[(&str, &[u8])]) -> Vec<u8> {
        match self {
            Self::Tar => sink_support::tar_archive(
                &files
                    .iter()
                    .map(|(name, data)| sink_support::tar_file(name, data))
                    .collect::<Vec<_>>(),
            ),
            Self::Zip => sink_support::zip_archive(
                files
                    .iter()
                    .map(|(name, data)| sink_support::zip_file(name, data))
                    .collect(),
            ),
            Self::SevenZ => common::solid_copy_7z(
                &files
                    .iter()
                    .map(|(name, data)| common::RawEntry::File(name, data))
                    .collect::<Vec<_>>(),
            ),
        }
    }

    fn write(self, dir: &Path, bytes: &[u8]) -> std::path::PathBuf {
        let path = dir.join(self.file_name());
        std::fs::write(&path, bytes).unwrap();
        path
    }
}

fn config() -> SecurityConfig {
    SecurityConfig::default()
        .with_allow_solid_archives(true)
        .with_allowed_extensions(vec!["txt".into()])
        .with_max_total_size(LIMIT)
}

fn root(error: &ArchiveError) -> &ArchiveError {
    match error {
        ArchiveError::PartialExtraction { source, .. } => root(source),
        other => other,
    }
}

fn mixed(format: Format) -> Vec<u8> {
    format.build(&[
        ("a.txt", b"hi"),
        ("deep/dir/big.bin", &[7; BIG]),
        ("b.txt", b"yo"),
    ])
}

#[test]
fn a_skipped_file_charges_no_quota_on_a_fresh_and_an_existing_destination() {
    for format in FORMATS {
        let work = TempDir::new().unwrap();
        let archive = format.write(work.path(), &mixed(format));
        let existing = TempDir::new().unwrap();
        let fresh = work.path().join("fresh");

        for dest in [existing.path(), fresh.as_path()] {
            let report = extract_archive(&archive, dest, &config())
                .unwrap_or_else(|e| panic!("{format:?} into {}: {e}", dest.display()));

            assert_eq!(report.files_extracted, 2, "{format:?}");
            assert_eq!(report.files_skipped, 1, "{format:?}");
            assert!(dest.join("a.txt").is_file(), "{format:?}");
            assert!(!dest.join("deep/dir/big.bin").exists(), "{format:?}");
        }
    }
}

#[test]
fn a_skipped_file_leaves_no_directory_behind() {
    for format in FORMATS {
        let work = TempDir::new().unwrap();
        let archive = format.write(work.path(), &mixed(format));
        let dest = work.path().join("out");

        extract_archive(&archive, &dest, &config()).unwrap();

        assert!(!dest.join("deep").exists(), "{format:?}");
    }
}

#[test]
fn a_disallowed_file_with_a_traversal_path_is_refused_not_skipped() {
    for format in FORMATS {
        let work = TempDir::new().unwrap();
        let dest = work.path().join("out");
        let archive = format.write(
            work.path(),
            &format.build(&[("a.txt", b"hi"), ("../x.bin", b"escape")]),
        );

        let error = extract_archive(&archive, &dest, &config()).unwrap_err();

        assert_matches!(
            root(&error),
            ArchiveError::PathTraversal { .. },
            "{format:?}"
        );
        assert!(!work.path().join("x.bin").exists(), "{format:?}");
    }
}

#[test]
fn list_counts_a_disallowed_file_toward_the_file_limit_only() {
    for format in FORMATS {
        let work = TempDir::new().unwrap();
        let archive = format.write(work.path(), &mixed(format));

        let manifest = list_archive(&archive, &config()).unwrap();
        assert_eq!(manifest.entries().len(), 3, "{format:?}");

        let tight = config().with_max_file_count(2);
        let error = list_archive(&archive, &tight).unwrap_err();
        assert_matches!(
            error,
            ArchiveError::QuotaExceeded {
                resource: QuotaResource::FileCount { .. }
            },
            "{format:?}"
        );
    }
}

fn zip_with_zeros(name: &str) -> Vec<u8> {
    let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let options = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
    writer.start_file("a.txt", options).unwrap();
    writer.write_all(b"hi").unwrap();
    writer.start_file(name, options).unwrap();
    writer.write_all(&vec![0; 2 << 20]).unwrap();
    writer.finish().unwrap().into_inner()
}

fn sevenz_with_zeros(name: &str) -> Vec<u8> {
    let mut writer = ArchiveWriter::new(Cursor::new(Vec::new())).unwrap();
    let zeros = vec![0u8; 2 << 20];
    for (name, data) in [("a.txt", &b"hi"[..]), (name, zeros.as_slice())] {
        let mut entry = ArchiveEntry::new_file(name);
        entry.has_stream = true;
        entry.size = data.len() as u64;
        writer.push_archive_entry(entry, Some(data)).unwrap();
    }
    writer.finish().unwrap().into_inner()
}

#[test]
fn a_disallowed_high_ratio_file_is_skipped_in_zip_and_refused_in_7z() {
    let work = TempDir::new().unwrap();
    let relaxed = SecurityConfig::default()
        .with_allow_solid_archives(true)
        .with_allowed_extensions(vec!["txt".into()]);

    let zip = Format::Zip.write(work.path(), &zip_with_zeros("bomb.bin"));
    let report = extract_archive(&zip, work.path().join("zip-out"), &relaxed).unwrap();
    assert_eq!(report.files_skipped, 1);

    let sevenz = Format::SevenZ.write(work.path(), &sevenz_with_zeros("bomb.bin"));
    let error = extract_archive(&sevenz, work.path().join("7z-out"), &relaxed).unwrap_err();
    assert_matches!(root(&error), ArchiveError::ZipBomb(_));
}

#[test]
fn verify_enforces_the_file_limit_equally_for_allowed_and_skipped_files() {
    for format in FORMATS {
        let work = TempDir::new().unwrap();
        let tight = config().with_max_file_count(2);
        let outcome = |names: [&str; 3]| {
            let bytes = format.build(&names.map(|name| (name, &b"x"[..])));
            let archive = format.write(work.path(), &bytes);
            let result = exarch_core::verify_archive(&archive, &tight);
            matches!(
                result,
                Err(ArchiveError::QuotaExceeded {
                    resource: QuotaResource::FileCount { .. }
                })
            )
        };

        assert!(outcome(["a.txt", "b.txt", "c.txt"]), "{format:?} allowed");
        assert!(outcome(["a.bin", "b.bin", "c.bin"]), "{format:?} skipped");
    }
}

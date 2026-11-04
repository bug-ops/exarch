//! The validation pipeline, driven by whole archives through `extract_archive`.
//!
//! One pipeline decides every entry. These tests exercise it end to end, the
//! way an attacker reaches it: CVE-2025-4517-style `..` traversal variants,
//! absolute paths, path-depth limits, banned components (including a
//! case-insensitive bypass attempt), symlink and hardlink escapes, the
//! disabled-by-default link policies, and zip-bomb ratio and quota ordering.

#![allow(clippy::unwrap_used)]

#[path = "../sink_support/mod.rs"]
mod sink_support;

use std::assert_matches;

use exarch_core::ArchiveError;
use exarch_core::ExtractionReport;
use exarch_core::Limit;
use exarch_core::QuotaResource;
use exarch_core::SecurityConfig;
use exarch_core::extract_archive;
use exarch_testkit::raw_zip::RawEntry;
use exarch_testkit::raw_zip::deflate_zeros;
use sink_support::tar_archive;
use sink_support::tar_file;
use sink_support::tar_hardlink;
use sink_support::tar_symlink;
use sink_support::zip_archive;
use sink_support::zip_file;
use tempfile::TempDir;

fn extract_bytes(
    name: &str,
    bytes: &[u8],
    config: &SecurityConfig,
) -> Result<ExtractionReport, ArchiveError> {
    let dir = TempDir::new().unwrap();
    let archive = dir.path().join(name);
    std::fs::write(&archive, bytes).unwrap();
    let out = dir.path().join("out");
    std::fs::create_dir(&out).unwrap();
    extract_archive(&archive, &out, config)
}

fn extract_tar(
    entries: &[Vec<u8>],
    config: &SecurityConfig,
) -> Result<ExtractionReport, ArchiveError> {
    extract_bytes("a.tar", &tar_archive(entries), config)
}

fn extract_zip(
    entries: Vec<RawEntry>,
    config: &SecurityConfig,
) -> Result<ExtractionReport, ArchiveError> {
    extract_bytes("a.zip", &zip_archive(entries), config)
}

fn one_file(name: &str) -> Result<ExtractionReport, ArchiveError> {
    extract_tar(&[tar_file(name, b"x")], &SecurityConfig::default())
}

#[test]
fn parent_traversal_variants_are_refused() {
    for path in [
        "../etc/passwd",
        "../../etc/passwd",
        "foo/../../etc/passwd",
        "foo/../../../etc/passwd",
    ] {
        assert_matches!(
            one_file(path),
            Err(ArchiveError::PathTraversal { .. }),
            "{path}"
        );
    }
}

#[cfg(unix)]
#[test]
fn absolute_paths_are_refused() {
    for path in ["/etc/passwd", "/tmp/malicious"] {
        assert!(one_file(path).is_err(), "{path}");
    }
}

#[test]
fn a_name_with_a_nul_byte_is_refused() {
    let result = extract_zip(
        vec![zip_file("file\0.txt", b"x")],
        &SecurityConfig::default(),
    );
    assert!(result.is_err());
}

#[test]
fn a_path_deeper_than_the_limit_is_refused() {
    // Short components keep the whole name inside a TAR header's name field.
    let deep = ["d"; 40].join("/");
    assert!(one_file(&deep).is_err());
}

#[test]
fn banned_components_are_refused_in_any_case() {
    for path in [
        ".git/config",
        ".ssh/id_rsa",
        ".gnupg/private-keys-v1.d/key.key",
        ".aws/credentials",
        ".kube/config",
        ".docker/config.json",
        ".env",
        ".Git/config",
        ".SSH/id_rsa",
        ".GNUPG/key",
        ".Aws/credentials",
    ] {
        assert!(one_file(path).is_err(), "{path}");
    }
}

#[test]
fn ordinary_paths_extract() {
    let entries: Vec<_> = [
        "README.md",
        "src/main.rs",
        "foo/bar/baz.txt",
        "data/config.json",
        "docs/guide.md",
    ]
    .into_iter()
    .map(|path| tar_file(path, b"x"))
    .collect();
    let report = extract_tar(&entries, &SecurityConfig::default()).unwrap();
    assert_eq!(report.files_extracted, 5);
}

fn links_allowed() -> SecurityConfig {
    SecurityConfig::default()
        .with_allow_symlinks(true)
        .with_allow_hardlinks(true)
}

#[test]
fn symlink_targets_that_leave_the_root_are_refused() {
    for (link, target) in [
        ("malicious_link", "/etc/passwd"),
        ("safe/link", "../../etc/passwd"),
        ("a/b/c/link", "../../../../etc/passwd"),
    ] {
        let result = extract_tar(&[tar_symlink(link, target)], &links_allowed());
        assert_matches!(
            result,
            Err(ArchiveError::SymlinkEscape { .. }),
            "{link} -> {target}"
        );
    }
}

#[test]
fn symlinks_are_refused_by_default() {
    let result = extract_tar(
        &[tar_symlink("link", "target.txt")],
        &SecurityConfig::default(),
    );
    assert_matches!(result, Err(ArchiveError::SecurityViolation { .. }));
}

#[test]
fn symlinks_that_stay_inside_the_root_extract() {
    for (link, target) in [("foo/link", "../bar/target.txt"), ("link", "target.txt")] {
        let report = extract_tar(&[tar_symlink(link, target)], &links_allowed()).unwrap();
        assert_eq!(report.symlinks_created, 1, "{link} -> {target}");
    }
}

#[test]
fn hardlink_targets_that_leave_the_root_are_refused() {
    for (link, target) in [
        ("malicious_hardlink", "/etc/passwd"),
        ("link", "../../etc/passwd"),
        ("a/b/c/link", "../../../../etc/passwd"),
    ] {
        let result = extract_tar(&[tar_hardlink(link, target)], &links_allowed());
        assert_matches!(
            result,
            Err(ArchiveError::HardlinkEscape { .. }),
            "{link} -> {target}"
        );
    }
}

#[test]
fn hardlinks_are_refused_by_default() {
    let result = extract_tar(
        &[tar_hardlink("link", "target.txt")],
        &SecurityConfig::default(),
    );
    assert_matches!(result, Err(ArchiveError::SecurityViolation { .. }));
}

#[test]
fn hardlinks_to_files_inside_the_root_extract_and_count() {
    let entries = [
        tar_file("foo/target.txt", b"one"),
        tar_file("target2.txt", b"two"),
        tar_hardlink("foo/link", "foo/target.txt"),
        tar_hardlink("link2", "target2.txt"),
    ];
    let report = extract_tar(&entries, &links_allowed()).unwrap();
    assert_eq!(report.files_extracted, 4);
}

const MIB: u64 = 1024 * 1024;

fn deflated_zeros(name: &str, len: u64) -> RawEntry {
    RawEntry {
        method: 8,
        data: deflate_zeros(len),
        size: len,
        ..zip_file(name, b"")
    }
}

#[test]
fn an_oversized_bomb_is_a_file_size_refusal_before_the_ratio_check() {
    let result = extract_zip(
        vec![deflated_zeros("42.zip", 60 * MIB)],
        &SecurityConfig::default(),
    );
    assert_matches!(
        result,
        Err(ArchiveError::QuotaExceeded {
            resource: QuotaResource::FileSize { .. }
        })
    );
}

#[test]
fn a_bomb_within_the_quotas_is_refused_by_ratio() {
    let config = SecurityConfig::default()
        .with_max_file_size(Limit::Unbounded)
        .with_max_total_size(Limit::Unbounded);
    let result = extract_zip(vec![deflated_zeros("bomb.bin", 1024 * MIB)], &config);
    assert_matches!(result, Err(ArchiveError::ZipBomb(_)));
}

#[test]
fn a_stored_entry_has_no_ratio_to_trip() {
    let report = extract_zip(
        vec![zip_file("ok.txt", b"hello")],
        &SecurityConfig::default(),
    )
    .unwrap();
    assert_eq!(report.files_extracted, 1);
}

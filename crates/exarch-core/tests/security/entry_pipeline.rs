//! The validation pipeline, driven by whole archives through `extract_archive`.
//!
//! One pipeline decides every entry. These tests exercise it end to end, the
//! way an attacker reaches it: CVE-2025-4517-style `..` traversal variants,
//! absolute paths, path-depth limits, banned components (including a
//! case-insensitive bypass attempt), symlink and hardlink escapes, the
//! disabled-by-default link policies, and zip-bomb ratio and quota ordering.

#![expect(clippy::unwrap_used, reason = "integration test helpers")]

use std::assert_matches;

use crate::sink_support::tar_archive;
use crate::sink_support::tar_file;
use crate::sink_support::tar_hardlink;
use crate::sink_support::tar_symlink;
use crate::sink_support::testkit::raw_zip::RawEntry;
use crate::sink_support::testkit::raw_zip::deflate_zeros;
use crate::sink_support::zip_archive;
use crate::sink_support::zip_file;
use crate::sink_support::zip_symlink;
use exarch_core::ArchiveError;
use exarch_core::ExtractionReport;
use exarch_core::Limit;
use exarch_core::QuotaResource;
use exarch_core::SecurityConfig;
use exarch_core::SolidArchives;
use exarch_core::SolidLimits;
use exarch_core::extract_archive;
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

const ALIAS_COMPONENTS: [&str; 6] = [
    ".\u{17f}sh",
    ".\u{df}h",
    ".\u{17f}\u{17f}h",
    ".aw\u{17f}",
    ".\u{212a}ube",
    ".doc\u{212a}er",
];

fn banned_signature(result: Result<ExtractionReport, ArchiveError>) -> String {
    match result {
        Ok(report) => format!("extracted {} files", report.files_extracted),
        Err(error) => crate::sink_support::signature(&error),
    }
}

fn assert_entry_banned(result: Result<ExtractionReport, ArchiveError>, what: &str) {
    let signature = banned_signature(result);
    assert!(
        signature.starts_with("SecurityViolation(BannedComponent"),
        "{what}: {signature}"
    );
}

fn assert_target_banned(result: Result<ExtractionReport, ArchiveError>, kind: &str, what: &str) {
    let signature = banned_signature(result);
    assert!(
        signature.starts_with(&format!(
            "SecurityViolation(LinkTargetBannedComponent {{ kind: {kind}"
        )),
        "{what}: {signature}"
    );
}

fn sevenz_config() -> SecurityConfig {
    links_allowed().with_solid_archives(SolidArchives::Allow(SolidLimits::DEFAULT))
}

fn extract_sevenz(
    entries: &[crate::common::RawEntry<'_>],
    config: &SecurityConfig,
) -> Result<ExtractionReport, ArchiveError> {
    extract_bytes("a.7z", &crate::common::solid_copy_7z(entries), config)
}

#[test]
fn tar_refuses_alias_spellings_of_banned_components() {
    for alias in ALIAS_COMPONENTS {
        let entry = format!("{alias}/authorized_keys");
        assert_entry_banned(
            extract_tar(&[tar_file(&entry, b"x")], &links_allowed()),
            &entry,
        );
        assert_target_banned(
            extract_tar(&[tar_symlink("link", &entry)], &links_allowed()),
            "Symlink",
            &entry,
        );
        assert_target_banned(
            extract_tar(&[tar_hardlink("link", &entry)], &links_allowed()),
            "Hardlink",
            &entry,
        );
    }
}

#[test]
fn zip_refuses_alias_spellings_of_banned_components() {
    for alias in ALIAS_COMPONENTS {
        let entry = format!("{alias}/authorized_keys");
        assert_entry_banned(
            extract_zip(vec![zip_file(&entry, b"x")], &links_allowed()),
            &entry,
        );
        assert_target_banned(
            extract_zip(vec![zip_symlink("link", &entry)], &links_allowed()),
            "Symlink",
            &entry,
        );
    }
}

#[test]
fn sevenz_refuses_alias_spellings_of_banned_components() {
    use crate::common::RawEntry;
    for alias in ALIAS_COMPONENTS {
        let entry = format!("{alias}/authorized_keys");
        assert_entry_banned(
            extract_sevenz(&[RawEntry::File(&entry, b"x")], &sevenz_config()),
            &entry,
        );
        if cfg!(unix) {
            assert_target_banned(
                extract_sevenz(
                    &[RawEntry::Link("link", entry.as_bytes())],
                    &sevenz_config(),
                ),
                "Symlink",
                &entry,
            );
        }
    }
}

#[test]
fn symlink_targets_with_alias_spellings_are_refused_in_every_format() {
    use crate::common::RawEntry;
    for alias in ALIAS_COMPONENTS {
        let target = format!("docs/{alias}");
        assert_target_banned(
            extract_tar(&[tar_symlink("link", &target)], &links_allowed()),
            "Symlink",
            &target,
        );
        assert_target_banned(
            extract_zip(vec![zip_symlink("link", &target)], &links_allowed()),
            "Symlink",
            &target,
        );
        if cfg!(unix) {
            assert_target_banned(
                extract_sevenz(
                    &[RawEntry::Link("link", target.as_bytes())],
                    &sevenz_config(),
                ),
                "Symlink",
                &target,
            );
        }
    }
}

#[test]
fn hardlink_into_a_banned_directory_is_refused_and_a_plain_one_is_not() {
    let into_banned = extract_tar(
        &[
            tar_file("ok.txt", b"x"),
            tar_hardlink("copy", ".ssh/id_ed25519"),
        ],
        &links_allowed(),
    );
    assert_target_banned(into_banned, "Hardlink", ".ssh/id_ed25519");

    let plain = extract_tar(
        &[tar_file("ok.txt", b"x"), tar_hardlink("copy", "ok.txt")],
        &links_allowed(),
    );
    assert!(plain.is_ok(), "{plain:?}");
}

#[test]
fn ignorable_code_points_do_not_hide_a_banned_component() {
    for entry in [
        ".s\u{200c}sh/config",
        ".\u{feff}ssh/config",
        ".ssh\u{200f}/config",
    ] {
        assert_entry_banned(
            extract_tar(&[tar_file(entry, b"x")], &links_allowed()),
            entry,
        );
        assert_target_banned(
            extract_tar(&[tar_symlink("link", entry)], &links_allowed()),
            "Symlink",
            entry,
        );
    }
}

#[cfg(unix)]
#[test]
fn hardlink_through_an_existing_destination_symlink_is_judged_where_it_lands() {
    use std::os::unix::fs::symlink;

    let dir = TempDir::new().unwrap();
    let archive = dir.path().join("a.tar");
    let out = dir.path().join("out");
    std::fs::create_dir_all(out.join(".ssh")).unwrap();
    std::fs::create_dir_all(out.join("docs")).unwrap();
    std::fs::File::create(out.join(".ssh/id")).unwrap();
    std::fs::File::create(out.join("docs/readme")).unwrap();
    symlink(".ssh", out.join("keys")).unwrap();
    symlink("docs", out.join("manuals")).unwrap();
    let config = SecurityConfig::default().with_allow_hardlinks(true);

    std::fs::write(&archive, tar_archive(&[tar_hardlink("copy", "keys/id")])).unwrap();
    assert_target_banned(
        extract_archive(&archive, &out, &config),
        "Hardlink",
        "keys/id",
    );
    assert!(!out.join("copy").exists());

    std::fs::write(
        &archive,
        tar_archive(&[tar_hardlink("copy", "manuals/readme")]),
    )
    .unwrap();
    extract_archive(&archive, &out, &config).unwrap();
    assert!(out.join("copy").exists());
}

#[test]
fn decomposed_spelling_of_a_configured_non_ascii_name_is_refused() {
    let config = links_allowed()
        .try_add_banned_path_component("caf\u{e9}")
        .unwrap();
    for spelled in ["caf\u{e9}", "cafe\u{301}", "CAFE\u{301}"] {
        let entry = format!("{spelled}/x");
        assert_entry_banned(extract_tar(&[tar_file(&entry, b"x")], &config), &entry);
        assert_target_banned(
            extract_tar(&[tar_symlink("link", &entry)], &config),
            "Symlink",
            &entry,
        );
        assert_target_banned(
            extract_tar(&[tar_hardlink("link", &entry)], &config),
            "Hardlink",
            &entry,
        );
    }
}

#[cfg(unix)]
mod through_symlinks {
    use super::*;
    use crate::common::RawEntry;
    use std::os::unix::fs::symlink;
    use std::path::Path;

    /// A destination holding `.ssh` and `docs` and the links `keys` (to
    /// `.ssh`), `alias` (to `keys`) and `manuals` (to `docs`).
    fn prepared() -> (TempDir, std::path::PathBuf) {
        let dir = TempDir::new().unwrap();
        let out = dir.path().join("out");
        std::fs::create_dir_all(out.join(".ssh")).unwrap();
        std::fs::create_dir_all(out.join("docs")).unwrap();
        symlink(".ssh", out.join("keys")).unwrap();
        symlink("keys", out.join("alias")).unwrap();
        symlink("docs", out.join("manuals")).unwrap();
        (dir, out)
    }

    #[derive(Clone, Copy)]
    enum Format {
        Tar,
        Zip,
        SevenZ,
    }

    impl Format {
        const ALL: [Self; 3] = [Self::Tar, Self::Zip, Self::SevenZ];

        fn extract(
            self,
            dir: &Path,
            out: &Path,
            file: &str,
            link: Option<(&str, &str)>,
        ) -> Result<ExtractionReport, ArchiveError> {
            let (name, bytes) = match self {
                Self::Tar => {
                    let mut entries = Vec::new();
                    entries.extend(link.map(|(name, target)| tar_symlink(name, target)));
                    entries.push(tar_file(file, b"x"));
                    ("a.tar", tar_archive(&entries))
                }
                Self::Zip => {
                    let mut entries = Vec::new();
                    entries.extend(link.map(|(name, target)| zip_symlink(name, target)));
                    entries.push(zip_file(file, b"x"));
                    ("a.zip", zip_archive(entries))
                }
                Self::SevenZ => {
                    let mut entries = Vec::new();
                    entries
                        .extend(link.map(|(name, target)| RawEntry::Link(name, target.as_bytes())));
                    entries.push(RawEntry::File(file, b"x"));
                    ("a.7z", crate::common::solid_copy_7z(&entries))
                }
            };
            let archive = dir.join(name);
            std::fs::write(&archive, bytes).unwrap();
            extract_archive(&archive, out, &sevenz_config())
        }
    }

    #[test]
    fn an_entry_path_through_a_destination_symlink_is_judged_where_it_lands() {
        for format in Format::ALL {
            for entry in ["keys/rc", "alias/rc"] {
                let (dir, out) = prepared();
                assert_entry_banned(format.extract(dir.path(), &out, entry, None), entry);
                assert!(!out.join(".ssh/rc").exists(), "{entry}");
            }
        }
    }

    #[test]
    fn a_symlink_target_through_a_destination_symlink_is_judged_where_it_lands() {
        for format in Format::ALL {
            for target in ["keys", "alias", "alias/inner"] {
                let (dir, out) = prepared();
                let result = format.extract(dir.path(), &out, "ok.txt", Some(("link", target)));
                assert_target_banned(result, "Symlink", target);
                assert!(out.join("link").symlink_metadata().is_err(), "{target}");
            }
        }
    }

    #[test]
    fn a_symlink_that_lands_outside_banned_names_still_works() {
        for format in Format::ALL {
            let (dir, out) = prepared();
            format
                .extract(
                    dir.path(),
                    &out,
                    "manuals/new.txt",
                    Some(("link", "manuals")),
                )
                .unwrap();
            assert!(out.join("docs/new.txt").exists());
            assert!(out.join("link").symlink_metadata().is_ok());
        }
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

#[cfg(unix)]
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

#[test]
fn a_hardlink_in_the_same_directory_as_its_target_extracts() {
    for (target, link) in [("target.txt", "link"), ("foo/target.txt", "foo/link")] {
        let entries = [tar_file(target, b"x"), tar_hardlink(link, target)];
        let report = extract_tar(&entries, &links_allowed()).unwrap();
        assert_eq!(report.files_extracted, 2, "{link} -> {target}");
    }
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

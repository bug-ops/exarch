//! `extract_archive` and `extract_to_sink` run the same validation gates: for
//! every fixture they either fail with the same error (variant and cause) or
//! succeed with the same files, symlinks and report counters.

#![allow(clippy::unwrap_used, clippy::needless_pass_by_value)]
#![allow(clippy::disallowed_methods)]

mod sink_support;

use std::assert_matches;
use std::io::Cursor;

use exarch_core::ArchiveError;
use exarch_core::ArchiveReader;
use exarch_core::Extension;
use exarch_core::ExtractionOptions;
use exarch_core::ExtractionReport;
use exarch_core::SecurityConfig;
use exarch_core::SeekableFormat;
use exarch_core::SinkOptions;
use exarch_core::extract_archive_with_options;
use exarch_core::extract_to_sink;
use sink_support::RecordingSink;
use sink_support::Tree;
use sink_support::signature;
use sink_support::tar_archive;
use sink_support::tar_dir;
use sink_support::tar_entry;
use sink_support::tar_file;
use sink_support::tar_hardlink;
use sink_support::tar_symlink;
use sink_support::walk;
use sink_support::zip_archive;
use sink_support::zip_dir;
use sink_support::zip_file;
#[cfg(unix)]
use sink_support::zip_symlink;
use tempfile::TempDir;

#[derive(Clone, Copy)]
enum Kind {
    Tar,
    Zip,
    SevenZ,
}

type Outcome = Result<ExtractionReport, ArchiveError>;

fn via_host(
    kind: Kind,
    bytes: &[u8],
    config: &SecurityConfig,
    options: &ExtractionOptions,
) -> (Outcome, Tree) {
    let dir = TempDir::new().unwrap();
    let name = match kind {
        Kind::Tar => "a.tar",
        Kind::Zip => "a.zip",
        Kind::SevenZ => "a.7z",
    };
    let archive = dir.path().join(name);
    std::fs::write(&archive, bytes).unwrap();
    let out = dir.path().join("out");
    let outcome = extract_archive_with_options(&archive, &out, config, options);
    let tree = if out.exists() {
        walk(&out)
    } else {
        Tree::default()
    };
    (outcome, tree)
}

fn via_sink(
    kind: Kind,
    bytes: &[u8],
    config: &SecurityConfig,
    options: &ExtractionOptions,
) -> (Outcome, RecordingSink) {
    let reader = match kind {
        Kind::Tar => ArchiveReader::tar(Cursor::new(bytes.to_vec()), None),
        Kind::Zip => ArchiveReader::seekable(Cursor::new(bytes.to_vec()), SeekableFormat::Zip),
        Kind::SevenZ => {
            ArchiveReader::seekable(Cursor::new(bytes.to_vec()), SeekableFormat::SevenZ)
        }
    };
    let mut sink = RecordingSink::default();
    let options = SinkOptions::try_from(options).unwrap();
    let outcome = extract_to_sink(reader, &mut sink, config, &options);
    (outcome, sink)
}

/// Runs both paths; returns whether they succeeded.
fn assert_parity(
    kind: Kind,
    bytes: Vec<u8>,
    config: &SecurityConfig,
    options: &ExtractionOptions,
) -> bool {
    let (host_result, host_tree) = via_host(kind, &bytes, config, options);
    let (sink_result, recorded) = via_sink(kind, &bytes, config, options);
    match (host_result, sink_result) {
        (Ok(host_report), Ok(sink_report)) => {
            assert_eq!(recorded.tree.files, host_tree.files, "files");
            assert_eq!(recorded.tree.symlinks, host_tree.symlinks, "symlinks");
            assert!(
                recorded.tree.dirs.is_subset(&host_tree.dirs),
                "sink dirs {:?} not within host dirs {:?}",
                recorded.tree.dirs,
                host_tree.dirs
            );
            assert_eq!(
                sink_report.files_extracted, host_report.files_extracted,
                "files_extracted"
            );
            assert_eq!(
                sink_report.directories_created, host_report.directories_created,
                "directories"
            );
            assert_eq!(
                sink_report.symlinks_created, host_report.symlinks_created,
                "symlinks_created"
            );
            assert_eq!(
                sink_report.bytes_written, host_report.bytes_written,
                "bytes_written"
            );
            assert_eq!(
                sink_report.files_skipped, host_report.files_skipped,
                "files_skipped"
            );
            assert_eq!(sink_report.warnings, host_report.warnings, "warnings");
            true
        }
        (Err(host_error), Err(sink_error)) => {
            assert_eq!(
                signature(&sink_error),
                signature(&host_error),
                "host: {host_error}, sink: {sink_error}"
            );
            false
        }
        (Err(host_error), Ok(_))
            if cfg!(windows)
                && host_error
                    .to_string()
                    .contains("symlinks are not supported on this platform") =>
        {
            false
        }
        (host_result, sink_result) => panic!("host: {host_result:?}, sink: {sink_result:?}"),
    }
}

fn default_config() -> SecurityConfig {
    SecurityConfig::default()
}

fn links_config() -> SecurityConfig {
    SecurityConfig::default()
        .with_allow_symlinks(true)
        .with_allow_hardlinks(true)
}

fn overwrite() -> ExtractionOptions {
    ExtractionOptions::default().with_skip_duplicates(false)
}

fn accepted(kind: Kind, bytes: Vec<u8>, config: &SecurityConfig) {
    assert!(
        assert_parity(kind, bytes, config, &ExtractionOptions::default()),
        "expected success"
    );
}

fn rejected(kind: Kind, bytes: Vec<u8>, config: &SecurityConfig) {
    assert!(
        !assert_parity(kind, bytes, config, &ExtractionOptions::default()),
        "expected failure"
    );
}

#[test]
fn tar_plain_tree() {
    accepted(
        Kind::Tar,
        tar_archive(&[
            tar_dir("d/"),
            tar_file("d/a.txt", b"alpha"),
            tar_file("b.txt", b""),
        ]),
        &default_config(),
    );
}

#[test]
fn tar_traversal_and_absolute_names_are_rejected() {
    for name in ["../evil", "a/../../evil", "/etc/evil"] {
        rejected(
            Kind::Tar,
            tar_archive(&[tar_file(name, b"x")]),
            &default_config(),
        );
    }
}

#[test]
fn tar_root_entry_must_be_a_directory() {
    rejected(
        Kind::Tar,
        tar_archive(&[tar_file(".", b"x")]),
        &default_config(),
    );
    accepted(Kind::Tar, tar_archive(&[tar_dir("./")]), &default_config());
}

#[test]
fn tar_special_entries_are_refused() {
    for kind in [
        tar::EntryType::Block,
        tar::EntryType::Char,
        tar::EntryType::Fifo,
    ] {
        rejected(
            Kind::Tar,
            tar_archive(&[tar_entry("dev", kind, b"", None)]),
            &default_config(),
        );
    }
}

#[cfg(unix)]
#[test]
fn tar_links_are_refused_unless_allowed() {
    let bytes = tar_archive(&[
        tar_file("t", b"x"),
        tar_symlink("s", "t"),
        tar_hardlink("h", "t"),
    ]);
    rejected(Kind::Tar, bytes.clone(), &default_config());
    accepted(Kind::Tar, bytes, &links_config());
}

#[test]
fn tar_link_escapes_are_rejected() {
    for entries in [
        vec![tar_symlink("s", "../../outside")],
        vec![tar_symlink("s", "/etc/passwd")],
        vec![tar_hardlink("h", "../outside")],
        vec![tar_hardlink("h", "/etc/passwd")],
        vec![tar_dir("a/"), tar_symlink("a/s", "../../x")],
    ] {
        rejected(Kind::Tar, tar_archive(&entries), &links_config());
    }
}

#[cfg(unix)]
#[test]
fn tar_file_through_symlinked_parent_is_delivered_resolved() {
    let bytes = tar_archive(&[
        tar_dir("real/"),
        tar_symlink("alias", "real"),
        tar_file("alias/f", b"payload"),
    ]);
    accepted(Kind::Tar, bytes.clone(), &links_config());
    let (outcome, sink) = via_sink(
        Kind::Tar,
        &bytes,
        &links_config(),
        &ExtractionOptions::default(),
    );
    outcome.unwrap();
    assert!(sink.tree.files.contains_key(std::path::Path::new("real/f")));
    assert!(
        !sink
            .tree
            .files
            .contains_key(std::path::Path::new("alias/f"))
    );
}

#[test]
fn tar_hardlink_chain_and_case_variant_target() {
    accepted(
        Kind::Tar,
        tar_archive(&[
            tar_file("a/x", b"data"),
            tar_hardlink("h1", "a/x"),
            tar_hardlink("h2", "h1"),
        ]),
        &links_config(),
    );
    let bytes = tar_archive(&[tar_file("a/x", b"data"), tar_hardlink("h", "A/x")]);
    let succeeded = assert_parity(
        Kind::Tar,
        bytes.clone(),
        &links_config(),
        &ExtractionOptions::default(),
    );
    let (outcome, sink) = via_sink(
        Kind::Tar,
        &bytes,
        &links_config(),
        &ExtractionOptions::default(),
    );
    assert_eq!(outcome.is_ok(), succeeded);
    if succeeded {
        // Case-insensitive host: the variant finds the first-stored spelling.
        assert_eq!(sink.tree.files[std::path::Path::new("h")], b"data");
        assert!(sink.tree.files.contains_key(std::path::Path::new("a/x")));
        assert!(!sink.tree.files.contains_key(std::path::Path::new("A/x")));
    } else {
        assert!(!sink.tree.files.contains_key(std::path::Path::new("h")));
    }
}

#[test]
fn tar_hardlink_to_missing_target_is_rejected() {
    rejected(
        Kind::Tar,
        tar_archive(&[tar_hardlink("h", "nope")]),
        &links_config(),
    );
}

#[test]
fn tar_hardlink_amplification_hits_the_total_quota() {
    let mut config = links_config();
    config.max_total_size = 250;
    rejected(
        Kind::Tar,
        tar_archive(&[
            tar_file("t", &[b'A'; 100]),
            tar_hardlink("h1", "t"),
            tar_hardlink("h2", "t"),
        ]),
        &config,
    );
}

#[test]
fn tar_quotas_are_enforced() {
    let mut config = default_config();
    config.max_file_size = 4;
    rejected(
        Kind::Tar,
        tar_archive(&[tar_file("big", b"12345")]),
        &config,
    );
    let mut config = default_config();
    config.max_file_count = 1;
    rejected(
        Kind::Tar,
        tar_archive(&[tar_file("a", b"1"), tar_file("b", b"2")]),
        &config,
    );
}

#[test]
fn tar_metadata_bomb_is_rejected() {
    let mut config = default_config();
    config.max_tar_metadata_bytes = 1024;
    let long_name = vec![b'a'; 4096];
    rejected(
        Kind::Tar,
        tar_archive(&[
            tar_entry(
                "././@LongLink",
                tar::EntryType::GNULongName,
                &long_name,
                None,
            ),
            tar_file("f", b"x"),
        ]),
        &config,
    );
}

#[test]
fn tar_duplicates_skip_and_overwrite() {
    let bytes = tar_archive(&[
        tar_file("f", b"first"),
        tar_file("f", b"second"),
        tar_dir("d/"),
        tar_dir("d/"),
    ]);
    assert!(assert_parity(
        Kind::Tar,
        bytes.clone(),
        &default_config(),
        &ExtractionOptions::default()
    ));
    assert!(assert_parity(
        Kind::Tar,
        bytes,
        &default_config(),
        &overwrite()
    ));
}

#[cfg(unix)]
#[test]
fn tar_overwrite_occupant_pairs_match() {
    let pairs: Vec<Vec<Vec<u8>>> = vec![
        vec![tar_dir("d/"), tar_file("d", b"x")],
        vec![
            tar_file("t", b"t"),
            tar_symlink("l", "t"),
            tar_file("l", b"x"),
        ],
        vec![tar_file("f", b"x"), tar_dir("f/")],
        vec![tar_file("f", b"x"), tar_symlink("f", "g")],
        vec![tar_dir("d/"), tar_symlink("d", "e")],
        vec![tar_symlink("l", "a"), tar_symlink("l", "a")],
        vec![tar_symlink("l", "a"), tar_symlink("l", "b")],
        vec![tar_file("f", b"x"), tar_hardlink("f", "g")],
        vec![
            tar_file("t", b"x"),
            tar_file("h", b"y"),
            tar_hardlink("h", "t"),
        ],
    ];
    // (succeeds when duplicates are skipped, succeeds when overwriting)
    let expected = [
        (true, false),
        (true, false),
        (false, false),
        (true, true),
        (true, false),
        (true, true),
        (true, false),
        (false, false),
        (true, false),
    ];
    for (entries, (skip_ok, overwrite_ok)) in pairs.into_iter().zip(expected) {
        let skipped = assert_parity(
            Kind::Tar,
            tar_archive(&entries),
            &links_config(),
            &ExtractionOptions::default(),
        );
        let overwritten = assert_parity(
            Kind::Tar,
            tar_archive(&entries),
            &links_config(),
            &overwrite(),
        );
        assert_eq!((skipped, overwritten), (skip_ok, overwrite_ok));
    }
}

/// Where the host cannot create symlinks it refuses them, while the sink keeps
/// delivering them: a sink stores a link as data.
#[cfg(not(unix))]
#[test]
fn host_refuses_symlinks_but_the_sink_delivers_them() {
    let bytes = tar_archive(&[tar_file("t", b"x"), tar_symlink("s", "t")]);
    let (host, _) = via_host(
        Kind::Tar,
        &bytes,
        &links_config(),
        &ExtractionOptions::default(),
    );
    assert!(host.is_err());
    let (outcome, sink) = via_sink(
        Kind::Tar,
        &bytes,
        &links_config(),
        &ExtractionOptions::default(),
    );
    outcome.unwrap();
    assert_eq!(
        sink.tree.symlinks[std::path::Path::new("s")],
        std::path::Path::new("t")
    );
}

#[test]
fn tar_parent_that_is_a_file_is_rejected() {
    rejected(
        Kind::Tar,
        tar_archive(&[tar_file("a", b"x"), tar_file("a/b", b"y")]),
        &default_config(),
    );
}

#[test]
fn tar_extension_filter_skips_alike() {
    let mut config = default_config();
    config.allowed_extensions = vec![Extension::try_from("txt").unwrap()];
    accepted(
        Kind::Tar,
        tar_archive(&[tar_file("a.txt", b"1"), tar_file("b.bin", b"2")]),
        &config,
    );
}

#[test]
fn tar_setuid_is_stripped() {
    let bytes = tar_archive(&[sink_support::tar_entry_mode(
        "suid",
        tar::EntryType::Regular,
        b"x",
        None,
        0o4755,
    )]);
    let (outcome, sink) = via_sink(
        Kind::Tar,
        &bytes,
        &default_config(),
        &ExtractionOptions::default(),
    );
    outcome.unwrap();
    let mode = sink.modes[std::path::Path::new("suid")].unwrap();
    assert_eq!(mode & 0o7000, 0, "{mode:o}");
}

#[test]
fn zip_plain_tree() {
    accepted(
        Kind::Zip,
        zip_archive(vec![
            zip_dir("d/"),
            zip_file("d/a.txt", b"alpha"),
            zip_file("e.txt", b""),
        ]),
        &default_config(),
    );
}

#[test]
fn zip_traversal_is_rejected() {
    for name in ["../evil", "a/../../evil"] {
        rejected(
            Kind::Zip,
            zip_archive(vec![zip_file(name, b"x")]),
            &default_config(),
        );
    }
}

#[cfg(unix)]
#[test]
fn zip_symlinks_follow_policy_and_resolve_parents() {
    let entries = || {
        vec![
            zip_dir("real/"),
            zip_symlink("alias", "real"),
            zip_file("alias/f", b"payload"),
        ]
    };
    rejected(Kind::Zip, zip_archive(entries()), &default_config());
    accepted(Kind::Zip, zip_archive(entries()), &links_config());
    rejected(
        Kind::Zip,
        zip_archive(vec![zip_symlink("s", "../../outside")]),
        &links_config(),
    );
}

#[test]
fn zip_forged_declared_size_is_a_security_violation() {
    use exarch_testkit::raw_zip::RawEntry;
    let payload = vec![0x41u8; 1024 * 1024];
    let entry = RawEntry {
        date: 0,
        size: 50,
        ..RawEntry::deflated("bomb.txt", &payload).unwrap()
    };
    rejected(Kind::Zip, zip_archive(vec![entry]), &default_config());
}

#[test]
fn zip_zero_compressed_entry_is_a_ratio_bomb() {
    use exarch_testkit::raw_zip::RawEntry;
    let entry = RawEntry {
        declared_compressed: Some(0),
        local_sizes: Some((0, 64)),
        ..RawEntry::stored("a.txt", &[7u8; 64])
    };
    rejected(Kind::Zip, zip_archive(vec![entry]), &default_config());
}

#[test]
fn zip_ratio_bomb_is_rejected() {
    use exarch_testkit::raw_zip::RawEntry;
    let payload = vec![0u8; 8 * 1024 * 1024];
    rejected(
        Kind::Zip,
        zip_archive(vec![RawEntry::deflated("zeros", &payload).unwrap()]),
        &default_config(),
    );
}

#[test]
fn zip_crc_corrupt_entry_is_rejected() {
    let mut bytes = zip_archive(vec![zip_file("a.txt", b"UNIQUE-PAYLOAD")]);
    let at = bytes
        .windows(14)
        .position(|w| w == b"UNIQUE-PAYLOAD")
        .unwrap();
    bytes[at] ^= 1;
    rejected(Kind::Zip, bytes, &default_config());
}

#[test]
fn zip_duplicate_names_fail_the_structural_policy_before_any_write() {
    let bytes = zip_archive(vec![zip_file("a", b"1"), zip_file("a", b"2")]);
    let (outcome, sink) = via_sink(
        Kind::Zip,
        &bytes,
        &default_config(),
        &ExtractionOptions::default(),
    );
    assert!(outcome.is_err());
    assert!(sink.tree.files.is_empty());
    rejected(Kind::Zip, bytes, &default_config());
}

#[test]
fn zip_rejected_by_structure_leaves_no_destination() {
    let bytes = zip_archive(vec![zip_file("a", b"1"), zip_file("a", b"2")]);
    let dir = TempDir::new().unwrap();
    let archive = dir.path().join("a.zip");
    std::fs::write(&archive, &bytes).unwrap();
    let out = dir.path().join("out");
    assert!(
        extract_archive_with_options(
            &archive,
            &out,
            &default_config(),
            &ExtractionOptions::default()
        )
        .is_err()
    );
    assert!(!out.exists());
}

#[test]
fn zip_duplicates_and_extension_filter() {
    let mut config = default_config();
    config.zip_consistency = exarch_core::ZipConsistencyPolicy::Ignore;
    let bytes = zip_archive(vec![
        zip_file("f.txt", b"first"),
        zip_file("f.txt", b"second"),
        zip_file("g.bin", b"x"),
    ]);
    for options in [ExtractionOptions::default(), overwrite()] {
        let _ = assert_parity(Kind::Zip, bytes.clone(), &config, &options);
    }
    config.allowed_extensions = vec![Extension::try_from("txt").unwrap()];
    let _ = assert_parity(Kind::Zip, bytes, &config, &ExtractionOptions::default());
}

fn sevenz_fixtures() -> Vec<(String, Vec<u8>)> {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures");
    let mut fixtures: Vec<_> = std::fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "7z"))
        .map(|path| {
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            (name, std::fs::read(&path).unwrap())
        })
        .collect();
    fixtures.sort();
    assert!(fixtures.len() >= 15, "fixtures not found");
    fixtures
}

fn sevenz_configs() -> Vec<SecurityConfig> {
    vec![
        default_config(),
        links_config().with_allow_solid_archives(true),
        default_config()
            .with_allow_solid_archives(true)
            .with_max_total_size(16),
    ]
}

#[test]
fn sevenz_fixtures_match_the_path_based_extraction() {
    let mut accepted = 0;
    for (name, bytes) in sevenz_fixtures() {
        for config in sevenz_configs() {
            for options in [ExtractionOptions::default(), overwrite()] {
                eprintln!("fixture {name}");
                accepted += usize::from(assert_parity(
                    Kind::SevenZ,
                    bytes.clone(),
                    &config,
                    &options,
                ));
            }
        }
    }
    assert!(accepted > 20, "only {accepted} extractions succeeded");
}

/// A 7z archive that exercises every branch the host and sink share: a
/// directory, a repeated path, a symlink, and a file the extension filter
/// skips.
#[cfg(unix)]
fn sevenz_with_duplicates_and_links() -> Vec<u8> {
    use sevenz_rust2::ArchiveEntry;
    use sevenz_rust2::ArchiveWriter;

    const UNIX_EXTENSION: u32 = 0x8000;
    const S_IFLNK: u32 = 0o120_000;

    let mut writer = ArchiveWriter::new(Cursor::new(Vec::new())).unwrap();
    let dir = ArchiveEntry::new_directory("dir");
    writer.push_archive_entry::<&[u8]>(dir, None).unwrap();
    for (name, data) in [
        ("dir/a.txt", &b"first"[..]),
        ("dir/a.txt", &b"second"[..]),
        ("dir/b.bin", &b"binary"[..]),
    ] {
        let mut entry = ArchiveEntry::new_file(name);
        entry.has_stream = true;
        entry.size = data.len() as u64;
        writer.push_archive_entry(entry, Some(data)).unwrap();
    }
    let target = b"dir/a.txt";
    let mut link = ArchiveEntry::new_file("ln");
    link.has_stream = true;
    link.size = target.len() as u64;
    link.has_windows_attributes = true;
    link.windows_attributes = UNIX_EXTENSION | ((S_IFLNK | 0o777) << 16);
    writer.push_archive_entry(link, Some(&target[..])).unwrap();
    writer.finish().unwrap().into_inner()
}

#[cfg(unix)]
#[test]
fn sevenz_duplicates_links_and_filtered_files_match_the_path_based_extraction() {
    let bytes = sevenz_with_duplicates_and_links();
    let mut accepted = 0;
    for config in [
        default_config(),
        links_config(),
        links_config().try_add_allowed_extension("txt").unwrap(),
    ] {
        for options in [ExtractionOptions::default(), overwrite()] {
            accepted += usize::from(assert_parity(
                Kind::SevenZ,
                bytes.clone(),
                &config,
                &options,
            ));
        }
    }
    assert!(accepted >= 2, "only {accepted} extractions succeeded");
}

#[test]
fn sevenz_interleaved_empty_entries_are_delivered_in_archive_order() {
    let (_, bytes) = sevenz_fixtures()
        .into_iter()
        .find(|(name, _)| name == "interleaved-empty.7z")
        .unwrap();
    let dir = TempDir::new().unwrap();
    let archive = dir.path().join("a.7z");
    std::fs::write(&archive, &bytes).unwrap();
    let config = default_config().with_allow_solid_archives(true);
    let in_archive_order: Vec<_> = exarch_core::list_archive(&archive, &config)
        .unwrap()
        .entries()
        .iter()
        .filter(|entry| matches!(entry.kind, exarch_core::ManifestEntryKind::File))
        .map(|entry| entry.path.clone())
        .collect();
    assert!(in_archive_order.len() >= 3, "{in_archive_order:?}");

    let (result, sink) = via_sink(Kind::SevenZ, &bytes, &config, &ExtractionOptions::default());
    let report = result.unwrap();
    assert_eq!(sink.finished, in_archive_order);
    assert_eq!(sink.finished.len(), report.files_extracted);
}

#[test]
fn sevenz_quota_bomb_leaves_the_sink_untouched() {
    let (_, bytes) = sevenz_fixtures()
        .into_iter()
        .find(|(name, _)| name == "simple.7z")
        .unwrap();
    {
        let config = default_config().with_max_total_size(1);
        let (result, sink) = via_sink(Kind::SevenZ, &bytes, &config, &ExtractionOptions::default());
        assert_matches!(result.unwrap_err(), ArchiveError::QuotaExceeded { .. });
        assert!(sink.tree.files.is_empty() && sink.tree.dirs.is_empty());
        assert!(sink.finished.is_empty());
    }
}

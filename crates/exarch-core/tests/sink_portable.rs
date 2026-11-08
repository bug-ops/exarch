//! `PathModel::Portable` against `MemorySink`: the strictest rules of every
//! supported platform, applied on whichever host runs the test.

#![allow(clippy::unwrap_used)]

mod sink_support;

use std::assert_matches;
use std::io::Cursor;

use exarch_core::ArchiveError;
use exarch_core::ArchiveReader;
use exarch_core::ExtractionReport;
use exarch_core::MemorySink;
use exarch_core::PathModel;
use exarch_core::SecurityConfig;
use exarch_core::SinkExtractRequest;
use exarch_core::SinkOptions;
use sink_support::tar_archive;
use sink_support::tar_file;
use sink_support::tar_symlink;

fn run(
    archive: Vec<u8>,
    model: PathModel,
    config: &SecurityConfig,
) -> (Result<ExtractionReport, ArchiveError>, MemorySink) {
    let mut sink = MemorySink::default().with_path_model(model);
    let result = SinkExtractRequest::new(config)
        .with_options(SinkOptions::default())
        .extract(ArchiveReader::tar(Cursor::new(archive), None), &mut sink);
    (result, sink)
}

fn portable(archive: Vec<u8>) -> (Result<ExtractionReport, ArchiveError>, MemorySink) {
    run(archive, PathModel::Portable, &SecurityConfig::default())
}

fn links() -> SecurityConfig {
    SecurityConfig::default()
        .with_allow_symlinks(true)
        .with_max_path_depth(exarch_core::non_zero!(4000))
}

fn long_file(name: &str) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    let mut header = tar::Header::new_gnu();
    header.set_size(1);
    header.set_mode(0o644);
    builder.append_data(&mut header, name, &b"x"[..]).unwrap();
    let mut bytes = builder.into_inner().unwrap();
    bytes.truncate(bytes.len() - 1024);
    bytes
}

fn long_dir(name: &str) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    let mut header = tar::Header::new_gnu();
    header.set_entry_type(tar::EntryType::Directory);
    header.set_size(0);
    header.set_mode(0o755);
    builder
        .append_data(&mut header, format!("{name}/"), std::io::empty())
        .unwrap();
    let mut bytes = builder.into_inner().unwrap();
    bytes.truncate(bytes.len() - 1024);
    bytes
}

fn long_symlink(name: &str, target: &str) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    let mut header = tar::Header::new_gnu();
    header.set_entry_type(tar::EntryType::Symlink);
    header.set_size(0);
    header.set_mode(0o777);
    builder.append_link(&mut header, name, target).unwrap();
    let mut bytes = builder.into_inner().unwrap();
    bytes.truncate(bytes.len() - 1024);
    bytes
}

const HAZARDS: [&str; 14] = [
    "a\\b", "a<b", "a>b", "a\"b", "a|b", "a?b", "a*b", "a\u{1}b", "C:x", "dot.", "space ", "aux",
    "NUL.txt", "d\\f",
];

#[test]
fn portable_refuses_every_hazardous_component() {
    // A Windows host splits a name at `\` before any hazard check.
    for name in HAZARDS
        .into_iter()
        .filter(|name| !(cfg!(windows) && name.contains('\\')))
    {
        let (result, sink) = portable(tar_archive(&[tar_file(name, b"x")]));
        assert!(result.is_err(), "{name:?} was accepted");
        assert_eq!(sink.iter().count(), 0, "{name:?} was delivered");
    }
}

#[test]
fn portable_refuses_a_hazard_in_a_directory_component() {
    let (result, _) = portable(tar_archive(&[tar_file("ok/a?b/f", b"x")]));
    let message = result.unwrap_err().to_string();
    assert!(message.contains("not portable"), "{message}");
}

#[test]
fn portable_reports_windows_hazards_with_their_own_reason() {
    // A Windows host rejects a drive prefix before the Portable hazard check.
    for (name, needle) in [("C:x", "':'"), ("dot.", "ends with"), ("aux", "reserved")]
        .into_iter()
        .filter(|(name, _)| !(cfg!(windows) && *name == "C:x"))
    {
        let message = portable(tar_archive(&[tar_file(name, b"x")]))
            .0
            .unwrap_err()
            .to_string();
        assert!(message.contains(needle), "{name}: {message}");
    }
}

#[cfg(unix)]
#[test]
fn the_unix_host_model_accepts_what_portable_refuses() {
    for name in HAZARDS {
        let (result, sink) = run(
            tar_archive(&[tar_file(name, b"x")]),
            PathModel::Host,
            &SecurityConfig::default(),
        );
        assert!(result.is_ok(), "{name:?}: {result:?}");
        assert_eq!(sink.iter().count(), 1, "{name:?}");
    }
}

#[cfg(unix)]
#[test]
fn portable_refuses_a_name_that_is_not_utf8() {
    let mut header = tar::Header::new_gnu();
    header.set_entry_type(tar::EntryType::Regular);
    header.set_mode(0o644);
    header.set_size(0);
    header.as_old_mut().name[..3].copy_from_slice(b"a\xffb");
    header.set_cksum();
    let (result, sink) = portable(tar_archive(&[header.as_bytes().to_vec()]));
    assert!(result.is_err());
    assert_eq!(sink.iter().count(), 0);
}

#[test]
fn portable_component_limit_is_255_bytes() {
    let (ok, _) = portable(tar_archive(&[long_file(&"a".repeat(255))]));
    assert!(ok.is_ok(), "{ok:?}");
    let (over, sink) = portable(tar_archive(&[long_file(&"a".repeat(256))]));
    assert!(over.is_err());
    assert_eq!(sink.iter().count(), 0);
}

#[test]
fn portable_component_limit_counts_utf8_bytes_of_wide_characters() {
    let (ok, _) = portable(tar_archive(&[long_file(&"\u{65e5}".repeat(85))]));
    assert!(ok.is_ok(), "{ok:?}");
    let (over, _) = portable(tar_archive(&[long_file(&"\u{65e5}".repeat(86))]));
    assert!(over.is_err());
}

#[test]
fn portable_path_limit_is_1023_bytes() {
    let segment = "a".repeat(100);
    let path = |n: usize| vec![segment.as_str(); n].join("/");
    let (ok, _) = portable(tar_archive(&[long_file(&path(10))]));
    assert!(ok.is_ok(), "{ok:?}");
    let (over, _) = portable(tar_archive(&[long_file(&path(11))]));
    assert!(over.is_err());
}

#[test]
fn portable_symlink_target_limit_is_1023_bytes() {
    let target = |extra: &str| format!("{}{extra}", "b/".repeat(511));
    let (ok, _) = run(
        tar_archive(&[long_symlink("l", &target("b"))]),
        PathModel::Portable,
        &links(),
    );
    assert!(ok.is_ok(), "{ok:?}");
    let (over, sink) = run(
        tar_archive(&[long_symlink("l", &target("bb"))]),
        PathModel::Portable,
        &links(),
    );
    assert!(over.is_err());
    assert_eq!(sink.iter().count(), 0);
}

#[test]
fn portable_case_variants_are_one_name_on_every_host() {
    let (result, sink) = portable(tar_archive(&[
        tar_file("Dir/A", b"first"),
        tar_file("dir/a", b"second"),
    ]));
    let report = result.unwrap();
    assert_eq!(report.files_skipped(), 1);
    let paths: Vec<_> = sink.iter().map(|(p, _)| p.to_path_buf()).collect();
    assert_eq!(paths, [std::path::PathBuf::from("Dir/A")]);
}

#[test]
fn portable_canonically_equivalent_names_are_one_name_on_every_host() {
    let (result, sink) = portable(tar_archive(&[
        tar_file("caf\u{e9}", b"first"),
        tar_file("cafe\u{301}", b"second"),
    ]));
    assert_eq!(result.unwrap().files_skipped(), 1);
    assert_eq!(sink.iter().count(), 1);
}

#[cfg(target_os = "linux")]
#[test]
fn the_linux_host_model_keeps_case_variants_apart() {
    let (result, sink) = run(
        tar_archive(&[tar_file("Dir/A", b"first"), tar_file("dir/a", b"second")]),
        PathModel::Host,
        &SecurityConfig::default(),
    );
    assert_eq!(result.unwrap().files_skipped(), 0);
    assert_eq!(sink.iter().count(), 2);
}

#[test]
fn portable_case_variant_directories_charge_the_file_count() {
    let entries: Vec<_> = [
        "aaaa/", "Aaaa/", "aAaa/", "aaAa/", "aaaA/", "AAaa/", "AaAa/", "aAAa/",
    ]
    .into_iter()
    .map(sink_support::tar_dir)
    .collect();
    let config = SecurityConfig::default()
        .with_max_file_count(exarch_core::non_zero!(2))
        .with_max_path_depth(exarch_core::non_zero!(2));
    let (result, _) = run(tar_archive(&entries), PathModel::Portable, &config);
    let mut error = &result.unwrap_err();
    while let ArchiveError::PartialExtraction(partial) = error {
        error = partial.cause();
    }
    assert_matches!(
        error,
        ArchiveError::QuotaExceeded {
            resource: exarch_core::QuotaResource::FileCount { max: 2, .. }
        },
        "{error:?}"
    );
}

#[test]
fn portable_symlink_chain_leaving_the_root_is_refused() {
    let (result, sink) = run(
        tar_archive(&[tar_symlink("up", "."), tar_symlink("d", "up/..")]),
        PathModel::Portable,
        &links(),
    );
    assert_matches!(
        result.unwrap_err(),
        ArchiveError::SymlinkEscape { .. } | ArchiveError::PartialExtraction(_),
        "escape not refused"
    );
    assert!(sink.get(std::path::Path::new("d")).is_none());
}

fn all_links() -> SecurityConfig {
    links().with_allow_hardlinks(true)
}

fn root_cause(error: &ArchiveError) -> &ArchiveError {
    match error {
        ArchiveError::PartialExtraction(partial) => root_cause(partial.cause()),
        other => other,
    }
}

#[test]
fn portable_hardlink_escape_is_refused() {
    for target in ["../x", "a/../../x", "/etc/passwd"] {
        let (result, sink) = run(
            tar_archive(&[
                tar_file("a/f", b"x"),
                sink_support::tar_hardlink("h", target),
            ]),
            PathModel::Portable,
            &all_links(),
        );
        let error = result.unwrap_err();
        assert_matches!(
            root_cause(&error),
            ArchiveError::HardlinkEscape { .. },
            "{target}: {error:?}"
        );
        assert!(sink.get(std::path::Path::new("h")).is_none());
    }
}

#[test]
fn portable_absolute_symlink_target_is_refused() {
    for target in ["/etc/passwd", "/", "/exarch-virtual-root/x"] {
        let (result, sink) = run(
            tar_archive(&[tar_symlink("l", target)]),
            PathModel::Portable,
            &links(),
        );
        let error = result.unwrap_err();
        assert_matches!(
            root_cause(&error),
            ArchiveError::SymlinkEscape { .. },
            "{target}: {error:?}"
        );
        assert_eq!(sink.iter().count(), 0);
    }
}

#[test]
fn portable_file_through_an_escaping_link_is_refused() {
    for target in ["..", "../..", "up/.."] {
        let (result, sink) = run(
            tar_archive(&[
                tar_symlink("up", "."),
                tar_symlink("l", target),
                tar_file("l/pwn", b"x"),
            ]),
            PathModel::Portable,
            &links(),
        );
        let error = result.unwrap_err();
        assert_matches!(
            root_cause(&error),
            ArchiveError::SymlinkEscape { .. },
            "{target}: {error:?}"
        );
        assert!(sink.get(std::path::Path::new("l/pwn")).is_none());
        assert!(sink.get(std::path::Path::new("pwn")).is_none());
    }
}

#[test]
fn portable_limits_hold_for_the_path_an_entry_lands_at() {
    let segment = "a".repeat(100);
    let deep = [segment.as_str(); 10].join("/");
    let (ok, _) = run(
        tar_archive(&[
            long_dir(&deep),
            long_symlink("l", &deep),
            long_file(&format!("l/{}", "n".repeat(10))),
        ]),
        PathModel::Portable,
        &links(),
    );
    assert!(ok.is_ok(), "{ok:?}");

    let (over, sink) = run(
        tar_archive(&[
            long_dir(&deep),
            long_symlink("l", &deep),
            long_file(&format!("l/{}", "n".repeat(20))),
        ]),
        PathModel::Portable,
        &links(),
    );
    let error = over.unwrap_err();
    assert_matches!(root_cause(&error), ArchiveError::Io(_), "{error:?}");
    assert!(
        sink.iter()
            .all(|(_, entry)| !matches!(entry, exarch_core::MemoryEntry::File { .. }))
    );
}

#[test]
fn portable_accepts_an_ordinary_archive() {
    let (result, sink) = portable(tar_archive(&[
        tar_file("docs/readme.md", b"hello"),
        tar_file("src/main.rs", b"fn main() {}"),
    ]));
    assert_eq!(result.unwrap().files_extracted, 2);
    let expected = 2 * MemorySink::ENTRY_OVERHEAD
        + ("docs/readme.md".len() + "src/main.rs".len()) as u64
        + 5
        + 12;
    assert_eq!(sink.stored_bytes(), expected);
}

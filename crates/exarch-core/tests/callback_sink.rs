//! `CallbackSink`: whole verified entries delivered to a closure.

#![allow(clippy::unwrap_used)]

mod sink_support;

use std::assert_matches;
use std::io;
use std::io::Cursor;
use std::path::Path;
use std::path::PathBuf;

use exarch_core::ArchiveError;
use exarch_core::ArchiveReader;
use exarch_core::CallbackSink;
use exarch_core::MemoryEntry;
use exarch_core::MemoryEntryKind;
use exarch_core::SecurityConfig;
use exarch_core::SinkOptions;
use exarch_core::extract_to_sink;
use sink_support::tar_archive;
use sink_support::tar_dir;
use sink_support::tar_file;
use sink_support::tar_hardlink;
use sink_support::tar_symlink;

type Delivered = Vec<(PathBuf, MemoryEntry)>;

fn links() -> SecurityConfig {
    SecurityConfig::default()
        .with_allow_symlinks(true)
        .with_allow_hardlinks(true)
}

fn collect(
    entries: &[Vec<u8>],
    config: &SecurityConfig,
    options: SinkOptions,
) -> (Result<(), ArchiveError>, Delivered) {
    let mut delivered = Delivered::new();
    let mut sink = CallbackSink::new(|path, entry| {
        delivered.push((path.as_path().to_path_buf(), entry));
        Ok(())
    });
    let reader = ArchiveReader::tar(Cursor::new(tar_archive(entries)), None);
    let result = extract_to_sink(reader, &mut sink, config, &options).map(drop);
    (result, delivered)
}

#[test]
fn every_kind_is_delivered_and_a_hardlink_comes_last_by_reference() {
    let entries = [
        tar_dir("d/"),
        tar_file("d/a.txt", b"hello"),
        tar_symlink("s", "d/a.txt"),
        tar_hardlink("h", "d/a.txt"),
    ];

    let (result, delivered) = collect(&entries, &links(), SinkOptions::default());

    result.unwrap();
    let kinds: Vec<_> = delivered.iter().map(|(_, e)| e.kind()).collect();
    assert_eq!(
        kinds,
        [
            MemoryEntryKind::Directory,
            MemoryEntryKind::File,
            MemoryEntryKind::Symlink,
            MemoryEntryKind::Hardlink
        ]
    );
    assert_matches!(
        &delivered[1].1,
        MemoryEntry::File { data, .. } if data == b"hello"
    );
    assert_matches!(
        &delivered[2].1,
        MemoryEntry::Symlink { target } if target == Path::new("d/a.txt")
    );
    assert_eq!(delivered[3].0, Path::new("h"));
    assert_matches!(
        &delivered[3].1,
        MemoryEntry::Hardlink { target } if target == Path::new("d/a.txt")
    );
    assert_eq!(MemoryEntryKind::Hardlink.as_str(), "hardlink");
}

#[test]
fn a_hardlink_target_is_the_resolved_path() {
    let entries = [
        tar_file("d/a.txt", b"x"),
        tar_symlink("dl", "d"),
        tar_hardlink("h", "dl/a.txt"),
    ];

    let (result, delivered) = collect(&entries, &links(), SinkOptions::default());

    result.unwrap();
    assert_matches!(
        &delivered.last().unwrap().1,
        MemoryEntry::Hardlink { target } if target == Path::new("d/a.txt")
    );
}

#[test]
fn a_hardlink_chain_is_delivered_link_by_link() {
    let entries = [
        tar_file("a", b"x"),
        tar_hardlink("b", "a"),
        tar_hardlink("c", "b"),
    ];

    let (result, delivered) = collect(&entries, &links(), SinkOptions::default());

    result.unwrap();
    let targets: Vec<_> = delivered
        .iter()
        .filter_map(|(path, entry)| match entry {
            MemoryEntry::Hardlink { target } => Some((path.clone(), target.clone())),
            _ => None,
        })
        .collect();
    assert_eq!(
        targets,
        [
            (PathBuf::from("b"), PathBuf::from("a")),
            (PathBuf::from("c"), PathBuf::from("b")),
        ]
    );
}

#[test]
fn under_overwrite_a_path_is_delivered_again() {
    let entries = [tar_file("a", b"one"), tar_file("a", b"two!")];

    let (result, delivered) = collect(
        &entries,
        &SecurityConfig::default(),
        SinkOptions::default().with_skip_duplicates(false),
    );

    result.unwrap();
    let data: Vec<_> = delivered
        .iter()
        .filter_map(|(_, e)| match e {
            MemoryEntry::File { data, .. } => Some(data.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(data, [b"one".to_vec(), b"two!".to_vec()]);
}

#[test]
fn implicit_parent_directories_are_not_delivered() {
    let (result, delivered) = collect(
        &[tar_file("a/b/c.txt", b"x")],
        &SecurityConfig::default(),
        SinkOptions::default(),
    );

    result.unwrap();
    assert_eq!(delivered.len(), 1);
}

#[test]
fn a_file_over_the_size_limit_is_refused_before_delivery() {
    let config = SecurityConfig::default().with_max_file_size(10);

    let (result, delivered) = collect(
        &[tar_file("big", &[7; 100])],
        &config,
        SinkOptions::default(),
    );

    assert!(result.is_err());
    assert!(delivered.is_empty());
}

#[test]
fn a_callback_error_ends_the_extraction() {
    let entries = [
        tar_file("a", b"1"),
        tar_file("b", b"2"),
        tar_file("c", b"3"),
    ];
    let mut calls = 0;
    let mut sink = CallbackSink::new(|_, _| {
        calls += 1;
        Err(io::Error::other("stop"))
    });
    let reader = ArchiveReader::tar(Cursor::new(tar_archive(&entries)), None);

    let result = extract_to_sink(
        reader,
        &mut sink,
        &SecurityConfig::default(),
        &SinkOptions::default(),
    );

    assert!(result.is_err());
    assert_eq!(calls, 1);
}
